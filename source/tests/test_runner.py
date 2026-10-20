"""自写测试运行器（不依赖 pytest / unittest）。

    python tests/test_runner.py

输出形如 `62/62 tests passed`，退出码 0 表示全绿。
每个测试都是无参函数，注册进 TESTS 后按定义顺序执行；失败会打印完整 traceback。
"""

from __future__ import annotations

import ast
import atexit
import json
import re
import sys
import tempfile
import traceback
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from structured_data_api.api import ApiContext, start_in_thread, stop_server  # noqa: E402
from structured_data_api.audit import AuditLog  # noqa: E402
from structured_data_api.config import load_config_dir  # noqa: E402
from structured_data_api.datasource import (  # noqa: E402
    build_database,
    fact_checksum,
    temporary_database,
)
from structured_data_api.guard import (  # noqa: E402
    QueryEngine,
    ReadOnlyGuard,
    StatementInspector,
    probe_authorizer,
    probe_readonly_uri,
    probe_row_cap,
    probe_statement_policy,
    probe_timeout,
)
from structured_data_api.model import ApiError, AuthToken, ErrorCode  # noqa: E402
from structured_data_api.openapi import build_spec  # noqa: E402
from structured_data_api.param_validate import validate_request  # noqa: E402
from structured_data_api.ratelimit import SlidingWindowLimiter  # noqa: E402
from structured_data_api.trace import DeterministicClock, SystemClock  # noqa: E402

TESTS: list[tuple[str, Callable[[], None]]] = []


def test(fn: Callable[[], None]) -> Callable[[], None]:
    TESTS.append((fn.__name__, fn))
    return fn


BUNDLE = load_config_dir(ROOT / "config")
_DS_CM = temporary_database()
DS = _DS_CM.__enter__()
atexit.register(lambda: _DS_CM.__exit__(None, None, None))

DATE_FROM = "2025-01-01"
DATE_TO = "2025-03-31"


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def make_engine(clock: Any | None = None) -> tuple[QueryEngine, AuditLog]:
    clock = clock or SystemClock()
    audit = AuditLog(clock, max_entries=2000)
    return QueryEngine(DS, BUNDLE.contract, BUNDLE.limits, audit, clock), audit


def expect_error(code: str, fn: Callable[[], Any], layer: str | None = None) -> ApiError:
    try:
        fn()
    except ApiError as exc:
        assert exc.code == code, f"期望 {code}，实际 {exc.code}：{exc.message}"
        if layer is not None:
            assert exc.layer == layer, f"期望 layer={layer}，实际 {exc.layer}"
        assert exc.message, "错误消息不能为空"
        return exc
    raise AssertionError(f"期望抛出 {code}，实际没有异常")


def base_request(**overrides: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "template": "sales_by_region",
        "params": {"date_from": DATE_FROM, "date_to": DATE_TO},
    }
    raw.update(overrides)
    return raw


def _http(
    base: str,
    path: str,
    token: str | None = None,
    method: str = "GET",
) -> tuple[int, dict[str, Any], dict[str, str]]:
    headers = {"Accept": "application/json"}
    if token:
        headers["X-API-Token"] = token
    data = b"{}" if method not in ("GET", "HEAD") else None
    request = Request(base + path, headers=headers, method=method, data=data)
    try:
        with urlopen(request, timeout=10) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw or "{}"), dict(response.headers)
    except HTTPError as exc:
        raw = exc.read().decode("utf-8")
        return exc.code, json.loads(raw or "{}"), dict(exc.headers)
    except URLError as exc:  # pragma: no cover - 只在服务未起来时触发
        raise AssertionError(f"HTTP 请求失败：{exc}") from exc


@contextmanager
def api():
    clock = SystemClock()
    audit = AuditLog(clock)
    engine = QueryEngine(DS, BUNDLE.contract, BUNDLE.limits, audit, clock)
    context = ApiContext(engine, BUNDLE.contract, BUNDLE.limits, BUNDLE.auth, audit, clock)
    server, thread, base = start_in_thread(context, host="127.0.0.1", port=0)
    try:
        yield base, context
    finally:
        stop_server(server, thread)


def token_of(token_id: str) -> str:
    for token in BUNDLE.auth.tokens.values():
        if token.id == token_id:
            return token.token
    raise AssertionError(f"缺少令牌 {token_id}")


# ---------------------------------------------------------------------------
# 配置与数据源
# ---------------------------------------------------------------------------


@test
def test_config_loads_contract() -> None:
    assert len(BUNDLE.contract.templates) == 8
    assert len(BUNDLE.contract.exposed_templates()) == 7
    assert BUNDLE.contract.read_only is True
    assert BUNDLE.contract.dialect == "sqlite"
    assert len(BUNDLE.contract.allowed_views) == 6
    assert BUNDLE.limits.max_rows_hard == 200


@test
def test_config_limits_are_sane() -> None:
    assert BUNDLE.limits.default_rows <= BUNDLE.limits.max_rows_hard
    assert BUNDLE.limits.allow_methods == ("GET",)
    assert BUNDLE.limits.query_timeout_ms >= BUNDLE.limits.benchmark_timeout_ms
    for tpl in BUNDLE.contract.templates.values():
        assert tpl.max_rows <= BUNDLE.limits.max_rows_hard
        assert tpl.views and all(v in BUNDLE.contract.allowed_views for v in tpl.views)


@test
def test_config_tokens_have_scopes() -> None:
    assert len(BUNDLE.auth.tokens) == 4
    audit_only = next(t for t in BUNDLE.auth.tokens.values() if t.id == "demo-audit-only")
    assert audit_only.scopes == ("audit",)
    query_only = next(t for t in BUNDLE.auth.tokens.values() if t.id == "demo-query-only")
    assert query_only.scopes == ("query",)
    burst = next(t for t in BUNDLE.auth.tokens.values() if t.id == "demo-burst")
    assert burst.rate_limit_limit == 5


@test
def test_datasource_star_schema() -> None:
    assert DS.stats["fact_sales"] == 4000
    assert DS.stats["dim_date"] == 731
    assert DS.stats["dim_region"] == 4
    assert DS.stats["dim_customer"] == 60
    assert DS.stats["views"] == 6
    conn = DS.connect_ro()
    try:
        rows = conn.execute("SELECT COUNT(*) FROM v_sales_enriched").fetchone()[0]
    finally:
        conn.close()
    assert rows == 4000


@test
def test_datasource_is_deterministic() -> None:
    tmpdir = Path(tempfile.mkdtemp(prefix="sdapi-test-"))
    try:
        db = tmpdir / "again.db"
        build_database(db)
        assert fact_checksum(db) == fact_checksum(DS.path)
    finally:
        for item in tmpdir.iterdir():
            item.unlink()
        tmpdir.rmdir()


@test
def test_datasource_readonly_uri_denies_writes() -> None:
    conn = DS.connect_ro()
    try:
        for sql in (
            "INSERT INTO fact_sales (sale_id) VALUES (1)",
            "UPDATE fact_sales SET quantity = 0",
            "DELETE FROM fact_sales",
            "DROP TABLE fact_sales",
        ):
            try:
                conn.execute(sql)
                raise AssertionError(f"只读连接允许了写操作：{sql}")
            except ApiError:
                raise
            except Exception as exc:
                assert "readonly" in str(exc).lower(), f"意外的错误：{exc}"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 第二层：语句白名单
# ---------------------------------------------------------------------------


@test
def test_statement_allows_select() -> None:
    verdict = StatementInspector(BUNDLE.contract.allowed_views).inspect(
        "SELECT region, SUM(orders) FROM v_sales_daily GROUP BY region"
    )
    assert verdict.ok and verdict.first_keyword == "SELECT"
    assert verdict.views == ("v_sales_daily",)


@test
def test_statement_allows_with_cte() -> None:
    verdict = StatementInspector(BUNDLE.contract.allowed_views).inspect(
        "WITH t AS (SELECT region, SUM(revenue_cents) AS r FROM v_sales_daily GROUP BY region)"
        " SELECT region, r FROM t ORDER BY r DESC LIMIT 3"
    )
    assert verdict.ok and verdict.first_keyword == "WITH"
    assert "t" in verdict.ctes


@test
def test_statement_allows_trailing_semicolon() -> None:
    verdict = StatementInspector(BUNDLE.contract.allowed_views).inspect(
        "SELECT COUNT(*) FROM v_sales_daily;"
    )
    assert verdict.ok and verdict.statement_count == 1


@test
def test_statement_rejects_delete() -> None:
    verdict = StatementInspector(BUNDLE.contract.allowed_views).inspect("DELETE FROM fact_sales")
    assert not verdict.ok and verdict.error_code == ErrorCode.SQL_NOT_ALLOWED


@test
def test_statement_rejects_drop() -> None:
    verdict = StatementInspector(BUNDLE.contract.allowed_views).inspect("DROP TABLE fact_sales")
    assert not verdict.ok and verdict.error_code == ErrorCode.SQL_NOT_ALLOWED


@test
def test_statement_rejects_insert() -> None:
    verdict = StatementInspector(BUNDLE.contract.allowed_views).inspect(
        "INSERT INTO fact_sales (sale_id) VALUES (1)"
    )
    assert not verdict.ok and verdict.error_code == ErrorCode.SQL_NOT_ALLOWED


@test
def test_statement_rejects_pragma() -> None:
    verdict = StatementInspector(BUNDLE.contract.allowed_views).inspect("PRAGMA table_info(fact_sales)")
    assert not verdict.ok and verdict.error_code == ErrorCode.SQL_NOT_ALLOWED


@test
def test_statement_rejects_attach() -> None:
    verdict = StatementInspector(BUNDLE.contract.allowed_views).inspect(
        "ATTACH DATABASE 'other.db' AS other"
    )
    assert not verdict.ok and verdict.error_code == ErrorCode.SQL_NOT_ALLOWED


@test
def test_statement_rejects_multi_statement() -> None:
    verdict = StatementInspector(BUNDLE.contract.allowed_views).inspect(
        "SELECT 1; DELETE FROM fact_sales"
    )
    assert not verdict.ok and verdict.error_code == ErrorCode.SQL_MULTI_STATEMENT
    assert verdict.statement_count == 2


@test
def test_statement_rejects_comment() -> None:
    verdict = StatementInspector(BUNDLE.contract.allowed_views).inspect(
        "SELECT * FROM v_sales_daily -- 注释"
    )
    assert not verdict.ok and verdict.error_code == ErrorCode.SQL_COMMENT


@test
def test_statement_rejects_block_comment() -> None:
    verdict = StatementInspector(BUNDLE.contract.allowed_views).inspect(
        "SELECT /* 注释 */ * FROM v_sales_daily"
    )
    assert not verdict.ok and verdict.error_code == ErrorCode.SQL_COMMENT


@test
def test_statement_rejects_unknown_view() -> None:
    verdict = StatementInspector(BUNDLE.contract.allowed_views).inspect(
        "SELECT * FROM secret_salary_table"
    )
    assert not verdict.ok and verdict.error_code == ErrorCode.VIEW_NOT_ALLOWED


@test
def test_statement_ignores_literals_with_keywords() -> None:
    verdict = StatementInspector(BUNDLE.contract.allowed_views).inspect(
        "SELECT region FROM v_sales_daily WHERE region = 'drop table x'"
    )
    assert verdict.ok, f"字符串字面量里的关键字不应误判：{verdict.reason}"


@test
def test_statement_rejects_empty() -> None:
    verdict = StatementInspector(BUNDLE.contract.allowed_views).inspect("   ")
    assert not verdict.ok and verdict.error_code == ErrorCode.SQL_NOT_ALLOWED


# ---------------------------------------------------------------------------
# 第一层：authorizer
# ---------------------------------------------------------------------------


def _guard_on_rw() -> tuple[Any, ReadOnlyGuard]:
    conn = DS.connect_rw()
    guard = ReadOnlyGuard(conn, StatementInspector(BUNDLE.contract.allowed_views))
    guard.install_authorizer()
    return conn, guard


@test
def test_authorizer_allows_select() -> None:
    conn, guard = _guard_on_rw()
    try:
        outcome = guard.run_raw("SELECT COUNT(*) AS n FROM fact_sales", max_rows=5)
        assert outcome.rows == [(4000,)]
    finally:
        conn.close()


@test
def test_authorizer_denies_insert() -> None:
    conn, guard = _guard_on_rw()
    try:
        expect_error(
            ErrorCode.SQL_AUTHORIZER,
            lambda: guard.run_raw("INSERT INTO fact_sales (sale_id) VALUES (1)"),
        )
        assert guard.denials and guard.denials[-1]["action"] == "SQLITE_INSERT"
    finally:
        conn.close()


@test
def test_authorizer_denies_update() -> None:
    conn, guard = _guard_on_rw()
    try:
        expect_error(
            ErrorCode.SQL_AUTHORIZER,
            lambda: guard.run_raw("UPDATE fact_sales SET quantity = 0 WHERE sale_id = 1"),
        )
        assert guard.denials and guard.denials[-1]["action"] == "SQLITE_UPDATE"
    finally:
        conn.close()


@test
def test_authorizer_denies_delete() -> None:
    conn, guard = _guard_on_rw()
    try:
        expect_error(ErrorCode.SQL_AUTHORIZER, lambda: guard.run_raw("DELETE FROM fact_sales"))
        assert guard.denials and guard.denials[-1]["action"] == "SQLITE_DELETE"
    finally:
        conn.close()


@test
def test_authorizer_denies_drop() -> None:
    conn, _guard = _guard_on_rw()
    try:
        expect_error(ErrorCode.SQL_AUTHORIZER, lambda: _guard.run_raw("DROP TABLE fact_sales"))
        count = conn.execute("SELECT COUNT(*) FROM fact_sales").fetchone()[0]
        assert count == 4000, "DROP 被拒后表必须还在"
    finally:
        conn.close()


@test
def test_authorizer_denies_pragma() -> None:
    conn, guard = _guard_on_rw()
    try:
        expect_error(
            ErrorCode.SQL_AUTHORIZER,
            lambda: guard.run_raw("PRAGMA table_info(fact_sales)"),
        )
        assert guard.denials and guard.denials[-1]["action"] == "SQLITE_PRAGMA"
    finally:
        conn.close()


@test
def test_authorizer_survives_multiple_denials() -> None:
    conn, guard = _guard_on_rw()
    try:
        for _ in range(3):
            try:
                guard.run_raw("DELETE FROM fact_sales")
            except ApiError:
                pass
        assert conn.execute("SELECT COUNT(*) FROM fact_sales").fetchone()[0] == 4000
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 参数校验
# ---------------------------------------------------------------------------


def validate(raw: Any, **kwargs: Any) -> Any:
    return validate_request(raw, BUNDLE.contract, BUNDLE.limits, **kwargs)


@test
def test_validate_defaults() -> None:
    request = validate(base_request())
    assert request.limit == BUNDLE.limits.default_rows
    assert request.params["region"] is None
    assert request.params["date_from"] == DATE_FROM


@test
def test_validate_template_missing() -> None:
    expect_error(ErrorCode.PARAM_MISSING, lambda: validate({"params": {}}), layer="param")


@test
def test_validate_template_unknown() -> None:
    expect_error(
        ErrorCode.TEMPLATE_UNKNOWN,
        lambda: validate({"template": "nope", "params": {}}),
        layer="param",
    )


@test
def test_validate_unexposed_template_blocked() -> None:
    expect_error(
        ErrorCode.TEMPLATE_UNKNOWN,
        lambda: validate({"template": "benchmark_cross_join", "params": {}}),
        layer="param",
    )
    request = validate({"template": "benchmark_cross_join", "params": {}}, allow_unexposed=True)
    assert request.template_id == "benchmark_cross_join"


@test
def test_validate_missing_required() -> None:
    exc = expect_error(
        ErrorCode.PARAM_MISSING,
        lambda: validate({"template": "sales_by_region", "params": {"date_to": DATE_TO}}),
        layer="param",
    )
    assert exc.field_name == "date_from"
    assert "date_from" in exc.message


@test
def test_validate_unknown_field() -> None:
    exc = expect_error(
        ErrorCode.PARAM_UNKNOWN,
        lambda: validate(
            base_request(params={"date_from": DATE_FROM, "date_to": DATE_TO, "customer_email": "a@b"})
        ),
        layer="param",
    )
    assert exc.field_name == "customer_email"


@test
def test_validate_field_not_in_template() -> None:
    expect_error(
        ErrorCode.PARAM_NOT_IN_TEMPLATE,
        lambda: validate(
            {
                "template": "daily_revenue",
                "params": {"date_from": DATE_FROM, "date_to": DATE_TO, "region": "华东"},
            }
        ),
        layer="param",
    )


@test
def test_validate_limit_string() -> None:
    expect_error(
        ErrorCode.PARAM_TYPE,
        lambda: validate(
            base_request(params={"date_from": DATE_FROM, "date_to": DATE_TO, "limit": "10"})
        ),
        layer="param",
    )


@test
def test_validate_limit_bool() -> None:
    expect_error(
        ErrorCode.PARAM_TYPE,
        lambda: validate(
            base_request(params={"date_from": DATE_FROM, "date_to": DATE_TO, "limit": True})
        ),
        layer="param",
    )


@test
def test_validate_limit_zero() -> None:
    expect_error(
        ErrorCode.PARAM_RANGE,
        lambda: validate(
            base_request(params={"date_from": DATE_FROM, "date_to": DATE_TO, "limit": 0})
        ),
        layer="param",
    )


@test
def test_validate_enum() -> None:
    expect_error(
        ErrorCode.PARAM_ENUM,
        lambda: validate(
            base_request(params={"date_from": DATE_FROM, "date_to": DATE_TO, "region": "火星"})
        ),
        layer="param",
    )


@test
def test_validate_injection_semicolon() -> None:
    expect_error(
        ErrorCode.PARAM_INJECTION,
        lambda: validate(
            base_request(
                params={
                    "date_from": DATE_FROM,
                    "date_to": DATE_TO,
                    "region": "华东'; DROP TABLE fact_sales; --",
                }
            )
        ),
        layer="param",
    )


@test
def test_validate_injection_comment() -> None:
    expect_error(
        ErrorCode.PARAM_INJECTION,
        lambda: validate(
            base_request(params={"date_from": DATE_FROM, "date_to": DATE_TO, "region": "华东--"})
        ),
        layer="param",
    )


@test
def test_validate_injection_quote() -> None:
    expect_error(
        ErrorCode.PARAM_INJECTION,
        lambda: validate(
            base_request(params={"date_from": DATE_FROM, "date_to": DATE_TO, "region": "华东' OR '1'='1"})
        ),
        layer="param",
    )


@test
def test_validate_injection_keyword() -> None:
    expect_error(
        ErrorCode.PARAM_INJECTION,
        lambda: validate(
            base_request(
                params={"date_from": DATE_FROM, "date_to": DATE_TO, "region": "华东 union select 1"}
            )
        ),
        layer="param",
    )


@test
def test_validate_length() -> None:
    expect_error(
        ErrorCode.PARAM_LENGTH,
        lambda: validate(
            base_request(params={"date_from": DATE_FROM, "date_to": DATE_TO, "region": "华" * 68})
        ),
        layer="param",
    )


@test
def test_validate_date_format() -> None:
    expect_error(
        ErrorCode.PARAM_TYPE,
        lambda: validate(
            base_request(params={"date_from": "2025/01/01", "date_to": DATE_TO})
        ),
        layer="param",
    )


@test
def test_validate_date_out_of_range() -> None:
    expect_error(
        ErrorCode.PARAM_RANGE,
        lambda: validate(
            base_request(params={"date_from": "2023-01-01", "date_to": DATE_TO})
        ),
        layer="param",
    )


@test
def test_validate_date_order() -> None:
    exc = expect_error(
        ErrorCode.PARAM_RANGE,
        lambda: validate(
            base_request(params={"date_from": "2025-06-01", "date_to": "2025-03-31"})
        ),
        layer="param",
    )
    assert "date_from" in exc.message


@test
def test_validate_row_limit() -> None:
    expect_error(
        ErrorCode.ROW_LIMIT,
        lambda: validate(
            {
                "template": "sales_line_sample",
                "params": {"date_from": DATE_FROM, "date_to": DATE_TO, "limit": 100000},
            }
        ),
        layer="param",
    )


@test
def test_validate_limit_over_template_cap() -> None:
    expect_error(
        ErrorCode.ROW_LIMIT,
        lambda: validate(
            {
                "template": "daily_revenue",
                "params": {"date_from": DATE_FROM, "date_to": DATE_TO, "limit": 121},
            }
        ),
        layer="param",
    )


@test
def test_validate_unknown_top_key() -> None:
    exc = expect_error(
        ErrorCode.PARAM_UNKNOWN,
        lambda: validate(base_request(sql="DELETE FROM fact_sales")),
        layer="param",
    )
    assert exc.field_name == "sql"


@test
def test_validate_duplicate_limit() -> None:
    expect_error(
        ErrorCode.PARAM_DUPLICATE,
        lambda: validate(
            base_request(
                limit=5,
                params={"date_from": DATE_FROM, "date_to": DATE_TO, "limit": 5},
            )
        ),
        layer="param",
    )


@test
def test_validate_params_not_object() -> None:
    expect_error(
        ErrorCode.PARAM_TYPE,
        lambda: validate({"template": "sales_by_region", "params": ["date_from"]}),
        layer="param",
    )


# ---------------------------------------------------------------------------
# 执行引擎
# ---------------------------------------------------------------------------


@test
def test_engine_valid_query() -> None:
    engine, _audit = make_engine()
    result = engine.handle(base_request())
    assert result.row_count == 4
    assert result.truncated is False
    assert list(result.columns) == ["region", "orders", "revenue"]
    total = sum(row["revenue"] for row in result.rows)
    assert total > 0


@test
def test_engine_all_templates_match_contract_columns() -> None:
    engine, _audit = make_engine()
    for tpl in BUNDLE.contract.exposed_templates():
        params: dict[str, Any] = {"date_from": DATE_FROM, "date_to": DATE_TO}
        if any(p.name == "limit" for p in tpl.params):
            params["limit"] = 5
        result = engine.handle({"template": tpl.id, "params": params})
        assert set(result.columns) == set(tpl.selectable_fields), (
            f"{tpl.id} 结果列与契约不一致：{result.columns}"
        )


@test
def test_engine_truncates_rows() -> None:
    engine, _audit = make_engine()
    result = engine.handle(
        {
            "template": "sales_line_sample",
            "params": {"date_from": DATE_FROM, "date_to": DATE_TO, "limit": 5},
        }
    )
    assert result.row_count == 5 and result.truncated is True


@test
def test_engine_row_limit_rejected() -> None:
    engine, _audit = make_engine()
    expect_error(
        ErrorCode.ROW_LIMIT,
        lambda: engine.handle(
            {
                "template": "sales_line_sample",
                "params": {"date_from": DATE_FROM, "date_to": DATE_TO, "limit": 100000},
            }
        ),
    )


@test
def test_engine_timeout_interrupts() -> None:
    engine, _audit = make_engine()
    expect_error(
        ErrorCode.TIMEOUT,
        lambda: engine.handle(
            {"template": "benchmark_cross_join", "params": {}}, allow_unexposed=True
        ),
        layer="row_limit",
    )


@test
def test_engine_connection_reusable_after_timeout() -> None:
    conn = DS.connect_ro()
    guard = ReadOnlyGuard(conn, StatementInspector(BUNDLE.contract.allowed_views))
    guard.install_authorizer()
    try:
        try:
            guard.run_raw(
                BUNDLE.contract.templates["benchmark_cross_join"].sql, {}, max_rows=1, timeout_ms=120
            )
            raise AssertionError("基准查询应当在 120ms 内被中断")
        except ApiError as exc:
            assert exc.code == ErrorCode.TIMEOUT
        assert conn.execute("SELECT COUNT(*) FROM fact_sales").fetchone()[0] == 4000
    finally:
        conn.close()


@test
def test_engine_audits_allowed_and_rejected() -> None:
    engine, audit = make_engine()
    engine.handle(base_request())
    try:
        engine.handle({"template": "nope", "params": {}})
    except ApiError:
        pass
    assert audit.count() == 2
    assert audit.entries[0].outcome == "allowed"
    assert audit.entries[1].outcome == "rejected"
    assert audit.entries[1].error_code == ErrorCode.TEMPLATE_UNKNOWN


# ---------------------------------------------------------------------------
# 限流与审计
# ---------------------------------------------------------------------------


@test
def test_ratelimit_allows_then_blocks() -> None:
    limiter = SlidingWindowLimiter(3, 60, name="t")
    assert [limiter.check("k", 100.0).allowed for _ in range(3)] == [True, True, True]
    decision = limiter.check("k", 101.0)
    assert decision.allowed is False and decision.remaining == 0
    assert decision.retry_after_s >= 1


@test
def test_ratelimit_window_slides() -> None:
    limiter = SlidingWindowLimiter(2, 10, name="t")
    assert limiter.check("k", 0.0).allowed
    assert limiter.check("k", 1.0).allowed
    assert not limiter.check("k", 2.0).allowed
    assert limiter.check("k", 11.0).allowed, "窗口边界过后应重新放行"


@test
def test_ratelimit_per_key() -> None:
    limiter = SlidingWindowLimiter(1, 60, name="t")
    assert limiter.check("a", 0.0).allowed
    assert not limiter.check("a", 1.0).allowed
    assert limiter.check("b", 1.0).allowed


@test
def test_audit_seq_and_jsonl() -> None:
    clock = DeterministicClock()
    audit = AuditLog(clock)
    audit.record(
        at=clock.now(), request_id="req-0001", source="local", method="LOCAL", path="/v1/query",
        template_id="sales_by_region", outcome="allowed", status=200, rows=4,
    )
    audit.record(
        at=clock.now(), request_id="req-0002", source="http", method="GET", path="/v1/query",
        template_id=None, outcome="rejected", status=400, error_code=ErrorCode.PARAM_ENUM,
        message="bad enum",
    )
    rows = [json.loads(line) for line in audit.to_jsonl().splitlines()]
    assert [r["seq"] for r in rows] == [1, 2]
    assert rows[0]["rows"] == 4
    assert rows[1]["error_code"] == ErrorCode.PARAM_ENUM


@test
def test_audit_does_not_store_plaintext_token() -> None:
    clock = DeterministicClock()
    audit = AuditLog(clock)
    token = AuthToken(id="demo-readonly", token="demo-readonly-7f3a", scopes=("query",))
    audit.record(
        at=clock.now(), request_id="req-0001", source="http", method="GET", path="/v1/fields",
        template_id=None, outcome="allowed", status=200, token_id=token.id,
    )
    text = audit.to_jsonl()
    assert "demo-readonly-7f3a" not in text
    assert token.masked() == "demo***"


# ---------------------------------------------------------------------------
# HTTP 接口
# ---------------------------------------------------------------------------


@test
def test_api_healthz_without_auth() -> None:
    with api() as (base, _ctx):
        status, body, _headers = _http(base, "/healthz")
        assert status == 200
        assert body["data"]["read_only"] is True


@test
def test_api_requires_token() -> None:
    with api() as (base, _ctx):
        status, body, _headers = _http(base, "/v1/fields")
        assert status == 401
        assert body["error"]["code"] == ErrorCode.AUTH_MISSING


@test
def test_api_rejects_bad_token() -> None:
    with api() as (base, _ctx):
        status, body, _headers = _http(base, "/v1/fields", token="not-a-token")
        assert status == 401
        assert body["error"]["code"] == ErrorCode.AUTH_INVALID


@test
def test_api_query_ok() -> None:
    with api() as (base, _ctx):
        path = "/v1/query?" + urlencode(
            {"template": "sales_by_region", "date_from": DATE_FROM, "date_to": DATE_TO, "limit": "10"}
        )
        status, body, headers = _http(base, path, token=token_of("demo-readonly"))
        assert status == 200, body
        assert body["data"]["row_count"] == 4
        assert body["data"]["limit"] == 10, "URL 字符串应被显式转成整数"
        assert headers.get("X-Request-Id", "").startswith("req-")


@test
def test_api_query_injection_rejected() -> None:
    with api() as (base, _ctx):
        path = "/v1/query?" + urlencode(
            {
                "template": "sales_by_region",
                "date_from": DATE_FROM,
                "date_to": DATE_TO,
                "region": "华东'; DROP TABLE fact_sales; --",
            }
        )
        status, body, _headers = _http(base, path, token=token_of("demo-readonly"))
        assert status == 400
        assert body["error"]["code"] == ErrorCode.PARAM_INJECTION


@test
def test_api_method_not_allowed() -> None:
    with api() as (base, _ctx):
        status, body, headers = _http(
            base, "/v1/query", token=token_of("demo-readonly"), method="POST"
        )
        assert status == 405
        assert body["error"]["code"] == ErrorCode.METHOD_NOT_ALLOWED
        assert headers.get("Allow") == "GET"


@test
def test_api_scope_denied() -> None:
    with api() as (base, _ctx):
        path = "/v1/query?" + urlencode(
            {"template": "sales_by_region", "date_from": DATE_FROM, "date_to": DATE_TO}
        )
        status, body, _headers = _http(base, path, token=token_of("demo-audit-only"))
        assert status == 403
        assert body["error"]["code"] == ErrorCode.SCOPE_DENIED


@test
def test_api_audit_tail_requires_audit_scope() -> None:
    with api() as (base, _ctx):
        for _ in range(3):
            _http(base, "/healthz")
        status, body, _headers = _http(base, "/v1/audit/tail?n=3", token=token_of("demo-readonly"))
        assert status == 200 and isinstance(body["data"], list) and len(body["data"]) == 3
        assert body["data"][0]["seq"] < body["data"][-1]["seq"]


@test
def test_api_not_found() -> None:
    with api() as (base, _ctx):
        status, body, _headers = _http(base, "/v1/nope", token=token_of("demo-readonly"))
        assert status == 404
        assert body["error"]["code"] == ErrorCode.NOT_FOUND


@test
def test_api_rate_limited() -> None:
    with api() as (base, _ctx):
        token = token_of("demo-burst")
        statuses = [_http(base, "/v1/fields", token=token)[0] for _ in range(6)]
        assert statuses[:5] == [200] * 5
        assert statuses[5] == 429
        status, body, headers = _http(base, "/v1/fields", token=token)
        assert status == 429 and body["error"]["code"] == ErrorCode.RATE_LIMITED
        assert int(headers.get("Retry-After", "0")) >= 1


@test
def test_api_audit_records_every_request() -> None:
    with api() as (base, context):
        _http(base, "/healthz")
        _http(base, "/v1/fields")
        _http(base, "/v1/fields", token=token_of("demo-readonly"))
        _http(base, "/v1/nope", token=token_of("demo-readonly"))
        assert context.audit.count() == 4
        outcomes = context.audit.outcome_counts()
        assert outcomes.get("rejected") == 2
        assert all(entry.request_id.startswith("req-") for entry in context.audit.entries)


@test
def test_api_duplicate_query_param_rejected() -> None:
    with api() as (base, _ctx):
        path = f"/v1/query?template=sales_by_region&date_from={DATE_FROM}&date_to={DATE_TO}&limit=5&limit=9"
        status, body, _headers = _http(base, path, token=token_of("demo-readonly"))
        assert status == 400
        assert body["error"]["code"] == ErrorCode.PARAM_DUPLICATE


# ---------------------------------------------------------------------------
# 契约与取证
# ---------------------------------------------------------------------------


@test
def test_openapi_structure() -> None:
    spec = build_spec(BUNDLE.contract, BUNDLE.limits, BUNDLE.auth)
    assert spec["openapi"].startswith("3.")
    assert spec["x-read-only"] is True
    assert len(spec["x-guard-layers"]) == 3
    assert spec["components"]["securitySchemes"]["ApiKeyAuth"]["name"] == BUNDLE.auth.header
    assert spec["security"] == [{"ApiKeyAuth": []}]


@test
def test_openapi_only_get_operations() -> None:
    spec = build_spec(BUNDLE.contract, BUNDLE.limits, BUNDLE.auth)
    for path, item in spec["paths"].items():
        assert set(item) == {"get"}, f"{path} 出现了非 GET 操作：{sorted(item)}"


@test
def test_openapi_template_enum_matches_contract() -> None:
    spec = build_spec(BUNDLE.contract, BUNDLE.limits, BUNDLE.auth)
    params = spec["paths"]["/v1/query"]["get"]["parameters"]
    template = next(p for p in params if p["name"] == "template")
    assert set(template["schema"]["enum"]) == {t.id for t in BUNDLE.contract.exposed_templates()}


@test
def test_openapi_has_no_sql_parameter() -> None:
    spec = build_spec(BUNDLE.contract, BUNDLE.limits, BUNDLE.auth)
    for path, item in spec["paths"].items():
        for param in item["get"].get("parameters", []):
            assert param["name"] not in ("sql", "query", "statement"), f"{path} 暴露了 SQL 参数"


@test
def test_probe_readonly_uri_all_blocked() -> None:
    rows = probe_readonly_uri(
        DS,
        [
            "INSERT INTO fact_sales (sale_id) VALUES (1)",
            "UPDATE fact_sales SET quantity = 0",
            "DELETE FROM fact_sales",
            "DROP TABLE fact_sales",
        ],
    )
    assert len(rows) == 4
    assert all(row["blocked"] for row in rows)
    assert all(row["layer"] == "L1" for row in rows)


@test
def test_probe_authorizer_reports_actions() -> None:
    rows = probe_authorizer(
        DS,
        [
            "INSERT INTO fact_sales (sale_id) VALUES (1)",
            "UPDATE fact_sales SET quantity = 0",
            "DELETE FROM fact_sales",
        ],
    )
    assert all(row["blocked"] for row in rows)
    assert "SQLITE_INSERT" in rows[0]["error"]
    assert "SQLITE_UPDATE" in rows[1]["error"]
    assert "SQLITE_DELETE" in rows[2]["error"]


@test
def test_probe_statement_policy_codes() -> None:
    inspector = StatementInspector(BUNDLE.contract.allowed_views)
    rows = probe_statement_policy(
        inspector,
        [
            "SELECT 1",
            "DELETE FROM fact_sales",
            "SELECT 1; SELECT 2",
            "SELECT * FROM fact_sales -- x",
            "SELECT * FROM nope",
        ],
    )
    assert rows[0]["blocked"] is False
    assert [row["error"].split(":")[0] for row in rows[1:]] == [
        ErrorCode.SQL_NOT_ALLOWED,
        ErrorCode.SQL_MULTI_STATEMENT,
        ErrorCode.SQL_COMMENT,
        ErrorCode.VIEW_NOT_ALLOWED,
    ]


@test
def test_probe_row_cap_and_timeout() -> None:
    inspector = StatementInspector(BUNDLE.contract.allowed_views)
    detail_sql = BUNDLE.contract.templates["sales_line_sample"].sql
    cap = probe_row_cap(
        DS,
        inspector,
        detail_sql,
        5,
        {"date_from": DATE_FROM, "date_to": DATE_TO, "limit": 5},
    )[0]
    assert cap["truncated"] is True and cap["rows_returned"] == 5
    slow = probe_timeout(
        DS, inspector, BUNDLE.contract.templates["benchmark_cross_join"].sql, 120
    )[0]
    assert slow["blocked"] is True and slow["connection_reusable"] is True


@test
def test_no_third_party_imports() -> None:
    stdlib = set(sys.stdlib_module_names)
    modules: set[str] = set()
    for path in (ROOT / "structured_data_api").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    modules.add(node.module.split(".")[0])
    allowed = stdlib | {"__future__"}
    unexpected = sorted(modules - allowed)
    assert not unexpected, f"出现非标准库依赖：{unexpected}"


@test
def test_filenames_are_ascii_and_utf8_without_bom() -> None:
    checked = 0
    for path in ROOT.rglob("*"):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(ROOT).as_posix()
        assert rel.isascii(), f"文件名不是 ASCII：{rel}"
        if path.is_file() and path.suffix in {".py", ".json", ".jsonl", ".md", ".log", ".txt"}:
            raw = path.read_bytes()
            assert not raw.startswith(b"\xef\xbb\xbf"), f"文件带 UTF-8 BOM：{rel}"
            checked += 1
    assert checked > 20, f"只检查到 {checked} 个文件，路径可能不对"


@test
def test_no_emoji_in_text_files() -> None:
    emoji = re.compile("[\U0001f000-\U0001faff\u2600-\u27bf\ufe0f\u2b00-\u2bff]")
    offenders: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if path.suffix not in {".py", ".json", ".jsonl", ".md", ".log", ".txt"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        match = emoji.search(text)
        if match:
            offenders.append(f"{path.relative_to(ROOT)} -> {match.group(0)!r}")
    assert not offenders, "发现 emoji：" + "; ".join(offenders)


def main() -> int:
    print(f"# test_runner: {len(TESTS)} tests")
    failures: list[tuple[str, str]] = []
    for name, fn in TESTS:
        try:
            fn()
            print(f"PASS {name}")
        except Exception:
            failures.append((name, traceback.format_exc()))
            print(f"FAIL {name}")
    total = len(TESTS)
    passed = total - len(failures)
    if failures:
        print("")
        print("=" * 70)
        for name, tb in failures:
            print(f"[FAIL] {name}")
            print(tb)
    print("")
    print(f"{passed}/{total} tests passed")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

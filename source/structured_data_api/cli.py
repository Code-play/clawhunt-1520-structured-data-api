"""命令行入口。

    python -m structured_data_api demo        # 一键复跑：三层取证 + 样例 + HTTP + 全部产物
    python -m structured_data_api serve       # 只读 HTTP 服务（前台）
    python -m structured_data_api query --template sales_by_region --param date_from=2025-01-01 ...
    python -m structured_data_api contract    # 打印 OpenAPI 3 契约
    python -m structured_data_api layers      # 只跑三层防线取证

演示用确定性时钟（固定起点 + 每次请求 1s 步进），因此 query_results / rejected_requests /
audit_log / layer_evidence / contract_openapi 连续两次运行逐字节一致，可哈希比对。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .api import ApiContext, start_in_thread, stop_server
from .audit import AuditLog
from .config import ConfigBundle, load_config_dir
from .datasource import DataSource, temporary_database
from .guard import (
    QueryEngine,
    probe_authorizer,
    probe_query_only,
    probe_readonly_uri,
    probe_row_cap,
    probe_statement_policy,
    probe_timeout,
)
from .model import ApiError, ErrorCode
from .openapi import build_spec
from .trace import DeterministicClock, LayerTrace, Printer, SystemClock, iso_z

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = ROOT / "config"
DEFAULT_SAMPLES = ROOT / "samples" / "queries.jsonl"
DEFAULT_OUT = ROOT / "out"

DEMO_START = "2025-01-01"
DEMO_END = "2025-03-31"

WRITE_PROBES = (
    "INSERT INTO fact_sales (sale_id, date_key, region_key, channel_key, product_key,"
    " customer_key, quantity, amount_cents) VALUES (999999, 1, 1, 1, 1, 1, 1, 100)",
    "UPDATE fact_sales SET quantity = 0 WHERE sale_id = 1",
    "DELETE FROM fact_sales WHERE sale_id = 1",
    "DROP TABLE fact_sales",
)

STATEMENT_PROBES = (
    "SELECT region, SUM(orders) AS orders FROM v_sales_daily GROUP BY region ORDER BY orders DESC",
    "WITH t AS (SELECT region, SUM(revenue_cents) AS r FROM v_sales_daily GROUP BY region)"
    " SELECT region, r FROM t ORDER BY r DESC LIMIT 3",
    "DELETE FROM fact_sales",
    "DROP TABLE fact_sales",
    "PRAGMA table_info(fact_sales)",
    "SELECT 1; DELETE FROM fact_sales",
    "SELECT * FROM fact_sales -- 注释注入",
    "SELECT * FROM secret_salary_table",
)


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    text = "".join(json.dumps(row, ensure_ascii=False, sort_keys=False) + "\n" for row in rows)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_samples(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{lineno} 样例不是合法 JSON：{exc}") from exc
    if not rows:
        raise SystemExit(f"{path} 里没有任何样例")
    return rows


def _section(out: Printer, title: str) -> None:
    out("")
    out("=" * 78)
    out(title)
    out("=" * 78)


def _http(
    base_url: str,
    path: str,
    *,
    token: str | None = None,
    method: str = "GET",
    body: bytes | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if token:
        headers["X-API-Token"] = token
    data = body if body is not None else (b"{}" if method not in ("GET", "HEAD") else None)
    request = Request(base_url + path, headers=headers, method=method, data=data)
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return {
                "status": response.status,
                "json": json.loads(raw) if raw else {},
                "headers": dict(response.headers),
            }
    except HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {"raw": raw}
        return {"status": exc.code, "json": payload, "headers": dict(exc.headers)}
    except URLError as exc:
        return {"status": 0, "json": {"error": str(exc)}, "headers": {}}


def _coerce(value: str) -> Any:
    try:
        return int(value)
    except ValueError:
        return value


def _context(bundle: ConfigBundle, ds: DataSource, audit: AuditLog, clock: Any) -> ApiContext:
    engine = QueryEngine(ds, bundle.contract, bundle.limits, audit, clock)
    return ApiContext(
        engine=engine,
        contract=bundle.contract,
        limits=bundle.limits,
        auth=bundle.auth,
        audit=audit,
        clock=clock,
    )


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------


def _demo_probes(out: Printer, ds: DataSource, engine: QueryEngine, trace: LayerTrace, clock: Any, out_dir: Path) -> None:
    def record(evidence: dict[str, Any], text: str) -> None:
        trace.add(evidence)
        out(text)

    _section(out, "1. 三层只读防线（逐层单独取证）")
    out("")
    out("1.1 第一层-a：只读连接 file:...?mode=ro（SQLite 文件层面就没有写权限）")
    for ev in probe_readonly_uri(ds, WRITE_PROBES):
        record(ev, f"  {ev['statement'].split()[0]:<7} blocked={str(ev['blocked']).lower():<5} {ev['error']}")
    out("")
    out("1.2 第一层-b：可写连接先执行 PRAGMA query_only=ON，再尝试写入")
    for ev in probe_query_only(ds, WRITE_PROBES[:1]):
        record(ev, f"  {ev['statement'].split()[0]:<7} blocked={str(ev['blocked']).lower():<5} {ev['error']}")
    out("")
    out("1.3 第一层-c：可写连接 + sqlite3 set_authorizer 回调（非 SELECT 动作在 prepare 阶段被拒）")
    for ev in probe_authorizer(ds, WRITE_PROBES):
        record(ev, f"  {ev['statement'].split()[0]:<7} blocked={str(ev['blocked']).lower():<5} {ev['error']}")
    out(f"  事实表行数不变：{ds.stats['fact_sales']} 行（写操作一条都没落地）")
    out("")
    out("1.4 第二层：语句白名单（解析层，未连接数据库即可判定）")
    records = probe_statement_policy(engine.inspector, STATEMENT_PROBES)
    for ev in records:
        if ev["blocked"]:
            detail = ev["error"]
        else:
            detail = f"允许：first_keyword={ev['first_keyword']} views={','.join(ev['views']) or '-'}"
        record(ev, f"  {'拒绝' if ev['blocked'] else '允许'}  {ev['statement'][:56]:<58} {detail}")
    out("")
    out("1.5 第三层：行数与超时上限")

    detail_sql = engine.contract.templates["sales_line_sample"].sql
    batch = {"date_from": DEMO_START, "date_to": DEMO_END, "limit": 5}
    row_ev = probe_row_cap(ds, engine.inspector, detail_sql, 5, batch)
    for ev in row_ev:
        record(ev, f"  行数上限 5：返回 {ev['rows_returned']} 行，truncated={str(ev['truncated']).lower()}（明细查询本身不写 LIMIT）")

    try:
        at = clock.now()
        clock.advance()
        engine.handle(
            {
                "template": "sales_line_sample",
                "params": {"date_from": DEMO_START, "date_to": DEMO_END, "limit": 100000},
            },
            source="local",
            at=at,
            allow_unexposed=True,
        )
        out("  行数超限：未被拒绝（异常）")
    except ApiError as exc:
        record(
            {
                "layer": "L3",
                "check": "row_limit_reject",
                "statement": "sales_line_sample limit=100000",
                "blocked": True,
                "mechanism": "limit > min(模板上限, 硬上限) 即校验期拒绝",
                "error": f"{exc.code}: {exc.message}",
            },
            f"  行数超限：拒绝 {exc.code}（{exc.message}）",
        )

    benchmark_sql = engine.contract.templates["benchmark_cross_join"].sql
    timeout_ms = engine.contract.templates["benchmark_cross_join"].timeout_ms or 150
    for ev in probe_timeout(ds, engine.inspector, benchmark_sql, timeout_ms):
        record(ev, f"  超时上限 {timeout_ms}ms：blocked={str(ev['blocked']).lower()}，"
                    f"连接仍可用={str(ev['connection_reusable']).lower()}（{ev['error']}）")

    counts = trace.by_layer()
    out("")
    out(f"  取证条目：L1={counts.get('L1', 0)}  L2={counts.get('L2', 0)}  L3={counts.get('L3', 0)}  合计={len(trace.entries)}")
    out(f"  L1 全部拒写：{[e['blocked'] for e in trace.entries if e['layer'] == 'L1' and e['check'] in ('readonly_uri', 'query_only', 'authorizer')].count(False) == 0}")


def _demo_samples(
    out: Printer,
    engine: QueryEngine,
    ds: DataSource,
    clock: Any,
    samples: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    _section(out, "2. 参数校验与调用结果（samples/queries.jsonl）")
    results: list[dict[str, Any]] = []
    rejections: list[dict[str, Any]] = []
    mismatches: list[str] = []
    out("")
    out(f"  {'样例':<7}{'模板':<25}{'结果/错误码':<26}{'行数':<6}说明")
    out("  " + "-" * 88)

    def row(sid: str, template: str, code: str, rows_text: str, note: str) -> None:
        out(f"  {sid:<7}{template[:24]:<25}{code:<26}{rows_text:<6}{note[:36]}")

    for sample in samples:
        sid = str(sample.get("id", "?"))
        mode = str(sample.get("mode", "template"))
        expect = sample.get("expect", {})
        if mode == "raw_sql":
            sql = str(sample.get("sql", ""))
            verdict = engine.inspector.inspect(sql)
            ok = verdict.error_code == expect.get("error_code")
            if not ok:
                mismatches.append(f"{sid}: 期望 {expect.get('error_code')} 实际 {verdict.error_code}")
            reason = verdict.reason
            rejections.append(
                {
                    "id": sid,
                    "request_id": "-",
                    "template_id": None,
                    "params": {"sql": sql},
                    "status": 403,
                    "error_code": verdict.error_code,
                    "layer": "statement",
                    "field": None,
                    "message": reason,
                }
            )
            out(f"  {sid:<7}{'(raw sql)':<25}{str(verdict.error_code):<26}{'-':<6}{reason[:36]}")
            continue
        if mode == "authorizer":
            sql = str(sample.get("sql", ""))
            ev = probe_authorizer(ds, [sql])[0]
            ok = bool(ev["blocked"]) and expect.get("error_code") == ErrorCode.SQL_AUTHORIZER
            if not ok:
                mismatches.append(f"{sid}: authorizer 未拒绝")
            rejections.append(
                {
                    "id": sid,
                    "request_id": "-",
                    "template_id": None,
                    "params": {"sql": sql},
                    "status": 403,
                    "error_code": ErrorCode.SQL_AUTHORIZER,
                    "layer": "authorizer",
                    "field": None,
                    "message": ev["error"],
                }
            )
            out(f"  {sid:<7}{'(authorizer)':<25}{ErrorCode.SQL_AUTHORIZER:<26}{'-':<6}{str(ev['error'])[:36]}")
            continue

        raw = sample.get("request", {})
        at = clock.now()
        clock.advance()
        try:
            result = engine.handle(raw, source="local", at=at)
        except ApiError as exc:
            ok = exc.code == expect.get("error_code")
            if not ok:
                mismatches.append(f"{sid}: 期望 {expect.get('error_code')} 实际 {exc.code}")
            rejections.append(
                {
                    "id": sid,
                    "request_id": "-",
                    "template_id": raw.get("template") if isinstance(raw, dict) else None,
                    "params": raw.get("params") if isinstance(raw, dict) else None,
                    "status": exc.http_status,
                    "error_code": exc.code,
                    "layer": exc.layer,
                    "field": exc.field_name,
                    "message": exc.message,
                }
            )
            out(f"  {sid:<7}{str(raw.get('template', '-'))[:24]:<25}{exc.code:<26}{'-':<6}{exc.message[:36]}")
            continue
        ok = expect.get("status") == 200
        if expect.get("truncated") is not None and bool(expect["truncated"]) != result.truncated:
            ok = False
            mismatches.append(f"{sid}: truncated 期望 {expect['truncated']} 实际 {result.truncated}")
        if expect.get("row_count") is not None and int(expect["row_count"]) != result.row_count:
            ok = False
            mismatches.append(f"{sid}: 行数期望 {expect['row_count']} 实际 {result.row_count}")
        if not ok:
            mismatches.append(f"{sid}: 期望成功但结果不符")
        results.append(
            {
                "id": sid,
                "request_id": "-",
                "template_id": result.template_id,
                "params": dict(raw.get("params", {})) if isinstance(raw, dict) else {},
                "limit": result.limit,
                "status": 200,
                "row_count": result.row_count,
                "truncated": result.truncated,
                "columns": list(result.columns),
                "rows": result.rows,
            }
        )
        out(f"  {sid:<7}{result.template_id[:24]:<25}{'200':<26}{result.row_count:<6}"
            f"{sample.get('note', '')[:36]}")

    out("")
    out(f"  合计 {len(samples)} 条：合法 {len(results)} 条，拒绝 {len(rejections)} 条，期望不符 {len(mismatches)} 条")
    if mismatches:
        for item in mismatches:
            out(f"  [不符] {item}")
    return results, rejections


def _demo_http(
    out: Printer,
    context: ApiContext,
    clock: Any,
    tokens: dict[str, str],
) -> list[dict[str, Any]]:
    _section(out, "3. 实时只读 HTTP 接口（GET + 令牌 + scope + 限流 + 审计）")
    server, thread, base_url = start_in_thread(context)
    calls: list[dict[str, Any]] = []
    try:
        out("")
        out("  服务：127.0.0.1:<临时端口>（后台线程，仅绑定回环地址）")
        out(f"  只读方法白名单：{', '.join(context.limits.allow_methods)}")
        out("")
        q = urlencode(
            {
                "template": "sales_by_region",
                "date_from": DEMO_START,
                "date_to": DEMO_END,
                "limit": "10",
            }
        )
        plan = [
            ("健康检查（免鉴权）", "/healthz", None, "GET"),
            ("字段白名单", "/v1/fields", tokens["readonly"], "GET"),
            ("模板列表", "/v1/queries", tokens["readonly"], "GET"),
            ("有效查询", f"/v1/query?{q}", tokens["readonly"], "GET"),
            ("明细截断（limit=5）", "/v1/query?" + urlencode(
                {"template": "sales_line_sample", "date_from": DEMO_START, "date_to": DEMO_END, "limit": "5"}
            ), tokens["readonly"], "GET"),
            ("缺少令牌", f"/v1/query?{q}", None, "GET"),
            ("令牌无效", f"/v1/query?{q}", "not-a-token", "GET"),
            ("方法不允许（POST）", "/v1/query", tokens["readonly"], "POST"),
            ("scope 不足（audit-only 查数）", f"/v1/query?{q}", tokens["audit_only"], "GET"),
            ("审计尾部", "/v1/audit/tail?n=2", tokens["readonly"], "GET"),
            ("注入式参数", "/v1/query?" + urlencode(
                {"template": "sales_by_region", "date_from": DEMO_START, "date_to": DEMO_END,
                 "region": "华东'; DROP TABLE fact_sales; --"}
            ), tokens["readonly"], "GET"),
            ("越过模板字段", "/v1/query?" + urlencode(
                {"template": "daily_revenue", "date_from": DEMO_START, "date_to": DEMO_END, "region": "华东"}
            ), tokens["readonly"], "GET"),
            ("未知路径", "/v1/nope", tokens["readonly"], "GET"),
        ]
        for label, path, token, method in plan:
            response = _http(base_url, path, token=token, method=method)
            body = response["json"]
            error = (body.get("error") or {}).get("code")
            data = body.get("data")
            rows = None
            if isinstance(data, dict) and "row_count" in data:
                rows = data.get("row_count")
                extra = f" rows={rows} truncated={str(data.get('truncated')).lower()}"
            elif isinstance(data, list):
                extra = f" items={len(data)}"
            elif isinstance(data, dict):
                extra = f" keys={len(data)}"
            else:
                extra = ""
            out(f"  {label:<26} {method:<5} -> {response['status']:<4}"
                f"{('[' + error + ']') if error else ''}{extra}")
            calls.append(
                {
                    "label": label,
                    "method": method,
                    "path": path.split("?")[0],
                    "token_id": token or "-",
                    "status": response["status"],
                    "error_code": error,
                    "rows": rows,
                    "allow_header": response["headers"].get("Allow"),
                    "retry_after": response["headers"].get("Retry-After"),
                }
            )

        burst = [tokens["burst"]]
        statuses: list[int] = []
        for _ in range(6):
            response = _http(
                base_url,
                "/v1/query?" + urlencode(
                    {"template": "segment_summary", "date_from": DEMO_START, "date_to": DEMO_END}
                ),
                token=burst[0],
            )
            statuses.append(response["status"])
            if response["status"] == 429:
                retry_after = response["headers"].get("Retry-After")
                calls.append(
                    {
                        "label": "限流（突发令牌第 6 次）",
                        "method": "GET",
                        "path": "/v1/query",
                        "token_id": "demo-burst",
                        "status": 429,
                        "error_code": (response["json"].get("error") or {}).get("code"),
                        "rows": None,
                        "allow_header": None,
                        "retry_after": retry_after,
                    }
                )
        out(f"  {'限流（5 次/60s 令牌）':<26} {'GET':<5} -> {statuses.count(200)}x200, {statuses.count(429)}x429"
            f"（Retry-After={calls[-1]['retry_after']}s）")
    finally:
        stop_server(server, thread)
    out("")
    out(f"  审计条目累计：{context.audit.count()} 条（成功 {context.audit.outcome_counts().get('allowed', 0)}"
        f" / 拒绝 {context.audit.outcome_counts().get('rejected', 0)}）")
    return calls


def cmd_demo(args: argparse.Namespace) -> int:
    out = Printer()
    config_dir = Path(args.config_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle = load_config_dir(config_dir)
    samples = load_samples(Path(args.samples))
    clock = DeterministicClock()
    trace = LayerTrace(clock)

    with temporary_database() as ds:
        audit = AuditLog(clock, max_entries=bundle.limits.audit_max_entries)
        context = _context(bundle, ds, audit, clock)
        engine = context.engine

        out("# 结构化数据与实时接口 · 一键复跑演示（ClawHunt #1520）")
        out(f"Python {sys.version.split()[0]} | 仅标准库 | 零第三方依赖")
        out(f"配置目录：{config_dir}")
        out(f"数据源：临时 sqlite 星型模型（合成数据，{ds.stats['fact_sales']} 条销售明细，{ds.stats['views']} 个视图）")
        out(f"加载：{bundle.describe()}")
        out(f"时钟：{clock.name}（{iso_z(clock.now())} 起，每次请求步进 1s）")

        _demo_probes(out, ds, engine, trace, clock, out_dir)
        results, rejections = _demo_samples(out, engine, ds, clock, samples)
        tokens = {
            "readonly": _token_of(bundle, "demo-readonly"),
            "audit_only": _token_of(bundle, "demo-audit-only"),
            "burst": _token_of(bundle, "demo-burst"),
        }
        calls = _demo_http(out, context, clock, tokens)

        spec = build_spec(bundle.contract, bundle.limits, bundle.auth)
        write_json(out_dir / "contract_openapi.json", spec)
        write_jsonl(out_dir / "query_results.jsonl", results)
        write_jsonl(out_dir / "rejected_requests.jsonl", rejections)
        write_jsonl(out_dir / "audit_log.jsonl", [e.to_dict() for e in audit.entries])
        write_jsonl(out_dir / "layer_evidence.jsonl", trace.entries)
        write_jsonl(out_dir / "http_calls.jsonl", calls)

        _section(out, "4. 产物清单")
        out("")
        artifacts = [
            ("contract_openapi.json", f"OpenAPI 3.0.3 契约，{len(spec['paths'])} 个路径"),
            ("query_results.jsonl", f"合法查询的真实结果 {len(results)} 条"),
            ("rejected_requests.jsonl", f"被拒请求 + 错误码 + 原因 {len(rejections)} 条"),
            ("audit_log.jsonl", f"审计日志 {audit.count()} 条（含 HTTP 与本地调用）"),
            ("layer_evidence.jsonl", f"三层防线取证 {len(trace.entries)} 条"),
            ("http_calls.jsonl", f"HTTP 调用明细 {len(calls)} 条"),
        ]
        for name, desc in artifacts:
            path = out_dir / name
            out(f"  {name:<26}{path.stat().st_size:>7} bytes  {desc}")
        out("")
        by_layer = trace.by_layer()
        out(f"结论：三层防线各自独立可复现（L1={by_layer.get('L1', 0)} / L2={by_layer.get('L2', 0)}"
            f" / L3={by_layer.get('L3', 0)} 条证据）；参数校验命中 {len(rejections)} 条；"
            f"HTTP 全部请求留审计。")
        out("")

    log_path = out_dir / "demo_run.log"
    log_path.write_text(out.text(), encoding="utf-8")
    return 0


def _token_of(bundle: ConfigBundle, token_id: str) -> str:
    for token in bundle.auth.tokens.values():
        if token.id == token_id:
            return token.token
    raise SystemExit(f"auth.json 里缺少令牌 {token_id}")


# ---------------------------------------------------------------------------
# 其它子命令
# ---------------------------------------------------------------------------


def cmd_serve(args: argparse.Namespace) -> int:
    bundle = load_config_dir(Path(args.config_dir))
    clock = SystemClock()
    with temporary_database() as ds:
        audit = AuditLog(clock, max_entries=bundle.limits.audit_max_entries)
        context = _context(bundle, ds, audit, clock)
        server, thread, base_url = start_in_thread(context, port=args.port)
        print(f"只读 API 已启动：{base_url}")
        print(f"令牌头：{bundle.auth.header}；只允许方法：{', '.join(bundle.limits.allow_methods)}")
        print(f"契约：{base_url}/v1/openapi.json")
        print(f"演示令牌：{_token_of(bundle, 'demo-readonly')}")
        print("按 Ctrl+C 停止")
        try:
            thread.join()
        except KeyboardInterrupt:
            print("收到中断，正在停止")
        finally:
            stop_server(server, thread)
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    bundle = load_config_dir(Path(args.config_dir))
    clock = SystemClock()
    params: dict[str, Any] = {}
    for item in args.param or []:
        if "=" not in item:
            raise SystemExit(f"--param 需要 key=value 形式，收到 {item!r}")
        key, value = item.split("=", 1)
        params[key] = _coerce(value)
    raw: dict[str, Any] = {"template": args.template, "params": params}
    if args.limit is not None:
        raw["limit"] = args.limit
    with temporary_database() as ds:
        audit = AuditLog(clock)
        engine = QueryEngine(ds, bundle.contract, bundle.limits, audit, clock)
        try:
            result = engine.handle(raw, source="local", allow_unexposed=args.allow_unexposed)
        except ApiError as exc:
            print(json.dumps({"status": exc.http_status, "error": exc.to_dict()}, ensure_ascii=False, indent=2))
            return 2
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_contract(args: argparse.Namespace) -> int:
    bundle = load_config_dir(Path(args.config_dir))
    spec = build_spec(bundle.contract, bundle.limits, bundle.auth)
    text = json.dumps(spec, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"已写入 {args.out}")
    else:
        print(text, end="")
    return 0


def cmd_layers(args: argparse.Namespace) -> int:
    bundle = load_config_dir(Path(args.config_dir))
    clock = DeterministicClock()
    trace = LayerTrace(clock)
    with temporary_database() as ds:
        audit = AuditLog(clock)
        engine = QueryEngine(ds, bundle.contract, bundle.limits, audit, clock)
        for ev in probe_readonly_uri(ds, WRITE_PROBES):
            trace.add(ev)
        for ev in probe_query_only(ds, WRITE_PROBES[:1]):
            trace.add(ev)
        for ev in probe_authorizer(ds, WRITE_PROBES):
            trace.add(ev)
        for ev in probe_statement_policy(engine.inspector, STATEMENT_PROBES):
            trace.add(ev)
        detail_sql = bundle.contract.templates["sales_line_sample"].sql
        batch = {"date_from": DEMO_START, "date_to": DEMO_END, "limit": 5}
        for ev in probe_row_cap(ds, engine.inspector, detail_sql, 5, batch):
            trace.add(ev)
        benchmark_sql = bundle.contract.templates["benchmark_cross_join"].sql
        for ev in probe_timeout(ds, engine.inspector, benchmark_sql, bundle.limits.benchmark_timeout_ms):
            trace.add(ev)
    print(trace.to_jsonl(), end="")
    print(f"# {len(trace.entries)} 条取证，{trace.by_layer()}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="structured_data_api",
        description="ClawHunt #1520 结构化数据只读接口（纯标准库）",
    )
    sub = parser.add_subparsers(dest="command")

    demo = sub.add_parser("demo", help="一键复跑演示并生成 out/ 全部产物")
    demo.add_argument("--config-dir", default=str(DEFAULT_CONFIG))
    demo.add_argument("--samples", default=str(DEFAULT_SAMPLES))
    demo.add_argument("--out-dir", default=str(DEFAULT_OUT))
    demo.set_defaults(func=cmd_demo)

    serve = sub.add_parser("serve", help="启动只读 HTTP 服务")
    serve.add_argument("--config-dir", default=str(DEFAULT_CONFIG))
    serve.add_argument("--port", type=int, default=8080)
    serve.set_defaults(func=cmd_serve)

    query = sub.add_parser("query", help="本地执行一次查询（不经过 HTTP）")
    query.add_argument("--config-dir", default=str(DEFAULT_CONFIG))
    query.add_argument("--template", required=True)
    query.add_argument("--param", action="append", default=[], metavar="KEY=VALUE")
    query.add_argument("--limit", type=int, default=None)
    query.add_argument("--allow-unexposed", action="store_true")
    query.set_defaults(func=cmd_query)

    contract = sub.add_parser("contract", help="输出 OpenAPI 3 契约 JSON")
    contract.add_argument("--config-dir", default=str(DEFAULT_CONFIG))
    contract.add_argument("--out", default=None)
    contract.set_defaults(func=cmd_contract)

    layers = sub.add_parser("layers", help="只跑三层防线取证")
    layers.add_argument("--config-dir", default=str(DEFAULT_CONFIG))
    layers.set_defaults(func=cmd_layers)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ["demo"]
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())

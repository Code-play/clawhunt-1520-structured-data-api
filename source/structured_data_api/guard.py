"""三层只读防线。

第一层 数据库层面拒绝写入（不依赖调用方自觉）
  a) 只读连接：`file:...?mode=ro`，SQLite 在文件句柄层面就没有写权限；
  b) `PRAGMA query_only=ON`，把可写连接降级为只读；
  c) `set_authorizer` 回调：只放行 SELECT / READ / FUNCTION / RECURSIVE，
     其余动作（INSERT/UPDATE/DELETE/DROP/ALTER/PRAGMA/ATTACH/TRANSACTION...）
     在 prepare 阶段就被 SQLITE_DENY 拒绝。

第二层 语句白名单（解析层，比数据库更早）
  - 只允许单条语句；末尾一个分号可以；
  - 首关键字必须是 SELECT 或 WITH；
  - 出现注释（-- 或 /* */）直接拒；
  - 出现写/管理关键字（INSERT/UPDATE/DELETE/DROP/PRAGMA/ATTACH/VACUUM...）直接拒；
  - 语句引用的视图/表必须在 allowed_views 白名单内。

第三层 行级与时间上限
  - 请求 limit 超过模板上限或全局硬上限 -> 校验期拒绝（E_ROW_LIMIT）；
  - 执行时 fetchmany(max_rows + 1)，多出的行被截断并返回 truncated=true；
  - 用 sqlite3 的 progress handler 做执行期超时中断（E_TIMEOUT），
    中断后连接仍可用，不会留下半开事务。

三层互不依赖：即使某一层被误关，另外两层仍然生效（verify 逐个单独断言）。
"""

from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .datasource import DataSource
from .model import (
    AccessContract,
    ApiError,
    AuditEntry,
    ErrorCode,
    Limits,
    QueryRequest,
    QueryResult,
)
from .param_validate import validate_request

# ---------------------------------------------------------------------------
# 语句白名单
# ---------------------------------------------------------------------------

DENIED_KEYWORDS: frozenset[str] = frozenset(
    {
        "insert",
        "update",
        "delete",
        "drop",
        "alter",
        "create",
        "replace",
        "truncate",
        "attach",
        "detach",
        "pragma",
        "vacuum",
        "reindex",
        "analyze",
        "grant",
        "revoke",
        "begin",
        "commit",
        "rollback",
        "savepoint",
        "release",
        "into",
        "load_extension",
        "writefile",
        "readfile",
    }
)

SQL_KEYWORDS: frozenset[str] = DENIED_KEYWORDS | frozenset(
    {
        "select",
        "with",
        "recursive",
        "from",
        "where",
        "group",
        "order",
        "by",
        "limit",
        "offset",
        "having",
        "join",
        "left",
        "right",
        "inner",
        "outer",
        "cross",
        "on",
        "using",
        "as",
        "and",
        "or",
        "not",
        "null",
        "is",
        "in",
        "between",
        "like",
        "glob",
        "union",
        "all",
        "distinct",
        "case",
        "when",
        "then",
        "else",
        "end",
        "asc",
        "desc",
        "exists",
        "cast",
        "collate",
        "escape",
        "values",
    }
)

_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)?|[(),;]|[^\sA-Za-z0-9_(),;]+")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

ALLOWED_AUTHORIZER_ACTIONS = frozenset(
    {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_FUNCTION,
        sqlite3.SQLITE_RECURSIVE,
    }
)

ACTION_NAMES: dict[int, str] = {
    sqlite3.SQLITE_SELECT: "SQLITE_SELECT",
    sqlite3.SQLITE_READ: "SQLITE_READ",
    sqlite3.SQLITE_FUNCTION: "SQLITE_FUNCTION",
    sqlite3.SQLITE_RECURSIVE: "SQLITE_RECURSIVE",
    sqlite3.SQLITE_INSERT: "SQLITE_INSERT",
    sqlite3.SQLITE_UPDATE: "SQLITE_UPDATE",
    sqlite3.SQLITE_DELETE: "SQLITE_DELETE",
    sqlite3.SQLITE_DROP_TABLE: "SQLITE_DROP_TABLE",
    sqlite3.SQLITE_DROP_VIEW: "SQLITE_DROP_VIEW",
    sqlite3.SQLITE_ALTER_TABLE: "SQLITE_ALTER_TABLE",
    sqlite3.SQLITE_CREATE_TABLE: "SQLITE_CREATE_TABLE",
    sqlite3.SQLITE_CREATE_VIEW: "SQLITE_CREATE_VIEW",
    sqlite3.SQLITE_PRAGMA: "SQLITE_PRAGMA",
    sqlite3.SQLITE_ATTACH: "SQLITE_ATTACH",
    sqlite3.SQLITE_DETACH: "SQLITE_DETACH",
    sqlite3.SQLITE_TRANSACTION: "SQLITE_TRANSACTION",
    sqlite3.SQLITE_SAVEPOINT: "SQLITE_SAVEPOINT",
    sqlite3.SQLITE_REINDEX: "SQLITE_REINDEX",
    sqlite3.SQLITE_ANALYZE: "SQLITE_ANALYZE",
}


def action_name(action: int) -> str:
    return ACTION_NAMES.get(action, f"SQLITE_ACTION_{action}")


def split_literals(sql: str) -> tuple[str, list[str]]:
    """把字符串字面量替换成空格，返回 (代码骨架, 注释片段)。

    这样关键字扫描不会把 `'drop table'` 当成写操作，也便于统计语句条数。
    引号包围的标识符保留内容（它是标识符而不是值）。
    """
    out: list[str] = []
    comments: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch == "'":
            out.append(" ")
            i += 1
            while i < n:
                if sql[i] == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            out.append(" ")
        elif ch == "-" and sql.startswith("--", i):
            j = sql.find("\n", i)
            j = n if j < 0 else j
            comments.append(sql[i:j])
            out.append(" ")
            i = j
        elif ch == "/" and sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            j = n if j < 0 else j + 2
            comments.append(sql[i:j])
            out.append(" ")
            i = j
        elif ch in ("`", "["):
            close = "`" if ch == "`" else "]"
            j = sql.find(close, i + 1)
            j = n if j < 0 else j
            out.append(" " + sql[i + 1 : j] + " ")
            i = j + 1
        elif ch == '"':
            j = i + 1
            buf: list[str] = []
            while j < n:
                if sql[j] == '"':
                    if j + 1 < n and sql[j + 1] == '"':
                        buf.append('"')
                        j += 2
                        continue
                    j += 1
                    break
                buf.append(sql[j])
                j += 1
            out.append(" " + "".join(buf) + " ")
            i = j
        else:
            out.append(ch)
            i += 1
    return "".join(out), comments


@dataclass
class StatementVerdict:
    ok: bool
    first_keyword: str = ""
    statement_count: int = 0
    views: tuple[str, ...] = ()
    ctes: tuple[str, ...] = ()
    error_code: str | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "first_keyword": self.first_keyword,
            "statement_count": self.statement_count,
            "views": list(self.views),
            "ctes": list(self.ctes),
            "error_code": self.error_code,
            "reason": self.reason,
        }

    def raise_if_blocked(self) -> None:
        if not self.ok:
            raise ApiError(
                self.error_code or ErrorCode.SQL_NOT_ALLOWED,
                self.reason,
                layer="statement",
                http_status=403,
            )


class StatementInspector:
    """第二层：语句白名单解析（不执行，只看形态）。"""

    def __init__(self, allowed_views: Sequence[str]) -> None:
        self.allowed_views = frozenset(allowed_views)

    def inspect(self, sql: str) -> StatementVerdict:
        code, comments = split_literals(sql or "")
        tokens = _WORD_RE.findall(code)
        if comments:
            return StatementVerdict(
                ok=False,
                statement_count=0,
                error_code=ErrorCode.SQL_COMMENT,
                reason=f"语句中不允许出现注释（{comments[0][:20]}），拒绝执行",
            )
        segments: list[list[str]] = [[]]
        for tok in tokens:
            if tok == ";":
                segments.append([])
            else:
                segments[-1].append(tok)
        bodies = [seg for seg in segments if seg]
        count = len(bodies)
        if count == 0:
            return StatementVerdict(
                ok=False, statement_count=0, error_code=ErrorCode.SQL_NOT_ALLOWED,
                reason="空语句",
            )
        if count > 1:
            return StatementVerdict(
                ok=False,
                statement_count=count,
                error_code=ErrorCode.SQL_MULTI_STATEMENT,
                reason=f"检测到 {count} 条语句，一条请求只允许一条只读语句",
            )
        body = bodies[0]
        first = body[0].upper()
        if first not in ("SELECT", "WITH"):
            return StatementVerdict(
                ok=False,
                first_keyword=first,
                statement_count=1,
                error_code=ErrorCode.SQL_NOT_ALLOWED,
                reason=f"语句必须以 SELECT 或 WITH 开头，实际首关键字是 {first}",
            )
        upper_tokens = [t.upper() for t in body]
        if first == "WITH" and "SELECT" not in upper_tokens:
            return StatementVerdict(
                ok=False,
                first_keyword=first,
                statement_count=1,
                error_code=ErrorCode.SQL_NOT_ALLOWED,
                reason="WITH 子句之后没有 SELECT，不是只读查询",
            )
        for tok, upper in zip(body, upper_tokens):
            if upper.lower() in DENIED_KEYWORDS:
                return StatementVerdict(
                    ok=False,
                    first_keyword=first,
                    statement_count=1,
                    error_code=ErrorCode.SQL_NOT_ALLOWED,
                    reason=f"语句包含非只读关键字 {tok.upper()}，拒绝执行",
                )
        ctes = _cte_names(body)
        refs = _table_refs(body)
        unknown = [
            r for r in refs if r not in self.allowed_views and r.lower() not in {c.lower() for c in ctes}
        ]
        if unknown:
            return StatementVerdict(
                ok=False,
                first_keyword=first,
                statement_count=1,
                views=tuple(refs),
                ctes=tuple(ctes),
                error_code=ErrorCode.VIEW_NOT_ALLOWED,
                reason=(
                    f"语句引用了白名单之外的视图/表：{', '.join(sorted(set(unknown)))}；"
                    f"允许：{', '.join(sorted(self.allowed_views))}"
                ),
            )
        return StatementVerdict(
            ok=True,
            first_keyword=first,
            statement_count=1,
            views=tuple(refs),
            ctes=tuple(ctes),
        )


def _cte_names(tokens: Sequence[str]) -> list[str]:
    names: list[str] = []
    if not tokens or tokens[0].upper() != "WITH":
        return names
    i = 1
    if i < len(tokens) and tokens[i].upper() == "RECURSIVE":
        i += 1
    depth = 0
    expecting = True
    while i < len(tokens):
        tok = tokens[i]
        if expecting and _IDENT_RE.match(tok):
            names.append(tok)
            expecting = False
            i += 1
            continue
        if tok == "(":
            depth += 1
            i += 1
            continue
        if tok == ")":
            depth -= 1
            i += 1
            if depth == 0:
                if i < len(tokens) and tokens[i] == ",":
                    expecting = True
                    i += 1
                    continue
                break
            continue
        i += 1
    return names


def _table_refs(tokens: Sequence[str]) -> list[str]:
    refs: list[str] = []
    i = 0
    while i < len(tokens):
        if tokens[i].upper() in ("FROM", "JOIN"):
            j = i + 1
            while j < len(tokens):
                if tokens[j] == "(":
                    break
                if not _IDENT_RE.match(tokens[j]):
                    break
                refs.append(tokens[j])
                j += 1
                if j < len(tokens) and tokens[j].upper() == "AS":
                    j += 2
                elif (
                    j < len(tokens)
                    and _IDENT_RE.match(tokens[j])
                    and tokens[j].lower() not in SQL_KEYWORDS
                ):
                    j += 1
                if j < len(tokens) and tokens[j] == ",":
                    j += 1
                    continue
                break
        i += 1
    return refs


# ---------------------------------------------------------------------------
# 第一层与第三层：连接守卫
# ---------------------------------------------------------------------------


def map_sqlite_error(exc: sqlite3.Error, *, layer: str = "authorizer") -> ApiError:
    text = str(exc)
    lowered = text.lower()
    if "not authorized" in lowered:
        return ApiError(
            ErrorCode.SQL_AUTHORIZER,
            f"数据库授权回调拒绝了该操作：{text}",
            layer="authorizer",
            http_status=403,
        )
    if "readonly" in lowered or "read-only" in lowered:
        return ApiError(
            ErrorCode.DB_READONLY,
            f"数据库连接是只读的，拒绝写入：{text}",
            layer="authorizer",
            http_status=403,
        )
    if "interrupted" in lowered:
        return ApiError(
            ErrorCode.TIMEOUT,
            "查询超过时间上限，被中断（progress handler）",
            layer="row_limit",
            http_status=504,
        )
    return ApiError(
        ErrorCode.DB_ERROR,
        f"数据库执行失败：{type(exc).__name__}: {text}",
        layer=layer,
        http_status=500,
    )


@dataclass
class GuardExecution:
    columns: tuple[str, ...]
    rows: list[tuple[Any, ...]]
    truncated: bool
    requested_rows: int
    elapsed_ms: int
    denials: list[dict[str, Any]] = field(default_factory=list)
    statement: StatementVerdict | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "columns": list(self.columns),
            "row_count": len(self.rows),
            "truncated": self.truncated,
            "requested_rows": self.requested_rows,
            "elapsed_ms": self.elapsed_ms,
            "denials": list(self.denials),
            "statement": self.statement.to_dict() if self.statement else None,
        }


class ReadOnlyGuard:
    """包住一个连接：装 authorizer、装超时、按行数上限取数。"""

    def __init__(self, conn: sqlite3.Connection, inspector: StatementInspector | None = None) -> None:
        self.conn = conn
        self.inspector = inspector
        self.denials: list[dict[str, Any]] = []

    def install_authorizer(self) -> None:
        self.conn.set_authorizer(self._authorize)

    def _authorize(self, action: int, arg1: Any, arg2: Any, dbname: Any, trigger: Any) -> int:
        if action in ALLOWED_AUTHORIZER_ACTIONS:
            return sqlite3.SQLITE_OK
        self.denials.append(
            {
                "action": action_name(action),
                "action_code": action,
                "target": arg1,
                "column": arg2,
            }
        )
        return sqlite3.SQLITE_DENY

    def run_raw(
        self,
        sql: str,
        params: Mapping[str, Any] | None = None,
        *,
        max_rows: int = 200,
        timeout_ms: int = 800,
    ) -> GuardExecution:
        """不做语句白名单检查，只走 authorizer + 行数/超时（用于第一层独立取证）。"""
        deadline = time.monotonic() + max(0.001, timeout_ms / 1000.0)
        start = time.monotonic()

        def _progress() -> int:
            return 1 if time.monotonic() > deadline else 0

        self.conn.set_progress_handler(_progress, 2000)
        try:
            cursor = self.conn.execute(sql, dict(params or {}))
            fetched = cursor.fetchmany(max_rows + 1)
            columns = tuple(d[0] for d in cursor.description) if cursor.description else ()
            truncated = len(fetched) > max_rows
            rows = [tuple(r) for r in fetched[:max_rows]]
        except sqlite3.Error as exc:
            raise map_sqlite_error(exc) from exc
        finally:
            self.conn.set_progress_handler(None, 0)
        return GuardExecution(
            columns=columns,
            rows=rows,
            truncated=truncated,
            requested_rows=max_rows,
            elapsed_ms=int((time.monotonic() - start) * 1000),
            denials=list(self.denials),
        )

    def execute(
        self,
        sql: str,
        params: Mapping[str, Any] | None = None,
        *,
        max_rows: int = 200,
        timeout_ms: int = 800,
    ) -> GuardExecution:
        """第二层 + 第一层 + 第三层，正常业务路径必须走这里。"""
        if self.inspector is None:
            raise ApiError(ErrorCode.SQL_NOT_ALLOWED, "未配置语句白名单，拒绝执行", layer="statement")
        verdict = self.inspector.inspect(sql)
        verdict.raise_if_blocked()
        outcome = self.run_raw(sql, params, max_rows=max_rows, timeout_ms=timeout_ms)
        outcome.statement = verdict
        return outcome


# ---------------------------------------------------------------------------
# 统一执行入口（本地 CLI 与 HTTP 共用，审计与防线只在这里实现一次）
# ---------------------------------------------------------------------------


class QueryEngine:
    def __init__(
        self,
        datasource: DataSource,
        contract: AccessContract,
        limits: Limits,
        audit: Any,
        clock: Any,
    ) -> None:
        self.datasource = datasource
        self.contract = contract
        self.limits = limits
        self.audit = audit
        self.clock = clock
        self.inspector = StatementInspector(contract.allowed_views)
        self.warnings: list[str] = []
        self._check_contract_views()

    def _check_contract_views(self) -> None:
        """加载后再自检一次：模板声明的视图必须都在白名单里。"""
        for tpl in self.contract.templates.values():
            for view in tpl.views:
                if view not in self.contract.allowed_views:
                    self.warnings.append(f"模板 {tpl.id} 声明了未授权视图 {view}")

    def handle(
        self,
        raw: Any,
        *,
        source: str = "local",
        method: str = "LOCAL",
        path: str = "/v1/query",
        token_id: str = "-",
        client_ip: str = "-",
        at: Any = None,
        request_id: str | None = None,
        allow_unexposed: bool = False,
    ) -> QueryResult:
        """校验 + 执行 + 审计。任何拒绝都会写审计后抛出 ApiError。"""
        at = at or self.clock.now()
        rid = request_id or self.audit.next_request_id()
        template_id = raw.get("template") if isinstance(raw, Mapping) else None
        if not isinstance(template_id, str):
            template_id = None
        try:
            request = validate_request(
                raw, self.contract, self.limits, allow_unexposed=allow_unexposed
            )
            template_id = request.template_id
            result = self._execute(request)
        except ApiError as exc:
            self.audit.record(
                at=at,
                request_id=rid,
                source=source,
                method=method,
                path=path,
                template_id=template_id,
                outcome="rejected",
                status=exc.http_status,
                error_code=exc.code,
                token_id=token_id,
                client_ip=client_ip,
                params=_audit_preview(raw),
                message=exc.message,
                layer=exc.layer,
            )
            raise
        self.audit.record(
            at=at,
            request_id=rid,
            source=source,
            method=method,
            path=path,
            template_id=request.template_id,
            outcome="allowed",
            status=200,
            rows=result.row_count,
            token_id=token_id,
            client_ip=client_ip,
            params=request.audit_params(),
            layer="ok",
        )
        return result

    def _execute(self, request: QueryRequest) -> QueryResult:
        template = self.contract.templates[request.template_id]
        verdict = self.inspector.inspect(template.sql)
        verdict.raise_if_blocked()

        bind: dict[str, Any] = {k: v for k, v in request.params.items()}
        bind["limit"] = request.limit
        timeout_ms = template.timeout_ms or self.limits.query_timeout_ms

        conn = self.datasource.connect_ro()
        try:
            guard = ReadOnlyGuard(conn, self.inspector)
            guard.install_authorizer()
            outcome = guard.run_raw(
                template.sql, bind, max_rows=request.limit, timeout_ms=timeout_ms
            )
        finally:
            conn.close()

        extra = set(outcome.columns) - set(template.selectable_fields)
        if extra:
            raise ApiError(
                ErrorCode.SCHEMA_DRIFT,
                f"模板 {template.id} 返回了契约未声明的列：{', '.join(sorted(extra))}",
                layer="row_limit",
                http_status=500,
            )

        rows = [dict(zip(outcome.columns, row)) for row in outcome.rows]
        return QueryResult(
            template_id=template.id,
            columns=outcome.columns,
            rows=rows,
            row_count=len(rows),
            truncated=outcome.truncated,
            limit=request.limit,
            layers={
                "statement": {
                    "first_keyword": verdict.first_keyword,
                    "views": list(verdict.views),
                    "statement_count": verdict.statement_count,
                },
                "authorizer": {"allowed_actions": sorted(action_name(a) for a in ALLOWED_AUTHORIZER_ACTIONS)},
                "row_cap": {
                    "requested": request.limit,
                    "template_max": template.max_rows,
                    "global_max": self.limits.max_rows_hard,
                },
                "timeout_ms": timeout_ms,
            },
        )

    def describe_layers(self) -> list[dict[str, str]]:
        return [
            {
                "layer": "L1",
                "name": "数据库只读凭据",
                "mechanism": "mode=ro URI + PRAGMA query_only + sqlite3 set_authorizer",
                "evidence": "out/layer_evidence.jsonl 中 layer=L1 的记录",
            },
            {
                "layer": "L2",
                "name": "语句白名单",
                "mechanism": "单语句 + SELECT/WITH 首关键字 + 禁注释/写关键字 + 视图白名单",
                "evidence": "out/layer_evidence.jsonl 中 layer=L2 的记录",
            },
            {
                "layer": "L3",
                "name": "行级与时间上限",
                "mechanism": "limit 上限校验 + fetchmany 截断 + progress handler 超时中断",
                "evidence": "out/layer_evidence.jsonl 中 layer=L3 的记录",
            },
        ]


def _audit_preview(raw: Any) -> dict[str, Any] | None:
    if raw is None:
        return None
    if isinstance(raw, Mapping):
        preview: dict[str, Any] = {}
        for key, value in list(raw.items())[:6]:
            text = value if isinstance(value, str) else repr(value)
            preview[str(key)] = text if len(text) <= 80 else text[:80] + "..."
        return preview
    return {"_raw": str(raw)[:80]}


# ---------------------------------------------------------------------------
# 取证辅助：让"每一层都能单独复现"变成可执行代码
# ---------------------------------------------------------------------------


def _evidence(
    layer: str, check: str, statement: str, blocked: bool, mechanism: str, error: str | None
) -> dict[str, Any]:
    return {
        "layer": layer,
        "check": check,
        "statement": statement,
        "blocked": blocked,
        "mechanism": mechanism,
        "error": error,
    }


def probe_readonly_uri(ds: DataSource, statements: Iterable[str]) -> list[dict[str, Any]]:
    """a) mode=ro：连文件都没有写权限。"""
    rows: list[dict[str, Any]] = []
    conn = ds.connect_ro()
    try:
        for sql in statements:
            try:
                conn.execute(sql)
                rows.append(_evidence("L1", "readonly_uri", sql, False, "file:...?mode=ro", None))
            except sqlite3.Error as exc:
                mapped = map_sqlite_error(exc)
                rows.append(_evidence("L1", "readonly_uri", sql, True, "file:...?mode=ro", f"{mapped.code}: {exc}"))
    finally:
        conn.close()
    return rows


def probe_query_only(ds: DataSource, statements: Iterable[str]) -> list[dict[str, Any]]:
    """b) PRAGMA query_only=ON：把可写连接降级为只读。"""
    rows: list[dict[str, Any]] = []
    conn = ds.connect_rw()
    try:
        conn.execute("PRAGMA query_only = ON")
        for sql in statements:
            try:
                conn.execute(sql)
                rows.append(_evidence("L1", "query_only", sql, False, "PRAGMA query_only=ON", None))
            except sqlite3.Error as exc:
                mapped = map_sqlite_error(exc)
                rows.append(_evidence("L1", "query_only", sql, True, "PRAGMA query_only=ON", f"{mapped.code}: {exc}"))
    finally:
        conn.close()
    return rows


def probe_authorizer(ds: DataSource, statements: Iterable[str]) -> list[dict[str, Any]]:
    """c) set_authorizer：可写连接也被回调挡住，且能报出被拒的动作名。"""
    rows: list[dict[str, Any]] = []
    conn = ds.connect_rw()
    before = conn.execute("SELECT COUNT(*) FROM fact_sales").fetchone()[0]
    try:
        guard = ReadOnlyGuard(conn)
        guard.install_authorizer()
        for sql in statements:
            guard.denials.clear()
            try:
                conn.execute(sql)
                rows.append(_evidence("L1", "authorizer", sql, False, "sqlite3 set_authorizer", None))
            except sqlite3.Error as exc:
                denied = [d["action"] for d in guard.denials]
                rows.append(
                    _evidence(
                        "L1",
                        "authorizer",
                        sql,
                        True,
                        "sqlite3 set_authorizer",
                        f"{ErrorCode.SQL_AUTHORIZER}: {exc}（被拒动作 {','.join(denied) or '未知'}）",
                    )
                )
    finally:
        after = conn.execute("SELECT COUNT(*) FROM fact_sales").fetchone()[0]
        conn.set_authorizer(None)
        conn.close()
    if before != after:
        rows.append(
            _evidence(
                "L1",
                "authorizer_rowcount",
                "SELECT COUNT(*) FROM fact_sales",
                False,
                "rowcount invariant",
                f"事实表行数从 {before} 变成 {after}，防线被突破",
            )
        )
    return rows


def probe_statement_policy(inspector: StatementInspector, statements: Iterable[str]) -> list[dict[str, Any]]:
    """第二层单独取证：只看解析结果，不碰数据库。"""
    rows: list[dict[str, Any]] = []
    for sql in statements:
        verdict = inspector.inspect(sql)
        rows.append(
            {
                "layer": "L2",
                "check": "statement_whitelist",
                "statement": sql,
                "blocked": not verdict.ok,
                "mechanism": "StatementInspector",
                "error": None if verdict.ok else f"{verdict.error_code}: {verdict.reason}",
                "first_keyword": verdict.first_keyword,
                "statement_count": verdict.statement_count,
                "views": list(verdict.views),
            }
        )
    return rows


def probe_row_cap(
    ds: DataSource,
    inspector: StatementInspector,
    sql: str,
    cap: int,
    params: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """第三层（行）：SQL 不写 LIMIT，由 guard 截断。"""
    conn = ds.connect_ro()
    try:
        guard = ReadOnlyGuard(conn, inspector)
        guard.install_authorizer()
        outcome = guard.run_raw(sql, params, max_rows=cap, timeout_ms=800)
        return [
            {
                "layer": "L3",
                "check": "row_cap",
                "statement": sql,
                "blocked": outcome.truncated,
                "mechanism": f"fetchmany({cap}+1) 截断",
                "error": None,
                "rows_returned": len(outcome.rows),
                "truncated": outcome.truncated,
            }
        ]
    finally:
        conn.close()


def probe_timeout(
    ds: DataSource,
    inspector: StatementInspector,
    sql: str,
    timeout_ms: int,
    params: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """第三层（时间）：progress handler 中断，且中断后连接仍可用。"""
    conn = ds.connect_ro()
    try:
        guard = ReadOnlyGuard(conn, inspector)
        guard.install_authorizer()
        start = time.monotonic()
        try:
            guard.run_raw(sql, params, max_rows=1, timeout_ms=timeout_ms)
            blocked = False
            error = None
        except ApiError as exc:
            blocked = True
            error = f"{exc.code}: {exc.message}"
        elapsed = int((time.monotonic() - start) * 1000)
        reused = conn.execute("SELECT COUNT(*) FROM fact_sales").fetchone()[0]
        return [
            {
                "layer": "L3",
                "check": "timeout",
                "statement": sql,
                "blocked": blocked,
                "mechanism": f"progress handler + {timeout_ms}ms 截止",
                "error": error,
                "elapsed_ms": elapsed,
                "connection_reusable": reused > 0,
            }
        ]
    finally:
        conn.close()

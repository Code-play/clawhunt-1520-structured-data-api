"""只读 HTTP 接口（标准库 http.server）。

只读体现在四件事上：
  1. 路由只注册 GET；其它方法一律 405 + Allow: GET（不是靠文档约定）；
  2. 只读 scope：查数需要 query scope，审计需要 audit scope，越权 403；
  3. 滑动窗口限流：每令牌独立配额，超限 429 + Retry-After；
  4. 全量审计：成功、拒绝、鉴权失败、限流、方法不对都写一条审计（含 request_id）。

服务本身不持有可写连接：每个查询都新开一个 mode=ro 连接，装 authorizer 后执行，用完即关。
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .audit import AuditLog
from .guard import QueryEngine
from .model import AccessContract, ApiError, AuthConfig, AuthToken, ErrorCode, Limits
from .openapi import build_spec
from .ratelimit import LimiterRegistry, SlidingWindowLimiter


_INT_RE = re.compile(r"^-?\d+$")
_FLOAT_RE = re.compile(r"^-?\d+(?:\.\d+)?$")


def _coerce_scalar(field_type: str, value: str) -> Any:
    """URL query 值都是字符串，这里只做与字段声明类型一致的显式转换。"""
    if field_type == "integer":
        return int(value) if _INT_RE.match(value) else value
    if field_type == "number":
        return float(value) if _FLOAT_RE.match(value) else value
    if field_type == "boolean":
        lowered = value.lower()
        if lowered in ("true", "1"):
            return True
        if lowered in ("false", "0"):
            return False
        return value
    return value


@dataclass
class ApiContext:
    engine: QueryEngine
    contract: AccessContract
    limits: Limits
    auth: AuthConfig
    audit: AuditLog
    clock: Any

    def __post_init__(self) -> None:
        self._limiters = LimiterRegistry(self.limits.rate_limit_limit, self.limits.rate_limit_window_s)
        self._spec = build_spec(self.contract, self.limits, self.auth)

    def limiter_for(self, token: AuthToken) -> SlidingWindowLimiter:
        return self._limiters.for_key(
            token.id, token.rate_limit_limit, token.rate_limit_window_s
        )

    def spec(self) -> dict[str, Any]:
        return self._spec


class ReadOnlyApiHandler(BaseHTTPRequestHandler):
    server_version = "StructuredDataApi/1.0"
    protocol_version = "HTTP/1.1"

    # ---- HTTP 方法：只有 GET 会被正常处理，其余进 405 ----
    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch("HEAD")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch("PUT")

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch("PATCH")

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch("DELETE")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch("OPTIONS")

    # ---- 关键流程 ----
    def _dispatch(self, method: str) -> None:
        ctx: ApiContext = self.server.context  # type: ignore[attr-defined]
        at = ctx.clock.now()
        ctx.clock.advance()
        request_id = ctx.audit.next_request_id()
        parsed = urlsplit(self.path)
        path = parsed.path or "/"
        client_ip = self.client_address[0] if self.client_address else "-"
        token_id = "-"
        audited = False
        try:
            if len(self.path) > ctx.limits.max_url_length:
                raise ApiError(
                    ErrorCode.REQUEST_TOO_LARGE,
                    f"请求 URL 长度 {len(self.path)} 超过上限 {ctx.limits.max_url_length}",
                    layer="transport",
                )
            if method != "GET":
                self._drain_body()
                raise ApiError(
                    ErrorCode.METHOD_NOT_ALLOWED,
                    f"本接口只读，只允许 GET，收到 {method}",
                    layer="transport",
                    headers={"Allow": "GET"},
                )
            if path == "/healthz" and ctx.limits.healthz_without_auth:
                payload = {
                    "request_id": request_id,
                    "status": 200,
                    "data": {
                        "status": "ok",
                        "read_only": True,
                        "dialect": ctx.contract.dialect,
                        "contract_version": ctx.contract.contract_version,
                    },
                }
                ctx.audit.record(
                    at=at,
                    request_id=request_id,
                    source="http",
                    method=method,
                    path=path,
                    template_id=None,
                    outcome="allowed",
                    status=200,
                    token_id="-",
                    client_ip=client_ip,
                    layer="ok",
                )
                self._respond(200, payload, {}, request_id)
                return
                return

            token = self._authenticate(ctx)
            token_id = token.id
            decision = ctx.limiter_for(token).check(token.id, at.timestamp())
            if not decision.allowed:
                raise ApiError(
                    ErrorCode.RATE_LIMITED,
                    f"令牌 {token.id} 在 {decision.window_s}s 内已调用 {decision.used} 次"
                    f"（上限 {decision.limit}），请在 {decision.retry_after_s}s 后重试",
                    layer="transport",
                    headers={"Retry-After": str(decision.retry_after_s)},
                    detail=json.dumps(decision.to_dict(), ensure_ascii=False),
                )

            if path == "/v1/query":
                self._require_scope(token, "query")
                raw = self._build_query_request(ctx, parsed)
                try:
                    result = ctx.engine.handle(
                        raw,
                        source="http",
                        method=method,
                        path=path,
                        token_id=token.id,
                        client_ip=client_ip,
                        at=at,
                        request_id=request_id,
                        allow_unexposed=False,
                    )
                except ApiError:
                    audited = True
                    raise
                audited = True
                payload = {
                    "request_id": request_id,
                    "status": 200,
                    "data": result.to_dict(),
                }
                self._respond(200, payload, {}, request_id)
                return

            data = self._route(ctx, path, parsed, token)
            ctx.audit.record(
                at=at,
                request_id=request_id,
                source="http",
                method=method,
                path=path,
                template_id=None,
                outcome="allowed",
                status=200,
                token_id=token.id,
                client_ip=client_ip,
                layer="ok",
            )
            self._respond(200, {"request_id": request_id, "status": 200, "data": data}, {}, request_id)
        except ApiError as exc:
            if not audited:
                ctx.audit.record(
                    at=at,
                    request_id=request_id,
                    source="http",
                    method=method,
                    path=path,
                    template_id=None,
                    outcome="rejected",
                    status=exc.http_status,
                    error_code=exc.code,
                    token_id=token_id,
                    client_ip=client_ip,
                    message=exc.message,
                    layer=exc.layer,
                )
            self._respond(
                exc.http_status,
                {"request_id": request_id, "status": exc.http_status, "error": exc.to_dict()},
                exc.headers,
                request_id,
            )

    def _drain_body(self) -> None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            length = 0
        if length > 0:
            try:
                self.rfile.read(min(length, 65536))
            except OSError:
                pass

    def _authenticate(self, ctx: ApiContext) -> AuthToken:
        header_value = self.headers.get(ctx.auth.header)
        if not header_value:
            raise ApiError(
                ErrorCode.AUTH_MISSING,
                f"缺少访问令牌：请在请求头 {ctx.auth.header} 中提供",
                layer="auth",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        token = ctx.auth.lookup(header_value.strip())
        if token is None:
            raise ApiError(
                ErrorCode.AUTH_INVALID,
                "访问令牌无效或已吊销",
                layer="auth",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        return token

    @staticmethod
    def _require_scope(token: AuthToken, scope: str) -> None:
        if scope not in token.scopes:
            raise ApiError(
                ErrorCode.SCOPE_DENIED,
                f"令牌 {token.id} 缺少 {scope} scope（现有：{', '.join(token.scopes)}）",
                layer="auth",
            )

    @staticmethod
    def _build_query_request(ctx: ApiContext, parsed: Any) -> dict[str, Any]:
        qs = parse_qs(parsed.query, keep_blank_values=True)
        duplicated = sorted(k for k, v in qs.items() if len(v) > 1)
        if duplicated:
            raise ApiError(
                ErrorCode.PARAM_DUPLICATE,
                f"参数 {duplicated[0]} 在 URL 中重复出现，拒绝猜测取值",
                field_name=duplicated[0],
                layer="param",
            )
        flat = {k: v[0] for k, v in qs.items()}
        raw: dict[str, Any] = {"params": flat}
        if "template" in flat:
            raw["template"] = flat.pop("template")
        # URL 里一切都是字符串：只对契约声明为数值的字段做一次显式转换。
        # 转换失败就保持字符串，让校验层给出 E_PARAM_TYPE（而不是在这里猜）。
        for name in list(flat):
            meta = ctx.contract.fields.get(name)
            if meta is None:
                continue
            flat[name] = _coerce_scalar(meta.type, flat[name])
        return raw

    def _route(self, ctx: ApiContext, path: str, parsed: Any, token: AuthToken) -> Any:
        if path == "/v1/fields":
            self._require_scope(token, "query")
            return [meta.to_dict() for meta in ctx.contract.fields.values()]
        if path == "/v1/queries":
            self._require_scope(token, "query")
            return [tpl.to_dict() for tpl in ctx.contract.exposed_templates()]
        if path == "/v1/contract":
            self._require_scope(token, "query")
            return {
                "contract": ctx.contract.to_dict(),
                "limits": ctx.limits.to_dict(),
                "layers": ctx.engine.describe_layers(),
                "views": [
                    {"name": name} for name in ctx.contract.allowed_views
                ],
            }
        if path == "/v1/openapi.json":
            self._require_scope(token, "query")
            return ctx.spec()
        if path == "/v1/audit/tail":
            self._require_scope(token, "audit")
            n = self._parse_tail_n(parsed)
            return ctx.audit.tail(n)
        raise ApiError(
            ErrorCode.NOT_FOUND,
            f"路径 {path} 不存在；可用：/healthz, /v1/contract, /v1/fields, /v1/queries, "
            "/v1/query, /v1/audit/tail, /v1/openapi.json",
            layer="transport",
        )

    @staticmethod
    def _parse_tail_n(parsed: Any) -> int:
        qs = parse_qs(parsed.query, keep_blank_values=True)
        values = qs.get("n")
        if not values:
            return 10
        raw = values[0].strip()
        if not raw.isdigit():
            raise ApiError(
                ErrorCode.PARAM_TYPE,
                f"参数 n 必须是非负整数，实际：{raw!r}",
                field_name="n",
                layer="param",
            )
        n = int(raw)
        if n < 1 or n > 50:
            raise ApiError(
                ErrorCode.PARAM_RANGE,
                f"参数 n={n} 超出范围 1..50",
                field_name="n",
                layer="param",
            )
        return n

    def _respond(self, status: int, payload: dict[str, Any], headers: dict[str, str], request_id: str) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Request-Id", request_id)
        self.send_header("Cache-Control", "no-store")
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def log_message(self, fmt: str, *args: Any) -> None:
        # 访问日志进审计日志，标准错误保持干净（demo_run.log 只留业务输出）。
        return


class ReadOnlyApiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], context: ApiContext) -> None:
        self.context = context
        super().__init__(address, ReadOnlyApiHandler)


def create_server(
    context: ApiContext,
    host: str | None = None,
    port: int | None = None,
) -> ReadOnlyApiServer:
    host = host or context.limits.api_host
    port = context.limits.api_port if port is None else port
    return ReadOnlyApiServer((host, int(port)), context)


def start_in_thread(
    context: ApiContext,
    host: str | None = None,
    port: int | None = None,
) -> tuple[ReadOnlyApiServer, threading.Thread, str]:
    server = create_server(context, host=host, port=port)
    thread = threading.Thread(target=server.serve_forever, name="sdapi-http", daemon=True)
    thread.start()
    bound_host, bound_port = server.server_address[0], server.server_address[1]
    base_url = f"http://{bound_host}:{bound_port}"
    return server, thread, base_url


def stop_server(server: ReadOnlyApiServer, thread: threading.Thread | None = None) -> None:
    server.shutdown()
    server.server_close()
    if thread is not None:
        thread.join(timeout=5)

"""领域模型：错误码、字段元数据、查询模板、访问契约、限额、请求/结果、审计条目。

本模块只放数据结构与序列化，不读文件、不碰数据库，便于单独测试。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

# ---------------------------------------------------------------------------
# 错误码
# ---------------------------------------------------------------------------

ERROR_CATALOG: dict[str, tuple[int, str]] = {
    "E_PARAM_MISSING": (400, "缺少必填参数"),
    "E_PARAM_TYPE": (400, "参数类型不正确"),
    "E_PARAM_RANGE": (400, "参数超出允许范围"),
    "E_PARAM_ENUM": (400, "参数不在枚举白名单内"),
    "E_PARAM_UNKNOWN": (400, "参数不在全局字段白名单内"),
    "E_PARAM_NOT_IN_TEMPLATE": (400, "参数不在该模板的允许字段内"),
    "E_PARAM_INJECTION": (400, "参数包含注入特征字符"),
    "E_PARAM_LENGTH": (400, "参数长度超限"),
    "E_PARAM_DUPLICATE": (400, "参数重复出现"),
    "E_TEMPLATE_UNKNOWN": (400, "查询模板不存在或未开放"),
    "E_ROW_LIMIT": (400, "请求行数超过允许上限"),
    "E_SQL_NOT_ALLOWED": (403, "语句不是只读查询"),
    "E_SQL_MULTI_STATEMENT": (403, "一条请求只允许一条语句"),
    "E_SQL_COMMENT": (403, "语句中不允许出现注释"),
    "E_VIEW_NOT_ALLOWED": (403, "语句引用了白名单之外的视图"),
    "E_SQL_AUTHORIZER": (403, "数据库授权回调拒绝了该操作"),
    "E_DB_READONLY": (403, "数据库连接是只读的"),
    "E_SCHEMA_DRIFT": (500, "结果列与契约声明不一致"),
    "E_TIMEOUT": (504, "查询超时被中断"),
    "E_DB_ERROR": (500, "数据库执行失败"),
    "E_AUTH_MISSING_TOKEN": (401, "缺少访问令牌"),
    "E_AUTH_INVALID_TOKEN": (401, "访问令牌无效"),
    "E_SCOPE_DENIED": (403, "令牌 scope 不足"),
    "E_RATE_LIMITED": (429, "触发限流"),
    "E_METHOD_NOT_ALLOWED": (405, "只允许 GET"),
    "E_NOT_FOUND": (404, "路径不存在"),
    "E_REQUEST_TOO_LARGE": (414, "请求过长"),
}


class ErrorCode:
    """错误码常量（字符串，便于直接进 JSON / 审计日志）。"""

    PARAM_MISSING = "E_PARAM_MISSING"
    PARAM_TYPE = "E_PARAM_TYPE"
    PARAM_RANGE = "E_PARAM_RANGE"
    PARAM_ENUM = "E_PARAM_ENUM"
    PARAM_UNKNOWN = "E_PARAM_UNKNOWN"
    PARAM_NOT_IN_TEMPLATE = "E_PARAM_NOT_IN_TEMPLATE"
    PARAM_INJECTION = "E_PARAM_INJECTION"
    PARAM_LENGTH = "E_PARAM_LENGTH"
    PARAM_DUPLICATE = "E_PARAM_DUPLICATE"
    TEMPLATE_UNKNOWN = "E_TEMPLATE_UNKNOWN"
    ROW_LIMIT = "E_ROW_LIMIT"
    SQL_NOT_ALLOWED = "E_SQL_NOT_ALLOWED"
    SQL_MULTI_STATEMENT = "E_SQL_MULTI_STATEMENT"
    SQL_COMMENT = "E_SQL_COMMENT"
    VIEW_NOT_ALLOWED = "E_VIEW_NOT_ALLOWED"
    SQL_AUTHORIZER = "E_SQL_AUTHORIZER"
    DB_READONLY = "E_DB_READONLY"
    SCHEMA_DRIFT = "E_SCHEMA_DRIFT"
    TIMEOUT = "E_TIMEOUT"
    DB_ERROR = "E_DB_ERROR"
    AUTH_MISSING = "E_AUTH_MISSING_TOKEN"
    AUTH_INVALID = "E_AUTH_INVALID_TOKEN"
    SCOPE_DENIED = "E_SCOPE_DENIED"
    RATE_LIMITED = "E_RATE_LIMITED"
    METHOD_NOT_ALLOWED = "E_METHOD_NOT_ALLOWED"
    NOT_FOUND = "E_NOT_FOUND"
    REQUEST_TOO_LARGE = "E_REQUEST_TOO_LARGE"

    ALL = tuple(ERROR_CATALOG)


class ApiError(Exception):
    """带错误码、字段名、HTTP 状态与所属防线的可读异常。"""

    def __init__(
        self,
        code: str,
        message: str = "",
        *,
        field_name: str | None = None,
        layer: str = "param",
        http_status: int | None = None,
        detail: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        status, default_message = ERROR_CATALOG.get(code, (400, "请求被拒绝"))
        self.code = code
        self.message = message or default_message
        self.field_name = field_name
        self.layer = layer
        self.http_status = http_status if http_status is not None else status
        self.detail = detail
        self.headers = dict(headers or {})
        super().__init__(f"{code}: {self.message}")

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "layer": self.layer,
        }
        if self.field_name:
            payload["field"] = self.field_name
        if self.detail:
            payload["detail"] = self.detail
        return payload


# ---------------------------------------------------------------------------
# 元数据
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldMeta:
    """字段白名单里的一条：类型、范围、枚举、长度都在这里声明。"""

    name: str
    type: str
    description: str = ""
    enum: tuple[str, ...] = ()
    minimum: Any = None
    maximum: Any = None
    max_length: int | None = None
    pii: bool = False

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any], maximum_override: Any = None) -> "FieldMeta":
        maximum = raw.get("maximum", maximum_override)
        if "maximum_ref" in raw:
            maximum = maximum_override
        return cls(
            name=str(raw["name"]),
            type=str(raw["type"]),
            description=str(raw.get("description", "")),
            enum=tuple(str(x) for x in raw.get("enum", ())),
            minimum=raw.get("minimum"),
            maximum=maximum,
            max_length=raw.get("max_length"),
            pii=bool(raw.get("pii", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "type": self.type,
            "description": self.description,
            "pii": self.pii,
        }
        if self.enum:
            payload["enum"] = list(self.enum)
        if self.minimum is not None:
            payload["minimum"] = self.minimum
        if self.maximum is not None:
            payload["maximum"] = self.maximum
        if self.max_length is not None:
            payload["max_length"] = self.max_length
        return payload


@dataclass(frozen=True)
class TemplateParam:
    name: str
    required: bool = False
    default: Any = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": self.name, "required": self.required}
        if self.default is not None:
            payload["default"] = self.default
        return payload


@dataclass(frozen=True)
class QueryTemplate:
    id: str
    title: str
    description: str
    sql: str
    params: tuple[TemplateParam, ...]
    selectable_fields: tuple[str, ...]
    views: tuple[str, ...]
    max_rows: int
    timeout_ms: int | None = None
    exposed_via_api: bool = True
    purpose: str = "aggregate"

    def param(self, name: str) -> TemplateParam | None:
        for item in self.params:
            if item.name == name:
                return item
        return None

    @property
    def allowed_params(self) -> tuple[str, ...]:
        return tuple(p.name for p in self.params)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "QueryTemplate":
        return cls(
            id=str(raw["id"]),
            title=str(raw.get("title", raw["id"])),
            description=str(raw.get("description", "")),
            sql=str(raw["sql"]),
            params=tuple(
                TemplateParam(
                    name=str(p["name"]),
                    required=bool(p.get("required", False)),
                    default=p.get("default"),
                )
                for p in raw.get("params", ())
            ),
            selectable_fields=tuple(str(x) for x in raw.get("selectable_fields", ())),
            views=tuple(str(x) for x in raw.get("views", ())),
            max_rows=int(raw.get("max_rows", 50)),
            timeout_ms=raw.get("timeout_ms"),
            exposed_via_api=bool(raw.get("exposed_via_api", True)),
            purpose=str(raw.get("purpose", "aggregate")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "purpose": self.purpose,
            "exposed_via_api": self.exposed_via_api,
            "max_rows": self.max_rows,
            "timeout_ms": self.timeout_ms,
            "params": [p.to_dict() for p in self.params],
            "selectable_fields": list(self.selectable_fields),
            "views": list(self.views),
        }


@dataclass(frozen=True)
class AccessContract:
    contract_version: str
    name: str
    dialect: str
    read_only: bool
    allowed_views: tuple[str, ...]
    templates: Mapping[str, QueryTemplate]
    fields: Mapping[str, FieldMeta]
    output_fields: tuple[str, ...]
    notes: tuple[str, ...] = ()

    def template(self, template_id: str) -> QueryTemplate:
        try:
            return self.templates[template_id]
        except KeyError:
            raise ApiError(
                ErrorCode.TEMPLATE_UNKNOWN,
                f"查询模板 {template_id!r} 不存在或未开放；可用模板：{', '.join(sorted(self.templates))}",
                layer="param",
            ) from None

    def field(self, name: str) -> FieldMeta:
        try:
            return self.fields[name]
        except KeyError:
            raise ApiError(
                ErrorCode.PARAM_UNKNOWN,
                f"参数 {name!r} 不在全局字段白名单内；允许：{', '.join(sorted(self.fields))}",
                field_name=name,
                layer="param",
            ) from None

    def exposed_templates(self) -> tuple[QueryTemplate, ...]:
        return tuple(t for t in self.templates.values() if t.exposed_via_api)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "name": self.name,
            "dialect": self.dialect,
            "read_only": self.read_only,
            "allowed_views": list(self.allowed_views),
            "output_fields": list(self.output_fields),
            "templates": [t.to_dict() for t in self.templates.values()],
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class Limits:
    max_rows_hard: int
    default_rows: int
    max_param_length: int
    max_params: int
    max_url_length: int
    query_timeout_ms: int
    benchmark_timeout_ms: int
    rate_limit_limit: int
    rate_limit_window_s: int
    audit_max_entries: int
    api_host: str
    api_port: int
    allow_methods: tuple[str, ...]
    healthz_without_auth: bool
    server_header: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_rows_hard": self.max_rows_hard,
            "default_rows": self.default_rows,
            "max_param_length": self.max_param_length,
            "max_params": self.max_params,
            "max_url_length": self.max_url_length,
            "query_timeout_ms": self.query_timeout_ms,
            "benchmark_timeout_ms": self.benchmark_timeout_ms,
            "rate_limit": {"limit": self.rate_limit_limit, "window_seconds": self.rate_limit_window_s},
            "audit_max_entries": self.audit_max_entries,
            "api": {
                "host": self.api_host,
                "port": self.api_port,
                "allow_methods": list(self.allow_methods),
                "healthz_without_auth": self.healthz_without_auth,
            },
        }


@dataclass(frozen=True)
class AuthToken:
    id: str
    token: str
    scopes: tuple[str, ...]
    rate_limit_limit: int | None = None
    rate_limit_window_s: int | None = None

    def masked(self) -> str:
        head = self.token[:4] if len(self.token) >= 4 else self.token[:1]
        return f"{head}***"

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "scopes": list(self.scopes), "token_masked": self.masked()}


@dataclass(frozen=True)
class AuthConfig:
    header: str
    tokens: Mapping[str, AuthToken]

    def lookup(self, token: str) -> AuthToken | None:
        return self.tokens.get(token)


@dataclass(frozen=True)
class QueryRequest:
    template_id: str
    params: Mapping[str, Any]
    limit: int
    raw: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"template": self.template_id, "params": dict(self.params), "limit": self.limit}

    def audit_params(self) -> dict[str, Any]:
        payload = dict(self.params)
        payload["limit"] = self.limit
        return payload


@dataclass
class QueryResult:
    template_id: str
    columns: tuple[str, ...]
    rows: list[dict[str, Any]]
    row_count: int
    truncated: bool
    limit: int
    layers: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "columns": list(self.columns),
            "row_count": self.row_count,
            "truncated": self.truncated,
            "limit": self.limit,
            "rows": self.rows,
            "layers": self.layers,
        }


@dataclass
class AuditEntry:
    seq: int
    at: str
    request_id: str
    source: str
    method: str
    path: str
    template_id: str | None
    outcome: str
    status: int
    error_code: str | None = None
    rows: int | None = None
    token_id: str = "-"
    client_ip: str = "-"
    params: Mapping[str, Any] | None = None
    message: str | None = None
    layer: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "at": self.at,
            "request_id": self.request_id,
            "source": self.source,
            "method": self.method,
            "path": self.path,
            "template_id": self.template_id,
            "outcome": self.outcome,
            "status": self.status,
            "error_code": self.error_code,
            "layer": self.layer,
            "rows": self.rows,
            "token_id": self.token_id,
            "client_ip": self.client_ip,
            "params": dict(self.params) if self.params is not None else None,
            "message": self.message,
        }

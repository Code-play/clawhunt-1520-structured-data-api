"""生成 OpenAPI 3 风格契约 JSON（不依赖任何第三方库）。

覆盖：鉴权方式（header token）、只读方法约束、模板枚举、字段枚举/范围、
所有错误码对应的 HTTP 状态、限流响应头，以及三层防线的机器可读扩展字段。
"""

from __future__ import annotations

from typing import Any

from .model import AccessContract, AuthConfig, Limits


def _param_schema(meta: Any, limits: Limits) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": meta.type if meta.type != "date" else "string"}
    if meta.type == "date":
        schema["format"] = "date"
    if meta.enum:
        schema["enum"] = list(meta.enum)
    if meta.minimum is not None:
        schema["minimum"] = meta.minimum
    if meta.maximum is not None:
        schema["maximum"] = min(int(meta.maximum), limits.max_rows_hard) if meta.type == "integer" else meta.maximum
    if meta.max_length is not None:
        schema["maxLength"] = meta.max_length
    if meta.description:
        schema["description"] = meta.description
    return schema


def _error_response(description: str, code: str) -> dict[str, Any]:
    return {
        "description": description,
        "content": {
            "application/json": {
                "schema": {"$ref": "#/components/schemas/ErrorResponse"},
                "example": {
                    "request_id": "req-0001",
                    "status": 400,
                    "error": {
                        "code": code,
                        "message": "参数 region 不在枚举白名单内：华东, 华南, 华北, 西南",
                        "layer": "param",
                        "field": "region",
                    },
                },
            }
        },
    }


def build_spec(contract: AccessContract, limits: Limits, auth: AuthConfig) -> dict[str, Any]:
    exposed = contract.exposed_templates()
    template_ids = [t.id for t in exposed]
    field_params = [
        {
            "name": meta.name,
            "in": "query",
            "required": False,
            "schema": _param_schema(meta, limits),
            "description": meta.description
            + ("（是否必填取决于模板，见模板定义）" if meta.name.startswith("date_") else ""),
        }
        for meta in contract.fields.values()
        if meta.name != "limit"
    ]
    limit_schema: dict[str, Any] = {
        "type": "integer",
        "minimum": 1,
        "maximum": limits.max_rows_hard,
        "default": limits.default_rows,
        "description": "返回行数上限；还受模板 max_rows 约束，超出即 400 E_ROW_LIMIT",
    }
    query_parameters = [
        {
            "name": "template",
            "in": "query",
            "required": True,
            "schema": {"type": "string", "enum": template_ids},
            "description": "查询模板 id（客户端不提交 SQL）",
        },
        *field_params,
        {"name": "limit", "in": "query", "required": False, "schema": limit_schema},
    ]
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "ClawHunt #1520 结构化数据只读接口",
            "version": contract.contract_version,
            "description": (
                "面向企业 Agent 的只读 OLAP 查询接口。\n"
                "设计约束：只允许 GET；令牌鉴权 + scope；滑动窗口限流；全程审计；\n"
                "三层只读防线（数据库只读凭据 / 语句白名单 / 行级与超时上限）互不依赖。\n"
                "客户端只能引用模板 id，不能提交 SQL 文本。"
            ),
            "x-order": 1520,
        },
        "servers": [
            {
                "url": f"http://{limits.api_host}:{{port}}",
                "description": "本地演示服务（端口由启动参数决定，0 表示临时端口）",
                "variables": {"port": {"default": "8080"}},
            }
        ],
        "security": [{"ApiKeyAuth": []}],
        "tags": [
            {"name": "meta", "description": "契约与元数据（只读）"},
            {"name": "query", "description": "数据查询（只读）"},
            {"name": "audit", "description": "审计查询（只读）"},
        ],
        "paths": {
            "/healthz": {
                "get": {
                    "tags": ["meta"],
                    "summary": "健康检查（免鉴权、免限流）",
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "服务可用",
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"},
                                    "example": {
                                        "status": "ok",
                                        "read_only": True,
                                        "dialect": "sqlite",
                                        "contract_version": contract.contract_version,
                                    },
                                }
                            },
                        }
                    },
                }
            },
            "/v1/contract": {
                "get": {
                    "tags": ["meta"],
                    "summary": "读取访问契约（模板、视图、字段、上限、三层防线）",
                    "responses": {
                        "200": {"description": "契约内容", "content": {"application/json": {"schema": {"type": "object"}}}},
                        "401": _error_response("缺少或无效令牌", "E_AUTH_MISSING_TOKEN"),
                        "429": _error_response("触发限流", "E_RATE_LIMITED"),
                    },
                }
            },
            "/v1/fields": {
                "get": {
                    "tags": ["meta"],
                    "summary": "字段白名单与元数据",
                    "responses": {
                        "200": {"description": "字段列表", "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/FieldMeta"}}}}},
                        "401": _error_response("缺少或无效令牌", "E_AUTH_INVALID_TOKEN"),
                    },
                }
            },
            "/v1/queries": {
                "get": {
                    "tags": ["meta"],
                    "summary": "可用查询模板列表（含参数与结果列声明）",
                    "responses": {
                        "200": {"description": "模板列表", "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/QueryTemplate"}}}}},
                        "401": _error_response("缺少或无效令牌", "E_AUTH_INVALID_TOKEN"),
                    },
                }
            },
            "/v1/query": {
                "get": {
                    "tags": ["query"],
                    "summary": "执行一次只读查询",
                    "description": (
                        "按模板执行查询。参数按字段白名单校验（类型/长度/枚举/范围/注入特征），"
                        "日期区间必须闭合且 date_from <= date_to。"
                        "行数超过模板上限或全局硬上限返回 400 E_ROW_LIMIT；"
                        "执行超时返回 504 E_TIMEOUT。"
                    ),
                    "parameters": query_parameters,
                    "responses": {
                        "200": {
                            "description": "查询结果",
                            "headers": {
                                "X-Request-Id": {"schema": {"type": "string"}, "description": "请求 id，与审计日志对应"}
                            },
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/QueryResult"},
                                    "example": {
                                        "request_id": "req-0002",
                                        "status": 200,
                                        "data": {
                                            "template_id": "sales_by_region",
                                            "columns": ["region", "orders", "revenue"],
                                            "row_count": 4,
                                            "truncated": False,
                                            "rows": [{"region": "华东", "orders": 512, "revenue": 1234567.89}],
                                        },
                                    },
                                }
                            },
                        },
                        "400": _error_response("参数校验失败 / 行数超限", "E_PARAM_ENUM"),
                        "401": _error_response("缺少或无效令牌", "E_AUTH_MISSING_TOKEN"),
                        "403": _error_response("scope 不足或语句被防线拒绝", "E_SCOPE_DENIED"),
                        "404": _error_response("路径不存在", "E_NOT_FOUND"),
                        "405": _error_response("方法不允许（只允许 GET）", "E_METHOD_NOT_ALLOWED"),
                        "429": _error_response("触发限流", "E_RATE_LIMITED"),
                        "500": _error_response("服务端错误（含结果列与契约不一致）", "E_SCHEMA_DRIFT"),
                        "504": _error_response("查询超时", "E_TIMEOUT"),
                    },
                }
            },
            "/v1/audit/tail": {
                "get": {
                    "tags": ["audit"],
                    "summary": "读取审计日志尾部（需要 audit scope）",
                    "parameters": [
                        {
                            "name": "n",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "审计条目",
                            "content": {
                                "application/json": {
                                    "schema": {"type": "array", "items": {"$ref": "#/components/schemas/AuditEntry"}}
                                }
                            },
                        },
                        "403": _error_response("令牌缺少 audit scope", "E_SCOPE_DENIED"),
                    },
                }
            },
            "/v1/openapi.json": {
                "get": {
                    "tags": ["meta"],
                    "summary": "本契约自身（OpenAPI 3.0.3）",
                    "responses": {"200": {"description": "OpenAPI 文档", "content": {"application/json": {"schema": {"type": "object"}}}}},
                }
            },
        },
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": auth.header,
                    "description": "明文令牌仅用于演示；生产应改为短期凭据 + 哈希存储 + 轮换。",
                }
            },
            "schemas": {
                "ErrorResponse": {
                    "type": "object",
                    "required": ["request_id", "status", "error"],
                    "properties": {
                        "request_id": {"type": "string", "example": "req-0007"},
                        "status": {"type": "integer", "example": 400},
                        "error": {
                            "type": "object",
                            "required": ["code", "message", "layer"],
                            "properties": {
                                "code": {"type": "string", "example": "E_PARAM_INJECTION"},
                                "message": {"type": "string", "example": "参数 region 包含注入特征（分号（多语句拼接）），已拒绝"},
                                "layer": {"type": "string", "enum": ["param", "statement", "authorizer", "row_limit", "auth", "transport"]},
                                "field": {"type": "string", "example": "region"},
                            },
                        },
                    },
                },
                "QueryResult": {
                    "type": "object",
                    "required": ["request_id", "status", "data"],
                    "properties": {
                        "request_id": {"type": "string"},
                        "status": {"type": "integer", "enum": [200]},
                        "data": {
                            "type": "object",
                            "required": ["template_id", "columns", "row_count", "truncated", "rows"],
                            "properties": {
                                "template_id": {"type": "string", "example": "sales_by_region"},
                                "columns": {"type": "array", "items": {"type": "string"}},
                                "row_count": {"type": "integer", "example": 4},
                                "truncated": {"type": "boolean", "description": "是否因行数上限被截断"},
                                "limit": {"type": "integer"},
                                "rows": {"type": "array", "items": {"type": "object"}},
                                "layers": {"type": "object", "description": "本次执行命中的防线配置回显"},
                            },
                        },
                    },
                },
                "FieldMeta": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "type": {"type": "string", "enum": ["string", "integer", "number", "date", "boolean"]},
                        "description": {"type": "string"},
                        "enum": {"type": "array", "items": {"type": "string"}},
                        "minimum": {"description": "下限（数值或日期）"},
                        "maximum": {"description": "上限（数值或日期）"},
                        "max_length": {"type": "integer"},
                        "pii": {"type": "boolean"},
                    },
                },
                "QueryTemplate": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "exposed_via_api": {"type": "boolean"},
                        "max_rows": {"type": "integer"},
                        "timeout_ms": {"type": "integer"},
                        "params": {"type": "array", "items": {"type": "object"}},
                        "selectable_fields": {"type": "array", "items": {"type": "string"}},
                        "views": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "AuditEntry": {
                    "type": "object",
                    "properties": {
                        "seq": {"type": "integer"},
                        "at": {"type": "string", "format": "date-time"},
                        "request_id": {"type": "string"},
                        "source": {"type": "string", "enum": ["http", "local"]},
                        "method": {"type": "string"},
                        "path": {"type": "string"},
                        "template_id": {"type": "string", "nullable": True},
                        "outcome": {"type": "string", "enum": ["allowed", "rejected"]},
                        "status": {"type": "integer"},
                        "error_code": {"type": "string", "nullable": True},
                        "rows": {"type": "integer", "nullable": True},
                        "token_id": {"type": "string"},
                        "client_ip": {"type": "string"},
                    },
                },
            },
            "responses": {},
        },
        "x-read-only": True,
        "x-allowed-methods": list(limits.allow_methods),
        "x-guard-layers": [
            {
                "layer": "L1",
                "name": "数据库只读凭据",
                "mechanisms": ["file:...?mode=ro", "PRAGMA query_only=ON", "sqlite3 set_authorizer"],
                "denied_actions": [
                    "SQLITE_INSERT",
                    "SQLITE_UPDATE",
                    "SQLITE_DELETE",
                    "SQLITE_DROP_TABLE",
                    "SQLITE_DROP_VIEW",
                    "SQLITE_ALTER_TABLE",
                    "SQLITE_CREATE_TABLE",
                    "SQLITE_CREATE_VIEW",
                    "SQLITE_PRAGMA",
                    "SQLITE_ATTACH",
                    "SQLITE_DETACH",
                    "SQLITE_TRANSACTION",
                    "SQLITE_SAVEPOINT",
                ],
            },
            {
                "layer": "L2",
                "name": "语句白名单",
                "mechanisms": ["单语句", "首关键字 SELECT/WITH", "禁注释", "禁写关键字", "视图白名单"],
                "error_codes": ["E_SQL_NOT_ALLOWED", "E_SQL_MULTI_STATEMENT", "E_SQL_COMMENT", "E_VIEW_NOT_ALLOWED"],
            },
            {
                "layer": "L3",
                "name": "行级与时间上限",
                "mechanisms": ["limit 校验", "fetchmany 截断 + truncated 标记", "progress handler 超时中断"],
                "limits": {
                    "max_rows_hard": limits.max_rows_hard,
                    "query_timeout_ms": limits.query_timeout_ms,
                },
                "error_codes": ["E_ROW_LIMIT", "E_TIMEOUT"],
            },
        ],
        "x-rate-limit": {
            "algorithm": "sliding_window",
            "default_limit": limits.rate_limit_limit,
            "window_seconds": limits.rate_limit_window_s,
            "scope": "per token",
            "response_headers": ["Retry-After"],
        },
        "x-audit": {
            "enabled": True,
            "fields": ["seq", "at", "request_id", "source", "method", "path", "template_id", "outcome", "status", "error_code", "rows", "token_id", "client_ip", "params", "layer"],
            "token_storage": "id + masked，明文不落盘",
        },
    }

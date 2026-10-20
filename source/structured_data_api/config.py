"""配置加载与校验。

四份配置各司其职：
  fields.json          字段白名单（输入字段 + 允许出现在结果里的列名）
  access_contract.json 视图白名单 + 查询模板白名单
  limits.json          行数上限、超时、限流、API 运行参数
  auth.json            演示令牌与 scope

加载即校验：配置写错（模板引用了未登记的视图、参数不在字段白名单内、
上限超过硬上限、allow_methods 里出现写方法等）会直接抛 ConfigError，
不会带着坏配置跑起来。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from . import views as views_module
from .model import (
    AccessContract,
    AuthConfig,
    AuthToken,
    FieldMeta,
    Limits,
    QueryTemplate,
)

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"})
KNOWN_SCOPES = frozenset({"query", "audit"})


class ConfigError(Exception):
    """配置不合法。加载期失败优于运行期带病工作。"""


@dataclass(frozen=True)
class ConfigBundle:
    contract: AccessContract
    limits: Limits
    auth: AuthConfig
    config_dir: Path

    @property
    def fields(self) -> Mapping[str, FieldMeta]:
        return self.contract.fields

    def describe(self) -> str:
        return (
            f"契约 {self.contract.contract_version} | 模板 {len(self.contract.templates)} 个"
            f"（对外 {len(self.contract.exposed_templates())}）| 视图 {len(self.contract.allowed_views)} 个"
            f" | 字段 {len(self.contract.fields)} 个 | 硬上限 {self.limits.max_rows_hard} 行"
        )


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigError(f"配置文件不存在：{path}")
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"配置文件不可读：{path}（{exc}）") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path.name} 不是合法 JSON：第 {exc.lineno} 行 {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path.name} 顶层必须是对象")
    return data


def _require_int(data: Mapping[str, Any], key: str, *, minimum: int = 1) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"limits.json 的 {key} 必须是整数，实际：{value!r}")
    if value < minimum:
        raise ConfigError(f"limits.json 的 {key} 必须 >= {minimum}，实际：{value}")
    return value


def load_limits(path: Path) -> Limits:
    data = read_json(path)
    max_rows_hard = _require_int(data, "max_rows_hard")
    if max_rows_hard > 1000:
        raise ConfigError(
            f"limits.json 中 max_rows_hard={max_rows_hard} 超过实现允许的上限 1000"
        )
    default_rows = _require_int(data, "default_rows")
    if default_rows > max_rows_hard:
        raise ConfigError(
            f"limits.json 的 default_rows({default_rows}) 不能大于 max_rows_hard({max_rows_hard})"
        )
    query_timeout_ms = _require_int(data, "query_timeout_ms")
    benchmark_timeout_ms = _require_int(data, "benchmark_timeout_ms")
    if benchmark_timeout_ms > query_timeout_ms:
        raise ConfigError("limits.json 的 benchmark_timeout_ms 不能大于 query_timeout_ms")
    rate = data.get("rate_limit") or {}
    if not isinstance(rate, dict):
        raise ConfigError("limits.json 的 rate_limit 必须是对象")
    audit = data.get("audit") or {}
    api = data.get("api") or {}
    if not isinstance(api, dict):
        raise ConfigError("limits.json 的 api 必须是对象")
    allow_methods = api.get("allow_methods", ["GET"])
    if not isinstance(allow_methods, list) or not allow_methods:
        raise ConfigError("limits.json 的 api.allow_methods 必须是非空数组")
    methods = tuple(str(m).upper() for m in allow_methods)
    bad = [m for m in methods if m != "GET"]
    if bad:
        raise ConfigError(
            "limits.json 的 api.allow_methods 只能是 GET（本服务只读），发现：" + ", ".join(bad)
        )
    return Limits(
        max_rows_hard=max_rows_hard,
        default_rows=default_rows,
        max_param_length=_require_int(data, "max_param_length"),
        max_params=_require_int(data, "max_params"),
        max_url_length=_require_int(data, "max_url_length"),
        query_timeout_ms=query_timeout_ms,
        benchmark_timeout_ms=benchmark_timeout_ms,
        rate_limit_limit=_require_int(rate, "limit"),
        rate_limit_window_s=_require_int(rate, "window_seconds"),
        audit_max_entries=_require_int(audit, "max_entries"),
        api_host=str(api.get("host", "127.0.0.1")),
        api_port=int(api.get("port", 0)),
        allow_methods=methods,
        healthz_without_auth=bool(api.get("healthz_without_auth", True)),
        server_header=str(api.get("server_header", "StructuredDataApi/1.0")),
    )


def load_fields(path: Path, limits: Limits) -> tuple[dict[str, FieldMeta], tuple[str, ...]]:
    data = read_json(path)
    raw_fields = data.get("fields")
    if not isinstance(raw_fields, list) or not raw_fields:
        raise ConfigError("fields.json 的 fields 必须是非空数组")
    fields: dict[str, FieldMeta] = {}
    for raw in raw_fields:
        if not isinstance(raw, dict) or "name" not in raw or "type" not in raw:
            raise ConfigError(f"fields.json 字段定义不完整：{raw!r}")
        meta = FieldMeta.from_dict(raw, maximum_override=limits.max_rows_hard)
        if meta.name in fields:
            raise ConfigError(f"fields.json 字段重复：{meta.name}")
        if meta.type not in {"string", "integer", "number", "date", "boolean"}:
            raise ConfigError(f"字段 {meta.name} 的类型 {meta.type!r} 不受支持")
        if meta.type in {"string", "date"} and not meta.max_length:
            raise ConfigError(f"字段 {meta.name} 缺少 max_length")
        if meta.max_length and meta.max_length > limits.max_param_length:
            raise ConfigError(
                f"字段 {meta.name} 的 max_length({meta.max_length}) 超过 limits.max_param_length"
            )
        fields[meta.name] = meta
    output_fields = tuple(str(x) for x in data.get("output_fields", ()))
    if not output_fields:
        raise ConfigError("fields.json 缺少 output_fields（允许出现在结果里的列名白名单）")
    return fields, output_fields


def load_contract(
    path: Path,
    fields: Mapping[str, FieldMeta],
    output_fields: tuple[str, ...],
    limits: Limits,
) -> AccessContract:
    data = read_json(path)
    if not bool(data.get("read_only", False)):
        raise ConfigError("access_contract.json 必须声明 read_only=true")
    allowed_views = tuple(str(v) for v in data.get("allowed_views", ()))
    if not allowed_views:
        raise ConfigError("access_contract.json 缺少 allowed_views")
    unknown_views = [v for v in allowed_views if v not in views_module.VIEW_DEFINITIONS]
    if unknown_views:
        raise ConfigError(
            "allowed_views 里有未在 views.py 定义的视图：" + ", ".join(unknown_views)
        )
    raw_templates = data.get("templates")
    if not isinstance(raw_templates, list) or not raw_templates:
        raise ConfigError("access_contract.json 的 templates 必须是非空数组")
    templates: dict[str, QueryTemplate] = {}
    for raw in raw_templates:
        if not isinstance(raw, dict) or "id" not in raw or "sql" not in raw:
            raise ConfigError(f"模板定义不完整：{raw!r}")
        tpl = QueryTemplate.from_dict(raw)
        if tpl.id in templates:
            raise ConfigError(f"模板 id 重复：{tpl.id}")
        if not tpl.views:
            raise ConfigError(f"模板 {tpl.id} 必须声明 views（用于白名单核对）")
        bad_views = [v for v in tpl.views if v not in allowed_views]
        if bad_views:
            raise ConfigError(f"模板 {tpl.id} 引用了未授权视图：{', '.join(bad_views)}")
        if not tpl.selectable_fields:
            raise ConfigError(f"模板 {tpl.id} 必须声明 selectable_fields")
        bad_cols = [c for c in tpl.selectable_fields if c not in output_fields]
        if bad_cols:
            raise ConfigError(f"模板 {tpl.id} 的结果列不在 output_fields 白名单内：{', '.join(bad_cols)}")
        if not tpl.params:
            if tpl.purpose != "timeout_probe":
                raise ConfigError(f"模板 {tpl.id} 没有任何参数，却也不是 timeout_probe")
        for param in tpl.params:
            if param.name not in fields:
                raise ConfigError(f"模板 {tpl.id} 的参数 {param.name} 不在 fields.json 白名单内")
            if param.required and param.default is not None:
                raise ConfigError(f"模板 {tpl.id} 的必填参数 {param.name} 不应有默认值")
        if tpl.max_rows > limits.max_rows_hard:
            raise ConfigError(
                f"模板 {tpl.id} 的 max_rows({tpl.max_rows}) 超过 limits.max_rows_hard"
            )
        if tpl.timeout_ms is not None and tpl.timeout_ms > limits.query_timeout_ms:
            raise ConfigError(
                f"模板 {tpl.id} 的 timeout_ms({tpl.timeout_ms}) 超过 limits.query_timeout_ms"
            )
        if tpl.exposed_via_api and tpl.purpose == "timeout_probe":
            raise ConfigError(f"模板 {tpl.id} 是 timeout_probe，不允许对外暴露")
        templates[tpl.id] = tpl
    return AccessContract(
        contract_version=str(data.get("contract_version", "0.0.0")),
        name=str(data.get("name", "structured-data-api")),
        dialect=str(data.get("dialect", "sqlite")),
        read_only=True,
        allowed_views=allowed_views,
        templates=templates,
        fields=dict(fields),
        output_fields=output_fields,
        notes=tuple(str(n) for n in data.get("notes", ())),
    )


def load_auth(path: Path, limits: Limits) -> AuthConfig:
    data = read_json(path)
    header = str(data.get("header", "X-API-Token"))
    raw_tokens = data.get("tokens")
    if not isinstance(raw_tokens, list) or not raw_tokens:
        raise ConfigError("auth.json 的 tokens 必须是非空数组")
    tokens: dict[str, AuthToken] = {}
    ids: set[str] = set()
    for raw in raw_tokens:
        if not isinstance(raw, dict) or not raw.get("token"):
            raise ConfigError(f"auth.json 令牌定义不完整：{raw!r}")
        token_id = str(raw.get("id", ""))
        if not token_id or token_id in ids:
            raise ConfigError(f"auth.json 令牌 id 缺失或重复：{token_id!r}")
        ids.add(token_id)
        scopes = tuple(str(s) for s in raw.get("scopes", ()))
        if not scopes or any(s not in KNOWN_SCOPES for s in scopes):
            raise ConfigError(f"令牌 {token_id} 的 scopes 非法：{scopes}")
        rate = raw.get("rate_limit") or {}
        tokens[str(raw["token"])] = AuthToken(
            id=token_id,
            token=str(raw["token"]),
            scopes=scopes,
            rate_limit_limit=int(rate["limit"]) if "limit" in rate else None,
            rate_limit_window_s=int(rate["window_seconds"]) if "window_seconds" in rate else None,
        )
    return AuthConfig(header=header, tokens=tokens)


def load_config_dir(config_dir: Path) -> ConfigBundle:
    config_dir = Path(config_dir)
    limits = load_limits(config_dir / "limits.json")
    fields, output_fields = load_fields(config_dir / "fields.json", limits)
    contract = load_contract(config_dir / "access_contract.json", fields, output_fields, limits)
    auth = load_auth(config_dir / "auth.json", limits)
    return ConfigBundle(contract=contract, limits=limits, auth=auth, config_dir=config_dir)

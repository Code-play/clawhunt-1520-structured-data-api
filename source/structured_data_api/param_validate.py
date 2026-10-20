"""参数校验：类型、范围、白名单字段、注入式输入。

校验是"先拒绝、再执行"：任何一条不满足都抛 ApiError（带错误码 + 字段名 + 可读中文消息），
不会把可疑输入带到 SQL 层。校验分四道：

  1. 请求体形状：只允许 template / params / limit 三个键
  2. 模板白名单：template 必须是已登记且（对 API）对外暴露的模板
  3. 字段白名单：参数必须在 fields.json 且在该模板的 params 内
  4. 值校验：类型 -> 长度 -> 注入特征 -> 枚举 -> 范围（含 date_from <= date_to 跨字段约束）
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any, Mapping

from .model import (
    AccessContract,
    ApiError,
    ErrorCode,
    FieldMeta,
    Limits,
    QueryRequest,
)

TOP_LEVEL_KEYS = ("template", "params", "limit")

_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("分号（多语句拼接）", re.compile(r";")),
    ("单行注释", re.compile(r"--")),
    ("块注释", re.compile(r"/\*|\*/")),
    ("引号（尝试闭合字符串）", re.compile(r"['\"`]")),
    (
        "SQL 关键字序列",
        re.compile(
            r"\b(union\s+select|union\s+all|drop\s+(table|view|index)|"
            r"insert\s+into|delete\s+from|update\s+\w+\s+set|"
            r"attach\s+database|detach\s+database|pragma|vacuum|alter\s+table)\b",
            re.IGNORECASE,
        ),
    ),
    ("控制字符", re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")),
)

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _preview(value: Any, limit: int = 40) -> str:
    text = value if isinstance(value, str) else repr(value)
    text = "".join(ch if 32 <= ord(ch) < 127 or ord(ch) > 127 else "?" for ch in text)
    return text if len(text) <= limit else text[:limit] + "..."


def check_injection(field_name: str, value: str) -> None:
    """注入式输入检测（防御性，纵深用；真正的注入防护是参数绑定 + 语句白名单）。"""
    for label, pattern in _INJECTION_PATTERNS:
        if pattern.search(value):
            raise ApiError(
                ErrorCode.PARAM_INJECTION,
                f"参数 {field_name} 包含注入特征（{label}），已拒绝；值：{_preview(value)}",
                field_name=field_name,
                layer="param",
                detail=f"matched={label}",
            )


def _expect_str(field_name: str, value: Any) -> str:
    if not isinstance(value, str):
        raise ApiError(
            ErrorCode.PARAM_TYPE,
            f"参数 {field_name} 期望字符串，实际是 {type(value).__name__}",
            field_name=field_name,
            layer="param",
        )
    return value


def _check_length(field_name: str, value: str, meta: FieldMeta) -> None:
    if meta.max_length is not None and len(value) > meta.max_length:
        raise ApiError(
            ErrorCode.PARAM_LENGTH,
            f"参数 {field_name} 长度 {len(value)} 超过上限 {meta.max_length}",
            field_name=field_name,
            layer="param",
        )


def _check_string(field_name: str, value: Any, meta: FieldMeta) -> str:
    text = _expect_str(field_name, value)
    check_injection(field_name, text)
    _check_length(field_name, text, meta)
    if meta.enum and text not in meta.enum:
        raise ApiError(
            ErrorCode.PARAM_ENUM,
            f"参数 {field_name}={_preview(text)} 不在枚举白名单内：{', '.join(meta.enum)}",
            field_name=field_name,
            layer="param",
        )
    if not meta.enum and not text.strip():
        raise ApiError(
            ErrorCode.PARAM_RANGE,
            f"参数 {field_name} 不能是空字符串",
            field_name=field_name,
            layer="param",
        )
    return text


def _check_date(field_name: str, value: Any, meta: FieldMeta) -> str:
    text = _expect_str(field_name, value)
    _check_length(field_name, text, meta)
    if not _DATE_RE.match(text):
        raise ApiError(
            ErrorCode.PARAM_TYPE,
            f"参数 {field_name} 必须是 YYYY-MM-DD 格式的日期，实际：{_preview(text)}",
            field_name=field_name,
            layer="param",
        )
    try:
        parsed = date.fromisoformat(text)
    except ValueError:
        raise ApiError(
            ErrorCode.PARAM_TYPE,
            f"参数 {field_name} 不是合法日历日期：{_preview(text)}",
            field_name=field_name,
            layer="param",
        ) from None
    if meta.minimum is not None and parsed < date.fromisoformat(str(meta.minimum)):
        raise ApiError(
            ErrorCode.PARAM_RANGE,
            f"参数 {field_name}={text} 早于允许范围下限 {meta.minimum}",
            field_name=field_name,
            layer="param",
        )
    if meta.maximum is not None and parsed > date.fromisoformat(str(meta.maximum)):
        raise ApiError(
            ErrorCode.PARAM_RANGE,
            f"参数 {field_name}={text} 晚于允许范围上限 {meta.maximum}",
            field_name=field_name,
            layer="param",
        )
    return text


def _check_integer(
    field_name: str,
    value: Any,
    meta: FieldMeta,
    *,
    hard_cap: int | None = None,
    cap_reason: str = "",
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ApiError(
            ErrorCode.PARAM_TYPE,
            f"参数 {field_name} 期望整数，实际是 {type(value).__name__}（布尔值不算整数）",
            field_name=field_name,
            layer="param",
        )
    cap = hard_cap if hard_cap is not None else meta.maximum
    if meta.minimum is not None and value < int(meta.minimum):
        raise ApiError(
            ErrorCode.PARAM_RANGE,
            f"参数 {field_name}={value} 小于下限 {meta.minimum}",
            field_name=field_name,
            layer="param",
        )
    if cap is not None and value > int(cap):
        code = ErrorCode.ROW_LIMIT if hard_cap is not None else ErrorCode.PARAM_RANGE
        raise ApiError(
            code,
            f"参数 {field_name}={value} 超过上限 {cap}{cap_reason}",
            field_name=field_name,
            layer="param",
        )
    return value


def _check_number(field_name: str, value: Any, meta: FieldMeta) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ApiError(
            ErrorCode.PARAM_TYPE,
            f"参数 {field_name} 期望数值，实际是 {type(value).__name__}",
            field_name=field_name,
            layer="param",
        )
    if meta.minimum is not None and value < meta.minimum:
        raise ApiError(
            ErrorCode.PARAM_RANGE,
            f"参数 {field_name}={value} 小于下限 {meta.minimum}",
            field_name=field_name,
            layer="param",
        )
    if meta.maximum is not None and value > meta.maximum:
        raise ApiError(
            ErrorCode.PARAM_RANGE,
            f"参数 {field_name}={value} 超过上限 {meta.maximum}",
            field_name=field_name,
            layer="param",
        )
    return float(value)


def validate_value(field_name: str, value: Any, meta: FieldMeta) -> Any:
    if meta.type == "string":
        return _check_string(field_name, value, meta)
    if meta.type == "date":
        return _check_date(field_name, value, meta)
    if meta.type == "integer":
        return _check_integer(field_name, value, meta)
    if meta.type == "number":
        return _check_number(field_name, value, meta)
    if meta.type == "boolean":
        if not isinstance(value, bool):
            raise ApiError(
                ErrorCode.PARAM_TYPE,
                f"参数 {field_name} 期望布尔值",
                field_name=field_name,
                layer="param",
            )
        return value
    raise ApiError(
        ErrorCode.PARAM_TYPE,
        f"参数 {field_name} 的声明类型 {meta.type!r} 不受支持",
        field_name=field_name,
        layer="param",
    )


def validate_request(
    raw: Any,
    contract: AccessContract,
    limits: Limits,
    *,
    allow_unexposed: bool = False,
) -> QueryRequest:
    if not isinstance(raw, Mapping):
        raise ApiError(
            ErrorCode.PARAM_TYPE,
            f"请求必须是 JSON 对象，实际是 {type(raw).__name__}",
            layer="param",
        )
    unknown_top = [k for k in raw if k not in TOP_LEVEL_KEYS]
    if unknown_top:
        raise ApiError(
            ErrorCode.PARAM_UNKNOWN,
            f"请求包含未定义的键 {', '.join(sorted(unknown_top))}；"
            f"只允许 {', '.join(TOP_LEVEL_KEYS)}。本服务不接受客户端提交 SQL。",
            field_name=str(unknown_top[0]),
            layer="param",
        )
    if "template" not in raw:
        raise ApiError(
            ErrorCode.PARAM_MISSING,
            "缺少必填参数 template（查询模板 id）",
            field_name="template",
            layer="param",
        )
    template_id = raw["template"]
    if not isinstance(template_id, str) or not template_id.strip():
        raise ApiError(
            ErrorCode.PARAM_TYPE,
            "参数 template 必须是非空字符串",
            field_name="template",
            layer="param",
        )
    template_id = template_id.strip()
    if template_id not in contract.templates:
        raise ApiError(
            ErrorCode.TEMPLATE_UNKNOWN,
            f"查询模板 {template_id!r} 不存在；可用模板：{', '.join(sorted(contract.templates))}",
            field_name="template",
            layer="param",
        )
    template = contract.templates[template_id]
    if not template.exposed_via_api and not allow_unexposed:
        raise ApiError(
            ErrorCode.TEMPLATE_UNKNOWN,
            f"查询模板 {template_id!r} 不存在或未对外开放",
            field_name="template",
            layer="param",
        )

    raw_params = raw.get("params", {})
    if raw_params is None:
        raw_params = {}
    if not isinstance(raw_params, Mapping):
        raise ApiError(
            ErrorCode.PARAM_TYPE,
            f"params 必须是对象，实际是 {type(raw_params).__name__}",
            field_name="params",
            layer="param",
        )
    params = dict(raw_params)
    if len(params) > limits.max_params:
        raise ApiError(
            ErrorCode.PARAM_LENGTH,
            f"参数个数 {len(params)} 超过上限 {limits.max_params}",
            field_name="params",
            layer="param",
        )

    if "limit" in params and "limit" in raw:
        raise ApiError(
            ErrorCode.PARAM_DUPLICATE,
            "limit 同时出现在 params 与顶层，无法判断以哪个为准",
            field_name="limit",
            layer="param",
        )
    raw_limit: Any = raw["limit"] if "limit" in raw else params.pop("limit", None)

    for name in params:
        if name not in contract.fields:
            raise ApiError(
                ErrorCode.PARAM_UNKNOWN,
                f"参数 {name!r} 不在全局字段白名单内；允许：{', '.join(sorted(contract.fields))}",
                field_name=str(name),
                layer="param",
            )
        if template.param(name) is None:
            raise ApiError(
                ErrorCode.PARAM_NOT_IN_TEMPLATE,
                f"参数 {name!r} 不在模板 {template.id} 的允许字段内；"
                f"该模板允许：{', '.join(template.allowed_params)}",
                field_name=str(name),
                layer="param",
            )

    validated: dict[str, Any] = {}
    for spec in template.params:
        if spec.name == "limit":
            continue
        if spec.name in params:
            meta = contract.field(spec.name)
            validated[spec.name] = validate_value(spec.name, params[spec.name], meta)
        elif spec.required:
            raise ApiError(
                ErrorCode.PARAM_MISSING,
                f"缺少必填参数 {spec.name}（模板 {template.id}）",
                field_name=spec.name,
                layer="param",
            )
        else:
            validated[spec.name] = spec.default

    limit_spec = template.param("limit")
    if limit_spec is None:
        if raw_limit is not None:
            raise ApiError(
                ErrorCode.PARAM_NOT_IN_TEMPLATE,
                f"模板 {template.id} 不接受 limit 参数",
                field_name="limit",
                layer="param",
            )
        limit = limits.default_rows
    else:
        if raw_limit is None:
            limit = int(limit_spec.default if limit_spec.default is not None else limits.default_rows)
        else:
            cap = min(template.max_rows, limits.max_rows_hard)
            limit = _check_integer(
                "limit",
                raw_limit,
                contract.field("limit"),
                hard_cap=cap,
                cap_reason=f"（模板 {template.id} 上限 {template.max_rows} 行，全局硬上限 {limits.max_rows_hard} 行）",
            )
        limit = min(limit, template.max_rows, limits.max_rows_hard)

    _check_date_order(validated)

    return QueryRequest(
        template_id=template.id,
        params=validated,
        limit=limit,
        raw=dict(raw),
    )


def _check_date_order(params: Mapping[str, Any]) -> None:
    if "date_from" in params and "date_to" in params:
        start, end = params.get("date_from"), params.get("date_to")
        if isinstance(start, str) and isinstance(end, str) and start > end:
            raise ApiError(
                ErrorCode.PARAM_RANGE,
                f"date_from={start} 晚于 date_to={end}，日期区间为空",
                field_name="date_from",
                layer="param",
            )

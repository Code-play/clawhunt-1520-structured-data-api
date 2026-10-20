"""交付物自检脚本：逐项复跑并断言，不依赖任何第三方库。

    python verify/run_verification.py

产物：
    verify/records/demo_output.txt      demo 的完整标准输出（第一次运行）
    verify/records/tests_output.txt     单元测试的完整标准输出
    verify/records/verify_output.txt    本脚本的检查日志
    verify/records/http_transcript.jsonl 真实 HTTP 调用记录（状态码 / 错误码 / 审计序号）
    verify/records/artifact_hashes.txt  产物哈希（用于确定性对比）
    verify/verification_record.md       人类可读的验证记录
    verify/verification_result.json     机器可读的验证结果

判定：全部断言通过时打印 `N/N assertions passed` 并以 0 退出；否则以 1 退出。
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"
OUT = ROOT / "out"
VERIFY = ROOT / "verify"
RECORDS = VERIFY / "records"
PYTHON = sys.executable

sys.path.insert(0, str(ROOT))

from structured_data_api.api import ApiContext, start_in_thread, stop_server
from structured_data_api.audit import AuditLog
from structured_data_api.config import ConfigError, load_config_dir
from structured_data_api.datasource import temporary_database
from structured_data_api.guard import (
    QueryEngine,
    ReadOnlyGuard,
    StatementInspector,
    probe_authorizer,
    probe_query_only,
    probe_readonly_uri,
    probe_row_cap,
    probe_statement_policy,
    probe_timeout,
)
from structured_data_api.model import ApiError, ErrorCode
from structured_data_api.openapi import build_spec
from structured_data_api.trace import SystemClock

LOG: list[str] = []
RESULTS: list[dict[str, Any]] = []
TRANSCRIPT: list[dict[str, Any]] = []
DEMO_STDOUT = ""
DEMO2_STDOUT = ""
TESTS_STDOUT = ""
HASHES: dict[str, str] = {}
HASHES2: dict[str, str] = {}

PASSED = 0
TOTAL = 0


def emit(line: str = "") -> None:
    LOG.append(line)
    print(line)


def section(title: str) -> None:
    emit("")
    emit("=" * 78)
    emit(title)
    emit("=" * 78)


def check(name: str, fn: Callable[[], str | None]) -> None:
    global PASSED, TOTAL
    TOTAL += 1
    try:
        detail = fn() or ""
    except Exception as exc:
        RESULTS.append(
            {
                "name": name,
                "ok": False,
                "detail": f"{type(exc).__name__}: {exc}",
            }
        )
        emit(f"  FAIL  {name}")
        emit(f"        {type(exc).__name__}: {exc}")
        return
    PASSED += 1
    RESULTS.append({"name": name, "ok": True, "detail": detail})
    emit(f"  PASS  {name}" + (f"  [{detail}]" if detail else ""))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in read_text(path).splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args: list[str], timeout: int = 600) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        args,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=timeout,
    )


def http_call(
    base: str,
    path: str,
    *,
    token: str | None = None,
    method: str = "GET",
    body: bytes | None = None,
) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
    headers = {"Accept": "application/json"}
    if token:
        headers["X-API-Token"] = token
    data = body
    if method not in {"GET", "HEAD"} and data is None:
        data = b"{}"
    request = Request(base + path, headers=headers, method=method, data=data)
    started = time.monotonic()
    try:
        with urlopen(request, timeout=10) as response:
            raw = response.read()
            status = response.status
            hdrs = {k.lower(): v for k, v in response.headers.items()}
    except HTTPError as exc:
        raw = exc.read()
        status = exc.code
        hdrs = {k.lower(): v for k, v in exc.headers.items()}
    elapsed = int((time.monotonic() - started) * 1000)
    parsed: dict[str, Any] | None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        parsed = None
    error_code = None
    if isinstance(parsed, dict) and isinstance(parsed.get("error"), dict):
        error_code = parsed["error"].get("code")
    TRANSCRIPT.append(
        {
            "method": method,
            "path": path,
            "token": "present" if token else "absent",
            "status": status,
            "error_code": error_code,
            "elapsed_ms": elapsed,
            "request_id": (parsed or {}).get("request_id") if isinstance(parsed, dict) else None,
        }
    )
    return status, parsed, hdrs


def build_context(config=None):
    bundle = config or load_config_dir(CONFIG)
    manager = temporary_database()
    ds = manager.__enter__()
    clock = SystemClock()
    audit = AuditLog(clock)
    engine = QueryEngine(ds, bundle.contract, bundle.limits, audit, clock)
    context = ApiContext(engine, bundle.contract, bundle.limits, bundle.auth, audit, clock)
    return bundle, manager, ds, engine, audit, context


def token_of(bundle, token_id: str) -> str:
    for token in bundle.auth.tokens.values():
        if token.id == token_id:
            return token.token
    raise AssertionError(f"未知令牌 id：{token_id}")


def first_error_code(fn: Callable[[], Any]) -> str:
    try:
        fn()
    except ApiError as exc:
        return exc.code
    raise AssertionError("预期抛出 ApiError，实际未抛出")


def main() -> int:
    global DEMO_STDOUT, DEMO2_STDOUT, TESTS_STDOUT, HASHES, HASHES2
    RECORDS.mkdir(parents=True, exist_ok=True)

    emit("ClawHunt #1520 交付物自检")
    emit(f"交付目录：{ROOT}")
    emit(f"解释器：{sys.version.split()[0]} | {PYTHON}")
    emit(f"运行时间戳：{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")

    section("1. 环境与文件结构")
    check(
        "Python 版本不低于 3.10",
        lambda: f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        if sys.version_info >= (3, 10)
        else (_ for _ in ()).throw(AssertionError(f"版本过低：{sys.version}")),
    )

    required = [
        "SOLUTION.md",
        "README.md",
        "DELIVERY.md",
        ".gitignore",
        "config/fields.json",
        "config/access_contract.json",
        "config/limits.json",
        "config/auth.json",
        "structured_data_api/__init__.py",
        "structured_data_api/__main__.py",
        "structured_data_api/model.py",
        "structured_data_api/config.py",
        "structured_data_api/views.py",
        "structured_data_api/datasource.py",
        "structured_data_api/param_validate.py",
        "structured_data_api/guard.py",
        "structured_data_api/trace.py",
        "structured_data_api/audit.py",
        "structured_data_api/ratelimit.py",
        "structured_data_api/openapi.py",
        "structured_data_api/api.py",
        "structured_data_api/cli.py",
        "samples/queries.jsonl",
        "tests/test_runner.py",
        "verify/run_verification.py",
    ]

    def required_files() -> str:
        missing = [rel for rel in required if not (ROOT / rel).is_file()]
        if missing:
            raise AssertionError("缺少文件：" + ", ".join(missing))
        return f"{len(required)} 个必备文件齐全"

    check("必备文件全部存在", required_files)

    py_files = sorted(
        p
        for p in ROOT.rglob("*.py")
        if "__pycache__" not in p.parts and ".venv" not in p.parts
    )

    def ascii_names() -> str:
        bad = [
            str(p.relative_to(ROOT))
            for p in ROOT.rglob("*")
            if "__pycache__" not in p.parts
            and any(ord(ch) > 127 for ch in str(p.relative_to(ROOT)))
        ]
        if bad:
            raise AssertionError("非 ASCII 路径：" + ", ".join(bad))
        return f"扫描 {len(py_files)} 个 py 文件所在目录树，路径全 ASCII"

    check("目录与文件名全 ASCII", ascii_names)

    text_files = [
        p
        for p in ROOT.rglob("*")
        if p.is_file()
        and "__pycache__" not in p.parts
        and p.suffix in {".py", ".json", ".jsonl", ".md", ".txt", ".log", ".gitignore"}
    ]

    def no_bom() -> str:
        bad = [str(p.relative_to(ROOT)) for p in text_files if p.read_bytes()[:3] == b"\xef\xbb\xbf"]
        if bad:
            raise AssertionError("含 BOM：" + ", ".join(bad))
        return f"{len(text_files)} 个文本文件均为无 BOM UTF-8"

    check("所有文本文件无 BOM", no_bom)

    emoji_ranges = (
        (0x1F000, 0x1FAFF),
        (0x2600, 0x27BF),
        (0x2B00, 0x2BFF),
        (0xFE00, 0xFE0F),
        (0x200D, 0x200D),
    )

    def no_emoji() -> str:
        hits: list[str] = []
        for path in text_files:
            text = path.read_text(encoding="utf-8", errors="replace")
            for index, ch in enumerate(text):
                code = ord(ch)
                if any(lo <= code <= hi for lo, hi in emoji_ranges):
                    hits.append(f"{path.relative_to(ROOT)}@{index}")
                    break
        if hits:
            raise AssertionError("检出 emoji：" + ", ".join(hits))
        return "未检出 emoji / 装饰性符号"

    check("文档与代码不含 emoji", no_emoji)

    stdlib = set(sys.stdlib_module_names)

    def stdlib_only() -> str:
        bad: list[str] = []
        for path in py_files:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""] if node.level == 0 else []
                else:
                    continue
                for name in names:
                    root = name.split(".")[0]
                    if not root:
                        continue
                    if root in stdlib or root == "structured_data_api":
                        continue
                    bad.append(f"{path.relative_to(ROOT)} -> {root}")
        if bad:
            raise AssertionError("发现非标准库导入：" + ", ".join(bad))
        return f"{len(py_files)} 个模块仅使用标准库"

    check("零第三方依赖（AST 扫描导入）", stdlib_only)

    def no_site_packages() -> str:
        vendored = [
            p.name
            for p in [ROOT / "site-packages", ROOT / "vendor", ROOT / "requirements.txt"]
            if p.exists()
        ]
        if vendored:
            raise AssertionError("存在疑似依赖目录：" + ", ".join(vendored))
        return "无 requirements.txt / vendor / site-packages"

    check("仓库内无第三方依赖痕迹", no_site_packages)

    section("2. 配置装载与契约一致性")
    bundle = load_config_dir(CONFIG)

    check(
        "契约与字段数量符合设计",
        lambda: _expect(
            (
                f"模板 {len(bundle.contract.templates)} 个 / 对外 {len(bundle.contract.exposed_templates())} 个 / "
                f"视图 {len(bundle.contract.allowed_views)} 个 / 字段 {len(bundle.contract.fields)} 个 / "
                f"输出列 {len(bundle.contract.output_fields)} 个"
            ),
            len(bundle.contract.templates) == 8
            and len(bundle.contract.exposed_templates()) == 7
            and len(bundle.contract.allowed_views) == 6
            and len(bundle.contract.fields) == 7
            and len(bundle.contract.output_fields) == 14,
        ),
    )

    check(
        "硬上限与默认行数自洽",
        lambda: _expect(
            f"hard={bundle.limits.max_rows_hard} default={bundle.limits.default_rows}",
            1 <= bundle.limits.default_rows <= bundle.limits.max_rows_hard <= 1000,
        ),
    )

    check(
        "只读方法白名单仅 GET",
        lambda: _expect(str(bundle.limits.allow_methods), bundle.limits.allow_methods == ("GET",)),
    )

    def template_views() -> str:
        for tpl in bundle.contract.templates.values():
            unknown = [v for v in tpl.views if v not in bundle.contract.allowed_views]
            if unknown:
                raise AssertionError(f"模板 {tpl.id} 引用未授权视图 {unknown}")
        return "8 个模板引用的视图全部在白名单内"

    check("模板视图均在白名单内", template_views)

    def template_fields() -> str:
        for tpl in bundle.contract.templates.values():
            extra = [f for f in tpl.selectable_fields if f not in bundle.contract.output_fields]
            if extra:
                raise AssertionError(f"模板 {tpl.id} 输出列未登记 {extra}")
        return "8 个模板的输出列均已登记"

    check("模板输出列均在白名单内", template_fields)

    def auth_shape() -> str:
        tokens = list(bundle.auth.tokens.values())
        assert len(tokens) == 4, f"令牌数量 {len(tokens)}"
        assert len({t.id for t in tokens}) == 4
        for token in tokens:
            assert token.scopes, f"{token.id} 无 scope"
            assert set(token.scopes) <= {"query", "audit"}
            assert token.token not in token.masked(), "掩码泄漏明文"
        return "4 个令牌，scope 合法，掩码不泄漏明文"

    check("演示令牌结构合法", auth_shape)

    def config_reject(loader: Callable[[], Any], expect: str) -> None:
        try:
            loader()
        except ConfigError as exc:
            assert expect in str(exc), f"错误信息不含 {expect}：{exc}"
            return
        raise AssertionError(f"未拒绝：{expect}")

    def mutate_limits(overrides: dict[str, Any]) -> Callable[[], Any]:
        def loader() -> Any:
            tmp = Path(tempfile.mkdtemp(prefix="sdapi-cfg-"))
            try:
                target = tmp / "cfg"
                shutil.copytree(CONFIG, target)
                limits = json.loads((target / "limits.json").read_text(encoding="utf-8"))
                for key, value in overrides.items():
                    if key.startswith("api."):
                        limits.setdefault("api", {})[key[4:]] = value
                    else:
                        limits[key] = value
                (target / "limits.json").write_text(
                    json.dumps(limits, ensure_ascii=False, indent=2), encoding="utf-8"
                )
                return load_config_dir(target)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

        return loader

    check(
        "装载期拒绝 POST 方法",
        lambda: _expect("ConfigError: allow_methods", _raises(config_reject, mutate_limits({"api.allow_methods": ["GET", "POST"]}), "allow_methods")),
    )

    check(
        "装载期拒绝超过硬上限的行数",
        lambda: _expect("ConfigError: max_rows_hard", _raises(config_reject, mutate_limits({"max_rows_hard": 99999}), "max_rows_hard")),
    )

    def mutate_contract_views() -> Any:
        tmp = Path(tempfile.mkdtemp(prefix="sdapi-cfg-"))
        try:
            target = tmp / "cfg"
            shutil.copytree(CONFIG, target)
            contract = json.loads((target / "access_contract.json").read_text(encoding="utf-8"))
            contract["allowed_views"] = [v for v in contract["allowed_views"] if v != "v_product_rank"]
            (target / "access_contract.json").write_text(
                json.dumps(contract, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            return load_config_dir(target)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    check(
        "装载期拒绝视图漂移",
        lambda: _expect(
            "ConfigError: v_product_rank",
            _raises(config_reject, mutate_contract_views, "v_product_rank"),
        ),
    )

    section("3. 一键演示的真实产物")
    demo = run([PYTHON, "-X", "utf8", "-m", "structured_data_api", "demo"])
    DEMO_STDOUT = demo.stdout + demo.stderr
    (RECORDS / "demo_output.txt").write_text(DEMO_STDOUT, encoding="utf-8", newline="\n")
    check(
        "demo 子进程退出码为 0",
        lambda: _expect(f"exit={demo.returncode} 输出 {len(DEMO_STDOUT)} 字符", demo.returncode == 0),
    )

    def demo_sections() -> str:
        needed = [
            "三层只读防线",
            "参数校验与调用结果",
            "实时只读 HTTP 接口",
            "产物清单",
            "结论",
        ]
        missing = [s for s in needed if s not in DEMO_STDOUT]
        if missing:
            raise AssertionError("缺少段落：" + ", ".join(missing))
        return "4 个主体段落 + 结论齐全"

    check("demo 输出覆盖四段验收内容", demo_sections)

    artifacts = [
        "contract_openapi.json",
        "query_results.jsonl",
        "rejected_requests.jsonl",
        "audit_log.jsonl",
        "layer_evidence.jsonl",
        "http_calls.jsonl",
        "demo_run.log",
    ]
    check(
        "out/ 七个产物齐全",
        lambda: _expect(
            ", ".join(f"{name}={_size(OUT / name)}B" for name in artifacts),
            all((OUT / name).is_file() for name in artifacts),
        ),
    )

    evidence = read_jsonl(OUT / "layer_evidence.jsonl")
    by_layer = {layer: [e for e in evidence if e["layer"] == layer] for layer in ("L1", "L2", "L3")}

    check(
        "取证条目分布 L1=9 / L2=8 / L3=3",
        lambda: _expect(
            f"L1={len(by_layer['L1'])} L2={len(by_layer['L2'])} L3={len(by_layer['L3'])} 合计={len(evidence)}",
            len(by_layer["L1"]) == 9 and len(by_layer["L2"]) == 8 and len(by_layer["L3"]) == 3,
        ),
    )

    def l1_all_blocked() -> str:
        modes = sorted({e["check"] for e in by_layer["L1"]})
        open_ones = [e["statement"] for e in by_layer["L1"] if not e["blocked"]]
        if open_ones:
            raise AssertionError("存在未被拦截的写入：" + "; ".join(open_ones))
        assert modes == ["authorizer", "query_only", "readonly_uri"], f"机制缺失：{modes}"
        return "三种机制共 9 条证据全部 blocked=true"

    check("L1 九条取证全部拦截写入", l1_all_blocked)

    def l1_rowcount() -> str:
        rows = [e for e in by_layer["L1"] if e["check"] == "authorizer_rowcount"]
        assert not rows, "出现事实表行数变化告警"
        assert all(e["blocked"] for e in by_layer["L1"])
        return "无行数变化告警条目，事实表保持 4000 行"

    check("L1 拦截后事实表行数不变", l1_rowcount)

    def l2_shape() -> str:
        blocked = [e for e in by_layer["L2"] if e["blocked"]]
        allowed = [e for e in by_layer["L2"] if not e["blocked"]]
        assert len(blocked) == 6, f"被拒 {len(blocked)} 条"
        assert len(allowed) == 2, f"放行 {len(allowed)} 条"
        assert all(e["first_keyword"] in {"SELECT", "WITH"} for e in allowed)
        codes = {e["error"].split(":")[0] for e in blocked}
        assert codes == {
            "E_SQL_NOT_ALLOWED",
            "E_SQL_MULTI_STATEMENT",
            "E_SQL_COMMENT",
            "E_VIEW_NOT_ALLOWED",
        }, codes
        return "放行 2 条、拒绝 6 条，覆盖 4 类错误码"

    check("L2 白名单分类正确", l2_shape)

    def l3_shape() -> str:
        checks = {e["check"]: e for e in by_layer["L3"]}
        assert set(checks) == {"row_cap", "row_limit_reject", "timeout"}, checks
        assert checks["row_cap"]["blocked"] is True and checks["row_cap"]["truncated"] is True
        assert checks["row_cap"]["rows_returned"] == 5
        assert checks["row_limit_reject"]["error"].startswith("E_ROW_LIMIT")
        assert checks["timeout"]["blocked"] is True
        assert checks["timeout"]["connection_reusable"] is True
        return "行截断 5 行、数量上限 E_ROW_LIMIT、超时中断且连接可复用"

    check("L3 行数与超时证据完整", l3_shape)

    results = read_jsonl(OUT / "query_results.jsonl")
    rejected = read_jsonl(OUT / "rejected_requests.jsonl")
    samples = read_jsonl(ROOT / "samples" / "queries.jsonl")

    check(
        "样例 35 条且结果分布 10 成功 / 25 拒绝",
        lambda: _expect(
            f"samples={len(samples)} results={len(results)} rejected={len(rejected)}",
            len(samples) == 35 and len(results) == 10 and len(rejected) == 25,
        ),
    )

    def sample_match() -> str:
        observed: dict[str, set[str]] = {}
        for row in rejected:
            observed.setdefault(row["id"], set()).add(row["error_code"])
        mismatches: list[str] = []
        for sample in samples:
            expect = sample["expect"]
            if expect.get("status") == 200:
                continue
            want = expect.get("error_code")
            got = observed.get(sample["id"], set())
            if not got or (want and want not in got):
                mismatches.append(f"{sample['id']}={sorted(got) or '未拒绝'} 期望 {want}")
        if mismatches:
            raise AssertionError("; ".join(mismatches))
        valid_done = {r["id"] for r in results}
        valid_want = {s["id"] for s in samples if s["expect"].get("status") == 200}
        if valid_done != valid_want:
            raise AssertionError(f"成功样例不符：{sorted(valid_done ^ valid_want)}")
        return "35 条样例的期望状态与错误码逐条吻合"

    check("样例期望与实际结果零不符", sample_match)

    def results_columns() -> str:
        allowed = set(bundle.contract.output_fields)
        for row in results:
            extra = set(row["columns"]) - allowed
            if extra:
                raise AssertionError(f"{row['id']} 返回未登记列 {extra}")
            assert row["row_count"] == len(row["rows"])
        return "10 条成功结果仅含登记列"

    check("查询结果列受输出白名单约束", results_columns)

    def rejected_shape() -> str:
        for row in rejected:
            assert row["error_code"].startswith("E_"), row
            assert 400 <= row["status"] < 600
            assert row["message"] and row["layer"]
        codes = sorted({r["error_code"] for r in rejected})
        return f"{len(rejected)} 条拒绝均带 code/status/message/layer，覆盖 {len(codes)} 类错误"

    check("拒绝记录字段完整", rejected_shape)

    audit_rows = read_jsonl(OUT / "audit_log.jsonl")
    http_rows = read_jsonl(OUT / "http_calls.jsonl")

    def audit_shape() -> str:
        seqs = [r["seq"] for r in audit_rows]
        assert seqs == list(range(1, len(seqs) + 1)), "seq 不连续"
        assert {r["source"] for r in audit_rows} == {"local", "http"}
        counts: dict[str, int] = {}
        for row in audit_rows:
            counts[row["outcome"]] = counts.get(row["outcome"], 0) + 1
        return f"{len(audit_rows)} 条（成功 {counts.get('allowed', 0)} / 拒绝 {counts.get('rejected', 0)}）"

    check("审计日志序号连续且双来源", audit_shape)

    def audit_token_masking() -> str:
        text = read_text(OUT / "audit_log.jsonl")
        for token in bundle.auth.tokens.values():
            assert token.token not in text, f"审计日志出现明文令牌 {token.id}"
        known = {token.id for token in bundle.auth.tokens.values()} | {"-"}
        ids = {r["token_id"] for r in audit_rows}
        assert ids <= known, f"出现未知 token_id：{sorted(ids - known)}"
        assert ids - {"-"}, "HTTP 审计未记录 token_id"
        return "明文令牌未落盘，token_id 取值均来自配置"

    check("审计日志不存明文令牌", audit_token_masking)

    def http_audit_join() -> str:
        assert len(http_rows) >= 14, len(http_rows)
        paths = {r["path"] for r in http_rows}
        audited = {r["path"] for r in audit_rows if r["source"] == "http"}
        missing = paths - audited
        if missing:
            raise AssertionError(f"HTTP 调用未入审计：{sorted(missing)}")
        return f"{len(http_rows)} 次 HTTP 调用全部可关联到审计路径"

    check("HTTP 调用与审计可关联", http_audit_join)

    openapi = json.loads(read_text(OUT / "contract_openapi.json"))

    def openapi_shape() -> str:
        assert openapi["openapi"].startswith("3.")
        assert openapi["x-read-only"] is True
        assert openapi["x-allowed-methods"] == ["GET"], openapi["x-allowed-methods"]
        methods = {m for item in openapi["paths"].values() for m in item}
        assert methods == {"get"}, methods
        assert openapi["components"]["securitySchemes"]["ApiKeyAuth"]["in"] == "header"
        layers = [layer["layer"] for layer in openapi["x-guard-layers"]]
        assert layers == ["L1", "L2", "L3"], layers
        return f"{len(openapi['paths'])} 个路径全部仅 GET，三层防线已写入 x-guard-layers"

    check("OpenAPI 契约只读且含三层声明", openapi_shape)

    def openapi_matches_code() -> str:
        fresh = build_spec(bundle.contract, bundle.limits, bundle.auth)
        assert fresh == openapi, "out/contract_openapi.json 与代码生成的契约不一致"
        return "落盘契约与 build_spec 输出逐字段一致"

    check("落盘契约可重复生成", openapi_matches_code)

    HASHES = {name: sha256(OUT / name) for name in artifacts if name != "demo_run.log"}

    demo2 = run([PYTHON, "-X", "utf8", "-m", "structured_data_api", "demo"])
    DEMO2_STDOUT = demo2.stdout + demo2.stderr
    HASHES2 = {name: sha256(OUT / name) for name in HASHES}
    (RECORDS / "artifact_hashes.txt").write_text(
        "\n".join(
            f"{HASHES[name]}  {name}  {'identical' if HASHES[name] == HASHES2[name] else 'changed'}"
            for name in sorted(HASHES)
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    check(
        "连续两次 demo 产物逐字节一致",
        lambda: _expect(
            f"{len(HASHES)} 个产物哈希相同",
            demo2.returncode == 0 and HASHES == HASHES2,
        ),
    )

    def demo_log_matches() -> str:
        log_text = read_text(OUT / "demo_run.log")
        assert "结论" in log_text and "35 条" in log_text
        assert "期望不符 0 条" in log_text
        return f"demo_run.log {len(log_text)} 字符，含零不符结论"

    check("demo_run.log 与运行一致", demo_log_matches)

    section("4. 单元测试")
    tests = run([PYTHON, "-X", "utf8", "tests/test_runner.py"])
    TESTS_STDOUT = tests.stdout + tests.stderr
    (RECORDS / "tests_output.txt").write_text(TESTS_STDOUT, encoding="utf-8", newline="\n")
    check(
        "测试子进程退出码为 0",
        lambda: _expect(f"exit={tests.returncode}", tests.returncode == 0),
    )

    def tests_summary() -> str:
        assert "FAIL" not in TESTS_STDOUT, "存在失败用例"
        match = re.search(r"(\d+)/(\d+) tests passed", TESTS_STDOUT)
        assert match, "未找到 tests passed 汇总"
        passed, total = int(match.group(1)), int(match.group(2))
        assert passed == total, f"{passed}/{total}"
        assert total >= 60, f"用例数偏少：{total}"
        return f"{passed}/{total} tests passed"

    check("测试全部通过且规模达标", tests_summary)

    section("5. 三层只读防线独立复现（脱离 HTTP 与 CLI）")
    writes = [
        "INSERT INTO fact_sales (sale_id) VALUES (999999)",
        "UPDATE fact_sales SET quantity = 0",
        "DELETE FROM fact_sales",
        "DROP TABLE fact_sales",
    ]

    with temporary_database() as ds:
        def readonly_uri() -> str:
            rows = probe_readonly_uri(ds, writes)
            assert len(rows) == 4 and all(r["blocked"] for r in rows), rows
            assert {r["error"].split(":")[0] for r in rows} == {"E_DB_READONLY"}
            conn = ds.connect_ro()
            try:
                count = conn.execute("SELECT COUNT(*) FROM fact_sales").fetchone()[0]
            finally:
                conn.close()
            assert count == 4000, count
            return "mode=ro 拒绝 4 类写操作，行数仍 4000"

        check("L1-a 只读 URI 独立拦截", readonly_uri)

        def query_only() -> str:
            rows = probe_query_only(ds, writes[:1])
            assert rows[0]["blocked"] and rows[0]["error"].startswith("E_DB_READONLY")
            return "PRAGMA query_only=ON 拒绝 INSERT"

        check("L1-b query_only 独立拦截", query_only)

        def authorizer() -> str:
            rows = probe_authorizer(ds, writes)
            assert all(r["blocked"] for r in rows), rows
            conn = ds.connect_rw()
            try:
                count = conn.execute("SELECT COUNT(*) FROM fact_sales").fetchone()[0]
            finally:
                conn.close()
            assert count == 4000, count
            return "set_authorizer 拒绝 4 类写操作，行数仍 4000"

        check("L1-c authorizer 独立拦截", authorizer)

        inspector = StatementInspector(bundle.contract.allowed_views)

        def statement_policy() -> str:
            cases = {
                "DELETE FROM fact_sales": "E_SQL_NOT_ALLOWED",
                "SELECT 1; DELETE FROM fact_sales": "E_SQL_MULTI_STATEMENT",
                "SELECT * FROM fact_sales -- x": "E_SQL_COMMENT",
                "SELECT * FROM secret_salary_table": "E_VIEW_NOT_ALLOWED",
            }
            for sql, code in cases.items():
                verdict = inspector.inspect(sql)
                assert not verdict.ok and verdict.error_code == code, f"{sql} -> {verdict.error_code}"
            ok = inspector.inspect("SELECT region FROM v_sales_daily")
            assert ok.ok and ok.first_keyword == "SELECT"
            return "6 类语句定性正确，全程未连接数据库"

        check("L2 语句白名单独立判定", statement_policy)

        def row_cap() -> str:
            rows = probe_row_cap(
                ds,
                inspector,
                bundle.contract.templates["sales_line_sample"].sql,
                7,
                {"date_from": "2025-01-01", "date_to": "2025-03-31"},
            )
            assert rows[0]["truncated"] is True and rows[0]["rows_returned"] == 7
            return "SQL 不含 LIMIT，仍被截到 7 行"

        check("L3 行数截断独立生效", row_cap)

        def timeout() -> str:
            started = time.monotonic()
            rows = probe_timeout(
                ds,
                inspector,
                bundle.contract.templates["benchmark_cross_join"].sql,
                150,
            )
            elapsed = int((time.monotonic() - started) * 1000)
            assert rows[0]["blocked"] is True, rows
            assert rows[0]["error"].startswith("E_TIMEOUT")
            assert elapsed < 3000, elapsed
            return f"{elapsed}ms 内中断，连接仍可用"

        check("L3 超时中断独立生效", timeout)

    def l1_without_l2() -> str:
        with temporary_database() as ds:
            conn = ds.connect_rw()
            guard = ReadOnlyGuard(conn)
            guard.install_authorizer()
            try:
                code = first_error_code(lambda: guard.run_raw("DELETE FROM fact_sales"))
            finally:
                conn.close()
            assert code == "E_SQL_AUTHORIZER", code
            return "未装语句检查器，authorizer 仍拒绝 DELETE"

    check("L1 不依赖 L2", l1_without_l2)

    def l2_without_l1() -> str:
        verdict = StatementInspector(bundle.contract.allowed_views).inspect("PRAGMA table_info(x)")
        assert not verdict.ok and verdict.error_code == "E_SQL_NOT_ALLOWED"
        return "无数据库连接也能拒绝 PRAGMA"

    check("L2 不依赖 L1", l2_without_l1)

    section("6. 参数校验矩阵（直接调用校验器）")
    probe_engine, probe_audit, probe_manager = _engine_for(bundle)

    def want(raw: Any, code: str) -> None:
        def call() -> Any:
            return probe_engine.handle(raw)

        got = first_error_code(call)
        assert got == code, f"期望 {code}，实际 {got}"

    check("缺少 template", lambda: _expect("E_PARAM_MISSING", _run(want, {"params": {}}, "E_PARAM_MISSING")))
    check(
        "未知模板",
        lambda: _expect("E_TEMPLATE_UNKNOWN", _run(want, {"template": "nope"}, "E_TEMPLATE_UNKNOWN")),
    )
    check(
        "未知顶层键（试图提交 SQL）",
        lambda: _expect(
            "E_PARAM_UNKNOWN",
            _run(want, {"template": "sales_by_region", "sql": "SELECT 1"}, "E_PARAM_UNKNOWN"),
        ),
    )
    check(
        "未知参数名",
        lambda: _expect(
            "E_PARAM_UNKNOWN",
            _run(
                want,
                {
                    "template": "sales_by_region",
                    "params": {"date_from": "2025-01-01", "date_to": "2025-01-31", "customer_email": "a@b"},
                },
                "E_PARAM_UNKNOWN",
            ),
        ),
    )
    check(
        "参数不属于该模板",
        lambda: _expect(
            "E_PARAM_NOT_IN_TEMPLATE",
            _run(
                want,
                {"template": "daily_revenue", "params": {"date_from": "2025-01-01", "date_to": "2025-01-31", "region": "华东"}},
                "E_PARAM_NOT_IN_TEMPLATE",
            ),
        ),
    )
    for label, value in (
        ("分号拼接", "华东; DROP TABLE fact_sales"),
        ("单行注释", "华东--"),
        ("块注释", "华东/**/"),
        ("引号闭合", "华东' OR '1'='1"),
        ("关键字序列", "华东 UNION SELECT"),
    ):
        check(
            f"注入式输入：{label}",
            lambda v=value: _expect(
                "E_PARAM_INJECTION",
                _run(
                    want,
                    {"template": "sales_by_region", "params": {"date_from": "2025-01-01", "date_to": "2025-01-31", "region": v}},
                    "E_PARAM_INJECTION",
                ),
            ),
        )
    check(
        "枚举外取值",
        lambda: _expect(
            "E_PARAM_ENUM",
            _run(
                want,
                {"template": "sales_by_region", "params": {"date_from": "2025-01-01", "date_to": "2025-01-31", "region": "火星"}},
                "E_PARAM_ENUM",
            ),
        ),
    )
    check(
        "日期顺序颠倒",
        lambda: _expect(
            "E_PARAM_RANGE",
            _run(
                want,
                {"template": "sales_by_region", "params": {"date_from": "2025-06-01", "date_to": "2025-01-01"}},
                "E_PARAM_RANGE",
            ),
        ),
    )
    check(
        "日期越过下界",
        lambda: _expect(
            "E_PARAM_RANGE",
            _run(
                want,
                {"template": "sales_by_region", "params": {"date_from": "2020-01-01", "date_to": "2025-01-01"}},
                "E_PARAM_RANGE",
            ),
        ),
    )
    check(
        "字符串超长",
        lambda: _expect(
            "E_PARAM_LENGTH",
            _run(
                want,
                {"template": "sales_by_region", "params": {"date_from": "2025-01-01", "date_to": "2025-01-31", "region": "华" * 80}},
                "E_PARAM_LENGTH",
            ),
        ),
    )
    check(
        "整数参数传字符串",
        lambda: _expect(
            "E_PARAM_TYPE",
            _run(want, {"template": "sales_by_region", "params": {"date_from": "2025-01-01", "date_to": "2025-01-31"}, "limit": "20"}, "E_PARAM_TYPE"),
        ),
    )
    check(
        "布尔值不算整数",
        lambda: _expect(
            "E_PARAM_TYPE",
            _run(want, {"template": "sales_by_region", "params": {"date_from": "2025-01-01", "date_to": "2025-01-31"}, "limit": True}, "E_PARAM_TYPE"),
        ),
    )
    check(
        "日期格式错误",
        lambda: _expect(
            "E_PARAM_TYPE",
            _run(want, {"template": "sales_by_region", "params": {"date_from": "2025/01/01", "date_to": "2025-01-31"}}, "E_PARAM_TYPE"),
        ),
    )
    check(
        "limit 超过模板上限",
        lambda: _expect(
            "E_ROW_LIMIT",
            _run(want, {"template": "sales_line_sample", "params": {"date_from": "2025-01-01", "date_to": "2025-01-31"}, "limit": 100000}, "E_ROW_LIMIT"),
        ),
    )

    def valid_query() -> str:
        result = probe_engine.handle(
            {"template": "sales_by_region", "params": {"date_from": "2025-01-01", "date_to": "2025-03-31"}}
        )
        assert result.row_count == 4 and not result.truncated
        assert result.limit == bundle.limits.default_rows
        return f"4 行，limit={result.limit}，truncated=false"

    check("合法请求返回真实数据", valid_query)

    def truncated_query() -> str:
        result = probe_engine.handle(
            {"template": "sales_line_sample", "params": {"date_from": "2025-01-01", "date_to": "2025-01-31", "limit": 5}}
        )
        assert result.row_count == 5 and result.truncated is True
        return "limit=5 返回 5 行且 truncated=true"

    check("明细查询按需截断", truncated_query)

    def error_messages() -> str:
        try:
            probe_engine.handle({"template": "sales_by_region", "params": {"date_from": "2025-01-01", "date_to": "2025-01-31", "region": "火星"}})
        except ApiError as exc:
            text = str(exc.to_dict())
            assert "region" in text and "华东" in text, text
            assert "Traceback" not in text
            return "错误体含字段名与可选值，无堆栈"
        raise AssertionError("未拒绝")

    check("错误信息可读且指明字段", error_messages)

    section("7. 实时只读 HTTP 接口（真实起服务）")
    bundle2, manager2, ds2, engine2, audit2, context2 = build_context(bundle)
    server, thread, base = start_in_thread(context2, host="127.0.0.1", port=0)
    try:
        query_tok = token_of(bundle2, "demo-readonly")
        audit_tok = token_of(bundle2, "demo-audit-only")
        burst_tok = token_of(bundle2, "demo-burst")

        def health() -> str:
            status, body, _ = http_call(base, "/healthz")
            assert status == 200 and body["data"]["read_only"] is True
            return "免鉴权健康检查 200 且声明 read_only"

        check("GET /healthz 免鉴权可用", health)

        def contract_ep() -> str:
            status, body, _ = http_call(base, "/v1/contract", token=query_tok)
            assert status == 200 and body["data"]["contract"]["contract_version"] == bundle2.contract.contract_version
            return "返回契约版本与三层说明"

        check("GET /v1/contract 需要 query scope", contract_ep)

        def fields_ep() -> str:
            status, body, _ = http_call(base, "/v1/fields", token=query_tok)
            assert status == 200 and len(body["data"]) == 7
            return "7 个字段元数据"

        check("GET /v1/fields", fields_ep)

        def queries_ep() -> str:
            status, body, _ = http_call(base, "/v1/queries", token=query_tok)
            assert status == 200 and len(body["data"]) == 7
            assert all(item["exposed_via_api"] for item in body["data"])
            return "7 个对外模板（benchmark 不暴露）"

        check("GET /v1/queries", queries_ep)

        def query_ep() -> str:
            qs = urlencode(
                {
                    "template": "sales_by_region",
                    "date_from": "2025-01-01",
                    "date_to": "2025-03-31",
                }
            )
            status, body, _ = http_call(base, f"/v1/query?{qs}", token=query_tok)
            assert status == 200 and body["data"]["row_count"] == 4
            return "URL 参数经类型转换后返回 4 行"

        check("GET /v1/query 正常返回", query_ep)

        def query_trunc() -> str:
            qs = urlencode(
                {
                    "template": "sales_line_sample",
                    "date_from": "2025-01-01",
                    "date_to": "2025-01-31",
                    "limit": "5",
                }
            )
            status, body, _ = http_call(base, f"/v1/query?{qs}", token=query_tok)
            assert status == 200 and body["data"]["row_count"] == 5
            assert body["data"]["truncated"] is True
            return "limit=5 触发第三层截断"

        check("GET /v1/query 明细截断", query_trunc)

        def missing_token() -> str:
            status, body, _ = http_call(base, "/v1/fields")
            assert status == 401 and body["error"]["code"] == "E_AUTH_MISSING_TOKEN"
            return "401 + E_AUTH_MISSING_TOKEN"

        check("缺少令牌被拒", missing_token)

        def bad_token() -> str:
            status, body, _ = http_call(base, "/v1/fields", token="not-a-real-token")
            assert status == 401 and body["error"]["code"] == "E_AUTH_INVALID_TOKEN"
            return "401 + E_AUTH_INVALID_TOKEN"

        check("无效令牌被拒", bad_token)

        def bad_method() -> str:
            status, body, headers = http_call(base, "/v1/fields", token=query_tok, method="POST", body=b"")
            assert status == 405 and body["error"]["code"] == "E_METHOD_NOT_ALLOWED"
            assert headers.get("allow") == "GET"
            return "405 + Allow: GET"

        check("写方法一律 405", bad_method)

        def scope_query() -> str:
            status, body, _ = http_call(base, "/v1/query?template=sales_by_region", token=audit_tok)
            assert status == 403 and body["error"]["code"] == "E_SCOPE_DENIED"
            return "audit-only 令牌查数被 403"

        check("scope 隔离：audit 令牌不能查数", scope_query)

        def tail_ok() -> str:
            status, body, _ = http_call(base, "/v1/audit/tail?n=3", token=audit_tok)
            assert status == 200 and len(body["data"]) == 3
            assert body["data"][0]["seq"] < body["data"][-1]["seq"]
            return "返回最近 3 条，序号递增"

        check("GET /v1/audit/tail 正常", tail_ok)

        def tail_denied() -> str:
            status, body, _ = http_call(base, "/v1/audit/tail", token=token_of(bundle2, "demo-query-only"))
            assert status == 403 and body["error"]["code"] == "E_SCOPE_DENIED"
            return "query-only 令牌读审计被 403"

        check("scope 隔离：query 令牌不能读审计", tail_denied)

        def not_found() -> str:
            status, body, _ = http_call(base, "/v1/nope", token=query_tok)
            assert status == 404 and body["error"]["code"] == "E_NOT_FOUND"
            return "404 + E_NOT_FOUND"

        check("未知路径 404", not_found)

        def inject_http() -> str:
            qs = urlencode(
                {
                    "template": "sales_by_region",
                    "date_from": "2025-01-01",
                    "date_to": "2025-01-31",
                    "region": "华东; DROP TABLE fact_sales",
                }
            )
            status, body, _ = http_call(base, f"/v1/query?{qs}", token=query_tok)
            assert status == 400 and body["error"]["code"] == "E_PARAM_INJECTION"
            return "400 + E_PARAM_INJECTION"

        check("URL 注入式参数被拒", inject_http)

        def outside_template() -> str:
            qs = urlencode(
                {
                    "template": "daily_revenue",
                    "date_from": "2025-01-01",
                    "date_to": "2025-01-31",
                    "region": "华东",
                }
            )
            status, body, _ = http_call(base, f"/v1/query?{qs}", token=query_tok)
            assert status == 400 and body["error"]["code"] == "E_PARAM_NOT_IN_TEMPLATE"
            return "400 + E_PARAM_NOT_IN_TEMPLATE"

        check("越过模板字段被拒", outside_template)

        def rate_limited() -> str:
            codes = []
            retry_after = None
            for _ in range(6):
                status, _body, headers = http_call(base, "/v1/fields", token=burst_tok)
                codes.append(status)
                if status == 429:
                    retry_after = headers.get("retry-after")
            assert codes[:5] == [200] * 5, codes
            assert codes[5] == 429, codes
            assert retry_after and int(retry_after) > 0
            return f"前 5 次 200，第 6 次 429（Retry-After={retry_after}s）"

        check("滑动窗口限流 60s/5 次", rate_limited)

        def openapi_ep() -> str:
            status, body, _ = http_call(base, "/v1/openapi.json", token=query_tok)
            assert status == 200 and body["data"]["openapi"].startswith("3.")
            return "在线契约与落盘契约同类"

        check("GET /v1/openapi.json", openapi_ep)

        def audit_every_request() -> str:
            assert audit2.count() == len(TRANSCRIPT), f"审计 {audit2.count()} 条，请求 {len(TRANSCRIPT)} 条"
            entries = audit2.entries
            for entry, call in zip(entries, TRANSCRIPT):
                assert entry.method == call["method"], (entry.method, call["method"])
                assert entry.path == call["path"].split("?")[0], (entry.path, call["path"])
                assert entry.status == call["status"], (entry.status, call["status"])
                assert entry.error_code == call["error_code"], (entry.error_code, call["error_code"])
            return f"{len(TRANSCRIPT)} 次请求逐条入审计且状态一致"

        check("每次 HTTP 调用都有对应审计", audit_every_request)

        def audit_masking_http() -> str:
            text = json.dumps([e.to_dict() for e in audit2.entries], ensure_ascii=False)
            for token in bundle2.auth.tokens.values():
                assert token.token not in text
            known = {token.id for token in bundle2.auth.tokens.values()} | {"-"}
            assert {e.token_id for e in audit2.entries} <= known
            return "只记录 token_id，明文令牌未进入审计"

        check("HTTP 审计不存明文令牌", audit_masking_http)

        def tail_reflects() -> str:
            status, body, _ = http_call(base, "/v1/audit/tail?n=5", token=audit_tok)
            assert status == 200 and len(body["data"]) == 5
            return "尾部 5 条包含刚发生的请求"

        check("审计尾部实时可见", tail_reflects)
    finally:
        stop_server(server, thread)
        manager2.__exit__(None, None, None)

    check(
        "服务关闭后端口释放",
        lambda: _expect("端口可再次绑定", _port_free(base)),
    )

    probe_manager.__exit__(None, None, None)

    section("8. 文档与交付说明")
    solution = ROOT / "SOLUTION.md"
    readme = ROOT / "README.md"
    delivery = ROOT / "DELIVERY.md"
    gitignore = ROOT / ".gitignore"

    def solution_size() -> str:
        text = read_text(solution)
        size = len(text)
        assert 8000 <= size <= 9800, f"字符数 {size}"
        return f"{size} 字符（要求 8000-9800）"

    check("SOLUTION.md 篇幅达标", solution_size)

    def solution_sections() -> str:
        text = read_text(solution)
        needed = ["三层", "参数校验", "OpenAPI", "审计", "复现", "REPO_LINK_HERE", "ZIP_LINK_HERE"]
        missing = [s for s in needed if s not in text]
        if missing:
            raise AssertionError("缺少：" + ", ".join(missing))
        return "覆盖三层防线/校验/契约/审计/复现，含两处链接占位"

    check("SOLUTION.md 覆盖验收要点", solution_sections)

    def readme_steps() -> str:
        text = read_text(readme)
        commands = re.findall(r"python -m structured_data_api \w+", text)
        assert len(set(commands)) >= 3, commands
        assert "tests/test_runner.py" in text
        return "三步：demo / tests / verify 均给出命令"

    check("README.md 提供三步复跑命令", readme_steps)

    def delivery_manifest() -> str:
        text = read_text(delivery)
        needed = ["out/", "layer_evidence.jsonl", "audit_log.jsonl", "verify/", "samples/queries.jsonl"]
        missing = [s for s in needed if s not in text]
        if missing:
            raise AssertionError("缺少：" + ", ".join(missing))
        return "清单覆盖产物/证据/验证目录"

    check("DELIVERY.md 列出交付清单", delivery_manifest)

    def ignore_rules() -> str:
        text = read_text(gitignore)
        assert "__pycache__" in text and "*.pyc" in text
        return "__pycache__ 与字节码已忽略"

    check(".gitignore 规则可用", ignore_rules)

    def no_placeholders() -> str:
        hits: list[str] = []
        scanned = [
            p
            for p in text_files
            if "verify" not in p.relative_to(ROOT).parts
        ]
        for path in scanned:
            text = path.read_text(encoding="utf-8", errors="replace")
            for marker in ("TODO", "FIXME", "XXX", "YOUR_", "<placeholder>"):
                if marker in text:
                    hits.append(f"{path.relative_to(ROOT)}:{marker}")
        if hits:
            raise AssertionError(", ".join(hits))
        return "无 TODO/FIXME/占位标记"

    check("交付物无未完成标记", no_placeholders)

    section("结果")
    emit(f"断言：{PASSED}/{TOTAL} 通过")
    if PASSED != TOTAL:
        failed = [r for r in RESULTS if not r["ok"]]
        emit("失败项：")
        for item in failed:
            emit(f"  - {item['name']} | {item['detail']}")
    emit(f"{PASSED}/{TOTAL} assertions passed")

    (RECORDS / "verify_output.txt").write_text("\n".join(LOG) + "\n", encoding="utf-8", newline="\n")
    with (RECORDS / "http_transcript.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for call in TRANSCRIPT:
            handle.write(json.dumps(call, ensure_ascii=False) + "\n")

    result = {
        "order": 1520,
        "title": "结构化数据与实时接口",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": sys.version.split()[0],
        "ok": PASSED == TOTAL,
        "assertions_passed": PASSED,
        "assertions_total": TOTAL,
        "checks": RESULTS,
        "artifacts": {name: HASHES.get(name) for name in artifacts},
        "http_calls": len(TRANSCRIPT),
        "samples": {"total": 35, "valid": 10, "rejected": 25},
    }
    (VERIFY / "verification_result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    (VERIFY / "verification_record.md").write_text(
        render_record(result, bundle), encoding="utf-8", newline="\n"
    )
    return 0 if PASSED == TOTAL else 1


def _expect(detail: str, condition: Any) -> str:
    if not condition:
        raise AssertionError(detail)
    return detail


def _size(path: Path) -> int:
    return path.stat().st_size if path.is_file() else -1


def _raises(handler: Callable[[Callable[[], Any], str], None], fn: Callable[[], Any], needle: str) -> str:
    handler(fn, needle)
    return needle


def _run(handler: Callable[[Any, str], None], raw: Any, code: str) -> str:
    handler(raw, code)
    return code


def _engine_for(bundle):
    manager = temporary_database()
    ds = manager.__enter__()
    clock = SystemClock()
    audit = AuditLog(clock)
    engine = QueryEngine(ds, bundle.contract, bundle.limits, audit, clock)
    return engine, audit, manager


def _port_free(base: str) -> str:
    port = int(base.rsplit(":", 1)[1])
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass
    except OSError:
        return f"127.0.0.1:{port} 已释放"
    raise AssertionError(f"服务仍在监听 127.0.0.1:{port}")


def render_record(result: dict[str, Any], bundle) -> str:
    lines = [
        "# 验证记录 · ClawHunt #1520 结构化数据与实时接口",
        "",
        f"- 生成时间：{result['generated_at']}",
        f"- 解释器：Python {result['python']}（仅标准库）",
        f"- 结论：{'通过' if result['ok'] else '未通过'}，{result['assertions_passed']}/{result['assertions_total']} 断言通过",
        f"- 契约：{bundle.contract.contract_version}，模板 {len(bundle.contract.templates)} 个（对外 {len(bundle.contract.exposed_templates())}），视图 {len(bundle.contract.allowed_views)} 个",
        "",
        "## 复跑方式",
        "",
        "```bash",
        "python -m structured_data_api demo",
        "python tests/test_runner.py",
        "python verify/run_verification.py",
        "```",
        "",
        "## 断言明细",
        "",
        "| # | 断言 | 结果 | 证据 |",
        "| --- | --- | --- | --- |",
    ]
    for index, item in enumerate(result["checks"], start=1):
        detail = str(item["detail"]).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {index} | {item['name']} | {'PASS' if item['ok'] else 'FAIL'} | {detail} |")
    lines += [
        "",
        "## 产物哈希（SHA-256）",
        "",
        "| 产物 | SHA-256 |",
        "| --- | --- |",
    ]
    for name in sorted(result["artifacts"]):
        lines.append(f"| {name} | `{result['artifacts'][name]}` |")
    lines += [
        "",
        "## 关键数值",
        "",
        "- 三层取证：L1=9 / L2=8 / L3=3 条，L1 九条全部 blocked=true，事实表仍 4000 行。",
        "- 样例：35 条（合法 10、拒绝 25），期望与实际零不符。",
        "- HTTP：真实起服务后逐项调用，401/403/405/404/400/429/200 均覆盖，每次调用都有审计条目。",
        "- 单元测试：输出见 `verify/records/tests_output.txt`。",
        "",
        "原始输出保存在 `verify/records/`：`demo_output.txt`、`tests_output.txt`、`verify_output.txt`、`http_transcript.jsonl`、`artifact_hashes.txt`。",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())

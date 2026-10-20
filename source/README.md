# 结构化数据与实时接口（#1520）

只读 OLAP 查询服务：模板化查询、三层只读防线、27 个错误码、OpenAPI 3.0.3 契约、全量审计。纯 Python 标准库，无第三方依赖。

## 环境

- Python 3.10 及以上（本次在 3.13.9 验证）
- 无需 `pip install`，无需数据库服务

## 三步复跑

```bash
# 1. 一键演示：生成三层取证、跑 35 条样例、起 HTTP 服务并调用
python -m structured_data_api demo

# 2. 单元测试：预期输出 86/86 tests passed
python tests/test_runner.py

# 3. 交付自检：复跑 demo 与测试，真实调用 HTTP，预期 93/93 assertions passed
python verify/run_verification.py
```

## 产物

- `out/contract_openapi.json`：OpenAPI 3.0.3 契约，7 个路径全部只允许 GET
- `out/query_results.jsonl`：10 条合法查询的真实结果
- `out/rejected_requests.jsonl`：25 条被拒请求与错误码
- `out/audit_log.jsonl`：一次演示的 48 条审计
- `out/layer_evidence.jsonl`：三层防线 20 条取证（L1=9、L2=8、L3=3）
- `out/http_calls.jsonl`：14 次 HTTP 调用明细
- `out/demo_run.log`：完整演示日志
- `verify/records/`：demo、测试、自检的原始输出与哈希清单

## 常用命令

```bash
python -m structured_data_api serve --port 8000    # 只起 HTTP 服务
python -m structured_data_api contract            # 打印契约
python -m structured_data_api layers              # 只跑三层取证
python -m structured_data_api query --template sales_by_region --param date_from=2025-01-01 --param date_to=2025-03-31
```

## 目录

```
config/                 字段白名单、访问契约、上限、演示令牌
structured_data_api/    13 个模块：配置、数据源、校验、守卫、审计、限流、契约、API、CLI
samples/queries.jsonl   35 条调用样例
tests/test_runner.py    86 个用例
verify/                 自检脚本与验证记录
out/                    运行产物
```

详细设计见 `SOLUTION.md`，交付清单与验证结论见 `DELIVERY.md`。

# 交付说明（#1520 结构化数据与实时接口）

## 一、交付内容

| 路径 | 内容 | 证明什么 |
| --- | --- | --- |
| `SOLUTION.md` | 设计说明、三层防线、参数校验、契约、取舍 | 方案可读、决策可追溯 |
| `README.md` | 环境与三步复跑命令 | 买家可自行跑通 |
| `config/fields.json` | 7 个输入字段 + 14 个输出列白名单 | 参数与结果列都有边界 |
| `config/access_contract.json` | 6 个视图、8 个模板（对外 7 个）、模板 SQL | 客户端只能引用模板，不能提交 SQL |
| `config/limits.json` | 行数硬上限 200、默认 20、查询 800ms、探针 150ms、限流 60/60s | 第三层与传输层上限集中管理 |
| `config/auth.json` | 4 个演示令牌（query+audit、audit、burst、query-only） | 鉴权与 scope 隔离可演示 |
| `structured_data_api/` | 13 个模块，纯标准库 | 实现完整、零依赖 |
| `samples/queries.jsonl` | 35 条样例：合法 10、拒绝 25 | 参数校验与语句白名单的输入集 |
| `tests/test_runner.py` | 86 个用例 | 单元级回归 |
| `verify/run_verification.py` | 93 条断言，真实起 HTTP 服务 | 端到端自检 |
| `out/contract_openapi.json` | OpenAPI 3.0.3，7 个路径，全部 GET | 契约交付物 |
| `out/query_results.jsonl` | 10 条成功查询的真实结果 | 调用结果样例 |
| `out/rejected_requests.jsonl` | 25 条拒绝记录，含错误码与原因 | 校验真的在拒绝 |
| `out/audit_log.jsonl` | 46 条审计（成功 21、拒绝 25） | 每次调用可追溯 |
| `out/layer_evidence.jsonl` | 20 条取证（L1=9、L2=8、L3=3） | 三层防线逐条可复核 |
| `out/http_calls.jsonl` | 14 次 HTTP 调用明细 | 接口真实可用 |
| `out/demo_run.log` | 完整演示日志 | 复跑输出留档 |
| `verify/verification_record.md` | 逐条断言表 + 产物哈希 | 验收记录 |
| `verify/verification_result.json` | 机器可读结果 | 便于流水线消费 |
| `verify/records/` | demo、测试、自检原始输出、HTTP 明细、哈希清单 | 不依赖口述的证据 |

## 二、环境

- Python 3.10+（本次 3.13.9，Windows）
- 仅标准库：`sqlite3`、`http.server`、`urllib`、`dataclasses`、`json`、`argparse`
- 不需要网络、不需要数据库服务、不需要 `pip install`

## 三、复跑与预期输出

```bash
python -m structured_data_api demo
python tests/test_runner.py
python verify/run_verification.py
```

预期：

- demo 退出码 0，`out/` 生成 7 个文件，日志末尾给出「L1=9 / L2=8 / L3=3」「期望不符 0 条」；
- 测试输出 `86/86 tests passed`；
- 自检输出 `93/93 assertions passed`，退出码 0。

## 四、验证覆盖

1. 结构与依赖：必备文件、ASCII 路径、无 BOM、无 emoji、AST 扫描确认零第三方导入。
2. 配置：数量与白名单一致；装载期拒绝非 GET 方法、超硬上限行数、视图漂移。
3. 演示产物：7 个文件、20 条取证、35 条样例零不符、审计序号连续、契约可重复生成。
4. 确定性：连续两次 demo 的 6 个产物 SHA-256 一致。
5. 单元测试：86/86。
6. 三层独立复现：只读 URI、query_only、authorizer 各自拒写且行数不变；语句白名单脱离数据库可用；截断与超时各自生效；L1 不依赖 L2，L2 不依赖 L1。
7. 参数校验：缺失、未知、模板外字段、5 类注入、枚举、范围、长度、类型、行数上限逐项命中错误码。
8. HTTP：健康检查、契约、字段、模板、查询、截断、401、403、405、404、400、429（带 Retry-After）、审计尾部、在线契约；每次调用都能在审计中找到对应条目，且明文令牌未落盘。
9. 文档：SOLUTION 篇幅 8000-9800 字符、含两处链接占位；README 三步命令；本文件清单完整。

## 五、已知边界

- 令牌为演示明文，生产应改为哈希存储与短期轮换；
- 限流为单进程内存滑动窗口，多副本需外部存储；
- 审计写内存并落 JSONL，生产应接入不可篡改日志；
- 数据为固定种子合成的星型模型，不含真实客户信息；
- `benchmark_cross_join` 仅作为超时探针，不对外暴露。

## 六、链接

- 仓库：REPO_LINK_HERE
- 打包：ZIP_LINK_HERE

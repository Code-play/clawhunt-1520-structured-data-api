# 验证记录 · ClawHunt #1520 结构化数据与实时接口

- 生成时间：2026-10-20T15:57:15Z
- 解释器：Python 3.13.9（仅标准库）
- 结论：通过，93/93 断言通过
- 契约：1.0.0，模板 8 个（对外 7），视图 6 个

## 复跑方式

```bash
python -m structured_data_api demo
python tests/test_runner.py
python verify/run_verification.py
```

## 断言明细

| # | 断言 | 结果 | 证据 |
| --- | --- | --- | --- |
| 1 | Python 版本不低于 3.10 | PASS | 3.13.9 |
| 2 | 必备文件全部存在 | PASS | 25 个必备文件齐全 |
| 3 | 目录与文件名全 ASCII | PASS | 扫描 16 个 py 文件所在目录树，路径全 ASCII |
| 4 | 所有文本文件无 BOM | PASS | 38 个文本文件均为无 BOM UTF-8 |
| 5 | 文档与代码不含 emoji | PASS | 未检出 emoji / 装饰性符号 |
| 6 | 零第三方依赖（AST 扫描导入） | PASS | 16 个模块仅使用标准库 |
| 7 | 仓库内无第三方依赖痕迹 | PASS | 无 requirements.txt / vendor / site-packages |
| 8 | 契约与字段数量符合设计 | PASS | 模板 8 个 / 对外 7 个 / 视图 6 个 / 字段 7 个 / 输出列 14 个 |
| 9 | 硬上限与默认行数自洽 | PASS | hard=200 default=20 |
| 10 | 只读方法白名单仅 GET | PASS | ('GET',) |
| 11 | 模板视图均在白名单内 | PASS | 8 个模板引用的视图全部在白名单内 |
| 12 | 模板输出列均在白名单内 | PASS | 8 个模板的输出列均已登记 |
| 13 | 演示令牌结构合法 | PASS | 4 个令牌，scope 合法，掩码不泄漏明文 |
| 14 | 装载期拒绝 POST 方法 | PASS | ConfigError: allow_methods |
| 15 | 装载期拒绝超过硬上限的行数 | PASS | ConfigError: max_rows_hard |
| 16 | 装载期拒绝视图漂移 | PASS | ConfigError: v_product_rank |
| 17 | demo 子进程退出码为 0 | PASS | exit=0 输出 8153 字符 |
| 18 | demo 输出覆盖四段验收内容 | PASS | 4 个主体段落 + 结论齐全 |
| 19 | out/ 七个产物齐全 | PASS | contract_openapi.json=28721B, query_results.jsonl=5594B, rejected_requests.jsonl=8384B, audit_log.jsonl=20557B, layer_evidence.jsonl=6796B, http_calls.jsonl=2844B, demo_run.log=10608B |
| 20 | 取证条目分布 L1=9 / L2=8 / L3=3 | PASS | L1=9 L2=8 L3=3 合计=20 |
| 21 | L1 九条取证全部拦截写入 | PASS | 三种机制共 9 条证据全部 blocked=true |
| 22 | L1 拦截后事实表行数不变 | PASS | 无行数变化告警条目，事实表保持 4000 行 |
| 23 | L2 白名单分类正确 | PASS | 放行 2 条、拒绝 6 条，覆盖 4 类错误码 |
| 24 | L3 行数与超时证据完整 | PASS | 行截断 5 行、数量上限 E_ROW_LIMIT、超时中断且连接可复用 |
| 25 | 样例 35 条且结果分布 10 成功 / 25 拒绝 | PASS | samples=35 results=10 rejected=25 |
| 26 | 样例期望与实际结果零不符 | PASS | 35 条样例的期望状态与错误码逐条吻合 |
| 27 | 查询结果列受输出白名单约束 | PASS | 10 条成功结果仅含登记列 |
| 28 | 拒绝记录字段完整 | PASS | 25 条拒绝均带 code/status/message/layer，覆盖 15 类错误 |
| 29 | 审计日志序号连续且双来源 | PASS | 46 条（成功 21 / 拒绝 25） |
| 30 | 审计日志不存明文令牌 | PASS | 明文令牌未落盘，token_id 取值均来自配置 |
| 31 | HTTP 调用与审计可关联 | PASS | 14 次 HTTP 调用全部可关联到审计路径 |
| 32 | OpenAPI 契约只读且含三层声明 | PASS | 7 个路径全部仅 GET，三层防线已写入 x-guard-layers |
| 33 | 落盘契约可重复生成 | PASS | 落盘契约与 build_spec 输出逐字段一致 |
| 34 | 连续两次 demo 产物逐字节一致 | PASS | 6 个产物哈希相同 |
| 35 | demo_run.log 与运行一致 | PASS | demo_run.log 8153 字符，含零不符结论 |
| 36 | 测试子进程退出码为 0 | PASS | exit=0 |
| 37 | 测试全部通过且规模达标 | PASS | 86/86 tests passed |
| 38 | L1-a 只读 URI 独立拦截 | PASS | mode=ro 拒绝 4 类写操作，行数仍 4000 |
| 39 | L1-b query_only 独立拦截 | PASS | PRAGMA query_only=ON 拒绝 INSERT |
| 40 | L1-c authorizer 独立拦截 | PASS | set_authorizer 拒绝 4 类写操作，行数仍 4000 |
| 41 | L2 语句白名单独立判定 | PASS | 6 类语句定性正确，全程未连接数据库 |
| 42 | L3 行数截断独立生效 | PASS | SQL 不含 LIMIT，仍被截到 7 行 |
| 43 | L3 超时中断独立生效 | PASS | 151ms 内中断，连接仍可用 |
| 44 | L1 不依赖 L2 | PASS | 未装语句检查器，authorizer 仍拒绝 DELETE |
| 45 | L2 不依赖 L1 | PASS | 无数据库连接也能拒绝 PRAGMA |
| 46 | 缺少 template | PASS | E_PARAM_MISSING |
| 47 | 未知模板 | PASS | E_TEMPLATE_UNKNOWN |
| 48 | 未知顶层键（试图提交 SQL） | PASS | E_PARAM_UNKNOWN |
| 49 | 未知参数名 | PASS | E_PARAM_UNKNOWN |
| 50 | 参数不属于该模板 | PASS | E_PARAM_NOT_IN_TEMPLATE |
| 51 | 注入式输入：分号拼接 | PASS | E_PARAM_INJECTION |
| 52 | 注入式输入：单行注释 | PASS | E_PARAM_INJECTION |
| 53 | 注入式输入：块注释 | PASS | E_PARAM_INJECTION |
| 54 | 注入式输入：引号闭合 | PASS | E_PARAM_INJECTION |
| 55 | 注入式输入：关键字序列 | PASS | E_PARAM_INJECTION |
| 56 | 枚举外取值 | PASS | E_PARAM_ENUM |
| 57 | 日期顺序颠倒 | PASS | E_PARAM_RANGE |
| 58 | 日期越过下界 | PASS | E_PARAM_RANGE |
| 59 | 字符串超长 | PASS | E_PARAM_LENGTH |
| 60 | 整数参数传字符串 | PASS | E_PARAM_TYPE |
| 61 | 布尔值不算整数 | PASS | E_PARAM_TYPE |
| 62 | 日期格式错误 | PASS | E_PARAM_TYPE |
| 63 | limit 超过模板上限 | PASS | E_ROW_LIMIT |
| 64 | 合法请求返回真实数据 | PASS | 4 行，limit=20，truncated=false |
| 65 | 明细查询按需截断 | PASS | limit=5 返回 5 行且 truncated=true |
| 66 | 错误信息可读且指明字段 | PASS | 错误体含字段名与可选值，无堆栈 |
| 67 | GET /healthz 免鉴权可用 | PASS | 免鉴权健康检查 200 且声明 read_only |
| 68 | GET /v1/contract 需要 query scope | PASS | 返回契约版本与三层说明 |
| 69 | GET /v1/fields | PASS | 7 个字段元数据 |
| 70 | GET /v1/queries | PASS | 7 个对外模板（benchmark 不暴露） |
| 71 | GET /v1/query 正常返回 | PASS | URL 参数经类型转换后返回 4 行 |
| 72 | GET /v1/query 明细截断 | PASS | limit=5 触发第三层截断 |
| 73 | 缺少令牌被拒 | PASS | 401 + E_AUTH_MISSING_TOKEN |
| 74 | 无效令牌被拒 | PASS | 401 + E_AUTH_INVALID_TOKEN |
| 75 | 写方法一律 405 | PASS | 405 + Allow: GET |
| 76 | scope 隔离：audit 令牌不能查数 | PASS | audit-only 令牌查数被 403 |
| 77 | GET /v1/audit/tail 正常 | PASS | 返回最近 3 条，序号递增 |
| 78 | scope 隔离：query 令牌不能读审计 | PASS | query-only 令牌读审计被 403 |
| 79 | 未知路径 404 | PASS | 404 + E_NOT_FOUND |
| 80 | URL 注入式参数被拒 | PASS | 400 + E_PARAM_INJECTION |
| 81 | 越过模板字段被拒 | PASS | 400 + E_PARAM_NOT_IN_TEMPLATE |
| 82 | 滑动窗口限流 60s/5 次 | PASS | 前 5 次 200，第 6 次 429（Retry-After=60s） |
| 83 | GET /v1/openapi.json | PASS | 在线契约与落盘契约同类 |
| 84 | 每次 HTTP 调用都有对应审计 | PASS | 22 次请求逐条入审计且状态一致 |
| 85 | HTTP 审计不存明文令牌 | PASS | 只记录 token_id，明文令牌未进入审计 |
| 86 | 审计尾部实时可见 | PASS | 尾部 5 条包含刚发生的请求 |
| 87 | 服务关闭后端口释放 | PASS | 端口可再次绑定 |
| 88 | SOLUTION.md 篇幅达标 | PASS | 8565 字符（要求 8000-9800） |
| 89 | SOLUTION.md 覆盖验收要点 | PASS | 覆盖三层防线/校验/契约/审计/复现，含两处链接占位 |
| 90 | README.md 提供三步复跑命令 | PASS | 三步：demo / tests / verify 均给出命令 |
| 91 | DELIVERY.md 列出交付清单 | PASS | 清单覆盖产物/证据/验证目录 |
| 92 | .gitignore 规则可用 | PASS | __pycache__ 与字节码已忽略 |
| 93 | 交付物无未完成标记 | PASS | 无 TODO/FIXME/占位标记 |

## 产物哈希（SHA-256）

| 产物 | SHA-256 |
| --- | --- |
| audit_log.jsonl | `4e9070e7af854615e3869186b2cf987a57b8bf5b3b3074c1ce6c4d792d251f81` |
| contract_openapi.json | `f4529e09a82382d3cc6a442eaa6dbe8fc114d855e429211491ba7e83f88aa14d` |
| demo_run.log | `None` |
| http_calls.jsonl | `d996b26d4a0ca10f9fd52e9924bd395d499c25fc21badf1e3cf531240ccab30d` |
| layer_evidence.jsonl | `d571c7c25045ae4b2343bd890b7066bb57abc9a4592c889e38604d5aca8054c3` |
| query_results.jsonl | `70edac7513b5e452db7d8b1586b9d9f1837367c7e001413cb4ea2387bef07d9d` |
| rejected_requests.jsonl | `38715943091c6148eea8b5cf1b4c614f6619709df126ac75330c927ef78a8fee` |

## 关键数值

- 三层取证：L1=9 / L2=8 / L3=3 条，L1 九条全部 blocked=true，事实表仍 4000 行。
- 样例：35 条（合法 10、拒绝 25），期望与实际零不符。
- HTTP：真实起服务后逐项调用，401/403/405/404/400/429/200 均覆盖，每次调用都有审计条目。
- 单元测试：输出见 `verify/records/tests_output.txt`。

原始输出保存在 `verify/records/`：`demo_output.txt`、`tests_output.txt`、`verify_output.txt`、`http_transcript.jsonl`、`artifact_hashes.txt`。

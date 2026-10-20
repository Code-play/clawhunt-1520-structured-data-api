# 结构化数据与实时接口（ClawHunt #1520）

给企业 Agent 提供一条「能查数、但绝不可能改数」的实时通道：客户端只提交模板 id 与白名单参数，服务端在数据库连接、SQL 解析、结果集三个层面同时上锁，并把每一次成功与失败写入审计日志。交付物是可直接运行的 Python 标准库工程，含 35 条真实调用样例、7 个产物文件、86 个单元测试与 93 条自检断言。

## 一、问题与交付边界

买家要的不是一份「请注意只读」的说明，而是一条可以被验证的边界：即使调用方写了 `DELETE`，即使某个中间件被绕过，即使 SQL 拼接出现漏洞，数据表也不能少一行。围绕这句要求，本单交付四件事：

1. 三层只读边界，每层单独可复现，互不依赖；
2. 显式参数校验，类型、范围、枚举、白名单字段、注入式输入都有可读错误；
3. 实时只读 HTTP 接口，GET + 令牌 + scope + 滑动窗口限流 + 全量审计；
4. OpenAPI 3.0.3 契约与真实调用结果样例。

不做的事也写清楚：不提供自然语言转 SQL，不允许客户端提交 SQL 文本，不接生产数据库，不含任何真实客户数据。演示数据是按固定种子生成的星型模型，订单金额以分为单位，随交付物一起生成、一起销毁。

## 二、交付物一览

- `structured_data_api/`：13 个模块，纯标准库（`sqlite3`、`http.server`、`dataclasses`、`urllib`），无第三方依赖。
- `config/`：字段白名单、访问契约、运行上限、演示令牌四份 JSON，装载时即校验，配置错误直接拒绝启动。
- `samples/queries.jsonl`：35 条样例，10 条合法、25 条应被拒绝，覆盖参数、模板、SQL、写操作四类。
- `tests/test_runner.py`：86 个用例，打印 `86/86 tests passed`。
- `verify/run_verification.py`：自动复跑 demo 与测试，真实起 HTTP 服务，输出 `93/93 assertions passed`，原始输出落 `verify/records/`。
- `out/`：契约、成功结果、拒绝记录、审计日志、三层取证、HTTP 调用明细、完整演示日志七个文件。

## 三、五个关键设计决策

### 3.1 只读能力落在连接上，不落在调用方自律上

绝大多数「只读接口」靠代码评审保证：只要没人写 `INSERT` 就安全。本项目的做法是让连接本身没有写权限。SQLite 用 `file:...?mode=ro` URI 打开时，写操作在文件层面就失败；即便换成可写连接，也先执行 `PRAGMA query_only=ON`；再进一步，用 `sqlite3.set_authorizer` 在 prepare 阶段拒绝非 SELECT 动作。三层任选其一都能独立挡住写入，三层叠加是为了证明「单点失手不会升级为数据损坏」。

### 3.2 三层防线职责分离

- 第一层管「能不能写」：连接只读、query_only、authorizer；
- 第二层管「这条语句像不像只读」：首关键字必须是 SELECT/WITH、只允许一条语句、禁注释、禁写关键字、视图白名单；
- 第三层管「返回多少、跑多久」：limit 校验、`fetchmany` 截断、progress handler 超时中断。

分层不是为了好看，而是为了让每层都能被单独测试。`verify/run_verification.py` 第五节刻意在「没有语句检查器」的情况下验证 authorizer 仍拒绝 DELETE，在「没有数据库」的情况下验证解析器仍拒绝 PRAGMA，在「没有前两层」的情况下验证截断与超时仍生效。

### 3.3 客户端只能引用模板，不能提交 SQL

请求体只允许 `template`、`params`、`limit` 三个顶层键。出现 `sql` 键直接 `E_PARAM_UNKNOWN` 并提示「服务不接受客户端提交 SQL」。模板的 SQL 写在 `config/access_contract.json` 里，参数以命名占位符绑定，值永远不会被拼进 SQL 文本。这样即使参数里塞了 `'; DROP TABLE`，它也只是一个被拒绝的字符串，而不是语法的一部分。

### 3.4 契约由配置生成，避免文档与实现漂移

`openapi.py` 从同一份 `AccessContract`、`Limits`、`AuthConfig` 生成 OpenAPI 3.0.3。路径、参数、响应、错误码、`x-guard-layers`、`x-rate-limit`、`x-audit` 都是代码产物，落盘的 `out/contract_openapi.json` 与 `build_spec()` 的输出逐字段一致，`verify` 会重新生成并比对。契约里的 7 个路径全部只有 `get`，`x-allowed-methods` 写着 `["GET"]`，`x-read-only` 为 `true`。

### 3.5 确定性让证据可复核

演示数据用 `random.Random(1520)` 生成，事实表 4000 行、日期维 731 天、4 个大区、4 个渠道、12 个商品、60 个客户分层，不写磁盘持久库，跑完即删。演示时钟从 `2026-01-05T09:00:00Z` 起，每个请求步进 1 秒。因此连续两次 `demo` 的契约、结果、拒绝、审计、三层取证、HTTP 明细六个文件逐字节相同，SHA-256 可直接对比，`verify/records/artifact_hashes.txt` 记录了这一结果。

## 四、第一层：数据库只读凭据

三种机制，9 条取证，全部 `blocked=true`：

1. `mode=ro` URI：INSERT / UPDATE / DELETE / DROP 四类语句全部返回 `attempt to write a readonly database`，错误码 `E_DB_READONLY`；
2. `PRAGMA query_only=ON`：把可写连接临时变成只读，INSERT 同样被拒；
3. `set_authorizer`：不在放行集合里的动作一律 `SQLITE_DENY`，四类写操作在 prepare 阶段失败，错误码 `E_SQL_AUTHORIZER`，并被记录为 `SQLITE_INSERT`、`SQLITE_UPDATE`、`SQLITE_DELETE`。

放行动作集合是白名单而非黑名单：`SQLITE_SELECT`、`SQLITE_READ`、`SQLITE_FUNCTION`、`SQLITE_RECURSIVE`。任何新出现的动作默认拒绝，所以 `PRAGMA`、`ATTACH`、`CREATE`、`DROP` 都不需要单独列。DROP TABLE 在 authorizer 回调里上报的动作名是 `SQLITE_DELETE`，测试断言这点而不是想当然地写 `SQLITE_DROP_TABLE`。取证结束后重新统计 `fact_sales`，仍是 4000 行。

## 五、第二层：语句白名单

`StatementInspector` 先把字符串字面量剥离，再做词法判断，避免把 `WHERE region = 'drop table x'` 误判为写操作。规则按顺序执行：

| 规则 | 拒绝示例 | 错误码 |
| --- | --- | --- |
| 只允许一条语句 | `SELECT 1; DELETE FROM fact_sales` | `E_SQL_MULTI_STATEMENT` |
| 首关键字必须是 SELECT 或 WITH | `DELETE FROM fact_sales`、`PRAGMA table_info(x)` | `E_SQL_NOT_ALLOWED` |
| 禁止注释 | `SELECT * FROM fact_sales -- x` | `E_SQL_COMMENT` |
| 禁止写关键字 | `INSERT`、`UPDATE`、`ATTACH` 等 | `E_SQL_NOT_ALLOWED` |
| 视图白名单 | `SELECT * FROM secret_salary_table` | `E_VIEW_NOT_ALLOWED` |

CTE 名称会被识别为局部别名，不计入表引用；真实表名必须在 6 个视图之内。演示里放行 2 条（普通 SELECT 与 WITH），拒绝 6 条，覆盖 4 个错误码。这一层完全不连接数据库，所以它可以在连接建立之前、在网关侧、在单元测试里独立运行。

## 六、第三层：行数与超时

- 行数：模板自身有 `max_rows`，全局还有 `max_rows_hard=200`。请求的 `limit` 超过二者较小值直接 `E_ROW_LIMIT`，不会先查再截。明细模板 `sales_line_sample` 的 SQL 故意不写 LIMIT，由 `fetchmany(limit+1)` 截断并标记 `truncated=true`，这样「截断」是执行层的事实，而不是 SQL 文本里的承诺。
- 超时：`progress handler` 每 2000 次虚拟机指令检查一次单调时钟，超过阈值返回非零中断查询，映射为 `E_TIMEOUT`。自连接模板 `benchmark_cross_join` 会扫描 1600 万行，实测约 6 秒，用 150ms 阈值可以稳定中断；中断后同一连接仍能执行 `SELECT COUNT(*)`，证明超时不会污染连接状态。

第三层的 3 条取证分别是：cap=5 返回 5 行且 truncated、limit=100000 在参数层被拒、150ms 超时中断且连接可复用。

## 七、参数校验

校验器按「类型 → 注入特征 → 长度 → 枚举 → 范围」的顺序执行，并区分全局字段白名单与模板可用字段。27 个错误码可分为五组：

| 分组 | 错误码 |
| --- | --- |
| 请求形状 | `E_PARAM_MISSING`、`E_PARAM_UNKNOWN`、`E_PARAM_DUPLICATE`、`E_TEMPLATE_UNKNOWN` |
| 类型与范围 | `E_PARAM_TYPE`、`E_PARAM_RANGE`、`E_PARAM_ENUM`、`E_PARAM_LENGTH`、`E_ROW_LIMIT` |
| 字段可见性 | `E_PARAM_NOT_IN_TEMPLATE` |
| 注入与语句 | `E_PARAM_INJECTION`、`E_SQL_NOT_ALLOWED`、`E_SQL_MULTI_STATEMENT`、`E_SQL_COMMENT`、`E_VIEW_NOT_ALLOWED` |
| 执行与传输 | `E_SQL_AUTHORIZER`、`E_DB_READONLY`、`E_SCHEMA_DRIFT`、`E_TIMEOUT`、`E_DB_ERROR`、`E_AUTH_MISSING_TOKEN`、`E_AUTH_INVALID_TOKEN`、`E_SCOPE_DENIED`、`E_RATE_LIMITED`、`E_METHOD_NOT_ALLOWED`、`E_NOT_FOUND`、`E_REQUEST_TOO_LARGE` |

几个容易被忽略的点：

- 布尔值不算整数，`limit=true` 返回 `E_PARAM_TYPE`，避免 Python 里 `True == 1` 的隐式转换；
- 日期必须是严格的 `YYYY-MM-DD`，且落在 `2024-01-01` 到 `2025-12-31` 之间，`date_from` 不得晚于 `date_to`；
- `region` 只接受四个枚举值，长度上限 8，超长与枚举外取值是两个不同的错误码；
- 注入特征包括分号、单双引号、`--`、`/* */`、控制字符、SQL 关键字序列；错误信息只回显预览值，不回显整段输入；
- 每个错误都带字段名与可读中文说明，HTTP 层再包一层 `request_id`，调用方可以直接定位。

## 八、HTTP 接口与契约

服务用 `http.server.ThreadingHTTPServer`，只绑定 `127.0.0.1`，只注册 GET（其余方法在分发前统一 405 并带 `Allow: GET`）。7 个端点：

| 方法 | 路径 | scope | 说明 |
| --- | --- | --- | --- |
| GET | `/healthz` | 免鉴权 | 存活与只读声明 |
| GET | `/v1/contract` | query | 契约、上限、三层说明 |
| GET | `/v1/fields` | query | 7 个字段元数据 |
| GET | `/v1/queries` | query | 7 个对外模板 |
| GET | `/v1/query` | query | 执行模板查询 |
| GET | `/v1/audit/tail` | audit | 最近审计条目 |
| GET | `/v1/openapi.json` | query | 在线契约 |

鉴权用 `X-API-Token`，四个演示令牌分别演示：常规读写（query+audit）、只给审计（audit）、低配额突发（query+audit，5 次/60 秒）、只给查询（query）。scope 不足返回 403，令牌缺失或无效返回 401，路径不存在返回 404，参数错误返回 400，限流返回 429 并带 `Retry-After`。

审计在响应之前写入，字段包括序号、时间、request_id、来源、方法、路径、模板、结果、状态码、错误码、命中层、返回行数、token_id、客户端地址、参数预览与消息。审计只记录令牌标识，不记录明文令牌；`verify` 会扫描审计文件确认四个令牌的明文都不出现。演示一次完整跑完产生 46 条审计（成功 21、拒绝 25），HTTP 侧 14 次调用全部可关联。

## 九、数据模型

六张表加六个视图，全部只读：

- `fact_sales`：4000 条销售明细，金额以分为单位，避免浮点累计误差；
- `dim_date`：731 天，覆盖 2024-01-01 至 2025-12-31；
- `dim_region`：华东、华南、华北、西南；
- `dim_channel`：online、retail、partner、wholesale；
- `dim_product`：12 个商品，含品类与单价；
- `dim_customer`：60 个客户，只有分层标签，没有姓名、电话、地址。

视图层承担聚合：`v_sales_daily`、`v_category_revenue`、`v_channel_daily`、`v_segment_summary`、`v_product_rank`、`v_sales_enriched`。模板只引用视图，不直接触碰事实表，这样即使视图定义变化，第二层的视图白名单与第三层的输出列白名单仍能各自兜底。输出列另有 14 项白名单，模板返回未登记的列会触发 `E_SCHEMA_DRIFT`。

## 十、复现步骤与真实验证结果

三步复跑，全部只需要 Python 3.10 以上：

```bash
python -m structured_data_api demo
python tests/test_runner.py
python verify/run_verification.py
```

本次实际运行结果：

- `demo` 退出码 0，生成 7 个产物；三层取证 20 条（L1=9、L2=8、L3=3），35 条样例期望不符 0 条；
- `tests/test_runner.py` 输出 `86/86 tests passed`；
- `verify/run_verification.py` 输出 `93/93 assertions passed`，其中真实起 HTTP 服务并发起 20 余次请求，覆盖 200/400/401/403/404/405/429；
- 连续两次 `demo` 的 6 个确定性产物 SHA-256 完全一致；
- `verify/records/` 保存了 demo、测试、自检的原始输出、HTTP 调用明细与哈希清单，`verification_record.md` 给出逐条断言表。

复现要点：不要用 `-O` 运行，不要在 demo 目录里放旧产物；`verify` 会覆盖 `out/`，这正是确定性比对的一部分。若在 Windows 控制台看到中文乱码，那是终端解码问题，文件本身是 UTF-8。

## 十一、错误响应示例

HTTP 层的错误统一为 `{request_id, status, error}`，`error` 至少包含 `code`、`message`、`layer`，能定位到字段时再加 `field`。例如把 `region` 写成 `华东; DROP TABLE fact_sales`：

```json
{
  "request_id": "req-0012",
  "status": 400,
  "error": {
    "code": "E_PARAM_INJECTION",
    "message": "参数 region 包含注入特征（分号（多语句拼接）），已拒绝；值：华东...",
    "layer": "param",
    "field": "region"
  }
}
```

状态码与错误码分工明确：401 只管身份，403 管 scope 与语句策略，400 管请求本身，404 管路径，405 管方法，429 管配额，504 管超时。调用方不需要解析自然语言就能决定重试、改参还是换凭据。

## 十二、取舍与已知边界

- SQLite 而不是 PostgreSQL：单文件、零运维、`mode=ro` 与 authorizer 的行为可预测，适合做可复现交付；生产替换为只读副本账号时，三层结构不变，只需替换第一层的实现。
- 令牌明文写在配置里：仅用于本地验收，文档与契约都注明生产应改为哈希存储、短期凭据与轮换。
- 限流是单进程内存滑动窗口：多副本部署需要换成 Redis 或网关限流，接口语义不变。
- 审计写内存并落 JSONL：演示够用，生产应进入不可篡改的日志系统；当前实现保留 5000 条上限，避免无限增长。
- `benchmark_cross_join` 是故意保留的「慢查询探针」，不对外暴露（`exposed_via_api=false`），只用于证明超时机制真的会中断。
- 不做分页游标：当前数据集最大 4000 行，limit 硬上限 200，足够覆盖 Agent 的聚合查询场景。

## 十三、验收对照

| 验收要求 | 对应实现 | 可核对证据 |
| --- | --- | --- |
| 参数校验 | 27 个错误码，类型/范围/枚举/长度/注入/白名单逐项校验 | `samples/queries.jsonl` 25 条拒绝、`out/rejected_requests.jsonl` |
| 只读边界 | 只读 URI、query_only、authorizer、语句白名单、行数与超时 | `out/layer_evidence.jsonl` 20 条取证、`verify` 第五节独立复现 |
| 调用结果样例 | 10 条成功查询的真实行数据 + 14 次 HTTP 调用明细 | `out/query_results.jsonl`、`out/http_calls.jsonl` |
| 契约 | OpenAPI 3.0.3，7 个路径全部 GET，含三层与限流声明 | `out/contract_openapi.json`、`/v1/openapi.json` |

仓库地址：- 交付物仓库（含可浏览源码树 source/ 与打包文件）：https://github.com/Code-play/clawhunt-1520-structured-data-api

打包下载：- 打包下载（zip）：https://github.com/Code-play/clawhunt-1520-structured-data-api/raw/main/1520-structured-data-api.zip

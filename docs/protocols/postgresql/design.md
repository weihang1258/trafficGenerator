# PostgreSQL（PostgreSQL 数据库线协议 v3，Frontend/Backend Protocol）设计契约

> 版本：v1.1.1（P-PIPE 文档轨修订；#82 postgresql）
> 日期：2026-09-30
> 车道：并发管线车道 A（文档轨）｜协议号：**82**
> 配套文件：`docs/protocols/postgresql/testcase.md`、`trafficgen/test/protocol_pcap/cases/postgresql.json`（**71 例 = 51 正 + 20 负**）以及 `cases/kingbase.json`（15 例，同层同 `proto`，`dialect=kingbase`）
> 规范基线：PostgreSQL 官方文档 Chapter 54 "Frontend/Backend Protocol"（18 版，报文格式 §54.7 / 错误字段 §54.8 / 消息流 §54.2 / SASL §54.3 / 复制 §54.4）；SHA-256 SCRAM 参照 RFC 7677；TCP/IPv4/IPv6 参照 RFC 9293/8200。
> **层链唯一真相**：本契约全文示例只有纯 `layers` 形——地址只住 `ip` 层（`src`/`dst`；IPv6 地址族同住 `ip` 层，仓库无 `ipv6` 层，kerberos/ntlm 先例）、端口只住 `tcp` 层（`src_port`/`dst_port`）、数量只走 `flow_control`；顶层只允许 `layers`/`flow_control` 家族/`output`（CORE_MEMORY §1.11–1.13）。任何顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/`postgresql` 子映射都判违规。
> **注册现状**：`postgresql` 层**已注册**（`layers/registry.go:644-660`，`CategoryTerminal` + `DependsOn ["tcp"]`），且 `allowedProtocols["postgresql"]=true`（`core/protocols.go:51`）、`NewChainPlanner("postgresql")` 已在 `cmd/server/main.go:517` 注册。本文**不宣称本次跑过 suite、不启动服务器**；所有"已落码/未落码"结论均标实测出处。
> **与 kingbase #35 的关系**：kingbase 已于 2026-09-22 **协议身份退役**，唯一合法形态 = 本层 `dialect:"kingbase"`（端口 54321，`registry.go:1886-1890` 的 `dialectFieldContract` 覆盖 + `chain_planner.go:554-594` 契约块）。本协议 = **主层 / 主协议**，kingbase = 本层的 **dialect 变体**。判定依据见 §10.6。

---

## 1. 范围、证据等级与已落码边界

本设计定义 PostgreSQL v3（major=3；minor=0 与 1）与 v3.2（PostgreSQL 18 起，minor=2）线协议的**前端/后端报文**在两个 carrier profile 上的生成契约：

- **P-DIRECT（直连，本契约主力）**：客户端直连服务端 TCP 5432，Startup → 认证序列 → ParameterStatus* → BackendKeyData → ReadyForQuery → 查询事务* → Terminate → TCP 挥手。
- **P-EXT（扩展协议）**：同一 TCP 连接上 Parse/Bind/Describe/Execute/Sync/Close/Flush 事件序（PostgreSQL 文档 §54.2.3 Extended Query）。

**证据等级三档（本契约纪律）**：

| 档 | 可写内容 | 是否固定线字节 |
|---|---|---|
| ①规范原文级 | Startup/typed 外层、各报文类型字节、认证子类型 int32、ReadyForQuery 三状态、ErrorResponse/NoticeResponse 字段序列、扩展协议 8 种完成指示字节、NegotiateProtocolVersion 布局、SSLRequest/CancelRequest/GSSENCRequest 魔数 | 是——逐字节可断言 |
| ②dissector 实测级 | Wireshark `pgsql.*` 字段名与取值（本机 TShark 3.6.14 实测 **56** 字段）、各报文在 dissector 侧的 `pgsql.type` 字符串、`decode_as` 行为、端口启发式边界 | 是——但仅作断言通道，不改写线真相 |
| ③实现现状级 | 本仓库 `internal/protocol/postgresql/*` 与 `internal/protocol/pgwire/*` 的已落码能力边界（哪些事件 kind 有 builder、哪些配置键被消费） | 是——作为"今日可达/不可达"的判据 |

**已落码边界（实测，2026-09-26 HEAD）**：

- 生成器：`internal/protocol/postgresql/layer_gen.go`（182 行）——事件驱动，`buildEventPayload` 覆盖 **14 个 kind**：`startup`/`auth_request`/`auth_response`/`password`/`parameter_status`/`backend_key_data`/`ready`/`query`/`simple_query`/`row_description`/`data_row`/`command_complete`/`query_error`/`terminate`（`layer_gen.go:117-177`）。
- 字节原语：`internal/protocol/pgwire/pgwire.go`（241 行）——`StartupMessage`/`TypedMessage`/`AuthRequest`/`PasswordMessage`/`ParameterStatus`/`BackendKeyData`/`ReadyForQuery`/`QueryMessage`/`RowDescription`/`DataRow`/`CommandComplete`/`ErrorResponse`/`TerminateMessage`/`TruncateStartup`（`pgwire.go:72-222`）。
- 校验器：`internal/protocol/postgresql/validate.go`（175 行）——`validatePostgresqlConfig` + `checkPostgreSqlWireFault` + `validatePostgreSqlEvent` 状态机（`validate.go:33/86/126`），经 `layer_gen.go:181-182` 的 `RegisterLayerValidator` 接入。
- **未接线（关键现状，P4 必办）**：`spec.Weak`——旧 `internal/protocol/postgresql/planner.go`（1455 行，含扩展协议 17 种 operation、6 种 auth method、COPY/复制/LISTEN、MSS 分段、握手/挥手自产）**没有任何非测试调用方**：全仓库 `grep -rn "protocol/postgresql"` 非测试命中只有 `cmd/server/main.go:131` 的空白导入（`_`），链路径只走 `layer_gen.go`。该 planner 的 `Plan()` 由 `planner_test.go`/`planner_coverage_test.go`/`planner_testpoints_test.go` 直调保留为回归面，**不构成线上能力**。本契约把它的能力逐项列为 A′（引擎可构建，需接线）或 B′（结构缺口），见 §11.2 / testcase §8.2。

当前 `cases/postgresql.json` 为 **71 例 = 51 正 + 20 负**；`cases/kingbase.json` **15 例**（`proto` 均为 `postgresql`，`dialect=kingbase`）。两个文件合计 86 例；其中 postgresql.json 的 71 个语义 ID 是本契约权威，kingbase 15 例为已收官 dialect 存量审计基线。

---

## 2. 推荐配置、层链与事件形状

### 2.1 层链

唯一合法链形：**`[ip, tcp, postgresql]`**（IPv6 地址族同住 `ip` 层，不新增层）。`postgresql` 是**终结层**（`CategoryTerminal`），无 `TransformEvents`、无 `OptionalOn`、无 `TransportOn`、无 `InnerRequired`——registry 实测见 `registry.go:644-660`。

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.82", "dst": "198.51.100.82"}},
    {"tcp": {"src_port": 45082}},
    {"postgresql": {
      "dialect": "postgresql",
      "wire_profile": "postgresql_v3",
      "events": [
        {"kind": "startup", "user": "bench", "database": "bench"},
        {"kind": "auth_request", "direction": "s2c", "authtype": 0},
        {"kind": "parameter_status", "direction": "s2c"},
        {"kind": "backend_key_data", "direction": "s2c"},
        {"kind": "ready", "direction": "s2c"},
        {"kind": "query", "sql": "SELECT 1"},
        {"kind": "row_description", "direction": "s2c"},
        {"kind": "data_row", "direction": "s2c"},
        {"kind": "command_complete", "direction": "s2c", "tag": "SELECT 1"},
        {"kind": "ready", "direction": "s2c"},
        {"kind": "terminate"}
      ]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

> **`tcp.dst_port` 不写**：由 `postgresql` 层 `FieldContract {"tcp.dst_port": "5432"}`（`registry.go:649`）经 `EffectiveFieldContract`（`registry.go:1896`）补齐；dialect=kingbase 时被 `dialectFieldContract`（`registry.go:1886-1890`）覆盖为 54321。用户显式写端口时**域校验强制等于契约端口**，不等即拒（`chain_planner.go:585-591`）。

### 2.2 层内配置键（**唯一权威 = registry `Fields`，实测 5 键**）

| 键 | 类型 | 默认 | 语义 | 证据 |
|---|---|---|---|---|
| `dialect` | string | `"postgresql"` | 内容/端口变体选择器（`postgresql` \| `kingbase`）；非法值拒 `unknown dialect %q` | `registry.go:651`；`validate.go:39`（`unknown dialect`） |
| `wire_profile` | string | `"postgresql_v3"` | 版本/兼容模式模板名；必须 ∈ 已登记 4 值，空值拒 | `registry.go:652`；`validate.go:41-46` |
| `events` | list | `[]` | 有序应用事件序列（单会话） | `registry.go:653`；`layer_gen.go:60-64` |
| `sessions` | list | `[]` | 多会话展开：每项 `{src_port, events[]}`；非空时 `events` 被忽略 | `registry.go:654`；`layer_gen.go:48-59` |
| `wire_fault` | object | nil | 负例故障注入口，**不是线上字段** | `registry.go:658`；`validate.go:86-124`（`checkPostgreSqlWireFault`，2 有效 kind + 4 类非法形） |

**层字段范围校验（V9）**：白名单制——5 键之外的任何键 → `layers: layer "postgresql": unknown field %q`（`complete.go:279-293`）。**这是本协议唯一的事件形状守卫**：`ev.Kind`/`ev.Direction` 等事件内键**不受 registry 约束**（`events` 是 `list` 型无界字段，`complete.go:292-300` 对 `Min==0 && Max==0` 直接 skip）。

### 2.3 事件形状与「死字段」清单（P4 必办，实测）

`PostgreSQLEvent` 是 Go struct（`core/types.go:6438-6459`），14 个 JSON 键；`buildEventPayload`（`layer_gen.go:117-177`）**实际消费 8 键**：

| 事件键 | 被消费？ | 消费点 / 备注 |
|---|---|---|
| `kind` | ✅ | `layer_gen.go:118` switch（14 值： startup/auth_request/auth_response+password/parameter_status/backend_key_data/ready/query+simple_query/row_description/data_row/command_complete/query_error/terminate） |
| `direction` | ✅ | `layer_gen.go:77`（`"s2c"` → down，其余 up） |
| `user` / `database` | ✅ 仅 `startup` | `layer_gen.go:120-127`（startup 参数面） |
| `authtype` | ✅ 仅 `auth_request` | `layer_gen.go:129-135`（auth_request `authtype *int32`，缺省 3=cleartext） |
| `name` / `value` | ✅ 仅 `parameter_status` | `layer_gen.go:137-143`（parameter_status 空则循环 7 项缺省表） |
| `pid` / `secret` | ✅ 仅 `backend_key_data` | `layer_gen.go:144-150`（backend_key_data，0 → 12345/67890） |
| `sql` | ✅ 仅 `query`/`simple_query` | `layer_gen.go:151-158`（query/simple_query，空则 `"SELECT 1"`） |
| `tag` | ✅ 仅 `command_complete` | `layer_gen.go:159-164`（command_complete，空则 `"SELECT 1"`） |
| **`profile`** | ❌ **死字段** | 全仓库生成器零读取（`layer_gen.go` 无 `.Profile`；`chain_planner_translate.go:2009-2036` 的 JSON 往返只搬运不求值）。存量 15/16 例携带该键（仅 0-event 的 `kingbase_connect` 除外；含 `sessions[]` 内事件） → G-PG-5 |
| **`result`** | ❌ **死字段** | 同上（`auth_response` 的 `result:"success"` 在存量 6 例 8 事件中出现，`events[]` 6 + `sessions[]` 2，不影响字节）。→ G-PG-5 |

> **声明**：`profile`/`result` **不在 registry 白名单**（它们是事件内键，registry 只列层顶 5 键），所以不触发 `unknown field`；它们是"配上不报错但也不生效"的**静默无效配置**。本契约 P4 处置 = **删键**（§1.12「明确不解决仅适用于字段根本不被消费的场景，且用例配置里必须删掉该字段」），不写"登记保留"。

### 2.4 wire_profile 登记值与能力边界（实测）

| wire_profile | 语义 | 今日状态 |
|---|---|---|
| `postgresql_v3` | PostgreSQL v3.0 主模板（默认） | ✅ 可生成（存量 1 例在用） |
| `postgresql_v3_compatible_reference` | v3 外层回归参考 profile | ✅ 登记（`validate.go:18`），无专属用例 |
| `kingbase_es_v8_pg_compatible` | KingBaseES v8 PG-compatible | ✅ 可生成（存量 15 例在用） |
| `kingbase_native_pending` | KingBase 原生模式 | ❌ **登记但显式拒绝**：`validate.go:48`（`no fixed payload`） `wire profile %q has no fixed payload (native pending)` |

**关键现状（P4 必办）**：`wire_profile` **不参与任何字节构造**——`PostgreSQLGenerator` 是 dialect-agnostic 的（`layer_gen.go:12-19` 注释原文：generator dialect-agnostic，dialect 只选端口 + wire_profile），两种 profile 产出**完全相同的 PG v3 外层字节**。profile 差异**只落在 validator 的登记表**与端口（由 dialect 决定）。跨版本差异（v3.2 的 NegotiateProtocolVersion、可变长 BackendKeyData secret key）**今日零支持** → B′ G-PG-2。

---

## 3. 线格式权威（逐字段，P4 builder 硬对照表）

### 3.1 外层两种形态（唯一区分点）

```text
StartupMessage / SSLRequest / CancelRequest / GSSENCRequest（无 type 字节）
  int32 length      —— 含自身 4 字节（大端）
  int32 code        —— 协议版本号 或 请求魔数
  [payload]

其余全部消息（typed message）
  Byte1 type        —— ASCII 单字节
  int32 length      —— **含自身 4 字节，不含 type 字节**（大端）
  [payload]
```

**长度公式（可复算）**：
- Startup：`length = 4 + 4 + Σ(len(name)+1+len(value)+1) + 1`（末尾额外 NUL）
- typed：`length = 4 + len(payload)`
- 空 payload 的 typed 消息：`length = 4`（如 Terminate `X 00 00 00 04`）

**实测锚（本机 text2pcap + tshark 复算）**：空参数 Startup = **9 字节**（`00 00 00 09 00 03 00 00 00`）；单参数 `user/test` = **19 字节**；四参数 = **82 字节**；`pgsql.length` 字段读回与公式一致（实测 9/19/82）。

### 3.2 启动/请求码（大端 int32）

| 名称 | 值 | 十六进制 | 方向 | 备注 |
|---|---:|---|---|---|
| ProtocolVersion 3.0 | 196608 | `00 03 00 00` | F | 本契约主力 |
| ProtocolVersion 3.1 | 196609 | `00 03 00 01` | F | 管线模式（`protocol_version` 配置） |
| ProtocolVersion 3.2 | 196610 | `00 03 00 02` | F | PostgreSQL 18，256-bit cancel key；**dissector 实测读作 Unknown**（§3.9） |
| CancelRequest | 80877102 | `04 D2 16 2E` | F | 高 16 位 1234 / 低 16 位 5678 |
| SSLRequest | 80877103 | `04 D2 16 2F` | F | 高 16 位 1234 / 低 16 位 5679 |
| GSSENCRequest | 80877104 | `04 D2 16 30` | F | 高 16 位 1234 / 低 16 位 5680 |

**dissector 实测（本机 TShark 3.6.14）**：`SSLRequest` 无 `decode_as` 也在默认端口被识别为 `pgsql.type = "SSL request"`；`CancelRequest` → `"Cancel request"`；`GSSENCRequest` → `"GSS encrypt request"`；而 **`00 03 00 01`（v3.1）与 `00 03 00 02`（v3.2）均读作 `Unknown`**——即 dissector 只认 3.0 版本号。

### 3.3 全部报文类型字节表（规范 §54.7 权威 + dissector 实测双列）

| type | 名称 | 方向 | payload 关键字段 | dissector `pgsql.type` 实测 |
|---|---|---|---|---|
| （无） | StartupMessage | F | version + name/value NUL 对 + 末尾 NUL | `Startup message`（启 v3.0） |
| （无） | SSLRequest / CancelRequest / GSSENCRequest | F | code（+ pid/key 或 4B key） | `SSL request` / `Cancel request` / `GSS encrypt request` |
| `R` | Authentication* | B | int32 子类型 | `Authentication request` |
| `p` | PasswordMessage / SASLInitialResponse / SASLResponse / GSSResponse | F | 上下文决定（见 §3.4） | `Password message`（无上下文时） |
| `S` | ParameterStatus | B | name\0 value\0 | `Parameter status` |
| `K` | BackendKeyData | B | int32 pid + Byte^n secret（**n 可变**） | `Backend key data` |
| `Z` | ReadyForQuery | B | Byte1 状态 `I`\|`T`\|`E` | `Ready for query` |
| `Q` | Query（Simple） | F | String（SQL，NUL 终止） | `Simple query` |
| `T` | RowDescription | B | int16 列数 + 逐列（name\0, tableOID i32, colNum i16, typeOID i32, typeLen i16, typeMod i32, format i16） | `Row description` |
| `D` | DataRow | B | int16 列数 + 逐列（int32 长度，**-1 = NULL** + 值） | `Data row` |
| `C` | CommandComplete | B | String 命令标签 | `Command completion` |
| `E` | ErrorResponse | B | 字段序列（Byte1 码 + String）+ 单字节 0 终止 | `Error response` |
| `N` | NoticeResponse | B | 同 ErrorResponse 结构 | `Notice response` |
| `A` | NotificationResponse | B | int32 pid + channel\0 + payload\0 | `Notification response` |
| `I` | EmptyQueryResponse | B | 无 | `Empty query response` |
| `n` | NoData | B | 无 | `No data` |
| `t` | ParameterDescription | B | int16 参数数 + 逐参数 int32 OID | `Parameter description` |
| `s` | PortalSuspended | B | 无 | `Portal suspended` |
| `V` | FunctionCallResponse | B | int32 长度（-1 = NULL）+ 值 | `Function call response` |
| `X` | Terminate | F | 无 | `Termination` |
| `v` | NegotiateProtocolVersion | B | int32 服务端最新 minor + int32 未识别选项数 + String[] | `Unknown`（3.6.14 未实现） |
| `P` | Parse | F | stmt\0 query\0 int16 参数类型数 + int32[] | `Parse` |
| `B` | Bind | F | portal\0 stmt\0 int16 C + int16[C] + int16 值数 + (int32 len + bytes)* + int16 R + int16[R] | `Bind` |
| `D` | Describe | F | Byte1 `S`\|`P` + name\0 | `Describe` |
| `E` | Execute | F | portal\0 + int32 maxRows | `Execute` |
| `S` | Sync | F | 无 | `Sync` |
| `H` | Flush | F | 无 | `Flush` |
| `C` | Close | F | Byte1 `S`\|`P` + name\0 | `Close` |
| `1` | ParseComplete | B | 无 | `Parse complete` |
| `2` | BindComplete | B | 无 | `Bind complete` |
| `3` | CloseComplete | B | 无 | `Close complete` |
| `d` | CopyData | F&B | Byte^n | `Copy data` |
| `c` | CopyDone | F&B | 无 | `Copy done` |
| `f` | CopyFail | F | String | `Copy fail` |
| `G` | CopyInResponse | B | int8 格式 + int16 N + int16[N] | `Copy in response` |
| `H` | CopyOutResponse | B | int8 格式 + int16 N + int16[N] | `Copy out response` |
| `W` | CopyBothResponse | B | int8 格式 + int16 N + int16[N] | `Copy both response` |
| `F` | FunctionCall | F | int32 funcOID + int16 C + int16[C] + int16 参数数 + (int32 len + bytes)* + int16 结果格式 | `Function call` |

> **类型字节撞车警告（两处，都是规范原文事实，不是笔误）**：
> ① **`H` 二义**：`Flush`（F）与 `CopyOutResponse`（B）同为 0x48，靠**方向 + 会话状态**消歧。
> ② **`S` 三义**：`Sync`（F）/ `ParameterStatus`（B）/ Startup 里的无类型码，靠**方向**消歧。`C` 三义：`CommandComplete`（B）/ `Close`（F）/ `CopyDone` 是 `c` 小写。`D` 二义：`DataRow`（B）/ `Describe`（F）。`E` 二义：`ErrorResponse`（B）/ `Execute`（F）。
> ③ **直接后果**：**方向是本协议断言的必需维度**——同一字节在不同方向语义相反。本契约所有正例**必须**显式写 `direction`。

**实测锚（distractor 探针口径）**：把 typed 消息**单独**打进包（无会话上下文）时，tshark 把 `S` 读作 `Sync`、`C` 读作 `Close`、`D` 读作 `Describe`、`E` 读作 `Execute`——即 dissector 默认按**前端方向**猜。因此 `pgsql.type` 的期望值**只有在完整会话上下文里才等于真实语义**，孤立包的断言不可作为设计依据（这是存量 15/16 例走完整会话序的根因，`kingbase_connect` 为 0-event 纯连接例外；也是 P4 断言纪律）。

### 3.4 Authentication* 子类型表（int32，规范 §54.7）

| 码 | 名称 | 方向 | 附加 payload |
|---:|---|---|---|
| 0 | AuthenticationOk | B | 无 |
| 2 | AuthenticationKerberosV5 | B | 无 |
| 3 | AuthenticationCleartextPassword | B | 无 |
| 5 | AuthenticationMD5Password |  | Byte4 salt（固定 4 字节） |
| 6 | AuthenticationSCMCredential | B | 无（已废弃） |
| 7 | AuthenticationGSS | B | 无 |
| 8 | AuthenticationGSSContinue | B | Byte^n GSSAPI/SSPI 数据 |
| 9 | AuthenticationSSPI | B | 无 |
| 10 | AuthenticationSASL | B | SASL 机制名列表，逐个 String，末尾零字节终止 |
| 11 | AuthenticationSASLContinue | B | Byte^n SASL 质询 |
| 12 | AuthenticationSASLFinal | B | Byte^n SASL 结果附加数据 |

> **长度实测**：`R 00 00 00 08 00 00 00 00`（AuthOk，8 字节）；MD5 = `R 00 00 00 0C 00 00 00 05 <4B salt>`（12 字节）。**R11/R12 带最小空 payload 时 dissector 实测读作 `Unknown`**（本机 3.6.14）——即只有 0/3/5/10 等被识别，P4 断言 R11/R12 必须走 frames hex。

### 3.5 ReadyForQuery 状态字节

`I` = idle（不在事务块）/ `T` = in transaction block / `E` = failed transaction block（查询被拒直到块结束）。dissector 字段 `pgsql.status`（FT_UINT8）。

### 3.6 ErrorResponse / NoticeResponse 字段序列

`Byte1 字段码 + String 值` 重复，**以单个 0x00 字节终止**（不是空字符串对）。字段码（规范 §54.8）：

| 码 | 含义 | 码 | 含义 |
|---|---|---|---|
| `S` | Severity（本地化） | `P` | Position |
| `V` | Severity（非本地化） | `W` | Where |
| `C` | SQLSTATE（**5 字符**） | `F` | File |
| `M` | 主消息 | `L` | Line |
| `D` | Detail | `R` | Routine |
| `H` | Hint | `q` | 内部查询 |
| `s` | 内部位置 | | |

字段**可任意顺序**，前端必须静默忽略未知字段码。生成器缺省文案（`layer_gen.go:172`）：`severity="ERROR"` / `code="42P01"` / `message="relation does not exist"`。

### 3.7 查询事务的两条路径

- **Simple Query**（`Q`）：单条 SQL 字符串；响应 = `T`/`D`*/`C` 或 `E` + `Z`。多语句（SQL 含 `;`）时**中间不夹 `Z`**，只有整批结束才 `Z`（规范 §54.2.3；本仓库 legacy planner `splitMultiStatement` 同判）。
- **Extended Query**（§54.2.3）：`P`→`1`、`B`→`2`、`D`→`T`/`n`/`t`、`E`→`D`*/`C`/`s`、`S`→`Z`、`H`（无响应）、`C`→`3`。**错误发生在任一阶段：跳过该消息之后到 `Sync` 之前的所有消息**，然后发 `E` + `Z`。

### 3.8 BackendKeyData 的变长面（v3.2 新增）

规范：`int32 pid` + `Byte^n secret`，**n 从 4 至 256 字节可变**，由 length 字段决定；v3.2 之前恒 4 字节。**今日实现**：`pgwire.BackendKeyData(pid, secret int32)` 硬编码 8 字节 payload（`pgwire.go:128-134`）→ 变长 secret 是 B′ 缺口 G-PG-2。

### 3.9 dissector 能力边界（实测，写死供 P4 参照）

| 探针 | 结果 |
|---|---|
| Startup v3.0（`00 03 00 00`） | `pgsql.type="Startup message"`，`pgsql.version_major=3`、`version_minor=0`、`pgsql.length` 正确 |
| Startup v3.1（`00 03 00 01`）/ v3.2（`00 03 00 02`） | `pgsql.type="Unknown"`（**字段通道不可用**） |
| 单独 typed `R`（任意子类型） | `Unknown`（无会话上下文时不拆） |
| 单独 typed `S` / `C` / `D` / `E` | 读作 `Sync` / `Close` / `Describe` / `Execute`（按前端方向猜） |
| 单独 `Q` | `Simple query` + `pgsql.query` 正确 |
| 单独 `p` | `Password message` |
| 单独 `X` | `Termination` |
| `v`（NegotiateProtocolVersion） | `Unknown` |
| 裸 `00 03 00 00` 且**无参数** | `Startup message` + `pgsql.length=9`（合法最短形） |

**结论（P4 断言纪律）**：①**字段通道需要完整会话上下文**（Startup 起头）；②**非 3.0 版本号与 R11/R12/`v` 必须走 frames hex**；③`decode_as` 只对**非标准端口**必要（§10.5）。

---

## 4. 会话状态机与自动派生（设计权威）

### 4.1 状态集合

```text
Init ──Startup──▶ Started ──Auth*──▶ Authenticating ──AuthOk──▶ Ready
                                                                  │
                          ┌───────────────Query/Extended──────────┤
                          ▼                                        │
                      Busy ──(T/D/C 或 E)──▶ Ready ◀───────────────┘
                                                                  │
                                       Terminate ─▶ Closed ──FIN──▶ End
```

- `Init → Started`：客户端发 Startup（**唯一无 type 字节的报文**）。
- `Authenticating`：服务端按需发 `R`；客户端按子类型回应（3→`p` 明文；5→`p` md5；10→`p` SASLInitialResponse、11↔`p`、12）。
- `Ready`：服务端发 `Z` 后进入。**`ReadyForQuery` 的 'I'/'T'/'E' 三态由事务状态决定，不由消息类型决定**。
- `Ready → Busy`：客户端发 `Q`（或扩展序）。
- **状态机守卫（当前唯一强制项，实测）**：`validate.go:126-144`（`validatePostgreSqlEvent` :126 + `before ready` :139） —— `direction="c2s"` 且 kind ∈ {`query`, `simple_query`, `password`} 且**尚未 ready** → 拒 `postgresql: event %d: %s before ready (state error)`。`ready` 由 s2c 的 `ready`/`auth_request`/`row_description`/`data_row`/`command_complete`/`query_error` 六类置位（`validate.go:158-166`：`s2cMakesPgReady` 六类）。

### 4.2 非法转移（拒绝 + 锚词）

| 非法转移 | 锚词 | 触发点 |
|---|---|---|
| 未 ready 即 query/password | `state` | `validate.go:139`（`before ready`，负例 `kingbase_neg_state` 在用） |
| 未登记 kind | `invalid kind` | `validate.go:128`（`invalid kind`） |
| 非法 direction（非 `c2s`/`s2c`） | `invalid direction` | `validate.go:131`（`invalid direction`） |
| `query`/`simple_query` 空 SQL | `requires non-empty sql` | `validate.go:134`（`non-empty sql`） |
| 未登记 dialect | `unknown dialect` | `validate.go:39`（`unknown dialect`） |
| 未登记 wire_profile | `unknown wire profile` | `validate.go:45`（`unknown wire profile`） |
| `kingbase_native_pending` | `no fixed payload` | `validate.go:48`（`no fixed payload`） |
| 链夹 `udp` | `carrier must be tcp` | `chain_planner.go:572-575` |
| 显式 dst_port ≠ 契约端口 | `is not the default %d` | `chain_planner.go:585-591` |
| `wire_fault.kind` 越界 | `unknown kind` | `validate.go:123`（`checkPostgreSqlWireFault` default 分支） |

### 4.3 自动派生帧（生成器自动补的内容，逐条列出）

| 派生内容 | 触发条件 | 内容 |
|---|---|---|
| StartupMessage | `kind="startup"` | 参数取自 `user`/`database`（空则只有 version + 终止 NUL，= 9 字节） |
| AuthenticationRequest | `kind="auth_request"` | 子类型取自 `authtype`；**缺省 3（cleartext）**，与存量 `authtype:0` 显式写法不同（`layer_gen.go:129-133`） |
| PasswordMessage | `kind="auth_response"` / `"password"` | **恒 `"testpass"`**（`layer_gen.go:135`）——不接受事件级密码值 |
| ParameterStatus | `kind="parameter_status"` 且 `name`/`value` 均空 | 从 7 项缺省表**按实例内计数器循环**（`layer_gen.go:90-98/140-143`，`paramIdx` 是 per-generator 字段，每流从 0 起） |
| BackendKeyData | `kind="backend_key_data"` 且 pid/secret 为 0 | 12345 / 67890 |
| Query | `kind="query"` 且 `sql` 空 | `"SELECT 1"` |
| CommandComplete | `kind="command_complete"` 且 `tag` 空 | `"SELECT 1"` |
| ErrorResponse | `kind="query_error"` | 恒 `ERROR` / `42P01` / `relation does not exist` |
| ReadyForQuery | `kind="ready"` | **恒 `'I'`**（`layer_gen.go:154`，`RFQIdle`）——`'T'`/`'E'` 今日不可达 → A′ |
| Terminate | `kind="terminate"` | 无 payload |
| **TCP 握手/挥手** | 由 `tcp` 层决定（`handshake` 默认 true、`termination` 默认 true；`rst` 默认 false） | 不在本层内 |
| **会话边界** | `sessions[]` 每项的 `src_port` 作为 `MessageEvent.SrcPort` 上报（`layer_gen.go:53`），tcp 层检测到端口变化即挥旧握新（`generator.go:1457` 会话边界注释 + P0a 多会话注 `generator.go:1008-1010`） | 多会话展开 |

> **「自动应答」不存在**：本层是**声明式脚本化回放**，不因收到 `R` 自动补 `p`。每个方向的报文都必须在 `events[]` 里显式声明（与 protocol-doc-requirements §5 术语表一致）。

---

## 5. 依赖声明与端口契约

**依赖（§5.1）**：依赖 `tcp` 层（唯一载体，`DependsOn ["tcp"]` registry.go:644）；依赖 `ip` 层提供地址族与 TTL（经 tcp 的 `DependsOn ["ip"]` 间接补全）；**无 `udp` 语义**（链夹 udp 判死）；无外部密钥/证书依赖（认证字节为固定测试值，不做真实密码学）。

**端口契约（§1.3 R1/R2）**：`FieldContract {"tcp.dst_port": "5432"}`（`registry.go:649`）→ dialect=kingbase 时 `dialectFieldContract`（`registry.go:1886-1890`）覆盖为 `"54321"` → 由 `chain_planner.go:554-594` 的契约块计算 `contractPort` 并写 `spec.DstPort`。**用户显式写端口 = 域校验**（等于契约端口才放行，`chain_planner.go:585-591`）。`postgresql` 同时在 `validateBaseDstPortHandled` 名单里（`chain_planner.go:644`），故通用 FieldContract 端口补齐块不覆盖它。

---

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **6.1/6.2 目标与预算**：本层为**事件驱动流式渲染**——逐事件构造一个 PG 报文并立即 `EmitMsg`，无全量聚合、无按包增长的结构（`layer_gen.go:72-84`）；唯一可变状态是 per-generator 的 `paramIdx` 计数（int，O(1) 内存）。帧长上界：typed 消息 ≤ `4 + len(payload)`，payload 由事件字段长度决定（`sql`/`tag`/参数值都是配置输入，天然有界）；Startup ≤ `9 + Σ(参数对)`。并发面：每个 flow 一个新 generator 实例（`layer_gen.go:180` 工厂），**无共享可变状态、无需锁**。速率与队列上限由框架（Pacer / 有界队列）承担，本层不重复定义。
- **6.3 双路验收**：**pcap 路** = suite 落盘 `/tmp/mcp-pcaps/postgresql/`，用 tshark `pgsql.*` 字段 + frames hex 校对；**NIC 路** = `output_type=port_group` + 网口 `enp135s0f0np0` 抓包，断言 TCP/应用字段一致（记忆 `testing-interface` 指定网口）。
- **6.4 依据**：流式路径如 6.1 所述；每条流新增内存 = 一个 generator 实例（含一个 int 计数）+ 当前报文字节切片；无共享状态、无锁；限速与多 worker 总速率正确性由框架 pacer（共享桶）保证，本层不引入第二套速率语义。
- **6.5 诚实待确认**：**吞吐（包/秒、bit/秒）、并发流数、内存上限的具体数字待 P4 基准实测后钉**，本文不写承诺数字（§6.5「没有代码路径或基准数据支撑的性能数字只能标为待确认」）。
- **6.6 六类场景**：基线（单会话单查询）/ 目标规模（多会话 `sessions[]`）/ 压力上限（大 SQL + 大参数值，逼近 MSS 分段）/ 长时间运行（长会话多轮查询）/ 并发交错（多流 `flows=N` × 多会话）/ 背压（下游消费慢时队列积压行为）。前五类 P4/P5 落用例，背压类沿用框架既有测试面。
- **6.7 断言口径**：断言**实际输出值**（`pgsql.type`/`pgsql.query`/`pgsql.tag`/`pgsql.status`/`pgsql.authtype` + frames hex），**不许只断言"任务没失败"**；负例断言锚词。
- **6.8 失败边界**：功能正确但超预算视为设计不合格——本层的预算面即"单 flow 常驻内存 O(1)"，若 P4 引入按流缓存报文数组即违反本条。

---

## 7. 错误处理与错误传播

- 所有校验错误必须在 **planner/validator 边界**抛出并传播为 **task error**，**不许**产出成功 PCAP、`completed + 0 packet`、或只剩 TCP 外壳的假成功（CORE_MEMORY §14.11/§14.12）。
- 负例执行期 `expect` 键集合**严格**为 `{"expect_error", "error_contains"}`（protocol-doc-requirements §7「负例纯净性」）。
- **`wire_fault` 的当前实现边界（实测）**：`checkPostgreSqlWireFault`（`validate.go:86-124`）只接受**对象**形 `{"kind": ..., "value": ...}`，两个 kind：
  - `truncate_startup` → `wire fault: startup length truncated by %v, below minimum outer length`（锚词 `length`）
  - `message_limit` → `wire fault: message %v exceeds implementation limit`（锚词 `limit`）
  - 其它 kind → `unknown kind %q`；字符串 / 数字 / 数组形 → `expected object, got ...`
  - 空对象 / null / 空串 / 缺键 = **无故障**（no-op），这是刻意的（`registry.go:655-658` 注释说明 schema 默认若为 `""` 会被误读为故障）。
  - **注意**：`truncate_startup` 的**字节截断动作在生成器侧未接线**（`layer_gen.go` 不读 `wire_fault`）——故障在 validator 期就被拒绝，因此负例走"配置被拒"通道而非"产出截断包"通道。这是**正确也是唯一可行**的通道（§14.11 要求坏配置必须被拒）。
- `wire_profile` 越界、dialect 越界、事件 kind/direction 越界、state 越界、carrier 越界、端口越界——锚词表见 §4.2。

---

## 8. 存量审计口径

`cases/postgresql.json`（71 例）+ `cases/kingbase.json`（15 例）合计 **86 例**；本设计的逐 ID 权威集合为 postgresql.json 的 **71 例（51 正 + 20 负）**，kingbase 15 例只作 dialect 存量审计去向。三条实测事实先行：

1. **JSON 71 例的顶层形状已静态对账**：69 例顶层仅 `layers`，1 例合法 `group_id` 框架键（#46），1 例故意保留 `layers` + 顶层 `postgresql` 双键 presence 负例（#65，G-PG-6，不能宣称今日真实拒绝）。因此**正例顶层游离键 = 0**；#65 是唯一故意违规形状，不得清洗为正例。kingbase 15 例另作 dialect 存量审计，均已是纯 layers。
2. **`decode_as` 分布**：postgresql.json 的 71 例中，标准端口例无需声明；kingbase 15 例中 9 个正例带 `tcp.port==54321,pgsql`，6 个负例无（无 PCAP）。
3. **20/20 负例纯净**：全部负例的 `expect` 只有 `{expect_error, error_contains}`；#65 虽为 presence 缺口形，仍遵守双键负例契约。

---

## 9. 用例集合摘要（ID 权威在 testcase §2）

**合计 71 个语义 ID = 51 正 + 20 负**（其中存量 16 例为改写/等价覆盖，48 例为新增或 A′ 待落）。分布：

- 正例 51：启动与请求码 9（#1–#9）/ 认证子类型 11（#10–#20）/ 参数与后端键 4（#21–#24）/ 事务状态与查询 10（#25–#34）/ 扩展协议 5（#35–#39）/ 异步与函数调用 3（#40–#42）/ 分段与多流 6（#43–#48）/ 长会话与异常结束 3（#67–#69）。
- 负例 20：原有配置、状态、载体、事件与 `wire_fault` 面（#49–#64）+ presence/静态复制/认证 token 边界（#65–#66、#70–#71）。

逐 ID、逐 `packet_count`、逐断言见 testcase §2–§4。

---

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：矩阵三张子表——①报文×会话状态矩阵（§10.2）②数据形态变体表（§10.3）③商业行为→用例映射表（§10.5）。条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号，**不留白**。
> **内层密码学边界（本设计铁律，逐矩阵行重申）**：MD5 摘要、SCRAM 质询/响应、GSSAPI token 一律 **opaque**——只校验存在性/长度/非全零；**不实现真实密码学、不解密、不验证口令**（`planner.go:36-39` 原文自陈"the planner does NOT implement real cryptography"）。无授权密钥不得声称验证过凭证。

### 10.1 八项规范矩阵

| # | 规范要求（条款+本契约节） | 业务场景 | 代码现状（实测） | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：单 TCP 长连接承载全部会话（Startup→…→Terminate）；无控制/数据分离；客户端主动建连（规范 §54.2「To begin a session, a frontend opens a connection…」；本契约 §4） | 连接池客户端（pgx/libpq/JDBC）建连+多轮查询 | ✅ registry 已注册（`registry.go:644-660`）；✅ 生成器事件驱动（`layer_gen.go`）；✅ 多会话经 `sessions[].src_port` 复用同一 TCP 层多连接（`layer_gen.go:48-62` + `generator.go:1457` 会话边界） | 无（A′ 已覆盖连通性） |
| 2 | 报文表：无类型 Startup 4 码 + 39 个 typed 类型字节（规范 §54.7 全枚举；本契约 §3.1–3.3） | 全报文族覆盖 | ⚠️ **已实现 11 个**：Startup、R、p、S、K、Z、Q、T、D、C、E、X（`pgwire.go` + `layer_gen.go:117-177`）；❌ **未实现**：N/A/I/n/t/s/V/v、P/B/D(Describe)/E(Execute)/S(Sync)/H(Flush)/C(Close)、1/2/3、d/c/f/G/H/W、F | 缺口 → A′（legacy planner 已有扩展协议 17 种 operation、COPY、复制、LISTEN、FunctionCall 的实现可供接线）+ B′ G-PG-1/2 |
| 3 | 状态机：Init→Started→Authenticating→Ready→Busy→Ready→Closed；非法转移拒（规范 §54.2.2/§54.2.3；本契约 §4.1） | 客户端乱序发包、未 ready 即查询 | ⚠️ **部分**：c2s `query`/`password` before-ready 拒（`validate.go:126-144`：`validatePostgreSqlEvent` + `c2sNeedsPgReady` 三 kind）；其余转移**无守卫**（可配 `terminate` 后继续 `query`，validator 不拦） | 缺口 → A′（补状态守卫）+ §10.2 逐格 |
| 4 | 字段表：全部 int 字段**大端**；长度含自身（typed 不含 type 字节）；String = NUL 终止；Byte^n 变长（规范 §54.6/§54.7；本契约 §3.1） | 跨实现互操作（libpq/pgx/JDBC/psycopg） | ✅ 大端（`pgwire.go:65` `appendUint32` 用 `>>24/16/8`）；✅ 长度含自身、typed 不含 type（`pgwire.go:93-100`）；⚠️ `BackendKeyData` secret **恒 4 字节**（`pgwire.go:128`），变长面未实现 | 变长 secret → B′ G-PG-2 |
| 5 | 错误处理：ErrorResponse/NoticeResponse 字段序列 + 单 0x00 终止；扩展协议错误跳过至 Sync；连接期错误即断连（规范 §54.8/§54.2.3；本契约 §3.6/§7） | 查询报错、语法错、关系不存在 | ⚠️ 仅恒值 `ERROR/42P01/relation does not exist`（`layer_gen.go:172`）；❌ 无字段级配置、无 NoticeResponse（`N`）、无 SQLSTATE 可配置面 | 缺口 → A′（legacy `PGErrorField`（`types.go:6703-6706`）结构 + `ErrorFields`/`ErrorSegment`（`types.go:6675-6680`）已实现） |
| 6 | 超时与活性：**PostgreSQL 协议层无 keepalive/超时/重传语义**——由 TCP 承担；会话空闲不断连（服务端 `idle_session_timeout` 是配置项非协议特性）（规范 §54.2 无此章；本契约 §11.3） | 连接池长连接空闲复用 | ✅ 协议层无自有定时器（生成器不含 sleep）；✅ TCP keepalive 由 `tcp` 层握手机制承担 | **不适用**（显式声明：协议无此语义，不硬凑用例；长保活用例由"同连接多轮查询"承载） |
| 7 | NAT/代理：PostgreSQL 无应用层 NAT 遍历（无 PORT/PASV 类衍生连接）；`CancelRequest` 是**第二条独立连接**（F 侧发起，携带目标后端 pid+key）——这是本协议唯一的"关联连接"形态（规范 §54.2.6/§54.7 CancelRequest；本契约 §10.4） | PgBouncer/连接池中间件；查询取消 | ❌ 未实现（无 CancelRequest builder、无跨连接关联建模） | 缺口 → B′ G-PG-3（关联流形态：主连接 + 取消连接，`driven_by` 语义待裁定） |
| 8 | 版本/方言：major=3（minor 0/1/2）；minor 由服务端 `NegotiateProtocolVersion`（`v`）回落；方言面 = 认证方法族（trust/cleartext/md5/scram-sha-256/gss/sspi）；KingBase = 本层 dialect 变体（规范 §54.2.1/§54.2.2；本契约 §2.4/§10.6） | PG 15/16/18 并存；KingBaseES 兼容部署 | ⚠️ `protocol_version` 字段存在但**生成器不读**（`layer_gen.go:119-127` 恒 `ProtocolVersion` 常量）；❌ `v` 未实现；✅ 6 种认证方法在 legacy planner 已实现（`planner.go:469-525` 的 `runAuth`：trust/cleartext/md5/scram-sha-256/gss/sspi），⚠️ 事件面只暴露 `authtype` 单数字（无 SCRAM 三步事件） | 缺口 → B′ G-PG-2（v3.2/协商）+ A′（SCRAM 三步事件化） |

### 10.2 子表①：报文×会话状态矩阵（逐格已覆/缺失/不适用）

> **适配声明**：本协议无"响应码"概念（§4.22 原型是请求命令×响应码）。等价物 = **报文类型 × 会话状态**（规范 §54.2 状态流转），并叠加**方向**维度（因 §3.3 的类型字节二义）。
> 行 = 报文族（21 行）；列 = 5 个会话状态面。

| 报文族 \ 状态 | Init→Started | Authenticating | Ready（空闲） | Busy（查询中） | Closed（Terminate 后） |
|---|---|---|---|---|---|
| Startup（无类型） | 已覆 #1/#3/#4 | 不适用（不可重发） | 不适用 | 不适用 | 不适用 |
| SSL/Cancel/GSSENC（无类型） | 已覆 #7/#8/#9 | 不适用 | 不适用 | 已覆 #9（Cancel 独立连接） | 不适用 |
| `R` Authentication* | 不适用 | 已覆 #10–#20（11 子类型） | 不适用 | 不适用 | 不适用 |
| `p` Password/SASL/GSS | 不适用 | 已覆 #12/#13/#18–#20 | 不适用 | 不适用 | 不适用 |
| `S` ParameterStatus | 不适用 | 已覆 #21/#22 | 缺口→A′（运行期 SET 后下发） | 缺口→A′ | 不适用 |
| `K` BackendKeyData | 不适用 | 已覆 #23 | 不适用 | 不适用 | 不适用 |
| `Z` ReadyForQuery | 不适用 | 已覆 #24/#25/#26 | 已覆（每轮查询收尾，全例） | 不适用 | 不适用 |
| `Q` Query | 不适用 | 缺口→负例 #54（before-ready 判死） | 已覆 #27/#28/#29/#30/#31 | 缺口→A′（嵌套查询非法态） | 缺口→负例 #64（Terminate 后查询，A′） |
| `T`/`D`/`C` 结果族 | 不适用 | 不适用 | 不适用 | 已覆 #27–#32 | 不适用 |
| `E` ErrorResponse | 不适用 | 缺口→A′（认证失败即断连） | 缺口→A′（语法错） | 已覆 #32 | 不适用 |
| `N` NoticeResponse | 不适用 | 不适用 | 缺口→A′（server push） | 缺口→A′ | 不适用 |
| `A` NotificationResponse | 不适用 | 不适用 | 缺口→A′（LISTEN 异步推送） | 缺口→A′ | 不适用 |
| `I` EmptyQueryResponse | 不适用 | 不适用 | 缺口→A′（空 SQL） | 缺口→A′ | 不适用 |
| `n`/`t`/`s`/`V` | 不适用 | 不适用 | 不适用 | 缺口→A′（扩展协议族，legacy 已实现） | 不适用 |
| `v` NegotiateProtocolVersion | 已覆 #42 | 不适用 | 不适用 | 不适用 | 不适用 |
| `P`/`B`/`D`(Desc)/`E`(Exec) | 不适用 | 不适用 | 缺口→A′ #35–#38 | 缺口→A′ | 不适用 |
| `S` Sync / `H` Flush / `C` Close | 不适用 | 不适用 | 缺口→A′ #39 | 缺口→A′ | 不适用 |
| `1`/`2`/`3` 完成指示 | 不适用 | 不适用 | 缺口→A′（随机型报文成对） | 缺口→A′ | 不适用 |
| `d`/`c`/`f`/`G`/`H`/`W` COPY 族 | 不适用 | 不适用 | 缺口→A′（legacy `copy-from`/`copy-to` 已实现） | 缺口→A′ | 不适用 |
| `F`/`V` FunctionCall 族 | 不适用 | 不适用 | 缺口→A′（legacy `function-call` 已实现） | 缺口→A′ | 不适用 |
| `X` Terminate | 不适用 | 缺口→A′（认证中断连） | 已覆 #1（Terminate 面，全正例收尾） | 缺口→A′（查询中断） | 已覆（Terminate 后 TCP 挥手，全正例） |

**逐格机械重数（可复核）**：表体 **21 行 × 5 列 = 105 格**，三类：
- **已覆 27 格**（#1/#7–#9/#10–#20/#21–#26/#32/#23 等落点，含"全例"共享格）；
- **不适用 55 格**（协议定义上不可能出现的状态×报文组合——如 Startup 只可能出现在 Init、结果族只可能出现在 Busy）；
- **缺口 23 格**：其中 **缺口→A′ 用例通道 19 格**（本契约 testcase 已建例或立 A′ 补例），**缺口→负例通道 4 格**（#54/#55/#64 + wire_fault 面）。

27 + 55 + 23 = 105 ✓ 无空格。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

| # | 变体维度 | 形态 | 对应用例 | 备注（实测锚） |
|---:|---|---|---|---|
| 1 | 地址族 | IPv4 / IPv6（同住 `ip` 层） | #1/#2 | IPv6 起点 74 = 14+40+20；IPv4 起点 54 |
| 2 | 启动码 | v3.0 `00 03 00 00` / v3.1 `00 03 00 01` / v3.2 `00 03 00 02` | #1（v3.0 基线 Startup）+ #5/#6（v3.1/v3.2 路径） | **dissector 只认 3.0**，其余走 frames hex |
| 3 | 启动请求魔数 | SSLRequest `04 D2 16 2F` / CancelRequest `04 D2 16 2E` / GSSENCRequest `04 D2 16 30` | #7/#8/#9 | 三者默认端口即被识别（实测），且三者均只声明"客户端意图"、**无服务端响应字节** |
| 4 | Startup 参数集 | 空（9B）/ 单参数（19B）/ 四参数（82B）/ 长值（>MSS 触发分段） | #3/#4 + #43 | 长度公式 §3.1 可复算 |
| 5 | 认证子类型 | 0 / 2 / 3 / 5 / 6 / 7 / 8 / 9 / 10 / 11 / 12（11 值） | #10–#20 | **R11/R12 带空 payload 实测 Unknown** → frames hex |
| 6 | 认证响应形态 | cleartext（`p` + String）/ md5（`p` + `md5` 十六进制 35 字符）/ SASLInitialResponse（mech String + int32 len + bytes）/ SASLResponse / GSSResponse | #12/#13/#18–#20 | md5 摘要 = opaque（不校验值） |
| 7 | ParameterStatus | 缺省 7 项循环 / 显式 name+value / 空 value | #21/#22 | 缺省表 `server_encoding`…`application_name`（`layer_gen.go:90-98`） |
| 8 | BackendKeyData | pid/secret 缺省 12345/67890 / 显式值 / v3.2 变长 secret（4–256B） | #23 | 变长面 = B′ G-PG-2 |
| 9 | ReadyForQuery 状态 | `I` / `T` / `E` | #24（`I`） | `T`/`E` 今日不可达 → A′ |
| 10 | Simple Query | 单语句 / 多语句（`;`，中间不夹 `Z`）/ 空 SQL / 超长 SQL（分段） | #27–#31 + #43/#44 | 空 SQL 被 validator 拒（`requires non-empty sql`） |
| 11 | 结果族 | 0 列 `T` + 0 行 / 单列单行 / 多列多行 / 相同列名两列 | #30/#31 | 生成器恒 1 列 `col1`/恒 1 行值 `42`（`pgwire.go:148-176`）→ 列/行可配置面 = A′ |
| 12 | CommandComplete 标签 | `SELECT 1` / `INSERT 0 1` / `UPDATE 3` / `BEGIN` / 空标签 | #29 + A′ | 标签是 String，无校验 |
| 13 | ErrorResponse 字段 | severity+code+message 三字段 / 更多字段（detail/hint/position/where）/ 未知字段码 | #32 | 生成器恒 3 字段 → 可配置面 = A′ |
| 14 | 未知类型字节 | 0x00 / 0xFF / ASCII 未登记字符 | 负例 #56 | 今日**无此守卫**（生成器按 kind 分支，未知 kind 走 `invalid kind` 而非字节校验）→ 判"现状钉" |
| 15 | 扩展协议 | Parse/Bind/Describe/Execute/Sync/Close/Flush + 完成指示 1/2/3 + NoData/PortalSuspended/ParameterDescription | #35–#39 | legacy planner 全实现，事件面未接线 → A′ |
| 16 | COPY 族 | CopyIn/CopyOut/CopyBoth + CopyData/Done/Fail | A′（legacy `copy-from`/`copy-to` 已实现） | 事件面未接线 |
| 17 | 复制协议 | XLogData / PrimaryKeepalive / CopyBothResponse | A′（legacy `replication-*` 已实现） | 事件面未接线 |
| 18 | 函数调用 | FunctionCall + FunctionCallResponse（含 NULL 结果 -1） | A′（legacy `function-call` 已实现） | 事件面未接线 |
| 19 | 方向 | c2s / s2c 显式；类型字节二义对（H/S/C/D/E） | 全正例 | **方向是必需维度**（§3.3 警告） |
| 20 | 分段 | 单报文跨 segment / 多报文合并 / 跨 MSS | #43/#44 | TCP 层分段（`mss` 默认 1460，registry tcp 字段） |
| 21 | 多会话/多流 | `sessions[]` 多连接（各自 src_port）/ `flows=N` 多流 | #45/#46 | `layer_gen.go:48-59` + `worker.go:307-308` |
| 22 | 动态字段 | ip/tcp 四元组 × 五策略 | #46 | §12 清单 |
| 23 | 端口 | 默认 5432（dialect=postgresql）/ 54321（kingbase）/ 非标准端口必须声明 | #48 + 负例 #50 | 非默认端口 ≠ 契约端口即拒（`chain_planner.go:585-591`） |
| 24 | 输出路 | pcap / NIC（port_group） | A′（P5 NIC 例） | 双路验收 §6.3 |
| 25 | `decode_as` | 标准端口免声明 / 非标准端口必须声明 | #48 | §10.5 实测 |
| 26 | wire_fault | `truncate_startup` / `message_limit` / 未知 kind / 非对象形 | 负例 #60–#63 | `validate.go:86-124`（`checkPostgreSqlWireFault`：空/no-op :87-111，有效 kind :116-119，未知 kind :122-123） |
| 27 | 死字段 | 事件内 `profile` / `result` | 负例 #59（判死）+ 存量删键 | §2.3 |

### 10.4 关联关系专节（§3.8–3.10）：CancelRequest 与「无派生流」的边界

PostgreSQL **没有**控制流派生数据流的形态（对照 FTP 控制+数据、SIP 信令+媒体）：查询响应与请求复用**同一条 TCP 连接**。唯一的跨连接关系是 **CancelRequest**——客户端在**第二条 TCP 连接**上发送「目标后端 pid + secret」，服务端处理后**立即关闭该连接、不发任何响应字节**（规范 §54.2.6）。

| 关联三件事（§3.9） | CancelRequest 的取值 |
|---|---|
| 归属哪个会话 | **不是会话**——是一条一次性的独立连接（生命周期 = 建连 → 发一帧 → 挥手） |
| 归属哪个事务 | 无（不携带事务标识） |
| 由哪个字段决定 | `BackendKeyData` 的 `pid` + `secret`（由被取消的主连接在认证后收到） |

**结论**：`driven_by` 语义**不能直接套用**（CWMP 范本的 `driven_by{session,transaction,field}` 要求被关联流属于某个会话的事务）。本契约如实声明：**CancelRequest 今日不实现**（B′ G-PG-3），其关联语义待 P4 与框架共同裁定（三选一：`driven_by` 扩展 / 独立的 `cancel_of{pid,secret_source}` 字段 / 明确不支持）。**不许**用「同一模板连续重复发射」冒充该关联（§3.13）。

### 10.5 候选方案对比（§4.17）与三路对照（§4.12–4.15）

**三路对照**：

① **规范原文**：PostgreSQL 官方文档 Chapter 54（§54.2 消息流 / §54.3 SASL / §54.4 复制 / §54.6 数据类型 / §54.7 报文格式 / §54.8 错误字段）；版本面 = PG 18 文档（协议 3.2）。本契约引用的每个类型字节、长度语义、字段顺序均出自 §54.7，**不引博客/二手解读**（§4.11）。

② **现网行为**（产品+行为+出处）：
- **libpq / psql（PostgreSQL 官方 C 客户端）**：建连固定发 Startup 或先发 SSLRequest（`sslmode=prefer` 默认）再发 Startup；认证后收 `R`/`S`*/`K`/`Z`；`psql` 退出发 Terminate。出处：客户端源码行为 + 官方文档 §54.2.1 流程描述。
- **pgx（Go）/ psycopg（Python）/ JDBC**：同为上序；JDBC 默认 `sslmode=prefer` 且默认 `extra_float_digits`、`application_name` 参数。出处：官方文档 §54.2.1 参数列表 + 各客户端文档。
- **连接池/PgBouncer**：客户端可见行为不变（Startup 的 `user`/`database` 语义被池改写）。
- **KingBaseES**：`dialect=kingbase` 端口 54321、`wire_profile=kingbase_es_v8_pg_compatible`（本仓库 #35 已收官，15 例 pcap 通过）。
- **确认方式（G-PG-4）**：本机回环起 PostgreSQL 或 KingBaseES，用 `psql`/`pgx` 抓包核对 Startup 参数面与认证序列——**当前未做**，故"现网行为"档仅到"官方文档描述的客户端行为"级，未到"本机抓包已确认"级。

③ **开源实现思路**：
- **Wireshark `epan/dissectors/packet-pgsql.c`**（本机 TShark 3.6.14 实测 **56** 个 `pgsql.*` 字段，口径 `tshark -G fields | awk -F'\t' '$3 ~ /^pgsql[.]/' | wc -l`）：字段面覆盖 `pgsql.type`/`length`/`frontend`/`version_major|minor`/`authtype`/`salt`/`auth.sasl.mech|data`/`parameter_name|value`/`pid`/`key`/`status`/`query`/`password`/`statement`/`portal`/`returns`/`tag`/`copydata`/`error` 及错误字段子面（`severity`/`code`/`message`/`detail`/`hint`/`position`/`where`/`file`/`line`/`routine`…）+ 行描述子面（`field.count`/`col.name`/`col.index`/`oid`/`oid.table`/`oid.type`/`format`/`val.length`/`val.data`/`col.typemod`）。**只借鉴字段语义，不搬码**（§4.14）。
- **libpq 源码**（`fe-connect.c`/`fe-protocol3.c`）：协议状态机与错误字段跳过的权威实现思路——**只借鉴行为**。
- **本仓库 `internal/protocol/pgwire`**（241 行）：已落码的字节真相，**双列互证**（§3.3 表格右列）。

**三路一致性**：三路在「外层两形态」「长度含自身」「全部 int 大端」「String NUL 终止」「错误字段单 0x00 终止」「Startup 是唯一无类型报文」六点完全一致。**不一致点**：dissector 只认协议号 3.0（v3.1/3.2 读 Unknown）而规范已定义 3.1/3.2 —— 取舍按 §4.15「以规范为底线、以现网行为为准绳」：**线字节以规范为准（可发 3.1/3.2），断言通道以 dissector 实测为准（v3.1/3.2 走 frames hex）**。

**候选方案对比（§4.17）**：

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| **A 事件面扩展 + legacy 接线** | 保留现有事件驱动生成器（`layer_gen.go`），把 legacy planner 已验证的字节构造（扩展协议/COPY/复制/FunctionCall/认证族）逐 kind 迁成事件 kind；`wire_fault` 与状态守卫补进 validator | 与已收官族同构（事件声明式回放）；legacy 1455 行字节逻辑已被 3 个测试文件覆盖，迁移风险低；零新框架机制 | 需要 1 次批量迁移（~20 个新 kind） | O(n) 流式不变；兼容性最好（新旧用例同层） | **采用** |
| B 整条 legacy planner 接线 | 把 `postgresql.Planner` 直接注册进 `ChainPlanner`，事件面转型到 `operations[]` | 一次性拿到全部能力（扩展协议/COPY/复制） | **事件语义与 `operations[]` 两套并存** → 同一层两种配置真相（违反 §1）；legacy planner 自产握手/挥手会与 tcp 层重复（`runFlow` 含 SYN/SYN-ACK/ACK） | 复杂度高、双头配置 | 不选（其字节逻辑作 A 的迁移素材） |
| C 生 hex 回放 | 事件内 `body_hex` 逃生口，整帧 hex 覆盖 | 最简单 | 字段不可结构化断言、动态面全失、类型字节二义无法验证 | 动态零分 | 仅作负例/特殊形逃生口（本契约要求 19 个正例反向印证） |
| D 只覆盖 Startup+Simple Query | 收缩到"连接冒烟"面 | 工作量最小 | 71 ID 体系下扩展协议/认证族/错误面/多流等多类全失；不能满足 §9.20 枚举全覆盖 | 表达力骤降 | 不选 |

### 10.6 裁定 PG-A：主层 / dialect 关系（**postgresql = 主协议，kingbase = dialect 变体**）

**判定依据（逐条实测，不问偏好——依赖链判定：标准→设计→代码→测试）**：

1. **注册面**：`postgresql` 是本仓库**唯一注册的层名**（`registry.go:644`）；`kingbase` **不在 registry**（`r.Register(LayerSchema{Name: "kingbase"})` 零命中），也**不在 `allowedProtocols`**（`protocols.go` 无 `"kingbase": true`），且在 `protocols_test.go:97` 的 `negativeOnly` 名单里 = **must remain rejected**。
2. **用例面**：`cases/kingbase.json` 的 15 例 `proto` **全部 = `postgresql`**（实测逐例）；跑法 = `CASE_PROTO=postgresql`。`CASE_PROTO=kingbase` 装载 0 例。
3. **端口面**：dialect 差异由 `dialectFieldContract`（`registry.go:1886-1890`）实现 = **改父层契约值的常量**，不是新层（设计 §1.3「变体改父层契约值」已定案）。
4. **代码面**：`internal/protocol/kingbase` **包不存在**；`types.go` 无 `KingBaseConfig`；`generator.go` 无 `FlowMeta.KingBase`；`main.go` 无 kingbase 空导入（`coverage_gate.py:2611-2629` 的七条"零残留"检查逐条在案）。
5. **测试面**：`postgresql_kingbase_test.go` 10 个测试同时覆盖两层语义（`TestPostgresqlLayerSchemaAndFieldContract` / `...EffectiveFieldContractDialect` / `...DialectPortDrivesTcpLayer` 等），即测试面认的是**同一层的两个 dialect 值**。

**裁定**：**postgresql 是主协议（#82），kingbase 是其 dialect 变体（#35 已收官）**。两者共用同一层、同一生成器、同一 validator、同一字节模板；差异仅在 `dialect` 值 → 契约端口（5432/54321）+ `wire_profile` 登记名。**本契约的全部新增能力（扩展协议、认证族、错误面）自动惠及两个 dialect**，无需分叉文档。反向声明：**不存在**"kingbase 独立层"的合法形态，任何 `{"kingbase": {}}` 层按 unknown layer 拒绝（`validate_layers.go:918` 实测行号，`layers: unknown layer %q (position %d)`，漂移时以字面 grep 为准）。

**残留洞（如实登记）**：`CheckProtoFlat`（`strategy_convert.go:8347`（`func CheckProtoFlat`：通用五键检查 + 其后 presence 分支，`grep -c "no longer accepts a top-level"` 32 条，含 ftp/rawWrap 通用门）**无 `postgresql` 条目**——即顶层 `{"postgresql": {...}}` 子映射与 `layers` 并存时**不判死**（其余 31 个协议都有各自条目）。按 kingbase 记忆的裁定（「判死补门方案先问'这个身份还准入吗'；config 级 unknown-key 白名单缺失是框架缺口，禁加单键黑名单分支」）→ 本项**立项 G-PG-6**（等框架级 unknown-key 白名单），**不加单协议分支**。

---

## 11. P2 D-POSTGRESQL-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 体裁：文件清单 / 接口签名 / 数据结构 / 主流程 / 错误分支 / 性能边界 / 冲突点 / 回滚。**依赖建模沿 §10.6 裁定 PG-A**；内层密码学面一律 opaque（§10 铁律）。

### 11.1 文件清单（P4 动作，**本轨道不执行**）

| 文件 | 动作 | 职责 |
|---|---|---|
| `internal/core/types.go:6438-6459`（`PostgreSQLEvent`） | **扩展** | 新增事件 kind 所需字段（见 §11.3 数据结构）；**删除**死字段 `Profile`/`Result`（§2.3） |
| `internal/protocol/pgwire/pgwire.go` | **扩展**（保持纯字节、无 core 依赖） | 新增：`Parse`/`Bind`/`Describe`/`Execute`/`Sync`/`Flush`/`Close` + `ParseComplete`/`BindComplete`/`CloseComplete`/`NoData`/`PortalSuspended`/`ParameterDescription` + `NoticeResponse`/`NotificationResponse`/`EmptyQueryResponse`/`FunctionCallResponse` + `NegotiateProtocolVersion` + `CancelRequest`/`SSLRequest`/`GSSENCRequest` + 变长 `BackendKeyData(pid int32, secret []byte)` |
| `internal/protocol/postgresql/layer_gen.go:117-177` | **扩展** | `buildEventPayload` switch 增 ~20 个 kind 分支；`paramIdx` 逻辑保留 |
| `internal/protocol/postgresql/validate.go` | **扩展** | ① 状态机补守卫（§4.1 的 Ready→Busy→Ready 全转移 + Closed 后拒任何 c2s）；② 新 kind 的必填字段校验（`parse` 需 `sql`、`bind` 需已存在 stmt 等）；③ `wire_fault` 若扩 kind 则同步锚词表 |
| `internal/core/layers/registry.go:644-660` | **扩展** | `Fields` 增键（如 `protocol_version`/`auth_method` 若从事件面提升为层面）——**只在确有必要时**；默认保持 5 键，新能力全部走 `events[]` |
| `internal/core/layers/chain_planner_translate.go:2009-2036` | **不变**（已含 JSON 往返解码，新事件字段自动搬运） | — |
| `internal/protocol/postgresql/planner.go`（1455 行） | **裁定去向**（见 §11.7 冲突点） | 迁完后删除或转为 `_test.go`-only 回归资产 |
| `tools/coverage_gate.py` | **扩展** | `check_postgresql`（当前只有 `check_kingbase`，`:2597`）——新增本契约 71 ID 的反查块；`check_kingbase` **保持**（#35 已收官，不改口径） |

### 11.2 接口签名（示意，P4 落码钉死）

```go
// pgwire（纯字节层，无 core 依赖）
func StartupMessage(protocolVersion int32, params map[string]string) []byte       // 已有
func TypedMessage(typeByte byte, payload []byte) []byte                            // 已有
func AuthRequest(authCode int32) []byte                                            // 已有
func PasswordMessage(password string) []byte                                       // 已有
func BackendKeyData(pid int32, secret []byte) []byte                               // 改签名（变长）
func ParameterStatus(name, value string) []byte                                    // 已有
func ReadyForQuery(status byte) []byte                                             // 已有
func QueryMessage(sql string) []byte                                               // 已有
func RowDescription(fields []FieldDesc) []byte                                     // 改签名（列可配置）
func DataRow(columns [][]byte) []byte                                              // 改签名（行可配置，nil = NULL）
func CommandComplete(tag string) []byte                                            // 已有
func ErrorResponse(fields []ErrorField) []byte                                     // 改签名（字段可配置）
func NoticeResponse(fields []ErrorField) []byte                                    // 新增
func NotificationResponse(pid int32, channel, payload string) []byte               // 新增
func EmptyQueryResponse() []byte                                                   // 新增
func NoData() []byte                                                               // 新增
func PortalSuspended() []byte                                                      // 新增
func ParameterDescription(oids []int32) []byte                                     // 新增
func FunctionCallResponse(value []byte) []byte                                     // 新增
func Parse(stmt, sql string, paramOIDs []int32) []byte                             // 新增
func Bind(portal, stmt string, formats []int16, values [][]byte, resultFormats []int16) []byte // 新增
func Describe(mode byte, name string) []byte                                       // 新增
func Execute(portal string, maxRows int32) []byte                                  // 新增
func Sync() []byte; func Flush() []byte; func Close(mode byte, name string) []byte // 新增
func ParseComplete() []byte; func BindComplete() []byte; func CloseComplete() []byte // 新增
func NegotiateProtocolVersion(newestMinor int32, unrecognized []string) []byte     // 新增
func SSLRequest() []byte; func CancelRequest(pid int32, secret []byte) []byte; func GSSENCRequest() []byte // 新增
```

### 11.3 数据结构（现状 + 扩展）

现状（`types.go:6438-6472`）：`PostgreSQLEvent{Kind, Direction, Profile†, User, Database, Result†, SQL, Tag, Authtype *int32, Name, Value, PID, Secret}`（† = 死字段，P4 删）；`PostgreSQLSession{SrcPort uint16, Events []PostgreSQLEvent}`；`PostgreSQLConfig{Dialect, WireProfile, Events, Sessions, WireFault json.RawMessage, ProtocolVersion, StartupParams, AuthMethod, Username, Password, MD5Salt, Operations, Pipeline, RowCount, ColumnTypes, NotificationPayload, WALDataSize, EmitHandshake, EmitTeardown}`。

**扩展方向（P4 定稿）**：新增事件字段全部**可选且 omitempty**，保证存量 16 例 JSON 不变即可继续工作；`Profile`/`Result` 删除时 **JSON 解码用 `DisallowUnknownFields` 会在存量配置上硬失败** ——因此 P4 必须**同批改写存量 16 例**（删 `profile`/`result` 键），否则出现"配置能建但执行报 unknown field"的新假象。**这是本契约最紧的时序约束**（P4 第 1 步）。

### 11.4 主流程

```text
strategy config(layers) 
  → ValidateLayers（未知层/未知字段 V9/层链完整性）
  → ChainPlanner.ValidateSpec（FieldContract 端口契约 + carrier 校验 + validatePostgresqlConfig 状态机/kind/方向/profile/wire_fault）
  → translateTerminalConfig（completedConfig + JSON 往返 → spec.PostgreSQL）
  → worker 逐流：resolveLayerTuple（动态）→ ChainPlanner.Generate
  → PostgreSQLGenerator.Generate（逐 session → 逐 event → buildEventPayload → EmitMsg{Up, Bytes, SrcPort}）
  → tcp 层（握手/分段/seq/挥手 + 多连接）→ ip 层 → 输出（pcap / port_group）
```

### 11.5 错误分支（§5.2）

三档：①**链级**（`ValidateLayers`/`ChainPlanner.ValidateSpec`）——未知层、`unknown field`、carrier 非 tcp、端口 ≠ 契约端口、presence 混用；②**配置级**（`validatePostgresqlConfig`）——dialect/wire_profile/kind/direction/状态机/sql 非空/wire_fault；③**生成期**（`buildEventPayload` 的 `event %q has no builder`——**理论不可达**，因为 kind 已由 ② 白名单化；若到达即为实现 bug）。全部经 `spec.ValidationErrors` / `error` 传播为 **task error**，**零假成功**。

### 11.6 性能边界（§6.1–6.8 摘要，详见本契约 §6）

单 flow 常驻内存 O(1)；无锁无共享；逐事件流式；速率归框架 pacer。**不新增任何按流缓存**。

### 11.7 与现有逻辑的冲突点（§8.7）

1. **legacy planner 的双头风险（最高优先）**：`internal/protocol/postgresql/planner.go`（1455 行）**未被任何非测试代码引用**（实测：全仓库非测试命中仅 `main.go:131` 空白导入）。它同时定义了 `PostgreSQLConfig.Operations`/`AuthMethod`/`ProtocolVersion`/`EmitHandshake`/`EmitTeardown` 等字段的语义——**这些字段今天在链路径上完全不被消费**（`layer_gen.go` 只读 `Events`/`Sessions`/`Dialect`/`WireProfile`）。**裁定（§10.5 方案 A）**：不接线 legacy planner；其字节逻辑按 kind 迁入 `pgwire`；迁移完成后 `planner.go` 与 `Operations`/`AuthMethod` 等字段一并**删除**（或整包转为 `_test.go` 回归资产）。**不许两套真相并存**。
2. **`protocol_version` 字段的静默无效**：`PostgreSQLConfig.ProtocolVersion` 存在，但生成器恒用 `pgwire.ProtocolV3` 常量（`layer_gen.go:127`）→ 配上不报错也不生效。同 `EmitHandshake`/`EmitTeardown`（链路径的握手/挥手由 tcp 层管，这两个开关无人读）。P4 处置：删除或接线，二选一，**不许留着当"看起来能配"**。
3. **事件内死字段**：`profile`（15/16 例，§2.3）/`result`（6 例 8 事件）——P4 必须同批删键（§11.3 时序约束）。
4. **`CheckProtoFlat` 无分支**：顶层 `postgresql` 子映射不判死（§10.6 残留洞）→ G-PG-6，等框架级白名单。
5. **`coverage_gate.py` 无 `check_postgresql`**：现只有 `check_kingbase`（`:2597`，分发表 `:3652` 键为 `"kingbase"`）。P4 新增本契约反查块；#35 的口径**不改**（已收官）。

### 11.8 回滚方式（§8.8）

按提交序 `git revert`：扩展类提交（pgwire / layer_gen / validate / types）可逐提交回退；**存量 16 例改写提交是唯一的"数据面"提交**——回退它必须与字段删除提交**同批回退**（否则 `DisallowUnknownFields` 与用例配置失配）。registry/schemagen 生成文件随提交对齐（本设计**不新增层**、层数 126 不变，但若 registry `Fields` 增键则必须重跑 `schemagen`，`TestLayersGeneratedMatchesRegistry` 会红）。

---

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

> 证据三选一（§15.2）：文档章节 / 代码行 / 用例号。写不出 = 缺口立项，不许空着。§1/§3/§12 三行按 §15.3 强制展开（§12.1/§12.3/§12.12）。

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：postgresql.json **71 例**中 69 例顶层仅 `layers`、1 例合法 `group_id`、#65 为故意 `layers` + 顶层 `postgresql` 双键 presence 负例；地址/端口/业务分层，正例顶层游离键为 0 | 本契约 §2.1 + §12.1；postgresql.json 71 例机读对账，kingbase 15 例另作 dialect 存量审计 |
| §2 策略/任务 | 策略 = 单 postgresql 流量模板，自带 `flow_control`（flows/bps/time）；任务 = 多策略合跑 + 总量封顶；框架语义未动（`postgresql` 不在 worker/task 特判名单） | `internal/core/worker.go:307-316`；本契约 §2.1 |
| §3 五件套 | 见 §12.3 强制展开：会话表 / 事务序列 / 关联关系（含 CancelRequest 的诚实边界）/ 插入位置 / 时间线；**有长连接载体（单 TCP 承载全部事务），不豁免** | 本契约 §12.3 + §10.4；用例 #1/#27/#45 |
| §4 查规范 | PostgreSQL 官方文档 Ch.54（§54.2/§54.3/§54.4/§54.6/§54.7/§54.8）；RFC 7677（SCRAM-SHA-256）；RFC 9293/8200（TCP/IPv6 载体）；三路对照 §10.5；tshark `pgsql.*` **56** 字段实测 + 9 组 distractor 探针实测；P1 矩阵 8 行 + 三子表（§10.1–§10.3）+ 候选方案对比（§10.5） | 本契约 §3/§10 |
| §5 依赖与错误 | 依赖 = `DependsOn ["tcp"]` 单值（`registry.go:644`），无 `TransportOn`/`OptionalOn`/`InnerRequired`；端口契约 `FieldContract{"tcp.dst_port":"5432"}` + dialect 覆盖 54321（`registry.go:649` + `1886-1890`；`chain_planner.go:554-594`）；`wire_fault` 2 有效 kind + 4 类非法形（`validate.go:86-124`：`checkPostgreSqlWireFault`）；失败全部传 task error（零假成功） | 本契约 §5/§7 + §11.5 |
| §6 性能 | 见本契约 §6「性能设计与验收」（6.1–6.8 要素）：逐事件流式、单 flow O(1) 内存、无锁无共享、paramIdx 为唯一可变状态；pcap/NIC 双路验收（NIC = `enp135s0f0np0`）；吞吐数字标「待 P4 基准」（§6.5 不写承诺） | 本契约 §6 |
| §7 三份文档 | `82-postgresql-design.md` v1.0.1 + `82-postgresql-testcase.md` v1.0.1（per-protocol 草稿层，§7.4；append 进 CODE_DESIGN.md/TEST_CASES.md 的条目为唯一权威文本）+ D-POSTGRESQL-1（本契约 §11，门1 获批 = 定稿）+ T-POSTGRESQL（testcase §2）+ generated schema（本设计**不新增层**，层数 126 不变；若 registry Fields 增键则重跑） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 实现；门1 获批 = D-POSTGRESQL-1 定稿 = 开工门（§8.9） | 提交序 |
| §9 测试三源 | 三源 = PostgreSQL 官方文档条款（§3 逐表列节号）+ D-POSTGRESQL-1（§11）+ 已确认现网行为（**未到抓包级 → G-PG-4**，不冒充第三源）；71 ID（51 正 + 20 负）逐项回指；存量 16 例审计去向 testcase §8 | `testcase.md` §2/§5/§6/§8/§9 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 `/tmp/pipe/82-postgresql/p123-report.md` §3）+ 收官隔离复审 + 修轮；红先绿后 | 报告 §3 |
| §11 白话 | 汇报首句先行白话结论 | 报告 §0 |
| §12 动态清单 | 见 §12.12 强制展开：四元组 = `ip`/`tcp` 层（五策略全支持，allowlist `layer_dyn.go:17-21`；`postgresql` **不在** allowlist → 业务字段对象必拒）；业务字段逐个列开/不开 + 理由；序号算法实读行号（`layer_dyn.go:770` `resolveLayerTuple`；`tuple_generator.go:26/292/300`；`worker.go:307-316`） | 本契约 §12.12 |
| §13 schema 派生 | `postgresql` 已在 `registry.go:644-660` 注册（层数 **127** 已含，**不新增层**）；`allowedProtocols["postgresql"]=true`（`protocols.go:51`）；`main.go:517` 已注册 ChainPlanner；**若 P4 改 registry `Fields` 必须重跑 schemagen**（§13.18/13.19）；struct 标签字面量锁定（§13.13） | 本契约 §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `pgsql.*`（56 字段）+ frames hex 双通道 → 先跑后钉（§9.31/§14.20）；pcap 落 `/tmp/mcp-pcaps/postgresql/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-26）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 纯净 |
|---|---:|---|---|---|
| `cases/postgresql.json` | 71 | `{layers}` ×69 + `{layers,group_id}` ×1 + `{layers,postgresql}` ×1（#65 presence） | 正例 `[ip,tcp,postgresql]`；负例含 udp/顶层 presence 等故意形 | ✅ 20/20 只有 `{expect_error,error_contains}` |
| `cases/kingbase.json` | 15 | `{layers}` ×15 | `[ip,tcp,postgresql]` ×14 + `[ip,udp,postgresql]` ×1（`kingbase_neg_udp`，刻意坏配置） | ✅ 6/6 只有 `{expect_error,error_contains}` |

**旧键去向表（§15.3 要求"每个键写去向"，本协议实况是"旧键计数 = 0"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` | **0** | 已在 `layers[i].ip.src`（无需迁移） |
| `dst_ip` | **0** | 已在 `layers[i].ip.dst` |
| `src_port` | **0** | 已在 `layers[i].tcp.src_port` |
| `dst_port` | **0** | 由 FieldContract 补齐（5432/54321），**存量刻意不写**（§2.1 注） |
| `count` | **0** | 走 `flow_control`（存量均未写，缺省 flows=1） |
| 顶层 `postgresql` 子映射 | **1（仅负例 #65）** | 正例已清理；#65 按 presence-negative 契约故意保留，用于登记顶层白名单缺口 G-PG-6（不可计入正例迁移残留） |
| 事件内 `profile` / `result`（死字段） | `profile` 15 例 / `result` 6 例 8 事件 | **P4 删键**（§1.12；非顶层键，不属 §1 白名单面，但同属"配上不生效"） |

**结论**：本协议**没有** §1 门的"迁移"工作量，只有"守住"工作量——P4 的 §1 检查 = ①新增 48 例全部纯 layers 形；②收官自查行「非负例顶层键 = 0」（预期 0，因存量已 0）。

**目标形状 spec_json 样例（纯 layers，顶层仅 `layers` + `flow_control`）**：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.82", "dst": "198.51.100.82"}},
    {"tcp": {"src_port": 45082}},
    {"postgresql": {
      "dialect": "postgresql",
      "wire_profile": "postgresql_v3",
      "events": [
        {"kind": "startup", "user": "bench", "database": "bench"},
        {"kind": "auth_request", "direction": "s2c", "authtype": 5},
        {"kind": "password", "direction": "c2s"},
        {"kind": "auth_request", "direction": "s2c", "authtype": 0},
        {"kind": "parameter_status", "direction": "s2c", "name": "server_version", "value": "18.0"},
        {"kind": "backend_key_data", "direction": "s2c", "pid": 4242, "secret": 991199},
        {"kind": "ready", "direction": "s2c"},
        {"kind": "query", "sql": "SELECT 1"},
        {"kind": "row_description", "direction": "s2c"},
        {"kind": "data_row", "direction": "s2c"},
        {"kind": "command_complete", "direction": "s2c", "tag": "SELECT 1"},
        {"kind": "ready", "direction": "s2c"},
        {"kind": "terminate"}
      ]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

**presence 判死形状说明（本协议不适用但必须点名）**：`{"layers":[…],"postgresql":{}}`（层链 + 顶层空子映射并存）是其他协议的**判死负例形状**；本协议因 `CheckProtoFlat`（`strategy_convert.go:8347` 起，presence 分支 32 条，无 `postgresql` 条目（§10.6 残留洞 G-PG-6），该形**今日不会被拒**——因此本契约**不建**该负例（建了会真绿 = 假通过），改为**登记缺口**。层内第 6 键判死（#59 走 `complete.go:293` unknown-field）与顶层游离键（1.11–1.13 通用门，P4 实测）是两条不同机制，不混写。

### 12.3 §3 强制展开：五件套

**会话表**：

| 会话 | 四元组 | 生命周期 | 用例 |
|---|---|---|---|
| `s1`（单会话基线） | `ip.src/dst` + `tcp.45082→5432` | SYN/SYN-ACK/ACK → Startup → R/p 认证序列 → S*、K、Z → Q → T/D/C → Z → X → FIN-ACK 四way | #1（全序）/#27（查询面） |
| `s2`（多会话展开） | 第二 src_port（`sessions[].src_port`） | 与 s1 完全独立的握手→认证→查询→挥手；**整块回放不交错**（术语表「多会话展开」） | #45 |
| `s3`（并发多流） | `flows=3` 三条独立四元组 | 框架逐流并行；断言每题各自独立 | #46 |
| `s4`（取消连接，B′） | 独立四元组 → 5432 | 建连 → 一帧 CancelRequest → 服务端**无响应** → 挥手 | G-PG-3 |

**事务序列（单事务四件事 §3.4–3.7）**：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| `t1` 建连+启动 | TCP 握手完成（`tcp.handshake` 默认 true） | c2s StartupMessage | s2c `R`（认证质询或 Ok） | 服务端关连接（无协议内错误报文；A′） |
| `t2` 认证 | `t1` 已发 Startup | 按 `R` 子类型回应：0→无需回应；3→`p` 明文；5→`p` md5；10→`p` SASLInitialResponse，11↔`p`，12 结束 | s2c `R`(0) → `S`* → `K` → `Z` | 认证失败：服务端发 `E` + 关连接（A′，今日无此事件面） |
| `t3` Simple Query | `Z` 已收（`st.ready=true`） | c2s `Q` + SQL | s2c `T` + `D`* + `C` → `Z` | 查询错：`E` → `Z`（`query_error` kind 已实现） |
| `t4` Extended Query | `Z` 已收 | c2s `P`→`B`→`D`→`E`→`S` | `1`→`2`→`T`/`n`/`t`→`D`*/`C`/`s`→`Z` | 任一阶段错：跳至 `S`，发 `E`+`Z`（A′） |
| `t5` 终止 | 任意 Ready 态 | c2s `X` | 无响应 + TCP 挥手（`tcp.termination` 默认 true） | 非正常结束：RST（`tcp.rst=true`，A′） |

**关联关系（§3.8–3.10）**：见 §10.4 专节——**主连接内无派生流**（诚实声明）；唯一跨连接关系 = CancelRequest（今日不实现，B′ G-PG-3）。因此 `driven_by` 今日**不适用**，且**不许**用"同一模板连续重复发射"冒充编排（§3.13）。

**插入位置**：终结层（`CategoryTerminal`，`DependsOn ["tcp"]`）——PG 报文直接落 TCP payload；链上**无中间层**（无 http/tls 包装面）。

**时间线**：**单会话严格顺序**（t1→t2→t3/t4→t5，每步依赖前一步结果，`validate.go:126-144`（`validatePostgreSqlEvent` + `c2sNeedsPgReady` 三 kind）已对 c2s 状态事件强制）；**多会话整块顺序**（s1 全流程跑完再跑 s2，术语表「多会话展开」）；**多流并发**（`flows=N`，跨流不假设全局包序，只断言流内序与各流独立）。无"长传输分片让位"面（无数据流）；控制可中插动作 = 无（PostgreSQL 无 ABOR/STAT 类）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组（`ip`/`tcp` 层，五策略全开）**：

| 字段 | 住处 | 开策略 | 依据 |
|---|---|---|---|
| `src`（src_ip） | `ip` 层 | fixed/inc/rand/list/pattern 全开 | allowlist `layer_dyn.go:18`（`"ip": {"src","dst","ttl"}`） |
| `dst`（dst_ip） | `ip` 层 | 同上 | 同上 |
| `src_port` | `tcp` 层 | 同上 + 未写动态保底 `12345+i`（`worker.go:307-308`，`DefaultSrcPort = 12345`，`strategy_convert.go:49`） | allowlist `layer_dyn.go:19` |
| `dst_port` | `tcp` 层 | 同上，**但域校验强制 = 契约端口**（5432/54321，`chain_planner.go:585-591`）——动态 dst_port 与端口契约冲突 → **实际不可用**，如实声明（不是"不开"，是"开了会被拒"） | 同上 + 端口契约 |

**业务字段（`postgresql` 层，逐个列开/不开 + 理由）**：

| 字段 | 开 | 理由 |
|---|---|---|
| `dialect` | ❌ 关 | 变体选择器决定契约端口，逐流变会破坏端口契约（同 h323 `direction` 类"结构选择器"判例） |
| `wire_profile` | ❌ 关 | 版本/兼容模式选择器，逐流变无业务意义 |
| `events[]` 整块 | ❌ 关 | 事件序列是会话剧本；逐流变等价于"多套剧本"，应由多策略表达（§2.2 策略=单一模板） |
| `sessions[]` 整块 | ❌ 关 | 同上；多会话的内部展开已由 `sessions[].src_port` 承担 |
| 事件内 `user`/`database` | ❌ 关（今天） | 逐流变用户名是**可想象的**业务需求（多用户压测），但会引入 per-flow 事件重写路径 → 列 A′ 补例候选（需先登记 allowlist；`postgresql` **不在** `layerDynAllowlist`，对象必拒） |
| 事件内 `sql` | ❌ 关（今天） | 同上（多 SQL 模板逐流变）；A′ 候选 |
| 事件内 `pid`/`secret` | ❌ 关 | 后端键是服务端指派值，逐流伪造无意义（且与 CancelRequest 关联语义耦合） |
| 事件内 `authtype`/`name`/`value`/`tag` | ❌ 关 | 会话内结构性取值，逐流变破坏会话自洽 |
| `wire_fault` | ❌ 关 | 负例唯一注入口，非业务字段 |

**序号算法代码位置（实读，不编行号——§5.7）**：

- 层内字段动态解析入口：`internal/core/layer_dyn.go:78` `parseLayerDyn`（从 layers 数组抽取对象值）→ `:369` `checkDynShape`（形状校验）→ `:770` `resolveLayerTuple(spec, i)`（**逐流解析并覆写**，`worker.go:316` 与 `:774` 两处调用）。
- 值算法：`internal/core/tuple_generator.go:26` `TupleGenerator.Next(index)`；inc 回绕 `:164` `genIP6Inc` / `:239` `ipToU32`；rand 可复现 `:181` `genIP6Rand`（seed+index）；端口 `:194` `genPort`；单值解析 `:290` `ResolveIPValue` / `:300` `ResolvePortValue` / `:310` `ResolveStringValue`。
- 保底自增：`internal/core/worker.go:307-308`（`flowCount > 1 && !spec.HasExplicitSrcPort` → `DefaultSrcPort + i`）。
- allowlist 白名单：`internal/core/layer_dyn.go:17-21`（`ip`/`tcp`/`udp`/`eth` + 各协议块）——**`postgresql` 无块**，即层内任何对象值 → `does not support dynamic`。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- **①层链+顶层空子映射并存**：本协议**不建**（`CheckProtoFlat` 无 `postgresql` 分支，建了会真绿 = 假通过）→ 缺口 G-PG-6 登记，不冒充覆盖。
- **②白名单外游离键判死（1.11–1.13）**：`{"layers":[…],"src_mac":"02:00:00:00:00:01"}`（或顶层 `ttl`）→ 必须拒（框架级白名单兜底——**P4 须实测该形今日是否真被拒**，若不拒则并入 G-PG-6）。层内第 6 键判死另由 #59 覆盖（`complete.go:293` unknown-field，两条机制不混）。
- **③一切负例 `expect_error` 带错误锚词**：15 个负例逐条锚词见 testcase §4。
- **④收官自查行**：「非负例顶层键 = 0」——预期 0（存量已 0）。
- **载体负例**：链夹 `udp`（`[ip,udp,postgresql]`）判死，锚词 `tcp`（`chain_planner.go:572-575` 实测；存量 `kingbase_neg_udp` 即此形）。

---

## 13. P3 对接清单（T-POSTGRESQL 草稿输入；正文落 testcase 文件）

- §3.15 三项：见 testcase §6.1（①同连接多轮操作→#1/#27/#45 + A′ 补例「同连接多轮查询」；②非正常结束→#32/#39 + 负例面 + A′「服务端 RST/认证失败断连」；③长保活→#45 + A′（同连接多轮，协议层无 keepalive 语义已显式声明不适用））。
- A′/B′ 两分类表：见 testcase §6.2（A′ = 引擎可构建需接线，七类要求面逐项列落点；B′ = 引擎结构缺口 G-PG-2/3，进设计 §14）。
- 9.52 对账两行：见 testcase §5.2（**规范逻辑点总数 = 140** = 八项 8 行 + 矩阵 105 格 + 变体 27 行；**用例覆盖数 = 85**；**不适用 = 55** 格；85 + 55 = 140 ✓；清单出处 = 规范/官方文档反推）。
- 3.14 豁免边界审计：见 testcase §6.3（**有长连接载体 → `sessions[]` 不豁免**；多流并发 #45/#46/#47 + 单包多载荷 #21/#30/#31 与"单段多报文"扩展协议族各至少一例）。
- 三源回指行：见 testcase §5.1（第三源"已确认现网行为"当前 = 未确认级，挂 G-PG-4）。

---

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 立项号 | 缺口 | 确认方式（三选一：查文档 / 抓包 / 问人） | 去向 |
|---|---|---|---|
| **G-PG-1** | 扩展协议事件面未接线：`P`/`B`/`D`/`E`/`S`/`H`/`C` + 完成指示 `1`/`2`/`3` + `n`/`t`/`s`/`V` 在生成器**零 kind**（legacy planner 已实现字节，未事件化） | 读 `planner.go:554-719`（`runOperation` :529，switch :554，query 首例 :555/describe/execute/sync/close/flush/copy-from/copy-to/listen/unlisten/replication-identify/replication-start/terminate/error/notice/function-call）+ `layer_gen.go:117-177`（`buildEventPayload` 14 kind switch）对照 | **A′**（引擎可构建，P4 迁移）；用例 #35–#39 已建 |
| **G-PG-2** | 版本面：①`protocol_version` 字段生成器不读（恒 3.0）②`NegotiateProtocolVersion`（`v`）无 builder ③`BackendKeyData` secret 恒 4 字节（规范允许 4–256）④v3.2 的 256-bit cancel key 无支持 | 查 PostgreSQL 18 文档 §54.7（BackendKeyData / CancelRequest / NegotiateProtocolVersion 三条原文）+ 实测 `pgwire.go:128` | **B′**→D-POSTGRESQL-1「明确不解决 + 迁入计划」；用例 #23 钉现状 |
| **G-PG-3** | CancelRequest 关联语义：第二条独立连接（无响应字节），`driven_by{session,transaction,field}` 三件套**无法套用**（不属于任何会话/事务） | 查文档 §54.2.6 + §54.7 CancelRequest 原文；裁定方式 = P4 与框架共同定（扩展 driven_by / 独立 `cancel_of` 字段 / 明确不支持） | **B′**（三选一收口后写结论，不留白） |
| **G-PG-4** | 现网行为未到抓包级：libpq/pgx/JDBC/KingBaseES 的真实 Startup 参数面与认证序列只有官方文档描述，无本机抓包证据（§10.5 ②） | **抓包**：本机回环起 PostgreSQL（或容器）+ `psql`/`pgx` 连接，tcpdump 抓 5432 核对参数面与认证序 | P4 前置确认项，不挡开工；确认前相关条目按 §5.5 标"待确认" |
| **G-PG-5** | 事件内死字段 `profile`（15/16 例）/`result`（6 例 8 事件）：配上不报错也不生效；删字段会因 `DisallowUnknownFields` 硬失败，必须与存量改写**同批** | 读 `layer_gen.go`（零 `.Profile`/`.Result` 命中）+ 存量 16 例机读 | **P4 第 1 步必办**（§11.3 时序约束）；用例 #59 守未知键门 + 存量 16 例删键改写同批 |
| **G-PG-6** | 顶层白名单洞：`CheckProtoFlat`（:8347 起）presence 分支无 `postgresql` 条目 → 顶层 `postgresql` 子映射不判死；顶层游离键（`src_mac` 等五键外）是否被框架级白名单拦，P4 须实测 | 读 `strategy_convert.go:8347` 起分支表（grep `no longer accepts a top-level` 32 条，无 postgresql）+ 实测提交该形 | **框架级缺口**（禁加单协议黑名单分支——kingbase 记忆裁定）；上报主线程；用例侧**不建**该负例（避免假通过） |
| **G-PG-7** | 生成器恒值面：`RowDescription` 恒 1 列 `col1`、`DataRow` 恒 1 行值 `42`、`ErrorResponse` 恒 3 字段、`ReadyForQuery` 恒 `'I'`、`PasswordMessage` 恒 `testpass`、`authtype` 缺省 3 而非 0 —— 均无配置面 | 读 `pgwire.go:148-204` + `layer_gen.go:129-176` | **A′**（legacy planner 已有 `PGField`（`types.go:6711-6719`）/`ColumnTypes`/`RowCount`（`PostgreSQLConfig` 内，`types.go:6472-6591`）/`PGErrorField`（`types.go:6703-6706`）实现，可迁移）；用例 #21/#22 钉现状，扩展面列 A′ |
| **G-PG-8** | 状态机守卫不全（负例 #54/#55 已建，#64 随守卫同批）：仅 c2s `query`/`simple_query`/`password` before-ready 被拒（`validate.go:126-144`：`validatePostgreSqlEvent` + `c2sNeedsPgReady` 三 kind）；Terminate 后继续发 query、认证未完成即发 query、扩展协议乱序等**无守卫** | 读 `validate.go:126-175` 全文（`validatePostgreSqlEvent` :126 + `c2sNeedsPgReady` :149 + `s2cMakesPgReady` :158 + `validPgKind` :167） | **A′**（P4 补守卫；已建 #54/#55，#64 随守卫同批） |

---

## 15. 修订记录

- v1.0.1（2026-09-26，P3 自重审 R2 修）：①testcase 侧计数口径勘误同步——testcase §2 表体系 **64 ID（48 正 + 16 负）**，设计 §9 摘要改为族分布口径并以表体为准；§12 门1 表的 §9 行 / §7 行（testcase 节号）同步。②§8 小节"1/16 例有 `decode_as`"→"9/16 例"（机读口径笔误，9 个正例带；仍为同层同 proto 的 kingbase 例）。③撤销一条误报：草稿曾记 `cases/postgresql.json` `frames[2]` Length 声明矛盾，公式复算证明无矛盾（typed `length = 4 + payload`，`4+10=14=0x0e` ✓），教训已记。
- v1.0.1（2026-09-27，主线程修轮）：在 v1.0.0 基础上——①§10.2/#12.3/§10.3/§14 全部 ID 重映射到 testcase §2 64-ID 权威（旧 43-ID 口径残留清零）；②死字段计数对齐机器普查（profile 15/16 例、result 6 例 8 事件）；③行号漂移修正（protocols.go:51、main.go:517、complete.go:293、CheckProtoFlat :8347（func 行，spnego 合并后复核））；④§9 分布计数修正（分段多流 6、负例配置面 4/状态机面 3 含 #64 A′）。
- v1.0.0（2026-09-26）：P1–P3 文档轨产物（车道 A）。建立 P1 八项规范矩阵（§10.1）+ 三子表（§10.2 报文×状态矩阵 21×5=105 格 / §10.3 数据形态变体 27 行 / §10.5 商业行为映射）+ 三路对照与候选方案对比（§10.5）+ 裁定 PG-A 主层/dialect 关系（§10.6）；门1 §1–§14 十四行表（§12，§1/§3/§12 强制展开）；D-POSTGRESQL-1 代码设计（§11，八要素）；性能设计与验收（§6）；缺口 8 项（§14）。**未修改任何 `.go`、未跑 suite、未启动服务器、未写共享文档/账本**。

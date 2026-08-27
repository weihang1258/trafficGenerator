# KingBase（人大金仓）数据库协议设计

> 版本：v1.1.0（改写为 postgresql 层 dialect 变体）  
> 日期：2026-08-20  
> 修订：2026-08-26（v1.1.0，见 §7 修订记录）  
> 状态：仅设计与用例契约。kingbase 现为 **postgresql 层的 dialect 变体**，复用 postgresql 的 PostgreSQL v3 wire（Startup/typed message/事件语义）；代码层面**独立 `kingbase` 层已撤销**，不再注册到 layer registry，而是作为 postgresql 层的 `dialect="kingbase"` 值（见 §1/§2/§4）。  
> 配套文件：`docs/protocol-designs/34-kingbase-testcase.md`、`trafficgen/test/protocol_pcap/cases/kingbase.json`

## 1. 范围、证据等级和 profile（档案）边界

KingBase（人大金仓）KingbaseES 数据库客户端通常通过 TCP 连接数据库服务，常见默认监听端口为 **54321**。KingbaseES 提供 PostgreSQL-compatible wire（兼容 PostgreSQL 的线协议）模式；公开且跨版本可稳定约束的是 TCP 载体、端口，以及 PostgreSQL v3 外层消息的类别、长度字段位置和会话事件语义。本版以 profile 区分 KingbaseES 版本/兼容模式，不把一个版本的私有细节推广到其他版本。

| 证据级别 | 本版可写内容 | 是否固定 KingBase 应用十六进制 |
|---|---|---|
| TCP/IP 外层 | TCP、默认目的端口 54321、四元组、IPv4/IPv6、握手/终止、方向 | 只断言 tshark（抓包解析器）传输字段 |
| PostgreSQL-compatible 外层 | Startup（启动消息，无 type 字节）、带 type 的 length（长度）消息、Authentication/Ready/Query/Error 的消息类别和顺序 | 只固定公开外层布局；不把 KingBase 私有参数当成常量 |
| KingBase profile | `kingbase_es_v8_pg_compatible` 等实现契约名 | profile 名不是线上字节，不直接写入 payload（载荷） |
| 未定稿私有 wire | 原生认证摘要、版本扩展、SQL 扩展、参数键值、错误字段细节、压缩/TLS | 不写固定 hex（十六进制）；实现前需版本化 PCAP（抓包文件）或官方字节证据 |

`kingbase_es_v8_pg_compatible` 是本版用例的契约名，不保证对应所有 KingbaseES 发行版或补丁。后续支持的版本必须增加独立 profile（例如 `kingbase_es_<version>_pg_compatible`），并独立给出证据；不能通过改写现有 profile 的字节来兼容。`kingbase_native_pending` 表示原生模式的待实现边界，未取得可复现证据前不得作为正例生成器。

本版**不宣称**以下内容已定稿：KingBase 具体版本的默认认证方法、密码摘要或 SCRAM（Salted Challenge Response Authentication Mechanism，加盐挑战响应认证机制）参数、私有认证消息字段、SQL 扩展 opcode（操作码）、扩展数据类型、错误码/字段、服务端参数键值、压缩、SSL/TLS、复制协议和真实服务端执行结果。即使这些内容在某个部署中存在，也必须由对应 profile 和 fixture（固定样本）承载。

不变式：

1. postgresql 层（`dialect=kingbase`）只能承载在 TCP 上；UDP、裸 IP、缺少 TCP 或不完整层链必须拒绝。`dialect=kingbase` **不是独立层**，而是 postgresql 层的变体值（target：`[ip, tcp, postgresql]` + `postgresql.dialect="kingbase"`）。
2. 默认 `dst_port=54321`（dialect=kingbase，对比 dialect=postgresql 默认 5432）；端口由 postgresql 层据 dialect 生成 FieldContract（→tcp.dst_port=54321），非标准端口不是隐式兼容入口，除非未来设计明确增加 profile 和显式开关。
3. `wire_profile` 决定版本/兼容模式（postgresql 层字段）；同一会话不能混用 PostgreSQL-compatible 与 native profile。
4. 一个 session（会话）由独立四元组标识；认证状态、请求序列和响应关联不得跨流混用。
5. TCP 三次握手、应用数据段和正常 FIN 终止由公共 TCP 层负责；应用事件不隐式增加未配置的 ACK 或服务端事件。
6. 应用 payload 超过 MSS（最大报文段长度）时可能被 TCP 分段；固定 frame offset（帧偏移）只适用于对应实际 segment，不代表 TCP stream（流）偏移。
7. planner（规划器）错误必须传播到 task（任务）错误终态，不能“完成但 0 包”。

## 2. 层链、端口和 profile

kingbase = **postgresql 层的 dialect 变体**，因此不写独立 `kingbase` 层，而是写 `[ip, tcp, postgresql]` + `postgresql.dialect="kingbase"`：

```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345}},{"postgresql":{"dialect":"kingbase"}}]}
```

postgresql 层（dialect=kingbase）默认配置：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345}},
    {"postgresql": {
        "dialect": "kingbase",
        "wire_profile": "kingbase_es_v8_pg_compatible",
        "events": []
    }}
  ]
}
```

- `src_ip`/`dst_ip` 归位到 ip 层 `src`/`dst`；`src_port` 归位到 tcp 层；`dst_port` **不写**——由 postgresql 层据 dialect 生成 FieldContract 写入（dialect=kingbase → 54321；dialect=postgresql → 5432）。
- 不再有顶层平铺 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`kingbase` 子块（G1）。
- `dialect` 是 postgresql 层的字段：`kingbase` 时按 KingBase 变体取默认端口 54321 与 KingBase profile；缺省 `postgresql`。

`wire_profile` 仍是选择编码模板的稳定名称（postgresql 层字段）：

| profile | 语义 | v1 状态 |
|---|---|---|
| `kingbase_es_v8_pg_compatible` | KingbaseES 某 v8 兼容 PostgreSQL v3 的外层契约 | 允许出现在设计正例；具体私有字段待 fixture |
| `postgresql_v3_compatible_reference` | 用于外层回归的 PostgreSQL v3 兼容参考 profile | 只作为显式参考，不表示 KingBase 版本 |
| `kingbase_native_pending` | KingBase 原生/私有模式 | 待实现；没有固定 payload |
| 其他名称 | 未登记版本或模式 | planner 拒绝，错误包含 `profile` |

`wire_profile` 与事件内 `profile` 分层：前者选择会话版本/兼容模式，后者选择事件类别的已登记模板（例如 `startup_v3`、`auth_profile_defined`、`query_simple_v3`）。事件 profile 不得覆盖会话 wire profile 的版本边界。

## 3. PostgreSQL-compatible 外层语义

本节是 postgresql 层（`dialect=kingbase` 时）的共享 wire 语义：kingbase 不另造 wire，直接复用 postgresql 的 PG v3 外层（Startup、typed message、事件序列）。以下类别与顺序在 `dialect=kingbase` 下同样成立；差异只在默认端口（54321）与 `wire_profile`。

### 3.1 Startup message（启动消息）

Startup 是唯一没有 1 字节 type tag（类型标签）的 PostgreSQL v3 外层消息：

```text
int32 length（包含自身 4 字节）
int32 protocol_version（v3.0 为 0x00030000；按网络字节序）
key NUL value NUL ... NUL
```

`length` 按实际编码后的字节数计算，参数列表以额外的 NUL 结束。参数名、值和是否需要 KingBase 私有参数由 profile 决定；本版不对 `user`、`database`、`application_name` 之外的部署参数作固定字节承诺，也不把某个数据库名或版本字符串写成规范常量。Startup 的线布局仅适用于 `*_pg_compatible` profile；`kingbase_native_pending` 不自动复用它。

### 3.2 Typed message（带类型消息）

除 Startup 外，PostgreSQL-compatible v3 消息为：

```text
1 byte type | int32 length（包含 length 字段，不包含 type） | payload
```

下列是本版只固定**外层**的类别：

| type | 语义 | 方向 | v1 约束 |
|---|---|---|---|
| `R` | Authentication request（认证请求） | s2c | 认证子类型/盐/机制由 auth profile 决定，不固定 |
| `p` | Authentication response（认证响应） | c2s | 摘要、密码和 SASL 字节由 auth profile 决定，不固定 |
| `Z` | Ready for query（准备查询） | s2c | status 语义按兼容外层解释；私有扩展待实现 |
| `Q` | Simple query（简单查询） | c2s | SQL 以 profile 编码；可观察 query 事件，不伪造扩展字段 |
| `E` | Error response（错误响应） | s2c | 字段标签、SQLSTATE、错误文本由版本/profile 决定 |
| `T`/`D`/`C` | Row description/Data row/Command completion | s2c | 查询成功结果外层按原子事件发送；本版不固定列元数据 |
| `X` | Terminate（终止请求） | c2s | 可作为会话结束事件；长度由编码器计算 |

`R`、`p` 的外层类别可以稳定断言，但不能从类别推导认证方法。`Z` 的“ready”语义可稳定断言，具体 status 和版本扩展必须从 profile 读取。`Q` 的 SQL 文本是用户输入，不应当被当作 KingBase 私有 wire 事实。`E` 只证明错误响应类别和非空可观察载荷，不固定真实服务端错误码。

### 3.3 会话状态事件

兼容 profile 的推荐事件顺序为：

```text
TCP handshake → Startup → Authentication request/response → Ready
→ Query → (T/Data/Command completion 或 Error) → Ready → Terminate → TCP FIN
```

`connect` 是传输层连接事件，不额外制造一个未知的 KingBase 应用头；其应用入口是显式 `startup` 事件。信任认证或服务端不发送某类认证往返的 profile 可以缩短认证事件，但必须在 profile 契约中显式声明，不能由 planner 猜测。

- 成功查询响应至少包含 `Row description`、`Data row`、`Command completion` 等兼容外层事件，并在下一次查询前发送 `ready`。
- 错误查询响应使用 `query_error`/`Error response` 外层事件；错误后是否保持会话由显式事件决定。
- Startup、Authentication、Ready、Query、Error 事件都各占一个应用 TCP payload 的默认原子段；MSS 分段时以实际包数为准并同步三方文档。
- 不模拟数据库执行：`SELECT 1` 等 SQL 只用于可观察请求文本，结果字段不是服务端真实性承诺。

## 4. 配置契约

用 postgresql 层 + `dialect="kingbase"`；不再有独立 `kingbase` 层/子块：

```json
{
  "layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"tcp": {"src_port": 12345}}, {"postgresql": {
    "dialect": "kingbase",
    "wire_profile": "kingbase_es_v8_pg_compatible",
    "events": [
      {"kind": "startup", "direction": "c2s", "profile": "startup_v3", "user": "test", "database": "test"},
      {"kind": "auth_request", "direction": "s2c", "profile": "auth_profile_defined"},
      {"kind": "auth_response", "direction": "c2s", "profile": "auth_profile_defined", "result": "success"},
      {"kind": "ready", "direction": "s2c", "profile": "ready_idle"},
      {"kind": "query", "direction": "c2s", "profile": "query_simple_v3", "sql": "SELECT 1"},
      {"kind": "row_description", "direction": "s2c", "profile": "row_description_outer"},
      {"kind": "data_row", "direction": "s2c", "profile": "data_row_outer"},
      {"kind": "command_complete", "direction": "s2c", "profile": "command_complete_outer", "tag": "SELECT 1"},
      {"kind": "ready", "direction": "s2c", "profile": "ready_idle"}
    ]
  }}]}
```

| 键 | 类型 | 默认/约束 | 语义 |
|---|---|---|---|
| `dialect` | string | `postgresql`；可改 `kingbase` | 内容/端口变体键；`kingbase` 时默认端口 54321 且 profile 需为 KingBase 兼容模板 |
| `wire_profile` | string | 必填；必须登记 | 版本/兼容模式选择；不直接编码到 wire |
| `events` | array | 可为空；按序 | 应用层语义事件 |
| `kind` | enum | 见 §3.3 | 事件类别；编码模板由 profile 选择 |
| `direction` | enum | `c2s`/`s2c` | 发送方向 |
| `profile` | string | 与 `wire_profile` 兼容 | 事件编码模板名；私有模板待实现 |
| `sql` | string | 仅 query | 用户 SQL 文本；按兼容 profile 编码 |
| `sessions` | array | 与 `events` 二选一 | 每个 session 独立四元组和状态 |
| `wire_fault` | object | 仅负例 | planner 边界故障注入，不代表合法线上帧 |

校验规则：

1. `layers` 必须含 postgresql 层（`dialect=kingbase`）且其承载层为 TCP；UDP/缺 TCP 拒绝。**kingbase 不再作为独立层注册**——若配置出现 `{"kingbase":{}}` 层，按未知/已撤销层拒绝（应改为 postgresql 层 + dialect=kingbase）。
2. 目的端口默认 54321（dialect=kingbase）；**领域校验强制 54321**——`dialect=kingbase` 下即使用户显式写 `tcp.dst_port` 为其他值（如 54322）也被拒绝（端口负例 `kingbase_neg_port` 验证）。依据：字段优先级只决定**合法值域内的默认值**（需求 §1.6），用户显式 > FieldContract 不覆盖领域合法性——超出合法值域由校验拒绝。
3. 未登记 `wire_profile` 或事件 profile 拒绝；不得回退到 PostgreSQL 或任意随机 payload。
4. Startup length 小于最小外层长度、声明长度超过实际编码长度或超出实现上限时拒绝；长度必须按编码字节计算，不按字符数。
5. 认证响应、Query、Terminate 等状态事件只能在 profile 允许的状态出现；未 Ready 即 Query 的配置拒绝。
6. `kingbase_native_pending` 不得使用 `*_pg_compatible` 事件模板，反之亦然。
7. 失败在 planner/validator（校验器）边界传播为 task error；不能输出空 PCAP 后报告成功。

## 5. 包数、偏移和场景映射

以下场景一律用 `[ip, tcp, postgresql]` + `postgresql.dialect="kingbase"` 表达；包数、偏移、锚点与 v1.0 一致（端口均为 dialect=kingbase 决定的 54321）。

小 payload、无额外 TCP option、每个应用事件一个 TCP 数据段时：

```text
packet_count = 3（SYN/SYN-ACK/ACK） + 应用事件数 + 4（FIN 终止）
```

IPv4 无 TCP option 时应用 payload 起点为 Ethernet 14 + IPv4 20 + TCP 20 = **offset 54**；IPv6 起点为 14 + 40 + 20 = **offset 74**。这些是实际 TCP segment 的帧偏移，不是跨分片的 stream offset。所有正例的 `frame` 只断言外层已知字节（type）或使用 `pgsql.*` 解码字段；不固定 KingBase 私有 auth、扩展和错误 payload。

| 场景 | JSON id | 应用事件数 | packet_count | 主要可观察锚点 |
|---|---|---:|---:|---|
| TCP connect | `kingbase_connect` | 0 | 7 | TCP 54321、握手、终止 |
| Startup | `kingbase_startup` | 1 | 8 | Startup message、TCP payload |
| Auth success | `kingbase_auth_success` | 4 | 11 | Authentication request/response、Ready |
| Query success | `kingbase_query_success` | 9 | 16 | Query、Row description/Data row/Command completion、Ready |
| Query error | `kingbase_query_error` | 7 | 14 | Query、Error response、Ready |
| IPv4 | `kingbase_ipv4` | 4 | 11 | IPv4、auth/ready 外层 |
| IPv6 | `kingbase_ipv6` | 4 | 11 | IPv6、auth/ready 外层 |
| Multi-session | `kingbase_multi_session` | 2×4 | 22 | 两个源端口、每流独立状态 |
| Startup length boundary | `kingbase_length_boundary` | 1 | 8 | 最小合法参数输入、非空 payload |
| UDP carrier negative | `kingbase_neg_udp` | — | — | 仅错误终态 |
| Port negative | `kingbase_neg_port` | — | — | 仅错误终态 |
| Profile negative | `kingbase_neg_profile` | — | — | 仅错误终态 |
| State negative | `kingbase_neg_state` | — | — | 仅错误终态 |
| Truncated negative | `kingbase_neg_truncated` | — | — | 仅错误终态 |
| Oversize negative | `kingbase_neg_oversize` | — | — | 仅错误终态 |

## 6. 实现完成定义与待实现边界

后续实现必须：

1. 注册 TCP→PostgreSQL（postgresql）终结层（`depends_on=[tcp]`，FieldContract→`tcp.dst_port`），并将 `dialect="kingbase"` 作为该层的变体字段（默认端口 54321）；层链校验拒绝 UDP/缺 TCP。**不再注册独立 `kingbase` 层**——旧 `kingbase` 层从 layer registry 移除/废弃，配置一律走 postgresql 层 + dialect=kingbase。
2. 将版本和兼容模式绑定到显式 profile；每个 profile 有官方规范或可复现 PCAP 依据。
3. 对 Startup/type+length 外层、R/p/Z/Q/E 类别分别写失败优先单测；长度按编码字节数回填并验证边界。
4. 让 API→engine→PCAP 集成路径传播未知 profile、状态、载体、截断和超限错误。
5. 在 MSS、TCP option、IPv6 和多会话下使用重组/解码字段验证，不能依赖固定 offset 的偶然稳定性。
6. 对 native 认证、KingBase 私有 SQL 扩展、错误码、结果元数据、压缩、TLS、复制和服务端真实执行另行设计，不以 PostgreSQL fixture 冒充实现。

待实现边界包括：具体 KingbaseES 版本映射、认证方法及摘要、私有参数、SQL 扩展 opcode/数据类型、错误字段编码、启动参数协商、服务端 session/backend key、压缩/TLS 和 profile-specific wire fixtures。任何未来固定 hex 都必须在 design、testcase、JSON 和审查文档四方同步，注明来源和版本。

## 7. 修订记录

- v1.1.0（2026-08-26）：按「`18-layer-config-design.md` v1.5.0 + 配置层级链优化需求 §7 F4（变体=profile）」改写——kingbase 由独立 TCP 终结层收敛为 **postgresql 层的 dialect 变体**（配置 `[ip, tcp, postgresql]` + `postgresql.dialect="kingbase"`，默认端口 54321，对比 dialect=postgresql 默认 5432）；不再注册独立 `kingbase` 层；端口改由 postgresql 层 FieldContract→`tcp.dst_port` 表达（据 dialect 取 5432/54321）；§3 PG v3 外层语义保留为 postgresql 层（dialect=kingbase 时）的共享 wire；§4 配置契约/校验规则、§6 实现要求相应调整。
- v1.0.0（2026-08-20）：建立 KingBase 三件套设计契约；固定 TCP/54321、PostgreSQL-compatible 外层事件语义、IPv4/IPv6、多会话、长度和状态负例；以 profile 隔离版本/兼容模式并明确不编造私有字节。

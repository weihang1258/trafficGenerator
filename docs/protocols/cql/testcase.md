# CQL/Cassandra Native Protocol（CQL/Cassandra 原生协议）测试用例设计

> 版本：v2.1.0（CORE 对齐审计版）  
> 日期：2026-09-30  
> 配套设计：`docs/protocols/cql/design.md`（v2.1.0，P6 F4 同期同步；P1 写作时 v2.0.0）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/cql.json`（CORE 对齐实测 30 例 = 15 正 + 15 负；全部正例顶层仅 `layers`，负例旧键仅用于判死）  
> 状态：P6 F1–F3 落盘（§2 F1/F2 标注 + §5 F3 包数表 + 本修订记录）；W1/W2 处置见 design §9.6（P4 已处置，P6 已验）。

## 1. 测试原则

用例从设计 §1（v4/v5、认证边界）、§2（层链/配置）、§3（9 字节 native frame）、§4（状态）、§5（失败处理）及 §6（包数/偏移）逐项派生。正例必须有 `packet_count`、TCP 握手/终止断言和至少一个 `fields` 或 `frames`；负例 `expect` **只能**有 `expect_error` 与 `error_contains`，不对失败 PCAP 作结构断言。

frame 头为 `version|flags|stream(2)|opcode|length(4)`；IPv4 无 option 时 payload 起点为 54，IPv6 为 74。`tcp.len` 是 TCP payload 字节数，等于 9+native body length。固定 hex 只锚定可复算外层，不把数据库真实执行结果、认证摘要、SASL 私有 challenge、压缩或 v5 metadata 当作事实。

### 1.1 T1–T6 测试点清单（先行）

| 编号 | 测试点 | CQL 落点 |
|---|---|---|
| T1 | 三源回指：规范、设计、现网行为分别可追溯 | v4/v5 native spec → design §9–§13 → 本文 §2–§5 与 `cql.json` |
| T2 | 先列测试点再落原子用例，覆盖载体、frame、状态、字段、版本、会话和错误传播 | 本文 §2 索引、§3 正例、§4 负例 |
| T3 | 原子粒度：每例只验证一个可区分行为面；多流和多轮单独成例 | #1–#15 按行为拆分；#16–#30 按故障锚点拆分 |
| T4 | 正常、失败、边界三类均有机器契约和稳定断言 | 正常/边界 #1–#15；失败 #16–#30；动态值只用字段、帧和长度断言 |
| T5 | §3.15 固定动作：同流多轮、非正常结束、长保活逐项落地或立项 | `cql_multi_round_query` 覆盖同流多轮；负例与 ERROR 覆盖失败；长保活明确不适用并归 TCP 层 |
| T6 | 存量用例逐例去向：合入、等价覆盖或作废必须有原因 | 17 例迁移基线见本文 §8；当前 30 个 ID 全部合入，无静默丢弃 |

## 2. 包数公式和索引

`packet_count = 3（TCP 握手） + 应用事件数 + 4（TCP 正常终止）`。每个小型事件一段；ACK 不计为应用事件。

| # | id | 类型 | 覆盖 | 应用事件 | 包数 |
|---:|---|---|---|---:|---:|
| 1 | `cql_v4_startup_ready` | 正 | v4 STARTUP→READY | 2 | 9 |
| 2 | `cql_options_supported` | 正 | OPTIONS→SUPPORTED multimap | 2 | 9 |
| 3 | `cql_auth_empty_sasl` | 正 | AUTHENTICATE/AUTH_RESPONSE/AUTH_SUCCESS | 3 | 10 |
| 4 | `cql_query_void` | 正 | STARTUP/READY/QUERY/RESULT VOID/READY | 5 | 12 |
| 5 | `cql_prepare_execute` | 正 | PREPARE/EXECUTE 请求（P6 F1：实测 4 事件/11 包，startup/ready 前置） | 4 | 11 |
| 6 | `cql_error_server` | 正 | 合法 ERROR 应用响应 | 1 | 8 |
| 7 | `cql_ipv6` | 正 | IPv6 v4 会话 | 4 | 11 |
| 8 | `cql_v5_tracing` | 正 | v5 version 和 flags（P6 F2：改形握手前 4 事件 options/supported/startup/ready，W2 B2 过渡档） | 4 | 11 |
| 9 | `cql_multi_session` | 正 | 两条独立 session | 4 | 18 |
| 10 | `cql_length_boundary` | 正 | length=0 OPTIONS | 1 | 8 |
| 11 | `cql_connect` | 正 | TCP connect，无应用事件 | 0 | 7 |
| 12 | `cql_neg_udp` | 负 | UDP 载体 | — | — |
| 13 | `cql_neg_version` | 负 | 未登记 profile/version | — | — |
| 14 | `cql_neg_opcode` | 负 | 非法 opcode | — | — |
| 15 | `cql_neg_length` | 负 | 声明长度超过 body | — | — |
| 16 | `cql_neg_state` | 负 | READY 前 QUERY | — | — |
| 17 | `cql_neg_limit` | 负 | 超过 frame 上限 | — | — |

### 2.1 当前 cases 对账（CORE 门2静态审计）

机器文件现状为 30 个唯一 ID（15 正 + 15 负），以下为完整 ID 集合；本节历史 17 例表记录迁移前基线，新增 13 例已纳入当前契约。

| 类型 | ID 集合 |
|---|---|
| 正例（15） | `cql_v4_startup_ready`, `cql_options_supported`, `cql_auth_empty_sasl`, `cql_query_void`, `cql_prepare_execute`, `cql_error_server`, `cql_ipv6`, `cql_v5_tracing`, `cql_multi_session`, `cql_length_boundary`, `cql_connect`, `cql_stream_correlation`, `cql_consistency_quorum`, `cql_flags_tracing_s2c_warning`, `cql_multi_round_query` |
| 负例（15） | `cql_neg_udp`, `cql_neg_version`, `cql_neg_opcode`, `cql_neg_length`, `cql_neg_state`, `cql_neg_limit`, `cql_neg_presence_top_level_cql`, `cql_neg_stray_src_ip`, `cql_neg_stray_count`, `cql_neg_unknown_layer_field`, `cql_neg_missing_tcp`, `cql_neg_startup_missing_cql_version`, `cql_neg_auth_order`, `cql_neg_v5_post_handshake_envelope`, `cql_neg_beta_flag_v4` |

当前正例均为 `[ip,tcp,cql]` 层链，顶层仅 `layers`；负例 expect 均严格为 `expect_error` + `error_contains`，负例中的顶层游离键只用于验证白名单拒绝，不是合法配置。

## 3. 正例契约

### 3.1 `cql_v4_startup_ready`（T-CQL-S1）

v4 profile，客户端 STARTUP（`CQL_VERSION=3.0.0`）后服务端 READY，9 包。packet 4 的 frame offset 54 为：

```text
04 00 00 00 01 00 00 00 16 00 01 00 0b 43 51 4c 5f 56 45 52 53 49 4f 4e 00 05 33 2e 30 2e 30
```

packet 5 为 `84 00 00 00 02 00 00 00 00`。STARTUP 的 string map 使用 short count=1；READY body 为空。断言 tcp.len 分别为 31 和 9。

### 3.2 `cql_options_supported`（T-CQL-S2）

OPTIONS 空 body 后 SUPPORTED multimap，9 包。packet 4 offset 54：`04 00 00 00 05 00 00 00 00`，tcp.len=9。packet 5 是包含 `CQL_VERSION` 和 `COMPRESSION` 的显式 multimap，tcp.len=61；只固定 short count、键和值的可复算字节，不推断服务器支持列表以外的压缩行为。

### 3.3 `cql_auth_empty_sasl`（T-CQL-S3）

`cql_v4_auth` profile，服务端 AUTHENTICATE、客户端零长度 AUTH_RESPONSE、服务端 AUTH_SUCCESS，10 包。packet 4 为 opcode `0x03` 和 authenticator string；packet 5 offset 54 为：

```text
04 00 00 00 0f 00 00 00 04 00 00 00 00
```

其中 length=4、bytes length=0。packet 6 为 `84 00 00 00 10 00 00 00 04 00 00 00 00`。空 SASL bytes 只覆盖 framing 边界，不是密码或认证成功依据；AUTH_SUCCESS 的私有 token 不固定。

### 3.4 `cql_query_void`（T-CQL-S4）

STARTUP→READY→QUERY→RESULT VOID→READY，12 包。packet 6 QUERY 文本为 `INSERT INTO ks.t (k) VALUES (1)`，frame offset 54，tcp.len=50；packet 7 RESULT VOID，frame 为：

```text
84 00 00 00 08 00 00 00 04 00 00 00 01
```

两次 READY 后状态边界明确。结果不包含 rows/metadata，因此不编造列类型、paging state 或真实写入效果。

### 3.5 `cql_prepare_execute`（T-CQL-S5）

P6 F1：实测 4 事件（startup/ready/prepare/execute）/11 包（P5 按 design §9.2 缺失格补 startup/ready 前置）。PREPARE 的 long string 是 `SELECT v FROM ks.t WHERE k = ?`；EXECUTE 使用 `[short bytes]` 的 `pid-1`、consistency=1、flags=0。两帧 offset 54 由 JSON 完整锚定；不隐式制造 PREPARE response，prepared metadata 和 bound values 留作 profile 边界。

### 3.6 `cql_error_server`（T-CQL-S6）

单个合法 s2c ERROR，8 包。frame offset 54：version=`0x84`、opcode=`0x00`、code=`0x00000000`、message=`server error`，tcp.len=27。该 ERROR 是协议内应用结果，不应设置 `expect_error`；具体错误详情字段不作跨版本承诺。

### 3.7 `cql_ipv6`（T-CQL-S7）

v4 profile、IPv6 地址、STARTUP→READY→QUERY→RESULT VOID，11 包。packet 4/5 的 frame offset 为 74，且 `ipv6.version=6`、端口 9042；头布局与 IPv4 完全相同，只改变以太网帧内 payload 起点。

### 3.8 `cql_v5_tracing`（T-CQL-S8）

v5 profile，P6 F2 实测形：握手前 4 事件（options/supported/startup/ready），11 包；W2 过渡档下 v5 握手后事件拒（锚词 `envelope`）。options 帧 `05 00 00 00 05 …`；SUPPORTED multimap 含 `CQL_VERSION` 5.0.0 + `COMPRESSION` snappy（tcp.len=56）；v5 beta、tracing response UUID、result metadata 不从 flags 猜测，只锁定 header 和基础帧。

### 3.9 `cql_multi_session`（T-CQL-S9）

两个独立四元组，源端口 12345/12346，各自 STARTUP→READY，18 包。断言源端口 distinct values 为 12345/12346、目的端口为 9042；不按全局 PCAP 序号推断两流交错顺序，stream/state 只在每流内关联。

### 3.10 `cql_length_boundary`（T-CQL-S10）

单个 OPTIONS，body length=0，完整 frame 为 9 字节，8 包。该例证明 `length=0` 合法，不把空 body 当作截断；packet 4 `tcp.len=9`，frame offset 54 断言完整头。

### 3.11 `cql_connect`（T-CQL-S11）

仅 TCP 9042 握手和正常终止，7 包；不隐式生成 STARTUP。packet 1 目的端口 9042，`has_payload=false`。

## 4. 负例契约

负例 expect 严格只有两个键，错误必须由 planner/validator 传播到 task error：

| id | 输入故障 | `error_contains` |
|---|---|---|
| `cql_neg_udp` | `layers=[udp,cql]` | `tcp` |
| `cql_neg_version` | `wire_profile=cql_v3` | `version` |
| `cql_neg_opcode` | `wire_fault.kind=opcode,value=255` | `opcode` |
| `cql_neg_length` | `wire_fault.kind=length,value=declared_gt_body` | `length` |
| `cql_neg_state` | 首个事件直接 QUERY | `state` |
| `cql_neg_limit` | `wire_fault.kind=message_limit,value=over_limit` | `limit` |

`wire_fault` 只表示配置校验注入，不允许生成损坏但成功的 PCAP。若实现最终错误文本不同，须先同步 design、testcase、JSON、audit 四方。

## 5. 三方一致性检查清单

本文、设计 §6 和 JSON 都是 **30 个唯一 id，顺序一致**。正例 **15**、负例 **15**；正例包数 `[9,9,10,12,11,8,11,11,18,8,7,13,11,11,14]`，负例不出现 `packet_count`。正例 `spec_json` 顶层键均为 `{layers}`；负例仅保留用于验证拒绝的游离键/层链形状。

## 6. 实现后执行建议

先运行 JSON 语法、hex（十六进制）解析、三方 id/包数/负例键静态检查；层注册后依次跑 v4 header、OPTIONS/SUPPORTED、auth、QUERY/VOID、PREPARE/EXECUTE、ERROR，再跑 IPv6/v5/多会话。MSS 分段必须通过 TCP stream 重组断言。取得认证或 Cassandra 版本 fixture 后，再增加 profile-specific challenge、metadata 和 compression 用例，不把当前边界改成猜测。

## 7. 修订记录

- v2.0.1（2026-09-28，P6 F1–F4 同期同步）：F1 prepare_execute 9→11 包/4 事件（P5 补 startup/ready 前置）；F2 v5_tracing 改形握手前 4 事件（W2 B2 过渡档）；F3 总数 17→30（15正15负）+ 包数表更新；F4 见 design §9.1/§9.6 W1/W2 标"P4 已处置"。
- v2.0.0（2026-09-26）：P1–P3 完整产物。新增 §8 存量 17 例逐条去向审计（9.14）与 §9 P3 固定动作（§3.15 三项 / A′·B′ 两分类 / 9.52 对账两行 / 3.14 豁免审计 / 三源回指 / 断言通道实测）；§1–§6 正文保留（旧文逐条核对见 design §14.2）；状态行按注册/落码实测改写。
- v1.0.0（2026-08-20）：建立 11 个正例和 6 个负例；覆盖 CQL v4/v5、STARTUP/OPTIONS/READY/SUPPORTED、认证 bytes 边界、QUERY/PREPARE/EXECUTE/RESULT/ERROR、IPv4/IPv6、多会话、frame length/非法 opcode/状态/UDP/上限负例。

## 8. 存量 17 例逐条去向审计（§9.14；P1 迁移前基线，P4 已执行）

实测口径：17 例迁移前基线（11 正 6 负）；现行机器契约为 30 例（15 正 15 负），新增 13 例已纳入 §2.1 完整 ID 集合。17/17 顶层键 = `['cql','dst_ip','dst_port','layers','src_ip','src_port']`；`layers` = `[{"tcp":{}},{"cql":{}}]` 16 例 + `[{"udp":{}},{"cql":{}}]` 1 例（N1）；0/17 有 `ip` 层、0/17 有 `flow_control`、0/17 有 `count`（缺键补齐非迁移）；负例 `expect` 6/6 恰为 `{expect_error, error_contains}` ✓；正例断言字段用量 = `tcp.dstport`×7 / `tcp.srcport`×4 / `tcp.len`×8 / `ipv6.version`×2，**`cql.*` 协议字段 0 条**；frames hex 9 例。

| # | id | 类型 | 形状现状 | 去向（P4 改写） |
|---:|---|---|---|---|
| 1 | `cql_v4_startup_ready` | 正 | 旧扁平 + frames 2 帧钉 | **保留改写**：加 ip 层/端口进 tcp/cql 4 键迁层条目/补 `flow_control.flows=1`；帧钉值不变（STARTUP/READY 无 flags 面） |
| 2 | `cql_options_supported` | 正 | 旧扁平 + frames 2 帧钉 | 保留改写；帧钉值不变（空 body/multimap 无 flags） |
| 3 | `cql_auth_empty_sasl` | 正 | 旧扁平 + frames 3 帧钉 | 保留改写；帧钉值不变 |
| 4 | `cql_query_void` | 正 | 旧扁平 + frames 2 帧钉（packet 6 QUERY 带 4 字节 flags） | **保留改写 + 帧重钉**：W1 修后 v4 QUERY flags=1 字节，packet 6 hex 与 `tcp.len` 50→47 重钉（14.6 先跑后钉） |
| 5 | `cql_prepare_execute` | 正 | 旧扁平 + frames 2 帧钉（packet 5 EXECUTE 带 4 字节 flags） | **保留改写 + 帧重钉**：同 W1，packet 5 重钉 |
| 6 | `cql_error_server` | 正 | 旧扁平 + frames 1 帧钉 | 保留改写；帧钉值不变 |
| 7 | `cql_ipv6` | 正 | 旧扁平（v6 地址）+ frames 2 帧（startup/ready） | 保留改写；ip 层填 v6 地址，offset 74 不变；QUERY 帧未钉不受 W1 影响 |
| 8 | `cql_v5_tracing` | 正 | 旧扁平 + frames 4 帧钉（握手前 unframed OPTIONS/SUPPORTED/STARTUP/READY） | **保留改形**：W2 过渡档下 v5 握手后事件拒；本例仅覆盖握手前 4 事件，帧钉随形重钉（G-CQL-3） |
| 9 | `cql_multi_session` | 正 | 旧扁平 + sessions[] 双源端口 | 保留改写；**多流展开相容性 B 轨首跑即验**（mongodb "one flow per chain" 裁定），撞拒则改形上报 |
| 10 | `cql_length_boundary` | 正 | 旧扁平 + frames 1 帧 | 保留改写；帧钉值不变 |
| 11 | `cql_connect` | 正 | 旧扁平 + 无 payload | 保留改写；`has_payload=false` 保持 |
| 12 | `cql_neg_udp` | 负 | `layers=[{udp},{cql}]` 旧扁平 | **改形负例**：纯 layers `[ip,udp,cql]` + 非法内容（载体族错），锚词 `tcp` 保持 |
| 13 | `cql_neg_version` | 负 | 旧扁平 + `wire_profile=cql_v3` | 改形负例（业务键迁层条目），锚词 `version` 保持 |
| 14 | `cql_neg_opcode` | 负 | 旧扁平 + wire_fault | 改形负例（wire_fault 迁层条目），锚词 `opcode` 保持 |
| 15 | `cql_neg_length` | 负 | 旧扁平 + wire_fault | 改形负例，锚词 `length` 保持 |
| 16 | `cql_neg_state` | 负 | 旧扁平 + 首事件 QUERY | 改形负例，锚词 `state` 保持 |
| 17 | `cql_neg_limit` | 负 | 旧扁平 + wire_fault | 改形负例，锚词 `limit` 保持 |
| — | （新增）presence 负例 | 负 | 无 | **P4 新增**：`{"layers":[{"ip":{}},{"tcp":{}},{"cql":{}}],"cql":{}}` 判死，锚词 `top-level`（design §11.4） |
| — | （新增）游离键负例 | 负 | 无 | **P4 新增**：顶层游离键（如 `src_mac`）判死 |
| — | （新增）A′ 补例批 | 正 | 无 | **P4/P5 新增**：stream 非零关联例、consistency 逐值、同连接多轮 QUERY、`cql.*` 字段断言批（§9.6 十字段）、STARTUP 缺 CQL_VERSION 负例（G-CQL-6/7） |

合计：17 例迁移基线逐条有去向，新增 13 例纳入当前机器契约，共 30 例（15 正 + 15 负），无静默丢弃。

## 9. P3 固定动作（CORE_MEMORY §3.15 / §9.52 / §9.14 / 覆盖审计要求面）

### 9.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| 项 | 结论 | 用例/立项 |
|---|---|---|
| 同连接/同流内多轮操作 | **已覆**：S4 单轮 QUERY→RESULT→READY；`cql_multi_round_query` 覆盖同连接两轮 QUERY/RESULT | 当前机器契约已落例 |
| 非正常结束 | **已覆**：N1–N6 六负例 + S6 合法 ERROR 应用响应；认证失败分支（AUTH_ERROR 0x0100）无例 | 认证失败码面 → G-CQL-5 |
| 长保活 | **明确不适用**：CQL 无协议级心跳/保活消息（design §9.1 行6）；TCP keepalive 归 tcp 层 | 无缺口（显式不适用） |

### 9.2 A′/B′ 两分类表（要求面反推）

| 分类 | 本协议条目 |
|---|---|
| **A′（纯用例/断言面可表达，不动代码）** | ①`cql.*` 字段断言批（已落部分，G-CQL-7 继续扩面）；②stream 非零 + 响应 stream 回填关联例（已落）；③consistency 非 ONE（已落 1 值，余值待补）；④同连接多轮 QUERY（已落）；⑤frame flags 位（已落 tracing/warning，余位待补）；⑥STARTUP NO_COMPACT/THROW_ON_OVERLOAD 选项面；⑦超长/截断 long string 边界（maxFrameBytes 256KiB 内） |
| **B′（需代码或框架改动，另立项）** | G-CQL-1（纯 layers 收口 + 多流展开实测）、G-CQL-2（W1 flags 宽度）、G-CQL-3（W2 v5 面）、G-CQL-4（result_kind 死字段）、G-CQL-5（4 opcode + 4 result kind + 17 码）、G-CQL-6（校验补面） |

### 9.3 9.52 对账两行 + 清单出处声明

- **行 1**：规范逻辑点总数 = **97 枚举点（9 面）**：opcode 16 + frame flags 4 + QUERY/EXECUTE flags 7 + consistency 11 + result kinds 5 + error codes 17 + 数据类型 23 + STARTUP 选项 4 + v5 差异 10。清单出处 = native_protocol_v4.spec（1219 行）/ v5.spec（1537 行）**原文反推**（2026-09-26 自 apache/cassandra trunk 取），非从用例或引擎能力反推。
- **行 2**：用例覆盖数 = **30 例**（15 正 15 负，实测）；枚举点已覆 **20/97**（opcode 12 + flags 2 形 + query flags 2 形 + consistency 1 + result kind 1 + error code 1 + STARTUP 选项 1），未覆 77 点全部归 G-CQL-2/3/5/6/7/8 或“明确不支持”，无留白。

### 9.4 3.14 豁免边界审计

CQL 是 TCP 长连接协议 → 3.14"无长连接协议"豁免**不适用**，不主张任何豁免：多会话 = `sessions[]` 双源端口（#9 已覆）；多事务 = §9.1 行1（A′ 补）；单包多载荷 = **不适用**（CQL 一帧一消息，无多 question/多 RR 形态——与 DNS 族差异显式声明）。

### 9.5 三源回指行（§9.2–9.4）

| 源 | 回指 |
|---|---|
| 规范（v4/v5 spec 原文） | §2 frame header ↔ #1–#11 frames hex；§4.1.1 STARTUP ↔ #1；§4.1.4 QUERY ↔ #4；§4.2.5 RESULT ↔ #4/#7/#8；§4.2.1 ERROR ↔ #6 |
| 设计（D-CQL-1） | design §9 矩阵行 ↔ 本文用例号；design §12 文件清单 ↔ #1–#17 改写 |
| 现网行为 | Cassandra 4.x/5.x + DataStax driver 形态 ↔ #1/#4（同构）；**未确认级 → G-CQL-8**（抓 cqlsh/docker Cassandra 回环包确认） |

### 9.6 断言通道核对（tshark 3.6.14 实测）

- `cql.*` 唯一字段 **83 个**（`tshark -G fields` 实测）；合成 pcap 探针（TCP seq 对齐 + 端口 9042）实测 **10 字段可解**：`cql.version`（0x04/0x84/0x05/0x85）、`cql.direction`、`cql.opcode`、`cql.stream`、`cql.message_length`、`cql.flags`、`cql.consistency`、`cql.query.flags`（FT_UINT8，W1 佐证）、`cql.result.kind`、`cql.error_code`。
- **端口前提**：必须 9042 才挂 CQL dissector（非标端口不解码，实测）——断言用例一律钉 9042。
- **TCP 流前提**：seq/ack 必须真实衔接（探针首轮 seq 未对齐致 RESULT 帧不解码——断言 pcap 由引擎真实生成，天然满足；人工合成探针须自证）。
- 迁移前 17 例断言字段用量：`tcp.dstport`×7 / `tcp.srcport`×4 / `tcp.len`×8 / `ipv6.version`×2 / frames 9 例 / **`cql.*` 0 条**；当前机器契约已加入 `cql.stream/opcode/consistency/flags` 协议断言。

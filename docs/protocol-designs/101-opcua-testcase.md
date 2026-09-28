# #101 opcua（OPC UA）测试用例契约

> 版本：v1.0.1（P-PIPE 文档轨 P1–P3 + 结果文档过期登记）
> 日期：2026-09-28
> 配套设计：`docs/protocol-designs/101-opcua-design.md` v1.0.1（D-OPCUA-1）
> 旧基线：`docs/protocol-designs/25-opcua-testcase.md` v1.0.0（文档列 T1–T14，实际 JSON 12 例；**承其断言思路**，冲突处按实测 pcap 与代码事实改正，见设计 §0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/opcua.json`（12/12 ID 与本版 §2 一致，顺序一致，已机读实测；**顶层键已是纯层链形，零残留**）
> 白话一句：**十二条检查：十条看正常收发（握手、开通道、带签名、读写浏览、订阅、两类错误码、多会话、新网段），两条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **12 个唯一语义 ID：10 正 + 2 负**（负例 N-1/N-2）。派生规则：设计 §3 每个消息/字段条款、§5 每个事务/自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-28 机读实测）**：12/12 例顶层键 = `{expect,id,proto,spec_json,summary}`；`spec_json` 顶层键 = **`{layers}` ×12（唯一键，零游离键、零顶层 `opcua` 子映射）**——本协议存量**顶层零残留**，无 §1 迁移工作量（设计 §12.1；全仓另有 26 个协议同形，非唯一）；层形 `[tcp,opcua]` ×11 + `[ip,tcp,opcua]` ×1（`opcua_ipv6`）；10 正例 `expect` 含 `packet_count`；2 负例 `expect` 键集合 = `{expect_error,error_contains,notes}`（含 `notes`，非严格两键，G-OPCUA-7）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`、`tcp.flags`、`opcua.*` 字段、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线（旧稿结论已反转，设计 §0 #14）**：本机 tshark **3.6.14 有 opcua dissector**——`tshark -G fields` 中 `opcua.*` **442 字段**，`tshark -G decodes` 有 `tcp.port 4840 opcua`；12 例 pcap 全部被解码（`_ws.col.Protocol = OpcUa`，`frame.protocols` 含 `:opcua`），**零 `_ws.malformed`**（实测）。可用字段通道：① `opcua.transport.type/chunk/size/scid`；② `opcua.security.tokenid`；③ `opcua.servicenodeid.numeric`；④ `opcua.nodeid.numeric`；⑤ `opcua.RequestHandle`；⑥ frames 原始 hex（offset 54/74）。**进制纪律（实测）**：`opcua.transport.size`、`opcua.transport.scid`、`opcua.security.tokenid`、`opcua.servicenodeid.numeric`、`opcua.RequestHandle` 用**十进制串**；`opcua.transport.type` 用类型名串（`HEL`/`ACK`/`OPN`/`MSG`/`CLO`）。

**断言基线**：今日 12 例只用 `packet_count` + `has_handshake` + `terminates` + `tcp.dstport` + frames；**48 条 frame 断言已逐条对实测 pcap 复核（全 OK）**。`opcua.*` field 断言**今日零使用** → A′ 立项（G-OPCUA-3，把已可用的 dissector 字段补起来）。

**动态字段禁止硬编码**：生成期值（`RequestHandle`/`SequenceNumber`/`TokenId`）用固定锚点断言（本实现恒为常量，`planner.go:187-190`）。

**包数约定（实测公式，设计 §9）**：单流 = 3（握手）+ 2（HEL/ACK）+ 2（OPN 对）+ 2×服务对数 + 2（**CLO 对**）+ 4（FIN 四包）= **13 + 2×服务对数**。**旧稿 §4.1 "CLO 无响应"与实测相反**（实测 CLO 请求/响应各一帧，`hello_ack` 帧 8/9）。负例无 `packet_count`（实测 0 帧）。

**保活/重试/RST 口径**：协议层无 PING 类保活；订阅 keep-alive 是**发布空转**（`PublishResponse` notificationData 为 null，**服务体 57 vs 带通知 74；MessageSize 85 vs 102**），不是心跳；RST 为框架 tcp 层能力，本协议层不新增断言（A′ 补例 G-OPCUA-6 除外）；正例恒 FIN 优雅终止。

## 2. 原子用例索引（12 ID = 10 正 + 2 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count（实测） |
|---:|---|---|---|---:|
| 1 | `opcua_hello_ack` | 正 | §3.4：HEL/ACK 基线（空 EndpointUrl） | 13 |
| 2 | `opcua_open_none` | 正 | §3.4/§3.7：OPN None + 多节点 Read（令牌复用） | 15 |
| 3 | `opcua_open_sign` | 正 | §3.4：Sign 模式结构路径（SecurityMode=2） | 13 |
| 4 | `opcua_write` | 正 | §3.5：Write + DataValue/Variant | 15 |
| 5 | `opcua_browse` | 正 | §3.5：Browse ObjectsFolder 前向引用 | 15 |
| 6 | `opcua_subscribe` | 正 | §3.6：订阅五件套 + 通知 + keep-alive | 23 |
| 7 | `opcua_bad_node` | 正 | §7/§9.1：ServiceResult=BadNodeIdUnknown | 15 |
| 8 | `opcua_denied` | 正 | §7/§9.1：ServiceResult=BadUserAccessDenied | 15 |
| 9 | `opcua_ipv6` | 正 | §2：IPv6 独立用例（offset 74） | 15 |
| 10 | `opcua_multi_session` | 正 | §5：sessions=3 连续三对 Read | 19 |
| 11 | `opcua_bad_size_neg` | 负 | §7：N-1 MessageSize 注入 | —（实测 0 帧） |
| 12 | `opcua_no_channel_neg` | 负 | §7：N-2 未建通道服务 | —（实测 0 帧） |

T-编号对照：T-OPCUA-T1 ≡ #1；T-OPCUA-T2 ≡ #2；T-OPCUA-T3 ≡ #3；T-OPCUA-T5 ≡ #4；T-OPCUA-T6 ≡ #5；T-OPCUA-T7 ≡ #6；T-OPCUA-T9 ≡ #7；T-OPCUA-T10 ≡ #8；T-OPCUA-T11 ≡ #9；T-OPCUA-T12 ≡ #10；T-OPCUA-T13 ≡ #11；T-OPCUA-T14 ≡ #12。（旧稿 T4/T8 为文档引用锚点，无独立 JSON 用例，见 §8.2。**序号以 cases JSON 顺序为权威**：JSON 中 `opcua_ipv6` 在 `opcua_multi_session` 之前。）

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count` + `terminates` + frames 断言；帧位由 §1 公式与实测 pcap 双向确认。

### 3.1 `opcua_hello_ack`（13）

`tcp.dst_port=4840`、`opcua.security_mode="none"`、`opcua.close=true`。

- `has_handshake=true`、`terminates=true`、`packet_count=13`（服务对数 0）。
- `tcp.dstport=4840`（帧 4）。
- frames：帧 4 offset 54 `48 45 4c 46 20 00 00 00`（`'HEL'+'F'` + MessageSize=32 LE，**含 4B 空 EndpointUrl 长度前缀**）；帧 5 offset 54 `41 43 4b 46 1c 00 00 00`（`'ACK'+'F'` + 28）；帧 6 `4f 50 4e 46`（OPN）；帧 8 `43 4c 4f 46`（CLO 请求）。
- **MessageSize 证据**：HEL=32 = 8 头 + 20（5×UInt32）+ 4（空 EndpointUrl）；ACK=28 = 8 + 20（**无 EndpointUrl**）——两帧差 4 字节即该字段的直接证据。

### 3.2 `opcua_open_none`（15）

`security_mode="none"`、`read=[{node_ids:["ns=0;i=1001","ns=0;i=1002"], attribute_id:13}]`、`close=true`。

- frames：帧 6 offset 54 `4f 50 4e 46` + offset 62 `00 00 00 00`（OPN 请求 SecureChannelId=0）；帧 7 offset 54 `4f 50 4e 46` + offset 62 `01 00 00 00`（响应 SecureChannelId=1）；帧 8 offset 54 `4d 53 47 46` + offset 62 `01 00 00 00` + offset 66 `e8 03 00 00`（**MSG 的 SecureChannelId=1 与 SecurityTokenId=1000，证明 OPN 响应令牌被对称段复用**）；帧 10 `43 4c 4f 46`。
- **补充可断言（tshark 实测，A′ 可收编）**：帧 8 `opcua.transport.size=111`（= 8+16+4+83，Read 两节点 `47+18×2`）；`opcua.servicenodeid.numeric=631`；帧 9 = 68（响应 `32+4×2`）。
- **多节点证据**：帧 8 内 @129 `01 00 e9 03`（node 1001）、@147 `01 00 ea 03`（node 1002）——一帧两节点，非两帧。

### 3.3 `opcua_open_sign`（13）

`security_mode="sign"`、`close=true`。

- frames：帧 6 offset 54 `4f 50 4e 46` + offset 62 `00 00 00 00`；帧 7 offset 54 `4f 50 4e 46` + offset 62 `01 00 00 00`；帧 8 `43 4c 4f 46`。
- **结构路径证据（实测）**：帧 6 与 `open_none` 帧 6 **等长（MessageSize 87 = body 79+8；以太帧 141 = 54+87）**，唯一差异在 @129：none `01 00 00 00` vs sign `02 00 00 00`（SecurityMode 枚举）。**本用例不声称真实签名/证书可用**（设计 §3.4 诚实边界、G-OPCUA-4）。

### 3.4 `opcua_write`（15）

`security_mode="none"`、`write=[{node_ids:["ns=0;i=1001"], attribute_id:13}]`、`close=true`。

- frames：帧 8 offset 54 `4d 53 47 46` + offset 62 `01 00 00 00` + offset 66 `e8 03 00 00`；帧 9 `4d 53 47 46`（响应）；帧 10 `43 4c 4f 46`。
- **补充可断言（实测）**：帧 8 `opcua.transport.size=81`（= 8+16+4+53，WriteValue `35+18×1`，含 DataValue 掩码 `01` + Variant `06` Int32）；帧 9 = 64。

### 3.5 `opcua_browse`（15）

`security_mode="none"`、`browse=[{node_ids:["ns=0;i=85"], attribute_id:0}]`、`close=true`。

- frames：帧 8 offset 54 `4d 53 47 46` + offset 62 `01 00 00 00` + offset 66 `e8 03 00 00`；帧 9 `4d 53 47 46`；帧 10 `43 4c 4f 46`。
- **补充可断言（实测）**：帧 8 `opcua.transport.size=100`（= 8+16+4+72，BrowseDescription `53+19×1`）；帧 9 = 72；`opcua.servicenodeid.numeric=527`。
- **结构边界（诚实声明）**：本用例只覆盖 BrowseRequest 结构存在 + 帧位；**nodeClassMask=0 / resultMask=63 的取值断言今日无**（旧稿 §10.3 的 nodeClassMask 0x3F 与代码不符，设计 §0 #10）→ A′ 立项（G-OPCUA-3）。

### 3.6 `opcua_subscribe`（23）

`security_mode="none"`、`subscription={publishing_interval_ms:1000, publish_count:2, publish_interval_ms:1000, keep_alive:true, max_keep_alive_count:100, monitored_nodes:["ns=0;i=1001"]}`、`close=true`。

- frames（offset 54）：帧 8/10/12/14/16 `4d 53 47 46`（五对请求）；帧 18 `43 4c 4f 46`（CLO 请求）。
- **包数证据**：服务对数 5 → 13 + 2×5 = 23 ✓。**CLO 对**在帧 18/19（两帧均 `CLOF` size 59），FIN 四包在帧 20–23。
- **补充可断言（tshark 实测，本用例最丰富）**：帧 8/9 = CreateSubscription（TypeId 787/788；size 81/72）；帧 10/11 = CreateMonitoredItems（**751**/752；113/81）；帧 12/13 = SetPublishingMode（**791**/792；68/61）；帧 14/15 = Publish 带通知（826/827；**63/102**）；帧 16/17 = Publish keep-alive（826/827；**63/85**）。
- **通知 vs keep-alive 证据**：帧 15 size=102（notificationData 长度 1 + ExtensionObject 体 8）vs 帧 17 size=85（notificationData null）——**17 字节差（74 − 57）即"有无通知"的直接证据**。
- **SetPublishingMode TypeId 791/792 是 confirmed 缺陷**（官方 797/800、tshark 表 799/802），设计 §9.2 M-1 已立项修复；**修复后本用例帧 12/13 TypeId hex 变、帧数与其余断言不变**。

### 3.7 `opcua_bad_node`（15）

`security_mode="none"`、`read=[{node_ids:["ns=0;i=9999"], attribute_id:13}]`、`error_inject={op:"bad_node", node:"ns=0;i=9999"}`、`close=true`。

- frames：帧 8/9 `4d 53 47 46`；帧 10 `43 4c 4f 46`。
- **ServiceResult 断言（本轮新钉，实测可执行）**：响应帧 9 **offset 94** = `00 00 34 80`（StatusCode BadNodeIdUnknown LE）。**该偏移本轮已实测复核**（@90 RequestHandle `02 00 00 00`、@94 ServiceResult、@98 diagnostics `00`），旧稿"偏移不硬编码"可收窄为精确断言 → A′ 收编（G-OPCUA-3）。
- **注入路径证据**：请求帧 8 @129 `01 00 0f 27`（读目标 `ns=0;i=9999`=0x270F）；响应帧 9 **results[] 仍 Good**，坏码只在 ResponseHeader（`builder.go:216-218` 注释口径）。

### 3.8 `opcua_denied`（15）

`security_mode="none"`、`write=[{node_ids:["ns=0;i=1001"], attribute_id:13}]`、`error_inject={op:"denied"}`、`close=true`。

- frames：帧 8/9 `4d 53 47 46`；帧 10 `43 4c 4f 46`。
- **ServiceResult 断言（本轮新钉，实测可执行）**：响应帧 9 **offset 94** = `00 00 1f 80`（StatusCode BadUserAccessDenied LE）——本轮实测复核通过 → A′ 收编（G-OPCUA-3）。

### 3.9 `opcua_ipv6`（15）

`layers[0].ip={src:"2001:db8::1", dst:"2001:db8::2"}`、`tcp.dst_port=4840`、`read=[{node_ids:["ns=0;i=1001"]}]`、`close=true`。

- frames（**offset 74** = 14+40+20）：帧 4 `48 45 4c 46 20 00 00 00`；帧 5 `41 43 4b 46 1c 00 00 00`；帧 6 `4f 50 4e 46`；帧 8 `4d 53 47 46`；帧 10 `43 4c 4f 46`。
- **协议与地址族解耦证据**：HEL/ACK 的 MessageSize 在 IPv6 下**仍为 32/28**，字节不变，只有载荷起点从 54 变 74。

### 3.10 `opcua_multi_session`（19）

`security_mode="none"`、`sessions=3`、`read=[{node_ids:["ns=1;i=1001"], attribute_id:13}]`、`close=true`。

- frames：帧 8/10/12 `4d 53 47 46`（三对请求）；帧 14 `43 4c 4f 46`（CLO）。
- **包数证据**：服务对数 3 → 13 + 2×3 = 19 ✓。
- **补充可断言（实测）**：帧 8/10/12 size 均 **93**（Read `47+18×1`），TypeId 均 **631**，读目标 @129 均 `01 01 e9 03`（`ns=1;i=1001`）。
- **诚实声明（本用例断言口径边界，设计 §5/G-OPCUA-2）**：`sessions=3` 实现为**连续三对 Read，非交错**；三对的 AuthenticationToken @82 **全为 `01 00 00 00`**（同一无会话令牌，**无每会话独立令牌**）；RequestHandle @94 顺序 2/3/4（**共用同一计数器，非独立空间**）。**本用例不断言状态隔离**，只断言"三对 MSG 存在 + CLO 帧位"；旧稿 §1.2/§2.12 的"分空间/交错"描述未落码。

**正例总则**：多节点一帧、多会话多对、Sign 结构路径、订阅多周期均为正例形态，只有配置/长度错误进入负例。

## 4. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功（**实测两例 pcap 均 0 帧**，文件名 `<id>.neg.pcap`）。锚词与设计 §7 表一一对应、同序（代码逐字，`planner.go` 实测行号）：

| ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（`planner.go` 逐字） | 代码行 |
|---|---|---|---|---|
| `opcua_bad_size_neg` | `bad_message_size=true` + `bad_length=true` | `MessageSize` | `opcua: MessageSize is invalid` | `planner.go:31` |
| `opcua_no_channel_neg` | `skip_channel=true` + `read=[…]` | `secureChannel` | `opcua: secureChannel is required before MSG service` | `planner.go:37` |

**锚词口径**：`error_contains` 是**子串**判定；两例均命中代码文案（前缀 `opcua: `）。

**负例原子性**：每例单一故障注入；单次执行不得混注。**N-1 存量同时置 `bad_length=true`**（两注入并存）——`Validate` 按 `BadMessageSize` 先判（`planner.go:30` 早于 `:33`），故锚词稳定为 `MessageSize`；`bad_length` 单独分支（`opcua: String length is invalid`，`planner.go:34`）今日无用例 → A′ 立项（G-OPCUA-7）。

**旧稿语义已反转（设计 §0 #16）**：旧稿 §9.3/§9.4 称两例"字节仍完整能发出，靠 tshark 告警捕获"；**实测为 Validate 阶段直接拒绝、零包**——本版按实现钉，用例 `expect_error` 语义与之一致。

**expect 键形状注**：存量 2 负例 `expect` = `{expect_error, error_contains, notes}`（含 `notes`），与 92-moxa 范式的严格两键不同——P4 收窄时删 `notes`（G-OPCUA-7）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：`security_mode %q invalid`（`planner.go:24`）；`transport %q invalid`（`:27`，层内不可达，G-OPCUA-1）；`sessions %d out of range`（`:40`）；`service operation requires at least one node id`（`:44`）；`node id %q is not ns=<int>;i=<int>`（`builder.go:69`）；`node id %q exceeds four-byte encoding`（`builder.go:72`）；`MessageSize %d exceeds UInt16`（`builder.go:17`）。

**未入用例的静默路径（缺陷候选）**：`error_inject.op` 未知值 → `serviceResult` 的 switch 无 default，**静默返回 0（Good）**（`planner.go:67-73`）→ G-OPCUA-7 裁定拒绝或登记。

## 5. 覆盖与对账

### 5.1 三源回指行

OPC UA Part 6/Part 4 + 官方 `NodeIds.csv`/`StatusCode.csv`（设计 §10）+ D-OPCUA-1（设计 §11）+ tshark 3.6.14 字段表与 **12 例实测 pcap**（`/tmp/mcp-pcaps/opcua/`）→ 12 ID（本契约 §2）。第三源"已确认现网行为"当前 = **抓包级已到**（本仓引擎产出的 12 例 pcap 逐帧核对），但**真实服务器/开源实现的线字节未取到** → G-OPCUA-8（按 §5.5 不写死进实现）。

**12 ID 逐项回指（§9.5 要求）**：#1←设计 §3.4；#2←§3.4/§3.7；#3←§3.4；#4←§3.5；#5←§3.5；#6←§3.6；#7←§7/§9.1；#8←§7/§9.1；#9←§2；#10←§5；#11←§7 N-1；#12←§7 N-2。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **OPC UA Part 6/Part 4 公开语义 + 官方 NodeIds/StatusCode CSV + 旧基线契约 + 仓库落码反推 + tshark 3.6.14 字段与 pcap 实测**，**非纯规范反推**（Part 6 条款号未逐条核对 → G-OPCUA-8）。
- **对账两行**：**要求逻辑点总数 = 74**（八项 8 行 + 矩阵 27 格 + 变体 24 行 + 商业映射 15 行）；**用例覆盖数 = 46**（八项已覆 4 + 矩阵已覆 17 + 变体已覆 15 + 商业已覆 10）；**不适用 = 8**（八项 1 + 矩阵 2 + 商业 5）；**开放立项 = 20**（八项 3 + 矩阵 A′ 8 + 变体立项 9）。46 + 8 + 20 = 74。✓
  **粒度声明**：行/格粒度每点 1 计；G-OPCUA-1…G-OPCUA-10 与 M-1 不折进 74。**反查全绿 ≠ 覆盖全**（§9.52 原文）。逐表重数见设计 §10.1（八项 8 = 覆 4 + 立项 3 + 不适用 1）/§10.2（27 格 = 覆 17 + A′ 8 + 不适用 2）/§10.3（24 行 = 覆 15 + 立项 9）/§10.4（15 行 = 覆 10 + 不适用 5）。
- **门3 抽查候选**：最复杂用例 = **#6 `opcua_subscribe`**（23 帧：传输层 2 + OPN 对 + **5 对订阅服务**（CreateSub/CreateMon/SetPubMode/Publish通知/Publish keep-alive）+ CLO 对 + FIN 四包；交织维度 = 服务(5)×方向(2)×通知有无(2)×TypeId(5 组)）；**建议门3 抽 #6 + #10**（`opcua_multi_session` 补多会话面）。

### 5.3 T-编号与旧 id 对照（设计 §9 全表摘要）

`opcua_hello_ack` ≡ T-OPCUA-T1；`opcua_open_none` ≡ T-OPCUA-T2；`opcua_open_sign` ≡ T-OPCUA-T3；`opcua_write` ≡ T-OPCUA-T5；`opcua_browse` ≡ T-OPCUA-T6；`opcua_subscribe` ≡ T-OPCUA-T7；`opcua_bad_node` ≡ T-OPCUA-T9；`opcua_denied` ≡ T-OPCUA-T10；`opcua_multi_session` ≡ T-OPCUA-T12；`opcua_ipv6` ≡ T-OPCUA-T11；`opcua_bad_size_neg` ≡ T-OPCUA-T13；`opcua_no_channel_neg` ≡ T-OPCUA-T14。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接多对服务（#6 五对、#10 三对、#2 两对）→ 多轮 Read 连续 | 已覆 #6/#10/#2 |
| ② | 非正常结束 | 正常 FIN 全正例 + CLO 对；应用层正常终止 = CLO；传输异常 = RST（框架 tcp 层能力） | 已覆（CLO 对全正例）；RST **A′ 立项**（G-OPCUA-6，本层零断言） |
| ③ | 长保活 | 协议层无 keepalive 心跳；订阅 keep-alive = 发布空转（#6 帧 16/17，size 85 vs 带通知 102） | 已覆 #6 |

无空项：① 有已覆例；② 有已覆例 + 1 条 A′ 立项；③ 有 #6。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| field 断言面 | 收编 tshark `opcua.*` 字段（`transport.size`/`servicenodeid.numeric`/`transport.type`）——今日零使用 | G-OPCUA-3 |
| ServiceResult 面 | #7/#8 收窄为 offset 94 精确断言（本轮已实测复核） | G-OPCUA-3 |
| TypeId 修复 | M-1：SetPublishingMode 791/792 → 799/802 + 响应侧统一 Encoding 值 | G-OPCUA-9 |
| 拒绝分支面 | `bad_length` 单独 / `security_mode` 非法 / 空 `node_ids` / NodeId 解析两分支 / `error_inject.op` 未知值 | G-OPCUA-7 |
| 上限面 | MessageSize UInt16 上限（65535） | G-OPCUA-7 |
| 关闭面 | `close=false`（少 CLO 对） | 设计 §8 |
| 端口面 | `dst_port` 缺省补齐 4840 | 设计 §8 |
| 地址族面 | 异族混写拒绝 | 设计 §8 |
| 订阅面 | 单周期无 keep-alive（`publish_count=1`） | 设计 §10.3 #19 |
| EndpointUrl 面 | 非空 EndpointUrl（`BuildHEL` 支持入参） | 设计 §10.3 #2 |
| NodeId 面 | String/Guid/Opaque 编码 | G-OPCUA-5 |
| 多会话面 | 每会话独立令牌 + 交错调度 | G-OPCUA-2 |
| 非正常结束 | `tcp.rst` 补例 | ② 的 A′（G-OPCUA-6） |

**B′（框架面）**：`CheckProtoFlat` opcua presence 分支 + 游离顶层键通用门（G-OPCUA-1，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态（G-OPCUA-3，allowlist 无 `opcua` 行）/ 负例 `notes` 键收窄（G-OPCUA-7）。进设计 §14，「明确不解决 + 迁入计划」。

### 6.3 3.14 豁免边界审计

**有长连接载体（TCP）→ `sessions[]` 不豁免**（设计 §12.3 会话表 s1/s2；本协议 `sessions` 是**层内结构选择器**（连续 N 对 Read），不是 `sessions[]` 数组——**形态差异已声明**，G-OPCUA-2）；多流并发由策略级 `flow_control {"flows": N}` 承载（本版 12 例未用，存量单 flow）；**单包多载荷** = **不适用**（OPC UA 每消息一个服务体，无多 question/多 RR 类形态，如实声明）。

## 7. 实现后执行建议

1. **P4 顺序**：①先修 M-1（`planner.go:103` → `add(799, 802, …)`）与 G-OPCUA-9（响应侧 Encoding 值），重跑后钉 #6 帧 12/13 TypeId；②补 A′ field 断言（收编 `opcua.*`）；③补 A′ 拒绝分支例；④全量复跑。**本协议无 §1 迁移步骤**（顶层零残留）。
2. **实测顺序**：先 #1（HEL/ACK MessageSize 32/28 基线），再 #2（OPN 令牌复用 62/66 锚点），再 #4/#5（服务体长度 81/100），再 #6（订阅五对 + 通知/keep-alive size 差），最后 #9（IPv6 offset 74）、#10（多会话三对）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=opcua` 全量不是增量）；门2④ 反查绿后进 P6。
4. 任何 Part 6/Part 4 条款号的具体引用须有规范原文证据（G-OPCUA-8 纪律）。

## 8. 存量审计（12 例逐条去向）

### 8.1 存量实测面（2026-09-28）

`cases/opcua.json` **12 例**：10 正带 `packet_count`（13/15/13/15/15/23/15/15/19/15），**与实测 pcap 帧数 10/10 逐例一致**（`tshark -r … | wc -l`）；2 负 `expect` 键集合 `{expect_error,error_contains,notes}`，实测 pcap 均 **0 帧**；12/12 顶层键仅 `{layers}`（**零残留**）；48 条 frame 断言逐条对实测 pcap 复核（**全 OK**）；层内 `opcua` 已带 11 键（与 registry Fields 逐键一致，机读实测）。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **旧稿包数全错**：25-design §6 速查表（11/13/13/21）与实测（13/15/13/23）不符——旧稿漏算 CLO 响应与 FIN 包。本版 §1 按实测公式钉死，JSON 今日即正确。
2. **旧稿"CLO 无响应"与实测相反**：实测 CLO 请求/响应各一帧（帧 18/19，均 size 59）。旧稿 §4.1 引 Part 4 §5.13.3 支撑该结论——**条款原文未核对**，列 G-OPCUA-8；本版按实现钉。
3. **旧稿 T4/T8 是虚例**：文档列 T1–T14 十四条，JSON 只有 12 例（T4 Read 合并入 T2、T8 keep-alive 合并入 T7）。本版 §2 以 12 个唯一语义 ID 为准，T4/T8 保留为对照编号。
4. **旧稿"无 tshark dissector"已反转**：本机 3.6.14 有 opcua dissector（442 字段 + 4840 端口绑定），12 例 pcap 全解码、零 malformed。今日 12 例仍全走 frames——**不是被迫，是未收编**（A′ G-OPCUA-3）。
5. **M-1 confirmed 缺陷**：SetPublishingMode TypeId 791/792 指向的是 `ModifySubscriptionRequest`（不是 SetPublishingMode 的正确线上 id；正确为官方 Encoding 797/800、tshark 表 799/802）。成因是按 `+4` 自增规律推出。设计 §9.2 已立项。
6. **`sessions>1` 语义与旧稿不符**：实现为连续 N 对 Read，无独立令牌/独立 handle 空间/交错（G-OPCUA-2）。
7. **负例 `notes` 键**：2 负例 expect 含 `notes`，与严格两键口径不符（G-OPCUA-7）。
8. **存量 `expect.notes` 文案与实现相反（2 条，C-6）**：`opcua_multi_session` 的 notes 称三对 Read "**interleaved**" 且 "each keeps its own AuthenticationToken and RequestHandle space"——实测**连续非交错**、三对 @82 全 `01 00 00 00`、handle 2/3/4 共用计数器；`opcua_subscribe` 的 notes 称 "CLO … **has no CLO response**"——实测帧 18/19 均 `CLOF` size 59。**本文档 §3.10/§3.6 已诚实声明事实，但存量 JSON 的 notes 字段本身仍是错的**，P4 必须改写（G-OPCUA-2/G-OPCUA-7 的 P4 动作已列）。
9. **存量未覆盖**：`bad_length` 单独、`security_mode` 非法、`security_mode` 缺省、NodeId 非法/越界、空 `node_ids`、`close=false`、缺省端口、异族混写、单周期订阅、非空 EndpointUrl、MessageSize 上限、RST**今日零用例**（A′ 补）。
10. **结果文档过期（G-OPCUA-10）**：tracked 结果产物 `trafficgen/docs/protocol-pcap-test/opcua.md` 写 "Cases: 12 — pass 12, fail 0, error 0"，但末次提交 `91f2487`（**2026-08-30**）早于判死提交 `0417be5`（2026-09-13）；`docs/protocol-pcap-test/opcua/` **0 个 pcap**（目录根本不存在）。故该 12/12 **是过期产物、未经今日复跑证实，不得作为"今日已复跑"依据**。**opcua 特殊性（须写清，不得夸大）**：opcua 是本批**唯一已合规**的协议（12/12 顶层键仅 `{layers}`，§1），其 12 例**今日仍应可跑**——本缺口**不是**"不可跑"，而是"**数字未经今日复跑证实 + 无 pcap 留档**"；本车道未跑该套件，故不以任何形式引用该产物。归属**代码阶段**（P5 重跑套件后重生成该产物）。

### 8.3 逐条去向表（12 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `opcua_hello_ack` | T1 | **保留** | 形状已合规（纯 layers）；可补 `opcua.transport.*` field 断言 |
| `opcua_open_none` | T2 | **保留** | 同上；可补 `transport.size=111` + `servicenodeid.numeric=631` |
| `opcua_open_sign` | T3 | **保留** | 同上；可补 @129 SecurityMode=2 断言（替代当前仅靠帧位） |
| `opcua_write` | T5 | **保留** | 同上；可补 `transport.size=81` |
| `opcua_browse` | T6 | **保留** | 同上；nodeClassMask/resultMask 取值断言另立 A′ |
| `opcua_subscribe` | T7 | **改写** | 帧 12/13 TypeId 按 M-1 修复后重钉（791/792→799/802） |
| `opcua_bad_node` | T9 | **改写** | 收窄为 offset 94 = `00 00 34 80` 精确断言（本轮实测复核） |
| `opcua_denied` | T10 | **改写** | 收窄为 offset 94 = `00 00 1f 80` 精确断言（本轮实测复核） |
| `opcua_ipv6` | T11 | **保留** | 形状已合规；可补 `ipv6.src/dst` field 断言 |
| `opcua_multi_session` | T12 | **保留** | 断言口径收窄说明（不断言状态隔离，G-OPCUA-2） |
| `opcua_bad_size_neg` | T13 | **保留** | 删 `notes`；补 `bad_length` 单独例（A′） |
| `opcua_no_channel_neg` | T14 | **保留** | 删 `notes` |

无"作废不注原因"：0 作废，0 等价覆盖（12 例全部保留/改写 + A′ 新增）。**本协议存量 12/12 顶层零残留**（与 ftp/ldap/jt808 等共 27 个协议同为纯层链形，**非全仓唯一**；见设计 §12.1 注）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

建议在主线程合入后，于 `coverage_gate.py` 的 opcua 段登记下列断言（**每条均可从本契约与 cases JSON 直接机读，不需新造事实**）：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['opcua']) == 12` 且 ID 集合 = §2 十二项，顺序一致 | 本契约 §2 |
| 2 | 12/12 例 `spec_json` 顶层键 ⊆ `{layers}`（**本协议零游离键**） | 本契约 §1；设计 §12.1 |
| 3 | 10 正例 `packet_count == 13 + 2×服务对数`（服务对数由 spec 推出） | 设计 §9 公式 |
| 4 | 2 负例 `expect` 键 == `{expect_error, error_contains}`（P4 删 `notes` 后） | 本契约 §4 |
| 5 | 负例 `error_contains` ∈ 代码锚词集 `{"MessageSize", "secureChannel", "String length", "security_mode", "sessions", "node id"}` | 设计 §7 |
| 6 | 非负例顶层键计数 == 0（**今日已成立**） | 设计 §12.1 |
| 7 | 每正例至少一条 frames 断言落在 offset 54（IPv4）或 74（IPv6） | 本契约 §3 |
| 8 | M-1 修复后：`opcua_subscribe` 帧 12/13 TypeId ∈ `{799, 802}` | 设计 §9.2 |

**另注意**：`docs/protocol-pcap-test/opcua.md` 的 12/12 pass 是**过期产物**（G-OPCUA-10，末次提交 `91f2487` 2026-08-30 早于判死提交 `0417be5` 2026-09-13；`docs/protocol-pcap-test/opcua/` 0 个 pcap），**不得作为"今日已复跑"依据**（口径与 pcep 车道 G-PCEP-11 一致）。**但 opcua 是本批唯一已合规协议（12/12 顶层键仅 `{layers}`），12 例今日仍应可跑**——该提醒**仅限**"数字未经今日复跑证实 + 无 pcap 留档"，**不得读成"套件不可跑"**。

## 10. 修订记录

- v1.0.1（2026-09-28，小补登记）：§8.2 新增第 10 条 **G-OPCUA-10**（结果文档过期）——`docs/protocol-pcap-test/opcua.md`（tracked 产物）写「12 — pass 12」是**过期产物**（末次提交 `91f2487` 2026-08-30，早于判死提交 `0417be5` 2026-09-13；`docs/protocol-pcap-test/opcua/` **0 个 pcap**），**未经今日复跑证实，不得作为"今日已复跑"依据**；§9 表末加同口径提醒句；粒度声明缺口范围 `G-OPCUA-1…G-OPCUA-9` → **`…G-OPCUA-10`**；配套设计版本 `v1.0.0` → `v1.0.1`。**本缺口不代表 opcua 不可跑**——opcua 为本批唯一已合规协议（12/12 顶层键仅 `{layers}`，§1），12 例今日仍应可跑；本车道未跑该套件，登记仅限"数字未经今日复跑证实 + 无 pcap 留档"。口径对齐 pcep 先例 G-PCEP-11。仅文档，未动 JSON/代码。自审 1 轮，末轮干净。
- v1.0.0（2026-09-28）：P-PIPE #101 文档轨 P1–P3。**承 25-opcua-testcase 的 12 ID / 锚词 / 断言思路**；形状基线机读实测（§1，**顶层零残留**）；48 条 frame 断言逐条对实测 pcap 复核（全 OK）；包数公式 `13+2×服务对数` 与实测 10/10 一致；冲突处按实测/代码改正（旧稿包数全错、CLO 有响应、tshark dissector 存在、T4/T8 虚例、ServiceResult 偏移收窄、M-1 TypeId 缺陷）；P3 固定动作（§6）；执行建议（§7）；存量审计（§8，12/12 保留或改写）；覆盖反查门建议断言行（§9）。自审见 `/tmp/pipe/doc-lanes/opcua.md`。

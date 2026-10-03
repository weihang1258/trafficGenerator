# #101 opcua（OPC UA · 工业互操作统一架构，二进制协议 TCP 4840）设计契约

> 版本：v1.0.1（P-PIPE 文档轨 P1–P3 + 结果文档过期登记；修订记录见 §15）
> 日期：2026-09-28
> 车道：文档轨（#101 opcua 续号）
> 旧基线：`docs/protocol-designs/25-opcua-design.md` v1.0.0 + `25-opcua-testcase.md` v1.0.0（12 例 = 10 正 + 2 负；本 #101 为 P-PIPE 续号重做，**承 25-opcua-design 审计通过的分层模型、MessageHeader 布局、NodeId/Variant 编码表、RequestHeader 字段序、订阅链路顺序、AttributeId/枚举表**，不搬旧稿的过时状态声明与错误数字，逐条见 §0）
> 存量用例：`trafficgen/test/protocol_pcap/cases/opcua.json`（12/12 ID 与旧稿一致，顺序一致，已机读实测；**顶层键已是纯层链形，零残留**——本协议无 §1 迁移工作量，见 §12.1；全仓另有 26 个协议同为此形，见 §12.1 注）
> 规范基线：① OPC UA Part 6（UA Binary 线格式：MessageHeader / SecureConversationMessageHeader / 内置类型编码，下称 **spec**）；② OPC UA Part 4（服务定义与 RequestHeader/ResponseHeader）；③ OPC Foundation `UA-Nodeset` 官方 `NodeIds.csv` / `StatusCode.csv`（**NodeId 与 StatusCode 取值的唯一权威**，2026-09-28 拉取实测，§3.5/§9.1）；④ 本机 tshark 3.6.14 `opcua.*` 字段表与 12 例实测 pcap（`/tmp/mcp-pcaps/opcua/`，包数与偏移的唯一权威）；⑤ 本仓库落码（`internal/protocol/opcua/` 五文件 + 接线，§11）；⑥ 旧基线设计文档（内部契约，非外部规范）
> 白话一句：**工业设备的"通用电话系统"——先握手（HEL/ACK 报缓冲大小），再开一条安全通道（OPN 领令牌），然后在这条通道上打电话（MSG：读、写、浏览、订阅），最后挂断（CLO）。所有数字都是小端。**

## 0. 25→101 沿革与旧稿校正声明（门1 必答：基线继承关系）

本 #101 与旧稿 `25-opcua-*` 是**同一协议的续号契约**，不是新协议。旧稿归档在磁盘，仅作只读历史参考。审计逐条给出校正结论（区分"承旧稿"与"旧稿过时"）：

| # | 旧稿说法（25-*） | HEAD 实测（2026-09-28） | 校正结论 |
|---|---|---|---|
| 1 | design 11 章、testcase 5 章；无沿革章、无门1 十四行表、无 P1 规范矩阵三子表、无动态清单、无性能验收两路、无五件套、无缺口清单 | — | **结构缺口**，本版按 §10/§12/§6/§12.12/§12.3/§14 补齐 |
| 2 | "实现状态：**设计阶段，尚无 OPC UA Go 生成器或层注册**"（design 头注）；"`internal/protocol/opcua/`、`OPCUAConfig` 均是计划接口" | 五文件已落码共 **1135 行**：`builder.go` 501 / `planner.go` 230 / `opcua_test.go` 345 / `layer_gen.go` 48 / `types.go` 11（`wc -l` 实测）；13 个 `Test*` 函数（`grep -c` 实测）；`registry.go:720` 已注册 | **旧稿"设计阶段"已过时**；本版 §11 为 as-built 逆向定稿 |
| 3 | §5.1/§8.1："层注册，规划中"，"配置零负载（layer 条目不携带字节），全部携带在 `spec.OPCUA`" | `registry.go:720` 已注册 `opcua`（`CategoryTerminal`，`DependsOn ["tcp"]`，**Fields 11 键**）；生成表 127 层中 `opcua` 条目字段与 registry 逐键一致（机读实测） | **旧稿"零负载/规划中"已过时**：层内已有 11 个可住字段，且 translate 已接线（#4） |
| 4 | §5.3/§8.3："`strategy_convert.go` 新增 `case "opcua"`……规划中" | `strategy_convert.go:1645` 已有 `case "opcua"`（顶层子映射 → `spec.OPCUA`）；`chain_planner_translate.go:1891` 已有 `case "opcua"`（**层内 config → `spec.OPCUA`**）；`protocols.go:50` `"opcua": true`；`chain_planner.go:1025` 缺省目的端口 4840；`:750` 端口语义白名单含 opcua | **平面接线与层内化均已通**；"规划中"作废 |
| 5 | §5.6 三例 JSON 用 `{"strategy":{"type":"custom","layers":[...]},"spec":[...]}` 形；§8.2.3 用顶层 `opcua` 子映射形 | 存量 12 例机读：12/12 顶层键 = `{layers}`（**仅此一键**），层链 `[tcp,opcua]` ×11 + `[ip,tcp,opcua]` ×1 | **旧稿两种样例形均已作废**（一种是策略包装形、一种是过渡态违规形）；本版 §2 只给纯层链形，且**存量已达标** |
| 6 | §6 S1/S2/S3/S5 包数速查表：S1 仅握手 11 / S2 OPN 13 / S3 Read 13 / S5 订阅 21 | 12 例实测 pcap 帧数：hello_ack **13** / open_none **15** / open_sign **13** / write **15** / browse **15** / subscribe **23** / bad_node **15** / denied **15** / ipv6 **15** / multi_session **19**；JSON `packet_count` 与 pcap **10/10 逐例一致**（机读对账） | **旧稿包数全错**（漏算 CLO 响应与 FIN 包）；本版 §9 按 JSON/pcap 钉死 |
| 7 | §4.1 称"CLO 无响应（Part 4 §5.13.3），CLO 后直接 FIN"；§6 S5 序列写"包 22 CLO → 包 23 FIN" | 实测：CLO 是**对称 MSG 家族的一对**——请求包 + 响应包（两帧均 `CLOF` size 59），之后才是 FIN 四包（`hello_ack` 帧 8/9 = CLO 对，帧 10-13 = FIN） | **旧稿"CLO 无响应"与实测不符**（与 Part 4 原文对照列为 G-OPCUA-8）；本版 §5 按实测 |
| 8 | §4.2 安全策略矩阵：None → PolicyUri 70B（`#None` URI）、证书双 null；Sign → PolicyUri 102B + 证书 512B/20B 占位 | 实测 OPN 包体**恒 79 字节**（MessageSize **87** = 79+8；以太帧 141 = 54+87）：PolicyUri / SenderCertificate / ReceiverCertificateThumbprint **三个字符串全部写成长度 0 的空串**（`builder.go:125-126`）；None 与 Sign 的**唯一差异**是请求体 SecurityMode 字段（@129）`01 00 00 00` → `02 00 00 00` | **旧稿"PolicyUri 70B/证书占位"未实现**（旧稿是设计意图，代码未落）；本版 §3.4 按代码+实测钉，差异列 G-OPCUA-4 |
| 9 | §3.3 RequestHeader：`AuthenticationToken` 无会话时 TwoByte 0（**2B**）、AdditionalHeader null（**2B**） | 代码 `putRequestHeader`（`builder.go:85-95`）写 **FourByte** NodeId（4B `01 00 00 00`）+ timestamp 8B + handle 4B + returnDiagnostics 4B + auditEntryId null 4B + timeoutHint 4B + additionalHeader null **3B**（TwoByte NodeId 2B + encoding 1B）= **31B**；实测 @82 `01 00 00 00` 4B | **旧稿字段尺寸错**（2B→4B、2B→3B）；本版 §3.3 按代码逐字节 |
| 10 | §3.4/§10.3 Browse：`NodeClassMask` 默认 **0x3F**（Object\|Variable\|Method\|…）、`ResultMask` 0x3F | 代码 `browseRequestBody`（`builder.go:292-294`）：nodeClassMask 写 **0**，resultMask 写 **63**（0x3F） | **旧稿把 nodeClassMask 默认值写错**（0x3F 只对 resultMask 成立）；本版 §3.6 按代码 |
| 11 | §3.4 Read：`MaxAge` Duration UInt32、`TimestampsToReturn` 枚举 Int32 | 代码 `readRequestBody`（`builder.go:193`）：MaxAge 写 **Double 8B**（0.0），timestampsToReturn 4B = 0 | **旧稿 MaxAge 类型错**（UInt32→Double）；本版 §3.5 按代码 |
| 12 | §1.4 服务清单：Read=629、Write=671、Browse=525、CreateSubscription=785、CreateMonitoredItems=749、SetPublishingMode=797、Publish=824、OpenSecureChannel=446、CloseSecureChannel=450；§2.8 明言"本设计统一用 FourByte 编码" | 实测 TypeId 与官方 `NodeIds.csv` **DataTypes 列**逐条一致（446/452/631*/673/527/751/787/826）；但旧稿把 **DataType id 与 DefaultBinary Encoding id 混用**（Read=629 是 DataType，线上必须写 631）；**SetPublishingMode 实际写 791/792**，官方为 **797/800** | **旧稿表内混用两类 id**；SetPublishingMode 取值见 M-1（§9.2）——**该对是全表唯一"指向了另一个服务"的取值**（791/792 确实存在于官方 NodeIds.csv 与 tshark 表中，但属 `ModifySubscriptionRequest`；其余响应侧偏差是同服务的 DataType/Encoding 口径差异，见 G-OPCUA-9） |
| 13 | §9.1 StatusCode 表：`BadSecurityModeRejected 0x80890000`、`BadSecureChannelIdInvalid 0x80870000` | 官方 `StatusCode.csv` 实测：**BadSecurityModeRejected = 0x80540000**、**BadSecureChannelIdInvalid = 0x80220000**（`Good/BadUserAccessDenied/BadNodeIdUnknown` 三值旧稿正确） | **旧稿两个取值臆造**；本版 §9.1 按官方 CSV |
| 14 | testcase §4.1："**OPC UA 的 tshark 字段名在当前 Wireshark 树中不存在**（gitlab 当前树无 packet-opcua.c 解析器）"，故"MessageHeader 断言一律用 FrameAssert" | tshark **3.6.14 有 opcua dissector**：`tshark -G fields` 中 `opcua.*` **442 字段**；`tshark -G decodes` 有 `tcp.port 4840 opcua`；12 例 pcap 全部被解码（`_ws.col.Protocol = OpcUa`，`frame.protocols` 含 `:opcua`），**零 malformed** | **旧稿"无 dissector"已过时**（可能是旧版本 tshark 或未按端口绑定时的结论）；本版 §1 给出可用字段通道，A′ 立项把 field 断言补起来（G-OPCUA-3） |
| 15 | testcase §1.2 表列 **T1–T14** 十四条；§2.4 T4、§2.8 T8 自述"已合并到 T2/T7，不再独立成 JSON 用例" | JSON 实测 **12 例**；T4/T8 无独立 id | **旧稿"14 例"是虚数**（含 2 个仅存于文档的引用锚点）；本版 §9 以 12 个唯一语义 ID 为准 |
| 16 | §9.3/§9.4 负例 `bad_message_size` / `skip_channel` 语义："字节仍完整能发出，靠 tshark 告警捕获" | 代码 `planner.go:30-38`：两者均在 **Validate 阶段直接拒绝**（`opcua: MessageSize is invalid` / `opcua: secureChannel is required before MSG service`），**不产流**；实测两例 pcap 均 0 帧 | **旧稿"字节能发出"与实现相反**；本版 §7 按"Validate 拒绝、零包、传 task error"钉死 |
| 17 | design §7 / testcase §1.2 引用 `docs/protocol-designs/audit/25-opcua-adversarial-audit.md` | 该目录**不存在**（`ls audit/` 实测：No such file or directory）；`INDEX.md:119` 同引 | **死引用**（与 ldp/someip 车道同款）；本版不复制该死引用 |

**依赖链判定纪律**：以上均为可判题（旧文→官方 CSV/代码/pcap 三级对照），直接判定，不问偏好。不可判的（Part 6 §7.1.2.x 条款号逐条对应、CLO 响应是否合规）标"待确认"并写清确认方式（G-OPCUA-8）。

**产物过期登记（重要，G-OPCUA-10）**：`trafficgen/docs/protocol-pcap-test/opcua.md`（**tracked 结果产物**，`git ls-files` 可证）写 "Cases: 12 — pass 12, fail 0, error 0"，但该文件末次提交 `91f2487`（**2026-08-30**），**早于**判死提交 `0417be5`（2026-09-13，扁平判死泛化全协议 `CheckProtoFlat`）；`docs/protocol-pcap-test/opcua/` 目录**根本不存在（0 个 pcap 文件）**。**该结果文档是过期产物，12/12 pass 未经今日复跑证实，不代表今日已复跑**——读者不得据此判断套件已复跑。

**opcua 特殊性（须写清，不得夸大）**：opcua 是本批**已合规的协议之一**（12/12 例 `spec_json` 顶层键仅 `{layers}`，机读实测；全仓另有 26 个协议同形），故其 12 例**今日仍应可跑**。本缺口**不是**"不可跑"登记，而是"**12/12 数字未经今日复跑证实 + `docs/protocol-pcap-test/opcua/` 无 pcap 留档**"。本车道**未跑**该套件，故本文档**不以任何形式**（含"今日已跑通"）引用该产物作为套件可跑证据。

## 1. 范围、profile 与实现状态边界

本版定义 **OPC UA Binary（Part 6 定义的紧凑线格式）承载于 TCP 4840** 的流量生成：传输层问候（HEL/ACK）、安全通道建立（OPN）、对称段服务调用（Read/Write/Browse/订阅家族）、关闭（CLO）。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `opcua_tcp_v1`（主） | TCP，fixture 4840 | HEL/ACK → OPN → MSG 服务对 → CLO 对 → FIN | 真实服务器语义（节点是否存在、权限） |
| `opcua_sign_v1` | 同上，仅 `security_mode="sign"` | 同上（**仅请求体 SecurityMode 字段取 2**） | 真实 RSA-PSS 签名/证书可用性（§3.4 诚实边界） |
| `opcua_ipv6_v1` | 同上，仅外层 IPv6 | 同上 | 从 IPv4 fixture 推导 IPv6 地址 |

**显式边界（当前缺口均登记，不冒充支持）**：① 当前 Sign 只改 SecurityMode 枚举，真实证书/签名列 G-OPCUA-4；② 当前每消息恒为单 final 块，分段/重组列 G-OPCUA-12；③ 当前不实现 CreateSession/ActivateSession，列 G-OPCUA-11；④ 当前仅支持 opc.tcp/TCP 4840，HTTPS/WebSocket 列 G-OPCUA-13；⑤ 当前未实现 PubSub，列 G-OPCUA-14；⑥ NodeId 当前只支持 FourByte，列 G-OPCUA-5；⑦ 不实现超 UInt16 的 MessageSize（`builder.go:17` 上限守卫）。

**实现状态（2026-09-28 实测）**：`opcua` 层已注册（`registry.go:720`，`CategoryTerminal`，`DependsOn ["tcp"]`，Fields 11 键）；planner/builder/生成器已落码（`internal/protocol/opcua/` 五文件 1135 行）；`allowedProtocols["opcua"]=true`（`protocols.go:50`）；层内 translate 已接线（`chain_planner_translate.go:1891`）；缺省目的端口 4840（`chain_planner.go:1025`）；12 语义用例已落 `cases/opcua.json` 且 pcap 实测在案。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport/srcport`、`tcp.flags`、`opcua.*` 字段、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, opcua]`（引擎自动补 `ip`；最小链 `[tcp, opcua]`）。opcua 报文是 TCP payload 的应用层字节流，**由 tcp 层负责分段与握手挥手**。

端口：OPC UA `opc.tcp://` 默认 **TCP 4840**（planner 缺省已落码 `chain_planner.go:1025`）。fixture 统一 `dst_port=4840`；用例一律显式写端口并纳入断言。

固定偏移：无 VLAN/IP options/TCP options 时，**每帧 OPC UA 消息头起点为 IPv4 offset 54**（14+20+20）、**IPv6 offset 74**（14+40+20）。消息内字段偏移按 §3.1 头布局递推；**变长字段之后的偏移不稳**（§3.3 注）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**本协议存量 12 例已是此形，无需迁移**）：

```json
{
  "layers": [
    {"tcp": {"dst_port": 4840}},
    {"opcua": {"security_mode": "none", "read": [{"node_ids": ["ns=0;i=1001"], "attribute_id": 13}], "close": true}}
  ]
}
```

多流样例（数量只走 `flow_control`；本协议存量未用，四元组留空走 worker 保底递增 §12.12）：

```json
{
  "layers": [
    {"tcp": {"dst_port": 4840}},
    {"opcua": {"security_mode": "none", "read": [{"node_ids": ["ns=0;i=1001"]}]}}
  ],
  "flow_control": {"flows": 3}
}
```

## 3. 线格式编码（承 25 稿审计通过部分；冲突处按代码/实测钉）

### 3.1 MessageHeader（8 字节，承 25 稿 §2.2 审计通过）

| 偏移 | 字段 | 类型/尺寸 | 说明 |
|---|---|---|---|
| 0 | MessageType | 3 字节 ASCII | `HEL`/`ACK`/`ERR`/`OPN`/`CLO`/`MSG`/`RHE` |
| 3 | ChunkType | 1 字节 ASCII | 本实现**恒 `'F'`**（`uaFrame` 把 4 字节 kind 整体传入，`'HELF'`/`'ACKF'`/`'OPNF'`/`'MSGF'`/`'CLOF'`） |
| 4 | MessageSize | UInt32 **LE** | 整个消息（含 8B 头）的总字节数，由 `uaFrame` 一次写定 |

`uaFrame`（`builder.go:13-25`）：`out = 8 + len(body)`；`copy(out, kind)`；`binary.LittleEndian.PutUint32(out[4:8], uint32(len(out)))`。**两遍编码在此退化为一次**——body 先算全长，头后写。

**长度上限**：`len(body)+8 > 0xffff` 即拒（`builder.go:17`，锚词 `opcua: MessageSize %d exceeds UInt16`）。

### 3.2 NodeId 与 TypeId（承 25 稿 §2.8 掩码表；本实现只用 FourByte）

| 掩码 | 类型 | 布局 | 本实现 |
|---|---|---|---|
| `0x00` | TwoByte | id: Byte（ns=0） | 仅用于 **null TypeId / null ExtensionObject**（`b[0],b[1]=0x00,0x00`，`builder.go:273/387`）与 Browse 的 referenceTypeId（`0x00, 33`） |
| `0x01` | FourByte | ns: Byte + id: UInt16 LE | **服务 TypeId、AuthenticationToken、被读/被写/被浏览节点、monitoredItemId 全部用它**（`serviceNodeID`，`builder.go:58-62`） |
| `0x02`–`0x05` | Numeric/String/Guid/Opaque | — | **不实现**（`parseFourByteNodeID` 只接受 `ns=<int>;i=<int>`，§3.7） |

**文本 → 线格式**：`ns=N;i=M`（`parseFourByteNodeID`，`builder.go:66-79`）：`b[0]=0x01`、`b[1]=byte(ns)`、`b[2:4]=UInt16 LE(M)`；`ns>255` 或 `M>65535` 即拒。**注意**：即便 `ns=0` 且 `M<=255`（本可 TwoByte）也**统一写 FourByte**——这是本实现的固定选择，不是规范强制（实测 `ns=0;i=1001` → `01 00 e9 03`）。

### 3.3 RequestHeader（31 字节）与 ResponseHeader（24 字节）

**RequestHeader**（`putRequestHeader`，`builder.go:85-95`）——旧稿 §3.3 的尺寸已校正（§0 #9）：

| 偏移 | 字段 | 尺寸 | 实测值 |
|---|---|---|---|
| 0 | AuthenticationToken | NodeId **4B**（FourByte ns=0 id=0） | `01 00 00 00` |
| 4 | Timestamp | DateTime Int64 8B | `00 00 00 00 00 00 00 00`（未指定时刻） |
| 12 | RequestHandle | UInt32 4B | 2 起递增 |
| 16 | ReturnDiagnostics | UInt32 4B | 0 |
| 20 | AuditEntryId | String null 4B | `00 00 00 00` |
| 24 | TimeoutHint | UInt32 4B | 60000 |
| 28 | AdditionalHeader | ExtensionObject null **3B** | `00 00 00` |

**ResponseHeader**（`putResponseHeader`，`builder.go:104-111`）——**24 字节，比 RequestHeader 少 7**：

| 偏移 | 字段 | 尺寸 |
|---|---|---|
| 0 | Timestamp | DateTime 8B |
| 8 | RequestHandle | UInt32 4B（回显请求） |
| 12 | **ServiceResult** | StatusCode UInt32 4B |
| 16 | ServiceDiagnostics | DiagnosticInfo null 1B（`00`） |
| 17 | StringTable | String[] null 4B（`ff ff ff ff`） |
| 21 | AdditionalHeader | ExtensionObject null 3B（`00 00 00`） |

> **ServiceResult 是 ResponseHeader 的第 3 个字段，不是第 2 个**：`builder.go:97-103` 注释记载——早期版本漏写 ServiceResult，tshark 把 diagnostics mask 字节当成 ServiceResult 读出 `0xffffff00`，后续字段全体错位。这是本实现的一处**被 tshark 实证钉死**的布局（§9.2 复现）。

### 3.4 传输层与安全通道消息

**HEL**（`BuildHEL`，`builder.go:33-43`）：body 24B + EndpointUrl；`protocolVersion=0`、`receiveBufferSize=65536`、`sendBufferSize=65536`、`maxMessageSize=0`、`maxChunkCount=0`、`endpointUrl` 长度 4B + 字节（**本实现恒传空串**，`buildEvents` 调 `BuildHEL("")`）。空串 → **MessageSize 32**（以太帧 86），字段 = `20 00 00 00`（实测帧 4 offset 54）。

**ACK**（`BuildACK`，`builder.go:46-54`）：body 恒 20B（无 EndpointUrl）→ **MessageSize 28**（以太帧 82），字段 = `1c 00 00 00`（实测帧 5）。

**OPN**（`BuildOPN`，`builder.go:119-141`）：body 恒 **79B**，**MessageSize 87**（= 79+8；以太帧 141 = 54+87）：

| body 偏移 | 字段 | 值 |
|---|---|---|
| 0 | SecureChannelId | 请求 0 / 响应 1 |
| 4–15 | securityPolicyUri / senderCertificate / receiverCertificateThumbprint | **三个长度 0 空串**（12B，`builder.go:125-126`） |
| 16 / 20 | SequenceNumber / RequestId | 1 / 1 |
| 24 | TypeId NodeId | 446（FourByte） |
| 28 | RequestHeader | 31B（handle=1） |
| 59 / 63 | clientProtocolVersion / requestType | 0 / 0（ISSUE） |
| 67 | **SecurityMode** | `01`（none）/ `02`（sign）——**Sign 与 None 的唯一差异** |
| 71 / 75 | clientNonce（null） / requestedLifetime | 0 / 3600000 |

**诚实边界（Sign 模式）**：旧稿设计的"PolicyUri 70B/102B + 证书 512B/20B 占位"**未实现**（§0 #8）。今日 Sign 只是把 SecurityMode 枚举从 1 改成 2，**不产证书、不算签名、不改安全头长度**。本版**不声称**该路径产出的流可被真实服务器验证。

**CLO**（`BuildCLO`，`builder.go:165-171`）：对称头（16B）+ TypeId 452 + RequestHeader(31) = body 51B，**MessageSize 59**（以太帧 = 54+59 = 113；此 113 是**以太帧长**，与 §8 的最大 **MessageSize** 113 数值巧合、口径不同）；`buildEvents` 发**请求 + 响应各一帧**（§5、§0 #7）。

### 3.5 服务请求体（逐服务，按代码钉）

**ReadRequest**（`readRequestBody`，`builder.go:186-214`）：body = RequestHeader(31) + **maxAge Double 8B**（旧稿写 UInt32，§0 #11）+ timestampsToReturn 4B + ReadValueIds 数组长度 4B + 每项 **18B**（NodeId 4B + attributeId 4B + indexRange null 4B + **null QualifiedName 6B**）。总长 = `47 + 18n`。
> **null QualifiedName 是 6 字节不是 1**（`putNullQualifiedName`，`builder.go:177-180`）：ns UInt16(2) + name String null(4)。`builder.go:175-176` 注释记载 tshark 会把裸 `0x00` 解成 bogus Id。

**ReadResponse**（`readResponseBody`，`builder.go:219-225`）：ResponseHeader(24) + results 数组（每项 status UInt32 4B，**恒 Good**）+ null 诊断数组 4B = `32 + 4n`。
> **注入的错误走 ResponseHeader.ServiceResult，不走 results[]**：`builder.go:216-218` 注释明写（§7）。

**WriteRequest**（`writeRequestBody`，`builder.go:231-256`）：RequestHeader(31) + NodesToWrite 长度 4B + 每项 **18B**（NodeId 4B + attributeId 4B + indexRange null 4B + DataValue：encoding mask `0x01` 1B + Variant mask `0x06`（Int32）1B + Int32 值 4B）= `35 + 18n`。**WriteResponse 复用 `readResponseBody`**（`writeResponseBody`，`builder.go:260-262`）。

**BrowseRequest**（`browseRequestBody`，`builder.go:269-298`）：RequestHeader(31) + View（TwoByte NodeId 2B + timestamp 8B + viewVersion 4B = 14B）+ maxRefs 4B + 数组长度 4B + 每项 **19B**（NodeId 4B + direction 4B + referenceTypeId TwoByte 2B（`0x00,33`）+ includeSubtypes 1B + **nodeClassMask 4B = 0** + resultMask 4B = 63）= `53 + 19n`（旧稿 nodeClassMask 0x3F 已校正，§0 #10）。

**BrowseResponse**（`browseResponseBody`，`builder.go:303-316`）：ResponseHeader(24) + 数组长度 4B + 每项 12B（status 4B + continuationPoint null 4B + references null 4B）+ null 诊断 4B。

### 3.6 订阅家族请求体

| 服务 | 编码函数 | 长度公式 | 关键字段 |
|---|---|---|---|
| CreateSubscriptionRequest | `createSubRequestBody` (`builder.go:322-335`) | 恒 53 | RequestHeader(31) + requestedPublishingInterval **Double 8B** + lifetimeCount 4B（恒 10000）+ maxKeepAliveCount 4B（**0 → 10 兜底**）+ maxNotifications 4B(0) + publishingEnabled 1B(1) + priority 1B(0) |
| CreateSubscriptionResponse | `createSubResponseBody` (`:340-352`) | 恒 44 | ResponseHeader(24) + subscriptionId 4B(1) + revisedPublishingInterval Double 8B + revisedLifetime 4B + revisedKeepAlive 4B |
| CreateMonitoredItemsRequest | `createMonRequestBody` (`:360-397`) | `43 + 42n` | RequestHeader(31) + subscriptionId 4B(1) + timestampsToReturn 4B(0) + 数组长度 4B + 每项 42B（ReadValueId 18B + monitoringMode 4B(**2=Reporting**) + clientHandle 4B(i+1) + samplingInterval Double 8B + filter null ExtObj 3B + queueSize 4B(1) + discardOldest 1B(1)） |
| CreateMonitoredItemsResponse | `createMonResponseBody` (`:403-422`) | `32 + 21n` | ResponseHeader(24) + 数组长度 4B + 每项 21B（status 4B + monitoredItemId NodeId 4B + revisedSamplingInterval Double 8B + revisedQueueSize 4B + filterResult null 1B）+ null 诊断 4B |
| SetPublishingModeRequest | `setPubModeRequestBody` (`:426-433`) | 恒 40 | RequestHeader(31) + publishingEnabled 1B(1) + SubscriptionIds 长度 4B + id 4B(1) |
| SetPublishingModeResponse | `setPubModeResponseBody` (`:438-445`) | 恒 33 | ResponseHeader(24) + 长度 4B(1) + results **Boolean 1B**(`0x01`) + null 诊断 4B |
| PublishRequest | `publishRequestBody` (`:449-454`) | 恒 35 | RequestHeader(31) + Acknowledgements 数组 null 4B |
| PublishResponse（带通知） | `publishResponseBody` (`:463-487`) | 恒 **74** | ResponseHeader(24) + subscriptionId 4B(1) + availableSeqNumbers null 4B + moreNotifications 1B(0) + NotificationMessage（sequenceNumber 4B(1) + publishTime 8B + notificationData 长度 4B(1)）+ ExtensionObject（**TypeId FourByte 811** + encoding `0x01` + body 长度 4B(8) + DataChangeNotification：MonitoredItemNotifications 空数组 4B + diagnosticInfos null 4B）+ results null 4B + diagnostics null 4B |
| PublishResponse（keep-alive） | 同上非 0 分支 (`:488-500`) | 恒 **57** | 同上但 notificationData 数组 **null**、sequenceNumber = 2 |

> **DataChangeNotification TypeId = 811** = `DataChangeNotification_Encoding_DefaultBinary`（官方 `NodeIds.csv:623`），与本实现一致 ✓。

### 3.7 对称段消息封装

`BuildMSG`（`builder.go:155-161`）：body = 对称头 **16B**（SecureChannelId 4B + SecurityTokenId 4B + SequenceNumber 4B + RequestId 4B）+ TypeId NodeId 4B + 服务体。**没有额外的 encoding 字节**——`builder.go:152-154` 注释记载 tshark 的 dissector 直接从 TypeId 后走服务结构，加 encoding 字节会整体错位。

`msgHeader`（`builder.go:145-150`）：channelID=1、tokenID=0x3e8（1000）、seq/reqID 从 2 起**共用同一个递增计数器**（`buildEvents:204-220`：每帧 `seq++; reqID++`）——实测帧 8 seq=reqID=2、帧 9 = 3、帧 10 = 4。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明服务清单（read/write/browse/subscription）与安全模式，引擎按固定剧本产出事件序列（HEL→ACK→OPN 对→服务对→CLO 对），tcp 层负责握手挥手。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 会话建立与保活探测 | HEL/ACK 协商缓冲大小后立即关闭 | #1（`opcua_hello_ack`） |
| ② 无安全通道打开 | OPN(None) → 令牌复用进对称段 | #2（`opcua_open_none`） |
| ③ 带签名通道打开 | OPN(Sign) 结构路径 | #3（`opcua_open_sign`） |
| ④ 读变量（多节点） | Read 多 NodeId → 响应 | #2（含 2 节点）、#10（多会话各一节点） |
| ⑤ 写变量 | Write + DataValue → 结果数组 | #4（`opcua_write`） |
| ⑥ 浏览地址空间 | Browse ObjectsFolder 前向引用 | #5（`opcua_browse`） |
| ⑦ 订阅周期发布 | CreateSub→CreateMon→SetPubMode→Publish(通知)→Publish(keep-alive) | #6（`opcua_subscribe`） |
| ⑧ 权限/节点错误 | 响应 ServiceResult 注入坏码 | #7（`opcua_bad_node`）、#8（`opcua_denied`） |
| ⑨ IPv6 产线 | 同上，仅外层 IPv6 | #9（`opcua_ipv6`） |
| ⑩ 多逻辑会话 | sessions=3 连续 Read | #10（`opcua_multi_session`） |

**五层覆盖逐层结论**：功能层——传输层/安全通道/对称服务/订阅/关闭五类正例 + 拒绝分支 2 类负例（§7）；性能层——最小帧边界（ACK 28B/HEL 32B）、订阅最长序列（23 包）、多会话序列（19 包）、MessageSize UInt16 上限守卫；数据场景层——空载荷/二进制 b64/多节点/多会话/非默认枚举（Sign=2）/节点越界/长度错误；地址与流层——v4/v6 独立用例、单流基线、多会话（`sessions` 层内键）；**流关联（控制流派生数据流）显式不适用**：单 TCP 连接承载全部消息，无副连接；**多流（会话内并发流）显式不适用**：单连接串行收发，多流由策略级 `flow_control` 承载（本版未用）。业务层——十场景全部有落点。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① 真实签名/证书（未实现，G-OPCUA-4）；② 分段与重组（恒单 final 块）；③ CreateSession/ActivateSession 会话层（未实现，§3.3 用无会话令牌）；④ NodeId 的 String/Guid/Opaque 编码（未实现，G-OPCUA-5）；⑤ RST 异常中断（框架 tcp 层能力，本层零断言，A′ 补例 G-OPCUA-6）。

## 5. 消息/事务模型与状态机

**事务定义**：一次请求 + 一次响应（对称段一对 MSG，或 OPN 一对）。**多事务** = 一个连接内多对按序执行：#2（OPN 对 + Read 对）、#6（5 对订阅服务）、#10（3 对 Read）。

opcua 层无自有状态机：握手/挥手/分段在 tcp 层；opcua 层是"按配置顺序把服务翻译成事件"的纯函数驱动。

| 阶段 | 产出帧 | 用例 |
|---|---|---|
| 传输层 | HEL（up）+ ACK（down） | 全正例 |
| 安全通道 | OPN 请求（up）+ OPN 响应（down） | #2/#3/#4–#10 |
| 服务序列 | 每服务一对 MSG（up/down 交替） | #2/#4/#5/#6/#7/#8/#9/#10 |
| 关闭 | CLO 请求（up）+ **CLO 响应（down）** | 全 `close:true` 正例 |

**事件序（`buildEvents`，`planner.go:172-230`）**：`HEL(up)` → `ACK(down)` → `OPN(up, ch=0)` → `OPN(down, ch=1)` → 每服务对 `MSG(up)`/`MSG(down)` → 若 `Close`：`CLO(up)` + `CLO(down)`。**实测帧位**（hello_ack）：帧 4 HEL / 5 ACK / 6 OPN req / 7 OPN resp / 8 CLO / 9 CLO resp / 10–13 FIN 四包。

**服务选择优先级（`servicePairs`，`planner.go:85-168`，互斥 switch）**：① `subscription != nil` → 订阅五件套（CreateSub/CreateMon/SetPubMode/Publish×1..2）；② 否则 `len(Write)>0` → 每 op 一对 Write；③ 否则 `len(Browse)>0` → 每 op 一对 Browse；④ 否则 → Read：`sessions` 次（`sessions==0` 且 `len(Read)==0` → **无服务对**，即纯握手用例；`sessions==0` 且 `len(Read)>0` → 1 次；`sessions=N` → N 次，每次读 `Read[0]`，`Read` 空则读内置 `ns=0;i=2253`）。

**多会话展开（`sessions>1`）——诚实声明**：`sessions=N` 产出 **N 对连续 Read**（实测 `multi_session` 帧 8–13 = 3 对），**不是交错**；且 `buildEvents` 对每对用**同一份** `putRequestHeader`（AuthenticationToken 恒 FourByte ns=0 id=0，实测三对 @82 全为 `01 00 00 00`）、handle 顺序递增 2/3/4。**本实现没有"每会话独立 AuthenticationToken / 独立 RequestHandle 空间 / 交错调度"**——旧稿 §4.5/§6 S8 描述的分空间与交错是设计意图，未落码。用例 #10 的断言与实现一致（只断言 3 对 MSG 存在 + CLO），**本版不声称多会话状态隔离**（差异列 G-OPCUA-2）。

**自动派生规则**：① `security_mode` 缺省 `none`（`planner.go:20-22`）；② `cfg==nil`（空配置）→ 默认化 `security none + read + close`（`planner.go:15-18` 与 `layer_gen.go:29-31` 双默认，P0b-2）；③ OPN 响应 channelID 恒 1、tokenID 恒 1000（`planner.go:187-190` 常量）；④ TCP 握手/FIN 由 tcp 层自动补；⑤ `Close` 缺省 true → 恒发 CLO 对。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流全链 ≤23 帧（含握手挥手，订阅最长）；订阅 5 对服务为最大服务序列；多会话 3 对为最大服务对数；MessageSize 上限 UInt16（65535，`builder.go:17`）。吞吐数字待 P4 基准，**本版不写承诺**（§6.5）。
- **依据**：事件序列流式产出（`buildEvents` 返回切片，长度 = 4 + 2×服务对数 + 2，**与配置规模线性**，无全量包聚合）；每帧内存 = 该帧 MessageSize（最小 ACK 28B / HEL 32B；**最大 = 订阅 CreateMonitoredItems 请求 113**，见 §8）；无跨流共享状态；无锁（常量与局部变量）。
- **验收两路（§6.3 强制）**：pcap（`/tmp/mcp-pcaps/opcua/`，`<id>.pcap` / 负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `opcua.transport.*` 字段、帧原始 hex 与 `packet_count`，不只断言"任务没报错"。
- **六类场景落点（§6.6）**：基线（#1，13 帧）/ 目标规模（#6 订阅 23 帧）/ 压力上限（#2 多节点 Read + #10 多会话 19 帧）/ 长时间运行（订阅多周期展开承载语义）/ 并发交错（顺序多对承载语义，并发路径为例外不启用）/ 背压（`packet_count` 精确计数守卫帧数漂移 + MessageSize UInt16 守卫）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 planner/validator 拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功（实测两例 pcap 均 **0 帧**）：

| # | 负例 ID | 故障输入 | 代码锚词 | 代码行 |
|---:|---|---|---|---|
| N-1 | `opcua_bad_size_neg` | `bad_message_size=true`（+`bad_length=true` 并存） | `opcua: MessageSize is invalid` | `planner.go:31` |
| N-2 | `opcua_no_channel_neg` | `skip_channel=true` 且有 read/write/browse | `opcua: secureChannel is required before MSG service` | `planner.go:37` |

**负例原子性**：每例单一故障注入；单次执行不得混注。N-1 存量同时置 `bad_length=true`（**两注入并存**，`Validate` 按 `BadMessageSize` 先判——`planner.go:30` 早于 `:33`），故命中锚词稳定为 `MessageSize`；`bad_length` 单独分支（锚词 `opcua: String length is invalid`，`planner.go:34`）**今日无用例** → A′ 立项（G-OPCUA-7）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：`security_mode %q invalid`（`planner.go:24`）；`transport %q invalid`（`:27`，`Transport` 键**层内不可达**——registry Fields 无该键，见 G-OPCUA-1）；`sessions %d out of range`（`:40`，`sessions<0 || >100`）；`service operation requires at least one node id`（`:44`，空 `node_ids`）；`node id %q is not ns=<int>;i=<int>`（`builder.go:69`）；`node id %q exceeds four-byte encoding`（`builder.go:72`）；`MessageSize %d exceeds UInt16`（`builder.go:17`）。

**不得误报的合法协议事件**：多节点 Read（#2）；多会话连续 Read（#10）；Sign 模式（#3）；订阅 5 对（#6）；IPv6（#9）；`close:false`（合法，仅少 CLO 对，今日无正例 → A′ 立项）。

## 8. 边界

- **帧长与 MessageSize**：ACK **MessageSize 28** / HEL **32** 为最小两帧；**最大 MessageSize = 113**（`opcua_subscribe` 帧 10 CreateMonitoredItems 请求，body `43+42×1`）；对应**最大以太帧 = 167**（同帧；`opcua_ipv6` **帧 8** Read 请求亦 167 = 74+93，IPv6 头多 20B 故 MessageSize 仅 93 而以太长持平）；OPN 为 87（**非最大**）。MessageSize UInt16 上限 65535 今日无例 → A′ 补例（G-OPCUA-7）。
- **服务对数**：`Read` 多节点为**一帧多节点**（`47+18n`），不是多帧；`Write`/`Browse` 每 op 一对；`sessions=N` 为 N 对。
- **SecurityMode**：只接受 `none`/`sign`（`planner.go:23`）；`signandencrypt` 旧稿列入枚举但**代码拒绝**（§0 #12 表内枚举与实现差异）。
- **NodeId**：只 FourByte（`ns<=255` 且 `id<=65535`）；String/Guid/Opaque 拒绝 → A′ 立项。
- **端口**：显式 4840 全正例；缺省 4840（`chain_planner.go:1025` 补齐）今日无例 → A′ 补例。
- **地址族**：v4/v6 独立用例（#1–#8/#10 为 IPv4、#9 为 IPv6）；异族混写拒绝 → A′ 立项。
- **多会话**：`sessions` 语义为"连续 N 对 Read"，**不是交错、无独立令牌空间**（§5 诚实声明）。
- 不得产生回绕长度或超量分配（帧长由 `uaFrame` 一次算定）。

## 9. 原子 ID 与完成定义（12 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 | packet_count（实测） |
|---:|---|---|---|---:|
| 1 | `opcua_hello_ack` | 正 | §3.4：HEL/ACK 基线（空 EndpointUrl） | 13 |
| 2 | `opcua_open_none` | 正 | §3.4/§3.7：OPN None + 多节点 Read（令牌复用） | 15 |
| 3 | `opcua_open_sign` | 正 | §3.4：Sign 模式结构路径（SecurityMode=2） | 13 |
| 4 | `opcua_write` | 正 | §3.5：Write + DataValue/Variant | 15 |
| 5 | `opcua_browse` | 正 | §3.5：Browse ObjectsFolder 前向引用 | 15 |
| 6 | `opcua_subscribe` | 正 | §3.6：订阅五件套 + 通知 + keep-alive | 23 |
| 7 | `opcua_bad_node` | 正 | §7：ServiceResult=BadNodeIdUnknown | 15 |
| 8 | `opcua_denied` | 正 | §7：ServiceResult=BadUserAccessDenied | 15 |
| 9 | `opcua_ipv6` | 正 | §2：IPv6 独立用例（offset 74） | 15 |
| 10 | `opcua_multi_session` | 正 | §5：sessions=3 连续三对 Read | 19 |
| 11 | `opcua_bad_size_neg` | 负 | §7：N-1 MessageSize 注入 | —（0 帧） |
| 12 | `opcua_no_channel_neg` | 负 | §7：N-2 未建通道服务 | —（0 帧） |

**包数公式**：单流 = 3（握手）+ 2（HEL/ACK）+ 2（OPN 对）+ 2×服务对数 + 2（CLO 对）+ 4（FIN 四包）= **13 + 2×服务对数**。校验：#1 服务对数 0 → 13 ✓；#2/#4/#5/#7/#8/#9 对数 1 → 15 ✓；#3 对数 0 → 13 ✓；#6 对数 5 → 23 ✓；#10 对数 3 → 19 ✓。**10/10 与实测 pcap 逐例一致**（§0 #6）。

### 9.1 StatusCode 取值（官方 `StatusCode.csv` 实测，2026-09-28）

| 名称 | 官方值 | 本实现用法 |
|---|---|---|
| Good | `0x00000000` | 默认响应（`serviceResult` 返回 0） |
| BadUserAccessDenied | `0x801F0000` | `error_inject.op="denied"`（`planner.go:71`） |
| BadNodeIdUnknown | `0x80340000` | `error_inject.op="bad_node"`（`planner.go:69`） |
| BadSecureChannelIdInvalid | `0x80220000` | **未用**（旧稿 §9.1 写 0x80870000 错，§0 #13） |
| BadSecurityModeRejected | `0x80540000` | **未用**（旧稿 §9.1 写 0x80890000 错，§0 #13） |

### 9.2 M-1：SetPublishingMode 服务 TypeId 取值错（confirmed finding）

| 项 | 值 | 出处 |
|---|---|---|
| 本实现 | 请求 **791** / 响应 **792** | `planner.go:103` `add(791, 792, …)`；实测帧 12 TypeId `01 00 17 03` = 791 |
| 官方 DataType | **797** / **800** | `NodeIds.csv:609/612` |
| 官方 DefaultBinary Encoding | **799** / **802** | `NodeIds.csv:611/614` |
| tshark 3.6.14 表 | **799** / **802** | 探针实测：patch 成 799 → `SetPublishingModeRequest (799)`；802 → `SetPublishingModeResponse (802)` |
| **结论** | **791/792 不是 SetPublishingMode 的正确线上 id**（正确 = 799/802） | 791/792 本身**存在**于官方 NodeIds.csv 与 tshark 表中，但属 `ModifySubscriptionRequest`：791 = 该服务 DataType；792 = 其 `_Encoding_DefaultXml`（tshark 实测把 792 解成 `ModifySubscriptionRequest (XML Encoding)`）。**即该对指向了另一个服务**——全表唯一一处此形态（其余偏差是同服务的 DataType/Encoding 口径差异，G-OPCUA-9） |

**成因**：`planner.go:95-125` 的订阅分支 id 不是从官方表取，而是按"787/788 → 791/792 → 826/827"的**自增规律**推出来的——787（CreateSub ✓）、751（CreateMon ✓）、826（Publish ✓）三个对了，中间那个跟着 `+4` 规律写成了 791/792，而官方在 788→797 之间跳了 9。

**修复**：`planner.go:103` 改为 `add(799, 802, …)`（取 tshark 表 = 官方 Encoding 值，与其余七族同口径）。**修复后须重跑后钉**：帧 12/13 TypeId hex 由 `01 00 17 03`/`01 00 18 03` 变为 `01 00 1f 03`/`01 00 22 03`；**帧数与其余断言不变**（body 长度与字段布局无关）。

**口径一致性（其余七族已对）**：Read `631/632`、Write `673/674`、Browse `527/528`、CreateSub `787/788`、CreateMon `751/752`、Publish `826/827`、OPN `446`、CLO `452` —— 实测 tshark 对 631/673/527/751/787/826/446/452 **全部按 Encoding id 命名**，本实现与之一致 ✓；**响应侧 632/674/528/752/788/827 官方 Encoding 值为 634/676/530/754/790/829**，本实现写的是 DataType 值——tshark 对响应侧 id 表内缺失（解成 `Unknown`），**故不影响解码，但与请求侧口径不统一**（列为 G-OPCUA-9，修复建议同 M-1：响应侧改用 Encoding 值）。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | TCP 客户端主动建连；传输层握手协商缓冲大小（Part 6 §7.1.2） | 场景①–⑩ | `DependsOn ["tcp"]` 单值（`registry.go:720`）；HEL/ACK 已落码（`builder.go:33/46`） | 无 |
| 2 | 命令/消息表 | 传输层 3 类 + 安全通道 2 类 + 服务 9 类（§1.4 旧稿表） | 场景①–⑦ | `servicePairs` 四分支 + `BuildOPN`/`BuildCLO`（`planner.go:85`） | TypeId 取值见 M-1/G-OPCUA-9 |
| 3 | 状态机 | 建连—通道—服务—释放 4 阶段（旧稿 §4.1） | #2/#6/#10 | opcua 层无自有状态；tcp 层拥有握手挥手 | 无 |
| 4 | 字段表 | MessageHeader 3 键 + RequestHeader 7 键 + ResponseHeader 6 键（§3.1/§3.3） | 数据场景层 | `uaFrame`/`putRequestHeader`/`putResponseHeader` 逐字段 | 无 |
| 5 | 错误处理 | 2 类负例 + 7 个未入例拒绝分支（§7） | 负例 N-1/N-2 | planner 7 种拒绝分支（`planner.go:23-58`）+ builder 2 种（`:17/:69`） | A′ 5 条（§14） |
| 6 | 超时与活性 | RequestHeader 有 TimeoutHint（60000）；协议无 PING 类保活；订阅 keep-alive 是**发布空转**不是心跳 | #6 | `TimeoutHint=60000` 已落码（`builder.go:91`）；订阅 keep-alive 空转已落码（`planner.go:120-122`） | 无 |
| 7 | NAT/代理/被动 | 无被动模式概念（客户端直连） | — | 无 `sessions[].src_port`；多流走策略级 `flow_control` | **显式不适用**被动模式；NAT 穿透为框架面 |
| 8 | 版本/方言 | `opc.tcp://` 唯一 profile；Sign 结构路径已覆；IPv6 已覆 | 正例 10 | `security_mode` 二值（`planner.go:23`）；缺省端口 4840（`chain_planner.go:1025`） | Sign 真实密码学 → G-OPCUA-4；Part 6 条款号逐条核对 → G-OPCUA-8 |

### 10.2 子表①：服务 × 终态矩阵（逐格已覆/立项/不适用）

| 服务 | T1 正常终态 | T2 配置拒绝 | T3 RST 异常终态 |
|---|---|---|---|
| HEL/ACK | 已覆（#1） | 已覆（#11 代表例，拒绝与消息无关） | A′ 立项（G-OPCUA-6） |
| OPN None | 已覆（#2） | 同上代表已覆 | A′ 立项（G-OPCUA-6） |
| OPN Sign | 已覆（#3） | 同上代表已覆 | A′ 立项（G-OPCUA-6） |
| Read | 已覆（#2/#10） | 同上代表已覆 | A′ 立项（G-OPCUA-6） |
| Write | 已覆（#4） | 同上代表已覆 | A′ 立项（G-OPCUA-6） |
| Browse | 已覆（#5） | 同上代表已覆 | A′ 立项（G-OPCUA-6） |
| 订阅五件套 | 已覆（#6） | 同上代表已覆 | A′ 立项（G-OPCUA-6） |
| CLO | 已覆（全正例） | 同上代表已覆 | A′ 立项（G-OPCUA-6） |
| 服务级坏码 | 已覆（#7/#8） | 不适用（错误注入非配置拒绝） | 不适用（无传输异常终态） |

**逐格重数**：9 行 × 3 列 = 27 格——已覆 **17**（T1 列 9 + T2 列 8）/ A′ 立项 **8**（T3 列 8）/ **不适用 2**（坏码行 T2/T3——错误注入不是配置拒绝，亦无传输异常终态），零空格。17 + 8 + 2 = 27 ✓

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **24 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | 空 EndpointUrl（HEL） | 覆（#1，MessageSize=32） |
| 2 | 非空 EndpointUrl | A′ 立项（`BuildHEL` 支持入参，今日恒传空串） |
| 3 | 多节点 Read（一帧多 NodeId） | 覆（#2，2 节点） |
| 4 | 单节点 Read | 覆（#9/#10） |
| 5 | 空 `read` 且无其他服务 | 覆（#1/#3，无服务对） |
| 6 | `node_ids` 空数组 | A′ 立项（`planner.go:44` 有分支，今日无例） |
| 7 | NodeId `ns=0;i<=255` | 覆（#1–#8 全用 FourByte） |
| 8 | NodeId `ns=0;i>255` | 覆（#2 `i=1001`、#7 `i=9999`） |
| 9 | NodeId `ns>0` | 覆（#10 `ns=1;i=1001`） |
| 10 | NodeId 超四字节界（`ns>255`/`id>65535`） | A′ 立项（`builder.go:72` 有分支） |
| 11 | NodeId 非 `ns=;i=` 文本 | A′ 立项（`builder.go:69` 有分支） |
| 12 | `security_mode="none"` | 覆（#1/#2/#4–#10） |
| 13 | `security_mode="sign"` | 覆（#3） |
| 14 | `security_mode` 缺省 | **A′ 立项**（机读实测 **12/12 例全部显式写 `security_mode`**；缺省分支 `planner.go:20-22` **无任何用例走过**，与同表行 6/10/11 同口径） |
| 15 | `security_mode` 非法（如 `signandencrypt`） | A′ 立项（`planner.go:24` 有分支，今日无例） |
| 16 | Write + DataValue/Variant | 覆（#4） |
| 17 | Browse 前向引用 | 覆（#5） |
| 18 | 订阅 1 通知 + 1 keep-alive | 覆（#6） |
| 19 | 订阅仅 1 周期（无 keep-alive） | A′ 立项（`planner.go:108-122` 有分支） |
| 20 | `sessions=3` | 覆（#10） |
| 21 | `sessions` 缺省（=0） | 覆（全正例除 #10） |
| 22 | `sessions` 越界（<0 或 >100） | A′ 立项（`planner.go:40` 有分支） |
| 23 | `close=false` | A′ 立项（少 CLO 对，今日无正例） |
| 24 | IPv6 载体 | 覆（#9，offset 74） |

15 覆 + 9 立项 = 24。✓
### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 缓冲大小协商探测（Part 6 §7.1.2 HEL/ACK） | #1 | 已覆 |
| 2 | 无安全通道建立（None） | #2 | 已覆 |
| 3 | 带签名通道建立（Sign） | #3 | 已覆（结构路径） |
| 4 | 变量读取（SCADA 采集） | #2/#9/#10 | 已覆 |
| 5 | 变量写入（下发行） | #4 | 已覆 |
| 6 | 地址空间浏览（组态发现） | #5 | 已覆 |
| 7 | 订阅周期发布（变化上报） | #6 | 已覆 |
| 8 | 权限拒绝（只读节点写） | #8 | 已覆 |
| 9 | 节点不存在 | #7 | 已覆 |
| 10 | 多客户端/多会话并发 | #10 | 已覆（**但实现为连续非交错**，§5） |
| 11 | 真实证书/签名校验 | — | **缺口立项 G-OPCUA-4**（真实密码学超出当前生成器范围，未来补齐 Sign 线格式与独立断言） |
| 12 | 会话层（CreateSession/ActivateSession） | — | **缺口立项 G-OPCUA-11**（当前直接使用无会话令牌；未来补建会话状态与独立令牌） |
| 13 | 分段传输（超缓冲大消息） | — | **缺口立项 G-OPCUA-12**（当前恒单 final 块；未来补 chunk 分片/重组与边界用例） |
| 14 | HTTPS/WebSocket 承载 | — | **缺口立项 G-OPCUA-13**（当前仅 opc.tcp/TCP 4840；未来补承载 profile 与独立用例） |
| 15 | PubSub（UADP/MQTT） | — | **缺口立项 G-OPCUA-14**（当前仅 Client/Server Binary；未来补 PubSub 承载与独立用例） |

10 覆 + 5 缺口立项 = 15。✓ 无映射无确认即缺口——本表零空项。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：①规范原文（OPC UA Part 6/Part 4 + 官方 `NodeIds.csv`/`StatusCode.csv`，定"必须是什么"——本轮已用官方 CSV 校正旧稿两处臆造 StatusCode 与 TypeId 口径，§0 #12/#13）；②商业化软件实际行为（**未取到**：真实 OPC UA 服务器行为、open62541/node-opcua 的线字节未抓包核对 → G-OPCUA-8 待确认）；③可靠开源实现思路（open62541 的 `UA_TcpMessageHeader` 小端合并、node-opcua 的 `writeUInt32LE`——只借鉴"MessageSize 必须小端"这一条思路）。三路一致点：MessageHeader 布局、小端、服务 TypeId 取 Encoding 值；不一致点：**CLO 是否有响应**（旧稿称无、实测实现发响应，见 G-OPCUA-8）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `opcua` 终结层（本版；enip/tds 同构先例） | 服务序列/安全模式/订阅多周期可声明可断言；代价 = 一套层（已落码 1135 行） | **采用** |
| B | 直接 tcp 层 + 顶层 payload | 无服务对/无 TypeId/无令牌复用 → 12 例中 10 例不可表达 | **否决** |
| C | 拆成"传输层 opcua + 服务层 ua-svc"两层 | 两层的边界（TokenId 从 OPN 响应流入对称段）需跨层状态传递，框架层间无此通道 | **否决**（状态在 `buildEvents` 局部变量，单层内聚更简单） |

## 11. P2 D-OPCUA-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 状态说明：实现已落码（`internal/protocol/opcua/` 五文件），本 P2 条目为 P-PIPE 文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口；P4 在本协议内为"缺口收敛"（§14），不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:1445-1485` + `:1705`） | `OPCUAConfig`/`OPCUANodeRead`/`OPCUASubConfig`/`OPCUAErrInject` + `FlowSpec.OPCUA` 槽位 | —（共享文件） |
| `trafficgen/internal/protocol/opcua/builder.go` | 线编码：`uaFrame` + HEL/ACK/OPN/MSG/CLO + 8 类服务体 | 501 |
| `trafficgen/internal/protocol/opcua/planner.go` | `Planner.Validate`（7 分支）+ `servicePairs`（四分支）+ `buildEvents` | 230 |
| `trafficgen/internal/protocol/opcua/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator` + `RegisterLayerValidator`，`init()`） | 48 |
| `trafficgen/internal/protocol/opcua/types.go` | 类型别名 + `defaultPort=4840` 常量 | 11 |
| `trafficgen/internal/protocol/opcua/opcua_test.go` | 13 个 `Test*`（编码面 + 生成器面 + Validate 面 + 注册面 + 默认流面） | 345 |
| 接线 5 件 | registry 注册（`layers/registry.go:720`）/ translate 层内分支（`chain_planner_translate.go:1891`）/ convert 子配置搬运（`strategy_convert.go:1645`）/ protocols 准入（`protocols.go:50`）/ 缺省端口 + 端口语义白名单（`chain_planner.go:1025`/`:750`） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`planner.go:13`）：`OPCUA==nil` 通过（空配置默认流，P0b-2）；`security_mode` 枚举、`transport` 枚举、`BadMessageSize`、`BadLength`、`SkipChannel` 组合、`sessions` 范围、每 op 非空 node_ids、每 NodeId 四字节可解析、订阅 monitored_nodes 各归一分支。
- `servicePairs(cfg) ([]uaExchange, error)`（`planner.go:85`）：四分支互斥 switch，返回请求/响应体与两侧 TypeId。
- `buildEvents(cfg) ([]struct{Up bool; Bytes []byte}, error)`（`planner.go:172`）：产出全部应用层帧（不含 TCP 握手/挥手）。
- 生成器：`Name() "opcua"`；`GenEvents()` 返回自身；`EmitEvent` 未接线显式错（防误调，`layer_gen.go:15-17`）；`Generate` 逐帧 `EmitMsg`（`layer_gen.go:19-41`）。

### 11.3 数据结构

`OPCUAConfig{Transport, SecurityMode, Read[], Write[], Browse[], Subscription, Sessions, ErrorInject, Close, SkipChannel, BadMessageSize, BadLength}`（`types.go:1445-1460`）；`OPCUANodeRead{NodeIDs[], AttributeID}`（`:1464-1467`）；`OPCUASubConfig{PublishingIntervalMs, PublishCount, PublishIntervalMs, KeepAlive, MaxKeepAliveCount, MonitoredNodes[]}`（`:1471-1478`）；`OPCUAErrInject{Op, Node}`（`:1482-1485`）。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry Fields 11 键 allowlist）→ translate（层内 config → `spec.OPCUA`）→ planner `Validate` → 生成器 `Generate` → `buildEvents`（HEL/ACK/OPN 对 → `servicePairs` 逐对 MSG → CLO 对）→ worker（tcp 层补握手挥手与分段）→ writer（PCAP/NIC）。

### 11.5 错误分支

7 种 planner 拒绝（`planner.go:23-58`）+ 2 种 builder 拒绝（`:17` MessageSize 上限、`:69/:72` NodeId 解析）全部传 task error（零假成功——两负例实测 0 帧）。`ErrorInject.Op` 未知值**静默返回 0（Good）**（`planner.go:67-73` 的 switch 无 default 分支）→ A′ 立项（G-OPCUA-7）。

### 11.6 性能边界

见 §6（事件序列线性产出、per-flow 局部状态、无跨流共享、无锁；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- `CheckProtoFlat`（`strategy_convert.go:8625` 起）**无 opcua 分支**（`grep -c 'protocol == "opcua"'` = 0 实测）：顶层 `opcua` 子映射 presence 不判死——与 dns/mqtt/http 族已登记协议不同，属缺口 G-OPCUA-1（禁加单协议黑名单分支，等框架级 unknown-key 白名单；kingbase 记忆裁定）。
- **顶层未知键通用门也缺**：游离顶层键（如 `{layers:[…], bogus: 1}`）今日**不判死**（`CheckProtoFlat` 只查五键 + 各协议子映射白名单）→ presence 负例今日建了会真绿 = 假通过，**不建**（G-OPCUA-1，与 moxa G-MOXA-2 同款）。
- 动态 allowlist（`internal/core/layer_dyn.go` 头部）：`opcua` **零命中**实测 → 业务字段动态对象即拒；四元组 `ip`/`tcp` 全开。见 §12.12。
- registry `opcua` 有 Fields 11 键（与 moxa 的"Fields 空"不同）→ **层内 `read`/`write`/`browse`/`subscription`/`security_mode` 等今日已可住**；但 `Transport` 键（`types.go:1446`）**未登记**在 registry Fields → 层内不可达（G-OPCUA-1 附表）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 5 文件 + 接线 5 处（registry/protocols/translate/convert/chain_planner）；不触及其他协议。cases 回滚 = 恢复 12 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 12/12 顶层 = `{layers}` **仅此一键，零残留**；目标形状见 §2 样例且**存量已达标**（本协议无迁移工作量；全仓同形协议 27 个，见 §12.1 注） | §12.1；`cases/opcua.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 opcua 流量模板；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（终结层）/时间线。有长连接，不豁免 | §12.3 + §5 |
| §4 查规范 | Part 6/Part 4 + 官方 `NodeIds.csv`/`StatusCode.csv` + tshark 3.6.14 字段与 12 例 pcap 实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["tcp"]` 单值（`registry.go:720`）；7+2 种拒绝分支；失败传 task error（两负例 0 帧实测） | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待 P4 基准，不写承诺；pcap/NIC 两路验收明写） | §6 |
| §7 三份文档 | `101-opcua-{design,testcase}.md` v1.0.1（草稿层）+ D-OPCUA-1（§11，门1 获批 = 定稿）+ T-OPCUA（testcase §2，12 ID）+ 旧稿 25-* 为历史层 | 修订记录 |
| §8 设计先行 | P1–P3 先于 P4 缺口收敛；门1 获批 = D-OPCUA-1 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = Part 6/Part 4 + 官方 CSV（§10）+ D-OPCUA-1（§11）+ tshark 3.6.14 字段与 pcap 实测（**已到抓包级**：12 例 pcap 在案、48 条 frame 断言逐条复核 OK）；12 ID 逐项回指；存量 12 例审计去向 testcase §8 | `101-opcua-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 `/tmp/pipe/doc-lanes/opcua.md`）+ 收官隔离复审；红先绿后 | 自审日志 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `opcua` 已在 `registry.go:720` 注册（**不新增层**）；生成表 127 层同代（`fields` 11 键与 registry 逐键一致，机读实测）；**P4 若改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `opcua.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/opcua/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-28）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/opcua.json` | 12 | **`{layers}` ×12**（唯一顶层键，**零游离键**） | `[tcp,opcua]` ×11 + `[ip,tcp,opcua]` ×1 | 2/2 = `{expect_error, error_contains}` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 本协议**从未用过顶层地址**；IPv6 例已住 `layers[0].ip.{src,dst}`（#9） |
| `src_port` | **0** | 本已 absent（保底 `12345+i`）；目标形按需迁 `layers[i].tcp.src_port` |
| `dst_port` | **0** | 已住 `layers[i].tcp.dst_port`（12/12 显式写 4840） |
| `count` | **0** | 走 `flow_control`（本版未用） |
| 顶层 `opcua` 子映射 | **0** | 已住 `layers[i].opcua`（12/12） |
| `strategy_fc` / `flow_control` | **0** | 本协议无多流用例；目标形按需加 |

**结论**：**本协议存量 12/12 顶层零残留**——§1 门的动作 = ①**无旧键可删**；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测 12/12 顶层仅 `layers`）；③A′ 新增例全部沿用纯 layers 形（§13）。
> **注（2026-09-28 机读全仓统计）**：全仓 `cases/*.json` 中**共 27 个协议**今日已是纯 `{layers}` 形（bacnet/dcerpc/dtls/edp/ftp/hl7/igmp/jt808/jt809/jtt905/kerberos/kingbase/ldap/megaco/mmse/ntlm/ocsp/**opcua**/pppoe/pptp/rtmp/rtsp/sctp/sstp/vnc/xmpp/xmrmining），本协议只是其中之一，**并非"唯一"**；其余 98 个协议文件仍含顶层旧键或协议子映射。本协议的**特有事实**仅是"12/12 例今日即零残留"，不构成全仓唯一性。

目标形状样例见 §2（顶层仅 `layers`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"opcua":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 opcua 分支，`grep -c` = 0 实测）→ **P4 不建该负例**（建了会真绿 = 假通过）→ 缺口 G-OPCUA-1 登记。② 白名单外游离键判死（`unknown field`）今日**亦无通用门** → 同 G-OPCUA-1，P4 不建。③ 2 负例每条带锚词（已齐，§7）。④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

会话表：`s1` 单连接基线（#1/#2/#3/#4/#5/#6/#7/#8/#10，各自四元组，HEL→ACK→OPN 对→服务对→CLO 对→FIN 四包）/ `s2` 多逻辑会话（#10，`sessions=3`，**连续三对 Read 非交错**，§5 诚实声明）。事务：`t1` 传输层握手（HEL/ACK，tcp 层建连后）/ `t2` 通道打开（OPN 对，领 TokenId 1000）/ `t3` 服务调用（MSG 对，每 op 一对）/ `t4` 关闭（CLO 对 + tcp 层 FIN）；每事务四件事（前置/触发/成功/失败）见 §5 阶段表 + §4 场景表。关联关系：**无派生流**（诚实声明：单 TCP 连接承载全部消息，无 `driven_by`；订阅的 Publish 不派生新连接）。插入位置：终结层（`[ip,tcp,opcua]`，无中间层）。时间线：消息内严格顺序 / 服务对顺序展开 / 多会话连续（#10）/ 无交错（`concurrent` 为例外路径不启用）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst`、`tcp.src_port/dst_port` 五策略全开（allowlist `internal/core/layer_dyn.go` 头部实测：`ip`/`tcp`/`udp`/`eth`；保底 `DefaultSrcPort+i`（`strategy_convert.go:49`）；dst 动态与 4840 缺省和平共处——显式/动态值非零即不触发补齐）。

**业务字段 8 项全关**（allowlist 无 `opcua` 行，`grep` 零命中实测；对象即拒）：`security_mode`（通道级标量，逐流变无意义）/ `read`·`write`·`browse`（服务清单，列表无动态形状）/ `subscription`（嵌套对象，无动态形状）/ `sessions`（结构选择器）/ `error_inject`（负例注入器）/ `close`·`skip_channel`·`bad_message_size`·`bad_length`（布尔开关）——逐流变体需求列 A′ 候选（testcase §6.2；今日按 §9.36 口径不冒充覆盖）。

序号算法实读：`parseLayerDyn`（`layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go` 头部）——**`opcua` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。

## 13. P3 对接清单（T-OPCUA 草稿输入；正文落 testcase 文件）

12 ID（10 正 + 2 负）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。A′ 候选 9 例：`opcua_neg_bad_length`（`bad_length` 单独）/ `opcua_neg_bad_mode`（`security_mode` 非法）/ `opcua_neg_bad_nodeid`（NodeId 文本非法 + 越界，两形状同例）/ `opcua_neg_empty_nodes`（`node_ids` 空数组）/ `opcua_no_close`（`close=false`）/ `opcua_default_port`（删 `dst_port` 不断言值）/ `opcua_neg_mixed_family`（异族混写）/ `opcua_sub_single_publish`（无 keep-alive 单周期）/ `opcua_abort_rst`（G-OPCUA-6）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-OPCUA-1 | `CheckProtoFlat` 无 opcua 分支（顶层 `opcua` 子映射 presence 不判死）+ 无游离顶层键通用门 + `Transport` 键未登记 registry Fields | P4 先实测再建例；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单）；`Transport` 键裁定登记或删 |
| G-OPCUA-2 | `sessions>1` 实现为**连续 N 对 Read**，无独立 AuthenticationToken / 独立 RequestHandle 空间 / 交错调度（旧稿 §4.5 描述未落码） | A′ 候选：补实现每会话独立令牌与交错，或登记为当前能力缺口并收窄用例 #10 断言口径。用例今日不得声称状态隔离。**P4 必做**：改写 `opcua_multi_session` 的 `expect.notes` 文案——存量原文 "the three Read request/response pairs are **interleaved** and each keeps its own AuthenticationToken and RequestHandle space" **与实现相反**（实测三对 @82 全 `01 00 00 00`、handle 2/3/4 共用计数器、帧 8/10/12 连续非交错） |
| G-OPCUA-3 | 业务字段动态全关（allowlist 无 `opcua` 行） | A′ 候选，不冒充已覆盖（§9.36 口径） |
| G-OPCUA-4 | Sign 模式只改 SecurityMode 枚举，**不产证书/不算签名/不改安全头长度**（旧稿 §4.2 的 PolicyUri 70B/102B + 证书占位未实现） | 缺口立项：补齐真实密码学后新增独立用例并重算帧长 |
| G-OPCUA-5 | NodeId 只支持 FourByte（String/Guid/Opaque 未实现） | A′ 候选（`ns=N;s=Name` 形状）；今日不得声称覆盖 |
| G-OPCUA-6 | RST 非正常结束补例（§3.15②后半） | A′ 补例 `opcua_abort_rst`（`tcp.rst` 框架能力，本层零断言） |
| G-OPCUA-7 | 未入例拒绝分支 5 条（`bad_length` 单独 / `security_mode` 非法 / 空 `node_ids` / NodeId 解析两分支 / `ErrorInject.Op` 未知值静默 Good）+ MessageSize UInt16 上限 + `security_mode` 缺省分支（§10.3 行 14 已改判立项） | A′ 补例（含 `ErrorInject.Op` 未知值的**静默 Good 是缺陷候选**，P4 裁定拒绝或登记）。**已做（2026-09-30）**：`opcua_subscribe` 的 `expect.notes` 文案已改为"CLO 有请求与响应对"；两条负例已删 `notes` 键（严格两键口径）；`opcua_multi_session` 文案已改为"三对连续 Read + 同一令牌 + 共用 RequestHandle 计数器" |
| G-OPCUA-8 | 第三源（真实服务器/开源实现线字节）未取到；Part 6 §7.1.2.x 条款号未逐条核对；**CLO 是否有响应**与旧稿 §4.4/§6 记载矛盾（实测发响应） | 待确认：抓 open62541 或真实 OPC UA 服务器包对照，或查 Part 4 §5.13.3 原文；确认前按实现钉、不声称合规。**风险（须写清）**：若原文确为"CLO 单向无响应"，则**全部 10 个正例**（机读实测 `close:true` = 10/10，两负例不产流不受影响）的**帧位与 `packet_count` 需整体重算**——每例减 1 帧：13→12、15→14、23→22、19→18；§9 包数公式 `13+2×服务对数` 须改为 `12+2×服务对数`；testcase §1 形状基线、§3 各例帧位与 §8.1 实测面同步重钉 |
| G-OPCUA-9 | 响应侧 TypeId 用 DataType 值（632/674/528/752/788/827），请求侧用 Encoding 值（631/673/527/751/787/826）——**口径不统一**；tshark 响应侧表内缺失故不影响解码 | P4 与 M-1 一并修（响应侧改 634/676/530/754/790/829）；修后重跑后钉（帧数与 body 布局不变） |
| G-OPCUA-10 | **结果文档过期**：`trafficgen/docs/protocol-pcap-test/opcua.md`（**tracked 产物**）写 `Cases: 12 — pass 12, fail 0, error 0`，但末次提交 `91f2487`（**2026-08-30**）早于判死提交 `0417be5`（2026-09-13）；`docs/protocol-pcap-test/opcua/` **0 个 pcap**（目录根本不存在，非"空目录"）——故该 12/12 **未经今日复跑证实，不得作为"今日已复跑"依据**。**opcua 特殊性（须写清，不得夸大）**：opcua 是本批**已合规的协议之一**（12/12 顶层键仅 `{layers}`，机读实测），故其 12 例今日**仍应可跑**——本缺口**不是**"不可跑"，而是"**数字未经今日复跑证实 + 无 pcap 留档**"；本车道亦未跑该套件，故**不以任何形式**（含"今日已跑通"）引用该产物 | **代码阶段**（P5 重跑套件后重生成该产物）；本版**不删不改**（tracked 产物，删除属 P5 动作，此处仅登记事实）；在此之前读者不得据此判断套件已复跑（口径与 pcep 先例 G-PCEP-11 一致） |

## 15. 修订记录

- v1.0.1（2026-09-28，小补登记）：新增缺口 **G-OPCUA-10**（§14）——`trafficgen/docs/protocol-pcap-test/opcua.md` 的「12/12 pass」是**过期产物**（末次提交 `91f2487` 2026-08-30，早于判死提交 `0417be5` 2026-09-13；`docs/protocol-pcap-test/opcua/` 0 个 pcap），**归属代码阶段**（P5 重跑套件后重生成）；§0 增产物过期登记段；缺口范围 `G-OPCUA-1…G-OPCUA-9` → **`…G-OPCUA-10`**。**本缺口不代表 opcua 不可跑**——opcua 为本批已合规协议之一（12/12 顶层键仅 `{layers}`），12 例今日应可跑，登记仅限"数字未经今日复跑证实 + 无 pcap 留档"。**不改任何 tracked 产物**（`trafficgen/docs/protocol-pcap-test/` 下零改动）。自审 1 轮，末轮干净。
- v1.0.1（2026-09-30，P4 静态闭环）：同步 D/T/C 审计结论；校正 `chain_planner_translate.go` 行号为 1891；与 cases JSON 对齐订阅 CLO 响应、多会话连续/共享计数器、负例严格两键；缺失 Fields/动态 translate 能力继续以 G-OPCUA-1/G-OPCUA-3 登记，不机械迁移；未运行 suite、服务、MCP、NIC。自审 2 轮，末轮干净。
- v1.0.0（2026-09-28）：P-PIPE #101 文档轨 P1–P3。续号重做：25→101 沿革与 **17 项**旧稿校正（§0，含 2 处官方 CSV 实证的取值臆造、1 处包数全错、1 处 tshark dissector 存在性反转、1 处"CLO 无响应"与实测矛盾）；存量 12 例机读审计（**顶层零残留**，本协议无迁移工作量）；48 条 frame 断言逐条对实测 pcap 复核（全 OK）；§12.1/12.3/12.12 强制展开 + 12-P2；D-OPCUA-1 as-built 定稿（§11）；**M-1（SetPublishingMode TypeId 791/792 → 799/802）confirmed finding**（§9.2）；缺口 G-OPCUA-1…G-OPCUA-9。自审见 `/tmp/pipe/doc-lanes/opcua.md`。

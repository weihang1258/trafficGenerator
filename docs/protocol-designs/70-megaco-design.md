# Megaco/H.248（媒体网关控制协议，文本编码）设计契约

> 版本：v1.2.2（设计阶段）  
> 日期：2026-09-01  
> 状态：仅设计与 PCAP（抓包文件）/NIC（网卡）用例契约；`megaco`/`h248`/`mgcp` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。**按《协议设计文档与用例文档需求文档 v1.3》完成独立对抗重审**（审查员 rr-megaco：行为面 114 点，✓79/半8/✗27；confirmed findings 5 MAJOR C 项 + 2 MAJOR D 项 + 约 20 MINOR + 4 N 项），本版 v1.2.0 为修复轮产物：语义 ID 23 → 77（46 正 + 31 负），待 rr-megaco 复验；v1.1.0 及以前的审查/修复记录见 §10 修订记录。
> 配套文件：`docs/protocol-designs/70-megaco-testcase.md`、`trafficgen/test/protocol_pcap/cases/megaco.json`  
> 规范基线：RFC 3525（Gateway Control Protocol v1，正文与 ITU-T H.248.1 (03/2002) 等价）——§7 命令与描述符、§8 事务、§9 承载、§11 MG-MGC 控制接口、Annex A（ASN.1/BER 二进制编码）、Annex B（文本编码 ABNF）、Annex D（IP 承载：D.1 UDP、D.2 TCP SHALL 采用 TPKT 成帧）、Appendix I（示例呼叫流）；TPKT 头字段规范：RFC 1006。端口出处：IANA 注册 `megaco-h248 2944 (tcp/udp)`、`h248-binary 2945 (tcp/udp)`、`mgcp-gateway 2427 (tcp/udp)`。  
> 本版按 `protocol-doc-requirements.md` v1.0（2026-08-31）强制契约重写，取代 2026-08-21 旧稿；与旧稿/任务口径冲突处一律以规范为准（见 §10 修订记录）。

## 1. 范围、profile 和未注册边界

本契约覆盖 Megaco/H.248 v1 的文本编码线格式与事务模型：消息（Message）→ 事务（Transaction：Request/Reply/Pending/ResponseAck）→ 动作（Action/ContextID）→ 命令（Add/Modify/Subtract/Move/AuditValue/AuditCapability/Notify/ServiceChange）四层结构、描述符（Media/Local/Remote/LocalControl/TerminationState/Events/Signals/DigitMap/ObservedEvents/Statistics/Services/Audit/Error 等）、TerminationID 命名与通配符、事务关联标识（transactionId）配对、UDP/TCP 双载体与 IPv4/IPv6。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `megaco_v1_text`（主 profile） | UDP 或 TCP / 2944，IPv4+IPv6 | RFC 3525 文本编码全部上述能力 | 真实媒体面（RTP 流、编解码协商结果）、网关状态真实性 |
| `megaco_v1_ber`（边界提及） | 默认 2945（RFC 3525 §9 Transport 引言/Annex D.1） | 仅作为编码 profile 存在声明；本期 77 例不产生 BER 载荷 | 把文本字节当 BER 解析或反之（见负例） |
| `mgcp_alias`（入口别名） | 入口名 `mgcp` 时默认 UDP 2427 | 与 `megaco_v1_text` 完全同一 planner 语义与同一文本线格式 | **MGCP 本体线格式（RFC 3435 的 CRCX/MDCX/DLCX 等 verb）超出本 planner 合并范围，不展开、不臆造** |

**三名合一决策（不得更改）**：`h248`、`mgcp`、`megaco` 三个名字合并为一个 Megaco/H.248 planner（规划器）覆盖。决策出处：`docs/protocol-designs/00-unimplemented-list.md` 备注第 3 条与"实现决策"第 3 条（需求方 2026-08-18 确认）。差异只在入口别名与端口默认值：入口名 `megaco`/`h248` 默认 2944（文本），入口名 `mgcp` 默认 2427；机器契约 `cases/megaco.json` 的 `proto` 固定为 `megaco`，不得用 `h248`/`mgcp`。实现以别名归一化到同一语义模型，不复制三套状态机。

**主线选文本编码的理由**：①现网 H.248 联调与仿真普遍使用文本编码（可读、易构造、易排障）；②可校准性好——本机 tshark 3.6.14 实测 `megaco` 文本 dissector（解析器）字段齐全且绑定 2944 端口（§3.9 实测清单），BER 需 ASN.1 编解码器且公开样本少；③文本编码允许用起始行与命令 token 做稳定字节断言。BER（Annex A，TLV 大端）按规范钉住默认端口 2945，仅作 profile 边界提及；"配置声明 BER 而载荷为文本（或反之）"进入负例（§7）。

**长消息口径（规范修正）**：RFC 3525 文本编码**没有应用层消息分段**——Annex B ABNF 的 `messageBody` 只有 `errorDescriptor / transactionList` 两种形态，全文无分段字段；全文 "segment*" 仅出现在无关引用（I.366.1）。因此本契约不臆造 "Segmentation" 线格式：长消息由 **TCP MSS（分段）跨 segment 承载、按字节流重组后按 TPKT 长度域切分（Annex D.2：TCP 承载 SHALL 采用 RFC 1006 TPKT 成帧），再按文本语法验证**，UDP 则单数据报承载完整消息并受 MTU 约束（Annex D.1 明示实现者注意 MTU 限制）。任务书"长消息分段 Segmentation"按规范修正为上述口径（TPKT 是成帧不是分段：MSS 分段发生在 TPKT PDU 之下，一条长 TPKT PDU 可跨多个 segment）。

**输出契约（pcap/NIC 双输出）**：本契约的用例同时服务于 pcap（抓包文件）与 port_group/NIC（网卡）两种输出路径——两路径共用同一份 cases JSON、同一 tshark 字段/帧字节断言，NIC 路径仅抓包口不同，不改变断言语义（v1.2 C-2，与 64-cwmp/66-doh/67-onvif/68-hl7 同形）。**RST 不产生**：所有 TCP 会话以完整三次握手开始、四次挥手闭合，本契约不产生 RST/异常中断（与 doh/cwmp 同口径；Megaco 控制关联行为面不含传输层异常中断）。

**并发会话（v1.2 翻案）**：v1.1 曾声明 `concurrent: true` 本版不适用；v1.2 按 rr-megaco 翻案纳入——单关联内事务串行性只约束关联内部，不约束生成器级多连接交错（判例：cwmp 翻案⑦/doh/onvif/hl7 同形），`sessions[]` 增 `concurrent: true` 交错回放，正例 `megaco_udp_ipv4_concurrent_sessions`。流关联与多流不适用声明**保留**（理由见 §4.1/§5.2，本轮不翻案）。

**未注册边界**：当前仓库没有注册 `megaco` 层、planner、validator（校验器）或生成器。`cases/megaco.json` 只保留一个 `megaco_neg_unregistered` 注册前置占位（`expect_error=true`、`error_contains` 精确为 `unknown layer`）；该占位不计入 77 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 Megaco 行为通过。注册后移除占位，按 testcase 文档 §2 顺序补入 46 个正例与 31 个负例。

**动态值不硬编码**：transactionId、ContextID（数值型）、媒体 SDP 中的地址/端口、时间戳是运行期或配置值；JSON fixtures 与断言不得把它们写成固定常量冒充动态行为——断言用 `nonzero`、`same_as_packet`、`distinct_values`、包间关系与稳定 token 字节。TerminationID、DigitMap 内容、Reason 文本、mId 属于 provisioning（预配置）值，允许在 fixture 中显式给出。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, udp, megaco]`、`[ipv6, udp, megaco]`、`[ip, tcp, megaco]`、`[ipv6, tcp, megaco]`，terminal layer（终端层）为 `megaco`，自动补齐 `ip/ipv6 → udp/tcp`。端口默认值随入口名与编码声明确定：

| 入口名 / 编码 | 默认端口 | 出处 |
|---|---:|---|
| `megaco` / `h248`，text | 2944（UDP 或 TCP） | RFC 3525 §9 Transport 引言、Annex D.1；IANA megaco-h248 |
| `mgcp`（别名入口），text | 2427（UDP） | 合并决策；IANA mgcp-gateway |
| 任意入口，`encoding=ber`（仅未来） | 2945 | RFC 3525 §9 Transport 引言："2945 for binary-encoded operation"（旧稿"BER 默认 2944"系笔误，按规范修正） |

端口可由配置显式覆盖，但 planner 不得静默改写；载体（UDP/TCP）与层链冲突必须拒绝（§7）。

无 VLAN（虚拟局域网）、无 IP options（IP 选项）、无 TCP options（TCP 头恰 20B）时，Megaco 文本字节起点 offset（偏移）为：

| 载体 | 文本起点 | 组成 |
|---|---:|---|
| UDP/IPv4 | 42 | Ethernet 14 + IPv4 20 + UDP 8 |
| UDP/IPv6 | 62 | Ethernet 14 + IPv6 40 + UDP 8 |
| TCP/IPv4 | 58 | Ethernet 14 + IPv4 20 + TCP 20 + TPKT 4 |
| TCP/IPv6 | 78 | Ethernet 14 + IPv6 40 + TCP 20 + TPKT 4 |

**TPKT 成帧（TCP 载荷起点 = offset 54/74）**：RFC 3525 Annex D.2 为 SHALL——H.248 over TCP 每条消息前置 RFC 1006 TPKT 头 4B：`版本(1B)=0x03`、`保留(1B)=0x00`、`总长度(2B，大端) = TPKT 头 4B + Megaco 消息长度`。即 TCP 载荷前 4 字节是 TPKT 头，Megaco 文本从 offset 58（IPv4）/78（IPv6）开始；帧字节断言 `[54..57] = 03 00 <len_hi> <len_lo>`（IPv6 为 `[74..77]`）。tshark 3.6.14 的 megaco TCP 解析路径先 `is_tpkt()` 探测：TPKT 分支按 `dissect_tpkt_encap` 解帧（规范主路径），非 TPKT 回退裸文本——本契约采用 TPKT 主路径，不做"声明偏离"。**UDP 报文边界**：一个 UDP 数据报承载恰好一个完整 Megaco message（消息），无 TPKT（Annex D.1）；响应必须发回对应请求的源地址与源端口（RFC 3525 §9）。**TCP 流式**：TCP segment（分段）边界不是消息边界；消息定界依据是 **TPKT 长度域**（字节流重组后按 4B 头切分 TPKT PDU），文本语法（起始行到 messageBody 闭合）仅用于内容验证；小 MSS 时一条长 TPKT PDU 可跨多个 segment（§8）。

## 3. 线格式编码（文本）

### 3.1 message 层（RFC 3525 Annex B.2 ABNF）

```text
megacoMessage = LWSP [authenticationHeader SEP] message          ; 认证头本版不用
message       = MegacopToken SLASH Version SEP mId SEP messageBody
messageBody   = ( errorDescriptor / transactionList )
```

- 起始行两种等价形态：`MEGACO/<version>`（全称 token）或 `!/<version>`（缩写 token，`MegacopToken = ("MEGACO" / "!")`）。`Version = 1*2(DIGIT)`（1-2 位数字，§8.3：版本从 1 起），主口径恒为 `1`；2 位数字形态属语法边界正例 carve-out（用例 40，只断言解析接受、不做语义裁决），`0` 与 3 位数字拒绝（§7）。**注意：起始行后没有字面方括号包消息体——RFC 附录示例里的 `[124.124.124.222]` 是 `mId` 的 domainAddress（IP 地址字面方括号）形式，不是消息体括号**；任务书 `!/1 [Msg...]` 口径按规范修正。
- `mId`（消息发起方标识，§8.3：同一控制关联期间必须恒定）四种形式：`domainAddress`（`[192.0.2.10]` / `[2001:db8::10]`，可带 `:端口`）、`domainName`（`<mgw-1.example.net>`，尖括号内 ≤64 字符）、`mtpAddress`（`MTP{十六进制}` 花括号形态，七号信令场景，本版不用；v1.2 D-3 修正——RFC 3525 Annex B `mtpAddress` 以花括号包十六进制 token，旧稿方括号系笔误）、`deviceName`（pathNAME）。
- `SEP = (WSP / EOL / COMMENT) LWSP`，`EOL = (CR [LF] / LF)`，`LWSP = *(WSP / COMMENT / EOL)`，`COMMENT = ";" ... EOL`——空白、换行与 `;` 注释高度自由；**ABNF 与文本编码全部大小写不敏感（含 TerminationID、DigitMap 名），唯独 SDP 内容大小写敏感**。
- `messageBody` 或者是一个 `errorDescriptor`（消息级错误），或者是 1..n 个事务的 `transactionList`。多个事务拼接进一个消息；消息只是运输机制，**事务之间没有顺序含义**（§8.3）。

### 3.2 transaction 层（事务与关联标识）

```text
transactionList        = 1*( transactionRequest / transactionReply /
                             transactionPending / transactionResponseAck )
transactionRequest     = TransToken EQUAL TransactionID LBRKT actionRequest *(COMMA actionRequest) RBRKT
transactionReply       = ReplyToken EQUAL TransactionID LBRKT [ImmAckRequiredToken COMMA]
                         ( errorDescriptor / actionReplyList ) RBRKT
transactionPending     = PendingToken EQUAL TransactionID LBRKT RBRKT
transactionResponseAck = ResponseAckToken LBRKT transactionAck *(COMMA transactionAck) RBRKT
transactionAck         = transactionID / (transactionID "-" transactionID)
```

| 事务形态 | 全称 token | 缩写 token | 线上示例 |
|---|---|---|---|
| 请求 | `Transaction` | `T` | `T9998{...}` |
| 响应 | `Reply` | `P` | `P9998{...}`（可带 `IA,` 前缀声明 `ImmAckRequired`） |
| 未决 | `Pending` | `PN` | `PN9998{}` |
| 响应确认 | `TransactionResponseAck` | `K` | `K{9998}` 或范围 `K{100-105}` |

`TransactionID = UINT32 = 1*10(DIGIT)`。**事务关联标识 = transactionId**：由发送方分配、在发送方作用域内唯一（§8.1.1）；对端以同一 ID 回 Reply/Pending；`(mId, transactionId)` 二元组用于 At-Most-Once 去重（Annex D.1.1/D.1.2.1）。`K` 确认可携带区间（文本用 `-` 表示区间，Annex D.1.2.2），用于删除已确认响应副本。**K 校验规则**：`K` 的单点或区间所覆盖的每个事务 ID，必须 ⊆ 本会话已发生（已收到最终 Reply）的事务 ID 集合；确认未发生/未确认过的事务属 validator 拒绝项（锚词 `transaction`，负例 64）。区间形式 `K{a-b}` 合法；因 dissector 对区间 transid 只取首个数（§3.9 已知行为），v1.2 新增区间正例（用例 27）以帧字节前缀（`K{` + 区间文本）断言、不固化数值，既有单点例（13）不变。

### 3.3 action 层（Context 与通配符）

```text
actionRequest = CtxToken EQUAL ContextID LBRKT (( contextRequest [COMMA commandRequestList] ) / commandRequestList) RBRKT
actionReply   = CtxToken EQUAL ContextID LBRKT (( errorDescriptor / commandReply ) / (commandReply COMMA errorDescriptor)) RBRKT
ContextID     = (UINT32 / "*" / "-" / "$")    ; 0x0、0xFFFFFFFE、0xFFFFFFFF 为保留值
```

`CtxToken = ("Context" / "C")`。三个特殊值的语义（§8.1.2、Annex B.1）：`-` = NULL context（终结点尚未加入任何上下文，ROOT 类操作与空闲编程用它）；`$` = CHOOSE（请求 MG 新建上下文/自选终结点，**只允许出现在请求侧；Reply 必须回具体数值 ContextID**）；`*` = ALL（寻址全部上下文，不含 NULL）。MGC 不得使用"部分指定"的 ContextID 通配。数值 ContextID 由 MG 分配、MG 作用域内唯一，MGC 后续事务必须沿用 MG 返回的值——这是事务交互（后序事务依赖前序事务状态）的核心关联。

### 3.4 command 层（八命令）

```text
commandRequest = ( ammRequest / subtractRequest / auditRequest / notifyRequest / serviceChangeRequest )
commandRequestList = ["O-"] ["W-"] commandRequest *(COMMA ["O-"] ["W-"] commandRequest)
ammRequest         = (AddToken / MoveToken / ModifyToken) EQUAL TerminationID [LBRKT ammParameter *(COMMA ammParameter) RBRKT]
subtractRequest    = SubtractToken EQUAL TerminationID [LBRKT auditDescriptor RBRKT]
auditRequest       = (AuditValueToken / AuditCapToken) EQUAL TerminationID LBRKT auditDescriptor RBRKT
notifyRequest      = NotifyToken EQUAL TerminationID LBRKT observedEventsDescriptor [COMMA errorDescriptor] RBRKT
serviceChangeRequest = ServiceChangeToken EQUAL TerminationID LBRKT serviceChangeDescriptor RBRKT
```

| 命令 | token（全称/缩写） | 请求方向（现网惯例） | 语义要点（RFC 章节） |
|---|---|---|---|
| Add | `Add` / `A` | MGC→MG | 把终结点加入 Context；`Add=$` 令 MG 自选终结点（§7.2.1） |
| Modify | `Modify` / `MF` | MGC→MG | 修改终结点属性/事件/信号；NULL context 上编程空闲终结点（§7.2.2） |
| Subtract | `Subtract` / `S` | MGC→MG | 从 Context 移除；Context 内最后一个 Subtract 后上下文消失，可回 Statistics（§7.2.3） |
| Move | `Move` / `MV` | MGC→MG | 把终结点移到另一 Context，参数与 Add/Modify 同构（§7.2.4） |
| AuditValue | `AuditValue` / `AV` | MGC→MG | 审计当前值；**不受命令排序约束**（§9.1 规则 5）（§7.2.5） |
| AuditCapability | `AuditCapability` / `AC` | MGC→MG | 审计能力集（§7.2.6） |
| Notify | `Notify` / `N` | MG→MGC | 事件上报，携带 ObservedEvents（§7.2.7） |
| ServiceChange | `ServiceChange` / `SC` | 双向 | 注册/退服/故障切换/移交；ROOT 表示整机（§7.2.8） |

`O-` 前缀 = 可选命令（失败不中断事务，§8）；`W-` 前缀 = 请求通配化汇总响应（§6.2.2）。响应形态：`ammsReply`（Add/Move/Modify/Subtract）回 TerminationID 与可选 terminationAudit；`auditReply` 回属性集合或 `contextTerminationAudit`；`notifyReply`/`serviceChangeReply` 回命令确认或 errorDescriptor。**同一事务内命令按序执行；首个失败命令之后的事务内命令不再执行（可选命令除外）**（§8）。wildcarded 命令对每个匹配终结点各生成响应，除非请求 `W-` 汇总（§6.2.2）。

### 3.5 descriptor（描述符）层

| 描述符 | token（全称/缩写） | 语法要点 | RFC 章节 |
|---|---|---|---|
| Media | `Media` / `M` | `mediaParm = streamParm / streamDescriptor / terminationStateDescriptor`；stream 与 streamParm 二选一不混用 | §7.1.4 |
| Stream | `Stream` / `ST` | `Stream = <StreamID UINT16> { ... }`；tshark 字段 `megaco.streamid` | §7.1.6 |
| LocalControl | `LocalControl` / `O` | `Mode = SendOnly(SO)/ReceiveOnly(RC)/SendReceive(SR)/Inactive(IN)/Loopback(LB)`；`ReservedValue(RV)/ReservedGroup(RG) = ON/OFF`；包属性 `pkgdname=value`（如 `tdmc/gain=2`） | §7.1.7 |
| Local / Remote | `Local` / `L`，`Remote` / `R` | `{ octetString }` 承载 SDP（RFC 2327）；SDP 中的 `}` 须转义为 `\}`；`$` 可出现在 SDP 内表示待定值 | §7.1.8 |
| TerminationState | `TerminationState` / `TS` | `ServiceStates(SI) = Test(TE)/OutOfService(OS)/InService(IV)`；`EventBufferControl(BF) = OFF/LockStep(SP)`；包属性 | §7.1.5 |
| Events | `Events` / `E` | `[= RequestID] { pkgdName [参数], ... }`；RequestID 关联后续 Notify 的 ObservedEvents；支持嵌入描述符与 `DigitMap=名` | §7.1.9 |
| EventBuffer | `EventBuffer` / `EB` | 事件缓冲描述 | §7.1.10 |
| Signals | `Signals` / `SG` | `{ pkgdname [参数], SignalList=ID{...} }`；信号类型 `OO/TO/BR` | §7.1.11 |
| DigitMap | `DigitMap` / `DM` | `= 名 [ { [T:定时器,] [S:,] [L:,] 数字串 } ]`；数字串字母 `0-9 a-k A-K L S Z`、`x` 任意、`[2-5]` 范围、`.` 长通配、`|` 分支；定时器 T/S/L 各 1-99 秒（`T:0` 为禁用启动定时器的合法语义，不属越界；越界=T>99 与 S/L 为 0——v1.2 D-4 口径修正）；数字串含 `Z` 修饰符（digitMapLetter，Timer 口径 100ms-9.9s） | §7.1.14 |
| ObservedEvents | `ObservedEvents` / `OE` | `= RequestID { [时间戳:] pkgdname [参数], ... }`；时间戳 ISO 8601 `yyyymmddThhmmssss`（百分之一秒精度） | §7.1.17 |
| Statistics | `Statistics` / `SA` | `{ pkgdname[=值], ... }`，Subtract 回复携带 | §7.1.15 |
| Packages | `Packages` / `PG` | `{ 名-版本, ... }`（如 `g-1`） | §7.1.16 |
| Audit | `Audit` / `AT` | `{ auditItem, ... }`，auditItem ∈ {Mux,Modem,Media,Signals,EventBuffer,DigitMap,Statistics,Events,ObservedEvents,Packages} | §7.1.12 |
| Services | `Services` / `SV` | ServiceChange 命令参数块：`Method(MT)`、`Reason(RE)`、`Delay(DL)`、`ServiceChangeAddress(AD)`、`MgcIdToTry(MG)`（两者互斥——ABNF at most one of either，validator 校验，负例 77）、`ServiceChangeMgcId`（Reply 改派用，§11.2）、`Profile(PF)=名/版本`、`Version(V)`、`TimeStamp`、扩展参数 | §7.1.13 |
| Error | `Error` / `ER` | `= 1*4(DIGIT) { "原因字符串" }`；错误码出处混合——部分 RFC 3525 正文引用、部分 H.248.8/IANA 错误码注册（v1.2 D-5 口径修正） | §7.1.19 |
| Topology / Mux / Modem | `Topology` / `TP`，`Mux` / `MX`，`Modem` / `MD` | Context 属性三元组 / 复用 / 调制解调；本版正例不展开 | §7.1.2/3/18 |

`pkgdName = 包名/条目名`（如 `al/of`、`dd/ce`、`cg/dt`、`tdmc/gain`），`*/*` 表示全部。`EQUAL/LBRKT/RBRKT/COMMA` 都允许零或多空白（`LWSP`），故 `Method=Restart` 与 `Method = Restart` 等价——fixture 固定用 RFC 附录 I 风格（token 后空格、`=` 前后无强制空格按示例）。

### 3.6 ServiceChange 方法与原因码（§7.2.8、§13.3）

`Method ∈ {Graceful(GR), Forced(FO), Restart(RS), Disconnected(DC), HandOff(HO), Failover(FL), 扩展}`。`Reason` 是带引号字符串：十进制原因码 + 可选空格 + 文本（如 `"901 Cold Boot"`）。规范原因码样例：`900 Service Restored`、`901 Cold Boot`、`903 MGC Directed Change`、`908 MG Impending Failure`、`909 MGC Impending Failure`。协议级错误码样例（v1.2 D-5 出处口径修正：部分为 RFC 3525 正文引用（如 410/411/430/505，见 §7.2/§8/§9.1），部分经 H.248.8/IANA 错误码注册（如 431/442）——逐码出处以规范索引为准，不统一声称"正文引用"）：`400 Bad Request`、`401 Protocol Error`、`403 Syntax Error in TransactionRequest`、`406 Version Not Supported`、`410 Incorrect Identifier`、`411 Unknown ContextID`、`422 Syntax Error in Action`、`430 Unknown TerminationID`、`431 No TerminationID matched a wildcard`、`442 Syntax Error in Command`、`505 Command Received before a ServiceChange Reply`。

### 3.7 TerminationID 与 ROOT（§6.2.2、§6.2.5、Annex B.1）

`TerminationID = "ROOT" / pathNAME / "$" / "*"`；`pathNAME ≤ 64 字符`，可含 `/` 分层与前缀结构（如 `A4444`、`R13/3/1`）。通配：`*` = ALL（前缀匹配，如 `R13/3/*` 匹配该前缀全部；**ALL 不寻址 ROOT**）；`$` = CHOOSE（请求 MG 创建/自选）。ROOT 是网关整体的虚拟终结点（根包属性：`maxTerminations`、`normalMGExecutionTime`、`normalMGCExecutionTime`、`ProvisionalResponseTimerValue` 等）。

### 3.8 端序与数值编码

文本编码全部为 ASCII 十进制文本（`UINT16 = 1*5(DIGIT)`、`UINT32 = 1*10(DIGIT)`、`Version = 1*2(DIGIT)`），**没有字节端序概念**；二进制 BER（Annex A）为 TLV 大端，仅 profile 边界（§1）。值编码：`VALUE = quotedString / 1*SafeChar`；含 SafeChars 之外字符的值必须用双引号 quotedString（双引号不可出现在值内）；`SafeChar` 不含 `;[]{}:,#<>=`（这些是 `RestChar`，只能出现在 quotedString）。`octetString`（SDP）允许 `%x01-FF` 除转义规则外字节，`}` 转义为 `\}`。

### 3.9 tshark 证据字段（本机 3.6.14 `-G fields` 实测）

`megaco` 文本 dissector 绑定 `udp.port 2944`、`tcp.port 2944`（另 sctp 2944），2944 载荷自动按 megaco 解码。可用字段（本契约断言只用这些或标准载体字段）：

```text
megaco.start_token  megaco.version  megaco.mId
megaco.transaction  megaco.transid  megaco.context  megaco.ctx  megaco.ctx.term
megaco.command  megaco.command_optional  megaco.wildcard_response
megaco.media  megaco.localdescriptor  megaco.remotedescriptor  megaco.localcontroldescriptor
megaco.mode  megaco.streamid  megaco.servicestates  megaco.eventbuffercontrol
megaco.reservevalue  megaco.reservegroup  megaco.terminationstate
megaco.events  megaco.requestid  megaco.observedevents  megaco.signal
megaco.digitmap  megaco.statistics  megaco.packagesdescriptor  megaco.pkgdname
megaco.audit  megaco.audititem  megaco.termid  megaco.topology  megaco.priority
megaco.error  megaco.error_code  megaco.error_string
```

另实测存在解析诊断字段 `megaco.parse_error`、`megaco.errored_command`、`megaco.no_command`、`megaco.no_descriptor`、`megaco.error_code.invalid` 等，实现后可作负例辅助证据。**端口 2427（mgcp 别名用例）实测绑定的是 `mgcp` dissector（`mgcp.req.verb` 等），tshark 不会自动按 megaco 解码**：该用例证据用 `decode_as` 指令（`-d udp.port==2427,megaco`）或 offset 42 起的起始行/命令 token 字节断言，二选一，case JSON 实现时定并同步四件套。`h248.*` 是 BER 解析器字段族，文本主线不用。TCP 载荷侧实测：megaco TCP 解析先 `is_tpkt()` 探测，TPKT 分支走 `dissect_tpkt_encap`（本契约主路径），非 TPKT 回退裸文本。已知 dissector 行为（断言校准用）：`transactionPending` 的 `megaco.transaction` 也置 `Reply`（值域 {Request, Reply, TransactionResponseAck, Error}）；`K` 区间 transid 只取首个数——Pending 与 `K` 的断言按帧字节前缀处理（用例 13/27）。

### 3.10 消息总长度公式

- Megaco 消息长度（文本）= 起始行 + 事务块按 §3.1–§3.5 ABNF 逐 token 展开的字节数（含 LWSP/EOL 与注释），无固定上界；受载体约束：UDP 载体 ≤ MTU − IP 头 − UDP 头（Annex D.1），TCP 载体受 MSS 分段（§8）。
- UDP/IPv4 帧长 = Ethernet 14 + IPv4 20 + UDP 8 + 消息长度；UDP/IPv6 帧长 = 14 + 40 + 8 + 消息长度。
- TCP 载荷内 TPKT PDU = TPKT 头 4B + 消息长度（TPKT 总长度域 = 4 + 消息长度，RFC 1006）；TCP/IPv4 帧长 = 14 + 20 + 20 + 4 + 消息长度；TCP/IPv6 帧长 = 14 + 40 + 20 + 4 + 消息长度。一条 TPKT PDU 跨段时段数 = ceil((4 + 消息长度) / MSS)，TCP 包数 = 3 + 段数 + 4（§9 约定）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

生成器是**声明式脚本化回放**：`sessions[]`（事件编排会话）自带四元组与自己的事件序列，`events[]` 按序整块回放，双侧（MG/MGC）报文都来自脚本声明，不自动补业务响应；引擎内仅既有自动应答（如 TCP 握手补齐）与连接边界（事件序列中源端口切换触发新连接）属反应性成分。

现网五个典型场景（RFC 3525 Appendix I 走查为蓝本）：

1. **MG 注册（冷启动）**：MG 向主用 MGC 发 `ServiceChange = ROOT {Services {Method=Restart, Reason="901 Cold Boot", ServiceChangeAddress=<端口>, Profile=<名>/1, TimeStamp}}`；MGC 回同 transactionId 的 Reply（不带 `MgcIdToTry` 即接受注册；带则 MG 转向指定 MGC 重发，§11.2）。首个 ServiceChange 必须携带 `ServiceChangeVersion` 供版本协商（§11.3，低版本胜出，否则 406）。**注册完成前 MG 不得发其他命令**（§9.1 规则 6；违反即错误 505）。
2. **呼叫建立命令序列**：MGC 先在 NULL context 编程空闲物理终结点（`Modify = A4444 {Events=2222{al/of}, Signals, DigitMap}`）→ MG 摘机 `Notify`（`ObservedEvents=2222{al/of}`）→ MGC 二次 Modify 换事件集与拨号计划 → `Context = $ { Add = A4444, Add = $ {Media{Stream=1{LocalControl{Mode=ReceiveOnly}, Local{SDP(含 $)}}}} }` 建连 → MG Reply 回具体 ContextID 与填充后的 Local（地址/端口/编解码）→ MGC 用对端媒体参数 Modify Remote → 话毕 `Subtract`（可回 Statistics），Context 消失。
3. **Notify 事件上报**：MG 检测到事件（摘机、DTMF 收号完成 `dd/ce{ds="..."}`）即发 Notify；`ObservedEvents` 的 RequestID 必须与生效 Events 描述符的 RequestID 一致（§7.1.9/§7.1.17 关联）；UDP 上同一终结点同时至多一个未决 Notify（§9.1 规则 3）。
4. **Audit 巡检**：MGC 用 AuditValue/AuditCapability 巡检具体终结点、ROOT（根包属性、Packages）或通配 `*`；Audit 不受命令排序约束（§9.1 规则 5）；通配审计可逐匹配回或 `W-` 汇总回。
5. **MGC 故障 handoff/failover**：MGC 计划退服→向 MG 发 `ServiceChange` `Method=HandOff` + `Reason="903 MGC Directed Change"` + `MgcIdToTry=<新 MGC>`（Services 的 Method 与 Reason 均 REQUIRED，§7.1.13/Annex B.2）；MG 向新 MGC 发 `ServiceChange` `Method=HandOff` + `Reason="903 MGC Directed Change"`（§11.5）。MG 检测到 MGC 失败→向备用 MGC 发 `Method=Failover` + `Reason="909 MGC Impending Failure"`；重连原 MGC 用 `Disconnected`。响应永远回请求源地址（§9）。

### 4.1 五层覆盖落点

| 层面 | 要求 | 本协议落点（用例 ID 见 testcase §2） |
|---|---|---|
| 功能 | 全部命令/事务形态/状态流转有正例；错误处理逐故障输入负例（v1.3） | 八命令全覆盖：SC（1/2/7/8/19/20/21/22/38/44）、Modify（4/5/12/15/17/18/23/29/31/32/33/41/42/43/46）、Add/Subtract（4/9）、Move（9）、Notify（5/12）、AV/AC（3/6/34/36/37）、O-/W-（6）；事务四形态：Request/Reply 全体、Pending+IA+K（13）与 K 区间（27）；错误描述符两级：动作级（3）+事务级（26）、`transid 0` 错误 Reply（28）；描述符族：Media/LocalControl（4/9/29/41）、TerminationState（18）、Events/EventBuffer/Embed/无 RequestID（5/12/30/42/43）、Signals（35）、DigitMap（10/17/46）、ObservedEvents（5）、Services（19/38/44）、Audit（6/34）、Statistics（4）、Packages（6）；状态流转：注册→协商→编程→建连→拆连（4/19）、handoff/failover/disconnected（2/7/21/22）、改派（44）；负例 47-77 逐故障输入 31 行（§7） |
| 性能 | 大报文/边界/多事务并发 | 大 DigitMap 单数据报承载（10）；长 TPKT PDU 跨 MSS 分段、按 TPKT 长度域切分重组（11）；长事务 Pending/IA/K 往返（13）；K 区间（27）；UDP 超 MTU 拒绝（负例 76）；消息长度上界=MSS/MTU 约束（§3.10、§8） |
| 数据场景 | 值域/边界/编码变体 | Mode 值域 RC/SR（4/9）+SO/IN/LB（31/32/33）；RV/RG（29）；TerminationState（18）；auditItem 值域（34）；Signals OO/TO/BR+SignalList（35）；Method 值域 Graceful/Forced/Disconnected（20/21/22）；错误码 431/442（36/37）；Delay/TimeStamp（38）；版本协商（19）；Z 修饰符（46）；缩写/大小写（8）；空白/注释（23）；mId 形态（24/25）；边界：TerminationID 恰 64（15）、transactionId 恰 UINT32 上界（16）、定时器恰 99（17）、transid 0（28）、ContextID 0xFFFFFFFD（39）、Version 2 位（40）、StreamID 65535（41）；通配 `-/$/*`（4/6/9）；Reason 引号串（1/2/7） |
| 地址与流 | v4+v6、单流基线、多会话/并发 | v4 全量、v6（2/4）；UDP/TCP 双载体；单流基线（1）；多会话（7/12/44）；**并发会话（v1.2 翻案纳入）**（45，`concurrent: true` 交错）；**流关联显式不适用（保留）**：Megaco 是控制面协议，本 planner 不派生 RTP 媒体数据面，媒体地址/端口仅作 SDP 文本与描述符存在性断言 |
| 业务 | 现网场景、多会话、多事务 | 注册（1/14/19/44）、呼叫建立（4/9）、Notify 上报（5/12）、Audit 巡检（6/34）、handoff/failover/disconnected（2/7/21/22）；多事务：同消息双事务（3/6）+ 会话内多消息依赖（4）+ 长事务三方握手（13）；多会话双四元组状态隔离（12）；并发关联（45）；三名合一别名（14） |

## 5. 消息/事务模型与状态机

### 5.1 事务关联与配对规则

- **事务关联标识 = transactionId**：发送方作用域唯一（§8.1.1）；MGC 可按 MG 分空间，MG 仅凭 `(mId, transactionId)` 去重（Annex D.1.2.1）。事务 ID 0 保留给"请求缺 ID"的错误 Reply（§8.1.1）。
- **一请求一响应**：一个 TransactionRequest 恰好对应一个 TransactionReply，期间可有多个 TransactionPending（§8）。Reply 的 transactionId 必须等于请求；`ImmAckRequired(IA)` 出现在"曾回过 Pending"的最终 Reply 里，对端以 `K{...}` 确认——Pending→IA→K 构成 Annex D.1.4/D.1.2.2 的三方握手（TCP 同样适用，Annex D.2.2/D.2.4）。
- **事务间无序、事务内有序**：同一消息内多事务相互独立、可乱序/并发处理（§8.3）；同一事务内命令顺序执行，首错停止（`O-` 可选命令豁免）（§8）。**生成器按事件序列显式驱动顺序**（声明式脚本化回放），不依赖传输层保序语义；UDP 上跨消息顺序由事件序列决定。
- **事务交互**：后序事务依赖前序事务状态——Add 返回的具体 ContextID/TerminationID 被后续 Modify/Move/Subtract 引用；`$`/CHOOSE 只在请求侧，响应必回具体值（§8.1.2）。
- **MG/MGC 双侧驱动角色**：注册、Notify、Failover/Disconnected 由 MG 发起；呼叫控制（Add/Modify/Move/Subtract）、Audit、HandOff 由 MGC 发起；ServiceChange 双向。会话按 `role` 或事件 `direction`（`c2s` = MG→MGC，`s2c` = MGC→MG）声明方向，planner 校验"该角色在该状态是否允许发该命令"。mId 两方向各自恒定（RFC §8.3 每实体所有消息同一 mId）：`mid` 是会话 role 实体的 mId、`peer_mid` 是对端实体的 mId（§6）；方向映射随角色翻转——role=mg 会话：c2s（MG→MGC）消息用 `mid`、s2c（MGC→MG）消息用 `peer_mid`；role=mgc 会话相反（s2c 用 `mid`、c2s 用 `peer_mid`）。未声明 `peer_mid` 时按 §6 派生（role=mg 取 `[dst_ip]`、role=mgc 取 `[src_ip]`）。

### 5.2 会话状态机（每个事件编排会话独立一份）

| 状态 | 允许事件 | 必须保持 | 非法事件 → validator 拒绝（锚词） |
|---|---|---|---|
| `Unregistered` | MG 发 SC(Restart/Failover/HandOff) 注册；收到 MGC HandOff | 注册前不得发其他命令（违反→错误 505 语义，§9.1 规则 6、§11.2） | MG 发非 SC 命令 → 拒绝（`command`） |
| `Registering` | SC 的 Reply（接受/改派 MgcIdToTry）；版本协商 Version 字段 | Reply transactionId = 注册请求；低版本胜出（§11.3） | Reply id ≠ 请求 id → 拒绝（`transaction`）；版本非 1-2 位数字或为 0 → 拒绝（`message`） |
| `Registered` | MGC 侧任意事务；MG 侧 Notify/SC | mId 两方向各自恒定（§5.1、§6）；事务 ID 作用域唯一 | reply 动作使用 `$`/`*` context → 拒绝（`command`）；同会话重复 transactionId → 拒绝（`transaction`） |
| `Provisioning`（NULL context） | Modify/AV/AC 于具体终结点或 ROOT | 终结点存在才可 Modify；Events RequestID 记录待 Notify 关联 | Modify 不存在的终结点 → 拒绝（`command`） |
| `CallActive`（数值 Context） | Add($ 建连)/Modify/Move/Subtract | CHOOSE 只在请求；响应回具体 ContextID；Context 内最后 Subtract 后 Context 消失 | 引用未创建 Context → 拒绝（`command`）；保留值 ContextID（0/0xFFFFFFFE/0xFFFFFFFF）作具体 Context → 拒绝（`length`） |
| `LongRunning`（长事务） | PN{ }、最终 Reply(IA)、K{单点/区间} | PN/Reply/K 同 transactionId；IA 仅在回过 PN 之后；K 覆盖集 ⊆ 已确认事务集合（§3.2） | PN/Reply id ≠ 请求 id、IA 无前置 PN、K 确认未发生事务 → 拒绝（`transaction`） |
| `Failover/Handoff` | SC(HandOff/Failover/Disconnected) + Reply | 响应发请求源地址；新关联重新走 Unregistered→注册；Services 的 Method 与 Reason 均必选（§3.6） | 会话四元组与请求源地址不符 → 拒绝（`carrier`）；Reason 缺失 → 拒绝（`message`） |
| `Error`（事件级） | Reply 内 errorDescriptor（如 430） | 首错停止本事务后续命令；`O-` 命令豁免；消息级 Error 则无事务体（本版不覆盖正例，§7） | 首错后非 O- 命令仍执行 → 拒绝（`command`） |

**初始状态规则（确定性）**：每个事件编排会话的初始状态由首事件唯一确定——首事件为 MG 发出的注册类 SC（Restart/Failover/HandOff）→ 从 `Unregistered` 起步；其余一切会话（含全部 role=mgc 会话、以及以 MGC 编程/呼叫/审计事务开头的会话）初始即 `Registered` 等价态。依据：注册是 MG 的义务，MGC 侧无注册义务（§11）；声明式回放的会话是预配置控制关联，注册只是可选的首事件（用例 4/5/9 据此合法）。

**确定性声明**：同一配置输入（rand 类策略须显式 `seed`）必然产生同一事件序列与同一字节输出；生成器在某状态下遇到合法事件按序编码回放，遇到非法事件一律在 validator 配置期拒绝（§7 锚词传播为 task error），不静默跳过、不自动修正、不重排成合法顺序。

**流关联显式声明不适用**（理由见 §4.1 地址与流行）。多流（一个会话内部并发流）亦不设：一个控制关联就是一条 UDP 四元组流或一条 TCP 字节流。**并发会话（v1.2 翻案）**：多连接级并发纳入——`sessions[]` 支持 `concurrent: true` 交错回放（正例 45；判例 cwmp⑦/doh/onvif/hl7 同形：单关联内事务串行性只约束关联内部，不约束生成器级多连接交错）；多会话默认仍按序整块展开（§8）。

## 6. 配置 typedef（JSON 形状契约，非现有 Go 结构）

顶层遵循层链配置；`megaco` 子映射承载协议语义。事件编排会话（`sessions[]`）各自带四元组与事件序列，按序整块回放（多会话展开）：

```json
{
  "protocol": "megaco",
  "config": {
    "layers": [{"udp": {}}, {"megaco": {}}],
    "src_ip": "192.0.2.10", "dst_ip": "192.0.2.4",
    "src_port": 40000, "dst_port": 2944,
    "megaco": {
      "profile": "megaco_v1_text",
      "encoding": "text",
      "version": 1,
      "token_form": "long",
      "sessions": [
        {
          "name": "mgc-assoc-1",
          "src_ip": "192.0.2.10", "dst_ip": "192.0.2.4",
          "src_port": 40000, "dst_port": 2944,
          "mid": "<mgw-1.example.net>",
          "peer_mid": "[192.0.2.4]",
          "role": "mg",
          "events": [
            {
              "kind": "message",
              "direction": "c2s",
              "transactions": [
                {
                  "id": "auto",
                  "type": "request",
                  "actions": [
                    {
                      "context": "-",
                      "commands": [
                        {
                          "name": "ServiceChange",
                          "termination": "ROOT",
                          "optional": false,
                          "wildcard_response": false,
                          "descriptor": {
                            "services": {
                              "method": "Restart",
                              "reason": "901 Cold Boot",
                              "service_change_address": 2944,
                              "profile": "ResGW/1",
                              "version": 1
                            }
                          }
                        }
                      ]
                    }
                  ]
                }
              ]
            },
            {
              "kind": "message",
              "direction": "s2c",
              "transactions": [
                {
                  "id": "same_as_request:0",
                  "type": "reply",
                  "actions": [
                    {
                      "context": "-",
                      "commands": [
                        { "name": "ServiceChange", "termination": "ROOT",
                          "descriptor": { "services": { "profile": "ResGW/1", "version": 1 } } }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }
      ],
      "wire_fault": null
    }
  }
}
```

配置键约束：

| 键 | 约束 |
|---|---|
| `profile` | 本版固定 `megaco_v1_text`；`mgcp_alias` 仅表示"入口名 mgcp + 2427 默认端口"，线格式不变 |
| `encoding` | `text`（主线）；`ber` 仅可声明，本期不产生 BER 载荷——声明与载荷不一致必须拒绝（负例 47）；text 编码配 2945 端口同拒（负例 48） |
| `version` | 起始行版本 1-2 位数字，主口径恒 `1`（2 位数字形态为语法边界 carve-out，用例 40）；3 位数字拒绝（负例 51，Min/Max [1,99] 执法）；显式 `0` = 采用缺省版本（V9 skip-0 框架规则下 schema 面不报错、渲染与缺省同值 1，线上无差异——负例 50 以书面豁免登记，实现面 D-MEGACO-1 F6 表；v1.2.2 修） |
| `token_form` | `long`（`MEGACO/1`、`Transaction`、`Context`、`Add`）或 `abbrev`（`!/1`、`T`、`C`、`MF`、`AV` 等），仅影响编码形式，语义相同；response_ack 缩写形恒 `K`（§3.2 表， abbrev 下不得出现 `ResponseAck` 长串） |
| `whitespace` | 空白/注释变体（RFC 3525 Annex B.2 LWSP/EOL/COMMENT，用例 23）：缺省标准 LF；`cr` = CR-only EOL；`comment` = 起始行与事务列表之间插入独立 `; ...` 注释行（合法 ABNF COMMENT，tshark 3.6 dissector 不实现会报 `_ws.malformed` 伪影，帧字节以用例 frames 六钉为准）；`lwsp` = 起始行 SEP 双空格 |
| `mid` | 会话 role 实体（`mg`/`mgc`）的 mId，四种形式之一（§3.1），同一会话内恒定；方向映射随角色翻转（§5.1）：role=mg 用于 c2s 消息、role=mgc 用于 s2c 消息 |
| `peer_mid` | 对端实体的 mId，四种形式之一，用于另一方向消息（role=mg 的 s2c / role=mgc 的 c2s）。优先级：显式 `peer_mid` > 自动派生（未声明时取对端地址 domainAddress：role=mg → `[dst_ip]`、role=mgc → `[src_ip]`，地址族随外层 v4/v6）；validator 校验两方向各自恒定（§5.1） |
| `sessions[]` | 事件编排会话：四元组 + `role`（`mg`/`mgc`）+ `events[]`；多会话按序整块回放，第二会话包号起点 = 前会话总包数 + 1；`concurrent: true` 交错回放（v1.2 翻案，正例 45） |
| `events[]` | 事件序列；`kind=message`、`direction=c2s/s2c`；一个事件一条完整 Megaco 消息（可含多事务） |
| `transactions[].id` | `auto`（运行期分配，缺省）或 `same_as_request:<序号>`（Reply/Pending 引用同会话第 i 个请求）；显式数字仅允许 wire_fault 注入用与 §8 声明的边界用例（边界值本身即被测规格点，如用例 16 的 4294967295），其余正例禁止固化运行期值 |
| `transactions[].type` | `request` / `reply` / `pending` / `response_ack`；`response_ack` 无 actions，写 `ack` 区间声明 |
| `actions[].context` | `"-"` / `"$"` / `"*"` / 数字字符串；`reply` 动作里出现 `"$"` 或 `"*"` 必须拒绝（CHOOSE/ALL 仅请求侧语义，负例 58）；数值 Context 不得取保留值 0/0xFFFFFFFE/0xFFFFFFFF（负例 71） |
| `commands[]` | `name` ∈ 八命令；`termination` 为 ROOT/pathNAME/`$`/`*`；`optional` 映射 `O-` 前缀；`wildcard_response` 映射 `W-` 前缀 |
| `descriptor` | 子映射按 §3.5 描述符表：`media`（streams[]{id, local_control{mode,...}, local_sdp, remote_sdp}, termination_state{...}）、`events`（request_id, items[]{pkgdname, params, digit_map, keep_active}）、`signals`、`digit_map`（name, timers, value）、`observed_events`（request_id, items[]{timestamp, pkgdname, params}）、`services`（method, reason, delay, service_change_address, mgc_id, service_change_mgc_id, profile, version, timestamp）、`audit`（items[]）、`event_buffer`（v1.2）、`embed`（Events 嵌套，v1.2）、`statistics`、`packages`、`error`（code, text）、`topology`、`mux`、`modem` |
| `wire_fault` | 仅负例的故障注入口，31 值与 §7 表一一对应（同序）：`encoding_text_as_ber`、`encoding_port_mismatch`、`syntax_start_line`、`syntax_version_zero`、`syntax_version_three_digits`、`syntax_mid_missing`、`syntax_mid_invalid`、`syntax_body_form`、`syntax_services_missing_params`、`command_pre_registration`、`command_modify_nonexistent`、`command_reply_choose_all`、`command_uncreated_context`、`command_first_error_continues`、`pairing_reply_id_mismatch`、`pairing_pending_id_mismatch`、`pairing_duplicate_transid`、`pairing_ack_unconfirmed`、`pairing_ia_without_pending`、`pairing_observed_requestid`、`length_message_truncated`、`length_termid_over_64`、`length_transid_over_uint32`、`length_digitmap_timer`、`length_context_reserved`、`carrier_layer_mismatch`、`carrier_entry_port_encoding`、`carrier_invalid_port`、`carrier_return_address`、`carrier_udp_mtu_exceeded`、`services_address_mgcidtotry_conflict` |

`Validate` 必须覆盖：profile/encoding/版本/端口与载体一致性、token_form 合法性、mId 形式与会话恒定（含 `peer_mid` 派生）、事务类型与 id 引用闭环（每个 request 恰好一个 reply/pending 配对）、CHOOSE/ALL 使用侧别、命令-角色-状态合法性（§5.2）、描述符必选参数（如 Services 的 Method/Reason）与互斥参数（ServiceChangeAddress↔MgcIdToTry——负例 77）、TerminationID 长度与通配、digitMap 语法、多会话四元组独立性、wire_fault 仅注入不落线。

**自动派生清单**（生成器自动补出的内容，逐项触发条件与内容，不依赖隐含知识）：

| 派生项 | 触发条件 | 内容/规则 |
|---|---|---|
| TCP 三次握手 | TCP 载体会话首事件之前 | 引擎既有自动应答；SYN→SYN-ACK→ACK；计入 §9 TCP 包数（= 3 + 段数 + 4） |
| TCP 四次挥手 | TCP 载体会话末事件之后（每个方向 FIN/ACK 各一） | 引擎既有自动应答；FIN→ACK→FIN→ACK（双向）；计入 §9 TCP 包数 |
| TCP MSS 分段 | TCP 载荷（TPKT PDU）总长 > MSS | 引擎既有 MSS 分段；TPKT 是成帧不是分段，TPKT 长度域不变；分段发生在 TPKT 之下，跨段时 TPKT 头只出现在第一段（流内首个分段），后续段为 TCP PSH-ACK payload 延续 |
| TPKT 头（RFC 1006） | 每条 TCP 消息（每个 events[] message 元素） | 头 4B：版本 0x03、保留 0x00、总长度 = 4B 头 + Megaco 消息长度（2B 大端） |
| transactionId auto | `transactions[].id == "auto"` | 运行期分配 UINT32 非零非重复；同会话作用域唯一 |
| `same_as_request:<i>` 回填 | Reply/Pending/ResponseAck 配置引用 | 解析为该会话第 i 个 request 的 transactionId；validator 闭环校验（每个 request 恰一个 reply/pending） |
| 对端 mId 派生 | 存在对端方向消息（role=mg 的 s2c / role=mgc 的 c2s）且未显式 `peer_mid` | 取对端地址 domainAddress：role=mg → `[dst_ip]`、role=mgc → `[src_ip]`（地址族随外层 v4/v6） |
| 本端 mId 派生 | 未显式 `mid` | 取本端（role 实体）地址 domainAddress：role=mg → `[src_ip]`、role=mgc → `[dst_ip]` |
| Pending→IA 校验 | reply 携带 `ImmAckRequired` 前缀 | validator 校验该事务此前至少一条 PN（pnid == transid），否则拒绝（锚词 `transaction`，§5.2） |
| K 区间覆盖校验 | K 携带区间 `K{a-b}` 或单点 `K{x}` | validator 校验覆盖集 ⊆ 本会话已发生（已收最终 Reply）事务 ID 集合；否则拒绝（锚词 `transaction`） |

**配置→validator→builder→事件/包管线分步**：① 配置层：JSON 读入，按 §6 键约束与 `Validate` 清单校验（合法 → 进 builder；非法 → 拒绝并经任务错误传播，§7 锚词）；② builder 层：按 `encoding=token_form` 拼装文本线格式（§3.1–§3.5），对 TCP 载体额外拼 TPKT 头（§3.10）；③ 事件层：把 events[] 序列喂给 scheduler，按 s2c/c2s 排序落入 UDP 数据报或 TCP TPKT PDU，再交给 MSS 分段；④ 输出层：UDP 一个数据报一消息；TCP = 3 握手 + N 段 + 4 挥手（§9 约定）；⑤ 验证层：tshark 解码 + §3.9/§3.10 字段与帧字节断言。

## 7. 错误处理（负例锚词表）

所有负例在 planner/validator 阶段失败并传播为 task error（任务错误）：不得产出成功 PCAP、不得 `completed/0 packet`、不得只剩传输层外壳假成功。负例执行期 `expect` 严格只有 `expect_error` 与 `error_contains`。锚词（anchor word）是错误文案必须包含的关键词，validator 实现与用例契约共用本表：

| 负例 ID | 类别 | 故障输入（单一注入） | 主锚词 `error_contains` | 备选锚词 | 设计依据 |
|---|---|---|---|---|---|
| `megaco_neg_encoding_text_as_ber` | 配置/编码错 | `encoding=ber` 声明而载荷为文本字节 | `encoding` | ber/text | 设计§1/§3.8 |
| `megaco_neg_encoding_port_mismatch` | 配置/编码错 | text 编码声明配 2945（BER 默认端口） | `encoding` | port | 设计§2 |
| `megaco_neg_syntax_start_line` | 线格式错 | 起始行 MegacopToken 缺失/拼错（非 `MEGACO`/`!`） | `message` | syntax | RFC 3525 Annex B |
| `megaco_neg_syntax_version_zero` | 线格式错 | 起始行版本为 `0` | `version` | message | 设计§3.1 |
| `megaco_neg_syntax_version_three_digits` | 线格式错 | 起始行版本 3 位数字（Version=1*2DIGIT 越界） | `version` | message | RFC 3525 Annex B |
| `megaco_neg_syntax_mid_missing` | 线格式错 | mId 缺失（起始行后直接 messageBody） | `mid` | message | 设计§3.1 |
| `megaco_neg_syntax_mid_invalid` | 线格式错 | mId 非法形式（四形态之外） | `mid` | message | 设计§3.1 |
| `megaco_neg_syntax_body_form` | 线格式错 | messageBody 既非事务表也非 errorDescriptor | `message` | syntax | RFC 3525 Annex B |
| `megaco_neg_syntax_services_missing_params` | 线格式错 | Services 缺必选 Method/Reason（描述符必选参数） | `message` | services | RFC 3525 §7.1.13 |
| `megaco_neg_command_pre_registration` | 状态机错 | 注册前发非 SC 命令（505 语义，§9.1 规则 6） | `command` | state | RFC 3525 §9.1 |
| `megaco_neg_command_modify_nonexistent` | 状态机错 | 未 Add 先 Modify/Subtract 不存在终结点 | `command` | termination | 设计§5.2 |
| `megaco_neg_command_reply_choose_all` | 状态机错 | reply 动作使用 `$`/`*` context（CHOOSE/ALL 仅请求侧） | `command` | context | 设计§3.3 |
| `megaco_neg_command_uncreated_context` | 状态机错 | 引用未创建的数值 Context | `command` | context | 设计§5.2 |
| `megaco_neg_command_first_error_continues` | 状态机错 | 同事务首命令失败后第二命令（无 O-）响应仍出现（首错后仍执行） | `command` | state | RFC 3525 §8 |
| `megaco_neg_pairing_reply_id_mismatch` | 关联错 | Reply transactionId 与请求不等 | `transaction` | reply | 设计§5.1 |
| `megaco_neg_pairing_pending_id_mismatch` | 关联错 | Pending transactionId 与请求不等 | `transaction` | pending | 设计§5.1 |
| `megaco_neg_pairing_duplicate_transid` | 关联错 | 同会话重复 transactionId（作用域唯一性） | `transaction` | duplicate | 设计§5.1 |
| `megaco_neg_pairing_ack_unconfirmed` | 关联错 | `K` 确认未发生/未确认过的事务（覆盖集 ⊄ 已确认集合） | `transaction` | ack | 设计§3.2 |
| `megaco_neg_pairing_ia_without_pending` | 关联错 | `ImmAckRequired` 出现在未回过 Pending 的事务 | `transaction` | ack | 设计§5.2 |
| `megaco_neg_pairing_observed_requestid` | 关联错 | ObservedEvents RequestID 与生效 Events RequestID 不匹配 | `transaction` | requestid | RFC 3525 §7.1.9/§7.1.17 |
| `megaco_neg_length_message_truncated` | 长度错 | 消息截断（messageBody 未闭合/尾部缺失） | `length` | truncat | 设计§7 |
| `megaco_neg_length_termid_over_64` | 长度错 | TerminationID 超 64 字符（pathNAME 上界） | `length` | limit | RFC 3525 §6.2.2 |
| `megaco_neg_length_transid_over_uint32` | 长度错 | transactionId >4294967295（UINT32 越界） | `length` | limit | 设计§3.2 |
| `megaco_neg_length_digitmap_timer` | 长度错 | DigitMap 定时器越界：T>99 或 S/L 为 0（D-4 口径：T:0 为合法禁用语义不归越界） | `length` | timer | RFC 3525 §7.1.14 |
| `megaco_neg_length_context_reserved` | 长度错 | ContextID 取保留值 0/0xFFFFFFFE/0xFFFFFFFF 作具体 Context | `length` | context | RFC 3525 §8.1.2 |
| `megaco_neg_carrier_layer_mismatch` | 配置/载体错 | 层链 udp/tcp 与配置声明不符 | `carrier` | layer | 设计§2 |
| `megaco_neg_carrier_entry_port_encoding` | 配置/载体错 | 入口名-端口-编码组合非法（text 配 2945、mgcp 别名配非法载体） | `carrier` | profile | 设计§2 |
| `megaco_neg_carrier_invalid_port` | 配置/载体错 | 非法端口号（0/65536） | `port` | carrier | 设计§2 |
| `megaco_neg_carrier_return_address` | 配置/载体错 | 会话四元组与请求源地址不符（响应回程校验失败，§9） | `carrier` | address | RFC 3525 §9 |
| `megaco_neg_carrier_udp_mtu_exceeded` | 长度错 | UDP 载体消息长 > MTU−头开销（validator 拒绝或要求改 TCP，不静默截断，C-8） | `length` | mtu | RFC 3525 Annex D.1+设计§8 |
| `megaco_neg_services_address_mgcidtotry_conflict` | 描述符参数错 | Services 同时携带 ServiceChangeAddress 与 MgcIdToTry（ABNF at most one of either，C-17） | `services` | exclusive | RFC 3525 §7.1.13 |

**事件级错误 ≠ 负例**：Reply 内携带 errorDescriptor（动作级，如审计不存在终结点回 `Error = 430`，用例 3；事务级 `Reply=id{Error=411}`，用例 26）与设备回包语义错误（线格式合法、语义错，如 431/442，用例 36/37）是**合法协议行为**，属正例；只有配置错、线格式错、状态机错、关联错、长度错、描述符参数错才进入负例。错误保留最具体原因并从 planner 传到 task；不得自动补齐缺失 ID、不得把非法命令重排成合法顺序、不得跨事务代答。

**消息级错误覆盖声明**：真消息级 errorDescriptor（`messageBody = errorDescriptor`，整条消息无事务体）本版 77 例**不设正例**——其线格式（起始行+错误描述符、无事务块）与错误传播路径已被事件级 430 正例（用例 3，Error 描述符线格式）与 `megaco_neg_message_syntax`（负例 53 `syntax_body_form`，messageBody 形态校验）夹住，单独成例增量覆盖有限；§5.2 Error 行保留其定义，未来如需覆盖另立新 ID。用例 3 的 430 是**事务/动作级**错误描述符（Error 在 Reply 事务体内），不是消息级错误——两文档表述已统一。

## 8. 边界

- **长消息**：RFC 3525 文本编码无应用层分段（§1 口径修正）。TCP 载体下长消息（TPKT PDU）按 MSS 分段，字节流重组后按 TPKT 长度域切分、文本语法验证（用例 11）；TPKT 是成帧不是分段——分段发生在 TPKT PDU 之下（§2、§3.10）。UDP 载体下整条消息必须落在单个数据报内（用例 10），超 MTU 的长消息属于配置边界，validator 应拒绝或要求改用 TCP——不静默截断、不做 IP 分片依赖（负例 76）。
- **UDP 报文边界 vs TCP 流式**：UDP 一数据报一消息（无 TPKT）；TCP segment 边界与消息边界无关，消息定界依据 **TPKT 长度域**（Annex D.2 SHALL，RFC 1006 头 4B，§2），文本语法仅用于验证；`EOL` 允许 `CR`、`LF`、`CRLF` 三种形态与自由 LWSP，解析不得依赖固定行宽。
- **IPv4/IPv6**：双栈用独立 fixture，不同 layer-chain 顶层不得混址；UDP/IPv6 起点 62、TCP/IPv6 文本起点 78（TPKT 头在 74，§2 表）。mId 的 domainAddress 形式须与外层地址族一致。
- **多会话**：多会话 = 多个独立四元组（如 MG↔MGC1 与 MG↔MGC2），会话间状态不串用——事务 ID 空间、Context/终结点映射、Events RequestID 全部按会话隔离；多会话展开按序整块回放，第二会话包号起点 = 前会话总包数 + 1；`concurrent: true` 并发交错回放（v1.2 翻案纳入，正例 45——交错只作用于生成器级多连接，两会话事务配对/状态隔离断言不放宽）。
- **多事务**：同消息双事务（事务独立、id 互异、响应可聚合回单消息，§8.3）与会话内多消息事务依赖（Add→Modify→Subtract 状态链）分别有正例（3、4）。
- **空 context 与通配符语义**：`-`（NULL）用于 ROOT 类与空闲编程；`$`（CHOOSE）仅请求侧，响应必须回具体数值 ContextID；`*`（ALL）寻址全部上下文（不含 NULL），TerminationID 的 `*` 前缀匹配不寻址 ROOT；MGC 不得部分通配 ContextID。
- **数值边界**：transactionId/ContextID 为 UINT32 十进制文本（>4294967295 拒绝）；保留值 0x0/0xFFFFFFFE/0xFFFFFFFF 不得作为具体 Context 使用；TerminationID ≤64 字符；DigitMap 定时器 T/S/L 1-99（`T:0`=禁用启动定时器的合法语义，不属越界；越界=T>99 与 S/L 的 0，负例 70）；版本 1-2 位数字且从 1 起。**正向边界用例 carve-out**：边界用例 15/16/17 及 v1.2 相邻值例 28/39/40/41 允许在 fixture 显式固化边界值本身（TerminationID 恰 64 字符、transactionId 恰 4294967295、定时器恰 99、transid 0、ContextID 0xFFFFFFFD、Version 2 位形态、StreamID 65535）——被测规格点即边界值，不属"冒充动态值"（§6 `transactions[].id` 行同步）。
- **编码变体**：全 token 均有全称/缩写两形（§3.4/3.5 表）；大小写不敏感（SDP 除外）；LWSP/注释自由插入——正例覆盖缩写形态（用例 8）、空白/注释变体（23）与 mId 形态变体（24/25），解析不得因空白形态差异误判。

## 9. 原子 ID 与完成定义

**ID 权威 = testcase §2**（v1.2 D-1）：设计不再维护逐 ID 全量镜像表——v1.1 的"23 个唯一语义 ID"固化契约废除；设计、testcase 与未来 JSON 使用同一 77 个语义 ID 集合与顺序（46 正 + 31 负），权威序以 testcase §2 为准，设计按簇给出覆盖图景。当前 JSON 只放 `megaco_neg_unregistered` 前置占位，不计入 77 个语义 ID。约定包数：UDP 每消息一包；TCP = 3（握手）+ N（承载 TPKT PDU 字节的分段数，§3.10）+ 4（双向 FIN/ACK 挥手）。

**正例 46 条按簇**（编号 = testcase §2 行号）：

- **基线与载体族（1-17）**：注册/事务关联（1）、IPv6（2）、TCP 双事务+动作级错误（3）、v6 呼叫全流（4）、Notify 关联（5）、Audit/通配（6）、handoff 双会话（7）、缩写 token（8）、Move（9）、大 DigitMap（10）、TPKT 跨段重组（11）、多会话隔离（12）、PN/IA/K 三方握手（13）、2427 别名（14）、边界三例：TerminationID 恰 64 / transid 恰 UINT32 上界 / 定时器恰 99（15/16/17）。
- **描述符与协商族（18-25）**：TerminationState（18）、版本协商（19）、Method 值域 Graceful/Forced/Disconnected（20/21/22）、空白/注释变体（23）、mId `[IP]:port` 与 deviceName（24/25）。
- **事务与关联族（26-28）**：事务级 errorDescriptor（26）、K 区间（27）、`transid 0` 错误 Reply（28）。
- **值域族（29-38）**：RV/RG（29）、EventBuffer（30）、Mode SO/IN/LB（31/32/33）、auditItem 值域（34）、Signals OO/TO/BR+SignalList（35）、错误码 431/442（36/37）、Services Delay/TimeStamp（38）。
- **边界与形态族（39-46）**：ContextID 0xFFFFFFFD（39）、Version 2 位（40）、StreamID 65535（41）、Embed（42）、Events 无 RequestID（43）、注册改派（44）、并发会话（45）、DigitMap Z 修饰符（46）。

**负例 31 条**（47-77）：逐故障输入一行一例，与 §7 表一一对应——编码×2、线格式×7、状态机×5、关联×6、长度×6（含 UDP 超 MTU）、载体×4、描述符参数×1；`wire_fault` 31 值枚举见 §6。

**完成定义**：注册 `megaco` terminal layer（含 `h248`/`mgcp` 别名归一）；逐 token 生成 §3 文本线格式（长/缩写两形、LWSP/EOL 合规、SDP 转义；TCP 载体 TPKT 头与长度域定界）；事务关联（auto id 分配 + same_as 引用 + `peer_mid` 派生）与 §5.2 状态机（含初始状态规则与非法事件锚词）校验生效；UDP 单数据报边界与 TCP TPKT 定界（长度域切分）+ MSS 分段重组均可观测；IPv4/IPv6 × UDP/TCP 四组合落表；77 个语义 ID 正负断言与错误传播（锚词表 §7）完成；未注册阶段只接受 `unknown layer` 占位；实现后逐条对照 tshark `megaco.*` 实测字段校准并同步四件套（设计/testcase/JSON/audit）。

## 10. 修订记录

- v1.2.2（2026-09-23，复评收口）：§6 `version` 行改如实语义——显式 `0` = 采用缺省版本（V9 skip-0 + 渲染为 1，线上与缺席同值），负例 50 转书面豁免（D-MEGACO-1 F6 表）；负例 51（3 位数字）维持执法。实现侧 Min/Max [1,99] 只约束非零显式值（复评 U3：旧注释"[1,99] 覆盖显式 0"为伪声明）。
- v1.2.1（2026-09-23，实现轮补行）：§6 键表补 `whitespace` 行（实现面 `registry.go` 七键已含该键，用例 23 帧字节已钉——v1.2.0 键表漏行，D-MEGACO-1 修轮 F13 补记）+ `token_form` 行补 response_ack 缩写恒 `K` 澄清（修轮 F2 实证旧渲染歧义）。
- v1.2.0（2026-09-01，v1.3 重审修复轮）：rr-megaco 行为面 114 点全枚举重审（✓79/半8/✗27；5 MAJOR C + 2 MAJOR D + 约 20 MINOR + 4 N）后重出：语义 ID 23 → 77（46 正 + 31 负）。关键修复：**D-1**（CRITICAL）§9 固化契约废除——ID 权威改 testcase §2，设计 §9 改簇级覆盖图景；**C-2**（CRITICAL）负例逐故障输入原子拆分 6→31 行（一行一例单一注入），§7 表整表重排、§6 `wire_fault` 枚举扩 31 值（三方同序）；**C-1** 三基线声明入 §1（pcap/NIC 双输出、RST 不产生、并发会话翻案）+ §5.2/§6/§8 翻案落点与正例 45；**C-5** TerminationState 例（18）、**C-6** 版本协商例（19）、**C-7** Method 值域补 Graceful/Forced/Disconnected（20/21/22）、**C-8** UDP 超 MTU 负例（76）、**C-9** 空白/注释例（23）、**C-10** mId `[IP]:port`/deviceName 例（24/25）、**C-11** 事务级 errorDescriptor 例（26）、**C-12** K 区间例（27）、**C-13** `transid 0` 错误 Reply 例（28）、**C-14** RV/RG（29）+EventBuffer（30）、**C-15** Mode SO/IN/LB（31/32/33）+auditItem（34）+Signals OO/TO/BR（35）、**C-16** 错误码 431/442 例（36/37）、**C-17** Delay/TimeStamp 例（38）+Services 互斥负例（77）、**C-18** 边界相邻值例（39/40/41）、**C-19** Embed（42）+Events 无 RequestID（43）、**C-20** 注册改派例（44）；**D-3/N-1** `mtpAddress` 改 `MTP{...}` 花括号（§3.1）；**D-4/N-3** DigitMap `T:0` 合法语义口径（§3.5/§8）+越界负例限定 T>99 与 S/L 的 0（负例 70）+Z 修饰符例（46）；**D-5/N-2** 错误码出处改"部分正文引用、部分 H.248.8/IANA 注册"（§3.5/§3.6）；**D-6/N-4** 用例 3 首错停止断言改包级字节包含原语；**N-5** §3.9 字段清单补实测字段 `reservevalue/reservegroup/terminationstate`；§3.1 Version 口径改"主口径恒 1、2 位数字为语法边界 carve-out"；§6 typedef 补 `concurrent`/`event_buffer`/`embed`/`service_change_mgc_id`、负例编号全量重指（47-77）。既有决策未改：三名合一、TPKT 主路径、消息级 Error 不覆盖声明（77 例内仍不设正例）、边界固化 carve-out、流关联/多流不适用。
- v1.0.0（2026-08-31）：按 `protocol-doc-requirements.md` v1.0 强制契约重写，取代 2026-08-21 旧稿。两文档独立、统一术语（事件编排会话/多会话展开/事务/锚词）、业务场景分析、五层覆盖逐层落点、三名合一决策出处（00-unimplemented-list.md 备注 3 与实现决策 3，需求方 2026-08-18）。相对旧稿的规范修正：①二进制编码默认端口按 RFC 3525 §9.1 修正为 2945（旧稿默认 2944）；②明确 RFC 3525 文本编码无应用层消息分段，"长消息 Segmentation" 修正为 TCP MSS 分段重组 + UDP 单数据报口径；③起始行方括号归属 mId 地址形式，非消息体括号；④主线文本编码，BER 降为 profile 边界（不再设 BER 正例，编码不一致进负例）；⑤正例 ID 统一 `megaco_` 前缀（旧稿正例为 `h248_` 前缀）；⑥依据 tshark 实测补充 megaco dissector 字段清单与 2427 端口 mgcp 绑定事实（旧稿误写"没有专用 Megaco dissector"）。
- 三向交叉审计（2026-08-31，用例审设计/设计审用例/规范审两份）2 轮，修复项见两份文档修订记录；本轮主要修复：①用例 3 的 T2 从"Modify 不存在终结点"改为"AuditValue 不存在终结点"——避免与负例 17 的状态机错语义重叠，并顺势覆盖 Error 描述符正例；②用例 6 补 AuditCapability 命令与 Audit 描述符落点（此前八命令缺 AC）；③用例 9 并入 Move 命令（此前八命令缺 Move），packet_count 2→4；④用例 5 从 2 消息扩为 4 消息（补 Events 编程事务），使 ObservedEvents↔Events RequestID 关联可断言；⑤§3.5 补 `Events` 描述符 RequestID 可选、`ObservedEvents` RequestID 必选的区分；⑥负例 17 锚词从 `state` 调整主锚词为 `command` 并在 §7 表内对齐 testcase §5；⑦规范审回对 RFC 3525：补 §9.1 规则 6（SC 必为 MG 首命令）与错误 505 到负例 17 依据、补 `ImmAckRequired` 仅出现在回过 Pending 的最终 Reply 的前提表述、修正 `Reason` 为 quotedString 必选形式的表述。
- 独立隔离审查修复：v1.1.0（2026-09-01）按独立审查员 22 项问题清单（F1–F22：2 高危/2 中高危/18 中低）逐项关闭。关键项：**F1 采用 TPKT 成帧**（决策依据 RFC 3525 Annex D.2 为 SHALL；现网 H.248 over TCP 实态即 TPKT；tshark 规范解析路径也是 TPKT 分支——按规范采用，不做"声明偏离"）：§2 补 RFC 1006 TPKT 头规格（版本 0x03+保留 0x00+16bit 大端总长=4B 头+消息长度），TCP 文本起点改 58（v4）/78（v6），消息定界依据改 TPKT 长度域（文本语法仅验证），新增 §3.10 消息总长度公式；F2 补对端 mId 表达（`peer_mid` 键，显式优先于 `[dst_ip]` 自动派生）并入 Validate 与 §5.1；F3 用例 7 会话 1 与 §4 场景 5 补必选 `Reason="903 MGC Directed Change"`；F4 用例 4 回填改两条 Modify（单命令单 TerminationID）；F5 O-/W- 前缀并入用例 6（断言 `megaco.command_optional`/`megaco.wildcard_response`）；F6 覆盖映射两表以用例正文为真值重算（§4.1 与 testcase §6）；F7 用例 8 补 Modify{Events} 对（2→4 包）；F9 §2 偏移表补"无 TCP options"、§6 尾补管线分步；F10 §5.2 增非法事件锚词列、初始状态规则与确定性声明；F12 用例 3 T2 改两命令断言首错停止、负例 22 补 ContextID 保留值；F13 消息级 Error 显式声明不覆盖；F18 新增正向边界用例 15-17（TerminationID 恰 64 字符 / transactionId 恰 4294967295 / 定时器恰 99），语义 ID 总数 20→23（17 正+6 负），负例顺延为 18-23；F20 §3.2 增 K 覆盖集校验规则、用例 13 改单点 `K{9998}`；F21 两文档 §9/§2 表同构（含占位行）；F22 §6 增自动派生清单。其余 F8/F11/F14-F17/F19 在 testcase 文档对应小节关闭。本轮起负例编号为 18-23；2026-08-31 及此前修订记录中的"负例 15-20"系 v1.0.0 时代编号，按负例 ID 名称一一对应（如"负例 17"= `megaco_neg_command_state`，今 #20）。
- 复验修复 R1-R5（2026-09-01，独立审查复验轮）：①R1 用例 12 会话 2 补 Events 编程对（Notify 前置编程，RequestID 关联，§4 场景 3），packet_count 8→10，§4.1 Events 落点 +12；②R2 用例 13 帧字节断言裁为事务形态前缀（`T`/`PN`/`P`+数字/`K{`），不固化 transactionId 数值（§6/§8 动态值口径一致）；③R4 §5.2 Failover/Handoff 行两个锚词落负例——负例 19 补"Services 缺必选 Method/Reason"、负例 23 补"会话四元组与请求源地址不符"，另补负例 21"IA 无前置 PN"使 LongRunning 行锚词亦可触达（§5.2 第 4 列全部锚词均有负例对应）；④R5 用例 3 T2 第二命令改 `AuditValue = ROOT`（不依赖终结点存在性，避免与 §5.2"Modify 不存在终结点→拒绝"冲突），首错停止断言不变。R3/R2 testcase 侧改动见 testcase §8。

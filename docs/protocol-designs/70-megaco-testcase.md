# Megaco/H.248（媒体网关控制协议，文本编码）测试用例契约

> 版本：v1.1.0（设计阶段）
> 日期：2026-09-01
> 配套设计：`docs/protocol-designs/70-megaco-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/megaco.json`
> 状态：仅设计与 PCAP（抓包文件）/NIC（网卡）用例契约；`megaco`/`h248`/`mgcp` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。**独立隔离对抗审查已完成**（v1.1.0 定稿：独立审查 agent 三向审计 22 项清单（2 高危/2 中高危/18 中低）→ 修复 → 复验新发现 R1-R5 → 二轮修复 → 二轮复验 clean + S1 备忘闭合；审查/修复记录见 §8 修订记录）。
> 本版按 `protocol-doc-requirements.md` v1.0（2026-08-31）强制契约重写，取代 2026-08-21 旧稿；与旧稿/任务口径冲突处一律以规范为准（见 §8 修订记录）。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 23 个唯一语义 ID：17 个正例、6 个负例。当前 JSON 只保留一个 `megaco_neg_unregistered` 注册前置占位：`proto=megaco`、`expect_error=true`、`error_contains` 精确为 `unknown layer`；该占位不计入 23 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 Megaco 行为通过。注册后移除占位，再按本文 §2 顺序补入 17 个正例与 6 个负例。

**机器契约**：`trafficgen/test/protocol_pcap/cases/megaco.json`（第二阶段生成，本版不写文件）。`proto` 固定为 `megaco`，不得用 `h248`/`mgcp`；三入口别名由 planner 归一。

**未注册边界**：`megaco`、`h248`、`mgcp` 层均未注册。当前唯一合法 JSON 条目是 `megaco_neg_unregistered`；注册前的拒绝、0 包或空 PCAP 不是协议行为通过。TSHARK 实测（本机 3.6.14）：megaco 文本 dissector 绑定 2944 端口、字段族 `megaco.*` 齐全（设计 §3.9 清单）；2427 端口绑定的是 `mgcp` dissector——`megaco_udp_2427_mgcp_alias` 用例实现后证据在"decode_as 强制 megaco"与"offset 42 起始行/命令 token 字节断言"二选一，case JSON 实现时定并同步设计/testcase/audit。

**基线**：RFC 3525 / ITU-T H.248.1 (03/2002)，文本编码（Annex B.2 ABNF），主线 profile `megaco_v1_text`。动态值（transactionId、数值 ContextID、媒体 SDP 地址/端口、时间戳）不硬编码：用 `nonzero`、`same_as_packet`、`distinct_values`、包间关系与稳定 token 字节断言；TerminationID、DigitMap 内容、Reason 文本、mId 属预配置值，允许 fixture 显式给出。不做"媒体已建立""编解码协商成功"等超出控制面的断言；没有 RTP 层实现时，Local/Remote SDP 只作 `megaco.localdescriptor`/`megaco.remotedescriptor` 存在性与文本前缀断言。

**包数约定**（设计 §9）：UDP 每消息一包；TCP = 3（SYN/SYN-ACK/ACK）+ N（承载 TPKT PDU 字节的分段数）+ 4（双向 FIN/ACK）。约定数字是实现基线，若实现采用不同 ACK 合并或分段方式，须同步更新四件套，不得把约定数字当 RFC 消息数。

**TPKT 成帧**（设计 §2）：TCP 载体每条消息前置 RFC 1006 TPKT 头 4B（`版本=0x03`、`保留=0x00`、`总长度 2B 大端 = 4B 头 + Megaco 消息长度`），Megaco 文本起点 offset **58（IPv4）/78（IPv6）**；消息定界依据 TPKT 长度域，文本语法仅作内容验证。决策依据（v1.1.0）：RFC 3525 Annex D.2 为 SHALL，现网 H.248 over TCP 实态即 TPKT，tshark 规范解析路径也是 TPKT 分支——按规范采用，不做"声明偏离"。UDP 承载不变（一数据报一消息，无 TPKT，offset 42/62 不变）。

**多会话包号规则**（设计 §8）：多会话展开按序整块回放，第二会话起点 = 前会话总包数 + 1（如用例 12：第一会话 4 包，第二会话从包 5 起、共 6 包）。

## 2. 原子用例索引

| # | ID | 类型 | 载体 | 覆盖 | 设计依据（设计 §） | 约定 packet_count |
|---:|---|---|---|---|---|---:|
| 1 | `megaco_udp_ipv4_registration` | 正 | UDP/IPv4 | MG 注册 SC(Restart,ROOT)+Services、Reply 事务关联、单流基线 | §2、§3.2、§3.5、§3.6、§5.2、§9 | 2 |
| 2 | `megaco_udp_ipv6_failover` | 正 | UDP/IPv6 | SC(Failover)+Reason 909、IPv6 offset 62 | §3.6、§5.2、§8、§9 | 2 |
| 3 | `megaco_tcp_ipv4_dual_transaction` | 正 | TCP/IPv4 | 同消息双事务、T2 首错停止（430 后第二命令不执行）、事务/动作级错误描述符 | §2(TPKT)、§3.2、§3.4、§3.5、§5.1、§5.2、§7、§9 | 9 |
| 4 | `megaco_tcp_ipv6_call_flow` | 正 | TCP/IPv6 | 编程→建连(Add+Local SDP)→回填(两条 Modify Remote)→拆连(Subtract+Statistics)，多消息事务依赖 | §3.3、§3.5、§4、§5.2、§8、§9 | 15 |
| 5 | `megaco_udp_ipv4_notify_events` | 正 | UDP/IPv4 | Events(RequestID) 编程→Notify(ObservedEvents 同 RequestID)→Reply | §3.5、§4、§5.1、§9 | 4 |
| 6 | `megaco_udp_ipv4_audit_wildcard` | 正 | UDP/IPv4 | 同消息双事务 O-AV(ROOT)+W-AC(*)，O-/W- 前缀，ROOT 与通配区分 | §3.4、§3.5、§3.7、§9 | 2 |
| 7 | `megaco_udp_ipv4_handoff` | 正 | UDP/IPv4 | 两会话 handoff：SC HandOff+Reason 903+MgcIdToTry / SC HandOff+Reason 903，`peer_mid` 区分 MGC，多会话展开 | §3.6、§4、§5.2、§6、§8、§9 | 4 |
| 8 | `megaco_udp_ipv4_abbrev_tokens` | 正 | UDP/IPv4 | 缩写 token：`!/1`、`T`、`C`、`MF`、`E`、`P`；注册对+Modify{Events} 对；大小写不敏感 | §3.1、§3.4、§3.5、§9 | 4 |
| 9 | `megaco_udp_ipv4_move_media` | 正 | UDP/IPv4 | Move 命令 + 完整 Media 描述符（LocalControl+Local/Remote SDP、StreamID）、前置 Add 建连对 | §3.4、§3.5、§5.2、§9 | 4 |
| 10 | `megaco_udp_ipv4_large_digitmap` | 正 | UDP/IPv4 | 大 DigitMap 长消息单数据报承载、Events/Signals | §3.5、§8、§9 | 2 |
| 11 | `megaco_tcp_ipv4_mss_reassembly` | 正 | TCP/IPv4 | 长 TPKT PDU 跨 TCP 分段（小 MSS）、按 TPKT 长度域切分重组 | §2、§3.10、§8、§9 | 11 |
| 12 | `megaco_udp_ipv4_multi_session` | 正 | UDP/IPv4 | 多会话双四元组状态隔离（会话 2：Events 编程对+Notify 对），第二会话起点=前会话包数+1 | §4、§5.2、§8、§9 | 10 |
| 13 | `megaco_tcp_ipv4_pending_immack` | 正 | TCP/IPv4 | T→PN{}→Reply(IA)→K 单点（同请求 ID），At-Most-Once 三方握手，帧字节形态前缀 | §3.2、§5.1、§5.2、§9 | 11 |
| 14 | `megaco_udp_2427_mgcp_alias` | 正 | UDP/IPv4 | 入口名 `mgcp`+默认 2427+同一文本线格式注册对，三名合一 | §1、§2、§3.9、§9 | 2 |
| 15 | `megaco_udp_ipv4_termid_max_length` | 正 | UDP/IPv4 | TerminationID 恰 64 字符（pathNAME 上界） | §3.7、§8、§9 | 2 |
| 16 | `megaco_udp_ipv4_transid_max` | 正 | UDP/IPv4 | transactionId 恰 4294967295（UINT32 上界，边界固化 carve-out） | §3.2、§8、§9 | 2 |
| 17 | `megaco_udp_ipv4_digitmap_timer_max` | 正 | UDP/IPv4 | DigitMap 定时器恰 99（1-99 上界） | §3.5、§8、§9 | 2 |
| 18 | `megaco_neg_encoding_mismatch` | 负 | — | 编码声明与载荷不一致 | §7 | — |
| 19 | `megaco_neg_message_syntax` | 负 | — | 起始行/版本/mId/消息体语法错 | §7 | — |
| 20 | `megaco_neg_command_state` | 负 | — | 命令-状态机/CHOOSE 侧别/未创建引用 | §7 | — |
| 21 | `megaco_neg_transaction_pairing` | 负 | — | transactionId 配对/重复/K 覆盖集校验错 | §7 | — |
| 22 | `megaco_neg_length_truncation` | 负 | — | 截断/长度与数值上界（64 字符 TerminationID、UINT32 越界、ContextID 保留值、定时器越界） | §7 | — |
| 23 | `megaco_neg_carrier_port` | 负 | — | 载体/端口/入口名-编码组合非法 | §7 | — |
| 24 | `megaco_neg_unregistered` | 占位 | — | 层注册前置占位，不计语义覆盖 | §1 未注册边界 | — |

## 3. 线上编码与偏移断言

文本消息从应用起点开始。无 VLAN、无 IP options、无 TCP options 时：UDP/IPv4 offset 42（Eth 14 + IPv4 20 + UDP 8）、UDP/IPv6 offset 62；TCP 载荷起点 54（IPv4）/74（IPv6）前置 RFC 1006 TPKT 头 4B（`版本=0x03`、`保留=0x00`、`总长度 2B 大端 = 4 + 消息长度`），Megaco 文本起点 **58（IPv4）/78（IPv6）**（设计 §2）。UDP 一数据报一消息（无 TPKT）；TCP 先按字节流重组，再按 **TPKT 长度域**切分消息（Annex D.2 SHALL），文本语法（起始行到 messageBody 闭合）仅用于内容验证，segment 边界不等于消息边界。

起始行稳定前缀两形：`MEGACO/1 `（长形）与 `!/1 `（缩写形）；其后是 `mId`：`<domain>`（尖括号域名）、`[IPv4]`/`[IPv6]`（方括号地址）、`[IPv4]:端口`（带端口）、或 deviceName pathNAME。消息级示例（RFC 3525 Appendix I 风格）：

```text
MEGACO/1 [192.0.2.10] Transaction = 10003 {
    Context = $ {
        Add = A4444,
        Add = $ {
            Media { Stream = 1 {
                LocalControl { Mode = ReceiveOnly },
                Local { v=0 c=IN IP4 $ m=audio $ RTP/AVP 4 a=ptime:30 }
            } }
        }
    }
}
```

实现后证据以 tshark 实测字段为准（`tshark -G fields | grep megaco` 已核，见设计 §3.9）：`megaco.start_token`（起始行 token）、`megaco.version`、`megaco.mId`、`megaco.transaction`（方向）、`megaco.transid`、`megaco.context`/`megaco.ctx`、`megaco.ctx.term`、`megaco.command`、`megaco.termid`、`megaco.requestid`、`megaco.digitmap`、`megaco.mode`、`megaco.streamid`、`megaco.error_code`、`megaco.error_string`、`megaco.localdescriptor`/`megaco.remotedescriptor` 等。**字段断言使用实测格式**（如 `megaco.transid` 为 FT_UINT32 十进制、`megaco.version` 为 FT_STRING）；不得臆造未实测字段名/格式。端口 2944 自动按 megaco 解码；2427 按 §1 规则处理。

## 4. 正例逐项断言契约

1. **`megaco_udp_ipv4_registration`**（UDP/IPv4/2944，MG→MGC→MG 两消息，packet_count=2）：请求起始行 `MEGACO/1 `、mId 恒定；`megaco.transid` 存在（nonzero）、`megaco.command=ServiceChange`、`megaco.ctx.term=ROOT`、Services 含 `Method=Restart` 与 `Reason="901 Cold Boot"`、Profile/ServiceChangeAddress/Version 存在；Reply 事务 ID 与请求 `same_as_packet` 关联（`megaco.transid` request/reply 相等），Reply 含 `ServiceChange=ROOT` 且带 `Profile`/`Version`；`has_payload` 每包成立。
2. **`megaco_udp_ipv6_failover`**（UDP/IPv6/2944，packet_count=2）：`ip.version=6`（或 `ipv6.*` 断言）、offset 62 起文本；起始行 `MEGACO/1`；SC `Method=Failover`、`Reason="909 MGC Impending Failure"`；Reply 关联同用例 1 规则；`megaco.transid` 两包同值。
3. **`megaco_tcp_ipv4_dual_transaction`**（TCP/IPv4/2944，packet_count=9 = 3+N+4，N=2：1 请求消息（双事务）+ 1 响应消息；实现按实际分段数同步；帧字节 `[54..57] = 03 00 <len_hi> <len_lo>`——TPKT 头，总长域 = 4+消息长度；Megaco 文本自 offset 58 起）：先断言 TCP 握手（tcp.flags SYN/SYN-ACK/ACK 各一）；同一条 Megaco 消息内两个事务 `T1{...}`、`T2{...}`，`megaco.transid` `distinct_values` 恰两个；T1 为 `AuditValue` ROOT 成功；T2 为两条命令：首命令 `AuditValue = A9999 {Audit{Events}}` 引用不存在终结点，Reply 内携带 `Error = 430 {"Unknown TerminationID"}` 类 errorDescriptor（`megaco.error_code=430`）；第二命令 `AuditValue = ROOT {Audit {Packages}}` 因**首错停止**不执行（第二命令选 ROOT 审计——不依赖终结点存在性，避免与 §5.2"Modify 不存在终结点→拒绝"校验冲突）——断言 T2 的 actionReply 仅含 errorDescriptor、无第二条命令响应（以 T2 的 transactionId 前缀定位其回应区间，帧字节断言该区间无第二条 `AuditValue` 响应回文；`megaco.error_code=430` 在 Reply 消息中恰一次）。事件级错误返回是合法协议行为，不是负例；两条 Reply 聚合在单条消息中；`megaco.transid` request/reply 配对正确。本例为**事务/动作级错误描述符正例**（Error 430 在 Reply 事务体内；真消息级 Error 本版声明不覆盖，设计 §7）。握手包不承载 Megaco 字节。
4. **`megaco_tcp_ipv6_call_flow`**（TCP/IPv6/2944，packet_count=15 = 3 握手 + 8 段（4 请求消息 + 4 Reply 各一 TPKT PDU）+ 4 挥手；实现按实际分段同步；帧字节 `[74..77] = 03 00 <len_hi> <len_lo>`（TPKT 头），文本自 offset 78 起）：同一控制关联内 4 个顺序事务（多消息依赖）：①`Modify = A4444` 于 NULL context 编程（Events 含 RequestID、Signals）；②`Context = $ { Add = A4444, Add = $ {Media{Stream=1{LocalControl{Mode=ReceiveOnly}, Local{SDP(含 $)}}}} }` 建连，Reply 回具体数值 ContextID（`megaco.ctx` 数值、A4444 之外新增终结点）与填充后 Local（地址/端口/`RTP/AVP`）；③两条命令回填 `Modify = A4444 {Remote{SDP(对端媒体)}}, Modify = A4445 {Remote{SDP(对端媒体)}}`——单命令单 TerminationID，`A4444/A4445` 整串是一个 pathNAME（分层终结点命名），不能当两终结点通配（设计 §3.7）；④`Subtract = A4444, Subtract = A4445` 拆连，Subtract Reply 可携带 `megaco.statistics`。断言：`ipv6.nxt=6`（TCP）、offset 78、事务 ID 严格递增/不重复、每个 Reply transactionId 与请求 `same_as_packet`、`megaco.mode=ReceiveOnly`、`megaco.streamid=1`、`megaco.localdescriptor`/`megaco.remotedescriptor` 存在（`megaco.localdescriptor` 为 FT_NONE 时改以 SDP 文本与 offset 字节前缀断言）；CHOOSE `$` 只出现在请求侧。会话 `role=mgc`：初始即 `Registered` 等价态（设计 §5.2 初始状态规则），首事件 Modify 合法。
5. **`megaco_udp_ipv4_notify_events`**（UDP/IPv4，packet_count=4，四个消息 4 包）：①MGC `Modify = A4444 {Events = 2222 {al/of}}`；②Reply；③MG `Notify = A4444 {ObservedEvents = 2222 {al/of(...)}}`，ObservedEvents 的 RequestID 与①的 Events RequestID **same_as_packet 同值**（`megaco.requestid` 两包相等）；④Reply。断言 `megaco.command` 序列 Modify/Notify、`megaco.events`/`megaco.observedevents` 存在、事件项 `al/of` 与时间戳字段存在。
6. **`megaco_udp_ipv4_audit_wildcard`**（UDP/IPv4，packet_count=2，双事务聚合单消息）：同一消息内 `T1{Context=- {O-AuditValue = ROOT {Audit {Packages}}}}`、`T2{Context=* {W-AuditCapability = * {Audit {Events}}}}`；断言 `megaco.transid` 恰两个 distinct、命令 AV 与 AC 并存（八命令含 AC）、`megaco.ctx.term=ROOT` 与通配 `*` 均可解析、`O-` 前缀使 `megaco.command_optional` 存在、`W-` 前缀使 `megaco.wildcard_response` 存在（通配汇总响应；两字段出现侧别实现后按实测校准）、Reply 对 ROOT 与 `*` 分别返回（ROOT 与 ALL 不混同——设计 §8）。
7. **`megaco_udp_ipv4_handoff`**（UDP/IPv4，packet_count=4，两事件编排会话，多会话展开）：会话 1（MG↔MGC1）2 包：MGC1 `ServiceChange = ROOT {Services{Method=HandOff, Reason="903 MGC Directed Change", MgcIdToTry=<mgc-2.example.net>}}`（s2c；Services 的 Method 与 Reason 均 REQUIRED，设计 §3.6/§7.1.13）+ Reply；会话 2（MG↔MGC2）2 包、起点 = 2+1 = 包 3：MG `ServiceChange = ROOT {Services{Method=HandOff, Reason="903 MGC Directed Change"}}`（c2s）+ Reply。断言：两会话各自独立事务 ID 空间、mId 按方向分别恒定（本例两会话 role=mg——c2s 全部消息 mId = 会话 `mid`（MG 的 mId 两会话相同——同一网关）、s2c 全部消息 mId = 会话 `peer_mid`（会话 1 与会话 2 显式给不同值，即 MGC1/MGC2 的 mId 不同；role=mgc 会话的方向映射相反，设计 §5.1/§6）、未写时按设计 §6 自动派生 `[dst_ip]`，显式值优先）、`megaco.mId` 与四元组对应、Reason 903 两会话均存在。
8. **`megaco_udp_ipv4_abbrev_tokens`**（UDP/IPv4，packet_count=4，两对消息）：注册对改用全缩写与混合大小写：起始行 `!/1 [192.0.2.10]`、`T<transid>{C=-{SC=ROOT{SV{MT=Restart,RE="901 Cold Boot"}}}}`、回复 `P<transid>{...}`；再加一对编程消息 `T<transid>{C=-{MF=A4444{E=2222{al/of}}}}` + `P<transid>{...}`（缩写 MF/E 落地，设计 §3.4/§3.5；transid 运行期动态分配，不写进断言，§7.7）；断言 `megaco.start_token=!/1`（或等价实测值）、命令 token 缩写解析为 ServiceChange/Modify（`megaco.command` 字段语义不变）、`megaco.events` 存在、大小写不敏感变体（如 `context`/`Context`）不被误判。
9. **`megaco_udp_ipv4_move_media`**（UDP/IPv4，packet_count=4，4 消息 4 包：Add 建连对 + Move 对）：消息 1-2 `Context = $ { Add = A4445 {Media{...}} }` + Reply，建立源 Context 并得到具体 ContextID；消息 3-4 `Context = $ { Move = A4445 {Media{Stream=1{LocalControl{Mode=SendReceive}, Local{SDP}, Remote{SDP}}}} }` 移至新上下文 + Reply；断言 `megaco.command=Move`、`megaco.mode=SendReceive`、`megaco.streamid=1`、Local/Remote SDP 文本存在、Reply 回具体 ContextID（$ 仅请求侧）；Move 命令与 Add/Modify 同参数结构（设计 §3.4）。
10. **`megaco_udp_ipv4_large_digitmap`**（UDP/IPv4，packet_count=2）：单数据报承载含长 DigitMap 的 `Modify`（`DigitMap = Dialplan0 {(0 | 00 | [1-7]xxx | 8xxxxxxx | Fxxxxxxx | Exx | 91xxxxxxxxxx | 9011x.)}` 类，>1KB 文本）与 Events/Signals 引用；Reply 回。断言：`udp.length` 覆盖整条消息、`megaco.digitmap` 存在（FT_STRING 全值或前缀字节断言）、无截断；UDP 一数据报一消息边界成立。
11. **`megaco_tcp_ipv4_mss_reassembly`**（TCP/IPv4/2944，packet_count=11 = 3 握手 + 4 段（请求跨 2 段 + 响应跨 2 段，共 4 段承载 TPKT PDU 字节）+ 4 挥手；实现按实际分段同步）：设置小 MSS 使同一条长消息（如含大 Media/SDP 的 Add，整条 TPKT PDU）跨多个 TCP segment；断言先按 `tcp.stream` 重组字节流，再**按 TPKT 长度域切分出完整消息**（每条 TPKT PDU 自带 4B 头与总长，可跨段；帧字节 `[54..57] = 03 00 <len_hi> <len_lo>`，TPKT 头只出现在首段），最后按文本语法验证内容完整（起始行+messageBody 闭合）——定界依据是 TPKT 长度域，文本语法仅验证（设计 §2/§8）；`megaco.transid` 唯一、`megaco.command=Add`、Local SDP 文本完整；不得按 segment 边界拆消息。
12. **`megaco_udp_ipv4_multi_session`**（UDP/IPv4，packet_count=10，两个事件编排会话）：会话 1（四元组 A，src_port 40001）4 包：注册对 + 编程 Modify 对；会话 2（四元组 B，src_port 40002）6 包、起点 = 4+1 = 包 5：另一组注册对 + Events 编程对 + Notify 对——Notify 的 ObservedEvents 必须有前置 Events 编程（RequestID 关联，RFC 3525 §7.2.7、设计 §4 场景 3；无前置编程会触发负例 21 的 RequestID 校验，故 Notify 前必须显式编排 Events 对）。断言：两会话四元组 distinct（src/dst 端口）、`megaco.transid` 各自独立（允许数值重叠但按会话/四元组隔离）、终结点/Events RequestID 映射不串用（会话 1 的 `A4444` 与会话 2 的 `B5555` 互不引用）、包号符合多会话展开规则。
13. **`megaco_tcp_ipv4_pending_immack`**（TCP/IPv4，packet_count=11 = 3 握手 + 4 应用消息分段（T、PN、Reply(IA)、K 各一 TPKT PDU，帧字节 `[54..57] = 03 00 <len_hi> <len_lo>`、文本自 offset 58 起）+ 4 挥手；实现按实际分段同步）：长事务演示：`T{...}` 请求 → 对端 `PN{<同请求ID>}` → 最终 `Reply` 带 `ImmAckRequired` 前缀（`P<同请求ID>{IA,...}`）→ 请求方 `K{<同请求ID>}`（单点；区间形式 `K{a-b}` 合法但本例不用——dissector 对区间 transid 只取首个数，设计 §3.2/§3.9）。断言：PN/Reply/Ack 的 `megaco.transid` 与请求 `same_as_packet`（transactionId 运行期动态分配，不把数值写进断言，§7.7）；`K` 覆盖集 ⊆ 本会话已确认事务集合（单点即该已确认事务，设计 §3.2 校验规则）；**帧字节形态前缀区分四形态**（offset 58 起）：请求段以 `T` 开头、Pending 段以 `PN` 开头、Reply 段以 `P`+数字开头、Ack 段以 `K{` 开头——只断言事务形态 token 字节，不固化 transactionId 数值。dissector 已知行为注记：`PN` 消息的 `megaco.transaction` 字段也置 `Reply`（值域 {Request, Reply, TransactionResponseAck, Error}），四形态区分以帧字节形态前缀为准、不依赖 `megaco.transaction` 取值（设计 §3.9）。At-Most-Once 语义（Annex D.1.2.2/D.1.4）由 `events[]` 事件序列显式编排、不自动派生。
14. **`megaco_udp_2427_mgcp_alias`**（UDP/IPv4，入口名 `mgcp`，packet_count=2）：默认 `dst_port=2427`；与用例 1 同结构的注册对（同一文本线格式、同一 `MEGACO/1` 起始行）；证据按 §1 二选一（decode_as `udp.port==2427,megaco` 后的 `megaco.*` 字段，或 offset 42 起始行 + `ServiceChange`/`ROOT`/`Services` token 字节断言）。断言端口=2427、别名归一后语义与 H.248 相同——**不产生 MGCP 本体线格式**（CRCX/MDCX 等超出合并范围，设计 §1）。
15. **`megaco_udp_ipv4_termid_max_length`**（UDP/IPv4，packet_count=2）：`Modify = <64 字符 pathNAME> {Events = 2222 {al/of}}`（终结点串 = `A` + 63 位数字，恰好 64 字符——§3.7 pathNAME 上界）+ Reply；断言 `megaco.termid` 存在且帧字节中该终结点串恰 64 字符（≤64 合法、>64 归负例 22）、`megaco.command=Modify`、Reply 与请求 `same_as_packet` 关联。
16. **`megaco_udp_ipv4_transid_max`**（UDP/IPv4，packet_count=2）：请求与 Reply 的 transactionId 恰为 `4294967295`（UINT32 上界——边界用例显式固化边界值，设计 §6/§8 carve-out，不属"冒充动态值"）；断言 `megaco.transid=4294967295` 两包同值（`same_as_packet`）、起始行与命令 token 正常解析；>4294967295 归负例 22。
17. **`megaco_udp_ipv4_digitmap_timer_max`**（UDP/IPv4，packet_count=2）：`Modify = A4444 {DigitMap = Dm99 {T:99, (0|00|1xxx)}}`（定时器 T 恰 99——§3.5 定时器 1-99 上界）+ Reply；断言帧字节含 `T:99` 文本（DigitMap 值内）、`megaco.digitmap` 存在、`megaco.command=Modify`；定时器 >99 归负例 22。

**正例总则**：每条实现后至少含 `packet_count`/`min_packets`、载体与方向断言、`has_payload`、可观察 fields、稳定 frames（起始行与关键 token 字节前缀）；动态值只用关联断言。合法 505/406 等"事件级错误返回"是正例行为——本版覆盖于用例 3 的事务/动作级 Error 描述符；真消息级 errorDescriptor（messageBody=errorDescriptor）本版不设正例，设计 §7 有显式声明；只有配置、线格式、状态机、关联、长度错误进入负例（设计 §7）。

## 5. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩传输层外壳的假成功。执行期 `expect` 严格只有 `{"expect_error","error_contains"}` 两个键，不添加 `packet_count`、`notes`、`min_packets`、`fields` 或 `frames`。锚词与设计 §7 表一一对应：

| ID | 类别 | 故障输入 | `error_contains`（主锚词，可并列备选） |
|---|---|---|---|
| `megaco_neg_encoding_mismatch` | 配置/编码错 | `encoding=ber` 而载荷为文本字节（或反之）；BER 声明配 2944 文本端口 | `encoding`（备 `ber`/`text`） |
| `megaco_neg_message_syntax` | 线格式错 | 起始行损坏（MegacopToken 缺失/拼错）、版本 `0` 或 3 位数字、mId 缺失或非法形式、消息体既非事务表也非错误描述符、Services 缺必选 Method/Reason（描述符必选参数缺失） | `message`（备 `version`/`mid`/`syntax`） |
| `megaco_neg_command_state` | 状态机错 | 注册前发非 SC 命令（错误 505 语义）；未 Add 先 Modify/Subtract 不存在终结点；reply 动作使用 `$`/`*` context；引用未创建 Context；同事务首命令失败后第二命令（无 O- 前缀）响应仍出现在 Reply（首错后仍执行） | `command`（备 `state`/`context`/`termination`） |
| `megaco_neg_transaction_pairing` | 关联错 | Reply/Pending transactionId 与请求不等；同会话重复 transactionId；`K` 确认从未确认过的事务（覆盖集 ⊄ 已确认事务集合，设计 §3.2 校验规则）；`ImmAckRequired` 出现在未回过 Pending 的事务（IA 前提校验，设计 §5.2）；ObservedEvents RequestID 与 Events 不匹配 | `transaction`（备 `reply`/`correlation`/`ack`） |
| `megaco_neg_length_truncation` | 长度错 | 消息截断（messageBody 未闭合/尾部缺失）、TerminationID 超 64 字符、transactionId 超 UINT32（>4294967295）、digitMap 定时器越界、ContextID 取保留值 0/0xFFFFFFFE/0xFFFFFFFF 作具体 Context | `length`（备 `truncat`/`limit`） |
| `megaco_neg_carrier_port` | 配置/载体错 | 层链 udp/tcp 与配置不符；入口名-端口-编码组合非法（text 配 2945、mgcp 别名配 TCP 2427 之外的载体声明）；非法端口号；会话四元组与请求源地址不符（响应回程地址校验失败） | `carrier`（备 `port`/`profile`） |
| `megaco_neg_unregistered` | 注册前置 | `proto=megaco` 且 layers 含未注册 `megaco` | **`unknown layer`** |

负例不能用"0 包"、空 PCAP 或任务成功替代错误传播；动态 ID 缺失/错配不能由 planner 自动补齐。

## 6. 五层覆盖映射

| 层面 | 用例落点 | 说明 |
|---|---|---|
| 功能 | 正 1-17；负 18-23 | 八命令：SC(1,2,7,8,12,14)、Modify(4,5,8,10,12,15)、Add(4,9)、Subtract(4)、Move(9)、Notify(5,12)、AV(3,6)+AC(6)、O-/W- 前缀(6)；事务四形态：Request/Reply 全体、Pending+ResponseAck(13)；描述符：Media/Local/Remote(4,9,11)、Events(4,5,8,10,12)、Signals(4,10)、DigitMap(10,17)、ObservedEvents(5)、Services(1,2,7)、Statistics(4)、Packages/Audit(6)、Error(3)；状态流转：注册→编程→建连→拆连(4)、handoff(7)、长事务三方握手(13)；负例六类各 ≥1 |
| 性能 | 10、11、13 | 长消息（TPKT PDU）跨 TCP 分段、按 TPKT 长度域切分重组（MSS，11）；大 DigitMap 单数据报（10）；长事务 Pending/IA/K 往返（13）；消息长度上界受 MTU/MSS 约束（设计 §3.10/§8） |
| 数据场景 | 1/2/3/4/6/7/8/9、15-17 | Reason/Profile/Version 引号串与数值域（1/2/7）；错误码 430 事件级返回（3）；O-/W- 前缀（6）与通配 `-/$/*`（4,6,9）；缩写 token 与大小写变体（8）；正向边界值：TerminationID 恰 64 字符（15）、transactionId 恰 4294967295（16）、DigitMap 定时器恰 99（17） |
| 地址与流 | 1、2、3、4、14；流关联显式不适用 | v4 全量 + v6(2,4)；UDP(1,2,5-10,12,14-17)与 TCP(3,4,11,13)；单流基线(1)；**流关联不适用**：Megaco 为控制面，不派生 RTP 媒体数据面，媒体仅作 SDP/描述符存在性断言（设计 §4.1） |
| 业务 | 1、2、4、5、6、7、9、12、13、14 | 注册(1,14)、呼叫建立命令序列(4,9)、Notify 上报(5)、Audit 巡检(6)、handoff/failover(2,7)、多会话(12)、多事务（同消息双事务 3/6、会话内多消息依赖 4、长事务三方握手 13） |

## 7. 机器契约与三方一致性

1. 运行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/megaco.json`，确认当前 JSON 恰有一个 `megaco_neg_unregistered`：`proto=megaco`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
2. 设计 §9、本文 §2、注册后的 `megaco.json`、audit 保持同一 23 个语义 ID、同一顺序、17 正例 + 6 负例；当前 JSON 另有不计语义覆盖的注册前置占位。
3. 17 个正例实现后均有 `packet_count`/`min_packets`、载体、方向、编码、动态关联（nonzero/same_as_packet/distinct/包间关系）与可观察字段；6 个负例 `expect` 键集合恰为 `{expect_error,error_contains}`，packet_count 为 `—`。
4. 线上断言以 tshark 实测为准：`tshark -G fields | grep -E 'megaco\.'`（设计 §3.9 已核）；2944 自动解码；2427 按 §1 规则（decode_as 或字节断言）。不得伪造未实测 `megaco.*` 字段名/格式。
5. 文本按 ABNF 语法边界校验：起始行、事务/动作/命令/描述符层级、LWSP/EOL/注释与大小写规则；SDP 内容大小写敏感且 `}` 转义（设计 §3）。
6. UDP 保留数据报边界（一数据报一消息，无 TPKT）；TCP 先按字节流重组、再按 TPKT 长度域切分消息（文本语法验证，Annex D.2 SHALL）；MSS 分段不改变 TPKT PDU 边界。
7. 动态 transactionId/ContextID/媒体值只用 presence/nonzero/same_as_packet/distinct/类型长度，不枚举固定运行期 ID。
8. 负例覆盖配置错/线格式错/状态机错/关联错/长度错/载体端口错六类并传播为 task error；`unknown layer` 占位不得冒充协议语义负例已执行。

## 8. 修订记录

- v1.0.0（2026-08-31）：按 `protocol-doc-requirements.md` v1.0 强制契约重写，取代 2026-08-21 旧稿。两文档独立、统一术语（事件编排会话/多会话展开/事务/锚词）、14 正例 + 6 负例 + 1 占位、四层偏移（42/62/54/74）、UDP 每消息一包与 TCP 3+N+4 包数约定、多会话第二会话起点 = 前会话包数 + 1。正例 ID 统一 `megaco_` 前缀（旧稿为 `h248_` 前缀）；BER 从正例移除、降为负例锚点（`megaco_neg_encoding_mismatch`）；补充 tshark 实测证据与 2427 端口 mgcp dissector 绑定事实。
- 三向交叉审计（2026-08-31）2 轮，修复项与设计 §10 同步：①用例 3 T2 改为 AuditValue 不存在终结点（避免与负例 17 语义重叠、覆盖 Error 描述符正例）；②用例 6 并入 AuditCapability 与 Audit 描述符；③用例 9 并入 Move 命令（packet_count 2→4）；④用例 5 扩为 4 消息（补 Events 编程事务）使 RequestID 关联可断言；⑤用例 11 包数调整为 3+N+4 表达式（11 = 3+4+4）；⑥负例锚词表与设计 §7 完全对齐（负例 17 主锚词 `command`）；⑦规范回对：补 505/406 语义到负例 17、补 `ImmAckRequired` 前提（仅回过 Pending 的最终 Reply）、修正 Reason 为 quotedString 必选。
- 独立隔离审查修复：v1.1.0（2026-09-01）按独立审查员 22 项问题清单（F1–F22）逐项关闭（与设计 §10 v1.1.0 同轮）：①TCP 载体采用 TPKT 成帧（决策依据 RFC 3525 Annex D.2 SHALL + RFC 1006 头 4B；现网实态与 tshark 规范路径均为 TPKT）：文本起点 58/78、帧字节 `[54..57]/[74..77]=03 00 <len>` 断言、消息定界改 TPKT 长度域，用例 3/4/11/13 偏移与断言 +4 重算（F1）；②用例 7 会话 1 Services 补必选 Reason="903 MGC Directed Change"（F3）；③用例 4 回填改两条 Modify 单 TerminationID（F4）；④O-/W- 并入用例 6，断言 `megaco.command_optional`/`megaco.wildcard_response`（F5）；⑤用例 8 补 Modify{Events} 对，packet_count 2→4（F7）；⑥§2 索引表增"设计依据"列（F8）；⑦新增正向边界用例 15-17（TerminationID 恰 64 字符 / transactionId 恰 4294967295 / 定时器恰 99，F18），语义 ID 20→23（17 正+6 负），负例顺延为 18-23；⑧用例 3 T2 改两命令断言"首错停止"、措辞改"事务/动作级错误描述符"，消息级 Error 声明不覆盖（设计 §7，F12/F13）；⑨负例 22 补 ContextID 保留值故障输入（F12）；⑩用例 13 改单点 `K{9998}`、帧字节前缀断言、dissector 已知行为注记（Pending 也置 "Reply"、区间 transid 只取首数，F14/F20），"被显式事件驱动"改"由 events[] 事件序列显式编排、不自动派生"（F15）；⑪删除用例 6 不可判定断言（"与后续任意状态兼容"，F19）；⑫§2 占位行与设计 §9 表同构（F21）；⑬§6 覆盖映射两表以用例正文为真值重算（F6）。
- 复验修复 R1-R5（2026-09-01，独立审查复验轮）：①R1 用例 12 会话 2 补 Events 编程对（Notify 前置编程，RequestID 关联，RFC 3525 §7.2.7），packet_count 8→10，Events 落点 +12（§6）；②R2 用例 13 帧字节断言裁为形态前缀（`T`/`PN`/`P`+数字/`K{`）、叙事改 `<同请求ID>` 占位，不再固化 transactionId 数值（§7.7）；③R3 §6 数据场景落点补 7；④R4 负例 19 补"Services 缺必选 Method/Reason"、负例 21 补"IA 无前置 PN"、负例 23 补"会话四元组与请求源地址不符"——§5.2 第 4 列锚词全部可由负例触达（设计 §7 同步）；⑤R5 用例 3 T2 第二命令改 `AuditValue = ROOT`（不依赖终结点存在性，不与"Modify 不存在终结点"校验冲突），首错停止断言改"T2 回应区间无第二条命令响应 + `megaco.error_code=430` 恰一次"。

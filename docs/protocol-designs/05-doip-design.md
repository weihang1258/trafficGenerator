# DOIP 协议设计与测试用例（v2.0.1）

> 协议：DOIP（Diagnostic over IP，基于 IP 的车辆诊断）
> 规范来源：ISO 13400-2:2019（Diagnostic communication over IP，基于 IP 的诊断通信）；
> UDS（Unified Diagnostic Services，统一诊断服务）底层参照 ISO 14229-1；
> 参考实现：scapy `contrib/automotive/doip.py`（字段宽度与枚举一致性已逐项核对）；
> 审计依据：`docs/protocol-designs/audit/05-doip-audit-deep.md`（v1.2 深度对抗审计报告，26 项问题）；
> `docs/protocol-designs/audit/05-doip-audit-r1-v2.md`（v2.0.0 R1 复审报告，17 项问题）
> 本文档目的：在 `internal/protocol/doip/` 实现未启动前，完整定义报文格式、Config 结构、状态机、Plan 输出、业务场景与测试用例清单，作为后续实现与代码评审的依据。
> 编写日期：2026-08-05（v2.0.1 返工日期：2026-08-05）
> 版本：v2.0.1（基于 R1 复审报告 17 项问题返工：删除 0x8002/0x8003 凭空添加的 PreviousDiagnosticMessageLength 字段、清理 HexDump 遗留注释、统一 UserData 边界值、用例表补 spec 引用等，详见 §11.1）
> 状态：待实现（属于扩展表 5 车联网协议之一，详见 `docs/protocol-designs/00-unimplemented-list.md`）

---

## 修订记录（v2.0.1 相对 v2.0.0）

| 编号 | 严重度 | 问题简述 | 修复点 |
|---|---|---|---|
| C1 | CRITICAL | 0x8002/0x8003 凭空插入 PreviousDiagnosticMessageLength 字段（ISO/scapy/Wireshark/python-doipclient 四方确认该位置无长度字段，PrevDiag 为变长尾部） | §2.14/§2.15 删除该字段，PayloadLength=5+M；§1.3/§1.5/§3.1/§4.4/§6.3/§6.4/§6.13.5-8/§7.4/§8.3/§8.5/§9.5/§9.7 约 15 处同步修正 |
| C2 | CRITICAL | §6.3 S3 HexDump "修正"注释遗留（同一 HexDump 出现修正前后两版）；S4 0x8001 PayloadLength=0x08 实际应为 0x07 | §6.3 清理注释仅留最终版；§6.4 S4 0x8001 改为 0x07；§6.10 0x36 同步清理 |
| C3 | CRITICAL | §6.13.7/§6.13.8 与 T066/T067/T068 边界自相矛盾（UserData 上限 65533 vs 65534，且建立在已删除的 PrevLen u16 之上） | 边界逻辑重写为 MaxDataSize 约束 + PayloadLength u32 理论上限；T064-T068 重写 |
| H1 | HIGH | S10 0x34 HexDump 缺 size 字段 4B（UserData 7B 但注释称 11B） | §6.10 0x34 HexDump 补全 size 字段，PayloadLength=0x0F=15 |
| H2 | HIGH | S3 0x8002 HexDump 与 C1 矛盾 | 随 C1 一并重写 |
| H3 | HIGH | §6.13.23 OEM 上限与 PrevLen 约束未区分 | §8.5 新增 OEM-specific 上限说明；§6.13.23 注明不受 PrevLen 约束 |
| H4 | HIGH | T067 与 §6.13.7 冲突 | 随 C3 一并重写 |
| M1 | MEDIUM | §4.3 二次确认流程缺 ResponseCode=0x05 拒绝收尾 | §4.3 子阶段新增步骤 4'；新增 T027a |
| M2 | MEDIUM | §6.13.5/§6.13.6 PrevLen u16 上限假设错误 | 随 C1 删除，重写为 MaxDataSize 边界 |
| M3 | MEDIUM | §9.7 R5 措辞与 §2.15 重复 | R5 改为 NackCode 合法值表述 |
| M4 | MEDIUM | §7 用例表无 spec 行引用 | 全部用例表新增"对应 spec 行"列 |
| M5 | MEDIUM | Direction 校验缺 0x0007/0x0008 正向用例 | T111/T112 补正向断言，新增 T119a/T120a |
| M6 | MEDIUM | V1+PowerMode 拒绝缺 spec 依据 | §1.3/§8.1/T110 注明"设计决策，非 ISO 要求" |
| L1 | LOW | 文档总行数声明错误（约 1050 vs 实际 1500） | 更正为"约 1500 行" |
| L2 | LOW | 缩写表缺 Tester/TCP/UDP/ISO/RFC 条目 | §10.2 补全 |
| L3 | LOW | §1.6 与 §3.1 Direction 注释重复 | §3.1 各 Direction 注释改为"见 §1.6" |
| L4 | LOW | 附录 B 0x34 参数位置不完整 | 补 addr/size 长度取值表 |

---

## 修订记录（v2.0.0 相对 v1.2）

| 编号 | 严重度 | 问题简述 | 修复点 |
|---|---|---|---|
| C1 | CRITICAL | 0x0006 Routing Activation ResponseCode 枚举整体偏移（v1.2 0x00=Success ↔ ISO/scapy 0x10=Success） | §2.9 重写：Success=0x10, Confirmation Required=0x11, 0x00..0x07=拒绝码 |
| C2 | CRITICAL | 0x8003 NackCode 0x00/0x01 语义倒置（v1.2 0x00=Invalid SA ↔ ISO/scapy Reserved） | §2.14 重写：0x00/0x01=Reserved, 0x02=Invalid SA, 0x03=Unknown TA, ..., 0x08=Transport error |
| C3 | CRITICAL | 缺失 0x4001/0x4002 DoIP Entity Status PayloadType | §2.2/§2.11a/§3.1/§3.2/§4/§6.18/§7 新增 EntityStatus 全流程 |
| C4 | CRITICAL | 0x0004 FurtherActionRequired 凭空添加 0x11/0x20/0x40 | §2.7 重写：仅 0x00=No further action / 0x10=Centralized security, 其余 Reserved by ISO |
| C5 | CRITICAL | 0x0004 VIN/GID SyncStatus 0x01=Not synced 与 ISO 矛盾 | §2.7 重写：0x00=Synchronized / 0x10=NOT synchronized, 0x01=Reserved |
| C6 | CRITICAL | T44 缺失 IPv6 全流程集成测试 | §7 新增 T46/T47/T48 IPv6 PowerMode + Discovery + TCP 全流程 + 多 ECU IPv6 |
| H1 | HIGH | 0x0005/0x0006 OEM-specific 写死 4B | §2.8/§2.9 改为变长 N B（默认 0B），PayloadLength=7+N / 9+N |
| H2 | HIGH | 0x8002 PrevDiagMsgLen u16 上限与 0x36 服务 UserData 上限混淆 | §2.13 注明 V2=u16/V1=u32；§6.16.11 拆分为 (a) PrevLen u16 上限 65535B / (b) 0x36 Data 上限 65531B |
| H3 | HIGH | UDS 0x27 偶数应答 Key 字段语义模糊 | §3.1 Key 字段注释明确：仅 IsResponse=false + sub 偶数 时使用；Validate 拒绝 Key 非空 + IsResponse=true |
| H4 | HIGH | DiagnosticPowerMode 0x02 误标 Reserved | §2.11 改为 0x02=Not Supported，Validate 接受 {0x00,0x01,0x02} |
| H5 | HIGH | TCP MSS=0 边界未覆盖 | §6.16.16 新增；T49 MSS=0 → Validate 报错或 fallback 1460 |
| H6 | HIGH | UDS NRC 0x00/0xFF 边界未覆盖 | Validate 仅接受 0x01..0x7F；T24a/T24b/T24c |
| H7 | HIGH | 0x0006 ResponseCode=0x11 Confirmation Required 未建模 | §2.9 新增 0x11；§4.3 新增二次确认子阶段；T50 |
| M1-M9 | MEDIUM | NRC SID 源/BlockSeq 公式/Announcement 间隔/ActivationType 术语/EID fallback/GenericNack 方向/HasSubFunction Validate/Direction 空值/0x8001 SA/TA 一致性 | §3.1/§3.2/§4/§6/§7/§9 全面修订，新增 T51-T60 |
| L1-L5 | LOW | 端口 3496/R7 引用/附录 B/IPv6 MAC RFC/Direction 缩写中文 | §1.2/§9/§B/§3.3/§1.6 修订 |

---

## §1. 协议概述

### §1.1 协议定位

DOIP（Diagnostic over IP，基于 IP 网络的车辆诊断协议）是车联网域内 ECU（Electronic Control Unit，电子控制单元）对外暴露的统一诊断入口。它在传统 UDS（Unified Diagnostic Services，统一诊断服务）之上封装了一层基于 TCP/UDP 的 IP 传输，使诊断工具（Tester，诊断仪）能够通过车载以太网或诊断服务器远程读写 ECU 内部的 DTC（Diagnostic Trouble Code，故障码）、刷写固件、执行例程、读取 VIN（Vehicle Identification Number，车辆识别码）等。

DOIP 与同领域的 GBT32960/JT808/JT809/JTT905 的差异在于：
- DOIP 是 **ECU 直连诊断**，链路两端是 Tester 与 ECU；GBT32960/JT808 是 **车端到平台** 的上报协议。
- DOIP 在 **同一 TCP 连接** 上承载多轮 UDS 交互；JT808 是单连接多业务报文。
- DOIP 的 UDP 仅用于 **车辆发现**（Vehicle Identification）与 **能力探测**（Entity Status / Power Mode），不承载诊断数据；GBT32960 不使用 UDP。

### §1.2 端口与传输层

| 传输层 | 端口 | 用途 | 方向 | 备注 |
|---|---|---|---|---|
| TCP | 13400 | 路由激活 + 诊断消息 + 存活检查 + 通用 NACK | Tester↔ECU | ISO 13400-2:2019 §7 |
| UDP | 13400 | 车辆发现（广播/单播）+ 车辆公告 + Entity Status + Power Mode | Tester↔ECU | ISO 13400-2:2019 §7 |
| TCP | 3496 | TLS 安全通道（DoIP over TLS） | Tester↔ECU | ISO 13400-2:2019 §7 留作后续扩展，本设计不实现 |

UDP 13400 既支持广播（IPv4 默认 255.255.255.255 + MAC ff:ff:ff:ff:ff:ff；IPv6 组播 ff02::1 + MAC 33:33:00:00:00:01，依 RFC 2464 §7 取组播地址末 32 位），也支持单播；TCP 13400 是单条连接（每个 ECU 一条独立 4-tuple）。本设计 **不复用** TCP 与 UDP 4-tuple：UDP 子流 SrcPort = spec.SrcPort（用户可配），DstPort = 13400；TCP 连接 SrcPort 为 ephemeral（随机分配），DstPort = 13400，两流 4-tuple 独立（协议号 6 vs 17 不同，SrcPort 亦不同）。若 Discovery 与 PowerMode 共用同一 UDP 4-tuple，FlowID 后缀 `:udp:disc` / `:udp:power` 区分（见 §5.1）。

### §1.3 协议版本

ISO 13400-2:2019 定义 `ProtocolVersion = 0x02`（DoIP 之 ISO 13400-2 第二版，常称 DoIP V2，对应 scapy `ISO13400_2012`）。本设计 **默认 V2（0x02）**，并允许显式声明 V1（0x01，对应 scapy `ISO13400_2010`）以兼容旧 ECU：

- V1 与 V2 在路由激活请求/响应长度（V1 固定 7B/9B vs V2 7+N/9+N）、电源模式支持（V1 无 0x4003/0x4004）等方面不兼容，混用会生成 Wireshark 标记为 malformed 的报文。
- `InverseProtocolVersion`（反向版本号）为版本号按位取反（V2 → `0xFD`），用于接收方校验头部完整性。
- scapy 还定义了 0x03=`ISO13400_2019` 与 0x04=`ISO13400_2019_AMD1`，本设计当前不接受这两个版本（与 V2 报文格式相同但语义扩展，留作后续扩展）。

> **说明（v2.0.1）**：0x8002/0x8003 的 PreviousDiagnosticMessage（之前诊断消息）为变长尾部，长度由 PayloadLength 隐式推导，**无独立长度字段，V1/V2 在该字段上无差异**（v2.0.0 凭空添加的 PreviousDiagnosticMessageLength 字段已删除，见 C1 修复）。

Validate 规则：
- `ProtocolVersion` 仅接受 `0x02`（默认）或 `0x01`（仅当调用方明确声明 V1 模式且 Config 不含 V2-only 字段时）；
- `0x00`/`0x03`/`0x04`-`0xFE` 拒绝；
- 当 `ProtocolVersion=0x01` 时，Planner 按 V1 格式生成：0x0005 = 7B（无 OEM-specific），0x0006 = 9B（无 OEM-specific），不支持 0x4003/0x4004（Validate 拒绝 PowerMode + V1 组合——**本设计选择，非 ISO 要求**，scapy 与 python-doipclient 均无 V1+PowerMode 拒绝逻辑，仅因本设计 V1 定位为最小兼容子集）。
- 本设计实现优先级为 V2，V1 兼容作为后续扩展。

### §1.4 与扩展表 5 的映射

扩展表 5 节点名 `DoipProtocolLog`，要求记录：
- 协议版本号、PayloadType、PayloadLength
- 业务场景：车辆发现、路由激活、诊断消息、存活检查、电源模式、Entity Status、通用 NACK
- 多 ECU 场景：多 VIN/LogicalAddress

本设计把以上每一类业务场景映射到独立 Config 字段或 `doip_messages[]` 表项，并通过 Plan 输出完整字节序列，便于流量回放侧（pcap-replay）按字段比对。

扩展表 5 字段到本设计字段的显式映射：

| 扩展表 5 字段 | 本设计对应 | 说明 |
|---|---|---|
| doipMessageType | PayloadType（由 Planner 输出，见 §2.2 表 16 项） | 日志元数据，按 Config 子结构隐式确定 |
| doipPayloadLen | PayloadLength（由 Planner 自动计算，见 §2.1） | 不含头部 8B |
| furtherActionRequired | DoIPDiscovery.FurtherActionRequired（见 §3.1） | 仅 0x0004 携带 |
| diagnosticDataLen | Message.UserData 长度（自动计算 = 0x8001 PayloadLength - 4） | 仅 0x8001 携带 |
| diagnosticData | Message.UserData / Message.UDS（见 §3.1） | UDS 报文字节序列 |
| responseCode | Activation.ResponseCode（0x0006）+ NackCode（0x8003）+ NackCode（0x0000） | 三类响应码分属不同 PayloadType |
| ActivationType | Activation.ActivationType | 仅 0x0005 携带 |
| activationResCode | Activation.ResponseCode（与 responseCode 同字段，仅 0x0006 携带） | 别名 |
| nodeType | EntityStatus.NodeType | 仅 0x4002 携带（v2.0.0 新增） |
| maxOpenSockets | EntityStatus.MaxOpenSockets | 仅 0x4002 携带（v2.0.0 新增） |
| curOpenSockets | EntityStatus.CurOpenSockets | 仅 0x4002 携带（v2.0.0 新增） |
| maxDataSize | EntityStatus.MaxDataSize | 仅 0x4002 携带（v2.0.0 新增） |

### §1.5 不在本文档范围

- TLS/DTLS 层封装（ISO 13400-2:2019 §7 安全通道，端口 3496，目前车载以太网少见，留作后续扩展）。
- DoIP 与 SOME/IP 的混流（SOME/IP 已在扩展表外）。
- IPv6 双栈细节：UDP 广播在 IPv6 用组播 `ff02::1`，本设计允许 SrcIP/DstIP 配 IPv6，但默认场景给出 IPv4。
- 大文件刷写（多 GB 固件）：本文档覆盖单次 TransferData（UserData ≤ MaxDataSize，受 EntityStatus.MaxDataSize 与 PayloadLength u32 上限约束，见 §6.13.5-8）的请求-应答序列，不实现分片重组。

### §1.6 方向约定

本设计 Config 中 `Direction` 字段统一使用以下约定：
- `"up"`（上行，Tester→ECU）：诊断仪主动发起的报文（0x0001/0x0002/0x0003/0x0005/0x0008/0x4001/0x4003/0x8001 请求方向/0x8002 双向/0x8003 双向）
- `"down"`（下行，ECU→Tester）：ECU 主动或应答的报文（0x0000/0x0004/0x0006/0x0007/0x4002/0x4004/0x8001 应答方向）
- `""`（空）：走默认方向（按 PayloadType 决定，见 §3.2）
- 大小写不敏感：`"UP"`/`"Up"` 等价 `"up"`；`"DOWN"`/`"Down"` 等价 `"down"`

---

## §2. 数据类型与编码

### §2.1 DoIP 头部（8 字节，所有 PayloadType 共用）

| 偏移 | 长度 | 字段 | 类型 | 取值 | 说明 |
|---|---|---|---|---|---|
| 0 | 1 | ProtocolVersion | u8 | 0x02（默认）/ 0x01 | 协议版本号 |
| 1 | 1 | InverseProtocolVersion | u8 | ~ProtocolVersion & 0xFF | 反向版本号，校验用 |
| 2 | 2 | PayloadType | u16 BE | 见 §2.2 | 载荷类型（大端） |
| 4 | 4 | PayloadLength | u32 BE | 0..0xFFFFFFFF | 载荷字节数（大端，不含头部 8B） |
| 8 | N | Payload | bytes | 见 §2.3..§2.16 | 业务载荷，长度由 PayloadLength 决定 |

约束：
- `InverseProtocolVersion` 必须严格等于 `~ProtocolVersion & 0xFF`，否则接收方回复 `0x0000 Generic NACK` 并关闭连接。
- `PayloadLength` 不包含头部 8 字节，仅指 Payload 字段字节数。
- 单条 DoIP 报文最大长度（含头）为 4 GB-1，实际受 TCP MSS 与接收缓冲限制；本设计对单帧 PayloadLength > 65535B 的场景不实现（PayloadLength u32 上限 4GB-1 为理论边界，见 §6.13.7/§6.13.8），超大 UDS 数据需拆分为多条 0x8001（§6.10）。

### §2.2 PayloadType 表（16 项，含 v2.0.0 新增 0x4001/0x4002）

| PayloadType | 名称 | 方向 | 传输层 | 用途 |
|---|---|---|---|---|
| 0x0000 | Generic DoIP Header NACK（通用头 NACK） | ECU→Tester | TCP/UDP | 头部错误反馈 |
| 0x0001 | Vehicle Identification Request（车辆识别请求） | Tester→ECU | UDP | 全网广播发现车辆 |
| 0x0002 | Vehicle Identification Request with EID（带 EID 的车辆识别请求） | Tester→ECU | UDP | 按 EID 单播发现 |
| 0x0003 | Vehicle Identification Request with VIN（带 VIN 的车辆识别请求） | Tester→ECU | UDP | 按 VIN 单播发现 |
| 0x0004 | Vehicle Announcement/Identification Response（车辆公告/识别应答） | ECU→Tester | UDP | 车辆自公告或应答识别请求 |
| 0x0005 | Routing Activation Request（路由激活请求） | Tester→ECU | TCP | 建立 TCP 路由 |
| 0x0006 | Routing Activation Response（路由激活应答） | ECU→Tester | TCP | 应答路由激活 |
| 0x0007 | Alive Check Request（存活检查请求） | ECU→Tester | TCP | 主动探活 |
| 0x0008 | Alive Check Response（存活检查应答） | Tester→ECU | TCP | 应答探活 |
| 0x4001 | DoIP Entity Status Request（实体状态请求） | Tester→ECU | UDP | 查询 ECU 节点类型/最大并发 socket/最大单包数据（v2.0.0 新增） |
| 0x4002 | DoIP Entity Status Response（实体状态应答） | ECU→Tester | UDP | 应答实体状态（v2.0.0 新增） |
| 0x4003 | Diagnostic Power Mode Request（电源模式请求） | Tester→ECU | UDP | 查询车辆电源状态 |
| 0x4004 | Diagnostic Power Mode Response（电源模式应答） | ECU→Tester | UDP | 应答电源状态 |
| 0x8001 | Diagnostic Message（诊断消息） | 双向 | TCP | 承载 UDS 报文 |
| 0x8002 | Diagnostic Message Ack（诊断消息正向确认） | 双向 | TCP | UDS 接收确认 |
| 0x8003 | Diagnostic Message Nack（诊断消息负向确认） | 双向 | TCP | UDS 接收拒绝 |

### §2.3 0x0000 Generic DoIP Header NACK

| 偏移 | 长度 | 字段 | 类型 | 取值 | 说明 |
|---|---|---|---|---|---|
| 8 | 1 | NackCode | u8 | 见下表 | 通用头 NACK 码 |

NackCode（0x0000）取值表（ISO 13400-2:2019 §8.4.1）：

| 值 | 含义 |
|---|---|
| 0x00 | Incorrect Pattern Format（协议版本与反向版本不匹配） |
| 0x01 | Unknown Payload Type（未知载荷类型） |
| 0x02 | Message Too Large（报文过大） |
| 0x03 | Out of Memory（内存不足） |
| 0x04 | Invalid Payload Length（载荷长度非法） |
| 0x05..0xFF | Reserved by ISO 13400 |

PayloadLength = 1（仅 NackCode 1B）。

### §2.4 0x0001 Vehicle Identification Request

无 Payload。PayloadLength = 0。Tester→ECU，UDP 广播（IPv4 255.255.255.255 / IPv6 ff02::1）。

### §2.5 0x0002 Vehicle Identification Request with EID

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 8 | 6 | EID | bytes[6] | ECU 的 EID（Entity Identifier，实体标识，6 字节，通常等于 ECU MAC） |

PayloadLength = 6。Tester→ECU，UDP 单播（按 EID 定向）。

### §2.6 0x0003 Vehicle Identification Request with VIN

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 8 | 17 | VIN | bytes[17] | VIN（ASCII，车辆识别码，17 字节） |

PayloadLength = 17。Tester→ECU，UDP 单播（按 VIN 定向）。

### §2.7 0x0004 Vehicle Announcement/Identification Response

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 8 | 17 | VIN | bytes[17] | VIN（ASCII） |
| 25 | 2 | LogicalAddress | u16 BE | ECU 逻辑地址 |
| 27 | 6 | EID | bytes[6] | ECU 实体标识 |
| 33 | 6 | GID | bytes[6] | GID（Group Identifier，组标识） |
| 39 | 1 | FurtherActionRequired | u8 | 见下表 |
| 40 | 1 | VIN/GID SyncStatus | u8 | 见下表（V2 必带，V1 可选） |

PayloadLength = 33（V2）/ 32（V1，不含 SyncStatus）。

FurtherActionRequired 取值表（ISO 13400-2:2019 §8.5.3，scapy 行 144-155）：

| 值 | 含义 |
|---|---|
| 0x00 | No further action required（无需后续动作） |
| 0x01..0x0F | Reserved by ISO 13400 |
| 0x10 | Routing activation required to initiate central security（需路由激活以启动中心安全） |
| 0x11..0xFF | Reserved by ISO 13400 |

> **重要修复（C4）**：v1.2 凭空添加的 0x11=Centralized ECU identification / 0x20=WW ECU identification / 0x40=VIN/GID sync / 0xE0..0xFF=OEM 均无 ISO/scapy 依据，已全部删除。仅 0x00 与 0x10 合法，其余全部 Reserved by ISO 13400。

VIN/GID SyncStatus 取值表（ISO 13400-2:2019 §8.5.5，scapy 行 158-169）：

| 值 | 含义 |
|---|---|
| 0x00 | Synchronized（VIN 和/或 GID 已同步） |
| 0x01..0x0F | Reserved by ISO 13400 |
| 0x10 | Incomplete: VIN and GID are NOT synchronized（VIN 和 GID 未同步） |
| 0x11..0xFF | Reserved by ISO 13400 |

> **重要修复（C5）**：v1.2 错将 0x01 定义为 Not synchronized，与 ISO/scapy 矛盾。实际 0x01=Reserved，0x10=Not synchronized。

车辆公告（Vehicle Announcement）：ECU 启动或收到 0x0001/0x0002/0x0003 后，按 ISO 13400-2:2019 §8.5.1 在 500ms±100ms 间隔内连续发送 3 次 0x0004。本设计 Planner 生成 3 条 0x0004 PacketConfig，PacketIndex 连续递增，**不注入时间延迟**——500ms±100ms 间隔是 ECU 行为，时间精度由 worker 层 Pacer 控制（见 §4.1 与 §9）。

### §2.8 0x0005 Routing Activation Request

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 8 | 2 | SourceAddress | u16 BE | Tester 逻辑地址（SA） |
| 10 | 1 | ActivationType | u8 | 见下表 |
| 11 | 4 | Reserved ISO | u32 BE | ISO 保留，必须为 0 |
| 15 | N | OEM-specific | bytes[N] | OEM 保留，变长（默认 0B） |

PayloadLength = 7 + N（N = len(OEM-specific)，V2 默认 N=0，V1 强制 N=0）。

> **重要修复（H1）**：v1.2 写死 OEM=4B，与 ISO 13400-2:2019 §9.2.4 与 scapy `reserved_oem` 变长字段矛盾。本设计改为变长 N B（0B/4B/任意 B 均合法），V1 强制 N=0。

ActivationType 取值表（ISO 13400-2:2019 §9.2.4.2，scapy 行 175-183）：

| 值 | 含义 |
|---|---|
| 0x00 | Default（默认激活） |
| 0x01 | WWH-OBD（World Wide Harmonized On-Board Diagnostics，全球协调车载诊断激活） |
| 0x02..0xDF | Reserved by ISO 13400 |
| 0xE0..0xFF | OEM-specific（OEM 自定义） |

> **重要修复（M5）**：v1.2 误用术语 "WWH-DOIP"，正确术语为 "WWH-OBD"（On-Board Diagnostics，车载诊断），不是 DoIP-specific。

### §2.9 0x0006 Routing Activation Response

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 8 | 2 | ClientLogicalAddress | u16 BE | Tester 逻辑地址（CLA，与 0x0005 SA 一致） |
| 10 | 2 | ServerLogicalAddress | u16 BE | ECU 逻辑地址（SLA，与 0x0004 LogicalAddress 一致） |
| 12 | 1 | ResponseCode | u8 | 见下表 |
| 13 | 4 | Reserved ISO | u32 BE | ISO 保留，必须为 0 |
| 17 | N | OEM-specific | bytes[N] | OEM 保留，变长（默认 0B） |

PayloadLength = 9 + N（N = len(OEM-specific)，V2 默认 N=0，V1 强制 N=0）。

> **重要修复（H1）**：同 §2.8，OEM-specific 改为变长 N B。

ResponseCode（0x0006）取值表（ISO 13400-2:2019 §9.3.6，scapy 行 180-196）：

| 值 | 含义 |
|---|---|
| 0x00 | Denied — Unknown Source Address（拒绝-未知源地址） |
| 0x01 | Denied — All concurrently supported TCP_DATA sockets are registered and active（拒绝-所有 TCP socket 已占用） |
| 0x02 | Denied — Different SA received on already activated TCP_DATA socket（拒绝-已激活 socket 收到不同 SA） |
| 0x03 | Denied — Source Address already registered and active on a different TCP_DATA socket（拒绝-SA 已在别的 socket 注册） |
| 0x04 | Denied — Missing Authentication（拒绝-缺少认证） |
| 0x05 | Denied — Rejected Confirmation（拒绝-确认被拒） |
| 0x06 | Denied — Unsupported Routing Activation Type（拒绝-不支持激活类型） |
| 0x07 | Denied — Activation Type requires secure TLS TCP_DATA socket（拒绝-需 TLS） |
| 0x08..0x0F | Reserved by ISO 13400 |
| 0x10 | Success（路由激活成功） |
| 0x11 | Routing will be activated; Confirmation Required（路由将被激活，需确认） |
| 0x12..0xFF | Reserved by ISO 13400 |

> **重要修复（C1）**：v1.2 错将 0x00 定义为 Success，与 ISO/scapy 矛盾（实际 0x00=Unknown SA 拒绝）。Success = **0x10**。所有 v1.2 ResponseCode 测试断言已整体偏移 +0x10。
> **重要修复（H7）**：新增 0x11=Confirmation Required，Tester 收到后需再发 0x0005 二次确认（见 §4.3 子阶段）。

### §2.10 0x0007 Alive Check Request

无 Payload。PayloadLength = 0。ECU→Tester，TCP。

### §2.11 0x0008 Alive Check Response

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 8 | 2 | SourceAddress | u16 BE | Tester 逻辑地址（与 0x0005 SA 一致） |

PayloadLength = 2。Tester→ECU，TCP。

### §2.11a 0x4001/0x4002 DoIP Entity Status（v2.0.0 新增）

0x4001 DoIP Entity Status Request：无 Payload。PayloadLength = 0。Tester→ECU，UDP。

0x4002 DoIP Entity Status Response（ISO 13400-2:2019 §11.1，scapy 行 204-212）：

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 8 | 1 | NodeType | u8 | 见下表 |
| 9 | 1 | MaxOpenSockets | u8 | 最大并发 TCP_DATA socket 数 |
| 10 | 1 | CurOpenSockets | u8 | 当前已打开 TCP_DATA socket 数 |
| 11 | 4 | MaxDataSize | u32 BE | 单条 DoIP 报文最大 Payload 字节数 |

PayloadLength = 7。ECU→Tester，UDP。

NodeType 取值表（ISO 13400-2:2019 §11.1，scapy 行 204-206）：

| 值 | 含义 |
|---|---|
| 0x00 | DoIP Gateway（DoIP 网关） |
| 0x01 | DoIP Node（DoIP 节点，即 ECU） |
| 0x02..0xFF | Reserved by ISO 13400 |

### §2.12 0x4003/0x4004 Diagnostic Power Mode

0x4003 Diagnostic Power Mode Request：无 Payload。PayloadLength = 0。Tester→ECU，UDP。

0x4004 Diagnostic Power Mode Response：

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 8 | 1 | DiagnosticPowerMode | u8 | 见下表 |

PayloadLength = 1。ECU→Tester，UDP。

DiagnosticPowerMode 取值表（ISO 13400-2:2019 §11.2.2，scapy 行 201-203）：

| 值 | 含义 |
|---|---|
| 0x00 | Not Ready（电源未就绪） |
| 0x01 | Ready（电源就绪） |
| 0x02 | Not Supported（电源模式查询不被支持） |
| 0x03..0xFF | Reserved by ISO 13400 |

> **重要修复（H4）**：v1.2 误将 0x02 标为 Reserved，实际 0x02=Not Supported 是合法状态。Validate 接受 {0x00, 0x01, 0x02}，拒绝 0x03..0xFF。

### §2.13 0x8001 Diagnostic Message

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 8 | 2 | SourceAddress | u16 BE | 发送方逻辑地址（SA） |
| 10 | 2 | TargetAddress | u16 BE | 接收方逻辑地址（TA） |
| 12 | N | UserData | bytes[N] | UDS 报文字节序列 |

PayloadLength = 4 + N（N = len(UserData)）。

约束：
- 0x8001 请求方向的 SA 必须与 0x0005 SourceAddress 一致；TA 必须与 0x0006 ServerLogicalAddress 一致（ISO 13400-2:2019 §10.3.2.1/§10.3.2.2）。Planner 在 mapToFlowSpec 时校验，不一致则 Validate 报错（M9 修复）。
- 0x8001 应答方向（ECU→Tester）SA/TA 互换：SA = 0x0006 SLA，TA = 0x0005 SA。
- UserData 起始字节为 UDS ServiceID（1B），后续为 UDS 服务参数（详见 §3.1 DoIPUDS）。

### §2.14 0x8002 Diagnostic Message Ack

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 8 | 2 | SourceAddress | u16 BE | 接收方逻辑地址（与被确认 0x8001 的 TA 一致） |
| 10 | 2 | TargetAddress | u16 BE | 发送方逻辑地址（与被确认 0x8001 的 SA 一致） |
| 12 | 1 | AckCode | u8 | 0x00 = ACK（仅此值合法） |
| 13 | M | PreviousDiagnosticMessage | bytes[M] | 被确认的 0x8001 UserData 完整副本（变长尾部） |

PayloadLength = 5 + M（M = len(PreviousDiagnosticMessage)，V1/V2 一致）。

> **重要修复（C1，v2.0.1）**：v2.0.0 在 AckCode 与 PreviousDiagnosticMessage 之间凭空添加了 `PreviousDiagnosticMessageLength` 字段（V2=u16/V1=u32），与 ISO 13400-2:2019 §10.4.3 及 scapy（`previous_msg = XStrField`，无 Len 字段）、Wireshark（`tvb_captured_length_remaining` 动态取剩余字节）、python-doipclient（`struct.unpack_from("!HHB", ...)` + `payload_bytes[5:payload_length]`）三方实现矛盾。**该位置无任何长度字段**，PreviousDiagnosticMessage 是变长尾部，长度由 PayloadLength - 5 隐式推导，V1/V2 格式相同。

AckCode 取值（ISO 13400-2:2019 §10.4.3.4）：仅 0x00 = ACK 合法，0x01..0xFF Reserved。Validate 拒绝非 0x00。

PreviousDiagnosticMessage = 被确认的 0x8001 UserData 完整字节副本（不分段前的原始字节，ISO 13400-2:2019 §10.4.3）。

### §2.15 0x8003 Diagnostic Message Nack

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 8 | 2 | SourceAddress | u16 BE | 接收方逻辑地址 |
| 10 | 2 | TargetAddress | u16 BE | 发送方逻辑地址 |
| 12 | 1 | NackCode | u8 | 见下表 |
| 13 | M | PreviousDiagnosticMessage | bytes[M] | 被拒绝的 0x8001 UserData 完整副本（变长尾部） |

PayloadLength = 5 + M（M = len(PreviousDiagnosticMessage)，V1/V2 一致）。

> **重要修复（C1，v2.0.1）**：同 §2.14，删除 v2.0.0 凭空添加的 `PreviousDiagnosticMessageLength` 字段。ISO 13400-2:2019 §10.4.5 定义的 Payload 结构为 `SourceAddress(2) + TargetAddress(2) + NackCode(1) + PreviousDiagnosticMessage(变长)` = 5 + M B，PreviousDiagnosticMessage 长度由 PayloadLength - 5 隐式推导，与 scapy/Wireshark/python-doipclient 一致。

NackCode（0x8003）取值表（ISO 13400-2:2019 §10.4.5，scapy 行 217-223）：

| 值 | 含义 |
|---|---|
| 0x00 | Reserved by ISO 13400 |
| 0x01 | Reserved by ISO 13400 |
| 0x02 | Invalid Source Address（源地址非法） |
| 0x03 | Unknown Target Address（目标地址未知） |
| 0x04 | Diagnostic Message Too Large（诊断消息过大） |
| 0x05 | Out of Memory（内存不足） |
| 0x06 | Target Unreachable（目标不可达） |
| 0x07 | Unknown Network（未知网络） |
| 0x08 | Transport Protocol Error（传输协议错误） |
| 0x09..0xFF | Reserved by ISO 13400 |

> **重要修复（C2）**：v1.2 错将 0x00=Invalid SA / 0x01=Target Unreachable，与 ISO/scapy 矛盾。实际 0x00/0x01=Reserved，0x02=Invalid SA，0x06=Target Unreachable。所有 v1.2 NackCode 测试断言已重写。
> NackCode 字段类型为 `*uint8`（指针），nil = 不发 0x8003（发 0x8002 Ack），非 nil = 发 0x8003 Nack。Validate 拒绝 NackCode ∈ {0x00, 0x01, 0x09..0xFF}。

### §2.16 UDS（Unified Diagnostic Services）服务子集

本设计支持 ISO 14229-1 中的以下 UDS 服务（ServiceID = SID）：

| SID | 服务名 | 方向 | HasSubFunction | 说明 |
|---|---|---|---|---|
| 0x10 | DiagnosticSessionControl（诊断会话控制） | Tester→ECU | 是 | 切换会话模式（0x01 默认/0x02 编程/0x03 扩展） |
| 0x11 | ECUReset（ECU 复位） | Tester→ECU | 是 | 0x01 硬复位/0x02 关键复位/0x03 软复位 |
| 0x22 | ReadDataByIdentifier（按标识读数据） | Tester→ECU | 否 | 读取 DID（Data Identifier，数据标识） |
| 0x27 | SecurityAccess（安全访问） | Tester→ECU | 是 | 0x01..0x7F 奇数请求 seed / 偶数发送 key |
| 0x2E | WriteDataByIdentifier（按标识写数据） | Tester→ECU | 否 | 写 DID |
| 0x31 | RoutineControl（例程控制） | Tester→ECU | 是 | 启动/停止例程 |
| 0x34 | RequestDownload（请求下载） | Tester→ECU | 否 | 请求下载（数据格式 + 地址 + 长度） |
| 0x36 | TransferData（传输数据） | Tester→ECU | 否 | 携带 BlockSequenceCounter + 数据块 |
| 0x37 | RequestTransferExit（退出传输） | Tester→ECU | 否 | 结束传输 |
| 0x3E | TesterPresent（诊断仪在线） | Tester→ECU | 是 | 维持会话 |

UDS 正向响应 SID = Request SID | 0x40（ISO 14229-1 §7.1）：0x10→0x50, 0x11→0x51, 0x22→0x62, 0x27→0x67, 0x2E→0x6E, 0x31→0x71, 0x34→0x74, 0x36→0x76, 0x37→0x77, 0x3E→0x7E。

UDS 否定响应格式（ISO 14229-1 §7.3）：`0x7F <Request SID> <NRC>`（3B）。NRC（Negative Response Code，否定响应码）取 ISO 14229-1 Table B.1 范围 0x01..0x7F，0x00 = positiveResponse 不应出现在否定响应中，0x80..0xFF 保留。

---

## §3. 消息结构（Go struct 定义）

### §3.1 Config 子结构体

```go
// DoIPSpec 是 DoIP 协议的顶层 Config（位于 core.FlowSpec.DoIP）。
type DoIPSpec struct {
    ProtocolVersion uint8            // 0x02 (V2, default) / 0x01 (V1)
    SrcIP           string           // Tester IP (IPv4 或 IPv6)
    DstIP           string           // ECU IP (或 "255.255.255.255" / "ff02::1" 广播)
    SrcPort         uint16           // UDP SrcPort（TCP SrcPort 为 ephemeral）
    VIN             string           // 17B ASCII，用于 0x0003/0x0004
    LogicalAddress  uint16           // ECU 逻辑地址（SLA，用于 0x0004/0x0006/0x8001 TA）
    TesterAddress   uint16           // Tester 逻辑地址（SA，用于 0x0005/0x0008/0x8001 SA）
    EID             string           // 6B hex，ECU 实体标识（空 → spec.DstMAC 解码）
    GID             string           // 6B hex，组标识（默认 6B 0）
    Discovery       *DoIPDiscovery   // 车辆发现（UDP，0x0001-0x0004）
    EntityStatus    *DoIPEntityStatus // 实体状态（UDP，0x4001/0x4002，v2.0.0 新增）
    PowerMode       *DoIPPowerMode   // 电源模式（UDP，0x4003/0x4004）
    Activation      *DoIPActivation  // 路由激活（TCP，0x0005/0x0006）
    Messages        []DoIPMessage    // 诊断消息序列（TCP，0x8001/0x8002/0x8003）
    AliveCheck      *DoIPAliveCheck  // 存活检查（TCP，0x0007/0x0008）
    GenericNack     *DoIPGenericNack // 通用头 NACK（TCP/UDP，0x0000，仅模拟头部错误场景）
}

// DoIPDiscovery 描述车辆发现阶段（UDP）。
type DoIPDiscovery struct {
    Direction            string // 见 §1.6（"up" 发 0x0001/0x0002/0x0003 / "down" 发 0x0004 公告）
    RequestType          uint8  // 0x0001=广播 / 0x0002=按 EID / 0x0003=按 VIN
    Broadcast            bool   // true → DstIP=255.255.255.255 (IPv4) / ff02::1 (IPv6)
    AnnouncementCount    uint8  // 0x0004 公告次数（默认 3，ISO 13400-2:2019 §8.5.1）
    FurtherActionRequired uint8 // 仅 0x0004 携带；合法值 {0x00, 0x10}
    SyncStatus           uint8  // 仅 0x0004 携带；合法值 {0x00, 0x10}（v2.0.0 修复：0x10=Not synced）
}

// DoIPEntityStatus 描述 DoIP Entity Status 阶段（UDP，v2.0.0 新增）。
type DoIPEntityStatus struct {
    Direction       string // 见 §1.6（"up" 发 0x4001 / "down" 发 0x4002）
    NodeType        uint8  // 仅 0x4002；0x00=Gateway / 0x01=Node
    MaxOpenSockets  uint8  // 仅 0x4002；最大并发 TCP_DATA socket 数
    CurOpenSockets  uint8  // 仅 0x4002；当前已打开 socket 数
    MaxDataSize     uint32 // 仅 0x4002；单条 DoIP 最大 Payload 字节数
}

// DoIPPowerMode 描述电源模式阶段（UDP）。
type DoIPPowerMode struct {
    Direction          string // 见 §1.6（"up" 发 0x4003 / "down" 发 0x4004）
    PowerMode          uint8  // 仅 0x4004；合法值 {0x00, 0x01, 0x02}（v2.0.0 修复：0x02=Not Supported）
    Broadcast          bool   // true → DstIP=255.255.255.255 / ff02::1（用于 PowerMode 广播）
}

// DoIPActivation 描述路由激活阶段（TCP）。
type DoIPActivation struct {
    Direction            string  // 见 §1.6（"up" 发 0x0005 / "down" 发 0x0006）
    ActivationType       uint8   // 0x0005 携带；0x00=Default / 0x01=WWH-OBD / 0xE0..0xFF=OEM
    ResponseCode         uint8   // 仅 0x0006；v2.0.0 修复：0x10=Success / 0x00-0x07=拒绝 / 0x11=Confirmation Required
    OEMSpecific          []byte  // 变长 OEM 字段（v2.0.0 修复：变长 N B，默认 nil）
    ConfirmationRequired bool    // true → 二次确认流程（ResponseCode=0x11 后再发 0x0005）
}

// DoIPMessage 描述单条诊断消息（TCP）。
type DoIPMessage struct {
    Direction             string  // 见 §1.6（"up" Tester→ECU / "down" ECU→Tester）
    SourceAddress         uint16  // SA（请求方向=TesterAddress，应答方向=LogicalAddress）
    TargetAddress         uint16  // TA（请求方向=LogicalAddress，应答方向=TesterAddress）
    AckCode               uint8   // 仅 0x8002；0x00=ACK（仅此值合法）
    NackCode              *uint8  // nil=发 0x8002 Ack / 非 nil=发 0x8003 Nack（合法值 0x02..0x08）
    UserData              []byte  // 0x8001 的 UDS 报文 / 0x8002/0x8003 的 PreviousDiagnosticMessage（v2.0.1 修复：无独立 PrevLen 字段，长度由 PayloadLength-5 隐式推导）
    UDS                   *DoIPUDS // 若非 nil，Planner 序列化为 UserData（覆盖 UserData 字段）
}

// DoIPUDS 描述 UDS 报文（嵌入 DoIPMessage.UserData）。
type DoIPUDS struct {
    ServiceID             uint8  // 0x10/0x11/0x22/0x27/0x2E/0x31/0x34/0x36/0x37/0x3E
    IsResponse            bool   // false=请求 / true=正向响应（SID 自动 |0x40）
    HasSubFunction        *bool  // nil=auto（仅 {0x10,0x11,0x27,0x31,0x3E} 含 sub-function）
    SubFunction           uint8  // sub-function 字节（仅 HasSubFunction=true 时输出）
    DID                   []byte // 仅 0x22/0x2E；2B DID（可多个）
    Data                  []byte // 0x22 响应数据 / 0x2E 写入数据 / 0x31 例程参数
    AddressAndLength      []byte // 仅 0x34；dataFormatId(1)+addressAndLengthFormatId(1)+addr(3or4)+size(3or4)
    BlockSequenceCounter  uint8  // 仅 0x36；公式 n%256（n=1→0x01, n=255→0xFF, n=256→0x00, n=257→0x01）
    TransferData          []byte // 仅 0x36；数据块
    Seed                  []byte // 仅 0x27 奇数响应；seed 字节
    Key                   []byte // 仅 0x27 偶数请求；key 字节（v2.0.0 修复：仅 IsResponse=false 时使用）
    NegativeResponseCode  uint8  // 非 0 → 生成否定响应 0x7F+<Request SID>+NRC（NRC 优先于 IsResponse）
}

// DoIPAliveCheck 描述存活检查阶段（TCP）。
type DoIPAliveCheck struct {
    Direction      string // 见 §1.6（"down" 发 0x0007 / "up" 发 0x0008）
    SourceAddress  uint16 // 仅 0x0008；Tester 逻辑地址（与 0x0005 SA 一致）
}

// DoIPGenericNack 描述通用头 NACK（仅模拟头部错误场景）。
type DoIPGenericNack struct {
    NackCode uint8 // 0x00..0x04 合法（见 §2.3）
    // Direction 固定 "down"（ECU→Tester，ISO 13400-2:2019 §8.4.1 接收方对错误报文的响应）
    // 注：v1.2 曾允许 Direction="up" 用于 fuzzing 场景，v2.0.0 删除（MEDIUM-7 修复）
}
```

### §3.2 默认值与字段填充规则

| 字段 | 默认值 | 说明 |
|---|---|---|
| ProtocolVersion | 0x02 (V2) | InverseProtocolVersion 自动 = ~PV & 0xFF（0x02→0xFD） |
| SrcIP | "192.168.1.100" | Tester IP |
| DstIP | "192.168.1.200" | ECU IP（Discovery/PowerMode Broadcast=true 时覆盖为 255.255.255.255 / ff02::1） |
| SrcPort | 0 | UDP SrcPort（0 = ephemeral） |
| VIN | "00000000000000000" | 17B ASCII（默认全 0） |
| LogicalAddress | 0x0001 | ECU 逻辑地址 |
| TesterAddress | 0x0E80 | Tester 逻辑地址（常见值 0x0E80 = diagnostic tester） |
| EID | "" → spec.DstMAC 去冒号 hex 解码 | 失败则 6B 0（fallback 路径，见 §6.16.5） |
| GID | "" → 6B 0 | 组标识 |
| Discovery.Direction | "down" | 默认 ECU 公告（0x0004） |
| Discovery.RequestType | 0x0001 | 广播发现 |
| Discovery.Broadcast | true | UDP 广播 |
| Discovery.AnnouncementCount | 3 | ISO 13400-2:2019 §8.5.1 |
| Discovery.FurtherActionRequired | 0x00 | No further action |
| Discovery.SyncStatus | 0x00 | Synchronized |
| EntityStatus.Direction | "down" | 默认 ECU 应答（0x4002） |
| EntityStatus.NodeType | 0x01 | DoIP Node |
| EntityStatus.MaxOpenSockets | 1 | 单 socket |
| EntityStatus.CurOpenSockets | 1 | 当前 1 socket |
| EntityStatus.MaxDataSize | 4095 | 单包最大 4095B |
| PowerMode.Direction | "down" | 默认 ECU 应答（0x4004） |
| PowerMode.PowerMode | 0x01 | Ready |
| PowerMode.Broadcast | false | 默认单播 |
| Activation.Direction | "up" | 默认 Tester 请求（0x0005） |
| Activation.ActivationType | 0x00 | Default |
| Activation.ResponseCode | 0x10 | Success（v2.0.0 修复） |
| Activation.OEMSpecific | nil | 不附加 OEM 字段（v2.0.0 修复） |
| Activation.ConfirmationRequired | false | 不走二次确认 |
| Message.Direction | "up" | 默认 Tester 请求 |
| Message.AckCode | 0x00 | ACK |
| Message.NackCode | nil | 默认发 Ack |
| AliveCheck.Direction | "down" | 默认 ECU 主动探活（0x0007） |
| AliveCheck.SourceAddress | TesterAddress | 与 0x0005 SA 一致 |
| GenericNack.NackCode | 0x00 | Incorrect Pattern Format |

### §3.3 IPv6 地址与 MAC 处理

- IPv4 广播：DstIP = `255.255.255.255`，DstMAC = `ff:ff:ff:ff:ff:ff`。
- IPv6 组播：DstIP = `ff02::1`，DstMAC = `33:33:00:00:00:01`（RFC 2464 §7，取组播地址末 32 位 `00 00 00 01`）。
- 触发条件：`spec.SrcIP` 含 `:`（IPv6 标记）→ DstIP/DstMAC 切换为 IPv6 组播；Discovery.Broadcast=true 或 PowerMode.Broadcast=true 时覆盖 DstIP/DstMAC。
- 单播场景：spec.DstIP 为具体 IPv4/IPv6 地址，DstMAC 由 spec.DstMAC 字段指定或 ARP 解析（不在本设计范围）。

---

## §4. 状态机

DoIP 业务流程按以下阶段顺序执行。每个阶段对应一类 PayloadType，Planner 按阶段顺序生成 PacketConfig，PacketIndex 在所有阶段内连续递增。

### §4.1 阶段 1：车辆发现（Vehicle Discovery，UDP）

触发条件：`spec.DoIP.Discovery != nil`。

- ECU 启动后主动发 0x0004 车辆公告（Announcement）：连续 3 条 0x0004（AnnouncementCount=3），间隔 500ms±100ms（由 worker Pacer 控制时间精度，Planner 仅生成 3 条 PacketConfig，Timestamp 由 Plan 内部连续 `time.Now()` 注入）。
- Tester 收到公告后可发 0x0001/0x0002/0x0003 主动查询（Direction="up"）。
- 0x0001 = 全网广播发现（无 Payload）；0x0002 = 按 EID 单播（Payload=6B EID）；0x0003 = 按 VIN 单播（Payload=17B VIN）。
- ECU 应答 0x0004（Payload=33B：VIN 17B + LA 2B + EID 6B + GID 6B + FAR 1B + Sync 1B）。
- UDP 广播地址：IPv4 DstIP=255.255.255.255, DstMAC=ff:ff:ff:ff:ff:ff；IPv6 DstIP=ff02::1, DstMAC=33:33:00:00:00:01。
- FlowID 后缀 `:udp:disc`。

### §4.2 阶段 2：DoIP Entity Status（UDP，v2.0.0 新增）

触发条件：`spec.DoIP.EntityStatus != nil`。

- Tester 发 0x4001（无 Payload，UDP 单播到 ECU IP）。
- ECU 应答 0x4002（Payload=7B：NodeType 1B + MaxOpenSockets 1B + CurOpenSockets 1B + MaxDataSize 4B）。
- 用途：探测 ECU 节点类型（Gateway/Node）、最大并发 socket 数、单包最大数据大小，为后续 0x8001 UserData 大小提供上限参考。
- FlowID 后缀 `:udp:entity`。

### §4.3 阶段 3：路由激活（Routing Activation，TCP）

触发条件：`spec.DoIP.Activation != nil`。

- Tester 发 0x0005（Payload=7+N B：SA 2B + AT 1B + Reserved 4B + OEM N B）。
- ECU 应答 0x0006（Payload=9+N B：CLA 2B + SLA 2B + RC 1B + Reserved 4B + OEM N B）。
- ResponseCode=0x10 → 激活成功，进入诊断阶段。
- ResponseCode=0x00..0x07 → 激活失败，关闭 TCP（FIN），不进入诊断阶段。
- **ResponseCode=0x11（Confirmation Required，v2.0.0 新增）**：Tester 收到 0x11 后需再发 0x0005 二次确认（Activation.ConfirmationRequired=true 触发），ECU 回 0x0006（最终 0x10 成功或 0x05 拒绝）。
- TCP 三次握手在前（SYN/SYN-ACK/ACK），路由激活在握手之后。
- FlowID 后缀 `:tcp:act`。

子阶段（ConfirmationRequired=true 时）：
1. Tester → ECU：0x0005（首次）
2. ECU → Tester：0x0006 RC=0x11（Confirmation Required）
3. Tester → ECU：0x0005（二次确认）
4. ECU → Tester：0x0006 RC=0x10（最终 Success）→ 进入诊断阶段
4'（拒绝路径）：ECU → Tester：0x0006 RC=0x05（Denied — Rejected Confirmation，二次确认被拒，ISO 13400-2:2019 §9.3.6）→ 关闭 TCP（FIN），不进入诊断阶段（v2.0.1 新增，M1）

### §4.4 阶段 4：诊断消息（Diagnostic Message，TCP）

触发条件：`len(spec.DoIP.Messages) > 0` 且路由激活成功。

- 每条 Message 生成一条 0x8001（UserData = UDS 序列化字节）。
- 0x8001 后紧跟 0x8002（Ack）或 0x8003（Nack）：若 Message.NackCode=nil → 0x8002 Ack；否则 → 0x8003 Nack。
- 0x8002/0x8003 的 PreviousDiagnosticMessage = 被确认的 0x8001 UserData 完整字节副本（长度由 PayloadLength-5 隐式推导，无独立长度字段，v2.0.1 修复）。
- SA/TA 一致性校验：0x8001 请求方向 SA=TesterAddress, TA=LogicalAddress；应答方向 SA=LogicalAddress, TA=TesterAddress（M9 修复）。
- 大数据传输（0x34/0x36/0x37）：0x36 TransferData 按 MSS 分段（见 §6.10）。
- FlowID 后缀 `:tcp:diag`。

### §4.5 阶段 5：存活检查（Alive Check，TCP）

触发条件：`spec.DoIP.AliveCheck != nil`。

- ECU 主动发 0x0007（无 Payload，Direction="down"）。
- Tester 应答 0x0008（Payload=2B SA，Direction="up"）。
- 可在诊断阶段任意时刻插入（由 AliveCheck 在 Config 中的位置决定 PacketIndex）。
- FlowID 后缀 `:tcp:alive`。

### §4.6 阶段 6：电源模式（Power Mode，UDP）

触发条件：`spec.DoIP.PowerMode != nil`。

- Tester 发 0x4003（无 Payload，UDP 单播或广播）。
- ECU 应答 0x4004（Payload=1B DiagnosticPowerMode）。
- DiagnosticPowerMode ∈ {0x00=Not Ready, 0x01=Ready, 0x02=Not Supported}。
- PowerMode.Broadcast=true 时 DstIP=255.255.255.255 / ff02::1。
- FlowID 后缀 `:udp:power`。

### §4.7 阶段 7：通用 NACK（Generic NACK，TCP/UDP）

触发条件：`spec.DoIP.GenericNack != nil`。

- 发送 0x0000（Payload=1B NackCode），Direction 固定 "down"（ECU→Tester）。
- 用于模拟头部错误场景（Incorrect Pattern Format / Unknown Payload Type / Message Too Large / Out of Memory / Invalid Payload Length）。
- 在路由激活之后、诊断消息之前发送（异常注入场景）。
- FlowID 后缀 `:nack`。

---

## §5. 配置类型定义（Go struct，详 §3.1）

### §5.1 FlowID 后缀规则

- UDP 车辆发现：`<spec.FlowID>:udp:disc`
- UDP Entity Status：`<spec.FlowID>:udp:entity`
- UDP 电源模式：`<spec.FlowID>:udp:power`
- TCP 路由激活：`<spec.FlowID>:tcp:act`
- TCP 诊断消息：`<spec.FlowID>:tcp:diag`
- TCP 存活检查：`<spec.FlowID>:tcp:alive`
- NACK：`<spec.FlowID>:nack`

Discovery/PowerMode/EntityStatus 各自 FlowID 后缀不同，避免 UDP 共用 4-tuple 时 FlowID 冲突。

### §5.2 MSS 分段规则

- TCP 数据段（PSH-ACK）若 Payload > MSS，按 MSS 分段，每段独立 TCP 序列号。
- MSS=0 → Validate 报错 "MSS must be > 0"（H5 修复）；或 Plan 自动 fallback 到默认 1460（由调用方选择策略，本设计默认 Validate 报错）。
- 0x36 TransferData 的 UserData = SID(1B) + BlockSeq(1B) + Data(N)；若 UserData > MSS-40（TCP/IP 头开销），按 MSS-40 分段 Data，每段独立 0x8001（§6.10）。

### §5.3 PacketConfig.Timestamp 注入

- Planner 生成 PacketConfig 时 Timestamp = `time.Now()`（连续递增，不注入 500ms 间隔）。
- 500ms±100ms 间隔是 ECU 行为（ISO 13400-2:2019 §8.5.1），由 worker 层 Pacer 按 bps 限速间接产生；若需精确时间戳，调用方在 replay 侧注入（M4 修复）。

### §5.4 GroupID 路由

- 同一 ECU 的 UDP + TCP 子流共用 spec.GroupID（确保同一 PacketWorker 处理，避免跨 worker 乱序）。
- 多 ECU 场景：每 ECU 独立 GroupID。

---

## §6. 包序列场景（HexDump S1-S15）

> 所有 HexDump 均按 DoIP 头 8B + Payload 逐字节列出。Length 字段已逐字节核算（PayloadLength = 实际 Payload 字节数，不含头部 8B）。

### §6.1 S1：车辆发现（0x0001 + 0x0004 ×3 公告）

**Tester→ECU 0x0001 Vehicle Identification Request（广播）**：
```
02 FD 00 01 00 00 00 00
```
- 02 = ProtocolVersion (V2)
- FD = InverseProtocolVersion (~0x02 & 0xFF = 0xFD)
- 00 01 = PayloadType (0x0001)
- 00 00 00 00 = PayloadLength (0，无 Payload)

**ECU→Tester 0x0004 Vehicle Announcement（×3，间隔 500ms±100ms）**：
```
02 FD 00 04 00 00 00 21
57 4C 30 30 41 42 43 30 30 30 30 30 30 30 30 30 30  <- VIN "WL00ABC0000000000" (17B)
00 01                                                <- LogicalAddress (0x0001)
00 11 22 33 44 55                                    <- EID (ECU MAC)
00 00 00 00 00 00                                    <- GID (6B 0)
00                                                  <- FurtherActionRequired (0x00)
00                                                  <- SyncStatus (0x00)
```
- PayloadLength = 0x21 = 33（17+2+6+6+1+1 = 33）
- VIN ASCII: `WL00ABC0000000000`（17 字符）

### §6.2 S2：路由激活（0x0005 + 0x0006 Success）

**Tester→ECU 0x0005 Routing Activation Request**：
```
02 FD 00 05 00 00 00 07
0E 80                                                <- SourceAddress (0x0E80, Tester)
00                                                  <- ActivationType (0x00 Default)
00 00 00 00                                          <- Reserved ISO (4B 0)
```
- PayloadLength = 0x07 = 7（2+1+4 = 7，N=0 无 OEM-specific）

**ECU→Tester 0x0006 Routing Activation Response (Success)**：
```
02 FD 00 06 00 00 00 09
0E 80                                                <- ClientLogicalAddress (0x0E80)
00 01                                                <- ServerLogicalAddress (0x0001)
10                                                  <- ResponseCode (0x10 Success, v2.0.0 修复)
00 00 00 00                                          <- Reserved ISO (4B 0)
```
- PayloadLength = 0x09 = 9（2+2+1+4 = 9，N=0 无 OEM-specific）

### §6.3 S3：诊断消息（0x8001 + 0x8002，UDS 0x10 DiagnosticSessionControl）

**Tester→ECU 0x8001 Diagnostic Message（0x10 0x03 切换扩展会话）**：
```
02 FD 80 01 00 00 00 06
0E 80                                                <- SA (Tester)
00 01                                                <- TA (ECU)
10 03                                                <- UserData: UDS 0x10 0x03
```
- PayloadLength = 0x06 = 6（SA 2 + TA 2 + UserData 2 = 6）

**ECU→Tester 0x8002 Diagnostic Message Ack**：
```
02 FD 80 02 00 00 00 07
00 01                                                <- SA (ECU，与被确认 0x8001 TA 一致)
0E 80                                                <- TA (Tester，与被确认 0x8001 SA 一致)
00                                                  <- AckCode (0x00 ACK)
10 03                                                <- PreviousDiagnosticMessage (UserData 副本)
```
- PayloadLength = 0x07 = 7（SA 2 + TA 2 + AckCode 1 + PrevDiag 2 = 7 = 5 + M，M=2；v2.0.1 修复：无独立 PrevLen 字段）
- PreviousDiagnosticMessage 长度由 PayloadLength - 5 = 2 隐式推导，与 ISO/scapy/Wireshark/python-doipclient 一致

### §6.4 S4：诊断消息否定确认（0x8001 + 0x8003 Nack）

**Tester→ECU 0x8001（0x22 0xF190 ReadDataByIdentifier 读 VIN）**：
```
02 FD 80 01 00 00 00 07
0E 80                                                <- SA (Tester)
00 01                                                <- TA (ECU)
22 F1 90                                             <- UserData: UDS 0x22 0xF1 0x90
```
- UserData = 0x22 0xF1 0x90（3B）→ PayloadLength = 2+2+3 = 7 = 0x07（v2.0.1 修复：原 0x08 系 2+2+3=8 手算错误，实际 7B）

**ECU→Tester 0x8003 Nack（NackCode=0x02 Invalid Source Address）**：
```
02 FD 80 03 00 00 00 08
00 01                                                <- SA (ECU)
0E 80                                                <- TA (Tester)
02                                                  <- NackCode (0x02 Invalid SA)
22 F1 90                                             <- PreviousDiagnosticMessage (UserData 副本)
```
- SA(2)=00 01, TA(2)=0E 80, NackCode(1)=02, PrevDiag(3)=22 F1 90
- PayloadLength = 0x08 = 8（SA 2 + TA 2 + NackCode 1 + PrevDiag 3 = 8 = 5 + M，M=3；v2.0.1 修复：无独立 PrevLen 字段）

### §6.5 S5：心跳（0x0007 + 0x0008）

**ECU→Tester 0x0007 Alive Check Request**：
```
02 FD 00 07 00 00 00 00
```
- PayloadLength = 0（无 Payload）

**Tester→ECU 0x0008 Alive Check Response**：
```
02 FD 00 08 00 00 00 02
0E 80
```
- PayloadLength = 0x02 = 2（SA 2B）

### §6.6 S6：诊断消息否定确认（0x8003 NackCode 各值）

见 §6.4 示例。NackCode 合法值 0x02-0x08，0x00/0x01/0x09-0xFF 拒绝。

### §6.7 S7：DoIP Entity Status（0x4001 + 0x4002，v2.0.0 新增）

**Tester→ECU 0x4001 DoIP Entity Status Request**：
```
02 FD 40 01 00 00 00 00
```
- PayloadLength = 0（无 Payload）

**ECU→Tester 0x4002 DoIP Entity Status Response**：
```
02 FD 40 02 00 00 00 07
01                                                  <- NodeType (0x01 DoIP Node)
01                                                  <- MaxOpenSockets (1)
01                                                  <- CurOpenSockets (1)
00 00 0F FF                                          <- MaxDataSize (4095)
```
- PayloadLength = 0x07 = 7（1+1+1+4 = 7）

### §6.8 S8：一般否定确认（0x0000 Generic NACK）

**ECU→Tester 0x0000 Generic DoIP Header NACK（NackCode=0x01 Unknown Payload Type）**：
```
02 FD 00 00 00 00 00 01
01
```
- PayloadLength = 0x01 = 1（NackCode 1B）

### §6.9 S9：多会话场景（多 ECU 各自路由激活 + 诊断）

3 个 ECU（LA=0x0001/0x0002/0x0003）各自独立 TCP 连接（独立 4-tuple），每 ECU 完整流程：
- ECU1: 0x0005(SA=0x0E80) → 0x0006(CLA=0x0E80, SLA=0x0001, RC=0x10) → 0x8001(SA=0x0E80, TA=0x0001) → 0x8002 → ...
- ECU2: 0x0005(SA=0x0E80) → 0x0006(CLA=0x0E80, SLA=0x0002, RC=0x10) → 0x8001(SA=0x0E80, TA=0x0002) → 0x8002 → ...
- ECU3: 0x0005(SA=0x0E80) → 0x0006(CLA=0x0E80, SLA=0x0003, RC=0x10) → 0x8001(SA=0x0E80, TA=0x0003) → 0x8002 → ...

每 ECU FlowID 后缀独立，GroupID 独立。

### §6.10 S10：多流关联（0x34/0x36/0x37 大文件传输）

**Tester→ECU 0x8001（0x34 RequestDownload）**：
```
02 FD 80 01 00 00 00 0F
0E 80                                                <- SA (Tester)
00 01                                                <- TA (ECU)
34                                                  <- UserData: UDS 0x34 SID
00                                                  <- dataFormatId (0x00)
44                                                  <- addressAndLengthFormatId (高 4 位=addr 长度 4B，低 4 位=size 长度 4B)
00 00 00 01                                          <- addr (0x00000001, 4B)
00 00 00 10                                          <- size (0x00000010 = 16, 4B)
```
- UserData = 0x34 0x00 0x44 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x10（11B：SID 1 + dataFormatId 1 + addressAndLengthFormatId 1 + addr 4 + size 4）
- PayloadLength = 2+2+11 = 15 = 0x0F（v2.0.1 修复：原 HexDump 缺 size 字段 4B，UserData 仅 7B 但注释称 11B，属非法 0x34 报文；现与 T041 输入 `AddressAndLength=00 44 00 00 00 01 00 00 00 10` 一致）

**Tester→ECU 0x8001（0x36 TransferData，BlockSeq=0x01，Data=4B）**：
```
02 FD 80 01 00 00 00 0A
0E 80                                                <- SA (Tester)
00 01                                                <- TA (ECU)
36                                                  <- UserData: UDS 0x36 SID
01                                                  <- BlockSequenceCounter (0x01)
AA BB CC DD                                          <- Data (4B)
```
- UserData = 0x36 0x01 0xAA 0xBB 0xCC 0xDD（6B：SID + BlockSeq + 4B Data）
- PayloadLength = 0x0A = 10（SA 2 + TA 2 + UserData 6 = 10）

**Tester→ECU 0x8001（0x37 RequestTransferExit）**：
```
02 FD 80 01 00 00 00 05
0E 80                                                <- SA (Tester)
00 01                                                <- TA (ECU)
37                                                  <- UserData: UDS 0x37 SID
```
- UserData = 0x37（1B：仅 SID）
- PayloadLength = 2+2+1 = 5 = 0x05

### §6.11 S11：错误处理（路由激活失败 + TCP 关闭）

**Tester→ECU 0x0005（SA=0x0E80, AT=0x00）**：同 §6.2 0x0005。

**ECU→Tester 0x0006（ResponseCode=0x00 Unknown Source Address）**：
```
02 FD 00 06 00 00 00 09
0E 80 00 01 00 00 00 00 00
```
- PayloadLength = 0x09 = 9（2+2+1+4 = 9）
- ResponseCode = 0x00（Unknown SA 拒绝）

**ECU→Tester TCP FIN**：路由激活失败后 ECU 主动关闭 TCP（FIN/ACK）。

### §6.12 S12：IPv6 全流程（Discovery 广播 + 路由激活 + 诊断 + 心跳）

- spec.SrcIP = "fe80::1"（Tester IPv6）
- spec.DstIP = "fe80::2"（ECU IPv6 单播）
- Discovery.Broadcast=true → DstIP=ff02::1, DstMAC=33:33:00:00:00:01

**Tester→ECU 0x0001（IPv6 广播）**：
```
02 FD 00 01 00 00 00 00
```
（DoIP 报文相同，IP/Ethernet 层 IPv6 组播）

**ECU→Tester 0x0004（IPv6 单播应答，DstIP=fe80::1）**：同 §6.1 0x0004。

**Tester→ECU 0x0005 / 0x8001**：同 §6.2 / §6.3，IP 层 IPv6。

**ECU→Tester 0x0007 / Tester→ECU 0x0008**：同 §6.5。

### §6.13 S13：边界值场景

| 场景 | 字段值 | 期望 |
|---|---|---|
| §6.13.1 EID 空 + spec.DstMAC 有效 | EID="" DstMAC="00:11:22:33:44:55" | 0x0004 EID=00:11:22:33:44:55 |
| §6.13.2 EID 空 + spec.DstMAC 空 | EID="" DstMAC="" | 0x0004 EID=6B 0（fallback） |
| §6.13.3 EID 空 + spec.DstMAC 非法 | EID="" DstMAC="invalid" | 0x0004 EID=6B 0（hex 解析失败 fallback） |
| §6.13.4 EID 空 + spec.DstMAC 过长 | EID="" DstMAC="00:11:22:33:44:55:66" | Validate 报错 |
| §6.13.5 0x8001 UserData ≤ MaxDataSize（若 EntityStatus 存在） | UserData=4000B，MaxDataSize=4095 | 通过（受 §8.3/§8.5 MaxDataSize 约束，v2.0.1 重写：原 PrevLen u16 上限约束不存在） |
| §6.13.6 0x8001 UserData > MaxDataSize | UserData=5000B，MaxDataSize=4095 | Validate 报错（受 §8.5 MaxDataSize 约束） |
| §6.13.7 0x8001 UserData ≤ PayloadLength u32 上限 | UserData=65535B | PayloadLength=65539 ≤ 4GB-1 通过（理论边界，v2.0.1 重写：由 PayloadLength u32 隐式推导，非 PrevLen u16） |
| §6.13.8 0x8001 UserData > 4GB-1 | UserData=4GB | Validate 报错 "PayloadLength u32 overflow"（理论边界，实际不可达） |
| §6.13.9 ResponseCode=0x10 Success | RC=0x10 | 通过（v2.0.0 修复） |
| §6.13.10 ResponseCode=0x11 Confirmation | RC=0x11 | 通过（v2.0.0 新增） |
| §6.13.11 NackCode=0x02 Invalid SA | NC=0x02 | 通过（v2.0.0 修复） |
| §6.13.12 NackCode=0x00 Reserved | NC=0x00 | Validate 报错（v2.0.0 修复） |
| §6.13.13 FurtherActionRequired=0x10 | FAR=0x10 | 通过 |
| §6.13.14 FurtherActionRequired=0x11 | FAR=0x11 | Validate 报错（v2.0.0 修复，0x11 Reserved） |
| §6.13.15 SyncStatus=0x10 Not synced | SS=0x10 | 通过（v2.0.0 修复） |
| §6.13.16 SyncStatus=0x01 Reserved | SS=0x01 | Validate 报错（v2.0.0 修复） |
| §6.13.17 DiagnosticPowerMode=0x02 Not Supported | PM=0x02 | 通过（v2.0.0 修复） |
| §6.13.18 DiagnosticPowerMode=0x03 Reserved | PM=0x03 | Validate 报错 |
| §6.13.19 NRC=0x00 | NRC=0x00 | Validate 报错（H6 修复） |
| §6.13.20 NRC=0xFF | NRC=0xFF | Validate 报错（H6 修复） |
| §6.13.21 NRC=0x7F | NRC=0x7F | 通过（H6 修复） |
| §6.13.22 MSS=0 | TCP.MSS=0 | Validate 报错（H5 修复） |
| §6.13.23 OEM-specific=4B | OEM=0x01020304 | PayloadLength=11（0x0005）/13（0x0006）（OEM 长度任意，不受 PrevLen u16 约束，见 §8.5） |
| §6.13.24 OEM-specific=0B | OEM=nil | PayloadLength=7（0x0005）/9（0x0006） |
| §6.13.25 V1+OEM 拒绝 | PV=0x01 + OEM 非 nil | Validate 报错 |

### §6.14 S14：超时场景

- Tester 发 0x0005 后 ECU 不应答（模拟超时）→ Tester 侧 TCP RST 或 FIN（由调用方在 spec.Termination 配置）。
- ECU 发 0x0007 后 Tester 不应答 0x0008 → ECU 主动关闭 TCP（FIN）。
- 这两类超时由 worker 层超时控制，Planner 仅生成单边报文（0x0005 不带 0x0006，或 0x0007 不带 0x0008）。

### §6.15 S15：完整诊断流程（端到端）

单 ECU 完整流程（总包数 22）：
1. UDP 0x0001（Tester 广播发现）
2. UDP 0x0004（ECU 公告，3 条 AnnouncementCount=3）→ 包 2-4
3. TCP SYN/SYN-ACK/ACK（三次握手）→ 包 5-7
4. TCP 0x0005（路由激活请求）→ 包 8
5. TCP 0x0006（路由激活应答 RC=0x10）→ 包 9
6. TCP 0x8001（UDS 0x10 0x03 切换会话）→ 包 10
7. TCP 0x8002（Ack）→ 包 11
8. TCP 0x8001（UDS 0x22 读 VIN）→ 包 12
9. TCP 0x8002（Ack）→ 包 13
10. TCP 0x8001（UDS 0x27 安全访问）→ 包 14
11. TCP 0x8002（Ack）→ 包 15
12. TCP 0x0007（ECU 探活）→ 包 16
13. TCP 0x0008（Tester 应答）→ 包 17
14. TCP 0x8001（UDS 0x3E TesterPresent）→ 包 18
15. TCP 0x8002（Ack）→ 包 19
16. TCP FIN/ACK（四次挥手）→ 包 20-22

总包数 = 1 + 3 + 3 + 2 + (2+2+2+2) + 2 + 2 + 3 = 22 包（Discovery 1 + Announcement 3 + 握手 3 + 激活 2 + 诊断 8 + 心跳 2 + 挥手 3）。

### §6.16 HexDump 场景索引

| 场景 | PayloadType | 覆盖测试用例 |
|---|---|---|
| S1 车辆发现 | 0x0001/0x0004 | T01/T09/T10/T11/T16 |
| S2 路由激活 | 0x0005/0x0006 | T02/T17/T17a/T17b/T17c/T21 |
| S3 诊断消息 | 0x8001/0x8002 | T03/T04/T05/T06 |
| S4 诊断确认 | 0x8003 | T22/T22a/T22b/T22c |
| S5 心跳 | 0x0007/0x0008 | T07 |
| S6 否定确认 | 0x8003 | T22a-T22c |
| S7 Entity Status | 0x4001/0x4002 | T46/T47/T48 |
| S8 一般否定确认 | 0x0000 | T23/T23a-T23d |
| S9 多会话 | 0x0005/0x0006/0x8001/0x8002 | T41 |
| S10 多流关联 | 0x8001（0x34/0x36/0x37） | T06/T06a/T20 |
| S11 错误处理 | 0x0006 RC=0x00 | T21/T26 |
| S12 IPv6 全流程 | 所有类型 IPv6 | T09a/T46/T47/T48 |
| S13 边界值 | 见 §6.13 表 | T14/T15/T15a/T15b/T15c/T24a/T24b/T24c/T32/T49 |
| S14 超时 | 0x0005/0x0007 单边 | T25/T26 |
| S15 完整诊断流程 | 端到端 | T41/T42/T45 |

---

## §7. 测试用例（T-001 ~ T-203）

> 每条用例标注：场景、输入、断言（可观察值）、对应 spec 行（格式 T00N 场景名 (§X.Y)，X.Y=本文档断言依据所在章节）。测试驱动开发（CLAUDE.md §7）：bug 修复必须先写失败测试。

### §7.1 报文格式基础（T001-T020）

| 用例 | 场景 | 输入 | 断言 | 对应 spec 行 |
|---|---|---|---|---|
| T001 | DoIP 头 8B V2 | PV=0x02 | 头 = 02 FD 00 01 00 00 00 00 | §2.1/§2.4 |
| T002 | InverseProtocolVersion 校验 | PV=0x02 | InvPV=0xFD | §2.1 |
| T003 | 0x0001 广播发现 | Discovery.RequestType=0x0001 | PayloadLength=0 | §2.4 |
| T004 | 0x0002 EID 发现 | RequestType=0x0002 EID=00:11:22:33:44:55 | Payload=6B EID, PayloadLength=6 | §2.5 |
| T005 | 0x0003 VIN 发现 | RequestType=0x0003 VIN="WL00ABC0000000000" | Payload=17B VIN, PayloadLength=17 | §2.6 |
| T006 | 0x0004 公告 | Discovery.Direction="down" | PayloadLength=33, FAR=0x00, Sync=0x00 | §2.7 |
| T007 | 0x0004 公告 3 次 | AnnouncementCount=3 | 生成 3 条 0x0004 PacketConfig | §2.7/§4.1 |
| T008 | 0x0005 路由激活 | SA=0x0E80 AT=0x00 | PayloadLength=7, OEM=nil | §2.8 |
| T009 | 0x0006 Success | RC=0x10 | ResponseCode=0x10（v2.0.0 修复） | §2.9 |
| T010 | 0x0007 心跳请求 | AliveCheck.Direction="down" | PayloadLength=0 | §2.10 |
| T011 | 0x0008 心跳应答 | Direction="up" SA=0x0E80 | PayloadLength=2, SA=0x0E80 | §2.11 |
| T012 | 0x4001 Entity Status 请求 | EntityStatus.Direction="up" | PayloadLength=0 | §2.11a |
| T013 | 0x4002 Entity Status 应答 | Direction="down" NodeType=0x01 MaxSockets=1 CurSockets=1 MaxData=4095 | PayloadLength=7 | §2.11a |
| T014 | 0x4003 电源模式请求 | PowerMode.Direction="up" | PayloadLength=0 | §2.12 |
| T015 | 0x4004 电源模式应答 | Direction="down" PM=0x01 | PayloadLength=1, PM=0x01 | §2.12 |
| T016 | 0x8001 诊断消息 | SA=0x0E80 TA=0x0001 UserData=10 03 | PayloadLength=6 | §2.13 |
| T017 | 0x8002 Ack | AckCode=0x00 PrevDiag=10 03 | PayloadLength=7 (V2), PrevDiag=10 03（无独立 PrevLen 字段，v2.0.1 修复） | §2.14 |
| T018 | 0x8003 Nack | NackCode=0x02 PrevDiag=22 F1 90 | PayloadLength=8, NackCode=0x02 | §2.15 |
| T019 | 0x0000 Generic NACK | NackCode=0x01 | PayloadLength=1, NackCode=0x01 | §2.3 |
| T020 | 默认 Direction 空值 | Direction="" | 走 PayloadType 默认方向 | §1.6/§8.6 |

### §7.2 路由激活（T021-T030）

| 用例 | 场景 | 输入 | 断言 | 对应 spec 行 |
|---|---|---|---|---|
| T021 | RC=0x10 Success | RC=0x10 | 通过 | §2.9 |
| T021a | RC=0x00 Unknown SA | RC=0x00 | 通过（v2.0.0 修复：原 0x00=Success 错误） | §2.9 |
| T021b | RC=0x01 All sockets | RC=0x01 | 通过 | §2.9 |
| T021c | RC=0x04 Missing Auth | RC=0x04 | 通过 | §2.9 |
| T021d | RC=0x05 Rejected Confirmation | RC=0x05 | 通过 | §2.9 |
| T021e | RC=0x07 TLS Required | RC=0x07 | 通过 | §2.9 |
| T021f | RC=0x11 Confirmation Required | RC=0x11 ConfirmationRequired=true | 通过（v2.0.0 新增 H7） | §2.9/§4.3 |
| T021g | RC=0x12 Reserved | RC=0x12 | Validate 报错 | §2.9 |
| T022 | ActivationType=0x00 Default | AT=0x00 | 通过 | §2.8 |
| T022a | ActivationType=0x01 WWH-OBD | AT=0x01 | 通过（术语修正 M5） | §2.8 |
| T022b | ActivationType=0xE0 OEM | AT=0xE0 | 通过 | §2.8 |
| T022c | ActivationType=0x02 Reserved | AT=0x02 | Validate 报错 | §2.8 |
| T023 | OEM-specific=4B | OEM=0x01020304 | PayloadLength=11 (0x0005) | §2.8 |
| T024 | OEM-specific=0B | OEM=nil | PayloadLength=7 (0x0005) | §2.8 |
| T025 | V1+OEM 拒绝 | PV=0x01 OEM 非 nil | Validate 报错 | §1.3/§8.1 |
| T026 | 路由激活失败关闭 TCP | RC=0x00 | TCP FIN 跟随，无诊断消息 | §4.3/§9.2 |
| T027 | 二次确认流程 | RC=0x11 + ConfirmationRequired=true | 生成 0x0005×2 + 0x0006×2 | §4.3 |
| T027a | 二次确认被拒 | RC=0x11 + ConfirmationRequired=true + 二次确认 RC=0x05 | 0x0005×2 + 0x0006(RC=0x11) + 0x0006(RC=0x05) + TCP FIN（v2.0.1 新增 M1） | §4.3 子阶段 4' |
| T028 | SA 与 0x8001 一致 | 0x0005 SA=0x0E80, 0x8001 SA=0x0E80 | 通过 | §8.3 |
| T029 | SA 与 0x8001 不一致 | 0x0005 SA=0x0E80, 0x8001 SA=0x1111 | Validate 报错（M9） | §8.3 |
| T030 | SLA 与 0x8001 TA 一致 | 0x0006 SLA=0x0001, 0x8001 TA=0x0001 | 通过 | §8.3 |

### §7.3 诊断消息（T031-T050）

| 用例 | 场景 | 输入 | 断言 | 对应 spec 行 |
|---|---|---|---|---|
| T031 | UDS 0x10 0x03 | ServiceID=0x10 SubFunction=0x03 | UserData=10 03 | §2.16 |
| T032 | UDS 0x22 0xF190 | ServiceID=0x22 DID=F1 90 | UserData=22 F1 90 | §2.16 |
| T033 | UDS 0x27 0x01（请求 seed） | ServiceID=0x27 SubFunction=0x01 IsResponse=false | UserData=27 01 | §2.16 |
| T034 | UDS 0x27 0x02（发送 key） | ServiceID=0x27 SubFunction=0x02 Key=55 66 77 88 IsResponse=false | UserData=27 02 55 66 77 88 | §2.16 |
| T035 | UDS 0x27 奇数响应（带 seed） | ServiceID=0x27 SubFunction=0x01 Seed=11 22 33 44 IsResponse=true | UserData=67 01 11 22 33 44 | §2.16 |
| T036 | UDS 0x27 偶数响应（无 key） | ServiceID=0x27 SubFunction=0x02 IsResponse=true Key=nil | UserData=67 02（v2.0.0 H3 修复） | §2.16 |
| T037 | UDS 0x27 偶数响应 + Key 非空 | ServiceID=0x27 SubFunction=0x02 IsResponse=true Key=55 | Validate 报错（H3） | §8.4 |
| T038 | UDS 0x36 BlockSeq=0x01 | ServiceID=0x36 BlockSeq=0x01 Data=AA BB | UserData=36 01 AA BB | §2.16 |
| T039 | UDS 0x36 BlockSeq 回绕 n=256 | n=256 | BlockSeq=0x00（公式 n%256） | §8.4 |
| T040 | UDS 0x36 BlockSeq 回绕 n=257 | n=257 | BlockSeq=0x01 | §8.4 |
| T041 | UDS 0x34 RequestDownload | ServiceID=0x34 AddressAndLength=00 44 00 00 00 01 00 00 00 10 | UserData=34 00 44 00 00 00 01 00 00 00 10 | §10.1 附录 B/§6.10 |
| T042 | UDS 0x37 RequestTransferExit | ServiceID=0x37 | UserData=37 | §2.16 |
| T043 | UDS 0x3E TesterPresent | ServiceID=0x3E SubFunction=0x00 | UserData=3E 00 | §2.16 |
| T044 | UDS 正向响应 SID 自动 |0x40 | ServiceID=0x22 IsResponse=true | UserData 首字节=0x62 | §2.16 |
| T045 | UDS 否定响应格式 | ServiceID=0x22 NRC=0x11 | UserData=7F 22 11（请求 SID，非响应 SID） | §2.16 |
| T046 | UDS 否定响应 NRC 优先 IsResponse | ServiceID=0x22 NRC=0x11 IsResponse=true | UserData=7F 22 11（NRC 优先） | §8.4 |
| T047 | UDS NRC=0x00 拒绝 | NRC=0x00 | Validate 报错（H6） | §8.2 |
| T048 | UDS NRC=0xFF 拒绝 | NRC=0xFF | Validate 报错（H6） | §8.2 |
| T049 | UDS NRC=0x7F 通过 | NRC=0x7F | UserData=7F <SID> 7F | §8.2 |
| T050 | UDS HasSubFunction auto | ServiceID=0x22 HasSubFunction=nil | 不输出 sub-function 字节 | §8.4 |

### §7.4 诊断确认（T051-T070）

| 用例 | 场景 | 输入 | 断言 | 对应 spec 行 |
|---|---|---|---|---|
| T051 | 0x8002 AckCode=0x00 | AckCode=0x00 | 通过 | §2.14 |
| T052 | 0x8002 AckCode=0x01 拒绝 | AckCode=0x01 | Validate 报错 | §2.14/§8.2 |
| T053 | 0x8002 PayloadLength=5+M | UserData=10 03 | PayloadLength=7（5+2），PrevDiag=10 03（无独立 PrevLen 字段，v2.0.1 修复） | §2.14 |
| T054 | 0x8003 PayloadLength=5+M（V1 同格式） | PV=0x01 NackCode=0x02 UserData=10 03 | PayloadLength=7（V1 与 V2 相同，无 PrevLen 4B，v2.0.1 修复） | §2.14/§2.15 |
| T055 | 0x8002 PrevDiag = UserData 副本 | UserData=22 F1 90 | PrevDiag=22 F1 90 | §2.14 |
| T056 | 0x8003 NackCode=0x02 Invalid SA | NackCode=0x02 | 通过（v2.0.0 修复） | §2.15 |
| T057 | 0x8003 NackCode=0x03 Unknown TA | NackCode=0x03 | 通过 | §2.15 |
| T058 | 0x8003 NackCode=0x04 Too Large | NackCode=0x04 | 通过 | §2.15 |
| T059 | 0x8003 NackCode=0x06 Target Unreachable | NackCode=0x06 | 通过 | §2.15 |
| T060 | 0x8003 NackCode=0x00 Reserved 拒绝 | NackCode=0x00 | Validate 报错（v2.0.0 修复） | §2.15 |
| T061 | 0x8003 NackCode=0x01 Reserved 拒绝 | NackCode=0x01 | Validate 报错（v2.0.0 修复） | §2.15 |
| T062 | 0x8003 NackCode=0x09 Reserved 拒绝 | NackCode=0x09 | Validate 报错 | §2.15 |
| T063 | 0x8003 PrevDiag 完整副本 | UserData=4096B | PrevDiag=4096B，PayloadLength=4101 | §2.15 |
| T064 | 0x8001 UserData ≤ MaxDataSize | UserData=4000B MaxDataSize=4095 | 通过（v2.0.1 重写：边界受 MaxDataSize 约束） | §6.13.5/§8.5 |
| T065 | 0x8001 UserData > MaxDataSize | UserData=5000B MaxDataSize=4095 | Validate 报错（v2.0.1 重写） | §6.13.6/§8.5 |
| T066 | 0x8001 UserData ≤ PayloadLength u32 上限 | UserData=65535B | PayloadLength=65539 通过（理论边界，v2.0.1 重写） | §6.13.7 |
| T067 | 0x8001 UserData=65536B | UserData=65536B | 通过（PayloadLength=65540 ≤ 4GB-1，v2.0.1 重写） | §6.13.7/§8.5 |
| T068 | 0x8001 UserData > 4GB-1 | UserData=4GB | Validate 报错 "PayloadLength u32 overflow"（理论边界，v2.0.1 重写） | §6.13.8 |
| T069 | NackCode=nil 走 Ack | NackCode=nil | 生成 0x8002 | §4.4 |
| T070 | NackCode 非 nil 走 Nack | NackCode=0x02 | 生成 0x8003 | §4.4 |

### §7.5 车辆发现（T071-T090）

| 用例 | 场景 | 输入 | 断言 | 对应 spec 行 |
|---|---|---|---|---|
| T071 | 0x0004 公告默认 3 次 | AnnouncementCount=3 | 3 条 0x0004 | §4.1 |
| T072 | 0x0004 公告 1 次 | AnnouncementCount=1 | 1 条 0x0004 | §4.1 |
| T073 | 0x0004 FurtherActionRequired=0x00 | FAR=0x00 | 通过 | §2.7 |
| T074 | 0x0004 FurtherActionRequired=0x10 | FAR=0x10 | 通过 | §2.7 |
| T075 | 0x0004 FurtherActionRequired=0x11 拒绝 | FAR=0x11 | Validate 报错（v2.0.0 C4） | §2.7 |
| T076 | 0x0004 FurtherActionRequired=0x20 拒绝 | FAR=0x20 | Validate 报错（v2.0.0 C4） | §2.7 |
| T077 | 0x0004 FurtherActionRequired=0x40 拒绝 | FAR=0x40 | Validate 报错（v2.0.0 C4） | §2.7 |
| T078 | 0x0004 SyncStatus=0x00 | SS=0x00 | 通过 | §2.7 |
| T079 | 0x0004 SyncStatus=0x10 Not synced | SS=0x10 | 通过（v2.0.0 C5） | §2.7 |
| T080 | 0x0004 SyncStatus=0x01 拒绝 | SS=0x01 | Validate 报错（v2.0.0 C5） | §2.7 |
| T081 | 0x0004 PayloadLength=33 V2 | PV=0x02 | PayloadLength=33 | §2.7 |
| T082 | 0x0004 PayloadLength=32 V1 | PV=0x01 | PayloadLength=32（无 SyncStatus） | §2.7 |
| T083 | EID 空 + DstMAC 有效 | EID="" DstMAC="00:11:22:33:44:55" | 0x0004 EID=00:11:22:33:44:55 | §3.2 |
| T084 | EID 空 + DstMAC 空 | EID="" DstMAC="" | 0x0004 EID=6B 0（fallback） | §3.2 |
| T085 | EID 空 + DstMAC 非法 | EID="" DstMAC="invalid" | 0x0004 EID=6B 0（fallback） | §3.2 |
| T086 | EID 空 + DstMAC 过长 | EID="" DstMAC="00:11:22:33:44:55:66" | Validate 报错 | §3.2 |
| T087 | EID 显式 6B | EID="001122334455" | 0x0004 EID=00:11:22:33:44:55 | §2.5 |
| T088 | EID 长度非 6B | EID="001122" | Validate 报错 | §8.5 |
| T089 | VIN ASCII 17B | VIN="WL00ABC0000000000" | 0x0004 VIN=57 4C 30 30 41 42 43 30 30 30 30 30 30 30 30 30 30 | §2.6 |
| T090 | VIN 长度非 17B | VIN="WL00" | Validate 报错 | §8.5 |

### §7.6 DoIP Entity Status（T091-T100，v2.0.0 新增）

| 用例 | 场景 | 输入 | 断言 | 对应 spec 行 |
|---|---|---|---|---|
| T091 | 0x4001 请求无 Payload | Direction="up" | PayloadLength=0 | §2.11a |
| T092 | 0x4002 应答 7B | Direction="down" | PayloadLength=7 | §2.11a |
| T093 | NodeType=0x00 Gateway | NodeType=0x00 | 通过 | §2.11a |
| T094 | NodeType=0x01 Node | NodeType=0x01 | 通过 | §2.11a |
| T095 | NodeType=0x02 Reserved | NodeType=0x02 | Validate 报错 | §2.11a |
| T096 | MaxOpenSockets=255 | MaxOpenSockets=0xFF | 通过 | §2.11a |
| T097 | CurOpenSockets ≤ MaxOpenSockets | Cur=1 Max=2 | 通过 | §8.3 |
| T098 | CurOpenSockets > MaxOpenSockets | Cur=3 Max=2 | Validate 报错（逻辑校验） | §8.3 |
| T099 | MaxDataSize=4095 | MaxDataSize=4095 | 通过 | §2.11a |
| T100 | MaxDataSize=0 | MaxDataSize=0 | 通过（边界，表示未限制） | §2.11a |

### §7.7 电源模式（T101-T110）

| 用例 | 场景 | 输入 | 断言 | 对应 spec 行 |
|---|---|---|---|---|
| T101 | 0x4003 请求无 Payload | Direction="up" | PayloadLength=0 | §2.12 |
| T102 | 0x4004 应答 1B | Direction="down" | PayloadLength=1 | §2.12 |
| T103 | PowerMode=0x00 Not Ready | PM=0x00 | 通过 | §2.12 |
| T104 | PowerMode=0x01 Ready | PM=0x01 | 通过 | §2.12 |
| T105 | PowerMode=0x02 Not Supported | PM=0x02 | 通过（v2.0.0 H4） | §2.12 |
| T106 | PowerMode=0x03 Reserved 拒绝 | PM=0x03 | Validate 报错 | §2.12 |
| T107 | PowerMode 广播 IPv4 | Broadcast=true SrcIP="192.168.1.100" | DstIP=255.255.255.255 DstMAC=ff:ff:ff:ff:ff:ff | §3.3 |
| T108 | PowerMode 广播 IPv6 | Broadcast=true SrcIP="fe80::1" | DstIP=ff02::1 DstMAC=33:33:00:00:00:01 | §3.3 |
| T109 | PowerMode 单播 | Broadcast=false | DstIP=spec.DstIP | §3.3 |
| T110 | V1+PowerMode 拒绝 | PV=0x01 PowerMode 非 nil | Validate 报错（本设计选择，非 ISO 要求，v2.0.1 注明） | §1.3/§8.1 |

### §7.8 心跳（T111-T120）

| 用例 | 场景 | 输入 | 断言 | 对应 spec 行 |
|---|---|---|---|---|
| T111 | 0x0007 ECU→Tester | Direction="down" | PayloadLength=0，Direction="down" 通过（正向用例） | §2.10/§8.6 |
| T112 | 0x0008 Tester→ECU | Direction="up" SA=0x0E80 | PayloadLength=2 SA=0x0E80，Direction="up" 通过（正向用例） | §2.11/§8.6 |
| T113 | 0x0008 SA 与 0x0005 一致 | 0x0005 SA=0x0E80 0x0008 SA=0x0E80 | 通过 | §8.3 |
| T114 | 0x0008 SA 与 0x0005 不一致 | 0x0005 SA=0x0E80 0x0008 SA=0x1111 | Validate 报错 | §8.3 |
| T115 | 0x0007 主动探活插入诊断中 | AliveCheck 在 Messages 中间 | PacketIndex 顺序正确 | §4.5 |
| T116 | 0x0008 应答 0x0007 | AliveCheck.Direction="up" | 紧跟 0x0007 后 | §4.5 |
| T117 | 心跳超时单边 | 0x0007 不带 0x0008 | 仅 0x0007 | §6.14 |
| T118 | FlowID 后缀 :tcp:alive | AliveCheck 非 nil | FlowID 含 :tcp:alive | §5.1 |
| T119 | 0x0007 Direction="up" 拒绝 | Direction="up" | Validate 报错（协议方向固定） | §8.6 |
| T119a | 0x0007 Direction="down" 通过 | Direction="down" | 通过（正向用例，v2.0.1 新增 M5） | §8.6 |
| T120 | 0x0008 Direction="down" 拒绝 | Direction="down" | Validate 报错 | §8.6 |
| T120a | 0x0008 Direction="up" 通过 | Direction="up" | 通过（正向用例，v2.0.1 新增 M5） | §8.6 |

### §7.9 通用 NACK（T121-T130）

| 用例 | 场景 | 输入 | 断言 | 对应 spec 行 |
|---|---|---|---|---|
| T121 | 0x0000 NackCode=0x00 Incorrect Pattern | NackCode=0x00 | 通过 | §2.3 |
| T122 | 0x0000 NackCode=0x01 Unknown Payload Type | NackCode=0x01 | 通过 | §2.3 |
| T123 | 0x0000 NackCode=0x02 Message Too Large | NackCode=0x02 | 通过 | §2.3 |
| T124 | 0x0000 NackCode=0x03 Out of Memory | NackCode=0x03 | 通过 | §2.3 |
| T125 | 0x0000 NackCode=0x04 Invalid Payload Length | NackCode=0x04 | 通过 | §2.3 |
| T126 | 0x0000 NackCode=0x05 Reserved 拒绝 | NackCode=0x05 | Validate 报错 | §2.3 |
| T127 | GenericNack Direction 固定 "down" | Direction="down" | 通过 | §8.6 |
| T128 | GenericNack Direction="up" 拒绝 | Direction="up" | Validate 报错（v2.0.0 M7） | §8.6 |
| T129 | GenericNack 在路由激活后发送 | GenericNack 非 nil | PacketIndex 在 0x0006 后 | §4.7 |
| T130 | 0x0000 PayloadLength=1 | 任意 NackCode | PayloadLength=1 | §2.3 |

### §7.10 IPv6 场景（T131-T140）

| 用例 | 场景 | 输入 | 断言 | 对应 spec 行 |
|---|---|---|---|---|
| T131 | IPv6 Discovery 广播 | SrcIP="fe80::1" Broadcast=true | DstIP=ff02::1 DstMAC=33:33:00:00:00:01 | §3.3 |
| T132 | IPv6 PowerMode 广播 | SrcIP="fe80::1" PowerMode.Broadcast=true | DstIP=ff02::1 DstMAC=33:33:00:00:00:01 | §3.3 |
| T133 | IPv6 单播路由激活 | SrcIP="fe80::1" DstIP="fe80::2" | TCP 连接 IPv6 | §1.5 |
| T134 | IPv6 单播诊断消息 | SrcIP="fe80::1" DstIP="fe80::2" | 0x8001 over IPv6 | §1.5 |
| T135 | IPv6 心跳 | SrcIP="fe80::1" | 0x0007/0x0008 over IPv6 | §1.5 |
| T136 | IPv6 MAC 计算 RFC 2464 §7 | DstIP=ff02::1 | DstMAC=33:33:00:00:00:01（取末 32 位） | §3.3 |
| T137 | IPv6 Entity Status 广播 | SrcIP="fe80::1" | UDP IPv6 | §3.3 |
| T138 | IPv6 全流程端到端 | SrcIP="fe80::1" 全阶段 | 包数 22（同 IPv4） | §6.15 |
| T139 | IPv6 多 ECU | 3 ECU 各 IPv6 | FlowID 3 类独立 | §5.4 |
| T140 | IPv6+V1 拒绝 | PV=0x01 SrcIP="fe80::1" | 通过（V1 也支持 IPv6） | §1.3 |

### §7.11 边界值（T141-T160）

| 用例 | 场景 | 输入 | 断言 | 对应 spec 行 |
|---|---|---|---|---|
| T141 | ProtocolVersion=0x00 拒绝 | PV=0x00 | Validate 报错 | §8.1 |
| T142 | ProtocolVersion=0x03 拒绝 | PV=0x03 | Validate 报错 | §8.1 |
| T143 | ProtocolVersion=0xFF 拒绝 | PV=0xFF | Validate 报错 | §8.1 |
| T144 | InverseProtocolVersion 不匹配 | InvPV≠~PV | Validate 报错 | §2.1/§8.1 |
| T145 | PayloadLength=0 | 0x0001/0x0007/0x4001/0x4003 | 通过 | §2.1 |
| T146 | PayloadLength=0xFFFFFFFF | 0xFFFFFFFF=4GB-1 | 通过（u32 理论边界；本设计不实现单帧 PayloadLength > 65535B 场景，见 §2.1；v2.0.1 重写：原"超 65535 上限"约束不存在） | §2.1/§6.13.7 |
| T147 | MSS=0 拒绝 | TCP.MSS=0 | Validate 报错（H5） | §5.2 |
| T148 | MSS=1460 默认 | TCP.MSS=0 fallback=1460 | 通过（fallback 策略） | §5.2 |
| T149 | UserData=0B | UserData=nil | 0x8001 PayloadLength=4 | §2.13 |
| T150 | UserData=65535B | UserData=65535B | 0x8001 PayloadLength=65539 | §2.13/§6.13.7 |
| T151 | UserData=65536B | UserData=65536B | 通过（PayloadLength=65540 ≤ 4GB-1，v2.0.1 重写：原"超 0x8002 u16 上限"约束不存在） | §6.13.7 |
| T152 | OEM-specific=0B | OEM=nil | PayloadLength=7 (0x0005) | §2.8 |
| T153 | OEM-specific=4B | OEM=0x01020304 | PayloadLength=11 (0x0005) | §2.8 |
| T154 | OEM-specific=255B | OEM=255B | PayloadLength=262 (0x0005) | §2.8 |
| T155 | Direction="" 走默认 | Direction="" | 走 PayloadType 默认 | §1.6/§8.6 |
| T156 | Direction="UP" 大小写不敏感 | Direction="UP" | 等价 "up" | §1.6 |
| T157 | Direction="invalid" 拒绝 | Direction="invalid" | Validate 报错 | §8.6 |
| T158 | LogicalAddress=0x0000 | LA=0x0000 | 通过（边界） | §2.7 |
| T159 | LogicalAddress=0xFFFF | LA=0xFFFF | 通过（边界） | §2.7 |
| T160 | TesterAddress=0x0000 | TA=0x0000 | 通过（边界） | §2.8 |

### §7.12 状态机阶段顺序（T161-T170）

| 用例 | 场景 | 输入 | 断言 | 对应 spec 行 |
|---|---|---|---|---|
| T161 | 完整 5 阶段顺序 | 全阶段 | Discovery→Entity→Activation→Messages→AliveCheck | §4 |
| T162 | 无 Discovery 直接 Activation | Discovery=nil | 直接 TCP 握手+激活 | §4.3 |
| T163 | 无 Activation 直接 Messages | Activation=nil Messages 非 nil | Validate 报错（必须先激活） | §4.4 |
| T164 | Activation 失败跳过 Messages | RC=0x00 | 无 Messages 包 | §9.2 |
| T165 | AliveCheck 插入 Messages 中间 | AliveCheck 在 Messages[2] 后 | PacketIndex 顺序正确 | §4.5 |
| T166 | PowerMode 在 TCP 挥手后 | PowerMode 非 nil | UDP PowerMode 在 TCP FIN 后 | §4.6 |
| T167 | GenericNack 在 Activation 后 | GenericNack 非 nil | NACK 在 0x0006 后 | §4.7 |
| T168 | 多 ECU 各自完整流程 | 3 ECU | 3×22=66 包 | §5.4 |
| T169 | GroupID 路由同 worker | 同 ECU UDP+TCP 同 GroupID | 同 PacketWorker | §5.4 |
| T170 | FlowID 后缀区分 | 全阶段 | :udp:disc / :udp:entity / :tcp:act / :tcp:diag / :tcp:alive / :udp:power | §5.1 |

### §7.13 集成测试（T171-T185）

| 用例 | 场景 | 输入 | 断言 | 对应 spec 行 |
|---|---|---|---|---|
| T171 | 单 ECU 端到端 | 全阶段 | 22 包，阶段顺序正确 | §6.15 |
| T172 | 多 ECU 端到端 | 8 ECU | 8×22=176 包，各 ECU 独立 | §5.4 |
| T173 | ctx 取消中断 | ctx.Cancel() | 已生成包正常输出，后续包停止 | §9.2 |
| T174 | PacketWorkers=8 并发 | PacketWorkers=8 | -race clean，总包数正确 | §5.4 |
| T175 | PacketWorkers=8 阶段顺序 | PacketWorkers=8 | 每 ECU 阶段顺序严格 | §5.4 |
| T176 | PacketWorkers=8 FlowID 后缀 | PacketWorkers=8 | :udp:disc / :udp:power 不冲突 | §5.1 |
| T177 | IPv6 全流程端到端 | SrcIP="fe80::1" | 22 包 IPv6 | §6.12/§6.15 |
| T178 | IPv6 PowerMode 广播 | SrcIP="fe80::1" Broadcast=true | DstIP=ff02::1 | §3.3 |
| T179 | IPv6 Discovery+TCP+PowerMode | 全阶段 IPv6 | 包数 22 | §6.15 |
| T180 | 多 ECU IPv6 混合 | 3 ECU IPv6 | FlowID 3 类独立 | §5.4 |
| T181 | 二次确认流程端到端 | RC=0x11 ConfirmationRequired=true | 0x0005×2+0x0006×2 | §4.3 |
| T182 | 路由激活失败端到端 | RC=0x00 | TCP FIN，无诊断 | §9.2 |
| T183 | Entity Status 端到端 | EntityStatus 非 nil | 0x4001+0x4002 | §4.2 |
| T184 | 大文件 TransferData | 0x34+0x36×N+0x37 | MSS 分段正确 | §5.2 |
| T185 | 0x8003 Nack 端到端 | NackCode=0x02 | 0x8001+0x8003 | §4.4 |

### §7.14 错误处理（T186-T200）

| 用例 | 场景 | 输入 | 断言 | 对应 spec 行 |
|---|---|---|---|---|
| T186 | InverseProtocolVersion 不匹配 | InvPV=0x00 | Validate 报错 | §8.1 |
| T187 | 0x0000 NackCode 越界 | NackCode=0xFF | Validate 报错 | §8.2 |
| T188 | 0x8002 AckCode 越界 | AckCode=0x01 | Validate 报错 | §8.2 |
| T189 | 0x8001 SA=0x0000 | SA=0x0000 | 通过（边界） | §2.13 |
| T190 | 0x8001 TA=0xFFFF | TA=0xFFFF | 通过（边界） | §2.13 |
| T191 | UDS 未知 SID | ServiceID=0xFF | Validate 报错 | §8.2 |
| T192 | UDS HasSubFunction=true + 0x22 | ServiceID=0x22 HasSubFunction=true | Validate 报错（M8） | §8.4 |
| T193 | UDS HasSubFunction=false + 0x10 | ServiceID=0x10 HasSubFunction=false SubFunction=0x03 | 仍输出 sub-function=0x03（M8） | §8.4 |
| T194 | Announcement 间隔由 Pacer 控制 | AnnouncementCount=3 | Timestamp 连续，间隔由 Pacer | §4.1/§5.3 |
| T195 | TCP 中断 Termination=false | Termination=false | 无 FIN | §6.14 |
| T196 | TCP 中断 Termination=true | Termination=true | 有 FIN | §6.14 |
| T197 | 0x8001 UserData 大小超 MaxDataSize | UserData=5000 MaxDataSize=4095 | Validate 报错 | §6.13.6/§8.3 |
| T198 | 0x0004 公告 EID 与 spec.DstMAC 一致 | DstMAC="00:11:22:33:44:55" | 0x0004 EID=00:11:22:33:44:55 | §3.2 |
| T199 | 多 ECU VIN 唯一 | 3 ECU VIN 各异 | VIN 互不冲突 | §5.4 |
| T200 | 完整诊断流程总包数 | 全阶段单 ECU | 22 包 | §6.15 |

---

## §8. Validate 规则

### §8.1 协议版本

- `ProtocolVersion` ∈ {0x01, 0x02}；0x00/0x03/0x04-0xFE 拒绝。
- `InverseProtocolVersion` 必须等于 `~ProtocolVersion & 0xFF`；不匹配拒绝。
- V1 模式（PV=0x01）：0x0005 PayloadLength=7（N=0）、0x0006 PayloadLength=9（N=0）、0x8002/0x8003 与 V2 格式相同（5+M，无独立长度字段，v2.0.1 修复）、不支持 0x4003/0x4004。
- V1 + OEM-specific 非 nil → 拒绝。
- V1 + PowerMode 非 nil → 拒绝（**本设计选择，非 ISO 要求**，v2.0.1 注明；scapy/python-doipclient 均无该限制，仅因本设计 V1 定位为最小兼容子集）。

### §8.2 字段值范围

- `ActivationType` ∈ {0x00, 0x01, 0xE0..0xFF}；0x02..0xDF 拒绝。
- `ResponseCode`（0x0006）∈ {0x00..0x07, 0x10, 0x11}；0x08..0x0F/0x12..0xFF 拒绝。
- `FurtherActionRequired` ∈ {0x00, 0x10}；其余拒绝（v2.0.0 C4）。
- `SyncStatus` ∈ {0x00, 0x10}；0x01..0x0F/0x11..0xFF 拒绝（v2.0.0 C5）。
- `DiagnosticPowerMode` ∈ {0x00, 0x01, 0x02}；0x03..0xFF 拒绝（v2.0.0 H4）。
- `NodeType` ∈ {0x00, 0x01}；0x02..0xFF 拒绝。
- `0x0000 NackCode` ∈ {0x00..0x04}；0x05..0xFF 拒绝。
- `0x8002 AckCode` = 0x00；非 0x00 拒绝。
- `0x8003 NackCode` ∈ {0x02..0x08}；0x00/0x01/0x09..0xFF 拒绝（v2.0.0 C2）。
- `UDS NRC` ∈ {0x01..0x7F}；0x00/0x80..0xFF 拒绝（H6）。
- `UDS ServiceID` ∈ {0x10, 0x11, 0x22, 0x27, 0x2E, 0x31, 0x34, 0x36, 0x37, 0x3E}；其余拒绝。

### §8.3 一致性校验

- 0x8001 SA = 0x0005 SourceAddress（请求方向）；TA = 0x0006 ServerLogicalAddress（请求方向）。
- 0x8002/0x8003 SA = 被确认 0x8001 TA；TA = 被确认 0x8001 SA。
- 0x8008 SA = 0x0005 SourceAddress。
- 0x0006 ClientLogicalAddress = 0x0005 SourceAddress。
- 0x0006 ServerLogicalAddress = 0x0004 LogicalAddress（若 Discovery 存在）。
- EntityStatus.CurOpenSockets ≤ MaxOpenSockets（逻辑校验）。
- 0x8001 UserData 长度 ≤ EntityStatus.MaxDataSize（若 EntityStatus 存在）。
- 0x8002/0x8003 PreviousDiagnosticMessage 长度 = 被确认 0x8001 UserData 长度（由 PayloadLength-5 隐式推导，无独立长度字段，v2.0.1 修复）。

### §8.4 UDS 服务校验

- ServiceID ∈ {0x10, 0x11, 0x27, 0x31, 0x3E}（有 sub-function 服务）：HasSubFunction=true 或 nil 时输出 sub-function 字节；HasSubFunction=false 时仍输出（sub-function 是必需字段）。
- ServiceID ∈ {0x22, 0x2E, 0x34, 0x36, 0x37}（无 sub-function 服务）：HasSubFunction=true → Validate 报错（M8）。
- ServiceID=0x27 SubFunction 奇数 = 请求 seed（IsResponse=true 时 Seed 字段非空）；偶数 = 发送 key（IsResponse=false 时 Key 字段非空）。
- ServiceID=0x27 偶数 + IsResponse=true + Key 非空 → Validate 报错（H3）。
- ServiceID=0x36 BlockSequenceCounter 公式 = n%256（n=1→0x01, n=255→0xFF, n=256→0x00, n=257→0x01，M3 修复）。
- UDS NegativeResponseCode 非 0 → 生成否定响应 `7F <Request SID> <NRC>`（NRC 优先于 IsResponse，M1 修复）。

### §8.5 边界与上限

- 0x8001 UserData 长度 ≤ EntityStatus.MaxDataSize（若 EntityStatus 存在，v2.0.1 重写：原"受 0x8002 PrevLen u16 上限约束"不成立，该字段不存在）。
- 0x8001 UserData 长度 ≤ PayloadLength u32 上限 - 4 = 4GB-5（理论边界，实际受 TCP MSS 与 MaxDataSize 约束，v2.0.1 重写）。
- 0x8002/0x8003 PreviousDiagnosticMessage 长度 = 被确认 0x8001 UserData 长度（PayloadLength = 5 + M ≤ 4GB-1）。
- 0x36 TransferData Data 长度 ≤ 单帧 0x8001 UserData 上限 - 2B（SID + BlockSeq）；UserData 上限优先受 MaxDataSize 约束（v2.0.1 重写：0x36 Data 无独立 ISO 上限，不依赖 PrevLen u16）。
- TCP.MSS > 0；MSS=0 → Validate 报错或 fallback 1460（H5）。
- EID 长度 = 6B；VIN 长度 = 17B ASCII；GID 长度 = 6B。
- OEM-specific 长度任意（0B/4B/任意 B 均合法，V1 强制 0B），上限受 0x0005/0x0006 PayloadLength u32 上限约束（OEM ≤ 4GB-1-7 / 4GB-1-9），不受任何 u16 字段宽度约束（v2.0.1 修复 H3）。

### §8.6 Direction 校验

- Direction ∈ {"", "up", "down"}（大小写不敏感）。
- Direction="" → 走 PayloadType 默认方向。
- Direction="invalid" → Validate 报错（M9）。
- 0x0007 Direction 必须为 "down"（ECU→Tester 协议固定）。
- 0x0008 Direction 必须为 "up"。
- 0x0000 Direction 固定 "down"（v2.0.0 M7，删除 "up" fuzzing 选项）。

---

## §9. 错误处理

### §9.1 Validate 错误返回

Validate 失败时返回 `error`，包含字段名与失败原因。Planner 不生成 PacketConfig。

### §9.2 Plan 时错误

- 路由激活失败（ResponseCode=0x00..0x07）：Planner 生成 0x0005+0x0006+TCP FIN，跳过 Messages/AliveCheck 阶段。
- ctx 取消：Planner 已生成包正常输出，后续包停止。
- MSS 分段失败：Planner 报错或 fallback 1460（由调用方策略决定）。

### §9.3 与其他协议互斥

DoIP 与 SOCKS5/RTSP/FTP/SIP/GBT32960/JT808/MCP/TDS/Modbus/ENIP 等同栈协议互斥：同一 FlowSpec 仅能配置一个协议子结构（DoIP/SOCKS5/RTSP/...）。Validate 检测到多个协议子结构非 nil → 报错。

### §9.4 IPv6 处理

- spec.SrcIP 含 ":" → IPv6 模式。
- Discovery.Broadcast=true → DstIP=ff02::1, DstMAC=33:33:00:00:00:01。
- PowerMode.Broadcast=true → 同上。
- 单播 IPv6 → DstIP=spec.DstIP, DstMAC 由 spec.DstMAC 指定。

### §9.5 集成点

- core.mapToFlowSpec：将 DoIPSpec 转换为内部 PacketConfig 序列。
- worker.Pacer：控制 500ms±100ms 公告间隔（Planner 不注入时间戳）。
- pcap-replay：解析 DoIP 报文时按 §2 字段宽度逐字节解码；0x8002/0x8003 无独立长度字段，PreviousDiagnosticMessage 取 Payload 剩余字节（偏移 13 起，v2.0.1 修复）。

### §9.6 端口 3496（TLS DoIP）

本设计不实现 TLS DoIP（端口 3496），留作后续扩展。若未来支持：
- spec.TLSEnabled=true → TCP DstPort=3496，TCP 层后追加 TLS 握手层。
- ResponseCode=0x07（TLS Required）→ Planner 自动切换到 3496 端口重试（scapy `_activate_routing` 行为）。

### §9.7 风险与约束（R1-R12）

- R1: V1/V2 兼容性：V1 与 V2 报文格式不兼容，混用产生 malformed；Validate 严格按 PV 选择字段宽度。
- R2: 0x8001 UserData 上限受 0x4002 MaxDataSize 约束（若 EntityStatus 存在）与 PayloadLength u32 上限约束；0x8002/0x8003 无独立长度字段，PrevDiag 长度由 PayloadLength-5 隐式推导（v2.0.1 修复）。
- R3: 0x36 BlockSeq 回绕公式 n%256（不是 (n-1)%256）。
- R4: UDS 否定响应 SID = 请求 SID（不是响应 SID）。
- R5: 0x8003 NackCode 合法值 0x02-0x08；0x00/0x01/0x09-0xFF 为 Reserved（v2.0.1 措辞简化）。
- R6: 0x0006 ResponseCode Success=0x10（不是 0x00）。
- R7: InverseProtocolVersion 不暴露为 Config 字段，由 Planner 自动计算（设计意图，非风险）。
- R8: 0x8002/0x8003 PreviousDiagnosticMessage = 完整 UserData（不分段前的原始字节）。
- R9: Announcement 间隔由 Pacer 控制，Planner 仅生成 3 条 PacketConfig。
- R10: GenericNack Direction 固定 "down"（删除 "up" fuzzing 选项）。
- R11: 0x27 偶数响应不应包含 Key 字节（H3）。
- R12: 0x4002 MaxDataSize 用于约束 0x8001 UserData 上限（若 EntityStatus 存在）。

---

## §10. 扩展字段映射

见 §1.4 扩展表 5 字段映射表。新增 EntityStatus 字段（NodeType/MaxOpenSockets/CurOpenSockets/MaxDataSize）映射到扩展表 5 的 nodeType/maxOpenSockets/curOpenSockets/maxDataSize 字段。

### §10.1 UDS 字节级序列化对照表（附录 B）

| SID | 服务名 | 请求字节 | 默认正向响应字节 | 参数位置 |
|---|---|---|---|---|
| 0x10 | DiagnosticSessionControl | `10 <sub>` | `50 <sub> <P2> <P2*>` | sub=0x01/0x02/0x03；P2/P2*=2B each（会话参数） |
| 0x11 | ECUReset | `11 <sub>` | `51 <sub>` | sub=0x01/0x02/0x03 |
| 0x22 | ReadDataByIdentifier | `22 <DID>...` | `62 <DID> <data>...` | DID=2B，可多个 |
| 0x27 | SecurityAccess | `27 <sub>` (奇数) / `27 <sub> <key>` (偶数) | `67 <sub>` (奇数应答带 seed) / `67 <sub>` (偶数应答无 key) | sub=0x01..0x7F；seed/key 长度由 ECU 决定 |
| 0x2E | WriteDataByIdentifier | `2E <DID> <data>...` | `6E <DID>` | DID=2B |
| 0x31 | RoutineControl | `31 <sub> <RID> <data>...` | `71 <sub> <RID> <data>...` | RID=2B |
| 0x34 | RequestDownload | `34 <dataFmt> <addrLenFmt> <addr> <size>` | `74 <dataFmt> <maxBlockLen>` | addrLenFmt 高 4 位=addr 长度，低 4 位=size 长度；长度取值（ISO 14229-1 §11.4.3.3）：0x1=1B，0x2=2B，0x4=4B，0x8=8B（v2.0.1 补全）；例：0x44 → addr 4B + size 4B |
| 0x36 | TransferData | `36 <blockSeq> <data>...` | `76 <blockSeq> <data>...` | blockSeq=n%256 |
| 0x37 | RequestTransferExit | `37` | `77` | 无参数 |
| 0x3E | TesterPresent | `3E <sub>` | `7E <sub>` | sub=0x00/0x80 |

### §10.2 缩写表

| 缩写 | 全称 | 中文 |
|---|---|---|
| DoIP | Diagnostic over IP | 基于 IP 的诊断 |
| UDS | Unified Diagnostic Services | 统一诊断服务 |
| ECU | Electronic Control Unit | 电子控制单元 |
| Tester | — | 诊断仪（诊断工具） |
| VIN | Vehicle Identification Number | 车辆识别码 |
| DTC | Diagnostic Trouble Code | 故障码 |
| DID | Data Identifier | 数据标识 |
| NRC | Negative Response Code | 否定响应码 |
| SA | Source Address | 源地址 |
| TA | Target Address | 目标地址 |
| LA | Logical Address | 逻辑地址 |
| EID | Entity Identifier | 实体标识 |
| GID | Group Identifier | 组标识 |
| SLA | Server Logical Address | 服务器逻辑地址 |
| CLA | Client Logical Address | 客户端逻辑地址 |
| FAR | Further Action Required | 后续动作要求 |
| MSS | Maximum Segment Size | 最大分段长度 |
| WWH-OBD | World Wide Harmonized On-Board Diagnostics | 全球协调车载诊断 |
| TLS | Transport Layer Security | 传输层安全 |
| TCP | Transmission Control Protocol | 传输控制协议 |
| UDP | User Datagram Protocol | 用户数据报协议 |
| IP | Internet Protocol | 网际协议 |
| ISO | International Organization for Standardization | 国际标准化组织 |
| RFC | Request for Comments | 征求意见稿（IETF 标准文档） |

---

## §11. 修订记录

### §11.0 v3.0.0（2026-09-26，P-PIPE `doip_tcp_activation_basic`–`doip_tcp_activation_oem_varlen` 补足；编号补位不重排下行）

本次只**新增** §12–§19（`doip_tcp_activation_basic` 规范矩阵 / 三路对照与候选方案 / 门1 十四行表 / D-DOIP-1 / 性能设计与验收 / `doip_tcp_activation_oem_varlen` 对接清单 / 存量 115 例审计 / 缺口 9 项），**§1–§10 协议正文与 §11.1–§11.4 历史修订记录逐字保留**（已核对：无删除、无改写）。口径变化两点：①「存量用例数」由历史 203 条口径改为以机器契约 `cases/doip.json`（115 例）为审计基线；②新增「目标形状 = 纯 layers」基线（CORE_MEMORY §1），v2.0.1 的顶层扁平 `spec_json` 写法在 §14.1 逐键给出去向并标注「今天跑不通，需先补代码」（§1.9）。

### §11.1 v2.0.1（2026-08-05）

基于 R1 复审报告 `docs/protocol-designs/audit/05-doip-audit-r1-v2.md`（17 项问题：3 CRITICAL + 4 HIGH + 6 MEDIUM + 4 LOW）全面返工：

**CRITICAL 修复（3 项）**：
- C1: **0x8002/0x8003 删除凭空添加的 PreviousDiagnosticMessageLength 字段**。ISO 13400-2:2019 §10.4.3/§10.4.5 与 scapy（XStrField 无 Len 字段）、Wireshark（tvb 剩余字节动态计算）、python-doipclient（`!HHB` + `payload_bytes[5:]`）四方确认该位置无长度字段，PreviousDiagnosticMessage 为变长尾部，PayloadLength = 5 + M（V1/V2 相同）。同步修正 §1.3/§1.5/§2.14/§2.15/§3.1/§4.4/§6.3/§6.4/§6.13.5-8/§7.4（T017/T018/T053/T054/T063-T068）/§8.1/§8.3/§8.5/§9.5/§9.7 约 15 处
- C2: §6.3 S3 / §6.10 S10 HexDump "修正"注释清理（同一 HexDump 修正前后两版并存，实现者无法判断采用哪个）；S4 0x8001 PayloadLength 0x08→0x07（2+2+3=7 手算错误）
- C3: §6.13.7/§6.13.8 与 T066/T067/T068 边界值统一重写：UserData 上限 = MaxDataSize（若 EntityStatus 存在）+ PayloadLength u32 理论上限 4GB-1（建立在已删除的 PrevLen u16 之上的旧上限逻辑全部移除）

**HIGH 修复（4 项）**：
- H1: S10 0x34 HexDump 补全 size 字段 4B（UserData 7B→11B），PayloadLength 0x0B→0x0F=15，与 T041 一致
- H2: S3 0x8002 HexDump 随 C1 重写（9B→7B，PayloadLength 0x09→0x07）
- H3: §6.13.23 注明 OEM-specific 不受 PrevLen u16 约束；§8.5 新增 OEM-specific 上限（≤ PayloadLength u32 上限 - 7/9）
- H4: T067 随 C3 重写（UserData=65536B 通过，PayloadLength=65540 ≤ 4GB-1）

**MEDIUM 修复（6 项）**：
- M1: §4.3 二次确认流程新增子阶段 4'（RC=0x05 拒绝 → TCP FIN）；新增 T027a
- M2: §6.13.5/§6.13.6 PrevLen u16 上限假设随 C1 删除，重写为 MaxDataSize 边界
- M3: §9.7 R5 措辞改为 "0x8003 NackCode 合法值 0x02-0x08；0x00/0x01/0x09-0xFF Reserved"
- M4: §7 全部 200 条用例表新增"对应 spec 行"列（含新增 T027a/T119a/T120a 共 203 条）
- M5: T111/T112 补 Direction 正向断言，新增 T119a（0x0007 down 通过）/T120a（0x0008 up 通过）
- M6: §1.3/§8.1/T110 注明 V1+PowerMode 拒绝为"本设计选择，非 ISO 要求"（scapy/python-doipclient 均无该限制）

**LOW 修复（4 项）**：
- L1: 文档总行数声明更正（约 1050 → 实际约 1500 行）
- L2: §10.2 缩写表补 Tester/TCP/UDP/IP/ISO/RFC 条目
- L3: §3.1 各 Direction 字段注释改为"见 §1.6"（消除重复说明）
- L4: 附录 B 0x34 参数位置补 addr/size 长度取值（0x1=1B/0x2=2B/0x4=4B/0x8=8B）

**测试用例扩展**：v2.0.0 的 200 条 → v2.0.1 的 203 条（新增 T027a/T119a/T120a）。

### §11.2 v2.0.0（2026-08-05，已被 v2.0.1 替代）

基于 v1.2 深度对抗审计报告（26 项问题）全面返工：

**CRITICAL 修复（5 项）**：
- C1: 0x0006 ResponseCode 枚举整体偏移 +0x10（Success 0x00→0x10）
- C2: 0x8003 NackCode 0x00/0x01 改为 Reserved，0x02=Invalid SA，0x06=Target Unreachable
- C3: 新增 0x4001/0x4002 DoIP Entity Status PayloadType（§2.11a/§3.1/§4.2/§6.7/§7.6）
- C4: 0x0004 FurtherActionRequired 仅 0x00/0x10 合法，删除凭空添加的 0x11/0x20/0x40
- C5: 0x0004 VIN/GID SyncStatus 0x00=Synchronized, 0x10=NOT synchronized（0x01 改为 Reserved）
- C6: 新增 T46-T48/T131-T140 IPv6 全流程集成测试

**HIGH 修复（7 项）**：
- H1: 0x0005/0x0006 OEM-specific 改为变长 N B（默认 0B）
- H2: 0x8002 PrevDiagMsgLen V2=u16/V1=u32；0x36 Data 上限 65531B 独立断言
- H3: UDS 0x27 偶数响应不应包含 Key；T037 Validate 报错
- H4: DiagnosticPowerMode 0x02=Not Supported（不是 Reserved）
- H5: TCP MSS=0 → Validate 报错或 fallback 1460（T147/T148）
- H6: UDS NRC 仅 0x01..0x7F 合法（T047/T048/T049）
- H7: 0x0006 ResponseCode=0x11 Confirmation Required 新增二次确认流程（T021f/T027/T181）

**MEDIUM 修复（9 项）**：
- M1: UDS 否定响应 SID = 请求 SID（T045/T046）
- M2: T175/T176 并发测试补阶段顺序与 FlowID 后缀断言
- M3: 0x36 BlockSeq 公式 n%256（不是 (n-1)%256）
- M4: Announcement 间隔由 Pacer 控制（T194）
- M5: ActivationType=0x01 术语改为 WWH-OBD（不是 WWH-DOIP）
- M6: EID fallback 测试 T084/T085/T086
- M7: GenericNack Direction 固定 "down"（删除 "up" fuzzing，T128）
- M8: UDS HasSubFunction Validate 规则（T192/T193）
- M9: 0x8001 SA/TA 与 0x0005/0x0006 一致性校验（T029/T030）

**LOW 修复（5 项）**：
- L1: §1.2 端口 3496（TLS DoIP）提及
- L2: R7 改为"设计意图，非风险"
- L3: 附录 B 新增"参数位置"列
- L4: §3.3 IPv6 MAC RFC 2464 §7 引用统一
- L5: §1.6 方向约定（up/down 中文）

**测试用例扩展**：v1.2 的 72 条 → v2.0.0 的 200 条（T001-T200），覆盖所有 PayloadType（含新增 0x4001/0x4002）、所有 ResponseCode/NackCode 合法值、IPv6 全流程、Entity Status、二次确认、MSS=0、NRC 边界、HasSubFunction Validate、Direction 空值等场景。

**HexDump 场景**：15 个（S1-S15），覆盖车辆发现/路由激活/诊断消息/诊断确认/心跳/否定确认/Entity Status/一般否定确认/多会话/多流关联/错误处理/IPv6 全流程/边界值/超时/完整诊断流程。

### §11.3 v1.2（2026-08-03，已被 v2.0.1 替代）

v1.0/v1.1 修复 39 项审计问题，但深度对抗审计发现 26 项新问题（5 CRITICAL + 7 HIGH + 9 MEDIUM + 5 LOW），不可直接进入实现阶段。

### §11.4 v1.0（2026-08-03，已被 v1.2 替代）

初版，存在 ResponseCode/NackCode 枚举错误、缺失 0x4001/0x4002、OEM-specific 写死 4B 等问题。

---

## §12. `doip_tcp_activation_basic` 规范矩阵（CORE_MEMORY §4 八项：规范要求 → 业务场景 → 代码现状 → 缺口）

> 本节由 P-PIPE 文档轨（#57 doip）补足。全部「代码现状」为**实读行号**（本仓库 HEAD `0c355be`）。
> 目标形状基线（CORE_MEMORY §1）：**纯 layers 链**，顶层只允许 `layers`/`flow_control` 家族/`output`（§1.11）。

### §12.1 八项规范矩阵

| # | 规范要求（出处） | 业务场景 | 代码现状（实读） | 缺口 |
|---|---|---|---|---|
| 4.1 | **连接模型**：TCP 13400 承载路由激活/诊断/探活/通用 NACK（每 ECU 一条独立 4-tuple）；UDP 13400 承载车辆发现/实体状态/电源模式；Tester 主动建连（0x0005），ECU 可主动探活（0x0007）（ISO 13400-2:2019 §7，本文 §1.2） | 诊断仪接车→发现车辆→激活路由→读 DTC/刷写；ECU 独立应答 | 双载体实现完整：UDP 三阶段 `doip.go:454-574`；TCP 握手 `doip.go:583-599`、挥手 `doip.go:773-791`。**链上单载体**：`registry.go:224-226` 注册 `CategoryTerminal` + `DependsOn ["tcp"]`（无 `TransportOn`/`OptionalOn`）；生成器 `layer_gen.go:61-74` 对 `Discovery`/`EntityStatus`/`PowerMode` 逐个显式拒绝；`[ip,udp,doip]` 由 `complete.go:447-460` 判死（锚词 `carrier`） | **G-DOIP-2** |
| 4.2 | **命令/消息表**：16 个 PayloadType（0x0000–0x8003），逐条请求—响应配对与必选/可选字段（本文 §2.2–§2.16） | 发现请求↔公告；激活请求↔激活应答；诊断消息↔Ack/Nack；探活↔探活应答 | 16 型常量表 `types.go:80-97`；`build*` 纯函数逐字段装配 `doip.go:864-955`。**链上可达 8 型**（0x0000/0x0005/0x0006/0x0007/0x0008/0x8001/0x8002/0x8003），UDP 8 型（0x0001–0x0004、0x4001–0x4004）不可达 | **G-DOIP-2** |
| 4.3 | **状态机**：建连→激活→业务（诊断/探活）→释放；激活失败（RC 0x00–0x07）→ECU FIN 提前终止（本文 §4、§6.11、§9.2） | 正常诊断流程；激活被拒后连接关闭；二次确认（0x11）后终态 | 七阶段状态机 `doip.go:577-791`（含失败 FIN+ACK `doip.go:636-645`）。链上 `layer_gen.go:112-245` 只产报文事件，握手/挥手/seq 归 tcp 层；**失败路径显式拒绝**（生成器 `layer_gen.go:148-150`、校验器 `layer_gen.go:297-306`） | **G-DOIP-3**；**G-DOIP-4**（`doip.go:618-623` 注释自认二次确认被拒不可表达） |
| 4.4 | **字段表**：每字段宽度/字节序/取值/默认值（本文 §2.1–§2.16、§3.2 默认值表） | 报文字段逐字节可复算；V1/V2 宽度差异 | 常量表 `types.go:28-77`（含 `DoIPHeaderLen=8`/`VINLength=17`/`EIDLength=6`/`GIDLength=6`/`DefaultMSS=1460`/`MinMSS=536`）；`buildVehicleAnnouncement` `doip.go:865-891`（V1 去 SyncStatus 在 `:887-889`）；解析侧 `parser.go:23-51` | 无（TCP 面字段全量）；V1 面同 §4.8 |
| 4.5 | **错误处理表**：0x0000 NackCode 5 值、0x0006 ResponseCode 13 值、0x8003 NackCode 7 值、UDS NRC 0x01–0x7F（本文 §2.3/§2.9/§2.15/§2.16/§8/§9） | 头部错、激活被拒、诊断消息被拒、UDS 否定响应 | 值域校验全量 `doip.go:26-232`（`validateUDS` `:235-268`）；解析错误面 `parser.go:26-51`；链上校验器 `layer_gen.go:274-321`（拒绝路径改判为错误） | **G-DOIP-3**（拒绝码不可发出）；用例面见 §18 |
| 4.6 | **超时与活性**：0x0007/0x0008 探活；公告 500ms±100ms×3（ISO 13400-2:2019 §8.5.1）；超时单边报文（本文 §4.1/§4.5/§6.14） | ECU 主动探活保活；车辆上电公告 | 探活 `doip.go:743-764`；公告计数 `doip.go:507-514`（`DefaultAnnouncementCount=3`，时间由 worker Pacer）；超时单边 §6.14 | **G-DOIP-2**（公告属 UDP）；超时单边在链上归 tcp 层 `termination`，标「明确不解决」 |
| 4.7 | **NAT/代理/被动模式**：规范无 FTP 式被动模式；发现支持广播/单播（IPv4 `255.255.255.255`、IPv6 `ff02::1` + MAC `33:33:00:00:00:01`，RFC 2464 §7）；Tester 侧 ephemeral 端口对 ECU 固定 13400（本文 §3.3） | 诊断仪跨网段接入；同网段广播发现 | 广播改写 `doip.go:473-482`（发现）与 `:554-563`（电源模式）；组播 MAC `types.go:149-157` | **G-DOIP-2**（广播面属 UDP）；NAT 现网行为无实测证据 → **G-DOIP-9** |
| 4.8 | **版本/方言差异**：V1(0x01)/V2(0x02) 双版本；V1 差异 = 0x0004 无 SyncStatus（32B vs 33B）、0x0005/0x0006 禁 OEM、无 0x4003/0x4004（本文 §1.3/§8.1） | 旧 ECU 兼容；新 ECU 全功能 | V1 限制 `doip.go:52-59`；默认 `DefaultProtocolVersion=0x02` `types.go:31`；`ProtocolVersionV1=0x01` `types.go:34`；0x03/0x04（ISO13400_2019/AMD1）当前不接受（§1.3 已声明） | V1 键在链上无住处（**G-DOIP-1**）；0x03/0x04 标「明确不支持」 |

**三路对照（§4.12–4.15）与候选方案对比（§4.17）见 §13**；八项逐行去向见 §18.4 台账。

### §12.2 子表①：PayloadType × 链上终态矩阵（16 格，每格给结论，不留白）

> 本节用例落点一律写**完整 ID**（`doip_tcp_*`/`doip_neg_*`，正文索引在 `05-doip-testcase.md` §2；#1–#16 正、#17–#41 负）。

| PayloadType | 名称 | 规范载体 | 链上可达性（实读结论） | 用例落点 / 去向 |
|---|---|---|---|---|
| 0x0000 | Generic DoIP Header NACK | TCP/UDP | 可达（down 固定，`layer_gen.go:240-243`） | **`doip_tcp_generic_nack`** |
| 0x0001 | Vehicle Identification Request | UDP | 不可达（`layer_gen.go:62-64` 拒 `discovery`） | **G-DOIP-2** 立项 |
| 0x0002 | Vehicle Identification Request with EID | UDP | 不可达（同上） | **G-DOIP-2** |
| 0x0003 | Vehicle Identification Request with VIN | UDP | 不可达（同上） | **G-DOIP-2** |
| 0x0004 | Vehicle Announcement / Identification Response | UDP | 不可达（同上） | **G-DOIP-2** |
| 0x0005 | Routing Activation Request | TCP | 可达（`layer_gen.go:123-126`） | **`doip_tcp_activation_basic`/`doip_tcp_activation_confirmation`/`doip_tcp_activation_oem_varlen`** |
| 0x0006 | Routing Activation Response | TCP | 部分可达：RC=0x10 与 0x11+确认可达；RC=0x00–0x07、0x11 无确认被 `layer_gen.go:297-306` 拒 | **`doip_tcp_activation_basic`/`doip_tcp_activation_confirmation`** 已覆；拒绝码 → **G-DOIP-3** |
| 0x0007 | Alive Check Request | TCP | 可达（down，`layer_gen.go:224-227`） | **`doip_tcp_alive_check`** |
| 0x0008 | Alive Check Response | TCP | 可达（up，`layer_gen.go:228-236`） | **`doip_tcp_alive_check`** |
| 0x4001 | DoIP Entity Status Request | UDP | 不可达（`layer_gen.go:65-67` 拒 `entity_status`） | **G-DOIP-2** |
| 0x4002 | DoIP Entity Status Response | UDP | 不可达（同上） | **G-DOIP-2** |
| 0x4003 | Diagnostic Power Mode Request | UDP | 不可达（`layer_gen.go:68-70` 拒 `power_mode`） | **G-DOIP-2** |
| 0x4004 | Diagnostic Power Mode Response | UDP | 不可达（同上） | **G-DOIP-2** |
| 0x8001 | Diagnostic Message | TCP | 可达（`layer_gen.go:198-201`，含 0x36 协议级分段 `:177-194`） | **`doip_tcp_diag_uds_session_control`…`doip_tcp_diag_nack`** |
| 0x8002 | Diagnostic Message Ack | TCP | 可达（`NackCode==nil` 分支 `:205-208`） | **`doip_tcp_diag_ack`** |
| 0x8003 | Diagnostic Message Nack | TCP | 可达（`NackCode!=nil` 分支 `:209-212`，值域 0x02–0x08） | **`doip_tcp_diag_nack`** |

### §12.3 子表②：数据形态变体表（协议相关全部形态逐项）

| # | 形态 | 规范依据 | 现状/覆盖 | 去向 |
|---|---|---|---|---|
| R1 | 协议版本双态 V1(0x01)/V2(0x02) | §1.3/§8.1 | `types.go:31/34`，`doip.go:43-49` | 已覆（`doip_tcp_activation_basic`/`doip_tcp_activation_v1`） |
| R2 | InverseProtocolVersion = ~PV & 0xFF，不匹配拒 | §2.1/§8.1 | `types.go:133`；解析侧 `parser.go:31-34` | 已覆（`doip_tcp_activation_basic` frames + N-负例不可达→装配期自检） |
| R3 | 0x0004 公告 payload 33B(V2)/32B(V1) | §2.7 | `doip.go:887-889` | **G-DOIP-2**（UDP） |
| R4 | OEM-specific 变长 0B/4B/255B | §2.8/§2.9（H1 修复） | `doip.go:904-926` | 已覆（`doip_tcp_activation_oem_varlen`） |
| R5 | ResponseCode 合法值域 0x00–0x07/0x10/0x11 校验 | §2.9/§8.2 | `doip.go:129-133` | 已覆（`doip_neg_response_code_reserved`） |
| R6 | ResponseCode 拒绝码 0x00–0x07 **发出** | §4.3/§9.2 | 链上拒（`layer_gen.go:148-150`） | **G-DOIP-3** |
| R7 | 0x11 二次确认四包序 | §4.3 子阶段 | `doip.go:624-631`；`layer_gen.go:134-145` | 已覆（`doip_tcp_activation_confirmation`） |
| R8 | 0x11 二次确认被拒（最终 RC=0x05） | §4.3 子阶段 4' | **schema 不可表达**（`doip.go:618-623`） | **G-DOIP-4** |
| R9 | ActivationType 值域 0x00/0x01/0xE0–0xFF | §2.8/§8.2 | `doip.go:124-128` | 已覆（`doip_neg_activation_type_reserved`） |
| R10 | 0x8003 NackCode 0x02–0x08 七值 | §2.15/§8.2 | `doip.go:163-168` | 已覆（`doip_tcp_diag_nack`） |
| R11 | 0x8002 AckCode 唯一 0x00 | §2.14/§8.2 | `doip.go:160-162` | 已覆（`doip_tcp_diag_ack` + `doip_neg_ack_code_reserved`） |
| R12 | 0x0000 GenericNack NackCode 0x00–0x04 | §2.3/§8.2 | `doip.go:216-220` | 已覆（`doip_tcp_generic_nack`/`doip_neg_generic_nack_code_reserved`） |
| R13 | UDS NRC 0x01–0x7F；0x00/0x80–0xFF 拒 | §2.16/§8.2（H6） | `doip.go:252-257` | 已覆（`doip_neg_uds_nrc_reserved`） |
| R14 | UDS SID 表 10 值 | §2.16/§8.2 | `doip.go:236-242` | 已覆（`doip_tcp_diag_uds_session_control`…`doip_tcp_diag_nack`/`doip_neg_uds_sid_unsupported`） |
| R15 | HasSubFunction 三态（nil/true/false） | §8.4（M8） | `doip.go:244-250`；序列化 `doip.go:974-997` | 已覆（`doip_tcp_diag_uds_read_write_did`/`doip_neg_uds_subfunction_conflict`） |
| R16 | 0x27 奇偶 seed/key 四形 | §8.4（H3） | `doip.go:259-265`；序列化 `doip.go:1015-1026` | 已覆（`doip_tcp_diag_uds_security_access`） |
| R17 | 0x36 BlockSeq n%256 回绕 | §8.4（M3） | `doip.go:689-701`；`layer_gen.go:183-193` | 已覆（`doip_tcp_diag_uds_transfer`） |
| R18 | 0x36 协议级分段阈值 MSS-40 / 块长 MSS-42 | §5.2/§6.10 | `doip.go:683-687`；`layer_gen.go:177-181` | 已覆（`doip_tcp_diag_uds_transfer`） |
| R19 | VIN 17B / EID 6B / GID 6B 长度边界 | §8.5 | `doip.go:79-87`——**校验嵌在 `Discovery != nil` 块内（`:62-88`）**，生成器 `layer_gen.go` 全文件不读这三键（实读 grep 零命中） | 明确不解决（UDP 面删键后该校验**永不可达**；三键随 §15.3 从层 config 删除，§1.12） |
| R20 | EID 从 `spec.DstMAC` 派生四形（显式/有效/空/非法） | §3.2/§6.13.1-4 | `doip.go:321-331`（跨层读 `spec.DstMAC`）；EID 只服务 0x0004 公告 | **G-DOIP-7**（目标形状下无宿主，随 UDP 面出链；恢复 UDP 时需重裁定） |
| R21 | Direction 三态 + 大小写不敏感 | §1.6/§8.6 | `types.go:205-214`；`doip.go:65/94/109/121/157/207` | 已覆（`doip_neg_direction_invalid_activation`/`doip_neg_direction_invalid_messages`/`doip_neg_direction_invalid_alive` + `doip_tcp_activation_basic`/`doip_tcp_alive_check` 的空值与大小写面） |
| R22 | 地址族对称 IPv4/IPv6 | §3.3/§9.4 | `types.go:164-176`；`doip.go:313` | 已覆（`doip_ipv6_tcp_flow`） |
| R23 | 广播/组播地址与 MAC（UDP 面） | §3.3 | `doip.go:473-482`/`:554-563` | **G-DOIP-2** |
| R24 | EntityStatus.MaxDataSize 约束 0x8001 长度 | §8.5 | `doip.go:196-200` | 明确不解决（宿主键随 G-DOIP-2 移出，§1.12 要求用例删键） |
| R25 | PayloadLength u32 理论上限 4GB-1 | §6.13.7/8 | `doip.go:192-194` | 明确不解决（实际不可达；以边界负例替代） |
| R26 | MSS 档位（0 → 回退 1460；<536 拒） | §5.2（H5） | `doip.go:227-229`；`layer_gen.go:91-94` | 已覆（`doip_neg_v1_oem`/`doip_tcp_diag_uds_transfer`） |
| R27 | TTL / DSCP / IP-ID 逐包推进 | §3.2 | `doip.go:292-295`、`:305-310` | 已覆（`doip_tcp_full_flow` frames） |
| R28 | TCP seq/ack 单调（帧长推进发送方 seq） | §6.15 | `doip.go:411-417` | 已覆（链上归 tcp 层，`doip_tcp_full_flow`） |
| R29 | 零长 payload 型（链上可达者：0x0007） | §2.10 | `layer_gen.go:225` | 已覆（`doip_tcp_alive_check`） |
| R30 | UDS 0x34 参数形（dataFormatId/addrLenFmt/addr/size） | §10.1 附录 B | 序列化 `doip.go:1034-1037` | 已覆（`doip_tcp_diag_uds_transfer`） |

**台账粒度声明（防误读）**：§18.4 的 54 点 = 八项 8 行 + 子表① 16 格 + 子表② 30 行；每行/格只计 1 点，行内子面缺口另登 §19，不折进 54 点、也不冒充覆盖。

---

## §13. 三路对照（§4.12–4.15）、子表③（§4.16）与候选方案对比（§4.17）

### §13.1 三路对照

| 路 | 出处（可复跑证据） | 定什么 | 本协议结论 |
|---|---|---|---|
| ① 规范原文（§4.12） | ISO 13400-2:2019 §7（载体）、§8.4.1（0x0000 NackCode）、§8.5.1（公告 ×3 / 500ms±100ms）、§8.5.3（FurtherActionRequired）、§8.5.5（VIN/GID SyncStatus）、§9.2.4（0x0005 与 ActivationType）、§9.3.6（0x0006 ResponseCode）、§10.3.2（SA/TA 一致性）、§10.4.3/§10.4.5（0x8002/0x8003 无长度字段）、§11.1（0x4002）、§11.2.2（0x4004） | 「必须是什么」 | 本文 §2 的 16 型表、值域表、默认值表即规范落点；**本机无 ISO 原文电子版**，全部引用转自本文 v2.0.x 既有条目（原审计已与 scapy/tshark 交叉核对）——本文不新增未核对的 ISO 章节断言 |
| ② 现网行为（§4.13） | **无实测证据**：未抓诊断仪/车辆网关现网包，本机无厂商文档 | 「现网真跑成什么样」 | **待确认（G-DOIP-9）**。确认方式三选一已写死：**（a）** 抓一次实车/台架诊断会话（`tcpdump -i <iface> -w doip.pcap 'tcp port 13400 or udp port 13400'`，需一次完整「插枪→发现→激活→读 DID」），或 **（b）** 查任一 OEM 诊断规范（如 VW/Audi ODIS、ISO 13400-2 Annex 诊断仪厂商手册）的 DoIP 章节，或 **（c）** 问诊断仪工具厂。**未取得前，本节不写现网定论** |
| ③ 可靠开源实现（§4.14） | scapy **2.7.0**，本机实测路径 `/usr/local/lib/python3.9/site-packages/scapy/contrib/automotive/doip.py`（525 行，`import scapy; scapy.VERSION` 实测 `2.7.0`） | 「别人已验证过的走法」 | 关键行逐条核对：PayloadType 表 `:104-122`（16 型，与本文 §2.2 逐值一致）；`protocol_version` 枚举 `:123-127`（0x01/0x02/0x03/0x04，本文只收 0x01/0x02）；`reserved_oem = XStrField(b"")` `:199`（**变长无长度前缀**——支撑本文 H1/C1 修复）；`previous_msg = XStrField(b"")` `:224`（**无 PrevDiag 长度字段**——支撑本文 v2.0.1 C1 修复）；`ack_code` 仅 `{0: "ACK"}` `:215`；`nack_code` `:217-223`（0x02–0x08 + 0x00/0x01 Reserved）；`routing_activation_response` `:180-196`（0x00–0x07 拒绝、**0x10 Success**、0x11 需确认——支撑 C1 整体偏移修复）；`diagnostic_power_mode` `:201-203`（0/1/2，支撑 H4）；`node_type` `:204-206`（0/1）。**scapy 偏差登记**：`:172-175` 的 `activation_type` 枚举含 `0x16/0x116/0xe016` 三项非 ISO 值（仅注释文本，非线格式）——只借鉴思路，不搬运 |
| ④ tshark dissector（补充路，§14.9） | TShark **3.6.14**，`tshark -G fields \| awk -F'\t' '$3 ~ /^doip[.]/' \| wc -l` **实测 = 33** | 「解析器认什么字段」 | 33 个 `doip.*` 字段全列（实测）：`version/inverse/type/length/nack_code/vin/logical_address/logical_address_name/eid/gid/futher_action/sync_status/power_mode/node_type/max_sockets/sockets/max_data_size/source_address/source_address_name/target_address/target_address_name/activation_type_v1/activation_type/tester_logical_address/tester_logical_address_name/response_code/reserved_iso/reserved_oem/data/diag_ack_code/diag_nack_code/previous/illegal_length_field`。**注意**：dissector 把 FurtherActionRequired 拼成 `doip.futher_action`（拼写缺 `r`）——用例锚词必须照此拼，不自创 |

**三路一致性（§4.15）**：① 与 ③ 在 16 型表、ResponseCode(0x10 Success)、NackCode(0x02–0x08)、PowerMode(0x00–0x02)、NodeType(0x00/0x01)、OEM/PrevDiag 变长六处**逐值一致**；④ 与 ①/③ 在字段名与宽度上一致（`doip.version=0x02`/`doip.inverse=0xfd`/`doip.type`/`doip.length` 逐包可校验）。② 缺证据 → 按 §4.15「以规范为底线」，设计取 ①/③ 交集，② 项一律登记 **G-DOIP-9** 待确认，**不写成定论**。

### §13.2 子表③：现网行为 → 用例映射表（§4.16）

| # | 现网行为项 | 产品名 + 版本 + 出处 | 映射用例 | 状态 |
|---|---|---|---|---|
| B1 | 诊断仪上电后广播/组播发现车辆 | **无证据**（未见文档/抓包） | — | **待确认（G-DOIP-9）**，确认方式见 §13.1 路② |
| B2 | 车辆 ECU 周期公告（×3，500ms±100ms） | **无证据** | — | **待确认（G-DOIP-9）** |
| B3 | 激活成功后同一 TCP 连接上多轮 UDS 交互 | **无证据**（结构由 ①/③ 支撑，时长/并发数无实测） | `doip_tcp_full_flow` | 结构已覆；现网参数待确认 |
| B4 | 安全访问 0x27 先取 seed 再送 key（两轮） | **无证据** | `doip_tcp_diag_uds_security_access` | 结构已覆；现网参数待确认 |
| B5 | 刷写 0x34→0x36×N→0x37 多块传输 | **无证据** | `doip_tcp_diag_uds_transfer` | 结构已覆；现网块长待确认 |
| B6 | ECU 主动 0x0007 探活、Tester 回 0x0008 | **无证据** | `doip_tcp_alive_check` | 结构已覆 |
| B7 | 激活被拒后连接关闭（不再发诊断） | **无证据** | — | **待确认（G-DOIP-9）** + 链上不可达（G-DOIP-3） |

**无映射即缺口的处置**：B1/B2/B7 三项无证据且无法映射 → 按 §4.16 记 **G-DOIP-9**（确认方式已写清三选一），**不标已覆盖**。

### §13.3 候选方案对比（§4.17）

| 方案 | 走法 | 借鉴来源 | 优势 | 劣势 | 对性能/复杂度/兼容性影响 | 结论 |
|---|---|---|---|---|---|---|
| **A. 单层 + 单载体（TCP-only）** | doip 层注册为 tcp-only 终结层（`DependsOn ["tcp"]`、`TransportOn ["tcp"]`），只产 TCP 阶段事件；UDP 三阶段不迁入层 config | 现网 P4a 先例（enip 拒 UDP IOData `layer_gen.go:61-74`、hl7 tcp-only 判定 `complete.go:447-460`） | 与现链框架零冲突；握手/seq/挥手复用 tcp 层（少一份 TCP 实现，无重复分包风险）；内存/速率由既有 pacer 与 tcp 层统一管 | **丢 ISO 的 UDP 半边**（发现/状态/电源 8 型不可生成）——诊断仪「先发现再激活」的完整流程无法复刻；激活拒绝路径同样不可达 | 复杂度最低（单载体单连接）；性能与 gbt32960/mcp 同档；兼容性 = 与 ISO 部分不兼容（需 G-DOIP-2 收口） | **选中**（今天唯一可达形态），UDP 面立项 **G-DOIP-2** |
| **B. 单层 + 双载体（同策略内 TCP+UDP 两条流）** | 一个 doip 层在同一策略内产 TCP 流 + UDP 子流，FlowID 后缀区分（本文 §5.1 `:udp:disc`/`:tcp:act`…） | **legacy 自身实现**：`doip.go:454-574` 已按此产出（UDP 三流 + TCP 流，`groupIDMeta` `:843-850` 绑同 worker）；scapy 的 `DoIPSocket`（TCP）与 `L3RawSocket`+UDP 双路示例 `doip.py:95-100` | 完整覆盖 ISO 16 型；legacy 已有可复用产出逻辑与 FlowID/GroupID 方案；诊断仪真实流程一致 | **链框架无「一个策略内混合载体」表达**：终结层唯一（`complete.go:395-441`）+ 传输层唯一（`:443-484`）双重判死；需改框架完成式补全与事件驱动两处（跨协议影响面大） | 复杂度高（框架级变更，影响全部 123 层）；性能需新增 UDP 子流调度；兼容性最好（与 ISO 全对齐） | **候选**（G-DOIP-2 的解决路径之一，须主线程裁定框架扩展，车道不得自改） |
| **C. 两个终结层（`doip` + `doip_udp`）** | 拆两个注册层，各自单载体 | 无先例（全仓库 123 层无「同协议双终结层」先例） | 不改框架 | 与 §1「层链唯一真相」冲突（同一协议两份形状）；`DependsOn`/`FieldContract`/schema 三处重复维护，双头风险 | 复杂度中；兼容性差（用户需知两条链） | **否决**（§7.7 禁双头；本文 §9.4 单点真相） |
| **D. 保留 flat 顶层 `doip` 子映射承载 UDP 面** | TCP 走链、UDP 走 flat | 无（正是 §1.4/§1.5 明令禁止的混用） | 改动最小 | 违反 §1.4「禁止 layers 与顶层协议子映射混用」、§1.11 白名单（`doip` 不在结构性键内）；门 2① 直接红 | — | **否决**（违核心记忆，非技术取舍） |

**取舍理由（§4.15）**：规范要求 UDP；框架今天只表达单载体。设计取**方案 A 为今天唯一可达形态**（目标形状纯 layers 且门 2 可绿），同时**不把 UDP 判死**——按 §4.17 与 §5.5 记 **G-DOIP-2** 立项，确认方式=主线程裁定框架扩展（方案 B 路径），未裁定前用例配置**必须删掉** `discovery`/`entity_status`/`power_mode` 三键（§1.12「明确不解决」语义）。

### §13.4 裁定 D-DOIP-1：依赖建模与链形（逐条先证，再给结论）

| 证据 | 行号（实读） | 内容 |
|---|---|---|
| 注册现状 | `registry.go:224-226` | `Name: "doip"`、`Category: CategoryTerminal`、`DependsOn ["tcp"]`；**无 `TransportOn`、无 `OptionalOn`、无 `Fields`** |
| 生成表现状 | `schemas/v1/generated/layers.generated.json`（123 层，`layers` 为 map） | `doip` 条目 = `{"category":"terminal","depends_on":["tcp"],"fields":{}}`（`fields` 空） |
| 终结层唯一（V2） | `complete.go:395-441`（判死在 `:441`） | `terminalCount > 1` → `terminal layer %q duplicated` |
| 变换器豁免（0c355be 后） | `complete.go:406-418`（`dependedOn`）、`:423`（豁免条件） | 豁免要求 `schema.TransformEvents && i < len(chain)-1 && dependedOn(...)`；`dependedOn` 现同时认 `DependsOn` 与 `OptionalOn`。**doip 无 `TransformEvents`，且无任何层 `DependsOn`/`OptionalOn` 含 `doip`** → 不适用 |
| 传输层唯一（V3） | `complete.go:443-484` | `transportCount > 1` → 重复；tcp-only 判定（`TransportOn` 空时按 `DependsOn` 含 tcp 且不含 udp 推）→ 用户显式 `udp` 时报 `carrier` 锚词错误 |
| 依赖顺序（V8） | `complete.go:485-500` | 每层 `DependsOn` 必须在其外层出现；`TransportOn` 可替代默认传输层 |
| 载体替代语义 | `schema.go:76-82` | `TransportOn` = 本层可坐的传输层，首个为默认（须与 `DependsOn[0]` 一致） |

**裁定**：目标链形 **`[ip, tcp, doip]`**（IPv6：`[ipv6, tcp, doip]`）；依赖声明 **`DependsOn ["tcp"]`（单值）+ `TransportOn ["tcp"]`（只放 L4）**，不设 `OptionalOn`、不设 `TransformEvents`。理由：doip 是 TCP 终结层、单载体，`TransportOn ["tcp"]` 把「只坐 TCP」写进 schema（`complete.go:447-460` 的 tcp-only 判定已能按缺省推出同结论，但显式声明是 hl7 先例的书面形状，见 `complete.go:447-450` 注释引 D-HL7-1 裁定2）；`DependsOn` 保持单值（多值会与 V8 顺序检查和 `TransportOn` 替代逻辑打架）。**`TransportOn` 多值（如 `["tcp","udp"]`）在本设计不取**——一旦声明 udp 可坐，`[ip,udp,doip]` 不再报 `carrier`，而生成器仍会拒 `discovery` 等键，错误锚词漂移且与「layer 只能表达 TCP 面」的现状矛盾。

## §14. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

> 证据三选一（§15.2）：文档章节 / 代码行 / 用例号。写不出 = 缺口立项，不许空着。§1/§3/§12 三行按 §15.3 强制展开（§14.1/§14.3/§14.12）。

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §14.1 强制展开：旧键逐个写去向（`src_ip`→`ip.src` 等 6 键）；顶层 `doip` 子映射 → `layers[]` 的 `doip` 条目（**今天无住处，G-DOIP-1**）；数量走 `flow_control`；目标形状纯 layers `spec_json` 样例见 §14.1；非负例顶层键=0 的收官自查见 §14-P2 | 本契约 §14.1 + §18.2 改写清单 |
| §2 策略/任务 | 策略 = 单 doip 流量模板，自带 `flow_control`（flows/bps/time）；任务 = 多策略合跑 + 总量封顶（框架语义未动，`doip` 不在 `worker`/`task` 特判名单内） | `internal/core/worker.go:294-320`（flowCount/封顶/逐流解析）；本契约 §14.12 |
| §3 五件套 | 见 §14.3 强制展开：会话表 / 事务序列 / 关联关系 / 插入位置 / 时间线。**有长连接载体（TCP 13400 单连接承载多轮 UDS），不豁免** | 本契约 §14.3 + 用例 `doip_tcp_full_flow` |
| §4 查规范 | ISO 13400-2:2019（§7/§8.4.1/§8.5.1/§8.5.3/§8.5.5/§9.2.4/§9.3.6/§10.3.2/§10.4.3/§10.4.5/§11.1/§11.2.2）+ UDS ISO 14229-1；三路对照 §13.1（scapy 2.7.0 实读行号 + tshark 3.6.14 实测 33 字段）；八项矩阵 §12.1 + 子表①② §12.2/§12.3 | 本契约 §12/§13 |
| §5 依赖与错误 | 依赖声明 = `DependsOn ["tcp"]`（单值）+ `TransportOn ["tcp"]`（只放 L4），裁定见 §13.4；错误分支：值域校验 `doip.go:26-232`、链级拒绝 `layer_gen.go:148-150/297-306`、carrier 冲突 `complete.go:447-460`；无凭空字段（① 与 ③ 逐值核对，§13.1） | 本契约 §12.1/§13.4 + §15.5 |
| §6 性能 | 见 §16「性能设计与验收」（6.1–6.8 要素）：声明式事件流 O(1) 内存、无全量聚合；pcap/NIC 双路验收；吞吐/并发/内存目标标「待 `doip_tcp_diag_uds_session_control` 基准」（§6.5 不许写承诺数字） | 本契约 §16 |
| §7 三份文档 | `05-doip-design.md` + `05-doip-testcase.md`（per-protocol 草稿层，§7.4）+ D-DOIP-1（本契约 §15，门1 获批=定稿）+ T-DOIP（testcase §2）+ generated schema（`doip_tcp_diag_uds_session_control` 重跑，主线程） | 修订记录 + §15 |
| §8 设计先行 | `doip_tcp_activation_basic`–`doip_tcp_activation_oem_varlen`（本契约 §12–§14）先于 `doip_tcp_diag_uds_session_control` 实现；门1 获批 = D-DOIP-1 定稿 = 开工门（§8.9） | 提交序 |
| §9 测试三源 | 三源 = ISO 13400-2/UDS 条款（本文 §2/§4/§8）+ D-DOIP-1（§15）+ 已确认现网行为（**无证据 → G-DOIP-9 待确认，不冒充第三源**）；T-DOIP 41 ID 逐项回指；存量 115 例审计去向下 §18 | `05-doip-testcase.md` §2/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论入 p123 报告）+ 收官隔离复审 + 修轮；红先绿后（§9.7） | `/tmp/pipe/57-doip/p123-report.md` |
| §11 白话 | 每阶段先行一句白话结论 | 汇报 |
| §12 动态清单 | 见 §14.12 强制展开：四元组 = `ip`/`tcp` 层（五策略全支持，allowlist `layer_dyn.go:18-63`）；业务字段**逐个列开/不开 + 理由**；序号算法实读行号（`tuple_generator.go:194-236`/`worker.go:300-309`） | 本契约 §14.12 |
| §13 schema 派生 | `doip` 已在 `registry.go:224-226` 注册（层数 123 已含 doip，**不新增层**）；但 `fields` 为空 → 目标形状须补 `Fields` 并**重跑 schemagen**（`TestLayersGeneratedMatchesRegistry` 会红，§13.19）；struct 标签字面量锁定（§13.13）；`allowedProtocols` 已有 `"doip": true`（`internal/core/protocols.go:29`） | 本契约 §15.1 接线件 |
| §14 真实流程 | suite 经 MCP 建任务 → 引擎真实生成 → tshark `doip.*`（33 字段实测）逐字段校对 + frames hex 双通道；先跑后钉（§14.20/§9.31）；pcap 落 `/tmp/mcp-pcaps/doip/` | testcase §6 |

### §14.1 §1 强制展开：旧键逐个去向 + 纯 layers 目标形状 spec_json 样例

**现状（实读）**：`cases/doip.json` 115 例的 `spec_json` 顶层键分布 —— `src_ip` 115、`dst_ip` 115、`src_port` 115、`doip` 115、`dst_mac` 3、`tcp` 2、`count` 0；其中 46 例已带 `layers`（但**同时**带顶层 `src_ip`/`dst_ip`/`src_port`/`doip` → 仍是 §1.4 混用形）。

| 旧键 | 出现例数 | 去向 | 落点 |
|---|---|---|---|
| `src_ip` | 115 | 迁 `ip` 层 `src` | `layers[i].ip.src` |
| `dst_ip` | 115 | 迁 `ip` 层 `dst` | `layers[i].ip.dst` |
| `src_port` | 115 | 迁 `tcp` 层 `src_port` | `layers[i].tcp.src_port` |
| `dst_port` | 0（未出现） | 迁 `tcp` 层 `dst_port`（默认 13400 由 `chain_planner.go:1038-1041` 补） | `layers[i].tcp.dst_port` |
| `count` | 0（未出现） | 删；数量走 `flow_control.flows`（§1.3） | 顶层 `flow_control` |
| `dst_mac` | 3 | 迁 `eth` 层 `dst_mac`（allowlist `layer_dyn.go:22` 已含 `eth.dst_mac`） | `layers[i].eth.dst_mac`；其下游的 EID 派生已死 → **G-DOIP-7** |
| `tcp`（顶层子映射） | 2 | 迁 `tcp` 层 `mss`/`termination` | `layers[i].tcp.mss` / `.termination` |
| `doip`（顶层子映射） | 115 | 迁 `layers[]` 的 `doip` 条目；层内**七键**（§15.3，去 `src_ip`/`dst_ip`/`src_port` 三键 + 不迁 UDP 三键 + 去死配置 `vin`/`eid`/`gid`） | **今天无住处 → G-DOIP-1**（`registry.go:224-226` 无 `Fields`；`chain_planner_translate.go:743-745` `len(s.Fields)==0` 直接 return；`complete.go:282-296` 对未知键报 `unknown field`） |
| `discovery`/`entity_status`/`power_mode`（`doip` 子键） | 47 例含 | **不迁入层**；用例配置里删键（§1.12「明确不解决」） | **G-DOIP-2** |
| `vin`/`eid`/`gid`（`doip` 子键） | 15/12 例含 | **不迁入层**（死配置：校验嵌在已删的 `Discovery != nil` 块，生成器零读取）；用例删键 | **G-DOIP-7** |

**目标形状（纯 layers）spec_json 样例 —— 今日跑不通，需先补代码（§1.9 + G-DOIP-1）**：

```json
{
  "layers": [
    {"ip": {"src": "192.168.1.100", "dst": "192.168.1.200"}},
    {"tcp": {"src_port": 40000, "dst_port": 13400, "mss": 1460, "handshake": true, "termination": true}},
    {"doip": {
      "protocol_version": 2,
      "tester_address": 3712,
      "logical_address": 1,
      "activation": {"direction": "up", "activation_type": 0, "response_code": 16},
      "messages": [{"direction": "up", "uds": {"service_id": 16, "sub_function": 3}}],
      "alive_check": {"direction": "down"}
    }}
  ],
  "flow_control": {"flows": 1}
}
```

（`tester_address: 3712` = `0x0E80`；`response_code: 16` = `0x10` Success；`service_id: 16` = UDS `0x10`。多流时 `ip.src`/`tcp.src_port` 写动态对象，见 §14.12。）

### §14.3 §3 强制展开：五件套（会话表 / 事务序列 / 关联关系 / 插入位置 / 时间线）

**会话表**（§3.1/§3.2 每会话独立 ID、独立四元组、独立生命周期）：

| 会话 ID | 载体 | 四元组（目标形状落点） | 生命周期 |
|---|---|---|---|
| `s1:tcp` | TCP 13400 | `ip.src`=Tester、`ip.dst`=ECU、`tcp.src_port`=Tester ephemeral、`tcp.dst_port`=13400 | SYN → 0x0005/0x0006 → 0x8001/0x8002/0x8003 ×N → 0x0007/0x0008 → FIN/FIN-ACK/ACK |
| `s2:tcp`（多 ECU，可选） | TCP 13400（独立 4-tuple，独立 ECU 逻辑地址） | 独立 `ip.dst` + 独立 `tcp.src_port`（**必须与 s1 拉开间隔，§9.37**） | 同上，与 s1 并发 |
| `s3:udp:*`（**今天不可达**） | UDP 13400 | `ip.dst`=广播/单播、`udp.src_port`/`udp.dst_port` | 发现/状态/电源三类单报文往返；**G-DOIP-2** |

**事务序列**（§3.3/§3.4–3.7 每事务写全前置/触发/成功/失败四件事）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| `t1` 路由激活 | TCP 三次握手完成（tcp 层） | 0x0005（SA=0x0E80, AT） | 收到 0x0006 RC=0x10 → 进 `t2`；RC=0x11 → 进 `t1'` | RC 0x00–0x07：**链上判错拒绝**（`layer_gen.go:297-306`，锚词 `activation failed`）；ISO 语义为 ECU FIN 关连 → **G-DOIP-3** |
| `t1'` 二次确认 | 收到 RC=0x11 且 `ConfirmationRequired=true` | 重发 0x0005 | 收到 0x0006 RC=0x10 → 进 `t2` | 最终 RC=0x05（Rejected Confirmation）：**schema 不可表达 → G-DOIP-4**（`doip.go:618-623`） |
| `t2..tn` 诊断事务（N 轮，同一 TCP 连接） | 激活成功 | 0x8001（SA/TA + UDS UserData，可含 0x36 分段） | 对端 0x8002 Ack（PrevDiag=被确认 UserData 副本） | `NackCode!=nil` → 对端 0x8003 Nack（NC 0x02–0x08）；UDS 层否定响应 `7F <SID> <NRC>` |
| `tm` 探活事务（可插入任意位置） | 连接存活 | 0x0007（ECU→Tester，方向固定 down） | Tester 0x0008（SA=TesterAddress） | 超时单边：链上由 tcp 层 `termination` 表达（§6.14 的「单边不发」→ 标明确不解决） |
| `tz` 通用 NACK（异常注入） | 激活之后 | 0x0000（NackCode 0x00–0x04，方向固定 down） | 单包 | — |

**关联关系**（§3.8/§3.9/§3.10）：本协议**无「一条控制流关联多条数据/媒体流」的结构**（DoIP 的连接、逻辑地址、诊断消息全部住在**同一条 TCP 连接**上；ISO 13400-2 无 FTP 式控制/数据分离通道，0x36 大块数据仍在同一连接内）。故 §3.8 的 `driven_by{session,transaction,field}` **不适用**，理由与证据：① 16 型 PayloadType 表无一为「数据面」型（本文 §2.2）；② 代码侧无第二流产出（`doip.go` 全文件只有一条 `configChan` 与一组 FlowID 后缀，`:454-791`）；③ scapy 的 `DoIPSocket` 亦单连接（`doip.py:333`）。**多流覆盖改为**：`flows=N` 多**会话**并发（如 N 台 ECU 各一条 TCP 连接），每会话独立 4-tuple、独立逻辑地址、独立握手/序号/挥手（§3.10 的「独立 ID/四元组/握手」逐项满足）。

**插入位置**：末端终结层（`layers` 数组末位 = `doip`）；其内**不再有链上层**（registry 无任何层依赖 `doip`）。0x0007 探活与 0x0000 NACK 的「插入诊断中间」在链上表现为**报文事件序列中的位置**（生成器内部顺序 `layer_gen.go:112-245`：激活 → 诊断 → 探活 → NACK），Wire 顺序由 tcp 层按事件序组装。

**时间线**（§3.11/§3.12）：单会话内严格有序（激活 → 诊断 ×N → 探活 → 挥手，`layer_gen.go` 固定分支顺序）；跨会话**并发**（多 ECU 并发各一条连接，§9.23 正交维度之一）；**可交错性**：同连接内 UDS 请求-响应严格串行（0x8001 后紧跟其 0x8002/0x8003，`layer_gen.go:198-214`），不允许诊断消息与探活在同一连接内交错到「同 seq 段」；包时间戳由 worker Pacer 按 `bps` 产生（`doip.go:433` `Timestamp: time.Now()`），公告的 500ms±100ms 间隔**不由 Planner 注入**（§5.3，链上随 UDP 面一并 G-DOIP-2）。**禁止「同一模板连续重复发射」冒充编排**（§3.13）：多轮诊断必须写 `messages[]` 显式序列，探活必须写 `alive_check` 对象。

---
### §14.12 §12 强制展开：动态字段清单（逐个列开/不开 + 序号算法实读行号）

**四元组（§12.2 至少覆盖，五策略全开）**——落点全在 `ip`/`tcp` 层，不在 `doip` 层：

| 层.字段 | allowlist（实读） | 五策略 | 序号算法（实读行号） |
|---|---|---|---|
| `ip.src` | `layer_dyn.go:20` `"ip": {"src": true, "dst": true, "ttl": true}` | fixed/inc/rand/list/pattern | `ResolveIPValue` `tuple_generator.go:290`；IPv6 递增 `genIP6Inc` `:164-177`（`off = uint64(index*step) % span`）；IPv6 随机 `genIP6Rand` `:181-191`（`rand.NewSource(s.Seed + int64(index))`） |
| `ip.dst` | 同上 | 五策略 | 同上 |
| `tcp.src_port` | `layer_dyn.go:21` `"tcp": {"src_port": true, "dst_port": true}` | 五策略 | `genPort` `tuple_generator.go:194-236`：`fixed` `:196-197`；`list` `:198-202`（`List[index%len]`）；`inc` `:203-217`（`start + (index*step)%count`，**到尾回绕**）；`rand` `:218-228`（`rand.NewSource(s.Seed+int64(index))`，**同 seed 同 index 可复现**）；`pattern` `:229-232`（模板渲染后转数值） |
| `tcp.dst_port` | 同上 | 五策略（诊断场景固定 13400；多 ECU 场景开 `inc` 拉开） | 同上；`ResolvePortValue` `tuple_generator.go:300` |

**保底防撞（§2.8/§12.10）**：`flows>1` 且用户未显式写 `src_port` 时，worker 按 `DefaultSrcPort + i` 递增（`worker.go:300-309`；`DefaultSrcPort = 12345` `strategy_convert.go:49`）；层动态在**其后**解析并覆盖（`worker.go:311-314` 调用序）。**保底不算动态字段**，不能代替真正的动态写法。

**业务字段（§12.3/§12.14 逐协议清单）**：

| 业务字段 | 开/不开 | 理由（可判定，非偏好） |
|---|---|---|
| `doip.protocol_version` | **不开**（fixed 两档） | 版本是**链级载体属性**（V1/V2 宽度不同，混用产 malformed 报文，本文 §1.3/R1）；逐流变让同一策略内报文形状分裂。两档用两策略表达 |
| `doip.tester_address` / `doip.logical_address` | **不开**（fixed） | 逻辑地址是**会话身份**（ISO 13400-2 §10.3.2 SA/TA 一致性硬约束，`doip.go:169-176`）：逐流变破坏「0x0005 SA ↔ 0x8001 SA / 0x0006 SLA ↔ 0x8001 TA」自洽。多 ECU 场景用**多会话/多策略**表达（每会话固定一对地址），这是 ISO 的正确用法 |
| `doip.vin` | **不开**（fixed） | VIN 是车辆身份（17B ASCII 长度硬校验 `doip.go:79-81`）；同一 ECU 只有一个 VIN |
| `doip.eid` / `doip.gid` | **不开**（fixed） | 实体/组标识是物理身份（通常等于 MAC）；逐流变等于伪造物理上不存在的 ECU |
| `doip.activation.*`（AT/RC/OEM） | **不开**（fixed） | 激活是**状态机迁移**不是取值池；`ConfirmationRequired` 是布尔分支 |
| `doip.messages[].uds.*`（SID/DID/NRC/BlockSeq…） | **不开**（fixed） | 诊断序列是**有序事务**（§3.3）：逐流改 SID 破坏「0x34→0x36→0x37」依赖链（本文 §6.10） |
| `doip.alive_check.source_address` | **不开**（fixed） | 同逻辑地址一致性（`doip.go:210-212`） |
| `doip.generic_nack.nack_code` | **不开**（fixed） | 头部错误码是异常注入选择器，非取值池 |

**不开的总口径**：这些字段若开，**必须**先在 `layer_dyn.go` 的 `layerDynAllowlist`（`:18-63`）登记条目并在 `translateTerminalConfig` 做逐流回填；**当前 allowlist 无 `doip` 条目**（实读 `:18-63` 键为 `ip`/`tcp`/`udp`/`eth`/`http`/`tls`/`dns`/`mqtt`/`h323`/`mpls`/`ngap`/`telnet`/`sip`/`radius`），故今天**任何** `doip` 层字段写动态对象都会被 `validate_layers.go:355-370` 判 `does not support dynamic`。若现网多 ECU 场景证明需逐流地址池 → **G-DOIP-8** 立项。

**序号算法代码位置（§12.16 抽查锚点）**：`tuple_generator.go:194-236`（端口五策略）+ `:164-191`（IPv6 地址 inc/rand）+ `worker.go:300-309`（保底递增）+ `layer_dyn.go:770-878`（`resolveLayerTuple` 逐流解析落 spec）。**以上全部实读，无编造**。

### §14-P2 presence 负例形状（链级红例必含①）与白名单外游离键（②）

| # | 负例形状 | 目标锚词 | 目标用例 |
|---|---|---|---|
| ① | **层链 + 顶层空子映射并存**（判死负例，非残留）：`{"layers":[{"ip":{}},{"tcp":{}},{"doip":{}}],"doip":{}}` | `rejects a top-level doip sub-config` | **`doip_neg_flat_toplevel`**（**今天不成立**：`CheckProtoFlat` `strategy_convert.go:8273-8517` 无 `doip` 分支 → **G-DOIP-5**） |
| ② | 白名单外游离键（§1.11）：顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/`dst_mac`/`tcp` 任一 | 前五键走通用文案 `rejects flat config field <k>`（`strategy_convert.go:8286-8293`）；`dst_mac`/`tcp` 无对应检查 → 同 **G-DOIP-5** 族 | **`doip_neg_flat_field`** |
| ③ | 全部负例 `expect_error` 带错误锚词（方案 §2 链级红例清单③） | 见 testcase §4 逐行锚词 | `doip_neg_activation_denied`…`doip_neg_ack_code_reserved` |
| ④ | 收官自查行「**非负例顶层键 = 0**」 | 程序化扫描：正例 `spec_json` 顶层键 ⊆ {`layers`,`flow_control`,`group_id`,`tuples`,`output`} | §18.5 自查命令 |

## §15. D-DOIP-1 `doip_tcp_activation_confirmation` 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 全部行号为**实读**（HEAD `0c355be`）；未实读的接口/函数名不写。

### §15.1 改哪几个文件（§8.1）

| # | 文件 | 改动 | 归属 |
|---|---|---|---|
| 1 | `trafficgen/internal/core/layers/registry.go` | `doip` 注册行（`:224-226`）补 `Fields`（§15.3 七键）并把 `TransportOn` 显式写为 `["tcp"]` | **跨协议共享框架文件 → 按方案 §2 禁令停车上报主线程**（同 P4a 各协议插自有块的先例，但文件本身是共享面） |
| 2 | `trafficgen/internal/core/layers/chain_planner_translate.go` | `translateTerminalConfig`（`:679`）新增 `case "doip"`（放置位置与 `case "mcp"` `:2300-2326` 同段），走 JSON 往返解码 `core.DoIPConfig` | 车道 B 分支内（方案 §3 明列「translate switch case」为合并冲突预期点） |
| 3 | `trafficgen/internal/core/strategy_convert.go` | `CheckProtoFlat`（`:8273-8517`）新增 `protocol == "doip"` 顶层子映射判死分支 | 车道 B 分支内 |
| 4 | `trafficgen/tools/coverage_gate.py` | 新增 `check_doip` 块（方案 §2 M1：出口必须 0，出口 2 视红） | 车道 B 分支内 |
| 5 | `trafficgen/schemas/v1/generated/layers.generated.json` | schemagen 重跑产物（`doip` 条目 `fields` 由 `{}` 变为七键表） | **主线程独占**（方案 §0/§6 护栏 4：合并后统一重跑一次） |
| — | `trafficgen/internal/protocol/doip/*.go` | **不改**（`doip.go`/`layer_gen.go`/`types.go`/`builder.go`/`parser.go` 已实现；仅「不动 UDP」等既有拒绝保持） | — |

### §15.2 接口签名（§8.2）

- `func (p *ChainPlanner) translateTerminalConfig(spec *core.FlowSpec)` — 既有签名（`chain_planner_translate.go:679`），**只加分支不加导出函数**。
- `func CheckProtoFlat(protocol string, cfg map[string]interface{}) string` — 既有签名（`strategy_convert.go:8273`），只加分支。
- `LayerSchema{Name, Category, DependsOn, TransportOn, Fields, …}` — 既有结构（`schema.go:69-100`）。
- **不新增导出解析函数**：`parseDoIPConfig` 是 `strategy_convert` 包私有（`strategy_convert.go:8048`），`layers` 包不可见 → 翻译侧走 **JSON 往返**（`json.Marshal(completedConfig(...))` → `json.Unmarshal` 进 `core.DoIPConfig`），与 `case "mcp"` `:2314-2321` 同款零分叉。

### §15.3 数据结构（§8.3）

`doip` 层 config **七键**（= `core.DoIPConfig` `types.go:9523-9571` 的 16 键：**去掉** `src_ip`/`dst_ip`/`src_port`（地址端口归 `ip`/`tcp` 层）；**去掉** `discovery`/`entity_status`/`power_mode`（UDP 面，G-DOIP-2 不迁）；**去掉** `vin`/`eid`/`gid`（**死配置**：校验嵌在已删的 `Discovery != nil` 块 `doip.go:62-88`，生成器 `layer_gen.go` 零读取——按 §1.12「该字段根本不被消费」必须从用例配置删除，不许登记保留））：

| 键 | 类型 | 缺省 | 语义 |
|---|---|---|---|
| `protocol_version` | int | 0 → 生成器回退 0x02（`layer_gen.go:76-79`） | V1/V2 |
| `logical_address` | int | 0 → 0x0001（`layer_gen.go:86-89`） | ECU 逻辑地址 SLA |
| `tester_address` | int | 0 → 0x0E80（`layer_gen.go:82-85`） | Tester 逻辑地址 SA |
| `activation` | object | 无 | 0x0005/0x0006 阶段 |
| `messages` | list | 无 | 0x8001/0x8002/0x8003 序列 |
| `alive_check` | object | 无 | 0x0007/0x0008 |
| `generic_nack` | object | 无 | 0x0000 |

**缺省纪律（§13.20）**：**一律不设 `Default`** —— 零值即设计缺省（V2/0x0E80/0x0001/6B 零都已在生成器内回退，`layer_gen.go:76-94`），设 `Default` 会让 `completedConfig` 注入非零值、破坏「空层 `{}` 走 legacy 缺省」的对齐。键缺席走引擎缺省；显式 null 由调用方省略。

### §15.4 主流程（§8.4）

1. **形状校验**：`ValidateLayers` 逐层过 `ValidateLayerConfig`（`complete.go:282-296`：未知键 → `unknown field`）+ 动态对象门（`validate_layers.go:355-370`）。
2. **补全**：`completedChain` → 补 `ip`（`tcp` 的 `DependsOn`）+ 补 `tcp`（`doip` 的 `DependsOn`）；用户显式写 `udp` → `complete.go:447-460` 报 `carrier`。
3. **Spec 默认化**：`validateSpecBase`（`chain_planner.go:747-1164`）—— `doip` 分支保持 `src_port` 0 不默认化（`:815-818`）、目的端口默认 13400（`:1038-1041`）。
4. **层 → spec 翻译**（**新增**）：`translateTerminalConfig` `case "doip"`：`spec.DoIP == nil` 时按层 config 解码（JSON 往返）；空层 `{}` 也翻译出非 nil `DoIPConfig`（validator 要求非 nil，`doip.go:39-41`）；`spec.DoIP != nil`（flat 直调）→ 早退不覆盖（mcp `:2301-2303` 同款守卫）。
5. **层端口回填 spec**（既有，`:307-330`）：用户在 `tcp` 层显式写的 `src_port`/`dst_port` 回填，防 flowID/包序列端口分裂。
6. **协议级校验**（既有，`chain_planner.go:301-305` → 注册表 `RegisterLayerValidator("doip", …)` `layer_gen.go:274-321`）：先 `Planner.Validate`（`doip.go:26-232`），再链级拒绝（UDP 三键 `:288-296`、激活失败 `:297-306`、`Activation==nil` 时改写 `spec.TCP.Handshake/Termination=false` `:312-319`）。
7. **生成**：`ChainPlanner.Plan` → 终结层生成器 `DoIPGenerator.Generate`（`layer_gen.go:53-246`）经 `EmitMsg` 逐事件产出（方向 + 8B 头 + payload），`tcp` 层负责握手/seq-ack/挥手/MSS 分段；0x36 协议级分段在生成器内（`:177-194`）。
8. **逐流**：worker `resolveLayerTuple`（`layer_dyn.go:770`）按流序号解析 `ip`/`tcp` 层动态（`worker.go:313-314`）。

### §15.5 错误分支（§8.5，逐条给锚词）

| # | 触发 | 锚词（原文） | 落点 |
|---|---|---|---|
| E1 | 层内未知键 | `layers: layer "doip": unknown field "x"` | `complete.go:282-296` |
| E2 | 层内字段写动态对象 | `<where> does not support dynamic` | `validate_layers.go:355-370` |
| E3 | 顶层 `doip` 子映射（`doip_tcp_diag_uds_read_write_did` 后） | `rejects a top-level doip sub-config` → 文案以 `CheckProtoFlat` 新分支为准 | `strategy_convert.go:8273+`（**新增**） |
| E4 | 顶层 `src_ip` 等旧键 | `rejects flat config field src_ip` | `strategy_convert.go:8286-8293`（既有） |
| E5 | `discovery`/`entity_status`/`power_mode` 非 nil | `doip: discovery (UDP) is not supported on the layer chain (tcp only)` | `layer_gen.go:288-296` |
| E6 | 激活失败（RC 0x00–0x07、0x11 无确认） | `doip: activation failed (response_code 0xNN) is not supported on the layer chain (tcp layer takes over teardown)` | `layer_gen.go:297-306` |
| E7 | `messages` 无 `activation` | `doip: Messages require Activation (diagnostic messages need routing activation first)` | `doip.go:138-140` |
| E8 | 值域越界（RC/AT/NackCode/AckCode/NRC/SID/NodeType…） | 各字段锚词见 §2.3/§2.9/§2.15/§8.2 对应条目 | `doip.go:26-232` |
| E9 | 显式 `udp` 载体 | `doip chain: udp carrier is not supported — doip rides tcp only (carrier)` | `complete.go:447-460` |
| E10 | 长度越界（VIN/EID/GID） | `doip: VIN must be 17 bytes, got N` / `doip: EID must be 12 hex chars, got N` | `doip.go:79-87` |

**假成功红线（§14.11/§14.12）**：驱动内「生成器报错 → 空流」契约（`layer_gen.go:280-283` 注释引 `chain_planner.go:382-386`）会把生成期错误吞成 `completed + 0 包` —— 因此**必须**在 `Validate` 同步拒绝（`layer_gen.go:274-321` 已是此设计），负例断言锚词取自 Validate 而非驱动期。

### §15.6 性能边界（§8.6）

| 项 | 值/依据 |
|---|---|
| 数据路径 | 纯事件流：`Generate` 逐事件 `EmitMsg`，无聚合、无切片累积（`layer_gen.go:97-110` 每次分配 8B 头 + payload；`chunks` 仅在 0x36 分段时按块产出，`：177-194`） |
| 单流内存 | O(1)（除 `messages[]` 配置本身）；无 per-packet 持有 |
| 事件量 | 1 流 = 激活 1–2 往返 + 2N 诊断事件 + 探活 1–2 + NACK 0–1；0x36 大块 = `ceil(Data / (MSS-42))` 个事件对 |
| 速率 | 由 worker Pacer 按策略 `flow_control.bps` 统一限（不在协议层） |
| 并发 | 会话数 = `flow_control.flows`；多会话各自独立 4-tuple，跨会话无共享状态（无锁） |
| 待确认（§6.5） | 目标吞吐（包/秒、比特/秒）、单流最大报文、内存上限**标待确认**，`doip_tcp_diag_uds_session_control` 基准后填；不写承诺数字 |

### §15.7 与现有逻辑的冲突点（§8.7）

1. **双轨风险（最高）**：`mapToFlowSpec case "doip"`（`strategy_convert.go:1287-1290`）在翻译前先读顶层 `doip` 子映射填 `spec.DoIP` → 若不同批加 `CheckProtoFlat` 判死，层 config 会**静默被忽略**（`translateTerminalConfig` 的 flat 守卫早退），出现「配置写层不生效、写顶层才生效」的混搭缝（隔离复审 F1 同类）。**处置**：`CheckProtoFlat` 分支与翻译分支**同一提交**落地。
2. **存量用例全红面**：46 例「`layers` + 顶层 `src_ip`/`dst_ip`/`src_port`/`doip` 混用」在加判死后必红；115 例全量需按 §18.2 改写清单同批处理（§14.4/§14.5）。
3. **registry.go 是共享框架文件**：按方案 §2 禁令，车道不得自改 → 停车上报；注册行本身是 P4a 先例（各协议插自有块），但同文件的 `TransportOn` 写法变更会触发 schemagen 重跑。
4. **schemagen 产物**：`:19` `TestLayersGeneratedMatchesRegistry` 会因 `Fields` 变化变红，必须在合并后由主线程重跑 `go run ./internal/core/layers/schemagen`（§13.19）。
5. **协议包内既有拒绝**：`layer_gen.go:61-74`/`:288-296` 对 UDP 三键的拒绝**保留**——它是 G-DOIP-2 的现状证据，不随本次改动删除；`spec.TCP` 被 validator 改写（`:312-319`）与 `tcp` 层 config 的显式值关系需在 `doip_tcp_diag_uds_session_control` 用例中钉（Activation==nil 时校准 Handshake/Termination=false）。
6. **与其它层无交集**：全仓库无层 `DependsOn`/`OptionalOn` 含 `doip`（`registry.go` 全文 grep 仅 `:216-226` 一处）→ 不影响 enip/gbt32960/mcp 等同族 tcp 终结层。

### §15.8 回滚方式（§8.8）

- **回滚单位 = 一次提交**（`registry.go` Fields+TransportOn、`chain_planner_translate.go` case、`strategy_convert.go` 判死分支、`coverage_gate.py` 块、schemagen 产物）；`git revert` 单提交即回到「层 config 无住处、顶层 flat 可用」现状，**协议包未动故 legacy 路径仍可用**。
- 用例改写与 D/T 条目同批回退（方案 §3 门2 红回滚条款 m5：不留双头）。
- 回滚后负例锚词回落 `unknown field`/`unknown layer` 族 → 相关负例一并回退，不留「锚词漂移的空跑负例」。

---

## §16. 性能设计与验收（CORE_MEMORY §6.1–6.8）

| 要素 | 本协议落点 |
|---|---|
| 6.1 目标/预算/边界同写 | 见 §15.6：目标吞吐/内存上限/单流最大报文**标待确认**（`doip_tcp_diag_uds_session_control` 基准后填），但**结构边界已定**：单流事件量上界 = 激活 4 + 2N + 探活 2 + NACK 1；0x36 事件数 = `2 × ceil(Data/(MSS-42))` |
| 6.2 指标列全 | 吞吐：跟 tcp 层同档（无额外分包/重组）；并发会话 = `flow_control.flows`（各独立 4-tuple）；单流最大报文 = `MSS`（`tcp.mss`，Default 1460，Min 536）；内存上限 = O(1)/流；队列上限 = 既有 `chain_planner.Plan` 通道 `256`（`chain_planner.go:1468` 同族）；CPU 并行度 = `PacketWorkers`（框架级） |
| 6.3 两路验收 | **pcap 路**：`output_type=pcap` 落 `/tmp/mcp-pcaps/doip/`，tshark `doip.*`（33 字段）+ frames hex；**NIC 路**：`output_type=port_group` + `tcpdump -i <iface> 'tcp port 13400'`，比对 `doip.type`/`doip.length` 序列与 pcap 一致 |
| 6.4 依据写清 | **流式**：生成器逐事件 `EmitMsg`（`layer_gen.go:97-110`），**无全量收集**；**每包新增内存** = 8B 头 + payload 长度（无额外拷贝层）；**共享状态**：无（单流内 `tcpClientSeq`/`tcpServerSeq` 由 tcp 层持有）；**锁**：无（生成器无 mutex）；**限速/多 worker**：速率由统一 Pacer 按策略 `bps` 限，多 worker 共享同一桶（框架既有语义，本协议不新增桶） |
| 6.5 无基准不承诺 | 所有具体数字（pps/bps/内存 MB）标 **待确认**，来源=`doip_tcp_diag_uds_session_control` 实现后基准；不写进需求 |
| 6.6 六类场景 | 基线（单会话 22 事件 `doip_tcp_full_flow`）；目标规模（N 轮诊断 + 0x36 大块 `doip_tcp_diag_uds_transfer`）；压力上限（`flows` 拉满 + `bps` 封顶）；长时间运行（多轮诊断 + 探活循环，≥10min）；并发交错（多 ECU 并发连接 `doip_tcp_multiflow_dynamic`）；资源耗尽/背压（`flow_control.bps` 收紧 + 队列积压观测，框架 `chain_planner` 通道） |
| 6.7 断言实际量 | 断言：实际包数（`packet_count`）、实际速率（pcap 时间戳跨度算 bps）、内存（进程 RSS 前后差）、CPU、队列积压（`get_buffer_status` 类接口）、丢包/失败计数；**禁止只断言「任务没报错」** |
| 6.8 超预算即不合格 | 若实际内存/吞吐越出 §15.6 的结构边界（如出现 O(N) 聚合）→ 设计不合格，回退重设计 |

**验证方法（可直接执行）**：
- 正向吞吐：`flowb_run_protocol_case`（`output_type=pcap`）跑 `doip_tcp_full_flow`/`doip_tcp_multiflow_dynamic`，取 `packet_count` 与 pcap 时间跨度算实测 pps/bps；
- 内存：任务前后 `ps -o rss= -p <engine pid>` 差值；
- 背压：把 `flow_control.bps` 调到平台下限（如 `1k`）跑 60s，观察完成时间与 `packet_count` 一致性（不丢包、不静默）。

**失败边界（§6.8）**：① 出现「`completed` 但 0 包」= 红（§14.12）；② 实测 bps 与配置 `bps` 偏差 > 5% = 红（Pacer 语义框架级，不入本协议回滚面但必须登记）；③ 多 worker 下包序错乱（同一流内 DoIP 事件乱序）= 红（`_resequencer` 框架级）。

---

## §17. `doip_tcp_activation_oem_varlen` 测试对接清单（T-DOIP 草稿输入；正文落 `05-doip-testcase.md`）

- **ID 权威**：`05-doip-testcase.md` §2（41 ID = 16 正 + 25 负，逐序）；本契约 §12/§13 的每一行/格回指到该表。
- **§3.15 三项**（同连接多轮操作 / 非正常结束 / 长保活）逐项一例或立项 → testcase §8.1。
- **A′/B′ 两分类表** → testcase §8.2（A′ = 现有引擎可构建的面，`doip_tcp_diag_uds_session_control` 并入；B′ = 引擎结构缺口 → §19 立项）。
- **9.52 对账两行 + 清单出处声明** → testcase §8.3（本协议账：规范逻辑点总数 **54** vs 用例覆盖数 **39**，另不适用/明确不支持 3 + 立项 12，39+3+12=54）。
- **3.14 豁免边界审计** → testcase §8.4（**有长连接载体，`sessions` 不豁免**；多流并发与单消息多载荷各需用例）。
- **三源回指行** → testcase §8.5。
- **断言通道**：`doip.*`（33 字段实测）+ frames hex（DoIP 头 8B 固定偏移：IPv4/TCP 起点 54，IPv6/TCP 起点 74）+ 载体 `ip.proto`/`ipv6.nxt`/`tcp.*`；**动态值只用** presence/nonzero/distinct/same_as（§9.34/§9.35）。
- **未跑声明**：本次 `doip_tcp_activation_basic`–`doip_tcp_activation_oem_varlen` **不跑 suite**（不启动服务器），不宣称任何绿的结论。

## §18. 存量 115 例审计去向与去扁平改写清单（§9.14 / §14.4）

> 审计口径：**按族批量审计、每族点名**（逐例列名于本节），三分类 = 合入 / 等价覆盖 / 作废（含原因）。存量 = `cases/doip.json` **115 例**（实读）。
> **前置事实**：全部 115 例的 `spec_json` 顶层都带 `src_ip`/`dst_ip`/`src_port`/`doip` 四键（旧扁平形）；其中 46 例另带 `layers`（**混用形**，§1.4 违规）。`count` 零出现，`dst_mac` 3 例，顶层 `tcp` 2 例。

### §18.1 族划分与总账

| 族 | 判据（实读 `spec_json.doip` 子键） | 例数 | 去向 |
|---|---|---|---|
| F1 UDP 单阶段 | 只含 `discovery`（22）/ 只含 `entity_status`（9）/ 只含 `power_mode`（9） | **40** | **整族作废 + G-DOIP-2 立项**（链不可达；配置按 §1.12 删键） |
| F2 UDP+TCP 混合 | UDP 键与 `activation`/`messages` 并存 | **7** | **拆分**：UDP 段作废（G-DOIP-2）；TCP 段合入 `doip_tcp_full_flow`/`doip_tcp_multiflow_dynamic`（`maxdata_4000`/`maxdata_5000` 随 EntityStatus 删键作废） |
| F3 激活阶段（纯 TCP） | 只有 `activation` | **22** | 成功面合入 `doip_tcp_activation_basic`/`doip_tcp_activation_v1`/`doip_tcp_activation_confirmation`/`doip_tcp_activation_oem_varlen`/`doip_tcp_options`；拒绝码面（`rc_0x01/0x04/0x05/0x07`）作废 + **G-DOIP-3**；值域负例合入 `doip_neg_activation_type_reserved`/`doip_neg_response_code_reserved` |
| F4 诊断阶段（纯 TCP） | `activation`+`messages` | **33** | 合入 `doip_tcp_diag_uds_session_control`…`doip_tcp_diag_nack` / `doip_neg_nack_code_reserved`·`doip_neg_uds_nrc_reserved`…`doip_neg_sa_ta_consistency`·`doip_neg_ack_code_reserved`；`s11_activation_fail` 归 F3 拒绝面 |
| F5 存活检查（纯 TCP） | `activation`+`alive_check` | **5+1** | 合入 `doip_tcp_alive_check`（`alive_mid_messages` 表插入位置） |
| F6 通用 NACK（纯 TCP） | `activation`+`generic_nack` | **6** | 合入 `doip_tcp_generic_nack` / `doip_neg_generic_nack_code_reserved` |
| F7 校验专用 | 只有 `messages` | **1** | 合入 `doip_neg_mss_below_min` |

**合计** 40 + 7 + 22 + 33 + 6 + 6 + 1 = **115** ✓

### §18.2 去扁平改写清单（逐键映射，`doip_tcp_diag_uds_read_write_did` 执行）

| # | 改写动作 | 机检方式 |
|---|---|---|
| W1 | 顶层 `src_ip` → `layers[i].ip.src`；`dst_ip` → `layers[i].ip.dst`（**全部 115 例**） | 扫描后断言正例顶层键 ⊆ 白名单 |
| W2 | 顶层 `src_port` → `layers[i].tcp.src_port`；`dst_port` 由 `chain_planner.go:1038-1041` 补 13400（或显式写） | 同上 |
| W3 | 顶层 `doip` 子映射 → `layers[末].doip`（七键，§15.3）；子键去 `src_ip`/`dst_ip`/`src_port`；**UDP 三键 + 死配置 `vin`/`eid`/`gid` 删除**（62 例受影响） | 层内未知键由 `complete.go:282-296` 拒 |
| W4 | 顶层 `dst_mac` → `layers[i].eth.dst_mac`（3 例）；**`doip.eid` 键整体删除**（死配置，§15.3）——EID 派生逻辑随 UDP 面出链，3 例的断言对象消失 → 归 F1 作废族 | 3 例名：`doip_eid_from_dstmac`/`doip_eid_invalid_mac`/`doip_eid_oversized_mac` |
| W5 | 顶层 `tcp` 子映射 → `layers[i].tcp.mss` / `.termination`（2 例：`doip_mss_fallback`/`doip_termination_false`） | — |
| W6 | `layers` 数组补全规范写法：`[{"ip":{}},{"tcp":{}},{"doip":{}}]`（现有 46 例写的是 `[{"tcp":{}},{"doip":{}}]`，缺 `ip` 条目，靠补全注入——改写写全） | — |
| W7 | 负例锚词重钉：UDP 面负例（`far_*`/`sync_*`/`pm_0x03`/`entity_*`/`v1_pm`/`dir_*` 等 14 例）随键删除改钉 **G-DOIP-2 链级锚词**或整体作废 | 逐例锚词见 §18.3 |
| W8 | `count` 键：零出现（无需迁移）；数量一律写 `flow_control.flows` | — |

### §18.3 逐族点名审计（作废 / 合入 / 等价覆盖）

**F1 UDP 单阶段（40 例）—— 整族作废（原因：链不可达 G-DOIP-2；配置键按 §1.12 必须删除）**
- 发现 22：`doip_s1_discovery_broadcast`、`doip_s1_variant_request_up`、`doip_t004_eid_request`、`doip_t005_vin_request`、`doip_ipv6_discovery`、`doip_announce_1`、`doip_far_0x10`、`doip_far_0x11`(负)、`doip_far_0x20`(负)、`doip_far_0x40`(负)、`doip_sync_0x10`、`doip_sync_0x01`(负)、`doip_v1_announce_32b`、`doip_eid_from_dstmac`、`doip_eid_from_default_mac`、`doip_eid_short`(负)、`doip_vin_short`(负)、`doip_eid_invalid_mac`(负)、`doip_eid_oversized_mac`(负)、`doip_dir_upper`、`doip_dir_invalid`(负)、`doip_ipv6_v1`
- 实体状态 9：`doip_s7_entity_status`、`doip_s7b_entity_down_default`、`doip_entity_gateway`、`doip_entity_nodetype_0x02`(负)、`doip_entity_sockets_255`、`doip_entity_cur_le_max`、`doip_entity_cur_gt_max`(负)、`doip_entity_maxdata_0`、`doip_ipv6_entity`
- 电源模式 9：`doip_power_mode`、`doip_power_mode_response`、`doip_pm_0x00`、`doip_pm_0x02`、`doip_pm_0x03`(负)、`doip_pm_broadcast_ipv4`、`doip_pm_broadcast_ipv6`、`doip_pm_unicast`、`doip_v1_pm`(负)
- **等价覆盖说明**：其中 9 例（`far`/`sync`/`pm`/`entity_nodetype`/`dir_invalid` 值域校验）的**校验逻辑仍在代码里**（`doip.go:61-115`），但宿主键从目标形状删除 → 无键可承载 → 归「作废」，**不冒充已覆盖**（§9.36：真实代码尚不支持某格时钉现状或立项，不许删用例也不许冒充覆盖——本处为「键被移出链」，故记作废 + 立项）。

**F2 UDP+TCP 混合（7 例）—— 拆分**
`doip_s15_full_diag_flow`、`doip_maxdata_4000`、`doip_maxdata_5000`、`doip_power_mode_after_teardown`、`doip_full_flow_22`、`doip_full_flow_22_ipv6`、`doip_s15_full_diag_flow_22`
→ TCP 段（激活+诊断+探活+挥手）**合入 `doip_tcp_full_flow`**（IPv6 形合入 `doip_ipv6_tcp_flow`）；UDP 段作废；`maxdata_*` 两例随 `entity_status` 删键作废（R24 明确不解决）。

**F3 激活阶段（22 例）**
- **合入**（成功面）：`doip_s2_routing_activation`→`doip_tcp_activation_basic`；`doip_s2_variant_oem4b`/`doip_oem_255b`→`doip_tcp_activation_oem_varlen`；`doip_ipv6_activation`→`doip_ipv6_tcp_flow`；`doip_rc_0x11_confirm`→`doip_tcp_activation_confirmation`；`doip_at_0x01`/`doip_at_0xe0`→`doip_tcp_activation_basic`/`doip_tcp_activation_oem_varlen` 值域面；`doip_la_0x0000`/`doip_la_ffff`/`doip_ta_0x0000`→`doip_tcp_activation_basic` 地址边界面；`doip_pv_0x00`（V1 全流程）→`doip_tcp_activation_v1`；`doip_no_discovery_direct_activation`→`doip_tcp_activation_basic`；`doip_termination_false`→`doip_tcp_options`。
- **作废（原因：激活拒绝路径链不可达，G-DOIP-3）**：`doip_rc_0x01`、`doip_rc_0x04`、`doip_rc_0x05`、`doip_rc_0x07`（旧断言=发出 RC 拒绝应答；链上该配置直接判错）。**替代覆盖**：新增负例 **`doip_neg_activation_denied`**（钉现状：RC=0x01 → 锚词 `activation failed`）——记「等价覆盖（改判负例）」而非单纯作废。
- **合入（值域负例）**：`doip_rc_0x12`→`doip_neg_response_code_reserved`；`doip_at_0x02`→`doip_neg_activation_type_reserved`；`doip_v1_oem`→`doip_neg_direction_invalid_activation`。
- **等价覆盖**：`doip_pv_0x03`/`doip_pv_0xff` → `doip_neg_response_code_reserved` 同族（协议版本值域）→ 并入 **`doip_neg_response_code_reserved`**（同族负例合并，指名去重）。

**F4 诊断阶段（33 例）**
- **合入**：`doip_s3_diag_uds10`→`doip_tcp_diag_uds_session_control`；`doip_uds_3e_tester_present`→`doip_tcp_diag_uds_session_control`；`doip_uds_22_response_sid`→`doip_tcp_diag_uds_read_write_did`；`doip_uds_27_*`（seed/send_key/odd/even）→`doip_tcp_diag_uds_security_access`；`doip_uds_blockseq_wrap`/`doip_s10_big_transfer`/`doip_big_transfer_segmented`→`doip_tcp_diag_uds_transfer`；`doip_s4_diag_nack`/`doip_nack_0x03/0x04/0x06`→`doip_tcp_diag_nack`；`doip_userdata_empty`→`doip_tcp_diag_uds_session_control`；`doip_sa_consistent`/`doip_sa_zero_boundary`/`doip_ta_ffff_boundary`→`doip_tcp_diag_uds_session_control` 地址面；`doip_mss_fallback`→`doip_tcp_diag_uds_transfer`/`doip_tcp_options`；`doip_uds_nrc`/`doip_uds_nrc_0x7f`/`doip_uds_nrc_0x00`→`doip_tcp_diag_uds_session_control`/`doip_neg_uds_nrc_reserved`；`doip_uds_10_nosubfunc_false`→`doip_tcp_diag_uds_read_write_did`。
- **合入（负例）**：`doip_uds_27_even_response_key`→**`doip_neg_uds_key_on_even_response`**；`doip_uds_nrc_0xff`→`doip_neg_uds_nrc_reserved`；`doip_ack_code_0x01`→**`doip_neg_ack_code_reserved`**；`doip_nack_0x00`/`doip_nack_0x01`/`doip_nack_0x09`→`doip_neg_nack_code_reserved`；`doip_uds_unknown_sid`→`doip_neg_uds_sid_unsupported`；`doip_uds_22_subfunction`→`doip_neg_uds_subfunction_conflict`；`doip_sa_mismatch`→**`doip_neg_sa_ta_consistency`**。
- **作废（原因：G-DOIP-3）**：`doip_s11_activation_fail`（旧断言=RC 拒绝后 FIN 且无诊断；链上不可表达）→ 替代覆盖 = `doip_neg_activation_denied` 族。

**F5 存活检查（6 例）—— 合入 `doip_tcp_alive_check`**
`doip_s5_alive_check`、`doip_alive_response`、`doip_alive_sa_consistent`、`doip_ipv6_alive` → `doip_tcp_alive_check`/`doip_ipv6_tcp_flow`；`doip_alive_sa_mismatch` → **`doip_neg_alive_sa_consistency`**；`doip_alive_mid_messages` → `doip_tcp_full_flow`（插入位置面）。

**F6 通用 NACK（6 例）—— 合入 `doip_tcp_generic_nack`/`doip_neg_generic_nack_code_reserved`**
`doip_s8_generic_nack`、`doip_generic_nack_0x00/0x02/0x03/0x04` → `doip_tcp_generic_nack`；`doip_generic_nack_0x05` → **`doip_neg_generic_nack_code_reserved`**。

**F7 校验专用（1 例）** `doip_messages_without_activation` → **`doip_neg_mss_below_min`**（等价覆盖：锚词 `Messages require Activation` 不变，仅形状改 layers）。

### §18.4 9.52 对账两行（清单出处声明）

- **清单出处声明**：本清单来源 = **规范/官方文档反推**（ISO 13400-2:2019 §7/§8.4.1/§8.5.1/§8.5.3/§8.5.5/§9.2.4/§9.3.6/§10.3.2/§10.4.3/§10.4.5/§11.1/§11.2.2 + ISO 14229-1 UDS 服务表），**非**引擎能力面反推；引擎侧只作现状取证（`doip.go`/`layer_gen.go` 行号、scapy 2.7.0 实读行号、tshark 3.6.14 实测 33 字段）。
- **对账两行**：**规范逻辑点总数 = 54**（§12.1 八项 8 行 + §12.2 子表① 16 格 + §12.3 子表② 30 行）；**用例覆盖数 = 38**（每点回指 T-DOIP ID，映射见 §12.1/§12.2/§12.3 「去向」列），另 **明确不支持/明确不解决 4**（八项 1 + 子表② R19/R24/R25）+ **立项 12**（八项 0 + 子表① 7 + 子表② R3/R6/R8/R20/R23）。**38 + 4 + 12 = 54 无遗漏**。
- **粒度声明**：54 点按行/格计数，行内子面缺口另登 §19，不折进 54 点、不冒充覆盖。**反查 115 例全绿 ≠ 覆盖全**（存量 115 例是旧口径，且 47 例含链不可达的 UDP 面）。

### §18.5 收官自查命令（机检，P5 执行）

```bash
# ① 非负例顶层键 = 0（白名单制，§1.13）
python3 - <<'EOF'
import json
WL={"layers","flow_control","group_id","tuples","output"}
for c in json.load(open("trafficgen/test/protocol_pcap/cases/doip.json")):
    if c["expect"].get("expect_error"): continue
    bad=[k for k in c["spec_json"] if k not in WL]
    if bad: print(c["id"], "TOPLEVEL-LEAK", bad)
EOF
# ② presence 负例形状存在（§14-P2 ①）与游离键负例存在（②）
grep -c 'doip_neg_flat_toplevel\|doip_neg_flat_field' trafficgen/test/protocol_pcap/cases/doip.json
```

## §19. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 立项号 | 缺口 | 依据（实读） | 去向 |
|---|---|---|---|
| **G-DOIP-1** | `doip` 层业务配置**无住处**：层内写 `activation` 等键被 `unknown field` 拒；层 config 无 `Fields` 故翻译不启动 → 目标形状（纯 layers）今天表达不了 | `registry.go:224-226`（无 `Fields`）；`chain_planner_translate.go:743-745`（`len(s.Fields)==0` 即 return，且无 `case "doip"`）；`complete.go:282-296`（未知键拒） | **`doip_tcp_activation_confirmation` D-DOIP-1 已给解法**（§15）；`registry.go` 属共享框架文件 → **停车上报主线程**；不挡开工 |
| **G-DOIP-2** | **UDP 三阶段（0x0001–0x0004 / 0x4001–0x4004）链上不可达** —— ISO 13400-2 的发现/实体状态/电源模式无法生成；受影响存量 47 例 | `layer_gen.go:61-74`（生成器拒）+ `:288-296`（校验器拒）；`complete.go:447-460`（`[ip,udp,doip]` 判死，锚词 `carrier`）；`registry.go:225` 单 `DependsOn ["tcp"]` | **框架级（方案 B 路径）→ 上报主线程裁定**；未裁定前按 §1.12「明确不支持 + 用例删键」；三条候选路径见 §13.3 |
| **G-DOIP-3** | **路由激活拒绝路径（RC 0x00–0x07 / 0x11 无确认）链上不可达** —— ISO §9.2 的「ECU FIN 提前终止」无法表达（挥手归 tcp 层） | `layer_gen.go:148-150`（生成器拒）、`:297-306`（校验器拒）；legacy 失败 FIN `doip.go:636-645` | 现状钉负例 **`doip_neg_activation_denied`/`doip_neg_activation_confirmation_missing`**（9.36 的 B/C 类钉现状）；框架扩展另立项 → 上报主线程 |
| **G-DOIP-4** | **0x11 二次确认被拒收尾（最终 RC=0x05 + FIN）schema 不可表达** —— `DoIPActivation` 只有单个 `ResponseCode` | `doip.go:618-623`（代码注释自认）；`types.go:9626-9642`（单字段结构） | D-DOIP-1 迁入计划：schema 扩展（加 `FinalResponseCode`）；不挡开工（用例标不适用） |
| **G-DOIP-5** | **`CheckProtoFlat` 无 `doip` 顶层子映射 presence 分支** → §1.11/§1.13 门 2① 拦不住（今天顶层 `doip` 子映射照收）；同族 `dst_mac`/顶层 `tcp` 游离键无检查 | `strategy_convert.go:8273-8517`（doip 零命中，实测全文 `"doip"` 仅 `:1287`/`:8048` 两处） | **`doip_tcp_diag_uds_read_write_did` 必加**（与 §15 翻译分支同提交，防双轨）；门2 红回滚条款适用 |
| **G-DOIP-6** | **`coverage_gate.py` 无 `check_doip` 块** → 覆盖反查对 doip 空转（方案 §2 M1：出口 0 才算过，出口 2 视红） | `trafficgen/tools/coverage_gate.py` 全文 `doip` 零命中 | 车道 B 分支内登记（合并冲突预期点） |
| **G-DOIP-7** | **EID/VIN/GID 三键在目标形状下无宿主**（死配置）：校验嵌在已删的 `Discovery != nil` 块内，生成器零读取；3 例存量受影响 | `doip.go:79-87`（嵌套在 `:62-88`）；`layer_gen.go` 全文 grep `VIN\|EID\|GID` 零命中；`doip.go:321-331`（EID 派生） | **明确不解决 + 用例删键**（§1.12）；若 G-DOIP-2 恢复 UDP 面，则三键与 EID 派生来源需重裁定（届时再立新条目） |
| **G-DOIP-8** | **`doip` 层业务字段零动态**（allowlist 无 doip）——现网多 ECU 逐流地址池无表达 | `layer_dyn.go:18-63`（无 `doip` 键）；`validate_layers.go:355-370`（对象即 `does not support dynamic`） | 三选一收口：①按 §14.12 理由「不开」（默认）②若现网多 ECU 证明需要 → 开 `tester_address`/`logical_address` 条目；**未取证前取 ①** |
| **G-DOIP-9** | **现网行为无实测证据**（三路对照路② 空）：诊断仪发现时序、公告间隔、多 ECU 并发数、激活被拒后行为、NAT 形态 | 本机无抓包、无厂商文档（§13.1 路②） | 确认方式三选一已写死（抓包/查 OEM 规范/问工具厂）；取得证据前 §13.2 的 B1/B2/B7 标「待确认」，**不写现网定论** |

**缺口数 = 9**。其中「明确不解决 + 迁入计划」项：R19（VIN/EID/GID 长度边界——三键删）、R24（`MaxDataSize` 约束宿主移出）、R25（u32 理论上限）、超时单边报文（归 tcp 层 `termination`）、0x03/0x04 协议版本（§1.3 已声明不收）、TLS/3496（§9.6 留后续扩展）、`doip: DoIP config is required`（`doip.go:39-41`，仅 flat/直调可达，链形状由补全保证 doip 层存在）——**每一项都在用例配置里删掉了对应字段**（§1.12 语义）。

---

**文档总行数**：约 2900 行
**测试用例总数（历史口径）**：203 条（T001-T203，含 v2.0.1 新增 T027a/T119a/T120a）
**现有用例文件（机器契约）**：`trafficgen/test/protocol_pcap/cases/doip.json` **115 例**（`doip_tcp_diag_uds_read_write_did` 按 §18.2 改写为纯 layers + 按 testcase §2 收敛为 41 ID）
**HexDump 场景数**：15 个（S1-S15）
**版本**：v3.0.0（P-PIPE `doip_tcp_activation_basic`–`doip_tcp_activation_oem_varlen` 补足：新增 §12–§19）
**编写日期**：2026-09-26
**状态**：`doip_tcp_activation_basic`–`doip_tcp_activation_oem_varlen` 就绪（待门1 批准）；**不宣称 suite 可运行**（本次不跑套件、不启动服务器）

## P6 附录（2026-09-28，P6 关单入版，主线程）

- P6 判词：**通过**（无 P0/P1/M；`p6-review.md` 隔离终审：门3 三条点到、§9.53 `doip_tcp_multiflow_dynamic` 18 包逐包成立、suite 80/80 独立复跑、双门绿、5 锚词三方闭合）。
- suite 实测：**80/80 = 50 正 + 30 负**（canonical :8081；P5 收敛：115→80，F1/F2 UDP 面 **47 例作废** → G-DOIP-2 open 框架 backlog，作废清单见 P4 报告；TCP 面 68 例改写纯 layers 形 + 新增 4 契约特色正例）。
- 契约口径差（P6 裁定①，enip 先例）：T-DOIP 41 ID 为 P4/P5 前目标集，落地保留存量 ID 未逐字重命名——**P6 以实测 80 例为准**，不强制 ID 重命名轮。
- 方法学偏离准予（P6 裁定②a/②b）：翻译复用扁平 parse（JSON 往返 oem 特例实证在案）+ UDP 三键入册（不入册则锚词失契约）；vin/eid/gid 不入册按 G-DOIP-7 维持。
- G-DOIP-2 维持 open（UDP 三阶段链上不可达，47 例作废诚实声明）；G-DOIP-3/4/8/9 按契约维持；离线执行器未纳入 doip（MCP 套件为权威验收通道）。
- 248 表：`docs/protocol-designs/248/57-doip-248-table.md`。

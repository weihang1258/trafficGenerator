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

**文档总行数**：约 1500 行
**测试用例总数**：203 条（T001-T203，含 v2.0.1 新增 T027a/T119a/T120a）
**HexDump 场景数**：15 个（S1-S15）
**版本**：v2.0.1
**编写日期**：2026-08-05
**状态**：待实现（实现前最后一版，所有 CRITICAL/HIGH/MEDIUM/LOW 问题已修复）

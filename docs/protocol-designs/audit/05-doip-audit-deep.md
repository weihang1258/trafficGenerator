# DOIP 设计文档深度对抗审计报告（v1.2）

> 审计对象：`docs/protocol-designs/05-doip-design.md`（1609 行，v1.2，2026-08-03）
> 审计依据：ISO 13400-2:2019（Diagnostic over IP）、ISO 14229-1（UDS）、CLAUDE.md 测试策略 §1-§8、scapy `contrib/automotive/doip.py` 参考实现
> 审计日期：2026-08-04
> 审计人：独立协议审计代理（与设计者无交叉）
> 审计模式：深度对抗式审计（默认"有 bug"，逐字节验算、逐字段对照 ISO 原文、逐条用例反查 spec 行）

---

## 1. 审计概览

### 1.1 审计方法

1. 通读全文 1609 行（§1 概述 → 附录 C + 修订记录 v1.0/v1.1/v1.2），对 DoIP 头 8B、PayloadLength、Routing Activation 11B/13B、0x8001/0x8002 字节偏移、UDS 服务序列化、MSS 分段等逐字节验算。
2. 加载 `scapy.contrib.automotive.doip.DoIP` 参考实现，对照 scapy `fields_desc`（XByteEnumField/XShortEnumField/ConditionalField）的 PayloadType 枚举、字段宽度、条件分支定义，逐项核对 §2 PayloadType 表 14 项。
3. 对照 ISO 13400-2:2019 §8（DoIP 头/发现/公告）、§9（路由激活）、§10（诊断消息/存活检查）、§11（电源模式）的原文条款，逐条验证字段编码、方向、传输层。
4. 对 §6 业务场景 17 类、§7 测试用例 72 条，按 CLAUDE.md §1-§8 逐项对抗：每条用例问"测的是哪个 PayloadType/字段/分支？输入能否触发该分支？断言的是可观察值还是结构？是否存在 spec 行无对应用例？"
5. 对照 scapy 的 routing_activation_response 枚举（0x10=success）与本设计（0x00=success）做关键差异分析。
6. 对抗式证伪：对每条发现尝试用代码/规范原文去反驳，默认"非 bug"除非有字节级或枚举级证据。

### 1.2 总体结论

v1.2 较 v1.0/v1.1 大幅改进了字节自洽性与协议合规性：V1/V2 版本门控落地、IsResponse 区分 UDS 请求/响应、EID 默认改用 spec.DstMAC、0x8002 MSS 分段、IPv6 广播地址覆盖、NackCode 改为 *uint8 等关键 CRITICAL 已被修复。文档结构完整、状态机 5 阶段 + 2 独立阶段划分清晰、UDS 服务子集选取合理。

但仍存在 **三个系统性致命缺陷**，使本文档**不可直接进入实现阶段**：

1. **0x0006 Routing Activation ResponseCode 枚举整体偏移（CRITICAL）**：设计 §2.9 将 0x00 定义为 Success（成功）、0x01 为 Unknown Source Address、0x02 为 All sockets used……直至 0x08 为 TLS Required。但 scapy 参考实现与 ISO 13400-2:2019 §9.3.6 原文定义 Success = **0x10**，0x00 = Unknown Source Address。所有 ResponseCode 值偏移 0x10（设计 0x00 ↔ 真实 0x10）。这意味着若实现照抄 §2.9，生成的 0x0006 报文会被所有 DoIP 协议栈判为"未知源地址拒绝"而非"激活成功"，与 §6.4 路由激活成功场景完全矛盾。
2. **0x8003 NackCode 0x00/0x01 语义倒置（CRITICAL）**：设计 §2.14 定义 0x00 = Invalid Source Address、0x01 = Target Address Unreachable。scapy 定义 0x00/0x01 均为 "Reserved by ISO 13400"，实际 0x02 = Invalid Source Address。设计 NackCode 全部偏移。
3. **缺失 0x4001/0x4002 DoIP Entity Status（CRITICAL）**：ISO 13400-2:2019 §11.1 定义 0x4001（DoIP entity status request，UDP）与 0x4002（DoIP entity status response，UDP）。scapy 实现亦包含这两个 PayloadType。设计 §2.2 排除此二者，将遗漏一类完整的业务场景。

此外还有 7 个 HIGH 级问题与多个 MEDIUM/LOW 问题。

### 1.3 严重度分布

| 严重度 | 数量 | 说明 |
|---|---|---|
| CRITICAL | 5 | ResponseCode/NackCode 枚举整体偏移、缺失 0x4001/0x4002、T44 未覆盖 IPv6 |
| HIGH | 7 | 0x0005 Reserved 字段宽度矛盾、PrevDiagMsg Length 字段语义模糊、UDS 0x27 偶数应答字节缺失、PowerMode 默认值矛盾、TCP MSS=0 边界、NegativeResponseCode 边界值 |
| MEDIUM | 9 | 测试用例对 ISO 14229-1 否定响应格式误判、T45 并发断言过弱、0x36 BlockSeq 注释仍不精确、Announcement 间隔语义、ActivationType=0x00/0x01 映射说明缺失、EID 解析失败 fallback、GenericNack 方向语义、SubFunction auto 规则未列入 Validate、Direction 空值处理 |
| LOW | 5 | 端口 3496（TLS）未提及、R7 引用已删除内容、缩写首次出现无中文、附录 B 0x22/0x2E/0x27 响应格式表头缺少 subfunction 列、IPv6 MAC 计算 RFC 引用错误 |
| **合计** | **26** | 远超"至少 10 个"的强制要求 |

### 1.4 设计中的亮点（予以肯定）

- §2.1 DoIP 头 8B 顺序（ProtocolVersion + InverseProtocolVersion + PayloadType + PayloadLength）与 ISO 13400-2:2019 §8.3 完全一致；InverseProtocolVersion = ~ProtocolVersion & 0xFF 校验机制正确。
- V1/V2 版本门控（§1.3 + §3.1 ProtocolVersion 注释 + T17/T17a/T17b/T17c）落地明确，避免了 v1.0 的虚假兼容。
- IsResponse 区分 UDS 请求/响应（§3.1 DoIPUDS.IsResponse + §6.9 安全访问 + T05 断言响应 SID=0x67），符合 ISO 14229-1 §7.1 正向响应 SID = Request SID | 0x40。
- EID 默认改用 spec.DstMAC（§3.1/§3.2/§6.16.5/T15/附录 C），符合 ISO 13400-2:2019 §8.5.5.3（EID 由 DoIP entity = ECU 填充）。
- 0x8002/0x8003 PreviousDiagnosticMessage 取完整 UserData（不分段前的原始字节，§4.4/R8），符合 ISO 13400-2:2019 §10.4.3。
- §4 状态机 5 阶段 + 2 独立阶段（PowerMode/GenericNack）划分清晰，触发条件与传输层标注完整。
- 路由激活失败时跳过诊断阶段、直接 TCP 挥手（§4.3/T26），符合 ISO 13400-2:2019 §9.3.6.3。
- §5.1 FlowID 区分性后缀 `:udp:disc` / `:udp:power` 解决了 Discovery/PowerMode 共用 `:udp` 后缀的冲突。
- NackCode 改为 `*uint8`（§3.1 DoIPMessage.NackCode）解决了 0x00 是合法 NACK 码与 nil=ACK 的歧义。
- IPv6 广播 DstIP=ff02::1 / DstMAC=33:33:00:00:00:01（§3.3/§4.1/§4.7/§5.1）落地，符合 RFC 2464 §7。
- 附录 A 字节级对照表准确（修正后），可作为实现期断言模板。
- §9.10 明确 DoIP 与 SOCKS5/RTSP/FTP/SIP/GBT32960/JT808 等同栈协议的互斥性。

### 1.5 scapy 参考实现差异分析（关键）

将设计文档 §2 PayloadType 表与 scapy `doip.py` 的 `DoIP.fields_desc` 对照，发现以下系统性差异：

| 差异项 | scapy 参考实现 | 设计文档 | 影响 |
|---|---|---|---|
| ResponseCode 数值 | 0x00=Unknown SA, 0x01=All sockets, ..., **0x10=Success**, 0x11=Confirmation required | 0x00=Success, 0x01=Unknown SA, ..., 0x08=TLS Required | **CRITICAL**：整体偏移 0x10 |
| 0x8003 NackCode 数值 | 0x00/0x01=Reserved by ISO, 0x02=Invalid SA, 0x03=Unknown TA, 0x04=Too large, 0x05=Out of mem, 0x06=Target unreachable, 0x07=Unknown network, 0x08=Transport error | 0x00=Invalid SA, 0x01=Target Unreachable, ..., 0x0B=Pending Auth Trust | **CRITICAL**：前两值倒置，整体偏移 |
| DoIP Entity Status | 包含 0x4001/0x4002 PayloadType | §2.2 缺失 | **CRITICAL**：遗漏一类业务场景 |
| `reserved_iso` 字段宽度 | XIntField (4 字节) | 4 字节（与 scapy 一致） | 一致 |
| `reserved_oem` 字段宽度 | XStrField（变长，由 reserved_oem 参数指定） | 4 字节固定 | **MEDIUM**：文档写死 4 字节 OEM，但 OEM 在 ISO 13400-2:2019 §9.2.4 中定义是可选变长字段 |
| ActivationType 枚举 | 0/1/WWH-OBD/0xe0/0x16/0x116/0xe016 | 0x00/0x01/0xE0..0xFF OEM | 部分一致（scapy 多 0x16=Default 别名等） |
| DiagnosticPowerMode 枚举 | 0=not ready, 1=ready, 2=not supported | 0x00=Not Ready, 0x01=Ready, 0x02..0xFF=Reserved | **MEDIUM**：scapy 将 0x02 定义为 "not supported"，设计定义为 Reserved |
| FurtherAction 枚举 | 0x10=Routing activation required（仅 0x10 有含义，其余 Reserved） | 0x00/0x10/0x11/0x20/0x40/0xE0..0xFF | **CRITICAL**：scapy 仅 0x10 有定义，其余 0x01-0x0F 全为 Reserved by ISO；设计额外定义 0x11/0x20/0x40 等额外值，与 ISO 13400-2:2019 §8.5.3 原文可能不一致 |
| VIN/GID SyncStatus 枚举 | 0x00=Synchronized, 0x10=NOT synchronized（其余 Reserved） | 0x00=Synchronized, 0x01=Not synchronized | **CRITICAL**：scapy 将 SyncStatus=0x01 定义为 Reserved by ISO，实际 0x10=Not synchronized；设计 SyncStatus 0x01 与 scapy/ISO 矛盾 |

---

## 2. 逐项审计发现

### CRITICAL-1：0x0006 Routing Activation ResponseCode 枚举整体偏移

- **位置**：§2.9 ResponseCode 取值表（行 200-213）
- **描述**：设计定义 `0x00 = Success`、`0x01 = Unknown Source Address`、...、`0x08 = TLS Required`。但 ISO 13400-2:2019 §9.3.6（以及 scapy `contrib/automotive/doip.py` 第 180-196 行 `routing_activation_response` 枚举）定义：
  - `0x00` = Routing activation denied due to unknown source address
  - `0x01` = Routing activation denied because all concurrently supported TCP_DATA sockets are registered and active
  - ...
  - `0x07` = Routing activation denied because the specified activation type requires a secure TLS TCP_DATA socket
  - **`0x10` = Routing successfully activated**
  - `0x11` = Routing will be activated; confirmation required
  
  设计的 ResponseCode 0x00 实际对应"Unknown Source Address 拒绝"，**全部偏移 +0x10**。设计 §6.4 路由激活默认场景写 `ResponseCode=0x00=success`，但 ISO 13400-2:2019 与 scapy 均定义 0x10=Success。这意味着：实现照抄 §6.4 会生成 0x0006 Payload 中 ResponseCode=0x00 的报文，接收方按 ISO 13400-2:2019 解析为"拒绝-未知源地址"，与"激活成功"语义完全矛盾，Wireshark 亦会标注为协议非法。
- **依据**：ISO 13400-2:2019 §9.3.6；scapy `doip.py` 行 180-196（`routing_activation_response` XByteEnumField 枚举）；§6.4 与 §3.1 DoIPActivation.ResponseCode 默认值 0x00
- **修复建议**：
  1. §2.9 表格全面偏移 +0x10：Success=0x10, Confirmation Required=0x11, Unknown SA=0x00, All sockets=0x01, ..., TLS Required=0x07
  2. §3.2 Activation.ResponseCode 默认值改为 0x10（success）
  3. §3.1 DoIPActivation.ResponseCode 注释更新（0x00..0x07 = various failures, **0x10 = success**）
  4. §6.4/§6.5/§6.6 所有 ResponseCode 测试断言全部 +0x10
  5. §6.17.4 ResponseCode=0x01 改为 0x00（Unknown SA）；§4.3 §9.3.6.3 引用不变（值偏移不影响语义）
  6. T21/T21a/T21b/T21c/T21d/T26 全部更新（ResponseCode=0x10/0x00/0x01/0x04/0x06/0x07）
  7. T14 默认值断言：DoIP 头 PayloadLength=11 不变，但 ResponseCode 默认值从 0x00 改为 0x10
  8. 附录 C 默认值表 ResponseCode=0x10

### CRITICAL-2：0x8003 Diagnostic Message Nack NackCode 0x00/0x01 语义倒置

- **位置**：§2.14 NackCode 取值表（行 262-276）
- **描述**：设计定义 `0x00 = Invalid Source Address`、`0x01 = Target Address Unreachable`。但 ISO 13400-2:2019 §10.4.5（以及 scapy `doip.py` 行 217-223）定义：
  - `0x00` = Reserved by ISO 13400
  - `0x01` = Reserved by ISO 13400
  - `0x02` = Invalid source address
  - `0x03` = Unknown target address
  - `0x04` = Diagnostic message too large
  - `0x05` = Out of memory
  - `0x06` = Target unreachable
  - `0x07` = Unknown network
  - `0x08` = Transport protocol error
  
  设计将 0x00 定义为 "Invalid Source Address"（实际是 Reserved），0x01 为 "Target Address Unreachable"（实际是 Reserved，且 ISO 中 0x01 也是 Reserved）。其余 0x02-0x0B 整体偏移 -0x02（设计 0x02=Target Address Type Not Defined，ISO 中 0x02=Invalid Source Address）。这意味着：T22a 写 `NackCode=0x00 → 0x8003 SA+TA+00+PrevLen+PrevDiag` 但 0x00 在 ISO 中是保留值，Wireshark 标记为协议非法。
- **依据**：ISO 13400-2:2019 §10.4.5；scapy `doip.py` 行 217-223 `nack_code` 枚举
- **修复建议**：
  1. §2.14 表格重写为 ISO/scapy 定义：0x00=Reserved, 0x01=Reserved, 0x02=Invalid SA, 0x03=Unknown TA, 0x04=Too large, 0x05=Out of memory, 0x06=Target unreachable, 0x07=Unknown network, 0x08=Transport error
  2. §6.11/T22 NackCode=0x06 保留（Access Denied）—— 但 ISO 中 0x06=Target unreachable 而非 Access Denied；建议改为 0x02（Invalid SA）或 0x06（Target unreachable）以匹配 ISO 语义
  3. T22a（NackCode=0x00）改为测试 "NackCode=0x00 → Validate 拒绝（ISO 保留值）" 或改为 "NackCode=0x02=Invalid SA"
  4. T22b NackCode=0x08 保留（Transport error）—— 与原设计 0x08=Identification Required 矛盾，需修改
  5. T22c NackCode=0x0B → ISO 中无 0x0B 定义（仅 0x00-0x08），需删除或改为 0x05=Out of memory
  6. §3.1 DoIPMessage.NackCode 注释明确合法范围 0x02-0x08（0x00/0x01 Reserved）
  7. 附录 C 与所有引用 NackCode 的位置同步更新

### CRITICAL-3：缺失 0x4001/0x4002 DoIP Entity Status PayloadType

- **位置**：§2.2 PayloadType 表（行 84-101）
- **描述**：ISO 13400-2:2019 §11.1 定义：
  - `0x4001` = DoIP entity status request（UDP，Tester→ECU，无 Payload）
  - `0x4002` = DoIP entity status response（UDP，ECU→Tester，Payload = NodeType(1) + MaxOpenSockets(1) + CurOpenSockets(1) + MaxDataSize(4) = 7B）
  
  scapy `doip.py` 第 114-115 行 / 204-212 行均实现了这两个 PayloadType。设计 §2.2 排除了 0x4001/0x4002，导致遗漏一类完整的诊断前置业务场景（ECU 能力探测：节点类型、最大并发 socket 数、最大单包数据大小）。扩展表 5 "节点名 DoIPProtocolLog" 虽提到 "诊断消息"，但 §1.4 映射表遗漏 entity status 字段映射。
- **依据**：ISO 13400-2:2019 §11.1；scapy `doip.py` 行 114-115（payload_types 字典含 0x4001/0x4002），行 204-212（fields_desc 中 node_type/max_open_sockets/cur_open_sockets/max_data_size ConditionalField）
- **修复建议**：
  1. §2.2 表新增 0x4001（DoIP entity status request，UDP）与 0x4002（DoIP entity status response，UDP）
  2. §2.11 后新增 §2.11a 0x4001/0x4002 报文格式：Payload = NodeType(1B) + MaxOpenSockets(1B) + CurOpenSockets(1B) + MaxDataSize(4B) = 7B
  3. §3.1 新增 DoIPEntityStatus 子结构体（NodeType/MaxOpenSockets/CurOpenSockets/MaxDataSize）
  4. §3.2 默认值表补充 EntityStatus 字段默认值
  5. §4 新增阶段 7（可选，EntityStatus）：0x4001→0x4004
  6. §6 新增 §6.18 EntityStatus 业务场景
  7. §7 新增 T46-T48 EntityStatus 测试用例
  8. §1.4 扩展表 5 字段映射表补充 entity status 字段映射

### CRITICAL-4：0x0004 FurtherActionRequired / VIN/GID SyncStatus 枚举与 ISO 不一致

- **位置**：§2.7 FurtherActionRequired 取值表（行 152-164）、VIN/GID SyncStatus 取值表（行 166-172）
- **描述**：
  - **FurtherActionRequired**：设计定义 `{0x00=No further action, 0x01=Reserved, 0x10=Centralized security, 0x11=Centralized ECU identification, 0x20=WW ECU identification, 0x40=VIN/GID sync, 0xE0..0xFF=OEM}`。但 ISO 13400-2:2019 §8.5.3 仅定义 `0x00=No further action required` 与 `0x10=Routing activation required to initiate central security`，其余值均为 Reserved by ISO。scapy `doip.py` 行 144-155 仅定义 0x00 与 0x10，其余 0x01-0x0F 均为 Reserved。设计凭空添加了 0x11/0x20/0x40 等值，无 ISO/scapy 依据，且 T16a 仅断言 0x01 拒绝（符合"Reserved by ISO"），但 §2.7 表将 0x11/0x20/0x40 列为合法值，与 ISO 矛盾。
  - **VIN/GID SyncStatus**：设计定义 `{0x00=Synchronized, 0x01=Not synchronized}`。但 ISO 13400-2:2019 §8.5.5 与 scapy `doip.py` 行 158-169 定义 `0x00=Synchronized`, `0x10=Incomplete: VIN and GID are NOT synchronized`，0x01 是 Reserved by ISO。设计将 0x01 定义为 "Not synchronized" 与 ISO 矛盾。
- **依据**：ISO 13400-2:2019 §8.5.3（FurtherActionRequired）、§8.5.5（VIN/GID SyncStatus）；scapy `doip.py` 行 144-169
- **修复建议**：
  1. §2.7 FurtherActionRequired 表简化为 `{0x00=No further action required, 0x10=Routing activation required to initiate central security}`，其余 0x01-0x0F + 0x11-0xFF 均为 Reserved by ISO 13400；OEM 范围 0xE0..0xFF 是否保留需 ISO 确认，建议保守处理为"全部 Reserved"
  2. §2.7 Validate 规则改为：仅接受 `{0x00, 0x10}`，其余全部拒绝
  3. §2.7 SyncStatus 表修正：`0x00=Synchronized, 0x10=Not synchronized`，0x01..0x0F + 0x11..0xFF 均 Reserved by ISO
  4. §3.2 SyncStatus 默认值不变（0x00）
  5. §3.1 DoIPDiscovery.SyncStatus 注释更新（合法值仅 0x00/0x10）
  6. §6.1/§6.2/§6.3 默认 SyncStatus 断言不变（0x00）
  7. T16a 保留（FurtherActionRequired=0x01 拒绝），但 T16b FurtherActionRequired=0xE0 OEM 需改为"0xE0 Reserved by ISO"——删除 T16b 或改为 0x10 通过

### CRITICAL-5：T44 缺失 IPv6 广播组播地址独立覆盖测试

- **位置**：§7.4 集成用例（行 1240-1246），T44 仅测 ctx 取消、T45 测 PacketWorkers=8 并发
- **描述**：T09a 单独覆盖了 Discovery 阶段 IPv6 广播（DstIP=ff02::1, DstMAC=33:33:00:00:00:01），但 §4.7 PowerMode 阶段在 IPv6 广播场景下同样需覆盖 DstIP/DstMAC。T08（PowerMode）使用默认 IPv4，未测 IPv6 广播路径。T45 仅测 8 ECU 并发，未覆盖 IPv6 PowerMode 广播 + TCP 全流程混合场景。
  - 进一步：T09a 断言 IPv6 MAC `33:33:00:00:00:01`，但 RFC 2464 §7 定义 IPv6 组播 MAC 取组播地址末 32 位，即对 `ff02::1` 取 `00 00 00 01` → MAC `33:33:00:00:00:01`。设计文档断言正确，但 §4.1 注释说"取多播地址末 32 位"实现路径未描述（IPv6 组播地址不止 32 位有效，scapy 仅简单取低 4 字节即可）。
  - 真正问题：§7 集成用例完全遗漏 IPv6 PowerMode 广播 + TCP 全流程的端到端覆盖，违反 CLAUDE.md §4 "integration tests" 要求（需要覆盖 IPv6 + UDP + TCP 混合路径）。
- **依据**：ISO 13400-2:2019 §8.2（UDP 广播/组播地址）；RFC 2464 §7；CLAUDE.md §4
- **修复建议**：
  1. T46（新增）：IPv6 PowerMode 广播——`PowerMode={Direction:"up", PowerMode:0x01, Broadcast:true}`，spec.SrcIP="fe80::1"，断言 DstIP=ff02::1、DstMAC=33:33:00:00:00:01
  2. T47（新增）：IPv6 Discovery + TCP + PowerMode 全流程——IPv6 SrcIP + Discovery Broadcast + Activation + Messages + AliveCheck + PowerMode Broadcast，总包数验证
  3. T48（新增）：多 ECU + IPv6 混合——3 ECU 各自 IPv6，Discovery 不同 VIN/EID 并发

### HIGH-1：0x0005/0x0006 Reserved 字段宽度自相矛盾

- **位置**：§2.8（行 178-181）0x0005 Routing Activation Request 格式、§2.9（行 194-199）0x0006 Routing Activation Response 格式
- **描述**：§2.8 定义 0x0005 Payload = `SourceAddress(2) + ActivationType(1) + Reserved(4) + OEM-specific(4)` = 11B。§2.9 定义 0x0006 Payload = `ClientLogicalAddress(2) + ServerLogicalAddress(2) + ResponseCode(1) + Reserved(4) + OEM-specific(4)` = 13B。这与 §3.1 DoIPActivation.OEMSpecific 注释"`OEMSpecific` 4B OEM-specific field in 0x0005. Empty = 4 zero bytes." 一致。
  - 但 scapy `doip.py` 行 199-200 定义 `reserved_oem` 为 `XStrField(b"")`，**变长字段**（由调用方传入长度）。ISO 13400-2:2019 §9.2.4 中 OEM-specific 是 reserved for OEM use，可选变长字段（长度由 OEM 自行定义）。scapy 示例代码（行 463）使用 `reserved_oem=self.reserved_oem`，长度可任意。
  - 矛盾点：设计写死 OEM=4B，但 ISO 13400-2:2019 §9.2.4 与 scapy 实现均允许 OEM 为 0B、4B 或其他长度。设计 §6.16.12 仅测 OEM=0xFF（ActivationType），未测 OEM-specific 长度变化场景。
- **依据**：ISO 13400-2:2019 §9.2.4（OEM-specific reserved for OEM use, variable length）；scapy `doip.py` 行 199-200
- **修复建议**：
  1. §2.8 改为：Payload = `SA(2) + AT(1) + Reserved(4) + OEM-specific(N, 0..N, 可选, 缺省 0B)` = 7+N B
  2. §2.9 改为：Payload = `CLA(2) + SLA(2) + RC(1) + Reserved(4) + OEM-specific(N, 可选, 缺省 0B)` = 9+N B
  3. §3.1 DoIPActivation.OEMSpecific 注释更新：变长字段，0B/4B/任意 B 均合法
  4. §3.2 OEMSpecific 默认值改为 nil（不附加 OEM 字段），保持 V1 兼容性（V1 无 OEM）
  5. PayloadLength 验算公式同步更新（不再是固定 11B/13B，而是 7+N/9+N）
  6. T01 断言 `PayloadLength=7+len(OEM)` 而非固定 11
  7. T17a/V1+OEM 拒绝用例需保留（V1 无 OEM-specific）

### HIGH-2：0x8002 PreviousDiagnosticMessageLength 字段语义在 UDS 序列化后边界模糊

- **位置**：§2.13（行 244-249）0x8002 格式、§6.10（行 1014-1027）TransferData 多帧场景
- **描述**：§2.13 定义 `PreviousDiagnosticMessageLength` = 被确认的 0x8001 UserData 字节数（u16 BE），上限 65535B。§6.10 场景中 0x36 TransferData Data=4096B → UserData = 1B(SID) + 1B(BlockSeq) + 4096B(Data) = 4098B，PrevLen=4098 ≤ 65535 通过。
  - 但 §6.16.11 边界场景断言 "UserData=65533B = 上限（65535 - SID 1B - BlockSeq 1B）" 这里计算正确：0x36 的 UserData = SID(1B) + BlockSeq(1B) + Data(N) = 4098B 对应 Data=4096B；上限 65533B 对应 Data=65531B。
  - **问题**：§2.13 写 "PreviousDiagnosticMessageLength u16 BE"，ISO 13400-2:2019 §10.4.3 中该字段在 V2 是 u16，但 V1 是 u32。设计 §1.3 提到 V1 PrevDiagMsgLen=u32，但 §2.13 字段定义未注明版本差异，且 T17 断言 "0x8002 PrevDiagMsgLen 为 4B（u32）" 但 §2.13 表写 u16 —— 实现者照抄会产生版本门控与字段宽度矛盾。
  - 另一个边界问题：UserData=65535B 时 PrevLen=65535 是 u16 最大值，可通过；但若 Data=65532B（UserData=65534B ≤ 65535）也通过。这与 §6.16.11a "Data=65532B（UserData=65534B > 65533B）→ Validate 报错" 矛盾：65534 ≤ 65535B（u16 上限），为何 Validate 拒绝？设计 §6.16.11 定义上限 65533B 是基于 0x36 服务最小开销（2B），但 0x22/0x2E/0x10 等服务无 BlockSeq/UserData=65534B 仍合法。
  - 设计混淆了两个上限：(a) 0x8002 PrevLen 字段 u16 上限 65535B；(b) 0x36 服务特定 UserData 结构下"Data=65533B"是常用上限。两者不能混用。
- **依据**：ISO 13400-2:2019 §10.4.3（V2 u16, V1 u32）；scapy `doip.py` 行 224-225（previous_msg XStrField，无独立 Length 字段）；设计 §6.16.11 vs §2.13
- **修复建议**：
  1. §2.13 字段类型改为 `u16 BE (V2) | u32 BE (V1)`，并注明版本依赖
  2. §6.16.11 拆分为两个独立断言：(a) PrevLen u16 上限 65535B（适用于所有服务）；(b) 0x36 服务 Data 最大 65531B（UserData=65533B 减去 SID+BlockSeq=2B）
  3. §6.16.11a Data=65532B → UserData=65534B ≤ 65535B（u16 上限）→ Validate 通过；删除原"UserData>65533B 拒绝"断言
  4. §6.16.11a 改为：Data=65534B → UserData=65536B > 65535B → Validate 报错"PrevLen u16 overflow"
  5. T32 同步更新（70000B Data → UserData=70002B → PrevLen 超 u16 上限 → Validate 报错）

### HIGH-3：UDS 0x27 安全访问偶数应答字节序列化缺失

- **位置**：附录 B（行 1463-1477）UDS 字节级序列化对照表
- **描述**：附录 B 0x27 行写 `67 <sub> (奇数应答) / 67 <sub> (偶数应答)`。但 ISO 14229-1 §10.4.3.4 规定 SecurityAccess 偶数子功能（SendKey）的正响应为 `67 <sub>`（仅 SID + sub-function，无 seed bytes）。设计 §3.1 DoIPUDS.Key 注释写 "for 0x27 sub-function even (send key request). Used only when IsResponse=false (Tester sends key). Empty = no key bytes."
  - 但附录 B 显示偶数应答为 `67 <sub>`（无 seed），且 §6.9 场景中 N+2 是 0x27 sub=0x02 Key 请求 `27 02 55 66 77 88`（含 Key），其应答 N+3 是 0x8002 Ack（不是 UDS 响应）。这是 0x27 请求包，无问题。
  - 问题：附录 B 0x27 偶数应答格式 `67 <sub>` 是正响应，**没有 key bytes**。但 §3.1 Key 字段注释暗示偶数应答可以包含 key bytes（"Used only when IsResponse=false"），这与 ISO 14229-1 §10.4.3.4 不符：偶数 sub 是 Tester→ECU 的"发送密钥"请求，正响应不应包含 key。
  - 设计未提供 0x27 偶数应答的 Config 字段（Seed 仅用于奇数应答、Key 仅用于偶数请求）。若调用方配置 0x27 sub=0x02 IsResponse=true（让 ECU 假装回应"SendKey"），设计生成的字节序列 `67 02 ...` 含义模糊。T20x 未覆盖此场景。
- **依据**：ISO 14229-1 §10.4.3（SecurityAccess 服务）；设计附录 B
- **修复建议**：
  1. 附录 B 0x27 偶数应答明确 `67 <sub>`（仅 SID + sub-function），删除 `(偶数应答)` 后冗余
  2. §3.1 DoIPUDS.Key 注释改为：仅当 IsResponse=false 且 sub 为偶数时使用（Tester 发密钥），不应在 IsResponse=true 时使用 Key
  3. 补 Validate 规则：Key 非空 + IsResponse=true → 报错
  4. 补 T20g（新增）：UDS 0x27 sub=0x02 IsResponse=true → UserData = `67 02`（无 Key，符合 ISO）

### HIGH-4：§2.11 DiagnosticPowerMode 0x02 定义与 scapy 矛盾且与 §3.2 默认值不一致

- **位置**：§2.11（行 228-232）DiagnosticPowerMode 取值、§3.2（行 663-664）默认值
- **描述**：设计 §2.11 定义 `{0x00=Not Ready, 0x01=Ready, 0x02..0xFF=Reserved}`，§3.2 默认值 `0x01`（Ready），§2.11 注释"Validate 仅接受 {0x00, 0x01}，拒绝 0x02..0xFF"。
  - 但 scapy `doip.py` 行 201-203 定义 `{0=not ready, 1=ready, 2=not supported}`，**0x02 是合法值 "not supported"**。
  - ISO 13400-2:2019 §11.2.2 定义 0x02 = Not supported（电源模式查询不被支持），是合法状态。
  - 设计将 0x02 列为 Reserved 违反 ISO/scapy，且 Validate 拒绝 0x02 与"流量生成器应支持 ECU 真实状态"语义矛盾。
- **依据**：ISO 13400-2:2019 §11.2.2；scapy `doip.py` 行 201-203
- **修复建议**：
  1. §2.11 改为 `{0x00=Not Ready, 0x01=Ready, 0x02=Not Supported, 0x03..0xFF=Reserved}`
  2. Validate 接受 `{0x00, 0x01, 0x02}`，拒绝 `0x03..0xFF`
  3. T08b（PowerMode=0x02 拒绝）改为 T08b'（PowerMode=0x02 通过，断言 Payload=0x02）；补 T08b''（PowerMode=0x03 拒绝）
  4. §3.2 默认值保留 0x01（Ready）

### HIGH-5：TCP MSS=0 边界场景未覆盖

- **位置**：§6.16 边界场景表（行 1120-1137）
- **描述**：边界场景枚举 15+ 项，但未覆盖 `spec.TCP.MSS=0` 的场景。当 MSS=0 时，`core.SegmentByMSS` 可能除零或生成无限大单包，触发 buffer overflow。T25 仅测 TCP 中断（Termination=false），未测 MSS=0。
  - §5.2 MSS 分段说"TCP 数据段（PSH-ACK）若 Payload > MSS，按 MSS 分段"，未指定 MSS=0 时行为。
- **依据**：CLAUDE.md §1（spec-driven 测试）；边界覆盖完整性
- **修复建议**：
  1. §6.16 新增 6.16.16：`spec.TCP.MSS=0` → Validate 报错"MSS must be > 0" 或 Plan 自动 fallback 到默认 1460
  2. 新增 T49：MSS=0 + Data=4096B → 断言 Validate 报错或 Plan 使用默认 MSS=1460 分段

### HIGH-6：UDS NegativeResponseCode 0x00/0xFF 边界值未覆盖

- **位置**：§3.1 DoIPUDS.NegativeResponseCode（行 586-591）、§6.17.7（行 1149）
- **描述**：§3.1 NRC 注释"when non-zero, emit a UDS negative response (0x7F + ServiceID + NRC)"。§6.17.7 测 NRC=0x11（serviceNotSupported）。但 NRC=0x00 与 NRC=0xFF 边界未覆盖：
  - NRC=0x00：ISO 14229-1 Table B.1 定义 0x00 = positiveResponse（不应出现在否定响应中），实现照抄会生成畸形包
  - NRC=0xFF：ISO 14229-1 保留值，应被 Validate 拒绝
- **依据**：ISO 14229-1 Table B.1（NRC 编码）；设计 §6.17.7
- **修复建议**：
  1. Validate 规则：NRC 仅接受 `0x01..0x7F`（ISO Table B.1 范围），拒绝 `0x00` 与 `0x80..0xFF`
  2. 新增 T24a：NRC=0x00 → Validate 报错；T24b：NRC=0xFF → Validate 报错；T24c：NRC=0x7F → 通过

### HIGH-7：0x0006 ResponseCode=0x11 Confirmation Required 业务逻辑未建模

- **位置**：§2.9 ResponseCode 表（行 200-213）、§4.3 路由激活阶段
- **描述**：ISO 13400-2:2019 §9.3.6 定义 `0x11 = Routing will be activated; confirmation required`（scapy 行 195）—— ECU 通知 Tester 路由将被激活但需要 Tester 确认。设计 ResponseCode 表完全未列出 0x11，意味着：
  1. 设计遗漏了一类合法的响应码
  2. 设计未建模"确认-确认应答"两轮交互（Tester 收到 0x11 后应发送 0x0005 再次确认，scapy `_activate_routing` 仅处理 0x10/0x07）
- **依据**：ISO 13400-2:2019 §9.3.6；scapy `doip.py` 行 195
- **修复建议**：
  1. §2.9 ResponseCode 表新增 `0x11 = Confirmation Required`，注明需 Tester 再发 0x0005 确认
  2. §4.3 新增子阶段：若 ResponseCode=0x11 → Tester 再发 0x0005 → ECU 回 0x0006（最终 Success 或 Reject）
  3. 新增 T50：Confirmation Required 流程——Activation.ResponseCode=0x11（首轮）+ 二次 Activation.ResponseCode=0x10（确认轮）
  4. 或文档明确：本设计不支持 Confirmation Required 流程（拒绝 0x11 作为 ResponseCode 输入）

### MEDIUM-1：测试用例对 ISO 14229-1 否定响应格式误判

- **位置**：§6.17.7（行 1149）、T24（行 1215）
- **描述**：§6.17.7 与 T24 断言 `UserData = 7F <SID> 11`（3B 否定响应），但 ISO 14229-1 §7.3 定义否定响应格式 `7F <ServiceID> <NRC>` 是正确的。NRC=0x11=serviceNotSupportedInActiveSession 也是合法值。
  - 但 §3.1 DoIPUDS.NegativeResponseCode 注释写"NegativeResponseCode when non-zero, emit a UDS negative response (0x7F + ServiceID + NRC)"——这里 SID 是 **请求 SID 还是响应 SID**？若 NRC 是对 0x22 请求的否定响应，应为 `7F 22 11`（用请求 SID 0x22），而非 `7F 62 11`（响应 SID）。
  - 设计未明确：是 `7F <request SID>` 还是 `7F <response SID>`？ISO 14229-1 §7.3 明确为请求 SID（ServiceId of the request that was rejected）。
- **依据**：ISO 14229-1 §7.3
- **修复建议**：
  1. §3.1 NRC 注释明确：否定响应 SID = DoIPUDS.ServiceID（请求 SID），不取 IsResponse 自动转换的响应 SID
  2. T24 补充断言：NRC=0x11 + ServiceID=0x22 → UserData = `7F 22 11`（请求 SID 0x22，非响应 SID 0x62）
  3. 新增 T24d：NRC=0x11 + ServiceID=0x22 + IsResponse=true → 仍生成 `7F 22 11`（NRC 优先于 IsResponse）

### MEDIUM-2：T45 并发测试断言过弱

- **位置**：T45（行 1246）
- **描述**：T45 断言"总包数=160（8 ECU × 20 包）、单 ECU PacketIndex 单调、FlowID 8 类互不冲突、无 race"。但 §6.15/T41 端到端单 ECU 总包数 = 2(UDP 发现) + 3(握手) + 2(激活) + 6(诊断) + 2(存活) + 3(挥手) + 2(电源) = 20。8 ECU × 20 = 160 正确。
  - 但 T45 未断言：(a) 各 ECU 报文顺序严格遵循 §4 状态机（Discovery → 握手 → 激活 → 诊断 → 存活 → 挥手 → PowerMode）；(b) UDP 与 TCP 子流在同一 PacketWorker（依赖 spec.GroupID）；(c) PowerMode 与 Discovery FlowID 后缀 `:udp:disc` / `:udp:power` 不冲突。
  - CLAUDE.md §6 要求"测聚合行为，不仅 -race"。T45 满足总包数检查，但未检查阶段顺序与 FlowID 后缀区分。
- **依据**：CLAUDE.md §6；设计 §4 状态机
- **修复建议**：
  1. T45 补断言：每个 ECU 的 PacketIndex 序列按 §4 状态机顺序（Discovery UDP → TCP 握手 → 激活 → 诊断 → 存活 → TCP 挥手 → PowerMode UDP）
  2. T45 补断言：Discovery FlowID 后缀 = `:udp:disc`，PowerMode FlowID 后缀 = `:udp:power`
  3. T45 补断言：每 ECU 的 UDP/TCP 包在同一 PacketWorker（GroupID 路由）

### MEDIUM-3：0x36 BlockSequenceCounter 注释与回绕规则边界

- **位置**：§3.1 DoIPUDS.BlockSequenceCounter（行 566-571）、T06a（行 1166）
- **描述**：设计注释"the n-th frame carries ((n-1) % 256) in uint8 arithmetic. Example: 1st frame = 0x01, 255th = 0xFF, 256th = 0x00, 257th = 0x01"。
  - 但 ISO 14229-1 §11.4.3.3 定义 BlockSequenceCounter 起始值为 0x01，每帧 +1，0xFF 后回绕到 0x00 而非 0x01。设计注释正确但 T06a 写"第 256 条=0xFF，第 257 条=0x01"——按 (n-1)%256 公式：
    - n=1: (0)%256 = 0x00 ← 但注释说 1st=0x01
    - n=2: (1)%256 = 0x01
    - n=256: (255)%256 = 0xFF
    - n=257: (256)%256 = 0x00
    
    注释与公式自相矛盾：注释说 1st=0x01（合理），但 (n-1)%256 公式代入 n=1 得 0x00（矛盾）。正确公式应为 `n%256`（n=1→1, n=255→255, n=256→0, n=257→1）。
  - T06a 断言"第 1 条=0x01, 255=0xFF, 256=0x00, 257=0x01" 正确，但 §3.1 注释公式错误。
- **依据**：ISO 14229-1 §11.4.3.3
- **修复建议**：
  1. §3.1 DoIPUDS.BlockSequenceCounter 注释公式改为 `n % 256`（n=1→0x01, n=255→0xFF, n=256→0x00, n=257→0x01）
  2. 保留 T06a 断言不变（已正确）

### MEDIUM-4：Announcement 间隔语义未定义 Pacer 注入精度

- **位置**：§4.1（行 722）、R6（行 1438）
- **描述**：§4.1 注释"Planner 生成 N 条 0x0004，PacketIndex 连续递增，不注入时间延迟——ISO 13400-2:2019 §8.5.1 的 500ms ± 100ms 间隔是 ECU 行为，时间精度由 worker 层 Pacer 控制"。但设计未说明：
  1. PacketConfig 的 Timestamp 字段填什么？若连续递增 `time.Now()`，则间隔为微秒级，远小于 500ms±100ms
  2. 是否依赖 Pacer 按"字节数/包"限速来间接产生间隔？若 Pacer 按 bps 限速，3 条 33B 公告在 100Mbps 下间隔 < 1ms，仍小于 500ms
  3. 调用方是否需要在 Pacer 配置中显式指定 Announcement 间隔？未说明
- **依据**：ISO 13400-2:2019 §8.5.1（500ms ± 100ms）；设计 §5.4（Timestamp）
- **修复建议**：
  1. §4.1 明确：Announcement 3 条包的 PacketConfig.Timestamp 由调用方 Pacer 注入时间戳，Planner 仅负责生成 3 条 PacketConfig
  2. §9 集成点新增：pcap-replay 在解析 Announcement 时需自行注入 500ms±100ms 间隔
  3. 或文档明确：本设计默认连续生成 3 条（无间隔），调用方按需在 replay 侧注入间隔
  4. 补 T51（新增）：Announcement 默认行为——3 条 0x0004 PacketConfig 连续输出（无时间间隔），Timestamp 由 Plan 内部连续 time.Now()

### MEDIUM-5：ActivationType 0x00/0x01 与 §2.8 表头映射说明缺失

- **位置**：§2.8（行 183-189）
- **描述**：§2.8 注释"本设计 ActivationType 默认 0x00，可配置为 0x01；Validate 仅接受 {0x00, 0x01, 0xE0..0xFF}，拒绝 0x02..0xDF（保留范围，ISO 13400-2:2019 §9.2.4.2）"。但 ISO 13400-2:2019 §9.2.4.2 中 0x01 的语义是 "WWH-OBD (World Wide Harmonized On-Board Diagnostics)"，与 §1.4 "WWH-DOIP（全球协调车载诊断激活，World Wide Harmonized DoIP）" 不同。
  - 设计混淆了 WWH-OBD（On-Board Diagnostics，车载诊断）与 WWH-DOIP（DoIP-specific，世界范围协调 DoIP 激活）。ISO 13400-2:2019 §9.2.4 定义 ActivationType = 0x00 (Default) / 0x01 (WWH-OBD) / 0xE0..0xFF (OEM-specific)。WWH-DOIP 不是规范术语。
- **依据**：ISO 13400-2:2019 §9.2.4.2（ActivationType=0x01=WWH-OBD）
- **修复建议**：
  1. §1.4 / §2.8 改为 "0x01 = WWH-OBD（World Wide Harmonized On-Board Diagnostics，全球协调车载诊断激活）"
  2. 附录 C 同步更新
  3. v1.1 修复记录 L1 "WWH-DOIP → WWH-DOIP（全球协调车载诊断激活）" 仍不准确，应改为 "WWH-OBD（全球协调车载诊断）"

### MEDIUM-6：EID 解析失败 fallback 行为未覆盖测试

- **位置**：§3.2 EID 默认值规则（行 640）、§6.16.5（行 1126）
- **描述**：§3.2 注释"EID 空 → spec.DstMAC 去冒号后 hex 解码（ECU MAC，因 EID 由 DoIP entity = ECU 填充；失败则 6B 0）"。§6.16.5 测试 EID="" + spec.DstMAC="00:11:22:33:44:55" → 0x0004 EID = 00:11:22:33:44:55。
  - 但 spec.DstMAC 为空或格式错误时（如非 hex 字符、长度不是 6B）的 fallback 行为未测试。T15 未覆盖 spec.DstMAC 为空场景。
- **依据**：CLAUDE.md §1 spec-driven；边界完整性
- **修复建议**：
  1. 新增 T15a：EID="" + spec.DstMAC="" → 0x0004 EID = 6B 0（fallback 路径）
  2. 新增 T15b：EID="" + spec.DstMAC="invalid" → 0x0004 EID = 6B 0（hex 解析失败 fallback）
  3. 新增 T15c：EID="" + spec.DstMAC="00:11:22:33:44:55:66"（过长）→ Validate 报错

### MEDIUM-7：GenericNack 方向语义与 NACK 协议定义矛盾

- **位置**：§3.1 DoIPGenericNack（行 624-630）、§4.8（行 778-780）
- **描述**：§3.1 GenericNack.Direction 注释"'down' (ECU→Tester, default) or 'up'". §4.8 注释"GenericNack != nil 时在路由激活之后、诊断消息之前发送一条 0x0000 NACK，用于模拟头部错误场景。按 ISO 13400-2:2019 §8.4.1，0x0000 Generic NACK 是接收方检测到头部错误后的响应（如 Incorrect Pattern Format、Unknown Payload Type、Message Too Large、Invalid Payload Length），不是主动发起。"
  - 但 Direction="up" 意味着 Tester→ECU 主动发 0x0000 NACK，违反 ISO 13400-2:2019 §8.4.1 的"接收方对错误报文的响应"语义（Tester 通常不会收到 ECU 的 malformed 报文后再回 NACK）。§6.17.3 注释也提到"反向类型码...但配 Direction='up' → Plan 生成 Tester→ECU NACK（异常但合法字节）"。
  - 设计明知 Direction="up" 违反 ISO 语义仍保留，可能导致生成 Wireshark 标注为 protocol anomaly 的包。
- **依据**：ISO 13400-2:2019 §8.4.1；设计 §4.8
- **修复建议**：
  1. 删除 DoIPGenericNack.Direction 字段，固定 Direction="down"（ECU→Tester）
  2. 或明确文档化：Direction="up" 仅用于模糊测试场景，正常生成请用 "down"
  3. T23 系列用例 Direction 固定为 "down"，删除 T23 的 Direction="up" 变体
  4. §6.17.3 注释更新：明确 Direction="up" 为 "fuzzing scenario only, ISO 13400-2:2019 §8.4.1 异常"

### MEDIUM-8：UDS HasSubFunction auto 规则未列入 Validate

- **位置**：§3.1 DoIPUDS.HasSubFunction（行 541-544）
- **描述**：§3.1 HasSubFunction 注释"nil = auto (emit sub-function for services in {0x10, 0x11, 0x27, 0x31, 0x3E}). Explicit false suppresses the sub-function byte."
  - 但 §3.1 也提到 "0x36's BlockSequenceCounter is a separate field, NOT a sub-function"。这意味着 0x36 默认会包含 sub-function 字节（因在 {0x10,0x11,0x27,0x31,0x3E} 集合外，不包含；但若误把 0x36 加进集合，会双重发 BlockSeq 与 sub-function）。
  - 实际 §3.1 注释正确排除 0x36。但未明确：(a) 用户显式设 HasSubFunction=true + ServiceID=0x22（无 sub-function 的服务）时 Validate 是否报错；(b) 用户显式设 SubFunction=0x05 + ServiceID=0x22 时 Plan 是否忽略 SubFunction。
- **依据**：ISO 14229-1 各服务定义；设计 §3.1
- **修复建议**：
  1. Validate 规则：ServiceID ∈ {0x22, 0x2E, 0x34, 0x36, 0x37}（无 sub-function 服务）若 HasSubFunction=true → 报错
  2. ServiceID ∈ {0x10, 0x11, 0x27, 0x31, 0x3E}（有 sub-function 服务）若 HasSubFunction=false → Plan 仍发 sub-function 字节（用户需 SubFunction=0 表示空 sub-function）
  3. 新增 T52：ServiceID=0x22 + HasSubFunction=true → Validate 报错
  4. 新增 T53：ServiceID=0x10 + HasSubFunction=false + SubFunction=0x03 → 仍发 sub-function=0x03 字节

### MEDIUM-9：DoIPMessage Direction 空值处理未定义

- **位置**：§3.1 DoIPMessage.Direction（行 489-491）、§3.2 默认值（行 655）
- **描述**：§3.2 默认值 `Message.Direction="up"`，但 §3.1 注释"Direction (方向): 'up' (Tester→ECU, default) or 'down' (ECU→Tester)"。未定义 Direction="" 或 Direction="invalid" 的行为：
  1. Direction="" → 应走默认 "up"
  2. Direction="invalid" → Validate 报错
  3. Direction="UP"（大写）→ 是否大小写敏感？
- **依据**：CLAUDE.md §1 spec-driven
- **修复建议**：
  1. Validate 规则：Direction 仅接受 {"", "up", "down"}；"up"/"down" 大小写不敏感；"" 走默认
  2. 新增 T54：Direction="" → 默认 "up"；T55：Direction="invalid" → Validate 报错；T56：Direction="UP" → 等价 "up"

### LOW-1：端口 3496（TLS DoIP）未提及

- **位置**：§1.2（行 23-28）
- **描述**：设计只提 TCP 13400，未提 ISO 13400-2:2019 §7 定义的 TLS DoIP 端口 3496。scapy `doip.py` 行 340 `tls_port=3496`。设计 §1.5 明确"TLS/DTLS 层封装（ISO 13400-2 §7 安全通道，目前车载以太网少见，留作后续扩展）"——但应至少在 §1.2 或 §9 集成点提及端口 3496 留待扩展。
- **依据**：ISO 13400-2:2019 §7；scapy `doip.py` 行 340
- **修复建议**：
  1. §1.2 表格新增 TLS 行：`| TCP | 3496 | TLS 安全通道（ISO 13400-2 §7，留作后续扩展） | Tester↔ECU |`
  2. §1.5 注释引用 §7 + 端口 3496

### LOW-2：R7 引用已删除内容

- **位置**：§9.12 R7（行 1439）
- **描述**：R7 注释"InverseProtocolVersion 不暴露为 Config 字段"——但 §1.3/§3.1 明确 InverseProtocolVersion 不暴露，R7 引用此事实作为风险点，逻辑混乱（不暴露是设计意图，不是风险）。
  - v1.1 修订记录 L3 已将 R7 改为"不暴露为 Config 字段，由 Planner 自动计算，用户无误配风险"——但仍是"风险"而非"设计意图"。
- **依据**：文档自洽性
- **修复建议**：
  1. R7 删除或改为"风险：若未来需暴露 InverseProtocolVersion 字段，用户可能误配导致接收方判为 malformed"
  2. §1.3 已明确不暴露，无需在 R7 重复

### LOW-3：附录 B 0x22/0x2E/0x27 响应格式表头缺少 subfunction 列

- **位置**：附录 B（行 1463-1477）
- **描述**：附录 B 仅展示"请求字节"和"默认正向响应字节"两列，未列出 subfunction 参数位置（如 0x10/0x11/0x31/0x3E 的 sub 字节、0x27 的 seed/key 字节、0x34 的 addr/size 字节、0x36 的 blockSeq 字节）。实现者难以判断 UserData 总长。
- **依据**：设计自洽性
- **修复建议**：
  1. 附录 B 新增第三列"参数位置"：标注每个服务的可选参数（如 0x22 的 DID 位置、0x34 的 fmt/addr/size 位置）
  2. 或附录 B 改为更详细的字节级公式表

### LOW-4：IPv6 组播 MAC 计算 RFC 引用错误

- **位置**：§4.1（行 726）
- **描述**：§4.1 注释"IPv6（spec.SrcIP 含 `:`）：DstIP = `ff02::1`，DstMAC = `33:33:00:00:00:01`（RFC 2464 §7，取多播地址末 32 位）"。RFC 2464 §7 确实定义 IPv6 组播 MAC 映射，但 §1.3 / §3.3 / §4.7 / §5.1 多次重复"取多播地址末 32 位"且 RFC 引用均一致。实际 RFC 引用正确，但 §1.2 未提及 IPv6 广播组播 MAC 机制。
- **依据**：RFC 2464 §7；设计自洽性
- **修复建议**：
  1. §1.2 补充 IPv6 广播组播机制说明（DstIP=ff02::1, DstMAC=33:33:00:00:00:01）
  2. 删除 §4.1 / §4.7 RFC 2464 重复引用（保留 §3.3 一处即可）

### LOW-5：Direction 缩写"上/下"在正文首次出现缺中文

- **位置**：§3.1（多处）、§3.2（行 655）
- **描述**：§3.1 DoIPMessage.Direction 注释"'up' (Tester→ECU, default) or 'down' (ECU→Tester)"，未明确"up=上=Tester→ECU, down=下=ECU→Tester"。符合 CLAUDE.md 中文注释规范，但后续 Direction 字符串在多处出现无重复说明。
- **依据**：CLAUDE.md 中文章写要求
- **修复建议**：
  1. §1 概述新增 1.6 节"方向约定"：明确 up=上行=Tester→ECU, down=下行=ECU→Tester
  2. §3.1 DoIPMessage.Direction / DoIPPowerMode.Direction / DoIPGenericNack.Direction 注释引用 §1.6

---

## 3. 测试用例覆盖率分析（对照 CLAUDE.md §1-§8）

### 3.1 spec-driven test derivation（§1）

- §2 PayloadType 表 14 项：T01(0x0005/0x0006), T07(0x0007/0x0008), T08(0x4003/0x4004), T09(0x0001), T10(0x0002), T11(0x0003), T16(0x0004), T22(0x8003), T23(0x0000) — 11/14 有用例，**0x8001/0x8002 单包独立用例缺失**（仅通过 T03-T06 隐式覆盖）
- §2.3 NACK Code 5 值：T23+T23a-T23d → 5/5 ✓
- §2.7 FurtherActionRequired 6 值：T16(0x00) + T16a(0x01 拒) + T16b(0xE0) → 3/6，遗漏 0x10/0x11/0x20/0x40 测试（CRITICAL-4 修复后将全部重新定义）
- §2.7 VIN/GID SyncStatus 2 值：未独立测试（T16 隐式覆盖 0x00）
- §2.9 ResponseCode 9 值（修正前 6 值覆盖）：T01(0x00 success) + T21(0x01) + T21a(0x02) + T21b(0x05) + T21c(0x07) + T21d(0x08) → 6/9，遗漏 0x03/0x04/0x06（注：CRITICAL-1 修复后编号偏移）
- §2.14 NackCode 12 值：T22(0x06) + T22a(0x00) + T22b(0x08) + T22c(0x0B) → 4/12（注：CRITICAL-2 修复后 0x00/0x01 是 Reserved 用例需重写）
- §2.11 DiagnosticPowerMode 3 值：T08(0x01) + T08a(0x00) + T08b(0x02 拒) → 3/3（注：CRITICAL 与 scapy 矛盾需修复后调整 T08b）
- §2.15 UDS 服务 10 项：T03(0x10), T04(0x22), T05(0x27), T06(0x34/0x36/0x37), T20(0x34), T20a(0x34), T20b(0x34), T20c(0x11), T20d(0x2E), T20e(0x31), T20f(0x3E) → 10/10 ✓
- §1.4 扩展表 5 字段映射表 8 项：未独立测试用例

### 3.2 cover failure paths（§2）

- §6.6/6.11/6.14/6.17 每个异常场景：T21-T26 + T22a-T22c + T23a-T23d → 基本覆盖
- 路由激活失败关闭 TCP（§4.3）：T26 ✓
- NegativeResponse：T24 ✓
- TCP 中断（T25）：✓
- **遗漏**：GenericNack Direction="up" 反向场景无专用用例（MEDIUM-7）

### 3.3 one test per code path（§3）

- 每个 PayloadType 单独测：基本满足（11/14 PayloadType 有独立用例）
- **遗漏**：0x8001 与 0x8002 无独立单包用例（仅 T03-T06 隐式覆盖）

### 3.4 integration tests（§4）

- T41-T45 端到端：5 条覆盖单 ECU 全流程 / 多 ECU / GroupID / ctx 取消 / 并发
- **遗漏**：IPv6 全流程（CRITICAL-5）

### 3.5 assert observable outcomes（§5）

- 每条用例断言 Payload 字节值：基本满足
- **弱点**：未断言 PacketConfig.Timestamp 字段（MEDIUM-4）

### 3.6 concurrency correctness（§6）

- T45 8 ECU 并发：覆盖
- **弱点**：未断言阶段顺序与 FlowID 后缀（MEDIUM-2）

### 3.7 failing-test-first（§7）

- 设计阶段无 bug：声明于 §8.7，实现阶段执行
- **现状**：v1.2 修订记录显示 v1.0→v1.1 修复 39 项但未提供"failing test 先行"证据

### 3.8 adversarial review of test quality（§8）

- §7 用例表标注对应场景编号：✓
- v1.1 修订记录列出 6 处"测试通过但测错东西"：✓（T05/T06/T17/T20/T22/T26）
- v1.2 修订记录补 13 项：✓
- **遗漏**：v1.2 修订未对 ResponseCode/NackCode 整体偏移（CRITICAL-1/2）做对抗复核

---

## 4. 与 ISO 13400-2:2019 规范一致性逐项核查

| # | 核查项 | ISO 13400-2:2019 要求 | 设计文档结论 | 状态 |
|---|---|---|---|---|
| 1 | DoIP 头 8B = PV(1)+InvPV(1)+PT(2)+PL(4) | §8.3 | §2.1 正确 | ✓ |
| 2 | InverseProtocolVersion = ~PV & 0xFF | §8.3 | §2.1/§1.3 正确 | ✓ |
| 3 | PayloadLength 不含头部 8B | §8.3 | §2.1 约束正确 | ✓ |
| 4 | PayloadType 大端 | §8.3 | §2.1 正确 | ✓ |
| 5 | 0x0000 Generic NACK Code 0x00-0x04 | §8.4.1 | §2.3 表完整，T23+T23a-T23d 全覆盖 | ✓ |
| 6 | 0x0001 Vehicle Ident Req 无 payload | §8.5.2 | §2.4/T09 正确 | ✓ |
| 7 | 0x0002 带 EID 6B | §8.5.3 | §2.5/T10 正确 | ✓ |
| 8 | 0x0003 带 VIN 17B ASCII | §8.5.4 | §2.6/T11 正确 | ✓ |
| 9 | 0x0004 Payload = VIN(17)+LA(2)+EID(6)+GID(6)+FAR(1)+Sync(1)=33B | §8.5.5 | §2.7 正确，附录 A PayloadLength=33 正确 | ✓ |
| 10 | 0x0004 公告发 3 次，间隔 500ms±100ms | §8.5.1 | §2.7 提及但 §4.1 "不强制" 语义模糊（M10 已修复 T16） | ✓ |
| 11 | 0x0004 FurtherActionRequired 仅 0x00/0x10 合法 | §8.5.3 | §2.7 表含 0x11/0x20/0x40 等多余值（CRITICAL-4） | ✗ |
| 12 | 0x0004 VIN/GID SyncStatus 仅 0x00/0x10 合法 | §8.5.5 | §2.7 表 0x01=Not synced（CRITICAL-4） | ✗ |
| 13 | 0x0005 Req V2 = SA(2)+AT(1)+Rsv(4)+OEM(N)=7+N B | §9.2.4 | §2.8 写死 OEM=4B=HIGH-1 | ⚠ |
| 14 | 0x0006 Resp V2 = CLA(2)+SLA(2)+RC(1)+Rsv(4)+OEM(N)=9+N B | §9.3.6 | §2.9 写死 OEM=4B=HIGH-1 | ⚠ |
| 15 | 0x0006 ResponseCode Success=0x10 | §9.3.6 | §2.9 写 0x00=Success（CRITICAL-1） | ✗ |
| 16 | 0x0007 Alive Check Req 始终 ECU→Tester | §10.2.2 | §4.5 Direction="down" 正确 | ✓ |
| 17 | 0x0008 Alive Check Resp 始终 Tester→ECU | §10.2.3 | §4.5 Direction="up" 正确 | ✓ |
| 18 | 0x4001 DoIP entity status req | §11.1 | §2.2 缺失（CRITICAL-3） | ✗ |
| 19 | 0x4002 DoIP entity status resp | §11.1 | §2.2 缺失（CRITICAL-3） | ✗ |
| 20 | 0x4003 Power Mode Req 无 payload | §11.2.1 | §2.11/T08 正确 | ✓ |
| 21 | 0x4004 Power Mode Resp = 1B | §11.2.2 | §2.11 正确 | ✓ |
| 22 | 0x4004 DiagnosticPowerMode 0x02=Not Supported | §11.2.2 | §2.11 写 0x02=Reserved（CRITICAL/HIGH-4） | ✗ |
| 23 | 0x8001 = SA(2)+TA(2)+UserData(N) | §10.3.2 | §2.12/T03 正确 | ✓ |
| 24 | 0x8001 SA 必须与 0x0005 SA 一致 | §10.3.2.1 | §3.1 Validate 注释声明，**但 §9 集成点未在 mapToFlowSpec 落地** | ⚠ |
| 25 | 0x8001 TA 必须与 0x0006 SLA 一致 | §10.3.2.2 | 同 24 | ⚠ |
| 26 | 0x8002 = SA(2)+TA(2)+AckCode(1)+PrevLen(2)+PrevDiag(N) | §10.4.3 | §2.13 V2 2B PrevLen 正确 | ✓ |
| 27 | 0x8002 AckCode 仅 0x00 合法 | §10.4.3.4 | §3.1 Validate 拒绝非零 | ✓ |
| 28 | 0x8002 PrevLen V2=u16 / V1=u32 | §10.4.3 | §2.13 写死 u16（HIGH-2） | ⚠ |
| 29 | 0x8003 NackCode 0x00/0x01=Reserved | §10.4.5 | §2.14 写 0x00/0x01=合法值（CRITICAL-2） | ✗ |
| 30 | 路由激活失败应关闭 TCP | §9.3.6.3 | §4.3/T26 正确 | ✓ |
| 31 | UDP 广播 255.255.255.255 / IPv6 ff02::1 | §8.2 | §1.2/§3.3 IPv4 正确；IPv6 §3.3/§4.1/§4.7/§5.1 落地 | ✓ |
| 32 | UDP 广播 MAC ff:ff:ff:ff:ff:ff / IPv6 33:33:00:00:00:01 | RFC 2464 | 同 31 | ✓ |
| 33 | UDS ServiceId 正向响应 = Request SID \| 0x40 | ISO 14229-1 §7.1 | §3.1 DoIPUDS.IsResponse 正确 | ✓ |
| 34 | UDS Negative Response = 7F + Request SID + NRC | ISO 14229-1 §7.3 | §6.17.7/T24 部分正确但 MEDIUM-1 未明确 SID 来自请求 | ⚠ |
| 35 | UDS BlockSequenceCounter 0xFF 后回绕到 0x00 | ISO 14229-1 §11.4.3.3 | §3.1 注释正确但公式 (n-1)%256 错误（MEDIUM-3） | ⚠ |

---

## 5. 最终结论与返工要求

### 5.1 最终结论

**本文档（v1.2）不可直接进入实现阶段。**

v1.2 修复了 v1.0/v1.1 的 39 项审计问题（8 CRITICAL + 11 HIGH + 13 MEDIUM + 7 LOW），但通过本次深度对抗审计，发现 **5 项 CRITICAL + 7 项 HIGH + 9 项 MEDIUM + 5 项 LOW = 26 项新问题**，其中 3 项 CRITICAL（ResponseCode/NackCode 枚举整体偏移、缺失 0x4001/0x4002）属于协议级硬伤，实现照抄将产生与 ISO 13400-2:2019 不兼容的畸形包或遗漏完整业务场景。

### 5.2 必须先返工的问题编号（按返工优先级）

#### P0 — 实现前必须修复（否则照抄即产生协议非法包）

1. **CRITICAL-1**：0x0006 Routing Activation ResponseCode 枚举整体偏移（设计 0x00 ↔ ISO/scapy 0x10）
2. **CRITICAL-2**：0x8003 NackCode 0x00/0x01 语义倒置（设计 0x00=Invalid SA ↔ ISO/scapy Reserved）
3. **CRITICAL-3**：缺失 0x4001/0x4002 DoIP Entity Status PayloadType（§2.2/§3.1/§4/§6/§7/§1.4 全部更新）
4. **CRITICAL-4**：0x0004 FurtherActionRequired 与 VIN/GID SyncStatus 枚举与 ISO/scapy 不一致（§2.7 全面修正）

#### P1 — 实现前需修复（避免产生协议异常或边界漏测）

5. **CRITICAL-5**：T44/T45 缺失 IPv6 全流程集成测试
6. **HIGH-1**：0x0005/0x0006 OEM-specific 字段写死 4B，应改为变长（§2.8/§2.9/§3.1/§3.2 修正）
7. **HIGH-2**：0x8002 PrevDiagMsgLength u16 上限与 0x36 服务 UserData 上限混淆（§2.13/§6.16.11/T32 拆分）
8. **HIGH-4**：DiagnosticPowerMode 0x02 误标 Reserved（应为 Not Supported，§2.11/T08b 修正）

#### P2 — 实现阶段建议修复（提升测试质量与文档自洽性）

9. **HIGH-3**：UDS 0x27 偶数应答 Key 字段语义模糊
10. **HIGH-5**：TCP MSS=0 边界未覆盖（T49）
11. **HIGH-6**：UDS NRC 边界值（0x00/0xFF）未覆盖（T24a/T24b）
12. **HIGH-7**：0x0006 ResponseCode=0x11 Confirmation Required 业务逻辑未建模
13. **MEDIUM-1 至 MEDIUM-9**：UDS 否定响应 SID 源、BlockSeq 公式、Announcement 间隔语义、ActivationType 术语、EID fallback、GenericNack 方向、HasSubFunction Validate、Direction 空值处理

#### P3 — 文档完善（LOW-1 至 LOW-5）

14. 端口 3496（TLS）未提及
15. R7 引用已删除内容
16. 附录 B 缺参数位置列
17. IPv6 MAC 计算 RFC 引用重复
18. Direction 缩写首次出现缺中文

### 5.3 修复后验证要求

1. 对每条 CRITICAL/HIGH 修复，必须提供字节级重算证据（如 "修正后 0x0006 PayloadLength=9+N bytes for OEM=N"）
2. 所有 ResponseCode/NackCode/FurtherActionRequired/SyncStatus 测试用例（T21-T22c/T16a/T16b/T08a/T08b）必须更新断言值
3. 新增 T46-T56 补充缺失场景（IPv6 全流程/0x4001/0x4002/MSS=0/NRC 边界/Confirmation Required/HasSubFunction Validate/Direction 空值）
4. 修复完成后需重新执行 §3 测试覆盖率分析（spec-driven/failure path/one test per path/integration/observable/concurrency/failing-test-first/test quality），确认覆盖率从 72 条扩展至 ≥ 85 条
5. 对照 scapy `doip.py` `fields_desc` 重新核对所有 PayloadType 枚举与字段宽度

---

**审计人**：独立协议审计代理
**审计完成日期**：2026-08-04
**下次审计建议**：P0-P1 修复后重新审计，关注 v1.3 的字节级自洽性、scapy 一致性、测试覆盖率三项核心指标
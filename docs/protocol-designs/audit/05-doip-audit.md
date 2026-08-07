# DOIP 设计文档对抗审计报告

> 审计对象：`docs/protocol-designs/05-doip-design.md`（1371 行，v1.0，2026-08-03）
> 审计依据：ISO 13400-2:2019、ISO 14229-1、CLAUDE.md 测试策略 §1-§8、`internal/protocol/socks5/socks5.go` Planner 模式、`internal/core/types.go` FlowSpec 结构体
> 审计日期：2026-08-03
> 审计人：独立协议审计代理（与设计者无交叉）
> 审计模式：交叉对抗（逐字节验算、逐条用例反查 spec 行、对抗式证伪每条发现）

## 1. 审计概览

### 1.1 审计方法

1. 通读全文 1371 行（§1 概述 → 附录 C 默认值速查），对每一处字节级期望值逐字节验算（DoIP 头 8B、PayloadLength、UDS ServiceId/SubFunction/DID/RID 编码、PrevDiagMsgLen 与 UserData 一致性、MSS 分段长度）。
2. 对 §2.2 PayloadType 表 14 项、§2.3 NACK Code 表 5 项、§2.7 FurtherActionRequired 表 6 项、§2.9 ResponseCode 表 9 项、§2.14 NackCode 表 12 项、§2.15 UDS 服务表 10 项，逐条对照 ISO 13400-2:2019 与 ISO 14229-1 原文核对编码与语义。
3. 对 §6 业务场景 17 类、§7 测试用例 45 条，按 CLAUDE.md §1-§8 逐项对抗：每条用例问"测的是哪个 PayloadType/字段/分支？输入能否触发该分支？断言的是可观察值还是结构？是否存在 spec 行无对应用例？"
4. 对照 `socks5.go` Planner 实现（emit/emitData/emitUDP 闭包、FlowID `:udp` 后缀、GroupID 路由、MSS 分段）核查 DOIP 设计的代码组织与集成点。
5. 对抗式证伪：对每条发现尝试"读实际代码/规范原文去反驳"，默认"非 bug"除非有字节级证据。

### 1.2 总体结论

设计文档**结构完整**：DoIP 头 8B 顺序正确、PayloadType 表 14 项全列、状态机 5 阶段 + 2 独立阶段划分清晰、UDS 服务子集选取合理、多 ECU 4-tuple 区分机制与 SOCKS5 先例一致、附录 A/B/C 字节级对照表实用。这是本仓库扩展表 5 车联网协议设计中较好的部分。

但存在三类系统性缺陷：

1. **字节级示例与附录自相矛盾（CRITICAL ×3）**：§6.4 期望 hex 的 PayloadLength 写 `00 00 00 07`/`00 00 00 09` 但附录 A 与下方"修正"说明均为 `0B`/`0D`；T20 期望 `34 22 00 00 10 00 01 00`（8B，fmt=0x44 编码）与输入 `fmt=0x22`（应 6B）矛盾；§6.9 用 UDS 请求 SID `0x27` 标注 ECU 响应消息，但按 ISO 14229-1 正向响应 SID 应为 `0x67`。实现者照抄会产生 Wireshark 标记为 malformed 的包。
2. **协议一致性硬伤（CRITICAL ×4）**：EID 默认推导用 `spec.SrcMAC`（Tester MAC）而非 `spec.DstMAC`（ECU MAC）；V1 兼容性声称支持但实际生成 V2 格式（7B/9B vs 11B/13B 路由激活、2B vs 4B PrevDiagMsgLen）；AliveCheck `Direction="up"` 让 Tester 主动发 0x0008，违反 ISO 13400-2:2019 §10.2（0x0007 始终由 ECU 发起）；多 UDP 子流（Discovery + PowerMode）共用 `:udp` 后缀导致 FlowID 冲突。
3. **测试用例虚假覆盖（HIGH ×4）**：§7 声称 45 条覆盖 §2 全表，实际 §2.14 NackCode 12 个合法值 0 测（T22 用非法值 0x10）、§2.9 ResponseCode 9 个值仅测 2 个、§2.3 NACK Code 5 个值仅测 1 个、§2.15 UDS 10 个服务 4 个无专用用例。T45 并发测试仅断言 `-race` 干净，未测聚合行为（CLAUDE.md §6 违规）。

### 1.3 严重度分布

| 严重度 | 数量 | 说明 |
|---|---|---|
| CRITICAL | 8 | 字节错误/协议硬伤/虚假兼容 → 实现照抄即产出畸形包或协议非法序列 |
| HIGH | 11 | 内部矛盾/测试覆盖虚假/校验缺失 |
| MEDIUM | 13 | 边界未覆盖/语义未定义/可观察性不足 |
| LOW | 7 | 表述不精确/计数不符/政策未声明 |
| **合计** | **39** | 远超"至少 10 个"的强制要求 |

### 1.4 设计中的亮点（予以肯定）

- §2.1 DoIP 头 8B 顺序（ProtocolVersion + InverseProtocolVersion + PayloadType + PayloadLength）与 ISO 13400-2:2019 §8.3 完全一致；`InverseProtocolVersion = ~ProtocolVersion & 0xFF` 校验机制正确。
- §2.2 PayloadType 表 14 项（0x0000-0x8003）编码与方向/传输层标注全部正确，含 0x4003/0x4004 电源模式（V2 新增）。
- §2.13/§2.14 0x8002/0x8003 携带 PreviousDiagnosticMessage 副本的设计符合 ISO 13400-2:2019 §10.4.3/§10.4.5，且 R8 明确"取完整 UserData（不分段前的原始字节）"——这是正确的。
- §4 状态机 5 阶段 + 2 独立阶段（PowerMode/GenericNack）划分清晰，触发条件与传输层标注完整。
- §3.3 与 SOCKS5 的 GroupID 共享机制（UDP/TCP 子流同 PacketWorker 保持发送顺序）正确继承先例。
- §6.16 边界场景表 15 项 + §6.17 异常场景表 8 项，覆盖 VIN/EID 长度、LogicalAddress 边界、PayloadLength 边界、ActivationType 保留范围、ProtocolVersion 不支持等关键边界。
- §9.10 明确 DoIP 与 SOCKS5/RTSP/FTP/SIP/GBT32960/JT808 等同栈协议的互斥性，避免端口冲突。
- 附录 A 字节级对照表（除 §6.4 矛盾外）准确，可作为实现期断言模板。

### 1.5 ISO 13400-2:2019 一致性逐项核查表（维度 1 全量核对）

| # | 核查项 | ISO 要求 | 设计结论 | 状态 |
|---|---|---|---|---|
| 1 | DoIP 头 8B = PV(1)+InvPV(1)+PT(2)+PL(4) | §8.3 | §2.1 正确 | ✓ |
| 2 | InverseProtocolVersion = ~PV & 0xFF | §8.3 | §2.1/§1.3 正确（V2→0xFD） | ✓ |
| 3 | PayloadLength 不含头部 8B | §8.3 | §2.1 约束正确 | ✓ |
| 4 | PayloadType 大端 | §8.3 | §2.1 正确 | ✓ |
| 5 | 0x0000 Generic NACK Code 0x00-0x04 | §8.4.1 | §2.3 表完整 | ✓（测试仅 1/5，见 H10） |
| 6 | 0x0001 Vehicle Ident Req 无 payload | §8.5.2 | §2.4 正确 | ✓ |
| 7 | 0x0002 带 EID 6B | §8.5.3 | §2.5 正确 | ✓ |
| 8 | 0x0003 带 VIN 17B ASCII | §8.5.4 | §2.6 正确 | ✓ |
| 9 | 0x0004 Payload = VIN(17)+LA(2)+EID(6)+GID(6)+FAR(1)+Sync(1)=33B | §8.5.5 | §2.7 正确，附录 A `00 00 00 21`=33 正确 | ✓ |
| 10 | 0x0004 公告发 3 次，间隔 500ms±100ms | §8.5.1 | §2.7 提及但 §4.1 "不强制" 语义模糊（M10） | ⚠ |
| 11 | 0x0005 Req = SA(2)+AT(1)+Rsv(4)+OEM(4)=11B (V2) | §9.2.4 | §2.8 V2 11B 正确；但 §6.4 hex 写 7B（C1）；V1 7B 未实现（C6） | ✗ |
| 12 | 0x0006 Resp = CLA(2)+SLA(2)+RC(1)+Rsv(4)+OEM(4)=13B (V2) | §9.3.6 | §2.9 V2 13B 正确；但 §6.4 hex 写 9B（C1）；V1 9B 未实现（C6） | ✗ |
| 13 | 0x0007 Alive Check Req 始终 ECU→Tester | §10.2.2 | §4.5 Direction="up" 让 Tester 发 0x0008（无前置 0x0007），违反（H1） | ✗ |
| 14 | 0x0008 Alive Check Resp 始终 Tester→ECU | §10.2.3 | 同 13 | ✗ |
| 15 | 0x4003 Power Mode Req 无 payload | §11.2.1 | §2.11 正确 | ✓ |
| 16 | 0x4004 Power Mode Resp = 1B | §11.2.2 | §2.11 正确 | ✓ |
| 17 | 0x8001 = SA(2)+TA(2)+UserData(N) | §10.3.2 | §2.12 正确 | ✓ |
| 18 | 0x8001 SA 必须与 0x0005 SA 一致 | §10.3.2.1 | 设计允许 per-message 覆盖，无校验（H3） | ✗ |
| 19 | 0x8001 TA 必须与 0x0006 SLA 一致 | §10.3.2.2 | 设计允许 per-message 覆盖，无校验（H4） | ✗ |
| 20 | 0x8002 = SA(2)+TA(2)+AckCode(1)+PrevLen(2)+PrevDiag(N) | §10.4.3 | §2.13 正确（V2 2B PrevLen） | ✓ |
| 21 | 0x8002 AckCode=0x00，其它保留 | §10.4.3.4 | 设计允许任意 uint8，无校验（M9） | ⚠ |
| 22 | 0x8003 NackCode 0x00-0x0B | §10.4.5 | §2.14 表完整；T22 用 0x10 非法（C4） | ✗ |
| 23 | 路由激活失败应关闭 TCP | §9.3.6.3 | §4.3/§6.17.4/T26 生成"拒绝后继续诊断"非法序列（H5） | ✗ |
| 24 | UDP 广播 255.255.255.255 / IPv6 ff02::1 | §8.2 | §1.2/§3.3 IPv4 正确；IPv6 仅 R4 提及未落地（H7） | ⚠ |
| 25 | UDP 广播 MAC ff:ff:ff:ff:ff:ff / IPv6 33:33:00:00:00:01 | RFC 2464 | §3.3 仅 IPv4 MAC；IPv6 MAC 未落地（H7） | ⚠ |

---

## 2. CRITICAL 问题

### C1. §6.4 示例 hex 的 PayloadLength 与附录 A 及"修正"说明自相矛盾

**位置**：§6.4 期望报文序列表（第 823-824 行）vs 下方"修正"说明（第 830-832 行）vs 附录 A（第 1319-1320 行）。

**描述**：§6.4 表格中：
- 0x0005 的 DoIP 头 hex 写为 `02 FD 00 05 00 00 00 07`，即 PayloadLength=7；但表格右侧注释写 "SA(2) + AT(1) + Rsv(4) + OEM(4) = 11B"。
- 0x0006 的 hex 写为 `02 FD 00 06 00 00 00 09`（PayloadLength=9），但注释写 13B。

设计在表格下方加了"修正"说明（第 830-832 行）承认 PayloadLength 应为 11/13，并声明"本设计严格按 ISO 13400-2:2019 的 11B/13B 长度生成"。但 **表格内的 hex 本身未修正**，仍为 `00 00 00 07` / `00 00 00 09`。

附录 A（第 1319-1320 行）则正确写为 `02 FD 00 05 00 00 00 0B`（11）和 `02 FD 00 06 00 00 00 0D`（13）。

**依据**：ISO 13400-2:2019 §9.2.4 Routing Activation Request payload = SourceAddress(2) + ActivationType(1) + Reserved(4) + OEM-specific(4) = 11 bytes；§9.3.6 Response = ClientLogicalAddress(2) + ServerLogicalAddress(2) + ResponseCode(1) + Reserved(4) + OEM-specific(4) = 13 bytes。

**影响**：实现者若直接照抄 §6.4 表格的 hex 作为测试期望，会生成 PayloadLength 与 Payload 实际长度不匹配的非法报文。接收方按 ISO 13400-2:2019 §8.4.1 会回复 0x0000 Generic NACK（NACK Code 0x04 Invalid Payload Length）并关闭连接。这正是 CLAUDE.md 审计史上"测试测了错误期望还全绿"的反向变体（此处是测试期望本身就是错的）。

**修复建议**：将 §6.4 表格中 0x0005 的 `00 00 00 07` 改为 `00 00 00 0B`，0x0006 的 `00 00 00 09` 改为 `00 00 00 0D`，并删除"修正"说明（或保留说明但标注"表格已修正"）。同时 T01（第 1068 行）已正确写 `PayloadLength=11`/`13`，无需改动。

### C2. T06 测试输入与 §6.16.11 UserData 上限直接矛盾

**位置**：§6.10 / T06（第 921、1073 行）vs §6.16.11（第 1041 行）。

**描述**：
- §6.16.11 声明 "0x36 TransferData 4GB → Validate 报错（超 0x8001 UserData 上限 4095B）"。
- T06 输入为 `Data=4096B×2`，期望 "0x36 PayloadLength=4102；BlockSeq 1→2"。
- 0x36 的 UserData = SID(1) + BlockSeq(1) + Data(4096) = 4098B，**超过 4095B 上限**。

按 §6.16.11，T06 的输入应在 Validate 阶段被拒绝；但 T06 期望 Plan 成功生成包。两者直接矛盾，无法同时满足。

**依据**：§6.16.11 设定的 4095B 上限本身也有问题（见 M5）—— 4095B 限制来自 ISO 15765-2（ISO-TP / CAN 传输层），DoIP 不受此约束。DoIP 的 UserData 上限受 0x8002 PrevDiagMsgLen（V2: 2B = 65535B）和 TCP 缓冲约束。

**影响**：实现者无法同时满足 T06 和 §6.16.11。若按 §6.16.11 实现 Validate，T06 失败；若按 T06 实现，§6.16.11 的 Validate 形同虚设。这正是 CLAUDE.md §8 警告的"测试通过但测错东西"——其中一个测试必然在测错误的实现分支。

**修复建议**：统一 UserData 上限。建议将上限改为 65533B（2B PrevDiagMsgLen 上限 65535 减去 SID+BlockSeq 2B），或明确 DoIP 不受 ISO-TP 4095B 限制；同时修正 §6.16.11 的 Validate 规则。T06 的 Data=4096B 在新上限下合法。

### C3. T20 期望字节与 fmt=0x22 输入不匹配

**位置**：T20（第 1087 行）。

**描述**：T20 输入 `UDS={0x34, addr=0x1000, size=0x100, fmt=0x22}`，期望 `UserData = 34 22 00 00 10 00 01 00`（8 字节）。

按 ISO 14229-1 §11.4.3.2，`AddressAndLengthFormatIdentifier`（fmt）高 nibble = memorySize 长度，低 nibble = memoryAddress 长度。fmt=0x22 表示 memorySize 2B + memoryAddress 2B。因此：
- SID(1) + fmt(1) + memoryAddress(2B = 0x1000 → `10 00`) + memorySize(2B = 0x100 → `01 00`) = **6 字节**
- 期望应为 `34 22 10 00 01 00`

T20 给出的 8 字节 `34 22 00 00 10 00 01 00` 实际是 fmt=0x44（4B addr + 4B size）的编码（`00 00 10 00` = 4B addr 0x1000，`01 00` 后还缺 2B 才是 4B size 0x100）。这与输入 fmt=0x22 矛盾，且 8 字节本身也不完整（fmt=0x44 应为 10 字节：1+1+4+4）。

**依据**：ISO 14229-1 §11.4.3.2 RequestDownload 请求格式：`34 <ALFI> <memoryAddress> <memorySize>`，ALFI 字段定义见 §11.4.3.2 表。

**影响**：实现者按 T20 期望编码会产生 fmt 与字节数不匹配的非法 UDS 报文。Wireshark 会标记为 "Malformed UDS: RequestDownload length mismatch"。

**修复建议**：将 T20 期望改为 `34 22 10 00 01 00`（6 字节），或将输入改为 `fmt=0x44, addr=0x1000, size=0x100` 并期望 `34 22 00 00 10 00 00 00 01 00`（10 字节）。同时补 T20a 测 fmt=0x11（1B+1B，期望 `34 11 00 01`）、T20b 测 fmt=0x33（3B+3B）以覆盖 ALFI 边界。

### C4. §6.11 / T22 使用 NackCode=0x10，但 §2.14 表中无此值

**位置**：§6.11（第 944 行）、T22（第 1094 行）vs §2.14（第 240-255 行）。

**描述**：§2.14 的 NackCode 表仅定义 0x00-0x0B（共 12 个值）。§6.11 与 T22 使用 `NackCode:0x10`，该值不在表中，属于 ISO 13400-2:2019 §10.4.5 保留值。

**依据**：ISO 13400-2:2019 §10.4.5 表 10-5 明确列出 NackCode 0x00-0x0B，0x0C-0xFF 保留。设计 §2.14 表也仅列 0x00-0x0B，未声明 0x10 为 OEM 扩展。

**影响**：实现者按 §2.14 实现 Validate 会拒绝 0x10；但 T22 期望 Plan 成功生成 0x8003 包。内部矛盾。若实现者照抄 T22，Validate 形同虚设；若 Validate 拒绝，T22 失败。

**修复建议**：将 §6.11 / T22 的 NackCode 改为表内合法值（如 0x06 Access Denied 或 0x01 Target Address Unreachable），或在 §2.14 表中补充 0x10 的定义并注明 "OEM-specific extension"。推荐前者以保持与 ISO 一致。

### C5. EID 默认推导使用 spec.SrcMAC（Tester MAC），应为 spec.DstMAC（ECU MAC）

**位置**：§3.1 DoIPConfig.EID 注释（第 354 行）、§3.2 默认值表（第 565 行）。

**描述**：设计声明 `EID | spec.SrcMAC 去冒号后 hex 解码`。

EID（Entity Identifier）在 0x0004 Vehicle Announcement/Identification Response 中由 **ECU 填充**，应为 ECU 的 MAC 地址。在 up 方向（Tester→ECU）中，`spec.SrcMAC` 是 Tester MAC，`spec.DstMAC` 才是 ECU MAC。因此 EID 应从 `spec.DstMAC` 推导。

**依据**：ISO 13400-2:2019 §8.5.5.3 Entity Identifier："The EID is the MAC address of the DoIP entity sending the vehicle announcement message." DoIP entity = ECU。

**影响**：所有依赖 EID 默认推导的用例（T15、T10、T16）会产生 EID = Tester MAC 的非法报文。Wireshark 会将 EID 与以太网源 MAC（ECU 的 SrcMAC）不匹配标记为异常。更隐蔽的是，0x0002 请求按 EID 查找 ECU，若请求 EID（默认推导自 SrcMAC）= Tester MAC，ECU 不会应答。

**修复建议**：将 §3.1 和 §3.2 的 EID 默认推导源从 `spec.SrcMAC` 改为 `spec.DstMAC`。同步修正 T15 断言 "0x0004 EID 字段 = `00 11 22 33 44 55`"：若 spec.SrcMAC="00:11:22:33:44:55" 是 Tester MAC，则 EID 应推导自 spec.DstMAC（需在 T15 中明确 spec.DstMAC）。

### C6. V1（ProtocolVersion=0x01）兼容性声明与实际生成格式矛盾

**位置**：§1.3（第 32 行）、§3.1 ProtocolVersion 注释（第 294-295 行）、T17（第 1084 行）。

**描述**：设计声称 "同时支持 0x01（V1，老车型）作为兼容选项"，T17 也测试 V1（期望 DoIP 头第 1 字节 = 0x01，第 2 字节 = 0xFE）。但 V1（ISO 13400-2:2012）与 V2（2019）在以下方面不同：

| 差异点 | V1 (2012) | V2 (2019) | 设计实际生成 |
|---|---|---|---|
| 0x0005 Routing Activation Request | SA(2)+AT(1)+Rsv(4) = 7B | SA(2)+AT(1)+Rsv(4)+OEM(4) = 11B | 11B（V2 格式） |
| 0x0006 Routing Activation Response | CLA(2)+SLA(2)+RC(1)+Rsv(4) = 9B | CLA(2)+SLA(2)+RC(1)+Rsv(4)+OEM(4) = 13B | 13B（V2 格式） |
| 0x8002/0x8003 PreviousDiagnosticMessageLength | 4B (u32) | 2B (u16) | 2B（V2 格式） |
| 0x4003/0x4004 Power Mode | V1 不支持 | V2 支持 | 支持（V2 格式） |
| 0x0005 OEM-specific 字段 | V1 无此字段 | V2 新增 | 生成（V2 格式） |

当用户设 `ProtocolVersion=0x01` 时，Planner 仍生成 V2 格式的 11B/13B 路由激活和 2B PrevDiagMsgLen，与 V1 规范不兼容。

**依据**：ISO 13400-2:2012（V1）§9.2 vs ISO 13400-2:2019（V2）§9.2。V2 在路由激活请求/响应中新增了 4B OEM-specific 字段；PrevDiagMsgLen 从 V1 的 4B 改为 V2 的 2B（因实际诊断消息罕有 >65535B）。

**影响**：声称 V1 兼容但实际生成 V2 报文，V1 ECU 会因 PayloadLength 不匹配回复 0x0000 NACK Code 0x04 并关闭连接。T17 仅断言 DoIP 头前 2 字节，未断言路由激活 payload 长度，因此 T17 通过但实际 V1 不兼容——典型的"测试通过但测错东西"。

**修复建议**：要么删除 V1 兼容性声明（声明仅支持 V2），要么在 Planner 中按 ProtocolVersion 版本门控格式：
- V1: 0x0005 = 7B（无 OEM），0x0006 = 9B（无 OEM），0x8002/0x8003 PrevDiagMsgLen = 4B，不支持 0x4003/0x4004。
- V2: 当前格式。
- Validate 拒绝 V1 + PowerMode 组合。

### C7. 多 UDP 子流 FlowID 后缀冲突（Discovery + PowerMode 共用 `:udp`）

**位置**：§5.1 FlowID 填充规则（第 715 行）、§3.1 DoIPPowerMode 注释（第 327-331 行）。

**描述**：§5.1 规定 UDP 子流 FlowID = `f"{SrcIP}-{DstIP}-{SrcPort}-{DstPort}"` + `":udp"`。

DOIP 可能有 **两个独立 UDP 子流**：
1. Discovery（阶段 0，TCP 之前）
2. PowerMode（阶段 6，TCP 挥手之后）

§3.1 DoIPPowerMode 注释明确说 "may run on the same UDP 4-tuple or a separate one"。若两者共用同一 UDP 4-tuple（相同的 SrcIP/DstIP/SrcPort/DstPort），则 FlowID 均为 `xxx:udp`，**resequencer 会把两个子流的包混在一起排序**，导致 Discovery 的 0x0004 与 PowerMode 的 0x4004 交错。

对比 SOCKS5：只有单个 UDP relay 子流（udp_associate），`:udp` 后缀无冲突。DOIP 有两个独立 UDP 子流，需区分。

**依据**：`socks5.go` 第 386 行 `FlowID: flowID + ":udp"` 单子流无冲突。DOIP 设计未考虑双子流场景。

**影响**：多 UDP 子流场景下包序错乱，pcap 回放对比失败。T41（端到端全流程）包含 Discovery + PowerMode，若两者共用 4-tuple，T41 的包序断言会失败。

**修复建议**：使用区分性后缀：Discovery 用 `:udp:disc`，PowerMode 用 `:udp:power`；或强制两个 UDP 子流使用不同 SrcPort（Discovery 用 spec.SrcPort，PowerMode 用 spec.SrcPort+1 或独立配置）。

### C8. §6.9 用 UDS 请求 SID 标注 ECU 响应消息（应为 SID|0x40 正向响应码）

**位置**：§6.9（第 901、907-910 行）、§2.15 UDS 服务表（第 261-272 行）、附录 B（第 1330-1343 行）、§3.1 DoIPUDS 结构体（第 468-520 行）。

**描述**：§6.9 配置 `Messages=[{UDS:{ServiceID:0x27, SubFunction:0x01, Seed:[0x11,0x22,0x33,0x44]}, Direction:"down"}]`，期望 Idx N 的 UserData = `27 01 11 22 33 44`，注释为 "请求种子响应"。

按 ISO 14229-1 §7.1，UDS 请求 ServiceId 与正向响应 ServiceId 的关系为 `正向响应 SID = 请求 SID | 0x40`。因此：
- 0x27 SecurityAccess 请求 → 正向响应 SID = **0x67**
- 0x22 ReadDataByIdentifier 请求 → 正向响应 SID = 0x62
- 0x10 DiagnosticSessionControl 请求 → 正向响应 SID = 0x50

§6.9 的 Direction="down"（ECU→Tester）是 ECU 发送响应，但 UserData 用请求 SID `0x27` 而非响应 SID `0x67`，这是 **协议非法**——ECU 不会发送 SID=0x27 的包（0x27 是 Tester 请求码）。

更系统性的问题是：**DoIPUDS 结构体没有区分请求与正向响应的字段**。`ServiceID` 字段被用于双向（请求和响应都用同一个 SID），这无法表达 ISO 14229-1 的请求/响应 SID 配对关系。附录 B 正确列出了正向响应 SID（0x50/0x51/0x62/0x67/0x6E/0x71/0x74/0x76/0x77/0x7E），但 §6.9 与 DoIPUDS 结构体未落地这一区分。

**依据**：ISO 14229-1 §7.1 Service identifier："The response Service identifier is equal to the request Service identifier with the bit 6 set to 1 (i.e. request SID + 0x40)." 附录 B 已正确反映此规则。

**影响**：实现者按 §6.9 编码会生成 ECU 发送 SID=0x27 的非法报文。Wireshark 会标记为 "Unexpected UDS ServiceId 0x27 from server"。所有 UDS 响应消息（Direction=down）都会用错 SID。T05（SecurityAccess 完整）的断言 "UserData = `27 01` + 4B Seed" 也会测错东西——通过则说明序列化器漏实现了响应 SID 转换。

**修复建议**：
1. 在 DoIPUDS 结构体新增 `IsResponse bool` 字段（或 `ResponseType` 枚举：request/positive_response/negative_response）。
2. Plan 序列化时：若 IsResponse=true 且 NegativeResponseCode=0，则 SID 字节写 `ServiceID | 0x40`；若 NegativeResponseCode!=0，则写 `0x7F` + ServiceID + NRC。
3. 修正 §6.9 期望：Idx N UserData = `67 01 11 22 33 44`（正向响应 SID 0x67）。
4. 修正 T05 断言：响应 UserData 用 `67 01`，请求 UserData 用 `27 02`。
5. 同步检查 §6.7（SessionControl 响应）、§6.8（ReadDataByIdentifier 响应）—— 这些场景的 Direction=down 响应也应使用 SID|0x40，但 §6.7/§6.8 仅展示了 up 方向请求，响应方向由 0x8002 携带 PrevDiagMsg 体现，因此 §6.7/§6.8 本身无错（但若用户配 Direction=down 的 UDS 响应消息，仍需 IsResponse）。

---

## 3. HIGH 问题

### H1. AliveCheck Direction="up" 语义产生协议非法序列

**位置**：§4.5（第 678-680 行）、§3.1 DoIPAliveCheck.Direction（第 524-527 行）。

**描述**：§4.5 规定 `Direction="up"` 时 "Tester → ECU 发 0x0008（极少见，反向探活），ECU → Tester 回 0x0007"。

但按 ISO 13400-2:2019 §10.2：
- 0x0007 Alive Check Request **始终由 ECU 发起**（ECU 检测 TCP 空闲超时）
- 0x0008 Alive Check Response **始终由 Tester 发送**

Tester 不会主动发 0x0007，ECU 不会主动发 0x0008。设计的 "Direction=up" 模式让 Tester 发 0x0008（无前置 0x0007），这是 **协议非法的孤悬响应**。

**依据**：ISO 13400-2:2019 §10.2.2 Alive Check Request："sent by a DoIP entity to verify if the tester is still active." §10.2.3 Alive Check Response："sent by the tester in response to a received Alive Check Request." DoIP entity = ECU。

**影响**：生成不符合 ISO 13400-2 的报文序列，Wireshark 会标记为 "Unexpected Alive Check Response (no preceding request)"。

**修复建议**：删除 DoIPAliveCheck.Direction 字段，固定为 ECU 发 0x0007 → Tester 回 0x0008。若需模拟 Tester 主动探活，应使用 0x3E TesterPresent（UDS 保活），而非 0x0007/0x0008。

### H2. 0x8002 Ack 在大 UDS 场景下也需 MSS 分段，但设计声称不分段

**位置**：§4.4（第 672 行）、R8（第 1306 行）、§6.10（第 930 行）。

**描述**：§4.4 声明 "0x8002/0x8003 通常 ≤ MSS，不分段"。但 R8 规定 0x8002 的 PreviousDiagnosticMessage 取 **完整 UserData**（不分段前的原始字节）。

若 0x8001 携带 4096B UserData（如 0x36 TransferData），则 0x8002 = SA(2)+TA(2)+AckCode(1)+PrevLen(2)+PrevDiag(4096) = 4103B，远超 MSS 1460，**必须分段**。§6.10 的 N+3 行也显示 0x8002 携带 4096B PreviousDiagnosticMessage（"PrevLen=4102 + `36 01 <4096B>`"），但未提及分段。

**依据**：TCP MSS 限制适用于所有 TCP payload，不区分 DoIP PayloadType。0x8002 携带 PrevDiagMsg 副本时，其长度等于 0x8001 UserData 长度。

**影响**：大 UDS 场景下 0x8002 超过 TCP MSS，未分段会导致单包过大（被 IP 分片或拒绝）。

**修复建议**：将 §4.4 改为 "0x8002/0x8003 携带的 PreviousDiagnosticMessage 可能超过 MSS，需按 MSS 分段，分段逻辑同 0x8001"。在 §6.10 N+3 行补注 "0x8002 按 MSS 分 3 段（1460+1460+1183）"。

### H3. 0x8001 SourceAddress 未强制与路由激活 SourceAddress 一致

**位置**：§3.1 DoIPMessage.SourceAddress（第 437-438 行）。

**描述**：DoIPMessage.SourceAddress 允许 per-message 覆盖，默认回退到 Activation.SourceAddress。但 ISO 13400-2:2019 §10.3.2.1 规定 0x8001 的 SourceAddress **必须** 与 0x0005 Routing Activation Request 的 SourceAddress 一致（即 Tester 的逻辑地址）。

设计允许用户为不同 Message 设置不同 SourceAddress，这会生成协议非法报文（ECU 会回复 0x8003 NackCode=0x00 Invalid Source Address）。

**依据**：ISO 13400-2:2019 §10.3.2.1："The source address of a diagnostic message shall be identical to the source address used in the routing activation request."

**影响**：用户误配 SourceAddress 会产生非法序列，且 Validate 不拦截。

**修复建议**：Validate 阶段强制 `Message.SourceAddress`（若非 0）== `Activation.SourceAddress`（若非 0）；或删除 per-message SourceAddress 字段，统一使用 Activation 层的值。

### H4. 0x8001 TargetAddress 未强制与 0x0006 ServerLogicalAddress 一致

**位置**：§3.1 DoIPMessage.TargetAddress（第 439-441 行）。

**描述**：DoIPMessage.TargetAddress 允许 per-message 覆盖。但 ISO 13400-2:2019 §10.3.2.2 规定 0x8001 的 TargetAddress **必须** 与 0x0006 Routing Activation Response 的 ServerLogicalAddress 一致（即 ECU 的逻辑地址）。

设计允许用户设置不同 TargetAddress，会生成 ECU 无法识别的诊断消息（0x8003 NackCode=0x01 Target Address Unreachable）。

**依据**：ISO 13400-2:2019 §10.3.2.2："The target address of a diagnostic message shall be identical to the logical address of the DoIP entity received in the routing activation response."

**影响**：同 H3，Validate 缺失一致性校验。

**修复建议**：Validate 阶段强制 `Message.TargetAddress`（若非 0）== `Activation.ServerLogicalAddress`（若非 0）或 `DoIPConfig.LogicalAddress`。

### H5. §6.17.4 / T26 "拒绝后继续诊断"生成协议非法序列

**位置**：§4.3（第 661 行）、§6.17.4（第 1054 行）、T26（第 1098 行）。

**描述**：§4.3 声明 "若 Activation.ResponseCode != 0x00，Planner 仍生成响应包...但不跳过后续诊断消息阶段（由调用方决定）"。§6.17.4 / T26 显式测试 "ResponseCode=0x01 + Messages!=nil → 仍生成诊断包"。

按 ISO 13400-2:2019 §9.3.6.3，Routing Activation 失败（ResponseCode != 0x00）时 **TCP 连接应被 ECU 关闭**，不允许后续诊断消息。设计生成 "拒绝后继续诊断" 是协议非法序列。

虽然设计辩解 "由调用方决定是否合理"，但这违反了 CLAUDE.md 测试策略 §2 "测试失败路径" 的精神——失败路径应该测 **协议如何拒绝**，而非 **生成违反协议的序列**。

**依据**：ISO 13400-2:2019 §9.3.6.3："If the routing activation failed, the DoIP entity shall close the TCP connection."

**影响**：生成 Wireshark 标记为 "Diagnostic message before successful routing activation" 的非法序列。T26 通过则说明实现生成了非法报文——典型的"测试通过但测错东西"。

**修复建议**：将 §4.3 改为 "ResponseCode != 0x00 时，Planner 跳过诊断消息阶段，直接进入 TCP 挥手"。删除 T26 或改为 "Validate 警告 ResponseCode!=0 + Messages!=nil 不合理"。

### H6. PowerMode Broadcast=true 未覆盖 spec.DstIP/DstMAC

**位置**：§3.1 DoIPPowerMode（第 534-546 行）、§4.7（第 687-688 行）、§3.3（第 592-597 行）。

**描述**：§3.1 DoIPPowerMode.Broadcast 默认 true，§3.2 确认 "PowerMode.Broadcast | true"。§3.3 仅说明 Discovery 广播时覆盖 DstMAC，**未提及 PowerMode 广播时的 DstIP/DstMAC 覆盖**。

若 PowerMode.Broadcast=true 但 spec.DstIP 是单播 IP（如 10.0.0.1），Planner 不覆盖 spec.DstIP，则 0x4003 请求会发到单播地址而非广播。这与 Broadcast=true 语义矛盾。

**依据**：ISO 13400-2:2019 §11.2.1 Diagnostic Power Mode Request 可广播发送。

**影响**：PowerMode 广播模式下 DstIP/DstMAC 不一致，广播请求发到单播地址，其它 ECU 收不到。

**修复建议**：在 §3.3 或 §4.7 明确 "PowerMode.Broadcast=true 时，DstIP=255.255.255.255（或 IPv6 ff02::1），DstMAC=ff:ff:ff:ff:ff:ff（或 IPv6 33:33:00:00:00:01），覆盖 spec 对应字段"。

### H7. IPv6 组播 DstMAC 仅在 R4 提及，主文本未落地

**位置**：§1.5（第 47 行）、R4（第 1302 行）、§3.3（第 596 行）、§5.1（第 720 行）。

**描述**：§1.5 提到 "UDP 广播在 IPv6 用组播 ff02::1"，R4 提到 "DstMAC 为 33:33:00:00:00:01"。但 §3.3（DstMAC 覆盖规则）和 §5.1（PacketConfig 填充）**未在主流程中实现 IPv6 组播 MAC 的判断逻辑**。

§3.3 只说 "UDP 广播时 DstMAC 默认 ff:ff:ff:ff:ff:ff"，未区分 IPv4/IPv6。R4 作为 "风险与未决事项" 出现，说明主文本未落地。

**依据**：RFC 2464 §7 IPv6 多播以太网 MAC = `33:33:00:00:00:xx`（取多播地址末 32 位）。ff02::1 → `33:33:00:00:00:01`。

**影响**：IPv6 场景下广播包的 DstMAC 错误（用了 IPv4 广播 MAC ff:ff:ff:ff:ff:ff 而非 IPv6 组播 MAC 33:33:00:00:00:01），二层不通。

**修复建议**：在 §3.3 / §5.1 明确 "Broadcast=true 且 SrcIP 含 `:`（IPv6）时，DstIP=ff02::1，DstMAC=33:33:00:00:00:01；否则 DstIP=255.255.255.255，DstMAC=ff:ff:ff:ff:ff:ff"。补 T09a 测 IPv6 广播。

### H8. 0x11/0x2E/0x31/0x3E UDS 服务无专用测试用例（CLAUDE.md §1 违规）

**位置**：§8.1（第 1149-1150 行）、§7.1 测试用例表、§2.15 UDS 服务表。

**描述**：§8.1 自认 "0x11 ECUReset、0x2E WriteDataByIdentifier、0x31 RoutineControl、0x3E TesterPresent 需补单独用例（实现阶段补 T20a-T20d）"。

按 CLAUDE.md §1 "Spec-driven test derivation"：§2.15 UDS 服务表 10 项中 4 项无专用用例，覆盖率 60%。这违反 "每个 spec 表行至少一条用例" 的规则。

更严重的是：**0x3E TesterPresent 是 DoIPConfig 的默认 UDS**（`Message.UDS.ServiceID` 默认 0x3E），却无专用测试验证默认 UDS 序列化。T14 测 "默认值" 但不断言 0x3E 字节。

**依据**：CLAUDE.md §1 "Every table, field list, and error-handling row in the design spec is a test-case checklist." §2.15 表 10 行是 spec 表，每行需至少一条用例。

**影响**：UDS 序列化器对 0x11/0x2E/0x31/0x3E 的字段排布（子功能、DID/RID、Data）无测试守护，可能产生字节错位。

**修复建议**：在 §7.1 补：
- T20a（0x11 ECUReset sub=0x01 → `11 01` / 正向响应 `51 01`）
- T20b（0x2E WriteData DID=0xF190 + data=[0xAA,0xBB] → `2E F1 90 AA BB` / `6E F1 90`）
- T20c（0x31 RoutineControl sub=0x01 RID=0xFF01 → `31 01 FF 01` / `71 01 FF 01`）
- T20d（0x3E TesterPresent sub=0x00 → `3E 00` / `7E 00`）

### H9. 0x8003 NackCode 仅测非法值 0x10，合法值 0x00-0x0B 全未测（CLAUDE.md §2/§3 违规）

**位置**：§7.2 T22、§2.14 NackCode 表。

**描述**：T22 测 NackCode=0x10（非法值，见 C4），而 §2.14 表中 12 个合法 NackCode（0x00-0x0B）**无一被测试**。

按 CLAUDE.md §2 "Cover failure paths" 和 §3 "One test per code path"：每个 NackCode 是独立 code path，需独立测试。当前覆盖率 0/12。

**依据**：CLAUDE.md §3 "If a method/branch exists, it needs a test that exercises it." NackCode 0x00-0x0B 是 12 个独立分支。

**影响**：0x8003 NackCode 序列化可能错位（如 NackCode 字节位置错、PrevDiagMsgLen 与 PrevDiagMsg 不匹配），无测试守护。

**修复建议**：至少补 3 条代表性用例：
- T22a（NackCode=0x00 Invalid Source Address）
- T22b（NackCode=0x06 Access Denied）
- T22c（NackCode=0x08 Identification Required）
每条断言 0x8003 完整字节（SA + TA + NackCode + PrevLen + PrevDiag）。

### H10. 0x0000 Generic NACK 仅测 NackCode=0x01，其余 4 个未测

**位置**：§7.2 T23、§2.3 NACK 码表。

**描述**：§2.3 定义 5 个 NACK Code（0x00-0x04），T23 仅测 0x01（Unknown Payload Type）。0x00/0x02/0x03/0x04 无测试。

按 CLAUDE.md §3 "One test per code path"：5 个 NACK Code 各是独立 path，覆盖率应 5/5。当前 1/5。

**依据**：CLAUDE.md §3。ISO 13400-2:2019 §8.4.1 表 8-1 定义 5 个 NACK Code。

**影响**：0x0000 NACK 序列化对 0x00/0x02/0x03/0x04 的字节编码无测试守护。

**修复建议**：补：
- T23a（NackCode=0x00 Incorrect Pattern Format）
- T23b（0x02 Message Too Large）
- T23c（0x03 Out of Memory）
- T23d（0x04 Invalid Payload Length）

### H11. 路由激活 ResponseCode 仅测 0x01，0x02-0x08 全未测

**位置**：§7.2 T21、§2.9 ResponseCode 表。

**描述**：§2.9 定义 9 个 ResponseCode（0x00-0x08），T21 仅测 0x01（Unknown Source Address）。0x02-0x08 共 7 个值无测试。

按 CLAUDE.md §3：每个 ResponseCode 是独立 path。当前覆盖率 2/9（0x00 由 T01 隐含覆盖，0x01 由 T21 覆盖）。

**依据**：CLAUDE.md §3。ISO 13400-2:2019 §9.3.6 表 9-1 定义 9 个 ResponseCode。

**影响**：0x0006 ResponseCode 字节位置可能错（尤其在 13B payload 中），0x02-0x08 场景无测试守护。

**修复建议**：至少补：
- T21a（0x02 All sockets used）
- T21b（0x05 Missing Authentication）
- T21c（0x07 Unsupported Activation Type）
- T21d（0x08 TLS Required）

---

## 4. MEDIUM 问题

### M1. 0x0002 ResponseEID 未强制与请求 EID 一致

**位置**：§3.1 DoIPDiscovery.ResponseEID（第 397-398 行）。

**描述**：0x0002 请求按 EID 查找 ECU，0x0004 应答应包含 **相同的 EID**。但设计允许 ResponseEID 独立配置，默认回退到 DoIPConfig.EID。若用户设 ResponseEID 与请求 EID 不同，会生成语义矛盾的应答（请求 EID A，应答 EID B）。

**修复建议**：Validate 阶段强制 ResponseEID（若非空）== 请求 EID（若 RequestType=0x0002）。

### M2. 0x36 BlockSequenceCounter 回绕未处理

**位置**：§3.1 DoIPUDS.BlockSequenceCounter（第 502 行）、§2.15 0x36 说明。

**描述**：BlockSequenceCounter 是 1B，按 ISO 14229-1 §11.4.3.3 从 1 开始递增，0xFF 后回绕到 0x00。设计默认值 1，但未说明回绕行为。多帧刷写（>255 帧）场景会溢出。

**修复建议**：在 §2.15 或 §3.1 注明 "BlockSequenceCounter 按 (n-1) % 256 + 1 回绕"。补 T06a 测 256 帧 TransferData 的回绕。

### M3. NegativeResponseCode 方向语义未明确

**位置**：§3.1 DoIPUDS.NegativeResponseCode（第 516-519 行）。

**描述**：NegativeResponseCode 非 0 时生成 `7F <SID> <NRC>`。但否定响应是 **ECU 发送**（down 方向）。若 `Message.Direction="up"`（请求）且 NegativeResponseCode 非 0，应生成什么？设计未明确。

**修复建议**：明确 "NegativeResponseCode 仅在 Direction=down 时生效；Direction=up 时忽略并警告"。

### M4. 自动 SubFunction 检测规则未明确

**位置**：§3.1 DoIPUDS.HasSubFunction（第 479-481 行）。

**描述**：HasSubFunction=nil 时 "auto (emit sub-function for services that require it)"。但哪些服务 "require" 子功能未列出。按 §2.15：0x10/0x11/0x27/0x31/0x3E 有子功能；0x22/0x2E/0x34/0x36/0x37 无子功能（紧跟 DID/fmt/blockSeq/nothing）。0x36 的 BlockSequenceCounter 是否算子功能？设计未明确。

**修复建议**：在 §3.1 列出 "有子功能的服务集合 {0x10, 0x11, 0x27, 0x31, 0x3E}"，并说明 0x36 的 BlockSeq 作为独立字段（非 SubFunction）。

### M5. 0x36 TransferData 4095B UserData 上限非协议强制

**位置**：§6.16.11、R2（第 1300 行）。

**描述**：§6.16.11 设 UserData 上限 4095B，R2 说 "Validate 默认上限 4095B，可通过 OEM 选项放宽"。但 4095B 限制来自 ISO 15765-2（ISO-TP / CAN 传输层），**DoIP 不受此限制**。DoIP 的 UserData 上限受 0x8002 PrevDiagMsgLen（2B=65535B）和 TCP 缓冲约束。

4095B 限制过于保守，会导致大文件刷写场景（如 4096B/帧）无法配置，与 T06 矛盾（见 C2）。

**修复建议**：将 UserData 上限改为 65533B（65535 - SID - BlockSeq），或移除硬限制交由调用方控制。

### M6. ActivationType 保留范围 (0x02-0xDF) Validate 规则未完整指定

**位置**：§2.8 ActivationType 表、§6.16.13（第 1043 行）。

**描述**：§2.8 定义 0x00、0x01、0xE0-0xFF 为合法，0x02-0xDF 为保留。§6.16.13 仅测 0x05 被拒。Validate 是否拒绝整个 0x02-0xDF 范围未明确。T18 测 0xE0 通过，但 0x02-0xDF 边界（如 0xDF）未测。

**修复建议**：明确 "Validate 拒绝 0x02-0xDF"，补 T18a 测 0xDF 被拒、T18b 测 0xE0 通过（已有 T18）。

### M7. FurtherActionRequired 保留值未拒绝

**位置**：§2.7 FurtherActionRequired 表、§3.1 DoIPDiscovery.FurtherActionRequired。

**描述**：§2.7 列出合法值 0x00/0x10/0x11/0x20/0x40，0x01 为 "Reserved by ISO"。但 DoIPDiscovery.FurtherActionRequired 是 uint8，允许任意值。Validate 是否拒绝 0x01 及其它未列出值未明确。

**修复建议**：明确 "Validate 仅接受 {0x00, 0x10, 0x11, 0x20, 0x40, 0xE0-0xFF}，拒绝 0x01-0x0F/0x12-0x1F/0x21-0x3F/0x41-0xDF"。补 T16a 测 0x01 被拒。

### M8. DiagnosticPowerMode 保留值未拒绝

**位置**：§2.11 DiagnosticPowerMode 表。

**描述**：§2.11 定义 0x00/0x01/0x02，其中 0x02 为保留。DoIPPowerMode.PowerMode 是 uint8。0x03-0xFF 是否拒绝未明确。注意 §3.2 默认值表写 "PowerMode.PowerMode | 0x01（ready）"，但 §3.1 注释写 "0x00 not ready (default)"——**默认值自相矛盾**。

**修复建议**：明确 "Validate 仅接受 {0x00, 0x01}，拒绝 0x02-0xFF"。修正 §3.1 或 §3.2 的默认值矛盾（建议默认 0x01 ready 与 §3.2 一致）。

### M9. AckCode 非 0 值未拒绝

**位置**：§2.13 AckCode、§3.1 DoIPMessage.AckCode。

**描述**：§2.13 说 "AckCode | 0x00 = ACK"，ISO 13400-2:2019 §10.4.3.4 定义其它值为保留。DoIPMessage.AckCode 允许任意 uint8。Validate 未拒绝非 0 值。

**修复建议**：明确 "Validate 拒绝 AckCode != 0x00"。

### M10. Vehicle Announcement 500ms 间隔未明确跳过

**位置**：§2.7（第 155 行）、§4.1（第 644 行）。

**描述**：§2.7 说 "公告由 ECU 启动时主动发送 3 次（间隔 500ms ± 100ms）"。§4.1 说 "间隔可由 spec.ThinkTime 模拟但不强制"。

"不强制" 语义模糊：是 3 个公告背靠背发（无延迟），还是依赖 spec.ThinkTime 控制延迟？若前者，与 ISO 13400-2:2019 §8.5.1 的 500ms 间隔不符；若后者，需明确 ThinkTime 的映射关系。

**修复建议**：明确 "Planner 生成 3 条 0x0004 公告，PacketIndex 连续递增，不注入时间延迟（时间精度由 worker 层 Pacer 控制，不在 Planner 范围）"。

### M11. 0x0004 公告内容一致性未指定

**位置**：§4.1（第 644 行）。

**描述**：Announcement 模式发 3 条 0x0004，3 条的 VIN/LogicalAddress/EID/GID/FAR/SyncStatus 是否完全相同？ISO 13400-2:2019 §8.5.1 要求相同。设计未明确。

**修复建议**：明确 "N 条公告内容完全相同（同 VIN/LA/EID/GID/FAR/Sync）"。补 T16a 断言 3 条公告字节级一致。

### M12. T45 并发测试仅断言 -race 干净，未测聚合行为（CLAUDE.md §6 违规）

**位置**：§7.4 T45（第 1127 行）。

**描述**：T45 "PacketWorkers=8 并发 | 8 ECU 并发 | 无 race；-race 干净"。

按 CLAUDE.md §6 "Concurrency tests must verify correctness, not just race-safety"："-race 干净不代表逻辑正确。需测聚合可观察行为（如总包数 = 8×20=160，每 ECU 内 PacketIndex 单调）"。

T45 仅断言无 race，未断言总包数或 per-ECU 单调性。这是 CLAUDE.md 明确警告的反模式："a pacer concurrency test checked -race was clean (no data race) but never measured the actual aggregate rate, so 8 workers each sleeping independently (8x the configured rate) passed."

**修复建议**：补 T45 断言 "总包数 = 160（8 ECU × 20 包/ECU）；每 ECU 的 PacketIndex 在其 FlowID 内 0..19 单调；FlowID 8 类互不冲突"。

### M13. §6.9 安全访问"请求种子响应"方向标注与 DOIP 语义不符

**位置**：§6.9（第 901、907 行）。

**描述**：§6.9 注释 Idx N 为 "请求种子响应"，Direction=down（ECU→Tester）。但 ISO 14229-1 §11.4.2 SecurityAccess 的 "请求种子" 是 Tester 发送 `27 01` 请求，ECU 回 `67 01 <seed>` 响应。设计把 "请求种子响应" 标为 ECU 发送（down）是对的，但 UserData 用 `27 01`（请求 SID）而非 `67 01`（响应 SID）——这是 C8 的根因。

更细的问题：§6.9 的 Config 把 `Seed` 字段放在 Direction=down 的 Message 里，但 DoIPUDS.Seed 注释（第 490 行）写 "Response-only. Empty = no seed bytes"——暗示 Seed 是响应字段。但结构体没有 IsResponse 标志，Plan 如何知道这条 Message 是响应还是请求？只能靠 Direction=down 推断，但 Direction=down 也可用于 Tester 发送的下行请求（极少见但合法）。

**修复建议**：与 C8 一起修复——新增 IsResponse 字段，明确 Seed/Key 的方向语义：IsResponse=true 时用 SID|0x40 + Seed；IsResponse=false 时用 SID + Key。

---

## 5. LOW 问题

### L1. "WWHDOIP" 术语略松

**位置**：§2.8 ActivationType 表（第 169 行）。

**描述**：0x01 命名为 "WWHDOIP（全球车载诊断激活）"。ISO 13400-2:2019 §9.2.4.2 原文为 "WWH-DOIP"（World Wide Harmonized DoIP），中文直译应为 "全球协调 DOIP"。"全球车载诊断" 是意译但不够精确。

**修复建议**：改为 "WWH-DOIP（全球协调车载诊断激活）"。

### L2. UDP 临时源端口选择未指定

**位置**：§1.2（第 28 行）。

**描述**：§1.2 说 "UDP 用任意 ephemeral port → 13400"。但 "任意" 的具体选择策略未指定。是 spec.SrcPort（与 TCP 共用），还是 Planner 自动分配？若与 TCP 共用 SrcPort，UDP 与 TCP 子流 4-tuple 仅差协议号（6 vs 17），需确认无冲突。

**修复建议**：明确 "UDP 子流 SrcPort = spec.SrcPort（与 TCP 共用），DstPort = 13400"。或若需独立 SrcPort，明确分配规则。

### L3. R7 关于 InverseProtocolVersion 拒绝的描述误导

**位置**：R7（第 1305 行）。

**描述**：R7 说 "Validate 拒绝用户提供的 InverseProtocolVersion 字段（不暴露）"。但 DoIPConfig 结构体中 **根本没有 InverseProtocolVersion 字段**，用户无法提供。R7 描述了一个不存在的风险。

**修复建议**：删除 R7，或改为 "InverseProtocolVersion 不暴露为 Config 字段，由 Planner 自动计算，无用户误配风险"。

### L4. GenericNack 发送时机不匹配 NACK 语义

**位置**：§4.8（第 691-692 行）。

**描述**：§4.8 说 GenericNack 在 "路由激活之后、诊断消息之前" 发送。但 0x0000 Generic NACK 按 ISO 13400-2:2019 §8.4.1 是 **接收方检测到头部错误后的响应**，不是主动发起。设计生成 "孤悬 NACK"（无前置错误包）语义不准确。

虽然这是流量生成器的合理简化（不模拟错误包本身），但应明确说明。

**修复建议**：在 §4.8 补充 "GenericNack 模拟 ECU 对未生成的 malformed 包的响应，malformed 包本身不在输出中"。

### L5. 扩展表 5 字段 doipMessageType / diagnosticDataLen 未直接映射

**位置**：§1.4（第 36-39 行）。

**描述**：扩展表 5 要求记录 doipMessageType 和 diagnosticDataLen。设计将这些映射到 Config 结构（Discovery/Activation/Messages 等子结构）和 PayloadLength（自动计算），**未提供单一字段** doipMessageType 供日志记录。

diagnosticDataLen 对应 0x8001 UserData 长度，设计用 Message.UserData 长度隐式表达，无显式字段。

**影响**：pcap-replay 侧若按扩展表 5 字段名比对，可能找不到对应 Config 字段。

**修复建议**：在 §1.4 补充映射表 "doipMessageType → 由 Planner 输出的 PayloadType 字段（日志元数据）；diagnosticDataLen → Message.UserData 长度（自动计算）"。

### L6. §5.4 IPID 从 0 起始可能被指纹识别

**位置**：§5.4（第 741 行）。

**描述**：nextIPID() 从 0 单调递增。真实 DoIP 实现的 IPID 起始值通常随机（避免操作系统指纹识别）。从 0 起始可能被 IDS 识别为流量生成器。

对比 SOCKS5 `socks5.go` 第 303 行 `ipID := uint16(0)` 也是从 0 起——这是项目惯例，但 DOIP 作为车联网协议，IDS 检测风险更高。

**修复建议**：可选改为 "IPID 起始值随机（RFC 6528 风格），后续单调递增"。或保持项目惯例但在文档注明。

### L7. §7.5 用例计数与实际条目不符

**位置**：§7.5 用例统计表（第 1131-1137 行）。

**描述**：§7.5 声称 "正向 20（T01-T20）/ 负向 6（T21-T26）/ 边界 14（T27-T40）/ 集成 5（T41-T45）/ 合计 45"。

实际清点：
- 正向 T01-T20 = 20 条 ✓
- 负向 T21-T26 = 6 条 ✓
- 边界 T27-T40 = 14 条 ✓
- 集成 T41-T45 = 5 条 ✓
- 合计 45 ✓

计数正确，但 §8.1 提到 "实现阶段补 T20a-T20d"，这些用例未计入 45 条。若补足，总数应为 49+。建议在 §7.5 注明 "实现阶段补 T20a-T20d/T21a-T21d/T22a-T22c/T23a-T23d 后总数 ~60"。

**修复建议**：在 §7.5 补一行 "实现阶段补足后预期总数 ~60 条"。

---

## 6. 字段覆盖率审计（扩展表 5）

扩展表 5（`docs/protocol-designs/00-unimplemented-list.md` 第 19 行）要求记录的字段 vs 设计覆盖情况：

| 扩展表 5 字段 | 设计对应 | 覆盖状态 |
|---|---|---|
| doipMessageType | 由 Config 子结构（Discovery/Activation/Messages/AliveCheck/PowerMode/GenericNack）隐式确定，Planner 输出 PayloadType | 隐式覆盖，无单一字段（见 L5） |
| doipPayloadLen | PayloadLength，由 Planner 自动计算 | 覆盖（自动） |
| furtherActionRequired | DoIPDiscovery.FurtherActionRequired | 覆盖（但保留值未拒绝，见 M7） |
| diagnosticDataLen | Message.UserData 长度（隐式） | 隐式覆盖（见 L5） |
| diagnosticData | Message.UserData / Message.UDS | 覆盖 |
| responseCode | Activation.ResponseCode（0x0006）+ NackCode（0x8003） | 覆盖（但 NackCode 测试用非法值，见 C4） |
| ActivationType | Activation.ActivationType | 覆盖 |
| activationResCode | Activation.ResponseCode（与 responseCode 同字段） | 覆盖（同字段） |

**结论**：8 个字段全部覆盖，但 doipMessageType 和 diagnosticDataLen 为隐式覆盖，建议在 §1.4 补充显式映射说明（L5）。FurtherActionRequired 和 AckCode 的 Validate 规则缺失（M7/M9）影响字段值的安全性。

---

## 7. 测试用例质量审计

按 CLAUDE.md 测试策略 §1-§8 逐条审计 45 条用例：

### 7.1 §1 Spec-driven test derivation

| Spec 表行 | 对应用例 | 状态 |
|---|---|---|
| §2.1 DoIP 头 | T38（InversePV 一致性） | 覆盖 |
| §2.3 NACK Code 0x00-0x04 | T23（仅 0x01） | **不足**：4/5 未测（H10） |
| §2.7 FurtherActionRequired 0x00/0x10/0x11/0x20/0x40 | 无 | **缺失**（M7） |
| §2.7 SyncStatus 0x00/0x01 | 无 | **缺失** |
| §2.8 ActivationType 0x00/0x01/0xE0-0xFF | T01/T02/T18 | 覆盖（边界 0xDF 未测，M6） |
| §2.9 ResponseCode 0x00-0x08 | T01（0x00）/T21（0x01） | **不足**：7/9 未测（H11） |
| §2.11 PowerMode 0x00/0x01/0x02 | T08（0x01） | **不足**：0x00/0x02 未测（M8） |
| §2.13 AckCode 0x00 | T03-T06（隐含 0x00） | 覆盖（非 0 值未拒绝，M9） |
| §2.14 NackCode 0x00-0x0B | T22（0x10 非法） | **缺失**：12 个合法值全未测（H9） |
| §2.15 UDS 0x10/0x11/0x22/0x27/0x2E/0x31/0x34/0x36/0x37/0x3E | T03(0x10)/T04(0x22)/T05(0x27)/T06(0x34/0x36/0x37)/T20(0x34) | **不足**：0x11/0x2E/0x31/0x3E 未测（H8） |

**违规**：§1 要求 "每行至少一条用例"，§2.14 整表 0 合法用例，§2.7 FAR/SyncStatus 0 用例，§2.15 UDS 4/10 无专用用例。

### 7.2 §2 Cover failure paths

| 失败路径 | 对应用例 | 状态 |
|---|---|---|
| 0x0006 拒绝 | T21 | 覆盖（仅 1/8 ResponseCode） |
| 0x8003 拒绝 | T22 | 覆盖（非法 NackCode，C4） |
| 0x0000 NACK | T23 | 覆盖（仅 1/5 NackCode） |
| UDS 否定响应 | T24 | 覆盖 |
| TCP 中断 | T25 | 覆盖 |
| 拒绝后继续诊断 | T26 | 覆盖（但序列非法，H5） |
| VIN/EID 长度错 | T27/T28/T29 | 覆盖 |
| ActivationType 保留 | T30 | 覆盖（仅 0x05） |
| ProtocolVersion 不支持 | T31 | 覆盖 |
| UserData 超限 | T32 | 覆盖（但与 T06 矛盾，C2） |

**部分违规**：失败路径有覆盖但深度不足（ResponseCode 2/9、NackCode 0/12、NACK Code 1/5）。

### 7.3 §3 One test per code path

14 个 PayloadType 覆盖情况：

| PayloadType | 对应用例 | 状态 |
|---|---|---|
| 0x0000 | T23 | 覆盖 |
| 0x0001 | T09 | 覆盖 |
| 0x0002 | T10 | 覆盖 |
| 0x0003 | T11 | 覆盖 |
| 0x0004 | T09-T11（应答）/T16（公告） | 覆盖 |
| 0x0005 | T01/T02 | 覆盖 |
| 0x0006 | T01/T21 | 覆盖 |
| 0x0007 | T07 | 覆盖 |
| 0x0008 | T07 | 覆盖 |
| 0x4003 | T08 | 覆盖 |
| 0x4004 | T08 | 覆盖 |
| 0x8001 | T03-T06/T20 | 覆盖 |
| 0x8002 | T03-T06 | 覆盖 |
| 0x8003 | T22 | 覆盖 |

**合规**：14/14 PayloadType 覆盖。但每个 PayloadType 内部的 code path（如不同 NackCode、不同 ResponseCode）未全覆盖（见 §7.1）。

### 7.4 §4 Integration tests

T41-T45 覆盖端到端、多 ECU、GroupID 路由、ctx 取消、并发。**合规**。

但缺 "Discovery + Activation + Messages 无 PowerMode" 的组合（T41 包含所有阶段），建议补 T41a 测部分阶段组合。另缺 "仅 Discovery 无 TCP" 的纯 UDP 场景。

### 7.5 §5 Assert observable outcomes

大部分用例断言具体字节（如 T03 "UserData = `10 01`"）。但部分用例仅断言结构：
- T14 "默认值"：断言 VIN/LogicalAddress/SourceAddress 默认值，未断言生成的 DoIP 头字节。
- T36 "Empty Messages"：仅断言 "无诊断包"，未断言完整包序列。
- T37 "Empty Discovery"：仅断言 "用默认 0x0001 广播"，未断言字节。
- T45 "并发"：仅断言 -race 干净，未断言聚合包数（M12）。

**部分违规**：4 条用例断言不充分。

### 7.6 §6 Concurrency correctness

T45 仅断言 -race 干净（见 M12）。**违规**：未测聚合行为。CLAUDE.md §6 明确警告 "a pacer concurrency test checked -race was clean but never measured the actual aggregate rate"。

### 7.7 §7 Failing-test-first

设计阶段无 bug，§8.7 声明 "实现阶段强制执行"。**合规**（设计阶段）。

### 7.8 §8 Adversarial review of test quality

本审计即为对抗审查。发现以下 "测试通过但测错东西" 的风险：
- T06 测 4096B Data 但 Validate 应拒绝（C2）—— 测试若通过说明 Validate 未实现。
- T20 期望字节与输入 fmt 矛盾（C3）—— 测试若通过说明序列化器按错误逻辑编码。
- T22 用非法 NackCode=0x10（C4）—— 测试若通过说明 Validate 未检查 NackCode 范围。
- T26 测协议非法序列（H5）—— 测试通过但生成 Wireshark 标记为异常的报文。
- T05/T06 响应消息用请求 SID（C8）—— 测试通过但生成 SID 错误的 UDS 响应。
- T17 V1 兼容仅断言头 2 字节（C6）—— 测试通过但 V1 路由激活格式未测。

### 7.9 测试用例质量总评

| 维度 | 评分 | 说明 |
|---|---|---|
| Spec 覆盖（§1） | 中 | PayloadType 全覆盖，但表内 code path 深度不足 |
| 失败路径（§2） | 中下 | 有覆盖但 ResponseCode/NackCode 深度严重不足 |
| Code path（§3） | 中上 | 14 PayloadType 覆盖，子 path 不足 |
| 集成（§4） | 良 | T41-T45 覆盖端到端 |
| 可观察断言（§5） | 良 | 大部分断言字节，4 条不足 |
| 并发正确性（§6） | 差 | T45 仅 -race，未测聚合 |
| 失败测试优先（§7） | N/A | 设计阶段 |
| 对抗审查（§8） | — | 本审计进行中 |

---

## 8. 多 ECU 场景正确性

### 8.1 4-tuple 唯一性

§6.15 要求 "M 个独立 DoIPConfig，每个挂在不同 FlowSpec 上，4-tuple 不同（不同 DstIP 或 DstPort）"。设计合理。

但未在 Validate 层强制：若两个 DoIPConfig 共用 4-tuple（同 DstIP+DstPort+SrcIP+SrcPort），FlowID 冲突，resequencer 混序。设计依赖策略层保证 4-tuple 唯一性，未在 DoIP Planner 内校验。

**建议**：在 §6.15 补充 "Validate 无法跨 FlowSpec 校验 4-tuple 唯一性，由策略层在 class 级别保证"。

### 8.2 LogicalAddress 唯一性

§6.15 要求 "不同 LogicalAddress"。但同样未跨 FlowSpec 校验。两个 ECU 配相同 LogicalAddress 会导致 0x8001 TargetAddress 歧义。

**建议**：同 8.1，由策略层保证。

### 8.3 VIN 唯一性

设计未提及多 ECU 场景的 VIN 唯一性。同一车辆内多 ECU 应共享同一 VIN（ISO 13400-2:2019 §8.5.5.1），但不同 ECU 的 0x0004 应答中 VIN 相同、LogicalAddress 不同。设计未明确这一约束。

**建议**：在 §6.15 补充 "多 ECU 共享同一 VIN，LogicalAddress 不同"。

### 8.4 GroupID 路由

§3.3 声明 "UDP 与 TCP 子流共享同一 GroupID，确保两者路由到同一 PacketWorker，保持发送顺序"。

但多 ECU 场景下，若所有 ECU 的 GroupID 相同，所有包路由到同一 PacketWorker，退化为串行。R3 提及此风险但缓解方案 "调用方调整 PacketWorkers" 不足。

**建议**：明确 "多 ECU 场景每个 ECU 用不同 GroupID（按 4-tuple 哈希），确保并行"。

### 8.5 多 ECU 测试覆盖

T13（3 ECU FlowID 唯一）、T40（同 T13）、T42（3×20=60 包）、T45（8 ECU -race）。

**缺失**：
- 多 ECU 共用 4-tuple 的冲突场景（应被策略层拒绝）
- 多 ECU 共用 LogicalAddress 的冲突场景
- 多 ECU 共用 VIN 的正确性验证
- 多 ECU 共用 GroupID 的串行退化场景

---

## 9. 总体评分

### 9.1 分项评分

| 维度 | 满分 | 得分 | 说明 |
|---|---|---|---|
| ISO 13400-2 一致性 | 25 | 16 | 头部/PayloadType 表正确；路由激活格式正确但示例 hex 错（C1）；V1 兼容虚假（C6）；AliveCheck 方向非法（H1）；EID 推导错 MAC（C5） |
| 扩展表 5 字段覆盖 | 10 | 8 | 8 字段覆盖，2 字段隐式（L5），FurtherActionRequired/AckCode Validate 缺失（M7/M9） |
| 状态机完整性 | 15 | 11 | 5 阶段完整；AliveCheck 方向错（H1）；GenericNack 时机语义不准（L4）；拒绝后继续诊断非法（H5） |
| UDS 服务字段格式 | 15 | 8 | 10 ServiceID 覆盖；T20 编码 bug（C3）；响应 SID 缺失（C8）；SubFunction 自动检测未明确（M4） |
| 多 ECU 场景 | 10 | 7 | 4-tuple/LA 区分合理；跨 FlowSpec 校验缺失；UDP FlowID 冲突（C7） |
| 测试用例质量（CLAUDE.md §1-§8） | 20 | 10 | 数量达标但 spec 覆盖深度不足；NackCode/ResponseCode 严重缺失；并发测试不充分；4 条用例测错东西 |
| 文档一致性 | 5 | 2 | §6.4 与附录 A 矛盾（C1）；T06 与 §6.16.11 矛盾（C2）；§3.1 与 §3.2 PowerMode 默认值矛盾（M8） |

### 9.2 总分

| 总分 | 62 / 100 |
|---|---|
| 评级 | C+（需修正后方可实现） |

### 9.3 阻塞性问题清单（实现前必须修复）

| # | 问题 | 严重度 |
|---|---|---|
| C1 | §6.4 hex PayloadLength 错误 | CRITICAL |
| C2 | T06 vs §6.16.11 UserData 上限矛盾 | CRITICAL |
| C3 | T20 期望字节与 fmt=0x22 矛盾 | CRITICAL |
| C4 | T22 NackCode=0x10 非法 | CRITICAL |
| C5 | EID 推导用错 MAC（SrcMAC vs DstMAC） | CRITICAL |
| C6 | V1 兼容性虚假（无版本门控） | CRITICAL |
| C7 | UDP 子流 FlowID 冲突（Discovery + PowerMode） | CRITICAL |
| C8 | UDS 响应消息用请求 SID（缺 IsResponse 字段） | CRITICAL |
| H1 | AliveCheck Direction 语义错 | HIGH |
| H5 | 拒绝后继续诊断生成非法序列 | HIGH |
| H8-H11 | 测试用例 spec 覆盖严重不足 | HIGH |

### 9.4 非阻塞性建议

- M1-M13：实现阶段逐步修正
- L1-L7：文档优化，可在实现后补充

### 9.5 与 SOCKS5 Planner 模式对比

DOIP 设计在结构上借鉴了 SOCKS5 的 Planner 模式（emit/emitData/emitUDP 闭包、FlowID+":udp" 子流、GroupID 路由），整体架构合理。主要差距：

| 对比项 | SOCKS5 | DOIP | 差距 |
|---|---|---|---|
| UDP 子流数 | 1（udp_associate） | 2（Discovery + PowerMode） | FlowID 后缀冲突（C7） |
| 失败路径测试 | 7 条 MCP e2e | T21-T26（6 条，深度不足） | NackCode/ResponseCode 覆盖率低 |
| 协议版本兼容 | SOCKS4/5 双版本，版本门控完整（socks5.go 第 283-286 行 SOCKS4 udp_associate 降级） | V1/V2 声称但无版本门控 | C6 |
| Validate 严格度 | 端口/地址/Cmd 全校验 | SourceAddress/TargetAddress 一致性未校验 | H3/H4 |
| 响应码区分 | Reply rep=0/非0 二元 | 9 个 ResponseCode + 12 个 NackCode + 5 个 NACK Code | 表全但测试深度不足 |
| UDS 请求/响应区分 | N/A | 缺 IsResponse 字段 | C8 |

### 9.6 结论

DOIP 设计文档在 **协议头部格式、PayloadType 表、状态机阶段划分、附录字节级对照表** 上基本正确，可作为实现起点。但存在 **8 个 CRITICAL 问题**（示例 hex 错误、测试用例自相矛盾、V1 兼容虚假、EID 推导错 MAC、UDP FlowID 冲突、UDS 响应 SID 缺失）和 **11 个 HIGH 问题**（AliveCheck 方向非法、测试覆盖深度不足、SourceAddress/TargetAddress 一致性未校验、拒绝后继续诊断非法），**必须在实现前修复**。

测试用例数量（45 条）达标但质量不达标：按 CLAUDE.md §1-§8 审计，spec 覆盖深度不足（NackCode 0/12、ResponseCode 2/9、UDS 服务 6/10、NACK Code 1/5），并发测试仅 -race 干净未测聚合，存在 6 处 "测试通过但测错东西" 风险（T06/T20/T22/T26/T05/T17）。

**建议**：修复全部 CRITICAL + HIGH 问题后，再进入实现阶段。修复后预期评分 85+（A-）。

---

**审计完成时间**：2026-08-03
**审计问题总数**：39
**严重度分布**：CRITICAL 8 / HIGH 11 / MEDIUM 13 / LOW 7

# DOIP 设计文档 v2.0.0 复审报告（R1）

> 审计对象：`docs/protocol-designs/05-doip-design.md`（v2.0.0，1500 行，2026-08-05）
> 审计依据：ISO 13400-2:2019（Diagnostic over IP）、ISO 14229-1（UDS）、scapy `contrib/automotive/doip.py`、Wireshark `packet-doip.c`、python-doipclient `messages.py`、CLAUDE.md §Testing Policy
> 审计模式：独立复审，默认"有 bug"，逐字节验算 + 逐字段对照 ISO/scapy/Wireshark
> 审计日期：2026-08-05
> 审计人：独立协议审计代理（与 v2.0.0 设计者无交叉）

---

## 1. 审计概览

### 1.1 审计方法

1. 通读全文 1500 行，对 DoIP 头 8B、0x0005/0x0006 PayloadLength（7+N/9+N）、0x8001 SA/TA/UserData、0x8002/0x8003 AckCode/NackCode/PrevDiag 等逐字节验算。
2. 加载 scapy `contrib/automotive/doip.py`、Wireshark `epan/dissectors/packet-doip.c`、python-doipclient `messages.py` 三方参考实现，对照 §2 PayloadType 表 16 项与字段宽度。
3. 对照 ISO 13400-2:2019 §8（DoIP 头/发现/公告）、§9（路由激活）、§10（诊断消息/存活检查）、§11（电源模式/Entity Status）原文条款，逐项验证。
4. 对 §6 HexDump S1-S15 逐字节核算，验证 PayloadLength 与字段宽度自洽性。
5. 对 §7 测试用例 T001-T200 共 200 条，按 CLAUDE.md §Testing Policy §1-§8 对抗式复核。
6. 重点核实 v2.0.0 修订记录声称修复的 26 项问题（C1-C6/H1-H7/M1-M9/L1-L5）是否真正落地。

### 1.2 总体结论

v2.0.0 相对 v1.2 在协议合规性上有重大改进：C1（ResponseCode Success=0x10）、C2（NackCode 0x00/0x01=Reserved）、C3（新增 0x4001/0x4002）、C4（FurtherActionRequired 仅 0x00/0x10）、C5（SyncStatus 0x10=Not synced）等 5 项 CRITICAL 修复均已正确落地；H1-H7、M1-M9、L1-L5 大部分也已落地。

但本次复审发现 **3 项新 CRITICAL + 4 项 HIGH + 6 项 MEDIUM + 4 项 LOW = 17 项问题**，其中最严重的是 **CRITICAL-1：0x8002/0x8003 报文格式与 ISO/scapy/Wireshark/python-doipclient 四方参考实现矛盾**——设计在 AckCode/NackCode 与 PreviousDiagnosticMessage 之间凭空插入了一个 2 字节（V2）/ 4 字节（V1）的 `PreviousDiagnosticMessageLength` 字段，但 ISO 13400-2:2019 §10.4.3/§10.4.5 与所有三方实现均显示该位置无任何长度字段，PreviousDiagnosticMessage 是变长尾部，长度由 PayloadLength 隐式推导。实现照抄 §2.14/§2.15 会生成畸形报文，Wireshark 标记为 malformed。

**本文档不可直接进入实现阶段。**

### 1.3 严重度分布

| 严重度 | 数量 | 说明 |
|---|---|---|
| CRITICAL | 3 | 0x8002/0x8003 凭空插入 PrevDiagMsgLen 字段、HexDump 多处错误被保留、T067 与 §6.13.7/§6.13.8 边界自相矛盾 |
| HIGH | 4 | S10 HexDump 0x34 UserData 长度错误、S3 0x8001 HexDump "修正"后仍遗留错误注释、§6.13.23 OEM 上限与 §6.13.6 矛盾、T067 与 §6.13.7 边界冲突 |
| MEDIUM | 6 | §4.3 二次确认流程缺 ResponseCode=0x05 收尾、§6.13.5 PrevLen u16 上限假设错误、§9.7 R5 措辞、§7 多条用例无 spec 行引用、Direction 校验缺 0x0007/0x0008 反向用例、V1+PowerMode 拒绝缺 spec 依据 |
| LOW | 4 | 文档总行数声明错误、缩写表缺 ECU/Tester 等条目、§1.6 与 §3.1 Direction 注释重复、附录 B 0x34 参数位置不完整 |
| **合计** | **17** | |

### 1.4 v2.0.0 已正确落地的修复（予以肯定）

- **C1 落地**：§2.9 ResponseCode 表 Success=0x10、Confirmation Required=0x11、0x00..0x07=拒绝码，与 scapy 行 180-196 完全一致。
- **C2 落地**：§2.15 NackCode 表 0x00/0x01=Reserved、0x02=Invalid SA、0x03=Unknown TA、0x04=Too Large、0x05=Out of Memory、0x06=Target Unreachable、0x07=Unknown Network、0x08=Transport Error，与 scapy 行 217-223 完全一致。
- **C3 落地**：§2.2 表新增 0x4001/0x4002，§2.11a 定义完整 7B Payload（NodeType 1B + MaxOpenSockets 1B + CurOpenSockets 1B + MaxDataSize 4B BE），§3.1 新增 DoIPEntityStatus 结构体，§4.2 新增阶段 2，§6.7 新增 S7 场景，§7.6 新增 T091-T100。
- **C4 落地**：§2.7 FurtherActionRequired 仅 0x00/0x10 合法，0x01..0x0F + 0x11..0xFF 全部 Reserved，与 scapy 行 144-155 一致。
- **C5 落地**：§2.7 SyncStatus 0x00=Synchronized、0x10=NOT synchronized、0x01..0x0F + 0x11..0xFF Reserved，与 scapy 行 158-169 一致。
- **C6 落地**：§7.10 新增 T131-T140 IPv6 场景，§7.13 新增 T177-T180 IPv6 端到端。
- **H1 落地**：§2.8/§2.9 OEM-specific 改为变长 N B，PayloadLength=7+N / 9+N，§3.1 OEMSpecific 改为 `[]byte`，§3.2 默认 nil。
- **H4 落地**：§2.12 DiagnosticPowerMode 0x02=Not Supported，Validate 接受 {0x00,0x01,0x02}。
- **H5 落地**：§5.2 MSS=0 → Validate 报错或 fallback 1460，§6.13.22 + T147/T148。
- **H6 落地**：§8.4 NRC 仅接受 0x01..0x7F，T047/T048/T049。
- **H7 落地**：§2.9 新增 0x11 Confirmation Required，§4.3 新增二次确认子阶段，T021f/T027/T181。
- **M3 落地**：§3.1 BlockSequenceCounter 公式改为 n%256（不是 (n-1)%256）。
- **M5 落地**：§2.8 ActivationType=0x01 改为 WWH-OBD（不是 WWH-DOIP）。
- **M7 落地**：§3.1 GenericNack Direction 固定 "down"，删除 "up" fuzzing 选项，T128。
- **M9 落地**：§2.13/§8.3 SA/TA 一致性校验，T029/T030。

### 1.5 三方参考实现一致性矩阵

| 字段/枚举 | ISO 13400-2 | scapy | Wireshark | python-doipclient | 本设计 v2.0.0 | 状态 |
|---|---|---|---|---|---|---|
| DoIP 头 8B | §8.3 | ✓ | ✓ | ✓ | ✓ | 一致 |
| PayloadType 16 项 | §8.x | ✓ | ✓ | ✓ | ✓ | 一致 |
| 0x0006 ResponseCode | §9.3.6 | ✓ | ✓ | ✓ | ✓ | 一致（C1 已修） |
| 0x8003 NackCode | §10.4.5 | ✓ | ✓ | ✓ | ✓ | 一致（C2 已修） |
| 0x4002 NodeType | §11.1 | ✓ | ✓ | ✓ | ✓ | 一致（C3 已修） |
| FurtherActionRequired | §8.5.3 | ✓ | ✓ | ✓ | ✓ | 一致（C4 已修） |
| SyncStatus | §8.5.5 | ✓ | ✓ | ✓ | ✓ | 一致（C5 已修） |
| DiagnosticPowerMode | §11.2.2 | ✓ | ✓ | ✓ | ✓ | 一致（H4 已修） |
| **0x8002 Payload 结构** | §10.4.3 | SA+TA+AckCode+PrevDiag（无 Len） | SA+TA+AckCode+PrevDiag（无 Len） | SA+TA+AckCode+PrevDiag（无 Len） | SA+TA+AckCode+**PrevLen(2B/4B)**+PrevDiag | **不一致（CRITICAL-1）** |
| **0x8003 Payload 结构** | §10.4.5 | SA+TA+NackCode+PrevDiag（无 Len） | SA+TA+NackCode+PrevDiag（无 Len） | SA+TA+NackCode+PrevDiag（无 Len） | SA+TA+NackCode+**PrevLen(2B/4B)**+PrevDiag | **不一致（CRITICAL-1）** |
| 0x0005 reserved_oem | §9.2.4 | XStrField（变长） | 变长 | 变长 | []byte（变长） | 一致（H1 已修） |
| 0x8002 PrevDiag 长度上限 | §10.4.3 | 无独立字段 | tvb 剩余字节 | tvb[5:payload_length] | u16 65535 / u32 4GB-1 | **不一致（CRITICAL-1）** |

---

## 2. 逐项审计发现

### CRITICAL-1：0x8002/0x8003 凭空插入 PreviousDiagnosticMessageLength 字段

- **位置**：§2.14（行 360-376）0x8002 Diagnostic Message Ack 格式表、§2.15（行 378-406）0x8003 Diagnostic Message Nack 格式表、§6.3 S3 HexDump、§6.4 S4 HexDump、§6.13.5/§6.13.6/§6.13.7/§6.13.8 边界值、T017/T018/T053/T054/T064-T068 测试用例
- **描述**：设计在 0x8002/0x8003 的 AckCode/NackCode 与 PreviousDiagnosticMessage 之间插入了一个 `PreviousDiagnosticMessageLength` 字段（V2=u16 BE 2B，V1=u32 BE 4B），并据此推导 PayloadLength = 7+M（V2）/ 9+M（V1）。但 ISO 13400-2:2019 §10.4.3（0x8002）/§10.4.5（0x8003）定义的 Payload 结构为：
  - 0x8002：`SourceAddress(2) + TargetAddress(2) + AckCode(1) + PreviousDiagnosticMessage(变长)` = 5 + M B
  - 0x8003：`SourceAddress(2) + TargetAddress(2) + NackCode(1) + PreviousDiagnosticMessage(变长)` = 5 + M B
  
  四方参考实现一致确认无独立长度字段：
  - **scapy** `doip.py`：`previous_msg = XStrField` 条件为 `p.payload_type in [0x8002, 0x8003]`，**无 PreviousDiagnosticMessageLength 字段**，PreviousDiagnosticMessage 直接消费剩余字节。
  - **Wireshark** `packet-doip.c`：`tvb_captured_length_remaining(tvb, DOIP_DIAG_MESSAGE_ACK_PREVIOUS_OFFSET)` 动态计算剩余字节，无独立 length 字段。
  - **python-doipclient** `messages.py`：`DiagnosticMessagePositiveAcknowledgement.unpack` = `struct.unpack_from("!HHB", payload_bytes)` + `payload_bytes[5:payload_length]`，明确显示 5B 头（SA 2 + TA 2 + AckCode 1）+ 变长 PrevDiag，**无 PrevLen 字段**。
  
  设计的 PrevLen 字段是凭空添加的。实现照抄 §2.14/§2.15 会产生两种畸形：
  1. PayloadLength 与实际 Payload 字节数不匹配（多 2B/4B）
  2. PreviousDiagnosticMessage 起始偏移错误（实际从偏移 13/15 开始，设计从 15/17 开始），Wireshark 标记为 malformed。
- **依据**：ISO 13400-2:2019 §10.4.3/§10.4.5；scapy `doip.py` fields_desc；Wireshark `packet-doip.c` `DOIP_DIAG_MESSAGE_ACK_PREVIOUS_OFFSET`；python-doipclient `messages.py` 行 691-716/591-619
- **修复建议**：
  1. §2.14 表删除 `PreviousDiagnosticMessageLength` 行，PayloadLength = 5 + M（不分 V1/V2）
  2. §2.15 表同样删除 `PreviousDiagnosticMessageLength` 行，PayloadLength = 5 + M
  3. §2.14/§2.15 备注：PreviousDiagnosticMessage 长度由 PayloadLength - 5 隐式推导，与 scapy/Wireshark/python-doipclient 一致
  4. §3.1 DoIPMessage.UserData 注释更新（不再有 PrevLen 字段）
  5. §6.3 S3 0x8002 HexDump 重写：`02 FD 80 02 00 00 00 07` + `00 01 0E 80 00 10 03`（PayloadLength = 5+2 = 7，PrevDiag=10 03）
  6. §6.4 S4 0x8003 HexDump 重写：`02 FD 80 03 00 00 00 08` + `00 01 0E 80 02 22 F1 90`（PayloadLength = 5+3 = 8）
  7. §6.13.5/§6.13.6 边界值删除（PrevLen u16 上限已不存在）
  8. §6.13.7/§6.13.8 0x36 Data 上限改为受 PayloadLength u32 上限约束（4GB-1），实际受 TCP MSS 与 MaxDataSize 约束
  9. T017/T018/T053/T054/T064-T068 全部重写：删除 PrevLen 字段断言，改为 PayloadLength = 5 + len(PrevDiag) 断言
  10. §1.3 V1/V2 版本差异说明删除"0x8002/0x8003 PrevDiagMsgLen = 4B（u32）"行（V1/V2 在该字段无差异）
  11. §8.5 边界与上限：0x8001 UserData 长度上限改为受 0x4002 MaxDataSize 与 PayloadLength u32 上限约束，删除"受 0x8002 PrevLen u16 上限约束"

### CRITICAL-2：§6.3 S3 HexDump "修正"后注释遗留错误，0x8001 HexDump 与 0x8002 HexDump 计算错误被保留

- **位置**：§6.3 S3（行 744-776）
- **描述**：§6.3 S3 的 0x8001 HexDump 经"修正"后为 `02 FD 80 01 00 00 00 06 / 0E 80 00 01 10 03`，PayloadLength=0x06=6。核算：SA(2) + TA(2) + UserData(2) = 6，正确。
  - 但 0x8001 HexDump 上方仍保留"修正前"的 `02 FD 80 01 00 00 00 05`（PayloadLength=0x05=5）与"修正"注释（行 753-755），导致同一 HexDump 出现两个版本，实现者无法判断采用哪个。
  - 0x8002 HexDump 经"修正"后为 `02 FD 80 02 00 00 00 09 / 00 01 0E 80 00 00 02 10 03`，PayloadLength=0x09=9。核算：SA(2) + TA(2) + AckCode(1) + PrevLen(2) + PrevDiag(2) = 9（按设计的 PrevLen 字段）。
  - 但 0x8002 上方同样保留"修正前"的 `00 00 00 07`（PayloadLength=0x07=7）注释（行 768-770），同一 HexDump 出现两个版本。
  - 同时 §6.3 S3 0x8002 行 773-776 "修正"后的 9 字节 HexDump `00 01 0E 80 00 00 02 10 03` 拆分异常：按设计字段顺序 SA(00 01) + TA(0E 80) + AckCode(00) + PrevLen(00 02) + PrevDiag(10 03) = 9B 正确，但 0x8001 部分"修正前"的 5 字节 HexDump（`02 FD 80 01 00 00 00 05 / 0E 80 00 01 10 03`）实际上算 SA(2)+TA(2)+UserData(2)=6 而非 5，所以"修正"是必要的，但注释遗留导致文档自相矛盾。
- **依据**：CLAUDE.md §Testing Policy §5（断言可观察值）；设计自洽性
- **修复建议**：
  1. §6.3 S3 删除所有"修正前"HexDump 与"修正"注释，仅保留最终正确版本
  2. 同时按 CRITICAL-1 修复 0x8002 HexDump（删除 PrevLen 字段）
  3. 全文排查其他"修正"注释（§6.10 S10 行 867-872 0x36 HexDump 同样有"修正"注释），统一删除并保留最终版本

### CRITICAL-3：§6.13.7/§6.13.8 与 T066/T067/T068 边界值自相矛盾

- **位置**：§6.13.7（行 925）、§6.13.8（行 926）、T066（行 1093）、T067（行 1094）、T068（行 1095）
- **描述**：§6.13.7 定义 "0x36 Data 上限：Data=65531B（UserData=65533B=SID+BlockSeq+Data）→ PrevLen=0xFFFD 通过"。§6.13.8 定义 "0x36 Data 溢出：Data=65534B（UserData=65536B > 65535）→ Validate 报错"。
  - T066：Data=65531B → UserData=65533B → PrevLen=0xFFFD 通过
  - T067：Data=65532B → UserData=65534B → **通过**（≤65535 u16 上限）
  - T068：Data=65534B → UserData=65536B → Validate 报错（H2）
  
  矛盾点：
  1. §6.13.7 称 UserData=65533B 是上限（Data=65531B），但 T067 允许 UserData=65534B（Data=65532B）通过。65534 > 65533，按 §6.13.7 应拒绝，但 T067 通过。
  2. §6.13.8 称 Data=65534B（UserData=65536B）拒绝，但 T068 也是 Data=65534B（UserData=65536B）拒绝——这里一致，但 T067 的 Data=65532B 与 §6.13.7 的 Data=65531B 上限只差 1B，逻辑上 65532 应也超上限。
  3. 根本原因：设计混淆了"0x36 服务 Data 字段上限"与"0x8002 PrevLen u16 上限"。前者无 ISO 上限（受 MaxDataSize 约束），后者受 u16 字段宽度约束（但 CRITICAL-1 已指出 PrevLen 字段不存在）。
  4. 修复 CRITICAL-1 后，§6.13.7/§6.13.8 与 T066/T067/T068 的整个边界逻辑需重写：UserData 上限改为受 0x4002 MaxDataSize 与 PayloadLength u32 上限约束。
- **依据**：CLAUDE.md §Testing Policy §1（spec-driven）；ISO 13400-2:2019 §10.4.3/§11.1
- **修复建议**：
  1. 修复 CRITICAL-1 后，§6.13.5-§6.13.8 全部重写：
     - §6.13.5：UserData ≤ MaxDataSize（若 EntityStatus 存在）→ 通过
     - §6.13.6：UserData > MaxDataSize → Validate 报错
     - §6.13.7：UserData ≤ PayloadLength u32 上限（4GB-1）→ 通过
     - §6.13.8：UserData > 4GB-1 → Validate 报错（理论边界，实际不可达）
  2. T064-T068 重写为 MaxDataSize 边界测试，而非 PrevLen u16 边界测试
  3. §8.5 边界与上限同步更新

### HIGH-1：§6.10 S10 0x34 RequestDownload HexDump UserData 长度与 PayloadLength 不自洽

- **位置**：§6.10 S10（行 850-859）
- **描述**：0x34 HexDump 为 `02 FD 80 01 00 00 00 0B / 0E 80 00 01 34 00 44 00 00 00 01`。
  - PayloadLength = 0x0B = 11
  - 核算：SA(2) + TA(2) + UserData(?) = 4 + UserData = 11 → UserData = 7B
  - UserData 字节：`34 00 44 00 00 00 01` = 7B ✓
  - 但 UserData 注释（行 858）写 "SID(1) + dataFormatId(1) + addressAndLengthFormatId(1) + addr(4 if fmt&0x0F==4) + size(4 if fmt&0xF0==0x40) = 11B"，与实际 UserData 7B 不符。
  - 实际 UserData `34 00 44 00 00 00 01` 拆分：SID=0x34, dataFormatId=0x00, addressAndLengthFormatId=0x44（高 4 位=4=addr 长度，低 4 位=4=size 长度），addr=0x00000001（4B），size=缺失（应 4B 但 HexDump 只到 01）。
  - 所以 HexDump 实际缺 size 字段 4B，正确 HexDump 应为 `02 FD 80 01 00 00 00 0F / 0E 80 00 01 34 00 44 00 00 00 01 00 00 00 10`（PayloadLength = 4 + 11 = 15 = 0x0F）。
  - §6.10 注释（行 858）"size 暂略简化"承认了这一点，但简化后的 HexDump 不是合法 0x34 报文（Wireshark 标记为 malformed）。
- **依据**：ISO 14229-1 §11.4.3.3 RequestDownload 服务格式；设计 §10.1 附录 B
- **修复建议**：
  1. §6.10 0x34 HexDump 补全 size 字段 4B，PayloadLength 改为 0x0F=15
  2. 或将 §6.10 注释改为"示例简化，实际 0x34 UserData 必须包含完整 size 字段"
  3. T041 输入 `AddressAndLength=00 44 00 00 00 01 00 00 00 10` 已正确包含 size=0x10，UserData 应为 11B，PayloadLength 应为 15。§6.10 HexDump 需与 T041 一致。

### HIGH-2：§6.3 S3 0x8001 HexDump "修正"注释遗留，且 0x8002 HexDump 与 CRITICAL-1 矛盾

- **位置**：§6.3 S3（行 744-776）
- **描述**：见 CRITICAL-2。除注释遗留问题外，0x8002 HexDump `00 01 0E 80 00 00 02 10 03`（9B）中的 `00 02` 是设计凭空添加的 PrevLen 字段，与 CRITICAL-1 矛盾。修复 CRITICAL-1 后应为 `00 01 0E 80 00 10 03`（7B，PayloadLength=7）。
- **依据**：CRITICAL-1
- **修复建议**：随 CRITICAL-1 一并修复

### HIGH-3：§6.13.23 OEM-specific 上限与 §6.13.6/§6.13.8 边界矛盾

- **位置**：§6.13.23（行 941）、§6.13.6（行 924）、§6.13.8（行 926）
- **描述**：§6.13.23 测试 "OEM-specific=4B → PayloadLength=11（0x0005）/ 13（0x0006）"。核算：0x0005 = SA(2) + AT(1) + Reserved(4) + OEM(4) = 11 ✓；0x0006 = CLA(2) + SLA(2) + RC(1) + Reserved(4) + OEM(4) = 13 ✓。
  - §6.13.24 测试 "OEM-specific=0B → PayloadLength=7（0x0005）/ 9（0x0006）"。核算：7=2+1+4+0 ✓，9=2+2+1+4+0 ✓。
  - 但 §6.13.6 测试 "0x8002 PrevDiagMsgLen u16 溢出 → Validate 报错"，意味着 PrevDiagMsgLen u16 上限 65535B 是硬约束。若 OEM-specific=4B 且 UserData=65535B，0x8001 PayloadLength = 4 + 65535 = 65539B，受 0x8002 PrevLen u16 约束（CRITICAL-1 已指出该约束不存在）。
  - §6.13.23 与 §6.13.6 的约束逻辑相互独立但文档未明确：OEM-specific 长度上限受 0x0005/0x0006 PayloadLength u32 上限约束（4GB-1），不受 PrevLen u16 约束。设计未声明 OEM-specific 上限，可能导致实现者误以为 OEM-specific 也受 65535B 约束。
- **依据**：CLAUDE.md §Testing Policy §1
- **修复建议**：
  1. §8.5 边界与上限新增 "OEM-specific 长度 ≤ PayloadLength u32 上限 - 7（0x0005）/ 9（0x0006）"
  2. §6.13.23 注明 "OEM-specific 不受 PrevLen u16 约束"
  3. 修复 CRITICAL-1 后，§6.13.6 整个删除，本问题自动消解

### HIGH-4：T067 与 §6.13.7 边界冲突

- **位置**：T067（行 1094）、§6.13.7（行 925）
- **描述**：见 CRITICAL-3。T067 Data=65532B → UserData=65534B 通过，但 §6.13.7 称 Data=65531B（UserData=65533B）是上限。65534 > 65533，逻辑矛盾。
- **依据**：CRITICAL-3
- **修复建议**：随 CRITICAL-3 一并修复

### MEDIUM-1：§4.3 二次确认流程缺 ResponseCode=0x05 收尾场景

- **位置**：§4.3（行 614-621）
- **描述**：§4.3 子阶段列出 4 步：(1) Tester 0x0005 → (2) ECU 0x0006 RC=0x11 → (3) Tester 0x0005 二次 → (4) ECU 0x0006 RC=0x10。但 §2.9 ResponseCode 表定义 0x05 = "Rejected Confirmation"——即二次确认也可能被拒绝。§4.3 未列出"二次确认被拒"子场景，T027 仅测"0x0005×2 + 0x0006×2"成功路径，未测 0x05 拒绝路径。
- **依据**：ISO 13400-2:2019 §9.3.6（0x05=Rejected Confirmation）；CLAUDE.md §2（cover failure paths）
- **修复建议**：
  1. §4.3 子阶段新增步骤 4'：ECU 0x0006 RC=0x05（二次确认被拒）→ TCP FIN
  2. 新增 T027a：ConfirmationRequired=true + 二次确认 RC=0x05 → 0x0005×2 + 0x0006(RC=0x11) + 0x0006(RC=0x05) + TCP FIN

### MEDIUM-2：§6.13.5/§6.13.6 PrevLen u16 上限假设错误

- **位置**：§6.13.5（行 923）、§6.13.6（行 924）
- **描述**：§6.13.5 称 "UserData=65535B → PrevLen=0xFFFF 通过"，§6.13.6 称 "UserData=65536B → PrevLen u16 overflow → Validate 报错"。但 CRITICAL-1 已指出 PrevLen 字段不存在，PreviousDiagnosticMessage 长度由 PayloadLength u32 隐式推导。因此 §6.13.5/§6.13.6 的整个边界逻辑无效。
  - 即使忽略 CRITICAL-1，按设计的 PrevLen u16 上限逻辑：PrevLen u16 上限 = 65535，但 UserData 是 0x8001 的字段，PrevLen 是 0x8002 的字段，二者通过 PreviousDiagnosticMessage 副本关联。PrevLen 描述的是 PreviousDiagnosticMessage 长度（= UserData 长度），所以 UserData ≤ 65535 的约束来自 PrevLen u16 字段宽度。但 CRITICAL-1 指出该字段不存在，约束失效。
- **依据**：CRITICAL-1
- **修复建议**：随 CRITICAL-1 一并删除

### MEDIUM-3：§9.7 R5 措辞与 §2.15 注释重复

- **位置**：§9.7 R5（行 1385）
- **描述**：R5 "0x8003 NackCode 0x00/0x01 是 Reserved（不是 Invalid SA / Target Unreachable）"。§2.15 已明确说明，R5 重复。且 R5 措辞"不是 Invalid SA / Target Unreachable"暗示 v1.2 的错误，对实现者无指导意义。
- **依据**：文档自洽性
- **修复建议**：
  1. R5 改为 "0x8003 NackCode 合法值 0x02-0x08，0x00/0x01/0x09-0xFF Reserved"
  2. 或删除 R5（§2.15 已说明）

### MEDIUM-4：§7 多条测试用例无 spec 行引用

- **位置**：§7 全部用例（T001-T200）
- **描述**：CLAUDE.md §Testing Policy §1 要求"每条测试用例对应 spec 行"。§7 用例表只有"用例/场景/输入/断言"四列，无"对应 spec 行"列。例如 T001 断言"头 = 02 FD 00 01 00 00 00 00"，但未引用 §2.1（DoIP 头）或 §2.4（0x0001）。实现者难以反查 spec 依据。
  - §7 开头（行 997）提到"对应 spec 行"，但表格无该列。
- **依据**：CLAUDE.md §Testing Policy §1
- **修复建议**：
  1. §7 每个用例表新增"对应 spec 行"列
  2. 或在"场景"列括注 spec 行号（如 "T001 DoIP 头 8B V2 (§2.1)"）

### MEDIUM-5：Direction 校验缺 0x0007/0x0008 反向用例

- **位置**：§8.6（行 1338-1340）、§7.8（T119/T120）
- **描述**：§8.6 规定 "0x0007 Direction 必须为 'down'"，"0x0008 Direction 必须为 'up'"。T119 测 "0x0007 Direction='up' → Validate 报错"，T120 测 "0x0008 Direction='down' → Validate 报错"。但 §7.8 仅此 2 条反向用例，缺正向用例（0x0007 Direction="down" 通过、0x0008 Direction="up" 通过）。T111/T112 隐式覆盖正向，但未明确标注 Direction 校验。
- **依据**：CLAUDE.md §Testing Policy §3（one test per code path）
- **修复建议**：
  1. T111 注释补 "Direction='down' 通过"
  2. T112 注释补 "Direction='up' 通过"
  3. 新增 T119a：0x0007 Direction="down" 通过；T120a：0x0008 Direction="up" 通过

### MEDIUM-6：V1+PowerMode 拒绝缺 spec 依据

- **位置**：§1.3（行 69）、§8.1（行 1289）、T110（行 1152）
- **描述**：§1.3 称 "V1 不支持 0x4003/0x4004（Validate 拒绝 PowerMode + V1 组合）"。§8.1 重申。T110 测 "PV=0x01 PowerMode 非 nil → Validate 报错"。
  - 但 ISO 13400-2:2019 并未明确禁止 V1 使用 0x4003/0x4004。scapy `doip.py` 的 0x4003/0x4004 字段条件是 `p.payload_type in [0x4003, 0x4004]`，与 protocol_version 无关。python-doipclient 也无 V1+PowerMode 拒绝逻辑。
  - 设计声明 V1 不支持 PowerMode 是设计选择（非 ISO 要求），但未在 spec 中说明理由。实现者可能误以为是 ISO 要求。
- **依据**：ISO 13400-2:2019 §11.2（无 V1 限制）；scapy `doip.py` fields_desc
- **修复建议**：
  1. §1.3 改为 "本设计选择不支持 V1+PowerMode 组合（设计决策，非 ISO 要求）"
  2. §8.1 同步
  3. T110 注释补 "设计决策，非 ISO 要求"

### LOW-1：文档总行数声明错误

- **位置**：行 1495
- **描述**：声明"文档总行数：约 1050 行"，实际 1500 行。
- **依据**：文档自洽性
- **修复建议**：改为"约 1500 行"

### LOW-2：缩写表缺 ECU/Tester/TCP/UDP 等条目

- **位置**：§10.2 缩写表（行 1417-1437）
- **描述**：缩写表列 17 项，但缺 ECU（Electronic Control Unit）、Tester、TCP、UDP、ISO、RFC 等常用缩写。CLAUDE.md 要求"每个英文术语首次出现需中文解释"。
- **依据**：CLAUDE.md 中文章写要求
- **修复建议**：缩写表补全 ECU/Tester/TCP/UDP/ISO/RFC 等

### LOW-3：§1.6 与 §3.1 Direction 注释重复

- **位置**：§1.6（行 105-112）、§3.1 多处 Direction 字段注释
- **描述**：§1.6 定义 Direction "up/down/空" 约定，§3.1 DoIPDiscovery.Direction/DoIPPowerMode.Direction/DoIPActivation.Direction/DoIPMessage.Direction/DoIPEntityStatus.Direction/DoIPAliveCheck.Direction 注释均重复说明。LOW-5（v2.0.0 已修）要求 §3.1 引用 §1.6，但 §3.1 仍重复。
- **依据**：文档自洽性
- **修复建议**：§3.1 各 Direction 字段注释改为 "见 §1.6"

### LOW-4：附录 B 0x34 参数位置不完整

- **位置**：§10.1 附录 B（行 1410）
- **描述**：0x34 行 "addrLenFmt 高 4 位=addr 长度，低 4 位=size 长度"，但未说明 addr/size 长度的具体取值（1/2/4/8B 对应 0x1/0x2/0x4/0x8）。实现者难以判断 UserData 总长。
- **依据**：ISO 14229-1 §11.4.3.3
- **修复建议**：附录 B 0x34 行补 "addr 长度 ∈ {0x1:1B, 0x2:2B, 0x4:4B, 0x8:8B}，size 长度同"

---

## 3. 测试用例覆盖率分析（对照 CLAUDE.md §Testing Policy）

### 3.1 spec-driven test derivation（§1）

- §2 PayloadType 表 16 项：T001-T020 覆盖 14 项（0x0000/0x0001/0x0002/0x0003/0x0004/0x0005/0x0006/0x0007/0x0008/0x4001/0x4002/0x4003/0x4004/0x8001/0x8002/0x8003 全覆盖）✓
- §2.3 0x0000 NackCode 5 值：T121-T125 全覆盖 ✓
- §2.7 FurtherActionRequired 2 值：T073/T074 通过 + T075/T076/T077 拒绝 ✓
- §2.7 SyncStatus 2 值：T078/T079 通过 + T080 拒绝 ✓
- §2.9 ResponseCode 11 值：T021/T021a-T021g 覆盖 0x10/0x00/0x01/0x04/0x05/0x07/0x11/0x12 ✓
- §2.15 NackCode 9 值（0x02-0x08 + 0x00/0x01 拒绝）：T056-T062 全覆盖 ✓
- §2.12 DiagnosticPowerMode 3 值：T103/T104/T105 通过 + T106 拒绝 ✓
- §2.11a NodeType 2 值：T093/T094 通过 + T095 拒绝 ✓
- §2.16 UDS 服务 10 项：T031-T050 全覆盖 ✓
- §1.4 扩展表 5 字段映射：未独立测试用例（遗漏）

### 3.2 cover failure paths（§2）

- 路由激活失败：T021a-T021e/T026 ✓
- 0x8003 Nack 各码：T056-T062 ✓
- 0x0000 GenericNack 各码：T121-T126 ✓
- V1+OEM 拒绝：T025 ✓
- V1+PowerMode 拒绝：T110 ✓（但缺 spec 依据，见 MEDIUM-6）
- **遗漏**：二次确认被拒（ResponseCode=0x05）路径（MEDIUM-1）

### 3.3 one test per code path（§3）

- 每个 PayloadType 单独测：16/16 ✓
- 每个 UDS 服务单独测：10/10 ✓
- **遗漏**：0x8002/0x8003 PrevDiag 为空（M=0）场景无独立用例

### 3.4 integration tests（§4）

- T171-T185 端到端：15 条覆盖单 ECU/多 ECU/IPv6/二次确认/路由激活失败/Entity Status/大文件/Nack ✓
- **遗漏**：无 PowerMode + EntityStatus + Discovery 三阶段 UDP 混合端到端用例

### 3.5 assert observable outcomes（§5）

- 每条用例断言 PayloadLength/字段字节值：基本满足
- **弱点**：T0194（Announcement 间隔）未断言具体 Timestamp 值，仅"由 Pacer 控制"

### 3.6 concurrency correctness（§6）

- T174/T175/T176 PacketWorkers=8 并发：覆盖总包数 + 阶段顺序 + FlowID 后缀 ✓
- 改进明显（v1.2 的 MEDIUM-2 已修）

### 3.7 failing-test-first（§7）

- 设计阶段无 bug：声明于 §8.7
- v2.0.0 修订记录显示 v1.2→v2.0.0 修复 26 项但未提供"failing test 先行"证据

### 3.8 adversarial review of test quality（§8）

- §7 用例表标注对应场景编号：✓
- v2.0.0 修订记录列出 26 项修复：✓
- **遗漏**：v2.0.0 修订未对 0x8002/0x8003 PrevDiagMsgLen 字段存在性做对抗复核（CRITICAL-1）

---

## 4. 与 ISO 13400-2:2019 规范一致性逐项核查

| # | 核查项 | ISO 13400-2:2019 要求 | 设计文档结论 | 状态 |
|---|---|---|---|---|
| 1 | DoIP 头 8B = PV(1)+InvPV(1)+PT(2)+PL(4) | §8.3 | §2.1 正确 | ✓ |
| 2 | InverseProtocolVersion = ~PV & 0xFF | §8.3 | §2.1/§1.3 正确 | ✓ |
| 3 | PayloadLength 不含头部 8B | §8.3 | §2.1 约束正确 | ✓ |
| 4 | PayloadType 大端 | §8.3 | §2.1 正确 | ✓ |
| 5 | 0x0000 Generic NACK Code 0x00-0x04 | §8.4.1 | §2.3 表完整 | ✓ |
| 6 | 0x0001 Vehicle Ident Req 无 payload | §8.5.2 | §2.4 正确 | ✓ |
| 7 | 0x0002 带 EID 6B | §8.5.3 | §2.5 正确 | ✓ |
| 8 | 0x0003 带 VIN 17B ASCII | §8.5.4 | §2.6 正确 | ✓ |
| 9 | 0x0004 Payload = VIN(17)+LA(2)+EID(6)+GID(6)+FAR(1)+Sync(1)=33B | §8.5.5 | §2.7 正确 | ✓ |
| 10 | 0x0004 公告发 3 次，间隔 500ms±100ms | §8.5.1 | §2.7/§4.1 正确（间隔由 Pacer 控制） | ✓ |
| 11 | 0x0004 FurtherActionRequired 仅 0x00/0x10 合法 | §8.5.3 | §2.7 正确（C4 已修） | ✓ |
| 12 | 0x0004 VIN/GID SyncStatus 仅 0x00/0x10 合法 | §8.5.5 | §2.7 正确（C5 已修） | ✓ |
| 13 | 0x0005 Req V2 = SA(2)+AT(1)+Rsv(4)+OEM(N)=7+N B | §9.2.4 | §2.8 正确（H1 已修） | ✓ |
| 14 | 0x0006 Resp V2 = CLA(2)+SLA(2)+RC(1)+Rsv(4)+OEM(N)=9+N B | §9.3.6 | §2.9 正确（H1 已修） | ✓ |
| 15 | 0x0006 ResponseCode Success=0x10 | §9.3.6 | §2.9 正确（C1 已修） | ✓ |
| 16 | 0x0006 ResponseCode 0x11=Confirmation Required | §9.3.6 | §2.9/§4.3 正确（H7 已修） | ✓ |
| 17 | 0x0007 Alive Check Req 始终 ECU→Tester | §10.2.2 | §4.5 Direction="down" 正确 | ✓ |
| 18 | 0x0008 Alive Check Resp 始终 Tester→ECU | §10.2.3 | §4.5 Direction="up" 正确 | ✓ |
| 19 | 0x4001 DoIP entity status req | §11.1 | §2.11a 正确（C3 已修） | ✓ |
| 20 | 0x4002 DoIP entity status resp | §11.1 | §2.11a 正确（C3 已修） | ✓ |
| 21 | 0x4003 Power Mode Req 无 payload | §11.2.1 | §2.12 正确 | ✓ |
| 22 | 0x4004 Power Mode Resp = 1B | §11.2.2 | §2.12 正确 | ✓ |
| 23 | 0x4004 DiagnosticPowerMode 0x02=Not Supported | §11.2.2 | §2.12 正确（H4 已修） | ✓ |
| 24 | 0x8001 = SA(2)+TA(2)+UserData(N) | §10.3.2 | §2.13 正确 | ✓ |
| 25 | 0x8001 SA 必须与 0x0005 SA 一致 | §10.3.2.1 | §2.13/§8.3 正确（M9 已修） | ✓ |
| 26 | 0x8001 TA 必须与 0x0006 SLA 一致 | §10.3.2.2 | §2.13/§8.3 正确（M9 已修） | ✓ |
| 27 | **0x8002 = SA(2)+TA(2)+AckCode(1)+PrevDiag(变长)** | §10.4.3 | §2.14 凭空插入 PrevLen 字段 | **✗（CRITICAL-1）** |
| 28 | 0x8002 AckCode 仅 0x00 合法 | §10.4.3.4 | §2.14 正确 | ✓ |
| 29 | **0x8003 = SA(2)+TA(2)+NackCode(1)+PrevDiag(变长)** | §10.4.5 | §2.15 凭空插入 PrevLen 字段 | **✗（CRITICAL-1）** |
| 30 | 0x8003 NackCode 0x00/0x01=Reserved | §10.4.5 | §2.15 正确（C2 已修） | ✓ |
| 31 | 路由激活失败应关闭 TCP | §9.3.6.3 | §4.3/T026 正确 | ✓ |
| 32 | UDP 广播 255.255.255.255 / IPv6 ff02::1 | §8.2 | §1.2/§3.3 正确 | ✓ |
| 33 | UDP 广播 MAC ff:ff:ff:ff:ff:ff / IPv6 33:33:00:00:00:01 | RFC 2464 | §3.3 正确 | ✓ |
| 34 | UDS ServiceId 正向响应 = Request SID \| 0x40 | ISO 14229-1 §7.1 | §3.1 DoIPUDS.IsResponse 正确 | ✓ |
| 35 | UDS Negative Response = 7F + Request SID + NRC | ISO 14229-1 §7.3 | §3.1/§8.4 正确（M1 已修） | ✓ |
| 36 | UDS BlockSequenceCounter 0xFF 后回绕到 0x00 | ISO 14229-1 §11.4.3.3 | §3.1 公式 n%256 正确（M3 已修） | ✓ |

**核查结果**：36 项中 34 项一致，2 项不一致（CRITICAL-1 影响 0x8002/0x8003 两项）。

---

## 5. HexDump 自洽性逐项验算

| 场景 | HexDump | PayloadLength 声明 | 实际核算 | 状态 |
|---|---|---|---|---|
| S1 0x0001 | `02 FD 00 01 00 00 00 00` | 0 | 头 8B + 0B = 8B ✓ | ✓ |
| S1 0x0004 | `02 FD 00 04 00 00 00 21` + 33B | 0x21=33 | 17+2+6+6+1+1=33 ✓ | ✓ |
| S2 0x0005 | `02 FD 00 05 00 00 00 07` + 7B | 0x07=7 | 2+1+4+0=7 ✓ | ✓ |
| S2 0x0006 | `02 FD 00 06 00 00 00 09` + 9B | 0x09=9 | 2+2+1+4+0=9 ✓ | ✓ |
| S3 0x8001 | `02 FD 80 01 00 00 00 06` + 6B | 0x06=6 | 2+2+2=6 ✓ | ✓（注释遗留见 CRITICAL-2） |
| S3 0x8002 | `02 FD 80 02 00 00 00 09` + 9B | 0x09=9 | 2+2+1+2+2=9（按设计）✓；但 ISO 实际 2+2+1+2=7（无 PrevLen） | **✗（CRITICAL-1）** |
| S4 0x8001 | `02 FD 80 01 00 00 00 08` + `0E 80 00 01 22 F1 90` | 0x08=8 | Payload 实际 7B（0E 80 00 01 22 F1 90），SA(2)+TA(2)+UserData(3)=7 → 应为 0x07；设计自身算式"2+2+3=8"亦错误（7≠8） | **✗（PayloadLength 错误）** |
| S4 0x8003 | `02 FD 80 03 00 00 00 0A` + 9B | 0x0A=10 | 2+2+1+2+3=10（按设计）✓；但 ISO 实际 2+2+1+3=8（无 PrevLen） | **✗（CRITICAL-1）** |
| S5 0x0007 | `02 FD 00 07 00 00 00 00` | 0 | 0B ✓ | ✓ |
| S5 0x0008 | `02 FD 00 08 00 00 00 02` + 2B | 0x02=2 | 2B ✓ | ✓ |
| S7 0x4001 | `02 FD 40 01 00 00 00 00` | 0 | 0B ✓ | ✓ |
| S7 0x4002 | `02 FD 40 02 00 00 00 07` + 7B | 0x07=7 | 1+1+1+4=7 ✓ | ✓ |
| S8 0x0000 | `02 FD 00 00 00 00 00 01` + 1B | 0x01=1 | 1B ✓ | ✓ |
| S10 0x34 | `02 FD 80 01 00 00 00 0B` + 7B | 0x0B=11 | 2+2+7=11 ✓（但 UserData 缺 size，见 HIGH-1） | **✗（HIGH-1）** |
| S10 0x36 | `02 FD 80 01 00 00 00 0A` + 6B | 0x0A=10 | 2+2+6=10 ✓ | ✓（注释遗留） |
| S10 0x37 | `02 FD 80 01 00 00 00 05` + 1B | 0x05=5 | 2+2+1=5 ✓ | ✓ |
| S11 0x0006 RC=0x00 | `02 FD 00 06 00 00 00 09` + 9B | 0x09=9 | 2+2+1+4+0=9 ✓ | ✓ |

**HexDump 验算结论**：
- S3 0x8002、S4 0x8003 受 CRITICAL-1 影响，PayloadLength 多 2B
- S4 0x8001 PayloadLength=0x08 但实际应为 0x07（HexDump 字节 6B + 头 8B，PayloadLength 应为 6，写 8 错误）
- S10 0x34 UserData 不完整（HIGH-1）
- 其余 HexDump 自洽

---

## 6. 最终结论与返工要求

### 6.1 最终结论

**本文档（v2.0.0）不可直接进入实现阶段。**

v2.0.0 正确修复了 v1.2 的 26 项问题中的大部分（C1-C5/H1/H4-H7/M1/M3/M5/M7/M9/L1-L5 已落地），但本次复审发现 3 项新 CRITICAL + 4 项 HIGH + 6 项 MEDIUM + 4 项 LOW = 17 项新问题。其中 **CRITICAL-1（0x8002/0x8003 凭空插入 PrevDiagMsgLen 字段）** 是协议级硬伤，与 ISO 13400-2:2019 §10.4.3/§10.4.5 及 scapy/Wireshark/python-doipclient 四方参考实现矛盾，实现照抄会生成 Wireshark 标记为 malformed 的畸形报文。

### 6.2 必须先返工的问题（按优先级）

#### P0 — 实现前必须修复

1. **CRITICAL-1**：0x8002/0x8003 删除 PreviousDiagnosticMessageLength 字段，PayloadLength = 5 + M（V1/V2 一致），HexDump/边界值/测试用例全部重写
2. **CRITICAL-2**：§6.3 S3 / §6.10 S10 HexDump "修正"注释清理，仅保留最终版本
3. **CRITICAL-3**：§6.13.7/§6.13.8 与 T066/T067/T068 边界值随 CRITICAL-1 重写

#### P1 — 实现前需修复

4. **HIGH-1**：§6.10 S10 0x34 HexDump 补全 size 字段
5. **HIGH-2**：§6.3 S3 0x8002 HexDump 随 CRITICAL-1 重写
6. **HIGH-3**：§6.13.23 OEM-specific 上限与 PrevLen 约束关系明确（随 CRITICAL-1 消解）
7. **HIGH-4**：T067 随 CRITICAL-3 重写

#### P2 — 实现阶段建议修复

8. **MEDIUM-1**：§4.3 二次确认流程补 0x05 拒绝子场景 + T027a
9. **MEDIUM-2**：§6.13.5/§6.13.6 随 CRITICAL-1 删除
10. **MEDIUM-3**：§9.7 R5 措辞简化
11. **MEDIUM-4**：§7 测试用例表新增"对应 spec 行"列
12. **MEDIUM-5**：T111/T112 补 Direction 正向断言 + T119a/T120a
13. **MEDIUM-6**：V1+PowerMode 拒绝注明"设计决策，非 ISO 要求"

#### P3 — 文档完善

14. **LOW-1**：文档总行数更正
15. **LOW-2**：缩写表补全
16. **LOW-3**：§3.1 Direction 注释引用 §1.6
17. **LOW-4**：附录 B 0x34 参数位置补全

### 6.3 修复后验证要求

1. CRITICAL-1 修复后，必须提供 0x8002/0x8003 字节级重算证据（如 "修正后 0x8002 PayloadLength = 5 + M，HexDump = 02 FD 80 02 00 00 00 07 / 00 01 0E 80 00 10 03"）
2. 对照 scapy `doip.py` fields_desc + Wireshark `packet-doip.c` + python-doipclient `messages.py` 三方实现重新核对 0x8002/0x8003 字段
3. 所有 0x8002/0x8003 相关测试用例（T017/T018/T053-T055/T063-T070）全部重写断言
4. §6.3 S3 / §6.4 S4 / §6.10 S10 HexDump 全部重算并清理"修正"注释
5. §6.13 边界值表随 CRITICAL-1/CRITICAL-3 重写后，重新执行 §3 测试覆盖率分析

---

**审计人**：独立协议审计代理
**审计完成日期**：2026-08-05
**下次审计建议**：CRITICAL-1/CRITICAL-2/CRITICAL-3 修复后重新审计，重点验证 0x8002/0x8003 字段结构与四方参考实现的一致性

---

## 附录：审计依据来源

- ISO 13400-2:2019（Diagnostic communication over IP）
- ISO 14229-1（Unified Diagnostic Services）
- scapy `contrib/automotive/doip.py`（参考实现，fields_desc 字段定义）
- Wireshark `epan/dissectors/packet-doip.c`（参考实现，`DOIP_DIAG_MESSAGE_ACK_PREVIOUS_OFFSET` 与 `tvb_captured_length_remaining` 逻辑）
- python-doipclient `messages.py`（参考实现，`DiagnosticMessagePositiveAcknowledgement.unpack` = `struct.unpack_from("!HHB", payload_bytes)` + `payload_bytes[5:payload_length]`，明确无 PrevLen 字段）
- CLAUDE.md §Testing Policy §1-§8

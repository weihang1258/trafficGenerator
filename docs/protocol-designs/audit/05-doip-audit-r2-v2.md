# DOIP 设计文档 v2.0.1 复审报告（R2）

> 审计对象：`docs/protocol-designs/05-doip-design.md`（v2.0.1，1568 行，2026-08-05）
> 审计依据：ISO 13400-2:2019、ISO 14229-1、scapy `contrib/automotive/doip.py`（本地 /usr/local/lib/python3.9/site-packages/scapy/contrib/automotive/doip.py）、python-doipclient `messages.py`/`client.py`（GitHub jacobschaer/python-doipclient，已获取源码核实）、CLAUDE.md §Testing Policy
> 审计模式：独立复审，默认"有 bug"，逐字节验算 + 逐字段对照 ISO/参考实现
> 审计日期：2026-08-05
> 审计人：独立协议审计代理（与 v2.0.0/v2.0.1 设计者无交叉）

---

## 1. 审计概览

### 1.1 审计方法

1. 通读全文 1568 行，对 DoIP 头 8B、0x0005/0x0006 PayloadLength（7+N/9+N）、0x8001 SA/TA/UserData、0x8002/0x8003 AckCode/NackCode/PrevDiag 等逐字节验算。
2. 加载本地 scapy `doip.py`（`fields_desc` 全字段）、python-doipclient `messages.py`（1071 行，含 `DiagnosticMessagePositiveAcknowledgement.unpack = struct.unpack_from("!HHB") + payload_bytes[5:payload_length]`）与 `client.py`（`get_entity` 发送逻辑）逐项对照。
3. 逐项核对 v2.0.1 修订记录声称修复的 R1 复审 17 项问题（3C+4H+6M+4L）是否真正落地。
4. 对 §6 HexDump S1-S15 逐字节核算，验证 PayloadLength 与字段宽度自洽性。
5. 对 §7 测试用例 T001-T200 及后缀变体，按 CLAUDE.md §Testing Policy §1-§8 对抗式复核（编号连续性、索引引用有效性、断言强度）。
6. 对 §6.16 场景索引表、§8 Validate 规则、附录 B 逐项交叉引用核验。

### 1.2 总体结论

**v2.0.1 的 17 项修复已全部正确落地**（详见 §2）。R1 复审的 3 项 CRITICAL（0x8002/0x8003 凭空插入 PrevLen 字段、HexDump 注释遗留、边界值自相矛盾）已彻底修复，且经本地 scapy + python-doipclient 源码再次确认 0x8002/0x8003 无独立长度字段（`!HHB` + `payload_bytes[5:]`），PayloadLength = 5 + M 正确。

但本次复审独立发现 **6 项 MEDIUM + 5 项 LOW = 11 项新问题**，其中 2 项为协议语义问题（0x0002/0x0003 目标地址、0x50 响应 P2/P2* 可选性），4 项为文档内部矛盾/引用失效，5 项为一致性/措辞问题。**无 CRITICAL、无 HIGH**。

**结论：本文档可以进入实现阶段，但建议在实现启动前快速修正 MEDIUM-1（§6.16 索引）与 MEDIUM-2（0x0002/0x0003 地址）两项；其余问题可在实现期间处理。**

### 1.3 严重度分布

| 严重度 | 数量 | 说明 |
|---|---|---|
| CRITICAL | 0 | — |
| HIGH | 0 | — |
| MEDIUM | 6 | §6.16 索引全部失效、0x0002/0x0003 目标地址描述与 ISO 矛盾、SubFunction 输出条件矛盾、MaxDataSize=0 语义矛盾、0x50 响应 P2/P2* 与 scapy 矛盾、分段 BlockSeq/Ack 未定义 |
| LOW | 5 | 用例总数声明不符、§6.16.5 引用失效、修订记录旧编号、§8.4 0x27 措辞、T049 断言占位符 |
| **合计** | **11** | |

### 1.4 v2.0.1 已正确落地的修复（予以肯定）

- **C1 落地**：§2.14/§2.15 已删除 PreviousDiagnosticMessageLength 字段，PayloadLength = 5 + M（V1/V2 一致）。§1.3 说明、§3.1 UserData 注释、§4.4、§6.3/§6.4 HexDump、§6.13.5-8、T017/T018/T053/T054/T063-T068、§8.1/§8.3/§8.5/§9.5/§9.7 全部同步修正。与 python-doipclient `!HHB` + `payload_bytes[5:payload_length]` 及 scapy `XStrField("previous_msg")`（无 Len 字段）逐字节一致。
- **C2 落地**：§6.3/§6.4/§6.10 HexDump 无遗留"修正前"版本与注释；§6.4 S4 0x8001 PayloadLength = 0x07（2+2+3=7 核算正确）。
- **C3 落地**：§6.13.5-8 重写为 MaxDataSize 约束 + PayloadLength u32 理论上限；T064/T065/T066/T067/T068 边界一致（T067 UserData=65536B → PayloadLength=65540 ≤ 4GB-1 通过，无矛盾）。
- **H1 落地**：§6.10 0x34 HexDump 补全 size 4B，UserData=11B，PayloadLength=0x0F=15，与 T041 输入一致。
- **H2 落地**：§6.3 S3 0x8002 HexDump 为 7B（00 01 0E 80 00 10 03），PayloadLength=0x07。
- **H3 落地**：§6.13.23 注明"不受 PrevLen u16 约束"；§8.5 新增 OEM 上限（≤ 4GB-1-7/9）。
- **H4 落地**：T067 随 C3 重写，与 §6.13.7 一致。
- **M1 落地**：§4.3 子阶段新增 4'（RC=0x05 拒绝 → TCP FIN）；新增 T027a。
- **M2 落地**：§6.13.5/§6.13.6 重写为 MaxDataSize 边界。
- **M3 落地**：§9.7 R5 措辞简化。
- **M4 落地**：§7 全部用例表新增"对应 spec 行"列。
- **M5 落地**：T111/T112 补正向断言；新增 T119a/T120a。
- **M6 落地**：§1.3/§8.1/T110 注明"本设计选择，非 ISO 要求"。
- **L1-L4 落地**：行数声明、缩写表、§3.1 Direction 注释、附录 B addr/size 长度取值均已完成。

### 1.5 参考实现一致性矩阵（v2.0.1 与 ISO/scapy/python-doipclient）

| 字段/枚举 | ISO 13400-2 | scapy | python-doipclient | 本设计 v2.0.1 | 状态 |
|---|---|---|---|---|---|
| DoIP 头 8B | §8.3 | ✓ | ✓ | ✓ | 一致 |
| 0x0005 = 7+N / 0x0006 = 9+N | §9.2.4/§9.3.6 | ✓ | ✓（`!HBL`/`!HBLL`） | ✓ | 一致 |
| 0x0006 ResponseCode 0x00-0x07/0x10/0x11 | §9.3.6 | ✓ | ✓（IntEnum 同值） | ✓ | 一致 |
| 0x8003 NackCode 0x02-0x08 | §10.4.5 | ✓ | ✓ | ✓ | 一致 |
| **0x8002 = SA(2)+TA(2)+AckCode(1)+PrevDiag(变长)** | §10.4.3 | ✓ | ✓（`!HHB`+`[5:]`） | ✓ | **一致（C1 已修）** |
| **0x8003 = SA(2)+TA(2)+NackCode(1)+PrevDiag(变长)** | §10.4.5 | ✓ | ✓ | ✓ | **一致（C1 已修）** |
| 0x4002 = NodeType(1)+MCTS(1)+NCTS(1)+MDS(4) | §11.1 | ✓ | ✓（`!BBBL`） | ✓ | 一致 |
| 0x0004 = VIN(17)+LA(2)+EID(6)+GID(6)+FAR(1)+Sync(1)=33 | §8.5.5 | ✓ | ✓（`!17sH6s6sBB`） | ✓ | 一致 |
| 0x0004 V1 32B（无 SyncStatus） | 2010 版 | ✓ | ✓（`!17sH6s6sB`） | ✓ | 一致 |
| **0x0002/0x0003 目标地址** | §8.5.3/§8.5.4 广播地址 | — | ✓（`sendto((ecu_ip_address, ...))`，默认 255.255.255.255） | **写"单播"** | **不一致（MEDIUM-2）** |
| **0x50 响应 sessionParameterRecord 可选** | ISO 14229-1 可选 | ✓（StrField 默认空） | ✓ | **附录 B 写强制 P2/P2\*** | **不一致（MEDIUM-4）** |

---

## 2. 独立审计发现

### MEDIUM-1：§6.16 HexDump 场景索引表全部引用失效（15 行无一可追溯）

- **位置**：§6.16（行 999-1017）
- **描述**：场景索引表的"覆盖测试用例"列引用大量不存在的测试编号，或张冠李戴：
  - S2 引用 T17/T17a/T17b/T17c——§7 无 T17a/T17b/T17c（T017 是"0x8002 Ack"）。
  - S4/S6 引用 T22/T22a/T22b/T22c——§7 无 T22a-T22c（T022 是"ActivationType=0x00"）。
  - S8 引用 T23/T23a-T23d——§7 无 T23a-T23d（T023 是"OEM-specific=4B"）。
  - S10 引用 T06/T06a/T20——§7 无 T06a。
  - S12 引用 T09a/T46/T47/T48——§7 无 T09a；T46/T47/T48 实际是"UDS 否定响应 NRC 优先/拒绝"用例，与 IPv6 无关。
  - S13 引用 T14/T15/T15a/T15b/T15c/T24a/T24b/T24c/T32/T49——§7 无 T15a-T15c/T24a-T24c；T049 是"NRC=0x7F 通过"。
  - S7 Entity Status 应指向 T012/T013/T091-T100，实际指向 T46/T47/T48（错误）。
  - S12 IPv6 应指向 T131-T140/T177-T180，实际指向 T09a/T46/T47/T48（错误）。
  - S9 引用 T41——T041 是"UDS 0x34 RequestDownload"，S9 多会话应指向 T161-T170/T171-T185。
  - S15 引用 T41/T42/T45——T042 是"0x37 RequestTransferExit"，T045 是"否定响应格式"，与"完整诊断流程 22 包"无关（应指向 T171/T200）。
- **根因**：这些编号是 v1.2/v2.0.0 时期旧测试编号体系的遗留。v2.0.0 新增 T46-T48/T131-T140 等后编号体系变化，v2.0.1 声称"全部用例表新增对应 spec 行列"（M4 修复）但未同步更新 §6.16 索引。
- **依据**：CLAUDE.md §Testing Policy §1（每条用例对应 spec 行）；文档自洽性
- **修复建议**：§6.16 索引按 §7 实际编号重写。建议映射：S1→T001/T003/T006/T007/T071-T090；S2→T008/T009/T021/T021a-g/T026/T027/T027a；S3→T016/T017/T031-T043/T051-T055；S4→T018/T056-T062；S5→T010/T011/T111-T120/T119a/T120a；S7→T012/T013/T091-T100；S8→T019/T121-T130；S9→T161-T170/T172；S10→T041/T038-T040/T042/T184；S11→T021a/T026/T182；S12→T131-T140/T177-T180；S13→§6.13 表 + T141-T160；S14→T117/T195/T196；S15→T171/T200。

### MEDIUM-2：0x0002/0x0003 Vehicle Identification Request 目标地址描述与 ISO/参考实现矛盾（"单播"应为"广播"）

- **位置**：§2.5（行 209）、§2.6（行 217）、§4.1（行 617）、§1.6（行 135）
- **描述**：§2.5 写 "0x0002 ... UDP 单播（按 EID 定向）"，§2.6 写 "0x0003 ... UDP 单播（按 VIN 定向）"，§4.1 同步写"0x0002 = 按 EID 单播"。
  - 但 ISO 13400-2:2019 §8.5.3/§8.5.4 规定：带 EID/VIN 的车辆识别请求与 0x0001 一样**发往车辆识别广播地址（IPv4 255.255.255.255）**，区别仅在 Payload 中携带 EID/VIN，使所有 ECU 判断"是否是我"再应答（不匹配的 ECU 不应答）。
  - python-doipclient `get_entity()`（client.py 行 330-375）实证：`ecu_ip_address="255.255.255.255"` 为默认，0x0001/0x0002/0x0003 均 `sock.sendto(data_bytes, (ecu_ip_address, UDP_DISCOVERY))`——同一个地址，无单播特殊化。
  - scapy `bind_bottom_up(UDP, DoIP, dport=13400)` 亦无按 EID 单播的地址逻辑。
- **影响**：若实现者按"单播"实现（发往 spec.DstIP 的 ECU 单播地址），生成的 0x0002/0x0003 报文在真实网络中行为与 ISO 不符（无法触发"所有 ECU 判断应答"机制，且与 §3.3 Broadcast=true 的 DstIP 覆盖逻辑冲突——Broadcast 只对 0x0001 生效，0x0002/0x0003 的 DstIP 语义未定义）。§4.1 也未定义 0x0002/0x0003 的 DstIP/DstMAC 处理。
- **依据**：ISO 13400-2:2019 §8.5.3/§8.5.4；python-doipclient `client.py` `get_entity()` 实现
- **修复建议**：§2.5/§2.6/§4.1 改为"UDP 广播（与 0x0001 相同地址 255.255.255.255 / ff02::1，Payload 携带 EID/VIN 以限定应答方）"，或明确"目标地址由 spec.DstIP 决定（可为广播或单播）"。§1.6 方向注释同步。若保留单播选项，需在 §4.1 明确 DstIP 覆盖规则。

### MEDIUM-3：SubFunction 输出条件文档内部矛盾（§3.1 与 §8.4/T193 冲突）

- **位置**：§3.1 DoIPUDS.SubFunction 注释（行 534）vs §8.4（行 1347）vs T193（行 1299）
- **描述**：§3.1 写 "`SubFunction uint8 // sub-function 字节（仅 HasSubFunction=true 时输出）`"；§8.4 写 "ServiceID ∈ {0x10,0x11,0x27,0x31,0x3E}：HasSubFunction=true 或 nil 时输出 sub-function 字节；**HasSubFunction=false 时仍输出**（sub-function 是必需字段）"；T193 断言 "HasSubFunction=false + 0x10 → 仍输出 sub-function=0x03"。
  - ISO 14229-1 中 0x10/0x11/0x27/0x31/0x3E 的 sub-function 参数是**必需**的（0x10 请求 = `10 <sessionType>` 至少 2B）。因此 §8.4/T193 正确，§3.1 行 534 注释错误。
  - 实现者若按 §3.1 注释实现（false 时不输出），T193 会失败；按 T193 实现则违反 §3.1 文档。
- **依据**：ISO 14229-1 §10.4（DiagnosticSessionControl 请求格式）；scapy `UDS_DSC`（`ByteEnumField('diagnosticSessionType')` 必有）；文档自洽性
- **修复建议**：§3.1 行 534 注释改为 "sub-function 字节（0x10/0x11/0x27/0x31/0x3E 必需字段，HasSubFunction=false 亦输出；nil=auto 按 SID 判定）"。

### MEDIUM-4：附录 B 0x50 响应格式与 scapy/ISO 矛盾（P2/P2* 非强制）

- **位置**：§10.1 附录 B 行 1435
- **描述**：附录 B 写 "0x10 默认正向响应字节 `50 <sub> <P2> <P2*>`"，未标注可选性，暗示 P2/P2*（会话参数记录）总是存在（5B 响应）。
  - scapy `UDS_DSCPR`（uds.py 行 148-154）：`StrField('sessionParameterRecord', b"")`——**默认空**，P2/P2* 是可选参数记录。
  - ISO 14229-1：0x50 响应 = `50 <sessionType> [sessionParameterRecord]`，sessionParameterRecord（P2/P2* 等）为**可选**。
  - 设计 §3.1 DoIPUDS **没有任何 P2/P2* 字段**，无法生成附录 B 声称的 5B 响应。T 系列也无 0x50 具体字节断言用例，实现者无法判定按 3B 还是 5B 实现。
- **依据**：ISO 14229-1；scapy `uds.py` `UDS_DSCPR`；python-doipclient `messages.py`（0x50 响应同）
- **修复建议**：附录 B 0x10 行改为 "`50 <sub>`（sessionParameterRecord 可选，本设计不建模 P2/P2*）"，并新增一条 0x50 响应用例断言 `50 03`（或 `50 03` + 可选参数记录）。

### MEDIUM-5：MaxDataSize=0 语义与 §8.5 约束公式矛盾（T100 vs §8.5）

- **位置**：T100（行 1164）vs §8.5（行 1356）vs §6.13.5
- **描述**：T100 断言 "MaxDataSize=0 → 通过（边界，表示未限制）"。但 §8.5/§6.13.5 约束为 "0x8001 UserData 长度 ≤ EntityStatus.MaxDataSize（若 EntityStatus 存在）"。若 MaxDataSize=0 按字面代入，UserData 必须 ≤0 即只能为空报文，与 T100 的"未限制"语义矛盾。
  - ISO 13400-2:2019 §11.1 中 MDS=0 的语义是"未定义/未知"，非"未限制"。python-doipclient `max_data_size` 属性注释为 "0 to 4GB"，未定义 0 的豁免语义。
  - 实现者无法判定：MaxDataSize=0 时 0x8001 UserData 校验应通过（T100）还是拒绝一切非空（§8.5 字面）。
- **依据**：ISO 13400-2:2019 §11.1；文档自洽性
- **修复建议**：§8.5/§6.13.5 补充豁免："MaxDataSize=0 表示未知/未定义，不执行 UserData 上限校验（T100）"；或删除 T100 的"未限制"断言改为明确报错。

### MEDIUM-6：0x36 按 MSS 分段的 BlockSeq 递增与每段 Ack 行为未定义（§4.4 与 §5.2 矛盾）

- **位置**：§5.2（行 709）vs §4.4（行 654）vs T184（行 1285）
- **描述**：§5.2 说 "0x36 TransferData 的 UserData = SID(1B) + BlockSeq(1B) + Data(N)；若 UserData > MSS-40，按 MSS-40 分段 Data，**每段独立 0x8001**"。§4.4 说 "每条 Message 生成一条 0x8001"，"0x8001 后紧跟 0x8002（Ack）或 0x8003（Nack）"。
  - 矛盾 1：一个 0x36 Message 分段后生成 N 条 0x8001，与 §4.4 "每条 Message 生成一条 0x8001"冲突。
  - 矛盾 2：ISO 14229-1 要求每个 TransferData 请求的 BlockSequenceCounter 递增（1, 2, 3, ...），分段后的每条 0x8001 的 BlockSeq 如何分配（每段独立递增？整个 Message 一个 BlockSeq？）未定义。
  - 矛盾 3：每段 0x8001 是否各跟一个 0x8002 Ack 未定义（§4.4 说紧跟 Ack，但分段场景可能只在最后一段 Ack）。
  - T184 断言仅 "MSS 分段正确"，无具体断言（分段数、BlockSeq 序列、Ack 数）。
- **依据**：ISO 14229-1 §11.4.3.5（TransferData 请求格式与 blockSequenceCounter 语义）；CLAUDE.md §Testing Policy §5（断言可观察值）
- **修复建议**：§5.2 明确：分段后每条 0x8001 的 BlockSeq 独立递增（段 1=0x01, 段 2=0x02, ...），每段 0x8001 均紧跟对应 0x8002；T184 补具体断言（如 UserData=4000B、MSS=1460 → 3 段，BlockSeq=01/02/03，3 个 0x8002）。

### LOW-1：文档声明"203 条（T001-T203）"与实际不符（无 T201-T203）

- **位置**：行 1564、行 1508
- **描述**：文档声明 "测试用例总数：203 条（T001-T203，含 v2.0.1 新增 T027a/T119a/T120a）"。实际 §7 用例表为 T001-T200 连续（无 T201-T203），外加后缀变体 T021a-g/T022a-c/T027a/T119a/T120a 共 10 个。实际独立用例定义 = 200 + 10 = 210，或按"主编号"计 200+3 新增 = 203（若把 T027a/T119a/T120a 算作新增），但"T001-T203"的写法错误（无 T201/T202/T203 实体）。
- **依据**：文档自洽性
- **修复建议**：改为 "210 条（T001-T200 + 10 后缀变体，含 v2.0.1 新增 T027a/T119a/T120a）"。

### LOW-2：§3.2 引用 §6.16.5 失效（应为 §6.13.1-4）

- **位置**：§3.2 行 570
- **描述**：EID 默认值行写 "失败则 6B 0（fallback 路径，见 §6.16.5）"。§6.16 是场景索引表，无 §6.16.5 小节。EID fallback 边界实际在 §6.13.1-4。
- **依据**：文档自洽性
- **修复建议**：改为 "见 §6.13.1-4"。

### LOW-3：修订记录中 §6.16.11/§6.16.16 为旧编号（v2.0.1 已移至 §6.13）

- **位置**：§11.1 修订记录 v2.0.0 行 51（H2）、行 54（H5）
- **描述**：v2.0.0 修订记录写 "§6.16.11 拆分..."、"§6.16.16 新增..."。v2.0.1 已将边界值从 §6.16 移至 §6.13（§6.13.5-8），但 v2.0.0 修订记录未同步（§11.2 的 H2/H5 行仍引用 §6.16.11/§6.16.16）。
- **依据**：文档自洽性
- **修复建议**：§11.2 H2/H5 行的 §6.16.11/§6.16.16 改为 §6.13.5-8/§6.13.22。

### LOW-4：§8.4 0x27 表述措辞易误读（"奇数 = 请求 seed（IsResponse=true 时 Seed 非空）"）

- **位置**：§8.4 行 1349
- **描述**：§8.4 写 "ServiceID=0x27 SubFunction 奇数 = 请求 seed（IsResponse=true 时 Seed 字段非空）"。实际 ISO 语义：奇数请求（`27 01`）由 Tester 发出（IsResponse=false）；ECU 的正向响应（`67 01 <seed>`，IsResponse=true）才携带 seed。§8.4 把"奇数"与"IsResponse=true"并列在同一分句，易被实现者误读为"奇数请求也是响应"。T033/T035 断言本身正确（`27 01` 请求 / `67 01 11 22 33 44` 响应），仅 §8.4 措辞问题。
- **依据**：ISO 14229-1 §10.4.2；scapy `UDS_SA`/`UDS_SAPR`（securitySeed 仅在响应 SID 0x67 且奇数 sub 时出现）
- **修复建议**：§8.4 改为 "ServiceID=0x27 奇数 sub：请求 = `27 <sub>`（无数据），响应（IsResponse=true）= `67 <sub> <seed>`（Seed 非空）；偶数 sub：请求 = `27 <sub> <key>`（Key 非空，IsResponse=false），响应 = `67 <sub>`（无 key）"。

### LOW-5：T049 断言用占位符且 spec 行引用不精确

- **位置**：T049（行 1098）
- **描述**：T049 断言写 "UserData=7F <SID> 7F"，用占位符 `<SID>` 而非具体字节（T045 用具体 `7F 22 11`）。且"对应 spec 行"列标 §8.2（NRC 范围校验），但否定响应格式定义在 §2.16/§8.4。
- **依据**：CLAUDE.md §Testing Policy §5（断言可观察值）
- **修复建议**：T049 断言改为具体字节（如输入 ServiceID=0x22 → `UserData=7F 22 7F`），spec 行补 §2.16/§8.4。

---

## 3. 测试用例覆盖率分析（对照 CLAUDE.md §Testing Policy）

### 3.1 spec-driven test derivation（§1）

- §2 PayloadType 表 16 项：T001-T020 覆盖 16/16 ✓
- §2.3 0x0000 NackCode 5 值：T121-T125 ✓
- §2.7 FAR 2 值 + 拒绝：T073/T074 + T075-T077 ✓
- §2.7 SyncStatus 2 值 + 拒绝：T078/T079 + T080 ✓
- §2.9 ResponseCode 11 值：T021/T021a-g ✓
- §2.15 NackCode：T056-T062 ✓
- §2.12 PowerMode 3 值：T103-T106 ✓
- §2.11a NodeType：T093-T095 ✓
- §2.16 UDS 10 服务：T031-T050 ✓
- §1.4 扩展表 5 字段映射：**仍无独立测试用例**（R1 已指出，v2.0.1 未补——遗漏延续）
- §10.1 附录 B 各服务响应字节：**仅 0x67 有断言（T035/T036），其余 9 个服务响应格式（50/51/62/6E/71/74/76/77/7E）无字节级用例**（MEDIUM-4 相关）

### 3.2 cover failure paths（§2）

- 路由激活失败：T021a-e/T026 ✓；二次确认被拒：T027a ✓（M1 落地）
- 0x8003 Nack 各码：T056-T062 ✓
- 0x0000 GenericNack 各码：T121-T126 ✓
- V1+OEM / V1+PowerMode 拒绝：T025/T110 ✓
- Direction 反向：T119/T120 + 正向 T119a/T120a ✓（M5 落地）
- **遗漏**：MaxDataSize=0 的边界判定（MEDIUM-5）；0x50 等响应格式缺失（MEDIUM-4）

### 3.3 one test per code path（§3）

- 每个 PayloadType 单独测 ✓
- **遗漏延续**：0x8002/0x8003 PrevDiag 为空（M=0）场景仍无独立用例（R1 §3.3 已指出，v2.0.1 未补）

### 3.4 integration tests（§4）

- T171-T185 端到端 ✓
- **遗漏延续**：无 PowerMode + EntityStatus + Discovery 三阶段 UDP 混合端到端用例（R1 §3.4 已指出，v2.0.1 未补）

### 3.5 assert observable outcomes（§5）

- 各用例断言 PayloadLength/字段字节值：基本满足
- **弱点延续**：T194（Announcement 间隔）未断言具体 Timestamp 值（R1 §3.5 已指出）

### 3.6 concurrency correctness（§6）

- T174/T175/T176 PacketWorkers=8 并发 ✓

### 3.7 failing-test-first（§7）

- 设计阶段无 bug 声明；v2.0.1 修复 17 项但未提供"failing test 先行"证据（设计文档惯例，可接受）

### 3.8 adversarial review of test quality（§8）

- **新增问题**：§6.16 索引与 §7 实际编号脱节（MEDIUM-1）——索引是测试质量的"导航图"，失效后实现者无法按场景定位用例，违反 §8"测试质量对抗复核"精神

---

## 4. 与 ISO 13400-2:2019 规范一致性逐项核查

| # | 核查项 | ISO 要求 | 设计文档 | 状态 |
|---|---|---|---|---|
| 1 | DoIP 头 8B = PV(1)+InvPV(1)+PT(2)+PL(4) | §8.3 | §2.1 | ✓ |
| 2 | InverseProtocolVersion = ~PV & 0xFF | §8.3 | §2.1/§1.3 | ✓ |
| 3 | PayloadLength 不含头部 8B | §8.3 | §2.1 | ✓ |
| 4 | 0x0000 NackCode 0x00-0x04 | §8.4.1 | §2.3 | ✓ |
| 5 | 0x0001 无 payload | §8.5.2 | §2.4 | ✓ |
| 6 | **0x0002/0x0003 目标地址（广播）** | §8.5.3/§8.5.4 | §2.5/§2.6 写"单播" | **✗（MEDIUM-2）** |
| 7 | 0x0004 = 33B（V2）/32B（V1） | §8.5.5 | §2.7 | ✓ |
| 8 | 0x0004 FAR 仅 0x00/0x10 | §8.5.3 | §2.7 | ✓ |
| 9 | 0x0004 SyncStatus 仅 0x00/0x10 | §8.5.5 | §2.7 | ✓ |
| 10 | 0x0004 公告 3 次、500ms±100ms | §8.5.1 | §2.7/§4.1 | ✓ |
| 11 | 0x0005 = 7+N / 0x0006 = 9+N | §9.2.4/§9.3.6 | §2.8/§2.9 | ✓ |
| 12 | 0x0006 ResponseCode 0x00-0x07/0x10/0x11 | §9.3.6 | §2.9 | ✓ |
| 13 | 0x0007 恒 ECU→Tester / 0x0008 恒 Tester→ECU | §10.2.2/§10.2.3 | §4.5/§8.6 | ✓ |
| 14 | 0x4001 无 payload / 0x4002 = 7B | §11.1 | §2.11a | ✓ |
| 15 | 0x4003 无 payload / 0x4004 = 1B | §11.2 | §2.12 | ✓ |
| 16 | DiagnosticPowerMode 0x02=Not Supported | §11.2.2 | §2.12 | ✓ |
| 17 | 0x8001 = SA(2)+TA(2)+UserData(N) | §10.3.2 | §2.13 | ✓ |
| 18 | 0x8001 SA/TA 一致性 | §10.3.2.1/§10.3.2.2 | §2.13/§8.3 | ✓ |
| 19 | **0x8002 = SA+TA+AckCode+PrevDiag（无 Len）** | §10.4.3 | §2.14 | ✓（C1 已修） |
| 20 | **0x8003 = SA+TA+NackCode+PrevDiag（无 Len）** | §10.4.5 | §2.15 | ✓（C1 已修） |
| 21 | 0x8002 AckCode 仅 0x00 | §10.4.3.4 | §2.14 | ✓ |
| 22 | 0x8003 NackCode 0x02-0x08 | §10.4.5 | §2.15 | ✓ |
| 23 | 路由激活失败关闭 TCP | §9.3.6.3 | §4.3/T026 | ✓ |
| 24 | UDP 广播 255.255.255.255 / ff02::1 | §8.2 | §1.2/§3.3 | ✓ |
| 25 | 组播 MAC 33:33:00:00:00:01 | RFC 2464 | §3.3 | ✓ |
| 26 | UDS SID 正向响应 \|0x40 | ISO 14229-1 §7.1 | §2.16 | ✓ |
| 27 | UDS 否定响应 7F+ReqSID+NRC | ISO 14229-1 §7.3 | §2.16/§8.4 | ✓ |
| 28 | UDS 0x27 奇数 seed/偶数 key | ISO 14229-1 | §2.16/T033-T037 | ✓（§8.4 措辞见 LOW-4） |
| 29 | UDS 0x36 BlockSeq n%256 | ISO 14229-1 | §3.1/§8.4 | ✓ |
| 30 | **UDS 0x50 响应 sessionParameterRecord 可选** | ISO 14229-1 | 附录 B 写强制 P2/P2\* | **✗（MEDIUM-4）** |

**核查结果**：30 项中 28 项一致，2 项不一致（MEDIUM-2、MEDIUM-4）。

---

## 5. HexDump 自洽性逐项验算

| 场景 | HexDump | PayloadLength 声明 | 实际核算 | 状态 |
|---|---|---|---|---|
| S1 0x0001 | `02 FD 00 01 00 00 00 00` | 0 | 0B ✓ | ✓ |
| S1 0x0004 | `02 FD 00 04 00 00 00 21` + 33B | 0x21=33 | 17+2+6+6+1+1=33 ✓ | ✓ |
| S2 0x0005 | `02 FD 00 05 00 00 00 07` + 7B | 0x07=7 | 2+1+4+0=7 ✓ | ✓ |
| S2 0x0006 | `02 FD 00 06 00 00 00 09` + 9B | 0x09=9 | 2+2+1+4+0=9 ✓ | ✓ |
| S3 0x8001 | `02 FD 80 01 00 00 00 06` + 6B | 0x06=6 | 2+2+2=6 ✓ | ✓ |
| S3 0x8002 | `02 FD 80 02 00 00 00 07` + 7B | 0x07=7 | 2+2+1+2=7=5+2 ✓ | ✓（C1 已修） |
| S4 0x8001 | `02 FD 80 01 00 00 00 07` + 7B | 0x07=7 | 2+2+3=7 ✓ | ✓（C2 已修） |
| S4 0x8003 | `02 FD 80 03 00 00 00 08` + 8B | 0x08=8 | 2+2+1+3=8=5+3 ✓ | ✓（C1 已修） |
| S5 0x0007 / 0x0008 | 0B / 2B | 0 / 2 | ✓ | ✓ |
| S7 0x4001 / 0x4002 | 0B / 7B | 0 / 7 | ✓ | ✓ |
| S8 0x0000 | `02 FD 00 00 00 00 00 01` + 1B | 0x01=1 | 1B ✓ | ✓ |
| S10 0x34 | `02 FD 80 01 00 00 00 0F` + 15B | 0x0F=15 | 2+2+11=15 ✓ | ✓（H1 已修） |
| S10 0x36 | `02 FD 80 01 00 00 00 0A` + 10B | 0x0A=10 | 2+2+6=10 ✓ | ✓ |
| S10 0x37 | `02 FD 80 01 00 00 00 05` + 5B | 0x05=5 | 2+2+1=5 ✓ | ✓ |
| S11 0x0006 RC=0x00 | `02 FD 00 06 00 00 00 09` + 9B | 0x09=9 | 2+2+1+4+0=9 ✓ | ✓ |

**HexDump 验算结论**：15 个 HexDump 全部自洽，无遗留错误（R1 的 CRITICAL-2/HIGH-1/HIGH-2 已全部修复）。

---

## 6. 最终结论与建议

### 6.1 最终结论

**本文档（v2.0.1）可以进入实现阶段。**

- v2.0.1 已正确修复 R1 复审的全部 17 项问题（3C+4H+6M+4L），0x8002/0x8003 报文格式与 ISO 13400-2:2019 §10.4.3/§10.4.5 及 scapy/python-doipclient 三方参考实现逐字节一致，15 个 HexDump 全部自洽。
- 本次复审独立发现 11 项新问题（6 MEDIUM + 5 LOW），**无 CRITICAL、无 HIGH**。其中 MEDIUM-2（0x0002/0x0003 目标地址）与 MEDIUM-4（0x50 响应格式）是协议语义问题，但均不阻塞主体实现：0x8002/0x8003/0x8001/0x0005/0x0006 等核心路径已完全定义正确。

### 6.2 建议处理优先级

#### P1 — 实现启动前建议快速修正（2 项）

1. **MEDIUM-1**：§6.16 场景索引表按 §7 实际编号重写（15 行引用全部失效，实现者按索引无法定位用例）
2. **MEDIUM-2**：§2.5/§2.6/§4.1 的 0x0002/0x0003 目标地址改为广播（或明确 DstIP 语义），否则实现者生成的发现报文行为与 ISO 不符

#### P2 — 实现期间处理（4 项）

3. **MEDIUM-3**：§3.1 SubFunction 注释与 §8.4/T193 统一（sub-function 是必需字段）
4. **MEDIUM-4**：附录 B 0x50 响应格式标注 sessionParameterRecord 可选（P2/P2* 非强制），补 0x50 响应用例
5. **MEDIUM-5**：§8.5 明确 MaxDataSize=0 的豁免语义（与 T100 一致）
6. **MEDIUM-6**：§5.2 明确分段时 0x36 BlockSeq 递增规则与每段 Ack 行为，T184 补具体断言

#### P3 — 文档完善（5 项）

7. **LOW-1**：用例总数声明更正
8. **LOW-2**：§3.2 "§6.16.5" 引用改为 "§6.13.1-4"
9. **LOW-3**：§11.2 修订记录 §6.16.11/§6.16.16 改为 §6.13 编号
10. **LOW-4**：§8.4 0x27 措辞拆分请求/响应语义
11. **LOW-5**：T049 断言用具体字节

#### 测试覆盖遗留（非阻塞，建议补）

12. §1.4 扩展表 5 字段映射无独立用例（R1 已指出，v2.0.1 未补）
13. 0x8002/0x8003 PrevDiag 为空（M=0）无独立用例（R1 已指出，v2.0.1 未补）
14. Discovery + EntityStatus + PowerMode 三阶段 UDP 混合端到端用例缺失（R1 已指出，v2.0.1 未补）

---

**审计人**：独立协议审计代理
**审计完成日期**：2026-08-05
**下次审计建议**：MEDIUM-1/MEDIUM-2 修正后可在实现阶段以代码评审形式跟进，无需再整轮文档复审

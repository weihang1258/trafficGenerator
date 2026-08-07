# 13-modbus-design v2.0.2 复审报告（第三轮，R3）

审计对象：`docs/protocol-designs/13-modbus-design.md`（v2.0.2，1839 行）
审计日期：2026-08-05
依据：Modbus.org MB-ASYM-TCP V1.1b3 / PI-MBUS-300 Rev. J；交叉核实：pymodbus 官方实现源码（`pymodbus/pdu/file_message.py`、`diag_message.py`、`mei_message.py`、`other_message.py`、`register_message.py`）、Modbus 社区规范资料
方法：逐节核对 11 个重点修复项 + 全文档 15 个 HexDump 逐字节核算 + 205 条用例抽样核对

## 结论汇总

| 严重度 | 数量 |
|--------|------|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 2 |
| LOW | 2 |
| **合计** | **7** |

**最终结论：否——存在 1 项 CRITICAL（FC 0x14 响应 item 结构与规范不符）+ 2 项 HIGH（FC 0x08 子功能上限 0x0013 与规范不符、T-055 的 0x0C 响应字段顺序与规范不符），修复后方可进入实现阶段。**

---

## 一、CRITICAL

### C-1. FC 0x14 响应 item 结构错误（§3.3.12 / §4.5 / T-020 / T-115 示例 / §8.4 / §10.3）

**位置**：§3.3.12 响应表（item 含 Reference Type + Byte Count + Record Data）、T-020、§8.4 FC 0x14 行、§10.3、§6 示例 `14 06 06 04 1234 5678`。

**描述**：文档将 FC 0x14 响应 item 定义为 `RefType(1) + Byte Count(1) + Record Data`。依据规范（V1.1b3 §6.14 表 31 及 pymodbus `ReadFileRecordResponse.encode`：`packet += struct.pack(">BB", len(record.record_data)+1, 0x06); packet += record.record_data`），响应 item 结构是 `File Response Length(1) + RefType(1) + Record Data(N)`——**没有 item 内 Byte Count 字段**，且 item 中**不含 File Number/Record Number**。文档把"首字节长度字段"误当作 Byte Count、且漏掉 File Response Length 计数含 RefType 的语义，长度公式也随之错：文档算 item=2+2×RL，规范为 1+1+2×RL=2+2×RL（数值上巧合一致，但字段语义错误；且 item 内没有"Byte Count=Record Length×2"这种字段——长度字段值应为 `1+2×RL` 而非 `2×RL`）。

**依据**：MB-ASYM-TCP §6.14 表 31；pymodbus file_message.py:112-119（`len(record.record_data)+1` 即含 RefType 的 File Response Length）。

**修复**：响应 item 改为 `File Response Length(1, =1+2×RL) + RefType(1)=0x06 + Record Data(2×RL)`；同步修正 T-020、§8.4 公式、§10.3 映射、S 场景示例与 Length 核算（外层 Byte Count 不变，故现有长度数值可保留，但字段表必须改）。

### C-2. FC 0x15 请求 item 缺失长度字段语义（§3.3.13 示例）

**位置**：§3.3.13 示例 `15 0B 06 0001 0000 0002 1234 5678`。

**描述**：文档请求示例的 item 首字节直接是 RefType=0x06。规范（V1.1b3 §6.15 表 35；pymodbus `WriteFileRecordRequest.encode`）item 首字节应为 **Byte Count(1) = 7 + 2×RL**（含 RefType 在内的 item 总长），即示例应为 `15 0B 0B 06 0001 0000 0002 1234 5678`（12 字节数据段中 Byte Count 字段=0x0B）。当前示例缺 Byte Count 字节，实际 wire 字节数错（示例总长 12 vs 规范 13），且 tshark 解析会失败。同 §10.3 的 FC 0x15 映射 `0:FC:1, 1:ByteCount:1, 2:items` 说明字段存在但示例自相矛盾。

**依据**：MB-ASYM-TCP §6.15 表 35；pymodbus file_message.py:154-168。

**修复**：修正 §3.3.13 示例字节序列与 Length 核算（PDU=14 字节、MBAP Length=15），并核对 T-021 相应字节（T-021 断言 `15 0B ...` 后跟 `06 0001...` 亦缺该字节，需一并核对）。

## 二、HIGH

### H-1. FC 0x08 子功能上限 0x0013 与规范不符（§3.3.6 / V-117 / T-113/T-203/T-204 / §2.7）

**位置**：§3.3.6 子功能表、V-117、T-113（0x0014 拒绝）、T-203（0x0013 合法）、§2.7。

**描述**：文档将子功能上限定为 0x0013 并把 0x0014 视为非法。规范（V1.1b3 §6.8 表 17-24 及 pymodbus diag_message.py:417-438）定义 **0x0014 = Clear Overrun Counter and Flag**、**0x0015 = Get/Clear Modbus Plus Statistics** 均为合法子功能。0x0013 是"Return IOP Overrun Count"不是上限。R2-H1 修复方向本身是错的——v2.0.1 的 0x0018 上限值也不对；正确上限应含 0x0015（0x0016-0xFFFF 保留/未定义）。

**依据**：MB-ASYM-TCP §6.8；pymodbus diag_message.py（0x0000-0x0015 全实现）。

**修复**：上限改为 0x0015（或至少承认 0x0014/0x0015 合法）；0x0005-0x0009 保留判断不变；同步 T-113/T-203/T-204、V-117、§3.3.6、§11.3.2 修订记录。

### H-2. FC 0x0C 响应字段顺序与规范不符（§3.3.8 / T-055 / §4.5 / §8.4）

**位置**：§3.3.8 响应表（Status, EventCount, MessageCount 顺序）、T-055 断言 `0C 0A FFFF 0064 000A`、§4.5、§8.4。

**描述**：文档响应字段顺序为 `Status(2) + EventCount(2) + MessageCount(2) + Events`。规范（V1.1b3 §6.6 表 10；pymodbus other_message.py:150-160 `struct.pack(">B", 6+len); struct.pack(">H", ready); struct.pack(">HH", event_count, message_count)`）顺序为 **Status(2) + EventCount(2) + MessageCount(2)**——文档将 EventCount 与 MessageCount 对调。T-055 的期望字节 `FFFF 0064 000A`（EventCount=100=0x0064, MessageCount=10=0x000A）在规范下应为 `FFFF 000A 0064`（若 EventCount=100）或 EventCount=10, MessageCount=100 的语义。R1-C7 只修了 Byte Count 公式，字段顺序错误残留。

**依据**：MB-ASYM-TCP §6.6 表 10；pymodbus other_message.py:150-160。

**修复**：§3.3.8 响应表交换 EventCount/MessageCount 顺序；T-055 期望字节改为 `0C 0A FFFF 0064 000A` 的规范序（并核对配置注释中 EventCount=100/MessageCount=10 的对应关系）；同步 §4.5、§8.4。

## 三、MEDIUM

### M-1. FC 0x2B MEI Type 0x0E 标注为 CANopen 有误（§3.3.17 / T-026）

**位置**：§3.3.17 MEI Type 表（0x0D=Read Device Identification；0x0E=CANopen General）、T-026。

**描述**：规范（V1.1b3 §6.21 表 42）中 MEI Type **0x0E = Read Device Identification**（Response），0x0D 是 Request；CANopen 封装是 CiA 309 扩展（MEI Type 0x0D/0x0E 用于 CANopen 网关），V1.1b3 正文未定义"CANopen General"为 0x0E。文档"0x0E=CANopen General"表述与规范语义不符，且与 R2-C2 的"响应 MEI Type 回显 0x0D"自洽性冲突（若响应回显 0x0D，则 0x0E 从无 wire 出现，T-026 的 `2B 0E` 用例在真实设备上不可复现）。

**依据**：MB-ASYM-TCP §6.21 表 42（0x0D request / 0x0E response）；pymodbus mei_message.py（ReadDeviceInformationRequest.sub_function_code=0x0E）。

**修复**：0x0E 标注改为"Read Device Identification（响应侧）"或明确"CANopen 封装（CiA 309）为扩展，V1.1b3 未定义"，T-026 相应改为验证 0x0E 作为响应 MEI Type 的合法性或删除该用例。

### M-2. FC 0x11 请求/响应方向标注混乱（§3.3.11 / T-019 / §7.2）

**位置**：§3.3.11 表格"响应（修复 M2-CRIT-2）"后紧跟 §4.5 行 `0x11 | FC + Byte Count=2+N + Slave ID...`；T-019 断言 Length=7。

**描述**：T-019 输入 `RV=[0x03,0x01,0xFF,0xAA,BB]`（5 字节）对应响应 PDU `11 03 01 FF AA BB`=6 字节、Length=7 正确；但 T-019 的 RV 示例中 `0xAA,BB` 之间缺逗号（笔误，低危）。另 §3.3.11 请求说明"仅 1 字节 FC=0x11"正确，但与 §10.2 映射表 `StartingAddress | PDU offset 1 | FC 0x01-0x06/0x0F/0x10/0x16/0x18 通用` 一致，无实质错误；主要为 T-019 笔误与 §3.3.11 响应示例字节 `11 04 01 FF AA BB`（Byte Count=4 但只列 3 字节数据）的自洽性问题——示例第二行 `11 04 01 FF AA BB` 中 Byte Count=4 应为 5 字节数据（1+1+3）或改 Byte Count=3。

**依据**：文档内部自洽性核对（Byte Count=4 需 4 字节数据，示例仅 3 字节）。

**修复**：T-019 RV 补逗号；§3.3.11 示例第二行改为 `11 04 01 FF AA BB CC` 或 `11 03 01 FF AA`。

## 四、LOW

### L-1. S14 豁免路径与 §8.3 背书规则的冲突表述（§1.3 / §8.3 / T-081）

**位置**：§1.3 豁免规则、§8.3 表。

**描述**：§1.3 豁免规则要求"FC 不在支持集 **且** ExceptionCode≠0"；§8.3 表第一行"FC 0x05 WriteValue=0x1234 配 ExceptionCode"与 T-081"FC=0x99, ExcCode=0 → 拒绝"一致，无冲突。但 T-031~T-040 的异常码用例（FC 0x01/0x03/0x05/0x10 + ExceptionCode）均断言 `XX 01` 等响应，而 §1.3 明确"豁免不适用于支持集内的合法 FC"——合法 FC 配 ExceptionCode 时响应 PDU = `FC|0x80 + ExcCode` 与 §3.4 一致，无矛盾。实质问题：§1.3 与 §8.3 均未说明"支持集内 FC + ExceptionCode"的请求 PDU 是否仍正常构造（文档 §4.1 表格"TxSent | ExceptionCode≠0 → Exception"暗示请求照常生成），建议 T-032 增加请求 PDU 仍按 FC 0x03 正常构造的断言，消除实现歧义。

**依据**：文档 §4.1 状态机表与 §3.4 的组合推演。

**修复**：§4.1 或 §9.1 明示"支持集内 FC 配 ExceptionCode 时请求 PDU 正常构造、仅响应替换为异常 PDU"，T-032 补请求 PDU 断言。

### L-2. 文档日期与修订记录日期不一致

**位置**：文档头"设计日期：2026-08-03（v1 初稿）／2026-08-05（v2.0.0/v2.0.1/v2.0.2）"与 §11.1-11.3 的"2026-08-05"一致；但文档头第 6 行写"v2.0.0 重写／v2.0.1/v2.0.2 复审修订"日期均为 2026-08-05，而 v1 初稿标注 2026-08-03，v2.0.0 全量重写在同日完成——同日 4 个版本轮转的可信度问题；另 §11.2 声称"v2.0.1 之后文档 §4-§11 丢失重建"（§11.3），重建后 §11.2 的 R2 修复清单与 §11.3 修复清单存在重复描述（R2-C1 在 §11.2 与 §11.3.1 各述一次），建议核对版本时间线。

**依据**：文档头 vs §11。

**修复**：统一版本时间线表述，或在 §11.2 明确"v2.0.1 为中间版本未独立成文"。

---

## 五、重点修复项复核结论（对照审计要求 1-11）

| # | 审计项 | 结论 |
|---|--------|------|
| 1 | S14 异常响应 `99 01`（0x99\|0x80 幂等） | ✅ 正确（§6.15、T-201、§1.3、V-103 一致；与 T-025 的 `C1 01` 对照自洽） |
| 2 | FC 0x2B 响应 PDU 完整规格化 | ✅ 正确（§3.3.17 七字段齐全，T-202 13 字节断言与 pymodbus 结构一致） |
| 3 | FC 0x08 子功能上限 0x0013 | ❌ 上限应为 0x0015（见 H-1，0x0014/0x0015 均为合法子功能） |
| 4 | 删除 T-064/T-108 不可达断言 | ✅ 正确（§11.3.2 R2-H2；T-064 已改语义为 0x0013 上限合法用例，T-205 覆盖独立性） |
| 5 | MBAP Length = 1(Unit) + PDU | ✅ 正确（15 个 HexDump 全部逐字节核算通过，含 S13 Length=0x00FD=253） |
| 6 | FC 0x14 响应 item 含 Byte Count | ❌ 字段语义错误（见 C-1，规范为 File Response Length 而非 Byte Count） |
| 7 | FC 0x16 公式 (Cur AND A) OR (O AND ~A) | ✅ 正确（与规范公式一致；§3.3.14 明确"实现不执行该公式"的边界声明合理） |
| 8 | 异常码 01-08, 0A, 0B（含 07） | ✅ 正确（10 个码齐全，T-031~T-040 全覆盖；0x09 排除合理） |
| 9 | UnitID=0 广播功能可用 | ✅ 正确（*uint8 方案、V-002 写功能码限定、T-047~T-050 覆盖，含异常响应抑制） |
| 10 | HexDump 自洽性 | ❌ S1-S15 的 Length 全部自洽，但 §3.3.13 FC 0x15 示例缺 Byte Count 字节（C-2）、§3.3.11 示例 Byte Count 与实际数据字节不符（M-2） |
| 11 | 测试用例符合 Testing Policy | ⚠️ 部分符合（T-201~T-205 修复验证充分；但 T-020 断言了错误的 FC 0x14 响应结构、T-055 断言了错误的字段顺序——测试与文档同错，违反"测试必须来自规范"） |

## 六、未发现问题的区域（已核对）

- S1-S15 全部 Length 核算（含 S9 Length=0x0011、S13 Length=0x00FD）正确
- FC 0x18 响应 Byte Count=2 字节（`>HH` 与 pymodbus 一致）、FIFO Count≤31 正确
- FC 0x17 双数量字段、WriteAddress 回退公式（uint16 模运算）正确
- FC 0x2B 响应七字段结构与 pymodbus `ReadDeviceInformationResponse` 一致
- 异常响应 PDU=2 字节、MBAP Length=3 正确
- TID 分配公式 `(N-1) mod 65536` 与回绕用例（T-043/T-137~T-139）正确
- 位打包规则（§2.2 LSB 优先 + 低地址字节先）正确
- 广播三条细则（§4.4）逻辑自洽
- 205 条用例编号连续性、§7.8 矩阵与 §11.3.4 R2-L4 统计一致

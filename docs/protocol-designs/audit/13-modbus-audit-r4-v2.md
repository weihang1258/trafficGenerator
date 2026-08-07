# 13-modbus-design v2.0.3 复审报告（第四轮，R4）

审计对象：`docs/protocol-designs/13-modbus-design.md`（v2.0.3，1889 行）
审计日期：2026-08-05
依据：Modbus.org MB-ASYM-TCP V1.1b3 / PI-MBUS-300 Rev. J；交叉核实：**本机 tshark 3.6.14 实测 12 种 wire 形态**（文档自认"tshark 为最终裁判"）、pymodbus dev 官方源码（`file_message.py`/`mei_message.py`）、RFC 7540 原文
方法：逐节核对 9 项重点（C-1/H-1/H-2/C-2/M-2/M-1/7/8/9）+ 全部 15 个 HexDump 逐字节核算 + 205 条用例对照 CLAUDE.md §Testing Policy 逐条审核 + tshark 实证裁决

## 结论汇总

| 严重度 | 数量 |
|--------|------|
| CRITICAL | 1 |
| HIGH | 4 |
| MEDIUM | 3 |
| LOW | 4 |
| **合计** | **12** |

**最终结论：否——v2.0.3 声称修复的 C-2（FC 0x15 请求 item 补 Byte Count）方向错误：item 首字节不是 Byte Count，而是 Reference Type=0x06（tshark 实测：文档形式 `15 0C 0B 06...` 被 Wireshark 标记 Malformed，规范形式 `15 0B 06...` 正常解析；pymodbus `WriteFileRecordRequest.encode` 为 `>BHHH` 直接写 0x06）。另有 4 项 HIGH（其中 MEI 0x0E=响应侧标注为规范根本性误读）与 6 项中低问题，修复后方可进入实现阶段。**

---

## 一、CRITICAL

### C-1. FC 0x15 请求 item 首字节语义错误——v2.0.3 的 R3-C2 修复方向错误（§3.3.13 / §5.2 / T-021 / §8.2 V-115 / §8.4 / §10.3 / §11.4.1）

**位置**：§3.3.13 请求表与示例（`15 0C 0B 06 0001 0000 0002 1234 5678`）、T-021、§5.2 Values 注释、V-115、§8.4 FC 0x15 行与示例核对、§10.3。

**描述**：v2.0.3 按"规范 §6.15 表 35"将请求 item 定义为 `Byte Count(1)=7+2×RL + RefType(1) + File(2) + Record(2) + RecLen(2) + Record Data`，item 总长 8+2×RL，外层 Byte Count=0x0C。tshark 3.6.14 实测（本机）：`15 0C 0B 06 0001 0000 0002 1234 5678` → 外层 Byte Count=12，随后把 0x0B 当 Reference Type、`06 00 01` 当 Reference Number、`00 00` 当 Word Count，**标记 Malformed**；而规范形式 `15 0B 06 0001 0000 0002 1234 5678`（item 首字节直接是 Reference Type=0x06，外层 BC=11）→ **正常解析：Byte Count=11、Reference Type=6、File Number=1、Record Number=0、Word Count=2、Data**。pymodbus `WriteFileRecordRequest.encode` 亦为 `packet += struct.pack(">BHHH", 0x06, file, rec, len)`，外层 `total_length = sum(7+2×RL)`——**item 内无 Byte Count 字段，首字节即 Reference Type**。规范 §6.15 表 35 原文 item 结构为 `Reference Type | File Number | Record Number | Record Length | Record Data`（引用头字段为 Reference Type 而非 Byte Count；v2.0.2 的 `7+2×RL` 步进其实是对的）。

**依据**：tshark 3.6.14 实测（frame 1 Malformed vs frame 2 正常，`tshark -V`）；pymodbus dev file_message.py `WriteFileRecordRequest.encode`。

**修复建议**：FC 0x15 请求 item 结构改为 `RefType(1)=0x06 + File(2) + Record(2) + RecLen(2) + Data(2×RL)`，item 总长 = 7+2×RL；外层 Byte Count = Σ(7+2×RL)。示例改回 `15 0B 06 0001 0000 0002 1234 5678`（外层 BC=0x0B=11，PDU=13 字节，MBAP Length=14=0x000E）。同步修正 §1.5 不变量 9、§4.5、§5.2、T-021、T-057、V-115（Record Length 偏移回到 5-6）、§8.4 公式（1+Σ(7+2×RL)）、§10.3、§11.4.1 修订记录；T-187 增加"tshark 无 Malformed"断言。

---

## 二、HIGH

### H-1. FC 0x2B MEI Type 0x0E 语义标注错误——R3-M1 修复方向错误（§3.3.17 / §1.4 / §5.2 / §8.2 V-118 / T-026 / §10.4 / §11.4.3）

**位置**：§3.3.17 MEI Type 表（"0x0D=Read Device Identification（请求）；0x0E=Read Device Identification（响应侧 MEI Type）"）、§1.4（"0x0E 仅作响应侧 MEI Type 接受"）、§5.2 SubFunction 注释、V-118（0x0D=请求、0x0E=响应侧）、T-026、§10.4、§11.4.3 R3-M1。

**描述**：该"0x0D=请求 / 0x0E=响应侧"的二分是**对规范表 42 的根本性误读**。规范 §6.21 表 42 的 MEI Type 值是"**per FC 2B sub-function** 的请求值"（MEI Type 0x0D=**CANopen General（CiA 309）**、0x0E=**Read Device Identification**），即 0x0D 是 CANopen 封装、0x0E 是 Read Device Identification——**两者都是请求侧 MEI Type，没有"响应侧用 0x0D、请求侧用 0x0E"的区分**（Read Device Identification 的响应与请求使用同一个 MEI Type 0x0E）。tshark 3.6.14 实测：`2B 0D 01 00` → "MEI type: **CANopen Request/Response (13)**"；`2B 0E 01 00` → "MEI type: **Read Device Identification (14)**"。文档的 T-026（"0x0E=响应侧 MEI Type，Validate 接受"）与 T-025（请求 `2B 0D 01 00`、响应回显 0x0D）直接生成 Wireshark 视为 CANopen 的报文。

**依据**：规范 §6.21 表 42（0x0D=CANopen General、0x0E=Read Device Identification）；tshark 3.6.14 实测 frame 8/9；pymodbus mei_message.py（ReadDeviceInformationRequest/Response 均 `sub_function_code=0x0E`）。

**修复建议**：更正 MEI Type 语义：0x0D=CANopen General（CiA 309，本设计不实现）、0x0E=Read Device Identification（请求与响应同用 0x0E）。FC 0x2B 的 SubFunction 合法值改为 `0x000E`（Read Device Identification）；T-025 请求改 `2B 0E 01 00`、响应 `2B 0E 01 01 00 00 01 ...`；T-026 改为验证 0x0D（CANopen）被拒绝或按不实现处理；同步修正 §1.4、§5.2、V-118（0x0D 不再是合法 MEI Type）、§10.4、§11.4.3。

### H-2. FC 0x11 响应中 Byte Count 字段缺失（§3.3.11 / §4.5 / §8.4 / T-019 / S8）

**位置**：§3.3.11 响应表（字段：Byte Count + Slave ID + Run Indicator + Additional Data）、§4.5 FC 0x11 行、§8.4、T-019、S8 示例 `11 04 01 FF AA BB`。

**描述**：规范（§6.11 of V1.1b3 / PI-MBUS-300）中 FC 0x11 响应的字段顺序为 **Slave ID(1) + Run Indicator(1) + Additional Data(N)**——**没有首字节 Byte Count 字段**（Byte Count 仅存在于 Modbus RTU 的 FC 0x11 响应；Modbus TCP 的 FC 0x11 响应直接以 Slave ID 开始）。tshark 3.6.14 实测 `11 04 01 FF AA BB`：显示 "Data: 0401ffaabb"，无 Byte Count 字段（被 Wireshark 视为原始数据）。文档将 FC 0x11 的"首字节"当作 Byte Count=0x04，实际该字节是 Slave ID=0x04。对照：pymodbus `ReportSlaveIdResponse`（report_slave_id_message.py）编码无 Byte Count。此问题自 v2.0.0 起即存在，且 M2-CRIT-2（v2.0.0 声称"修复"）与 R3-M2（v2.0.3 声称"修正"）两轮均未发现。

**依据**：规范 §6.11 响应表；tshark 3.6.14 实测 frame 10；pymodbus report_slave_id_message.py。

**修复建议**：删除 FC 0x11 响应的首字节 Byte Count 字段。示例改为 `11 01 FF AA BB`（Slave ID=0x01、Run=0xFF、Additional=AA BB）；T-019/S8 相应改 RV 与断言；§4.5/§8.4（0x11 行改为 2+N）、§3.3.11、§10.3 同步修正；T-185 改为断言 tshark "Report Slave ID" 且无 Byte Count 字段（或删除该断言）。

### H-3. §8.3 背书规则与 §8.2 V-116 冲突（§8.3 / V-116 / T-111）

**位置**：§8.3 表第 1 行（"FC 0x05 WriteValue=0x1234 + ExcCode∈{0x04-0x08,0x0A,0x0B} → 合法"）、V-116 与 T-111。

**描述**：V-116（及 T-111 的错误消息）规定 WriteValue 非法值时**必须**配 ExceptionCode 才接受；§8.3 表第 1 行"无 ExceptionCode → 拒绝"列与 V-116 一致，但第 3 列与底部"规则：任意合法异常码均可背书"表明"配 ExcCode ∈ {0x04-0x08, 0x0A, 0x0B} → 合法"。若解读为"该列仅说明语义（背书合法）"，则与 V-116 一致，无冲突；但按字面（第 3 列"合法"与第 1 列"拒绝"对照），§8.3 表暗示"不同异常码区间背书效果不同"（0x01-0x03 与 0x04-0x0B 分别列出），而实际 Validate 只检查"ExceptionCode≠0 且合法"，两种区间行为完全相同。表格式 3 列布局误导实现者可能写出区间分支。

**依据**：文档内部 V-116 vs §8.3；§8.3 底部规则文字。

**修复建议**：§8.3 表精简为 2 列（无 ExcCode → 拒绝；配任意合法 ExcCode → 合法），删除误导性的"0x01-0x03 / 0x04-0x0B"区间列，或加注"两列行为相同，仅语义场景不同"。

### H-4. FC 0x18 FIFO Count=0 时长度不一致（§3.3.16 / T-062 / T-131 / §8.4）

**位置**：§3.3.16 响应表与约束、T-062、T-131、§8.4 FC 0x18 行。

**描述**：§3.3.16 约束"若 ResponseValues 中 FIFO Count > 31，Validate 拒绝"（V-119）只检查 FIFO Count 字段。但 §8.4 的 ResponseValues 长度公式为 `2 + 2 + FIFOCount×2`（Byte Count 2B + FIFO Count 2B + 值 2N），T-062/T-131 的 FIFO Count=0 时 RV 为 `00 00 00 00`（BC=2、FIFO=0、无值），而 T-029 的 FIFO Count=2 时 RV 为 6 字节。文档未定义 **FIFO Count（RV 中偏移 2-3）与 RV 中值字节数的自洽校验**：若用户配 FIFO Count=5 但只给 4 字节值，planner 按 §4.5 自动构造（BC=2+2N、FIFO=5、值=0）还是按 RV 透传？T-062/T-131 与 T-029 的 RV 长度不同（4 vs 6），证明实现需按 FIFO Count 重新计算 BC 与值长度——但 V-119 只查 >31，未定义"值字节数 ≠ 2×FIFO Count"时的行为（静默截断/报错？）。这是响应构造规则的未定义分支。

**依据**：文档内部 T-029 vs T-062 vs §8.4 公式。

**修复建议**：定义并测试"RV 值字节数 ≠ 2×FIFO Count"的 Validate 规则（如 `response_values length must match FIFO count`），或明确 planner 忽略 RV 中的值部分、按 FIFO Count 自动生成全 0 值（并在 V-119 旁注明）。

---

## 三、MEDIUM

### M-1. FC 0x08 子功能 0x0015 在 tshark 中被标记 Unknown（§3.3.6 / T-150 / T-203 / T-204 / V-117）

**位置**：§3.3.6 子功能表（0x0015=Get/Clear Modbus Plus Statistics 合法）、T-150、T-204、V-117。

**描述**：tshark 3.6.14 实测子功能 0x0014 → "Clear Overrun Counter and Flag (20)"（正常识别），0x0015 → "**Unknown (21)**"——即 Wireshark 3.6 的值表只到 0x0014，0x0015 未收录。文档将 0x0015 列为合法子功能（R3-H1 修复），V-117 允许它，但文档自认"tshark 为最终裁判"（§7.7），T-150 断言 0x0015 合法却无对应 tshark 集成用例——按文档自己的裁判标准，0x0015 报文无法被 tshark 逐字段识别。此外 MB-ASYM-TCP V1.1b3 §6.8 的"0x0015 Return IOP Overrun Count"是否准确（V1.1b3 官方表仅列至 0x0014、且 0x0013 的"Return IOP Overrun Count"名称在 pymodbus 与 Wireshark 中归属不同）存在版本间差异，文档未引用 pymodbus diag_message.py 佐证 0x0015。

**依据**：tshark 3.6.14 实测 frame 6（Diagnostic Code: Unknown (21)）。

**修复建议**：在 §3.3.6 加注"0x0015 在 Wireshark 3.6 值表未收录（显示 Unknown），tshark 集成用例（T-181~T-200）不覆盖 0x0015；如需验证用 tshark 新版本或自写解析器"，与 §9.5 工具链弱化声明对齐。

### M-2. 集成用例（T-181~T-200）普遍缺少字段级断言（§7.6 / CLAUDE.md §Testing Policy 4/5）

**位置**：§7.6 T-181~T-200。

**描述**：20 条集成用例中多数断言仅"tshark output 含 'Read Holding Registers' 等字符串"（T-181~T-184、T-188、T-191、T-198~T-200），未断言字节级/字段级输出。且 T-185（Report Server ID）断言"Byte Count"字段——FC 0x11 响应本无 Byte Count 字段（见 H-2），该断言在 tshark 上必然失败；T-186（FC 0x14）断言"item 含 File Response Length 字段"，但未给出该字段的期望值断言。按 CLAUDE.md §Testing Policy 5（断言可观察输出，而非结构存在），这些用例断言过弱，且至少 2 条（T-185/T-186）存在与文档自身 wire 形态不一致的断言。

**依据**：§7.6 表；tshark 实测 frame 10（FC 0x11 无 Byte Count 字段）。

**修复建议**：T-185 改为断言 Slave ID/Run Indicator 值或删除 Byte Count 断言；T-186 增加 File Response Length 具体值断言（如 =1+2×RL）；其余用例补充至少一个字段值断言（如 `modbus.ev_count==100` 类字段级匹配）。

### M-3. FC 0x17 响应与广播规则交叉未定义（§4.4 / V-002 / §1.3 / T-094~T-095）

**位置**：§1.5 不变量 11、§4.4 第 1 条、V-002、T-094/T-095、§4.2 广播特殊规则。

**描述**：文档反复强调"广播仅纯写功能码（0x05/0x06/0x0F/0x10/0x15/0x16）合法，FC 0x17 读写混合拒绝"（T-095 断言拒绝）。但**规范**对广播的定义是"除读功能码与 0x08 诊断外均可广播"（Modbus 规范 Broadcast：FC 0x05/0x06/0x0F/0x10/0x15/0x16 可广播——这与文档一致），规范未将 FC 0x17 单列为可广播。文档自身 §4.4 第 1 条"广播 + FC 0x17 → Validate 拒绝"与 §4.2 广播规则一致（0x17 不在纯写集），故文档内部自洽；问题在于：实现时若实现者按 §4.4 枚举"纯写集"而非"拒绝读集"编程，T-094 只测了 0x01，未覆盖 0x03/0x04/0x11/0x14/0x18/0x2B 等读类 FC 的广播拒绝路径——文档未给出"全部读类 FC 广播均拒绝"的参数化用例（§Testing Policy 3）。

**依据**：文档内部 T-094~T-095 仅 2 例；规范 Broadcast 定义。

**修复建议**：补充参数化负向用例：广播 + FC 0x02/0x03/0x04/0x07/0x08/0x0B/0x0C/0x11/0x14/0x18/0x2B 均拒绝（至少各 1 例）。

---

## 四、LOW

### L-1. 依据链缺 RFC 7540 内容（§1.1）

**位置**：§1.1 与文档头"规范来源：... / RFC 7540（信息性）"。

**描述**：RFC 7540 是 HTTP/2 规范，与 Modbus TCP 无任何内容关联；文档称其"仅引用 TCP 传输通用约定"但 TCP 传输约定在 RFC 793，且文档正文未实际引用 RFC 7540 的任何条款。该引用纯属误导（可能是先前模板遗留）。删除后文档更严谨。

**依据**：RFC 7540（HTTP/2）；文档 §1.1 自述"无 Modbus 内容"。

**修复建议**：删除规范来源与 §1.1 中的 RFC 7540 引用，或替换为 RFC 793（TCP）。

### L-2. 修订记录 §11.3.3 与正文 C-1 的残留矛盾（§11.3.3 / §11.4.1）

**位置**：§11.3.3 R2-M2 行的"R3 更正"注 vs §11.4.1 R3-C2。

**描述**：R3-C2 声称"FC 0x15 请求 item 首字节为 Byte Count=7+2×RL"，但 R3-M2 的更正注说"R2-M2 的 7+2×RL 遗漏了 item 首字节的 Byte Count 字段"——两处都对"首字节是否 Byte Count"表述一致，但均与规范（首字节=RefType）不符（见 C-1）。修订记录与正文一起错，无需单独列条；但"修复 R3-C2"的措辞会让实现者误以为该字段已获规范确认。归入 C-1 修复范围即可，此处仅记录。

**依据**：文档内部 §11.4.1 vs §11.3.3 注。

**修复建议**：随 C-1 一并修正 §11.4.1 的修复声明。

### L-3. T-089 归类矛盾（§7.3 / §2.5 / §8.2 V-122）

**位置**：T-089（"异常码 0x00 非法"）、§2.5（"0x00（=正常响应）...一律拒绝"）、V-122（"0x00 视为正常响应不报错"）。

**描述**：T-089 位于负向用例分组（§7.3），但输入"ExcCode=0x00"的期望是"接受（0=正常响应语义，V-016 允许）——不报错"，行为是正向的。且 §2.5 说"0x00 一律拒绝"而 V-122 说"0x00 视为正常响应不报错"——两处矛盾（0x00 究竟拒绝还是接受）。T-089 的"期望：接受"与 V-122 一致，与 §2.5 冲突。该歧义自 v2.0.2 起存在（§11.3.4 R2-L4 曾明确"含 T-089 的'异常码 0x00 接受'特殊语义"，说明是有意为之），但 §2.5 表述未同步。

**依据**：文档内部 §2.5 vs V-122 vs T-089。

**修复建议**：§2.5 补注"0x00 在配置层视为'未设置异常'，不报错（V-122）；与异常响应无关"，消除矛盾表述。

### L-4. 测试用例对照矩阵 §7.8 引用缺失（§7.8 / §7.4）

**位置**：§7.8 矩阵（"§2.7 数量上限 T-003/T-007/T-098~T-110"、"§8.4 响应长度公式 T-007/T-029/T-055/T-124/T-158"）。

**描述**：§7.8 将边界用例全部归属 T-098~T-110 与 T-121~T-160，但 §7.4 标题为"边界用例（T-121 ~ T-160）"，矩阵未引用 T-121~T-160 的任何编号（如 T-126 qty=1968、T-128 qty=123 上限、T-130 WriteBC=242、T-132 FIFO=31 等边界断言未入矩阵），且 T-003 与 T-122 重复（qty=2000 两条）、T-030 与 T-132 重复（FIFO=31 两条，§11.3.4 R2-L3 已承认"与 T-030 等价"仍保留）。矩阵与用例编号的映射不完整。

**依据**：文档内部 §7.2~§7.4 vs §7.8。

**修复建议**：§7.8 数量上限行补充 T-121~T-132 等边界编号；或删除重复用例（T-122/T-132）并同步计数（205→203）。

---

## 五、v2.0.3 修复项复核结论（9 项）

| # | 修复项 | v2.0.3 声明 | 复核结论 |
|---|--------|-------------|----------|
| 1 | C-1：FC 0x14 响应 item 改为 File Response Length=1+2×RL | 已修复 | **正确**。tshark 实测 `14 06 05 06 1234 5678` → Byte Count=6、item Byte Count=5、RefType=6、Data=12345678，正常解析；pymodbus 一致（len(data)+1） |
| 2 | H-1：FC 0x08 子功能上限 0x0015 | 已修复 | **部分正确**。0x0014 tshark 识别为 Clear Overrun Counter and Flag ✓；0x0015 tshark 显示 Unknown（M-1）；上限 0x0015 本身符合规范 §6.8 |
| 3 | H-2：FC 0x0C 字段顺序 | 已修复 | **正确**。tshark 实测 `0C 0A FFFF 0064 000A ...` → Status=0xffff、Event Count=100、Message Count=10，顺序与文档一致 |
| 4 | C-2：FC 0x15 请求 item 补 Byte Count | 已修复 | **错误（方向性）**。item 首字节是 Reference Type=0x06 而非 Byte Count；文档形式被 tshark 判 Malformed（C-1/CRITICAL） |
| 5 | M-2：FC 0x11 示例 Byte Count 自洽 | 已修复 | **仅算术自洽**。BC=0x04 与其自身 4 字节数据算术自洽，但 FC 0x11 响应规范无 Byte Count 字段（H-2）；且 R3-M2 拒绝 R3 审计建议的 `11 04 01 FF AA BB CC` 属正确判断（该例 BC=4 与 5 字节数据确实矛盾），但未发现"首字节是 Slave ID" |
| 6 | M-1：MEI Type 0x0E 标注 | 已修复 | **错误（方向性）**。0x0E=Read Device Identification（请求与响应同用），0x0D=CANopen General；"0x0D=请求/0x0E=响应侧"系对表 42 的误读（H-1） |
| 7 | MBAP Length = 1(Unit)+PDU | — | **正确**。全部 15 个 HexDump 逐字节核算一致（S1~S15 的 Length 均 =1+PDU） |
| 8 | HexDump 自洽性 | — | **除 C-1（S13 无 FC 0x15 场景，S 场景未受影响）外全部自洽**。S1~S12、S14、S15 的 TID/Length/PDU 核算无算术错误；T-020/T-021 示例的"文档内部算术"自洽，但 wire 形态错（C-1）；S8/T-019 的 BC=0x04 算术自洽但字段语义错（H-2） |
| 9 | 测试用例符合 CLAUDE.md §Testing Policy | — | **部分符合**。M-2（断言过弱）、M-3（广播拒绝未参数化）、L-4（矩阵映射不全）；正向/负向/边界三分组结构、每 FC 至少 1 正向、10 异常码全覆盖（T-031~T-040）、豁免路径（T-081/T-201）等符合政策 |

---

## 六、实验记录（tshark 3.6.14 实测）

生成 13 个 Modbus/TCP 报文（MBAP + PDU）写入 pcap，`tshark -r -V` 逐帧检查：

| 帧 | 载荷（PDU） | tshark 判定 | 结论 |
|----|-------------|-------------|------|
| 1 | `15 0C 0B 06 0001 0000 0002 1234 5678`（v2.0.3 FC 0x15 形式） | **Malformed**（BC=12 → RefType=11 → RefNum=0x060001 → WordCount=0） | 文档 C-1 错误实锤 |
| 2 | `15 0B 06 0001 0000 0002 1234 5678`（规范形式） | 正常：BC=11、RefType=6、File=1、Record=0、WordCount=2、Data | 规范实锤 |
| 3 | `14 06 05 06 1234 5678`（v2.0.3 FC 0x14 响应） | 正常：BC=6、item Byte Count=5、RefType=6、Data | C-1(0x14) 正确 |
| 4 | `14 06 06 0001 0000 0002`（FC 0x14 请求） | 正常：BC=6、item BC=6、RefType=0、Data=0100000002 | 请求 item 结构正确（但 item 内"BC=6"是 RefType 6 与 BC=6 的巧合） |
| 5 | `08 0014 1234` | Diagnostics / **Clear Overrun Counter and Flag (20)** | 0x0014 合法实锤 |
| 6 | `08 0015 1234` | Diagnostics / **Unknown (21)** | 0x0015 未收录（M-1） |
| 7 | `0C 0A FFFF 0064 000A 01 02 03 04` | Status=0xffff、Event Count=100、Message Count=10 | H-2 正确 |
| 8 | `2B 0D 01 00` | MEI type: **CANopen Request/Response (13)** | 0x0D=CANopen 实锤（H-1） |
| 9 | `2B 0E 01 00` | MEI type: **Read Device Identification (14)**，Basic，Conformity=0x00（后续字段因我未构造完整响应而 Malformed，非结构错误） | 0x0E=Read Device Identification 实锤（H-1） |
| 10 | `11 04 01 FF AA BB` | Report Slave ID，**Data: 0401ffaabb**（无 Byte Count 字段） | H-2 实锤 |
| 11 | `18 0006 0002 0001 0002` | Byte Count (16-bit)=6、Word Count=2、Data=00010002 | FC 0x18 结构正确 |
| 12 | `15 07 06 0001 0000 0002 1234 5678`（v2.0.2 形式） | 正常：BC=7、RefType=6、RefNum=0x00010000、WordCount=2、Data | 佐证"无 item 内 Byte Count" |
| 13 | `15 1B 0B 06 0001 0000 0002 1234 5678 0A 06 000A 000A 0001 1234 5678 90`（v2.0.3 双 item） | **Malformed** | 双 item 同样错误 |

---

## 七、最终结论

**否。v2.0.3 不可直接进入实现阶段。**

1 项 CRITICAL（C-1：FC 0x15 请求 item 首字节语义，R3-C2 修复方向错误，tshark 实测 Malformed）+ 4 项 HIGH（H-1：MEI 0x0E 语义误读，R3-M1 方向错误；H-2：FC 0x11 响应多出 Byte Count 字段；H-3：§8.3 背书区间表述歧义；H-4：FC 0x18 长度自洽未定义）+ 3 项 MEDIUM + 4 项 LOW。

v2.0.3 的 9 项复核中：6 项正确（C-1-0x14、H-1 上限值、H-2-0x0C、第 7 项 Length 公式、HexDump 算术、测试政策大体），2 项方向性错误（C-2/FC 0x15、M-1/MEI 0x0E），1 项部分正确（H-1/0x0015 tshark 未收录）。此外 R3 轮 7 项中未发现的新问题：FC 0x11 响应 Byte Count 缺失（H-2，tshark 实测确认）。

**优先修复顺序**：C-1（FC 0x15 item 结构）→ H-1（MEI Type）→ H-2（FC 0x11 响应）→ H-3/H-4 → M-1~M-3 → L-1~L-4。修复后建议用 tshark 对全部 19 个 FC 的请求/响应报文做一次实测回归（与本文档第六节同法），以 tshark 无 Malformed 为通过标准。

**文档结束（v2.0.3，2026-08-05）**

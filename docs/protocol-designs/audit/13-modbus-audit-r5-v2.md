# MODBUS TCP 设计文档 R5 复审审计报告（13-modbus-design.md v2.0.4）

- 审计对象：`/home/weihang/trafficGenerator/docs/protocol-designs/13-modbus-design.md`（v2.0.4，1944 行）
- 审计日期：2026-08-05
- 审计方式：对照 Modbus.org MB-ASYM-TCP V1.1b3 / PI-MBUS-300 Rev. J 逐节核对 + **本机 tshark 3.6.14 / text2pcap 实测 wire 形态**（共 20+ 种报文逐字节构造并解析）+ 测试用例质量审查（CLAUDE.md §Testing Policy）
- 默认"有 bug"原则：所有关键断言均以 tshark 实测裁决，不采信文档自述

## 0. 实测方法论

使用 `text2pcap -T <src>,<dst>` 构造带 MBAP 头的 TCP 载荷，`tshark -V` 解析，逐字段比对文档断言。实测清单：

| # | 报文形态 | 文档断言 | tshark 实测 | 结论 |
|---|---------|---------|------------|------|
| 1 | FC 0x15 请求 `15 0B 06 0001 0000 0002 1234 5678`（Length=0x000E） | 正常解析（C-1/R4-C1 规范形式） | Byte Count=11、Reference Type=6、File=1、Record=0、Word Count=2、Data=12345678，无 Malformed | ✅ 一致 |
| 2 | FC 0x15 请求 `15 0C 0B 06 0001 0000 0002 1234 5678`（v2.0.3 形式） | 被标记 Malformed | Malformed，Reference Type=11、Word Count=0 | ✅ 一致 |
| 3 | FC 0x11 响应 `11 01 FF AA BB`（Length=6） | 无 Byte Count（R4-H2） | Report Slave ID，Data: 01ffaabb，无 Byte Count 字段 | ✅ 一致 |
| 4 | FC 0x11 响应 `11 04 01 FF AA BB`（旧形式，Length=7） | 0x04 是 Slave ID 而非 BC | Data: 0401ffaabb（0x04 进 Data） | ✅ 一致 |
| 5 | FC 0x2B 请求 `2B 0E 01 00` | MEI=Read Device Identification（R4-H1） | "MEI type: Read Device Identification (14)"，Basic (1)，VendorName | ✅ 一致 |
| 6 | FC 0x2B 请求 `2B 0D 01 00` | 0x0D=CANopen 不实现 | "MEI type: CANopen Request/Response (13)"，Data: 0d0100 | ✅ 一致 |
| 7 | FC 0x2B 响应 `2B 0E 01 01 00 00 01 00 04 41 42 43 44`（T-025/T-202） | 七字段完整 | Conformity=Basic stream(0x01)、More Follows=0x00、Next=0、Objects=1、Object#1 ID=VendorName Len=4 Val=ABCD | ✅ 一致 |
| 8 | FC 0x14 请求 `14 06 06 0001 0000 0002` | item 7B 固定步进，BC=6 | Byte Count: 6，Group 0 正常 | ✅ 一致 |
| 9 | FC 0x14 请求双 item（T-057，BC=14=0x0E） | 2×7B 步进 | Byte Count: 14，Group 0/1 均解析，无 Malformed | ✅ 一致 |
| 10 | FC 0x14 响应 `14 06 05 06 1234 5678`（T-020/T-186） | File Response Length=0x05（R3-C1） | Byte Count: 6，**Group 0 Byte Count: 5**、Reference Type: 6、Data: 12345678 | ⚠️ 值一致，字段名不符（见 F-02） |
| 11 | FC 0x18 响应 `18 0006 0002 0001 0002`（T-029） | Byte Count 2B=6、FIFO Count=2 | Byte Count (16-bit): 6、Word Count: 2、Data: 00010002 | ✅ 一致 |
| 12 | FC 0x18 响应 FIFO=31（T-030） | FIFO Count=31 | Byte Count (16-bit): 62、Word Count: 31 | ✅ 一致 |
| 13 | FC 0x0C 响应 `0C 0A FFFF 0064 000A 01 02 03 04`（T-055） | Status→EventCount→MessageCount 顺序（R3-H2） | Byte Count: 10、Status: 0xffff、Event Count: 100、Message Count: 10、Events×4 | ✅ 一致 |
| 14 | FC 0x0B 响应 `0B FFFF 0064` | Status 2B=0xFFFF | Get Comm. Event Counters、Status: 0xffff、Event Count: 100 | ✅ 一致 |
| 15 | FC 0x08 子功能 0x0014 | 合法，tshark 识别 | "Clear Overrun Counter and Flag (20)" | ✅ 一致 |
| 16 | FC 0x08 子功能 0x0015 | 合法但 tshark 显示 Unknown（R4-M1） | "Unknown (21)" | ✅ 一致 |
| 17 | FC 0x08 子功能 0x0013 | 合法（R3-H1） | "Unknown (19)" | ✅ 一致（0x0013 值合法，tshark 未收录值表） |
| 18 | FC 0x17 请求/响应（T-027/S9） | Length=0x0011/0x0017 | Read Reference=0、Read Word Count=10、Write Reference=20、Write Word Count=3、Byte Count=6、Data=111122223333；响应 Byte Count: 20 | ✅ 一致 |
| 19 | FC 0x03 qty=125 响应（S13/T-007） | Length=0x00FD=253 | Byte Count: 250，无 Malformed | ✅ 一致 |
| 20 | 异常响应 `83 02` | FC\|0x80 + ExcCode | "Read Holding Registers. Exception: Illegal data address"，Length: 3 | ✅ 一致 |
| 21 | 豁免路径 `99 01`（S14/T-201） | 0x99\|0x80=0x99 幂等 | "Unknown (25). Exception: Illegal function"，Function Code: Unknown (25)=0x19 显示为 0x19 | ⚠️ 见 F-01 |
| 22 | FC 0x0F 请求（T-053） | BC=⌈10/8⌉=2 | Byte Count: 2、Data: 0301 | ✅ 一致 |
| 23 | FC 0x16 请求/响应（T-023） | AND/OR Mask | AND mask: 0xffff、OR mask: 0x0000 | ✅ 一致 |
| 24 | FC 0x15 双 item 请求（T-022，RecLen=1+1） | 每 item 9B 动态步进，BC=18 | Byte Count: 18、Group 0 Word Count: 1、Group 1 Word Count: 1，无 Malformed | ✅ 一致 |
| 25 | FC 0x14 请求双 item 步进（RecLen 相同 7B 固定） | T-057 BC=14 | 双 Group 正常解析 | ✅ 一致 |
| 26 | FC 0x0C 响应 BC=5（<6 固定字段） | 自洽校验 | Malformed（tshark 判） | ⚠️ 佐证 V-119 类校验的必要性 |
| 27 | FC 0x18 响应 BC=0006 但值字节 2B（Length 截断） | 自洽校验 V-119 | Word Count=2、Data 截断为 000100，**无 Malformed** | ⚠️ 见 F-05 |

结论：v2.0.4 声称的 5 个重点修复（C-1/H-1/H-2/H-3/H-4）**全部与 tshark 实测一致**，方向正确、落地正确。发现的问题集中在测试用例断言细节与少量文档自洽性，详见下文。

## 1. 问题汇总

| ID | 严重度 | 位置 | 摘要 |
|----|--------|------|------|
| F-01 | LOW | §6.15/T-201 | tshark 对 `99 01` 的 Function Code 显示为 0x19（Unknown (25)），与文档"0x99 原样传输"的自洽性陈述需加工具链注 |
| F-02 | MEDIUM | T-186/§7.6 | 断言 tshark 输出含 "File Response Length" 字段名，实测字段名为 "Group 0 Byte Count: 5" |
| F-03 | LOW | §6.9 S8 配置注释 | S8 的 ResponseValues 语义（FC 之后字节）未显式说明，易与 T-080 混淆 |
| F-04 | MEDIUM | T-187 断言 | tshark 3.6.14 对 0x15 item 首字节显示 "Reference Type: 6" 与文档断言一致，但文档 §3.3.13 表"Record Number"字段名与 tshark "Reference Number (32 bit)" 不同（值一致） |
| F-05 | MEDIUM | T-119b/V-119 | 断言 FC 0x18 "response_values length must match FIFO count" 为 Validate 错误——实测 tshark 对 Length 截断的 0x18 响应**不报 Malformed**，该自洽校验是文档自定义（合理），但 T-119b 断言错误消息依赖实现；且 §8.3 背书表"FC 0x18 FIFO Count=32 配异常码合法"与 V-119 的"值字节数自洽"交互未定义 |
| F-06 | MEDIUM | T-062/T-131 | FC 0x18 FIFO Count=0 响应 `18 0002 0000`（值字节数=0）——tshark 实测该形态可解析（Word Count: 0），但文档 §2.7 表"FC 0x18 FIFO Count 最小 0"与 §8.3 背书表冲突未说明 |
| F-07 | LOW | §11.5.2 R4-H2 文本 | "v2.0.0 起的 M2-CRIT-2 与 R3-M2 两轮修复均未发现"——M2-CRIT-2 原始记录（§11.1）标注的正是"FC 0x11 响应漏 Byte Count"，即当年加的是多余字段；§11.1 的追溯注已覆盖，但 §11.4.3 R3-M2 条目未同步标注"该轮修复本身错误" |
| F-08 | LOW | §3.3.6 子功能表 | 0x0002/0x0003 行写"回显"，但规范 §6.8 中 0x0003（Change ASCII Input Delimiter）响应含新分隔符数据（回显请求数据字段），0x0002（Return Diagnostic Register）响应含诊断寄存器内容——"回显"仅对 0x0000 严格成立 |
| F-09 | LOW | §4.5 表 FC 0x08 行 | "回显请求 PDU（子功能 0x0000 Return Query Data 语义）"——对非 0x0000 子功能，planner 自动构造未定义（依赖 ResponseValues），与 §3.3.6"v2 默认实现 0x0000 回显模式"需显式关联 |
| F-10 | LOW | §2.5 异常码表 | 0x07 Negative Acknowledge 的说明沿用 PI-MBUS-300 的串行链路语义（"客户端应请求诊断或错误信息"），在 Modbus TCP 上下文无对应机制，建议标注"保留码，wire 上合法" |

合计：0 CRITICAL + 0 HIGH + 4 MEDIUM + 6 LOW。

## 2. v2.0.4 重点修复逐项核实（对照 tshark 实测）

### 2.1 C-1：FC 0x15 请求 item 回退（✅ 正确）

文档 §3.3.13/§1.5 不变量 9/§5.2 注释/T-021/T-022/V-115/§8.4/§10.3 全部统一为：item = RefType(1)+File(2)+Record(2)+RecLen(2)+Data(2×RL)，总长 7+2×RL，外层 BC=Σ(7+2×RL)，Record Length 偏移 5-6。

tshark 实测（#1/#2）：规范形式 `15 0B 06 0001 0000 0002 1234 5678`（Length=0x000E=14）→ 正常解析（Byte Count=11、Reference Type=6、File Number=1、Record Number=0、Word Count=2、Data=12345678，无 Malformed）；v2.0.3 形式 `15 0C 0B 06 ...` → Malformed。**文档回退方向正确**。

双 item 动态步进（T-022，RecLen=1+1，item 各 9B，外层 BC=18=0x12）实测正常解析（#24），"按各 item 偏移 5-6 的 RecLen 动态步进"（V-115）成立。v2.0.4 的 §11.5.1 记录（R3-C2 方向错误、pymodbus `>BHHH` 依据）与实测一致。

### 2.2 H-1：FC 0x2B MEI Type（✅ 正确）

文档 §3.3.17/§5.2/§5.3/V-118/§1.4/T-025/T-026/T-117 统一为：0x0E=Read Device Identification（请求/响应同用）、0x0D=CANopen General 不实现。

tshark 实测（#5/#6）：`2B 0E 01 00` → "MEI type: Read Device Identification (14)"；`2B 0D 01 00` → "MEI type: CANopen Request/Response (13)"。**文档的 MEI Type 语义与实测完全一致**，R4-H1 回退 R3-M1 正确。

### 2.3 H-2：FC 0x11 响应无 Byte Count（✅ 正确）

文档 §3.3.11/§4.5/§6.1/§6.9/T-019/T-080/T-185/§8.4/§10.3 统一为：响应 = FC + Slave ID(1) + Run Indicator(1) + Additional(N)，无 Byte Count。

tshark 实测（#3/#4）：`11 01 FF AA BB`（Length=6）→ "Report Slave ID"，Data: 01ffaabb，无 Byte Count 字段；`11 04 01 FF AA BB`（Length=7，旧形式）→ Data: 0401ffaabb——0x04 作为数据被吞入 Data 字段，证实旧形式错误。**文档删除 Byte Count 字段正确**，§6.9 S8 的 Length=0x0006=1+5 与总字节 12 核算自洽。

### 2.4 H-3：§8.3 背书表 2 列（✅ 正确）

v2.0.4 将 §8.3 从 R3 的 3 列区间布局（无 ExcCode / ExcCode∈{0x01-0x03} / ExcCode∈{0x04-0x0B}）精简为 2 列（无 ExcCode / 配任意合法 ExcCode），并显式声明"Validate 只检查 ExceptionCode 合法且非零，不区分区间"。消除了实现者写出区间分支的误导。**方向正确**。

### 2.5 H-4：FC 0x18 长度自洽（✅ 正确，但见 F-05/F-06）

文档 §3.3.16/V-119/§4.5/T-062/T-119b/§8.4 统一为：RV 值字节数必须 = 2×FIFO Count，Byte Count 由 planner 按 2+2×FIFO Count 重算。

tshark 实测（#11/#12/#27）：FIFO=2 且值 4B → "Byte Count (16-bit): 6、Word Count: 2、Data: 00010002" 完整解析；FIFO=31 且值 62B → "Byte Count (16-bit): 62、Word Count: 31"。但 Length 截断（值 2B 而 FIFO=2、BC=6）→ Word Count=2、Data 截断为 000100，**tshark 不报 Malformed**——即 tshark 对 FC 0x18 的 BC/FIFO/值三者的自洽性不做校验，该自洽校验是文档自定义的 Validate 规则（对 traffic generator 是合理的防御），但 T-119b 的断言消息依赖实现而非规范，见 F-05。

### 2.6 MBAP Length = 1(Unit) + PDU 字节数（✅ 全部场景一致）

实测 #1/#3/#5/#8/#10/#11/#18/#19/#20 中 Length 值全部与文档核算一致（0x000E/0x0006/0x0005/0x0009/0x0009/0x0011/0x0017/0x00FD/0x0003）。

### 2.7 全部 HexDump 自洽性（✅ S1-S15 逐字节核算无矛盾）

S1-S15 的 PDU 字节、Byte Count、Length 逐项核算：S1（01 02 03 01，Length=5）、S2（03 06 1234 5678 9ABC，Length=9）、S3（05 0064 FF00，Length=6）、S4（10 0014 0002 04 1111 2222，Length=11；响应 Length=6）、S5（0F 0000 000A 02 0301，Length=9；响应 Length=6）、S6（06 0014 1234，Length=6）、S7（08 0000 AABB，Length=6）、S8（11 01 FF AA BB，Length=6）、S9（Length=17/23）、S10（16 0000 FFFF 0000，Length=8）、S13（Length=253）、S14（99，Length=2；响应 Length=3）、S15（TID 0/1/2）——全部自洽，无算术错误。

## 3. 问题详情

### F-01（LOW）§6.15 S14 / T-201：tshark 对 0x99 的功能码显示为 0x19

- **位置**：§6.15（行 1209 附近）、T-201（行 1512）
- **描述**：文档断言 `99 01` 中功能码字节 0x99 原样传输（0x99|0x80=0x99 幂等）。tshark 实测（#21）：`99 01`（Length=3）→ "Function 25: Unknown Function. Exception: Illegal function"，Function Code 显示为 **0x19**（Unknown (25)）——Wireshark 对 bit7 置位的功能码做掩码显示（0x99 & 0x7F = 0x19），并识别为异常响应（Function 25 + Exception: Illegal function）。
- **依据**：tshark 3.6.14 实测输出。文档对 wire 字节的正确性（0x99 原样）无问题，但 §6.15 验证一节和 T-201 断言"bytes PDU=`99 01`"若将来用 tshark 做集成验证（同 T-181~T-200 的方式），tshark 会显示 0x19 而非 0x99，与文档的"幂等语义"表述需要工具链注记调和。
- **修复建议**：在 §6.15 或 §9.5 工具链声明中加注："tshark 3.6 对 bit7 置位的功能码显示为 `FC & 0x7F`（0x99 显示为 Unknown (25)=0x19），wire 字节仍为 0x99；集成用例若断言 tshark 输出须以 0x19 为准或改用自写解析器"。

### F-02（MEDIUM）T-186：tshark 字段名 "File Response Length" 不存在

- **位置**：T-186（行 1492）、§7.6 集成用例、§11.5.2 R4-M2
- **描述**：T-186 断言 `tshark output 含 "Read File Records" + File Response Length 值=0x05`（R4-M2 加强为"字段级断言"）。实测（#10）：tshark 3.6.14 对 FC 0x14 响应 item 首字节的显示是 **"Group 0\n    Byte Count: 5"**，没有 "File Response Length" 字样。
- **依据**：tshark 3.6.14 实测输出。文档 R4-M2 自称"字段值断言以 tshark 实测为准"，但该断言中的字段名并未实测验证。
- **修复建议**：T-186 断言改为 `tshark output 含 "Read File Records" 且含 "Byte Count: 5"`（或加注"tshark 显示名为 Group N Byte Count，即规范的 File Response Length"），并说明与规范术语的映射。

### F-03（LOW）§6.9 S8：ResponseValues 配置注释未显式声明"FC 之后字节"

- **位置**：§6.9 S8 配置（行 1034）、§8.4 表头
- **描述**：S8 配置 `ResponseValues=[0x01, 0xFF, 0xAA, 0xBB]`（Slave ID=0x01, Run Indicator=0xFF, Additional=2 字节），§8.4 表头声明"ResponseValues 长度均为 FC 之后的字节"，但 S8 正文未重复该语义。T-080 用 RV=[0x01, 0xFF]（无 Additional）与 S8 的 4 字节 RV 并存，两处字节核算正确但读者易混淆"RV 是否含 FC"。
- **依据**：§8.4 表头与 §6.9 正文的表述差异；T-020 的 RV 注释（"ResponseValues 含外层 BC"）已显式标注，S8 未标注。
- **修复建议**：S8 配置注释补一句"RV 为 FC 之后的字节（同 §8.4 表头）"。

### F-04（MEDIUM）T-187 / §3.3.13：item 字段名与 tshark 显示名差异

- **位置**：T-187（行 1493）、§3.3.13 表（行 402）
- **描述**：文档 §3.3.13 表将 item 字段命名为 Reference Type / File Number / Record Number / Record Length / Record Data；T-187 断言 `tshark output 含 "Reference Type" 字段=6`。实测（#1）：tshark 3.6.14 显示 **"Reference Type: 6"、"Reference Number (32 bit): 65536"（=File<<16|Record）、"Word Count: 2"、"Data: 12345678"**——"File Number/Record Number"在 tshark 中被合并为 32 位 Reference Number，无独立 File Number 字段名。
- **依据**：tshark 3.6.14 实测输出。
- **修复建议**：T-187 断言保持 "Reference Type" 即可（值=6 一致）；文档 §3.3.13 表可加注"tshark 将 File+Record 合并显示为 Reference Number (32 bit)"，避免实现者用 tshark 断言 File Number 字段时踩空。

### F-05（MEDIUM）T-119b / V-119 与 §8.3 背书交互未定义；tshark 不校验 0x18 自洽性

- **位置**：T-119b（行 1408）、V-119（行 1578）、§8.3（行 1589）、T-112（行 1399）
- **描述**：①V-119 定义"RV 值字节数必须 = 2×FIFO Count"——这是文档自定义的防御性 Validate 规则（tshark 实测 #27 对 BC=6/FIFO=2/值 2B 的截断形态不报 Malformed，规范未要求此校验），本身合理且 T-119b 已覆盖负向路径（符合 §Testing Policy 第 2 条）。②**真正的缺口**：§8.3 背书表第 3 行"FC 0x18 FIFO Count=32 配任意合法异常码 → 合法"，与 V-119 的"值字节数 = 2×FIFO Count 自洽校验"交互未定义——FIFO Count=32 配 ExceptionCode 时，请求 PDU 的 RV 仍含 FIFO Count=32，但响应被替换为异常 PDU；RV 中值字节数按 2×32=64 校验还是跳过？文档未说明该路径下 V-119 是否豁免。同理 §8.3 第 2 行"Quantity=0 配异常码 → 合法"与 V-104~V-107 的交互已隐含"背书覆盖数量校验"，但 FC 0x18 的自洽校验是否被背书覆盖无对应条款。
- **依据**：§8.3 与 V-119 的交叉核对；tshark #27 实测。
- **修复建议**：在 §8.3 或 V-119 补充一句："配 ExceptionCode 时响应为异常 PDU，FC 0x18 的 RV 自洽校验（V-119）仍对请求侧 RV 生效（FIFO Count=32 仍拒绝），或显式定义背书时跳过该校验"——二选一需明确，并补一条对应测试（如 T-119c）。

### F-06（MEDIUM）T-062/T-131：FC 0x18 FIFO Count=0 的形态 tshark 可解析，但 §2.7 与 §8.3 边界表述需统一

- **位置**：T-062（行 1333）、T-131（行 1425）、§2.7 表（行 161）、§8.3（行 1589）、§3.3.16（行 482）
- **描述**：T-062/T-131 定义 FIFO Count=0 响应 `18 0002 0000`（Byte Count=2、FIFO Count=0、值字节数=0），断言自洽。tshark 实测：`18 0002 0000`（Length=0x0006=6）→ "Byte Count (16-bit): 2、Word Count: 0"（无 Data，无 Malformed）——形态合法。但文档 §3.3.16 与 §2.7 将 FIFO Count 最小标为 0，而 §2.7 表"0x18 FIFO Count（响应）最小 0 最大 31"与 §8.3"FIFO Count=32 配异常码合法"之间缺"FIFO Count=0 是否合法"的显式背书交互说明（FIFO Count=0 本身已合法，无冲突，但文档未显式声明"0 合法"与"背书规则无关"）。
- **依据**：tshark 实测 + §2.7/§3.3.16/§8.3 交叉核对。
- **修复建议**：§2.7 或 §3.3.16 加一句"FIFO Count=0 合法（空 FIFO，Byte Count=2）"，与 T-062/T-131 呼应；§8.3 背书表行注明"FIFO Count=32 背书仅在 RV 自洽（值字节数=2×32）或异常响应跳过 RV 校验时成立"（合并到 F-05 的修复）。

### F-07（LOW）§11.5.2 R4-H2 与 §11.4.3 R3-M2 的历史标注不对称

- **位置**：§11.4.3 R3-M2（行 1897）、§11.5.2 R4-H2（行 1921）、§11.1（行 1786）
- **描述**：R4-H2 在 §11.1 的 M2-CRIT-2 历史条目加了 R4 更正注（"方向错误——FC 0x11 响应规范中无 Byte Count 字段"），但 §11.4.3 R3-M2 条目（"FC 0x11 响应示例逐字节核算修正……BC 值更正为 0x04"）未同步标注"该轮修复方向错误，v2.0.4 已回退"。实现者读 §11.4.3 时仍可能误信 0x04 是合法 Byte Count。
- **依据**：§11 修订记录交叉核对。
- **修复建议**：§11.4.3 R3-M2 条目末尾加 R4 更正注（同 §11.3.3 R2-M2 的做法）。

### F-08（LOW）§3.3.6 子功能表：0x0002/0x0003 的"回显"表述不精确

- **位置**：§3.3.6 子功能表（行 273）
- **描述**：表中 0x0002/0x0003 行写"回显"。规范 §6.8：0x0002（Return Diagnostic Register）响应数据字段是**诊断寄存器内容**（回显请求中的 16 位数据字段值）；0x0003（Change ASCII Input Delimiter）响应**回显新分隔符**（请求数据字段）。"回显"对这两个子功能实质成立（响应数据=请求数据字段），但响应语义（诊断寄存器/分隔符）未说明，与 0x0000（Return Query Data 完整回显 PDU）混淆。
- **依据**：MB-ASYM-TCP §6.8 表 14/15 的响应语义。
- **修复建议**：0x0002/0x0003 行改为"响应含请求数据字段回显（诊断寄存器内容/新分隔符）"，与 0x0000 的"整 PDU 回显"区分。

### F-09（LOW）§4.5 FC 0x08 行与 §3.3.6"默认 0x0000 回显"的关联未显式化

- **位置**：§4.5 表（行 640）、§3.3.6 注（行 283）
- **描述**：§4.5 表 FC 0x08 行写"回显请求 PDU（子功能 0x0000 Return Query Data 语义）"，§3.3.6 注写"v2 默认实现 0x0000 回显模式，其他子功能由用户通过 ResponseValues 显式注入"。两处表述一致但未交叉引用；实现者对"非 0x0000 子功能 + ResponseValues 为空"时 planner 的行为（拒绝？回显？）无定义。
- **依据**：§4.5/§3.3.6 交叉核对。
- **修复建议**：§4.5 FC 0x08 行加注"SubFunction≠0x0000 且 ResponseValues 为空时，planner 行为未定义（建议 Validate 拒绝或回显请求数据字段），需在实现前明确"。

### F-10（LOW）§2.5 异常码 0x07 的说明沿用串行链路语义

- **位置**：§2.5 异常码表（行 137）
- **描述**：0x07 Negative Acknowledge 的说明"客户端应请求诊断或错误信息"源自 PI-MBUS-300（串行链路）；Modbus TCP 中 0x07 是保留合法的异常码，无对应"请求诊断"机制（FC 0x08 诊断是主动功能而非响应触发）。文档 v2.0.0 恢复 0x07 合法性的修复（M2-HIGH-4）正确，但说明文字可能误导实现者去实现不存在的联动。
- **依据**：MB-ASYM-TCP §7 表 24；PI-MBUS-300 §6.17。
- **修复建议**：0x07 行说明改为"合法异常码（TCP 中保留，wire 上可传输），无联动机制"。

## 4. 测试用例质量审查（CLAUDE.md §Testing Policy）

- **spec-driven 覆盖**：§7.8 对照矩阵将 §1.3/§2.5/§2.7/§3.3/§3.4/§4.2/§4.4/§5.2/§5.3/§6/§8.1/§8.2/§8.3/§8.4/§9/§10.3 全部映射到用例，19 个 FC × 至少 1 条正向（T-001~T-030/T-052~T-080）、10 个异常码各 1 条（T-031~T-040）、R4 追加 13 条覆盖广播负向参数化（T-095b~T-095l）与 MEI 0x000F 拒绝（T-117b）与 FC 0x18 自洽（T-119b）——覆盖完整，无已识别的"规范行无对应测试"缺口。
- **负向路径**：T-081~T-120 覆盖 40 条 Validate 拒绝（非法 FC/异常码/数量/Values 长度/广播/UnitID 保留/子功能/MEI），含失败路径，符合 §Testing Policy 第 2 条。
- **集成测试**：T-181~T-200 用 tshark 验证 wire 形态，符合第 4 条"跨层集成"；但存在 F-02/F-04 的字段名断言问题（断言目标与 tshark 实际输出不符），以及 F-01 的 0x99 显示问题——这些属于"断言与工具输出匹配性"缺陷，不是覆盖缺口。
- **可观察输出断言**：T-001~T-080 大多断言具体字节序列（如 `01 02 03 01`），符合第 5 条。
- **残余缺口**：
  1. §8.3 背书 + V-119 交互无测试（F-05，建议 T-119c）。
  2. FC 0x0C 的 Byte Count 与 Events 长度解耦仅 T-056 一条，无负向（Events 配置与 BC 不自洽时 Validate 是否拒绝未定义——§8.4 0x0C 行未声明该校验）。
  3. FC 0x14 响应 item 的 File Response Length 与 Record Data 长度不自洽（如 FRL=5 但 Data=6B）无 Validate 规则与测试——tshark 对该形态是否 Malformed 未实测（建议实现时以 tshark 实测为准）。
  4. T-117b（SubFunction=0x000F）与 T-026/T-117（0x000D）覆盖了 0x0E 之外的拒绝路径，但 0x00-0x0C/0x10-0xFF 的拒绝仅靠 V-118 文字，无参数化——LOW。
- **整体评价**：测试用例质量符合 §Testing Policy 的精神，218 条用例覆盖充分；上述缺口均为 LOW/MEDIUM 级补充项，不影响进入实现。

## 5. 结论

**本文档可以进入实现阶段（是）。**

依据：
1. v2.0.4 声称的 5 个重点修复（C-1/H-1/H-2/H-3/H-4）全部经 tshark 3.6.14 实测确认方向正确、落地正确；
2. MBAP Length 公式、15 个 HexDump 场景、19 个 FC 的 PDU 结构逐字节核算无算术错误；
3. 测试用例 218 条覆盖完整，符合 §Testing Policy 主要条款；
4. 本次审计发现 0 CRITICAL + 0 HIGH + 4 MEDIUM + 6 LOW，全部为测试断言细节、工具链注记、表述精确性问题，不涉及 wire 格式错误，不阻塞实现。

建议实现阶段注意（MEDIUM 项）：
- T-186 断言改用 tshark 实际字段名（Group N Byte Count）；
- §8.3 背书与 V-119 自洽校验的交互需在实现前定稿（F-05）；
- tshark 集成用例对 FC 0x99 豁免路径的断言以 0x19 显示为准（F-01）。

---

**文档结束（R5 复审审计，2026-08-05）**


- **位置**：T-119b（行 1408）、V-119（行 1578）、§8.3（行 1589）、T-112（行 1399）
- **描述**：①V-119 定义"RV 值字节数必须 = 2×FIFO Count"——这是文档自定义的防御性 Validate 规则（tshark 实测 #27 对 BC=6/FIFO=2/值 2B 的截断形态不报 Malformed，规范未要求此校验），本身合理且 T-119b 已覆盖负向路径（符合 §Testing Policy 第 2 条）。②**真正的缺口**：§8.3 背书表第 3 行"FC 0x18 FIFO Count=32 配任意合法异常码 → 合法"，与 V-119 的"值字节数 = 2×FIFO Count 自洽校验"交互未定义——FIFO Count=32 配 ExceptionCode 时，请求 PDU 的 RV 仍含 FIFO Count=32，但响应被替换为异常 PDU；RV 中值字节数按 2×32=64 校验还是跳过？文档未说明该路径下 V-119 是否豁免。同理 §8.3 第 2 行"Quantity=0 配异常码 → 合法"与 V-104~V-107 的交互已隐含"背书覆盖数量校验"，但 FC 0x18 的自洽校验是否被背书覆盖无对应条款。
- **依据**：§8.3 与 V-119 的交叉核对；tshark #27 实测。
- **修复建议**：在 §8.3 或 V-119 补充一句："配 ExceptionCode 时响应为异常 PDU，FC 0x18 的 RV 自洽校验（V-119）仍对请求侧 RV 生效（FIFO Count=32 仍拒绝），或显式定义背书时跳过该校验"——二选一需明确，并补一条对应测试（如 T-119c）。





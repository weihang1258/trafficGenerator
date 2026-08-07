# GBT32960 设计文档对抗审计报告

> 审计对象：`docs/protocol-designs/01-gbt32960-design.md`（1523 行，v1.0，2026-08-03）
> 审计依据：GB/T 32960.3-2016 规范、CLAUDE.md 测试策略 §1-§8、`internal/protocol/socks5/socks5.go` Planner 模式、`internal/core/types.go` Config 字段模式
> 审计日期：2026-08-03
> 审计人：独立协议审计代理

## 1. 审计概览

本审计对 GBT32960 设计文档进行交叉对抗审查，覆盖 GB/T 32960.3-2016 协议一致性、扩展表 1 (gbt32960ProtocolLog) 字段覆盖、状态机完整性、Config 字段完整性、多车场景、CLAUDE.md 测试策略 8 条规则以及常见陷阱。

### 1.1 审计结论

| 维度 | 评价 |
|---|---|
| 起始符/命令单元/应答标志/VIN/加密/长度/校验 字段顺序 | 头部骨架与规范一致（24B + BCC） |
| BCC 校验范围 | 正确（不含起始符，从命令单元到数据单元末） |
| 0x01 车辆登入数据单元 | CRITICAL：与规范不符（流水号 2B 不是 20B；漏掉可充电储能子系统字段） |
| 0x02 实时上报数据单元 | CRITICAL：与规范完全不符（规范是「信息类型+信息体」循环，无固定报警/状态/流水号头部） |
| 0x04 车辆登出数据单元 | CRITICAL：与规范不符（漏掉登入流水号字段，仅 6B 时间） |
| 0x05 平台登入 / 0x07-0x0A 命令标识 | CRITICAL：命令标识编码可能整体错位（规范平台登入=0x05，但设计中 0x07=补发请求/0x08=控制/0x0B=心跳/0x0C=确认 需核实） |
| 加密方式枚举 | MEDIUM：规范含 0x04 SM2 / 0x05 SM4（设计仅列 0x01-0x03） |
| 应答标志 0xFE 语义 | HIGH：0xFE 是「上行报文应答标志」而非「首发占位」 |
| 状态机 | 基本完整，但 LoginAck 失败分支路径含糊、心跳方向错误 |
| Config 字段完整性 | 缺扩展表 1 多个字段（connectId/procedureType/platformDomain 等） |
| 多车场景 | 4-tuple 分配合理，但 strategy_vin 概念字段与现有模式不符 |
| 测试用例 | 89 条数量达标，但 spec 覆盖偏差大（基于错误格式写正向用例）、失败路径缺位 |

### 1.2 问题严重度分布

| 严重度 | 数量 |
|---|---|
| CRITICAL | 8 |
| HIGH | 9 |
| MEDIUM | 9 |
| LOW | 6 |
| **合计** | **32** |

## 2. CRITICAL 问题

### C1. §3.1 0x01 车辆登入数据单元结构与规范不符

**位置**：§3.1（第 145-153 行），表「0x01 车辆登入」数据单元字段定义。

**问题**：设计文档定义 0x01 数据单元为「登入时间 6B + SIM 号 20B + 车辆序列号 20B = 46B」。但 GB/T 32960.3-2016 表 7（车辆登入数据格式和定义）实际为：

| 字段 | 长度 | 类型 |
|---|---|---|
| 数据采集时间/登入时间 | 6 | BYTE[6] |
| **登入流水号** | **2** | **WORD** |
| **ICCID（SIM卡号）** | **20** | STRING |
| **可充电储能子系统数 n** | **1** | BYTE |
| **可充电储能系统编码长度 m** | **1** | BYTE |
| **可充电储能系统编码** | **n×m** | STRING |

设计文档把「登入流水号」字段误描述为 20B ASCII「车辆序列号」（实际 2B WORD），且完全漏掉了「可充电储能子系统数 + 编码长度 + 编码」三字段。设计文档第 153 行称「车辆序列号是流水的 20 字节字符串」，与规范无任何对应。

**依据**：GB/T 32960.3-2016 表 7；参考「登入流水号 2 字节 WORD，每登入一次自动加1，从1开始循环累加，最大值65531，循环周期为天（每日00:00归0）」。

**影响**：实现者照此设计生成的 0x01 报文将被 Wireshark gbt32960 解析器标记为 Malformed，所有后续业务流程（0x02 上报、0x0C 确认）均无法被真实平台解析。

**修复建议**：
1. 将 0x01 数据单元改为「登入时间 6B + 登入流水号 2B(WORD 大端) + ICCID 20B + 可充电储能子系统数 1B + 编码长度 1B + 编码 n×m B」。
2. Config 字段 `VehicleLoginSerial`（20B 字符串）改为 `LoginSerialNumber`（uint16，范围 1-65531）。
3. 新增 Config 字段 `RechargeableSubsysCount`、`RechargeableSubsysCodeLength`、`RechargeableSubsysCodes`（string 数组）。
4. §7.1 hex 示例重写（当前 hex `00 2E` data length=46 也需调整为 6+2+20+1+1+n×m）。
5. 附录 B.1 hex 重写。

### C2. §3.2 0x02 实时信息上报数据单元结构与规范完全不符

**位置**：§3.2（第 156-208 行），表「0x02 实时信息上报」数据单元字段定义。

**问题**：设计文档定义 0x02 数据单元为「采集时间 6B + 数据项流水号 2B + 报警标志 4B + 状态标志 2B + 子数据项 N」固定 14B 头部 + 子项。但 GB/T 32960.3-2016 表 7（实时信息上报数据格式和定义）实际为「信息类型标志 + 信息体」循环结构，**没有**独立的流水号、报警标志、状态标志头部字段：

| 字段 | 长度 | 类型 |
|---|---|---|
| 数据采集时间 | 6 | BYTE[6] |
| 信息类型标志(1) | 1 | BYTE |
| 信息体(1) | — | — |
| …… | — | — |
| 信息类型标志(n) | 1 | BYTE |
| 信息体(n) | — | — |

报警数据是信息类型 0x07 下的一个信息体（含最高报警等级 1B + 通用报警标志 32B），而非 0x02 头部的固定字段。状态标志属于 JT/T 808 而非 GB/T 32960.3。设计文档把 JT808 的「报警标志 DWORD + 状态 DWORD + 经纬度 + 速度」位置基本报文格式误植到 GBT32960。

**依据**：GB/T 32960.3-2016 表 7（实时信息上报）、表 8（信息类型标志定义：0x01 整车/0x02 驱动电机/0x05 车辆位置/0x06 极值/0x07 报警数据）。规范明确「实时数据报文的数据单元中，可以信息类型为单位进行任意拼装，但不得以数据项为单位进行拼装」。

**影响**：所有 0x02 报文将被 Wireshark 标记为 Malformed；T-GBT-008（断言数据单元 ≥14B = 6+2+4+2+子项）是基于错误格式写出的测试，按 spec 驱动（CLAUDE.md §1）应推翻重写。

**修复建议**：
1. 0x02 数据单元改为「采集时间 6B + (信息类型 1B + 信息体)*」循环结构。
2. 删除 `AlarmFlags`/`StatusFlags` 作为 0x02 头部固定字段的描述，改为「报警数据是信息类型 0x07 的信息体」。
3. 信息类型 0x05（车辆位置）格式：「定位状态 1B + 经度 4B(DWORD) + 纬度 4B(DWORD)」，**不含速度**（设计 §3.2.3 称「定位子项 type=0x05 + 经纬度 + 速度」是错误的，速度属于 JT808 而非 GBT32960）。
4. Config 字段重构：`AlarmFlags` 改为 `AlarmData` 子结构（含 `MaxAlarmLevel` uint8 + `GeneralAlarmFlags` 32B hex），独立于 0x02 头部。
5. 附录 B.3 hex 重写。

### C3. §3.4 0x04 车辆登出数据单元漏掉登入流水号字段

**位置**：§3.4（第 215-216 行）。

**问题**：设计文档定义 0x04 数据单元为「仅 6 字节登出时间 BCD」。但规范车辆登出数据单元为「登出时间 6B + 登入流水号 2B(WORD)」，且「登出流水号与当次登入流水号一致」。

**依据**：GB/T 32960.3-2016 车辆登出章节：「字段包括登出时间、登入流水号」「登出流水号与当次登入流水号一致」。

**影响**：0x04 报文长度错（设计 6B，规范 8B）；平台无法将登出与登入关联，业务断裂。T-GBT-009「断言登出时间 BCD 编码正确」未断言流水号字段（因为设计根本没这字段），按 CLAUDE.md §5「断言可观测」属于结构断言而非值断言。

**修复建议**：0x04 数据单元改为「登出时间 6B BCD + 登入流水号 2B WORD 大端」；Config 增加 `LogoutSerialNumber`（空则与 `LoginSerialNumber` 一致）。

### C4. §1.3 命令标识 0x05-0x0C 编码与规范一致性存疑

**位置**：§1.3（第 38-53 行）命令总览表。

**问题**：设计文档定义 12 个命令：0x01 车辆登入 / 0x02 实时上报 / 0x03 补报 / 0x04 车辆登出 / 0x05 平台登入 / 0x06 平台登出 / 0x07 补发请求 / 0x08 控制命令 / 0x09 参数查询 / 0x0A 参数设置 / 0x0B 平台心跳 / 0x0C 平台确认。

但规范命令标识存在多种版本分歧：
- 部分资料显示平台登入=0x05、平台登出=0x06；
- 另有资料显示平台心跳命令标识为 **0x80**（不是 0x0B），平台登入=0x07 而非 0x05；
- 「补发请求」方向（平台→车辆）在规范中是否存在独立命令标识未在设计文档中给出规范条目引用。

设计文档第 38-53 行的命令表没有标注每条命令的规范条目号（如表 X），无法溯源。设计文档自称「GBT32960 定义了 12 个命令」但未引用 GB/T 32960.3 第几章第几表。

**依据**：GB/T 32960.3-2016 命令标识定义章节；web 检索结果显示「0x80 平台心跳」与设计文档的「0x0B 平台心跳」冲突。

**影响**：若命令标识编码错误，所有平台侧报文（0x05/0x06/0x0B）将被接收方丢弃；T-GBT-010/011/012/074 等用例全部基于错误编码。

**修复建议**：
1. 设计文档 §1.3 表格每行增加「规范条目」列，标注 GB/T 32960.3-2016 章节号与表号。
2. 核实 0x05/0x06/0x07/0x08/0x0B/0x0C 的确切编码（特别是平台心跳是否为 0x80 而非 0x0B）。
3. 若规范确有 0x80 心跳，则设计文档 §3.11 的 `0x0B` 全部改为 `0x80`，附录 A 常量 `GBT32960CmdHeartbeat` 改值。
4. §6.1 包序列表（第 605-626 行）的 cmd 字段同步修正。

### C5. §1.4 应答标志 0xFE 语义错误

**位置**：§1.4（第 55-66 行）+ §2.2 第 94 行 + §3.11 第 810 行 + 附录 A 第 1413 行。

**问题**：设计文档定义 0xFE 为「首发报文用 0xFE（保留值，表示无应答语义）」，并在 §3.11 把平台心跳的应答标志也填 0xFE。但规范明确：「当报文为上行（命令包）时，应答标志应为 0xFE」——0xFE 是**所有上行报文**的应答标志（因为上行报文是命令发起方，无需应答上一条），而非仅「首发报文」。

设计文档 §3.11 平台心跳是**平台→平台**方向（上行到上级平台），应答标志 0xFE 正确；但 §6.1 包序列第 4 行「0x0C 平台确认 down (resp=01)」后的第 6 行「0x02 实时上报 up」的应答标志应填 0xFE（上行），而设计文档示例 hex（附录 B.3 第 1455 行）写 `23 23 02 FE` 正确，但 §1.4 文字描述「首发报文用 0xFE」误导——按规范**所有上行报文**都用 0xFE，不只是首发。

更严重：设计 §3.12（第 263-264 行）称 0x0C 平台确认「应答标志字段即承载成功/错误/VIN 重复/命令不支持语义」——但 0x0C 是**下行**报文，下行报文的应答标志按规范也应是 0xFE（下行报文同样是命令发起方）。0x01/0x02 的成功与否应体现在 0x0C 的**数据单元**（确认的命令单元回填）+ 上行报文次条的应答标志。设计文档把语义搞反了。

**依据**：GB/T 32960.3-2016 命令单元定义：「当报文为上行（命令包）时，应答标志应为 0xFE」；应答标志 0x01 成功 / 0x02 错误等是**应答报文**（下行 0x0C 之外的应答）的语义。

**影响**：实现者按设计文档会把 0x0C 报文头应答标志填 0x01-0x04（错误），正确做法是 0x0C 应答标志也填 0xFE，成功/失败语义在 0x0C 数据单元或下一上行报文的应答标志。所有 T-GBT-015/016/017/018 用例断言「0x0C resp=0x01/0x02/0x03/0x04」均错误。

**修复建议**：
1. §1.4 改为「0xFE = 上行报文应答标志（命令发起方无需应答上一条）；0x01-0x04 = 下行应答报文（0x0C 之外）的应答结果」。
2. §3.12 0x0C 数据单元语义重写：0x0C 报文头应答标志恒 0xFE，0x0C 数据单元 1B 是「所确认报文的命令单元」，成功/失败由 0x0C 的下一上行报文应答标志或独立应答报文承载。
3. 附录 B.2 hex `23 23 0C 01` 改为 `23 23 0C FE`（若 0x0C 是下行）。
4. 所有 ResponseFlags 相关用例（T-GBT-015~018）重写。

### C6. §3.5 0x05 平台登入数据单元字段长度与规范不符

**位置**：§3.5（第 220-228 行）。

**问题**：设计文档定义 0x05 数据单元为「平台用户名 12B + 平台密码 20B + 加密密钥序号 16B = 48B」。但规范平台登入数据单元的「加密密钥序号」实际为 16B 但其语义是「加密密钥的标识/版本号」而非「密钥序号」。更重要的是：设计文档未引用规范条目，无法验证 12/20/16 这三个长度的规范来源。web 检索的多个来源对平台登入字段长度描述不一（部分资料平台用户名为 12B，部分为变量长度）。

设计文档第 228 行称「VIN 字段对平台报文无意义，全 17 字节填 0x00」——但 web 检索显示规范规定平台报文的「唯一识别码」字段使用「城市邮政编码+VIN前三位」等规则，**不是全 0x00**。

**依据**：GB/T 32960.3-2016 平台登入章节；web 来源：「车辆数据传输时用VIN，平台传输时用城市邮政编码+VIN前三位等规则」。

**影响**：0x05 报文的 VIN 字段全 0x00 将被上级平台拒绝（无法识别平台身份）；T-GBT-012 断言「12 user + 20 pwd + 16 encrypt_seq」基于未溯源的长度。

**修复建议**：
1. §3.5 增加规范条目引用。
2. 平台报文 VIN 字段（唯一识别码）改为「城市邮政编码 + VIN 前三位」或明确允许用户通过 Config 字段 `PlatformID` 自定义 17B。
3. 核实 12/20/16 长度的规范来源，若与规范不符则修正。
4. §4.3 `GBT32960PlatformLogin` 增加 `PlatformID` 字段（17B 平台唯一识别码）。

### C7. §3.2.1 报警标志位定义与规范不一致

**位置**：§3.2.1（第 168-191 行）报警标志位域表。

**问题**：设计文档定义 bit31=电池高温报警、bit30=电池电压过高报警、bit29=电池电压过低报警 等 16 个固定报警位（bit31-bit16），bit15-bit0 厂商自定义。但 web 检索规范原文显示报警标志位定义完全不同：
- bit0 = 温度差异报警（不是 bit31 电池高温）
- bit1 = 电池高温报警（不是 bit30 电池电压过高）
- bit2 = 车载储能装置类型过压报警
- bit3 = 车载储能装置类型欠压报警
- bit19 = 热事件报警（修订草案新增）

设计文档的「bit31 电池高温」位序与规范「bit1 电池高温」完全相反，且设计文档自称「与 Wireshark gbt32960 解析器一致」——但若 Wireshark 解析器按规范 bit0=温度差异，则设计文档的位序约定与 Wireshark 不一致。

更根本的问题（见 C2）：报警标志在规范中是信息类型 0x07 信息体的一部分（最高报警等级 1B + 通用报警标志 32B），不是 0x02 头部固定字段。

**依据**：GB/T 32960.3-2016 报警数据章节；web 来源：「bit 0 温度差异报警、bit 1 电池高温报警、bit 2 过压报警、bit 3 欠压报警」「热事件报警 第19个bit」。

**影响**：所有报警上报报文（§7.3 场景）的报警标志字段值错误；T-GBT-038「80000000 → 80 00 00 00 大端」按设计是「电池高温」，按规范是「bit31 厂商自定义」。

**修复建议**：
1. 删除 §3.2.1 整个位域表（因为报警标志不是 0x02 头部字段）。
2. 在信息类型 0x07 报警数据信息体章节重新定义：「最高报警等级 1B（0=无/1=一级/2=二级/3=三级）+ 通用报警标志 32B（bit0 温度差异/bit1 电池高温/.../bit19 热事件）」。
3. Config `AlarmFlags` 改为 `AlarmData` 结构含 `MaxAlarmLevel` + `GeneralAlarmFlags`。
4. §7.3 报警上报场景重写。

### C8. §3.2.2 状态标志位域是 JT808 字段误植

**位置**：§3.2.2（第 194-202 行）状态标志位域表。

**问题**：设计文档定义 0x02 头部 2B 状态标志位域（bit15 车辆状态/bit14 充电状态/bit13 运行模式/bit12 车辆模式/bit11 绝缘状态）。但 GB/T 32960.3-2016 **没有**「状态标志」这一头部字段——状态字段属于 JT/T 808 位置基本信息的「状态 DWORD」（bit0 ACC/bit1 定位/bit2 南北纬/bit3 东西经/bit18 GPS 卫星定位）。

设计文档把 JT808 的状态位域（语义和位数都改了）误植到 GBT32960 的 0x02 头部。这是 C2 问题的子症状，但单独列出因为状态标志在 Config 中有独立字段 `StatusFlags`，影响面广。

**依据**：GB/T 32960.3-2016 实时信息上报数据单元（无状态标志字段）；JT/T 808-2019 位置基本信息（状态 DWORD 语义如上）。

**影响**：所有 `StatusFlags` Config 字段无对应报文位置；T-GBT-041「4000 → 40 00 大端 充电中」基于错误的位定义。

**修复建议**：
1. 删除 §3.2.2 整个状态标志位域表。
2. Config 删除 `StatusFlags` 字段（或改为信息类型 0x01 整车数据下的子字段，若规范确有整车状态字段则引用规范条目）。
3. §7.12 状态变更记录场景中 `status_flags` 字段移除或重构。
4. T-GBT-041/042 用例删除或重写。

## 3. HIGH 问题

### H1. §2.3 VIN 编码字符集约束不完整

**位置**：§2.3（第 102-105 行）。

**问题**：设计文档称「VIN 字符集为 GB/T 32960.3 规定的 VIN 字符集（不含 I/O/Q，详见 ISO 3779）」。但 V4 校验规则（第 450 行）只校验「非 ASCII 字符（任一字节 > 0x7F）」，**不校验** I/O/Q 三字母。VIN 含 I/O/Q 的输入会通过 Validate 但被真实平台拒绝。

**依据**：ISO 3779 VIN 字符集约束（不含 I/O/Q/U/Z 等易混淆字母，具体由 GB 16735 规定）。

**影响**：用户输入 `VIN="LIOXXXXXXXXXXXX5"` 会通过 Validate 但生成非法 VIN。

**修复建议**：V3 增加「VIN 含 I/O/Q 字符」校验，错误消息 `gbt32960: VIN contains invalid char %q at offset %d (I/O/Q not allowed)`。增加对应负向用例。

### H2. §2.4 BCC 算法描述与伪代码边界条件不一致

**位置**：§2.4（第 109-127 行）。

**问题**：文字描述「校验范围为偏移 2 到 24+N-1 的全部字节」（24+N-1 是数据单元最后一字节偏移），但伪代码（第 114-122 行）写 `for i := 2; i < len(packet); i++`，其中 `len(packet)` 是「起始符到数据单元」长度（不含 BCC）。两者等价但表述方式不同——伪代码用 `len(packet)` 容易让实现者误以为 `packet` 包含 BCC（若包含则循环会异或 BCC 自身）。

§6.3 第 651 行 `bcc := bccXOR(buf[2:])` 是正确写法（`buf` 不含 BCC），但 §2.4 伪代码 `packet` 参数语义不清。

**依据**：GB/T 32960.3-2016 BCC 定义（从命令单元第一字节到数据单元最后一字节异或）。

**影响**：实现者若把 BCC 字节也传入 `bccXOR` 则 BCC 计算错误（包含自身）；T-GBT-002「独立实现 BCC 比对」若独立实现也含 BCC 则两个错误抵消，测试通过但实际错误。

**修复建议**：§2.4 伪代码改为 `// packet[2:len(packet)-1] = 命令单元到数据单元（不含 BCC，BCC 已剥离）` 并明确 `packet` 不含 BCC。或直接用切片 `bccXOR(buf[2:len(buf)-1])` 风格。

### H3. §2.5 数据长度字段上限与规范不符

**位置**：§2.5（第 130-133 行）。

**问题**：设计文档称「长度上限：65535 字节（2 字节字段上限）」。但规范明确「数据单元长度有效值范围 0~65531」（web 来源：「数据单元长度 WORD，有效值范围 0~65531」）。65532-65535 是保留值。

设计文档 V14 校验「Reports[i].Serial < 0 或 > 65535」对应的是流水号（且流水号规范上限是 65531 不是 65535），但**没有**对 CustomFields/数据单元长度做 65531 上限校验。

**依据**：GB/T 32960.3-2016 数据单元长度字段定义（0-65531）。

**影响**：生成的报文数据长度字段为 65532-65535 将被接收方视为非法。

**修复建议**：增加 V28 校验「数据单元长度 > 65531 报错」；§7.14 边界表增加「CustomFields 致数据单元 > 65531」用例。

### H4. §5.1 状态机 LoginAck 失败分支路径含糊

**位置**：§5.3（第 590-597 行）异常分支表。

**问题**：§5.3 称「ST_LOGIN_ACKED resp=02/03/04 → 不进入 ST_REPORTING，直接转 ST_LOGOUT_SENT」。但 §1.4 / §3.12 已混乱（见 C5）——若 0x0C 报文头应答标志恒 0xFE，那么「resp=02/03/04」从哪个字段读？设计文档第 594 行写「resp=02/03/04（由 ResponseFlags 触发）」但 ResponseFlags Config 字段在 §4.1 第 354 行注释「override the default 0x01 success on the next 0x0C acknowledgement」——即 ResponseFlags 写入 0x0C 报文头应答标志字段。这与 C5 矛盾。

更严重：若 resp=03（VIN 重复），规范行为是平台拒绝该车辆登入，**车辆侧不应主动登出**（应等待平台断开 TCP 或重试）。设计文档称「直接转 ST_LOGOUT_SENT」即车辆主动发 0x04 登出，但 VIN 重复意味着平台认为这辆车已在线，车辆发 0x04 是对哪次登出？逻辑断裂。

**依据**：GB/T 32960.3-2016 应答标志语义；规范 VIN 重复处理（平台拒绝，非车辆主动登出）。

**影响**：状态机在 resp=03 时行为不符合规范；T-GBT-054「LoginAck resp=02 不进入 Reporting」用例不断言登出报文是否生成，覆盖不全。

**修复建议**：
1. 厘清 resp 字段来源（C5 修复后）。
2. resp=03 分支改为「车辆侧等待 TCP 关闭或重试登入（Config 字段控制），不主动登出」。
3. T-GBT-054 增加断言「resp=02 时是否生成 0x04 登出报文」。

### H5. §5.2 平台心跳方向错误

**位置**：§5.2（第 558-588 行）+ §3.11（第 259-260 行）+ §7.7（第 803-810 行）。

**问题**：设计文档 §5.2 状态机图把「ST_HEARTBEAT emit 0x0B up × N」画成上行（平台→上级平台），方向正确。但 §7.7 第 808 行写「连续生成 3 条 0x0B up 报文」——`up` 在项目代码（socks5.go 第 323 行 `direction` 参数）中表示 client→server。对于平台心跳，平台是 client、上级平台是 server，`up` 正确。

但 §3.11 第 810 行「`23 23 0B FE <17×00> 01 00 00 <bcc>`」中加密方式字段写 `01`——平台心跳若作为平台→上级平台报文，加密方式应与平台登入 0x05 一致（可能用 0x03 AES128），而非恒 0x01。设计文档未说明心跳加密方式是否继承 PlatformLogin 配置。

**依据**：GB/T 32960.3-2016 平台心跳；规范加密方式字段语义。

**影响**：若用户配置 PlatformLogin.EncryptSeq 指向 AES128 密钥，但心跳加密方式恒 0x01，平台与上级平台加密方式不一致。

**修复建议**：§3.11 增加「心跳加密方式字段继承 PlatformLogin 配置（或独立 HeartbeatEncryptRule 字段）」。

### H6. §4.1 Config 缺少扩展表 1 多个字段

**位置**：§4.1（第 274-376 行）GBT32960Config 主结构。

**问题**：对照 `00-unimplemented-list.md` 扩展表 1 (gbt32960ProtocolLog)，设计文档缺以下字段：

| 扩展表字段 | 中文 | Config 字段 | 状态 |
|---|---|---|---|
| connectId | 连接 ID | 无 | 缺失 |
| procedureType | 流程类型 | `Role` 部分覆盖 | 部分缺失 |
| vehicleLoginTime | 车辆登入时间 | `LoginTime` | 已覆盖 |
| loginSerialNumber | 登入流水号 | `VehicleLoginSerial`（语义错，应为 uint16） | 语义错 |
| vehicleLoginoutTime | 车辆登出时间 | `LogoutTime` | 已覆盖 |
| loginoutSerialNumber | 登出流水号 | 无 | 缺失 |
| encryptionRule | 加密规则 | `EncryptRule` | 已覆盖 |
| platformDomain | 平台域名 | 无 | 缺失 |
| setPlatformDomain | 设置平台域名 | 无 | 缺失 |
| statusChangeTrace | 状态变更记录 | `StatusChangeTrace` | 已覆盖（但语义错，见 C8） |
| maxAlarmLevel | 最高报警等级 | 无 | 缺失 |
| alarmFlags | 通用报警标志 | `AlarmFlags` | 已覆盖（但位定义错，见 C7） |
| isTransBatteryData | 是否传输电池数据 | 无 | 缺失 |

**依据**：`docs/protocol-designs/00-unimplemented-list.md` 第 15 行；扩展表 1 字段定义。

**影响**：6 个字段缺失（connectId/loginoutSerialNumber/platformDomain/setPlatformDomain/maxAlarmLevel/isTransBatteryData），实现后无法完整支持扩展表上报。

**修复建议**：
1. Config 增加 `ConnectID` (string)、`LogoutSerialNumber` (uint16)、`PlatformDomain` (string)、`SetPlatformDomain` (string)、`MaxAlarmLevel` (uint8 0-3)、`IsTransBatteryData` (bool)。
2. `VehicleLoginSerial` 改为 `LoginSerialNumber` (uint16)。
3. §4.4 增加对应 Validate 规则（V28-V33）。
4. §8 增加对应用例。

### H7. §6.1 包序列表 ACK 包语义错误

**位置**：§6.1（第 605-626 行）包序列表。

**问题**：第 5 行「4 down TCP PSH-ACK 0x0C 平台确认」后第 5 行「5 up TCP ACK pure ACK for #4」。但 socks5.go 第 411-413 行的 TCP 握手模式是 SYN/SYN-ACK/ACK 三步，握手后第一个数据 PSH-ACK 不需要单独 pure ACK 响应（除非接收方窗口耗尽）。设计文档在第 5 行强制每条 PSH-ACK 后跟一条 pure ACK，这违反 TCP 实际行为（接收方仅在需要时发 ACK，且可延迟合并）。

更严重：第 11 行「8 up TCP ACK pure ACK」、第 14 行「11 up TCP ACK」——每条 down 方向 PSH-ACK 后都跟 up pure ACK，但 up 方向 PSH-ACK（如 0x02 上报）后**没有** down pure ACK（第 9 行 0x02 up 后第 10 行直接 0x0C down）。这种不对称 ACK 模式不符合 TCP 双向累计确认语义。

**依据**：RFC 9293 TCP 确认机制；socks5.go 第 411-413 行（握手后无 pure ACK，直接数据）。

**影响**：生成的 pcap 中 ACK 模式不自然，tshark 可能标记「Dup ACK」或「Out of Order」；T-GBT-052「包数 = 14」基于错误的 ACK 计数。

**修复建议**：
1. 删除每条 PSH-ACK 后的 pure ACK，改为「累计确认：下一 PSH-ACK 隐含 ACK 上一报文」。
2. §6.1 包序列重算，T-GBT-052/053 包数断言更新。
3. 参考 socks5.go 的 emit 模式（无 pure ACK）。

### H8. §6.2 MSS 分段约束与 V27 矛盾

**位置**：§6.2（第 631-637 行）+ V27（第 473 行）。

**问题**：§6.2 称「v1 不实现 MSS 分段，约束 CustomFields 长度 ≤ MSS-26，由 Validate 检查」。但 V27 校验规则（第 473 行）写「spec.TCP.MSS < MinMSS(536) 报错」——V27 只校验 MSS 下限，**没有**校验「CustomFields 长度 ≤ MSS-26」。设计文档 §6.2 声明的约束在 Validate 规则表中不存在。

**依据**：CLAUDE.md §3「测试正确的函数/scope——每个代码路径需有测试」。

**影响**：用户配置 CustomFields=2000B + MSS=1460 时数据单元 2024B > MSS-26=1434，planner 生成的单条报文超过 MSS 触发 IP 分片或 TCP 层错误；T-GBT-071「MSS=100 报错」只覆盖 MSS 下限，未覆盖 CustomFields 与 MSS 关系。

**修复建议**：增加 V29 校验「len(CustomFields 解码) + 24 + 1 > spec.TCP.MSS 报错」（或 warning）；§8 增加「CustomFields 超 MSS-26」用例。

### H9. §7.11 多车场景 strategy_vin 概念字段与现有模式不符

**位置**：§7.11（第 864-895 行）。

**问题**：设计文档 §7.11 引入 `strategy_vin` / `strategy_sim` / `strategy_serial` / `reports_count` 概念性字段（第 884-888 行），并在第 895 行注释「上述 strategy_vin 等是概念性字段，实际多车生成由 core 层的 TupleGenerator + strategy_convert 处理」。但检索 `internal/core/strategy_convert.go` 显示现有协议（socks5/sip/rtsp 等）**没有** `strategy_*` 前缀的概念字段模式——多车生成靠 `tuples` 字段（TupleGenerator）+ 顶层 Config 字段（如 socks5 的 `socks5_dst_addr` 在 strategy 层用 pattern 策略）。

设计文档发明的 `strategy_vin` 命名与现有模式不一致，会让实现者困惑：到底是 planner 内部处理 strategy_vin，还是 strategy_convert 处理？

**依据**：`internal/core/strategy_convert.go`（无 strategy_* 前缀字段）；socks5 多车模式（靠 tuples + 顶层 socks5_dst_addr pattern 策略）。

**影响**：实现者可能错误地在 gbt32960 planner 内部解析 strategy_vin（违反「planner 只处理单车」原则）。

**修复建议**：
1. §7.11 删除 `strategy_vin` 等概念字段，改为「多车场景：用户在 strategy 层用 pattern 策略生成 M 条 FlowSpec，每条 FlowSpec 的 gbt32960.vin 字段由 pattern 填充」。
2. 给出与 socks5 一致的多车 Config 模板（顶层 `vin` 字段用 pattern 策略，无 strategy_ 前缀）。

## 4. MEDIUM 问题

### M1. §2.3 VIN 补齐字符 0x00 vs 0x20 规范未明确

**位置**：§2.3（第 102-105 行）+ §2.3 设计取舍注释。

**问题**：设计文档承认「GBT32960 规范对不足 17 字节如何补齐没有明确文字」，并称「工程实践中厂商普遍用 0x00」「Wireshark 解析器也按 0x00 处理」。但「厂商普遍」≠「规范规定」，且部分厂商可能用 0x20（空格）。设计文档未提供 Wireshark 解析器源码引用或厂商实例佐证。

**依据**：GB/T 32960.3-2016（未明确补齐字符）；CLAUDE.md §1「spec 驱动」要求标注规范条目。

**影响**：若实际目标平台按 0x20 补齐，生成的报文 VIN 字段解析错误。

**修复建议**：§2.3 增加「Config 字段 `VINPadByte`（默认 0x00，可选 0x20）允许用户选择补齐字符」；或明确「v1 固定 0x00，遇到 0x20 平台时再扩展」。

### M2. §3.1 登入时间 BCD 世纪处理与 LoginTime 时区含糊

**位置**：§3.1（第 147 行）+ §4.5（第 485 行）。

**问题**：§3.1 称「BCD 编码 YYMMDDHHMMSS，6 字节；例 2026-08-03 14:30:00 → 26 08 03 14 30 00」。§4.5 称「LoginTime 空 = time.Now()（UTC，转 BCD 时按北京时间 +8）」。

问题：
1. 设计文档未说明 LoginTime 字符串「2026-08-03 14:30:00」的时区——是 UTC 还是北京时间？若用户填北京时间但 planner 当 UTC 处理则 BCD 错误。
2. §4.5「time.Now() UTC 转 BCD 按北京时间 +8」逻辑含糊——time.Now() 返回 UTC，+8 后是北京时间，但若用户 LoginTime 字符串已经是北京时间，planner 不应再 +8。

**依据**：GB/T 32960.3-2016 时间定义（GMT+8）；CLAUDE.md §5「断言可观测」。

**影响**：用户填当地时间但被当 UTC，BCD 时间偏 8 小时；T-GBT-044「2026-08-03 14:30:00 → 26 08 03 14 30 00」不断言时区来源。

**修复建议**：
1. LoginTime 字符串要求带时区（RFC3339 强制 `+08:00` 或 `Z`）。
2. §4.5 改为「LoginTime 字符串时区即 BCD 时区；time.Now() 默认用本地时区（应文档化为北京时间）」。
3. T-GBT-044 增加时区断言。

### M3. §4.4 V8 AlarmFlags hex 长度范围与 V9 冗余

**位置**：§4.4 V8/V9（第 454-455 行）。

**问题**：V8 校验「AlarmFlags 非 1-8 位 hex 字符串」+ V9「AlarmFlags 解析后 > 0xFFFFFFFF」。V8 已限制 1-8 位 hex（最大 0xFFFFFFFF），V9 永远不会触发（8 位 hex 最大值就是 0xFFFFFFFF）。V9 是死代码。

更严重：1-3 位 hex（如 "1"）会被 V8 接受，但报警标志规范是固定 4 字节（8 位 hex），1-3 位 hex 生成的报文报警字段长度不是 4 字节。

**依据**：GB/T 32960.3-2016 报警标志固定 4 字节；CLAUDE.md §3「测试正确的 scope」。

**影响**：用户填 "1" 会通过 Validate 但生成 1 字节报警字段（应为 4 字节）。

**修复建议**：V8 改为「AlarmFlags 必须是恰好 8 位 hex」；删除 V9（或保留作防御性校验）。

### M4. §4.4 V12 LoginTime 格式校验不完整

**位置**：§4.4 V12（第 458 行）。

**问题**：V12 校验「LoginTime 非 RFC3339 / 非 YYYY-MM-DD HH:MM:SS 且非空」。但 RFC3339 要求时区后缀（`Z` 或 `+08:00`），「YYYY-MM-DD HH:MM:SS」无时区。两种格式同时接受会导致时区歧义（见 M2）。且 V12 未校验「YYYY-MM-DD HH:MM:SS」的月份 1-12、日 1-31 等范围（仅校验格式）。

**依据**：RFC 3339；CLAUDE.md §2「覆盖失败路径」。

**影响**：用户填「2026-13-45 25:61:61」通过格式校验但语义非法。

**修复建议**：V12 改为「统一用 RFC3339（强制时区），拒绝无时区的 YYYY-MM-DD HH:MM:SS；或两者都接受但 YYYY-MM-DD HH:MM:SS 默认北京时间」；增加 V12b 校验时间字段范围合法。

### M5. §4.4 V24 警告而非报错违反 fail-fast

**位置**：§4.4 V24（第 470 行）。

**问题**：V24「InjectBCCError=true 且 BCCErrorIndex 超出实际消息数 → warning only（在 Plan 阶段才知实际消息数；Validate 阶段跳过）」。这违反 CLAUDE.md §2「覆盖失败路径」与 §7「failing-test-first」——warning 会被用户忽略，但实际生成的 pcap 不含 BCC 错误，测试场景失败。

**依据**：CLAUDE.md §2 失败路径覆盖；§7 failing-test-first。

**影响**：T-GBT-004「InjectBCCError=true, index=999 断言不注入、不 panic」断言「不注入」但用户期望「注入」会得到静默失败。

**修复建议**：V24 改为「Plan 阶段检查 BCCErrorIndex 超出消息数 → 返回 error 中止生成」（或在 Validate 阶段预计算消息数）。T-GBT-004 改为「index=999 报错」。

### M6. §7.10 加密场景 EncryptRule=02/03 但不实际加密的 BCC 影响

**位置**：§7.10（第 844-860 行）。

**问题**：§7.10 称「planner 仅填充加密方式字段为 0x02/0x03，不实际加密——用户通过 custom_fields 提供已加密字节」「BCC 计算范围不变（仍覆盖加密方式字段 + 数据单元）」。

规范要求「先加密后校验」（web 来源：「当数据单元存在加密时，应先加密后校验；服务端平台接收时应先校验后解密」）。设计文档的做法（用户在外部加密后填入 custom_fields，planner 对已加密字节算 BCC）符合规范——但设计文档未明确说明「BCC 是对密文算还是明文算」。第 858 行「BCC 计算范围不变」可解读为「对 custom_fields（密文）算」，正确；但若实现者误以为「对明文算再加密」则错误。

**依据**：GB/T 32960.3-2016 加密与校验顺序。

**影响**：实现者可能先对明文算 BCC 再把 custom_fields 当密文写入，导致 BCC 与密文不匹配。

**修复建议**：§7.10 增加明确说明「BCC 始终对最终写入报文的数据单元字节（即 custom_fields 解码后的密文）计算，与 EncryptRule 无关」。

### M7. §7.12 StatusChangeTrace AtReportIndex 重复条目未定义

**位置**：§7.12（第 912-934 行）。

**问题**：§7.12 示例 status_change_trace 5 条目 AtReportIndex 分别 0/1/2/3/4（每个 index 一条）。但若用户配置两条 AtReportIndex=2（重复），设计文档未定义行为——是后一条覆盖前一条？还是合并？还是报错？

V25（第 471 行）只校验 AtReportIndex 越界，不校验重复。

**依据**：CLAUDE.md §2 失败路径覆盖。

**影响**：重复 AtReportIndex 行为未定义，实现者可能任选一种。

**修复建议**：V25 增加「AtReportIndex 重复 → 报错」或 §7.12 明确「后一条覆盖前一条」。

### M8. §8 测试用例缺「0x07 补发请求」「0x09 参数查询」「0x0A 参数设置」覆盖

**位置**：§8（第 996-1163 行）测试用例清单。

**问题**：§8 共 89 条用例，但**没有**针对 0x07 补发请求（平台→车辆）、0x09 参数查询、0x0A 参数设置的用例。设计文档 §3.7/3.9/3.10 定义了这三个命令的数据单元格式，但 §8 无对应测试。

**依据**：CLAUDE.md §1「spec 驱动——每个规范行至少一个测试」；§3「每个代码路径需有测试」。

**影响**：0x07/0x09/0x0A 实现后无测试覆盖，可能存在字段编码 bug。

**修复建议**：§8 增加T-GBT-090（0x07 补发请求时间格式）、T-GBT-091（0x09 参数查询）、T-GBT-092（0x0A 参数设置）用例。

### M9. §8 T-GBT-073 tshark 验证依赖 Wireshark 解析器准确性

**位置**：§8 T-GBT-073（第 1131 行）+ §10.5（第 1261-1269 行）。

**问题**：T-GBT-073「生成 pcap，tshark -V 解析无 Malformed 标记」。§10.5 引用「Wireshark 自带 gbt32960 解析器（epan/dissectors/packet-gbt32960.c）」。但 Wireshark 解析器本身可能存在 bug 或与规范不一致（设计文档 §2.3 第 105 行、§3.2.1 第 169 行多次引用 Wireshark 行为作为依据）。若 Wireshark 解析器按错误的位序理解报警标志（见 C7），则「无 Malformed」不等于「符合规范」。

**依据**：CLAUDE.md §8「adversarial review of test quality——green suite that tests the wrong things is worse than no tests」。

**影响**：T-GBT-073 可能给出虚假的「合规」信号。

**修复建议**：T-GBT-073 增加「同时用独立实现的 GBT32960 解析器（测试代码内）校验字段值，不仅依赖 tshark」。

## 5. LOW 问题

### L1. §1.2 与 SIP/RTSP 对比章节价值有限

**位置**：§1.2（第 32-34 行）。

**问题**：§1.2 称「GBT32960 与 SIP/RTSP 一样是单 TCP 流承载多消息的信令协议，但没有独立的 UDP 数据面」。这个对比对 GBT32960 实现无指导意义，且 SIP/RTSP 的 UDP 数据面是 RTP，GBT32960 无对应概念。

**依据**：CLAUDE.md「注释/格式建议」级别。

**影响**：无功能影响，仅文档冗余。

**修复建议**：可保留作为上下文，或删除。

### L2. §4.1 Config 字段注释风格不一致

**位置**：§4.1（第 274-376 行）。

**问题**：部分字段注释含「（中文）」解释（如 `VIN (车辆识别码, Vehicle Identification Number)`），部分字段无（如 `HeartbeatCount (心跳次数)`）。socks5.go 第 53-129 行常量注释风格统一用「英文 (中文)」格式。

**依据**：socks5.go 注释风格；MEMORY.md「gloss English terms」反馈。

**影响**：无功能影响，仅风格不一致。

**修复建议**：统一所有字段注释为「英文名 (中文, English expansion)」格式。

### L3. §6.3 伪代码 buf[2:] 切片风格与 socks5 不一致

**位置**：§6.3（第 643-655 行）。

**问题**：§6.3 伪代码用 `bccXOR(buf[2:])`，但 socks5.go 第 263-265 行用 `fmt.Sprintf` 风格生成 FlowID。伪代码风格与项目实际 Go 代码风格略有差异（如 `make([]byte, 0, 25+len(data))` 在项目代码中常见，但 `binary.BigEndian.AppendUint16` 是 Go 1.19+ API，需确认项目 Go 版本支持）。

**依据**：项目 Go 1.25（MEMORY.md「mcp-phase1」记录）。

**影响**：无功能影响，`binary.BigEndian.AppendUint16` 在 Go 1.19+ 可用，项目 Go 1.25 支持。

**修复建议**：无需修改，伪代码可读性可接受。

### L4. §9 审计清单与 §8 用例编号交叉引用不明确

**位置**：§9（第 1166-1228 行）。

**问题**：§9 审计清单引用「T-GBT-002」「T-GBT-054」等用例编号，但未明确「检查方法」列的用例是否覆盖该行所有风险。例如 §9.4「4-tuple 冲突 → T-GBT-059」但未标注「是否需新增 T-GBT-0XX 覆盖 planner 共享状态风险」。

**依据**：CLAUDE.md §8「adversarial review of test quality」。

**影响**：审计清单执行时可能遗漏未列出的风险点。

**修复建议**：§9 每行增加「覆盖用例」+「待补用例」两列。

### L5. §11 模板说明章节对 GBT32960 审计无直接价值

**位置**：§11（第 1285-1373 行）。

**问题**：§11 是给后续 JT808/JT809/JTT905 协议设计者的模板说明，对 GBT32960 本身的审计无直接价值。但其中提到「JT808 转义是最大实现风险」「JT809 双流模型」等，这些信息在 GBT32960 实现时不需考虑。

**依据**：CLAUDE.md「注释/格式建议」级别。

**影响**：无功能影响。

**修复建议**：可保留作为后续协议模板参考。

### L6. 附录 D 修订历史仅一行

**位置**：附录 D（第 1517-1520 行）。

**问题**：修订历史仅「v1.0 初稿」一行，无审计后修订记录。

**依据**：文档规范。

**影响**：无功能影响。

**修复建议**：审计后增加 v1.1 修订记录。

## 6. 测试用例质量审计（按 CLAUDE.md §1-§8 逐条）

### §1 Spec 驱动测试推导

**评价：FAIL**

设计文档 §8 共 89 条用例，但大量用例基于**错误的 spec**（C1/C2/C3/C7/C8）。例如：
- T-GBT-007「0x01 数据单元 46 字节 = 6 时间 + 20 SIM + 20 序列号」——基于 C1 错误格式（实际应为 6+2+20+1+1+n×m）。
- T-GBT-008「0x02 数据单元 ≥14 字节 = 6 时间 + 2 流水号 + 4 报警 + 2 状态 + 子项」——基于 C2 错误格式（实际应为 6 + 信息类型循环）。
- T-GBT-038「80000000 → 电池高温」——基于 C7 错误位定义（实际 bit1=电池高温）。

设计文档未引用 GB/T 32960.3-2016 具体表号（如表 7、表 8、表 14），无法溯源每条用例的规范依据。违反 CLAUDE.md §1「每条用例对应规范具体行」。

### §2 失败路径覆盖

**评价：PARTIAL**

负向用例覆盖较好（V1-V27 大部分有对应负向用例），但缺：
- 0x07/0x09/0x0A 命令的负向用例（见 M8）。
- 加密方式 0x04/0x05（SM2/SM4）的负向用例（设计文档未定义这些枚举值，见加密方式枚举 MEDIUM 问题）。
- VIN 含 I/O/Q 字符的负向用例（见 H1）。
- 数据单元长度 > 65531 的负向用例（见 H3）。
- CustomFields + MSS 关系的负向用例（见 H8）。

### §3 测试正确的 scope——每个代码路径一个测试

**评价：PARTIAL**

- BCC 算法有独立测试（T-GBT-002），符合 §3。
- 但 0x07/0x09/0x0A 命令无任何测试（见 M8），代码路径未覆盖。
- V24（BCCErrorIndex 越界）是 warning 而非 error（见 M5），测试断言「不注入、不 panic」是测试 warning 路径而非 error 路径。

### §4 集成测试

**评价：PASS**

T-GBT-069/070/073 是端到端集成测试（TCP 握手 + GBT32960 + 挥手 + tshark 验证），符合 §4。多车场景 T-GBT-057~060 也覆盖了多 FlowSpec 集成。

### §5 断言可观测

**评价：FAIL**

- T-GBT-007「断言数据单元 46 字节」——结构断言非值断言（且 46 字节本身错误，见 C1）。
- T-GBT-008「断言数据单元 ≥14 字节」——结构断言，未断言具体字段值。
- T-GBT-044「断言 6 字节 BCD 合法」——「合法」未定义具体值。
- T-GBT-049「断言时间分别为 LoginTime+30/60/90s」——不断言 BCD 编码字节值，仅断言时间戳语义。

违反 CLAUDE.md §5「断言输出值和可观测行为，非结构存在」。

### §6 并发测试正确性

**评价：PARTIAL**

- T-GBT-059「100 辆车并发，断言无 4-tuple 重复」覆盖并发场景。
- 但未测量「100 辆车的实际总吞吐 vs 配置 rate」（CLAUDE.md §6 要求）。
- §9.4 提到「planner 共享状态导致并发污染」风险，但 T-GBT-058 仅测 2 车 VIN 不同，未测「100 车 -race 是否 clean」。

### §7 Failing-test-first

**评价：FAIL**

设计文档 §8 是测试用例清单，无任何「先写失败测试再修复」的记录。§7.15 BCC 错误注入场景描述了 bug fix 语义（「测试接收端对 BCC 校验失败报文的处理」），但未标注「failing-test-first」。

### §8 Adversarial review of test quality

**评价：FAIL（本审计即是对抗审查）**

本审计发现 32 个问题，其中 8 个 CRITICAL（基于错误 spec 写用例）。设计文档 §9 自审清单（第 1166-1228 行）覆盖了部分风险（BCC 范围、VIN 补齐、状态机 ACK），但**未发现** C1-C8 这些 spec 一致性 CRITICAL 问题。§9 自审清单局限于「实现易错点」，未对抗「spec 理解错误」。

## 7. 字段覆盖率审计

### 7.1 扩展表 1 (gbt32960ProtocolLog) 字段 vs Config 字段对照表

| 扩展表字段 | 中文 | Config 字段 | 类型 | 状态 |
|---|---|---|---|---|
| connectId | 连接 ID | — | — | **缺失** |
| procedureType | 流程类型 | `Role` | string | 部分覆盖（vehicle/platform 二选一，扩展表可能含更多值） |
| vehicleLoginTime | 车辆登入时间 | `LoginTime` | string | 已覆盖 |
| loginSerialNumber | 登入流水号 | `VehicleLoginSerial` | string | **语义错**（应为 uint16，见 C1） |
| vehicleLoginoutTime | 车辆登出时间 | `LogoutTime` | string | 已覆盖 |
| loginoutSerialNumber | 登出流水号 | — | — | **缺失** |
| encryptionRule | 加密规则 | `EncryptRule` | string | 已覆盖（但枚举不全，缺 0x04/0x05） |
| platformDomain | 平台域名 | — | — | **缺失** |
| setPlatformDomain | 设置平台域名 | — | — | **缺失** |
| statusChangeTrace | 状态变更记录 | `StatusChangeTrace` | []GBT32960StatusChange | 已覆盖（但语义错，见 C8） |
| maxAlarmLevel | 最高报警等级 | — | — | **缺失** |
| alarmFlags | 通用报警标志 | `AlarmFlags` | string | 已覆盖（但位定义错，见 C7） |
| isTransBatteryData | 是否传输电池数据 | — | — | **缺失** |

### 7.2 缺失字段汇总

**缺失 6 个**：connectId / loginoutSerialNumber / platformDomain / setPlatformDomain / maxAlarmLevel / isTransBatteryData

**语义错 2 个**：loginSerialNumber（string 应为 uint16）/ statusChangeTrace（基于错误的状态标志位定义）

**枚举不全 1 个**：encryptionRule（缺 0x04 SM2 / 0x05 SM4）

## 8. 多车场景正确性

### 8.1 4-tuple 分配

**评价：基本正确**

§7.11 表格（第 899-904 行）给出 100 辆车的 4-tuple 分配：src_ip 固定 10.0.0.1、dst_ip 固定 10.1.1.1、src_port 20000-20099 递增、dst_port 10020 固定。这与 socks5 多车模式一致（tuples strategy + src_port inc）。

**风险**：src_port 范围 20000-29999 共 10000 个端口，若 M > 10000 则端口回绕，可能产生 4-tuple 冲突。设计文档未说明回绕行为。

### 8.2 VIN/SIM/序列号唯一性

**评价：VIN 唯一性机制错误**

§7.11 第 884 行 `strategy_vin` 用 pattern `LVEH{n:017d}` 生成 VIN，n_range [1, 1000]。但：
1. `LVEH{n:017d}` 生成 17 字节 VIN（LVEH 4 字节 + n 13 字节零填充），但 VIN 字符集不含 I/O/Q（见 H1），`LVEH` 含 V/E/H 合法但需校验。
2. n_range [1, 1000] 仅 1000 个唯一 VIN，但 flows.count=100，足够；若 count > 1000 则 VIN 重复。
3. 设计文档第 907 行「每条流的 VIN 必须唯一」未说明 planner 如何检测重复（planner 只处理单车，VIN 重复检测应在 strategy 层或 task 层）。

**SIM 唯一性**：`strategy_sim` pattern `1380013{n:04d}` n_range [0, 9999]，最多 10000 个唯一 SIM，足够。

**序列号唯一性**：`strategy_serial` inc [1, 99999]，但这是「车辆登入序列号」（语义错，见 C1），实际规范登入流水号是 2B WORD，每日 00:00 归 0，跨车无需唯一（每车独立计数）。

### 8.3 GroupID 路由

**评价：缺失**

§7.11 未提及 GroupID。GBT32960 单流协议，每条 FlowSpec 是独立 TCP 流，无需 GroupID 路由（与 socks5 一致）。但若用户希望「同一辆车的登入+上报+登出保序」，则需 GroupID——设计文档未说明。

socks5.go 第 513-520 行 `groupIDMeta` 函数处理 GroupID，GBT32960 planner 应复用此模式。设计文档 §10.1 第 1240 行仅说「新增字段 GBT32960 *GBT32960Config」，未提及 GroupID 集成。

**修复建议**：§7.11 增加「多车场景每条 FlowSpec 独立 GroupID（或无 GroupID，由 4-tuple 哈希路由）」。

## 9. 集成点审计

### 9.1 types.go 新增字段

**评价：基本正确**

§10.1（第 1234-1241 行）称「在 types.go FlowSpec struct 中新增 `GBT32960 *GBT32960Config`，位置约第 210 行 Socks 之后」。检索 types.go 第 210 行确认为 `Socks *SocksConfig`，新增 GBT32960 字段位置合理。

**风险**：types.go 第 178-219 行注释明确「L7 protocol configurations (phase 3 batch). Appended at end per flowspec_extension.md §2.3 to avoid touching existing field layout」——新增字段应追加在末尾（第 219 行 WireGuard 之后），而非「Socks 之后」（第 210 行）。设计文档 §10.1 位置描述可能误导实现者插入中间。

**修复建议**：§10.1 改为「追加在 FlowSpec 末尾（WireGuard 之后），与 phase 3 batch 字段风格一致」。

### 9.2 strategy_convert.go 新增 case

**评价：部分正确**

§10.3 称「strategy_convert.go 新增 GBT32960 的 strategy 处理：支持 vin/sim/vehicle_login_serial 字段使用 pattern/inc/list 策略」。但检索 strategy_convert.go 第 734-743 行 socks5 case 显示：socks5 **没有**独立的 strategy 字段处理，多车生成靠通用 tuples strategy + 顶层 Config 字段（如 socks5_dst_addr 在 strategy 层用 pattern）。

设计文档 §10.3 描述的「vin/sim/vehicle_login_serial 字段使用 pattern/inc/list 策略」与现有模式不一致——现有模式是顶层 Config 字段直接用 strategy_config，无需 strategy_convert 特殊处理。

**修复建议**：§10.3 改为「GBT32960 字段（vin/sim 等）作为顶层 Config 字段，由 strategy 层通用 pattern/inc 策略处理，strategy_convert.go 仅新增 case 'gbt32960' 解析 sub-map 并填充默认端口 10020」。

### 9.3 main.go 注册顺序

**评价：正确**

§10.4 称「gbt32960.NewPlanner().Register(registry)」。检索 main.go 第 378 行 `app.engine.RegisterPlanner(socks5.NewPlanner())` 确认注册模式。GBT32960 注册应追加在 main.go 第 385 行 xmpp 之后（或按字母序插入）。

**风险**：§10.4 写「`gbt32960.NewPlanner().Register(registry)`」但 main.go 用 `app.engine.RegisterPlanner(socks5.NewPlanner())`（方法名 `RegisterPlanner` 不是 `Register`）。设计文档伪代码与实际 API 不符。

**修复建议**：§10.4 改为 `app.engine.RegisterPlanner(gbt32960.NewPlanner())`。

### 9.4 与现有协议互斥规则

**评价：缺失**

设计文档未说明「同一 FlowSpec 不能同时 GBT32960 + JT808」或「GBT32960 + Socks」的互斥规则。检索 convert.go 第 127-130 行显示现有协议互斥表（`"mpls": true, "gtp": true, "socks5": true, ...`），GBT32960 应加入此表。

**修复建议**：§10.2 增加「GBT32960 加入 convert.go 协议互斥表，与 socks5/sip/rtsp 等互斥」。

### 9.5 默认端口填充

**评价：正确**

§10.2 称「默认端口 10020 在 mapToFlowSpec 处填充（与 socks5 的 1080 一致）」。检索 strategy_convert.go 第 738-743 行 socks5 默认端口填充模式（`if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil { spec.DstPort = 1080 }`），GBT32960 应复用此模式填 10020。

## 10. 总体评分

### PASS WITH FIXES（重大修复后可通过）

**理由**：

设计文档结构完整（11 章 + 4 附录，1523 行），状态机、Config 字段、测试用例数量（89 条）、集成点描述均达到设计文档基线。BCC 校验范围、起始符、命令单元头部骨架与规范一致。

但存在 **8 个 CRITICAL 问题**，其中 C1/C2/C3/C7/C8 是 spec 一致性硬伤——0x01/0x02/0x04 数据单元格式与 GB/T 32960.3-2016 完全不符，C7 报警标志位定义与规范相反，C5 应答标志 0xFE 语义错误。按设计文档实现的代码生成的报文将被 Wireshark 标记为 Malformed，且无法被真实 GBT32960 平台解析。

**修复优先级**：
1. **P0（必须修复，阻塞实现）**：C1, C2, C3, C4, C5, C6, C7, C8——重新核实 GB/T 32960.3-2016 原文，重写 §3 命令单元数据单元格式、§1.4 应答标志语义、§3.2.1 报警标志位定义。
2. **P1（实现前修复）**：H1-H9——VIN 字符集校验、BCC 边界、数据长度上限、状态机分支、Config 字段补全、ACK 模式、MSS 约束、多车 strategy 字段。
3. **P2（实现中修复）**：M1-M9——VIN 补齐字符、时区、Validate 规则、测试用例补全。
4. **P3（可选修复）**：L1-L6——文档风格。

**建议**：设计文档 v1.1 应基于 GB/T 32960.3-2016 原文（非 web 二手来源）重写 §3 章节，并补充每个命令的规范条目引用（表号）。在 spec 一致性确认前，不建议开始代码实现。

---

## 三轮审计 v1.1.2（2026-08-03）

### 审计概览

- **审计对象**：`/home/weihang/trafficGenerator/docs/protocol-designs/01-gbt32960-design.md` v1.1.2（约 1938 行，123 条测试用例）
- **审计方法**：六维对抗式审计（spec 一致性 / 扩展字段 / 状态机 / 多终端 / 测试质量 / 常见陷阱），逐节交叉验证 v1.1.0→v1.1.1→v1.1.2 的 51 个已修复项是否真修复，以及是否引入新问题
- **审计工具**：Read / Grep / Bash（未运行 go build/test）
- **发现新问题总数**：**11 个**（1 CRITICAL + 4 HIGH + 4 MEDIUM + 2 LOW）

### CRITICAL（1 项）

#### C1-2026-08-03｜§3.12 / §1.4 / §5.3：0x0C 报文头应答标志恒 0xFE 与 GB/T 32960.3-2016 §7.8 应答机制存在潜在冲突

- **位置**：§3.12（第 344-356 行）、§1.4（第 59-80 行）、§5.3（第 761-769 行）
- **描述**：设计文档反复强调 0x0C 平台确认报文**报文头应答标志字段恒填 0xFE**（line 346「恒填 0xFE」、line 351「恒 0xFE」、line 356「恒 0xFE」），并认为成功/失败语义通过「下一上行报文」的应答标志字段承载。然而 GB/T 32960.3-2016 §7.8 规定的平台确认应答**明确要求**响应标志字段承载处理结果（0x01 成功 / 0x02 错误 / 0x03 VIN 重复 / 0x04 命令不支持）。设计 v1 简化方案（§3.12 line 353「也可通过独立应答报文承载」）可能与真实终端/平台互通时产生不一致——接收端若按规范解析 0x0C 报文头应答标志字段（期望 0x01-0x04），会因读到 0xFE 而判定为「不应答」（spec 原意）。该问题在 v1.1.2 H5 修复时未被审计触及——H5 仅清理了 0x0C **数据单元**是否承载成功/失败的歧义，但未触及 0x0C **报文头**应答标志是否承载应答结果的规范要求。
- **依据**：GB/T 32960.3-2016 §7.8「平台确认」应答机制；§3.12 line 346、351、356；§1.4 line 108 表注「下行 0x0C 报文头应答标志也恒 0xFE」
- **建议**：核实 GB/T 32960.3-2016 §7.8 原文对 0x0C 报文头应答标志字段的具体规定：
  - 若规范明确 0x0C 报文头应答标志可填 0xFE（无需应答）或 0x01-0x04（应答结果），则保留当前设计并在 §3.12 补充「也可承载应答结果」选项，由 Config 字段 `PlatformAckResponseFlags` 控制（v1 默认 0xFE 简化，v2 实现规范完整路径）
  - 若规范强制 0x0C 报文头应答标志承载 0x01-0x04，则当前设计错误，需把 `ResponseFlags` 从「下一上行报文 resp」改为「0x0C 报文头 resp」，并修改 T-GBT-015~018 断言
- **审计状态**：需规范原文确认后方可定性，建议**暂缓进入实现阶段**直至澄清

### HIGH（4 项）

#### H1-2026-08-03｜§7.1 hex 示例：VIN 字段字节数错误（19B vs 17B）

- **位置**：§7.1（第 856-874 行）
- **描述**：§7.1 hex 注释写明 VIN=「LXXXXXXXXXXXXXXX1」17 字节，但 hex dump 在 line 862-863 给出 `4C 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 31`，实际为 **19 字节**（L + 17 个 0x58 + 0x31），比规范多 2 个 X。多出的 2 字节会导致后续偏移全部错位：`加密方式 01` 实际落在偏移 21 而非规范要求的 21（巧合相等），但 `数据长度 00 1F` 落在偏移 22-23 而非规范的 22-23，`登入时间 BCD` 落在偏移 24 而非规范的 24（再次巧合），但总报文长实际为 56+2=58 字节而非规范 56 字节，BCC 范围错误覆盖 `bytes 2..56` 而非规范的 `bytes 2..54`。
- **依据**：§2.1 报文格式表（VIN 17B）；§7.1 line 856 注释自述「17 字节」；line 862-863 hex 实际为 19 字节
- **建议**：line 862-863 hex 修正为 17 字节（`4C 58 58 58 58 58 58 58 58 58 58 58 58 58 58 31`，即 L + 15 个 0x58 + 0x31）；同步检查 B.1 附录 hex（第 1717-1718 行，同样 18 字节）是否也有类似错误
- **关联问题**：M1-2026-08-03（B.1 VIN hex 18B vs 17B）

#### H2-2026-08-03｜§4.5 / §7.2 / T-GBT-048：LogoutTime 默认公式三处不一致

- **位置**：§4.5（第 652 行）、§7.2（第 897-904 行）、T-GBT-048（第 1293 行）
- **描述**：LogoutTime 默认公式出现 3 种不同表述：
  - §4.5 line 652：`LoginTime + Σ(Reports 间隔) + 60s`
  - §7.2 line 904：「Reports 结束后 +30s 默认」（即 14:32:00 = 14:31:30 + 30s）
  - T-GBT-048 line 1293：`LoginTime + 30s×N + 60s`（N=Reports 数）
  
  以 §7.2 配置（LoginTime=14:30:00, N=3 Reports, 间隔 30s）为例：
  - §4.5 公式：14:30:00 + 90s + 60s = **14:32:30**
  - §7.2 注释：14:31:30 + 30s = **14:32:00**
  - T-GBT-048 公式：14:30:00 + 30×3 + 60s = **14:32:30**
  
  同一输入得到 2 个不同输出。§4.5 与 T-GBT-048 一致（14:32:30），但 §7.2 与 Config 实际值（line 950 `"logout_time": "2026-08-03T14:32:00+08:00"`）一致（14:32:00），说明 §7.2 是「user override」或「Reports 结束后 +30s」的特例路径，与 §4.5 默认公式相矛盾。
- **依据**：§4.5 line 652；§7.2 line 904 注释 + line 950 Config 值；T-GBT-048 line 1293
- **建议**：明确文档：
  - 若 LogoutTime 默认 = LoginTime + 30s×N + 60s（即 §4.5/T-GBT-048 公式），则 §7.2 应改为 LogoutTime=14:32:30 + 对应 Config 值
  - 若 §7.2 是「Reports 结束后 +30s」（=Last Report Time + 30s），则 §4.5/T-GBT-048 公式需修改为 `Last Report Time + 30s`
  
  两种语义不同：前者从 LoginTime 累计，后者从最后一条 Report 累计。建议统一为 `Last Report Time + 30s`（更符合真实终端行为：Reports 全部完成后再等 30s 登出），同步更新 §4.5/T-GBT-048/T-GBT-049 三处

#### H3-2026-08-03｜V29 / §6.2：MSS 校验公式遗漏 6 字节采集时间

- **位置**：§4.4 V29（第 629 行）、§6.2（第 808 行）、T-GBT-103（第 1405 行）
- **描述**：V29 公式写 `len(CustomFields 解码) + 24 + 1 > spec.TCP.MSS`（即 CustomFields ≤ MSS-25）。但 §6.2 line 808 自述「约束 CustomFields 长度 ≤ MSS-26」。两者公式差 1 字节。结合 §6.2 line 805「数据单元前 (MSS-24) 字节」的描述：
  - 0x02 数据单元 = 6 字节采集时间 + Σ(信息类型 1B + 信息体 nB)
  - 若 CustomFields 包含 0x05 车辆位置（9B），则数据单元 = 6 + 1 + 9 = 16 字节
  - 报文头 = 起始符(2) + cmd(1) + resp(1) + VIN(17) + enc(1) + len(2) = 24 字节
  - 报文总长 = 24 + 16 + BCC(1) = 41 字节，远小于 MSS 1460
  
  V29 的 `(CustomFields + 24 + 1)` 中「24」是报文头 + BCC(1) = 25，但未包含采集时间(6)。正确公式应为 `6 + len(CustomFields) + 24 + 1 > MSS`（即 6 采集时间 + CustomFields + 报文头 + BCC），或 `CustomFields ≤ MSS - 31`（即 MSS-24-6-1）。当前 V29 实际是 `CustomFields ≤ MSS - 25`，**允许 CustomFields 上限过大 6 字节**（MSS-25 vs 正确值 MSS-31）。
- **依据**：§3.2 数据单元格式（采集时间 6B）；§4.4 V29 line 629；§6.2 line 808；§6.2 line 805
- **建议**：V29 公式修改为 `len(CustomFields 解码) + 6 + 24 + 1 > spec.TCP.MSS`（CustomFields + 采集时间 + 报文头 + BCC 总和 > MSS），错误消息改为 `CustomFields length %d exceeds MSS-31 budget %d`；§6.2 line 808 同步改为 `≤ MSS-31`；T-GBT-103 边界值由 1436 改为 1430

#### H4-2026-08-03｜T-GBT-081：补报流水号不连续用例引用不存在的字段

- **位置**：§8.14 T-GBT-081（第 1363 行）
- **描述**：T-GBT-081 描述「ReissueReports 流水号 100/101/102，与 Reports 的 1/2/3 不连续」，但 GBT32960Report struct（§4.2 第 533-544 行）**无 Serial 字段**——只有 Time / AlarmData / CustomFields 三个字段。§4.1 line 441-444 注释也明确「The Serial field is kept for backward compat but only used for V14 range check (1-65531)」，但 GBT32960Report struct 实际并未定义 Serial 字段。该用例无法在 Go 代码中直接编写（无 Config 字段可设置）。
- **依据**：§4.2 GBT32960Report 定义（无 Serial 字段）；§8.14 T-GBT-081 line 1363
- **建议**：选项 A：在 GBT32960Report 中新增 `Serial int` 字段（json tag `serial,omitempty`，omitempty 保证 0 不写入），写入 0x02/0x03 数据单元**前**作为可选 2 字节（与 §3.2 line 187 数据单元格式表新增一列「可选流水号」），由 Config 控制是否启用。选项 B：删除 T-GBT-081 用例或修改为「ReissueReports Time 不连续」（基于已有 Time 字段）。推荐选项 B——0x02 数据单元规范无独立流水号字段（H2 v1.1.0 修复已确认），补报场景同样无流水号字段，强行新增字段违反 spec

### MEDIUM（4 项）

#### M1-2026-08-03｜附录 B.1：B.1 VIN hex 字节数错误（18B vs 17B）

- **位置**：附录 B.1（第 1717-1718 行）
- **描述**：B.1 line 1717 VIN hex 为 `4C 58 58 58 58 58 58 58 58 58 58 58 58 58 58`（15 字节），line 1718 续 `58 58 31`（3 字节），合计 **18 字节**（L + 16 个 0x58 + 0x31），比规范多 1 字节。与 H1 §7.1 的 19 字节问题类似但偏移错位不同。
- **依据**：附录 B.1 line 1717-1718
- **建议**：B.1 line 1717 改为 14 个 0x58（`4C 58 58 58 58 58 58 58 58 58 58 58 58 58`），line 1718 续 `58 58 31`（3 字节），合计 17 字节（L + 15 个 0x58 + 0x31）

#### M2-2026-08-03｜§4.4：缺少 LogoutTime ≥ LoginTime 验证

- **位置**：§4.4 V12-V13（第 611-613 行）
- **描述**：§4.4 验证规则仅校验 LoginTime/LogoutTime 的 RFC3339 格式（V12/V13）和时间字段范围（V12b），但**未校验** LogoutTime ≥ LoginTime（LogoutTime 早于 LoginTime 在语义上无效——车辆必须先登入才能登出）。T-GBT-080 校验 ReissueReports[0].Time < LoginTime（补报时间早于登入），但未校验 LogoutTime < LoginTime。
- **依据**：§4.4 V12-V13；§8.10 T-GBT-080；§5.1 状态机（ST_LOGIN_SENT → ... → ST_LOGOUT_SENT 顺序）
- **建议**：新增 V34 校验：`LogoutTime < LoginTime`（LogoutTime 非空且早于 LoginTime）时报错 `gbt32960: LogoutTime %q is earlier than LoginTime %q`；新增 T-GBT-109 用例负向验证

#### M3-2026-08-03｜§6.2 / §4.4 V29：MSS 约束表述「MSS-26」与 V29 公式「MSS-25」不一致

- **位置**：§6.2 line 808 vs §4.4 V29 line 629
- **描述**：§6.2 line 808 写「约束 CustomFields 长度 ≤ MSS-26，由 Validate 检查」，§4.4 V29 line 629 公式是 `CustomFields ≤ MSS-25`。同一约束在两处表述差 1 字节。结合 H3（遗漏 6 字节采集时间），正确值应为 MSS-31，但至少 §6.2/V29 内部应统一。
- **依据**：§6.2 line 808；§4.4 V29 line 629
- **建议**：统一为 `CustomFields ≤ MSS-31`（含采集时间 6B + 报文头 24B + BCC 1B）；§6.2 与 V29 同步更新；参见 H3 修复方案

#### M4-2026-08-03｜§5.1：状态机图中 ST_REPORTING → ST_REMOTE_CTRL 与 ST_REISSUE 的顺序关系未明确

- **位置**：§5.1 状态机图（第 680-716 行）、§5.1 状态转换说明 3-4（第 722-723 行）
- **描述**：状态机图（line 691-705）将 ST_REPORTING、ST_REMOTE_CTRL、ST_REISSUE 三个状态分别绘制为 ST_LOGIN_ACKED 之后的分支，但**未明确画出** ST_REPORTING → ST_REMOTE_CTRL → ST_REISSUE → ST_LOGOUT_SENT 的顺序连线（即 ST_REMOTE_CTRL 与 ST_REISSUE 的先后顺序）。line 722-723 文字说明两者均由 ST_REPORTING 出发，但未说明 ST_REMOTE_CTRL 与 ST_REISSUE 之间的相对顺序。Config 字段 `RemoteControl.AtReportIndex` 仅控制 ST_REPORTING 内部的 RemoteControl 插入位置，不解决 ST_REPORTING 完成后 ST_REMOTE_CTRL（末尾插入）与 ST_REISSUE 之间的顺序歧义。
- **依据**：§5.1 line 691-705 状态机图；line 722-723 文字说明
- **建议**：在状态机图中补充箭头：`ST_REPORTING → ST_REMOTE_CTRL → ST_REISSUE → ST_LOGOUT_SENT`；或明确文档「ST_REMOTE_CTRL 在 ST_REISSUE 之前」（两者均可选但顺序固定）；新增 T-GBT-110 用例验证顺序

### LOW（2 项）

#### L1-2026-08-03｜§4.1 line 441-444：GBT32960Report 注释「Serial field is kept」与 struct 定义不符

- **位置**：§4.1 Reports 注释（第 441-444 行）
- **描述**：注释写「The Serial field is kept for backward compat but only used for V14 range check (1-65531)」，但 §4.2 GBT32960Report struct 定义（第 533-544 行）**未包含** Serial 字段——只有 Time / AlarmData / CustomFields 三个字段。该注释与代码脱节，开发者按注释实现会出现「field not found」编译错误。V14 已弱化（line 614「已弱化：0x02 数据单元无独立流水号字段」），无 Serial 校验需求，注释应同步删除或修正。
- **依据**：§4.1 line 441-444；§4.2 line 533-544；§4.4 V14 line 614
- **建议**：删除 line 441-444 的「Serial field is kept for backward compat」整段注释（V14 已弱化，无用途）；或改为 `// 0x02 has no per-report serial field in spec — see §3.2 data unit format`

#### L2-2026-08-03｜§4.4：缺少 RechargeableSubsysCodeLength < 1 验证

- **位置**：§4.1 第 419-421 行（字段定义）、§4.4 V30/V31（第 630-631 行）
- **描述**：§4.1 注释说明 `RechargeableSubsysCodeLength m ≥ 1`（line 419），§4.4 V30 校验 RechargeableSubsysCount ≥ 1，V31 校验 Codes 长度 == Count，但**未校验** RechargeableSubsysCodeLength ≥ 1。若用户配置 `rechargeable_subsys_code_length=0`，planner 写入 0 字节编码导致 SubsysCode 字段缺失——与 V31 校验耦合（Codes 数组的字符串长度检查可能通过，但 m=0 会使整段编码为空）。规范要求 m ≥ 1（GB/T 32960.3-2016 §6.1 车辆登入数据单元）。
- **依据**：§4.1 line 419-421 字段定义；§4.4 V30/V31；GB/T 32960.3-2016 §6.1
- **建议**：新增 V30b 校验：`RechargeableSubsysCodeLength < 1` 报错 `gbt32960: RechargeableSubsysCodeLength %d must be >= 1`；新增 T-GBT-110 负向用例验证

### 审计结论

- **新发现 11 个问题**（1 CRITICAL + 4 HIGH + 4 MEDIUM + 2 LOW），其中：
  - **C1-2026-08-03**（0x0C 报文头应答标志与 GB/T 32960.3-2016 §7.8 规范一致性）是唯一 CRITICAL 问题，需核实规范原文后方可定性。该问题在 v1.1.0/v1.1.1/v1.1.2 三轮审计中均未触及，是设计「简化」与「规范完整性」的潜在冲突点
  - **H1-H4** 均为可量化错误（hex 字节数错位、公式不一致、字段引用不存在、公式遗漏），影响实现正确性或测试可执行性
  - **M1-M4 / L1-L2** 为风格/完整性问题，可在实现时一并修复
- **v1.1.2 历史修复**：14/14 项修复均正确应用（通过 1938 行全文逐节比对 + hex dump 验证 + 状态机图对照 + 测试用例交叉引用确认），未发现 v1.1.2 修复引入回归
- **是否可进入实现阶段**：**暂缓**。需先澄清 C1（0x0C 报文头应答标志规范要求）后方可进入实现；H1-H4 建议在澄清 C1 后**同步修复**（属于 hex/公式/字段引用错误，修复成本低且影响 spec 一致性）；M/L 项可在实现 PR 中一并修复
- **建议的下一步**：
  1. 核实 GB/T 32960.3-2016 §7.8 原文对 0x0C 报文头应答标志字段的具体规定
  2. 根据核实结果修改 §3.12 / §1.4 / §5.3，澄清 0x0C 应答机制
  3. 同步修复 H1-H4 / M1-M4 / L1-L2（共 10 项）
  4. 修复后更新附录 D 修订记录为 v1.1.3，再进入实现阶段

---

（审计报告结束，累计三轮共 65 个问题：11 CRITICAL + 18 HIGH + 17 MEDIUM + 19 LOW）

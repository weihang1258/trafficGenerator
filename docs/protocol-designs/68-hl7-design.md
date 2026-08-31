# HL7 v2.x over MLLP（医疗信息交换标准 / 最小下层协议）设计契约

> 版本：v2.0.1（设计阶段）
> 日期：2026-09-01
> 状态：**尚未实现**；本文定义实现后的 PCAP（抓包文件）断言，不宣称当前测试套件可运行，不修改 Go（编程语言）/MCP（模型上下文协议）实现。**独立隔离对抗审查已完成**（v2.0.1 定稿：独立审查 agent 三向审计 12 项清单（1C/3M/8N）→ 修复 → 复验 clean，含二轮复验；审查/修复记录见 §10）。
> 配套文件：`docs/protocol-designs/68-hl7-testcase.md`、`trafficgen/test/protocol_pcap/cases/hl7.json`
> 规范基线：HL7 v2.x 官方标准（HL7.org，v2.5/v2.8 公开文档，本章节按 v2.x 通用章节口径引用）；MLLP（Minimal Lower Layer Protocol，最小下层协议，HL7 附录/实施指南的 LLP 封装）；IANA 服务端口登记 hl7 = TCP 2575。tshark 断言字段以本机 3.6.14 `-G fields`/`-G decodes` 实测为准（§3.9）。

## 1. 范围、profile 和未注册边界

本版定义 HL7 v2.x 消息经 **MLLP** 封装、以 **TCP 字节流**为载体的线格式与事务模型：HL7 消息 = 段序列（**MSH 必为首段**）；段 = 字段（`|` 分隔，MSH 段特殊）；字段 = 组件（`^`）、重复（`~`）、子组件（`&`）；转义（`\F\`、`\S\`、`\R\`、`\E\`、`\T\`、`\H\`、`\N\`、`\Xdd..\` 等）。MLLP 帧 = `0x0b`（VT 起始块）+ 消息字节 + `0x1c 0x0d`（FS CR 结束块）。消息类型覆盖现网常用：**ADT^A01/A02/A03**（入院/转科/出院）、**ORU^R01**（检验结果上传）、**SIU^S12**（预约）、**ACK/NAK**（确认，MSA 段）。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `mllp`（主 profile） | TCP / 2575，IPv4+IPv6 | MSH/EVN/PID/PV1/SCH/AIS/OBR/OBX/MSA/ERR 段、ACK/NAK 确认流、MLLP 封装、消息→ACK 配对、多消息长连接 | 患者真实存在、临床结果正确、身份认证成功、医学业务处理成功 |

显式边界（均"不实现、不声称、不许静默转换"）：UDP/串口/MLLP 之外的载体本版不支持（负例 `hl7_neg_transport_port`）；HL7 批量文件（batch，FHS/BHS 外层）本版不展开；HL7 增强确认模式（MSH-15/16 组合声明的 Commit Accept/Application 两级确认 CA/CE/CR）本版不展开——统一按**原确认模式**（Original Mode）单级 ACK，MSA-1 ∈ {`AA`,`AE`,`AR`}；TLS/TCP 加密载体（HL7 over TLS）不在本版；Z 段（厂商扩展段）按显式配置透传、不由 profile 自动生成。**流关联显式不适用**（理由见 §4 五层覆盖结论）；**并发会话（`concurrent: true`）本版不适用**——MLLP 连接本身单消息串行确认，双连接用多会话展开表达（§5）。

当前仓库没有注册 `hl7` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/hl7.json` 只保留一个不计入语义 ID 的注册前置占位 `hl7_neg_unregistered`（已实测：`proto=hl7`、层链 `[{"tcp":{}},{"hl7":{}}]`、`expect_error=true`、`error_contains` 精确为 `unknown layer`）。占位的拒绝、0 包或空 PCAP 不得报告为 HL7 行为通过；注册后按本文 §9 与用例文档 §2 的同一顺序替换为 25 个语义用例。

**动态值不硬编码**：Message Control ID（MSH-10）、消息时间（MSH-7/EVN-2）、患者标识（PID-3）、ACK 的控制 ID 均为运行期/配置策略值，断言用 `presence`、`nonzero`、`distinct_values`、`same_as_packet` 与稳定长度/格式；只有协议常量（分隔符字节、0x0b/0x1c 0x0d、默认端口 2575、确认码 `AA/AE/AR`）可固定。HL7 文本以 ASCII/UTF-8 字节长度与字节边界为准，不以字符数代替 TCP/MLLP 字节长度。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[tcp, hl7]`（引擎自动补 `ip`；需显式地址族时写 `[ip, tcp, hl7]` 或 `[ipv6, tcp, hl7]`）。`hl7` 为 terminal layer，在其上产出 MLLP 帧与消息序列。默认目标端口 **2575**（IANA 登记 hl7）；tshark 3.6.14 实测 hl7 dissector 绑定 `tcp.port 2575`（`-G decodes`：`tcp.port 2575 hl7`），2575 载荷自动按 hl7 解码。端口可被配置覆盖，但 planner 不得悄然改写；**载体只能是 TCP**（负例 `hl7_neg_transport_port`：UDP 载体、非 2575、层链缺 tcp 一律拒绝）。

无 VLAN（虚拟局域网）、无 IP options、无 TCP options 的数据段时，MLLP 帧首字节（应用层 payload 第 1 字节，即 `0x0b`）起点：

| 载体 | 应用起点 offset | 组成 |
|---|---:|---|
| TCP/IPv4 | 54 | Ethernet 14 + IPv4 20 + TCP 20 |
| TCP/IPv6 | 74 | Ethernet 14 + IPv6 40 + TCP 20 |

**TCP 分段边界不是 HL7 消息边界**：接收端必须先按字节流重组，再以 MLLP 帧起止块（`0x0b` 起始、`0x1c 0x0d` 终止）识别完整帧，不得根据 TCP segment 数量推断消息数（一个 segment 可承载多帧，一条长消息可跨多 segment）。SYN/SYN-ACK 段可携带 TCP options（数据段通常无 options），planner 不得假设所有段的载荷起点都是 54/74——**该固定偏移只对无 options 的数据承载段成立**，断言按段分类处理。

## 3. 线格式编码（HL7 v2 文本与 MLLP 封装，逐项标注出处）

### 3.1 MLLP 帧格式（MLLP 实施指南）

```text
<0x0b> <HL7 message: 段序列，每段以 0x0d (CR) 结尾，含最后一段> <0x1c> <0x0d>
   VT=0x0b                    FS=0x1c  CR=0x0d
```

- 帧起始块：单个字节 `0x0b`（VT，Vertical Tab）。**VT 只能作为帧起始**，正文中出现未转义的 `0x0b` 属非法 framing。
- 帧结束块：`0x1c 0x0d`（FS + CR），FS 必须紧邻终止 CR。**正文中的 CR 是段终止符**，不得把任意 CR 误作 MLLP 结束；终止 CR 专指 `0x1c` 之后的 `0x0d`。
- 正文中出现未转义的 `0x1c` 会在错误位置闭合帧（dissector 按第一个 `0x1c 0x0d` 找 EOB）——正文控制字节必须转义（§3.3）或视为 framing 错误（负例 `hl7_neg_mllp_framing`）。
- tshark 实测行为（3.6.14，据公开源码 packet-hl7.c 与 `-G` 元数据）：启发式识别首 5 字节 `0x0b` + `"MSH|"` 即按 hl7 解码；在字节流中搜索 `0x1c 0x0d` 作为 EOB 并计算块长；段边界按 CR/LF/CRLF 任一识别（HL7 规范要求 CR，本版生成器一律用 CR，dissector 的 LF/CRLF 宽容不影响断言）。**生成器产出的帧必须以 `0x0b` 紧接 `"MSH|"` 开头**，否则不会被按 hl7 解码。

### 3.2 HL7 段/字段/组件/重复/子组件（v2.x Chapter 2）

- **段（Segment）**：3 字符段 ID（`MSH`、`EVN`、`PID`、`PV1`、`SCH`、`AIS`、`OBR`、`OBX`、`MSA`、`ERR`）+ 字段序列，段以 CR 结尾。消息最外层必须以 `MSH` 开始；段顺序按消息结构（MSH-9 第三组件声明）固定。
- **字段分隔符（MSH-1）**：`|`。非 MSH 段的第一个字段即字段 1；**MSH 段特殊**：`MSH` 后紧跟的第 1 个 `|` 是 MSH-1 字段分隔符本身，紧随其后的 4 字符是 MSH-2。
- **编码字符（MSH-2）**：4 个字符按顺序 = 组件分隔符（`^`）、重复分隔符（`~`）、转义字符（`\`）、子组件分隔符（`&`）。正文实际分隔符必须与 MSH-2 声明一致（负例 `hl7_neg_field_separator`）。
- **组件（`^`）**：字段内组件分隔；如 `ADT^A01^ADT_A01` 三组件。
- **重复（`~`）**：字段值可重复，如 `PID-3` 多患者标识 `PAT1^^^HOSP^MR~PAT2^^^HOSP^MR2`。
- **子组件（`&`）**：组件内子组件分隔，如 EI 类型 `OBR-2` 序号的 `ORD-1001&HIS`（实体标识 & 命名空间）。
- **转义（`\`）**：见 §3.3。

### 3.3 转义序列（v2.x Chapter 2 "Use of Escape Sequences"）

转义字符 = MSH-2 第 3 字符（标准为 `\`）。字段值内以 `\` 起始的转义序列按表解释，**转义后的内容不得伪造分隔符或 MLLP 控制字节**：

| 序列 | 语义 | 线上字节 |
|---|---|---|
| `\F\` | 字面字段分隔符 | `\F\`（3 字节，不解为 `\|`） |
| `\S\` | 字面组件分隔符 | `\S\`（3 字节，不解为 `^`） |
| `\R\` | 字面重复分隔符 | `\R\`（3 字节，不解为 `~`） |
| `\E\` | 字面转义字符 | `\E\`（3 字节，不解为 `\`） |
| `\T\` | 字面子组件分隔符 | `\T\`（3 字节，不解为 `&`） |
| `\H\` / `\N\` | 高亮开始/恢复正常 | `\H\` / `\N\` |
| `\Xdd..\` | 十六进制字节（每字节 2 个十六进制数字，如 `\X0D\` = CR） | 转义文本原样 |

**转义边界**：转义序列只解释字面值，不改变字段/组件/重复结构；未转义的控制字节（`0x0b`/`0x1c` 落入正文）违反 framing；`\X..\` 的十六进制须成对合法，非法转义序列属字段级错误（负例 `hl7_neg_field_separator` 或 `hl7_neg_mllp_framing` 视注入点）。本版正例断言转义文本以原样字节落线且**不**产生真实分隔符/MLLP 控制字节。

### 3.4 MSH 字段表（现网常用 MSH-1…MSH-12，出处：v2.5/v2.8 Chapter 2 MSH 段）

| 字段 | 名称 | 类型 | 长度上限 | 值域/语义 | 本版取值 |
|---|---|---|---|---|---|
| MSH-1 | 字段分隔符 | ST | 1 | `\|` | 固定 `\|` |
| MSH-2 | 编码字符 | ST | 4 | `^` `~` `\` `&` | 固定 `^~\&` |
| MSH-3 | 发送应用 | HD | 180 | 应用标识 | 配置 |
| MSH-4 | 发送机构 | HD | 180 | 机构标识 | 配置 |
| MSH-5 | 接收应用 | HD | 180 | 应用标识 | 配置 |
| MSH-6 | 接收机构 | HD | 180 | 机构标识 | 配置 |
| MSH-7 | 消息日期时间 | TS | 26 | `YYYYMMDDHHMM[SS[.S]]` | 运行期（timestamp 策略） |
| MSH-8 | 安全 | ST | 40 | 本版留空 | — |
| MSH-9 | 消息类型 | MSG | 15 | 三组件：`<消息代码>^<触发事件>^<消息结构>`（如 `ADT^A01^ADT_A01`、`ORU^R01^ORU_R01`、`SIU^S12^SIU_S12`、`ACK^A01^ACK`） | 事件声明 |
| MSH-10 | 消息控制 ID | ST | 20 | 发送方作用域内唯一；**事务关联标识** | 运行期（control_id 策略） |
| MSH-11 | 处理 ID | PT | 3 | `P`(生产)/`T`(测试)/`D`(调试) | 配置（默认 `P`） |
| MSH-12 | 版本 ID | VID | 60 | `2.5`/`2.8` 等（常用 3 字符） | 配置 |
| MSH-15 | 接受确认类型 | ID | 2 | `AL`/`NE`/`ER`/`SU`（增强模式用，本版可留空） | 留空 |
| MSH-16 | 应用确认类型 | ID | 2 | 同上 | 留空 |

MSH-15/16 留空 = 未声明两级确认期望；本版确认语义由 profile 统一约定（§5 自动派生），不依赖 MSH-15/16。

### 3.5 常用业务段（v2.x 对应章节）

| 段 | 现网角色 | 关键字段（本版断言/生成） |
|---|---|---|
| `EVN` | ADT 事件段 | EVN-1 事件类型码（`A01`/`A02`/`A03`，须与 MSH-9 触发事件一致）、EVN-2 事件记录时间（运行期） |
| `PID` | 患者段 | PID-1 集合 ID(`1`)、PID-3 患者标识列表（CX，运行期/策略，可重复 `~`）、PID-5 患者姓名（XPN，组件结构 `姓^名^中间名`）、PID-7 出生日期、PID-8 性别 |
| `PV1` | 就诊段 | PV1-1 集合 ID(`1`)、PV1-2 就诊类别(`I` 住院/`O` 门诊/`E` 急诊)、PV1-3 就诊位置（PL，组件 `机构^病房^床位`，A02 变更此字段）、PV1-36 离院方式（A03）、PV1-44 入院时间、PV1-45 离院时间（A03） |
| `SCH` | 预约头段（SIU） | SCH-1 placer 预约 ID（EI，`&` 子组件）、SCH-2 filler 预约 ID、SCH-7 预约原因、SCH-11 开始时间、SCH-12 结束时间 |
| `AIS` | 预约服务段（SIU） | AIS-1 集合 ID、AIS-2 通用服务标识（CE） |
| `OBR` | 检验/医嘱请求段（ORU） | OBR-1 集合 ID、OBR-2 placer 医嘱号（EI）、OBR-3 filler 医嘱号（EI）、OBR-4 通用服务标识（CE：`码^文本^LOINC`）、OBR-7 标本采集/观察时间、OBR-25 结果状态（`P`/`F`/`C`） |
| `OBX` | 结果段（ORU，可多段） | OBX-1 集合 ID（递增）、OBX-2 值类型（`ST`/`NM`/`CE`/…）、OBX-3 观察标识（CE：`LOINC码^文本^LN`）、OBX-5 观察值（按值类型）、OBX-6 单位（CE）、OBX-7 参考范围、OBX-11 结果状态（`F`/`P`/`C`） |
| `MSA` | 确认段（ACK/NAK） | MSA-1 确认码（`AA`/`AE`/`AR`）、MSA-2 原消息控制 ID（= 被确认消息的 MSH-10，**事务关联**）、MSA-3 文本消息（可选） |
| `ERR` | 错误段（NAK 可选） | ERR-1 错误位置、ERR-3 HL7 错误码、ERR-4 严重级（`E`/`W`/`I`）、ERR-5 应用错误码（`200` 等）+ 文本 |

ACK/NAK 消息：MSH-9 = `ACK^<触发事件>^ACK`，必含 MSA 段；拒绝/错误响应用 `AE`/`AR` + 可选 ERR，**不能只改文本而保持请求消息类型**。成功 ACK（`AA`）只表示线上格式与关联正确，不等于业务数据已处理——测试只断言 wire 格式、关联与响应码。

### 3.6 每消息总长度公式（可计算）

段文本长度：`len(seg) = 3（段 ID）+ (F-1)（F = 字段数，即 `|` 出现次数 + 1）+ Σ len(field_j)`

消息正文长度：`len(msg) = Σ_i (len(seg_i) + 1)`（每段含结尾 CR `0x0d`，含最后一段）

MLLP 帧长度：`len(frame) = 1（0x0b）+ len(msg) + 2（0x1c 0x0d）`

字节级示例（IPv4/TCP，offset 54 起）：

```text
offset 54 (0x36):  0x0b                                                 VT 起始块
offset 55:         4D 53 48 7C 5E 7E 5C 26 7C ...                        "MSH|^~\&|..."
                   (MSH 段：byte0-2="MSH"，byte3='|'=MSH-1，byte4-7="^~\&"=MSH-2)
...                41 44 54 5E 41 30 31 5E 41 44 54 5F 41 30 31          "ADT^A01^ADT_A01"（MSH-9）
...                30 44                                                        CR 段终止
...                45 56 4E 7C 41 30 31 7C ... 30 44                     "EVN|A01|..." CR
...                50 49 44 7C ... 30 44                                  "PID|..." CR
...                50 56 31 7C ... 30 44                                  "PV1|..." CR（最后一段）
末 2 字节:         1C 0D                                                  FS CR 结束块
```

按公式：上例 4 段（MSH/EVN/PID/PV1），`len(frame) = 1 + Σ(len(seg)+1) + 2`。断言基线：TCP payload 首字节 = `0x0b`，末两字节 = `0x1c 0x0d`——**一律以 frames hex 断言**；`hl7.llp.sob`/`hl7.llp.eob` 受 tshark 偏好门控且断言 harness 不支持 `-o` 传参，不用作断言字段（§3.9 实测）。

### 3.7 端序与数值编码

HL7 v2 文本线格式**全部为 ASCII 文本**，无字节端序概念；数值（集合 ID、MSA-1 码、时间戳）都是文本。唯一涉及多字节的是 MLLP 结束块 `0x1c 0x0d`（FS CR）与 dissector 的 `hl7.llp.eob` FT_UINT16 显示值——线上字节序固定为 `1c 0d`（FS 在前 CR 在后）；实测（偏好开启后，§3.9）显示值为 `0x1c0d`（FS、CR 两字节拼合），无需再校准。

### 3.8 数据场景要点

- **MSH-12 版本值域**：`2.5`/`2.8` 均合法，版本只影响声明与字段规则，不可绕过必需字段（负例 `hl7_neg_msh_required`）。
- **MSA-1 确认码值域**：`AA`（应用接受）/`AE`（应用错误）/`AR`（应用拒绝）；`AA` 是成功确认，`AE`/`AR` 是拒绝/错误确认（NAK 语义）。
- **动态字段**：MSH-7/EVN-2 时间、MSH-10/MSA-2 控制 ID、PID-3 患者标识——运行期/策略值，presence/nonzero/distinct/same_as 断言，不硬编码。
- **空字段**：合法空可选字段以空槽表示（`PID|1||...` 中 PID-3 前的空槽），不得折叠为错位字段。

### 3.9 tshark 证据字段（本机 3.6.14 `-G fields` 实测）

`hl7` dissector 绑定 `tcp.port 2575`（`-G decodes` 实测 `tcp.port 2575 hl7`）。可用字段（本契约断言只用这些或标准载体字段）：

```text
hl7.llp.sob        FT_UINT8    LLP 起始块（0x0b，BASE_HEX）——偏好 hl7.display_llp 门控，默认 FALSE 不提取
hl7.llp.eob        FT_UINT16   LLP 结束块（偏好开启后显示值 0x1c0d；hl7.display_llp 门控，默认 FALSE 不提取）
hl7.raw            FT_STRING   原始消息文本（hl7.display_raw 门控，默认 FALSE 不提取）
hl7.raw.segment    FT_STRING   逐段原始文本（hl7.display_raw 门控，默认 FALSE 不提取）
hl7.segment        FT_STRING   整段原始文本（段名+字段+段尾 CR，如 "MSH|^~\&|HIS|...|"；非 3 字符段名）——默认可提取
hl7.message.type   FT_STRING   MSH-9 消息代码（ADT/ORU/ACK/…）——实测默认可提取
hl7.event.type     FT_STRING   MSH-9 触发事件（A01/R01/…）——实测默认可提取
hl7.field          FT_STRING   段内各字段值（每段首值即段名）——默认可提取
hl7.malformed      FT_NONE     解析失败诊断（expert info）
```

**实测证据（3.6.14，构造单包 MLLP mini pcap、TCP 2575 载荷实跑）**：默认偏好下 `-T fields` 可提取 `hl7.segment`（值为**整段原始文本**，一帧多段以逗号拼接，如 `MSH|^~\&|HIS|...|\r,EVN|A01|...\r,...`）、`hl7.field`（每段首值即段名，如 `MSH,^~\&,HIS,...`）、`hl7.message.type`/`hl7.event.type`（`ADT`/`A01`——源码中的 hidden 项实测**可提取**）；`hl7.llp.sob`/`hl7.llp.eob`/`hl7.raw`/`hl7.raw.segment` 默认**不提取**（输出为空），需 `-o hl7.display_llp:TRUE -o hl7.display_raw:TRUE` 后才出现（sob=`0x0b`、eob=`0x1c0d`、raw/raw.segment 为整段文本）。

**断言口径（由上述实测决定）**：pcaptest 断言 harness（`internal/pcaptest` 的 RunTshark）只支持 `-d` 解码提示、**不支持 `-o` 偏好传参**，且字段断言无前缀/包含谓词（`-T fields` 多 occurrence 以逗号拼接为单值）——因此 **MLLP 边界字节（`0x0b`/`0x1c 0x0d`）与段序列/段存在性断言一律用 frames hex**（段 ID+`|` 的字节，如 `45 56 4E 7C`=`EVN|`；固定策略值下偏移可计算）；`hl7.message.type`/`hl7.event.type` 可作 fields 断言、frames hex 为其后备（如 `41 44 54 5E 41 30 31` = `ADT^A01`）；`hl7.segment`/`hl7.field` 的整段文本不作精确值断言、仅作人工核对辅助。不得臆造未实测字段名/格式。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性声明**：本引擎对 HL7 采用**声明式脚本化回放**——配置是剧本（`sessions[]`/`events[]` 逐条声明），引擎是回放者，按序产出帧；"事件驱动"一词不用于定性整体行为，仅用于两处反应性成分：①**自动应答**（`ack_mode=auto` 时收到/发出请求消息自动派生 ACK 响应帧，§5 自动派生规则）；②**连接边界**（事件序列中源端口/会话切换触发新 TCP 连接，如多会话展开）。

| 现网场景 | 事务交互 | 驱动顺序 | 对应用例 |
|---|---|---|---|
| ① ADT 入院（A01） | TCP→MLLP `MSH/EVN/PID/PV1`→ACK `AA`→TCP 关闭 | 发送方驱动，ACK 自动应答 | `hl7_adt_a01_ipv4` |
| ② ADT 转科（A02） | `MSH/EVN/PID/PV1`（PV1-3 更新位置）→ACK | 同 ① | `hl7_adt_a02_transfer` |
| ③ ADT 出院（A03） | `MSH/EVN/PID/PV1`（PV1-45 离院时间）→ACK | 同 ① | `hl7_adt_a03_discharge` |
| ④ ORU 检验结果上传（R01） | `MSH/PID/OBR/OBX×N`→ACK；OBX 逐项结果按序 | 同 ①；多 OBX 一次性携带 | `hl7_oru_r01_results` |
| ⑤ SIU 预约（S12） | `MSH/SCH/AIS`→ACK | 同 ① | `hl7_siu_s12_appointment` |
| ⑥ 应用错误确认（NAK） | 消息→ACK `AE`/`AR`+ERR 段（MSA-2 仍关联原控制 ID） | ACK 码与 ERR 段由配置声明 | `hl7_nak_error_segment` |
| ⑦ 批量/长连接多事务 | 同一 TCP 连接内连续多笔消息→ACK，MSH-10 各自 distinct、MSA-2 各自配对 | events[] 按序；连接持续到事件结束才关 | `hl7_multi_transaction_long_connection` |
| ⑧ 主动测试/生产切换 | MSH-11 `P`/`T`、MSH-12 版本随配置 | 声明 | `hl7_version_profiles` |

**事务交互**：消息→ACK **强制配对**——每条需要确认的消息必须有其 ACK（MSA-2 回带原 MSH-10）；多事务 = 一个连接内多笔消息→ACK，事务间有先后依赖（events[] 顺序）与关联标识（MSH-10↔MSA-2）。**驱动顺序**：events[] 显式声明每条消息与 ACK 配置（`auto` 自动补 / 显式码 / `null` 关闭，§5）。

**五层覆盖逐层结论**（用例 ID 见用例文档 §2）：

- **功能**：消息类型 ADT^A01/A02/A03、ORU^R01、SIU^S12、ACK/NAK 各一正例；MLLP 起止块、段/字段/组件/重复/转义规则各一正例；错误处理七方向各至少一条负例（framing/段结构/分隔符/必需字段/确认关联/载体端口/长度上界，§7）。
- **性能**：长消息跨 MSS 分段重组（`hl7_tcp_mss_reassembly`）+ 帧长公式（§3.6）+ MLLP 帧完整/截断判定（§8）。
- **数据场景**：MSH-12 版本值域 2.5/2.8（`hl7_version_profiles`）、MSA-1 码值域 AA/AE/AR（`hl7_ack_code_domain`）、动态字段 presence/nonzero/distinct/same_as、转义序列值域（`hl7_escape_sequences`）。
- **地址与流**：IPv4（基线全量）与 IPv6（`hl7_ipv6_transport`）独立 fixture、单流基线、多会话双四元组（`hl7_multi_session_isolation`）；**流关联显式不适用**——HL7 是单消息交换协议，请求/ACK 在同一 TCP 连接内完成，不存在"控制流派生数据流/媒体流"的主从关系，MSA-2 是事务关联标识而非流关联（§5）；**多流（会话内并发流）亦不适用**——一个会话 = 一条 TCP 字节流，并发维度由多会话/多事务承担。
- **业务**：入院/转科/出院、检验结果上传、预约、批量长连接、应用错误确认均为现网日常，优先于教科书全消息类型遍历。

## 5. 消息/事务模型与状态机

### 5.1 事务定义与关联规则

- **事务 = 一次消息→ACK 交互**。关联标识 = **MSH-10（Message Control ID）**：请求消息分配 MSH-10，ACK 的 **MSA-2 必须回带与请求 MSH-10 相同的值**（`same_as_packet`）。发送方作用域内 MSH-10 唯一（同一连接/会话内 `distinct`）。
- **多事务** = 一个 TCP 连接内多笔消息→ACK 按序执行，事务间有先后依赖（事件序列顺序）与关联标识（MSH-10↔MSA-2 各自配对）。**事务交互**示例：同一连接先发 ADT^A01 收 AA，再发 ORU^R01 收 AA——后序事务不依赖前序业务状态（HL7 各消息独立），依赖仅体现在控制 ID 空间与连接生命周期上。
- **ACK 语义（原确认模式）**：`AA` = 应用接受；`AE` = 应用错误（已接收未处理，带 ERR）；`AR` = 应用拒绝。`AA` 是成功确认；`AE`/`AR` 是 NAK 语义（负例 `hl7_neg_ack_correlation` 覆盖"把错误 ACK 当成功/关联错"）。

### 5.2 自动派生规则（自动应答，逐条显式，不依赖隐含知识）

`ack_mode` 取值与派生行为：

| `ack_mode` | 行为 | 触发 |
|---|---|---|
| `auto`（默认） | 每条消息事件后自动派生一条 ACK 响应帧 | 反应性自动应答 |
| `{code: "AE"/"AR", err_segments: [...]}` | 自动派生 ACK，MSA-1=指定码，可附 ERR 段 | 同上 |
| `null` | 不派生 ACK 帧（单发/批量场景） | 关闭自动应答 |

**自动派生 ACK 的内容（逐条）**：① MLLP 封装 `0x0b ... 0x1c 0x0d`；② 方向反转（请求 c2s → ACK s2c）；③ MSH-1/MSH-2 与请求相同（`\|`、`^~\&`）；④ MSH-3/4 = 请求 MSH-5/6（收发应用对调），MSH-5/6 = 请求 MSH-3/4；⑤ MSH-7 = 新运行期时间戳；⑥ MSH-9 = `ACK^<请求触发事件>^ACK`；⑦ MSH-10 = 新运行期控制 ID（**与请求 MSH-10 不同**，`distinct`）；⑧ MSH-11 = 同请求；⑨ MSH-12 = 同请求；⑩ MSA-1 = 确认码（默认 `AA`）；⑪ **MSA-2 = 请求 MSH-10（原样复制，`same_as_packet`）**；⑫ 配置 ERR 段时按 §3.5 编码追加。派生规则确定性：同一配置 + 同一事件必然同一形状（仅运行期策略值变化）。

**驱动顺序**：`events[]` 显式声明每条消息；`ack_mode` 决定 ACK 是否/如何自动补出。**无自动补帧的情况显式写出**：`ack_mode=null` 时引擎不补 ACK（负例 `hl7_neg_ack_correlation` 不得把缺 ACK 当自动补全）。多会话 = 多连接，状态互不串用（§8）。

### 5.3 会话状态机（每个事件编排会话独立一份）

| 状态 | 允许事件 | 必须保持 |
|---|---|---|
| `Connecting` | TCP 握手（SYN/SYN-ACK/ACK） | 握手完成前不得产出 MLLP 字节 |
| `Established`（idle） | 发送/接收一条完整 MLLP 帧 | 帧完整判定：`0x0b` 起始 + `0x1c 0x0d` 终止（按方向字节流缓冲）；MSH 必为首段 |
| `TxPending`（消息已发） | 自动派生 ACK（`ack_mode=auto/显式`）；`ack_mode=null` 直接回 idle | ACK 的 MSA-2 必须等于本消息 MSH-10；MSH-10 不得复用 |
| `Acked`（确认已出） | 下一条消息 | 控制 ID 空间递增不重复 |
| `Closing` | FIN/ACK 挥手 | 事件序列结束才关连接；关闭后不得产生新业务帧 |
| `Closed` | — | 连接关闭，会话结束 |

**帧组装子状态（每方向独立）**：`WaitSOB`（等 `0x0b`）→ `InMessage`（累积字节，遇 `0x1c 0x0d` 判定完整）→ 校验 MSH 首段与段 CR。截断帧（无 `0x1c 0x0d` 即 TCP 关闭/流结束）属 framing 错误（负例 `hl7_neg_mllp_framing`）。

### 5.4 连接生命周期与多会话

- 连接生命周期：建立（3 包握手）→ 持续多事务（消息→ACK 循环，可 0 或多笔）→ 关闭（FIN/ACK×2）。连接在 events[] 结束时关闭，不提前、不延后。
- **多会话展开**：`sessions[]` 数组按序**整块**回放——先跑完第 1 个会话全流程（握手→事件→挥手）再跑下一个，不交错；第二会话包号起点 = 前会话总包数 + 1。每个会话独立四元组、独立控制 ID 空间、独立 PID/时间策略，状态互不串用（`hl7_multi_session_isolation`）。
- **并发会话（`concurrent: true`）本版显式不适用**：MLLP 连接内单消息串行确认，双连接用多会话展开表达。
- **流关联显式不适用**：HL7 无控制流派生数据流/媒体流；MSA-2 是事务关联标识，不是流关联锚点（见 §4 五层覆盖结论）。

## 6. 配置 typedef（JSON 形状契约，非现有 Go 结构）

顶层遵循层链配置；`hl7` 子映射承载协议语义。事件编排会话（`sessions[]`）各自带四元组与事件序列，按序整块回放（多会话展开）：

```json
{
  "layers": [{"tcp": {}}, {"hl7": {}}],
  "src_ip": "192.0.2.68", "dst_ip": "198.51.100.68",
  "src_port": 42680, "dst_port": 2575,
  "hl7": {
    "profile": "mllp",
    "version": "2.8",
    "field_separator": "|",
    "encoding_chars": "^~\\&",
    "ack_mode": "auto",
    "sessions": [
      {
        "name": "his-admit-1",
        "src_port": 42680, "dst_port": 2575,
        "role": "sender",
        "sending_app": "HIS", "sending_fac": "GH",
        "receiving_app": "LIS", "receiving_fac": "GH",
        "processing_id": "P",
        "control_id": {"strategy": "inc", "range": [1000, 9999], "step": 1},
        "timestamp": {"strategy": "rand", "range": [1725081600, 1725085200], "seed": 68},
        "patient_id": {"strategy": "inc", "range": [100000, 999999], "step": 1},
        "events": [
          {"kind": "msg", "direction": "c2s",
           "message_type": "ADT^A01^ADT_A01",
           "segments": [
             {"name": "EVN", "fields": [["A01"], ["@ts"]]},
             {"name": "PID", "fields": [["1"], [], ["@pid^^^HOSP^MR"], [], ["DOE^JOHN^A"], [], ["19800101"], ["M"]]},
             {"name": "PV1", "fields": [["1"], ["I"], ["WARD^1^BED5"]]}
           ],
           "ack": "auto"},
          {"kind": "msg", "direction": "c2s",
           "message_type": "ORU^R01^ORU_R01",
           "segments": [
             {"name": "PID", "fields": [["1"], [], ["@pid^^^HOSP^MR"]]},
             {"name": "OBR", "fields": [["1"], ["ORD-1001&HIS"], ["FILL-2001&LIS"], ["2339-0^Glucose^LN"], [], [], ["@ts"], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], ["F"]]},
             {"name": "OBX", "fields": [["1"], ["NM"], ["2339-0^Glucose^LN"], ["1"], ["95"], ["mg/dL"], ["70-99"], [], [], [], ["F"]]},
             {"name": "OBX", "fields": [["2"], ["ST"], ["4548-4^Hemoglobin A1c^LN"], ["1"], ["5.6"], ["%"], ["4.0-5.6"], [], [], [], ["F"]]}
           ],
           "ack": {"code": "AA"}}
        ]
      },
      {
        "name": "lis-oru-2",
        "src_port": 42681, "dst_port": 2575,
        "role": "sender",
        "sending_app": "LIS", "sending_fac": "GH",
        "receiving_app": "HIS", "receiving_fac": "GH",
        "control_id": {"strategy": "inc", "range": [2000, 9999], "step": 1},
        "events": [
          {"kind": "msg", "direction": "c2s",
           "message_type": "SIU^S12^SIU_S12",
           "segments": [
             {"name": "SCH", "fields": [["APPT-9001&HIS"], [], [], [], [], [], ["SURGERY"], [], [], [], ["@ts"], ["@ts"]]},
             {"name": "AIS", "fields": [["1"], ["MRI^MRI Scan^LN"]]}
           ],
           "ack": "null"}
        ]
      }
    ],
    "wire_fault": ""
  }
}
```

配置键约束：

| 键 | 约束 |
|---|---|
| `profile` | 本版固定 `mllp`；非 mllp profile 拒绝 |
| `version` | MSH-12，`2.5`/`2.8`；只影响声明与字段规则，不可绕过必需字段 |
| `field_separator` / `encoding_chars` | 默认 `\|`、`^~\&`；`encoding_chars` 必须恰 4 字符（组件/重复/转义/子组件），正文分隔符必须与声明一致（负例 `hl7_neg_field_separator`） |
| `ack_mode` | `auto` / `{code, err_segments}` / `null`（§5.2）；`null` 时引擎不补 ACK |
| `sessions[]` | 事件编排会话：四元组 + `role`（`sender`/`receiver`）+ `events[]`；多会话按序整块回放，第二会话包号起点 = 前会话总包数 + 1 |
| `events[]` | 事件序列；`kind=msg`、`direction=c2s/s2c`；一个事件一条完整 MLLP 消息（`message_type` 3 组件 + `segments[]`） |
| `segments[].fields` | 字段值数组；`@ts`/`@pid`/`@name`/`@cid` 为运行期占位（timestamp/patient_id/control_id 策略替换）；空槽 `[]` 表示空字段；段以 CR 结尾、帧自动封装 MLLP |
| `ack`（消息级） | 覆盖会话级 `ack_mode`：`"auto"` / `{"code":...}` / `null` |
| `wire_fault` | 仅负例的故障注入口：`mllp_framing` / `segment_order` / `field_separator` / `msh_required` / `ack_correlation` / `transport_port` / `length_limit`（§7 一一对应），不得成为线上字段 |

`Validate` 必须覆盖：profile/version/分隔符声明与正文一致性、MSH 必为首段、MSH-9/10/11/12 存在、消息类型 3 组件合法（§3.4）、段名 ∈ 已知段表、`ack` 配置合法（`auto`/码/`null`）、控制 ID 空间会话内唯一、多会话四元组独立、wire_fault 仅注入不落线。

## 7. 错误处理（负例锚词表）

以下输入必须由 planner/validator 拒绝并传播为 task error（任务错误），不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。负例执行期 `expect` 严格只有 `expect_error` 与 `error_contains`。锚词（anchor word）为错误文案必须包含的关键词，validator 实现与用例文档 §5 共用本表：

| 负例 ID | 类别 | 故障输入（方向） | `error_contains` 候选锚词 |
|---|---|---|---|
| `hl7_neg_mllp_framing` | 线格式/framing 错 | 缺 VT、结束块 FS/CR 缺失或错误、正文出现未转义控制字节（0x0b/0x1c）、帧未闭合（流结束无 `0x1c 0x0d`） | `mllp` 或 `framing` |
| `hl7_neg_segment_order` | 段/结构错 | 首段非 MSH、段未以 CR 结尾、`0x1c 0x0d` 后追加段、段名非法 | `segment` 或 `msh` |
| `hl7_neg_field_separator` | 字段/分隔符错 | MSH-1 缺失或长度≠1、MSH-2 长度≠4、正文实际分隔符与声明不一致、非法转义序列 | `field` 或 `separator` |
| `hl7_neg_msh_required` | MSH 必需字段错 | MSH-9/10/11/12 缺失、MSH-9 消息类型/触发事件非法（不在 §3.4 值域）、必需字段错位 | `msh` 或 `required` |
| `hl7_neg_ack_correlation` | 确认/关联错 | `ack_mode=auto` 派生 ACK 时 MSA-2 ≠ 请求 MSH-10、ACK 缺 MSH-9=ACK 或缺 MSA 段、确认码非法（非 AA/AE/AR）、把 NAK 当成功 | `ack` 或 `correlation` |
| `hl7_neg_transport_port` | 载体/端口错 | UDP 载体、目标端口非 2575 且未显式配置、层链缺 tcp（hl7 直连 ip/udp）、非法端口 | `port` 或 `transport` |
| `hl7_neg_length_limit` | 长度上界错 | MSH-9 >15、MSH-10 >20、MSH-12 >60、MSH-7 >26、MSA-2 >20（§8 上界表；恰等上界为合法边界值） | `length` 或 `limit` |

**不得误报为 planner error 的合法协议事件**：合法转义序列（`\F\` 等）、重复字段/重复 OBX、空可选字段（`||` 空槽）、TCP 分段/粘连/多帧同段、IPv4/IPv6 双栈、ACK `AA` 与 NAK `AE`/`AR` 合法确认码、`ack_mode=null` 无 ACK 帧、动态控制 ID/时间/PID、`MSH-15/16` 留空、字段长度恰等上界（如 MSH-10 恰 20 字符——边界值合法，越界才拒绝）。只有配置错、线格式错、段/字段结构错、必需字段错、确认关联错、载体端口错、长度上界错进入负例。错误保留最具体来源从 planner 传到 task；不得自动补齐缺失 ID、不得把非法消息重排成合法顺序、不得跨事务代答。

## 8. 边界

- **字段/段长度上界**（v2.5 数据字典）：MSH-9 ≤15、MSH-10 ≤20、MSH-12 ≤60（常用 3）、MSA-2 ≤20、MSH-7 ≤26；段名恰 3 字符。超界属配置错误（validator 拒绝，不静默截断；负例 `hl7_neg_length_limit`，恰等上界为合法边界值不拒绝）。
- **MLLP 帧完整与截断**：完整帧 = `0x0b` 起始 + `0x1c 0x0d` 终止；截断（缺 FS/CR）→ 负例 `hl7_neg_mllp_framing`。正文含未转义 `0x1c` 会提前闭合帧，必须转义（§3.3）。
- **转义边界**：转义序列只解释字面值，不产生真实分隔符/MLLP 控制字节；`\Xdd..\` 十六进制须成对合法；非法转义进负例。
- **超长消息跨 MSS**：长消息按 TCP 分段重组后以完整 MLLP 帧解析（`hl7_tcp_mss_reassembly`）；**segment 边界 ≠ 消息边界**；一个 segment 可承载多帧，不得按 segment 数推断消息数。
- **IPv4/IPv6**：双栈独立 fixture；数据承载段应用起点 offset 54/74（§2）；外层 IP 头不同，MLLP/HL7 字节一致（`hl7_ipv6_transport`）。
- **多会话双四元组**：≥2 个独立四元组；控制 ID 空间、PID/时间策略、帧缓冲按会话隔离；多会话展开按序整块回放，第二会话包号起点 = 前会话总包数 + 1（`hl7_multi_session_isolation`）。
- **多事务**：同一连接多笔消息→ACK，MSH-10 各自 distinct、MSA-2 各自配对、连接持续到事件结束（`hl7_multi_transaction_long_connection`）。
- **动态值**：MSH-10/MSA-2 关联用 same_as、跨消息/会话用 distinct、MSH-7/EVN-2/PID-3 用 presence/nonzero；不得硬编码运行期值，不得产生回绕长度或超量分配。

## 9. 原子 ID 与完成定义

设计、testcase 与未来 `hl7.json` 必须使用同一组 25 个唯一语义 ID（18 正 + 7 负）、同一顺序；当前 JSON 另有不计入的 `hl7_neg_unregistered` 占位。约定 packet_count（正例）：TCP = 3（握手）+ 每笔消息→ACK 2 包（请求 1 段 + ACK 1 段）+ 4（FIN/ACK×2）；`ack_mode=null` 的消息只 1 包；跨段每加 1 段 +1；多会话 = 各会话之和。实现期以实际输出校准，断言以 fields/frames 为准。

| # | ID | 类型 | 覆盖（设计 §） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `hl7_adt_a01_ipv4` | 正 | ADT^A01（MSH/EVN/PID/PV1）+ MLLP/IPv4 单消息基线 + 自动 ACK（§3.4/§3.5/§5.2） | 9 |
| 2 | `hl7_adt_a02_transfer` | 正 | ADT^A02 转科（EVN-1=A02、PV1-3 位置更新），消息类型原子单元（§3.5） | 9 |
| 3 | `hl7_adt_a03_discharge` | 正 | ADT^A03 出院（EVN-1=A03、PV1-45 离院时间），消息类型原子单元（§3.5） | 9 |
| 4 | `hl7_oru_r01_results` | 正 | ORU^R01：OBR + 多 OBX（序号递增、值类型/值/单位、线上顺序）（§3.5） | 9 |
| 5 | `hl7_siu_s12_appointment` | 正 | SIU^S12：SCH/AIS 预约段、EI `&` 子组件（§3.5） | 9 |
| 6 | `hl7_ack_success_association` | 正 | ACK `AA`：MSH-9=ACK、MSA-1=AA、MSA-2 same_as 请求 MSH-10（§3.5/§5.1） | 9 |
| 7 | `hl7_nak_error_segment` | 正 | NAK `AE`+ERR 段：MSA-1=AE、ERR 存在、MSA-2 仍关联（§3.5/§5.1） | 9 |
| 8 | `hl7_mllp_frame_bytes` | 正 | MLLP 起止块逐字节：offset 54 首字节 0x0b、末两字节 0x1c 0x0d、段 CR 与终止 CR 区分（§3.1） | 9 |
| 9 | `hl7_component_subcomponent` | 正 | 组件 `^` 与子组件 `&`（PID-5 名字、OBR-2 EI）（§3.2） | 9 |
| 10 | `hl7_field_repetition` | 正 | 重复 `~`（PID-3 多标识），字段规则原子单元（§3.2） | 9 |
| 11 | `hl7_escape_sequences` | 正 | 转义 `\F\`/`\S\`/`\R\`/`\E\`/`\T\`/`\H\`/`\N\`/`\X..\`：不产生真实分隔符/控制字节（§3.3） | 9 |
| 12 | `hl7_multi_transaction_long_connection` | 正 | 同连接多事务：3 笔消息→ACK 按序、MSH-10 各自 distinct、MSA-2 各自配对、连接持续到事件结束（§5.1/§5.4） | 13 |
| 13 | `hl7_tcp_mss_reassembly` | 正 | 性能：长消息跨 TCP 分段重组 + 第二帧粘连；segment 边界≠消息边界（§2/§8） | 10 |
| 14 | `hl7_ipv6_transport` | 正 | IPv6/TCP/2575：ipv6.nxt=6、offset 74、MLLP 字节同 v4（§2/§8） | 9 |
| 15 | `hl7_multi_session_isolation` | 正 | 多会话双四元组：控制 ID/PID/时间 distinct、状态隔离、第二会话起点=前会话总包数+1（§5.4） | 18 |
| 16 | `hl7_version_profiles` | 正 | MSH-12 版本值域 2.5/2.8 + MSH-11 处理 ID P/T（同连接两消息，§3.4/§3.8） | 11 |
| 17 | `hl7_ack_code_domain` | 正 | MSA-1 码值域 AA/AE/AR 各出现一次（§3.8） | 13 |
| 18 | `hl7_ack_disabled` | 正 | `ack_mode=null`：无 ACK 帧（自动应答关闭分支，§5.2） | 8 |
| 19 | `hl7_neg_mllp_framing` | 负 | MLLP 起止字节/控制字节/未闭合（§7） | — |
| 20 | `hl7_neg_segment_order` | 负 | 首段非 MSH/段未 CR 结尾/EOB 后追加段（§7） | — |
| 21 | `hl7_neg_field_separator` | 负 | MSH-1/MSH-2 长度/声明与正文不一致/非法转义（§7） | — |
| 22 | `hl7_neg_msh_required` | 负 | MSH-9/10/11/12 缺失、消息类型非法（§7） | — |
| 23 | `hl7_neg_ack_correlation` | 负 | MSA-2 不关联、ACK 缺 MSH-9=ACK/缺 MSA、码非法（§7） | — |
| 24 | `hl7_neg_transport_port` | 负 | UDP 载体、非 2575、层链缺 tcp（§7） | — |
| 25 | `hl7_neg_length_limit` | 负 | 字段长度上界越界：MSH-9/10/12、MSH-7、MSA-2 超限（§7/§8） | — |

**完成定义**：注册 `tcp→hl7` 层链（含 IPv6）；按 §3 逐字段生成 HL7 文本消息与 MLLP 帧；事务关联（MSH-10 分配 + MSA-2 配对）与 §5.2 自动派生规则生效；TCP 字节流重组与 MLLP 帧完整判定可观测；IPv4/IPv6、多会话展开、多事务长连接、MSS 分段与边界均可观测；25 个语义 ID 正负断言与错误传播（锚词表 §7）完成；未注册阶段只接受 `unknown layer` 占位；实现后逐条对照 tshark `hl7.*` 实测字段校准并同步四件套（设计/testcase/JSON/audit）。

## 10. 修订记录

- v1.0.0（2026-08-20）：旧稿首版（14 正 + 6 负：含 pcap_nic_consistency、v25_v28_version_profiles、multi_flow_dynamic_fields 等 ID）。
- v2.0.0（2026-08-31）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写/review，取代 2026-08-20 旧稿（旧稿见 git 历史）。相对旧稿的主要变化：①按原子用例原则将 14 正例拆分为 18 个不可再分单元（消息类型 ADT^A01/A02/A03、ORU^R01、SIU^S12 各自成例；MLLP 起止块、组件/子组件、重复、转义、MLLP 帧字节、ACK/NAK、关联、长连接多事务、MSS 重组、IPv6、多会话、版本、确认码值域、ack 关闭各一例）；②删除 `pcap_nic_consistency`（测试方法非协议语义）、`multi_flow_dynamic_fields`（HL7 单连接字节流，多流不适用）、合并 `v25_v28` 与 `multi_obx` 的重复覆盖；③按统一术语重写（事件编排会话/多会话展开/事务/锚词/声明式脚本化回放），显式声明流关联不适用（HL7 无控制流派生数据流）与并发会话不适用；④新增 §3.9 tshark 证据字段（实测 hl7 dissector 绑定 2575、字段族清单、MSH-9 派生语义、hidden 项校准项）；⑤新增 §5.2 自动派生规则（ack_mode auto/显式/null 逐条）与 §5.3 会话状态机、§3.6 帧长公式；⑥负例按 mllp/segment/field/msh/ack/port 六方向重构锚词表。**待独立隔离审查**。
- v2.0.1（2026-09-01）：按独立隔离审查 12 项问题清单（1 CRITICAL / 3 MAJOR / 8 MINOR）修复：① **`hl7.segment` 语义更正（CRITICAL）**——实测（构造 MLLP mini pcap 实跑）为整段原始文本而非 3 字符段名，段序列/段存在性断言改为 frames hex（段 ID+`|` 字节，§3.9，用例 §3.2/§4 多处）；② `hl7.llp.sob`/`hl7.llp.eob`/`hl7.raw`/`hl7.raw.segment` 偏好门控写明（`hl7.display_llp`/`hl7.display_raw` 默认 FALSE，开启后 sob=`0x0b`、eob=`0x1c0d`），断言 harness 不支持 `-o` 传参故 MLLP 边界断言一律 frames hex（§3.6/§3.7/§3.9）；③ 新增长度上界负例 `hl7_neg_length_limit`（负例 6→7，语义 ID 24→25，设计 §6/§7/§8/§9 与用例/JSON 三方同步）；④ 错误处理负例方向五→七（§4）；⑤ 设计声明的 MSH-7/EVN-2、MSH-11 处理 ID、PID-7/PID-8、OBX-11/OBR-25、AIS-2、ACK 帧内 MSH-7/MSH-11/MSH-12 断言在用例落地（§3.5/§3.8/§5.2 → 用例 §4 #1/#4/#5/#6/#16）；⑥ `hl7.message.type`/`hl7.event.type` 提取性由"实现后校准"更新为实测可提取（§3.9）。

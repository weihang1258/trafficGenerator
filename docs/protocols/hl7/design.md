# HL7 v2.x over MLLP（医疗信息交换标准 / 最小下层协议）设计契约

> 版本：v2.1.1（设计阶段）
> 日期：2026-09-01
> 状态：已落地契约，HL7 registry、planner、validator 与终结层 generator 已接线；本次仅完成静态契约审计，未运行协议套件、Go 测试或 NIC/PCAP 验证。
> 配套文件：`docs/protocol-designs/68-hl7-testcase.md`、`trafficgen/test/protocol_pcap/cases/hl7.json`
> 规范基线：HL7 v2.x 官方标准（HL7.org，v2.5/v2.8 公开文档，本章节按 v2.x 通用章节口径引用）；MLLP（Minimal Lower Layer Protocol，最小下层协议，HL7 附录/实施指南的 LLP 封装）；IANA 服务端口登记 hl7 = TCP 2575。tshark 断言字段以本机 3.6.14 `-G fields`/`-G decodes` 实测为准（§3.9）。

## 1. 范围、profile 和未注册边界

本版定义 HL7 v2.x 消息经 **MLLP** 封装、以 **TCP 字节流**为载体的线格式与事务模型：HL7 消息 = 段序列（**MSH 必为首段**）；段 = 字段（`|` 分隔，MSH 段特殊）；字段 = 组件（`^`）、重复（`~`）、子组件（`&`）；转义（`\F\`、`\S\`、`\R\`、`\E\`、`\T\`、`\H\`、`\N\`、`\Xdd..\` 等）。MLLP 帧 = `0x0b`（VT 起始块）+ 消息字节 + `0x1c 0x0d`（FS CR 结束块）。消息类型覆盖现网常用：**ADT^A01/A02/A03**（入院/转科/出院）、**ORU^R01**（检验结果上传）、**SIU^S12**（预约）、**ACK/NAK**（确认，MSA 段）。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `mllp`（主 profile） | TCP / 2575，IPv4+IPv6 | MSH/EVN/PID/PV1/SCH/AIS/OBR/OBX/MSA/ERR 段、ACK/NAK 确认流、MLLP 封装、消息→ACK 配对、多消息长连接 | 患者真实存在、临床结果正确、身份认证成功、医学业务处理成功 |

显式边界（均"不实现、不声称、不许静默转换"）：UDP/串口/MLLP 之外的载体本版不支持（负例 `hl7_neg_carrier_udp`）；HL7 批量文件（batch，FHS/BHS 外层）本版不展开；HL7 增强确认模式（MSH-15/16 组合声明的 Commit Accept/Application 两级确认 CA/CE/CR）本版不展开——统一按**原确认模式**（Original Mode）单级 ACK，MSA-1 ∈ {`AA`,`AE`,`AR`}；TLS/TCP 加密载体（HL7 over TLS）不在本版；Z 段（厂商扩展段）**显式声明（在事件 `segments[]` 中配置）即放行透传、不由 profile 自动生成；未显式声明的 Z 段拒绝**（D-3 矛盾解决：Validate 段表白名单对以 Z 开头的段名要求显式配置标志，负例 `hl7_neg_z_segment_unconfigured`）。**流关联显式不适用**（理由见 §4 五层覆盖结论；HL7 无控制流派生数据流，该声明经复验合理保留）；**并发会话（`concurrent: true`）纳入覆盖**（v2.1 翻案，C-1，cwmp⑦/doh #27 同判例）：MLLP 连接内单消息串行确认约束的是单个会话内部，不约束生成器级多连接交错——`hl7_concurrent_sessions` 双会话交错回放（§5.4）。

当前仓库已注册 `hl7` layer、planner、validator 与终结层 generator；`tcp→hl7` 层链及 95 例的配置形状已有代码接线。本次闭环只完成文档与 JSON 静态核对，未运行协议套件、Go 测试、服务端或 NIC/PCAP；因此不能把静态接线等同于 95 例线上语义已通过。

**pcap/NIC 双输出契约**：pcap 与 `port_group`/NIC 两种输出路径使用同一份用例契约——同一组语义 ID、同一包数约定、同一断言集（fields/frames），不含输出路径专有断言；NIC 路径的抓包口差异不改变任何用例语义（C-7，与 64-cwmp/66-doh 同形）。

**动态值不硬编码**：Message Control ID（MSH-10）、消息时间（MSH-7/EVN-2）、患者标识（PID-3）、ACK 的控制 ID 均为运行期/配置策略值，断言用 `presence`、`nonzero`、`distinct_values`、`same_as_packet` 与稳定长度/格式；只有协议常量（分隔符字节、0x0b/0x1c 0x0d、默认端口 2575、确认码 `AA/AE/AR`）可固定。HL7 文本以 ASCII/UTF-8 字节长度与字节边界为准，不以字符数代替 TCP/MLLP 字节长度。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[tcp, hl7]`（引擎自动补 `ip`；需显式地址族时写 `[ip, tcp, hl7]` 或 `[ipv6, tcp, hl7]`）。`hl7` 为 terminal layer，在其上产出 MLLP 帧与消息序列。默认目标端口 **2575**（IANA 登记 hl7）；tshark 3.6.14 实测 hl7 dissector 绑定 `tcp.port 2575`（`-G decodes`：`tcp.port 2575 hl7`），2575 载荷自动按 hl7 解码。端口可被配置覆盖，但 planner 不得悄然改写；**非默认端口为显式正例落点**（`hl7_port_nondefault`，C-3）——实测非 2575 载荷 tshark 不按 hl7 解码（D-4），该例断言带 `-d tcp.port==<N>,hl7` DecodeAs 提示或全 frames hex。**载体只能是 TCP**（负例：UDP 载体、层链缺 tcp、非法端口一律拒绝；端口数值本身显式配置即合法，无「非 2575 且未显式配置」形态——D-2 删除不可达输入）。

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
- 正文中出现未转义的 `0x1c` 会在错误位置闭合帧（dissector 按第一个 `0x1c 0x0d` 找 EOB）——正文控制字节必须转义（§3.3）或视为 framing 错误（负例 `hl7_neg_framing_control_byte`）。
- tshark 实测行为（3.6.14，构造 pcap 实证，D-4 实测口径修正）：**解码门 = 端口绑定 + dissector 内部校验**——2575 载荷自动按 hl7 解码（`tcp.port 2575 hl7`）；非 2575 载荷**必须 `-d tcp.port==<N>,hl7` DecodeAs 提示**（harness 已实证支持）。登记在册的启发式（`-G heuristic-decodes` 的 `tcp hl7 T`）实测**不触发**（端口 6666 上教科书级 `0x0b+MSH|...+1c 0d` 帧不解码、frame.protocols 停在 tcp；2575 上非 `0x0b` 载荷也无 hl7 节点）——「启发式扫描 0x0b+MSH|」的旧声明被实测证伪。dissector 在字节流中搜索 `0x1c 0x0d` 作为 EOB；段边界按 CR/LF/CRLF 任一识别（本版生成器一律用 CR）。

### 3.2 HL7 段/字段/组件/重复/子组件（v2.x Chapter 2）

- **段（Segment）**：3 字符段 ID（`MSH`、`EVN`、`PID`、`PV1`、`SCH`、`AIS`、`OBR`、`OBX`、`MSA`、`ERR`）+ 字段序列，段以 CR 结尾。消息最外层必须以 `MSH` 开始；段顺序按消息结构（MSH-9 第三组件声明）固定。
- **字段分隔符（MSH-1）**：`|`。非 MSH 段的第一个字段即字段 1；**MSH 段特殊**：`MSH` 后紧跟的第 1 个 `|` 是 MSH-1 字段分隔符本身，紧随其后的 4 字符是 MSH-2。
- **编码字符（MSH-2）**：4 个字符按顺序 = 组件分隔符（`^`）、重复分隔符（`~`）、转义字符（`\`）、子组件分隔符（`&`）。正文实际分隔符必须与 MSH-2 声明一致（负例 `hl7_neg_separator_mismatch`）。
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

**转义边界**：转义序列只解释字面值，不改变字段/组件/重复结构；未转义的控制字节（`0x0b`/`0x1c` 落入正文）违反 framing；`\X..\` 的十六进制须成对合法，非法转义序列属字段级错误（负例 `hl7_neg_escape_invalid`）。本版正例断言转义文本以原样字节落线且**不**产生真实分隔符/MLLP 控制字节。

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
| MSH-11 | 处理 ID | PT | 3 | `P`(Production 生产)/`T`(Training 培训)/`D`(Debugging 调试)——v2.5 Table 0103 官方值域，N-2 修正 | 配置（默认 `P`） |
| MSH-12 | 版本 ID | VID | 60 | `2.5`/`2.8` 等（常用 3 字符） | 配置 |
| MSH-15 | 接受确认类型 | ID | 2 | `AL`/`NE`/`ER`/`SU`（增强模式用，本版可留空） | 留空 |
| MSH-16 | 应用确认类型 | ID | 2 | 同上 | 留空 |

MSH-15/16 留空 = 未声明两级确认期望；本版确认语义由 profile 统一约定（§5 自动派生），不依赖 MSH-15/16。

**MSH 渲染派生规则（D-5，代码可生成级）**：①**尾随空槽策略**——MSH 段渲染截至最后非空字段（MSH-15/16 留空时不输出尾随空槽，段终止 CR 紧随 MSH-12 值）；中段空字段保留空槽（`||`，不折叠，§3.8）。②**timestamp 渲染规则**——`timestamp` 策略的 epoch 秒按 **UTC 渲染为 `YYYYMMDDHHMMSS` 定宽 14 位**（无小数/时区后缀的缺省形态）；fixture 可显式给出任意 TS 语法合法串（含 `.SSSS±ZZZZ`）。③**MSH-7 上界注**——数据字典 textual 长度 26 为 validator 长度上界；TS 语法最长合法形态为 24 字符（`YYYYMMDDHHMMSS.SSSS±ZZZZ`），边界例取语法最长形态，不构造语法非法串。

### 3.5 常用业务段（v2.x 对应章节）

| 段 | 现网角色 | 关键字段（本版断言/生成） |
|---|---|---|
| `EVN` | ADT 事件段 | EVN-1 事件类型码（`A01`/`A02`/`A03`，**须与 MSH-9 触发事件一致——Validate 校验项（C-13），不一致负例 `hl7_neg_event_mismatch`**）、EVN-2 事件记录时间（运行期） |
| `PID` | 患者段 | PID-1 集合 ID(`1`)、PID-3 患者标识列表（CX，运行期/策略，可重复 `~`）、PID-5 患者姓名（XPN，组件结构 `姓^名^中间名`）、PID-7 出生日期、PID-8 性别 |
| `PV1` | 就诊段 | PV1-1 集合 ID(`1`)、PV1-2 就诊类别(`I` 住院/`O` 门诊/`E` 急诊)、PV1-3 就诊位置（PL，组件 `机构^病房^床位`，A02 变更此字段）、PV1-36 离院方式（A03）、PV1-44 入院时间、PV1-45 离院时间（A03） |
| `SCH` | 预约头段（SIU） | SCH-1 placer 预约 ID（EI，`&` 子组件）、SCH-2 filler 预约 ID、**SCH-4 预约原因**（v2.5，RE）、**SCH-10 开始日期/时间**（TQ，R）、**SCH-11 结束日期/时间**（TQ，O）——D-1 按 v2.5 Chapter 10 修正字段号 |
| `AIS` | 预约服务段（SIU） | AIS-1 集合 ID、**AIS-3 通用服务标识 USI**（CE；AIS-2 Segment Action Code v2.4 已废为 B）——D-1 按 v2.5 修正 |
| `OBR` | 检验/医嘱请求段（ORU） | OBR-1 集合 ID、OBR-2 placer 医嘱号（EI）、OBR-3 filler 医嘱号（EI）、OBR-4 通用服务标识（CE：`码^文本^LOINC`）、OBR-7 标本采集/观察时间、OBR-25 结果状态（`P`/`F`/`C`） |
| `OBX` | 结果段（ORU，可多段） | OBX-1 集合 ID（递增）、OBX-2 值类型（`ST`/`NM`/`CE`/…）、OBX-3 观察标识（CE：`LOINC码^文本^LN`）、OBX-5 观察值（按值类型）、OBX-6 单位（CE）、OBX-7 参考范围、OBX-11 结果状态（`F`/`P`/`C`） |
| `MSA` | 确认段（ACK/NAK） | MSA-1 确认码（`AA`/`AE`/`AR`）、MSA-2 原消息控制 ID（= 被确认消息的 MSH-10，**事务关联**）、MSA-3 文本消息（可选） |
| `ERR` | 错误段（NAK 可选） | **ERR-2 错误位置**（ERL，v2.5；ERR-1=Error Code and Location 复合 ELD——N-3 修正）、ERR-3 HL7 错误码（HL70357 域，如 `200`=Unsupported message type）、ERR-4 严重级（`E`/`W`/`I`）、**ERR-5 本地应用错误码**（CWE，本地码——非 HL70357 域）+ 文本 |

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
...                0D                                                          CR 段终止（N-1 修正：单字节 0x0D，原文误作 ASCII "0D" 两字节）
...                45 56 4E 7C 41 30 31 7C ... 0D                           "EVN|A01|..." CR
...                50 49 44 7C ... 0D                                        "PID|..." CR
...                50 56 31 7C ... 0D                                        "PV1|..." CR（最后一段）
末 2 字节:         1C 0D                                                  FS CR 结束块
```

按公式：上例 4 段（MSH/EVN/PID/PV1），`len(frame) = 1 + Σ(len(seg)+1) + 2`。断言基线：TCP payload 首字节 = `0x0b`，末两字节 = `0x1c 0x0d`——**一律以 frames hex 断言**；`hl7.llp.sob`/`hl7.llp.eob` 受 tshark 偏好门控且断言 harness 不支持 `-o` 传参，不用作断言字段（§3.9 实测）。

### 3.7 端序与数值编码

HL7 v2 文本线格式**全部为 ASCII 文本**，无字节端序概念；数值（集合 ID、MSA-1 码、时间戳）都是文本。唯一涉及多字节的是 MLLP 结束块 `0x1c 0x0d`（FS CR）与 dissector 的 `hl7.llp.eob` FT_UINT16 显示值——线上字节序固定为 `1c 0d`（FS 在前 CR 在后）；实测（偏好开启后，§3.9）显示值为 `0x1c0d`（FS、CR 两字节拼合），无需再校准。

### 3.8 数据场景要点

- **MSH-12 版本值域**：`2.5`/`2.8` 均合法，版本只影响声明与字段规则，不可绕过必需字段（MSH-9/10/11/12 缺失负例族 `hl7_neg_msh9_missing` 等）。
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
- **ACK 语义（原确认模式）**：`AA` = 应用接受；`AE` = 应用错误（已接收未处理，带 ERR）；`AR` = 应用拒绝。`AA` 是成功确认；`AE`/`AR` 是 NAK 语义（派生 ACK 关联错误负例 `hl7_neg_ack_msa2_mismatch`、确认码非法负例 `hl7_neg_ack_code_invalid`）。

### 5.2 自动派生规则（自动应答，逐条显式，不依赖隐含知识）

`ack_mode` 取值与派生行为：

| `ack_mode` | 行为 | 触发 |
|---|---|---|
| `auto`（默认） | 每条消息事件后自动派生一条 ACK 响应帧 | 反应性自动应答 |
| `{code: "AE"/"AR", err_segments: [...]}` | 自动派生 ACK，MSA-1=指定码，可附 ERR 段 | 同上 |
| `null` | 不派生 ACK 帧（单发/批量场景） | 关闭自动应答 |

**自动派生 ACK 的内容（逐条）**：① MLLP 封装 `0x0b ... 0x1c 0x0d`；② 方向反转（请求 c2s → ACK s2c）；③ MSH-1/MSH-2 与请求相同（`\|`、`^~\&`）；④ MSH-3/4 = 请求 MSH-5/6（收发应用对调），MSH-5/6 = 请求 MSH-3/4；⑤ MSH-7 = 新运行期时间戳；⑥ MSH-9 = `ACK^<请求触发事件>^ACK`；⑦ MSH-10 = 新运行期控制 ID（**与请求 MSH-10 不同**，`distinct`）；⑧ MSH-11 = 同请求；⑨ MSH-12 = 同请求；⑩ MSA-1 = 确认码（默认 `AA`）；⑪ **MSA-2 = 请求 MSH-10（原样复制，`same_as_packet`）**；⑫ 配置 ERR 段时按 §3.5 编码追加。派生规则确定性：同一配置 + 同一事件必然同一形状（仅运行期策略值变化）。

**驱动顺序**：`events[]` 显式声明每条消息；`ack_mode` 决定 ACK 是否/如何自动补出。**无自动补帧的情况显式写出**：`ack_mode=null` 时引擎不补 ACK（ACK 缺段负例 `hl7_neg_ack_no_msa`，不得把缺 ACK 当自动补全）。多会话 = 多连接，状态互不串用（§8）。

### 5.3 会话状态机（每个事件编排会话独立一份）

| 状态 | 允许事件 | 必须保持 |
|---|---|---|
| `Connecting` | TCP 握手（SYN/SYN-ACK/ACK） | 握手完成前不得产出 MLLP 字节 |
| `Established`（idle） | 发送/接收一条完整 MLLP 帧 | 帧完整判定：`0x0b` 起始 + `0x1c 0x0d` 终止（按方向字节流缓冲）；MSH 必为首段 |
| `TxPending`（消息已发） | 自动派生 ACK（`ack_mode=auto/显式`）；`ack_mode=null` 直接回 idle | ACK 的 MSA-2 必须等于本消息 MSH-10；MSH-10 不得复用 |
| `Acked`（确认已出） | 下一条消息 | 控制 ID 空间递增不重复 |
| `Closing` | FIN/ACK 挥手 | 事件序列结束才关连接；关闭后不得产生新业务帧 |
| `Closed` | — | 连接关闭，会话结束 |

**帧组装子状态（每方向独立）**：`WaitSOB`（等 `0x0b`）→ `InMessage`（累积字节，遇 `0x1c 0x0d` 判定完整）→ 校验 MSH 首段与段 CR。截断帧（无 `0x1c 0x0d` 即 TCP 关闭/流结束）属 framing 错误（负例 `hl7_neg_framing_eob_missing`）。

### 5.4 连接生命周期与多会话

- 连接生命周期：建立（3 包握手）→ 持续多事务（消息→ACK 循环，可 0 或多笔）→ 关闭（FIN/ACK×2）。连接在 events[] 结束时关闭，不提前、不延后。
- **多会话展开**：`sessions[]` 数组按序**整块**回放——先跑完第 1 个会话全流程（握手→事件→挥手）再跑下一个，不交错；第二会话包号起点 = 前会话总包数 + 1。每个会话独立四元组、独立控制 ID 空间、独立 PID/时间策略，状态互不串用（`hl7_multi_session_isolation`）。
- **并发会话（`concurrent: true`）纳入覆盖**（v2.1 翻案，C-1）：MLLP 连接内单消息串行确认约束的是单个会话内部的事务交替，不约束生成器级多连接交错——`hl7_concurrent_sessions` 双客户端四元组交错回放，断言 MSH-10/PID-3/MSA-2 配对互不串用。
- **异常中断声明**（C-12）：本协议挥手统一 FIN/ACK×2 正常序列，`hl7` 层不产生 RST（传输层注入面非本协议语义，与 64-cwmp/66-doh 同形）；生成器不在会话中途注入 RST，异常中断场景不设用例。
- **流关联显式不适用**：HL7 无控制流派生数据流/媒体流；MSA-2 是事务关联标识，不是流关联锚点（见 §4 五层覆盖结论）。

## 6. 配置 typedef（JSON 形状契约，非现有 Go 结构）

顶层遵循层链配置；`hl7` 子映射承载协议语义。事件编排会话（`sessions[]`）各自带四元组与事件序列，按序整块回放（多会话展开）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.68", "dst": "198.51.100.68"}},
    {"tcp": {"src_port": 42680, "dst_port": 2575}},
    {"hl7": {
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
             {"name": "SCH", "fields": [["APPT-9001&HIS"], [], [], ["SURGERY"], [], [], [], [], [], ["@ts"], ["@ts"]]},
             {"name": "AIS", "fields": [["1"], [], ["MRI^MRI Scan^LN"]]}
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
| `field_separator` / `encoding_chars` | 默认 `\|`、`^~\&`；`encoding_chars` 必须恰 4 字符（组件/重复/转义/子组件），正文分隔符必须与声明一致（负例 `hl7_neg_separator_mismatch`） |
| `ack_mode` | `auto` / `{code, err_segments}` / `null`（§5.2）；`null` 时引擎不补 ACK |
| `sessions[]` | 事件编排会话：四元组 + `role`（`sender`/`receiver`）+ `events[]`；多会话按序整块回放，第二会话包号起点 = 前会话总包数 + 1 |
| `events[]` | 事件序列；`kind=msg`、`direction=c2s/s2c`；一个事件一条完整 MLLP 消息（`message_type` 3 组件 + `segments[]`） |
| `segments[].fields` | 字段值数组；`@ts`/`@pid`/`@name`/`@cid` 为运行期占位（timestamp/patient_id/control_id 策略替换）；空槽 `[]` 表示空字段；段以 CR 结尾、帧自动封装 MLLP |
| `ack`（消息级） | 覆盖会话级 `ack_mode`：`"auto"` / `{"code":...}` / `null` |
| `wire_fault` | 仅负例注入口（**32 个显式配置值 + 1 个载体形态**`carrier_udp`；与 §7 表/用例文档 §5 的 33 个负例一一对应，v2.1 逐故障输入原子拆分，C-2）：`framing_sob_missing`/`framing_eob_missing`/`framing_eob_malformed`/`framing_control_byte`/`segment_first_not_msh`/`segment_no_cr`/`segment_after_eob`/`segment_name_invalid`/`msh1_invalid`/`msh2_invalid`/`separator_mismatch`/`escape_invalid`/`msh9_missing`/`msh10_missing`/`msh11_missing`/`msh12_missing`/`msh9_domain`/`ack_msa2_mismatch`/`ack_no_msh9`/`ack_no_msa`/`ack_code_invalid`/`carrier_udp`/`carrier_no_tcp`/`port_invalid`/`len_msh9`/`len_msh10`/`len_msh12`/`len_msh7`/`len_msa2`/`event_mismatch`/`address_family_mixed`/`required_segment_missing`/`z_segment_unconfigured`，不得成为线上字段 |

`Validate` 必须覆盖：profile/version/分隔符声明与正文一致性、MSH 必为首段、MSH-9/10/11/12 存在、消息类型 3 组件合法（§3.4）、段名 ∈ 已知段表 ∪ 显式声明的 Z 段（D-3）、**EVN-1 与 MSH-9 触发事件一致（C-13，负例 `hl7_neg_event_mismatch`）**、**每消息类型必需业务段集校验（D-6，显式声明：ADT^A01/A02/A03 必需 EVN+PID+PV1、ORU^R01 必需 OBR、SIU^S12 必需 SCH+AIS，缺失拒绝——负例 `hl7_neg_required_segment_missing`）**、**地址族与层链字面量一致（C-11：`[ipv6]` 层配 IPv4 字面量拒绝，负例 `hl7_neg_address_family_mixed`）**、`ack` 配置合法（`auto`/码/`null`）、控制 ID 空间会话内唯一、多会话四元组独立、wire_fault 仅注入不落线。

## 7. 错误处理（负例锚词表）

以下输入必须由 planner/validator 拒绝并传播为 task error（任务错误），不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。负例执行期 `expect` 严格只有 `expect_error` 与 `error_contains`。锚词（anchor word）为错误文案必须包含的关键词，主锚词钉死（备选供实现期校准，N-4），validator 实现与用例文档 §5 共用本表；**逐故障输入原子拆分：一行一例、钉死单一注入**（C-2）：

| 负例 ID | `wire_fault` 注入口（v2.1，33 值） | 故障输入（单一注入） | `error_contains` 主锚词（备选） | 依据 |
|---|---|---|---|---|
| `hl7_neg_framing_sob_missing` | `framing_sob_missing` | 载荷缺起始块 `0x0b`（直接以 `MSH|` 开头） | `mllp`（framing） | MLLP |
| `hl7_neg_framing_eob_missing` | `framing_eob_missing` | 帧未闭合：流结束无 `0x1c 0x0d`（截断帧） | `mllp`（framing） | MLLP |
| `hl7_neg_framing_eob_malformed` | `framing_eob_malformed` | 结束块形态错：`0x1c` 后无 `0x0d` | `mllp`（framing） | MLLP |
| `hl7_neg_framing_control_byte` | `framing_control_byte` | 正文出现未转义 `0x1c`（提前闭合 EOB；同族备选 `0x0b`） | `mllp`（framing） | MLLP+设计§3.3 |
| `hl7_neg_segment_first_not_msh` | `segment_first_not_msh` | 首段非 MSH（如 EVN 开头） | `msh`（segment） | 设计§3.2 |
| `hl7_neg_segment_no_cr` | `segment_no_cr` | 段未以 CR 结尾 | `segment`（msh） | 设计§3.2 |
| `hl7_neg_segment_after_eob` | `segment_after_eob` | `0x1c 0x0d` 之后追加段 | `segment`（msh） | 设计§3.1 |
| `hl7_neg_segment_name_invalid` | `segment_name_invalid` | 段名非法（非 3 字符/未知段名） | `segment`（msh） | 设计§3.2 |
| `hl7_neg_msh1_invalid` | `msh1_invalid` | MSH-1 缺失或长度≠1 | `separator`（field） | 设计§3.2 |
| `hl7_neg_msh2_invalid` | `msh2_invalid` | MSH-2 长度≠4 | `separator`（field） | 设计§3.2 |
| `hl7_neg_separator_mismatch` | `separator_mismatch` | 正文实际分隔符与 MSH-2 声明不一致 | `separator`（field） | 设计§3.2 |
| `hl7_neg_escape_invalid` | `escape_invalid` | 非法转义序列（`\X` 十六进制不成对） | `escape`（field） | 设计§3.3 |
| `hl7_neg_msh9_missing` | `msh9_missing` | MSH-9 缺失 | `msh`（required） | 设计§3.4 |
| `hl7_neg_msh10_missing` | `msh10_missing` | MSH-10 缺失 | `msh`（required） | 设计§3.4 |
| `hl7_neg_msh11_missing` | `msh11_missing` | MSH-11 缺失 | `msh`（required） | 设计§3.4 |
| `hl7_neg_msh12_missing` | `msh12_missing` | MSH-12 缺失 | `msh`（required） | 设计§3.4 |
| `hl7_neg_msh9_domain` | `msh9_domain` | MSH-9 消息代码/触发事件不在值域（如 `XYZ^Q99^XYZ_Q99`） | `msh`（type） | 设计§3.4 |
| `hl7_neg_ack_msa2_mismatch` | `ack_msa2_mismatch` | 派生 ACK 的 MSA-2 ≠ 请求 MSH-10 | `ack`（correlation） | 设计§5.1 |
| `hl7_neg_ack_no_msh9` | `ack_no_msh9` | ACK 缺 MSH-9=ACK | `ack`（correlation） | 设计§5.2⑥ |
| `hl7_neg_ack_no_msa` | `ack_no_msa` | ACK 缺 MSA 段 | `ack`（msa） | 设计§3.5 |
| `hl7_neg_ack_code_invalid` | `ack_code_invalid` | MSA-1 确认码非 AA/AE/AR（如 `XX`） | `ack`（correlation） | 设计§3.8 |
| `hl7_neg_carrier_udp` | `carrier_udp` | UDP 载体（层链 `[{"udp":{}},{"hl7":{}}]`） | `carrier`（transport） | 设计§2 |
| `hl7_neg_carrier_no_tcp` | `carrier_no_tcp` | 层链缺 tcp（hl7 直连 ip） | `layer`（carrier） | 设计§2 |
| `hl7_neg_port_invalid` | `port_invalid` | 非法端口（0/65536） | `port`（transport） | 设计§2 |
| `hl7_neg_len_msh9` | `len_msh9` | MSH-9 >15 字符 | `length`（limit） | 设计§8 |
| `hl7_neg_len_msh10` | `len_msh10` | MSH-10 >20 字符 | `length`（limit） | 设计§8 |
| `hl7_neg_len_msh12` | `len_msh12` | MSH-12 >60 字符 | `length`（limit） | 设计§8 |
| `hl7_neg_len_msh7` | `len_msh7` | MSH-7 >26 字符（textual 上界） | `length`（limit） | 设计§8 |
| `hl7_neg_len_msa2` | `len_msa2` | MSA-2 >20 字符 | `length`（limit） | 设计§8 |
| `hl7_neg_event_mismatch` | `event_mismatch` | EVN-1 与 MSH-9 触发事件不一致（MSH-9=ADT^A01 + `EVN|A02|`，C-13 失败用例先行） | `event`（consistency） | 设计§3.5 |
| `hl7_neg_address_family_mixed` | `address_family_mixed` | 地址族混合：`[ipv6]` 层配 IPv4 字面量（C-11） | `address`（family） | 设计§6 |
| `hl7_neg_required_segment_missing` | `required_segment_missing` | ADT^A01 缺必需业务段 PID（D-6：按 MSH-9 结构声明必需段集） | `segment`（required） | 设计§6 Validate v2.1 |
| `hl7_neg_z_segment_unconfigured` | `z_segment_unconfigured` | 未显式声明的 Z 段（段表白名单外且无 allow 标志，D-3 联动） | `z`（segment） | 设计§1 v2.1/§6 |

**不得误报为 planner error 的合法协议事件**：合法转义序列（`\F\` 等）、重复字段/重复 OBX、空可选字段（`||` 空槽）、TCP 分段/粘连/多帧同段、IPv4/IPv6 双栈、ACK `AA` 与 NAK `AE`/`AR` 合法确认码、`ack_mode=null` 无 ACK 帧、动态控制 ID/时间/PID、`MSH-15/16` 留空、字段长度恰等上界（如 MSH-10 恰 20 字符——边界值合法，越界才拒绝）。只有配置错、线格式错、段/字段结构错、必需字段错、确认关联错、载体端口错、长度上界错进入负例。错误保留最具体来源从 planner 传到 task；不得自动补齐缺失 ID、不得把非法消息重排成合法顺序、不得跨事务代答。

## 8. 边界

- **字段/段长度上界**（v2.5 数据字典）：MSH-9 ≤15、MSH-10 ≤20、MSH-12 ≤60（常用 3）、MSA-2 ≤20、MSH-7 ≤26（textual 上界；语法最长合法形态 24，见 §3.4 注）；段名恰 3 字符。超界属配置错误（validator 拒绝，不静默截断；**逐字段负例 `hl7_neg_len_*` 五行**，恰等上界为合法边界值不拒绝——边界正例 #55-58）**——v2.1 起负例按字段拆分为 `len_msh9`/`len_msh10`/`len_msh12`/`len_msh7`/`len_msa2` 五行（C-2/D-2）**。
- **MLLP 帧完整与截断**：完整帧 = `0x0b` 起始 + `0x1c 0x0d` 终止；截断（缺 FS/CR）→ 负例 `hl7_neg_framing_eob_missing`。正文含未转义 `0x1c` 会提前闭合帧，必须转义（§3.3）。
- **转义边界**：转义序列只解释字面值，不产生真实分隔符/MLLP 控制字节；`\Xdd..\` 十六进制须成对合法；非法转义进负例。
- **超长消息跨 MSS**：长消息按 TCP 分段重组后以完整 MLLP 帧解析（`hl7_tcp_mss_reassembly`）；**segment 边界 ≠ 消息边界**；一个 segment 可承载多帧，不得按 segment 数推断消息数。
- **IPv4/IPv6**：双栈独立 fixture；数据承载段应用起点 offset 54/74（§2）；外层 IP 头不同，MLLP/HL7 字节一致（`hl7_ipv6_transport`）。
- **多会话双四元组**：≥2 个独立四元组；控制 ID 空间、PID/时间策略、帧缓冲按会话隔离；多会话展开按序整块回放，第二会话包号起点 = 前会话总包数 + 1（`hl7_multi_session_isolation`）。
- **多事务**：同一连接多笔消息→ACK，MSH-10 各自 distinct、MSA-2 各自配对、连接持续到事件结束（`hl7_multi_transaction_long_connection`）。
- **动态值**：MSH-10/MSA-2 关联用 same_as、跨消息/会话用 distinct、MSH-7/EVN-2/PID-3 用 presence/nonzero；不得硬编码运行期值，不得产生回绕长度或超量分配。

## 9. 原子 ID 与完成定义

**ID 权威（v1.3 行为面全枚举）**：语义用例 ID 清单以**用例文档 §2 为唯一权威**（v2.1 起按可测试行为面全枚举扩量：**95 条 = 62 正例 + 33 负例**，对应 rr-hl7 枚举 145 行为面点）；本节不再维护 ID 逐条表（v2.0.x 的 25 ID 表见 git 历史）。设计、用例文档与当前 `hl7.json` 使用同一组唯一 ID 与顺序（JSON 实为 95 例，与本文一一对应，无额外占位）。约定 packet_count（正例）：TCP = 3（握手）+ 每笔消息→ACK 2 包（请求 1 段 + ACK 1 段）+ 4（FIN/ACK×2）；`ack_mode=null` 的消息只 1 包；跨段每加 1 段 +1；多会话/并发 = 各会话之和。实现期以实际输出校准，断言以 fields/frames 为准。正例面：消息类型族（ADT 三事件/ORU/SIU/NAK 双形态/ACK 派生规则 §5.2 逐条/s2c/最小 ACK）、编码族（转义 8 序列逐序列、组件/子组件/重复/CX、MLLP 帧字节+帧长公式、自定义分隔符/编码字符）、MSH 字段族（app/fac、TS 格式、三组件、MSH-8 空/非空、MSH-15/16 尾随策略、P/T/D）、段结构族（集合 ID、Z 段透传、ERR 字段、MSA-3）、值域族（PV1-2 I/O/E、OBX-2、结果状态 F/P/C）、边界族（恰等上界 ×4）、载体/会话族（v4/v6、v6 多事务、多会话、并发会话、非默认端口、多帧粘连、inc 策略）。负例面：§7 表 33 行逐故障输入。

**完成定义**：注册 `tcp→hl7` 层链（含 IPv6）；按 §3 逐字段生成 HL7 文本消息与 MLLP 帧；事务关联（MSH-10 分配 + MSA-2 配对）与 §5.2 自动派生规则生效；TCP 字节流重组与 MLLP 帧完整判定可观测；IPv4/IPv6、多会话展开、多事务长连接、MSS 分段与边界均可观测；95 个语义 ID（62 正 + 33 负）正负断言与错误传播（锚词表 §7，33 行主锚词钉死）完成；实现后逐条对照 tshark `hl7.*` 实测字段校准并同步四件套（设计/testcase/JSON/audit）。

## 10. P1 规范矩阵与三路对照

### 10.1 八项矩阵（规范要求 → 业务场景 → 代码现状 → 缺口）

| 项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 连接模型 | MLLP over TCP，帧边界独立于 TCP segment | ADT/ORU/SIU、长连接 | HL7 layer 已注册；目标链 `[ip,tcp,hl7]` | H1：已闭环，转套件/NIC 验证 |
| 消息表 | MSH/EVN/PID/PV1、OBR/OBX、SCH/AIS、ACK/MSA/ERR | #1–#8、#21 | 事件模型已落码 | H2：已闭环，转套件/NIC 验证 |
| 状态机 | 建连→消息→确认→关闭；同连接多事务 | #21、#24、#30 | 目标 `sessions[].events[]` 顺序模型 | H3：会话执行 |
| 字段表 | MSH-1..12、业务段字段、MLLP 控制字节 | #9–#20、#39–#60 | 设计字段表与边界已列 | H4：字段校验 |
| 错误处理 | framing、段、载体、长度、关联错误必须失败 | #63–#95 | 32 个 `wire_fault` 显式值 + 载体形态 UDP 例；错误传播待实跑 | H5：错误传播（待实跑） |
| 活性 | TCP 长连接可承载多轮消息；MLLP 无自有保活 | #21、#32、#61 | events 顺序支持多轮；未实现重试 | H6：真实链路验证 |
| NAT/代理 | MLLP 本身无代理/被动数据流语义 | #25/#26 多会话 | 四元组按会话隔离 | H7：多会话验证 |
| 版本方言 | HL7 v2.5/v2.8、TCP 默认 2575、IPv4/v6 | #23/#24/#27/#28 | 目标 profile 与端口规则已定 | H8：版本/端口校验 |

### 10.2 子表一：消息类型 × 响应码

| 请求消息 | AA | AE | AR | 缺口 |
|---|---|---|---|---|
| ADT^A01/A02/A03 | #1–#3/#6 | #7 | #8 | 无 |
| ORU^R01 | #4/#37 | #7 | #8 | 无 |
| SIU^S12 | #5 | #7 | #8 | 无 |
| ACK/NAK | — | #7 | #8 | ACK 自身不得再派生 ACK，H2 |

### 10.3 子表二：数据形态变体

| 形态 | 用例/结论 |
|---|---|
| IPv4/IPv6 × 单事务/多事务 | #1/#23/#24 |
| 单段、多段、跨 MSS、同段多帧 | #9/#21/#22/#61 |
| 组件/重复/子组件/八类转义 | #10–#20 |
| 空槽、尾随空槽、自定义分隔符 | #43/#44/#48/#49 |
| ACK AA/AE/AR、ERR、MSA-3 | #6–#8/#30/#59/#60 |
| 正常/非正常关闭 | 正常挥手 #1；中途中断 H6（需代码注入） |
| 业务字段边界与越界 | #55–#58、#87–#91 |

### 10.4 子表三：商业行为 → 用例映射

| 行为（来源） | 用例 | 结论 |
|---|---|---|
| HIS→LIS ADT 入院/转科/出院 | #1–#3 | 已覆盖 |
| LIS 检验结果多 OBX | #4/#22 | 已覆盖 |
| 预约系统 SCH/AIS | #5 | 已覆盖 |
| ACK/NAK 互操作 | #6–#8/#30/#37 | 已覆盖 |
| MLLP 长连接批处理 | #21/#32 | 已覆盖 |
| IPv6 与非默认端口部署 | #23/#24/#27 | 已覆盖 |
| 多系统并行连接 | #25/#26 | 已覆盖 |
| 商业 Z 段透传 | #47/#95 | 显式声明后通过，未声明拒绝 |

### 10.5 三路对照与候选方案

| 来源 | 结论 | 证据/用例 |
|---|---|---|
| HL7 v2.5 Chapter 2/9/10 + MLLP 指南 | MSH 首段、CR 分段、VT/FS-CR framing、MSA 关联 | §3、#9、#63–#74 |
| 商业 HIS/LIS 常见行为 | TCP 2575、ADT/ORU/SIU、ACK/NAK、多轮长连接 | #1–#8/#21；真实产品抓包待确认 H6 |
| 开源实现思路 | 分层 parser：先 MLLP framing，再段/字段，再业务校验 | 目标 planner；实现前不得声称互操作 |

| 方案 | 优点 | 代价 | 结论 |
|---|---|---|---|
| A：`[ip,tcp,hl7]` 终结层 + events | 层链单一真相、按会话流式生成 | 需新增 HL7 parser/planner | 采用 |
| B：复用通用 TCP payload 原文 | 改动小、可回放固定 bytes | 无业务字段校验、动态 ACK 难表达 | 不采用 |

## 11. P2 代码设计（八要素）

1. **文件**：新增 `trafficgen/internal/protocol/hl7/` planner、builder、layer generator 与测试；接线 registry/schema/translate/Meta/main；更新三件本协议产物。2. **接口**：`Validate(spec core.FlowSpec) error`、`Plan(ctx, spec) (<-chan core.PacketConfig,error)`、终结层 `Generate`/`GenEvents`。3. **结构**：`HL7Config{Profile,Version,FieldSeparator,EncodingChars,AckMode,Sessions,WireFault}`；`Session{四元组,Role,Events}`；`Event{Direction,MessageType,Segments,Ack}`。4. **流程**：校验 profile/载体/字段 → 建 TCP → 按 events 渲染 MSH 与业务段 → MLLP 封装 → 自动 ACK → 长连接关闭。5. **错误**：33 个 wire_fault 各自单一拒绝锚词，错误传到 task error，不生成成功 PCAP。6. **性能边界**：事件与帧逐项流式生成；队列有界；单条消息按 MSS 分段；不得聚合全会话 payload。7. **冲突点**：HL7 terminal layer 不得放顶层业务映射；`MSH-10`/`MSA-2` 只能按事务关联；不能把 TCP segment 数当消息数。8. **回滚**：只回退 HL7 新增接线与三件本协议产物，不修改共享协议语义。

## 12. 动态字段清单

| 字段 | 住处 | 策略 | 序号/理由 |
|---|---|---|---|
| `ip.src`/`ip.dst` | ip 层 | fixed/inc/rand/list/pattern | 按 flow index 解析，地址族保持一致 |
| `tcp.src_port`/`tcp.dst_port` | tcp 层 | fixed/inc/rand/list/pattern | src 未写时 `12345+i` 保底；dst 默认 2575 |
| `MSH-10` / `MSA-2` | hl7 event | control_id fixed/inc/rand/list/pattern；MSA-2 same_as | 每会话事务序号 i；ACK 复制本事务请求 ID |
| `MSH-7` / `EVN-2` | hl7 event | timestamp fixed/rand/inc | epoch 按 UTC 渲染 14 位；同一 i 可复现 |
| `PID-3` | PID 字段 | fixed/inc/rand/list/pattern | 按 flow index 替换 `@pid`；未写则 fixed |
| `segments[].fields` 业务值 | hl7 层 | fixed/list/pattern；其余未实现前置 H4 | 消息编排不能靠复制冒充多事务 |

未写动态时按 fixed；`flows>1` 且四元组全静态须拒绝或告警。动态值始终住在对应层/事件字段，不新增顶层键。

## 13. 门1 §1–§14 对照表

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 | 地址/端口在 ip/tcp，业务在 hl7，数量走 flow_control；正例顶层仅 layers | §6、cases 全量扫描 |
| §2 | 策略单 HL7 模板，任务负责总量封顶 | §12 |
| §3 | sessions/events、事务 ACK 关联、无派生数据流、顺序/并发已写 | §4/§5/§11 |
| §4 | HL7 v2.5/MLLP + 三路对照 + 三子表 | §10 |
| §5 | 依赖 ip/tcp 前置状态，33 个错误锚词 | §7 |
| §6 | 流式帧、边界性能、pcap/NIC 双路验收 | §6（下节） |
| §7 | 设计、用例、JSON 三份本协议产物互相对账 | §9/用例§8 |
| §8 | 八要素已列 | §11 |
| §9 | 95 ID 三源回指、正负例与失败路径 | 用例§2/§5 |
| §10 | 文档自审与复审后再进入实现 | 修订记录 |
| §11 | 首节给出协议白话边界 | §1 |
| §12 | 四元组与业务动态逐项列策略 | §12 |
| §13 | layer registry/schema 生成后对账 | H1/H8 |
| §14 | MCP→引擎→tshark；未实现前不宣称运行 | 用例§7 |

## 14. 性能设计与缺口立项

流式生成目标：单消息仅保留当前段与当前帧，队列/缓冲沿公共 pipeline 有界；并发会话按独立状态运行；pcap 与真实网卡分别检查帧字节、字段、方向、吞吐、内存、CPU、队列积压和失败。基线/目标规模/压力/长跑/交错/背压六类测试在代码接线完成后仍待实跑，所有数字以落盘 pcap 与测量为准。

| 缺口 | 内容 | 状态 |
|---|---|---|
| H1 | hl7 layer、planner、validator、generator、schema 接线 | 已闭环（静态），转套件/NIC 实跑 |
| H2 | ACK 派生与 MSH-10/MSA-2 关联 | 已落码（layer_gen/dynamic），待实跑（先 #1/#6/#21） |
| H3 | 多会话/并发/异常关闭编排 | 已落码（concurrent 交错），待实跑 #25/#26 与 §3.15 |
| H4 | 字段值域、必需段、Z 段白名单校验 | 已落码（validateSegCommon/必需段集），待实跑 #67–#95 |
| H5 | 33 个错误输入的拒绝文案 | 已落码（wireFaultAnchors 33 锚词），以实跑文案回填 `error_contains`，不得伪造 |
| H6 | 长保活/真实 HIS-LIS 互操作抓包确认 | 未闭环：抓 HL7 v2.5 2575 实际交互包后更新 |
| H7 | IPv6/非默认端口/MSS 重组运行校准 | 待实跑：逐例落盘 pcap/tshark 校准 |

## 15. 改造审计与历史教训核对

### 15.1 机器对账（2026-10-01，`hl7.json` 实测）

95 例 = 62 正 + 33 负，与用例文档 §2/§8 同 ID 同顺序。正例与负例的 `spec_json` 顶层键集合均为 `{layers}`（无顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`、无协议子映射、无 MAC）；层链形状分布 = 94 例 `[ip,tcp,hl7]` + 1 例 `[udp,hl7]`（`hl7_neg_carrier_udp`，故意保留的载体 presence 负例，其拒绝锚词由层链规划器 `chain_planner.go` 返回 `carrier`，非 `wireFaultAnchors` 条目）。33 条负例 `expect` 键集合严格为 `{expect_error,error_contains}`，无 `packet_count`/`frames`/`fields`；32 个 `wire_fault` 锚词与 `protocol/hl7/planner.go` 的 `wireFaultAnchors` 逐值一致，1 个载体形态负例见上。

### 15.2 三个历史教训与现状

- **对象形静默丢弃**：已修正。`internal/core/hl7.go` 的 `coerceAckJSON` 把对象形 `ack_mode`/`ack` 收敛为规范 JSON 文本交给 `parseAckSpec`，不再整块丢配置；`chain_planner_translate.go` 的 hl7 分支解码失败写 `ValidationErrors` 走任务错误，不置空成默认流假成功。
- **唯一解析权威**：已落实。`internal/protocol/hl7/dynamic.go` 的 `dynState` 是会话策略解析与序号解析的唯一权威，planner 校验（`validateSession` 控制 ID 判重、长度门）与 generator 用同一解析结果；`resolveAckSpec` 统一会话级/事件级 ACK 优先级，校验与渲染不分叉。
- **声明夹具失配**：已校正。`registry.go` 声明 hl7 终结层 `DependsOn: [tcp]`、`TransportOn: [tcp]`、`FieldContract: {tcp.dst_port: 2575}`；JSON 正例全为 `[ip,tcp,hl7]`，唯一 `[udp,hl7]` 只作故意拒绝负例，文档声明与用例夹具一致。

### 15.3 性能验收矩阵（pcap 与网卡两路，待运行）

| 场景 | pcap 输出路径验收 | port_group/NIC 输出路径验收 | 资源断言 |
|---|---|---|---|
| 基线/目标规模 | tshark 校验 MLLP 边界、段/字段、方向、`tcp.stream` | 抓包校验同一字段与方向，差异仅抓包口 | 包/秒、比特/秒 |
| 压力上限/长时间运行 | 文件完整性与帧重组、无截断 | 持续抓包无缺帧、无丢包 | 内存上限、CPU 并行度 |
| 并发交错（#25/#26） | 多 `tcp.stream` 事务配对与交错顺序 | 多连接方向与配对 | 队列/缓冲积压 |
| 资源耗尽/背压 | 缓冲满即 task error，不得假成功 | NIC 丢包/失败可见 | 丢包率、失败数 |

六类场景（基线/目标规模/压力上限/长跑/并发交错/背压）逐类两路各一跑；所有数字以落盘 pcap 与 NIC 测量为准，本轮不运行套件/服务/网卡（§14 H6/H7）。

### 15.4 门1 三行展开

- **§1 行（顶层旧键去向 + 完整 spec_json 例）**：本协议顶层旧键为 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count` 与旧扁平协议子映射 `hl7`。去向：地址 → `ip` 层 `src`/`dst`；端口 → `tcp` 层 `src_port`/`dst_port`（缺省 2575）；数量 → `flow_control`；`hl7` 子映射 → `hl7` 终结层（`chain_planner_translate.go` 层 config 分支）。完整例：`{"layers":[{"ip":{"src":"192.0.2.68","dst":"198.51.100.68"}},{"tcp":{"src_port":42680,"dst_port":2575}},{"hl7":{"sessions":[{"events":[{"kind":"msg","direction":"c2s","message_type":"ADT^A01^ADT_A01","segments":[{"name":"EVN","fields":["A01","20260901083045",""]},{"name":"PID","fields":["1","","PAT001^^^HOSP^MR"]},{"name":"PV1","fields":["1","I"]}]}]}]}}]}`（JSON 正例 #1 实形）。
- **§3 行（五件套）**：会话表 = `sessions[]`（每会话独立四元组/控制 ID 空间）；事务序列 = `events[]` 的消息→ACK 有序序列；关联关系 = `MSH-10 ↔ MSA-2`（`same_as_packet`），非控制流派生数据流（HL7 无数据/媒体流，已登记适用性结论）；插入位置 = 每事件 ACK 紧随本事件（`ack_mode=auto/显式码`），`ack_mode=null` 不插入；时间线 = 同连接按 `events[]` 顺序推进，多会话整块回放、`concurrent:true` 按事件序号交错（§5.3/§5.4）。
- **§12 行（动态字段清单 + 序号算法代码位置）**：四元组（`ip.src`/`ip.dst`/`tcp.src_port`/`tcp.dst_port`）五策略齐全；业务字段 `MSH-10`（`control_id`）、`MSA-2`（ACK 复制）、`MSH-7`/`EVN-2`（`timestamp`）、`PID-3`（`patient_id`）各列策略，未实现前置 H4 的 `segments[].fields` 已注记。序号算法代码位置：`internal/protocol/hl7/dynamic.go` 的 `dynState.resolve`（按会话内事件序号解析策略对象）；ACK 关联值由 `internal/protocol/hl7/layer_gen.go` 的 `resolveAckSpec`/`parseAckSpec` 复制请求 MSH-10。

## 16. 修订记录

- v1.0.0（2026-08-20）：旧稿首版（14 正 + 6 负：含 pcap_nic_consistency、v25_v28_version_profiles、multi_flow_dynamic_fields 等 ID）。
- v2.1.1（2026-09-01，复验 V 轮收尾）：rr-hl7 复验 25/27 CLOSED 后 V 系列小修：V-3 §1/§3/§5/§6/§8 散文 11 处旧负例 ID（transport_port/mllp_framing/field_separator/msh_required/ack_correlation）替换为新原子 ID、25→95；V-5 §7 framing_control_byte 行单一注入钉死 `0x1c`。用例侧 V-1/V-2/V-4/V-6 同轮修复（见用例 §9）。修复后送 rr-hl7 关单复验。
- v2.1.0（2026-09-01，v1.3 重审修复轮）：rr-hl7 按《需求文档 v1.3》独立重审（行为面 145 点、2C/8M/12M）后全量修复：①**D-1**（CRITICAL）SCH/AIS 字段号按 v2.5 修正（SCH-4 预约原因/SCH-10 开始/SCH-11 结束、AIS-3 USI——原 SCH-7/11/12 与 AIS-2 为两文档一起偏离规范），§3.5/§6 fixture 同步；②**C-2**（CRITICAL）§7 负例表逐故障输入原子拆分 7→33 行（一行一例单一注入、主锚词钉死 N-4），§6 wire_fault 枚举 33 值一一对齐；③C-1 并发会话翻案纳入（§1/§5.4，`hl7_concurrent_sessions`；流关联/多流不适用声明合理保留）；④C-3+D-4 §2 非默认端口正例落点 + §3.1 实测口径修正（启发式声明被实测证伪，解码门=端口绑定+内部校验、非 2575 须 `-d`）；⑤C-7 §1 pcap/NIC 双输出契约声明；⑥C-12 §5.4 RST 不产生声明；⑦D-2 §7/§2 删除 2 个不可实现输入（「非 2575 且未显式配置」不可达、「把 NAK 当成功」无注入点）；⑧D-3 Z 段规则改「显式声明放行/未声明拒绝」（§1/§6）；⑨C-13 §3.5/§6 EVN-1↔MSH-9 一致性校验行 + 负例；⑩D-6 §6 必需业务段集校验显式声明 + 负例；⑪C-11 §6 地址族混合拒绝；⑫D-5 §3.4 渲染派生规则（尾随空槽截至最后非空字段、epoch→UTC 定宽 14 位、MSH-7 textual 26/语法 24 注）；⑬N-1 §3.6 字节示例段终止 CR 更正为单字节 `0D`；⑭N-2 MSH-11 值域注按 Table 0103 修正（T=Training）；⑮N-3 ERR 行按 v2.5 修正（错误位置=ERR-2/ERL、ERR-5=本地应用码 CWE）；⑯§9 ID 权威改用例文档 §2、总量 95 条（62 正 + 33 负）。
- v2.0.0（2026-08-31）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写/review，取代 2026-08-20 旧稿（旧稿见 git 历史）。相对旧稿的主要变化：①按原子用例原则将 14 正例拆分为 18 个不可再分单元（消息类型 ADT^A01/A02/A03、ORU^R01、SIU^S12 各自成例；MLLP 起止块、组件/子组件、重复、转义、MLLP 帧字节、ACK/NAK、关联、长连接多事务、MSS 重组、IPv6、多会话、版本、确认码值域、ack 关闭各一例）；②删除 `pcap_nic_consistency`（测试方法非协议语义）、`multi_flow_dynamic_fields`（HL7 单连接字节流，多流不适用）、合并 `v25_v28` 与 `multi_obx` 的重复覆盖；③按统一术语重写（事件编排会话/多会话展开/事务/锚词/声明式脚本化回放），显式声明流关联不适用（HL7 无控制流派生数据流）与并发会话不适用；④新增 §3.9 tshark 证据字段（实测 hl7 dissector 绑定 2575、字段族清单、MSH-9 派生语义、hidden 项校准项）；⑤新增 §5.2 自动派生规则（ack_mode auto/显式/null 逐条）与 §5.3 会话状态机、§3.6 帧长公式；⑥负例按 mllp/segment/field/msh/ack/port 六方向重构锚词表。**待独立隔离审查**。
- v2.0.1（2026-09-01）：按独立隔离审查 12 项问题清单（1 CRITICAL / 3 MAJOR / 8 MINOR）修复：① **`hl7.segment` 语义更正（CRITICAL）**——实测（构造 MLLP mini pcap 实跑）为整段原始文本而非 3 字符段名，段序列/段存在性断言改为 frames hex（段 ID+`|` 字节，§3.9，用例 §3.2/§4 多处）；② `hl7.llp.sob`/`hl7.llp.eob`/`hl7.raw`/`hl7.raw.segment` 偏好门控写明（`hl7.display_llp`/`hl7.display_raw` 默认 FALSE，开启后 sob=`0x0b`、eob=`0x1c0d`），断言 harness 不支持 `-o` 传参故 MLLP 边界断言一律 frames hex（§3.6/§3.7/§3.9）；③ 新增长度上界负例 `hl7_neg_length_limit`（负例 6→7，语义 ID 24→25，设计 §6/§7/§8/§9 与用例/JSON 三方同步）；④ 错误处理负例方向五→七（§4）；⑤ 设计声明的 MSH-7/EVN-2、MSH-11 处理 ID、PID-7/PID-8、OBX-11/OBR-25、AIS-2、ACK 帧内 MSH-7/MSH-11/MSH-12 断言在用例落地（§3.5/§3.8/§5.2 → 用例 §4 #1/#4/#5/#6/#16）；⑥ `hl7.message.type`/`hl7.event.type` 提取性由"实现后校准"更新为实测可提取（§3.9）。
- v2.1.2（2026-10-01，文档改造轮）：按 CORE_MEMORY §4/§5/§6/§8/§12/§15 补 §4 三张子表结论列与三路对照、§5.5 依赖与错误处理、§6 性能两路验收矩阵、§12 序号算法代码位置、§13 门1 三行展开、§16 机器对账与三个历史教训核对；`hl7.json` 实测 95 例（62 正 + 33 负）与文档一致，未改 JSON。本节新增 §16。


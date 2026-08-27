# HL7 v2/MLLP（医疗信息交换/最小下层协议）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-21  
> 状态：仅设计与 PCAP（抓包文件）/NIC（网卡）用例契约；`hl7` 层尚未注册，不修改 Go（编程语言）或 MCP（模型上下文协议）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/68-hl7-testcase.md`、`trafficgen/test/protocol_pcap/cases/hl7.json`  
> 规范基线：HL7 v2.5/v2.8、HL7 MLLP（Minimal Lower Layer Protocol，最小下层协议）、默认 TCP 2575。

## 1. 范围、证据等级和未注册边界

本设计定义 HL7 v2 消息的文本段、字段、组件、重复项和转义规则，以及 MLLP 的 framing（帧封装）：起始 VT（Vertical Tab，垂直制表，`0x0b`）、消息内容、结束 FS（File Separator，文件分隔符，`0x1c`）和 CR（Carriage Return，回车，`0x0d`）。默认载体为 TCP（传输控制协议）/2575；TCP 分段边界不是 HL7 字段边界，接收端必须先重组字节流再识别 MLLP 帧。

HL7 消息的最外层必须以 `MSH` 开始。MSH-1 是字段分隔符，MSH-2 是四个编码字符（组件、重复、转义、子组件）；后续字段用 MSH-1 分隔，组件/重复/子组件按 MSH-2 解析。本文基线覆盖 HL7 v2.5/v2.8 常用结构：`MSH`、`EVN`、`PID`、`PV1`、`OBR`、`OBX`，以及 ACK（Acknowledgment，确认）/NAK（Negative Acknowledgment，否定确认）。具体消息版本应由 MSH-12 声明，不能以固定样本值代替运行时值。

当前仓库没有注册 `hl7` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/hl7.json` 只保留一个注册前置占位 `hl7_neg_unregistered`，不计入下文 20 个语义 ID；其唯一错误预期必须是 `expect_error=true` 且 `error_contains` 精确为 `unknown layer`。未注册边界不得声称 HL7 可运行、可生成 PCAP/NIC 或已通过任何协议断言。

动态 Message Control ID（消息控制标识）、消息时间（MSH-7/EVN-2）、患者标识（PID-3）和其他现场值不得硬编码。实现后用 `presence`、`nonzero`、`distinct`、`same_as_packet` 或稳定长度/格式断言；只有协议常量（例如分隔符字节、默认端口和 ACK code）可固定。

## 2. 推荐层链、配置和载体

推荐层链为 `[ip, tcp, hl7]` 或 `[ipv6, tcp, hl7]`，默认目标端口 2575；层链是未来实现集成契约，不表示当前已注册。

```json
{
  "layers": [{"ip": {}}, {"tcp": {}}, {"hl7": {}}],
  "src_ip": "192.0.2.68", "dst_ip": "198.51.100.68",
  "src_port": 42680, "dst_port": 2575,
  "hl7": {
    "version": "2.8", "message_type": "ADT^A01",
    "profile": "mllp", "ack_mode": "auto",
    "patient_id": {"strategy": "rand", "range": [100000, 999999], "seed": 68}
  }
}
```

| 配置键 | 约束 |
|---|---|
| `profile` | 当前契约为 `mllp`；每个应用消息都由 VT + 内容 + FS + CR 封装。 |
| `transport`/端口 | 仅 TCP；默认目标端口 2575。TCP payload 可分段、合并或多帧粘连。 |
| `version` | MSH-12 的 `2.5` 或 `2.8`；版本只影响声明和字段规则，不可绕过必需字段。 |
| `message_type` | MSH-9 的消息代码/触发事件，至少覆盖 ADT、ORM、ORU、ACK/NAK；消息类型必须与结构和响应关联一致。 |
| `encoding_chars` | MSH-2 四字符，按顺序表示组件、重复、转义、子组件；必须与正文实际分隔符一致。 |
| `segments` | 按消息顺序生成；每段以 CR 结尾，不能在 MLLP 结束符后继续追加段。 |
| `control_id` | MSH-10；运行时生成，响应 MSA-2 必须关联请求，不能固定常量。 |
| `timestamp` | MSH-7/EVN-2；运行时生成并满足格式/存在性，不能硬编码日期时间。 |
| `patient_id` | PID-3；运行时生成或策略值，跨请求需按测试要求 distinct，同一响应关联时 same-as。 |
| `ack_mode` | `auto` 根据请求生成 ACK 或 NAK；ACK/NAK 的 MSH-9、MSA-1、MSA-2 与原请求关联。 |
| `wire_fault` | 仅负例注入口：`mllp_framing`、`separators`、`required_field`、`message_ack`、`truncated`、`transport`。 |

HL7 文本使用 ASCII（美国信息交换标准代码）/UTF-8 fixture（固定样本）时，应以字节长度和字节边界为准，不以 Unicode（统一码）字符数代替 TCP/MLLP 长度。HL7 转义序列（如 `\F\`、`\S\`、`\R\`、`\T\`、`\E\`）在字段值内解释；转义后的内容不能伪造分隔符或 MLLP 终止符。

## 3. HL7 v2 消息结构

典型 ADT（Admit/Discharge/Transfer，入院/出院/转院）请求顺序为：

```text
VT MSH|^~\\&|SENDER|FACILITY|RECEIVER|FACILITY|<runtime-ts>||ADT^A01|<runtime-control>|P|2.8 CR
EVN|A01|<runtime-ts> CR
PID|1||<runtime-patient>^^^HOSP^MR||... CR
PV1|1|I|... CR
FS CR
```

典型 ORU（Observation Result，观察结果）/ORM（Order Message，医嘱消息）可继续包含 `OBR` 与一个或多个 `OBX`。段顺序、必需字段和触发事件必须与 MSH-9/版本声明一致。

| 段 | 语义与最低断言 |
|---|---|
| `MSH` | 必需且首段；MSH-1/MSH-2、MSH-9、MSH-10、MSH-11、MSH-12 存在并彼此自洽。 |
| `EVN` | ADT 事件段；EVN-1 触发事件与 MSH-9 关联，EVN-2 动态时间存在。 |
| `PID` | 患者段；PID-3 动态患者标识存在，重复/组件分隔按 MSH-2 解释。 |
| `PV1` | 就诊段；就诊类别和位置等字段按声明结构编码，不把空字段折叠为错位字段。 |
| `OBR` | 观察请求/医嘱段；服务标识、请求控制 ID/关联字段与消息类型一致。 |
| `OBX` | 结果段；至少断言序号、值类型、观察标识和值边界，多个 OBX 保持线上顺序。 |
| `MSA` | ACK/NAK 响应段；MSA-1 为 `AA`/`AE`/`AR` 等合法确认码，MSA-2 等于请求 MSH-10。 |

MSH-9 的 ACK 响应必须使用 `ACK` 消息类型并包含 MSA；拒绝或错误响应使用 NAK 语义（例如 MSA-1=`AE`/`AR`），不能只改变文本而保持请求消息类型。成功 ACK 不等于业务数据已处理；测试只断言 wire（线上）格式、关联和响应码。

## 4. MLLP framing 和 TCP 重组

MLLP 帧格式固定为：

```text
0x0b <HL7 message bytes, each segment ending 0x0d> 0x1c 0x0d
```

VT 只能作为帧起始，FS 必须紧邻最终 CR；消息内容中的 CR 是段终止符，不能把任意 CR 误作 MLLP 结束。内容中出现 VT、FS 或未正确转义的控制字节属于非法 framing。接收端应支持一个 TCP segment 拆分 VT、MSH、FS/CR，也应支持一个 segment 承载多帧；不能根据 segment 数量推断消息数。

每个方向单独维护 TCP stream（字节流）缓冲区和 MLLP frame 状态。多会话/多流不得共享缓冲区；四元组、地址族、控制 ID 和患者标识用于隔离。PCAP（抓包文件）和 NIC 捕获应分别验证 TCP 三次握手、方向、2575 端口、MLLP 字节和重组后的段/字段。

## 5. IPv4/IPv6、多会话和动态字段

IPv4 与 IPv6 使用独立 fixture，分别断言 `ip.proto=6` 或 `ipv6.nxt=6`、地址族、TCP 端口和 payload 方向。至少两个会话应具有不同的运行时控制 ID、时间或患者标识；同一请求与其 ACK 的 MSH-10/MSA-2 必须 `same_as_packet`，不同会话的控制 ID/PID-3 必须 `distinct`。不能依赖全局包序或固定时间。

PCAP/NIC 断言以稳定外层和动态关系为主：VT/FS/CR 字节、MSH/EVN/PID/PV1/OBR/OBX/MSA 的段名、字段槽位、类型和长度，控制 ID/时间/患者标识的存在性与关联。没有医学业务引擎、患者主索引或 ACK 处理上下文时，不声称患者真实存在、业务成功、临床结果正确或身份认证成功。

## 6. 错误处理和错误传播

负例必须在 planner/validator 阶段拒绝，并将原始原因传播为 task error；不能输出成功 PCAP、`completed/0 packet` 或只有 TCP 外壳的假成功。负例分别覆盖：MLLP 起止字节/多帧边界、MSH-1/MSH-2 分隔符、自洽的 MSH 必需字段、消息类型与 ACK 关联、截断/长度、TCP/2575/IPv4/IPv6 地址族和错误传播。负例的 `expect` 仅允许 `expect_error` 与 `error_contains`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `hl7_neg_mllp_framing` | 缺 VT、错误 FS/CR、控制字节落入正文或多帧边界非法 | `mllp` 或 `framing` |
| `hl7_neg_field_separators` | MSH-1/MSH-2 缺失、长度错误或与字段实际分隔不一致 | `separator` 或 `encoding` |
| `hl7_neg_msh_required` | MSH 缺首段、MSH-9/10/11/12 或必需字段缺失/错位 | `msh` 或 `required` |
| `hl7_neg_message_ack` | 消息类型/触发事件错误、ACK/NAK 缺 MSA 或 MSA-2 不关联请求 | `ack` 或 `message` |
| `hl7_neg_length_truncated` | TCP/MLLP payload 截断、FS/CR 缺失、段长度/字节边界不完整 | `length` 或 `truncated` |
| `hl7_neg_transport_profile` | UDP、错误端口、TCP/地址族不一致或 planner 错误未传播 | `tcp`、`port` 或 `transport` |

合法的空可选字段、重复 OBX、UTF-8 字节、TCP 分段/合并、IPv4/IPv6、ACK `AA` 与 NAK `AE/AR`、动态控制 ID/时间/PID 不得被负例规则误报。必须区分 MLLP 结束 CR 与段 CR，并保留具体错误来源。

## 7. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例和 6 个负例；顺序必须与 `68-hl7-testcase.md` §2 及注册后的 `hl7.json` 完全一致。当前 JSON 只有不计数的注册前置占位。

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `hl7_adt_a01_mllp_ipv4` | 正 | HL7 v2.5/v2.8 ADT^A01，MSH/EVN/PID/PV1 与 MLLP/IPv4 | 8 |
| 2 | `hl7_oru_obr_obx_results` | 正 | ORU 消息的 OBR/多个 OBX、值类型/顺序与 MLLP | 10 |
| 3 | `hl7_orm_order_segments` | 正 | ORM 医嘱消息、MSH/PID/PV1/OBR 字段与动态控制 ID | 8 |
| 4 | `hl7_ack_success_association` | 正 | ACK `AA`、ACK MSH-10 与 MSA-2 请求关联 | 8 |
| 5 | `hl7_nak_error_association` | 正 | NAK `AE/AR`、错误文本边界与请求控制 ID 关联 | 8 |
| 6 | `hl7_mllp_control_bytes` | 正 | VT/FS/CR 精确 framing、段 CR 与终止 CR 区分 | 6 |
| 7 | `hl7_tcp_segment_reassembly` | 正 | VT/MSH/字段/FS/CR 跨 TCP 分段及多帧合并重组 | 10 |
| 8 | `hl7_field_component_escaping` | 正 | MSH-1/MSH-2、组件/重复/子组件和 HL7 转义序列 | 8 |
| 9 | `hl7_ipv6_transport` | 正 | IPv6/TCP/2575 地址族、MLLP 内容和方向 | 8 |
| 10 | `hl7_multi_session_dynamic_identity` | 正 | 多会话/多流隔离、动态 control ID/时间/PID distinct | 16 |
| 11 | `hl7_v25_v28_version_profiles` | 正 | v2.5 与 v2.8 MSH-12 声明及结构差异 | 12 |
| 12 | `hl7_multi_obx_order` | 正 | 多个 OBX 顺序、重复项、值类型和值边界 | 10 |
| 13 | `hl7_pcap_nic_consistency` | 正 | PCAP/NIC TCP 2575、方向、MLLP 字节和字段一致 | 12 |
| 14 | `hl7_ack_nak_roundtrip` | 正 | 请求→ACK/NAK 往返、多流关联和错误码传播 | 16 |
| 15 | `hl7_neg_mllp_framing` | 负 | MLLP 起止字节、控制字节或多帧 framing 错误 | — |
| 16 | `hl7_neg_field_separators` | 负 | MSH-1/MSH-2 缺失、错长或分隔符不一致 | — |
| 17 | `hl7_neg_msh_required` | 负 | MSH 必需字段、首段、版本或字段槽位错误 | — |
| 18 | `hl7_neg_message_ack` | 负 | 消息类型/ACK 关联/MSA-2 或 NAK 语义错误 | — |
| 19 | `hl7_neg_length_truncated` | 负 | TCP/MLLP/段长度或截断导致不完整消息 | — |
| 20 | `hl7_neg_transport_profile` | 负 | TCP/端口/地址族错误和 planner 错误传播 | — |

三方契约必须保持本文 §7、`68-hl7-testcase.md` §2、注册后的 `hl7.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `hl7_neg_unregistered`，且唯一预期为 `unknown layer`。

## 8. 实现完成定义

注册 `hl7` layer 后，需完成 v2.5/v2.8 MSH/EVN/PID/PV1/OBR/OBX/ACK/NAK 结构、MLLP VT/FS/CR framing、字段/组件/转义解析、TCP 分段重组、IPv4/IPv6、多会话状态隔离以及 planner→worker→PCAP/NIC 输出。正例必须观察到合法 MLLP 帧和动态字段关联；负例必须传播原始错误且无假成功输出。测试应覆盖正负 20 项、PCAP/NIC、-race（竞态检测）和集成路径；未提供业务主数据时不得声称临床或身份语义已验证。

## 9. 修订记录

- v1.0.0（2026-08-21）：建立 14 个 HL7 v2/MLLP 正例和 6 个严格负例，覆盖 MSH/EVN/PID/PV1/OBR/OBX、ACK/NAK、VT/FS/CR、TCP 重组、IPv4/IPv6、多会话、多版本和 PCAP/NIC；不修改 Go/MCP 实现。

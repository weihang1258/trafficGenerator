# HL7 v2/MLLP（医疗信息交换/最小下层协议）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-21  
> 配套设计：`docs/protocol-designs/68-hl7-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/hl7.json`  
> 状态：`hl7` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。基线为 HL7 v2.5/v2.8、MLLP（Minimal Lower Layer Protocol，最小下层协议），默认 TCP（传输控制协议）端口 2575。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `hl7_neg_unregistered`，其 `expect` 必须 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。三方检查以设计 §7、本文 §2 和未来 JSON 为准。

MLLP 只断言字节级 framing、TCP（传输控制协议）方向/端口、HL7 段和字段结构；不能把 TCP segment（数据段）边界当成 HL7 消息边界。动态 Message Control ID（消息控制标识）、MSH-7/EVN-2 时间和 PID-3 患者标识使用 `presence`、`nonzero`、`distinct`、`same_as_packet` 或长度/格式断言，不硬编码运行时值。没有医学业务引擎或患者主索引时，不声称临床业务成功、患者真实存在或身份认证通过。

## 2. 原子用例索引

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

## 3. 正例逐项断言契约

1. **`hl7_adt_a01_mllp_ipv4`**：建立 IPv4/TCP/2575，断言请求为 `VT MSH ... CR ... FS CR`，首段 MSH、MSH-9=`ADT^A01`、MSH-10 动态存在、MSH-12 为 2.5 或 2.8；随后有 EVN、PID（PID-3 动态）、PV1，`packet_count=8`。
2. **`hl7_oru_obr_obx_results`**：断言 ORU 消息包含 OBR 和至少两个 OBX，OBX 序号、值类型、观察标识、值边界和线上顺序稳定，MSH/MLLP framing 合法，`packet_count=10`。
3. **`hl7_orm_order_segments`**：断言 ORM 触发事件与 OBR 医嘱结构一致，MSH/PID/PV1/OBR 段槽位不错位；MSH-10、MSH-7 和 PID-3 仅 presence/nonzero，`packet_count=8`。
4. **`hl7_ack_success_association`**：请求后响应首段 MSH-9 为 ACK，MSA-1=`AA`，MSA-2 `same_as_packet` 请求 MSH-10；响应仍由 MLLP VT/FS/CR 封装，`packet_count=8`。
5. **`hl7_nak_error_association`**：断言 NAK 语义的 MSA-1=`AE` 或 `AR`、错误文本字段存在且边界合法，MSA-2 关联请求控制 ID，不将错误 ACK 当成功，`packet_count=8`。
6. **`hl7_mllp_control_bytes`**：逐字节断言 VT=`0x0b`、最终 FS=`0x1c`、终止 CR=`0x0d`；段内 CR 与 MLLP 终止 CR 分开识别，`packet_count=6`。
7. **`hl7_tcp_segment_reassembly`**：将 VT、MSH、字段、FS/CR 跨多个 TCP segment，另发送粘连的第二帧；重组后得到两个完整消息，segment 边界不改变字段解析，`packet_count=10`。
8. **`hl7_field_component_escaping`**：断言 MSH-1 为 `|`、MSH-2 为四个编码字符，组件/重复/子组件和 `\F\`/`\S\`/`\R\`/`\T\`/`\E\` 只在字段内生效，转义内容不伪造 MLLP 控制字节，`packet_count=8`。
9. **`hl7_ipv6_transport`**：独立 IPv6/TCP fixture，断言 `ipv6.nxt=6`、地址族、2575 端口、方向和 MLLP 内容；不能从 IPv4 用例继承地址，`packet_count=8`。
10. **`hl7_multi_session_dynamic_identity`**：至少两个并行会话/流，断言每流缓冲隔离、MSH-10/PID-3/时间存在且不同会话 `distinct`，各自 ACK/NAK 只关联本流，`packet_count=16`。
11. **`hl7_v25_v28_version_profiles`**：分别发送 MSH-12=`2.5` 与 `2.8` 的合法 fixture，断言版本声明、段顺序和字段边界自洽，不把版本字符串硬编码为唯一运行时消息值，`packet_count=12`。
12. **`hl7_multi_obx_order`**：同一 ORU 中至少三个 OBX，断言序号递增/线上顺序、不同值类型和空可选字段不导致错位；每个值只断言稳定类型/长度，`packet_count=10`。
13. **`hl7_pcap_nic_consistency`**：同一 fixture 分别输出 PCAP 并在 NIC 捕获；断言 TCP/2575、方向、VT/FS/CR、MSH/PID/OBR/OBX 外层和动态关联一致。过滤器推荐 `tcp port 2575`，`packet_count=12`。
14. **`hl7_ack_nak_roundtrip`**：至少两个请求分别得到 ACK 与 NAK，跨多流断言请求 MSH-10 与响应 MSA-2 一一 `same_as_packet`、MSA-1 码正确、MLLP framing 完整，`packet_count=16`。

正例只对可观察的字节/字段和动态关系作断言。时间、控制 ID、患者标识、具体医学文本和值不得硬编码；无业务语义证据不声称处理成功。

## 4. 负例契约

每个负例必须在 planner/validator 失败并传播为 task error；不能产生成功 PCAP、`completed/0 packet` 或只有 TCP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `hl7_neg_mllp_framing` | 缺 VT、错误 FS/CR、控制字节落入正文或多帧边界非法 | `mllp` 或 `framing` |
| `hl7_neg_field_separators` | MSH-1/MSH-2 缺失、长度错误或与正文分隔符不一致 | `separator` 或 `encoding` |
| `hl7_neg_msh_required` | MSH 非首段，或 MSH-9/10/11/12、版本/必需字段缺失 | `msh` 或 `required` |
| `hl7_neg_message_ack` | 消息类型/触发事件错误、ACK/NAK 缺 MSA 或 MSA-2 不关联请求 | `ack` 或 `message` |
| `hl7_neg_length_truncated` | TCP/MLLP payload、段 CR 或 FS/CR 截断导致不完整消息 | `length` 或 `truncated` |
| `hl7_neg_transport_profile` | UDP、错误端口、TCP/地址族不一致或 planner 错误未传播 | `tcp`、`port` 或 `transport` |

合法的空可选字段、重复 OBX、UTF-8 字节、TCP 分段/合并、IPv4/IPv6、ACK `AA` 与 NAK `AE/AR`、动态值不得被负例规则误报。负例不得污染合法格式：每条故障只改变对应一项协议前提，且不借助未声明的业务错误替代 framing/结构错误。

## 5. 三方一致性和静态检查

1. 设计 §7、本文 §2 和注册后的 `hl7.json` 必须保持同一组 20 个 ID、同一顺序：14 正例后接 6 负例；当前 JSON 另有且仅有 `hl7_neg_unregistered` 占位。
2. 未来正例均有 `packet_count`/`min_packets`、TCP/2575、方向、MLLP 字节和稳定字段断言；负例的 `packet_count` 固定为 `—`，`expect` 只能有 `expect_error`、`error_contains`。
3. MLLP 的 VT/FS/CR 按字节断言；段 CR 不等于 FS 后的终止 CR；TCP segment 边界不得替代 MLLP frame 边界。
4. MSH 必须首段，MSH-1/MSH-2 驱动字段/组件/重复/转义解析；MSH-9、MSH-10、MSH-11、MSH-12 与消息结构自洽。
5. ADT/ORU/ORM 分别覆盖 EVN/PID/PV1、OBR/OBX 和医嘱字段；ACK/NAK 使用 ACK MSH-9、MSA-1 与 MSA-2 关联原请求。
6. 动态 control ID、时间和 PID-3 使用 presence/nonzero/distinct/same_as_packet，不硬编码；同一流关联、不同流隔离。
7. IPv4/IPv6、多流、TCP 分段/粘连和 PCAP/NIC 以流内状态为准，不依赖全局交织包序；默认目标端口为 2575。
8. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/hl7.json` 应成功；当前数组只能含 `hl7_neg_unregistered`，且 `proto=hl7`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `hl7` layer 后，先检查 JSON parser、ID 顺序、正负 expect 键集合、MSH 分隔符/必需字段、段顺序、MLLP 控制字节、ACK/NAK 关联、动态字段和 TCP 重组，再运行 1–14 的 PCAP/NIC 正例和 15–20 的错误传播。若解析器不能显示 HL7 字段，使用 `tcp` 和稳定 raw frame bytes；不能把唯一 placeholder 运行结果报告为 HL7 suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-21）：建立 14 个 HL7 v2/MLLP 正例和 6 个严格负例，覆盖 MSH/EVN/PID/PV1/OBR/OBX、ACK/NAK、VT/FS/CR、TCP 分段重组、IPv4/IPv6、多会话、多版本、PCAP/NIC 和错误传播；不修改 Go/MCP 实现。

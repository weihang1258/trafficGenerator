# HL7 v2.x over MLLP（医疗信息交换标准 / 最小下层协议）测试用例契约

> 版本：v2.0.1（设计阶段）
> 日期：2026-09-01
> 配套设计：`docs/protocol-designs/68-hl7-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/hl7.json`（proto key：`hl7`）
> 状态：**尚未实现**；本文定义实现后的 PCAP（抓包文件）断言。当前 JSON 仅含注册前置占位 `hl7_neg_unregistered`，实现期按本文 §2 顺序替换为 25 个语义用例。**独立隔离对抗审查已完成**（v2.0.1 定稿：独立审查 agent 三向审计 12 项清单（1C/3M/8N）→ 修复 → 复验 clean，含二轮复验；审查/修复记录见 §9）。
> 规范基线：HL7 v2.x 官方标准（HL7.org，v2.5/v2.8）、MLLP 封装、IANA TCP 2575。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 25 个唯一语义 ID：18 个正例 + 7 个负例。**原子性原则**：一个用例只验证一个协议行为/规格点（每条消息类型、每个字段规则、每个边界、每个错误分支各一例，如 ADT^A01 与 ORU^R01 分开、MLLP 起始/结束块一例、重复字段一例、转义一例、MSA-2 关联一例），不做"合并杂例"；数量由协议结构决定。派生规则：设计 §3 每个编码条款（MLLP 起止块、段/字段/组件/重复/转义、MSH 字段表、段结构）、§5 每个状态/事务行为（自动派生 ACK、帧组装、多事务配对、多会话）、§7 每行错误处理在本文有对应断言；断言不得超出设计（并追溯到 HL7 v2.x 规范）声明范围。

**未注册边界**：`hl7` 层未注册。当前唯一合法 JSON 条目是 `hl7_neg_unregistered`（`proto=hl7`、层链 `[{"tcp":{}},{"hl7":{}}]`、`expect_error=true`、`error_contains` 精确为 `unknown layer`，已实测该文件现状）；占位不计入 25 个语义 ID，注册前的拒绝、0 包或空 PCAP 不是协议行为通过。

**断言字段以 tshark 3.6.14 实测为准**（`-G fields`/`-G decodes` + 构造 MLLP mini pcap 实跑）：hl7 dissector 绑定 `tcp.port 2575`，2575 载荷自动按 hl7 解码。**默认偏好下可提取**：`hl7.segment`（FT_STRING，**整段原始文本**——段名+字段+段尾 CR，如 `MSH|^~\&|HIS|...|`，**不是 3 字符段名**；一帧多段在 `-T fields` 输出中逗号拼接）、`hl7.field`（段内各字段值，每段首值即段名）、`hl7.message.type`/`hl7.event.type`（MSH-9 消息代码/触发事件，hidden 项实测可提取）、`hl7.malformed`（解析诊断）。**偏好门控默认不提取**（需 `-o hl7.display_llp:TRUE -o hl7.display_raw:TRUE`）：`hl7.llp.sob`（开后 `0x0b`）、`hl7.llp.eob`（开后 `0x1c0d`）、`hl7.raw`/`hl7.raw.segment`——而 pcaptest 断言 harness（`internal/pcaptest` 的 RunTshark）只支持 `-d` 解码提示、**不支持 `-o` 偏好传参**，故这四个字段不用作断言。**断言口径**：MLLP 边界字节（首字节 `0B`、帧尾 `1C 0D`）与段序列/段存在性一律 frames hex（段 ID+`|` 字节，如 `45 56 4E 7C` = `EVN|`；固定策略值下偏移可计算）；`hl7.message.type`/`hl7.event.type` 可用作 fields 断言，frames hex 为其后备（`41 44 54 5E 41 30 31` = `ADT^A01`，见 §3）；字段断言无前缀/包含谓词，`hl7.segment`/`hl7.field` 的整段文本不作精确值断言、仅作人工核对辅助。标准载体字段 `tcp.stream`、`tcp.len`、`tcp.flags.*`、`ip.version`、`ipv6.nxt` 照常可用。MSA-2 与 MSH-10 的关联断言用 `same_as_packet`（对应位置帧字节），PID-3/时间用 `nonzero`/`distinct_values`/hex 存在性；不得臆造未实测字段名/格式。

动态字段禁止硬编码：MSH-10/MSA-2 控制 ID、MSH-7/EVN-2 时间、PID-3 患者标识用关联/存在性断言；无医学业务引擎或患者主索引时，不声称临床业务成功、患者真实存在或身份认证通过——ACK `AA` 只断言线上格式、关联与响应码。

## 2. 原子用例索引

**约定 packet_count**（设计 §9）：TCP = 3（握手 SYN/SYN-ACK/ACK）+ 每笔消息→ACK 2 包（请求 1 段 + ACK 1 段，未跨段时）+ 4（双向 FIN/ACK 挥手）；`ack_mode=null` 的消息只 1 包；消息跨段每加 1 段 +1；**多会话 = 各会话之和，第二会话起点 = 前会话总包数 + 1**。约定数字是实现基线，若实现采用不同 ACK 合并或分段方式，须同步更新四件套（设计/testcase/JSON/audit）；断言以 fields/frames 为准。负例无 packet_count（执行期 `expect` 严格只有 `expect_error`、`error_contains`）。

| # | ID | 类型 | 覆盖（设计 §） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `hl7_adt_a01_ipv4` | 正 | ADT^A01 消息类型 + MLLP/IPv4 单消息基线 + 自动 ACK（§3.4/§3.5/§5.2） | 9 |
| 2 | `hl7_adt_a02_transfer` | 正 | ADT^A02 转科（EVN-1=A02、PV1-3 位置更新）（§3.5） | 9 |
| 3 | `hl7_adt_a03_discharge` | 正 | ADT^A03 出院（EVN-1=A03、PV1-45 离院时间）（§3.5） | 9 |
| 4 | `hl7_oru_r01_results` | 正 | ORU^R01：OBR + 多 OBX 序号/值类型/线上顺序（§3.5） | 9 |
| 5 | `hl7_siu_s12_appointment` | 正 | SIU^S12：SCH/AIS 段、EI `&` 子组件（§3.5） | 9 |
| 6 | `hl7_ack_success_association` | 正 | ACK `AA`：MSH-9=ACK、MSA-1=AA、MSA-2 关联 MSH-10（§5.1） | 9 |
| 7 | `hl7_nak_error_segment` | 正 | NAK `AE`+ERR 段、MSA-2 仍关联（§3.5/§5.1） | 9 |
| 8 | `hl7_mllp_frame_bytes` | 正 | MLLP 起止块逐字节 0x0b/0x1c 0x0d、段 CR 与终止 CR 区分（§3.1） | 9 |
| 9 | `hl7_component_subcomponent` | 正 | 组件 `^`、子组件 `&`（PID-5、OBR-2 EI）（§3.2） | 9 |
| 10 | `hl7_field_repetition` | 正 | 重复 `~`（PID-3 多标识）（§3.2） | 9 |
| 11 | `hl7_escape_sequences` | 正 | 转义 `\F\`/`\S\`/`\R\`/`\E\`/`\T\`/`\H\`/`\N\`/`\X..\` 不产生真实分隔符/控制字节（§3.3） | 9 |
| 12 | `hl7_multi_transaction_long_connection` | 正 | 同连接 3 笔事务：MSH-10 distinct、MSA-2 各自配对、连接持续（§5.1/§5.4） | 13 |
| 13 | `hl7_tcp_mss_reassembly` | 正 | 长消息跨 MSS 分段 + 第二帧粘连同段；segment≠消息边界（§2/§8） | 10 |
| 14 | `hl7_ipv6_transport` | 正 | IPv6/TCP/2575、ipv6.nxt=6、offset 74、MLLP 字节同 v4（§2/§8） | 9 |
| 15 | `hl7_multi_session_isolation` | 正 | 多会话双四元组、控制 ID/PID distinct、第二会话起点=前会话+1（§5.4） | 18 |
| 16 | `hl7_version_profiles` | 正 | MSH-12 版本值域 2.5/2.8 + MSH-11 处理 ID P/T（同连接两消息）（§3.4/§3.8/§4⑧） | 11 |
| 17 | `hl7_ack_code_domain` | 正 | MSA-1 码值域 AA/AE/AR 各一次（§3.8） | 13 |
| 18 | `hl7_ack_disabled` | 正 | `ack_mode=null`：无 ACK 帧（§5.2 关闭分支） | 8 |
| 19 | `hl7_neg_mllp_framing` | 负 | MLLP 起止/控制字节/未闭合（§7） | — |
| 20 | `hl7_neg_segment_order` | 负 | 首段非 MSH/段未 CR 结尾/EOB 后追加段（§7） | — |
| 21 | `hl7_neg_field_separator` | 负 | MSH-1/MSH-2 长度/声明与正文不一致/非法转义（§7） | — |
| 22 | `hl7_neg_msh_required` | 负 | MSH-9/10/11/12 缺失、消息类型非法（§7） | — |
| 23 | `hl7_neg_ack_correlation` | 负 | MSA-2 不关联、ACK 缺段/码非法（§7） | — |
| 24 | `hl7_neg_transport_port` | 负 | UDP 载体/非 2575/层链缺 tcp（§7） | — |
| 25 | `hl7_neg_length_limit` | 负 | 字段长度上界越界：MSH-9/10/12、MSH-7、MSA-2 超限（§7/设计 §8） | — |
| — | `hl7_neg_unregistered` | 占位 | 层注册前置，不计语义覆盖 | — |

## 3. 线上编码与偏移断言

层链 `[tcp, hl7]`，无 VLAN/IP options/TCP options 的数据承载段，MLLP 帧首字节（应用层 payload 第 1 字节 = `0x0b`）起点：IPv4 offset 54（Eth 14 + IPv4 20 + TCP 20）、IPv6 offset 74。SYN/SYN-ACK 段可带 TCP options，固定偏移只对数据承载段成立。断言分层：

1. **MLLP 帧字节（frames hex 权威断言）**：请求/ACK 帧的 TCP payload 首字节 = `0x0b`（`0B`），末两字节 = `1C 0D`；`hl7.llp.sob`/`hl7.llp.eob` 受 `hl7.display_llp` 偏好门控（默认 FALSE 不提取）且断言 harness 不支持 `-o` 偏好传参，**不用作断言字段**（§1 实测）。段内 CR（`0D`，每段末尾）与 MLLP 终止 CR（`1C` 之后的 `0D`）分开识别——`hl7_mllp_frame_bytes` 逐字节断言这一区分。
2. **段名/段序列与消息类型**：`hl7.segment` 实测为**整段原始文本**（如 `MSH|^~\&|HIS|...|`）而非 3 字符段名，且 `-T fields` 多段逗号拼接、字段断言无前缀/包含谓词——**段存在性/段序列断言一律 frames hex**：段 ID + `|` 字节（`4D 53 48 7C`=`MSH|`、`45 56 4E 7C`=`EVN|`、`50 49 44 7C`=`PID|`、`50 56 31 7C`=`PV1|`、`53 43 48 7C`=`SCH|`、`41 49 53 7C`=`AIS|`、`4F 42 52 7C`=`OBR|`、`4F 42 58 7C`=`OBX|`、`4D 53 41 7C`=`MSA|`、`45 52 52 7C`=`ERR|`），段序列按帧内出现先后断言；`hl7.field` 每段首值即段名，仅作人工核对辅助。MSH-9 消息类型优先 `hl7.message.type`/`hl7.event.type`（实测默认可提取）；后备帧字节：offset 54 后 MSH 段内 `41 44 54 5E 41 30 31 5E` = `ADT^A01^`、`4F 52 55 5E 52 30 31` = `ORU^R01`、`53 49 55 5E 53 31 32` = `SIU^S12`、`41 43 4B 5E` = `ACK^`。MSA-2 关联用 `same_as_packet` 指向请求帧 MSH-10 槽位字节。
3. **MSH 分隔符**：每帧 offset 54 起（v4）`0B 4D 53 48 7C 5E 7E 5C 26 7C` = `VT MSH|^~\&|`——MSH-1=`|`、MSH-2=`^~\&` 的字节级断言；任意帧出现该前缀即证明 MSH 首段 + 分隔符合规。
4. **TCP 重组**：TCP segment 边界不是 MLLP 消息边界。跨段消息先按 `tcp.stream` 重组字节流再断言完整帧；一个 segment 承载多帧时按 `0x0b`/`0x1c 0x0d` 切分，不按 segment 计数。
5. **多会话包号规则**：`sessions[]` 按多会话展开整块回放——先跑完第 1 个会话全流程（握手→事件→挥手）再跑第 2 个，不交错；**第二会话 TCP 握手 SYN 包号 = 前一会话总包数 + 1**（如用例 15：会话 1 共 9 包，会话 2 从包 10 起）。跨会话关联断言用 `tcp.stream` 区分，不硬编码全局包号。

## 4. 正例逐项断言契约

以下 fields/frames 为最低断言集，实现期可增不可减。所有正例共享基线：三次握手、数据承载段、挥手；请求帧 offset 54（v4）/74（v6）起 `0B 4D 53 48 7C 5E 7E 5C 26 7C`（`VT MSH|^~\&|`）；`tcp.stream` 单值（除多会话/粘连用例）。

1. **`hl7_adt_a01_ipv4`**（9 = 3+2+4）：`192.0.2.68:42680 → 198.51.100.68:2575`。请求帧（包 4）：MSH-9 段内 `41 44 54 5E 41 30 31`（`ADT^A01`）；段序列 MSH/EVN/PID/PV1 用 frames hex（`4D 53 48 7C`、`45 56 4E 7C`、`50 49 44 7C`、`50 56 31 7C` 按帧内先后）；EVN-1=`A01` hex `45 56 4E 7C 41 30 31 7C`（`EVN|A01|`，与 MSH-9 触发事件一致）；MSH-7 消息时间槽 nonzero（MSH 段内 MSH-6 之后的非空槽，运行期 timestamp 策略不硬编码）、EVN-2 事件时间槽 nonzero（EVN-1 之后的非空槽）；PID-3 存在（PID 段内 hex nonzero）；PID-7 出生日期槽存在、PID-8 性别 `M`（PID 段内 hex `7C 4D 7C` = `|M|`）；PV1-2=`I`。ACK 帧（包 5，方向反转）：`41 43 4B 5E 41 30 31`（`ACK^A01`）、MSA-1=`AA` hex `4D 53 41 7C 41 41 7C`（`MSA|AA|`）、MSA-2 `same_as_packet` 包 4 MSH-10。`has_payload` 对包 4/5 成立。
2. **`hl7_adt_a02_transfer`**（9）：同基线形状；EVN-1=`A02` hex `45 56 4E 7C 41 30 32 7C`（`EVN|A02|`）、MSH-9 `41 44 54 5E 41 30 32`（`ADT^A02`）；PV1-3 位置组件 `WARD^2^BED9`（转科后位置）hex 存在；ACK 同上关联规则。只与用例 1 差分：触发事件 A02 + 位置变更字段。
3. **`hl7_adt_a03_discharge`**（9）：EVN-1=`A03` hex `45 56 4E 7C 41 30 33 7C`（`EVN|A03|`）、MSH-9 `ADT^A03`；PV1 段含离院时间槽（PV1-45，`@ts` 占位 → nonzero hex）与离院方式槽（PV1-36）；ACK 关联同规则。
4. **`hl7_oru_r01_results`**（9）：MSH-9 `4F 52 55 5E 52 30 31`（`ORU^R01`）；段存在性 frames hex：`4F 42 52 7C`（`OBR|`）与 ≥2 个 `4F 42 58 7C`（`OBX|`）；OBX-1 集合 ID 递增（hex `4F 42 58 7C 31 7C`/`4F 42 58 7C 32 7C` = `OBX|1|`/`OBX|2|`）；OBX-2 值类型 `NM`/`ST` 各出现、OBX-3 观察标识 `2339-0^Glucose^LN` 组件结构 hex 存在、OBX-5 值与 OBX-6 单位槽存在、OBX-11 结果状态 `F`（OBX 段尾 `7C 46 0D` = `|F`+CR）；OBR-4 `码^文本^LN` 三组件 hex 存在、OBR-25 结果状态 `F`（OBR 段尾 `7C 46 0D`）；ACK 关联。
5. **`hl7_siu_s12_appointment`**（9）：MSH-9 `53 49 55 5E 53 31 32`（`SIU^S12`）；段存在性 frames hex：`53 43 48 7C`（`SCH|`）、`41 49 53 7C`（`AIS|`）（无 EVN/PID/PV1——与 ADT 形状差分）；SCH-1 EI 子组件 `APPT-9001&HIS`（`26` = `&`）hex 存在；SCH-7 预约原因、SCH-11 开始时间槽存在；AIS-2 通用服务标识 CE 三组件结构 hex 存在（如 `4D 52 49 5E` = `MRI^`）；ACK 关联。
6. **`hl7_ack_success_association`**（9）：聚焦 ACK 帧自身形状（与用例 1 差分：断言重心在 MSA 而非业务段）：ACK 帧 MSH-9 `ACK^A01`（`41 43 4B 5E 41 30 31`）、MSA-1=`AA` hex `4D 53 41 7C 41 41 7C`（`MSA|AA|`）、**MSA-2 `same_as_packet` 请求帧 MSH-10 槽位**、ACK 的 MSH-10 与请求 MSH-10 `distinct_values`（ACK 分配新控制 ID）；ACK 帧 MSH-3/4 = 请求 MSH-5/6（收发对调）hex 存在性；ACK 帧 MSH-7 槽 nonzero（§5.2⑤ 新运行期时间戳：MSH-6 之后的非空槽）；MSH-11/MSH-12 与请求相同（§5.2⑧⑨：默认配置 `P`/`2.8` 下 ACK 帧内 hex `7C 50 7C 32 2E 38` = `|P|2.8` 存在）。
7. **`hl7_nak_error_segment`**（9）：配置 `ack={"code":"AE","err_segments":[...]}`；ACK 帧 MSA-1=`AE` hex `4D 53 41 7C 41 45 7C`（`MSA|AE|`）；帧内含 `ERR` 段（frames hex `45 52 52 7C` = `ERR|` 存在）；ERR 段含 HL7 错误码与严重级槽；MSA-2 仍 `same_as_packet` 请求 MSH-10——**NAK 是合法协议行为（正例），不得当负例或成功处理**。
8. **`hl7_mllp_frame_bytes`**（9）：逐字节断言（**全 frames hex**；`hl7.llp.sob`/`hl7.llp.eob` 受 `hl7.display_llp` 偏好门控默认不提取且 harness 不支持 `-o` 传参，不用作断言字段，见 §1/§3.1）：请求帧 payload 首字节 `0B`（offset 54）、末两字节 `1C 0D`（本例时间/控制 ID 用固定策略值使帧长确定、尾部偏移可计算）；段间 CR：EVN 段末尾 `0D`（CR，段终止符）后紧跟 `50 49 44`（`PID`）——证明段 CR 是段终止符；最后一段 PV1 末尾 `0D 1C 0D` 形态（段 CR + FS CR）——证明终止 CR 仅在 `1C` 之后。ACK 帧同样断言。
9. **`hl7_component_subcomponent`**（9）：PID-5 姓名 `DOE^JOHN^A`（组件 `^`，`5E`）hex 存在于 PID 段；OBR-2 `ORD-1001&HIS`（子组件 `&`，`26`）——本例消息类型用 ORU^R01（OBR 段自然出现）；断言组件/子组件字节与 MSH-2 声明（`^`、`&`）一致。
10. **`hl7_field_repetition`**（9）：PID-3 患者标识列表两值重复 `PAT1^^^HOSP^MR~PAT2^^^HOSP^MR2`（`7E` = `~`）hex 存在于 PID 段；断言重复分隔符与 MSH-2 第 2 字符一致；ACK 关联照常。
11. **`hl7_escape_sequences`**（9）：一个 OBX-5 观察值字段（OBX-2=`TX`/`ST`；NTE 段不在设计允许段表，不用作载体）内携带转义序列集 `\F\`（`5C 46 5C`）、`\S\`（`5C 53 5C`）、`\R\`、`\E\`、`\T\`、`\H\`、`\N\`、`\X0D\` hex 存在于帧内；断言转义文本**原样落线**且帧内不出现裸 `0x0b`/`0x1c` 控制字节、`\F\` 位置不被解析为额外字段（段字段数不变——raw 段文本对照或 frames hex 段长核对）。
12. **`hl7_multi_transaction_long_connection`**（13 = 3+3×2+4）：同一 `tcp.stream`、单连接；3 笔事务按 events[] 顺序：ADT^A01→ACK、ORU^R01→ACK、SIU^S12→ACK；断言 3 个请求帧 MSH-10 `distinct_values` 恰 3 值（同连接控制 ID 空间唯一）、每笔 ACK 的 MSA-2 `same_as_packet` 对应请求帧 MSH-10（配对不串）、连接在最后一笔 ACK（包 9）后才挥手（FIN 自包 10 起、挥手 4 包 = 包 10–13 收尾）。
13. **`hl7_tcp_mss_reassembly`**（10 = 3+3+4，请求跨 2 段）：配置小 MSS 使一条长 ORU 消息（多 OBX 长文本）跨 2 个 TCP segment，另一条短消息与之**粘连在同一 segment**（一个 segment 承载跨帧尾部+下一帧）且短消息 `ack=null`（无 ACK 帧——3 个数据包 = 长请求 2 段 + 长请求的 ACK 1 包，恰合 10）；断言：先按 `tcp.stream` 重组再解析——两条完整 MLLP 帧（重组字节流中两个 `0B` 起始、两个 `1C 0D` 终止，frames hex；`hl7.llp.sob` 偏好门控不作字段断言）、消息数 = 2 ≠ segment 数、重组后段/字段断言照常成立。
14. **`hl7_ipv6_transport`**（9）：`2001:db8::68 → 2001:db8:bb::68`（源/目的分别为 v4 fixture `192.0.2.68`/`198.51.100.68` 的 v6 等价，doc-2026 文档网段 2001:db8::/32 内）对端端口 2575；断言 `ipv6.nxt=6`、数据承载段应用起点 offset 74 起 `0B 4D 53 48 7C ...`、MLLP/HL7 字节与用例 1 一致（外层 IP 头除外）；ACK 关联照常。
15. **`hl7_multi_session_isolation`**（18 = 9+9，两个事件编排会话，多会话展开）：会话 1（四元组 A，src_port 42680）ADT^A01→ACK；会话 2（四元组 B，src_port 42681）ORU^R01→ACK，起点 = 9+1 = 包 10。断言：两会话 `tcp.stream` distinct、四元组 src_port distinct、会话间 MSH-10 `distinct_values`（控制 ID 空间隔离）、PID-3 会话间 distinct（策略隔离）、第二会话 SYN 包号 = 10、各自 ACK 只关联本会话请求（MSA-2 配对不跨会话）。
16. **`hl7_version_profiles`**（11 = 3+2×2+4）：同一连接两笔消息分别 MSH-12=`2.5` 与 `2.8`、MSH-11 处理 ID 分别 `P` 与 `T`（设计 §3.4/§4⑧；MSH-11 紧邻 MSH-12 之前，联合 hex 断言消除单字节歧义：`7C 50 7C 32 2E 35` = `|P|2.5`、`7C 54 7C 32 2E 38` = `|T|2.8` 在各自 MSH 段内存在）；断言两帧版本/处理 ID 字段值不同、其余结构一致；ACK 各自关联（MSA-2 各配其请求）。
17. **`hl7_ack_code_domain`**（13 = 3+3×2+4）：同一连接 3 笔消息，ACK 配置分别为 `AA`、`AE`、`AR`；断言 3 个 ACK 帧 MSA-1 依次 hex `4D 53 41 7C 41 41 7C`（`MSA|AA|`）、`4D 53 41 7C 41 45 7C`（`MSA|AE|`）、`4D 53 41 7C 41 52 7C`（`MSA|AR|`）（值域全覆盖）、每笔 MSA-2 各自 `same_as_packet` 请求 MSH-10。
18. **`hl7_ack_disabled`**（8 = 3+1+4）：`ack_mode=null` 单消息；断言连接内**只有 1 个业务帧**（请求），无反向 ACK 帧（包 4 后无对端→本端方向数据包，挥手直接开始）；请求帧 MSH/MLLP 断言照常——证明自动应答关闭分支不补帧。

**正例总则**：每条实现后至少含 `packet_count`/`min_packets`、载体与方向断言、`has_payload`、可观察 fields、稳定 frames hex；动态值只用关联/存在性断言，不硬编码运行期值。

## 5. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只有 TCP 外壳的假成功；执行期 `expect` 键集合严格为 `{expect_error, error_contains}`。锚词与设计 §7 表一一对应：

| ID | 故障输入（`wire_fault`/配置注入口） | 目标 `error_contains`（主锚词，备选并列） |
|---|---|---|
| `hl7_neg_mllp_framing` | 缺 VT 起始块、结束块 FS/CR 缺失或错误（如 `0x1c` 后无 `0x0d`）、正文出现未转义 `0x0b`/`0x1c`、帧未闭合（流结束无 `0x1c 0x0d`） | `mllp` 或 `framing` |
| `hl7_neg_segment_order` | 首段非 MSH（如 EVN 开头）、段未以 CR 结尾、`0x1c 0x0d` 之后追加段、段名非法（非 3 字符或未知段） | `segment` 或 `msh` |
| `hl7_neg_field_separator` | MSH-1 缺失或长度≠1、MSH-2 长度≠4、正文实际分隔符与 MSH-2 声明不一致、非法转义序列（`\X` 十六进制不成对） | `field` 或 `separator` |
| `hl7_neg_msh_required` | MSH-9/MSH-10/MSH-11/MSH-12 任一缺失、MSH-9 消息类型/触发事件不在值域（如 `XYZ^Q99`）、必需字段错位 | `msh` 或 `required` |
| `hl7_neg_ack_correlation` | 自动派生 ACK 的 MSA-2 ≠ 请求 MSH-10、ACK 缺 MSH-9=ACK 或缺 MSA 段、MSA-1 确认码非 AA/AE/AR | `ack` 或 `correlation` |
| `hl7_neg_transport_port` | UDP 载体（层链 `[{"udp":{}},{"hl7":{}}]`）、目标端口非 2575 且未显式配置、层链缺 tcp（hl7 直连 ip） | `port` 或 `transport` |
| `hl7_neg_length_limit` | 字段长度上界越界：MSH-9 >15、MSH-10 >20、MSH-12 >60、MSH-7 >26、MSA-2 >20（设计 §8 上界表；恰等上界为合法边界值不拒绝） | `length` 或 `limit` |

**合法协议事件不进负例（防误报）**：合法转义序列、重复字段/重复 OBX、空可选字段（`||` 空槽）、TCP 分段/粘连/多帧同段、IPv4/IPv6、`AA`/`AE`/`AR` 全部确认码（`AE`/`AR` 是合法 NAK）、`ack_mode=null` 无 ACK、动态控制 ID/时间/PID、MSH-15/16 留空、字段长度恰等上界（如 MSH-10 恰 20 字符——边界值合法，越界才拒绝）。负例不得污染合法格式：每条故障只改变对应一项协议前提；错误保留最具体来源，不得自动补齐缺失 ID 或重排消息。

## 6. 五层覆盖映射

| 层面 | 用例 ID 落点 | 说明 |
|---|---|---|
| 功能 | 正 1–11、17、18；负 19–25 | 消息类型 ADT^A01/A02/A03、ORU^R01、SIU^S12、ACK/NAK 各一例；MLLP 帧字节、组件/子组件、重复、转义各一例；确认码值域、ack 关闭分支；错误七方向各 1 条负例（framing/段结构/分隔符/必需字段/关联/载体端口/长度上界） |
| 性能 | 13；负 25 | 长消息跨 MSS 分段重组 + 多帧粘连同段；帧长公式与字段长度上界及其越界负例（设计 §3.6/§8） |
| 数据场景 | 11、16、17；负 21、22 | 转义序列值域、MSH-12 版本 2.5/2.8、MSA-1 码 AA/AE/AR 全值域、动态字段 presence/distinct/same_as；分隔符/必需字段负例 |
| 地址与流 | 1（v4 单流基线）、14（v6）、15（多会话双四元组）；**流关联显式不适用** | v4+v6 必覆盖；多会话展开第二会话起点 = 前会话总包数 + 1；流关联不适用：HL7 请求/ACK 同连接完成，无控制流派生数据流/媒体流（MSA-2 是事务关联而非流关联，设计 §4/§5.4） |
| 业务 | 1–5（入院/转科/出院/检验上传/预约现网日常）、7（应用错误确认）、12（批量长连接）、15（多系统并行对接） | 现网典型场景优先于教科书全消息类型遍历；多事务（12、16、17）与多会话（15）齐备 |

## 7. 机器契约与三方一致性

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/hl7.json` 通过；当前数组恰含 1 条 `hl7_neg_unregistered`：`proto=hl7`、层链 `[{"tcp":{}},{"hl7":{}}]`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
2. 实现注册 `hl7` 层后：移除占位，按 §2 顺序补入 25 个语义用例；ID、顺序与设计 §9 完全一致（18 正 + 7 负）。
3. 正例每条含 `packet_count`（或 `min_packets`）+ `fields` + `frames`；`fields` 只用 §1 实测存在的 tshark 字段；MSH-9 派生字段提取不稳时用 §3 的 frames hex 约定，实现期定并同步四件套。
4. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields/frames。
5. 断言包号引用跨会话/跨连接时用 `tcp.stream` + 会话起点规则（§3.5），不硬编码全局包号；动态值用 `same_as_packet`/`distinct_values`/`nonzero`。
6. MLLP 帧字节（`0B` 起始、`1C 0D` 终止）按字节断言；段 CR ≠ 终止 CR；TCP segment 边界不得替代 MLLP 帧边界（重组后断言）。
7. 负例覆盖配置错/线格式错/段结构错/必需字段错/确认关联错/载体端口错/长度上界错七类并传播为 task error；`unknown layer` 占位不得冒充协议语义负例已执行。

## 8. 三方一致性表

设计 §9、本文 §2、实现后 `hl7.json` 保持同一 25 个语义 ID、同一顺序（当前 JSON 另有占位，不计入）：

```text
hl7_adt_a01_ipv4
hl7_adt_a02_transfer
hl7_adt_a03_discharge
hl7_oru_r01_results
hl7_siu_s12_appointment
hl7_ack_success_association
hl7_nak_error_segment
hl7_mllp_frame_bytes
hl7_component_subcomponent
hl7_field_repetition
hl7_escape_sequences
hl7_multi_transaction_long_connection
hl7_tcp_mss_reassembly
hl7_ipv6_transport
hl7_multi_session_isolation
hl7_version_profiles
hl7_ack_code_domain
hl7_ack_disabled
hl7_neg_mllp_framing
hl7_neg_segment_order
hl7_neg_field_separator
hl7_neg_msh_required
hl7_neg_ack_correlation
hl7_neg_transport_port
hl7_neg_length_limit
```

## 9. 修订记录

- v1.0.0（2026-08-20）：旧稿首版（与旧设计稿配套的 14+6 ID 索引）。
- v2.0.0（2026-08-31）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写/review，取代 2026-08-20 旧稿（旧稿见 git 历史）。按原子用例原则拆分为 18 正 + 6 负：ADT^A01/A02/A03、ORU^R01、SIU^S12 各自成例，MLLP 起止块/组件/子组件/重复/转义各一例，ACK 关联与 NAK ERR 段分立，新增 ack 关闭分支（`hl7_ack_disabled`）与确认码值域（`hl7_ack_code_domain`）原子例；删除 `pcap_nic_consistency`（测试方法非协议语义）、`multi_flow_dynamic_fields`（HL7 单连接字节流，多流不适用）、`v25_v28` 与 `multi_obx` 重复覆盖并入版本/结果用例。按 tshark 3.6.14 实测固化断言基线（hl7 dissector 绑定 2575、`hl7.llp.sob/eob/segment/raw.segment/field/message.type/event.type/malformed` 字段族、MSH-9 hidden 项提取性校准项）；新增 §3 线上编码与偏移断言（帧字节/段名/MSH 前缀 hex/重组/多会话包号）与 §6 五层覆盖映射（流关联显式不适用）。**待独立隔离审查**。
- v2.0.1（2026-09-01）：按独立隔离审查 12 项问题清单（1 CRITICAL / 3 MAJOR / 8 MINOR）修复：① **`hl7.segment` 语义更正（CRITICAL）**——实测（构造 MLLP mini pcap 实跑）为整段原始文本而非段名，段序列/段存在性/raw 前缀类断言全部改 frames hex（§1/§3.2/§4 #1/#4/#5/#7/#17）；② `hl7.llp.sob`/`hl7.llp.eob`/`hl7.raw`/`hl7.raw.segment` 偏好门控写明（`hl7.display_llp`/`hl7.display_raw` 默认 FALSE，开启后 sob=`0x0b`、eob=`0x1c0d`），harness 不支持 `-o` 传参故 MLLP 边界断言改 frames hex（§1/§3.1/§4 #8/#13）；③ 新增长度上界负例 `hl7_neg_length_limit`（负例 6→7、语义 ID 24→25，§1/§2/§5/§6/§7/§8 与设计/JSON 三方同步）；④ #16 补 MSH-11 处理 ID `P`/`T` 联合断言（`|P|2.5`/`|T|2.8` hex）；⑤ 设计声明字段断言落地：#1 补 MSH-7/EVN-2 槽 nonzero 与 PID-7/PID-8、#4 补 OBX-11/OBR-25、#5 补 AIS-2、#6 补 ACK 帧 MSH-7 槽 nonzero 与 MSH-11/MSH-12 同请求断言；⑥ #12 FIN 帧号更正（最后一笔 ACK=包 9，FIN 自包 10 起）；⑦ #13 写明短消息 `ack=null`（packet_count 10 = 3+2+1+4 成立）；⑧ #11 转义载体改 OBX-5（OBX-2=`TX`/`ST`，删不在允许段表的 NTE）；⑨ 占位 JSON notes 计数更正为 25 语义 ID（18 正 + 7 负）；⑩ `hl7.message.type`/`hl7.event.type` 提取性由"实现后校准"更新为实测可提取。

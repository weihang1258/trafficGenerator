# DOIP（Diagnostic over IP，基于 IP 的车辆诊断）测试用例契约

> 版本：v1.0.0（P-PIPE P1–P3 文档轨产出；#57 doip）
> 日期：2026-09-26
> 配套设计：`docs/protocol-designs/05-doip-design.md`（v3.0.0，§12–§19 为本次新增）
> 机器契约：`trafficgen/test/protocol_pcap/cases/doip.json`（现存 **115 例**，旧扁平形；P5 按设计 §18.2 改写为本契约 §2 的 41 ID）
> 状态：**设计阶段**。本次**不跑 suite、不启动服务器**，不宣称任何绿的结论；ID 权威 = 本文 §2。

## 1. 测试原则与形状基线

- **形状基线（CORE_MEMORY §1）**：`spec_json` 必须是**纯 layers** 形——地址只住 `ip` 层、端口只住 `tcp` 层、数量只走 `flow_control`；顶层只允许 `layers`/`flow_control` 及其家族/`output`（§1.11）。**正例顶层键 = 0**（白名单外即红）。
- **载体**：doip 层为 TCP-only 终结层，链形 `[ip, tcp, doip]`（IPv6：`[ipv6, tcp, doip]`），`tcp.dst_port` 默认 13400（`chain_planner.go:1038-1041`）。UDP 面（发现/实体状态/电源模式）**链上不可达**（设计 §19 G-DOIP-2）→ 用例配置**不得出现** `discovery`/`entity_status`/`power_mode` 三键；**`vin`/`eid`/`gid` 同样不得出现**（死配置：校验嵌在已删的 `Discovery != nil` 块 `doip.go:62-88`，生成器零读取，设计 §15.3/G-DOIP-7）。层内只允许七键：`protocol_version`/`logical_address`/`tester_address`/`activation`/`messages`/`alive_check`/`generic_nack`。
- **断言通道**：`doip.*` tshark 字段（本机 TShark 3.6.14 实测 **33 个** `doip.*` 字段，口径 `tshark -G fields | awk -F'\t' '$3 ~ /^doip[.]/' | wc -l`）+ `frames` hex（DoIP 头 8B 固定偏移：Ethernet+IPv4+TCP 无 options 起点 **54** = 14+20+20；IPv6 起点 **74** = 14+40+20）+ 载体字段 `ip.proto`/`ipv6.nxt`/`tcp.srcport`/`tcp.dstport`/`tcp.flags`。**不自创字段名**；注意 dissector 把 FurtherActionRequired 拼作 `doip.futher_action`。
- **动态值纪律（§9.34/§9.35）**：`flows>1` 的逐流变化只用 `presence`/`nonzero`/`distinct_values`/`same_as_packet` 断言，禁止硬编码；速率/包数按真实 pcap 钉（§9.31/§14.20）。
- **负例纪律（§14.11/§14.12）**：`expect` 键集合严格为 `{"expect_error","error_contains"}`；锚词取自 Validate 期（生成期错误会被驱动契约吞成 `completed + 0 包`，见设计 §15.5 假成功红线）。
- **存量声明（§9.14/§14.4）**：现存 115 例为旧扁平形（115 例带顶层 `src_ip`/`dst_ip`/`src_port`/`doip`；46 例另带 `layers` = §1.4 混用形），逐族去向见设计 §18，本文 §2 是改写后的目标 ID 集。

## 2. 原子用例索引（41 ID = 16 正 + 25 负，顺序为权威）

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `doip_tcp_activation_basic` | 正 | IPv4/TCP 13400：0x0005 → 0x0006 RC=0x10；SA/TA 与 SLA 一致性 | 4 |
| 2 | `doip_tcp_activation_v1` | 正 | PV=0x01 最小兼容子集（0x0005 PayloadLength=7、0x0006=9、无 OEM） | 4 |
| 3 | `doip_tcp_activation_confirmation` | 正 | RC=0x11 + ConfirmationRequired → 0x0005×2 + 0x0006（0x11→0x10） | 6 |
| 4 | `doip_tcp_activation_oem_varlen` | 正 | OEM-specific 变长 0B/4B/255B → PayloadLength 7+N / 9+N | 4 |
| 5 | `doip_tcp_diag_uds_session_control` | 正 | UDS 0x10/0x11（含 sub-function 必选字节）；NRC 否定响应 `7F <SID> <NRC>` | 6 |
| 6 | `doip_tcp_diag_uds_read_write_did` | 正 | UDS 0x22/0x2E：请求与正向响应（SID 按位或 0x40）、DID 2B、HasSubFunction 三态 | 8 |
| 7 | `doip_tcp_diag_uds_security_access` | 正 | UDS 0x27 四形：seed 请求 / 送 key / 奇 sub 响应带 seed / 偶 sub 响应无 key | 8 |
| 8 | `doip_tcp_diag_uds_transfer` | 正 | UDS 0x34 → 0x36×N → 0x37；BlockSeq `n%256` 回绕；>MSS-40 时协议级分段 | 12 |
| 9 | `doip_tcp_diag_ack` | 正 | 0x8001 + 0x8002（AckCode=0x00；PrevDiag = 被确认 UserData 完整副本；PayloadLength=5+M） | 6 |
| 10 | `doip_tcp_diag_nack` | 正 | 0x8001 + 0x8003（NackCode 0x02/0x03/0x04/0x05/0x06/0x07/0x08 逐值） | 6 |
| 11 | `doip_tcp_alive_check` | 正 | 0x0007（down，零长）+ 0x0008（up，SA=TesterAddress，PayloadLength=2） | 6 |
| 12 | `doip_tcp_generic_nack` | 正 | 0x0000（down；NackCode 0x00–0x04 逐值；PayloadLength=1） | 6 |
| 13 | `doip_tcp_full_flow` | 正 | 端到端：激活 → 诊断 ×N → 探活插入中段 → FIN 挥手（含主动探活插入位置） | 22 |
| 14 | `doip_ipv6_tcp_flow` | 正 | IPv6 全流程（`ipv6.nxt=6`，起点 74），与 IPv4 fixture 独立 | 22 |
| 15 | `doip_tcp_multiflow_dynamic` | 正 | `flows=N` 多会话 + `ip`/`tcp` 层动态五策略（inc 回绕 / rand 可复现 / list 轮转 / pattern 替换） | 8×N |
| 16 | `doip_tcp_options` | 正 | `tcp` 层开关：`mss`（缺省 1460）、`handshake`、`termination` 三档组合 | 6 |
| 17 | `doip_neg_activation_denied` | 负 | RC=0x01（拒绝码）→ 链上判错（ISO 的 FIN 关连不可表达，钉现状） | — |
| 18 | `doip_neg_activation_confirmation_missing` | 负 | RC=0x11 但 `confirmation_required` 未置位 | — |
| 19 | `doip_neg_udp_carrier` | 负 | 显式 `udp` 载体（`[ip,udp,doip]`） | — |
| 20 | `doip_neg_udp_phase_discovery` | 负 | 层内 `discovery` 非空（UDP 面） | — |
| 21 | `doip_neg_udp_phase_entity_status` | 负 | 层内 `entity_status` 非空 | — |
| 22 | `doip_neg_udp_phase_power_mode` | 负 | 层内 `power_mode` 非空 | — |
| 23 | `doip_neg_flat_toplevel` | 负 | 层链 + 顶层 `doip` 空子映射并存（presence 判死） | — |
| 24 | `doip_neg_flat_field` | 负 | 顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/`dst_mac`/`tcp` 任一 | — |
| 25 | `doip_neg_activation_type_reserved` | 负 | ActivationType=0x02（保留区） | — |
| 26 | `doip_neg_response_code_reserved` | 负 | ResponseCode=0x12（同类含 0x08–0x0F）；协议版本 0x03/0xFF 同族 | — |
| 27 | `doip_neg_nack_code_reserved` | 负 | 0x8003 NackCode=0x00 / 0x01 / 0x09 | — |
| 28 | `doip_neg_generic_nack_code_reserved` | 负 | 0x0000 NackCode=0x05 | — |
| 29 | `doip_neg_uds_nrc_reserved` | 负 | UDS NRC=0x00 / 0xFF | — |
| 30 | `doip_neg_uds_sid_unsupported` | 负 | UDS ServiceID=0xFF（不在 10 服务表） | — |
| 31 | `doip_neg_uds_subfunction_conflict` | 负 | SID=0x22 + `HasSubFunction=true` | — |
| 32 | `doip_neg_uds_key_on_even_response` | 负 | SID=0x27 偶 sub + `IsResponse=true` + Key 非空 | — |
| 33 | `doip_neg_sa_ta_consistency` | 负 | 0x8001 SA ≠ TesterAddress（TA ≠ LogicalAddress 同族） | — |
| 34 | `doip_neg_alive_sa_consistency` | 负 | 0x0008 SA ≠ TesterAddress | — |
| 35 | `doip_neg_messages_without_activation` | 负 | `messages` 非空但 `activation` 缺席 | — |
| 36 | `doip_neg_mss_below_min` | 负 | `tcp.mss` < 536（RFC 879 下限） | — |
| 37 | `doip_neg_v1_oem` | 负 | PV=0x01 + OEM-specific 非空 | — |
| 38 | `doip_neg_direction_invalid_activation` | 负 | `activation.direction`="invalid" | — |
| 39 | `doip_neg_direction_invalid_messages` | 负 | `messages[0].direction`="invalid" | — |
| 40 | `doip_neg_direction_invalid_alive` | 负 | `alive_check.direction`="invalid" | — |
| 41 | `doip_neg_ack_code_reserved` | 负 | 0x8002 AckCode=0x01 | — |

**最小实现条目优先（§9.26）**：本文 41 个 ID 中，**先补**最小实现面（#1 激活 / #9–#10 确认对 / #5–#8 UDS 核心 / #19 载体 / #35 守卫）；**再扩**现网高频（#13 端到端 / #14 IPv6 / #15 多流）；最后全量。

**对账**：本文 41 = 16 正 + 25 负；设计 §12/§13 的每行/格回指本表；与 `cases/doip.json` 的 41 个 ID 逐序一致（P5 落地后由门 2② 机检）。设计侧缩写 `Nn` ↔ 本文 `#(n+16)`（N1=#17 … N25=#41）。

## 3. 正例逐项断言契约（16 项）

1. **`doip_tcp_activation_basic`**：链 `[ip,tcp,doip]`；断言 `ip.proto=6`、`tcp.dstport=13400`、`doip.version=0x02`、`doip.inverse=0xfd`、`doip.type=0x0005`（up）与 `0x0006`（down）、`doip.length=7`/`9`、`doip.source_address=0x0e80`、`doip.response_code=0x10`、`doip.reserved_iso=0`；frames 钉 8B 头（起点 54）；`packet_count=4`（握手/挥手归 tcp 层，tcp fixture 口径以实测为准）。
2. **`doip_tcp_activation_v1`**：`doip.version=0x01`、`doip.inverse=0xfe`、`doip.length=7`/`9`（V1 强制无 OEM）；`packet_count=4`。
3. **`doip_tcp_activation_confirmation`**：事件序 0x0005 → 0x0006(RC=0x11) → 0x0005 → 0x0006(RC=0x10)；断言 `doip.response_code` 逐包为 `0x11`/`0x10`、`doip.length=9`；`packet_count=6`。
4. **`doip_tcp_activation_oem_varlen`**：三档 OEM（0B/4B/255B）→ `doip.length` = 7/11/262（0x0005）与 9/13/264（0x0006）；`doip.reserved_oem` 长度逐档断言（**变长无长度前缀**，scapy `doip.py:199` 同款）；`packet_count` 逐档钉。
5. **`doip_tcp_diag_uds_session_control`**：0x8001 UserData = `10 03`（请求）/`7F 10 12`（NRC 否定响应，SID 为**请求 SID**）；断言 `doip.data` 字节序列 + `doip.source_address`/`doip.target_address`；`packet_count=6`。
6. **`doip_tcp_diag_uds_read_write_did`**：UserData = `22 F1 90`（请求）/`62 F1 90 <data>`（正向响应，SID 按位或 0x40）；`2E <DID> <data>`；`HasSubFunction` 三态：`0x22` 配 `true` 判错（负例 #31）、缺省与 `false` 均不产 sub-function 字节；`packet_count=8`。
7. **`doip_tcp_diag_uds_security_access`**：四形逐字节：`27 01`（seed 请求）/`27 02 55 66 77 88`（送 key）/`67 01 <seed>`（奇 sub 响应带 seed）/`67 02`（偶 sub 响应**无 key**）；`packet_count=8`。
8. **`doip_tcp_diag_uds_transfer`**：`34 00 44 00 00 00 01 00 00 00 10` → `36 01 <data…>`（BlockSeq 递增，n=256→0x00、n=257→0x01 回绕）→ `37`；Data > MSS-40 时按 `MSS-42` 分块、每块独立 0x8001；断言逐块 `doip.length` 与 `doip.data` 前缀；`packet_count=12`。
9. **`doip_tcp_diag_ack`**：`doip.type=0x8002`、`doip.diag_ack_code=0x00`、`doip.previous` = 被确认 UserData 完整副本、`doip.length=5+M`（**无 PrevDiag 长度字段**，scapy `doip.py:224` 同款）；方向与被确认 0x8001 相反（SA/TA 互换）；`packet_count=6`。
10. **`doip_tcp_diag_nack`**：`doip.type=0x8003`、`doip.diag_nack_code` 逐值 0x02–0x08、`doip.previous` 同前；`packet_count=6`。
11. **`doip_tcp_alive_check`**：0x0007 `doip.length=0` 且方向 down；0x0008 `doip.length=2`、`doip.source_address=0x0e80` 且方向 up；两包 `direction` 均以缺省（空值）表达一次（覆盖 §8.6 默认方向分支 + 大小写不敏感另由 `"UP"` 字面值覆盖）；`packet_count=6`。
12. **`doip_tcp_generic_nack`**：`doip.type=0x0000`、`doip.length=1`、`doip.nack_code` 逐值 0x00–0x04、方向固定 down；`packet_count=6`。
13. **`doip_tcp_full_flow`**：断言完整事件序列（0x0005/0x0006/0x8001/0x8002×N/0x0007/0x0008）+ 挥手由 tcp 层产出；探活插入诊断中段时**顺序**必须按 `messages[]` 位置体现（§9.28：不用「字段出现过」冒充「行为顺序对」）；`packet_count=22`（以真实 pcap 校准）。
14. **`doip_ipv6_tcp_flow`**：`ipv6.nxt=6`、`tcp.dstport=13400`、起点 **74**；DoIP 层字节与 IPv4 形逐字节一致；`packet_count=22`。
15. **`doip_tcp_multiflow_dynamic`**：`flow_control.flows=N`；`ip.src`/`tcp.src_port` 写动态对象；断言 ①inc 到尾回绕 ②rand 同 seed+index 可复现 ③list 轮转 ④pattern 替换 ⑤**静态复制被拒**（同模板无动态 + `flows>1` → 拒绝/告警，§12.9）；四元组互异用 `distinct_values`；`packet_count` 按实际 pcap 钉。
16. **`doip_tcp_options`**：`tcp.mss`（含 0 → 回退 1460）、`handshake=false`、`termination=false` 三档组合各一断言（`tcp.flags` 无 SYN / 无 FIN）；`packet_count=6`。

> **计数口径**：本文的 `packet_count` 是**约定值**，落地时必须由 P5 先跑一遍拿真实 pcap 再钉（§9.31/§14.20）；凡「握手/挥手归 tcp 层」的差异以实测为准并回填本表。

## 4. 负例契约（25 项）

每个负例必须在 Validate 期失败并传播为 task error；不得产生成功 pcap、`completed/0 packet` 或只剩 TCP 外壳的假成功。`expect` 键集合严格为 `{"expect_error","error_contains"}`：

| # | ID | 故障输入 | 目标 `error_contains` | 现状锚词来源（实读） |
|---:|---|---|---|---|
| 17 | `doip_neg_activation_denied` | `activation.response_code`=0x01 | `activation failed` | `layer_gen.go:302-305` |
| 18 | `doip_neg_activation_confirmation_missing` | RC=0x11 且 `confirmation_required` 缺省 | `activation failed` | 同上（0x11 无确认走同一分支） |
| 19 | `doip_neg_udp_carrier` | 链含 `udp` 层 | `carrier` | `complete.go:447-460` |
| 20 | `doip_neg_udp_phase_discovery` | 层内 `discovery` 非空 | `discovery` 且 `not supported` | `layer_gen.go:289` |
| 21 | `doip_neg_udp_phase_entity_status` | 层内 `entity_status` 非空 | `entity_status` 且 `not supported` | `layer_gen.go:292` |
| 22 | `doip_neg_udp_phase_power_mode` | 层内 `power_mode` 非空 | `power_mode` 且 `not supported` | `layer_gen.go:295` |
| 23 | `doip_neg_flat_toplevel` | `layers` + 顶层 `doip:{}` 并存 | `no longer accepts a top-level doip sub-config` | **P5 待落地**（G-DOIP-5） |
| 24 | `doip_neg_flat_field` | 顶层 `src_ip`（等七键） | `no longer accepts flat config field` | `strategy_convert.go:8286-8293` |
| 25 | `doip_neg_activation_type_reserved` | `activation_type`=0x02 | `ActivationType must be 0x00, 0x01, or 0xE0-0xFF` | `doip.go:126` |
| 26 | `doip_neg_response_code_reserved` | `response_code`=0x12 | `ResponseCode must be 0x00-0x07, 0x10, or 0x11` | `doip.go:132` |
| 27 | `doip_neg_nack_code_reserved` | `NackCode`=0x00/0x01/0x09 | `NackCode must be 0x02-0x08` | `doip.go:166` |
| 28 | `doip_neg_generic_nack_code_reserved` | `generic_nack.nack_code`=0x05 | `GenericNack.NackCode must be 0x00-0x04` | `doip.go:218` |
| 29 | `doip_neg_uds_nrc_reserved` | `NegativeResponseCode`=0x00/0xFF | `NegativeResponseCode must be 0x01-0x7F` | `doip.go:255` |
| 30 | `doip_neg_uds_sid_unsupported` | `ServiceID`=0xFF | `ServiceID 0xFF is not supported` | `doip.go:241` |
| 31 | `doip_neg_uds_subfunction_conflict` | SID=0x22 + `HasSubFunction`=true | `does not support sub-function` | `doip.go:248` |
| 32 | `doip_neg_uds_key_on_even_response` | SID=0x27 偶 sub + `IsResponse`=true + Key 非空 | `Key must be empty for even sub-function response` | `doip.go:263` |
| 33 | `doip_neg_sa_ta_consistency` | 0x8001 `source_address`=0x1111（≠TesterAddress） | `must match TesterAddress` | `doip.go:172` |
| 34 | `doip_neg_alive_sa_consistency` | 0x0008 `source_address`=0x1111 | `must match TesterAddress` | `doip.go:211` |
| 35 | `doip_neg_messages_without_activation` | `messages` 非空、`activation` 缺席 | `Messages require Activation` | `doip.go:139` |
| 36 | `doip_neg_mss_below_min` | `tcp.mss`=200 | `MSS 200 too small` | `doip.go:228` |
| 37 | `doip_neg_v1_oem` | `protocol_version`=1 + `activation.oemspecific` 非空 | `V1 does not support OEM-specific data` | `doip.go:57` |
| 38 | `doip_neg_direction_invalid_activation` | `activation.direction`="invalid" | `Activation.Direction must be "up", "down", or empty` | `doip.go:122` |
| 39 | `doip_neg_direction_invalid_messages` | `messages[0].direction`="invalid" | `Messages[0].Direction must be "up", "down", or empty` | `doip.go:158` |
| 40 | `doip_neg_direction_invalid_alive` | `alive_check.direction`="invalid" | `AliveCheck.Direction must be "up", "down", or empty` | `doip.go:208` |
| 41 | `doip_neg_ack_code_reserved` | `messages[0].ack_code`=0x01 | `AckCode must be 0x00` | `doip.go:161` |

**不许误报为负例的合法形**：空 `doip:{}` 层（合法，走缺省）、`protocol_version` 缺省（=V2）、`direction` 空值（走 PayloadType 默认方向）、`mss` 缺省（=1460）、V1+无 OEM、RC=0x10、RC=0x11+确认（正例）。

## 5. 三方一致性与静态检查

1. **ID 一致性**：本文 §2 的 41 ID = 设计 §12/§13 回指 = `cases/doip.json` 落地后的 41 条，顺序一致（16 正 #1–#16 + 25 负 #17–#41）；门 2② 机检。
2. **形状一致性**：正例 `spec_json` 顶层键 ⊆ {`layers`,`flow_control`,`group_id`,`tuples`,`output`}（§1.13 白名单制）；`doip` 层 config 只允许七键（设计 §15.3）；UDP 三键出现即负例 #20–#22，`vin`/`eid`/`gid` 出现即违规（死配置）。
3. **断言一致性**：字段名只用实测的 33 个 `doip.*`（注意 `doip.futher_action` 拼写）+ 通用 `ip`/`ipv6`/`tcp`/`frame` 字段；不自创；动态值只用 presence/nonzero/distinct/same_as。
4. **负例纪律**：`expect` 只能有 `expect_error`/`error_contains`；锚词非空且取自 Validate 期（§14.11）。
5. **JSON 合法性**：`python3 -m json.tool trafficgen/test/protocol_pcap/cases/doip.json` 必须成功。
6. **未跑声明**：本次不跑 suite；不得把存量 115 例的任何运行结果报告为 DOIP suite 通过。

## 6. 实现后执行建议

1. 先跑负例族 #17–#41（锚词最便宜），确认 Validate 期拒绝与锚词逐条命中；
2. 再跑正例 #1–#4（激活族）钉 `doip.length`/`doip.response_code` 与 frames 偏移 54/74；
3. 再跑 #9/#10（Ack/Nack 的 `doip.previous` 边界）与 #8（0x36 分段与 BlockSeq 回绕）；
4. 最后 #13/#14/#15/#16（端到端 / IPv6 / 多流动态 / 开关）；
5. 每步先 `flowb_run_protocol_case` 落 pcap 到 `/tmp/mcp-pcaps/doip/`，用 `tshark -r <pcap> -Y doip -T fields -e doip.type -e doip.length -e doip.response_code` 对照，再回填 `packet_count` 与期望值（§9.31/§14.20）；
6. 全量跑（§14.19 不许增量）全绿后再挂门 3 抽查（§9.53 必抽最复杂用例 = #13/#15）。

## 7. 修订记录

- v1.0.0（2026-09-26）：建立 T-DOIP 契约（16 正 + 25 负 = 41 ID），覆盖 ISO 13400-2 的 TCP 面（激活/确认/OEM/诊断/确认与否定确认/探活/通用 NACK）、UDS 服务子集、链形与载体边界、动态字段、负例锚词；UDP 面（8 PayloadType）按 G-DOIP-2 标不可达、配置键删；`vin`/`eid`/`gid` 按死配置删（G-DOIP-7）。本次不跑 suite。

## 8. P3 固定动作（CORE_MEMORY §3.15 / §3.14 / §9.52 / §9.14）

### 8.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 同一条 TCP 13400 连接上：激活（0x0005/0x0006）→ 多轮诊断（0x8001/0x8002 ×N，含 0x34→0x36→0x37 三段依赖）→ 探活 → 挥手 | **已覆**：#5/#6/#7/#8（UDS 多轮）+ #13（端到端 22 事件） |
| ② | 非正常结束 | 激活被拒（RC 0x01…）链上判错（ISO 的 FIN 关连不可表达）；诊断消息 0x8003 否定确认；UDS 否定响应 `7F <SID> <NRC>` | **已覆半程**：#10（0x8003 逐值）+ #5（NRC）；**拒绝即关连**形 → **G-DOIP-3**，现状钉负例 #17/#18（9.36 钉现状） |
| ③ | 长保活 | 单 TCP 连接内多轮诊断 + 探活（0x0007/0x0008）中插；`tcp.termination=false` 形 | **已覆**：#11（探活）+ #13（探活插入诊断中段）+ #16（`termination` 开关） |

无空项。②的「拒绝即关连」面进 B′（G-DOIP-3），不删用例。

### 8.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流四类审计）

**A′（现有引擎可构建 → 41 ID 内已覆，P4 并入）**：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | PayloadType 16 型；ResponseCode 13 值；ActivationType 值域；NackCode(0x8003) 7 值；AckCode 单值；GenericNack 5 值；UDS SID 10 值；NRC 0x01–0x7F；HasSubFunction 三态；0x27 奇偶四形；BlockSeq `n%256`；OEM 变长；PrevDiag 变长（无长度字段）；零长 payload 型；Direction 三态 | #1–#12 已覆；值域越界 → 负例 #25–#32、#41；Direction 非法 → #38–#40 |
| 业务 | 激活成功/确认（0x11）/探活插入/多轮诊断/UDS 服务序列/挥手开关 | #1/#3/#5–#8/#11/#13/#16 已覆 |
| 现网 | 诊断仪发现时序、公告间隔、多 ECU 并发数、激活被拒行为、NAT 形态 | **无证据 → G-DOIP-9**（确认方式三选一，见设计 §13.1/§13.2） |
| 多流 | 多会话并发（`flows=N`，各独立 4-tuple）+ 单流内多轮事务 | #15（多会话）+ #13（同连接多轮）已覆 |
| 地址族 | IPv4/IPv6 对称（TCP 13400、起点 54/74） | #1 与 #14 已覆，逐格对照 |
| 动态 | 四元组五策略（inc 回绕/rand 可复现/list 轮转/pattern 替换/静态复制拒） | #15 已覆；**业务字段零动态**（设计 §14.12 理由）→ 明确不支持（非缺口） |
| 长保活 | 单连接多轮诊断 + 探活中插 | #13/#16 已覆 |

**B′（引擎结构缺口 → 设计 §19 立项，D-DOIP-1「明确不解决 + 迁入计划」）**：
**G-DOIP-1**（层 config 无住处）、**G-DOIP-2**（UDP 三阶段不可达，40 例存量作废）、**G-DOIP-3**（激活拒绝路径不可达，4 例存量作废 + 1 例改判）、**G-DOIP-4**（0x11 被拒收尾 schema 不可表达）、**G-DOIP-5**（`CheckProtoFlat` 无 doip 分支 → 负例 #23 今日不成立）、**G-DOIP-6**（`coverage_gate` 无块）、**G-DOIP-7**（VIN/EID/GID 死配置，3+15+12 例含键）、**G-DOIP-8**（业务动态零开）、**G-DOIP-9**（现网无证据）。**均不挡开工**（除 G-DOIP-1 是形状前置）。

### 8.3 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **规范/官方文档反推**（ISO 13400-2:2019 §7/§8.4.1/§8.5.1/§8.5.3/§8.5.5/§9.2.4/§9.3.6/§10.3.2/§10.4.3/§10.4.5/§11.1/§11.2.2 + ISO 14229-1 服务与 NRC 表），**非**引擎能力面反推；引擎/scapy/tshark 只作现状取证（`doip.go` 实读行号、scapy 2.7.0 `doip.py` 实读行号、TShark 3.6.14 实测 33 字段）。
- **对账两行**：**规范逻辑点总数 = 54**（设计 §12.1 八项 8 行 + §12.2 子表① 16 格 + §12.3 子表② 30 行）；**用例覆盖数 = 38**（每点回指本文 §2 的 T-DOIP ID）+ **明确不支持/明确不解决 4** + **立项 12**；38+4+12 = 54，无遗漏。
- **粒度声明**：54 点按行/格计数（八项按行、子表① 按格、子表② 按行），行内子面缺口另登设计 §19，不折进 54 点、不冒充覆盖。**存量 115 例全绿 ≠ 覆盖全**。

### 8.4 §3.14 豁免边界审计

本协议**有长连接载体**（TCP 13400 单连接承载多轮诊断 + 探活），故 §3 五件套**不豁免**（设计 §14.3 逐件写全）。两项各至少一例：
- **多流并发**：#15（`flows=N` 多会话，各独立四元组与独立生命周期）；
- **单消息多载荷**：#8（单个 0x8001 承载 0x36 大块数据并按 `MSS-42` 分段，每段独立 0x8001 与 BlockSeq）、#9/#10（0x8002/0x8003 单条承载完整 PrevDiag 副本）、#13（单会话内 22 个事件）。

**关联副流（§3.8）不适用**：DoIP 无控制流/数据流分离（16 型表无数据面型；`doip.go` 全文件单 `configChan`；scapy `DoIPSocket` 单连接）——理由与证据见设计 §14.3「关联关系」段，非豁免逃逸。

### 8.5 三源回指行

**源①** ISO 13400-2:2019（§7 载体 / §8.4.1 / §8.5.1 / §8.5.3 / §8.5.5 / §9.2.4 / §9.3.6 / §10.3.2 / §10.4.3 / §10.4.5 / §11.1 / §11.2.2）+ ISO 14229-1（UDS 服务表、NRC 表）→ **源②** D-DOIP-1（设计 §15）→ **源③** 已确认现网行为（**缺证据 → G-DOIP-9，不冒充第三源**）→ 本文 §2（41 ID）→ `test/protocol_pcap/cases/doip.json`。ID 权威 = 本文 §2。

### 8.6 断言契约核对结论（与设计 §12/§13 一致）

本文 §2 的 41 ID 与设计 §12 子表①②、§13 裁定逐条核对：子表① 16 格中 9 格指向本文正例、7 格指向 G-DOIP-2；子表② 30 行中 22 行指向本文用例、5 行指向 G-DOIP-2/3/4/7/2、3 行标明确不解决（R19/R24/R25）；八项 8 行 7 已覆 + 1 明确不支持。**存量审计（§9.14）**：115 例逐族去向见设计 §18.1–§18.3（F1 40 例作废 / F2 7 例拆分 / F3 22 例（含 13 合入 + 4 例改判负例 + 3 值域负例 + 2 同族去重）/ F4 33 例 / F5 6 例 / F6 6 例 / F7 1 例），去扁平改写清单见设计 §18.2（W1–W8）。断言通道用实测的 33 个 `doip.*` 字段 + frames hex，动态值用 presence/nonzero/distinct/same_as，**不自创字段名**。**未跑期纪律**：本次不跑套件，不得报告为 DOIP suite 通过。

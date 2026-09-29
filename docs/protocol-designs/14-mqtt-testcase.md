# MQTT 测试用例契约（as-built）

> 版本：v1.0.0（P-PIPE 文档轨批次二 as-built）  
> 日期：2026-09-29  
> 配套设计：`docs/protocol-designs/14-mqtt-design.md`（v2.0.2）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/mqtt.json`（机读顺序为权威）

一句话：**206 条 MQTT 检查（140 正 + 66 负），覆盖 TCP/TLS 承载、3.1.1/5.0 控制包、QoS、属性、会话、动态策略与边界拒绝；正例查包序/帧字节/字段，负例查 planner/validator 锚词。**

## 1. 形状与统计基线

| 项 | 机读实测 |
|---|---:|
| 总例数 | **206** |
| 正/负 | **140 / 66** |
| JSON 顺序 | 1–206，本文不重排 ID |
| 正例 `spec_json` 顶层键 | `{layers}` × **140**（全部正例，零游离键）；负例中另有 65 例同为 `{layers}`（合计 `{layers}` × 205），1 例例外见下行 |
| 负例 `spec_json` 顶层键 | `{layers}` × **65**；`{mqtt,group_id}` × **1** |
| 层形 | `[ip,tcp,mqtt]` × **204**；`[ip,tcp,tls,mqtt]` × **1**；空 `layers` × **1**（故意判死） |
| `expect` 负例形状 | **66/66** 含 `expect_error,error_contains,notes`，无包数/fields/frames |
| 正例 `fields` 条数 | **52** |
| 正例 `frames` 条数 | **215** |
| 正例包数键 | `packet_count` × **136**；`min_packets` × **4**（其中 `mqtt_t005_publish_qos_fixed_header` 同时有二者；动态三例为 min-only；TLS 例无包数） |
| 负例包数键 | **0**（不允许假成功或 0 包成功） |

`layers` 内部键分布已实测：IP/TCP/MQTT 是主路径；仅 `mqtt_over_tls` 加 TLS；仅 `mqtt_t149_group_id_shared` 使用游离 `{mqtt,group_id}`，且它是**故意 presence 判死负例，不是正例残留**。

## 2. ID 顺序与场景族索引

| 场景族 | 数量（正/负） | ID（严格按 JSON 出现顺序） |
|---|---:|---|
| S场景/基础业务编排 | 14（14/0） | `mqtt_s1_connect_basic`, `mqtt_s2_publish_qos0`, `mqtt_s3_publish_qos1`, `mqtt_s4_publish_qos2`, `mqtt_s5_subscribe`, `mqtt_s7_ping`, `mqtt_s9_will`, `mqtt_s12_v5_properties`, `mqtt_s13_auth`, `mqtt_s14_connack_reject`, `mqtt_s15_v5_keepalive_timeout`, `mqtt_s10_multi_session__s0`, `mqtt_s10_multi_session__s1`, `mqtt_s10_multi_session__s2` |
| TLS承载 | 1（1/0） | `mqtt_over_tls` |
| T系列规范/边界/状态机 | 176（118/58） | `mqtt_t013_will_retain_flag`, `mqtt_t014_will_qos2_flag`, `mqtt_t017_suback_multi_reason`, `mqtt_t019_v5_disconnect_reason`, `mqtt_t021_v5_publish_no_props`, `mqtt_t028_property_binary`, `mqtt_t041_connack_session_present`, `mqtt_t053_keep_alive_zero`, `mqtt_t151_v5_nolocal`, `mqtt_t168_rst_no_disconnect`, `mqtt_t005_publish_qos_fixed_header`, `mqtt_t006_publish_dup_retain`, `mqtt_t007_pubrel_flags_force_02`, `mqtt_t018_ping_disconnect_v311`, `mqtt_t022_v5_suback_propslen_zero`, `mqtt_t029_property_stringpair`, `mqtt_t015_will_qos3_reject`, `mqtt_t037_publish_qos3_reject`, `mqtt_t067_v5_session_present_clean_reject`, `mqtt_t068_v4_no_username_password_reject`, `mqtt_t069_clean_session_and_session_present_reject`, `mqtt_t070_session_present_with_error_reject`, `mqtt_t079_invalid_retain_handling_reject`, `mqtt_t171_property_id_out_of_range`, `mqtt_t172_property_uint16_overflow`, `mqtt_t190_empty_topic_no_alias_reject`, `mqtt_t132_connack_v5_code128`, `mqtt_t133_disconnect_v5_code148`, `mqtt_t134_suback_v5_code97`, `mqtt_t135_v5_connack_code3_reject`, `mqtt_t136_connect_prop_max_packet_size`, `mqtt_t137_connect_prop_forbidden_id`, `mqtt_t138_publish_prop_payload_format`, `mqtt_t139_publish_prop_forbidden_id`, `mqtt_t140_will_prop_delay_interval`, `mqtt_t141b_subscribe_subid_200`, `mqtt_t141c_down_publish_two_subids`, `mqtt_t141d_subscribe_two_subids_reject`, `mqtt_t191_packetid_65535_qos2`, `mqtt_t192_subscribe_multi_filter`, `mqtt_t200a_shared_sub_311_reject`, `mqtt_t001_connect_v311_bytes`, `mqtt_t002_connect_v5_properties_bytes`, `mqtt_t003a_connack_rc_1`, `mqtt_t003b_connack_rc_3`, `mqtt_t004a_connack_v5_rc_130`, `mqtt_t004b_connack_v5_rc_135`, `mqtt_t004c_connack_v5_rc_144`, `mqtt_t023_will_delay_interval_v5`, `mqtt_t024_v5_will_no_props_len_zero`, `mqtt_t026_up_publish_subid_reject`, `mqtt_t031_default_packet_order`, `mqtt_t035_ping_after_publish`, `mqtt_t038_qos2_down_matrix`, `mqtt_t039_qos1_down_matrix`, `mqtt_t043_mss_segmentation`, `mqtt_t044_mss_536_min`, `mqtt_t045_mss_535_reject`, `mqtt_t046_mss_100_reject`, `mqtt_t047_syn_options`, `mqtt_t048_tcp_teardown_flags`, `mqtt_t050_disconnect_false_fin`, `mqtt_t052_initial_seq_1000`, `mqtt_t077_rl_127_vbi_7f`, `mqtt_t078_rl_128_vbi_8001`, `mqtt_t079_rl_16383_vbi_ff7f`, `mqtt_t080_rl_16384_vbi_808001`, `mqtt_t070_sub_filter_plus`, `mqtt_t071_sub_filter_hash_mid`, `mqtt_t073_alias_first_use_empty_topic`, `mqtt_t074_alias_reuse_established`, `mqtt_t074b_alias_without_max_declared`, `mqtt_t082_zero_payload_publish`, `mqtt_t084_auto_packet_id`, `mqtt_t086_will_no_topic`, `mqtt_t087_v4_password_no_username`, `mqtt_t088_v5_password_no_username`, `mqtt_t089_version_3`, `mqtt_t090_version_6`, `mqtt_t091_suback_code_len_mismatch`, `mqtt_t092_sub_filters_empty`, `mqtt_t093_prop_binary_bad_hex`, `mqtt_t094_prop_uint32_nonnum`, `mqtt_t095_v4_properties`, `mqtt_t099_connack_code_6_v4`, `mqtt_t100_connack_137_v5`, `mqtt_t102_connack_148_v5`, `mqtt_t103_connack_141_v5`, `mqtt_t104_connack_200_v5`, `mqtt_t105_clean_session_present`, `mqtt_t106_ackcode_nonzero_present`, `mqtt_t107_publish_topic_wildcard`, `mqtt_t108_publish_prop_0x11`, `mqtt_t109_dup_content_type`, `mqtt_t110_v4_will_delay`, `mqtt_t111_share_sub_legal`, `mqtt_t112_share_no_filter`, `mqtt_t113_empty_clientid_clean_false`, `mqtt_t115_v5_connect_props_len_zero`, `mqtt_t118_utf8_topic_bytes`, `mqtt_t119_packet_id_65535`, `mqtt_t120_will_empty_clientid`, `mqtt_t152_nolocal_v4`, `mqtt_t153_retain_as_published_v5`, `mqtt_t154_retain_handling_2`, `mqtt_t155_retain_handling_3`, `mqtt_t160_qos0_packet_id`, `mqtt_t161_qos_3`, `mqtt_t162_subscribe_packet_id_auto`, `mqtt_t163_disconnect_last_mqtt`, `mqtt_t164_connack_v4_sp_bits`, `mqtt_t165_connack_v5_sp_bits`, `mqtt_t166_sub_no_filters`, `mqtt_t167_topic_65536`, `mqtt_t169_rst_will`, `mqtt_t170_fin_will`, `mqtt_t171_prop_id_100`, `mqtt_t172_prop_uint16_overflow`, `mqtt_t173_prop_uint32_overflow`, `mqtt_t174_prop_byte_overflow`, `mqtt_t175_prop_binary_overlen`, `mqtt_t190_empty_topic_no_alias`, `mqtt_t191_packet_id_65535_qos2`, `mqtt_t192_multi_filter_subscribe`, `mqtt_t198_connack_max_qos`, `mqtt_t199_connack_retain_available`, `mqtt_t200_connack_shared_sub_avail`, `mqtt_t059_retain_multi_session__s0`, `mqtt_t059_retain_multi_session__s1`, `mqtt_t064_srcport_explicit_sessions__s0`, `mqtt_t064_srcport_explicit_sessions__s1`, `mqtt_t064_srcport_explicit_sessions__s2`, `mqtt_t065_session_override_inherit__s0`, `mqtt_t065_session_override_inherit__s1`, `mqtt_t066_messages_inherit_replace__s0`, `mqtt_t066_messages_inherit_replace__s1`, `mqtt_t066_messages_inherit_replace__s2`, `mqtt_t146_flowid_suffix__s0`, `mqtt_t146_flowid_suffix__s1`, `mqtt_t146_flowid_suffix__s2`, `mqtt_t147_tcp_seq_independent__s0`, `mqtt_t147_tcp_seq_independent__s1`, `mqtt_t148_packet_index_independent__s0`, `mqtt_t148_packet_index_independent__s1`, `mqtt_t148_packet_index_independent__s2`, `mqtt_t149_group_id_shared`, `mqtt_t150_session_srcport_priority__s0`, `mqtt_t150_session_srcport_priority__s1`, `mqtt_t176_clean_session_inherit__s0`, `mqtt_t176_clean_session_inherit__s1`, `mqtt_t177_keep_alive_inherit__s0`, `mqtt_t177_keep_alive_inherit__s1`, `mqtt_t177b_keep_alive_zero_override__s0`, `mqtt_t177b_keep_alive_zero_override__s1`, `mqtt_t178_disconnect_inherit__s0`, `mqtt_t178_disconnect_inherit__s1`, `mqtt_t179_will_replace__s0`, `mqtt_t179_will_replace__s1`, `mqtt_t180_will_nil_inherit__s0`, `mqtt_t180_will_nil_inherit__s1`, `mqtt_t193_pubrel_flags_fixed`, `mqtt_t197_qos3_reject`, `mqtt_t141a_up_publish_subid_reject`, `mqtt_t085_will_qos3_reject`, `mqtt_t096_dstport_default_1883`, `mqtt_t131_zero_payloads`, `mqtt_t100_connack_130_v5`, `mqtt_t100_connack_135_v5`, `mqtt_t100_connack_144_v5`, `mqtt_t159_no_second_connect`, `mqtt_t121_strategy_convert`, `mqtt_t125_validation_error_propagation`, `mqtt_t126_multi_session_4tuple__s0`, `mqtt_t126_multi_session_4tuple__s1`, `mqtt_t126_multi_session_4tuple__s2`, `mqtt_t127_workers8_no_reorder` |
| 动态策略 | 3（3/0） | `mqtt_dyn_client_id_list`, `mqtt_dyn_topic_pattern`, `mqtt_dyn_payload_list` |
| IPv6承载 | 1（1/0） | `mqtt_v6_connect` |
| 命名负例 | 8（0/8） | `mqtt_neg_dup_qos0`, `mqtt_neg_bad_direction`, `mqtt_neg_unknown_prop_format`, `mqtt_neg_prop_stringpair_nonul`, `mqtt_neg_prop_vbi_overflow`, `mqtt_neg_sessions_rejected`, `mqtt_neg_prop_string_nul`, `mqtt_neg_clientid_nul` |
| 业务组合 | 3（3/0） | `mqtt_biz_telemetry_subpub`, `mqtt_biz_abnormal_will_alarm`, `mqtt_biz_v5_session_full` |

说明：T 系列共 176 条（118 正、58 负），按设计文档 §7 的 RFC 字段、状态机、计划输出、业务、异常边界、属性/会话/并发等面聚合；不把它们伪拆成未在 JSON 中存在的新 ID。

## 3. 正例最低断言契约

正例的公共要求是 TCP 握手/协商/终止元数据（存在时由 `has_handshake`、`negotiated`、`terminates` 表达），并按例选择 `frames`、`fields` 或动态集合。帧断言共 **215** 条，字段断言共 **52** 条；所有 hex、offset、字段值均以 cases JSON 原文为准，不从设计示例外推。

| 断言面 | 覆盖内容 |
|---|---|
| 固定头/控制包 | CONNECT/CONNACK、PUBLISH QoS 0/1/2、PUBACK/PUBREC/PUBREL/PUBCOMP、SUBSCRIBE/SUBACK、PING、DISCONNECT |
| MQTT 版本 | 3.1.1 level 4 与 5.0 level 5；v5 Properties Length、Reason Code、Topic Alias、NoLocal、Will Delay 等 |
| TCP 载体 | SYN/SYN-ACK/ACK、seq/初始序列、MSS 分段、FIN/RST 变体、默认/显式端口 |
| TLS 载体 | `[ip,tcp,tls,mqtt]` 单例 `mqtt_over_tls`，检查 8883 与 TLS record 字段 |
| 业务/会话 | 订阅、多消息、认证、保活、遗嘱、多 session、字段继承/替换、FlowID/PacketIndex/seq 独立性 |
| 动态/地址族 | client_id/topic/payload 策略；IPv6 CONNECT；动态例用 `distinct_values`/`min_packets` |

包数分布（正例，按 `packet_count`）：9×13、10×31、11×53、12×16、13×10、14×6、17×3、18×2、22×2（合计 136）；其中 `mqtt_t005_publish_qos_fixed_header`（计入 17×3）额外带 `min_packets=11`，动态三例为 min-only（`min_packets` = 20/22/22，无 `packet_count`），TLS 例两者皆无。

## 4. 负例契约与锚词

负例必须在 planner/validator 阶段失败并传播为 task error；`expect` 不含 `packet_count`、`min_packets`、`fields`、`frames`。以下是 66 条 JSON 原文 `error_contains` 的分类计数（不把同锚词误合并为一个例）：

| `error_contains` | 条数 |
|---|---:|
| `connect_ack_code` | 6 |
| `qos` | 3 |
| `retain_handling` | 2 |
| `uint16` | 2 |
| `topic` | 2 |
| `out of range` | 2 |
| `wildcard` | 2 |
| `alias` | 2 |
| `version` | 2 |
| `filters` | 2 |
| `uint32` | 2 |
| `5.0` | 2 |
| `session_present` | 2 |
| `65535` | 2 |
| `invalid will qos` | 1 |
| `username required when password is set` | 1 |
| `mutually exclusive` | 1 |
| `session_present=true is invalid` | 1 |
| `not allowed` | 1 |
| `not allowed in packet type 0x10` | 1 |
| `not allowed in packet type 0x30` | 1 |
| `subscription identifier cannot repeat` | 1 |
| `shared subscriptions are 5.0 only` | 1 |
| `subscription` | 1 |
| `will` | 1 |
| `username` | 1 |
| `ack_reason_codes` | 1 |
| `binary` | 1 |
| `0x11` | 1 |
| `duplicate` | 1 |
| `delay_interval` | 1 |
| `share` | 1 |
| `packet_id` | 1 |
| `0x64` | 1 |
| `byte` | 1 |
| `no longer accepts a top-level mqtt sub-config` | 1 |
| `invalid message qos` | 1 |
| `subscription identifier` | 1 |
| `will qos` | 1 |
| `DUP flag is invalid for QoS 0` | 1 |
| `invalid message direction` | 1 |
| `unknown property format` | 1 |
| `stringpair must contain NUL separator` | 1 |
| `exceeds 268435455` | 1 |
| `one flow per chain` | 1 |
| `string contains U+0000` | 1 |
| `forbidden UTF-8 code point` | 1 |

合计核验：6 + 3 + 12×2 + 33 = **66**；共 **47** 种锚词。关键故障面：版本/CONNACK code 域、Session Present 互斥、QoS/Will QoS、DUP 与方向、Topic/alias、订阅过滤器与共享订阅、属性白名单/重复/格式/溢出、UTF-8/NUL、VBI 上限、MSS、Password/Username、链形 presence 与单 flow 约束。

## 5. 承载与状态机核对

- 204 条正/负标准链均是 `[ip,tcp,mqtt]`；`mqtt_over_tls` 是唯一 `[ip,tcp,tls,mqtt]` 例。TLS 例的 `tls.record.content_type=22`/`length nonzero` 断言按 JSON 现状记录。
- MQTT 正常会话通常为 TCP 三次握手 → CONNECT/CONNACK → 可选 SUBSCRIBE、PUBLISH、PING → DISCONNECT → TCP 终止；拒绝例只允许 CONNECT/CONNACK 后终止。
- QoS0 无确认，QoS1 为 PUBLISH+PUBACK，QoS2 为 PUBLISH+PUBREC+PUBREL+PUBCOMP；下行例的 ACK 方向按设计矩阵翻转。
- `mqtt_t149_group_id_shared` 的空 `layers` 与顶层 `mqtt/group_id` 是**故意判死负例**（`no longer accepts a top-level mqtt sub-config`）；不能登记为正例残留，也不能声称 group_id 跨流已在本契约落地。

## 6. 配置面与编码覆盖

覆盖设计 §2–§5 的固定头/VBI、CONNECT flags、Will、Properties、Topic Alias、订阅选项、Reason Code、认证、IPv4/IPv6、端口与 TCP 选项。VBI 边界正例包括 127/128/16383/16384；最大值/溢出在负例中核对。

动态策略仅 3 例：`mqtt_dyn_client_id_list`、`mqtt_dyn_topic_pattern`、`mqtt_dyn_payload_list`；三例均通过 `strategy_fc` flows 产生 `min_packets` 与 `distinct_values` 断言。

## 7. 规范/设计回指

设计文档 §1 范围与不实现项、§2 编码、§3 报文构造、§4 状态机、§5 配置类型、§6 S1–S15 场景、§7 T-001–T-215 测试清单，是本 JSON 的语义来源；本契约只登记 JSON 已存在的 206 个 ID。WebSocket、MQTT-SN、AUTH 生成、UNSUBSCRIBE/UNSUBACK 等设计中明确不实现的面，不得从本清单推断为已覆盖。

## 8. 存量审计与缺口

- **已覆盖（文件形状）**：206/206 有唯一 ID；140/140 正例；66/66 负例；正例 215 帧断言、52 字段断言；负例断言形状统一且无包数。
- **故意判死形状**：`mqtt_t149_group_id_shared` 是唯一 `{mqtt,group_id}` 顶层形状，故意验证层链迁移后的 presence 门；不是“正例残留”。
- **仍待 P5/实现阶段核验**：本轮仅完成 cases JSON 机读审计与契约文档；未取得今日完整 suite、pcap、NIC 或 tshark 复跑证据，因此不得宣称通过。
- **可疑/需复核项**：TLS 例的 `content_type=22` 与 summary 对 application_data 的描述存在语义张力；应在 P5 以实际抓包复核，本文不擅自改写。
- **不适用/未实现**：设计 §1.4 明确列出的 WebSocket、MQTT-SN、TLS 内部握手细节、AUTH、UNSUBSCRIBE/UNSUBACK 不计为本 JSON 覆盖缺口，除非后续范围变更。

## 9. P3 固定动作（§3.15 与 A′/B′）

| 项 | MQTT 对照 | 状态 |
|---|---|---|
| 同连接多轮操作 | CONNECT 后订阅/发布/保活/QoS ACK 多轮均有例 | 已覆盖（以 JSON 为准） |
| 非正常结束 | disconnect=false、RST/FIN、遗嘱编排有例 | 已覆盖/模型偏差见设计 §4.4 |
| 长保活 | PINGREQ/PINGRESP 与 keep_alive 变体有例；不模拟真实 timer | 已覆盖简化模型 |
| A′ | 版本/属性/alias/VBI/MSS/UTF-8/端口/动态/IPv6 等均有正负例 | 多数已入 JSON，逐项复核待 P5 |
| B′ | 顶层 mqtt/group_id 链形 presence 判死例已存在；无证据称框架面全绿 | 待 P5 |

## 10. 执行与断言纪律

1. 以 `mqtt.json` 原始顺序执行；不得按设计 T 编号重排或丢弃重复语义 ID。
2. 正例先验证包数/握手/终止，再验证 frames hex/offset 与 fields；动态值按 `distinct_values`，不硬编码顺序。
3. 负例只验证 `expect_error` 与 `error_contains` 子串命中，并确认无成功 PCAP/无“completed/0 packet”假绿。
4. 任何 P5 结果须注明 suite、pcap/NIC 路径、tshark 版本与实际命中数；当前文档不代替执行证据。

## 11. 修订记录

- v1.0.0（2026-09-29）：按 `mqtt.json` 206 条记录建立 as-built 契约；完成 140/66 分类、ID 顺序、层形与 `{mqtt,group_id}` 分布、expect/packet_count/min_packets/fields/frames 机读统计；聚合 S/T/dynamic/business/TLS/IPv6 场景族；登记 `mqtt_t149_group_id_shared` 为故意判死负例；未宣称 suite/pcap/NIC 通过。自审 2 轮，末轮干净。

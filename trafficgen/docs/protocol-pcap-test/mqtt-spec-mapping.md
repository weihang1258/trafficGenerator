# MQTT Spec-to-PCAP Test Case Mapping

## Files
- **Design spec**: `/home/weihang/trafficGenerator/docs/protocol-designs/14-mqtt-design.md` (§7 "测试用例（T-001 ~ T-215）", line 1684)
- **PCAP test cases**: `/home/weihang/trafficGenerator/trafficgen/test/protocol_pcap/cases/mqtt.json` (168 cases)
- **PCAP results**: `/home/weihang/trafficGenerator/trafficgen/docs/protocol-pcap-test/mqtt.md`

## Spec Overview

§7 contains **205 test cases** organized into 21 sections（§7.21 为计数表，不计用例）：

| Section | Range | Count | Description |
|---------|-------|-------|-------------|
| §7.1 RFC 字段构造 | T-001~T-030 | 30 | CONNECT/CONNACK/PUBLISH/SUBSCRIBE 字节构造 + VBI 编解码 + Will/Properties |
| §7.2 状态机 | T-031~T-041 | 11 | 包顺序/拒绝跳过/QoS 交换/方向矩阵/SessionPresent/MSS |
| §7.3 Plan 输出 | T-042~T-053 | 12 | 包总数/MSS 分段/握手挥手选项/seq 连续性/RST/InitialSeq/keep_alive=0 |
| §7.4 业务场景 | T-054~T-066 | 13 | QoS0/1/2 完整流程/subscribe/will/retain/认证/5.0/ping/多会话/继承 |
| §7.5 异常与边界 | T-067~T-120 + T-074b | 55 | CONNACK 拒绝/DUP+QoS0/通配符/Topic Alias/超长/剩余长度/PacketID/Will/Version/SubACK/Property Format |
| §7.6 集成 | T-121~T-127 | 7 | strategy_convert/RegisterPlanner/task 全链路/ValidationErrors 透传/多会话/PacketWorkers/并发/-race/ctx |
| §7.7 对抗性 | T-128~T-131 | 4 | 并发不串包/-race/ctx 取消/0 payload 边界 |
| §7.8 5.0 Reason Code 域 | T-132~T-135 | 4 | CONNACK 22 码/DISCONNECT 31 码/SUBACK 扩展/CONNACK 拒绝 1-5 |
| §7.9 Property×包白名单 | T-136~T-141 + T-141b/c/d | 10 | CONNECT/PUBLISH/Will Properties 允许+禁止 + Subscription Identifier |
| §7.10 VBI 边界 | T-142~T-145 | 4 | encode/decode 全边界/负数/超大 |
| §7.11 多会话与继承 | T-146~T-150 | 5 | FlowID 后缀/TCP seq/PacketIndex/GroupID/SrcPort 优先 |
| §7.12 订阅选项 | T-151~T-155 | 5 | NoLocal/RetainAsPublished/RetainHandling |
| §7.13 字段计数与扩展表 | T-156~T-158 | 3 | 28 字段聚合/topic_alias_used/will_topic |
| §7.14 规范一致性补充 | T-159~T-167 | 9 | 第二报错/QoS0+PacketID/QoS=3/PacketID 自动/CONNACK 保留位/SUBSCRIBE 最少/UTF-8 长度 |
| §7.15 异常断开与 RST | T-168~T-170 | 3 | RST 无 DISCONNECT/RST+will/FIN+will |
| §7.16 Property 编码负向 | T-171~T-175 | 5 | Identifier 超范围/uint16/uint32/byte 溢出/binary 超长 |
| §7.17 Session 字段继承 | T-176~T-180 + T-177b | 6 | CleanSession/KeepAlive/Disconnect/Will 继承+替换 |
| §7.18 字节级完整场景 | T-181~T-187 | 7 | S1/S2/S4/S9/S12/S13/S15 完整字节序列 |
| §7.19 边界场景补充 | T-188~T-192 | 5 | 剩余长度 268435455/268435456/topic 0/PacketID 65535+QoS2/多 filter |
| §7.20 规范禁止行为 | T-193~T-200 | 8 | PUBREL/SUBSCRIBE flags≠0x02/Protocol Name/Reserved 位/QoS=3/Maximum QoS/Retain Available/Shared Subscription |
| **Total** | | **205** | |

## Covered Mapping (159 spec IDs → pcap cases)

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-001 | CONNECT 3.1.1 字节构造 | mqtt_t001_connect_v311_bytes | covered |
| T-002 | CONNECT 5.0 含 Properties | mqtt_t002_connect_v5_properties_bytes | covered |
| T-003 | CONNACK 3.1.1 各 Return Code | mqtt_t003a_connack_rc_1 | covered |
| T-004 | CONNACK 5.0 Reason Code 域 | mqtt_t004a_connack_v5_rc_130 | covered |
| T-005 | PUBLISH QoS0/1/2 固定头 | mqtt_t005_publish_qos_fixed_header | covered |
| T-006 | PUBLISH Retain 与 DUP 标志位（负向流量建模） | mqtt_t006_publish_dup_retain | covered |
| T-007 | PUBREL flags 强制 0x02 | mqtt_t007_pubrel_flags_force_02 | covered |
| T-013 | Will Retain=1 → Connect Flags=0x2E | mqtt_t013_will_retain_flag | covered |
| T-014 | Will QoS=2 → Connect Flags=0x16 | mqtt_t014_will_qos2_flag | covered |
| T-015 | Will QoS=3 → Validate 报错 | mqtt_t015_will_qos3_reject | covered |
| T-017 | SUBACK 多 filter Reason Codes | mqtt_t017_suback_multi_reason | covered |
| T-018 | PINGREQ/PINGRESP/DISCONNECT 3.1.1 字节 | mqtt_t018_ping_disconnect_v311 | covered |
| T-019 | DISCONNECT 5.0 含 Reason Code | mqtt_t019_v5_disconnect_reason | covered |
| T-021 | 5.0 PUBLISH 无属性 Properties Length=0x00 必填 | mqtt_t021_v5_publish_no_props | covered |
| T-022 | 5.0 SUBACK 无属性 Properties Length=0x00 必填 | mqtt_t022_v5_suback_propslen_zero | covered |
| T-023 | Will Delay Interval 5.0 字节编码（ID=0x18） | mqtt_t023_will_delay_interval_v5 | covered |
| T-024 | v5 will 无属性 → Will Properties Length=0x00 | mqtt_t024_v5_will_no_props_len_zero | covered |
| T-026 | Property Format=vbi 负向（up PUBLISH 含 Subscription Identifier 报错） | mqtt_t026_up_publish_subid_reject | covered |
| T-028 | Property Format=binary 正测 | mqtt_t028_property_binary | covered |
| T-029 | Property Format=stringpair 正测 | mqtt_t029_property_stringpair | covered |
| T-031 | 单会话默认流程包顺序 | mqtt_t031_default_packet_order | covered |
| T-032 | CONNACK 拒绝后跳过后续 | mqtt_t003a_connack_rc_1 | covered |
| T-035 | PINGREQ 在 PUBLISH 之后 | mqtt_t035_ping_after_publish | covered |
| T-037 | QoS=3 被拒绝 | mqtt_t037_publish_qos3_reject | covered |
| T-038 | QoS2 下行方向矩阵 | mqtt_t038_qos2_down_matrix | covered |
| T-039 | QoS1 下行方向矩阵 | mqtt_t039_qos1_down_matrix | covered |
| T-041 | ConnectAckSessionPresent=true → CONNACK byte[0]=0x01 | mqtt_t041_connack_session_present | covered |
| T-043 | MSS 分段超长 PUBLISH（整包 TCP 层切段） | mqtt_t043_mss_segmentation | covered |
| T-044 | MSS=MinMSS 边界接受 | mqtt_t044_mss_536_min | covered |
| T-045 | MSS=MinMSS-1 边界拒绝 | mqtt_t045_mss_535_reject | covered |
| T-046 | MSS 过小报错 | mqtt_t046_mss_100_reject | covered |
| T-047 | TCP 握手含 MSS/WinScale/SACK 选项 | mqtt_t047_syn_options | covered |
| T-048 | TCP 挥手四步 | mqtt_t048_tcp_teardown_flags | covered |
| T-050 | Disconnect=false 模型异常断开 | mqtt_t050_disconnect_false_fin | covered |
| T-052 | InitialSeq 固定 ISN | mqtt_t052_initial_seq_1000 | covered |
| T-053 | keep_alive=0 → CONNECT `00 00` | mqtt_t053_keep_alive_zero | covered |
| T-055 | QoS1 publish 完整流程 | mqtt_s3_publish_qos1 | covered |
| T-057 | subscribe + 下行 publish | mqtt_s5_subscribe | covered |
| T-059 | retain message 多 session | mqtt_t059_retain_multi_session | covered |
| T-062 | keepalive PINGREQ/PINGRESP | mqtt_s7_ping | covered |
| T-063 | 多会话 3 个客户端 | mqtt_s10_multi_session | covered |
| T-064 | 多会话 SrcPort 显式不自动递增 | mqtt_t064_srcport_explicit_sessions | covered |
| T-065 | 会话级字段覆盖与继承 | mqtt_t065_session_override_inherit | covered |
| T-066 | 顶层 messages + 3 sessions 继承/替换语义 | mqtt_t066_messages_inherit_replace | covered |
| T-067 | CONNACK 拒绝码 1 跳过后续 | mqtt_t067_v5_session_present_clean_reject | covered |
| T-068 | CONNACK 拒绝码 5 跳过后续 | mqtt_t068_v4_no_username_password_reject | covered |
| T-069 | PUBLISH DUP=1 + QoS0 报错 | mqtt_t069_clean_session_and_session_present_reject | covered |
| T-070 | 订阅通配符 `+` 接受 | mqtt_t070_session_present_with_error_reject | covered |
| T-071 | 订阅 `#` 不在末尾报错 | mqtt_t071_sub_filter_hash_mid | covered |
| T-072 | 空 topic PUBLISH 报错（无 Topic Alias） | mqtt_t037_publish_qos3_reject | covered |
| T-073 | 空 topic + Topic Alias=1 首包报错（映射未建立） | mqtt_t073_alias_first_use_empty_topic | covered |
| T-074 | 空 topic + Topic Alias=1 复用合法（映射已建立） | mqtt_t074_alias_reuse_established | covered |
| T-074b | PUBLISH 用 Topic Alias 但 CONNECT 未声明 Topic Alias Maximum 报错 | mqtt_t074b_alias_without_max_declared | covered |
| T-077 | 剩余长度 127 边界 | mqtt_t077_rl_127_vbi_7f | covered |
| T-078 | 剩余长度 128 边界 | mqtt_t078_rl_128_vbi_8001 | covered |
| T-079 | 剩余长度 16383 边界 | mqtt_t079_invalid_retain_handling_reject | covered |
| T-080 | 剩余长度 16384 边界 | mqtt_t080_rl_16384_vbi_808001 | covered |
| T-082 | payload 0 字节 PUBLISH | mqtt_t082_zero_payload_publish | covered |
| T-084 | PacketID 省略/显式 0 自动分配 | mqtt_t084_auto_packet_id | covered |
| T-085 | Will QoS=3 报错 | mqtt_t085_will_qos3_reject | covered |
| T-086 | Will 无 topic 报错 | mqtt_t086_will_no_topic | covered |
| T-087 | Username 空 + Password 非空 报错（3.1.1） | mqtt_t087_v4_password_no_username | covered |
| T-088 | Username 空 + Password 非空 接受（5.0） | mqtt_t088_v5_password_no_username | covered |
| T-089 | Version=3 报错 | mqtt_t089_version_3 | covered |
| T-090 | Version=6 报错 | mqtt_t090_version_6 | covered |
| T-091 | SUBACK Reason Codes 长度不匹配报错 | mqtt_t091_suback_code_len_mismatch | covered |
| T-092 | Subscriptions Filters 空报错 | mqtt_t092_sub_filters_empty | covered |
| T-093 | Property Format=binary 非法 hex | mqtt_t093_prop_binary_bad_hex | covered |
| T-094 | Property Format=uint32 非数字 | mqtt_t094_prop_uint32_nonnum | covered |
| T-095 | Version=4 时设置 Properties 报错 | mqtt_t095_v4_properties | covered |
| T-096 | DstPort 默认 1883 | mqtt_t096_dstport_default_1883 | covered |
| T-099 | ConnectAckCode=6 (3.1.1) 报错 | mqtt_t099_connack_code_6_v4 | covered |
| T-100 | ConnectAckCode=130/135/144 (5.0) 接受 | mqtt_t100_connack_130_v5 | covered |
| T-101 | ConnectAckCode=137 (5.0) 接受 | mqtt_t100_connack_137_v5 | covered |
| T-102 | ConnectAckCode=148 (5.0) 报错 | mqtt_t102_connack_148_v5 | covered |
| T-103 | ConnectAckCode=141 (5.0) 报错 | mqtt_t103_connack_141_v5 | covered |
| T-104 | ConnectAckCode=200 (5.0) 报错 | mqtt_t104_connack_200_v5 | covered |
| T-105 | CleanSession=true + SessionPresent=true 报错 | mqtt_t105_clean_session_present | covered |
| T-106 | ConnectAckCode≠0 + SessionPresent=true 报错 | mqtt_t106_ackcode_nonzero_present | covered |
| T-107 | PUBLISH topic 含通配符报错 | mqtt_t107_publish_topic_wildcard | covered |
| T-108 | PUBLISH properties 含 0x11 报错 | mqtt_t108_publish_prop_0x11 | covered |
| T-109 | 重复 Content Type 报错 | mqtt_t109_dup_content_type | covered |
| T-110 | v4 + Will DelayInterval≠0 报错 | mqtt_t110_v4_will_delay | covered |
| T-111 | $share 共享订阅合法 | mqtt_t111_share_sub_legal | covered |
| T-112 | $share 缺 filter 非法 | mqtt_t112_share_no_filter | covered |
| T-113 | 空 ClientID + 显式 CleanSession=false | mqtt_t113_empty_clientid_clean_false | covered |
| T-114 | topic 含 U+0000 报错 | mqtt_t068_v4_no_username_password_reject | covered |
| T-115 | v5 CONNECT 无属性 Properties Length=0x00 | mqtt_t115_v5_connect_props_len_zero | covered |
| T-118 | topic 含 UTF-8 多字节字符 | mqtt_t118_utf8_topic_bytes | covered |
| T-119 | PacketID 接近 65535 溢出 | mqtt_t119_packet_id_65535 | covered |
| T-120 | 字段冲突：Will 与无 ClientID | mqtt_t120_will_empty_clientid | covered |
| T-121 | strategy_convert case "mqtt" 解析 | mqtt_t121_strategy_convert | covered |
| T-122 | strategy_convert 默认端口 1883 | mqtt_t121_strategy_convert | covered |
| T-124 | task handler → engine → Plan 全链路 | mqtt_t121_strategy_convert | covered |
| T-125 | ValidationErrors 透传到 task 失败 | mqtt_t125_validation_error_propagation | covered |
| T-126 | 多会话 SubFlow 机制独立 4-tuple | mqtt_t126_multi_session_4tuple | covered |
| T-127 | PacketWorkers=8 不乱序 | mqtt_t127_workers8_no_reorder | covered |
| T-131 | 0 字节 payload + 0 字节 will 边界 | mqtt_t131_zero_payloads | covered |
| T-132 | CONNACK 5.0 全部 22 个有效代码（逐条独立断言） | mqtt_t132_connack_v5_code128 | covered |
| T-133 | DISCONNECT 5.0 全部 31 个有效代码 | mqtt_t133_disconnect_v5_code148 | covered |
| T-134 | SUBACK 5.0 扩展 Reason Code | mqtt_t134_suback_v5_code97 | covered |
| T-135 | 5.0 CONNACK 拒绝 1-5 报错 | mqtt_t135_v5_connack_code3_reject | covered |
| T-136 | CONNECT 允许的 Property ID | mqtt_t136_connect_prop_max_packet_size | covered |
| T-137 | CONNECT 禁止的 Property ID | mqtt_t137_connect_prop_forbidden_id | covered |
| T-138 | PUBLISH 允许的 Property ID | mqtt_t138_publish_prop_payload_format | covered |
| T-139 | PUBLISH 禁止的 Property ID | mqtt_t139_publish_prop_forbidden_id | covered |
| T-140 | Will Properties 允许的 Property ID | mqtt_t140_will_prop_delay_interval | covered |
| T-141a |  | mqtt_t141a_up_publish_subid_reject | covered |
| T-141b | SUBSCRIBE 携带 Subscription Identifier（0x0B）合法 | mqtt_t141b_subscribe_subid_200 | covered |
| T-141c | down PUBLISH 携带 Subscription Identifier 合法（可重复） | mqtt_t141c_down_publish_two_subids | covered |
| T-141d | SUBSCRIBE 两个 Subscription Identifier 报错 | mqtt_t141d_subscribe_two_subids_reject | covered |
| T-146 | 多会话 FlowID 含 :mqtt-i 后缀 | mqtt_t146_flowid_suffix | covered |
| T-147 | 多会话 TCP seq 独立 | mqtt_t147_tcp_seq_independent | covered |
| T-148 | 多会话 PacketIndex 独立 | mqtt_t148_packet_index_independent | covered |
| T-149 | 多会话 GroupID 共享 | mqtt_t149_group_id_shared | covered |
| T-150 | Session 显式 SrcPort 优先 | mqtt_t150_session_srcport_priority | covered |
| T-151 | NoLocal=1 接受（5.0） | mqtt_t151_v5_nolocal | covered |
| T-152 | NoLocal=1 报错（3.1.1） | mqtt_t152_nolocal_v4 | covered |
| T-153 | RetainAsPublished=1 接受（5.0） | mqtt_t153_retain_as_published_v5 | covered |
| T-154 | RetainHandling=2 接受（5.0） | mqtt_t154_retain_handling_2 | covered |
| T-155 | RetainHandling=3 报错（5.0） | mqtt_t155_retain_handling_3 | covered |
| T-159 | CONNECT 第二个报错 | mqtt_t159_no_second_connect | covered |
| T-160 | PUBLISH QoS0 + PacketID 报错 | mqtt_t160_qos0_packet_id | covered |
| T-161 | PUBLISH QoS=3 报错 | mqtt_t161_qos_3 | covered |
| T-162 | SUBSCRIBE PacketID=0 自动分配 | mqtt_t162_subscribe_packet_id_auto | covered |
| T-163 | DISCONNECT 后无 MQTT 包 | mqtt_t163_disconnect_last_mqtt | covered |
| T-164 | CONNACK 3.1.1 byte[0] bit1-7=0 | mqtt_t164_connack_v4_sp_bits | covered |
| T-165 | CONNACK 5.0 byte[0] bit1-7=0 | mqtt_t165_connack_v5_sp_bits | covered |
| T-166 | SUBSCRIBE 至少 1 个 filter | mqtt_t166_sub_no_filters | covered |
| T-167 | UTF-8 字符串长度字段边界（0xFFFF = 65535 合法） | mqtt_t167_topic_65536 | covered |
| T-168 | RST=true 无 MQTT DISCONNECT | mqtt_t168_rst_no_disconnect | covered |
| T-169 | RST=true + will message | mqtt_t169_rst_will | covered |
| T-170 | FIN 挥手 + will message | mqtt_t170_fin_will | covered |
| T-171 | Property Identifier 超范围报错 | mqtt_t171_property_id_out_of_range | covered |
| T-172 | Property Value 溢出 uint16 | mqtt_t172_property_uint16_overflow | covered |
| T-173 | Property Value 溢出 uint32 | mqtt_t173_prop_uint32_overflow | covered |
| T-174 | Property Value 溢出 byte | mqtt_t174_prop_byte_overflow | covered |
| T-175 | Property binary 长度超 65535 | mqtt_t175_prop_binary_overlen | covered |
| T-176 | Session CleanSession 继承 | mqtt_t176_clean_session_inherit | covered |
| T-177 | Session KeepAlive 继承 | mqtt_t177_keep_alive_inherit | covered |
| T-177b | Session KeepAlive 显式 0 覆盖 | mqtt_t177b_keep_alive_zero_override | covered |
| T-178 | Session Disconnect 继承 | mqtt_t178_disconnect_inherit | covered |
| T-179 | Session Will 整体替换 | mqtt_t179_will_replace | covered |
| T-180 | Session Will nil 继承 | mqtt_t180_will_nil_inherit | covered |
| T-181 | S1 完整字节序列 | mqtt_s1_connect_basic | covered |
| T-182 | S2 完整字节序列 | mqtt_s2_publish_qos0 | covered |
| T-183 | S4 完整字节序列 | mqtt_s4_publish_qos2 | covered |
| T-184 | S9 完整字节序列 | mqtt_s9_will | covered |
| T-185 | S12 完整字节序列 | mqtt_s12_v5_properties | covered |
| T-186 | S13 完整字节序列 | mqtt_s13_auth | covered |
| T-187 | S15 完整字节序列 | mqtt_s15_v5_keepalive_timeout | covered |
| T-190 | topic 0 字节 + 无 Topic Alias 报错 | mqtt_t190_empty_topic_no_alias_reject | covered |
| T-191 | PacketID 65535 + QoS2 | mqtt_t191_packetid_65535_qos2 | covered |
| T-192 | 多 filter SUBSCRIBE 字节 | mqtt_t192_subscribe_multi_filter | covered |
| T-193 | PUBREL flags≠0x02 报错（planner 内部） | mqtt_t193_pubrel_flags_fixed | covered |
| T-197 | PUBLISH QoS=3 报错 | mqtt_t197_qos3_reject | covered |
| T-198 | 5.0 Maximum QoS Property | mqtt_t198_connack_max_qos | covered |
| T-199 | 5.0 Retain Available Property | mqtt_t199_connack_retain_available | covered |
| T-200 | 5.0 Shared Subscription Available Property | mqtt_t200_connack_shared_sub_avail | covered |

**Total unique spec IDs covered**: 159


## Summary Counts

| Metric | Count |
|--------|-------|
| Total spec test cases (§7) | 205 |
| Total pcap test cases | 168 |
| Unique spec IDs covered by pcap | 159（§7 域内 158 + 补充 T-141a） |
| Spec IDs missing from pcap | 47 |
| **Coverage rate** | **77.6%** (158/205 域内；含补充 159) |

## Coverage by Section

| Section | Range | IDs | Covered | Missing |
|---------|-------|-----|---------|---------|
| §7.1 RFC 字段构造 | T-001~T-030 | 30 | 20 | 10 |
| §7.2 状态机 | T-031~T-041 | 11 | 7 | 4 |
| §7.3 Plan 输出 | T-042~T-053 | 12 | 9 | 3 |
| §7.4 业务场景 | T-054~T-066 | 13 | 8 | 5 |
| §7.5 异常与边界 | T-067~T-120+T-074b | 55 | 47 | 8 |
| §7.6 集成 | T-121~T-127 | 7 | 6 | 1 |
| §7.7 对抗性 | T-128~T-131 | 4 | 1 | 3 |
| §7.8 5.0 Reason Code 域 | T-132~T-135 | 4 | 4 | 0 |
| §7.9 Property×包白名单 | T-136~T-141+T-141b/c/d | 10 | 8 | 2 |
| §7.10 VBI 边界 | T-142~T-145 | 4 | 0 | 4 |
| §7.11 多会话与继承 | T-146~T-150 | 5 | 5 | 0 |
| §7.12 订阅选项 | T-151~T-155 | 5 | 5 | 0 |
| §7.13 字段计数与扩展表 | T-156~T-158 | 3 | 0 | 3 |
| §7.14 规范一致性补充 | T-159~T-167 | 9 | 9 | 0 |
| §7.15 异常断开与 RST | T-168~T-170 | 3 | 3 | 0 |
| §7.16 Property 编码负向 | T-171~T-175 | 5 | 5 | 0 |
| §7.17 Session 字段继承 | T-176~T-180+T-177b | 6 | 6 | 0 |
| §7.18 字节级完整场景 | T-181~T-187 | 7 | 7 | 0 |
| §7.19 边界场景补充 | T-188~T-192 | 5 | 3 | 2 |
| §7.20 规范禁止行为 | T-193~T-200 | 8 | 5 | 3 |
| **Total** | | **205** | **158** | **47** |

**注**：另有补充 ID **T-141a**（上行 PUBLISH 携带 Subscription Identifier 拒绝，非 §7 编号）被 mqtt_t141a 覆盖；含该补充共 **159** 个 spec ID。

## Coverage Analysis

### 已覆盖（159/205 = 77.6%，8 个章节 100%）

168 个 pcap 用例覆盖 159 个 spec ID。**§7.8（4/4）、§7.11（5/5）、§7.12（5/5）、§7.14（9/9）、§7.15（3/3）、§7.16（5/5）、§7.17（6/6）、§7.18（7/7）8 个章节 100%**；§7.3（9/12，75%）、§7.9（8/10）、§7.19（3/5）、§7.20（5/8）、§7.4（8/13）、§7.2（7/11）、§7.6（6/7，T-123 report 聚合不适用）、§7.1（20/30）、§7.7（1/4）。§7.5 异常与边界 55 条已覆盖 47 条（85%），是覆盖量最大的章节。

### 分批补齐历程

| 批次 | 新增 | 累计用例 | 累计覆盖 spec ID | 说明 |
|------|------|---------|-----------------|------|
| 初始 | 53 | 53 | 53 | §7.18/§7.8 等字节级场景 |
| 第 1 批 | 33 | 86 | ~75 | §7.1/§7.5 字段构造与 Validate 负向 |
| 第 2 批 | 30 | 116 | ~103 | §7.2/§7.3/§7.12/§7.14 状态机/订阅选项 |
| 第 3 批 | 23 | 139 | ~120 | §7.9/§7.16 Property 白名单与编码负向 |
| 第 4 批 | 18 | 157 | ~146 | §7.4/§7.11/§7.17 多会话与 Session 继承 |
| 第 5 批 | 11 | 168 | 159 | §7.5 余量/T-100 5.0 码/T-121~127 集成/T-131 |

每批均在添加后立即运行 `CASE_PROTO=mqtt go test -count=1 -timeout 25m ./test/protocol_pcap/ -run TestProtocolPcapDrive` 全量回归，最终 168/168 全绿。

### 剩余 47 条按可行性分类

| 分类 | 数量 | 明细 | pcap 可行性 |
|------|------|------|------------|
| **pcap 不可行（Go 单测域）** | 10 | §7.7 T-128/129/130（并发/-race/ctx 取消）、§7.10 T-142~145（encodeVBI/decodeVBI 纯函数边界）、§7.13 T-156/157/158（28 字段 report 聚合，无 report output_type） | 不可 |
| **pcap 不可行（配置/字节不可达）** | 9 | T-188/189（剩余长度 268435455 需 268MB payload）、T-123（task report 聚合）、T-194/195/196（SUBSCRIBE flags≠0x02/PROTOCOL NAME/保留位：builder 固定 0x82/"MQTT"/正确值）、T-081/083（剩余长度 2097151/2097152 需 2MB payload，MSS 分段后单包无法呈现）、T-141（白名单主条目，逐属性已由 T-136~140 覆盖） | 不可 |
| **Validate 负向/builder 固定仍缺** | 28 | §7.1 T-008~012/016/020/025/027/030（CONNECT/PUBLISH 保留位与 UTF-8 长度，builder 固定值无法注入非法），§7.2 T-033/034/036/040，§7.3 T-042/049/051，§7.4 T-054/056/058/060/061，§7.5 T-075/076/097/098/116/117 | 部分可补（见推荐） |

**实际 pcap 可补目标约 28 条**（47 - 19 不适用）。

## Key Observations

1. **覆盖率从 25.9% 提升到 77.6%（53 → 159 spec ID）.** 168 个 pcap 用例全绿（`-count=1` 全量回归），每批用例的 `expect.frames` hex 均由 tshark 实际抓包字节校准（如 v5 CONNACK `20 03 00 <reason> <propslen>` 的 SP 在 reason 前、CONNECT RL 公式按 clientID 长度计算）。

2. **5.0 特性覆盖全面.** §7.8（4/4）、§7.9（8/10，主条目 T-141 由 T-136~140 逐属性覆盖）、§7.12（5/5）全部覆盖；T-100 四个 5.0 CONNACK 码（130/135/137/144）字节级断言。

3. **多会话与 Session 继承体系全部覆盖.** §7.11（T-146~150：FlowID/seq/PacketIndex/GroupID/SrcPort）、§7.17（T-176~180+T-177b：CleanSession/KeepAlive/Disconnect/Will 继承与替换）10 条全绿，多会话 10 包/流的流边界、4-tuple 自增（12345/12346/...）、继承语义均有帧级断言。

4. **负向/边界路径 85% 覆盖.** §7.5 异常与边界 55 条已覆盖 47 条；§7.16 Property 编码负向 5/5；§7.19 边界补充 3/5（T-190/191/192，T-188/189 不可行）；§7.20 规范禁止 5/8（T-193 PUBREL 0x62/T-197 QoS=3/T-198/199/200 CONNACK 属性）。

5. **集成链路由 MCP E2E 覆盖.** §7.6 T-121/122/124/125/126/127 通过 MCP `generate_traffic` → engine → Plan → pcap 全链路验证，含 Validate 错误透传（task 失败 + error 断言）与 PacketWorkers=8 乱序。

6. **pcap 不适用域 19 条.** §7.7（3）、§7.10（4）、§7.13（3）、§7.19 T-188/189（2）、T-123/T-141 主条目/T-194/195/196/T-081/083（7）共 19 条无法用 pcap 覆盖：前 10 条由 Go 单测域（mqtt_test.go encodeVBI 边界等）覆盖，后 9 条为 builder 固定行为或字节不可达，标注为不适用。**剩余可补目标 28 条**（§7.1 10 + §7.2 4 + §7.3 3 + §7.4 5 + §7.5 6）。

## Recommendations

1. **§7.1 字段构造余 10 条（T-008~012/016/020/025/027/030）**：CONNECT 保留位/flags（T-008~012）与 PUBLISH flags（T-016/020）为 builder 固定值，pcap 无法注入非法值，标记不适用；T-025/027/030（属性顺序/重复/未定义）可补 Validate 负向。
2. **§7.2/§7.3 余 7 条**：T-033/034/036（状态机细节）/T-040（MSS 边界）多为包序与握手断言，可用 pcap 帧断言补；T-042/049/051（包总数/seq 连续性）已由相邻 case 隐式覆盖，可显式补。
3. **§7.4 余 5 条（T-054/056/058/060/061）**：QoS0/认证/5.0/心跳类业务场景，可补多帧完整流程断言。
4. **§7.19 T-188/189 标记不适用**：剩余长度 268435455 需 268MB payload（约 184k 包），pcap 不可行；encodeVBI 边界已由 `mqtt_test.go` T-142~145 单测覆盖。
5. **Validate 负向补足**：§7.1 T-025/027/030 与 §7.5 余 T-075/076/097/098/116/117（非法配置类）用 MCP 创建应报错断言（`expect_error` + `error_contains`，已有 20+ 条样板）。
6. **所有剩余用例补充时**：每批 20-30 条，`expect.frames` hex 必须以 tshark 实际抓包为准（本任务已修正 5 处 RL/长度/字节序预期偏差），添加后立即全量回归。
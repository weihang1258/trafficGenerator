# mqtt Pcap Test Results

Cases: 168 — pass 168, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| mqtt_s10_multi_session | S10/T-063: 3 会话并发独立流(每流 10 包, PUBLISH a/b/c) | pass | 30 | [pcap](mqtt/mqtt_s10_multi_session.pcap) |
| mqtt_s12_v5_properties | S12/T-185: MQTT 5.0 CONNECT Properties(SessionExpiry+TopicAliasMax+UserProp) + PUBLISH ContentType/TopicAlias(11 包) | pass | 12 | [pcap](mqtt/mqtt_s12_v5_properties.pcap) |
| mqtt_s13_auth | S13/T-186: Username/Password 认证(ConnectFlags=0xC2, 9 包:3 握手+CONNECT+CONNACK+DISCONNECT+3 挥手) | pass | 10 | [pcap](mqtt/mqtt_s13_auth.pcap) |
| mqtt_s14_connack_reject | S14/T-068: CONNACK 拒绝码 5 跳过后续 MQTT 包(8 包) | pass | 9 | [pcap](mqtt/mqtt_s14_connack_reject.pcap) |
| mqtt_s15_v5_keepalive_timeout | S15/T-187: 5.0 Keep Alive 超时 DISCONNECT Reason=0x8D (9包, disconnect_reason=141) | pass | 10 | [pcap](mqtt/mqtt_s15_v5_keepalive_timeout.pcap) |
| mqtt_s1_connect_basic | S1/T-181: 3.1.1 CONNECT/CONNACK 基础连接(9 包：3 握手+CONNECT+CONNACK+DISCONNECT+3 挥手, 实现实际包数) | pass | 10 | [pcap](mqtt/mqtt_s1_connect_basic.pcap) |
| mqtt_s2_publish_qos0 | S2/T-182: PUBLISH QoS0 无 PacketID 无 PUBACK(10 包:3 握手+CONNECT+CONNACK+PUBLISH+DISCONNECT+3 挥手) | pass | 11 | [pcap](mqtt/mqtt_s2_publish_qos0.pcap) |
| mqtt_s3_publish_qos1 | S3/T-055: PUBLISH QoS1(packet_id=100) + PUBACK 同 ID(11 包) | pass | 12 | [pcap](mqtt/mqtt_s3_publish_qos1.pcap) |
| mqtt_s4_publish_qos2 | S4/T-183: PUBLISH QoS2 四步交换 PUBREC/PUBREL/PUBCOMP(13 包) | pass | 14 | [pcap](mqtt/mqtt_s4_publish_qos2.pcap) |
| mqtt_s5_subscribe | S5/T-057: SUBSCRIBE sensor/+ + SUBACK 同 PacketID(11 包) | pass | 12 | [pcap](mqtt/mqtt_s5_subscribe.pcap) |
| mqtt_s7_ping | S7/T-062: PINGREQ/PINGRESP keep alive(11 包) | pass | 12 | [pcap](mqtt/mqtt_s7_ping.pcap) |
| mqtt_s9_will | S9/T-184: Will Message QoS1(ConnectFlags=0x0E, 10 包, 无 DISCONNECT) | pass | 11 | [pcap](mqtt/mqtt_s9_will.pcap) |
| mqtt_t001_connect_v311_bytes | T-001: CONNECT 3.1.1 字节构造(10 0e 00 04 4d 51 54 54 04 02 00 3c 00 02 63 31, 9 包) | pass | 10 | [pcap](mqtt/mqtt_t001_connect_v311_bytes.pcap) |
| mqtt_t002_connect_v5_properties_bytes | T-002: CONNECT 5.0 含 Properties(SessionExpiry 0x11+TopicAliasMax 0x22+UserProp 0x26) 字节级(9 包) | pass | 10 | [pcap](mqtt/mqtt_t002_connect_v5_properties_bytes.pcap) |
| mqtt_t003a_connack_rc_1 | T-003/T-032: CONNACK 3.1.1 ReturnCode=1(unacceptable protocol)+拒绝后跳过后续(8 包) | pass | 9 | [pcap](mqtt/mqtt_t003a_connack_rc_1.pcap) |
| mqtt_t003b_connack_rc_3 | T-003: CONNACK 3.1.1 ReturnCode=3(server unavailable) 字节(8 包) | pass | 9 | [pcap](mqtt/mqtt_t003b_connack_rc_3.pcap) |
| mqtt_t004a_connack_v5_rc_130 | T-004: CONNACK 5.0 ReasonCode=130(0x82 Protocol error) 字节(8 包) | pass | 9 | [pcap](mqtt/mqtt_t004a_connack_v5_rc_130.pcap) |
| mqtt_t004b_connack_v5_rc_135 | T-004: CONNACK 5.0 ReasonCode=135(0x87 Not authorized) 字节(8 包) | pass | 9 | [pcap](mqtt/mqtt_t004b_connack_v5_rc_135.pcap) |
| mqtt_t004c_connack_v5_rc_144 | T-004: CONNACK 5.0 ReasonCode=144(0x90 Topic Name invalid) 字节(8 包) | pass | 9 | [pcap](mqtt/mqtt_t004c_connack_v5_rc_144.pcap) |
| mqtt_t005_publish_qos_fixed_header | T-005: PUBLISH 固定头 QoS0/1/2 → 0x30/0x32/0x34 (3 PUBLISH 验证首字节) | pass | 17 | [pcap](mqtt/mqtt_t005_publish_qos_fixed_header.pcap) |
| mqtt_t006_publish_dup_retain | T-006: PUBLISH QoS1+DUP=1+Retain=1 固定头首字节 0x3B (畸形流量建模) | pass | 12 | [pcap](mqtt/mqtt_t006_publish_dup_retain.pcap) |
| mqtt_t007_pubrel_flags_force_02 | T-007: PUBREL flags=0x02 强制 (QoS2 PUBREL=0x62 与 PUBLISH/PUBREC/PUBCOMP 对照) | pass | 14 | [pcap](mqtt/mqtt_t007_pubrel_flags_force_02.pcap) |
| mqtt_t013_will_retain_flag | T-013: Will Retain=1 → ConnectFlags=0x2E(9 包) | pass | 10 | [pcap](mqtt/mqtt_t013_will_retain_flag.pcap) |
| mqtt_t014_will_qos2_flag | T-014: Will QoS=2 → ConnectFlags=0x16(9 包) | pass | 10 | [pcap](mqtt/mqtt_t014_will_qos2_flag.pcap) |
| mqtt_t015_will_qos3_reject | T-015/T-071: will.qos=3 → Validate 拒绝 (规范: 0/1/2) | pass | 0 | [pcap]() |
| mqtt_t017_suback_multi_reason | T-017: SUBACK 3 filter ReasonCodes 00 01 80(11 包) | pass | 12 | [pcap](mqtt/mqtt_t017_suback_multi_reason.pcap) |
| mqtt_t018_ping_disconnect_v311 | T-018: 3.1.1 PINGREQ C0 00 / PINGRESP D0 00 / DISCONNECT E0 00 字节 | pass | 12 | [pcap](mqtt/mqtt_t018_ping_disconnect_v311.pcap) |
| mqtt_t019_v5_disconnect_reason | T-019: 5.0 DISCONNECT 含 ReasonCode E0 02 00 00(9 包) | pass | 10 | [pcap](mqtt/mqtt_t019_v5_disconnect_reason.pcap) |
| mqtt_t021_v5_publish_no_props | T-021: 5.0 PUBLISH 无属性 PropertiesLen=0x00(10 包) | pass | 11 | [pcap](mqtt/mqtt_t021_v5_publish_no_props.pcap) |
| mqtt_t022_v5_suback_propslen_zero | T-022: 5.0 SUBACK 含 PropertiesLen=0x00 (90 04 00 01 00 00) | pass | 12 | [pcap](mqtt/mqtt_t022_v5_suback_propslen_zero.pcap) |
| mqtt_t023_will_delay_interval_v5 | T-023: 5.0 Will Properties ID=0x18 Delay Interval=5 字节编码(9 包) | pass | 10 | [pcap](mqtt/mqtt_t023_will_delay_interval_v5.pcap) |
| mqtt_t024_v5_will_no_props_len_zero | T-024: 5.0 will 无属性 → Will Properties Length=0x00 必填(9 包) | pass | 10 | [pcap](mqtt/mqtt_t024_v5_will_no_props_len_zero.pcap) |
| mqtt_t026_up_publish_subid_reject | T-026: 5.0 up PUBLISH 含 Subscription Identifier 0x0B → Validate 拒绝(§3.3.4 MQTT-3.3.4-6) | pass | 0 | [pcap]() |
| mqtt_t028_property_binary | T-028: 5.0 Property binary Correlation Data(10 包) | pass | 11 | [pcap](mqtt/mqtt_t028_property_binary.pcap) |
| mqtt_t029_property_stringpair | T-029: 5.0 Property Format=stringpair (CONNECT UserProp ID=0x26) | pass | 10 | [pcap](mqtt/mqtt_t029_property_stringpair.pcap) |
| mqtt_t031_default_packet_order | T-031: 默认流程包顺序: TCP flags 02 12 10 18 18 18 18 11 11 10 + MQTT type 序列(10 包) | pass | 11 | [pcap](mqtt/mqtt_t031_default_packet_order.pcap) |
| mqtt_t035_ping_after_publish | T-035: PINGREQ 在 PUBLISH 之后、DISCONNECT 之前(12 包) | pass | 13 | [pcap](mqtt/mqtt_t035_ping_after_publish.pcap) |
| mqtt_t037_publish_qos3_reject | T-037/T-072: messages[].qos=3 → Validate 拒绝 (QoS 仅 0/1/2) | pass | 0 | [pcap]() |
| mqtt_t038_qos2_down_matrix | T-038: QoS2 下行方向矩阵: PUBLISH(down) PUBREC(up) PUBREL(down) PUBCOMP(up) 共享 PacketID=4(13 包) | pass | 14 | [pcap](mqtt/mqtt_t038_qos2_down_matrix.pcap) |
| mqtt_t039_qos1_down_matrix | T-039: QoS1 下行方向矩阵: PUBLISH(down) → PUBACK(up) 共享 PacketID=3(11 包) | pass | 12 | [pcap](mqtt/mqtt_t039_qos1_down_matrix.pcap) |
| mqtt_t041_connack_session_present | T-041: SessionPresent=1 → CONNACK 20 02 01 00(9 包) | pass | 10 | [pcap](mqtt/mqtt_t041_connack_session_present.pcap) |
| mqtt_t043_mss_segmentation | T-043: MSS 分段超长 PUBLISH(4000B payload, MSS=1460) → 整包不拆仅 TCP 层切 3 段(12 包) | pass | 13 | [pcap](mqtt/mqtt_t043_mss_segmentation.pcap) |
| mqtt_t044_mss_536_min | T-044: MSS=536(MinMSS 边界) 接受 → PUBLISH 切 8 段(536×7+254)(17 包) | pass | 18 | [pcap](mqtt/mqtt_t044_mss_536_min.pcap) |
| mqtt_t045_mss_535_reject | T-045: MSS=535(< MinMSS=536) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t046_mss_100_reject | T-046: MSS=100(过小) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t047_syn_options | T-047: TCP SYN/SYN-ACK 含 MSS(kind2)+WinScale(kind3)+SACK(kind4) 选项(9 包) | pass | 10 | [pcap](mqtt/mqtt_t047_syn_options.pcap) |
| mqtt_t048_tcp_teardown_flags | T-048: TCP 挥手四步 flags=11 11 10(默认 spec 10 包) | pass | 11 | [pcap](mqtt/mqtt_t048_tcp_teardown_flags.pcap) |
| mqtt_t050_disconnect_false_fin | T-050: Disconnect=false 模型异常断开: 无 DISCONNECT, TCP 仍 FIN 挥手(8 包) | pass | 9 | [pcap](mqtt/mqtt_t050_disconnect_false_fin.pcap) |
| mqtt_t052_initial_seq_1000 | T-052: TCP InitialSeq=1000 → SYN seq=1000, 第三个包 ACK seq=1001(9 包) | pass | 10 | [pcap](mqtt/mqtt_t052_initial_seq_1000.pcap) |
| mqtt_t053_keep_alive_zero | T-053: keep_alive=0 → CONNECT 保活字段 00 00(9 包) | pass | 10 | [pcap](mqtt/mqtt_t053_keep_alive_zero.pcap) |
| mqtt_t059_retain_multi_session | T-059: 两 session Retain=1 publish 各自独立(20 包) | pass | 20 | [pcap](mqtt/mqtt_t059_retain_multi_session.pcap) |
| mqtt_t064_srcport_explicit_sessions | T-064: 3 session 显式 SrcPort 50000/50001/50002(30 包) | pass | 30 | [pcap](mqtt/mqtt_t064_srcport_explicit_sessions.pcap) |
| mqtt_t065_session_override_inherit | T-065: session1 覆盖 username/will/ping=false, session2 全继承(20 包) | pass | 22 | [pcap](mqtt/mqtt_t065_session_override_inherit.pcap) |
| mqtt_t066_messages_inherit_replace | T-066: 顶层 messages 继承 vs session1 整体替换(29 包) | pass | 30 | [pcap](mqtt/mqtt_t066_messages_inherit_replace.pcap) |
| mqtt_t067_v5_session_present_clean_reject | T-067: 3.1.1 connect_ack_code=6 → Validate 拒绝 (3.1.1 仅允 0-5) | pass | 0 | [pcap]() |
| mqtt_t068_v4_no_username_password_reject | T-068: v4 password set but no username → Validate 拒绝 (3.1.2.6 PasswordFlag 需 UsernameFlag) | pass | 0 | [pcap]() |
| mqtt_t069_clean_session_and_session_present_reject | T-069: clean_session=true + session_present=true → Validate 互斥拒绝 | pass | 0 | [pcap]() |
| mqtt_t070_session_present_with_error_reject | T-070: session_present=true + connect_ack_code!=0 → Validate 拒绝 (错误 CONNACK 无 session) | pass | 0 | [pcap]() |
| mqtt_t070_sub_filter_plus | T-070: 订阅 filter=sport/+/score 合法 → SUBSCRIBE payload 含字面量(12 包) | pass | 13 | [pcap](mqtt/mqtt_t070_sub_filter_plus.pcap) |
| mqtt_t071_sub_filter_hash_mid | T-071: 订阅 filter=sport/#/score(# 不在末尾) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t073_alias_first_use_empty_topic | T-073: 5.0 空 topic + Topic Alias=1 首包(映射未建立) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t074_alias_reuse_established | T-074: 5.0 空 topic + Topic Alias=1 复用(映射已建立) → 合法, 第二条 Topic Name 长度=0(12 包) | pass | 12 | [pcap](mqtt/mqtt_t074_alias_reuse_established.pcap) |
| mqtt_t074b_alias_without_max_declared | T-074b: 5.0 PUBLISH 用 Topic Alias 但 CONNECT 未声明 0x22 → Validate 拒绝(规则 §8.1 10b) | pass | 0 | [pcap]() |
| mqtt_t077_rl_127_vbi_7f | T-077: 剩余长度 127 边界 → VBI 单字节 0x7F(10 包) | pass | 11 | [pcap](mqtt/mqtt_t077_rl_127_vbi_7f.pcap) |
| mqtt_t078_rl_128_vbi_8001 | T-078: 剩余长度 128 边界 → VBI 两字节 0x80 0x01(10 包) | pass | 11 | [pcap](mqtt/mqtt_t078_rl_128_vbi_8001.pcap) |
| mqtt_t079_invalid_retain_handling_reject | T-079: 5.0 subscription.retain_handling=5 → Validate 拒绝 (仅 0/1/2) | pass | 0 | [pcap]() |
| mqtt_t079_rl_16383_vbi_ff7f | T-079: 剩余长度 16383 边界 → VBI 0xFF 0x7F(21 包) | pass | 22 | [pcap](mqtt/mqtt_t079_rl_16383_vbi_ff7f.pcap) |
| mqtt_t080_rl_16384_vbi_808001 | T-080: 剩余长度 16384 边界 → VBI 三字节 0x80 0x80 0x01(21 包) | pass | 22 | [pcap](mqtt/mqtt_t080_rl_16384_vbi_808001.pcap) |
| mqtt_t082_zero_payload_publish | T-082: payload 0 字节 PUBLISH → RemainingLen=3(仅 Topic Name)(10 包) | pass | 11 | [pcap](mqtt/mqtt_t082_zero_payload_publish.pcap) |
| mqtt_t084_auto_packet_id | T-084: QoS1 不显式 packet_id → 自动分配=1, PUBLISH 与 PUBACK 共享 0x00 0x01(11 包) | pass | 12 | [pcap](mqtt/mqtt_t084_auto_packet_id.pcap) |
| mqtt_t085_will_qos3_reject | T-085: will qos=3 → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t086_will_no_topic | T-086: will 无 topic → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t087_v4_password_no_username | T-087: 3.1.1 Username 空 + Password 非空 → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t088_v5_password_no_username | T-088: 5.0 Username 空 + Password 非空 → 接受, Connect Flags bit6=1 bit7=0(9 包) | pass | 10 | [pcap](mqtt/mqtt_t088_v5_password_no_username.pcap) |
| mqtt_t089_version_3 | T-089: Version=3 → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t090_version_6 | T-090: Version=6 → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t091_suback_code_len_mismatch | T-091: AckReasonCodes 长度(2) != Filters 长度(3) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t092_sub_filters_empty | T-092: subscriptions 无 filters → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t093_prop_binary_bad_hex | T-093: Property Format=binary Value='xyz'(非 hex) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t094_prop_uint32_nonnum | T-094: Property Format=uint32 Value='abc'(非数字) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t095_v4_properties | T-095: Version=4 设置 Properties → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t096_dstport_default_1883 | T-096: 默认 DstPort=1883 → 握手包 tcp.dstport=1883(10 包) | pass | 11 | [pcap](mqtt/mqtt_t096_dstport_default_1883.pcap) |
| mqtt_t099_connack_code_6_v4 | T-099: 3.1.1 connect_ack_code=6 → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t100_connack_130_v5 | T-100: 5.0 connect_ack_code=130 → CONNACK 20 03 00 82 00(8 包) | pass | 9 | [pcap](mqtt/mqtt_t100_connack_130_v5.pcap) |
| mqtt_t100_connack_135_v5 | T-100: 5.0 connect_ack_code=135 → CONNACK 20 03 00 87 00(8 包) | pass | 9 | [pcap](mqtt/mqtt_t100_connack_135_v5.pcap) |
| mqtt_t100_connack_137_v5 | T-101: 5.0 connect_ack_code=137(Server busy) → CONNACK 20 03 00 89 00(8 包) | pass | 9 | [pcap](mqtt/mqtt_t100_connack_137_v5.pcap) |
| mqtt_t100_connack_144_v5 | T-100: 5.0 connect_ack_code=144 → CONNACK 20 03 00 90 00(8 包) | pass | 9 | [pcap](mqtt/mqtt_t100_connack_144_v5.pcap) |
| mqtt_t102_connack_148_v5 | T-102: 5.0 connect_ack_code=148(Topic Alias invalid, 仅 DISCONNECT) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t103_connack_141_v5 | T-103: 5.0 connect_ack_code=141(Keep Alive timeout, 仅 DISCONNECT) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t104_connack_200_v5 | T-104: 5.0 connect_ack_code=200(超 0x9F=159 上限) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t105_clean_session_present | T-105: CleanSession=true + SessionPresent=true → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t106_ackcode_nonzero_present | T-106: connect_ack_code=5 + SessionPresent=true → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t107_publish_topic_wildcard | T-107: PUBLISH topic 含通配符 a/# → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t108_publish_prop_0x11 | T-108: PUBLISH properties 含 0x11(Session Expiry, 非 PUBLISH 白名单) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t109_dup_content_type | T-109: PUBLISH properties 重复 Content Type(0x03) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t110_v4_will_delay | T-110: 3.1.1 will delay_interval=5 → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t111_share_sub_legal | T-111: 5.0 共享订阅 $share/g/sensor/+ 合法 → SUBSCRIBE payload 含字面量(12 包) | pass | 13 | [pcap](mqtt/mqtt_t111_share_sub_legal.pcap) |
| mqtt_t112_share_no_filter | T-112: $share/g(缺 filter 部分) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t113_empty_clientid_clean_false | T-113: 空 ClientID + 显式 CleanSession=false → planner 强制 CleanSession=true, Connect Flags bit1=1(9 包) | pass | 10 | [pcap](mqtt/mqtt_t113_empty_clientid_clean_false.pcap) |
| mqtt_t115_v5_connect_props_len_zero | T-115: 5.0 CONNECT 无属性 → Properties Length 字节 0x00 必填(9 包) | pass | 10 | [pcap](mqtt/mqtt_t115_v5_connect_props_len_zero.pcap) |
| mqtt_t118_utf8_topic_bytes | T-118: topic='传感器/温度'(UTF-8 多字节) → 长度字段=字节数 6+3=9(10 包) | pass | 11 | [pcap](mqtt/mqtt_t118_utf8_topic_bytes.pcap) |
| mqtt_t119_packet_id_65535 | T-119: packet_id=65535(QoS1) → PUBLISH/PUBACK 共享 0xFF 0xFF, 自增 wrap 1(11 包) | pass | 12 | [pcap](mqtt/mqtt_t119_packet_id_65535.pcap) |
| mqtt_t120_will_empty_clientid | T-120: 空 ClientID + will → 通过; Connect Flags bit1=1(Clean) + bit2=1(Will)(9 包) | pass | 10 | [pcap](mqtt/mqtt_t120_will_empty_clientid.pcap) |
| mqtt_t121_strategy_convert | T-121: MCP 全链路解析 mqtt 配置 → task completed + pcap 含 MQTT(9 包) | pass | 10 | [pcap](mqtt/mqtt_t121_strategy_convert.pcap) |
| mqtt_t125_validation_error_propagation | T-125: qos=3 → task 失败, error 含 'qos'(Validate 错误透传) | pass | 0 | [pcap]() |
| mqtt_t126_multi_session_4tuple | T-126: 3 session 未显式 SrcPort → 4-tuple 互异, SrcPort 自增 12345/12346/12347(30 包) | pass | 30 | [pcap](mqtt/mqtt_t126_multi_session_4tuple.pcap) |
| mqtt_t127_workers8_no_reorder | T-127: 默认 spec 8 PacketWorkers → 包序与 PacketIndex 一致(10 包) | pass | 11 | [pcap](mqtt/mqtt_t127_workers8_no_reorder.pcap) |
| mqtt_t131_zero_payloads | T-131: 0 字节 payload + 0 字节 will → 不 panic, 长度字段=0(10 包) | pass | 11 | [pcap](mqtt/mqtt_t131_zero_payloads.pcap) |
| mqtt_t132_connack_v5_code128 | T-132: 5.0 CONNACK Reason Code 128 (Unspecified error) → CONNACK 20 03 00 80 00 + 无后续 MQTT 包(8 包) | pass | 9 | [pcap](mqtt/mqtt_t132_connack_v5_code128.pcap) |
| mqtt_t133_disconnect_v5_code148 | T-133: 5.0 DISCONNECT Reason Code 148 (Topic Alias invalid) → e0 02 94 00(9 包) | pass | 10 | [pcap](mqtt/mqtt_t133_disconnect_v5_code148.pcap) |
| mqtt_t134_suback_v5_code97 | T-134: 5.0 SUBACK 扩展 Reason Code 0x97(No matching subscribers) → 90 04 00 01 00 97(11 包) | pass | 12 | [pcap](mqtt/mqtt_t134_suback_v5_code97.pcap) |
| mqtt_t135_v5_connack_code3_reject | T-135: 5.0 connect_ack_code=3 → Validate 拒绝(3.1.1 码 1-5 在 5.0 非有效代码) | pass | 0 | [pcap]() |
| mqtt_t136_connect_prop_max_packet_size | T-136: 5.0 CONNECT Properties 含 0x22 Maximum Packet Size=1024(uint32) → CONNECT 含 22 00 00 04 00(9 包) | pass | 10 | [pcap](mqtt/mqtt_t136_connect_prop_max_packet_size.pcap) |
| mqtt_t137_connect_prop_forbidden_id | T-137: 5.0 CONNECT 含 0x12(不在 CONNECT 白名单) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t138_publish_prop_payload_format | T-138: 5.0 PUBLISH Properties 含 0x01 Payload Format Indicator=1(byte) → 30 11 ... 02 01 01 78(10 包) | pass | 11 | [pcap](mqtt/mqtt_t138_publish_prop_payload_format.pcap) |
| mqtt_t139_publish_prop_forbidden_id | T-139: 5.0 PUBLISH 含 0x11 Session Expiry Interval(不在 PUBLISH 白名单) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t140_will_prop_delay_interval | T-140: 5.0 Will Properties 0x18 Delay Interval=5(配置中唯一可触达 Will Property 字段) → CONNECT 含 18 00 00 00 05(9 包) | pass | 10 | [pcap](mqtt/mqtt_t140_will_prop_delay_interval.pcap) |
| mqtt_t141a_up_publish_subid_reject | T-141a: 默认方向(up) PUBLISH 带 Subscription Identifier 0x0B → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t141b_subscribe_subid_200 | T-141b: 5.0 SUBSCRIBE Properties 0x0B Subscription Identifier=200(vbi) → 82 ... 0b c8 01(11 包) | pass | 12 | [pcap](mqtt/mqtt_t141b_subscribe_subid_200.pcap) |
| mqtt_t141c_down_publish_two_subids | T-141c: 5.0 down PUBLISH 两个 0x0B SubID=200/201(可重复) → 30 ... 0b c8 01 0b c9 01 | pass | 13 | [pcap](mqtt/mqtt_t141c_down_publish_two_subids.pcap) |
| mqtt_t141d_subscribe_two_subids_reject | T-141d: 5.0 SUBSCRIBE 两个 0x0B Subscription Identifier → Validate 拒绝(SUBSCRIBE 0x0B 不得重复) | pass | 0 | [pcap]() |
| mqtt_t146_flowid_suffix | T-146: 多会话 FlowID 含 :mqtt-0/1/2 后缀(30 包) | pass | 30 | [pcap](mqtt/mqtt_t146_flowid_suffix.pcap) |
| mqtt_t147_tcp_seq_independent | T-147: 多会话 TCP seq 独立不互相影响(30 包) | pass | 20 | [pcap](mqtt/mqtt_t147_tcp_seq_independent.pcap) |
| mqtt_t148_packet_index_independent | T-148: 多会话 PacketIndex 每流从 0 起(30 包) | pass | 30 | [pcap](mqtt/mqtt_t148_packet_index_independent.pcap) |
| mqtt_t149_group_id_shared | T-149: GroupID=fixed g1 + 3 session → 同 worker 顺序输出(30 包) | pass | 30 | [pcap](mqtt/mqtt_t149_group_id_shared.pcap) |
| mqtt_t150_session_srcport_priority | T-150: Sessions[0].SrcPort=50000 不自动递增(20 包) | pass | 20 | [pcap](mqtt/mqtt_t150_session_srcport_priority.pcap) |
| mqtt_t151_v5_nolocal | T-151: 5.0 SUBSCRIBE NoLocal → Options 字节 bit2=1(11 包) | pass | 12 | [pcap](mqtt/mqtt_t151_v5_nolocal.pcap) |
| mqtt_t152_nolocal_v4 | T-152: 3.1.1 filter NoLocal=true → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t153_retain_as_published_v5 | T-153: 5.0 filter RetainAsPublished=true → Options byte bit3=1(12 包) | pass | 13 | [pcap](mqtt/mqtt_t153_retain_as_published_v5.pcap) |
| mqtt_t154_retain_handling_2 | T-154: 5.0 RetainHandling=2 → Options byte bit4-5=10(12 包) | pass | 13 | [pcap](mqtt/mqtt_t154_retain_handling_2.pcap) |
| mqtt_t155_retain_handling_3 | T-155: 5.0 RetainHandling=3(11, Protocol Error) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t159_no_second_connect | T-159: planner 不产出第二个 CONNECT → 仅包 4 为 CONNECT(10 包) | pass | 11 | [pcap](mqtt/mqtt_t159_no_second_connect.pcap) |
| mqtt_t160_qos0_packet_id | T-160: QoS0 + packet_id → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t161_qos_3 | T-161: PUBLISH QoS=3 → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t162_subscribe_packet_id_auto | T-162: SUBSCRIBE 不设 packet_id → 自动分配=1(12 包) | pass | 13 | [pcap](mqtt/mqtt_t162_subscribe_packet_id_auto.pcap) |
| mqtt_t163_disconnect_last_mqtt | T-163: DISCONNECT 是最后一个 MQTT PSH-ACK 段(10 包) | pass | 11 | [pcap](mqtt/mqtt_t163_disconnect_last_mqtt.pcap) |
| mqtt_t164_connack_v4_sp_bits | T-164: 3.1.1 CONNACK byte[0] ∈ {0x00, 0x01}(bit1-7=0)(9 包) | pass | 10 | [pcap](mqtt/mqtt_t164_connack_v4_sp_bits.pcap) |
| mqtt_t165_connack_v5_sp_bits | T-165: 5.0 CONNACK byte[0] ∈ {0x00, 0x01}(9 包) | pass | 10 | [pcap](mqtt/mqtt_t165_connack_v5_sp_bits.pcap) |
| mqtt_t166_sub_no_filters | T-166: subscriptions filters=[] → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t167_topic_65536 | T-167: topic 65536B(超 2 字节长度上限) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t168_rst_no_disconnect | T-168: RST=true 无 DISCONNECT, 最后包 RST(6 包) | pass | 6 | [pcap](mqtt/mqtt_t168_rst_no_disconnect.pcap) |
| mqtt_t169_rst_will | T-169: RST=true + will → will PUBLISH+PUBACK 在 RST 前(8 包) | pass | 8 | [pcap](mqtt/mqtt_t169_rst_will.pcap) |
| mqtt_t170_fin_will | T-170: FIN 挥手 + will → will PUBLISH+PUBACK 在 FIN 前(10 包) | pass | 11 | [pcap](mqtt/mqtt_t170_fin_will.pcap) |
| mqtt_t171_prop_id_100 | T-171: Property Identifier=100(未分配) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t171_property_id_out_of_range | T-171: Property identifier=100 → Validate 拒绝 (MQTT 5.0 仅允 1-44) | pass | 0 | [pcap]() |
| mqtt_t172_prop_uint16_overflow | T-172: Property uint16 Value=70000(>65535) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t172_property_uint16_overflow | T-172: Property uint16 value=70000 → Validate 拒绝 (>65535) | pass | 0 | [pcap]() |
| mqtt_t173_prop_uint32_overflow | T-173: Property uint32 Value=5000000000(>4294967295) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t174_prop_byte_overflow | T-174: Property byte Value=256(>255) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t175_prop_binary_overlen | T-175: Property binary Value 65536B hex → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t176_clean_session_inherit | T-176: 顶层 CleanSession=false, session 继承 → CONNACK SP=1(20 包) | pass | 20 | [pcap](mqtt/mqtt_t176_clean_session_inherit.pcap) |
| mqtt_t177_keep_alive_inherit | T-177: 顶层 KeepAlive=120, session 继承 → CONNECT 00 78(20 包) | pass | 20 | [pcap](mqtt/mqtt_t177_keep_alive_inherit.pcap) |
| mqtt_t177b_keep_alive_zero_override | T-177b: 顶层 60, session keep_alive:0 显式覆盖 → 00 00(20 包) | pass | 20 | [pcap](mqtt/mqtt_t177b_keep_alive_zero_override.pcap) |
| mqtt_t178_disconnect_inherit | T-178: 顶层 Disconnect=false, session 继承 → 无 DISCONNECT 包(20 包) | pass | 18 | [pcap](mqtt/mqtt_t178_disconnect_inherit.pcap) |
| mqtt_t179_will_replace | T-179: 顶层 will=a, session will=b → CONNECT 含 will topic b(20 包) | pass | 20 | [pcap](mqtt/mqtt_t179_will_replace.pcap) |
| mqtt_t180_will_nil_inherit | T-180: 顶层 will=a, session will=nil → CONNECT 含 will topic a(20 包) | pass | 20 | [pcap](mqtt/mqtt_t180_will_nil_inherit.pcap) |
| mqtt_t190_empty_topic_no_alias | T-190: topic='' 无 Topic Alias(v4) → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t190_empty_topic_no_alias_reject | T-190/T-114: messages[].topic='' 且未建立 topic alias → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t191_packet_id_65535_qos2 | T-191: QoS2 + packet_id=65535 → 4 包交换均含 0xFF 0xFF(13 包) | pass | 14 | [pcap](mqtt/mqtt_t191_packet_id_65535_qos2.pcap) |
| mqtt_t191_packetid_65535_qos2 | T-191: PacketID=65535(0xFFFF)+QoS2 → PUBLISH/PUBREC/PUBREL/PUBCOMP 四包共享 ff ff (边界最大 PacketID) | pass | 14 | [pcap](mqtt/mqtt_t191_packetid_65535_qos2.pcap) |
| mqtt_t192_multi_filter_subscribe | T-192: 3 filter SUBSCRIBE(a/b+/c/#) QoS 0/1/2 → 3 filter+3 options(13 包) | pass | 13 | [pcap](mqtt/mqtt_t192_multi_filter_subscribe.pcap) |
| mqtt_t192_subscribe_multi_filter | T-192: 单 SUBSCRIBE 多 filter (a/b QoS0 + c/# QoS1 + d/+ QoS2) → 3 filter 同一包 + SUBACK 3 码 | pass | 12 | [pcap](mqtt/mqtt_t192_subscribe_multi_filter.pcap) |
| mqtt_t193_pubrel_flags_fixed | T-193: buildPubrel 首字节恒 0x62(13 包) | pass | 14 | [pcap](mqtt/mqtt_t193_pubrel_flags_fixed.pcap) |
| mqtt_t197_qos3_reject | T-197: messages qos=3 → Validate 拒绝 | pass | 0 | [pcap]() |
| mqtt_t198_connack_max_qos | T-198: 5.0 CONNACK Maximum QoS=1 → 输出 24 01(9 包) | pass | 10 | [pcap](mqtt/mqtt_t198_connack_max_qos.pcap) |
| mqtt_t199_connack_retain_available | T-199: 5.0 CONNACK Retain Available=0 → 输出 25 00(9 包) | pass | 10 | [pcap](mqtt/mqtt_t199_connack_retain_available.pcap) |
| mqtt_t200_connack_shared_sub_avail | T-200: 5.0 CONNACK Shared Sub Available=1 → 输出 2A 01(9 包) | pass | 10 | [pcap](mqtt/mqtt_t200_connack_shared_sub_avail.pcap) |
| mqtt_t200a_shared_sub_311_reject | T-200 补: 3.1.1 订阅 $share/ 共享订阅 filter → Validate 拒绝 (共享订阅 5.0 only) | pass | 0 | [pcap]() |

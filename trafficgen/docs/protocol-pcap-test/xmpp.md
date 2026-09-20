# xmpp Pcap Test Results

Cases: 11 — pass 11, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| xmpp_t10_neg_direction | 负例：message direction=left（枚举外） | pass | 0 | [pcap]() |
| xmpp_t11_long_body_mss | T-11 长 body 超 MSS 分段（9.46 超长边界）：3000 字符 body→message 节 ~3060B→2 个 TCP 段 | pass | 22 | [pcap](xmpp/xmpp_t11_long_body_mss.pcap) |
| xmpp_t1_smoke_plain | T-1 smoke 改写（PLAIN 19 帧参考形）：10 阶段全序 + 5222 | pass | 19 | [pcap](xmpp/xmpp_t1_smoke_plain.pcap) |
| xmpp_t2_digest_md5 | T-2 auth_mechanism=DIGEST-MD5：四步质询应答 | pass | 21 | [pcap](xmpp/xmpp_t2_digest_md5.pcap) |
| xmpp_t3_scram_sha1 | T-3 auth_mechanism=SCRAM-SHA-1：六步交换（参考 pcap 同机制） | pass | 23 | [pcap](xmpp/xmpp_t3_scram_sha1.pcap) |
| xmpp_t4_anonymous | T-4 auth_mechanism=ANONYMOUS：匿名单轮 | pass | 19 | [pcap](xmpp/xmpp_t4_anonymous.pcap) |
| xmpp_t5_presence_off | T-5 presence=false：presence 缺席 | pass | 18 | [pcap](xmpp/xmpp_t5_presence_off.pcap) |
| xmpp_t6_messages_both | T-6 messages 双向：up/down message 节 | pass | 21 | [pcap](xmpp/xmpp_t6_messages_both.pcap) |
| xmpp_t7_identity_custom | T-7 from/jid/resource/stream_id 定制 | pass | 19 | [pcap](xmpp/xmpp_t7_identity_custom.pcap) |
| xmpp_t8_plain_credentials | T-8 username/password 定制：PLAIN base64 钉 | pass | 19 | [pcap](xmpp/xmpp_t8_plain_credentials.pcap) |
| xmpp_t9_neg_mech | 负例：auth_mechanism=NTLM（枚举外） | pass | 0 | [pcap]() |

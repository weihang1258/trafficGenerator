# dtls Pcap Test Results

Cases: 20 — pass 20, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| dtls_ccs_alert_application | CCS→alert→加密 epoch appdata/关闭（外层类型混排） | pass | 16 | [pcap](dtls/dtls_ccs_alert_application.pcap) |
| dtls_encrypted_opaque_boundary | 加密 epoch 外层可见/明文不可声称（opaque 边界） | pass | 10 | [pcap](dtls/dtls_encrypted_opaque_boundary.pcap) |
| dtls_epoch_sequence_transition | epoch 0→1 切换、每方向 48-bit sequence 独立递增 | pass | 14 | [pcap](dtls/dtls_epoch_sequence_transition.pcap) |
| dtls_handshake_fragmentation | 一个 handshake 消息跨 3 records 分片 | pass | 10 | [pcap](dtls/dtls_handshake_fragmentation.pcap) |
| dtls_handshake_reassembly | 乱序分片按 message_seq/offset 重组（续片共用 msg_seq） | pass | 10 | [pcap](dtls/dtls_handshake_reassembly.pcap) |
| dtls_ipv4_v12_basic | IPv4/UDP 4433 DTLS 1.2 握手+应用+关闭基线 | pass | 12 | [pcap](dtls/dtls_ipv4_v12_basic.pcap) |
| dtls_ipv6_v12_basic | IPv6/UDP 4433 DTLS 1.2 握手+应用+关闭基线 | pass | 12 | [pcap](dtls/dtls_ipv6_v12_basic.pcap) |
| dtls_multi_flow | 多四元组多流（src_ip/src_port 独立，状态不跨流拼接） | pass | 12 | [pcap](dtls/dtls_multi_flow.pcap) |
| dtls_multi_session_isolation | 双独立 session 各自 cookie/epoch/seq/关闭（不串用） | pass | 24 | [pcap](dtls/dtls_multi_session_isolation.pcap) |
| dtls_neg_cookie_state | cookie 只能出现在 type 3 HVR 上 | pass | 0 | [pcap]() |
| dtls_neg_fragment_bounds | 分片超出 handshake length（fragment_offset+fraglen > length） | pass | 0 | [pcap]() |
| dtls_neg_record_truncated | record Length 与实际 datagram 字节不符（wire_fault 注入） | pass | 0 | [pcap]() |
| dtls_neg_sequence_overflow | seq 超 48-bit 范围（wire_fault 注入） | pass | 0 | [pcap]() |
| dtls_neg_udp_carrier | DTLS 需要 UDP 载体，tcp 载体拒绝 | pass | 0 | [pcap]() |
| dtls_neg_version_epoch | 非法版本/epoch（wire_fault 注入） | pass | 0 | [pcap]() |
| dtls_pcap_nic_consistency | PCAP/NIC 同 fixture：方向/4433/record 头一致 | pass | 16 | [pcap](dtls/dtls_pcap_nic_consistency.pcap) |
| dtls_record_boundary_lengths | record 长度边界（1/62/1/2/1400/1） | pass | 6 | [pcap](dtls/dtls_record_boundary_lengths.pcap) |
| dtls_retransmission_timeout | flight 重传（同 msg_seq / 新 record seq）+ 超时关闭 | pass | 18 | [pcap](dtls/dtls_retransmission_timeout.pcap) |
| dtls_v10_legacy_record | DTLS 1.0 legacy record version feff | pass | 12 | [pcap](dtls/dtls_v10_legacy_record.pcap) |
| dtls_v12_cookie_exchange | DTLS 1.2 完整 cookie 交换 + 握手 | pass | 16 | [pcap](dtls/dtls_v12_cookie_exchange.pcap) |

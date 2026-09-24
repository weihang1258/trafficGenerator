# kerberos Pcap Test Results

Cases: 20 — pass 20, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| kerberos_ap_req_ap_rep | AP-REQ/AP-REP 三服务交换：ticket/authenticator opaque | pass | 6 | [pcap](kerberos/kerberos_ap_req_ap_rep.pcap) |
| kerberos_as_req_as_rep | AS-REQ/AS-REP 单对：nonce/realm/principal 外壳 | pass | 2 | [pcap](kerberos/kerberos_as_req_as_rep.pcap) |
| kerberos_encrypteddata_opaque | EncryptedData etype/长度可见、内层 opaque | pass | 6 | [pcap](kerberos/kerberos_encrypteddata_opaque.pcap) |
| kerberos_ipv4_udp_as_basic | IPv4/UDP 88 AS 交换（preauth 轮回 kinit 形态） | pass | 4 | [pcap](kerberos/kerberos_ipv4_udp_as_basic.pcap) |
| kerberos_ipv6_udp_as_basic | IPv6/UDP 88 独立 AS fixture（外层地址族不改变 DER） | pass | 4 | [pcap](kerberos/kerberos_ipv6_udp_as_basic.pcap) |
| kerberos_krb_error_preauth_required | KRB-ERROR PREAUTH_REQUIRED 字段面 + 重试 | pass | 4 | [pcap](kerberos/kerberos_krb_error_preauth_required.pcap) |
| kerberos_multi_session_flow | 多会话/多流：三客户端独立 nonce/ticket/framing 状态 | pass | 12 | [pcap](kerberos/kerberos_multi_session_flow.pcap) |
| kerberos_neg_encrypted_boundary | EncryptedData 外壳越界（wire_fault 注入） | pass | 0 | [pcap]() |
| kerberos_neg_message_tag | 顶层 tag/msg-type 不一致（声明 msg_type=11 于 as_req） | pass | 0 | [pcap]() |
| kerberos_neg_tcp_length | TCP 4-byte record 长度前缀错（wire_fault 注入） | pass | 0 | [pcap]() |
| kerberos_neg_time_nonce_replay | skew/nonce/replay 状态错（wire_fault 注入） | pass | 0 | [pcap]() |
| kerberos_neg_truncated_record | 消息/DER 头截断（wire_fault 注入） | pass | 0 | [pcap]() |
| kerberos_neg_udp_carrier | 双载体并存拒（一条 kerberos 流只骑单载体） | pass | 0 | [pcap]() |
| kerberos_nonce_time_skew | nonce 关联、时间窗口、KRB_AP_ERR_SKEW 边界 | pass | 6 | [pcap](kerberos/kerberos_nonce_time_skew.pcap) |
| kerberos_pcap_nic_consistency | PCAP/NIC 一致：方向/端口/88/record 外壳稳定 | pass | 8 | [pcap](kerberos/kerberos_pcap_nic_consistency.pcap) |
| kerberos_preauth_rfc6113 | RFC 6113 METHOD-DATA 保序 + PA-TGS-REQ 载体区分 | pass | 6 | [pcap](kerberos/kerberos_preauth_rfc6113.pcap) |
| kerberos_replay_retransmission | 请求重传复用 bytes + 重复 AP-REQ replay 错误 | pass | 8 | [pcap](kerberos/kerberos_replay_retransmission.pcap) |
| kerberos_tcp_record_framing | TCP 4-byte record framing：整 record + record 跨 segments 按 length 重组 | pass | 11 | [pcap](kerberos/kerberos_tcp_record_framing.pcap) |
| kerberos_tgs_req_tgs_rep | AS→TGS→AP 全链：krbtgt 与 service ticket 边界 | pass | 6 | [pcap](kerberos/kerberos_tgs_req_tgs_rep.pcap) |
| kerberos_ticket_principal_realm | Ticket/principal/realm 组件与关联 | pass | 6 | [pcap](kerberos/kerberos_ticket_principal_realm.pcap) |

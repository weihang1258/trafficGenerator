# sstp Pcap Test Results

Cases: 22 — pass 22, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| sstp_attribute_protocol_id | Encapsulated Protocol ID 属性：Attribute ID 0x01 / LengthPacket 0x0006 / Value 0x0001 | pass | 15 | [pcap](sstp/sstp_attribute_protocol_id.pcap) |
| sstp_attribute_status_crypto | Status Info（0x02）+ Crypto Binding（0x03）：总长 0x0068/变长，ACK 与 CONNECTED 的 nonce 同值 | pass | 17 | [pcap](sstp/sstp_attribute_status_crypto.pcap) |
| sstp_call_abort | CALL ABORT：Type 0x0005 + Status Info，ABORT 后无任何后续消息且连接关闭 | pass | 19 | [pcap](sstp/sstp_call_abort.pcap) |
| sstp_call_connect_ack | CALL CONNECT ACK：Crypto Binding Request + Status Info、方向 s2c | pass | 16 | [pcap](sstp/sstp_call_connect_ack.pcap) |
| sstp_call_connect_nak | CALL CONNECT NAK 拒绝路径（sessions[] 形）：REQUEST→NAK(Status Info) 后连接终止，禁 CONNECTED/PPP | pass | 16 | [pcap](sstp/sstp_call_connect_nak.pcap) |
| sstp_call_connect_request | CALL CONNECT REQUEST：Length 0x000e、Type 0x0001、Num 1、Encapsulated Protocol ID | pass | 15 | [pcap](sstp/sstp_call_connect_request.pcap) |
| sstp_call_connected | CONNECTED：Length 0x0070、Crypto Binding 0x0068（SHA-256 profile），其后才允许 PPP | pass | 18 | [pcap](sstp/sstp_call_connected.pcap) |
| sstp_group_coalesced_record | group 同 record 双 message：首条组首 group=2，两条 c2s PPP 同一条 TLS record | pass | 18 | [pcap](sstp/sstp_group_coalesced_record.pcap) |
| sstp_https_tls_handshake | TCP/443 + TLS 握手 + application-data 载体（无密钥只断言 TLS） | pass | 16 | [pcap](sstp/sstp_https_tls_handshake.pcap) |
| sstp_length_record_segmentation | SSTP Length 跨 TLS record/TCP segment：单 message 切多 record + 大帧跨 TCP 段 | pass | 269 | [pcap](sstp/sstp_length_record_segmentation.pcap) |
| sstp_multi_connection | 多连接隔离：flows=2 两条独立 TCP/443 + TLS session，各自完成控制序与 PPP | pass | 36 | [pcap](sstp/sstp_multi_connection.pcap) |
| sstp_neg_attribute_length | 属性头截断/LengthPacket 越界或把 Message Type 0x0005/0x0006 当属性（wire_fault 注入） | pass | 0 | [pcap]() |
| sstp_neg_header_length | common/control header 长度或 Length 不一致（wire_fault 注入） | pass | 0 | [pcap]() |
| sstp_neg_ppp_framing | PPP framing 错：缺 address/control（ff 03）压缩形 | pass | 0 | [pcap]() |
| sstp_neg_state_transition | 越序：未 ACK 即 CONNECTED / 未 CONNECTED 即 PPP / ABORT 后续发 | pass | 0 | [pcap]() |
| sstp_neg_tls_boundary | TLS record 截断/明文 SSTP 越过 TLS/跨连接拼接（wire_fault 注入） | pass | 0 | [pcap]() |
| sstp_neg_transport_carrier | 裸 TCP 载体缺 TLS（SSTP 只能经 TLS application-data 承载） | pass | 0 | [pcap]() |
| sstp_pcap_nic_consistency | PCAP/NIC 载体一致：TCP/443 + TLS 握手/应用数据 + 方向 + 握挥手数量 | pass | 16 | [pcap](sstp/sstp_pcap_nic_consistency.pcap) |
| sstp_ppp_ipv4 | C=0 PPP IPv4：ff 03 00 21 + IPv4 头（version/length/checksum 实算） | pass | 18 | [pcap](sstp/sstp_ppp_ipv4.pcap) |
| sstp_ppp_ipv6 | C=0 PPP IPv6：ff 03 00 57 + IPv6 头（version/payload length/Next Header 59） | pass | 18 | [pcap](sstp/sstp_ppp_ipv6.pcap) |
| sstp_ppp_mppe_boundary | MPPE 边界：information 恰好 16B（block 对齐）与 20B（跨 boundary），密文 opaque | pass | 19 | [pcap](sstp/sstp_ppp_mppe_boundary.pcap) |
| sstp_session_ordering | 同连接严格顺序 + ECHO 保活（单流确定序；重连四元组新鲜度由 multi_connection 覆盖） | pass | 20 | [pcap](sstp/sstp_session_ordering.pcap) |

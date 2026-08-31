# ams Pcap Test Results

Cases: 20 — pass 20, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| ams_command_response | S4: broker.info COMMAND→RESPONSE，CorrelationID 77 头字段配对 | pass | 15 | [pcap](ams/ams_command_response.pcap) |
| ams_event_retransmission | S6: 显式重传复用同一 message_id/sequence/payload，不伪造新消息 | pass | 15 | [pcap](ams/ams_event_retransmission.pcap) |
| ams_frame_boundary | S14: Length=18 最小帧、零长 TLV、uint64 安全整数边界值与显式关闭 | pass | 19 | [pcap](ams/ams_frame_boundary.pcap) |
| ams_frame_header_ipv4 | S1: TCP/IPv4 61616 最小 HELLO 协商，帧头 Length/Version/Type/Flags 与 FrameEnd(ae5a) | pass | 9 | [pcap](ams/ams_frame_header_ipv4.pcap) |
| ams_handshake_auth | S2: HELLO→HELLO_OK→AUTH→AUTH_OK 四步握手，认证只带 credential 引用 | pass | 11 | [pcap](ams/ams_handshake_auth.pcap) |
| ams_ipv4_ipv6_same_payload | S11: 双栈连接各自完成 HELLO 协商，应用帧字节一致（连接级显式地址自驱链） | pass | 18 | [pcap](ams/ams_ipv4_ipv6_same_payload.pcap) |
| ams_ipv6 | S10: IPv6/TCP 61616 同一 HELLO fixture，ipv6.nxt=6、payload offset 74 | pass | 9 | [pcap](ams/ams_ipv6.pcap) |
| ams_message_ack | S5: ack-required MESSAGE→MESSAGE_ACK，ack_for 关联 message_id | pass | 15 | [pcap](ams/ams_message_ack.pcap) |
| ams_mss_frame_reassembly | S13: 3000B payload 帧跨 MSS 三段（1460/1460/143），按 Length 重组 | pass | 17 | [pcap](ams/ams_mss_frame_reassembly.pcap) |
| ams_multi_session | S8: 单 TCP 连接双 SessionID 独立状态（corr/sequence/ack 隔离） | pass | 21 | [pcap](ams/ams_multi_session.pcap) |
| ams_multi_stream | S9: 两个 TCP 四元组（42051/42053）各自完成握手+会话+命令，状态不串用 | pass | 30 | [pcap](ams/ams_multi_stream.pcap) |
| ams_neg_correlation_response | N4: RESPONSE 无对应 COMMAND → correlation/response 拒绝 | pass | 0 | [pcap]() |
| ams_neg_frame_encoding | N1: wire_fault bad_version → version/frame 拒绝 | pass | 0 | [pcap]() |
| ams_neg_handshake_state | N2: 首帧非 HELLO（直接 AUTH）→ hello/handshake 拒绝 | pass | 0 | [pcap]() |
| ams_neg_message_ack | N5: MESSAGE_ACK 引用未发送 message → message/ack 拒绝 | pass | 0 | [pcap]() |
| ams_neg_session_reference | N3: 会话未打开先发 command → session 拒绝 | pass | 0 | [pcap]() |
| ams_neg_tlv_length | N6: wire_fault tlv_overrun → tlv/field/length 拒绝 | pass | 0 | [pcap]() |
| ams_ping_pong | S7: session 内显式 PING→PONG（空 payload 最小帧，无自动保活注入） | pass | 15 | [pcap](ams/ams_ping_pong.pcap) |
| ams_session_open_close | S3: 认证后 OPEN_SESSION/OPEN_OK→CLOSE_SESSION/CLOSE_OK，关闭后终止 | pass | 15 | [pcap](ams/ams_session_open_close.pcap) |
| ams_tlv_and_binary_payload | S12: TLV 边界与二进制 body/payload（base64 配置、线上裸字节） | pass | 15 | [pcap](ams/ams_tlv_and_binary_payload.pcap) |

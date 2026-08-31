# openwire Pcap Test Results

Cases: 24 — pass 24, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| openwire_ack_modes | S15: auto/client/individual 三类 consumer/ack，acktype 0/2/3、messagecount 边界 | pass | 22 | [pcap](openwire/openwire_ack_modes.pcap) |
| openwire_connection_session | S3: ConnectionInfo/ack 后 SessionInfo 生命周期 | pass | 11 | [pcap](openwire/openwire_connection_session.pcap) |
| openwire_dispatch_ack | S6: MessageDispatch 后 MessageAck，correlation 关联 consumer/message | pass | 16 | [pcap](openwire/openwire_dispatch_ack.pcap) |
| openwire_exception_response | S12: connection_info 请求 → ExceptionResponse（correlation=1，THROWABLE） | pass | 10 | [pcap](openwire/openwire_exception_response.pcap) |
| openwire_ipv4_ipv6_same_payload | S14: 独立双栈 fixture 各自完成协商+connection+session，WireFormatInfo payload 一致 | pass | 22 | [pcap](openwire/openwire_ipv4_ipv6_same_payload.pcap) |
| openwire_message_body_segmentation | S11: 4000B body 跨 MSS 分段（1460/1460/1252）；tshark 不重组跨段 PDU（dissector 限制，malformed 白名单），按分段 tcp.len 与 length 前缀帧字节断言 | pass | 15 | [pcap](openwire/openwire_message_body_segmentation.pcap) |
| openwire_message_persistent | S5: persistent=true 的 Message 携带 body 与 producer/session 关联 | pass | 13 | [pcap](openwire/openwire_message_persistent.pcap) |
| openwire_multi_connection | S10: 两个独立 TCP 连接（40001/40003）各自协商+connection+session | pass | 22 | [pcap](openwire/openwire_multi_connection.pcap) |
| openwire_multi_flow | S9: 同连接多 session/producer/consumer/destination 交织，s2c ack 回执 | pass | 17 | [pcap](openwire/openwire_multi_flow.pcap) |
| openwire_neg_carrier_profile | N9: 非 61616 目的端口 → tcp/port/profile 拒绝 | pass | 0 | [pcap]() |
| openwire_neg_correlation | N5: ack 引用未注册 consumer → correlation/message 拒绝 | pass | 0 | [pcap]() |
| openwire_neg_destination | N8: 非法 destination → destination 拒绝 | pass | 0 | [pcap]() |
| openwire_neg_entity_scope | N7: producer 引用本连接未开 session → entity/connection 拒绝 | pass | 0 | [pcap]() |
| openwire_neg_length_overrun | N3: wire_fault length_overrun → length 拒绝 | pass | 0 | [pcap]() |
| openwire_neg_short_frame | N1: wire_fault short_frame → frame/length 拒绝 | pass | 0 | [pcap]() |
| openwire_neg_state_order | N4: 未建 session 先发 producer → state/session 拒绝 | pass | 0 | [pcap]() |
| openwire_neg_transaction | N6: commit 无 begin → transaction 拒绝 | pass | 0 | [pcap]() |
| openwire_neg_unknown_command | N2: wire_fault bad_type → command/type 拒绝 | pass | 0 | [pcap]() |
| openwire_producer_consumer | S4: ProducerInfo(queue://orders)+ConsumerInfo(topic://events)，distinct 实体 ID | pass | 13 | [pcap](openwire/openwire_producer_consumer.pcap) |
| openwire_remove_shutdown | S13: RemoveInfo(consumer 2) + ShutdownInfo 后连接终止，无新业务 command | pass | 14 | [pcap](openwire/openwire_remove_shutdown.pcap) |
| openwire_transaction_commit | S7: begin→message(事务内)→commit，transactioninfo.type=2 | pass | 15 | [pcap](openwire/openwire_transaction_commit.pcap) |
| openwire_transaction_rollback | S8: begin→message→rollback，transactioninfo.type=4 | pass | 15 | [pcap](openwire/openwire_transaction_rollback.pcap) |
| openwire_wire_format_ipv4 | S1: IPv4/TCP 61616 建连后首 command 为 WireFormatInfo（版本12、协商 options） | pass | 8 | [pcap](openwire/openwire_wire_format_ipv4.pcap) |
| openwire_wire_format_ipv6 | S2: IPv6/TCP 61616 协商，ipv6.nxt=6，payload offset 74 | pass | 10 | [pcap](openwire/openwire_wire_format_ipv6.pcap) |

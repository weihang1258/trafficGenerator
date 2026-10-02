# amqp Pcap Test Results

Cases: 24 — pass 24, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| amqp_basic_body_segmentation | 200B body frame_max=128 多 BODY 拆分 | pass | 20 | [pcap](amqp/amqp_basic_body_segmentation.pcap) |
| amqp_basic_consume_deliver_ack | consume→deliver→HEADER→BODY→ack 关联 | pass | 22 | [pcap](amqp/amqp_basic_consume_deliver_ack.pcap) |
| amqp_basic_get_empty | basic.get(70) 与显式 get-empty(72) | pass | 18 | [pcap](amqp/amqp_basic_get_empty.pcap) |
| amqp_basic_publish | publish→HEADER→BODY、BodySize=6 | pass | 19 | [pcap](amqp/amqp_basic_publish.pcap) |
| amqp_channel_open_close | channel 1 open/close 全序 + connection close | pass | 20 | [pcap](amqp/amqp_channel_open_close.pcap) |
| amqp_confirm_transaction | tx.select/commit/rollback 六方法（class 90） | pass | 22 | [pcap](amqp/amqp_confirm_transaction.pcap) |
| amqp_connection_handshake | Full connection handshake: protocol header -> start/start-ok/tune/tune-ok/open/open-ok | pass | 14 | [pcap](amqp/amqp_connection_handshake.pcap) |
| amqp_exchange_queue_declare | exchange/queue declare 参数和响应 | pass | 20 | [pcap](amqp/amqp_exchange_queue_declare.pcap) |
| amqp_frame_boundary | frame_max=4096 + 空 properties header + heartbeat 混排 | pass | 20 | [pcap](amqp/amqp_frame_boundary.pcap) |
| amqp_heartbeat | HEARTBEAT type 8/channel 0/size 0 双向双包 | pass | 16 | [pcap](amqp/amqp_heartbeat.pcap) |
| amqp_ipv6 | AMQP 0-9-1 protocol header over TCP/IPv6, application bytes unchanged | pass | 8 | [pcap](amqp/amqp_ipv6.pcap) |
| amqp_keepalive_multi_channel | 双 channel + heartbeat 隔离 | pass | 21 | [pcap](amqp/amqp_keepalive_multi_channel.pcap) |
| amqp_multi_connection | Two independent TCP connections with separate protocol header and handshake | pass | 21 | [pcap](amqp/amqp_multi_connection.pcap) |
| amqp_neg_channel_state | channel 0 上 basic.publish（自然守卫） | pass | 0 | [pcap]() |
| amqp_neg_content_length | body_size_override=100 vs body=5（自然守卫） | pass | 0 | [pcap]() |
| amqp_neg_frame_encoding | wire_fault bad_frame_type 注入 | pass | 0 | [pcap]() |
| amqp_neg_handshake_state | wire_fault handshake_state 注入 + open-before-tune-ok 事件序 | pass | 0 | [pcap]() |
| amqp_neg_missing_tcp | 链缺 tcp 直连判死（[ip,amqp]） | pass | 0 | [pcap]() |
| amqp_neg_presence_top_submap | 层链+顶层空 amqp 子映射并存判死（presence 负例形状） | pass | 0 | [pcap]() |
| amqp_neg_protocol_header | wire_fault protocol_version 注入 | pass | 0 | [pcap]() |
| amqp_neg_session_reference | wire_fault session_reference 注入 | pass | 0 | [pcap]() |
| amqp_neg_stray_top_key | 顶层游离键 src_ip 判死（白名单外） | pass | 0 | [pcap]() |
| amqp_neg_udp_carrier | 链中夹 udp 层判死（单 TCP 载体） | pass | 0 | [pcap]() |
| amqp_protocol_header_ipv4 | AMQP 0-9-1 8-byte protocol header over TCP/IPv4, port 5672 | pass | 8 | [pcap](amqp/amqp_protocol_header_ipv4.pcap) |

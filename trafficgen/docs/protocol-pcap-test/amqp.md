# amqp Pcap Test Results

Cases: 20 — pass 20, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| amqp_basic_body_segmentation | Body > frame_max auto-split into multiple BODY frames; reassembled length equals BodySize | pass | 20 | [pcap](amqp/amqp_basic_body_segmentation.pcap) |
| amqp_basic_consume_deliver_ack | basic.consume -> basic.deliver -> HEADER -> BODY -> basic.ack on same channel | pass | 22 | [pcap](amqp/amqp_basic_consume_deliver_ack.pcap) |
| amqp_basic_get_empty | basic.get followed by explicit basic.get-empty response | pass | 18 | [pcap](amqp/amqp_basic_get_empty.pcap) |
| amqp_basic_publish | basic.publish -> HEADER (class=60) -> BODY with BodySize match | pass | 19 | [pcap](amqp/amqp_basic_publish.pcap) |
| amqp_channel_open_close | Channel 1 open/open-ok then channel.close/close-ok then connection.close/close-ok | pass | 20 | [pcap](amqp/amqp_channel_open_close.pcap) |
| amqp_confirm_transaction | tx.select -> tx.commit -> tx.rollback with select-ok/commit-ok/rollback-ok | pass | 22 | [pcap](amqp/amqp_confirm_transaction.pcap) |
| amqp_connection_handshake | Full connection handshake: protocol header -> start/start-ok/tune/tune-ok/open/open-ok | pass | 14 | [pcap](amqp/amqp_connection_handshake.pcap) |
| amqp_exchange_queue_declare | exchange.declare (direct) + queue.declare with respective ok responses | pass | 20 | [pcap](amqp/amqp_exchange_queue_declare.pcap) |
| amqp_frame_boundary | Frame boundary: heartbeat size=0, BodySize=0 with HEADER, frame_max edge | pass | 20 | [pcap](amqp/amqp_frame_boundary.pcap) |
| amqp_heartbeat | Heartbeat frame: type=8, channel=0, size=0, end=CE | pass | 16 | [pcap](amqp/amqp_heartbeat.pcap) |
| amqp_ipv6 | AMQP 0-9-1 protocol header over TCP/IPv6, application bytes unchanged | pass | 8 | [pcap](amqp/amqp_ipv6.pcap) |
| amqp_keepalive_multi_channel | Single connection, channels 1 and 2 with heartbeat and state isolation | pass | 21 | [pcap](amqp/amqp_keepalive_multi_channel.pcap) |
| amqp_multi_connection | Two independent TCP connections with separate protocol header and handshake | pass | 21 | [pcap](amqp/amqp_multi_connection.pcap) |
| amqp_neg_channel_state | Business method on unopened channel or channel 0 misuse rejected | pass | 0 | [pcap]() |
| amqp_neg_content_length | Header BodySize does not match total BODY frame lengths rejected | pass | 0 | [pcap]() |
| amqp_neg_frame_encoding | Unknown frame type, non-CE end marker, or size overflow rejected | pass | 0 | [pcap]() |
| amqp_neg_handshake_state | Wrong method order, direction, or tune/open state rejected | pass | 0 | [pcap]() |
| amqp_neg_protocol_header | Missing or incorrect AMQP protocol header rejected | pass | 0 | [pcap]() |
| amqp_neg_session_reference | Delivery/consumer/channel reference across connections rejected | pass | 0 | [pcap]() |
| amqp_protocol_header_ipv4 | AMQP 0-9-1 8-byte protocol header over TCP/IPv4, port 5672 | pass | 8 | [pcap](amqp/amqp_protocol_header_ipv4.pcap) |

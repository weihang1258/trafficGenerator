# gnutella Pcap Test Results

Cases: 20 — pass 20, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| gnutella_binary_vendor_payload | S13: Vendor binary payload（base64 配置、线上裸字节 deadbeef00010203） | pass | 10 | [pcap](gnutella/gnutella_binary_vendor_payload.pcap) |
| gnutella_forward_ttl_hops | S6: 同 GUID 转发副本 TTL-1/Hops+1，payload 不变 | pass | 11 | [pcap](gnutella/gnutella_forward_ttl_hops.pcap) |
| gnutella_frame_boundary | S15: PayloadLength=0 最小 PING、TTL/Hops 边界（255/0）、空 criteria、uint32 满值边界 | pass | 14 | [pcap](gnutella/gnutella_frame_boundary.pcap) |
| gnutella_handshake_ipv4 | S1: TCP/IPv4 6346 CONNECT/0.6→200 OK 握手与能力头（键序稳定） | pass | 9 | [pcap](gnutella/gnutella_handshake_ipv4.pcap) |
| gnutella_ipv4_ipv6_same_payload | S12: 双栈连接各自完成 CONNECT/200 握手，帧字节一致（自驱链） | pass | 18 | [pcap](gnutella/gnutella_ipv4_ipv6_same_payload.pcap) |
| gnutella_ipv6 | S11: IPv6/TCP 6346 握手+PING，ipv6.nxt=6、payload offset 74 | pass | 10 | [pcap](gnutella/gnutella_ipv6.pcap) |
| gnutella_mss_message_reassembly | S14: 3000B 文件名 QueryHit 跨 MSS 三段，按 23B 头+PayloadLength 重组 | pass | 13 | [pcap](gnutella/gnutella_mss_message_reassembly.pcap) |
| gnutella_multi_connection | S10: 双连接（42059/42062）各自握手+ping/pong，节点状态不串用 | pass | 22 | [pcap](gnutella/gnutella_multi_connection.pcap) |
| gnutella_multi_queryhit | S7: 同一 Query 双 QueryHit（同 QueryID，不同 ServentID/result），Hits=result 数 | pass | 12 | [pcap](gnutella/gnutella_multi_queryhit.pcap) |
| gnutella_multi_stream | S9: 两个 TCP 四元组各自握手并发不同 Query，状态隔离 | pass | 20 | [pcap](gnutella/gnutella_multi_stream.pcap) |
| gnutella_neg_handshake | N1: wire_fault bad_handshake_line → handshake/header 拒绝 | pass | 0 | [pcap]() |
| gnutella_neg_message_header | N2: wire_fault bad_descriptor → descriptor/message 拒绝 | pass | 0 | [pcap]() |
| gnutella_neg_payload_encoding | N5: PONG 地址宽度不符 profile（v4 配 16B）→ address/payload 拒绝 | pass | 0 | [pcap]() |
| gnutella_neg_query_correlation | N4: QUERY_HIT 引用未发送 query → query/correlation 拒绝 | pass | 0 | [pcap]() |
| gnutella_neg_transport_profile | N6: 非 6346 目的端口 → port 拒绝 | pass | 0 | [pcap]() |
| gnutella_neg_ttl_hops | N3: TTL+Hops 回绕（200+100）→ ttl/hops 拒绝 | pass | 0 | [pcap]() |
| gnutella_ping_pong | S2: 握手后 PING→PONG，同 GUID 关联、PONG 地址/文件计数字段 | pass | 11 | [pcap](gnutella/gnutella_ping_pong.pcap) |
| gnutella_push | S4: QueryHit 后显式 PUSH，ServentID/FileIndex/目标端口关联 | pass | 12 | [pcap](gnutella/gnutella_push.pcap) |
| gnutella_query_queryhit | S3: QUERY(criteria NUL 终止)→QUERY_HIT，QueryID 关联与 Hits/result 一致 | pass | 11 | [pcap](gnutella/gnutella_query_queryhit.pcap) |
| gnutella_vendor_message | S5: Vendor 扩展（VendorID/Selector/Version/payload），显式业务事件 | pass | 10 | [pcap](gnutella/gnutella_vendor_message.pcap) |

# swarm Pcap Test Results

Cases: 20 — pass 20, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| swarm_binary_chunk | S12: binary chunk payload（base64 配置、线上裸字节 0xdeadbeef…） | pass | 14 | [pcap](swarm/swarm_binary_chunk.pcap) |
| swarm_chunk_delivery_ack | S6: ack-required STORE（flags bit2）→ MESSAGE_ACK ack_for=message_id | pass | 15 | [pcap](swarm/swarm_chunk_delivery_ack.pcap) |
| swarm_chunk_retrieve | S5: RETRIEVE→CHUNK 同 CorrelationID，chunk 携带地址与二进制载荷 | pass | 15 | [pcap](swarm/swarm_chunk_retrieve.pcap) |
| swarm_chunk_store | S4: content-addressed STORE/STORE_OK（chunk_address 32B + size + payload） | pass | 15 | [pcap](swarm/swarm_chunk_store.pcap) |
| swarm_discovery_ipv4 | S1: UDP/IPv4 discovery PING/PONG（SWD1 datagram，nonce 关联） | pass | 2 | [pcap](swarm/swarm_discovery_ipv4.pcap) |
| swarm_fragment_reassembly | S13: 大 chunk 双 CHUNK 分片（flags bit3，index 0/1 共享 corr/addr/sequence） | pass | 16 | [pcap](swarm/swarm_fragment_reassembly.pcap) |
| swarm_frame_boundary | S14: Length=26 最小帧、chunk_size=0、零长 payload TLV、2^53-1 correlation 边界 | pass | 18 | [pcap](swarm/swarm_frame_boundary.pcap) |
| swarm_handshake_tcp_ipv4 | S2: TCP/IPv4 storage HELLO/HELLO_OK/AUTH/AUTH_OK 四步握手 | pass | 11 | [pcap](swarm/swarm_handshake_tcp_ipv4.pcap) |
| swarm_ipv4_ipv6_same_payload | S11: 双栈 TCP storage 各自完成 HELLO 协商，帧字节一致（连接级显式地址自驱链） | pass | 18 | [pcap](swarm/swarm_ipv4_ipv6_same_payload.pcap) |
| swarm_ipv6 | S10: UDP/IPv6 discovery 同一 fixture，ipv6.nxt=17、payload offset 62 | pass | 2 | [pcap](swarm/swarm_ipv6.pcap) |
| swarm_manifest_exchange | S7: MANIFEST 携带 manifest_root（32B）与 manifest_entry | pass | 14 | [pcap](swarm/swarm_manifest_exchange.pcap) |
| swarm_multi_session | S9: 单连接双 SessionID（各自 store/retrieve），会话状态隔离 | pass | 19 | [pcap](swarm/swarm_multi_session.pcap) |
| swarm_neg_ack_correlation | N5: MESSAGE_ACK 引用未知 message → ack/correlation 拒绝 | pass | 0 | [pcap]() |
| swarm_neg_chunk_integrity | N3: chunk_payload 长度 ≠ chunk_size → chunk/length 拒绝 | pass | 0 | [pcap]() |
| swarm_neg_frame_encoding | N1: wire_fault bad_version → version/frame 拒绝 | pass | 0 | [pcap]() |
| swarm_neg_handshake_state | N2: 首帧非 HELLO（直接 AUTH）→ hello/handshake 拒绝 | pass | 0 | [pcap]() |
| swarm_neg_session_reference | N4: 会话未打开先发 store → session/connection 拒绝 | pass | 0 | [pcap]() |
| swarm_neg_transport_profile | N6: 非 1634 目的端口 → port 拒绝 | pass | 0 | [pcap]() |
| swarm_session_open_close | S3: 认证后 OPEN_SESSION/OPEN_OK→CLOSE/CLOSE_OK，关闭后终止 | pass | 15 | [pcap](swarm/swarm_session_open_close.pcap) |
| swarm_stream_multiplex | S8: 单会话双 StreamID（store/store_ok@1 与 retrieve/chunk@2），流状态隔离 | pass | 17 | [pcap](swarm/swarm_stream_multiplex.pcap) |

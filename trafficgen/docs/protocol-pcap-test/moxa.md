# moxa Pcap Test Results

Cases: 13 — pass 13, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| moxa_bidirectional | S3/T-MOXA-S3-01: 双向 4 块流（up WR/down RT 交替），事件模式每块 1 包，11 包 = 3 握手 + 4 数据 + 4 挥手 | pass | 11 | [pcap](moxa/moxa_bidirectional.pcap) |
| moxa_binary_payload | S5/T-MOXA-S5-01: payload_b64 aGFoYQ== → "haha"，8 包 | pass | 8 | [pcap](moxa/moxa_binary_payload.pcap) |
| moxa_ipv6 | S6/T-MOXA-S6-01: IPv6 载体，payload 偏移 74，8 包 | pass | 8 | [pcap](moxa/moxa_ipv6.pcap) |
| moxa_multi_segment | S2/T-MOXA-S2-01: 单块 2000B A > MSS1460 → 2 段（1460+540），payload 首字节 41，段 1=包4 段 2=包5 | pass | 9 | [pcap](moxa/moxa_multi_segment.pcap) |
| moxa_neg_bad_b64 | N-5/E-T3: payload_b64 非法 → 拒绝（非法 base64；非法方向同族见设计 §9.1 E-T2） | pass | 0 | [pcap]() |
| moxa_neg_bad_direction | N-7/E-T2: stream 块 direction 非法值 'sideways' → 校验拒绝 | pass | 0 | [pcap]() |
| moxa_neg_config_packet | N-2: 配置报文字节（受控探针 5a 5a 5a）混入 stream → 拒绝（诚实边界，待定字节不进数据面，设计 §9.2） | pass | 0 | [pcap]() |
| moxa_neg_empty_payload | N-1/E-T1: stream 空 payload → validator 拒绝（任务失败 = PASS） | pass | 0 | [pcap]() |
| moxa_neg_no_handshake | N-4/E-T5: tcp.handshake=false → 拒绝（透明透传需 TCP 连接） | pass | 0 | [pcap]() |
| moxa_neg_oversize | N-6/E-B1: payload 3000B > MaxBlockBytes2048 → 拒绝（超长>MSS 且>2048 合并于本用例） | pass | 0 | [pcap]() |
| moxa_neg_sessions_multi | N-3/E-S3: sessions=3 > 1 → 拒绝（v1 多会话走 strategy flows，设计 §4.3） | pass | 0 | [pcap]() |
| moxa_sessions_multi | S4/T-MOXA-S4-01: 多串口会话 = flows=3，src_port 12345/12346/12347，dst_port 恒 4800，3×8=24 包；聚合用 distinct_exclude 滤掉对端口 | pass | 24 | [pcap](moxa/moxa_sessions_multi.pcap) |
| moxa_single_up | S1/T-MOXA-S1-01: 单向上行 "hello"，8 包 = 3 握手 + 1 数据 + 4 挥手（事件模式无单独 ACK） | pass | 8 | [pcap](moxa/moxa_single_up.pcap) |

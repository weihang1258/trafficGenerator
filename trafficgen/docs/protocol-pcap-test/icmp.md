# icmp Pcap Test Results

Cases: 8 — pass 8, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| icmp_t1_smoke | T-1 smoke 配对：缺省 ping 2 帧——ip.proto=1；icmp.type p1=8/p2=0；src/dst 换向 | pass | 2 | [pcap](icmp/icmp_t1_smoke.pcap) |
| icmp_t2_header_bytes | T-2 头字节钉：8B 头整钉（type 08/code 00/校验和 192d/id=seq=1 回退面）+data ping；体首=帧偏移 34（eth14+ip20） | pass | 2 | [pcap](icmp/icmp_t2_header_bytes.pcap) |
| icmp_t3_explicit | T-3 显式 identifier=7/sequence=9/data=abc 覆盖钉 | pass | 2 | [pcap](icmp/icmp_t3_explicit.pcap) |
| icmp_t4_pattern | T-4 Pattern 多轮：2×echo 步 → 4 帧（req+auto-reply×2）；identifier=5 显式、seq 1/2 递增、data aa/bb 逐字节 | pass | 4 | [pcap](icmp/icmp_t4_pattern.pcap) |
| icmp_t5_neg_type | 负例：type=3 非 Echo 拒（validator 逐步校验） | pass | 0 | [pcap]() |
| icmp_t6_neg_code | 负例：code=1 拒（Echo code 恒 0） | pass | 0 | [pcap]() |
| icmp_t7_neg_presence | 负例：层链+顶层 icmp 子映射并存=判死（presence 负例形状） | pass | 0 | [pcap]() |
| icmp_t8_neg_static_copy | 负例：ip 层显式标量+strategy_fc flows=2 → 框架层链门（icmpv6_vn_static_copy 同款） | pass | 0 | [pcap]() |

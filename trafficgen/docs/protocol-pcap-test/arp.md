# arp Pcap Test Results

Cases: 12 — pass 12, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| arp_t10_neg_target_mac | 负例：target_mac 格式非法拒（复审 M1 补例） | pass | 0 | [pcap]() |
| arp_t11_neg_target_ip | 负例：target_ip 格式非法拒（复审 M1 补例） | pass | 0 | [pcap]() |
| arp_t12_neg_static_copy | T-12 静态复制拒（12.9）：eth 层显式标量+flows=2 → 框架通用门（复审 M2 补例，sv_vn_static_copy 同款） | pass | 0 | [pcap]() |
| arp_t1_baseline_pair | T-1 基线配对：op=1 缺省地址 2 帧——帧1 广播 ff*6+oper 0001+tha 全零；帧2 单播+oper 0002 角色互换 | pass | 2 | [pcap](arp/arp_t1_baseline_pair.pcap) |
| arp_t2_bytes_full | T-2 字节全钉：帧1 28B 载荷五段全等（htype 0001+ptype 0800+hlen 06+plen 04+oper 0001+sha/spa/tha 全零/tpa） | pass | 2 | [pcap](arp/arp_t2_bytes_full.pcap) |
| arp_t3_explicit_addrs | T-3 显式地址覆盖：sender/target IP+MAC 全显式 → sha/spa/tha/tpa 与 ether src 双钉 | pass | 2 | [pcap](arp/arp_t3_explicit_addrs.pcap) |
| arp_t4_single_reply | T-4 单发宣告（op=2）：1 帧，ether 单播 dst=sender_mac（裁定3 勘误：legacy 此形广播错位） | pass | 1 | [pcap](arp/arp_t4_single_reply.pcap) |
| arp_t5_neg_operation | 负例：operation=3 拒（V9 registry [1,2] 先火） | pass | 0 | [pcap]() |
| arp_t6_neg_sender_ip | 负例：sender_ip 格式非法拒（validator 锚） | pass | 0 | [pcap]() |
| arp_t7_neg_ip_carrier | 负例：[eth,ip,arp] IP 承载混入拒（V-carrier 通用门，sv 同款锚） | pass | 0 | [pcap]() |
| arp_t8_neg_presence | 负例：层链+顶层 arp 子映射并存=判死（presence 负例形状） | pass | 0 | [pcap]() |
| arp_t9_neg_sender_mac | 负例：sender_mac 格式非法拒（复审 M1 补例——矩阵行5 MAC 半面） | pass | 0 | [pcap]() |

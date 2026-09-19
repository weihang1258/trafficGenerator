# mpls Pcap Test Results

Cases: 14 — pass 14, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| mpls_direction_down | T-MPLS-10: direction=down（地址+MAC 全交换） | pass | 1 | [pcap](mpls/mpls_direction_down.pcap) |
| mpls_frames_multi | T-MPLS-9: frames=3 多帧（IP ID 逐帧+1） | pass | 3 | [pcap](mpls/mpls_frames_multi.pcap) |
| mpls_inner_tcp | T-MPLS-12: 内层 TCP 裸头（inner_proto:6） | pass | 1 | [pcap](mpls/mpls_inner_tcp.pcap) |
| mpls_multicast | T-MPLS-11: multicast EtherType 0x8848 | pass | 1 | [pcap](mpls/mpls_multicast.pcap) |
| mpls_neg_direction | T-MPLS-8: direction 非法 | pass | 0 | [pcap]() |
| mpls_neg_innerproto | T-MPLS-7: inner_proto 非法 | pass | 0 | [pcap]() |
| mpls_neg_label | T-MPLS-4: label 超 20bit（legacy Validate 真门） | pass | 0 | [pcap]() |
| mpls_neg_sbit | T-MPLS-6: S 位非栈底 | pass | 0 | [pcap]() |
| mpls_neg_tc | T-MPLS-5: TC 超 3bit | pass | 0 | [pcap]() |
| mpls_port_dyn | T-MPLS-14: mpls.src_port 动态 inc+flows=2（E1 逐流端口池） | pass | 2 | [pcap](mpls/mpls_port_dyn.pcap) |
| mpls_single_label_ipv4 | 冒烟：单标签栈（label 100/TTL 64）内层 IPv4/UDP 单帧；地址 ip 层、端口 mpls 层（存量等价迁移） | pass | 1 | [pcap](mpls/mpls_single_label_ipv4.pcap) |
| mpls_v6 | T-MPLS-13: v6 内层对照（builder 双族 §3.9） | pass | 1 | [pcap](mpls/mpls_v6.pcap) |
| mpls_vn_presence | T-MPLS-2: 顶层 mpls presence 判死（空 map 也死） | pass | 0 | [pcap]() |
| mpls_vn_static_port | T-MPLS-3: mpls 层静态端口+flows=2 拒（12.9，门扩扫 mpls 层） | pass | 0 | [pcap]() |

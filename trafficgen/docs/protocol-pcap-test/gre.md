# gre Pcap Test Results

Cases: 21 — pass 21, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| gre_4in6 | 4in6 异构（T-GRE-7）：外层 v6、内层显式 v4——外层 EtherType 0x86dd + next header 47，GRE proto 0x0800 | pass | 1 | [pcap](gre/gre_4in6.pcap) |
| gre_6in4 | 6in4 异构（T-GRE-6）：外层 v4、内层 ip 层显式 v6——内层地址不被外层顶掉（静默覆盖修复的正例） | pass | 1 | [pcap](gre/gre_6in4.pcap) |
| gre_basic_ipv4 | 层链形 [ip,gre,ip,udp,dns]：GRE(无flags,proto 0x0800)封装内层 IPv4/UDP/DNS 查询 -> 1 帧；tshark 自动解 GRE | pass | 1 | [pcap](gre/gre_basic_ipv4.pcap) |
| gre_checksum | checksum C 位（T-GRE-9）：C 位置位（flags 0x8000）+ 4B 校验和 | pass | 1 | [pcap](gre/gre_checksum.pcap) |
| gre_inner_tcp_dynamic | 内层tcp动态正例（T-GRE-18）：T-GRE-8链形内层dst_port inc[80,8080 step8000]+flows=2→两流内层目的端口distinct(80/8080) | pass | 18 | [pcap](gre/gre_inner_tcp_dynamic.pcap) |
| gre_inner_ttl | 内层 TTL 覆盖（T-GRE-12）：内层 ip{ttl:60} 生效，外层仍 64——两个 TTL 独立 | pass | 1 | [pcap](gre/gre_inner_ttl.pcap) |
| gre_inner_udp_dynamic | 内层udp动态正例（T-GRE-17）：内层src_port inc 41000-41001+flows=2→两流内层源端口distinct | pass | 2 | [pcap](gre/gre_inner_udp_dynamic.pcap) |
| gre_kcs_combo | K+C+S 三键组合（T-GRE-11）：flags 0xb000，GRE 头 16B（4基+4校验+4键+4序号） | pass | 1 | [pcap](gre/gre_kcs_combo.pcap) |
| gre_key | key K 位与值（T-GRE-10）：key=0x12345678，K 位置位（flags 0x2000） | pass | 1 | [pcap](gre/gre_key.pcap) |
| gre_neg_dyn_checksum | 负例：关字段checksum动态被拒（T-GRE-19补，sequence/key/checksum同锚词三键齐锁） | pass | 0 | [pcap]() |
| gre_neg_dyn_key | 负例：关字段 key 动态被拒（T-GRE-4） | pass | 0 | [pcap]() |
| gre_neg_dyn_sequence | 负例：关字段sequence动态被拒（T-GRE-19，代表checksum/key同锚词） | pass | 0 | [pcap]() |
| gre_neg_flat | 负例：顶层扁平五键判死（T-GRE-2） | pass | 0 | [pcap]() |
| gre_neg_inner_dyn | 负例：内层 ip 动态拒绝（T-GRE-13）——单四元组模型，内层地址静态 | pass | 0 | [pcap]() |
| gre_neg_inner_mixed | 负例：内层混族拒绝（T-GRE-14）——v4 源 + v6 目的不是合法 IP 包 | pass | 0 | [pcap]() |
| gre_neg_static_copy | 负例：层链静态复制拒绝 flows=2+全静态标量（T-GRE-3） | pass | 0 | [pcap]() |
| gre_outer_ip_dynamic | 外层ip动态正例（T-GRE-16）：外层src list双值+flows=2→两流外层源distinct，内层恒192.168.1.1 | pass | 2 | [pcap](gre/gre_outer_ip_dynamic.pcap) |
| gre_outer_ip_rand | 外层ip rand动态（T-GRE-21，D-DNS-1顺手：GRE备注②关闭，seed=7可复现） | pass | 2 | [pcap](gre/gre_outer_ip_rand.pcap) |
| gre_sequence_multi | sequence 多帧递增（T-GRE-8）：内层 [tcp,http] 9 帧（3握手+2数据+4挥手），S 位置位逐帧序号 0→8 | pass | 9 | [pcap](gre/gre_sequence_multi.pcap) |
| gre_v6_in_v6 | v6-in-v6 纯 v6 隧道（T-GRE-5）：外层 IPv6(next header 47) + GRE proto 0x86dd + 内层 IPv6/UDP/DNS -> 1 帧 | pass | 1 | [pcap](gre/gre_v6_in_v6.pcap) |
| gre_vlan_tagged | VLAN正例（T-GRE-15）：链首vlan{id:100,priority:4}→外层帧打802.1Q tag（TPID 0x8100+TCI 0x8064），其余偏移+4 | pass | 1 | [pcap](gre/gre_vlan_tagged.pcap) |

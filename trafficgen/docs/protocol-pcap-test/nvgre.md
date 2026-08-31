# nvgre Pcap Test Results

Cases: 20 — pass 20, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| nvgre_basic_ipv4_inner_ipv4 | outer IPv4/47 GRE + TEB + inner Ethernet/IPv4: flags 0x2000, protocol 0x6558, key, inner MAC/EtherType/IP | pass | 1 | [pcap](nvgre/nvgre_basic_ipv4_inner_ipv4.pcap) |
| nvgre_basic_ipv6_inner_ipv6 | outer/inner IPv6 independent fixtures | pass | 1 | [pcap](nvgre/nvgre_basic_ipv6_inner_ipv6.pcap) |
| nvgre_inner_ethernet_boundary | boundary: explicit broadcast/unicast MACs, empty payload legal | pass | 1 | [pcap](nvgre/nvgre_inner_ethernet_boundary.pcap) |
| nvgre_inner_vlan | inner 802.1Q: TPID 0x8100, TCI=PCP<<13\|VID, post-VLAN EtherType + inner IP | pass | 1 | [pcap](nvgre/nvgre_inner_vlan.pcap) |
| nvgre_key_endian_and_ttl | key network byte order 12 34 56 7a + outer TTL boundary 255 (hop-limit boundary uses outer v6) | pass | 1 | [pcap](nvgre/nvgre_key_endian_and_ttl.pcap) |
| nvgre_mtu_reassembly | large inner frame: full payload carried intact (no real IP fragmentation this version) | pass | 1 | [pcap](nvgre/nvgre_mtu_reassembly.pcap) |
| nvgre_multi_flow_same_vsid | same VSID, two Flow IDs: key high 24 bits equal, low 8 bits distinct | pass | 3 | [pcap](nvgre/nvgre_multi_flow_same_vsid.pcap) |
| nvgre_multi_vsid | multi-VSID: distinct key high 24 bits, per-VSID inner frame association | pass | 3 | [pcap](nvgre/nvgre_multi_vsid.pcap) |
| nvgre_neg_address_family | negative: inner ether_type ipv6 with IPv4 src_ip rejected (address family mismatch) | pass | 0 | [pcap]() |
| nvgre_neg_carrier_length | negative: length wraparound (payload overflow) rejected | pass | 0 | [pcap]() |
| nvgre_neg_gre_flags_protocol | negative: reserved GRE flags / non-TEB protocol rejected | pass | 0 | [pcap]() |
| nvgre_neg_inner_ethernet_vlan | negative: invalid inner MAC rejected | pass | 0 | [pcap]() |
| nvgre_neg_key_vsid_flow | negative: VSID beyond 24-bit rejected (key missing/endian via wire fault) | pass | 0 | [pcap]() |
| nvgre_neg_vsid_flow_isolation | negative: cross-VSID/flow state reuse rejected | pass | 0 | [pcap]() |
| nvgre_outer_inner_family_matrix | four outer/inner IPv4-IPv6 family combinations | pass | 2 | [pcap](nvgre/nvgre_outer_inner_family_matrix.pcap) |
| nvgre_outer_ipv4_inner_ipv6 | outer IPv4/47 + inner Ethernet/IPv6 (EtherType 0x86dd) | pass | 1 | [pcap](nvgre/nvgre_outer_ipv4_inner_ipv6.pcap) |
| nvgre_outer_ipv6_inner_ipv4 | outer IPv6 Next Header=47 + GRE/TEB + inner IPv4 (independent family) | pass | 1 | [pcap](nvgre/nvgre_outer_ipv6_inner_ipv4.pcap) |
| nvgre_pcap_nic_consistency | PCAP output: deterministic key + inner prefix (NIC capture is orchestrated externally) | pass | 1 | [pcap](nvgre/nvgre_pcap_nic_consistency.pcap) |
| nvgre_vsid_max_flow_max | VSID=0xffffff, FlowID=0xff: key ff ff ff ff, no truncation | pass | 1 | [pcap](nvgre/nvgre_vsid_max_flow_max.pcap) |
| nvgre_vsid_zero_flow_zero | explicit VSID=0, FlowID=0: key 00 00 00 00 survives (not defaulted away) | pass | 1 | [pcap](nvgre/nvgre_vsid_zero_flow_zero.pcap) |

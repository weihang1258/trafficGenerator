# vxlan Pcap Test Results

Cases: 20 — pass 20, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| vxlan_empty_inner_payload | empty inner payload but complete Ethernet header; UDP length recomputable | pass | 1 | [pcap](vxlan/vxlan_empty_inner_payload.pcap) |
| vxlan_i_flag_reserved | I flag=1 with all reserved bits zero, fixed 8-byte header | pass | 1 | [pcap](vxlan/vxlan_i_flag_reserved.pcap) |
| vxlan_inner_vlan_ethernet | inner 802.1Q VLAN: TPID 0x8100 + TCI, VXLAN header unchanged at 42 | pass | 1 | [pcap](vxlan/vxlan_inner_vlan_ethernet.pcap) |
| vxlan_ipv4_outer_ipv4_inner | IPv4 outer/UDP 4789 + IPv4 inner Ethernet: fixed 8-byte header, VNI 5000 | pass | 1 | [pcap](vxlan/vxlan_ipv4_outer_ipv4_inner.pcap) |
| vxlan_ipv4_outer_ipv6_inner | IPv4 outer with independent IPv6 inner fixture (EtherType 0x86dd) | pass | 1 | [pcap](vxlan/vxlan_ipv4_outer_ipv6_inner.pcap) |
| vxlan_ipv6_outer_ipv4_inner | IPv6 outer/UDP 4789 with IPv4 inner: VXLAN header at offset 62 | pass | 1 | [pcap](vxlan/vxlan_ipv6_outer_ipv4_inner.pcap) |
| vxlan_ipv6_outer_ipv6_inner | IPv6 outer and IPv6 inner dual-stack combination | pass | 1 | [pcap](vxlan/vxlan_ipv6_outer_ipv6_inner.pcap) |
| vxlan_mss_not_applicable | UDP carrier does not negotiate MSS and emits no TCP handshake: one datagram | pass | 1 | [pcap](vxlan/vxlan_mss_not_applicable.pcap) |
| vxlan_multi_flow | three flows x up/down: distinct source ports, VNIs and inner identities | pass | 6 | [pcap](vxlan/vxlan_multi_flow.pcap) |
| vxlan_multi_vni | four same-outer-tuple datagrams with distinct VNIs and paired inner fixtures | pass | 4 | [pcap](vxlan/vxlan_multi_vni.pcap) |
| vxlan_neg_checksum | negative: checksum wire fault rejected | pass | 0 | [pcap]() |
| vxlan_neg_header_truncated | negative: VXLAN header shorter than 8 bytes cannot be encoded | pass | 0 | [pcap]() |
| vxlan_neg_inner_frame | negative: inner fixture with invalid MAC rejected | pass | 0 | [pcap]() |
| vxlan_neg_reserved_flags | negative: I flag cleared is rejected at validation | pass | 0 | [pcap]() |
| vxlan_neg_udp_carrier | negative: non-4789 UDP destination port rejected | pass | 0 | [pcap]() |
| vxlan_neg_vni_overflow | negative: VNI beyond 24-bit rejected | pass | 0 | [pcap]() |
| vxlan_outer_inner_independent | outer and inner fixtures independent: outer v4 with both inner families | pass | 2 | [pcap](vxlan/vxlan_outer_inner_independent.pcap) |
| vxlan_pcap_nic_capture | PCAP output: directional up/down datagrams with flags/VNI and inner identity (NIC capture orchestrated externally) | pass | 2 | [pcap](vxlan/vxlan_pcap_nic_capture.pcap) |
| vxlan_udp_checksum_profiles | IPv4 UDP checksum zero profile vs auto nonzero profile | pass | 2 | [pcap](vxlan/vxlan_udp_checksum_profiles.pcap) |
| vxlan_vni_boundary | VNI=0 and VNI=0xffffff 24-bit boundary datagrams | pass | 2 | [pcap](vxlan/vxlan_vni_boundary.pcap) |

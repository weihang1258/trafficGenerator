# geneve Pcap Test Results

Cases: 20 — pass 20, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| geneve_empty_inner_payload | zero-length inner payload but complete Ethernet header; UDP length recomputable | pass | 1 | [pcap](geneve/geneve_empty_inner_payload.pcap) |
| geneve_inner_vlan_ethernet | inner 802.1Q: TPID 0x8100 + TCI, base header unchanged at 42 | pass | 1 | [pcap](geneve/geneve_inner_vlan_ethernet.pcap) |
| geneve_ipv4_outer_ipv4_inner | IPv4 outer/UDP 6081 + Ethernet/IPv4 inner: fixed 8-byte base header, VNI 5000 | pass | 1 | [pcap](geneve/geneve_ipv4_outer_ipv4_inner.pcap) |
| geneve_ipv4_outer_ipv6_inner | IPv4 outer with independent IPv6 inner fixture (inner EtherType 0x86dd) | pass | 1 | [pcap](geneve/geneve_ipv4_outer_ipv6_inner.pcap) |
| geneve_ipv6_outer_ipv4_inner | IPv6 outer/UDP 6081 with IPv4 inner: base header at offset 62 | pass | 1 | [pcap](geneve/geneve_ipv6_outer_ipv4_inner.pcap) |
| geneve_ipv6_outer_ipv6_inner | IPv6 outer and IPv6 inner dual-stack fixture, addresses never conflated | pass | 1 | [pcap](geneve/geneve_ipv6_outer_ipv6_inner.pcap) |
| geneve_mss_not_applicable | UDP carrier negotiates no MSS and emits no TCP handshake: one datagram | pass | 1 | [pcap](geneve/geneve_mss_not_applicable.pcap) |
| geneve_multi_flow | three flows x up/down: distinct ports, VNIs, per-flow options and inner identities | pass | 6 | [pcap](geneve/geneve_multi_flow.pcap) |
| geneve_multi_vni | four same-outer-tuple datagrams with distinct VNIs and paired inner fixtures | pass | 4 | [pcap](geneve/geneve_multi_vni.pcap) |
| geneve_neg_checksum | negative: checksum wire fault rejected | pass | 0 | [pcap]() |
| geneve_neg_header_truncated | negative: GENEVE base header shorter than 8 bytes cannot be encoded | pass | 0 | [pcap]() |
| geneve_neg_option_length | negative: option data not 4-byte aligned rejected | pass | 0 | [pcap]() |
| geneve_neg_reserved_version_flags | negative: nonzero version rejected (RFC 8926 defines version 0 only) | pass | 0 | [pcap]() |
| geneve_neg_udp_carrier_inner | negative: non-6081 UDP destination port rejected | pass | 0 | [pcap]() |
| geneve_neg_vni_protocol | negative: VNI beyond 24-bit rejected | pass | 0 | [pcap]() |
| geneve_options_multiple | three datagrams with empty / single / multi option chains, OptLen accumulates | pass | 3 | [pcap](geneve/geneve_options_multiple.pcap) |
| geneve_options_single | single option: class/type/reserved/length/data, inner shifted by option bytes | pass | 1 | [pcap](geneve/geneve_options_single.pcap) |
| geneve_pcap_nic_consistency | PCAP output: directional up/down datagrams with version/OptLen/VNI and inner identity (NIC capture orchestrated externally) | pass | 2 | [pcap](geneve/geneve_pcap_nic_consistency.pcap) |
| geneve_version_flags | version=0 with flags all-zero / OAM bit / Critical bit, reserved zero, VNI=1 | pass | 3 | [pcap](geneve/geneve_version_flags.pcap) |
| geneve_vni_boundary | VNI=0 and VNI=0xffffff 24-bit boundary datagrams | pass | 2 | [pcap](geneve/geneve_vni_boundary.pcap) |

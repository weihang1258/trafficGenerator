# isis Pcap Test Results

Cases: 25 — pass 25, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| isis_area_system_id | L2 LSP separates Area and System ID | pass | 1 | [pcap](isis/isis_area_system_id.pcap) |
| isis_ipv4_ipv6_tlv_profiles | Independent IPv4 and IPv6 TLV profiles | pass | 2 | [pcap](isis/isis_ipv4_ipv6_tlv_profiles.pcap) |
| isis_l1_csnp | L1 CSNP with one LSP Entry | pass | 1 | [pcap](isis/isis_l1_csnp.pcap) |
| isis_l1_iih_ethertype | EtherType L1 LAN IIH | pass | 1 | [pcap](isis/isis_l1_iih_ethertype.pcap) |
| isis_l1_iih_llc | LLC L1 LAN IIH with Area TLV | pass | 1 | [pcap](isis/isis_l1_iih_llc.pcap) |
| isis_l1_lsp_ipv4 | L1 LSP with Area and IPv4 interface TLVs | pass | 1 | [pcap](isis/isis_l1_lsp_ipv4.pcap) |
| isis_l1_lsp_tlv_order | L1 LSP preserves standard TLV order | pass | 1 | [pcap](isis/isis_l1_lsp_tlv_order.pcap) |
| isis_l2_iih_ethertype | EtherType L2 LAN IIH | pass | 1 | [pcap](isis/isis_l2_iih_ethertype.pcap) |
| isis_l2_iih_llc | LLC L2 LAN IIH | pass | 1 | [pcap](isis/isis_l2_iih_llc.pcap) |
| isis_l2_lsp_ipv6 | L2 LSP with IPv6 interface TLV | pass | 1 | [pcap](isis/isis_l2_lsp_ipv6.pcap) |
| isis_l2_psnp | L2 PSNP with one LSP Entry | pass | 1 | [pcap](isis/isis_l2_psnp.pcap) |
| isis_length_checksum | L1 LSP length and Fletcher checksum | pass | 1 | [pcap](isis/isis_length_checksum.pcap) |
| isis_neg_address_family | Reject mixed address-family TLV profile | pass | 0 | [pcap]() |
| isis_neg_checksum | Reject bad LSP checksum | pass | 0 | [pcap]() |
| isis_neg_duplicate_area | Reject duplicate Area TLV sources | pass | 0 | [pcap]() |
| isis_neg_header | Reject malformed Common Header | pass | 0 | [pcap]() |
| isis_neg_identifier | Reject malformed System ID | pass | 0 | [pcap]() |
| isis_neg_ip_carrier | Reject IP carrier | pass | 0 | [pcap]() |
| isis_neg_length | Reject PDU/TLV length mismatch | pass | 0 | [pcap]() |
| isis_neg_level_type | Reject level/type mismatch | pass | 0 | [pcap]() |
| isis_neg_mixed_carrier | Reject mixed LLC and EtherType | pass | 0 | [pcap]() |
| isis_neg_profile | Reject unknown wire profile | pass | 0 | [pcap]() |
| isis_neg_state | Reject event outside adjacency state | pass | 0 | [pcap]() |
| isis_neg_vendor_tlv | Reject unregistered vendor TLV | pass | 0 | [pcap]() |
| isis_neighbor_up_sequence | Explicit neighbor up sequence | pass | 4 | [pcap](isis/isis_neighbor_up_sequence.pcap) |

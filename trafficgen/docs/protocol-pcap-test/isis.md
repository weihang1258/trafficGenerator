# isis Pcap Test Results

Cases: 25 — pass 0, fail 12, error 13

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| isis_area_system_id | L2 LSP separates Area and System ID | error | 0 | `` |
| isis_ipv4_ipv6_tlv_profiles | Independent IPv4 and IPv6 TLV profiles | error | 0 | `` |
| isis_l1_csnp | L1 CSNP with one LSP Entry | error | 0 | `` |
| isis_l1_iih_ethertype | EtherType L1 LAN IIH | error | 0 | `` |
| isis_l1_iih_llc | LLC L1 LAN IIH with Area TLV | error | 0 | `` |
| isis_l1_lsp_ipv4 | L1 LSP with Area and IPv4 interface TLVs | error | 0 | `` |
| isis_l1_lsp_tlv_order | L1 LSP preserves standard TLV order | error | 0 | `` |
| isis_l2_iih_ethertype | EtherType L2 LAN IIH | error | 0 | `` |
| isis_l2_iih_llc | LLC L2 LAN IIH | error | 0 | `` |
| isis_l2_lsp_ipv6 | L2 LSP with IPv6 interface TLV | error | 0 | `` |
| isis_l2_psnp | L2 PSNP with one LSP Entry | error | 0 | `` |
| isis_length_checksum | L1 LSP length and Fletcher checksum | error | 0 | `` |
| isis_neg_address_family | Reject mixed address-family TLV profile | fail | 0 | `` |
| isis_neg_checksum | Reject bad LSP checksum | fail | 0 | `` |
| isis_neg_duplicate_area | Reject duplicate Area TLV sources | fail | 0 | `` |
| isis_neg_header | Reject malformed Common Header | fail | 0 | `` |
| isis_neg_identifier | Reject malformed System ID | fail | 0 | `` |
| isis_neg_ip_carrier | Reject IP carrier | fail | 0 | `` |
| isis_neg_length | Reject PDU/TLV length mismatch | fail | 0 | `` |
| isis_neg_level_type | Reject level/type mismatch | fail | 0 | `` |
| isis_neg_mixed_carrier | Reject mixed LLC and EtherType | fail | 0 | `` |
| isis_neg_profile | Reject unknown wire profile | fail | 0 | `` |
| isis_neg_state | Reject event outside adjacency state | fail | 0 | `` |
| isis_neg_vendor_tlv | Reject unregistered vendor TLV | fail | 0 | `` |
| isis_neighbor_up_sequence | Explicit neighbor up sequence | error | 0 | `` |

## Failures

### isis_area_system_id — L2 LSP separates Area and System ID

generate: layers: unknown layer "isis" (position 1)

### isis_ipv4_ipv6_tlv_profiles — Independent IPv4 and IPv6 TLV profiles

generate: layers: unknown layer "isis" (position 1)

### isis_l1_csnp — L1 CSNP with one LSP Entry

generate: layers: unknown layer "isis" (position 1)

### isis_l1_iih_ethertype — EtherType L1 LAN IIH

generate: layers: unknown layer "isis" (position 1)

### isis_l1_iih_llc — LLC L1 LAN IIH with Area TLV

generate: layers: unknown layer "isis" (position 1)

### isis_l1_lsp_ipv4 — L1 LSP with Area and IPv4 interface TLVs

generate: layers: unknown layer "isis" (position 1)

### isis_l1_lsp_tlv_order — L1 LSP preserves standard TLV order

generate: layers: unknown layer "isis" (position 1)

### isis_l2_iih_ethertype — EtherType L2 LAN IIH

generate: layers: unknown layer "isis" (position 1)

### isis_l2_iih_llc — LLC L2 LAN IIH

generate: layers: unknown layer "isis" (position 1)

### isis_l2_lsp_ipv6 — L2 LSP with IPv6 interface TLV

generate: layers: unknown layer "isis" (position 1)

### isis_l2_psnp — L2 PSNP with one LSP Entry

generate: layers: unknown layer "isis" (position 1)

### isis_length_checksum — L1 LSP length and Fletcher checksum

generate: layers: unknown layer "isis" (position 1)

### isis_neg_address_family — Reject mixed address-family TLV profile

rejected but error "layers: unknown layer \"isis\" (position 1)" does not contain "address"

### isis_neg_checksum — Reject bad LSP checksum

rejected but error "layers: unknown layer \"isis\" (position 1)" does not contain "checksum"

### isis_neg_duplicate_area — Reject duplicate Area TLV sources

rejected but error "layers: unknown layer \"isis\" (position 1)" does not contain "area"

### isis_neg_header — Reject malformed Common Header

rejected but error "layers: unknown layer \"isis\" (position 1)" does not contain "header"

### isis_neg_identifier — Reject malformed System ID

rejected but error "layers: unknown layer \"isis\" (position 1)" does not contain "system"

### isis_neg_ip_carrier — Reject IP carrier

rejected but error "layers: unknown layer \"isis\" (position 1)" does not contain "carrier"

### isis_neg_length — Reject PDU/TLV length mismatch

rejected but error "layers: unknown layer \"isis\" (position 1)" does not contain "length"

### isis_neg_level_type — Reject level/type mismatch

rejected but error "layers: unknown layer \"isis\" (position 1)" does not contain "level"

### isis_neg_mixed_carrier — Reject mixed LLC and EtherType

rejected but error "layers: unknown layer \"isis\" (position 1)" does not contain "carrier"

### isis_neg_profile — Reject unknown wire profile

rejected but error "layers: unknown layer \"isis\" (position 1)" does not contain "profile"

### isis_neg_state — Reject event outside adjacency state

rejected but error "layers: unknown layer \"isis\" (position 1)" does not contain "state"

### isis_neg_vendor_tlv — Reject unregistered vendor TLV

rejected but error "layers: unknown layer \"isis\" (position 1)" does not contain "tlv"

### isis_neighbor_up_sequence — Explicit neighbor up sequence

generate: layers: unknown layer "isis" (position 1)


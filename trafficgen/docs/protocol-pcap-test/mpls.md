# mpls Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| mpls_single_label_ipv4 | smoke: single label stack (label 100, TTL 64) over inner IPv4/UDP -> 1 frame; tshark auto-parses MPLS (eth.type 0x8847) | pass | 1 | [pcap](mpls/mpls_single_label_ipv4.pcap) |

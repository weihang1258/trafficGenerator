# ike_nat_t Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| ike_nat_t_sa_init_header_only | smoke: IKEv2 SA_INIT initiator header-only message (no payloads) over UDP 500; tshark auto-parses isakmp; no Non-ESP marker since dst != 4500 | pass | 1 | [pcap](/tmp/mcp-pcaps/ike_nat_t/ike_nat_t_sa_init_header_only.pcap) |

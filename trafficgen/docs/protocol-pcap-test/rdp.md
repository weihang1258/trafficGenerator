# rdp Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| rdp_tcp3389_x224_mcs | smoke: RDP over TCP 3389; X.224 connection request/confirm + MCS Connect Initial (27 frames incl. handshake and FIN); LBMSRS heuristic dissector claims frame 9-10 -> decode_as echo forces data | pass | 27 | [pcap](rdp/rdp_tcp3389_x224_mcs.pcap) |

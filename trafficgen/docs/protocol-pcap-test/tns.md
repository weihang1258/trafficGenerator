# tns Pcap Test Results

Cases: 12 — pass 5, fail 7, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| tns_connect_accept | S1/T-TNS-S1: CONNECT→ACCEPT→TTC data; TCP 1521 | fail | 11 | `tns/tns_connect_accept.pcap` |
| tns_header_fields | S7/T-TNS-S7: complete public header fields and DATA flags | fail | 11 | `tns/tns_header_fields.pcap` |
| tns_ipv6_connect | S5/T-TNS-S5: IPv6 CONNECT→ACCEPT | fail | 9 | `tns/tns_ipv6_connect.pcap` |
| tns_multi_session | S6/T-TNS-S6: two independent CONNECT→ACCEPT sessions | fail | 11 | `tns/tns_multi_session.pcap` |
| tns_neg_checksum | N4: nonzero checksum conflicts with disabled mode | pass | 0 | [pcap]() |
| tns_neg_data_flags | N5: nonzero DATA flags rejected in v1 | pass | 0 | [pcap]() |
| tns_neg_length | N3: packet length below 8 rejected | pass | 0 | [pcap]() |
| tns_neg_packet_type | N2: unknown packet type rejected | pass | 0 | [pcap]() |
| tns_neg_udp | N1: UDP carrier rejected | pass | 0 | [pcap]() |
| tns_redirect | S3/T-TNS-S3: CONNECT→REDIRECT; no reconnect | fail | 9 | `tns/tns_redirect.pcap` |
| tns_refuse | S2/T-TNS-S2: CONNECT→REFUSE; no DATA | fail | 9 | `tns/tns_refuse.pcap` |
| tns_ttc_sqlnet_session | S4/T-TNS-S4: TTC and SQL*Net profile sequence, flags zero | fail | 13 | `tns/tns_ttc_sqlnet_session.pcap` |

## Failures

### tns_connect_accept — S1/T-TNS-S1: CONNECT→ACCEPT→TTC data; TCP 1521

verify: expert: frame 4 malformed: [Malformed Packet: TNS],_ws.malformed; expert: frame 5 malformed: [Malformed Packet: TNS],_ws.malformed; field tns.reserved: tshark [-r /tmp/mcp-pcaps/tns/tns_connect_accept.pcap -T fields -e tns.reserved -d tcp.port==2049,rpc -d tcp.port==6000,x11 -d tcp.port==1883,mqtt -d tcp.port==6667,irc]: exit status 1: tshark: Some fields aren't valid:
	tns.reserved
; field tns.data_flags: tshark [-r /tmp/mcp-pcaps/tns/tns_connect_accept.pcap -T fields -e tns.data_flags -d tcp.port==2049,rpc -d tcp.port==6000,x11 -d tcp.port==1883,mqtt -d tcp.port==6667,irc]: exit status 1: tshark: Some fields aren't valid:
	tns.data_flags


### tns_header_fields — S7/T-TNS-S7: complete public header fields and DATA flags

verify: expert: frame 4 malformed: [Malformed Packet: TNS],_ws.malformed; expert: frame 5 malformed: [Malformed Packet: TNS],_ws.malformed; field tns.packet_checksum on packet 4: got "0x0000", want "0"; field tns.reserved: tshark [-r /tmp/mcp-pcaps/tns/tns_header_fields.pcap -T fields -e tns.reserved -d tcp.port==2049,rpc -d tcp.port==6000,x11 -d tcp.port==1883,mqtt -d tcp.port==6667,irc]: exit status 1: tshark: Some fields aren't valid:
	tns.reserved
; field tns.header_checksum on packet 4: got "0x0000", want "0"; field tns.packet_checksum on packet 5: got "0x0000", want "0"; field tns.reserved: tshark [-r /tmp/mcp-pcaps/tns/tns_header_fields.pcap -T fields -e tns.reserved -d tcp.port==2049,rpc -d tcp.port==6000,x11 -d tcp.port==1883,mqtt -d tcp.port==6667,irc]: exit status 1: tshark: Some fields aren't valid:
	tns.reserved
; field tns.header_checksum on packet 5: got "0x0000", want "0"; field tns.packet_checksum on packet 6: got "0x0000", want "0"; field tns.reserved: tshark [-r /tmp/mcp-pcaps/tns/tns_header_fields.pcap -T fields -e tns.reserved -d tcp.port==2049,rpc -d tcp.port==6000,x11 -d tcp.port==1883,mqtt -d tcp.port==6667,irc]: exit status 1: tshark: Some fields aren't valid:
	tns.reserved
; field tns.header_checksum on packet 6: got "0x0000", want "0"; field tns.packet_checksum on packet 7: got "0x0000", want "0"; field tns.reserved: tshark [-r /tmp/mcp-pcaps/tns/tns_header_fields.pcap -T fields -e tns.reserved -d tcp.port==2049,rpc -d tcp.port==6000,x11 -d tcp.port==1883,mqtt -d tcp.port==6667,irc]: exit status 1: tshark: Some fields aren't valid:
	tns.reserved
; field tns.header_checksum on packet 7: got "0x0000", want "0"; field tns.data_flags: tshark [-r /tmp/mcp-pcaps/tns/tns_header_fields.pcap -T fields -e tns.data_flags -d tcp.port==2049,rpc -d tcp.port==6000,x11 -d tcp.port==1883,mqtt -d tcp.port==6667,irc]: exit status 1: tshark: Some fields aren't valid:
	tns.data_flags
; field tns.data_flags: tshark [-r /tmp/mcp-pcaps/tns/tns_header_fields.pcap -T fields -e tns.data_flags -d tcp.port==2049,rpc -d tcp.port==6000,x11 -d tcp.port==1883,mqtt -d tcp.port==6667,irc]: exit status 1: tshark: Some fields aren't valid:
	tns.data_flags


### tns_ipv6_connect — S5/T-TNS-S5: IPv6 CONNECT→ACCEPT

verify: expert: frame 4 malformed: [Malformed Packet: TNS],_ws.malformed; expert: frame 5 malformed: [Malformed Packet: TNS],_ws.malformed; field tns.packet_checksum on packet 4: got "0x0000", want "0"; field tns.header_checksum on packet 5: got "0x0000", want "0"

### tns_multi_session — S6/T-TNS-S6: two independent CONNECT→ACCEPT sessions

verify: expert: frame 4 malformed: [Malformed Packet: TNS],_ws.malformed; expert: frame 5 malformed: [Malformed Packet: TNS],_ws.malformed; expert: frame 6 malformed: [Malformed Packet: TNS],_ws.malformed; expert: frame 7 malformed: [Malformed Packet: TNS],_ws.malformed; count: got 11 packets, want 18; field tcp.srcport: distinct values mismatch (want [12345 12346]; missing [12346]; unexpected [])

### tns_redirect — S3/T-TNS-S3: CONNECT→REDIRECT; no reconnect

verify: expert: frame 4 malformed: [Malformed Packet: TNS],_ws.malformed

### tns_refuse — S2/T-TNS-S2: CONNECT→REFUSE; no DATA

verify: expert: frame 4 malformed: [Malformed Packet: TNS],_ws.malformed

### tns_ttc_sqlnet_session — S4/T-TNS-S4: TTC and SQL*Net profile sequence, flags zero

verify: expert: frame 4 malformed: [Malformed Packet: TNS],_ws.malformed; expert: frame 5 malformed: [Malformed Packet: TNS],_ws.malformed; field tns.data_flags: tshark [-r /tmp/mcp-pcaps/tns/tns_ttc_sqlnet_session.pcap -T fields -e tns.data_flags -d tcp.port==2049,rpc -d tcp.port==6000,x11 -d tcp.port==1883,mqtt -d tcp.port==6667,irc]: exit status 1: tshark: Some fields aren't valid:
	tns.data_flags
; field tns.packet_checksum on packet 9: got "0x0000", want "0"


# nmea Pcap Test Results

Cases: 80 — pass 80, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| nmea_tcp_gga_beidou_talker | TCP BD talker GGA stream (BeiDou) | pass | 8 | [pcap](nmea/nmea_tcp_gga_beidou_talker.pcap) |
| nmea_tcp_gga_galileo_talker | TCP GA talker GGA stream (Galileo) | pass | 8 | [pcap](nmea/nmea_tcp_gga_galileo_talker.pcap) |
| nmea_tcp_gga_gb_talker | TCP GB talker GGA stream (GB) | pass | 8 | [pcap](nmea/nmea_tcp_gga_gb_talker.pcap) |
| nmea_tcp_gga_gi_talker | TCP GI talker GGA stream (NavIC/IRNSS) | pass | 8 | [pcap](nmea/nmea_tcp_gga_gi_talker.pcap) |
| nmea_tcp_ipv4_concurrent_sessions | TCP two concurrent sessions (interleaved) | pass | 18 | [pcap](nmea/nmea_tcp_ipv4_concurrent_sessions.pcap) |
| nmea_tcp_ipv4_gga_badcs | TCP GGA with corrupt checksum stream | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_gga_badcs.pcap) |
| nmea_tcp_ipv4_gga_gltalker | TCP GL talker GGA stream | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_gga_gltalker.pcap) |
| nmea_tcp_ipv4_gga_gntalker | TCP GN talker GGA stream | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_gga_gntalker.pcap) |
| nmea_tcp_ipv4_gga_iitalker | TCP II talker GGA stream | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_gga_iitalker.pcap) |
| nmea_tcp_ipv4_gga_nocs | TCP GGA without checksum stream | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_gga_nocs.pcap) |
| nmea_tcp_ipv4_gga_only | TCP single-sentence GGA stream | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_gga_only.pcap) |
| nmea_tcp_ipv4_gll | TCP single-sentence GLL stream | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_gll.pcap) |
| nmea_tcp_ipv4_gsa | TCP single-sentence GSA stream | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_gsa.pcap) |
| nmea_tcp_ipv4_gsa_full | TCP 18-field GSA stream | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_gsa_full.pcap) |
| nmea_tcp_ipv4_gsv | TCP single-sentence GSV stream | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_gsv.pcap) |
| nmea_tcp_ipv4_gsv_three_seq | TCP GSV 3-message sequence stream | pass | 10 | [pcap](nmea/nmea_tcp_ipv4_gsv_three_seq.pcap) |
| nmea_tcp_ipv4_pack_gga_rmc | TCP GGA+RMC packed in single segment | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_pack_gga_rmc.pcap) |
| nmea_tcp_ipv4_proprietary_pgrme | TCP $PGRME proprietary sentence stream | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_proprietary_pgrme.pcap) |
| nmea_tcp_ipv4_rmc_220knots | TCP RMC with high speed 220.5 knots | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_rmc_220knots.pcap) |
| nmea_tcp_ipv4_rmc_only | TCP single-sentence RMC stream | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_rmc_only.pcap) |
| nmea_tcp_ipv4_rmc_void | TCP RMC void status A stream | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_rmc_void.pcap) |
| nmea_tcp_ipv4_stream | TCP single-session GGA+RMC two-sentence stream | pass | 9 | [pcap](nmea/nmea_tcp_ipv4_stream.pcap) |
| nmea_tcp_ipv4_two_sessions_sequential | TCP two sequential sessions | pass | 18 | [pcap](nmea/nmea_tcp_ipv4_two_sessions_sequential.pcap) |
| nmea_tcp_ipv4_vtg | TCP single-sentence VTG stream | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_vtg.pcap) |
| nmea_tcp_ipv4_zda | TCP single-sentence ZDA stream | pass | 8 | [pcap](nmea/nmea_tcp_ipv4_zda.pcap) |
| nmea_tcp_ipv6_stream | TCP IPv6 single-session GGA+RMC stream | pass | 9 | [pcap](nmea/nmea_tcp_ipv6_stream.pcap) |
| nmea_tcp_multicast | TCP multicast destination GGA+RMC stream | pass | 9 | [pcap](nmea/nmea_tcp_multicast.pcap) |
| nmea_tcp_nondefault_port | TCP nondefault port 4001 | pass | 9 | [pcap](nmea/nmea_tcp_nondefault_port.pcap) |
| nmea_tcp_rmc_gq_talker | TCP GQ talker RMC stream (QZSS) | pass | 8 | [pcap](nmea/nmea_tcp_rmc_gq_talker.pcap) |
| nmea_tcp_rst | TCP RST termination after GGA | pass | 5 | [pcap](nmea/nmea_tcp_rst.pcap) |
| nmea_tcp_rst_multi | TCP RST termination after GGA+RMC | pass | 6 | [pcap](nmea/nmea_tcp_rst_multi.pcap) |
| nmea_tcp_udp_coexist | TCP GGA + UDP RMC coexisting sessions | pass | 10 | [pcap](nmea/nmea_tcp_udp_coexist.pcap) |
| nmea_tcp_udp_coexist_reversed | UDP GGA + TCP RMC coexisting sessions (reversed order) | pass | 10 | [pcap](nmea/nmea_tcp_udp_coexist_reversed.pcap) |
| nmea_tcp_wf_address_family_mismatch | TCP wire fault: address family mismatch (IPv6 in IPv4 flow) | pass | 0 | [pcap]() |
| nmea_tcp_wf_carrier_conflict | TCP wire fault: carrier conflict (both TCP and UDP) | pass | 0 | [pcap]() |
| nmea_tcp_wf_carrier_layer_missing | TCP wire fault: carrier layer missing (GRE without IP) | pass | 0 | [pcap]() |
| nmea_tcp_wf_checksum_hex_width | TCP wire fault: checksum with >2 hex digits | pass | 0 | [pcap]() |
| nmea_tcp_wf_checksum_mismatch | TCP wire fault: checksum mismatch (*6A observed vs computed *69) | pass | 0 | [pcap]() |
| nmea_tcp_wf_date_out_of_range | TCP wire fault: RMC date 321226 (day 32 invalid) | pass | 0 | [pcap]() |
| nmea_tcp_wf_direction_char | TCP wire fault: invalid hemisphere direction X | pass | 0 | [pcap]() |
| nmea_tcp_wf_field_count_extra | TCP wire fault: GGA field count extra (15 fields) | pass | 0 | [pcap]() |
| nmea_tcp_wf_field_count_short | TCP wire fault: GGA field count short (missing altitude) | pass | 0 | [pcap]() |
| nmea_tcp_wf_gsa_fix_type | TCP wire fault: GSA fix type 0 (must be 1/2/3) | pass | 0 | [pcap]() |
| nmea_tcp_wf_gsa_mode_char | TCP wire fault: GSA mode A is valid (testmode char, not M) | pass | 0 | [pcap]() |
| nmea_tcp_wf_gsv_seq_correlation | TCP wire fault: GSV sequence correlation broken (msg 3 of 3 missing) | pass | 0 | [pcap]() |
| nmea_tcp_wf_lat_over | TCP wire fault: latitude 9030.0000 (90 degrees 30 minutes exceeds 90) | pass | 0 | [pcap]() |
| nmea_tcp_wf_lf_only | TCP wire fault: LF only (no CR) | pass | 0 | [pcap]() |
| nmea_tcp_wf_lon_over | TCP wire fault: longitude 011310.000 exceeds 180 | pass | 0 | [pcap]() |
| nmea_tcp_wf_minutes_over | TCP wire fault: latitude minutes 60 or more | pass | 0 | [pcap]() |
| nmea_tcp_wf_missing_crlf | TCP wire fault: missing CRLF | pass | 0 | [pcap]() |
| nmea_tcp_wf_missing_dollar | TCP wire fault: missing $ (sentence must start with $) | pass | 0 | [pcap]() |
| nmea_tcp_wf_port_undeclared | TCP wire fault: port undeclared in session | pass | 0 | [pcap]() |
| nmea_tcp_wf_propagation | TCP wire fault: propagation mode unspecified | pass | 0 | [pcap]() |
| nmea_tcp_wf_proprietary_no_checksum | TCP wire fault: $PGRME without mandatory checksum | pass | 0 | [pcap]() |
| nmea_tcp_wf_sentence_length | TCP wire fault: sentence exceeds 82-byte limit | pass | 0 | [pcap]() |
| nmea_tcp_wf_start_bang | TCP wire fault: sentence starts with ! | pass | 0 | [pcap]() |
| nmea_tcp_wf_status_char | TCP wire fault: GLL status X (must be A or V) | pass | 0 | [pcap]() |
| nmea_tcp_wf_talker_p_standard | TCP wire fault: $P used with standard sentence type GGA | pass | 0 | [pcap]() |
| nmea_tcp_wf_time_out_of_range | TCP wire fault: UTC time 253519 exceeds 24:00:00 | pass | 0 | [pcap]() |
| nmea_tcp_wf_truncated_tcp | TCP wire fault: truncated sentence | pass | 0 | [pcap]() |
| nmea_tcp_wf_unknown_talker | TCP wire fault: unknown talker XX | pass | 0 | [pcap]() |
| nmea_tcp_wf_unknown_type | TCP wire fault: unknown sentence type XYZ | pass | 0 | [pcap]() |
| nmea_udp_gll | UDP GLL datagram | pass | 1 | [pcap](nmea/nmea_udp_gll.pcap) |
| nmea_udp_gn_gga | UDP GN talker GGA datagram | pass | 1 | [pcap](nmea/nmea_udp_gn_gga.pcap) |
| nmea_udp_gsa | UDP GSA datagram | pass | 1 | [pcap](nmea/nmea_udp_gsa.pcap) |
| nmea_udp_gsv_three_seq | UDP GSV 3-message sequence | pass | 3 | [pcap](nmea/nmea_udp_gsv_three_seq.pcap) |
| nmea_udp_ipv4_gga | UDP single GGA datagram | pass | 1 | [pcap](nmea/nmea_udp_ipv4_gga.pcap) |
| nmea_udp_ipv4_gga_rmc | UDP GGA+RMC two datagrams | pass | 2 | [pcap](nmea/nmea_udp_ipv4_gga_rmc.pcap) |
| nmea_udp_ipv6_gga | UDP IPv6 single GGA datagram | pass | 1 | [pcap](nmea/nmea_udp_ipv6_gga.pcap) |
| nmea_udp_multicast_gga | UDP multicast GGA datagram | pass | 1 | [pcap](nmea/nmea_udp_multicast_gga.pcap) |
| nmea_udp_nondefault_port_gga | UDP nondefault port 4001 | pass | 1 | [pcap](nmea/nmea_udp_nondefault_port_gga.pcap) |
| nmea_udp_pack_gga_rmc | UDP GGA+RMC packed in single datagram | pass | 1 | [pcap](nmea/nmea_udp_pack_gga_rmc.pcap) |
| nmea_udp_proprietary_pgrme | UDP $PGRME proprietary datagram | pass | 1 | [pcap](nmea/nmea_udp_proprietary_pgrme.pcap) |
| nmea_udp_rmc_invalid_status | UDP RMC void status V | pass | 1 | [pcap](nmea/nmea_udp_rmc_invalid_status.pcap) |
| nmea_udp_rmc_void | UDP RMC status A datagram | pass | 1 | [pcap](nmea/nmea_udp_rmc_void.pcap) |
| nmea_udp_two_sessions_concurrent | UDP two concurrent sessions | pass | 2 | [pcap](nmea/nmea_udp_two_sessions_concurrent.pcap) |
| nmea_udp_vtg | UDP VTG datagram | pass | 1 | [pcap](nmea/nmea_udp_vtg.pcap) |
| nmea_udp_wf_udp_cross_datagram | UDP wire fault: multiple sentences in one datagram | pass | 0 | [pcap]() |
| nmea_udp_wf_udp_truncated | UDP wire fault: truncated datagram | pass | 0 | [pcap]() |
| nmea_udp_zda | UDP ZDA datagram | pass | 1 | [pcap](nmea/nmea_udp_zda.pcap) |

# hl7 Pcap Test Results

Cases: 95 — pass 95, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| hl7_ack_ar_reject | NAK AR reject: second negative ACK form | pass | 9 | [pcap](hl7/hl7_ack_ar_reject.pcap) |
| hl7_ack_code_domain | MSA-1 value domain AA/AE/AR | pass | 13 | [pcap](hl7/hl7_ack_code_domain.pcap) |
| hl7_ack_disabled | ack_mode=null: no ACK frame | pass | 8 | [pcap](hl7/hl7_ack_disabled.pcap) |
| hl7_ack_minimal_form | ACK minimal form: MSH+MSA only | pass | 9 | [pcap](hl7/hl7_ack_minimal_form.pcap) |
| hl7_ack_override_null | Event-level ack=null overrides session-level auto | pass | 12 | [pcap](hl7/hl7_ack_override_null.pcap) |
| hl7_ack_rule_new_ts | ACK MSH-7: new 14-digit UTC timestamp (nonzero) | pass | 9 | [pcap](hl7/hl7_ack_rule_new_ts.pcap) |
| hl7_ack_rule_separators | ACK derived MSH-1/MSH-2 identical to request | pass | 9 | [pcap](hl7/hl7_ack_rule_separators.pcap) |
| hl7_ack_rule_swap | ACK derived MSH-3/4 swaps with MSH-5/6 (4-slot diff) | pass | 9 | [pcap](hl7/hl7_ack_rule_swap.pcap) |
| hl7_ack_success_association | ACK AA association: MSA-2 = request MSH-10 | pass | 9 | [pcap](hl7/hl7_ack_success_association.pcap) |
| hl7_ack_trigger_oru | ACK trigger echo: ORU^R01 -> ACK^R01^ACK | pass | 9 | [pcap](hl7/hl7_ack_trigger_oru.pcap) |
| hl7_adt_a01_ipv4 | ADT^A01 baseline: MSH/EVN/PID/PV1 + auto ACK | pass | 9 | [pcap](hl7/hl7_adt_a01_ipv4.pcap) |
| hl7_adt_a02_transfer | ADT^A02 transfer: EVN-1=A02, PV1-3 update | pass | 9 | [pcap](hl7/hl7_adt_a02_transfer.pcap) |
| hl7_adt_a03_discharge | ADT^A03 discharge: EVN-1=A03, PV1-45/PV1-36 present | pass | 9 | [pcap](hl7/hl7_adt_a03_discharge.pcap) |
| hl7_boundary_msh10_msa2_len20 | MSH-10/MSA-2 20 chars upper-bound | pass | 9 | [pcap](hl7/hl7_boundary_msh10_msa2_len20.pcap) |
| hl7_boundary_msh12_len60 | MSH-12 60 chars upper-bound | pass | 9 | [pcap](hl7/hl7_boundary_msh12_len60.pcap) |
| hl7_boundary_msh7_ts_max | MSH-7 longest legal TS (24 chars) | pass | 9 | [pcap](hl7/hl7_boundary_msh7_ts_max.pcap) |
| hl7_boundary_msh9_len15 | MSH-9 15 chars upper-bound | pass | 9 | [pcap](hl7/hl7_boundary_msh9_len15.pcap) |
| hl7_component_subcomponent | Component ^ and subcomponent & (PID-5 XPN, OBR-2 EI) | pass | 9 | [pcap](hl7/hl7_component_subcomponent.pcap) |
| hl7_concurrent_sessions | Concurrent sessions: round-robin event replay | pass | 18 | [pcap](hl7/hl7_concurrent_sessions.pcap) |
| hl7_control_id_inc_strategy | control_id inc strategy: 1000/1001/1002 across messages | pass | 13 | [pcap](hl7/hl7_control_id_inc_strategy.pcap) |
| hl7_custom_encoding_chars | Custom encoding_chars '@~\!': MSH-2 slot + component join via declared ec[0] | pass | 9 | [pcap](hl7/hl7_custom_encoding_chars.pcap) |
| hl7_custom_field_separator | Custom field_separator '#' reflected in MSH-1 | pass | 9 | [pcap](hl7/hl7_custom_field_separator.pcap) |
| hl7_err_fields | ERR segment fields: position/code/severity/local | pass | 9 | [pcap](hl7/hl7_err_fields.pcap) |
| hl7_escape_e | Escape \E\: literal escape character | pass | 9 | [pcap](hl7/hl7_escape_e.pcap) |
| hl7_escape_f | Escape \F\: literal field separator | pass | 9 | [pcap](hl7/hl7_escape_f.pcap) |
| hl7_escape_h_n | Escape \H\ / \N\: highlight begin / resume paired | pass | 9 | [pcap](hl7/hl7_escape_h_n.pcap) |
| hl7_escape_hex | Escape \Xdd\: single hex byte | pass | 9 | [pcap](hl7/hl7_escape_hex.pcap) |
| hl7_escape_hex_multibyte | Escape \Xdddd\: multi-byte hex variant | pass | 9 | [pcap](hl7/hl7_escape_hex_multibyte.pcap) |
| hl7_escape_r | Escape \R\: literal repetition separator | pass | 9 | [pcap](hl7/hl7_escape_r.pcap) |
| hl7_escape_s | Escape \S\: literal component separator | pass | 9 | [pcap](hl7/hl7_escape_s.pcap) |
| hl7_escape_t | Escape \T\: literal subcomponent separator | pass | 9 | [pcap](hl7/hl7_escape_t.pcap) |
| hl7_evn2_time_format | EVN-2 14-digit timestamp (same as MSH-7) | pass | 9 | [pcap](hl7/hl7_evn2_time_format.pcap) |
| hl7_field_repetition | Field repetition ~: PID-3 multi-identifier | pass | 9 | [pcap](hl7/hl7_field_repetition.pcap) |
| hl7_ipv6_multi_transaction | IPv6 multi-transaction (2 events on one stream) | pass | 11 | [pcap](hl7/hl7_ipv6_multi_transaction.pcap) |
| hl7_ipv6_transport | IPv6/TCP/2575 baseline | pass | 9 | [pcap](hl7/hl7_ipv6_transport.pcap) |
| hl7_mllp_frame_bytes | MLLP frame: SOB 0x0B, EOB 0x1C 0x0D, segment CR=0x0D | pass | 9 | [pcap](hl7/hl7_mllp_frame_bytes.pcap) |
| hl7_mllp_multi_frame_burst | 3 MLLP frames burst in one TCP segment (all ack=null) | pass | 8 | [pcap](hl7/hl7_mllp_multi_frame_burst.pcap) |
| hl7_msa3_text | MSA-3 text message optional | pass | 9 | [pcap](hl7/hl7_msa3_text.pcap) |
| hl7_msh15_16_empty | MSH-15/16 empty: trailing empty slots trimmed | pass | 9 | [pcap](hl7/hl7_msh15_16_empty.pcap) |
| hl7_msh7_ts_format | MSH-7 timestamp: 14-digit UTC, fixed-width | pass | 9 | [pcap](hl7/hl7_msh7_ts_format.pcap) |
| hl7_msh8_empty_slot | Empty slot rendering: MSH-8/PID-2 empty, not collapsed | pass | 9 | [pcap](hl7/hl7_msh8_empty_slot.pcap) |
| hl7_msh8_populated | MSH-8 populated: non-empty security field | pass | 9 | [pcap](hl7/hl7_msh8_populated.pcap) |
| hl7_msh9_structure | MSH-9 three-component structure code^event^structure | pass | 9 | [pcap](hl7/hl7_msh9_structure.pcap) |
| hl7_msh_app_fac_fields | MSH-3..6 four slots present: app/fac sender/receiver | pass | 9 | [pcap](hl7/hl7_msh_app_fac_fields.pcap) |
| hl7_multi_session_isolation | Multi-session isolation: 2 sessions, control_id distinct | pass | 18 | [pcap](hl7/hl7_multi_session_isolation.pcap) |
| hl7_multi_transaction_long_connection | Multi-transaction long connection: 3 msg+ACK on one stream | pass | 13 | [pcap](hl7/hl7_multi_transaction_long_connection.pcap) |
| hl7_nak_error_segment | NAK AE + ERR segment: legal negative acknowledgement | pass | 9 | [pcap](hl7/hl7_nak_error_segment.pcap) |
| hl7_neg_ack_code_invalid | MSA-1 ack code not in {AA,AE,AR} (e.g. XX) | pass | 0 | [pcap]() |
| hl7_neg_ack_msa2_mismatch | Derived ACK MSA-2 != request MSH-10 | pass | 0 | [pcap]() |
| hl7_neg_ack_no_msa | ACK missing MSA segment | pass | 0 | [pcap]() |
| hl7_neg_ack_no_msh9 | ACK missing MSH-9=ACK | pass | 0 | [pcap]() |
| hl7_neg_address_family_mixed | Address family mixed: ipv6 layer with v4 literal | pass | 0 | [pcap]() |
| hl7_neg_carrier_no_tcp | Missing TCP layer: hl7 directly on ip | pass | 0 | [pcap]() |
| hl7_neg_carrier_udp | carrier udp: udp carrier layer (natural face — hl7 rides tcp only) | pass | 0 | [pcap]() |
| hl7_neg_escape_invalid | Escape: invalid \X hex (unpaired digits) | pass | 0 | [pcap]() |
| hl7_neg_event_mismatch | EVN-1 vs MSH-9 trigger event mismatch | pass | 0 | [pcap]() |
| hl7_neg_framing_control_byte | Framing: unescaped 0x1c in payload closes EOB early | pass | 0 | [pcap]() |
| hl7_neg_framing_eob_malformed | Framing EOB malformed: 0x1c without 0x0d | pass | 0 | [pcap]() |
| hl7_neg_framing_eob_missing | Framing EOB missing: truncated frame | pass | 0 | [pcap]() |
| hl7_neg_framing_sob_missing | Framing SOB missing: payload starts with MSH\| | pass | 0 | [pcap]() |
| hl7_neg_len_msa2 | MSA-2 >20 chars | pass | 0 | [pcap]() |
| hl7_neg_len_msh10 | MSH-10 >20 chars | pass | 0 | [pcap]() |
| hl7_neg_len_msh12 | MSH-12 >60 chars | pass | 0 | [pcap]() |
| hl7_neg_len_msh7 | MSH-7 >26 chars (textual upper bound) | pass | 0 | [pcap]() |
| hl7_neg_len_msh9 | MSH-9 >15 chars | pass | 0 | [pcap]() |
| hl7_neg_msh10_missing | MSH-10 missing | pass | 0 | [pcap]() |
| hl7_neg_msh11_missing | MSH-11 missing | pass | 0 | [pcap]() |
| hl7_neg_msh12_missing | MSH-12 missing | pass | 0 | [pcap]() |
| hl7_neg_msh1_invalid | MSH-1: missing or wrong length (!=1 char) | pass | 0 | [pcap]() |
| hl7_neg_msh2_invalid | MSH-2: encoding chars length !=4 | pass | 0 | [pcap]() |
| hl7_neg_msh9_domain | MSH-9 message code/trigger outside value domain | pass | 0 | [pcap]() |
| hl7_neg_msh9_missing | MSH-9 missing | pass | 0 | [pcap]() |
| hl7_neg_port_invalid | Invalid port (0 or 65536) | pass | 0 | [pcap]() |
| hl7_neg_required_segment_missing | ADT^A01 missing required business segment (PID) | pass | 0 | [pcap]() |
| hl7_neg_segment_after_eob | Segment: extra segment after EOB | pass | 0 | [pcap]() |
| hl7_neg_segment_first_not_msh | Segment: first segment is not MSH | pass | 0 | [pcap]() |
| hl7_neg_segment_name_invalid | Segment: invalid segment name (not 3 chars) | pass | 0 | [pcap]() |
| hl7_neg_segment_no_cr | Segment: missing trailing CR | pass | 0 | [pcap]() |
| hl7_neg_separator_mismatch | Separator: body delimiter differs from MSH-2 declaration | pass | 0 | [pcap]() |
| hl7_neg_z_segment_unconfigured | Z segment not explicitly allowed | pass | 0 | [pcap]() |
| hl7_obx_valuetype_ce | OBX-2=CE coded value type | pass | 9 | [pcap](hl7/hl7_obx_valuetype_ce.pcap) |
| hl7_oru_r01_results | ORU^R01: OBR + multiple OBX, ascending set IDs | pass | 9 | [pcap](hl7/hl7_oru_r01_results.pcap) |
| hl7_pid3_cx_components | PID-3 CX five-component: ID^^^HOSP^MR | pass | 9 | [pcap](hl7/hl7_pid3_cx_components.pcap) |
| hl7_port_nondefault | Non-default port 2675: planner must not silently rewrite | pass | 9 | [pcap](hl7/hl7_port_nondefault.pcap) |
| hl7_processing_id_d | MSH-11=D: Table 0103 Debugging value | pass | 9 | [pcap](hl7/hl7_processing_id_d.pcap) |
| hl7_pv1_class_emergency | PV1-2=E emergency class | pass | 9 | [pcap](hl7/hl7_pv1_class_emergency.pcap) |
| hl7_pv1_class_outpatient | PV1-2=O outpatient class | pass | 9 | [pcap](hl7/hl7_pv1_class_outpatient.pcap) |
| hl7_result_status_corrected | Result status C=Corrected: OBR-25=C, OBX-11=C | pass | 9 | [pcap](hl7/hl7_result_status_corrected.pcap) |
| hl7_result_status_pending | Result status P=Pending: OBR-25=P, OBX-11=P | pass | 9 | [pcap](hl7/hl7_result_status_pending.pcap) |
| hl7_s2c_receiver_role | s2c direction with role=receiver | pass | 9 | [pcap](hl7/hl7_s2c_receiver_role.pcap) |
| hl7_set_id_fields | Set ID fields: PID-1/PV1-1 = 1 | pass | 9 | [pcap](hl7/hl7_set_id_fields.pcap) |
| hl7_siu_s12_appointment | SIU^S12: SCH/AIS segments | pass | 9 | [pcap](hl7/hl7_siu_s12_appointment.pcap) |
| hl7_tcp_mss_reassembly | TCP MSS reassembly: mss=536, long ORU frame spans 2 segments (0B in first, 1C 0D in last — reassembly lands on tail segment) | pass | 12 | [pcap](hl7/hl7_tcp_mss_reassembly.pcap) |
| hl7_version_profiles | MSH-12 version values 2.5/2.8 + MSH-11 P/T | pass | 11 | [pcap](hl7/hl7_version_profiles.pcap) |
| hl7_z_segment_passthrough | Z segment passthrough with allow_z_segments flag | pass | 9 | [pcap](hl7/hl7_z_segment_passthrough.pcap) |

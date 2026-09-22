# megaco Pcap Test Results

Cases: 79 — pass 79, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| megaco_neg_carrier_entry_port_encoding | entry-name/port/encoding triple mismatch | pass | 0 | [pcap]() |
| megaco_neg_carrier_invalid_port | invalid port value | pass | 0 | [pcap]() |
| megaco_neg_carrier_layer_mismatch | carrier layer conflicts with chain shape | pass | 0 | [pcap]() |
| megaco_neg_carrier_return_address | response not returned to request source address | pass | 0 | [pcap]() |
| megaco_neg_carrier_udp_mtu_exceeded | UDP datagram over MTU | pass | 0 | [pcap]() |
| megaco_neg_command_first_error_continues | second command response after first error (no O-) | pass | 0 | [pcap]() |
| megaco_neg_command_modify_nonexistent | Modify/Subtract on nonexistent termination | pass | 0 | [pcap]() |
| megaco_neg_command_pre_registration | non-SC command before registration (505) | pass | 0 | [pcap]() |
| megaco_neg_command_reply_choose_all | reply action uses $/* context (request-side only) | pass | 0 | [pcap]() |
| megaco_neg_command_uncreated_context | references uncreated numeric Context | pass | 0 | [pcap]() |
| megaco_neg_encoding_port_mismatch | text encoding declared with BER port 2945 | pass | 0 | [pcap]() |
| megaco_neg_encoding_text_as_ber | encoding=ber declared while payload is text bytes | pass | 0 | [pcap]() |
| megaco_neg_length_context_reserved | reserved ContextID as concrete value | pass | 0 | [pcap]() |
| megaco_neg_length_digitmap_timer | DigitMap timer out of range (T>99 / S=0 / L=0) | pass | 0 | [pcap]() |
| megaco_neg_length_message_truncated | message truncated (unclosed body) | pass | 0 | [pcap]() |
| megaco_neg_length_termid_over_64 | TerminationID over 64 chars | pass | 0 | [pcap]() |
| megaco_neg_length_transid_over_uint32 | transactionId over UINT32 | pass | 0 | [pcap]() |
| megaco_neg_pairing_ack_unconfirmed | K acknowledges unconfirmed transaction | pass | 0 | [pcap]() |
| megaco_neg_pairing_duplicate_transid | duplicate transactionId in one session | pass | 0 | [pcap]() |
| megaco_neg_pairing_ia_without_pending | ImmAckRequired without prior Pending | pass | 0 | [pcap]() |
| megaco_neg_pairing_observed_requestid | ObservedEvents RequestID mismatch with Events | pass | 0 | [pcap]() |
| megaco_neg_pairing_pending_id_mismatch | Pending transactionId != request | pass | 0 | [pcap]() |
| megaco_neg_pairing_reply_id_mismatch | Reply transactionId != request | pass | 0 | [pcap]() |
| megaco_neg_services_address_mgcidtotry_conflict | ServiceChangeAddress and MgcIdToTry both set | pass | 0 | [pcap]() |
| megaco_neg_syntax_body_form | messageBody neither transactionList nor errorDescriptor | pass | 0 | [pcap]() |
| megaco_neg_syntax_mid_invalid | mId not one of the four legal forms | pass | 0 | [pcap]() |
| megaco_neg_syntax_mid_missing | mId missing (messageBody directly after start line) | pass | 0 | [pcap]() |
| megaco_neg_syntax_services_missing_params | Services missing required Method/Reason | pass | 0 | [pcap]() |
| megaco_neg_syntax_start_line | start line MegacopToken missing/misspelled | pass | 0 | [pcap]() |
| megaco_neg_syntax_version_three_digits | start line version 3 digits (1*2DIGIT overflow) | pass | 0 | [pcap]() |
| megaco_neg_syntax_version_zero | start line version 0 | pass | 0 | [pcap]() |
| megaco_neg_tx_error_on_request | transaction-level error descriptor on a request (reply-side only) | pass | 0 | [pcap]() |
| megaco_neg_tx_error_with_actions | reply carries both error descriptor and actions (ABNF exclusive) | pass | 0 | [pcap]() |
| megaco_tcp_ipv4_ack_range | K range form K{100-101} | pass | 11 | [pcap](megaco/megaco_tcp_ipv4_ack_range.pcap) |
| megaco_tcp_ipv4_dual_transaction | same-message dual transactions over TPKT | pass | 8 | [pcap](megaco/megaco_tcp_ipv4_dual_transaction.pcap) |
| megaco_tcp_ipv4_mss_reassembly | long TPKT PDU spans TCP segments (mss=536, 4 segments) | pass | 11 | [pcap](megaco/megaco_tcp_ipv4_mss_reassembly.pcap) |
| megaco_tcp_ipv4_pending_immack | T -> PN{} -> Reply(IA) -> K three-way handshake | pass | 11 | [pcap](megaco/megaco_tcp_ipv4_pending_immack.pcap) |
| megaco_tcp_ipv4_transaction_level_error | transaction-level errorDescriptor reply (Reply=id{Error=430}) | pass | 9 | [pcap](megaco/megaco_tcp_ipv4_transaction_level_error.pcap) |
| megaco_tcp_ipv6_call_flow | program->notify->reply multi-message dependency over TCP/IPv6 | pass | 11 | [pcap](megaco/megaco_tcp_ipv6_call_flow.pcap) |
| megaco_udp_2427_mgcp_alias | mgcp alias entry: default port 2427, same text wire format | pass | 1 | [pcap](megaco/megaco_udp_2427_mgcp_alias.pcap) |
| megaco_udp_ipv4_abbrev_tokens | abbrev token form: !/1 start line, T/C/SC/SV short tokens | pass | 1 | [pcap](megaco/megaco_udp_ipv4_abbrev_tokens.pcap) |
| megaco_udp_ipv4_audit_item_domain | Audit auditItem domain: Media/Signals/DigitMap/Statistics | pass | 1 | [pcap](megaco/megaco_udp_ipv4_audit_item_domain.pcap) |
| megaco_udp_ipv4_audit_wildcard | O-AuditValue(ROOT) + W-AuditCapability(*) in one message | pass | 1 | [pcap](megaco/megaco_udp_ipv4_audit_wildcard.pcap) |
| megaco_udp_ipv4_concurrent_sessions | concurrent sessions interleaved replay | pass | 4 | [pcap](megaco/megaco_udp_ipv4_concurrent_sessions.pcap) |
| megaco_udp_ipv4_context_id_high_boundary | ContextID 0xFFFFFFFD near upper bound | pass | 1 | [pcap](megaco/megaco_udp_ipv4_context_id_high_boundary.pcap) |
| megaco_udp_ipv4_digitmap_timer_max | DigitMap T timer exactly 99 (1-99 upper bound) | pass | 1 | [pcap](megaco/megaco_udp_ipv4_digitmap_timer_max.pcap) |
| megaco_udp_ipv4_digitmap_z_timer | DigitMap Z long-duration modifier | pass | 1 | [pcap](megaco/megaco_udp_ipv4_digitmap_z_timer.pcap) |
| megaco_udp_ipv4_embed_events | Events nested descriptor (Embed) | pass | 1 | [pcap](megaco/megaco_udp_ipv4_embed_events.pcap) |
| megaco_udp_ipv4_error_code_431 | error code 431: No TerminationID matched a wildcard | pass | 2 | [pcap](megaco/megaco_udp_ipv4_error_code_431.pcap) |
| megaco_udp_ipv4_error_code_442 | error code 442: Syntax error in command | pass | 2 | [pcap](megaco/megaco_udp_ipv4_error_code_442.pcap) |
| megaco_udp_ipv4_eventbuffer_descriptor | EventBuffer descriptor items | pass | 1 | [pcap](megaco/megaco_udp_ipv4_eventbuffer_descriptor.pcap) |
| megaco_udp_ipv4_events_no_requestid | Events without RequestID (ABNF optional) | pass | 1 | [pcap](megaco/megaco_udp_ipv4_events_no_requestid.pcap) |
| megaco_udp_ipv4_handoff | two-session handoff: SC HandOff+MgcIdToTry then re-registration | pass | 3 | [pcap](megaco/megaco_udp_ipv4_handoff.pcap) |
| megaco_udp_ipv4_large_digitmap | large DigitMap message in one UDP datagram | pass | 1 | [pcap](megaco/megaco_udp_ipv4_large_digitmap.pcap) |
| megaco_udp_ipv4_method_disconnected | SC Method=Disconnected (908 Disconnected) | pass | 1 | [pcap](megaco/megaco_udp_ipv4_method_disconnected.pcap) |
| megaco_udp_ipv4_method_forced | SC Method=Forced (905 Forced) | pass | 1 | [pcap](megaco/megaco_udp_ipv4_method_forced.pcap) |
| megaco_udp_ipv4_method_graceful | SC Method=Graceful (902 Scheduled Maintenance) | pass | 1 | [pcap](megaco/megaco_udp_ipv4_method_graceful.pcap) |
| megaco_udp_ipv4_mid_address_port | mId domainAddress with port [IP]:2944 | pass | 1 | [pcap](megaco/megaco_udp_ipv4_mid_address_port.pcap) |
| megaco_udp_ipv4_mid_devicename | mId deviceName (pathNAME) form | pass | 1 | [pcap](megaco/megaco_udp_ipv4_mid_devicename.pcap) |
| megaco_udp_ipv4_mode_inactive | LocalControl Mode=Inactive | pass | 1 | [pcap](megaco/megaco_udp_ipv4_mode_inactive.pcap) |
| megaco_udp_ipv4_mode_loopback | LocalControl Mode=Loopback | pass | 1 | [pcap](megaco/megaco_udp_ipv4_mode_loopback.pcap) |
| megaco_udp_ipv4_mode_sendonly | LocalControl Mode=SendOnly | pass | 1 | [pcap](megaco/megaco_udp_ipv4_mode_sendonly.pcap) |
| megaco_udp_ipv4_move_media | Move command + full Media descriptor | pass | 3 | [pcap](megaco/megaco_udp_ipv4_move_media.pcap) |
| megaco_udp_ipv4_multi_session | two sessions with independent 4-tuples and txid spaces | pass | 2 | [pcap](megaco/megaco_udp_ipv4_multi_session.pcap) |
| megaco_udp_ipv4_notify_events | Events(RequestID) programming -> Notify(ObservedEvents same rid) | pass | 4 | [pcap](megaco/megaco_udp_ipv4_notify_events.pcap) |
| megaco_udp_ipv4_registration | MG registration: SC(Restart,ROOT)+Services, Reply pairing | pass | 2 | [pcap](megaco/megaco_udp_ipv4_registration.pcap) |
| megaco_udp_ipv4_registration_redirect | redirect: Reply ServiceChangeMgcId then MG re-registers at new MGC | pass | 4 | [pcap](megaco/megaco_udp_ipv4_registration_redirect.pcap) |
| megaco_udp_ipv4_reserved_value_group | LocalControl ReservedValue/ReservedGroup ON/OFF | pass | 1 | [pcap](megaco/megaco_udp_ipv4_reserved_value_group.pcap) |
| megaco_udp_ipv4_services_delay_timestamp | Services Delay + TimeStamp parameters | pass | 1 | [pcap](megaco/megaco_udp_ipv4_services_delay_timestamp.pcap) |
| megaco_udp_ipv4_signals_types | Signals OO/TO/BR + SignalList | pass | 1 | [pcap](megaco/megaco_udp_ipv4_signals_types.pcap) |
| megaco_udp_ipv4_streamid_max | StreamID UINT16 upper bound 65535 | pass | 1 | [pcap](megaco/megaco_udp_ipv4_streamid_max.pcap) |
| megaco_udp_ipv4_termid_max_length | TerminationID exactly 64 chars (pathNAME upper bound) | pass | 1 | [pcap](megaco/megaco_udp_ipv4_termid_max_length.pcap) |
| megaco_udp_ipv4_termination_state | TerminationState: ServiceStates + EventBufferControl | pass | 1 | [pcap](megaco/megaco_udp_ipv4_termination_state.pcap) |
| megaco_udp_ipv4_transid_max | transactionId exactly 4294967295 (UINT32 upper bound) | pass | 1 | [pcap](megaco/megaco_udp_ipv4_transid_max.pcap) |
| megaco_udp_ipv4_transid_zero_error_reply | transactionId 0 error reply for missing-id request | pass | 2 | [pcap](megaco/megaco_udp_ipv4_transid_zero_error_reply.pcap) |
| megaco_udp_ipv4_version_negotiation | MG proposes Version=2, Reply wins with Version=1 | pass | 2 | [pcap](megaco/megaco_udp_ipv4_version_negotiation.pcap) |
| megaco_udp_ipv4_version_two_digits | start line Version 2-digit form (1*2 DIGIT carve-out) | pass | 1 | [pcap](megaco/megaco_udp_ipv4_version_two_digits.pcap) |
| megaco_udp_ipv4_whitespace_comment_variants | comment line + LWSP variants tolerated | pass | 1 | [pcap](megaco/megaco_udp_ipv4_whitespace_comment_variants.pcap) |
| megaco_udp_ipv6_failover | SC(Failover)+Reason 909 over IPv6 (offset 62) | pass | 2 | [pcap](megaco/megaco_udp_ipv6_failover.pcap) |

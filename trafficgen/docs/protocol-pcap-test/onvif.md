# onvif Pcap Test Results

Cases: 95 — pass 95, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| onvif_capabilities_category_analytics | CapabilityCategory=Analytics (200 path) | pass | 9 | [pcap](onvif/onvif_capabilities_category_analytics.pcap) |
| onvif_capabilities_category_device | CapabilityCategory=Device | pass | 9 | [pcap](onvif/onvif_capabilities_category_device.pcap) |
| onvif_capabilities_category_events | CapabilityCategory=Events | pass | 9 | [pcap](onvif/onvif_capabilities_category_events.pcap) |
| onvif_capabilities_category_imaging | CapabilityCategory=Imaging | pass | 9 | [pcap](onvif/onvif_capabilities_category_imaging.pcap) |
| onvif_capabilities_category_media | CapabilityCategory=Media | pass | 9 | [pcap](onvif/onvif_capabilities_category_media.pcap) |
| onvif_capabilities_category_ptz | CapabilityCategory=PTZ | pass | 9 | [pcap](onvif/onvif_capabilities_category_ptz.pcap) |
| onvif_capabilities_multi_category | Category 0..n: dual values | pass | 9 | [pcap](onvif/onvif_capabilities_multi_category.pcap) |
| onvif_concurrent_sessions | Concurrent sessions: 4-tuples distinct, transactions paired | pass | 18 | [pcap](onvif/onvif_concurrent_sessions.pcap) |
| onvif_date_time_daylight_timezone | SystemDateAndTime: DaylightSavings=true + TimeZone | pass | 9 | [pcap](onvif/onvif_date_time_daylight_timezone.pcap) |
| onvif_date_time_localtime | SystemDateAndTime: LocalDateTime present | pass | 9 | [pcap](onvif/onvif_date_time_localtime.pcap) |
| onvif_date_time_manual | DateTimeType=Manual | pass | 9 | [pcap](onvif/onvif_date_time_manual.pcap) |
| onvif_device_get_capabilities | GetCapabilities: Category=All + Capabilities/XAddr | pass | 9 | [pcap](onvif/onvif_device_get_capabilities.pcap) |
| onvif_device_get_device_information | GetDeviceInformation: 5 mandatory fields + UsernameToken | pass | 9 | [pcap](onvif/onvif_device_get_device_information.pcap) |
| onvif_device_get_network_interfaces | GetNetworkInterfaces: tds:NetworkInterfaces (token attr) + tt:Enabled | pass | 9 | [pcap](onvif/onvif_device_get_network_interfaces.pcap) |
| onvif_events_create_absolute_termination | Create with absolute dateTime TerminationTime | pass | 9 | [pcap](onvif/onvif_events_create_absolute_termination.pcap) |
| onvif_events_create_pullpoint_subscription | CreatePullPointSubscription: PT1M + SubscriptionReference | pass | 9 | [pcap](onvif/onvif_events_create_pullpoint_subscription.pcap) |
| onvif_events_create_to_pull_correlation | Create→Pull correlation (wsa:To ← same_as_response) | pass | 11 | [pcap](onvif/onvif_events_create_to_pull_correlation.pcap) |
| onvif_events_create_with_filter | Create with Filter (wsnt:TopicExpression) | pass | 9 | [pcap](onvif/onvif_events_create_with_filter.pcap) |
| onvif_events_pull_messages | PullMessages: Timeout/MessageLimit + NotificationMessage | pass | 9 | [pcap](onvif/onvif_events_pull_messages.pcap) |
| onvif_events_pull_messages_limit_1 | PullMessages MessageLimit=1 lower bound | pass | 9 | [pcap](onvif/onvif_events_pull_messages_limit_1.pcap) |
| onvif_events_pull_messages_limit_int_max | PullMessages MessageLimit=2147483647 (xs:int max) | pass | 9 | [pcap](onvif/onvif_events_pull_messages_limit_int_max.pcap) |
| onvif_events_pull_messages_timeout_zero | PullMessages timeout zero messages (legal) | pass | 9 | [pcap](onvif/onvif_events_pull_messages_timeout_zero.pcap) |
| onvif_events_pull_timeout_pt0s | PullMessages Timeout=PT0S (duration zero) | pass | 9 | [pcap](onvif/onvif_events_pull_timeout_pt0s.pcap) |
| onvif_fault_400_auth | Auth Fault: HTTP 400 + env:Sender/ter:NotAuthorized | pass | 9 | [pcap](onvif/onvif_fault_400_auth.pcap) |
| onvif_fault_500_no_such_service | 500 Fault: env:Receiver/ter:ActionNotSupported + nested ter:NoSuchService | pass | 9 | [pcap](onvif/onvif_fault_500_no_such_service.pcap) |
| onvif_fault_full_form | Fault full form: Node/Role/Detail | pass | 9 | [pcap](onvif/onvif_fault_full_form.pcap) |
| onvif_http_400_malformed_no_body | Table 5 400 Malformed: no envelope | pass | 9 | [pcap](onvif/onvif_http_400_malformed_no_body.pcap) |
| onvif_http_401_digest_challenge | 401 challenge → with creds retry → 200 (2 transactions) | pass | 11 | [pcap](onvif/onvif_http_401_digest_challenge.pcap) |
| onvif_http_405_method_not_allowed | Table 5 405: method not POST/GET | pass | 9 | [pcap](onvif/onvif_http_405_method_not_allowed.pcap) |
| onvif_http_415_unsupported_media | Table 5 415: unsupported media type | pass | 9 | [pcap](onvif/onvif_http_415_unsupported_media.pcap) |
| onvif_http_host_explicit | Host explicit domain | pass | 9 | [pcap](onvif/onvif_http_host_explicit.pcap) |
| onvif_http_keepalive_multi_transaction | Multi-transaction keep-alive (3 txs on one stream) | pass | 13 | [pcap](onvif/onvif_http_keepalive_multi_transaction.pcap) |
| onvif_ipv4_get_system_date_and_time | POST/IPv4 plaintext single-flow baseline (PRE_AUTH, envelope/headers full) | pass | 9 | [pcap](onvif/onvif_ipv4_get_system_date_and_time.pcap) |
| onvif_ipv6_media_get_profiles | IPv6 media GetProfiles | pass | 9 | [pcap](onvif/onvif_ipv6_media_get_profiles.pcap) |
| onvif_ipv6_transport | IPv6 transport baseline (offset 74) | pass | 9 | [pcap](onvif/onvif_ipv6_transport.pcap) |
| onvif_long_message_id | Long MessageID: full 36 chars urn:uuid: | pass | 9 | [pcap](onvif/onvif_long_message_id.pcap) |
| onvif_media_get_profiles | GetProfiles: trt:Profiles (token attr) + tt:VideoEncoder | pass | 9 | [pcap](onvif/onvif_media_get_profiles.pcap) |
| onvif_media_get_profiles_multi | GetProfiles 0..n: dual Profiles tokens distinct | pass | 9 | [pcap](onvif/onvif_media_get_profiles_multi.pcap) |
| onvif_media_get_snapshot_uri | GetSnapshotUri: ProfileToken → http MediaUri | pass | 9 | [pcap](onvif/onvif_media_get_snapshot_uri.pcap) |
| onvif_media_get_stream_uri | GetStreamUri: StreamSetup+ProfileToken (transactional) | pass | 11 | [pcap](onvif/onvif_media_get_stream_uri.pcap) |
| onvif_mss_large_capabilities | MSS large capabilities: response spans segments | pass | 10 | [pcap](onvif/onvif_mss_large_capabilities.pcap) |
| onvif_multi_session | Multi-session: 2 sessions, MessageID space independent | pass | 18 | [pcap](onvif/onvif_multi_session.pcap) |
| onvif_neg_action_mismatch | Action/operation mismatch | pass | 0 | [pcap]() |
| onvif_neg_action_suffix | Action already carries Response suffix | pass | 0 | [pcap]() |
| onvif_neg_addressing_action | wsa:Action missing | pass | 0 | [pcap]() |
| onvif_neg_addressing_message_id | wsa:MessageID missing | pass | 0 | [pcap]() |
| onvif_neg_addressing_ns | wsa namespace wrong | pass | 0 | [pcap]() |
| onvif_neg_addressing_relates | RelatesTo != MessageID | pass | 0 | [pcap]() |
| onvif_neg_auth_missing | READ_SYSTEM transaction missing auth | pass | 0 | [pcap]() |
| onvif_neg_carrier_layer | Layer chain missing http (tcp→onvif direct) | pass | 0 | [pcap]() |
| onvif_neg_carrier_port | Port/carrier conflict (HTTPS profile on port 80) | pass | 0 | [pcap]() |
| onvif_neg_carrier_wsdiscovery | WS-Discovery UDP 3702 as main chain (wire-fault flagged) | pass | 0 | [pcap]() |
| onvif_neg_charset_missing | charset missing | pass | 0 | [pcap]() |
| onvif_neg_charset_wrong | charset wrong (gbk) | pass | 0 | [pcap]() |
| onvif_neg_content_type | Content-Type text/xml | pass | 0 | [pcap]() |
| onvif_neg_fault_code | Fault missing s:Code | pass | 0 | [pcap]() |
| onvif_neg_fault_reason | Fault missing s:Reason | pass | 0 | [pcap]() |
| onvif_neg_fault_subcode | Subcode missing ter: prefix | pass | 0 | [pcap]() |
| onvif_neg_fault_value | Code/Value outside SOAP 1.2 set | pass | 0 | [pcap]() |
| onvif_neg_length_content_length | Content-Length != rendered body bytes | pass | 0 | [pcap]() |
| onvif_neg_length_truncation | Envelope byte count mismatch (truncation) | pass | 0 | [pcap]() |
| onvif_neg_message_limit_range | MessageLimit 2147483648 (xs:int+1 overflow) | pass | 0 | [pcap]() |
| onvif_neg_operation_ns | Service/operation namespace mismatch | pass | 0 | [pcap]() |
| onvif_neg_operation_unknown | Unknown operation | pass | 0 | [pcap]() |
| onvif_neg_parameter_duration | Timeout not xs:duration form | pass | 0 | [pcap]() |
| onvif_neg_parameter_message_limit | PullMessages missing MessageLimit | pass | 0 | [pcap]() |
| onvif_neg_parameter_profile_token | GetStreamUri missing ProfileToken | pass | 0 | [pcap]() |
| onvif_neg_parameter_stream_setup | GetStreamUri missing StreamSetup | pass | 0 | [pcap]() |
| onvif_neg_parameter_timeout | PullMessages missing Timeout | pass | 0 | [pcap]() |
| onvif_neg_service_unknown | Service not in four | pass | 0 | [pcap]() |
| onvif_neg_soap_body_missing | s:Body missing | pass | 0 | [pcap]() |
| onvif_neg_soap_envelope_ns | SOAP 1.1 envelope namespace | pass | 0 | [pcap]() |
| onvif_neg_soap_header_order | s:Header after s:Body | pass | 0 | [pcap]() |
| onvif_neg_soap_truncated | XML truncated | pass | 0 | [pcap]() |
| onvif_neg_subscription_cross_session | Subscription reference cross-session | pass | 0 | [pcap]() |
| onvif_neg_subscription_source | PullMessages wsa:To → non-Create event | pass | 0 | [pcap]() |
| onvif_neg_token_created | UsernameToken missing Created | pass | 0 | [pcap]() |
| onvif_neg_token_nonce | UsernameToken missing Nonce | pass | 0 | [pcap]() |
| onvif_neg_token_range | ProfileToken 65 chars (>maxLength 64) | pass | 0 | [pcap]() |
| onvif_neg_wsnt_ns | wsnt namespace URI wrong | pass | 0 | [pcap]() |
| onvif_network_interfaces_multi | NetworkInterfaces 1..n: dual interfaces tokens distinct | pass | 9 | [pcap](onvif/onvif_network_interfaces_multi.pcap) |
| onvif_port_nondefault | Non-default port 8080 | pass | 9 | [pcap](onvif/onvif_port_nondefault.pcap) |
| onvif_ptz_continuous_move | ContinuousMove: ProfileToken + Velocity (tt:PTZSpeed) | pass | 9 | [pcap](onvif/onvif_ptz_continuous_move.pcap) |
| onvif_ptz_continuous_move_timeout | ContinuousMove with Timeout (xs:duration) | pass | 9 | [pcap](onvif/onvif_ptz_continuous_move_timeout.pcap) |
| onvif_ptz_move_stop_sequence | PTZ Move→Stop: 2 transactions, MessageID distinct | pass | 11 | [pcap](onvif/onvif_ptz_move_stop_sequence.pcap) |
| onvif_ptz_stop_flags | Stop with PanTilt+Zoom full form | pass | 9 | [pcap](onvif/onvif_ptz_stop_flags.pcap) |
| onvif_ptz_stop_no_flags | Stop: PanTilt/Zoom omitted (legal optional) | pass | 9 | [pcap](onvif/onvif_ptz_stop_no_flags.pcap) |
| onvif_single_transaction_connection_close | Single transaction: Connection close (D-12) | pass | 9 | [pcap](onvif/onvif_single_transaction_connection_close.pcap) |
| onvif_soap12_envelope_structure | envelope encoding rules full family | pass | 9 | [pcap](onvif/onvif_soap12_envelope_structure.pcap) |
| onvif_soap12_prefix_variant | envelope namespace URI persisted (prefix is implementation-defined) | pass | 9 | [pcap](onvif/onvif_soap12_prefix_variant.pcap) |
| onvif_token_len_63 | ProfileToken 63 chars (maxLength-1) | pass | 9 | [pcap](onvif/onvif_token_len_63.pcap) |
| onvif_token_len_64 | ProfileToken 64 chars (maxLength full) | pass | 9 | [pcap](onvif/onvif_token_len_64.pcap) |
| onvif_usernametoken_created_namespace | Created utility ns URI explicit | pass | 9 | [pcap](onvif/onvif_usernametoken_created_namespace.pcap) |
| onvif_ws_addressing_correlation | wsa:Action/MessageID/RelatesTo per-pair | pass | 9 | [pcap](onvif/onvif_ws_addressing_correlation.pcap) |
| onvif_ws_security_usernametoken | UsernameToken: secext ns/4 elements/nonce+created | pass | 9 | [pcap](onvif/onvif_ws_security_usernametoken.pcap) |

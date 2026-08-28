# pcep Pcap Test Results

Cases: 24 — pass 22, fail 1, error 1

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| pcep_common_header_length | Common header version type length | pass | 11 | [pcap](pcep/pcep_common_header_length.pcap) |
| pcep_delegation_rfc8281_profile | RFC 8281 delegation flags | pass | 12 | [pcap](pcep/pcep_delegation_rfc8281_profile.pcap) |
| pcep_ipv6_address_family | IPv6 endpoint and ERO | pass | 11 | [pcap](pcep/pcep_ipv6_address_family.pcap) |
| pcep_keepalive_direction | Explicit Keepalive direction | pass | 13 | [pcap](pcep/pcep_keepalive_direction.pcap) |
| pcep_lsp_object_flags | Stateful LSP and SRP flags | pass | 11 | [pcap](pcep/pcep_lsp_object_flags.pcap) |
| pcep_metric_flags | Metric Cost and Bound flags | pass | 11 | [pcap](pcep/pcep_metric_flags.pcap) |
| pcep_multi_request | Multiple request and response IDs | pass | 14 | [pcap](pcep/pcep_multi_request.pcap) |
| pcep_multi_session | Two independent TCP sessions | error | 0 | `` |
| pcep_neg_address_family | Mixed IPv4 IPv6 objects | pass | 0 | [pcap]() |
| pcep_neg_keepalive | Keepalive with object | pass | 0 | [pcap]() |
| pcep_neg_malformed_length | Malformed message length | pass | 0 | [pcap]() |
| pcep_neg_object_length | Malformed object length | pass | 0 | [pcap]() |
| pcep_neg_session_id | Session ID drift | fail | 0 | `` |
| pcep_neg_stateful_without_profile | Stateful object in base profile | pass | 0 | [pcap]() |
| pcep_neg_unknown_type | Unknown message type | pass | 0 | [pcap]() |
| pcep_object_flags | P/I and LSPA flags | pass | 10 | [pcap](pcep/pcep_object_flags.pcap) |
| pcep_open_bidirectional | Bidirectional Open and Keepalive | pass | 11 | [pcap](pcep/pcep_open_bidirectional.pcap) |
| pcep_open_keepalive | Open then explicit Keepalive | pass | 10 | [pcap](pcep/pcep_open_keepalive.pcap) |
| pcep_pcntf_and_pcerr | Notification and Error messages | pass | 13 | [pcap](pcep/pcep_pcntf_and_pcerr.pcap) |
| pcep_pcrep_ipv4_ero_rro | IPv4 PCRep RRO Metric | pass | 11 | [pcap](pcep/pcep_pcrep_ipv4_ero_rro.pcap) |
| pcep_pcreq_ipv4_ero_metric | IPv4 PCReq ERO Metric | pass | 11 | [pcap](pcep/pcep_pcreq_ipv4_ero_metric.pcap) |
| pcep_rro_ipv4_ipv6 | IPv4 RRO address and L flag | pass | 11 | [pcap](pcep/pcep_rro_ipv4_ipv6.pcap) |
| pcep_stateful_rfc8231_profile | RFC 8231 stateful capability | pass | 10 | [pcap](pcep/pcep_stateful_rfc8231_profile.pcap) |
| pcep_tcp_direction | TCP direction across 4189 | pass | 12 | [pcap](pcep/pcep_tcp_direction.pcap) |

## Failures

### pcep_multi_session — Two independent TCP sessions

task ended failed: output error: [c34f142b-66cc-4f9c-864d-6a286f2d0728-65b6a04b-ee7b-42c2-b8d2-ca5275bcff36: validation failed: pcep: config is required]

### pcep_neg_session_id — Session ID drift

expected task to be rejected but it completed


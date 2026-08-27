# pcep Pcap Test Results

Cases: 24 — pass 0, fail 7, error 17

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| pcep_common_header_length | Common header version type length | error | 0 | `` |
| pcep_delegation_rfc8281_profile | RFC 8281 delegation flags | error | 0 | `` |
| pcep_ipv6_address_family | IPv6 endpoint and ERO | error | 0 | `` |
| pcep_keepalive_direction | Explicit Keepalive direction | error | 0 | `` |
| pcep_lsp_object_flags | Stateful LSP and SRP flags | error | 0 | `` |
| pcep_metric_flags | Metric Cost and Bound flags | error | 0 | `` |
| pcep_multi_request | Multiple request and response IDs | error | 0 | `` |
| pcep_multi_session | Two independent TCP sessions | error | 0 | `` |
| pcep_neg_address_family | Mixed IPv4 IPv6 objects | fail | 0 | `` |
| pcep_neg_keepalive | Keepalive with object | fail | 0 | `` |
| pcep_neg_malformed_length | Malformed message length | fail | 0 | `` |
| pcep_neg_object_length | Malformed object length | fail | 0 | `` |
| pcep_neg_session_id | Session ID drift | fail | 0 | `` |
| pcep_neg_stateful_without_profile | Stateful object in base profile | fail | 0 | `` |
| pcep_neg_unknown_type | Unknown message type | fail | 0 | `` |
| pcep_object_flags | P/I and LSPA flags | error | 0 | `` |
| pcep_open_bidirectional | Bidirectional Open and Keepalive | error | 0 | `` |
| pcep_open_keepalive | Open then explicit Keepalive | error | 0 | `` |
| pcep_pcntf_and_pcerr | Notification and Error messages | error | 0 | `` |
| pcep_pcrep_ipv4_ero_rro | IPv4 PCRep RRO Metric | error | 0 | `` |
| pcep_pcreq_ipv4_ero_metric | IPv4 PCReq ERO Metric | error | 0 | `` |
| pcep_rro_ipv4_ipv6 | IPv4 RRO address and L flag | error | 0 | `` |
| pcep_stateful_rfc8231_profile | RFC 8231 stateful capability | error | 0 | `` |
| pcep_tcp_direction | TCP direction across 4189 | error | 0 | `` |

## Failures

### pcep_common_header_length — Common header version type length

generate: invalid or missing protocol: pcep

### pcep_delegation_rfc8281_profile — RFC 8281 delegation flags

generate: invalid or missing protocol: pcep

### pcep_ipv6_address_family — IPv6 endpoint and ERO

generate: invalid or missing protocol: pcep

### pcep_keepalive_direction — Explicit Keepalive direction

generate: invalid or missing protocol: pcep

### pcep_lsp_object_flags — Stateful LSP and SRP flags

generate: invalid or missing protocol: pcep

### pcep_metric_flags — Metric Cost and Bound flags

generate: invalid or missing protocol: pcep

### pcep_multi_request — Multiple request and response IDs

generate: invalid or missing protocol: pcep

### pcep_multi_session — Two independent TCP sessions

generate: invalid or missing protocol: pcep

### pcep_neg_address_family — Mixed IPv4 IPv6 objects

rejected but error "invalid or missing protocol: pcep" does not contain "address"

### pcep_neg_keepalive — Keepalive with object

rejected but error "invalid or missing protocol: pcep" does not contain "keepalive"

### pcep_neg_malformed_length — Malformed message length

rejected but error "invalid or missing protocol: pcep" does not contain "length"

### pcep_neg_object_length — Malformed object length

rejected but error "invalid or missing protocol: pcep" does not contain "object"

### pcep_neg_session_id — Session ID drift

rejected but error "invalid or missing protocol: pcep" does not contain "session"

### pcep_neg_stateful_without_profile — Stateful object in base profile

rejected but error "invalid or missing protocol: pcep" does not contain "stateful"

### pcep_neg_unknown_type — Unknown message type

rejected but error "invalid or missing protocol: pcep" does not contain "type"

### pcep_object_flags — P/I and LSPA flags

generate: invalid or missing protocol: pcep

### pcep_open_bidirectional — Bidirectional Open and Keepalive

generate: invalid or missing protocol: pcep

### pcep_open_keepalive — Open then explicit Keepalive

generate: invalid or missing protocol: pcep

### pcep_pcntf_and_pcerr — Notification and Error messages

generate: invalid or missing protocol: pcep

### pcep_pcrep_ipv4_ero_rro — IPv4 PCRep RRO Metric

generate: invalid or missing protocol: pcep

### pcep_pcreq_ipv4_ero_metric — IPv4 PCReq ERO Metric

generate: invalid or missing protocol: pcep

### pcep_rro_ipv4_ipv6 — IPv4 RRO address and L flag

generate: invalid or missing protocol: pcep

### pcep_stateful_rfc8231_profile — RFC 8231 stateful capability

generate: invalid or missing protocol: pcep

### pcep_tcp_direction — TCP direction across 4189

generate: invalid or missing protocol: pcep


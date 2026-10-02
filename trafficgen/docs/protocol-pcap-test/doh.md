# doh Pcap Test Results

Cases: 110 — pass 110, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| doh_b64_residue_1 | base64url residue-1 form: 19B wire -> 26-char param | pass | 9 | [pcap](doh/doh_b64_residue_1.pcap) |
| doh_b64_residue_2 | base64url residue-2 form: 20B wire -> 27-char param | pass | 9 | [pcap](doh/doh_b64_residue_2.pcap) |
| doh_concurrent_sessions | Two concurrent sessions interleaved, no state bleed | pass | 18 | [pcap](doh/doh_concurrent_sessions.pcap) |
| doh_dns_aa_set | Response AA=1 (authoritative answer), flags 85 80 | pass | 9 | [pcap](doh/doh_dns_aa_set.pcap) |
| doh_dns_answer_aaaa | AAAA answer (RDLENGTH=16) | pass | 9 | [pcap](doh/doh_dns_answer_aaaa.pcap) |
| doh_dns_answer_cname_chain | CNAME -> A two-answer chain | pass | 9 | [pcap](doh/doh_dns_answer_cname_chain.pcap) |
| doh_dns_answer_multi_types | A + AAAA answers in configured order | pass | 9 | [pcap](doh/doh_dns_answer_multi_types.pcap) |
| doh_dns_answer_svcb_alias | HTTPS SVCB AliasForm (priority 0 + svc.example.net + empty params, RDLENGTH 19) | pass | 9 | [pcap](doh/doh_dns_answer_svcb_alias.pcap) |
| doh_dns_answer_svcb_alpn | HTTPS SVCB AnswerForm (priority + root target + alpn h2) | pass | 9 | [pcap](doh/doh_dns_answer_svcb_alpn.pcap) |
| doh_dns_answer_ttl | A answer NAME/TYPE/CLASS/TTL/RDLENGTH/RDATA structure | pass | 9 | [pcap](doh/doh_dns_answer_ttl.pcap) |
| doh_dns_answer_txt_strings | TXT multi character-strings (per-segment length byte) | pass | 9 | [pcap](doh/doh_dns_answer_txt_strings.pcap) |
| doh_dns_header_query | DNS header 12B big-endian field-by-field | pass | 9 | [pcap](doh/doh_dns_header_query.pcap) |
| doh_dns_id_65534 | DNS ID=65534 adjacent value (max-1) | pass | 9 | [pcap](doh/doh_dns_id_65534.pcap) |
| doh_dns_id_max | DNS ID=65535 full value | pass | 9 | [pcap](doh/doh_dns_id_max.pcap) |
| doh_dns_id_one | DNS ID=1 adjacent value (min+1) | pass | 9 | [pcap](doh/doh_dns_id_one.pcap) |
| doh_dns_id_zero | DNS ID=0 boundary (RFC 8484 4.1 SHOULD value; declared deviation) | pass | 9 | [pcap](doh/doh_dns_id_zero.pcap) |
| doh_dns_negative_cache_soa | Negative cache: ANCOUNT=0 + NSCOUNT=1 + SOA + max-age=MINIMUM | pass | 9 | [pcap](doh/doh_dns_negative_cache_soa.pcap) |
| doh_dns_qclass_ch | QCLASS=CHAOS(3) value variant, echoed in answer | pass | 9 | [pcap](doh/doh_dns_qclass_ch.pcap) |
| doh_dns_qname_254 | Full-name 254 adjacent value (CL=270) | pass | 9 | [pcap](doh/doh_dns_qname_254.pcap) |
| doh_dns_qname_label_62 | Single label 62 adjacent value (CL=80) | pass | 9 | [pcap](doh/doh_dns_qname_label_62.pcap) |
| doh_dns_qname_label_63 | Single 63-byte label upper bound (wire 81, CL=81) | pass | 9 | [pcap](doh/doh_dns_qname_label_63.pcap) |
| doh_dns_qname_total_255 | Full-name 255-byte upper bound (63/63/63/61 labels, CL=271) | pass | 9 | [pcap](doh/doh_dns_qname_total_255.pcap) |
| doh_dns_question_a | QNAME label encoding, QTYPE=A(1), QCLASS=IN(1) | pass | 9 | [pcap](doh/doh_dns_question_a.pcap) |
| doh_dns_question_aaaa | QTYPE=AAAA(28) query with AAAA answer | pass | 9 | [pcap](doh/doh_dns_question_aaaa.pcap) |
| doh_dns_question_https | QTYPE=HTTPS(65) query (RFC 9460) | pass | 9 | [pcap](doh/doh_dns_question_https.pcap) |
| doh_dns_question_mx | QTYPE=MX(15) query; MX answer pref 2B big-endian + exchange | pass | 9 | [pcap](doh/doh_dns_question_mx.pcap) |
| doh_dns_question_root | Root QNAME shortest message (wire 17B) | pass | 9 | [pcap](doh/doh_dns_question_root.pcap) |
| doh_dns_question_txt | QTYPE=TXT(16) query with single-string TXT answer | pass | 9 | [pcap](doh/doh_dns_question_txt.pcap) |
| doh_dns_ra_zero | Response RA=0 (no recursion available) | pass | 9 | [pcap](doh/doh_dns_ra_zero.pcap) |
| doh_dns_rcode_15_upper | RCODE=15 (4-bit value upper bound) | pass | 9 | [pcap](doh/doh_dns_rcode_15_upper.pcap) |
| doh_dns_rcode_formerr | RCODE=1 FORMERR carried by 200 | pass | 9 | [pcap](doh/doh_dns_rcode_formerr.pcap) |
| doh_dns_rcode_notimp | RCODE=4 NOTIMP | pass | 9 | [pcap](doh/doh_dns_rcode_notimp.pcap) |
| doh_dns_rcode_refused | RCODE=5 REFUSED | pass | 9 | [pcap](doh/doh_dns_rcode_refused.pcap) |
| doh_dns_rd_zero | Request RD=0 (recursion not desired) | pass | 9 | [pcap](doh/doh_dns_rd_zero.pcap) |
| doh_dns_response_noerror | RCODE=0, QR=1, RA=1, ID echo | pass | 9 | [pcap](doh/doh_dns_response_noerror.pcap) |
| doh_dns_response_nxdomain | RCODE=3 NXDOMAIN with HTTP 200 (HTTP success != DNS success) | pass | 9 | [pcap](doh/doh_dns_response_nxdomain.pcap) |
| doh_dns_response_servfail | RCODE=2 SERVFAIL with HTTP 200 | pass | 9 | [pcap](doh/doh_dns_response_servfail.pcap) |
| doh_dns_ttl_4294967294 | TTL=4294967294 adjacent value | pass | 9 | [pcap](doh/doh_dns_ttl_4294967294.pcap) |
| doh_dns_ttl_max | TTL=0xFFFFFFFF full value + max-age=4294967295 | pass | 9 | [pcap](doh/doh_dns_ttl_max.pcap) |
| doh_dns_ttl_one | TTL=1 adjacent value + max-age=1 | pass | 9 | [pcap](doh/doh_dns_ttl_one.pcap) |
| doh_dns_ttl_zero | TTL=0 boundary + max-age=0 | pass | 9 | [pcap](doh/doh_dns_ttl_zero.pcap) |
| doh_get_aa_set | AA=1 GET variant | pass | 9 | [pcap](doh/doh_get_aa_set.pcap) |
| doh_get_answer_aaaa | AAAA answer GET variant (RDLENGTH 00 10) | pass | 9 | [pcap](doh/doh_get_answer_aaaa.pcap) |
| doh_get_answer_cname_chain | CNAME -> A chain GET variant | pass | 9 | [pcap](doh/doh_get_answer_cname_chain.pcap) |
| doh_get_answer_svcb_alpn | SVCB AnswerForm GET variant | pass | 9 | [pcap](doh/doh_get_answer_svcb_alpn.pcap) |
| doh_get_answer_ttl | A answer structure GET variant (RDLENGTH/RDATA frames) | pass | 9 | [pcap](doh/doh_get_answer_ttl.pcap) |
| doh_get_ipv4_base64url | GET dns parameter base64url unpadded (no body, CL:0) | pass | 9 | [pcap](doh/doh_get_ipv4_base64url.pcap) |
| doh_get_ipv6_base64url | GET/IPv6 isolated fixture (2001:db8::66 -> 2001:db8::100:66) | pass | 9 | [pcap](doh/doh_get_ipv6_base64url.pcap) |
| doh_get_negative_cache_soa | SOA negative cache GET variant | pass | 9 | [pcap](doh/doh_get_negative_cache_soa.pcap) |
| doh_get_port_nondefault | Non-default port 8080 GET variant | pass | 9 | [pcap](doh/doh_get_port_nondefault.pcap) |
| doh_get_qname_max | 255-name GET variant: 271B wire (residue 1) unpadded 362-char param | pass | 9 | [pcap](doh/doh_get_qname_max.pcap) |
| doh_get_question_aaaa | QTYPE=AAAA(28) GET variant | pass | 9 | [pcap](doh/doh_get_question_aaaa.pcap) |
| doh_get_question_https | QTYPE=HTTPS(65) GET variant | pass | 9 | [pcap](doh/doh_get_question_https.pcap) |
| doh_get_question_mx | QTYPE=MX(15) GET variant | pass | 9 | [pcap](doh/doh_get_question_mx.pcap) |
| doh_get_question_txt | QTYPE=TXT(16) GET variant | pass | 9 | [pcap](doh/doh_get_question_txt.pcap) |
| doh_get_rcode_15 | RCODE=15 GET variant (4-bit upper bound) | pass | 9 | [pcap](doh/doh_get_rcode_15.pcap) |
| doh_get_rcode_formerr | RCODE=1 GET variant (2xx carries any RCODE) | pass | 9 | [pcap](doh/doh_get_rcode_formerr.pcap) |
| doh_get_rcode_notimp | RCODE=4 GET variant | pass | 9 | [pcap](doh/doh_get_rcode_notimp.pcap) |
| doh_get_rcode_refused | RCODE=5 GET variant | pass | 9 | [pcap](doh/doh_get_rcode_refused.pcap) |
| doh_get_rd_zero | RD=0 GET variant (pinned 44-char param, flags 00 00) | pass | 9 | [pcap](doh/doh_get_rd_zero.pcap) |
| doh_get_response_noerror | NOERROR + A answer GET variant | pass | 9 | [pcap](doh/doh_get_response_noerror.pcap) |
| doh_get_response_nxdomain | NXDOMAIN GET variant | pass | 9 | [pcap](doh/doh_get_response_nxdomain.pcap) |
| doh_get_response_servfail | SERVFAIL GET variant | pass | 9 | [pcap](doh/doh_get_response_servfail.pcap) |
| doh_get_root_query | Root-name GET variant: 17B wire (residue 2) 23-char param | pass | 9 | [pcap](doh/doh_get_root_query.pcap) |
| doh_http_accept_absent | Request without Accept header (SHOULD-absent legal form) | pass | 9 | [pcap](doh/doh_http_accept_absent.pcap) |
| doh_http_cache_age_header | Age header present (RFC 8484 5.1 client consideration) | pass | 9 | [pcap](doh/doh_http_cache_age_header.pcap) |
| doh_http_cache_control | max-age equals the MINIMUM answer TTL (300/60 -> 60) | pass | 9 | [pcap](doh/doh_http_cache_control.pcap) |
| doh_http_cache_control_soa_minimum | Negative-cache max-age exactly equals SOA MINIMUM | pass | 9 | [pcap](doh/doh_http_cache_control_soa_minimum.pcap) |
| doh_http_connection_close | Single transaction explicit Connection: close | pass | 9 | [pcap](doh/doh_http_connection_close.pcap) |
| doh_http_content_length_exact | Content-Length exact 33 (request) / 64 (response) | pass | 9 | [pcap](doh/doh_http_content_length_exact.pcap) |
| doh_http_error_400 | GET missing dns parameter -> 400 empty body, no DNS wire | pass | 9 | [pcap](doh/doh_http_error_400.pcap) |
| doh_http_error_400_extra_param | GET dns + extra query parameter -> 400 (dns is the only parameter) | pass | 9 | [pcap](doh/doh_http_error_400_extra_param.pcap) |
| doh_http_error_404 | Unknown URI -> 404 empty body, no DNS wire | pass | 9 | [pcap](doh/doh_http_error_404.pcap) |
| doh_http_error_415 | Unsupported media type -> 415 empty body, no DNS wire | pass | 9 | [pcap](doh/doh_http_error_415.pcap) |
| doh_http_host_explicit | Explicit Host header (doh.example.com, not dst_ip default) | pass | 9 | [pcap](doh/doh_http_host_explicit.pcap) |
| doh_http_keepalive_multi_transaction | 3 transactions on one connection, per-request keep-alive policy | pass | 13 | [pcap](doh/doh_http_keepalive_multi_transaction.pcap) |
| doh_http_mixed_get_post | POST -> GET mixed on one connection; Content-Type only on POST | pass | 11 | [pcap](doh/doh_http_mixed_get_post.pcap) |
| doh_min_frame_get | Minimal GET: root name 17B wire -> 23-char param | pass | 9 | [pcap](doh/doh_min_frame_get.pcap) |
| doh_mss_large_response | Large response spans MSS segments (3 TXT x 2x255 strings, 1650B wire) | pass | 10 | [pcap](doh/doh_mss_large_response.pcap) |
| doh_multi_session | Two sessions sequential, dual 4-tuples, isolated state | pass | 18 | [pcap](doh/doh_multi_session.pcap) |
| doh_neg_ancount_mismatch | ANCOUNT does not equal the declared answer count | pass | 0 | [pcap]() |
| doh_neg_base64_invalid | base64url containing illegal characters (+//) | pass | 0 | [pcap]() |
| doh_neg_base64_padding | base64url carrying = padding | pass | 0 | [pcap]() |
| doh_neg_base64_truncated | base64url decoding to fewer than 12 bytes | pass | 0 | [pcap]() |
| doh_neg_content_length | POST Content-Length does not equal the DNS body bytes | pass | 0 | [pcap]() |
| doh_neg_content_type | Content-Type is not application/dns-message | pass | 0 | [pcap]() |
| doh_neg_dns_header_short | POST body shorter than the 12-byte DNS header | pass | 0 | [pcap]() |
| doh_neg_dns_id_range | dns_id declared 65536 (16-bit bound +1) | pass | 0 | [pcap]() |
| doh_neg_dns_qdcount_zero | QDCOUNT=0 rejected (question section required) | pass | 0 | [pcap]() |
| doh_neg_dns_qname_overflow | QNAME label exceeds 63 bytes | pass | 0 | [pcap]() |
| doh_neg_dns_question_truncated | Question missing root terminator / QTYPE truncated | pass | 0 | [pcap]() |
| doh_neg_get_content_type | GET transaction declares a Content-Type header (no body carrier) | pass | 0 | [pcap]() |
| doh_neg_layer_chain_missing_http | Layer chain missing the http carrier (tcp->doh direct) | pass | 0 | [pcap]() |
| doh_neg_method | HTTP method is not GET or POST | pass | 0 | [pcap]() |
| doh_neg_opcode_nonzero | Opcode != 0 (QUERY only in this version) | pass | 0 | [pcap]() |
| doh_neg_port_conflict | Port/carrier declaration conflicts with the plaintext profile (443) | pass | 0 | [pcap]() |
| doh_neg_qdcount_multi | QDCOUNT>1 (this version carries exactly one question) | pass | 0 | [pcap]() |
| doh_neg_qtype_token | qtype is a non-numeric unknown token (BOGUS) | pass | 0 | [pcap]() |
| doh_neg_query_missing | GET config missing the dns query parameter | pass | 0 | [pcap]() |
| doh_neg_rdlength_mismatch | Answer RDLENGTH does not equal the RDATA byte count | pass | 0 | [pcap]() |
| doh_neg_response_id | Response DNS ID differs from the request ID | pass | 0 | [pcap]() |
| doh_neg_response_qr | Response event declares QR=0 (responses must set QR=1) | pass | 0 | [pcap]() |
| doh_neg_response_question | Response Question mismatched / 2xx without DNS body | pass | 0 | [pcap]() |
| doh_neg_ttl_range | TTL declared 4294967296 (2^32 bound +1) | pass | 0 | [pcap]() |
| doh_neg_wire_over_max | Declared DNS wire total length exceeds 65535 | pass | 0 | [pcap]() |
| doh_neg_z_nonzero | Reserved Z bits non-zero | pass | 0 | [pcap]() |
| doh_port_nondefault_get | GET on non-default port 8080 | pass | 9 | [pcap](doh/doh_port_nondefault_get.pcap) |
| doh_port_nondefault_post | POST on non-default port 8080 (full-stack semantics unchanged) | pass | 9 | [pcap](doh/doh_port_nondefault_post.pcap) |
| doh_post_ipv4_http11 | POST/IPv4 plaintext single-flow baseline | pass | 9 | [pcap](doh/doh_post_ipv4_http11.pcap) |
| doh_post_ipv6_http11 | POST/IPv6 carrier (ipv6.nxt=6, offset 74) | pass | 9 | [pcap](doh/doh_post_ipv6_http11.pcap) |

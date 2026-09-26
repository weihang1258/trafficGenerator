# ocsp Pcap Test Results

Cases: 20 — pass 20, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| ocsp_basic_response_status | responseStatus successful + ResponseBytes + BasicOCSPResponse（ResponderID byName） | pass | 9 | [pcap](ocsp/ocsp_basic_response_status.pcap) |
| ocsp_batch_multi_request | 批量 requestList 3 项：线上顺序保留 + 逐项响应匹配 | pass | 9 | [pcap](ocsp/ocsp_batch_multi_request.pcap) |
| ocsp_http_ipv4_request_response | HTTP POST/IPv4 单查询：DER OCSPRequest/OCSPResponse + content type | pass | 9 | [pcap](ocsp/ocsp_http_ipv4_request_response.pcap) |
| ocsp_http_ipv6_request_response | HTTP POST/IPv6 独立 fixture：地址族/外层 DER 与响应 | pass | 9 | [pcap](ocsp/ocsp_http_ipv6_request_response.pcap) |
| ocsp_multi_session_stream | 多会话/keep-alive：两 HTTP 会话交错回放 + tryLater(3)/503 重试分支 + nonce 隔离 | pass | 22 | [pcap](ocsp/ocsp_multi_session_stream.pcap) |
| ocsp_neg_carrier_profile | HTTP profile 与链载体不一致（http-post 但链无 http 层） | pass | 0 | [pcap]() |
| ocsp_neg_certid_hash_length | 算法 OID 与 hash 长度不匹配（sha256 + 20B fixture） | pass | 0 | [pcap]() |
| ocsp_neg_der_truncated | DER 父/子 TLV 截断（wire_fault 注入） | pass | 0 | [pcap]() |
| ocsp_neg_nonce_extension | nonce 双层 OCTET STRING 长度越界（40B > 32B 上限） | pass | 0 | [pcap]() |
| ocsp_neg_request_response_mismatch | 批量项不匹配（request_count 3 vs request.certs 2 项） | pass | 0 | [pcap]() |
| ocsp_neg_signature | 签名算法名未知（signature_algorithm 结构错误） | pass | 0 | [pcap]() |
| ocsp_nonce_extension | nonce 扩展双层 OCTET STRING：请求/响应同值（same_as） | pass | 9 | [pcap](ocsp/ocsp_nonce_extension.pcap) |
| ocsp_pcap_nic_consistency | PCAP/NIC 一致：POST + RFC 5019 GET base64url（无 padding）双会话 carrier 断言 | pass | 18 | [pcap](ocsp/ocsp_pcap_nic_consistency.pcap) |
| ocsp_request_certid_sha1 | SHA-1 CertID：OID 1.3.14.3.2.26 + 20B issuer hashes + 最短 INTEGER serial | pass | 9 | [pcap](ocsp/ocsp_request_certid_sha1.pcap) |
| ocsp_request_certid_sha256_rfc8954 | RFC 8954 SHA-256 CertID：OID + 32B 双 hash（算法↔长度绑定） | pass | 9 | [pcap](ocsp/ocsp_request_certid_sha256_rfc8954.pcap) |
| ocsp_response_signature_extensions | Basic signature/certs + ResponseData[1]/SingleResponse[1] 扩展槽 | pass | 9 | [pcap](ocsp/ocsp_response_signature_extensions.pcap) |
| ocsp_signed_request | 签名请求：requestorName/optionalSignature/signatureAlgorithm/certs 结构面 | pass | 9 | [pcap](ocsp/ocsp_signed_request.pcap) |
| ocsp_single_response_statuses | SingleResponse 三态：good[0]/revoked[1]+RevokedInfo/unknown[2] tag 面 | pass | 9 | [pcap](ocsp/ocsp_single_response_statuses.pcap) |
| ocsp_tcp_record_framing | 裸 TCP 整 DER：无私有长度前缀，响应 DER 跨 segment 按父长度重组 | pass | 10 | [pcap](ocsp/ocsp_tcp_record_framing.pcap) |
| ocsp_time_validity_windows | 时间窗：producedAt/thisUpdate 必需 + nextUpdate 可选 [0] EXPLICIT（缺省形） | pass | 9 | [pcap](ocsp/ocsp_time_validity_windows.pcap) |

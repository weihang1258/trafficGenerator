# http Pcap Test Results

Cases: 67 — pass 67, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| http_chunked_response | 响应 chunked：Transfer-Encoding chunked（T-HTTP-13） | pass | 9 | [pcap](http/http_chunked_response.pcap) |
| http_conn_close_single | single txn Connection close T-HTTP-40 | pass | 9 | [pcap](http/http_conn_close_single.pcap) |
| http_delete_method | DELETE method T-HTTP-30 | pass | 9 | [pcap](http/http_delete_method.pcap) |
| http_dyn_body_b64_list | 业务body_b64 list轮转两流（T-HTTP-68） | pass | 18 | [pcap](http/http_dyn_body_b64_list.pcap) |
| http_dyn_body_list | 业务body list轮转两流（T-HTTP-63） | pass | 18 | [pcap](http/http_dyn_body_list.pcap) |
| http_dyn_pattern_reject | 负例：层地址端口pattern被拒（T-HTTP-59） | pass | 0 | [pcap]() |
| http_dyn_respbody_b64_list | 业务response_body_b64 list轮转两流（T-HTTP-69） | pass | 18 | [pcap](http/http_dyn_respbody_b64_list.pcap) |
| http_dyn_respbody_list | 业务response_body list轮转两流（T-HTTP-64） | pass | 18 | [pcap](http/http_dyn_respbody_list.pcap) |
| http_dyn_sip_rand | ip.src rand seed7三流聚合（T-HTTP-58，值pcap实测回填） | pass | 27 | [pcap](http/http_dyn_sip_rand.pcap) |
| http_dyn_sport_fixed | fixed单流：显式43200不断聚合（T-HTTP-55） | pass | 9 | [pcap](http/http_dyn_sport_fixed.pcap) |
| http_dyn_sport_inc_wrap | inc到尾回绕：43300-43302五流回绕（T-HTTP-56） | pass | 45 | [pcap](http/http_dyn_sport_inc_wrap.pcap) |
| http_dyn_sport_list | list轮转：43100/43101四流各两次（T-HTTP-54） | pass | 36 | [pcap](http/http_dyn_sport_list.pcap) |
| http_dyn_sport_rand | rand seed7 range43000-43009四流聚合（T-HTTP-53/57，值pcap实测回填） | pass | 36 | [pcap](http/http_dyn_sport_rand.pcap) |
| http_dyn_sport_rand_repro | rand复现对照：同seed同range同值（T-HTTP-57，与53对照） | pass | 36 | [pcap](http/http_dyn_sport_rand_repro.pcap) |
| http_dyn_status_inc | 业务status_code inc回绕200-201两流（T-HTTP-66） | pass | 18 | [pcap](http/http_dyn_status_inc.pcap) |
| http_dyn_status_list | 业务status_code list枚举200/404两流（T-HTTP-65） | pass | 18 | [pcap](http/http_dyn_status_list.pcap) |
| http_dyn_status_rand_repro | 业务status_code rand复现对照（T-HTTP-67，与66对照） | pass | 18 | [pcap](http/http_dyn_status_rand_repro.pcap) |
| http_dyn_uri_fixed | 业务uri fixed对照：恒/a单流（T-HTTP-62） | pass | 9 | [pcap](http/http_dyn_uri_fixed.pcap) |
| http_dyn_uri_list | 业务uri list轮转：/a /b两流（T-HTTP-60） | pass | 18 | [pcap](http/http_dyn_uri_list.pcap) |
| http_dyn_uri_pattern | 业务uri pattern替换：/u1 /u2两流（T-HTTP-61） | pass | 18 | [pcap](http/http_dyn_uri_pattern.pcap) |
| http_file_source_fill | file_source fill形态：16字节A体（T-HTTP-45） | pass | 9 | [pcap](http/http_file_source_fill.pcap) |
| http_file_source_literal | 请求 file_source literal：体来自文件源（T-HTTP-27） | pass | 9 | [pcap](http/http_file_source_literal.pcap) |
| http_file_source_random | file_source random定长8字节seed7（T-HTTP-46） | pass | 9 | [pcap](http/http_file_source_random.pcap) |
| http_get_baseline | GET 基线：单事务请求/响应，Host 自动、Connection close（T-HTTP-7） | pass | 9 | [pcap](http/http_get_baseline.pcap) |
| http_gzip_response | 响应 gzip：Content-Encoding 存在（T-HTTP-12） | pass | 9 | [pcap](http/http_gzip_response.pcap) |
| http_head_method | HEAD method T-HTTP-31 | pass | 9 | [pcap](http/http_head_method.pcap) |
| http_ipv6 | IPv6：Host 加括号（T-HTTP-15） | pass | 9 | [pcap](http/http_ipv6.pcap) |
| http_ipv6_mss_segments | IPv6响应MSS分段10包（T-HTTP-48） | pass | 10 | [pcap](http/http_ipv6_mss_segments.pcap) |
| http_ipv6_multiflow_dynamic | IPv6多流：inc源端口两流18包（T-HTTP-47） | pass | 18 | [pcap](http/http_ipv6_multiflow_dynamic.pcap) |
| http_keepalive_multi_transactions | keep-alive 3 事务：同连接 3 对请求/响应（T-HTTP-9） | pass | 13 | [pcap](http/http_keepalive_multi_transactions.pcap) |
| http_layer_version_bare | 层裸 version 1.1：翻译归一为 HTTP/1.1（T-HTTP-2） | pass | 9 | [pcap](http/http_layer_version_bare.pcap) |
| http_mss_req_segments_long_body | req mss536 long body segments T-HTTP-39 | pass | 14 | [pcap](http/http_mss_req_segments_long_body.pcap) |
| http_mss_segments_long_response | mss 536 long resp T-HTTP-28 | pass | 10 | [pcap](http/http_mss_segments_long_response.pcap) |
| http_multiflow_dynamic_sport | multiflow inc sport T-HTTP-41 | pass | 18 | [pcap](http/http_multiflow_dynamic_sport.pcap) |
| http_neg_bad_mss | 负例：MSS 100 越下界（T-HTTP-1） | pass | 0 | [pcap]() |
| http_neg_dyn_closed_method | 负例：method关字段对象拒绝（T-HTTP-71） | pass | 0 | [pcap]() |
| http_neg_dyn_uri_inc | 负例：uri inc在string面拒绝（T-HTTP-70） | pass | 0 | [pcap]() |
| http_neg_flat_src_ip | 负例：顶层扁平src_ip判死（T-HTTP-50） | pass | 0 | [pcap]() |
| http_neg_missing_carrier_gbt | 负例：gbt缺http载体（T-HTTP-52） | pass | 0 | [pcap]() |
| http_neg_static_copy | 负例：静态复制拒绝（T-HTTP-51） | pass | 0 | [pcap]() |
| http_neg_top_http | 负例：顶层http presence判死（T-HTTP-72） | pass | 0 | [pcap]() |
| http_nondefault_port | 非默认端口 8080：用户显式优先（T-HTTP-16） | pass | 9 | [pcap](http/http_nondefault_port.pcap) |
| http_pipelined | pipelined：3 请求先行后 3 响应（T-HTTP-10） | pass | 13 | [pcap](http/http_pipelined.pcap) |
| http_post_body | POST 带体：Content-Length 自动、Content-Type 嗅探 JSON（T-HTTP-8） | pass | 9 | [pcap](http/http_post_body.pcap) |
| http_put_method | PUT method T-HTTP-29 | pass | 9 | [pcap](http/http_put_method.pcap) |
| http_req_body_b64 | req body_b64 wins T-HTTP-18 | pass | 9 | [pcap](http/http_req_body_b64.pcap) |
| http_req_body_invalid_b64_fallback | req bad b64 falls back to body T-HTTP-38 | pass | 9 | [pcap](http/http_req_body_invalid_b64_fallback.pcap) |
| http_req_chunk_size_multi | 请求 chunk_size=5 多分块（frames钉GET行，T-HTTP-21） | pass | 9 | [pcap](http/http_req_chunk_size_multi.pcap) |
| http_req_chunked | req chunked T-HTTP-20 | pass | 9 | [pcap](http/http_req_chunked.pcap) |
| http_req_chunked_mss | chunked乘MSS分段10包请求在包5（T-HTTP-49） | pass | 10 | [pcap](http/http_req_chunked_mss.pcap) |
| http_req_content_encoding_legacy | 旧content_encoding键回退给响应编码：gzip生效（T-HTTP-44） | pass | 9 | [pcap](http/http_req_content_encoding_legacy.pcap) |
| http_req_encoding_non_gzip | req encoding br passthrough T-HTTP-37 | pass | 9 | [pcap](http/http_req_encoding_non_gzip.pcap) |
| http_req_gzip | req gzip T-HTTP-19 | pass | 9 | [pcap](http/http_req_gzip.pcap) |
| http_req_gzip_chunked_composite | req gzip+chunked T-HTTP-35 | pass | 9 | [pcap](http/http_req_gzip_chunked_composite.pcap) |
| http_req_headers_custom | req custom headers T-HTTP-17 | pass | 9 | [pcap](http/http_req_headers_custom.pcap) |
| http_req_headers_legacy | 旧headers键兼容：request_headers缺席时回退headers（T-HTTP-43） | pass | 9 | [pcap](http/http_req_headers_legacy.pcap) |
| http_resp_201_created | resp 201 Created T-HTTP-34 | pass | 9 | [pcap](http/http_resp_201_created.pcap) |
| http_resp_301_location | resp 301 Location T-HTTP-32 | pass | 9 | [pcap](http/http_resp_301_location.pcap) |
| http_resp_500 | resp 500 T-HTTP-33 | pass | 9 | [pcap](http/http_resp_500.pcap) |
| http_resp_body_b64 | resp body_b64 T-HTTP-23 | pass | 9 | [pcap](http/http_resp_body_b64.pcap) |
| http_resp_empty_no_content_type | resp empty body T-HTTP-26 | pass | 9 | [pcap](http/http_resp_empty_no_content_type.pcap) |
| http_resp_headers_override | resp header override T-HTTP-22 | pass | 9 | [pcap](http/http_resp_headers_override.pcap) |
| http_resp_status_text_override | resp 418 custom phrase T-HTTP-24 | pass | 9 | [pcap](http/http_resp_status_text_override.pcap) |
| http_resp_unknown_status | resp 599 fallback T-HTTP-25 | pass | 9 | [pcap](http/http_resp_unknown_status.pcap) |
| http_response_status_404 | 响应 404：状态行与自定义响应体（T-HTTP-11） | pass | 9 | [pcap](http/http_response_status_404.pcap) |
| http_ttl_custom | TTL 128 经顶层spec注入层（层直写被回写覆盖，T-HTTP-42） | pass | 9 | [pcap](http/http_ttl_custom.pcap) |
| http_version_10_no_auto_host | HTTP/1.0：不自动加 Host（T-HTTP-14） | pass | 9 | [pcap](http/http_version_10_no_auto_host.pcap) |

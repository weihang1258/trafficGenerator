# dns Pcap Test Results

Cases: 29 — pass 29, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| dns_aaaa | AAAA查询（T-DNS-4）：dns{query_type:28}→qry.type=28 | pass | 1 | [pcap](dns/dns_aaaa.pcap) |
| dns_aaaa_response | AAAA响应(T-DNS-20):问example.com AAAA→答2001:db8::1 | pass | 2 | [pcap](dns/dns_aaaa_response.pcap) |
| dns_cname_chain | CNAME链(T-DNS-16):answers=CNAME+A→ANCOUNT=2,别名cname回显 | pass | 2 | [pcap](dns/dns_cname_chain.pcap) |
| dns_dnskey_response | DNSKEY响应(T-DNS-28):问example.com DNSKEY→答flags/protocol/algorithm | pass | 2 | [pcap](dns/dns_dnskey_response.pcap) |
| dns_ds_response | DS响应(T-DNS-27):问example.com DS→答keytag/algorithm/digest | pass | 2 | [pcap](dns/dns_ds_response.pcap) |
| dns_edns0 | EDNS0（T-DNS-7）：edns0_enabled→附加节ARCOUNT=1 | pass | 1 | [pcap](dns/dns_edns0.pcap) |
| dns_multi_answer | 单包双答（T-DNS-15）：answers双A→ANCOUNT=2 | pass | 2 | [pcap](dns/dns_multi_answer.pcap) |
| dns_multi_question | 单包双问（T-DNS-14）：questions双问→QDCOUNT=2 | pass | 1 | [pcap](dns/dns_multi_question.pcap) |
| dns_mx_response | MX响应(T-DNS-21):问example.com MX→答mail preference+exchange | pass | 2 | [pcap](dns/dns_mx_response.pcap) |
| dns_name_dynamic | name动态（T-DNS-8）：list双域名+flows=2→两流域名distinct | pass | 2 | [pcap](dns/dns_name_dynamic.pcap) |
| dns_naptr_response | NAPTR响应(T-DNS-29):问example.com NAPTR→答order/preference/flags/service | pass | 2 | [pcap](dns/dns_naptr_response.pcap) |
| dns_neg_empty_name | 负例：空域名拒（T-DNS-13） | pass | 0 | [pcap]() |
| dns_neg_flat | 负例：顶层dns子映射presence判死（T-DNS-2，空map也死） | pass | 0 | [pcap]() |
| dns_neg_long_domain | 负例:超长label拒(T-DNS-17):单label 64字节>63上限 | pass | 0 | [pcap]() |
| dns_neg_rcode | 负例：response_code=16越界拒（T-DNS-12，4位上限15） | pass | 0 | [pcap]() |
| dns_neg_static_copy | 负例：层链静态复制拒绝flows=2+全静态标量（T-DNS-3） | pass | 0 | [pcap]() |
| dns_neg_tcp | 负例：transport=tcp链上拒（T-DNS-11） | pass | 0 | [pcap]() |
| dns_ns_response | NS响应(T-DNS-23):问example.com NS→答ns1.example.com | pass | 2 | [pcap](dns/dns_ns_response.pcap) |
| dns_nxdomain_soa | NXDOMAIN+权威节（T-DNS-6）：response_code:3+authority SOA→rcode=3 | pass | 2 | [pcap](dns/dns_nxdomain_soa.pcap) |
| dns_ptr_response | PTR反向(T-DNS-24):问1.0.0.10.in-addr.arpa PTR→答host.example.com | pass | 2 | [pcap](dns/dns_ptr_response.pcap) |
| dns_qtype_dynamic | query_type动态（T-DNS-9）：inc[1,28 step27]+flows=2→1/28 distinct | pass | 2 | [pcap](dns/dns_qtype_dynamic.pcap) |
| dns_response | 响应包（T-DNS-5）：is_response+response_ip→2包，响应txid回显、A=1.2.3.4 | pass | 2 | [pcap](dns/dns_response.pcap) |
| dns_retry_same_txid | 重传同txid(T-DNS-18):固定txid 1001→双包dns.id同为0x03e9 | pass | 2 | [pcap](dns/dns_retry_same_txid.pcap) |
| dns_smoke_01 | [chain] 冒烟：DNS单查询（example.com A记录，层链形[ip,udp,dns]，域名进dns层name）。dst 53（IANA），txid默认0x1234、QR=0、RD=1，共1包 | pass | 1 | [pcap](dns/dns_smoke_01.pcap) |
| dns_srv_response | SRV响应(T-DNS-25):问_sip._tcp.example.com SRV→答priority/weight/port/target | pass | 2 | [pcap](dns/dns_srv_response.pcap) |
| dns_txid_dynamic | txid动态（T-DNS-10）：inc[1000,1001]+flows=2→双txid distinct | pass | 2 | [pcap](dns/dns_txid_dynamic.pcap) |
| dns_txt_response | TXT响应(T-DNS-22):问example.com TXT→答文本 | pass | 2 | [pcap](dns/dns_txt_response.pcap) |
| dns_v6_aaaa_response | v6承载AAAA问答(T-DNS-26):fd00::1问example.com AAAA→答2001:db8::1 | pass | 2 | [pcap](dns/dns_v6_aaaa_response.pcap) |
| dns_v6_query | IPv6承载(T-DNS-19):v6地址查询→ip.version=6 | pass | 1 | [pcap](dns/dns_v6_query.pcap) |

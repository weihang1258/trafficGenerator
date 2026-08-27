# ldap Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| ldap-bind-search-basic | LDAP (端口 389) 冒烟：完整 TCP 握手 + bindRequest(0) → bindResponse(1) → searchRequest(3) → searchResEntry(4) → unbind(2) + 终止 | pass | 13 | [pcap](ldap/ldap-bind-search-basic.pcap) |

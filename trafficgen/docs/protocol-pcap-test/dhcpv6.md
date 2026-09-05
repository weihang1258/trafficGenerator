# dhcpv6 Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| dhcpv6_smoke_01 | [chain] 冒烟：DHCPv6 SARR（Solicit/Advertise/Request/Reply，IPv6 链路，src_mac 必填）。顶层不设端口 → dst 默认 547（IANA）、src 保持 flow 默认 12345，leased addr 2001:db8::100，共 4 包 | pass | 4 | [pcap](dhcpv6/dhcpv6_smoke_01.pcap) |

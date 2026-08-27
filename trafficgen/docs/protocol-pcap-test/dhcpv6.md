# dhcpv6 Pcap Test Results

Cases: 1 — pass 0, fail 0, error 1

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| dhcpv6_smoke_01 | 冒烟：DHCPv6 SARR（Solicit/Advertise/Request/Reply，IPv6 链路，src_mac 必填）。顶层不设端口 → dst 默认 547（IANA）、src 保持 flow 默认 12345，leased addr 2001:db8::100，共 4 包 | error | 0 | `` |

## Failures

### dhcpv6_smoke_01 — 冒烟：DHCPv6 SARR（Solicit/Advertise/Request/Reply，IPv6 链路，src_mac 必填）。顶层不设端口 → dst 默认 547（IANA）、src 保持 flow 默认 12345，leased addr 2001:db8::100，共 4 包

task ended failed: output error: [a450723e-e8be-4426-9417-f2d2cb03dc52-3748421f-47df-4465-a754-6de87370ca19: unknown protocol: dhcpv6]


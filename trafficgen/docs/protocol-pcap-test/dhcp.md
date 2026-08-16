# dhcp Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| dhcp_smoke_01 | 冒烟：DHCP DORA（Discover/Offer/Request/ACK）。src 保持 flow 默认 12345、目的端口取 IANA 67/68（resolvePorts 只回退零值），your_ip/server_id 来自默认配置，共 4 包 | pass | 4 | [pcap](/tmp/mcp-pcaps/dhcp/dhcp_smoke_01.pcap) |

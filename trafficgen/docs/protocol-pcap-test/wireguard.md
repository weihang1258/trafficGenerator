# wireguard Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| wireguard_smoke_01 | 冒烟：WireGuard 握手（空配置）。顶层不设端口 → dst 默认 51820（IANA）、src 保持 flow 默认 12345；initiator→responder→transport（type 1/2/4），共 3 包 | pass | 3 | [pcap](/tmp/mcp-pcaps/wireguard/wireguard_smoke_01.pcap) |

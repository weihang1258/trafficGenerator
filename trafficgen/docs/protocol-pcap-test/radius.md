# radius Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| radius_smoke_01 | 冒烟：RADIUS Access-Request（空配置）→ 自动响应 Access-Accept。顶层不设端口 → dst 默认 1812（IANA）、src 保持 flow 默认 12345，请求含 User-Name AVP，共 2 包 | pass | 2 | [pcap](/tmp/mcp-pcaps/radius/radius_smoke_01.pcap) |

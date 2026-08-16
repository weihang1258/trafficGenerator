# l2tp Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| l2tp_smoke_01 | 冒烟：L2TPv2 tunnel_with_data。顶层不设端口 → dst 默认 1701（IANA）、src 保持 flow 默认 12345；建隧道 SCCRQ/SCCRP/SCCCN + ICRQ/ICRP/ICCN + PPP 数据帧 + StopCCN，共 8 包 | pass | 8 | [pcap](/tmp/mcp-pcaps/l2tp/l2tp_smoke_01.pcap) |

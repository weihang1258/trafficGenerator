# ike Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| ike_smoke_01 | 冒烟：IKEv2 空配置 → standard_v2（IKE_SA_INIT + IKE_AUTH 各一对）。显式 src_port=12345（客户端临时端口，planner 禁止 500 作源端口），dst 默认 500，共 4 包 | pass | 4 | [pcap](/tmp/mcp-pcaps/ike/ike_smoke_01.pcap) |

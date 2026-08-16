# syslog Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| syslog_smoke_01 | 冒烟：syslog RFC5424 消息（空配置）。顶层不设端口 → 默认 dst 514（IANA），facility=1(2)/level=6(Info)，共 1 包 | pass | 1 | [pcap](/tmp/mcp-pcaps/syslog/syslog_smoke_01.pcap) |

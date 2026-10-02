# mdns Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| mdns_smoke_01 | [chain] 冒烟：mDNS 查询（x.local A 记录）。顶层不设端口 → 双向均 5353（IANA），多播 224.0.0.251、IP TTL=255（RFC 6762 §11），共 1 包 | pass | 1 | [pcap](mdns/mdns_smoke_01.pcap) |

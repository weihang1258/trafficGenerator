# dns Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| dns_smoke_01 | 冒烟：DNS 单查询（example.com A 记录）。顶层不设端口 → 默认 dst 53（IANA），txid 默认 0x1234、QR=0、RD=1，共 1 包 | pass | 1 | [pcap](dns/dns_smoke_01.pcap) |

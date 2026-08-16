# postgresql Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| postgresql-query-basic | PostgreSQL (端口 5432) 冒烟：完整 TCP 握手 + 启动消息 → 认证 → 参数 → SELECT 1 查询 → 终止 | pass | 23 | [pcap](/tmp/mcp-pcaps/postgresql/postgresql-query-basic.pcap) |

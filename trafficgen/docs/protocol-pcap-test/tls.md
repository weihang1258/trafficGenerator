# tls Pcap Test Results

Cases: 15 — pass 15, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| tls-cert-dyn-san | cert.san list 轮转：两流 SAN 分别 a.test/b.test（T-TLS-13） | pass | 32 | [pcap](tls/tls-cert-dyn-san.pcap) |
| tls-cert-dyn-subject | cert.subject list 轮转：两流 CN 分别 a.test/b.test（T-TLS-12） | pass | 32 | [pcap](tls/tls-cert-dyn-subject.pcap) |
| tls-cert-neg-bad-date | 负例：坏日期被拒（T-TLS-15b） | pass | 0 | [pcap]() |
| tls-cert-neg-dyn-keytype | 负例：cert 关字段 key_type 动态被拒（T-TLS-14） | pass | 0 | [pcap]() |
| tls-cert-neg-keytype-value | 负例：key_type 非法值被拒（T-TLS-15a） | pass | 0 | [pcap]() |
| tls-cert-static | cert 静态全填：自定义 DN/SAN/有效期进 Certificate（T-TLS-10） | pass | 16 | [pcap](tls/tls-cert-static.pcap) |
| tls-dyn-sni-fixed | 业务 sni fixed 对照：单流恒为 a.com（T-TLS-5 对照端） | pass | 16 | [pcap](tls/tls-dyn-sni-fixed.pcap) |
| tls-dyn-sni-list | 业务 sni list 轮转：a.com/b.com 两流（T-TLS-5） | pass | 32 | [pcap](tls/tls-dyn-sni-list.pcap) |
| tls-dyn-sni-pattern | 业务 sni pattern 替换：host1.com/host2.com 两流（T-TLS-6） | pass | 32 | [pcap](tls/tls-dyn-sni-pattern.pcap) |
| tls-handshake-basic | TLS（端口 443）冒烟：完整 TCP 握手 + TLS 1.3 ClientHello → ServerHello → EncryptedExtensions → Certificate → Finished → 应用数据 + 终止（T-TLS-1） | pass | 16 | [pcap](tls/tls-handshake-basic.pcap) |
| tls-http-inner | https 套娃：内层 http GET /tls-inner 包进 ApplicationData（T-TLS-9） | pass | 16 | [pcap](tls/tls-http-inner.pcap) |
| tls-neg-dyn-closed-version | 负例：关闭字段 version/alpn/role 动态被拒（T-TLS-8） | pass | 0 | [pcap]() |
| tls-neg-flat | 负例：顶层扁平五键判死（T-TLS-3） | pass | 0 | [pcap]() |
| tls-neg-static-copy | 负例：层链静态复制拒绝 flows=2+全静态标量（T-TLS-4） | pass | 0 | [pcap]() |
| tls-sni-alpn | SNI/ALPN 进 ClientHello 扩展：example.com + h2（T-TLS-2） | pass | 16 | [pcap](tls/tls-sni-alpn.pcap) |

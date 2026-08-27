# ssh Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| ssh-basic-session | SSH (端口 22) 冒烟：完整 TCP 握手 + 密钥交换 KEXINIT → 服务请求 → 认证 → 会话通道 → 终止 | pass | 23 | [pcap](ssh/ssh-basic-session.pcap) |

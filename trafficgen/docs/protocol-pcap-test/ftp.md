# ftp Pcap Test Results

Cases: 1 — pass 1, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| ftp_smoke_01 | FTP 控制通道冒烟：显式 banner + USER/PASS/QUIT 命令（types.go FTPConfig，RFC 959 §4.1），空配置只产握手+终止（设计行为），本 case 用显式消息配置驱动数据帧 | pass | 14 | [pcap](ftp/ftp_smoke_01.pcap) |

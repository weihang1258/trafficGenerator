# sip Pcap Test Results

Cases: 18 — pass 18, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| sip_basic_dialog | 冒烟：TCP 3握手+五消息dialog(INVITE/200/ACK/BYE/200)+4挥手=12包（存量等价迁移） | pass | 12 | [pcap](sip/sip_basic_dialog.pcap) |
| sip_default_port | T-SIP-16: sip 层无端口→dst 缺省 5060 | pass | 12 | [pcap](sip/sip_default_port.pcap) |
| sip_empty_dialog | T-SIP-18: 空 dialog→7 包最小联结（nil-config 合同） | pass | 7 | [pcap](sip/sip_empty_dialog.pcap) |
| sip_flat_presence | T-SIP-2: 顶层 sip presence 判死（空 map 也死） | pass | 0 | [pcap]() |
| sip_flat_static_port | T-SIP-3: sip 层静态端口+flows=2 拒（12.9，门扩扫 sip 层） | pass | 0 | [pcap]() |
| sip_hdr_completion | T-SIP-4: 无头 INVITE→Call-ID/Via/CSeq/Max-Forwards 全生成（RFC 3261 §8.1.1.4） | pass | 12 | [pcap](sip/sip_hdr_completion.pcap) |
| sip_hdr_user_wins | T-SIP-5: 显式 CSeq:7+Call-ID→保留+200 响应回显（user 头赢三态） | pass | 9 | [pcap](sip/sip_hdr_user_wins.pcap) |
| sip_mss_segment | T-SIP-10: 3000B body→MSS 1460 分段 3 段 | pass | 11 | [pcap](sip/sip_mss_segment.pcap) |
| sip_options | T-SIP-7: OPTIONS 方法枚举+200 | pass | 9 | [pcap](sip/sip_options.pcap) |
| sip_port_dyn | T-SIP-17: sip.src_port 动态 inc+flows=2（E1 逐流端口池，2 流×12=24 包） | pass | 24 | [pcap](sip/sip_port_dyn.pcap) |
| sip_register | T-SIP-6: REGISTER 方法枚举+200 | pass | 9 | [pcap](sip/sip_register.pcap) |
| sip_rtp_down | T-SIP-12: RTP down 方向+显式 media 端口（src 30000/dst 30001→线上 src=30001/dst=30000） | pass | 10 | [pcap](sip/sip_rtp_down.pcap) |
| sip_rtp_filesource | T-SIP-14: RTP FileSource literal 'pay'→帧 payload 实字节（FileSource 优先合同） | pass | 10 | [pcap](sip/sip_rtp_filesource.pcap) |
| sip_rtp_media | T-SIP-11: RTP 媒体子流（EmitMedia+frames:2/PT 0→UDP 5004 两帧；14 包） | pass | 14 | [pcap](sip/sip_rtp_media.pcap) |
| sip_sdp_body | T-SIP-9: SDP body 无 Content-Length 头→自动补（RFC 合同 sip.go:308-314） | pass | 9 | [pcap](sip/sip_sdp_body.pcap) |
| sip_sdp_port | T-SIP-13: SDP m=audio 6007020→RTP src=6007020（scanSDPMediaPorts 合同） | pass | 10 | [pcap](sip/sip_sdp_port.pcap) |
| sip_status_codes | T-SIP-8: 响应码枚举 100/180/200/404（INVITE 多响应+404 拒绝路径） | pass | 15 | [pcap](sip/sip_status_codes.pcap) |
| sip_v6 | T-SIP-15: ip 层 v6→IP 透明正例（9.24 地址族对称） | pass | 12 | [pcap](sip/sip_v6.pcap) |

# telnet Pcap Test Results

Cases: 17 — pass 17, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| telnet_banner | T-TELNET-13: banner+file_source 前置（握手后首数据段 down） | pass | 15 | [pcap](telnet/telnet_banner.pcap) |
| telnet_basic_session | 冒烟：TCP 3握手+defaultDialog 6事件+4挥手=13包（存量等价迁移） | pass | 13 | [pcap](telnet/telnet_basic_session.pcap) |
| telnet_default_port | T-TELNET-15: telnet 层无端口键 → dst 缺省 23（translate 镜像 setDefaultDstPort） | pass | 13 | [pcap](telnet/telnet_default_port.pcap) |
| telnet_flat_presence | T-TELNET-2: 顶层 telnet presence 判死（空 map 也死） | pass | 0 | [pcap]() |
| telnet_flat_static_port | T-TELNET-3: telnet 层静态端口+flows=2 拒（12.9，门扩扫 telnet 层） | pass | 0 | [pcap]() |
| telnet_iac_escape | T-TELNET-10: IAC 转义 data 0xFF 翻倍（RFC 854 §3；data_b64 形态） | pass | 8 | [pcap](telnet/telnet_iac_escape.pcap) |
| telnet_login_fail | T-TELNET-5: login_fail 场景（失败路径 'Login incorrect' 重提示=27 包校准） | pass | 27 | [pcap](telnet/telnet_login_fail.pcap) |
| telnet_login_full | T-TELNET-4: login_full 场景+5 参数键（协商 11+登录 8+shell+双命令+logout=33 包校准） | pass | 33 | [pcap](telnet/telnet_login_full.pcap) |
| telnet_long_output | T-TELNET-7: long_output 场景（8197B 响应 MSS 1460 分段 6 段=36 包校准） | pass | 36 | [pcap](telnet/telnet_long_output.pcap) |
| telnet_multi_command | T-TELNET-6: multi_command 场景+commands:[uname,pwd]（多动作组合流 9.11=33 包校准） | pass | 33 | [pcap](telnet/telnet_multi_command.pcap) |
| telnet_neg_scenario | T-TELNET-17: unknown scenario → legacy 白名单拒 | pass | 0 | [pcap]() |
| telnet_option_reject | T-TELNET-8: option_reject 场景（DONT/WONT 拒绝路径=28 包校准） | pass | 28 | [pcap](telnet/telnet_option_reject.pcap) |
| telnet_port_dyn | T-TELNET-16: telnet.src_port 动态 inc+flows=2（E1 逐流端口池，2 流×13=26 包） | pass | 26 | [pcap](telnet/telnet_port_dyn.pcap) |
| telnet_sb_subneg | T-TELNET-11: sb 子协商框架字节+SubData 0xFF 翻倍 | pass | 8 | [pcap](telnet/telnet_sb_subneg.pcap) |
| telnet_synch | T-TELNET-9: synch 场景（IAC IP+DM 中断长输出=38 包校准） | pass | 38 | [pcap](telnet/telnet_synch.pcap) |
| telnet_ttype_naws_singles | T-TELNET-12: ttype_is/naws 缺省值（xterm/80x24）+七单字节命令枚举格 | pass | 16 | [pcap](telnet/telnet_ttype_naws_singles.pcap) |
| telnet_v6 | T-TELNET-14: ip 层 v6 → IP 透明正例（9.24 地址族对称；eth.type 0x86dd） | pass | 13 | [pcap](telnet/telnet_v6.pcap) |

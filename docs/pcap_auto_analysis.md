# /home/pcap_auto 全量 pcap 深度分析报告(造流复刻视角)

> 扫描日期: 2026-08-01
> 扫描范围: /home/pcap_auto 递归全部 pcap 文件(含子目录)
> 扫描工具: tshark 3.6.14 + 文件名编码解析 + 代表文件深度字段提取
> 判定视角: **普通造流(planner)能否复刻**,非流回放(replay)
> 判定标准: ✅=有对应 planner 可完整复刻 / ⚠️=无 L7 planner 但 L4 字节级可造 / ❌=当前无法造

## 一、总览

| 指标 | 数值 |
|------|------|
| 文件总数 | 17951 |
| 总数据量 | 4.2 GB |
| 命名编码可解析 | 16952 (94.4%) |
| 命名编码不可解析(特殊文件) | 999 |

## 二、目录 × 协议矩阵

| 目录 | 文件数 | 协议组(L3-L4:dport 文件数) |
|------|-------|---------------------------|
| mypcap/eu_pcaps/ipv6_monfil_pcaps/ipv6_8314 | 8316 | IPv6-TCP:80:8204; IPv6-TCP:8001:56; IPv6-TCP:8002:56 |
| llcj_pcap | 2483 | IPv6-TCP:80:551; IP-TCP:80:509; IP-TCP:443:201; IPv6-TCP:443:201; IP-TCP:1080:24; IP-TCP:554:24; IP-TCP:6868:24; IP-TCP:38350:24 |
| llcj_mirror | 2483 | IPv6-TCP:80:551; IP-TCP:80:509; IP-TCP:443:204; IPv6-TCP:443:204; IP-TCP:1080:24; IP-TCP:554:24; IP-TCP:6868:24; IP-TCP:38350:24 |
| monitor | 1381 | IP-TCP:80:421; IPv6-TCP:80:402; IP-TCP:443:73; IPv6-TCP:443:71; IP-TCP:6868:24; IP-TCP:38350:24; IPv6-TCP:6868:24; IPv6-TCP:38350:24 |
| fiter | 1339 | IP-TCP:80:403; IPv6-TCP:80:387; IPv6-TCP:443:70; IP-TCP:443:68; IP-TCP:6868:24; IP-TCP:38350:24; IPv6-TCP:6868:24; IPv6-TCP:38350:24 |
| mypcap/eu_pcaps/ipv4_monfil_pcaps/692 | 693 | IP-TCP:80:687; IP-TCP:8081:2; IP-TCP:28597:1; IP-TCP:8088:1; IP-TCP:8880:1; eth:ethertype:ip:tcp:1 |
| mypcap/publicpcap/IPv4/http_illegal | 173 | eth:ethertype:ip:tcp:169; eth:ethertype:ip:tcp:http:3; eth:ethertype:ipv6:tcp:1 |
| mypcap/publicpcap/IPV6/http_illegal | 156 | eth:ethertype:ipv6:tcp:153; eth:ethertype:ipv6:tcp:http:3 |
| accesslog | 96 | IP-TCP:80:46; IPv6-TCP:80:46; IP-TCP:8000:2; IPv6-TCP:8000:2 |
| mypcap/sendpcap/mirror | 73 | IP-TCP:80:37; eth:ethertype:ip:tcp:16; eth:ethertype:ipv6:tcp:7; eth:ethertype:ipv6:ipv6.hopopts:icmpv6:3; IP-TCP:443:1; IP-TCP:28597:1; IP-TCP:8880:1; eth:ethertype:ip:udp:dns:1 |
| fz | 62 | IP-TCP:8000:47; eth:ethertype:ip:tcp:8; IP-TCP:80:6; eth:ethertype:ipv6:tcp:1 |
| mypcap/publicpcap/IPV6/http_get | 60 | eth:ethertype:ipv6:tcp:http:60 |
| mypcap/publicpcap/IPv4/http_get | 60 | eth:ethertype:ip:tcp:http:60 |
| mypcap/postpcap | 59 | eth:ethertype:ip:tcp:32; eth:ethertype:ipv6:tcp:27 |
| mypcap/test/3 | 35 | eth:ethertype:ip:tcp:34; eth:ethertype:ip:tcp:tls:1 |
| mypcap | 26 | eth:ethertype:ip:tcp:21; IP-TCP:80:1; IP-TCP:8880:1; eth:ethertype:ip:udp:dns:1; eth:ethertype:ipv6:tcp:1; eth:ethertype:ipv6:tcp:http:1 |
| (top) | 23 | eth:ethertype:ip:tcp:14; eth:ethertype:ip:icmp:4; eth:ethertype:vlan:ethertype:ip:1; eth:ethertype:ip:tcp:http:1; eth:ethertype:ip:tcp:data:1; eth:ethertype:ip:sctp:ngap:ngap:nas-5gs:1; eth:ethertype:arp:1 |
| mypcap/publicpcap/IPV6 | 23 | eth:ethertype:ipv6:tcp:15; eth:ethertype:ipv6:ipv6.hopopts:icmpv6:3; eth:ethertype:ipv6:udp:dns:1; eth:ethertype:ipv6:udp:radius:1; eth:ethertype:ipv6:tcp:rtsp:1; eth:ethertype:ipv6:udp:sip:sdp:1; eth:ethertype:ipv6:tcp:smtp:1 |
| mypcap/publicpcap/IPv4/http | 23 | eth:ethertype:ip:tcp:20; eth:ethertype:ip:udp:data:1; eth:ethertype:ip:tcp:http:urlencoded-form:1; eth:ethertype:ip:tcp:http:1 |
| mypcap/ProtoPcap/ARD-163_news-19-0041-V66.1-IM_getui-22-0268-00 | 22 | IP-TCP:80:22 |
| bc | 21 | eth:ethertype:vlan:ethertype:ip:tcp:19; eth:ethertype:ip:tcp:data:1; eth:ethertype:ip:tcp:1 |
| mypcap/publicpcap/IPv4/https | 21 | eth:ethertype:ip:tcp:18; IP-TCP:443:1; eth:ethertype:ip:udp:data:1; eth:ethertype:ip:tcp:tls:1 |
| mypcap/publicpcap/xdr2 | 21 | eth:ethertype:ip:tcp:11; eth:ethertype:ipv6:tcp:5; eth:ethertype:ip:udp:dns:3; eth:ethertype:ip:udp:sip:1; eth:ethertype:ip:udp:sip:sdp:1 |
| mypcap/test/1 | 20 | eth:ethertype:ip:tcp:18; eth:ethertype:ip:tcp:http:1; eth:ethertype:ip:tcp:http:data:1 |
| mypcap/https | 20 | eth:ethertype:ip:tcp:18; eth:ethertype:ip:udp:data:1; eth:ethertype:ip:tcp:tls:1 |
| mypcap/sendpcap/xdr | 20 | eth:ethertype:ip:tcp:17; IPv6-TCP:80:1; eth:ethertype:ip:tcp:http:urlencoded-form:1; eth:ethertype:ip:tcp:http:1 |
| mypcap/test/2 | 19 | eth:ethertype:ip:tcp:18; eth:ethertype:ip:udp:gtp:ip:tcp:1 |
| mypcap/publicpcap/IPv4 | 17 | eth:ethertype:ip:tcp:11; eth:ethertype:vlan:ethertype:ip:tcp:3; eth:ethertype:vlan:ethertype:ip:gre:ip:tcp:2; eth:ethertype:ip:udp:l2tp:ppp:ip:tcp:tls:1 |
| mypcap/publicpcap/IPv4/ftp | 15 | eth:ethertype:ip:tcp:14; eth:ethertype:arp:1 |
| mypcap/publicpcap/Radius | 12 | eth:ethertype:ip:udp:radius:11; eth:ethertype:arp:1 |
| mypcap/ProtoPcap/ARD-163_news-19-0041-V66.1-IM_https-22-0035-00 | 11 | IP-TCP:443:11 |
| bzip | 10 | eth:ethertype:ip:tcp:6; eth:ethertype:ipv6:tcp:4 |
| mypcap/test/4 | 10 | eth:ethertype:ip:tcp:10 |
| mypcap/publicpcap/IPv4/dns | 10 | eth:ethertype:ip:udp:dns:5; eth:ethertype:ip:udp:gtp:ip:tcp:2; eth:ethertype:ip:tcp:2; eth:ethertype:vlan:ethertype:ip:udp:dns:1 |
| mypcap/eu_pcaps | 10 | eth:ethertype:ip:tcp:10 |
| mypcap/eu_pcaps/ipv4_monfil_pcaps/other | 10 | eth:ethertype:ip:tcp:10 |
| kjvpn_kk | 9 | IP-TCP:80:9 |
| dns | 9 | eth:ethertype:vlan:ethertype:ip:udp:dns:4; eth:ethertype:ip:udp:dns:4; eth:ethertype:ip:tcp:1 |
| mypcap/ProtoPcap/ARD-163_news-19-0041-V66.1-IM_dns-22-0065-00 | 9 | IP-TCP:53:9 |
| mypcap/idc3 | 9 | eth:ethertype:vlan:ethertype:ip:tcp:2; eth:ethertype:ip:gre:arp:1; eth:ethertype:ip:udp:gtp:ip:udp:data:1; eth:ethertype:mpls:ip:udp:ldp:1; eth:ethertype:pppoes:ppp:lcp:1; eth:ethertype:ip:gre:ip:udp:dns:1; eth:ethertype:mpls:pwethheuristic:pwethcw:eth:ethertype:ip:tcp:1; eth:ethertype:pppoes:ppp:ip:tcp:http:1 |
| mypcap/get_field | 9 | eth:ethertype:ip:tcp:8; eth:ethertype:ip:tcp:http:1 |
| mypcap/publicpcap/IPv4/sip | 9 | eth:ethertype:ip:tcp:5; eth:ethertype:ip:udp:sip:sdp:2; eth:ethertype:ip:udp:sip:1; eth:ethertype:ipv6:tcp:1 |
| rs | 8 | eth:ethertype:ip:tcp:8 |
| mypcap/app_pcap | 7 | eth:ethertype:ip:tcp:7 |
| mypcap/field/http/request_method/http1_1 | 6 | eth:ethertype:ip:tcp:5; eth:ethertype:arp:1 |
| mypcap/ProtoPcap/ARD-163_news-19-0041-V66.1-IM_gaode_map-10-0003-00 | 5 | IP-TCP:443:5 |
| mypcap/eu_pcaps/ipv6_monfil_pcaps/other | 5 | IPv6-TCP:80:3; eth:ethertype:ipv6:tcp:2 |
| VPN/wireguard | 5 | eth:ethertype:ip:udp:wg:5 |
| mypcap/field/http/request_method/http1_0 | 4 | eth:ethertype:ip:tcp:3; eth:ethertype:arp:1 |
| mypcap/publicpcap/IPv4/rtsp | 4 | eth:ethertype:ip:tcp:3; eth:ethertype:ipv6:tcp:1 |
| VPN/SHADOWSOCKS | 4 | eth:ethertype:ip:tcp:4 |
| mypcap/publicpcap/IPv4/email | 3 | eth:ethertype:ip:tcp:3 |
| mypcap/ProtoPcap/ARD-163_news-19-0041-V66.1-IM_aliyun-17-0021-00 | 2 | IP-TCP:443:2 |
| mypcap/ProtoPcap/ARD-163_news-19-0041-V66.1-IM_DHCP-22-0079-00 | 2 | IP-TCP:67:1; IP-TCP:68:1 |
| VPN/OPENVPN | 2 | eth:ethertype:ip:tcp:1; eth:ethertype:ip:udp:openvpn:1 |
| mypcap/test | 1 | eth:ethertype:ip:tcp:1 |
| mypcap/ProtoPcap | 1 | eth:ethertype:ip:udp:data:1 |
| mypcap/ProtoPcap/ARD-163_news-19-0041-V66.1-IM_http_qita-22-0259-01 | 1 | IP-TCP:80:1 |
| mypcap/publicpcap | 1 | eth:ethertype:ip:tcp:1 |
| mypcap/publicpcap/IPv4/com | 1 | eth:ethertype:ip:tcp:1 |
| mypcap/eu_pcaps/ipv6_monfil_pcaps | 1 | IPv6-TCP:80:1 |
| VPN/vmess | 1 | eth:ethertype:ip:tcp:1 |

## 三、按端口组的深度分析表单(协议/层级/格式/数据内容/造流判定)

> 每个 (L3, L4, dport) 组合取代表文件做 tshark 深度解析。数据内容为前几包 L7 关键字段样例。

| L3 | L4 | 目标端口 | 文件数 | 协议栈(L7) | 层级格式要点 | 数据内容样例 | 造流判定 | 对应 planner |
|----|----|---------|-------|------------|-------------|-------------|---------|-------------|
| IP | ICMP | None | 9 | icmp | Eth 0x0800, IPv4 ttl=64 df=0x00 | icmp: 8, 0, 0x9901 | ✅ | icmp |
| IPv6 | ICMPv6 | None | 6 | icmpv6 | Eth 0x86dd, IPv6 | icmpv6: 136, 0, 0x688c | ✅ | icmpv6 |
| IP | SCTP | 38412 | 3 | ngap | Eth 0x0800, IPv4 ttl=64 df=0x40 | sctp: 38413, 38412, 0x10041003 | ⚠️ | sctp |
| IP | TCP | 1080 | 12 | socks | Eth 0x0800, IPv4 ttl=32 df=0x40, TCP SYN win=5792 MSS/WScale | — | ⚠️ | tcp |
| IPv6 | TCP | 1080 | 12 | socks | Eth 0x86dd, IPv6, TCP SYN win=5792 MSS/WScale | — | ⚠️ | tcp |
| IP | TCP | 110 | 12 | pop | Eth 0x0800, IPv4 ttl=64 df=0x40, TCP SYN win=8192 MSS/WScale | — | ✅ | pop3 |
| IPv6 | TCP | 110 | 12 | pop | Eth 0x86dd, IPv6, TCP SYN win=8192 MSS/WScale | — | ✅ | pop3 |
| IP | TCP | 12001 | 3 | http | Eth 0x0800, IPv4 ttl=64 df=0x00, TCP SYN-ACK win=8192 | — | ✅ | http |
| IPv6 | TCP | 12001 | 3 | http | Eth 0x86dd, IPv6, TCP SYN-ACK win=8192 | — | ✅ | http |
| IP | TCP | 12011 | 3 | tcp | Eth 0x0800, IPv4 ttl=64 df=0x00, TCP SYN-ACK win=8192 | — | ✅ | tcp/udp |
| IPv6 | TCP | 12011 | 3 | tcp | Eth 0x86dd, IPv6, TCP SYN-ACK win=8192 | — | ✅ | tcp/udp |
| IP | TCP | 12014 | 3 | tcp | Eth 0x0800, IPv4 ttl=64 df=0x00, TCP PSH-ACK win=8192 | — | ✅ | tcp/udp |
| IPv6 | TCP | 12014 | 3 | tcp | Eth 0x86dd, IPv6, TCP PSH-ACK win=8192 | — | ✅ | tcp/udp |
| IP | TCP | 12017 | 3 | http | Eth 0x0800, IPv4 ttl=64 df=0x00, TCP SYN-ACK win=8192 | — | ✅ | http |
| IPv6 | TCP | 12017 | 3 | http | Eth 0x86dd, IPv6, TCP SYN-ACK win=8192 | — | ✅ | http |
| IP | TCP | 12024 | 3 | http | Eth 0x0800, IPv4 ttl=64 df=0x00, TCP SYN-ACK win=8192 | — | ✅ | http |
| IPv6 | TCP | 12024 | 3 | http | Eth 0x86dd, IPv6, TCP SYN-ACK win=8192 | — | ✅ | http |
| IP | TCP | 12026 | 3 | http | Eth 0x0800, IPv4 ttl=64 df=0x00, TCP PSH-ACK win=8192 | — | ✅ | http |
| IPv6 | TCP | 12026 | 3 | http | Eth 0x86dd, IPv6, TCP PSH-ACK win=8192 | — | ✅ | http |
| IP | TCP | 143 | 12 | imap | Eth 0x0800, IPv4 ttl=64 df=0x40, TCP SYN win=65535 MSS/WScale | — | ✅ | imap |
| IPv6 | TCP | 143 | 12 | imap | Eth 0x86dd, IPv6, TCP SYN win=65535 MSS/WScale | — | ✅ | imap |
| IP | TCP | 14567 | 3 | tcp | Eth 0x0800, IPv4 ttl=61 df=0x40, TCP PSH-ACK win=255 | data: 5b:00:00:00:1a:00:01:33:, 26 | ✅ | tcp/udp |
| IP | TCP | 1720 | 12 | h225 | Eth 0x0800, IPv4 ttl=64 df=0x40, TCP SYN win=8192 MSS/WScale | — | ⚠️ | tcp |
| IPv6 | TCP | 1720 | 12 | h225 | Eth 0x86dd, IPv6, TCP SYN win=8192 MSS/WScale | — | ⚠️ | tcp |
| IP | TCP | 1723 | 12 | pptp | Eth 0x0800, IPv4 ttl=128 df=0x40, TCP SYN win=8192 MSS/WScale | — | ⚠️ | tcp |
| IPv6 | TCP | 1723 | 12 | pptp | Eth 0x86dd, IPv6, TCP SYN win=8192 MSS/WScale | — | ⚠️ | tcp |
| IP | TCP | 1935 | 12 | rtmpt | Eth 0x0800, IPv4 ttl=64 df=0x40, TCP SYN win=29200 MSS/WScale | — | ⚠️ | tcp |
| IPv6 | TCP | 1935 | 12 | rtmpt | Eth 0x86dd, IPv6, TCP SYN win=29200 MSS/WScale | — | ⚠️ | tcp |
| IP | TCP | 21 | 12 | ftp | Eth 0x8100, VLAN 1160, IPv4 ttl=128 df=0x00, TCP SYN win=32768 MSS/WScale | — | ✅ | ftp |
| IPv6 | TCP | 21 | 12 | ftp | Eth 0x8100, VLAN 1160, IPv6, TCP SYN win=32768 MSS/WScale | — | ✅ | ftp |
| IP | TCP | 2152 | 3 | tls | Eth 0x0800, IPv4 ttl=128 df=0x00, TCP SYN win=32768 MSS/WScale | — | ✅ | tls |
| IPv6 | TCP | 2152 | 3 | tls | Eth 0x86dd, IPv6, TCP SYN win=32768 MSS/WScale | — | ✅ | tls |
| IP | TCP | 22 | 12 | ssh | Eth 0x0800, IPv4 ttl=128 df=0x40, TCP PSH-ACK win=256 | — | ✅ | ssh |
| IPv6 | TCP | 22 | 12 | ssh | Eth 0x86dd, IPv6, TCP PSH-ACK win=256 | — | ✅ | ssh |
| IP | TCP | 23 | 12 | telnet | Eth 0x0800, IPv4 ttl=64 df=0x40, TCP SYN win=32120 MSS/WScale | — | ✅ | telnet |
| IPv6 | TCP | 23 | 12 | telnet | Eth 0x86dd, IPv6, TCP SYN win=32120 MSS/WScale | — | ✅ | telnet |
| IP | TCP | 25 | 12 | smtp | Eth 0x0800, IPv4 ttl=64 df=0x40, TCP SYN win=8192 MSS/WScale | — | ✅ | smtp |
| IPv6 | TCP | 25 | 12 | smtp | Eth 0x86dd, IPv6, TCP SYN win=8192 MSS/WScale | — | ✅ | smtp |
| IP | TCP | 28597 | 3 | http | Eth 0x0800, IPv4 ttl=64 df=0x40, TCP SYN win=8192 MSS/WScale | — | ✅ | http |
| IPv6 | TCP | 28597 | 3 | http | Eth 0x86dd, IPv6, TCP SYN win=8192 MSS/WScale | — | ✅ | http |
| IP | TCP | 3389 | 12 | data | Eth 0x0800, IPv4 ttl=128 df=0x40, TCP SYN win=64512 MSS/WScale | — | ✅ | tcp |
| IPv6 | TCP | 3389 | 12 | data | Eth 0x86dd, IPv6, TCP SYN win=64512 MSS/WScale | — | ✅ | tcp |
| IP | TCP | 38350 | 24 | tcp | Eth 0x0800, IPv4 ttl=40 df=0x40, TCP PSH-ACK win=227 | data: 05:ff, 2 | ✅ | tcp/udp |
| IPv6 | TCP | 38350 | 24 | tcp | Eth 0x86dd, IPv6, TCP PSH-ACK win=227 | data: 05:ff, 2 | ✅ | tcp/udp |
| IP | TCP | 389 | 12 | ldap | Eth 0x0800, IPv4 ttl=128 df=0x40, TCP SYN win=8192 MSS/WScale | — | ⚠️ | tcp |
| IPv6 | TCP | 389 | 12 | ldap | Eth 0x86dd, IPv6, TCP SYN win=8192 MSS/WScale | — | ⚠️ | tcp |
| IP | TCP | 443 | 12 | tls | Eth 0x0800, IPv4 ttl=128 df=0x40, TCP SYN win=64240 MSS/WScale | — | ✅ | tls |
| IPv6 | TCP | 443 | 12 | tls | Eth 0x86dd, IPv6, TCP SYN win=64240 MSS/WScale | — | ✅ | tls |
| IP | TCP | 465 | 12 | tls | Eth 0x0800, IPv4 ttl=64 df=0x40, TCP SYN win=8192 MSS/WScale | — | ✅ | tls |
| IPv6 | TCP | 465 | 12 | tls | Eth 0x86dd, IPv6, TCP SYN win=8192 MSS/WScale | — | ✅ | tls |
| IP | TCP | 5060 | 12 | sip | Eth 0x0800, IPv4 ttl=128 df=0x00, TCP SYN win=32768 MSS/WScale | — | ✅ | sip |
| IPv6 | TCP | 5060 | 12 | sip | Eth 0x86dd, IPv6, TCP SYN win=32768 MSS/WScale | — | ✅ | sip |
| IP | TCP | 5222 | 12 | xmpp | Eth 0x0800, IPv4 ttl=64 df=0x40, TCP SYN win=14600 MSS/WScale | — | ⚠️ | tcp |
| IPv6 | TCP | 5222 | 12 | xmpp | Eth 0x86dd, IPv6, TCP SYN win=14600 MSS/WScale | — | ⚠️ | tcp |
| IP | TCP | 53 | 1 | dns | Eth 0x0800, IPv4 ttl=64 df=0x40, UDP len=40 | dns: 0x3632, 0x0100, {'dns.flags.response_raw | ✅ | dns |
| IP | TCP | 554 | 24 | rtsp | Eth 0x0800, IPv4 ttl=128 df=0x00, TCP SYN win=32768 MSS/WScale | — | ⚠️ | tcp |
| IPv6 | TCP | 554 | 24 | rtsp | Eth 0x86dd, IPv6, TCP SYN win=32768 MSS/WScale | — | ⚠️ | tcp |
| IP | TCP | 5901 | 12 | vnc | Eth 0x0800, IPv4 ttl=128 df=0x40, TCP SYN win=65535 MSS/WScale | — | ⚠️ | tcp |
| IPv6 | TCP | 5901 | 12 | vnc | Eth 0x86dd, IPv6, TCP SYN win=65535 MSS/WScale | — | ⚠️ | tcp |
| IP | TCP | 62763 | 12 | tcp | Eth 0x0800, IPv4 ttl=53 df=0x40, TCP PSH-ACK win=245 | tls: {'tls.record.content_typ | ✅ | tcp/udp |
| IPv6 | TCP | 62763 | 12 | tcp | Eth 0x86dd, IPv6, TCP PSH-ACK win=245 | tls: {'tls.record.content_typ | ✅ | tcp/udp |
| IP | TCP | 67 | 1 | dhcp | Eth 0x0800, IPv4 ttl=128 df=0x00, UDP len=308 | dhcp: 1, 0x01, 6 | ✅ | dhcp |
| IP | TCP | 68 | 1 | dhcp | Eth 0x0800, IPv4 ttl=64 df=0x00, UDP len=556 | dhcp: 2, 0x01, 6 | ✅ | dhcp |
| IP | TCP | 6868 | 24 | data | Eth 0x0800, IPv4 ttl=64 df=0x40, TCP SYN win=29200 MSS/WScale | — | ✅ | tcp |
| IPv6 | TCP | 6868 | 24 | data | Eth 0x86dd, IPv6, TCP SYN win=29200 MSS/WScale | — | ✅ | tcp |
| IP | TCP | 7611 | 3 | data | Eth 0x0800, IPv4 ttl=50 df=0x40, TCP SYN win=14600 MSS/WScale | — | ✅ | tcp |
| IP | TCP | 80 | 46 | http | Eth 0x0800, IPv4 ttl=128 df=0x00, TCP SYN win=32768 MSS/WScale | — | ✅ | http |
| IPv6 | TCP | 80 | 46 | http | Eth 0x86dd, IPv6, TCP SYN win=32768 MSS/WScale | — | ✅ | http |
| IP | TCP | 8000 | 47 | http | Eth 0x0800, IPv4 ttl=64 df=0x40, TCP SYN win=64240 MSS/WScale | — | ✅ | http |
| IPv6 | TCP | 8000 | 11 | http | Eth 0x86dd, IPv6, TCP SYN win=64240 MSS/WScale | — | ✅ | http |
| IPv6 | TCP | 8001 | 2 | http | Eth 0x86dd, IPv6, TCP SYN win=32768 MSS/WScale | — | ✅ | http |
| IPv6 | TCP | 8002 | 2 | http | Eth 0x86dd, IPv6, TCP SYN win=32768 MSS/WScale | — | ✅ | http |
| IP | TCP | 8081 | 1 | http | Eth 0x0800, IPv4 ttl=128 df=0x00, TCP SYN win=32768 MSS/WScale | — | ✅ | http |
| IP | TCP | 8088 | 1 | http | Eth 0x0800, IPv4 ttl=52 df=0x40, TCP SYN win=14600 MSS/WScale | — | ✅ | http |
| IP | TCP | 8880 | 2 | http | Eth 0x0800, IPv4 ttl=64 df=0x40, TCP SYN win=64240 MSS/WScale | — | ✅ | http |
| IP | TCP | 993 | 12 | tls | Eth 0x0800, IPv4 ttl=128 df=0x40, TCP SYN win=8192 MSS/WScale | — | ✅ | tls |
| IPv6 | TCP | 993 | 12 | tls | Eth 0x86dd, IPv6, TCP SYN win=8192 MSS/WScale | — | ✅ | tls |
| IP | TCP | 995 | 12 | tls | Eth 0x0800, IPv4 ttl=64 df=0x40, TCP SYN win=8192 MSS/WScale | — | ✅ | tls |
| IPv6 | TCP | 995 | 12 | tls | Eth 0x86dd, IPv6, TCP SYN win=8192 MSS/WScale | — | ✅ | tls |
| IP | TCP | 9999 | 3 | tcp | Eth 0x0800, IPv4 ttl=64 df=0x00, TCP SYN win=8192 | — | ✅ | tcp/udp |
| IPv6 | TCP | 9999 | 3 | tcp | Eth 0x86dd, IPv6, TCP SYN win=8192 | — | ✅ | tcp/udp |
| IP | UDP | 123 | 12 | ntp | Eth 0x0800, IPv4 ttl=32 df=0x40, UDP len=116 | ntp: 0xe3, {'ntp.flags.li_raw': ['3, 0 | ✅ | ntp |
| IPv6 | UDP | 123 | 12 | ntp | Eth 0x86dd, IPv6, UDP len=116 | ntp: 0xe3, {'ntp.flags.li_raw': ['3, 0 | ✅ | ntp |
| IP | UDP | 161 | 21 | snmp | Eth 0x0800, IPv4 ttl=64 df=0x40, UDP len=45 | snmp: 0, public, 1 | ✅ | snmp |
| IPv6 | UDP | 161 | 21 | snmp | Eth 0x86dd, IPv6, UDP len=45 | snmp: 0, public, 1 | ✅ | snmp |
| IP | UDP | 17767 | 12 | data | Eth 0x0800, IPv4 ttl=128 df=0x00, UDP len=368 | data: 4b:55:00:03:00:00:01:68:, 360 | ✅ | tcp |
| IPv6 | UDP | 17767 | 12 | data | Eth 0x86dd, IPv6, UDP len=368 | data: 4b:55:00:03:00:00:01:68:, 360 | ✅ | tcp |
| IP | UDP | 1813 | 12 | radius | Eth 0x0800, IPv4 ttl=255 df=0x00, UDP len=489 | radius: 4, 159, 481 | ⚠️ | udp |
| IPv6 | UDP | 1813 | 12 | radius | Eth 0x86dd, IPv6, UDP len=489 | radius: 4, 159, 481 | ⚠️ | udp |
| IP | UDP | 1900 | 12 | ssdp | Eth 0x0800, IPv4 ttl=1 df=0x00, UDP len=182 | ssdp: {'_ws.expert': {'http.ch, 239.255.255.250:1900, USER-AGENT: Google Chrom | ✅ | ssdp |
| IPv6 | UDP | 1900 | 12 | ssdp | Eth 0x86dd, IPv6, UDP len=182 | ssdp: {'_ws.expert': {'http.ch, 239.255.255.250:1900, USER-AGENT: Google Chrom | ✅ | ssdp |
| IP | UDP | 22448 | 6 | data | Eth 0x0800, IPv4 ttl=128 df=0x00, UDP len=49 | data: 65:af:12:6f:e1:9b:a3:2e:, 41 | ✅ | tcp |
| IPv6 | UDP | 22448 | 6 | data | Eth 0x86dd, IPv6, UDP len=49 | data: 65:af:12:6f:e1:9b:a3:2e:, 41 | ✅ | tcp |
| IP | UDP | 31601 | 12 | udp | Eth 0x0800, IPv4 ttl=64 df=0x40, UDP len=120 | — | ✅ | tcp/udp |
| IPv6 | UDP | 31601 | 12 | udp | Eth 0x86dd, IPv6, UDP len=120 | — | ✅ | tcp/udp |
| IP | UDP | 4500 | 12 | isakmp | Eth 0x0800, IPv4 ttl=32 df=0x40, UDP len=88 | isakmp: 75:5c:d6:7e:8f:61:d1:de, fc:ac:65:91:5e:71:2c:05, 5 | ✅ | ike_nat_t |
| IPv6 | UDP | 4500 | 12 | isakmp | Eth 0x86dd, IPv6, UDP len=88 | isakmp: 75:5c:d6:7e:8f:61:d1:de, fc:ac:65:91:5e:71:2c:05, 5 | ✅ | ike_nat_t |
| IP | UDP | 53 | 15 | dns | Eth 0x8100, VLAN 1160, IPv4 ttl=64 df=0x00, UDP len=45 | dns: 0x6b3b, 0x0100, {'dns.flags.response_raw | ✅ | dns |
| IPv6 | UDP | 53 | 12 | dns | Eth 0x8100, VLAN 1160, IPv6, UDP len=45 | dns: 0x6b3b, 0x0100, {'dns.flags.response_raw | ✅ | dns |
| IP | UDP | 5353 | 12 | mdns | Eth 0x0800, IPv4 ttl=255 df=0x00, UDP len=50 | mdns: 0x0000, 0x0000, {'dns.flags.response_raw | ✅ | mdns |
| IPv6 | UDP | 5353 | 12 | mdns | Eth 0x86dd, IPv6, UDP len=58 | mdns: 0x0000, 0x0000, {'dns.flags.response_raw | ✅ | mdns |
| IPv6 | UDP | 547 | 12 | dhcpv6 | Eth 0x86dd, IPv6, UDP len=44 | dhcpv6: 11, 0xe5786c, Option Request | ✅ | dhcpv6 |
| IP | UDP | 67 | 12 | dhcp | Eth 0x0800, IPv4 ttl=64 df=0x00, UDP len=308 | dhcp: 1, 0x01, 6 | ✅ | dhcp |
| IP | UDP | 69 | 12 | data | Eth 0x0800, IPv4 ttl=32 df=0x40, UDP len=44 | tftp: 1, bootB-p-SnaT237952db.img, netascii | ✅ | tcp |
| IPv6 | UDP | 69 | 12 | data | Eth 0x86dd, IPv6, UDP len=44 | tftp: 1, bootB-p-SnaT237952db.img, netascii | ✅ | tcp |

## 四、特殊命名文件分析表单

> 文件名不含标准编码,按 tshark 识别结果归类。

| 文件(相对路径) | 大小 | 协议栈 | 数据内容样例 | 造流判定 | 说明 |
|----------------|------|--------|-------------|---------|------|
| llcj_pcap.pcap | 548269K | eth:ethertype:ip:icmp | — | ✅ | icmp planner 支持 Echo Request/Reply |
| llcj_mirror.pcap | 542905K | eth:ethertype:ip:icmp | — | ✅ | icmp planner 支持 Echo Request/Reply |
| xiaoshuo_txt5m_192.168.43.2_17894_192.168.1.1_80_moreget40.pcap | 220761K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| fiter.pcap | 187265K | eth:ethertype:ip:icmp | 8, 0, 0x9901 | ✅ | icmp planner 支持 Echo Request/Reply |
| monitor.pcap | 187231K | eth:ethertype:ip:icmp | — | ✅ | icmp planner 支持 Echo Request/Reply |
| bc/180001310_001001_1321202409121143520960610002000.pcap | 137523K | eth:ethertype:ip:tcp:data | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| bc/pcapdump_16.pcap | 58771K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| 0x31+0x04a1+1010000059814+3++RZX+001001+0+20260128094000952000.pcap | 57592K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| httptxt_80m_192.168.31.101_59437_23.224.171.42_80.pcap | 57541K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| rs/smtp_ipa_5ca672688d571f2b5d5dd4cd62a13934.pcap | 54317K | eth:ethertype:ip:tcp | — | ✅ | smtp planner 支持 |
| rs/pop_ipa_5ca672688d571f2b5d5dd4cd62a13934.pcap | 50161K | eth:ethertype:ip:tcp | — | ✅ | pop3 planner 支持 |
| accesslog.pcap | 45636K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| rs/ftp_ipa_5ca672688d571f2b5d5dd4cd62a13934.pcap | 36460K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| bc/pcapdump_10.pcap | 33889K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| rs/smtp_apk_ffa1fda3e10399e6a8d942033bb38099.pcap | 22652K | eth:ethertype:ip:tcp | — | ✅ | smtp planner 支持 |
| mypcap/publicpcap/Radius/HN_radius3.pcap | 22120K | eth:ethertype:ip:udp:radius | 1, 206, 264 | ⚠️ | 无 RADIUS planner,用 udp planner 造字节 |
| mypcap/publicpcap/Radius/HN_radius4.pcap | 22120K | eth:ethertype:ip:udp:radius | — | ⚠️ | 无 RADIUS planner,用 udp planner 造字节 |
| rs/pop_apk_ffa1fda3e10399e6a8d942033bb38099.pcap | 20478K | eth:ethertype:ip:tcp | — | ✅ | pop3 planner 支持 |
| rs/ftp_apk_ffa1fda3e10399e6a8d942033bb38099.pcap | 14448K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| rs/http_apk_ffa1fda3e10399e6a8d942033bb38099.pcap | 14402K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/xdr2/audio_ipv4.pcap | 7396K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bc/pcapdump_7.pcap | 7362K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bc/pcapdump_15.pcap | 7359K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bc/pcapdump_6.pcap | 6141K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| bc/pcapdump_6x.pcap | 6141K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| bc/pcapdump_11.pcap | 6139K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| bc/pcapdump_4.pcap | 6138K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| bc/pcapdump_2.pcap | 6137K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| bc/pcapdump_3.pcap | 5962K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| bc/pcapdump_1.pcap | 5960K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| bc/pcapdump_14.pcap | 5959K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bc/pcapdump_12.pcap | 5959K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| bc/pcapdump_12x.pcap | 5958K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| bc/pcapdump_5.pcap | 5957K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| bc/pcapdump_8.pcap | 5804K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bc/pcapdump_13.pcap | 5803K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bc/pcapdump_8x.pcap | 5803K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bc/pcapdump_9.pcap | 4624K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| rs/http_ipa_b6a5cf9219a5419d81e738389abf232e.pcap | 4081K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/4/4-10.pcap | 3989K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/get_field/get_jpeg.pcap | 3989K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bzip/IP-TCP-10.6.1.11-20.6.1.11-29379-80-6-4-429-3381_1000.pcap | 3877K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bzip/IP-TCP-20.5.1.11-30.5.1.11-29379-80-6-4-429-3381_1000.pcap | 3877K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| VPN/SHADOWSOCKS/SHADOWSOCKS-1.pcap | 2638K | eth:ethertype:ip:tcp | — | ✅ | shadowsocks planner 已实现(tshark 不识别加密流) |
| mypcap/publicpcap/IPv4/sip/SIP_Endpoint6.pcap | 2526K | eth:ethertype:ip:tcp | — | ✅ | sip planner 支持信令+媒体 |
| mypcap/publicpcap/Radius/AAA_Radius.pcap | 2491K | eth:ethertype:arp | — | ✅ | arp planner 完整支持 |
| mypcap/test/1/1-20.pcap | 2431K | eth:ethertype:ip:tcp:http:data | 8)L$X�IG����VvX��A�, {'_ws.expert': {'http., B���a�y0�A(>�S�j�;r | ✅ | tcp planner 造原始字节流 |
| mypcap/test/1/1-19.pcap | 2411K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/4/4-9.pcap | 2184K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/https/tengxuhuiyi.pcap | 2064K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/tengxuhuiyi.pcap | 2064K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/test/4/4-8.pcap | 2029K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bzip/IP-TCP-10.3.1.1-20.3.1.1-8604-80-5-2-371-1231_1000.pcap | 1674K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bzip/IP-TCP-10.6.1.1-20.6.1.1-8604-80-5-2-371-1231_1000.pcap | 1674K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bzip/IP-TCP-10.1.1.1-20.1.1.1-8604-80-5-2-361-1231_1000.pcap | 1664K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bzip/IP-TCP-10.9.1.2-20.9.1.2-4537-80-5-2-361-1226_1000.pcap | 1659K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/email/M_SMTP.pcap | 1597K | eth:ethertype:ip:tcp | — | ✅ | smtp planner 支持 |
| mypcap/test/1/1-18.pcap | 1414K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/xdr2/video_ipv4.pcap | 1190K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bzip/IPv6-TCP-2e02__1208-2e03__1208-10650-80-4-3-378-481_1000.pcap | 948K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bzip/IPv6-TCP-2e02__201-2e03__201-21592-80-4-3-377-481_1000.pcap | 947K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bzip/IPv6-TCP-2e02__60c-2e03__60c-10650-80-4-3-377-481_1000.pcap | 947K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bzip/IPv6-TCP-2e02__c0c-2e03__c0c-10650-80-4-3-377-481_1000.pcap | 947K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/https/https_yichang_checksumgoogle.pcap | 812K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/https_yichang_checksumgoogle.pcap | 812K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPV4_9gongzhi.pcap | 794K | eth:ethertype:ip:tcp | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/idc3/10、vlan_http.pcap | 765K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-35.pcap | 593K | eth:ethertype:ip:tcp:tls | Transport Layer Security | ✅ | tcp planner 造原始字节流 |
| mypcap/test/4/4-7.pcap | 531K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| fz/post_txt_utf_8.pcap | 512K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/idc3/2.gtp_tunneling_udp.pcap | 493K | eth:ethertype:ip:udp:gtp:ip:udp:data | 80:00:ae:33:21:4e:79:9, 172 | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/test/1/1-17.pcap | 447K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/4/4-6.pcap | 440K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/https/HTTPs_oa_fenbao.pcap | 435K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/https/HTTPs_oa_fenbao.pcap | 435K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/HTTP_up1.0_dw1.1.pcap | 431K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/https/shunfeng.pcap | 428K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/shunfeng.pcap | 428K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| VPN/vmess/vmess.pcap | 416K | eth:ethertype:ip:tcp | — | ✅ | vmess planner 已实现(tshark 不识别加密流) |
| mypcap/publicpcap/IPv4/ipframe20get.pcap | 391K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/test/1/1-16.pcap | 346K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/sip/sip_rtp_ipv4.pcap | 326K | eth:ethertype:ip:tcp | — | ✅ | sip planner 支持信令+媒体 |
| mypcap/publicpcap/IPV6/sip_rtp_ipv6.pcap | 321K | eth:ethertype:ipv6:tcp | — | ✅ | sip planner 支持信令+媒体 |
| mypcap/publicpcap/IPv4/sip/sip_rtp_ipv6.pcap | 321K | eth:ethertype:ipv6:tcp | — | ✅ | sip planner 支持信令+媒体 |
| mypcap/test/1/1-15.pcap | 312K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/2/2-18.pcap | 289K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/1/1-14.pcap | 287K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/IPV6_mix.pcap | 264K | eth:ethertype:ipv6:ipv6.hopopts:icmpv6 | 131, 0, 0x810d | ✅ | icmpv6 planner 支持 Echo + 邻居发现 |
| mypcap/publicpcap/IPV6/IPV6_mix.pcap | 264K | eth:ethertype:ipv6:ipv6.hopopts:icmpv6 | — | ✅ | icmpv6 planner 支持 Echo + 邻居发现 |
| mypcap/test/2/2-17.pcap | 242K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/2/2-16.pcap | 212K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/app_pcap/9.驱动精灵.pcap | 212K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/ipv6_radius.pcap | 209K | eth:ethertype:ipv6:udp:radius | 1, 2, 336 | ⚠️ | 无 RADIUS planner,用 udp planner 造字节 |
| mypcap/publicpcap/IPV6/ipv6_radius.pcap | 209K | eth:ethertype:ipv6:udp:radius | — | ⚠️ | 无 RADIUS planner,用 udp planner 造字节 |
| mypcap/test/1/1-13.pcap | 202K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-34.pcap | 178K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| VPN/wireguard/WIREGUARD_15.pcap | 171K | eth:ethertype:ip:udp:wg | — | ✅ | wireguard planner 支持(tshark 层名 wg) |
| mypcap/test/1/1-12.pcap | 169K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| VPN/wireguard/WIREGUARD_12.pcap | 166K | eth:ethertype:ip:udp:wg | 4, 00:00:00, 0x13cf755c | ✅ | wireguard planner 支持(tshark 层名 wg) |
| mypcap/publicpcap/IPv4/http/more_post.pcap | 166K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/test/3/3-33.pcap | 164K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/4/4-5.pcap | 161K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| VPN/wireguard/WIREGUARD_13.pcap | 146K | eth:ethertype:ip:udp:wg | — | ✅ | wireguard planner 支持(tshark 层名 wg) |
| mypcap/sendpcap/mirror/POP3_150.pcap | 138K | eth:ethertype:ip:tcp | — | ✅ | pop3 planner 支持 |
| mypcap/publicpcap/IPv4/email/POP3_150.pcap | 138K | eth:ethertype:ip:tcp | — | ✅ | pop3 planner 支持 |
| mypcap/test/1/1-11.pcap | 135K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http/more_post0.pcap | 133K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/IMAP.pcap | 133K | eth:ethertype:ip:tcp | — | ✅ | imap planner 支持 |
| mypcap/publicpcap/IPv4/IMAP.pcap | 133K | eth:ethertype:ip:tcp | — | ✅ | imap planner 支持 |
| mypcap/test/4/4-4.pcap | 129K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/test/3/3-32.pcap | 128K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| VPN/wireguard/WIREGUARD_14.pcap | 127K | eth:ethertype:ip:udp:wg | — | ✅ | wireguard planner 支持(tshark 层名 wg) |
| mypcap/test/4/4-3.pcap | 119K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/xdr2/text_ipv4.pcap | 118K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/ipv4_monfil_pcaps/other/big5_192.168.43.2_27708--102.168.1.1_80.pcap | 118K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/1/1-10.pcap | 117K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/get_field/get_json.pcap | 117K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-31.pcap | 117K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/ipv4_monfil_pcaps/other/utf8_192.168.43.2_27726--102.168.1.19_80.pcap | 114K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/error_fenpian.pcap | 108K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/test/2/2-15.pcap | 106K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/rtsp_rtp_ipv6.pcap | 104K | eth:ethertype:ipv6:tcp | — | ⚠️ | 无 rtsp planner,用 tcp planner 造字节,无 SDP/RTSP 语义 |
| mypcap/publicpcap/IPv4/rtsp/rtsp_rtp_ipv6.pcap | 104K | eth:ethertype:ipv6:tcp | — | ⚠️ | 无 rtsp planner,用 tcp planner 造字节,无 SDP/RTSP 语义 |
| mypcap/eu_pcaps/ipv4_monfil_pcaps/other/gb2312_192.168.43.2_27712--102.168.1.5_80.pcap | 102K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/rtsp/proto_rtsp.pcap | 102K | eth:ethertype:ip:tcp | — | ⚠️ | 无 rtsp planner,用 tcp planner 造字节,无 SDP/RTSP 语义 |
| mypcap/test/1/1-9.pcap | 100K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/4/4-1.pcap | 92K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/4/4-2.pcap | 92K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/ipv4_monfil_pcaps/other/utf16_192.168.43.2_27723--102.168.1.16_80.pcap | 86K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/1/1-8.pcap | 85K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| bc/aideo.pcap | 84K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-30.pcap | 84K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-29.pcap | 81K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-28.pcap | 78K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-27.pcap | 72K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/test/3/3-26.pcap | 70K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/test/3/3-24.pcap | 61K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-25.pcap | 61K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/2/2-14.pcap | 60K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/1/1-7.pcap | 60K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| VPN/wireguard/WIREGUARD_16.pcap | 59K | eth:ethertype:ip:udp:wg | — | ✅ | wireguard planner 支持(tshark 层名 wg) |
| mypcap/http_smtp.pcap | 54K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/1/1-6.pcap | 54K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/moreget_content.pcap | 51K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/2/2-13.pcap | 50K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/xdr2/application_ipv6.pcap | 46K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| moreget_content_dn.pcap | 44K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_tcpsegment_2_ipv6.pcap | 40K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/test/1/1-5.pcap | 39K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/ipv6_pop3.pcap | 37K | eth:ethertype:ipv6:tcp | — | ✅ | pop3 planner 支持 |
| mypcap/publicpcap/IPV6/ipv6_pop3.pcap | 37K | eth:ethertype:ipv6:tcp | — | ✅ | pop3 planner 支持 |
| mypcap/test/1/1-4.pcap | 35K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/2/2-12.pcap | 35K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_tcpsegment_2.pcap | 32K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/test/2/2-11.pcap | 31K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/1/1-3.pcap | 31K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/get_field/get_jpg.pcap | 31K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/get_field/get_zip.pcap | 31K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/1-3.pcap | 31K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-23.pcap | 30K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-22.pcap | 28K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/2/2-10.pcap | 28K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/test/12k.pcap | 26K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_tcpsegment_6_ipv6.pcap | 25K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/HTTP_up1.0_dw1.1_2.pcap | 25K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/test/2/2-9.pcap | 23K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/test/1/1-2.pcap | 23K | eth:ethertype:ip:tcp:http | — | ✅ | tcp planner 造原始字节流 |
| VPN/OPENVPN/OPENVPN_TCP_V2_HMAC-2.pcap | 23K | eth:ethertype:ip:tcp | — | ✅ | openvpn planner 支持 TCP/UDP |
| mypcap/ARD-dangdang-13-0006-V8.12.1-IM_360_public.pcap | 22K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/xdr2/png_ipv6.pcap | 21K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_tcpsegment_6.pcap | 21K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-21.pcap | 19K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/get_field/get_css.pcap | 19K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/fil_8_187_key.pcap | 19K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/8_199.pcap | 19K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-20.pcap | 19K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| VPN/OPENVPN/OPENVPN_UDP_V2_HMAC-5.pcap | 18K | eth:ethertype:ip:udp:openvpn | 0x38, {'openvpn.opcode_raw':, 9342127712127161814 | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/ftp/ftp_passive.pcap | 18K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/test/2/2-8.pcap | 18K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/2-8.pcap | 18K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/xdr/refresh.pcap | 16K | eth:ethertype:ip:tcp:http | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http/refresh.pcap | 16K | eth:ethertype:ip:tcp:http | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_code_tcpsegment_11_ipv6.pcap | 16K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/3_161.pcap | 16K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/xdr/tcp_segment_10.168.64.2_53219_10.168.3.174_80.pcap | 16K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/ipv4_monfil_pcaps/other/tcp_segment_10.168.64.2_53219_10.168.3.174_80.pcap | 16K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/7_170.pcap | 15K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/ipv4_monfil_pcaps/other/tcp_segment_10.168.64.2_49479_10.168.3.173_80.pcap | 15K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/xdr2/gif_ipv4.pcap | 15K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/ftp/FTP_port.pcap | 15K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/sendpcap/xdr/login.pcap | 15K | eth:ethertype:ip:tcp:http:urlencoded-form | {'_ws.expert': {'http., www.guanggoo.com, Cookie: _ga=GA1.2.1689 | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/login.pcap | 15K | eth:ethertype:ip:tcp:http:urlencoded-form | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/app_pcap/ARD-163_news-19-0041-V66.1-IM_wangyiwang-19-0041-02-0001_192.168.1.102_59397--112.13.119.38_443.pcap | 15K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/get_rdm.pcap | 14K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/xdr/http10.pcap | 14K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| VPN/SHADOWSOCKS/SHADOWSOCKS-4.pcap | 14K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/eu_pcaps/ipv6_monfil_pcaps/other/tcp_segment_3ffe0000000000000200ff00fe030587_16556_3ffe0000000000000200ff00fe030021_80.pcap | 14K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_code_tcpsegment_11.pcap | 13K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/ipv6_monfil_pcaps/other/tcp_segment_3ffe0000000000000200ff00fe030587_16557_3ffe0000000000000200ff00fe030021_80.pcap | 13K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/post_segment.pcap | 13K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/test/3/3-19.pcap | 13K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/200ok_segment.pcap | 13K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/test_url_2048_ipv6.pcap | 13K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/longurl_ipframe.pcap | 12K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/test_url_2048.pcap | 12K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/app_pcap/jingdong.pcap | 12K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/longurl_normal.pcap | 12K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/xdr/longurl_normal.pcap | 12K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv4_post_10.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_11.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_12.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_13.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_14.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_15.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_16.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_17.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_18.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_19.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_20.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_1.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_2.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_3.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_4.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_5.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_6.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_7.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_8.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_9.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_dport_0.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_dport_65535.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_dport_81.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_dport_82.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_dport_83.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_dport_84.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_dport_85.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/xdr2/ipv4_post_1.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/xdr2/post_ipv4.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_21.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_22.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_23.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_24.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv4_post_25.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/jinritoutiao.pcap | 11K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/sip/sip002551.pcap | 10K | eth:ethertype:ip:udp:sip | REGISTER sip:211.150.6, {'sip.Method_raw': ['5, Via: SIP/2.0/UDP 172.3 | ✅ | sip planner 支持信令+媒体 |
| mypcap/publicpcap/xdr2/sip002551.pcap | 10K | eth:ethertype:ip:udp:sip | — | ✅ | sip planner 支持信令+媒体 |
| mypcap/sendpcap/xdr/visit.pcap | 10K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/visit.pcap | 10K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/get_field/get_gif.pcap | 10K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/app_pcap/tuiaguanegaopintai.pcap | 10K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/https/ofobike_B.pcap | 10K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/ofobike_B.pcap | 10K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/eu_pcaps/ipv4_monfil_pcaps/other/gzip_192.168.1.3_6819_10.168.1.3_80.pcap | 9K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-18.pcap | 9K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_cookie_long_ipv6.pcap | 9K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/sendpcap/xdr/http11.pcap | 9K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/http11.pcap | 9K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_longURL4118_2_ipv6.pcap | 9K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_user_agent_long_ipv6.pcap | 9K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_cookie_long.pcap | 9K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/sendpcap/xdr/http9.pcap | 9K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/http9.pcap | 9K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| url_2050_IP-TCP-10.1.1.221-20.1.1.5-53336-80-5-6-2584-6110.pcap | 9K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| url_2049_IP-TCP-10.1.1.221-20.1.1.4-53336-80-4-6-2517-6110.pcap | 9K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| url_2048_IP-TCP-10.1.1.221-20.1.1.3-53336-80-4-6-2516-6110.pcap | 9K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_longURL4118_2.pcap | 9K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_user_agent_long.pcap | 9K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http-2get.pcap | 9K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/http10.pcap | 9K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| VPN/SHADOWSOCKS/SHADOWSOCKS-3.pcap | 9K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/get_field/get_js.pcap | 8K | eth:ethertype:ip:tcp:http | — | ✅ | tcp planner 造原始字节流 |
| VPN/SHADOWSOCKS/SHADOWSOCKS-2.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/eu_pcaps/3_84.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-17.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/https/19_0003_zhenai.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/https/19_0003_zhenai_reorder_[021]_False.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/https/19_0003_zhenai_reorder_[102]_False.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/https/19_0003_zhenai_reorder_[120]_False.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/https/19_0003_zhenai_reorder_[201]_False.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/https/19_0003_zhenai_reorder_[210]_False.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/19_0003_zhenai.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/19_0003_zhenai_reorder_[021]_False.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/19_0003_zhenai_reorder_[102]_False.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/19_0003_zhenai_reorder_[120]_False.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/19_0003_zhenai_reorder_[201]_False.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/19_0003_zhenai_reorder_[210]_False.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/https/zhenai_noack.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/zhenai_noack.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/https/zhenai_nosyn_ack.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/zhenai_nosyn_ack.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/https/zhenai_nosyn.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/zhenai_nosyn.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/https/zhenai_noack-syn_ack.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/zhenai_noack-syn_ack.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/https/zhenai_nosyn-syn_ack.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/zhenai_nosyn-syn_ack.pcap | 8K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_retran_200OK_ipv6.pcap | 8K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/https/zhenai_no3woshou.pcap | 8K | eth:ethertype:ip:tcp:tls | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/zhenai_no3woshou.pcap | 8K | eth:ethertype:ip:tcp:tls | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_ipfragment_24.pcap | 7K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_retran_200OK.pcap | 7K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/app_pcap/PC-work_weixin-01-0002-V3.0.16.1608-IM_360_public-19-0049-99-0002_192.168.1.101_15451--111.7.68.222_80.pcap | 7K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/app_pcap/ARD-360buy-13-0003-V8.5.8-IM_360buy-13-0003-01-1444_192.168.137.210_50839--106.39.164.113_443.pcap | 7K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ipfragment_22.pcap | 7K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| test.pcap | 7K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_tcpsegment_30_ipv6.pcap | 7K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/jingdong.pcap | 7K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| domain129_IP-TCP-10.1.1.221-20.1.1.2-53336-80-4-6-622-6110.pcap | 7K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| domain128_IP-TCP-10.1.1.221-20.1.1.1-53336-80-4-6-621-6110.pcap | 7K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_code_ipfragment_32.pcap | 7K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_ctype_tcpsegment_60_ipv6.pcap | 7K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/ipv6_icmp70.pcap | 7K | eth:ethertype:ipv6:ipv6.hopopts:icmpv6 | — | ✅ | icmpv6 planner 支持 Echo + 邻居发现 |
| mypcap/publicpcap/IPV6/ipv6_icmp70.pcap | 7K | eth:ethertype:ipv6:ipv6.hopopts:icmpv6 | — | ✅ | icmpv6 planner 支持 Echo + 邻居发现 |
| mypcap/idc3/5.vlan_sample.pcap | 6K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_retran_get_ipv6.pcap | 6K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| moreget_content_up.pcap | 6K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_tcpsegment_30.pcap | 6K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_tcpsegment_44_ipv6.pcap | 6K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/https/liebaobroswer.pcap | 6K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/liebaobroswer.pcap | 6K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_retran_get.pcap | 6K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/l2tp.pcap | 6K | eth:ethertype:ip:udp:l2tp:ppp:ip:tcp:tls | {'tls.record.content_t | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ctype_tcpsegment_60.pcap | 6K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| fz/post_中文内容.pcap | 6K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/test/3/3-16.pcap | 6K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_tcpsegment_44.pcap | 6K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/https/1.CSDN.pcap | 6K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPv4/https/1.CSDN.pcap | 6K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| fz/post_中文1.pcap | 6K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| JT_T808_IP-TCP-221.178.125.88-20.1.1.6-9968-7611-29-28-2723-2038.pcap | 6K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ipfragment_42.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ctype_ipfragment_80.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/ftp/Ftp_download.pcap | 5K | eth:ethertype:arp | — | ✅ | icmpv6 planner 支持 Echo + 邻居发现 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_tcpsegment_244_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/2/2-7.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ipfragment_68.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_tcpsegment_180_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_user_agent_tcpsegment_180_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_tcpsegment_244.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/fil_3_41_srcip.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/smtp3.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | smtp planner 支持 |
| mypcap/publicpcap/IPv4/email/smtp3.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | smtp planner 支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_retran_ack_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_retran_rst_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_retran_syn-ack_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_retran_syn_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_ipfragment_264.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/test/3/3-14.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-15.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_host_base64_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get_ipfragment_600.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_get_ipfragment_601.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_get_ipfragment_602.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_user_agent_repeat_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/2/2-6.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_base64_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_cookie_repeat_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/app_pcap/weixing.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/test/2/2-5.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_cookie_wrap_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_tcpsegment_180.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_user_agent_tcpsegment_180.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_host_special_symbols_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_host_special_symbols_不带管道连接符_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_special_symbols_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_repeat_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-13.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_ISO88591_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_GB18030_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_tcpsegment_530_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_8UTF8_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_UTF-16_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_UTF-99_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_gb2312_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_UTF-8_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_UUU-8_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_UTF_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_big5_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_GBK_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_error_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_error3_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_char_error2_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_repeat_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ipfragment_200.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_user_agent_ipfragment_200.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_repeatURI_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_host_repeat_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_code600_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_ctype_repeat_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_repeat_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_code_repeat_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_code500_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_UpgradeHTTP20_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_code301_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_ctype_xhtml+xml_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_host_base64.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_HTTP_repeat_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_ctype_json_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_code404_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_ctype_xml_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_code100_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_code201_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_HTTP111_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_miss4_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_GETS_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_HTTP1.1_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_code_error2_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_code_error3_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_miss3_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_200OK_tcpfragment_1_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_200OK_tcpfragment_2_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_200OK_tcpfragment_3_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_HTTP09_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_HTTP10_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_HTTP11_2_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_HTTP20_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_HTTP99_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_ctype_error2_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_ctype_error3_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_ctype_error_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_dport_unusual_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_gEt_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_host2_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_reorder_1_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_reorder_2_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp:http | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_reorder_3_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_reorder_4_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_reorder_5_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_reorder_6_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_reorder_7_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response09_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response10_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response20_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_code_error_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_error2_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_error_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_sport_1025_21_dport_1025_21_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_sport_1025_66_dport_1025_66_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_sport_1025_80_dport_1025_80_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_sport_eql_dport_src_eql_dst_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_src_eql_dst_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_update_field_sport_1025_11713_dport_1025_11713_load_ContentTypetexthtml_ContentTypeTEXTHTML_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_GE_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_HTP11_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_HTTP11_3_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_HTTP11_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_HTTP1_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_ctype_textttt_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_host_miss2_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_host_miss4_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_error3_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_miss2_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_miss_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_G_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_host_ipv6_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_host_miss5_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_host_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_user_agent_repeat.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_HTTP_empty2_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_code_error5_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_error5_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_noGET_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_base64.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_host_miss3_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_host_miss7_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_code_error6_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_cookie_miss_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_retran_ack.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_retran_rst.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_retran_syn-ack.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_retran_syn.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_HTTP_empty_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_ctype_error5_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_error4_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_user_agent_miss_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_ctype_error4_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_cookie_repeat.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_response_code_error4_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_host_miss_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_host_miss8_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_host_miss6_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_cookie_wrap.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_noURI2_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_noURI_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_host_special_symbols.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_host_special_symbols_不带管道连接符.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_empty_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_special_symbols.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_noGET2_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_repeat.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_200OK_ipfragment_550.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_200OK_ipfragment_551.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_200OK_ipfragment_552.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_ISO88591.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_GB18030.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_8UTF8.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_UTF-16.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_UTF-99.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_gb2312.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_UTF-8.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_UUU-8.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_UTF.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_big5.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_GBK.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_error.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/xdr2/Http_ContentType_Multipart.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_error3.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_char_error2.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_tcpsegment_530.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_miss_ack_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_miss_rst_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_miss_syn-ack_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_miss_syn_ipv6.pcap | 5K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_repeat.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ipfragment_550.pcap | 5K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_repeatURI.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_host_repeat.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_code600.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ctype_repeat.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_cookie_miss2_ipv6.pcap | 4K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_repeat.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_code_repeat.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_code500.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_user_agent_miss2_ipv6.pcap | 4K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_UpgradeHTTP20.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_code301.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ctype_xhtml+xml.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_HTTP_repeat.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ctype_json.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_code404.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ctype_xml.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_code100.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_code201.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_HTTP111.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_miss4.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_GETS.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_HTTP1.1.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_code_error2.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_code_error3.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_miss3.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_200OK_tcpfragment_1.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_200OK_tcpfragment_2.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_200OK_tcpfragment_3.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_HTTP09.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_HTTP10.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_HTTP11_2.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_HTTP20.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_HTTP99.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ctype_error.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ctype_error2.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ctype_error3.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_dport_unusual.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_gEt.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_host2.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_reorder_1.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_reorder_2.pcap | 4K | eth:ethertype:ip:tcp:http | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_reorder_3.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_reorder_4.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_reorder_5.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_reorder_6.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_reorder_7.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response09.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response10.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response20.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_code_error.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_error.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_error2.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_sport_1025_21_dport_1025_21.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_sport_1025_66_dport_1025_66.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_sport_1025_80_dport_1025_80.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_sport_eql_dport_src_eql_dst.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_src_eql_dst.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_update_field_sport_1025_11713_dport_1025_11713_load_ContentTypetexthtml_ContentTypeTEXTHTML.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_GE.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_HTP11.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_HTTP1.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_HTTP11.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_HTTP11_3.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ctype_textttt.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_host_miss2.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_host_miss4.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_error3.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_miss.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_miss2.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_G.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_host_miss5.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_HTTP_empty2.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_code_error5.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_error5.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_noGET.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_host_miss3.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_host_miss7.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_code_error6.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_cookie_miss.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_HTTP_empty.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ctype_error5.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_error4.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_user_agent_miss.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_ctype_error4.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_response_code_error4.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_host_miss.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_host_miss8.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_host_miss6.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_miss_syn_syn-ack_ipv6.pcap | 4K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_noURI.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_noURI2.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_empty.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_noGET2.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_miss_ack.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_miss_rst.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_miss_syn-ack.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_miss_syn.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/2/2-4.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_miss_shake_ipv6.pcap | 4K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_cookie_miss2.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_user_agent_miss2.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_miss_syn_syn-ack.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/ipv4_monfil_pcaps/692/monit034.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/field/http/request_method/http1_1/trace0.pcap | 4K | eth:ethertype:arp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_miss_shake.pcap | 4K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| fz/post_中文1_no_down.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/eu_pcaps/ipv4_monfil_pcaps/other/utf8-keyword.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/fil_3_27_domain.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/sip/sip0211.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | sip planner 支持信令+媒体 |
| mypcap/publicpcap/xdr2/sip0211.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | sip planner 支持信令+媒体 |
| fz/post_字母数字.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/sendpcap/mirror/ipv6_imap.pcap | 4K | eth:ethertype:ipv6:tcp | — | ✅ | imap planner 支持 |
| mypcap/publicpcap/IPV6/ipv6_imap.pcap | 4K | eth:ethertype:ipv6:tcp | — | ✅ | imap planner 支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_miss_get_ipv6.pcap | 4K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/test/3/3-11.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-12.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-10.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| fz/postv6_gbk.pcap | 4K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/https.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/sendpcap/xdr/https.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/sendpcap/mirror/fenpian4.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_miss_get.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/sendpcap/mirror/RTSP.pcap | 4K | eth:ethertype:ip:tcp | — | ⚠️ | 无 rtsp planner,用 tcp planner 造字节,无 SDP/RTSP 语义 |
| mypcap/publicpcap/IPv4/rtsp/RTSP.pcap | 4K | eth:ethertype:ip:tcp | — | ⚠️ | 无 rtsp planner,用 tcp planner 造字节,无 SDP/RTSP 语义 |
| mypcap/publicpcap/IPv4/rtsp/RTSP_17.pcap | 4K | eth:ethertype:ip:tcp | — | ⚠️ | 无 rtsp planner,用 tcp planner 造字节,无 SDP/RTSP 语义 |
| mypcap/test/2/2-3.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/get_field/get_flv.pcap | 4K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_only_down_ipv6.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_only_down.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/posts1.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/ftp/up_ftp.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/sendpcap/mirror/ipv6_rtsp.pcap | 3K | eth:ethertype:ipv6:tcp:rtsp | DESCRIBE rtsp://[3FFE:, {'rtsp.method_raw': [',  | ⚠️ | 无 rtsp planner,用 tcp planner 造字节,无 SDP/RTSP 语义 |
| mypcap/publicpcap/IPV6/ipv6_rtsp.pcap | 3K | eth:ethertype:ipv6:tcp:rtsp | — | ⚠️ | 无 rtsp planner,用 tcp planner 造字节,无 SDP/RTSP 语义 |
| mypcap/publicpcap/IPv4/ftp/FTP_passive_1.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/publicpcap/IPv4/post_502badgate.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/POST_gre_nm9.pcap | 3K | eth:ethertype:vlan:ethertype:ip:gre:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/test/3/3-9.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_miss_200OK_ipv6.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_miss_200OK.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/test/2/2-2.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/fenpian6.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/test/3/3-8.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/field/http/request_method/http1_0/trace0.pcap | 3K | eth:ethertype:arp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/proto_imap.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | imap planner 支持 |
| fz/post返回包命中.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/post_Data.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/xdr/post_Data.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/ipv4_monfil_pcaps/other/gzip_192.168.43.2_29797_10.138.1.1_80.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| fz/post多关键字不命中.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/postpcap/ipv6_post_10.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_11.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_12.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_13.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_14.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_15.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_16.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_17.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_18.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_19.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_20.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_1.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_2.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_3.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_4.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_5.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_6.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_7.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_8.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_9.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_dport_0.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_dport_65535.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_dport_81.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_dport_82.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_dport_83.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_dport_84.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/postpcap/ipv6_post_dport_85.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/xdr2/ipv6_post_1.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/xdr2/post_ipv6.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/meizu.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/HTTPS_SNI_Certificates.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/sendpcap/mirror/ipv6_https.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/publicpcap/IPV6/ipv6_https.pcap | 3K | eth:ethertype:ipv6:tcp | — | ✅ | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| mypcap/sendpcap/xdr/up1_ftp.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/publicpcap/IPv4/ftp/up1_ftp.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/publicpcap/xdr2/ftp_up.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/publicpcap/IPv4/get-segment-http.pcap | 3K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/ipv6_sip.pcap | 2K | eth:ethertype:ipv6:udp:sip:sdp | INVITE sip:wr@[3FFE:0:, {'sip.Method_raw': ['4, Via: SIP/2.0/UDP [3ffe | ✅ | sip planner 支持信令+媒体 |
| mypcap/publicpcap/IPV6/ipv6_sip.pcap | 2K | eth:ethertype:ipv6:udp:sip:sdp | — | ✅ | sip planner 支持信令+媒体 |
| mypcap/publicpcap/IPv4/ftp/FTP_nopassive_dw16.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/sendpcap/mirror/smtp.pcap | 2K | eth:ethertype:ipv6:tcp | — | ✅ | smtp planner 支持 |
| mypcap/publicpcap/IPV6/smtp.pcap | 2K | eth:ethertype:ipv6:tcp | — | ✅ | smtp planner 支持 |
| mypcap/app_name_http.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/ftp/FTP_passive_dw15.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/test/3/3-7.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/get_field/get_png.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-6.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_miss_get_200OK_ipv6.pcap | 2K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/xdr2/application_ipv4.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/idc3/7、mpls_http.pcap | 2K | eth:ethertype:mpls:pwethheuristic:pwethcw:eth:ethertype:ip:t | 2859, 0, 1 | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/ipv6_ftp_NoData.pcap | 2K | eth:ethertype:ipv6:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/publicpcap/IPV6/ipv6_ftp_NoData.pcap | 2K | eth:ethertype:ipv6:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_miss_get_200OK.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_post_tcpsegment_350_ipv6.pcap | 2K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_post_tcpsegment_351_ipv6.pcap | 2K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_post_tcpsegment_352_ipv6.pcap | 2K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/sip/SIP_UDP6.pcap | 2K | eth:ethertype:ip:udp:sip:sdp | INVITE sip:wr@192.168., {'sip.Method_raw': ['4, Via: SIP/2.0/UDP 192.1 | ✅ | sip planner 支持信令+媒体 |
| mypcap/publicpcap/IPv4/sip/sip0201.pcap | 2K | eth:ethertype:ip:udp:sip:sdp | — | ✅ | sip planner 支持信令+媒体 |
| mypcap/publicpcap/xdr2/sip0201.pcap | 2K | eth:ethertype:ip:udp:sip:sdp | — | ✅ | sip planner 支持信令+媒体 |
| mypcap/publicpcap/IPV6/http_post_ipfragment_450.pcap | 2K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_post_ipfragment_451.pcap | 2K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_post_ipfragment_452.pcap | 2K | eth:ethertype:ipv6:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/777.pcap | 2K | eth:ethertype:vlan:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/SIP.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | sip planner 支持信令+媒体 |
| mypcap/publicpcap/IPv4/sip/SIP.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | sip planner 支持信令+媒体 |
| mypcap/publicpcap/xdr2/text_ipv6.pcap | 2K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/POST_zhengchang.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| fz/post_字母数字_no_down.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/2222.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_post_tcpsegment_350.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_post_tcpsegment_351.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_post_tcpsegment_352.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/test/2/2-1_gtp.pcap | 2K | eth:ethertype:ip:udp:gtp:ip:tcp | 0x30, {'gtp.flags.version_ra, 0xff | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_post_ipfragment_350.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_post_ipfragment_351.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_post_ipfragment_352.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/sendpcap/mirror/ipv6_smtp.pcap | 2K | eth:ethertype:ipv6:tcp:smtp | — | ✅ | smtp planner 支持 |
| mypcap/publicpcap/IPV6/ipv6_smtp.pcap | 2K | eth:ethertype:ipv6:tcp:smtp | — | ✅ | smtp planner 支持 |
| mypcap/sendpcap/mirror/dw_ftp.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/publicpcap/IPv4/ftp/dw_ftp.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/publicpcap/xdr2/ftp_dw.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/publicpcap/IPv4/ftp/ftp_port0.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/publicpcap/IPv4/ftp/FTP_passive_0.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/eu_pcaps/fil_1_8_url.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/s2.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/ipv4_monfil_pcaps/other/1036-url.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/idc3/9、pppoe_http.pcap | 2K | eth:ethertype:pppoes:ppp:ip:tcp:http | {'_ws.expert': {'http., www.heise.de, Referer: http://www.he | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-5.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/eu_pcaps/3_1.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/http_longurl.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/2/2-1.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/2-1.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/sip/portion_sip.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | sip planner 支持信令+媒体 |
| mypcap/publicpcap/IPv4/ftp/ftp_port1.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/test/3/3-4.pcap | 2K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/http_getlong.pcap | 2K | eth:ethertype:ip:udp:data | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_only_200OK_ipv6.pcap | 2K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_only_200OK.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/sendpcap/xdr/http_up5.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/http/http_up5.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/GET.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/ProtoPcap/02_0009_02_baofeng.pcap | 1K | eth:ethertype:ip:udp:data | 28:23:18:be:84:e1:6c:c, 48 | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/https/02_0009_02_baofeng.pcap | 1K | eth:ethertype:ip:udp:data | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/https/02_0009_02_baofeng.pcap | 1K | eth:ethertype:ip:udp:data | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/test/3/3-3.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-2.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_only_up_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/dns/DNS_TCP_gtp101001.pcap | 1K | eth:ethertype:ip:udp:gtp:ip:tcp | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/IPv4/dns/DNS_TCP_gtp101007.pcap | 1K | eth:ethertype:ip:udp:gtp:ip:tcp | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_only_up.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| JT_T809_IP-TCP-27.17.20.222-20.1.1.7-58164-14567-5-4-578-260.pcap | 1K | eth:ethertype:ip:tcp:data | 5b:00:00:00:1a:00:01:3, 26 | ✅ | tcp planner 造原始字节流 |
| mypcap/field/http/request_method/http1_0/post.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| 12.pcap | 1K | eth:ethertype:ip:tcp:http | {'_ws.expert': {'http., news.baidu.com, Cookie: BDUSS=XRZYXZWb | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/ftp/FTP_passive_up12.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/sendpcap/xdr/com.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/com/com.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_only_get_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/Radius/stop.pcap | 1K | eth:ethertype:ip:udp:radius | — | ⚠️ | 无 RADIUS planner,用 udp planner 造字节 |
| mypcap/publicpcap/IPv4/ftp/FTP_nopassive_up11.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | ftp planner 支持控制+数据面 |
| mypcap/sendpcap/xdr/get.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/field/http/request_method/http1_0/get.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_only_get.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/ipv6_http.pcap | 1K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/ipv6_http.pcap | 1K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/ipv6_http.pcap | 1K | eth:ethertype:ipv6:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/HTTP_gre_nm4.pcap | 1K | eth:ethertype:vlan:ethertype:ip:gre:ip:tcp | 0x0000, {'gre.flags.checksum_r, 0x0800 | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/field/http/request_method/http1_1/post.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/xdr/put.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/field/http/request_method/http1_1/put.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/idc3/6、gre_dns.pcap | 1K | eth:ethertype:ip:gre:ip:udp:dns | 0x4c87, 0x0100, {'dns.flags.response_r | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/Radius/start.pcap | 1K | eth:ethertype:ip:udp:radius | — | ⚠️ | 无 RADIUS planner,用 udp planner 造字节 |
| mypcap/field/http/request_method/http1_0/head.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/15http_gov_get_url_jpg_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/23http_get_url_bmp_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/24http_get_url_BMP_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/xdr/HTTP1.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/HTTP1.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/HTTP1.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/HTTP2.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/HTTP3.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/HTTP4.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/HTTP5.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/HTTP6.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/HTTP7.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/HTTP8.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/dst_port_0.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/dst_port_520.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/dst_port_65535.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/dst_port_80.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/dst_port_8080.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/http_82.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/http_special.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/xdr/delete.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/dstport_81.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/dstport_82.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/dstport_83.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/http_82.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/http_special.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/field/http/request_method/http1_1/delete.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/field/http/request_method/http1_1/get.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/15http_gov_get_url_jpg_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/23http_get_url_bmp_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/24http_get_url_BMP_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/17http_get_url_png_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/18http_get_url_PNG_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/http_get_url_woff_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/xdr/http_dw4.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http/http_dw4.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/17http_get_url_png_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/18http_get_url_PNG_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/http_get_url_woff_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/dns/TCP_DNSsmtp_1_8.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| dns/TCP_DNSHTTP_1_8.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/IPv4/ftp/up2_ftp.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | 自定义 TCP 字节流,tcp planner 直接支持 |
| mypcap/publicpcap/IPv4/dns/TCP_DNSHTTP_1_8.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/sendpcap/xdr/head.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/field/http/request_method/http1_1/head.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/http_get_url_htm_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| dns/dns_1.pcap | 1K | eth:ethertype:ip:udp:dns | 0x6b3b, 0x0100, {'dns.flags.response_r | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/sendpcap/mirror/dns.pcap | 1K | eth:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/IPv4/http_get/http_get_url_htm_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/dns/dns.pcap | 1K | eth:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/IPV6/http_get/http_get_url_mp3_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/02http_get_url_SWF_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/05http_get_url_flv_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/06http_get_url_FLV_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/07http_get_url_fla_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/08http_get_url_FLA_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/09http_get_url_flc_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/10http_get_url_FLC_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/21http_get_url_gif_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/22http_get_url_GIF_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/27http_get_url_pic_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/28http_get_url_PIC_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/31http_get_url_acc_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/32http_get_url_ACC_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/35http_get_url_raw_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/36http_get_url_RAW_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/37http_get_url_vss_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/38http_get_url_VSS_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/39http_get_url_tig_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/40http_get_url_TIG_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/41http_get_url_ogg_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/42http_get_url_OGG_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/43http_get_url_jtf_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/44http_get_url_JTF_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/45http_get_url_wav_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/46http_get_url_WAV_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/47http_get_url_mid_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/48http_get_url_MID_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/49http_get_url_jff_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/50http_get_url_JFF_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/51http_get_url_jpe_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/52http_get_url_JPE_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/53http_get_url_ape_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/54http_get_url_APE_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/55http_get_url_asf_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/56http_get_url_ASF_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/http_get_url_mp3_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/test/3/3-1.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/test/1/1-1.pcap | 1K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_get/02http_get_url_SWF_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/05http_get_url_flv_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/06http_get_url_FLV_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/07http_get_url_fla_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/08http_get_url_FLA_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/09http_get_url_flc_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/10http_get_url_FLC_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/21http_get_url_gif_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/22http_get_url_GIF_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/27http_get_url_pic_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/28http_get_url_PIC_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/31http_get_url_acc_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/32http_get_url_ACC_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/35http_get_url_raw_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/36http_get_url_RAW_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/37http_get_url_vss_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/38http_get_url_VSS_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/39http_get_url_tig_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/40http_get_url_TIG_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/41http_get_url_ogg_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/42http_get_url_OGG_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/43http_get_url_jtf_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/44http_get_url_JTF_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/45http_get_url_wav_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/46http_get_url_WAV_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/47http_get_url_mid_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/48http_get_url_MID_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/49http_get_url_jff_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/50http_get_url_JFF_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/51http_get_url_jpe_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/52http_get_url_JPE_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/53http_get_url_ape_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/54http_get_url_APE_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/55http_get_url_asf_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/56http_get_url_ASF_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/25http_get_url_ico_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/26http_get_url_ICO_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/13http_get_url_js_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/14http_get_url_JS_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/Radius/radius_other.pcap | 1K | eth:ethertype:ip:udp:radius | — | ⚠️ | 无 RADIUS planner,用 udp planner 造字节 |
| mypcap/publicpcap/IPv4/http_get/25http_get_url_ico_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/26http_get_url_ICO_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/13http_get_url_js_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/14http_get_url_JS_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| dns/dns_more4A1.pcap | 1K | eth:ethertype:vlan:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/IPV6/http_get/03http_get_url_flac_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/04http_get_url_FLAC_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/19http_get_url_jpeg_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/20http_get_url_JPEG_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/29http_get_url_webp_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/30http_get_url_WEBP_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/33http_get_url_tiff_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/34http_get_url_TIFF_2_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/16http_get_url_JPG_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/03http_get_url_flac_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/04http_get_url_FLAC_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/19http_get_url_jpeg_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/20http_get_url_JPEG_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/29http_get_url_webp_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/30http_get_url_WEBP_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/33http_get_url_tiff_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/34http_get_url_TIFF_2.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/16http_get_url_JPG_1.pcap | 1K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/01http_get_url_swf_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/http_get_url_svg_1_ipv6.pcap | 1K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/01http_get_url_swf_1.pcap | 0K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/http_get_url_svg_1.pcap | 0K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/11http_get_url_css_1_ipv6.pcap | 0K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPV6/http_get/12http_get_url_CSS_2_ipv6.pcap | 0K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/11http_get_url_css_1.pcap | 0K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/publicpcap/IPv4/http_get/12http_get_url_CSS_2.pcap | 0K | eth:ethertype:ip:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| dns/dns_recode_1.pcap | 0K | eth:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/four.pcap | 0K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/dns/dns_baidu.pcap | 0K | eth:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/IPv4/dns/dns_recode_1.pcap | 0K | eth:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/xdr2/dns_recode_1.pcap | 0K | eth:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/Radius/stop-13.pcap | 0K | eth:ethertype:ip:udp:radius | — | ⚠️ | 无 RADIUS planner,用 udp planner 造字节 |
| mypcap/publicpcap/Radius/stop-28.pcap | 0K | eth:ethertype:ip:udp:radius | — | ⚠️ | 无 RADIUS planner,用 udp planner 造字节 |
| dns/dns_more4A.pcap | 0K | eth:ethertype:vlan:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/idc3/3.mpls2.5_sample.pcap | 0K | eth:ethertype:mpls:ip:udp:ldp | 16, 6, 1 | ✅ | udp planner 造原始字节流 |
| mypcap/publicpcap/Radius/portion_Radius.pcap | 0K | eth:ethertype:ip:udp:radius | — | ⚠️ | 无 RADIUS planner,用 udp planner 造字节 |
| mypcap/publicpcap/Radius/start-28.pcap | 0K | eth:ethertype:ip:udp:radius | — | ⚠️ | 无 RADIUS planner,用 udp planner 造字节 |
| mypcap/publicpcap/Radius/start-13.pcap | 0K | eth:ethertype:ip:udp:radius | — | ⚠️ | 无 RADIUS planner,用 udp planner 造字节 |
| mypcap/idc3/4.pppoe_sample.pcap | 0K | eth:ethertype:pppoes:ppp:lcp | 0xc021 | ⚠️ | PPPoE LCP,无 PPPoE planner,字节级兜底 |
| dns/DNS_v4_vlan.pcap | 0K | eth:ethertype:vlan:ethertype:ip:udp:dns | 0x2f2b, 0x0100, {'dns.flags.response_r | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/IPv4/dns/DNS_v4_vlan.pcap | 0K | eth:ethertype:vlan:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/Radius/radius_one.pcap | 0K | eth:ethertype:ip:udp:radius | — | ⚠️ | 无 RADIUS planner,用 udp planner 造字节 |
| dns/dns_moreA.pcap | 0K | eth:ethertype:vlan:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| syn.pcap | 0K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/sendpcap/mirror/ipv6_dns.pcap | 0K | eth:ethertype:ipv6:udp:dns | 0x002a, 0x0000, {'dns.flags.response_r | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/IPV6/ipv6_dns.pcap | 0K | eth:ethertype:ipv6:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| dns/dns_recode_2.pcap | 0K | eth:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/IPv4/dns/dns_recode_2.pcap | 0K | eth:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/xdr2/dns_recode_2.pcap | 0K | eth:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/dns_test.pcap | 0K | eth:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| dns/dns_recode_3.pcap | 0K | eth:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/IPv4/dns/dns_recode_3.pcap | 0K | eth:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/publicpcap/xdr2/dns_recode_3.pcap | 0K | eth:ethertype:ip:udp:dns | — | ✅ | dns planner 支持 A/AAAA/CNAME 等 |
| mypcap/ipv6_http2.pcap | 0K | eth:ethertype:ipv6:tcp:http | {'_ws.expert': {'http., www.actipv618.com, Connection: Keep-Alive | ✅ | http planner 完整支持 GET/POST 等 |
| mypcap/sendpcap/mirror/ipv6_http2.pcap | 0K | eth:ethertype:ipv6:tcp:http | — | ✅ | http planner 完整支持 GET/POST 等 |
| SCTP_NAS.pcap | 0K | eth:ethertype:ip:sctp:ngap:ngap:nas-5gs | 38413, 38412, 0x10041003 | ⚠️ | 无 NGAP/NAS-5GS planner,SCTP 层可造 |
| arp_1.pcap | 0K | eth:ethertype:arp | — | ✅ | arp planner 完整支持 |
| mypcap/sendpcap/mirror/ipv6_icmp1.pcap | 0K | eth:ethertype:ipv6:ipv6.hopopts:icmpv6 | — | ✅ | icmpv6 planner 支持 Echo + 邻居发现 |
| mypcap/publicpcap/IPV6/ipv6_icmp1.pcap | 0K | eth:ethertype:ipv6:ipv6.hopopts:icmpv6 | — | ✅ | icmpv6 planner 支持 Echo + 邻居发现 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_only_ack_ipv6.pcap | 0K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_only_rst_ipv6.pcap | 0K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_only_syn-ack_ipv6.pcap | 0K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPV6/http_illegal/http_get_only_syn_ipv6.pcap | 0K | eth:ethertype:ipv6:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/idc3/1.ARPoverGRE.pcap | 0K | eth:ethertype:ip:gre:arp | 0x0000, {'gre.flags.checksum_r, 0x0806 | ✅ | arp planner 完整支持 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_only_ack.pcap | 0K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_only_rst.pcap | 0K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_only_syn-ack.pcap | 0K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| mypcap/publicpcap/IPv4/http_illegal/http_get_only_syn.pcap | 0K | eth:ethertype:ip:tcp | — | ✅ | tcp planner 造原始字节流 |
| 11.pcap | 0K | eth:ethertype:vlan:ethertype:ip | — | ⚠️ | 未识别协议 ip,用 tcp/udp planner 字节级兜底 |

## 五、按目录造流判定汇总

| 目录 | 文件数 | ✅ | ⚠️ | ❌ | 说明 |
|------|-------|----|----|----|------|
| mypcap/eu_pcaps/ipv6_monfil_pcaps/ipv6_8314 | 8316 | 8316 | 0 | 0 |  |
| llcj_pcap | 2483 | 2216 | 267 | 0 | 含无 L7 planner 的协议(用 tcp/udp 字节级兜底) |
| llcj_mirror | 2483 | 2216 | 267 | 0 | 含无 L7 planner 的协议(用 tcp/udp 字节级兜底) |
| monitor | 1381 | 1290 | 91 | 0 | 含无 L7 planner 的协议(用 tcp/udp 字节级兜底) |
| fiter | 1339 | 1248 | 91 | 0 | 含无 L7 planner 的协议(用 tcp/udp 字节级兜底) |
| mypcap/eu_pcaps/ipv4_monfil_pcaps/692 | 693 | 693 | 0 | 0 |  |
| mypcap/publicpcap/IPv4/http_illegal | 173 | 173 | 0 | 0 |  |
| mypcap/publicpcap/IPV6/http_illegal | 156 | 156 | 0 | 0 |  |
| accesslog | 96 | 96 | 0 | 0 |  |
| mypcap/sendpcap/mirror | 73 | 70 | 3 | 0 | 含无 L7 planner 的协议(用 tcp/udp 字节级兜底) |
| fz | 62 | 62 | 0 | 0 |  |
| mypcap/publicpcap/IPV6/http_get | 60 | 60 | 0 | 0 |  |
| mypcap/publicpcap/IPv4/http_get | 60 | 60 | 0 | 0 |  |
| mypcap/postpcap | 59 | 59 | 0 | 0 |  |
| mypcap/test/3 | 35 | 35 | 0 | 0 |  |
| mypcap | 26 | 26 | 0 | 0 |  |
| (top) | 23 | 21 | 2 | 0 | 含无 L7 planner 的协议(用 tcp/udp 字节级兜底) |
| mypcap/publicpcap/IPV6 | 23 | 20 | 3 | 0 | 含无 L7 planner 的协议(用 tcp/udp 字节级兜底) |
| mypcap/publicpcap/IPv4/http | 23 | 23 | 0 | 0 |  |
| mypcap/ProtoPcap/ARD-163_news-19-0041-V66.1-IM_getui-22-0268-00 | 22 | 22 | 0 | 0 |  |
| bc | 21 | 21 | 0 | 0 |  |
| mypcap/publicpcap/IPv4/https | 21 | 21 | 0 | 0 |  |
| mypcap/publicpcap/xdr2 | 21 | 21 | 0 | 0 |  |
| mypcap/test/1 | 20 | 20 | 0 | 0 |  |
| mypcap/https | 20 | 20 | 0 | 0 |  |
| mypcap/sendpcap/xdr | 20 | 20 | 0 | 0 |  |
| mypcap/test/2 | 19 | 19 | 0 | 0 |  |
| mypcap/publicpcap/IPv4 | 17 | 17 | 0 | 0 |  |
| mypcap/publicpcap/IPv4/ftp | 15 | 15 | 0 | 0 |  |
| mypcap/publicpcap/Radius | 12 | 1 | 11 | 0 | 含无 L7 planner 的协议(用 tcp/udp 字节级兜底) |
| mypcap/ProtoPcap/ARD-163_news-19-0041-V66.1-IM_https-22-0035-00 | 11 | 11 | 0 | 0 |  |
| bzip | 10 | 10 | 0 | 0 |  |
| mypcap/test/4 | 10 | 10 | 0 | 0 |  |
| mypcap/publicpcap/IPv4/dns | 10 | 10 | 0 | 0 |  |
| mypcap/eu_pcaps | 10 | 10 | 0 | 0 |  |
| mypcap/eu_pcaps/ipv4_monfil_pcaps/other | 10 | 10 | 0 | 0 |  |
| kjvpn_kk | 9 | 9 | 0 | 0 |  |
| dns | 9 | 9 | 0 | 0 |  |
| mypcap/ProtoPcap/ARD-163_news-19-0041-V66.1-IM_dns-22-0065-00 | 9 | 9 | 0 | 0 |  |
| mypcap/idc3 | 9 | 8 | 1 | 0 | 含无 L7 planner 的协议(用 tcp/udp 字节级兜底) |
| mypcap/get_field | 9 | 9 | 0 | 0 |  |
| mypcap/publicpcap/IPv4/sip | 9 | 9 | 0 | 0 |  |
| rs | 8 | 8 | 0 | 0 |  |
| mypcap/app_pcap | 7 | 7 | 0 | 0 |  |
| mypcap/field/http/request_method/http1_1 | 6 | 6 | 0 | 0 |  |
| mypcap/ProtoPcap/ARD-163_news-19-0041-V66.1-IM_gaode_map-10-0003-00 | 5 | 5 | 0 | 0 |  |
| mypcap/eu_pcaps/ipv6_monfil_pcaps/other | 5 | 5 | 0 | 0 |  |
| VPN/wireguard | 5 | 5 | 0 | 0 |  |
| mypcap/field/http/request_method/http1_0 | 4 | 4 | 0 | 0 |  |
| mypcap/publicpcap/IPv4/rtsp | 4 | 0 | 4 | 0 | 含无 L7 planner 的协议(用 tcp/udp 字节级兜底) |
| VPN/SHADOWSOCKS | 4 | 4 | 0 | 0 |  |
| mypcap/publicpcap/IPv4/email | 3 | 3 | 0 | 0 |  |
| mypcap/ProtoPcap/ARD-163_news-19-0041-V66.1-IM_aliyun-17-0021-00 | 2 | 2 | 0 | 0 |  |
| mypcap/ProtoPcap/ARD-163_news-19-0041-V66.1-IM_DHCP-22-0079-00 | 2 | 2 | 0 | 0 |  |
| VPN/OPENVPN | 2 | 2 | 0 | 0 |  |
| mypcap/test | 1 | 1 | 0 | 0 |  |
| mypcap/ProtoPcap | 1 | 1 | 0 | 0 |  |
| mypcap/ProtoPcap/ARD-163_news-19-0041-V66.1-IM_http_qita-22-0259-01 | 1 | 1 | 0 | 0 |  |
| mypcap/publicpcap | 1 | 1 | 0 | 0 |  |
| mypcap/publicpcap/IPv4/com | 1 | 1 | 0 | 0 |  |
| mypcap/eu_pcaps/ipv6_monfil_pcaps | 1 | 1 | 0 | 0 |  |
| VPN/vmess | 1 | 1 | 0 | 0 |  |

## 六、pcap 中识别协议 vs trafficgen 造流能力对照矩阵

| 协议 | 出现位置(端口/目录) | 普通造流 | 对应 planner | 说明 |
|------|--------------------|---------|-------------|------|
| http | HTTP-alt(790 文件) | ✅ | http | http planner 完整支持 GET/POST 等 |
| tcp | custom(234 文件) | ✅ | tcp/udp | tcp planner 造原始字节流 |
| data | custom(211 文件) | ✅ | tcp | 自定义 TCP 字节流,tcp planner 直接支持 |
| tls | HTTPS(153 文件) | ✅ | tls | tls planner 支持 TLS 1.2/1.3 握手+记录 |
| rtsp | RTSP(56 文件) | ⚠️ | tcp | 无 rtsp planner,用 tcp planner 造字节,无 SDP/RTSP 语义 |
| dns | DNS(56 文件) | ✅ | dns | dns planner 支持 A/AAAA/CNAME 等 |
| ftp | FTP(44 文件) | ✅ | ftp | ftp planner 支持控制+数据面 |
| snmp | SNMP(42 文件) | ✅ | snmp | snmp planner 支持 v1/v2c/v3 |
| sip | SIP(40 文件) | ✅ | sip | sip planner 支持信令+媒体 |
| radius | RADIUS(37 文件) | ⚠️ | udp | 无 RADIUS planner,用 udp planner 造字节 |
| smtp | SMTP(33 文件) | ✅ | smtp | smtp planner 支持 |
| pop | POP3(30 文件) | ✅ | pop3 | pop3 planner 支持 |
| imap | IMAP(29 文件) | ✅ | imap | imap planner 支持 |
| udp | RTCP(25 文件) | ✅ | tcp/udp | udp planner 造原始字节流 |
| vnc | VNC(24 文件) | ✅ | vnc | vnc planner 支持 Tight/VNC Auth/None 握手 + 数据面 |
| telnet | Telnet(24 文件) | ✅ | telnet | telnet planner 支持 |
| h225 | H.323(24 文件) | ⚠️ | tcp | 无 H.225 planner,用 tcp planner 造字节 |
| socks | SOCKS(24 文件) | ⚠️ | tcp | 无 SOCKS planner,用 tcp planner 造字节 |
| ldap | LDAP(24 文件) | ⚠️ | tcp | 无 LDAP planner,用 tcp planner 造字节 |
| pptp | PPTP(24 文件) | ⚠️ | tcp | 无 PPTP planner,用 tcp planner 造字节 |
| rtmpt | RTMPT(24 文件) | ⚠️ | tcp | 无 RTMPT planner,用 tcp planner 造字节 |
| xmpp | XMPP(24 文件) | ⚠️ | tcp | 无 XMPP planner,用 tcp planner 造字节 |
| ssh | SSH(24 文件) | ✅ | ssh | ssh planner 支持版本交换+KEX |
| ntp | NTP(24 文件) | ✅ | ntp | ntp planner 支持 v3/v4 |
| isakmp | IKE-NAT-T(24 文件) | ✅ | ike_nat_t | ike_nat_t planner 支持 IKEv1 NAT-T(4500) |
| mdns | mDNS(24 文件) | ✅ | mdns | mdns planner 支持 |
| ssdp | SSDP(24 文件) | ✅ | ssdp | ssdp planner 支持 M-SEARCH/NOTIFY |
| dhcp | DHCP(14 文件) | ✅ | dhcp | dhcp planner 支持 Discover/Offer/Request/Ack |
| icmp | dport=None(13 文件) | ✅ | icmp | icmp planner 支持 Echo Request/Reply |
| icmpv6 | dport=None(13 文件) | ✅ | icmpv6 | icmpv6 planner 支持 Echo + 邻居发现 |
| dhcpv6 | DHCPv6(12 文件) | ✅ | dhcpv6 | dhcpv6 planner 支持 SARR 等场景 |
| wg | dport=special(5 文件) | ✅ | wireguard | wireguard planner 支持(tshark 层名 wg) |
| ngap | dport=38412(4 文件) | ⚠️ | sctp | 无 NGAP/NAS-5GS planner,SCTP 层可造 |
| arp | dport=special(3 文件) | ✅ | arp | arp planner 完整支持 |
| ip | dport=special(1 文件) | ⚠️ | tcp/udp | 未识别协议 ip,用 tcp/udp planner 字节级兜底 |
| lcp | dport=special(1 文件) | ⚠️ | tcp | PPPoE LCP,无 PPPoE planner,字节级兜底 |
| openvpn | dport=special(1 文件) | ✅ | openvpn | openvpn planner 支持 TCP/UDP |

## 七、总体结论

### 7.1 关键发现

1. **全部 17951 个 pcap 至少可字节级造流**(无 L7 planner 的协议可用 tcp/udp planner 造 L4 字节流)
2. **L2/L3/L4 三层 100% 有 planner 支持**(IPv4/IPv6/VLAN/ARP/TCP/UDP/SCTP/ICMP/ICMPv6)
3. **35+ 个 L7 协议有专门 planner**(http/dns/ftp/sip/ssh/telnet/smtp/pop3/imap/tls/dhcp/dhcpv6/ntp/snmp/mdns/ssdp/ike/ike_nat_t/l2tp/wireguard/openvpn/syslog/rdp/mysql/postgresql/redis/grpc 等)
4. **部分协议只有字节级兜底**(rtsp/rtmpt/h323/pptp/ldap/xmpp/vnc/socks/radius/tftp/rtcp/gtp/ngap 无专门 planner)
5. **极少数封装无法构造**(GRE/MPLS/PPPoE 隧道头没有支持)
6. **VPN 加密 payload 不可解密**,造流后字节流不是有效 VPN 流量(密钥协商失败)

### 7.2 造流可行性统计

| 判定 | 文件数 | 占比 |
|------|--------|------|
| ✅ | 17211 | 95.9% |
| ⚠️ | 740 | 4.1% |
| ❌ | 0 | 0.0% |

**判定说明**: ✅=有对应 planner,可完整构造协议栈(含 L7 语义); ⚠️=无 L7 planner,但 tcp/udp planner 可造 L4 字节级流(业务语义丢失); ❌=GRE/MPLS 等封装头无法构造。

### 7.3 修改建议(按优先级)

| 优先级 | 建议 | 影响文件 | 说明 |
|--------|------|---------|------|
| P1 | 新增 RTSP/SDP planner | ~56 文件 | llcj 系列 dport=554 有 56 个 RTSP 文件 |
| P1 | 新增 RADIUS planner | ~37 文件 | llcj 系列 dport=1813 有 37 个 RADIUS 文件 |
| P2 | 新增 XMPP/VNC/SOCKS/LDAP/PPTP/RTMPT/H.323 planner | ~168 文件 | 每个 24 文件,均为常见内网协议 |
| P3 | 新增 TFTP/RTCP planner | ~37 文件 | dport=69/31601 |
| P3 | 回放保留 TCP 重传时序 | fz 等 | 造流不复现原始重传 |

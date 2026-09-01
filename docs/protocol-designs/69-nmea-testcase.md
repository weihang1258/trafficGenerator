# NMEA 0183（海用电子设备数据交换标准，National Marine Electronics Association 0183）测试用例契约

> 版本：v2.0.0（测试用例）
> 日期：2026-09-02
> 配套设计：`docs/protocol-designs/69-nmea-design.md`（v2.0.0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/nmea.json`（proto key：`nmea`；本版不写文件，当前 JSON 仅含注册前置占位）
> 状态：按《协议设计文档与用例文档需求文档 v1.3》对 v1.0.0 初稿执行重写级修复轮（独立审查报告 /tmp/nmea_v13/report.md：23 findings = C 10 / D 8 / N 5 + §0 行为面枚举 ~92 点），20 → **80 例（49 正 + 31 负）**，待复验关闭。
> 修订记录：v2.0.0（2026-09-02）：按 v1.3 重写，取代 2026-08-20 v1.0.0 初稿（旧稿见 git 历史；旧稿 14+6 粗粒度用例全部重排为 49+31 原子用例）。逐 finding 落点见设计 §10。

## 1. 测试原则和未注册边界

用例从规范行为面与设计 §2–§9 派生，共 **80 个唯一语义 ID：49 个正例 + 31 个负例**（审查报告 §0 行为面枚举 ~92 测试点对齐——同字段同形值域变体按设计 §8 代表值策略并帧承载，其余逐点一例）。**ID 权威 = 本文 §2**（设计 §9 为簇级覆盖图景）。**一个用例只验证一个协议行为**（v1.3 §7 原子原则）；断言依据链在 §2「依据」列逐行标注（NMEA 0183 公开口径/gpsd NMEA.txt/设计 §n）。

当前 JSON 只保留一个 `nmea_neg_unregistered` 注册前置占位：`proto=nmea`、`expect_error=true`、`error_contains` 精确为 `unknown layer`（占位 `dst_port=10110` 与本版 fixture 一致，无需修正）；该占位不计入 80 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 NMEA 行为通过。注册后移除占位，按本文 §2 顺序补入 49 个正例与 31 个负例（**占位 notes 同步修正项见 §7.8**）。

**输出契约（pcap/NIC 双输出）**：本契约的用例同时服务于 pcap（抓包文件）与 port_group/NIC（网卡）两种输出路径——两路径共用同一份 cases JSON、同一 tshark 字段/帧字节断言（`tcp.payload`/`udp.payload` 整句 hex、offset 54/74/42/62 frames、`tcp.len`/`tcp.stream`/`udp.length`/`udp.stream`），NIC 路径经 tcpdump 捕获（`nic_capture` 用例级开关；实测口 enp135s0f0np0）后以同一断言集核验——**网卡 checksum offload 仅影响 IP/TCP/UDP 校验和字段，NMEA 句内 XOR 校验和是应用层 ASCII 文本，不受 offload 影响**；L2 无 VLAN 前提下偏移与载荷提取稳定（与 64/66/67/68/70/65/73/74/75 号协议同形）；不设仅单路径可用的断言。`nmea_pcap_nic_consistency`（正例 49）为双路径一致性专项观测例，契约段覆盖全部用例。

**TSHARK 实测基线（本机 3.6.14，`-G fields`/`-G protocols` 核验，版本化钉死、非条件句——N-7）**：本机**没有 NMEA dissector（解析器）**——`tshark -G protocols | grep -ci nmea` = 0；`-G fields` 中含 "nmea" 的字段全部属于其他协议（`aprs.ct.nmea_src`、`wlan.measure.rep.repmode.mapfield.unmeasured`、`nbap.commonmeasurementValue`），**不存在任何 `nmea.*` 字段，不得臆造**。**无 DecodeAs 依赖**：本协议无 dissector 可言，全部断言走 raw payload 通道，与端口无关（非默认端口正例 42 不需要任何 `-d` 提示——与 hl7#27/bacnet#46"有 dissector 需 DecodeAs"判例形不同因）。可用断言通道（`-G fields` 实测存在）：① `tcp.payload`（FT_BYTES，TCP 载荷原始字节——单句不跨段时即**完整句含 CRLF**）、`udp.payload`（UDP 数据报原始字节，一报文一句时即完整句、多句时为句集拼接）；② `tcp.srcport`/`tcp.dstport`/`tcp.stream`/`tcp.len`/`tcp.flags.syn`/`tcp.flags.ack`/`tcp.flags.fin`/`tcp.flags.reset`、`udp.srcport`/`udp.dstport`/`udp.stream`/`udp.length`；③ `ip.version`、`ipv6.nxt`、`frame.number`/`frame.len`；④ `frames` 数组 `offset/hex` 断言（句首 `$`=`24` 起点：TCP/IPv4 offset 54、TCP/IPv6 74、UDP/IPv4 42、UDP/IPv6 62）。**TCP 分段边界不是句子边界**：跨段句按 `tcp.stream` 重组后断言整句（§3.3）；粘句段按 CRLF（`0d0a`）拆句计数；UDP 按数据报边界承载句集、不跨报文拼接。

**保活/RST/重连口径（设计 §5，N-8）**：无应用层 keepalive 帧、TCP keepalive 探测不产生（长连接活性由句子周期输出体现）——不设 keepalive 例亦不进负例；**RST 异常中断 = 正例 46**（`tcp.flags.reset==1`、RST 后无句子帧、无挥手——`terminates` 不适用）；**重连 = 正例 47**（新四元组、句子流重启、无恢复语义）；FIN 优雅终止由其余全部 TCP 正例 `terminates=true` 承载——v1.3 §4 清单"FIN/RST 或异常中断"双形态闭合；**UDP 无连接**：无握手/挥手/RST/保活语义——UDP 正例不携带 `has_handshake`/`terminates`（恒 false 不写入 expect）。

**动态字段与 fixture 常量**：UTC 时间、经纬度、卫星参数、XOR 校验和的具体值全部为**预配置 fixture 常量**（§3 常量表与字节基线表钉死，逐句 hex 可精确预算、XOR 可逐字节复算——N-16）；运行期变化值（若实现期引入）用 `same_as_packet`/`distinct_values`/`nonzero` 断言。不声称真实定位正确性、卫星真实存在、接收机状态真实。

**包数约定（N-17，全部给算式）**：**TCP 会话 = 3（SYN/SYN-ACK/ACK 握手）+ N（承载句子的 TCP 段数，缺省每句 1 段；粘连合并/跨段切分按实际段数）+ 4（双向 FIN 挥手，FIN+ACK×2+FIN/ACK）**，数据帧从帧 4 起；**RST 终止形态 = 3 + N + 1（单侧 RST，无挥手）**；**UDP = 数据报数**（无握手/挥手）；**多会话按序 = 各会话之和，第二会话握手包号 = 前会话总包数 + 1**；并发（`concurrent:true`）= 各会话之和（交错）；多载体 = TCP 部分与 UDP 部分之和。实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖（依据） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `nmea_tcp_ipv4_stream` | 正 | IPv4/TCP 单流基线：GGA+RMC 两句流、`$..*xx\r\n` 全形态（设计 §2/§3.1；gpsd GGA/RMC） | 9 |
| 2 | `nmea_gga_full_fields` | 正 | GGA 15 字段全形态（13/14 空占位）（设计 §3.4；gpsd GGA） | 8 |
| 3 | `nmea_gga_dgps_fields` | 正 | GGA 可选字段全填充：质量 2 + DGPS 年龄 1.0 + 站 ID 0001（设计 §3.4） | 8 |
| 4 | `nmea_gga_no_fix` | 正 | GGA 无定位：质量 0 + 位置字段全空（设计 §3.4） | 8 |
| 5 | `nmea_gga_fix_quality_enum` | 正 | fix quality 值域代表 1/2/4 三帧（设计 §3.4/§8；0 由用例 4 承载） | 10 |
| 6 | `nmea_rmc_full_fields` | 正 | RMC 12 字段全形态（含磁偏角 E/W + 模式 A）（设计 §3.4；gpsd RMC） | 8 |
| 7 | `nmea_rmc_status_void` | 正 | RMC 状态值域：A 有效全字段帧 + V 空字段帧（位置/速度/航向空、模式 N）（设计 §3.4） | 9 |
| 8 | `nmea_gsa_full_slots` | 正 | GSA 12 卫星槽全满 + 模式 A + 维度 3 + PDOP/HDOP/VDOP（设计 §3.4；gpsd GSA） | 8 |
| 9 | `nmea_gsa_mode_ma` | 正 | GSA 模式值域 M（手动）/A（自动）两帧（设计 §3.4） | 9 |
| 10 | `nmea_gsa_fix_2d` | 正 | GSA 维度 2（2D）+ VDOP 空字段（无高度解形态）（设计 §3.4） | 8 |
| 11 | `nmea_gsa_sparse_slots` | 正 | GSA 卫星槽稀疏：前 5 槽填、后 7 槽空逗号保留（设计 §3.4） | 8 |
| 12 | `nmea_gsv_single` | 正 | GSV 单消息（total=1,msg=1）+ 卫星四字段组（设计 §3.4；gpsd GSV） | 8 |
| 13 | `nmea_gsv_sequence` | 正 | GSV 三消息序列（4+4+3 星、total=3、msg 1/2/3 关联）（设计 §3.4/§5） | 10 |
| 14 | `nmea_gsv_snr_empty` | 正 | GSV 卫星组 SNR 空字段形态（仰角/方位在场）（设计 §3.4） | 8 |
| 15 | `nmea_vtg_full_fields` | 正 | VTG 9 字段（磁航向空占位、双速度单位、模式 A、校验和 `*00`）（设计 §3.4） | 8 |
| 16 | `nmea_gll_full_fields` | 正 | GLL 7 字段（位置/时间/状态 A/模式 A）（设计 §3.4） | 8 |
| 17 | `nmea_zda_full_fields` | 正 | ZDA 6 字段（日期 + 本地时区 +08,00）（设计 §3.4） | 8 |
| 18 | `nmea_zda_zone_negative` | 正 | ZDA 负时区形态两帧（+08,00 / -05,30）（设计 §3.4/§8） | 9 |
| 19 | `nmea_proprietary_sentence` | 正 | `$P` 专有句：`$PGRME` + opaque payload + 强制校验和（设计 §3.4；GARMIN 公开示例） | 8 |
| 20 | `nmea_checksum_recompute` | 正 | XOR 复算：四句型流逐句复算（`$`/`*` 排除、两位 hex）（设计 §3.3/§3.1） | 11 |
| 21 | `nmea_checksum_uppercase` | 正 | 校验和含字母位大写形态（`*6E`）（设计 §3.3⑤） | 8 |
| 22 | `nmea_checksum_omitted_standard` | 正 | 标准句无校验和合法形态（`M,,` 后直接 CRLF）（设计 §3.3：标准句校验和可选） | 8 |
| 23 | `nmea_talker_gn` | 正 | talker GN（组合 GNSS 现网默认）：GNGGA（设计 §3.2③） | 8 |
| 24 | `nmea_talker_gl` | 正 | talker GL（GLONASS）：GLGGA（设计 §3.2） | 8 |
| 25 | `nmea_talker_ii` | 正 | talker II（集成仪表）：IIGLL（设计 §3.2） | 8 |
| 26 | `nmea_lat_boundary` | 正 | 纬度边界两帧：0000.0000（0°）/ 9000.0000（满度 90°）（设计 §3.4/§8，N-12） | 9 |
| 27 | `nmea_lon_boundary` | 正 | 经度边界两帧：00000.0000（0°）/ 18000.0000（满度 180°）（设计 §3.4/§8，N-12） | 9 |
| 28 | `nmea_minutes_max` | 正 | 分满值 59.9999（纬经双字段）（设计 §3.4/§8，N-12） | 8 |
| 29 | `nmea_hemisphere_sw` | 正 | 半球变体：纬 S + 经 W（南/西半球形态）（设计 §3.4） | 8 |
| 30 | `nmea_multi_sentence_packed` | 正 | 多句粘连单段：RMC+VTG 115B 段内 2 个 CRLF（设计 §3.1/§5） | 8 |
| 31 | `nmea_split_after_dollar` | 正 | TCP 跨段切位①：段界在 `$` 后（split offset 1）（设计 §2/§3.1） | 9 |
| 32 | `nmea_split_in_field` | 正 | TCP 跨段切位②：段界在纬度字段内（offset 20，`4807/038` 切分）（设计 §3.1） | 9 |
| 33 | `nmea_split_in_checksum` | 正 | TCP 跨段切位③：段界在两位校验和 hex 之间（offset 67，`*6/9` 切分）（设计 §3.1/§3.3） | 9 |
| 34 | `nmea_split_crlf` | 正 | TCP 跨段切位④：段界在 CR 与 LF 之间（offset 69）（设计 §3.1） | 9 |
| 35 | `nmea_mss_packed_stream` | 正 | 30 句 ×70B=2100B 打包跨 2 段（MSS 1460）重组（设计 §8） | 9 |
| 36 | `nmea_max_sentence_length` | 正 | 82 字节句长上界（`$PXYZ,P×71*77` 整句恰 82B）（设计 §3.1/§8） | 8 |
| 37 | `nmea_udp_single_sentence` | 正 | UDP/IPv4 单句数据报基线（offset 42）（设计 §2） | 1 |
| 38 | `nmea_udp_multi_sentence` | 正 | UDP 多句单报文（GGA+RMC+VTG 185B、3 个 CRLF）（设计 §2/§8） | 1 |
| 39 | `nmea_udp_ipv6` | 正 | UDP/IPv6（offset 62、`ipv6.nxt=17`）（设计 §2/§8） | 1 |
| 40 | `nmea_udp_multicast` | 正 | UDP 多播目的 239.192.0.1:10110 两报文（设计 §8⑤） | 2 |
| 41 | `nmea_ipv6_tcp` | 正 | TCP/IPv6（offset 74、`ipv6.nxt=6`、句字节同 v4）（设计 §2/§8） | 9 |
| 42 | `nmea_port_nondefault` | 正 | 非默认端口 4001 显式声明（句字节同基线、无 DecodeAs 依赖）（设计 §2，N-7） | 9 |
| 43 | `nmea_mixed_transport` | 正 | 多载体 fixture：TCP 会话（GGA+RMC）+ UDP 两报文（设计 §6，N-23） | 11 |
| 44 | `nmea_multi_session` | 正 | 多会话按序展开双四元组（流/重组缓存隔离）（设计 §5/§6） | 18 |
| 45 | `nmea_concurrent_sessions` | 正 | 并发会话 `concurrent:true` 三设备交错（tcp.stream 三值 distinct）（设计 §4⑦/§5，N-1） | 27 |
| 46 | `nmea_rst_interrupt` | 正 | RST 异常中断（`tcp.flags.reset==1`、其后无句、无挥手）（设计 §5，N-8） | 5 |
| 47 | `nmea_reconnect` | 正 | 断线重连（新四元组、句子流重启、无恢复语义）（设计 §5，N-8） | 16 |
| 48 | `nmea_invalid_checksum` | 正 | 坏校验和观测模式（`*6A`≠复算 `*69`，生成并原样输出、expect 无 error）（设计 §3.3/§7，N-21） | 8 |
| 49 | `nmea_pcap_nic_consistency` | 正 | pcap/NIC 双输出一致性专项（同一契约，§1 输出契约段覆盖全部用例）（设计 §1，N-3） | 9 |
| 50 | `nmea_neg_missing_dollar` | 负 | §7：句子去 `$` 裸地址起始 | — |
| 51 | `nmea_neg_missing_crlf` | 负 | §7：流末句无 CRLF 裸结束 | — |
| 52 | `nmea_neg_lf_only` | 负 | §7：行尾仅 LF 无 CR | — |
| 53 | `nmea_neg_truncated_tcp` | 负 | §7：TCP 流字段中间截断 | — |
| 54 | `nmea_neg_udp_truncated` | 负 | §7：UDP 报文尾无 CRLF（半句入报文） | — |
| 55 | `nmea_neg_udp_cross_datagram` | 负 | §7：一句拆进两个数据报 | — |
| 56 | `nmea_neg_start_bang` | 负 | §7：`!` 起始（AIS 形态，§3.6 排除项） | — |
| 57 | `nmea_neg_unknown_talker` | 负 | §7：talker `ZZ` 不在值域表 | — |
| 58 | `nmea_neg_unknown_type` | 负 | §7：formatter `XYZ` 不在支持集 | — |
| 59 | `nmea_neg_talker_p_standard` | 负 | §7：`$PGA…` P 当标准 talker | — |
| 60 | `nmea_neg_field_count_short` | 负 | §7：GGA 12 字段（逗号数不足） | — |
| 61 | `nmea_neg_field_count_extra` | 负 | §7：GGA 16 字段（多余尾字段） | — |
| 62 | `nmea_neg_lat_over` | 负 | §7：纬度 9030.0000（90°30′ 越界） | — |
| 63 | `nmea_neg_lon_over` | 负 | §7：经度 18030.0000 越界 | — |
| 64 | `nmea_neg_minutes_over` | 负 | §7：分 60.0000（4860.0000） | — |
| 65 | `nmea_neg_direction_char` | 负 | §7：纬半球 `X` | — |
| 66 | `nmea_neg_time_out_of_range` | 负 | §7：时间 253519.00（hh=25） | — |
| 67 | `nmea_neg_date_out_of_range` | 负 | §7：日期 320394（dd=32） | — |
| 68 | `nmea_neg_status_char` | 负 | §7：RMC 状态 `C` | — |
| 69 | `nmea_neg_gsa_mode_char` | 负 | §7：GSA 模式 `X` | — |
| 70 | `nmea_neg_gsa_fix_type` | 负 | §7：GSA 维度 `4` | — |
| 71 | `nmea_neg_sentence_length` | 负 | §7：83 字节句（82 上界+1） | — |
| 72 | `nmea_neg_checksum_mismatch` | 负 | §7：`*6A` ≠ 复算 `*69` | — |
| 73 | `nmea_neg_checksum_hex_width` | 负 | §7：`*` 后一位 hex（`*9`） | — |
| 74 | `nmea_neg_proprietary_no_checksum` | 负 | §7：$P 句无校验和（专有句强制） | — |
| 75 | `nmea_neg_gsv_seq_correlation` | 负 | §7：GSV 序号跳变（msg 1→3） | — |
| 76 | `nmea_neg_carrier_layer_missing` | 负 | §7：层链缺 tcp/udp 直连 | — |
| 77 | `nmea_neg_carrier_conflict` | 负 | §7：tcp 层链 + udp transport 声明矛盾 | — |
| 78 | `nmea_neg_port_undeclared` | 负 | §7：非 10110 端口未显式声明 | — |
| 79 | `nmea_neg_address_family_mismatch` | 负 | §7：v6 地址配 v4 层链（或反向） | — |
| 80 | `nmea_neg_error_propagation` | 负 | §7：已知校验错误被吞、任务假成功 | — |
| — | `nmea_neg_unregistered` | 占位 | 当前层注册前置 | — |

## 3. 线上编码和偏移断言

层链 `[tcp, nmea]`/`[udp, nmea]`，无 VLAN/IP options/TCP options 时**每句首字节（`$`=`24`）起点：TCP/IPv4 offset 54、TCP/IPv6 74、UDP/IPv4 42、UDP/IPv6 62**（句尾恒 `0d 0a`）。断言分层：

1. **载体与方向（fields 权威断言）**：设备帧 `tcp.srcport=40069`、`tcp.dstport=10110`（NMEA 是单向流——采集端不回发，全流同向；无响应帧断言）；`ip.version=4`（IPv6 fixture 断言 `ipv6.nxt=6`（TCP）/`17`（UDP）且不得出现 v4 地址——EtherType 0x86DD 仅作辅助）；`tcp.len` = 该段承载字节数（单句单段时 = 句长）；UDP 断言 `udp.srcport`/`udp.dstport`/`udp.length`（= 8+payload）/`udp.stream`。
2. **NMEA 句（tcp.payload/udp.payload + frames 双通道）**：单句不跨段时 `tcp.payload` = 完整句 hex（短句全断、长句断前缀+分解段+后缀）；frames 断言在 offset 54/74/42/62 校验句首 `24`（`$`）、五字符地址 ASCII hex（如 `474750474741` = `GPGGA`）、句尾 `0d 0a`。句型名 ASCII hex：`GGA`=`474741`、`RMC`=`524d43`、`GSA`=`475341`、`GSV`=`475356`、`VTG`=`565447`、`GLL`=`474c4c`、`ZDA`=`5a4441`。
3. **TCP 跨段重组**：跨段句按 `tcp.stream` 重组后断言整句（重组流起点 = 首段 offset 54）；**任何单段不构成完整句时不得按段断言整句 hex**，改为断言首段前缀 + 末段后缀 + 各段 `tcp.len` 之和 = 句长；粘句段按段内 `0d0a` 计数拆句（段边界 ≠ 句边界双向断言）。
4. **多会话/并发包号规则**：`sessions[]` 按多会话展开整块回放——先跑完第 1 个会话全流程（握手→句子→挥手）再跑第 2 个，不交错；**第二会话 TCP 握手包号 = 前一会话总包数 + 1**。跨会话断言用 `tcp.stream`（或 UDP `udp.stream`）区分，不硬编码全局包号。**并发回放**：`concurrent: true` 为多设备交错回放模式（正例 45）——与按序整块展开（正例 44）分立；单会话内句子序不变。

**fixture 常量**（N-16：全部钉死，句字节可精确预算、XOR 可逐字节复算）：IPv4 TCP `192.0.2.69:40069 → 198.51.100.69:10110`；IPv6 `2001:db8::69 → 2001:db8::100:69`（端口同 40069→10110）；多播目的 `239.192.0.1:10110`；非默认端口 4001；并发三设备 `src_port=40069/40070/40071`；UDP 会话 `src_port=40069`。位置常量：`4807.038,N / 01131.000,E`（基线）、`123519.00`（UTC）、`230394`（日期）、速度航向 `022.4 / 084.4`；卫星 ID 集 `04,05,06,09,12,17,19,24,25,29,31,32`（GSA 满槽 12 星取全集；GSV 序列 11 星取除 32 外——msg1 04/05/09/17｜msg2 19/12/24/25｜msg3 29/31/06）；DOP `2.5/1.3/2.0`；海拔 `545.4,M`、大地差 `46.9,M`。**核心句字节基线表**（全句 hex 含 CRLF 尾 `0d0a`；XOR 复算值即句内 `*` 后两位；脚本逐句核对）：

| 句子 | 总长（含 CRLF） | XOR | 全句 hex |
|---|---:|---|---|
| GGA 基线 `$GPGGA,123519.00,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*69` | 70 | 69 | `2447504747412C3132333531392E30302C343830372E3033382C4E2C30313133312E3030302C452C312C30382C302E392C3534352E342C4D2C34362E392C4D2C2C2A36390D0A` |
| GGA DGPS 全字段 `…E,2,08,0.9,545.4,M,46.9,M,1.0,0001*44` | 77 | 44 | `2447504747412C3132333531392E30302C343830372E3033382C4E2C30313133312E3030302C452C322C30382C302E392C3534352E342C4D2C34362E392C4D2C312E302C303030312A34340D0A` |
| GGA RTK（质量 4）`…E,4,12,0.8,512.3,M,43.1,M,,*6E` | 70 | 6E | `2447504747412C3132333531392E30302C343830372E3033382C4E2C30313133312E3030302C452C342C31322C302E382C3531322E332C4D2C34332E312C4D2C2C2A36450D0A` |
| GGA 无定位 `$GPGGA,123519.00,,,,,0,,,,M,,M,,*45` | 37 | 45 | `2447504747412C3132333531392E30302C2C2C2C2C302C2C2C2C4D2C2C4D2C2C2A34350D0A` |
| GGA 纬 0° `$GPGGA,123519.00,0000.0000,N,…*59` | 71 | 59 | `2447504747412C3132333531392E30302C303030302E303030302C4E2C30313133312E3030302C452C312C30382C302E392C3534352E342C4D2C34362E392C4D2C2C2A35390D0A` |
| GGA 纬 90° `$GPGGA,123519.00,9000.0000,N,…*50` | 71 | 50 | `2447504747412C3132333531392E30302C393030302E303030302C4E2C30313133312E3030302C452C312C30382C302E392C3534352E342C4D2C34362E392C4D2C2C2A35300D0A` |
| GGA 经 0° `$GPGGA,…,4807.038,N,00000.0000,E,…*5B` | 71 | 5B | `2447504747412C3132333531392E30302C343830372E3033382C4E2C30303030302E303030302C452C312C30382C302E392C3534352E342C4D2C34362E392C4D2C2C2A35420D0A` |
| GGA 经 180° `$GPGGA,…,4807.038,N,18000.0000,E,…*52` | 71 | 52 | `2447504747412C3132333531392E30302C343830372E3033382C4E2C31383030302E303030302C452C312C30382C302E392C3534352E342C4D2C34362E392C4D2C2C2A35320D0A` |
| GGA 分满值 `$GPGGA,123519.00,0059.9999,N,00059.9999,E,…*6B` | 72 | 6B | `2447504747412C3132333531392E30302C303035392E393939392C4E2C30303035392E393939392C452C312C30382C302E392C3534352E342C4D2C34362E392C4D2C2C2A36420D0A` |
| GGA 南西 `$GPGGA,…,4807.038,S,01131.000,W,…*66` | 70 | 66 | `2447504747412C3132333531392E30302C343830372E3033382C532C30313133312E3030302C572C312C30382C302E392C3534352E342C4D2C34362E392C4D2C2C2A36360D0A` |
| RMC 基线 `$GPRMC,123519.00,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W,A*29` | 75 | 29 | `244750524D432C3132333531392E30302C412C343830372E3033382C4E2C30313133312E3030302C452C3032322E342C3038342E342C3233303339342C3030332E312C572C412A32390D0A` |
| RMC 状态 V `$GPRMC,123519.00,V,,,,,,,230394,,,N*7F` | 40 | 7F | `244750524D432C3132333531392E30302C562C2C2C2C2C2C2C3233303339342C2C2C4E2A37460D0A` |
| GSA 满槽 `$GPGSA,A,3,04,05,06,09,12,17,19,24,25,29,31,32,2.5,1.3,2.0*3F` | 63 | 3F | `2447504753412C412C332C30342C30352C30362C30392C31322C31372C31392C32342C32352C32392C33312C33322C322E352C312E332C322E302A33460D0A` |
| GSA 手动模式 `$GPGSA,M,3,04,05,06,09,12,17,19,24,25,29,31,32,2.5,1.3,2.0*33` | 63 | 33 | `2447504753412C4D2C332C30342C30352C30362C30392C31322C31372C31392C32342C32352C32392C33312C33322C322E352C312E332C322E302A33330D0A` |
| GSA 2D `$GPGSA,A,2,04,05,,09,,,,,,,,,2.5,1.3,*10` | 42 | 10 | `2447504753412C412C322C30342C30352C2C30392C2C2C2C2C2C2C2C2C322E352C312E332C2A31300D0A` |
| GSA 稀疏槽 `$GPGSA,A,3,04,05,,09,12,,,,,,,,2.5,1.3,2.0*3E` | 47 | 3E | `2447504753412C412C332C30342C30352C2C30392C31322C2C2C2C2C2C2C2C322E352C312E332C322E302A33450D0A` |
| GSV 单消息 `$GPGSV,1,1,02,04,45,190,47,29,80,270,39*79` | 44 | 79 | `2447504753562C312C312C30322C30342C34352C3139302C34372C32392C38302C3237302C33392A37390D0A` |
| GSV 序列 1/3 `$GPGSV,3,1,11,04,45,190,47,05,20,090,38,09,33,230,45,17,66,280,47*76` | 70 | 76 | `2447504753562C332C312C31312C30342C34352C3139302C34372C30352C32302C3039302C33382C30392C33332C3233302C34352C31372C36362C3238302C34372A37360D0A` |
| GSV 序列 2/3 `$GPGSV,3,2,11,19,05,110,42,12,15,220,35,24,40,050,41,25,10,170,33*70` | 70 | 70 | `2447504753562C332C322C31312C31392C30352C3131302C34322C31322C31352C3232302C33352C32342C34302C3035302C34312C32352C31302C3137302C33332A37300D0A` |
| GSV 序列 3/3 `$GPGSV,3,3,11,29,80,270,39,31,55,310,44,06,50,200,40*40` | 57 | 40 | `2447504753562C332C332C31312C32392C38302C3237302C33392C33312C35352C3331302C34342C30362C35302C3230302C34302A34300D0A` |
| GSV SNR 空 `$GPGSV,1,1,01,04,45,190,*45` | 29 | 45 | `2447504753562C312C312C30312C30342C34352C3139302C2A34350D0A` |
| VTG `$GPVTG,084.4,T,,M,022.4,N,041.4,K,A*00` | 40 | 00 | `2447505654472C3038342E342C542C2C4D2C3032322E342C4E2C3034312E342C4B2C412A30300D0A` |
| GLL `$GPGLL,4807.038,N,01131.000,E,123519.00,A,A*66` | 48 | 66 | `244750474C4C2C343830372E3033382C4E2C30313133312E3030302C452C3132333531392E30302C412C412A36360D0A` |
| ZDA +08 `$GPZDA,123519.00,23,03,1994,+08,00*4F` | 39 | 4F | `2447505A44412C3132333531392E30302C32332C30332C313939342C2B30382C30302A34460D0A` |
| ZDA -05 `$GPZDA,123519.00,23,03,1994,-05,30*47` | 39 | 47 | `2447505A44412C3132333531392E30302C32332C30332C313939342C2D30352C33302A34370D0A` |
| $P 专有 `$PGRME,15.0,M,20.0,M,25.0,M*1F` | 32 | 1F | `245047524D452C31352E302C4D2C32302E302C4D2C32352E302C4D2A31460D0A` |
| 82B 上界 `$PXYZ,PPPP…（P×71）…PPP*77` | 82 | 77 | 头 `245058595A2C505050505050` + `50`×141 + 尾 `5050502A37370D0A` |
| 无校验和句 `$GPGGA,123519.00,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,` + CRLF | 67 | —（无） | `2447504747412C3132333531392E30302C343830372E3033382C4E2C30313133312E3030302C452C312C30382C302E392C3534352E342C4D2C34362E392C4D2C2C0D0A` |
| GN talker `$GNGGA,123519.00,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*77` | 70 | 77 | `24474E4747412C3132333531392E30302C343830372E3033382C4E2C30313133312E3030302C452C312C30382C302E392C3534352E342C4D2C34362E392C4D2C2C2A37370D0A` |
| GL talker `$GLGGA,…（同 GGA 基线字段）…*75` | 70 | 75 | `24474C4747412C3132333531392E30302C343830372E3033382C4E2C30313133312E3030302C452C312C30382C302E392C3534352E342C4D2C34362E392C4D2C2C2A37350D0A` |
| II talker `$IIGLL,4807.038,N,01131.000,E,123519.00,A,A*71` | 48 | 71 | `244949474C4C2C343830372E3033382C4E2C30313133312E3030302C452C3132333531392E30302C412C412A37310D0A` |
| 坏校验和观测 `$GPGGA,…（同 GGA 基线）…*6A` | 70 | 6A（≠复算 69） | `2447504747412C3132333531392E30302C343830372E3033382C4E2C30313133312E3030302C452C312C30382C302E392C3534352E342C4D2C34362E392C4D2C2C2A36410D0A` |

（`tcp.payload`/`udp.payload` 值即上表 hex；GGA 基线句内字节偏移：`$`@0、地址 `GPGGA`@1-5、纬度字段起点 @17、`*`@65、校验和两位 @66-67、CR@68、LF@69——split 用例 31-34 的切位偏移据此钉死。）

## 4. 正例逐项断言契约

以下 fields/frames 为最低断言集，实现期可增不可减。除 UDP 例（无握手/挥手，packet_count=报文数）与用例 46（RST，`terminates` 不适用）外，每例均含 `has_handshake=true`、`terminates=true`、数据帧 `has_payload`（`tcp.payload` nonzero + 句首 `24` frames）；句 hex 均引自 §3 字节基线表。

1. **`nmea_tcp_ipv4_stream`**（9 = 3+2+4）：帧 4 = GGA 基线句全 hex（70B，`tcp.len=70`）；帧 5 = RMC 基线句全 hex（75B）；断言 `tcp.dstport=10110`、`tcp.srcport=40069` 全程同向（无响应帧）、frames offset 54 起句首 `24` + `474750474741`（GPGGA）与 `474750524D43`（GPRMC）、句尾 `0d0a`；挥手完整。
2. **`nmea_gga_full_fields`**（8）：帧 4 = GGA 基线句全 hex；逐字段字节断言：时间字段 `3132333531392E3030`（123519.00）、纬 `343830372E303338`、半球 `4E`、经 `30313133312E303030`、`45`、质量 `31`、星数 `3038`、HDOP `302E39`、海拔 `3534352E342C4D`、大地差 `34362E392C4D`、**尾部空字段占位 `2C2C`（age/station 空、逗号保留）**、校验和 `2A3639`。
3. **`nmea_gga_dgps_fields`**（8）：帧 4 = DGPS 全字段句全 hex（77B）；断言质量 `32`（2=DGPS）、age 字段 `312E30`（1.0）、站 ID `30303031`（0001）三字段**全部在场**（与用例 2 的 `2C2C` 空形态 distinct——可选字段空/满两种 wire 形态）；校验和 `2A3434`。
4. **`nmea_gga_no_fix`**（8）：帧 4 = 无定位句全 hex（37B、14 字段）；断言质量字段 `30`（0=无效）、位置四字段全空（时间后 `2C2C2C2C2C30`——lat/NS/lon/EW 空且质量 0）、numsats/hdop/alt 空（`30` 后 `2C2C2C2C4D`）、`4D` 单位占位 f10/f12 保留、f13/f14 空逗号保留；**句子完整合法**（无定位≠非法句）。
5. **`nmea_gga_fix_quality_enum`**（10 = 3+3+4，三句各一段）：帧 4/5/6 = 质量分别 `31`/`32`/`34`（1 GPS/2 DGPS/4 RTK）的三句（GGA 基线/DGPS/RTK 句 hex）；断言三帧质量位字节 `31`/`32`/`34` distinct 且星数字段 RTK 帧为 `3132`（12）；值域 0/5-8 声明不设例（validator 校验）。
6. **`nmea_rmc_full_fields`**（8）：帧 4 = RMC 基线句全 hex（75B）；断言状态 `41`（A）、SOG `3032322E34`、COG `3038342E34`、日期 `323330333934`（230394）、磁偏角 `3030332E312C57`（003.1,W）、模式 `41`（A）；12 字段全部在场。
7. **`nmea_rmc_status_void`**（9 = 3+2+4，两句各一段）：帧 4 = RMC 基线（A 全字段）；帧 5 = V 句全 hex（40B、12 字段）；断言状态位 `41` vs `56` distinct、V 帧位置/速度/航向六字段全空（`56` 后 `2C2C2C2C2C2C2C`——lat/NS/lon/EW/SOG/COG 空连续 7 逗号）、日期仍在场（`323330333934`）、模式 `4E`（N=无效）——**句子存在≠定位有效**。
8. **`nmea_gsa_full_slots`**（8）：帧 4 = GSA 满槽句全 hex（63B、17 字段）；断言模式 `41`、维度 `33`（3D）、12 个卫星 ID 逗号定界全部在场（`30342C30352C30362C30392C31322C31372C31392C32342C32352C32392C33312C3332`——12 个 ID 无空槽、恰 12 槽）、PDOP/HDOP/VDOP `322E352C312E332C322E30`；校验和 `2A3346`。
9. **`nmea_gsa_mode_ma`**（9 = 3+2+4，两句各一段）：帧 4 = 自动模式句（模式 `41`）；帧 5 = 手动模式句（模式 `4D`）；断言两帧首字段字节 `41`/`4D` distinct、其余字段同构（差异仅模式位）；校验和 `2A3346` vs `2A3333`。
10. **`nmea_gsa_fix_2d`**（8）：帧 4 = 2D 句全 hex（42B）；断言维度 `32`（2D）、卫星槽 `30342C30352C2C3039`（含空槽）、**VDOP 空字段**（`322E352C312E332C` 后直接 `2A`——DOP 三元组末位空占位）；校验和 `2A3130`。
11. **`nmea_gsa_sparse_slots`**（8）：帧 4 = 稀疏槽句全 hex（47B）；断言前 5 槽 `30342C30352C2C30392C3132`、**后 7 槽连续空逗号保留**（`2C`×7 在场——槽位不可压缩）、DOP 三元组完整；校验和 `2A3345`。
12. **`nmea_gsv_single`**（8）：帧 4 = GSV 单消息句全 hex（44B）；断言头三字段 `312C312C3032`（total=1,msg=1,sats=02）、两组卫星四字段（`30342C34352C3139302C3437` 与 `32392C38302C3237302C3339`——ID/仰角/方位/SNR）；校验和 `2A3739`。
13. **`nmea_gsv_sequence`**（10 = 3+3+4）：帧 4/5/6 = 序列三句全 hex（70/70/57B）；断言 total 字节三帧同值 `33`（序列关联）、msg 字节 `31`/`32`/`33` 递增、总星数三帧同值 `3131`（11=4+4+3 恰闭合）、卫星组 4+4+3 分布（帧 4/5 各 4 组、帧 6 三组后即 `2A`）、msg2 含 `31322C31352C323230`（卫星 12 在场）、msg3 末组 `30362C35302C3230302C3430`（卫星 06 在场）；校验和 `2A3736`/`2A3730`/`2A3430`。
14. **`nmea_gsv_snr_empty`**（8）：帧 4 = SNR 空句全 hex（29B）；断言卫星组 `30342C34352C3139302C`——ID/仰角/方位在场、**SNR 空**（方位 `313930` 后直接 `2A`）。
15. **`nmea_vtg_full_fields`**（8）：帧 4 = VTG 句全 hex（40B）；断言真航向 `3038342E342C54`、**磁航向空占位**（`542C2C4D`）、速度节 `3032322E342C4E`、速度 km/h `3034312E342C4B`、模式 `41`；**校验和 `2A3030`（`*00` 数值 0 合法形态）**。
16. **`nmea_gll_full_fields`**（8）：帧 4 = GLL 句全 hex（48B）；断言位置四字段、时间 `3132333531392E3030`、状态 `41`、模式 `41`；校验和 `2A3636`。
17. **`nmea_zda_full_fields`**（8）：帧 4 = ZDA 句全 hex（39B）；断言时间、日 `3233`、月 `3033`、年 `31393934`、本地时区 `2B30382C3030`（+08,00——带符号 2 位 + 分）；校验和 `2A3446`。
18. **`nmea_zda_zone_negative`**（9 = 3+2+4，两句各一段）：帧 4 = +08,00 句、帧 5 = -05,30 句（全 hex）；断言时区字段 `2B30382C3030` vs `2D30352C3330` distinct（正/负两种 wire 形态）。
19. **`nmea_proprietary_sentence`**（8）：帧 4 = `$PGRME` 句全 hex（32B）；断言句首 `24` + `50`（`$P`）、厂商 ID `47524D`（GRM）、payload 逐字节保留（`31352E302C4D2C32302E302C4D2C32352E302C4D`）、**校验和在场**（`2A3146`——专有句强制，设计 §3.3）；不做任何 payload 语义断言（opaque）。
20. **`nmea_checksum_recompute`**（11 = 3+4+4）：帧 4-7 = GGA/RMC/GSA/GSV 四句各一段（hex 同基线表）；**逐句复算断言**：`$` 与 `*` 排除、`$` 后至 `*` 前全部字节 XOR = 句内两位 hex——四句校验和 `3639`/`3239`/`3132`/`3739` 全部按句内字节逐字节复算核对（实现期由校准脚本执行同算式）；`*` 后恰两位 hex、随后即 `0d0a`。
21. **`nmea_checksum_uppercase`**（8）：帧 4 = GGA RTK 句全 hex（70B）；断言校验和两位 `3645`（`6E`——**含字母位大写形态**，fixture 钉死；小写 `3665` 不产生，设计 §3.3⑤）。
22. **`nmea_checksum_omitted_standard`**（8）：帧 4 = 无校验和句全 hex（67B）；断言末字段空占位 `2C2C` 后**直接 `0d0a`**（无 `2A` 无 hex——标准句校验和可选，规范原文口径）；句首至句尾结构与基线一致（仅少 `*xx` 三字节，长度 70−3=67）。
23. **`nmea_talker_gn`**（8）：帧 4 = `$GNGGA` 句全 hex（70B）；断言地址字段 `474E474741`（GN**GGA**——talker 2 + type 3）、句型字段同 GGA 基线；校验和 `2A3737`（与 GP 形态 distinct——talker 参与校验域）。
24. **`nmea_talker_gl`**（8）：帧 4 = `$GLGGA` 句全 hex（70B）；断言地址 `474C474741`；校验和 `2A3735`。
25. **`nmea_talker_ii`**（8）：帧 4 = `$IIGLL` 句全 hex（48B）；断言地址 `4949474C4C`（II 集成仪表）；校验和 `2A3731`。
26. **`nmea_lat_boundary`**（9 = 3+2+4，两句各一段）：帧 4 = 纬 0° 句（71B，纬字段 `303030302E30303030`）、帧 5 = 纬 90° 句（71B，`393030302E30303030`）；断言 0/满度两边界值在线（度值域 00-90 钉死两界）。
27. **`nmea_lon_boundary`**（9 = 3+2+4，两句各一段）：帧 4 = 经 0° 句（`30303030302E30303030`）、帧 5 = 经 180° 句（`31383030302E30303030`）；断言经度域 000-180 两界。
28. **`nmea_minutes_max`**（8）：帧 4 = 分满值句全 hex（72B）；断言纬分 `30352C39393939` 中的 `39393939`（59.9999——分域满值）与经分同值；4 位小数形态与基线 3 位并存（fixture 两形态钉死）。
29. **`nmea_hemisphere_sw`**（8）：帧 4 = 南西句全 hex（70B）；断言纬半球 `53`（S）、经半球 `57`（W）——与基线 `4E`/`45`（N/E）构成半球四值全覆盖。
30. **`nmea_multi_sentence_packed`**（8 = 3+1+4）：帧 4 单段 115B = RMC 句（75B）+ VTG 句（40B）拼接；断言 `tcp.len=115`、段内恰 **2 个 `0d0a`**（句界）、前缀 = RMC 句首 hex、`…3239 0D0A` 后紧跟 `244750565447`（`$GPVTG`）——**段边界 ≠ 句边界**（一段两句、无句被段界切坏）。
31. **`nmea_split_after_dollar`**（9 = 3+2+4）：GGA 句切 2 段，split offset 1；帧 4 = 1B（`24`，offset 54）、`tcp.len=1`；帧 5 = 69B（`474750474741…0D0A`）；断言两段 `tcp.len` 和 = 70、按 `tcp.stream` 重组后 = 基线句全 hex、XOR 复算不变（段界不改变句内字节）。
32. **`nmea_split_in_field`**（9）：split offset 20（纬度字段第 4 字符处）；帧 4 = 20B（尾字节 `34383037`——`4807`）、帧 5 = 50B（起 `3033382C…`——`038,`）；重组后全句 hex 与基线逐字节一致。
33. **`nmea_split_in_checksum`**（9）：split offset 67（两位校验和 hex 之间）；帧 4 = 67B（尾 `2A36`——`*6`）、帧 5 = 3B（`390D0A`——`9\r\n`）；重组后 `2A3639` 完整、XOR 复算通过——校验和两位被段界分开仍是同一句。
34. **`nmea_split_crlf`**（9）：split offset 69（CR/LF 之间）；帧 4 = 69B（尾 `0D`）、帧 5 = 1B（`0A`）；重组后句尾 `0D0A` 完整——CR 与 LF 分属两段不构成两句。
35. **`nmea_mss_packed_stream`**（9 = 3+2+4）：30 句 GGA（`pack:true` 连续 2100B）跨 2 段（MSS 1460：段 1 = 1460B、段 2 = 640B）；断言两段 `tcp.len` 和 = 2100、重组流恰 30 个 `0d0a`、段 1 末尾句与段 2 开头句拼接完整（重组流中每句 hex 与基线一致）——**段界落在句中任意位置均不破坏句界**。
36. **`nmea_max_sentence_length`**（8）：帧 4 = 82B 上界句（`$PXYZ,` + `P`×71 + `*77` + CRLF）；断言 `tcp.len=82`、句首 `245058595A2C`、校验和 `2A3737`、XOR 复算通过——82 为含 `$` 与 CRLF 的总长上界（相邻 83 由负例 71 校验）。
37. **`nmea_udp_single_sentence`**（1）：帧 1 = GGA 基线句单报文；断言 `udp.payload` = 全句 hex（70B）、`udp.length=78`（8+70）、frames offset 42 起句首 `24`、`ip.version=4`；无握手/挥手（packet_count=1）。
38. **`nmea_udp_multi_sentence`**（1）：帧 1 = GGA+RMC+VTG 三句一报文（70+75+40=185B）；断言 `udp.payload` 185B、段内 3 个 `0d0a`、三句 hex 顺序拼接（前缀/中缀/后缀断言）——**报文边界承载句集、不跨报文拼接**。
39. **`nmea_udp_ipv6`**（1）：IPv6/UDP fixture（`2001:db8::69 → 2001:db8::100:69`）；断言 `ipv6.nxt=17`、frames offset 62 起句首 `24`、句 hex 与用例 37 完全一致（同一逻辑句，仅外层 IP 头不同）；不得出现 `ip.version=4`。
40. **`nmea_udp_multicast`**（2）：两报文目的 `239.192.0.1:10110`（GGA 句 + RMC 句各一报文）；断言 `udp.dstport=10110`、目的 IP = 239.192.0.1（组播域 D 类）、两报文 `udp.stream` 区分（或同流两报文按帧序）、句 hex 同基线——多播目的形态与单播（37）仅 IP 目的不同；广播形态不产生（设计 §8 声明）。
41. **`nmea_ipv6_tcp`**（9）：IPv6/TCP fixture（`2001:db8::69:40069 → 2001:db8::100:69:10110`）；断言 `ipv6.nxt=6`、句首 offset **74**、GGA/RMC 两句 hex 与用例 1 完全一致、挥手完整；不得出现 `ip.version=4`（EtherType 0x86DD 仅辅助）。
42. **`nmea_port_nondefault`**（9）：显式声明 `dst_port=4001`（非默认），句子/会话形态同用例 1；断言 `tcp.dstport=4001`、`tcp.srcport=4001`（下行不适用——单向流仅上行）、句 hex 与用例 1 **完全一致**（端口不进句内容）；**无 DecodeAs 依赖**（本机无 dissector，断言全走 `tcp.payload`/frames，端口变化不改变任何断言通道——与 bacnet#46"47809 需 `-d`"判例形不同因）；planner 不得静默改写端口（负例 78 校验未声明即拒）。
43. **`nmea_mixed_transport`**（11 = TCP 9 + UDP 2）：sessions[0] TCP（GGA+RMC 两句流 → 9 包）+ sessions[1] `transport:"udp"`（GGA/RMC 两报文 → 2 包）；断言 TCP 部分帧 1-9 形态同用例 1、UDP 部分 `udp.payload` 两句 hex、两载体端口/流独立（`tcp.stream` 与 `udp.stream` 各自承载）——**多载体 fixture 术语落点**（设计 §6 会话级 transport）。
44. **`nmea_multi_session`**（18 = 9+9）：会话 1（`src_port=40069`，GGA+RMC）与会话 2（`src_port=40070`，同句子序列）按序整块展开；断言两 `tcp.stream` distinct、**第二会话握手包号 = 10**（前会话 9 包 + 1）、两会话句子字节各自完整（重组缓存隔离——会话 2 首句不得与会话 1 末句拼接）、帧序无交错（先 1 全流程后 2）。
45. **`nmea_concurrent_sessions`**（27 = 9×3）：`concurrent: true` 三设备（`src_port=40069/40070/40071`）交错回放各自 GGA+RMC 流；断言 `tcp.stream` **三值 distinct**、三会话数据帧**交错出现**（帧序源端口交替，非整块串行——与用例 44 按序展开分立）、每流句子按 `tcp.stream` 重组完整（流间字节互不串用）、单会话内句子序不变（GGA 先 RMC 后）。
46. **`nmea_rst_interrupt`**（5 = 3 握手 + 1 数据段 + 1 RST）：GGA 句（段 4）发出后、计划中 RMC 句前，设备侧 **RST 短路终止**（会话级 `termination:"rst"`）；断言出现 `tcp.flags.reset==1` 帧（设备→采集端）、**RST 后无任何句子帧**（其后无 `tcp.len>0` 帧、无 RMC 段）、**无 FIN 挥手**（无 `tcp.flags.fin==1` 四步——与全部 FIN 正例 distinct）；`has_handshake=true`；`terminates` 断言不适用。
47. **`nmea_reconnect`**（16 = 8+8）：会话 1（GGA 单句 → 3+1+4=8）FIN 关闭；会话 2 **重连**（`src_port=40070` 新四元组、新握手）句子流重启（fixture 钉死：会话 2 = GGA 单句，序列从头重启）；断言两 `tcp.stream` distinct、会话 2 握手包号 = 9、会话 2 句子流从 GGA 起（与事件序列一致）、**无跨连接状态恢复**（会话 2 不依赖会话 1 的任何句子上下文——NMEA 无会话语义，流重启即完整重启）。
48. **`nmea_invalid_checksum`**（8）：帧 4 = 坏校验和观测句全 hex（`*6A`，复算应 `*69`）；断言 `tcp.payload` 原样输出注入字节（`2A3641` 在场）、句长 70B、CRLF 完整、方向正确——**观测模式**：本例验证引擎生成并原样输出坏校验和句（`wire_fault:checksum_mismatch` 的观测形态，expect 不含 error）；与负例 72 同一注入入口两态分立（设计 §3.3/§7 N-21：不是"转发"、不污染合法句定义）。
49. **`nmea_pcap_nic_consistency`**（9）：同一配置（GGA+RMC，同用例 1）分别输出 pcap 与 NIC（`nic_capture` 开启，口 enp135s0f0np0）；断言两路径帧数一致（9）、句 hex 逐字节一致（offset 54 起）、CRLF/XOR 复算一致、`tcp.stream` 分配一致——**双输出共用同一契约**的专项观测（offload 只影响 L3/L4 校验和字段，句内 XOR 不受影响，§1 契约段）。

**正例总则**：每条实现后至少含 `packet_count`（或 `min_packets`）+ 载体与方向断言 + `has_payload` + 可观察 fields（`tcp.*`/`udp.*`/`ip.version`/`ipv6.nxt` 实测字段）+ 稳定 frames（句首 `24`/地址/句尾 `0d0a`）；句 hex 均由 §3 字节基线表钉死（可精确预算、XOR 可复算）。合法协议事件（无校验和标准句、无定位空字段、RMC 状态 V、GSA 稀疏/2D 空 VDOP、GSV SNR 空、VTG 磁航向空、`*00` 校验和、观测坏校验和、多播目的）均为正例形态，只有配置、线格式、字段、值域、长度、关联、载体错误进入负例（设计 §7）。**代表值策略声明**（设计 §8）：fix quality 5-8、RMC 模式 D/E、ZDA 时区 ±13 满值、talker GA/GB/GQ/GI/BD/AI/EC/HC/WI/CD/SD/VD、小写校验和、广播 UDP、tag block、GSV signal ID、空字段全空最短句——值域声明 + validator 校验，不逐值设例。

## 5. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP/UDP 外壳的假成功；执行期 `expect` 键集合**严格为** `{expect_error, error_contains}`。**单一注入纪律（N-4）：一行一例，钉死该行注入的单一 `wire_fault`/配置变异；主锚词为钉死的单一字面值**（不再是候选列表）；`wire_fault` 注入口列与设计 §6 枚举/§7 表三方一一对应（31 值同序）：

| # | ID | `wire_fault` 注入口 | 故障输入（单一注入） | 主锚词 |
|---:|---|---|---|---|
| 50 | `nmea_neg_missing_dollar` | `missing_dollar` | GGA 句去 `$`（`GPGGA,…*69` 裸地址起始） | `dollar` |
| 51 | `nmea_neg_missing_crlf` | `missing_crlf` | 流末句去 CRLF（`…*69` 裸结束） | `crlf` |
| 52 | `nmea_neg_lf_only` | `lf_only` | 行尾仅 LF（`…*69` + `0A`，无 CR） | `crlf` |
| 53 | `nmea_neg_truncated_tcp` | `truncated_tcp` | TCP 流在纬度字段中间结束（`…,48` 后流终、无 CRLF） | `truncat` |
| 54 | `nmea_neg_udp_truncated` | `udp_truncated` | UDP 报文尾无 CRLF（`…*69` 封入报文、无 `0D0A`） | `datagram` |
| 55 | `nmea_neg_udp_cross_datagram` | `udp_cross_datagram` | 一句拆进两个数据报（报文 1 至字段中、报文 2 接余下） | `datagram` |
| 56 | `nmea_neg_start_bang` | `start_bang` | `!AIVDM,1,1,,,,…` 起始（AIS 封装形态，设计 §3.6） | `start` |
| 57 | `nmea_neg_unknown_talker` | `unknown_talker` | talker `ZZ`（`$ZZGGA,…`——不在 §3.2 值域表） | `talker` |
| 58 | `nmea_neg_unknown_type` | `unknown_type` | formatter `XYZ`（`$GPXYZ,…`——不在支持集） | `type` |
| 59 | `nmea_neg_talker_p_standard` | `talker_p_standard` | `$PGA,123519.00,…`（P 当标准 talker，5 字符地址误用） | `talker` |
| 60 | `nmea_neg_field_count_short` | `field_count_short` | GGA 12 字段（`…,M,46.9,M` 即止，尾部两字段连逗号缺失） | `field` |
| 61 | `nmea_neg_field_count_extra` | `field_count_extra` | GGA 16 字段（`…,M,,,*69` 追加多余尾字段） | `field` |
| 62 | `nmea_neg_lat_over` | `lat_over` | 纬度 `9030.0000,N`（dd=90 且分>0——越 90°） | `latitude` |
| 63 | `nmea_neg_lon_over` | `lon_over` | 经度 `18030.0000,E`（越 180°） | `longitude` |
| 64 | `nmea_neg_minutes_over` | `minutes_over` | 纬度 `4860.0000,N`（分 60.0000 ≥60） | `minute` |
| 65 | `nmea_neg_direction_char` | `direction_char` | 纬半球 `X`（∉ N/S） | `direction` |
| 66 | `nmea_neg_time_out_of_range` | `time_out_of_range` | UTC `253519.00`（hh=25 越界） | `time` |
| 67 | `nmea_neg_date_out_of_range` | `date_out_of_range` | 日期 `320394`（dd=32 越界） | `date` |
| 68 | `nmea_neg_status_char` | `status_char` | RMC 状态 `C`（∉ A/V） | `status` |
| 69 | `nmea_neg_gsa_mode_char` | `gsa_mode_char` | GSA 模式 `X`（∉ M/A） | `mode` |
| 70 | `nmea_neg_gsa_fix_type` | `gsa_fix_type` | GSA 维度 `4`（∉ 1/2/3） | `fix` |
| 71 | `nmea_neg_sentence_length` | `sentence_length` | 83B 句（`$PXYZ,P×72*xx`——82 上界 +1） | `length` |
| 72 | `nmea_neg_checksum_mismatch` | `checksum_mismatch` | `*6A` ≠ 句内复算 `*69`（与正例 48 观测态同源、本行为拒绝） | `checksum` |
| 73 | `nmea_neg_checksum_hex_width` | `checksum_hex_width` | `*` 后一位 hex（`…*9` + CRLF——宽度非恰 2） | `checksum` |
| 74 | `nmea_neg_proprietary_no_checksum` | `proprietary_no_checksum` | `$PGRME,15.0,M,20.0,M,25.0,M` + CRLF（专有句强制校验和，设计 §3.3） | `checksum` |
| 75 | `nmea_neg_gsv_seq_correlation` | `gsv_seq_correlation` | GSV 序列 msg 跳变（total=3、msg 1→3 缺 2——§5 唯一句间关联） | `sequence` |
| 76 | `nmea_neg_carrier_layer_missing` | `carrier_layer_missing` | 层链 `[{"nmea":{}}]` 直连（缺 tcp/udp） | `carrier` |
| 77 | `nmea_neg_carrier_conflict` | `carrier_conflict` | tcp 层链 + 会话 `transport:"udp"` 声明矛盾 | `carrier` |
| 78 | `nmea_neg_port_undeclared` | `port_undeclared` | `dst_port=4001` 而未显式声明（静默回退禁止） | `port` |
| 79 | `nmea_neg_address_family_mismatch` | `address_family_mismatch` | IPv6 地址配 IPv4 层链（`[ip,tcp,nmea]` + v6 地址）或反向 | `family` |
| 80 | `nmea_neg_error_propagation` | `propagation` | validator 已知校验和错误被吞、任务 completed/0 packet 假成功 | `propagat` |

合法协议事件不进负例（防误报，同设计 §7 防误报清单）：标准句无校验和（正例 22）、观测坏校验和（正例 48）、RMC 状态 V/空字段（正例 7）、GGA 质量 0 空字段（正例 4）、GSA 稀疏空槽与 2D 空 VDOP（正例 10/11）、GSV SNR 空（正例 14）、VTG 磁航向空、`*00` 校验和（正例 15）、空字段占位（全部可空字段）、多播目的（正例 40）、非默认端口显式声明（正例 42）。

## 6. 五层覆盖映射

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 1-25、30-36（正）；50-80（负） | 七句型 + $P 每型至少一例（GGA 4/RMC 2/GSA 4/GSV 3/VTG/GLL/ZDA/$P 各 1-2，字段级拆分）、校验和三形态（复算/大写/省略）、talker 4 例、GSV 序列关联（13）、TCP 组帧七形态；负例 31 类逐故障（线格式 7/地址 3/字段 2/值域 10（含长度）/校验 3/关联 1/载体 4/传播 1）；`!` AIS 与 tag block 为设计 §3.6/§1 排除项 |
| 性能 | 30、35、36；负 71 | 多句粘连单段（115B 两句）、30 句打包 2100B 跨 2 段重组、82B 句长上界（+相邻 83 负例）；发包速率由框架既有配置承载（v1.3 §10 口径） |
| 数据场景 | 4、5、7、9、10、11、14、18、26-29；负 62-70 | 空字段三形态（GGA 可选字段/无定位/RMC void）、fix quality 与模式/状态/维度枚举、GSV SNR 空、ZDA 正负时区、度分值域边界（0/满度/59.9999/南西半球）、时间/日期/状态/模式/维度越界拒绝 |
| 地址与流 | 1（v4 TCP 单流基线）、37（v4 UDP 基线）、39（UDP v6）、41（TCP v6）、40（多播）、42（非默认端口）、43（多载体）、44（多会话按序）、45（并发交错）、46（RST）、47（重连） | TCP/UDP × v4/v6 四组合；并发会话（45，N-1）；RST/重连（46/47，N-8）；流关联与多流显式不适用（设计 §4：单向传感器数据流，无控制/数据分离、单连接串行） |
| 业务 | 1/2/6（接收机持续推送）、23/24（多星座接收机）、4/7（无定位告警）、8-14（卫星状态巡检）、15-18（航行数据面板）、19（厂商扩展混流）、44/45（AIS/GPS 网关多设备）、46/47（断流重连）、37-40（UDP 网关分发） | 现网 NMEA 日常场景优先（§4 场景表逐行对应用例） |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/nmea.json` 通过；当前数组恰含 1 条 `nmea_neg_unregistered`：`proto=nmea`、层链 `[{"tcp":{}},{"nmea":{}}]`、`dst_port=10110`（与本版 fixture 一致，无需修正）、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
2. 实现注册 `nmea` 层后：移除占位，按 §2 顺序补入 80 个语义用例；**ID 权威 = 本文 §2**（设计 §9 为簇级图景），`nmea.json` 与本文 §2/§8 三方同序（脚本核验）。
3. **计数自查**：§2 表行数 = 80（49 正 + 31 负）+ 1 占位行；§8 一致性清单 ID 数 = 80；脚本断言三方同序。
4. 正例每条含 `packet_count`（或 `min_packets`）+ `fields` + `frames`；`fields` 只用 §1 实测存在的 tshark 字段（`tcp.*`/`udp.*`/`ip.version`/`ipv6.nxt`/`frame.*`），**不使用任何 `nmea.*` 字段**（本机无本协议 dissector，实测钉死）；断言通道 = `tcp.payload`/`udp.payload` 整句 hex + frames offset 54/74/42/62 双通道。
5. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields/frames。
6. **负例原子性（N-4/N-5）**：31 行每行恰注入一个故障；`wire_fault` 取值集合 = §5 注入口列 31 值（三方同序：设计 §6 枚举/§7 表/本文 §5 表）；主锚词为单一钉死字面值，无候选列表；旧稿"坏 JSON"外类故障已删除（ASCII 句子协议无 JSON 成分）。
7. **包数算式（N-17）**：TCP = 3+N+4（RST 形态 3+N+1）；UDP = 报文数；多会话/并发/多载体 = 各部分之和（第二会话握手包号 = 前会话总包数 + 1）；§2 表 packet_count 列与 §4 逐例算式逐行一致（脚本核验）；实现期以实际输出校准。
8. **注册时 JSON notes 同步修正项**（N-20 登记，本版不改 JSON）：当前 `nmea.json` 占位条目 notes 仍写旧稿口径"14 positive and 6 negative"（20 例计数），实现注册 `nmea` 层、按 §2 顺序补入 80 个语义用例时，必须同步把 notes 改写为本文 §2 对应行的覆盖描述（并核对 packet_count 与断言通道），不得保留占位期陈旧 notes。
9. **pcap/NIC 双输出（N-3）**：两输出路径共用本契约（同一 cases JSON、同一 fields/frames 断言），NIC 路径抓包口差异不改变断言语义（网卡 offload 不影响句内 XOR——应用层 ASCII 文本）；不设仅单路径可用的断言。
10. 跨会话/跨段断言用 `tcp.stream`/`udp.stream` + 多会话展开起点规则（§3.4），不硬编码全局包号；句内值全部 fixture 钉死（§3 基线表），运行期值用 `same_as_packet`/`distinct_values`/`nonzero`。
11. 若实现期实证发现端口惯例（10110/4001/多播组）、小写校验和接受性、度分小数位形态与本版 ⑤ 假设不符，设计 §3 与本文 §3/§4 对应断言同步校准，并在两文档修订记录登记。

## 8. 三方一致性表

设计 §9（簇级图景）、本文 §2、实现后 `nmea.json` 保持同一 80 个语义 ID、同一顺序（当前 JSON 另有占位 `nmea_neg_unregistered`，不计入——占位 ID 在此显式登记，与 §2 末行对齐）：

```text
nmea_tcp_ipv4_stream
nmea_gga_full_fields
nmea_gga_dgps_fields
nmea_gga_no_fix
nmea_gga_fix_quality_enum
nmea_rmc_full_fields
nmea_rmc_status_void
nmea_gsa_full_slots
nmea_gsa_mode_ma
nmea_gsa_fix_2d
nmea_gsa_sparse_slots
nmea_gsv_single
nmea_gsv_sequence
nmea_gsv_snr_empty
nmea_vtg_full_fields
nmea_gll_full_fields
nmea_zda_full_fields
nmea_zda_zone_negative
nmea_proprietary_sentence
nmea_checksum_recompute
nmea_checksum_uppercase
nmea_checksum_omitted_standard
nmea_talker_gn
nmea_talker_gl
nmea_talker_ii
nmea_lat_boundary
nmea_lon_boundary
nmea_minutes_max
nmea_hemisphere_sw
nmea_multi_sentence_packed
nmea_split_after_dollar
nmea_split_in_field
nmea_split_in_checksum
nmea_split_crlf
nmea_mss_packed_stream
nmea_max_sentence_length
nmea_udp_single_sentence
nmea_udp_multi_sentence
nmea_udp_ipv6
nmea_udp_multicast
nmea_ipv6_tcp
nmea_port_nondefault
nmea_mixed_transport
nmea_multi_session
nmea_concurrent_sessions
nmea_rst_interrupt
nmea_reconnect
nmea_invalid_checksum
nmea_pcap_nic_consistency
nmea_neg_missing_dollar
nmea_neg_missing_crlf
nmea_neg_lf_only
nmea_neg_truncated_tcp
nmea_neg_udp_truncated
nmea_neg_udp_cross_datagram
nmea_neg_start_bang
nmea_neg_unknown_talker
nmea_neg_unknown_type
nmea_neg_talker_p_standard
nmea_neg_field_count_short
nmea_neg_field_count_extra
nmea_neg_lat_over
nmea_neg_lon_over
nmea_neg_minutes_over
nmea_neg_direction_char
nmea_neg_time_out_of_range
nmea_neg_date_out_of_range
nmea_neg_status_char
nmea_neg_gsa_mode_char
nmea_neg_gsa_fix_type
nmea_neg_sentence_length
nmea_neg_checksum_mismatch
nmea_neg_checksum_hex_width
nmea_neg_proprietary_no_checksum
nmea_neg_gsv_seq_correlation
nmea_neg_carrier_layer_missing
nmea_neg_carrier_conflict
nmea_neg_port_undeclared
nmea_neg_address_family_mismatch
nmea_neg_error_propagation
```

## 9. 修订记录

- v1.0.0（2026-08-20）：旧稿首版（14 正 + 6 负，粗粒度语义用例，散文式断言、无 hex 基线、无包数算式、负例三锚词候选列表）。
- v2.0.0（2026-09-02，v1.3 重写级修复轮）：独立审查报告（docs-bacnet，/tmp/nmea_v13/report.md）23 findings（C 10 / D 8 / N 5）+ §0 行为面枚举 ~92 测试点逐条落，20 → **80 例（49 正 + 31 负）**。逐条落点（与设计 §10 同步）：N-1 并发会话（45，`concurrent:true` 三设备交错）+ #11 拆分为按序（44）/并发（45）；N-2/§1 输出契约段；N-7 版本化实测基线（无 dissector/无 nmea.*/无 DecodeAs）+ 非默认端口正例 42 + 负例 78；N-8 RST 正例 46/重连正例 47 + 保活口径 + UDP 无连接声明；N-9 句型原子化（GGA 4 例等逐字段拆分）；N-10 talker 三正例（23-25）+ `!` 起始负例 56；N-11 校验和口径引规范原文（标准句可选正例 22/专有句强制负例 74）；N-12 度分边界正例 26-29 + 负例 62-65 原子拆分；N-13 GSV 序号负例 75 + 多播正例 40；N-14/N-16 逐字段表 + 长度公式 + §3 字节基线表（fixture 常量钉死、XOR 逐句复算）；N-15 §1/§4 口径（单向流/保活/RST/重连/并发）+ 五层映射；N-17 包数算式（§1 约定 + §4 逐例，含 §2 表五行勘误注记）；N-18 §2 依据列；N-19 ID 权威 = 本文 §2；N-20 §7.8 JSON notes 注册同步项；N-21 正例 48 观测模式与负例 72 两态同源；N-22 IPv6 断言 `ipv6.nxt` + 显式地址；N-23 多载体正例 43 + 术语。**复验修正（提交前，与设计 §10 同步）**：§3 基线表 4 处 fixture 结构错误修正（GGA 无定位 37B/*45、RMC V 40B/*7F、GSA 满槽/手动 63B/*3F/*33 补卫星 32、GSV 序列 70/70/57B/*76/*70/*40 恰 11 星），§4 用例 4/7/8/9/13 断言与长度/校验和同步更新。

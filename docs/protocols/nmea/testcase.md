# NMEA 0183（海用电子设备数据交换标准，National Marine Electronics Association 0183）测试用例契约

> 版本：v2.0.0（测试用例）
> 日期：2026-09-02
> 配套设计：`docs/protocols/nmea/design.md`（v2.0.0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/nmea.json`（proto key：`nmea`；现有 80 例，层链形状已对齐，**严格 LayerChain 尚不可执行**，见能力缺口 G-NMEA-1/G-NMEA-3）
> 状态：按《协议设计文档与用例文档需求文档 v1.3》完成 T1–T6/C1–C6 审计；本轮仅改文档与 cases，不宣称 suite 已复跑。
> 修订记录：v2.0.0（2026-09-02）：按 v1.3 重写，取代 2026-08-20 v1.0.0 初稿（旧稿见 git 历史；旧稿 14+6 粗粒度用例全部重排为 49+31 原子用例）。逐 finding 落点见设计 §10。

## 1. 测试原则和未注册边界

用例从规范行为面与设计 §2–§9 派生，共 **80 个唯一语义 ID：49 个正例 + 31 个负例**（审查报告 §0 行为面枚举 ~92 测试点对齐——同字段同形值域变体按设计 §8 代表值策略并帧承载，其余逐点一例）。**ID 权威 = 本文 §2**（设计 §9 为簇级覆盖图景）。**一个用例只验证一个协议行为**（v1.3 §7 原子原则）；断言依据链在 §2「依据」列逐行标注（NMEA 0183 公开口径/gpsd NMEA.txt/设计 §n）。

当前 JSON 已包含 80 个语义用例（49 正例、31 负例）；其中 `nmea_tcp_wf_carrier_layer_missing` 故意保留缺承载层形状，作为单一载体错误负例，不计入正例白名单审计。

**输出契约（pcap/NIC 双输出）**：本契约的用例同时服务于 pcap（抓包文件）与 port_group/NIC（网卡）两种输出路径——两路径共用同一份 cases JSON、同一 tshark 字段/帧字节断言（`tcp.payload`/`udp.payload` 整句 hex、offset 54/74/42/62 frames、`tcp.len`/`tcp.stream`/`udp.length`/`udp.stream`），NIC 路径经 tcpdump 捕获（`nic_capture` 用例级开关；实测口 enp135s0f0np0）后以同一断言集核验——**网卡 checksum offload 仅影响 IP/TCP/UDP 校验和字段，NMEA 句内 XOR 校验和是应用层 ASCII 文本，不受 offload 影响**；L2 无 VLAN 前提下偏移与载荷提取稳定（与 64/66/67/68/70/65/73/74/75 号协议同形）；不设仅单路径可用的断言。`nmea_tcp_rmc_gq_talker`（正例 49）仅覆盖 GQ talker；pcap/NIC 两路径共用断言是契约要求，不代表已有专项例或已完成实测。

**TSHARK 实测基线（本机 3.6.14，`-G fields`/`-G protocols` 核验，版本化钉死、非条件句——N-7）**：本机**没有 NMEA dissector（解析器）**——`tshark -G protocols | grep -ci nmea` = 0；`-G fields` 中含 "nmea" 的字段全部属于其他协议（`aprs.ct.nmea_src`、`wlan.measure.rep.repmode.mapfield.unmeasured`、`nbap.commonmeasurementValue`），**不存在任何 `nmea.*` 字段，不得臆造**。**无 DecodeAs 依赖**：本协议无 dissector 可言，全部断言走 raw payload 通道，与端口无关（非默认端口正例 42 不需要任何 `-d` 提示——与 hl7#27/bacnet#46"有 dissector 需 DecodeAs"判例形不同因）。可用断言通道（`-G fields` 实测存在）：① `tcp.payload`（FT_BYTES，TCP 载荷原始字节——单句不跨段时即**完整句含 CRLF**）、`udp.payload`（UDP 数据报原始字节，一报文一句时即完整句、多句时为句集拼接）；② `tcp.srcport`/`tcp.dstport`/`tcp.stream`/`tcp.len`/`tcp.flags.syn`/`tcp.flags.ack`/`tcp.flags.fin`/`tcp.flags.reset`、`udp.srcport`/`udp.dstport`/`udp.stream`/`udp.length`；③ `ip.version`、`ipv6.nxt`、`frame.number`/`frame.len`；④ `frames` 数组 `offset/hex` 断言（句首 `$`=`24` 起点：TCP/IPv4 offset 54、TCP/IPv6 74、UDP/IPv4 42、UDP/IPv6 62）。**TCP 分段边界不是句子边界**：跨段句按 `tcp.stream` 重组后断言整句（§3.3）；粘句段按 CRLF（`0d0a`）拆句计数；UDP 按数据报边界承载句集、不跨报文拼接。

**保活/RST/重连口径（设计 §5，N-8）**：无应用层 keepalive 帧、TCP keepalive 探测不产生（长连接活性由句子周期输出体现）——不设 keepalive 例亦不进负例；**RST 异常中断 = 正例 46**（`tcp.flags.reset==1`、RST 后无句子帧、无挥手——`terminates` 不适用）；**重连 = 正例 47**（新四元组、句子流重启、无恢复语义）；FIN 优雅终止由其余全部 TCP 正例 `terminates=true` 承载——v1.3 §4 清单"FIN/RST 或异常中断"双形态闭合；**UDP 无连接**：无握手/挥手/RST/保活语义——UDP 正例不携带 `has_handshake`/`terminates`（恒 false 不写入 expect）。

**动态字段与 fixture 常量**：UTC 时间、经纬度、卫星参数、XOR 校验和的具体值全部为**预配置 fixture 常量**（§3 常量表与字节基线表钉死，逐句 hex 可精确预算、XOR 可逐字节复算——N-16）；运行期变化值（若实现期引入）用 `same_as_packet`/`distinct_values`/`nonzero` 断言。不声称真实定位正确性、卫星真实存在、接收机状态真实。

**包数约定（N-17，全部给算式）**：**TCP 会话 = 3（SYN/SYN-ACK/ACK 握手）+ N（承载句子的 TCP 段数，缺省每句 1 段；粘连合并/跨段切分按实际段数）+ 4（双向 FIN 挥手，FIN+ACK×2+FIN/ACK）**，数据帧从帧 4 起；**RST 终止形态 = 3 + N + 1（单侧 RST，无挥手）**；**UDP = 数据报数**（无握手/挥手）；**多会话按序 = 各会话之和，第二会话握手包号 = 前会话总包数 + 1**；并发（`concurrent:true`）= 各会话之和（交错）；多载体 = TCP 部分与 UDP 部分之和。实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖（依据） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `nmea_tcp_ipv4_stream` | 正 | IPv4/TCP 单流基线：GGA+RMC 两句流、`$..*xx\r\n` 全形态（设计 §2/§3.1；gpsd GGA/RMC） | 9 |
| 2 | `nmea_tcp_ipv4_gga_only` | 正 | GGA 14 个数据字段（末尾 13/14 为空占位）（设计 §3.4；gpsd GGA） | 8 |
| 3 | `nmea_tcp_ipv4_rmc_only` | 正 | RMC 12 字段全形态（状态 A、速度/航向、日期、磁偏角 E/W、模式 A）（设计 §3.4；gpsd RMC） | 8 |
| 4 | `nmea_tcp_ipv6_stream` | 正 | GGA 无定位：质量 0 + 位置字段全空（设计 §3.4） | 8 |
| 5 | `nmea_tcp_multicast` | 正 | fix quality 值域代表 1/2/4 三帧（设计 §3.4/§8；0 由用例 4 承载） | 10 |
| 6 | `nmea_tcp_nondefault_port` | 正 | RMC 12 字段全形态（含磁偏角 E/W + 模式 A）（设计 §3.4；gpsd RMC） | 8 |
| 7 | `nmea_tcp_ipv4_gsa` | 正 | RMC 状态值域：A 有效全字段帧 + V 空字段帧（位置/速度/航向空、模式 N）（设计 §3.4） | 9 |
| 8 | `nmea_tcp_ipv4_gsv` | 正 | GSV 三字段头 + 卫星四字段组（设计 §3.4；gpsd GSV） | 8 |
| 9 | `nmea_tcp_ipv4_vtg` | 正 | VTG 真航向/磁航向/双速度单位/模式 A（设计 §3.4；gpsd VTG） | 8 |
| 10 | `nmea_tcp_ipv4_gll` | 正 | GLL 7 字段位置/时间/状态/模式（设计 §3.4；gpsd GLL） | 8 |
| 11 | `nmea_tcp_ipv4_zda` | 正 | ZDA UTC/日期/有符号本地时区字段（设计 §3.4；gpsd ZDA） | 8 |
| 12 | `nmea_tcp_ipv4_proprietary_pgrme` | 正 | `$PGRME` 专有句与强制校验和（设计 §3.4；GARMIN 公开示例） | 8 |
| 13 | `nmea_tcp_ipv4_gga_gntalker` | 正 | GSV 三消息序列（4+4+3 星、total=3、msg 1/2/3 关联）（设计 §3.4/§5） | 10 |
| 14 | `nmea_tcp_ipv4_gga_gltalker` | 正 | GSV 卫星组 SNR 空字段形态（仰角/方位在场）（设计 §3.4） | 8 |
| 15 | `nmea_tcp_ipv4_gga_iitalker` | 正 | VTG 9 字段（磁航向空占位、双速度单位、模式 A、校验和 `*00`）（设计 §3.4） | 8 |
| 16 | `nmea_tcp_ipv4_gga_nocs` | 正 | GLL 7 字段（位置/时间/状态 A/模式 A）（设计 §3.4） | 8 |
| 17 | `nmea_tcp_ipv4_gga_badcs` | 正 | GGA 错误校验和观测：句子按声明原样输出，不验证通过（设计 §3.3） | 8 |
| 18 | `nmea_tcp_ipv4_pack_gga_rmc` | 正 | ZDA 负时区形态两帧（+08,00 / -05,30）（设计 §3.4/§8） | 9 |
| 19 | `nmea_tcp_ipv4_rmc_void` | 正 | `$P` 专有句：`$PGRME` + opaque payload + 强制校验和（设计 §3.4；GARMIN 公开示例） | 8 |
| 20 | `nmea_tcp_ipv4_gsv_three_seq` | 正 | XOR 复算：四句型流逐句复算（`$`/`*` 排除、两位 hex）（设计 §3.3/§3.1） | 11 |
| 21 | `nmea_tcp_ipv4_gsa_full` | 正 | 校验和含字母位大写形态（`*6E`）（设计 §3.3⑤） | 8 |
| 22 | `nmea_tcp_ipv4_two_sessions_sequential` | 正 | 标准句无校验和合法形态（`M,,` 后直接 CRLF）（设计 §3.3：标准句校验和可选） | 8 |
| 23 | `nmea_tcp_ipv4_concurrent_sessions` | 正 | talker GN（组合 GNSS 现网默认）：GNGGA（设计 §3.2③） | 8 |
| 24 | `nmea_udp_ipv4_gga` | 正 | talker GL（GLONASS）：GLGGA（设计 §3.2） | 8 |
| 25 | `nmea_udp_ipv4_gga_rmc` | 正 | talker II（集成仪表）：IIGLL（设计 §3.2） | 8 |
| 26 | `nmea_udp_ipv6_gga` | 正 | UDP/IPv6 单 GGA 数据报（地址族与 UDP 载体组合）（设计 §2/§8） | 1 |
| 27 | `nmea_udp_multicast_gga` | 正 | UDP 组播目的 `239.192.0.1:10110` 单 GGA 数据报（设计 §8⑤） | 1 |
| 28 | `nmea_udp_nondefault_port_gga` | 正 | UDP 显式非默认目的端口 `4001` 单 GGA 数据报（设计 §2） | 1 |
| 29 | `nmea_udp_pack_gga_rmc` | 正 | UDP GGA+RMC 同一数据报 | 1 |
| 30 | `nmea_udp_gn_gga` | 正 | UDP GN talker GGA 数据报 | 1 |
| 31 | `nmea_udp_rmc_void` | 正 | UDP RMC 状态 A 数据报 | 1 |
| 32 | `nmea_udp_proprietary_pgrme` | 正 | UDP `$PGRME` 专有句数据报 | 1 |
| 33 | `nmea_udp_gsv_three_seq` | 正 | UDP GSV 三消息序列 | 3 |
| 34 | `nmea_udp_two_sessions_concurrent` | 正 | UDP 双会话并发数据报 | 2 |
| 35 | `nmea_udp_vtg` | 正 | UDP VTG 数据报 | 1 |
| 36 | `nmea_udp_gll` | 正 | UDP GLL 数据报 | 1 |
| 37 | `nmea_udp_zda` | 正 | UDP ZDA 数据报 | 1 |
| 38 | `nmea_udp_gsa` | 正 | UDP GSA 数据报 | 1 |
| 39 | `nmea_tcp_rst` | 正 | TCP GGA 后 RST 终止 | 5 |
| 40 | `nmea_tcp_rst_multi` | 正 | TCP GGA+RMC 后 RST 终止 | 6 |
| 41 | `nmea_tcp_udp_coexist` | 正 | TCP GGA + UDP RMC 共存会话（配置边界，未宣称实现完成） | 9 |
| 42 | `nmea_udp_rmc_invalid_status` | 正 | UDP RMC 状态 V 数据报 | 1 |
| 43 | `nmea_tcp_udp_coexist_reversed` | 正 | UDP GGA + TCP RMC 反序共存会话（配置边界，未宣称实现完成） | 9 |
| 44 | `nmea_tcp_ipv4_rmc_220knots` | 正 | TCP RMC 高速 220.5 knots | 8 |
| 45 | `nmea_tcp_gga_galileo_talker` | 正 | TCP GA talker GGA 流 | 8 |
| 46 | `nmea_tcp_gga_beidou_talker` | 正 | TCP BD talker GGA 流 | 8 |
| 47 | `nmea_tcp_gga_gb_talker` | 正 | TCP GB talker GGA 流 | 8 |
| 48 | `nmea_tcp_gga_gi_talker` | 正 | TCP GI talker GGA 流 | 8 |
| 49 | `nmea_tcp_rmc_gq_talker` | 正 | TCP GQ talker RMC 流 | 8 |
| 50 | `nmea_tcp_wf_missing_dollar` | 负 | §7：句子去 `$` 裸地址起始 | — |
| 51 | `nmea_tcp_wf_missing_crlf` | 负 | §7：流末句无 CRLF 裸结束 | — |
| 52 | `nmea_tcp_wf_lf_only` | 负 | §7：行尾仅 LF 无 CR | — |
| 53 | `nmea_tcp_wf_truncated_tcp` | 负 | §7：TCP 流字段中间截断 | — |
| 54 | `nmea_udp_wf_udp_truncated` | 负 | §7：UDP 报文尾无 CRLF（半句入报文） | — |
| 55 | `nmea_udp_wf_udp_cross_datagram` | 负 | §7：一句拆进两个数据报 | — |
| 56 | `nmea_tcp_wf_start_bang` | 负 | §7：`!` 起始（AIS 形态，§3.6 排除项） | — |
| 57 | `nmea_tcp_wf_unknown_talker` | 负 | §7：talker `ZZ` 不在值域表 | — |
| 58 | `nmea_tcp_wf_unknown_type` | 负 | §7：formatter `XYZ` 不在支持集 | — |
| 59 | `nmea_tcp_wf_talker_p_standard` | 负 | §7：`$PGA…` P 当标准 talker | — |
| 60 | `nmea_tcp_wf_field_count_short` | 负 | §7：GGA 12 字段（逗号数不足） | — |
| 61 | `nmea_tcp_wf_field_count_extra` | 负 | §7：GGA 16 字段（多余尾字段） | — |
| 62 | `nmea_tcp_wf_lat_over` | 负 | §7：纬度 9030.0000（90°30′ 越界） | — |
| 63 | `nmea_tcp_wf_lon_over` | 负 | §7：经度 18030.0000 越界 | — |
| 64 | `nmea_tcp_wf_minutes_over` | 负 | §7：分 60.0000（4860.0000） | — |
| 65 | `nmea_tcp_wf_direction_char` | 负 | §7：纬半球 `X` | — |
| 66 | `nmea_tcp_wf_time_out_of_range` | 负 | §7：时间 253519.00（hh=25） | — |
| 67 | `nmea_tcp_wf_date_out_of_range` | 负 | §7：日期 320394（dd=32） | — |
| 68 | `nmea_tcp_wf_status_char` | 负 | §7：RMC 状态 `C` | — |
| 69 | `nmea_tcp_wf_gsa_mode_char` | 负 | §7：GSA 模式 `X` | — |
| 70 | `nmea_tcp_wf_gsa_fix_type` | 负 | §7：GSA 维度 `4` | — |
| 71 | `nmea_tcp_wf_sentence_length` | 负 | §7：83 字节句（82 上界+1） | — |
| 72 | `nmea_tcp_wf_checksum_mismatch` | 负 | §7：`*6A` ≠ 复算 `*69` | — |
| 73 | `nmea_tcp_wf_checksum_hex_width` | 负 | §7：`*` 后一位 hex（`*9`） | — |
| 74 | `nmea_tcp_wf_proprietary_no_checksum` | 负 | §7：$P 句无校验和（专有句强制） | — |
| 75 | `nmea_tcp_wf_gsv_seq_correlation` | 负 | §7：GSV 序号跳变（msg 1→3） | — |
| 76 | `nmea_tcp_wf_carrier_layer_missing` | 负 | §7：层链缺 tcp/udp 直连 | — |
| 77 | `nmea_tcp_wf_carrier_conflict` | 负 | §7：tcp 层链 + udp transport 声明矛盾 | — |
| 78 | `nmea_tcp_wf_port_undeclared` | 负 | §7：非 10110 端口未显式声明 | — |
| 79 | `nmea_tcp_wf_address_family_mismatch` | 负 | §7：v6 地址配 v4 层链（或反向） | — |
| 80 | `nmea_tcp_wf_propagation` | 负 | §7：已知校验错误被吞、任务假成功 | — |

## 3. 线上编码和偏移断言

层链 `[ip, tcp, nmea]` / `[ip, udp, nmea]`，无 VLAN/IP options/TCP options 时**每句首字节（`$`=`24`）起点：TCP/IPv4 offset 54、TCP/IPv6 74、UDP/IPv4 42、UDP/IPv6 62**（句尾恒 `0d 0a`）。断言分层：

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

以下为与 `cases/nmea.json` 当前 49 个正例逐 ID 对齐的最低断言集；TCP/UDP 载体、会话数量、并发/终止形态以 `spec_json` 实际值为准，动态包号未经过 suite 校准时不额外宣称。

1. **`nmea_tcp_ipv4_stream`**（packet_count=9）：TCP single-session GGA+RMC two-sentence stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
2. **`nmea_tcp_ipv4_gga_only`**（packet_count=8）：TCP single-sentence GGA stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
3. **`nmea_tcp_ipv4_rmc_only`**（packet_count=8）：TCP single-sentence RMC stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
4. **`nmea_tcp_ipv6_stream`**（packet_count=9）：TCP IPv6 single-session GGA+RMC stream；断言 `tcp.payload`、frames offset 74、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
5. **`nmea_tcp_multicast`**（packet_count=9）：TCP multicast destination GGA+RMC stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
6. **`nmea_tcp_nondefault_port`**（packet_count=9）：TCP nondefault port 4001；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
7. **`nmea_tcp_ipv4_gsa`**（packet_count=8）：TCP single-sentence GSA stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
8. **`nmea_tcp_ipv4_gsv`**（packet_count=8）：TCP single-sentence GSV stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
9. **`nmea_tcp_ipv4_vtg`**（packet_count=8）：TCP single-sentence VTG stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
10. **`nmea_tcp_ipv4_gll`**（packet_count=8）：TCP single-sentence GLL stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
11. **`nmea_tcp_ipv4_zda`**（packet_count=8）：TCP single-sentence ZDA stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
12. **`nmea_tcp_ipv4_proprietary_pgrme`**（packet_count=8）：TCP $PGRME proprietary sentence stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
13. **`nmea_tcp_ipv4_gga_gntalker`**（packet_count=8）：TCP GN talker GGA stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
14. **`nmea_tcp_ipv4_gga_gltalker`**（packet_count=8）：TCP GL talker GGA stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
15. **`nmea_tcp_ipv4_gga_iitalker`**（packet_count=8）：TCP II talker GGA stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
16. **`nmea_tcp_ipv4_gga_nocs`**（packet_count=8）：TCP GGA without checksum stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
17. **`nmea_tcp_ipv4_gga_badcs`**（packet_count=8）：TCP GGA with deliberately mismatched checksum; this is the **observation mode** and must emit the sentence unchanged (expect does not contain `expect_error`); checksum verification belongs to the negative twin `nmea_tcp_wf_checksum_mismatch` (#72), not this positive case。
18. **`nmea_tcp_ipv4_pack_gga_rmc`**（packet_count=8）：TCP GGA+RMC packed in single segment；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
19. **`nmea_tcp_ipv4_rmc_void`**（packet_count=8）：TCP RMC void status A stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
20. **`nmea_tcp_ipv4_gsv_three_seq`**（packet_count=10）：TCP GSV 3-message sequence stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
21. **`nmea_tcp_ipv4_gsa_full`**（packet_count=8）：TCP 18-field GSA stream；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
22. **`nmea_tcp_ipv4_two_sessions_sequential`**（packet_count=18）：TCP two sequential sessions；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`sessions`=2、`tcp.stream`、`tcp.len`。
23. **`nmea_tcp_ipv4_concurrent_sessions`**（packet_count=18）：TCP two concurrent sessions (interleaved)；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`sessions`=2、`concurrent:true`、`tcp.stream`、`tcp.len`。
24. **`nmea_udp_ipv4_gga`**（packet_count=1）：UDP single GGA datagram；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`udp.srcport`/`udp.dstport`、`udp.length`。
25. **`nmea_udp_ipv4_gga_rmc`**（packet_count=2）：UDP GGA+RMC two datagrams；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`udp.srcport`/`udp.dstport`、`udp.length`。
26. **`nmea_udp_ipv6_gga`**（packet_count=1）：UDP IPv6 single GGA datagram；断言 `udp.payload`、frames offset 62、句首 `24`、句尾 `0d0a`、`udp.srcport`/`udp.dstport`、`udp.length`。
27. **`nmea_udp_multicast_gga`**（packet_count=1）：UDP multicast GGA datagram；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`udp.srcport`/`udp.dstport`、`udp.length`。
28. **`nmea_udp_nondefault_port_gga`**（packet_count=1）：UDP nondefault port 4001；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`udp.srcport`/`udp.dstport`、`udp.length`。
29. **`nmea_udp_pack_gga_rmc`**（packet_count=1）：UDP GGA+RMC packed in single datagram；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`udp.srcport`/`udp.dstport`、`udp.length`。
30. **`nmea_udp_gn_gga`**（packet_count=1）：UDP GN talker GGA datagram；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`udp.srcport`/`udp.dstport`、`udp.length`。
31. **`nmea_udp_rmc_void`**（packet_count=1）：UDP RMC status A datagram；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`udp.srcport`/`udp.dstport`、`udp.length`。
32. **`nmea_udp_proprietary_pgrme`**（packet_count=1）：UDP $PGRME proprietary datagram；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`udp.srcport`/`udp.dstport`、`udp.length`。
33. **`nmea_udp_gsv_three_seq`**（packet_count=3）：UDP GSV 3-message sequence；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`udp.srcport`/`udp.dstport`、`udp.length`。
34. **`nmea_udp_two_sessions_concurrent`**（packet_count=2）：UDP two concurrent sessions；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`sessions`=2、`concurrent:true`、`udp.srcport`/`udp.dstport`、`udp.length`。
35. **`nmea_udp_vtg`**（packet_count=1）：UDP VTG datagram；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`udp.srcport`/`udp.dstport`、`udp.length`。
36. **`nmea_udp_gll`**（packet_count=1）：UDP GLL datagram；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`udp.srcport`/`udp.dstport`、`udp.length`。
37. **`nmea_udp_zda`**（packet_count=1）：UDP ZDA datagram；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`udp.srcport`/`udp.dstport`、`udp.length`。
38. **`nmea_udp_gsa`**（packet_count=1）：UDP GSA datagram；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`udp.srcport`/`udp.dstport`、`udp.length`。
39. **`nmea_tcp_rst`**（packet_count=5）：TCP RST termination after GGA；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
40. **`nmea_tcp_rst_multi`**（packet_count=6）：TCP RST termination after GGA+RMC；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
41. **`nmea_tcp_udp_coexist`**（packet_count=10）：TCP GGA + UDP RMC coexisting sessions；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`sessions`=2、按 session `transport` 分流、`udp.srcport`/`udp.dstport`、`udp.length`。
42. **`nmea_udp_rmc_invalid_status`**（packet_count=1）：UDP RMC void status V；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`udp.srcport`/`udp.dstport`、`udp.length`。
43. **`nmea_tcp_udp_coexist_reversed`**（packet_count=10）：UDP GGA + TCP RMC coexisting sessions (reversed order)；断言 `udp.payload`、frames offset 42、句首 `24`、句尾 `0d0a`、`sessions`=2、按 session `transport` 分流、`udp.srcport`/`udp.dstport`、`udp.length`。
44. **`nmea_tcp_ipv4_rmc_220knots`**（packet_count=8）：TCP RMC with high speed 220.5 knots；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
45. **`nmea_tcp_gga_galileo_talker`**（packet_count=8）：TCP GA talker GGA stream (Galileo)；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
46. **`nmea_tcp_gga_beidou_talker`**（packet_count=8）：TCP BD talker GGA stream (BeiDou)；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
47. **`nmea_tcp_gga_gb_talker`**（packet_count=8）：TCP GB talker GGA stream (GB)；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
48. **`nmea_tcp_gga_gi_talker`**（packet_count=8）：TCP GI talker GGA stream (NavIC/IRNSS)；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
49. **`nmea_tcp_rmc_gq_talker`**（packet_count=8）：TCP GQ talker RMC stream (QZSS)；断言 `tcp.payload`、frames offset 54、句首 `24`、句尾 `0d0a`、`tcp.stream`、`tcp.len`。
**正例总则**：每条实现后至少含 `packet_count`（或 `min_packets`）+ 载体与方向断言 + `has_payload` + 可观察 fields（`tcp.*`/`udp.*`/`ip.version`/`ipv6.nxt` 实测字段）+ 稳定 frames（句首 `24`/地址/句尾 `0d0a`）；句 hex 均由 §3 字节基线表钉死（可精确预算、XOR 可复算）。合法协议事件（无校验和标准句、无定位空字段、RMC 状态 V、GSA 稀疏/2D 空 VDOP、GSV SNR 空、VTG 磁航向空、`*00` 校验和、观测坏校验和、多播目的）均为正例形态，只有配置、线格式、字段、值域、长度、关联、载体错误进入负例（设计 §7）。**代表值策略声明**（设计 §8）：fix quality 5-8、RMC 模式 D/E、ZDA 时区 ±13 满值、talker GA/GB/GQ/GI/BD/AI/EC/HC/WI/CD/SD/VD、小写校验和、广播 UDP、tag block、GSV signal ID、空字段全空最短句——值域声明 + validator 校验，不逐值设例。

**#2/#49 语义对账修正**：#2 是 GGA **14 个数据字段**的单句字段/空占位基线；#49 是 GQ（QZSS）talker 的 RMC 单句值域覆盖，二者不再以“15 字段”或未登记 talker 描述。

**校验和两态约定**：#17 `nmea_tcp_ipv4_gga_badcs` 是**观测正例**，配置显式 `checksum_value:6A`，期望生成并原样输出错误 XOR 文本；不把它称为“验证校验和”或成功校验。#72 `nmea_tcp_wf_checksum_mismatch` 才是 validator 拒绝并传播 `checksum` 锚词的负例；两者共享同一错误字节形态但分别验证观测与拒绝，不得混写。

## 5. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP/UDP 外壳的假成功；执行期 `expect` 键集合**严格为** `{expect_error, error_contains}`。**单一注入纪律（N-4）：一行一例，钉死该行注入的单一 `wire_fault`/配置变异；主锚词为钉死的单一字面值**（不再是候选列表）；`wire_fault` 注入口列与设计 §6 枚举/§7 表三方一一对应（31 值同序）：

| # | ID | `wire_fault` 注入口 | 故障输入（单一注入） | 主锚词 |
|---:|---|---|---|---|
| 50 | `nmea_tcp_wf_missing_dollar` | `missing_dollar` | GGA 句去 `$`（`GPGGA,…*69` 裸地址起始） | `dollar` |
| 51 | `nmea_tcp_wf_missing_crlf` | `missing_crlf` | 流末句去 CRLF（`…*69` 裸结束） | `crlf` |
| 52 | `nmea_tcp_wf_lf_only` | `lf_only` | 行尾仅 LF（`…*69` + `0A`，无 CR） | `crlf` |
| 53 | `nmea_tcp_wf_truncated_tcp` | `truncated_tcp` | TCP 流在纬度字段中间结束（`…,48` 后流终、无 CRLF） | `truncat` |
| 54 | `nmea_udp_wf_udp_truncated` | `udp_truncated` | UDP 报文尾无 CRLF（`…*69` 封入报文、无 `0D0A`） | `datagram` |
| 55 | `nmea_udp_wf_udp_cross_datagram` | `udp_cross_datagram` | 一句拆进两个数据报（报文 1 至字段中、报文 2 接余下） | `datagram` |
| 56 | `nmea_tcp_wf_start_bang` | `start_bang` | `!AIVDM,1,1,,,,…` 起始（AIS 封装形态，设计 §3.6） | `start` |
| 57 | `nmea_tcp_wf_unknown_talker` | `unknown_talker` | talker `ZZ`（`$ZZGGA,…`——不在 §3.2 值域表） | `talker` |
| 58 | `nmea_tcp_wf_unknown_type` | `unknown_type` | formatter `XYZ`（`$GPXYZ,…`——不在支持集） | `type` |
| 59 | `nmea_tcp_wf_talker_p_standard` | `talker_p_standard` | `$PGA,123519.00,…`（P 当标准 talker，5 字符地址误用） | `talker` |
| 60 | `nmea_tcp_wf_field_count_short` | `field_count_short` | GGA 12 字段（`…,M,46.9,M` 即止，尾部两字段连逗号缺失） | `field` |
| 61 | `nmea_tcp_wf_field_count_extra` | `field_count_extra` | GGA 16 字段（`…,M,,,*69` 追加多余尾字段） | `field` |
| 62 | `nmea_tcp_wf_lat_over` | `lat_over` | 纬度 `9030.0000,N`（dd=90 且分>0——越 90°） | `latitude` |
| 63 | `nmea_tcp_wf_lon_over` | `lon_over` | 经度 `18030.0000,E`（越 180°） | `longitude` |
| 64 | `nmea_tcp_wf_minutes_over` | `minutes_over` | 纬度 `4860.0000,N`（分 60.0000 ≥60） | `minute` |
| 65 | `nmea_tcp_wf_direction_char` | `direction_char` | 纬半球 `X`（∉ N/S） | `direction` |
| 66 | `nmea_tcp_wf_time_out_of_range` | `time_out_of_range` | UTC `253519.00`（hh=25 越界） | `time` |
| 67 | `nmea_tcp_wf_date_out_of_range` | `date_out_of_range` | 日期 `320394`（dd=32 越界） | `date` |
| 68 | `nmea_tcp_wf_status_char` | `status_char` | RMC 状态 `C`（∉ A/V） | `status` |
| 69 | `nmea_tcp_wf_gsa_mode_char` | `gsa_mode_char` | GSA 模式 `X`（∉ M/A） | `mode` |
| 70 | `nmea_tcp_wf_gsa_fix_type` | `gsa_fix_type` | GSA 维度 `4`（∉ 1/2/3） | `fix` |
| 71 | `nmea_tcp_wf_sentence_length` | `sentence_length` | 83B 句（`$PXYZ,P×72*xx`——82 上界 +1） | `length` |
| 72 | `nmea_tcp_wf_checksum_mismatch` | `checksum_mismatch` | `*6A` ≠ 句内复算 `*69`（与正例 17 观测态同源、本行为拒绝） | `checksum` |
| 73 | `nmea_tcp_wf_checksum_hex_width` | `checksum_hex_width` | `*` 后一位 hex（`…*9` + CRLF——宽度非恰 2） | `checksum` |
| 74 | `nmea_tcp_wf_proprietary_no_checksum` | `proprietary_no_checksum` | `$PGRME,15.0,M,20.0,M,25.0,M` + CRLF（专有句强制校验和，设计 §3.3） | `checksum` |
| 75 | `nmea_tcp_wf_gsv_seq_correlation` | `gsv_seq_correlation` | GSV 序列 msg 跳变（total=3、msg 1→3 缺 2——§5 唯一句间关联） | `sequence` |
| 76 | `nmea_tcp_wf_carrier_layer_missing` | `carrier_layer_missing` | 层链 `[{"nmea":{}}]` 直连（缺 tcp/udp） | `carrier` |
| 77 | `nmea_tcp_wf_carrier_conflict` | `carrier_conflict` | tcp 层链 + 会话 `transport:"udp"` 声明矛盾 | `carrier` |
| 78 | `nmea_tcp_wf_port_undeclared` | `port_undeclared` | `dst_port=4001` 而未显式声明（静默回退禁止） | `port` |
| 79 | `nmea_tcp_wf_address_family_mismatch` | `address_family_mismatch` | IPv6 地址配 IPv4 层链（`[ip,tcp,nmea]` + v6 地址）或反向 | `family` |
| 80 | `nmea_tcp_wf_propagation` | `propagation` | validator 已知校验和错误被吞、任务 completed/0 packet 假成功 | `propagat` |

合法协议事件不进负例（防误报，同设计 §7 防误报清单）：标准句无校验和（正例 22）、观测坏校验和（正例 17）、RMC 状态 V/空字段（正例 7）、GGA 质量 0 空字段（正例 4）、GSA 稀疏空槽与 2D 空 VDOP（正例 10/11）、GSV SNR 空（正例 14）、VTG 磁航向空、`*00` 校验和（正例 15）、空字段占位（全部可空字段）、多播目的（正例 40）、非默认端口显式声明（正例 42）。

## 6. 五层覆盖映射

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 1-25、30-36（正）；50-80（负） | 七句型 + $P 每型至少一例（GGA 4/RMC 2/GSA 4/GSV 3/VTG/GLL/ZDA/$P 各 1-2，字段级拆分）、校验和三形态（复算/大写/省略）、talker 4 例、GSV 序列关联（13）、TCP 组帧七形态；负例 31 类逐故障（线格式 7/地址 3/字段 2/值域 10（含长度）/校验 3/关联 1/载体 4/传播 1）；`!` AIS 与 tag block 为设计 §3.6/§1 排除项 |
| 性能 | 30、35、36；负 71 | 多句粘连单段（115B 两句）、30 句打包 2100B 跨 2 段重组、82B 句长上界（+相邻 83 负例）；发包速率由框架既有配置承载（v1.3 §10 口径） |
| 数据场景 | 4、5、7、9、10、11、14、18、26-29；负 62-70 | 空字段三形态（GGA 可选字段/无定位/RMC void）、fix quality 与模式/状态/维度枚举、GSV SNR 空、ZDA 正负时区、度分值域边界（0/满度/59.9999/南西半球）、时间/日期/状态/模式/维度越界拒绝 |
| 地址与流 | 1（v4 TCP 单流基线）、37（v4 UDP 基线）、39（UDP v6）、41（TCP v6）、40（多播）、42（非默认端口）、43（多载体）、44（多会话按序）、45（并发交错）、46（RST）、47（重连） | TCP/UDP × v4/v6 四组合；并发会话（45，N-1）；RST/重连（46/47，N-8）；流关联与多流显式不适用（设计 §4：单向传感器数据流，无控制/数据分离、单连接串行） |
| 业务 | 1/2/6（接收机持续推送）、23/24（多星座接收机）、4/7（无定位告警）、8-14（卫星状态巡检）、15-18（航行数据面板）、19（厂商扩展混流）、44/45（AIS/GPS 网关多设备）、46/47（断流重连）、37-40（UDP 网关分发） | 现网 NMEA 日常场景优先（§4 场景表逐行对应用例） |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/nmea.json` 通过；当前数组含 80 条语义用例（49 正/31 负），正例层链迁移完成，31 条负例均保留故意故障形状。
2. `nmea.json` 与本文 §2/§8 三方按实际 80 条语义用例对账；ID 权威为本文 §2，负例 `nmea_tcp_wf_carrier_layer_missing` 是故意缺承载层形状。
3. **计数自查**：§2 表行数 = 80（49 个正例 + 31 个负例）；§8 一致性清单 ID 数与 JSON 实际顺序一致；脚本断言三方同序。
4. 正例每条含 `packet_count`（或 `min_packets`）+ `fields` + `frames`；`fields` 只用 §1 实测存在的 tshark 字段（`tcp.*`/`udp.*`/`ip.version`/`ipv6.nxt`/`frame.*`），**不使用任何 `nmea.*` 字段**（本机无本协议 dissector，实测钉死）；断言通道 = `tcp.payload`/`udp.payload` 整句 hex + frames offset 54/74/42/62 双通道。
5. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields/frames。
6. **负例原子性（N-4/N-5）**：31 行每行恰注入一个故障；`wire_fault` 取值集合 = §5 注入口列 31 值（三方同序：设计 §6 枚举/§7 表/本文 §5 表）；主锚词为单一钉死字面值，无候选列表；旧稿"坏 JSON"外类故障已删除（ASCII 句子协议无 JSON 成分）。
7. **包数算式（N-17）**：TCP = 3+N+4（RST 形态 3+N+1）；UDP = 报文数；多会话/并发/多载体 = 各部分之和（第二会话握手包号 = 前会话总包数 + 1）；§2 表 packet_count 列与 §4 逐例算式逐行一致（脚本核验）；实现期以实际输出校准。
8. **summary/覆盖描述对账**：JSON 各例 summary 须与本文 §2 对应行的覆盖描述一致；`nmea_tcp_wf_carrier_layer_missing` 的 summary 明确为缺承载层负例，不得写成正例能力。
9. **pcap/NIC 双输出（N-3）**：两输出路径共用本契约（同一 cases JSON、同一 fields/frames 断言），NIC 路径抓包口差异不改变断言语义（网卡 offload 不影响句内 XOR——应用层 ASCII 文本）；不设仅单路径可用的断言。
10. 跨会话/跨段断言用 `tcp.stream`/`udp.stream` + 多会话展开起点规则（§3.4），不硬编码全局包号；句内值全部 fixture 钉死（§3 基线表），运行期值用 `same_as_packet`/`distinct_values`/`nonzero`。
11. 若实现期实证发现端口惯例（10110/4001/多播组）、小写校验和接受性、度分小数位形态与本版 ⑤ 假设不符，设计 §3 与本文 §3/§4 对应断言同步校准，并在两文档修订记录登记。

## 8. 三方一致性表

设计 §9（簇级图景）、本文 §2、`nmea.json` 保持同一 80 个语义 ID、同一顺序；负例故意故障形状按 §5 保留，不作为正例层链入口。

```text
nmea_tcp_ipv4_stream
nmea_tcp_ipv4_gga_only
nmea_tcp_ipv4_rmc_only
nmea_tcp_ipv6_stream
nmea_tcp_multicast
nmea_tcp_nondefault_port
nmea_tcp_ipv4_gsa
nmea_tcp_ipv4_gsv
nmea_tcp_ipv4_vtg
nmea_tcp_ipv4_gll
nmea_tcp_ipv4_zda
nmea_tcp_ipv4_proprietary_pgrme
nmea_tcp_ipv4_gga_gntalker
nmea_tcp_ipv4_gga_gltalker
nmea_tcp_ipv4_gga_iitalker
nmea_tcp_ipv4_gga_nocs
nmea_tcp_ipv4_gga_badcs
nmea_tcp_ipv4_pack_gga_rmc
nmea_tcp_ipv4_rmc_void
nmea_tcp_ipv4_gsv_three_seq
nmea_tcp_ipv4_gsa_full
nmea_tcp_ipv4_two_sessions_sequential
nmea_tcp_ipv4_concurrent_sessions
nmea_udp_ipv4_gga
nmea_udp_ipv4_gga_rmc
nmea_udp_ipv6_gga
nmea_udp_multicast_gga
nmea_udp_nondefault_port_gga
nmea_udp_pack_gga_rmc
nmea_udp_gn_gga
nmea_udp_rmc_void
nmea_udp_proprietary_pgrme
nmea_udp_gsv_three_seq
nmea_udp_two_sessions_concurrent
nmea_udp_vtg
nmea_udp_gll
nmea_udp_zda
nmea_udp_gsa
nmea_tcp_rst
nmea_tcp_rst_multi
nmea_tcp_udp_coexist
nmea_udp_rmc_invalid_status
nmea_tcp_udp_coexist_reversed
nmea_tcp_ipv4_rmc_220knots
nmea_tcp_gga_galileo_talker
nmea_tcp_gga_beidou_talker
nmea_tcp_gga_gb_talker
nmea_tcp_gga_gi_talker
nmea_tcp_rmc_gq_talker
nmea_tcp_wf_missing_dollar
nmea_tcp_wf_missing_crlf
nmea_tcp_wf_lf_only
nmea_tcp_wf_truncated_tcp
nmea_udp_wf_udp_truncated
nmea_udp_wf_udp_cross_datagram
nmea_tcp_wf_start_bang
nmea_tcp_wf_unknown_talker
nmea_tcp_wf_unknown_type
nmea_tcp_wf_talker_p_standard
nmea_tcp_wf_field_count_short
nmea_tcp_wf_field_count_extra
nmea_tcp_wf_lat_over
nmea_tcp_wf_lon_over
nmea_tcp_wf_minutes_over
nmea_tcp_wf_direction_char
nmea_tcp_wf_time_out_of_range
nmea_tcp_wf_date_out_of_range
nmea_tcp_wf_status_char
nmea_tcp_wf_gsa_mode_char
nmea_tcp_wf_gsa_fix_type
nmea_tcp_wf_sentence_length
nmea_tcp_wf_checksum_mismatch
nmea_tcp_wf_checksum_hex_width
nmea_tcp_wf_proprietary_no_checksum
nmea_tcp_wf_gsv_seq_correlation
nmea_tcp_wf_carrier_layer_missing
nmea_tcp_wf_carrier_conflict
nmea_tcp_wf_port_undeclared
nmea_tcp_wf_address_family_mismatch
nmea_tcp_wf_propagation
```

## 9. 层链迁移审计（T1-T6，2026-09-30）

| ID | 测试审计结论 | 证据 |
|---|---|---|
| T1 | 80 个语义 ID（49 正/31 负）与 JSON 一一对账；规范/设计/现网依据列已在 §2/§6 给出 | §2、§6、JSON 机读清单 |
| T2 | 测试点按句型、承载、边界、会话、错误传播先行列出，再映射 JSON | §2、§6 |
| T3 | 正例按不可再分行为组织，覆盖数据形态/业务场景/现网场景及字段/边界断言；负例单一注入 | §4/§5 |
| T4 | 单向协议无同连接多轮事务；非正常结束由 RST 46、长保活按 NMEA 周期输出口径登记为不适用 | §1/§4/设计 §5 |
| T5 | 旧 20 例已等价拆分为当前 49+31 原子 ID；去向为 §2 与 §8，同名旧稿不再作为权威 | §8、修订记录 |
| T6 | 31 个负例均只含 `expect_error` 与 `error_contains`；断言禁止成功包假绿 | §5、JSON 全量审计 |

### 9.1 六项覆盖清单（C1-C6）

| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | JSON 可解析、80 ID 唯一、49 正/31 负 | 已逐条对账 |
| C2 | 正例严格 `[ip,carrier,nmea]` 层链；故意错误层链仅在负例 | 常规 47 个正例已迁移；41/43 保留 tcp+udp 并列层链作为当前代码能力下的**严格 C2 迁移缺口**，不计为 C2 已完成证据；地址/端口无游离顶层键 |
| C3 | 七句型、双载体、IPv4/IPv6、会话与字段边界均有覆盖 | §2/§6 与 JSON 对应 |
| C4 | 31 负例带精确锚词且无成功断言 | 已逐条对账 |
| C5 | 多会话/并发/重连/多载体均有 §2 ID 去向 | 44–47、43；41/43 的多载体形状仅登记迁移缺口，不宣称严格 C2 或混合输出已完成 |
| C6 | pcap/NIC 双输出契约已写明；本轮未重跑 suite/NIC | 待 G-NMEA-2 闭环，不宣称通过 |

## 10. 修订记录

- v1.0.0（2026-08-20）：旧稿首版（14 正 + 6 负，粗粒度语义用例，散文式断言、无 hex 基线、无包数算式、负例三锚词候选列表）。
- v2.0.0（2026-09-02，v1.3 重写级修复轮）：独立审查报告（docs-bacnet，/tmp/nmea_v13/report.md）23 findings（C 10 / D 8 / N 5）+ §0 行为面枚举 ~92 测试点逐条落，20 → **80 例（49 正 + 31 负）**。逐条落点（与设计 §10 同步）：N-1 并发会话（45，`concurrent:true` 三设备交错）+ #11 拆分为按序（44）/并发（45）；N-2/§1 输出契约段；N-7 版本化实测基线（无 dissector/无 nmea.*/无 DecodeAs）+ 非默认端口正例 42 + 负例 78；N-8 RST 正例 46/重连正例 47 + 保活口径 + UDP 无连接声明；N-9 句型原子化（GGA 4 例等逐字段拆分）；N-10 talker 三正例（23-25）+ `!` 起始负例 56；N-11 校验和口径引规范原文（标准句可选正例 22/专有句强制负例 74）；N-12 度分边界正例 26-29 + 负例 62-65 原子拆分；N-13 GSV 序号负例 75 + 多播正例 40；N-14/N-16 逐字段表 + 长度公式 + §3 字节基线表（fixture 常量钉死、XOR 逐句复算）；N-15 §1/§4 口径（单向流/保活/RST/重连/并发）+ 五层映射；N-17 包数算式（§1 约定 + §4 逐例，含 §2 表五行勘误注记）；N-18 §2 依据列；N-19 ID 权威 = 本文 §2；N-20 §7.8 JSON notes 注册同步项；N-21 坏校验和观测正例（17）与负例 72 两态同源；N-22 IPv6 断言 `ipv6.nxt` + 显式地址；N-23 多载体正例 43 + 术语。**复验修正（提交前，与设计 §10 同步）**：§3 基线表 4 处 fixture 结构错误修正（GGA 无定位 37B/*45、RMC V 40B/*7F、GSA 满槽/手动 63B/*3F/*33 补卫星 32、GSV 序列 70/70/57B/*76/*70/*40 恰 11 星），§4 用例 4/7/8/9/13 断言与长度/校验和同步更新。

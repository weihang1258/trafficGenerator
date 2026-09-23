# EDP（增强设备协议，Enhanced Device Protocol / 中国移动 OneNET 设备接入协议）测试用例契约

> 版本：v2.1.0（测试用例）
> 日期：2026-09-02
> 配套设计：`docs/protocol-designs/72-edp-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/edp.json`（proto key：`edp`；本版不写文件，当前 JSON 仅含注册前置占位，占位端口已对齐 fixture）
> 状态：**已按 v1.3 重审清单修复（v2.1.0），待审查方复验关闭**（按《协议设计文档与用例文档需求文档》§3 流程：本文不自行宣称已通过对抗审查，以审查方对问题清单逐条确认关闭为完成标准）。
> 修订记录：v2.1.1（2026-09-23，修轮 F9 勘误）：§2 行 48/§4.48 约定包数 1444→1446（3+2+1437+4，原表算术自相矛盾；引擎与分段模拟双证 1446）；v2.1.0（2026-09-02）：按《需求文档 v1.3》rr-edp 重审（8C+5N）全量落地，用例 39 → **89 条（61 正 + 28 负）**（行为面全枚举 ~125 点、0.7+ 例/点，doh 111/onvif 95 同档）：**C-1** §1 补 pcap/NIC 双输出契约；**C-2** 并发会话翻案纳入 + `edp_concurrent_sessions`；**C-4** +`edp_port_nondefault`（12472）；**C-5** 负例 12 → 28 行原子拆分（一行一注入）、wire_fault 枚举 28 值 1:1 同序、锚词改"主锚词钉死（备选括注）"；**C-6** 边界相邻值族补齐（127/16,383/2,097,151 各档上界 + json 65,534 + devid u16 上界 65,535）；**C-7** edp.json 占位三处对齐（4472/41072/notes 89）；**C-8** §1 edp.* 字段表述更正（字段存在但全部属 Extreme Discovery Protocol）；**N4** 标志×格式矩阵 4×5 全 20 格补齐（+13 例）；**N5** +`edp_connack_rtn1`。另补行为面扩量例：多帧粘连、二进制透传/命令载荷、SAVEACK err_code≠0、msg_id 满值、keep_time 最小非零、64B cmdid、心跳 3 轮、IPv6 全事务、type3 值域 string/对象、type1 token 变体（取代 v2.0.1 的范围外声明）。ID 权威 = 本文 §2（设计 §9 改簇级）。
> 修订记录：v2.0.1（2026-09-01）：按独立隔离审查 9 项问题清单（4 MAJOR + 5 MINOR）修复——E01 用例 `edp_datapoint_value_types` `tcp.len` 344→345（1+2+342）；E02 新增 4 字节变长档正例 `edp_remainlen_4byte_band`（remainlen 恰 2,097,152），`edp_remainlen_multibyte` 改 128 下界、`edp_mss_large_bin` 改 16,384 档下界；E03 rtn 值域声明；E04 CONNRESP 帧号 6→5；E05 负例 state 补 DISCONNECT 后注入；E06 keep_time 默认值断言由用例 1 承载；E07 +`edp_json_u16_max`；E08 token 范围外声明（v2.1 已由正例取代）；E09 +`edp_savedata_deliver`。另修 1 处清单外算术错（`edp_long_devid` 141 为 2 字节 varint，总长 144）。
> 修订记录：v2.0.0（2026-09-01）：按需求文档 v1.1 独立隔离审查流程重写，取代 2026-08-21 旧稿（旧稿 14+6 用例基于已废弃的臆造线格式）。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 **89 个唯一语义 ID：61 个正例 + 28 个负例**（v1.3 行为面全枚举：消息 × 字段 × 值域 × 边界相邻值 × 错误分支 × 载体 × 场景 × 交互，约 125 个可测试行为点）。派生规则：设计 §3 每个编码条款（每消息类型、每数据格式、每标志组合、每变长长度档含双侧边界）、§5 每个状态/事务/关联行为、§7 每行错误处理（一行一注入）在本文有对应断言；断言不得超出设计（并追溯到 OneNET 官方 EdpKit SDK / 官方文档站）声明范围。**一个用例只验证一个协议行为**（原子原则）。

当前 JSON 只保留一个 `edp_neg_unregistered` 注册前置占位：`proto=edp`、`expect_error=true`、`error_contains` 精确为 `unknown layer`；该占位不计入 89 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 EDP 行为通过。注册后移除占位，再按本文 §2 顺序补入 61 个正例与 28 个负例（占位端口已在 v2.1 对齐 fixture：src_port 41072、dst_port 4472）。

**输出契约（pcap/NIC 双输出）**：本协议全部用例同时兼容两种输出路径——`pcap` 文件输出（断言以 tshark 读 pcap 为准）与 `port_group`/NIC 网口输出（同一份用例契约驱动真实发包，断言由抓包侧使用相同 tshark 字段/原始字节校验）；两路径共用同一 cases JSON，不设仅单路径可用的断言（需求文档 v1.3 §8.2-7）。

**TSHARK 实测基线（本机 3.6.14，`-G fields`/`-G protocols` 核验 + 构造 pcap 实证，非臆造）**：本机**没有 OneNET EDP 的 dissector（解析器）**——`tshark -G protocols` 里的 "EDP" 是 **Extreme Discovery Protocol**（Extreme 网络设备邻居发现协议），与本协议无关；`-G fields` 实测**存在 `edp.*` 字段**（`edp.version`/`edp.reserved`/`edp.length`/`edp.checksum` 等），**全部属 Extreme Discovery Protocol、与本协议无关，禁用任何 `edp.*` 字段**（实现期字段白名单不得误收 Extreme 的字段）。可用字段（`-G fields` 实测存在）：`tcp.payload`（FT_BYTES，TCP 载荷原始字节——**即完整 EDP 报文**，构造 pcap 实证精确提取）、`tcp.len`、`tcp.srcport`、`tcp.dstport`、`tcp.stream`、`tcp.flags.syn/ack/fin/push`、`ip.version`、`ipv6.nxt`、`frame.number`、`frame.len`。**断言通道与端口无关、无 DecodeAs 依赖**（设计 §2）：不依赖端口→dissector 绑定。EDP 内容断言双通道：① `tcp.payload` 全帧 hex 值断言（fields）；② raw frame EDP 首字节起点（IPv4 offset 54 / IPv6 offset 74）的 `frames` `offset/hex` 断言。**TCP 分段边界不是 EDP 帧边界**：跨段报文按 `tcp.stream` 重组后再断言完整帧。

**动态字段禁止硬编码**：SAVEACK 应答 JSON 的 msg_id/err_code、CMDREQ 的 cmdid 为生成期值时用 `same_as_packet`/`distinct_values`/`nonzero` 或 fixture 钉死值断言；本版 fixture 把 devid/apikey/msg_id/cmdid/JSON 内容全部钉死为常量（见 §3 fixture 常量），帧字节断言按设计 §3 公式可精确预算（构造 pcap 已实证）。

**包数约定**（单帧不跨段时）：会话 = 3（TCP 握手）+ N（承载 EDP 报文的 TCP 段数，通常每报文 1 段）+ 4（双向 FIN 挥手）。connect 事件含 CONNREQ+CONNRESP 两帧；跨 MSS 大帧 N = ceil(帧长/1460)；实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count。

## 2. 原子用例索引（ID 唯一权威）

| # | ID | 类型 | 覆盖（设计 §） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `edp_connreq_devid_ipv4` | 正 | §3.3/§4①：方式 1 连接 + CONNRESP rtn=0，IPv4 单流基线 | 9 |
| 2 | `edp_connreq_userid` | 正 | §3.3：方式 2 连接（0xC0、空 devid、userid+authinfo） | 9 |
| 3 | `edp_connack_refused` | 正 | §3.3：CONNRESP rtn=2 拒绝路径 + 连接关闭 | 9 |
| 4 | `edp_connack_rtn1` | 正 | §3.3：CONNRESP rtn=1（协议错误）路径 | 9 |
| 5 | `edp_port_nondefault` | 正 | §2：非默认端口 12472（端口变体声明，断言与端口无关） | 9 |
| 6 | `edp_pingreq_pingresp` | 正 | §3.4：心跳（2 字节最小帧） | 11 |
| 7 | `edp_heartbeat_multi` | 正 | §3.4/§4②：周期心跳 3 轮（单连接重复心跳事务） | 15 |
| 8 | `edp_savedata_type1_fulljson` | 正 | §3.5：type1 × flag 0xC0（FullJson 基线） | 10 |
| 9 | `edp_savedata_type1_flag00` | 正 | §3.5：type1 × flag 0x00（矩阵格） | 10 |
| 10 | `edp_savedata_type1_flag40` | 正 | §3.5：type1 × flag 0x40（矩阵格） | 10 |
| 11 | `edp_savedata_type1_flag80` | 正 | §3.5：type1 × flag 0x80（矩阵格） | 10 |
| 12 | `edp_savedata_type1_token` | 正 | §3.5：type1 顶层 `token` 变体（JSON 内容自由度正例化） | 10 |
| 13 | `edp_savedata_type3_simple` | 正 | §3.5：type3 × flag 0x00（简单 JSON 基线） | 10 |
| 14 | `edp_savedata_type3_flag40` | 正 | §3.5：type3 × flag 0x40（矩阵格） | 10 |
| 15 | `edp_savedata_type3_flag80` | 正 | §3.5：type3 × flag 0x80（矩阵格） | 10 |
| 16 | `edp_savedata_type3_flagc0` | 正 | §3.5：type3 × flag 0xC0（矩阵格） | 10 |
| 17 | `edp_savedata_type3_value_string` | 正 | §3.5：type3 值域 string（`{"status":"online"}`） | 10 |
| 18 | `edp_savedata_type3_value_object` | 正 | §3.5：type3 值域对象（loc 形态） | 10 |
| 19 | `edp_savedata_type4_time` | 正 | §3.5：type4 × flag 0x40（时间键基线） | 10 |
| 20 | `edp_savedata_type4_flag00` | 正 | §3.5：type4 × flag 0x00（矩阵格） | 10 |
| 21 | `edp_savedata_type4_flag80` | 正 | §3.5：type4 × flag 0x80（矩阵格） | 10 |
| 22 | `edp_savedata_type4_flagc0` | 正 | §3.5：type4 × flag 0xC0（矩阵格） | 10 |
| 23 | `edp_savedata_type5_string` | 正 | §3.5：type5 × flag 0x80（裸字符串基线） | 10 |
| 24 | `edp_savedata_type5_flag00` | 正 | §3.5：type5 × flag 0x00（矩阵格） | 10 |
| 25 | `edp_savedata_type5_flag40` | 正 | §3.5：type5 × flag 0x40（矩阵格） | 10 |
| 26 | `edp_savedata_type5_flagc0` | 正 | §3.5：type5 × flag 0xC0（矩阵格） | 10 |
| 27 | `edp_savedata_type2_bin` | 正 | §3.5：type2 × flag 0xC0（desc+u32+bin 基线） | 10 |
| 28 | `edp_savedata_type2_flag40` | 正 | §3.5：type2 × flag 0x40（矩阵格） | 10 |
| 29 | `edp_savedata_type2_flag80` | 正 | §3.5：type2 × flag 0x80（矩阵格） | 10 |
| 30 | `edp_savedata_bin_empty` | 正 | §3.5/§8：type2 × flag 0x00 + bin_len=0 边界 | 10 |
| 31 | `edp_savedata_deliver` | 正 | §3.2/§3.5：平台→设备 SAVEDATA 同构方向 | 10 |
| 32 | `edp_saveack_msgid` | 正 | §3.6：msg_id 关联回带（err_code=0） | 11 |
| 33 | `edp_saveack_err_code` | 正 | §3.6：SAVEACK err_code=1（非零结果码变体） | 11 |
| 34 | `edp_msgid_max` | 正 | §3.5/§8：msg_id u16 满值 0xFFFF | 10 |
| 35 | `edp_pushdata_upload` | 正 | §3.7：设备→平台透传（文本载荷） | 10 |
| 36 | `edp_pushdata_deliver` | 正 | §3.7：平台→设备下发 | 10 |
| 37 | `edp_pushdata_binary` | 正 | §3.7：透传二进制不透明载荷 | 10 |
| 38 | `edp_cmdreq_cmdresp` | 正 | §3.8：命令事务（cmdid 关联、resp 非空文本） | 11 |
| 39 | `edp_cmdresp_empty` | 正 | §3.8：resp_len=0 条件缺省 | 11 |
| 40 | `edp_cmdreq_binary` | 正 | §3.8：命令二进制载荷（req/resp 均 4B） | 11 |
| 41 | `edp_cmdid_long` | 正 | §3.8/§8：64B 长 cmdid 关联 | 11 |
| 42 | `edp_disconnect` | 正 | §3.9：DISCONNECT + 挥手 | 10 |
| 43 | `edp_multi_frame_segment` | 正 | §2/§3.1：多帧粘连（两帧一个 TCP 段） | 10 |
| 44 | `edp_remainlen_multibyte` | 正 | §3.1：2 字节变长编码下界（remainlen 128） | 10 |
| 45 | `edp_remainlen_1byte_max` | 正 | §3.1/§8：1 字节档上界（remainlen 127 → `7f`） | 10 |
| 46 | `edp_remainlen_2byte_max` | 正 | §3.1/§8：2 字节档上界（remainlen 16,383 → `ff7f`） | 21 校准 |
| 47 | `edp_remainlen_3byte_max` | 正 | §3.1/§8：3 字节档上界（remainlen 2,097,151 → `ffff7f`） | 1446 校准 |
| 48 | `edp_remainlen_4byte_band` | 正 | §3.1/§8：4 字节档下界（remainlen 2,097,152 → `80808001`） | 1446 校准 |
| 49 | `edp_datapoint_value_types` | 正 | §3.5：type1 JSON 值类四种（int/float/string/对象） | 10 |
| 50 | `edp_json_u16_max` | 正 | §3.5/§8：json 精确上界 65,535 | 52 校准 |
| 51 | `edp_json_u16_adjacent` | 正 | §3.5/§8：json 邻位 65,534（上界 -1） | 54 校准 |
| 52 | `edp_multi_transaction_keepalive` | 正 | §5/§4⑧：单连接多事务全链 | 16 |
| 53 | `edp_ipv6` | 正 | §2/§8：IPv6 独立 fixture（connect，offset 74） | 9 |
| 54 | `edp_ipv6_savedata` | 正 | §2/§8：IPv6 全事务（connect+savedata） | 10 |
| 55 | `edp_multi_session` | 正 | §5/§8：双设备双四元组多会话展开 | 20 |
| 56 | `edp_concurrent_sessions` | 正 | §5：并发会话交错回放（concurrent:true 翻案） | 22 |
| 57 | `edp_mss_large_bin` | 正 | §8/§3.10：16,350B bin 跨 MSS 重组（3 字节档下界 16,384） | 19 校准 |
| 58 | `edp_keep_time_boundary` | 正 | §3.3/§8：keep_time 0xFFFF 满值 | 9 |
| 59 | `edp_keep_time_min` | 正 | §3.3/§8：keep_time=1 最小非零（0 显式不使用） | 9 |
| 60 | `edp_long_devid` | 正 | §8：64B 长 devid/apikey（2 字节 varint） | 9 |
| 61 | `edp_devid_u16_max` | 正 | §3.3/§8：devid u16 上界 65,535B | 53 校准 |
| 62 | `edp_neg_type_unknown` | 负 | §7：未知消息类型值（不在 §3.2 表内） | — |
| 63 | `edp_neg_type_unimplemented` | 负 | §7：类型在表内但属边界不实现（0xE0/0xF0） | — |
| 64 | `edp_neg_remainlen_mismatch` | 负 | §7：remainlen ≠ 消息体实际字节数 | — |
| 65 | `edp_neg_remainlen_truncated` | 负 | §7：报文截断（体短于 remainlen） | — |
| 66 | `edp_neg_remainlen_5byte` | 负 | §7：变长编码第 5 字节仍置延续位 | — |
| 67 | `edp_neg_conn_protocol_name` | 负 | §7：协议名 ≠ "EDP" | — |
| 68 | `edp_neg_conn_version` | 负 | §7：协议版本 ≠ 1 | — |
| 69 | `edp_neg_conn_flag` | 负 | §7：连接标志非 0x40/0xC0 | — |
| 70 | `edp_neg_savedata_format` | 负 | §7：数据格式标志越域（0x00/0x06/0xFF） | — |
| 71 | `edp_neg_bin_desc_no_dsid` | 负 | §7：type2 desc 无 `ds_id` | — |
| 72 | `edp_neg_bin_desc_invalid` | 负 | §7：type2 desc 非法 JSON | — |
| 73 | `edp_neg_bin_desc_over` | 负 | §7：desc ≥65,536（wire 口径，恰值即拒） | — |
| 74 | `edp_neg_bin_over_3mb` | 负 | §7：bin_len ≥3MB（wire 口径，恰值即拒） | — |
| 75 | `edp_neg_state_no_connect` | 负 | §7：事件序列不以 connect 开头 | — |
| 76 | `edp_neg_state_after_reject` | 负 | §7：CONNRESP rtn≠0 后继续排业务事件 | — |
| 77 | `edp_neg_state_after_disconnect` | 负 | §7：DISCONNECT 后继续排业务事件 | — |
| 78 | `edp_neg_cmdid_correlation` | 负 | §7：CMDRESP cmdid 与 CMDREQ 不匹配 | — |
| 79 | `edp_neg_msgid_correlation` | 负 | §7：SAVEACK msg_id ≠ SAVEDATA 消息编号 | — |
| 80 | `edp_neg_json_invalid` | 负 | §7：JSON 载荷非法（截断/非对象） | — |
| 81 | `edp_neg_json_over_u16` | 负 | §7：json >65,535（u16 溢出） | — |
| 82 | `edp_neg_layer_chain` | 负 | §7：层链缺 tcp（`[edp]` 直连） | — |
| 83 | `edp_neg_carrier_udp` | 负 | §7：UDP 载体 | — |
| 84 | `edp_neg_port_conflict` | 负 | §7：端口/载体声明矛盾 | — |
| 85 | `edp_neg_auth_devid_empty` | 负 | §7：方式 1 devid 空串 | — |
| 86 | `edp_neg_auth_apikey_empty` | 负 | §7：方式 1 apikey 空串 | — |
| 87 | `edp_neg_auth_userid_empty` | 负 | §7：方式 2 userid 空串 | — |
| 88 | `edp_neg_auth_authinfo_empty` | 负 | §7：方式 2 authinfo 空串 | — |
| 89 | `edp_neg_connack_rtn_range` | 负 | §7：CONNRESP rtn 超 0–9 值域 | — |
| — | `edp_neg_unregistered` | 占位 | 当前层注册前置 | — |

## 3. 线上编码和偏移断言

层链 `[tcp, edp]`，无 VLAN/IP options/TCP options 时 **EDP 报文首字节（消息类型）起点为 IPv4 offset 54、IPv6 offset 74**（构造 pcap 实证：`tcp.payload` 即完整 EDP 报文，帧偏移 54 处逐字节吻合）。断言分层：

1. **载体与方向（fields 权威断言）**：设备帧 `tcp.srcport=<会话源端口>`、`tcp.dstport=4472`（端口变体用例 #5 为 12472）；平台帧（CONNRESP/PINGRESP/SAVEACK/CMDREQ/PUSHDATA 下发/SAVEDATA 下行）端口互换。`ip.version=4`（或 IPv6 fixture 断言 `ipv6.nxt=6` 且不得出现 v4 地址）、`tcp.len` = 该段承载的 EDP 报文字节数（单帧不跨段时）。
2. **EDP 报文（tcp.payload + frames 双通道）**：单帧不跨段时 `tcp.payload` 值 = 完整报文 hex（如 CONNRESP 恰为 `20020000`、PINGREQ 恰为 `c000`）；frames 断言在 offset 54/74 处校验关键前缀——消息类型字节（`10`/`20`/`30`/`40`/`80`/`90`/`a0`/`b0`/`c0`/`d0`）、剩余长度变长字节、协议名 `45 44 50`（"EDP"）、cmdid/msg_id 前缀等。变长长度断言例：remainlen 128 → 偏移 55 起两字节 `80 01`（2 字节档下界边界值，用例 44；remainlen 127 仍为 1 字节 `7f`，用例 45）。
3. **跨段重组**：大帧（≥MSS）按 `tcp.stream` 重组后断言完整报文（重组流起点 = 首段 offset 54）；**任何单段不构成完整帧时不得按段断言整帧 hex**。
4. **多帧粘连**：一个 TCP 段可含多个 EDP 帧（`coalesce: true`，设计 §6）——`tcp.payload` 为多帧顺序拼接，按 §3.1 变长长度自然定界逐帧断言（用例 #43）。
5. **多会话/并发包号规则**：`sessions[]` 多会话展开整块回放——先跑完第 1 个会话全流程（握手→事件→挥手）再跑第 2 个，不交错（**第二会话握手包号 = 前一会话总包数 + 1**）；`concurrent: true` 交错回放（#56，包总数不变、仅交错）；跨会话关联断言用 `tcp.stream` 区分，不硬编码全局包号。

**fixture 常量**（帧字节可精确预算；各用例只列差异项）：地址 `192.0.2.72 → 198.51.100.72`（IPv6 `2001:db8::72 → 2001:db8::100:72`）、`src_port=41072`、`dst_port=4472`（非默认变体 `12472`）；devid=`123456789`、apikey=`kJ8mQ2xV`、userid=`284276`、authinfo=`secret-auth-info`、keep_time=128（0x0080；满值 0xFFFF、最小非零 1）、msg_id=0x55AA（21930；满值 0xFFFF）、cmdid=`12345678`（长值 `C`×64）、命令 req=`{"led":"on"}`、resp=`{"status":"ok"}`（二进制变体 `DE AD BE EF`）；type3 JSON=`{"temperature":22}`（值域变体 `{"status":"online"}` / `{"loc":{"lon":117.48,"lat":39.96}}`）、type1 JSON=`{"datastreams":[{"id":"temp","datapoints":[{"at":"2026-08-31 12:00:00","value":22}]}]}`（token 变体加顶层 `{"token":"t-123",...}`）、type4 JSON=`{"temperature":{"2026-08-31 12:00:00":22}}`、bin desc=`{"ds_id":"fw","ver":"1.0"}`、bin=`DE AD BE EF`、透传目标设备=`987654321`、上行透传数据=`GATEWAY:HELLO`（二进制变体 `00 FF 10 A5`）、下行透传数据=`CMD:REBOOT`、SAVEACK JSON=`{"msg_id":21930,"err_code":0}`（非零变体 `err_code=1`）、长标识符 64B fixture（devid/apikey 各 64B）、devid u16 上界 65,535B fixture。

## 4. 正例逐项断言契约

以下 fields/frames 为最低断言集，实现期可增不可减；帧 hex 均按设计 §3 公式对 fixture 常量预算（构造 pcap 已实证同构样本）。每例均含 `has_handshake=true`、`terminates=true`、数据帧 `has_payload=true`。

1. **`edp_connreq_devid_ipv4`**（9）：设备帧（帧 4，offset 54）hex `101e000345445001400080000931323334353637383900086b4a386d51327856`（CONNREQ 方式 1 全 32 字节：`10`=类型、`1e`=remainlen 30、`0003 454450`="EDP"、`01`=版本、`40`=方式 1 标志、`0080`=keep 128、`0009`+devid、`0008`+apikey）；平台帧（帧 5，握手 3 帧后第 2 帧业务）`tcp.payload` 恰为 `20020000`（CONNRESP，rtn=0 在末字节）；`tcp.dstport=4472` 全程、`ip.version=4`；挥手完整。
2. **`edp_connreq_userid`**（9）：设备帧 hex `1025000345445001c000800000000632383432373600107365637265742d617574682d696e666f`（`c0`=方式 2 标志、`0000`=空 devid、`0006`+userid、`0010`+authinfo，remainlen 37=0x25）；CONNRESP `20020000`。
3. **`edp_connack_refused`**（9）：CONNREQ 同用例 1（apikey 可换 fixture 钉死错误值）；CONNRESP `tcp.payload` 恰为 `20020200`（rtn=2 设备 ID 鉴权失败）；**rtn 字节后无任何业务帧**（断言挥手前 `tcp.len>0` 的帧仅 CONNREQ/CONNRESP 两帧）；连接随后关闭。
4. **`edp_connack_rtn1`**（9）：CONNREQ 同用例 1；CONNRESP `tcp.payload` 恰为 `20020001`（rtn=1 验证失败：协议错误，合法错误路径）；rtn 字节后无业务帧、挥手关闭（同用例 3 形状）。rtn=3–9 维持值域声明不逐项设例（设计 §8）。
5. **`edp_port_nondefault`**（9）：`dst_port=12472`（端口由配置覆盖，planner 不得静默改写）；CONNREQ/CONNRESP 字节与用例 1 **完全一致**（同一逻辑报文——EDP 帧自定界，与端口无关）；断言 `tcp.dstport=12472` 全程 + payload hex 同用例 1。
6. **`edp_pingreq_pingresp`**（11）：connect/CONNRESP 同用例 1；心跳请求帧 `tcp.payload` 恰为 `c000`、`tcp.len=2`（协议最小帧）；心跳响应帧 `d000`；方向断言（ping 设备→平台、pong 平台→设备）。
7. **`edp_heartbeat_multi`**（15 = 3+2+6+4）：connect 同用例 1 后 3 轮 ping 事件：单 `tcp.stream` 内 `c000`/`d000` 交替出现 3 对（`tcp.payload` 首字节序列 `c0 d0 c0 d0 c0 d0`）、各 `tcp.len=2`、方向逐帧断言——周期保活的多轮重复事务。
8. **`edp_savedata_type1_fulljson`**（10）：存储帧 offset 54 hex 前缀 `8067c0000931323334353637383955aa010056`（`80`+`67`=remainlen 103+`c0`=devid+msg_id 标志+devid+`55aa`+`01`=type1+`0056`=json 长 86）+ JSON 首部 ASCII `{"datastreams":`（hex `7b226461746173747265616d73223a`）与时间串 `2026-08-31 12:00:00`（hex 前缀 `323032362d30382d3331`）；帧尾 `7d`（JSON 闭合）；`tcp.len=105`。
9. **`edp_savedata_type1_flag00`**（10）：type1 JSON 同用例 8（86B），flag `0x00`：remainlen = `4+86 = 90`（0x5A）；帧 offset 54 前缀 `805a00010056`+JSON 同用例 8；`tcp.len=92`。
10. **`edp_savedata_type1_flag40`**（10）：flag `0x40`（仅 msg_id 0x55AA）：remainlen = `6+86 = 92`（0x5C）；前缀 `805c4055aa010056`+JSON；`tcp.len=94`。
11. **`edp_savedata_type1_flag80`**（10）：flag `0x80`（仅 devid）：remainlen = `6+9+86 = 101`（0x65）；前缀 `8065800009313233343536373839010056`+JSON；`tcp.len=103`。
12. **`edp_savedata_type1_token`**（10）：type1 JSON 含顶层 token：`{"token":"t-123","datastreams":[...]}`（102B，u16 长 `0066`），flag `0xC0`：remainlen = `8+9+102 = 119`（0x77）；前缀 `8077c0000931323334353637383955aa0100667b22746f6b656e223a22742d313233222c226461746173747265616d73223a`（含 token ASCII hex `746f6b656e`）；`tcp.len=121`——token 为 JSON 内容自由度（设计 §3.5），帧结构/长度公式与无 token 全同（正例取代 v2.0.1 范围外声明）。
13. **`edp_savedata_type3_simple`**（10）：存储帧 `tcp.payload` 恰为 `8016000300127b2274656d7065726174757265223a32327d`（`00`=无 devid/msg_id、`03`=type3、`0012`=json 长 18、`{"temperature":22}`）；`tcp.len=24`。
14. **`edp_savedata_type3_flag40`**（10）：flag `0x40`：remainlen = `6+18 = 24`（0x18）；帧 `80184055aa0300127b2274656d7065726174757265223a32327d`（与用例 32 存储帧字节相同——**断言面不同**：本例断言矩阵格 type3×flag40 形状，用例 32 断言 SAVEACK 关联）；`tcp.len=26`。
15. **`edp_savedata_type3_flag80`**（10）：flag `0x80`：remainlen = `6+9+18 = 33`（0x21）；帧 `80218000093132333435363738390300127b2274656d7065726174757265223a32327d`；`tcp.len=35`。
16. **`edp_savedata_type3_flagc0`**（10）：flag `0xC0`：remainlen = `8+9+18 = 35`（0x23）；帧 `8023c0000931323334353637383955aa0300127b2274656d7065726174757265223a32327d`；`tcp.len=37`。
17. **`edp_savedata_type3_value_string`**（10）：type3 值为字符串：json=`{"status":"online"}`（19B，u16 长 `0013`）、flag `0x00`：remainlen = `4+19 = 23`（0x17）；帧 `8017000300137b22737461747573223a226f6e6c696e65227d`；`tcp.len=25`。
18. **`edp_savedata_type3_value_object`**（10）：type3 值为对象（官方 FAQ 位置形态）：json=`{"loc":{"lon":117.48,"lat":39.96}}`（34B，u16 长 `0022`）、flag `0x00`：remainlen = `4+34 = 38`（0x26）；帧 `8026000300227b226c6f63223a7b226c6f6e223a3131372e34382c226c6174223a33392e39367d7d`；`tcp.len=40`。
19. **`edp_savedata_type4_time`**（10）：存储帧 hex `80304055aa04002a7b2274656d7065726174757265223a7b22323032362d30382d33312031323a30303a3030223a32327d7d`（`40`=仅 msg_id、`04`=type4、时间键形态 `{"temperature":{"2026-08-31 12:00:00":22}}`）；`tcp.len=50`。
20. **`edp_savedata_type4_flag00`**（10）：type4 JSON 同用例 19（42B），flag `0x00`：remainlen = `4+42 = 46`（0x2E）；帧 `802e0004002a`+JSON 同用例 19；`tcp.len=48`。
21. **`edp_savedata_type4_flag80`**（10）：flag `0x80`：remainlen = `6+9+42 = 57`（0x39）；帧 `803980000931323334353637383904002a`+JSON；`tcp.len=59`。
22. **`edp_savedata_type4_flagc0`**（10）：flag `0xC0`：remainlen = `8+9+42 = 59`（0x3B）；帧 `803bc0000931323334353637383955aa04002a`+JSON；`tcp.len=61`。
23. **`edp_savedata_type5_string`**（10）：存储帧 hex `801b80000931323334353637383905000c68656c6c6f206f6e656e6574`（`80`=仅 devid、`05`=type5、`000c`+`hello onenet` 非 JSON 裸串）；`tcp.len=29`。
24. **`edp_savedata_type5_flag00`**（10）：type5 串同用例 23（12B），flag `0x00`：remainlen = `4+12 = 16`（0x10）；帧 `80100005000c68656c6c6f206f6e656e6574`；`tcp.len=18`。
25. **`edp_savedata_type5_flag40`**（10）：flag `0x40`：remainlen = `6+12 = 18`（0x12）；帧 `80124055aa05000c68656c6c6f206f6e656e6574`；`tcp.len=20`。
26. **`edp_savedata_type5_flagc0`**（10）：flag `0xC0`：remainlen = `8+9+12 = 29`（0x1D）；帧 `801dc0000931323334353637383955aa05000c68656c6c6f206f6e656e6574`；`tcp.len=31`。
27. **`edp_savedata_type2_bin`**（10）：存储帧 hex `8033c0000931323334353637383955aa02001a7b2264735f6964223a226677222c22766572223a22312e30227d00000004deadbeef`（`02`=type2、desc JSON 含 `"ds_id"`、`00000004`=u32 bin_len 4、`deadbeef`）；`tcp.len=53`。
28. **`edp_savedata_type2_flag40`**（10）：type2 Bin flag `0x40`（desc/bin 同用例 27）：remainlen = `10+26+4 = 40`（0x28）；帧 `80284055aa02001a7b2264735f6964223a226677222c22766572223a22312e30227d00000004deadbeef`；`tcp.len=42`。
29. **`edp_savedata_type2_flag80`**（10）：flag `0x80`：remainlen = `10+9+26+4 = 49`（0x31）；帧 `803180000931323334353637383902001a7b2264735f6964223a226677222c22766572223a22312e30227d00000004deadbeef`；`tcp.len=51`。
30. **`edp_savedata_bin_empty`**（10）：存储帧 hex `80220002001a7b2264735f6964223a226677222c22766572223a22312e30227d00000000`（`00`=无 devid/msg_id 标志、bin_len=0、**desc 后无任何字节**，remainlen 34）；`tcp.len=36`——空二进制为合法边界，不得误报缺载荷。
31. **`edp_savedata_deliver`**（10）：平台→设备 SAVEDATA 同构方向（设计 §3.2/§3.5，SDK `UnpackSavedata` 同构解包证据）。事件 = connect→CONNRESP 后平台下行 SAVEDATA 一帧：下行帧 hex 与用例 13 同构，`tcp.payload` 恰为 `8016000300127b2274656d7065726174757265223a32327d`（type/flag/format/JSON 全同，仅方向不同）；方向断言互换（`tcp.srcport=4472`、`tcp.dstport=41072`）；**下行 SAVEDATA 无应答帧**（SAVEACK 仅平台对上行 SAVEDATA 回带，设计 §3.5/§3.6），下行帧后仅挥手帧。
32. **`edp_saveack_msgid`**（11）：事件 = connect→savedata（flag `0x40`、msg_id 0x55AA、type3）→SAVEACK。存储帧 hex `80184055aa0300127b2274656d7065726174757265223a32327d`；确认帧（平台→设备）`tcp.payload` 恰为 `902000001d7b226d73675f6964223a32313933302c226572725f636f6465223a307d`（SAVEACK：`90`+`20`+`00` 标志+`001d` JSON 长+`{"msg_id":21930,"err_code":0}`）；**应答 JSON 的 msg_id（21930）与 SAVEDATA 的 `55aa` 同值**（fixture 钉死；生成期取值时用 `same_as_packet` 断言）。SAVEACK JSON 内容结构为设计 §3.6 假设形态，实现期实证后如平台形态不同则同步校准断言。
33. **`edp_saveack_err_code`**（11）：事件同用例 32，savedata 的 `ack` 配置 `err_code=1`：确认帧 `tcp.payload` 恰为 `902000001d7b226d73675f6964223a32313933302c226572725f636f6465223a317d`（`{"msg_id":21930,"err_code":1}`，29B 同长——仅结果码数字位不同，帧尾 `3a317d` vs 用例 32 `3a307d`）；msg_id 关联断言同用例 32。
34. **`edp_msgid_max`**（10）：savedata（flag `0x40`、type3、msg_id=0xFFFF）：帧 `801840ffff0300127b2274656d7065726174757265223a32327d`（remainlen 24 同用例 14——仅 msg_id 值不同）；断言 offset 57 起两字节 `ffff`（u16 满值）；`tcp.len=26`；本例不配 ack（msg_id 满值下无 SAVEACK，单一断言面）。
35. **`edp_pushdata_upload`**（10）：透传帧（设备→平台）hex `30180009393837363534333231474154455741593a48454c4c4f`（`30`+remainlen 24+`0009`+dst_devid `987654321`+`GATEWAY:HELLO` 原样字节）；**后续无任何应答帧**（断言挥手前仅 connect/connack/pushdata 三条业务帧）。
36. **`edp_pushdata_deliver`**（10）：下发帧（平台→设备，端口互换）hex `30150009393837363534333231434d443a5245424f4f54`（src_devid `987654321` + `CMD:REBOOT`）；同构断言 + 方向断言。
37. **`edp_pushdata_binary`**（10）：透传帧（设备→平台）hex `300f000939383736353433323100ff10a5`（remainlen = `2+9+4 = 15`（0x0F）+dst_devid+4 字节二进制 `00 ff 10 a5` 原样）；`tcp.len=17`——data 为不透明原始字节（SDK `WriteBytes` 无格式约束），二进制载荷与用例 35 文本载荷同构。
38. **`edp_cmdreq_cmdresp`**（11）：命令帧（平台→设备）hex `a01a000831323334353637380000000c7b226c6564223a226f6e227d`（`a0`+remainlen 26+`0008`+cmdid `12345678`+`0000000c`=u32 req 长 12+req JSON）；应答帧（设备→平台）hex `b01d000831323334353637380000000f7b22737461747573223a226f6b227d`（`b0`+remainlen 29+**cmdid 与命令帧同值**+`0000000f`+resp）；cmdid 前缀 `00083132333435363738` 两帧逐字节相同（`same_as_packet`/fixture 钉死）。
39. **`edp_cmdresp_empty`**（11）：CMDREQ 同用例 38；应答帧 `tcp.payload` 恰为 `b00a00083132333435363738`（remainlen 10 = cmdid_len+2；**cmdid 后无 resp_len/resp 字节**，条件缺省形态）；`tcp.len=12`。
40. **`edp_cmdreq_binary`**（11）：命令帧 hex `a0120008313233343536373800000004deadbeef`（remainlen = `2+8+4+4 = 18`（0x12）、u32 req 长 4、req=`DE AD BE EF` 二进制）；应答帧 hex `b0120008313233343536373800000004deadbeef`（remainlen = `8+4+6 = 18`、resp 同 4B 二进制、**cmdid 关联同值**）；req/resp 为不透明命令字节（官方 FAQ：命令内容对平台不透明）。
41. **`edp_cmdid_long`**（11）：cmdid = `C`×64（u16 长 `0040`）：命令帧 remainlen = `2+64+4+12 = 82`（0x52），帧 `a0520040`+`43`×64+`0000000c7b226c6564223a226f6e227d`、`tcp.len=84`；应答帧 remainlen = `64+12+6 = 82`（0x52），帧 `b0520040`+`43`×64+`0000000f7b22737461747573223a226f6b227d`；**64B cmdid 两帧逐字节相同**（`same_as_packet`）。
42. **`edp_disconnect`**（10）：事件 = connect→DISCONNECT。断开帧（设备→平台）`tcp.payload` 恰为 `4000`（2 字节，设计 §3.9 假设形态——实现期实证平台行为，若平台实际形态不同则按实证校准并同步设计）；断开后仅挥手帧、无业务帧。
43. **`edp_multi_frame_segment`**（10 = 3+2+1+4）：事件 = connect→savedata（type3 flag `0x00`）×2，`coalesce: true`（设计 §6）：**一个 TCP 段承载两帧**——`tcp.payload` 恰为 `8016000300127b2274656d7065726174757265223a32327d8016000300127b2274656d7065726174757265223a32327d`（用例 13 帧字节 ×2 顺序拼接）、`tcp.len=48`；按 §3.1 变长长度自然定界逐帧断言（第一帧 remainlen 22 定界后第二帧起点即帧内 offset 24）——多帧粘连为流式协议合法形态（设计 §2）。
44. **`edp_remainlen_multibyte`**（10）：事件 = connect→savedata（flag `0x00`、type3、json 为 124 字节 fixture 钉死合法 JSON 填充 `{"k":"<A×116>"}`）。存储帧 offset 55 起两字节 `8001`（**remainlen 恰 128 = 2 字节编码下界，127↔128 档边界值**：remainlen = 4+124 = 128）+ `0003007c`（标志/格式/json 长 124）；`tcp.len=131`（总长 = 1+2+128）。
45. **`edp_remainlen_1byte_max`**（10）：json 为 123 字节填充 `{"k":"<A×115>"}`，flag `0x00`：remainlen = `4+123 = 127` → offset 55 单字节 `7f`（**1 字节档上界**，127↔128 边界另一侧）+ `0003007b`（json 长 123=0x7B）；`tcp.len=129`（总长 = 1+1+127）。
46. **`edp_remainlen_2byte_max`**（21 校准 = 3+2+12+4）：json 为 16,379 字节填充，flag `0x00`：remainlen = `4+16379 = 16,383` → offset 55 起两字节 `ff7f`（**2 字节档上界**，16,383↔16,384 边界另一侧）；帧总长 16,386 = 1460×11+326 → 12 段；`tcp.len` 各段和 = 16,386；按 `tcp.stream` 重组后 json 恰 16,379B。
47. **`edp_remainlen_3byte_max`**（1446 校准 = 3+2+1437+4）：type2 大载荷，bin = 2,097,117B（desc 同用例 27，26B）：remainlen = `8+26+2097117 = 2,097,151` → **3 字节变长编码 `ff ff 7f`**（3 字节档上界，2,097,151↔2,097,152 边界另一侧）；bin_len u32 = `001fffdd`；帧总长 2,097,155 = 1460×1436+595 → 1,437 段；断言同用例 48 形状（重组流 + bin_len 域不切坏 + 各段和）。
48. **`edp_remainlen_4byte_band`**（1446 校准 = 3+2+1437+4）：事件 = connect→savedata type2 大载荷。bin 为 2,097,118 字节 fixture 填充（desc 同用例 27，26 字节）：remainlen = **恰 2,097,152**（2,097,151↔2,097,152 档边界值）→ **4 字节变长编码 `80 80 80 01`**（设计 §3.1 表第 4 档示例同值）；bin_len = 2,097,118 < 3MB SDK 上界（设计 §3.5）。首段（MSS 1460）offset 54 起前缀 `80 80808001 00 02 001a`+desc hex+`001fffde`（u32 bin_len）+bin 填充起始；按 `tcp.stream` 重组后断言完整帧总长 2,097,157（=1+4+2,097,152）、**分段边界不切坏 u32 bin_len 字段**、`tcp.len` 各段和 = 帧总长；帧跨 1,437 个 TCP 段（2,097,157 = 1460×1436+597，末段 597B）。
49. **`edp_datapoint_value_types`**（10）：type1 FullJson 含四类值——int 22、float 45.5、string `device-A`、对象 `{"lon":117.48,"lat":39.96}`（官方 FAQ 位置上报形态）；帧 offset 54 前缀 `80d602c0000931323334353637383955aa0101...`（remainlen 342 → 2 字节变长 `d602`）+ JSON 内 `22`、`45.5`、`device-A`、`"lon"`/`"lat"` 的 ASCII hex 子串断言；`tcp.len=345`（总长 = 1+2+342）。
50. **`edp_json_u16_max`**（52 校准 = 3+2+45+4）：事件 = connect→savedata（flag `0x00`、type3、json 为**恰 65,535 字节** fixture 钉死合法 JSON 填充 `{"k":"<A×65,527>"}`）。存储帧 offset 55 起 3 字节 `838004`（remainlen = 4+65,535 = 65,539）+ offset 60 起 json 长度域 **`ffff`（65,535 = u16 满值，精确上界）** + json 填充起始；按 `tcp.stream` 重组后断言 JSON 字节数恰 65,535、帧总长 65,543（=1+3+65,539）；帧跨 45 个 TCP 段（65,543 = 1460×44+1303）。**>65,535 由负例 `edp_neg_json_over_u16` 拒绝，精确上界正例 + 超界负例成对闭合**。
51. **`edp_json_u16_adjacent`**（54 校准 = 3+2+45+4）：json 为**恰 65,534 字节**填充 `{"k":"<A×65,526>"}`（上界 -1 邻位，仍合法）：remainlen = 4+65,534 = 65,538 → 3 字节 `828004`；json 长度域 `fffe`；帧总长 65,542 = 1460×44+1302 → 45 段；重组后 json 恰 65,534B——与用例 50 构成 65,534/65,535 相邻值对。
52. **`edp_multi_transaction_keepalive`**（16）：单 `tcp.stream` 九帧业务序列：CONNREQ(`10`)→CONNRESP(`20`)→SAVEDATA(`80`)→SAVEACK(`90`)→PINGREQ(`c0`)→PINGRESP(`d0`)→CMDREQ(`a0`)→CMDRESP(`b0`)→DISCONNECT(`40`)；断言各帧类型字节按此顺序出现（`tcp.payload` 首字节序列恰为 `10 20 80 90 c0 d0 a0 b0 40`）、cmdid/msg_id 关联同用例 32/38、无乱序（设计 §1：本版按序回放）。
53. **`edp_ipv6`**（9）：IPv6 独立 fixture（`2001:db8::72 → 2001:db8::100:72`，显式给出）；断言 `ipv6.nxt=6`、EDP 首字节 offset **74**、CONNREQ/CONNRESP 字节与用例 1 完全一致（同一逻辑报文，仅外层 IP 头不同）；不得出现 `ip.version=4`。
54. **`edp_ipv6_savedata`**（10）：IPv6 fixture + connect→savedata（type3 flag `0x00`）：存储帧字节与用例 13 **完全一致**（EDP 报文与 IP 版本无关）；断言 offset 74 处 `80160003...` 同构、`ipv6.nxt=6`——v6 全事务（不只 connect）。
55. **`edp_multi_session`**（20 = 10+10）：会话 1（`src_port=41072`，devid `123456789`）与会话 2（`src_port=41073`，devid `223456780`）各含 connect+connack+savedata；断言 `tcp.stream` 两值 distinct、**第二会话握手包号 = 11**（= 前会话 10 包 + 1，多会话展开）、两会话 devid 字节串 distinct、各自 CONNRESP rtn=0、会话间状态不串用。
56. **`edp_concurrent_sessions`**（22 = 11+11）：`concurrent: true` 双会话**交错回放**（src_port 41072/41073，devid `123456789`/`223456780`，各含 connect+connack+savedata+saveack）：断言两 `tcp.stream` 值 distinct、**各会话事务配对完整**（每 stream 内 `10 20 80 90` 齐全、CONNRESP rtn=0、SAVEACK 归属本 stream）、**devid/msg_id 上下文跨流互不串用**（会话 1 的 SAVEACK msg_id 只回带本会话 SAVEDATA 的 0x55AA，会话 2 用 msg_id 0x55AB 区分）、包总数不变（仅交错）——生成器级多设备并发不违反单会话串行（设计 §5 翻案，判例 cwmp⑦/doh#24/onvif#56 同口径）。
57. **`edp_mss_large_bin`**（19 校准 = 3+2+12+4）：savedata type2、bin 为 16,350 字节 fixture 填充（desc 同用例 27，26 字节）：remainlen = **恰 16,384**（16,383↔16,384 档边界值）→ **3 字节变长编码 `80 80 01`**（3 字节档下界）；首段 offset 54 起前缀 `80 808001 00 02 001a`+desc hex+`00003fde`（u32 bin_len = 16,350）+bin 填充起始；按 `tcp.stream` 重组后完整帧（帧跨 12 段，16,388 = 1460×11+328，末段 328B）、`tcp.len` 各段和 = 帧总长 16,388、**分段边界不切坏 u32 bin_len 字段**。
58. **`edp_keep_time_boundary`**（9）：**仅满值边界**：CONNREQ offset 63 起两字节 `ffff`（keep_time=0xFFFF，remainlen 不变 0x1e = 13+9+8），得 CONNRESP `20020000`；keep_time 默认值 0x0080 断言由用例 1 的 CONNREQ hex 承载（单会话 9 包仅容纳一次 CONNREQ，不另设默认值变体会话）。
59. **`edp_keep_time_min`**（9）：keep_time=1（**最小非零**；0 显式不使用，设计 §8）：CONNREQ offset 63 起两字节 `0001`，remainlen 不变 0x1e；CONNRESP `20020000`。
60. **`edp_long_devid`**（9）：devid/apikey 各 64 字节 fixture 钉死字符串；CONNREQ remainlen = `13+64+64 = 141`（>127 → **2 字节变长编码 `8d 01`**）；断言 offset 55 起两字节 `8d01`、offset 57 起 `0003 454450`（协议名）、offset 66 起 devid 长度域 `0040`（64）、`tcp.len=144`（总长 = 1+2+141）。
61. **`edp_devid_u16_max`**（53 校准 = 3+45+1+4）：devid = 65,535 字节 fixture 钉死（u16 前缀上界；apikey 仍 8B）：remainlen = `13+65535+8 = 65,556` → 3 字节 `948004`；断言 offset 55 起 `948004`、offset 67 起 devid 长度域 **`ffff`**（65,535 = u16 满值）、CONNRESP 帧（帧 3+45+1 后）`20020000`；CONNREQ 帧总长 65,560 = 1460×44+1320 → 45 段（`tcp.len` 各段和断言）——标识符 u16 上界与 64B 长值（用例 60）构成上界族。

**正例总则**：每条实现后至少含 `packet_count`（或 `min_packets`）+ 载体与方向断言 + `has_payload`（数据帧 `tcp.payload` nonzero）+ 类型字节 frames 断言；帧 hex 均可由设计 §3 公式 + fixture 常量精确预算（本文已给出全部锚定样本）；动态值只用存在与关联断言。合法协议事件（CONNRESP rtn 1–9、空 resp、空 bin、PUSHDATA 无应答、非默认端口、token 顶层字段）均为正例形态，只有配置、线格式、状态、关联、长度错误进入负例（设计 §7）。

## 5. 负例契约（一行一注入）

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；执行期 `expect` 键集合**严格为** `{expect_error, error_contains}`。**锚词为主锚词单一钉死**（注册 `edp` 层时每行 `error_contains` 恰取主锚词；备选词仅作实现自由度备注，不入断言）；`wire_fault` 枚举 28 值与下表 28 行 **1:1 同序**（设计 §6/§7 同步）：

| # | ID | `wire_fault` 注入口 | 故障输入 | 主锚词（备选） |
|---:|---|---|---|---|
| 62 | `edp_neg_type_unknown` | `type_unknown` | 消息类型值不在设计 §3.2 表（如 `0x00`/`0x50`/`0xFF`） | `type`（备选 message/unknown） |
| 63 | `edp_neg_type_unimplemented` | `type_unimplemented` | 类型在 §3.2 表内但属 §1 边界不实现（`0xE0`/`0xF0`，ENCRYPT） | `type`（备选 unimplemented/encrypt） |
| 64 | `edp_neg_remainlen_mismatch` | `remainlen_mismatch` | 剩余长度 ≠ 消息体实际字节数 | `remainlen`（备选 length/mismatch） |
| 65 | `edp_neg_remainlen_truncated` | `remainlen_truncated` | 报文截断（体短于 remainlen 声明） | `truncat`（备选 remainlen/length） |
| 66 | `edp_neg_remainlen_5byte` | `remainlen_5byte` | 变长编码第 5 字节仍置延续位（`ReadRemainlen` len_len>4） | `remainlen`（备选 varint/byte） |
| 67 | `edp_neg_conn_protocol_name` | `protocol_name` | 协议名 ≠ "EDP"（如 "EDQ"） | `protocol`（备选 name） |
| 68 | `edp_neg_conn_version` | `version` | 协议版本 ≠ 1（如 0/2） | `version`（备选 protocol） |
| 69 | `edp_neg_conn_flag` | `conn_flag` | 连接标志非 0x40/0xC0（如 0x00/0x80/0xFF） | `flag`（备选 connect） |
| 70 | `edp_neg_savedata_format` | `format_flag` | 数据格式标志取 0x00/0x06/0xFF 等值域外值 | `format`（备选 type） |
| 71 | `edp_neg_bin_desc_no_dsid` | `bin_desc_no_dsid` | type2 desc 无 `ds_id` 字段 | `ds_id`（备选 desc） |
| 72 | `edp_neg_bin_desc_invalid` | `bin_desc_invalid` | type2 desc 非法 JSON（截断/非对象） | `desc`（备选 json/invalid） |
| 73 | `edp_neg_bin_desc_over` | `bin_desc_over` | desc ≥65,536B（wire 口径恰值即拒，SDK 严格 > 差异见设计 §3.5） | `desc`（备选 length/over） |
| 74 | `edp_neg_bin_over_3mb` | `bin_over_3mb` | bin_len ≥3MB（wire 口径恰值即拒） | `length`（备选 bin/size） |
| 75 | `edp_neg_state_no_connect` | `state_no_connect` | 事件序列不以 connect 开头（首事件 savedata/ping/pushdata/cmdresp） | `connect`（备选 state/sequence） |
| 76 | `edp_neg_state_after_reject` | `state_after_reject` | CONNRESP rtn≠0 后继续排业务事件 | `state`（备选 connect/sequence） |
| 77 | `edp_neg_state_after_disconnect` | `state_after_disconnect` | DISCONNECT 后继续排业务事件（设计 §5 Disconnecting 约束） | `state`（备选 connect/sequence） |
| 78 | `edp_neg_cmdid_correlation` | `cmdid` | cmdreq 配置的应答 cmdid 与请求 cmdid 不同值 | `cmdid`（备选 correlation/cmd） |
| 79 | `edp_neg_msgid_correlation` | `msg_id` | saveack 配置的回带 msg_id ≠ 触发 savedata 的消息编号 | `msg_id`（备选 correlation） |
| 80 | `edp_neg_json_invalid` | `json_invalid` | format 0x01/0x03/0x04 的内容非法 JSON（截断/非对象） | `json`（备选 invalid/parse） |
| 81 | `edp_neg_json_over_u16` | `json_over_u16` | json >65,535 字节（u16 溢出；65,534/65,535 邻位对见正例 50/51） | `json`（备选 length/u16） |
| 82 | `edp_neg_layer_chain` | `layer_chain` | 层链缺 tcp（`[{"edp":{}}]` 直连） | `layer`（备选 carrier/tcp） |
| 83 | `edp_neg_carrier_udp` | `carrier_udp` | UDP 载体（`[{"udp":{}},{"edp":{}}]`） | `carrier`（备选 udp/layer） |
| 84 | `edp_neg_port_conflict` | `port_conflict` | 端口/载体声明矛盾（如 dst_port 与载体约束冲突、同 fixture 内端口不一致） | `port`（备选 conflict/carrier） |
| 85 | `edp_neg_auth_devid_empty` | `auth_devid_empty` | 方式 1 devid 空串 | `devid`（备选 auth/config） |
| 86 | `edp_neg_auth_apikey_empty` | `auth_apikey_empty` | 方式 1 apikey 空串 | `apikey`（备选 auth/config） |
| 87 | `edp_neg_auth_userid_empty` | `auth_userid_empty` | 方式 2 userid 空串 | `userid`（备选 auth/config） |
| 88 | `edp_neg_auth_authinfo_empty` | `auth_authinfo_empty` | 方式 2 authinfo 空串 | `authinfo`（备选 auth/config） |
| 89 | `edp_neg_connack_rtn_range` | `connack_rtn` | `connack_rtn` 取 0–9 值域外值（如 10/0xFF） | `rtn`（备选 value/range） |

合法协议事件不进负例（防误报）：CONNRESP rtn=1–9、CMDRESP 空 resp、bin_len=0、PUSHDATA 无应答、keep_time 满值/最小非零、空 json 数值字段、非默认端口、顶层 token、type5 非 JSON 裸串、下行 SAVEDATA 无应答。

## 6. 五层覆盖映射

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 1–7、31–43、52（正）；62–89（负） | 10 类实现范围消息每类正例（connect 两方式/connack rtn 0/1/2/端口/心跳单轮多轮/savedata 五格式+下行同构方向/saveack 关联与 err_code/msg_id 满值/pushdata 双向+二进制/cmd 四形态+长 cmdid/disconnect/多帧粘连/多事务全链）；负例 28 行一行一注入逐行与设计 §7 对应；ENCRYPT×2 为设计 §1 边界（负例 63 承载"类型在表但不实现"拒绝分支） |
| 性能 | 44–48、50–51、57 | remainlen 四档**双侧边界**（127/128、16,383/16,384、2,097,151/2,097,152 各有正例对）、json 65,535/65,534 上界对（超界负例 81）、16K/2M 级 bin 跨 MSS 分段重组（12/1,437 段）、多帧粘连（43）；发包速率由框架既有配置承载（v1.3 口径） |
| 数据场景 | 8–30、34、45–51、58–61；负 70–74、80、81 | 标志×格式 4×5 **全 20 格**（两维独立声明，设计 §3.5）、五格式值域（int/string/对象）、时间格式、json 值类与上界邻位对、bin_len=0、msg_id/keep_time/devid/cmdid 满值与长度族；非法值拒绝 |
| 地址与流 | 1（v4 单流基线）、5（端口变体）、53/54（v6）、55（多会话双四元组）、56（并发会话） | v4+v6 必覆盖（connect 与全事务）、非默认端口、多会话展开、**并发会话翻案纳入**；流关联与多流显式不适用（设计 §4 声明） |
| 业务 | 1–7（接入/心跳）、8–34（周期上报簇）、35–37（透传）、38–41（命令下发）、42/52（断开/完整生命周期） | OneNET EDP 现网日常场景优先（接入-心跳-上报-命令链） |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/edp.json` 通过；当前数组恰含 1 条 `edp_neg_unregistered`：`proto=edp`、层链 `[{"tcp":{}},{"edp":{}}]`、`src_port=41072`、`dst_port=4472`（v2.1 已对齐 fixture）、`expect_error=true`、`error_contains` 精确为 `unknown layer`、notes 计数 89（61 正 + 28 负）。
2. 实现注册 `edp` 层后：移除占位，按 §2 顺序补入 89 个语义用例（61 正 + 28 负）；ID 唯一、顺序即权威（设计 §9 簇级引用本文 §2；脚本核验 §2 = §8 = `edp.json`）。
3. 正例每条含 `packet_count`（或 `min_packets`）+ `fields` + `frames`；`fields` 只用 §1 实测存在的 tshark 字段（`tcp.*`/`ip.version`/`ipv6.nxt`/`frame.*`），**不使用任何 `edp.*` 字段**（本机 EDP dissector 属 Extreme Discovery Protocol，`edp.*` 字段全部属 Extreme，禁用）。
4. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields；`error_contains` 恰取 §5 表主锚词（备选词不入断言）。
5. 负例 `wire_fault` 28 值与 §5 表行 1:1 同序（设计 §6 枚举 = 设计 §7 表 = 本文 §5，三方同序）。
6. 跨会话/跨段断言用 `tcp.stream` + 多会话展开起点规则（§3.5）；动态值用 `same_as_packet`/`distinct_values`/`nonzero`；不硬编码全局包号（并发会话只断言 stream 归属，不断言全局交错序）。
7. 若实现期实证 SAVEACK JSON 实际形态 / DISCONNECT 报文体 / CONNRESP 标志字节与本版假设（设计 §3.6/§3.9/§3.3）不符，设计 §3 与本文 §4 对应断言同步校准，并在两文档修订记录登记。

## 8. 三方一致性表

本文 §2（ID 唯一权威）、本文 §8、实现后 `edp.json` 保持同一 89 个语义 ID、同一顺序（设计 §9 为簇级引用；当前 JSON 另有占位，不计入）：

```text
edp_connreq_devid_ipv4
edp_connreq_userid
edp_connack_refused
edp_connack_rtn1
edp_port_nondefault
edp_pingreq_pingresp
edp_heartbeat_multi
edp_savedata_type1_fulljson
edp_savedata_type1_flag00
edp_savedata_type1_flag40
edp_savedata_type1_flag80
edp_savedata_type1_token
edp_savedata_type3_simple
edp_savedata_type3_flag40
edp_savedata_type3_flag80
edp_savedata_type3_flagc0
edp_savedata_type3_value_string
edp_savedata_type3_value_object
edp_savedata_type4_time
edp_savedata_type4_flag00
edp_savedata_type4_flag80
edp_savedata_type4_flagc0
edp_savedata_type5_string
edp_savedata_type5_flag00
edp_savedata_type5_flag40
edp_savedata_type5_flagc0
edp_savedata_type2_bin
edp_savedata_type2_flag40
edp_savedata_type2_flag80
edp_savedata_bin_empty
edp_savedata_deliver
edp_saveack_msgid
edp_saveack_err_code
edp_msgid_max
edp_pushdata_upload
edp_pushdata_deliver
edp_pushdata_binary
edp_cmdreq_cmdresp
edp_cmdresp_empty
edp_cmdreq_binary
edp_cmdid_long
edp_disconnect
edp_multi_frame_segment
edp_remainlen_multibyte
edp_remainlen_1byte_max
edp_remainlen_2byte_max
edp_remainlen_3byte_max
edp_remainlen_4byte_band
edp_datapoint_value_types
edp_json_u16_max
edp_json_u16_adjacent
edp_multi_transaction_keepalive
edp_ipv6
edp_ipv6_savedata
edp_multi_session
edp_concurrent_sessions
edp_mss_large_bin
edp_keep_time_boundary
edp_keep_time_min
edp_long_devid
edp_devid_u16_max
edp_neg_type_unknown
edp_neg_type_unimplemented
edp_neg_remainlen_mismatch
edp_neg_remainlen_truncated
edp_neg_remainlen_5byte
edp_neg_conn_protocol_name
edp_neg_conn_version
edp_neg_conn_flag
edp_neg_savedata_format
edp_neg_bin_desc_no_dsid
edp_neg_bin_desc_invalid
edp_neg_bin_desc_over
edp_neg_bin_over_3mb
edp_neg_state_no_connect
edp_neg_state_after_reject
edp_neg_state_after_disconnect
edp_neg_cmdid_correlation
edp_neg_msgid_correlation
edp_neg_json_invalid
edp_neg_json_over_u16
edp_neg_layer_chain
edp_neg_carrier_udp
edp_neg_port_conflict
edp_neg_auth_devid_empty
edp_neg_auth_apikey_empty
edp_neg_auth_userid_empty
edp_neg_auth_authinfo_empty
edp_neg_connack_rtn_range
```

## 9. 修订记录

- v2.1.0（2026-09-02）：按《需求文档 v1.3》rr-edp 重审（8C+5N，报告 /tmp/edp_v13/report.md）全量落地，用例 39 → 89（61 正 + 28 负）：C-1 双输出契约、C-2 并发翻案 + `edp_concurrent_sessions`、C-4 +`edp_port_nondefault`、C-5 负例原子拆分 12→28 行 + wire_fault 28 值 1:1 + 主锚词钉死、C-6 相邻值族（127/16,383/2,097,151/65,534/devid u16 上界）、C-7 占位对齐、C-8 edp.* 表述更正、N4 矩阵 4×5 全 20 格（+13 例）、N5 +rtn=1；另补行为面扩量例 8 条（多帧粘连/二进制透传/二进制命令/SAVEACK err_code/msg_id 满值/keep_time 最小/64B cmdid/心跳 3 轮/IPv6 全事务/type3 值域×2/type1 token）；ID 权威改本文 §2（设计 §9 簇级）。状态：已按清单修复，待审查方复验关闭。
- v2.0.1（2026-09-01）：按独立隔离审查 9 项问题清单（4 MAJOR + 5 MINOR）修复（详见文档头修订记录）。
- v2.0.0（2026-09-01）：按需求文档 v1.1 独立隔离审查流程重写，取代 2026-08-21 旧稿。
- v1.0.0（2026-08-21）：旧稿首版（14 正 + 6 负，基于已废弃的臆造线格式）。

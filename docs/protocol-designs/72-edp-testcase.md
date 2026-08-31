# EDP（增强设备协议，Enhanced Device Protocol / 中国移动 OneNET 设备接入协议）测试用例契约

> 版本：v2.0.1（测试用例）
> 日期：2026-09-01
> 配套设计：`docs/protocol-designs/72-edp-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/edp.json`（proto key：`edp`；本版不写文件，当前 JSON 仅含注册前置占位）
> 状态：**独立隔离对抗审查已完成**（v2.0.1 定稿：独立审查 agent 三向审计 10 项清单（4M/6N，含复验新发现 E10）→ 修复 → 复验 clean；审查/修复记录见 §9 修订记录 v2.0.0/v2.0.1）。
> 修订记录：v2.0.1（2026-09-01）：按独立隔离审查 9 项问题清单（4 MAJOR + 5 MINOR）修复——E01 用例 20 `tcp.len` 344→345（1+2+342）；E02 新增 4 字节变长档正例 `edp_remainlen_4byte_band`（remainlen 恰 2,097,152 → `80 80 80 01`），`edp_remainlen_multibyte` 改 2 字节档下界 128（`80 01`）、`edp_mss_large_bin` 改 remainlen 恰 16,384 档下界（`80 80 01`），§4.19/§4.25 分段数与 packet_count 按公式重算；E04 用例 1 CONNRESP 帧号 6→5（与 §1 包数约定一致）；E05 负例 33 故障输入补"DISCONNECT 后继续排业务事件"；E06 用例 26 写明默认值断言由用例 1 承载、本例仅 0xFFFF（保 9 包）；E07 新增 json 精确上界正例 `edp_json_u16_max`（65,535，u16 满值 `ffff`）；E08 type1 顶层 token 声明为 JSON 内容自由度、用例范围外（§4.20 声明）；E09 新增平台→设备 SAVEDATA 同构方向正例 `edp_savedata_deliver`。自查另修 1 处清单外算术错：用例 27 `edp_long_devid` remainlen 141 为 2 字节 varint（`8d 01`），总长 143→144、字段偏移顺延。ID 总数 36→39（27 正 + 12 负），§2/§8 三方表同步。
> 修订记录：v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-21 旧稿（旧稿见 git 历史；旧稿 14+6 用例基于已废弃的臆造线格式，全部重排）。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 **39 个唯一语义 ID：27 个正例 + 12 个负例**。派生规则：设计 §3 每个编码条款（每消息类型、每数据格式、每标志组合、每变长长度档）、§5 每个状态/事务/关联行为、§7 每行错误处理在本文有对应断言；断言不得超出设计（并追溯到 OneNET 官方 EdpKit SDK / 官方文档站）声明范围。**一个用例只验证一个协议行为**（v1.1 §7 原子原则）。

当前 JSON 只保留一个 `edp_neg_unregistered` 注册前置占位：`proto=edp`、`expect_error=true`、`error_contains` 精确为 `unknown layer`；该占位不计入 39 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 EDP 行为通过。注册后移除占位，再按本文 §2 顺序补入 27 个正例与 12 个负例；**占位现端口 9847 一并改为 4472**（旧稿遗留，见设计 §1）。

**TSHARK 实测基线（本机 3.6.14，`-G fields`/`-G protocols` 核验 + 构造 pcap 实证，非臆造）**：本机**没有 OneNET EDP 的 dissector（解析器）**——`tshark -G protocols` 里的 "EDP" 是 **Extreme Discovery Protocol**（Extreme 网络设备邻居发现协议），与本协议无关，**不得使用任何 `edp.*` 字段**（实测输出为空）。可用字段（`-G fields` 实测存在）：`tcp.payload`（FT_BYTES，TCP 载荷原始字节——**即完整 EDP 报文**，构造 pcap 实证精确提取）、`tcp.len`、`tcp.srcport`、`tcp.dstport`、`tcp.stream`、`tcp.flags.syn/ack/fin/push`、`ip.version`、`ipv6.nxt`、`frame.number`、`frame.len`。EDP 内容断言双通道：① `tcp.payload` 全帧 hex 值断言（fields）；② raw frame（原始帧）EDP 首字节起点（IPv4 offset 54 / IPv6 offset 74）的 `frames` `offset/hex` 断言。**TCP 分段边界不是 EDP 帧边界**：跨段报文按 `tcp.stream` 重组后再断言完整帧。

**动态字段禁止硬编码**：SAVEACK 应答 JSON 的 msg_id/err_code、CMDREQ 的 cmdid 为生成期值时用 `same_as_packet`/`distinct_values`/`nonzero` 或 fixture 钉死值断言；本版 fixture 把 devid/apikey/msg_id/cmdid/JSON 内容全部钉死为常量（见 §3 fixture 常量），帧字节断言按设计 §3 公式可精确预算（构造 pcap 已实证）。

**包数约定**（设计 §9 完成定义；单帧不跨段时）：会话 = 3（TCP 握手）+ N（承载 EDP 报文的 TCP 段数，通常每报文 1 段）+ 4（双向 FIN 挥手）。connect 事件含 CONNREQ+CONNRESP 两帧；实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖（设计 §） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `edp_connreq_devid_ipv4` | 正 | §3.3/§4①：方式 1 连接 + CONNRESP rtn=0，IPv4 单流基线 | 9 |
| 2 | `edp_connreq_userid` | 正 | §3.3：方式 2 连接（0xC0、空 devid、userid+authinfo） | 9 |
| 3 | `edp_connack_refused` | 正 | §3.3：CONNRESP rtn=2 拒绝路径 + 连接关闭 | 9 |
| 4 | `edp_pingreq_pingresp` | 正 | §3.4：心跳（2 字节最小帧） | 11 |
| 5 | `edp_savedata_type1_fulljson` | 正 | §3.5：flag 0xC0 + type1 FullJson | 10 |
| 6 | `edp_savedata_type3_simple` | 正 | §3.5：flag 0x00 + type3 简单 JSON | 10 |
| 7 | `edp_savedata_type4_time` | 正 | §3.5：flag 0x40 + type4 时间键 | 10 |
| 8 | `edp_savedata_type5_string` | 正 | §3.5：flag 0x80 + type5 裸字符串 | 10 |
| 9 | `edp_savedata_type2_bin` | 正 | §3.5：type2 二进制 | 10 |
| 10 | `edp_savedata_bin_empty` | 正 | §3.5/§8：bin_len=0 边界 | 10 |
| 11 | `edp_savedata_deliver` | 正 | §3.2/§3.5：平台→设备 SAVEDATA 同构方向 | 10 |
| 12 | `edp_saveack_msgid` | 正 | §3.6：msg_id 关联回带 | 11 |
| 13 | `edp_pushdata_upload` | 正 | §3.7：设备→平台透传 | 10 |
| 14 | `edp_pushdata_deliver` | 正 | §3.7：平台→设备下发 | 10 |
| 15 | `edp_cmdreq_cmdresp` | 正 | §3.8：命令事务（resp 非空） | 11 |
| 16 | `edp_cmdresp_empty` | 正 | §3.8：resp_len=0 条件缺省 | 11 |
| 17 | `edp_disconnect` | 正 | §3.9：DISCONNECT + 挥手 | 10 |
| 18 | `edp_remainlen_multibyte` | 正 | §3.1：2 字节变长编码下界（remainlen 128） | 10 |
| 19 | `edp_remainlen_4byte_band` | 正 | §3.1/§8：4 字节变长编码（remainlen 恰 2,097,152） | 1444 校准 |
| 20 | `edp_datapoint_value_types` | 正 | §3.5：JSON 值域变体 | 10 |
| 21 | `edp_json_u16_max` | 正 | §3.5/§8：json 精确上界 65,535 | 52 校准 |
| 22 | `edp_multi_transaction_keepalive` | 正 | §5/§4⑧：单连接多事务全链 | 16 |
| 23 | `edp_ipv6` | 正 | §2/§8：IPv6 独立 fixture | 9 |
| 24 | `edp_multi_session` | 正 | §5/§8：双设备双四元组 | 20 |
| 25 | `edp_mss_large_bin` | 正 | §8/§3.10：16,350B bin 跨 MSS 重组（3 字节档下界 16,384） | 19 校准 |
| 26 | `edp_keep_time_boundary` | 正 | §3.3/§8：keep_time 0xFFFF 满值（默认 0x0080 由用例 1 承载） | 9 |
| 27 | `edp_long_devid` | 正 | §8：64B 长标识符（2 字节 varint） | 9 |
| 28 | `edp_neg_unknown_type` | 负 | §7：未知消息类型 | — |
| 29 | `edp_neg_remainlen` | 负 | §7：剩余长度错/截断/超 4 字节 | — |
| 30 | `edp_neg_connect_protocol` | 负 | §7：协议名/版本/连接标志错 | — |
| 31 | `edp_neg_savedata_format` | 负 | §7：数据格式标志越域 | — |
| 32 | `edp_neg_bin_desc` | 负 | §7：desc 无 ds_id/非法/超界、bin 超 3MB | — |
| 33 | `edp_neg_state` | 负 | §7：状态机错 | — |
| 34 | `edp_neg_cmdid_correlation` | 负 | §7：cmdid 关联错 | — |
| 35 | `edp_neg_msgid_correlation` | 负 | §7：msg_id 关联错 | — |
| 36 | `edp_neg_json_payload` | 负 | §7：非法 JSON/json 超 u16 | — |
| 37 | `edp_neg_carrier_port` | 负 | §7：载体/端口/层链错 | — |
| 38 | `edp_neg_connect_auth` | 负 | §7：鉴权字段为空 | — |
| 39 | `edp_neg_connack_rtn` | 负 | §7：CONNRESP rtn 超值域 | — |
| — | `edp_neg_unregistered` | 占位 | 当前层注册前置 | — |

## 3. 线上编码和偏移断言

层链 `[tcp, edp]`，无 VLAN/IP options/TCP options 时 **EDP 报文首字节（消息类型）起点为 IPv4 offset 54、IPv6 offset 74**（构造 pcap 实证：`tcp.payload` 即完整 EDP 报文，帧偏移 54 处逐字节吻合）。断言分层：

1. **载体与方向（fields 权威断言）**：设备帧 `tcp.srcport=<会话源端口>`、`tcp.dstport=4472`；平台帧（CONNRESP/PINGRESP/SAVEACK/CMDREQ/PUSHDATA 下发）端口互换。`ip.version=4`（或 IPv6 fixture 断言 `ipv6.nxt=6` 且不得出现 v4 地址）、`tcp.len` = 该段承载的 EDP 报文字节数（单帧不跨段时）。
2. **EDP 报文（tcp.payload + frames 双通道）**：单帧不跨段时 `tcp.payload` 值 = 完整报文 hex（如 CONNRESP 恰为 `20020000`、PINGREQ 恰为 `c000`）；frames 断言在 offset 54/74 处校验关键前缀——消息类型字节（`10`/`20`/`30`/`40`/`80`/`90`/`a0`/`b0`/`c0`/`d0`）、剩余长度变长字节、协议名 `45 44 50`（"EDP"）、cmdid/msg_id 前缀等。变长长度断言例：remainlen 128 → 偏移 55 起两字节 `80 01`（2 字节档下界边界值，用例 18；remainlen 127 仍为 1 字节 `7f`，设计 §3.1 表）。
3. **跨段重组**：大帧（≥MSS）按 `tcp.stream` 重组后断言完整报文（重组流起点 = 首段 offset 54）；**任何单段不构成完整帧时不得按段断言整帧 hex**。
4. **多会话包号规则**：`sessions[]` 按多会话展开整块回放——先跑完第 1 个会话全流程（握手→事件→挥手）再跑第 2 个，不交错；**第二会话 TCP 握手包号 = 前一会话总包数 + 1**。跨会话关联断言用 `tcp.stream` 区分，不硬编码全局包号。

**fixture 常量**（帧字节可精确预算；各用例只列差异项）：地址 `192.0.2.72 → 198.51.100.72`（IPv6 `2001:db8::72 → 2001:db8::100:72`）、`src_port=41072`、`dst_port=4472`；devid=`123456789`、apikey=`kJ8mQ2xV`、userid=`284276`、authinfo=`secret-auth-info`、keep_time=128（0x0080）、msg_id=0x55AA（21930，SDK 演示常量）、cmdid=`12345678`、命令 req=`{"led":"on"}`、resp=`{"status":"ok"}`、type3 JSON=`{"temperature":22}`、type1 JSON=`{"datastreams":[{"id":"temp","datapoints":[{"at":"2026-08-31 12:00:00","value":22}]}]}`、bin desc=`{"ds_id":"fw","ver":"1.0"}`、bin=`DE AD BE EF`、透传目标设备=`987654321`、上行透传数据=`GATEWAY:HELLO`、下行透传数据=`CMD:REBOOT`、SAVEACK JSON=`{"msg_id":21930,"err_code":0}`。

## 4. 正例逐项断言契约

以下 fields/frames 为最低断言集，实现期可增不可减；帧 hex 均按设计 §3 公式对 fixture 常量预算（构造 pcap 已实证同构样本）。每例均含 `has_handshake=true`、`terminates=true`、数据帧 `has_payload=true`。

1. **`edp_connreq_devid_ipv4`**（9）：设备帧（帧 4，offset 54）hex `101e000345445001400080000931323334353637383900086b4a386d51327856`（CONNREQ 方式 1 全 32 字节：`10`=类型、`1e`=remainlen 30、`0003 454450`="EDP"、`01`=版本、`40`=方式 1 标志、`0080`=keep 128、`0009`+devid、`0008`+apikey）；平台帧（帧 5，握手 3 帧后第 2 帧业务）`tcp.payload` 恰为 `20020000`（CONNRESP，rtn=0 在末字节）；`tcp.dstport=4472` 全程、`ip.version=4`；挥手完整。
2. **`edp_connreq_userid`**（9）：设备帧 hex `1025000345445001c000800000000632383432373600107365637265742d617574682d696e666f`（`c0`=方式 2 标志、`0000`=空 devid、`0006`+userid、`0010`+authinfo，remainlen 37=0x25）；CONNRESP `20020000`。
3. **`edp_connack_refused`**（9）：CONNREQ 同用例 1（apikey 可换 fixture 钉死错误值）；CONNRESP `tcp.payload` 恰为 `20020200`（rtn=2 设备 ID 鉴权失败）；**rtn 字节后无任何业务帧**（断言挥手前 `tcp.len>0` 的帧仅 CONNREQ/CONNRESP 两帧）；连接随后关闭。
4. **`edp_pingreq_pingresp`**（11）：connect/CONNRESP 同用例 1；心跳请求帧 `tcp.payload` 恰为 `c000`、`tcp.len=2`（协议最小帧）；心跳响应帧 `d000`；方向断言（ping 设备→平台、pong 平台→设备）。
5. **`edp_savedata_type1_fulljson`**（10）：存储帧 offset 54 hex 前缀 `8067c0000931323334353637383955aa010056`（`80`+`67`=remainlen 103+`c0`=devid+msg_id 标志+devid+`55aa`+`01`=type1+`0056`=json 长 86）+ JSON 首部 ASCII `{"datastreams":`（hex `7b226461746173747265616d73223a`）与时间串 `2026-08-31 12:00:00`（hex 前缀 `323032362d30382d3331`）；帧尾 `7d`（JSON 闭合）；`tcp.len=105`。
6. **`edp_savedata_type3_simple`**（10）：存储帧 `tcp.payload` 恰为 `8016000300127b2274656d7065726174757265223a32327d`（`00`=无 devid/msg_id、`03`=type3、`0012`=json 长 18、`{"temperature":22}`）；`tcp.len=24`。
7. **`edp_savedata_type4_time`**（10）：存储帧 hex `80304055aa04002a7b2274656d7065726174757265223a7b22323032362d30382d33312031323a30303a3030223a32327d7d`（`40`=仅 msg_id、`04`=type4、时间键形态 `{"temperature":{"2026-08-31 12:00:00":22}}`）；`tcp.len=50`。
8. **`edp_savedata_type5_string`**（10）：存储帧 hex `801b80000931323334353637383905000c68656c6c6f206f6e656e6574`（`80`=仅 devid、`05`=type5、`000c`+`hello onenet` 非 JSON 裸串）；`tcp.len=29`。
9. **`edp_savedata_type2_bin`**（10）：存储帧 hex `8033c0000931323334353637383955aa02001a7b2264735f6964223a226677222c22766572223a22312e30227d00000004deadbeef`（`02`=type2、desc JSON 含 `"ds_id"`、`00000004`=u32 bin_len 4、`deadbeef`）；`tcp.len=53`。
10. **`edp_savedata_bin_empty`**（10）：存储帧 hex `80220002001a7b2264735f6964223a226677222c22766572223a22312e30227d00000000`（`00`=无 devid/msg_id 标志、bin_len=0、**desc 后无任何字节**，remainlen 34）；`tcp.len=36`——空二进制为合法边界，不得误报缺载荷。
11. **`edp_savedata_deliver`**（10）：平台→设备 SAVEDATA 同构方向（设计 §3.2/§3.5，SDK `UnpackSavedata` 同构解包证据）。事件 = connect→CONNRESP 后平台下行 SAVEDATA 一帧：下行帧 hex 与用例 6 同构，`tcp.payload` 恰为 `8016000300127b2274656d7065726174757265223a32327d`（type/flag/format/JSON 全同，仅方向不同）；方向断言互换（`tcp.srcport=4472`、`tcp.dstport=41072`）；**下行 SAVEDATA 无应答帧**（SAVEACK 仅平台对上行 SAVEDATA 回带，设计 §3.5/§3.6），下行帧后仅挥手帧。
12. **`edp_saveack_msgid`**（11）：事件 = connect→savedata（flag `0x40`、msg_id 0x55AA、type3）→SAVEACK。存储帧 hex `80184055aa0300127b2274656d7065726174757265223a32327d`；确认帧（平台→设备）`tcp.payload` 恰为 `902000001d7b226d73675f6964223a32313933302c226572725f636f6465223a307d`（SAVEACK：`90`+`20`+`00` 标志+`001d` JSON 长+`{"msg_id":21930,"err_code":0}`）；**应答 JSON 的 msg_id（21930）与 SAVEDATA 的 `55aa` 同值**（fixture 钉死；生成期取值时用 `same_as_packet` 断言）。SAVEACK JSON 内容结构为设计 §3.6 假设形态，实现期实证后如平台形态不同则同步校准断言。
13. **`edp_pushdata_upload`**（10）：透传帧（设备→平台）hex `30180009393837363534333231474154455741593a48454c4c4f`（`30`+remainlen 24+`0009`+dst_devid `987654321`+`GATEWAY:HELLO` 原样字节）；**后续无任何应答帧**（断言挥手前仅 connect/connack/pushdata 三条业务帧）。
14. **`edp_pushdata_deliver`**（10）：下发帧（平台→设备，端口互换）hex `30150009393837363534333231434d443a5245424f4f54`（src_devid `987654321` + `CMD:REBOOT`）；同构断言 + 方向断言。
15. **`edp_cmdreq_cmdresp`**（11）：命令帧（平台→设备）hex `a01a000831323334353637380000000c7b226c6564223a226f6e227d`（`a0`+remainlen 26+`0008`+cmdid `12345678`+`0000000c`=u32 req 长 12+req JSON）；应答帧（设备→平台）hex `b01d000831323334353637380000000f7b22737461747573223a226f6b227d`（`b0`+remainlen 29+**cmdid 与命令帧同值**+`0000000f`+resp）；cmdid 前缀 `00083132333435363738` 两帧逐字节相同（`same_as_packet`/fixture 钉死）。
16. **`edp_cmdresp_empty`**（11）：CMDREQ 同用例 15；应答帧 `tcp.payload` 恰为 `b00a00083132333435363738`（remainlen 10 = cmdid_len+2；**cmdid 后无 resp_len/resp 字节**，条件缺省形态）；`tcp.len=12`。
17. **`edp_disconnect`**（10）：事件 = connect→DISCONNECT。断开帧（设备→平台）`tcp.payload` 恰为 `4000`（2 字节，设计 §3.9 假设形态——实现期实证平台行为，若平台实际形态不同则按实证校准并同步设计）；断开后仅挥手帧、无业务帧。
18. **`edp_remainlen_multibyte`**（10）：事件 = connect→savedata（flag `0x00`、type3、json 为 124 字节 fixture 钉死合法 JSON 填充，如 `{"k":"<A×116>"}` 补齐至 124B）。存储帧 offset 55 起两字节 `8001`（**remainlen 恰 128 = 2 字节编码下界，127↔128 档边界值**：remainlen = 4+124 = 128；127 仍为 1 字节 `7f`）+ `0003007c`（标志/格式/json 长 124）；`tcp.len=131`（总长 = 1+2+128）。
19. **`edp_remainlen_4byte_band`**（1444 校准）：事件 = connect→savedata type2 大载荷。bin 为 2,097,118 字节 fixture 填充（desc 同用例 9，26 字节）：remainlen = `1+1+(2+26)+4+2097118` = **恰 2,097,152**（2,097,151↔2,097,152 档边界值）→ **4 字节变长编码 `80 80 80 01`**（设计 §3.1 表第 4 档示例同值）；bin_len = 2,097,118 < 3MB SDK 上界（设计 §3.5）。首段（MSS 1460）offset 54 起前缀 `80 80808001 00 02 001a`+desc hex+`001fffde`（u32 bin_len = 0x1FFFDE）+bin 填充起始；按 `tcp.stream` 重组后断言完整帧总长 2,097,157（=1+4+2,097,152）、**分段边界不切坏 u32 bin_len 字段**（重组流中 desc JSON 闭合后恰为 4 字节长度域）、`tcp.len` 各段和 = 帧总长；帧跨 1,437 个 TCP 段（2,097,157 = 1460×1436+597，末段 597B）；packet_count = 3+1437+4 = 1444（实现期校准，断言以重组流为准）。
20. **`edp_datapoint_value_types`**（10）：type1 FullJson 含四类值——int 22、float 45.5、string `device-A`、对象 `{"lon":117.48,"lat":39.96}`（官方 FAQ 位置上报形态）；帧 offset 54 前缀 `80d602c0000931323334353637383955aa0101...`（remainlen 342 → 2 字节变长 `d602`）+ JSON 内 `22`、`45.5`、`device-A`、`"lon"`/`"lat"` 的 ASCII hex 子串断言；`tcp.len=345`（总长 = 1+2+342）。**顶层 `token` 变体声明**：token 属 type1 JSON 内容自由度——同一 u16 前缀 + JSON 字节编码，不改帧结构与长度公式断言形态（SDK `PacketSavedataJson` 对 JSON 串原样 `WriteStr`）；按原子原则不并入本例、不单独设例，用例范围外（设计 §3.5 声明）。
21. **`edp_json_u16_max`**（52 校准）：事件 = connect→savedata（flag `0x00`、type3、json 为**恰 65,535 字节** fixture 钉死合法 JSON 填充，如 `{"k":"<A×65,527>"}` 补齐至 65,535B）。存储帧 offset 55 起 3 字节 `838004`（remainlen = 4+65,535 = 65,539 → 3 字节变长，3 字节档自然覆盖）+ offset 60 起 json 长度域 **`ffff`（65,535 = u16 满值，精确上界）** + json 填充起始；首段前缀 `80 838004 00 03 ffff`+json 起始字节。按 `tcp.stream` 重组后断言 JSON 字节数恰 65,535、帧总长 65,543（=1+3+65,539）；帧跨 45 个 TCP 段（65,543 = 1460×44+1303）；packet_count = 3+45+4 = 52（实现期校准）。**>65,535 由负例 `edp_neg_json_payload` 拒绝，精确上界正例 + 超界负例成对闭合**。
22. **`edp_multi_transaction_keepalive`**（16）：单 `tcp.stream` 九帧业务序列：CONNREQ(`10`)→CONNRESP(`20`)→SAVEDATA(`80`)→SAVEACK(`90`)→PINGREQ(`c0`)→PINGRESP(`d0`)→CMDREQ(`a0`)→CMDRESP(`b0`)→DISCONNECT(`40`)；断言各帧类型字节按此顺序出现（`tcp.payload` 首字节序列恰为 `10 20 80 90 c0 d0 a0 b0 40`）、cmdid/msg_id 关联同用例 12/15、无乱序（设计 §1：本版按序回放）。
23. **`edp_ipv6`**（9）：IPv6 独立 fixture（`2001:db8::72 → 2001:db8::100:72`，显式给出）；断言 `ipv6.nxt=6`、EDP 首字节 offset **74**、CONNREQ/CONNRESP 字节与用例 1 完全一致（同一逻辑报文，仅外层 IP 头不同）；不得出现 `ip.version=4`。
24. **`edp_multi_session`**（20 = 10+10）：会话 1（`src_port=41072`，devid `123456789`）与会话 2（`src_port=41073`，devid `223456780`）各含 connect+connack+savedata；断言 `tcp.stream` 两值 distinct、**第二会话握手包号 = 11**（= 前会话 10 包 + 1，多会话展开）、两会话 devid 字节串 distinct、各自 CONNRESP rtn=0、会话间状态不串用。
25. **`edp_mss_large_bin`**（19 校准）：savedata type2、bin 为 16,350 字节 fixture 填充（desc 同用例 9，26 字节）：remainlen = `1+1+(2+26)+4+16350` = **恰 16,384**（16,383↔16,384 档边界值，2 字节档上界 16,383 仍为 `ff 7f`）→ **3 字节变长编码 `80 80 01`**（3 字节档下界，设计 §3.1 公式）；首段（MSS 1460）offset 54 起前缀 `80 808001 00 02 001a`+desc hex+`00003fde`（u32 bin_len = 16,350 = 0x3FDE）+bin 填充起始；断言按 `tcp.stream` 重组后完整帧（首段 offset 54 起 `80`+变长+`0002`+desc+u32 bin_len+16,350B bin，末段以 bin 末字节收尾）、帧跨 12 个 TCP 段（16,388 = 1460×11+328，末段 328B）、`tcp.len` 各段和 = 帧总长 16,388、**分段边界不切坏 u32 bin_len 字段**（重组流中 desc JSON 闭合后恰为 4 字节长度域）；packet_count = 3+12+4 = 19（实现期校准）。
26. **`edp_keep_time_boundary`**（9）：**仅满值边界**：CONNREQ offset 63 起两字节 `ffff`（keep_time=0xFFFF，remainlen 不变 0x1e = 13+9+8），得 CONNRESP `20020000`；keep_time 默认值 0x0080 断言由用例 1 的 CONNREQ hex 承载（单会话 9 包仅容纳一次 CONNREQ，不另设默认值变体会话——原子原则：默认值规格点已在用例 1 断言）。
27. **`edp_long_devid`**（9）：devid/apikey 各 64 字节 fixture 钉死字符串；CONNREQ remainlen = `13+64+64 = 141`（>127 → **2 字节变长编码 `8d 01`**，设计 §3.1）；断言 offset 55 起两字节 `8d01`、offset 57 起 `0003 454450`（协议名）、offset 66 起 devid 长度域 `0040`（64）、`tcp.len=144`（总长 = 1+2+141）。

**正例总则**：每条实现后至少含 `packet_count`（或 `min_packets`）+ 载体与方向断言 + `has_payload`（数据帧 `tcp.payload` nonzero）+ 类型字节 frames 断言；帧 hex 均可由设计 §3 公式 + fixture 常量精确预算（本文已给出全部锚定样本）；动态值只用存在与关联断言。合法协议事件（CONNRESP rtn 1–9、空 resp、空 bin、PUSHDATA 无应答）均为正例形态，只有配置、线格式、状态、关联、长度错误进入负例（设计 §7）。

## 5. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；执行期 `expect` 键集合**严格为** `{expect_error, error_contains}`。锚词与设计 §7 表一一对应、同序：

| ID | 故障输入（`wire_fault`/配置注入口） | 目标 `error_contains` |
|---|---|---|
| `edp_neg_unknown_type` | 消息类型值不在设计 §3.2 表（如 `0x00`/`0x50`/`0xFF`） | `type`、`message` |
| `edp_neg_remainlen` | 剩余长度 ≠ 消息体实际字节数、报文截断、变长编码第 5 字节仍置延续位 | `remainlen`、`length`、`truncat` |
| `edp_neg_connect_protocol` | 协议名非 "EDP"、版本 ≠1、连接标志非 0x40/0xC0 | `protocol`、`version`、`flag` |
| `edp_neg_savedata_format` | 数据格式标志取 0x00/0x06/0xFF 等值域外值 | `format`、`type` |
| `edp_neg_bin_desc` | type2 desc 无 `ds_id`、desc 非法 JSON、desc ≥65,536、bin_len ≥3MB | `desc`、`ds_id`、`length` |
| `edp_neg_state` | 事件序列不以 connect 开头（如首事件 savedata/ping/pushdata）、CONNRESP rtn≠0 后继续排业务事件、DISCONNECT 后继续排业务事件（设计 §5 Disconnecting 约束） | `state`、`connect`、`sequence` |
| `edp_neg_cmdid_correlation` | cmdreq 配置的应答 cmdid 与请求 cmdid 不同值 | `cmdid`、`correlation`、`cmd` |
| `edp_neg_msgid_correlation` | saveack 配置的回带 msg_id ≠ 触发 savedata 的消息编号 | `msg_id`、`correlation` |
| `edp_neg_json_payload` | format 0x01/0x03/0x04 的内容非法 JSON（截断/非对象）、json >65,535 字节 | `json`、`length` |
| `edp_neg_carrier_port` | 层链缺 tcp（`[{"edp":{}}]` 直连）、UDP 载体、端口/载体声明矛盾 | `carrier`、`port`、`layer` |
| `edp_neg_connect_auth` | 方式 1 devid 或 apikey 空串、方式 2 userid 或 authinfo 空串 | `devid`、`auth`、`config` |
| `edp_neg_connack_rtn` | `connack_rtn` 取 0–9 值域外的值（如 10/0xFF） | `rtn`、`value` |

合法协议事件不进负例（防误报）：CONNRESP rtn=1–9、CMDRESP 空 resp、bin_len=0、PUSHDATA 无应答、keep_time 满值、空 json 数值字段。

## 6. 五层覆盖映射

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 1–22（正）；28–39（负） | 10 类实现范围消息每类正例（connect 两方式/connack 拒绝路径/心跳/savedata 五格式四标志组合 + 平台→设备同构方向/saveack/pushdata 双向/cmd 条件缺省/disconnect）+ 多事务全链；负例 12 类锚词逐类与设计 §7 对应；ENCRYPT×2 为设计 §1 边界不设用例 |
| 性能 | 18、19、21、25、24 | 2/3/4 字节变长长度（边界值 128/16,384/2,097,152 各有正例：18/25/19）、json 65,535 精确上界正例（21；超界由负例 36 拒绝）、bin 3MB 上界（超界由负例 32 拒绝）、16K 级与 2MB 级 bin 跨 MSS 分段重组（25/19，12 段与 1,437 段）、多会话并发；发包速率由框架既有配置承载（v1.1 §10 口径） |
| 数据场景 | 5–10、18–21、25–27；负 31、32、36 | 数据格式 0x01–0x05 全枚举、标志四组合、JSON 值域（int/float/string/对象）、时间格式、remainlen 变长四档、bin_len=0、json 精确上界、keep_time 满值（默认 0x0080 由用例 1 承载）、64B 长标识符；非法值拒绝 |
| 地址与流 | 1（v4 单流基线）、23（v6）、24（多会话双四元组） | v4+v6 必覆盖；流关联与多流显式不适用（设计 §4 声明：EDP 转发走同一 TCP 连接、单连接串行） |
| 业务 | 1/2（接入）、4（心跳）、5–12（周期上报，含下行同构）、15/16（命令下发）、13/14（透传）、3（鉴权失败重连前奏）、22（完整生命周期） | OneNET EDP 现网日常场景优先（接入-心跳-上报-命令链） |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/edp.json` 通过；当前数组恰含 1 条 `edp_neg_unregistered`：`proto=edp`、层链 `[{"tcp":{}},{"edp":{}}]`、`expect_error=true`、`error_contains` 精确为 `unknown layer`（注册时把占位端口 9847 改为 4472）。
2. 实现注册 `edp` 层后：移除占位，按 §2 顺序补入 39 个语义用例；ID、顺序与设计 §9 完全一致（脚本核验）。
3. 正例每条含 `packet_count`（或 `min_packets`）+ `fields` + `frames`；`fields` 只用 §1 实测存在的 tshark 字段（`tcp.*`/`ip.version`/`ipv6.nxt`/`frame.*`），**不使用任何 `edp.*` 字段**（本机 EDP dissector 属 Extreme Discovery Protocol，与本协议无关）。
4. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields。
5. 跨会话/跨段断言用 `tcp.stream` + 多会话展开起点规则（§3.4），不硬编码全局包号；动态值用 `same_as_packet`/`distinct_values`/`nonzero`。
6. 若实现期实证 SAVEACK JSON 实际形态 / DISCONNECT 报文体 / CONNRESP 标志字节与本版假设（设计 §3.6/§3.9/§3.3）不符，设计 §3 与本文 §4 对应断言同步校准，并在两文档修订记录登记。

## 8. 三方一致性表

设计 §9、本文 §2、实现后 `edp.json` 保持同一 39 个语义 ID、同一顺序（当前 JSON 另有占位，不计入）：

```text
edp_connreq_devid_ipv4
edp_connreq_userid
edp_connack_refused
edp_pingreq_pingresp
edp_savedata_type1_fulljson
edp_savedata_type3_simple
edp_savedata_type4_time
edp_savedata_type5_string
edp_savedata_type2_bin
edp_savedata_bin_empty
edp_savedata_deliver
edp_saveack_msgid
edp_pushdata_upload
edp_pushdata_deliver
edp_cmdreq_cmdresp
edp_cmdresp_empty
edp_disconnect
edp_remainlen_multibyte
edp_remainlen_4byte_band
edp_datapoint_value_types
edp_json_u16_max
edp_multi_transaction_keepalive
edp_ipv6
edp_multi_session
edp_mss_large_bin
edp_keep_time_boundary
edp_long_devid
edp_neg_unknown_type
edp_neg_remainlen
edp_neg_connect_protocol
edp_neg_savedata_format
edp_neg_bin_desc
edp_neg_state
edp_neg_cmdid_correlation
edp_neg_msgid_correlation
edp_neg_json_payload
edp_neg_carrier_port
edp_neg_connect_auth
edp_neg_connack_rtn
```

## 9. 修订记录

- v1.0.0（2026-08-21）：旧稿首版（14 正 + 6 负，基于已废弃的臆造线格式：40 字节帧头/magic EDP1/CRC32/REGISTER-HEARTBEAT-TELEMETRY 消息集）。
- v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-21 旧稿（旧稿见 git 历史）。以 OneNET 官方 EdpKit SDK 两副本 + 官方文档站为基线重排为 36 条（24 正 + 12 负）：每消息类型、每数据格式（0x01–0x05）、每标志组合（0x00/0x40/0x80/0xC0）、每关联规则（cmdid/msg_id）、每边界（变长长度 2/3 字节档、bin_len=0、keep_time 满值、64B 长标识符、CONNRESP rtn 值域）各一例；索引表改为五列格式（覆盖列引用设计 § 编号）；以 tshark 3.6.14 实测固化"无 OneNET EDP dissector（tshark 的 EDP=Extreme Discovery Protocol，禁用 `edp.*` 字段）、断言走 `tcp.payload` 全帧 hex + offset 54/74 frames 双通道"基线，并按官方 SDK 逻辑构造 pcap 实证（CONNREQ/CONNRESP/SAVEDATA/SAVEACK/CMDREQ/CMDRESP/PINGREQ/PINGRESP 逐字节提取吻合）；新增 §3 偏移与双通道断言、§6 五层映射、§8 三方一致性表；删除旧稿 tls/pcap_nic/multi_stream 等不适用项（设计 §1/§4 边界）。状态：**待独立隔离审查**。

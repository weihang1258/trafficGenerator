# #29 jt808（JT/T 808-2019 终端通讯协议）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨 as-built）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/02-03-04-jt808-jt809-jtt905-design.md`（D-JT808-1，Part A §2A–§8A，三协议合集——本文只引用 JT808 部分）
> 前序基线：设计 §8A 测试用例清单 **A-01…A-59**（连号 58 个平号 + 9 个字母变体行 = **67 行**；设计文末自述"65 条"与行数不符，登记 G-JT808-7）；**存量 16 例是 T-1…T-16 独立编号**（实现期重排，非 A 系直接投影，映射见 §5.3）
> 机器契约：`trafficgen/test/protocol_pcap/cases/jt808.json`（**16/16 ID 与本版 §2 一致，顺序一致，已机读实测**；**全部 16 例 `spec_json` 顶层键 = 纯 `{layers}`，零游离键、零顶层子映射、零顶层四元组、零 `count`——非负例顶层残留 = 0**）
> 白话一句：**十六条检查：十二条看正常收发（注册、鉴权、双流水号、帧字节、位置上报、版本方言、平台下发、文本、属性应答、分包、心跳），四条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3A（报文格式）、§4A（消息体）、§5A（Config/Validate）、§6A（状态机/双 SN）、§7A（数据场景）逐项派生，存量落码为 **16 个唯一语义 ID：12 正 + 4 负**（T-1…T-16，其中 T-11…T-14 为负例）。**一个用例只验证一个协议行为**；断言不得超出设计声明范围。

**形状基线（2026-09-29 机读实测）**：

| 项 | 值 |
|---|---|
| 例数 | **16**（12 正 + 4 负） |
| 例顶层键 | 全 16 例含 `{expect,id,proto,spec_json,summary}`；无例级 `notes`、无 `strategy_fc`（多流语义本协议零用例） |
| **`spec_json` 顶层键（全部 16 例）** | **`{layers}` ×16（唯一键，零游离键）——非负例与负例顶层残留均为 0，无 §1 迁移工作量** |
| 层形 | `[ip,jt808]` ×16 统一两层（TCP 载体，无独立 transport 层；端口**无层字段**，`dst_port` 缺省 7611 由生成器内部缺省供给） |
| 正例 `expect` | `packet_count` ×12（**无 `min_packets` 用例**）；`fields` ×2（#1/#2，共 **13 条**，全部 `tcp.flags`/`tcp.dstport`）；`frames` ×12（hex 钉帧，**主断言通道**）；`notes` ×12（帧内逐字段证据） |
| 正例 `has_payload` | ×8；#6/#7/#8/#16 四例**显式不适用**（最大帧 15/25/26/15B 低于 80B 载荷断言门，短帧用例口径） |
| 负例 `expect` | 4/4 = `{expect_error, error_contains, notes}`（**无 `packet_count`、无 `fields`、无 `frames`**） |

**输出契约（pcap/NIC 双输出）**：设计契约 = 两路径共用同一 cases JSON 与断言集（`tcp.flags`/`tcp.dstport` 字段通道 + `frames` hex 通道）。**现状诚实标注**：本契约**无 NIC/pcap 复跑实证可引用**——16 例的 `frames` hex 与包数为在案已钉值，P5 重跑后方可刷新证据；本文不对任何一例声称"今日已复跑通过"。

**包数公式（实测钉死，TCP 族口径）**：单流 = **3（握手 SYN/SYN-ACK/ACK）+ 消息帧数 + 3（挥手 FIN/FIN/ACK）**；消息帧 = 每帧一个 TCP PSH-ACK（payload 起点 offset 54 = eth 14 + ip 20 + tcp 20），JT808 报文一条一帧（体 >1023B 走协议分包，仍一分包一帧）。**负例无 `packet_count`**（planner 拒绝，不产帧）。逐例复算：#1=3+4+3、#2=3+1+3、#3=3+4+3、#4/#5/#6/#8/#9/#16=3+1+3、#7=3+3+3、#10=3+2+3（分片 2 帧）、#15=3+3+3，合计 **95 帧**（机读复算）。

**保活/重试/RST 口径**：保活 = 0x0002 终端心跳空体上行（#16 覆盖）；设计 §6A.1 的 30s 超时重发为**状态机声明**，存量无对应用例（A′）；挥手为 **3 帧 FIN/FIN/ACK**（#1 fields 钉 0x011/0x011/0x010），RST 不设断言。

**断言强度基线（诚实标注）**：主断言通道是 `frames`（hex 钉帧，offset 54 起逐字节），强于字段通道；但 `fields` 仅 2 例 13 条且只覆盖 TCP 面（`tcp.flags`/`tcp.dstport`），**无任何 `jt808.*` dissector 字段断言**（与 dns 的"全字段通道"相反）——tshark 对 JT808 无内置 dissector，hex 钉帧是合理选择，但须登记：**断言不含 tshark 字段名依赖，无字段版本漂移风险**。

## 2. 原子用例索引（16 ID = 12 正 + 4 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | 包数 | 断言面 |
|---:|---|---|---|---:|---|
| 1 | `jt808_t1_baseline_assoc` | 正 | §6A/§7A.11：基线关联（握手+注册→应答→鉴权→通用应答+挥手；msgId 序 0100/8100/0102/8001；双 SN 空间 0/0→1/1） | 10 | fields 11 + frames 4 |
| 2 | `jt808_t2_frame_header_bytes` | 正 | §3A.1/§3A.4：帧头字节钉（0x7e 定界、BCD、SN=42、XOR 校验 b4） | 7 | fields 2 + frames 1 |
| 3 | `jt808_t3_dual_sn_autobind` | 正 | §6A.2/§5A M-05：双 SN 空间（100/200）+ 4 自动绑定逐格钉 | 10 | frames 4 |
| 4 | `jt808_t4_register_body_fields` | 正 | §4A.1：注册体字段钉（省/市 BE + 三段 pad + 车牌色 + GBK 车牌） | 7 | frames 1 |
| 5 | `jt808_t5_location_bitmerge_escape` | 正 | §4A.3/§5A H-05/§3A.4：位置上报 28B 面 + ACC 位合并 + TLV 0x7e/0x7d 转义 | 7 | frames 1 |
| 6 | `jt808_t6_version2011_encrypt_bit` | 正 | §3A.2/§5A：版本方言 2011（版本位 000）+ encrypt_flag=1（bit15，占位不加密） | 7 | frames 1 |
| 7 | `jt808_t7_down_tlv_trio` | 正 | §4A.9：0x8103 设置参数 TLV + 0x8104 查询参数（空体）+ 0x0003 注销（上行） | 9 | frames 3 |
| 8 | `jt808_t8_text_down_gbk` | 正 | §4A.9/§7A.8：0x8300 文本下发（text_flag 位 + GBK 中文载荷） | 7 | frames 1 |
| 9 | `jt808_t9_property_response` | 正 | §4A.6：0x0107 终端属性应答 17 字段全钉 | 7 | frames 1 |
| 10 | `jt808_t10_fragmentation` | 正 | §3A.2/§7A.12(e)：分包（体 1076B>1023 拆 2，总包数@+12/序号@+14，SN 同值） | 8 | frames 2 |
| 11 | `jt808_t11_neg_phone_11digits` | 负 | §5A.1：手机号 11 位拒 | — | 0 |
| 12 | `jt808_t12_neg_auth_missing_code` | 负 | §5A.1/§7A.2(c)：auth 过程无 AuthCode 拒 | — | 0 |
| 13 | `jt808_t13_neg_color0_plate` | 负 | §5A.1：LicenseColor=0 但 LicensePlate 非空拒 | — | 0 |
| 14 | `jt808_t14_neg_ackflag_99` | 负 | §5A.1/§7A.10：ACKFlag=99 拒（嵌套键 V9 不下探） | — | 0 |
| 15 | `jt808_t15_identity_composite` | 正 | §4A.1/§4A.2/§7A.9：身份面复合例（6 键显式 + 注册失败 result=2 无鉴权码） | 9 | frames 3 |
| 16 | `jt808_t16_heartbeat` | 正 | §7.2（JT/T 808）：终端心跳 0x0002 空体上行（保活核心型） | 7 | frames 1 |

**A-编号对照要点**：存量 16 例是设计 §8A A-01…A-59 清单的**实现期重排子集**，T 系编号与 A 系**不是一一映射**（例：#4 ≈ A-01+A-04 合并钉、#16 ≈ A 系清单外的 F4 勘误补齐型）。A 系其余条目（如 A-07 空码 validation、A-27 SN 回绕、A-29 多终端并发、A-31…A-47 validate 面、A-52/A-53 方向钉）**未逐一落例**——诚实登记为 A′（§6.2），不冒充已覆盖。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count` + `frames`（hex 钉帧）；帧值以在案已钉 bytes 为准（P5 重跑前不新增数值声明）。

### 3.1 `jt808_t1_baseline_assoc`（10 包）

`ip{src:10.0.0.1, dst:20.0.0.1}`、`jt808{phone:"012345678901", auth_code:"ABCDEF1234567890", procedures:[register, registration_response, auth, platform_general_response]}`。

- `packet_count=10` = 3 握手 + 4 消息 + 3 挥手；11 条 fields：帧 1/2/3 `tcp.flags`=0x002/0x012/0x010（握手三拍）、帧 1 `tcp.dstport=7611`、帧 4–7 `tcp.flags=0x018`（四条消息 PSH-ACK）、帧 8/9 `tcp.flags=0x011` + 帧 10 `0x010`（挥手三拍）。
- **帧字节（offset 54 起）**：f4 = `7e 01 00 08 25 …`（0x0100 注册，props 0x0825 = 版本位 010(2019) | 体长 0x25(37B，plate 空——LicenseColor 缺省 0)）；f5 = `7e 81 00 08 13 … 41 42 43 44`（0x8100：respSN 自动绑 0x0100 的 SN=0，result=0 携带 AuthCode 16B，props 0x0813=19B）；f6 = `7e 01 02 08 33 … 00 01 41 42 43 44`（0x0102：上行 SN=1；体 = AuthCode16 + IMEI15(0 填充) + 软件版本20(0 填充) = 51B）；f7 = `7e 80 01 08 05 … 00 01 00 01 01 02 00`（0x8001：respSN 绑最近上行 SN=1、respMsgId 绑最近上行 msgId=0x0102，result=0）。
- **双 SN 证据**：上行 0/1、下行 0/1 各自独立计数（§6A.2 design 语义）。
- **自驱面**：握手/挥手由生成器自驱（raw 自驱）；端口 = 生成器内部缺省 7611（**层无端口字段**，与 vnc/pptp 变体同款）。

### 3.2 `jt808_t2_frame_header_bytes`（7 包）

`jt808{phone:"012345678901", initial_sn:42, procedures:[register]}`。

- `packet_count=7`；2 条 fields：帧 1 `tcp.flags=0x002`、`tcp.dstport=7611`。
- **整帧 52B 钉（offset 54）**：`7e + 头12B + 体37B + 校验1B + 7e`；头 = msgId 0100 + props 0825 + 手机号 BCD `012345678901`→`01 23 45 67 89 01` + SN `002a`(42)。
- **体 37B 钉**：省 0000 + 市 0000 + 厂商 `TEST`(0x00 补至 5) + 型号 `TG-DEMO`(0x20 补至 20) + 终端ID `0000001` + 色 00；校验 `b4` = 头+体逐字节 XOR（design §3A.4：**校验范围含消息体**）。
- **无转义面**：本帧无 0x7e/0x7d 载荷字节（转义路径由 #5 覆盖）。

### 3.3 `jt808_t3_dual_sn_autobind`（10 包）

`jt808{phone:"012345678901", initial_sn:100, platform_initial_sn:200, procedures:[query_location, location_query_response(+location_data), text_down(text_flag:1,text:"hi"), terminal_general_response]}`。

- `packet_count=10`；无 fields（本协议多数正例同款，主断言在 frames）。
- **帧字节钉**：f4 = `7e 82 01 08 00 … 00 c8 cb`（0x8201 查询位置下行空体，下行 SN=0x00c8=200——PlatformInitialSN 独立空间）；f5 = `7e 02 01 08 1e … 00 64 00 c8 00 00 00 01 … 02 60 d3 60`（0x0201：querySN 自动绑最近 0x8201=0x00c8、上行 SN=0x0064=100；体 = querySN2 + 28B 位置面，lat 0260d360=39900000、time BCD 260921120000）；f6 = `7e 83 00 08 03 … 00 c9 01 68 69 c9`（0x8300 文本下发：下行 SN=0x00c9 递增，text_flag 01 + GBK "hi"=6869）；f7 = `7e 00 01 08 05 … 00 65 00 c9 83 00 00 ab`（0x0001：respSN 绑最近下行 SN=0x00c9、respMsgId 绑 0x8300；上行 SN=0x0065）。
- **双计数器互不干扰证据**：上行 100/101、下行 200/201，两空间同帧并存（§6A.2）。
- **4 条自动绑定逐格钉**：0x0201→最近 0x8201、0x0001→最近下行、0x8100→最近 0x0100（#1）、0x8001→最近上行（#1）——**M-05 全四格在本协议两例内闭合**。

### 3.4 `jt808_t4_register_body_fields`（7 包）

`jt808{phone:"012345678901", province_id:11, license_color:1, license_plate:"京A12345", terminal_model:"TG-DEMO-X", procedures:[register]}`。

- `packet_count=7`；1 帧钉（f4，offset 54）。
- **体 45B（props 0x082d）**：省 `000b`(11) + 市 `0000` + 厂商 `5445535400`（TEST+0x00 补至 5）+ 型号 `TG-DEMO-X`+0x20×11（补至 20）+ 终端ID `30`×7 + 色 `01` + GBK 车牌。
- **三段 pad 规则钉**：厂商/终端ID **0x00** 补、型号 **0x20** 补（`54472d44454d4f2d58`+`20`×11）、GBK 车牌不补——与 #9 的"APN/硬件版本 GBK 不补"共同构成 pad 全谱。
- **GBK 证据**：京A12345 = `be a9 41 31 32 33 34 35`（京=0xBEA9，ASCII 原样）。

### 3.5 `jt808_t5_location_bitmerge_escape`（7 包）

`jt808{procedures:[location_report{location_data:{alarm_flag:1, latitude:39900000, longitude:116390000, altitude:50, speed:600, direction:90, time:"260921120000", acc:true, extra_items:[{type:1, value:[126,125]}]}}]}`。

- `packet_count=7`；1 帧钉：整帧 49B = `7e + 头12 + 体32 + 校验 + 7e`。
- **28B 固定面 + 位合并**：alarm `00000001` + status `00000001`（status_flag 直设缺省 0，**acc=true OR 入 bit0**，design §5A H-05）+ lat `0260d360` + lon `06eff870` + alt `0032` + speed `0258` + dir `005a` + time BCD `260921120000` + TLV。
- **转义面（§3A.4）**：TLV = type `01` + len `02` + value `7e 7d`；线上 `7e→7d 02`、`7d→7d 01`，帧长 +2（`7d 02 7d 01` 在 payload 偏移 42–45）。
- **props/校验口径**：props 0x0820 = 体长 0x20(32，**转义前**)；校验 `3c` 对**原始未转义消息体**全量逐字节 XOR，再进行转义——"先算校验后转义"的线上证据。

### 3.6 `jt808_t6_version2011_encrypt_bit`（7 包）

`jt808{version:"2011", encrypt_flag:1, procedures:[cancel]}`。

- `packet_count=7`；1 帧钉：`7e 00 03 80 00 01 23 45 67 89 01 00 00 0b 7e`（0x0003 注销空体，整帧 15B）。
- **props 0x8000 双位钉**：bit15 加密标志置位 + 版本位 000(2011)——与 #1/#2 的 2019（010，即 0x0800）对照；**2013=001 同机制不单列**（B′ 注记）。
- **加密占位口径**：encrypt_flag=1 不做真加密（design §5A/§11A.2）：仅标志位置位、体明文。
- `has_payload` 不适用：最大帧 15B 低于 80B 载荷断言门（短帧用例口径）。

### 3.7 `jt808_t7_down_tlv_trio`（9 包）

`jt808{procedures:[set_params{params:[{id:1,value:"abcd"},{id:130,value:[0,255]}]}, query_params, cancel]}`。

- `packet_count=9` = 3 + 3 消息 + 3；3 帧钉（f4/f5/f6）。
- **f4 0x8103 体 17B（props 0x0811）**：参数总数 `02` 前导 + TLV×2：ID **DWORD** `00000001` + len `04` + `abcd` / ID DWORD `00000082` + len `02` + `00ff`——**规范体形（F2 勘误后实测钉：总数 BYTE 前导 + 参数ID 4 字节）**；下行 SN=0。
- **f5 0x8104 空体**（props 0x0800）；**f6 0x0003 注销空体但属上行**（终端主动）→ 上行 SN=0——**方向与计数器归属分离**的直接证据。
- **value 双形（getByteSlice 原文语义）**：param1 用原文字符串 `"abcd"`、param2 用字节数组 `[0,255]`——字符串=**原文字节**非 hex（P5 勘误钉）。
- `has_payload` 不适用：最大帧 25B 低于 80B 门。

### 3.8 `jt808_t8_text_down_gbk`（7 包）

`jt808{procedures:[text_down{text_flag:1, text:"限速30公里"}]}`。

- `packet_count=7`；1 帧钉：`7e 83 00 08 0b … 00 01 cf de cb d9 33 30 b9 ab c0 ef 34`。
- **体 13B（props 0x080b）**：text_flag `01` + GBK：限=`cfde` 速=`cbd9` 3=`33` 0=`30` 公=`b9ab` 里=`c0ef`；下行 SN=0。
- **GBK 编码器证据**：中文载荷字节由 GBK 编码器产出（jtcommon.GBKEncode；JT/T808 文本默认 GBK，GB 18030 子集）。
- `has_payload` 不适用（最大帧 26B < 80B 门）。

### 3.9 `jt808_t9_property_response`（7 包）

`jt808{procedures:[property_response{property_data:{device_type:1, manufacturer_id:"TEST", terminal_model:"TG-PROP", terminal_id:"0000001", icc_id:"1234567890", imei:"012345678901234", software_version:"V9.9", gnss_module:1, comm_module:2, province_id:11, city_id:1, county_id:1, town_id:1, operator:1, apn:"cmnet", hardware_version:"H1", max_speed:200}}]}`。

- `packet_count=7`；1 帧钉。
- **体 100B（props 0x0862）全 17 字段序钉**：类型 `01` + 厂商 5(0x00 pad) + 型号 20(0x20 pad) + 终端ID 7 + ICC 10 + IMEI 15 + 软版本 20(0x00 pad) + GNSS/通信模块 `01`/`02` + 省市区镇 BE（`000b`/`0001`/`0001`/`0001`）+ 运营商 `01` + APN GBK `cmnet`（不补）+ 硬件版本 `H1`（不补）+ 最高速度 `00c8`(200)。
- **定长补零 vs 变长不补的分界证据**：APN/硬件版本 GBK 后不补零（0x0107 变长尾），与厂商/型号/ID 定长补零规则同帧对照。
- **设计 17 字段覆盖声明核对**：设计 §4A.6 的 17 字段与帧序一致；无字段缺测。

### 3.10 `jt808_t10_fragmentation`（8 包）

`jt808{procedures:[set_params{params: 5 项，value 模式 (i*37+j)%251}]}`（体 1076B）。

- `packet_count=8` = 3 + **2 分片帧** + 3；2 帧钉（f4/f5）。
- **拆分证据**：体 = 总数 `01`×5 项[参数ID DWORD + 长度 BYTE + 210B value] = 1076B > MaxBodyLength 1023（10 位体长域上界）→ buildFragmentedFrames 拆 2；分片 1 = 1023B（props 0x4bff）/ 分片 2 = 53B（props 0x4835）。
- **封装项规范序（F1 勘误钉）**：消息总包数 WORD@+12 = `0002`、包数据序号 WORD@+14 = `0001`/`0002`；**两分片同 SN=0**（design §3A.2：同一逻辑消息共享 MsgSN）、各带独立 XOR 校验。
- **转义附加覆盖**：value 模式 (i*37+j)%251 中 0x7d 实际命中（线上 `7d 01` 转义）；0x7e 不出现（值域 ≤250）。
- `has_payload=true`（分片帧超 80B 门）。

### 3.11 `jt808_t15_identity_composite`（9 包）

`jt808{phone:"012345678901", province_id:11, city_id:1, manufacturer_id:"JT808", terminal_id:"7777777", imei:"111111111111111", software_version:"SW-VER-1.0", registration_result:2, auth_code:"ABCDEF1234567890", terminal_type:1, procedures:[register, registration_response, auth]}`。

- `packet_count=9` = 3 + 3 消息 + 3；3 帧钉。
- **身份 6 键逐字节钉**：city_id `0001` / 厂商 `4a54383038`（JT808，5B 无 pad） / 终端ID `37373737373737`（7777777） / imei 15×`31` / software_version `SW-VER-1.0`+0x00 pad——顶层键全数落线。
- **注册失败路径**：registration_result=2 → 0x8100 体 = respSN `0000` + `02` 仅 **3B 无鉴权码**（result≠0 省略 AuthCode，JT/T808 §7.8 路径）；props 0x0803。
- **B′ 诚实注记（零消费键）**：`terminal_type` 显式置 1 但 builder 零消费（0x0107 属性体读 `property_data.*` 不读顶层 TerminalType）——**键登记但无 wire 面**。
- **鉴权体证据**：f6 = AuthCode 16B（`ABCDEF1234567890`）+ imei 15×31 + SW-VER-1.0+0×11 pad，体 51B（props 0x0833）。

### 3.12 `jt808_t16_heartbeat`（7 包）

`jt808{procedures:[heartbeat]}`。

- `packet_count=7`；1 帧钉：`7e 00 02 08 00 01 23 45 67 89 01 00 00 82 7e`（0x0002 终端心跳，空体、props 0x0800(2019 版本位)、上行 msgSN、整帧 15B 含 XOR 校验 82）。
- **保活核心型（F4 勘误补齐）**：JT/T 808 §7.2 心跳为空体上行帧——设计 §8A A 系清单未列 0x0002，本例为 as-built 增量（**G-JT808-1**，见 §5.4）。
- `has_payload` 不适用（短帧口径）。
- **消息族去向注记（F4）**：0x0002 已编排；0x0104/0x0108/0x8003 等未编排型登记 B′（设计 D-JT808-1 裁定5）。

**正例总则**：消息一帧一 PSH-ACK、握手/挥手自驱、双 SN 空间并存、体超 1023B 协议分包——均为正例形态；只有配置校验错误进入负例。

## 4. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功（**本契约无在案 pcap 复跑实证，P5 重跑后补**）。锚词与 planner `ValidateConfig`（`trafficgen/internal/protocol/jt808/jt808.go`）逐字对应：

| # | ID | 故障输入（机读实测） | JSON `error_contains` | 代码锚（ValidateConfig） | 拒绝层 |
|---:|---|---|---|---|---|
| N-1 | `jt808_t11_neg_phone_11digits` | `phone:"12345678901"`（11 位） | `must be 12 digits` | Phone 长度/数字门（`^\d{12}$`） | planner ValidateConfig |
| N-2 | `jt808_t12_neg_auth_missing_code` | `procedures:[auth]`，顶层与过程级双缺 AuthCode | `AuthCode is empty` | ProcAuth 存在时顶层/过程级至少一处非空（design §7A.2 H-07） | planner ValidateConfig |
| N-3 | `jt808_t13_neg_color0_plate` | `license_color:0` + `license_plate:"京A12345"` | `LicenseColor=0 but LicensePlate non-empty` | 色 0=无车牌、plate 必须空（design §5A.1） | planner ValidateConfig |
| N-4 | `jt808_t14_neg_ackflag_99` | `procedures:[platform_general_response{ack_flag:99}]` | `ACKFlag 99 invalid` | ACKFlag>3 拒（design §7A.10：0-3 合法，无 99=其他） | planner ValidateConfig |

**锚词口径**：`error_contains` 是**子串**判定，4/4 均为 planner ValidateConfig 锚（N-4 尤其注意：`ack_flag` 是**嵌套 procedures 键，registry V9 区间门不下探 list/object**——锚落 planner 而非框架层，P3 复审核准的拦截点）。

**负例原子性**：每例单一故障注入；4/4 机读实测均单注入。

**负例纯净性**：4/4 `expect` 键集合 = `{expect_error, error_contains, notes}`（**无 `packet_count`、无 `fields`、无 `frames`**）；`notes` 仅注锚来源，不断言 wire 行为——符合负例纪律。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：Version 非法（`invalid Version`）、EncryptFlag>1、ManufacturerId>5/非 ASCII、TerminalModel>20、TerminalId>7、Direction≥360、Latitude>90000000、Longitude>180000000、RegistrationResult>4——**以上 9 条选定 planner 锚**今日零负例；另有手机号非 12 位/非数字、LicenseColor 非法枚举等 ValidateConfig 分支，同样未建立独立负例。层校验器（layer validator）双段校验的第一段（层内键形/枚举）亦无独立负例（N-1 notes 口径：planner 锚为"jt808 layer validator 双段校验的第二段"）。

## 5. 覆盖与对账

### 5.1 三源回指行

JT/T 808-2019（设计 §2A–§8A 引用面）+ D-JT808-1（合集设计 Part A）+ **16 例在案已钉 frames/包数**（机读实测形状，见 §1/§2）→ 16 ID（本契约 §2）。第三源"已确认现网行为"当前 = **形状级**（ID/顺序/顶层键形/expect 键形/包数/帧 hex 全部机读核对）；**pcap 复跑与 NIC 实证今日不声称**（P5 重跑后刷新）。

**16 ID 逐项回指（设计 §）**：#1←§6A/§7A.11；#2←§3A.1/§3A.4；#3←§6A.2/§5A M-05；#4←§4A.1；#5←§4A.3/§5A H-05/§3A.4；#6←§3A.2/§11A.2；#7←§4A.9；#8←§4A.9/§7A.8；#9←§4A.6；#10←§3A.2/§7A.12(e)；#11–#14←§5A.1；#15←§4A.1/§4A.2/§7A.9；#16←**as-built 增量（设计未列，G-JT808-1）**。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **合集设计 Part A（D-JT808-1）公开语义 + 仓库落码反推 + 16 例存量机读审计**，**非纯规范反推**（JT/T 808-2019 逐条条款号未全部标注到行 → G-JT808-6）。
- **对账两行（逐表重数，机读复算，不做跨表二次加总）**：设计计划面要求逻辑点 = **§8A 表面 A-01…A-59，实际 67 行**（58 个平号 + 9 个字母变体行；设计文末自述"65 条"与表行数不符，登记 **G-JT808-7**）；存量已落 = **16 例**（A 系重排子集 + F4 增量 1 例）；**未落 51 行**（A′ 立项，§6.2）。**16 ≠ 67，缺口如实登记**；粒度：表中每行计 1，F4/G-JT808-N 不折进设计表计数。**反查全绿 ≠ 覆盖全**。
- **门3 抽查候选**：最复杂用例 = **#3 `jt808_t3_dual_sn_autobind`**（4 帧钉：双 SN 空间并存 × 4 条自动绑定 × 下行 TLV/位置体/文本体三族）；建议门3 抽 #3 + #10（分包规范序 + 附加转义）。

### 5.3 T-编号与 id 对照

见 §2 表（16/16 一一对应，T-1…T-16）。**与 A 系映射要点**：#1≈A-01+A-13（序贯缩量）、#2≈A-26/A-50（校验范围含体）、#3≈A-14/A-15+A-54/A-55（双 SN 独立 + 自动绑定）、#4≈A-01+A-04、#5≈A-11+A-23/A-24+A-43、#6≈A-34+A-37、#7≈A-19+A-16、#8≈A-21、#9≈A-17（全 17 字段）、#10≈A-28a+A-51、#11≈A-31、#12≈A-07、#13≈A-33、#14≈A-40、#15≈A-48（result=2 单值）+ A-39 身份面、#16=**A 系外增量**。映射为语义近似（存量 T 系为独立编排，非 A 系机械投影）。

### 5.4 设计未覆盖、实现已含（as-built 诚实登记）

| 项 | 现状 | 登记 |
|---|---|---|
| 0x0002 终端心跳 | 设计 §8A A 系清单**无 0x0002 用例行**；实现 `emitProcedure` ProcHeartbeat + #16 已编排钉帧（JT/T 808 §7.2 语义） | **G-JT808-1**（as-built 增量，依据 = 实现与在案帧，不虚构设计依据） |
| `platform_initial_sn` 层键 | 设计 §6A.2 仅描述 platformMsgSN 状态变量语义（PlatformInitialSN=0 缺省）；层键 `platform_initial_sn` 显式配置面为落码增量（#3 用例驱动） | **G-JT808-2** |
| 0x8103 规范体形（总数前导+DWORD ID） | 设计 §4A.9 写 "ParamId(1)"（1 字节 ID）；实现/用例实测为**参数总数 BYTE 前导 + 参数ID DWORD**（F2 勘误钉）——**设计与落码不一致，以机读帧为准** | **G-JT808-3**（P4 修设计 §4A.9 或修码，二选一，不得两头悬置） |
| 分包封装项偏移序 | 设计 §3A.2/§7A.12(e) 只述"共享 SN+独立校验"；总包数@+12/序号@+14 的**字段序**为落码钉值（F1 勘误） | **G-JT808-4** |
| `getByteSlice` 原文语义（param value 字符串=原文字节非 hex） | 设计无此口径；#7 用例双形钉 | **G-JT808-5** |
| 设计 §8A 自述计数与表行数 | 设计文末写“JT808 用例数：65 条”，但 §8A 表实际为 67 行（A-01…A-59 含 9 个字母变体行）；本文按逐行重数，不把 65 当作机器契约 | **G-JT808-7** |
| （编位保留）JT809 族 0x1005/0x1006/0x1008 | **非 JT808 面**——三 MsgId 属 **jt809**（主链路连接保持/应答、主链路关闭通知，`trafficgen/internal/protocol/jt809/types.go:49-52`），合集设计 Part B 未描述、JT809 cases 已编排；**本文件不为其设立 JT808 缺口**（跨协议引用见 jt809 文档轨） | 归属 JT809 车道，不占本协议缺口号 |

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | **适用**——单 TCP 会话内多消息序贯（#1 四消息、#3 四消息、#7 三消息） | **已覆**（#1/#3/#7；多轮"应答绑定"由 #1/#3 自动绑定面覆盖） |
| ② | 非正常结束 | **部分适用**——注册失败 result≠0 → 0x8100 无鉴权码后终止（#15 覆盖 wire 面）；"拒绝后立即断开"的状态机行为（§6A.1 registered_await→terminated）无独立用例 | **#15 已覆 wire 面**；状态机行为 A′ |
| ③ | 长保活 | **适用**——0x0002 心跳为保活核心型（#16 已编排）；周期多次心跳（HeartbeatCount 语义属 jtt905，JT808 为 procedures 显式编排）与 30s 超时重发无用例 | **#16 已覆单拍**；重复心跳/超时重发 A′ |

### 6.2 A′/B′ 两分类表

**A′（P4/P5 接线候选，设计 §8A 未落存量面）**：

| 类 | 内容 | 落点 |
|---|---|---|
| validate 面 | Version 非法 / EncryptFlag>1 / ManufacturerId、TerminalModel、TerminalId 超长 / Direction≥360 / Latitude、Longitude 越界 / RegistrationResult>4 等选定锚零负例（另含手机号非数字、LicenseColor 非法枚举等分支，未逐一单列） | 设计 §5A.1（本契约 §4） |
| SN 回绕面 | InitialSN=65534 连续 4 条 SN=65534/65535/0/1（A-27） | 设计 §7A.12(b) |
| 多终端面 | N 终端独立 4-tuple/独立 MsgSN/Phone 互异（A-29/A-30）——存量全 16 例单流，`strategy_fc` 零用例 | 设计 §7A.11 |
| 平台命令面 | 0x8103→0x0001、0x8104→0x0107、0x8201→0x0201 的**配回应答序**已有（#3/#7），但 0x8300→0x0001 配对、30s 超时重发（A-42）零用例 | 设计 §7A.8/§6A.1 |
| 心跳面 | 0x0002 多拍 + 心跳与业务消息交织 | 设计 §6A（G-JT808-1 后续） |
| G-JT808-3 面 | 0x8103 体形设计/代码二选一对齐后回归钉 | 本契约 §5.4 |
| 字段断言面 | `fields` 仅 TCP 面 13 条；可为 `tcp.seq/ack` 递增、dst_port 缺省 7611 补字段断言 | 本契约 §1 |
| NIC/复跑面 | 16 例 pcap 复跑留档 + NIC 路径用例（今日零证据） | 本契约 §1 |

**B′（框架面）**：① `terminal_type` 顶层键零消费（#15 登记键但无 wire 面，读 `property_data.*` 路径）——键存废 P4 裁定；② 嵌套 procedures 键 V9 区间门不下探（#14 notes 口径，锚落 planner 是**准拦截点**但框架层存在盲扫面）；③ 2013 版本位同机制不单列（#6 notes 已注记，可收编 1 例）。

### 6.3 3.14 豁免边界审计

**长连接载体（TCP）→ `sessions[]` 豁免不适用**：JT808 单会话 = 单 TCP 流全生命周期（握手→消息→挥手），无多会话编排需求；多终端并发由多 flow 承载（A′ 多终端面）。**单包多载荷 = 不适用**（JT808 一帧一报文，协议分包 #10 是"一逻辑消息多帧"，非单帧多载荷）。

## 7. 实现后执行建议

1. **P4 顺序**：①先裁 G-JT808-3（0x8103 体形设计/码对齐）；②补选定 validate 面负例，并另补手机号非数字、LicenseColor 非法枚举等分支；③补 SN 回绕 + 多终端（`strategy_fc`）例；④ B′① `terminal_type` 键存废裁定；⑤全量复跑。**本协议无 §1 迁移步骤**（16/16 顶层键纯 `{layers}`，零残留）。
2. **实测顺序**：先 #2（帧头字节 + XOR 校验含体，52B 整帧），再 #1（基线 10 帧序 + 双 SN 空间），再 #3（双 SN 100/200 + 4 绑定），再 #5（转义 7d02/7d01 + 校验先算后转义），最后 #10（分包规范序 + 附加转义）、#9（17 字段 100B 体）。
3. **进制与字节纪律（本协议高频错点）**：props = 版本位(×0x0400)|加密位(0x8000)|体长；BCD 手机号 big-endian 半字节；pad 三段规则（厂商/终端ID 0x00、型号 0x20、GBK 变长不补）；校验 = **头+体 XOR（含体，不含首尾 7e 与校验字节）**，且**先算校验后转义**（props 体长为转义前值）；分包项@+12/+14 与消息头相接、参与校验。
4. 二进制与 HEAD 同代确认（门2③）；门2② 全量（`CASE_PROTO=jt808` 全量不是增量）；门2④ 反查绿后进 P6。
5. 任何 JT/T 808-2019 条款号的具体引用须有规范原文证据（G-JT808-6 纪律）；as-built 增量只引实现与在案帧，**不得虚构设计依据**（G-JT808-1 纪律）。

## 8. 存量审计（16 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/jt808.json` **16 例**：12 正（`packet_count` 12/12：10/7/10/7/7/7/9/7/7/8/9/7，合计 95 帧，公式 3+N+3 逐例复算一致）+ 4 负；**全部 16 例 `spec_json` 顶层键 = `{layers}` 唯一键，非负例顶层残留 = 0**；层形 `[ip,jt808]` ×16；正例 `expect` 主断言 = `frames` ×12（hex 钉帧）+ `fields` ×2 例 13 条（TCP 面）；负例 `expect` = `{expect_error, error_contains, notes}` ×4，无 `packet_count`。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **G-JT808-3 设计/码不一致（最须先裁）**：设计 §4A.9 "ParamId(1)" vs 落码实测"总数前导 + DWORD ID"（#7/#10 双例钉帧）——不得两头悬置。
2. **设计清单计数矛盾**：§8A 页脚自述 65 条，表逐行机读为 67 行，不能写成“A 系清单 59 条”。实际 67 行、存量 16 例的差额按逐行粒度另记为 G-JT808-7 相关缺口；本契约不将设计计数冒充存量覆盖。
3. **无 pcap/NIC 复跑实证可引用**：本文所有"实测/钉"字样均指**在案已钉值**（cases JSON 内 frames/notes 与既有审计），**非今日复跑**——P5 重跑后刷新证据链。
4. **`fields` 断言弱**：仅 2 例 13 条且全 TCP 面（`tcp.flags`/`tcp.dstport`），协议面全靠 frames hex——无 tshark 字段名依赖（jt808 无内置 dissector），但亦无字段级交叉验证。
5. **`strategy_fc` 零用例**：多流/多终端语义零覆盖（A′ 多终端面）。
6. **`terminal_type` 零消费**：#15 显式置 1 无 wire 面（B′①）。
7. **负例锚全落 planner**：4/4 ValidateConfig 锚，层校验器第一段（层内键形/枚举门）零独立负例。
8. **心跳/超时重发零重复拍**：#16 单拍，30s 重发语义（§6A.1）零用例（A′）。

### 8.3 逐条去向表（16 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `jt808_t1_baseline_assoc` | T1 | **保留** | 形状合规；可补 `tcp.seq/ack` 字段断言 |
| `jt808_t2_frame_header_bytes` | T2 | **保留** | 无 |
| `jt808_t3_dual_sn_autobind` | T3 | **保留** | 无（门3 抽查候选） |
| `jt808_t4_register_body_fields` | T4 | **保留** | 无 |
| `jt808_t5_location_bitmerge_escape` | T5 | **保留** | 无 |
| `jt808_t6_version2011_encrypt_bit` | T6 | **保留** | 可收编 2013 版本位对照例（B′③） |
| `jt808_t7_down_tlv_trio` | T7 | **保留** | G-JT808-3 裁定后复核 props/体长钉 |
| `jt808_t8_text_down_gbk` | T8 | **保留** | 无 |
| `jt808_t9_property_response` | T9 | **保留** | 无 |
| `jt808_t10_fragmentation` | T10 | **保留** | 无（门3 抽查候选） |
| `jt808_t11_neg_phone_11digits` | T11 | **保留** | 无 pcap 留档，P4/P5 补跑 |
| `jt808_t12_neg_auth_missing_code` | T12 | **保留** | 同上 |
| `jt808_t13_neg_color0_plate` | T13 | **保留** | 同上 |
| `jt808_t14_neg_ackflag_99` | T14 | **保留** | 同上；B′② 框架盲扫面登记 |
| `jt808_t15_identity_composite` | T15 | **保留** | B′① `terminal_type` 键存废裁定 |
| `jt808_t16_heartbeat` | T16 | **保留** | G-JT808-1 登记；可补多拍心跳 |

**统计（机读复算）**：**保留 16 + 改写 0 + 作废 0 = 16**。存量非负例 12/12 顶层零残留（纯层链形）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['jt808']) == 16` 且 ID 集合 = §2 十六项，顺序一致 | 本契约 §2 |
| 2 | 16 例 `spec_json` 顶层键 == `{layers}`（零游离键，今日已成立） | 本契约 §1 |
| 3 | 层形恒 `[ip,jt808]`（16/16） | 本契约 §1 |
| 4 | 12 正例 `packet_count` == `3 + 消息帧数 + 3`（消息帧数由 procedures/分包推出；合计 95） | 本契约 §1 |
| 5 | 4 负例 `expect` 键集合 == `{expect_error, error_contains, notes}` | 本契约 §4 |
| 6 | 负例 `error_contains` ∈ 代码锚词集 `{"must be 12 digits", "AuthCode is empty", "LicenseColor=0 but LicensePlate non-empty", "ACKFlag 99 invalid"}` | 本契约 §4 |
| 7 | 每正例至少一条 `frames` hex 断言（12/12 成立） | 本契约 §3 |
| 8 | 正例 `has_payload` 缺席当且仅当短帧口径（#6/#7/#8/#16 四例） | 本契约 §1 |

## 10. 修订记录

- `v1.0.0`（2026-09-29）：P-PIPE 文档轨 #29 jt808 as-built。16 例存量逐条机读审计（§8.1：包数 12/12 公式一致、合计 95、非负例顶层零残留、4 负例形状干净、正例 frames ×12）；§5.4 as-built 诚实登记（**G-JT808-1…G-JT808-7**，含设计 §4A.9 与落码体形不一致的 G-JT808-3、设计 §8A 文末计数与表行数不一致的 G-JT808-7；JT809 族 0x1005/0x1006/0x1008 明确归属 jt809 车道不占本协议缺口号）；§5 对账（设计表实际 67 行 vs 存量 16 例，51 行 A′ 如实登记）；§6 P3 固定动作（三项 ①③已覆②部分覆；A′ 8 类；B′ 3 项）；§7 执行建议；§8 存量审计（保留 16 + 改写 0 + 作废 0）；§9 覆盖反查门建议断言行 8 条。**本文不声称 pcap 复跑/NIC 证据，P5 重跑后刷新**。自审 2 轮，末轮干净。
- `v1.0.1`（2026-09-29）：隔离复审修正 4 处：校验顺序改为原始未转义字节先 XOR 后转义；将 9 条校验锚改称选定锚并补记手机号非数字与 LicenseColor 非法枚举分支未覆盖；字段断言覆盖改为 2 例/13 条；`has_payload` 缺席短帧改为 #6/#7/#8/#16 四例。

# #118 rtmp（Adobe RTMP）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3，as-built 型）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/118-rtmp-design.md` v1.0.0（D-RTMP-1）
> 旧基线：**无**（本协议无旧稿，设计 §0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/rtmp.json`（**16/16 ID 与本版 §2 一致，顺序一致，已机读实测**；`spec_json` 顶层键已是纯层链形，零残留）
> 白话一句：**十六条检查：十三条看正常收发（握手分段、chunk 头字节、协议控制四消息、推拉两模式、自定义 app/流名、音视频 chunk、双向、两种载荷形），三条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **16 个唯一语义 ID：13 正 + 3 负**（负例 N-1/N-2/N-3）。派生规则：设计 §3 每个消息/字段条款、§5 每个事务/自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：16/16 例顶层键 = `{expect,id,proto,spec_json,summary}`；`spec_json` 顶层键 = **`{layers}` ×16（唯一键，零游离键、零顶层 `rtmp` 子映射）**——本协议存量**顶层零残留**，无 §1 迁移工作量（设计 §12.1）；层形 `[ip,rtmp]` ×16（**无 `tcp` 层**——rtmp 是 raw 自驱终结层，设计 §11.4）；3 负例 `expect` 键集合 = `{expect_error,error_contains,notes}`（**含 `notes`**，非严格两键，G-RTMP-4）。

**`packet_count` 覆盖现状（G-RTMP-4）**：**仅 4 例带 `packet_count`**（#1/#2/#3/#4，均 20）；其余 9 正例**无 `packet_count`**，只断 `has_handshake`+`terminates`（+ 部分 `fields`）。→ A′ 补 `packet_count = 20 + len(data)`。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`、`tcp.flags`、`tcp.len`、offset 54 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。**今日 16 例零 `nic_capture`**（G-RTMP-12）。

**TSHARK 基线（本机 3.6.14 实测）**：RTMP dissector 的**协议名是 `RTMPT`、字段前缀是 `rtmpt.`**（`tshark -G protocols` → `Real Time Messaging Protocol  RTMPT  rtmpt`；`tshark -G decodes` → `tcp.port 1935 rtmpt`；`tshark -G fields` → `rtmpt.*` **38 字段**）。**警告**：同机另有 7 个 `rtmp.*` 字段，属**另一个协议**（Routing Table Maintenance Protocol，AppleTalk），断言时写错前缀会取到无关字段（设计 §0 #2）。可用字段通道：① `rtmpt.handshake.c0/s0/c1/s1/c2/s2`；② `rtmpt.header.format/csid/timestamp/bodysize/typeid/streamid`；③ `rtmpt.scm.chunksize/csid/seq/was/limittype`；④ `rtmpt.ucm.eventtype`；⑤ `rtmpt.function.call/response`；⑥ `rtmpt.audio.*`/`rtmpt.video.*`；⑦ frames 原始 hex（offset 54/74）。

**`rtmpt.*` 实测样例（本车道探针，2026-09-29）**：帧 11 `header.format=0`/`header.csid=3`/`header.bodysize=65`/`header.typeid=0x14`/`header.streamid=0`；帧 12 `header.typeid=0x05,0x06,0x04,0x01,0x14`（**五连五类型**）、`scm.chunksize=4096`、`scm.was=2500000`、`scm.limittype`（Dynamic）；帧 17 `function.call=play`；帧 18 `header.typeid=0x08`、`audio.*`。

**断言基线**：今日 16 例只用 `packet_count`（4 例）+ `has_handshake` + `terminates` + `has_payload`（1 例）+ `tcp.dstport` + `tcp.flags` + `tcp.len` + frames；**5 条 frame 断言 + 17 条 field 断言已逐条对实测 pcap 复核（全 OK，§5.4）**。`rtmpt.*` field 断言**今日零使用** → A′ 立项（G-RTMP-1）。

**动态字段禁止硬编码**：握手随机段（C1/S1/S2/C2 的 time 与 1528B 随机）**不可断言取值**——用例只钉**分段形状**（`tcp.len`）与**定长头字节**；序列号/窗口大小由生成器自建（`clientSeq=randUint32()` 或 `spec.TCP.InitialSeq`，链路径下 `spec.TCP` 恒 nil → 随机）。

**包数约定（实测公式，设计 §5.2）**：`packet_count = 20 + N`（N = `rtmp.data` 数组长度）。推导：3（TCP 握手）+ 7（RTMP 握手 2+3+2 段）+ 7（命令面帧 11-17）+ 3（挥手）= **20**；每条数据面 chunk 恰 +1 段。**16/16 与实测 pcap 逐例一致**（§5.4）。

**保活/重试/RST 口径**：协议层**无 PING 类保活**（spec 的 Ping/Pong User Control 6/7 未实现，设计 §5.3）；无重试/重连概念；RST 为框架 tcp 层能力，本协议层不新增断言（A′ 补例 G-RTMP-7 除外）；正例恒 FIN 优雅终止（3 帧挥手，末帧纯 ACK）。

## 2. 原子用例索引（16 ID = 13 正 + 3 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | 依据链 | packet_count（实测） |
|---:|---|---|---|---|---:|
| 1 | `rtmp_play_session_full` | 正 | §5.2：play 全会话基线（缺省 app/流名） | Adobe RTMP Spec §5.2/§7.2.1 | 20 |
| 2 | `rtmp_handshake_segments` | 正 | §3.2/§8：握手三批按 MSS 分段（2/3/2 段） | Spec §5.2 | 20 |
| 3 | `rtmp_chunk_header_amf0_connect` | 正 | §3.3/§3.4/§3.7：chunk 头 12B + AMF0 connect 逐字节 | Spec §5.3.1/§7.2.1 | 20 |
| 4 | `rtmp_protocol_control_messages` | 正 | §3.6/§3.7：协议控制四消息 + createStream/play 帧字节 | Spec §7.1/§7.2.2-3 | 20 |
| 5 | `rtmp_publish_mode` | 正 | §5.1：`command=publish` 分支 | Spec §7.2.3 | 20 |
| 6 | `rtmp_stream_name_custom` | 正 | §3.7：`stream_name` 自定义入 play 参数 | Spec §7.2.3 | 20 |
| 7 | `rtmp_app_tc_url_custom` | 正 | §3.7：`app`/`tc_url` 显式（覆盖自动构造分支） | Spec §7.2.1 | 20 |
| 8 | `rtmp_data_audio` | 正 | §3.8：msgType 8 + csid 4 | Spec §11.4 | 21 |
| 9 | `rtmp_data_video` | 正 | §3.8：msgType 9 + csid 6 | Spec §11.4 | 21 |
| 10 | `rtmp_data_bidirectional` | 正 | §3.8：up 音频 + down 视频（方向序） | Spec §11.4 | 22 |
| 11 | `rtmp_data_payload_b64` | 正 | §3.8：`payload_b64` 解码透传 | 设计 §3.8 | 21 |
| 12 | `rtmp_composite_publish_multi_data` | 正 | §5.2：publish + 自定义 app/流名 + 双 chunk 复合 | 设计 §5.2 | 22 |
| 13 | `rtmp_neg_app_too_long` | 负 | §7：N-1 | 设计 §7 | —（实测 0 帧） |
| 14 | `rtmp_neg_command_invalid` | 负 | §7：N-2 | 设计 §7 | —（实测 0 帧） |
| 15 | `rtmp_neg_msg_type_invalid` | 负 | §7：N-3 | 设计 §7 | —（实测 0 帧） |
| 16 | `rtmp_data_payload_raw` | 正 | §3.8：`payload` 原文字节透传（非 hex） | 设计 §3.8 | 21 |

**T-编号对照**：T-1 ≡ #1；T-2 ≡ #2；T-3 ≡ #3；T-4 ≡ #4；T-5 ≡ #5；T-6 ≡ #6；T-7 ≡ #7；T-8 ≡ #8；T-9 ≡ #9；T-10 ≡ #10；T-11 ≡ #11；T-12 ≡ #12；T-13 ≡ #13；T-14 ≡ #14；T-15 ≡ #15；T-16 ≡ #16（T-编号沿用 `cases` 的 `summary` 前缀，与 JSON 顺序一致——**注意 JSON 中 #16 排在最后，T-16 编号与位置一致**）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `has_handshake` + `terminates`；帧位由 §1 公式与实测 pcap 双向确认。**统一 fixture**：`layers[0].ip = {src:"10.0.0.1", dst:"20.0.0.1"}`；**16/16 例均不写 `dst_port`**（缺省落 1935）；worker 保底 `src_port=12345`。

### 3.1 `rtmp_play_session_full`（20，T-1）

`rtmp: {}`（全缺省：app=`live`、tcUrl 自动构造、command=`play`、stream_name=`stream`）。

- `has_handshake=true`、`terminates=true`、`has_payload=true`、`packet_count=20`（N=0）。
- `tcp.dstport=1935`（帧 1）。
- `tcp.flags`：帧 1 = `0x002`（SYN）、帧 2 = `0x012`（SYN-ACK）、帧 18 = `0x011`（FIN-ACK）。**按位比较**（`verify.go:115-117`）：断言 `0x002` vs 实测 `0x0002` 判过。
- `tcp.len`：帧 4 = `1460`、帧 5 = `77`、帧 8 = `153`、帧 11 = `77`（connect chunk）。
- **本例是唯一带 `has_payload` 的正例**：通用判据 `frame.len > 80`（`verify.go:366`，rtmp 无协议专属分支）——握手段 1460B 帧必然满足。
- **`notes` 文案核对**：存量 notes 称"20 帧=握手3+C0C1 2段+S0S1S2 3段+C2 2段+connect 1+服务端五连 1+客户端winack 1+createStream 1+setBufferLen 1+_result 1+play 1+挥手4"——**末项"挥手4"与实现不符**（实现 3 帧挥手，设计 §5.2）；且 notes 称 C2 段为"1460/76"（与实测一致 ✓）。→ G-RTMP-4。

### 3.2 `rtmp_handshake_segments`（20，T-2）

`rtmp: {}`。

- `packet_count=20`；`tcp.len` 逐段：帧 4=`1460`、5=`77`（C0C1 **1537B** → 2 段）；帧 6=`1460`、7=`1460`、8=`153`（S0S1S2 **3073B** → 3 段）；帧 9=`1460`、10=`76`（C2 **1536B** → 2 段）。
- **分段形状证据**：1537 = 1460+77 ✓；3073 = 1460+1460+153 ✓；1536 = 1460+76 ✓。**MSS 恒 1460**（链路径下 `spec.TCP` 为 nil，`mss` 取 `DefaultMSS`，设计 §11.7）。
- **随机值不断言**：C1/S1 的 time 与 1528B 随机段取值**不可断言**（crypto/rand），本例只钉分段形状 ✓。

### 3.3 `rtmp_chunk_header_amf0_connect`（20，T-3）

`rtmp: {}`。

- **帧 11 @offset 54**（24 字节）：`03 00 00 00 00 00 41 14 00 00 00 00 02 00 07 63 6f 6e 6e 65 63 74`——逐字段：`03` = fmt0+csid3；`00 00 00` = timestamp 0；`00 00 41` = **length 65**（= 77 − 12）；`14` = msgType 20；`00 00 00 00` = **streamID 小端 0**；`02 00 07` = AMF0 String 长 7；`connect` 7 字节。**24 = 12（chunk 头）+ 12（AMF0 头+命令名）** ✓
- **帧 11 @offset 76**（9 字节）：`00 3f f0 00 00 00 00 00 00` = AMF0 `Number(1.0)`（大端 IEEE-754）✓
- `tcp.dstport=1935`（帧 4）；`packet_count=20`。
- **本例钉死 chunk 头 12 字节的全部字段**（fmt/csid/ts/len/type/streamID），是 §3.3 的直接证据。

### 3.4 `rtmp_protocol_control_messages`（20，T-4）

`rtmp: {}`。

- **帧 12 @54**（15 字节）：`02 00 00 00 00 00 04 05 00 00 00 00 00 26 25 a0`——csid 2、len 4、**type 5（Window Ack Size）**、payload `00 26 25 a0` = **2500000**（大端）✓。**该帧 194B 内含 5 个 chunk**（设计 §3.7 表：type 5/6/4/1/20），本 frames 断言只钉第 1 个。
- **帧 14 @54**（28 字节）：`03 00 00 00 00 00 19 14 00 00 00 00 02 00 0c 63 72 65 61 74 65 53 74 72 65 61 6d`——csid 3、len 25、type 20、streamID 0、`String("createStream")` ✓
- **帧 17 @54**（22 字节）：`03 00 00 00 00 00 1a 14 01 00 00 00 02 00 04 70 6c 61 79 00`——csid 3、len 26、type 20、**streamID `01 00 00 00` = 小端 1**（createStream 之后的流号）、`String("play")` + `Number` 起始 `00` ✓
- `tcp.dstport=1935`（帧 4）；`packet_count=20`。
- **补充可断言（tshark 实测，A′ 可收编）**：`rtmpt.header.typeid` 在帧 12 为 `0x05,0x06,0x04,0x01,0x14`（五连五类型）；`rtmpt.scm.chunksize=4096`；`rtmpt.scm.was=2500000`；`rtmpt.function.call=play`（帧 17）。
- **结构边界（诚实声明）**：本例钉的是"协议控制四消息存在 + 三段帧字节"，**Set Peer Bandwidth 的 limit type=2(Dynamic)、Stream Begin 事件类型=0、Set Chunk Size=4096 的取值断言今日无** → A′ 立项（G-RTMP-1）。

### 3.5 `rtmp_publish_mode`（20，T-5）

`rtmp: {command:"publish"}`。

- `has_handshake=true`、`terminates=true`。**无 `packet_count`**（G-RTMP-4）→ A′ 补 20。
- **断言缺口（诚实声明）**：本例**今日不断言 publish 字节**——只断握手与终止，与 #1 的断言集**无法区分**。→ A′ 必须补 frames（**帧 17 @54 = `03 00 00 00 00 00 24 14 01 00 00 00 02 00 07 70 75 62 6c 69 73 68`**——len `00 00 24` = 36、`String("publish")`；该帧 `tcp.len=48` = 12 + 36，实测 `function.call=publish`）。**这是本套件最弱的一例**（G-RTMP-4）。

### 3.6 `rtmp_stream_name_custom`（20，T-6）

`rtmp: {stream_name:"movie1"}`。

- `has_handshake=true`、`terminates=true`。**无 `packet_count`、无 frames**（G-RTMP-4）。
- **断言缺口**：`movie1` 字节入 AMF0 串的位置**今日不断言** → A′ 补 frames（**帧 17 @86 = `02 00 06 6d 6f 76 69 65 31`**，即 `String("movie1")`；实测帧 17 尾部 `… 00 06 6d 6f 76 69 65 31`）。

### 3.7 `rtmp_app_tc_url_custom`（20，T-7）

`rtmp: {app:"live2", tc_url:"rtmp://20.0.0.1:1935/live2"}`。

- `has_handshake=true`、`terminates=true`。**无 `packet_count`、无 frames**（G-RTMP-4）。
- **覆盖分支**：`tc_url` 显式值优先于自动构造（`rtmp.go:193-196`）；`app="live2"` 使 connect 命令对象属性变为 `String("live2")`。
- **断言缺口**：命令对象属性字节今日不断言 → A′ 补 frames（**帧 11 @82 = `03 00 03 61 70 70 02 00 05 6c 69 76 65 32 00 05 74 63 55 72 6c 02 00 1a 72 74 6d 70 3a 2f 2f 32 30 2e 30 2e 30 2e 31 3a 31 39 33 35 2f 6c 69 76 65 32`** = 对象头 + `app="live2"` + `tcUrl="rtmp://20.0.0.1:1935/live2"`（26 字节串）；该帧 `tcp.len=84` = 12 + 72 载荷）。

### 3.8 `rtmp_data_audio`（21，T-8）

`rtmp: {data:[{direction:"up", msg_type:8, chunk_stream_id:4}]}`。

- `has_handshake=true`、`terminates=true`。**无 `packet_count`**（G-RTMP-4）→ A′ 补 **21**（N=1）。
- **帧位实测**：帧 18 = 数据 chunk（`tcp.len=112` = 12 头 + 100 payload，**头字节 `04 00 00 00 00 00 64 08 01 00 00 00`**：csid 4、len 0x64=100、type 8、streamID 小端 1；PSH-ACK 上行）；帧 19-21 = 挥手 3 帧。
- **payload 缺省（**注意存量 notes 错误**）**：notes 称"payload 缺省 100B **随机**"，实现是 **100 字节全零**（`rtmp.go:385` `make([]byte, 100)`，无 rand 调用；**实测该帧 100 字节 payload 的唯一字节值 = `00`**）→ G-RTMP-4（P4 必改文案）。
- **补充可断言（实测）**：`rtmpt.header.typeid=0x08`、`rtmpt.header.csid=4`、`rtmpt.audio.*` 存在。

### 3.9 `rtmp_data_video`（21，T-9）

`rtmp: {data:[{direction:"down", msg_type:9, chunk_stream_id:6}]}`。

- `has_handshake=true`、`terminates=true`。**无 `packet_count`** → A′ 补 **21**。
- **帧位实测**：帧 18 = 数据 chunk（`tcp.len=112`，**下行** PSH-ACK；头字节 `06 00 00 00 00 00 64 09 01 00 00 00` = csid 6 / len 100 / type 9 / streamID 1）；帧 19-21 = 挥手。
- **补充可断言（实测）**：`rtmpt.header.typeid=0x09`、`rtmpt.header.csid=6`。

### 3.10 `rtmp_data_bidirectional`（22，T-10）

`rtmp: {data:[{up,8,csid4}, {down,9,csid6}]}`。

- `has_handshake=true`、`terminates=true`。**无 `packet_count`** → A′ 补 **22**（N=2）。
- **帧位实测**：帧 18 = up 音频 chunk（`tcp.len=112`，`ip.src=10.0.0.1`）、帧 19 = down 视频 chunk（`tcp.len=112`，**`ip.src=20.0.0.1`**）、帧 20-22 = 挥手 3 帧。
- **方向序证据**：两 chunk 按 `data` 数组序**顺序**产出（非交错），up 在前 down 在后 ✓（设计 §3.8）。**方向可直接断言 `ip.src`**（实测帧 18 = `10.0.0.1`、帧 19 = `20.0.0.1`）→ A′ 收编（G-RTMP-4）。

### 3.11 `rtmp_data_payload_b64`（21，T-11）

`rtmp: {data:[{up,8,csid4, payload_b64:"cnRtcC1kYXRh"}]}`。

- `has_handshake=true`、`terminates=true`。**无 `packet_count`** → A′ 补 **21**。
- **载荷证据（可断言）**：`cnRtcC1kYXRh` 解码 = `rtmp-data`（**9 字节 ASCII**）→ 帧 18 `tcp.len = 12 + 9 = 21`（**实测 21 ✓**，头字节 `04 00 00 00 00 00 09 08 01 00 00 00` + payload `72 74 6d 70 2d 64 61 74 61`）。**今日不断言** → A′ 补 frames（@66 = `72 74 6d 70 2d 64 61 74 61`）。
- **双形 parse 面**：`payload_b64` 优先于 `payload`（`strategy_convert.go:5371-5377`）；**非法 base64 静默丢弃** → G-RTMP-8。

### 3.12 `rtmp_composite_publish_multi_data`（22，T-12）

`rtmp: {command:"publish", app:"stream1", stream_name:"cam1", data:[{up,8,csid4,payload_b64:"YXVkaW8w"}, {up,9,csid6,payload_b64:"dmlkZW8x"}]}`。

- `has_handshake=true`、`terminates=true`。**无 `packet_count`** → A′ 补 **22**（N=2）。
- **四类交织**（本套件最复杂例）：① `command=publish` 分支；② `app="stream1"` 入 connect 对象；③ `stream_name="cam1"` 入 publish 参数；④ 两条数据 chunk（audio+video，**均为 up**）。
- **载荷证据（可断言，实测）**：`YXVkaW8w` = `audio0`（6B）→ 帧 18 `tcp.len=18` + payload `61 75 64 69 6f 30`；`dmlkZW8x` = `video1`（6B）→ 帧 19 `tcp.len=18` + payload `76 69 64 65 6f 31`。**两帧 `ip.src` 均为 `10.0.0.1`**（双 up ✓）。命令面帧 17 `tcp.len=46`（publish，`len=0x22`=34）。
- **门3 抽查候选**：本例 + #4（三帧字节锚）+ #10（双向）。

### 3.13 `rtmp_data_payload_raw`（21，T-16）

`rtmp: {data:[{up,8,csid4, payload:"raw-frame"}]}`。

- `has_handshake=true`、`terminates=true`。**无 `packet_count`** → A′ 补 **21**。
- **载荷证据（可断言，实测）**：`"raw-frame"` **按原文字节**（9 字节，**不是 hex 串**）→ 帧 18 `tcp.len = 12 + 9 = 21`（**实测 21 ✓**）+ payload `72 61 77 2d 66 72 61 6d 65`。**pppoe cookie 同款陷阱**：`getByteSlice` 的字符串语义是原文字节；若误按 hex 解析会得到 4 字节或报错。**今日不断言** → A′ 补 frames（@66 = `72 61 77 2d 66 72 61 6d 65`）。
- **与 #11 的对照价值**：两例 `tcp.len` 同为 21、payload 字节不同（`rtmp-data` vs `raw-frame`），**是"b64 解码"与"原文透传"两种语义的直接对照证据**。

**正例总则**：缺省值、自定义 app/流名、推拉两模式、音视频两类型、双向、两种载荷形均为正例形态，只有配置错误进入负例。

## 4. 负例契约

负例必须在 validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功（**实测三例 `.neg.pcap` 均 0 帧**，文件名 `<id>.neg.pcap`）。锚词与设计 §7 表一一对应、同序（代码逐字，`rtmp.go` 实测行号）：

| ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（`rtmp.go` 逐字） | 代码行 |
|---|---|---|---|---|
| `rtmp_neg_app_too_long` | `app` = 256 个 `x` | `App exceeds` | `rtmp: App exceeds 255 bytes`（`%d`=`MaxAppLen`=255） | `:143` |
| `rtmp_neg_command_invalid` | `command="pause"` | `invalid Command` | `rtmp: invalid Command "pause" (supported: play, publish)` | `:149` |
| `rtmp_neg_msg_type_invalid` | `data[0] = {direction:"up", msg_type:5}` | `MsgType` | `rtmp: Data[0].MsgType 5 invalid (supported: 8=audio, 9=video)` | `:163` |

**锚词口径**：`error_contains` 是**子串**判定；三例均命中代码文案（前缀 `rtmp: `）。

**负例原子性**：每例单一故障注入，单次执行不混注 ✓（机读：三例 `spec_json` 各只注入一个故障字段；#13 只改 `app`、#14 只改 `command`、#15 只在 `data[0]` 改 `msg_type`）。

**expect 键形状注**：存量 3 负例 `expect` = `{expect_error, error_contains, notes}`（含 `notes`），与 92-moxa 范式的严格两键不同——P4 收窄时删 `notes`（G-RTMP-4）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：

| 分支 | 锚词 | 代码行 | 链路径可达性（本车道实测） |
|---|---|---|---|
| SrcIP 非法 | `rtmp: invalid SrcIP %q` | `:127` | **可达**（链路径 `ip.src` 注入 spec.SrcIP） |
| DstIP 非法 | `rtmp: invalid DstIP %q` | `:132` | **可达** |
| RTMPConfig 为 nil | `rtmp: RTMPConfig is required` | `:138` | **不可达**（translate 保底非 nil） |
| MSS 过小 | `rtmp: TCP.MSS %d too small (min 536)` | `:155` | **不可达**（链校验层先拒，锚词 `out of range [536,65535]`，G-RTMP-9） |

**未入用例的静默路径（缺陷候选，G-RTMP-8）**：`payload_b64` 非法 base64 → `decodeBase64` 失败**静默丢弃**（`strategy_convert.go:5371-5374` 无 else），payload 落缺省 100B，**任务成功、不报错**——**静默假成功**候选，P4 裁定拒绝或登记。

**不得误报的合法输入**：`command=""`（合法，走缺省 play）；`data` 空数组；`app`/`tc_url`/`stream_name` 缺省；`payload` 原文串（非 hex）；`payload` 与 `payload_b64` 并存（后者优先）。

## 5. 覆盖与对账

### 5.1 三源回指行

Adobe RTMP Specification 1.0（§5 握手 / §5.3 chunk / §7.1 协议控制 / §7.2 命令 / §11.4 消息类型，设计 §10）+ D-RTMP-1（设计 §11）+ tshark 3.6.14 `rtmpt.*` 字段表与 **16 例实测 pcap**（`/tmp/mcp-pcaps/rtmp/`，mtime 2026-09-27）→ 16 ID（本契约 §2）。第三源"已确认现网行为"当前 = **抓包级已到**（本仓引擎产出的 16 例 pcap 逐帧核对），但**真实 RTMP 服务器/开源实现的线字节未取到** → G-RTMP-11（按 §5.5 不写死进实现）。

**16 ID 逐项回指（§9.5 要求）**：#1←设计 §5.2；#2←§3.2/§8；#3←§3.3/§3.4/§3.7；#4←§3.6/§3.7；#5←§5.1；#6←§3.7；#7←§3.7；#8←§3.8；#9←§3.8；#10←§3.8；#11←§3.8；#12←§5.2；#13←§7 N-1；#14←§7 N-2；#15←§7 N-3；#16←§3.8。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **Adobe RTMP Spec 1.0 公开语义 + 仓库落码反推 + tshark 3.6.14 字段与 pcap 实测**，**非纯规范反推**（spec 条款号未逐条核对 → G-RTMP-11）。
- **对账两行**：**要求逻辑点总数 = 95**（八项 8 行 + 矩阵 36 格 + 变体 36 行 + 商业映射 15 行）；**用例覆盖数 = 60**（八项已覆 3 + 矩阵已覆 24 + 变体已覆 25 + 商业已覆 8）；**不适用 = 8**（八项 1 + 矩阵 0 + 商业 7）；**开放立项 = 27**（八项 4 + 矩阵 A′ 12 + 变体立项 11，三类互无交集）。60 + 8 + 27 = 95 ✓
  **粒度声明**：行/格粒度每点 1 计；G-RTMP-1…G-RTMP-13 为条目附注，不折进 95。**反查全绿 ≠ 覆盖全**（§9.52 原文）。逐表重数见设计 §10.1（八项 8 = 覆 3 + 立项 4 + 不适用 1）/§10.2（36 格 = 覆 24 + A′ 12 + 不适用 0）/§10.3（36 行 = 覆 25 + 立项 11）/§10.4（15 行 = 覆 8 + 不适用 7）。
- **门3 抽查候选**：最复杂用例 = **#12 `rtmp_composite_publish_multi_data`**（22 帧：握手 3 + 握手段 7 + 命令 7 + **2 条数据 chunk** + 挥手 3；交织维度 = 命令模式(2)×app(2)×流名(2)×数据方向(2)×msgType(2)）；**建议门3 抽 #12 + #4**（#4 含三帧字节锚，补 chunk 头面）。

### 5.3 T-编号与 id 对照（设计 §9 全表摘要）

`rtmp_play_session_full` ≡ T-1；`rtmp_handshake_segments` ≡ T-2；`rtmp_chunk_header_amf0_connect` ≡ T-3；`rtmp_protocol_control_messages` ≡ T-4；`rtmp_publish_mode` ≡ T-5；`rtmp_stream_name_custom` ≡ T-6；`rtmp_app_tc_url_custom` ≡ T-7；`rtmp_data_audio` ≡ T-8；`rtmp_data_video` ≡ T-9；`rtmp_data_bidirectional` ≡ T-10；`rtmp_data_payload_b64` ≡ T-11；`rtmp_composite_publish_multi_data` ≡ T-12；`rtmp_neg_app_too_long` ≡ T-13；`rtmp_neg_command_invalid` ≡ T-14；`rtmp_neg_msg_type_invalid` ≡ T-15；`rtmp_data_payload_raw` ≡ T-16。

### 5.4 存量实测复核（本车道，2026-09-29）

- **包数**：`tshark -r /tmp/mcp-pcaps/rtmp/<id>.pcap | wc -l` 逐例计数——**16/16 与公式 `20+N` 一致**；三负例 `.neg.pcap` 均 **0 帧**。
- **frames**：**5 条断言逐条从 pcap 取 offset 处字节比对，5/5 通过**（#3 ×2、#4 ×3）。
- **fields**：**17 条断言逐条取 tshark 字段值比对，17/17 通过**——其中 `tcp.flags` 3 条为**按位比较**（断言 `0x002` vs 实测 `0x0002`，`verify.go:110-120`），机读比对须用同一按位口径。
- **malformed**：`rtmp_` 前缀在 `IsMalformedWhitelisted`（`verify.go:569`）有白名单——`Loop in AMF dissection`（tshark AMF 递归守卫对嵌套 `_result` 对象误报）。实测 `rtmp_data_audio.pcap` 有 **5 帧**该伪影（帧 11/12/14/16/17），**白名单已覆盖不判红**；tshark **仍正确解析出消息名**（`connect()`/`Window Acknowledgement Size 2500000|Set Peer Bandwidth 2500000,Dynamic|Stream Begin 0|Set Chunk Size 4096|_result()`/`createStream()`/`_result()`/`play()`），证明 AMF 编码合法。
- **pcap 来源声明**：本次复核用的是 `/tmp/mcp-pcaps/rtmp/`（**mtime 2026-09-27**，晚于代码末次提交 `9b4ef16` 2026-09-20），**与 tracked 结果产物 `docs/protocol-pcap-test/rtmp.md` 无关**（该产物表格里的 pcap 链接全部死链，G-RTMP-13）。本车道**未跑 MCP 套件**，上述复核是对已有 pcap 的**离线断言核对**，不等于"套件今日已复跑"。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接内：握手 3 批 + 命令 7 帧 + N 条数据 chunk（#10 两条、#12 两条） | 已覆 #1/#4/#10/#12 |
| ② | 非正常结束 | 正常 FIN 全正例（3 帧挥手，末帧纯 ACK）；**协议层无异常结束概念**；传输异常 = RST（框架 tcp 层能力） | 已覆（FIN 全正例）；RST **A′ 立项**（G-RTMP-7，本层零断言） |
| ③ | 长保活 | **协议层无心跳**（Ping/Pong 未实现）；无周期消息 | **不适用 + 缺口**（G-RTMP-2：保活面缺失；非"未覆盖"而是"协议面未实现"） |

无空项：① 有已覆例；② 有已覆例 + 1 条 A′ 立项；③ **显式不适用 + 缺口登记**（不硬凑用例）。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| field 断言面 | 收编 tshark **`rtmpt.*`** 字段（`handshake.*`/`header.format,csid,typeid,streamid,bodysize`/`scm.chunksize,was,limittype`/`ucm.eventtype`/`function.call`/`audio.*`/`video.*`）——今日零使用。**字段名必须写 `rtmpt.`**（`rtmp.*` 属另一协议） | G-RTMP-1 |
| packet_count 面 | 9 个正例补 `packet_count = 20 + len(data)` | G-RTMP-4 |
| frames 面 | #5（publish 帧 17）、#6（流名字节）、#7（app/tcUrl 对象字节）、#8/#9（数据 chunk 头）、#11/#16（载荷字节）、#12（两载荷字节）——**先跑后钉** | G-RTMP-4 |
| notes 修正面 | #1 "挥手4"→3；#8 "100B 随机"→全零；负例删 `notes` | G-RTMP-4 |
| 地址族面 | `rtmp_ipv6`（offset 74，**实测可达**） | G-RTMP-5 |
| 多流面 | `flow_control:{flows:3}`（四元组保底递增） | G-RTMP-6 |
| 拒绝分支面 | SrcIP/DstIP 非法（**链路径可达**）；顶层 `rtmp` 子映射判死（**今日已可建**，§12-P2） | G-RTMP-1 / G-RTMP-8 |
| 长度守卫面 | `stream_name`/`tc_url` 超长；`payload_b64` 非法（静默落缺省，**假成功候选**）；`chunk_stream_id > 63` | G-RTMP-8 |
| 端口面 | 缺省 1935 显式断言 + 非默认 9999（**实测可达**） | G-RTMP-10 |
| 缺省分支面 | `data[].direction` 缺省（→down）、`msg_type` 缺省（→按方向 8/9）、`csid` 缺省（→按 msgType 4/6）——**三项均实测可达** | 设计 §3.8 |
| NIC 面 | `nic_capture` 开关 | G-RTMP-12 |
| 非正常结束 | `tcp.rst` 补例 | ② 的 A′（G-RTMP-7） |

**B′（框架面）**：游离顶层键通用门（G-RTMP-1，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态（`layer_dyn.go` 无 `rtmp` 行，对象即拒）/ `tcp` 层键在 raw 链上的有效性口径（G-RTMP-9，跨协议框架面）。进设计 §14，「明确不解决 + 迁入计划」。

### 6.3 3.14 豁免边界审计

**有长连接载体（TCP）→ `sessions[]` 不豁免**，但**本协议 `sessions[]` 形态不适用**：rtmp 是 raw 自驱终结层，**自建 TCP 连接**，链上无 `tcp` 层，故 `sessions[]`（多会话数组）**本协议层不消费**；多流并发由策略级 `flow_control {"flows": N}` 承载（本版 16 例未用，存量单 flow）——**形态差异已声明**（G-RTMP-6）。**单包多载荷** = **不适用**（RTMP 每 chunk 一个消息；一个 TCP 段可含多 chunk（服务端五连 5 个），但那是**同向顺序拼接**，不是多载荷语义，如实声明）。

## 7. 实现后执行建议

1. **P4 顺序**：①先补 `packet_count`（9 例）+ 删负例 `notes` + 修 #1/#8 的 notes 文案（G-RTMP-4，**不改断言值，只补不删**）；②补 frames（#5/#6/#7/#8/#9/#11/#12/#16，**先跑后钉**）；③收编 `rtmpt.*` field 断言（G-RTMP-1）；④补 A′ 例（IPv6/多流/端口/缺省分支/RST/判死负例）；⑤裁定长度守卫（G-RTMP-8）与 `tcp` 层键口径（G-RTMP-9）；⑥全量复跑。**本协议无 §1 迁移步骤**（顶层零残留）。
2. **实测顺序**：先 #3（chunk 头 12B 锚 + AMF0 1.0）、再 #4（三帧字节 + 五连类型）、再 #2（分段形状 2/3/2）、再 #1（全会话 + flags），最后 #8-#12/#16（数据面 chunk 头与载荷）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=rtmp` 全量不是增量）；门2④ 反查绿后进 P6。
4. 任何 spec 条款号的具体引用须有规范原文证据（G-RTMP-11 纪律）；`rtmpt.*` 字段名须经 `tshark -G fields` 确认（**不得用 `rtmp.*`**）。

## 8. 存量审计（16 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/rtmp.json` **16 例**：13 正（4 例带 `packet_count`=20/20/20/20）+ 3 负（`expect` 键集合 `{expect_error,error_contains,notes}`，实测 pcap 均 **0 帧**）；16/16 顶层键仅 `{layers}`（**零残留**）；层形 `[ip,rtmp]` ×16；5 条 frame + 17 条 field 断言逐条对实测 pcap 复核（**全 OK**）；`rtmpt.*` field 断言零使用（G-RTMP-1）；`nic_capture` 零使用（G-RTMP-12）。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **9 个正例无 `packet_count`**：只断 `has_handshake`+`terminates`，**无法与"包数错"区分**（G-RTMP-4）。
2. **11 例断言集完全相同**（#2/#5/#6/#7/#8/#9/#10/#11/#12/#16 均为 `{has_handshake,terminates,notes}`，另 #1 仅多一个 `has_payload`）——**#5 publish 与 #1 play 在断言层面不可区分**，#6/#7 的自定义值与缺省值也不可区分（G-RTMP-4）。**这是本套件最大的覆盖缺口**（16 例中 11 例的断言集完全同形）。
3. **#1 `notes` 称"挥手4"**，实现是 3 帧挥手（设计 §5.2）——文案错（G-RTMP-4）。
4. **#8 `notes` 称 payload "100B 随机"**，实现是 **100B 全零**（`rtmp.go:385`）——文案错（G-RTMP-4）。
5. **3 负例 `expect` 含 `notes`**，与严格两键口径不符（G-RTMP-4）。
6. **`rtmpt.*` 字段面零使用**：tshark 有 38 字段（含 `handshake.*`/`header.*`/`scm.*`/`function.*`），今日 16 例全走 `tcp.*` + frames——**不是被迫，是未收编**（A′ G-RTMP-1）。
7. **`payload_b64` 非法静默丢弃**（`strategy_convert.go:5371-5374`）——**静默假成功候选**（G-RTMP-8）。
8. **`tcp` 层键在 rtmp 链上无效**（`mss`/`initial_seq`/`window_size`/`handshake`/`termination` 实测零影响）——配置面与生效面不一致（G-RTMP-9）。
9. **存量未覆盖**：IPv6、多流、缺省端口显式断言、非默认端口、`data` 缺省 direction/msg_type/csid、长度越界、RST、顶层判死负例**今日零用例**（A′ 补，设计 §13 十例）。
10. **结果文档 pcap 留档目录缺失（G-RTMP-13）**：`trafficgen/docs/protocol-pcap-test/rtmp.md`（tracked 产物）写 `Cases: 16 — pass 16, fail 0, error 0`，表格 16 条 `[pcap](rtmp/...)` 链接**全部死链**（`docs/protocol-pcap-test/rtmp/` 目录不存在，0 个 pcap）。**该文件末次提交 `9b4ef16`（2026-09-20）晚于判死提交 `0417be5`（2026-09-13）**，故**不属"早于判死提交的过期产物"**（与 opcua G-OPCUA-10 / thrift G-THRIFT-10 不同款）；登记的事实仅是"**留档目录缺失**"。归属**代码阶段**（P5 重跑套件时重新落盘）。本车道未跑该套件，故不以任何形式引用该产物。

### 8.3 逐条去向表（16 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `rtmp_play_session_full` | T1 | **保留** | 补 frames（connect 锚可合并）+ 修 notes"挥手4"→3 |
| `rtmp_handshake_segments` | T2 | **保留** | 已强（7 条 `tcp.len` 分段锚）；可补 `rtmpt.handshake.*` |
| `rtmp_chunk_header_amf0_connect` | T3 | **保留** | 已最强（2 条 frames）；可补 `rtmpt.header.*` |
| `rtmp_protocol_control_messages` | T4 | **保留** | 已强（3 条 frames）；可补五连 `scm.*`/`ucm.eventtype` |
| `rtmp_publish_mode` | T5 | **改写** | **必补 frames**（帧 17 publish 字节）——今日与 #1 不可区分 |
| `rtmp_stream_name_custom` | T6 | **改写** | **必补 frames**（`movie1` 字节入 play 参数） |
| `rtmp_app_tc_url_custom` | T7 | **改写** | **必补 frames**（connect 对象 `app`/`tcUrl` 字节） |
| `rtmp_data_audio` | T8 | **改写** | 补 `packet_count=21` + frames（chunk 头 + 100B 全零 payload）+ 修 notes |
| `rtmp_data_video` | T9 | **改写** | 补 `packet_count=21` + frames（csid 6 + type 9） |
| `rtmp_data_bidirectional` | T10 | **改写** | 补 `packet_count=22` + frames（两 chunk）+ 可补 `ip.src` 方向断言 |
| `rtmp_data_payload_b64` | T11 | **改写** | 补 `packet_count=21` + frames（`rtmp-data` 9B） |
| `rtmp_composite_publish_multi_data` | T12 | **改写** | 补 `packet_count=22` + frames（两载荷字节，**先跑后钉**） |
| `rtmp_neg_app_too_long` | T13 | **保留** | 删 `notes`（严格两键） |
| `rtmp_neg_command_invalid` | T14 | **保留** | 删 `notes` |
| `rtmp_neg_msg_type_invalid` | T15 | **保留** | 删 `notes` |
| `rtmp_data_payload_raw` | T16 | **改写** | 补 `packet_count=21` + frames（`raw-frame` 9B 原文） |

无"作废不注原因"：**0 作废**，**8 例改写**（补断言，不删断言），**8 例保留**（其中 3 例仅删 `notes`）+ A′ 新增 10 例。**本协议存量 16/16 顶层零残留**。

## 9. 覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

建议在主线程合入后，于 `coverage_gate.py` 的 rtmp 段登记下列断言（**每条均可从本契约与 cases JSON 直接机读，不需新造事实**）：

| # | 建议断言 | 依据 | 今日状态 |
|---:|---|---|---|
| 1 | `len(cases['rtmp']) == 16` 且 ID 集合 = §2 十六项，顺序一致 | 本契约 §2 | **绿** |
| 2 | 16/16 例 `spec_json` 顶层键 ⊆ `{layers}`（**本协议零游离键**） | 本契约 §1；设计 §12.1 | **绿** |
| 3 | 16/16 例层形 = `[ip,rtmp]`（**无 `tcp` 层**） | 设计 §11.4 | **绿** |
| 4 | 每正例 `packet_count`（若存在）== `20 + len(rtmp.data)` | 设计 §5.2 公式 | **绿**（4/4 有此键的例） |
| 5 | 每正例 `packet_count` **存在** | G-RTMP-4 | **红**（9 例缺，P4 补后转绿） |
| 6 | 3 负例 `expect` 键 == `{expect_error, error_contains}`（P4 删 `notes` 后） | 本契约 §4 | **红**（今日含 `notes`） |
| 7 | 负例 `error_contains` ∈ 代码锚词集 `{"App exceeds", "invalid Command", "MsgType", "SrcIP", "DstIP", "TCP.MSS"}` | 设计 §7 | **绿** |
| 8 | 非负例顶层键计数 == 0（**今日已成立**） | 设计 §12.1 | **绿** |
| 9 | 顶层 `rtmp` 子映射 presence 判死（`CheckProtoFlat` 非空串） | 设计 §12-P2 | **绿**（门已落码） |
| 10 | 每正例至少一条 frames 断言落在 offset 54（IPv4）或 74（IPv6） | 本契约 §3 | **红**（**11 例无 frames**，P4 补后转绿） |
| 11 | 每正例 `has_handshake == true` 且 `terminates == true` | 本契约 §1 | **绿**（13/13） |
| 12 | 断言字段名不得以 `rtmp.` 开头（**属另一协议**），协议字段须用 `rtmpt.` | 设计 §0 #2 | **绿**（今日零 `rtmp.*` 断言） |

**红项 3 条**（#5/#6/#10），**如实标红，不得申报"今日已过"**；均为 P4 补断言动作，**非引擎缺陷**。

**另注意**：`trafficgen/docs/protocol-pcap-test/rtmp.md` 的 16/16 pass **其 pcap 留档目录缺失**（G-RTMP-13，表格 16 条链接全死链）——该文件末次提交 `9b4ef16`（2026-09-20）**晚于**判死提交 `0417be5`（2026-09-13），故**不属"过期产物"**；提醒仅限"**留档目录缺失**"，**不得读成"数字过期"或"套件不可跑"**。

## 10. 修订记录

- v1.0.0（2026-09-29）：P-PIPE #118 文档轨 P1–P3（**as-built 型**，**无旧稿**）。形状基线机读实测（§1，**顶层零残留**）；5 条 frame + 17 条 field 断言逐条对 **`/tmp/mcp-pcaps/rtmp/`（mtime 2026-09-27）** 复核（**全 OK**）；包数公式 `20+N` 与实测 16/16 一致；P3 固定动作（§6）；执行建议（§7）；存量审计（§8，16/16 逐条去向：7 保留 + 9 改写 + 0 作废）；覆盖反查门建议断言行 **12 条（3 红如实标红）**（§9）；缺口 G-RTMP-1…G-RTMP-13。自审见 `/tmp/pipe/doc-lanes/rtmp.md`。

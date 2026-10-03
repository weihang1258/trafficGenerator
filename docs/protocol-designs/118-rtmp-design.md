# #118 rtmp（Adobe Real-Time Messaging Protocol，TCP 1935）设计契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3，as-built 型）
> 日期：2026-09-29
> 车道：文档轨（#118 rtmp 续号；本协议**无旧稿**，见 §0）
> 存量用例：`trafficgen/test/protocol_pcap/cases/rtmp.json`（**16 例 = 13 正 + 3 负**，机读实测；顶层键已是纯层链形，零残留，§12.1）
> 规范基线：① Adobe《RTMP Specification 1.0》（2012-07-01，下称 **spec**，章节号一律用该文档自身的 `§` 编号：握手 §5、chunk 流 §5.3/§6、协议控制消息 §7.1、AMF0 §7.2、消息类型 §11.4）；② Action Message Format 0（AMF0）编码规范（spec 内嵌 §7.2 与 AMF0 类型标记表）；③ 本仓库落码（`internal/protocol/rtmp/` 三文件 + 接线，§11）；④ **本机 tshark 3.6.14 实测**——`tshark -G fields` 的 `rtmpt.*` 字段表与 `tshark -G decodes` 的 `tcp.port 1935 rtmpt` 绑定；⑤ **本机 pcap 实测**：`/tmp/mcp-pcaps/rtmp/`（**17 个文件**：16 例 + 1 个历史扁平例 `rtmp-connect-play-basic.pcap`；mtime 2026-09-27，晚于代码末次提交 2026-09-20），16/16 包数与全部 frames 断言逐条复核通过（§9.3）
> 白话一句：**视频直播的"电话系统"——先互相报名字（C0/C1/S0/S1/S2/C2 握手），再开一个频道（connect），然后建一条流（createStream），最后按流名拉或推（play/publish）；所有命令都是 AMF0 编码、塞进带 12 字节头的 chunk 里发出去。**

## 0. 沿革与本协议定位（门1 必答：基线继承关系）

**本协议无旧稿。** `docs/protocol-designs/` 下不存在 `NN-rtmp-*` 的既有设计/用例文档（`ls | grep -i rtmp` 实测：0 命中；`INDEX.md` 无 rtmp 行）。因此本版**不存在"旧稿校正"动作**，§0 改为登记三件与协议定位直接相关的事实：

| # | 事实 | 证据（实测） | 结论 |
|---|---|---|---|
| 1 | 代码落码时间 | `rtmp.go`/`layer_gen.go` 末次提交 `9b4ef16`（2026-09-20，D-RTMP-1 P5 收官）；`cases/rtmp.json` 同提交 | **as-built 定稿**：本版是对已落码实现的逆向契约，不是设计先行稿 |
| 2 | tshark 有 RTMP dissector（**名字是 `rtmpt` 不是 `rtmp`**） | `tshark -G protocols`：`Real Time Messaging Protocol  RTMPT  rtmpt`；`tshark -G decodes`：`tcp.port 1935 rtmpt`；`tshark -G fields`：`rtmpt.*` **38 字段**。**同名 `rtmp.*` 的 7 字段属另一个协议**（Routing Table Maintenance Protocol，AppleTalk `ddp.type 1/5 rtmp`），与本协议无关 | **断言通道存在**（`rtmpt.handshake.*`/`rtmpt.header.*`/`rtmpt.scm.*`/`rtmpt.ucm.*`/`rtmpt.function.*`）；今日 16 例**零使用** → A′ 立项（G-RTMP-1）。**教训登记**：搜 `rtmp.*` 会命中同名异协议字段，字段名必须写 `rtmpt.` |
| 3 | 存量 16 例顶层已是纯层链形 | 机读：16/16 `spec_json` 顶层键 = `{layers}`（**仅此一键**），层形 `[ip,rtmp]` ×16 | **零迁移工作量**；§12.1 的"旧键去向"表全 0 |

**本协议特殊性（须写清，不得含糊）**：

- **① 分块流（chunk stream）是核心，且本实现只落 chunk 基本头 fmt=0**。spec §5.3 定义 4 种消息头格式（fmt 0/1/2/3，**头长 11/7/3/0 字节可变**），本实现 `buildAMF0Chunk`（`rtmp.go:527-547`）**恒写 fmt=0（12 字节头）**——`basicHeader` 恒为 `ChunkType0<<6 | csid`。**fmt 1/2/3、扩展时间戳（0xFFFFFF）、Set Chunk Size 生效后的分块（一个消息跨多个 chunk）全部未实现**（§3.3 边界、G-RTMP-3）。
- **② Set Chunk Size 是"协商了但不用"的装饰**。服务端响应里确实发了 `Set Chunk Size = 4096`（`buildServerResponse` 第 4 条，`rtmp.go:593-596`），但**本实现的分段由 TCP MSS（1460）决定，不是由 chunk size 决定**——`emitData` 调 `segmentByMSS`（`rtmp.go:282-293`），chunk 与 TCP 段是 1:1。**chunk size 协商与消息分块重组在本实现里不存在**（G-RTMP-3）。
- **③ AMF0 只落 5 个类型标记**（`rtmp.go:95-99`）：`0x00 Number` / `0x01 Boolean` / `0x02 String` / `0x03 Object` / `0x05 Null`。**AMF3 全未实现**；AMF0 的 `0x04 MovieClip`/`0x06 Undefined`/`0x08 ECMAArray`/`0x0A StrictArray`/`0x0B Date`/`0x0C LongString` 等亦未实现（§3.5 边界、G-RTMP-2）。
- **④ 命令面只落 3 条命令**：`connect` / `createStream` / `play|publish`。spec §7.2 命令族（`call`/`close`/`releaseStream`/`FCPublish`/`FCUnpublish`/`deleteStream`/`pause`/`seek`/`receiveAudio`/… ）未实现（§5.2 边界、G-RTMP-2）。
- **⑤ 流关联（§4 层）显式不适用**：RTMP 的单条 TCP 连接承载**全部**控制消息与全部音视频 chunk（chunk stream id 区分逻辑流），**不派生副连接**——与 FTP（控制+数据双连接）、SIP（信令+媒体）不同族。详见 §4 五层结论与 §12.3。

**产物过期登记（重要，G-RTMP-13）**：`trafficgen/docs/protocol-pcap-test/rtmp.md`（**tracked 产物**，`git ls-files` 可证）写 `Cases: 16 — pass 16, fail 0, error 0`，末次提交 `9b4ef16`（**2026-09-20**），**晚于**判死提交 `0417be5`（2026-09-13，扁平判死泛化全协议 `CheckProtoFlat`），**且该文件不存在"过期"问题**——但 `trafficgen/docs/protocol-pcap-test/rtmp/` 目录**不存在（0 个 pcap）**（`ls -d` 实测），表格里的 16 条 `[pcap](rtmp/...)` 链接**全部是死链**。故：**16/16 数字与判死提交同代、不属"早于判死提交"的过期产物**；登记的事实是"**结果文档的 pcap 留档目录缺失**"而非"数字过期"。**归属阶段：代码阶段**（P5 重跑套件时由 runner 重新落盘 `docs/protocol-pcap-test/rtmp/`）。**本车道未跑该套件**，故本文档**不以任何形式**引用该产物作为套件可跑证据；§9.3 的包数与 frames 复核用的是 **`/tmp/mcp-pcaps/rtmp/` 下 mtime 2026-09-27 的 pcap**（晚于代码末次提交），来源与上述 tracked 产物无关。

**依赖链判定纪律**：以上均为可判题（代码行 / tshark 表 / pcap 字节三级对照），直接判定，不问偏好。不可判的（RTMP spec 条款号逐条对应、chunk size 协商在真实服务器上的行为）标"待确认"并写清确认方式（G-RTMP-11）。

## 1. 范围、profile 与实现状态边界

本版定义 **RTMP（Adobe RTMP Specification 1.0 的明文 TCP 承载）于 TCP 1935** 的流量生成：握手（C0/C1/C2 + S0/S1/S2）、命令阶段（connect → 服务端响应五连 → 客户端窗口确认 → createStream → Set Buffer Length → _result → play/publish）、可选数据阶段（音视频 chunk）。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `rtmp_tcp_v1`（主，唯一） | TCP，fixture 1935 | TCP 握手 → C0C1 → S0S1S2 → C2 → 命令序 → [数据面] → TCP 挥手 | 真实服务器语义（app 是否存在、流名是否可拉） |

**只有一个 profile**：无 TLS 承载（`rtmps` 未实现）、无 HTTP 隧道（`rtmpt`/`rtmpte` 未实现）、无 UDP 变体（`rtmfp` 是**另一个协议**，本仓另有独立层，见 §10.5）。

显式边界（"不实现、不声称、不许静默转换"）：

1. **不实现 chunk 分块**——每消息恒单 chunk，chunk size 协商值（4096）不参与分段（§3.3）；
2. **不实现消息头 fmt 1/2/3** 与扩展时间戳（§3.3）；
3. **不实现 AMF3**，AMF0 只落 5 个类型标记（§3.5）；
4. **不实现命令族其余命令**（call/close/releaseStream/pause/seek/… ），只落 connect/createStream/play/publish（§5.2）；
5. **不实现时间戳语义**——所有 chunk 的 timestamp 恒 0、streamID 恒 0（命令面）或 1（play/publish 与数据面），不模拟真实播放时钟（§3.3）；
6. **不实现 RTMP 层保活/重连**——spec 的 `Ping`/`Pong`（User Control event 6/7）未实现；连接活性由 TCP 层承担（§5.3）；
7. **不实现握手校验**——C2/S2 的随机字节按 spec 回显，但生成器**不校验**对端回显是否正确（生成器只产流不接收，§3.2）。

**实现状态（2026-09-29 实测）**：`rtmp` 层已注册（`internal/core/layers/registry.go:1916-1925`，`CategoryTerminal`，`DependsOn ["ip"]`，Fields **5 键**）；planner/builder/生成器已落码（`internal/protocol/rtmp/` 三文件：`rtmp.go` 749 行 / `layer_gen.go` 72 行 / `rtmp_test.go` 866 行；`grep -c '^func Test'` = **35**）；`allowedProtocols["rtmp"]=true`（`protocols.go:53`）；层内 translate 已接线（`layers/chain_planner_translate.go:2783`）；`isRawIPChain` 已列入 rtmp（`chain_planner_util.go:54`）；raw 分支已传 `meta.RTMP`（`chain_planner.go:1520`）；16 语义用例已落 `cases/rtmp.json` 且 pcap 实测在案。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`、`tcp.flags`、`tcp.len`、offset 54 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。今日 16 例**零 `nic_capture` 开关** → NIC 路径在本套件中未被用例显式启用（G-RTMP-12）。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, rtmp]`（最小链 `[rtmp]` 亦可，引擎自动补 `ip`；实测三者均产 20 包）。**rtmp 是 raw 自驱终结层**：它自建 TCP 握手/挥手、自建 IP 层之下的 L2 回填由 ChainPlanner 的 raw-IP 分支承担（`chain_planner.go:1488-1585`），**不需要也不接受链上出现 `tcp` 层**（§11.4）。

端口：RTMP 明文默认 **TCP 1935**。**缺省路径有两条且都落码**：① 扁平路径 `mapToFlowSpec` 的 `setDefaultDstPort(&spec, cfg, 1935)`（`strategy_convert.go:1127-1133`）；② **链路径由生成器 `Plan` 内部缺省**——`spec.DstPort` 为 0 时由 worker 保底、非 0 时原样使用；`rtmp` 在 `validateBaseDstPortHandled` 白名单内（`chain_planner.go:780-783`，白名单条目在 `:782`），故 `validateSpecBase` 的 DstPort switch **不为 rtmp 补端口**。实测：`{layers:[{ip:{}},{rtmp:{}}]}` 产 `dst_port=1935` ✓。

固定偏移：无 VLAN/IP options/TCP options 时，**每帧 RTMP 载荷起点为 IPv4 offset 54**（14+20+20）；IPv6 下为 **74**（14+40+20）。RTMP chunk 内字段偏移按 §3.3 递推；**AMF0 变长字段之后的偏移不稳**（§3.4 注）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**本协议存量 16 例已是此形，无需迁移**）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"rtmp": {"command": "play", "stream_name": "movie1", "app": "live2"}}
  ]
}
```

多流样例（数量只走 `flow_control`；**本协议存量未用**，四元组留空走 worker 保底递增 §12.12）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"rtmp": {}}
  ],
  "flow_control": {"type": "flows", "value": 3}
}
```

## 3. 线格式编码（逐字段标注出处）

### 3.1 字节序总表（本协议最易错处，逐字段钉死）

**RTMP 的字节序在同一帧内混用**，这是本协议最容易写错的地方（Gnutella 三处端序混写同类教训）。逐字段实测表：

| 字段 | 端序 | 出处 | 实测证据 |
|---|---|---|---|
| chunk 基本头（fmt+csid 位域） | —（位域） | spec §5.3.1.1 | `03` = fmt0<<6 \| csid 3 |
| chunk 消息头 timestamp（3B） | **大端** | spec §5.3.1.2 | 恒 0（`00 00 00`），端序不可辨 |
| chunk 消息头 message length（3B） | **大端** | spec §5.3.1.2 | `00 00 41` = 65 ✓ |
| chunk 消息头 message type id（1B） | — | spec §5.3.1.2 | `14` = 20 ✓ |
| chunk 消息头 **message stream id（4B）** | **小端** | spec §5.3.1.2（原文："…in **little-endian** format"） | play 帧 `01 00 00 00` = 流 1 ✓ |
| 协议控制消息 payload（4B 数值） | **大端** | spec §7.1 | Window Ack `00 26 25 a0` = 2500000 ✓ |
| User Control 事件类型（2B） | **大端** | spec §7.1.1 | Stream Begin `00 00`；Set Buffer Length `00 03` |
| User Control 事件数据（4B） | **大端** | spec §7.1.1 | 缓冲长度 `00 00 0b b8` = 3000 |
| **AMF0 数字（8B double）** | **大端** | AMF0 规范 | `00 3f f0 00 00 00 00 00 00` = Number 1.0 ✓ |
| **AMF0 字符串长度前缀（2B）** | **大端** | AMF0 规范 | `00 07` + `connect` ✓ |
| AMF0 对象属性键长度（2B） | **大端** | AMF0 规范 | `00 03` + `app` ✓ |
| 握手 C1/S1/S2 时间戳（4B） | **大端** | spec §5.2.1 | `binary.BigEndian.PutUint32`（`rtmp.go:427`） |

**一句话记法**：**只有 chunk 头的 stream id 是小端，其余全部大端**（含 AMF0 全部多字节字段）。

### 3.2 握手（spec §5.2；`rtmp.go:419-472`）

握手共 **3 个方向批次、合计 4609 字节**（1537 + 3073 + 1536），跨 TCP 段：

| 批次 | 方向 | 构成 | 总字节 | 构造函数 |
|---|---|---|---|---|
| C0+C1 | up | C0(1) + C1(1536) | **1537** | `buildC0C1`（`:422-432`） |
| S0+S1+S2 | down | S0(1) + S1(1536) + S2(1536) | **3073** | `buildS0S1S2`（`:439-458`） |
| C2 | up | C2(1536) | **1536** | `buildC2`（`:462-472`） |

**C0 / S0**（1 字节）：版本号，恒 `0x03`（`RTMPVersion`，`rtmp.go:63`）。

**C1 / S1**（1536 字节）：

| 偏移 | 长度 | 字段 | 本实现取值 |
|---|---|---|---|
| 0 | 4 | time（时间戳） | **随机 uint32 大端**（`randUint32()`，`:426`/`:444`） |
| 4 | 4 | zero | 恒 0（`make` 零值，`:428`/`:446` 注释） |
| 8 | 1528 | random | **crypto/rand 随机字节**（`:430`/`:447`） |

**S2**（1536 字节，`buildS0S1S2` 的 `buf[1537:3073]`）：

| 偏移 | 长度 | 字段 | 本实现取值 | 代码 |
|---|---|---|---|---|
| 0 | 4 | time（回显 C1 的 time） | `copy(buf[1537:1541], c0c1[1:5])` | `:451` |
| 4 | 4 | time2（服务端时间戳） | `s1TS`（= S1 的时间戳，大端） | `:453` |
| 8 | 1528 | random echo（回显 C1 随机段） | `copy(buf[1545:], c0c1[9:1537])` | `:455` |

**C2**（1536 字节，`buildC2`）：

| 偏移 | 长度 | 字段 | 本实现取值 | 代码 |
|---|---|---|---|---|
| 0 | 4 | time（回显 S1 的 time） | `copy(buf[0:4], s0s1s2[1:5])` | `:465` |
| 4 | 4 | time2（客户端时间戳） | `randUint32()` 大端 | `:467-468` |
| 8 | 1528 | random echo（回显 S1 随机段） | `copy(buf[8:], s0s1s2[9:1537])` | `:470` |

> **诚实边界**：spec §5.2 的 S2 第 4-8 字节原文是"time2（服务端时间戳）"，本实现写的是 `s1TS`（与 S1 的 time 同值）。这与 spec 的"服务端当前时间"语义**不等价**（应是第二次取时），属实现选择；因该字段无外部可观察语义（生成器不校验、服务器也不校验），**不列为缺陷**，登记为 G-RTMP-11 待确认项。

### 3.3 chunk 装配（spec §5.3；`buildAMF0Chunk`，`rtmp.go:527-547`）

**基本头（1 字节）**：`basicHeader = (fmt << 6) | (csid & 0x3F)`。本实现 **fmt 恒 0**，故恒为 `0x40 | csid`；实测 `03`（csid 3）、`02`（csid 2）。**csid 只用 6 位**（≤63），spec §5.3.1.1 的 csid=0（2 字节基本头）/csid=1（3 字节基本头）两种扩展形态**未实现**。

**消息头（11 字节，fmt=0）**：

| 偏移 | 长度 | 字段 | 端序 | 本实现取值 |
|---|---|---|---|---|
| 1 | 3 | timestamp | 大端 | **恒 0**（`:531` `ts := uint32(0)`，注释"握手后第一个消息"） |
| 4 | 3 | message length | 大端 | `len(amfData)`（**只写低 24 位**，`byte(msgLen>>16), byte(msgLen>>8), byte(msgLen)`） |
| 7 | 1 | message type id | — | 入参 `msgType`（§3.6 表） |
| 8 | 4 | **message stream id** | **小端** | 入参 `streamID`（命令面 0 或 1；数据面恒 1） |

**总长度公式**：`chunk 长 = 12 + len(AMF0 载荷)`；**以太帧长 = 54（IPv4）/ 74（IPv6）+ 该 chunk 长**。

**本实现的 chunk 边界 = TCP 段边界**（1 chunk 1 段，由 `emitData`→`segmentByMSS` 决定，`:282-293`）——**chunk size 协商值 4096 不参与分段**。故单 chunk 载荷 > 1460 时会被拆成多个 TCP 段，**第二个段起不再是合法 chunk 起点**（spec 允许，因为接收端按 chunk size 重组；但本实现既不按 chunk size 拆也不重组）。今日 16 例最大单 chunk 载荷 = **194 字节**（服务端五连，§9.2），**恒 < 1460，不触发跨段**——这是本实现"看起来对"的原因，属**待实现边界**（G-RTMP-3）。

**fmt 1/2/3 与扩展时间戳**：spec §5.3.1.2.2-4 定义 7/3/0 字节头，用于同一 chunk stream 上的后续消息（时间戳增量压缩）。**本实现完全未用**——同一 csid 上连续两条消息（如 connect 与 createStream 都用 csid 3）**各写一份完整 12 字节头**，这是**合法**的（fmt 0 对每条消息都成立），只是放弃了压缩（G-RTMP-3 记为能力边界，非缺陷）。

### 3.4 固定偏移锚点（实测，用于用例 frames 断言）

| 锚点 | 偏移 | 含义 |
|---|---|---|
| chunk 头起点 | **54**（IPv4）/ 74（IPv6） | 基本头 1B + 消息头 11B = 12B |
| 消息头 stream id | **62**（54+8） | 4B 小端 |
| AMF0 命令名（string） | **66**（54+12） | `02` + 2B 长度 + 名字 |
| AMF0 txnID（number） | **76**（54+12+10） | 命令名 `connect` 7 字节 → `02 00 07` + 7 = 10B |

> **变长字段之后的偏移不稳**：`_result`（7 字节名）与 `createStream`（12 字节名）后的偏移不同；数据面 chunk 的 payload 起点 = 54+12 = 66。**用例 frames 断言只钉帧首 12 字节 + 已知定长字段**（§9.2）。

### 3.5 AMF0 编码（`rtmp.go:474-520`）

**只落 5 个类型标记**（`rtmp.go:95-99`）：

| 标记 | 类型 | 编码 | 本实现 |
|---|---|---|---|
| `0x00` | Number | 8 字节 IEEE-754 double，**大端** | `amf0Number`（`:486-491`） |
| `0x01` | Boolean | 1 字节 | **常量已定义但无编码函数**（本实现未产布尔值） |
| `0x02` | String | 2 字节长度（大端）+ UTF-8 字节 | `amf0String`（`:477-483`） |
| `0x03` | Object | 属性序列 + `00 00 09` 结束标记 | `amf0Object`（`:501-515`） |
| `0x05` | Null | 单字节 | `amf0Null`（`:518-520`） |

**Object 编码细节**（`amf0Object`）：`0x03` + 逐属性[2 字节键长（大端）+ 键字节 + 值编码] + `00 00 09`。**键无 `0x02` 类型标记**（AMF0 对象键是裸长度前缀串）。**使用有序 `[]amf0Prop` 切片而非 map**（`:494-499` 注释）——Go map 迭代顺序不确定，用切片保证字节可复现。

**未实现的 AMF0 类型**（G-RTMP-2）：`0x04 MovieClip` / `0x06 Undefined` / `0x07 Reference` / `0x08 ECMAArray` / `0x09 ObjectEnd`（只作结束标记用）/ `0x0A StrictArray` / `0x0B Date` / `0x0C LongString` / `0x0D Unsupported` / `0x0F XMLDocument` / `0x10 TypedObject` / `0x11 AVMPlus`（AMF3 切换）。

### 3.6 消息类型 ID 与 chunk stream ID（spec §11.4；`rtmp.go:73-88`）

| 常量 | 值 | 用途 | 实测出现帧 |
|---|---:|---|---|
| `MsgTypeSetChunkSize` | **1** | Set Chunk Size | 服务端五连第 4 条 |
| `MsgTypeStreamBegin` | **4** | User Control: Stream Begin | 服务端五连第 3 条 |
| `MsgTypeWindowAckSize` | **5** | Window Acknowledgement Size | 服务端五连第 1 条 + 客户端回显 |
| `MsgTypeSetPeerBandwidth` | **6** | Set Peer Bandwidth | 服务端五连第 2 条 |
| `MsgTypeAudio` | **8** | Audio Data | 数据面（T-8/T-10/T-11/T-12/T-16） |
| `MsgTypeVideo` | **9** | Video Data | 数据面（T-9/T-10/T-12） |
| `MsgTypeAMF0Command` | **20**（0x14） | AMF0 Command | connect / 服务端 _result / createStream / _result / play / publish |

**chunk stream ID 分配**（`rtmp.go:76-79`）：`CSIDProtocol = 2`（服务端协议控制 + _result，参考 pcap）/ `CSIDCommand = 3`（客户端 AMF 命令与 User Control）/ `CSIDAudio = 4` / `CSIDVideo = 6`。

> **Set Buffer Length 用 csid 3 且 msgType 4**（`buildSetBufferLength`，`:675-685`）：注释明写"客户端 User Control 消息使用 CSID=3（参考 pcap）"。**注意该函数名含 `buildAMF0Chunk` 但 msgType 传 4（不是 20）**——名字是历史遗留，行为正确（实测帧 15 `rtmpt.header.typeid=0x04`、`bodysize=10`）。

### 3.7 AMF0 命令载荷逐条（`rtmp.go:549-685`）

**connect()**（`buildConnectAMF0`，`:554-567`）：`String("connect")` + `Number(1.0)` + `Object{app: String(app), tcUrl: String(tcURL)}`。

> **与 spec §7.2.1 的差异**：spec 的 connect 命令对象含 `app`/`flashVer`/`tcUrl`/`fpad`/`capabilities`/`audioCodecs`/`videoCodecs`/`videoFunction`/`pageUrl`/`objectEncoding` 等 10+ 属性；**本实现只写 `app` 与 `tcUrl` 两个**（`:561-564`）。**命令对象属性集是"最小可识别集"**，不是 spec 全集（G-RTMP-2）。transaction ID 实测为 **1.0**（`:559` 注释"参考 pcap"）——spec §7.2.1 示例用 0.0，本实现用 1.0（两者皆合法，transaction ID 由发起方自定；用例 frames 钉的是 1.0）。

**服务端响应五连**（`buildServerResponse`，`:573-602`）——**一个 TCP 段内串联 5 个独立 chunk**，逐条：

| 序 | msgType | csid | payload | 字节 | 代码 |
|---:|---:|---:|---|---|---|
| 1 | 5 Window Ack Size | 2 | `00 26 25 a0`（2500000，`DefaultWinAckSize`） | 4 | `:577` |
| 2 | 6 Set Peer Bandwidth | 2 | `00 26 25 a0` + `02`（Dynamic） | 5 | `:580-583` |
| 3 | 4 Stream Begin | 2 | 事件类型 `00 00` + 流 ID `00 00 00 00` | 6 | `:588-591` |
| 4 | 1 Set Chunk Size | 2 | `00 00 10 00`（4096，`DefaultChunkSize`） | 4 | `:594-596` |
| 5 | 20 _result | 2 | `buildConnectResult()` | 变长 | `:599` |

**五连总长 = 5×12 + 4+5+6+4+len(_result) = 60 + 19 + len(_result)**。`_result` 载荷 = `String("_result")`(10) + `Number(1.0)`(9) + `Null`(1) + `Object{level:"status", code:"NetConnection.Connect.Success", description:"Connection succeeded."}`。

> **实测帧长核对（逐字节解析，2026-09-29）**：帧 12 `tcp.len=194` = 60（5 个头）+ 19（4 条控制 payload）+ **115**（`_result` 载荷）。`_result` 载荷 115 字节的逐项分解（机读解析确认，非估算）：`String("_result")` 10 + `Number(1.0)` 9 + `Null` 1 + `Object` **95** = 115 ✓；对象 95 = `03`(1) + `level`(2+5) + `"status"`(3+6) + `code`(2+4) + `"NetConnection.Connect.Success"`(3+29) + `description`(2+11) + `"Connection succeeded."`(3+21) + 对象结束 `00 00 09`(3) = 95 ✓。**旧文（`cases` 的 notes）称"包12 服务端五连首 chunk"**——措辞是"首 chunk"，与实现一致（该帧是**一个 TCP 段**、内含 5 个 chunk）。

**客户端 Window Ack Size 回显**（`:328-329`）：csid 2、msgType 5、payload `00 26 25 a0`——**与服务端第 1 条同值**（`:328` 复用 `DefaultWinAckSize`）。**这是"回显"语义的实现选择**：spec §7.1.2 的 Window Ack Size 是"告知对端我期待多大的确认窗口"，客户端回显同值是常见做法但不是唯一做法（G-RTMP-11 待确认）。

**createStream()**（`buildCreateStreamAMF0`，`:630-636`）：`String("createStream")` + `Number(2.0)` + `Null`。

**_result（createStream 响应）**（`buildCreateStreamResult`，`:640-647`）：`String("_result")` + `Number(2.0)` + `Null` + `Number(1.0)`（**stream ID = 1.0**）。

**play()**（`buildPlayAMF0`，`:651-658`）：`String("play")` + `Number(3.0)` + `Null` + `String(streamName)`。

**publish()**（`buildPublishAMF0`，`:662-670`）：`String("publish")` + `Number(3.0)` + `Null` + `String(streamName)` + `String("live")`（发布类型，**硬编码 `live`**）。

**Set Buffer Length**（`buildSetBufferLength`，`:675-685`）：msgType 4、csid 3、payload = 事件类型 `00 03`(2B) + 流 ID `00 00 00 01`(4B) + 缓冲长度 ms `00 00 0b b8`(4B，`DefaultBufferLen=3000`) = **10 字节**。

### 3.8 数据面 chunk（`rtmp.go:352-404`）

每条 `RTMPDataChunk` 产**一个 chunk**（12 字节头 + payload），封装为**一条 PSH-ACK TCP 段**：

| 字段 | 缺省规则 | 代码 |
|---|---|---|
| `direction` | 空 → **`"down"`**（注释：play 拉流） | `:361-363` |
| `msg_type` | 0 → **`down` 时 9（视频）/ `up` 时 8（音频）** | `:365-372` |
| `chunk_stream_id` | 0 → msgType 8 则 4，否则 6 | `:374-381` |
| `payload` | 空 → **100 字节全零**（`make([]byte, 100)`，注释"模拟帧"） | `:383-386` |
| `streamID` | 恒 **1** | `:388` |

> **数据面方向与 `emit` 的交互**：`up` 走客户端 seq、`down` 走服务端 seq（`:392-402`）；**实测 `direction="up"` 的数据段 seq 落在客户端流上** ✓（`rtmp_data_audio.pcap` 帧 18 = 上行 PSH-ACK 112B）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明 app/流名/命令类型/数据面 chunk 清单，引擎按固定剧本产出事件序列（TCP 握手 → 握手三批 → 命令七步 → [数据面] → TCP 挥手）。**RTMP 层本身无状态机**（§5.1）。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 拉流播放（VOD/直播观看） | connect → 五连 → createStream → SetBufferLen → _result → play → [视频下行] | T-1（`rtmp_play_session_full`）、T-9、T-10、T-11、T-16 |
| ② 推流发布（主播上行） | 同上但第三阶段为 publish（含 `live` 类型参数） | T-5（`rtmp_publish_mode`）、T-8、T-12 |
| ③ 握手分段形状 | 握手三批按 MSS 分段（1537/3073/1536） | T-2（`rtmp_handshake_segments`） |
| ④ chunk 头 + AMF0 逐字节 | 12 字节头 + `connect` 名 + txnID | T-3（`rtmp_chunk_header_amf0_connect`） |
| ⑤ 协议控制四消息 | WindowAck/SetPeerBW/StreamBegin/SetChunkSize 逐条 | T-4（`rtmp_protocol_control_messages`） |
| ⑥ 自定义 app/tcUrl（多租户/多应用） | connect 命令对象属性变化 | T-7（`rtmp_app_tc_url_custom`） |
| ⑦ 自定义流名（多路流） | play 的流名参数变化 | T-6（`rtmp_stream_name_custom`） |
| ⑧ 音视频混合数据面（真实推拉） | 命令面后追加 up/down chunk | T-10（`rtmp_data_bidirectional`）、T-12（`rtmp_composite_publish_multi_data`） |
| ⑨ 二进制载荷透传（真实帧内容） | payload_b64 / payload 原文 | T-11（`rtmp_data_payload_b64`）、T-16（`rtmp_data_payload_raw`） |

**五层覆盖逐层结论**：

- **功能层**——握手三批 / 命令七步 / 协议控制五连 / 数据面 8+9 两类，全部有正例；错误处理 3 类负例（§7）。
- **性能层**——握手分段（1537→1460+77、3073→1460+1460+153、1536→1460+76，**唯一跨 MSS 分段面**）；最大单 chunk 载荷 194B（服务端五连）；**帧长上界与 chunk 分块未测**（G-RTMP-3）。
- **数据场景层**——app/tcUrl/stream_name 三字段缺省与显式（T-1/T-7/T-6）；命令二值（play/publish，T-1/T-5）；msgType 二值（8/9，T-8/T-9）；csid 显式（4/6，T-8/T-9）；payload 三形（缺省 100B / b64 / 原文，T-8/T-11/T-16）；direction 二值（up/down，T-8/T-9）。
- **地址与流层**——**IPv4 已覆（16/16 例）**；**IPv6 今日零用例** → A′ 立项（G-RTMP-5，实测 `[ip{2001:db8::1,2001:db8::2},rtmp]` 产 20 包、offset 74，引擎已支持）；单流基线（16/16）；**流关联（控制流派生数据流）显式不适用**（§0 特殊性⑤：单 TCP 连接承载全部，无副连接）；**多流（会话内并发流）显式不适用**（chunk stream id 是逻辑流标识，不是并发流；多流由策略级 `flow_control` 承载，本版未用）。
- **业务层**——九场景全部有落点（上表）；**多会话/多事务**：本协议**单连接单事务链**（connect→createStream→play 是一条有先后依赖的链，属"事务交互"），**多会话今日零用例** → A′ 立项（G-RTMP-6）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① chunk 分块与重组（未实现，G-RTMP-3）；② 消息头 fmt 1/2/3（未实现，G-RTMP-3）；③ AMF3（未实现，G-RTMP-2）；④ 命令族其余命令（未实现，G-RTMP-2）；⑤ Ping/Pong 保活（未实现，§5.3）；⑥ RST 异常中断（框架 tcp 层能力，本层零断言，A′ 补例 G-RTMP-7）；⑦ 真实服务器可拉性（生成器只产流）。

## 5. 消息/事务模型与状态机

### 5.1 状态机（本协议的关键诚实声明）

**RTMP 层无自有状态机。** 生成器是"按配置一次性顺序产出全部帧"的纯函数驱动——`Plan`（`rtmp.go:171-415`）内部无状态变量参与决策（只有 seq/ack/packetIndex 三个递增计数器）。spec §7.2 描述的 `uninitialized → connected → streaming` 状态迁移，在本实现里**体现为固定的线性帧序列**，不体现为可查询/可拒绝的状态变量：

| spec 状态（§7.2 语义） | 本实现对应帧 | 是否可"拒绝非法转移" |
|---|---|---|
| uninitialized | 帧 1-3（TCP 握手）+ 帧 4-10（RTMP 握手） | **否**——无状态变量，无拒绝分支 |
| connected | 帧 11（connect）+ 帧 12（五连） | **否** |
| streaming | 帧 13-17（winack/createStream/SetBufferLen/_result/play\|publish）+ 数据面 | **否** |

**非法转移在本实现里不可能发生，也不被检测**：例如"未 connect 直接 play"无法表达（配置里没有"跳过 connect"的开关），"未 createStream 直接 publish"同样无法表达（`buildServerResponse` 与 `createStream` 帧恒发，不受配置影响）。**这是设计选择而非缺陷**——生成器的职责是产出可识别的合法流，不是模拟服务器状态机（G-RTMP-11 待确认：是否需要引入可拒绝的状态机，取决于用例需求）。

**配置驱动的唯一分支**（`:344-350`）：`command == "publish"` → 发 `publish(streamName, "live")`；否则（含缺省）→ 发 `play(streamName)`。

### 5.2 固定帧序（20 + N 帧，N = 数据面 chunk 数）

| # | 帧 | 方向 | 内容 | 代码 |
|---:|---|---|---|---|
| 1 | SYN | up | client ISN | `:296` |
| 2 | SYN-ACK | down | server ISN | `:298` |
| 3 | ACK | up | — | `:300` |
| 4-5 | C0+C1 | up | 1537B → 2 段（1460+77） | `:305-306` |
| 6-8 | S0+S1+S2 | down | 3073B → 3 段（1460+1460+153） | `:309-310` |
| 9-10 | C2 | up | 1536B → 2 段（1460+76） | `:313-314` |
| 11 | connect | up | csid 3、msgType 20、streamID 0 | `:319-320` |
| 12 | 服务端五连 | down | csid 2、5 chunk 一段（194B） | `:324-325` |
| 13 | 客户端 Window Ack | up | csid 2、msgType 5、16B | `:328-329` |
| 14 | createStream | up | csid 3、msgType 20、37B | `:332-333` |
| 15 | Set Buffer Length | up | csid 3、msgType 4、22B | `:336-337` |
| 16 | _result(createStream) | down | csid 2、msgType 20、41B | `:340-341` |
| 17 | play / publish | up | csid 3、msgType 20、streamID 1、38B | `:344-350` |
| 18…17+N | 数据面 | up/down 按 `direction` | 每条一个 chunk + PSH-ACK 段 | `:353-404` |
| 末 4 帧 | FIN / FIN-ACK / ACK / … | — | 三次 `emit`（`:407-411`），共 **4 帧** | `:407-411` |

> **帧序实测核对**（`rtmp_play_session_full.pcap`）：帧 4-10 = 握手七段 ✓；帧 11 = connect（77B）✓；帧 12 = 194B ✓；帧 13 = 16B ✓；帧 14 = 37B ✓；帧 15 = 22B ✓；帧 16 = 41B ✓；帧 17 = 38B ✓；帧 18-20 = 挥手 ✓。**挥手帧数须写清**：`Plan` 只发 3 次挥手 emit（`:407-411`，up FIN / down FIN+ACK / up ACK），**末帧为纯 ACK（`0x0010`），无第 4 帧**——实测 `tcp.flags` 末三帧 = `0x0011`/`0x0011`/`0x0010`（共 20 帧：3 握手 + 7 握手段 + 7 命令 + 3 挥手 = 20 ✓）。用例 `terminates` 只断"末 3 帧内有 FIN/RST"（`verify.go:161-176`），与 3 帧挥手一致。

**包数公式**（**权威，与实测 16/16 一致**）：

```
packet_count = 20 + N      （N = rtmp.data 数组长度）
```

推导：握手 3 + RTMP 握手 7（2+3+2 段）+ 命令 7（帧 11-17）+ 挥手 3 = **20**；每条数据面 chunk 恰好 +1 段。

### 5.3 保活 / 重试 / 重连 / 异常中断（§3.15 三项）

| 项 | 本协议状态 | 依据 |
|---|---|---|
| **长保活** | **协议层无心跳**——spec §7.1.1 的 User Control `PingRequest(6)`/`PingResponse(7)` **未实现**；本实现唯一的 User Control 消息是 `Stream Begin(0)` 与 `Set Buffer Length(3)`，**都是一次性事件，不是周期心跳** | `rtmp.go:85/675`；16 例零保活断言 |
| **重试 / 重连** | **不适用**——生成器一次性产流，无连接生命周期管理 | §1 边界 |
| **异常中断** | **本层零断言**——RST 是框架 tcp 层能力；本协议正例恒 FIN 优雅终止 | `:407-411`；A′ 补例 G-RTMP-7 |

### 5.4 自动派生规则（逐条列出触发条件与内容）

1. **TCP 握手**恒发（3 帧，SYN/SYN-ACK/ACK），由 rtmp 层自建（不依赖链上 tcp 层）——`:296-300`；
2. **TCP 挥手**恒发（3 次 emit）——`:407-411`；
3. **服务端响应五连**恒发（WindowAck/SetPeerBandwidth/StreamBegin/SetChunkSize/_result），**不受任何配置影响**——`:573-602`；
4. **客户端 Window Ack 回显**恒发——`:328-329`；
5. **Set Buffer Length** 恒发（值恒 3000）——`:336-337`；
6. **缺省值**：`app` 空 → `"live"`（`:189-192`）；`tcUrl` 空 → `"rtmp://<DstIP>/<app>"`（`:193-196`）；`command` 空 → `"play"`（`:197-200`）；`stream_name` 空 → `"stream"`（`:201-204`）；`ttl` 0 → 64（`:206-209`）；`mss` 0 → 1460（`:212-215`）；
7. **数据面缺省**见 §3.8。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流全链 = 20 帧（无数据面）～ 20+N 帧（N 条数据面 chunk）；**握手三批合计 4609 字节是唯一的跨 MSS 分段面**（实测 7 个 TCP 段）；单 chunk 载荷实测最大 **194 字节**（服务端五连），**远小于 MSS 1460**，故命令面永不跨段。吞吐数字待 P4 基准，**本版不写承诺**（§6.5）。
- **依据**：`Plan` 是**单 goroutine 顺序产出**（`:178-412`），每帧即时 `select` 送入 256 缓冲通道（`:272-277`），**无全量聚合**；每帧内存 = 该帧 payload（最大 194B + 各层头）；无跨流共享状态；无锁（只有局部计数器与 crypto/rand 调用）。
- **验收两路（§6.3 强制）**：pcap（`/tmp/mcp-pcaps/rtmp/`，正例 `<id>.pcap` / 负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `tcp.dstport`/`tcp.flags`/`tcp.len` 字段、帧原始 hex 与 `packet_count`，**不只断言"任务没报错"**。**今日 16 例零 `nic_capture`**（G-RTMP-12）。
- **六类场景落点（§6.6）**：基线（T-1，20 帧）/ 目标规模（T-12，22 帧）/ 压力上限（握手 3073B 跨 3 段）/ 长时间运行（**不适用**——无保活面，§5.3）/ 并发交错（顺序单连接承载，并发路径不启用）/ 背压（`packet_count` 精确计数守卫帧数漂移 + `tcp.len` 逐段断言守卫分段形状）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 validator 拒绝并传播为 task error，**不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功**（实测三例 `.neg.pcap` 均 **0 帧**）：

| # | 负例 ID | 故障输入 | 代码锚词 | 代码行 |
|---:|---|---|---|---|
| N-1 | `rtmp_neg_app_too_long` | `app` 长度 > 255 | `rtmp: App exceeds 255 bytes`（`%d` = `MaxAppLen` = 255） | `rtmp.go:143` |
| N-2 | `rtmp_neg_command_invalid` | `command="pause"` | `rtmp: invalid Command "pause" (supported: play, publish)` | `rtmp.go:149` |
| N-3 | `rtmp_neg_msg_type_invalid` | `data[0].msg_type=5` | `rtmp: Data[0].MsgType 5 invalid (supported: 8=audio, 9=video)` | `rtmp.go:163` |

**负例原子性**：每例单一故障注入，单次执行不混注 ✓（机读：三例 `spec_json` 各只注入一个故障字段）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**——逐条实测过分支存在且可达：

| 分支 | 锚词 | 代码行 | 可达性实测 |
|---|---|---|---|
| SrcIP 非法 | `rtmp: invalid SrcIP %q` | `:127` | 可达（链路径 `ip.src` 经 spec 注入） |
| DstIP 非法 | `rtmp: invalid DstIP %q` | `:132` | 可达 |
| RTMPConfig 为 nil | `rtmp: RTMPConfig is required` | `:138` | **链路径不可达**（translate 保底非 nil，`:2783-2790`）；仅引擎直调可达 |
| MSS 过小 | `rtmp: TCP.MSS %d too small (min 536)` | `:155` | **链路径实测不可达**——`tcp.mss=100` 在链校验层就被拒（`layer "tcp" field "mss" = 100 invalid: out of range [536,65535]`），锚词到不了 rtmp validator（G-RTMP-9） |

**不得误报的合法协议事件**：`publish` 模式（T-5/T-8/T-12）；数据面 up/down 双向（T-10）；`payload` 原文字节（T-16，**不是 hex 串**——pppoe cookie 同款陷阱）；空 `data` 数组（T-1 等 13 例）；`app`/`tc_url`/`stream_name` 缺省（T-1 承接）。

## 8. 边界

- **帧长与分段**：RTMP 握手三批 1537/3073/1536 字节 → TCP 段 2/3/2（MSS 1460）；**命令面最大单段 194 字节**（服务端五连）；**单 chunk 最大 194 字节**（同上）。**chunk size 4096 不参与分段**（§3.3 待实现边界）。
- **csid 上界**：6 位 → **csid ≤ 63**；csid 0/1 的扩展基本头未实现（§3.3）。
- **message length 上界**：3 字节字段 → 理论 16777215；**本实现无上界守卫**（`msgLen` 直接截低 24 位，超 16MB 会静默回绕）——今日配置面（`app ≤ 255`、`stream_name` 无长度校验、payload 无上界）**可构造超长 chunk**，登记 G-RTMP-8。
- **AMF0 字符串长度**：2 字节前缀 → **≤ 65535**；`amf0String` 无守卫（`:477-483`），超长静默回绕（同 G-RTMP-8）。
- **`app` 长度**：**≤ 255**（`MaxAppLen`，`:102`）——唯一有显式守卫的字段。
- **`stream_name` / `tc_url` 长度**：**无守卫**（G-RTMP-8）。
- **端口**：显式 1935 全正例；缺省 1935（生成器 Plan 内部缺省 + `validateBaseDstPortHandled` 豁免）今日无例 → A′ 补例（G-RTMP-10）。
- **地址族**：IPv4 已覆 16/16；**IPv6 零例** → A′（G-RTMP-5）；异族混写由 `validateSpecBase` 通用门拒（实测 `SrcIP 10.0.0.1 and DstIP 2001:db8::2 must be same IP version`）。
- **数据面 chunk 数**：无上界；每条 +1 段。
- 不得产生回绕长度或超量分配（除上述未守卫字段）。

## 9. 原子 ID 与完成定义（16 个唯一语义 ID = 13 正 + 3 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count（实测） |
|---:|---|---|---|---:|
| 1 | `rtmp_play_session_full` | 正 | §5.2：play 全会话基线（缺省 app/流名） | 20 |
| 2 | `rtmp_handshake_segments` | 正 | §3.2/§8：握手三批按 MSS 分段（2/3/2 段） | 20 |
| 3 | `rtmp_chunk_header_amf0_connect` | 正 | §3.3/§3.4/§3.7：chunk 头 12B + AMF0 connect 逐字节 | 20 |
| 4 | `rtmp_protocol_control_messages` | 正 | §3.6/§3.7：协议控制四消息 + createStream/play 帧字节 | 20 |
| 5 | `rtmp_publish_mode` | 正 | §5.1：`command=publish` 分支 | 20 |
| 6 | `rtmp_stream_name_custom` | 正 | §3.7：`stream_name` 自定义入 play 参数 | 20 |
| 7 | `rtmp_app_tc_url_custom` | 正 | §3.7：`app`/`tc_url` 显式（覆盖自动构造分支） | 20 |
| 8 | `rtmp_data_audio` | 正 | §3.8：msgType 8 + csid 4 | 21 |
| 9 | `rtmp_data_video` | 正 | §3.8：msgType 9 + csid 6 | 21 |
| 10 | `rtmp_data_bidirectional` | 正 | §3.8：up 音频 + down 视频（方向序） | 22 |
| 11 | `rtmp_data_payload_b64` | 正 | §3.8：`payload_b64` 解码透传 | 21 |
| 12 | `rtmp_composite_publish_multi_data` | 正 | §5.2：publish + 自定义 app/流名 + 双 chunk 复合 | 22 |
| 13 | `rtmp_neg_app_too_long` | 负 | §7：N-1 | —（实测 0 帧） |
| 14 | `rtmp_neg_command_invalid` | 负 | §7：N-2 | —（实测 0 帧） |
| 15 | `rtmp_neg_msg_type_invalid` | 负 | §7：N-3 | —（实测 0 帧） |
| 16 | `rtmp_data_payload_raw` | 正 | §3.8：`payload` 原文字节透传（非 hex） | 21 |

**包数公式校验**（`20 + N`，N = `data` 数组长度）：#1–#7、#13–#15 的 N=0 → 20 ✓（#13–#15 负例不产流）；#8/#9/#11/#16 N=1 → 21 ✓；#10/#12 N=2 → 22 ✓。**16/16 与实测 pcap 逐例一致**（§9.3 机读）。

### 9.1 存量用例形状（2026-09-29 机读实测）

| 项 | 实测值 |
|---|---|
| 例数 | **16**（13 正 + 3 负） |
| `spec_json` 顶层键 | **`{layers}` ×16**（唯一顶层键，**零游离键**） |
| 层形 | `[ip, rtmp]` ×16（**无 `tcp` 层**——raw 自驱） |
| 正例 `expect` 键集合 | 3 种形态：`{has_handshake,terminates}`(9 例) / `+fields`(3 例) / `+fields,packet_count`(3 例) / `+fields,frames,packet_count`(2 例) / `{has_handshake,terminates,has_payload,fields,packet_count}`(1 例) |
| 负例 `expect` 键集合 | `{expect_error, error_contains, notes}` ×3（**含 `notes`**，非严格两键，G-RTMP-4） |
| 带 `packet_count` 的例 | **仅 4 例**（#1/#2/#3/#4）；其余 9 正例**无 `packet_count`** → A′ 补（G-RTMP-4） |
| `has_handshake`/`terminates` | 13/13 正例全有 ✓ |
| `has_payload` | 仅 #1 有 |
| `frames` 断言 | 5 条（#3 ×2、#4 ×3），**逐条对实测 pcap 复核通过**（§9.3） |
| `fields` 断言 | 17 条（`tcp.flags` ×3 / `tcp.dstport` ×4 / `tcp.len` ×10），**全部复核通过** |
| `nic_capture` | **0 例**（G-RTMP-12） |
| `decode_as` | 0 例 |

### 9.2 实测帧位锚点（供用例断言，全部机读复核）

| 例 | 帧 | 断言 | 实测值 |
|---|---:|---|---|
| #1 `rtmp_play_session_full` | 1/2/4/5/8/11/18 | flags `0x002`/`0x012`、len `1460`/`77`/`153`/`77`、flags `0x011` | 全部 ✓ |
| #2 `rtmp_handshake_segments` | 4-10 | len `1460/77/1460/1460/153/1460/76` | 全部 ✓ |
| #3 `rtmp_chunk_header_amf0_connect` | 11 @54 / @76 | `03 00 00 00 00 00 41 14 00 00 00 00 02 00 07 63 6f 6e 6e 65 63 74` / `00 3f f0 00 00 00 00 00 00` | 逐字节 ✓ |
| #4 `rtmp_protocol_control_messages` | 12 @54 | `02 00 00 00 00 00 04 05 00 00 00 00 00 26 25 a0` | ✓ |
| #4 | 14 @54 | `03 00 00 00 00 00 19 14 00 00 00 00 02 00 0c …createStream` | ✓ |
| #4 | 17 @54 | `03 00 00 00 00 00 1a 14 01 00 00 00 02 00 04 70 6c 61 79 00` | ✓（streamID 小端 = 1） |

**帧位常量表（实测）**：帧 11 connect `tcp.len=77`；帧 12 五连 `194`；帧 13 winack `16`；帧 14 createStream `37`；帧 15 SetBufferLen `22`；帧 16 _result `41`；帧 17 play `38`；帧 18 数据面/挥手。

### 9.3 复核方法与结论（本车道实测，非引用 tracked 产物）

- **包数**：`tshark -r /tmp/mcp-pcaps/rtmp/<id>.pcap | wc -l` 逐例计数，16/16 与公式 `20+N` 一致；三负例 `.neg.pcap` 均 **0 帧**。
- **frames**：5 条 frames 断言逐条从 pcap 取 offset 处字节比对，**5/5 通过**。
- **fields**：17 条 field 断言逐条取 tshark 字段值比对，**17/17 通过**（其中 `tcp.flags` 3 条按位比较：断言 `0x002` vs 实测 `0x0002`，`verify.go:115-117` 按位判定，**非字符串相等**——机器比对时须用同一按位口径）。
- **malformed**：`rtmp_*` 前缀在 `IsMalformedWhitelisted`（`verify.go:569`）中有白名单——`Loop in AMF dissection`（tshark AMF 递归守卫对嵌套 `_result` 对象误报）。实测 `rtmp_data_audio.pcap` 有 **5 帧**该伪影（帧 11/12/14/16/17），**白名单已覆盖，不判红**；同时 tshark **仍正确解析出消息名**（`connect()`/`Window Acknowledgement Size 2500000|Set Peer Bandwidth 2500000,Dynamic|Stream Begin 0|Set Chunk Size 4096|_result()`/`createStream()`/`_result()`/`play()`），证明 AMF 编码合法、仅 dissector 守卫误报。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵（逐格重数：8 = 已覆 3 + 立项 4 + 不适用 1）

**逐项计数**（供对账，与上表逐行对应）：**已覆 3**（#1 连接模型 / #5 错误处理 / #8 版本方言）/ **立项 4**（#2 命令消息表 → G-RTMP-2 / #3 状态机 → G-RTMP-11 / #4 字段表 → G-RTMP-2+G-RTMP-3 / #6 超时活性 → G-RTMP-2）/ **不适用 1**（#7 NAT/代理/被动）。3 + 4 + 1 = 8 ✓

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | TCP 客户端主动建连（spec §5.1：先握手后命令） | 场景①–⑨ | `DependsOn ["ip"]`；**自建 TCP 握手/挥手**（`rtmp.go:296-300/407-411`） | 无 |
| 2 | 命令/消息表 | 握手 3 批 + 协议控制 6 类 + 命令族 20+ 条 + 数据 2 类（spec §7.1/§7.2/§11.4） | 场景①–⑨ | 握手 3 批 ✓；协议控制落 5 条（SetChunkSize/WindowAck/SetPeerBW/StreamBegin/SetBufferLen）；命令落 3 条（connect/createStream/play\|publish）；数据 2 类 ✓ | 命令族其余 → G-RTMP-2 |
| 3 | 状态机 | uninitialized→connected→streaming（spec §7.2） | 场景①/② | **无状态机**（§5.1 诚实声明）——固定线性帧序，无拒绝分支 | G-RTMP-11（待确认是否需要） |
| 4 | 字段表 | 基本头 fmt+csid（§5.3.1.1）+ 消息头 4 字段（§5.3.1.2）+ AMF0 12 类型 | 数据场景层 | chunk 头 4 字段逐字段落码（§3.3）；AMF0 落 **5/12** 类型 | fmt 1/2/3 → G-RTMP-3；AMF0 7 类型 → G-RTMP-2 |
| 5 | 错误处理 | 配置/线格式/状态机/关联/长度/载体六类各至少一条负例 | 负例 N-1/N-2/N-3（**已覆 3 类：配置 App 长度 / 枚举 Command / 枚举 MsgType**） | validator 7 处 return，其中链路径可达 5 处 | **未覆 3 类**：长度类（`stream_name`/`tc_url`/`payload_b64`，G-RTMP-8）、载体类（无载体概念，**不适用**）、状态机类（无状态机，**不适用**） |
| 6 | 超时与活性 | spec §7.1.1 Ping/Pong（User Control 6/7）保活 | — | **未实现**；无周期消息 | G-RTMP-2（保活面缺失） |
| 7 | NAT/代理/被动 | 无被动模式概念（客户端直连）；rtmpt/rtmps 隧道另属 | — | 无 `sessions[].src_port`；多流走策略级 `flow_control` | **显式不适用**（隧道承载未实现，非本 profile） |
| 8 | 版本/方言 | C0/S0 版本号（本实现恒 0x03）；明文 TCP 唯一方言 | 正例 13 | `RTMPVersion=0x03` 硬编码（`:63`）；无版本协商 | 无（单方言，版本协商未实现且不需要） |

### 10.2 子表①：命令/消息 × 终态矩阵（逐格已覆/立项/不适用）

| 消息 | T1 正常终态 | T2 配置拒绝 | T3 RST 异常终态 |
|---|---|---|---|
| C0/C1/S0/S1/S2/C2 握手 | 已覆（#1/#2） | 已覆（#13 代表例，拒绝与消息无关） | A′ 立项（G-RTMP-7） |
| connect | 已覆（#1/#3/#7） | 同上代表已覆 | A′ 立项（G-RTMP-7） |
| Window Ack Size（服务端/客户端） | 已覆（#1/#4） | 同上代表已覆 | A′ 立项（G-RTMP-7） |
| Set Peer Bandwidth | 已覆（#1/#4） | 同上代表已覆 | A′ 立项（G-RTMP-7） |
| Stream Begin | 已覆（#1/#4） | 同上代表已覆 | A′ 立项（G-RTMP-7） |
| Set Chunk Size | 已覆（#1/#4） | 同上代表已覆 | A′ 立项（G-RTMP-7） |
| createStream + _result | 已覆（#1/#4） | 同上代表已覆 | A′ 立项（G-RTMP-7） |
| Set Buffer Length | 已覆（#1/#4） | 同上代表已覆 | A′ 立项（G-RTMP-7） |
| play | 已覆（#1/#4/#6） | 同上代表已覆 | A′ 立项（G-RTMP-7） |
| publish | 已覆（#5/#12） | 同上代表已覆 | A′ 立项（G-RTMP-7） |
| Audio Data(8) | 已覆（#8/#10/#11/#12/#16） | 已覆（#15 msgType 拒绝） | A′ 立项（G-RTMP-7） |
| Video Data(9) | 已覆（#9/#10/#12） | 同上代表已覆 | A′ 立项（G-RTMP-7） |

**逐格重数**：12 行 × 3 列 = 36 格——已覆 **24**（T1 列 12 + T2 列 12）/ A′ 立项 **12**（T3 列 12）/ **不适用 0**，零空格。24 + 12 + 0 = 36 ✓


### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

| # | 变体 | 落点 |
|---:|---|---|
| 1 | `app` 缺省（→ `live`） | 覆（#1/#2/#3/#4/#5/#6/#8–#11/#16） |
| 2 | `app` 显式 | 覆（#7 `live2`、#12 `stream1`） |
| 3 | `app` 超 255 | 覆负例（#13） |
| 4 | `tc_url` 缺省（→ 自动构造 `rtmp://<DstIP>/<app>`） | 覆（#1–#6/#8–#11/#16） |
| 5 | `tc_url` 显式 | 覆（#7） |
| 6 | `command` 缺省（→ `play`） | 覆（#1–#4/#6/#7/#8–#11/#16） |
| 7 | `command="publish"` | 覆（#5/#12） |
| 8 | `command` 非法 | 覆负例（#14） |
| 9 | `stream_name` 缺省（→ `stream`） | 覆（#1–#5/#7–#12/#16） |
| 10 | `stream_name` 显式 | 覆（#6 `movie1`、#12 `cam1`） |
| 11 | `stream_name` 超长（> 65535） | A′ 立项（无守卫，G-RTMP-8） || 12 | `data` 空数组 | 覆（#1–#7/#13–#15） |
| 13 | `data` 单条 | 覆（#8/#9/#11/#16） |
| 14 | `data` 两条 | 覆（#10/#12） |
| 15 | `data[].direction="up"` | 覆（#8/#10/#11/#12/#16） |
| 16 | `data[].direction="down"` | 覆（#9/#10） |
| 17 | `data[].direction` 缺省（→ `down`） | A′ 立项（**实测可达**：`{msg_type:0}` 产 21 包、段落 down 向；今日零例） |
| 18 | `data[].msg_type=8` | 覆（#8/#10/#11/#12/#16） |
| 19 | `data[].msg_type=9` | 覆（#9/#10/#12） |
| 20 | `data[].msg_type` 缺省（→ 按方向 8/9） | A′ 立项（实测可达，同 #17 形状） |
| 21 | `data[].msg_type` 非法 | 覆负例（#15） |
| 22 | `data[].chunk_stream_id` 显式 4/6 | 覆（#8/#9/#10/#11/#12/#16） |
| 23 | `data[].chunk_stream_id` 缺省（→ 按 msgType 4/6） | A′ 立项（实测可达） |
| 24 | `data[].chunk_stream_id` > 63（6 位截断） | A′ 立项（无守卫，G-RTMP-8） |
| 25 | `payload` 缺省（→ 100B 全零） | 覆（#8/#9/#10；#1 notes 称"100B 随机"**实为全零**，G-RTMP-4） |
| 26 | `payload_b64` 显式 | 覆（#11/#12） |
| 27 | `payload` 原文字节 | 覆（#16） |
| 28 | `payload_b64` 非法 base64 | A′ 立项（`decodeBase64` 失败**静默丢弃**→ payload 落缺省 100B，G-RTMP-8） |
| 29 | `payload` 与 `payload_b64` 同时存在 | A′ 立项（`payload_b64` 优先，`strategy_convert.go:5371-5377`） |
| 30 | IPv4 载体 | 覆（16/16） |
| 31 | IPv6 载体 | A′ 立项（**实测可达**：20 包、offset 74，G-RTMP-5） |
| 32 | 异族混写 | A′ 立项（通用门已拒，锚词 `must be same IP version`） |
| 33 | 缺省端口（不写 dst_port） | 覆（16/16 **均未写端口**，实测落 1935） |
| 34 | 非默认端口（`dst_port=9999`） | A′ 立项（**实测可达**：`tcp.dst_port=9999`） |
| 35 | MSS 非缺省（如 1000） | A′ 立项（**实测不可达**——`tcp.mss=1000` 被链校验层吞掉、分段仍 1460，G-RTMP-9） |
| 36 | MSS 越界（<536） | 覆负例（链校验层拒，锚词 `out of range [536,65535]`，**非 rtmp 锚词**，G-RTMP-9） |

**已覆 25 + A′ 立项 11 = 36** ✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 直播观看（play 拉流） | #1/#4/#6/#9/#10/#11/#16 | 已覆 |
| 2 | 主播推流（publish） | #5/#8/#12 | 已覆 |
| 3 | 多应用/多租户（app 区分） | #7/#12 | 已覆 |
| 4 | 多路流（stream_name 区分） | #6/#12 | 已覆 |
| 5 | 握手兼容性探测 | #2 | 已覆 |
| 6 | 协议控制协商（窗口/带宽/chunk size） | #4 | 已覆（**协商值不生效**，G-RTMP-3） |
| 7 | 缓冲长度设置（播放器缓冲） | #1/#4 | 已覆 |
| 8 | 音视频帧传输 | #8/#9/#10/#11/#12/#16 | 已覆 |
| 9 | 真实音视频编解码帧（H.264/AAC） | #11/#12/#16（**任意字节透传**：`payload_b64`/`payload` 两形可承载真实帧字节） | 已覆（**字节透传面**；不校验编解码合法性） |
| 10 | rtmps（TLS 承载 443） | — | **明确不解决**（未实现） |
| 11 | rtmpt/rtmpte（HTTP 隧道） | — | **明确不解决**（未实现） |
| 12 | 服务器状态机（拉流失败/流不存在错误码） | — | **明确不解决**（生成器只产流） |
| 13 | 大消息分块（超 chunk size） | — | **明确不解决**（G-RTMP-3） |
| 14 | Ping/Pong 保活 | — | **明确不解决**（未实现） |
| 15 | AMF3 / SharedObject | — | **明确不解决**（未实现） |

8 覆 + 7 不适用 = 15。✓ 无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比

三路：①**规范原文**（Adobe RTMP Specification 1.0，定"必须是什么"——本版按该文档的握手 §5.2、chunk §5.3、协议控制 §7.1、命令 §7.2、消息类型 §11.4 逐条提炼）；②**商业化软件实际行为**（**未取到**：未抓真实 RTMP 服务器（nginx-rtmp / SRS / Wowza）的线字节 → G-RTMP-11 待确认）；③**可靠开源实现思路**（未逐行比对；只借鉴"chunk stream id 分配"与"服务端五连顺序"两条常见做法，参考 pcap 值 2500000/4096/3000 已落在常量里）。

三路一致点：握手三批尺寸（1537/3073/1536）、chunk 基本头 fmt=0 的 `0x40|csid` 形态、消息头 11 字节字段序、AMF0 大端、命令名与 txnID 组合。
不一致点（待确认，G-RTMP-11）：connect 的 transaction ID（spec 示例 0.0 vs 本实现 1.0）；S2 第 4-8 字节语义（spec"服务端当前时间" vs 本实现回写 S1 时间戳）；客户端 Window Ack 回显值（spec 未规定必须回显同值）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `rtmp` raw 自驱终结层（本版；ldap/pppoe 同构先例） | 握手/chunk/AMF0/数据面全部可声明可断言；代价 = 自建 TCP 握手挥手（与链上 tcp 层能力重复） | **采用** |
| B | `[ip,tcp,rtmp]` 事件层 + 复用 tcp 层握手 | 复用 tcp 层可省 7 帧自建逻辑；但 legacy `Plan` 已自建全套且 **MSS 分段由 rtmp 自己算**（`segmentByMSS`），改造成本高 | **否决**（D-RTMP-1 裁定1：legacy 自建 TCP 原样保留，零分叉） |
| C | 拆成"握手层 rtmp-handshake + 命令层 rtmp-cmd" | 两层的 C1/S1 回显需跨层状态传递，框架层间无此通道 | **否决**（状态在 `Plan` 局部变量，单层内聚更简单） |

## 11. P2 D-RTMP-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 状态说明：实现已落码（`internal/protocol/rtmp/` 三文件），本 P2 条目为 P-PIPE 文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口；P4 在本协议内为"缺口收敛"（§14），不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:8682-8744`） | `RTMPConfig`（5 字段）+ `RTMPDataChunk`（4 字段）+ `FlowSpec.RTMP` 槽位（`:1867`） | —（共享文件） |
| `trafficgen/internal/protocol/rtmp/rtmp.go` | 常量表 + `Planner.Validate`（7 处 return）+ `Planner.Plan`（自建 TCP + 握手 + 命令 + 数据 + 挥手）+ 全部 builder | 749 |
| `trafficgen/internal/protocol/rtmp/layer_gen.go` | `RTMPGenerator`（`RegisterLayerGenerator` + `RegisterLayerValidator`，`init()`） | 72 |
| `trafficgen/internal/protocol/rtmp/rtmp_test.go` | **35 个 `Test*`**（编码面 + 生成器面 + Validate 面 + 握手回显面） | 866 |
| 接线 **9 处**（实测逐点） | ① registry 注册（`layers/registry.go:1916`）；② translate 层内分支（`layers/chain_planner_translate.go:2783`）；③ `isRawIPChain` 列入（`layers/chain_planner_util.go:54`）；④ raw 分支 `meta.RTMP` 传参（`layers/chain_planner.go:1520`）；⑤ 端口豁免白名单（`layers/chain_planner.go:782`）；⑥ 扁平缺省端口（`strategy_convert.go:1127`）；⑦ 协议准入（`protocols.go:53`）；⑧ 顶层子映射判死（`strategy_convert.go:9095`）；⑨ 层内解析入口导出（`strategy_convert.go:5340` `ParseRTMPConfigFromMap`）。**另 2 处在包内 `init()`**：`RegisterLayerGenerator` + `RegisterLayerValidator`（`layer_gen.go:63-72`） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`rtmp.go:124`）：7 处 return（行号实测）——`SrcIP` 非法（`:127`）/ `DstIP` 非法（`:132`）/ `RTMP==nil`（`:138`）/ `App` 超长（`:143`）/ `Command` 非法（`:149`）/ `TCP.MSS` 过小（`:155`）/ `Data[i].MsgType` 非法（`:163`）。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`rtmp.go:171`）：先 `Validate`，再起 goroutine 顺序产出；**256 缓冲通道**；`ctx.Done()` 在每个 emit/emitData 处检查（`:272-277`/`:283-288`）。
- 生成器：`Name() "rtmp"`；**`GenEvents()` 返回 `nil`**（`layer_gen.go:26`——**这是 raw 自驱分支的判定依据**：`ChainPlanner` 用 `GenEvents() != nil` 区分事件层与 raw 层，`chain_planner.go:1600`）；`Generate` 把 `req.Meta.RTMP` 与四元组组装成 `FlowSpec` 调 `NewPlanner().Plan`，**逐包把 `Direction` 改写为 `"up"`** 后 `req.Emit`（`:54-58`）。

### 11.3 数据结构

`RTMPConfig{App, TcURL, Command, StreamName string; Data []RTMPDataChunk}`（`types.go:8698-8720`）；`RTMPDataChunk{Direction string; MsgType, ChunkStreamID uint8; Payload []byte}`（`:8726-8743`）。

> **JSON 键名**（层内配置面，registry Fields 5 键）：`app` / `tc_url` / `command` / `stream_name` / `data`（`data` 项内子键 `direction`/`msg_type`/`chunk_stream_id`/`payload`/`payload_b64`，**子键不在 registry Fields 里**——`data` 登记为 `list` 类型，子键由扁平 parse 消费，§11.7）。

### 11.4 主流程（逐包方向处理是本节关键）

层链配置 → `ValidateLayers`（registry Fields 5 键 allowlist + 链形校验）→ `BuildLayersPlanner` → `ChainPlanner.Plan` → **`isRawIPChain` 判定为真** → raw 分支（`chain_planner.go:1488`）：
1. 取 `gens[len-1]`（= rtmp 生成器）；
2. `meta.SrcIP/DstIP/TTL/RTMP` 等字段补齐（`:1520` 传 `meta.RTMP`）；
3. **`Emit` 包装对 `Direction=="down"` 的包再换一次 L3 地址**（`:1544-1546`）；
4. `gen.Generate(ctx, req)` 逐包回填 L2/EtherType/DSCP/TTL/FlowID/Timestamp。

**方向处理（防双换，`layer_gen.go:8-11` 注释）**：legacy `Plan` 已在包内部完成 MAC/IP/端口换向并置 `Direction="down"`；raw drive 的 `Emit` 包装对 `"down"` 包**会再换一次 L3 地址**。故生成器**统一把每包 `Direction` 改写为 `"up"`** 后转 `Emit`——L3/L4 保持 legacy 换向结果，L2 MAC 保持 legacy 写入值（非空，drive 的回填跳过），**语义与 legacy 扁平路径逐字节一致**。**这是本协议接线最容易出错的一处**（ldap/pppoe 同款机制）。

### 11.5 错误分支

7 处 validator 拒绝全部传 task error（零假成功——三负例实测 0 帧）。**但链路径下只有 5 处可达**（`RTMP==nil` 与 `TCP.MSS` 两处不可达，§7）。**静默路径（缺陷候选）**：`decodeBase64` 失败静默丢弃 payload（`strategy_convert.go:5371-5374`，无 else 分支）→ payload 落缺省 100B，**不报错**（G-RTMP-8）。

### 11.6 性能边界

见 §6（顺序产出、per-flow 局部状态、256 缓冲通道、无跨流共享、无锁；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- **`CheckProtoFlat` 有 rtmp 分支**（`strategy_convert.go:9095-9104` 的 `rawWrapChains` map 含 `"rtmp": "[ip,rtmp]"`）：顶层 `rtmp` 子映射 presence **判死**（空 map 也死）✓；顶层四元组/`count` 五键亦判死 ✓（`:8630-8636`）。**但顶层白名单外游离键（如 `bogus`）今日不判死**（实测 `CheckProtoFlat("rtmp", {layers:[…], bogus:1})` 返回空串）→ presence 负例今日建了会真绿 = 假通过，**不建**（G-RTMP-1，与 opcua G-OPCUA-1 同款，等框架级 unknown-key 白名单）。
- **`tcp.mss` 键在 rtmp 链上无效**（G-RTMP-9）：链校验层把 `mss` 当通用 tcp 字段校验（范围 [536,65535]），但 **rtmp 生成器不读 `spec.TCP`**（`rtmp.go:212-215` 只读 `spec.TCP.MSS`，而链路径下 `spec.TCP` 恒 nil——实测 `spec.TCP=<nil>`）。故 `tcp.mss=1000` 被静默忽略、分段仍按 1460；`tcp.mss=100` 被链校验层拒（**锚词不是 rtmp 的**）。
- **`spec.TCP` 其余键全无效**：`initial_seq`/`window_size`/`handshake`/`termination` 实测对 rtmp 链**零影响**（生成器自建 ISN、恒 `winSize=65535`、恒握手恒挥手）。**这是 raw 自驱层的固有语义**（tcp 层不在链上），但 **registry 的 tcp 层 Fields 仍接受这些键**——配置面与生效面不一致（G-RTMP-9）。
- **动态 allowlist（`internal/core/layer_dyn.go` 头部）：`rtmp` 零命中**（`grep -c` = 0 实测）→ 层内任何对象值即拒（实测 `rtmp.app`/`rtmp.data`/`rtmp.dst_port` 三键对象均报 `does not support dynamic`）；四元组 `ip` 层全开。见 §12.12。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 3 文件 + **接线 9 处**（§11.1 表逐点列出：registry/translate/isRawIPChain/raw 分支/端口豁免/strategy_convert 四入口/protocols 准入）；不触及其他协议。cases 回滚 = 恢复 16 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 16/16 顶层 = `{layers}` **仅此一键，零残留**；目标形状见 §2 样例且**存量已达标**（本协议无迁移工作量）；顶层 `rtmp` 子映射与四元组五键**均已判死** | §12.1；`cases/rtmp.json` 机读实测；`CheckProtoFlat` 实测 |
| §2 策略/任务 | 策略 = 单 rtmp 流量模板；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（**无派生流，诚实声明**）/插入位置（raw 自驱终结层）/时间线。有长连接，不豁免 | §12.3 + §5 |
| §4 查规范 | Adobe RTMP Spec 1.0（§5/§7/§11.4）+ tshark 3.6.14 `rtmpt.*` 38 字段与 `tcp.port 1935 rtmpt` 绑定 + 16 例 pcap 实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["ip"]`（`registry.go:1916`）；7 处拒绝分支（链路径可达 5）；失败传 task error（三负例 0 帧实测） | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待 P4 基准，不写承诺；pcap/NIC 两路验收明写） | §6 |
| §7 三份文档 | `118-rtmp-{design,testcase}.md` v1.0.0（草稿层）+ D-RTMP-1（§11，门1 获批 = 定稿）+ T-RTMP（testcase §2，16 ID）；**无旧稿层** | 修订记录 |
| §8 设计先行 | 本协议为 **as-built 型**（代码先于本版文档，2026-09-20 落码）——门1 获批 = D-RTMP-1 定稿 = 后续改动入口 | 提交序 |
| §9 测试三源 | 三源 = Adobe RTMP Spec 1.0（§10）+ D-RTMP-1（§11）+ tshark 3.6.14 字段与 pcap 实测（**已到抓包级**：16 例 pcap 在案、5 条 frame + 17 条 field 断言逐条复核 OK）；16 ID 逐项回指；存量 16 例审计去向 testcase §8 | `118-rtmp-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 `/tmp/pipe/doc-lanes/rtmp.md`）+ 收官隔离复审；红先绿后 | 自审日志 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组 `ip` 层全开（allowlist 实测）；业务字段 5 键逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `rtmp` 已在 `registry.go:1916` 注册（**不新增层**）；Fields 5 键；**P4 若改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `rtmpt.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/rtmp/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/rtmp.json` | 16 | **`{layers}` ×16**（唯一顶层键，**零游离键**） | `[ip,rtmp]` ×16 | 3/3 = `{expect_error, error_contains, notes}` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 已住 `layers[0].ip.{src,dst}`（16/16 显式写 `10.0.0.1`/`20.0.0.1`） |
| `src_port` | **0** | 本已 absent（worker 保底 `12345`）；目标形按需迁 `layers[i].tcp.src_port`（**本协议 tcp 层不在链上，端口语义见 §11.7 注**） |
| `dst_port` | **0** | **16/16 均未写端口**，由生成器 Plan 内部缺省落 1935 |
| `count` | **0** | 走 `flow_control`（本版未用） |
| 顶层 `rtmp` 子映射 | **0** | 已住 `layers[1].rtmp`（16/16）；**顶层同键 presence 今日判死**（`CheckProtoFlat` 实测） |
| `strategy_fc` / `flow_control` | **0** | 本协议无多流用例；目标形按需加 |

**结论**：**本协议存量 16/16 顶层零残留**——§1 门的动作 = ①**无旧键可删**；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测 16/16 顶层仅 `layers`）；③A′ 新增例全部沿用纯 layers 形（§13）。

**判死门实测（本车道，2026-09-29）**：

| 输入形状 | `CheckProtoFlat` 返回 | 判定 |
|---|---|---|
| `{layers:[…], rtmp:{}}` | `protocol rtmp rejects a top-level rtmp sub-config (move it into the rtmp layer of a [ip,rtmp] layers chain)` | **判死 ✓**（可建负例） |
| `{layers:[…], src_ip/dst_ip/src_port/dst_port/count}` | `protocol rtmp rejects flat config field <k> …` | **判死 ✓**（五键全判） |
| `{layers:[…], bogus:1}` | `""`（**不判死**） | **缺口 G-RTMP-1**（presence 负例不得建，建了会真绿） |

目标形状样例见 §2（顶层仅 `layers`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"rtmp":{}}` **今日会被拒**（`rawWrapChains` 含 rtmp，`strategy_convert.go:9095-9104` 实测返回判死文案）→ **P4 可建该负例**（与 opcua 的 G-OPCUA-1 相反，本协议此项**已闭合**）。② 白名单外游离键判死（`unknown field`）**今日无通用门** → G-RTMP-1，P4 不建。③ 3 负例每条带锚词（已齐，§7）。④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

- **会话表**：`s1` 单连接基线（**16/16 例均为单连接**，各自四元组，TCP 握手 → C0C1 → S0S1S2 → C2 → 命令七步 → [数据面] → TCP 挥手）。**无第二会话**（多会话今日零用例，G-RTMP-6）。
- **事务序列**：`t1` TCP 建连（3 帧）/ `t2` RTMP 握手（3 批 7 段）/ `t3` connect 事务（connect → 服务端五连）/ `t4` 流建立事务（createStream → SetBufferLen → _result，**有先后依赖**）/ `t5` 播放/发布事务（play\|publish）/ `t6` 数据面（每条 chunk 一个"事务"，无关联标识）/ `t7` TCP 拆连。每事务四件事（前置/触发/成功/失败）见 §5.2 帧序表 + §4 场景表。**失败面**：本实现无"事务失败"路径（服务器恒成功），负例全是**配置期拒绝**（§7）。
- **关联关系**：**无派生流**（诚实声明：单 TCP 连接承载全部控制消息与音视频 chunk，无 `driven_by`，无副连接；chunk stream id 是**同一连接内的逻辑流标识**，不是新连接）。**与 FTP（控制+数据双连接）/SIP（信令+媒体）不同族**。
- **插入位置**：**raw 自驱终结层**（`[ip,rtmp]`，无中间层；链上出现 `tcp` 层不改变行为，实测 `[ip,tcp,rtmp]` 同样 20 包，§11.7）。
- **时间线**：严格顺序单线程产出（`Plan` 单 goroutine）；命令面顺序不可配置（connect→五连→winack→createStream→SetBufferLen→_result→play/publish 恒此序）；数据面在命令面之后按 `data` 数组序展开；**无交错**（`concurrent` 为例外路径不启用）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src`/`ip.dst` 两策略全开（allowlist `internal/core/layer_dyn.go:18` 实测：`ip` = `{src,dst,ttl}`）；`tcp.src_port`/`tcp.dst_port` 亦在 allowlist（`:19`）——但**本协议链上无 tcp 层**，`tcp` 层键在本协议链上不可用（§11.7）；端口动态须走**顶层扁平 `src_port`/`dst_port` 对象**（链路径下顶层四元组被 `CheckProtoFlat` 判死 → **端口动态在本协议链形下今日不可达**，G-RTMP-9）。保底 `DefaultSrcPort+i`（`strategy_convert.go:49`）；dst 动态与 1935 缺省和平共处（显式/动态值非零即不触发补齐）。

**业务字段 5 项全关**（allowlist 无 `rtmp` 行，`grep -c` 零命中实测；**三键对象实测均报 `layers[1](rtmp).<k> does not support dynamic`**）：`app`（应用名，逐流变无意义）/ `tc_url`（同上）/ `command`（二值枚举，结构选择器）/ `stream_name`（流名，**逐流变有真实需求**——多路流场景，列 A′ 首选候选）/ `data`（嵌套列表，无动态形状）。

序号算法实读：`parseLayerDyn`（`internal/core/layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go:17-71`）——**`rtmp` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。

## 13. P3 对接清单（T-RTMP 草稿输入；正文落 testcase 文件）

16 ID（13 正 + 3 负）+ packet_count 公式 `20+N` + 锚词 + fixture 常量（`10.0.0.1`/`20.0.0.1`、srcport 12345、dstport 1935）+ 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。A′ 候选 **10 例**：

`rtmp_ipv6`（IPv6 offset 74，**实测可达**）/ `rtmp_neg_app_at_max`（`app` 恰 255，边界相邻值）/ `rtmp_neg_command_empty_ok`（`command=""` 合法，走缺省 play，**正例**）/ `rtmp_data_default_direction`（`data:[{msg_type:0}]` 走缺省 down+video，**实测可达**）/ `rtmp_data_default_csid`（csid 缺省按 msgType 落 4/6）/ `rtmp_neg_bad_base64`（`payload_b64` 非法 → 静默落缺省 100B，G-RTMP-8）/ `rtmp_port_nondefault`（`dst_port=9999`，**实测可达**）/ `rtmp_multi_flow`（`flow_control:{flows:3}`，验证四元组保底递增）/ `rtmp_abort_rst`（G-RTMP-7）/ `rtmp_neg_top_rtmp_submap`（顶层 `rtmp` 子映射 presence 判死，**今日已可建**，§12-P2）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-RTMP-1 | `rtmpt.*` 字段断言面**今日零使用**（tshark 有 38 字段可用）+ 顶层白名单外游离键（`bogus`）**无通用门**（presence 负例不得建，建了会真绿） | A′ 收编字段断言（**字段名必须写 `rtmpt.` 不是 `rtmp.`**，§0 #2）；游离键等框架级 unknown-key 白名单 |
| G-RTMP-2 | **AMF0 只落 5/12 类型**（缺 MovieClip/Undefined/Reference/ECMAArray/StrictArray/Date/LongString 等）；**AMF3 全缺**；**命令族只落 3 条**（缺 call/close/releaseStream/FCPublish/FCUnpublish/deleteStream/pause/seek/… ）；**Ping/Pong 保活未实现** | **明确不解决**（生成器面收窄为"可识别的最小合法流"）+ A′ 若有用例需求再扩 |
| G-RTMP-3 | **chunk 分块与重组未实现**：Set Chunk Size 4096 是"协商了但不用"的装饰；分段由 TCP MSS 决定；消息头 **fmt 1/2/3 与扩展时间戳未实现**；单 chunk > MSS 时第二段起非合法 chunk 起点 | **待实现边界**（今日配置面最大单 chunk 194B < 1460，不触发）；A′ 补例需先扩实现 |
| G-RTMP-4 | **9 个正例无 `packet_count`**（仅 4 例有）；**11 例断言集完全同形**；3 负例 `expect` 含 `notes`（非严格两键）；#8 `notes` 称 payload "100B **随机**"而实现是 **100B 全零**（`rtmp.go:385` `make([]byte, 100)`）；#11 `notes` 称"JSON 往返不可达"需回查 | **P4 必做**：补 `packet_count`（`20+N`）、删负例 `notes`、改写 #8 的错误文案 |
| G-RTMP-5 | **IPv6 今日零用例**（实测引擎已支持：`[ip{2001:db8::1,2001:db8::2},rtmp]` 产 20 包、载荷起点 offset 74） | A′ 补例 `rtmp_ipv6` |
| G-RTMP-6 | **多会话今日零用例**；本协议单连接单事务链，无并发会话面 | A′ 补例（若需求确认多连接场景）或**明确不适用** |
| G-RTMP-7 | **RST 非正常结束补例**（§3.15②后半） | A′ 补例 `rtmp_abort_rst`（`tcp.rst` 框架能力，本层零断言） |
| G-RTMP-8 | **长度类守卫缺失**：`stream_name`/`tc_url` 无长度校验；`amf0String` 2 字节长度前缀无守卫（>65535 静默回绕）；chunk message length 3 字节字段无守卫（>16MB 静默回绕）；`chunk_stream_id` 6 位无守卫（>63 静默截断）；`payload_b64` 非法 base64 **静默丢弃**（`strategy_convert.go:5371-5374` 无 else）；`payload` 与 `payload_b64` 并存时后者优先**无提示** | **P4 裁定**：加守卫（拒绝）或登记为已知行为；至少 `payload_b64` 非法须显式报错（静默落缺省 100B 属**静默假成功**候选） |
| G-RTMP-9 | **`tcp` 层键在本协议链上无效**：`mss`/`initial_seq`/`window_size`/`handshake`/`termination` 实测对 rtmp 链**零影响**（生成器自建全套，`spec.TCP` 恒 nil）；`tcp.mss=100` 被链校验层拒（锚词 `out of range [536,65535]`，**不是 rtmp 锚词**，故 rtmp 的 `TCP.MSS %d too small` 分支链路径不可达）；端口动态在链形下不可达（顶层四元组判死） | **P4 裁定**：registry 的 tcp 层 Fields 对本协议是否应收窄；rtmp validator 的 MSS 分支保留或删 |
| G-RTMP-10 | **缺省端口无独立用例**（16/16 均未写端口，属"隐式覆盖"，非显式断言） | A′ 补例 `rtmp_default_port`（显式断言 1935） |
| G-RTMP-11 | **第三源未取到**（未抓真实 RTMP 服务器 nginx-rtmp/SRS/Wowza 的线字节）；三处语义待确认：connect txnID（spec 示例 0.0 vs 实现 1.0）、S2 第 4-8 字节（spec"服务端当前时间" vs 实现回写 S1 时间戳）、客户端 Window Ack 回显值；**spec 条款号未逐条核对** | **待确认**：抓真实服务器包对照，或查 spec 原文；确认前按实现钉、不声称合规 |
| G-RTMP-12 | **NIC 双输出今日零用例**（16 例 `nic_capture` 全缺） | A′ 或 P4 补 `nic_capture` 开关（§8.2 第 7 条要求 design 声明双输出契约，本文已声明） |
| G-RTMP-13 | **结果文档 pcap 留档目录缺失**：`trafficgen/docs/protocol-pcap-test/rtmp.md`（tracked）写 `Cases: 16 — pass 16, fail 0, error 0`，表格 16 条 `[pcap](rtmp/...)` 链接**全部死链**——`docs/protocol-pcap-test/rtmp/` **目录不存在（0 个 pcap）**。**注意**：该文件末次提交 `9b4ef16`（2026-09-20）**晚于**判死提交 `0417be5`（2026-09-13），故**不属"早于判死提交的过期产物"**（与 opcua G-OPCUA-10/thrift G-THRIFT-10 不同款）；登记的事实仅是"**留档目录缺失**" | **代码阶段**（P5 重跑套件时由 runner 重新落盘该目录）；本版**不删不改**（tracked 产物）；本车道**未跑**该套件，故不以任何形式引用该产物作为套件可跑证据 |

## 15. 修订记录

- v1.0.0（2026-09-29）：P-PIPE #118 文档轨 P1–P3（**as-built 型**）。**本协议无旧稿**（§0：`docs/protocol-designs/` 零 rtmp 命中）；存量 16 例机读审计（**顶层零残留**，本协议无迁移工作量）；5 条 frame + 17 条 field 断言逐条对 **`/tmp/mcp-pcaps/rtmp/`（mtime 2026-09-27，晚于代码末次提交 2026-09-20）** 复核（**全 OK**）；包数公式 `20+N` 与实测 16/16 一致；§12.1/12.3/12.12 强制展开 + 12-P2；D-RTMP-1 as-built 定稿（§11）；缺口 G-RTMP-1…G-RTMP-13。自审见 `/tmp/pipe/doc-lanes/rtmp.md`。

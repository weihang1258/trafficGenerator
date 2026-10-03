# HTTP-FLV（基于 HTTP 的 Flash Video 流）设计契约

> 版本：v3.0.0（已实现）
> 日期：2026-08-24
> 状态：已实现。http_flv 层已注册，http 层实现 EventTransformer 接口，[ip, tcp, http, http_flv] 链完整。
> 配套文件：`docs/protocol-designs/45-http-flv-testcase.md`、`trafficgen/test/protocol_pcap/cases/http-flv.json`
> 规范基线：Adobe Video File Format Specification（FLV，Flash Video 文件格式）、HTTP/1.1（超文本传输协议，RFC 9112/9110）和 AMF0（Action Message Format 0，动作消息格式 0）。

## 1. 范围与边界

HTTP-FLV 是以 HTTP/1.1 传输 FLV 字节流的直播/点播承载方式。它不是独立的 IP 协议：本设计将 `http_flv` 作为 HTTP 上的终结层，复用 http layer 完成 HTTP 帧封装，http_flv layer 只负责生成 FLV header（头）及 tag（标签）的 body 字节。

本阶段覆盖：

- HTTP `GET`、状态行、Host/Content-Type/Connection 等头；
- FLV header、`PreviousTagSize0`、script/audio/video 三类 tag；
- AAC（Advanced Audio Coding，高级音频编码）和 AVC/H.264（高级视频编码）常用 payload 的结构边界；
- 空 tag、最小 tag、最大可接受 tag、截断和长度不一致负例；
- TCP/IPv4、TCP/IPv6、keep-alive（保持连接）、多 session（会话）/多流。

不覆盖：HTTPS/TLS 加密、HTTP/2/HTTP/3、chunked transfer coding（分块传输编码）重组、WebSocket-FLV、RTMP、SPS/PPS 解码、AAC/H.264 编码器、AMF3、播放器时钟同步和真实摄像机采集。HTTPS 可作为未来独立 `tls→tcp→http_flv` 链，不得把加密字节宣称为可观察 FLV 字段。

http_flv 层已注册为 Category=Terminal、DependsOn=http，通过 chain planner 自动补全为 [ip, tcp, http, http_flv]。http 层实现 EventTransformer 接口，将 http_flv 的 FLV body 事件包装为 HTTP GET/200 帧。

## 2. 协议栈、端口和偏移

推荐层链为 `[ip, tcp, http, http_flv]`，http_flv 终结层依赖 http layer 完成 HTTP 请求/响应帧的生成，自身只产出 FLV body 字节作为事件流；IPv4/IPv6 由 source/destination address（源/目的地址）决定，HTTP-FLV payload（载荷）不改变。默认 HTTP destination port（目的端口）为 80（由 http layer 默认），HTTPS 端口 443 需 TLS profile（档案），不在本版明文正例中使用。

无 VLAN、无 IP options（选项）时，固定字节偏移如下：

| 承载 | Ethernet+IP+TCP | HTTP request/response 起点 | FLV 起点 |
|---|---:|---:|---:|
| TCP/IPv4 | 14+20+20=54 | 54（按方向分别计算） | response HTTP 头长度之后，不能硬编码为 54 |
| TCP/IPv6 | 14+40+20=74 | 74 | response HTTP 头长度之后，不能硬编码为 74 |

TCP segment（分段）边界不是 HTTP/FLV message（消息）边界。实现必须按 TCP stream reassembly（流重组）解析完整 HTTP 头，再按 FLV 长度解析 tag；PCAP 的 `packet_count` 只约束明确的 fixture（固定样本），不把一个应用消息错误地等同于一个 TCP 包。

## 3. 线上字节编码

### 3.1 HTTP/1.1

HTTP 帧封装（请求行、响应状态行、Host/Content-Type/Connection 等头、CRLF 序列化）由 http layer 负责，http_flv 层不重复生成 HTTP 字节。http_flv 终结层产生 FLV body 字节事件流（含 response body 中的 FLV header 与各 tag），经 http layer 的 HTTPGenerator 包装成 HTTP request/response 帧。

请求最小形状（由 http layer 配置生成）：

```text
GET /live/stream.flv HTTP/1.1\r\n
Host: example.test\r\n
Connection: keep-alive\r\n
\r\n
```

响应最小直播形状（FLV body 来自 http_flv 层事件）：

```text
HTTP/1.1 200 OK\r\n
Content-Type: video/x-flv\r\n
Connection: keep-alive\r\n
\r\n
```

请求方法必须为 `GET`，URI（统一资源标识符）必须以 `.flv` 结尾或由配置显式允许；HTTP version（版本）首版只接受 `HTTP/1.1`。`Content-Length` 只适合有限点播 fixture；直播响应可省略它并持续发送 FLV tag。头字段大小写不影响语义，但序列化顺序和 CRLF（回车换行）必须稳定，不能使用 LF 替代 CRLF。method/version/URI/headers 均在 http layer 配置上表达，http_flv 配置不再携带。

### 3.2 FLV header 与 tag 总体

FLV header 固定 9 字节，所有整数均为 big-endian（大端序，高位字节在前）：

| 偏移 | 长度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 3 | Signature | ASCII `FLV`，即 `46 4c 56` |
| 3 | 1 | Version | 首版为 `0x01` |
| 4 | 1 | Flags | bit2=audio、bit0=video；其余位必须为 0 |
| 5 | 4 | DataOffset | UI32，首版固定 `9` |

紧随 header 的 `PreviousTagSize0` 为 UI32 BE `0x00000000`。每个 tag 的线上布局为：

```text
TagType(1) DataSize(3) TimestampLower(3) TimestampExtended(1)
StreamID(3) Data(DataSize) PreviousTagSize(4)
```

`TagType`（标签类型）取值 8=audio、9=video、18=script。`DataSize`（数据大小）是 24-bit unsigned（无符号 24 位）且不包含 11 字节 tag header（头）和 4 字节 PreviousTagSize（前一标签大小）；`Timestamp`（时间戳）是 `TimestampExtended<<24 | TimestampLower` 的 32-bit unsigned 毫秒值，`TimestampLower / TimestampExtended` 分别是 24-bit 和 8-bit；`StreamID`（流标识）首版必须为 0。`PreviousTagSize` 必须等于前一个 tag 的完整线上长度；第一个 tag 后的值为 `11 + DataSize`，不是只有 DataSize。

### 3.3 Script tag（脚本标签）

`TagType=18 (0x12)`。默认使用 AMF0：第一个值为 string（字符串）`onMetaData`，第二个值为 ECMA array（ECMA 数组）或 object（对象）。允许配置 width、height、framerate、videocodecid、audiocodecid、duration 等元数据；键的出现顺序必须按配置保持。AMF0 string length 是 UI16 BE，ECMA array count 是 UI32 BE，object 以 `00 00 09` 结束。实现不得把 JSON 文本直接当成合法 AMF0。

### 3.4 Audio tag（音频标签）

`TagType=8 (0x08)`，Data 首字节为 SoundFormat(4 bits)、SoundRate(2 bits)、SoundSize(1 bit)、SoundType(1 bit)。AAC 时 SoundFormat=`10`，后跟 AACPacketType（0=sequence header，1=raw AAC）；sequence header 的 AudioSpecificConfig（音频特定配置）必须由显式 profile 或字节字段提供，不能由 planner 猜测采样率。非 AAC 音频只在未来显式 profile 中加入，不能把任意 payload 标成 AAC。

### 3.5 Video tag（视频标签）

`TagType=9 (0x09)`，Data 首字节为 FrameType(4 bits) 和 CodecID(4 bits)。AVC/H.264 时 CodecID=`7`，随后为 AVCPacketType（0=sequence header，1=NALU，2=end of sequence）和 signed 24-bit CompositionTime（合成时间，毫秒）。sequence header 的 AVCDecoderConfigurationRecord（AVC 解码器配置记录）和 NALU 的长度/起始码由配置明确给出；本 planner 不解码 SPS/PPS，也不从任意字节推断 CodecID。

## 4. 状态机和包序列

一个单 session 的推荐状态机为：

```text
TCP SYN/SYN-ACK/ACK
  → HTTP GET（客户端到服务端）
  → HTTP 200 + FLV header + PreviousTagSize0（服务端到客户端）
  → [script/audio/video tag + PreviousTagSize]*
  → keep-alive 等待更多 tag 或 HTTP/TCP termination（终止）
```

HTTP GET 必须先于 response；response 必须先于 FLV header；header 必须先于第一个 tag。多 session 时每条 TCP 连接独立拥有 URI、HTTP header、FLV timestamp 和 tag 序列，不得跨连接复用 PreviousTagSize 或时间戳状态。多流只表示多个独立 HTTP-FLV GET，不代表在一个 FLV tag 内交错两个 stream ID；首版每条流的 StreamID 恒为 0。

建议的未来 fixture 包序列（实际 TCP ACK 合并后 packet_count 以实现复核为准）：

1. TCP handshake 3 包；
2. HTTP GET 1 个应用方向 payload；
3. HTTP 200 + FLV header + PreviousTagSize0；
4. 显式 script/audio/video tags；
5. keep-alive 时继续同一连接上的第二组 tag，否则 FIN/ACK termination。

## 5. 配置 typedef（类型定义）

已实现为以下 Go struct（结构体），位于 `trafficgen/internal/core/types.go`：

```go
type HTTPFLVConfig struct {
    Flags     uint8    `json:"flags,omitempty"`      // audio=0x04, video=0x01; 0 → 0x05 (both)
    Tags      []FLVTag `json:"tags,omitempty"`       // 空 → 默认模板 (onMetaData + AAC + AVC)
    Rounds    int      `json:"rounds,omitempty"`     // HTTP GET/200 轮数；0 → 1
    WireFault string   `json:"wire_fault,omitempty"` // negative test only
}

type FLVTag struct {
    Type                 string  `json:"type,omitempty"`                   // script/audio/video
    Timestamp            uint32  `json:"timestamp,omitempty"`
    Data                 []byte  `json:"data,omitempty"`
    DataSizeOverride     *uint32 `json:"data_size_override,omitempty"`     // negative test only
    PreviousSizeOverride *uint32 `json:"previous_size_override,omitempty"` // negative test only
}
```

默认模板（Flags=0x05, Tags=[script onMetaData, audio AAC, video AVC], Rounds=1）在 chain_planner translateTerminalConfig 中应用。

Method/URI/Version/RequestHeaders/ResponseHeaders/KeepAlive 已上移到 http layer 配置，由 http layer 的 HTTPGenerator 负责 HTTP 帧；http_flv 配置只保留 FLV 语义字段（Flags/Tags/Rounds/WireFault）。实现必须对 method、version、URI、sessions/streams、flags、tag type、DataSize、timestamp、PreviousTagSize 和 payload 编码做 Validate（校验）。`wire_fault` 只允许测试注入，不能成为合法线上字段或被忽略。

## 6. 错误处理

错误必须从 planner/validator 经 engine（引擎）传播为 task error（任务错误）终态，不能 completed（完成）但 0 包。至少拒绝：

| 错误 | 稳定错误锚点 |
|---|---|
| 缺失/错误 HTTP method、version 或 URI | `http` 或 `method`/`version`/`uri` |
| response 不是 2xx、缺少 Content-Type 或 FLV body | `response`/`content-type`/`flv` |
| FLV signature/version/flags/DataOffset 错误 | `signature`/`version`/`flags`/`data offset` |
| tag header 少于 11 字节、DataSize 越过 stream | `tag`/`data size`/`truncated` |
| PreviousTagSize 与前 tag 长度不一致 | `previous tag`/`length` |
| AAC/AVC type-specific data 缺失或长度非法 | `audio`/`video`/`codec` |
| sessions/streams 小于 1、跨 session 状态串用 | `session`/`stream` |
| IPv4/IPv6 地址非法或 TCP 载体缺失 | `tcp`/`address` |

合法的 HTTP 4xx/5xx response 可作为未来“服务端错误响应”正例，但它不是 planner Validate 失败；本版不生成服务端业务错误。

## 7. IPv4/IPv6、多会话和边界

IPv4 外层使用 Ethernet type `0x0800`，FLV 应用起点按 TCP stream 重组；IPv6 外层使用 `0x86dd`，TCP Next Header（下一头）为 6。应用层字段和 tag 字节在两种地址族中必须相同，不能因为 IPv6 而改变 DataOffset、DataSize 或 PreviousTagSize。

空 tag 指 `DataSize=0`，线上仍有 11-byte tag header 和 4-byte PreviousTagSize；最小合法 script/audio/video tag 由各自最短 data 定义，不能把“只有 TagType”当作合法 tag。DataSize 最大受 UI24 上限 `0xffffff` 与实现内存/单 tag 上限共同约束；测试只使用明确可分配的边界值，不能分配全部 16 MiB 作为默认回归。截断、声明长度超过实际数据、PreviousTagSize 错误均必须失败。

## 8. 实现集成点

实现要点：

1. 在 layer registry（层注册表）登记 `http_flv` 为 Category=Terminal、DependsOn=`http`，并让 chain planner（层链规划器）自动补全 `ip→tcp→http` — **已完成**（`registry.go:223`）；
2. 在 `core/types.go` 增加 `HTTPFLVConfig`（Flags/Tags/Rounds/WireFault）和 `FLVTag`，在 strategy converter（策略转换器）解析 flat key 和 `layers` payload — **已完成**（`types.go:201`）；
3. 新增 http_flv 终结层 generator（生成器），以 FLV body 字节事件流形式产出，经 http layer 的 HTTPGenerator 包装成 HTTP request/response 帧 — **已完成**（`http_flv/planner.go` + `http/layer_gen.go` generateTransformer）；
4. FLV parser 以 DataSize/PreviousTagSize 校验，不能按 TCP packet 边界切消息 — **已完成**（`http_flv/builder.go`）；
5. 将 planner 错误接到 task 生命周期 — **已完成**（validator 注册于 `http_flv/planner.go:init()`）；
6. 使用 tshark（抓包解析器）注册字段或原始 frame 断言验证：`http.request.method`、`http.request.uri`、`http.response.code`、`http.content_type`；FLV 字段若 tshark 没有稳定解析器，使用 FLV 起点的 `frames` 断言，不伪造字段名 — **已完成**（`http-flv.json` 15 个语义用例覆盖）。

## 9. 与 testcase 映射及完成定义

`45-http-flv-testcase.md` 与语义 JSON 按下列 15 个原子 ID、同一顺序维护。http_flv 已注册，http-flv.json 已替换为 15 个语义用例（12 正例 + 3 负例）。

| # | ID | 类型 | 覆盖 |
|---:|---|---|---|
| 1 | `http_flv_get_header` | 正 | IPv4/TCP、GET、URI、Host、HTTP/1.1 |
| 2 | `http_flv_header_flags` | 正 | 200、Content-Type、FLV header、PreviousTagSize0 |
| 3 | `http_flv_script_tag` | 正 | AMF0 onMetaData script tag、UI16/UI32 长度 |
| 4 | `http_flv_audio_aac` | 正 | AAC sequence header/raw tag、SoundFormat=10 |
| 5 | `http_flv_video_avc` | 正 | AVC sequence header/NALU、CompositionTime |
| 6 | `http_flv_empty_tag` | 正 | DataSize=0、11+4 字节线上边界 |
| 7 | `http_flv_minimal_tags` | 正 | script/audio/video 最小合法 data |
| 8 | `http_flv_tag_boundary` | 正 | UI24 DataSize 边界、PreviousTagSize 全长 |
| 9 | `http_flv_keep_alive` | 正 | 同一连接第二组 tag、状态不重置 |
| 10 | `http_flv_multi_session` | 正 | 多 TCP session、URI/timestamp/PreviousTagSize 隔离 |
| 11 | `http_flv_ipv6` | 正 | IPv6/TCP 外层、应用字节语义不变 |
| 12 | `http_flv_multi_stream` | 正 | 多 stream 映射为独立 GET/session、StreamID=0 |
| 13 | `http_flv_neg_truncated_tag` | 负 | HTTP/FLV body 截断或 tag header 越界 |
| 14 | `http_flv_neg_length_mismatch` | 负 | DataSize 或 PreviousTagSize 不一致 |
| 15 | `http_flv_neg_validate` | 负 | method/version/flags/session 或 TCP carrier 非法 |

完成定义：

- `http_flv` 层已注册且依赖 http（通过 chain planner 自动补全 `ip→tcp→http`）— **已验证**；
- HTTP request/response 状态机、FLV header/tag 逐字节生成 — **已验证**；
- DataSize、timestamp、PreviousTagSize、AMF0/AAC/AVC 边界有单测和 PCAP 断言 — **已验证**；
- TCP stream 跨分段重组、keep-alive、多 session、IPv4/IPv6 均有集成测试 — **已验证**；
- 所有负例真正传播为任务错误 — **已验证**。

## 10. 修订记录

- v3.0.0（2026-08-24）：实现完成；http_flv 层注册、http EventTransformer、默认模板、Rounds 语义全部落地。
- v2.0.0（2026-08-24）：重构 layer chain 为 `[ip, tcp, http, http_flv]`，http_flv 终结层依赖 http layer 完成 HTTP 帧封装，自身只产出 FLV body 字节事件流；Method/URI/Version/Headers/KeepAlive 上移至 http layer 配置。
- v1.0.0（2026-08-20）：建立 HTTP-FLV over HTTP/1.1 设计契约，覆盖 HTTP、FLV header/tag、AMF0、AAC、AVC、状态机、边界、双栈和未注册实现边界；不修改 Go 实现。

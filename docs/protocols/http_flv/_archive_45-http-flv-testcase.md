# HTTP-FLV（基于 HTTP 的 Flash Video 流）测试用例设计

> 版本：v3.0.0（已实现）
> 日期：2026-08-24
> 配套设计：`docs/protocol-designs/45-http-flv-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/http-flv.json`
> 状态：http_flv 层已注册；当前 JSON 包含 15 个语义用例（12 正例 + 3 负例）。

## 1. 原则、证据和执行边界

本套件由设计文档 §2–§8 的每个字段/错误行派生，共 15 个原子 case（用例）：12 个正例、3 个负例。正例需要 `packet_count`、`fields`、`frames` 至少各一项；负例只允许 `expect_error` 和 `error_contains`，不能用 0 包或空 PCAP（抓包文件）冒充错误。

验证优先使用 tshark（抓包解析器）已注册的 HTTP/TCP/IP 字段：`http.request.method`、`http.request.uri`、`http.request.version`、`http.response.code`、`http.content_type`、`http.connection`、`tcp.dstport`、`tcp.srcport`、`tcp.stream`、`ip.version`、`ipv6.nxt`。FLV parser（解析器）字段是否在 tshark 版本中注册不可假定；FLV `46 4c 56`、header、tag header 和 length 统一用 `frames` 原始字节断言。动态 TCP sequence（序列号）、HTTP header 分段和 tag timestamp（时间戳）不写死在 packet index（包序）中，除非 fixture 明确固定。

无 VLAN、无 IP options 时，HTTP 应用载荷起点为 TCP/IPv4 offset（偏移）54、TCP/IPv6 offset 74。FLV 起点必须由 HTTP response header 的 CRLF 空行结束位置计算：示例 response header 以 `HTTP/1.1 200 OK`、`Content-Type: video/x-flv`、`Connection: close` 序列化时长度为 65，因此 FLV 起点为 IPv4 119、IPv6 139；实现若改变 header 顺序/字段，需同步 frame offset。

## 2. Case 索引

| # | ID | 类型 | 覆盖 | packet_count |
|---:|---|---|---|---:|
| 1 | `http_flv_get_header` | 正 | TCP/IPv4、GET `/live/test.flv`、HTTP/1.1、Host | 9 |
| 2 | `http_flv_header_flags` | 正 | 200、Content-Type、FLV signature/version/flags/DataOffset/PreviousTagSize0 | 9 |
| 3 | `http_flv_script_tag` | 正 | AMF0 `onMetaData` script tag、DataSize、PreviousTagSize | 9 |
| 4 | `http_flv_audio_aac` | 正 | AAC sequence header + raw audio、SoundFormat/PacketType | 9 |
| 5 | `http_flv_video_avc` | 正 | AVC sequence header + NALU、FrameType/CodecID/CompositionTime | 9 |
| 6 | `http_flv_empty_tag` | 正 | `DataSize=0` 空 tag 仍含 11+4 字节 | 9 |
| 7 | `http_flv_minimal_tags` | 正 | script/audio/video 各自最小合法 payload | 9 |
| 8 | `http_flv_tag_boundary` | 正 | 可分配边界 DataSize、24-bit 长度和 PreviousTagSize | 9 |
| 9 | `http_flv_keep_alive` | 正 | 两个 GET/response transaction、同 TCP stream、tag 持续 | 11 |
| 10 | `http_flv_multi_session` | 正 | 两条独立 TCP session、状态/时间戳/URI 隔离 | 9 |
| 11 | `http_flv_ipv6` | 正 | TCP/IPv6、Next Header=6、FLV bytes 与 IPv4 相同 | 9 |
| 12 | `http_flv_multi_stream` | 正 | 多 stream 配置映射为独立 GET/session，StreamID=0 | 9 |
| 13 | `http_flv_neg_truncated_tag` | 负 | tag header/data 截断 | — |
| 14 | `http_flv_neg_length_mismatch` | 负 | DataSize 或 PreviousTagSize 不一致 | — |
| 15 | `http_flv_neg_validate` | 负 | method/version/flags/session 或 TCP carrier 非法 | — |

## 3. 当前 JSON 状态

当前 JSON 已包含 15 个语义用例（12 正例 + 3 负例），不再需要未注册占位。

## 4. 未来正例的逐项可观察断言

以下是实现 `http_flv` 后必须落入 JSON 的原子断言。这里的 packet index 仅在对应 fixture 固定 TCP segmentation（分段）时有效；字段观察与 raw frame（原始帧）前缀必须同时存在。

1. **`http_flv_get_header`**：请求包观察 `tcp.dstport=80`、`http.request.method=GET`、`http.request.uri=/live/test.flv`、`http.request.version=HTTP/1.1`；raw frame 从 IPv4 offset 54 固定 `47 45 54 20 2f 6c 69 76 65 2f 74 65 73 74 2e 66 6c 76 20 48 54 54 50 2f 31 2e 31 0d 0a`（`GET /live/test.flv HTTP/1.1\r\n`）。
2. **`http_flv_header_flags`**：response 观察 `http.response.code=200`、`http.content_type=video/x-flv`、双向 `http.connection`；FLV raw frame 在 response header 结束后固定 `46 4c 56 01 05 00 00 00 09 00 00 00 00`，即 signature、version、audio+video flags、DataOffset=9、PreviousTagSize0=0。
3. **`http_flv_script_tag`**：观察 response 的 FLV 起点后 `TagType=0x12`、24-bit DataSize、timestamp 和 `PreviousTagSize=11+DataSize`；frame 至少固定 `12` 与 AMF0 string marker `02`、`00 0a 6f 6e 4d 65 74 61 44 61 74 61`（`onMetaData`），不把可变 ECMA 属性顺序伪装成固定。
4. **`http_flv_audio_aac`**：观察 `TagType=0x08`、data 首字节 SoundFormat=10、后续 AACPacketType=0/1；frame 固定 `08` 与 `a0`（示例 SoundRate=3、16-bit、stereo、AAC sequence header）以及 `PreviousTagSize` 可复算。
5. **`http_flv_video_avc`**：观察 `TagType=0x09`、data 首字节 CodecID=7、AVCPacketType=0/1、CompositionTime 为 signed 24-bit；frame 固定 `09` 与 `17 00 00 00`（keyframe+AVC sequence header、composition time 0）及末尾 PreviousTagSize。
6. **`http_flv_empty_tag`**：观察 `DataSize=0` 且 packet 仍含 11-byte tag header+4-byte PreviousTagSize；frame 固定 `12 00 00 00 00 00 00 00 00 00 00 00 00 00 0b`（示例 script empty tag，timestamp/stream=0，前一 tag size=11）。
7. **`http_flv_minimal_tags`**：三个 tag 各自至少观察 tag type、DataSize、timestamp、PreviousTagSize；script 最小 AMF0 结束对象、audio 最小 AAC sequence header、video 最小 AVC sequence header 必须分别有 raw frame 前缀，不以"有 FLV bytes"替代三种分支。
8. **`http_flv_tag_boundary`**：观察 DataSize 的高/低 24-bit 组合和上一标签总长；至少一个长度大于 65535 且小于实现 max tag bytes，frame 固定 3-byte DataSize；禁止只测试 8-bit 长度。
9. **`http_flv_keep_alive`**：观察同一 `tcp.stream` 中两次 HTTP GET/200，`http.connection=keep-alive`，第二组 FLV tag timestamp 不回退；每组 response FLV header 只出现一次，frame 分别断言第二 transaction 的 GET 与第二组 tag。
10. **`http_flv_multi_session`**：观察 `tcp.stream` 至少两个 distinct values（不同值），两个请求 URI/Host 和 response 200 均存在；各 stream 的第一 tag `PreviousTagSize0=0`，不可用跨 session 的同一 tag 状态通过断言。
11. **`http_flv_ipv6`**：观察 `ipv6.nxt=6`、`tcp.dstport=80`、HTTP GET/200；IPv6 TCP payload 起点 74，FLV header offset 139（以本文 §1 示例 response header 为准），raw bytes 与 IPv4 例的 `46 4c 56 01 05 00 00 00 09` 相同。
12. **`http_flv_multi_stream`**：观察至少两个独立 `tcp.stream` 与 GET URI；每一流 FLV tag 的 StreamID 三字节为 `00 00 00`，frame 断言每流 tag type/data size，不能把 streams 数量编码成 FLV StreamID。

## 5. 负路径逐项契约

| ID | 输入故障 | 唯一允许的执行期断言 |
|---|---|---|
| `http_flv_neg_truncated_tag` | tag header 少于 11B、或 DataSize 超过剩余 body | `expect_error=true`, `error_contains=truncated` 或 `tag` |
| `http_flv_neg_length_mismatch` | DataSize/PreviousTagSize 与实际长度不符 | `expect_error=true`, `error_contains=length` 或 `previous tag` |
| `http_flv_neg_validate` | method 非 GET、HTTP/1.0、flags 保留位、sessions=0、缺 TCP 或非法地址 | `expect_error=true`, `error_contains` 对应稳定 validator 锚点 |

## 6. 覆盖清单与三方一致性

| 设计要求 | 覆盖 ID | 证据类型 | 当前状态 |
|---|---|---|---|
| HTTP GET/Host/HTTP/1.1 | 1, 9, 10, 11, 12 | tshark HTTP fields + request frame | 已实现 |
| FLV signature/header/flags/DataOffset | 2 | response fields + raw frame | 已实现 |
| script/audio/video tag | 3, 4, 5, 7 | type-specific fields + frame | 已实现 |
| 空/最小/24-bit 边界 tag | 6, 7, 8 | DataSize/PreviousTagSize + frame | 已实现 |
| 截断/非法长度 | 13, 14 | task error | 已实现 |
| keep-alive/多会话/多流 | 9, 10, 12 | tcp.stream/HTTP fields + frames | 已实现 |
| IPv4/IPv6 | 1–2, 11 | ip.version/ipv6.nxt + offsets | 已实现 |
| Validate 负路径 | 13–15 | error propagation | 已实现 |

ID 闭环规则：设计文档 §9、本文 §2 索引和 JSON/audit 必须使用同一 15 个语义 ID。

## 7. 执行顺序

1. 运行 JSON parser、ID/expect 结构、fields 注册和 frame offset 静态检查。
2. 先运行 `http_flv_get_header`、`http_flv_header_flags`，确认 HTTP stream 重组和 FLV 起点。
3. 逐项运行 script/audio/video、空/最小/边界、keep-alive、多 session/stream、IPv6。
4. 注入截断、长度不一致和 Validate 错误，确认 planner→engine→task error，不能 completed 但 0 包。
5. 运行 `-race` 和 suite。

## 8. 修订记录

- v3.0.0（2026-08-24）：实现完成；http_flv 层已注册，JSON 替换为 15 个语义用例，覆盖状态更新为"已实现"。
- v2.0.0（2026-08-24）：更新层链为 `[ip, tcp, http, http_flv]`，JSON 占位用例从 `[tcp, http_flv]` 改为 `[http, http_flv]`。
- v1.0.0（2026-08-20）：建立 15 个 HTTP-FLV 原子用例和覆盖清单；当前 JSON 仅保留未注册层的严格错误占位，不修改 Go 实现。
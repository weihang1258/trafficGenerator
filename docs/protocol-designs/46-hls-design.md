# HLS（HTTP Live Streaming，HTTP 实时流媒体）设计文档

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：✅ 已实现（24/24 PCAP 测试通过）
> 配套文件：`docs/protocol-designs/46-hls-testcase.md`、`trafficgen/test/protocol_pcap/cases/hls.json`
> 规范基线：RFC 8216（HTTP Live Streaming）、Apple HTTP Live Streaming 规范；LL-HLS（Low-Latency HLS，低延迟 HLS）按 Apple 扩展作为可选边界。

## 1. 范围、实现状态和承载边界

HLS 是通过 HTTP（超文本传输协议）GET 获取 playlist（播放列表）和 media segment（媒体分片）的应用协议。本设计覆盖 master playlist（主播放列表）、media playlist（媒体播放列表）、MPEG-TS（MPEG 传输流）/fMP4（fragmented MP4，分片 MP4）分片、加密 key（密钥）、live sliding window（直播滑动窗口）以及 LL-HLS 的可选标签；不实现编码器、音视频解码器、真实时间源或 CDN（内容分发网络）缓存策略。

已实现 `hls` layer（层）和 planner，`[ip, tcp, http, hls]` 层链模式。HTTP 层担任 EventTransformer，将 HLS 的 playlist/segment/key body 事件包装为 HTTP GET/200 响应。24 个 PCAP 测试用例全部通过。

下表 `hls_http1`、`hls_https`、`hls_http2_boundary`、`hls_ipv6` 是承载 profile 名，不是 case ID，不计入 §8 的 24 个三方 ID。

承载矩阵：

| profile | 传输 | 默认端口 | 说明 |
|---|---|---:|---|
| `hls_http1` | TCP + HTTP/1.1 | 80 | 明文 GET、响应 body（正文）中的 playlist/segment |
| `hls_https` | TCP + TLS + HTTP/1.1 | 443 | 未提供解密密钥时只能观察 TCP/TLS/HTTP 外层，不能断言明文 playlist |
| `hls_http2_boundary` | TCP + TLS + HTTP/2 | 443 | 仅作为未来边界；当前不生成 HTTP/2 frame |
| `hls_ipv6` | IPv6 + TCP + HTTP | 80/443 | outer IP（外层 IP）地址族与 playlist 内容地址独立 |

无 VLAN（虚拟局域网）、无 IPv4 options、无 TCP options 的 HTTP/1.1 明文请求 payload 起点为 IPv4 offset 54（Ethernet 14 + IPv4 20 + TCP 20），IPv6 为 offset 74（14 + 40 + 20）。TCP MSS（最大报文段）分段不能改变 HTTP message（消息）重组后的正文语义。

## 2. 配置 typedef（类型定义）

推荐配置外形如下。顶层网络键遵循公共 IP/TCP/HTTP 层；HLS 语义位于 `hls` map（映射）中。

```json
{
  "layers": [{"tcp": {}}, {"http": {}}, {"hls": {}}],
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.20",
  "src_port": 40000,
  "dst_port": 80,
  "hls": {
    "profile": "rfc8216_v7",
    "sessions": [{
      "kind": "master",
      "uri": "/live/master.m3u8",
      "variants": [{"uri": "/live/low.m3u8", "bandwidth": 800000, "resolution": "640x360"}]
    }]
  }
}
```

配置键约束：

| 键 | 类型/约束 | 语义 |
|---|---|---|
| `profile` | `rfc8216_v7`、`apple_ll_hls` | 选择 RFC 8216 基线或明确启用 LL-HLS；不由 URI 猜测 |
| `sessions` | 有序 session（会话）数组 | 每个 `session_id` 代表一条独立 4-tuple（四元组）和事件序列；相同会话的 master/media/key/segment 事件必须共享状态，不同会话不得串用 |
| `kind` | `master`、`media`、`refresh`、`segment`、`key` | 事件类别；`refresh` 只刷新已存在的 live media playlist |
| `session_id` | 非空字符串（可选） | 事件所属会话；缺省时使用单一默认会话；不同 ID 必须通过事件级 `src_port` 或地址形成不同 4-tuple |
| `src_port` | 1–65535（事件级可选） | 覆盖该事件所属会话的源端口；同一 `session_id` 必须保持不变 |
| `uri` | 非空 URI-reference（URI 引用） | playlist/segment/key 资源 URI；可为相对 URI 或绝对 URI，解析后 HTTP request-target 必须为 path-absolute，不得包含未转义空格或控制字节 |
| `base_uri` | 可选 URI-reference | 解析相对 playlist/segment/key URI 的基准；未提供时使用当前 playlist URI 的目录 |
| `method` | 当前固定 `GET` | HLS 资源使用 GET；其他 method 必须拒绝或由 HTTP 层独立处理 |
| `playlist_type` | `master`、`media` | body 语法 profile；不能将 master 标签放进 media playlist |
| `playlist_mode` | `EVENT`、`VOD`（可选） | `#EXT-X-PLAYLIST-TYPE` 的生命周期语义；仅 media playlist 可用 |
| `target_duration` | 正整数秒 | `#EXT-X-TARGETDURATION`；必须不小于每个媒体分片的 `EXTINF` 四舍五入值 |
| `media_sequence` | 非负整数 | `#EXT-X-MEDIA-SEQUENCE`；live refresh 只能单调不减，除非显式 discontinuity/reset profile |
| `segments` | 有序分片数组 | 每项含 `uri`、`duration`，可选 `title`、`byte_range`、`key_ref`、`discontinuity`、`program_date_time` |
| `parts` | LL-HLS 部分分片数组 | 每项含 `uri`、正 `duration`，可选 `independent`；仅 `apple_ll_hls` |
| `preload_hint` | LL-HLS 预加载对象 | `type` 和 `uri`；仅 `apple_ll_hls` |
| `map` | fMP4 初始化段对象 | `uri` 和可选 `byte_range`，必须在首个 media segment 前 |
| `independent_segments` | 布尔 | 生成 `#EXT-X-INDEPENDENT-SEGMENTS` |
| `discontinuity_sequence` | 非负整数 | `#EXT-X-DISCONTINUITY-SEQUENCE` 基线 |
| `endlist` | 布尔 | 为 true 时生成 `#EXT-X-ENDLIST`，仅有限 media/VOD |
| `body` | 字符串（仅负例） | 直接指定/截断 playlist body，用于 malformed fixture |
| `response_status_code` | HTTP 状态码（可选） | 合法业务错误响应（404/410/429/5xx），不等同 planner error |
| `response_content_type` | 字符串（可选） | segment/map/key 响应的 Content-Type；未声明时按资源类型推导 |
| `response_body` | 字符串（可选） | 资源响应正文；需要二进制时使用 base64 表示 |
| `response_body_b64` | Base64 字符串（可选） | 资源响应二进制正文；优先于 `response_body` |
| `variants` | master variant 数组 | 每项至少有 URI 和 `bandwidth`；`CODECS`、`RESOLUTION` 等属性按声明原样编码 |
| `renditions` | `AUDIO`/`VIDEO`/`SUBTITLES`/`CLOSED-CAPTIONS` | `EXT-X-MEDIA` 关联组；URI 缺省时不伪造 media playlist 请求 |
| `key` | `method`、`uri`、可选 `iv`、`format` | AES-128（高级加密标准 128 位）key URI/IV；`METHOD=NONE` 禁止同时带 URI/IV |
| `byte_range` | `length` 正整数、`offset` 非负整数；同一资源必须有确定的 `resource_length` | 映射 `#EXT-X-BYTERANGE:length[@offset]`；同一 URI 的隐式 offset 依赖上一分片结束位置，且 `offset+length` 不得超过资源长度 |
| `resource_length` | 非负整数（使用 byte_range 时必填） | 为每个资源提供确定性总长度，使 206/Content-Range 和越界校验可执行 |
| `resource_responses` | 有序 segment/map/key 响应事件数组（可选） | 仅用于设计期把 playlist 引用与 HTTP 资源响应的 status、Content-Type、body 关联起来 |
| `live` | `window`、`refresh_count`、`refresh_interval` | 直播窗口刷新；刷新次数和间隔显式，不由 planner 无限生成 |
| `ll_hls` | `parts`、`part_target`、`server_control`、`preload_hint`、`skip`、`report` | 仅 `apple_ll_hls` 可用；`part_target` 映射 `#EXT-X-PART-INF:PART-TARGET`，`server_control` 映射 `#EXT-X-SERVER-CONTROL`，未声明 profile 时拒绝 LL 标签 |
| `wire_fault` | 仅负例 | `empty_body`、`truncate`、`bad_tag`、`bad_length`、`sequence_regress`、`invalid_uri`、`key_mismatch`、`discontinuity_sequence` 等注入故障 |

动态值（播放序号、session ID、HTTP Date、IV 缺省值）不能在 PCAP `frames` 中固化为随机常量。显式 fixture（固定样本）可以提供 `media_sequence`、`IV` 和 URI，以便验证字节契约。

## 3. HTTP playlist 交互和状态机

一个基本 master 会话是：

```text
TCP SYN → HTTP GET /master.m3u8 → 200 application/vnd.apple.mpegurl
       → 解析 EXT-X-STREAM-INF → HTTP GET /variant.m3u8
       → 200 media playlist → GET segment/key → 200 body
```

media live 会话是：

```text
GET media.m3u8(seq=N) → 200 window[N..N+k]
→ 等待 refresh_interval → GET media.m3u8(seq=N+1)
→ 窗口前移、旧 segment 淘汰 → 可选 ENDLIST 终止
```

状态机：

| 状态 | 允许事件 | 转移/不变式 |
|---|---|---|
| `Idle` | `master`/`media` GET | 建立 HTTP session；响应必须有 status、Content-Type 和 body |
| `MasterReady` | `variant`/`rendition` GET | `EXT-X-STREAM-INF` 下一行 URI 与请求目标关联；变体 bandwidth>0 |
| `MediaReady` | `segment`/`key`/`refresh` | media sequence、target duration 和分片顺序有效；key 引用可解析 |
| `LiveWindow` | `refresh`、`segment` | sequence 不回退；窗口按显式 count/interval 前移；不能静默补分片 |
| `Ended` | `ENDLIST` 后关闭/重复 GET | `#EXT-X-ENDLIST` 后不再生成新的 live sequence；重复请求可返回同一终态 fixture |
| `Error` | malformed body、非法 tag、关联缺失 | planner/validator 返回 task error；不得 completed/0 packet 假成功 |

HTTP 响应错误（404、410、429、5xx）是应用会话的合法错误事件，可作为独立测试 profile；配置非法、playlist 线格式错误和状态回退必须是任务错误，二者不可混淆。

## 4. Playlist 线格式与 EXT-X 标签

playlist 必须以 UTF-8 文本 `#EXTM3U` 开始；每行最多一个标签或 URI。未知标签可按 RFC 8216 的客户端兼容规则忽略，但本实现对配置中明确支持的标签必须严格校验参数、顺序和关联。

### 4.1 Master playlist

master 至少包含一组 `#EXT-X-STREAM-INF`，其属性行后紧跟 variant URI。关键标签：

- `#EXT-X-VERSION:n`：协议版本；不低于使用特性的要求。
- `#EXT-X-STREAM-INF:BANDWIDTH=...[,AVERAGE-BANDWIDTH=...][,CODECS=...][,RESOLUTION=WxH][,FRAME-RATE=...]`：variant 属性；`BANDWIDTH` 必须为正整数。
- `#EXT-X-MEDIA:TYPE=...,GROUP-ID="...",NAME="...",DEFAULT=YES|NO,AUTOSELECT=YES|NO[,URI="..."]`：音轨/字幕等 rendition。
- `#EXT-X-INDEPENDENT-SEGMENTS`：可出现在 master 或 media playlist；`#EXT-X-I-FRAMES-ONLY` 仅属于 media playlist，不能写入 master。

### 4.2 Media playlist

media playlist 的 segment entry 通常为 `#EXTINF:duration[,title]` 后跟 URI。标签约束：

- `#EXT-X-TARGETDURATION:n` 必须出现且为正整数；每个分片 duration 按 RFC 8216 取最近整数（`.5` ties-to-nearest 的边界按规范实现保持一致）不得超过 n。
- `#EXT-X-MEDIA-SEQUENCE:n` 指定第一分片序号；默认 0 仅在显式 profile 允许时使用。
- `#EXT-X-DISCONTINUITY-SEQUENCE:n` 为跨 discontinuity 的序号基线；不能把普通 sequence 变更伪装为 discontinuity。
- `#EXT-X-DISCONTINUITY` 标记编码参数、时间基或媒体格式边界；必须位于受影响分片之前。
- `#EXT-X-PROGRAM-DATE-TIME:date-time` 使用 ISO-8601；连续分片的时间关系保持一致。
- `#EXT-X-PLAYLIST-TYPE:EVENT|VOD` 与 `#EXT-X-ENDLIST`：VOD 终止；EVENT 可追加但不得回退历史窗口。
- `#EXT-X-INDEPENDENT-SEGMENTS`、`#EXT-X-MAP:URI="..."[,BYTERANGE="..."]`：fMP4 初始化段关联。
- `#EXT-X-BYTERANGE:length[@offset]`：长度不可为 0，offset 不得越过资源长度；隐式 offset 只能接续同 URI 的上一 range。
- `#EXT-X-KEY:METHOD=NONE` 或 `METHOD=AES-128,URI="..."[,IV=0x...]`：加密状态从该行作用到下一 key；`METHOD=NONE` 清除继承状态。

### 4.3 LL-HLS 边界

LL-HLS 仅在 `apple_ll_hls` profile 中可用：

- `#EXT-X-PART-INF:PART-TARGET=...`：LL-HLS media playlist 必须声明正的 part target，且每个 `EXT-X-PART` duration 不得超过该值；仅 `apple_ll_hls` profile。 
- `#EXT-X-PART:DURATION=...[,URI="..."],INDEPENDENT=YES|NO`：partial segment（部分分片）；duration>0，URI 必须可关联。
- `#EXT-X-PRELOAD-HINT:TYPE=PART|MAP,URI="..."[,BYTERANGE-START=...][,BYTERANGE-LENGTH=...]`：预加载提示；不得与已完成 part 重复。
- `#EXT-X-SERVER-CONTROL:CAN-SKIP-UNTIL=...[,PART-HOLD-BACK=...][,HOLD-BACK=...]`：服务端控制参数需满足 target duration 关系。
- `#EXT-X-RENDITION-REPORT:URI="...",LAST-MSN=...[,LAST-PART=...]`：跨 rendition 进度报告。
- `#EXT-X-SKIP:SKIPPED-SEGMENTS=n`：只能在支持 delta update（增量更新）且窗口仍可重建时使用。

本版不生成 HTTP/2 blocking reload、QUIC（快速 UDP Internet 连接）/HTTP/3 或未注册的 Apple 私有标签；这些是实现后独立扩展，不得静默降级为普通 `EXTINF`。

## 5. 媒体分片、byterange 和加密

分片 body 可以是 MPEG-TS 或 fMP4。HLS planner 只负责声明 HTTP 资源和确定性 bytes（字节）；不验证音视频帧语义。每个 segment 响应必须有与资源类型匹配的 `Content-Type`（例如 `video/mp2t` 或 `video/mp4`）以及可选 Content-Length。playlist 中的 URI 按原样作为相对 URI 解析，不能把 query 或 percent-encoding（百分号编码）错误解码后再发送。

`EXT-X-BYTERANGE` 的有效性：

1. length 是正整数；显式 offset 非负；`offset+length` 不溢出资源长度。
2. 无 offset 时，前一个 range 必须使用同一 URI，当前 offset 等于前一个 offset+length；跨 URI 时必须显式 offset。
3. range 不能重叠，除非实现另设缓存/重复读取 profile；本版默认拒绝重叠。
4. HTTP 响应可带 `206 Partial Content`、`Content-Range`；playlist 的 byte range 与 HTTP range 必须一致。

AES-128 规则：

- `METHOD=AES-128` 时 URI 必须非空，GET key 后返回 16-byte key；`IV` 显式时为 128-bit 十六进制值。
- 未显式 IV 时，媒体序列号按 128-bit big-endian 补零作为 IV；同一 segment 的 IV 在请求/响应中保持一致。
- key URI 状态继承至下一 `EXT-X-KEY` 或 `METHOD=NONE`；不能跨 session 继承。
- `SAMPLE-AES`、DRM（数字版权管理）系统和密钥轮换协议不在本版范围；误配必须报 `key`/`encryption` 错误。

## 6. 多会话、IPv4/IPv6 与生命周期

多会话必须至少有两个独立 HLS sessions，分别使用不同源端口或地址；每个 session 的 master、media sequence、key map、live window 和终止状态隔离。聚合 packet count 可受 TCP ACK 合并和 MSS 分段影响，因此未来正例的 `packet_count` 只在固定 fixture 中承诺；playlist 事件数量用 HTTP request/response 顺序断言。

IPv4/IPv6 只影响 outer transport：IPv6 session 使用 IPv6 source/destination 和 TCP next header=6；playlist URI、segment URI、key URI 不得因地址族改变。IPv4 和 IPv6 可在同一多会话 fixture 中并存，但不能共享 session state。

关闭规则：有限 master/media/segment 事件结束后发送 TCP FIN；live profile 的 `refresh_count` 到达上限后可显式 `ENDLIST` 或终止连接。无限 live 生成是禁止的；必须用 count/time flow control（流量控制）或 `refresh_count` 有界。

## 7. 错误处理和验证完成定义

以下错误必须在 planner/validator 处拒绝，并通过 task error 传播：空 body、缺少 `#EXTM3U`、未知但被配置为必需的 tag、`EXTINF` 无 URI、target duration 非正数、sequence 回退、discontinuity sequence 不一致、byterange 越界、AES-128 缺 key URI/非法 IV、key 与 segment 作用域不一致、非法 URI/control byte、LL-HLS 标签未启用 profile、session 跨流引用。

实现完成定义：

1. 注册 `hls` layer，明确字段表、HTTP 载体依赖、profile 和事件状态机；未知 profile/tag policy 不得静默猜测。
2. planner → worker → HTTP/TCP output 全链路生成可重组的 request/response；正文编码、Content-Length、Content-Type 和连接关闭语义一致。
3. 单测逐行验证 master/media 标签、属性顺序、target duration/sequence/discontinuity、byterange offset、AES-128 IV 推导和 live window 更新；至少覆盖每一错误表项。
4. PCAP 正例验证 HTTP status/URI、playlist bytes、segment/key response、IPv4/IPv6、多 session 和方向；TLS 未解密时只验证 TLS/HTTP 外层。
5. LL-HLS 只在 `apple_ll_hls` profile 开启，part/preload/skip/report 的时间和 MSN（媒体序列号）关系有独立测试；不能用普通 HLS 正例替代。
6. 未注册阶段运行 JSON 只能得到 rejected/not runnable；任何成功生成声称均为错误。

## 8. 场景与三方 ID

共 24 个唯一 ID，15 个目标正例、9 个负例（#12/#13 为空/截断和非法标签目标错误）；由于当前 `hls` 未注册，JSON 中 24 个条目暂统一为 `expect_error=true` + `error_contains="unknown layer"` 的注册前置占位。实现后应按 testcase 文档将 15 个目标正例改为 PCAP 断言，保留 9 个为严格 Validate（校验）负例。

| # | ID | 目标类型 | 覆盖 |
|---:|---|---|---|
| 1 | `hls_master_basic_ipv4` | 正 | master、STREAM-INF、IPv4 HTTP |
| 2 | `hls_media_target_duration` | 正 | media、TARGETDURATION、EXTINF |
| 3 | `hls_media_sequence` | 正 | MEDIA-SEQUENCE、连续分片序号 |
| 4 | `hls_discontinuity` | 正 | DISCONTINUITY/DISCONTINUITY-SEQUENCE |
| 5 | `hls_byterange` | 正 | BYTERANGE 显式/隐式 offset、206 |
| 6 | `hls_aes128_key` | 正 | AES-128 key URI、IV、继承 |
| 7 | `hls_live_refresh` | 正 | live sliding window、refresh 单调前移 |
| 8 | `hls_llhls_parts` | 正 | LL-HLS PART、PRELOAD-HINT 边界 |
| 9 | `hls_master_renditions` | 正 | AUDIO/SUBTITLES rendition 关联 |
| 10 | `hls_fmp4_init_map` | 正 | fMP4、EXT-X-MAP、独立分片 |
| 11 | `hls_vod_endlist` | 正 | VOD、ENDLIST、终止 |
| 12 | `hls_empty_and_truncated` | 负 | 空/截断 body 必须拒绝 |
| 13 | `hls_invalid_tag` | 负 | 非法 tag/属性/顺序拒绝 |
| 14 | `hls_ipv6_media` | 正 | IPv6 outer HTTP、media playlist |
| 15 | `hls_multi_session` | 正 | 多 4-tuple、状态隔离 |
| 16 | `hls_http_errors` | 正 | 404/410/429/5xx 合法 response event |
| 17 | `hls_uri_encoding` | 正 | 相对 URI、query、percent-encoding |
| 18 | `hls_neg_missing_extm3u` | 负 | 缺少 EXT-M3U |
| 19 | `hls_neg_target_duration` | 负 | target duration 非法/不足 |
| 20 | `hls_neg_sequence_regress` | 负 | live sequence 回退 |
| 21 | `hls_neg_byterange` | 负 | range 越界/隐式跨 URI |
| 22 | `hls_neg_key` | 负 | AES key URI/IV/method 不一致 |
| 23 | `hls_neg_ll_profile` | 负 | 未启用 LL profile 却带 LL 标签 |
| 24 | `hls_neg_session_state` | 负 | 跨 session 引用或非法状态转移 |

## 9. 修订记录

- v1.0.0（2026-08-20）：建立 RFC 8216/Apple HLS 设计，覆盖 master/media playlist、EXT-X 标签、分片、byterange、AES-128、live refresh、LL-HLS、状态机、IPv4/IPv6、多会话、错误传播及 24 个 ID；不修改 Go 实现。

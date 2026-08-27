# HLS（HTTP Live Streaming，HTTP 实时流媒体）测试用例设计

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/46-hls-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/hls.json`
> 状态：✅ 已实现（24/24 PCAP 测试通过）

## 1. 测试原则与状态边界

本套件共 24 个唯一 ID：15 个正例、9 个负例。已全部实现并通过 PCAP 测试验证。

HLS 是 HTTP 应用层协议。实现后的明文 HTTP/1.1 正例在无 VLAN/IP options/TCP options 时，IPv4 请求 payload 从 offset 54 开始，IPv6 从 offset 74 开始；TCP MSS 分段时先按 HTTP 重组再核对 body。HTTPS 未解密时只能断言 TCP/TLS/HTTP 外层，不能在 frames 固定 playlist 文本。每个目标正例必须有 `packet_count` 或 `min_packets`、`fields`、`frames`；负例的 `expect` 严格只有 `expect_error` 和 `error_contains`。

不把 `packet_count` 当作 HLS 业务事件数：TCP ACK 合并、MSS 分段和 HTTP 连接复用会影响包数。固定 fixture 才能使用精确 packet_count；live refresh 重点断言 request 顺序、sequence 单调和窗口内容。

## 2. 机器配置示例

以下是可被 JSON 解析器接受的设计期配置块；它描述实现注册后的目标行为，不是当前可执行正例，也不替代 `cases/hls.json` 的未注册占位。

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
      "kind": "media",
      "uri": "/live/low.m3u8",
      "target_duration": 6,
      "media_sequence": 42,
      "segments": [{"uri": "/seg/42.ts", "duration": 5.0}]
    }]
  }
}
```

## 3. 原子用例索引

| # | ID | 目标类型 | 覆盖 | 实现后断言重点 |
|---:|---|---|---|---|
| 1 | `hls_master_basic_ipv4` | 正 | IPv4 master playlist、STREAM-INF | GET URI、200、Content-Type、EXTM3U、BANDWIDTH、variant URI |
| 2 | `hls_media_target_duration` | 正 | media、TARGETDURATION、EXTINF | target duration 与分片 duration 关系 |
| 3 | `hls_media_sequence` | 正 | MEDIA-SEQUENCE、连续分片 | sequence 起点和 URI 顺序 |
| 4 | `hls_discontinuity` | 正 | DISCONTINUITY、DISCONTINUITY-SEQUENCE | 标签位于受影响 segment 前 |
| 5 | `hls_byterange` | 正 | 显式/隐式 BYTERANGE、206 | length/offset、Content-Range |
| 6 | `hls_aes128_key` | 正 | AES-128 key、IV、作用域 | key GET、16-byte key、加密 segment 关联 |
| 7 | `hls_live_refresh` | 正 | live sliding window、refresh | sequence 单调前移、旧分片淘汰 |
| 8 | `hls_llhls_parts` | 正 | LL-HLS PART/PRELOAD-HINT | profile、part duration、preload URI |
| 9 | `hls_master_renditions` | 正 | AUDIO/SUBTITLES | GROUP-ID/NAME/URI 与 variant 关联 |
| 10 | `hls_fmp4_init_map` | 正 | fMP4、EXT-X-MAP | init map URI/byterange、独立分片 |
| 11 | `hls_vod_endlist` | 正 | VOD、ENDLIST | ENDLIST 后不再生成 live sequence |
| 12 | `hls_empty_and_truncated` | 目标错误 | 空/截断 body | task error，不能 completed/0 packet |
| 13 | `hls_invalid_tag` | 目标错误 | 非法 tag/属性/顺序 | task error，不能静默忽略必需标签 |
| 14 | `hls_ipv6_media` | 正 | IPv6 outer、media playlist | ipv6.nxt=6、GET/media body |
| 15 | `hls_multi_session` | 正 | 多 session/状态隔离 | 两个源端口、各自 sequence/key/window |
| 16 | `hls_http_errors` | 正 | 404/410/429/5xx response event | status/URI 合法错误事件，不混同 planner error |
| 17 | `hls_uri_encoding` | 正 | 相对 URI、query、percent-encoding | request-target 按原样保留 |
| 18 | `hls_neg_missing_extm3u` | 负 | 缺少 EXT-M3U | `expect_error=true`, `error_contains=extm3u` |
| 19 | `hls_neg_target_duration` | 负 | target 非正/不足以覆盖 EXTINF | `error_contains=target` |
| 20 | `hls_neg_sequence_regress` | 负 | live sequence 回退 | `error_contains=sequence` |
| 21 | `hls_neg_byterange` | 负 | range 越界/隐式跨 URI | `error_contains=byterange` |
| 22 | `hls_neg_key` | 负 | AES key URI/IV/method 不一致 | `error_contains=key` |
| 23 | `hls_neg_ll_profile` | 负 | 未启用 profile 的 LL 标签 | `error_contains=ll` |
| 24 | `hls_neg_session_state` | 负 | 跨 session 引用/非法转移 | `error_contains=session` |

其中 #12/#13 的目标错误也在实现后的 JSON 中应转为严格 Validate 负例；当前占位统一使用 `error_contains: "unknown layer"` 表示 `hls` 层尚未注册，不能把它误解为已经验证了 playlist malformed 行为。

## 4. 正例契约（实现后）

### 3.1 Master/media 基线（#1–#4）

1. **`hls_master_basic_ipv4`**：HTTP GET `/live/master.m3u8`，响应 200，`Content-Type` 为 `application/vnd.apple.mpegurl` 或注册等价值；body 以 `#EXTM3U` 开始，含 `#EXT-X-VERSION:7`、`#EXT-X-STREAM-INF:BANDWIDTH=800000,RESOLUTION=640x360`，下一行是 `/live/low.m3u8`。frames 在 TCP payload offset 54 固定 `GET /live/master.m3u8 HTTP/1.1` 和 `#EXTM3U` 的稳定前缀；不得固定 Date、Content-Length 等可由编码变化的字段，除非 fixture 明确固定。
2. **`hls_media_target_duration`**：GET `/live/low.m3u8` 后返回 `#EXT-X-TARGETDURATION:6`、至少两个 `#EXTINF:5.0`/`#EXTINF:6.0` 和 segment URI；fields 断言 HTTP status、URI、Content-Type，body frame 断言 `#EXT-X-TARGETDURATION:6\n` 和 `#EXTINF:5.0`。每个 `EXTINF` 按 RFC 8216 四舍五入到最近整数后不超过 6。
3. **`hls_media_sequence`**：media body 含 `#EXT-X-MEDIA-SEQUENCE:42`，随后分片序列按 42、43、44；实现可用显式 fixture URI `/seg/42.ts` 等。断言 sequence 和 URI 顺序，不把 segment HTTP 请求包位当作 sequence。
4. **`hls_discontinuity`**：body 含 `#EXT-X-DISCONTINUITY-SEQUENCE:3`，在 `/seg/11.ts` 前出现 `#EXT-X-DISCONTINUITY`，之后 sequence 仍连续；断言标签先于受影响 URI，不能用 sequence 回退代替 discontinuity。

### 3.2 Range、key、live（#5–#7）

5. **`hls_byterange`**：同一 `/media.mp4` 的两个 range 分别 `#EXT-X-BYTERANGE:1000@0`、`#EXT-X-BYTERANGE:800`，且 `resource_length=1800`；第二 offset 隐式为 1000。segment response 使用 206，`Content-Range` 分别 `bytes 0-999/1800` 与 `bytes 1000-1799/1800`；断言 length/offset 和请求 URI，不能只断言 `EXT-X-BYTERANGE` 标签文本。
6. **`hls_aes128_key`**：同一 session 内先返回 media playlist（含 `#EXT-X-KEY:METHOD=AES-128,URI="/keys/live.key",IV=0x0000000000000000000000000000002A`），再 GET key 返回恰 16 bytes，随后 GET encrypted segment；后续 `METHOD=NONE` 事件清除继承。断言 key URI、key body 非零/长度、IV 字节前缀和 segment/key 关联；不固定真实密钥值。
7. **`hls_live_refresh`**：初次 `kind=media` body `MEDIA-SEQUENCE:100` 窗口 100–102，随后一次 `kind=refresh` body `MEDIA-SEQUENCE:101` 窗口 101–103；断言两个 GET URI 相同、响应顺序、sequence 单调增加和旧 100 淘汰。`refresh_count=1`/显式 interval 防止无限生成；不依赖 wall-clock 时间。

### 3.3 扩展、地址和多会话（#8–#17）

8. **`hls_llhls_parts`**：显式 `apple_ll_hls` profile，body 含 `#EXT-X-SERVER-CONTROL`、`#EXT-X-PART-INF:PART-TARGET=0.333`、`#EXT-X-PART:DURATION=0.333,URI="/p/101.1.m4s"`、`#EXT-X-PRELOAD-HINT:TYPE=PART,URI="/p/101.2.m4s"`；断言标签/属性和值。普通 `rfc8216_v7` profile 禁止这些标签（见 #23）。
9. **`hls_master_renditions`**：master 含 `EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="aud",NAME="main",DEFAULT=YES,URI="/audio.m3u8"` 和 STREAM-INF `AUDIO="aud"`；断言 GROUP-ID 一致及 URI 关联。
10. **`hls_fmp4_init_map`**：media 含 `#EXT-X-MAP:URI="/init.mp4",BYTERANGE="720@0"`、`#EXT-X-INDEPENDENT-SEGMENTS` 和 fMP4 segments；断言 map 在首个 segment 前、range 字段和 `video/mp4`。
11. **`hls_vod_endlist`**：`PLAYLIST-TYPE:VOD`、有限 `EXTINF` 后 `#EXT-X-ENDLIST`；断言终止，不能在 ENDLIST 后自动补 refresh 或新 segment。
12. **`hls_empty_and_truncated`**：目标实现拒绝 malformed playlist body；当前单个 fixture 同时固定空 body 和 truncate fault 的错误传播，注册后如需分别定位错误锚点再拆分为独立 ID。此版占位仍因未注册而失败，不能冒充 malformed 行为已覆盖。
13. **`hls_invalid_tag`**：目标实现拒绝 `bad_tag` 以及缺 URI 的 `EXTINF`；非法 BANDWIDTH、错误 tag 顺序和控制字节属于后续独立负例扩展，不能由当前单项占位宣称覆盖。
14. **`hls_ipv6_media`**：IPv6 TCP/HTTP GET `/v6/live.m3u8`，断言 `ipv6.nxt=6`、目标地址族、HTTP 200 和 media target/sequence；不把 IPv6 外层地址转写进 playlist URI。
15. **`hls_multi_session`**：两个独立 4-tuple 并行 session，一个请求 `/a/master.m3u8`、另一个 `/b/master.m3u8`，各自 media sequence/key/window 不串联；使用 `directional`、端口 distinct 或 session fixture 断言，不能假定多流 packet index 顺序。
16. **`hls_http_errors`**：显式 response events 返回 404、410、429、503；断言 status 与 request URI，作为合法 HTTP 应用错误，不应令 planner 失败。非预期的线格式错误仍必须 task error。
17. **`hls_uri_encoding`**：请求 `/live/seg%2F01.ts?token=a%2Bb`，断言 HTTP request-target 按原始 percent-encoding 保留；不得把 `%2F` 解码成路径分隔符或把 `+` 变空格。

## 5. 负例契约

每个负例必须由 planner/validator 错误传播为 task error，不得产生成功 PCAP、completed/0 packet 或只剩 TCP ACK 的假成功。

| ID | 故障注入 | `error_contains` |
|---|---|---|
| `hls_neg_missing_extm3u` | body 缺少首行 `#EXTM3U` | `extm3u` |
| `hls_neg_target_duration` | live refresh 的 target duration 非正，或小于任一 EXTINF 按 RFC 8216 四舍五入到最近整数后的值（当前 fixture 使用 2.5→3 边界） | `target` |
| `hls_neg_sequence_regress` | live refresh 的 MEDIA-SEQUENCE 小于上一版本 | `sequence` |
| `hls_neg_byterange` | length/offset 越界，或隐式 offset 跨 URI | `byterange` |
| `hls_neg_key` | AES-128 缺 URI、IV 非 128-bit、METHOD=NONE 仍带 key | `key` |
| `hls_neg_ll_profile` | 基线 profile 带 PART/PRELOAD-HINT/SKIP 等 LL 标签 | `ll` |
| `hls_neg_session_state` | segment/key 引用另一个 session 的状态，或 ENDLIST 后继续 live refresh | `session` |

## 6. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/hls.json`，确认 JSON 合法。
2. 检查 24 个 ID 唯一、顺序与设计 §8 和本文 §2 一致；当前 24 个 `expect` 均严格为 `expect_error=true`、`error_contains="unknown layer"`，因为 `hls` 层尚未注册。
3. 层注册后，15 个目标正例分别改为正例断言；每个正例补 `packet_count`/`min_packets`、`fields`、`frames`，9 个负例 `expect` 只能有 `expect_error`、`error_contains`。
4. 用 `tshark -G fields` 验证实际 HTTP/TLS/IPv4/IPv6 字段；不能把配置键（如 `hls.media_sequence`）直接当 tshark 字段。playlist body 的文本 bytes 用 frames 验证，动态 Date/ID/Content-Length 不写固定常量。
5. 明文 HTTP 重组后验证 playlist；TLS 无密钥只验证 TLS 外层。多 session 断言地址/端口或 distinct values，不依赖调度顺序。
6. 负例验证错误传播；任何成功/0 包任务均为失败，不得以空 PCAP 代替 Validate 错误。

## 7. 三方一致性表

设计 §8、本文 §2、JSON 数组均为下列 24 个 ID、同一顺序。目标正例为 #1–#11、#14–#17（15 项），负例为 #12–#13、#18–#24（9 项）；当前 JSON 因未注册统一占位，不宣称目标正例已执行。

```text
hls_master_basic_ipv4
hls_media_target_duration
hls_media_sequence
hls_discontinuity
hls_byterange
hls_aes128_key
hls_live_refresh
hls_llhls_parts
hls_master_renditions
hls_fmp4_init_map
hls_vod_endlist
hls_empty_and_truncated
hls_invalid_tag
hls_ipv6_media
hls_multi_session
hls_http_errors
hls_uri_encoding
hls_neg_missing_extm3u
hls_neg_target_duration
hls_neg_sequence_regress
hls_neg_byterange
hls_neg_key
hls_neg_ll_profile
hls_neg_session_state
```

## 8. 修订记录

- v1.0.0（2026-08-20）：建立 15 个目标正例与 9 个严格负例，覆盖 master/media、EXT-X 标签、分片、byterange、AES-128、live refresh、LL-HLS、IPv4/IPv6、多会话、HTTP 错误和 Validate 边界；当前仅提交设计/用例契约，不修改 Go 实现。

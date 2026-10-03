# HLS 用例契约（as-built）

> 白话一句：二十四条检查——十五条看正常收发（主列表、分片列表、边界标签、范围下载、密钥、直播刷新、低延迟、音轨、初始化段、点播结束、多路、错误回答、URI 编码），九条记录坏配置边界；每条只查一件事。
> 机器契约：`trafficgen/test/protocol_pcap/cases/hls.json`（24 ID，顺序与本文 §2 一致）。

## 1. 测试点清单与三源回指

每个案件的回指是 RFC/设计/cases 三源；现网行为以现有 fixture 表达，未抓真实服务端包的标 G-HLS-9。动态生成值（TCP ISN、Content-Length、Date 若出现）不定值，不定常量；包数以存量 JSON 为准，本轮没有用新 pcap 重新校准，待 P5 复跑见 G-HLS-10。

| ID | 行为点 | 规范/现网依据 | 设计章节 |
|---|---|---|---|
| `hls_master_basic_ipv4` | master playlist/版本/变体 | RFC 8216 §4.3.4 | §2 |
| `hls_media_target_duration` | TARGETDURATION/EXTINF | RFC 8216 §4.3.3 | §2 |
| `hls_media_sequence` | MEDIA-SEQUENCE/order | RFC 8216 §6.2.1 | §2 |
| `hls_discontinuity` | DISCONTINUITY/DISCONTINUITY-SEQUENCE | RFC 8216 §4.3.2.3 | §2 |
| `hls_byterange` | explicit/implicit BYTERANGE | RFC 8216 §4.3.2.2 | §2 |
| `hls_aes128_key` | AES-128 key/IV/NONE | RFC 8216 §4.3.2.4/§5 | §2 |
| `hls_live_refresh` | live window/refresh | RFC 8216 §6.2.2 | §3 |
| `hls_llhls_parts` | PART/PRELOAD | Apple LL-HLS | §2 |
| `hls_master_renditions` | EXT-X-MEDIA/变体关联 | RFC 8216 §4.3.4.1 | §2 |
| `hls_fmp4_init_map` | EXT-X-MAP/INDEPENDENT | RFC 8216 §4.3.2.5 | §2 |
| `hls_vod_endlist` | VOD/ENDLIST | RFC 8216 §4.3.3.2 | §2 |
| `hls_empty_and_truncated` | 空/截断 body 注入 | RFC 8216 §4.1 显式 fixture | §6 设计 |
| `hls_invalid_tag` | 无 URI segment/bad tag | RFC 8216 §4.1 | §6 设计 |
| `hls_ipv6_media` | IPv6 carrier | RFC 8216 与地址族解耦 | §1 |
| `hls_multi_session` | 多 session/array order | fixture | §3 |
| `hls_http_errors` | 404/410/429/503 response | RFC 8216 §6.2.1 | §2 |
| `hls_uri_encoding` | relative/query/percent bytes | RFC 3986 原样 request-target | §2 |
| `hls_neg_missing_extm3u` | 缺少 EXTM3U | RFC 8216 §4.1 | §6 |
| `hls_neg_target_duration` | target 非法/不足 | RFC 8216 §4.3.3.1 | §6 |
| `hls_neg_sequence_regress` | sequence 回退 | RFC 8216 §6.2.1 | §6 |
| `hls_neg_byterange` | range 越界/跨 URI | RFC 8216 §4.3.2.2 | §6 |
| `hls_neg_key` | key URI/IV/method | RFC 8216 §4.3.2.4/§5 | §6 |
| `hls_neg_ll_profile` | 非 LL profile 的 LL 标签 | Apple LL-HLS | §6 |
| `hls_neg_session_state` | 跨 session/state | fixture | §6 |

T2：清单来自上述表格；每个行为点向 §2/§3/§4 的断言映射独立可查。

T3：原子用例执行 24 例；D（数据面）覆盖 playlist/segment/key 字段，T（业务面）覆盖 master→media→segment/key、refresh/VOD、多 session，C（现网/承载面）覆盖 HTTP 字段、IPv4/IPv6 和 fixture 行为；三类覆盖均以现有生成器为边界，不能代表真实服务端全谱。强度受代码现状约束：枚举未全扫（G-HLS-5/G-HLS-6）、正交矩阵只到 IPv4/IPv6×单/多 session、动态整格当前无业务动态（设计§9）、断言边界在 frames/HTTP 字段（参见 G-HLS-9/G-HLS-10）。

T4：同连接多轮操作（#5/#6/#7/#15）已覆盖；非正常结束仅 HTTP 错误响应（RST 无用例 G-HLS-2）；长保活由 keep-alive headers 和多 session 覆盖，无 timer 自动 refresh（G-HLS-3）。

T5：存量 24 ID 全部合入，无作废；差异是顶层业务形迁入 hls 层，语义/断言未改。

T6：当前 9 个目标负例（#12–#13、#18–#24）不是已验证的 planner 拒绝；`hls` validator 当前只检查配置指针并恒返回 nil（`trafficgen/internal/protocol/hls/planner.go:107-116`），且仅 `empty_body`、`missing_extm3u`、`bad_tag` 三个注入口实际影响 body 生成（`builder.go:237-251`），其余负例字段尚无消费者。故不得以成功 PCAP 宣称已覆盖拒绝路径（G-HLS-1）。包数/字段断言仅是输出形状断言，改 validator 后全量重跑才能确认失败路径真会红。

## 2. 原子用例索引

| # | ID | 包数 | 断言重点 |
|---:|---|---|---|
| 1 | `hls_master_basic_ipv4` | 9 | GET `/live/master.m3u8`，200 |
| 2 | `hls_media_target_duration` | 9 | GET `/live/low.m3u8`，200 |
| 3 | `hls_media_sequence` | 9 | GET `/live/seq.m3u8`，200 |
| 4 | `hls_discontinuity` | 9 | GET `/live/disc.m3u8`，200 |
| 5 | `hls_byterange` | 13 | playlist GET + 两个 segment events |
| 6 | `hls_aes128_key` | 15 | playlist/key/segment events |
| 7 | `hls_live_refresh` | 11 | 两个 playlist events |
| 8 | `hls_llhls_parts` | 9 | GET `/live/ll.m3u8`，200 |
| 9 | `hls_master_renditions` | 9 | GET `/live/master.m3u8`，200 |
| 10 | `hls_fmp4_init_map` | 9 | GET `/live/fmp4.m3u8`，200 |
| 11 | `hls_vod_endlist` | 9 | GET `/vod/movie.m3u8`，200 |
| 12 | `hls_empty_and_truncated` | ≥6 | 目标负例；现状断言只有下界 |
| 13 | `hls_invalid_tag` | ≥6 | 目标负例；现状断言只有下界 |
| 14 | `hls_ipv6_media` | 9 | GET `/v6/live.m3u8`，200 |
| 15 | `hls_multi_session` | 13 | 多 session events |
| 16 | `hls_http_errors` | ≥6 | 四个 HTTP error events |
| 17 | `hls_uri_encoding` | 9 | percent/query 原样 GET，200 |
| 18 | `hls_neg_missing_extm3u` | ≥6 | 目标负例；现状只有下界 |
| 19 | `hls_neg_target_duration` | ≥6 | 目标负例；现状只有下界 |
| 20 | `hls_neg_sequence_regress` | ≥6 | 目标负例；现状只有下界 |
| 21 | `hls_neg_byterange` | ≥6 | 目标负例；现状只有下界 |
| 22 | `hls_neg_key` | ≥6 | 目标负例；现状只有下界 |
| 23 | `hls_neg_ll_profile` | ≥6 | 目标负例；现状只有下界 |
| 24 | `hls_neg_session_state` | ≥6 | 目标负例；现状只有下界 |

## 3. 正例逐项断言契约

明文 HTTP 正例统一断言请求 URI 和响应 status，playlist 文本由 frames 验证；TLS 明文不验证。`#1–4/#8–11/#14` 是单 GET/response（9 包：TCP 握手、请求/响应、FIN 序列的存量期望）；`#5`（13）、`#6`（15）、`#7`（11）、`#15`（13）是多 event 事务；`#16`（≥6）表达四个 HTTP error events，未断言 body 长度；`#17` 保留 `%2F`/`%2B` 原样。

## 4. 负例契约

9 个目标负例用 `min_packets` 占位，用于记录需要 planner/validator 拒绝的输入，但今日实现不拒绝。改 validator 后每个例必须改为只有 `expect_error`/`error_contains`，锚词必须与真实拒绝文案一致（G-HLS-1），不得保留包数或 frames 断言。`hls_http_errors`（#16）是合法 HTTP 错误事件，不是 planner 负例。

## 5. 机器契约与静态检查

1. `python3 -c "import json;json.load(open('trafficgen/test/protocol_pcap/cases/hls.json'))"`。
2. 24 ID 与本文 §2 一致且顺序一致；正例顶层仅 `layers`，必要时加 `flow_control`/`group_id`/`output`，不允许顶层业务。
3. 层链 `[ip,tcp,http,hls]`，地址端口不在 hls 层；hls 层保留一个完整业务对象。
4. tshark 字段直接验证 HTTP/TCP/IPv4/IPv6，不把配置键当字段；playlist 用 frames 核对稳定 bytes。
5. 负例改 validator 后重跑全量，错误传播失败即红。

## 6. 修订记录

- v2.0.1（2026-10-01）：纠正正/负例计数为 15/9，并注明负例注入口的实际消费范围与未消费字段，避免把目标拒绝误报为已覆盖。

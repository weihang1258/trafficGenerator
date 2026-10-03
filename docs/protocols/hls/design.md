# HLS 设计契约（as-built）

> 版本：v2.0.0；日期：2026-09-30；实现：`trafficgen/internal/protocol/hls/` + HTTP 变换器。
> 规范基线：RFC 8216 §4–§6；Apple HLS Authoring Specification（LL-HLS 扩展）。机器契约：`trafficgen/test/protocol_pcap/cases/hls.json`。

## 0. 实现边界

HLS 是 HTTP 承载的播放列表、分片和 key 事件生成器。当前链为 `[ip,tcp,http,hls]`：`hls` 只产一个下行 body event/session，HTTP 层将其包装成 GET/响应，TCP 层负责握手、分段和 FIN。已实现 master/media/refresh/segment/key、MPEG-TS/fMP4 声明、byterange 文本、AES-128 key 文本关联、VOD ENDLIST、IPv4/IPv6、多个有序会话和 `apple_ll_hls` 的 PART/PRELOAD-HINT 文本输出。未实现真实媒体编码/解码、播放器状态、HTTP/2/3、TLS 明文验证、CDN、无限直播调度和 playlist 语义 validator；负例字段目前由 body/config 进入生成路径，不应宣称已被 planner 拒绝（见 G-HLS-1）。

registry 已注册 `hls` 为 `CategoryTerminal`、`DependsOn=["http"]`、字段仅 `profile`/`wire_fault`（`internal/core/layers/registry.go:589-596`）；translate 对层配置创建 `HLSConfig` 并给每个 session 默认 `Rounds=1`（`chain_planner_translate.go:869-877`）。配置唯一真相是 hls 层，顶层 `hls` 子映射已迁移为判死缺口。

## 1. 层链、端口与配置形状

推荐完整形状如下；顶层仅结构键 `layers`（数量另用 `flow_control`），地址在 ip，端口在 tcp，业务全部在 hls 层。

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "198.51.100.20"}},
    {"tcp": {"src_port": 40000, "dst_port": 80}},
    {"http": {}},
    {"hls": {"profile": "rfc8216_v7", "sessions": [
      {"kind": "master", "uri": "/live/master.m3u8",
       "variants": [{"uri": "/live/low.m3u8", "bandwidth": 800000}]}
    ]}}
  ]
}
```

HTTP 默认目的端口由承载层 FieldContract 补为 80；本协议不自行改端口。IPv4 无 options 时 HTTP payload 起点为 54，IPv6 为 74。HLS 事件按 `sessions[]` 数组顺序处理，不交错；每项是一个 HTTP GET/response 事务。`session_id` 只是业务标识，当前生成器不建立独立 session 状态机。

字段事实（`internal/core/types.go:356-475,537-541`）：`HLSConfig` 含 profile、sessions、live、ll_hls、wire_fault 与负例注入口；`HLSSession` 含 kind/session_id/uri、playlist 字段、segments/variants/renditions、key/parts/preload/map、body/response 字段、range/resource、rounds；segment 含 uri/duration/title/byte_range/key_ref/discontinuity/program_date_time；key 含 method/uri/iv。

## 2. 线格式与主流程

`buildMasterPlaylist`（`builder.go:13-69`）输出 `#EXTM3U`、版本 7、可选 independent、`EXT-X-MEDIA`、`EXT-X-STREAM-INF` 后紧跟 variant URI。`buildMediaPlaylist`（`:71-165`）按顺序输出 playlist type、independent、LL 标签、TARGETDURATION（`ceil`）、MEDIA-SEQUENCE、DISCONTINUITY-SEQUENCE、KEY、MAP、每个 segment 的 DISCONTINUITY/BYTERANGE/EXTINF/URI、PART/PRELOAD、ENDLIST。显式 `body` 优先；empty/missing/bad-tag 只生成故障 body。

planner 的 `Generate`（`planner.go:24-48`）对每个 session 调 `buildSessionBody` 并发出一个 `MessageEvent{Up:false}`。HTTP transformer（`internal/protocol/http/hls_transformer.go:41-98`）读取对应 event，输出：playlist `application/vnd.apple.mpegurl`；segment 默认 `video/mp2t`；key 默认 `application/octet-stream`；显式状态码覆盖默认 200，4xx/5xx 不带 body；多事件均 `Connection: keep-alive`。`ResponseBodyB64` 可提供资源字节，默认 segment 是 `dummy segment content`，默认 key 是 16 字节 01..10。

byterange 仅在 playlist 文本生成中追踪同 URI 的上一 range 结束位置（`builder.go:113-144`）；实现不执行资源长度越界或 HTTP Content-Range 校验。AES key 仅按 `EXT-X-KEY` 文本输出/事件关联，不执行密钥长度、IV 或加密。LL-HLS 只在 profile 为 `apple_ll_hls` 时输出 PART-INF/SERVER-CONTROL/PART/PRELOAD 文本。

## 3. 会话、事务和流关联（CORE §3）

| 会话 | 事务序列 | 关联关系 | 插入位置 | 时间线 |
|---|---|---|---|---|
| 单 HLS session | 一个 playlist/segment/key event | HTTP GET 与该 event 的 URI 一一对应 | hls body → http transformer | 顺序 |
| 多 session | `sessions[0]…sessions[n]` | 仅按数组位置配对；无跨 session 状态 | 每项一个 GET/response 对 | 顺序、不交错 |

HLS 当前没有控制流与独立数据流的协议级关联：segment/key 是独立 HTTP 事务而非另建 TCP 数据通道，因此“多流关联”不适用；`flow_control` 复制的是整条策略流。§3.15：同连接多轮操作由 #5/#6/#7/#15 覆盖；非正常结束仅有 HTTP 错误响应（#16），TCP RST 未实现并登记 G-HLS-2；长保活由 keep-alive header 和多 session 顺序覆盖，但无 timer/refresh 自动调度，登记 G-HLS-3。

## 4. P1 规范要求→业务→代码→缺口矩阵

| 规范要求（依据） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|
| 连接模型：HTTP GET/response（RFC 8216 §4） | playlist、segment、key GET | HTTP transformer 逐 event 包装 | 已覆盖；不实现 HTTP/2/3（G-HLS-4） |
| playlist 类型与标签（§4.3） | master/media/VOD/live | builder 输出固定支持标签 | 未校验标签顺序/属性（G-HLS-1） |
| media sequence/window（§6.2） | refresh 前移 | refresh 仅数组事件 | 无单调状态校验（G-HLS-1） |
| segment 数据形态 | TS/fMP4/map/range | 仅声明 URI/body | 不解析媒体字节（G-HLS-5） |
| 加密（§4.3.2） | AES-128 key/IV | 输出 KEY 文本和 key body | 不加密、不验证 IV/key 长度（G-HLS-6） |
| 错误与终止 | 404/410/429/5xx、ENDLIST | 状态码/ENDLIST 可输出 | malformed 不传播 task error（G-HLS-1） |
| 版本/方言 | RFC v7、Apple LL | profile 分支 LL 文本 | 不支持 HTTP/2 blocking reload（G-HLS-4） |
| 超时/活性 | keep-alive、多 session | header 固定 keep-alive | 无 timer/自动 refresh（G-HLS-3） |

| 业务 | `sessions[]` 中的 master/media/segment/key/refresh 事件 | `HLSConfig.Sessions` 按序生成 body event | 已覆盖 #1–#17；不建立播放器解析状态机（G-HLS-1） |
| 承载 | HTTP/1.1 GET/response、IPv4/IPv6 | HTTP transformer 逐 event 包装 | 已覆盖明文 HTTP；不实现 HTTP/2/3/TLS 明文验证（G-HLS-4） |
| 控制 | live window、refresh_count、ENDLIST | 显式 session 数组，无 timer 调度 | 已表达 #7/#11；无自动 refresh scheduler（G-HLS-3） |
| 数据 | playlist、TS/fMP4 URI/body、byterange、key | builder 输出确定性文本/默认 body | 不解析媒体字节或执行 Content-Range/AES 校验（G-HLS-5/G-HLS-6/G-HLS-7） |

D/T/C 对账：D（数据面）= playlist 标签、segment/key/map/range/body（#1–#6、#8–#11、#17）；T（业务面）= master/media/refresh/VOD、多 session 和合法 HTTP error 事务（#1–#17）；C（现网/承载面）= HTTP request/response、状态码、IPv4/IPv6、keep-alive 与 fixture 线形（#1–#17）。24 例中的 7 个语义负例（#18–#24）和 2 个 malformed 例（#12–#13）仍是目标负例，不计入已覆盖拒绝统计（G-HLS-1）。
### 4.2 命令×响应码矩阵
|---|---|---|---|---|
| playlist GET | 已实现 #1–4,7–11,14–15 | 不适用 | 已表达 #16 | 已表达 #16 |
| segment GET | 已表达 #5,6,10,17 | 设计字段存在但当前不产 Content-Range（G-HLS-7） | 已表达 #16 | 已表达 #16 |
| key GET | 已表达 #6 | 不适用 | 缺独立例 G-HLS-8 | 缺独立例 G-HLS-8 |

### 4.3 数据形态变体表

| 形态 | 现状/用例 |
|---|---|
| master、media、refresh、VOD | 已实现；#1–4,#7,#9,#11 |
| TS、fMP4、MAP | URI/body 声明；#5,#10 |
| explicit/implicit range | playlist 文本生成；#5 |
| AES-128/NONE/IV | 文本/事件形；#6；密码学未实现 G-HLS-6 |
| LL PART/PRELOAD | profile 分支文本；#8；无独立 validator G-HLS-1 |
| IPv4/IPv6 | #1/#14；内容与地址独立 |
| 多 session/错误响应/URI encoding | #15/#16/#17 |

### 4.4 商业行为→用例映射

| 现网行为 | 依据/确认方式 | 用例 |
|---|---|---|
| master 后取 variant | RFC 8216 §4.3.4；现有 fixture | #1 |
| media window refresh | RFC 8216 §6.2.2；现有 fixture | #7 |
| AES key 单独 GET | RFC 8216 §5；现有 fixture | #6 |
| fMP4 init map | RFC 8216 §4.3.2.5；现有 fixture | #10 |
| keep-alive 多事务 | HTTP/1.1 现网通用行为；transformer | #5,#15 |
| 错误状态响应 | RFC 8216 §6.2.1；现有 fixture | #16 |
| LL-HLS parts | Apple LL-HLS；现有 fixture | #8 |

## 5. 三路对照与候选方案

规范原文以 RFC 8216 §4–§6 和 Apple LL-HLS 为底线；商业行为取常见 HLS 客户端的 master→media→segment/key 请求顺序（需真实服务端抓包才能确认 headers/重试，当前标 G-HLS-9）；开源实现思路采用本仓库 HTTP transformer 的 event→request/response 方式（`hls_transformer.go`），不复制外部代码。

| 走法 | 优点 | 代价 | 取舍 |
|---|---|---|---|
| A：hls 只产 body event，HTTP 统一包装 | 复用 TCP/HTTP 分段和连接语义，改动小 | 需要 hls/http 配置配对 | 当前采用 |
| B：hls 自己产完整 HTTP 字节 | 协议自包含 | 重复 HTTP framing、难复用 carrier | 不采用 |

## 6. 依赖、错误、性能

依赖顺序为 ip→tcp→http→hls；缺 carrier 由层校验拒绝（`validate_layers.go:939-940`）。内部 `EmitMsg` 缺失、ctx 取消、未知 session kind 返回 error；transformer 内层 event 提前关闭或未知 kind 返回 error。配置语义错误（空 body、坏 tag、sequence/range/key/profile）当前**不会**统一拒绝，见 G-HLS-1，不把成功 PCAP 冒充负例验证。

性能边界：每 session 一个 body event，流式处理，不聚合全部 sessions；HTTP/TCP 队列和 ring buffer 的上限由通用 pipeline 控制。当前无 HLS 专属吞吐/内存基准，目标验收用 pcap：逐字段/frames 重组 HTTP body；网卡路径用 tcpdump 校验同一 URI/status/body 前缀。规模验收应覆盖 1 session、24 例目标规模、多 session、长 body/MSS 分段、并发 flow_control、buffer 背压六类；数字待基准，不承诺。

## 7. 八要素与缺口

- 文件：`internal/protocol/hls/{planner,builder}.go`、`internal/protocol/http/hls_transformer.go`、registry/translate；文档与 cases 三文件。
- 接口：`HLSGenerator.Generate(ctx,*layers.GenRequest) error`；HTTP `generateHLSTransformer`。
- 结构：`HLSConfig`→`HLSSession`→segment/key/playlist 子结构。
- 流程：session body→HTTP GET→HTTP response→TCP output。
- 错误：ctx/缺 event/未知 kind 可返回；语义 malformed 当前不拒绝。
- 性能：流式 event，受通用 queue/buffer 约束。
- 冲突：旧顶层 hls 形违反 CORE；本轮 cases 迁入 hls 层，现有字段语义不改。
- 回滚：仅回滚本三文件即可恢复文档/cases；不改 Go。

| 缺口 | 现象 | 证据 | 归属阶段/计划 |
|---|---|---|---|
| G-HLS-1 | 负例字段没有 validator 锚词，24 例当前无 `expect_error` | `planner.go:107-115` validator 恒 nil；cases 12–13/18–24 | B：补 HLS validator 与真实负例后重跑 |
| G-HLS-2 | RST 非正常结束无 HLS 断言 | TCP carrier 负责关闭，HLS 无 fault 分支 | C：carrier/用例立项 |
| G-HLS-3 | live refresh 不按 timer 自动推进 | planner 只遍历 sessions | B：显式 refresh scheduler |
| G-HLS-4 | HTTP/2/3、TLS 明文不可验证 | 当前仅 HTTP transformer | C：独立承载扩展 |
| G-HLS-5 | 不解析 TS/fMP4 字节 | builder 仅返回 body | C：媒体解析器 |
| G-HLS-6 | AES 不加密/校验 key/IV | `buildKeyBody` 固定 16 bytes | B：加密语义 validator/codec |
| G-HLS-7 | 206 不生成 Content-Range | transformer 只写 status/content-type/length | B：range response 映射 |
| G-HLS-8 | key 错误响应无独立例 | cases #16 混合 HTTP errors | A：拆原子 cases |
| G-HLS-9 | 商业服务端 headers/retry 未抓包确认 | 本轮无真实服务端证据 | P5：抓包后补矩阵 |

## 8. 门1（CORE §15.1–15.3）十四行对照

| CORE | HLS 对照与证据 |
|---|---|
| §1 | 顶层 `src_ip/dst_ip/src_port/dst_port/count/hls` 全部迁移：地址→ip、端口→tcp、业务→layers[].hls、数量→flow_control；完整样例见§1。 |
| §2 | 策略复制由 flow_control；session 业务序列在 hls。 |
| §3 | 会话/事务/关联/插入/时间线五件套见§3；无副数据流，明确不适用。 |
| §4 | RFC 8216/Apple；P1 与三张子表见§4。 |
| §5 | 依赖和 error/继续/中断见§6。 |
| §6 | 流式、队列、pcap/NIC 双验收见§6。 |
| §7 | 本文与 cases 是协议契约，历史结果文档不作为今日证据。 |
| §8 | 八要素见§7。 |
| §9 | 24 ID 原子索引见 testcase §2；缺口不伪造覆盖。 |
| §10 | 文档自审和 cases 机读核对见交付报告。 |
| §11 | 用白话说明，技术证据指向代码/用例。 |
| §12 | 四元组与业务动态均当前未支持，理由/迁移计划见§9。 |
| §13 | registry/layers schema 是机器形状来源；hls 业务字段由现有 Go 类型消费。 |
| §14 | cases 是直接 strategy spec；本轮只做 JSON 解析与静态形状验证，不跑 suite。 |

## 9. 动态字段清单

四元组动态：`ip.src`、`ip.dst`、`tcp.src_port`、`tcp.dst_port` 均可由通用层动态策略承载；HLS 不重复计算，flow index 由通用 worker 解析。业务字段（URI、session_id、media_sequence、segment URI、key URI/IV、body、bandwidth、duration、parts）当前无 fixed/inc/rand/list/pattern 动态入口，按静态配置逐字输出；序号算法不存在，代码位置为 `planner.go:33-47` 数组遍历。需要动态业务字段时立项 B，禁止文档暗示自动变化。

## 10. 修订记录

- v2.0.0（2026-09-30）：按 CORE §1/§3/§4/§6/§8/§12/§15 重建 as-built 契约；登记实际 validator、HTTP carrier、性能与 HLS 语义缺口；cases 迁移业务配置至 hls 层。

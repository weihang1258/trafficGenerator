# HDS（Adobe HTTP Dynamic Streaming，Adobe HTTP 动态流）设计契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：仅设计与 PCAP（抓包文件）用例契约；`hds` 层尚未注册，不修改 Go（编程语言）planner（规划器），不宣称当前 suite（测试套件）可运行。
> 配套文件：`docs/protocol-designs/47-hds-testcase.md`、`trafficgen/test/protocol_pcap/cases/hds.json`
> 规范基线：Adobe HTTP Dynamic Streaming 规范、F4M manifest（F4M 清单）、Bootstrap/Fragment 规范、HTTP/1.1（超文本传输协议，RFC 9112/9110）和 TCP（传输控制协议）。

## 1. 范围、实现状态和承载边界

HDS 是使用 HTTP GET 获取 F4M manifest、bootstrap 和 F4F media fragment（媒体片段）的流媒体协议。F4M 是 XML（可扩展标记语言）清单；bootstrap 是描述 segment/fragment（分段/片段）时间线的二进制元数据；F4F 是按 HTTP 请求寻址的 fragment 容器。HDS 不是独立的 IP 协议，本设计将 `hds` 作为 TCP→HTTP 之上的终结层。

本版覆盖：

- F4M manifest 的 XML 声明、namespace（命名空间）、media、bootstrapInfo、live/VOD 语义；
- bootstrap `abst`、`asrt`、`afrt` box（盒）及其长度、版本、timescale（时间刻度）、segment/fragment run（运行表）编码；
- F4F media fragment 的请求 URI、box 边界、fragment sequence、timestamp、duration 和 payload；
- HTTP/1.1 GET/200、Content-Type、Content-Length、keep-alive（保持连接）及 TCP stream reassembly（流重组）；
- IPv4/IPv6、MSS（最大报文段长度）分段、多 session（会话）和同连接多资源请求；
- 空/截断 manifest、非法 XML/属性、bootstrap 长度越界、run table 不连续、fragment header/payload 截断等负路径。

不覆盖：HTTPS/TLS 解密、HTTP/2/HTTP/3、RTMFP（实时消息传输协议）、编码器/解码器、H.264/AAC 语义、DRM（数字版权管理）、CDN 缓存、无限 live（直播）生成。TLS 可作为未来独立 `tls→tcp→http→hds` 链；未解密时不能断言 manifest 或 fragment 明文。

当前仓库没有注册 `hds` layer（层），也没有对应的 planner、validator（校验器）或生成实现。设计中的语义原子 ID 只属于未来契约；当前 JSON 仅保留一个 `expect_error=true` 的 `unknown layer` 占位，不能把拒绝或 0 包报告为 HDS 通过。

## 2. 协议栈、URI 和固定偏移

推荐层链为 `[ip, tcp, http, hds]`；chain planner（层链规划器）应自动补齐 IP/TCP/HTTP 依赖。默认明文 HTTP 端口为 TCP/80。F4M 和 F4F 资源都通过 HTTP GET 获取：

| 资源 | 示例 request-target（请求目标） | 默认 Content-Type（内容类型） |
|---|---|---|
| manifest | `/live/channel.f4m` | `application/f4m+xml` |
| bootstrap | `/live/channel.bootstrap`（可由 media URL 内联） | `application/octet-stream` |
| fragment | `/live/channel/Seg1-Frag1` 或 profile 声明的 URI | `video/f4f` 或 `application/octet-stream` |

无 VLAN（虚拟局域网）、无 IP options（选项）、无 TCP options 时，HTTP payload（载荷）起点为 IPv4 offset（偏移）54（Ethernet 14 + IPv4 20 + TCP 20），IPv6 offset 为 74（14 + IPv6 40 + TCP 20）。应用消息不得假设一个 TCP packet（数据包）就是一个 HTTP/F4M/F4F 消息；MSS 分段后必须先重组 TCP stream，再按 Content-Length 和 box size 解析。

## 3. F4M manifest 结构

manifest 必须使用 UTF-8 XML，且文档元素为带 Adobe namespace 的 `<manifest>`。基线最小形状如下，属性顺序按配置稳定序列化：

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns="http://ns.adobe.com/f4m/1.0">
  <id>channel-1</id>
  <streamType>live</streamType>
  <media href="channel" streamId="main" bitrate="800" bootstrapInfoId="b0" />
  <bootstrapInfo id="b0" profile="named">BASE64_BOOTSTRAP</bootstrapInfo>
</manifest>
```

约束如下：

1. 根元素、namespace、`id`、`streamType` 和至少一项 `media` 必须存在；`streamType` 只能是显式 profile 允许的 `live` 或 `recorded`/VOD（点播）。
2. `media` 的 `href`/`url`、非空 `streamId`、正 `bitrate`（比特率）和 `bootstrapInfoId` 必须可解析；同一 manifest 中 streamId 不得重复。
3. `bootstrapInfo` 的 `id` 必须唯一；内容是 Base64（基于 64 个字符的二进制编码）后的 bootstrap bytes，而不是 JSON 或任意明文字符串。支持 inline（内联）文本和显式 URL profile，但二者不得同时缺失。
4. manifest 的 XML entity（实体）、属性引号、控制字符、未知必需属性和未闭合元素必须严格校验；未知可选元素按 profile 的明确兼容策略处理，不得把拼写错误静默当作已知元素。
5. manifest body 的 HTTP `Content-Length` 必须等于实际 UTF-8 字节数；截断 XML 或声明长度越过 body 末端必须失败。

## 4. Bootstrap 二进制编码

bootstrap 是独立的确定性字节流。所有 box 使用 ISO Base Media 风格的 big-endian（大端序）长度/type 头：`size:ui32 || type:4 ASCII || payload`；`size` 包含 8-byte box header，不能只计 payload。`size=1` 的 extended size 和 `size=0` 延伸到末尾，本版默认拒绝，除非 profile 显式启用并规定 64-bit 长度。

### 4.1 `abst` 主 box

`abst`（bootstrap box，启动描述盒）为 bootstrap 根盒。基线字段按下列顺序编码；版本/flags 为 1+3 字节，整数为无符号大端：

| 顺序 | 字段 | 长度/约束 |
|---:|---|---|
| 1 | box size/type | UI32 + ASCII `abst`，size 覆盖整个盒 |
| 2 | version/flags | UI8 + UI24；首版 version=0 |
| 3 | bootstrapVersion | UI32，正整数 |
| 4 | profile | UI8；profile bit field（位字段），保留位为 0 |
| 5 | live | UI8；live 标志按 profile 约束 |
| 6 | update | UI8；update 标志按 profile 约束 |
| 7 | timescale | UI32，正整数；决定 timestamp/duration 单位 |
| 8 | currentMediaTime | UI64；live/VOD profile 明确定义其语义 |
| 9 | smpteTimeCodeOffset | SI64；按 profile 定义时间码偏移，允许负值 |
| 10 | movieIdentifier | 长度前缀字符串；必须与 profile 的编码一致 |
| 11 | serverEntryTable | UI8 count，后跟每项长度前缀字符串 |
| 12 | qualityEntryTable | UI8 count，后跟每项长度前缀字符串 |
| 13 | drmData | 长度前缀字符串；无 DRM 时为空字符串 |
| 14 | metadata | 长度前缀字符串；由 profile 定义其 XML/二进制语义 |
| 15 | segmentRunTableCount | UI8 count，后跟 count 个 `asrt` child boxes |
| 16 | fragmentRunTableCount | UI8 count，后跟 count 个 `afrt` child boxes |

实现必须以实际 profile 的字段表确定第 7 项及字符串长度编码；不能为了“凑长度”插入 padding。所有 count、box size、字符串长度都必须与剩余字节严格一致。

### 4.2 `asrt` segment run table

`asrt`（Adobe segment run table，分段运行表）描述 segment 编号到 fragment 数量的映射：

```text
size(4) type="asrt" version(1) flags(3)
qualityEntryCount(1)
[qualityEntry: length-prefixed UTF-8]*
segmentRunEntryCount(4)
[firstSegment(4) fragmentsPerSegment(4)]*
```

`firstSegment` 必须为正数；同一表的 segment 起点严格递增；相邻范围不能重叠或出现未声明的隐式回退。`fragmentsPerSegment=0` 只允许 live profile 的显式开放段，不得作为普通 VOD 的缺省值。

### 4.3 `afrt` fragment run table

`afrt`（Adobe fragment run table，片段运行表）描述 fragment 的时间线：

```text
size(4) type="afrt" version(1) flags(3)
timescale(4) qualityEntryCount(1) [qualityEntry: length-prefixed UTF-8]*
fragmentRunEntryCount(4)
[firstFragment(4) firstFragmentTimestamp(8) fragmentDuration(4) [discontinuityIndicator(1) iff fragmentDuration==0]]*
```

`firstFragment` 严格递增；非零 `fragmentDuration` 使下一 timestamp 等于当前 timestamp 加 duration。`fragmentDuration=0` 仅用于 profile 定义的 discontinuity（不连续）/终止标记，必须有对应 indicator；timestamp 溢出、重叠、负向回退或表尾截断必须报错。`afrt.timescale` 必须与 `abst.timescale` 一致，除非 profile 明确声明覆盖。

## 5. F4F media fragment 编码

fragment request URI 由 manifest/media 的 URL profile 和 run table 共同确定，例如 `Seg1-Frag1`；实现必须使用 manifest 声明的 segment/fragment 编号，不得从字符串猜测另一个编号。响应为 HTTP 200 后，body 由可重组的 F4F box 序列组成：每个 box 均为 `UI32 size + 4-byte type + payload`，size 包含头。

一个最小合法 fragment fixture 至少包含 profile 要求的 fragment metadata box（例如 `afra`/`abst` 关联信息）和媒体 payload box（例如 `mdat`）；不能把任意 FLV tag、JSON 或裸 AAC/H.264 bytes 宣称为 F4F。`mdat` 的 size 必须覆盖自身 8-byte 头和实际媒体 bytes；fragment sequence、timestamp、duration 必须能与 `afrt` 对应，且不能超出 declared segment。

边界规则：

- `size < 8`、size 小于已读 box 头、size 越过 HTTP body 或 box 之间留下不可解释尾字节，均失败；
- 空 fragment 只在 profile 明确允许的终止 fixture 中可用，普通媒体 fragment 必须有非空 payload；
- fragment payload 不足一个完整媒体 sample 不由 planner 猜补；截断必须传递为 task error；
- URL 中 segment/fragment 编号、query 和 percent-encoding（百分号编码）按原始 request-target 保留，不能解码后重写。

## 6. HTTP/TCP 状态机与包序列

单 session 推荐状态机：

```text
TCP SYN/SYN-ACK/ACK
  → GET /channel.f4m
  ← HTTP 200 + F4M manifest
  → GET bootstrap/fragment URI
  ← HTTP 200 + bootstrap/F4F bytes
  → [同连接下后续 fragment GET]
  ← [fragment response]
  → keep-alive 继续或 FIN/ACK termination（终止）
```

状态不变式：

| 状态 | 允许事件 | 必须保持 |
|---|---|---|
| `Idle` | manifest GET | GET、URI、Host、HTTP/1.1 正确 |
| `ManifestReady` | bootstrap/fragment GET | media 的 streamId、bootstrapInfoId 可关联 |
| `BootstrapReady` | 按 run table 请求 fragment | segment/fragment 编号和 timestamp 单调 |
| `Streaming` | 下一 fragment、keep-alive | timescale、quality、session 状态不跨连接串用 |
| `Ended` | FIN 或显式 VOD 结束 | 结束后不得生成新的 live fragment |
| `Error` | malformed/truncated/非法关联 | planner/validator → engine（引擎）→ task error，不能 completed/0 packet |

HTTP request 必须先于对应 response；manifest 必须先于 bootstrap/fragment；bootstrap 必须先于依赖它的 fragment。keep-alive 时同一 TCP 连接可串行多个 GET/response，但每个 response 的 Content-Length 和 body 边界必须独立。无 keep-alive 时每个资源请求完成后关闭连接；多 session 必须使用独立 4-tuple（四元组）并隔离 run table、quality 和 timestamp。

## 7. 配置 typedef（类型定义）

以下是设计契约，不是当前存在的 Go struct（结构体）：

```go
type HDSConfig struct {
    Method          string        `json:"method"`          // 固定 GET
    Version         string        `json:"version"`         // HTTP/1.1
    Sessions        []HDSSession  `json:"sessions"`
    KeepAlive       bool          `json:"keep_alive"`
    Manifest        HDSManifest   `json:"manifest"`
    WireFault       string        `json:"wire_fault"`      // 仅负例
}

type HDSSession struct {
    SrcIP           string        `json:"src_ip"`
    DstIP           string        `json:"dst_ip"`
    SrcPort         uint16        `json:"src_port"`
    DstPort         uint16        `json:"dst_port"`
    ManifestURI     string        `json:"manifest_uri"`
}

type HDSManifest struct {
    ID              string        `json:"id"`
    StreamType      string        `json:"stream_type"`     // live 或 recorded
    URI             string        `json:"uri"`
    Media           []HDSMedia    `json:"media"`
    BootstrapInfos  []HDSBootstrap `json:"bootstrap_infos"`
}

type HDSBootstrap struct {
    ID              string        `json:"id"`
    Profile         string        `json:"profile"`
    Base64          string        `json:"base64"`
    URL             string        `json:"url"`
}

type HDSMedia struct {
    StreamID        string        `json:"stream_id"`
    Href            string        `json:"href"`
    Bitrate         uint32        `json:"bitrate"`
    BootstrapInfoID string        `json:"bootstrap_info_id"`
    Fragments       []HDSFragment `json:"fragments"`
}

type HDSFragment struct {
    Segment         uint32        `json:"segment"`
    Fragment        uint32        `json:"fragment"`
    Timestamp       uint64        `json:"timestamp"`
    Duration        uint32        `json:"duration"`
    Body            []byte        `json:"body"`
    SizeOverride    *uint32       `json:"size_override"` // 仅负例
}
```

Validate 必须覆盖 method/version/URI、stream type、media/stream ID、bitrate、bootstrap ID 引用、Base64、box size、version/flags、timescale、run table 单调性、fragment sequence/timestamp/duration、sessions 和 IP/TCP 载体。`wire_fault` 只能注入失败，不得作为线上字段或被忽略。

## 8. IPv4/IPv6、多会话和边界

IPv4 外层 EtherType（以太网类型）为 `0x0800`；IPv6 为 `0x86dd`，TCP Next Header（下一头）为 6。两种地址族的 HTTP/F4M/bootstrap/F4F 应用 bytes 必须相同；不能因 IPv6 改变 XML、box size、timescale 或 run table。

至少覆盖：manifest 单请求、manifest→bootstrap→fragment 多资源链、同连接 keep-alive 两个 fragment、两个独立 session、IPv6 session、MSS 导致的跨 TCP 段重组、最大明确可分配 box、empty/truncated/declared-length-overrun。不得把 UI32 size 或 UI64 timestamp 溢出包装为合法值；测试不得默认分配超大媒体 body。

## 9. 错误处理与实现集成点

必须拒绝并传播稳定错误锚点：

| 错误 | 稳定锚点 |
|---|---|
| method/version/URI/Host 错误或缺失 | `http`/`method`/`uri` |
| manifest 空、缺 root/namespace/media 或 XML 截断 | `manifest`/`xml`/`truncated` |
| streamId/bitrate/bootstrapInfoId 不合法 | `media`/`bootstrap`/`stream` |
| Base64、box type/version/flags 或 size 错误 | `bootstrap`/`box`/`size` |
| abst/asrt/afrt count、timescale、run 不连续 | `run`/`timescale`/`segment`/`fragment` |
| fragment URI 关联、sequence/timestamp/duration 错误 | `fragment`/`sequence`/`timestamp` |
| F4F box/payload 截断或 Content-Length 不一致 | `f4f`/`payload`/`length` |
| sessions 小于 1、状态跨 session 串用或 TCP 缺失 | `session`/`tcp` |

实现时应：

1. 在 layer registry（层注册表）登记 `hds` 为 Category=Terminal、DependsOn=`http`，并让 chain planner 自动补 `ip→tcp→http`；
2. 在 `core/types.go` 增加配置类型，在 strategy converter（策略转换器）解析 flat key（扁平键）和 `layers` payload；
3. 新增 F4M XML serializer/parser、bootstrap box builder/parser、F4F fragment planner，复用 HTTP/TCP MSS、checksum（校验和）和 IPv4/IPv6 builder；
4. 以 TCP stream 重组后的 HTTP Content-Length 划分资源，再以 box size 划分 bootstrap/F4F，禁止按 TCP packet 边界切消息；
5. 将 planner 错误接入 task 生命周期；未注册期间禁止将本文正例加入可执行 suite；
6. PCAP 使用已注册 HTTP/IP/TCP 字段和 `frames` 的实际 body 起点断言；动态 Content-Length 可在 fixture 固定时断言，不能硬编码运行期随机 ID。

## 10. 原子 ID 与完成定义

共 18 个唯一 ID，13 个目标正例、5 个严格负例。ID、覆盖和顺序必须与 `47-hds-testcase.md` 完全一致。当前 `cases/hds.json` 只放第 18 项的未注册占位；其余 17 项仅为文档契约。

| # | ID | 类型 | 覆盖 |
|---:|---|---|---|
| 1 | `hds_manifest_ipv4` | 正 | IPv4/TCP/HTTP GET、F4M root、media |
| 2 | `hds_bootstrap_abst` | 正 | Base64 bootstrap、abst header/timescale |
| 3 | `hds_asrt_segment_runs` | 正 | asrt segment run 与 fragment 数 |
| 4 | `hds_afrt_fragment_runs` | 正 | afrt timestamp/duration/discontinuity |
| 5 | `hds_fragment_f4f` | 正 | F4F box、mdat payload、fragment URI |
| 6 | `hds_manifest_bootstrap_fragment` | 正 | manifest→bootstrap→fragment 状态机 |
| 7 | `hds_keepalive_fragments` | 正 | 同 TCP session 多 fragment GET/response |
| 8 | `hds_multi_session` | 正 | 多 4-tuple、状态和时间线隔离 |
| 9 | `hds_ipv6` | 正 | IPv6/TCP/HTTP，应用字节语义不变 |
| 10 | `hds_mss_reassembly` | 正 | HTTP/F4F 跨 TCP segment 重组 |
| 11 | `hds_live_update` | 正 | live bootstrap update、run table 单调更新 |
| 12 | `hds_vod_end` | 正 | recorded/VOD 终止、FIN 后无新 fragment |
| 13 | `hds_boundary_box` | 正 | 最小 box、明确最大 size、长度边界 |
| 14 | `hds_neg_manifest` | 负 | 空/截断/非法 XML 或 manifest 关联 |
| 15 | `hds_neg_bootstrap` | 负 | Base64/abst/asrt/afrt size、count、run 错误 |
| 16 | `hds_neg_fragment` | 负 | F4F box/payload/sequence/timestamp 截断或越界 |
| 17 | `hds_neg_session_state` | 负 | 跨 session 引用、keep-alive 状态回退 |
| 18 | `hds_neg_unregistered` | 负 | 当前层注册表未注册，必须 `unknown layer` |

完成定义：F4M XML、abst/asrt/afrt 和 F4F box 可逐字节生成/解析；HTTP/TCP 状态、keep-alive、MSS 重组、IPv4/IPv6 和多 session 有集成测试；每个负例真正传播为 task error；未注册阶段不报告任何语义正例通过。

## 11. 修订记录

- v1.0.0（2026-08-20）：建立 HDS over HTTP/TCP 设计契约，覆盖 F4M、bootstrap `abst/asrt/afrt`、F4F fragment、状态机、配置、字节长度、双栈、多会话、keep-alive、边界及错误传播；不修改 Go 实现。

# #133 SSDP（UPnP Simple Service Discovery Protocol）设计契约

> 版本：v1.0（as-built，2026-09-29）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/ssdp.json`（当前 1 例）  
> 实现：`trafficgen/internal/protocol/ssdp/{planner.go,layer_gen.go}`；配置 `internal/core/types.go:7666`；registry `internal/core/layers/registry.go:181`。

## 0. 范围与事实边界

本契约描述当前实现的 SSDP 消息生成：HTTP/1.1 风格文本承载于 UDP 1900，支持 NOTIFY（alive/byebye/update）、M-SEARCH 及 200 OK response。SSDP 每条消息是独立 UDP datagram，不建立 TCP 连接、无 HTTP keep-alive/chunked 语义。当前 cases 只有 `ssdp_smoke_01`；未写入 cases 的能力均为实现能力说明或待测边界，不得报告为已覆盖。

规范依据：UPnP Device Architecture 1.1 §1.2（通知）、§1.3（搜索与响应）、§1.2.2（max-age/重发）、§1.3.4（MX 响应延迟）；SSDP 规范历史草案 `draft-cai-ssdp-v1-03 §6.2`（多播 TTL=4）；RFC 1112 §6.4（IPv4 多播 MAC）、RFC 2464 §7（IPv6 多播 MAC）；HTTP 行与 CRLF 语法沿用 RFC 7230 §3。RFC 6762 是 mDNS 规范，并非 SSDP 定义；本实现的 SSDP 语义以 UPnP DA 为准。

## 1. 协议栈、配置形状与接线

推荐层链为 `[ip, udp, ssdp]`，最小链 `[udp, ssdp]`；registry 将 `ssdp` 注册为 `CategoryTerminal`、依赖 `udp`。`strategy_convert.go:1490` 将层内 `ssdp` 映射到 `FlowSpec.SSDP`，`parseSSDPConfig` 位于 `:5919`。生成入口为 `SSDPGenerator.Generate`（`layer_gen.go:44`）；legacy `Planner.Plan` 在 `planner.go:207`，两者复用同一组 payload builder。

目标层链形状是 `[udp,ssdp]`，但当前唯一 case 的 `spec_json` 仍同时保留顶层 `src_port` 与顶层 `ssdp` 子映射：这是当前 as-built 输入形状，记录为迁移缺口而非改写 cases。

```json
{"layers":[{"udp":{}},{"ssdp":{}}],"src_port":0,"ssdp":{"message_type":"msearch","search_target":"ssdp:all"}}
```

该形状不是严格的纯层链形；后续接线应把协议字段迁入 `layers[].ssdp`，且不得删减本例已有断言。

端口：`DefaultPort=1900`（`planner.go:43`）。`src_port=0` 在 planner 中有效默认到 1900；显式源端口只接受 1900 或 0，目的端口只接受 1900（`planner.go:192-199`、`layer_gen.go:263-270`）。当前 smoke 的关键事实是 `src_port=0`，因此请求和自动响应均为 1900/1900。

## 2. 消息模型与线格式

每个事件对应一个 UDP datagram，文本使用 ASCII/UTF-8 字节、每行 `CRLF`，空行结束头部；无 body 的消息总长度为所有首行/头行字节之和加每个 CRLF 与末尾 CRLF。实现不插入 Content-Length，除非 `EmitContentLength=true` 且 response 有 body。

### 2.1 M-SEARCH

请求形状（`buildSSDPMSearch`, `planner.go:571-607`）：

```
M-SEARCH * HTTP/1.1\r\n
HOST: <multicast-host>:1900\r\n
MAN: "ssdp:discover"\r\n
MX: <1..5>\r\n
ST: <SearchTarget>\r\n
[USER-AGENT: <Server>\r\n]
\r\n
```

`HOST` 默认 IPv4 `239.255.255.250:1900`，源 IP 为 IPv6 时默认 `[ff02::c]:1900`（`buildHostHeader`, `planner.go:454-463`）；`MX=0` 默认 3 秒；`ST` 来自 `SearchTarget`，当前 smoke 为 `ssdp:all`。当前 case 的固定 payload 起点是 offset 42，且断言首行、HOST、MAN、MX、ST 原始字节。

### 2.2 200 OK response

响应形状（`buildSSDPResponse`, `planner.go:624-686`）：

```
HTTP/1.1 200 OK\r\n
CACHE-CONTROL: max-age=<N>\r\n
[DATE: <HTTP-date>\r\n]
EXT:\r\n
[LOCATION: <URL>\r\n]
[SERVER: <Server>\r\n]
ST: <SearchTarget>\r\n
USN: <USN>\r\n
[CONTENT-LENGTH: <len(Body)>\r\n]
\r\n[Body]
```

`MAX-AGE` 默认 1800 秒；`EXT:` 默认存在；`ST` 与 `USN` 必须由配置提供。M-SEARCH 自动 response 的目标是请求的 `spec.SrcIP/srcPort`，不是多播组。当前 smoke response 起点 offset 42，断言 200、HTTP/1.1、CACHE-CONTROL max-age=1800、EXT、ST 原始字节；实现生成的 `EXPIRE` 不存在，随机延迟不作断言。

### 2.3 NOTIFY

`buildSSDPNotify`（`planner.go:481-558`）生成：

```
NOTIFY * HTTP/1.1\r\n
HOST: <multicast-host>:1900\r\n
[CACHE-CONTROL: max-age=<N>\r\n]
[LOCATION: <URL>\r\n]
NT: <SearchTarget>\r\n
NTS: ssdp:<alive|byebye|update>\r\n
[SERVER: <Server>\r\n]
USN: <USN>\r\n
[BOOTID.UPNP.ORG: <uint32>\r\n]
[CONFIGID.UPNP.ORG: <uint32>\r\n]
[NEXTBOOTID.UPNP.ORG: <uint32>\r\n]
[SEARCHPORT.UPNP.ORG: <uint16>\r\n]
\r\n
```

`byebye` omits CACHE-CONTROL/LOCATION/SERVER；其他类型按字段启用规则输出。当前 cases 未覆盖 NOTIFY。

## 3. 字段、校验与默认

`SSDPConfig`（`types.go:7685-7782`）字段为 `MessageType`、`SearchTarget`、`USN`、`Location`、`Server`、`MaxAge`、`MX`、`BootID`、`ConfigID`、`NextBootID`、`SearchPort`、`ResponseCount`、`ResponseDelayMinMs/MaxMs`、`RepeatCount`、`Date`、`MulticastGroup`、`OmitExt`、`Body`、`EmitContentLength`、`RepeatIntervalMs`。

| 校验/缺省 | 规则与错误锚词 |
|---|---|
| MessageType | 必填；允许 alive/byebye/update/msearch/response；否则 `ssdp unknown message_type` |
| SearchTarget | 所有类型必填；msearch 锚词 `ssdp st (search_target) is required for msearch`，其他为 `ssdp nt ...` |
| USN | alive/byebye/update/response 必填；锚词 `ssdp usn is required`；长度 ≤4096 |
| Server | 长度 ≤4096；超限 `ssdp server header exceeds maximum`；256 仅建议警告常量 |
| MaxAge | alive 时 0→1800；>1800 或 <0 拒绝 |
| MX | msearch 时 0→3；>5 或 <0 拒绝 |
| 响应延迟 | response_count>1 要求 min≤max；超范围锚词 `ssdp response delay exceeds mx` |
| 端口/IP | IP 必须可解析；目的端口 1900；源端口 1900 或 0 |

配置缺省为空 `SSDPConfig` 时，`Generate`/`Plan` 默认 `alive + search_target=upnp:rootdevice`（`layer_gen.go:47-50`, `planner.go:217-220`）。非零 `TTL` 由 layer generator 使用；legacy planner 对 0 使用 `DefaultTTL=4`。实现注释称 SSDP 多播 TTL=4；生成器实际 `effectiveTTL=req.Meta.TTL`，因此链路显式 TTL 非零时可覆盖该默认。

## 4. 地址、流与状态

IPv4 默认组 `239.255.255.250`；IPv6 默认组 `ff02::c`。多播 IP 导出 MAC：IPv4 `01:00:5e:(IP低23位)`（RFC 1112），IPv6 `33:33:(IP低32位)`（RFC 2464）。`M-SEARCH` 与 NOTIFY 发往组地址；自动 response 单播回源地址。`MulticastGroup` 可覆盖组/目标，`DstMAC` 可显式覆盖。IP 目的地址不等于 SSDP HOST 语义时，HOST 头仍由组地址计算（当前 case 明确不断言 `ip.dst`）。

SSDP 无连接状态机。一次 M-SEARCH 事务是 `M-SEARCH → 0..N 个 200 OK`；当前默认 `ResponseCount=0` 被解释为 1 个响应。NOTIFY 是单向事件。`RepeatCount` 对 alive/update 产生多个独立 datagram，默认间隔 `MaxAge/3` 秒，或 `RepeatIntervalMs`。多会话、多流、父子流关联、TCP FIN/RST 不适用，原因是每个 datagram 独立且协议无连接；UDP 层每事件一 datagram。

## 5. 动态字段清单与序号

| 字段 | 动态写法/当前落点 | 序号算法/证据 |
|---|---|---|
| src_ip/dst_ip/src_port/dst_port | 框架四元组；端口 0→1900 | `planner.go:242-261`；每 packet 使用同一有效四元组，response 目标切到源 |
| message_type/search_target/usn | SSDPConfig 字符串 | 每事件读取配置；不在顶层另起字段 |
| max_age/mx | SSDPConfig 整数 | 0 使用固定默认；MX 决定随机 response 延迟上限 |
| response_count/repeat_count | SSDPConfig 整数 | `for` 循环逐事件递增 `packetIndex` |
| boot_id/config_id/next_boot_id/search_port | NOTIFY 头 | 仅非零且类型匹配时输出 |
| location/server/date/body | 头/body | 静态配置逐事件复制 |
| packet_index/ip_id | 生成器内部 | legacy `packetIndex` 从 0 递增，`ipID` 每包递增；层事件由 transport 接续 |

当前未证明 strategy 的 fixed/inc/rand/list/pattern 对上述协议字段均可用；`strategy_convert` 只负责静态 SSDPConfig 解析。该动态能力记为待实现边界，不计已覆盖。

## 6. 五层覆盖与业务场景

- **功能层**：已有 M-SEARCH 请求 + 自动 200 OK（`ssdp_smoke_01`）；NOTIFY 三种类型与 standalone response 的正例、非法 message_type/必填字段/端口错误均待测。
- **性能层**：已有双 datagram 基线；待测 RepeatCount、ResponseCount 多响应、最大 Server/USN、最大 UDP payload/分片边界。UDP 不存在 MSS/重组。
- **数据场景层**：已有 `ST=ssdp:all`、默认 MX/max-age、CRLF 原始字节；待测 UUID/URN、Location/Server/Body、0/上限/相邻溢出、非法编码与 Content-Length。
- **地址与流层**：代码支持 IPv4/IPv6 默认多播和 TTL/MAC 推导；当前 case 仅 IPv4 语义；IPv6、显式单播 response、混合地址族拒绝待测；多流/流关联不适用。
- **业务层**：已有控制点搜索并获得设备响应；设备上线/下线/更新、重复公告、多响应发现、多会话均待测。多事务仅为 M-SEARCH 的响应集合，不存在连接内事务。

典型生成顺序：配置 → validator → planner/layer generator → 事件（M-SEARCH/NOTIFY）→ UDP datagram；M-SEARCH 事件后按 response_count 自动延迟并回源生成 200 OK。

## 7. 门1：§1–§14 十四行对照表

| 条款 | SSDP 满足方式 | 证据 |
|---|---|---|
| §1 范围/旧键 | 当前 `ssdp_smoke_01` 使用 `[udp,ssdp]` 层链，但 JSON 仍有顶层 `src_port` 和 `ssdp` 子映射；迁移去向是 `layers[].ssdp`，不可报告为纯层链 | 本节、case `spec_json`、`strategy_convert.go:1490`、G-SSDP-8 |
| §2 规范依据 | UPnP DA 1.1 §1.2/§1.3、RFC 1112/2464、draft §6.2 | §0 |
| §3 五件套 | 会话表/父子流/多流均不适用；事务为 M-SEARCH 与响应，插入位置 UDP 每事件一 datagram，时间线见 §4/§6 | §4、`planner.go:378-441` |
| §4 五层覆盖 | 五层逐层列出现有与待测行为 | §6 |
| §5 线格式 | HTTP/1.1 首行、CRLF 头、空行；M-SEARCH/response/NOTIFY 逐字段 | §2 |
| §6 状态机 | 无连接状态；请求→响应的有限事务、NOTIFY 单向 | §4 |
| §7 错误处理 | validator 锚词与边界清单 | §3 |
| §8 性能容量 | 单 datagram；repeat/response count；USN/Server 上限 | §6、§3 |
| §9 地址与流 | UDP 1900、IPv4/IPv6 组、TTL、MAC、单播 response | §4 |
| §10 业务 | 搜索发现、公告/撤销/更新 | §6 |
| §11 输出契约 | pcap 与 NIC 共用 cases 断言；NIC 尚未实测登记缺口 | §8 |
| §12 动态字段 | 四元组、消息字段、packet/IP ID 清单；策略五态未证 | §5 |
| §13 注册与接线 | registry terminal/udp；layer generator、strategy convert 均接通 | §1 |
| §14 缺口与验收 | 当前 1 case；待测面、过期结果、coverage gate 建议见 §8 | §8 |

## 8. 缺口登记、过期产物与覆盖反查门

| ID | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-SSDP-1 | 只有 M-SEARCH smoke，NOTIFY/response 独立消息类型无 case | `cases/ssdp.json` 仅 1 ID；`planner.go:344-448` | P3 用例覆盖 |
| G-SSDP-2 | IPv6 多播、TTL、MAC 推导无断言 | `layer_gen.go:61-82`、`planner.go:272-305`；当前 case 仅 IPv4 | P3 地址覆盖 |
| G-SSDP-3 | validator 错误分支、边界上限无负例 | `planner.go:98-167`；cases 无 expect_error | P3 失败路径 |
| G-SSDP-4 | repeat/multi-response 延迟和包数无 case | `planner.go:344-441`；仅 packet_count=2 | P3 性能/业务 |
| G-SSDP-5 | 动态字段 fixed/inc/rand/list/pattern 未由 SSDP case 证明 | `strategy_convert.go:5919-5950` | P2 动态接线 |
| G-SSDP-6 | pcap/NIC 双路径尚未本轮实测；tracked 结果过期 | `trafficgen/docs/protocol-pcap-test/ssdp.md` 最后提交 2026-08-27，早于 0417be5 | P5 回归 |
| G-SSDP-7 | 当前 payload 断言不覆盖 tshark HTTPU 字段/多播 TTL | case 仅 fields + frames offset 42 | P4 断言增强 |
| G-SSDP-8 | 唯一 case 的 `spec_json` 仍含顶层 `src_port` 与顶层 `ssdp` 子映射，未达纯层链形 | `cases/ssdp.json:6-20` | P1 形状迁移 |

覆盖反查门建议静态断言：`ssdp_smoke_01` 必须存在且顺序唯一；`packet_count=2`；UDP src/dst port 均 1900；packet 1 首行 `M-SEARCH * HTTP/1.1`，packet 2 `HTTP/1.1 200 OK`；packet 1/2 frame offset 42 必须含 `HOST`、`ST`，请求含 `MAN`/`MX`，响应含 `CACHE-CONTROL`/`EXT`；`spec_json.layers` 必须为 `[udp,ssdp]` 且不得有游离顶层 `ssdp`。

## 9. pcap/NIC 契约与修订记录

两种输出均使用同一 cases JSON：pcap 断言 UDP/HTTPU 可观察字段与 raw frame；NIC 捕获仅改变采集路径，不改变 packet_count、方向或字节契约。当前未执行 NIC，不能宣称双路径通过。

- v1.0（2026-09-29）：按当前实现与唯一 case 逆向定稿；已知未覆盖面登记 G-SSDP-1…8。

自审：脚本/grep 复核字段、ID、包数、offset、JSON 形状与行号，**自审 3 轮，末轮干净**；待独立代码设计与用例覆盖审查。
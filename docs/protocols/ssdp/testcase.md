# #133 SSDP 测试用例契约

> 版本：v1.0（as-built，2026-09-29）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/ssdp.json`；当前唯一权威 ID 为 `ssdp_smoke_01`。

## 1. 测试原则与输出形状

本协议当前只有 1 个可执行例，不能把未来 NOTIFY、IPv6、负例写入当前 ID 集合。每个断言必须对应 UPnP Device Architecture 1.1 §1.3 的 M-SEARCH/response 语义、UDP 1900 端口约定或实现的原始字节输出。pcap 与 NIC 使用同一 cases JSON；本轮没有 NIC 实测，因此不报告双路径通过。

`spec_json` 已迁移为严格层链 `[udp,ssdp]`：端口住 `udp` 层，业务字段住 `ssdp` 层，顶层仅有 `layers`。本节断言保持不变；G-SSDP-8 已关闭。

SSDP 载荷起点固定为 IPv4 无 VLAN/options 时 offset 42（14 Ethernet + 20 IPv4 + 8 UDP）。当前 case 不断言 IP 目的地址，因为探针显示 L3 目标可由 fixture 提供，而 SSDP 多播语义由 `HOST` 头承载。

## 2. 原子用例索引（与 JSON 一致）

| # | ID | 类型 | 场景/依据 | 包数 | 可观察断言 |
|---:|---|---|---|---:|---|
| 1 | `ssdp_smoke_01` | 正 | UPnP DA 1.1 §1.3：控制点 M-SEARCH `ssdp:all`，自动 200 OK；端口默认化实现 `planner.go:249-258` | 2 | UDP 1900/1900；请求 `M-SEARCH * HTTP/1.1`；响应 `HTTP/1.1 200 OK`；请求/响应 raw headers |

该例不可再拆的行为点是：一条 M-SEARCH 请求和其一条自动响应组成一个最小请求-响应事务，且每个 datagram 仍需分别验证 UDP 端口、首行、HTTP 版本与协议关键头。它不是对 NOTIFY、IPv6 或错误路径的替代。

## 3. `ssdp_smoke_01` 逐字段契约

输入：

```json
{
  "layers":[{"udp":{"src_port":0}},{"ssdp":{"message_type":"msearch","search_target":"ssdp:all"}}]
}
```

`udp.src_port=0` 是关键输入：SSDP validator 只允许 1900 或 ephemeral 0；planner 将 0 解析为 1900。请求目的端口默认 1900。两包因此均为 UDP 1900/1900。

### 3.1 packet 1：M-SEARCH

必须满足：

- `udp.srcport = 1900`、`udp.dstport = 1900`。
- `http.request.method = M-SEARCH`、`http.request.version = HTTP/1.1`、`http.request.uri = *`。
- offset 42 起始字节必须匹配以下序列（这是前缀断言，不声称覆盖整个 datagram）：

```text
4d 2d 53 45 41 52 43 48 20 2a 20 48 54 54 50 2f 31 2e 31 0d 0a
48 4f 53 54 3a 20 32 33 39 2e 32 35 35 2e 32 35 35 2e 32 35 30 3a 31 39 30 30 0d 0a
4d 41 4e 3a 20 22 73 73 64 70 3a 64 69 73 63 6f 76 65 72 22 0d 0a
4d 58 3a 20 33 0d 0a 53 54 3a 20 73 73 64 70 3a 61 6c 6c 0d 0a
```

这逐字证明首行、HOST 多播组、MAN、默认 MX=3 和配置的 ST；末尾 CRLF 是边界。tshark HTTP dissector 不提供可靠独立 `http.st/http.host/http.man/http.mx` 字段，因此 raw bytes 是可执行的协议字段证据。

### 3.2 packet 2：200 OK

必须满足：

- `udp.srcport = 1900`、`udp.dstport = 1900`。
- `http.response.code = 200`、`http.response.version = HTTP/1.1`。
- offset 42 起始字节必须匹配以下序列（这是前缀断言，不声称覆盖整个 datagram）：

```text
48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d 0a
43 41 43 48 45 2d 43 4f 4e 54 52 4f 4c 3a 20 6d 61 78 2d 61 67 65 3d 31 38 30 30 0d 0a
45 58 54 3a 0d 0a
53 54 3a 20 73 73 64 70 3a 61 6c 6c 0d 0a
```

这逐字证明 HTTP 200、HTTP/1.1、默认 max-age=1800、UPnP `EXT:` 和 ST。响应的随机 MX 延迟、IPID/checksum 不纳入断言。

## 4. 存量审计与负例纪律

| 存量 ID | 去向 | 结论 |
|---|---|---|
| `ssdp_smoke_01` | 保留 | 唯一现有 case；2 包、字段、raw frame 与实现一致 |

当前无 `expect_error` case。validator 已有但未覆盖的锚词包括：`ssdp message_type is required`、`ssdp unknown message_type`、`ssdp st (search_target) is required for msearch`、`ssdp usn is required`、`ssdp destination port must be 1900`、`ssdp source port must be 1900 or ephemeral (0)`、`ssdp max-age exceeds UPnP 1.1 limit (1800)`、`ssdp mx exceeds UPnP recommended max (5)`、USN/Server 上限和响应延迟范围。后续负例必须每例只注入一个错误，且只保留 `expect_error` 与 `error_contains`，不得用成功 PCAP 代替失败传播。

## 5. 五层覆盖盘点

- **功能**：已覆盖 M-SEARCH → 200 OK 最小请求响应；未覆盖 NOTIFY alive/byebye/update 与 standalone response。
- **性能**：已覆盖 2 datagram 基线与最短默认头；未覆盖 RepeatCount、ResponseCount>1、Server/USN 上界及最大 UDP payload。
- **数据**：已覆盖 ST=ssdp:all、默认 MX/max-age、HTTP/1.1、CRLF 及 HOST/MAN/EXT；未覆盖 UUID/URN、Location、Server、Date、Body/Content-Length、字段上界/非法值。
- **地址与流**：已覆盖 UDP 1900/1900 和 IPv4 HOST 多播语义；未覆盖 IPv6 `ff02::c`/方括号 HOST、IPv6 MAC、TTL=4、显式单播 response；协议无 TCP 连接、流关联、多流，均不适用。
- **业务**：已覆盖控制点发现；未覆盖设备上线/撤销/更新、多次公告、多个设备响应。SSDP 多事务仅体现为一次请求后多个独立响应，不是长连接多事务。

## 6. 缺口登记

| ID | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-SSDP-1 | 只有一个 smoke，NOTIFY 三类型/standalone response 无正例 | cases 仅 `ssdp_smoke_01`; `planner.go:344-448` | P3 功能 |
| G-SSDP-2 | IPv6、TTL、MAC 和多播/单播目标无可执行断言 | `layer_gen.go:61-82`; cases 仅 IPv4 | P3 地址 |
| G-SSDP-3 | validator 所有错误分支无负例与 task-error 传播断言 | `planner.go:98-167`; cases 无 `expect_error` | P3 失败路径 |
| G-SSDP-4 | repeat、多响应、延迟和包数无例 | `planner.go:344-441` | P3 性能/业务 |
| G-SSDP-5 | 动态策略五态未由协议 case 证明 | `strategy_convert.go:5919-5950` | P2 动态 |
| G-SSDP-6 | tracked 结果文档过期且未有本轮 pcap/NIC 证据 | `trafficgen/docs/protocol-pcap-test/ssdp.md`, 2026-08-27 < 0417be5 | P5 回归 |
| G-SSDP-7 | raw frame 已覆盖关键头，但无 tshark HTTPU/TTL 字段断言 | 当前 case `frames`/`fields` 列表 | P4 断言 |
| G-SSDP-8 | 已关闭：端口与业务字段均已迁入层链 | `cases/ssdp.json:6-20`；顶层仅 `layers` | P1 迁移完成 |

## 7. 覆盖反查门建议断言

供主线程登记 `coverage_gate.py`，本车道不改共享门文件。建议每条静态可机读：

1. 存在且仅存在 `ssdp_smoke_01`，`proto=ssdp`。
2. `spec_json` 顶层键恰为 `{layers}`，层链为 `[udp,ssdp]`；`udp.src_port` 和 `ssdp.message_type/search_target` 均不得游离。
3. `packet_count=2`，两包 `udp.srcport=1900`、`udp.dstport=1900`。
4. packet 1 字段含 `M-SEARCH`、`HTTP/1.1`、`*`；packet 2 含响应 200、`HTTP/1.1`。
5. packet 1 frame offset 42 含 `M-SEARCH * HTTP/1.1`、`HOST: 239.255.255.250:1900`、`MAN: "ssdp:discover"`、`MX: 3`、`ST: ssdp:all`。
6. packet 2 frame offset 42 含 `HTTP/1.1 200 OK`、`CACHE-CONTROL: max-age=1800`、`EXT:`、`ST: ssdp:all`。
7. 原始帧断言总数为 2，且每条 hex 的 offset 为 42；不将 `ip.dst` 当作 SSDP HOST 断言。
8. `udp.src_port=0` 必须保留，防止把 planner 的默认端口路径误测成显式非默认端口。

## 8. 修订记录与自审

- v1.0（2026-09-29）：按 `cases/ssdp.json` 唯一 case、planner/layer generator/config/registry 接线逆向定稿；未覆盖行为登记 G-SSDP-1…8。

自审：逐条复核 JSON ID、包数、字段、offset、hex、形状缺口与实现路径；**自审 3 轮，末轮干净**；待独立代码设计与用例覆盖审查。

## 9. 测试点清单与三源回指（T1/T2/T3）

| 规范要求 | 业务场景 | 代码分支 | 用例/缺口 | 强度 |
|---|---|---|---|---|
| UPnP DA 1.1 §1.3 M-SEARCH 请求 | 控制点发现 | `planner.go:571-607` | `ssdp_smoke_01` | 正常数据+raw 边界 |
| UPnP DA 1.3 200 OK | 设备响应 | `planner.go:624-686` | `ssdp_smoke_01` | 响应码与原始字节 |
| DA §1.2 alive/byebye/update | 设备公告生命周期 | `planner.go:481-558` | G-SSDP-1 | 枚举逐值，待新增例 |
| DA §1.2.2 max-age / §1.3.4 MX | 缓存与延迟边界 | `planner.go:98-167` | G-SSDP-3/G-SSDP-4 | 0/上限/溢出 |
| draft-cai §6.2 TTL=4 | 多播发送 | `layer_gen.go:263-270` | G-SSDP-2 | IPv4/IPv6 正交 |

三源结论：规范来源为表中 UPnP/RFC 条款；设计回指 §2–§6；现网行为以当前 raw frame 断言为准。未有商业设备抓包的条目标 G-SSDP-1/G-SSDP-2，确认方式为采集真实 UPnP 控制点/设备 pcap 后补例。每个已实现分支至少一个例；其余列入缺口，不把现有 smoke 代替。

## 10. §3.15 事务覆盖

SSDP 是无连接、每消息独立 datagram 的协议，因此无“同连接多轮操作”与长连接保活；该边界由 UDP 独立报文模型决定。现有 `ssdp_smoke_01` 覆盖一个 M-SEARCH→response 事务。非正常结束（截断头、非法必填字段）尚无可执行例，登记 G-SSDP-3，后续以 `expect_error` + `error_contains` 逐分支补齐。重复公告/多响应不属于连接保活，登记 G-SSDP-4。

## 11. 存量审计与失败断言

唯一存量 ID `ssdp_smoke_01` 已合入，未作废、未拆分；其 2 包、9 条字段和 2 条 raw frame 均与 JSON 对账。当前无负例，因此 validator 失败路径仍是明确缺口；补例时每条只注入一个错误，expect 只含 `expect_error` 与准确的 `error_contains`，并断言任务提交失败而非“没有崩溃”。

## 12. 真实流程与性能验收

pcap 路径：MCP 建策略/任务→生成 pcap→tshark 校对端口、首行、HTTP 版本与 offset 42 raw bytes。NIC 路径：同一 JSON 通过 tcpdump 捕获，再校对同一字段；本轮 NIC 未执行，不能宣称通过。性能验收覆盖 2 包基线、RepeatCount/ResponseCount 压力、长时间公告、并发交错和队列背压；指标（包/秒、并发流、单包长度、内存、队列、CPU）以实测记录，未测项标 G-SSDP-4，不虚构数值。

## 13. T 编号与覆盖反查

`ssdp_smoke_01` 为 T-SSDP-1；G-SSDP-1…G-SSDP-7 分别对应待补测试点。反查必须检查顶层 `{layers}`、层内端口/业务字段、2 包、9 条 fields、2 条 frames 及所有 ID，禁止只按总数判绿。

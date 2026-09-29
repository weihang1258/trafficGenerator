# #133 SSDP 测试用例契约

> 版本：v1.0（as-built，2026-09-29）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/ssdp.json`；当前唯一权威 ID 为 `ssdp_smoke_01`。

## 1. 测试原则与输出形状

本协议当前只有 1 个可执行例，不能把未来 NOTIFY、IPv6、负例写入当前 ID 集合。每个断言必须对应 UPnP Device Architecture 1.1 §1.3 的 M-SEARCH/response 语义、UDP 1900 端口约定或实现的原始字节输出。pcap 与 NIC 使用同一 cases JSON；本轮没有 NIC 实测，因此不报告双路径通过。

`spec_json` 的目标形状是层链 `[udp,ssdp]`；但唯一存量 case 仍保留顶层 `src_port` 与顶层 `ssdp` 子映射，这是当前机器契约的迁移形，不能在文档中假报为纯层链。该问题登记为 G-SSDP-8；后续改形必须保持本节所有断言。

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
  "layers":[{"udp":{}},{"ssdp":{}}],
  "src_port":0,
  "ssdp":{"message_type":"msearch","search_target":"ssdp:all"}
}
```

`src_port=0` 是关键输入：SSDP validator 只允许 1900 或 ephemeral 0；planner 将 0 解析为 1900。请求目的端口默认 1900。两包因此均为 UDP 1900/1900。

### 3.1 packet 1：M-SEARCH

必须满足：

- `udp.srcport = 1900`、`udp.dstport = 1900`。
- `http.request.method = M-SEARCH`、`http.request.version = HTTP/1.1`、`http.request.uri = *`。
- offset 42 的完整字节必须为：

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
- offset 42 的完整字节必须为：

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
| G-SSDP-8 | 唯一 case 仍有顶层 `src_port` 与 `ssdp` 子映射，不是纯层链形 | `cases/ssdp.json:6-20`；`spec_json` 非仅 `layers` | P1 形状迁移 |

## 7. 覆盖反查门建议断言

供主线程登记 `coverage_gate.py`，本车道不改共享门文件。建议每条静态可机读：

1. 存在且仅存在 `ssdp_smoke_01`，`proto=ssdp`。
2. `spec_json.layers` 恰为 `[udp,ssdp]`，并显式登记当前顶层 `src_port`/`ssdp` 迁移形（G-SSDP-8）；后续纯层链迁移门不得允许游离键。
3. `packet_count=2`，两包 `udp.srcport=1900`、`udp.dstport=1900`。
4. packet 1 字段含 `M-SEARCH`、`HTTP/1.1`、`*`；packet 2 含响应 200、`HTTP/1.1`。
5. packet 1 frame offset 42 含 `M-SEARCH * HTTP/1.1`、`HOST: 239.255.255.250:1900`、`MAN: "ssdp:discover"`、`MX: 3`、`ST: ssdp:all`。
6. packet 2 frame offset 42 含 `HTTP/1.1 200 OK`、`CACHE-CONTROL: max-age=1800`、`EXT:`、`ST: ssdp:all`。
7. 原始帧断言总数为 2，且每条 hex 的 offset 为 42；不将 `ip.dst` 当作 SSDP HOST 断言。
8. `src_port=0` 必须保留，防止把 planner 的默认端口路径误测成显式非默认端口。

## 8. 修订记录与自审

- v1.0（2026-09-29）：按 `cases/ssdp.json` 唯一 case、planner/layer generator/config/registry 接线逆向定稿；未覆盖行为登记 G-SSDP-1…8。

自审：逐条复核 JSON ID、包数、字段、offset、hex、形状缺口与实现路径；**自审 3 轮，末轮干净**；待独立代码设计与用例覆盖审查。
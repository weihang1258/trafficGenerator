# DHCPv6（RFC 8415）测试用例契约

> 编号 #147；as-built 文档轨版本 v1.0（2026-09-29）。机器契约 `trafficgen/test/protocol_pcap/cases/dhcpv6.json` 为权威，本文件与它逐条一致（ID 集合、顺序、包数、断言、锚词）。设计配套 `docs/protocol-designs/147-dhcpv6-design.md`。

## 1. 原则与形状基线

- 一个用例只验证一个可独立判定的测试点；断言针对实际输出值（tshark 字段、包数、XID 关联），不断言"任务没报错"。
- 现有 1 例：`dhcpv6_smoke_01`，正例 SARR 冒烟。形状机读：顶层键 `expect,id,proto,spec_json,summary`；`spec_json` 顶层键 `layers,src_ip,dst_ip,src_mac,dhcpv6`——**四个游离顶层键与层链并存，G-DHCPV6-1**；层链 `[udp,dhcpv6]`；负例今日为零。
- 输出契约：pcap 与 NIC 两条输出路径使用同一 JSON 断言；本车道未跑套件，登记见设计 §7。
- 动态字段：XID 与自动 DUID 含随机/时间成分，断言使用"存在 + same_as_packet 关联"锚点而非常量（`dhcpv6.xid`）。

## 2. 用例索引（逐条与 JSON 一致，顺序为权威）

| # | ID | 类型 | 场景 | 依据链 | 包数 | 断言要点 |
|---:|---|---|---|---|---:|---|
| 1 | `dhcpv6_smoke_01` | 正 | SARR 四包（Solicit/Advertise/Request/Reply），租约 `2001:db8::100`，src 保持 12345、dst 547 | RFC 8415 §6.4/§7.3；`scenario.go:210-220` | 4 | `udp.dstport=547`、`dhcpv6.msgtype` 1/2/3/7、`dhcpv6.iaaddr.ip=2001:db8::100`、`ipv6.src` 按方向交换（2001:db8::1 ↔ 2001:db8::2）、`eth.src=aa:bb:cc:dd:ee:ff`、`ipv6.hlim=64`、`dhcpv6.xid` 存在且 2/3/4 与首包一致、`ipv6.dst=2001:db8::2`（packet 1/3） |

`notes` 另记载：端口方向解析与 `strategy_convert`/`resolveAddrs` 一致；Solicit/Request 目的为单播（RFC 允许多播 ff02::1:2，生成器选单播）；层链形式 `[udp,dhcpv6]` 且顶层字段保留（即 G-DHCPV6-1 现状）。

## 3. 正例断言明细（`dhcpv6_smoke_01`）

- packet_count=4；每包是一个 DHCPv6 消息一个 UDP datagram。
- 方向与端口：up 包（1、3）src=12345 → dst=547；down 包（2、4）反向。fixture 只断言 packet 1 `udp.dstport=547`（JSON 现状）。
- IPv6 交换：packet 1/3 src=2001:db8::1 dst=2001:db8::2；packet 2/4 反向（断言 packet 2 `ipv6.src=2001:db8::2`）。
- msgtype 序列 1→2→3→7；packet 2/4 含 `dhcpv6.iaaddr.ip=2001:db8::100`（option 5 由 `default_leased_addr` 生成）。
- XID 关联：packet 1 `dhcpv6.xid` 存在；packet 2/3/4 `same_as_packet:1`（SARR 同一交换共享 XID，RFC 8415 §15.1；`scenario.go:29-35,214-220`）。
- `ipv6.hlim=64`、`eth.src=aa:bb:cc:dd:ee:ff`（默认 TTL 与 DUID-LLT 的 MAC 来源）。

## 4. 负例契约与锚词（今日无 JSON 负例——A′ 立项）

负例执行期只有 `expect_error` + `error_contains`，锚词与 validator 字面值一一对应（`planner.go:141-267`）。**今日 0 条负例，属于 G-DHCPV6-3，不得冒充已覆盖**。A′ 候选锚词：

| 候选 ID | 故障输入 | 锚词（代码逐字） | 代码行 |
|---|---|---|---|
| `dhcpv6_neg_ipv4_src` | `src_ip=10.0.0.1` | `source IP must be IPv6` | planner.go:149 |
| `dhcpv6_neg_ipv4_dst` | `dst_ip=10.0.0.2` | `destination IP must be IPv6` | planner.go:158 |
| `dhcpv6_neg_empty_messages` | manual 无 messages | `at least one message is required` | planner.go:183 |
| `dhcpv6_neg_msgtype_range` | `msg_type=0` | `invalid msg-type` | planner.go:190 |
| `dhcpv6_neg_relay_no_fields` | msg_type=12 无 relay_fields | `relay message requires relay_fields` | planner.go:197 |
| `dhcpv6_neg_hop_overflow` | hop_count=33 | `exceeds limit` | planner.go:200 |
| `dhcpv6_neg_relay_addr` | link-address IPv4/空 | `relay link-address is required` / `must be IPv6` | planner.go:203/206 |
| `dhcpv6_neg_direction` | `direction=sideways` | `invalid direction` | planner.go:218 |
| `dhcpv6_neg_options_mtu` | options 总长>1452 | `exceeds MTU limit` | planner.go:230 |
| `dhcpv6_neg_duid_type` | DUID type=9 | `invalid DUID type` | planner.go:279 |
| `dhcpv6_neg_duid_long` | DUID 序列化>128B | `DUID too long` | planner.go:291 |
| `dhcpv6_neg_missing_mac` | 无 client_duid 无 src_mac | `src_mac is required` | planner.go:253 |
| `dhcpv6_neg_relay_config_ip` | relay_config 缺 relay_ip | `relay_ip is required` / `must be IPv6` | planner.go:259/262 |
| `dhcpv6_neg_unknown_scenario` | `scenario=foo` | `unknown scenario` | scenario.go:90 |
| `dhcpv6_neg_needs_leased` | `scenario=renew` 无 leased | `requires default_leased_addr` | scenario.go:57 |
| `dhcpv6_neg_scenario_with_messages` | scenario+messages 并存 | `cannot both be set` | scenario.go:82 |

## 5. 覆盖与对账

**门1 §12 动态字段回指**：四元组策略由 `ip`/`udp`/`eth` 层断言；dhcpv6 业务对象动态关闭，详见配套设计 §5。
- 三源回指：RFC 8415 §6.4/§7（消息）、§11（DUID）、§15.1（XID）、§21（options）、§19（relay）→ 实现 `planner.go`/`scenario.go`/`options.go` → 1 个 JSON ID（§2）。
- §3.15 三项：① 同流多轮操作 = SARR 四包共享 XID（已覆 #1）；② 非正常结束 = UDP 无 FIN/RST，以 Validate 拒绝为边界（负例 A′，不适用 FIN/RST）；③ 长保活 = 不适用（无保活机制）。
- A′ 分类：用例扩展（9 场景、relay 包装、option 边界、16 条负例）→ G-DHCPV6-3；顶层旧键迁移 → G-DHCPV6-1；业务动态 → G-DHCPV6-2。
- 门3 抽查建议：`dhcpv6_smoke_01`（SARR 交叉维度：方向 2 × msgtype 4 × XID 关联 × 租约地址）。

## 6. 存量审计

| 存量 ID | 去向 | 动作 |
|---|---|---|
| `dhcpv6_smoke_01` | **改写**（P4） | 迁移 `src_ip`/`dst_ip`/`src_mac`/`dhcpv6` 至层链后重钉；断言值与包数不变 |

0 作废；0 等价覆盖。过期产物：`trafficgen/docs/protocol-pcap-test/dhcpv6.md` 末次提交 2026-09-05 早于判死提交 `0417be5`，其 pass 数字不可作为今日复跑证据（G-DHCPV6-4，P5 重跑后重生成）。

## 7. 覆盖反查门建议断言行（供主线程登记，本车道不碰 coverage_gate.py）

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['dhcpv6']) == 1` 且 ID = `dhcpv6_smoke_01` | 本文 §2 |
| 2 | 该例 `packet_count == 4` | JSON expect |
| 3 | msgtype 断言含 1/2/3/7 四值 | 本文 §2/§3 |
| 4 | 4 包 XID 关联断言存在（存在 + 3 条 same_as_packet） | 本文 §3 |
| 5 | `spec_json` 顶层含 `layers` 且层链 == `[udp,dhcpv6]` | 本文 §1 |
| 6 | 非负例顶层旧键计数 == 4（G-DHCPV6-1 未收敛前如实标红） | 本文 §1/设计 §7 |

## 8. 修订记录

v1.0（2026-09-29）：按 cases JSON 机读与实现写 as-built；登记负例 A′ 与 G-DHCPV6-1…4。自审 1 轮，末轮干净；待独立审查。

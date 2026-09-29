# #140 mdns 测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨，as-built）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/140-mdns-design.md` v1.0.0（D-MDNS-1）
> 机器契约：`trafficgen/test/protocol_pcap/cases/mdns.json`（1 例，机读实测，顺序为权威）
> 白话一句：现在只有一条冒烟：问一次 `x.local` 的 A 记录，查一包，看地址端口 TTL 和 DNS 字节都对不对。

## 1. 测试原则与形状基线（机读实测 2026-09-29）

- cases 共 **1** 例：**1 正 + 0 负**。ID 顺序 = JSON 顺序 = §2 表序。
- `mdns_smoke_01` 顶层键 = `{id,proto,summary,spec_json,expect}`；`spec_json` 顶层键 = `{layers,src_ip,dst_ip,src_port,count,mdns}`（**六键，非纯层链**，G-MDNS-1）；层链 `[udp,mdns]`；`mdns` 子映射同时存在于顶层。
- `expect` 键集合 = `{packet_count,fields,frames,notes}`；`packet_count=1`；8 条 `fields` 断言 + 1 条 `frames` 断言（offset 42，25B payload）。
- 无 `expect_error` 用例；validator 拒绝分支未入 cases（设计 §6 G-MDNS-3）。
- 输出契约：pcap 与 NIC 双路径共用本契约断言（`udp.srcport/dstport`、`ip.dst/ip.ttl`、`dns.*`、offset 42 frames）；本车道未跑套件，所有"pass"均引用过期产物，不作为今日证据（G-MDNS-2）。

tshark 通道：`dns.flags.response`（0/1）、`dns.qry.name/type/class`、`udp.srcport/dstport`、`ip.dst`、`ip.ttl`，均可机读；进制按实测（ports/ttl 十进制串、`dns.qry.class` 形如 `0x0001`）。

## 2. 原子用例索引（1 ID，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count | 关键断言 |
|---:|---|---|---|---:|---|
| 1 | `mdns_smoke_01` | 正 | 设计 §1/§2/§3：query 单包 + 多播/端口/TTL 头约束 + DNS 线格式 | 1 | 见 §3 |

存量无其他 ID；T-编号对照不存在（本协议无旧编号体系）。

## 3. 正例断言契约

### 3.1 `mdns_smoke_01`（1 包）

配置事实（逐键对 JSON）：`layers=[{udp:{}},{mdns:{}}]`；顶层 `src_ip=10.0.0.1, dst_ip=20.0.0.1, src_port=5353, count=1`；顶层 `mdns.questions=[{name:"x.local",type:1}]`。

expect 逐条：

1. `packet_count=1`。
2. `udp.srcport=5353`（包 1）——RFC 6762 §5.4 源端口必须 5353；顶层显式给出，未设则 flow 默认 12345 会被 validate 拒绝（cases notes 记载）。
3. `udp.dstport=5353`（包 1）——RFC 6762 §5.4；strategy_convert 缺省收敛 dst 5353。
4. `ip.dst=224.0.0.251`（包 1）——RFC 6762 §11 多播组；planner/生成器按源 IP 族选 `224.0.0.251`（IPv4 默认）。
5. `ip.ttl=255`（包 1）——RFC 6762 §11 强制 TTL 255。
6. `dns.flags.response=0`（包 1）——query 模式 flags `0x0000`（QR=0，RFC 6762 §5.1）。
7. `dns.qry.name=x.local`（包 1）。
8. `dns.qry.type=1`（A）。
9. `dns.qry.class=0x0001`（IN；class 0 缺省 IN）。
10. frames：包 1 offset 42 `00 00 00 00 00 01 00 00 00 00 00 00 01 78 05 6c 6f 63 61 6c 00 00 01 00 01`——逐字节 = 12B 头（TXID 0000 + flags 0000 + QD=0001 + AN/NS/AR=0000）+ QNAME `01 'x' 05 'l o c a l' 00` + QTYPE 0001 + QCLASS 0001；payload 25B = 12 + (8+4+1)。

依据链：RFC 6762 §5.1（TXID=0）、§5.4（端口）、§11（TTL/组播）、RFC 1035 §4.1（头/问题区布局）；`dns.qry.class` 期望值 `0x0001` 以 tshark 实测口径为准（cases notes 记载探针已对齐）。

## 4. 负例契约（现存 0 条）

无 `expect_error` 用例。validator 拒绝分支（设计 §3 锚词表）尚未任何一条进入 JSON，不得声称已覆盖：未知 mode、端口非 0/5353（src 与 dst 各一）、query/probe 空 questions、response/announce/goodbye 空 answers、QName 首点/超长标签/超 255B、QTYPE 0/保留段 65281–65534、QCLASS 非 IN/QU/CacheFlush 形、地址族不一致、非 mDNS 多播组、TC 用于 query、ProbingJitterMax>250/负值、A/AAAA 地址族错配、SRV 缺 target、TXT>255B、NSEC 缺 next/types。以上每条 = 一个待补负例（P4 扩充，G-MDNS-3）。

## 5. 覆盖与对账

- **三源回指**：RFC 6762/1035（设计 §2/§3）+ D-MDNS-1 + `cases/mdns.json` → 1 ID（§2）。#1←设计 §1/§2/§3。
- **要求逻辑点 vs 覆盖**：设计 §4 五层展开的测试点中，今日已覆盖 = query 单包冒烟 1 点（含 9 项断言）；response/probe/announce/goodbye、RR 类型面、动态面、IPv6 面、负例面均为**待实现/待扩充**，从已覆盖统计排除，不计冒充。
- **门3 抽查候选**：唯一用例 `mdns_smoke_01`（单包：地址族 × 端口 × TTL × DNS 头 × QName 五维交织）。
- **反查门建议断言行**（供主线程登记 `coverage_gate.py`；本车道不碰该文件；每条可从 cases JSON + 设计静态机读）：
  1. `mdns.json` ID 集合 = `["mdns_smoke_01"]`（今日实测；扩充后须同步改）。
  2. `mdns_smoke_01.spec_json.layers` = `[udp,mdns]` 顺序链。
  3. `mdns_smoke_01.expect.packet_count` = 1。
  4. `mdns_smoke_01` 含 `frames` 断言 offset 42、hex 前缀 `00 00 00 00 00 01`。
  5. `mdns_smoke_01` 含 `dns.flags.response=0` 与 `ip.ttl=255` fields 断言。
  6. **红项如实标红**：`spec_json` 存在 `src_ip/dst_ip/src_port/count/mdns` 五个顶层游离键（G-MDNS-1），反查"纯层链零游离"今日不过；负例计数 = 0，反查"每错误分支至少一负例"今日不过。

## 6. 存量用例审计（逐 ID 去向）

| 存量 ID | 去向 | 动作（P4） |
|---|---|---|
| `mdns_smoke_01` | **改写** | 顶层 `src_ip/dst_ip/src_port/count/mdns` 迁入 `[ip,udp,mdns]` 层链（G-MDNS-1）；断言随迁（fields/frames 不变，ip.dst 由层内 dst 承载） |

无作废、无等价覆盖；扩充项（负例、其他模式、RR、IPv6、动态）均为新增而非改写。

**结果产物过期登记（G-MDNS-2）**：`trafficgen/docs/protocol-pcap-test/mdns.md`（tracked）写 `mdns_smoke_01 pass 1`，末次提交 `e7e7d1c`（**2026-08-27**）早于判死提交 `0417be5`（2026-09-13）；该 "pass" 是**过期产物**，未经今日复跑证实，读者不得据此判断套件今日通过。归属 P5（重跑后重生成产物）。

## 7. P3 固定动作

| §3.15 三项 | 对照 | 结论 |
|---|---|---|
| ① 同连接多轮操作 | mDNS 无连接，datagram 独立 | 不适用（连接概念不存在，非豁免空缺） |
| ② 非正常结束 | UDP 无 FIN/RST；异常 = validator 拒绝或损坏 datagram | 待补：负例面（G-MDNS-3） |
| ③ 长保活 | probe 3×250ms、announce 2×1000ms 是重复发包非保活 | 待补：probe/announce 用例（新增） |

A′（P4 接线）：负例全集、probe/announce/goodbye/response 正例、RR 类型逐型、IPv6 多播 + 混写拒绝、顶层游离键迁移、动态字段五策略。B′（框架面）：mDNS 业务字段的统一策略求值接入。以上均登记于设计 §6 与本文件 §5，未实现前不冒充覆盖。

## 8. 实现后执行建议

1. P4 先做 G-MDNS-1 迁移（唯一存量例），跑通后按 §5 反查门更新 ID 集合断言。
2. 负例按设计 §3 锚词逐条补，每条单一故障注入，`expect` 仅 `{expect_error,error_contains}`。
3. P5 重跑 pcap+NIC 双路径后重生成 `protocol-pcap-test/mdns.md`，消除 G-MDNS-2。

修订：v1.0.0（2026-09-29）初稿；待独立用例覆盖对抗审查。

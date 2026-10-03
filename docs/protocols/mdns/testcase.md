# #140 mDNS 测试用例契约

> 版本：v1.1.1（P-PIPE 文档轨，as-built）
> 日期：2026-10-01
> 配套设计：`docs/protocols/mdns/design.md` §1–§10
> 机器契约：`trafficgen/test/protocol_pcap/cases/mdns.json`（1 例，顺序为权威）

## 1. 原则与形状基线

当前共 **1 例：1 正、0 负**。唯一 ID 为 `mdns_smoke_01`；其 `spec_json` 顶层键实际为 `{layers,mdns}`，层链为 `[ip,udp,mdns]`。地址位于 ip，源端口位于 udp，但业务 questions 仍在顶层 `spec_json.mdns`；`layers[].mdns` 为空。该过渡形状是因为 `chain_planner_translate.go` 缺少 `case "mdns"`，registry 也无 Fields，不能宣称业务层链已可执行；缺口编号 G-MDNS-1。`count=1` 不写。无 `flow_control`，因此不宣称多流覆盖。expect 为 `packet_count`、8 条字段断言和 1 条 raw frame 断言。pcap 与 NIC 路径共用本文件断言；本车道未运行 suite，历史 pass 产物不作为当前证据。

## 2. 测试点清单先行（T2）

|规范条文|业务场景|代码分支|当前用例/缺口|
|---|---|---|---|
|RFC 6762 §5.1 / RFC 1035 §4.1|query header、QName、A question|`planner.go` query + DNS encoder；严格层业务 translate 缺 `case "mdns"`|T-MDNS-01 当前过渡形状；G-MDNS-1|
|RFC 6762 §5.4|UDP 源/目的 5353|UDP translate/planner|T-MDNS-01|
|RFC 6762 §11|IPv4 多播与 TTL 255|地址族默认组/TTL|T-MDNS-01；G-MDNS-4|
|RFC 6762 §§6,8,10|response/probe/announce/goodbye|mode 分支|G-MDNS-5|
|RFC 1035/RFC 4034|RR、QTYPE/QCLASS、RDATA|RR encoder/validator|G-MDNS-3/G-MDNS-5|
|RFC 6762 §8.1|重复、interval、jitter|重复调度|G-MDNS-5|
|RFC 6762 §11|IPv6 对称与混族拒绝|IPv6 组选择/validator|G-MDNS-4|
|统一动态契约|五策略、flows|公共策略求值/业务字段解析|G-MDNS-6|

## 3. 原子用例索引（T3/T4）

|#|ID|类型|场景类别|强度|覆盖|包数|
|---:|---|---|---|---|---|---:|
|1|`mdns_smoke_01`|正|数据 + 现网 query|字段/边界 frame pin|RFC 6762 §5.1/§5.4/§11；设计 §2/§4|1|

三类场景说明：当前例同时覆盖规范数据字段和常见 `.local` 单查询现网形状；业务复杂场景（DNS-SD 多 RR、probe、announce、goodbye）列为 G-MDNS-5，不冒充已覆盖。mDNS 无连接，故同连接多轮操作不适用；非正常结束以 validator 拒绝/损坏 datagram 立项；长保活不适用，probe/announce 的重复发送另立项。业务组合最低要求（多动作三动作）对无连接单 datagram 不适用，须以多 question/RR 复合例补齐而非把本例冒充。

## 4. `mdns_smoke_01` 断言契约

配置逐键对账：`layers[0].ip={src:10.0.0.1,dst:20.0.0.1}`；`layers[1].udp={src_port:5353}`；`layers[2].mdns={}`；当前业务配置仍由顶层 `spec_json.mdns.questions=[{name:x.local,type:1}]` 进入 `mapToFlowSpec`，这是 G-MDNS-1 过渡形状，不是可执行的严格终结层配置。

1. `packet_count=1`。
2. `udp.srcport=5353`。
3. `udp.dstport=5353`。
4. `ip.dst=224.0.0.251`。
5. `ip.ttl=255`。
6. `dns.flags.response=0`。
7. `dns.qry.name=x.local`。
8. `dns.qry.type=1`。
9. `dns.qry.class=0x0001`。
10. frame offset 42 的 25B DNS payload 为 `00 00 00 00 00 01 00 00 00 00 00 00 01 78 05 6c 6f 63 61 6c 00 00 01 00 01`。

断言分别钉到 RFC 6762 §§5.1/5.4/11、RFC 1035 §4.1 和设计 §4；端口、TTL、class 的值来自现有 case 实测口径。动态生成的值不硬编码。

## 5. 负例与失败路径（T6）

当前 0 条负例，故不能声称 validator 错误面已覆盖。G-MDNS-3 逐项新增：未知 mode、src/dst 非 0/5353、query/probe 空 questions、response/announce/goodbye 空 answers、QName 首点/超长标签/超 255B、QTYPE 0/保留段、QCLASS 非 IN/QU/cache-flush、混族地址、非 mDNS 组播、query 的 TC、jitter>250/负值、A/AAAA 地址族错配、SRV 缺 target、TXT>255B、NSEC 缺 next/types。每例只注入一个错误，expect 严格为 `{expect_error:true,error_contains:"mdns: ..."}`，断言 task 被拒且无成功帧；锚词须以实际 validator 文案校准。

## 6. 三源回指、存量审计与对账

规范源为 RFC 6762/1035/4034；设计源为 `design.md` §2–§10；现网源为授权 Bonjour/Avahi pcap（当前未取得，待确认方式为抓取并以 tshark 对照）。`mdns_smoke_01` 回指三源中的 query、端口、组播、TTL、DNS header/question 条目。存量唯一 ID 的去向为：**保留过渡形状并登记 G-MDNS-1**——地址/端口已迁入 `[ip,udp,mdns]`，但业务 `questions` 暂留顶层 `mdns`，不能在 translate 缺 case 时机械迁入空层；`count=1` 删除。无作废、无等价覆盖。

对账：JSON 1 ID = 本文 1 ID；正/负 = 1/0；层链键形为 `[ip,udp,mdns]`，但业务键形为顶层 `mdns` + 空 `layers[].mdns`（G-MDNS-1）；负例 expect 约束尚未实例化。spec-mapping 文件未发现，非缺口；历史 `protocol-pcap-test/mdns.md` 的 pass 数字早于当前改造且未复跑，不作为本轮证据。

## 7. 扩充计划与执行边界

G-MDNS-1 必须先补 `chain_planner_translate.go` 的 `case "mdns"`（严格层配置解码/映射）及 registry Fields，再把 `mdns.questions` 从顶层迁入 `layers[].mdns`；当前不能机械迁移，否则业务配置会被空层吞掉。迁移后补 G-MDNS-3/4/5 的原子正负例，再补 G-MDNS-6 动态整格；P5 用真实 MCP→引擎→pcap/NIC→tshark 流程校准包数和字段。执行时需覆盖基线、目标规模、压力、长跑、并发交错、背压，并断言吞吐、延迟、资源和失败/丢包；本车道按任务要求不运行 suite、服务或 MCP。

修订：v1.1.1（2026-10-01）按 T1–T6 重写，完成唯一存量 case 层链迁移与 JSON 对账；负例、IPv6、mode/RR、动态整格仍按设计缺口登记。

本版自审：两轮；第一轮逐条核对 CORE §3.14–§3.15、§9、§14 与 T1–T6，第二轮复核 ID/正负数/层链/断言和缺口互相一致，末轮干净。

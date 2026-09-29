# #140 mdns（Multicast DNS）设计契约

> 版本：v1.0.0（P-PIPE 文档轨，as-built）
> 日期：2026-09-29
> 范围：UDP 上的 mDNS 查询；现存 machine case 仅覆盖 query。
> 依据优先级：RFC 6762 §§5.1, 5.4, 6, 8.1, 8.3, 10.2, 11；RFC 1035 §§3.1, 4.1.1–4.1.2；代码与 cases JSON 实测。

## 0. 现状结论与边界

mDNS 是 UDP 终结层，registry `registry.go:172-174` 声明 `DependsOn:["udp"]`；生成器在 `internal/protocol/mdns/layer_gen.go:14-176`，legacy planner 在 `planner.go:186-699`。配置由 `strategy_convert.go:1217-1221,4464-4625` 解析，当前 machine case 只有 `mdns_smoke_01`（1 包）。mDNS 是多播、单向发送，不自动配对响应；本实现的事件方向恒 `up`。

当前 case 的 `spec_json` 仍保留顶层 `src_ip,dst_ip,src_port,count,mdns` 等旧平面字段，且 `layers` 已存在；目标迁移形状如下（当前 case 尚未达到该形状，见 G-MDNS-1）：

```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"224.0.0.251"}},{"udp":{"src_port":5353,"dst_port":5353}},{"mdns":{"questions":[{"name":"x.local","type":1}]}}]}
```

实现能力边界：支持 query/response/probe/announce/goodbye、A/AAAA/PTR/CNAME/SRV/TXT/NSEC RDATA、IPv4/IPv6 多播、重复与间隔；不实现 DNS name compression，消息按独立 QName 编码；不实现请求触发的自动响应、真实网络发现或多播监听。

## 1. 层链、端口、地址与输出

推荐链为 `[ip,udp,mdns]`；最小已存链 `[udp,mdns]`，IP 由框架/顶层地址补齐。mDNS 端口固定 UDP 5353（RFC 6762 §5.4）；planner 对零端口默认 5353，非零非 5353 拒绝。IPv4 默认组 `224.0.0.251`、IPv6 默认组 `ff02::fb`，按源地址族选择；组播 MAC 由 `multicastDstMAC` 推导 `01:00:5e:00:00:fb` 或 `33:33:00:00:00:fb`。IP TTL 强制为 255（RFC 6762 §11），与配置 TTL 无关。

pcap 与 NIC 使用同一 cases JSON 与 expect。pcap 产物是 UDP/IP/DNS 字段及原始 frame；NIC 路径应由同一字段/帧断言复用。现有结果文件 `trafficgen/docs/protocol-pcap-test/mdns.md` 最后提交为 `e7e7d1c`（2026-08-27），早于判死提交 `0417be5`（2026-09-13），且未核验当前 HEAD，登记 G-MDNS-2。

## 2. 线格式（代码可生成级）

DNS header 固定 12B，所有多字节字段网络字节序（big-endian）：

|偏移|字段|尺寸/编码|实现值|
|---:|---|---|---|
|0|Transaction ID|UInt16 BE|恒 0|
|2|Flags|UInt16 BE|query `0x0000`；response/announce/goodbye `0x8400`；response 且 `tc=true` 再置 `0x0200`|
|4|QDCOUNT|UInt16 BE|`len(Questions)`|
|6|ANCOUNT|UInt16 BE|`len(Answers)`|
|8|NSCOUNT|UInt16 BE|`len(Authorities)`|
|10|ARCOUNT|UInt16 BE|`len(Additionals)`|

QName 是每标签 `1B length + label bytes`，末尾 `0B`；根名 `.` 仅 `00`。标签 ≤63B、编码 QName ≤255B。Question 为 QName + QTYPE UInt16 + QCLASS UInt16；class 0 缺省 IN=1，QU/cache-flush 位为 `0x8000`。Resource Record 为 NAME + TYPE + CLASS + TTL UInt32 + RDLENGTH UInt16 + RDATA。class 0 缺省 IN；announce/goodbye 默认 cache-flush，goodbye 强制 TTL=0；TTL 0 在普通模式使用 DefaultTTL=4500，最大 2147483647。

RDATA：A=4B IPv4；AAAA=16B IPv6；PTR/CNAME=QName；SRV=`priority u16 + weight u16 + port u16 + target QName`；TXT=重复 `length u8 + bytes`；NSEC=`next QName + window blocks`，每块 `window u8 + bitmap length u8 + bitmap(1..32B)`，类型位按 RFC 4034 §4。`RawRDATA` 可原样覆盖 typed RDATA，仅供 malformed 测试。

总长度公式：`12 + Σ(question: qname_len+4) + Σ(rr: owner_qname_len+10+rdlength)`；无压缩、无 padding。当前 smoke payload 为 25B，UDP payload 起点 frame offset 42（14 Ethernet + 20 IPv4 + 8 UDP），原始 hex 与 cases 一致。

## 3. 配置、默认值与状态/驱动

`MDNSConfig` 字段完整清单：`mode, questions, answers, authorities, additionals, probing_repeat, probing_interval, probing_jitter_max, probing_jitter_seed, announcing_repeat, announcing_interval, response_delay, multicast_group, force_unicast_response, cache_flush, default_ttl, tc`。RR 字段：`name,type,class,ttl,ip_address,domain_name,priority,weight,port,target,txt_entries,nsec_next_name,nsec_types,raw_rdata`。

模式确定性：空 mode=query；query 1 包；response 1 包且首包前 sleep `response_delay`; probe 默认 3 包、250ms、jitter 上限 250ms；announce 默认 2 包、1000ms；goodbye 1 包、response flags、所有 answers TTL=0。每包均检查 context；probe jitter seed 非零使用 `math/rand.NewSource(seed)`，零 seed 使用非确定性随机源。query/probe 至少一个 question；response/announce/goodbye 至少一个 answer。未知 mode、非法端口、地址族不一致、非法 QName/QTYPE/QCLASS/RR 字段由 validator 返回带 `mdns:` 锚词错误。

### 五件套（§3 强制展开）

|项目|本协议实现|
|---|---|
|会话表|不适用：mDNS 无连接会话；每次 flow 是独立单向 datagram 序列。|
|事务序列|query/probe：DNS query；response：query-shaped response；announce/goodbye：unsolicited response。|
|关联关系|不适用：无请求-响应配对、Transaction ID 恒 0；单播响应请求仅由 QU bit 表达。|
|插入位置|生成器向 UDP `EmitMsg` 发送一个 `MessageEvent`；UDP 为每 event 发一个 datagram。|
|时间线|query/goodbye 即时；response 首包 delay；probe/announce 在包间按 interval+jitter 延迟。|

业务场景：服务发现使用 PTR query；设备探测使用 probe；服务上线 announce（PTR/SRV/TXT/A）；响应可含 answer/additional；下线 goodbye。现有 case 仅 query，其他行为是代码已实现但未进入 cases 的待实现边界，不计已覆盖。

## 4. 五层覆盖与性能

- **功能层**：现有 `mdns_smoke_01` 覆盖 query、Transaction ID=0、QR=0、单 question；response/probe/announce/goodbye、RR、validator 错误分支均未进入 cases。
- **性能层**：无压缩、单 datagram；QName≤255B、label≤63B、TXT entry≤255B、TTL≤2^31−1、jitter≤250ms；跨 UDP/IP 分片不由 mDNS planner 生成，需以大 payload/边界用例补证。
- **数据层**：现有仅 A query/type=1/class IN；A/AAAA/PTR/CNAME/SRV/TXT/NSEC、QU、cache-flush、TC、空/最大/非法值待覆盖。
- **地址与流层**：现有 IPv4 单流、多播目标、端口 5353、TTL 255；IPv6、IPv4/IPv6 混写拒绝、多流重复策略待覆盖。流关联不适用，理由是 mDNS 不建立父子连接。
- **业务层**：现有服务发现最小 query；多问句、probe、announce、response、goodbye、DNS-SD PTR/SRV/TXT/A 组合待覆盖；多会话/多事务不适用，mDNS datagram 没有连接内事务状态。

## 5. 门1 §1–§14 对照表

|门|as-built 满足方式与证据|
|---|---|
|§1 顶层旧键|当前 case 顶层 `src_ip,dst_ip,src_port,count,mdns` 未迁入层内；目标 `ip/udp/mdns` 形见 §0；G-MDNS-1。|
|§2 五层|§4 逐层列功能、性能、数据、地址与流、业务及不适用理由；现有 ID 为 `mdns_smoke_01`。|
|§3 五件套|§3 表格说明 mDNS 无会话/流关联，事件插入 UDP，时间线由 mode 驱动。|
|§4 代码生成|`planner.go:186-320,465-699` validator/planner；`layer_gen.go:38-176` MessageEvent；`strategy_convert.go:4464-4625` 解析。|
|§5 规范依据|RFC 6762 §§5.1/5.4/6/8/10/11、RFC 1035 §§3.1/4.1；线格式见 §2。|
|§6 字段/偏移|DNS 12B header、QName、Question、RR、RDATA 字段与长度公式见 §2。|
|§7 状态机|无连接状态机；mode→重复/延迟/flags/TTL 的确定性规则见 §3。|
|§8 错误处理|validator 锚词见 §3；负例未进入 JSON，G-MDNS-3 登记。|
|§9 性能容量|边界上限、单 datagram、无压缩和分片边界见 §4；大报文缺用例。|
|§10 地址/流|5353、224.0.0.251/ff02::fb、TTL 255、multicast MAC 见 §1；仅 IPv4 smoke。|
|§11 业务|服务发现/探测/上线/响应/下线定义见 §3、§4；仅服务发现落用例。|
|§12 动态字段|动态清单见下表；strategy parser 对 mDNS 业务字段为普通值解析，未发现 fixed/inc/rand/list/pattern 完整支持。|
|§13 输出|pcap/NIC 共用 cases 断言，§1；旧结果产物过期 G-MDNS-2。|
|§14 审计/修订|存量审计见 testcase §6；缺口 G-MDNS-1..3；待独立代码设计与用例覆盖审查。|

### §12 动态字段四元组

|字段|动态形态|序号算法/代码位置|当前状态|
|---|---|---|---|
|src_ip,dst_ip,src_port,dst_port|策略/流基础字段|框架 flow 序号与端口分配；mDNS validator `planner.go:186-210`|固定 smoke，需动态负例/回绕验收|
|questions[].name/type/class|策略业务字段|`parseMDNSQuestions:4570-4590` 逐数组复制；无字段级策略求值|未落动态五策略|
|answers/authorities/additionals RR 字段|策略业务字段|`parseMDNSResourceRecords:4593-4625`；数组顺序保留|未落动态五策略|
|mode/repeat/interval/jitter/default_ttl|配置控制字段|`MDNSGenerator.Generate:47-145` / planner `543-660`|固定配置，jitter seed 可复现但非策略动态|

## 6. 缺口登记

|ID|现象|证据|归属阶段|
|---|---|---|---|
|G-MDNS-1|现有 case 仍把地址、端口、count、mdns 放在顶层，未实现纯层链唯一真相|`cases/mdns.json:8-26`；`strategy_convert.go:1217-1221`|P4 层形收敛|
|G-MDNS-2|tracked mdns 结果文档早于 0417be5，当前数字未经 HEAD 复跑且无今日 pcap 证据|`git log`：e7e7d1c 2026-08-27；`trafficgen/docs/protocol-pcap-test/mdns/` 无核验|P5 复跑产物|
|G-MDNS-3|machine case 无负例，validator 各错误分支未证明任务失败/零包|`cases/mdns.json` 仅 1 正例；`planner.go:204-320`|P4 用例扩充|

## 7. §9 建议与修订记录

建议先迁移唯一 case 为 `[ip,udp,mdns]`，再补 IPv6、probe/announce/goodbye、RR 类型、边界与 validator 负例，最后从 pcap 与 NIC 双路径重生成结果产物。动态业务字段应接入统一策略求值后再声明已覆盖。

修订：v1.0.0（2026-09-29）初稿；待独立代码设计逻辑对抗审查与用例覆盖对抗审查。

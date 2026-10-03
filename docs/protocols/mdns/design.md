# mDNS（Multicast DNS）设计契约

> 版本：v1.2.1（P-PIPE 文档轨，as-built）
> 日期：2026-10-01
> 机器契约：`trafficgen/test/protocol_pcap/cases/mdns.json`
> 规范：RFC 6762 §§5.1、5.4、6、8.1、8.3、10.2、11；RFC 1035 §§3.1、4.1；RFC 4034 §4。

## 1. 范围、层链与现状

mDNS 是 UDP 终结层，registry `registry.go:172-174` 声明依赖 UDP；生成器为 `internal/protocol/mdns/layer_gen.go:14-176`，planner 为 `planner.go:186-699`，配置解析为 `strategy_convert.go:4464-4625`。本仓库当前只有一个可执行 query case，方向恒为 `up`，每个事件生成一个 UDP datagram。

目标配置真相是 `[ip,udp,mdns]`：地址在 `ip.src/dst`，端口在 `udp.src_port/dst_port`，业务字段应在 `mdns` 终结层，数量在 `flow_control`。但当前 translate 缺少 `case "mdns"`，业务配置尚无层内生效路径；唯一可执行 case 仍保留顶层 `mdns` 与空 `layers[].mdns` 的过渡形状，不能宣称严格层链业务支持。`count=1` 不写；多流使用 `strategy_fc:{"type":"flows","value":N}`。当前过渡形状：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"udp": {"src_port": 5353}},
    {"mdns": {}}
  ],
  "mdns": {"questions": [{"name": "x.local", "type": 1}]}
}
```

planner/layer generator 已实现 query/response/probe/announce/goodbye、A/AAAA/PTR/CNAME/SRV/TXT/NSEC、IPv4/IPv6 多播、重复与间隔；不生成 DNS name compression、自动响应、真实网络发现或多播监听。当前 cases 只证明 query/A/IPv4；其余已实现分支须由后续 cases 取证，未取证不计覆盖。

## 2. 规范要求→场景→代码→缺口矩阵（D1）

|规范要求|业务场景|代码现状|用例/缺口|
|---|---|---|---|
|UDP 5353、组播、TTL 255（6762 §5.4/§11）|IPv4 query|planner 固定端口/组/TTL|`mdns_smoke_01`；IPv6 G-MDNS-4|
|DNS query 头与 question（1035 §4.1）|`x.local` A query|header/QName/question 编码|`mdns_smoke_01`；边界 G-MDNS-3|
|response/announce/goodbye flags/TTL（6762 §§6,8,10）|服务发布/撤销|mode 分支已生成|G-MDNS-5：无 machine case|
|probe 重复与 jitter（6762 §8.1）|地址冲突探测|repeat/interval/jitter 已生成|G-MDNS-5|
|RR 类型与 RDATA|DNS-SD 服务发现|typed RDATA 已生成|G-MDNS-5|
|非法输入拒绝|错误配置|validator 返回 `mdns:` 锚词|G-MDNS-3：无负例|
|IPv4/IPv6 对称|两族多播|地址族选择已生成|G-MDNS-4：无 IPv6 case|
|版本/方言|QU/cache-flush、TC|字段已解析|G-MDNS-6：逐值取证不足|

### 命令/响应码矩阵

|模式/消息|正常输出|错误输入|覆盖|
|---|---|---|---|
|query/question|QR=0，至少一 question|空 questions、非法 QName/QTYPE/QCLASS|T-MDNS-01；G-MDNS-3|
|response/answers|QR=1，answers 非空|空 answers、RR 字段非法|G-MDNS-5；G-MDNS-3|
|probe|query flags，重复发送|空 questions、jitter>250ms|G-MDNS-5；G-MDNS-3|
|announce|unsolicited response，重复发送|空 answers、间隔非法|G-MDNS-5；G-MDNS-3|
|goodbye|response，answers TTL=0|空 answers、RR 非法|G-MDNS-5；G-MDNS-3|

### 数据形态变体表

|维度|当前证据|缺口|
|---|---|---|
|IPv4/IPv6|IPv4 query|IPv6 query、混族拒绝（G-MDNS-4）|
|RR|A query|AAAA/PTR/CNAME/SRV/TXT/NSEC（G-MDNS-5）|
|消息模式|query|response/probe/announce/goodbye（G-MDNS-5）|
|边界|单 QName、IN、type A|空/最大/非法标签、保留 type/class、TXT/NSEC 边界（G-MDNS-3）|
|动态|固定字段、固定 seed 代码路径|五策略动态整格（G-MDNS-6）|

### 现网行为→用例映射

|行为|用例|证据/状态|
|---|---|---|
|主流客户端对 `.local` A 查询|`mdns_smoke_01`|RFC 6762 §5.1/§5.4 + frame pin|
|服务发现 PTR→SRV/TXT/A|—|待确认：授权抓取 Bonjour/Avahi pcap 后立项|
|冲突探测 probe|—|待确认：授权抓取 Avahi pcap 后立项|
|服务发布与撤销 announce/goodbye|—|待确认：授权抓取 Bonjour pcap 后立项|

## 3. 三路对照与方案取舍（D2）

RFC 6762/1035 决定头、QName、RR、5353、多播和 TTL；商业行为的 Bonjour/Avahi 抓包尚未纳入本车道，只能将上述现网映射标为待确认；开源实现 Avahi 的行为思路是独立 datagram、按 mode 重复发送、无请求触发自动响应。本实现按规范固定 TTL 255，并按 mode 生成事件，不模拟监听状态机。

|方案|真实走法|优点|代价|结论|
|---|---|---|---|---|
|`[ip,udp,mdns]`，每事件一 datagram|本仓库 layer generator/planner|层链单源、能复用 UDP/pcap/NIC|业务配置尚因 translate 缺 case 无法从 mdns 层进入生成器|目标形状，待 G-MDNS-1|
|把 DNS 字段放 UDP 或顶层|历史扁平配置|迁移短|违反终结层归属、无法统一校验|不采用|
|为请求建立响应会话|真实 daemon 状态机|更接近 daemon|超出生成器单向事件边界、需共享状态|不采用|

## 4. 事务、状态与数据格式

DNS header 固定 12B，网络字节序；query flags `0x0000`，response/announce/goodbye `0x8400`，TC 仅 response 可置。QName 每标签 `length+bytes`，标签≤63B、编码≤255B；question 为 QName+QTYPE+QCLASS；RR 为 NAME+TYPE+CLASS+TTL+RDLENGTH+RDATA。A=4B、AAAA=16B、PTR/CNAME=QName、SRV 为五个字段、TXT 为 length-prefixed entries、NSEC 为 next QName 与 window bitmap。无压缩。

五件套：无连接会话；每个 flow 是独立 datagram 序列；事务是 mode 驱动的 query/response/探测/发布/撤销事件；无父子数据流关联；事件插入 UDP 层，一个事件一个 datagram；query/goodbye 即时，response 首包受 delay，probe/announce 按 interval+jitter 顺序发送。无长连接的三项固定处理：同连接多轮不适用（datagram 独立），非正常结束由 validator 拒绝或单个损坏 datagram 表达，长保活不适用；probe/announce 重复用例属于重复发送，不宣称连接保活。

## 5. 依赖与错误处理（D3）

依赖 `ip` 地址族、`udp` 端口和 mdns 配置；translator 组装层链后由 validator/planner 校验。非法 mode、端口、地址族、QName、RR、空必需集合等返回包含 `mdns:` 的 task error，中断当前任务且不产生成功帧；不重试。probe jitter 受≤250ms限制；上下文取消中断生成。自动响应、监听和压缩不在本接口内。

## 6. 性能设计与验收（D4）

生成按事件流式产出，不聚合全量；单帧内存为当前 Ethernet/IP/UDP/DNS buffer，队列和 ring buffer 上限由公共 pipeline 配置。可承诺边界仅为 QName≤255B、label≤63B、TXT entry≤255B、TTL≤2147483647、jitter≤250ms；包/秒、并发流、CPU、内存数字待基准后确认，不写成承诺。pcap 路径逐包用 tshark 加 raw frame 校验；NIC 路径用 tcpdump 后同一断言集校验。验收需覆盖基线、目标规模、压力上限、长时间、并发交错、背压，并断言吞吐、延迟、内存、CPU、队列和丢包/失败。

## 7. 八要素（D5）

- 文件：`internal/protocol/mdns/{planner.go,layer_gen.go}`、共享 UDP/IP builder/registry/translate、`cases/mdns.json`。
- 接口：validator/planner 的 `FlowSpec` 输入与 `MessageEvent` 输出；UDP 层按 event 生成 datagram。
- 结构：`MDNSConfig` 含 mode、questions、answers、authorities、additionals、重复/间隔/jitter、组播、TTL、TC；RR 含 type/class/TTL 与 typed/raw RDATA。
- 流程：层链校验→translate→planner→event→UDP/IP builder→pcap/NIC。
- 错误：返回 `mdns:` task error，中断且无成功帧。
- 性能边界：见 §6；无压缩、单 datagram、公共有界队列。
- 冲突点：顶层旧键、UDP默认端口覆盖、IPv4/IPv6组播选择与终结层业务归属；统一由层链和 validator 处理。
- 回滚：仅回滚本协议层/translate/cases 改动，不恢复顶层扁平正例；未改代码时 cases 可恢复上一版本层链。

## 8. 动态字段（D6）

|字段|fixed|inc|rand|list|pattern|序号/现状|
|---|---|---|---|---|---|---|
|`ip.src`,`ip.dst`|支持|待确认|待确认|待确认|待确认|公共层策略求值；mdns 不改地址|
|`udp.src_port`,`udp.dst_port`|支持|待确认|待确认|待确认|待确认|公共 UDP 层求值；5353 语义校验|
|`questions[].name/type/class`|支持|待确认|待确认|待确认|待确认|`strategy_convert.go:4570-4590` 数组解析，未接业务策略|
|RR name/type/class/TTL/RDATA|支持|待确认|待确认|待确认|待确认|`strategy_convert.go:4593-4625`，数组顺序保留|
|mode/repeat/interval/jitter/default_ttl|支持|不适用|seed 随机|不适用|不适用|`MDNSGenerator.Generate:47-145`|

未支持的动态格登记为 G-MDNS-6，不以静态复制冒充 flows 动态；流数量只通过 `flow_control`。

## 9. 门1 §1–§14 对照（D7）

|条款|满足方式与证据|
|---|---|
|§1|旧 `src_ip/dst_ip/src_port/dst_port/count/mdns` 的目标去向分别为 `ip`、`udp`、`flow_control`、`layers[].mdns`；但当前唯一 case 的顶层 `mdns` 是 G-MDNS-1 登记的过渡残留，完整现状 spec 见 §1。|
|§2|模式、头、RR、地址族、错误和性能分别见 §2、§4–§6。|
|§3|无连接会话；事件事务、关联、插入和时间线见 §4。|
|§4|RFC 6762/1035/4034 三路对照、P1矩阵和候选方案见 §2–§3。|
|§5|依赖、错误、重试和超时见 §5。|
|§6|性能边界及 pcap/NIC 验收见 §6。|
|§7|mode 驱动状态与 flags/TTL 规则见 §4。|
|§8|八要素见 §7。|
|§9|测试点、三类场景和存量去向见 testcase §2–§6。|
|§10|IPv4/IPv6、多播、端口和 TTL 见 §1/§4。|
|§11|query、DNS-SD、probe、announce、goodbye 场景见 §2/§4。|
|§12|四元组与业务字段动态矩阵见 §8。|
|§13|cases 是可直接消费的层链配置；pcap/NIC 共用断言。|
|§14|负例、真实流程和 frame/tshark 校准要求见 testcase §5–§7。|

## 10. 缺口与状态（D8）

|编号|缺口|证据|迁入/验收计划|
|---|---|---|---|
|G-MDNS-3|validator 错误分支无 machine 负例|cases 仅 1 正例|P4 按每个错误锚词新增单故障负例|
|G-MDNS-4|IPv6 与混族拒绝无 machine 证据|当前仅 IPv4|P4 新增 IPv6 正例与混族负例|
|G-MDNS-5|response/probe/announce/goodbye、RR 类型无 cases|planner 分支已有|P4 按 mode/RR 原子拆例|
|G-MDNS-6|业务字段五种动态策略无完整接入/取证|解析位置见 §8|代码开放统一策略后补动态整格|
|G-MDNS-2|tracked 结果文档未以当前 HEAD 复跑|历史产物早于现状|P5 真实 pcap/NIC 重跑并重生成产物|
|G-MDNS-1|`chain_planner_translate.go` 无 `case "mdns"`，层内业务字段无法进入 `spec.MDNS`；registry 也无 Fields|`registry.go:172-174` 注册无 Fields；translate 仅在 `drive` Meta 传递既有 `spec.MDNS`|先补 translate 的严格层配置解码/映射与对应测试，再将顶层 `mdns` 迁入 `layers[].mdns`；在此之前保留唯一过渡 case，不宣称严格层链可执行|

修订：v1.2.1（2026-10-01）补登记 G-MDNS-1：发现 mdns translate case/registry Fields 缺失，撤回“已严格层链迁移”的表述；保留唯一可执行 case 的顶层业务过渡形状，未改 Go、schema 或全局索引。

本版自审：两轮；第一轮逐项检查 CORE §1/§3/§4/§5/§6/§8/§12/§15 与 D1–D8，第二轮复核字段归属、缺口计划、门表和 cases 对账，末轮干净。

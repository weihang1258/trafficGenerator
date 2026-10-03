# #144 GTP 测试用例契约

> 版本：v1.1（as-built 修订，2026-10-01）
> 机器契约：`trafficgen/test/protocol_pcap/cases/gtp.json`（1 ID，纯层链 spec_json）。设计：`design.md`。

## 1. 测试原则与形状基线

用例是不可再分的可判定测试点。当前只有 1 个正例、0 个负例；pcap 与 NIC 必须共用本 JSON，本轮未执行 NIC。GTP 端口 2152 无自动 dissector，使用 `decode_as: udp.port==2152,gtp`。负例执行期严格只有 `expect_error` 与 `error_contains`，不得混入成功包断言。

`spec_json` 顶层键集合为 `{layers}`，层序为 `ip → udp → gtp`；这是当前 C 契约，不能用历史 flat 样例替代。

## 2. 原子用例索引（JSON 顺序权威）

|#|ID|类型|场景/依据|包数|断言|
|---:|---|---|---|---:|---|
|1|`gtp_smoke_01`|正|GTP-U T-PDU 空配置默认数据面；TS 29.281 §5.1–§5.2|1|version=1、message=0xff、length=28、TEID=0；外层 UDP 2152；GTP/inner IPv4 原始字节|

存量审计：`gtp_smoke_01` 保留 1，当前 JSON shape 已改为层链；无作废 ID、无新增未来 ID。GTP-C、IPv6、optional flags、Frames>1、各错误分支必须未来新增独立原子 ID，不得塞进本例。

## 3. `gtp_smoke_01` 逐条契约

输入（JSON 实际值）：

```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"udp":{"src_port":2152,"dst_port":2152}},{"gtp":{}}]}
```

层 translate 将空 GTP 映射为 `GTPConfig{}`；planner defaults：v1、PT=1、TEID=0、mode=u、Frames=1、inner IP 回退 outer IP、inner proto=UDP、TTL=64、direction=up。该默认链实际输出 1 个 UDP 封装的 GTP-U T-PDU。

- `packet_count=1`。
- tshark fields：packet 1 `gtp.flags.version=1`、`gtp.message=0xff`、`gtp.length=28`、`gtp.teid=0x00000000`。
- `decode_as`：`udp.port==2152,gtp`。
- frame bytes：offset 34 = `08 68 08 68`（外层 UDP src/dst 2152）；offset 42 = `30 ff 00 1c 00 00 00 00`（GTPv1 T-PDU、Length 28、TEID 0）；offset 62 = `0a 00 00 01 14 00 00 01`（inner IPv4 10.0.0.1→20.0.0.1）。
- `udp.dstport/ip.ttl/ip.proto` 不作 field 断言：内外层均有 IP/UDP，单值 FieldAssert 无法区分；外层端口由 offset 34 覆盖。

Length 28 = inner IPv4 20B + inner UDP 8B（空 payload）；GTP 固定头 8B 不计入 Length。offset 42 = Ethernet 14 + outer IPv4 20 + outer UDP 8；offset 62 = GTP offset 42 + header 8 + inner IPv4 offset 12 的地址位置。

## 4. 五层覆盖

### 功能

已覆盖 GTPv1 T-PDU 的固定 header version/message/length/TEID。未覆盖 GTP-C Echo/Create PDP、TV/TLV IE、E/S/PN optional block、extension header、down direction。功能缺口见 G-GTP-2/G-GTP-3。

### 性能

已覆盖单帧最小输出。未覆盖大 inner payload、Frames 多帧、extension/IE 上界、16-bit length 边界、跨底层 MSS/分片和并发吞吐；GTP planner 的 channel=256 是实现容量，不是协议速率保证。见 G-GTP-3。

### 数据场景

已覆盖默认 version=1、PT=1、TEID=0、inner IPv4/UDP 与空 payload。未覆盖 sequence/NPDU/extension、IE 编码、最大值/相邻溢出、TCP/ICMP/ICMPv6、非法值。见 G-GTP-3/G-GTP-4。

### 地址与流

已覆盖单 outer IPv4 + inner IPv4、up、单流。代码有 inner IPv6 路径但没有 JSON 证据；outer IPv6、down、控制/数据父子关联、多流/多会话均未覆盖。GTP 作为 UDP 应用层不提供 FIN/RST；异常中断属于承载层，当前无本协议 case。

### 业务

已覆盖现网用户面 T-PDU 冒烟。未覆盖控制面事务顺序、响应关联、PDP 生命周期、重试/重连/保活和多会话；不能以 planner 支持 scenarios 代替 case 证据。

## 5. 负例与错误覆盖

当前 JSON 无 `expect_error` ID。设计已登记的 validator 锚词必须在未来分别建立原子负例，并验证 task 终态失败、无成功 PCAP：`gtp: GTP config is required`、`Version`、`Mode`、`PT`、`not a valid IP address`、`use 58`/`use 1`、`not in supported list`、`exceeds`、`Frames`、`Direction`、`message_type is required`、`65535-byte maximum`（对应 `planner.go:88-185`）。当前只作缺口登记，不伪造覆盖。

## 6. 覆盖反查门建议断言

1. 形状门：`spec_json` 顶层键集合必须等于 `{layers}`（当前通过）；禁止 flat 游离键。
2. `gtp_smoke_01`：`packet_count=1`。
3. 该例 fields 必须保持 version=1、message=0xff、length=28、TEID=0 四项。
4. offset 34/42/62 三段 hex 必须与 JSON 逐字节一致。
5. GTP-C/IE、IPv6、E/S/PN、extension、Frames>1、inner L4 变体、每个 validator error branch 各需独立 ID（当前红）。
6. pcap 与 NIC 均引用同一 JSON；不得以旧结果产物冒充本轮复跑。

## 7. 缺口与过期产物

|缺口|现象|证据|归属阶段|
|---|---|---|---|
|G-GTP-1|GTP-C scenario/IE 无执行 case|`planner.go:333-357`；JSON 仅 1 ID|P5 功能|
|G-GTP-2|IPv6、E/S/PN、extension、Frames、多种 inner L4 无执行 case|`planner.go:361-391`；JSON 仅 smoke|P5 数据/地址/性能|
|G-GTP-3|validator 错误分支无负例|`planner.go:88-185`；JSON 无 `expect_error`|P5 错误|
|G-GTP-4|动态五策略未接线|`parseGTPConfig` `strategy_convert.go:4375` 以固定字段解析|P6 动态|
|G-GTP-5|多会话/流关联/控制事务未实现或未覆盖|GTP planner 单一 UDP flow；JSON 仅 1 case|P5 业务|
|G-GTP-6|tracked 结果产物过期|`trafficgen/docs/protocol-pcap-test/gtp.md` 末次提交早于 `0417be5`；主线程需以 `git log` 复核|P4 产物重跑|

## 8. 对账与修订

JSON ID 集合 = `{gtp_smoke_01}`；索引集合相同；正例=1、负例=0；packet_count=1；fields=4；frames=3；shape=layers。设计 D/T/C 证据相互一致。当前实现能力超出 case 的部分均标待实现/待覆盖，不计入完成度。

本轮修订删除 flat shape 的过时断言并收窄为当前层链；补齐五层不可再分覆盖点、严格负例契约、存量审计、覆盖门、缺口三要素和过期产物核验。**自审 2 轮，末轮干净**：逐条重读 JSON ID/顺序/包数/四 fields/三 offsets，并回查设计门1 §1–§14。

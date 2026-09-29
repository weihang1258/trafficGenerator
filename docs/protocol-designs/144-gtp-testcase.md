# #144 GTP 测试用例契约

> 版本：v1.0（as-built，2026-09-29）
> 机器契约：`trafficgen/test/protocol_pcap/cases/gtp.json`（1 ID，现状 flat spec_json）。设计：`144-gtp-design.md`。

## 1. 测试原则与输出

用例是不可再分的可判定测试点。当前存量只有 1 个正例、无负例；pcap 与 NIC 输出应共用本契约，但本批未执行 NIC。GTP 端口 2152 无自动 dissector，执行 pcap 时使用 `decode_as: udp.port==2152,gtp`。负例只允许 `expect_error` 与 `error_contains`，不得伪造成功包。

当前 case 的顶层 `spec_json` 仍 flat，目标层链形与迁移原因见设计 §1/§10；这不是已通过的层链契约。

## 2. 原子用例索引（cases JSON 顺序）

|#|ID|类型|场景/依据|包数|断言摘要|
|---:|---|---|---|---:|---|
|1|`gtp_smoke_01`|正|GTP-U T-PDU 默认数据面；TS 29.281 §5.1–§5.2|1|version=1、message=0xff、length=28、TEID=0；外层 UDP 2152；GTP/inner IPv4 原始字节|

存量审计：`gtp_smoke_01` 保留为冒烟但需层链改写；无作废 ID。未来 GTP-C、IPv6、optional flags、多帧、负例应新增独立 ID，不得塞进本例。

## 3. `gtp_smoke_01` 断言契约

输入（当前机器 JSON）：`src_ip=10.0.0.1`、`dst_ip=20.0.0.1`、`src_port=2152`、`dst_port=2152`、`count=1`、`gtp={}`；mode 缺省为 u，Version=1、PT=1、TEID=0、Frames=1，inner IP 回退 outer IP，inner proto=UDP。

- `packet_count=1`。
- tshark fields：packet 1 `gtp.flags.version = 1`；`gtp.message = 0xff`；`gtp.length = 28`；`gtp.teid = 0x00000000`。
- frame bytes：offset 34 = `08 68 08 68`（外层 UDP src/dst 2152）；offset 42 = `30 ff 00 1c 00 00 00 00`（GTPv1 T-PDU、Length 28、TEID 0）；offset 62 = `0a 00 00 01 14 00 00 01`（inner IPv4 source/destination）。
- `decode_as`：`udp.port==2152,gtp`。

不能从当前 case 断言：GTP-C message types/IE、Sequence/NPDU/extension、Frames>1、inner IPv6/TCP/ICMP、down direction、错误传播或动态策略。

## 4. 五层测试点覆盖

### 功能

已覆盖：GTPv1 T-PDU；固定 header version/message/TEID/Length。未覆盖：GTP-C scenarios、Echo/Create PDP、TV/TLV IE、E/S/PN optional block、extension header、down direction。缺口 G-GTP-2/G-GTP-3。

### 性能

已覆盖最小单帧和 1 个 T-PDU。未覆盖：大 inner payload、Frames 多帧、extension/IE 上界、16-bit length 边界、跨底层 MSS/分片、并发 aggregate throughput。缺口 G-GTP-3。

### 数据场景

已覆盖默认 Version 1、PT 1、TEID 0、inner UDP、默认 payload/IP。未覆盖零/最大 sequence、NPDU、extension data、IE 长度、IPv4 L4 变体及非法值。缺口 G-GTP-3/G-GTP-4。

### 地址与流

已覆盖单外层 IPv4 + 单 inner IPv4 flow。IPv6 inner 代码虽存在但无 case；外层 IPv6、up/down、控制流与数据流关联、多流/多会话均未覆盖。GTP 本身 UDP 无 FIN/RST；异常中断属于外层框架但没有本协议 case。

### 业务

已覆盖现网用户面 T-PDU 冒烟。未覆盖控制面事务、创建/删除 PDP 上下文、响应关联、重试/重连/保活和多会话。GTP-C 可按 scenarios 声明式顺序生成，但当前没有 case 证据。

## 5. 负例与错误覆盖

当前 JSON 无 `expect_error` ID。应分别为 validator 的 nil GTP、unsupported version/mode/PT/proto、invalid inner IP/family, extension overflow, negative Frames, invalid direction/message type/step direction, TLV overflow 建立原子负例，并断言完整锚词（见设计 §7）。现状登记 G-GTP-4；不得以“planner 可返回 error”代替执行契约。

## 6. 覆盖反查门建议断言行

- `gtp_smoke_01`: `packet_count=1`。
- `gtp_smoke_01`: `gtp.flags.version=1`、`gtp.message=0xff`、`gtp.length=28`、`gtp.teid=0x00000000`。
- `gtp_smoke_01`: frame offset 34/42/62 的三段 hex 与 §3 完全一致。
- 形状门：spec_json 顶层只允许 `layers`；当前 flat 键为红项（G-GTP-1）。
- 功能扩展门：GTP-C scenario/IE、S/PN/E、IPv6 inner、Frames>1、每个 validator error branch 各需独立 ID；当前均红。

## 7. 存量、缺口、产物

|缺口|现象|证据|归属阶段|
|---|---|---|---|
|G-GTP-1|存量 flat spec_json|`cases/gtp.json` 唯一 entry|P4 层链迁移|
|G-GTP-2|GTP-C/IE 无测试|planner scenario/encodeIEs 与 JSON 1 ID|P5 功能|
|G-GTP-3|IPv6、optional flags、multi-frame、inner L4 变体无测试|planner.go:350–408、500–597|P5 数据/地址/性能|
|G-GTP-4|validator 负例全无|planner.go:88–185；JSON 无 expect_error|P5 错误|
|G-GTP-5|动态五策略未接线|GTPConfig parseGTPConfig:4375；字段为固定值|P6 动态策略|
|G-GTP-6|tracked 结果产物过期|`trafficgen/docs/protocol-pcap-test/gtp.md` 末次提交 2026-08-27，早于 0417be5|P4 产物重跑|

## 8. 对账与自审

JSON ID 集合 = `{gtp_smoke_01}`；文档索引集合同为 1；packet_count=1；fields=4；frames=3；负例=0。存量审计总数 1（保留 1、改写 1、作废 0）。缺口 6 条；覆盖反查建议 6 组（其中 shape、扩展功能为红/待实现）。**自审 2 轮，末轮干净**：逐条从 JSON 重读 ID/顺序/包数/字段/offset/hex，并回查设计 §1–§14 与门1 十四行。

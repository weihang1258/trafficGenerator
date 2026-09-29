# #144 GTP（GPRS Tunnelling Protocol）设计契约

> 版本：v1.0（as-built，2026-09-29）
> 规范基线：3GPP TS 29.060（GTPv1-C）与 TS 29.281（GTPv1-U），RFC 768/791/8200（承载 UDP/IP）；代码与 cases 是当前可执行行为的最终依据。
> 实现：`trafficgen/internal/protocol/gtp/planner.go`、`layer_gen.go`；配置类型 `trafficgen/internal/core/types.go:GTPConfig`；层注册 `internal/core/layers/registry.go:520`。

## 1. 范围、层链与实现边界

本契约描述 GTPv1 作为 UDP 终结层的生成行为。推荐层链为 `[ip, udp, gtp]`；GTP 字节是 UDP payload，外层 L2/L3/L4 由核心 builder 生成。registry 将 `gtp` 登记为 `CategoryTerminal`、依赖 `udp`，无固定端口 FieldContract；Plan 按 mode 选择端口：GTP-U 2152、GTP-C 2123。

已实现：GTPv1 flags、TEID、可选 Sequence/N-PDU/extension、GTP-U T-PDU 内层 IPv4/IPv6（UDP/TCP/ICMP/ICMPv6）、GTP-C scenario 消息与 TV/TLV IE、up/down 地址方向、Frames。未实现或未由当前 cases 证明：GTPv2、真实网元状态机、PDP 上下文语义、重传/超时、分片重组、多流并发、动态 strategy 字段、真实 NIC/pcap 复跑。

输出契约：pcap 与 NIC（若运行框架启用 NIC 捕获）必须共用 `cases/gtp.json` 的同一断言；本批只登记现有 pcap smoke 契约，NIC 未执行。

目标形状（层链唯一配置真相）：
```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"udp":{"src_port":2152,"dst_port":2152}},{"gtp":{}}]}
```

## 2. 配置到帧的完整路径

`strategy_convert.go:1213` 读取顶层 `gtp` 子映射，`parseGTPConfig`（`:4375`）映射字段；层 translate 将配置放入 `FlowMeta.GTP`；registry 选择 `GTPGenerator`。`GTPGenerator.Generate`（`layer_gen.go:34`）复制 FlowMeta 到 `core.FlowSpec`，调用 `Planner.Plan`，把每个 `PacketConfig.Payload` 转为 `MessageEvent` 并设置 `L4PortOverride=true`，避免 UDP 层再次交换已由 GTP resolveDirection 处理的方向端口。

`Planner.Validate`（`planner.go:88`）只读校验；`Plan`（`:207`）在启动 goroutine 前解析默认值，再流式发送 `PacketConfig`。无聚合全流包切片。`emit` 给每包写 outer Ethernet/IP/UDP 元数据与 GTP payload；取消 context 即停止。

## 3. GTPv1 线格式

### 3.1 固定头与长度

所有多字节字段均为网络字节序（big-endian）。固定头为 8 字节：

|偏移|字段|宽度/编码|规则|
|---:|---|---|---|
|0|Flags|1B|Version bits7..5（v1=`001`），PT bit4，spare bit3=0，E/S/PN bits2..0|
|1|Message Type|1B|T-PDU=`0xff`；scenario 由配置指定，0 被拒绝|
|2|Length|UInt16 BE|头前 8B 之后的 optional block、extension、payload 总长度；不含 TEID|
|4|TEID|UInt32 BE|始终存在；默认 0|

总长公式：`8 + (E||S||PN ? 4 : 0) + (E ? 1 + extLenPadded : 0) + payloadLen`。Length 字段等于总长减 8。空 GTP-U 默认案例的 payload 是内层 IPv4/UDP 包 28B，故 GTP length=28、总 GTP=36B。

### 3.2 Optional 与 extension

E、S 或 PN 任一置位即追加 4B optional block：Sequence UInt16 BE、N-PDU Number 1B、Next-Extension-Type 1B（E=0 时写 0）。E 置位时再写 extension next-type 1B（实现恒 0）、Length 1B 与 content；`Length=(1+content+padding)/4`，content 按 4B 补齐。`ExtensionData` 最大 1018B，超出拒绝；`ExtensionType` 写入 optional block 的 next-extension 字段。

### 3.3 IE 编码（GTP-C）

`GTPIE.Type < 0x80` 使用 TV：`Type(1)+Value`，无长度字段；`Type >= 0x80` 使用 TLV：`Type(1)+Length(UInt16 BE)+Value`。TLV value 最大 65535B；TV 固定长度由协议类型语义决定，但当前 validator 不逐类型核验长度。scenario 每项恰好生成一条 GTP-C packet；scenario 非空时跳过 Frames 数据面。

## 4. GTP-U 内层数据

当 `Scenarios` 为空，Frames 个 T-PDU（0→1）承载 inner packet；message type 恒 `0xff`。InnerSrcIP/DstIP 缺省回退 outer flow IP；InnerProto 0 时 spec.TCP 存在则 TCP(6)，否则 UDP(17)；InnerTTL 0→64；InnerPayload nil→spec.Payload；InnerIPID 从配置值开始逐帧加一。IPv4 为 20B header + L4，DF 置位，header checksum RFC 791；IPv6 为 40B header，无 IP checksum，hop limit 64 默认。

inner L4：TCP 20B+options+payload，UDP 8B+payload，ICMPv4 8B+payload（echo request），ICMPv6 8B+payload；TCP/UDP/ICMPv6 用相应 pseudo-header checksum。InnerProto 仅允许 6/17/1/58；IPv4 与 ICMPv6、IPv6 与 ICMPv4 的组合拒绝。

Direction 默认 up；down 交换 outer MAC/IP/ports 及 inner source/destination。每包 PacketIndex 从 0 递增，flow ID 是 outer IP/port 字符串组合。

## 5. GTP-C scenario 与状态模型

配置是声明式剧本，不是收包驱动状态机。`Scenarios[]` 按顺序展开；每个 step 的 Direction 缺省为 cfg.Direction，再缺省 up；TEIDOverride 非 nil 替代 config TEID；Sequence 仅在 S flag 置位时写入，按 step 原值。当前实现没有自动响应、事务配对、重试、重连或跨 scenario 状态校验。

合法状态只有 planner 的两条选择：`Scenarios non-empty → control dialog`；`Scenarios empty → user-plane Frames`。MessageType=0、非法 direction/mode/version、负 Frames、错误内层地址/协议、超大 extension/IE TLV 被 Validate 拒绝。相同输入的 Plan 输出确定。

## 6. 业务场景与五层覆盖

- 功能：当前 JSON 仅覆盖 GTP-U 默认 T-PDU；GTP-C Echo/Create PDP 等 scenario 未落用例，列入缺口。
- 性能：Frames、inner payload、extension/IE 上界在代码有容量规则；MSS 分段、GTP 分片、并发测量未实现/未覆盖。
- 数据：version/PT/TEID/sequence/NPDU/extension/IE/inner fields 均有配置入口；仅空配置值在 cases 有观测证据。
- 地址与流：外层与内层 IPv4 代码存在；IPv6 代码存在但无 case。单流已覆盖；控制/数据父子流关联、多流不适用当前实现。
- 业务：GTP-U 用户面是现网核心路径；GTP-C 控制面为可生成剧本但未有契约案例。多会话、事务依赖、保活、重试、重连、FIN/RST 不适用 GTP UDP 本层，不能冒充已覆盖。

## 7. 错误契约

|输入|错误锚词（代码）|位置|
|---|---|---|
|GTP nil|`gtp: GTP config is required`|planner.go:90|
|Version 非 0/1|`Version ... not supported`|:98|
|Mode 非空/u/c|`Mode ... not in supported list`|:105|
|PT>1|`PT ... must be 0`|:109|
|内层 IP 非法|`is not a valid IP address`|:122|
|inner proto 与 IP 族不符|`is for IPv4/IPv6 inner packets`|:141/:145|
|不支持 inner proto|`not in supported list`|:148|
|ExtensionData>1018|`exceeds ... maximum`|:155|
|Frames<0|`Frames ... must be >= 0`|:159|
|非法 direction|`Direction ... not in supported list`|:166|
|scenario message_type=0|`message_type is required`|:171|
|非法 scenario direction|`Direction ... not in supported list`|:177|
|TLV value>65535|`value ... exceeds the 65535-byte maximum`|:183|

负路径必须在任务终态传播 error，不产生成功 PCAP；当前 JSON 没有负例。

## 8. 性能与容量

单包内存与 payload 长度线性；Plan 通过有界 channel（256）流式发包。GTP Length/IE 长度均 UInt16；extension content 上限 1018B。Frames 越大，单流输出线性增长，IPv4 IPID 与可选 Sequence 按 frame 递增并在 16 位转换处自然回绕；回绕未在 cases 验证。生成器不提供协议级速率承诺。

## 9. 当前 JSON 对账

唯一存量 `gtp_smoke_01`：1 包；spec_json 只有 `src_ip/dst_ip/src_port/dst_port/count/gtp`，尚未迁移成纯层链形，详见 G-GTP-1。断言：GTP version=1、message=0xff、length=28、TEID=0；frames offset 34 外层 UDP ports 2152、offset 42 GTP 头 `30 ff 00 1c 00 00 00 00`、offset 62 inner IPv4 `10.0.0.1→20.0.0.1`。`decode_as` 为 `udp.port==2152,gtp`。

## 10. 门1：§1–§14 对照表

|条款|as-built 满足方式与证据|
|---|---|
|§1 顶层旧键|存量仍为 flat：`src_ip,dst_ip,src_port,dst_port,count,gtp`；去向应为 `layers:[ip,udp,gtp]` 与 flow_control count；完整目标例见 §1，缺口 G-GTP-1。|
|§2 协议/规范|TS 29.060/29.281；头、IE、T-PDU 见 §3–4。|
|§3 五件套|会话表：无；事务序列：scenario 顺序；关联关系：无自动关联；插入位置：UDP payload；时间线：每帧即时发送。单 UDP 流无连接会话，控制/数据关联未实现。|
|§4 状态机|Plan 二分分支与 Validate 错误状态，见 §5/7。|
|§5 线格式|8B header、optional、extension、IE、inner IP 见 §3–4。|
|§6 配置|GTPConfig/GTPStep/GTPIE 全字段见 `types.go:5027`，解析见 `strategy_convert.go:4375`。|
|§7 驱动|Generate→Plan→MessageEvent，见 §2。|
|§8 默认值|v1、PT=1、port u=2152/c=2123、Frames=1、TTL=64、direction up，见 planner.go:218–260。|
|§9 错误|锚词表见 §7；无负例 case。|
|§10 性能|长度/容量/流式约束见 §8。|
|§11 地址与传输|外层 UDP；IPv4/IPv6 inner 代码；外层端口方向交换见 §4。|
|§12 动态字段|流序号算法：`packetIndex++`（planner.go:260–287）；Frames 序号：`InnerIPID+uint16(i)`、`Sequence+uint16(i)`（:381–408）。src/dst IP/port、TEID、inner payload、IE 等当前仅 fixed 配置；inc/rand/list/pattern 五种策略未接线。|
|§13 产物|设计/用例/cases 三件套；tracked 结果过期登记见 §13。|
|§14 验收|本文 §11–14 给出审计、缺口、反查建议、自审结论。|

## 11. 存量审计

`gtp_smoke_01` 保留为唯一冒烟例，但需改写 spec_json 为层链并将 count 移至 flow_control；其 fields/frames/packet_count 断言可保留。无其他存量 ID。

## 12. 覆盖反查门建议断言

1. `gtp_smoke_01`：packet_count=1；`gtp.flags.version=1`；`gtp.message=0xff`；`gtp.length=28`；`gtp.teid=0x00000000`。
2. 同例 frame offset 34 hex `08 68 08 68`；offset 42 hex `30 ff 00 1c 00 00 00 00`；offset 62 hex `0a 00 00 01 14 00 00 01`。
3. 反查 flat 判死：spec_json 顶层必须仅有 `layers`（当前红）。
4. GTP-C scenario、IPv6 inner、S/PN/E、Frames>1、错误锚词均应有独立 ID（当前红/未覆盖）。

## 13. 缺口与产物核验

- **G-GTP-1**：现象：唯一 case 是 flat 顶层键；证据：`cases/gtp.json` 实测 spec_json keys；归属：P4 层链迁移。
- **G-GTP-2**：现象：GTP-C scenario 与 IE 无 case；证据：Planner.Plan 分支 `planner.go:310–347`，JSON 仅 1 ID；归属：P5 功能覆盖。
- **G-GTP-3**：现象：IPv6、S/PN/E、Frames 多帧、inner TCP/ICMP 无 case；证据：planner.go:350–408/534；归属：P5 数据与地址覆盖。
- **G-GTP-4**：现象：validator 各错误分支无 expect_error case；证据：planner.go:88–185，JSON 无负例；归属：P5 错误覆盖。
- **G-GTP-5**：现象：动态字段五策略未接线；证据：GTPConfig 全部普通字段，parseGTPConfig:4375；归属：P6 动态策略。
- **G-GTP-6**：现象：tracked `trafficgen/docs/protocol-pcap-test/gtp.md` 末次提交 e7e7d1c（2026-08-27）早于 0417be5 判死基线；证据：`git log -1 -- trafficgen/docs/protocol-pcap-test/gtp.md`；归属：P4 产物重跑。

## 14. 修订与自审

本稿为初版 as-built。自审逐字段核对 GTPConfig、planner defaults、header length、case packet_count/offset/hex、门1十四行与缺口三要素；**自审 2 轮，末轮干净**。独立代码设计逻辑与用例覆盖对抗审查仍待主线程隔离执行。

# #144 GTP（GPRS Tunnelling Protocol）设计契约

> 版本：v1.1（as-built 修订，2026-10-01）
> 规范：3GPP TS 29.060（GTPv1-C）与 TS 29.281（GTPv1-U）；承载依据 RFC 768/791/8200。
> 实现证据：`trafficgen/internal/protocol/gtp/{planner.go,layer_gen.go}`、`trafficgen/internal/core/types.go:GTPConfig`、`trafficgen/internal/core/strategy_convert.go:4375`、层注册表及 `cases/gtp.json`。

## 1. 范围、层链与边界

本协议实现 GTPv1 over UDP。`mode=u`（缺省）生成 GTP-U T-PDU（默认 UDP 2152），`mode=c` 生成按 `scenarios[]` 编排的 GTP-C 消息（默认 UDP 2123）。GTP 是 UDP 的终结层；推荐唯一配置真相是层链：

```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"udp":{"src_port":2152,"dst_port":2152}},{"gtp":{}}]}
```

当前机器契约只有 `gtp_smoke_01`，其 `spec_json` 已为纯层链，顶层仅 `layers`。`count` 不在该例中；默认一次 T-PDU 由 GTP planner 的 `Frames=0 -> 1` 规则产生。flat `src_ip/dst_ip/src_port/dst_port/count/gtp` 形已从现行 case 移除，历史 flat 不是可执行契约。

已实现并有代码证据：GTPv1 header、TEID、E/S/PN optional block、单 extension header、GTP-C TV/TLV IE、GTP-U 内层 IPv4/IPv6 的 UDP/TCP/ICMP/ICMPv6、Frames、up/down。当前 JSON 仅证明空配置 GTP-U IPv4/UDP 单帧。未实现或未由 cases 证明：GTPv2、真实网元状态机、PDP 语义、重传/超时/分片重组、并发多流、动态五策略和真实 NIC/pcap 重跑。

pcap 与 NIC（启用时）必须共用同一个 `trafficgen/test/protocol_pcap/cases/gtp.json` 契约；本次只做静态文档/cases 审查，未宣称 NIC 或 suite 通过。

## 2. 配置到输出的路径

层 translate 将 `ip`、`udp`、`gtp` 层配置汇入 `FlowMeta`；`strategy_convert.go:4375` 的 `parseGTPConfig` 将 GTP 字段映射为 `GTPConfig`；`GTPGenerator.Generate` 调 `Planner.Plan`，把每个 `PacketConfig.Payload` 作为 UDP payload 的 `MessageEvent` 送出，并设置 `L4PortOverride`，避免 UDP 层二次交换方向端口。`Planner.Validate` 只读校验；`Plan` 先解析默认值，再通过有界 channel（256）流式产生包，不聚合整流。

## 3. GTPv1 线格式

### 3.1 固定头与长度

所有多字节字段为网络字节序（big-endian）。固定头 8B：

|偏移|字段|宽度/编码|规则|
|---:|---|---|---|
|0|Flags|1B|Version bits 7..5（v1=`001`）、PT bit4、spare bit3=0、E/S/PN bits 2..0|
|1|Message Type|1B|T-PDU=`0xff`；GTP-C 由 scenario 指定，0 拒绝|
|2|Length|UInt16 BE|8B 首部之后的 optional、extension、payload 总长，不含 TEID|
|4|TEID|UInt32 BE|始终存在，缺省 0|

`total = 8 + optional(0或4) + extension(E时为 1+ext块) + payload`，`Length = total - 8`。E/S/PN 任一置位即追加 `Sequence UInt16 + N-PDU UInt8 + Next-Extension-Type UInt8`。E 置位时 extension content 以 4B 补齐，extension length 以 4B 单位编码；当前 `ExtensionData` 上限 1018B。

### 3.2 GTP-U 内层

`Scenarios` 为空时，`Frames=0` 回退 1，逐帧 message=`0xff`。内层地址缺省回退外层 flow IP，`InnerProto=0` 在 `spec.TCP` 存在时为 TCP(6)，否则 UDP(17)；TTL/hop-limit 0 回退 64；IPv4 IPID 从 `InnerIPID` 起按帧加一；S flag 开启时 Sequence 按帧递增。IPv4 为 20B header，DF 置位并计算 RFC 791 checksum；IPv6 为 40B header，无 IP checksum。内层 L4 支持 TCP(6)、UDP(17)、ICMPv4(1)、ICMPv6(58)，族与 ICMP 类型不匹配拒绝。

`direction=down` 交换外层 MAC/IP/端口及内层源/目的地址；缺省为 `up`。当前 case 是单帧 up、IPv4、UDP。

### 3.3 GTP-C scenario 与 IE

`Scenarios` 非空时每个 step 恰好输出一个 GTP-C packet，跳过 Frames。step Direction 缺省继承 config Direction，再缺省 up；TEIDOverride 非空覆盖 config TEID；S flag 清零时不写 Sequence。Type<0x80 的 IE 编为 TV（Type+Value），Type>=0x80 编为 TLV（Type+UInt16 BE Length+Value）；TLV value 最大 65535B。当前无 GTP-C case，故这些是待实现覆盖边界，不计入已覆盖。

## 4. 状态、业务和五层覆盖

本引擎是声明式/脚本化回放，不是收包驱动状态机。唯一 planner 分支是 `Scenarios non-empty -> control dialog` 或 `Scenarios empty -> user-plane Frames`；同一输入确定地产生同一包序列。GTP-U 典型现网场景是隧道用户数据；GTP-C 的 Echo/PDP 建立等由有序 scenario 表达，但当前没有可执行 case。

|覆盖层|当前证据|明确缺口/不适用|
|---|---|---|
|功能|1 个 GTP-U T-PDU 正例：version/message/length/TEID|GTP-C 消息/IE、E/S/PN、extension、方向变体和每个 validator 错误无 JSON 负例|
|性能|单帧最小可执行输出|大内层 payload、Frames 多帧、extension/IE 上限、跨 MSS/分片、并发吞吐未覆盖；GTP 层不承诺速率|
|数据|默认 v1/PT=1/TEID=0、inner IPv4/UDP|零/最大 sequence、NPDU、extension、IE、TCP/ICMP 及非法值未覆盖|
|地址与流|外层 IPv4 + inner IPv4 的单流 up|IPv6、down、双载体同契约未执行；GTP UDP 本身无 FIN/RST；控制-数据父子流关联、多流未实现/未覆盖|
|业务|用户面单 T-PDU 冒烟|GTP-C 请求/响应关联、PDP 生命周期、重试/重连/保活、多会话未实现/未覆盖|

地址层的 IPv6 不是“代码存在即覆盖”：代码路径存在，但当前 JSON 无 IPv6 断言，保留为缺口。流关联和多流若需实现，必须新增独立原子 case，不能由 smoke 例代替。

## 5. 错误契约（待执行负例）

`Planner.Validate` 的已知错误锚词如下；当前 JSON **没有** `expect_error` 条目，不能声称这些分支已测试。

|输入|`error_contains` 锚词|证据|
|---|---|---|
|GTP nil|`gtp: GTP config is required`|`planner.go:88-91`|
|Version 非 0/1|`Version`|`:94-99`|
|Mode 非空/u/c|`Mode`|`:101-105`|
|PT>1|`PT`|`:108-110`|
|inner IP 非法|`not a valid IP address`|`:112-123`|
|ICMP 与 IP 族不符|`use 58` / `use 1`|`:126-146`|
|InnerProto 不支持|`not in supported list`|`:147-149`|
|ExtensionData>1018|`exceeds`|`:152-155`|
|Frames<0|`Frames`|`:158-160`|
|Direction 非 up/down|`Direction`|`:162-167`|
|scenario message_type=0|`message_type is required`|`:169-172`|
|scenario Direction 非法|`Direction`|`:173-178`|
|TLV value>65535|`65535-byte maximum`|`:179-184`|

未来负例必须严格只有 `expect_error` 与 `error_contains`，失败必须传播到任务终态且不得产生成功 PCAP；在实现/测试阶段逐错误分支补原子 ID。不得以本表替代执行证据。

## 6. 动态字段与序号

当前 `GTPConfig` 字段由 `parseGTPConfig` 以固定值解析：`mode/version/pt/teid/sequence_present/sequence/npdu_present/npdu_value/extension_present/extension_type/extension_data/scenarios/inner_src_ip/inner_dst_ip/inner_proto/inner_ttl/inner_ipid/inner_payload/tcp_options/frames/direction`。已实现的序号算法仅为 planner 内部：`packetIndex++`（`planner.go:270-300`）、`InnerIPID + uint16(i)`（`:376-379`）与 S flag 的 `Sequence + uint16(i)`（`:384-389`）。src/dst IP/port、TEID、inner payload、业务字段尚未接入 fixed/inc/rand/list/pattern 五策略；不得在文档或 JSON 假称动态已覆盖。动态实现阶段需分别测试回绕、可复现、轮转、pattern 替换及固定四元组重复拒绝/告警。

## 7. 门1：§1–§14 对照表

|条款|as-built 满足方式与证据|
|---|---|
|§1 顶层旧键|当前 `spec_json` 顶层仅 `layers`（`cases/gtp.json`）；目标链 `[ip,udp,gtp]`，例见本文 §1；无 flat 残留。|
|§2 规范|TS 29.060/29.281、RFC 768/791/8200；线字段见 §3。|
|§3 五件套|会话表：UDP 无连接，豁免；事务序列：scenario 顺序；关联关系：当前无自动关联；插入位置：UDP payload；时间线：每 frame 即时发送。GTP-C 父子事务未实现。|
|§4 状态机|Validate + Plan 二分分支，`Scenarios` 非空/为空，见 §4–5。|
|§5 线格式|8B header、optional、extension、IE、inner IP，见 §3。|
|§6 配置|`GTPConfig` 字段表与 JSON 解析证据见 §2、§6；层内 GTP 子映射由 translate 接线。|
|§7 驱动|层 generator → Planner.Plan → PacketConfig → MessageEvent → UDP payload，见 §2。|
|§8 默认值|v1、PT=1、u=2152/c=2123、Frames=1、TTL=64、direction=up、TEID=0，见 `planner.go:211-263`。|
|§9 错误|锚词表见 §5；当前负例数为 0，未宣称验证。|
|§10 性能|channel=256 流式输出；长度/extension 上限见 §3、§5；大包/并发未覆盖。|
|§11 地址与传输|外层 UDP；内层 IPv4/IPv6 代码路径；当前 case 只证明 IPv4。|
|§12 动态字段|字段清单、内部 frame 序号及未接入五策略见 §6。|
|§13 产物|design + testcase + cases 三件套；过期 tracked 产物见 §9。|
|§14 验收|D/T/C 对账、缺口和门建议见 §8–§10；未运行 suite/NIC。|

## 8. D/T/C 对账、覆盖门和存量审计

设计 D 面：D1 层链唯一真相/端口，D2 header/length/端序，D3 inner packet，D4 scenario/IE，D5 状态分支，D6 默认/错误，D7 性能容量，D8 动态字段；分别落在 §1–§6。测试 T 面只有一个可执行行为 ID，见 `testcase.md` §2；D 面中未被 JSON 证明的能力均标边界。C 面 `gtp.json` 仅 1 正例、0 负例，顶层 shape=layers，packet_count=1，fields=4，frames=3。

存量审计：`gtp_smoke_01` 保留 1；本轮仅修正其文档/JSON shape 对账，不作废、不新增未实现 ID。

覆盖反查门建议：
1. `spec_json` 顶层键集合必须等于 `{layers}`（当前通过）；
2. `gtp_smoke_01` packet_count=1；
3. version=1、message=0xff、length=28、TEID=0；
4. offsets 34/42/62 的三段 hex 与 cases 完全一致；
5. GTP-C、IPv6、E/S/PN、extension、Frames>1、每个 validator branch 必须分别有 ID（当前红）；
6. pcap/NIC 两路径引用同一 JSON，不得以旧结果产物代替复跑。

## 9. 缺口与过期产物

|ID|现象|证据|归属阶段|
|---|---|---|---|
|G-GTP-1|动态五策略未接线|`parseGTPConfig` 固定字段，`strategy_convert.go:4375`|P6 动态|
|G-GTP-2|GTP-C scenario/IE 无执行 case|`planner.go:333-357`；JSON 仅 1 ID|P5 功能|
|G-GTP-3|IPv6、E/S/PN、extension、Frames、多种 inner L4 无执行 case|`planner.go:361-391`；JSON 仅 smoke|P5 数据/地址/性能|
|G-GTP-4|validator 错误分支无负例|`planner.go:88-185`；JSON 无 `expect_error`|P5 错误|
|G-GTP-5|多会话/流关联/控制事务未实现或未覆盖|GTP planner 单流 channel；JSON 仅 1 case|P5 业务|
|G-GTP-6|tracked 结果产物过期|`trafficgen/docs/protocol-pcap-test/gtp.md` 末次提交早于 `0417be5`（需主线程复核 git 证据）|P4 产物重跑|

## 10. 修订与自审

本轮以实现和当前 `cases/gtp.json` 为权威，删除 flat shape 的过时表述，补齐 D/T/C、严格层链、五层覆盖、错误锚词和缺口三要素。自审第 1 轮：发现设计 §1/§9 与当前 JSON shape 不一致；第 2 轮已修正并复核 ID、顺序、包数、4 fields、3 frames、offset/hex、门1 十四行和缺口证据。**自审 2 轮，末轮干净。**

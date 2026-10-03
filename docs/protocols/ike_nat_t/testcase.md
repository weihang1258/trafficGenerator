# IKE-NAT-T 测试用例契约

> 版本：v1.1.0（层链迁移版）；日期：2026-09-30；权威 JSON：`trafficgen/test/protocol_pcap/cases/ike_nat_t.json`；实现仅对现有 case 负责。
> 配套设计：`docs/protocols/ike_nat_t/design.md` v1.1.0。
> 白话一句：**现网证据目前只有 UDP 500 上的 IKEv2 SA_INIT 空载荷头；层链已迁为 `[ip,udp,ike_nat_t]`，4500 marker、NAT-D 与 ESP 仍按缺口登记。**

## 1. 测试原则和形状基线

JSON 是唯一 ID、顺序、包数、字段、frame 锚点权威。本套件 1 正、0 负。形状为严格层链：唯一顶层键 = `{layers}`，链 `[ip,udp,ike_nat_t]`。case 显式 dst=500，因此不应出现 Non-ESP Marker；marker 只在实际 dst=4500 的新例验证。pcap/NIC 共用本 cases 断言；历史结果文档与 pcap 留档过期/缺失，见 §8/G-NATT-2。动态 SPI 只断言 nonzero/zero，不固定随机值。

## 2. 原子用例索引

|#|ID|类型|依据链|包数|
|---:|---|---|---|---:|
|1|`ike_nat_t_sa_init_header_only`|正|RFC 7296 §3.1；RFC 3948 端口边界；design §2-3|至少 1|

## 3. 正例逐项断言契约

### 3.1 `ike_nat_t_sa_init_header_only`

配置为严格层链 `ip.src=10.0.0.1`、`ip.dst=20.0.0.1`、`udp.dst_port=500`、`ike_nat_t.dialog=[{direction:"up",exchange_type:34}]`；单流不写 `count`。packet 1：`udp.dstport=500`；`isakmp.ispi` 非零；`isakmp.rspi=0000000000000000`；`isakmp.version=0x20`；`isakmp.exchangetype=34`；`isakmp.flags=0x08`；`isakmp.length=28`。frame packet 1 offset 58 的稳定字节为 `00 20 22 08 00 00 00 00 00 00 00 1c`。由于目的端口是 500，不能要求 Non-ESP Marker；SPIi 是运行期随机值。

## 4. 负例契约

现有 JSON 没有负例。planner 已覆盖非法方向、exchange、NAT-D 长度、IP、重传参数和缺配置错误，但这些未被此套件的 JSON 驱动，不能报告为已覆盖。

## 5. 覆盖与对账

设计 §7、本文 §2、JSON 数组均只有 `ike_nat_t_sa_init_header_only`，顺序一致；正例 1、负例 0；`min_packets=1`；fields 与 frames 非空。三源回指：RFC 7296 §3.1 / RFC 3948 端口边界 → design §2–§3、§14.1 → tshark `isakmp.*` 与 frame hex。五层反查：功能=SA_INIT；性能=单 UDP；数据=28B header；地址流=dst 500；业务=header-only IKEv2。NAT-D、4500、ESP、keepalive、重传、错误面均明确列 G-NATT-1，且每项有扩展计划。

**测试点清单（规范→业务→代码→缺口）**：SA_INIT header→空载荷请求→`buildIKENATTMessage`→T-1 已覆；4500 marker→NAT 浮动→`runPlan`→G-NATT-1；NAT-D→Notify SHA-1→`computeNATDHash`/`encodeNATTPayloads`→G-NATT-1；ESP/keepalive→UDP 封装与保活→`emitESPSubFlows`/`emitKeepaliveSubFlows`→G-NATT-1；非法 dialog/IP/nonce/重传→validator→G-NATT-1 负例。

**三类强度**：数据场景已覆盖版本/交换类型/标志/长度与零 SPIr；业务场景当前仅一条 SA_INIT，非正常结束和长保活列 G-NATT-1；现网场景当前仅 500 header，NAT 网关抓包列 G-NATT-1。规范逻辑点总数 13，已覆盖 7，缺口 6；数字仅为本文清单行计数，不代表协议全覆盖。

**§3.15 三项（同连接多轮操作／非正常结束／长保活）**：

|项|本协议对照|用例或立项|
|---|---|---|
|同连接多轮操作|同一 IKE SA 上连续 exchange（SA_INIT→AUTH→Child SA）|立项 G-NATT-1（P4 用例扩展）|
|非正常结束|INFORMATIONAL DELETE/超时中断|立项 G-NATT-1（P4 用例扩展）|
|长保活|UDP 4500 keepalive（`0xff` 单字节）|立项 G-NATT-1（P4 用例扩展）|

## 6. P3 固定动作

执行 JSON parser、ID 唯一性、正负 expect 结构、frame offset/hex 静态检查；运行 layer generator 并用 tshark `isakmp.*` 验证；单流 UDP 不适用 TCP handshake/termination。4500 marker 的 case 应另行新增，不能从本例推导。

## 7. 实现后执行建议

确认 dst=500 时 payload 直接从 IKE header 开始；确认 rspi 8B 全零；确认 SPIi 仅 nonzero；确认 version/exchange/flags/length 和 frame 稳定字节；失败必须传播 task error，不以空结果代替。

## 8. 存量审计与产物核验

|现存 ID|去向|原因|
|---|---|---|
|`ike_nat_t_sa_init_header_only`|合入并完成层链迁移|唯一权威 case，验证最小 IKEv2 NAT-T planner header 形状及 500 端口 marker 边界。|

无作废或改写 ID。存量 `spec_json` 已由扁平 `{count,dst_port,ike_nat_t}` 迁为严格层链 `{layers}`，链为 `[ip,udp,ike_nat_t]`。

**G-NATT-2 产物核验**：tracked `trafficgen/docs/protocol-pcap-test/ike_nat_t.md` 末次提交 `e7e7d1c`（2026-08-27）早于 `0417be5`（2026-09-13）；`trafficgen/docs/protocol-pcap-test/ike_nat_t/` 不存在、无 pcap。其 “pass 1” 未经 2026-09-29 今日复跑证实。

## 9. 缺口登记（三要素）

|ID|现象|证据|归属阶段|
|---|---|---|---|
|G-NATT-1|NAT-D/4500 marker/ESP/keepalive/重传和全部负例无 case；每项扩展计划与现网确认方式见 §5|JSON 仅 1 条 header-only 例|P3/P4 用例扩展|
|G-NATT-2|结果产物过期且无 pcap 留档，历史 pass 数未经今日复跑证实|`e7e7d1c` 2026-08-27 < `0417be5` 2026-09-13；目录不存在|P5 重跑并重生成产物|
|G-NATT-4|`CheckProtoFlat` 未登记 ike_nat_t，presence 负例会假绿|strategy_convert.go 无该分支|P6 框架面|
|G-NATT-5|dynamic allowlist 无 ike_nat_t 业务字段行|layer_dyn.go 无命中|P6 框架面|
|G-NATT-6|性能目标、规模边界与双路验收基准缺失；待取证，不作承诺|设计 §14.4|P5 性能取证|

## 10. 覆盖反查门建议断言行

|#|可静态机读断言|状态|
|---:|---|---|
|1|ID 恰为 `ike_nat_t_sa_init_header_only`，顺序 1|绿|
|2|正例=1、负例=0、`min_packets=1`|绿|
|3|dstport=500、SPIi nonzero、SPIr exact zero|绿|
|4|version=0x20、exchange=34、flags=0x08、length=28|绿|
|5|frame offset=58，hex 精确匹配|绿|
|6|顶层键 ⊆ `{layers}`，链 `[ip,udp,ike_nat_t]`|绿|
|7|负例锚词集合非空|红：0 负例，G-NATT-1|

pcap/NIC 两路必须复用同一断言集，不能用过期结果产物代替复跑。

## 11. 六项测试审计（T1-T6，2026-10-01）

| ID | 审计结论 | 证据 |
|---|---|---|
| T1 | 1 个 ID 唯一、顺序与 JSON 一致且 JSON 可解析 | `cases/ike_nat_t.json` 机读审计 |
| T2 | 唯一正例采用严格 `[ip,udp,ike_nat_t]` 层链 | 全量 `spec_json.layers` 审计 |
| T3 | 当前正例 1、负例 0；未把未入 JSON 的 validator 分支冒充覆盖 | `expect_error`/`error_contains` 计数；G-NATT-1 |
| T4 | 地址在 ip 层、端口在 udp 层、业务在 ike_nat_t 层；无游离旧键 | 顶层键与层内字段审计 |
| T5 | SPI 随机性只用 nonzero/零值断言；单流数量不伪造为业务字段 | §3.1 与 JSON fields |
| T6 | 层链迁移保持 packet 字段、offset/hex 与缺口语义；本车道未跑 suite/MCP/NIC | §1、§3、§9；工作流约束 |

迁移状态：1/1 case 为目标形状。当前没有 presence 负例；若新增，必须保留“层链 + 顶层 `ike_nat_t:{}` 并存”的判死形状。`unknown layer` 是未知层拒绝的真实锚词，但当前 JSON 没有该负例，不能计入已覆盖。

## 12. 六项覆盖清单（C1-C6）

| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | IPv4 UDP 500 上 IKEv2 SA_INIT header-only | 已覆盖唯一正例 |
| C2 | IKE header 字段、SPI 与稳定帧字节 | 已覆盖 version/exchange/flags/length、SPIi/SPIr、offset 58 |
| C3 | UDP 4500 marker、NAT-D 与端口浮动 | 未覆盖，G-NATT-1；500 例不能推导 4500 |
| C4 | ESP-in-UDP、keepalive、重传 | 未覆盖，G-NATT-1 |
| C5 | 错误处理与 presence/unknown-layer 判死形状 | 当前无负例，G-NATT-1；unknown-layer 锚词为 `unknown layer` |
| C6 | pcap/NIC 双通道与全量实际流程校准 | 文档车道未运行 suite/MCP/NIC，不宣称通过 |

## 13. 修订记录

- v1.1.0（2026-09-30）：迁移唯一 case 至严格层链；补齐测试点清单、三源回指、强度、扩展计划、存量审计与性能缺口 G-NATT-6；自审 2 轮，末轮干净。
- v1.0.1（2026-09-29）：批次二门1补齐形状基线、缺口三要素、产物过期登记与反查红项；自审 2 轮、末轮干净。
- v1.0.0（2026-09-29）：按现有 `ike_nat_t.json` 建立 as-built 用例契约。

# IKE-NAT-T 测试用例契约

> 版本：v1.0.1（as-built，批次二门1补齐）；日期：2026-09-29；权威 JSON：`trafficgen/test/protocol_pcap/cases/ike_nat_t.json`；实现仅对现有 case 负责。
> 配套设计：`142-ike_nat_t-design.md` v1.0.1。
> 白话一句：**现网只有一条检查：UDP 500 上的 IKEv2 SA_INIT 空载荷头；它不触发 4500 marker，所以 NAT 穿透扩展本身还没有测试证据。**

## 1. 测试原则和形状基线

JSON 是唯一 ID、顺序、包数、字段、frame 锚点权威。本套件 1 正、0 负。**机读形状**：唯一 `spec_json` 顶层键 = `{count,dst_port,ike_nat_t}`，无 `layers`（扁平残留 G-NATT-3）；本文不把 `udp,ike_nat_t` 目标形状写成存量事实。case 显式 dst=500，因此不应出现 Non-ESP Marker；marker 只在实际 dst=4500 的实现分支验证。pcap/NIC 共用本 cases 断言；历史结果文档与 pcap 留档过期/缺失，见 §8/G-NATT-2。动态 SPI 只断言 nonzero/zero，不固定随机值。

## 2. 原子用例索引

|#|ID|类型|依据链|包数|
|---:|---|---|---|---:|
|1|`ike_nat_t_sa_init_header_only`|正|RFC 7296 §3.1；RFC 3948 端口边界；design §2-3|至少 1|

## 3. 正例逐项断言契约

### 3.1 `ike_nat_t_sa_init_header_only`

配置为 `count=1`、`dst_port=500`、`ike_nat_t.dialog=[{direction:"up",exchange_type:34}]`。packet 1：`udp.dstport=500`；`isakmp.ispi` 非零；`isakmp.rspi=0000000000000000`；`isakmp.version=0x20`；`isakmp.exchangetype=34`；`isakmp.flags=0x08`；`isakmp.length=28`。frame packet 1 offset 58 的稳定字节为 `00 20 22 08 00 00 00 00 00 00 00 1c`。由于目的端口是 500，不能要求 Non-ESP Marker；SPIi 是运行期随机值。

## 4. 负例契约

现有 JSON 没有负例。planner 已覆盖非法方向、exchange、NAT-D 长度、IP、重传参数和缺配置错误，但这些未被此套件的 JSON 驱动，不能报告为已覆盖。

## 5. 覆盖与对账

设计 §7、本文 §2、JSON 数组均只有 `ike_nat_t_sa_init_header_only`，顺序一致；正例 1、负例 0；`min_packets=1`；fields 与 frames 非空。五层反查：功能=SA_INIT；性能=单 UDP；数据=28B header；地址流=dst 500；业务=header-only IKEv2。NAT-D、4500、ESP、keepalive、重传、错误面均明确未覆盖。

## 6. P3 固定动作

执行 JSON parser、ID 唯一性、正负 expect 结构、frame offset/hex 静态检查；运行 layer generator 并用 tshark `isakmp.*` 验证；单流 UDP 不适用 TCP handshake/termination。4500 marker 的 case 应另行新增，不能从本例推导。

## 7. 实现后执行建议

确认 dst=500 时 payload 直接从 IKE header 开始；确认 rspi 8B 全零；确认 SPIi 仅 nonzero；确认 version/exchange/flags/length 和 frame 稳定字节；失败必须传播 task error，不以空结果代替。

## 8. 存量审计与产物核验

|现存 ID|去向|原因|
|---|---|---|
|`ike_nat_t_sa_init_header_only`|保留|唯一权威 case，验证最小 IKEv2 NAT-T planner header 形状及 500 端口 marker 边界。|

无作废或改写 ID。**存量层链形缺口**：`spec_json` 顶层 `{count,dst_port,ike_nat_t}`，不是纯层链 `{layers}`（G-NATT-3）。

**G-NATT-2 产物核验**：tracked `trafficgen/docs/protocol-pcap-test/ike_nat_t.md` 末次提交 `e7e7d1c`（2026-08-27）早于 `0417be5`（2026-09-13）；`trafficgen/docs/protocol-pcap-test/ike_nat_t/` 不存在、无 pcap。其 “pass 1” 未经 2026-09-29 今日复跑证实。

## 9. 缺口登记（三要素）

|ID|现象|证据|归属阶段|
|---|---|---|---|
|G-NATT-1|NAT-D/4500 marker/ESP/keepalive/重传和全部负例无 case|JSON 仅 1 条 header-only 例|P3/P4 用例扩展|
|G-NATT-2|结果产物过期且无 pcap 留档，历史 pass 数未经今日复跑证实|`e7e7d1c` 2026-08-27 < `0417be5` 2026-09-13；目录不存在|P5 重跑并重生成产物|
|G-NATT-3|存量 `spec_json` 为扁平 `{count,dst_port,ike_nat_t}`，层链门不通过|机读 `cases/ike_nat_t.json`，无 `layers`|P4 cases 迁移|
|G-NATT-4|`CheckProtoFlat` 未登记 ike_nat_t，presence 负例会假绿|strategy_convert.go 无该分支|P6 框架面|
|G-NATT-5|dynamic allowlist 无 ike_nat_t 业务字段行|layer_dyn.go 无命中|P6 框架面|

## 10. 覆盖反查门建议断言行

|#|可静态机读断言|状态|
|---:|---|---|
|1|ID 恰为 `ike_nat_t_sa_init_header_only`，顺序 1|绿|
|2|正例=1、负例=0、`min_packets=1`|绿|
|3|dstport=500、SPIi nonzero、SPIr exact zero|绿|
|4|version=0x20、exchange=34、flags=0x08、length=28|绿|
|5|frame offset=58，hex 精确匹配|绿|
|6|顶层键 ⊆ `{layers}`|红：今日为 `{count,dst_port,ike_nat_t}`，G-NATT-3|
|7|负例锚词集合非空|红：0 负例，G-NATT-1|

pcap/NIC 两路必须复用同一断言集，不能用过期结果产物代替复跑。

## 11. 修订记录

- v1.0.1（2026-09-29）：批次二门1补齐形状基线、缺口三要素、产物过期登记与反查红项；**自审 2 轮，末轮干净**。
- v1.0.0（2026-09-29）：按现有 `ike_nat_t.json` 建立 as-built 用例契约。

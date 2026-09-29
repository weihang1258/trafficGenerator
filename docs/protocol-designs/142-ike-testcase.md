# IKE 测试用例契约

> 版本：v1.0.1（as-built，批次二门1补齐）；日期：2026-09-29；权威 JSON：`trafficgen/test/protocol_pcap/cases/ike.json`；实现只覆盖该 JSON 的现存形状。
> 配套设计：`143-ike-design.md` v1.0.1。
> 白话一句：**现网只有一条检查：空配置下 IKEv2 四包标准握手（SA_INIT 一对 + IKE_AUTH 一对）发得对不对；一条负例都没有——胡来能不能被拦下，今天没有证据。**

## 1. 测试原则和形状基线

JSON 是 ID、顺序、包数、断言和锚词唯一权威；本套件 1 正、0 负。**机读形状实测**：`spec_json` 顶层键恰为 `{src_port, ike}`，不存在 `layers`（扁平残留，G-IKE-3）；故本文不把 `udp,ike` 目标层链写成存量事实。pcap/NIC 两路共用该 cases 契约；旧结果文档及 pcap 留档过期/缺失，见 §8/G-IKE-2，未将其 pass 数申报为今日复跑。动态 SPI、Nonce、KE 等运行期值不固化。

## 2. 原子用例索引

|#|ID|类型|依据链|包数|断言|
|---:|---|---|---|---:|---|
|1|`ike_smoke_01`|正|RFC 7296 §1.2/§3.1；design §2-3|4|UDP dst 500；v2=2.0；SA_INIT=34、AUTH=35；initiator=0x08/responder=0x20；长度 376/225。|

## 3. 正例逐项断言契约

### 3.1 `ike_smoke_01`（4 包）

配置是 `src_port=12345`、`ike={}`；默认 scenario 为 `standard_v2`。四个 UDP datagram 按 SA_INIT request、SA_INIT response、IKE_AUTH request、IKE_AUTH response 排列。

- packet 1：`udp.dstport=500`、`isakmp.mjver=0x02`、`isakmp.mnver=0x00`、`isakmp.exchangetype=34`、`isakmp.flags=0x08`、`isakmp.length=376`。
- packet 2：`isakmp.exchangetype=34`、`isakmp.flags=0x20`。
- packet 3：`isakmp.exchangetype=35`、`isakmp.flags=0x08`、`isakmp.length=225`。
- packet 4：`isakmp.exchangetype=35`、`isakmp.flags=0x20`、`isakmp.length=225`。
- SPI/Nonce/KE 等运行期值不固定；notes 指定的动态 SPI 仅作存在性理解，不能增写固定值。

## 4. 负例契约

当前 cases JSON 没有负例。实现 validator 已拒绝缺少 IKE、非法地址/端口、未知 scenario、冲突配置和坏 payload；这些路径属于待补用例而不是本套件已通过覆盖。

## 5. 覆盖与对账

机读核验结果：JSON ID 数组恰为 [`ike_smoke_01`]；正例 1、负例 0；唯一 `packet_count=4`；正例 fields 非空且与 §3 一致；负例覆盖数为 0（**非错误通过**）。五层反查：功能=四消息 exchange/flags；性能=4 个 UDP datagram；数据=header length 376/225；地址流=dst 500/src 12345；业务=`standard_v2` SA_INIT/AUTH。NAT-T、TCP、ESP、真实加密、IPv6/VLAN 和负例均明确未覆盖；这些是 G-IKE-1，不从 1 条 smoke 推导。

**存量审计结论**：唯一用例保留；无作废。三件套的 ID/场景/包数/断言一致；层链形状不一致是迁移缺口 G-IKE-3，而非文档静默修正。

## 6. P3 固定动作

执行 JSON 解析、ID 唯一性/顺序、packet_count 与正负 expect 结构检查；运行 `ike` planner/layer generator 的 PCAP probe；用 tshark 实际字段名验证 `isakmp.*`。本协议为 UDP 单流，不适用 TCP handshake/termination；ESP 与 fragmented IKE 分支需独立 case。

## 7. 实现后执行建议

使用固定 `src_port=12345`，避免源端口 500；确认 packet 1/3 为 initiator、2/4 为 responder；确认 376/225 长度与 header offset；不要将随机 SPI、Nonce、KE 当作固定字节断言。失败必须传播为 task error，不能 0 包假绿。

## 8. 存量审计与产物核验

|现存 ID|去向|原因|
|---|---|---|
|`ike_smoke_01`|保留|唯一权威 case，覆盖默认 standard_v2 四包基础链；不新增虚构断言。|

无作废或改写 ID。**存量形状必须另列缺口**：`spec_json` 顶层 `{src_port, ike}`，不是纯层链 `{layers}`（G-IKE-3）；不得因文档目标形状而改写 JSON。

**结果产物过期登记 G-IKE-2**：tracked `trafficgen/docs/protocol-pcap-test/ike.md` 末次提交 `e7e7d1c`（2026-08-27）早于判死提交 `0417be5`（2026-09-13）；`trafficgen/docs/protocol-pcap-test/ike/` 目录不存在、无 pcap。文件中的 “Cases: 1 — pass 1” 未经 2026-09-29 今日复跑证实，本文不引用为通过证据。

## 9. 缺口登记（三要素）

|ID|现象|证据|归属阶段|
|---|---|---|---|
|G-IKE-1|只有 1 条正例，所有错误分支、高级场景、地址族/载体/数据面未被原子用例驱动|`cases/ike.json` 1/0；实现 validator/planner 分支见设计 §7/§10|P3/P4 用例扩展|
|G-IKE-2|结果产物 `ike.md` 过期且无 pcap 留档，历史 pass 数未经今日复跑证实|`e7e7d1c` 2026-08-27 < `0417be5` 2026-09-13；`protocol-pcap-test/ike/` 不存在|P5 重跑并重生成产物|
|G-IKE-3|存量 `spec_json` 为扁平 `{src_port,ike}`，层链门不通过|机读 `cases/ike.json`，无 `layers`|P4 cases 迁移|
|G-IKE-4|`CheckProtoFlat` 未登记 ike presence，建立 presence 负例会假绿|`strategy_convert.go` 对 `protocol == "ike"` grep 0 命中|P6 框架面|
|G-IKE-5|`layer_dyn.go` 无 ike 业务字段动态 allowlist，动态业务字段不可用|文件头 grep 无 ike 行|P6 框架面|

## 10. 覆盖反查门建议断言行

|#|可静态机读断言|状态|
|---:|---|---|
|1|ID 集合恰为 [`ike_smoke_01`] 且顺序一致|绿|
|2|正例=1、负例=0、唯一 `packet_count=4`|绿|
|3|packet 1/2 exchange=34，packet 3/4 exchange=35；flags `[0x08,0x20,0x08,0x20]`|绿|
|4|lengths packet 1=376、packet 3/4=225|绿|
|5|packet 1 dstport=500、mjver=0x02、mnver=0x00|绿|
|6|`spec_json` 顶层键 ⊆ `{layers}`|**红：今日存量 `{src_port,ike}`，G-IKE-3；不得申报已过**|
|7|负例锚词集合非空且每个错误分支至少一例|**红：0 负例，G-IKE-1**|

pcap/NIC 反查必须复用同一字段与 frame 断言集，不能因历史结果文档写 pass 而跳过实际复跑。

## 11. 修订记录

- v1.0.1（2026-09-29）：批次二门1补齐——存量形状与反查建议机读化、缺口三要素补齐（G-IKE-3/4/5）、产物过期登记 G-IKE-2（含 0-pcap 留档缺失）、§9 建议 7 行含红项如实标红；**自审 2 轮，末轮干净**。
- v1.0.0（2026-09-29）：按现有 `ike.json` 建立 as-built 用例契约。

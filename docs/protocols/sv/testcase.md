# SV 测试用例契约（文档轨）

> 版本：v1.1.0（2026-09-30）
> 机器契约：`trafficgen/test/protocol_pcap/cases/sv.json`。
> 配套设计：`docs/protocols/sv/design.md`（D1–D8）。本轮只审文档与 JSON 形状，不宣称重新运行 suite/NIC。
> 规范依据：IEC 61850-9-2、IEC 61850-8-1 Annex A、IEEE 802.1Q、ASN.1 BER；代码/pcap 是现状证据。

## T1 形状、层链和执行边界

SV 是 L2 终结协议，所有正常链严格为 `[eth, sv]`，不含 IP/transport；VLAN 是 SV/eth 生成路径的字段，不是 IP 载体。每条用例的 `spec_json` 是可直接提交的策略配置；流数量使用 case 顶层 `strategy_fc`。当前 `sv.count` 仍是层内单流帧预算，迁移缺口见 T6/C2，不把它解释为 flows。

机读审计（JSON 当前事实）：30 例，17 正、13 负；30/30 有 `spec_json.layers`；17/17 正例顶层仅有框架键；`sv_vn_presence` 的顶层 `sv:{}` 是故意 presence 负例；`sv_vn_static_copy` 的 `strategy_fc` 是故意静态复制负例。唯一非法 carrier 是 `sv_neg_ip_carrier` 的 `[ip,sv]`。

正例通过后须观察实际 PCAP：包数、`eth.type=0x88ba`、SV 字段、VLAN 字段、raw offset/hex，并确认 `frame.protocols` 无 `ip`。NIC 验收复用同一 JSON 字段与 raw 契约；本版 NIC 未运行。

## T2 原子 ID、顺序与包数

顺序以 JSON 为权威。正例 17 条、负例 13 条：

| # | ID | 类型 | 主要行为/实测数量 |
|---:|---|---|---:|
| 1 | `sv_smp_seq` | 正 | 基础 9-2LE，3 帧 |
| 2 | `sv_double_send` | 正 | 双发 6 帧，smpCnt 0,0,1,1,2,2 |
| 3 | `sv_smp_wrap` | 正 | 回绕 6 帧，0,1,2,3,0,1 |
| 4 | `sv_neg_wrap` | 负 | samples_per_cycle=0 |
| 5 | `sv_smp_synch_global` | 正 | smpSynch=2，4 帧 |
| 6 | `sv_neg_smp_synch` | 负 | smpSynch=5 |
| 7 | `sv_4i4v` | 正 | 4I+4V，至少 1 帧 |
| 8 | `sv_custom_dataset` | 正 | int32+float32，无 smpRate |
| 9 | `sv_vlan` | 正 | VLAN 100/priority 4 |
| 10 | `sv_period` | 正 | 250us 周期，至少 100 帧 |
| 11 | `sv_neg_confrev` | 负 | conf_rev=0 |
| 12 | `sv_neg_appid` | 负 | APPID 保留段 |
| 13 | `sv_vn_presence` | 负 | 顶层 `sv` presence |
| 14 | `sv_vn_static_copy` | 负 | static MAC + flows=2 |
| 15 | `sv_vn_empty_layer` | 负 | 空 sv 层 |
| 16 | `sv_neg_ip_carrier` | 负 | IP carrier |
| 17 | `sv_neg_vlan` | 负 | vlan_id=4096 |
| 18 | `sv_smp_synch_0` | 正 | smpSynch=0，APPID 0x7fff |
| 19 | `sv_smp_synch_1` | 正 | smpSynch=1 |
| 20 | `sv_neg_svid_255` | 负 | svID 超 255B |
| 21 | `sv_neg_no_data` | 负 | data 缺失 |
| 22 | `sv_neg_type` | 负 | int64 |
| 23 | `sv_neg_zero_appid` | 负 | APPID=0 |
| 24 | `sv_int32_neg` | 正 | int32 -1 raw bytes |
| 25 | `sv_float32` | 正 | float32 1.5 raw bytes |
| 26 | `sv_mac_dyn_inc` | 正 | MAC inc 回绕，3 流 |
| 27 | `sv_mac_dyn_list` | 正 | MAC list，2 流 |
| 28 | `sv_mac_dyn_rand` | 正 | MAC rand seed=7，2 流 |
| 29 | `sv_combo_vlan_double` | 正 | VLAN + double_send，4 帧 |
| 30 | `sv_combo_rate_dataset` | 正 | datSet + smpRate + 混合数据 |

正例的 `packet_count` 是当前静态/单流帧预算；多流例由 strategy flow control 展开。负例不写成功包数，必须失败并携带 T4 锚词。

## T3 正例断言契约

公共最低断言：正例须断言 `eth.type=0x88ba` 或等价 raw 字节；SV 头 APPID/Length/Reserve；svID、smpCnt、confRev、smpSynch、seqData 中适用字段；无 VLAN 时确认无 IP。`sv_smp_seq` raw 关键点为 APPID `40 00`、Length `00 70`、`svID` tag `80 0a`、smpCnt tag `82`、confRev tag `83`、smpSynch tag `85`、smpRate tag `86`、seqData tag `87`。VLAN 用例 raw `81 00 80 64 88 ba`；float32 raw `3f c0 00 00`；负 int32 raw `ff ff ff ff`。

逐格要求：

- 基线/回绕/双发：断言逐帧 smpCnt，不只断言字段存在；双发还断言相邻帧内容相同。
- 数据布局：4I+4V 断言 seqData 64B、质量值和端序；自定义集断言 2 通道长度、可选 smpRate 缺席；combo 断言 datSet 与混合类型。
- 枚举：smpSynch=0、1、2 分别有独立正例；APPID 上边界 0x7fff 有正例，保留段/零值为负例。
- VLAN/周期：VLAN ID/priority 与 TCI 同时断言；period 用时间戳单调性和容差（若 harness 不暴露时间字段，包数断言只能算降级证据）。
- 动态整格：MAC inc 回绕、list 轮转、rand seed 可复现逐一断言；静态复制必须是负例，不得用重复 MAC 的正例冒充 flows。

## T4 负例与错误传播

所有负例 `expect` 必须严格包含 `expect_error` 和 `error_contains` 两键；不能 completed/0 packet 假成功。当前锚词：

| ID | 故障 | 锚词 |
|---|---|---|
| `sv_neg_wrap` | samples_per_cycle<1 | `sv samples_per_cycle must be >= 1` |
| `sv_neg_smp_synch` | 非法同步值 | `sv smpSynch must be 0, 1 or 2` |
| `sv_neg_confrev` | confRev=0 | `sv confRev must be non-zero` |
| `sv_neg_appid` / `sv_neg_zero_appid` / `sv_vn_empty_layer` | APPID 不在 SV 区间 | `sv appid` |
| `sv_vn_presence` | 顶层协议映射 | `top-level sv sub-config` |
| `sv_vn_static_copy` | 静态复制 | `static four-tuple` |
| `sv_neg_ip_carrier` | L2 协议带 IP/transport | `must not have an ip/transport carrier` |
| `sv_neg_vlan` | VLAN ID 越界 | `out of range [0,4095]` |
| `sv_neg_svid_255` | svID 超长 | `sv svID is required and must be <=255 bytes` |
| `sv_neg_no_data` | data 缺失 | `sv data is required` |
| `sv_neg_type` | int64 不支持 | `sv data type "int64" unsupported` |

每例只有一个故障注入。presence 负例的形状是“层链 + 顶层空 `sv` 映射并存”，空 map 也必须拒绝；这不是允许的顶层字段。

## T5 覆盖审计与来源

| 审计项 | 当前结论 |
|---|---|
| ID/顺序 | 30，按 JSON 顺序，已逐项列出 |
| 正/负 | 17/13 |
| 层链 | 正例 `[eth,sv]`；唯一 carrier 负例 `[ip,sv]` |
| 顶层旧键 | 正例 0；presence 负例保留判死键；无顶层地址/端口/count |
| 业务动态 | MAC inc/list/rand 三格；SV 业务动态未实现，见 T6/C3 |
| 负例断言 | 13/13 有失败标志和锚词；禁止仅断言“没报错” |
| JSON 解析 | `python3 -m json.tool trafficgen/test/protocol_pcap/cases/sv.json` |
| 真实输出 | 历史 `docs/protocol-pcap-test/sv.md` 记载 30/30；本轮未重新跑，不能当本轮证据 |

规范要求面：BER 字段/端序/长度、APPID 区间、smpCnt 回绕、smpSynch 三值、9-2LE 4I+4V、可选字段、VLAN、L2 carrier 和错误分支均有对应 ID；多会话/多事务/多流关联对 SV 不适用，因为每帧是独立周期发布，不存在控制会话或关联数据流。性能六类和 NIC 是未执行的验收面，不由单包用例代替。

## T6 缺口与执行计划

| 缺口 | 证据 | 后续 |
|---|---|---|
| C1 | cases/harness 不能注入 Length/APDU/seqData 坏帧 | 增加 wire-fault 输入和 task-error 负例 |
| C2 | `count` 仍在 SV 层，flows 另走 strategy_fc | 先补 frame-budget/flow-control 语义，再迁移并全量校准包数 |
| C3 | 业务字段没有五类动态策略整格 | 明确字段与序号算法，补 fixed/inc/rand/list/pattern；当前仅 MAC 三格 |
| C4 | 多 ASDU/refrTm/smpMod/gmIdentity 无消费者 | 先补 schema/编码/校验，再补用例矩阵 |
| C5 | 本轮未运行 full suite/NIC | 服务器与 HEAD 同代后跑 30 例全量，再 tcpdump 复验 |
| C6 | 无 SV 性能基线 | 按设计 D7 测基线、目标规模、压力、长跑、交错、背压 |

回归顺序：先 `python3 -m json.tool`，再真实 MCP 创建/生成 PCAP，逐字段 tshark/raw 校对；负例先确认 task error，再确认无成功输出；最后授权 NIC 过滤 0x88ba/组播 MAC。未执行的步骤保持“待运行”，不改写成已通过。

## 测试自审

自审两轮：第一轮核对 T1–T6、30 个 ID、17/13 正负计数、严格 `[eth,sv]` 和负例锚词；第二轮复核包数、BER tags、VLAN/raw 字节、count/flows 边界与未运行声明。最后一轮干净。

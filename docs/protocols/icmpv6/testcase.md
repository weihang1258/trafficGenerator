# #126 ICMPv6（RFC 4443 Echo）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨，as-built）  
> 日期：2026-09-29  
> 配套设计：`docs/protocols/icmpv6/design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/icmpv6.json`（11 例，ID/顺序/包数/断言机读对账一致）

## 1. 测试原则和形状基线

- 用例从设计 §1–§6 派生，共 **11 个唯一语义 ID：5 正 + 6 负**。一例一测试点；综合冒烟仅作集成检查。
- 形状基线（机读实测）：11 例 `spec_json` 顶层键集合为 `{layers}` ×9、`{layers,icmpv6}` ×1（负例 #2 故意注入）、`{layers,group_id}` ×1（#11）；另有 2 条 cases 条目兄弟键 `strategy_fc`（#3、#11），它不属于 `spec_json`。层形一律 `[ip,icmpv6]`。6 个负例 `expect` 严格只有 `{expect_error,error_contains}`，无成功包结构断言。
- 断言通道：`icmpv6.type/code`、`icmpv6.echo.identifier/sequence_number`、`ipv6.src/dst/hlim`、`data.data`（tshark 紧凑 hex，实测无冒号）。cases 保留字段级契约；本轮未重跑 PCAP/NIC，不能把历史 smoke notes 的 checksum good=1 当作本轮证据。
- 输出契约：pcap 与 NIC 双输出共用同一 cases 断言集；负例仅失败校验，不产生成功 PCAP。
- 动态字段断言用具体包位序列（#11 的 4 包 `ipv6.src` 序列），配合固定 `group_id` 保证 worker FIFO 确定序。

## 2. 原子用例索引（11 ID = 5 正 + 6 负，顺序为权威）

| # | ID | 类型 | 场景 | 依据链 | 包数 |
|---:|---|---|---|---|---:|
| 1 | `icmpv6_smoke_01` | 正 | 缺省 ping：128→自动 129，id/seq=1 | RFC 4443 §4.1；设计 §2/§3 | 2 |
| 2 | `icmpv6_vn_presence` | 负 | 顶层 `icmpv6:{}` presence 判死 | 设计 §1.2；`CheckProtoFlat` | — |
| 3 | `icmpv6_vn_static_copy` | 负 | 静态 v6 地址 + `flows=2` 拒绝 | 设计 §4；static four-tuple 门 | — |
| 4 | `icmpv6_neg_v4` | 负 | v4 地址经链拒绝 | RFC 4443；设计 §4 | — |
| 5 | `icmpv6_neg_type` | 负 | `type=130` 非法 | RFC 4443 §4.1；设计 §4 | — |
| 6 | `icmpv6_neg_code` | 负 | `code=1` 非 0 | RFC 4443 §4.1/§4.2；设计 §4 | — |
| 7 | `icmpv6_neg_pattern_step` | 负 | pattern step `type=0` 非法 | 设计 §4；validator 分支 | — |
| 8 | `icmpv6_type_129` | 正 | 129 单发无回包；id=7/seq=9/probe | RFC 4443 §4.2；设计 §3.2 | 1 |
| 9 | `icmpv6_pattern_mixed` | 正 | 混型步 128+129 → 3 包；id 回退 | 设计 §3.2/§6 | 3 |
| 10 | `icmpv6_pattern_data` | 正 | 双 128 步多变 data → 4 包 | 设计 §3.2/§6 | 4 |
| 11 | `icmpv6_ip_dyn_multi` | 正 | `ip.src` inc + `flows=2` → 4 包逐流源异 | 设计 §6；3.14 逃生口 | 4 |

## 3. 正例断言契约

### 3.1 `icmpv6_smoke_01`（2 包）

包 1：`icmpv6.type=128`、`code=0`、`echo.identifier=0x0001`、`echo.sequence_number=1`、`ipv6.src=2001:db8::1`、`ipv6.dst=2001:db8::2`、`ipv6.hlim=64`。包 2：type=129、code=0、id/seq 镜像 1、`ipv6.src=2001:db8::2`、`ipv6.dst=2001:db8::1`（地址换向直接证据）。缺省 data `ping` 由实现测试覆盖，cases 未断言 data 通道。

### 3.2 `icmpv6_type_129`（1 包）

type=129、code=0、`echo.identifier=0x0007`、`echo.sequence_number=9`、`ipv6.src=2001:db8::1`、`ipv6.dst=2001:db8::2`、`data.data=70726f6265`（`probe`）。id=0x0007 ≠ seq=9 证明非 0 回退路径；无回包即 packet_count=1。

### 3.3 `icmpv6_pattern_mixed`（3 包）

步序 [128(seq1), 129(seq2)]：包 1 type=128/seq=1/id=0x0001；包 2 type=129/seq=1/id=0x0001（128 步自动回包镜像）；包 3 type=129/seq=2/id=0x0002（129 步单发）。identifier 缺省 0 → 回退 sequence（包 3 id=0x0002 是回退算法直接证据）。

### 3.4 `icmpv6_pattern_data`（4 包）

步序 [128(seq1,aa), 128(seq2,bb)] → [128/1, 129/1, 128/2, 129/2]；`data.data` 逐字节 `6161`、`6161`、`6262`、`6262`（请求与回包共享 step data）。

### 3.5 `icmpv6_ip_dyn_multi`（4 包）

`ip.src` inc `2001:db8::1..2` step1、dst 固定 `2001:db8::9`、flows=2、`group_id` 固定。`ipv6.src` 逐包 `2001:db8::1`、`2001:db8::9`、`2001:db8::2`、`2001:db8::9`：流 1 request(::1)/reply(src=dst ::9)，流 2 同形（::2）。

## 4. 负例契约

| ID | 故障注入 | `error_contains` |
|---|---|---|
| `icmpv6_vn_presence` | 顶层 `icmpv6:{}`（层链并存） | `top-level icmpv6 sub-config` |
| `icmpv6_vn_static_copy` | 层内静态 v6 地址 + `strategy_fc {flows:2}` | `static four-tuple` |
| `icmpv6_neg_v4` | 层内 `10.0.0.1/10.0.0.2` | `must be IPv6` |
| `icmpv6_neg_type` | 层内 `type=130` | `icmpv6 type must be 128 (Echo Request) or 129 (Echo Reply), got 130` |
| `icmpv6_neg_code` | 层内 `code=1` | `icmpv6 code must be 0 for Echo, got 1` |
| `icmpv6_neg_pattern_step` | pattern step `type=0` | `icmpv6 pattern step 1 type must be 128 or 129, got 0` |

负例原子性：每例单故障；expect 严格只有 `{expect_error,error_contains}`，无成功包结构断言。

## 5. 五层覆盖对账

- 功能：缺省 ping、单发、pattern 混型、多变 data、5 类拒绝门（#1/8/9/10/2–7）。
- 性能：包数 1/2/3/4 精确计数；动态两流展开（#11）；协议级速率/分片/保活不适用（设计 §5/§7）。
- 数据：data 三态（缺省 ping、显式 `probe`、显式 `aa/bb`）、id 回退、id 显式均有 cases 断言；checksum 参考实现由代码测试覆盖，但本轮未重跑 PCAP/NIC，故不宣称当前 tshark checksum 证据。
- 地址与流：v6 静态、v4 拒绝、src 动态 inc、reply 地址/MAC 镜像、flows=2 逐流（#1/4/11）；端口不适用。
- 业务：Echo request/reply 事务链（#1/9/10）；非 Echo 消息显式不适用（设计 §5）。

## 6. 存量用例审计（11/11 逐条）

| ID | 去向 | 说明 |
|---|---|---|
| `icmpv6_smoke_01` | 保留 | D-ICMPV6-1 P5 改写已迁层链形，fields 断言全保留 |
| `icmpv6_vn_presence` | 保留 | presence 门负例，锚词未变 |
| `icmpv6_vn_static_copy` | 保留 | static four-tuple 门负例 |
| `icmpv6_neg_v4` | 保留 | v6 族强制复用 legacy Validate |
| `icmpv6_neg_type` | 保留 | validator type 分支锚词逐字钉死 |
| `icmpv6_neg_code` | 保留 | validator code 分支 |
| `icmpv6_neg_pattern_step` | 保留 | pattern 逐步校验分支 |
| `icmpv6_type_129` | 保留 | id=7/seq=9 显式回显钉死 |
| `icmpv6_pattern_mixed` | 保留 | 3 包混型步 + id 回退证据 |
| `icmpv6_pattern_data` | 保留 | 4 包 data hex 逐字节断言 |
| `icmpv6_ip_dyn_multi` | 保留 | 动态 src + flows=2 唯一多流例 |

无改写、无作废、无新增；cases JSON 即权威，ID 集合/顺序/包数/断言与本文 §2–§4 逐条一致。

## 7. 产物过期核验（不触发登记）

`trafficgen/docs/protocol-pcap-test/icmpv6.md` 虽为 tracked 产物，但本轮未重新核对其生成提交、PCAP 内容或 NIC 输出；因此不把旧结果表当作当前验证证据，也不据此关闭缺口。双输出回归仍登记于设计 §10 的 G-ICMPV6-2，待 P4/MCP 使用同一 cases 契约重跑。

## 8. 覆盖反查门建议断言行（供主线程登记 `coverage_gate.py`；本车道不碰该文件）

每条静态机读（读 cases JSON 即判）：

| # | 断言 | 判定 |
|---|---|---|
| 1 | cases=11 且 ID 集合/顺序 = §2 表 | 相等 |
| 2 | 正例 5 且 packet_count 序列（按 §2 顺序）= [2,1,3,4,4] | 相等 |
| 3 | 负例 6 且 `expect` 严格只有 `{expect_error,error_contains}` | 全称 |
| 4 | 6 个锚词逐字匹配 §4 表 | 全称 |
| 5 | #1 断言含 `ipv6.hlim=64` 与双向 `ipv6.src/dst` | 存在 |
| 6 | #8 `data.data=70726f6265`、`echo.identifier=0x0007` | 存在 |
| 7 | #9 包 3 `identifier=0x0002`（id 回退证据） | 存在 |
| 8 | #10 四包 `data.data` 序列 = [6161,6161,6262,6262] | 相等 |
| 9 | #11 `ipv6.src` 序列 = [::1, ::9, ::2, ::9] 且带 `group_id` | 相等 |
| 10 | 全部正例层形恰为 `[ip,icmpv6]` 且无顶层业务键 | 全称 |

红项如实标红：无今日已过申报；以上为建议断言，登记与执行由主线程完成。

## 9. 附：执行建议

冒烟先行 `icmpv6_smoke_01`；负例按 §4 锚词逐条校验；`icmpv6_ip_dyn_multi` 需固定 `group_id` 保证流序；`data.data` hex 为 tshark 紧凑形（首跑校准口径继承）。

## 10. 层链迁移审计（T1-T6，2026-09-30）

| ID | 测试审计结论 | 证据 |
|---|---|---|
| T1 | 11 条 ID 唯一且 JSON 可解析 | `icmpv6.json` 机读校验 |
| T2 | 5 条正例与动态正例均使用 `[ip,icmpv6]` 严格层链 | 全量 `spec_json.layers` 审计 |
| T3 | 6 条负例保留故意错误输入与精确错误锚词 | `expect_error`/`error_contains` 审计 |
| T4 | IPv6 地址只在 ip 层；ICMPv6 字段只在 icmpv6 层；无端口 | 全量 spec_json 字段审计 |
| T5 | `strategy_fc` 仅作为 cases 用例驱动字段，不混入 `spec_json` | `icmpv6_vn_static_copy`、`icmpv6_ip_dyn_multi` |
| T6 | 迁移未改变协议字段、包数或负例语义 | 对照设计 §2–§4 与 11 条 cases 逐 ID 核对 |

### 10.1 迁移状态与缺口

- 已迁移：11/11 条 cases 均为层链形；5 条正例可作为目标配置形状，6 条负例保留故意违规输入。
- 特殊负例：`icmpv6_vn_presence` 有意保留顶层 `icmpv6:{}`，用于验证 presence 判死，不得清洗。
- 流控：`strategy_fc` 在 cases 条目兄弟键表达 flows，不是协议层字段。
- 缺口：非 Echo 类型与本批未重跑双输出已登记设计 §10 的 G-ICMPV6-1/2；不宣称新增覆盖。

## 11. 六项测试覆盖清单（C1-C6）

| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | JSON 可解析、ID 唯一、11 条清单一致 | 已逐条对账，11/11 |
| C2 | 严格 `[ip,icmpv6]` 层链与地址归属 | 正例全覆盖；presence 负例按设计保留 |
| C3 | Echo Request/Reply、单发 Reply、pattern 编排 | `icmpv6_smoke_01`、`icmpv6_type_129`、`icmpv6_pattern_mixed`/`data` |
| C4 | 动态 IPv6 多流与数据/标识字段断言 | `icmpv6_ip_dyn_multi`、`type_129`、pattern cases |
| C5 | IPv4/type/code/pattern/presence/static-copy 错误处理 | 6 个负例均有锚词，逐条对应设计 §4 |
| C6 | pcap/NIC 双输出全量流程校准 | 本批未重新运行 suite/MCP；旧结果表不作今日复跑声明，待 G-ICMPV6-2 闭环 |

## 12. 修订记录

- 2026-09-29：#126 as-built 用例契约初稿，与 cases JSON 11 例逐条对账。
- 2026-09-30：补齐 T1-T6/C1-C6 层链迁移审计与覆盖清单。
- 2026-10-01：核对路径与 cases 统计：`strategy_fc` 为 #3、#11 两条条目兄弟键；不声称非 Echo 或双输出已实现/验证。

# BGP（边界网关协议 v4）测试用例契约

> 版本：v1.0.0（P1–P3 文档轨产物；#80 bgp）
> 日期：2026-09-26
> 车道：并发管线车道 A（文档轨）
> 配套设计：`docs/protocol-designs/80-bgp-design.md`（D-BGP-1）
> 机器契约：`trafficgen/test/protocol_pcap/cases/bgp.json`（现存 19 例；目标 38 例，P5 落码）
> 旧基线：`docs/protocol-designs/36-bgp-testcase.md`（2026-08-20，10 正 + 9 负；本契约延续 19 ID 全集 + 增 19 A′）
> 状态：**`bgp` 层已注册但事件面进层未接线**（design §1：translate 无 `case "bgp"` + registry 无 `events`/`sessions` 键）——本文 19 存量 ID 的事件面仍走顶层 `bgp` 子映射（P5 改写对象），19 A′ 按目标层链形书写。本文**不宣称本次跑过 suite、不启动服务器**。

## 1. 测试原则与形状基线

用例从设计 §1（证据等级/profile）、§2（层链/事件）、§3（RFC 4271 线格式）、§4（状态机/派生）、§5（端口契约）、§7（错误表）逐项派生。

- 正例必须有 `packet_count`、TCP 握手/正常终止断言；除纯 `connect` 外必须有至少一个 `fields` 或 `frames` observable。
- 负例的 `expect` 严格只有 `expect_error` 与 `error_contains`，不对失败 PCAP 作断言（负例纯净性）。
- 包数公式（无额外 TCP option、每事件一 data segment）：`packet_count = 3 + 应用事件数 + 4`；多会话按每四元组独立计算后求和（`bgp_multi_session` 22 = 11×2；术语"多会话展开"整块回放）。
- IPv4 payload 起点 offset **54**；IPv6 起点 **74**。offset 仅用于未分段帧；MSS 分段走 TCP stream 重组。
- 长度复算（RFC 4271 逐字节，design §3.4）：全属性 UPDATE 总长 66=`00 42`（19+2+0+2+39+4）；withdraw 总长 27=`00 1b`（19+2+4+2+0）；/32 总长 67=`00 43`（19+2+0+2+39+5）。path_attr_len=39 位于 body[21:23]（withdrawn 空时）；withdrawn_len=4 时其后 `00 00` 是 path_attr_len=0（单测 `bgp_test.go:542-560` 字节级守护）。
- 所有正例显式使用 `wire_profile=bgp_rfc4271_ipv4_unicast`。IPv6 transport 仍用 IPv4 NLRI profile，不等于 MP_REACH 支持。

## 2. 原子用例索引（38 ID = 20 正 + 18 负，顺序为权威）

存量 19（T1–T10 + N1–N9，ID 延续旧基线 `bgp_*` 命名）+ A′ 19（`bgp_a_*`）。

| # | ID | 类型 | 覆盖（设计节） | 事件数 | 包数 |
|---|---|---|---|---:|---:|
| 1 | `bgp_connect` | 正 | T-存量：connect 无隐式事件（§4.3④） | 0 | 7 |
| 2 | `bgp_open_keepalive` | 正 | T-存量：双向 OPEN + 双向 KA（§3.2/3.3） | 4 | 11 |
| 3 | `bgp_update_attributes` | 正 | T-存量：全属性 UPDATE（§3.4） | 5 | 12 |
| 4 | `bgp_update_withdraw` | 正 | T-存量：withdraw /24（§3.4） | 5 | 12 |
| 5 | `bgp_notification_hold_expired` | 正 | T-存量：NOTIF 4/0（§3.5） | 3 | 10 |
| 6 | `bgp_hold_time_zero` | 正 | T-存量：hold=0（§3.2/V6） | 4 | 11 |
| 7 | `bgp_ipv4_nlri_32` | 正 | T-存量：/32 边界（§3.4/V16） | 5 | 12 |
| 8 | `bgp_ipv6_transport` | 正 | T-存量：IPv6 外层（§3.8） | 4 | 11 |
| 9 | `bgp_multi_session` | 正 | T-存量：双会话整块（§10.4） | 4×2 | 22 |
| 10 | `bgp_keepalive_length_boundary` | 正 | T-存量：length=19 下界（§3.1） | 4 | 11 |
| 11 | `bgp_a_multi_update_rounds` | 正 A′ | §3.15①：同连接多轮 UPDATE（>2 轮） | 7 | 14 |
| 12 | `bgp_a_update_multi_session` | 正 A′ | 矩阵缺格：多会话 UPDATE 面 | 5+4 | 23 |
| 13 | `bgp_a_origin_egp` | 正 A′ | V9：ORIGIN=1 | 5 | 12 |
| 14 | `bgp_a_origin_incomplete` | 正 A′ | V9：ORIGIN=2 | 5 | 12 |
| 15 | `bgp_a_community_no_advertise` | 正 A′ | V14：NO_ADVERTISE | 5 | 12 |
| 16 | `bgp_a_multi_flow_dynamic` | 正 A′ | §12 动态整格：`flows=3` + 四元组四策略 | 4×3 | 33 |
| 17 | `bgp_a_default_events_nil` | 正 A′ | V19：events 缺省 nil → 默认 6 事件流 | 6 | 13 |
| 18 | `bgp_a_server_abort_rst` | 正 A′ | §3.15②后半：服务端 RST（tcp 层能力，P4 实测） | 4 | —（P4 钉） |
| 19 | `bgp_a_update_combined_withdraw_nlri` | 正 A′ | §4.3 同包双区：withdrawn + 属性 + NLRI 同一 UPDATE | 5 | 12 |
| 20 | `bgp_a_notification_multi_session` | 正 A′ | 矩阵缺格：多会话 NOTIF 面 | 4+3 | 21 |
| 21 | `bgp_neg_udp` | 负 | N-存量：UDP 载体（§7#1） | — | — |
| 22 | `bgp_neg_mp_reach_profile` | 负 | N-存量：未登记 profile（§7#2） | — | — |
| 23 | `bgp_neg_marker` | 负 | N-存量：marker（§7#3） | — | — |
| 24 | `bgp_neg_length` | 负 | N-存量：length（§7#4） | — | — |
| 25 | `bgp_neg_type` | 负 | N-存量：type（§7#5） | — | — |
| 26 | `bgp_neg_version` | 负 | N-存量：version（§7#6） | — | — |
| 27 | `bgp_neg_as` | 负 | N-存量：AS 溢出（§7#7） | — | — |
| 28 | `bgp_neg_state` | 负 | N-存量：OPEN 前 UPDATE（§7#9） | — | — |
| 29 | `bgp_neg_address` | 负 | N-存量：IPv6 NLRI（§7#8） | — | — |
| 30 | `bgp_a_neg_open_after_established` | 负 A′ | 矩阵缺格：应用事件后 OPEN（`state`） | — | — |
| 31 | `bgp_a_neg_notification_not_last` | 负 A′ | 矩阵缺格：NOTIF 非末（`last`） | — | — |
| 32 | `bgp_a_neg_single_open` | 负 A′ | 矩阵缺格：单 OPEN（`exactly two`） | — | — |
| 33 | `bgp_a_neg_keepalive_before_open` | 负 A′ | 矩阵缺格：OPEN 前 KA（`state`） | — | — |
| 34 | `bgp_a_neg_notification_other_code` | 负 A′ | V22：Cease 6（`error_code`） | — | — |
| 35 | `bgp_a_neg_msg_overflow_4096` | 负 A′ | V2：超 4096（`4096`） | — | — |
| 36 | `bgp_a_neg_bad_identifier` | 负 A′ | V7：非法 identifier（`identifier`） | — | — |
| 37 | `bgp_a_neg_bad_nexthop` | 负 A′ | V11：非法 next_hop（`next_hop`） | — | — |
| 38 | `bgp_a_neg_notification_before_open` | 负 A′ | 矩阵缺格：OPEN 前 NOTIF（`state`） | — | — |

## 3. 正例逐项断言契约

T1–T10 延续旧基线（frames hex 与 fields 见 `cases/bgp.json` 实测；包数 `[7,11,12,12,10,11,12,11,22,11]`）。A′ 逐项：

- **#11**：S2 事件 + 3 个 UPDATE（不同 NLRI：`203.0.113.0/24`、`198.51.100.0/24`、`192.0.2.0/24`）；7 事件 → 14 包；packet 8/9/10 `bgp.type=2` + prefix_length 各异；方向全 c2s。
- **#12**：sessions[2]：s0 跑 T3 全属性 UPDATE（5 事件 → 12 包），s1 跑 S2（4 事件 → 11 包）；合计 23 包（P4 以实测 pcap 钉死）；聚合 `tcp.srcport distinct` 断言（9.38：排除 179）。
- **#13/#14**：T3 形，`origin` 改 1/2；packet 8 `bgp.update.path_attribute.origin` = 1/2；frame hex P4 先跑后钉。
- **#15**：T3 形，communities `["NO_ADVERTISE"]`；community 尾 4B = `ff ff ff 02`；hex 先跑后钉。
- **#16**：`flow_control.flows=3` + S2 事件；`ip.src` inc（回绕）/ `ip.dst` rand（seed 可复现）/ `tcp.src_port` list 轮转 / `ip.ttl` pattern——四策略同例（postgresql #46 先例）。断言：`ip.src` 的 `distinct_values` 三值（§9.34①语义发生）、同 seed 跨两次运行 same（§9.34②可复现）、`tcp.srcport` 轮转序；包数 11×3=33（P4 实测钉）。**静态复制面**：未写动态 + 未写死端口时保底 `12345+i`（`worker.go:307-308`）已防四元组全同（§12.9 不触发）；显式写死端口 + `flows>1` 面待 P4 实测（框架级）。
- **#17**：显式缺省 `events`（JSON 无该键）→ 默认 6 事件流（`defaultDualEvents`，`layer_gen.go:85`）；6 事件 → 13 包；packet 4 `bgp.open.version=4`。P4 须先确认链路"缺键透传"语义（层 config 缺键 vs JSON 缺键）。
- **#18**：S2 + tcp 层 `rst=true`（tcp 层 registry 有 `rst` 键，`registry.go:72`；若行为不符按 §9.36 B/C 分类钉现状）。包数 P4 钉。
- **#19**：S2 + 1 个 UPDATE 同时带 `withdrawn_prefixes=["198.51.100.0/24"]` + 全属性 + `nlri=["203.0.113.0/24"]`（RFC 4271 §4.3 允许双区同包；存量 T3/T4 均为单区）；5 事件 → 12 包；packet 8 `withdrawn_routes.length=4` + `path_attributes.length=39` + `prefix_length=24`；hex 先跑后钉。
- **#20**：sessions[2]：s0 跑 T5（3 事件→10 包），s1 跑 S2（4 事件→11 包）；合计 21 包；聚合端口断言。

## 4. 负例契约

存量 N1–N9（`error_contains`：`tcp`/`profile`/`marker`/`length`/`type`/`version`/`as`/`state`/`address`）全部延续。A′ 负例：

| ID | 输入 | `error_contains` |
|---|---|---|
| `bgp_a_neg_open_after_established` | S2 后再一 OPEN | `state`（`planner.go:81-83` "open after application events started"） |
| `bgp_a_neg_notification_not_last` | NOTIF 后再 KA | `last`（`planner.go:97` "must be the last"） |
| `bgp_a_neg_single_open` | 单 c2s OPEN | `exactly two`（`planner.go:105`） |
| `bgp_a_neg_keepalive_before_open` | 首事件 KA | `state`（`planner.go:89`） |
| `bgp_a_neg_notification_other_code` | `notification error_code=6` | `error_code`（`builder.go:509`） |
| `bgp_a_neg_msg_overflow_4096` | 850 个 /32 NLRI | `4096`（`builder.go:383`；单测 `:528-540`） |
| `bgp_a_neg_notification_before_open` | 首事件为 NOTIFICATION(4/0) | `state`（`planner.go:93` "notification before OPEN"） |
| `bgp_a_neg_bad_identifier` | `identifier="2001:db8::1"` | `identifier`（`builder.go:119-121`） |
| `bgp_a_neg_bad_nexthop` | `next_hop="2001:db8::1"` | `next_hop`（`builder.go:191-193`） |
| 缺：`prefix length 0`（`bgp_test.go` 无 pcap 例 → 若补例锚词待 P4 实测，现状立项无 ID） | — | — |
| 缺：`extended-length`（单测 `:514-526`；pcap 立项无 ID，锚词 `extended-length` 已知） | — | — |

`wire_fault` 是测试注入入口，不是合法线上字段；不得把损坏的 marker/length/type 生成为"成功"PCAP。MP_REACH、能力协商、4-octet ASN 均以新 profile 承载，不放宽存量负例。

## 5. 三源回指行与 9.52 对账

### 5.1 三源回指（§9.2–9.4）

- ①RFC/官方文档：RFC 4271 §4（头/OPEN/UPDATE/NOTIF/KA）/ §5（六属性）/ §6（错误码）/ §8（FSM）/ §9（UPDATE 收发）+ RFC 2545（传输）+ RFC 4760/5492/6793（B′边界）——设计 §3 逐表列节号。
- ②`docs/CODE_DESIGN.md` 对应条目：D-BGP-1（设计 §11，门1 获批 = 定稿）。
- ③已确认现网行为：Cisco hold 180/ka 60、JunOS hold 90/ka 30、FRR OPEN 能力（设计 §10.5，可判字节面已用 T2/T6 90/0 两档；协商过程 N/A 未冒充）。
- ID 权威 = 本文件 §2（38 ID）。

### 5.2 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **规范/官方文档反推**（RFC 4271 §4/§5/§6/§8 全表扫 + dissector 实测通道），**非**引擎能力面反推。引擎侧只作现状取证（builder 9 函数 + planner 状态机 + 单测 560 行 + registry/translate/Meta 链路 + tshark 784 字段）。
- **对账两行**：**规范逻辑行总数 = 70**（矩阵 20 格 + 变体 22 行 + 三路对照 6 + 错误表 14 + 状态机单测分支 8）；**已覆行 = 61**（38 ID 多对多覆盖：矩阵 20 全 + 变体 17 + 三路 3 + 错误 13 + 单测 8；单测 8 的 pcap 面与矩阵/错误 ID 同分支，仅 sessions==1 提升为例外，已在 V18 注记）；**无 ID 缺口行 = 3**（V6、V16、V21；其中 V6 = 错误表 #10 同一 hold 小值隙，不重复计数）；**B′ = 4 行**（V8/V10/C4/C6 → B2/B5/B2/B3）；**不适用 = 1**（C3 定时器协商）。61 + 3 + 4 + 1 = 69 unique 行 + 1 重复隙（V6/#10）= 70 ✓ 无遗漏。**粒度声明**：格/行粒度每点 1 计；G-BGP-5/6/7 配置门缺口中仅 V6/#10 折进 70（它是规范逻辑点），G-BGP-5/6 为配置门缺口不折入。**反查全绿 ≠ 覆盖全**（§9.52 原文）。
- **正交矩阵（§9.51）**：模式（OPEN/KA/UPDATE/NOTIF/空）× 方向（c2s/s2c）× 地址族（v4/v6）× 会话数（1/2）× 异常（正常/9 负类）——逐格能指出用例号（§2 表体为格→ID 映射本身；缺格面 = A′/B′ 格）。
- **9.53 门3 抽查预判**：**最复杂用例 = #11**（`bgp_a_multi_update_rounds`，7 事件 3 轮 UPDATE）；交织维度 = 会话(1)×事务(3)×流(握手+挥手)×异常(正常面)——当前偏弱在"并发交错"面（单会话），**建议门3 抽 #11 + #12**（多会话 UPDATE 补交错面），打回线：低于 9.49/9.50 下限即重做。

## 6. P3 固定动作

### 6.1 §3.15 三项逐项一例或立项（无例无项即缺口）
| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接多轮 UPDATE（S2 + 3 UPDATE） | A′ #11（新例；存量 T3 只有单轮） |
| ② | 非正常结束 | 正常 FIN（全正例 `terminates`）；NOTIF 终结（T5）；N1–N9 负例拒终态（含 N6/N7 非法 OPEN 即拒） | 前半已覆；后半 → A′ #18（RST，tcp 层 `rst` 键已登记，P4 实测行为） |
| ③ | 长保活 | 协议层无 keepalive 定时器语义（design §10.1#6 显式 N/A 面）；长会话 = 同连接多轮（#11 三轮）+ hold 两档字节（T2=90/T6=0）+ 多流并发（#16 `flows=3`） | 已覆 T6 + T10；多轮/多流为 A′ 新例 |

无空项：① 有 A′ 新例；② 有已覆例 + 2 条 A′；③ 有已覆例 + 1 档 A′。

### 6.2 A′/B′ 两分类表（要求面反推：数据 / 业务 / 现网 / 多流 / 地址族 / 断言通道六类）

A′（P4/P5 接线补例 19，§2 #11–#20 + #30–#38）：数据面（V2/V6/V7/V9/V11/V14/V16/V19/V21/V22 → #12–#17/#35–#37 + prefix-0/extended-length 两立项无 ID）/ 业务面（矩阵缺格 → #11/#12/#20/#30–#33/#38；NOTIF 位置 → #31/#34/#38）/ 现网面（hold 90/0 两档已覆 T2/T6；180 默认值不硬编码，设计 §10.5 取舍）/ 多流面（#16 动态整格 + #12/#20 会话面；9.39 互斥声明）/ 地址族面（T8 已覆；v6+多会话组合 → P4 实测后立项）/ 断言通道面（frames hex 先跑后钉 #11/#13–#15）。B′（G-BGP-5/6 配置门除外；design §14 B1–B5）：B1 MP_REACH（RFC 4760）/ B2 能力协商（RFC 5492）/ B3 4-octet ASN（RFC 6793）/ B4 refresh/graceful/auth/MD5 / B5 AS_SET + 扩展长度编码——D 条目"明确不解决 + 迁入计划"。

### 6.3 §3.14 豁免边界审计

**有长连接载体 → `sessions[]` 不豁免**（设计 §12.3 会话表 s1/s2）；多流并发（`flows=N` + T9 整块；9.39 互斥声明）；单包多载荷（UPDATE withdrawn+属性+NLRI 同包：T3/T4 已覆）。三项各有结论，**无豁免逃逸**。`concurrent` 交错面不适用（无该键，设计 §10.4 注记）。

### 6.4 断言契约核对结论（与设计 §3/§3.9/§11 一致）

存量 19 的 fields/frames 字段名（`bgp.type`/`bgp.length`/`bgp.open.*`/`bgp.update.*`/`bgp.notify.*`/`bgp.prefix_length`/`ipv6.version`/`tcp.*port`）全部命中本机 TShark 3.6.14 `bgp.*` 实测字段（§1 字段清单）；hex 金向量与 builder 单测一致（OPEN/UPDATE 全属性/withdraw//32/NOTIF/KA）；包数公式 §1 全中（`[7,11,12,12,10,11,12,11,22,11]` 机读复核）。A′ hex 一律先跑后钉（§9.31/§14.20），不手算。

### 6.5 §9.50 现网复合大场景（≥3 类交织；门3 抽查下限）

**#20 `bgp_a_notification_multi_session`** 为本协议复合大场景：会话(2 整块展开)×事务(t1 建连+t2 保活/通告+t3 异常终结 vs t1+t2)×异常(NOTIF 终结 vs 正常终结)×地址(同 v4 族内双四元组)——4 类交织 ≥3 类下限 ✓。简单冒烟例（T1 connect）不计入现网场景覆盖数。

## 7. 实现后执行建议（P4/P5）

1. G-BGP-5 落码（registry 增键 + translate `case "bgp"` + schemagen 重跑）→ 19 例改写纯层链形（§12.1 去向表）→ G-BGP-6 落码 → 全量 suite（`CASE_PROTO=bgp`）→ 19 A′ 逐例先跑后钉 → 全量复跑（§14.19）。
2. JSON 语法、ID 唯一性、正负 expect 结构、frame hex 长度静态检查先行；顺序：T1 → T2 → T3/T4/T7 → T5 → T8 → T9 → T10 → N1–N9 → A′。
3. pcap 落 `/tmp/mcp-pcaps/bgp/`（14.16）；NIC 用同一契约（enp135s0f0np0）。
4. 取得 RFC 4760/5492/6793 实现 profile 后另增 MP_REACH/能力/4-octet ASN 用例，不修改本套件 IPv4 基础契约。

## 8. 存量用例逐条审计去向（§9.14 / §14.4）

| 存量 ID | 去向 | 说明 |
|---|---|---|
| `bgp_connect` | 合入 T1 | 改写纯层链形（补 `ip` 层，删顶层四元组）；`events: []` 保留 connect-only 语义 |
| `bgp_open_keepalive` | 合入 T2 | 同上；事件面迁入 `bgp` 层 |
| `bgp_update_attributes` | 合入 T3 | 同上 |
| `bgp_update_withdraw` | 合入 T4 | 同上 |
| `bgp_notification_hold_expired` | 合入 T5 | 同上 |
| `bgp_hold_time_zero` | 合入 T6 | 同上 |
| `bgp_ipv4_nlri_32` | 合入 T7 | 同上 |
| `bgp_ipv6_transport` | 合入 T8 | `ip` 层住 IPv6 字面 |
| `bgp_multi_session` | 合入 T9 | sessions 面迁入层；聚合断言按 9.38 复核 |
| `bgp_keepalive_length_boundary` | 合入 T10 | 同 T2 形 |
| `bgp_neg_udp` | 合入 N1 | `[udp,bgp]` 刻意坏配置保留（载体负例） |
| `bgp_neg_mp_reach_profile` | 合入 N2 | 同上改写（顶层四元组进层） |
| `bgp_neg_marker` | 合入 N3 | 同上 |
| `bgp_neg_length` | 合入 N4 | 同上 |
| `bgp_neg_type` | 合入 N5 | 同上 |
| `bgp_neg_version` | 合入 N6 | 同上 |
| `bgp_neg_as` | 合入 N7 | 同上 |
| `bgp_neg_state` | 合入 N8 | 同上 |
| `bgp_neg_address` | 合入 N9 | 同上 |

19/19 有去向：10 合入正例 + 9 合入负例，**0 作废**。事件内死字段：无（`bgp` 事件键 12 个全被消费，design §2.3）。

## 9. 修订记录

- v1.0.0（2026-09-26）：P3 初稿。存量 19 全审计去向；A′ 19（10 正 + 9 负）；9.52 对账（70 = 61覆行+3缺口+4B′+1N/A+1重复隙）；§3.15/A′B′/3.14/门3 预判齐。

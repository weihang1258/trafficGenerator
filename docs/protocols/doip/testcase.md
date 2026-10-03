# DOIP（Diagnostic over IP）测试用例契约

> 版本：v1.1.0（按 CORE_MEMORY 对账 JSON as-built）
> 配套设计：`docs/protocols/doip/design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/doip.json`
> 本次仅做文档与 cases 对账；不跑 suite、不启动服务器。

## 1. 形状基线与三源

DoIP 当前可表达面是 TCP-only 终结层，严格层链为 `[ip,tcp,doip]`；IPv4 与 IPv6 都使用这条链，IPv6 仅以 `layers[].ip.src/dst` 的地址值表达，不另设 `ipv6` 层。地址只住 `ip`，端口只住 `tcp`，业务只住末端 `doip`。唯一动态多流例 `doip_tcp_multiflow_dynamic` 把 `tcp.src_port` 的 `inc` strategy 放在 `layers[].tcp`，并以 case 级 `strategy_fc` 表达两条流，作用是按流生成不同源端口。当前 JSON 的唯一 UDP 负例 `doip_neg_udp_carrier` 专门证明载体拒绝，不是成功配置。

三源回指：规范为 ISO 13400-2:2019（§7、§8.4.1、§9.2.4、§9.3.6、§10.3.2、§10.4.3、§10.4.5、§11.1、§11.2.2）及 ISO 14229-1 UDS 服务/NRC 表；设计为 `design.md` §2–§20；现网/解析器证据为现有 pcap 断言面与 TShark 3.6.14 字段表。真实 OEM 诊断仪包未取得，现网参数仍标 G-DOIP-9，不冒充已确认。

断言只使用 `doip.*`、`ip.proto`/`ipv6.nxt`、`tcp.*`、`frames`。IPv4/TCP DoIP 头起点为 54，IPv6/TCP 为 74。动态值使用 `presence`、`nonzero`、`distinct_values`、`same_as_packet`，不硬编码随机序列。

## 2. JSON 对账总览

| 项 | JSON 实测 |
|---|---:|
| 总例数 | **80** |
| 正例 | **50** |
| 负例 | **30** |
| `[ip,tcp,doip]` | **79** |
| `[ip,udp,doip]` | **1（仅负例）** |
| 非负例顶层键泄漏 | **0** |
| 负例 `expect` 锚词缺失 | **0** |
| 负例混入 `packet_count`/`frames` | **0** |

正例的 `spec_json` 顶层唯一键为 `layers`；唯一动态多流正例 `doip_tcp_multiflow_dynamic` 另带 case 级 `strategy_fc: {"type":"flows","value":2}` 作为流数载体。负例 `doip_neg_presence`、`doip_neg_stray_src_ip`、`doip_neg_stray_count` 保留为 CORE §15.4 的 presence/游离键判死形状，不计为成功配置。动态多流行为的端口策略和流数以 JSON 为准。

## 3. 原子用例索引（80 条，顺序与 JSON 一致）

| # | ID | 类型 | 关键覆盖 |
|---:|---|---|---|
| 1 | `doip_s2_routing_activation` | 正 | 0x0005/0x0006 成功激活 |
| 2 | `doip_s2_variant_oem4b` | 正 | OEM 变长激活 |
| 3 | `doip_s3_diag_uds10` | 正 | UDS 0x10 + Ack |
| 4 | `doip_s4_diag_nack` | 正 | 0x8003 Nack |
| 5 | `doip_s5_alive_check` | 正 | 0x0007 探活 |
| 6 | `doip_s8_generic_nack` | 正 | 0x0000 Generic NACK |
| 7 | `doip_s11_activation_fail` | 负 | 激活拒绝锚词 |
| 8 | `doip_s10_big_transfer` | 正 | 0x34/0x36/0x37 |
| 9 | `doip_alive_response` | 正 | 0x0008 响应 |
| 10 | `doip_ipv6_activation` | 正 | IPv6 激活 |
| 11–18 | `doip_rc_0x01`, `doip_at_0x01`, `doip_la_ffff`, `doip_uds_3e_tester_present`, `doip_rc_0x04`, `doip_rc_0x05`, `doip_rc_0x07`, `doip_rc_0x12` | 混合 | 激活码/地址/TesterPresent/值域 |
| 19–24 | `doip_rc_0x11_confirm`, `doip_at_0xe0`, `doip_at_0x02`, `doip_v1_oem`, `doip_sa_consistent`, `doip_sa_mismatch` | 混合 | 二次确认、版本、SA/TA |
| 25–34 | `doip_uds_27_seed_request`, `doip_uds_27_send_key`, `doip_uds_27_odd_response`, `doip_uds_27_even_response`, `doip_uds_27_even_response_key`, `doip_uds_22_response_sid`, `doip_uds_nrc`, `doip_uds_nrc_0x7f`, `doip_uds_nrc_0x00`, `doip_uds_nrc_0xff` | 混合 | UDS 0x27、0x22、NRC |
| 35–42 | `doip_uds_blockseq_wrap`, `doip_ack_code_0x01`, `doip_nack_0x03`, `doip_nack_0x04`, `doip_nack_0x06`, `doip_nack_0x00`, `doip_nack_0x01`, `doip_nack_0x09` | 混合 | BlockSeq、Ack/Nack 值域 |
| 43–52 | `doip_userdata_empty`, `doip_oem_255b`, `doip_alive_sa_consistent`, `doip_alive_sa_mismatch`, `doip_alive_mid_messages`, `doip_generic_nack_0x00`, `doip_generic_nack_0x02`, `doip_generic_nack_0x03`, `doip_generic_nack_0x04`, `doip_generic_nack_0x05` | 混合 | 空数据、OEM、探活、Generic NACK |
| 53–61 | `doip_pv_0x00`, `doip_pv_0x03`, `doip_pv_0xff`, `doip_la_0x0000`, `doip_ta_0x0000`, `doip_mss_fallback`, `doip_ipv6_alive`, `doip_no_discovery_direct_activation`, `doip_messages_without_activation` | 混合 | 版本、地址、MSS、前置状态 |
| 62–68 | `doip_termination_false`, `doip_sa_zero_boundary`, `doip_ta_ffff_boundary`, `doip_uds_unknown_sid`, `doip_uds_22_subfunction`, `doip_uds_10_nosubfunc_false`, `doip_big_transfer_segmented` | 混合 | 终止开关、边界、UDS 值域、分段 |
| 69–76 | `doip_neg_activation_confirmation_missing`, `doip_neg_presence`, `doip_neg_stray_src_ip`, `doip_neg_stray_count`, `doip_neg_udp_carrier`, `doip_neg_udp_phase_discovery`, `doip_neg_udp_phase_entity_status`, `doip_neg_udp_phase_power_mode` | 负 | 负契约、presence、UDP 拒绝 |
| 77–80 | `doip_tcp_full_flow`, `doip_tcp_multiflow_dynamic`, `doip_tcp_options_nohandshake`, `doip_tcp_diag_uds_read_write_did` | 正 | 端到端、多流、TCP 开关、DID |

> **范围行说明**：上表登记 JSON 实际 80 个 ID 的完整集合与顺序；精确包数与字段断言以 `doip.json` 为唯一机器真相。本次未重排 ID。

## 4. 正例断言契约

正例必须至少有 `packet_count` 和字段或帧断言；JSON 中的包数、字段名、帧偏移和 hex 是权威。覆盖面包括：

- 激活：0x0005/0x0006、ActivationType 0x00/0x01/0xE0、RC 0x10、OEM 0B/4B/255B、V1。
- 诊断：0x8001、0x8002、0x8003；UDS 0x10、0x22、0x27、0x34、0x36、0x37、0x3E；NRC、DID、Key/Seed、BlockSeq 回绕与 MSS 分段。
- 活性与错误：0x0007、0x0008、0x0000 五个合法 NACK 值。
- 地址族与载体：IPv4/TCP 正向面、IPv6/TCP 正向面；UDP 只在负例中验证拒绝。
- 复杂业务：`doip_alive_mid_messages` 验证同一连接多轮诊断中探活位置；`doip_tcp_full_flow` 验证激活、诊断、探活、终止顺序；`doip_tcp_diag_uds_read_write_did` 验证请求/响应 DID 形状。

包数是现有 JSON 断言，不在未跑 suite 时重新手算或宣称校准完成。

## 5. 负例契约

30 个负例均带非空 `error_contains`，且 `expect` 严格只含 `expect_error` 与 `error_contains`，不带成功型 `packet_count` 或 `frames`。锚词族如下：

| 故障族 | 当前 JSON 用例（逐条） | 锚词来源 |
|---|---|---|
| 激活失败/确认缺失 | `doip_s11_activation_fail`, `doip_rc_0x01`, `doip_rc_0x04`, `doip_rc_0x05`, `doip_rc_0x07`, `doip_neg_activation_confirmation_missing` | `layer_gen.go` 激活校验 |
| 激活/版本/值域 | `doip_rc_0x12`, `doip_at_0x02`, `doip_v1_oem`, `doip_ack_code_0x01`, `doip_nack_0x00`, `doip_nack_0x01`, `doip_nack_0x09`, `doip_generic_nack_0x05`, `doip_pv_0x03`, `doip_pv_0xff` | `doip.go` Validate 文案 |
| UDS 值域与形状 | `doip_uds_27_even_response_key`, `doip_uds_nrc_0xff`, `doip_uds_unknown_sid`, `doip_uds_22_subfunction` | `doip.go` UDS 校验文案 |
| 一致性/前置 | `doip_sa_mismatch`, `doip_alive_sa_mismatch`, `doip_messages_without_activation` | SA/TA 与状态前置校验 |
| 层链形状 | `doip_neg_presence`, `doip_neg_stray_src_ip`, `doip_neg_stray_count` | CORE §1.11/§15.4 判死形状 |
| 载体/UDP | `doip_neg_udp_carrier`, `doip_neg_udp_phase_discovery`, `doip_neg_udp_phase_entity_status`, `doip_neg_udp_phase_power_mode` | TCP-only 载体与 UDP 面拒绝 |

逐条对账：以上 6 组共 **30** 个 ID，恰与 JSON 中 `expect_error=true` 的集合一致；每条 `expect` 严格只含 `expect_error`/`error_contains`，且 `error_contains` 非空，不带成功型 `packet_count` 或 `frames`。

“负例真会红”需经 MCP 真实提交验证；本次按用户要求不跑 suite，故只确认 JSON 契约完整，不报告运行结果。

## 6. CORE §3.15 与五件套

| 要求 | 用例/处置 |
|---|---|
| 同连接多轮操作 | `doip_tcp_full_flow`、`doip_alive_mid_messages`、UDS Transfer 例；激活→多轮诊断→探活顺序显式记录 |
| 非正常结束 | 激活拒绝与确认缺失负例；底层 FIN/RST 的精确异常行为属于 TCP 层，未在 DoIP JSON 中伪造覆盖 |
| 长保活 | `doip_s5_alive_check`、`doip_alive_response`、`doip_alive_mid_messages` |
| 会话表 | 每个 TCP 流一个独立连接；`doip_tcp_multiflow_dynamic` 登记多流面，动态值不硬编码 |
| 事务序列 | 激活前置；每条诊断消息后按配置生成 Ack/Nack；探活按消息序插入 |
| 关联关系 | DoIP 无独立控制/数据流，0x36 仍在同一 TCP 连接；不伪造 `driven_by` |
| 插入位置 | `messages[]` 序列中由 `alive_check` 位置表达，端到端例断顺序而非仅字段出现 |
| 时间线 | 单连接严格有序；多流由 flow 控制；绝对时间与网卡行为待真实流程确认 |

## 7. 测试点清单与缺口矩阵

| 来源要求 | 业务场景 | 代码/断言面 | 去向 |
|---|---|---|---|
| 头部版本/长度/逆版本 | 激活、诊断、IPv6 | DoIP 8B 头、frames、`doip.version/inverse/length` | 正例 1–4、10、53–55 |
| PayloadType 与响应码 | 激活、Ack/Nack、Generic NACK | `doip.type` 与各 code 字段 | 正例 1–6、11–24、36–52 |
| UDS 服务和 NRC | 会话、DID、安全、刷写 | UserData/UDS 字段与 frames | 正例 3–4、25–35、43、68、80 |
| 状态与错误 | 缺激活、拒绝、地址不一致 | `expect_error` + 锚词 | 负例 7、11、15–18、24、29、34、36、40–42、52、54–55、61、65–66、69–76 |
| 多轮/保活/终止 | 长连接端到端 | 顺序字段与 packet_count | 47、77 |
| 动态/多流 | `doip_tcp_multiflow_dynamic` 的 `tcp.src_port` `inc` strategy，并以 case 级 `strategy_fc: {"type":"flows","value":2}` 表达两条流 | 已覆盖 case 级 `strategy_fc` 流数载体；DoIP 业务字段动态策略仍登记 G-DOIP-8，`flow_control` 未作为当前 JSON 统计 | 78 |

缺口：UDP 发现/实体状态/电源模式成功面因 TCP-only 链不可达，登记 G-DOIP-2；真实 OEM/NAT 行为无证据，登记 G-DOIP-9；DoIP 业务字段动态策略无实现，登记 G-DOIP-8。未把这些缺口冒充正例覆盖。

## 8. 存量去向与对账声明

JSON 已从旧扁平/混用口径收敛为 80 例机器契约：50 正例全部为层链形，30 负例保留用于拒绝和 CORE presence 形状。旧 115 例及历史 41-ID 目标集仅是设计文档的过程记录，不是当前 JSON 的 ID 权威；当前权威是本文件 §3 与 JSON 的 80 个 ID。

对账两行：

- JSON 总数 = **80 = 50 正 + 30 负**。
- 正例顶层泄漏 = **0**；负例锚词缺失 = **0**；负例混入成功断言 = **0**。

## 9. 执行边界

本次不跑 suite、不启动服务、不声称 80/80 运行通过。后续 P5 必须按 CORE §14.7–§14.20 走 MCP 建任务→真实生成→tshark/frames 校对，并以落盘 pcap 回填包数；先验收 `doip_tcp_full_flow` 与 `doip_tcp_multiflow_dynamic`，再跑全量。

## 10. 层链迁移审计（T1-T6，2026-09-30）

| ID | 测试审计结论 | 证据 |
|---|---|---|
| T1 | 80 条 ID 唯一且 JSON 可解析 | `doip.json` 机读校验 |
| T2 | 50 条正例均为 `[ip,tcp,doip]` 严格层链；唯一 UDP 链为负例 | 全量 `spec_json.layers` 审计 |
| T3 | 30 条负例保留故意错误输入与非空错误锚词 | `expect_error`/`error_contains` 审计 |
| T4 | IPv4/IPv6 地址只在 `ip` 层，端口只在 `tcp` 层，DoIP 业务字段只在 `doip` 层 | 全量 spec_json 字段审计 |
| T5 | 流控/动态驱动字段不混入协议层；多流现状以 `doip_tcp_multiflow_dynamic` 登记 | JSON 用例与 G-DOIP-8 |
| T6 | 本轮未改变协议字段、包数或负例语义；运行结论仍待 MCP/pcap 流程 | 对照本文件 §3–§9 与 80 条 cases |

### 10.1 迁移状态与缺口

- 已迁移：80/80 条 cases 均完成现状对账；50 条正例纯层链，30 条负例保留故意违规形状。
- 特殊负例：presence/游离键/UDP 载体例不得清洗为正例。
- 缺口：UDP 成功面、DoIP 业务动态和真实 OEM/NAT 行为分别登记 G-DOIP-2/G-DOIP-8/G-DOIP-9；本轮不冒充覆盖。

## 11. 六项测试覆盖清单（C1-C6）

| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | JSON 可解析、ID 唯一、80 条清单一致 | 已逐条对账，80/80 |
| C2 | 严格 `[ip,tcp,doip]` 层链与地址/端口归属 | 50 条正例全覆盖；UDP 载体仅负例保留 |
| C3 | 激活、UDS、探活、Generic NACK、IPv4/IPv6、动态多流和复杂流程 | 对应正例已登记；现状缺口不虚构 |
| C4 | 30 条负例均有单一故障与精确错误锚词，且 `expect` 仅含 `expect_error`/`error_contains` | 全部有非空 `error_contains`，无成功断言或额外键混入 |
| C5 | 当前 80 条机器契约中的旧扁平键、presence、UDP 载体与值域错误路径 | 30 条负例逐条保留，6 组故障族明列全部 ID，分别回指 §5 与 G-DOIP 缺口；历史 41-ID 目标集不计入当前覆盖 |
| C6 | pcap/NIC 双输出全量流程校准 | 本批未重新运行 suite/MCP；不得报告运行通过 |

自审两轮：第一轮逐条核对 T1-T6/C1-C6、JSON ID/层链/负例；第二轮复核三文件总数、承载分布、缺口与未跑声明，末轮干净。

## 12. 自审

逐条回查 CORE §1、§3.14–§3.15、§4.19–§4.22、§5、§6、§9.14、§9.20–§9.53、§12、§14.11–§14.20、§15.1–§15.4；JSON 80 例、50/30 分类、层链分布、负例锚词与成功断言已对账。未跑 suite 的运行结论未写入文档。

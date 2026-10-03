# S7comm（西门子 S7 通信协议）测试用例设计

> 版本：v1.1.0（P4 用例落地后文档校正）
> 日期：2026-09-30
> 配套设计：`docs/protocols/s7/design.md` v1.1.0
> 机器契约：`trafficgen/test/protocol_pcap/cases/s7.json`（28 例；16 正 + 12 负；ID/顺序与本文 §2 及 JSON 对齐）

## 1. 测试原则

用例由设计 §1–§17 逐项派生，共 **28 个唯一 ID：16 正 + 12 负**；正例断言 `packet_count`/字段/frames，负例严格只含 `expect_error` + `error_contains` 两个契约键。四元组只在 `ip`/`tcp` 层，业务字段只在 `s7` 终结层，数量只走用例级 `strategy_fc`。未知键负例对应严格层解码路径；未知 kind、非法 transport_size、sessions 越界对应语义校验路径。

- 字段全部来自 `tshark -G fields` 已注册字段；不写未经实测的固定 checksum/随机值。
- CR/CC 帧无 `s7comm.*`，只许 `cotp.*` 或帧字节断言；多会话用 `distinct_values`，不用帧定位。
- `has_handshake`/`has_payload`/`directional`/`terminates` 不作为 S7 专属配置键；载体由 `[ip,tcp,s7]` 层链表达。
- 断言数值以已落盘 pcap/历史实测为准；P5 若改变 builder/planner，必须重新钉包数和 frames。

## 2. 原子用例索引（与 JSON 同序）

| # | ID | 类型 | 覆盖 | packet_count |
|---:|---|---|---|---:|
| 1–9 | `s7_connect_setup_read` … `s7_multi_session_ports` | 正 | 建连、读写、setup、保活、SZL、错误头、IPv6、多会话 | 11–26 |
| 10–14 | `s7_negative_bad_rosctr` … `s7_udp_rejected` | 负 | ROSCTR、area、PDU 长度、bit、transport | — |
| 15–17 | `s7_neg_top_s7_presence_reject`, `s7_neg_stray_src_ip`, `s7_neg_udp_carrier` | 负 | presence 并存、顶层白名单、载体拒绝 | — |
| 18–21 | `s7_a1_multi_db_write`, `s7_a2_transport_size_octet`, `s7_a3_explicit_pdu_ref`, `s7_a4_multi_command_sequence` | 正 | A′ 多项写、octet、显式 PduRef、多事务 | 13/17 |
| 22–24 | `s7_b1_unknown_kind_rejected`, `s7_b2_transport_size_rejected`, `s7_b3_sessions_over_rejected` | 负 | B′ 语义拒绝 | — |
| 25 | `s7_neg_layer_unknown_key` | 负 | 层未知键严格拒绝 | — |
| 26–28 | `s7_a2b_transport_size_values`, `s7_area_values`, `s7_errcls_values` | 正 | transport-size、area、errcls 枚举代表格 | 13/18 |

JSON 实测：总数 28，正例 16、负例 12；正例均无 `error_contains`，12 个负例的 `expect` 严格只有 `expect_error` 与 `error_contains` 两个键，且无 `packet_count`/`frames`。

## 3. Positive（正例）断言契约

- `tcp.dstport=102` 为链语义（FieldContract），逐包方向由 tcp 层定；CR/CC 包断言 `cotp.type`（`0x0e/0x0d`）+ `cotp.srcref/destref`（`0x0001`）。
- `s7comm.header.rosctr`（1/3/7）、`s7comm.param.func`（`0xf0/0x04/0x05/0xfa`）、`s7comm.param.itemcount`、`s7comm.header.pduref`（回显）、`s7comm.data.returncode`（`0xff`）、`s7comm.data.transportsize`（`0x04/0x03/0x09`）、`s7comm.header.parlg/datlg`、`s7comm.header.errcls/errcod`、`s7comm.param.pdu_length/maxamq_calling/maxamq_called`、`s7comm.data.userdata.szl_id`（`0x0132`）——去重 23 字段，对 tshark 注册表（本机 3.6.14，`s7comm.*` 精确口径 1119）**命中 23/23，零自创**。
- frames offset 四档实测：**54**（S7 载荷基址，IPv4）/ **73**（多项 S7ANY 首项）/ **75**（多项数据头）/ **74**（IPv6 基址）；frames 断言总量以 JSON 实测为准。
- `decode_as` P6 m2 结论：tshark 3.6.14 不接受 `tcp.port==102,s7comm`，102 端口原生解码即 COTP/S7COMM，`decode_as` 直接移除。
- 原 14 例的 23 字段断言与新增枚举/边界例合并；实际字段、frames、包数以 JSON 为准。当前 28 例均有可执行实现；待实现边界（B′-5、G-S7-5/G-S7-6/G-S7-7）不伪装进 JSON。

## 4. Negative（负例）契约

12 负例均带 `expect_error:true + error_contains`，且 `expect` 严格只有这两个契约键，不带 `notes`、`packet_count` 或 `frames`。锚词按落码拒绝文案逐例钉定：

| ID | 拒绝位置 | `error_contains` |
|---|---|---|
| `s7_negative_bad_rosctr` | `Planner.Validate`（planner.go:25） | `invalid rosctr 9` |
| `s7_negative_bad_area` | `validateCommand`（builder.go:347） | `invalid area 0x00` |
| `s7_negative_pdu_mismatch` | `Planner.Validate`（planner.go:28） | `invalid pdu length` |
| `s7_negative_addr_range` | `validateCommand`（builder.go:353） | `invalid bit 8` |
| `s7_udp_rejected` | `Planner.Validate`（planner.go:21） | `transport "udp" is invalid` |
| `s7_neg_top_s7_presence_reject` | top-level presence guard | `no longer accepts a top-level s7 sub-config` |
| `s7_neg_stray_src_ip` | top-level whitelist guard | `no longer accepts flat config field src_ip` |
| `s7_neg_udp_carrier` | carrier guard（complete.go:462-467） | `carrier` |
| `s7_b1_unknown_kind_rejected` | S7 semantic validation | `unknown kind "reed"` |
| `s7_b2_transport_size_rejected` | S7 semantic validation | `invalid transport_size 0x0a` |
| `s7_b3_sessions_over_rejected` | S7 semantic validation | `invalid sessions 17` |
| `s7_neg_layer_unknown_key` | strict layer decode | `unknown field "bogus"` |

## 5. 存量与补充用例逐条去向审计（§9.14）

原存量 14 例全部合入并改写为严格层链形；补充 14 例分别覆盖 presence/白名单/载体红例、A′/B′ 与枚举矩阵。JSON 的 28 个 ID 均在 §2 登记，未作废任何存量行为。

| 范围 | 去向 | 改写动作 |
|---|---|---|
| 原 1–9 正例 | 合入 | `ip`/`tcp`/`s7` 层链 + `strategy_fc: flows=1`，保留字段/frames/包数 |
| 原 10–14 负例 | 合入 | 层链形 + `error_contains` 锚词 |
| `s7_neg_top_s7_presence_reject` / `s7_neg_stray_src_ip` / `s7_neg_udp_carrier` | 新增 | presence、顶层白名单、UDP carrier 负路径 |
| `s7_a1`–`s7_a4` | 新增 | A′ 多项写、尺寸、PduRef、多命令事务 |
| `s7_b1`–`s7_b3` / `s7_neg_layer_unknown_key` | 新增 | B′ 语义与严格解码失败路径 |
| `s7_a2b_transport_size_values` / `s7_area_values` / `s7_errcls_values` | 新增 | 枚举值矩阵代表格 |

断言包数/hex 沿用已落盘实测口径；若 P5 改动生成器，必须重新跑真实流程后再钉断言。

## 6. 三方一致性清单

设计 §6 S1–S12 ↔ 本文件 §2–§4 ↔ `s7.json`：28 个 ID、16 正/12 负完全对齐；正例均有成功断言，负例均有错误锚词且无成功断言；所有非负例 `spec_json` 顶层键均为 `layers`，`strategy_fc` 仅用于原 9 个存量正例（补充例的单流配置不需要重复声明）；offset 与枚举覆盖按 JSON 实际值核对。`decode_as` 已移除，102 端口原生解码。

## 7. 实现后执行顺序

D-S7-85 定稿（门1）→ `CASE_PROTO=s7` 全量真实流程 → A′/B′ 与枚举矩阵复核 → presence/白名单红例复核 → pipe_gate 四项 → P6；G-S7-2/3(B′-2)/4 已由当前实现与负例覆盖，后续只追踪剩余待实现边界。

## 8. 修订记录

- v1.1.0（2026-09-30）：P4 落地后校正。例数 14→28（16 正 + 12 负）与 JSON 对账；负例契约表按实际 `error_contains` 逐例重钉；存量去向表改记合入/新增两分类；删除与实况矛盾的"无锚词""14/14 缺 strategy_fc"等过期声明。
- v1.0.0（2026-09-26）：P3 初稿。T-S7-001~014 索引；正例 50 fields/14 frames/23 字段 23/23 命中；负例 5 双键现状 + 拒绝串原文；存量逐条去向；§9 固定动作全落。

## 8. 本轮文档闭环与自审

按当前 Go 实现、JSON 机器契约和 CORE_MEMORY 逐项回读：28 例（16 正 + 12 负）及 12 个负例锚词一致；负例 expect 均严格为 `expect_error` + `error_contains`；存量与新增 ID 顺序不变。R1 核对代码错误分支、JSON 计数和三方章节；R2 复读 design/testcase/cases 的数字、ID、顶层形状和剩余待实现边界，均无新增矛盾。**SELF_REVIEW: passed 2 rounds, last round clean.**

### 9.1 §3.15 三项逐项一例或立项

①同连接多轮操作：**已覆**——`s7_connect_setup_read`（setup+read）+ `s7_a4_multi_command_sequence`（同会话 read→write→readsZL 三事务，9.11 多动作下限）。②非正常结束：**已覆**——`s7_negative_*`/`s7_b*` 语义与严格解码拒绝 + UDP carrier 拒绝；FIN 优雅关闭由 tcp 层承载并计入包数。③长保活：**已覆**——`s7_keepalive`（0xFA 单发无响应）。

### 9.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流/地址族/断言通道六类）

A′（已落地）：`s7_a1_multi_db_write` / `s7_a2_transport_size_octet` + `s7_a2b_transport_size_values` / `s7_a3_explicit_pdu_ref` / `s7_a4_multi_command_sequence`。
B′（已落地为拒绝负例）：`s7_b1_unknown_kind_rejected` / `s7_b2_transport_size_rejected` / `s7_b3_sessions_over_rejected`；B′-4（TSAP/AmQ/PDU 配置面）见设计 §17 G-S7-5 文档回修；B′-5（错误头协商拒绝 3 格）仍为设计 §12.2 待实现边界。

### 9.3 9.52 对账两行 + 清单出处声明

清单出处 = Wireshark 解析器字段面 + 归档 21-s7 冻结表 + 落码实测面 + tshark `s7comm.*` 字段注册表实测，**非**从用例反推。
**规范逻辑点总数 69（子表① 24 格 + 子表② 33 行 + 八项 8 + 商业行为 4）vs 用例覆盖 24（① 6 + ② 9 + 八项 6 + 商业 3）+ 不适用 20（① 18 + 八项 2）+ A′ 4 + B′ 3 已落地 + B′-4 1 待实现 + B′-5 1 待实现 + 待确认 16（② 15 + 商业 TSAP 1）**；24+20+4+3+1+1+16 = 69。

### 9.4 §3.14 豁免边界审计

不豁免 sessions（`s7_multi_session_ports` 已覆）；多流并发（多会话展开）与单包多载荷（`s7_multi_db_read` 双 S7ANY、`s7_a1` 多项写）各有例；超时重传/NAT 显式不适用（设计 §12.1 #6/#7）；COTP 分片/认证/Block 传输/冗余明确不实现（设计 §8）。

### 9.5 三源回指行

Wireshark `packet-s7comm.c` → 设计 §3/§7 → 本文 §2–§4 的 28 例；tshark 字段注册表实测 → frames 双通道；现网 PLC 行为 → 设计 §17 G-S7-7 待重抓。

### 9.6 断言契约核对结论（与设计 §1/§10/§15 一致）

字段逐个对注册表命中；拒绝串逐字对代码；offset 四档对 frames 断言；包数序列对 `s7.json`；`decode_as` 已移除；负例锚词与代码文案一致。

### 9.7 性能设计与验收（§6.1–6.8 要素；细目见设计 §15.7）

单会话 ≤26 包、单 PDU ≤497B；会话 ≤16；O(单 PDU) 流式无锁；pcap + NIC（`tcp port 102`，enp135s0f0np0）同一契约；六类场景 P5 跑测；吞吐数字待基准。

# S7comm（西门子 S7 通信协议）测试用例设计

> 版本：v1.0.0（P3 完整产物）
> 日期：2026-09-26
> 配套设计：`docs/protocol-designs/85-s7-design.md` v1.0.0（D-S7-85 草稿 §14；门1 获批=定稿）
> 机器契约：`trafficgen/test/protocol_pcap/cases/s7.json`（14 例；9 正 + 5 负；正例包数 `[13,13,13,11,12,13,12,13,26]`，负例 0 包 + `expect_error`）
> 状态：`s7` 层已注册、builder/planner/generator 已落码（`registry.go:92`，`internal/protocol/s7/` 809 行，5 单测 + 链级 2 用例），D-S7-85 未定稿——P4 落码前以门1 获批版为准，不宣称当前 suite 可运行。

## 1. 测试原则

用例由设计 §1–§10 逐项派生，共 14 个唯一 ID（T-S7-001~014），正例 9 个、负例 5 个，顺序与设计 §9/§10 及 JSON 完全一致。每个正例断言 `packet_count` + 非空 `fields` + 非空 `frames`（多会话例外：frames 空，改 distinct 端口断言；实测 8/9 frames 非空）；每个负例 `expect` 恰有两个键（`expect_error` + `notes`，**无 `error_contains`** → G-S7-8）。

- 字段全部来自 `tshark -G fields` 已注册字段；不写未经实测的固定 checksum/随机值。
- frames 只用可复算字节（S1–S12 模板；双 S7ANY 内断言用 offset 73/75 并载明推导）。
- CR/CC 帧（包 4/5）无 `s7comm.*`，只许 `cotp.*` 或帧字节断言。
- 响应回显用 `same_as_packet`（PduRef）；多会话用 `distinct_values`（端口 + func），不用帧定位。
- 本协议 `has_handshake`/`has_payload`/`directional`/`terminates` 零出现（实测 0/14），不虚构握手通道键。
- **严格解码边界（P1 实测，诚实声明）**：顶层 `s7` 子映射经 `parseSubconfigJSON`（`strategy_convert_helpers.go:21-30`）用**普通 `json.Unmarshal`（无 `DisallowUnknownFields`）**解码——未知键静默忽略。因此负例不得依赖"未知键被拒"（G-S7-8 上报项）；`transport_size`/未知 kind 同理走语义校验（G-S7-2/3）。
- **口径冻结**：`readsZL` 拼写、`commands: []` setup-only 语义、`sessionBaseRef` 缺省 2、`readValueForItem` 合成值——P4 改任一项即重钉 frames（先跑后钉）。

## 2. 原子用例索引（与设计、JSON 同序；T-S7-001~014）

| # | T 号 | ID | 类型 | 覆盖 | packet_count |
|---:|---|---|---|---:|---:|
| 1 | T-S7-001 | `s7_connect_setup_read` | 正 | 建连全序列 + Read DB1（S1–S6） | 13 |
| 2 | T-S7-002 | `s7_write_m_area` | 正 | Write M100.0 BIT（S7–S8） | 13 |
| 3 | T-S7-003 | `s7_multi_db_read` | 正 | 双 S7ANY 读，单响应双项 | 13 |
| 4 | T-S7-004 | `s7_setup_pdu_length` | 正 | Setup 480/240 + MaxAmQ=1 | 11 |
| 5 | T-S7-005 | `s7_keepalive` | 正 | 0xFA 单发无响应 | 12 |
| 6 | T-S7-006 | `s7_read_szl` | 正 | Userdata SZL 0132/0004 | 13 |
| 7 | T-S7-007 | `s7_error_class_code` | 正 | 错误头 04/01 注入包 | 12 |
| 8 | T-S7-008 | `s7_ipv6_session` | 正 | IPv6 全会话，offset 74 | 13 |
| 9 | T-S7-009 | `s7_multi_session_ports` | 正 | sessions=2，distinct 端口 | 26 |
| 10 | T-S7-010 | `s7_negative_bad_rosctr` | 负 | 非法 ROSCTR=9 | — |
| 11 | T-S7-011 | `s7_negative_bad_area` | 负 | 非法 area=0x00 | — |
| 12 | T-S7-012 | `s7_negative_pdu_mismatch` | 负 | `pad_pdu_len` 长度不一致 | — |
| 13 | T-S7-013 | `s7_negative_addr_range` | 负 | bit=8 越界 | — |
| 14 | T-S7-014 | `s7_udp_rejected` | 负 | `transport=udp` | — |

## 3. Positive（正例）断言契约

- `tcp.dstport=102` 为链语义（FieldContract），逐包方向由 tcp 层定；CR/CC 包断言 `cotp.type`（`0x0e/0x0d`）+ `cotp.srcref/destref`（`0x0001`）。
- `s7comm.header.rosctr`（1/3/7）、`s7comm.param.func`（`0xf0/0x04/0x05/0xfa`）、`s7comm.param.itemcount`、`s7comm.header.pduref`（回显）、`s7comm.data.returncode`（`0xff`）、`s7comm.data.transportsize`（`0x04/0x03/0x09`）、`s7comm.header.parlg/datlg`、`s7comm.header.errcls/errcod`、`s7comm.param.pdu_length/maxamq_calling/maxamq_called`、`s7comm.data.userdata.szl_id`（`0x0132`）——去重 23 字段，对 tshark 注册表（本机 3.6.14，`s7comm.*` 精确口径 1119）**命中 23/23，零自创**。
- frames offset 四档实测：**54**（S7 载荷基址，IPv4）/ **73**（T-S7-003 首 S7ANY，54+19）/ **75**（T-S7-003 数据头，54+21）/ **74**（T-S7-008 IPv6 基址）；frames 总 14 条（3+2+2+2+1+2+1+1+0）。
- `decode_as` 现状 9 正例为 `tcp.port==102,tpkt`（与基线 §1.3 `s7comm` 口径不一致 → P4 统一，G-S7-1）。
- fields 总 50 条（12+5+5+6+4+7+4+5+2distinct）；`same_as_packet` 2 处（T-S7-001/003 PduRef 回显）。

## 4. Negative（负例）契约

5 负例 `expect` 现状均为 `expect_error:true + notes`，**无 `error_contains`**（违反 14.11 → G-S7-8 P4 补短锚词，原文见设计 §10）：

| T 号 | 拒绝位置 | 真实拒绝串（代码原文） |
|---|---|---|
| T-S7-010 | `Planner.Validate`（planner.go:25） | `s7: invalid rosctr 9` |
| T-S7-011 | `validateCommand`（builder.go:347） | `s7: invalid area 0x00` |
| T-S7-012 | `Planner.Validate`（planner.go:28） | `s7: invalid pdu length` |
| T-S7-013 | `validateCommand`（builder.go:353） | `s7: invalid bit 8` |
| T-S7-014 | `Planner.Validate`（planner.go:21） | `s7: transport "udp" is invalid` |

`[ip,udp,s7]` 链形载体负例（carrier 锚词面 `s7 chain: udp carrier is not supported … (carrier)`，complete.go:462-467）P4 与 `transport:udp` 双形状并存（设计 §16 #14）。

## 5. 存量 14 例逐条去向审计（§9.14；P1 存量实测，P4 按本表执行，全改写）

| # | ID | 去向 | 改写动作 |
|---|---|---|---|
| 1 | `s7_connect_setup_read` | 改写 | 顶层旧键（`src_ip/dst_ip/src_port/dst_port` + `s7` 子映射）迁层 + `strategy_fc{flows:1}` + `decode_as→s7comm`；包数 13 先跑后钉 |
| 2 | `s7_write_m_area` | 改写 | 同上；BIT 线性位索引帧断言保留 |
| 3 | `s7_multi_db_read` | 改写 | 同上；offset 73/75 内断言保留 |
| 4 | `s7_setup_pdu_length` | 改写 | 同上；`commands: []` setup-only 冻结 |
| 5 | `s7_keepalive` | 改写 | 同上；notes"包数 7"旧口径作废，按实测 12 钉（先跑后钉） |
| 6 | `s7_read_szl` | 改写 | 同上；`readsZL` 拼写冻结 |
| 7 | `s7_error_class_code` | 改写 | 同上；正例（产出错误头包），不补锚词 |
| 8 | `s7_ipv6_session` | 改写 | 同上；offset 74；v6 由 `ip` 层承载 |
| 9 | `s7_multi_session_ports` | 改写 | 同上；distinct 断言保留；`flows` 恒 1 |
| 10–14 | 5 负例 | 改写 + 补锚词 | 层链形 + `error_contains` 短锚词（§4 原文） |

禁搬运旧期望值：包数/hex 先跑后钉（14.6/14.20）。

## 6. 三方一致性清单

设计 §6 S1–S12 ↔ 本文件 §2/§3 ↔ s7.json `expect`：14 ID 全对齐；包数序列一致（§2）；offset 四档一致（§3）；断言字段 23/23 注册命中。`decode_as` 口径差（tpkt vs s7comm）与 T-S7-005 包数 notes 矛盾已显式登记（§1/§5 #5），P4 消灭。

## 7. 实现后执行顺序

D-S7-85 定稿（门1）→ G-S7-2/3/4 校验收紧 → 14 例改写 → presence/白名单红例 → `CASE_PROTO=s7` 全量绿 → A′ 补例 → pipe_gate 四项 → P6。

## 8. 修订记录

- v1.0.0（2026-09-26）：P3 初稿。T-S7-001~014 索引；正例 50 fields/14 frames/23 字段 23/23 命中；负例 5 双键现状 + 拒绝串原文；存量逐条去向；§9 固定动作全落。

## 9. P3 固定动作（CORE_MEMORY §3.15 / §9.52 / §9.14 / 覆盖审计要求面）

### 9.1 §3.15 三项逐项一例或立项（无例无项即缺口）

①同连接多轮操作：**半程**——T-S7-001（setup+read 两轮）有例，多命令序列（read→write→readsZL 同会话）零覆盖 → A′-4。②非正常结束：有例（T-S7-010~014 Validate 拒绝 + FIN 关闭含包数）。③长保活：有例（T-S7-005 keepalive 单发无响应）。

### 9.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流/地址族/断言通道六类）

A′（补例，不并入 14 ID 契约）：A′-1 多 DB 写多项 / A′-2 传输尺寸逐值（01/02/05/06/07/08/09）/ A′-3 显式 `pdu_ref` 非 2 基址 / A′-4 多命令序列三事务（9.11 下限）。
B′（待实现边界 → G）：B′-1 未知 kind 静默（G-S7-2）/ B′-2 transport_size 越界（G-S7-3）/ B′-3 sessions 越界（G-S7-4）/ B′-4 TSAP/AmQ/PDU 配置面（G-S7-5）/ B′-5 错误头协商拒绝 3 格（G-S7-3 修轮）。

### 9.3 9.52 对账两行 + 清单出处声明

清单出处 = Wireshark 解析器字段面 + 21-s7-design.md 冻结表 + 落码实测面 + tshark 1119 字段注册表实测，**非**从用例反推。
**规范逻辑点总数 69（子表① 24 格 + 子表② 33 行 + 八项 8 + 商业行为 4）vs 用例覆盖 24（① 6 + ② 9 + 八项 6 + 商业 3）+ 不适用 20（① 18 + 八项 2）+ A′ 4 + B′ 5 + 待确认 16（② 15 + 商业 TSAP 1）**；24+20+4+5+16 = 69，无遗漏。

### 9.4 3.14 豁免边界审计

不豁免 sessions（T-S7-009 已覆）；多流并发（多会话展开）与单包多载荷（T-S7-003 双 S7ANY）各有例；超时重传/NAT 显式不适用（设计 §12.1 #6/#7）；分片/认证/Block/冗余明确不实现（设计 §8）。

### 9.5 三源回指行

Wireshark `packet-s7comm.c` → D-S7-85 §3/§7 → T-S7-001~014（§3/§4）；tshark 实测（1119 注册 + 23/23 命中）→ frames 双通道；现网 PLC 行为 → G-S7-7 待重抓。

### 9.6 断言契约核对结论（与 design §1/§10/§15 一致）

23 字段逐个对注册表命中；5 拒绝串逐字对代码；offset 四档对存量断言；包数序列对 s7.json；`decode_as` 差与 keepalive notes 矛盾已登记待消。

### 9.7 性能设计与验收（§6.1–6.8 要素；细目见 design §15.7）

单会话 ≤26 包、单 PDU ≤497B；会话 ≤16；O(单 PDU) 流式无锁；pcap + NIC（`tcp port 102`，enp135s0f0np0）同一契约；六类场景 P5 跑测；吞吐数字待基准。

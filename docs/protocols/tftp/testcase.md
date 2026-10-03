# TFTP 测试用例契约（P-PIPE 轨 T-TFTP）

> 版本：v1.1.0（P5 层链迁移校准，2026-09-30）
> 配套设计：`docs/protocols/tftp/design.md`（D1–D8）；机器契约：`trafficgen/test/protocol_pcap/cases/tftp.json`
> 当前状态：**224 例 = 189 正例 + 35 负例**。正例已全部收敛为严格层链：187 例 `[ip,udp,tftp]`，2 例 `[eth,vlan,ip,udp,tftp]`；负例保留故意的 flat/presence/校验错误形状。本文以当前 JSON 为权威；历史 226 例与 P1–P3 缺口仅作迁移记录，不作为当前完成态。

## 1. 测试原则与当前边界

TFTP（RFC 1350）跑在 UDP 上：客户端从临时端口把 RRQ/WRQ 发往服务器知名端口 **69**，服务器随后**换用自己新选的 TID**（临时端口）继续会话，双方此后只用各自 TID（RFC 1350 §4）。用例从设计 §12–§15 逐项派生；**当前 224 例以 JSON 为权威**：189 个正例已是严格层链，35 个负例保留故意的 flat/presence/校验错误形状。历史 226 例迁移前全红记录仅用于追溯，不代表当前状态。

**当前不可达面（诚实声明）**：①层内业务键**写不进去**——`ValidateLayerConfig`（`complete.go:290-293`）拒未知字段（`Fields` 为空），且 `translateTerminalConfig`（`chain_planner_translate.go:742-744`）对 `len(Fields)==0` 早退 → 目标形状（design §13.2）需先补 G-TFTP-1；②非法/未知 opcode 注入**无入口**（§12.2 三格缺，G-TFTP-3）；③RFC 1350 §4 合规 TID 校验序列（丢包 + 向错误源回 ERROR(5) + 继续旧 TID）**不实现**（G-TFTP-6，S9 是 trafficgen 扩展语义，互操作负向）；④现网产品级出处缺（G-TFTP-5）。

当前正例断言含 `packet_count`/`min_packets`、方向（`directional`）、稳定 `frames` hex 或 `fields` 字段值；负例执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`。当前 35 个负例为故意判死配置，不能与正例的严格层链形状混淆。

## 2. 原子用例索引（按族，逐族点名回指 design §16）

| 族 | 计数 | 构成 | 去向（design §16） |
|---|---:|---|---|
| A 单流正例 | 175 | RRQ 95 + WRQ 21 + OACK 4 + matrix 5 + regress 13 + e2e 22（含 flows=1 的 mixed-dns/srcip-skip 与 bps 形的 e2e-bps）+ validate 正例 3 + 单例 10 + server 2 | 已为纯 layers 形，A 族逐 ID 点名 |
| B 多流正例 | 14（当前 `strategy_fc` 正例分组） | 当前机器契约对应 11 个 `flows>1` 多流/并发正例，另有 2 个 `flows=1` 与 1 个 `bps` 策略形状；数量/速率由驱动元数据承载，四元组由 UDP 层动态端口范围承载 | 已为层内四元组动态对象；当前正例已对账 |
| C 负例 | 35 | 当前 JSON 的 flat/presence/校验判死例；历史 40 例中 D 族 7 例删除，当前锚词以 JSON 为准 | 保留故意错误形状，不计为正例残留 |
| D 等价覆盖 | 7 | `t082`/`t090`/`t093`/`t094`/`t095` 各 1 例 + `t096` + `t101`（同主题双例，锚词粒度不同） | P5 删除（保留锚词更全的一条） |
| E 改判读 | 4 | `t101-tcp-mutex`（若未按 D 删）/ `http-coexist-reject` / `rrq-vlan-100` / `e2e-vlan` | 改锚词（顶层游离键判死）或迁 `vlan` 层 |
| F 规模巨例 | 5 | `winsize65535-wrap` / `-wrap2` / `rrq-blocks65536-parse` / `regress-blocks-65536-wrap` / `-blocks-wrap-seq` | 保留或拆分，拆分须登记去向 |
| A′ 补例 | 3 | **T-TFTP-V6**（`[ip,udp,tftp]`——`ip` 层写 v6 字面量，注册表无 `ipv6` 层；断言 `ipv6.nxt=17` + `udp.dstport=69` + `tftp.opcode`）＋ **T-TFTP-WRQ-RETX**（WRQ 方向 `retransmit_blocks`）＋ **T-TFTP-WRQ-TIDCHG**（WRQ + `server_tid_change`） | P5 新增（§6.2/§6.3） |

整数对账：**当前 JSON = 224 例（189 正例 + 35 负例）**。历史 226 例的 D 族 7 例已删除；D/E/F 为历史迁移子集标注，不另计当前基数。

## 3. 正例断言契约（改写后口径）

1. **RRQ 族**：`packet_count` 逐例 · `frames` hex 钉首字节（RRQ = `00 01` + filename + `\0` + mode + `\0` + 选项对，offset 42 = 14 Eth + 20 IP + 8 UDP）；`fields` = `tftp.opcode`=1 / `tftp.source_file`=文件名 / `tftp.type`=octet·netascii / DATA 的 `tftp.block` 与 `tftp.option.*`（OACK 回显）；端口断言：包 1 的 `udp.dstport`=69，**后续包的 `udp.srcport`=ServerTID ≠ 69**（TID 交换，RFC 1350 §4——本协议最关键的口径）。
2. **WRQ 族**：WRQ = `00 02`；无选项分支的 `tftp.opcode`=4 + `tftp.block`=0（服务器"就绪"ACK#0）；有选项分支**无 ACK#0**（客户端直接 DATA#1）；DATA 方向 up（`directional` 断言）。
3. **选项协商**：OACK 字节钉（`tftp-oack-blksize-15b` 15B / `-timeout-13b` / `-tsize-13b` / `-multiopt-35b`），`tftp.option.name`/`tftp.option.value` 双字段列表；固定顺序 blksize→timeout→tsize→windowsize；空 OACK = 仅 `00 06` 2 字节。
4. **窗口（RFC 7440）**：窗口内连续 N 个 DATA 无中间 ACK，窗口末 ACK 块号=窗口末块（`tftp.block`）；`windowsize=1` 与无选项包序列等价；末窗口块数 < windowsize 时该 ACK 为该窗口末块。
5. **重传（RFC 1350 §6 时序）**：`retransmit_blocks=[N]` 的 DATA#N **只出现一次**（丢包式：无"原 DATA+原 ACK"再重传的异常对）；重传 DATA 先于其 ACK；字节与原块相同。
6. **块号回绕**：`wrap_block_number=true` 时 Block# = `i mod 65536`；断言双口径 —— `tftp.block`（wire 值，回绕后可为 0）+ **`tftp.block.full`**（dissector 补偿值：DATA#0 报 65536，walk-through 探针实证）。回绕产生的 Block#=0 DATA 与 RFC 1350 合规客户端不可互操作（仅字节序列测试）。
7. **ERROR**：`tftp.error.code` + `tftp.error.message`（默认映射逐码：0→"Not defined" … 8→"Failed to negotiate options"）；ERROR 后不再有包；错误方向随 `error_side`（client 时 up）。
8. **TID 变更（扩展语义）**：DATA#N 起 `udp.srcport`=ServerTIDNew；客户端 ERROR(5) 的 `udp.dstport`=NewTID 且**传输继续**；本流标注"trafficgen 扩展、非 RFC 标准、互操作负向"。
9. **多流**：每流独立四元组 + 流内 PacketIndex 连续；层内四元组必须为动态对象（静态 + `flows>1` 被 `checkLayerChainStaticCopy` 拒）；100 流例断言四元组互异。

## 4. 负例契约（35 例，锚词逐族）

| 族 | 目标 `error_contains` | 出处 |
|---|---|---|
| filename | `tftp: filename is required` / `filename must not contain null byte` / `exceeds 255 bytes` | `tftp.go:50` 起 Validate |
| mode/transfer_mode | `invalid mode` / `invalid transfer_mode` / `transfer_mode "mail" is deprecated` | 同上 |
| 选项值域 | `blksize … out of range (8-65464)` / `timeout … (1-255)` / `windowsize … (1-65535)` / `error_code … (0-8)` | 同上 |
| TID | `server_tid … in well-known range (<1024)` / `server_tid_new …` / `must differ from server_tid` / `server_tid <N> conflicts with another flow in the same batch` | `tftp.go` + `schema/semantic.go:442-459`（函数 `:442`；锚词 `:457`） |
| EAB/blocks | `error_after_block … exceeds blocks_count` / `requires explicit blocks_count` / `requires data_payload_pattern or payload source` / `blocks_count … exceeds uint16 max` / `auto-append pushes blocks_count to 65536` | `tftp.go` |
| 互斥 | `server_tid_change and error_code are mutually exclusive` / `… and retransmit_blocks …` | `tftp.go` |
| retransmit | `retransmit_blocks entry <N> out of range` | `tftp.go` |
| 跨协议互斥（**迁层后改判读**，E 族） | 现状 `tcp field must not be set` / `http field must not be set`；迁层后应为顶层游离键/白名单锚词 | `tftp.go` V20 → 迁层后由 `CheckProtoFlat` 承载 |
| 顶层旧键（P5 新增 presence 负例） | `no longer accepts flat config field <k>` / `no longer accepts a top-level tftp sub-config` | `strategy_convert.go:8280-8285`（已生效）+ tftp presence 分支（G-TFTP-1 新增） |

> RFC 1350 §4 合规的 TID 校验负例（新 TID 包应被丢弃 + 向错误源回 ERROR(5) + 继续旧 TID）**不实现** → 不冒充覆盖（G-TFTP-6）；本协议所有 TID 变更例均标"互操作负向"。

## 5. 三方一致性与静态检查

1. 本文件 §2 分族、design §16/§19 去向表、`cases/tftp.json` 当前 224 例 ID **同一集合、同一分族**（当前 189 正例 + 35 负例）。
2. 改写后正例 `spec_json` 顶层键仅为 `layers`（门2①口径，design §19）；当前 189/189 正例均仅含 `layers`。多流端口由 UDP 层动态范围承载，策略流控元数据单独保留在例项顶层：正例 14 例（11 个 `flows>1`、2 个 `flows=1`、1 个 `bps`），负例 3 例用于冲突路径。
3. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/tftp.json` 应成功；当前 35 个负例 `expect` 键集严格为 `{expect_error, error_contains}`。
4. 断言通道：只用 `tshark -G fields` 实测字段（**`tftp.*` 31 字段**，`awk -F'\t' '$3 ~ /^tftp\./'` 口径；默认 awk 无 `-F'\t'` 只得 4，属列错位，禁用）+ `frames` hex；**不自创字段名**；13 个在用字段名全部实测存在（design §15.6）。
5. 巨例（F 族 5 例，含 65535 块窗口 / 65536 块回绕）为设计文档级规模；P5 执行面按需保留或拆分，拆分须登记去向（不得静默删）。
6. **ID 体系声明**：design §7 的 T-001~T-241 为**历史设计层编号**（241 条，wire 语义权威）；机器契约 ID 为当前 224 个 `tftp-*`。两者**非一一对应**——历史映射关系以 design §16/§19 为准；无落位者登记为缺口。

## 6. P3 固定动作

### 6.1 §3.15 三项

①同流多轮操作 → 锁步 DATA/ACK 多轮 + 选项协商轮（`tftp-rrq-multiblock-append` / `tftp-concurrent-8flows-100blk`（100 块）/ `tftp-rrq-winsize4-blocks8` / `tftp-matrix-allopts-retx-err`）；②非正常结束 → ERROR 终止族（当前 JSON 负例 35 例）+ TID 变更扩展 + 重传族 + 半标准流；WRQ 方向重传/TID 变更已由 `tftp-wrq-retransmit` / `tftp-wrq-tidchange` 覆盖；③长保活 → TFTP 无保活语义（UDP 无状态）→ 形态对应物 = 同 TID 长块序列（100 块 / 65535 块边界），**空闲复用/超时值明确不支持**。当前 `strategy_fc` 共 17 例：14 个正例（11 个 `flows>1`、2 个 `flows=1`、1 个 `bps`）+ 3 个负例；均由外部 `strategy_fc` 承载流数/速率，UDP 层动态端口承载四元组。

### 6.2 A′/B′ 两分类

A′（已落地）：`tftp-v6-basic` / `tftp-wrq-retransmit` / `tftp-wrq-tidchange` 已并入当前 JSON 224 例；D 族 7 例删除、E 族改判读、C 族改写、B 族层动态化均已反映在当前 JSON。
B′（引擎结构缺口 → design §17）：G-TFTP-1（业务 23 键迁层 + presence 判死 + 层翻译 case）、G-TFTP-2（`checkTFTPServerTID` 改读层 config + schema 形状）、G-TFTP-3（非法 opcode 注入能力）、G-TFTP-6（RFC §4 合规 TID 序列不实现）、G-TFTP-7（驱动失败→空流收敛，框架面）。

### 6.3 9.52 对账两行 + 清单出处

- 出处声明：清单=**规范/官方文档反推**（RFC 1350/2347/2348/2349/7440/6335），非引擎能力面反推。
- 对账（粒度实读，与 design §15.3 同数）：**规范逻辑点总数 51**（八项 8 行 + 矩阵 24 格 + 变体 19 行） vs **用例覆盖 40**（八项 8 + 矩阵 14 + 变体 18）+ 未覆盖 6（矩阵 5 格：WRQ 异常面 1 / DATA(up) 异常面 1 / 非法 opcode 3；变体 1 行：IPv6）+ 不适用 5 格。40 + 6 + 5 = 51 ✓。
P3 后历史固定动作的对账见设计 §15；当前 JSON 的迁移后覆盖统计以本节 C1–C6 为准。

### 6.4 3.14 豁免边界审计

无长连接会话结构 → `sessions[]` 豁免；豁免不豁免多流覆盖：①多流并发 = 当前 JSON 11 个 `flows>1` 正例；另有 2 个 `flows=1` 与 1 个 `bps` 策略形状，均由驱动元数据承载，UDP 层动态端口承载四元组；②单包多载荷 = 单包多选项对（`tftp-oack-multiopt-35b` 4 选项 / `tftp-rrq-all4opts`）。两项均有，无逃逸。

### 6.5 三源回指

RFC 1350/2347/2348/2349/7440（+6335）→ D-TFTP-1（design §14）→ `cases/tftp.json`（当前 224 例）；本机 tshark 3.6.14（`tftp.*` 31 字段 + 4 探针）与历史落盘 pcap 为旁证。

## 7. 修订记录

- v1.0.0（2026-09-26）：P3 产物。建立 T-TFTP 契约（§2 分族索引 / §3 正例断言 / §4 负例锚词 / §5 三方一致 / §6 固定动作）；存量 226 例实读分族 A 175 / B 11 / C 40 / D 7 / E 4 / F 5，整数对账 226 闭合（改写后 222 例含 A′ 3）；新增补例 T-TFTP-V6、T-TFTP-WRQ-RETX、T-TFTP-WRQ-TIDCHG。

## 7. 层链迁移审计（T1–T6，2026-09-30）

| ID | 审计结论 | 证据 |
|---|---|---|
| T1 | JSON 可解析，ID 唯一，224 例总数与设计 D7 对账 | 机读审计 |
| T2 | 189 个正例均为严格层链：187 个 `[ip,udp,tftp]`，2 个 `[eth,vlan,ip,udp,tftp]` | `cases/tftp.json` 全量扫描 |
| T3 | 35 个负例保留故意判死键/层链+顶层 presence 形状；不计为正例残留 | `expect.expect_error=true` 交叉审计 |
| T4 | 正例地址只在 ip 层、端口只在 udp 层、TFTP 业务只在 tftp 层；正例顶层旧键零残留 | 全量 `spec_json` 顶层键审计 |
| T5 | 多流端口使用 udp 层动态对象；流数量/速率不得写入 tftp 业务层 | `tftp-multiflow-*` / `tftp-concurrent-*` |
| T6 | 迁移不改变 ID、字段/帧断言或业务 notes；本轮未重新运行 MCP/NIC | D7；不作运行绿声明 |

## 8. 覆盖清单（C1–C6）

| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | JSON 可解析、ID 唯一、设计/用例/cases 统计一致 | 224/224 已对账 |
| C2 | 严格 `[ip,udp,tftp]` 与可选 `[eth,vlan,ip,udp,tftp]` 链及字段归属 | 189/189 正例已覆盖 |
| C3 | RRQ/WRQ、OACK、DATA/ACK、ERROR、重传、TID 迁移 | 现有正例覆盖；断言以各 ID 表为准 |
| C4 | 多流动态端口与二层封装 | 正例已有多流与 VLAN 例；IPv6 已有 `tftp-v6-basic` |
| C5 | flat/presence/字段校验负例与静态复制拒绝 | 35 个负例保留；仅计负例，不冒充成功覆盖 |
| C6 | pcap/NIC 双输出、压力/资源耗尽、RFC 合规 TID 校验序列 | 未全量复跑或未实现，继续登记 G-TFTP-5/6/7/8 |

## 9. 修订记录

- 2026-09-30：按 D1–D8、T1–T6、C1–C6 校准迁移后口径；同步当前 JSON 224 例、189/35 分账与严格层链形状。

## 10. 自审结论

自审两轮：第一轮逐项核对 D1–D8、层归属、负例判死形状、224 例统计；第二轮复核 T1–T6/C1–C6、ID/链形/顶层旧键和缺口口径，末轮干净。

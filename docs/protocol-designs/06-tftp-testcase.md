# TFTP 测试用例契约（P-PIPE 轨 T-TFTP）

> 版本：v1.0.0（P1–P3 产物）
> 日期：2026-09-26
> 配套设计：`docs/protocol-designs/06-tftp-design.md`（P1 矩阵 §12／门1 表 §13／D-TFTP-1 §14／P3 固定动作 §15／存量审计 §16／改写清单 §17）
> 机器契约：`trafficgen/test/protocol_pcap/cases/tftp.json`（**226 例已在库**，ID 权威 = 本文件 §2 + design §16 去向表）
> 状态：`tftp` 层已注册（`registry.go:187-192`，`Fields` **空**）且 P4a 生成器已落地（`layer_gen.go` 委托 legacy `Planner.Plan`）；存量 226 例为**旧形**（186 正例 = `layers` 两条目 + 顶层旧键混合形；40 负例 = 纯扁平形），去扁平 = G-TFTP-1/G-TFTP-4（P5 动作）。本文定义**改写后**的 PCAP/NIC 断言口径与 P3 固定动作结论。

## 1. 测试原则与当前边界

TFTP（RFC 1350）跑在 UDP 上：客户端从临时端口把 RRQ/WRQ 发往服务器知名端口 **69**，服务器随后**换用自己新选的 TID**（临时端口）继续会话，双方此后只用各自 TID（RFC 1350 §4）。用例从设计 §12–§15 逐项派生；**当前 226 例全部无法经真实流程提交**（实读判定）：`CheckProtoFlat`（`strategy_convert.go:8280-8285`）对顶层 `src_ip/dst_ip/src_port/dst_port/count` 判死 + `checkLayerFlatConflict`（`schema/semantic.go:179-190`，经由 `:172` 调用）判死 layers 与顶层四元组并存 → **226/226 今日 400**（未跑，本轨禁令不启服务器；依据=调用链实读 + `tests/proto_flat_test.go` 既有断言）。

**当前不可达面（诚实声明）**：①层内业务键**写不进去**——`ValidateLayerConfig`（`complete.go:290-293`）拒未知字段（`Fields` 为空），且 `translateTerminalConfig`（`chain_planner_translate.go:742-744`）对 `len(Fields)==0` 早退 → 目标形状（design §13.2）需先补 G-TFTP-1；②非法/未知 opcode 注入**无入口**（§12.2 三格缺，G-TFTP-3）；③RFC 1350 §4 合规 TID 校验序列（丢包 + 向错误源回 ERROR(5) + 继续旧 TID）**不实现**（G-TFTP-6，S9 是 trafficgen 扩展语义，互操作负向）；④现网产品级出处缺（G-TFTP-5）。

正例断言必须含 `packet_count`/`min_packets`、方向（`directional`）、稳定 `frames` hex 或 `fields` 字段值（**只用本机 tshark 实测字段**：`tftp.opcode`/`tftp.block`/`tftp.option.name`/`tftp.option.value`/`tftp.error.code`/`tftp.error.message` + 载体 `udp.*`/`ip.version`/`vlan.*`，共 13 个已用字段名，design §15.6）；负例执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`（存量 40 负例 **40/40 已带锚词**，实读零缺）。

## 2. 原子用例索引（按族，逐族点名回指 design §16）

| 族 | 计数 | 构成 | 去向（design §16） |
|---|---:|---|---|
| A 单流正例 | 175 | RRQ 95 + WRQ 21 + OACK 4 + matrix 5 + regress 13 + e2e 22（含 flows=1 的 mixed-dns/srcip-skip 与 bps 形的 e2e-bps）+ validate 正例 3 + 单例 10 + server 2 | 改写为纯 layers 形后并入（A 族逐 ID 点名） |
| B 多流正例 | 11 | `strategy_fc.flows>1` 的正例（flows 2/3/8/100） | 改写为**层内四元组动态对象**（否则 `checkLayerChainStaticCopy` 拒） |
| C 负例 | 40 | validate 34 + e2e 2 + concurrent 1 + multiflow 1 + tid 1 + http 1 | 改写为 layers 形 + 锚词逐字保留 |
| D 等价覆盖 | 7 | `t082`/`t090`/`t093`/`t094`/`t095` 各 1 例 + `t096` + `t101`（同主题双例，锚词粒度不同） | P5 删除（保留锚词更全的一条） |
| E 改判读 | 4 | `t101-tcp-mutex`（若未按 D 删）/ `http-coexist-reject` / `rrq-vlan-100` / `e2e-vlan` | 改锚词（顶层游离键判死）或迁 `vlan` 层 |
| F 规模巨例 | 5 | `winsize65535-wrap` / `-wrap2` / `rrq-blocks65536-parse` / `regress-blocks-65536-wrap` / `-blocks-wrap-seq` | 保留或拆分，拆分须登记去向 |
| A′ 补例 | 3 | **T-TFTP-V6**（`[ip,udp,tftp]`——`ip` 层写 v6 字面量，注册表无 `ipv6` 层；断言 `ipv6.nxt=17` + `udp.dstport=69` + `tftp.opcode`）＋ **T-TFTP-WRQ-RETX**（WRQ 方向 `retransmit_blocks`）＋ **T-TFTP-WRQ-TIDCHG**（WRQ + `server_tid_change`） | P5 新增（§6.2/§6.3） |

整数对账：**226 = 正 186（A 175 + B 11）+ 负 40（C 40，其中 D 删 7 → 219 例）+ A′ 3 → 222 例**（D/E/F 为族内子集标注，不另计基数）。

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

## 4. 负例契约（40 例，锚词逐族）

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

1. 本文件 §2 分族、design §16 去向表、`cases/tftp.json` 226 例 ID **同一集合、同一分族**（实读核对：A 175 / B 11 / C 40 / D 7 / E 4 / F 5 / A′ 3；整数分账 226 闭合）。
2. 改写后非负例顶层键 = `layers` + `strategy_fc`，其余为 0（门2①口径，design §13.1 完成式）；`count` 0 例（实读）、空 `tftp` 子映射 0 例。
3. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/tftp.json` 应成功；负例 `expect` 键集严格 `{expect_error, error_contains}`（现状 40/40 已带锚词）。
4. 断言通道：只用 `tshark -G fields` 实测字段（**`tftp.*` 31 字段**，`awk -F'\t' '$3 ~ /^tftp\./'` 口径；默认 awk 无 `-F'\t'` 只得 4，属列错位，禁用）+ `frames` hex；**不自创字段名**；13 个在用字段名全部实测存在（design §15.6）。
5. 巨例（F 族 5 例，含 65535 块窗口 / 65536 块回绕）为设计文档级规模；P5 执行面按需保留或拆分，拆分须登记去向（不得静默删）。
6. **ID 体系声明**：design §7 的 T-001~T-241 为**历史设计层编号**（241 条，wire 语义权威）；机器契约 ID 为 `tftp-*`（226 条）。两者**非一一对应**——映射关系以 design §16 去向表为准（每条历史编号由其语义面在分族表中落位；无落位者登记为缺口）。

## 6. P3 固定动作

### 6.1 §3.15 三项

①同流多轮操作 → 锁步 DATA/ACK 多轮 + 选项协商轮（`tftp-rrq-multiblock-append` / `tftp-concurrent-8flows-100blk`（100 块）/ `tftp-rrq-winsize4-blocks8` / `tftp-matrix-allopts-retx-err`）；②非正常结束 → ERROR 终止族 36 例 + TID 变更 2 例 + 重传 10 例 + 半标准流 2 例 + 40 负例（**单点缺口**：WRQ 方向重传/TID 变更 → T-TFTP-WRQ-RETX / T-TFTP-WRQ-TIDCHG）；③长保活 → TFTP 无保活语义（UDP 无状态）→ 形态对应物 = 同 TID 长块序列（100 块 / 65535 块边界），**空闲复用/超时值明确不支持**。无空项。

### 6.2 A′/B′ 两分类

A′（P5 可构建）：**T-TFTP-V6**（IPv6 对称例）、**T-TFTP-WRQ-RETX**、**T-TFTP-WRQ-TIDCHG**、D 族 7 例删除、E 族 4 例改判读/迁层、C 族 40 例改写、B 族 11 例层动态化。
B′（引擎结构缺口 → design §17）：G-TFTP-1（业务 23 键迁层 + presence 判死 + 层翻译 case）、G-TFTP-2（`checkTFTPServerTID` 改读层 config + schema 形状）、G-TFTP-3（非法 opcode 注入能力）、G-TFTP-6（RFC §4 合规 TID 序列不实现）、G-TFTP-7（驱动失败→空流收敛，框架面）。

### 6.3 9.52 对账两行 + 清单出处

- 出处声明：清单=**规范/官方文档反推**（RFC 1350/2347/2348/2349/7440/6335），非引擎能力面反推。
- 对账（粒度实读，与 design §15.3 同数）：**规范逻辑点总数 51**（八项 8 行 + 矩阵 24 格 + 变体 19 行） vs **用例覆盖 40**（八项 8 + 矩阵 14 + 变体 18）+ 未覆盖 6（矩阵 5 格：WRQ 异常面 1 / DATA(up) 异常面 1 / 非法 opcode 3；变体 1 行：IPv6）+ 不适用 5 格。40 + 6 + 5 = 51 ✓。
- P5 后口径（as-built，用例=224）：**覆盖 43** = 八项 8 + 矩阵 16（14 + 2：WRQ 异常面→`tftp-wrq-retransmit`、DATA(up) 异常面→`tftp-wrq-tidchange`）+ 变体 19（地址族→`tftp-v6-basic`）+ 未覆盖 3（非法/未知 opcode 三格，G-TFTP-3 已立项）+ 不适用 5 格。43 + 3 + 5 = 51 ✓。

### 6.4 3.14 豁免边界审计

无长连接会话结构 → `sessions[]` 豁免；豁免不豁免多流覆盖：①多流并发 = B 族 16 例（改写为层动态后并入）；②单包多载荷 = 单包多选项对（`tftp-oack-multiopt-35b` 4 选项 / `tftp-rrq-all4opts`）。两项均有，无逃逸。

### 6.5 三源回指

RFC 1350/2347/2348/2349/7440（+6335）→ D-TFTP-1（design §14）→ `cases/tftp.json`（226 例）；本机 tshark 3.6.14（`tftp.*` 31 字段 + 4 探针）+ 落盘实证 pcap（`/tmp/mcp-pcaps/tftp/tftp-rrq-short-aa100.pcap`）为旁证。

## 7. 修订记录

- v1.0.0（2026-09-26）：P3 产物。建立 T-TFTP 契约（§2 分族索引 / §3 正例断言 / §4 负例锚词 / §5 三方一致 / §6 固定动作）；存量 226 例实读分族 A 175 / B 11 / C 40 / D 7 / E 4 / F 5，整数对账 226 闭合（改写后 222 例含 A′ 3）；新增补例 T-TFTP-V6、T-TFTP-WRQ-RETX、T-TFTP-WRQ-TIDCHG。

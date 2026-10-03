# S7comm（西门子 S7 通信协议）设计文档

> 版本：v1.1.0（P4 用例落地后文档校正）
> 日期：2026-09-30
> 状态：P1 八项规范矩阵（§12）+ 三子表 + 三路对照与候选方案对比（§12.5/§12.6）+ 门1 §1–§14 十四行表（§13，§1/§3/§12 强制展开）+ P2 D-S7-85 代码设计草稿（§14）+ P3 对接清单与缺口立项（§15–§17）已落盘；**`s7` 层已注册、builder/planner/generator 已落码**（`registry.go:92`，`internal/protocol/s7/` 五个 Go 文件、884 行，含 5 个单测函数 + 链级空配置 2 用例）。P4 已将存量与补充用例统一为严格层链形；当前 cases 共 28 例（16 正 + 12 负），本契约仍不修改 Go 实现。
> 配套文件：`docs/protocols/s7/testcase.md`、`trafficgen/test/protocol_pcap/cases/s7.json`（28 例）
> 技术基线：`docs/protocol-designs/21-s7-design.md` v1.0.0（2026-08-18，1210 行，S1–S12 字节模板与字段表冻结为字节基线，本文不重复抄录，只引用章节号）+ `21-s7-testcase.md` v1.0.0（460 行）。
> 规范基线：S7comm 为西门子私有协议，**无公开 RFC/官方规范文档**；权威来源 = Wireshark `packet-s7comm.c` 解析器源码 + S7-300/400 现网抓包行为（证据链现状见 G-S7-7）。
> **层链唯一真相**：本契约示例只有纯 `layers` 形（`[ip,tcp,s7]`，业务键住 `s7` 层条目内）；当前 cases 28 例中所有非负例顶层仅 `layers`，3 个层链/白名单/载体负例按契约专门验证拒绝。

## 1. 范围、命令与已注册边界

S7comm 运行于 ISO-on-TCP（RFC 1006）之上，固定 TCP 目标端口 **102**，三层封装 TPKT → COTP → S7 PDU。本阶段命令限定为六种 `kind`（`planner.go`/`layer_gen.go` `buildS7Pair` 实际分支）：

| kind | ROSCTR | 请求/响应 | 说明 |
|---|---|---|---|
| `read`（默认，缺省 kind 走此分支） | 1 Job → 3 Ack_Data | Read Var 0x04 | S7ANY 参数 + 数据项回显 |
| `write` | 1 Job → 3 Ack_Data | Write Var 0x05 | 参数 S7ANY + 数据区 `[rc00,transp,len,value]` |
| `keepalive` | 1 Job，无响应 | 0xFA，parlg=1 datlg=0 | 空闲保活 |
| `readsZL`/`read_szl`（两拼写并存） | 7 Userdata → 7 Userdata | Read SZL，参数头 `00 01 12` | 系统状态列表，SZL-ID/Index |
| `error` | 无请求，仅 Ack_Data 响应 | errcls/errcod 非零 | 错误注入（默认 0x04/0x01） |

**已注册/已落码现状（P1 实测，行号真实）**：`s7` 终结层已注册（`registry.go:92`，`CategoryTerminal + DependsOn ["tcp"]`，`FieldContract {"tcp.dst_port": "102"}`，Fields 5 键 `transport/sessions/pdu_ref/pdu_size/commands`）；白名单已登记（P6 行 `protocols.go:54`；P1 写作时 50）；顶层 `s7` 子映射解析（P6 行 `strategy_convert.go:1544`；P1 写作时 1382-1384，经 `parseSubconfigJSON` 普通 `json.Unmarshal`，未知键静默忽略→G-S7-8 后半 open）；Meta 注入（`chain_planner_translate.go:108` `S7: spec.S7`（P6 行 `:2871 case "s7"` 严格解码；P1 写作时仅 108 直传），`generator.go:338`）；终结层生成器 `layer_gen.go`（192 行，`Generate :15`、`emitSession :50`、`sessionBaseRef :120` 缺省基 2、`buildS7Pair :130`）；校验器 `planner.go`（114 行，`Validate :13`，P0b 空配置 nil 放行 + `Plan :36` 缺省注入默认 read DB1）；字节构建 `builder.go`（369 行，`BuildConnectionRequest :68`、`BuildSetup :78`、`BuildRead :118`、`BuildWrite :143`、`BuildReadAck :184`、`BuildWriteAck`、`BuildKeepalive`、`BuildErrorAck`、`BuildReadSZL :287`、`BuildReadSZLAck :311`、`validateCommand :339`、`validArea :363`）；单测 5 函数（`s7_test.go`：CR 模板 hex、`Setup/Read` hex、`Validate` 4 负向、`Plan` 包发射、`Generator` 多会话端口）；链级空配置 2 用例（`chain_planner_s7_emptyconfig_test.go`：缺省 dst 102、用户显式 103 优先）。

不变式：

1. `s7` 终结层只能位于 `tcp` 层之后（`[ip,tcp,s7]`）；缺 `tcp`、夹 `udp` 进链按载体契约拒绝（`complete.go:456-475` tcpOnly 判定——s7 未声明 TransportOn 且 DependsOn 含 tcp，属 tcp-only 形态，`[ip,udp,s7]` 报 `s7 chain: udp carrier is not supported … (carrier)`）。
2. TPKT.Length = 4 + len(COTP) + len(S7 PDU)（`finalize :64` 自动回填）；parlg/datlg 按实际参数/数据区回填；Ack 变体头 12B（补 errcls/errcod），Job/Userdata 头 10B。
3. 响应回显请求 PduRef（`same_as_packet` 断言）；setup 为首个 S7 PDU（基址缺省 2，命令逐条 +1，`sessionBaseRef`）；CR/CC 用 COTP ref 不占 PduRef。
4. 多会话 `sessions=N` 按会话整块顺序回放（`layer_gen.go:34-46` for 循环，先跑完会话 0 全流程再跑会话 1）= **多会话展开**语义；会话 i 源端口 = 基础 `src_port + i`（缺省 12345）。
5. S7ANY 地址为 24 位线性位索引（`itemSpec :104-113`：`addr = byte*8+bit`，大端 3B）；校验界为 `Address ≤ 0xFFFF` 且 `bit ≤ 7`（`builder.go:349-353`，与 21-s7 §8.9 的"20 位"宣称矛盾，见 G-S7-3）。
6. 读响应值确定性合成（`readValueForItem :38`：item0 `12 34`，后续项按 db/address 漂移；多项值互异）。
7. 负例必须传播到 task error 终态，不产“损坏但成功”PCAP；12 个负例分别锁定层链、载体、语义与解码拒绝。

## 2. 会话生命周期（标准序列）

TCP 握手（3 包）→ COTP CR（0x0E）→ COTP CC（0x0D）→ Setup Job（F0，PDU 480）→ Setup Ack_Data（PDU 240）→ 业务命令对（read/write/readsZL 请求→响应；keepalive 单发；error 单响应）→ FIN 关闭（legacy planner 路径 2 包 FIN，`planner.go:110-111`）。CR/CC 帧无 S7 头（断言只许用 `cotp.*` 或帧字节，不许断言 `s7comm.*`）。

## 3. 消息结构（字段表索引，字节模板见基线 §6 S1–S12）

TPKT（4B：`03 00 + len`）→ COTP DT（3B：`02 f0 80`）→ S7 头（10/12B：protid `0x32` / rosctr / redid `0000` / pduref / parlg / datlg / errcls+errcod 仅 Ack）→ 参数区（setup 8B / read `04+count+S7ANY*` / write `05+count+S7ANY*` / keepalive `fa` / SZL 8B）→ 数据区（读请求 1B 项数；写请求逐项 `[00,transp,len,value]`；响应逐项 `[rc,transp,len,value]`；SZL `[ff,09,len,szl-id,index,…]`）。S7ANY 12B：`12 0a 10 transp len(2) db(2) area addr(3)`。字节序全大端（21-s7 §2.1 九行冻结）。

## 4. 状态机

`IDLE → (SYN) → ESTABLISHED → CR_SENT → (CC) → SETUP_SENT → (Ack_Data F0) → READY → (commands 序列) → CLOSED(FIN)`。setup 是 READY 闸门（此后才许业务命令；顺序由 `commands[]` 数组顺序决定=**事件序列**语义）。保活不占响应语义（PduRef 照常自增，无回显）。

## 5. 配置结构（实测 vs 基线 §5 差异表）

实测 `S7Config`（`types.go:1511-1517`）：`transport/sessions/pdu_ref/pdu_size/commands` 5 键；`S7Command`（`:1520-1539`）：`kind/rosctr/pdu_ref/items/value[][]byte/err_class/err_code/force_rosctr/pad_pdu_len/szl_id/szl_index`；`S7Item`（`:1542-1550`）：`area/db_number/address/bit/transport_size/length/data`。

| 基线 §5 宣称 | 实测 | 结论 |
|---|---|---|
| `SrcTSAP/DstTSAP/TPDUSize/MaxAmQ/PDULength` | 不存在（CR/Setup 全固定字节） | 虚声明 → G-S7-5 文档回修 |
| `S7Command.ItemCount/Direction/SkipResponse` | 不存在 | 虚声明 → G-S7-5 |
| `S7Item.Value` | 不存在（值在 `S7Command.Value[][]byte` 逐项对齐） | 虚声明 → G-S7-5 |
| `ErrClass/ErrCode/ForceROSCTR/PadPDULen` | 存在（指针型，仅负向/注入用） | 符合 |
| `sessions/peers/conns` | 仅 `sessions` | 基线 §8.5/§5.2 的 `peers/conns` 口径作废 → G-S7-5 |
| `transport_size` 字符串名（word/dword…） | 不存在（纯 uint8） | 虚声明 → G-S7-5 |

## 6. 包序列场景（索引，模板字节见基线 §6）

S1 CR / S2 CC / S3 Setup Job / S4 Setup Ack / S5 Read Job / S6 Read Ack / S7 Write Job / S8 Write Ack / S9 Keepalive / S10 SZL Req / S11 SZL Resp / S12 错误 Ack。用例映射见 testcase §2。

## 7. 错误处理

错误类 7 值（`00/81/82/83/84/85/87`）、数据项返回码 8 值（`00/01/03/05/06/07/0a/ff`，基线 §9.1/§9.2 冻结）；`Validate` 拒绝 transport 非 tcp、非法 ROSCTR、`pad_pdu_len`、非法 area/address/bit/transport_size/length、未知 kind 与 sessions 越界。未知 kind、transport_size 越界、sessions 越界均已由 B′ 负例锁定（`s7_b1`–`s7_b3`）。错误命令仍用于生成带 `errcls/errcod` 的 Ack_Data 注入；它不是配置错误路径。

## 8. 方言与已知限制（基线 §11.1 冻结）

S7-300/400 经典语义；S7-1500 认证/优化块访问、COTP 分片（PDU<480 不触发）、Block 传输 0x1C–0x1E、S7-400H 冗余——明确不实现。IPv6 经 `EtherTypeFor` 双栈（偏移 74），单测外层链已通。

## 9. 场景与包数映射

`packet_count` 序列（s7.json 实测）：单命令会话 13（握手 3 + CR/CC 2 + setup 2 + 命令 2 + FIN 2 + ACK 2）；setup-only 11；keepalive 12；error 12；双会话 26（=13×2，多会话展开无交错）；负例 0 包 + `expect_error`。

## 10. 负路径契约（锚词已落地）

12 个负例均带 `expect_error` 与 `error_contains`，且 `expect` 严格只有这两个契约键，不含 `notes`、`packet_count` 或 `frames`。原 5 个配置拒绝、3 个层链/白名单/载体拒绝、3 个新增语义拒绝和 1 个严格解码拒绝分别对应 `s7.json` 的负例 ID；锚词逐字按代码/层校验拒绝文案登记在 testcase §4。

## 11. 实现完成定义

P4 已完成用例层链迁移与补充覆盖：cases 28 例（16 正 + 12 负），所有正例 `spec_json` 顶层仅 `layers`；负例覆盖 presence、白名单、UDP carrier、原有五类配置拒绝、未知 kind、transport_size 越界、sessions 越界与层未知键。

## 12. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> S7comm 无公开规范：§4.9–4.11 的"规范原文"以 Wireshark `packet-s7comm.c`（字段/值域真相）+ RFC 1006（TPKT 承载）为准；现网行为以 S7-300/400 PLC 抓包为准（证据链现状 G-S7-7）。

### 12.1 八项规范矩阵

| # | 规范项 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：TCP 长连接，client 主动建连，无控制/数据分离 | 单 PLC 单会话读写；多 PLC 并发 | `Generate` 会话循环 + tcp 层握手/挥手；多会话展开 | 无（多 PLC 并发=多策略，框架面） |
| 2 | 命令表：Setup/Read/Write/Keepalive/ReadSZL/Error + 请求→响应配对 | 建连协商 → 读写 → 状态查询 → 保活 → 错误注入 | `buildS7Pair` 六分支全落码；响应回显 PduRef | 无（未知 kind 已由 `s7_b1_unknown_kind_rejected` 拒绝） |
| 3 | 状态机：CR→CC→Setup→READY→FIN；setup 为业务闸门 | 标准会话全序列；setup 缺席业务不发 | 事件序硬编码（CR/CC/setup/命令）；FIN 由 tcp 层 | 无 |
| 4 | 字段表：TPKT/COTP/S7 头 + 参数区 + 数据区逐字段（大端；长度三口径） | 逐字节模板 S1–S12 | builder 全函数 + 单测 hex 钉死（CR/Setup/Read） | TSAP/AmQ/PDU 面不可配但文档宣称可配 → G-S7-5 |
| 5 | 错误处理：errcls 7 类 + returncode 8 值 + Validate 负例 | 非法配置拒绝；错误头注入 | 校验覆盖 transport/ROSCTR/pdu/area/address/bit/length/transport_size/kind/sessions；error 命令注入 | B′ 配置拒绝已落地；错误头协商拒绝 3 格仍为 B′-5 缺口 |
| 6 | 超时与活性：keepalive 0xFA；空闲超时/重传为 PLC 侧行为 | 长连接保活 | keepalive 单发无响应 | 超时重传不适用（生成器无定时，显式声明） |
| 7 | NAT/代理/被动模式：无被动模式；TCP 102 直连 | 跨 NAT 读写 | TCP 透明承载，无特殊逻辑 | 不适用（显式声明） |
| 8 | 版本/方言：S7-300/400 经典；S7-1500 认证/优化块；Block 0x1C–0x1E；冗余 | 经典读写/SZL | 经典面全落码 | 方言面明确不实现（§8，不算缺口） |

### 12.2 子表①：命令×响应矩阵（逐格已覆/缺失/不适用；6 命令 × 4 响应 = 24 格）

| 命令 \ 响应 | Ack_Data | Userdata-Resp | 无响应 | 错误头 |
|---|---|---|---|---|
| Setup F0 | ✓ T-S7-004（240 回显） | 不适用 | 不适用 | 缺口→B′-5（协商拒绝面无例） |
| Read 0x04 | ✓ T-S7-001/003（回显+ff） | 不适用 | 不适用 | 缺口→B′-5（越界读 PLC 回错面无例） |
| Write 0x05 | ✓ T-S7-002（位图 OK） | 不适用 | 不适用 | ✓ T-S7-007（04/01 注入） |
| Keepalive 0xFA | 不适用 | 不适用 | ✓ T-S7-005 | 不适用 |
| ReadSZL | 不适用 | ✓ T-S7-006 | 不适用 | 缺口→B′-5（SZL 不存在 0x0a 面无例） |
| error 注入 | ✓ T-S7-007 | 不适用 | 不适用 | ✓（自身即错误头） |

已覆 6 格；不适用 18 格（协议无此组合，逐格显式声明）；缺口 3 格 → B′-5（G-S7-3 修轮内补例或立项）。

### 12.3 子表②：数据形态变体表（33 行）

area 9 行（`80/81/82/83/84/85/86/1C/1D`）：已覆 2（`84` DB 读、`83` M 写）+ 负例 1（`00` 拒绝）；待确认 6（`80/82/85/86/1C/1D`，A′/P4 展开）。
transport-size 请求面 9 行（`01–09`）：已覆 2（`04` WORD、`03` BIT）；待确认 7（A′-2 认领代表面，余 P4 展开）。
errcls 7 行：已覆 2（`00` 成功、`04` 注入）；待确认 5（B′-5）。
returncode 8 行：已覆 2（`ff` 读成功、`00` 写请求保留）；待确认 6（B′-5：`03/05/0a` 优先）。
已覆 9 行；缺口 24 行 = A′认领 4 + B′认领 5 + 待确认 15（P4 逐值展开）。

### 12.4 子表③：商业行为→用例映射表（CORE_MEMORY §4.16）

| 现网行为（S7-300/400） | 用例 | 确认方式 |
|---|---|---|
| PG/OP 建连（TSAP `01 00`/`01 02`，TPDU 1024，PDU 480/240） | T-S7-001/004 | 待确认：重抓包核对（G-S7-7；当前 CR/Setup 字节与单测 hex 一致） |
| DB 块读写（DB1.DBW0 WORD，M100.0 BIT） | T-S7-001/002/003 | 待确认：同上（线性位索引已由 tshark 实测钉死） |
| CPU 状态轮询（Read SZL `0132/0004`） | T-S7-006 | 待确认：同上 |
| 多 PLC 并发会话（独立源端口） | T-S7-009 | 有（distinct 端口断言；交错由 tcp 层定） |

无映射无确认即缺口：TSAP/TPDU/PDU 三参数面 + 读值漂移面（`readValueForItem` 合成值非 PLC 真值，文档化为合成口径）→ G-S7-7。

### 12.5 P1 三路对照（CORE_MEMORY §4.12–4.15）

- 规范路：无公开规范；RFC 1006（TPKT）+ Wireshark `packet-s7comm.c`（字段/值域/ROSCTR=7、Userdata-SZL 语义）为底线。
- 现网路：S7-300/400 抓包（`canon_all.pcap` 15 帧 + `plc_status.pcap`）——**当前盘上不存在**（`/tmp/s7lab/` 仅 `__pycache__`），行为结论暂以 21-s7-design.md 冻结文字为准，P4 前重抓或以 suite 实测回填（G-S7-7）。
- 开源路：snap7（S7ANY/imas 语义参考；其读请求 datlg=0 与本生成器 datlg=1 差异已在基线 §3.13 取舍：保持可预测，tshark 双接受）。
- 不一致取舍：Userdata=0x07（弃早期 0x04 假设）、SZL 走 Userdata（弃 Job 假设）、协议 ID 仅 0x32（弃 0x72/0x71）——三处已由实测裁定（基线 §1.3）。

### 12.6 候选方案对比（§4.17）

| 决策 | 方案 A（采用） | 方案 B（弃） | 取舍理由 |
|---|---|---|---|
| 终结层事件模式 | 复用 legacy 构建函数逐命令产事件（enip 同款） | 链上逐层独立生成 TPKT/COTP/S7 | A 字节级一致、改动最小；S7 三层头紧耦合，拆层无收益 |
| 读响应值 | 确定性合成（`readValueForItem`） | 固定常量回显 | A 使双项读值互异，可断言区分；PLC 真值不可预知，合成口径文档化 |
| 多会话 | 会话整块顺序（多会话展开） | 并发交错 | A 确定性包序可钉包号；交错由 tcp 层 pacer 定，断言用 distinct |
| 未知 kind | 拒绝（`s7_b1_unknown_kind_rejected`） | 静默 read | 拒绝拼写错误，避免假成功 |

## 13. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

证据三选一（文档章节 / 代码行 / 用例号）逐行落位；§1/§3/§12 三行强制展开见 §13.1/§13.3/§13.12（含完整 `spec_json` 样例）。

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 当前 28 例中所有非负例 `spec_json` 顶层仅 `layers`；地址/端口/业务键均住对应层，3 个边界负例验证 presence、游离键和 carrier 拒绝；数量在原 9 个存量正例用例级 `strategy_fc` | 本契约 §13.1/§16 + `s7.json` 实测 |
| §2 策略/任务 | 策略 = 单 S7 流量模板；任务 = 多策略合跑 + 总量封顶；本协议补充例均单流，不伪造任务级动态 | CORE_MEMORY §2 + testcase §2 |
| §3 五件套 | 会话表/事务序列/关联关系/插入位置/时间线见 §13.3；同连接多轮由 `s7_a4_multi_command_sequence` 覆盖，多会话由 `s7_multi_session_ports` 覆盖，保活由 `s7_keepalive` 覆盖 | §13.3 + testcase §2 |
| §4 查规范 | 无公开 RFC；RFC 1006 + Wireshark 解析器源码 + S7-300/400 行为；P1 矩阵 8 行 + 三子表 | §12 |
| §5 依赖与错误 | `DependsOn ["tcp"]`；失败返回 task error；12 个负例逐例带错误锚词 | registry.go:92 / complete.go:456-475 / testcase §4 |
| §6 性能 | 单会话 ≤26 包、单 PDU <480B + 头；pcap/NIC 双路及六类验收见 §15.7 | §15.7 |
| §7 三份文档 | 本文为设计入口，testcase 为用例入口，cases JSON 为机器契约；归档 21-s7 文档仅作基线 | §0 / §16 |
| §8 设计先行 | P4 用例迁移已完成；Go 实现不在本次车道改动范围 | 任务书范围 + git commit 52d7d76 |
| §9 测试三源 | Wireshark 字段面 + 归档冻结表 + 落码实测 + 现网行为待重抓；28 例在 testcase §2–§4 对账 | testcase §2–§4 / G-S7-7 |
| §10 评审闭环 | 本轮完成文档对账与 JSON 局部解析检查；未跑 suite/MCP（任务书禁止） | 本轮自审记录 |
| §11 白话 | S7 是 PLC 的长连接读写对话：先握手协商，再读写/保活，最后关闭 | 文档首段 |
| §12 动态清单 | 四元组动态算法见 §13.12；S7 业务字段目前无动态 allowlist，列 G-S7-6，不虚报支持 | §13.12 / G-S7-6 |
| §13 schema 派生 | registry 5 Fields 与层内嵌套键现状见 §1/§13.1；schema 派生不在本次改动范围 | registry.go:92-100 |
| §14 真实流程 | suite 经 MCP→引擎→tshark；本次未运行，P5 需真实复核包数/字段 | testcase §6–§7 / §15.7 |

### 13.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

| 旧键（P4 前 14 例现状，现全迁层） | 去向 | 说明 |
|---|---|---|
| 顶层 `src_ip`/`dst_ip` | `layers[0].ip.src/dst` | ip 层 Fields 有 `src/dst`（registry.go:31-34） |
| 顶层 `src_port`/`dst_port` | `layers[1].tcp.src_port/dst_port` | tcp 层端口键；dst 缺省 102 由 FieldContract 回填 |
| 顶层 `s7` 子映射（`transport/sessions/commands`） | `layers[2].s7` 同名键 | s7 Fields 有 5 键；`commands` 为 list 型，命令条目内键随 Meta 直传 |
| 顶层 `count` | 无（存量例均无） | 数量走 `strategy_fc: {"type":"flows","value":N}` |
| `sessions` 语义 | `s7.sessions` 住层（多会话展开，不走策略复制） | 静态复制禁令（12.9）：`flows>1` 且四元组静态 → 拒绝；s7 多会话靠 `sessions` 逐会话端口递增绕开 |

目标形状样例（`s7_connect_setup_read` 即此形；`strategy_fc` 为用例级键，与 `spec_json` 同级，见 driver.go:96-99）：

目标形状样例（`s7_connect_setup_read` 改写后，示意非最小可跑配置；`strategy_fc` 为用例级键，与 `spec_json` 同级，见 driver.go:96-99）：

```json
{
  "spec_json": {
    "layers": [
      {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
      {"tcp": {"src_port": 12345, "dst_port": 102}},
      {"s7": {"transport": "tcp", "sessions": 1, "commands": [
        {"kind": "read", "items": [
          {"area": 132, "db_number": 1, "address": 0, "transport_size": 4, "length": 1}
        ]}
      ]}}
    ]
  },
  "strategy_fc": {"type": "flows", "value": 1}
}
```

### 13.3 §3 强制展开：五件套（单载体 TCP 会话）

- 会话表：1 会话 = 1 TCP 连接（`src_port+i` 独立四元组，独立 PduRef 计数器）；双会话例 T-S7-009。
- 事务序列：setup（前置：CC 完成；动作为 F0 Job；成功→READY；失败→会话终止）→ 命令 N（前置：READY；动作依 kind；成功→响应回显；失败→ Validate 拒绝/错误头）。
- 关联关系：无控制-数据分离；请求↔响应由 PduRef 回显关联（`same_as_packet`），SZL 请求↔响应由 szl_id/index 回显。
- 插入位置：终结层事件（tcp 层负责握手/挥手/序号，s7 只产 TCP 载荷字节）。
- 时间线：会话内严格顺序；多会话整块顺序（先会话 0 全流程，后会话 1）；命令间无定时，并发交错不适用（显式声明）。

### 13.12 §12 强制展开：动态字段清单

四元组：`ip.src/dst` + `tcp.src_port/dst_port` 五策略全开（`fixed/inc/rand/list/pattern`，layer_dyn.go:17-19；序号算法 `TupleGenerator.Next` tuple_generator.go:26 + `resolveLayerTuple` layer_dyn.go:770，逐流确定性 + 到尾回绕）。
业务字段（`area/db_number/address/bit/transport_size/length/value/pdu_ref/sessions`）：**全关**（s7 不在 allowlist；层内出现动态对象即 `does not support dynamic`（P6 行 `validate_layers.go:888`；P1 写作时 564））→ G-S7-6（D-S7-85 条目；落地前按 §9.36 现状钉：多 DB 遍历等逐流变面暂由多策略/多会话覆盖）。
静态复制禁令：`flows>1` 且四元组全静态 → 框架拒绝（12.9）；s7 用例 `flows` 恒 1，会话复制走 `sessions`。

### 13-P2 presence 负例形状（链级红例必含①）

`s7` 层条目（`layers[].s7`，可空 `{}`）与顶层 `s7` 子映射并存 = 判死负例 `s7_neg_top_s7_presence_reject`；白名单外 `src_ip` 由 `s7_neg_stray_src_ip` 覆盖；UDP carrier 由 `s7_neg_udp_carrier` 覆盖。收官检查：非负例顶层键=0。

## 14. D-S7-85 P2 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批=定稿）

1. 改哪几个文件：本轮不改 Go；现有接线核对 `registry.go:92` + `strategy_convert.go:1649-1652` + `internal/protocol/s7/`；共享面 `parseSubconfigJSON` 未知键静默仅登记 G-S7-8，不在本车道自改。
2. 接口签名：`Planner.Validate(spec FlowSpec) error`（+未知 kind/transport_size/sessions 三支拒绝）；`buildS7Pair` 默认分支改返回 error（`s7: unknown kind %q`）；其余构建函数签名不变。
3. 数据结构：复用 `core.S7Config/S7Command/S7Item`（types.go:1511-1550）；基线 §5 虚声明键**不补 struct**（文档回修 G-S7-5，不反向加代码）。
4. 主流程：P4 已完成严格层链用例与负路径对账；G-S7-2/G-S7-3(B′-2)/G-S7-4 已在当前实现落地并由 B′ 负例覆盖；G-S7-5/G-S7-6/G-S7-7 与 G-S7-3(B′-5) 仍为文档化缺口，不在本次文档车道修改 Go 代码或运行 suite。
5. 错误分支：12 个负例均带 `error_contains`；其中 5 个原始配置拒绝、3 个层链边界拒绝、3 个新增语义拒绝、1 个层未知键拒绝；`[ip,udp,s7]` carrier 锚词已通。
6. 性能边界：O(n) 流式（单命令内存上界 = 单 PDU <480B + 头；多会话线性；无锁无 sleep；长连接无定时器）；吞吐数字待 P5 基准，不写承诺。
7. 冲突点：`parseSubconfigJSON` 未知键静默（跨协议共享面，不动，上报）；`readValueForItem` 合成值口径冻结（改值即改 3 例 frames hex，先跑后钉）；`sessionBaseRef` 缺省 2 冻结（改即改 pduref 全例）。
8. 回滚：revert 改写提交 + registry 行回退即恢复今日可跑态（今日 suite 若可跑）；校验收紧先行分别提交，可单点 revert。

## 15. P3 测试对接清单与缺口立项（T-S7 草稿输入；正文落 testcase 文件）

T-S7-001~014 ↔ 14 例一一对应（testcase §2）；A′ 4 项 + B′ 5 项见 §15.2。

### 15.1 §3.15 三项逐项一例或立项（无例无项即缺口）

①同连接多轮操作：**半程**——单命令/会话有例（T-S7-001 setup+read 两轮），**多命令序列（read→write→readsZL 同一会话）零覆盖**（cmdlens 1:12/0:2）→ A′-4。②非正常结束：有例（5 负例全为 Validate 拒绝；FIN 关闭由 tcp 层，包数已含）。③长保活：有例（T-S7-005 keepalive 单发无响应）。

### 15.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流/地址族/断言通道六类）

A′（已落地）：A′-1 多 DB 写多项、A′-2 传输尺寸逐值、A′-3 显式 PDU ref、A′-4 多命令序列，分别见 `s7_a1`–`s7_a4`。
B′（已落地为拒绝负例）：B′-1 未知 kind、B′-2 transport_size 越界、B′-3 sessions 越界，分别见 `s7_b1`–`s7_b3`。B′-4 TSAP/AmQ/PDU 配置面缺失（G-S7-5）与 B′-5 错误头协商拒绝面 3 格仍是待实现边界。

### 15.3 9.52 对账两行 + 清单出处声明

清单出处 = Wireshark 解析器字段面 + 21-s7-design.md 冻结表 + 落码实测面 + tshark 1119 字段注册表实测，**非**从用例反推。
**规范逻辑点总数 69（子表① 24 格 + 子表② 33 行 + 八项 8 + 商业行为 4）vs 用例覆盖 24（① 6 + ② 9 + 八项 6 + 商业 3）+ 不适用 20（① 18 + 八项 2：超时重传/NAT）+ A′ 4 + B′ 5 + 待确认 16（② 15 + 商业 TSAP 1）**；24+20+4+5+16 = 69，无遗漏。

### 15.4 3.14 豁免边界审计

不豁免 sessions（多会话 T-S7-009 已覆）；多流并发（多会话展开）与单包多载荷（双 S7ANY 项 T-S7-003）各有例；超时重传/NAT 显式不适用（§12.1 #6/#7）；COTP 分片/认证/Block 传输/冗余为明确不实现（§8）。

### 15.5 三源回指行

Wireshark `packet-s7comm.c`（ROSCTR/Userdata/字段名）→ D-S7-85 §3/§7 → T-S7-001~014（testcase §3/§4）；tshark 实测（1119 字段注册 + 23 用例字段 23/23 命中）→ frames hex 双通道；现网 PLC 行为 → G-S7-7 待重抓。

### 15.6 断言契约核对结论

正例 frames offset：IPv4=54（S7 头内偏移 73/75 两例为 S7ANY/数据区内断言，由 payload 相对偏移 19/21 + 54 导出，s7.json notes 已载明）；IPv6=74（T-S7-008）；`decode_as` P6 m2 结论：tshark 3.6.14 不接受 `tcp.port==102,s7comm`，102 端口原生解码即 COTP/S7COMM，`decode_as` 直接移除（P4 实测依据，lane 报告已载明，接受偏离 P1 字面）。

### 15.7 性能设计与验收（§6.1–6.8 要素）

目标：单会话全序列 ≤ 26 包，单 PDU ≤ 480B+17B 头；并发会话数 ≤16（校验收紧后）；内存 O(单 PDU) 流式、无全量收集、无共享状态、无锁；pcap（`/tmp/mcp-pcaps/s7/`）+ NIC（`tcp port 102`，网口 enp135s0f0np0）双路同一契约；六类场景 P5 跑测（基线/目标/压力/长连保活/多会话交错/背压）；断言实际包数/字段/字节，不只"任务未报错"；超预算即不合格。吞吐数字待 P5 基准，不写承诺（§6.5）。

### 16. 存量与补充用例审计去向（28 例；P4 已落地）

原 14 例全部合入；补充 14 例新增覆盖 presence/白名单/载体、A′/B′ 与枚举矩阵。机器契约完整逐例去向见 `docs/protocols/s7/testcase.md` §5，JSON ID 顺序为唯一权威。

| 范围 | 去向 | 改写动作 |
|---|---|---|
| 原 1–9 正例 | 合入 | 严格层链 + `strategy_fc: flows=1`，保留断言 |
| 原 10–14 负例 | 合入 | 严格层链 + `error_contains` |
| `s7_neg_*` / `s7_a*` / `s7_b*` / 枚举例 | 新增 | 见 testcase §5，分别覆盖层链边界、A′/B′ 和枚举矩阵 |

去扁平改写禁搬运旧期望值：P4 已以落盘实测断言为准；P5 若改生成器，须重新校准。

## 17. 缺口立项清单（现存缺口，不把已落地项伪报开放留白）

| 立项号 | 缺口 | 确认方式 | 去向 |
|---|---|---|---|
| G-S7-1 | 去扁平改写：存量例已迁层；presence/白名单/载体红例已加入；`decode_as` 已按原生 102 解码结论移除 | 代码实读 + 本契约 §13.1/§16 | **已关闭**：P4，28 例三方对账 |
| G-S7-2 | 未知 kind 已由 Planner.Validate 与生成器 default 双重拒绝 | 代码实读（planner.go:29-37；layer_gen.go:152-156） | **已关闭**：`s7_b1_unknown_kind_rejected` |
| G-S7-3 | `transport_size` 现已校验 0x01–0x09；Address 0xFFFF 上界保持现实现状；错误头协商拒绝 3 格仍缺 | 代码实读（builder.go:355-363） | **部分关闭**：B′-2 已落地；B′-5 保留为待实现边界 |
| G-S7-4 | `sessions` 现已校验负值与 >16；0 仍按生成器缺省为单会话 | 代码实读（planner.go:23-27；layer_gen.go:28-31） | **已关闭**：`s7_b3_sessions_over_rejected` |
| G-S7-5 | 基线 §5 虚声明字段（TSAP/TPDUSize/MaxAmQ/PDULength/ItemCount/Direction/SkipResponse/Item.Value/字符串 transport_size/`peers/conns`）与 struct 矛盾 | struct 实读（types.go:1511-1550） | 文档回修（删虚声明，不反向加代码）；B′-4 |
| G-S7-6 | 业务字段动态全关（s7 不在 allowlist，layer_dyn.go:17-71） | 代码实读 + §12 评估 | D-S7-85 条目；落地前按 §9.36 现状钉 |
| G-S7-7 | 证据链灭失（`canon_all.pcap`/`plc_status.pcap` 不在盘）+ 无公开规范（三路对照规范路缺）+ 商业行为 4 项待重抓确认 | 文件系统实测 + 抓包 | P4 前置：重抓 S7-300/400 会话或以 suite 实测回填；`readValueForItem` 合成值口径冻结文档化 |
| G-S7-8 | 跨协议 `parseSubconfigJSON` 未知键静默仍属共享面；S7 负例锚词已全部补齐 | cases 实测 + helpers 实读 | **部分关闭**：S7 负例已关闭；共享严格解码需主线程批处理 |

## 18. P1/P2/P3 对抗自重审结论（10.11；过 3 轮，末轮干净）

- **P1（八项矩阵 + 三子表）**：R1 抓 4 项——①子表①初稿 6×3=18 格漏"错误头"列 → 改 6×4=24 格复算（6+18+缺口3并入B′-5）；②子表②初稿 area 漏 `0x80` → 补 9 行，总数 33 复算；③#4 行"MaxAmQ 可配"与 struct 矛盾 → 改虚声明并立 G-S7-5；④三路对照初稿写"plc_status.pcap 已核"→ 实测文件不在盘 → 改待重抓 G-S7-7。R2 逐格回读 + 行号实读复核（registry.go:92/protocols.go:50/strategy_convert.go:1382/translate:108/generator.go:338/planner.go:13/builder.go:339；P6 m1 续漂：protocols 50→54、strategy_convert 1382→1544，锚词逐字在）。R3 末轮干净。
- **P2（D-S7-85 八要素）**：R1 抓 3 项——①初稿"新建 builder 文件"→ 实为零新建（复用 4 文件），改接线核对口径；②初稿回滚写"revert 单测"→ 改全量 revert 序；③未知键严格解码初稿列车道自改 → 改上报主线程（禁令 §6.1）。R2 接线行号逐条实读复核。R3 末轮干净。
- **P3（testcase §7 + §15/§16/§17）**：R1 抓 4 项——①9.52 初稿总数 61（漏商业 4 + 八项 8 口径混表头）→ 改 69 复算（24+20+4+5+16）；②§3.15①初稿写"有例"→ cmdlet 普查 `cmdlens {1:12, 0:2}` 多命令序列零覆盖 → 改半程 + A′-4；③负例初稿称"带锚词"→ 实测 expect 仅双键无 `error_contains` → 改 G-S7-8；④keepalive 包数 notes"7"与 `packet_count:12` 矛盾 → 记入 §16 #5 先跑后钉。R2 核 23 字段对 tshark 注册表 23/23 命中、包数序列、offset 四档（54/73/75/74）。R3 末轮干净。

三阶段合计修正 11 处（4 矩阵口径、3 P2 边界、4 对账/覆盖），末轮均干净。

### 18.1 文档逐条自核对结论（10.1：对规范逐条核对）

RFC 1006（TPKT）→ §3；Wireshark 解析器（ROSCTR/字段/值域）→ §3/§7/§12.3；S7-300/400 行为（会话序/TSAP/PDU）→ §2/§12.4（待重抓项挂 G-S7-7，不写死）；落码实测（行号/拒绝串/单测 hex）→ §1/§5/§10。无新造规范结论；未改基线 21-s7 任何冻结字节/取值。

### 18.2 与旧文档逐条核对结论（10.2）

21-s7-design.md（1210 行）逐节核对：S1–S12 模板/§2 表/§9 错误表原样冻结引用；§5/§8.9 与 struct 矛盾 9 处显式登记为 G-S7-5 而非静默改写；21-s7-testcase.md 14 ID/包数/断言现状原样载入 §16（#5 包数矛盾显式标注）。无旧条目被静默删除。

## 19. 文档闭环修订（2026-10-01）

按当前代码、三件套与 CORE_MEMORY 逐项核对：修正实现规模（五个 Go 文件、884 行）；将未知 kind、transport_size、sessions 的过期“未校验/静默”描述改为已落码行为；G-S7-1/G-S7-2/G-S7-4 关闭，G-S7-3/G-S7-8 标为部分关闭，仅保留真实的 B′-5、G-S7-5/G-S7-6/G-S7-7 与共享解码边界。JSON 实测仍为 28 例（16 正 + 12 负），负例均为纯双键契约。

自审 R1：逐段对照 `planner.go`、`layer_gen.go`、`builder.go`、`types.go`、注册表与 JSON ID/计数，发现并修正旧缺口状态和代码规模；确认未改 JSON 机器契约。R2：复读三份文件，核对 28/16/12、12 个负例锚词、三方顶层键与剩余缺口，未发现新增矛盾。**SELF_REVIEW: passed 2 rounds, last round clean.**

## 修订记录

- v1.1.0（2026-10-01，P4 文档闭环）：当前代码、JSON 与 CORE_MEMORY 三方对账。修正实现规模为五个 Go 文件/884 行；G-S7-1/G-S7-2/G-S7-4 关闭，G-S7-3/G-S7-8 标为部分关闭；未知 kind、transport_size、sessions 改为已落码行为。JSON 保持 28 例（16 正 + 12 负）。
- v1.0.1（2026-09-28，P6 m1/m2 回填）：m1 行号续漂登记（protocols 50→54、strategy_convert 1382→1544，锚词逐字在；P1 冻结版不改）；m2 `decode_as` 移除结论落盘（tshark 3.6.14 原生解码，偏离 P1 字面已接受）。
- v1.0.0（2026-09-26）：P1–P3 初稿。P1 矩阵 8 行 + 三子表（24 格/33 行/商业 4）+ 三路对照 + 候选方案 4 项；门1 十四行（三行强制展开 + spec 样例 + presence 形状）；D-S7-85 八要素；T-S7-001~014 + A′ 4 + B′ 5；9.52 对账 69=24+20+4+5+16；缺口 G-S7-1…8；自重审 3 轮 11 修正末轮干净。

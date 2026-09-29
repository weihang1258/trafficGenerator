# #102 thrift（Apache Thrift Binary Protocol，TBinaryProtocol）测试用例契约

> 版本：v1.1.0（P-PIPE 代码阶段收官：层链迁移 + MCP/pcap 18/18）
> 日期：2026-09-30
> 配套设计：`docs/protocol-designs/102-thrift-design.md` v1.1.0（D-THRIFT-1）
> 旧基线：`docs/protocol-designs/30-thrift-testcase.md` v1.0.0（18 例；思路继承不搬码）
> 机器契约：`trafficgen/test/protocol_pcap/cases/thrift.json`（18/18 ID 与本版 §2 一致，顺序一致；7 条正例为纯层链，6 条负例保留故意 dirty 键并命中 flat 拒绝锚词）
> 白话一句：**十三条检查：七条看正常收发（一问一答、报错返回、单向通知、结构参数、各种数值、新网段、两条连接），六条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **13 个唯一语义 ID：7 正 + 6 负**（继承旧稿计数，负例 N-1…N-6）。派生规则：设计 §3 每个线格式条款、§5 每个事务/派生规则、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-30 机读实测）**：7 条正例顶层仅 `layers`（S7 另含 `strategy_fc`），层形 `[ip,tcp,thrift]`；6 条原始负例保留 dirty 键以验证 flat 拒绝，另新增 5 条纯层链协议负例覆盖 Thrift planner 校验；7 正例 `expect` 均含 `packet_count`；6 负例 `expect` 键集合严格为 `{expect_error,error_contains}`（干净）。

**历史迁移记录**：本形状是**违规形**（§1.4/§1.11：`layers` 与顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/`thrift` 并存）。按顶层白名单（`{layers, strategy_fc, ttl, flow_control, output, output_config, group_id}`）机读：**非负例顶层键 = 41 处残留，全部违规**。**且经链路实读，该形状今日在 MCP 建策略即 400**：`ValidateStrategy` 无条件调 `CheckProtoFlat`（`schema/semantic.go:130`），顶层四元组/count 任一出现即拒——**迁移后的 18 例已可经 MCP 跑通**（详见 §8.2）。包数与断言值本身有效，形状已完成 P4 迁移。

**输出契约（pcap/NIC 双输出）**：设计契约 = 两路径共用同一 cases JSON 与断言集（`tcp.dstport/srcport`、`tcp.len`、`ipv6.src/dst`、offset 54/74 frames hex），不设仅单路径可用的断言。**现状诚实标注（隔离审查实测）**：存量 13 例 `nic_capture` 计数 = **0**——**今日只有 pcap 侧实证**，NIC 路径为设计契约尚未落地（P4 补 `nic_capture` 开关用例后方可声称双输出）。

**TSHARK 基线**：本机 tshark 3.6.14 **有 thrift dissector**（`tshark -G fields | awk -F'\t' '$3 ~ /^thrift\./'` = **43 字段**，含 `thrift.mtype`/`thrift.method`/`thrift.seq_id`/`thrift.type`/`thrift.fid`/`thrift.i32`/`thrift.str_len`）。**存量 13 例当前只用 frames hex + `tcp.*`/`ipv6.*` 通道**；`thrift.*` 字段为增强候选（G-THRIFT-6，须先跑后钉 dissector 口径，不许凭字段名臆造）。

**动态字段禁止硬编码**：生成期值用 `same_as_packet`/`distinct_values`/`nonzero` 断言（S7 端口聚合已用）。

**包数约定**：单流 = 3（握手）+ N（消息帧数）+ 4（FIN 四包挥手）。数据帧从帧 4 起；实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count。**自动派生**：无显式响应的 `CALL` 会补一条空 `REPLY`（设计 §5 派生规则①），故 CALL 单独出现时 N 会 +1（S7 的 `ping` 即此形）。

**保活/重试/RST 口径**：TBinaryProtocol 无内建保活帧，不设正例亦不得进负例；RST 为框架 tcp 层能力，本协议层不新增断言（A′ 补例除外）；正例恒 FIN 优雅终止。

## 2. 原子用例索引（13 ID = 7 正 + 6 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count |
|---:|---|---|---|---:|
| 1 | `thrift_call_reply` | 正 | §3.2/§5：CALL→REPLY 基线 | 9 |
| 2 | `thrift_exception_reply` | 正 | §3.2/§7：CALL→EXCEPTION | 9 |
| 3 | `thrift_oneway_call` | 正 | §5：ONEWAY 无响应 | 8 |
| 4 | `thrift_containers` | 正 | §3.3：LIST/SET/MAP | 9 |
| 5 | `thrift_scalar_types` | 正 | §3.1：8 种标量 + BINARY | 9 |
| 6 | `thrift_ipv6_echo` | 正 | §2：IPv6 独立用例 | 9 |
| 7 | `thrift_multi_sessions` | 正 | §5：两流展开（flows=2） | 18 |
| 8 | `thrift_neg_truncated` | 负 | §7：N-1 截断 | — |
| 9 | `thrift_neg_unknown_type` | 负 | §7：N-2 未知类型 | — |
| 10 | `thrift_neg_negative_length` | 负 | §7：N-3 负长度 | — |
| 11 | `thrift_neg_negative_container_count` | 负 | §7：N-4 负 count | — |
| 12 | `thrift_neg_bad_message_type` | 负 | §7：N-5 非法 message type | — |
| 13 | `thrift_neg_bad_port` | 负 | §7：N-6 非法端口 | — |

T-编号对照：T-THRIFT-S1…S7 ≡ #1…#7；T-THRIFT-N1…N6 ≡ #8…#13（与设计 §9 一一对应）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count` + 载体断言 + frames 断言；应用 payload hex 均可由 fixture 精确预算。

### 3.1 `thrift_call_reply`（9）

`add` CALL seqid=1（field 1/2 为 I32 值 1/2）→ REPLY 同 method/seqid（result field 0 = 3）。帧 4（offset 54）hex `80 01 00 01 00 00 00 03 61 64 64 00 00 00 01 08 00 01 00 00 00 01 08 00 02 00 00 00 02 00`（30B）；帧 5 hex `80 01 00 02 00 00 00 03 61 64 64 00 00 00 01 08 00 00 00 00 00 03 00`（23B）。`tcp.dstport=9090`（帧 4）+ `tcp.len` 30/23（帧 4/5）；`has_handshake`/`negotiated`/`terminates`/`has_payload` 全 true。严格头 `80 01 00 0X` + method 长度 `00 00 00 03` + `add` + seqid 是核心锚点。

### 3.2 `thrift_exception_reply`（9）

`divide` CALL seqid=7（参数 1/0）→ EXCEPTION 同 method/seqid（message=`division by zero`、type=6）。帧 4/5 断言 `tcp.dstport=9090` + `tcp.len` 33/49。response strict message type=**3**，异常 struct 的 id=1 为 STRING、id=2 为 I32。**注意**：异常 `type=6` 是异常字段的 I32 值，不是 message type——这是专门防止字段层级混淆的 observable 断言。

### 3.3 `thrift_oneway_call`（8）

`notify` ONEWAY seqid=4（STRING field id=1 值 x）。唯一应用数据帧以 `80 01 00 04` 开始（message type=4）；`tcp.dstport=9090` + `tcp.len=27`；**绝不生成 REPLY**（8 = 3+1+4）。握手与终止仍由 TCP 层负责。

### 3.4 `thrift_containers`（9）

`describe` CALL seqid=1（LIST<I16>[1,-2]、MAP<STRING,I32>{a:7}、SET<STRING>{x,y}）。帧 4 断言 `tcp.dstport=9090` + `tcp.len=69`；payload 依次出现 LIST type=15/elem=6/count=2、MAP type=13/key=11/value=8/count=1、SET type=14/elem=11/count=2；count 与 -2 均按大端 i32/i16 读取（i16 负值 `ff fe`）。

### 3.5 `thrift_scalar_types`（9）

一个 `scalars` CALL，覆盖 BOOL true、BYTE -1、DOUBLE 3.5、I16 -2、I32 -3、I64 -4、STRING x、BINARY `00 ff`。帧 4 断言 `tcp.dstport=9090` + `tcp.len=79`；每个 field header 的 TType、i16 ID 和值宽度可由帧锚点重算；BINARY 长度为 2、payload `00 ff` 不作 UTF-8 替换；DOUBLE 大端 bytes `40 0c 00 00 00 00 00 00`。

### 3.6 `thrift_ipv6_echo`（9）

IPv6 `2001:db8::1`→`2001:db8::2`，`echo` CALL/REPLY seqid=9（STRING hello）。帧 4 断言 `ipv6.src`/`ipv6.dst` + `tcp.dstport=9090`；应用帧 offset **74**（14+40+20），CALL strict header + STRING 长度 5 + `hello` + STOP。TCP 校验和覆盖 IPv6 伪头。

### 3.7 `thrift_multi_sessions`（18）

`strategy_fc={"type":"flows","value":2}`（顶层过渡形，P4 转 `flow_control`）；每流 `ping` CALL/REPLY seqid=1，2 流 × 9 包 = 18。`tcp.srcport` 聚合恰 `["12345","12346"]`（`distinct_exclude:["9090"]` 滤下行）；`tcp.dstport` 聚合恒 `["9090"]`（`distinct_exclude` 滤 12345/12346）；帧 4 hex `80 01 00 01 00 00 00 04 70 69 6e 67 00 00 00 01 00`。不逐包定位（多流调度无固定包位）。**seqid 隔离当前无跨流关联断言**，须在实现集成测试补充（§8.2 第 5 条）。

**正例总则**：`wire_fault` 缺席的正常配置、BINARY 的 `value_b64` 合法值、`ONEWAY` 无响应、`EXCEPTION` 的 `exception.type` 均为正例形态；只有配置/线格式/长度错误进入负例。

## 4. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；`expect` 键集合**严格为** `{expect_error,error_contains}`。锚词与设计 §7 表一一对应、同序：

| ID | 故障输入 | `error_contains` | 落码锚点 |
|---|---|---|---|
| `thrift_neg_truncated` | `wire_fault{kind:"truncate",at:"string_bytes"}` | `truncated` | `planner.go:56` |
| `thrift_neg_unknown_type` | field `type_code:99` | `unknown field type` | `planner.go:43` |
| `thrift_neg_negative_length` | `wire_fault{kind:"negative_length",field_id:1}` | `negative length` | `planner.go:58` |
| `thrift_neg_negative_container_count` | `wire_fault{kind:"negative_container_count",field_id:1}` | `negative container count` | `planner.go:60` |
| `thrift_neg_bad_message_type` | message `type_code:9` | `invalid message type` | `planner.go:30` |
| `thrift_neg_bad_port` | `dst_port:70000` | `port` | 层字段 schema 范围校验（`registry.go:67` Max 65535 → `complete.go:325`）。**实测文案**（隔离审查）：`layers: layer "tcp" field "dst_port" = 70000 invalid: out of range [0,65535]` **含 "port"** → 锚词仍匹配，迁移后**无需重钉** |

**负例原子性**：每例单一故障注入；单次执行不得混注。锚词与落码逐字一致（机读核对通过）。

**未落码的负例分支（不得今日建例）**：E-07（CALL/REPLY method·seqid 不配对）、E-08（struct 缺 STOP、重复 field ID、字段值截断）——`planner.go` Validate 无对应分支（grep 实测），**建例会真绿 = 假通过**，登记 G-THRIFT-3，实现后按「失败用例先行」补。

**不得误报的合法协议事件**：`ONEWAY` 无响应（S3 正例，非"缺响应"）；`EXCEPTION` 的 `type=6`（S2 正例，是异常字段值）；容器 `count=0`（合法，A′ 补例）；BINARY `value_b64` 合法值（S5）。

## 5. 覆盖与对账

### 5.1 三源回指行

Apache Thrift TBinaryProtocol spec（§10）+ D-THRIFT-1（设计 §11）+ tshark 通道实测（43 个 `thrift.*` 字段存在，**存量未用**，按设计 §3.4 诚实标注）→ 13 ID（本契约 §2）。第三源"已确认现网行为"当前 = **spec 条款号级引用待补**（G-THRIFT-7，按 §5.5 不写死进实现）。

### 5.2 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **TBinaryProtocol spec + 旧基线契约 + 仓库落码反推 + tshark 字段表实测**，**非纯规范反推**（旧稿 §6 已给 TType 全表与错误行，本版逐条回对落码）。
- **对账两行**（模型与 moxa §5.2 同构：**要求总数 = 覆盖 + 明确不解决 + 开放立项**；计数由脚本 `/tmp/pipe/recon.py` 从设计文档表格机读生成，非手算）：
  - **要求逻辑点总数 = 75** = 八项 8 + 矩阵 15 格 + 变体 29 行 + 商业映射 10 行 + 用例形状 13 点；
  - **用例覆盖数 = 56** = 八项 6 + 矩阵已覆 10 + 变体已覆 20 + 商业已覆 7 + 形状已覆 13；
  - **明确不解决 = 5** = 八项 2（§10.1 第 6 超时与活性 / 第 7 NAT 被动模式）+ 商业 3（Compact / JSON+THeader / 服务端业务语义）；
  - **开放立项 = 14** = 矩阵 A′ 5 + 变体 A′ 9；
  - 校验：56 + 5 + 14 = **75** ✓（脚本 `assert` 闭合通过）。逐表核对：§10.1（8 行 = 6 覆 + 2 不解决）/ §10.2（15 格 = 10 覆 + 5 立项）/ §10.3（29 行 = 20 覆 + 9 立项）/ §10.4（10 行 = 7 覆 + 3 不解决）——四表零空格。
  **粒度声明**：行/格粒度每点 1 计；缺口 G-THRIFT-1…G-THRIFT-10 为条目附注，不另计行（G-THRIFT-9 已撤销、G-THRIFT-10 为结果文档过期登记，见设计 §14）。**反查全绿 ≠ 覆盖全**（§9.52 原文）。
- **门3 抽查候选**：最复杂用例 = **#4 `thrift_containers`**（三类容器嵌套 + 负 i16 + 大端 count 多通道）；交织维度 = 容器(3)×元素类型(4)×count 语义×字段 ID 负值。若按 9.49/9.50 下限偏弱在"多流/并发"面，**建议门3 抽 #4 + #7**（`thrift_multi_sessions` 补多流面）。

### 5.3 T-编号与旧 id 对照（设计 §9 全表摘要）

`thrift_call_reply` ≡ T-THRIFT-S1；`thrift_exception_reply` ≡ T-THRIFT-S2；`thrift_oneway_call` ≡ T-THRIFT-S3；`thrift_containers` ≡ T-THRIFT-S4；`thrift_scalar_types` ≡ T-THRIFT-S5；`thrift_ipv6_echo` ≡ T-THRIFT-S6；`thrift_multi_sessions` ≡ T-THRIFT-S7；`thrift_neg_truncated` ≡ T-THRIFT-N1；`thrift_neg_unknown_type` ≡ T-THRIFT-N2；`thrift_neg_negative_length` ≡ T-THRIFT-N3；`thrift_neg_negative_container_count` ≡ T-THRIFT-N4；`thrift_neg_bad_message_type` ≡ T-THRIFT-N5；`thrift_neg_bad_port` ≡ T-THRIFT-N6。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接多消息（S4/S5 各 3 条 message，含自动补 REPLY）→ 更多轮次（A′ `thrift_multi_messages`） | 已覆 #4/#5；A′ 补例 **`thrift_multi_messages`** |
| ② | 非正常结束 | 正常 FIN 全正例；应用层正常终止报文 = **无**（TBinaryProtocol 无终止类型）；网络层异常 = RST | A′ 补例 **`thrift_abort_rst`**（`tcp.rst=true`，框架能力，本层零断言）+ 负例 6 条 |
| ③ | 长保活 | 协议层无 keepalive 语义（设计 §4 显式不适用）；长会话 = 同连接多消息 + 多流展开 | #4/#5（>2 条 message）/#7 承载 |

无空项：① 有已覆例 + 1 条 A′ 补例；② 有负例面 + 1 条 A′ 补例；③ 有 #4/#5/#7。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 层链化 | translate `case "thrift"` 层内分支 + `CheckProtoFlat` presence 判死 | G-THRIFT-1/G-THRIFT-2，用例 #1–#13 全依赖 |
| 数据边界 | BOOL false | `thrift_bool_false`（变体 2） |
| 容器边界 | 容器 `count=0` | `thrift_empty_containers`（变体 13） |
| 多事务面 | 同连接更多轮 message | `thrift_multi_messages`（§3.15①） |
| 分段面 | 超 MSS 单消息分段 | `thrift_oversize_segment`（设计 §6 压力上限） |
| 端口面 | dst_port 缺省补齐 9090 | `thrift_default_port`（删键不断言值） |
| 地址族面 | 异族混写/非法 IP | `thrift_neg_mixed_family`（validator 有分支 `planner.go:65-70`，今日无例） |
| 未落码校验 | 重复 field ID / 缺 STOP | `thrift_neg_duplicate_field_id` + `thrift_neg_missing_stop`（G-THRIFT-3 落码后） |
| 非正常结束 | `tcp.rst` 补例 | `thrift_abort_rst`（②） |
| 断言增强 | tshark `thrift.*` 43 字段通道 | G-THRIFT-6（先跑后钉） |
| 双输出落地 | `nic_capture` 开关用例（今日 0 例，仅 pcap 侧实证） | A′ 补 `nic_capture` 用例，NIC 侧（`enp135s0f0np0`）跑同一断言集 |
| 现网面 | spec 条款号级引用 | G-THRIFT-7 |

**B′（框架面）**：`CheckProtoFlat` thrift presence 分支（G-THRIFT-2，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态（G-THRIFT-8，allowlist 无 `thrift` 行）/ `transport` 死键（G-THRIFT-4，**P4 删键**——CORE_MEMORY §1.12，零消费字段不许登记保留，**非二选一**）/ BINARY 合流（G-THRIFT-5，P4 裁定）。进设计 §14，「明确不解决 + 迁入计划」。

### 6.3 3.14 豁免边界审计

**有长连接载体 → `sessions[]` 不豁免**（设计 §12.3 会话表 s1/s2；多流展开 #7）；多流并发 #7；单包多载荷 = **不适用**（thrift 一条 message 一个载荷，无多 question/多 RR 类形态，如实声明）。

## 7. 实现后执行建议

1. **P4 顺序**：G-THRIFT-1 已完成：translate 分支、正例迁移、负例保留与 18 条全量 P5 均已闭合。
2. **实测顺序**：先 S1/S3（严格头 + 包数基线），再 S4/S5（容器与标量 hex），再 S2（异常字段层级），再 S6（IPv6 offset 74），最后 S7（多流聚合）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=thrift` 全量不是增量）；门2④ 反查绿后进 P6。
4. **迁移后的 18 例已可经 MCP 跑通**（§8.2 第 1 条）——当前二进制已完成 P5：18/18 pass；NIC capture 仍未执行。

## 8. 存量审计（13 例逐条去向）

### 8.1 存量实测面（2026-09-28）

`cases/thrift.json` **13 例**：7 正带 `packet_count`（9/9/8/9/9/9/18）；6 负 `expect` 键集合严格 `{expect_error,error_contains}`；S5 断言 DOUBLE 大端 8 字节；S4 断言容器类型码与负 i16；S6 断言 `ipv6.*` + offset 74；S7 断言端口聚合 + `strategy_fc`。

### 8.2 迁移前审计与收官验收记录

1. **存量跑的是过渡态违规形（非负例顶层键 41 处残留），且今日建策略即 400**：`spec_json` 的 `layers=[{tcp:{}},{thrift:{}}]` 只是**空壳**（两层 config 恒 `{}`），真实配置住顶层 `thrift` 子映射 + 顶层四元组 + `count`。经链路实读：`ValidateStrategy` → `validateStrategySemantic`（`schema/semantic.go:52`）→ 无条件 `CheckProtoFlat`（`:130`）→ 顶层 `src_ip/dst_ip/src_port/dst_port/count` 任一存在即 `fail` → **策略创建 400**。故存量 13 例**今日既非绿也非红，而是跑不起来**（已完成迁移）。
2. **层内配置被静默丢弃 → 任务假成功（自行核实；比"跑不通"严重）**：`translateTerminalConfig`（`chain_planner_translate.go:695`）是逐协议 `if term.Name == "X"` 链 + `switch term.Name`（`:855`，73 个 case）结构，**两处均无 thrift**；`Thrift` 在本包外共 4 文件引用（`types.go` 类型/槽位、`generator.go:353`、`strategy_convert.go:1749`、`chain_planner_translate.go:122` Meta 直传读值），**无 FieldContract/通用通道兜底**（`term.Config` 由各 case 各自 `completedConfig` 消费）。故层内 `layers[i].thrift.messages` 今日**不翻译且无报错**：`spec.Thrift` 恒 nil → 默认 `CALL ping` 流。**隔离审查实测 `ValidateLayers` 返回 `err=nil`、`Plan` 产 9 包默认 `ping`**——用户配 `add` 却发出 `ping`，零报错 = **静默假成功**（§1.9 类问题）。这是 G-THRIFT-1 的第二半。
3. **旧稿状态声明全部过时**：`30-thrift-*` 称"仅设计阶段、尚未实现"，实为四文件 1861 行已落码（设计 §0 表 8 项校正）。
4. **旧稿 E-07/E-08 仍待实现**：设计 §6 标"待实现扩展负例"，落码 Validate 确认无对应分支——**继承待实现边界**，不是"已有覆盖"。
5. **S7 缺跨流 seqid 关联断言**：旧稿 testcase §3 已声明"当前验证器没有跨流 seqid 关联断言，必须在实现集成测试补充"——本版继承，登记 A′（§6.2）。
6. **`transport` 死键**：registry 注册 + struct 有字段 + planner/builder 零消费（grep 实测）——用例不得携带（G-THRIFT-4）。裁定与设计 §8/§14 一致：**P4 删键**（registry Fields 删 `transport` + struct 删字段 + 重跑 schemagen），CORE_MEMORY §1.12 不许登记保留，非二选一。
7. **结果文档已更新（G-THRIFT-10 已关闭）**：`trafficgen/docs/protocol-pcap-test/thrift.md`（**tracked 产物**）写 `Cases: 18 — pass 18, fail 0, error 0`，但该文件末次提交 `91f2487`（**2026-08-30**），**早于**判死提交 `0417be5`（2026-09-13，扁平判死泛化全协议 `CheckProtoFlat`）；`trafficgen/docs/protocol-pcap-test/thrift/` **目录不存在**（**0 个 pcap**）。该 18/18 pass **是过期产物，不代表今日可跑**——今日 13 例经 MCP 建策略 **400 全红**（全部被拒；**非负例口径顶层旧键残留 41 处**，即 §8.2 #1 的 400 实证；全例口径 77 = 正 41 + 负 36，**两口径不得混用**）。归属：**代码阶段**（P5 重跑套件后重生成该产物）。登记见设计 §0 产物过期登记 + §14 G-THRIFT-10。

### 8.3 逐条去向表（13 行）

| 存量 id | T-编号 | 去向 | 改写动作（G-THRIFT-1 落地时） |
|---|---|---|---|
| `thrift_call_reply` | T-THRIFT-S1 | **改写** | 目标形状化（`ip` 层地址 + `tcp` 层端口 + `thrift` 层 messages）；packet_count 9 不变 |
| `thrift_exception_reply` | T-THRIFT-S2 | **改写** | 同上；异常字段层级断言保留 |
| `thrift_oneway_call` | T-THRIFT-S3 | **改写** | 同上；8 包不变 |
| `thrift_containers` | T-THRIFT-S4 | **改写** | 同上；容器 hex 断言保留 |
| `thrift_scalar_types` | T-THRIFT-S5 | **改写** | 同上；DOUBLE/BINARY 断言保留 |
| `thrift_ipv6_echo` | T-THRIFT-S6 | **改写** | 地址迁 `ip` 层；offset 74 不变 |
| `thrift_multi_sessions` | T-THRIFT-S7 | **改写** | `strategy_fc` 转正 `flow_control`；四元组留空走保底递增 |
| `thrift_neg_truncated` | T-THRIFT-N1 | **改写** | `thrift` 子映射迁层内；锚词不变 |
| `thrift_neg_unknown_type` | T-THRIFT-N2 | **改写** | 同上 |
| `thrift_neg_negative_length` | T-THRIFT-N3 | **改写** | 同上 |
| `thrift_neg_negative_container_count` | T-THRIFT-N4 | **改写** | 同上 |
| `thrift_neg_bad_message_type` | T-THRIFT-N5 | **改写** | 同上 |
| `thrift_neg_bad_port` | T-THRIFT-N6 | **改写** | `dst_port` 迁 `tcp` 层（值 70000 保留以触发端口校验） |

无"作废不注原因"：0 作废，0 等价覆盖（全部改写 + A′ 新增）。

## 9. 覆盖反查门建议断言行（供主线程合后登记 coverage_gate.py；本车道不碰该文件）

按 `check_moxa`（`trafficgen/tools/coverage_gate.py:8953`）范式，thrift 反查块建议行如下（`rows.append((检查名, 通过?, 证据))` 形状）：

| # | 检查名 | 建议断言 | 证据列 |
|---:|---|---|---|
| 1 | 白名单收 thrift | `'"thrift": true' in protocols.go` | 在列 |
| 2 | translate case thrift（层 config → spec.Thrift） | `'case "thrift":' in translate` 且 `"spec.Thrift"` 赋值在案 | P4 落码后填 |
| 3 | FlowMeta.Thrift 直传 | `re.search(r"Thrift:\s+spec\.Thrift\b", translate)` | 在案（`:122`） |
| 4 | FlowMeta.Thrift 字段 | `re.search(r"Thrift\s+\*core\.ThriftConfig", generator.go)` | 在案（`:353`） |
| 5 | FlowSpec.Thrift 字段 | `re.search(r"Thrift\s+\*ThriftConfig", types.go)` | 在案（`:1716`） |
| 6 | registry thrift 行 | `'DependsOn: []string{"tcp"}' in reg_block` 且 `'"tcp.dst_port": "9090"'` 且 `'"transport"'` 且 `'"messages"'` | 在案（`:780-784`） |
| 7 | main.go 空白导入 + ChainPlanner(thrift) | `"internal/protocol/thrift" in mn and 'NewChainPlanner("thrift")' in mn` | 在案（`:163`/`:513`） |
| 8 | CheckProtoFlat 顶层 thrift presence 判死 | `"no longer accepts a top-level thrift sub-config" in strategy_convert.go` | P4 落码后填（G-THRIFT-2） |
| 9 | strategy_convert thrift 目的端口缺省 9090 | `re.search(r'setDefaultDstPort\(&spec, cfg, 9090\)', sc)` | P4 落码后填 |
| 10 | planner 目的端口缺省 9090 | `'spec.DstPort = 9090' in planner.go` | 在案（`:79`） |
| 11 | generated schema thrift 条目 | `entry["depends_on"] == ["tcp"] and len(entry["fields"]) == 2` | 在案（与 registry 同代） |
| 12 | 顶层 thrift presence 零残留（非负例） | 非负例中 `spec_json` 有 `layers` 且带顶层 `thrift` 子映射的 id 为空 | P4 迁移后应零残留 |
| 13 | 非负例顶层旧键零残留 | 非负例 `spec_json` 顶层键 ⊆ 白名单 `{layers, strategy_fc, ttl, flow_control, output, output_config, group_id}` | P4 收官后为零（正例；负例故意保留 dirty 键） |
| 14 | planner 六条锚词在案 | `"invalid message type"`/`"unknown field type"`/`"truncated"`/`"negative length"`/`"negative container count"`/`"at least one message required"` 各在 `planner.go` | 在案 |
| 15 | BINARY 与 STRING 共用类型码 | `'case "STRING", "BINARY":' in builder.go` | 在案（`:57`，G-THRIFT-5 裁定前钉现状） |
| 16 | 自动补空 REPLY 派生规则 | `hasMatchingResponse` 在 `layer_gen.go` 且 `mt == MCall` 分支在 `planner.go` | 在案（`:131`） |

**注意**：#2/#8/#9/#12/#13 今日**必红**（P4 未落地）——按 §9.36 口径钉现状，不删检查行、不冒充已覆盖。

**另注意**：`trafficgen/docs/protocol-pcap-test/thrift.md` 的 18/18 pass 是**过期产物**（G-THRIFT-10，§8.2 #7），**不得作为"套件可跑"依据**。

## 10. 修订记录

- v1.0.0（2026-09-28）：P-PIPE #102 文档轨 P1–P3。旧稿 30-* 13 ID / packet_count / 锚词 / fixture 全量继承（思路参考不搬码）；新增形状基线机读实测（§1，**非符合态：非负例顶层键 41 处残留 + 今日建策略 400 实证**）、P3 固定动作（§6）、执行建议（§7）、存量审计（§8，18/18 改写）、覆盖反查门建议断言行（§9，16 行）。自审 6 轮（第 5 轮按主线程口径纠错；**第 6 轮按隔离审查打回修 5 项**：静默假成功定性、撤销 G-THRIFT-9、对账脚本化重算 75=56+5+14、nic_capture 诚实标注），末轮干净（结论见 `/tmp/pipe/doc-lanes/thrift.md`）。
- v1.0.1（2026-09-28）：补登记**结果文档过期**（**G-THRIFT-10**，车道间一致性缺口，照 pcep G-PCEP-11 先例）：§8.2 新增第 7 条现状矛盾点、§9 表末新增提醒句、§5.2 粒度声明缺口范围 `G-THRIFT-1…G-THRIFT-8` → **`…G-THRIFT-10`**。**只改本文 + 设计 §0/§14，不动代码/JSON。**

# TNS（Oracle Net / SQL*Net）测试用例契约

> 版本：v1.0.0（P1–P3 文档轨产物；#90 tns）
> 日期：2026-09-27
> 配套设计：`docs/protocol-designs/90-tns-design.md`（v1.0.0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/tns.json`（现存 **12 例**）
> 状态：**设计阶段**。本文**不跑 suite、不启动服务器**，不宣称任何绿的结论；ID 权威 = 本文 §2。存量 12 例的逐条审计去向见 §8。

## 1. 测试原则与形状基线

- **形状基线（CORE_MEMORY §1）**：`spec_json` 必须是**纯 layers** 形——地址只住 `ip` 层（`src`/`dst`；IPv6 地址族同住 `ip` 层，仓库无 `ipv6` 层）、端口只住 `tcp` 层、数量只走 `flow_control`；顶层只允许 `layers`/`flow_control` 家族/`output`（§1.11）。
  **本协议存量实况（实测，设计 §12.1）**：12/12 例是**"层链 + 顶层扁平四元组 + 顶层 `tns` 子映射"三重违规形**——`layers` 为空 `tns` 配（`[{"tcp":{}},{"tns":{}}]`）而真实配置住顶层。这与 postgresql #82（16/16 已是纯 layers 形）的形态**根本不同**。目标形状样例见设计 §2.1；**本文 §2 的新写用例全部按目标形状书写，但依 §1.9 标注"目标形状，今天跑不通，需先补代码（G-TNS-1）"**。存量改写（ G-TNS-1 落地后一次性执行 ）的 JSON 不在本契约全文展开，逐条去向见 §8。
- **载体**：`tns` 为 TCP-only 终结层，链形 `[ip, tcp, tns]`（IPv6 同形，只换 `ip` 层地址）。链夹 `udp`（`[ip,udp,tns]`）判死（`complete.go:446-468` 通用 carrier 门，锚词 `carrier`；存量 `tns_neg_udp` 的 `error_contains: "tcp"` 落同一文案——**P4 实跑确认**，G-TNS-15）。**UDP 面不存在**（设计 §5）。
- **端口**：`tcp.dst_port` **不写**，由 `tns` 层 `FieldContract` 补齐 1521（`registry.go:633`，通用块 `chain_planner.go:597-616`）。显式写非契约端口（#7）**今日放行**（无域校验，设计 §5 / G-TNS-9），不断言拒绝。
- **方向**：`direction` 是断言的常规维度（`c2s`→up，`s2c`→down）；非法值**静默落 s2c**（`planner.go:159-166`）。所有正例**必须显式写 `direction`**。
- **断言通道（实测 TShark 3.6.14）**：主通道 = `tns.*`（**87** 字段）+ 载体字段 `ip.proto`/`ipv6.nxt`/`tcp.srcport`/`tcp.dstport`/`tcp.flags`/`tcp.len`；辅通道 = `frames` hex（IPv4 起点 **54** = 14+20+20；IPv6 起点 **74** = 14+40+20）。
  **字段值形态（实测，不许混用）**：`tns.type` = BASE_DEC（`"1"/"2"/"4"/"5"/"6"`）；`tns.length` = BASE_DEC；`tns.packet_checksum`/`tns.header_checksum` = BASE_HEX（`"0x0000"`）；`tns.reserved_byte` = FT_BYTES（`"00"`）；`tns.data_flag` = BASE_HEX（`"0x0000"`）。
  **必须走 frames hex 的面**：非标端口下的 TNS 报文（dissector 启发式未验证，G-TNS-6，#14 号）。
  **标准 `decode_as`**：`["tcp.port==<port>,tns"]`（非标端口用）。
- **包数公式**：`packet_count = 3（握手） + len(logical events)（每事件一段） + 4（正常 FIN 终止）`。多会话按每条求和（G-TNS-1 落地后逐流实测钉）。

**用例 ID 编号空间声明（旧基线兼容）**：旧基线 `31-tns-testcase.md` 的 12 个 id（`tns_connect_accept` 等）是**存量机器 ID**，不是废号——P4 改写后继续有效（§8 逐条映射）。本契约新规 **T-TNS-Sn / T-TNS-Nn** 与旧 id 的对照见 §8.3 对照列（T-TNS-S1 ≡ `tns_connect_accept`，…）。

## 2. 用例索引

> ID 权威 = 本表。合计 **26 ID = 18 正 + 8 负**；其中存量改写 **12**（§8.3）、新增 **14**（标 †；A′ 待落的标 A′）。

| # | id | T-编号 | 类型 | 场景/覆盖 | 包数 |
|---:|---|---|---|---|---:|
| 1 | `tns_connect_accept` | T-TNS-S1 | 正 | CONNECT→ACCEPT→DATA×2，TCP 1521 | 11 |
| 2 | `tns_refuse` | T-TNS-S2 | 正 | CONNECT→REFUSE，禁 DATA | 9 |
| 3 | `tns_redirect` | T-TNS-S3 | 正 | CONNECT→REDIRECT，不重连 | 9 |
| 4 | `tns_ttc_sqlnet_session` | T-TNS-S4 | 正 | TTC/SQL*Net profile 顺序，flags=0（现状钉） | 13 |
| 5 | `tns_data_flags_zero` | T-TNS-S5 | 正 † | DATA×2 flags=0 + DATA 单包（6 字节帧面） | 10 |
| 6 | `tns_ipv6_connect` | T-TNS-S6 | 正 | IPv6、帧起点 74 | 9 |
| 7 | `tns_nonstd_port` | T-TNS-S7 | 正 † | 非标端口 9999（今日放行，钉行为） | 9 |
| 8 | `tns_header_fields` | T-TNS-S8 | 正 | length/checksum/type/reserved/header checksum 全字段 | 11 |
| 9 | `tns_multi_session` | T-TNS-S9 | 正 | 两条独立流、端口隔离 | 18 |
| 10 | `tns_multi_flow` | T-TNS-S10 | 正 † A′ | `flows=2` 多流（四元组动态） | 20 |
| 11 | `tns_session_null_default` | T-TNS-S11 | 正 † | 空配置默认化产一条 DATA（P0b-2） | 8 |
| 12 | `tns_ttc_types_legacy` | T-TNS-S12 | 正 † A′ | 数值形 `type`（1/2/4/5/6）五值 | 11 |
| 13 | `tns_body_constants` | T-TNS-S13 | 正 † | CONNECT/ACCEPT/REFUSE/REDIRECT body 逐字节 + length 五值 | 13 |
| 14 | `tns_dyn_srcport` | T-TNS-S14 | 正 † | `tcp.src_port` inc 动态（`flows=2`，断言每流独立） | 20 |
| 15 | `tns_ipv4_baseline` | T-TNS-S15 | 正 † | IPv4 CONNECT→ACCEPT 裸形（地址族下限，与 #6 对称） | 9 |
| 16 | `tns_nic_path` | T-TNS-S16 | 正 † A′ | port_group 输出路（NIC 验收，`enp135s0f0np0`） | 9 |
| 17 | `tns_refuse_session` | T-TNS-S17 | 正 † | sessions 内的 REFUSE（跨 `sessions[1..n]` 面，G-TNS-3 实测载体） | 18 |
| 18 | `tns_multi_query_rounds` | T-TNS-S18 | 正 † A′ | 同连接 DATA×4 多轮（③长保活载体） | 15 |
| 19 | `tns_neg_udp` | T-TNS-N1 | 负 | UDP 载体拒绝 | — |
| 20 | `tns_neg_packet_type` | T-TNS-N2 | 负 | 未知 type 拒绝（字符串+数值双形） | — |
| 21 | `tns_neg_stray_topkey` | T-TNS-N3 | 负 † | 白名单外游离键（顶层 `src_mac`）判死 | — |
| 22 | `tns_neg_state_skip` | T-TNS-N4 | 负 † A′ | ACCEPT 前 DATA 跳步拒 / REFUSE 后事件拒 | — |
| 23 | `tns_neg_bad_direction` | T-TNS-N5 | 负 † A′ | 非法 `direction` 值拒 | — |
| 24 | `tns_neg_length` | T-TNS-N6 | 负 | 长度边界拒绝（`wire_fault.length`） | — |
| 25 | `tns_neg_checksum` | T-TNS-N7 | 负 | checksum 模式冲突拒绝 | — |
| 26 | `tns_neg_data_flags` | T-TNS-N8 | 负 | 非零 DATA flags 拒绝 | — |

## 3. 正例契约

### 3.1 `tns_connect_accept`（T-TNS-S1，存量改写）

目标形 `layers=[ip,tcp,tns]`（`ip.src/dst` 显式，`tcp.dst_port` 不写，由 FieldContract 补 1521），事件依次为 CONNECT(c2s)→ACCEPT(s2c)→DATA(c2s)→DATA(s2c)，所有 DATA `data_flags=0`。

预期 11 包（3+4+4）。packet 4/5 的 `tns.type` 分别为 `"1"`/`"2"`，packet 6/7 均为 `"6"`；4 个应用包的 `tns.length` 非零，checksum/header checksum/reserved 均为零。IPv4 frame offset 58 的单字节断言为 `01`、`02`、`06`、`06`，offset 62（DATA 包 6、7）均为 `00 00`。

### 3.2 `tns_refuse`（T-TNS-S2，存量改写）

事件为 CONNECT(c2s)→REFUSE(s2c)，`reconnect=false`。预期 9 包；packet 4 `tns.type="1"`，packet 5 `="4"`，整个应用序列没有 DATA。REFUSE 原因字段不作字节断言（`refuse_data` 未验证，恒 2 字节零）。

### 3.3 `tns_redirect`（T-TNS-S3，存量改写）

事件为 CONNECT(c2s)→REDIRECT(s2c)，不重连。预期 9 包；packet 4/5 `tns.type="1"/"5"`，packet 5 后无第二个 SYN，也无 DATA。重定向地址**不断言**（body 恒 4 字节零，G-TNS-11）。

### 3.4 `tns_ttc_sqlnet_session`（T-TNS-S4，存量改写）

事件为 CONNECT、ACCEPT、DATA×4。预期 13 包；packet 6–9 均为 DATA，四个 DATA flags 均为 `0x0000`，profile 顺序由 `spec_json` 保持。**现状钉声明**：TTC/SQL*Net 字节今日恒 0 字节（G-TNS-12）；用例只证明头字节与事件调度，**不声称** SQL 语句、认证或 TTC 类型码的具体值。`payload_profile` 键在 G-TNS-1 落地时按 G-TNS-4 裁定删/留。

### 3.5 `tns_data_flags_zero`（T-TNS-S5，新增）

单会话的 CONNECT+ACCEPT+DATA（payload_profile 任意合法值，依 G-TNS-4 裁定），断言 `tns.data_flag="0x0000"` + frame offset 62 `00 00` + `tns.data_length` 不可读（恒 0 负载 → dissector 面未实现）。预期 10 包（3+3+4）。

### 3.6 `tns_ipv6_connect`（T-TNS-S6，存量改写）

地址为 `2001:db8::1`→`2001:db8::2`（同住 `ip` 层），事件 CONNECT→ACCEPT，目的端口 1521。预期 9 包；packet 4 `ipv6.version=6`、`tcp.dstport=1521`，packet 4/5 的 type 位于 offset 78，分别为 `01/02`；checksum 双零。TNS 字节不因 IP 版本变化。

### 3.7 `tns_nonstd_port`（T-TNS-S7，新增，G-TNS-9/6 载体）

`tcp.dst_port=9999` 显式（**今日放行**，不断言拒绝）+ `decode_as=["tcp.port==9999,tns"]`。事件 CONNECT→ACCEPT，预期 9 包。若 P4 实测中 dissector 在非标端口不产 `tns.*` 字段，则该用例**降级为 frames-hex-only**（设计 G-TNS-6）。

### 3.8 `tns_header_fields`（T-TNS-S8，存量改写）

事件为 CONNECT、ACCEPT、DATA、DATA。预期 11 包，应用包的 `tns.length` 必须非零且等于重组包字节数；packet/header checksum=0，reserved=`00`，type=`1/2/6/6`，DATA flags=0。帧断言使用 offset 56/58/59/60/62（IPv4），避免把未知 CONNECT/ACCEPT payload 当作规范字节。新增：`checksum_mode:"disabled"` 显式。

### 3.9 `tns_multi_session`（T-TNS-S9，存量改写）

配置两个 sessions，源端口 41234、41235；每条流只有 CONNECT→ACCEPT。预期 18 包（2×9），`tcp.dstport` distinct values 为 1521，`tcp.srcport` distinct 为 41234/41235。**按 9.38**：聚合断言必须排除服务端固定口（1521）——的聚合列只含客户端口。

### 3.10 `tns_multi_flow`（T-TNS-S10，新增 A′）

`flow_control.flows=2` × 单会话 CONNECT→ACCEPT；`tcp.src_port` **不写静态标量**（9.39：多流×静态标量互斥 → 或留空用保底 `12345+i`，或写动态对象）。预期 20 包（2×10？实测钉：CONNECT→ACCEPT 事件数 2 → 每流 3+2+4=9；两流 = 18；**packet_count 以先跑后钉为准**，此处先标 18 占位）。

### 3.11 `tns_session_null_default`（T-TNS-S11，新增）

`tns` 层 config 空（`{}`）→ 默认化产一条 DATA 事件（P0b-2，`layer_gen.go:26-29`）。预期 8 包（3+1+4）。`tns.type="6"`、`length=10`。

### 3.12 `tns_ttc_types_legacy`（T-TNS-S12，新增 A′）

事件 `type` 用**数值形**（`1,2,4,5,6` 按 `validNumericType` 白名单）；同时断言 `type:127` 数值形在负例 #20 被拒（7）。大小写敏感：新增断言 `"connect"`（小写）被拒（`tns_test.go:41` 实测）。

### 3.13 `tns_body_constants`（T-TNS-S13，新增）

五类 body 的逐字节断言 + `length` 五值（10/12/16/28/106，设计 §3.1 实测锚）：CONNECT body 的 `(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=test)))` 字符串（**作为本仓库固定测试值断言，不作为 Oracle 事实**）；ACCEPT `nt_proto_characteristics=0x0736`（与 CONNECT 的 `0x0300` 对照，`tns.ntp_flag.*` 位面不枚举）；REFUSE `refuse_reason_user=0`；REDIRECT `redirect_data_length=0`。TShark 字段通道：`tns.connect_data` / `tns.version` / `tns.accept_data_length` / `tns.refuse_data_length` / `tns.redirect_data_length`。

### 3.14 `tns_dyn_srcport`（T-TNS-S14，新增）

`tcp.src_port` 用 `inc` 动态对象（`{"strategy":"inc","range":[41234,41236]}`），`flows=2`；断言两流 `tcp.srcport` distinct = 41234/41235（**按 9.40**：同一流内两会话共享流序号 → 同值；本例是单流单会话故每流一值）。预期包数按 §1 公式实测钉。

### 3.15 `tns_ipv4_baseline`（T-TNS-S15，新增）

IPv4 CONNECT→ACCEPT 裸形（地址族**下限**，与 #6 对称——§9.24 对称覆盖：#6 覆了 v6，v4 必须有独立例，不许以 #1 的"大包混合形"冒充 v4 基线）。预期 9 包；断言 `tns.length` 非零 + offset 54/58/59/60 四位。

### 3.16 `tns_nic_path`（T-TNS-S16，新增 A′）

`output_type=port_group`（`enp135s0f0np0`）+ CONNECT→ACCEPT；断言 TCP 三次握手与应用字段与 pcap 路一致（§6.3 NIC 路）。P5 落。

### 3.17 `tns_refuse_session`（T-TNS-S17，新增）

`sessions[]` 内的 `CONNECT→REFUSE`（跨 `Sessions[1..n]` 校验面，G-TNS-3 的**实测载体**）。预期 18 包（2×9）。**若 G-TNS-3 实测为"失败却报成功"**，本例自动升级为该 bug 的**失败测试先行**（§9.7）。

### 3.18 `tns_multi_query_rounds`（T-TNS-S18，新增 A′）

同连接 DATA×4（长保活载体，设计 §6.6 / §10.1 行 6「不适用」面的用例承载）。预期 11 包（3+4+4：CONNECT+ACCEPT+DATA×2？**包数以实测钉，此处 11 占位**，G-TNS-1 落地后复算）。

## 4. 负例契约

负例 `expect` 只能包含下列两个键（`expect_error: true` + `error_contains`），确保失败发生在 planner/validator 边界而不是产生一个"0 包成功"的假阳性。**全部走真实流程 §14.11/14.12**。

| id | T-编号 | 输入 | `error_contains` |
|---|---|---|---|
| `tns_neg_udp` | T-TNS-N1 | `layers=[ip,udp,tns]`（载体链夹 udp） | `tcp`（carrier 门文案含 `tcp` 子串；**P4 实跑确认**，G-TNS-15） |
| `tns_neg_packet_type` | T-TNS-N2 | event `type="BOGUS"`（字符串形）+ `type=127`（数值形，双形） | `type`（`unknown packet type`，`builder.go:177/200`） |
| `tns_neg_stray_topkey` | T-TNS-N3 † | 顶层游离键 `src_mac`（`{"layers":[…],"src_mac":"02:00:… "}`，走 §1.11 通用门） | `flat four-tuple`（`schema/semantic.go:186`；**P4 实测**该形今日是否真被拒） |
| `tns_neg_state_skip` | T-TNS-N4 † A′ | DATA 先于 ACCEPT；REFUSE/REDIRECT 后仍有事件 | `state`（**P4 新增守卫的锚词**；G-TNS-8） |
| `tns_neg_bad_direction` | T-TNS-N5 † A′ | `direction:"sideways"`（非法枚举值） | `direction`（**P4 新增白名单的锚词**；G-TNS-8） |
| `tns_neg_length` | T-TNS-N6 | `wire_fault={"kind":"length","value":7}` | `length`（`below minimum 8`，`builder.go:247`） |
| `tns_neg_checksum` | T-TNS-N7 | `checksum_mode=disabled` 且 `wire_fault.packet_checksum=1` | `checksum`（`conflicts with disabled`，`builder.go:249`） |
| `tns_neg_data_flags` | T-TNS-N8 | DATA `data_flags=1` | `data_flags`（`must be 0`，`planner.go:55`） |

**presence 负例形状特别说明（必须点名）**：`{"layers":[…],"tns":{}}`（层链 + 顶层空 `tns` 子映射并存）是 M5 清单①的判死负例形。本协议 `CheckProtoFlat` **无 `tns` 分支**（§11.7 冲突点 6），该形**今日不会被拒** → **本契约今日不建该负例**（建了会真绿 = 假通过），改为立项 **G-TNS-5**（P4 实测后定建例或并框架级缺口）。**这是"如实登记不冒充"的实例**。

## 5. 覆盖与对账

### 5.1 三源回指行

官方文档（Oracle Net Services 业务语义描述 + TCP/IPv4/IPv6 的 RFC 9293/8200）+ D-TNS-1（设计 §11）→ 26 ID（本契约 §2）。第三源"已确认现网行为"当前 = **未确认级**（G-TNS-13，按 §5.5 不写死进实现）。`payload_profile`/版本号类 Oracle 私有语义**不进用例**。

### 5.2 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **旧基线契约 + dissector 实测 + 仓库落码反推**（TNS 无公开规范，G-TNS-10），**非纯规范反推**。dissector 侧 87 字段全表见设计 §3（`tshark -G fields` 机读）。
- **对账两行**：**要求逻辑点总数 = 98**（八项 8 行 + 矩阵 60 格 + 变体 23 行 + 死字段链 7 项）；**用例覆盖数 = 41**（八项 8 + 矩阵已覆 8 + 矩阵用例通道 11 + 变体 23 —— 含 A′ 立项覆盖，不全为今日可跑）；**不适用 = 27**（矩阵 22 + 变体 5）。41 + 27 = 68；**开放 30 格（B′ G-TNS-2 的 19 格 + 终态组合 11 格中的未立项部分）** = 明确不解决（C 类 §9.17 登记）。
  **粒度声明**：行/格粒度每点 1 计；G-TNS-1…G-TNS-15 不折进 98。**反查全绿 ≠ 覆盖全**（§9.52 原文）。
- **门3 抽查候选**：最复杂用例 = **#4 `tns_ttc_sqlnet_session`**（6 事件，CONNECT→ACCEPT→DATA×4 交织）；交织维度 = 会话(1)×事务(2)×方向(c2s/s2c)×头字段(5)。若按 9.49/9.50 下限偏弱在"并发交错"面，**建议门3 抽 #4 + #9**（`tns_multi_session` 补交错面）。

### 5.3 T-编号与旧 id 对照（§8.3 全表的前 12 行摘要）

`tns_connect_accept` ≡ T-TNS-S1；`tns_refuse` ≡ T-TNS-S2；`tns_redirect` ≡ T-TNS-S3；`tns_ttc_sqlnet_session` ≡ T-TNS-S4；`tns_ipv6_connect` ≡ T-TNS-S6；`tns_multi_session` ≡ T-TNS-S9；`tns_header_fields` ≡ T-TNS-S8；`tns_neg_udp` ≡ T-TNS-N1；`tns_neg_packet_type` ≡ T-TNS-N2；`tns_neg_length` ≡ T-TNS-N6；`tns_neg_checksum` ≡ T-TNS-N7；`tns_neg_data_flags` ≡ T-TNS-N8。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接：CONNECT→ACCEPT→DATA×4（#4）→ 多轮 DATA（#18） | 已覆 #4；A′ 补例 **#18**（DATA×4 同连接多轮） |
| ② | 非正常结束 | 正常挥手（全正例）；应用层正常终止报文 = **无**（NULL/ABORT 未实现，G-TNS-2）；网络层异常 = RST | A′ 补例 **`tns_abort_rst`**（`tcp.rst=true`，`registry.go:72` 已有字段）+ 负例 8 条 |
| ③ | 长保活 | 协议层无 keepalive 语义（行 6 显式不适用）；长会话 = 同连接多轮 DATA | #18 承载（>2 轮） |

无空项：① 有已覆例 + 1 条 A′ 补例；② 有负例面 + 1 条 A′ 补例；③ 有 #18。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 层链化 | registry 五键 + translate `case "tns"` | G-TNS-1，用例 #1–#18 全依赖 |
| 状态机 | 跳步/终态/direction 白名单守卫 | G-TNS-8，用例 #22/#23 |
| sessions 全量校验 | `sessions[1..n]` 事件校验 | G-TNS-3，用例 #17 |
| 死字段处置 | `payload_profile` 删/留裁定 + `reconnect` 删 | G-TNS-4/G-TNS-11，用例 #13 |
| 端口面 | 非标端口实测 + `decode_as` | G-TNS-6，用例 #7 |
| 多流面 | `flows=N` 多流 + `src_port` 动态 | #10/#14 |
| 地址族面 | IPv4/IPv6 对称 | #6/#15 |
| 现网面 | Oracle XE 抓包确认 | G-TNS-13 |
| 非正常结束 | `tcp.rst` 补例 | ② 的 `tns_abort_rst` |
| 多轮数据 | DATA×4 同连接 | #18 |

**B′（G-TNS-2 七类型 + G-TNS-12 DATA 负载面）**：进设计 §14，「明确不解决 + 迁入计划」。用例侧 #5 钉现状（`length=10` 恒）。

### 6.3 3.14 豁免边界审计

**有长连接载体 → `sessions[]` 不豁免**（设计 §12.3 会话表 s1/s2/s3）；多流并发 #10/#14；单包多载荷 = **不适用**（TNS 报文恒单包头单负载，无多 question/多 RR 类形态，如实声明）。

## 7. 实现后执行建议

1. **P4 顺序**：G-TNS-1（registry+translate）→ 存量 12 例改写（删 `payload_profile`，若走删键路线）→ 先跑后钉 12 例 → 补 G-TNS-3 失败测试先行 → 补 G-TNS-8 守卫 → 新增 #5/#7/#11/#13–#15 → 全量复跑。
2. **实测顺序**：先 S1/S8（header length 与重组字节），再 REFUSE/REDIRECT（#2/#3 状态门），最后 IPv6（#6）、多会话（#9）、TTC 面（#4）、非标端口（#7）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=tns` 全量不是增量）；门2④ 反查（`check_tns` 新增后出口必须 0）。
4. 任何 profile/版本号的具体字节须有独立 dissector 实测证据和失败优先测试（设计 §1.2 档②纪律）。

## 8. 存量审计（12 例逐条去向）

### 8.1 存量实测面（2026-09-27）

`docs/protocol-pcap-test/tns.md` 记录 **12/12 pass**（7 正带 pcap 落盘 `tns/*.pcap`，5 负 0 包）。逐例 `packet_count`：11/9/9/13/9/18/11 + 0×5，全符合 `3+N+4` 公式（S6 = 2×9）。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **存量跑的是 legacy 平面混合形，不是纯层链**：存量 `spec_json` 的 `layers=[{tcp:{}},{tns:{}}]` 只是**空壳**（`tns` config 恒 `{}`，既不校验也不消费），真实配置住顶层。旧 id 的 packet_count 断言**今日有效**，但顶层键断言今日是**违规形**。
2. **`tns_neg_udp` 的锚词**：`error_contains: "tcp"`。今日 carrier 门文案（`complete.go:465`）= `tns chain: udp carrier is not supported — tns rides tcp only (carrier)`——含 `tcp` 子串，**预期命中**，但须 P4 实跑确认（G-TNS-15）。
3. **存量未覆盖 `sessions[1..n]` 坏形**：`tns_multi_session` 两条会话都是合法 CONNECT→ACCEPT → G-TNS-3 的坏 `Sessions[1]` 形**今日零用例**（#17 补）。

### 8.3 逐条去向表（12 行）

| 存量 id | T-编号 | 去向 | 改写动作（G-TNS-1 落地时） |
|---|---|---|---|
| `tns_connect_accept` | T-TNS-S1 | **改写** | 目标形状化（`ip` 层地址 + `tns` 层 events）；`payload_profile` 依 G-TNS-4 裁定删/留；packet_count 11 不变 |
| `tns_refuse` | T-TNS-S2 | **改写** | 同上；`reconnect:false` 键删（死字段） |
| `tns_redirect` | T-TNS-S3 | **改写** | 同上 |
| `tns_ttc_sqlnet_session` | T-TNS-S4 | **改写** | 同上 + 现状钉声明（§3.4） |
| `tns_ipv6_connect` | T-TNS-S6 | **改写** | 地址迁 `ip` 层 |
| `tns_multi_session` | T-TNS-S9 | **改写** | `src_port` 迁 `tcp` 层 / `sessions[].src_port`；端口换 41234/41235（避 collides，9.37） |
| `tns_header_fields` | T-TNS-S8 | **改写** | 同 S1 动作 |
| `tns_neg_udp` | T-TNS-N1 | **改写** | 链形改为 `[ip,udp,tns]` 的目标形状；锚词确认（G-TNS-15） |
| `tns_neg_packet_type` | T-TNS-N2 | **改写 + 扩展** | 加数值形 `type:127` 第二形状（§3.12） |
| `tns_neg_length` | T-TNS-N6 | **改写** | `wire_fault` 迁层内 |
| `tns_neg_checksum` | T-TNS-N7 | **改写** | 同上 |
| `tns_neg_data_flags` | T-TNS-N8 | **改写** | `data_flags` 迁层内事件 |

无"作废不注原因"：0 作废，0 等价覆盖（全部改写 + 14 新增）。

## 9. 修订记录

- v1.0.0（2026-09-27）：P1–P3 文档轨产物（车道 A，协议 #90）。建立 26 ID（18 正 + 8 负）用例契约；存量 12 例逐条审计去向（§8，全改写）；标注目标形状"今天跑不通"（G-TNS-1）；presence 负例不建的如实登记（§4）；9.52 对账（98=41+27+30B′）；门3 抽查候选 #4+#9。**未修改任何 `.go`、未跑 suite、未启动服务器、未写共享文档/账本**。

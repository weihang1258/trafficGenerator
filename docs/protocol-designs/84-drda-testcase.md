# DRDA T-DRDA 用例契约（10 ID＝8 正＋2 负）

> 版本：v1.0.0（P1–P3 文档轨产物；#84 drda REDO）
> 日期：2026-09-27
> 配对设计：`docs/protocol-designs/84-drda-design.md`
> 可执行契约：`trafficgen/test/protocol_pcap/cases/drda.json`（现存 10 例，过渡形）
> **ID 权威＝本文 §2**（顺序/类型/`packet_count` 与设计 §9 逐值一致）。
> 配套说明：旧 `29-drda-testcase.md`（v1.0.0 2026-08-20）不删除；逐条核对见 §8.6。

---

## 1. 测试原则与形状基线

- **形状基线（CORE_MEMORY §1）**：`spec_json` 必须是**纯 layers** 形——地址只住 `ip` 层（`src`/`dst`；IPv6 地址族同住 `ip` 层，仓库无 `ipv6` 层）、端口只住 `tcp` 层、数量只走 `flow_control`；顶层只允许 `layers`/`flow_control` 家族/`output`（§1.11）。**正例顶层键＝0**（白名单外即红）。
  **本协议存量实况（实测）**：10/10 例**是过渡形**（顶层七键 `src_ip/dst_ip/src_port/dst_port/count/drda`＋`layers`，层内 `{"tcp":{}}`/`{"drda":{}}` 双空；#10 的 `layers[0]` 为 `udp`）。改写清单见 §8.6——地址→`ip` 层、端口→`tcp` 层、`count:1`→`flow_control.flows=1`、`drda` 子映射→层内 `drda` 条目（待 G-DRDA-1 登记接线后落盘）。
- **载体**：`drda` 为 TCP-only 终结层，链形 `[ip, tcp, drda]`。链夹 `udp`（`[ip,udp,drda]`，#10）判死（锚词 `tcp`）。**UDP 面不存在**（设计 §5）。
- **端口**：`tcp.dst_port` **不写**，由 `drda` 层 `FieldContract {"tcp.dst_port": "446"}`（`registry.go:613`）补齐。显式写非 446 端口 → 拒。
- **断言通道（实测）**：主通道＝tshark `drda.*`（本机 TShark 3.6.14；`tshark -G fields | grep drda` 共 21 行，去噪 `bluecom.searchreq.addrdata` 误命中 1 行＋`btlmp.*` 1 行＋`P DRDA` 协议行 1 行后＝**18** 字段）＋载体字段 `tcp.srcport`/`tcp.dstport`/`tcp.len`/`tcp.flags`、`ipv6.version`/`ipv6.src`/`ipv6.dst`；辅通道＝`frames` hex（IPv4 起点 **54**＝14+20+20；IPv6 起点 **74**＝14+40+20）。**不自创字段名**。存量 10/10 例的 `drda.ddm.*` 9 字段全部命中实测字段 9/9。
- **正例 expect**：`directional` 8/8 true；`has_handshake`/`negotiated`/`terminates`/`has_payload` 8/8 true；`notes` 8/8（机读实测）。所有正例同时具备 `packet_count`＋`fields`/`frames`，包号 1 起始。
- **负例纪律（§14.11/§14.12）**：`expect` 键集合严格为 `{"expect_error","error_contains"}`（#9/#10 机读确认无 `packet_count`/`fields`/`frames`）；锚词逐字对 validator 字面值（#9 `dss_length` 对 `planner.go:35/39`；#10 `tcp` 对载体错口径）。
- **包数公式（存量 8 正例逐例复算通过）**：单会话 `packet_count ＝ 3（SYN/SYN-ACK/ACK）＋ 2N（N 个请求/响应对）＋ 4（FIN-ACK 四way）＝ 2N＋7`；#8 双会话＝两会话独立经此公式后求和（9＋9＝**18** ✓）。所有约定值按 §9.31/§14.6 **先跑后钉**，不照抄。
- **动态值纪律（§9.34/§9.35）**：`flows>1` 的逐流变化只用 `nonzero`/`distinct_values`/`same_as_packet` 断言，禁止硬编码（#8 `tcp.srcport distinct_values [12345,12346]` 先例）。

帧偏移铁律：IPv4 payload 起点 54，IPv6 起点 74；`frames[].hex` 是该偏移起的原始字节前缀；DDM 头固定 10 字节（`length(2) magic(1) format(1) correlator(2) length2(2) code_point(2)`，BE）。最小无参数对象 `00 0a d0 01 00 01 00 04`＋2 字节码点。

---

## 2. 原子用例索引（10 ID＝8 正＋2 负，顺序为权威）

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `drda_excsat` | 正 | IPv4 基线：握手→EXCSAT→EXCSATRD→挥手；DDM 头全字段 | 9 |
| 2 | `drda_security_check` | 正 | 三轮：EXCSAT＋ACCSEC＋SECCHK；占位 token 非真实密码 | 13 |
| 3 | `drda_database_connect` | 正 | 四轮：＋ACCRDB（`rdb_name=SAMPLE`）→RDB_ASSOCIATED | 15 |
| 4 | `drda_sql_success` | 正 | 五轮：＋SQLDTA→SQLCARD（SQLCODE=0） | 17 |
| 5 | `drda_sql_error` | 正 | 五轮：＋SQLDTA→SQLCARD（SQLCODE=-204／SQLSTATE=42704，应用错误不断链） | 17 |
| 6 | `drda_dss_min_length` | 正 | 长度下界：DDM length=10、length2=4 | 9 |
| 7 | `drda_ipv6_excsat` | 正 | IPv6（offset 74）字节等价 | 9 |
| 8 | `drda_multi_session` | 正 | 双 session 四元组／correlator／状态隔离 | 18 |
| 9 | `drda_dss_length_mismatch` | 负 | 声明 `dss_length=11` vs 编码 10 不一致 | — |
| 10 | `drda_udp_rejected` | 负 | `[udp,drda]` 载体拒 | — |

T-编号映射：T-DRDA-001–010 依次对上表 #1–#10（设计 §9 同序）。

---

## 3. 正例逐项断言契约

### 3.1 `drda_excsat`（#1，9 包，N=1）

- 配置：`association=excsat`，`correlator_start=1`，`ccsid=1208`；请求 `0x1041`／响应 `0x1443`，correlator=1。
- fields（packet 4/5，机读实录）：`tcp.dstport=446`；`drda.ddm.ddmid=0xd0`、`drda.ddm.format=0x01`、`drda.ddm.rqscrr=1`、`drda.ddm.length=10`、`drda.ddm.length2=4`、`drda.ddm.codepoint=0x1041`（packet 4）；packet 5 `codepoint=0x1443`＋`rqscrr same_as_packet=4`。
- frames：packet 4 offset 54 `00 0a d0 01 00 01 00 04 10 41`；packet 5 offset 54 `00 0a d0 01 00 01 00 04 14 43`。

### 3.2 `drda_security_check`（#2，13 包，N=3）

- 配置：`association=security`，`security_user=TESTUSR`，`security_token=[1,2,3,4]`（占位字节）；应用序 EXCSAT→ACCSEC(`0x106d`)→SECCHK(`0x106e`)，响应 `0x14ac`／`0x1219`。
- fields：packet 4 `0x1041`；packet 6 `0x106d`；packet 7 `0x14ac`；packet 8 `0x106e`＋`rqscrr=3`；packet 9 `0x1219`＋`rqscrr same_as_packet=8`。
- frames（magic 内偏移，不断言未知参数总长）：packet 6/7 offset 56 `d0 01 00 02`；packet 8/9 offset 56 `d0 01 00 03`。

### 3.3 `drda_database_connect`（#3，15 包，N=4）

- 配置：`association=database`，`rdb_name=SAMPLE`；ACCRDB `0x2001`／ACCRDBRM `0x2201`。
- fields：packet 10 `tcp.dstport=446`、`codepoint=0x2001`、`rqscrr=4`；packet 11 `codepoint=0x2201`＋`rqscrr same_as_packet=10`。
- frames（码点偏移，不断言 RDBNAM 参数总长）：packet 10 offset 62 `20 01`；packet 11 offset 62 `22 01`。ACCRDBRM 成功后才进 RDB_ASSOCIATED。

### 3.4 `drda_sql_success`（#4，17 包，N=5）

- 配置：`association=sql`，`sql={data:[1,2,3,4], code:0, state:"00000", diagnostic:""}`；SQLDTA `0x2412`／SQLCARD `0x2408`。
- fields：packet 12 `codepoint=0x2412`；packet 13 `codepoint=0x2408`＋`tcp.len nonzero`。⚠️ 存量 packet 13 另有 `drda.ddm.rqscrr same_as_packet=13`（**自指**，恒真不断言配对）→ **P4 修钉**（改 `same_as_packet=12`）。
- frames：packet 12 offset 62 `24 12`；packet 13 offset 62 `24 08`。SQLCODE=0 必须走链路响应参数（`0x1252`）或重组字节断言；旧 planner 路径响应无参数（设计 §1 已落码边界），P4 收敛。

### 3.5 `drda_sql_error`（#5，17 包，N=5）

- 配置同 #4，`sql={code:-204, state:"42704", diagnostic:"missing object"}`。
- fields／frames 同 #4 形状；⚠️ 同样 `same_as_packet=13` 自指→P4 修钉。应用错误**不转** task/config error，连接正常终止。

### 3.6 `drda_dss_min_length`（#6，9 包）

- 配置：`association=excsat`，`dss_length=10`，`dss_segments=[{format:1, correlator:1, length:10, length2:4, code_point:4161}]`。
- fields：packet 4/5 `drda.ddm.length=10`、`drda.ddm.length2=4`。
- frames：同 #1 两条（`10 41`／`14 43`）。验证长度边界，不把空 DSS 当成功业务阶段。

### 3.7 `drda_ipv6_excsat`（#7，9 包）

- 配置同 #1，地址 `2001:db8::1→2001:db8::2`。
- fields：packet 4 `ipv6.version=6`、`ipv6.src/dst`、`tcp.dstport=446`、`codepoint=0x1041`。
- frames：offset **74**，DDM 前缀与 #1 完全相同（IP 版本不改 DRDA 字节）。

### 3.8 `drda_multi_session`（#8，18 包）

- 配置：`association=excsat`，`sessions=[{id:s1,src_port:12345,…},{id:s2,src_port:12346,…}]`（correlator 各自从 1 起，不跨流复用）。
- fields：`tcp.srcport distinct_values [12345,12346]`（`distinct_exclude [446]`）；`tcp.dstport distinct_values [446]`。
- frames：packet 4 offset 54 `00 0a d0 01 00 01 00 04 10 41`。确定性按 session 顺序输出；未来并发实现改按流匹配。⚠️ 旧 planner 无 `Sessions` 展开（走链路已具，P4 收敛）。

---

## 4. 负例契约

| ID | 形状 | expect（键集合严格二键） | 锚词出处 |
|---|---|---|---|
| #9 `drda_dss_length_mismatch` | `dss_length=11`＋段 `length=10` | `expect_error=true`、`error_contains="dss_length"` | `planner.go:39`（`dss_length %d mismatches segment length %d`；下界形 `planner.go:35`） |
| #10 `drda_udp_rejected` | `[udp,drda]` | `expect_error=true`、`error_contains="tcp"` | 链载体校验口径 |

错误须在 planner/builder 生成数据前返回，不产截断 pcap。

---

## 5. 三源回指行与 9.52 对账

### 5.1 三源回指（§9.2–§9.4）

**①规范/官方文档**：DRDA V5 Vol.1–3（DSS/DDM 头 §10.1/§10.3、代码点表 §3.3/§10.4；设计 §10 各条＋节号）——本文 §3 的每个码点、长度公式、阶段顺序均可回指。
**②D-DRDA-1**（设计 §11）：文件清单／接口签名／数据结构／主流程／错误分支／性能边界／冲突点／回滚。
**③已确认的现网行为**：**当前为未确认级**——只有官方文档描述的 DB2 Connect 行为形态（EXCSAT→ACCSEC→SECCHK→ACCRDB→SQL 标准序），**无本机抓包证据** → 挂 **G-DRDA-3**，按 §5.5 不写死进实现（设计 §10.1 行 7）。
→ 落盘：`trafficgen/test/protocol_pcap/cases/drda.json`（目标 8 正＋2 负＋A′ 补例 T-11；ID 权威＝本文 §2）。

### 5.2 9.52 对账两行＋清单出处声明

- **清单出处声明**：本清单来源＝**规范/官方文档反推**（DRDA V5：DSS/DDM 头、代码点表、关联状态机；DB2 现网行为形态；tshark 3.6.14 `packet-drda.c` dissector 实测 18 字段＋§3.4 参数名实测矩阵），**非**引擎能力面反推。引擎侧只作现状取证：`registry.go:612` 已注册（10 键＋FieldContract 446）、`core/protocols.go:35` 白名单、`cases/drda.json` 10 例过渡形（顶层七键）、`chain_planner_translate.go` 51 case 无 drda。
- **对账两行**：
  - **规范逻辑点总数＝29**＝设计 §10.1 八项矩阵 **8** 行＋§10.2 请求×响应矩阵 **7** 格＋§10.3 数据形态变体表 **14** 行。
  - **用例覆盖数＝24**＝八项行 1–6、8 共 **7** 行＋矩阵**已覆 4 格**＋矩阵**缺口→用例通道 1 格**（T-11）＋变体 **12** 行，全部由 10 个语义 ID 承载。
  - **B′／立项＝5**＝八项行 7（现网面 1）＋矩阵 2 格＋变体 2 行 → G-DRDA-1/3/5。
  - 校验：**24＋5＝29** ✓ 无遗漏。
- **工具／断言面 5 点单列**（外层头／参数名／SQL 面／chained／截断诊断），不计入规范总数——映射到 §3 分流表，属实现面约束。
- **粒度声明（防误读）**：按设计 §10 的行／格粒度计数，每行只计 1 点；行内子面缺口另登设计 §14，**不折进 29 点、也不冒充覆盖**。反查 10/10 绿 ≠ 覆盖全——反查只证明清单内的点有例，本对账才证明清单本身全（§9.52 原文）。

---

## 6. P3 固定动作

### 6.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例／立项 |
|---|---|---|---|
| ① | 同连接／同流内的多轮操作 | 同一 TCP 446 连接内 EXCSAT→ACCSEC→SECCHK→ACCRDB→SQLDTA 多轮（#4：5 轮；#2：3 轮；#3：4 轮） | 已覆 #1–#5（单轮基线 #1/#6）；`sql_statement` 多语句事务→B′（G-DRDA-1 多语句面） |
| ② | 非正常结束 | SQLCARD 负 SQLCODE 应用错误不断链（#5）；长度非法拒（#9 设计边界 V3）；载体错拒（#10）；SECCHK/ACCRDB 失败终止（设计 §4 状态机） | 前半已覆（#5/#9/#10）；SECCHKRM/ACCRDBRM 失败终止面→**B′ 立项 G-DRDA-5**（planner 今日无失败分支语义） |
| ③ | 长保活 | TCP 长连接多轮 SQL（关联一次、SQL 多次）；`reconnect=true` 新连接 correlator 重起（设计 §4） | 已覆形状 #4/#5（关联＋SQL 同连接）；`reconnect` 语义→B′（G-DRDA-5） |

无空项。

### 6.2 A′/B′ 两分类表（要求面反推：数据／业务／现网／多流／地址族／断言通道六类）

**A′（引擎可构建→10 ID 内已覆＋A′ 补例建议）**：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | 11 码点逐值；DDM 头 6 子面；参数 TLV；SECMEC/USRID/PASSWORD/RDBNAM/UOWDSP/SQLSTT 六参数名；SQLCODE 有符号 U32 BE；SQLSTATE／诊断文本；CCSID 1208 编码字节数；length 下界 10/4；`length2=length-6` 恒等式 | #1–#8 已覆；非法形→#9/#10；**A′ 补例 T-11**（chained format `0x41` 首 DDM＋`drda.ddm.fmt.bit1` 断言；`DDMChained` 常量今日无 planner 可达路径） |
| 业务 | 关联四阶段状态机；association 四档截断；SQL 成功／错误双分支；失败终止；correlator 递增／配对 | #1–#5 已覆；失败终止→G-DRDA-5 |
| 现网 | DB2 Connect 标准序；RDBNAM=SAMPLE 缺省；CCSID 1208 | #1–#5 已覆；**抓包级确认→G-DRDA-3** |
| 多流 | 双 session 四元组／correlator／状态隔离（#8，18 包） | #8 已覆 |
| 地址族 | IPv4（#1–#6/#8–#10）／IPv6（#7）对称，offset 54/74 两档 | 已覆（无缺格） |
| 断言通道 | `drda.*` 18 字段实证；frames hex 双通道；SQLCODE/SQLSTATE 重组字节面（旧路 param 缺失，P4 修钉） | #1–#8 |

**B′（引擎结构缺口→D-DRDA-1「明确不解决＋迁入计划」，见设计 §14）**：

- **G-DRDA-1**（层内业务键翻译：translate 无 `case "drda"`，`association/sessions/dss_length` 今日 V9 全拒）——P4 接线动作。
- **G-DRDA-2**（死配置：`transport` 别名保留／`session_start` 删除／`sequence` 对象键删除（mms 键，非 drda）／`sql.statement` 删除或实现）。
- **G-DRDA-3**（现网证据升级：DB2 抓包级确认；SECMEC 值面、`security_token` 编码面、SECCHKCD、SQLCAXGRP 组）——P4 前置确认，不挡开工。
- **G-DRDA-4**（presence／白名单守卫缺 drda 分支：`CheckProtoFlat` 无 drda 分支＋`mapToFlowSpec` 无 ValidationErrors 注入块）——跨协议共享面，车道不改，上报主线程。
- **G-DRDA-5**（失败终止／重连语义：SECCHKRM/ACCRDBRM 失败终止、`reconnect` 新连接、`sql_statement` 多语句事务）。

**动态清单（§12／§9.34）**：四元组开策略（`inc` 回绕／`rand` 可复现／`list` 轮转／`pattern` 替换）在 `ip`／`tcp` 层；drda 业务键开策略面：`correlator_start/inc` 开（逐流递增，多流用 `distinct_values` 断言）；`association` 不开（截断档是形状选择器）；`security_user/rdb_name/sql.*` 开（多值面走 `nonzero`／`distinct_values`）；`dss_length` 不开（负例注入口）。**无序号算法代码位置**（业务无逐流序号语义，诚实"不适用"）。

### 6.3 §3.14 豁免边界审计

- **本协议有长连接载体**（TCP 446 单连接四阶段＋SQL 多轮），**不主张任何豁免**：会话表由设计 §4 显式声明，且 #8 覆盖双会话隔离。
- **多流并发**：已覆 #8（两 session 各自四元组／correlator／状态机隔离，18 包）。
- **单包多载荷**：DRDA 无"一包多载荷"形态（一 TCP payload＝一 DDM；chained 多 DDM 同包由 format `0x41` 表达→T-11）→该形态由 T-11 覆盖，不是豁免逃逸。
- 结论：多流、单包多载荷、多轮事务三项各有结论，无逃逸。

### 6.4 断言契约核对结论（与设计 §3／§9 一致）

1. **10 ID 契约核对**：本文 §2 与设计 §9 逐 ID、逐序、逐类型、逐 `packet_count` 一致——8 正例（9/13/15/17/17/9/9/18）＋2 负例（`expect` 只有 `expect_error`／`error_contains`），顺序同为 T-DRDA-001–010。
2. **存量审计（§9.14）**：当前 `cases/drda.json` 10 例逐条审计见 §8.6（合入 10/10，零作废；改写清单：顶层七键去向＋层内填充＋P4 修钉 3 处）。
3. **断言通道核对**：`drda.*` **18** 字段已实证（`tshark -G fields | grep drda`＝21 行，去噪 `bluecom` 误命中＋`btlmp`＋`P` 协议行后 18）；分流规则见 §1；SQLCODE/SQLSTATE 重组字节面 P4 修钉（旧路 param 缺失）。
4. **packet_count 纪律**：§2 约定值随注册后**先跑后钉**（§9.31／§14.6），以落盘 pcap 实测校准，不照抄本文约定值。

---

## 7. 实现后执行建议（P4/P5）

1. **先决**：完成设计 §11 的 G-DRDA-1 接线（registry 补 `association/sessions/dss_length`＋translate 加 `case "drda"`），再改写 cases；否则层内键被 V9 拒。
2. **落盘顺序**：① #1/#6 最小头和长度先钉 → ② #2/#3 关联状态机 → ③ #4/#5 SQL 面（含旧路响应参数收敛）→ ④ #7/#8/#9/#10 → ⑤ A′ 补例 T-11。
3. **修钉三处**：#4/#5 `same_as_packet: 13` 自指→12；旧 planner 响应参数收敛到 layer_gen 语义；旧 planner `Sessions` 展开收敛。
4. **跑法**：`CASE_PROTO=drda` 逐例 `flowb_run_protocol_case`；先 JSON 静态一致性检查。涉及 TCP stream 的场景同时检查重组后的 DDM length 与单包 FrameAssert。
5. **负例锚词**：与 `planner.go:35/39`／载体校验字面值逐条对齐；锚词漂移必须同步改用例，**不许放宽阈值**。
6. **pcap 落盘**：默认 `/tmp/mcp-pcaps/drda/`；NIC 例走 `port_group`＋`enp135s0f0np0`。

---

## 8. 存量用例逐条审计去向（§9.14／§14.4）

**存量基线（机读实测）**：`cases/drda.json` 10 例；`spec_json` 形状 10/10＝顶层七键（`src_ip/dst_ip/src_port/dst_port/count/drda`＋`layers`）＋`layers=[{"tcp":{}},{"drda":{}}]` 层内双空（#10 首层为 `udp`）。

### 8.1–8.5 逐条去向表（10/10 合入，零作废）

| 存量 ID | 类型 | 关键形状 | 去向 |
|---|---|---|---|
| `drda_excsat` | 正 | `association=excsat`，9 包 | **合入** #1：顶层七键按 §1 改写；`association` 待 G-DRDA-1 登记后填层内 |
| `drda_security_check` | 正 | `association=security`＋user/token，13 包 | **合入** #2 |
| `drda_database_connect` | 正 | `association=database`＋SAMPLE，15 包 | **合入** #3 |
| `drda_sql_success` | 正 | `association=sql`＋sql{0/00000}，17 包 | **合入** #4（＋P4 修钉自指） |
| `drda_sql_error` | 正 | `association=sql`＋sql{-204/42704}，17 包 | **合入** #5（＋P4 修钉自指） |
| `drda_dss_min_length` | 正 | `dss_length=10`＋segments，9 包 | **合入** #6（`dss_*` 待登记） |
| `drda_ipv6_excsat` | 正 | v6 地址，9 包 | **合入** #7（地址族同住 `ip` 层） |
| `drda_multi_session` | 正 | `sessions[2]`，18 包 | **合入** #8（`sessions` 待登记；走链路已具） |
| `drda_dss_length_mismatch` | 负 | `dss_length=11` vs 10，锚 `dss_length` | **合入** #9（锚词逐字保留） |
| `drda_udp_rejected` | 负 | `[udp,drda]`，锚 `tcp` | **合入** #10（判死形状保留） |

**结论**：10/10 全部有明确去向，**无一条"作废不注原因"**。改写在 P4 按设计 §13.1 执行。

### 8.6 对照旧需求文档逐条核对（10.2）

`29-drda-design.md` §1–§12／`29-drda-testcase.md` §1–§8 逐条核对：10 ID 集合／顺序／正负比（8 正＋2 负）／`packet_count` 序列（9/13/15/17/17/9/9/18）全保持；§1.3 不变量 8 条、§3.3 代码点 11 个、§2.2 CCSID 规则、§4 状态机三节全继承；旧文档"层尚未注册"按实测更正为"已注册已落码"；`transport` 别名语义、`sql` association 档、#4/#5 `rqscrr same_as_packet` 自指两处在新文档诚实声明为 P4 修钉项；**无旧条目被静默删除**。

---

## 9. 修订记录

- v1.0.0（2026-09-27）：P1–P3 文档轨产物（车道 A，#84 REDO 真写）。建立 10 ID 契约（8 正＋2 负）、正负例逐项断言契约、三源回指行、9.52 对账两行（29＝24＋5）、§3.15 三项、A′/B′ 两分类表、§3.14 豁免边界审计、存量 10 例逐条审计去向、实现后执行建议。**不跑 suite、不启动服务器**；ID 权威＝本文 §2。

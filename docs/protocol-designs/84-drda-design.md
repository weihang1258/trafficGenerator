# DRDA（DRDA 分布式关系数据库架构，IBM DB2 DSS/DDM）设计契约

> 版本：v1.0.0（P1–P3 文档轨产物；#84 drda REDO）
> 日期：2026-09-27
> 车道：并发管线车道 A（文档轨）｜协议号：**84**（ledger 执行顺序；文件按任务指令命名 `84-drda-*.md`）
> 配套文件：`docs/protocol-designs/84-drda-testcase.md`、`trafficgen/test/protocol_pcap/cases/drda.json`（现存 10 例）
> 旧基线：`docs/protocol-designs/29-drda-design.md` / `29-drda-testcase.md`（v1.0.0 2026-08-20，历史体裁，**不删除**；逐条核对见 testcase §8.6 与本设计 §13.1）
> 规范基线：The Open Group DRDA V5 Vol.1–3（DSS/DDM 头 §10.1/§10.3、代码点表 §3.3/§10.4）＋ IBM DB2 现网行为形态 ＋ 本机 TShark 3.6.14 `packet-drda.c` dissector 实测 **18** 个 `drda.*` 字段。
> **层链唯一真相**：本契约全文示例只有纯 `layers` 形——地址只住 `ip` 层（`src`/`dst`；IPv6 地址族同住 `ip` 层，仓库无 `ipv6` 层）、端口只住 `tcp` 层（`src_port`/`dst_port`）、数量只走 `flow_control`；顶层只允许 `layers`/`flow_control` 家族/`output`（CORE_MEMORY §1.11–1.13）。任何顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/`drda` 子映射都判违规。
> **注册现状**：`drda` 层**已注册**（`layers/registry.go:612-625`，`CategoryTerminal` + `DependsOn ["tcp"]` + `FieldContract {"tcp.dst_port": "446"}`），且 `allowedProtocols["drda"]=true`（`core/protocols.go:35`）。本文**不宣称本次跑过 suite、不启动服务器**；所有"已落码/未落码"结论均标实测出处。
> **与 29-drda 的关系**：29-* 是"层尚未注册"时代的设计稿（当时零落码）；本契约是注册＋875 行落码后（builder 98＋planner 240＋layer_gen 126＋types 9＋drda_test 402）的 REDO 重写，旧文档的 10 ID / 包数序列 / 代码点表全继承（§13.1），"未注册"论断按实测更正。

---

## 1. 范围、证据等级与已落码边界

本设计定义 IBM DRDA（Distributed Relational Database Architecture）在 TCP 446 上的 DSS（Data Stream Structure）/DDM（Distributed Data Management）报文生成契约：关联四阶段（EXCSAT→ACCSEC→SECCHK→ACCRDB）＋ SQLAM（SQLDTA→SQLCARD 成功/错误）＋ 长度边界 ＋ IPv4/IPv6 ＋ 多会话。

**证据等级三档（本契约纪律）**：

| 档 | 可写内容 | 是否固定线字节 |
|---|---|---|
| ①规范原文级 | DSS/DDM 10 字节头布局、11 个 v1 代码点、关联状态机、SQLCARD SQLCODE/SQLSTATE 语义 | 是——逐字节可断言 |
| ②dissector 实测级 | Wireshark `drda.*` 字段名与取值（本机 TShark 3.6.14 实测 **18** 字段，口径 `tshark -G fields \| grep drda` 去噪后计数） | 是——但仅作断言通道，不改写线真相 |
| ③实现现状级 | 本仓库 `internal/protocol/drda/*` 的已落码能力边界（哪些配置键被消费、哪条路缺接线） | 是——作为"今日可达/不可达"的判据 |

**已落码边界（实测，2026-09-27 HEAD）**：

- 生成器：`internal/protocol/drda/layer_gen.go`（126 行）——链路事件驱动，`emitSegments` 按 `DSSSegments` 或 `buildDefaultSegments` 展开请求/响应对；SQLCARD 响应带 SQLCODE（`0x1252`）＋SQLSTATE（`0x1495`）参数；支持 `Sessions[]` 多会话展开（`layer_gen.go:44-55`）。
- 旧 planner：`internal/protocol/drda/planner.go`（240 行）——flat 路径 `Plan()` 自产 TCP 握手/挥手（`planner.go:66-100`）；**响应无参数**（`respCodePoint` 映射后 `ddmBuild(0x01, corr, respCP, nil, false)`，`planner.go:135-144`）；**不展开 `Sessions`**（全函数无 `Sessions` 引用）；校验 `dss_length`（`planner.go:35/39`）。
- 字节原语：`internal/protocol/drda/builder.go`（98 行）——`ddmBuild`（10 字节头＋参数 TLV）、`param`（`length(2)+cp(2)+data`，空 data 产 4 字节空参数）、`u16enc/u32enc`；`chained=true` 强制 `format=0x41`（`builder.go:42-44`）。
- 配置结构：`core/types.go:1361-1420`——`DRDAConfig` 13 JSON 键 / `DRDASegment` 6 键 / `DRDASQLConfig` 5 键 / `DRDASession` 3 键（`types.go` 实读，见 §2.3）。
- **未接线（关键现状，P4 必办）**：`layers/chain_planner_translate.go` **51 个 `case` 无 `case "drda"`**（实测 `grep -c`）；层内 11 个业务键今日无翻译住处 → **G-DRDA-1**。`DRDA: spec.DRDA` 仅是 Meta 直传行（`chain_planner_translate.go:121`，coap/sip 同款）。

当前 `cases/drda.json` **10 例**（8 正＋2 负），全部是**过渡形**（顶层七键＋层内双空，见 §13.1）。

---

## 2. 推荐配置、层链与事件形状

### 2.1 层链

唯一合法链形：**`[ip, tcp, drda]`**（IPv6 地址族同住 `ip` 层，不新增层）。`drda` 是**终结层**（`CategoryTerminal`），无 `TransportOn`、无 `InnerRequired`——registry 实测见 `registry.go:612-625`。

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.84", "dst": "198.51.100.84"}},
    {"tcp": {"src_port": 12345}},
    {"drda": {
      "ccsid": 1208,
      "correlator_start": 1,
      "correlator_inc": 1,
      "security_user": "TESTUSR",
      "rdb_name": "SAMPLE",
      "sql": {"data": [1, 2, 3, 4], "code": 0, "state": "00000", "diagnostic": ""}
    }}
  ],
  "flow_control": {"flows": 1}
}
```

> **`tcp.dst_port` 不写**：由 `drda` 层 `FieldContract {"tcp.dst_port": "446"}`（`registry.go:613`）补齐。用户显式写非 446 端口 → 域校验拒。
> **今日不可达声明**：上例的层内 `drda` 键中，只有 registry 已登记的 10 键能过 V9（§2.2）；`association`/`sessions`/`dss_length`/`sql.statement` 等今日**无住处**（G-DRDA-1/G-DRDA-2），P4 先登记＋接线再落盘，今日不把过渡形冒充目标形。

### 2.2 层内配置键（**唯一权威 = registry `Fields`，实测 10 键**）

`registry.go:614-624` 实读（`session_start` 的 `Min:0 Max:0` = V9 无界，`complete.go:307` 放行语义）：

| 键 | 类型 | 消费现状（实测） |
|---|---|---|
| `transport` | string | ✅ 旧 planner 作 `association` 空值时的 legacy 别名（`planner.go:169-172`）；layer_gen 路径经同一 `buildDefaultSegments` 消费 |
| `session_start` | int | ❌ **死配置**——`core.DRDAConfig` 有同名字段（`types.go:1371`）但 planner/builder/layer_gen **零消费**（G-DRDA-2） |
| `ccsid` | uint16 | ✅ ACCSEC 参数 `0x2113` 的 u16 数据（`planner.go:183-187`；layer_gen 同源） |
| `correlator_start` | uint16 | ✅ 起始 correlator（0→1 缺省；`planner.go:56-59`，`layer_gen.go:29-32`） |
| `correlator_inc` | uint16 | ✅ 递增步长（0→1 缺省） |
| `security_user` | string | ✅ SECCHK 参数 `0x11a0` 数据（占位字节，非真实密码） |
| `security_token` | list | ⚠️ 结构有、今日请求编码**未消费**（SECCHK 只放 `security_user`；token 面待确认，G-DRDA-3） |
| `rdb_name` | string | ✅ ACCRDB 参数 `0x2115` 数据（空→`SAMPLE` 缺省，`planner.go:204-208`） |
| `sql` | object | ✅ `SQL != nil` 即追加 SQLDTA；`code/state` 进 SQLCARD 响应参数（仅 layer_gen，`layer_gen.go:92-107`；旧 planner 响应无参数） |
| `dss_segments` | list | ✅ 非空时绕过默认序列，直接编码用户段（`planner.go:106-110`，`layer_gen.go:62-66`） |

**层字段范围校验（V9）**：白名单制——10 键之外的任何层内键 → `layers: layer "drda": unknown field %q`（`complete.go:293` 实测逻辑）。`sql`/`dss_segments` 是 `object`/`list` 型无界字段（`Min==0 && Max==0` 直接 skip，`complete.go:307`），其**内部**键不受 registry 约束。

### 2.3 非 registry 业务键（今日住 flat 路径，P4 迁入层内）

`core.DRDAConfig`（`types.go:1361-1382`）另有 4 个 JSON 键不在 registry 内，今日只经 `strategy_convert.go:1456-1458` 的顶层 `case "drda"`（`parseSubconfigJSON[*DRDAConfig]`）到达：

| 键 | 类型 | 语义 | 去向 |
|---|---|---|---|
| `association` | string | 默认序列截断档：`excsat`=1 对 / `security`=3 对 / `database`=4 对 / `sql`=全＋SQL；空＝`transport` 别名，仍空＝全序列（`planner.go:166-172`） | **P4 登记进 registry**（G-DRDA-1） |
| `dss_length` | int | 声明长度一致性校验（负例注入口，非线上字段） | **P4 登记或转 `wire_fault`**（G-DRDA-1） |
| `sessions` | list | `DRDASession{ID/SrcPort/CorrelatorStart}` 多会话展开（仅 layer_gen，`layer_gen.go:44-55`） | **P4 登记进 registry**（G-DRDA-1） |
| `sql.statement` | string | 可选 SQLSTT 数据（今日**零消费**，code 注释与 builder 均无引用） | G-DRDA-2（删除或实现二选一） |

> **纠偏注记**：P1–P3 初稿曾把 `association`/`sequence` 写成 registry 键——实测否决：`association`/`sequence` 对象键属于 **`mms`** 层（`registry.go:596-609`），`drda` 无此二键。凡旧文引用以此为准更正。

### 2.4 `association` 四档截断语义（`buildDefaultSegments`，`planner.go:154-223` 实读）

| 档 | 请求对数 | 序列 | 用例 |
|---|---|---|---|
| `excsat` | 1 | EXCSAT | #1/#6/#7/#8 |
| `security` | 3 | EXCSAT＋ACCSEC＋SECCHK | #2 |
| `database` | 4 | ＋ACCRDB | #3 |
| `sql`（及空/非法值） | 5（有 `sql` 时） | ＋SQLDTA | #4/#5 |
| `""`＋`transport:""` | 全序列 | 同 `sql` 档（无 SQL 则 4 对） | — |

注：旧 JSON `#4/#5` 写作 `"association": "sql"`——`assoc` 非空非三档名→落全序列，行为等价，不算矛盾（testcase §8.6 注记）。

---

## 3. 线格式权威（逐字段，P4 builder 硬对照表）

### 3.1 DDM 头 10 字节（相对 TCP payload 起点；IPv4 帧偏移 54，IPv6 74）

| 偏移 | 字段 | 大小 | 值/语义 | 断言通道 |
|---:|---|---|---|---|
| 0 | DDM length | 2 | U16 BE，总长（含 10B 头），最小 10 | `drda.ddm.length` ＋ frames hex |
| 2 | Magic | 1 | `0xd0` | `drda.ddm.ddmid` ＋ hex |
| 3 | Format | 1 | `0x01` 基础；`0x41`＝chained 首 DDM | `drda.ddm.format` ＋ `drda.ddm.fmt.bit1` |
| 4 | Correlator | 2 | U16 BE，请求/响应配对，默认 1 起递增 | `drda.ddm.rqscrr` |
| 6 | Length2 | 2 | U16 BE，从 code point 起计，最小 4；恒等式 `length2 = length - 6` | `drda.ddm.length2` |
| 8 | Code point | 2 | U16 BE，见 §3.3 | `drda.ddm.codepoint` ＋ hex |

最小无参数对象 wire 字节：`00 0a d0 01 00 01 00 04` ＋ 2 字节代码点（#1 packet 4：`…00 04 10 41`）。

### 3.2 参数 TLV

每项 `length(2)+code_point(2)+data`（`builder.go:71-81`）；空 data 产 4 字节空参数（不拒——`len(data)>max` 才拒）。参数长度游标逐个解析，不按字符串终止符猜界。

### 3.3 v1 代码点表（11 个，`builder.go:8-22` 常量实读）

| 代码点 | 名称 | 方向 | 用途 |
|---:|---|---|---|
| `0x1041` | EXCSAT | C→S | 交换服务器属性 |
| `0x1443` | EXCSATRD | S→C | EXCSAT 响应 |
| `0x106d` | ACCSEC | C→S | 访问安全交换 |
| `0x14ac` | ACCSECRD | S→C | ACCSEC 响应 |
| `0x106e` | SECCHK | C→S | 安全检查 |
| `0x1219` | SECCHKRM | S→C | 安全检查结果 |
| `0x2001` | ACCRDB | C→S | 关联关系数据库 |
| `0x2201` | ACCRDBRM | S→C | 关联结果 |
| `0x2412` | SQLDTA | C→S | SQL 数据/参数 |
| `0x2408` | SQLCARD | S→C | SQL 结果状态卡 |
| `0x2414` | SQLSTT | C→S | SQL 语句文本（`sql.statement`，今日零消费，G-DRDA-2） |

响应映射 `respCodePoint`（`planner.go:227-243`）；未知请求码点→无响应（返回 0，不产包）。

### 3.4 阶段参数名（dissector 实测矩阵，text2pcap＋tshark 验证）

SECMEC `0x11a2` / USRID `0x11a0` / PASSWORD `0x11a1` / RDBNAM `0x2110` / UOWDSP `0x2115` / SQLSTT `0x2414`——六名全部经 text2pcap＋`tshark -V` 实测命中，无臆造。实现侧今日编码使用的参数码点为 `0x2113`(CCSID)／`0x11a0`(USRID)／`0x2115`(RDB名)／`0x2160`(SQL数据)／`0x1252`(SQLCODE)／`0x1495`(SQLSTATE)——与 dissector 展示名的对应关系 P4 以抓包逐项钉死，不在本设计编造映射表。

---

## 4. 会话状态机与自动派生（设计权威）

```text
CLOSED
  └─ TCP connect ─> TCP_ESTABLISHED
TCP_ESTABLISHED
  └─ EXCSAT / EXCSATRD ─> EXCHANGED
EXCHANGED
  └─ ACCSEC / ACCSECRD ─> SECURITY_NEGOTIATED
SECURITY_NEGOTIATED
  └─ SECCHK / SECCHKRM(success) ─> SECURITY_CHECKED
SECURITY_CHECKED
  └─ ACCRDB / ACCRDBRM(success) ─> RDB_ASSOCIATED
RDB_ASSOCIATED
  ├─ SQLDTA / SQLCARD(SQLCODE=0) ─> RDB_ASSOCIATED
  ├─ SQLDTA / SQLCARD(SQLCODE<0) ─> RDB_ASSOCIATED（应用错误，不断链）
  └─ close/FIN ─> CLOSED
```

- 失败终止：`SECCHKRM`/`ACCRDBRM` 失败 → 终止，不得发 SQLDTA——**今日 planner 无失败分支语义** → B′ **G-DRDA-5**。
- 重连：显式 `reconnect` 新连接 correlator 从 `correlator_start` 重起——今日无该键 → G-DRDA-5。
- 多会话：`sessions[]` 每项独立四元组＋correlator＋状态机（#8，18 包）；IP 版本只改帧偏移/伪首部，不改 DRDA 字节。

---

## 5. 依赖声明与端口契约

- 依赖声明＝`DependsOn ["tcp"]`（单值，`registry.go:612`）＋ FieldContract `tcp.dst_port=446`（`registry.go:613`）。
- `[udp, drda]` 判死（#10，锚词 `tcp`，载体校验口径）。
- `drda` 外再放应用终结层 → 链校验拒（Terminal 语义）。

---

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- 声明式事件流：`emitSegments`/旧 `Plan()` 均为逐段 emit，无全量聚合；`out` 通道缓冲 32（旧 planner）。
- pcap/NIC 双路验收；落盘默认 `/tmp/mcp-pcaps/drda/`。
- 吞吐/并发/内存目标标「待 P4 基准」——§6.5 纪律，不写承诺数字。

---

## 7. 错误处理与错误传播

| 编号 | 条件 | 处理 | 出处 | 用例 |
|---|---|---|---|---|
| V1 | 层链含 UDP 或缺 TCP | Validate 拒，错含 `tcp` | 链载体校验 | #10 |
| V2 | `dss_length < 6` | 拒 `dss_length %d is invalid (smaller than the 6-byte DSS header)` | `planner.go:35` | —（下界形） |
| V3 | `dss_length` 与段 `length` 不一致 | 拒 `dss_length %d mismatches segment length %d` | `planner.go:39` | #9 |
| V4 | DDM length 越界 `[10,0xffff]`／参数 `<4` | `ddmBuild`/`param` 拒 | `builder.go:47-57/71-81` | 设计边界 |
| V5 | SECCHK/ACCRDB 失败仍发 SQL | 应拒——今日无语义 | — | G-DRDA-5 |
| V6 | 真实密码/加密协商 | 不接受，unsupported | 设计边界 | — |

负例 `expect` 键集合严格为 `{"expect_error","error_contains"}`；锚词逐字对 validator 字面值（#9 `dss_length` 对 `planner.go:35/39`；#10 `tcp` 对载体错口径）。

---

## 8. 存量审计口径

`cases/drda.json` 10 例逐条审计见 testcase §8.6（合入 10/10，零作废）。审计基线形状：`layers=[{"tcp":{}},{"drda":{}}]` 层内双空＋顶层七键（`src_ip/dst_ip/src_port/dst_port/count/drda`＋`layers`）10/10（#10 的 `layers[0]` 为 `udp`）。

---

## 9. 用例集合摘要（ID 权威在 testcase §2）

8 正（T-DRDA-001–008，`packet_count` 9/13/15/17/17/9/9/18）＋2 负（T-DRDA-009/010）。公式：单会话 `3（握手）＋2N（N 个请求/响应对）＋4（挥手）＝2N＋7`；#8 双会话求和 18。约定值 P4 **先跑后钉**。

---

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项矩阵

| # | 规范要求（DRDA V5 卷章节） | 业务场景 | 代码现状 | 缺口/用例 |
|---|---|---|---|---|
| 1 | DSS/DDM 10 字节头（Vol.1 §10.1/§10.3） | 每包头可解析 | `ddmBuild` 已实现（`builder.go:42-69`） | #1/#6 已覆 |
| 2 | 代码点表（Vol.1 §3.3/§10.4） | 11 码点逐值 | 常量＋响应映射已实现 | #1–#5 已覆 |
| 3 | 关联状态机（EXCSAT→ACCRDB） | 建连四阶段 | `buildDefaultSegments` 四档截断 | #1–#3 已覆；失败终止→G-DRDA-5 |
| 4 | SQLAM 结果（SQLCARD） | 成功/错误双分支 | layer_gen 响应参数已实现；旧 planner 无参数 | #4/#5 已覆（走链路）；旧路 P4 修钉 |
| 5 | CCSID 编码（1208＝UTF-8） | 字符串字节数按编码后计 | `u16enc`＋`[]byte()` 直接编码 | #1–#5（`ccsid:1208`）；EBCDIC→G-DRDA-3 |
| 6 | 长度边界（length≥10／length2≥4／恒等式） | 非法形拒收 | `builder.go` 下界＋`planner.go:35/39` | #6/#9 已覆 |
| 7 | 现网行为（DB2 Connect 标准序） | 与真实 DB2 互操作形态一致 | 形态按文档实现，**无抓包证据** | **B′ G-DRDA-3**（未确认级，按 §5.5 不写死） |
| 8 | 多会话＋双地址族 | 会话隔离；v4/v6 对称 | `Sessions[]`（仅 layer_gen）；地址族由 `ip` 层承担 | #7/#8 已覆 |

### 10.2 请求×响应矩阵（7 格）

| 格 | 对 | 去向 |
|---|---|---|
| 1 | EXCSAT→EXCSATRD | #1 已覆 |
| 2 | ACCSEC→ACCSECRD＋SECCHK→SECCHKRM | #2 已覆 |
| 3 | ACCRDB→ACCRDBRM | #3 已覆 |
| 4 | SQLDTA→SQLCARD（成功＋错误） | #4/#5 已覆 |
| 5 | chained 首 DDM（`format=0x41`，`drda.ddm.fmt.bit1`） | 用例通道→A′ 补例 **T-11**（`DDMChained` 常量今日无 planner 可达路径） |
| 6 | SECCHKRM 失败→终止 | B′ G-DRDA-5 |
| 7 | ACCRDBRM 失败→终止 | B′ G-DRDA-5 |

### 10.3 数据形态变体表（14 行）

| # | 变体 | 去向 |
|---|---|---|
| 1 | DDM length 下界 10 | #6 已覆 |
| 2 | length2 下界 4 | #6 已覆 |
| 3 | `length2 = length - 6` 恒等式 | #6 已覆 |
| 4 | magic `0xd0` | #1–#8 已覆 |
| 5 | format `0x01` 基础形 | #1–#8 已覆 |
| 6 | correlator 递增＋请求/响应配对 | #1–#5 已覆 |
| 7 | 参数 TLV（length/cp/data） | #2–#5 已覆 |
| 8 | CCSID 1208 编码字节数 | #1–#5 已覆 |
| 9 | SQLCODE 有符号 U32 BE | #4/#5 已覆（链路） |
| 10 | SQLSTATE＋诊断文本 | #5 已覆（链路） |
| 11 | IPv6 offset 74 字节等价 | #7 已覆 |
| 12 | 双 session 四元组/correlator/状态隔离 | #8 已覆 |
| 13 | SECMEC 机制值面（现网取值） | B′ G-DRDA-3 |
| 14 | 失败 RM 参数面（终止语义载体） | B′ G-DRDA-5 |

---

## 11. P2 D-DRDA-1 代码设计（CORE_MEMORY §8 八要素；门1 获批＝定稿）

**文件清单**：`internal/protocol/drda/{builder,planner,layer_gen,types-alias}.go` 存量；P4 新增＝registry 字段登记＋`chain_planner_translate.go` 的 `case "drda"`＋`checkLayerChainStaticCopy` 式守卫（如适用）＋cases 改写。不碰共享文档/.go（跨协议守卫上报主线程，G-DRDA-4）。

**接口签名**：沿用 `Planner.Validate/Plan`＋`DRDAGenerator.Generate/emitSegments`；层内新键经 `GenRequest.Meta.DRDA`（既有直传行 `chain_planner_translate.go:121`）到达生成器。

**数据结构**：`core.DRDAConfig` 13 键（§2.3）即线上结构；registry 补登记 `association/sessions/dss_length/sql_statement` 四键（`session_start` 按 G-DRDA-2 退役，**不登记**）。

**主流程**：链路 `[ip,tcp,drda]`→V9→Meta→`emitSegments`（`DSSSegments` 非空直编，否则四档默认序列）→请求/响应成对 emit→TCP 挥手。

**错误分支**：§7 V1–V6；旧 planner 的 param-less 响应与无 `Sessions` 展开在 P4 收敛到 layer_gen 语义（修钉项，testcase §8.6）。

**性能边界**：§6（O(n) 流式，无聚合）。

**冲突点**：`CheckProtoFlat` 无 drda 分支＋`mapToFlowSpec` ValidationErrors 注入块无 drda 分支（G-DRDA-4，共享面，车道不改）。

**回滚**：纯加法（registry 加键＋translate 加 case），删即回滚；cases 改写保留旧包数公式复核。

**明确不解决**：G-DRDA-2（死配置三键去向：`transport` 别名保留、`session_start` 删除、`sql.statement` 删除或实现二选一）＋G-DRDA-5（失败终止/重连语义，迁入计划见 §14）。

---

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 旧顶层七键逐个写去向（`src_ip`→`ip.src` 等；顶层 `drda` 子映射→`layers[]` 的 `drda` 条目——**今天无住处，G-DRDA-1**：translate 无 case，层内键被 V9 拒）；数量走 `flow_control`；目标纯 layers 样例见 §2.1；非负例顶层键＝0 自查见 §13.1 | §2＋§13.1 |
| §2 策略/任务 | 策略＝单 drda 模板＋`flow_control`；任务＝多策略合跑＋总量封顶（`drda` 不在 worker/task 特判名单） | `internal/core/worker.go` |
| §3 五件套 | 会话表/事务序列/关联关系/插入位置/时间线见 testcase §6.1 设计映射；**有长连接载体（TCP 446 单连接四阶段＋SQL 多轮），不豁免** | testcase §3/#4/#8 |
| §4 查规范 | DRDA V5 Vol.1–3（§10.1/§10.3 头、§3.3/§10.4 码点）＋DB2 现网形态＋tshark 18 字段＋§3.4 参数名矩阵；八项矩阵＋子表①② | §10 |
| §5 依赖与错误 | `DependsOn ["tcp"]`＋FieldContract 446；错误分支 §7 | §5/§7 |
| §6 性能 | §6（O(n) 流式；双路验收；数字待 P4 基准） | §6 |
| §7 三份文档 | `84-drda-design.md`＋`84-drda-testcase.md`（per-protocol 草稿层）＋D-DRDA-1（§11，门1 获批＝定稿）＋T-DRDA（testcase §2–§4）＋generated schema（P4 重跑） | 修订记录＋§11 |
| §8 设计先行 | P1–P3 先于 P4；门1 获批＝D-DRDA-1 定稿＝开工门 | 提交序 |
| §9 测试三源 | 官方文档条款（§10 各条＋节号）＋D-DRDA-1（§11）＋已确认现网行为（**未确认级→G-DRDA-3，不冒充第三源**） | testcase §5 |
| §10 评审闭环 | 每阶段对抗自重审＋收官隔离复审＋修轮；红先绿后 | 报告 §3 |
| §11 白话 | 报告首节一句白话 | 汇报 |
| §12 动态清单 | 四元组＝ip/tcp 层（开策略见 testcase §6.2）；业务字段逐个列开/不开＋理由（`association` 开等；**无序号算法代码位置**——业务无逐流序号语义，诚实"不适用"） | testcase §6.2 |
| §13 schema 派生 | registry drda 行→schemagen 重跑；struct 标签字面量锁 | §2.2 |
| §14 真实流程 | suite 经 MCP 建任务→引擎生成→tshark `drda.*`＋frames hex 双通道；先跑后钉；pcap 落 `/tmp/mcp-pcaps/drda/` | testcase §7 |

---

## 13. P3 对接清单（T-DRDA 草稿输入；正文落 testcase 文件）

### 13.1 存量改写清单（10/10 合入，零作废）

| 存量 ID | 顶层七键去向 | 层内填充 | P4 修钉 |
|---|---|---|---|
| `drda_excsat`（#1，9 包） | 地址→`ip` 层；端口→`tcp`（`src_port` 显式，`dst` 由契约补）；`count:1`→`flow_control.flows=1`；`drda` 子映射→层内 | `association` 待登记后填层内（G-DRDA-1） | — |
| `drda_security_check`（#2，13 包） | 同上 | `security_user/token` 填层内（token 面待 G-DRDA-3） | — |
| `drda_database_connect`（#3，15 包） | 同上 | `rdb_name` 填层内 | — |
| `drda_sql_success`（#4，17 包） | 同上 | `sql{data,code:0,state}` 填层内 | 旧路响应参数收敛（走链路已具） |
| `drda_sql_error`（#5，17 包） | 同上 | `sql{data,code:-204,state:42704,diagnostic}` | 同上 |
| `drda_dss_min_length`（#6，9 包） | 同上 | `dss_segments`＋`dss_length` 填层内（待登记） | — |
| `drda_ipv6_excsat`（#7，9 包） | 地址族同住 `ip` 层（`2001:db8::1→::2` 存量形保留） | 同 #1 | — |
| `drda_multi_session`（#8，18 包） | `sessions[]` 填层内（待登记；`src_port` 逐 session） | — | 旧 planner 无展开（走链路已具） |
| `drda_dss_length_mismatch`（#9，负） | 形状不限（负例）；锚 `dss_length` 保留 | — | — |
| `drda_udp_rejected`（#10，负） | `[udp,drda]` 形保留（判死形状）；锚 `tcp` 保留 | — | — |

**非负例顶层键＝0 收官自查（P2）**：改写后 8 正例顶层只留 `layers`/`flow_control` 家族/`output`；`count` 去向 `flow_control.flows=1`（10/10 例原有 `count: 1`，R2 补）。

### 13.2 去向审计（新旧编号）

既有 `29-drda-*`（历史体裁）不删除；本车道产出 `84-drda-*`（新编号，账本执行顺序 #84）；`/tmp/pipe` 报告目录为 `/tmp/pipe/84-drda/`（无 29-drda 目录）。旧文档"层尚未注册"论断已失效，以本契约 §1 注册现状为准；其余 10 ID/包数/码点全继承。

### 13.3 B′→D-条目"明确不解决＋迁入计划"（G-DRDA-2/5）

见 §14。`session_start`（registry 有、types 有、零消费）→删除；`sql.statement`→删除或实现；失败终止/重连/`sql_statement` 多语句→G-DRDA-5 迁入计划。

---

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

- **G-DRDA-1**（层内业务键翻译）：`translateTerminalConfig` 无 `case "drda"`（51 case 实测无）；层内 `association/sessions/dss_length` 今日 V9 全拒（`association`/`sequence` 对象键是 mms 的，drda 从无此键——§2.3 纠偏）。P4：registry 补登记＋translate 加 case。过渡形（顶层 `drda` 子映射＋`strategy_convert.go:1456` 直传）保留至迁入完成。
- **G-DRDA-2**（死配置）：`transport` 别名保留；`session_start` 删除；`sequence` 对象键（旧 JSON 从未使用，且非 drda 键）删除；`sql.statement` 删除或实现二选一。
- **G-DRDA-3**（现网证据升级）：DB2 Connect/服务器抓包级确认；SECMEC 值面、`security_token` 编码面、SECCHKCD、SQLCAXGRP 组。P4 前置确认项，不挡开工；确认前按 §5.5 不写死。
- **G-DRDA-4**（presence/白名单守卫缺 drda 分支）：`CheckProtoFlat`（`strategy_convert.go:8322` 起，dns/mqtt/cwmp/megaco/hl7/mmse/ntlm/ocsp/edp/xmrmining/bacnet 同款分支缺 drda）＋`mapToFlowSpec` ValidationErrors 注入块无 drda 分支。跨协议共享面，车道不改，上报主线程。
- **G-DRDA-5**（失败终止/重连语义）：SECCHKRM/ACCRDBRM 失败终止、`reconnect` 新连接、`sql_statement` 多语句事务。planner 今日无失败分支语义。

A′ 补例建议 **T-11**（chained format `0x41` 首 DDM＋`drda.ddm.fmt.bit1` 断言；`DDMChained` 常量今日无 planner 可达路径）。

---

## 15. 修订记录

- v1.0.0（2026-09-27）：P1–P3 文档轨产物（车道 A，#84 REDO 真写）。自重审三轮（P1 三轮/P2 两轮/P3 两轮，末轮干净；详见报告 §2）：R1 补三路对照出处行号＋候选方案三行重写；R2 改写 G-DRDA-1"今天无住处"＋删序号算法编造行号；R3 逐档核对四档截断。文档逐条自核对（10.1：29 点逐点结论＋用例号；10.2：29-* §1–§12/testcase §1–§8 逐条核对，无静默删除）。**P1–P3 初稿关键勘误**：registry drda 键为 **10**（初稿误写 11，`association`/`sequence` 系 mms 键）；`session_start` 在 `core.DRDAConfig` **有字段**（初稿误写"types 无"）但零消费；translate 共 **51** case（初稿误写 49）；旧 planner 响应无参数＋无 `Sessions` 展开（初稿未点名）。**不跑 suite、不启动服务器**；ID 权威＝testcase §2。

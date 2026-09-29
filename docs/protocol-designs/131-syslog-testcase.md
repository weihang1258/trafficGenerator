# #131 syslog（RFC 5424 / RFC 3164）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨批次二，as-built）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/131-syslog-design.md` v1.0.0（D-SYSLOG-1）
> 旧基线：**无**（首份；代码注释引用的 `testcases_syslog.md` 为死文档，不作为依据，设计 §0 #1）
> 机器契约：`trafficgen/test/protocol_pcap/cases/syslog.json`（**1/1 ID 与本版 §2 一致，顺序一致，2026-09-29 机读实测**；顶层键 `{layers, syslog}` ——**非负例顶层键 1 处，红**，见 §1/§8）
> 白话一句：**一条检查：空配置也能发出一条标准的 `<14>1 - - - - - -`（用户级 info 日志，无正文）；其余 22 个校验分支（另有链级 3 门）"胡来能不能被拦下"的检查今天一条都还没建——全部立项待补，一条不冒充。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生。**本协议 pcap 契约面今日仅 1 个唯一语义 ID：1 正 + 0 负**（派生规则：设计 §3 每个字段条款、§5 每个派生行为、§7 每行错误处理在本文有对应断言**或**对应 A′ 立项；断言不得超出设计声明范围；不虚构用例——1 例就写 1 例）。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：1/1 例顶层键 = `{expect,id,proto,spec_json,summary}`；`spec_json` 顶层键 = **`{layers, syslog}`**（**非负例顶层键 = 1**：顶层 `syslog` 空子映射与层链并存——as-built 合规形但非零残留，配置唯一可达入口，G-SYSLOG-1；**今日不可删**，删则 facility/severity 缺省消失、线字节变 `<0>`（G-SYSLOG-2））；层形 `[udp,syslog]` ×1；正例 `expect` 键 = `{packet_count, fields, frames, notes}`；负例 0。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`udp.dstport`、`syslog.*` 字段、offset 42 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线（2026-09-29 `-G fields`/`-G decodes` 实测，tshark 3.6.14）**：`udp.port 514 → syslog` 绑定在案，`syslog.*` **12 字段**可用：`syslog.facility`(FT_UINT8)/`syslog.level`(FT_UINT8)/`syslog.msg`(FT_STRING)/`syslog.version`(FT_STRING)/`syslog.timestamp`(FT_ABSOLUTE_TIME)/`syslog.timestamp_rfc3164`(FT_STRING)/`syslog.hostname`/`syslog.appname`/`syslog.procid`/`syslog.msgid`(均 FT_STRING)/`syslog.msgid.bom`(FT_UINT24)/`syslog.msu_present`(FT_BOOLEAN)。**进制纪律**：`syslog.facility`/`syslog.level` 十进制串；文本字段原样串。**`syslog.msg` 值域口径（实测）**：3.6.14 的该字段值 = VERSION 起的剩余报文（存量断言 `1 - - - - - -` 即此形），不是 RFC 5424 §6.4 的纯 MSG 部分——新例断言按此口径取值，不得臆造"纯 MSG"。**TCP 514 绑定为 rsh 非 syslog**（G-SYSLOG-12）：TCP 载体（G-SYSLOG-3 接线后）用例须 `decode_as` 或改 fixture 端口。

**断言基线**：今日 1 例只用 `packet_count` + `fields` + `frames`；UDP 载体无 `has_handshake`/`terminates` 断言（无连接无终止概念）。4 条 fields 断言 + 1 条 frames 断言已逐条对实测 pcap 复核（2026-09-29，全命中，§3）。

**动态字段禁止硬编码**：IPv4 ID/校验和逐次随机——frames 断言锚点（offset 42 起）不触 18-19/24-25 字节；bsd 格式空 timestamp 取当前时刻——新例必须显式钉 timestamp（设计 §5 确定性两条）。

**包数约定**：`len(messages)>1` 时为 `len(messages)`（实现忽略 `count`）；否则为 `count`（缺省 1）。因此 `len(messages)==1,count=100` 实际生成 100 个数据报；只有多消息（`len(messages)>1`）时才忽略 `count`，不是 `max(count,len(messages))`。

**保活/重试/RST 口径**：UDP fire-and-forget，无 keepalive/重试/RST 概念（协议无此机制，设计 §10.1 行 6/7 显式不适用）；TCP 载体的 FIN/RST 待 G-SYSLOG-3 接线后另立。

## 2. 原子用例索引（1 ID = 1 正 + 0 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count（实测复核） |
|---:|---|---|---|---:|
| 1 | `syslog_smoke_01` | 正 | §3.1：RFC 5424 空配置默认流（`<14>1 - - - - - -`，dst 514 缺省） | 1 |

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

### 3.1 `syslog_smoke_01`（1）

`layers=[{"udp":{}},{"syslog":{}}]` + 顶层 `"syslog":{}`（as-built 形，G-SYSLOG-1/2 口径）。

- `packet_count=1`（messages 空、count 缺省 1）。
- fields：`udp.dstport=514`（帧 1）；`syslog.facility=1`、`syslog.level=6`（PRI `<14>` = 1×8+6，RFC 5424 §6.2.1）；`syslog.msg="1 - - - - - -"`（tshark 口径，§1）。
- frames：帧 1 offset 42 = `3c 31 34 3e 31 20 2d 20 2d 20 2d 20 2d 20 2d 20 2d`（17 字节 = `<14>1 - - - - - -` **全 payload 断言**）。
- **线字节证据（2026-09-29 对 `/tmp/mcp-pcaps/syslog/syslog_smoke_01.pcap` 复核）**：帧 60B（59 实发 + 1 字节 `pad_min_frame` 最小帧填充——**末位 0x00 是链路层填充不是消息内容**，存量 notes 的"0x00 终止符"说法为误诊，G-SYSLOG-11）；VERSION=1、六个字段全 NILVALUE（TIMESTAMP/HOSTNAME/APP-NAME/PROCID/MSGID/SD）、MSG 空省略无尾 SP——与设计 §3.1 编码器逐项吻合。
- **字段缺省来源（as-built 关键）**：facility=1/severity=6 来自顶层 `syslog:{}` 触发的扁平解析缺省（`strategy_convert.go:1501-1502`），非生成器缺省——空层链（无顶层键）将产出 PRI=0（G-SYSLOG-2，本例断言值依赖该键存在）。
- 未断言观察项（随引擎，不进契约）：src 12345（flow 默认）、DSCP CS1(0x20)、TTL 64、DF、IPv4 10.0.0.1→20.0.0.1、MAC 02:00:00:00:00:01→02。

**正例总则**：UDP 载体正例只有"消息面正确性"一类可断言点；多包/BSD/SD/BOM/IPv6 等均为 A′（§6.2），今日不冒充已覆盖。

## 4. 负例契约

**今日 0 负例**。设计 §7 的 22 个 validator/planner 拒绝分支 + 3 个链级门（tcp/tls、unknown field、flat 五键）**全部未建 pcap 负例**——锚词表与代码行号见设计 §7（逐字 22 行，不在此重复）；其中 UDP 上界分支（`:257`）只是**顶层单消息固定近似预检**：只估算 `cfg.Msg` 与顶层 StructuredData，未检查 `messages[]` 各条目或最终编码长度，且固定近似存在合法输入误拒可能，不能作为完整 UDP 65507 覆盖。每分支一例、`expect` 严格只有 `expect_error`+`error_contains`、锚词 = 代码文案子串。**优先补的 9 条**（覆盖高频误配 + 全部锚词形态）：facility>23（:119）/ severity>7（:122）/ format 非法（:131）/ version=0+rfc5424（:140）/ transport=tcp（**链级锚词** `not supported by the layer chain yet`，非 :153）/ timestamp 非 RFC3339（:204）/ 字段超长（:274）/ SD 未闭合（:297）/ UDP 顶层近似预检触发（:257）；另需补 `messages[]` 超限/临界值边界以证明当前漏检缺口，不能将其写成已覆盖。

**负例纪律**：`expect_error=true` 用例不得混入成功包结构断言；锚词与 validator 错误字面值一一对应（设计 §7 表为唯一出处）；presence 形状负例（`{"layers":[…],"syslog":{}}` 判死）**今日不建**——`CheckProtoFlat` 无 syslog 分支，建了会真绿 = 假通过（G-SYSLOG-1，与 12-P2 裁定一致）。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 5424/3164/5426/6587/5425 原文（设计 §10）+ D-SYSLOG-1（设计 §11）+ tshark 3.6.14 字段表与 pcap 实测（`/tmp/mcp-pcaps/syslog/`）→ 1 ID（本契约 §2）。

**1 ID 逐项回指（§9.5 要求）**：#1←设计 §3.1/§3.2（PRI 公式 + NILVALUE + 空 MSG 省略）+ §8（dst 缺省 514）。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 原文（2026-09-29 核对）+ 仓库落码反推 + tshark 3.6.14 字段与 pcap 实测**，非纯规范反推（真实收集器/rsyslog 线字节未取到，归 G-SYSLOG-8 批次补证）。RFC 5426 尺寸规范引用统一为 **§3.2**；错误文案中的 `(RFC 5426 §6)` 是代码历史字面，按原文匹配但不作为规范锚点。
- **对账两行**：**要求逻辑点总数 = 60**（八项 8 行 + 矩阵 21 格 + 变体 23 行 + 商业映射 8 行）；**用例覆盖数 = 4**（八项 1 + 矩阵 1 + 变体 1 + 商业 1——同为 `#1` 一例的四向计数）；**不适用/明确不解决 = 12**（八项 2〔行 6/7〕+ 矩阵 8 + 变体 0 + 商业 2）；**开放立项 = 44**（八项 5 + 矩阵 12〔A′ 10 + 待实现边界 2〕+ 变体 22〔A′ 20 + 待实现 1 + 分支在案 1〕+ 商业 5〔A′ 4 + 待实现 1〕）。4+12+44=60 ✓
  **粒度声明**：行/格粒度每点 1 计；矩阵 21 格与变体 23 行的 A′ 存在语义重叠（如 SD 形态两表各计 1），**两表各自内部加和自洽即为口径**，跨表不求和不重复。**反查全绿 ≠ 覆盖全**（§9.52 原文）。逐表重数见设计 §10.1（8 = 覆 1 + 立项 5 + 不适用 2）/§10.2（21 = 覆 1 + A′ 10 + 待实现 2 + 不适用 8）/§10.3（23 = 覆 1 + 单测待收编 20 + 待实现 1 + 分支在案 1）/§10.4（8 = 覆 1 + A′ 4 + 不解决 2 + 待实现 1）。
- **门3 抽查候选**：唯一用例 = #1（1 帧最小报文：字段序/PRI 公式/NILVALUE/空 MSG 四维一体）。建议门3 抽 #1 + A′ 首例（多包或 BSD，接线后）。

### 5.3 自审（机读，不手算）

自审脚本 `/tmp/pipe/doc-lanes/syslog-selfaudit.py`（落盘可复跑）：对 cases JSON 逐例核对 ID 集合/顺序、`spec_json` 顶层键集合、expect 键集合、packet_count、fields 断言值、frames offset+hex 与 pcap 实测（tshark 子进程）——**5 轮（含 3 轮修复），末轮干净（连续 2 轮 31 项零失败）**；对本文 §2/§3 的每个数字与 §5.2 的加和做程序化复算。修复轮发现并更正：§10.2 矩阵逐格归属（A′ 12→10、待实现 3→2、不适用 5→8）与 §5.2 对账（3+19+38→4+12+44）。结论：全部一致，1 处已知的"红"为如实申报（非负例顶层键=1，G-SYSLOG-1），非自审失败。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | UDP 同流多 datagram = `messages` 逐条 / `count` 复制（chain 单测已覆行为） | **A′ 立项**（`syslog_multi_message`/`syslog_count_copies`） |
| ② | 非正常结束 | UDP 无连接无终止概念——**不适用**（显式声明，不硬凑）；TCP 载体 FIN/RST 随 G-SYSLOG-3 | 不适用 + 待实现边界 |
| ③ | 长保活 | 协议无 keepalive 心跳（设计 §10.1 行 6） | **不适用**（显式声明） |

无空项：① 有 A′ 立项；②③ 有显式不适用声明。

### 6.2 A′/B′ 两分类表

**A′（P4 接线，链级今日即可执行——配置走 as-built 形顶层子映射）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 负例面 | 22 分支锚词例（优先 9 条见 §4） | G-SYSLOG-7 |
| 多包面 | `syslog_multi_message`（2 包，逐包 fields+frames）/ `syslog_count_copies`（count=3） | G-SYSLOG-7 |
| 字段面 | `syslog_full_fields`（TS/HOST/APP/PROCID/MSGID/SD/MSG 全显式 + 6 条 fields 断言） | G-SYSLOG-7 |
| 格式面 | `syslog_bsd_format`（预格式时间钉死，防 now() 非确定） | G-SYSLOG-7 |
| 地址面 | `syslog_ipv6`（offset 62 = 14+40+8，EtherType 86DD） | G-SYSLOG-7 |
| Metadata 面 | `syslog_priority`/`syslog_transport` 断言收编（若 runner 支持 metadata 断言） | G-SYSLOG-7 |
| 上界面 | UDP 顶层近似预检拒绝 + `messages[]` 漏检/临界值边界 | G-SYSLOG-4/7 |
| 缺省面 | G-SYSLOG-2 修复后补 `syslog_empty_chain_default`（纯层链无顶层键 → 断言 PRI 与修复裁定一致） | G-SYSLOG-2 |

**B′（框架面，进设计 §14「明确不解决 + 迁入计划」）**：`CheckProtoFlat` syslog presence 分支 + 游离顶层键通用门（G-SYSLOG-1，等框架级 unknown-key 白名单，禁单协议黑名单分支）/ registry Fields 登记或顶层键白名单化（G-SYSLOG-1）/ 业务字段动态（G-SYSLOG-7，allowlist 无 `syslog` 行）/ BOM 线形回正裁定（G-SYSLOG-5）/ sign 语义（G-SYSLOG-6，明确不解决）/ 存量 notes 文案修正（G-SYSLOG-11）。

### 6.3 3.14 豁免边界审计

**长连接载体**：无（UDP 单载体，TCP 待实现）→ `sessions[]` 形态**不存在**，无豁免声明需要；多流并发由策略级 `flow_control {"flows": N}` 承载（本版无用例，A′ 候选）；**单包多载荷 = 不适用**（RFC 5426 §3.1 一数据报一消息，规范强制，如实声明）。

## 7. 实现后执行建议

1. **P4 顺序**：①先裁 G-SYSLOG-2（缺省断层——影响一切"空配置"类新例的 PRI 断言）与 G-SYSLOG-5（BOM 线形——影响 BOM 例断言口径）；②按 §6.2 A′ 表补例（负例优先）；③G-SYSLOG-11 notes 文案修正随批；④全量复跑后重生成 `trafficgen/docs/protocol-pcap-test/syslog.md`（G-SYSLOG-8）。
2. **实测顺序**：#1（已有，复跑钉）→ `syslog_full_fields`（字段面基线）→ `syslog_multi_message`（包数公式）→ `syslog_bsd_format`（第二格式）→ 负例批（锚词逐一）→ `syslog_ipv6`（offset 62）。
3. 二进制与 HEAD 同代确认（门2③）；门2② 全量（`CASE_PROTO=syslog` 全量）；门2④ 反查绿后进 P6。
4. TCP 载体（G-SYSLOG-3）接线前，本协议**不建**任何 TCP 断言例；接线时同步 `decode_as` 口径（G-SYSLOG-12）。

## 8. 存量审计（1 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/syslog.json` **1 例**：正例带 `packet_count=1` + 4 fields + 1 frames 断言，**与 2026-09-27 pcap 逐条复核一致**（§3.1）；`spec_json` 顶层键 `{layers, syslog}`（**非负例顶层键 1 处，红**）；无负例。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **顶层 `syslog` 空子映射并存**（非负例顶层键=1）：as-built 合规形（配置唯一入口）但违反 1.11-1.13 零残留验收口径；且该键**承载缺省值**（G-SYSLOG-1/2，删键即断言变 `<0>`）——P4 收敛前不得删。
2. **notes 文案 2 处误诊**（断言本体全对）：①"msg 尾部含 0x00 终止符"实为 `pad_min_frame` 60B 最小帧填充；②"仅做帧前缀断言"实为全 payload 断言（17B 恰等）。另 summary "facility=1(2)" 的 "(2)" 无语义。→ G-SYSLOG-11，P4 改写 notes。
3. **RFC 章节引用漂移**（notes 引"RFC 5424 §6"尚可，代码注释引 §6.2.8/§6.4.4 已漂；UDP 尺寸规范依据统一为 RFC 5426 §3.2，代码错误文案中的 `(RFC 5426 §6)` 保留为历史字面，不宣称规范引用）→ G-SYSLOG-10。
4. **存量未覆盖**：22 拒绝分支、显式字段面、SD 面、BOM 面、BSD 面、多包面、IPv6、动态字段——今日零 pcap 例（A′ 补，G-SYSLOG-7）。
5. **结果文档过期**：tracked `trafficgen/docs/protocol-pcap-test/syslog.md`（仓根相对路径）"pass 1"（`e7e7d1c` 2026-08-27 < 判死 `0417be5` 2026-09-13）、`trafficgen/docs/protocol-pcap-test/syslog/` 0 pcap 留档 → G-SYSLOG-8；本车道对 2026-09-27 pcap 复核命中，但不冒充套件复跑。

### 8.3 逐条去向表（1 行）

| 存量 id | 去向 | 改写动作（P4） |
|---|---|---|
| `syslog_smoke_01` | **保留** | 仅修 `expect.notes` 3 处文案（G-SYSLOG-11）；断言（packet_count/fields/frames）**一字不动**；顶层键去留随 G-SYSLOG-1 收敛裁定 |

无"作废不注原因"：0 作废，0 等价覆盖（1 例保留）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

建议在主线程合入后，于 `coverage_gate.py` 登记 `check_syslog` 段（**每条均可从本契约与 cases JSON 静态机读，不需新造事实**；红项如实标红）：

| # | 建议断言 | 判定 | 今日状态 |
|---:|---|---|---|
| 1 | `len(cases['syslog']) == 1` 且 ID 集合与顺序 = `["syslog_smoke_01"]` | JSON 机读 | 绿 |
| 2 | 正例 `packet_count == 1` 且 messages 空且 count 缺省 | JSON 机读 | 绿 |
| 3 | `spec_json` 顶层键 ⊆ `{layers, syslog}`；**非负例顶层 `syslog` 键计数 == 1（红——G-SYSLOG-1 未收敛，如实标红，不得申报已过）** | JSON 机读 | **红** |
| 4 | 正例 frames：offset == 42 且 hex == `"3c 31 34 3e 31 20 2d 20 2d 20 2d 20 2d 20 2d 20 2d"`（17B 串比对） | JSON 机读 | 绿 |
| 5 | 正例 fields 字段 ∈ `{udp.dstport, syslog.facility, syslog.level, syslog.msg}` 且值 = §3.1 四值 | JSON 机读 | 绿 |
| 6 | 负例数 ≥ 1 且每负例 `expect` 键 == `{expect_error, error_contains}` 且锚词 ⊆ 设计 §7 锚词集 | JSON+设计机读 | **红（0 负例，G-SYSLOG-7）** |
| 7 | registry `syslog` 行 `Category==terminal && DependsOn==["udp"] && Fields 空`（空壳层现状钉死；G-SYSLOG-1 收敛后翻转此行） | `registry.go` 文本机读 | 绿（现状断言） |
| 8 | `main.go` 含 `_ "…/internal/protocol/syslog"` 与 `NewChainPlanner("syslog")` | 文本机读 | 绿 |
| 9 | 生成表 `layers.generated.json` syslog 条目 `fields == {}` 与 registry 同代 | JSON 机读 | 绿 |
| 10 | `layer_dyn` allowlist 无 `syslog` 行（业务字段动态全关钉死；开启须先改本契约 §6.2） | `layer_dyn.go` 文本机读 | 绿 |

**另注意**：`trafficgen/docs/protocol-pcap-test/syslog.md`（仓根相对路径）的 "pass 1" 是**过期产物**（G-SYSLOG-8，末次提交 2026-08-27 早于判死提交 2026-09-13；`trafficgen/docs/protocol-pcap-test/syslog/` 0 pcap），**不得作为"今日已复跑"依据**（口径 = pcep G-PCEP-11）。本车道对 2026-09-27 pcap 的断言复核（§3.1）是**证据复核**，非套件复跑。

## 10. 修订记录

- v1.0.0（2026-09-29）：P-PIPE 文档轨批次二 as-built 首版。形状基线机读实测（§1，**非负例顶层键 1 处红**如实申报）；1 ID 索引 + 正例逐项断言（4 fields + 1 frames 对 2026-09-27 pcap 全命中复核）；负例 0 条如实申报 + 22 分支锚词 A′ 全量立项（§4/§6.2）；tshark 12 字段 + `syslog.msg` 值域口径 + TCP 514→rsh 绑定实测（§1）；§3.15 三项 + A′/B′ 两分类 + 3.14 豁免（§6）；存量审计 1 例保留（§8，notes 3 处文案错登记 G-SYSLOG-11）；覆盖反查门建议 10 行（§9，2 红 8 绿如实标注）。自审 5 轮（脚本机读，含 3 轮修复），末轮干净（连续 2 轮 31 项零失败）（脚本 `/tmp/pipe/doc-lanes/syslog-selfaudit.py`）。

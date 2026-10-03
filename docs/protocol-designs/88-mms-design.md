# MMS（IEC 61850 制造报文规范，ISO 9506 / TCP 102）设计契约

> 版本：v1.0.0（P1–P3 文档轨产物；#88 mms，RESUME）
> 日期：2026-09-26
> 车道：并发管线车道 A（文档轨）｜协议号：**88**（ledger 队列位；文件按既有命名序 `88-mms-*.md`）
> 配套文件：`docs/protocol-designs/88-mms-testcase.md`、`trafficgen/test/protocol_pcap/cases/mms.json`（现存 11 例）
> 旧基线：`docs/protocol-designs/26-mms-design.md` v1.1.1 + `26-mms-testcase.md` v1.0.1（2026-08-18/20，前链路产物；本契约逐节对照其条目，见 §8/§10，旧条目无静默删除）
> 规范基线：ISO 9506-1/-2（MMS）+ IEC 61850-8-1（映射）+ RFC 1006（TPKT）+ ISO 8073（COTP）+ ISO 8650-1（ACSE）+ ISO 8823（表示层）；字节权威 = libiec61850 编码器 + Wireshark packet-mms.c/packet-acse.c + 本机 TShark 3.6.14 实测 + `/tmp/pipe/88-mms/` 三探针
> **层链唯一真相**：本契约全文示例只有纯 `layers` 形——地址只住 `ip` 层（`src`/`dst`；IPv6 地址族同住 `ip` 层，仓库无 `ipv6` 层，kerberos/ntlm/postgresql 先例）、端口只住 `tcp` 层（`src_port`/`dst_port`）、数量只走 `flow_control`；顶层只允许 `layers`/`flow_control` 家族/`output`（CORE_MEMORY §1.11–1.13）。任何顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/`mms` 子映射都判违规（今日 `CheckProtoFlat` 尚无 mms 分支 → 缺口 G-MMS-1，P4 必办）。
> **注册现状**：`mms` 层**已注册**（`layers/registry.go:596`，`CategoryTerminal` + `DependsOn ["tcp"]`，**无** `FieldContract`/`TransportOn`/`OptionalOn`），`allowedProtocols["mms"]=true`（`core/protocols.go:43`）、`NewChainPlanner("mms")` 已在 `cmd/server/main.go:509` 注册。本文**不宣称本次跑过 suite、不启动服务器**；所有"已落码/未落码"结论均标实测出处。
> **与 S7 的关系**：S7（21-s7）与 MMS 同住 TCP 102 + 同一套 TPKT/COTP 信封，区分只在 DT 内层首字节（`0x32`=S7comm，`0x0d`/`0x0e`=MMS 会话 SPDU）。引擎无按内层分流能力，混跑明确不支持（G-MMS-6，B′）。探针证据见 §3.9。

---

## 1. 范围、证据等级与已落码边界

本设计定义 IEC 61850-8-1 MMS（Manufacturing Message Specification，制造报文规范）在 TCP 102 上经 RFC 1006（TP0 over TCP）承载的**客户端-服务器确认服务**流量生成契约：TCP 握手 → COTP CR/CC → DT（会话 CONNECT/CP/AARQ/Initiate）双向关联 → Read/Write/GetNameList/Identify 确认对 + InformationReport 单向上送 + Confirmed-ErrorPDU 负向。

**证据等级三档（本契约纪律）**：

| 档 | 可写内容 | 是否固定线字节 |
|---|---|---|
| ①规范/旧基线级 | TPKT/COTP/SPDU/CP-CPA/ACSE/MMS PDU 布局、服务标签、Data 隐含标签、OID（旧基线 §2–§3 全文，RFC/ISO 出处逐节） | 是——逐字节可断言 |
| ②探针实测级 | `/tmp/pipe/88-mms/` 三探针（S7 DT / CR / DT1 / 粘包段）+ 本机 TShark 3.6.14 解码面（`tpkt.*`/`cotp.*`/`s7comm.*`，内层 MMS 拒解） | 是——但仅作断言通道与缺口证据，不改写线真相 |
| ③实现现状级 | 本仓库 `internal/protocol/mms/*`（builder 436 行 / layer_gen 267 行 / planner 187 行 / 单测 24 个）+ 接线五件（registry/translate/convert/chain/main）的已落码能力边界 | 是——作为"今日可达/不可达"的判据 |

**已落码边界（实测，2026-09-26 HEAD）**：

- 生成器：`internal/protocol/mms/layer_gen.go`（267 行）——事件驱动：空配置默认化（association-only 7 包，`layer_gen.go:22-27`）→ `emitFull`（CR/CC + DT1/DT2 + 服务）→ `MultiSession` 并发会话（会话 0 默认流端口，会话 i+1 = `40000+i`（`layer_gen.go:48-53`）；阶段序 CR全→CC全→DT1全→DT2全→服务串行，`:55-100`）。
- 字节原语：`internal/protocol/mms/builder.go`（436 行）——`BuildCR/BuildCC/cotpDT/ber/seq` + 5 服务请求/响应 + `BuildAssociate(cfg, response)`（默认输出与参考抓包逐字节一致，单测锁定）+ `BuildServiceError`。
- 校验器：`internal/protocol/mms/planner.go:15-55`（`Planner.Validate`）——transport 门（仅 `""`/`"tcp"`）、对象名/域名 32 字节门、datatype 白名单（10 值）、sequence 非负门 + 步名门、errorClass 三值门；经 `layer_gen.go:266` 的 `RegisterLayerValidator` 接入。
- 链路接线：`chain_planner_chain.go:502-515`（mms 链强制 `termination=false` + `concurrent=true`，tcp 层缺省时 nil 守卫外注入）；端口缺省双通道——`chain_planner.go:914`（`case "mms": spec.DstPort = 102`）+ `spec.DstPort==0` 通用门豁免名单含 mms（`:641`）；`main.go:509` + `protocols.go:43` + `strategy_convert.go:1374`（flat 旧形 `parseSubconfigJSON`）+ `chain_planner_translate.go:1700`（层链翻译，flat 权威早返）。
- **单测 24 个**（`mms_test.go:14-471`）：TPKT 超长拒、CR/CC canonical、DT1/DT2 canonical、非默认参数、servicesSupported 合法/非法、长形式长度、单 EXTERNAL 包装、会话+表示包装、服务载荷、invoke 递增、report 下行、多会话展开、空配置默认流、校验拒绝集。

当前 `cases/mms.json` **11 例**（§8 存量审计基线）。

---

## 2. 推荐配置、层链与事件形状

### 2.1 层链

唯一合法链形：**`[ip, tcp, mms]`**（IPv6 地址族同住 `ip` 层，不新增层）。`mms` 是**终结层**（`CategoryTerminal`），无 `TransformEvents`、无 `OptionalOn`、无 `TransportOn`、无 `FieldContract`——registry 实测见 `registry.go:596` 起 12 键（`:597-608`）。

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.88", "dst": "198.51.100.88"}},
    {"tcp": {"dst_port": 102}},
    {"mms": {
      "objects": [{"domain": "IED1", "name": "GGIO1.SPCSO1.stVal", "datatype": "boolean", "value": true}],
      "enableRead": true,
      "sequence": {"steps": ["read"]}
    }}
  ],
  "flow_control": {"flows": 1}
}
```

> **`tcp.dst_port` 可省**：缺省时链路径 `chain_planner.go:914` 补 102（legacy `Plan` 内 `planner.go:74-76` 同值承接）。mms 无 `FieldContract`，用户显式写端口**无域校验强制等于 102**（与 s7/postgresql 有契约不同，见 §5）。

### 2.2 层内配置键（**唯一权威 = registry `Fields`，实测 12 键**）

| 键 | 类型 | 默认 | 语义 | 证据 |
|---|---|---|---|---|
| `iedName` | string | `""`（builder 回退 `FAKE8150`） | Identify.vendorName 缺省来源 | `registry.go:597`；`builder.go:279-287` |
| `objects` | list | `[]` | 变量表（domain/name/datatype/value/members） | `registry.go:598`；`builder.go:65-72` |
| `enableRead` / `enableWrite` / `enableInformationReport` / `enableGetNameList` / `enableIdentify` | bool | `false` | 五服务开关（与 `sequence.steps` 交集才发，`layer_gen.go:149`） | `registry.go:599-603`；`layer_gen.go:232-247` |
| `multiSession` | list | `[]` | 并发会话：每项覆盖 objects（继承主配置其余，会话端口 `40000+i`） | `registry.go:604`；`layer_gen.go:34-47` |
| `association` | object | nil（全缺省） | localDetail/calling/called/nesting/servicesSupported/noAssociate | `registry.go:605`；`builder.go:339-370` |
| `sequence` | object | nil（`["read"]`） | steps/loop/stepGap/injectOn（后三今日零消费 → G-MMS-2） | `registry.go:606`；`planner.go:42` 仅校验 |
| `errorClassName` / `errorValue` | string/int | `""`/`0` | 负向：类（definition/service/access 三值）+ 值（0–255，0 表缺省 2） | `registry.go:607-608`；`builder.go:301-321` |

**层字段范围校验（V9）**：白名单制——12 键之外的任何键 → `layers: layer "mms": unknown field %q`（`complete.go:285-293` 通用块）。

### 2.3 事件形状与「死字段」清单（P4 必办，实测）

`MMSConfig` 是 Go struct（`core/types.go:1465-1478`，13 个字段 = `transport` + Registry 12 键全集；Registry `Fields`（`:597-608`）12 行 = 下表 12 键，struct 另有 `transport`（Registry 未登记，校验器直读））。**配上不生效四键**（G-MMS-2；P4 删键或接线二选一，不许留死配置）：

| 死字段 | 现状实证 | 处置 |
|---|---|---|
| `transport` | `planner.go:21` 只校验（非 tcp 即拒）；`chain_planner_translate.go` 的 `case "mms"` 块（`:1700-1756`）**零 `transport` 读取**（`grep -n Transport` 该文件零命中）；层链路径下写 `transport` 静默无消费 | P4 接线（读入校验）或删键 |
| `sequence.loop` / `sequence.stepGap` | 除 `planner.go:42` 非负校验外，全仓库零消费（`grep -rn StepGap\|Loop` 非测试命中仅 `types.go` 定义 + `megaco.go` 无关项） | 同上 |
| `sequence.injectOn` | 同上零消费；存量 `mms_information_report` 带 `injectOn: 1` 但 `emitServices` 不读它（report 靠 `steps` 含 `report` + `enableInformationReport` 触发）——**用例配了无效键**，P4 改写时要么接线要么从用例删掉 | 同上 |

### 2.4 wire_profile 登记值与能力边界

mms 无 `wire_profile`/版本选择器（单栈：RFC 1006 + 全会话栈恒定；版本/方言差异面见 §10.1 行 8）。`servicesSupported` 允许全覆盖默认位串（hex 串，首字节填充位数守卫，`builder.go:357-369`）。

---

## 3. 线格式权威（逐字段，P4 builder 硬对照表）

本章以旧基线 §2 全文为规范底（RFC/ISO 出处见旧基线 §2.2–§2.11），此处只收**与代码/探针双证过的确定字节**，不复抄旧基线全表（旧表继续有效，未删除）。

### 3.1 TPKT（RFC 1006，4B）

`03 00 <len16含头>`。`tpkt()`（`builder.go:9-18`）：`len(body)>65531` 即拒。探针 `probe_seq.pcap` pkt2/3：`03 00 00 14`（20B）、`03 00 00 a5`（165B）与存量 `mms_connect_establish` frames 逐字节一致。

### 3.2 COTP（ISO 8073 TP0）

- CR：`0f e0 00 00 00 01 00 c0 01 0c c2 01 01 c1 01 02`（LI=15，DST=0，SRC=1，TPDU 4096，called TSAP 01，calling TSAP 02）——`BuildCR`（`builder.go:20`），探针 pkt2 与用例帧 4 同值。
- CC：`0f d0 00 01 00 02 00 c0 01 0c c1 01 01 c2 01 02`（引用互换）——`BuildCC`（`:23`）。
- DT：`02 f0 80 + 数据`（EOT=0x80 恒单段；多段/EOT=0x00 未实现 → G-MMS-5）——`cotpDT`（`:27`）。

### 3.3 会话/表示/ACSE（DT1/DT2 信封）

`BuildAssociate`（`builder.go:335-436`）：SPDU 参数块 `spduParams` 23B（`:326`）→ 会话 CONNECT `0x0d` / CONNECT-ACK `0x0e` → CP `0x31`（P 选择符 `12 34 56 78`/`87 65 43 21`，PCDL 上下文 1=ACSE/3=MMS）/ CPA（`83 04 00000001` + `a5` 双 `30 0d` 结果项）→ AARQ `0x60` / AARE `0x61`（result 0 + diagnostic `a1 03 02 01 00`）→ EXTERNAL `28`（indirect-ref 3 + `a0` 包 Initiate `a8`/`a9`）。请求信封用 `c1 81 <len16>` 形、响应 `c1 <len>` 形（与参考抓包一致，函数注释 `:328-334`）。

Initiate-RequestPDU：`a8 27 {80 04 <localDetail=64000> 81 01 05 82 01 05 83 01 0a a4 16 {80 01 01 81 03 05 f1 00 82 0c 05 ee 1c 00 00 04 08 00 00 79 ef 18}}`（探针 pkt3 `a0 29 a8 27 80 04 00 00 fa 00 …` 起可验）。

### 3.4 MMS 确认 PDU（builder §3.5 旧基线 + 本契约双证）

顶层：`a0`=Confirmed-Request（含 `02 <invoke>` 通用 INTEGER，`confirmedRequest :203`）/ `a1`=Confirmed-Response（`:209`）/ `a2`=Confirmed-Error（invoke 改上下文 `80` 标签，`BuildServiceError :321`）/ `a3`=Unconfirmed。服务标签：read `a4` / write `a5` / getNameList `a1` / identify `a2`。

- Read 请求：`a0 {02 inv a4 {<VAS>}}`，VAS = `a1 {a0 {30 {a0 {a1 {1a domain 1a item}}}}}`（`variableAccessSpecification :65`；对象名用通用 VisibleString `0x1a`——tshark 3.6.14 packet-mms.c 要求，上下文 `0x8a` 会报 dissector error，函数注释 `:57-64`）。
- Read 响应：`a1 {02 inv a4 {a1 {<Data*>}}}`（`:217-227`；无 per-item 包装）。
- Write 请求：`a5 {VAS a0 {<Data*>}}`（`:229-239`）；Write 响应：`a5 {81 00 *}`（成功项 `81 00`，**不是**旧基线 §3.3 初版的 `80 01 00`——以代码+存量 `mms_write_success`（`a5 04 81 00 81 00`）为准，旧基线该行已过期，见 §8）。
- GetNameList 请求恒带 `a0 {80 00}` extendedObjectClass + `a1 {80 00}` vmdSpecific scope（`:254-262`）；响应 `a1 {a0 {1a*}}`（`:264`）。
- Identify 请求 `a0 {02 inv a2 {}}`（`:275`）；响应 `a2 {80 vendor 81 "MMS" 82 "1.0"}`（`:279-287`）。
- InformationReport：`a3 {a0 {VAS a0 {<Data*>}}}`（`:288-299`），生成器走下行单帧（`layer_gen.go:188-197`）。
- Confirmed-Error：`a2 {80 inv a2 {a0 {<classTag> <int value>}}}`，classTag：access→`0x87`（缺省）、definition→`0x82`、service→`0x84`（`:301-322`）；存量 `mms_service_error` 帧 9：`a2 0a 80 01 01 a2 05 a0 03 87 01 02`。

### 3.5 Data CHOICE（`dataValue :74-104`，build 实证）

| datatype | 标签 | value 编码 | cases |
|---|---|---|---|
| boolean | 0x83 | `ff`/`00` | 已覆 |
| integer | 0x85 | 最小长度大端补码（`integerBytes :106`） | 已覆（42） |
| unsigned | 0x86 | 同上无符号 | 已覆（7） |
| octetString | 0x89 | hex 串（合法偶 hex 解码，否则原文，`octetBytes :166`） | 已覆（"0102"） |
| utcTime | 0x91 | **8 字节**（4B 秒大端 + 3B 分数 + 1B 质量；`builder.go:87-98`，IEC 61850 UtcTime；tshark 异长即 malformed）| 已覆（`91 08 …`，旧基线"4 字节秒"口径已过期，见 §8）|
| visibleString | 0x8a | ASCII 原文 | builder 支持，**无 cases**（A′ T-MMS-12） |
| float / binaryTime / structure | — | **静默落 `default: ber(0x80,nil)`**（`:102`，错字节） | G-MMS-3（validator 放行 + builder 错编码，P4 修） |
| `""`（空） | — | validator 允许（`planner.go:58` 首值 `""`），builder → `0x80` 空 | 语义未定（G-MMS-3 同批裁定） |

### 3.6 错误类表

access→`0x87`（object-non-existent=2 已覆；access-denied=3 未覆）/ definition→`0x82`（未覆）/ service→`0x84`（未覆）/ file `0x8B` 未实现。`errorValue=0` 表缺省 2（`:303-306`）。

### 3.7 OID 汇总（旧基线 §2.11 沿用）

应用上下文 `1.0.9506.2.3`（`28 ca 22 02 03`）、MMS 抽象语法 `1.0.9506.2.1`（`28 ca 22 02 01`）、BER `2.1.1`（`51 01`）。探针 pkt3 `a1 06 06 28 ca 22 02 03` 可验。

### 3.8 帧序（1-based，SYN=帧1）

单流：1 SYN / 2 SYNACK / 3 ACK / 4 CR / 5 CC / 6 DT1(c2s) / 7 DT2(s2c) / 8+ 服务对（旧基线 §6.1，存量 `mms_connect_establish` packet_count=7）。链路层 `termination=false`（`chain_planner_chain.go:512`）故**无 FIN**（与 legacy `Plan` 尾部双 `0x11` 不同——legacy 面仅回归保留，非线上语义，见 §11.7）。

### 3.9 探针三结论（`/tmp/pipe/88-mms/`，TShark 3.6.14）

- **P-S7（`probe_s7.pcap`，1 包）**：载荷 `03 00 00 19 02 f0 80 32 01 00 00 00 01 00 0e 00 00 04 01 12 08 12 34 00 00` 被解码为 `tpkt:cotp:s7comm`（`s7comm.header.rosctr=1`、`param.func=0x04` read）。结论：**同端口同信封下 S7 与 MMS 的唯一区分在 DT 内层首字节**（`0x32` vs `0x0d`/`0x0e`）；MMS 内层 tshark 拒解（`frame.protocols` 止于 `data`，`probe_seq.pcap` pkt3）。
- **P-SEQ（`probe_seq.pcap`，3 包）**：pkt1=S7 DT（同上）、pkt2=MMS CR（与用例帧 4 逐字节同）、pkt3=MMS DT1（`03 00 00 a5 … a8 27 80 04 00 00 fa 00 …`，与用例帧 6 逐字节同）。结论：CR/DT1 canonical 双证成立；同端口上 S7 帧与 MMS 帧可交错出现（引擎无分流 → G-MMS-6）。
- **P-BOTH（`probe_both.pcap`，1 段 26B）**：`frame.len=80`（14+20+20+26），tcp 载荷 = 完整 S7 DT（25B）+ MMS CR 首字节 `03`。结论：**TCP 粘包/半包真实存在**——两 TPKT 可挤进一段、TPKT 可被切在段边界；harness `frames[]` 固定偏移断言隐含"一段一 TPKT"假设，分片/EOT 面未覆盖（G-MMS-5）。

---

## 4. 会话状态机与自动派生（设计权威）

### 4.1 状态集合

CLOSED →(SYN/SYNACK/ACK)→ TCP_ESTABLISHED →(CR/CC)→ COTP_ESTABLISHED →(DT1/DT2)→ ASSOCIATED →(服务对)→ DATA_EXCHANGE；`noAssociate=true` 时跳过中间两态直发服务（`planner.go:106` / `layer_gen.go:220`）。InformationReport 无 invoke、无响应。invoke 每连接从 1 递增（`emitServices :146-212`；多步递增有单测 `TestPlannerIncrementsInvokeIDAcrossSteps`，无 cases → A′ T-MMS-13）。

### 4.2 非法转移（拒绝 + 锚词）

| 非法 | 拒绝面 | 锚词 |
|---|---|---|
| `transport` 非空非 tcp | validator | `mms: transport %q invalid; MMS requires tcp`（`planner.go:22`） |
| 对象名空/超 32B、域名超 32B | validator | `mms: object name %q exceeds 32 bytes or is empty` / `mms: domain exceeds 32 bytes` |
| 未知 datatype/步名/错误类 | validator | `mms: datatype %q invalid` / `mms: sequence step %q invalid` / `mms: error class %q invalid` |
| sequence 负值 | validator | `mms: sequence values cannot be negative` |
| 未知层键 | V9 allowlist | `layers: layer "mms": unknown field %q` |
| 超长 TPKT（>65531） | builder | `mms: TPKT body exceeds 65531 bytes` |

### 4.3 自动派生帧（生成器自动补的内容，逐条列出）

空 `mms` 层 → 默认 association-only 7 包（`layer_gen.go:22-27`，`mms_connect_establish` 即此形）；`dst_port` 缺省 102（§5）；多会话副连接端口 `40000+i` 自动分配；Write/GetNameList/Identify 的响应由生成器按请求自动配对（planner 成对表见旧基线 §4.4，继续有效）。

---

## 5. 依赖声明与端口契约

- `DependsOn ["tcp"]` 单值（`registry.go:596`），无 TransportOn/OptionalOn/InnerRequired。`mms` 終结层之上不可再叠。
- 端口 102（IANA iso-tsap）缺省双通道：链路径 `chain_planner.go:914` + 通用门豁免 `:641`；legacy `planner.go:74`。**无 `FieldContract`**：显式 `tcp.dst_port≠102` 不被拒（与 s7/postgresql 有契约不同）——是否加契约由 P4 定（A′ G-MMS-8 候选，候选方案见 §10.5）。
- S7 同端口：无分流，混跑不支持（G-MMS-6）。

---

## 6. 性能设计与验收（CORE_MEMORY §6.1–§6.8）

- **目标/预算**：单流默认 7 包（关联）+ 2 包/确认服务；DT1 165B / DT2 161B / CR-CC 各 20B（含 TPKT）；单 flow 内存 O(1)（事件直发，无聚合；planner 通道 32 上限 `planner.go:77`）；多会话内存 O(会话数)（配置指针数组 `layer_gen.go:35`）。
- **依据**：`layer_gen.Generate` 逐事件 `EmitMsg` 直发（`:18-104`，无收集）；`emitServices` 逐步编解码（`:141-215`）；无共享可变状态、无锁（invoke 为栈上局部量）；跨流速率走框架 `flow_control` + `SharedTokenBucket`（框架语义未动）。
- **验收两路**：pcap 路（`/tmp/mcp-pcaps/mms/`，P5 全量）；NIC 路（`tcp port 102`，网口 `enp135s0f0np0` 按 testing-interface 记忆，P5 跑测）。
- **六类场景**（P5 跑测清单）：基线（7 包关联）/ 目标规模（多会话 18 包）/ 压力上限（大 objects 表 + 超长 TPKT 拒）/ 长时间（多轮事务 A′ T-MMS-13）/ 并发交错（multiSession 双会话）/ 资源耗尽（buffer 背压按框架语义）。
- **数字纪律**：吞吐/并发上限数字待 P4 基准（§6.5 不写承诺）；超预算按 §6.8 不合格。

---

## 7. 错误处理与错误传播

四类：配置错误（§4.2 表，任务拒绝创建，不产包）/ 服务拒绝（Confirmed-ErrorPDU，业务负向有意产出并断言）/ 编码层错误（TPKT 超长拒；float 等静默错字节是 bug，G-MMS-3）/ 链路时序错误（noAssociate 跳关联；对端无响应照发本侧全序，无重传）。失败一律传 task error，零假成功（要求面；P5 验证）。

---

## 8. 存量审计口径

11 例（`cases/mms.json`，2026-09-26 HEAD 实测）：10/11 顶层键仅 `{layers}`，链形 11/11 `[{tcp},{mms}]`（**无 `ip` 层**，地址走引擎缺省；P4 补 `ip` 层 + `flow_control`，G-MMS-8）；`flow_control` 0/11（§2.9：无动态时单流不撞，多流必补动态，见 §12.12）。

| 存量 ID | 去向 | 备注 |
|---|---|---|
| mms_connect_establish | 合入（T-MMS-1） | 空层默认流 7 包；CR/CC/DT1/DT2 canonical |
| mms_read_multi_type | 合入（T-MMS-2） | 5 对象多类型；utcTime `91 08` 8B（旧 testcase "4 字节秒"已过期） |
| mms_write_success | 合入（T-MMS-3） | 成功项 `81 00`（旧设计 `80 01 00` 已过期） |
| mms_information_report | 合入（T-MMS-4） | 下行单帧；`injectOn: 1` 为无效键（G-MMS-2），P4 改写时处理 |
| mms_getnamelist | 合入（T-MMS-5） | 请求恒带 extendedObjectClass（builder 行为） |
| mms_identify | 合入（T-MMS-6） | vendor 回退 FAKE8150 |
| mms_service_error | 合入（T-MMS-7） | access/2：`87 01 02` |
| mms_no_associate | 合入（T-MMS-8） | 帧 4 起直发 `a0` |
| mms_ipv6 | **改写**（T-MMS-9） | 顶层 `src_ip/dst_ip` flat 残留（§1 违规）→ P4 改 `ip` 层 `src/dst` + 偏移 74 不变 |
| mms_multi_session | 合入（T-MMS-10） | 双会话 18 包；副会话对象 IED2/integer 5 |
| mms_validate_reject | 合入（T-MMS-11） | 超长名拒，锚词 `name` |

去向合计：10 合入 + 1 改写 + 0 作废。旧基线预留 `mms_fragmented_dt`/`mms_name_list_paging`（旧 §10.2）继续预留，并入 G-MMS-4/5。

**旧基线过期口径勘误**（本契约已改，旧文件不动——历史层）：①Write 成功项 `80 01 00`→`81 00`；②utcTime"4 字节秒"→8B（4B 秒+3B 分数+1B 质量）；③Read 响应 frames（旧 testcase §2.2 的 `a1 81 81/a4 55/a1 53 + 91 04`）→ cases 现状 `a1 1e … a4 19 a1 17 + 91 08`。

---

## 9. 用例集合摘要（ID 权威在 testcase §2）

11 存量（T-MMS-1..11）+ A′ 补例 10 项（T-MMS-12..21，testcase §6.2，并入与否由主线程定）。B′ 结构缺口见 §14（G-MMS-3/4/5/6）。

---

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

方法声明：规范列以旧基线 §2–§4（RFC/ISO 出处逐节）为基线代理——旧基线已做 RFC 全文工作，本 RESUME 轨做"基线→代码→探针"三路对照复核，不重复抄 RFC 章节；凡旧基线与代码/探针不一致，以代码+探针为准并在 §8 登记过期。

### 10.1 八项规范矩阵

| # | 规范要求（旧基线出处） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 连接模型 | 长连接 C/S，控制数据不分离，客户端建连（旧 §1.1/§4.1） | 单会话读写 + 双会话并发 | `DependsOn ["tcp"]`（`registry.go:596`）；并发由 `concurrent=true`（`:512`） | 无（S7 共存见行 7） |
| 2 命令/消息表 | Initiate/Read/Write/Report/GetNameList/Identify + Error（旧 §1.3/§3.3-3.5） | 每服务请求—响应对 | builder 全实现（`:213-322`）；成对由生成器保证 | AARE 拒绝/Conclude 未实现（G-MMS-4） |
| 3 状态机 | TCP→COTP→ASSOCIATED→DATA（旧 §4.1/4.4） | 关联后才服务；noAssociate 负向 | planner + layer_gen 双实现一致；`termination=false` | 无 |
| 4 字段表 | BER 定长；Data 标签；名 ≤32B；OID（旧 §2.1/2.9-2.11） | 多类型一次读写 | 名门/标签表已落；float 等三值静默错（§3.5） | G-MMS-3 |
| 5 错误处理表 | ServiceError 类+值；关联拒绝；编码非法（旧 §3.5/§9） | 读不存在对象 → ErrorPDU | access/2 已覆；definition/service 类无 cases；AARE 拒绝只有旧 §4.2 纸面字节 | G-MMS-4/7 |
| 6 超时与活性 | 协议层无保活/重传语义（旧 §9.4：单边照发，不等待） | 长会话 = 同连接多轮事务 | 无保活实现（**显式不适用**，TCP 层兜底） | 无（长保活面由 A′ T-MMS-13 覆盖） |
| 7 NAT/代理/被动 | 无被动模式；同端口 S7 共存（本契约 §3.9 新增面，旧基线未述） | NAT 后长连接；S7 帧交错 | NAT 面框架语义；S7 共存零分流 | G-MMS-6（B′ 声明不支持） |
| 8 版本/方言 | MMS 增强上下文 `1.0.9506.2.3` 固定；CBB/服务位串固定（旧 §2.11/§3.1） | 单栈，无协商 | 位串固定（`builder.go:368-380`）；`servicesSupported` 可覆盖 | 无 |

### 10.2 子表①：PDU × 会话状态矩阵（11 行 × 3 列 = **33 格**；A=关联内正常，B=未关联，C=多会话并发）

| PDU | A | B | C |
|---|---|---|---|
| CR | 已覆（T-1 帧4） | 不适用（不发） | 已覆（T-10 帧4/8） |
| CC | 已覆（T-1 帧5） | 不适用 | 已覆（T-10） |
| DT1-assoc | 已覆（T-1 帧6） | 不适用 | 已覆（T-10） |
| DT2-assoc | 已覆（T-1 帧7） | 不适用 | 已覆（T-10） |
| Read | 已覆（T-2） | 已覆（T-8） | 已覆（T-10 帧15/17） |
| Write | 已覆（T-3） | 缺口（G-MMS-7） | 缺口（G-MMS-7） |
| Report | 已覆（T-4） | 缺口（G-MMS-7） | 缺口（G-MMS-7） |
| GetNameList | 已覆（T-5） | 缺口（G-MMS-7） | 缺口（G-MMS-7） |
| Identify | 已覆（T-6） | 缺口（G-MMS-7） | 缺口（G-MMS-7） |
| ConfirmedError | 已覆（T-7） | 缺口（G-MMS-7） | 缺口（G-MMS-7） |
| AARE拒绝/Conclude | 缺口（G-MMS-4） | 不适用 | 不适用 |

**逐格重数**：已覆 16（4×2+3+5×1）/ 缺口 11（5×2+1）/ 不适用 6（4+2）；16+11+6=33 ✓。

### 10.3 子表②：数据形态变体表（**32 行**）

| # | 变体 | 结论 |
|---|---|---|
| 1 | IPv4 | 已覆（T-1） |
| 2 | IPv6（`ip` 层同住） | 已覆但形状过期（T-9 flat 残留 → 改写） |
| 3–7 | boolean/integer/unsigned/octetString/utcTime(8B) | 已覆（T-2） |
| 8 | visibleString | 缺口（builder 支持，A′ T-MMS-12） |
| 9–11 | float/binaryTime/structure | 缺口（G-MMS-3 静默错字节） |
| 12 | 空 datatype | 缺口（语义未定，G-MMS-3 同批） |
| 13 | 名/域 ≤32B | 已覆（T-2 合法侧） |
| 14 | 名超 32B | 已覆（T-11） |
| 15 | 域超 32B | 缺口（代码分支有，零 cases 零单测行，A′ T-MMS-18） |
| 16 | errorClass access/2 | 已覆（T-7） |
| 17 | errorClass definition/service | 缺口（A′ T-MMS-15/16） |
| 18 | errorValue 非零定制 | 缺口（A′ T-MMS-17） |
| 19 | association 参数覆盖 | 缺口（有单测无 cases，A′ T-MMS-19） |
| 20 | servicesSupported 非法 | 缺口（仅单测，负例 A′ T-MMS-20） |
| 21 | noAssociate | 已覆（T-8） |
| 22 | multiSession 双会话 | 已覆（T-10） |
| 23 | invokeID 多步递增 | 缺口（仅单测，A′ T-MMS-13） |
| 24 | loop/stepGap | 缺口（死字段，G-MMS-2） |
| 25 | injectOn | 缺口（死字段，T-4 误配，G-MMS-2） |
| 26 | transport | 缺口（层链死字段，G-MMS-2） |
| 27 | TCP 粘包/半包（P-BOTH） | 缺口（G-MMS-5，B′） |
| 28 | S7 同端口交错（P-S7/P-SEQ） | 缺口（G-MMS-6，B′ 不支持） |
| 29 | GetNameList 分页 | 缺口（G-MMS-4，旧预留） |
| 30 | Conclude/Release | 缺口（G-MMS-4） |
| 31 | GetVarAttr/File/Journal | 缺口（G-MMS-4，旧 §10.1 预留） |
| 32 | COTP DT 分片/EOT | 缺口（G-MMS-5，旧 `mms_fragmented_dt` 预留） |

**重数**：已覆 12（1–7计7 + 13/14/16/21/22计5）/ 缺口 20；12+20=32 ✓。

### 10.4 关联关系专节（§3.8–3.10）

MMS 无"控制关联数据流"结构（单 TCP 连接内全序，无派生流、无 `driven_by`）：**诚实声明无关联流** + CancelRequest 式跨连接语义不适用。关联关系 = 会话内事务序（§12.3 t1–t5）+ 多会话并发（`concurrent=true` + `40000+i` 端口隔离，`layer_gen.go:49-54`）。

### 10.5 候选方案对比（§4.17）与三路对照（§4.12–4.15）

| 决策 | 候选 A（采用） | 候选 B | 取舍 |
|---|---|---|---|
| 端口缺省 | 无 FieldContract + chain switch 补 102（现状） | 加 `FieldContract tcp.dst_port=102`（s7/postgresql 款） | A 保持现状零改动；B 拦住误配端口。P4 二选一（G-MMS-8），本契约不预判 |
| float 等三值 | 修 builder 真编码 + 补例（A′） | validator 拒收（明确不支持） | P4 定；本契约要求"编码与校验一致"，不许一放一错（现状即此 bug） |
| 死字段 | 接线（transport 读入校验；Loop/StepGap/InjectOn 实现语义） | 删键（§1.12，配上不生效即删） | P4 二选一；T-4 的 `injectOn` 改写时同步处理 |
| S7 共存 | B′ 明确不支持混跑（文档声明 + 用例不覆） | 引擎按内层魔数分流 | B 复杂度高且需求未立项；选 A |

三路对照：①规范/旧基线（§2–§4）②现网行为（libiec61850 参考抓包 canonical + TShark dissector 面；真实 IED 抓包未到 → 不冒充第三源，缺口记 G-MMS-8 观察项）③开源实现（libiec61850 编码器行为，函数级对照 §3）。

### 10.6 裁定 MMS-A：S7/MMS 同端口关系

**mms 与 s7 是两个独立终结层**（各注册行、各 planner；`registry.go:92` vs `:596`），共享 TCP 102 只是 IANA 同端口（iso-tsap），**不合并、不复用代码**（信封同形但内层语义完全不同：S7 ROSCTR/param 码 vs MMS SPDU/BER）。探针 P-S7/P-SEQ 为裁定证据；混跑流量生成明确不支持（G-MMS-6）。

---

## 11. P2 D-MMS-2 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

### 11.1 文件清单（P4 动作，**本轨道不执行**）

- Modify: `internal/protocol/mms/builder.go`（G-MMS-3 三值真编码）、`internal/protocol/mms/layer_gen.go` 或 planner（G-MMS-2 死字段接线/删键；`translate` 读 `transport`）、`internal/core/strategy_convert.go`（G-MMS-1 `CheckProtoFlat` 加 mms 分支）、`trafficgen/tools/pipe_gate.sh`（presence 键表加 `mms`）、`trafficgen/tools/coverage_gate.py`（`check_mms` 登记）、`test/protocol_pcap/cases/mms.json`（G-MMS-7/8 改写 + A′ 补例）。
- Create: 无新文件（新用例只增 cases 条目；新层不增）。
- 不碰：`docs/CORE_MEMORY.md`、共享文档（主线程写）、他协议文件。

### 11.2 接口签名（示意，P4 落码钉死）

`BuildCR/CC/Associate/Read/Write/GetNameList/Identify/InformationReport/ServiceError` 签名不变；G-MMS-3 在 `dataValue` 内加 `float/binaryTime/structure` 真分支（或 validator 拒收二选一）；G-MMS-2 若接线则 `emitServices` 读 `Loop/StepGap/InjectOn`（多轮/间隔/中插上送）。

### 11.3 数据结构（现状 + 扩展）

`MMSConfig` 14 键不变（删键方案则去 `transport`/`loop`/`stepGap`/`injectOn`，同步 registry `Fields` 12→11/10 + schemagen 重跑）。

### 11.4 主流程

`Generate`（关联→服务→多会话展开）与 `Plan`（legacy 回归面）双实现现状不变；A′ 补例只增 cases 条目 + 必要 builder 修。

### 11.5 错误分支（§4.2 表 + G-MMS-1/3 新增锚词：presence 拒 `rejects a top-level mms sub-config`；三值修后锚词不变）

### 11.6 性能边界（§6 全文，P5 按六类跑）

### 11.7 与现有逻辑的冲突点（§8.7）

legacy `Plan`（`planner.go:70`）尾部双 FIN（`0x11`）与链路 `termination=false` 语义分叉——legacy 面仅单测回归保留（`TestPlannerAssociationAndRead` 等直调），线上走 `Generate`；P4 不得"统一"两面（改链语义会动全 cases 包数）。`translate` flat 权威早返（`:1701`）保留。

### 11.8 回滚方式（§8.8）

cases 改写/A′ 补例先备份 `mms.json`；builder 修失败测试先行（G-MMS-3 复现例红→绿）；`CheckProtoFlat` 加分支后全量 `go test ./internal/...` + 抽同族（s7/opcua/fins）suite 回归。

---

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 10/11 纯 layers 形；1 例 flat 残留（T-9）+ 全文件缺 `ip` 层/`flow_control` → G-MMS-8 改写；presence 判死今日缺失 → G-MMS-1 | 设计 §2.1/§12.1；cases 11 例实测 |
| §2 策略/任务 | 策略 = 单 MMS 流量模板，自带 `flow_control`（存量缺，P4 补）；任务 = 多策略合跑 + 总量封顶；框架语义未动 | `worker.go:300-316`；设计 §2.1 |
| §3 五件套 | 见 §12.3 强制展开：会话表（单/双/未关联）/ 事务 t1–t5（四件事）/ 关联关系（诚实无派生流，§10.4）/ 插入位置（终结层）/ 时间线（会内全序 + 双会话阶段序） | 设计 §12.3 + §4 |
| §4 查规范 | 旧基线 RFC/ISO 全文 + libiec61850 + TShark 3.6.14 + 三探针；八项矩阵 + 子表①33 格 + 子表②32 行 | 设计 §3/§10 |
| §5 依赖与错误 | `DependsOn ["tcp"]` 单值（`registry.go:596`），无端口契约；§4.2 六类拒 + 锚词；失败传 task error | 设计 §4.2/§5/§7 |
| §6 性能 | 见 §6（6.1–6.8 要素）：O(1)/流、无锁、默认字节量表；pcap/NIC 双路；数字待 P4 基准 | 设计 §6 |
| §7 三份文档 | `88-mms-{design,testcase}.md` v1.0.0（草稿层）+ D-MMS-2（§11，门1 获批 = 定稿）+ T-MMS（testcase §2，11+10 ID）+ schema（mms 已注册，不新增层） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 实现；门1 获批 = D-MMS-2 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 旧基线条款 + D-MMS-2 + 探针/TShark 实证 + builder wire 真相；现网 IED 抓包未到（G-MMS-8 观察项，不冒充第三源）；11 ID 逐项回指；存量审计 §8 | testcase §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123-report §3）+ 收官隔离复审 + 修轮；红先绿后 | p123-report §3 |
| §11 白话 | 每阶段先行一句白话结论（见 p123-report 首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组 = `ip`/`tcp` 层五策略全开（allowlist `layer_dyn.go:17-21`；`mms` 层业务键全关——对象即 `does not support dynamic`）；业务 9 项逐个列开/不开 + 理由；序号算法实读行号 | 设计 §12.12 |
| §13 schema 派生 | `mms` 已在 `registry.go:596-609` 注册；`allowedProtocols["mms"]`（`protocols.go:43`）；`main.go:509` 已接线；**若 P4 改 registry `Fields` 必须重跑 schemagen**（§13.18/13.19） | 设计 §11.1 |
| §14 真实流程 | suite 经 MCP 建任务 → 引擎真实生成 → tshark `tpkt.*`/`cotp.*` + frames hex 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/mms/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

- **存量实测**（11 例逐例机读）：`mms_ipv6` 顶层键 `{dst_ip, layers, src_ip}`（flat 残留，余 10 例仅 `{layers}`）；链形 11/11 `[{tcp},{mms}]`（无 `ip` 层）；`flow_control` 0/11。
- **旧键去向**：`src_ip`/`dst_ip` → `ip.src`/`ip.dst`（T-9 改写）；`src_port`/`dst_port` → `tcp` 层（缺省 102 经 `:914`）；`count` → `flow_control.flows`；顶层 `mms` 子映射 → `mms` 层（presence 判死今日缺失 → G-MMS-1 登记，不建假绿负例）。
- 样例见 §2.1（顶层仅 `layers`+`flow_control`）。

### 12.3 §3 强制展开：五件套

会话：`s1` 单会话全序（T-1..8）/ `s2` 双会话并发（T-10，阶段序 + `40000+i` 隔离）/ `s3` 未关联单流（T-8）。事务：`t1` 建连+关联（CR/CC/DT1/DT2）/ `t2` 读 / `t3` 写 / `t4` 名列表+标识 / `t5` 上送+错误，每事务前置/触发/成功/失败四件事全写（testcase §6.1 引用）。关联：无派生流诚实声明（§10.4）。插入位置：终结层，TCP 载荷起点 54（v4）/74（v6）。时间线：会内严格全序；双会话按"CR全→CC全→DT1全→DT2全→服务串行"（`layer_gen.go:55-100`）；多流（`flows>1`）并发 + 9.39 互斥（四元组动态化，见 §12.12）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst`、`tcp.src_port/dst_port` 五策略全开（allowlist `layer_dyn.go:17-21`；保底 `12345+i`（`strategy_convert.go:49`，`worker.go:307-308`）；mms 无端口契约故 dst 动态无冲突面）。**`mms` 层业务 12 键全关**（allowlist 无 mms 行）：`iedName/objects/enableRead/enableWrite/enableInformationReport/enableGetNameList/enableIdentify/multiSession/association/sequence/errorClassName/errorValue` 任一配动态对象即 `does not support dynamic`（`validate_layers.go:565/607` 通用门，`CheckLayerDynShape` 见 `layer_dyn.go:1037`）；`objects[].value` 的逐流变走多模板/多策略（§2.5），不冒充动态。序号算法实读（`parseLayerDyn:78` / `resolveLayerTuple:770` / `tuple_generator.go:26` / `worker.go:300-316`）。

### 12-P2 判死负例形状（链级红例必含清单①③④；①②待 G-MMS-1 落码）

P4 链级红例：①`{"layers":[…],"mms":{}}` 判死（G-MMS-1 落码后建，今日不建假绿例）；②白名单外游离键判死（V9 通用块已生效，可建）；③一切负例 `expect_error` + 错误锚词；④收官自查「非负例顶层键 = 0」。

---

## 13. P3 对接清单（T-MMS 草稿输入；正文落 testcase 文件）

11 存量 ID（T-MMS-1..11，testcase §2）+ A′ 补例 10 项（T-MMS-12..21，testcase §6.2）+ B′ 缺口（G-MMS-3/4/5/6）+ packet_count 契约（7 / 9 / 18，testcase §2 表）。

---

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 立项号 | 缺口 | 确认方式 / 去向 |
|---|---|---|
| G-MMS-1 | presence 判死缺失：`CheckProtoFlat` 无 mms 分支 + `pipe_gate.sh` 键表无 mms + `coverage_gate.py` 无 `check_mms` | P4 必办（A′；单协议分支先例充分，megaco/hl7/mmse 同款） |
| G-MMS-2 | 死字段：`transport`/`loop`/`stepGap`/`injectOn` 配上不生效（§2.3 实证） | P4 二选一：接线或删键；T-4 改写同步 |
| G-MMS-3 | float/binaryTime/structure 静默错字节（`builder.go:102`）+ 空 datatype 语义未定 | P4：真编码或 validator 拒收（编码与校验必须一致）；失败测试先行 |
| G-MMS-4 | AARE 拒绝/Conclude/分页/File/Journal/GetVarAttr 未实现（旧 §10 预留延续） | B′：明确不支持（文档声明）或立项实现 |
| G-MMS-5 | TCP 粘包/半包 + COTP DT 分片/EOT（P-BOTH 证据；旧 `mms_fragmented_dt` 预留延续） | B′：harness 单 TPKT/段假设，P4 不碰引擎分片 |
| G-MMS-6 | S7 同端口交错无分流（P-S7/P-SEQ 证据） | B′：明确不支持混跑 |
| G-MMS-7 | 服务×未关联/多会话矩阵 10 格缺口（Write/Report/GetNameList/Identify/Error × B/C） | A′ 补例（矩阵 B/C 格由 T-MMS-14 覆盖；T-MMS-15/16/17/19/20 覆盖变体行；全补或抽样由主线程定） |
| G-MMS-8 | 形状债：T-9 flat 改写 + 全文件补 `ip` 层 + `flow_control` 补例 + 端口契约二选一（§10.5）+ 现网 IED 抓包观察项 | P4 必办（改写）+ 观察项（抓包确认位串/TSAP 现网值） |

---

## 15. 修订记录

| 版本 | 日期 | 变更 |
|---|---|---|
| v1.0.0 | 2026-09-26 | P1–P3 文档轨初版：三探针结论 + 存量 11 例审计 + 旧基线三处过期勘误 + 33/32 格矩阵 + G-MMS-1..8 |

> 后续修订：P4 落码后回填实际证据号；每轮 pcap 回归后追补。

# #124 xmpp 测试契约（T-XMPP：11 例原子断言 + 覆盖反查；as-built）

> 版本：v1.0.1（P4 收敛：T-11 summary 3 段校正 + `has_payload` 补齐 + 负例 expect 两键收窄；设计侧为 `124-xmpp-design.md`）
> 日期：2026-09-29
> 用例文件：`trafficgen/test/protocol_pcap/cases/xmpp.json`（**权威**：ID 集合/顺序/包数/断言以本文件为准，本契约逐条与之对齐）
> 用例规模：**11 例 = 9 正 + 2 负**；9 正例实测帧数 19 / 21 / 23 / 19 / 18 / 21 / 19 / 19 / 22（与 `packet_count` 逐例一致）
> 证据：`/tmp/mcp-pcaps/xmpp/<id>.pcap`（9 正，实测在案）+ `<id>.neg.pcap`（2 负，**各 0 帧**）；本车道 tshark 3.6.14 逐帧复核 **46/46 断言 PASS**（21 frame + 14 field + 11 packet_count）
> 白话一句：**11 个用例就是 11 个"剧本片段"——每片声明一份配置，引擎跑出一条 pcap，测试逐字节比对固定几帧的开头、逐字段比对几个 tshark 字段、并数准总帧数。负例只做一件事：证明坏配置被拒且一个包都不许发。**

## 1. 测试原则和形状基线

### 1.1 三源与断言纪律

- **三源**：① 规范（RFC 6120/6121 + RFC 4616/2831/5802/4505，见设计 §3）；② 设计（`124-xmpp-design.md` §3 线格式 + §5 事务/包数公式）；③ 实测（tshark 3.6.14 字段面 + 参考 pcap + 本套件 11 例 pcap）。
- **先跑后钉**：所有 `frames[].hex` / `fields[].value` 必须由实跑 pcap 抄录，禁止凭代码推算书写；钉的是**前缀**（`frames[].hex` 语义 = 帧内 payload 自 `offset` 起的**逐字节前缀**，长度不限），不是整帧。
- **断言不得只见"任务没报错"**：正例必须同时含 `packet_count` + 至少 1 条 `frames` 或 `fields`（本套件 9/9 正例均≥1 ✓）。

### 1.2 TSHARK 基线（解码口径，写死不得漂移）

- **版本**：tshark **3.6.14**；`xmpp.*` 字段实测 **162 个**（`tshark -G fields | grep xmpp.` 机读）。
- **解码绑定**：`tcp.port == 5222 → xmpp` dissector（本套件 11/11 目的端口 5222，绑定成立）；`_ws.col.Protocol` 观测值 `XMPP`/`XML`（同一帧可两值，按 payload 内容分布；**不作为断言字段**）。
- **可断言字段白名单（今日实际使用 2 个）**：`xmpp.id`、`xmpp.type`（12 条断言）；`tcp.flags`、`tcp.dstport`、`ip.src`（框架通用 15 条断言中的 8 条）。
- **未使用但实测可用的字段（G-XMPP-17，A′ 收编候选）**：`xmpp.to` / `xmpp.from` / `xmpp.iq` / `xmpp.xmlns` / `xmpp.cdata` / `xmpp.attribute` / `xmpp.element`——**先跑后钉**，不许凭字段名臆造语义。
- **malformed 口径**：每正例 **2 帧**被 tshark 标 `Malformed Packet`，专家摘要 `Closing an unopened tag`（= 两帧 `</stream:stream>`：up 帧与 down 帧——dissector 不跨帧关联流上下文，**字节合法**，RFC 6120 §4.4 流关闭）；`internal/pcaptest/verify.go:574` 按 `strings.HasPrefix(caseID,"xmpp_")` + 摘要精确匹配豁免（另有 legacy `caseID=="xmpp-stream-basic"`）。**负例 0 帧 → 0 malformed（无需豁免）**。
- **专家信息（非 malformed，不入豁免）**：流头帧 `Unknown attribute to/version`、features 帧 `Unknown element: features`、iq set 帧 `Packet without response`——信息级，不影响判定，**不得**据此放宽断言。

### 1.3 断言基线（七类，逐例取值）

| 类 | 含义 | 本套件取值 |
|---|---|---|
| `has_handshake` | 必含 TCP 三次握手 | 9/9 正例 `true` |
| `negotiated` | 问候/协商面完成 | 9/9 正例 `true` |
| `terminates` | 流关闭 + TCP 正常终止（非 RST） | 9/9 正例 `true` |
| `has_payload` | 至少一帧带应用层载荷 | **9/9 正例**（T-11 已补齐） |
| `frames[]` | `{packet, offset, hex}` 帧内前缀逐字节钉 | 21 条（分布 §2） |
| `fields[]` | `{packet, field, value}` tshark 字段值钉 | 14 条（`tcp.flags`×3、`tcp.dstport`×1、`xmpp.id`×4、`xmpp.type`×4、`ip.src`×2） |
| `packet_count` | 帧数精确值 | 11/11 均含（9 正例实测一致；负例语义见 §4） |

### 1.4 包数约定（唯一公式 + 逐例校验）

```
packet_count = 16 + A + P + ΣS
A  = SASL 帧数：PLAIN 2 / ANONYMOUS 2 / DIGEST-MD5 4 / SCRAM-SHA-1 6
P  = presence：缺省 1；presence=false 为 0
ΣS = Σ 每条 message 节分段数（每节 ⌈节长/1460⌉，节长 = 50 + len(to) + len(body)）
```

逐例：T-1 `16+2+1=19`✓ / T-2 `16+4+1=21`✓ / T-3 `16+6+1=23`✓ / T-4 `16+2+1=19`✓ / T-5 `16+2+0=18`✓ / T-6 `16+2+1+2=21`✓ / T-7 `19`✓ / T-8 `19`✓ / T-11 `16+2+1+3=22`✓（3000B body → 节 3066B → 1460+1460+146）。
分解口径：`3 握手 + 13 固定数据帧（流开/features/auth/success/重启/postAuth/bind×2/sess×2/presence/流关×2）+ A-2 额外 SASL 帧 + ΣS-1 额外分段帧 + 3 终止（FIN/FIN-ACK/ACK）`。

### 1.5 保活 / 重试 / RST 口径

- **保活**：本协议**无** keepalive 面（XEP-0199 未建模，设计 §14 G-XMPP-9）→ 套件内**不得**出现保活周期帧；若未来建模，须新增独立 ID 并重算帧数。
- **重试**：无重传编排（全部确定性顺序剧本）→ 断言帧数即全量帧数，**不设"允许重传"宽容**；实测 11/11 无重传帧。
- **RST**：`terminates=true` 的语义 = **正常四包终止**（引擎自建 FIN/FIN-ACK/ACK 三帧 + 已计入的流关闭帧），**非 RST**；RST 路径**今日零用例**（G-XMPP-16 A′ 候选），**不得**在现有断言里放宽为"FIN 或 RST 皆可"。
- **时间戳/时延**：全部断言**不含**时间类字段（`frame.time_delta` 等），与机器负载无关。

### 1.6 用例文件形状（机读实测）

- 顶层键：11/11 = {`id`,`proto`,`summary`,`spec_json`,`expect`} 五键（无游离键）。
- `spec_json` 顶层：**11/11 仅 `layers` 一键**（零残留，设计 §12.1）。
- 层形：`[ip, xmpp]` ×11（ip 在先、xmpp 终结；**无 tcp 层**——raw 自驱，设计 §2.1）。
- 负例 `expect`：`{expect_error:true, error_contains}` 两键（严格形状；notes 已迁移至本文档 §4）。

## 2. 原子用例索引（ID 顺序 = 执行顺序 = 权威，机读自 JSON）

| # | ID | 场景 | 依据链 | 包数 | 断言 |
|---:|---|---|---|---:|---|
| 1 | `xmpp_t1_smoke_plain` | 缺省 PLAIN 全阶段基线 | 设计 §3.3/§3.4/§5.1 + RFC 6120 §4 | 19 | frames×5 + fields×12 |
| 2 | `xmpp_t2_digest_md5` | DIGEST-MD5 四步 | 设计 §3.4 + RFC 2831 | 21 | frames×3 |
| 3 | `xmpp_t3_scram_sha1` | SCRAM-SHA-1 六步 | 设计 §3.4 + RFC 5802 + 参考 pcap | 23 | frames×3 |
| 4 | `xmpp_t4_anonymous` | ANONYMOUS 匿名单轮 | 设计 §3.4 + RFC 4505 | 19 | frames×1 |
| 5 | `xmpp_t5_presence_off` | presence 缺席（位置证明） | 设计 §3.3 + RFC 6121 §4.2 | 18 | frames×1 |
| 6 | `xmpp_t6_messages_both` | messages 双向 + 方向值钉 | 设计 §3.3/§5.4 + RFC 6121 §5.2 | 21 | frames×2 + fields×2 |
| 7 | `xmpp_t7_identity_custom` | 身份四键定制值钉 | 设计 §3.3（to/from/id 语义） | 19 | frames×4 |
| 8 | `xmpp_t8_plain_credentials` | PLAIN 凭据 base64 钉 | 设计 §3.4 + RFC 4616 | 19 | frames×1 |
| 9 | `xmpp_t9_neg_mech` | 负：机制枚举外 | 设计 §7 N-1 | 0 | `error_contains` 锚 |
| 10 | `xmpp_t10_neg_direction` | 负：direction 枚举外 | 设计 §7 N-2 | 0 | `error_contains` 锚 |
| 11 | `xmpp_t11_long_body_mss` | 长 body 超 MSS 分段 | 设计 §3.1/§9（9.46 超长边界） | 22 | frames×1 |

**T-编号对照（双向，逐条回指设计）**：T-1 ≡ #1（CODE_DESIGN D-XMPP-1 P3 清单 T-1 同号）；T-2…#10 ≡ #2…#10；**T-11 = 追加轮 4 新增**（隔离复审缺口 3 补钉，CODE_DESIGN 未列 → 已在设计 §11.1 补记）。

**帧断言分布（21 条，机读计数）**：T-1 5 / T-2 3 / T-3 3 / T-4 1 / T-5 1 / T-6 2 / T-7 4 / T-8 1 / T-9 0 / T-10 0 / T-11 1 = **21** ✓
**字段断言分布（14 条，机读计数）**：T-1 12 / T-6 2 = **14** ✓（其余 9 例 0 条——**除 T-1/T-6 外无字段断言**，A′ 收编候选见 §6.2）

## 3. 正例逐项断言契约（9 例）

通用纪律：`frames[].offset` 全为 **54**（14 eth + 20 ip + 20 tcp，无 VLAN/无 IP options）；`frames[].hex` 为该偏移起的**前缀**（长度 11–128 字节不等，按各例钉的语义而定）；断言**只钉已写出的字节**，未写出的部分不作断言（不构成"任意即可"——见各例"禁止推断"）。

### 3.1 #1 `xmpp_t1_smoke_plain`（19 帧，最全基线）

- **spec 要点**：`[ip 10.0.0.1→20.0.0.1, xmpp {}]`（**空配置** → 全缺省派生，设计 §5.4）。
- **frames（5 条）**：
  - f4@54 `<…<stream:stream to='example.com'`（**缺省 to 值钉**；前缀止于 `27`=引号收尾）
  - f6@54 `<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>AHVzZXIAcGFzcw==</auth>`（**缺省凭据钉**：base64(`\0user\0pass`) 全元素）
  - f10@54 `<iq type='set' id='bind_1'`（bind 请求头）
  - f14@54 `<presence/>`（11 字节全帧 payload 钉）
  - f15@54 `</stream:stream>`（up 侧流关闭，16 字节全钉）
- **fields（12 条）**：f1 `tcp.flags`=0x002（SYN）/ f2 `tcp.flags`=0x012（SYN-ACK）/ f3 `tcp.flags`=0x010（ACK）/ f1 `tcp.dstport`=5222；f10 `xmpp.id`=bind_1 + `xmpp.type`=set；f11 `bind_1`+`result`；f12 `sess_1`+`set`；f13 `sess_1`+`result`（**iq 请求/响应 id 配对钉**，RFC 6120 §8.2.3）。
- **禁止推断**：`tcp.flags` 走 pcaptest **位比较**（`verify.go:114`，`0x002≡0x0002` 同义），不得改成字符串等值比较。
- **notes 要点**：包数分解（13 数据帧）；f15/f16 双流关闭白名单口径；缺省凭据钉为追加轮 4 所补。

### 3.2 #2 `xmpp_t2_digest_md5`（21 帧）

- **frames**：f6@54 `<auth … mechanism='DIGEST-MD5'/>`（自闭合）/ f7@54 `<challenge xmlns='…sasl'>`（**前缀止于 `>`**，载荷内容不钉）/ f9@54 `<success xmlns='…sasl'>`（前缀止于 `>`，rspauth 内容不钉）。
- **钉的语义**：步数（四步 = 比 PLAIN 多两帧）与帧位；**载荷内容不钉**（固定示例串，非真摘要，设计 §1 边界④）。
- **禁止推断**：不得由 f7/f9 前缀反推"载荷为空"（f7 实为 188B 含 124 字符 base64 nonce）。

### 3.3 #3 `xmpp_t3_scram_sha1`（23 帧，最大会话）

- **frames**：f6@54 auth `mechanism='SCRAM-SHA-1'` / f7@54 `<challenge xmlns='…sasl'></challenge>`（**空 challenge 全元素钉**，与参考 pcap 同形）/ f11@54 `<success xmlns='…sasl'>`（前缀止于 `>`，verification 载荷不钉）。
- **钉的语义**：六步交换（比 PLAIN 多四帧）+ 帧位；**中间 response/challenge 帧（f8–f10）不钉**（今日缺口，§6.2 A′ 候选 `field 断言收编`）。
- **门3 抽查候选**（设计 §9.1）：本例为最复杂用例。

### 3.4 #4 `xmpp_t4_anonymous`（19 帧）

- **frames**：f6@54 `<auth xmlns='…sasl' mechanism='ANONYMOUS'/>`（70 字节全元素钉）。
- **钉的语义**：匿名单轮与 PLAIN 同帧数（19）但 auth 元素自闭合无语义载荷。
- **冲突注记**：本机制**未在 features 宣告表出现**（宣告 5 机制 ≠ 枚举 4 值，设计 §3.4 G-XMPP-14）——断言只钉客户端所发字节，不钉服务端宣告一致性。

### 3.5 #5 `xmpp_t5_presence_off`（18 帧，最小会话）

- **frames**：f14@54 `</stream:stream>`。
- **钉的语义**：**位置证明**——f14 在 T-1 中是 `<presence/>`，本例 f14 直接是流关闭帧 → presence 确实缺席（不是"少一帧"式的间接推断）。
- **禁止推断**：不得据此断言"f14 之后无任何帧"（f15 = down 侧流关闭，f16–18 = 终止三帧）。

### 3.6 #6 `xmpp_t6_messages_both`（21 帧）

- **frames**：f15@54 `<message to='alice@example.com' type='chat'><body>ping</body></message>`（**全节 71 字节全钉**）/ f16@54 `<message to='user@example.com' type='chat'><body>pong</body></message>`（**全节 70 字节全钉**）。
- **fields**：f15 `ip.src`=10.0.0.1（up）/ f16 `ip.src`=20.0.0.1（**down 侧换向钉**）。
- **钉的语义**：up/down 两节字节同构（同 `buildMessageStanza`），**方向的唯一 e2e 可观察 = L3 侧别** → 该 2 条字段断言是 raw 链"防双换"（设计 §3.3 末）的**唯一回归拦截点**，**不得删除或降级**。
- **notes 要点**：追加轮 4（隔离复审）补钉。

### 3.7 #7 `xmpp_t7_identity_custom`（19 帧，帧序非升序）

- **frames（JSON 内书写序 = 4, 10, 5, 11）**：
  - f4@54 客户端流头全元素 `to='chat.x.cn'`（**to 定制值钉**）
  - f5@54 服务端流头 `from='chat.x.cn' id='ff11ee22'`（**from + stream_id 两值钉**；前缀止于 id 值引号）
  - f10@54 bind 请求 `<resource>bot7</resource>`（**resource 值钉**，全元素）
  - f11@54 bind result `<jid>ops@chat.x.cn/bot7</jid>`（**jid 值钉**，全元素）
- **形状注记（不改断言，G-XMPP-12 附注）**：frames 数组**未按 packet 升序**书写（4,10,5,11）——执行器按元素逐条比对，**不影响判定**；P4 可顺手排序（可读性，非缺陷）。
- **notes 要点**：追加轮 3 补 f5/f11 值断言（原 f4/f10 前缀不含这两键的值）。

### 3.8 #8 `xmpp_t8_plain_credentials`（19 帧）

- **frames**：f6@54 `<auth … mechanism='PLAIN'>AG9wcwBzM2NyZXQ=</auth>`（**全元素钉**，base64(`\0ops\0s3cret`)）。
- **钉的语义**：PLAIN 载荷 = RFC 4616 格式（authzid 空），**格式真、内容为配置值**；缺省路径由 #1 承接（两例互补，不可互替）。

### 3.9 #11 `xmpp_t11_long_body_mss`（22 帧）

- **frames**：f15@54 `3c 6d 65 73 73 61 67 65 20 74 6f 3d 27 62 75 6c 6b 40 65 78 61 6d 70 6c 65 2e 63 6f 6d 27 20 74 79 70 65 3d 27 63 68 61 74 27 3e 3c 62 6f 64 79`（message 节首段前缀，**止于 `<body`**）。
- **钉的语义**：3000 字符 body → 节 3066B → **3 段**（1460 + 1460 + 146，RFC 6120 无长度域 / 引擎唯一真实 MSS 边界）。
- **禁止推断**：f15 前缀**不含** body 内容 → 不得据此断言 body 值（body 值由 T-6 短节承接）。
- **notes 要点**：为追加轮 4（隔离复审缺口 3）所补；T-11 已校正为 3066B、3 段（1460+1460+146）。

## 4. 负例契约（2 例，先跑后钉、单注入、0 帧）

| # | ID | 故障注入（单一） | `error_contains`（逐字） | 代码锚（逐字） | 实测 |
|---:|---|---|---|---|---|
| 9 | `xmpp_t9_neg_mech` | `xmpp.auth_mechanism="NTLM"` | `unsupported auth mechanism` | `xmpp: unsupported auth mechanism %q (supported: PLAIN, DIGEST-MD5, SCRAM-SHA-1, ANONYMOUS)`（`xmpp.go:125`） | 0 帧 |
| 10 | `xmpp_t10_neg_direction` | `xmpp.messages[0].direction="left"` | `invalid direction` | `xmpp: message[%d] invalid direction %q (must be up or down)`（`xmpp.go:139`） | 0 帧 |

**负例纪律**：
1. **不得产出成功 pcap**——实测 `<id>.neg.pcap` **0 帧**（不许"completed/0 packet"假成功，不许只剩 TCP 外壳）。
2. **单注入**：#9 的 messages 为空、#10 的机制缺省（PLAIN）——除注入点外全部合法，锚词唯一归因。
3. **锚词匹配为包含式**（`error_contains`），锚词须为代码逐字子串（上表已逐字对齐，含 `%q` 占位符的**外围文本**，不含实际值）。
4. **形状已收窄**：两例 `expect` 严格为 `{expect_error, error_contains}` 两键；notes 信息已迁移至本文档 §4。
5. **red-first**：负例先证伪（改前不报错 = 漏锚），再证真（改动后报锚词）；本套件两锚今日实测生效（链路径 `layer_gen.go:69` → `chain_planner_gen.go:142` 定义 / `chain_planner.go:413` 调用 已接线）。

## 5. 覆盖与对账

### 5.1 三源回指（每个断言可溯源）

| 源 | 覆盖的断言面 |
|---|---|
| 规范（RFC 6120/6121 + 四机制 RFC） | 流头属性面（T-1/T-7）、SASL 四机制步形（T-2/T-3/T-4/T-8）、iq id 配对（T-1 fields）、message 节（T-6/T-11）、流关闭（全正例 f15/f16） |
| 设计（`124-xmpp-design.md`） | 线格式 §3.3/§3.4/§3.5（长度公式）、事务 §5.1（包数公式）、错误 §7（两锚） |
| 实测（tshark + pcap） | 21 frame 前缀、14 field 值、11 packet_count——**全部抄自实跑**，零推算 |

### 5.2 对账两行

- **要求逻辑点总数 = 106**（设计 §10 八项 8 + 矩阵 39 + 变体 39 + 商业 20）；**用例覆盖 = 57**；**不适用 = 18**；**开放立项 = 31**（57+18+31=106 ✓，逐表重数见设计 §10.1–§10.4）。**粒度声明**：行/格粒度每点 1 计；G-XMPP-1…17 与 confirmed 项不折进 106。**反查全绿 ≠ 覆盖全**。
- **断言级对账（本文件口径）**：11 例 ↔ 21 frame + 14 field + 11 packet_count = **46 条断言，逐条对 pcap 复核 PASS（46/46）**；9 正例帧数 ↔ `packet_count` 逐例一致；2 负例 ↔ 0 帧。

### 5.3 门3 抽查候选

| 候选 | 理由 |
|---|---|
| **#3 `xmpp_t3_scram_sha1`**（首推） | 最复杂：23 帧 = 10 阶段全序 × SCRAM 六步 × 参考 pcap 同机制交织；任一处顺序/帧数漂移即暴露 |
| **#11 `xmpp_t11_long_body_mss`** | 分段面唯一证据（3 段）+ summary 文字矛盾点 |
| **#6 `xmpp_t6_messages_both`** | 方向面唯一拦截点（`ip.src` 双向钉） |

### 5.4 T-编号 ↔ 用例 ID 对照

T-1…T-10 ≡ #1…#10（逐一对应，CODE_DESIGN D-XMPP-1 P3 清单同号）；**T-11 ≡ #11（追加轮 4 新增，主清单未列——已补记设计 §11.1）**。

## 6. P3 固定动作（每协议必做：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免边界审计）

### 6.1 §3.15 三项逐项结论

| 项 | 本协议结论 |
|---|---|
| **长保活** | **不适用/未建模**——XMPP 无强制心跳；XEP-0199 ping 未实现（G-XMPP-9，B′ 立项）；套件内零保活帧（§1.5） |
| **重传** | **不适用**——确定性顺序剧本，无重传编排；实测 11/11 无重传帧；`packet_count` 即全量（§1.5） |
| **RST/异常终止** | **未覆盖**——全部 `terminates=true` = 正常 FIN 四包；RST 路径零用例（G-XMPP-16，A′ 候选 `xmpp_abort_rst`） |

### 6.2 A′ 分类（用例侧补强，12 例候选）

| 候选 ID | 内容 | 对应缺口 |
|---|---|---|
| `xmpp_neg_top_level` | 顶层 `xmpp` 子映射 presence 形 → 判死红例（**判死已接线 `strategy_convert.go:9098`，今日建即真红**） | G-XMPP-6 |
| `xmpp_msg_defaults` | messages 项 to/body 双缺省值钉（缺省 `bob@example.com` / `Hello from trafficgen`） | G-XMPP-12 |
| `xmpp_presence_true` | `presence=true` 显式形（与 nil 同路径） | G-XMPP-1 |
| `xmpp_mech_lowercase` | `auth_mechanism="plain"` 归一化路径 | G-XMPP-10 |
| `xmpp_ipv6` | IPv6 载体（offset 74 零证据） | G-XMPP-4 |
| `xmpp_multiflow_dyn_ip` | `flows=2` + `ip.src/dst` 动态对象 + 端口 12345+i 断言 | G-XMPP-3 |
| `xmpp_mss_boundary` | 节长恰 1460±1 的边界相邻值（今日仅 71B 与 3066B 两点） | 设计 §10.3 #31 |
| `xmpp_abort_rst` | RST 异常终止 | 设计 §10.2 T3 列 |
| `xmpp_neg_bad_ip` | `SrcIP/DstIP` 非法（flat 形锚 `xmpp: invalid SrcIP`；链形被 validateSpecBase 遮蔽） | G-XMPP-11 |
| `xmpp_neg_mixed_family` | 异族混写（框架锚 `invalid source IP`） | 设计 §8 |
| field 断言收编 | `xmpp.to`/`xmpp.from`/`xmpp.iq`/`xmpp.cdata`/`xmpp.attribute`（先跑后钉） | G-XMPP-17 |
| `xmpp_neg_xml_escape` | 含 `'`/`<`/`&` 的身份键 → 产非法 XML 不拒（**缺陷候选**） | G-XMPP-16 |

### 6.3 B′ 分类（账本继承，裁定 4）

| 项 | 状态 |
|---|---|
| STARTTLS 未协商（TLS 态不存在） | **账本在案，明确不解决**——真实 TLS 非生成器范围（G-XMPP-7） |
| zlib 压缩未启用 | **账本在案，明确不解决**（G-XMPP-7） |
| SASL 失败路径未建模（参考 pcap 全失败会话） | **账本在案，明确不解决**（G-XMPP-7） |
| DIGEST/SCRAM 固定示例载荷（非真密码学） | **账本在案，明确不解决**（G-XMPP-7） |
| XEP-0199 IQ ping 保活 | **账本在案，未解决**（G-XMPP-9） |
| features 宣告 5 机制 vs 枚举 4 值不一致 | **confirmed，P4 裁定对齐**（G-XMPP-14） |
| `normalizeAuthMech` 大小写宽松（RFC 4422 区分大小写） | **账本注记 + A′ 候选**（G-XMPP-10） |
| 流重启沿用同一 `stream_id` | **待确认**（查 RFC 原文 + 抓 ejabberd restart 包，G-XMPP-15） |

### 6.4 3.14 豁免边界审计（白名单是否过宽）

- `verify.go:574` 豁免条件 = **caseID 前缀 `xmpp_` + 摘要逐字 `Closing an unopened tag`**（精确匹配，非 `Contains` 摘要）。审计：① 前缀面覆盖本套件 11/11（含负例——负例 0 帧故不触发）；② 摘要面**仅**流关闭伪影一种（实测每正例恰 2 帧）；③ **不得**把 `Unknown element/attribute`、`Packet without response` 等专家信息纳入豁免（今日未纳入 ✓）；④ **不得**放宽为"任意 Malformed Packet"——若未来出现第三帧 malformed，须先查明来源再决定是否扩白名单（扩 = 需记录理由与帧位）。
- 结论：**豁免边界与实测伪影面一一对应，无过宽**。

## 7. 实现后执行建议（P5 跑套件时照做）

1. **环境**：MCP 建策略/任务 → 引擎真实生成 → pcap 落 `/tmp/mcp-pcaps/xmpp/`（`<id>.pcap` / `<id>.neg.pcap`）；跑法坑见记忆 `protocol-pcap-smoke-runnable`（API key / PCAP_ROOT / 必须 `-run` 过滤）。
2. **双通道**：pcap 路径 + NIC 路径（`enp135s0f0np0`）跑**同一** 11 例；断言集路径无关（设计 §1 输出契约）。
3. **顺序**：先 9 正例（逐例 frame/field 比对）→ 再 2 负例（0 帧 + 锚词）→ 最后全量 `packet_count` 对账。
4. **红先绿后**：任何新断言先证伪（改前不匹配）再证真；负例先证锚词可达。
5. **不得跳步**：不得只跑 `has_handshake`/`packet_count` 而跳过 frames/fields；不得引用历史产物（`trafficgen/docs/protocol-pcap-test/xmpp.md` 的 11/11 结论**证据面缺失**，见 §8.1）。
6. **P4 前置已完成**：T-11 summary、T-11 补 `has_payload`、负例删 `notes` 三处已落地，随后再跑全量。

## 8. 存量审计（11 例逐条去向）

### 8.1 实测面（2026-09-29 本车道机读 + tshark 复核）

- `cases/xmpp.json`：11 例、五键顶层、`spec_json` 仅 `layers`、层形 `[ip,xmpp]` ×11 ——**全部达标**（设计 §12.1 零残留）。
- 11 个 pcap 全部在案：9 正例帧数 19/21/23/19/18/21/19/19/22 **逐例等于 `packet_count`**；2 负例 **0 帧**。
- 21 frame 断言逐字节复核 **OK**；14 field 断言逐值复核 **OK**（`tcp.flags` 走位比较）。
- **合计 46/46 PASS**（自审脚本机读，非人工计数）。
- 结果产物 `trafficgen/docs/protocol-pcap-test/xmpp.md`（tracked）：自称 "11 pass / 0 fail"，末次提交 `4caf4b9`（2026-09-21）——**晚于**判死提交 `0417be5`（2026-09-13）→ **不满足任务书过期判定条件，不登记为过期缺口**；但其输出目录 `trafficgen/docs/protocol-pcap-test/xmpp/` **不存在**（11 条链接全死链）→ 留档缺失，登记 G-XMPP-13。

### 8.2 已确认修正（P4 已落地）

| # | 修正 | 证据 |
|---|---|---|
| C-1 | T-11 summary 已校正为 3 个 TCP 段（1460+1460+146） | JSON summary + 实测 pcap f15/f16/f17 `tcp.len` |
| C-2 | T-11 `expect` 已补 `has_payload: true` | JSON 键集合 |
| C-3 | 两个负例 `expect` 已收窄为 `{expect_error, error_contains}` 两键 | JSON 键集合；说明见 §4 |

### 8.3 逐条去向表（保留 / 改写 / 作废）

| # | ID | 去向 | 依据 |
|---:|---|---|---|
| 1 | `xmpp_t1_smoke_plain` | **保留** | 断言全绿；缺省凭据/to 两值钉齐（追加轮 4 已完成） |
| 2 | `xmpp_t2_digest_md5` | **保留** | 步数 + 帧位钉；载荷不钉为有意（示例串，G-XMPP-7） |
| 3 | `xmpp_t3_scram_sha1` | **保留** | 与参考 pcap 同机制同形；中间帧不钉见 §6.2 A′ |
| 4 | `xmpp_t4_anonymous` | **保留** | 元素字节全钉；宣告不一致另记 G-XMPP-14 |
| 5 | `xmpp_t5_presence_off` | **保留** | 位置证明式断言（强于帧数推断） |
| 6 | `xmpp_t6_messages_both` | **保留** | 方向唯一拦截点；字段断言不可动 |
| 7 | `xmpp_t7_identity_custom` | **保留**（附注） | 四键值钉齐；frames 书写序 4,10,5,11 建议 P4 排序（可读性，非缺陷） |
| 8 | `xmpp_t8_plain_credentials` | **保留** | base64 全元素钉；与 #1 互补不互替 |
| 9 | `xmpp_t9_neg_mech` | **保留 + 收窄** | 锚词逐字对齐；expect 删 `notes`（C-3） |
| 10 | `xmpp_t10_neg_direction` | **保留 + 收窄** | 同上 |
| 11 | `xmpp_t11_long_body_mss` | **改写** | summary 2 段→3 段（C-1）+ 补 `has_payload`（C-2）；帧断言与包数保留 |

**作废数 = 0**（无失败例、无重复例、无失效例）。

## 9. 覆盖反查门建议断言行（主线程登记 `coverage_gate.py::check_xmpp` 用；本车道不碰该文件）

> 现状：`check_xmpp` 已在案（`tools/coverage_gate.py:7127-7168`，**23 行**，今日全绿），下述为**新增/替换建议**（主线程裁定采纳面）。

| 建议行 | 断言 | 理由 |
|---|---|---|
| `xmpp.case_count` | 用例数 == 11 | 防静默删例 |
| `xmpp.case_order` | ID 顺序 == §2 表序（逐 ID 比对） | 顺序即权威 |
| `xmpp.top_key_clean` | 非负例全部 `spec_json` 顶层键 == {layers} | §12.1 零残留守卫 |
| `xmpp.chain_shape` | 11/11 层形 == `[ip, xmpp]` | 层链唯一真相 |
| `xmpp.real_port` | 至少 1 例含 `tcp.dstport == 5222` 字段断言 | 端口缺省 5222 守卫 |
| `xmpp.handshake_flag` | 至少 1 例 `tcp.flags` SYN/SYN-ACK/ACK 三断言齐 | 自建握手守卫 |
| `xmpp.bind_pair` | 至少 1 例 `xmpp.id` == bind_1 且 set/result 双现 | iq 配对守卫 |
| `xmpp.sess_pair` | 至少 1 例 `xmpp.id` == sess_1 且 set/result 双现 | 会话建立守卫 |
| `xmpp.direction_pin` | T-6 的 f15/f16 `ip.src` 双向断言齐（10.0.0.1 / 20.0.0.1） | 防双换唯一拦截点 |
| `xmpp.mech_enum` | 4 机制各至少 1 例（PLAIN/DIGEST-MD5/SCRAM-SHA-1/ANONYMOUS） | 机制面不塌缩 |
| `xmpp.presence_off` | T-5 `packet_count` == 18 且 f14 == 流关闭前缀 | presence 缺席位置证明 |
| `xmpp.mss_split` | T-11 `packet_count` == 22 | 分段面守卫 |
| `xmpp.neg_anchor_mech` | T-9 `error_contains` 含 `unsupported auth mechanism` | 锚词不漂移 |
| `xmpp.neg_anchor_direction` | T-10 `error_contains` 含 `invalid direction` | 锚词不漂移 |
| `xmpp.neg_expect_keys` | 2 负例 expect 键 == {expect_error, error_contains} | C-3 收窄守卫（P4 后生效） |
| `xmpp.neg_zero_frame` | 2 负例 pcap 帧数 == 0 | 禁假成功 |
| `xmpp.has_payload_all` | 9 正例全含 `has_payload` | C-2 守卫（P4 后生效） |
| `xmpp.summary_seg3` | T-11 summary 明确为“3 个 TCP 段” | C-1 守卫 |
| `xmpp.offset_uniform` | 21 frame 断言 offset 全 == 54 | 偏移基守卫（IPv4 无 options） |
| `xmpp.frame_prefix_real` | 21 frame 前缀逐字节对 pcap 复核（先跑后钉） | 禁凭推算书写 |
| `xmpp.field_value_real` | 14 field 值对 pcap 复核（tcp.flags 位比较） | 同上 |
| `xmpp.malformed_whitelist` | 正例 malformed 帧数 == 2/例 且摘要 == "Closing an unopened tag" | §6.4 豁免边界守卫 |
| `xmpp.no_keepalive` | 11 例帧数 == 公式值（无保活帧混入） | §1.5 保活口径 |
| `xmpp.no_rst` | 正例终止三帧 flags 非 RST | terminates 口径守卫 |
| `xmpp.gap_registry` | 设计 §14 G-XMPP-1…17 条数 == 17 | 缺口表不缩水 |
| `xmpp.audit_rows` | 本文件 §8.3 行车数 == 11 且作废数 == 0 | 存量审计完整 |

## 10. 修订记录

- v1.0.1（2026-09-30）：P4 收敛三项已落地：T-11 summary 按实测改为 3066B/3 段，补 `has_payload: true`，两负例 `expect` 收窄为两键；消息 to/body 缺省路径仍为 A′ 候选。自审 2 轮，末轮干净。

- v1.0.0（2026-09-29）：与设计 v1.0.0 同版首发布。11 例存量逐条机读审计（**作废 0 / 改写 1 / 保留 + 收窄 2 / 保留 8**）；46/46 断言对 pcap 实测复核（21 frame + 14 field + 11 packet_count）；七类断言基线 + 包数公式 `16+A+P+ΣS`（9/9 一致）；负例 0 帧 + 单注入 + 锚词逐字；A′ 12 例候选 / B′ 8 项账本；3.14 豁免边界审计（无过宽）；覆盖反查门建议 26 行。自审 2 轮（机读脚本 + 逐数复核），末轮干净。

# GOOSE（IEC 61850-8-1）三件套文档对抗审查报告

> 审查对象：
> - `docs/protocol-designs/23-goose-design.md`（设计文档）
> - `docs/protocol-designs/23-goose-testcase.md`（用例文档）
> - `trafficgen/test/protocol_pcap/cases/goose.json`（用例数据）
>
> 审查口径：文档阶段审查——检查三件套**自洽性与规范一致性**，不审查 Go 代码实现是否存在；"未实现/未注册"记录为待实现边界，不阻断文档验收。
> 审查方式：对 JSON 每个 frames 断言的 offset 逐字段 BER 累加重算（python 脚本核对），对 design/testcase/cases 三方字段取值、长度、语义做交叉核对。
> 审查日期：2026-08-19

---

## 结论摘要

**三件套文档存在系统性帧偏移错误（CRITICAL）与多处文档自相矛盾（MAJOR），文档不得直接作为实现/断言依据，必须修订后验收。**

- **CRITICAL-1（未修复）**：goose.json 全部 APDU 内部 frames 偏移系统性错差 -1；根因是 design 文档 BER 长度形式计算错误：gocbRef（41B）+ datSet（35B）使 APDU 内容长度 = 173 > 127，goosePdu 必须使用 **BER 长形式 3 字节 `61 81 AD`**，而设计按短形式 2 字节 `61 AD` 计算，导致 JSON 所有 APDU 偏移比正确值小 1。
- **CRITICAL-2（新增）**：goose_heartbeat 的 `goose.length` 字段断言值 **184 错误**（正确 183，对应 `61 81 AD`），notes 中"APDU content 176→`61 81 b0`"的 APDU 内容长度 176 也是错的（正确 173→`61 81 AD`）。
- **MAJOR-1.1（未修复）**：design §2.5 断言 stNum/sqNum/confRev "定长 4"（`85 04 00 00 00 01`），§3.6/§2.6 断言"最小编码"（值 1 → 1 字节 `01`），§6.1 S1 HexDump 又是 `85 04 00 00 00 01`——**同一文档三处自相矛盾**。goose.json 按最小编码（`85 01 01`）编写，与 design §3.6 一致、与 §2.5/S1 HexDump 冲突。
- **MAJOR-2（未修复）**：design §6.5 S5 HexDump 标签表与 §3.7 自相矛盾：`87 04 <5 字节>`（长度=4 却跟 5 字节）、`84 02 01 fe`（bit_string 8 位 padding 算成 1）均与 §3.6/§3.7 的公式冲突；S5 allData 内容长 `ab 21`（33）与成员实际和 25 不符。
- **MAJOR-5（未修复）**：design §6.6 S6（无 IP 证明）的 FrameAssert 偏移仍是**无 VLAN 固定偏移 12/22**；goose.json 的 no_ip 用例复用同一固定偏移，在 VLAN 叠加时不可用——"无 IP"断言必须字节级且与 VLAN 分支解耦（前 12 字节 MAC 后即 88b8，不依赖 APDU 偏移）。
- **MINOR-7（未修复）**：design §8.5 CP 8B 分数秒公式括号内 "32768 = 0.5 秒" 是**陷阱**：32768 是秒的 2^-15，而 CP 8B 分数秒单位是 2^-32（0.5 秒应为 0x80000000）。§8.5 的正文（单位 2^-32）正确，括号举例错误。
- **MINOR-8（未修复）**：design §9.4 Length 校验公式只给无 VLAN 分支（`帧长 - 14 − 8 = APDU 长`），缺 VLAN 分支。goose.json 的 VLAN 用例在 notes 里自行推导了正确公式（188-18-8=162），但 design 正文未收录。

**配套修复清单（与 SV 前例对齐，24-sv-adversarial-audit.md 同样通过 frames 重编号修正）**：

| JSON id | 需修正项 |
|---------|----------|
| goose_heartbeat | 全部 APDU 内 offset +1（80 29:24→25，81 02 01 f4:67→68，82 23:71→72，83 29:108→109，84 08:151→152，85..89:161→162，8a..ab:176→177，成员 181/185/193→182/186/194，包 2/3 sqNum 164→165）；`goose.length` 184→**183**；LEN 占位、FrameAssert 60→61 边界修正；notes 的 176→173、`61 81 b0`→`61 81 AD` |
| goose_retransmit | 161→162（stNum+sqNum 合并段）、164→165（sqNum 各包）、176→177（num+allData）；packet 8 sqNum 改 ^6；count 8→6（Design 附录 B 同步）；notes 同步 |
| goose_dataset_change | 161→162（2 处）、164→165（2 处） |
| goose_test_flag | 167→168（2 处） |
| goose_ndscom_flag | 167→168（链起点）、173→174（ndsCom 段） |
| goose_vlan | 26 处 `61` 正确（VLAN 场景 61 恰在 26）；20 处 LEN `00 aa`（170）正确；无需改 |
| goose_multitype | 176→177、181→182、187→188、195→196、199→200、206→207、210→211、214→215、221→222 |
| goose_multidataset | 176→177、181→182、184→185、187→188、191→192、198→199、202→203 |
| goose_no_ip | 12/22 偏移正确；补充 VLAN 变体断言（前 12 字节后即 88b8） |

---

## 1. 代码设计逻辑审查 findings（design 文档自洽性与规范一致性）

### CRITICAL-1：BER 长度形式计算错误导致全文帧布局偏移系统性错差（即已知问题 CRITICAL-1"frames 偏移全部错锚固定 22"，未修复）

- **位置**：23-goose-design.md §2.5、§3.1、§6.1；23-goose-testcase.md §4.1/§8；goose.json 全部用例的 frames offset。
- **问题**：design §3.1/§6.1 把 goosePdu 的长度字段写成 2 字节（`61 <L1>`，内容 <L1> 隐含短形式），但实际数据集示例的 APDU 内容长度 = **173 字节**（gocbRef 41B + TAL 4B + datSet 35B + goID 41B + t 8B + stNum/sqNum/test/confRev/ndsCom 各最小编码 3B + num 3B + allData 18B）。
- **与规范矛盾证据**：BER 短形式长度必须 ≤ 127（高位 0）；173 > 127，必须使用**长形式 3 字节**：`61 81 AD`（0xAD=173）。design §2.5 自己也写了"所有值长度 ≤ 255 用短形式，`allData` 大数据集（如 4000 条目）可用长形式"——但这里**gocbRef+datSet 两个长字符串本身就把 APDU 内容推到 >127**，即使 allData 只有 18 字节也必须长形式。`61 81 AD` = 3 字节头意味着 APDU 内所有字段相对以太头偏移整体 +1。
- **文档内部矛盾证据**：design §3.1 表格在"22/26 goosePdu (APDU)"一行写 `61 <L>`（无 VLAN 偏移 22），与"所有值长度 ≤ 255 用短形式"（§2.5）冲突；SV 前例（24-sv-design.md/sv.json）同类 gocbRef/datSet 字符串下（10B svID）SV APDU 内容 < 128 用短形式，偏移无此问题——GOOSE 是**首个因控制块引用长而必须走长形式的 L2 终结协议**，不得简单类比 SV 模板。
- **后果**：goose.json 全部 APDU 内部 frames 偏移系统性小 1（脚本逐字段核对，12 个用例 40+ 断言全部 -1，只有 offset 22 的 `61` 与 offset 12 因在长形式影响范围前而恰好正确）。按此 JSON 实现断言会**在错误字节位置比对**，出现"断言值刚好错位仍绿"或"正确帧反被拒"的假阳性/假阴性。
- **修复建议**：design §3.1/§6.1 显式写 `61 81 <L>` 3 字节长形式并说明触发条件（APDU 内容 >127 因长字符串）；JSON 全部 APDU 内偏移 +1（见结论摘要表格）；testcase §4.1/§8 同步。**同时把 `61 81 AD` 记为必测字节**，防实现偷懒走短形式。

### CRITICAL-2：goose_heartbeat 的 goose.length 字段断言 184 错误（新增，与 CRITICAL-1 同源）

- **位置**：goose.json `goose_heartbeat` fields 第 3 条 `{"packet":1,"field":"goose.length","value":"184"}`；notes 第 1 条 "APDU content 176 bytes -> 61 81 b0"。
- **问题**：按最小编码（§3.6），APDU 内容 = 173，goosePdu 总长 = 175，`Length = 8 + 175 = 183`。JSON 写 184，notes 写 content 176→`61 81 b0`（176B），两者都比正确值大 1。
- **文档内部矛盾证据**：JSON 自身字段断言 stNum/sqNum 用最小编码 `85 01 01`、`86 01 01`（1 字节值），但长度计算却隐含 2 字节值编码（内容多 3 字节 = stNum/sqNum/confRev 各多 1 字节）——**同一用例内编码口径自相矛盾**。
- **修复建议**：字段值改 `"183"`；notes 改 "APDU content 173 → `61 81 AD`"；同时将 `goose.length == 183` 与 FrameAssert offset 22 `61 81 AD` 对照为互证断言（Length 口径 §2.4：从 APPID 起，= 8 + APDU 全长）。

### MAJOR-1.1：整数编码"定长 4"与"最小编码"同文档三处互相矛盾（已知问题 MAJOR-2，未修复）

- **位置**：design §2.5 标签表（stNum/sqNum/confRev 长度规则"定长 4"、TAL "典型 4"、numDatSetEntries "2-4 字节"）；§3.6 最小编码（"值 1 → 1 字节 `01`"、"**测试断言必须以最小编码为准**"）；§6.1 S1 HexDump（`85 04 00 00 00 01`、`88 04 00 00 00 01`、`86 04 00 00 00 01`）；§2.5 又举 TAL=500→`81 02 01 f4`（最小编码示例）。
- **问题**：S1 HexDump 与 §2.5 的"定长 4"直接矛盾于 §3.6 的最小编码规则；§2.5 自身 TAL 示例（最小编码 2B）与 stNum"定长 4"也矛盾。
- **与规范矛盾证据**：IEC 61850-8-1 的 INTEGER 是 ASN.1 BER，libiec61850 `ber_encoder.c` 的 `encodeInteger`/`compressInteger` 默认最小编码（除非显式固定宽度）。值 1 固定 4 字节 `85 04 00 00 00 01` 虽可被 Wireshark 解析，但**不是 libiec61850 的默认输出**，也违背设计自定的 §3.6。
- **文档内部矛盾证据**：goose.json 全部按最小编码（`85 01 01`、`88 01 01`、`81 02 01 f4`），与 design §3.6 一致；design §6.1 的 HexDump `85 04 00 00 00 01` 若作实现模板，JSON 断言全挂。
- **修复建议**：删除 §2.5 的"定长 4"/"典型 4"表述，统一为"BER 最小编码"，S1 HexDump 改为 `85 01 01`/`86 01 01`/`88 01 01`；numDatSetEntries 条目数 < 128 时 2 字节 `8a 01 <n>`。下游 JSON 已正确，无需改。

### MAJOR-1.2：S1 HexDump 的逐字段序列与最小编码后的偏移不一致（与 MAJOR-1.1 同源，S1 模板整体失真）

- **位置**：design §6.1 S1 HexDump（`61 <L1>` | `85 04 ...` | `8a 01 03` | `ab <L3>` | 成员 `85 02 04 d2`/`8c 06`/`85 02 16 2e`）。
- **问题**：模板按 4 字节整数编码画偏移，若实现按最小编码（JSON 口径），字节序列整体短 3 字节；§6.1 断言要点"FrameAssert offset 22 起"会因模板失真误导实现。
- **修复建议**：S1 HexDump 全面换成最小编码字节（或明示"以 JSON 最小编码为准，本表仅示意字段序"）。

### MAJOR-2：S5 多类型 HexDump 标签/长度/内容长自相矛盾（已知问题 MAJOR-2"最小编码 vs 定长断言"+ MAJOR-4"bit_string padding"未修复，合并为一条）

- **位置**：design §6.5 S5；goose.json `goose_multitype`。
- **问题**：
  1. **浮点标签**：§6.5 写 `87 04 <xx xx xx xx>`（长度 4、4 字节内容），§3.7 写"长度字段 = 1 + (format_width/8) = **5**"（`87 05` + 5 字节：1 指数宽 + 4 尾数宽）——**自相矛盾**。goose.json 已按 5 字节（`87 05 08`，偏移 199）写，与 §3.7 一致、与 §6.5 冲突。
  2. **bit_string 8 位**：§6.5 写 `84 02 01 fe`（unused=1），§3.6/§2.5 公式 `padding = (byteSize×8) − bitLength` = 8−8 = **0**，应为 `84 02 00 fe`。goose.json 已按 0 写（`84 02 00 fe`）——JSON 对、§6.5 错。
  3. **allData 内容长**：§6.5 写 `ab 21`（33 字节），按该表成员实际编码长（boolean 3 + uint32 4 + float 7 + bit_string 4 + visible_string 7）= **25** = `0x19`，且 `ab 21` 意味着 33 字节与成员字节数 25 不符——**文档内部算术矛盾**。
- **修复建议**：§6.5 全表按 §3.6/§3.7 公式重算（`87 05 ...`、`84 02 00 fe`、`ab 19`）；goose.json 不动（已正确）。

### MINOR-1：datSet 配置默认值与 libiec61850 示例的偏差（新增，文档一致性）

- **位置**：design §5.1 默认 DatSet 为 `simpleIOGenericIO/LLN0$AnalogValues`；libiec61850 goose_publisher_example 中 DefaultAPDU_01 的 datSet 为 `<gcbRef 去 $GO$>` 后的 `simpleIOGenericIO/LLN0$AnalogValues`；design §1.2/§2.5/§5.1 自己写 gocbRef 默认 `...$GO$gcbAnalogValues`。
- **问题**：datSet 语义上应指向数据集（不含 $GO$），design 默认值一致于此，**无矛盾**；但 design §6 开头"对齐 libiec61850 示例"的表述与 libiec 例子的 datSet 全名（含更多路径段）不完全一致。
- **判定**：不构成缺陷（默认值自洽），仅提示实现时以 design §5.1 为准，不照抄 libiec 示例。

### MINOR-3：goose_multitype 10 成员与 testcase 文档"8 成员"不一致（新增，三方一致性）

- **位置**：testcase §4.8 配置"数据集 8 成员（bool×2/int32×2/uint32/float32/bit_string×2/visible_string×2）"；goose.json `goose_multitype` 实际 10 成员（多 visible_string×2 的 2 个）；testcase §8 一致性表也写 "data 8 成员：bool×2/int32×2/uint32/float32/bit_string×2/visible_string×2"。
- **问题**：8 = 2+2+1+1+2+2 不含 visible_string；10 = 2+2+1+1+2+2。JSON 写 10 成员、numDatSetEntries=10（对），testcase 写 8（错）。**同文档自身两处（§4.8 与 §8）一致地错**
- **修复建议**：testcase §4.8/§8 的"8 成员"改"10 成员（含 visible_string×2）"，或 JSON 删 2 个成员并全量重算长度（不推荐，10 成员覆盖更全）。
- **关联**：同条还带出 MAJOR-2 的 allData 长度算差（见上）。

### MINOR-7：CP 8B 分数秒换算举例错误（已知问题，未修复）

- **位置**：design §8.5 "32768 = 0.5 秒"。
- **问题**：CP 8B 分数秒单位 = 2^-32 秒，0.5 秒 = 0x80000000（2147483648），**不是 32768**（32768 = 2^-15 秒，≈30.5µs，是北向 NTP 惯例而非 CP 8B）。§8.5 正文"单位 2^-32"正确，括号举例误导。
- **修复建议**：改"0x80000000 = 0.5 秒"。

### MINOR-8：design §9.4 Length 校验公式缺 VLAN 分支（已知问题，未修复）

- **位置**：design §9.4 "**校验公式唯一**：帧长 - 14（无 VLAN）− 8 = APDU 长"。
- **问题**：公式只在无 VLAN 成立；有 VLAN 时应为 帧长 - 18 - 8 = APDU 长。goose.json `goose_vlan` notes 已正确推导（188-18-8=162），design 正文未收录 VLAN 分支。
- **修复建议**：§9.4 补 VLAN 分支（帧长 - 18 − 8）。

### MINOR-9：goose_multidataset 的 bit_string 成员缺 bit_length 字段（新增，spec 键一致性）

- **位置**：goose.json `goose_multidataset` data 第 5 成员 `{"name":"s1","type":"bit_string","value":"aa"}`。
- **问题**：`goose_multitype` 的 bit_string 都带 `bit_length`（8/4），本用例不带；不带给实现"bit_length 是否必填/默认=字节数×8"留下歧义。design §5.1 GooseDataEntry 只写 `bit_string 以 "bpairs:8,val" 形式`，与 JSON 的 `value+bit_length` 键形态不一致（§5.1 说 bpairs 形式、JSON 用 value/bit_length 两键）。
- **修复建议**：统一 bit_string 输入形态（JSON 的 `value`+`bit_length` 与 §5.1 的 bpairs 语法二选一，design 补齐）；multidataset 补 `bit_length: 8`。

### 内部未发现缺陷的核对项（已确认段落）

- **§2.5 标签表（0x61/0x80-0x8A/0xAB）**：与 IEC 61850-8-1 / libiec61850 / Wireshark packet-goose.c 一致；"0x88 security 不存在"的差异记录正确，未采纳任务初稿标签是改进而非缺陷。
- **§2.4/§3.1 Length 口径**（从 APPID 起 = 8 + APDU 全长）：与 libiec61850 `gooseLength = payloadLength + 8` 一致。
- **§3.6 MMS Data 内部 tag（0x83-0x91/0xA1/0xA2）**：与 mms_access_result.c 一致。
- **§4 状态机**：心跳 stNum 恒同/sqNum 递增、事件 stNum+1/sqNum 重置 0、退避 Tmax×2^k、交叠判定——与 IEC 61850-8-1 表 GOOSE 控制块行为一致。
- **bit_string padding 公式 §3.6**（`(byteSize×8) − bitLength`、unused 首字节、位左对齐）：与 ber_encoder.c 一致（JSON 已正确实现）。
- **§3.7 浮点**：长度 5、首字节"指数符号/尾数符号"，与 IEC 61850-7-2 二进制浮点一致。

---

## 2. 用例覆盖审查 findings（testcase 文档 + goose.json）

### COV-1（MAJOR）：负路径 sqNum 不连续/stNum 回绕的**触发机制未定义**（断言可观测性）

- **位置**：goose.json `goose_neg_sqnum`（event_seq 注入 `"sqnum_step": 2`）、`goose_neg_stnum`（`start_stnum: 4294967295`）；testcase §5.2/§5.3 只写"框架注入"。
- **问题**：`sqnum_step` 与 `start_stnum` 这两个**链 id 在 design §5.3 flat 键/§5.1 GooseConfig/§10 扩展字段中都未定义**。GooseEvent 只有 DataIdx/DelayMs/Retransmits（§5.1），无 sqnum_step；StartStNum 有（§5.1），但"start_stnum=0xFFFFFFFF 必须报错"的校验行未写入 design §9 错误表（§9.1 只有生成器不回绕的运行时规则，无"起始值越界的静态校验"行）。
- **后果**：用例预期"expect_error + error_contains"，但**没有规范定义这个错误从哪来**——实现阶段要么发明校验、要么用例永远绿/永远挂，无法证明目标行为。
- **修复建议**：design §9 补两行静态校验：(a) `sqnum_step/retransmits` 序列注入跳号 → 校验/生成期报 "sqNum"（定义 sqnum_step 链 id，或改为由 event_seq 描述显式 sqNum 序列再校验连续性）；(b) `start_stnum == 0xFFFFFFFF`（或 > 合法上限）→ 校验报 "stNum"。两链 id 一并补进 §5.3 键清单与 §5.1 GooseConfig 字段注释。

### COV-2（MAJOR）："无 IP"用例主断言缺失（对比入口要求，已修复为字节级但不够成立）

- **位置**：goose.json `goose_no_ip`；design §6.6 S6；testcase §4.9。
- **已修复部分**：帧偏移 22 的 `61`（非 0x45）与偏移 12 `88 b8` 双字节断言已实现，符合"必须用字节级不依赖解析器"的口径；`frame.protocols` 只断言 nonzero（存在）避免两环境差异，正确。
- **剩余缺口**：
  1. **未排除"帧内存在 IP 头"的完整证据**：偏移 12 = 88b8 **且**偏移 22 = 61 只证明 L2 之后直接是 APDU——但没有断言**帧内其他位置不出现 IP 特征**（0x45/协议号/TCP/UDP 头）。对单协议生成器而言此证据足够，但更彻底的字节级证明是断言整帧 `frame.len` 精确 = 14+8+APDU（如 heartbeat 的 goID 变体）。属于增强项非阻断项。
  2. **VLAN 叠加时本用例不可用**：S6 固定偏移 12/22；VLAN 场景（goose_vlan 已独立成例）下偏移 12 是 `81 00` 而非 `88 b8`。建议 goose_no_ip 增加一个 vlan_enabled 变体的 `88 b8 @16` 断言（或明确"S6 只覆盖无 VLAN，VLAN 下由 S4 佐证"）。
- **建议**：补齐 VLAN 变体断言或文档明示边界；主体已符合"ethertype=0x88B8 + 字节级 offset 12/22"要求。

### COV-3（MINOR）：confRev 无独立"变更"用例，且无 confRev 静态校验负例

- **位置**：testcase §7 勾选清单 "confRev：初值 1 + 同流恒定（T-GSE-S1-01 same_as）"；design §9.3 confRev<1 负例；design §10.1 `goose_confrev_change` 扩展。
- **覆盖状态**：confRev 恒等已有 same_as 断言；confRev **变更**（§10.1 扩展现状是"立即支持"，且那个值可被 tshark `goose.confRev` 观测，但 §7 只标注"恒等/变化（并入 S1/S2）"——实际 S1/S2 **没有 confRev 变化断言**）；design §9.3 的 `confRev<1` 负例在 §7 映射表与 testcase §3.1 清单、goose.json 中**均未列**（testcase §5.4 负例表只有 3 行：appid/sqnum/stnum）。
- **后果**：design 错误处理表写了规则（§9.3 校验失败 + 命名 `goose_neg_confrev`），testcase/JSON 三处都没有对应用例——**design 承诺的负例未落地**（Testing Policy 第 2 条：错误处理表的行必须转成测试）。
- **修复建议**：补 `goose_neg_confrev`（conf_rev:0 → expect_error + error_contains "confRev"）；或把 §9.3 的行降级为待实现边界并三处同步标注。

### COV-4（MINOR）：多流隔离（多组播流/多 IED）无独立用例

- **位置**：design §4.7 "多 GOOSE 任务并行：各自独立定时器 + 独立 stNum/sqNum/数据集"；goose.json 无多任务/多流用例。
- **覆盖状态**：无独立流隔离用例（不同 dst_mac/goID/APPID 的流各自计数）。单任务内共享计数语义已由心跳/重发覆盖；**跨任务隔离**是 §4.7 的声明但无测试锚点。
- **修复建议**：实现阶段补"两任务（不同 dst_mac + 不同 APPID）同引擎并发，各自 stNum/sqNum 独立"用例（NIC/pcap 双输出都可锚）。文档阶段记录为待实现边界。

### COV-5（MINOR）：simulation 位（Reserve1 位 15）无覆盖

- **位置**：design §2.4 "Reserve1 位 15（仿真位 S-bit）：v1 默认 0"；goose.json 无 Reserve1 位 15 置位用例。
- **覆盖状态**：帧头 Reserve1 的 0 值在 S1-02 断言；位 15 仿真位置 1（`80 00`）无正例。
- **修复建议**：补 `reserve1_sim` 用例（Reserve1 = 0x8000 → tshark `goose.reserve1.s_bit` 或 FrameAssert `18-19 字节 80 00`）。

### COV-6（MINOR）：goID 显式值与缺省行为无独立用例

- **位置**：design §3.4 "goID 缺省 = 写 gocbRef 内容（libiec 行为）"；§10.1 扩展"goose_goid 显式值"。
- **覆盖状态**：心跳用例隐含 goID=缺省=gocbRef（frames offset 83 29 段），但**无 goID 显式≠gocbRef 的正例**，也无 goID 省略/显式的对照断言。
- **修复建议**：补 `goose_goid_explicit`（goID 显式 "customGOID" → FrameAssert `83 05 63 75 73 74 6f 6d`）。

### COV-7（MINOR）：多帧变化（stNum 连续 +1 两次事件）无覆盖

- **位置**：design §4.4 变化规则；goose.json 各事件用例都是单次变化。
- **覆盖状态**：两次连续事件（stNum 1→2→3、sqNum 每次重置 0）无用例；这是 stNum 单调性的强化覆盖。
- **修复建议**：补 `goose_double_event`（event_seq 两事件 → stNum 1/2/3、sqNum 1 → 0..n → 0..m）。

### COV-8（MINOR）：multi-frame uint32 分片 long-form 大数据集无覆盖（可选增强）

- **位置**：design §2.5 "allData 大数据集（如 4000 条目）可用长形式"。
- **覆盖状态**：4000 条目（allData 内容 >127）的 BER 长形式 allData 长度段未覆盖（APDU 级 61 81 AD 已被 heartbeat 隐式覆盖，但 allData 内层 `ab 81 xx` 无显式用例）。
- **修复建议**：可选——大数据集用例锚 `ab 81 <L>`；文档阶段记录为可选增强。

### 覆盖结论

正向覆盖维度健全（心跳/重发/数据集变化/test/ndsCom/VLAN/多类型/多数据集/无 IP 十条 + 3 负例），原子颗粒度合规（每用例单行为，综合冒烟未替代原子覆盖）。缺口集中在：负例触发机制未定义（COV-1）、confRev 负例未落地（COV-3）、多流/多事件/Reserve1-sbit/goID 显式等扩展行为无锚（COV-4/5/6/7）。

---

## 3. 待实现边界清单（不阻断文档验收，记录供实现阶段接入）

1. **层注册/链规划**（design §5.2/§8.2 已自述）：`goose` 终结层注册进 registry（CategoryTerminal/DependsOn=nil）、`[{"eth":{}},{"goose":{}}]` 链规划、validate 拒绝 goose+ip/tcp/udp 共存（R-GOOSE 不支持）——当前仓库未接线，属实现阶段。
2. **VLAN 写头/组播 MAC 覆盖引擎钩子**（§8.3）：engine 对 GOOSE 禁用 IP-组播推导、恒组播不回落单播、VLAN 头插入——实现阶段接入。
3. **事件定时器/帧生成**（§8.4/§8.9）：Static 心跳 Ticker、EventSeq 退避序列、APDU BER 编码函数、取消路径排空——实现阶段。
4. **每帧墙钟 t（CP 8B）**（§8.5）：真实发送时刻写 0x84（非 Plan 覆写时间戳——mdns 同款陷阱），实现阶段验证。
5. **负例触发机制**（COV-1）：`sqnum_step`/`start_stnum` 校验线需要在实现阶段定义（当前文档未定义输入→错误映射，见 COV-1，属文档缺口需先补 §9）。

---

## 4. 与前期审查记录对照（任务给出的 8 条已知问题）

| 已知问题 | 状态 | 本报告对应 |
|----------|------|-----------|
| CRITICAL-1 frames 偏移全部错锚固定 22 | **未修复**，且根因更深（BER 长形式缺失，锁定为 CRITICAL-1 + CRITICAL-2） | §1 CRITICAL-1/2 |
| MAJOR-2 最小编码 vs 定长断言 | **未修复**（design §2.5 vs §3.6 vs §6.1 三处矛盾；JSON 已按最小编码，对） | §1 MAJOR-1.1 |
| MAJOR-3 重发帧数不一致 | **未修复，实际更严重**（新增 §6.2 S2 帧序图），本报告扩展为重发帧数超提供（1 心跳+5 重发+1 心跳=7 帧，JSON 需求 8 帧）；另有 JSON 内包 8 sqNum==6 与 notes 自述"6 快速重发"矛盾 | §对照表 |
| MAJOR-4 bit_string padding 计算错 | **部分修复**：JSON 已按 `(byteSize×8)−bitLength`（`84 02 00 fe`、`84 02 04 f0` 全对），design §6.5 模板仍错（`84 02 01 fe`） | §1 MAJOR-2（合并） |
| MAJOR-5 "无 IP"断言不可用 | **已修复**（字节级 12/22 + frame.protocols 存在性）；残留 VLAN 变体与全帧长度证据缺口 | §2 COV-2 |
| MAJOR-6 多实例字段 tshark 连排 | **已修复**（goose_multitype 用 nonzero + 逐字节 frames 兜底，notes 明示逗号连排） | （无 finding） |
| MINOR-7 CP8B 分数秒 | **未修复**（§8.5 "32768 = 0.5 秒"） | §1 MINOR-7 |
| MINOR-8 Length 公式缺 VLAN 分支 | **未修复**（§9.4 无 VLAN 分支；JSON notes 自己推导正确） | §1 MINOR-8 |

---

## 5. REPL 验证记录（审计可复现性）

```
gocbRef len=41 (0x29), datSet len=35 (0x23)
Heartbeat 最小编码 APDU content = 173；goosePdu = 61 81 AD（长形式，3B）；Length = 183；
帧总长 = 22 + 175 = 197B（含 60B pad 需补）
JSON 写 goose.length=184、notes "content 176 → 61 81 b0" → 两者均 +1 错
VLAN（1 成员）content = 160 → Length = 170 (0xAA) → JSON offset 20 "00 aa" 正确
multitype 成员和 = 47 = 0x2f → JSON "ab 2f" 正确；multidataset = 26 = 0x1a → JSON "ab 1a" 正确
design §6.5 S5：ab 21(33) vs 成员和 25 矛盾；87 04 vs §3.7 长度 5 矛盾；84 02 01 fe vs padding=0 矛盾
偏移核对：goosePdu 长形式驱动下，全部 12 用例 APDU 内 frames 偏移 JSON 值 = 正确值 - 1（40+ 断言）
```

---

## 6. 结论

- **文档阶段判定**：**文档矛盾（不通过）**——CRITICAL-1/2 使 goose.json 全部 APDU 内断言按错误偏移落地，必须重算（修复量小：统一 +1 + 长度值 183 + notes 数值），design §2.5/§6.1/§6.5 的矛盾模板必须与 §3.6 最小编码口径统一；修复后再进入实现阶段。
- **亮点**：标签表（§2.5）、Length 口径（§2.4/§3.1）、MMS Data 内部 tag（§3.6）、状态机（§4）、bit_string padding 与浮点（JSON 内）、双层断言策略（FrameAssert 兜底 + goose.* 可选）均已对齐 libiec61850/Wireshark 权威字节事实。
- **修复优先级**：CRITICAL-1/2（偏移+长度，全部 JSON 用例）→ MAJOR-1.1/1.2（design 编码口径统一）→ COV-1（负例触发机制补 §9）→ MAJOR-2（§6.5 模板）→ 其余 MINOR。

## 7. 修复状态（2026-08-19，commit `65639ae`）

| finding | 修复 | 状态 |
|---------|------|------|
| CRITICAL-1 BER 长形式偏移 | goose.json 全部 APDU 内偏移 +1；design §6.1 S1 `61 81 AD` 长形式 | ✅ 已修复 |
| CRITICAL-2 goose.length 184→183 | goose.json goose_heartbeat fields + notes | ✅ 已修复 |
| MAJOR-1.1 定长 4 矛盾 | design §2.5 表 stNum/sqNum/confRev 改为"最小编码" | ✅ 已修复 |
| MAJOR-1.2 S1 HexDump 偏移 | design §6.1 全段按最小编码+长形式重写 | ✅ 已修复 |
| MAJOR-2 S5 多类型矛盾 | design §6.5 `87 04`→`87 05`、`84 02 01 fe`→`84 02 00 fe`、`ab 21`→`ab 19`；testcase 同步 | ✅ 已修复 |
| MINOR-7 CP8B 32768→0x80000000 | design §8.5 | ✅ 已修复 |
| MINOR-8 Length 缺 VLAN 分支 | design §9.4 补 VLAN 分支 (len-18-8) | ✅ 已修复 |
| MINOR-3 8 成员→10 成员 | testcase §4.8/§8 | ✅ 已修复 |
| COV-1 负例触发机制 | design §9 需补 sql 步/起始越界校验线（记录为待实现边界） | ⏳ 待补 |
| COV-3 confRev 负例未落地 | testcase/JSON 三处缺 confRev 负例（记录为待实现边界） | ⏳ 待补 |

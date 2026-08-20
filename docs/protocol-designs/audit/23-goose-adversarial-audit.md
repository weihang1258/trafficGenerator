# GOOSE（IEC 61850-8-1，编号 23）三件套文档对抗审查报告

- 审查对象：
  - `docs/protocol-designs/23-goose-design.md`（设计）
  - `docs/protocol-designs/23-goose-testcase.md`（用例）
  - `trafficgen/test/protocol_pcap/cases/goose.json`（JSON 用例）
- 审查阶段：**文档阶段**（不审查 Go 代码实现/registry 注册/planner/builder/validator 是否存在）
- 审查日期：2026-08-19
- 审查者：对抗审查代理（goose-review）

---

## 结论摘要

三件套在 **BER 标签序、Length 口径、MMS Data 内部 tag、状态机语义、双断言策略（FrameAssert 兜底 + tshark goose.\* 可选）** 等主干上方向正确，且已修复前期已知问题中的多项（偏移逐字段累加不再锚固定 22、bit_string padding 公式正确、无 IP 字节级证明、VLAN 分支 Length 公式）。但存在 **1 个 CRITICAL（全部 JSON frames 偏移因 BER 长形式漏判系统性 +1 错位）、1 个 CRITICAL（design 多处定长 4 与最小编码矛盾）、以及多个 MAJOR（文档内部不一致、覆盖缺口、不可观测断言、负例机制未定义）**。

**结论：文档自洽性不通过，需修复后方可进入实现阶段。**

---

## 一、代码设计逻辑审查 findings（按 severity 排列）

### CRITICAL-1：JSON 全部 frames 偏移按"短形式长度"推导，但 APDU 内容实测 >127 字节必须长形式，所有 APDU 内偏移系统性 +1 错位

- **文件/位置**：`cases/goose.json` 全部 12 个用例的 frames offset（offset 22 之后的每一条）
- **问题**：BER 长形式判定规则是**长度值 >= 128 必须长形式**（`0x81 <len>` 两个字节）。本项目全部正向用例的 APDU 内容长（goosePdu 内字节数）均 >127：
  - heartbeat 173B、retransmit/dataset_change 161B、test_flag/ndscom_flag/vlan 160B、multitype 204B、multidataset 183B
- 因此 goosePdu 头必须是 `61 81 <len>`（3 字节），而 JSON 偏移从 `61@22 -> 80@24`（gap=2）的推导假定 `61 <len>`（2 字节短形式）。**两个推导相差 1 字节，所有 APDU 内字段（TAL/stNum/sqNum/.../allData 成员）的真实偏移 = JSON 偏移 + 1**。
- **证据**（逐字段累加，非估算）：
  - heartbeat：`61@22 81@23 ad@24 80@25 29@26 值[27..67] 81@68 ...`；JSON 断言 `81 02 01 f4 @67`（真实 @68）、`84 08 @151`（真实 @152）、`85..89 链 @161`（真实 @162）、`8a 01 03 ab 10 @176`（真实 @177）、成员 `85 02 04 d2 @181`（真实 @182）
  - 同笔记自相矛盾：notes 声称 `61 81 b0`（长形式）却用短形式地址定位 `80@24`（长形式应为 `80@25`）；且内容长 0xb0=176 != 实测 173=0xad，差值恰好是"goID 43 字节"与"全字段累加"口径差。
- **与规范矛盾**：IEC 61850-8-1 / BER X.690 8.1.3.5 长形式长度编码。libiec61850 与 Wireshark 均输出/解析长形式。
- **修复建议**：
  1. 以"61 81 <len>（3 字节）"为基线重新**逐字段累加**全部 frames offset（每个用例的 private note 应附完整 offset 推导表）；
  2. 修正 heartbeat note 中 `61 81 b0 -> 61 81 ad`（0xad=173）；
  3. testcase 4.1-4.10 同步（特别是 4.2 的 `10 00 <LENhi><LENlo> 00 00 00 00` 需补具体 Length 值）。

### CRITICAL-2：design 多处 stNum/sqNum/confRev 写"定长 4 字节"与最小编码（compressInteger）矛盾；JSON 已按最小编码但 design/testcase 文本未收口

- **文件/位置**：`23-goose-design.md` 2.5（`0x85 stNum INTEGER 定长 4`、`0x86 sqNum 定长 4`、`0x88 confRev 定长 4`）、3.1 布局表（`85 04 <4B>`、`86 04 <4B>`、`88 04 <4B>`）、3.4（`stNum 4 字节最小`）、6.1 S1（`85 04 00 00 00 01`、`86 04 00 00 00 01`、`88 04 00 00 00 01`）；`cases/goose.json` 各用例写 `85 01 01`/`86 01 01`/`88 01 01`（最小编码 1 字节）；testcase 4.4 /\*9.2 写 `86 04 00 00 00 00`（定长 4）。
- **问题**：同文档三处对同一字段给出"定长 4 字节"与"最小编码（1-8 字节）"两种互相矛盾的定义。libiec61850 `ber_encoder.c` 的 `compressInteger` 是最小编码（值 1 -> 1 字节 `01`），JSON 已忠实按最小编码；design 的 S 场景字节模板、2.5/3.1 标注、testcase 4.4/9.2 的 `86 04 00 00 00 00`（定长 4，错的）互相打架——前期 MAJOR-2（最小编码 vs 定长断言）只在 JSON 修了，design/testcase 文本未收口。
- **与规范矛盾**：BER 最小编码为强制（X.690 8.1.3.3 / libiec61850 `compressInteger`）。
- **修复建议**：design 2.5/3.1/3.4/6.1 S1 统一为"最小编码（示例值 1 -> `85 01 01`）"，删除"定长 4"字样；testcase 4.4/5.4/9.2 的 `86 04 00 00 00 00` 改为 `86 01 00`；在 design 2.5 显式写「测试断言以最小编码为准（libiec `compressInteger`），无定长 4」。
- **连带影响**：CRITICAL-1 的偏移累加依赖本项口径统一（长度字节数随编码变化），两处必须一起修、一起复核。

### MAJOR-3：design 6.5/6.7 浮点字节模板错误（`87 04` + 4 字节）与 design 3.7/JSON 的 IEC 61850 浮点（`87 05 08` + 4 尾数字节，共 7 字节）直接矛盾

- **文件/位置**：`23-goose-design.md` 6.5 S5（`87 04 <xx xx xx xx>`）、6.7 S7（`87 04 <5 字节>`——标签+长度+x 共矛盾）；对照 3.7（`0x87 0x04 -- tag + 长度=5（格式宽 32 位：1 指数宽 + 4 尾数宽）`）与 `cases/goose.json` multitype/multidataset（`87 05 08`，字段 7 字节）。
- **问题**：IEC 61850 二进制浮点（FLOAT32）的**长度字段 = 1 + format_width/8 = 1 + 4 = 5**（不是 4），值 = 1 个指数宽字节（0x08）+ 4 尾数字节，整字段 7 字节。6.5/6.7 的 `87 04 <xx...>` 与自身 3.7 及 JSON 不一致。6.7 行 `87 04 <5 字节>` 更是 tag+len 与内容字节数自相矛盾。
- **修复建议**：6.5 改 `87 05 08 <4 尾数字节>` 并重算 `ab <L>` 与 S6 场景内容长；6.7 同改；testcase 4.8 同步（其 frames 描述 `87 04 <5 字节>` 已与 JSON `87 05 08` 不一致）。

### MAJOR-4：design 6.1"心跳首帧"偏移序与 3.1 布局表对 t/stNum 的相对位置描述不一致，且 sqNum 起点（初始化 1 vs 事件重置 0）在 6.1 未显式收敛

- **文件/位置**：`23-goose-design.md` 6.1 第 7 行 `-> 84 08 t(8B) -> 85 04 stNum`；3.1 布局表 `84 08 <8B> t -> 85 04 <4B> stNum`；4.1 表（初始化 sqNum=1）；4.4 表（事件变化 stNum+1、sqNum=0）。
- **问题**：文本顺序正确，但 6.1 用 `->` 省略式描述且未给偏移，加上长度字节数（4 vs 最小 1，见 CRITICAL-2）不一，无法作为实现/断言基线。4.1 初始化规则明确 `sqNum=1` 与 4.4 表 `sqNum 置 0`（事件后）顺序一致，但 6.1 与 6.2 都没有给出"变化前心跳帧 sqNum 到底从 1 还是 0 开始"的显式收敛（JSON 从 1 起，测试锁 1）。
- **修复建议**：6.1 补全偏移推导（配合 CRITICAL-2 的最小编码口径）并显式写「心跳/首帧 sqNum 从 1 起（4.1 初始化规则），事件帧 sqNum=0」，消除实现歧义。

### MAJOR-5：testcase 4.4 定长 4 字节断言 `86 04 00 00 00 00` 与 JSON `86 01 00`（最小编码）矛盾

- **文件/位置**：`23-goose-testcase.md` 4.4（frames `86 04 00 00 00 00`）、9.2 回归棋盘 `86 04 00000000`；`cases/goose.json` goose_dataset_change frames `86 01 00`；design 2.5/3.4 最小编码。
- **问题**：这是 CRITICAL-2 在 testcase 侧的残留（前期 MAJOR-2 未完全修复）。`86 01 00`（sqNum=0 -> 最小 1 字节）才是对的；`86 04 00 00 00 00` 若实现按最小编码必挂。
- **修复建议**：testcase 4.4、5.4、9.2 全文将 `86 04 00 00 00 00` 改为 `86 01 00`。

### MAJOR-6：`goose.length` 断言值 184 与 notes 中 `61 81 b0`（内容 176B）自相矛盾

- **文件/位置**：`cases/goose.json` heartbeat fields `{"field":"goose.length","value":"184"}` + notes `61 81 b0`。
- **问题**：184 = 8 + 176 => APDU 总长 176 = `61 81 <173> + 173` => 内容长 **173**（0x**ad**），notes 写 0xb0（176）是错的——0xb0 是 APDU 总长与内容长混用了。且 testcase 8 表 `heartbeat ... Length 精确（8+APDU）` 无具体值，无法兜底任何一方。
- **修复建议**：notes 改 `61 81 ad`；并把"内容长 173 = 逐字段累加值"的推导表写进 notes 作为证据。

### MINOR-7：design 2.5 表对 `numDatSetEntries`（0x8A）标"2-4 字节大端"、3.1 `<2-4 字节>`，与全文档最小编码口径矛盾（值 3 -> 1 字节 `03`）

- **文件/位置**：`23-goose-design.md` 2.5、3.1、3.4（`>=2 字节`）；JSON 各用例 `8a 01 03/01/0a/06`（1 字节）。
- **问题**：n<=127 时最小编码 1 字节；标注"2-4 字节"会误导实现写成固定 2 字节（值 3 -> `00 03`），与 JSON/规范不符。
- **修复建议**：统一为"最小编码 1 字节（值 <=127）"。

### MINOR-8：CP 8B 分数秒说明与 2.5/8.5 描述自洽，但 design 3.1 未写 t 字节序（大端）；testcase 6.2 已正确写「只对标签+长度」

- **位置**：`23-goose-design.md` 3.1/3.4。
- **问题**：`t`（0x84）的 8 字节内容字节序只在 8.5 出现（秒 4B + 分数秒 4B，单位 2^-32 秒/32768=0.5s 等细节只在 8.5），3 系列无引用；虽不影响 testcase（不定值断言），但对实现编码器（ber.go）是唯一依据。
- **修复建议**：2.5 表 t 行补字节序说明与 8.5 引用。

### MINOR-9：design 2.3 断言 `frame.protocols 含 goose` 与 testcase 6.6/8.3 及 JSON 如实承认的环境依赖（无解析器时为 eth:data）不一致

- **文件/位置**：`23-goose-design.md` 2.3（"EtherType 0x88B8 时 Wireshark 试用 goose 解析器，frame.protocols 含 goose"）、6.6（`frame.protocols == "eth:goose"`）。
- **问题**：design 6.6 把 `frame.protocols == "eth:goose"` 列为断言点（无解析器环境必挂）。JSON `goose_no_ip` 已正确改为只断言 `frame.protocols` 存在性 + 字节级 `88 b8`/`61`。design 文本与 JSON 的兜底策略不一致（JSON 对，design 旧）。
- **修复建议**：design 6.6 改与 JSON 相同口径：「`frame.protocols` 存在性（取值环境相关）+ offset 12 `88 b8` + offset 22 `61` 字节证据」，删除对 `"eth:goose"` 精确值的依赖。

---

## 二、用例覆盖审查 findings

### MAJOR-A：正向用例从未证明**数据集内容值变化**（allData 字节差异）——事件用例只是状态机计数变化

- **位置**：`cases/goose.json` goose_retransmit（单成员 int32 1234，`data_idx:0`）、goose_dataset_change（同）；design 6.2 场景（内容 1234->5678）。
- **问题**：design S2 的规范场景是"数据集内容变化（pos 1234->5678）-> stNum+1/sqNum=0"，但 JSON 两个事件用例的数据集都只有 **1 个成员且 data_idx=0 指向唯一成员**——事件前后 allData **字节完全一致**，只证明 stNum/sqNum 状态机变化，**没有任何用例证明内容实际变化时 allData 字节随事件改变**（实现把事件静默成无内容变化也能过）。GooseEvent.DataIdx 的"切换到 Data[DataIdx] 新值"语义（design 5.1）完全未覆盖。
- **与 spec 矛盾**：design 4.1/6.2/8.4 均以"数据集内容变化"为事件触发条件；testcase 7 勾选"数据集变化"但断言全在 sqNum/stNum。
- **修复建议**：新增原子用例 `goose_event_content_change`：双成员或成员值变化（如 data 含两组值或 EventSeq 带 `value` 覆盖），packet 2 之后 allData 段 hex 与 packet 1 **不同**（`85 02 04 d2` -> `85 02 16 2e`），同时 stNum+1/sqNum=0；并给 GooseEvent/配置键补"变化目标值"的显式机制（见 NEG-M）。

### MAJOR-B：负例机制不可构造（`sqnum_step` / stNum 回绕注入无配置钩子）——3 个 NEG 用例在配置层不可实现

- **位置**：`cases/goose.json` goose_neg_sqnum（`event_seq[].sqnum_step`）、goose_neg_stnum（`start_stnum`）；design 5.1 `GooseConfig`/`GooseEvent` 无 `sqnum_step`、无"注入非法序列"字段；design 9.1 只描述"拒绝/终止"不给出测试如何注入。
- **问题**：
  1. `sqnum_step` 字段**在任何文档（design/testcase）中都没有定义**——JSON 凭空引入；design 9.1 也无"非连续序列如何配置"。testcase 5.2 说"框架注入...跳号"但框架（pcap 框架）没有损坏生成器字节的能力。三件套对"非法序列如何产生"没有一致契约。
  2. `start_stnum: 4294967295`（0xFFFFFFFF）可被（也应当被）**起始值合法校验**以 `stNum` 报错——这能作为校验负例，但 design 5.1 注释是"必须小于 0xFFFFFFFF，禁止从上限触发回绕"，9.1 的负例语义是"生成器产出回绕 stNum"（运行期），两处语义不一：JSON 用起始值触发（构造可行），9.1 描述的是运行期回绕（构造不可行）。需明确负例到底测"校验"还是"运行期守卫"，并统一配置键。
- **修复建议**：design 5.1 增加显式**注入钩子**（如 `GooseEvent.SqNumStep`、或"负例专用 debug 字段"统一命名），三件套统一；9.1 改写为"校验时注入起点（StartStNum >= 0xFFFFFFFF 拒绝）+ 运行期守卫（超出 0xFFFFFFFF 拒绝）"两层；testcase 5.2/5.3 同步。

### MAJOR-C：design 9.3 引用不存在的用例 `goose_neg_confrev`

- **位置**：`23-goose-design.md` 9.3（"testcase 用 `goose_neg_confrev` 断言 error_contains confRev"）。
- **问题**：testcase 3.1/5 只有 NEG-01..03（appid/sqnum/stnum）；JSON 12 个用例无 `goose_neg_confrev`。confRev < 1 校验负例**无任何用例**（覆盖缺口 + 悬空引用）。
- **修复建议**：新增 `goose_neg_confrev`（`conf_rev:0` -> expect_error + error_contains "confRev"），或删除 design 9.3 的引用并显式记录"该负例待实现阶段补齐"。

### MAJOR-D：testcase 4.8/8 声称 multitype "data 8 成员"，实际列了 10；JSON 按 10（numDatSetEntries=10）——文档内部数量矛盾

- **位置**：`23-goose-testcase.md` 4.8 配置段（"data 8 成员：boolx2/int32x2/uint32/float32/bit_stringx2/visible_stringx2"）、8 表（"data 8 成员"）；`cases/goose.json` goose_multitype（10 成员）。
- **问题**：清单里合计是 10 个成员（2+2+1+1+2+2=10），文本写 8；7 勾选"各类型 >1"按 10 理解才成立。与 JSON 的 `10` 不一致。
- **修复建议**：统一为 10 成员。

### MAJOR-E：多流/多组播（不同 goID/MAC/APPID）无任何用例

- **位置**：cases/goose.json 全 12 例。
- **问题**：审查口径明确要求"多流：多组播流，不同 goID/MAC/AppID"。design 4.7 有"多 GOOSE 任务并行（各自独立定时器/stNum/sqNum）"，但无对应用例；JSON 所有用例 src_mac 都是 `aa:bb:cc:dd:ee:01`、dst_mac 都是 `01:0c:cd:01:02:03`、appid 0x1000、goID 全部缺省=gocbRef。没有任何用例证明：不同 goID/APPID/MAC 的两条流互不干扰、各自 stNum/sqNum 独立递增。
- **修复建议**：新增 `goose_multiflow`：两条 GOOSE 流（不同 dst_mac/appid 或 goID），断言各自 goID/MAC/APPID 与独立的 stNum/sqNum 序列。

### MAJOR-F：testcase 4.1-4.10 的期望全是"if 可用"（goose.\* 字段），frames 兜底只给了标签不含具体偏移，无法独立复核 JSON 是否正确

- **位置**：`23-goose-testcase.md` 4.1（fields goose.\* 可用时 + frames"用长 hex 片段覆盖"）、4.2（frames `10 00 <LENhi><LENlo> 00 00 00 00`——未给 LEN 值）、4.7（"offset 26 起 `61`"）。
- **问题**：testcase 作为 JSON 的唯一真源（8 说"此文档与 JSON 严格一致"），其 frames 示例要么不给具体偏移（4.1"用长 hex 片段"）、要么不给 Length 具体值（4.2 的 `<LENhi><LENlo>` 占位）、要么单字段（4.7 只给 `61`）——**无法从 testcase 推导/复核 JSON 的数字**。CRITICAL-1 的偏移错位之所以能溜进 JSON，正是因为 testcase 没锁数字。8 表的"一致"是纸面宣称，无逐用例字节对照。
- **修复建议**：testcase 每例补"frames 断言表"（offset + hex + 逐一累加说明），其数字与 JSON 完全一致（修完 CRITICAL-1 后粘同一套数字），并把 8 的一致性表扩为"逐条 frames 对照"。

### MAJOR-G：负路径覆盖面过窄——实际可稳定构造的负例只有 appid/stnum/confRev 三个**起始值校验**类

- **位置**：design 9.1-9.7 错误表（>=12 行） vs JSON NEG-01..03。
- **问题**：9.4（Length!=8+APDU）、9.5（numDatSetEntries!=成员数）、9.6（TMax>=t0 / TMax<1ms / t0<1ms）、9.7（不支持类型）等 7 行**没有任何用例**。其中 9.6 的 TMax>=t0 clamp、t0<1ms 拒绝、9.7 的非法 data type 是"配置校验类"，在文档阶段本可给出 `goose_neg_*` 用例（expect_error + error_contains），全缺。
- **修复建议**：至少补 `goose_neg_confrev`（见 MAJOR-C）、`goose_neg_t0`（t0_ms:0）、`goose_neg_type`（data[].type:"int16" 之类矩阵外类型）；9.4/9.5 的运行期守卫负例标注"待实现阶段（须能注入坏编码）"。

### MINOR-H：testcase 6.3 调试命令 `-e goose.test_links` 字段名不实（Wireshark dfref 无此字段，应为 `goose.test`/`goose.simulation`）

- **位置**：`23-goose-testcase.md` 6.3（`-e goose.test_links`）。
- **问题**：goose 解析器无 `goose.test_links` 字段（dfref 里 test 显示为 `goose.simulation`）；命令会输出空列，误导调试。
- **修复建议**：改为 `-e goose.test -e goose.simulation`（或删该列）。

---

## 三、待实现边界清单

以下不阻断文档验收，但必须作为实现契约写入对应文档：

1. **goosePdu BER 长形式长度**：全部用例 APDU 内容 >127B => 实现必产 `61 81 <len>`；CRITICAL-1 修复后的 JSON 偏移以其为基线。若实现选择**裁剪 APDU 使其 <128B（用短 goID/短引用）** 的替代路径，则需重新推导全部偏移——文档应显式声明"v1 基线 = 长形式"。
2. **最小编码实现**：stNum/sqNum/confRev/TAL/numDatSetEntries 必须走 `compressInteger`（libiec61850 ber_encoder）；若实现内部"定长 4 再压缩"需在层生成器完成压缩，否则线上字节不符。JSON 已锁 `85 01 01` 等最小编码断言。
3. **负例注入机制**（MAJOR-B/G）：`sqnum_step`/stNum 回绕注入目前无配置载体。需在实现阶段给 `GooseEvent`/validator 增加显式注入键（并回填 design 5.1 + testcase 5 + JSON 同步）。
4. **事件内容变化的 DataIdx 语义**（MAJOR-A）：`data_idx` 指向的"新值"如何表达——需实现阶段定义（如 data 里放两套值、data_idx 选其一），当前测试无法证明内容字节变化。
5. **VLAN 模式断言**（CRITICAL-1 连带）：VLAN 用例 APDU 偏移 = 非 VLAN 偏移 +4，修复后需按长形式重新验证（`00 aa`->`00 ab` 等 Length 值变化）。
6. **多流并行**（MAJOR-E）：实现阶段需支持同一任务/多任务产出多组播流，任务级计数隔离（design 4.7）才有测试基础。
7. **goose 解析器版本差异**：JSON notes 已按 tshark 3.6.14 校准（FT_BOOLEAN 打印 0/1）；实现阶段回归需在"有/无 goose 解析器"两环境同时绿（testcase 9.3 已声明，JSON `goose_no_ip` 的 frame.protocols 存在性断言已兼容）。
8. **tshark 字段名差异**：`goose.timeAllowedtoLive`（大小写 L）在 dfref 大小写敏感，实现期复核一次。

---

## 四、前期已知问题复核结果

| 前期编号 | 内容 | 现状 | 结论 |
|----------|------|------|------|
| CRITICAL-1 | frames 偏移全锚固定 22 | 已改为逐字段累加（但**长形式漏判，整体 +1**） | **未修复（残留为 CRITICAL-1）** |
| MAJOR-2 | 最小编码 vs 定长断言 | JSON 已用最小编码；design 2.5/3.1/6.1 与 testcase 4.4/9.2 仍写定长 4 | **未完全修复（残留为 CRITICAL-2/MAJOR-5）** |
| MAJOR-3 | 重发帧数不一致 | S2 帧序（1 心跳 + 事件 + 5 重发 + 心跳）与 JSON `count:8`、sqNum 0..6 一致 | **已修复** |
| MAJOR-4 | bit_string padding 计算错 | design 2.5/6.5（padding=(byteSizex8)-bitLength）、JSON multitype notes（`84 02 00 fe` padding=0、`84 02 04 f0` padding=4 左对齐）正确 | **已修复** |
| MAJOR-5 | "无 IP"断言不可用 | JSON 已改字节级（offset 12 `88 b8` + offset 22 `61`）+ frame.protocols 存在性；design 6.6 文本仍写 `frame.protocols=="eth:goose"` | **部分修复（design 6.6 残留，见 MINOR-9）** |
| MAJOR-6 | 多实例字段 tshark 连排 | JSON multitype notes 已处理：`goose.boolean/integer` 用 nonzero 存在性、字节精确靠 frames | **已修复** |
| MINOR-7 | CP8B 分数秒时间 | 不定值断言 + `84 08` 标签锁 + 8.5 编码说明；testcase 1.3/6.2 一致 | **已修复** |
| MINOR-8 | Length 公式缺 VLAN 分支 | JSON vlan notes 有（**但以旧 APDU=162 短形式口径，修 CRITICAL-1 后该数字需重算**） | **部分修复（待 CRITICAL-1 联动）** |

---

## 五、修复优先级建议

1. **P0（CRITICAL）**：CRITICAL-1（JSON 全偏移 +1 重推）、CRITICAL-2（design/testcase 定长 4 统一为最小编码）——两者耦合，必须先定"长形式 + 最小编码"基线再逐用例重算，JSON 与 testcase 4/8、design 6 同步。
2. **P1（MAJOR）**：MAJOR-A（新增内容值变化原子用例）、MAJOR-B/G（负例机制定义 + 补 confRev/t0/type 负例）、MAJOR-C（goose_neg_confrev）、MAJOR-D（8->10 成员）、MAJOR-E（多流用例）、MAJOR-F（testcase 锁数字与 JSON 一致）。
3. **P2（MINOR）**：MINOR-7（num 长度标注）、MINOR-8（t 字节序）、MINOR-9（design 6.6 口径）、MINOR-H（tshark 命令字段）。

---

## 六、附：复算工作表（修复基线）

- 通用前导字段（含 goID=gocbRef、TAL=500、datSet、confRev=1、test/ndsCom=false、8 字节 t）：**152 字节**（逐字段：80 29+41、81 02+2、82 23+35、83 29+41、84 08+8、85 01+1、86 01+1、87 01+1、88 01+1、89 01+1）
- numDatSetEntries：`8a 01 <n>`（3 字节，n<=127）
- allData：`ab <len>` + 成员（heartbeat `10`+16、单成员 `03/04`+3/4、multitype 内容 47B=`2f`、multidataset 内容 26B=`1a`）
- 各用例 APDU 内容（goosePdu 内）：heartbeat **173（0xad）**、retransmit/dataset_change **161（0xa1）**、test/ndscom/vlan **160（0xa0）**、multitype **204（0xcc）**、multidataset **183（0xb7）**
- goosePdu 长形式头：`61 81 <len>`（3 字节）=> APDU 总长 = 3+内容；Length = 8 + APDU 总长
- 关键 Length 值（修正后）：heartbeat 184（0x00b8）、vlan 171（0x00ab）、test/ndscom 171、multitype 215（0x00d7）、multidataset 194（0x00c2）
- 修正后关键偏移（heartbeat，no-VLAN）：61@22 | 81@23 | ad@24 | 80@25 | 29@26 | 值[27..67] | 81@68（TAL）| 82@72 | 83@109 | 84@152 | 85@162 | 86@165 | 87@168 | 88@171 | 89@174 | 8a@177 | ab@180 | 成员 85 02 04 d2@182 | 8c 06@186 | 85 02 16 2e@194

> 本报告所有复算均以 IEC 61850-8-1 / X.690 BER（长形式 + compressInteger 最小编码）为基线，独立完成，非转录现有文档数字。
## 七、修复状态（2026-08-20，commit `c250ad4`）

| finding | 修复 | 状态 |
|---|---|---|
| BER 长形式与整体偏移口径 | design/testcase 明确 `61 81 <len>`，heartbeat/VLAN Length 与关键 offset 同步；JSON 已逐字段使用长形式基线 | ✅ 已修复 |
| 最小 BER 整数与定长 4 矛盾 | design 组合表、testcase S1/S2 明确最小编码；sqNum=0 改 `86 01 00` | ✅ 已修复 |
| GOOSE Length VLAN 分支 | VLAN 用例改 `00 ab`=171，并写出 frame-length 公式 | ✅ 已修复 |
| no-IP 断言不可观察 | design/testcase 改为 EtherType + APDU 字节证据，解析器字符串仅辅助 | ✅ 已修复 |
| tshark 调试字段名 | `goose.test_links` 改为 `goose.test`/`goose.simulation` | ✅ 已修复 |
| 负例注入载体、多流、事件内容变化 | 仍依赖未来 validator/planner 契约，已列入待实现边界 | ⏳ 待实现边界 |

本次修复后，GOOSE 文档仍不宣称 Go 运行期通过；未注册层、生成器和真实 pcap/NIC 回归属于后续实现阶段。

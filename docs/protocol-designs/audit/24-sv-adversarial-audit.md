# IEC 61850-9-2 SV（Sampled Values，采样值）双视角对抗审查报告

> 审查日期：2026-08-19
> 审查范围：`24-sv-design.md`、`24-sv-testcase.md`、`trafficgen/test/protocol_pcap/cases/sv.json`
> 审查口径：文档阶段审查，审查对象是 design/testcase/cases 三件套的质量与自洽性。是否存在 Go 代码实现、layer 是否注册、planner/builder/validator 是否存在，属于后续实现阶段，不作为文档阶段验收缺陷。字段布局、wire 契约、断言可观察性、原子覆盖类 findings 属文档缺陷，须在文档阶段修复。

---

## 1. 代码设计逻辑审查 findings

### CRITICAL-1：sv_smp_seq 的 sv.length 字段断言值与 hex 自相矛盾

**文件**：`sv.json` sv_smp_seq expect.fields

**问题描述**：
- 字段断言 `{"packet": 1, "field": "sv.length", "value": "106"}`
- 同用例 FrameAssert `{"packet": 1, "offset": 14, "hex": "40 00 00 70 00 00 00 00"}`
- hex 中 `00 70` = 0x0070 = 112 十进制

**证据**：JSON 使用 10 字节 svID "xxxxMUnn01"，比 design §6.1 模板的 4 字节 svID "SV01" 多 6 字节。APDU 计算：
- ASDU 内容 = svID(12B) + smpCnt(4B) + confRev(6B) + smpSynch(3B) + smpRate(4B) + seqData(66B) = **95 字节**
- ASDU = `30 5f`(2) + 95 = 97 字节
- seqASDU = `a2 61`(2) + 97 = 99 字节
- noASDU = `80 01 01`(3) 字节
- savPdu 内容 = 3 + 99 = 102 字节
- savPdu = `60 66`(2) + 102 = **104 字节**
- SV Length = 8 + 104 = **112 = 0x70**

字段断言值 106 是 design §6.1 模板(4B svID)的 Length 值（8 + 98 = 106），但 JSON 实际使用 10B svID，故应为 112。

**修复建议**：将 `"value": "106"` 改为 `"value": "112"`。

---

### CRITICAL-2：sv_4i4v frames offset 56 应为 60（smpRate 存在导致 seqData 偏移计算错误）

**文件**：`sv.json` sv_4i4v expect.frames

**问题描述**：`{"packet": 1, "offset": 56, "hex": "87 40"}` 断言 seqData tag 在偏移 56，但该用例配置了 `smp_rate: 4000`，smpRate 字段(Tag 0x86)占用 4 字节(86 02 0f a0)，将 seqData 推到偏移 60。

**证据**：sv_smp_seq 同配置(10B svID + smpRate)的正确偏移链：
- smpCnt@43 `82 02 00 00`(4B)
- confRev@47 `83 04 00 00 00 01`(6B)
- smpSynch@53 `85 01 02`(3B)
- smpRate@56 `86 02 0f a0`(4B)
- seqData@60 `87 40`(2B)
- data@62

sv_4i4v 的 note 也自相矛盾：`"seqData tag@56, data@62..125"` — 若 seqData tag 在 56，data 应在 58，不是 62。

**修复建议**：将 offset 56 改为 offset 60。`"offset": 56, "hex": "87 40"` → `"offset": 60, "hex": "87 40"`。同时更新 note 中 `"seqData tag@56"` → `"seqData tag@60"`。

---

### CRITICAL-3：sv_double_send 的 savPdu 长度断言复制了设计模板值（1 通道 seqData 8B 不能用 60 60）

**文件**：`sv.json` sv_double_send expect.frames

**问题描述**：`{"packet": 1, "offset": 22, "hex": "60 60"}` 和 packet 2 相同断言。`60 60` 表示 savPdu 内容长度 0x60 = 96 字节，但该用例只有 1 通道 (I_A, int32, with quality)，seqData = 8 字节。

**证据**：1 通道 + 10B svID + smpRate 的核算：
- ASDU 内容 = svID(12) + smpCnt(4) + confRev(6) + smpSynch(3) + smpRate(4) + seqData(2+8=10) = **39 字节**
- ASDU = `30 27`(2) + 39 = 41 字节
- seqASDU = `a2 29`(2) + 41 = 43 字节
- noASDU = `80 01 01`(3) 字节
- savPdu 内容 = 3 + 43 = **46 字节**
- savPdu = `60 2e`(2) + 46 = 48 字节 (0x2e = 46)

`60 60` 是 8 通道 64B seqData 时的值(96 字节内容)，在此处复制错误。

**修复建议**：将 `"60 60"` 改为 `"60 2e"`。同时建议在 frames 中断言更多字节（如 `60 2e 80 01 01 a2 29 30 27`），以证明整个 BER 结构正确。

---

### MAJOR-4：sv_smp_seq 的 note 中帧长核算错误

**文件**：`sv.json` sv_smp_seq expect.notes

**问题描述**：note 原文 `"frame = 14 eth + 8 SV hdr + 106 APDU = 128B"` 与同 note 后面的 `"8 + 104 = 112 = 0x70"` 矛盾。

**证据**：10B svID 的 savPdu 总长 = 104 字节（CRITICAL-1 核算），帧总长 = 14 + 8 + 104 = **126 字节**，不是 128。"106 APDU" 也是错的——106 是 4B svID 模板的 SV Length 值，不是 APDU 长度。

**修复建议**：将 `"frame = 14 eth + 8 SV hdr + 106 APDU = 128B"` 改为 `"frame = 14 eth + 8 SV hdr + 104 APDU = 126B"`。

---

### MAJOR-5：sv_double_send 断言不足以证明"两帧字节完全相同"

**文件**：`sv.json` sv_double_send expect.frames

**问题描述**：设计 §4.6/§6.2 要求"两帧除帧序号（frame.number）外按原始字节完全相同"。但断言仅检查 offset 22 的 2 字节 `60 2e`（修复后），不足以证明整个帧（约 70 字节）相同。

**证据**：两帧可能 savPdu tag 相同但其他字段不同（如不同的 smpCnt 值，或不同的时间戳）。只用 2 字节断言无法排除这些差异。

**修复建议**：增加更多帧级别的 FrameAssert 覆盖，如：
- offset 0 hex `01 0c cd 04 00 01`（目的 MAC）
- offset 14 hex `40 00 00 38 00 00 00 00`（SV 头 8 字节）
- offset 22 完整 APDU 前 24 字节

或者添加 note 说明框架对帧级全等判定的当前限制，并记录单测覆盖。

---

### MAJOR-6：design §9.3 APPID 越界仅"警告"而非"拒绝"的矛盾

**文件**：`24-sv-design.md` §9.3

**问题描述**：APPID 0x0000-0x3FFF 的行描述为"GOOSE 保留段，显式配置时**警告**"，但同行的测试映射 `T-SV-NEG-02` 期望 `expect_error: true`（任务失败拒绝）。如果校验器只给警告，任务不会失败，测试将挂。

**证据**：sv_neg_appid 用例 `expect_error: true` + `error_contains: "appid"`。若设计说"警告"而非"拒绝"，该负例无法通过。

**修复建议**：将 §9.3 表中"警告"改为"拒绝（expect_error）"，与测试用例一致。或明确区分：0x3FFF 以下拒绝、0x8000-0xFFFF 仅警告，并在测试中对应。

---

### MAJOR-7：sv_neg_appid 的 appid 值与设计说明不一致

**文件**：`sv.json` sv_neg_appid spec_json / `24-sv-design.md` §9.3

**问题描述**：设计 §9.3 说"负例故意选 0x3999 落于 GOOSE 段以证明校验器区分段位"。sv_neg_appid 的 appid=14745=0x3999，正确。但设计 §2.4 的 APPID 分配表说"0x0000-0x3FFF：保留给 GOOSE"，而 sv_neg_appid 断言 `error_contains: "appid"`，未指定错误消息应提及 GOOSE 保留段或段位校验。

**修复建议**：在 sv_neg_appid 的 notes 中增加期望错误消息模板，如 `"appid 0x3999 is in the GOOSE-reserved range (0x0000-0x3FFF)"`，以指导 validator 实现。

---

### MINOR-8：sv_period 的时序断言完全依赖框架能力，无兜底

**文件**：`sv.json` sv_period expect

**问题描述**：`sv_period` 用例期望 `min_packets: 100` 但无任何时序断言。notes 说"若框架不支持时间字段，降级为 min_packets + 手工抽检"，但 min_packets 只证明发了 100 帧，不证明帧间隔是 250µs。如果发送器把所有帧一次性突发发出，min_packets 仍过。

**修复建议**：增加单测覆盖（ticker 间隔 == Period），并在 pcap 用例中添加 `frame.time_delta` 字段断言（若框架支持）。若框架不支持，notes 应明确记录"时序断言缺口：需单测或手工 tshark 验证"。

---

## 2. 用例覆盖审查 findings

### COVERAGE-1：confRev 变化场景无独立用例

**依据**：设计 §4.5 描述 confRev 变化行为（reconfigure -> confRev+1，smpCnt 连续递增）

**问题**：testcase 清单中没有 confRev 变化的独立用例。sv_smp_seq 仅断言 confRev 恒为 1。设计 §4.5 的"两阶段 confRev=1→confRev=2"未在 cases 中体现。

**修复建议**：新增 sv_confrev_change 用例，两阶段 config 或两个独立任务，分别断言 confRev=1 和 confRev=2，且 smpCnt 跨段连续（或记录为框架限制："两阶段需 engine 续帧支持"）。

---

### COVERAGE-2：smpSynch 三值枚举（0/1/2）未覆盖

**依据**：设计 §4.4/§6.10 定义了 smpSynch=0(未同步)、1(本地)、2(全局)三个值

**问题**：sv_smp_synch_global 只覆盖了 smpSynch=2。smpSynch=0 和 smpSynch=1 没有独立用例。testcase 文档提及 T-SV-S10-01 但未在 JSON 中实现。

**修复建议**：新增 sv_smp_synch_local（smpSynch=1）和 sv_smp_synch_nosync（smpSynch=0）两个正例，或一个枚举三值用例。每个断言对应帧的 `sv.smpSynch` 字段值精确对。

---

### COVERAGE-3：多流（多组播流）无覆盖

**依据**：设计 §1.1 和多流场景

**问题**：所有用例都是单流（单 svID/APPID/MAC）。设计 §4.11 描述"多 SV 任务并行：各自独立定时器 + 独立 smpCnt/confRev"，但无测试验证。

**修复建议**：新增 sv_multi_stream 用例，两条独立 SV 流（不同 dst_mac/APPID/svID），断言各自 smpCnt 独立递增、互不干扰。

---

### COVERAGE-4：refrTm（可选字段）无覆盖

**依据**：设计 §2.5 表列出 refrTm=0x84 可选

**问题**：sv_custom_dataset 测试了 smpRate 省略（可选字段不编码），但 refrTm 作为可选字段完全没有被覆盖——既没有"refrTm 编码"的正例，也没有"refrTm 省略"的证明。

**修复建议**：新增 sv_refrtm 用例，配置 refrTm 为某已知值，断言 `sv.refrTm` 字段存在且值正确。或者扩展 sv_custom_dataset 的 notes 说明 refrTm 省略是可验证的。

---

### COVERAGE-5：smpCnt 非零起始无覆盖

**依据**：设计 §10 扩展字段中提及 `sv_smpcnt_offset`

**问题**：所有用例 smpCnt 均从 0 起始。无用例验证 smpCnt 从非零值（如 100）起始的场景。

**修复建议**：新增 sv_smpcnt_offset 用例，配置 smpCnt 起始偏移为 100（或扩展字段），断言第一帧 `sv.smpCnt == 100`。

---

### COVERAGE-6：T-SV-NEG-03/04 在 JSON 中标记为"单测（缺口）"但 testcase 文档列为正向用例

**文件**：`24-sv-testcase.md` §8 对比表 / §5.3/5.4

**问题**：testcase 文档 §5.3/5.4 把 T-SV-NEG-03（Length 不符）和 T-SV-NEG-04（通道长度不符）写为独立用例，但 §8 又说"JSON 暂缺，记录于已知缺口"。两处表述不一致，且 §5.3/5.4 的 expect_error 描述不明确——"框架在 send 前拦截"或"tshark 判定 Malformed"语义模糊。

**修复建议**：统一表述——在 §5.3/5.4 开头标注"（当前框架不支持字段级恶意覆写，由单测覆盖，pcap 用例待后续补充）"，与 §8 一致。

---

### COVERAGE-7: 无 IP 证明在 sv_4i4v 中依赖 `frame.protocols == "eth:sv"`，但框架可能无解析器

**依据**：GOOSE 审查记忆 MAJOR-5 的教训——`frame.protocols` 在无解析器时显示 `eth:data` 而非 `eth:goose`

**问题**：sv_4i4v 断言 `frame.protocols == "eth:sv"`。如果 tshark 没有 sv 解析器，或 SV 帧 BER 编码错误导致解析器无法识别，`frame.protocols` 将显示 `eth:data`，断言失败。但更危险的是，如果解析器存在且正确，它并不能证明"没有 IP 层"——`frame.protocols` 显示的是解复用链，ETH 类型 0x88BA 时 tshark 自动用 sv 解析器，即使 APDU 的内容包含 IP 数据（如错误封装），`frame.protocols` 仍然是 `eth:sv`。

**证据**：sv_4i4v 已经包含 EtherType 字节级断言（offset 12 `88 ba`）和 APDU 首字节断言（offset 22 `60`），但这在 fields 和 frames 中断言分散在不同位置。sv_smp_seq 的 notes 说"see sv_4i4v for the dedicated no-IP proof"，但无 IP 证明分散在 sv_4i4v 中，不独立。

**修复建议**：sv_4i4v 的 `frame.protocols` 断言保留作为便捷证据，但核心无 IP 证明应依赖字节级证据：
- `eth.type == 0x88ba`（已有）
- `offset 22` 的 hex 以 `60` 开头（APDU 首字节，非 IP 头 0x45）
- 在 notes 中明确说明"无 IP 的字节级证据：EtherType 0x88ba + offset 22 为 0x60（savPdu tag），非 0x45（IPv4）"

---

## 3. 待实现边界清单

以下条目属"当前不可测试、需在实现阶段接入"的内容，**不阻断文档验收**。

| 边界 | 描述 | 验收条件 |
|------|------|----------|
| B-01 | sv 层未注册：所有用例在 `proto: "sv"` 时依赖 registry 层链解析 | registry 增加 `sv` 终结层 |
| B-02 | Validate 未实现：负例（sv_neg_wrap/neg_confrev/neg_appid/neg_smp_synch）依赖 validator 拒绝 | validator 实现所有 §9 校验规则 |
| B-03 | BER 编码器未实现：savPdu 的 BER 编码依赖 `ber.go` 的 encodeTL/encodeUInt16FixedSize 等 | 逐字节单测通过 |
| B-04 | 采样定时器未实现：sv_period 的 250µs 周期依赖 timer 驱动 | ticker 单测或 goleak 验证 |
| B-05 | 双重发逻辑未实现：sv_double_send 依赖同 tick 连发 2 帧 | 帧序单测通过 |
| B-06 | 组播 MAC 覆盖：engine 的组播覆盖机制对 SV 需禁用 IP 推导 | 帧输出 MAC 恒为配置值 |
| B-07 | sv_neg_appid 的 0x3999 段位校验：校验器须区分 GOOSE 段与 SV 段 | validator 返回含 "appid" 的错误 |
| B-08 | sv_period 的时序断言：`frame.time_delta` 断言依赖框架支持时间字段 | 框架支持时间字段或单测兜底 |
| B-09 | T-SV-NEG-03/04 的 JSON 用例：框架不支持字段级恶意覆写，需单测覆盖 | 单测注入错误 Length/seqData 长度断言 error |
| B-10 | smpSynch 两阶段切换：T-SV-S4-01 需要 engine 支持中途改配置或拆用例 | 拆为 sv_smp_synch_global（=2）和 sv_smp_synch_local（=1）等独立用例 |
| B-11 | confRev 变化两阶段：需要 engine 支持续帧或两阶段配置 | 拆为独立任务各断言 confRev |
| B-12 | 多流隔离：需要 engine 支持多流并行 | 创建两个独立任务断言各自 smpCnt 独立 |

---

## 4. 审查结论

### 文档自洽性：**已修复（需复审确认）**

共发现 3 个 CRITICAL、3 个 MAJOR、1 个 MINOR 文档缺陷 + 7 个覆盖缺口 + 12 个待实现边界。

### 修复状态（2026-08-19，commit `2e013a6`）

以下 CRITICAL/MAJOR findings 已在本轮修复：

| finding | 修复 | 提交 |
|---------|------|------|
| CRITICAL-1 sv.length 106→112 | sv.json sv_smp_seq fields | `2e013a6` |
| CRITICAL-2 seqData offset 56→60 | sv.json sv_4i4v frames + note | `2e013a6` |
| CRITICAL-3 savPdu 60 60→60 2e | sv.json sv_double_send frames | `2e013a6` |
| MAJOR-4 note 帧长 128→126 | sv.json sv_smp_seq notes | `2e013a6` |
| MAJOR-5 两帧全等断言加宽 | sv.json sv_double_send 增加 MAC/SV 头/APDU 多段断言 | `2e013a6` |
| MAJOR-6 §9.3 警告→拒绝 | 24-sv-design.md §9.3 | `2e013a6` |

### 待补覆盖缺口（记录为后续设计行，需补独立 case）

COVERAGE-1~7 中的补充建议（confRev 两阶段、smpSynch 三值枚举、多流、refrTm、非零 smpCnt、负例表述统一、无 IP 字节级证据）记录为后续设计增强项；当前 sv.json 已有 12 case 覆盖主路径与现有负例。

### 最严重问题摘要

| 优先级 | 文件 | 问题 | 影响 |
|--------|------|------|------|
| P0 | sv.json sv_smp_seq | sv.length 字段断言 106 != hex 0x70=112 | 已修复 `2e013a6` |
| P0 | sv.json sv_4i4v | seqData tag offset 56 应为 60（smpRate 存在） | 已修复 `2e013a6` |
| P0 | sv.json sv_double_send | savPdu tag `60 60` 应为 `60 2e`（1 通道非 8 通道） | 已修复 `2e013a6` |
| P1 | sv.json sv_double_send | 仅 2 字节断言，不足以证明"两帧完全相同" | 已修复 `2e013a6` |
| P1 | 24-sv-design.md §9.3 | "警告"与"expect_error"矛盾 | 已修复 `2e013a6` |
| P2 | 24-sv-testcase.md | 5 个覆盖缺口（confRev变化/smpSynch枚举/多流/refrTm/非零smpCnt） | 见"待补覆盖缺口" |

### 修复顺序建议

1. 修复 sv.json 的 3 个 CRITICAL（字段值/offset 计算错误）—— 这些是数字错误，实现后必导致测试挂
2. 修复设计 §9.3 的"警告/拒绝"矛盾
3. 增强 sv_double_send 的断言宽度
4. 补充 confRev 变化、smpSynch 枚举、多流等覆盖缺口
5. 统一 testcase 文档中 T-SV-NEG-03/04 的表述
# 09-tds-design.md v3.0.0 — HexDump 自洽性与字节序审计报告

> 审计维度：仅针对 §6 HexDump 场景（S1-S15）的字节级自洽性与字节序
> 审计方法：逐字节核算每个 HexDump，对照 MS-TDS v20260617 规范（ms-tds-spec.txt）核实
> 审计员：独立审计（非设计者）
> 审计日期：2026-08-04
> 严重度：CRITICAL > HIGH > MEDIUM > LOW

---

## 审计范围

逐场景核算以下内容：
1. Packet Header Length 字段 = 8（包头）+ body 实际字节数
2. 所有多字节字段字节序（Length/SPID 大端；其余小端）
3. 长度前缀（US_VARCHAR 2B LE / B_VARCHAR 1B / PLP）与数据长度匹配
4. 偏移表偏移值 vs 字段实际位置
5. Token 值正确性（Error=0xAA, Info=0xAB, Done=0xFD, DoneProc=0xFE, DoneInProc=0xFF, ColMetadata=0x81, Row=0xD1, NbcRow=0xD2, ReturnStatus=0x79, ReturnValue=0xAC, LoginAck=0xAD, FeatureExtAck=0xAE, EnvChange=0xE3, SessionState=0xE4, Order=0xA9）

---

## 审计发现

### 问题 H-1：S2 LOGIN7 请求 HexDump 字节数与 Length 字段不一致（CRITICAL）

**位置**：§6 S2「LOGIN7 请求」HexDump，第 1042-1052 行

**描述**：设计 HexDump 声称「共 0x0090 = 144 字节」，包头 Length 字段为 `00 90`（大端）= 144。但逐字节核算 HexDump 实际只有 142 字节，body 实际 134 字节，Length 字段声称的 body = 136 字节，差 2 字节。

**字节证据**：
- 包头第 2-3 字节（Length，BE）：`00 90` → 144
- 包头第 8-11 字节（LOGIN7.Length，LE）：`88 00 00 00` → 0x88 = 136
- 实际 HexDump 字节计数：142 字节（设计声称 144）
- 实际 body 字节数：142 - 8 = 134（Length 字段声称 136）

**根因**：设计声称 HostName = "host1"（5 字符，14B）但实际 HexDump 字节为 `73 00 6B 00 6F 00 73 00 74 00 76 00 31 00`（14B），解码为 "skostv1"（7 字符，14B）。规范示例 4.2 中 HostName = "skostov1"（8 字符，16B）。设计 HexDump 截断了 "skostov1" 中一个 'o' 字符（少 2 字节），导致 cchHostName=8 与实际 7 字符不符，且 ibUserName=0x6E（110）指向的位置超出实际 "skostv1" 数据区结束位置（94+14=108）。

**偏移表自洽性破裂**：
- ibHostName=0x5E=94，cchHostName=8 → 期望 HostName 数据 16B（8 字符）
- 实际 HostName 数据 14B（7 字符 "skostv1"）
- ibUserName=0x6E=110，但实际 "skostv1" 在 offset 94+14=108 结束，"sa" 数据从 108 开始，ibUserName=0x6E=110 指向 "sa" 数据中间，偏移表与数据区失配

**修复建议**：
- 方案 A：恢复 spec 4.2 原始 HostName "skostov1"（8 字符，16B），让 HexDump 字节数 = 144 与 Length 一致
- 方案 B：修改 cchHostName=7、ibUserName=0x6C（108）以匹配 7 字符 HostName，并修正后续所有偏移值
- 推荐方案 A，保持与规范示例一致

---

### 问题 H-2：S2 LOGIN7 HexDump 中 OptionFlags3 字节值与文字描述矛盾（HIGH）

**位置**：§6 S2「LOGIN7 字段构成」第 1016 行 + HexDump 第 1045 行

**描述**：设计文字描述「OptionFlags3=0x00」，但 HexDump 中对应位置（包 body offset 35）的字节为 `0x10`。

**字节证据**：
- HexDump 第 1045 行：`E0 03 00 10 00 00 00 00 09 04 00 00`
- 包 body 偏移映射：E0(32,OpFlags1) 03(33,OpFlags2) 00(34,TypeFlags) 10(35,OpFlags3) 00-00-00-00(36-39,TZ) 09-04-00-00(40-43,LCID)
- 文字描述：「OptionFlags3=0x00」
- HexDump 实际：OptionFlags3 = `0x10`
- 0x10 在 OptionFlags3 中是 fExtension 位（TDS 7.4），若 fExtension=1 则 ibExtension/cbExtension 应有效指向 FeatureExt 数据，但设计未声明 FeatureExt

**修复建议**：
- 若不使用 FeatureExt，应将 OptionFlags3 改为 `0x00`（同时修改 HexDump 第 35 字节 `10` → `00`）
- 若使用 FeatureExt，应文字描述 OptionFlags3=0x10 并补充 FeatureExt 数据区

---

### 问题 H-3：S2 LOGIN7 文字与 HexDump 中 HostName/AppName 值不一致（HIGH）

**位置**：§6 S2「LOGIN7 字段构成」第 1018、1021、1033、1036 行 + HexDump

**描述**：设计文字声称 HostName="host1"、AppName="trafficgen"（11 字符），但 HexDump 字节解码为 HostName="skostv1"（7 字符）、AppName="OSQL-32"（7 字符，cchAppName=7）。

**字节证据**：
- 文字第 1018 行：`ibHostName=0x005E cchHostName=0x0008 ; "host1"（8 字符，16 字节）`
- 文字第 1033 行：`0x5E: "host1" → 73 00 6B 00 6F 00 73 00 74 00 76 00 31 00（14B）`
- 实际 HexDump 字节 `73 00 6B 00 6F 00 73 00 74 00 76 00 31 00` 解码 = "skostv1"（7 字符）
- "host1" 的 UCS-2 LE 应为 `68 00 6F 00 73 00 74 00 31 00`（10B），与 HexDump 不符
- 文字第 1021 行：`cchAppName=0x0007 ; "trafficgen"（11 字符）` — 自相矛盾（cch=7 但声称 11 字符）
- 实际 AppName 数据 14B（7 字符 "OSQL-32"），不是 "trafficgen"

**修复建议**：将文字描述改为与 HexDump 一致：
- HostName = "skostov1"（8 字符，16B）并恢复缺失的 2 字节；或 HostName = "skostv1"（7 字符，14B）并修正 cchHostName=7
- AppName = "OSQL-32"（7 字符，14B），cchAppName=7（HexDump 与文字 cch 一致，但文字 "trafficgen" 标签错误）

---

### 问题 H-4：S2 Login Response HexDump 字节数与 Length 字段不一致（CRITICAL）

**位置**：§6 S2「Login Response」HexDump，第 1067-1092 行

**描述**：设计 HexDump 声称「共 0x0161 = 353 字节」，但逐字节核算实际为 355 字节，body = 347 字节，Length 字段声称 body = 345 字节，差 2 字节。

**字节证据**：
- 包头第 2-3 字节（Length，BE）：`01 61` → 353
- 实际 HexDump 字节计数：355 字节
- 实际 body 字节数：355 - 8 = 347
- Length 字段声称 body = 345

**根因分析（逐 token 解析）**：
- ENVCHANGE @8: Length=27, 29B（结束于 38）✓
- INFO @38: Length=88, 90B（结束于 129）✓
- ENVCHANGE @129: Length=8, 10B（结束于 140）✓
- ENVCHANGE @140: Length=23, 25B（结束于 166）✓
- ENVCHANGE @166: Length=19, 21B（结束于 188）✓
- INFO @188: Length=92, 94B（结束于 283）✓
- LOGINACK @283: Length=54, 56B（结束于 339）✓
- offset 339-340: `00 00`（2 字节）
- DONE @341: 13B（FD + 2B Status + 2B CurCmd + 8B RowCount）
- DONE 结束于 354
- offset 354: `00`（1 字节，多余）
- 总计 355 字节

- 规范示例 4.4 实际 353 字节，DONE 仅 12B（spec 自身 bug，缺 1 字节）
- 设计补充了 DONE 的第 13 字节（正确）但额外多 1 个尾部 `0x00`

**修复建议**：
- 删除 HexDump 最后一个 `00` 字节（offset 354），使总长度 354，DONE 13B 完整
- 重新核算 Length = 8 + body = 8 + (345 + 1) = 354 = 0x0162，更新包头 Length 字段为 `01 62`
- 或保持 Length=0x0161=353 但删 2 个尾部字节使 HexDump 字节数 = 353（与 spec 一致，但 spec 本身有 DONE 缺字节 bug）

---

### 问题 H-5：S2 LOGINACK ProgName 文字描述与规范不符（HIGH）

**位置**：§6 S2「LOGINACK 分解」第 1096 行 + §3.12 LOGINACK Token 第 653-660 行 + §11 修订记录第 2286 行

**描述**：设计多处声称 LoginAck.ProgName 用 US_VARCHAR（2B 长度 + UCS-2 LE），但 MS-TDS 规范 §2.2.7.14 明确定义 `ProgName = B_VARCHAR`（1B 长度 + UCS-2 LE）。设计 HexDump 中字节 `16` 是单字节长度前缀（B_VARCHAR，值=22），不是 US_VARCHAR 的 2B 长度前缀（若为 US_VARCHAR，长度应为 `16 00` 两字节）。

**字节证据**：
- 规范 ms-tds-spec.txt 第 5618 行：`ProgName = B_VARCHAR`
- 设计 §3.12 第 660 行：「ProgName 用 US_VARCHAR（2B 长度 + UCS-2 LE）」
- 设计 §11 修订记录第 2286 行：「ColName 用 B_VARCHAR；LoginAck.ProgName 用 US_VARCHAR」
- 设计 HexDump（第 1086-1087 行）：`AD 36 00 01 72 09 00 02 16 4D 00 69 00...`
  - AD(token) 36 00(Length=54) 01(Interface) 72 09 00 02(TDSVersion) 16(ProgName 长度=22) 4D 00...(ProgName 数据 44B)
  - `16` 是 1 字节长度前缀（B_VARCHAR），值=22 字符
  - 若为 US_VARCHAR，长度前缀应为 `16 00`（2 字节），但 HexDump 只有 1 字节 `16`
- §7.2 测试用例 T-034 第 1831 行：「[A36] ProgName 用 US_VARCHAR」— 测试断言错误
- §7.2 测试用例 T-035 第 1832 行：「Length=Interface(1)+TDSVersion(4)+ProgName(1+44)+ProgVersion(4)=54」— 公式中 `1+44` 表明 1B 长度 + 44B 数据 = B_VARCHAR，与文字「US_VARCHAR」自相矛盾

**修复建议**：
- 将 §3.12 第 660 行「ProgName 用 US_VARCHAR」改为「ProgName 用 B_VARCHAR」
- 将 §11 第 2286 行「LoginAck.ProgName 用 US_VARCHAR」改为「LoginAck.ProgName 用 B_VARCHAR」
- 将 §7.2 T-034 断言 [A36] 改为「ProgName 用 B_VARCHAR」
- HexDump 本身正确（使用 B_VARCHAR），仅需修正文字描述

---

### 问题 H-6：S2 Login Response Length 校验文字含糊且结果错误（MEDIUM）

**位置**：§6 S2「Length 校验」第 1094 行

**描述**：设计文字校验过程含糊，声称 body = 345，但实际逐 token 核算 body = 347。文字承认「差异在 INFO token 的细节长度上」但未给出确切原因，最终以「最终 Length 值以官方 0x0161 为准」收尾，回避了自洽性问题。

**字节证据**：
- 设计文字：「Body token 序列：ENVCHANGE(2+27=29) + INFO(2+88=90) + ENVCHANGE(2+8=10) + ENVCHANGE(2+23=25) + ENVCHANGE(2+19=21) + INFO(2+92=94) + LOGINACK(2+54=56) + DONE(1+2+2+8=13) = 29+90+10+25+21+94+56+13 = 338?」
- 实际逐 token 累加：29+90+10+25+21+94+56+13 = 338（文字算式结果 338）
- 但设计声称「实际 body = 345」
- 实际 HexDump body = 347
- 338（文字算式）vs 345（声称）vs 347（实际）——三重不一致

**修复建议**：
- 重新逐字节核算并明确每个 token 的实际字节数
- 修正 Length 字段值与 HexDump 字节数一致

---

### 问题 H-7：S6 RPC 请求 BigVarChar 参数编码语义错误（HIGH）

**位置**：§6 S6「请求字段构成」第 1257-1258 行 + HexDump 第 1262-1268 行

**描述**：设计 TYPE_INFO 使用 `A7`（BigVarChar，MBCS/ASCII 编码），但 ParamLenData 中数据使用 UCS-2 LE 编码（每字符 2 字节），且长度前缀 `05 00`（值=5）与实际数据长度（16B UCS-2 或 8B ASCII）均不匹配。

**字节证据**：
- TYPE_INFO：`A7 05 00 09 04 D0 00 34` → BigVarChar(0xA7) + maxlen=5 + Collation(5B)
- ParamLenData HexDump：`05 00 53 00 45 00 4C 00 45 00 43 00 54 00 20 00 31 00`（18B）
  - `05 00` 长度前缀（USHORT CHARBINLEN，2B LE）= 5
  - 后续 16B = "SELECT 1" 的 UCS-2 LE 编码（8 字符 × 2B）
- 规范：BigVarChar 数据应为 MBCS/ASCII（每字符 1B），不是 UCS-2
- 长度前缀 5 与数据 16B 不匹配；若数据为 ASCII "SELECT 1"（8B），长度前缀应为 `08 00`
- 若需 UCS-2 编码，应使用 NVarChar（0xE7）类型

**修复建议**：
- 方案 A（保留 BigVarChar）：将数据改为 ASCII "SELECT 1"（8B），长度前缀改为 `08 00`，maxlen 改为 8
- 方案 B（使用 NVarChar）：将 TYPE_INFO 改为 `E7`（NVarChar），maxlen 改为 8（字符数），长度前缀 `10 00`（16B UCS-2）
- 任一方案下，需重新核算 body 字节数并更新 Length 字段

---

### 问题 H-8：S6 RPC 请求 Length 字段值与文字算式结果不匹配（MEDIUM）

**位置**：§6 S6「Length 校验」第 1270 行

**描述**：设计文字算式自行得出 57 ≠ 73，然后声称「修正 Length=0x41」（65B），但未说明 73→57 的修正细节，文字含糊。

**字节证据**：
- 原始 Length=0x51=81，body=73
- 文字算式：22+2+2+1+12+1+8+9 = 57 → Length=0x41=65
- 实际 HexDump 字节数 = 65 ✓（Length 字段值 0x41=65 与 HexDump 一致）
- 但文字算式中「2+10（@stmt 名 B_VARCHAR）」= 12，而 B_VARCHAR 是 1B 长度 + 数据，"@stmt" 5 字符 = 10B → 共 11B（不是 12B）
- 算式中「2+14（数据）」= 16，但 HexDump 中数据 = 18B（`05 00` + 16B UCS-2）

**修复建议**：明确逐字段字节数：
- ALL_HEADERS=22 + ProcIDSwitch+ProcID=4 + OptionFlags=1 + ParamName(1+10)=11 + StatusFlags=1 + TYPE_INFO(1+2+5)=8 + ParamLenData(2+16)=18 = 65 ✓

---

### 问题 H-9：S15 PLP_NULL 文字描述错误（MEDIUM）

**位置**：§6 S15「Length 校验」第 1779 行

**描述**：文字描述「变长 NULL = 0xFFFF/PLP 0xFFFE 相关——注意 PLP NULL 是 0xFFFFFFFFFFFFFFFF，MAX 类型用 PLP_NULL 8B」中「PLP 0xFFFE」表述歧义，易误解为 PLP NULL 是 0xFE...FF。

**字节证据**：
- 规范 §2.2.5.4.4：PLP_NULL = `%xFFFFFFFFFFFFFFFF`（8B 全 FF）
- UNKNOWN_PLP_LEN = `%xFFFFFFFFFFFFFFFE`（8B，末字节 FE）
- 设计 HexDump 第 1763 行：`FF FF FF FF FF FF FF FF`（8B 全 FF）✓
- 设计文字第 1779 行：「变长 NULL = 0xFFFF/PLP 0xFFFE 相关」— 此处 0xFFFE 指代不明，易混淆 PLP_NULL 与 UNKNOWN_PLP_LEN

**修复建议**：
- 修正文字为：「变长 NULL = 0xFFFF（BIG* USHORTLEN 类型）；PLP_NULL = 0xFFFFFFFFFFFFFFFF（8B 全 FF，MAX 类型）；UNKNOWN_PLP_LEN = 0xFFFFFFFFFFFFFFFE（8B 末字节 FE，非 NULL）」
- HexDump 本身正确（使用 PLP_NULL 8B 全 FF），仅需修正文字表述

---

### 问题 H-10：S15 HexDump 中 NBCROW NullBitmap 与数据布局自洽性（LOW）

**位置**：§6 S15「响应字段构成」第 1744-1746 行 + HexDump 第 1763-1765 行

**描述**：设计文字称「行 2：c1 NULL, c2=NULL, c3=NULL, c4=7 → bitmap = 0x07（bit0..2 置位）；数据: 07 00 00 00」。但 c4=7 时，数据区应只含 c4 的值（4B LE = `07 00 00 00`），NullBitmap = `07`（1B，因 4 列向上取整到 1B），NBCROW token = D2 + NullBitmap(1B) + c4 data(4B) = 6B。

**字节证据**：
- HexDump 片段：`D2 07 07 00 00 00`
  - D2（NBCROW token）
  - 07（NullBitmap，bit0=c1 NULL, bit1=c2 NULL, bit2=c3 NULL, bit3=c4 非 NULL）
  - 07 00 00 00（c4 值=7，4B LE）
- token 总长 = 1 + 1 + 4 = 6B ✓
- 设计文字「数据: 07 00 00 00」描述正确
- 但设计 S15 Length 校验第 1767 行：`NBCROW(1+1+4 = 6)` ✓
- 整体 body 校验：COLMETADATA 65 + ROW 19 + NBCROW 6 + DONE 13 = 103 → Length=111=0x6F ✓

**结论**：S15 NBCROW 自洽，本条仅记录布局正确性已核实，无需修复。

---

## 各场景自洽性结论

| 场景 | Length=8+body | 字节序 | 长度前缀 | 偏移表 | Token 值 | 结论 |
|------|---------------|--------|----------|--------|----------|------|
| S1 Pre-Login | ✓ | ✓ BE | N/A | N/A | N/A | 自洽 |
| S2 LOGIN7 请求 | ✗ (142≠144) | ✓ | ✓ | ✗ 失配 | N/A | **不自洽** |
| S2 Login Response | ✗ (355≠353) | ✓ | ✓ | N/A | ✓ | **不自洽** |
| S3 SQL Batch SELECT | ✓ | ✓ | ✓ | N/A | ✓ | 自洽 |
| S4 SQL Batch DML | ✓ | ✓ | N/A | N/A | ✓ | 自洽 |
| S5 多结果集 | ✓ | ✓ | N/A | N/A | ✓ | 自洽 |
| S6 RPC 请求 | ✓ (字节数) | ✓ | ✗ 语义错 | N/A | N/A | **不自洽** |
| S6 RPC 响应 | ✓ | ✓ | N/A | N/A | ✓ | 自洽 |
| S7 RPC 长名 | ✓ | ✓ | ✓ | N/A | ✓ | 自洽 |
| S8 Error 响应 | ✓ | ✓ | ✓ | N/A | ✓ | 自洽 |
| S9 Info 响应 | ✓ | ✓ | ✓ | N/A | ✓ | 自洽 |
| S10 Attention | ✓ | ✓ | N/A | N/A | ✓ | 自洽 |
| S11 事务 | ✓ | ✓ | ✓ | N/A | ✓ | 自洽 |
| S12 MARS | ✓ | ✓ | N/A | N/A | ✓ | 自洽 |
| S13 多流 RPC | ✓ | ✓ | N/A | N/A | ✓ | 自洽 |
| S14 PLP+8B RowCount | ✓ | ✓ | ✓ PLP | N/A | ✓ | 自洽 |
| S15 NULL 处理 | ✓ | ✓ | ✓ | N/A | ✓ | 自洽（文字描述需修正 H-9） |

---

## 必须修复的问题

| 编号 | 严重度 | 场景 | 摘要 |
|------|--------|------|------|
| H-1 | CRITICAL | S2 LOGIN7 请求 | HexDump 142B ≠ Length 144B；HostName "skostv1" 截断致偏移表失配 |
| H-4 | CRITICAL | S2 Login Response | HexDump 355B ≠ Length 353B；尾部多余 1B + DONE 字节数与 spec 不一致 |
| H-2 | HIGH | S2 LOGIN7 | OptionFlags3 字节 0x10 ≠ 文字 0x00 |
| H-3 | HIGH | S2 LOGIN7 | HostName/AppName 文字标签与 HexDump 字节解码不一致 |
| H-5 | HIGH | S2 LOGINACK | ProgName 规范是 B_VARCHAR，设计文字称 US_VARCHAR，与规范冲突 |
| H-7 | HIGH | S6 RPC 请求 | BigVarChar 数据用 UCS-2 编码 + 长度前缀 05 不匹配数据 16B |
| H-6 | MEDIUM | S2 Login Response | Length 校验文字三重不一致（338/345/347） |
| H-8 | MEDIUM | S6 RPC 请求 | Length 校验文字算式细节与 HexDump 字节数不完全对应 |
| H-9 | MEDIUM | S15 NULL | PLP_NULL 文字「0xFFFE」表述歧义，易与 UNKNOWN_PLP_LEN 混淆 |
| H-10 | LOW | S15 NBCROW | 布局自洽，仅记录核实结果（无需修复） |

---

## 最终结论

**HexDump/字节序维度是否通过：否**

**必须修复的 CRITICAL 问题**：H-1、H-4
**必须修复的 HIGH 问题**：H-2、H-3、H-5、H-7
**建议修复的 MEDIUM 问题**：H-6、H-8、H-9

- 共发现 **10** 个问题
- 严重度分布：CRITICAL 2 / HIGH 4 / MEDIUM 3 / LOW 1
- S2 场景问题最密集（H-1/H-2/H-3/H-4/H-5/H-6 共 6 个），是必须返工重点
- S6 RPC 请求（H-7/H-8）次之
- S1/S3/S4/S5/S7/S8/S9/S10/S11/S12/S13/S14 场景 HexDump 自洽
- S15 场景 HexDump 自洽，仅文字描述需修正（H-9）

**核心根因**：
1. S2 LOGIN7 请求 HexDump 直接复制 spec 4.2 但截断了 HostName 2 字节，未同步调整偏移表与 Length
2. S2 Login Response HexDump 复制 spec 4.4 但 spec 自身 DONE token 缺 1 字节（spec bug），设计补齐后又多加 1 字节
3. LOGINACK.ProgName 文字描述沿袭 v2.0.1 错误（称 US_VARCHAR），与规范 B_VARCHAR 冲突，HexDump 本身正确
4. S6 RPC BigVarChar 编码语义混淆（MBCS 类型却用 UCS-2 数据）

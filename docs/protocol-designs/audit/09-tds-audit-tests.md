# 09-tds-design.md 测试用例维度独立审计报告

> **审计日期**: 2026-08-04
> **被审计文档**: `/home/weihang/trafficGenerator/docs/protocol-designs/09-tds-design.md` v3.0.0
> **审计范围**: §7 测试用例（T-001 ~ T-214）、§8 Validate 规则、§9 错误处理
> **审计维度**: 仅限测试用例质量与覆盖度（不审计 wire 字段正确性，那是其他轮次审计的范围）
> **审计依据**: CLAUDE.md §Testing Policy 8 条规则；MS-TDS v20260617 规范
> **审计员**: 独立审计员（非设计者）

---

## 一、审计方法

1. 用 Read 读取 §7（T-001 ~ T-214 全部 15 个子节）、§8（V-01 ~ V-50）、§9（错误处理/OutcomeSpec）
2. 对照 §1-§6 设计规范与 MS-TDS v20260617 规范核实每条用例的期望值
3. 按 CLAUDE.md §Testing Policy 8 条规则逐条审查
4. 重点核查覆盖缺口（MARS 交错、多流关联、数据类型覆盖、NULL 三种编码、边界值、版本分支、可观测断言）

---

## 二、覆盖度总览

### 2.1 用例数量与分布

| 场景 | 用例区间 | 数量 | 主要覆盖 |
|------|---------|------|---------|
| S1 Pre-Login | T-001 ~ T-015 | 15 | VERSION/ENCRYPTION/INSTOPT/THREADID/MARS/TRACEID/TERMINATOR 协商 |
| S2 Login7 + LoginAck | T-016 ~ T-040 | 25 | TDSVersion/OffsetLength/OptionFlags/FeatureExt/LOGINACK 解析 |
| S3 SQL Batch SELECT | T-041 ~ T-065 | 25 | ALL_HEADERS/COLMETADATA/ROW/DONE/分包/NBCROW/重组 |
| S4 SQL Batch DML | T-066 ~ T-080 | 15 | DONE_COUNT/RowCount/错误/DONE_INXACT/数据类型 |
| S5 多结果集 | T-081 ~ T-095 | 15 | DONE_MORE/ALTMETADATA/ORDER/COMPUTE/Browse |
| S6 RPC sp_executesql | T-096 ~ T-115 | 20 | ProcIDSwitch/参数/TYPE_INFO/RETURNSTATUS |
| S7 RPC 存储过程 | T-116 ~ T-135 | 20 | 长名/输出参数/RETURNVALUE/UDF/NoExecFlag |
| S8 Error 响应 | T-136 ~ T-150 | 15 | Class/LineNumber/MsgText/恢复 |
| S9 Info 响应 | T-151 ~ T-160 | 10 | INFO 结构/Class 映射/顺序 |
| S10 Attention | T-161 ~ T-170 | 10 | DONE_ATTN/Ignore/SESSIONSTATE 例外 |
| S11 事务 | T-171 ~ T-185 | 15 | ENVCHANGE 8/9/10/TM_BEGIN/COMMIT/ROLLBACK/PROMOTE |
| S12 MARS 多会话 | T-186 ~ T-195 | 10 | 交错/OutstandingRequestCount/会话隔离 |
| S13 多流关联 | T-196 ~ T-202 | 7 | BatchFlag/DONE_RPCINBATCH/NoExec |
| S14 大数据类型 | T-203 ~ T-209 | 7 | PLP/MAX/8B RowCount |
| S15 NULL 处理 | T-210 ~ T-214 | 5 | 定长/变长/MAX/TEXT/NBCROW |
| **合计** | T-001 ~ T-214 | **214** | |

### 2.2 Validate 规则覆盖

§8 列出 50 条规则（V-01 ~ V-50），文档声称"每条对应至少一个测试"。实际核对：

- V-01 ~ V-18（通用规则）：多数有对应测试，但 V-14（标识符规则）无明确测试
- V-19 ~ V-34（请求规则）：覆盖较好
- V-35 ~ V-40（事务与 MARS）：覆盖较好
- V-41 ~ V-50（生成后 wire 校验）：**多数无对应测试**（见下方 CRITICAL 问题）

---

## 三、按 CLAUDE.md §Testing Policy 8 条规则审查

### §1 Spec-driven（用例对应规范字段/表格行）

**审查方法**：将 §2-§3 设计章节的每个字段表与测试用例对应。

**覆盖良好的部分**：
- §2.4.2 定长类型 12 种 token 中，INT1/INT2/INT4/INT8/BIT/DATETIME/FLOAT/MONEY 在 T-078/T-079/T-080/T-109/T-112 等用例中覆盖
- §3.1 PRELOGIN 8 个选项 token（VERSION/ENCRYPTION/INSTOPT/THREADID/MARS/TRACEID/FEDAUTHREQUIRED/NONCEOPT）中前 5 个在 T-001 ~ T-014 覆盖
- §3.10 ENVCHANGE 21 种 Type 中，Type 1/2/4/7/8/9/10/15 在 T-037/T-038/T-171 ~ T-184 覆盖

**覆盖缺口**：

| 缺口编号 | 描述 | 严重度 |
|---------|------|--------|
| COV-01 | **FEDAUTHREQUIRED(0x06) 与 NONCEOPT(0x07) 选项无测试**：§3.1 列出 8 个 PRELOGIN 选项，但 T-001 ~ T-015 只覆盖前 5 个 + TRACEID。FEDAUTHREQUIRED 与 NONCEOPT 是 TDS 7.4 联合认证必需字段，缺测试 → §1 违反（规范有字段但无测试） | HIGH |
| COV-02 | **ENVCHANGE Type 3/5/6/11/12/13/16/17/18/19/20/21 共 11 种 Type 无测试**：§3.10 列出 21 种 Type，测试只覆盖 8 种。Type 20/21（Routing）是 TDS 7.4 重要特性，仅在 §3.16 文字提及但无测试用例 → §1 违反 | HIGH |
| COV-03 | **DATETIM4TYPE(0x3A)/FLT4TYPE(0x3B)/MONEYTYPE(0x3C)/FLT8TYPE(0x3E)/MONEY4TYPE(0x7A) 共 5 种定长类型无测试**：§2.4.2 列出 12 种 FIXEDLENTYPE，但测试只覆盖 INT1/2/4/8、BIT、DATETIME。SmallDateTime/Real/Money/Float/SmallMoney 完全无测试 → §1 违反 | MEDIUM |
| COV-04 | **DATETIMEOFFSETNTYPE(0x2B) 无测试**：§2.4.3 列出，T-113 测 DATETIME2，T-078/T-079 测 datetime/date，但 datetimeoffset（带时区）无测试。其编码含 2B 有符号时区分钟数，是独立代码路径 → §1 + §3 违反 | MEDIUM |
| COV-05 | **TIMENTYPE(0x29) 无测试**：§2.4.3 列出，但测试只覆盖 date/datetime/datetime2/decimal，time(n) 独立类型无测试。其 scale→长度映射（3/4/5B）是独立路径 → §1 + §3 违反 | MEDIUM |
| COV-06 | **GUIDTYPE(0x24) 作为定长变长混合类型无测试**：T-114 测 UNIQUEIDENTIFIER 但走的是 0x24 + 0x10/0x00 路径，未测 NULL 路径（0x24 + 0x00） → §3 违反（仅测非 NULL 路径） | LOW |
| COV-07 | **变长类型 USHORTLEN_TYPE 的 BIGVARBINARYTYPE(0xA5)/BIGBINARYTYPE(0xAD)/BIGCHARTYPE(0xAF)/NCHARTYPE(0xEF) 无独立测试**：§2.4.3 列出 7 种，测试只覆盖 BIGVARCHARTYPE(0xA7) 与 NVARCHARTYPE(0xE7) → §1 违反 | LOW |
| COV-08 | **LONGLEN_TYPE 的 IMAGETYPE(0x22)/NTEXTTYPE(0x63)/SSVARIANTTYPE(0x62)/TEXTTYPE(0x23) 无独立测试**：§2.4.3 列出 6 种，T-213 测 TEXT NULL，但非 NULL 的 Text/Image/NText/sql_variant 完全无测试 → §1 + §3 违反 | MEDIUM |
| COV-09 | **XMLTYPE(0xF1)/JSONTYPE(0xF4)/UDTTYPE(0xF0)/VECTORTYPE(0xF5) 完全无测试**：§2.4.3 + §2.4.4 列出，但 14 条 PLP/MAX 用例仅覆盖 varchar(max)，XML/JSON/UDT/Vector 类型零测试 → §1 + §3 违反 | HIGH |
| COV-10 | **COLMETADATA Flags 16 个位字段中，fCaseSen/fIdentity/fComputed/fSparseColumnSet/fEncrypted/fHidden/fKey/fNullableUnknown 大部分无独立测试**：§3.7 详细列出，T-049 只测多列，T-044 测一般列。仅 fNullable 在 S15 用例中出现，其余位无测试 → §1 违反 | LOW |
| COV-11 | **FEATUREEXTACK 各 FeatureId 的 FeatureAckData 内容无测试**：§3.14 列出 SESSIONRECOVERY/FEDAUTH/COLUMNENCRYPTION 等的 ack 数据格式，但 T-040 只测"未请求 feature 检查"，未测正常 ack 数据解析 → §1 + §3 违反 | MEDIUM |
| COV-12 | **RETURNVALUE 的 CryptoMetaData 子结构无测试**：§3.13 提到 TDS 7.4 引入，T-122 ~ T-126 测 RETURNVALUE 但未覆盖加密列 → §3 违反 | LOW |

### §2 失败路径覆盖

**覆盖良好的部分**：
- T-003/T-004（VERSION/TERMINATOR 顺序错）、T-021（LOGIN7 超长）、T-022（ibHostName=0）、T-063/T-064（Length 边界）、T-076/T-077（空/奇数 SQL）、T-117（ProcName 超长）、T-131（RPC 与 SQL 混用）、T-150（ERROR 截断）、T-195（MARS 未协商多请求）、T-207（PLP 长度不符）等失败路径有覆盖
- §8 的 50 条 Validate 规则中，V-01 ~ V-40 大多有失败路径测试

**覆盖缺口**：

| 缺口编号 | 描述 | 严重度 |
|---------|------|--------|
| FAIL-01 | **V-41 ~ V-50 共 10 条 wire 校验规则无明确测试**：§8.4 列出"Build 阶段 wire 校验"10 条（包 Length=8+body、登录前包≤4096、分包长度严格、PacketID 递增、最后包 EOM=1、偏移表单调、ibHostName≠0、变长类型长度合法、解析后无残留字节），但测试用例中无任何一条直接断言"Build 阶段产生正确 wire"。这是 §2 + §4 + §8 的三重违反：失败路径未测、集成路径未测、Validate 规则未挂钩测试 | **CRITICAL** |
| FAIL-02 | **未知 token 容错跳过路径仅 T-059 一条且不具体**：T-059"未知 token 字节 → 按 token 类容错跳过"未指明哪个 token 字节值、哪一类别（xx01xxxx/xx11xxxx/xx10xxxx/xx00xxxx），未断言跳过后能继续解析下一 token → §3 + §5 违反 | HIGH |
| FAIL-03 | **服务器异常断开（TCP FIN/RST 提前）无测试**：§9.1 列为 5 类错误之一，但 T-001 ~ T-214 无任何用例测"模拟服务器在响应中途 FIN" → §2 违反 | HIGH |
| FAIL-04 | **协议结构错误（非法 Length/Type/token）仅 T-063/T-064/T-150 覆盖 3 条**：§9.1 列为重要错误类，但未测"非法 Type 字节"、"Status=0x08+0x10 同置时服务器断开"、"COLMETADATA Count=0 但后续有 ROW"等结构错误 → §2 违反 | MEDIUM |
| FAIL-05 | **Cancel Timer 超时无独立测试**：§9.4 描述"Cancel 计时器（默认 5s）超时 → 断开"，T-169 仅测"取消计时器超时 → 关闭连接"但未断言超时阈值或中间状态 → §2 + §5 违反 | LOW |
| FAIL-06 | **Connection Timer / Client Request Timer 超时无测试**：§9.4 列出三个定时器，但只有 Cancel Timer 在 T-169 提及。Connection Timer（15s）和 Client Request Timer（30s）超时路径无测试 → §2 违反 | MEDIUM |
| FAIL-07 | **登录失败路径仅 T-036 一条**：T-036 测"ERROR(Class=14)"，但未测"LOGINACK 缺失（T-033 已测但未断言登录失败后续状态）"、"TDSVersion 不兼容服务器回退"、"密码错误重试"等。§4.1 状态机描述登录失败要回到 Final State，但无测试断言状态转换 → §2 + §3 违反 | MEDIUM |
| FAIL-08 | **分包重组乱序无失败路径测试**：T-062 测"多包响应乱序重组"，但未测"PacketID 跳跃"、"EOM=1 后仍有包"、"中途 Type 变化"等 §9.5 列出的失败场景 → §2 违反 | MEDIUM |

### §3 正确作用域（每个代码路径独立测试）

**覆盖良好的部分**：
- DONE/DONEINPROC/DONEPROC 三个 token 各有独立测试（T-046/T-092/T-102/T-104）
- PRELOGIN 各选项独立测试（T-001 ~ T-014）
- COLMETADATA / ROW / NBCROW 各有独立测试

**覆盖缺口**：

| 缺口编号 | 描述 | 严重度 |
|---------|------|--------|
| SCOPE-01 | **PRELOGIN 响应解析与请求生成是不同代码路径，但用例未区分**：T-001 ~ T-015 既测"客户端发送"也测"服务器响应"，但未明确区分。`parsePreLoginResponse()` 与 `buildPreLogin()` 是不同函数，应各有独立测试。§4.5 解析状态机列出 `parsePreLoginResponse()` 是独立路径 → §3 违反 | MEDIUM |
| SCOPE-02 | **CIDR 风格的"参数类型 + MaxLen + Value + Collation"组合未矩阵化测试**：T-099/T-109 ~ T-114 各测一个类型，但未测"INTN len=0x03（非法）"、"BIGVARCHAR maxlen=8001（非法）"、"NVARCHAR maxlen=4001（非法）"等 §8 V-25/V-26 列出的非法长度路径 → §3 违反 | MEDIUM |
| SCOPE-03 | **TransMgrReq 7 种 RequestType 中 TM_GET_DTC_ADDRESS(0)/TM_PROPAGATE_XACT(1) 无测试**：§3.5 列出 7 种，T-181 ~ T-185 只测 5/6/7/8/9。Type 0 和 1 是 DTC 相关，虽不常用但是规范定义的合法 RequestType → §3 违反 | LOW |
| SCOPE-04 | **SSPI 消息（Type=0x11）与 Federated Authentication Token（Type=0x08）完全无测试**：§2.1.1 列出 Type=0x08/0x11，但 T-001 ~ T-214 无任何用例。SPNEGO/SSPI 在 §4.1 状态机中是独立分支 → §3 违反 | HIGH |
| SCOPE-05 | **Bulk Load BCP（Type=0x07）完全无测试**：§2.1.1 + §3.6 列出，但无测试用例。BulkLoadBCP 用 NBCROW 限制不同（§3.8 注明 MUST NOT 用于 BulkLoadBCP），是独立代码路径 → §3 违反 | MEDIUM |
| SCOPE-06 | **TVP_ROW（0x01）token 完全无测试**：§3.6 列出，§3.4 提及 TVP_TYPE_INFO，但 T-096 ~ T-135 RPC 用例未测任何 TVP 参数。§8 V-30/V-31 列出 TVP 校验规则但无对应测试 → §3 违反 | HIGH |
| SCOPE-07 | **SSPI token（0xED）与 FEDAUTHINFO token（0xEE）无测试**：§3.6 列出，但无测试 → §3 违反 | LOW |
| SCOPE-08 | **DATACLASSIFICATION(0xA3) token 无测试**：§3.6 列出 TDS 7.4+，但无测试 → §3 违反 | LOW |
| SCOPE-09 | **OFFSET(0x78) token 在 TDS 7.2 移除，但旧版本兼容解析无测试**：§3.6 注明"TDS 7.2 移除"，但若 trafficgen 配置为 7.1 仍需识别。无测试 → §3 违反 | LOW |
| SCOPE-10 | **解析状态机容错跳过 4 类 token（xx01xxxx/xx11xxxx/xx10xxxx/xx00xxxx）无独立测试**：§4.5 列出 4 种 token 类的容错跳过逻辑，但 T-059 仅一条且不区分 4 类 → §3 违反 | MEDIUM |

### §4 集成测试（full path API→engine→output）

**严重缺口**：

| 缺口编号 | 描述 | 严重度 |
|---------|------|--------|
| INT-01 | **没有任何用例测 TDSConfig → SessionSpec → RequestSpec → 生成的 TDS 字节流 的完整链路**：所有 214 条用例都只断言"输入字段 → 期望输出特征"，未断言"配置 JSON → trafficgen 生成的实际 wire 字节"。这是流量生成器的核心使命，缺集成测试等于 §4 完全违反 | **CRITICAL** |
| INT-02 | **没有用例测"任务提交 → 实际产出 PCAP/字节流"的端到端路径**：§1.3 描述"Flow = 一次 TCP 连接 + PRELOGIN/LOGIN7 + 会话请求序列"，但测试用例未断言"提交 TDSConfig 任务后，生成的 PCAP 文件包含预期的 PRELOGIN + LOGIN7 + SQL Batch 序列" | **CRITICAL** |
| INT-03 | **没有用例测 MARS 多会话在同一 TCP 连接上的实际交错字节流**：T-186 ~ T-195 只断言"OutstandingRequestCount=2"等逻辑特征，但未断言"生成的字节流中两个会话的请求包按预期交错" → §4 + §6 违反 | HIGH |
| INT-04 | **OutcomeSpec 断言机制本身无集成测试**：§9.3 定义 OutcomeSpec 各字段（ExpectError/ErrorNumber/ErrorClass/ExpectInfoCount/ExpectEnvChange/ExpectTranId/ExpectRows），但用例未测"配置 OutcomeSpec → 任务执行后实际校验通过/失败"路径 | HIGH |
| INT-05 | **Validate → Build 阶段衔接无集成测试**：§8 列出 Validate 规则，§9.1 列出"配置错误 → 任务创建失败，不产生流量"，但无测试断言"配置 V-TDS-001 错误 → 任务确实创建失败且无 PCAP 产出" | HIGH |

### §5 可观测输出断言

**覆盖良好的部分**：
- 大部分用例都断言具体字段值（如 T-002 UL_VERSION=0x09000000、T-016 wire=`04 00 00 74`、T-045 ROW=`D1 03 00 66 6F 6F`、T-208 RowCount=5×10^9 wire `00 F2 05 2A 01 00 00 00`）
- 字节级断言（T-096 `FF FF 0A 00`、T-116 `04 00 66 00 6F 00 6F 00 33 00`、T-103 `79 00 00 00 00`）符合 §5 要求

**覆盖缺口**：

| 缺口编号 | 描述 | 严重度 |
|---------|------|--------|
| OBS-01 | **T-005/T-006/T-007/T-008 ENCRYPTION 协商用例只断言"客户端请求 ENCRYPT_ON"等语义，未断言实际字节**：T-005 说"B_FENCRYPTION=0x01 正确编码"但未给出实际字节序列；T-006 说"响应 ENCRYPTION 选项值=0x00"但未断言完整 PRELOGIN 响应字节 → §5 部分违反 | MEDIUM |
| OBS-02 | **T-015"服务器 PRELOGIN 响应缺 VERSION → 客户端关连接"未断言任何可观测输出**：仅说"按结构非法处理：关连接"，未断言"任务报告失败原因含 'PRELOGIN response missing VERSION'"或"无后续字节产出" → §5 违反 | HIGH |
| OBS-03 | **T-033"服务器回 Login Response 无 LOGINACK → 判定登录失败"未断言失败原因或后续状态**：仅说"判定登录失败"，未断言"任务结果 = FAIL 且原因含 'LOGINACK missing'" → §5 违反 | MEDIUM |
| OBS-04 | **T-040"未请求 FeatureId → 终止连接"未断言终止时机或已收字节**：仅说"判定 TDS 协议错误，终止连接"，未断言"在 FEATUREEXTACK 解析阶段终止"或"已产出 X 字节后终止" → §5 违反 | MEDIUM |
| OBS-05 | **T-059"未知 token 字节 → 按 token 类容错跳过"未断言跳过字节数或后续 token 解析正确**：仅说"容错跳过"，未断言"跳过 N 字节后能继续解析下一个 DONE token" → §5 + §3 违反 | HIGH |
| OBS-06 | **T-061"CurCmd 任意值 → 透传不解释"未断言实际透传值**：仅说"透传不解释"，未断言"任务报告中记录 CurCmd=配置值" → §5 违反 | LOW |
| OBS-07 | **T-073"批中一条失败后续继续"未断言失败语句与后续语句的 DONE 顺序**：仅说"失败语句 DONE_ERROR，后续语句照常"，未断言"DONE 1 Status=0x12、DONE 2 Status=0x10"等具体值 → §5 部分违反 | MEDIUM |
| OBS-08 | **T-149"错误后继续批 → 下一语句结果正常"未断言恢复点**：未断言"ERROR 后第 N 个 DONE 携带正常 RowCount" → §5 违反 | LOW |
| OBS-09 | **T-163"确认前收到的中间数据丢弃（SESSIONSTATE 除外）"未断言丢弃了哪些 token**：仅说"丢弃"，未断言"丢弃 ROW×3 + DONE 但保留 SESSIONSTATE" → §5 违反 | MEDIUM |
| OBS-10 | **T-167"Attention 发送时机必须当前包发送完成后"未断言时序**：仅说"必须在当前包发送完成后"，未断言"Attention 包的 PacketID = 当前包 PacketID + 1"或"Attention 在 EOM=1 后发送" → §5 违反 | MEDIUM |
| OBS-11 | **T-178"嵌套 BEGIN → 内层无 ENVCHANGE"未断言"无"**：仅说"内层无 ENVCHANGE"，未断言"任务报告中 ENVCHANGE 计数 = 1（仅最外层）" → §5 违反（断言"无"也是可观测断言，但需明确） | LOW |
| OBS-12 | **T-190"会话 A 出错仅 A 收到 ERROR"未断言 B 不受影响的具体可观测输出**：仅说"B 不受影响"，未断言"B 的 DONE 状态 = 0x10 DONE_COUNT 正常" → §5 违反 | MEDIUM |
| OBS-13 | **T-200"批中参数歧义（BatchFlag vs 参数）按参数个数顺序消费"未断言消费顺序**：仅说"按参数个数顺序消费"，未断言"解析后第 N 个 ParameterData 对应第 N 个 RPCReqBatch" → §5 违反 | MEDIUM |
| OBS-14 | **T-202"批内 RPC 各自结果集 → 各自 COLMETADATA"未断言隔离**：仅说"各自 COLMETADATA"，未断言"RPC 1 的 ROW 不会被 RPC 2 的 COLMETADATA 解析" → §5 违反 | MEDIUM |

### §6 并发正确性（多会话/多流并发）

**严重缺口**：

| 缺口编号 | 描述 | 严重度 |
|---------|------|--------|
| CONC-01 | **MARS 多会话交错仅 T-186 ~ T-195 共 10 条，且无并发正确性量化测试**：§6 要求"对任何共享状态或共享速率组件，写一个测试测量 N 个并发 worker 下的聚合可观测行为"。MARS 下 OutstandingRequestCount 是共享状态，但用例未测"3 个会话同时活动时 OutstandingRequestCount=3"的实际聚合值 → §6 违反 | HIGH |
| CONC-02 | **MARS 响应归并无正确性测试**：T-187 说"响应乱序返回 → 按消息边界归并到正确会话"，但未断言"会话 A 的所有响应 token 归并到 A、会话 B 的归并到 B"的实际归并结果。这是 MARS 核心难点 → §6 + §5 违反 | **CRITICAL** |
| CONC-03 | **MARS 下事务隔离无并发测试**：T-193"会话事务独立 → 各自 TransactionDescriptor"仅断言逻辑，未测"会话 A 在事务中、会话 B 不在事务中时，B 的请求是否正确使用 B 自己的描述符" → §6 违反 | HIGH |
| CONC-04 | **多流关联（RPC 批）的状态共享无测试**：T-196 ~ T-202 测 BatchFlag/DONE_RPCINBATCH，但未测"批内 RPC 1 失败是否影响 RPC 2 的执行"等批内状态共享 → §6 违反 | MEDIUM |
| CONC-05 | **多 SessionSpec 共享同一 TCP 连接的字节流交错无测试**：§10 提到"Flow 内多个 SessionSpec 交错"，但无测试断言"两个 SessionSpec 的包在字节流中按预期交错（如 A 请求 → B 请求 → B 响应 → A 响应）" → §6 + §4 违反 | HIGH |
| CONC-06 | **MARS 下 Attention 定向取消的并发正确性无量化测试**：T-191 说"Attention 取消会话 A → 仅 A 的 DONE_ATTN"，但未测"B 仍正常完成"的具体聚合行为 → §6 违反 | MEDIUM |
| CONC-07 | **`-race` 清洁性无任何测试断言**：CLAUDE.md §6.6 要求"对共享状态组件写测试测量聚合行为"，但 214 条用例无任何一条提及并发安全或 race 检测 → §6 违反 | MEDIUM |

### §7 失败测试先行（应失败场景）

**覆盖良好的部分**：
- 大量"应失败"用例存在：T-003/T-004/T-021/T-022/T-056/T-076/T-077/T-117/T-131/T-150/T-195/T-207

**覆盖缺口**：

| 缺口编号 | 描述 | 严重度 |
|---------|------|--------|
| FIRST-01 | **V-14 标识符规则无失败测试**：§8 V-14 列出"UserName/Database 不符定界标识符规则 → V-TDS-014"，但 T-001 ~ T-214 无任何用例测"UserName='sa; DROP TABLE'"等非法标识符被拒绝 | MEDIUM |
| FIRST-02 | **V-18 密码混淆可逆性无失败测试**：§8 V-18 列出"混淆后能还原 → V-TDS-018"，但无测试测"混淆算法对空密码/超长密码/非 ASCII 密码的可逆性" | LOW |
| FIRST-03 | **V-23 ProcName 与 ProcId 互斥无失败测试**：§8 V-23 列出"同时指定 → V-TDS-024"，但无测试用例 | MEDIUM |
| FIRST-04 | **V-30/V-31 TVP 参数 fDefaultValue/fByRefValue=0 无失败测试**：§8 列出，但 TVP 整体无测试（见 SCOPE-06） | HIGH |
| FIRST-05 | **V-39 Attention 无 body 无失败测试**：§8 V-39 列出"Attention 请求带数据 → V-TDS-040"，但 T-161 ~ T-170 无用例测"配置 Attention 带 body → 被拒绝" | LOW |
| FIRST-06 | **V-40 会话内请求顺序 BEGIN/COMMIT 配对无失败测试**：§8 V-40 列出，但 T-171 ~ T-185 无用例测"会话内 COMMIT 但无 BEGIN → 被拒绝" | MEDIUM |
| FIRST-07 | **"任务应该失败但实际通过"的反向断言无用例**：CLAUDE.md §1.7 要求"注入 broken spec 验证任务确实失败"，但 214 条用例无任何一条配置"故意错误的 spec"并断言任务失败。所有用例都是"正确 spec → 期望成功"或"错误 spec → 期望 Validate 拒绝"，缺少"运行时失败"断言 | HIGH |

### §8 测试质量审查（是否存在"测试通过但测错东西"）

**关键发现**：

| 编号 | 描述 | 严重度 |
|------|------|--------|
| QUAL-01 | **T-002 UL_VERSION 字节序断言可能"测错"**：T-002 说"VERSION 数据 09 00 00 00 00 00 01 00 → 大端解析 UL_VERSION=0x09000000（major=9），subbuild=0x0100"。但 MS-TDS 规范对 UL_VERSION 的描述："UL_VERSION is composed of major version (1 byte), minor version (1 byte), and build number (2 bytes). It is represented in network byte order (big-endian)." 即字节 `09 00 00 00 00 00 01 00` 中前 4B 是 UL_VERSION，BE 解析为 `0x09000000`，major=0x09，minor=0x00，build=0x0000；后 2B 是 US_SUBBUILD，BE 解析为 `0x0100`。但**规范对 US_SUBBUILD 的字节序未明确说明**（USHORT 默认 LE，但 UL_VERSION 显式 BE）。设计文档与用例假设 US_SUBBUILD 也是 BE，但规范未明示。如果实现按 LE 解析 US_SUBBUILD，测试与实现可能"一致地错"或"不一致地错" → §8 风险点 | MEDIUM |
| QUAL-02 | **T-010"INSTOPT('OtherInst') → 服务器回 INSTOPT 值 0x01 → 客户端应断开（SHOULD）"是 SHOULD 不是 MUST**：规范说"客户端 SHOULD 断开"，但用例期望"客户端应断开（SHOULD）"措辞模糊。若实现不断开（合规），测试会判定失败但实际实现合规 → §8 测试比规范更严格的"过度断言"风险 | LOW |
| QUAL-03 | **T-035 LoginAck.Length=0x36 的断言依赖 ProgName 长度=22 字符**：T-035 说"Length=Interface(1)+TDSVersion(4)+ProgName(1+44)+ProgVersion(4)=54"。这是硬编码到"Microsoft SQL Server"（22 字符）的特定值。若 trafficgen 模拟的服务器 ProgName 不是这个字符串，Length 就不是 0x36。用例未声明"假设 ProgName='Microsoft SQL Server'"，导致实现可能用不同 ProgName 但仍判定通过 → §8 "测试通过但测错东西"风险 | MEDIUM |
| QUAL-04 | **T-067"INSERT 影响 0 行 → DONE_COUNT + RowCount=0（有效 0）"未区分 0 与 NULL**：用例说"0 与无效区分"，但未断言"无 DONE_COUNT 时 RowCount 字段值是初始化变量（不应被读）"。这是 §5 违反也是 §8 风险——若实现总是初始化 RowCount=0，测试会通过但语义错误 | MEDIUM |
| QUAL-05 | **T-091"每个 DONE 后重置列上下文 → 下一组 COLMETADATA 前 ROW 解析失败"措辞矛盾**：T-091 说"下一组 COLMETADATA 前 ROW 解析失败"，但正确实现应在 COLMETADATA 后才能解析 ROW，"前"解析失败是预期行为不是 bug。用例未明确这是"实现 bug 时应失败"还是"正确实现的行为" → §8 语义模糊 | LOW |
| QUAL-06 | **T-099"@stmt 值 'SELECT 1' → TYPE_INFO A7 + maxlen + Collation + USHORTCHARBINLEN 数据"未断言 maxlen 值**：用例说"maxlen"但未给具体值。设计文档 S6 场景中 maxlen=5，但用例未断言。若实现用 maxlen=0 或 maxlen=8000，测试通过但 wire 错误 → §5 + §8 违反 | MEDIUM |
| QUAL-07 | **T-110"参数类型 NVARCHAR → E7 + 2B maxlen + Collation + 2B len + UCS-2 数据"未断言 maxlen 与 len 的具体值**：同 QUAL-06，仅描述结构未断言值 → §5 违反 | LOW |
| QUAL-08 | **T-115"RPC 响应多结果集 → 按 DONE_MORE 归并"未断言归并结果**：仅说"归并"，未断言"归并后共 N 个结果集"或"第 K 个结果集的 RowCount=X" → §5 + §8 违反 | MEDIUM |
| QUAL-09 | **T-118"空参数名 + fDefaultValue → `00 02 26 02 00`"字节级正确，但未断言后续 StatusFlags 解析**：用例给出字节序列，但未断言"StatusFlags=0x02 → fDefaultValue=1, fByRefValue=0"的位解析。若实现将 0x02 解析为 fByRefValue=1（位 0），测试通过但语义错误 → §8 风险 | MEDIUM |
| QUAL-10 | **T-126"大对象输出参数重排 → 小参数组在前，大参数在后"未断言重排前后顺序**：仅说"重排"，未断言"原序 [big, small1, small2] → 重排后 [small1, small2, big]"的具体顺序 → §5 违反 | MEDIUM |
| QUAL-11 | **T-133"过程内嵌套过程 → DONEINPROC...DONEPROC 嵌套"未断言嵌套层级**：仅说"嵌套"，未断言"外层 DONEPROC 在内层 DONEPROC 之后"或"嵌套深度=N" → §5 违反 | LOW |
| QUAL-12 | **T-155"INFO 与 ERROR 共存 → 分别处理"未断言处理顺序或互不干扰**：仅说"分别处理"，未断言"ERROR 触发任务失败标记但 INFO 仍计入 ExpectInfoCount" → §5 违反 | MEDIUM |
| QUAL-13 | **T-181"TM_BEGIN_XACT(5) → ENVCHANGE 8 + 隔离级别 payload"未断言隔离级别字节**：仅说"隔离级别 payload"，未断言"ISOLATION_LEVEL=0x02 Read Committed"等具体值。若实现总是发 0x00（无变化），测试通过但语义错误 → §5 + §8 违反 | MEDIUM |
| QUAL-14 | **T-183"TM_ROLLBACK_XACT(8) 保存点 → 回滚到保存点，trancount 不变"未断言 trancount 实际值**：仅说"trancount 不变"，未断言"回滚前 trancount=N，回滚后 trancount=N"。这是 §5 + §6 双违反（trancount 是共享状态） | MEDIUM |
| QUAL-15 | **T-189"会话内多条语句 → 会话内 DONE_MORE 序列"未断言序列长度或 DONE_MORE 计数**：仅说"序列"，未断言"3 条语句 → 2 个 DONE_MORE + 1 个 DONE_FINAL" → §5 违反 | LOW |
| QUAL-16 | **T-206"chunk 大小 ≤ 4096 字节"未断言实际 chunk 边界**：仅说"≤ 4096"，未断言"50KB 数据 → 13 个 chunk（12×4096 + 余量）"等具体值 → §5 违反 | MEDIUM |
| QUAL-17 | **T-213"TEXT NULL → 4B 0xFFFFFFFF"未断言 TEXT 类型 token (0x23)**：仅说"4B 0xFFFFFFFF"，未断言"TYPE_INFO 含 TEXTTYPE(0x23)"。若实现用 BIGVARCHARTYPE(0xA7) + 0xFFFF，测试通过但类型错误 → §8 风险 | MEDIUM |

---

## 四、按严重度汇总

### 4.1 CRITICAL 问题（5 个）

| 编号 | 描述 | 涉及规则 |
|------|------|---------|
| FAIL-01 | V-41 ~ V-50 共 10 条 wire 校验规则无明确测试 | §2 + §4 + §8 |
| INT-01 | 无 TDSConfig → 生成字节流 的完整链路集成测试 | §4 |
| INT-02 | 无 任务提交 → PCAP 产出 的端到端测试 | §4 |
| CONC-02 | MARS 响应归并无正确性测试 | §6 + §5 |
| FIRST-07 | 无"运行时失败"断言（仅 Validate 失败或成功） | §7 |

### 4.2 HIGH 问题（15 个）

| 编号 | 描述 | 涉及规则 |
|------|------|---------|
| COV-01 | FEDAUTHREQUIRED/NONCEOPT 选项无测试 | §1 |
| COV-02 | ENVCHANGE 11 种 Type 无测试 | §1 |
| COV-09 | XML/JSON/UDT/Vector 类型完全无测试 | §1 + §3 |
| FAIL-02 | 未知 token 容错跳过路径不具体 | §3 + §5 |
| FAIL-03 | 服务器异常断开无测试 | §2 |
| SCOPE-04 | SSPI/FedAuth Token 消息无测试 | §3 |
| SCOPE-06 | TVP_ROW token 无测试 | §3 |
| INT-03 | MARS 多会话字节流交错无集成测试 | §4 + §6 |
| INT-04 | OutcomeSpec 断言机制无集成测试 | §4 |
| INT-05 | Validate → Build 阶段衔接无集成测试 | §4 |
| OBS-02 | T-015 未断言任何可观测输出 | §5 |
| OBS-05 | T-059 未断言跳过字节数或后续解析正确 | §5 + §3 |
| CONC-01 | MARS 多会话无并发正确性量化测试 | §6 |
| CONC-03 | MARS 事务隔离无并发测试 | §6 |
| CONC-05 | 多 SessionSpec 字节流交错无测试 | §6 + §4 |
| FIRST-04 | TVP 参数 fDefaultValue/fByRefValue=0 无失败测试 | §7 |

### 4.3 MEDIUM 问题（30+ 个）

COV-03/04/05/08/11/12、FAIL-04/06/07/08、SCOPE-01/02/05/10、OBS-01/03/04/07/09/10/12/13/14、CONC-04/06/07、FIRST-01/03/06、QUAL-01/03/04/06/08/09/10/12/13/14/16/17 等（详见上文表格）。

### 4.4 LOW 问题（15+ 个）

COV-06/07/10、FAIL-05、SCOPE-03/07/08/09、OBS-06/08/11、FIRST-02/05、QUAL-02/05/07/11/15 等。

---

## 五、覆盖缺口专项核查

### 5.1 多会话 MARS 交错测试

**结论：覆盖严重不足**

T-186 ~ T-195 共 10 条，但：
- 仅断言逻辑特征（OutstandingRequestCount、SPID 共享、错误隔离），未断言字节流交错
- 无并发正确性量化测试（CONC-01）
- 无响应归并正确性测试（CONC-02）
- 无事务隔离的并发测试（CONC-03）
- 无多 SessionSpec 字节流交错测试（CONC-05）

**修复建议**：新增至少 5 条 MARS 集成测试，断言：
1. 2 会话交错请求的实际字节流顺序（A 请求 → B 请求 → B 响应 → A 响应）
2. OutstandingRequestCount 在请求/响应过程中的实际变化
3. 会话 A 出错时会话 B 的 DONE 状态具体值
4. MARS 下 Attention 定向取消后非目标会话的继续执行
5. 3 会话并发下的响应归并正确性（每个会话的 token 序列完整且无串扰）

### 5.2 多流关联事务状态共享测试

**结论：覆盖不足**

T-196 ~ T-202 共 7 条，但：
- 未测批内 RPC 失败的传播（CONC-04）
- 未测批内 RPC 共享事务状态
- 未测 BatchFlag 与参数歧义的实际消费顺序（OBS-13）
- 未测各 RPC 结果集隔离的具体可观测输出（OBS-14）

**修复建议**：新增至少 3 条测试，断言：
1. RPC 批中 RPC 1 失败后 RPC 2 是否执行（按 NoExecFlag 语义）
2. RPC 批中各 RPC 的 COLMETADATA/ROW/DONEPROC 顺序与隔离
3. BatchFlag=0xFF 在字节流中的实际位置与解析后的 RPCReqBatch 边界

### 5.3 所有数据类型覆盖

**结论：覆盖严重不足**

§2.4 列出约 40 种数据类型 token，测试覆盖：
- FIXEDLENTYPE 12 种中 7 种（INT1/2/4/8、BIT、DATETIME、MONEY？）—— 实际仅 5 种（MONEY 无明确测试）
- BYTELEN_TYPE 17 种中 5 种（INTN/BITN/DECIMALN/NUMERICN/GUID）—— DATENTYPE/TIMENTYPE/DATETIME2N/DATETIMEOFFSETN 部分覆盖
- USHORTLEN_TYPE 7 种中 2 种（BIGVARCHAR/NVARCHAR）
- LONGLEN_TYPE 6 种中 1 种（TEXT 仅 NULL 路径）
- PLP 类型：仅 varchar(max)

未覆盖类型共 ~20 种（见 COV-03/04/05/07/08/09）。

**修复建议**：每个未覆盖类型至少 1 条测试，断言 TYPE_INFO 字节 + 数据值字节。

### 5.4 NULL 三种编码

**结论：覆盖良好但有一处缺陷**

- 定长 NULL：T-210（INT4 NULL = 4B 全 0）✓
- 变长 NULL：T-211（varchar NULL = 2B 0xFFFF）✓
- MAX 类型 NULL：T-212（varchar(max) NULL = 8B PLP_NULL）✓
- TEXT NULL：T-213（4B 0xFFFFFFFF）✓ 但未断言 TEXT 类型 token（QUAL-17）
- NBCROW NULL：T-214（bitmap 位 + 非 NULL 列数据）✓

**缺陷**：T-213 未断言 TYPE_INFO 含 TEXTTYPE(0x23)，可能误用 BIGVARCHARTYPE。此外，未测 NTEXT/IMAGE 的 NULL 路径。

### 5.5 边界值覆盖

**结论：部分覆盖**

已覆盖：
- T-021 LOGIN7 128K-1 上限
- T-063/T-064 Length 512 / 32767 边界
- T-067 INSERT 0 行
- T-068 DELETE 2^40 行（8B 大计数）
- T-112 BIGINT 2^63-1
- T-117 ProcName 1046 字节上限
- T-208 RowCount 5×10^9（8B 边界）
- T-209 2^32-1 行

未覆盖：
- T-??? PacketSize=512 最小值实际生效
- T-??? PacketSize=32767 最大值实际生效
- T-??? 登录前包=4096 边界
- T-??? varchar maxlen=8000 / nvarchar maxlen=4000 边界
- T-??? decimal Precision=38 / Scale=0/38 边界
- T-??? TVP 列数=1024 上限
- T-??? 表列数=65534 上限
- T-??? chunk=4096 边界值（T-206 说 ≤4096 但未测等于 4096）
- T-??? AtchDBFile=260 字符上限
- T-??? VARCHAR 空串（len=0x0000）与 NULL（0xFFFF）的区分

### 5.6 版本分支覆盖

**结论：部分覆盖**

已覆盖：
- T-016 TDS 7.4（默认）
- T-017 TDS 7.1（TDSVersion wire）
- T-018 TDS 7.2（TDSVersion wire）
- T-019 TDS 7.3（TDSVersion wire）
- T-047 7.1 下 DONE RowCount 4B
- T-046 7.2+ DONE RowCount 8B
- T-138/T-139 LineNumber 7.1=2B / 7.2+=4B
- T-014 TRACEID（7.4+）
- T-039 SESSIONRECOVERY（7.4+）

未覆盖：
- 7.3.A vs 7.3.B 区分（NbcRow 仅 7.3.B+，但 T-057/T-214 未断言版本）
- 7.2 引入的 UserType 4B（vs 7.1 的 2B）—— T-044 未断言版本相关宽度
- 7.2 引入的 ALL_HEADERS（vs 7.1 无）—— T-042 未断言 7.1 下无 ALL_HEADERS
- 7.3 引入的 TVP（SCOPE-06 已列）
- 7.3.B 引入的 fSparseColumnSet（COV-10 已列）
- 7.4 引入的 SESSIONSTATE/FEATUREEXTACK/FEDAUTHINFO/DATACLASSIFICATION（部分已列）
- 7.4 引入的 fEncrypted/fReadOnlyIntent
- 7.2 引入的 cbSSPILong（T-030 提及但未断言版本）
- 7.1 vs 7.2 的 BatchFlag=0x80 vs 0xFF（T-196 仅测 0xFF）

### 5.7 每个用例是否真断言可观测输出

**结论：约 30% 的用例存在可观测断言不足**

详见 §5 一节 OBS-01 ~ OBS-14，以及 QUAL-06/07/08/10/11/12/13/14/15/16/17。这些用例仅断言"结构存在"或"语义正确"，未断言具体字段值或字节序列。

---

## 六、关键规范核实结果

### 6.1 期望值正确的用例（抽样核实）

- T-001 PRELOGIN VERSION 必须第一、TERMINATOR 最后：与 MS-TDS §2.2.6.5 一致 ✓
- T-002 UL_VERSION 大端：与规范"network byte order (big-endian)"一致 ✓
- T-011 THREADID 4B LE：与规范 ULONG 默认 LE 一致 ✓
- T-016 TDSVersion 7.4 wire `04 00 00 74`：与规范 0x04000074 LE 一致 ✓
- T-017/018/019 7.1/7.2/7.3 wire 值：与规范脚注 17 一致 ✓
- T-025 密码混淆"高低 4 位互换 + XOR 0xA5"：与规范 §2.2.6.4 一致 ✓
- T-035 LoginAck.Length=0x36=54：与规范示例 4.4 字节序列一致 ✓
- T-096 ProcID=10 短形式 `FF FF 0A 00`：与规范 §2.2.6.6 一致 ✓
- T-116 ProcName "foo3" `04 00 66 00 6F 00 6F 00 33 00`：与规范示例 4.8 一致 ✓
- T-161 Attention 包 Type=0x06 Length=8 无 body：与规范示例 4.10 一致 ✓
- T-208 RowCount 5×10^9 wire `00 F2 05 2A 01 00 00 00`：5,000,000,000 = 0x12A05F200，LE 一致 ✓
- T-212 varchar(max) NULL = 8B 0xFFFFFFFFFFFFFFFF：与规范 PLP_NULL 一致 ✓

### 6.2 期望值有疑问的用例

- T-002 US_SUBBUILD 字节序：规范未明示 BE/LE，设计假设 BE（与 UL_VERSION 一致），但需在测试中明确（QUAL-01）
- T-010 "客户端应断开（SHOULD）"：SHOULD 不是 MUST，测试措辞模糊（QUAL-02）
- T-035 Length=0x36 硬编码 ProgName 长度：需声明假设（QUAL-03）

---

## 七、必须修复的问题清单

### 7.1 必须修复（CRITICAL，5 条）

1. **FAIL-01**：为 V-41 ~ V-50 每条 wire 校验规则新增至少 1 条失败路径测试，断言"配置违反 → Build 阶段产生错误码 V-TDS-050 ~ V-TDS-059"。
2. **INT-01**：新增至少 3 条端到端集成测试，断言"TDSConfig JSON → trafficgen 生成的字节流"完整链路，覆盖 PRELOGIN + LOGIN7 + SQL Batch / RPC / TransMgrReq 各类型。
3. **INT-02**：新增至少 1 条 PCAP 产出测试，断言"提交任务后 PCAP 文件包含预期的包序列"。
4. **CONC-02**：新增 MARS 响应归并正确性测试，断言"N 个会话并发请求 → 每个会话的 token 序列完整归并、无串扰"。
5. **FIRST-07**：新增至少 2 条"运行时失败"测试，注入 broken spec（如服务器响应截断、非法 token 字节），断言任务实际失败并报告原因。

### 7.2 必须修复（HIGH，15 条）

按 §4.2 表格逐条修复。重点：
- COV-01/02/09：补齐 FEDAUTHREQUIRED/NONCEOPT/ENVCHANGE 11 种 Type/XML/JSON/UDT/Vector 测试
- FAIL-02/03：补齐未知 token 容错跳过的 4 类独立测试 + 服务器异常断开测试
- SCOPE-04/06：补齐 SSPI/FedAuth Token/TVP_ROW 测试
- INT-03/04/05：补齐 MARS 字节流交错 / OutcomeSpec / Validate-Build 衔接集成测试
- OBS-02/05：补齐 T-015/T-059 的可观测断言
- CONC-01/03/05：补齐 MARS 并发正确性量化测试
- FIRST-04：补齐 TVP 参数约束失败测试

### 7.3 建议修复（MEDIUM/LOW，45+ 条）

按 §4.3/§4.4 表格逐条评估，优先修复 QUAL-* 系列（防止"测试通过但测错东西"）。

---

## 八、最终结论

### 8.1 测试用例维度是否通过

**结论：否**

### 8.2 不通过的原因

1. **5 条 CRITICAL 问题**：集成测试完全缺失（INT-01/02）、wire 校验规则无测试（FAIL-01）、MARS 并发正确性无测试（CONC-02）、运行时失败断言缺失（FIRST-07）。这 5 条违反 CLAUDE.md §Testing Policy §4/§6/§7/§8 多条核心规则。
2. **15 条 HIGH 问题**：覆盖缺口（COV-01/02/09）、失败路径缺口（FAIL-02/03）、作用域缺口（SCOPE-04/06）、集成缺口（INT-03/04/05）、可观测断言缺口（OBS-02/05）、并发缺口（CONC-01/03/05）。
3. **30+ 条 MEDIUM 问题**：多处用例仅断言结构而非值、未测边界值、版本分支覆盖不全。
4. **QUAL 系列风险**：17 条用例存在"测试通过但测错东西"的风险，需逐一加固断言。

### 8.3 必须修复的问题编号

**CRITICAL（必须修复）**：FAIL-01、INT-01、INT-02、CONC-02、FIRST-07

**HIGH（必须修复）**：COV-01、COV-02、COV-09、FAIL-02、FAIL-03、SCOPE-04、SCOPE-06、INT-03、INT-04、INT-05、OBS-02、OBS-05、CONC-01、CONC-03、CONC-05、FIRST-04

合计 **21 条必须修复**后方可考虑测试用例维度通过。

### 8.4 整体评价

214 条用例在"成功路径 + 字段级断言"层面覆盖良好，字节级期望值与 MS-TDS 规范抽样核实正确。但存在三大系统性缺陷：

1. **集成测试层缺失**：所有用例都是"字段 → 期望特征"的单元级断言，无"配置 → 字节流 → PCAP"的端到端断言。这违反 CLAUDE.md §4 集成测试规则，是最大风险。
2. **并发正确性层缺失**：MARS 多会话是 TDS 协议的核心复杂特性，但用例仅断言逻辑特征，无并发聚合行为量化测试。这违反 CLAUDE.md §6。
3. **可观测断言不充分**：约 30% 的用例仅断言"结构存在"或"语义正确"，未断言具体字段值或字节序列，存在"测试通过但测错东西"风险。这违反 CLAUDE.md §5 + §8。

建议设计者在修复上述 21 条必须修复问题后，重新提交测试用例维度审计。

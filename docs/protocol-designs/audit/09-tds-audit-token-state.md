# TDS 设计文档审计报告 — Token 流 / 状态机 / 多会话多流 维度

> **审计对象**: `/home/weihang/trafficGenerator/docs/protocol-designs/09-tds-design.md` v3.0.0（2026-08-04）
> **规范来源**: `/home/weihang/trafficGenerator/docs/protocol-designs/ms-tds-spec.txt`（MS-TDS v20260617，修订版 42.0，12603 行）
> **审计范围**: §3（消息结构与 Token 流）、§4（状态机）、§6 中 S10/S12/S13（Attention/MARS/多流关联）
> **审计日期**: 2026-08-04
> **审计员**: 独立审计员（非设计者）

---

## 0. 审计方法

逐条比对设计文档 §3/§4/§6 中 Token 表、Token 流顺序、包类型、状态机、MARS、多流、Attention 机制与 MS-TDS v20260617 规范文本。每条发现给出：位置（节号/行号）、描述、依据（规范节号）、修复建议。严重度：CRITICAL > HIGH > MEDIUM > LOW。

---

## 1. 发现汇总

| 严重度 | 数量 |
|--------|------|
| CRITICAL | 2 |
| HIGH | 3 |
| MEDIUM | 4 |
| LOW | 3 |
| **合计** | **12** |

**结论**：**不通过**（存在 2 个 CRITICAL 问题：DONE_RPCINBATCH 归属错误、Attention Ack Type=0x05 与规范 Type 5=Unused 矛盾；以及 3 个 HIGH 问题：LOGINACK.ProgName 编码错误、SAVE TRAN trancount 语义错误、ENVCHANGE Type 16 漏列）。

---

## 2. 问题详述

### CRITICAL-1：DONE_RPCINBATCH(0x80) 在 §3.9 Status 位表中被错误归到 DONE 而非 DONEPROC

- **位置**: §3.9（第 582-592 行），Status 位表
- **描述**: 设计文档将 DONE_RPCINBATCH(0x80) 行的 "DONE" 列标为 "✓（仅 DONE）"，DONEINPROC/DONEPROC 列标为 "—"。但 MS-TDS 规范明确：0x80 DONE_RPCINBATCH 仅存在于 DONEPROC 的 Status 字段中，DONE 的 Status 位不包含 0x80。
- **依据**: MS-TDS §2.2.7.6 DONE 的 Status 位列表（规范第 4676-4696 行）仅含 0x00/0x01/0x02/0x04/0x10/0x20/0x100，无 0x80；§2.2.7.8 DONEPROC 的 Status 位列表（规范第 4779-4791 行）显式包含 "0x80: DONE_RPCINBATCH. This DONEPROC message is associated with an RPC within a set of batched RPCs. This flag is not set on the last RPC in the RPC batch."（规范第 4791 行）。设计文档 S13（第 1665-1666 行）HexDump 实际用的是 DONEPROC（`FE 81 00`），与表格标注自相矛盾。
- **修复建议**: 将 §3.9 Status 位表 DONE_RPCINBATCH 行改为：DONE 列 "—"，DONEPROC 列 "✓"，DONEINPROC 列 "—"。同步修正表格脚注。S13 场景描述中 "第 1 个 DONEPROC 带 DONE_RPCINBATCH=0x80 + DONE_MORE" 与表格不一致，需统一为 DONEPROC。

### CRITICAL-2：§3.15 称 "Attention Ack Type=0x05" 与规范 Type 5=Unused 直接冲突

- **位置**: §3.15（第 704 行）
- **描述**: 设计文档写道："**Attention Ack Type=0x05**（包头 Type 5 标记 Attention 确认消息类型；服务器对 Attention 的实际确认载体是 DONE_ATTN）"。但 MS-TDS 规范 §2.2.3.1.1 Type 字段表（规范第 1058 行）明确：Type=5 "Unused"，Type=6 "Attention signal"，Attention Acknowledgement 在 Server→Client 方向使用 Type=4（Tabular result）包承载（规范第 1099 行 "Attention Acknowledgement Server 4"）。设计文档中 "Type=0x05" 既被规范标为 Unused，又自相矛盾地用于 Attention Ack——会误导实现者构造一个 Type=5 的包，而规范要求服务器必须断开连接或忽略此 Type。
- **依据**: MS-TDS §2.2.3.1.1 Type 表（第 1056-1060 行）：`5 Unused`、`6 Attention signal No`；规范第 1099 行表：`Attention Acknowledgement Server 4`；§2.2.2.9 Attention Acknowledgment（第 1016-1019 行）："Attention messages are acknowledged in the DONE token data stream"，即承载在 Type=0x04 表格响应包的 DONE token 中（DONE_ATTN=0x20 位）。
- **修复建议**: 删除 §3.15 中 "Attention Ack Type=0x05" 这句错误定义，仅保留："Attention 确认 = 服务器在 Type=0x04 表格响应包的 DONE token 中置 DONE_ATTN(0x20) 位"；并在 §2.1.1 Type 表补一行 "0x05 Unused" 以与规范一致。同时移除 §11 修订记录中 "Attention Ack Type=0x05" 的 "已确认定义" 提法。

### HIGH-1：§3.12 称 LOGINACK.ProgName 用 US_VARCHAR，规范明确为 B_VARCHAR

- **位置**: §3.12（第 660 行）、§2.3 注释（第 202 行）、§11 "已确认定义"（第 2286 行）
- **描述**: 设计文档多处断言 "LoginAck.ProgName 用 US_VARCHAR（2B 长度 + UCS-2 LE）"，与 MS-TDS 规范直接矛盾。规范 §2.2.7.14 LOGINACK 的 Token Stream-Specific Rules（第 5620-5628 行）明确：`ProgName = B_VARCHAR`；规范示例 4.4（第 8012-8024 行）也以 `<B_VARCHAR><BYTELEN><BYTE>16</BYTE>...` 解析。设计文档 S2 的字节级示例 `AD 36 00 01 72 09 00 02 16 4D 00 ...` 中，`16` 被作为 1B 长度（=22 字符）使用——这正是 B_VARCHAR 语义，而非 US_VARCHAR（后者会读 2B `16 4D`=0x4D16=19734 字符长度，越界）。所以设计文本与字节示例自相矛盾：文本说 US_VARCHAR，字节按 B_VARCHAR 排列。
- **依据**: MS-TDS §2.2.7.14 LOGINACK（第 5623 行）：`ProgName = B_VARCHAR`；§2.2.5.2.1（第 1436-1437 行）：`B_VARCHAR = BYTELEN *CHAR`、`US_VARCHAR = USHORTLEN *CHAR`；示例 4.4（第 8011-8024 行）XML 解析标注 `<B_VARCHAR>`。
- **修复建议**: 将 §3.12、§2.3 注释、§11 "已确认定义" 中 "LoginAck.ProgName 用 US_VARCHAR" 全部改为 "B_VARCHAR（1B 长度 + UCS-2 LE）"。T-034（第 1831 行）"ProgName 用 US_VARCHAR" 同步修正。Length 校验：`Length = Interface(1) + TDSVersion(4) + ProgName(1+44) + ProgVersion(4) = 54` —— 这与 B_VARCHAR 一致（1B 长度），不需重算。

### HIGH-2：§4.3 事务状态机称 "SAVE TRAN → trancount+1"，与 SQL Server 语义相悖

- **位置**: §4.3 事务状态机（第 787 行）
- **描述**: 设计文档写道："`[ACTIVE] ──SAVE TRAN name──→ [ACTIVE]（trancount+1）`"。但 SQL Server 中 SAVE TRAN 仅在当前事务内创建保存点，不影响 @@trancount；trancount 仅由 BEGIN/COMMIT/ROLLBACK 改变。规范亦明确：SAVE TRAN "Sets a savepoint within the active transaction"（规范第 4000-4001 行）；TM_COMMIT/TM_ROLLBACK 的 fBeginXact 才涉及 trancount 变化；ROLLBACK 到保存点时 "trancount remains unchanged"（第 4101-4102 行）。设计文档将 SAVE TRAN 标为 trancount+1 会让实现误以为要发 ENVCHANGE Type 8（实际上 SAVE TRAN 不产生 ENVCHANGE）。
- **依据**: MS-TDS §2.2.7.9 ENVCHANGE 注释（第 5017 行）："For operations that change only the value of @@trancount, no ENVCHANGE stream is generated."；§2.2.6.9 TransMgrReq RequestType=9（第 4000-4001 行）："Sets a savepoint within the active transaction"；§2.2.6.9 TM_ROLLBACK_XACT（第 4101-4102 行）："If fBeginXact is 1, and the ROLLBACK only rolled back to a savepoint, the Begin_Xact operation is ignored and trancount remains unchanged." 设计文档自身 §3.10 注释也说 "SAVE TRAN" 无 ENVCHANGE（T-180 第 2022 行：`SAVE TRAN | 无 ENVCHANGE`），自相矛盾。
- **修复建议**: §4.3 将 SAVE TRAN 状态转移改为 `[ACTIVE] ──SAVE TRAN name──→ [ACTIVE]（trancount 不变，仅创建保存点）`，并补注 "不产生 ENVCHANGE"。

### HIGH-3：§3.10 ENVCHANGE Type 表漏列 Type 16（Transaction Manager Address）

- **位置**: §3.10（第 608-626 行），ENVCHANGE Type 表
- **描述**: 设计文档 Type 表从 Type 15 直接跳到 Type 17，未列 Type 16。但 MS-TDS 规范明确列出 Type 16 = "Transaction Manager Address (not used)"（第 4876 行、第 5012 行附近）。虽规范标记 "not used"，但作为规范事实点，设计文档应至少标注存在性以免实现者误解为 "Type 16 不存在"。同时 §3.5 TransMgrReq 表（第 498-506 行）称 RequestType 0（TM_GET_DTC_ADDRESS）响应为 "单列单行二进制结果集"，但规范第 3991 行明确："Returns DTC network address as a result set"——实际响应也应通过 ENVCHANGE Type 16 体现 Transaction Manager Address（规范第 4882 行："Type 16: Transaction Manager Address is sent in response to transaction manager requests with requests of type 0 (TM_GET_DTC_ADDRESS)"）。设计文档遗漏了 Type 16 与 TM_GET_DTC_ADDRESS 的对应关系。
- **依据**: MS-TDS §2.2.7.9 ENVCHANGE 注释（第 4882 行）："Type 16: Transaction Manager Address is sent in response to transaction manager requests with requests of type 0"；Type 列表（第 4876 行）："16: Transaction Manager Address"。
- **修复建议**: §3.10 表补行 "16 | Transaction Manager Address（规范标记 not used，响应 TM_GET_DTC_ADDRESS RequestType=0） | B_VARBYTE | %x00"；§3.5 TransMgrReq 表 RequestType=0 行明确响应路径为 ENVCHANGE Type 16。

### MEDIUM-1：§3.6 服务器响应 Token 表 OFFSET 行标注 "TDS 7.2 移除"，但 §4.5 解析器仍列出 parseOrder()，未说明版本门控

- **位置**: §3.6（第 529 行）、§4.5（第 838 行）
- **描述**: §3.6 表正确标注 "OFFSET | 0x78 | Fixed (5B) | 关键字偏移（TDS 7.2 移除）"，依据规范 §2.2.7.16（第 5728 行）"The token was removed in TDS 7.2"。但 §4.5 解析状态机将 0x78 → parseOrder() 列为常驻分支，未说明 TDS 7.2+ 不应再出现此 token。本设计默认 TDS 7.4，规范层面 OFFSET 不会出现在流中；若收到则属协议错误。设计文档的解析器容错策略应区分 "兼容性跳过" 与 "TDS 7.2+ 不应收到"。
- **依据**: MS-TDS §2.2.7.16（第 5728 行）。
- **修复建议**: §4.5 在 0x78 分支注明 "TDS 7.2 起服务器不再发送；TDS 7.4 收到视为协议错误"。

### MEDIUM-2：§3.6 未说明 Token 值 0xA5/0xAD 同时是数据类型 token 与流 token 的上下文复用

- **位置**: §3.6 服务器响应 Token 总表（第 511-538 行）、§2.4.3 数据类型表（第 253-263 行）
- **描述**: 0xA5 既是 COLINFO token（流上下文，§2.2.7.3）又是 BIGVARBINARYTYPE（数据类型上下文，§2.2.5.4.3）；0xAD 既是 LOGINACK token 又是 BIGBINARYTYPE。设计文档分别在 §3.6 和 §2.4.3 各自列出，但未在任何处显式提示"同值不同上下文"。这本身不是错误（两者上下文不重叠），但实现者解析 token 流时若不先按上下文区分可能误判。规范本身也未显式提示，属设计文档应补充的注解。
- **依据**: MS-TDS §2.2.7.3 COLINFO（第 4301 行）"The token value is 0xA5"；§2.2.5.4.3（第 1709 行）`BIGVARBINARYTYPE = %xA5`；§2.2.7.14 LOGINACK（第 5604 行）"The token value is 0xAD"；§2.2.5.4.3（第 1711 行）`BIGBINARYTYPE = %xAD`。
- **修复建议**: §3.6 表脚注或 §2.4.3 增注 "0xA5/0xAD（及 0xA4/0xAB/0xAA/0xAF 等）在不同上下文中复用：token 流上下文为流 token，TYPE_INFO 上下文为数据类型 token；解析时先按所在流（响应 token 流 vs COLMETADATA 列定义）确定上下文"。

### MEDIUM-3：§4.4 MARS 状态机描述 "响应顺序可与请求顺序不同" 在 MS-TDS 主规范中未显式定义，应标注来源

- **位置**: §4.4（第 812 行）、§1.4（第 88 行）
- **描述**: 设计文档多次断言 MARS 下 "响应顺序可与请求顺序不同（服务器并行处理）；客户端按消息边界（EOM + DONE）归并"。MS-TDS 主规范（v20260617）并未显式陈述此行为，MARS 多路复用的具体语义（包括交错、SMP 分片）实际定义在 MC-SMP（Session Multiplex Protocol）规范中，MS-TDS 仅在 §3.2.4/§3.3.5 提及 "If MARS is enabled, the TDS message MUST be passed through to the SMP layer"。设计文档将 MC-SMP 的语义直接陈述为 MS-TDS 事实，缺少规范出处，易误导读者。
- **依据**: MS-TDS §1.4（第 717-718 行）："If the Multiple Active Result Sets (MARS) feature is enabled, the Session Multiplex Protocol (SMP) is required"；§3.2.4（第 6358-6363 行）：MARS 通过 SMP 层；§3.3.5.9（第 6936-6937 行）："If MARS is enabled, all TDS server responses to client request messages MUST be passed through to the SMP layer"。
- **修复建议**: §1.4/§4.4 在 MARS 语义条目补注 "依据 MC-SMP 规范；MS-TDS 主规范仅规定 MARS 消息经 SMP 层传递"。SPID 标识连接而非会话的陈述同样应标注 "依据 MC-SMP 规范，非 MS-TDS 主规范直接定义"。

### MEDIUM-4：§3.15 称客户端发 Attention 后 "必须读取并丢弃除 SESSIONSTATE 外的所有数据，直到收到确认" — 措辞 "收到确认" 模糊

- **位置**: §3.15（第 700-701 行）
- **描述**: 设计文档写 "客户端发送 Attention 后必须读取并丢弃除 SESSIONSTATE 外的所有数据，直到收到确认"。规范 §2.2.1.7（第 911-914 行）的精确措辞是 "client MUST read until it receives an Attention acknowledgment"，且 §4.19.2 示例（第 10564-10566 行）进一步明确：客户端需读直到发现 DONE token with DONE_ATTN bit set，期间缓冲数据全部丢弃。设计文档表述虽不致命错误，但 "收到确认" 措辞可能被误解为 "收到任意响应即停"，未点明必须由 DONE_ATTN 位识别确认。
- **依据**: MS-TDS §2.2.1.7（第 913 行）"client MUST read until it receives an Attention acknowledgment"；§4.19.2（第 10564-10566 行）"The client reads and discards any data already buffered by the server until the acknowledgment is found"；§2.2.4.3（第 1289-1290 行）"final DONE token, which acknowledges that the attention signal is read"。
- **修复建议**: §3.15 改为 "客户端发送 Attention 后必须持续读取并丢弃除 SESSIONSTATE 外的所有数据，直到收到含 DONE_ATTN(0x20) 位的 DONE token——此 DONE 即为 Attention 确认载体。期间不回退到 Logged In 状态（见 §4.1 Sent Attention 状态）"。

### LOW-1：§3.10 ENVCHANGE Type 15 Promote Transaction 行措辞 "Length 字段只含 1B type" 易误读

- **位置**: §3.10（第 621 行）
- **描述**: 设计文档对 Type 15 的描述 "L_VARBYTE（DTC token；Length 字段只含 1B type）" 措辞晦涩，读者可能误解为 "NewValue 仅含 1B"。规范 §2.2.7.9（第 5024 行）明确："LENGTH for ENVCHANGE type 15 is sent as 0x01 indicating only the length of the type token. Client drivers are responsible for reading the additional payload if type is 15." 即 Length=0x01 仅表示 Type 字节长度，NewValue（DTC_TOKEN L_VARBYTE）的实际数据需客户端在 Length 之外单独读取。
- **依据**: MS-TDS §2.2.7.9 注释（第 5024 行）。
- **修复建议**: §3.10 Type 15 行 NewValue 改为 "DTC_TOKEN（L_VARBYTE，Length 字段=0x01 仅含 Type 字节；客户端须自行读 L_VARBYTE 4B 长度前缀 + DTC token 数据）"。

### LOW-2：§3.10 未显式列出 Type 14（Defect Transaction 对应反向语义），注释口径不统一

- **位置**: §3.10（第 619 行）
- **描述**: 设计文档列 Type 12 "Defect Transaction | %x00 | 8B"，但规范第 4881 行明确 Type 12 "Defect Transaction" 的 NEWVALUE=B_VARBYTE、OLDVALUE=%x00，即设计文档的 NewValue=%x00 与 OldValue=8B 应互换。设计文档行写法 "NewValue=%x00、OldValue=8B" 但表格列为 "%x00 | 8B"（NewValue|OldValue 顺序），与规范 "NEWVALUE=B_VARBYTE、OLDVALUE=%x00" 相反。再核对规范第 4914-4923 行表："12: Defect Transaction OLDVALUE=%x00 NEWVALUE=B_VARBYTE"——故 Type 12 应是 NewValue=B_VARBYTE(8B)、OldValue=%x00，设计文档表格列序与规范反了。
- **依据**: MS-TDS §2.2.7.9 Type 12 行（第 4914-4923 行）：`12: Defect Transaction OLDVALUE=%x00 NEWVALUE=B_VARBYTE`；§2.2.7.9 注释（第 5018-5019 行）："The payload of NEWVALUE for ENVCHANGE types 8, 11, and 17 and the payload of OLDVALUE for ENVCHANGE types 9, 10, and 12 is a ULONGLONG." 即 Type 12 的 OldValue 才是 %x00，NewValue 是 8B。
- **修复建议**: §3.10 Type 12 行改为 "12 | Defect Transaction | B_VARBYTE(8B TransactionID) | %x00"。

### LOW-3：§3.7 COLMETADATA Flags 注释中 "示例 4.7 中 Flags=0x20 是 usUpdateable=1 即 0x04？" 问号式表述含糊

- **位置**: §3.7（第 547 行）
- **描述**: 设计文档在 Flags 说明中夹注 "示例 4.7 中 Flags=`20 00`=0x0020，为 fComputed；示例 4.12 中 Flags=`05 00`=0x0005=fNullable|usUpdateable=1(0x04)？"，前半句断言 0x0020=fComputed，后半句用问号引出修正，自相矛盾且行文拖沓。规范 §2.2.7.4 COLMETADATA Flags（第 4396-4410 行）明确：fComputed(bit5=0x20)、fNullable(bit0=0x01)、usUpdateable(bit1-2，1=0x04)。故示例 4.7 的 0x0020=fComputed 确实无误，0x0005=fNullable(0x01)|usUpdateable=1(0x04)。设计文档应直接陈述结论而非问号设问。
- **依据**: MS-TDS §2.2.7.4 Flags 字段（第 4396-4410 行）。
- **修复建议**: §3.7 直接陈述："Flags=0x0020 → fComputed(bit5)；Flags=0x0005 → fNullable(bit0)|usUpdateable=1(bits1-2)"，删除问号式表述与冗余括号。

---

## 3. 通过项（已核实正确）

下列设计文档的关键断言经与 MS-TDS v20260617 规范逐条核实，确认正确：

### 3.1 Token 值
- ERROR=0xAA、INFO=0xAB、LOGINACK=0xAD、COLMETADATA=0x81、ROW=0xD1、NBCROW=0xD2、DONE=0xFD、DONEINPROC=0xFF、DONEPROC=0xFE、ENVCHANGE=0xE3、RETURNSTATUS=0x79、RETURNVALUE=0xAC、ORDER=0xA9、TABNAME=0xA4、COLINFO=0xA5、OFFSET=0x78（TDS 7.2 移除）、FEATUREEXTACK=0xAE、FEDAUTHINFO=0xEE、SESSIONSTATE=0xE4、SSPI=0xED、ALTMETADATA=0x88、ALTROW=0xD3、DATACLASSIFICATION=0xA3、TVP_ROW=0x01。
- 数据类型 token 全部正确（INT1TYPE=0x30、INT4TYPE=0x38、FLT8TYPE=0x3E、INT8TYPE=0x7F、DECIMALTYPE=0x37、NUMERICTYPE=0x3F、BIGVARBINARYTYPE=0xA5、BIGBINARYTYPE=0xAD、NVARCHARTYPE=0xE7、NCHARTYPE=0xEF 等）。
- ALTMETADATA/ALTROW 在 TDS 7.4 弃用（规范第 4145 行注释确认）。

### 3.2 包头 Type 字段
- SQL Batch=0x01、Pre-TDS7 Login=0x02、RPC=0x03、Tabular result=0x04、Attention=0x06、Bulk load=0x07、Federated Auth Token=0x08、TransMgrReq=0x0E、LOGIN7=0x10、SSPI=0x11、Pre-Login=0x12。规范第 1056-1060 行直接确认。

### 3.3 Status 位
- DONE_FINAL=0x00、DONE_MORE=0x01、DONE_ERROR=0x02、DONE_INXACT=0x04、DONE_COUNT=0x10、DONE_ATTN=0x20（仅 DONE）、DONE_SRVERROR=0x100。
- 包头 Status：0x00 普通、0x01 EOM、0x02 Ignore（须与 0x01 同置）、0x08 RESETCONNECTION、0x10 RESETCONNECTIONSKIPTRAN。
- 0x08 与 0x10 互斥（设计 V-38 校验规则与规范 §2.2.3.1.2 一致）。

### 3.4 Token 流顺序
- Login Response 顺序（ENVCHANGE×4 + INFO×2 + LOGINACK + DONE）与规范示例 4.4（第 7054-7100 行）一致。
- 服务器响应以 DONE/DONEPROC/DONEINPROC 结束；批内除最后 DONE 外都带 DONE_MORE（规范 §2.2.7.6 第 4657-4658 行）。
- LOGINACK 必须存在（规范 §2.2.7.14 第 5610-5611 行）；登录响应 DONE 必须最后（规范 §2.2.2.2 第 963-964 行）。
- ERROR/INFO 中 LineNumber=2B（TDS 7.1）/4B（TDS 7.2+）（规范 §2.2.7.10/§2.2.7.13）。
- DONE/DONEPROC/DONEINPROC DoneRowCount：TDS 7.1=4B LONG、TDS 7.2+=8B ULONGLONG（规范 §2.2.7.6 第 4668 行）。

### 3.5 状态机
- 客户端 11 状态（Initial/Sent Initial PRELOGIN/Sent TLS/SSL Negotiation/Sent LOGIN7 Complete/SPNEGO/FedAuth Info/Logged In/Sent Client Request/Sent Attention/Routing Completed/Final）与规范 §3.2.1（第 6276-6286 行）完全一致。
- 服务器 11 状态与规范 §3.3.1（第 6654-6664 行）一致。
- 服务器 Logged In 状态仅接受 Type 1/3/7/14，其他 Type 进入 Final State（规范 §3.3.5.8 第 6925-6927 行）。
- 服务器 Client Request Execution 状态下持续监听客户端消息（MARS 下可排队新请求）（规范 §3.3.5.9 第 6929-6935 行）。
- 三个客户端计时器（Connection 15s 默认、Client Request、Cancel）与规范 §3.2.2 一致。
- 客户端 Sent Attention 状态：收到含 DONE_ATTN 的响应才回 Logged In，否则停留（规范 §3.2.5.9 第 6580-6584 行）。

### 3.6 MARS 多会话（S12）
- MARS 通过 Pre-Login MARS 选项（PL_OPTION_TOKEN=0x04，VALUE=0x01）协商（规范 §2.2.6.5 第 3530 行）。
- ALL_HEADERS.TransactionDescriptor 头：TransactionDescriptor(ULONGLONG 8B) + OutstandingRequestCount(DWORD 4B)（规范 §2.2.5.3.2 第 1596-1607 行）。
- AutoCommit 下 TransactionDescriptor=0、OutstandingRequestCount=1（规范 §2.2.5.3.2 第 1592-1593 行）。
- TransactionDescriptor 头在 SQLBatch/RPC/TransMgrReq 中必需（规范 §2.2.5.3 表第 1538 行 "Required Required Required"）。

### 3.7 多流关联（S13）
- RPC 批用 BatchFlag=0xFF 分隔（TDS 7.2 起，TDS 7.2 前为 0x80）（规范 §2.2.6.6 第 3792 行）。
- NoExecFlag=0xFE 表示前一 RPC 不执行，返回 ERROR + DONEPROC 后继续（规范 §2.2.6.6 第 3806-3807 行注释）。
- ProcID 短形式：0xFFFF + USHORT（规范 §2.2.6.6 第 3839 行）。
- ProcName 长形式 US_VARCHAR，≤1046 字节（规范 §2.2.6.6 第 3838 行）。
- Sp_ExecuteSql=10、Sp_Cursor=1 ... Sp_Unprepare=15（规范 §2.2.6.6 第 3843-3854 行）。
- Batch 内多条 SQL 共享事务状态；显式事务发 ENVCHANGE 8/9/10，AutoCommit 不发（规范 §2.2.7.9 第 5016-5017 行）。

### 3.8 Attention 机制（S10）
- Attention 请求 Type=0x06、Status=0x01（EOM）、Length=8、无 body（规范 §2.2.1.7 第 915-917 行、§4.10 第 8816-8820 行示例）。
- Attention 必须在当前 TDS 包发送完成后才能发送（规范 §2.2.1.7 第 911-913 行）。
- 服务器确认 = DONE token 置 DONE_ATTN(0x20) 位（规范 §2.2.2.9 第 1018-1019 行、§2.2.7.6 第 4692 行）。
- 未发送完的请求用 Status=0x03（Ignore|EOM）取消，服务器返回单个 DONE_ERROR 表格响应，不发 Attention 确认（规范 §2.2.1.7 第 919-925 行）。
- 客户端读响应含 SESSIONSTATE 须保留，其余丢弃（规范 §2.2.4.3 第 1289-1290 行）。

### 3.9 ENVCHANGE Type 8/9/10 事务结构
- Type 8 Begin Transaction：NewValue=B_VARBYTE(1B 长度 0x08 + 8B TransactionID ULONGLONG LE)、OldValue=%x00（规范 §2.2.7.9 第 4914-4915 行 + 第 5018 行）。
- Type 9 Commit Transaction：NewValue=%x00、OldValue=B_VARBYTE(1B+8B)（规范 §2.2.7.9 第 4918-4920 行 + 第 5019 行）。
- Type 10 Rollback Transaction：NewValue=%x00、OldValue=B_VARBYTE(1B+8B)（规范 §2.2.7.9 第 4921-4923 行 + 第 5019 行）。
- 显式事务（BEGIN/COMMIT/ROLLBACK 用户控制生命周期）才发 ENVCHANGE 8/9/10；AutoCommit 不发；SAVE TRAN 不影响 @@trancount，不发 ENVCHANGE（规范 §2.2.7.9 第 5015-5017 行）。

### 3.10 TransMgrReq
- 包头 Type=0x0E、RequestType(USHORT) + [RequestPayload]（规范 §2.2.6.9 第 3965-3970 行）。
- RequestType 取值 0/1/5/6/7/8/9，未知 Type 接收方 SHOULD 断开（规范 §2.2.6.9 第 3981-4002 行）。
- TM_BEGIN_XACT payload=ISOLATION_LEVEL(1B)+BEGIN_XACT_NAME(B_VARBYTE)；隔离级别 0x00~0x05（规范 §2.2.6.9 第 4113-4115 行）。
- TM_COMMIT_XACT/TM_ROLLBACK_XACT 的 fBeginXact 位（规范 §2.2.6.9 第 4019-4081 行）。
- TM_SAVE_XACT 须指定非空名（规范 §2.2.6.9 第 4000-4001 行）。

### 3.11 PRELOGIN 选项
- VERSION 必须第一选项（规范 §3.3.5.1 第 6681 行）；TERMINATOR(0xFF) 必须最后（规范 §2.2.6.5 第 3543 行）。
- PL_OFFSET/PL_OPTION_LENGTH 大端（规范示例 4.1 第 7030-7090 行字节序确认）。
- MARS 选项 token=0x04，B_MARS 0x00/0x01（规范 §2.2.6.5 第 3530 行）。
- ENCRYPTION 0x00=off、0x01=on、0x02=not_sup、0x03=req（规范 §2.2.6.5 第 3567-3570 行）。

### 3.12 LOGIN7
- 包头 Type=0x10、Length 4B LE、TDSVersion 4B LE（0x04000074 wire LE `04 00 00 74`）（规范 §2.2.6.4 第 2807 行）。
- 密码混淆：高低 4 位互换再 XOR 0xA5（规范 §2.2.6.4 第 3431-3433 行）。
- OffsetLength 94B 含 cbSSPILong（规范示例 4.2 第 7400-7405 行 cbSSPILong 字段）。
- ibHostName 不得为 0（规范 §2.2.6.4 注释）。
- 登录字段 ≤128 字符（AtchDBFile ≤260）、cbExtension ≤255 字节、LOGIN7 总长 ≤128K-1。

### 3.13 ALL_HEADERS
- TotalLength(DWORD 含自身)、HeaderLength(DWORD 含自身)、HeaderType(USHORT LE)（规范 §2.2.5.3 第 1554-1560 行）。
- Query Notifications=0x0000、Transaction Descriptor=0x0002、Trace Activity=0x0003（规范 §2.2.5.3 表第 1538-1540 行）。
- 头仅出现在跨多包请求的首包；每个头类型至多出现一次（规范 §2.2.5.3 第 1534-1536 行）。
- Trace Activity 仅 TDS 7.4+（规范 §2.2.5.3.3 第 1608-1610 行）。

### 3.14 DONE_ATTN 表格归属
- DONE_ATTN(0x20) 仅在 DONE 的 Status 中（规范 §2.2.7.6 第 4692 行）；DONEINPROC/DONEPROC 的 Status 不含 0x20。设计文档 §3.9 此行标注正确。

### 3.15 NBCROW 位图
- TokenType(0xD2) + NullBitmap + AllColumnData；位 bit=1 表示 NULL 且数据不在行中（规范 §2.2.7.15 第 5690-5700 行）。
- 位按字节 LSB 序，向上取整到字节；列 0~7 在第一字节 bit0~bit7（规范 §2.2.7.15 第 5690-5695 行）。
- 仅服务器→客户端结果集；不得用于 BulkLoadBCP 和 TVP 行（规范 §2.2.7.15 第 5686-5688 行）。
- ROW 与 NBCROW 可混用（规范 §2.2.7.15 第 5684-5685 行）。

---

## 4. 必须修复的问题

| 编号 | 严重度 | 简述 |
|------|--------|------|
| CRITICAL-1 | CRITICAL | §3.9 DONE_RPCINBATCH(0x80) 归属颠倒：应仅 DONEPROC，非 DONE |
| CRITICAL-2 | CRITICAL | §3.15 "Attention Ack Type=0x05" 与规范 Type 5=Unused 矛盾 |
| HIGH-1 | HIGH | §3.12 LOGINACK.ProgName 应为 B_VARCHAR 而非 US_VARCHAR |
| HIGH-2 | HIGH | §4.3 SAVE TRAN 标 "trancount+1" 与 SQL Server 语义相悖 |
| HIGH-3 | HIGH | §3.10 ENVCHANGE Type 表漏列 Type 16（Transaction Manager Address） |

**结论**：**不通过**。上述 5 个问题（2 CRITICAL + 3 HIGH）必须修复后才能进入实现阶段。其余 7 个 MEDIUM/LOW 问题建议同步修复以提升规范一致性。

---

## 5. 附：审计范围外说明

本审计仅覆盖 Token 流 / 状态机 / 多会话多流维度。HexDump 字节级长度校验（S1-S15）、数据类型编码（§2.4）、Go struct（§5）、Validate 规则（§8）、错误处理（§9）等维度的潜在问题不在本报告范围内，建议另行审计。

---

*本审计报告以 MS-TDS v20260617（修订版 42.0）规范文本为唯一事实来源；设计文档与规范冲突时以规范为准。*

# 07-SMB 设计文档复审报告（r1-v2）

**审计对象**：`/home/weihang/trafficGenerator/docs/protocol-designs/07-smb-design.md`（v2.0.0，2884 行）
**规范**：MS-SMB2（[MS-SMB2] Microsoft Open Specifications）
**审计日期**：2026-08-05
**审计员**：独立审计代理
**方法**：逐节对照 MS-SMB2 §2.2 系列结构定义 + 逐字节核算所有 HexDump 的 NBSS 长度 / StructureSize / 各 Offset 字段自洽性 + 按 CLAUDE.md §Testing Policy 8 条规则评估测试用例

---

## 审计结论摘要

| 严重度 | 数量 |
|--------|------|
| CRITICAL | 7 |
| HIGH | 10 |
| MEDIUM | 7 |
| LOW | 5 |
| **合计** | **29** |

**最终结论：否（不能直接进入实现阶段）。** v2.0.0 虽然修复了 v1 的 SMB2 头 64 字节布局（本次复审确认 §3.1 头布局与 MS-SMB2 §2.2.1.2 完全一致），但引入了**一批新的系统性偏移错误**：几乎所有带可变缓冲区的命令（NEGOTIATE resp / SESSION_SETUP / TREE_CONNECT / QUERY_DIRECTORY / READ resp / SMB3.1.1 协商上下文）的 Offset/Length 字段与 NBSS 长度在文档内部自相矛盾，且其中相当一部分与 MS-SMB2 规范不符（如 SecurityBufferOffset 必须从 SMB2 头起始，文档示例中却按命令体起点计算）。测试用例大量复读文档自身的错误值，形成"自证"闭环，违反 CLAUDE.md §Testing Policy 第 1/5 条。若不修复，实现者按文档写出的报文将无法被 Wireshark/真实 SMB 服务端解析。

---

## 核对基线（本次复审确认正确的部分）

以下内容经逐字段核对 MS-SMB2，**确认无问题**，实现阶段可直接采用：

1. **§3.1 SMB2 SYNC Header 64 字节布局**：ProtocolId=0(4B)、StructureSize=4(2B)、CreditCharge=6(2B)、Status=8(4B)、Command=12(2B)、CreditRequest=14(2B)、Flags=16(4B)、NextCommand=20(4B)、MessageId=24(8B)、Reserved=32(4B)、TreeId=36(4B)、SessionId=40(8B)、Signature=48(16B)。与 MS-SMB2 §2.2.1.2 逐字段一致。
2. **§3.1 64 字节内存图（行 180-184）**：TREE_CONNECT 请求示例字节逐一核对无误（Command=0x0003 @12-13、MessageId=1 @24-31、SessionId=1 @40-47、CreditRequest=0x20 @14-15）。
3. **§3.2 Command 枚举 0x0000-0x0012**：19 个命令值与 MS-SMB2 §2.2.1.2 一致；各命令 StructureSize（NEGOTIATE 36/65、SESSION_SETUP 25/9、CREATE 57/89、READ 49/17、WRITE 49/17、CLOSE 24/60、TREE_CONNECT 9/16、TREE_DISCONNECT/LOGOFF/ECHO 4/4 等）全部正确。
4. **§3.3 Flags 位定义**：bit0=SERVER_TO_REDIR 0x01、bit1=ASYNC 0x02、bit2=RELATED 0x04、bit3=SIGNED 0x08，正确。
5. **§3.4 CreditCharge 规则**：SMB 2.0.2 必须填 0（MUST be reserved）、2.1+ 填 1，正确；§10.4 `creditCharge()` 函数正确。
6. **字节序**：全部 LE（仅 NBSS 长度 BE），正确；NBSS 前缀 type=0x00 + 3B BE 长度，正确。
7. **§3.11 CREATE 请求**：57 字节固定体、NameOffset=64+56=120、各字段偏移全部正确（SecurityFlags@2、RequestedOplockLevel@3、ImpersonationLevel@4、SmbCreateFlags@8、RootDirectoryFid@16、DesiredAccess@24、FileAttributes@28、ShareAccess@32、CreateDisposition@36、CreateOptions@40、NameOffset@44、NameLength@46、CreateContextsOffset@48、CreateContextsLength@52）。
8. **§3.12 CREATE 响应 89 字节**：字段偏移全部正确。
9. **§3.15 WRITE 请求 DataOffset=64+48=112**：正确（§3.15 行 454 与 S6 HexDump 行 1587 均正确）。
10. **§3.13 READ 请求 49 字节**：字段偏移全部正确。
11. **§3.17/3.18 CLOSE 请求 24 / 响应 60 字节**：偏移正确。
12. **§3.24 LOCK / §3.25 IOCTL 固定体**：IOCTL 固定体 54B（56 对齐），LOCK_ELEMENT 24B，正确。
13. **§3.27 TRANSFORM_HEADER 52 字节**：字段与大小正确（ProtocolId=0xFD534D42、Signature@4、Nonce@20、OriginalMessageSize@36、Reserved@40、Flags@42、SessionId@44）。
14. **§4.4 包总数公式**：19 + 2×AuthRounds + 2×N，27/29 包，正确。
15. **S1 请求的 DialectCount=5、dialect 数组、Preauth 上下文（DataLength=38、SaltLength=32、HashAlgorithms=[0x0001]）**：正确。
16. **S4 CREATE 请求 HexDump**：除 NameLength 与 NBSS 长度外全部正确（CreateAction=1、DesiredAccess=0x00120089 LE 等）。
17. **S5 READ 请求 / S6 WRITE 请求响应体 / S7 CLOSE / S8 LOCK / S9 IOCTL / S15 错误处理**的 SMB2 头字段：全部正确（MessageId、TreeId、SessionId、Flags、Command 等）。
18. **S14 签名/加密场景**：SIGNED 标志（req 0x08 / resp 0x09）、TRANSFORM_HEADER 52B 断言，正确。
19. **§9.3 错误响应命令体大小表**：与 MS-SMB2 错误响应约定一致。
20. **§7 测试用例对 SMB2 头 64 字节布局的全部字节断言（T196-T225、T286-T300）**：偏移引用正确（无 v1 的 TreeId@28/SessionId@32 类错误）。
21. **会话状态机（§4）与 MessageId 方案（§4.3）**：与真实 SMB2 会话流程一致（仅 T120 LOGOFF MessageId 有误，见 H-7）。
22. **S2 SESSION_SETUP 头字段**：SessionId=1 @40-47、Status=0xC0000016 LE `16 00 00 C0`、Flags=0x01，正确。

---

## CRITICAL 问题（7 项）

### C-1. NEGOTIATE 响应 SecurityBufferOffset 系统性错误：示例填 64，规范必须为 128

**位置**：§3.6 行 317（"SecurityBufferOffset | uint16 LE | 从 SMB2 头起始算的偏移（默认 64）"）、行 324（"NEGOTIATE 响应固定体 64 字节（0-63），SecurityBuffer 紧随其后，故 SecurityBufferOffset = 64"）；S1 resp HexDump 行 1175（`40 00` = 64）；T223 行 2431（"命令体偏移 56-57 = 40 00 (64 LE)"）。

**描述**：MS-SMB2 §2.2.4（NEGOTIATE 响应）明确规定 SecurityBufferOffset 从 **SMB2 头起始** 计算。NEGOTIATE 响应固定体 64 字节（StructureSize 65 编码为 64B 固定 + 1B padding 概念），SecurityBuffer 实际位于 SMB2 头后 64 字节处，故正确值 = **128**（0x80）。文档 §3.6 行 324 自己写的"从 SMB2 头起始算"与其结论"=64"直接矛盾——64 是"从命令体起始"的算法。S1 resp HexDump、T223 均复读错误值 64。

**依据**：MS-SMB2 §2.2.4 SMB2 NEGOTIATE Response：SecurityBufferOffset (2 bytes) — "The offset, in bytes, from the beginning of the SMB2 header to the security buffer." 固定体 64B → 128。

**修复建议**：§3.6 行 317/324 改为 128（0x80）；S1 resp 行 1175 改为 `80 00`；T223 断言改为 `80 00 (128 LE)`。注意同时导致 S1 resp 的 NegotiateContextOffset 与 NBSS 长度错误（见 C-3）。

### C-2. NEGOTIATE 请求 NegotiateContextOffset 错误：示例 104，正确 112

**位置**：S1 req HexDump 行 1108（`68 00 00 00` = 104）；T294 行 2527（仅断言 8B 对齐，未断言具体值）。

**描述**：S1 请求实际布局：SMB2 头 64 + 固定体 36 + dialects 10 + Padding 2 = **112**（0x70）。文档自己展示的布局（行 1101-1120：36B 固定 + 10B dialects + 2B padding）与 104 矛盾。104 = 64+36+4（把 dialects 当成 4 字节算），属计算错误。

**依据**：MS-SMB2 §2.2.3：NegotiateContextOffset 从 SMB2 头起始；按文档自身展示的布局计算即 112。

**修复建议**：行 1108 改为 `70 00 00 00`（112）。

### C-3. S1 NEGOTIATE resp HexDump 结构性错误：SecurityBuffer 长度 128 + Offset=104 不可能同时成立

**位置**：S1 resp 行 1175-1182。

**描述**：若按文档意图（SecurityBuffer 从偏移 104 起、长 128 字节，NegotiateContextList 从 104 起），则 SecurityBuffer（104-231）与 NegotiateContextList（104 起）**完全重叠**。三个字段（SecBufOffset=64 或 104、SecBufLen=128、NegoCtxOffset=104）中最多一个正确。正确组合为：SecurityBufferOffset=128、SecurityBufferLength=128、NegotiateContextOffset=256。

**依据**：MS-SMB2 §2.2.4 + §2.2.3.1 的偏移语义。

**修复建议**：S1 resp 全面重写：SecurityBufferOffset=128（`80 00`）、SecurityBufferLength=128（`80 00`）、NegotiateContextOffset=256（`00 01 00 00`）；NBSS 长度改 316（见 C-5）。

### C-4. NBSS 长度系统性错误：S1-S4、S6、S7 的 8 处 NBSS length 与自身字节数不符

**位置**：S1 req 行 1084（164 vs 正确 172）、S1 resp 行 1146（268 vs 正确 316）、S2 req#1 行 1206（136 vs 正确 160）、S2 resp#1 行 1252（192 vs 正确 184）、S3 req 行 1306（80 vs 正确 98）、S4 req 行 1385（126 vs 正确 138）、S6 req 行 1568（176 vs 正确 212）、S7 resp 行 1680（132 vs 正确 124）。

**描述**：NBSS 头长度 = SMB2 PDU 实际字节数。逐场景核算：
- S1 req：64+36+10+2+46+2+12 = **172**（0xAC），文档 164（0xA4）。
- S1 resp：64+64+128+46+2+12 = **316**（0x13C），文档 268（0x10C）。
- S2 req#1：64+24+72 = **160**（0xA0），文档 136（0x88）。
- S2 resp#1：64+8+112 = **184**（0xB8），文档 192（0xC0）。
- S3 req：64+8+26 = **98**（0x62），文档 80（0x50）。
- S4 req：64+56+16+2 = **138**（0x8A），文档 126（0x7E）。
- S6 req：64+48+100 = **212**（0xD4），文档 176（0xB0）。
- S7 resp：64+60 = **124**（0x7C），文档 132（0x84）。
S2 resp#1 的 192 可能是把 SecurityBufferLength 112 误算为 120 之类；S3 req 的 80 漏掉 18 字节 path+padding；S4 req 的 126 漏 12 字节。其中 S1 req 的 164 与 S6 req 的 176 恰好等于各自"错误 Offset 方案"下的数值，说明作者按错误偏移反推长度，属系统性连锁错误。

**依据**：NBSS length 定义（§2.2 本文件自己写的"总长度 = 后接 SMB2 PDU 字节数"）。

**修复建议**：按上表逐个修正。实现时以 `len(pdu)` 计算，禁止硬编码。

### C-5. READ 响应 DataOffset 错误：示例 64，正确 80

**位置**：§3.14 行 442（"DataOffset | uint8 | 从 SMB2 头起始，=64"）；S5 resp 行 1539（`40`）；T088 行 2251（"命令体偏移 2 = 40 (64)"）；T222 行 2430。

**描述**：READ 响应固定体 16 字节（StructureSize 17 的奇数编码），Data 字段从 SMB2 头起位于 64+16=**80**（0x50）。文档的"=64"是"从命令体起始"的错误算法。Wireshark 按 DataOffset 指向的位置读取数据，64 会指向命令体中部（StructureSize 字节），数据错位。

**依据**：MS-SMB2 §2.2.9.2 SMB2 READ Response：DataOffset (1 byte) — "The offset, in bytes, from the beginning of the SMB2 header to the data being read."

**修复建议**：§3.14 行 442 改 80；S5 resp 行 1539 改 `50`；T088/T222 断言改 `50 (80)`。S5 resp 的 NBSS 长度 0x1050=4176 恰好=64+16+4096，正确，改后仍自洽。

### C-6. QUERY_DIRECTORY 请求 FileNameOffset 错误：示例 72，正确 96

**位置**：§3.20 行 521（"FileNameOffset | uint16 LE | 从 SMB2 头起始"）；S10 req 行 1878（`48 00` = 72）；T245 行 2463（"命令体偏移 24-25 = 48 00 (72 LE)"）。

**描述**：QUERY_DIRECTORY 请求固定体 32 字节，FileName 从 SMB2 头起位于 64+32=**96**（0x60）。文档 72 是"从命令体起始"（32+40）的错误算法；且 §3.20 自身写明"FileNameOffset 从 SMB2 头起始"，与示例 72 直接矛盾。S10 req 的 NBSS 长度 88 也漏算（应为 98）。

**依据**：MS-SMB2 §2.2.15.1 SMB2 QUERY_DIRECTORY Request：FileNameOffset — "The offset, in bytes, from the beginning of the SMB2 header to the file name."

**修复建议**：S10 req 行 1878 改 `60 00`（96）；T245 改断言 96；NBSS 改 98（`00 00 62`）。

### C-7. S10 QUERY_DIRECTORY 响应条目自相矛盾：NextEntryOffset=104 与 FileNameLength=8 与"file.txt"三处互斥

**位置**：S10 resp 行 1913（NextEntryOffset=104）、行 1928（FileNameLength=8，注释自曝"实际 5 字符 × 2 = 10B"）、行 1929（实际展示 16 字节 "file.txt"）。

**描述**：ID_BOTH_DIR_INFO 固定体 100 字节（§3.21 行 539-557 正确）。条目 #1 若 FileName="file.txt"（16B），条目总长 = 100+16 = 116，NextEntryOffset 应为 **116** 而非 104（104 是按 FileNameLength=8 时的 108 四舍五入，或按 "a.txt" 10B 算 110 再错取整）。同时 FileNameLength=8 与"file.txt"=16B 直接冲突（T298 行 2531 的 CREATE Name 断言正确用 16B，此处却用 8）。条目 #2 的起点也因此错位。S10 resp 的 NBSS 长度 524（0x20C）按什么条目尺寸算均不自洽（两条目 116+116=232+8+64=304，或按文档尺寸 104+104 得 280，均 ≠ 524）。

**依据**：MS-FSCC §2.4.18 ID_BOTH_DIR_INFORMATION：NextEntryOffset 为"到下一结构起点的偏移（本结构从自身头部算）"；FileNameLength 为文件名 UTF-16LE 字节数。

**修复建议**：统一为 FileName="file.txt"（16B）：FileNameLength=`10 00`、NextEntryOffset=116（`74 00 00 00`）；条目 #2 相应平移；重算 resp NBSS 长度 = 64+8+116+116 = 304（0x130）。

---

## HIGH 问题（10 项）

### H-1. SESSION_SETUP 请求 SecurityBufferOffset 概念混乱：88 正确但"64+24"注释误导，且 S2 的 SecurityBufferOffset=88 与文档多处不一致

**位置**：§3.7 行 335（"从 SMB2 头起始（=64+24=88）"）、S2 req 行 1229（`58 00` = 88）、T032 行 2185。

**描述**：SESSION_SETUP 请求固定体 24 字节，SecurityBufferOffset=64+24=88 本身**正确**（MS-SMB2 §2.2.5.1 亦为从 SMB2 头起始）。但该值与 C-4 中 S2 req NBSS 长度 136（正确 160）矛盾：88+72=160，说明文档的 136 把 offset 与长度对不上。此外 T032 断言"命令体偏移 12-13 = 58 00"——命令体偏移 12-13 恰好是 SecurityBufferOffset 字段位置，表述可用，但需与 NBSS 修正联动。此条列为 HIGH 而非 CRITICAL 是因为字段值本身正确，问题在配套 NBSS 长度（C-4 已列）。

**依据**：MS-SMB2 §2.2.5.1。

**修复建议**：保留 88；修正 S2 req NBSS=160；将"=64+24=88"的注释改为"固定体 24B"以免读者按"从命令体起始"误解。

### H-2. TREE_CONNECT 请求 PathOffset 示例 72 与 PathLength=26、NBSS=80 三方矛盾

**位置**：§3.9 行 358（"PathOffset | uint16 LE | 从 SMB2 头起始（=64+8=72）"）、S3 req 行 1326（`48 00`）、行 1306（NBSS=80）。

**描述**：PathOffset=64+8=72 按"从 SMB2 头起始"**正确**（MS-SMB2 §2.2.8.1 同样从 SMB2 头起始）。但 path 26 字节 + 72 = 98 = PDU 总长，与 NBSS=80 矛盾（80 只算了 8 字节 path）。即 Offset 正确、Length 错误。

**依据**：MS-SMB2 §2.2.8.1 + NBSS 长度定义。

**修复建议**：S3 req NBSS 改 98（`00 00 62`）。

### H-3. CREATE 请求 NameLength 错误：file.txt 应为 16，示例 18

**位置**：S4 req 行 1415（"NameLength = 18 ("file.txt" UTF-16LE = 9×2 = 18B)"）；T072 行 2235（断言 16 LE 但用例注释写"8 字符"）。

**描述**："file.txt" 是 8 个字符，UTF-16LE 应为 16 字节（T298 行 2531 的断言字节 `66 00 69 00 6C 00 65 00 2E 00 74 00 78 00 74 00` 恰好 16 字节，与 NameLength=18 自相矛盾）。S4 req 的 Name 段（行 1419-1421）也只得 16 字节，其后接 2B padding。NameLength=18 会导致服务端/Wireshark 认为文件名含 9 个字符，解析错位。

**依据**：UTF-16LE 长度 = 字符数 × 2。

**修复建议**：行 1415 改 NameLength=16（`10 00`）；NBSS 同步改 138（C-4 已列）；T072 的注释"8 字符"与断言 16 字节一致，但描述"NameLength = 10 00"需与 S4 统一。

### H-4. S1 NEGOTIATE 请求 Padding 不足 8 字节对齐，Preauth 上下文位置错位

**位置**：S1 req 行 1119-1120（"Padding (2 bytes, 8B 对齐)"）。

**描述**：MS-SMB2 §2.2.3 要求 NegotiateContextList 中每个 context 8 字节对齐。文档布局：固定体 36 + dialects 10 + pad 2 = 48，48 已经是 8 的倍数，**Preauth 上下文从 112 起、长 46 字节 → 结束于 158，其后的 Encryption 上下文必须补 2B padding 才 8 对齐**。文档缺失该 pad，且 46 字节的 Preauth 上下文自身也非 8 的倍数（Wireshark 会按 8 对齐解析第二个 context，直接错位）。此外行 1123 注释"38 bytes"实为 DataLength（context 总长 46），行 1133 注释"6 bytes"实为 12 字节（8 头 + 4 Data），两处注释与字节数不符。

**依据**：MS-SMB2 §2.2.3.1："Each context MUST be aligned to an 8-byte boundary."

**修复建议**：Preauth 与 Encryption 两个 context 之间补 2B padding；修正两处注释（46/12 字节）；NBSS 同步改 172。

### H-5. §4.3 MessageId 公式与 T120 LOGOFF MessageId 断言矛盾：LOGOFF 应为 9 而非 8

**位置**：§4.3 行 777-782（CLOSE=5+N+1、TREE_DISCONNECT=5+N+2、LOGOFF=5+N+3）；T120 行 2293（"LOGOFF MessageId | AuthRounds=3, N=1 | req | SMB2 头偏移 24-31 = 08 00 00 00 00 00 00 00"）。

**描述**：按 §4.3 自己的公式（N=1）：LOGOFF = 5+1+3 = **9**。T120 断言 8（那是 TREE_DISCONNECT 的值）。同时 T287 行 2520 的 Command 序列"00 01 01 01 03 05 08 06 04 02"与 T289 行 2522 的 MessageId 序列"0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9"自洽（20 个 PDU 的 MessageId 0-9），而 T111 场景中 CLOSE=7、TREE_DISCONNECT=8、LOGOFF=9——三处（T120、T289、§4.3）至少 T120 与 T289 冲突（T120 断言 LOGOFF=8 而 T289 序列中 8 属于 TREE_DISCONNECT）。

**依据**：§4.3 公式 + T289 序列自洽性。

**修复建议**：T120 断言改 `09 00 00 00 00 00 00 00`（9）。T287 的 Command 序列第二项"01 01 01"表示 3 个 SESSION_SETUP，与 T289 的 MessageId 1-3 对应正确，无需改。

### H-6. 会话状态机中"服务端分配 SessionId/TreeId"与 trafficgen 同时生成两侧流量的职责边界未定义

**位置**：§4.1 行 724-725（"SESSION_SETUP 响应分配"、"TREE_CONNECT 响应分配"）、§10.3 行 2770-2774。

**描述**：trafficgen 同时生成请求与响应两侧 PDU。状态变量表说 SessionId/TreeId"由响应分配"，实现者会困惑：响应在生成时尚未执行，分配逻辑实际发生在 planner 顺序生成时（先算好响应再回填请求）。文档未写明**生成顺序**（先生成响应分配 ID，再生成后续请求）与**响应未生成时请求的 ID 填充时机**。这在多会话并发（S12）下尤其关键——§10.3 的 atomic 计数器是全局的，但 TreeId/FileId 的"会话内递增"语义在多 goroutine 下未说明同步机制（TreeId 非全局原子，若两会话并发分配会冲突）。

**依据**：CLAUDE.md §Testing Policy 第 6 条（并发正确性）；工程可实现性。

**修复建议**：§4.1 明确"planner 顺序生成（request→response→request...），SessionId/TreeId 在生成响应 PDU 时确定并回填后续请求"；TreeId 计数器挂在会话对象上（天然隔离），FileId 用 crypto/rand（已声明）；补充单测覆盖并发多会话下 TreeId 互不串扰。

### H-7. 错误注入跳过规则表与状态机图不一致：create 错误后 TREE_CONNECT 响应语义缺失

**位置**：§4.2 行 740（"CREATE 响应 STATUS_OBJECT_NAME_NOT_FOUND → 跳过 READ/WRITE/CLOSE，直接 TREE_DISCONNECT"）、行 751-753 表、S15 行 2106-2109。

**描述**：S15 场景中 CREATE 错误（0xC0000034）后直接 TREE_DISCONNECT，但**真实服务端对 CREATE 错误会如何处理取决于错误码**：0xC0000034 下句柄未建立，后续 TREE_DISCONNECT 合法（TreeId 仍有效）——这一点文档正确。但 §4.2 行 741 的通用规则"任意命令 ErrorResponseStatus 非零 → 该命令响应返回错误"与 §9.1 行 2660 的"请求正常生成、响应填错误码、命令体缩短"在 CREATE 场景下要求错误响应的命令体为 8 字节（§9.3），而 S15 行 2133-2135 展示的 CREATE 错误体为 `09 00 00 00`（StructureSize=9 = SESSION_SETUP 的尺寸！），与 §9.3 表"CREATE 错误响应体 8 字节 StructureSize=89"矛盾。S15 的错误体用的是 SESSION_SETUP 的 StructureSize。

**依据**：MS-SMB2 §2.2.6.2（CREATE 错误响应 StructureSize 仍为 89）；§9.3 自身表格。

**修复建议**：S15 行 2133-2135 改为 `59 00 00 00 00 00 00 00`（StructureSize=89 + 6B 零）；或按 MS-SMB2 惯例错误响应仅发头 + StructureSize。

### H-8. 测试用例 T229/T230 与 Validate 规则 V12-V16 冲突：AuthRounds 合法范围表述不一

**位置**：T229 行 2242（"anonymous 认证只能 1 轮"）、T230 行 2243（"AuthRounds 必须 1-3"）；V12 行 2604（"AuthRounds 必须 1-3"）、V16 行 2608（"ntlm 认证只能 2 或 3 轮"）。

**描述**：V16 规定 ntlm 只允许 2/3 轮，但 T149 行 2332 说"AuthRounds=0 默认 3"——0 既不在 1-3 内又作为默认值合法，Validate 需要特殊处理"0=默认"；V12 的"1-3"与 V16 的"ntlm 只能 2 或 3"对 AuthMechanism=ntlm、AuthRounds=1 的判定矛盾（V12 允许、V16 拒绝）。测试用例与 Validate 规则未对齐，实现时必然出现测试与校验打架。

**依据**：CLAUDE.md §Testing Policy 第 1 条（spec 驱动，规则表每行都要有测试）。

**修复建议**：统一为"AuthRounds=0 表示默认（按机制换算 3/2/1），显式 1-3 且与机制匹配才合法"；T149 与 V12/V16 表述同步修正；补 AuthRounds=1+ntlm 的负向用例。

### H-9. §7.14 Validate 负向用例与 §8 Validate 规则表存在无对应规则的用例

**位置**：T227 行 2240（"SelectedDialect 必须在 Dialects 列表中"）、T240 行 2453（同）、T235 行 2248（"ErrorResponseStatus 必须是已知 NT 状态码"）；V3 行 2590、V30 行 2637。

**描述**：反向检查发现：**T239（Dialects 含 SMB1）**、**T228（AuthMechanism 非法）**、**T231（CreateDisposition 超范围）**、**T232（UNC 格式）**、**T236（MaxTransactSize 超限）**、**T237/T238（长度错）** 均有对应 V2/V11/V21/V18/V32/V5/V6，无问题。但 **T233（OpType 非法）** 与 V23 行 2625 的错误消息不一致（T233 期望 "OpType 必须是 read/write/close/query_directory/query_info/set_info/flush/echo"——与 V23 一致，无问题）。真正的问题是：**T226（Dialects 含 0x9999）对应 V1 错误消息为 "dialect %s 不在 MS-SMB2 §2.2.3 允许列表"，但 MS-SMB2 §2.2.3 是 NEGOTIATE 请求结构而非 dialect 列表章节**（dialect 值定义在 §2.2.3 的 Dialects 字段说明与 §3.2.1 等），引用章节号错误。另 **T235 与 V30 冲突**：V30 说"必须是已知 NT 状态码"，而 T235 的输入 0x12345678 无对应状态名——但 §3.26 表只有 14 个状态码，若 ErrorResponseStatus 限定 14 个，则错误注入只能复现这 14 种，测试 T202"任意 NT 状态码 LE"与 V30 矛盾。

**依据**：CLAUDE.md §Testing Policy 第 1/2 条。

**修复建议**：修正 V1 引用章节号；明确 ErrorResponseStatus 的合法集合（14 个已知码 vs 任意 32 位），T202/T235/V30 三方统一。

### H-10. §6 HexDump 约定与 S14 不一致：S14 的加密 PDU 缺 NBSS 头

**位置**：§6 行 1057（"每个 HexDump 块的偏移从 SMB2 PDU 起始算（不含 NBSS 头）；NBSS 头单独列出"）；S14 PDU #1（行 2055-2069）与 PDU #10（行 2076-2089）。

**描述**：S14 PDU #1（签名版 SESSION_SETUP）与 PDU #10（加密 WRITE）均**未列 NBSS 头**（直接以 SMB2 头/TRANSFORM_HEADER 开头），违反 §6 约定"NBSS 头单独列出"。且 PDU #10 的 NBSS=268（行 2077）按"52+216"自洽，但 TRANSFORM_HEADER 场景的 NBSS 长度 = 52 + EncryptedMessage 长度 = 52+216=268 正确——唯一问题是头没画出来。属文档一致性缺陷，实现风险低，但测试用例（T178-T182、T225）无法据此验证 NBSS。

**依据**：§6 自身约定。

**修复建议**：S14 两个 PDU 补充 NBSS 头行。

---

## MEDIUM 问题（7 项）

### M-1. §3.6 NEGOTIATE 响应固定体注释与 65 的奇数编码未解释

**位置**：§3.6 行 306（"StructureSize | uint16 LE | 65 (0x0041，LE: `41 00`)"）。

**描述**：NEGOTIATE 响应固定体实际为 64 字节（行 1177 的 SecurityBufferOffset=64 也暗示如此），StructureSize=65 是"64+1"的奇数编码（MS-SMB2 惯例）。文档未说明为何 65 而字段表却列到偏移 60-63 共 64 字节，读者（实现者）容易按 65 字节排布缓冲区导致 SecurityBufferOffset 又错位。这与 C-1 直接相关：正是这个 64 vs 65 的混乱导致 SecurityBufferOffset=64 的错误。

**依据**：MS-SMB2 §2.2.4 的字段表（60-63 Reserved，固定体 64B）。

**修复建议**：§3.6 增加说明："StructureSize=65 是奇数编码，固定体实为 64 字节（最后 1 字节并入 SecurityBuffer 前的 padding）"。

### M-2. §2.2 NBSS 行 113-115 的"Length 分高低字节"表与"3 字节 BE"正文矛盾

**位置**：§2.2 行 113-115。

**描述**：行 113-115 把 3 字节长度拆成"1B high + 2B low"，正文（行 94、119）说"3 字节大端"。两者等价但表头容易误导（high 字节只有 1 位有效，17 位长度）。且行 119 示例"200 → `00 00 C8`"正确。属表述问题。

**依据**：NBSS（RFC 1001/1002）Session Message 长度 3 字节 BE。

**修复建议**：合并为一行"Length | 3 | BE"。

### M-3. T152/T269 断言 "NBSS = FF FF FF (2^24-1)" 自相矛盾

**位置**：T152 行 2335、T269 行 2492。

**描述**：若 PDU=16MB（16777216 字节），NBSS 长度字段 24 位最大 16777215，**16MB 超出 NBSS 表示范围**，报文无法承载。断言"FF FF FF"对应长度 16777215 而非 16MB。输入与期望不匹配。

**依据**：NBSS 长度 24 位；§2.2 行 117"最大 16,777,215"。

**修复建议**：输入改 "PDU=16777215B" 或期望改 "NBSS=00 00 00 溢出/被拒"。同时 V32-V34 的 16777216 上限也应为 16777215。

### M-4. T143（超长路径）期望未定义"NBSS 长度正确"的量化断言

**位置**：T143 行 2326。

**描述**："PathLength 大；NBSS 长度正确"——"正确"没有量化值，无法作为断言（违反 CLAUDE.md §Testing Policy 第 5 条：断言可观察输出）。同理 T142（NameLength=510）有量化值但未断言 TCP 分段后的重组完整性。

**依据**：CLAUDE.md §Testing Policy 第 5 条。

**修复建议**：T143 给出具体 PathLength 值（如 26+2×20=66）与对应 NBSS 字节；T142 断言 NameLength=510 且 PDU 总长 = 64+56+510+2。

### M-5. T199/T301/T302 的 CreditCharge 断言与 §3.4 的"响应不设 CreditCharge 语义"未区分

**位置**：T199 行 2402、T301-T304 行 2539-2542。

**描述**：§3.4 说 SMB 2.0.2 的 CreditCharge"MUST be reserved"（请求侧）；响应侧 CreditCharge 亦应为 0（服务端不消耗信用）。T301 断言请求 0x0202 的 CreditCharge=0 正确，但未覆盖**响应侧**；T198（2.1+ 默认 1）同样只查请求。若实现时响应 CreditCharge 填 1，测试全绿但协议违反 2.0.2 规则。缺一个"0x0202 响应 CreditCharge=0"用例。

**依据**：MS-SMB2 §2.2.1.2 CreditCharge 语义（响应侧信用归零）。

**修复建议**：新增用例：Dialects=["0x0202"] 时所有响应偏移 6-7 = 00 00。

### M-6. T186-T195 集成测试只断言"tshark 显示 SMB2"，未注入错误 spec 验证任务失败路径

**位置**：T186-T195。

**描述**：按 CLAUDE.md §Testing Policy 第 2/4 条，集成测试需覆盖失败路径：无效 spec（如 Dialects=["0x9999"]）应导致 Plan 返回错误、任务失败。当前集成测试全是成功路径（T001/T111 spec），无一条注入非法配置验证 Validate→Plan→任务失败的链路。这正是历史教训（planner 错误被静默吞掉、任务报 completed 0 包）的高危区。

**依据**：CLAUDE.md §Testing Policy 第 2、4 条。

**修复建议**：新增集成用例：T186b 用 Dialects=["0x9999"] 驱动全链路，断言任务失败且错误消息含 V1 文案。

### M-7. §5 配置字段 ClientCapabilities 默认 0x03 与 SMB3.1.1 语义冲突

**位置**：§5 行 843-845（"0 默认 SMB2_GLOBAL_CAP_ENCRYPTION | SMB2_GLOBAL_CAP_DIRECTORY_LEASING (0x03)"）、§5.2 行 1030。

**描述**：SMB2_GLOBAL_CAP_ENCRYPTION（bit0）在 dialect 0x0202/0x0210 下无意义（SMB3 才支持加密），默认 dialects 含 0x0202 时协商 0x0202 的客户端仍宣告 encryption 能力，协议上无害（服务端忽略）但 Wireshark 分析会显示能力与 dialect 不匹配。且 0x03 不含 MULTICHANNEL（bit2），真实 Win10 客户端通常 0x03 或含 multichannel。属设计选择问题，但文档未说明 0x0202 时是否降级。

**依据**：MS-SMB2 §2.2.3 能力位定义。

**修复建议**：§5.2 注明"Capabilities 按 SelectedDialect 调整（<0x0300 时清 bit0）"或提供测试 T305/T306 说明该行为。

---

## LOW 问题（5 项）

### L-1. 行 37"7 对请求/响应"与完整会话实际 10 对（NTLM 三阶段）不一致

**位置**：行 37（"完整会话至少 7 对请求/响应"）。

**描述**：§4.4 自身公式给出默认 NTLM 三阶段 = 10 对（20 个 SMB PDU，行 809）。行 37 的"7 对"是简化表述（NEGOTIATE+SESSION_SETUP×1+TREE_CONNECT+CREATE+CLOSE+TREE_DISCONNECT+LOGOFF=7），但未注明"简化（1 轮认证）"，与默认 3 轮矛盾。

**修复建议**：改为"至少 7 对（默认 NTLM 三阶段为 10 对）"。

### L-2. 行 68 dialect 注释 "0x0302=SMB3.0.2" 与行 30 的 "0x0300 起算" 表述可统一

**位置**：行 68、行 30。

**描述**：0x0302 官方名称 "SMB 3.0.2"（MS-SMB2 §2.2.3 表格），文档行 68 写 "SMB3.0.2" 正确；行 30"dialect 0x0302=SMB3.0.2"亦正确。无实质问题，仅建议行 30 补充 0x0302/0x0311 到概述。

**修复建议**：可不动；如需更严谨可列出全部 5 个 dialect。

### L-3. 行 84 "TRANSFORM_HEADER...52 字节，包裹密文" 未说明 EncryptedMessage 长度 = OriginalMessageSize 的约束

**位置**：行 84、行 651。

**描述**：§3.27 行 651 已写明"长度 = OriginalMessageSize"，行 84 无需重复。属冗余，不构成问题。**（撤回）**

### L-4. T034 PreviousSessionId=0x1234 的断言字节 `34 12 00 00 00 00 00 00` 正确但用例未说明该字段仅在多通道重连时使用

**位置**：T034 行 2187。

**描述**：PreviousSessionId 语义为"重连时复用上次会话"，trafficgen 生成独立会话时填 0 即可；T034 测试非零路径本身无害（测试字段写入），但 S2 场景中 PreviousSessionId 恒为 0，字段实际从未非零（除非用户显式配置）。文档未提供该字段的配置入口（§5 无 PreviousSessionId 字段）——**T034 测试了一个无法通过配置到达的状态**，违反 CLAUDE.md §Testing Policy 第 3 条（测试可达路径）。

**修复建议**：§5 增加 PreviousSessionId 配置字段，或删除 T034/改为内部实现单元测试。

### L-5. 行 33 概述"SMB 是会话级协议"与 §1.2"继承 FTP/SOCKS5 的 TCP 会话模型"重复表述

**位置**：行 33-34。

**描述**：纯文字冗余，无实质问题。**（撤回）**

### L-6. T193 "真实 NIC 发送" 用例依赖硬件（enp135s0f0np0），应标注为可跳过

**位置**：T193 行 2329。

**描述**：CI 环境无该网卡时用例必失败。历史经验（RDP/PCAP replay 记忆）中 NIC 用例用环境变量标记 skip。

**修复建议**：T193 标注"无网卡环境 skip"。

---

## 测试用例质量专项评估（CLAUDE.md §Testing Policy）

| 规则 | 评估 |
|------|------|
| §1 spec 驱动 | **部分违反**：315 条用例中绝大多数由 §2-§6 字段表推导，但 S1-S15 HexDump 的错误值被原样搬进断言（T088/T223/T245 等），形成"文档自证"闭环，规范值反而丢失 |
| §2 失败路径 | **违反**：T126-T140 覆盖错误注入序列，但错误**响应体内容**（§9.3 表）无一条用例断言（如 CREATE 错误体 StructureSize 应为 89 却无测试）；T202 只断言"NT 状态码 LE"未限定合法集合 |
| §3 测试正确函数/分支 | 部分违反：见 L-4（PreviousSessionId 不可达）、M-5（响应侧 CreditCharge 未测） |
| §4 集成测试 | **违反**：T186-T195 全为成功路径，无失败 spec 注入链路验证（见 M-6） |
| §5 断言可观察输出 | 部分违反：T143 等用例期望值非量化（见 M-4） |
| §6 并发正确性 | T163/T168 覆盖 -race 与 SessionId 原子性，**但未测并发下 TreeId/FileId 隔离**（T158 只测串行语义，多 goroutine 下 TreeId 计数器若为全局即会串扰，无测试拦截） |
| §7 失败测试先行 | 不适用（文档阶段） |
| §8 测试质量对抗审查 | 本报告即对抗审查产物；主要缺陷为"错误值自证"与"缺失规范值断言" |

---

## 修复优先级建议

1. **先修 7 个 CRITICAL**（C-1 至 C-7）：全部是 Offset/Length/NBSS 的算术与语义错误，一次性重算 §3.6/§3.14/§3.20/§3.21、S1-S7/S10 全部 HexDump 与 T088/T223/T245 断言；建议实现时写一个"offsets 表"用代码生成 HexDump 以防再犯。
2. **再修 HIGH**：H-5（T120 改 9）、H-7（S15 错误体）、H-8（AuthRounds 规则统一）、H-9（引用章节与状态码集合）。
3. **MEDIUM/LOW 随文档修订一起处理**。
4. **测试用例增补**：按 M-5/M-6/L-4 增加 4-6 条用例（0x0202 响应 CreditCharge=0、Validate 失败链路集成、并发 TreeId 隔离、0x0300 以下能力降级）。

---

## 结论

**否——不能直接进入实现阶段。**

文档的核心骨架（SMB2 头 64 字节布局、Command 枚举、Flags、各命令 StructureSize、CREATE/READ/WRITE/CLOSE 请求结构、TRANSFORM_HEADER、包数公式、状态机）经核对与 MS-SMB2 一致，v2.0.0 相对 v1 的修复是真实的。但存在 7 个 CRITICAL 级偏移/长度错误，全部集中在"带可变缓冲区的命令"上（NEGOTIATE resp 的 SecurityBufferOffset/NegotiateContextOffset、READ resp 的 DataOffset、QUERY_DIRECTORY 的 FileNameOffset 与条目长度、以及 8 处 NBSS 长度），且测试用例大量复读这些错误值。实现者若照文档编码，生成的报文将无法被 Wireshark 正确解析，SMB 会话也无法被真实服务端接受。建议按本报告修复后发布 v2.1.0，再进入实现阶段。

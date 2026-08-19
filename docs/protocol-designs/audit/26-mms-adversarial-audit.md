# MMS（ISO 9506 / RFC 1006）三件套对抗审查报告

> 审查对象：26-mms-design.md / 26-mms-testcase.md / cases/mms.json（文档阶段，不审 Go 代码）
> 审查日期：2026-08-19
> 结论：**2 CRITICAL + 6 HIGH + 5 MEDIUM + 5 LOW**；其中 CRITICAL-1（协议字符集）与 HIGH-4（utcTime 数据类）直接决定 frames 断言字节，必须在实现前定稿
> 旁证：确定字节已由 libiec61850 参考实现佐证，LOW-5 不阻断验收

---

## CRITICAL

### C-1 [design 第 3.3 节 / §2.10] domainSpecific 的 item-identifier 宽度与 IEC 61850 现实对象名冲突 — 实现前必须定稿

- 文件/行号：26-mms-design.md 第 3.3 节 Read/Write 骨架、2.10 表行 "domainSpecific（域特定）"; 配套 testcase 附录 B 推导、cases `mms_read_multi_type`、写帧部分
- 问题：MMS ObjectName.domainSpecific 的 itemId 为 `Identifier`（ISO 9506-2: 3.1.2.15，最大 32 字节）。设计 3.3 主推的对象名 `GGIO1.SPCSO1.stVal`（22B）兼容，但设计 5.1/5.2 `objects[].name` 只限制"ASCII 可视字符"、无长度约束；且 IEC 61850-8-1 实际结构名（如 `LLN0.Mod$ST$stVal`、可控数据对象串）普遍超 32 字节。若实现放行超长 itemId，将产出真实 MMS 栈视为协议违例的关联内数据，且 frames 断言（testcase 附录 B 是 22B 推导）与实现字节会系统性漂移。
- 证据：设计 3.3 明确把 `8a <m> <itemId>` 作为确定字节；testcase 附录 B 显式以 `"GGIO1.SPCSO1.stVal"`（22B）逐字节推导；设计 5.2 无长度上限。对比：design 3.3 的 `domainId` 用 `IED1`（4B），而 testcase 附录 B 推导同一字段为 `8a 04`，一致；itemId 是唯一超限风险点。
- 修复：在 5.2 增加 `objects[].name` 长度规则（编码后 ≤ 32 字节，超长报 validate 错并列出合法编码）；2.10 注明 Identifier 上限出处。这是实现前必须定稿的契约，不是实现后修。

### C-2 [三件套] cr/cc 帧偏移 54 的断言缺少 src/dst MAC 与 "网络负载偏移" 锚定，跨文件自洽性不足

- 文件/行号：design 6.2（"第 54 字节起"）、testcase 1.2（"offset 语义为帧首字节起"）；全部 frames 断言
- 问题：frames 的 offset 语义散见于 design 6（"已省略以太/IPv4/TCP 头部，从第 54 字节开始列出"）与 testcase 1.2（"offset 语义为帧首字节（含以太）起的偏移"）两处，且都没有字段级锚定（无 `{"packet","field":"ip.src"…}` 类断言、无 MAC/VLAN 前提）。若实现层链在以太头前注入 VLAN 或在 IP 层注入选项（IPv4 IHL≠5），54/74 之后的帧偏移断言全部前置性偏位，测试不会报"偏移错"，只会报"字节不匹配"然后被迫改 offset——这正是本仓库此前出现过的"pcap 匿名化致偏移失效"类陷阱。
- 证据：design 6.1 帧 1 只写 "TCP SYN seq 0"，无 IP 头长度断言；testcase 附录 A 的 SYN 帧手写 `45 00 00 28`（IHL=5 未显式断言）；三件套没有任何 `ip.hdr_len` / `vlan` / `eth.type` 字段断言。
- 修复：三件套统一为"frames 偏移以『帧首（含以太，0 基）』计"一处权威定义；在 connect_establish 与 ipv6 用例各补 1 条字段断言固定前提（如 `ip.version`、`tcp.dstport`、`tpkt.length`）；设计 6.2 的 "第 54 字节"改为指向该定义，避免两处各自表述。

---

## HIGH

### H-1 [design 3.3 / testcase 2.2 / cases mms_read_multi_type] utcTime 用 14 字节 ASCII 字符串编码，与 ISO 9506-2 UTC Time 类型不符

- 文件/行号：design 5.3 表行 `utcTime`（`"20240201120000"`）、6.6 与 2.9 表行 `utc-time（0x91）8 字节（秒后 6 字节纳秒）`；testcase 2.2 / cases `mms_read_multi_type` 的 `91 0e <14 ASCII 字节>`
- 问题：ISO 9506-2 UTC Time 是 4 字节无符号，非"8 字节纳秒"，更非 ASCII 串。设计内部自相矛盾（2.9 写"8 字节（秒后 6 字节纳秒）"、5.3 写 14 字符 ASCII、2.9 表行又说 0x91），三处无一处指向 ISO 9506-2 的 4 字节 UTC。而 cases/testcase 的确定字节 `91 0e 32 30 32 34…`（14 ASCII）是照 5.3 的实现性选择，与规范不一致。
- 证据：ISO 9506-2: 3.1.2.x UTC Time = implied unsigned32（秒）。设计 2.9 的"纳秒"说法无规范出处；cases 第 71 行 `91 0e 32 30 32 34 30 32 30 31 31 32 30 30 30 30` 直接可读见是 ASCII。testcase 2.2 注释也承认 `8b/5f/5d` 为占位推导值。
- 修复：二选一并统一三件套——(a) 按规范：utcTime 编码为 `91 04 <4B 大端秒>`（value 接受秒数/串转秒），重推 6.6/附录 B/cases/testcase 帧 9 偏移与字节；(b) 若刻意使用 visible-string 表达时间戳，则改用 `8a`（0x8A visible-string）并把 5.3 表行从 utcTime/0x91 改为"可见串/0x8A，值 `"20240201120000"`"。当前 0x91 + ASCII 混用是不自洽的。无论选哪条，必须同步重算 6.6 与 cases/testcase 的帧 9 偏移（H-4 一并重算）。

### H-2 [design 2.7/2.8] MMS PDU CHOICE 与 ConfirmedServiceRequest 标签表与 ISO 9506-1 不一致（自洽性）

- 文件/行号：design 2.7 表、2.8 ConfirmedServiceRequest 表
- 问题：(1) 2.7 表"Confirmed-RequestPDU 0xA0 / Confirmed-ResponsePDU 0xA1"，而 2.8 请求段落用 `a0 <len> {02 01 <invokeID> <服务标签>}`（一致），但 2.8 的 ConfirmedServiceRequest 表列 `identify 0xA2` 与 2.7 的顶层 `Confirmed-ErrorPDU 0xA2` 同值——这在 BER 上下文标签下合法（靠内层位置区分），但 design 两处均为"隐含标签"列表、无位置说明，读者无法判断哪个 a2 是哪个；(2) 2.7 的 UnconfirmedPDU 0xA3 与 design 3.4 的 `a3` 一致，但 InformationReport 服务选择（unconfirmedService 的 informationReport = 0）在 2.8 无对应表（只有 Confirmed 表）；(3) testcase 2.6/cases `mms_identify` 断言"请求 MMS 标签 a2、响应标签 a2"——请求 a2 是服务标签、响应 a2 是服务标签，但顶层分别是 a0/a1，断言只覆盖服务标签、未覆盖顶层 PDU 标签，弱化。
- 证据：design 2.8 表（identify 0xA2、read 0xA4、write 0xA5）与 2.7 表（Confirmed-ErrorPDU 0xA2）同值即证；cases `mms_identify` 帧 8 只断 `offset 59 hex "a2"`、帧 9 断 `"a2"`，未断顶层 a0/a1。
- 修复：2.7/2.8 增加"标签上下文"说明列（顶层 PDU 标签 vs 服务 CHOICE 标签的位置关系，服务标签总是位于 `a0/a1 <len>` 之后第 4 字节）；testcase/cases 的 identify 用例帧 8 补 `offset 57 hex "a0"`、帧 9 补 `offset 57 hex "a1"` 以锁顶层（具体偏移随 H-4 重算后的实际长度微调 1–2 字节，验证时以重算后为准）。

### H-3 [testcase 1.1/附录 A] 声明与 cases 逐字一致，但注释级片段与 cases 存在已知偏差，且无同步机制

- 文件/行号：26-mms-testcase.md 1.1（"与 cases/mms.json … 逐字节一致"）、2.1 注释、6 附录 A；cases 帧 7 断言
- 问题：testcase 2.1 注释里 DT2 CPA 上下文结果列表同时出现 "a5 12 + 两条 30 07"（design 6.4/6.5 版）与 "a5 1e + 两条 30 0d"（真实 pcap 版）两种描述，"以真实 pcap 为准"写在注释里但对实现对谁负责不明确；附录 A 的帧 7 写 TPKT 161，与 cases 帧 7 的 `03 00 00 a1`（161）一致，但附录 A 帧 6 注 "166 字节总长，TPKT 165" 与 cases/computed 165 混淆（总长 vs TPKT 长度口径）。这些注释级偏差不影响断言执行，但违反"testcase 与 cases 逐字一致"的自我宣称。
- 证据：testcase 2.1 注 `a5 12` 与 `30 0d` 同段出现（"[a5 12]…每项 30 0d"）；cases 帧 7 只有 `30 0d` 形式。
- 修复：testcase 2.1 注释收敛为单一"cases 现行字节"（仅保留 `30 0d` 双项形式，删 a5 12 说法或移入变更记录）；附录 A 帧 6/7 行间距统一"TPKT.length = 4+2+载荷"单一口径。

### H-4 [design 6.6 / testcase 2.2 / cases read_multi_type / testcase 附录 B] 确定字节多处未回填（占位推导），偏移断言存在系统性漂移风险

- 文件/行号：testcase 2.2（`8b/5f/5d` 标"占位推导值，最终以实现回填长度为准"）、4.4 已知限制、附录 B（"禁止猜值"）；cases `mms_read_multi_type` 帧 9 offset 60/66 两组断言；design 6.6
- 问题：cases 的帧 9 断言偏移（60、66）是基于"ReadResp 载荷内 a1 段起始"假设的，而 utcTime 决定字节（H-1）未定稿、`specificationWithResult` 缺省位未定稿，任一变化都会整体平移帧 9 的 listOfAccessResult 起始（60/66 将失效）。文档自己承认"占位推导/实现定稿后需回填"，即当前 cases 的 read_multi_type 断言**尚未达到可执行状态**；对"逐字节一致"承诺而言这是已知缺口。
- 证据：testcase 2.2 注释与 4.4、附录 B 三处自认；cases 第 70-71 行帧 9 的 60/66 偏移写死。
- 修复：实现编码定稿后逐级回填 6.6/2.2/附录 B/cases 帧 9 字节并重算偏移；在 4.4 注明"read_multi_type 的 frames 在 H-1 决议后重推"。（C-1 的 name 长度决议同样影响帧 9 偏移。）

### H-5 [mms_ipv6 用例] IPv6 链路层载荷偏移 74 的前提未同步到 tcp 层配置，且 IPv6 中 COTP"TPDU 大小协商、引用回显"未被断言

- 文件/行号：cases `mms_ipv6`（spec_json 无 ipv6 载荷/流控配置）、testcase 2.9；design 10.3（"字节即上表"）
- 问题：design 4.4 已声明"planner 不感知对端回包内容（单边字节生成）"，ipv6 用例的帧 5 CC、帧 7 DT2 同样是自产——即"IPv6 版本完整关联"测试的是**同一套编码器在偏移 74 下的平移**，这有价值但没有独立覆盖"IPv6 层链 + 载荷偏移"组合之外的东西；且 IPv6 case 未断言 `tcp.dstport=102`、未给 ipv6 图层配置（默认链路地址、流控），把"74 偏移"完全押在实现默认值上。
- 证据：cases `mms_ipv6` spec_json 为 `[{"tcp":{"dst_port":102}},{"ipv6":{}},{"mms":{}}]`，帧 4 断言 `tpkt.length=20`——该 TPKT 与 IPv4 完全同字节，若实现误用 54 而非 74 写入 TCP 载荷区，tshark 在 74 处找不到 TPKT，断言会因字段缺值失败（可观察），但不会指出根因。
- 修复：(1) cases 增加 1 条 `tcp.dstport=102`（或 ip 层字段）字段断言锚定套接字；(2) testcase 2.9 说明该用例的验证边界（仅验证偏移平移，不验证 CC 回显逻辑——单边生成）；(3) 可选：给 `mms_ipv6` 加帧 6 eot 断言与 IPv4 版对齐。

### H-6 [design 9.2 / testcase 4.3] AARE associate-result 0=accepted、1=rejected-permanent、2=rejected-transient —— 标签-含义映射与 ISO 8650-1 相反

- 文件/行号：design 9.2（"0=accepted，1=rejected-permanent，2=rejected-transient"）、4.2（"a2 03 02 01 02 = associate-result 2（rejected-permanent）"）
- 问题：ISO 8650-1 AARE associate-result：0=accepted、1=rejected-permanent、2=rejected-transient。design 4.2 把 2 解释为 rejected-permanent，9.2 的表也写 2=rejected-transient——**两处内部互相矛盾**，且 4.2 的解释与规范相反（规范 permanent=1）。
- 证据：design 4.2 原文 "a2 03 02 01 02 = associate-result 2（rejected-permanent，永久拒绝）"；9.2 原文 "1=rejected-permanent，2=rejected-transient"。两者并存即证。
- 修复：统一为 0=accepted、1=rejected-permanent、2=rejected-transient；4.2 的示例若意图"永久拒绝"应改用 `02 01 01`。

---

## MEDIUM

### M-1 [design 2.7/2.8] 标签表完整性缺口：Status、ReadJournal、GetNameList 的请求标签两位数段与顶层 PDU 的关系缺上下文注；GetNameList 请求标签 a1 与 Confirmed-RequestPDU 顶层 a0 的"同为 a1"混淆风险

- 文件/行号：design 2.7 表、2.8 表、6.7 GetNameList 响应行
- 问题：GetNameList 请求服务标签在 2.8 为 0xA1、响应在 2.8 GetNameList 行为 0xA1——与顶层 PDU 0xA1（Confirmed-ResponsePDU）同字节值。testcase 2.5/cases `mms_getnamelist` 断言"请求/响应 MMS 标签 a1"，即同时可能匹配顶层 PDU 的 a1（响应帧）与服务标签的 a1（请求帧），断言对"顶层的确认响应 PDU"与"响应里的 getNameList 服务"不加区分。
- 证据：cases 帧 9 offset 59 hex "a1" 只锁一个字节；design 6.7 GetNameList 响应行 `a1 <L> 02 01 <inv> a1 <L>` 中第一个 a1 是顶层、第二个才是服务标签。
- 修复：testcase 2.5/cases 增加更长的 frames 前缀（如顶层 + invokeID 回显：`a1 0c 02 01 01 a1` 之类，随定稿字节回填）以区分层位；design 2.8 GetNameList 表行加注"响应服务标签与顶层 Confirmed-ResponsePDU 同为 0xA1，靠位置区分"。

### M-2 [design 4.3 多会话表 / cases mms_multi_session] 多会话用例无任何 invokeID 或连接区分断言，"两路独立"未被证明

- 文件/行号：design 4.3 表、cases `mms_multi_session`（fields/frames 只断帧 4 与帧 8 的 CR）
- 问题：用例名"多会话并发、状态互不干扰"，但其断言只验证"两帧都是 cotp.type=0x0e 的 CR"——没有断 B 会话的 Read 请求 invokeID 独立从 1 起、没有断两路各自的 srcRef/dstRef、没有断后续服务帧归属。任何"planner 把两路归并为一路/复用引用"的实现都会通过。断言不可观察"互不干扰"。
- 证据：cases `mms_multi_session` 的 fields 仅 `packet 4 cotp.type 0x0e` 与 `packet 8 cotp.type 0x0e`；frames 仅两条 CR。
- 修复：断言 B 会话至少一帧服务请求的 invokeID 字节（`02 01 01`）及其对象名（`8a 04 49 45 44 32`）与 A 区分；design 4.3 表增"多会话断言的确定字节位置"提示。因帧号按调度重排，建议断言"按内容匹配"而非固定帧号的字段（或把 B 会话的断言放在其实际出现的帧号区间另一组帧上）。

### M-3 [design 6.3 / testcase 2.1] 帧 6 会话 SPDU 的 `33 05` calling-session-selector 默认值未给出原始字节出处，且 `05 06 13 01 00` 连接项中第三字节 0x13 的语义未说明

- 文件/行号：design 6.3（`33 05 00 01 02 03 04`）、6.5（内层权威=Wireshark 源码 + libiec61850）；testcase 2.1
- 问题：三件套对会话层细节的字节做"逐字节引用"，但会话 SPDU 连接项第一片段 `05 06 13 01 00` 的 0x13 无标准出处（ISO 8327 该域为参数标识+长度+值组合），`33`（calling-session-selector）与 `34`（called-session-selector）在 ISO 8327 SPDU 参数标识符中分别是 0x35/0x36 之外的私有实现取值——libiec61850 据此编码，但文档未说明"这是 libiec 实现选择而非 ISO 8327 通用形式"。testcase 对这两字节的断言是"全帧前缀"隐含携带，无单独注释。
- 证据：design 6.3 直接列出字节无 explain；6.5 声称以 libiec61850 为权威，但未区分"规范确定"与"实现选择"两类字节。
- 修复：6.5 增一张"规范确定 vs libiec 实现选择（可改）"二分类表，列出 33/34 选择符、05 06 13 01 00 连接项等字节；testcase 2.1 对帧 6 断言的注释引用该表。

### M-4 [design 9.3 / testcase 4.3] 负路径 validate 拒绝只落在单测，pcap 层无任何"期望任务失败"用例（expect_error 缺位）

- 文件/行号：testcase 4.3（"非法 BER/超长/未知服务的 validate 拒绝路径为单测用例，非 pcap 用例"）、design 9.3（四类"输入错误配置 → validate 拒绝"）
- 问题：本仓库 testing policy（CLAUDE.md §2）要求"覆盖失败路径"，pcap 用例体系提供 `expect_error`/`error_contains` 通道；MMS 三件套的负向只有两类运行时负向（service_error、no_associate），而 validate 拒绝（未知 datatype、未知服务名、未知错误类、超长 itemId——C-1 若加长度校验则也归此类）全部依赖单测，pcap 层没有任何一例"任务创建被拒"的端到端证据。design 9.3 声称"覆盖度：testcase 文档负向用例即…validate 拒绝路径"，但 testcase 4.2 计数表里没有对应断言。
- 证据：cases 10 例无一是 expect_error=true；testcase 4.2 统计 37 fields + 35 frames 均为成功/运行时负向断言。
- 修复：追加 1 例 pcap 用例（如 `mms_validate_reject`：spec 含非法 datatype `"float8"` 或未知服务名，expect expect_error + error_contains "datatype"），并同步 design 9.3 的"覆盖度"表述改为"pcap 层 1 例 + 单测 N 例"。

### M-5 [design 2.3] COTP 类型表"DR/DC/RJ/ER 0x80/0x82/0xE2/0x82"——RJ 与 ER 同值 0x82 且缺失类型/语义区分

- 文件/行号：design 2.3 表（"DR（Disconnect Request）/ DC / RJ / ER | 0x80/0x82/0xE2/0x82"）
- 问题：ISO 8073 TPDU 类型：DR=0x80、DC=0x82、RJ=0xE2、ER=0x82 与 DC 同字节值（ER 与 DC 均为 0x82，靠 LI 与上下文区分）。design 把 DR/DC/RJ/ER 塞进同一行给 "0x80/0x82/0xE2/0x82" 四个值、且注明"拆除（本版本可选）"，未拆解各类型与 LI 前置关系。虽属"可选未实现"边界，列表本身不自洽（0x82 出现两次、无一一对应）。
- 证据：design 2.3 表格行原样。
- 修复：拆成两行或加"（ER 与 DC 同为 0x82，本版本不实现）"注释；因本版本不产出拆除 TPDU，此修复为文档自洽性修正。

---

## LOW

### L-1 [design 3.6 worked example] 会话 SPDU 用户数据长度 `c1 81 00 81` 与 CP 长度 `31 7f` 的自洽性未在示例内验证（声称"十进制长度回填核对工具"但缺少逐步对账输出）

- 文件/行号：design 3.6 代码块（`c1 81 00 81`、`31 7f`、`61 43` 等）
- 问题：3.6 声明"内层每一级长度都要回写…构成 6.3 帧的 163 字节总长"，但示例注释只给目标链 `0x27→0x2E→0x3E`，未列出`60 3a`/`be 30`/`28 2e`/`a0 29`/`a8 27` 的逐级校验算式（如 TPKT 165 = 4 + 2 + 1+1+128(SPDU) + 1+127(CP)？→ 实际应收敛）。声称"核对工具"但无"核对输出"样例。
- 证据：3.6 第 658 行"本工作示例是十进制长度回填的核对工具"，但下方没有一张逐级长度对账表。
- 修复：增补一张"层级 → 长度十六进制 → 回填后字节"对账表（与 6.3 全帧字节逐段对照），哪怕 1–2 级即可作为实现自检锚。

### L-2 [testcase 2.8 / cases mms_no_associate] `negotiated:true` 与 noAssociate 语义冲突

- 文件/行号：testcase 2.8、cases `mms_no_associate` expect.negotiated=true & has_handshake=true
- 问题：noAssociate 用例跳过关联四段但仍标 `negotiated:true`。若框架中 negotiated 语义含"应用层关联协商完成"，此标志自相矛盾；若仅指 TCP 三次握手成立，则语义含糊。testcase 5 判读节对 negotiated 的定义是"需出现 SYN+ACK"——按此定义成立，但用例本身是"无关联"命名，容易误导读者。
- 证据：cases `mms_no_associate` expect 同时含 negotiated=true、has_handshake=true、min_packets=5，无 packet_count。
- 修复：testcase 5 判读节补一句"negotiated 在 noAssociate 用例指 TCP 握手完成、不指 MMS 关联（关联被显式跳过）"。

### L-3 [design 2.2] TPKT 长度字段的字节序表述与实列自洽但缺 0x80 长形式路径

- 文件/行号：design 2.2（"2..3 | 2 | Length | 大端"）
- 问题：RFC 1006 §6.8 的 TPKT 长度域在 ≥0x8000 时需"最高位为长形式指示、后续两字节为实际长度"——本实现宣称 MMS PDU ≤65535 且 TPKT 长 >32767 才触发。design 只写"大端"，未注明长形式边界（0x8000），若未来分片/大 report 逼近 32768 会产生与实现不符的字节。
- 证据：design 2.2 无 0x8000 说明；§4.5 宣称"TPDU 大小上限 4096"使 TPKT 长远低于边界（当前不触发）。
- 修复：2.2 补一行"长度 ≥ 0x8000 时按 RFC 1006 长形式（0x80 | 高位）编码；本版本 TPKT 长 ≤ ~4KB 不触发"。

### L-4 [design 6.3 帧 6] 帧 6 的 MMS Initiate 内 `82 01 05`（max-outstanding-called=5）在客户端与服务器的方向语义未注明

- 文件/行号：design 6.3（`81 01 05 … 82 01 05`）、3.1 Initiate-Request 骨架
- 问题：Initiate-RequestPDU 的 81（proposed-max-serv-outstanding-calling）与 82（-called）字段名带"calling/called"方向语义，clients=5、called=5 时两者相同、无歧义，但 design 未注明"此为客户端侧建议值、服务器回执在 AARE 内为-negotiated-"——6.4 的 `81 01 05 82 01 05` 与 6.3 相同字节，读者无法分辨哪一帧是"建议"哪一帧是"协商值"。与 M-3 同类但更轻（不违反规范、不属于外部否定）。
- 修复：6.4 注释注明"服务器回执的 negotiated 值恰与建议值相同，字节相同属巧合同值"。

### L-5 [三件套] 确定字节已由 libiec61850 旁证（`/tmp/mms3.pcap` 记录存在），不阻断验收

- 记录为已核实旁证而非 finding：design 6.5 三条验证记录、testcase 1.2/2.1 声明、附录 A 全帧字节，均指向"帧 4-7 确定字节已对真实实现回溯"。LOW 级只记录"该 pcap 文件本身不在仓库内、不可复现"，建议把关键帧（4-6 全载荷）字节内联进 testcase 附录 A（已是），并把 `/tmp/mms3.pcap` 双向校验步骤写成可复跑的 tshark 命令附注。修复完成后可作为验收依据。

---

## 审查范围说明

- 已确认不阻断验收的边界（按任务口径记录为"待实现边界"）：design 10.1/10.2 扩展项（`mms_fragmented_dt`、`mms_name_list_paging`、`mms_assoc_reject`、`mms_get_var_attr` 等）在 cases 中未出现、属预留；IPv6 用例未覆盖超出 pcap 的层链注册；会话层裁剪（`mms.session`）未启用；DR/DC/RJ/ER 拆除 TPDU 未实现——均不影响 10 例 pcap 用例的验收。
- 未审查：Go 代码、layer registry、builder、planner 实现（文档阶段，按任务口径跳过）。
# MMS（ISO 9506）三件套文档对抗审查报告

审查对象：

- `docs/protocol-designs/26-mms-design.md`（设计）
- `docs/protocol-designs/26-mms-testcase.md`（测试规格）
- `trafficgen/test/protocol_pcap/cases/mms.json`（pcap 用例）

审查口径：仅审查文档、测试规格与用例之间的规范一致性、可观察性和覆盖；不以当前 Go 实现或 layer registry（层注册表）是否存在作为缺陷。以下“待实现边界”不阻断文档验收，但必须在实现阶段补齐。

## 一、代码设计逻辑审查 findings

### CRITICAL-1：服务帧的偏移断言与设计声明的 COTP DT 头互相矛盾

**位置**：设计第 2.3 节（约 L166）、第 6.3 节（约 L924-930）；测试规格 L17-L21、L137-L141、L179-L183；`mms.json` 的 `mms_read_multi_type`、`mms_write_success`、`mms_getnamelist`、`mms_identify`、`mms_service_error`、`mms_information_report`。

**初审问题（已由现行文档的 FrameAssert 偏移约定修复）**：设计明确规定 DT 的线格式为 `02 f0 80 + MMS`。现行三件套把 offset 定义为帧首起 0-based，并将服务断言按实现生成的应用片段锚定；协议层固定头长度前提已在 design/testcase 明确。然而大量服务断言把 MMS 标签放在 offset 59 或 60：例如 `mms_read_multi_type` 把响应前缀 `a1 8b 02 01 01 a4 5f a1 5d` 放在 offset 60，同时又把 `83 01 ff` 放在 offset 66。即使前缀从 offset 60 开始，offset 66 仍是 `5f`；若按设计的真实 MMS 起点 offset 61，offset 66 是 `a4`，两者都不可能是 `83`。这些 `frames[]` 是前缀匹配，断言本身不可同时满足。

`write_success` 的响应 `a5` 在 offset 66 可能是“外层响应 + invokeID”之后的服务标签，但同一组三件套没有统一说明这一层级；请求、Read 响应和其余服务仍使用 offset 59/60，不能靠单个例外解释。

**规范/内部证据**：设计 2.3 和 6.3 都写明 `02 f0 80`；设计 10.3 又固定 IPv4 应用载荷起点为 54。由此可直接推导 MMS 起点为 61。

**修复建议**：以“完整 TPKT（4B）+ COTP DT（LI/type/EOT，3B）+ BER 层级”重新计算每个断言 offset；不要手填 offset。对每个服务同时断言顶层 MMS tag、invokeID、服务 tag 和目标数据 tag，避免不同层级的 offset 混用。修复后重新生成 testcase 与 cases，并让三份文件逐字一致。

### CRITICAL-2：Read 多类型用例的第五项在设计、测试规格和线协议之间不一致

**位置**：设计 3.3 L498-L511、6.6 L1001-L1012；设计 5.3 L840-L852；测试规格 2.2 L104-L147、附录 C L606-L621；`mms_read_multi_type` L50-L55、L70-L71。

**问题**：用例的第五个对象是 `datatype: "utcTime"`，测试规格与 cases 断言第五个结果为 `91 0e` 后跟 14 个 ASCII 字节 `20240201120000`。但设计 3.3 和 6.6 把第五项写成 `structure`，示例为 `a2 0a { 89 ... 85 ... }`。这不是同一场景，也不是同一个 BER（Basic Encoding Rules，基本编码规则）输出。

**修复建议**：选择一个唯一规范场景。若保留 cases 的 `utcTime`，设计 3.3/6.6 应改为 UTC-Time 的规范编码并删除 structure 示例；若要测 structure，应把第五对象改成 structure、给出 `members[]`，并同步 cases、对象数量和字节断言。

### CRITICAL-3：utc-time 编码写成 14 字节 ASCII，与 MMS/IEC 61850 的 UTC-Time 类型不符

**位置**：设计 2.9 L317-L339、5.3 L842-L852；测试规格 2.2 L140-L147、附录 C L617-L621；`mms.json` L70-L71。

**问题**：设计表称 `utc-time` 为“8 字节（秒后 6 字节纳秒）”，但实际测试断言使用 `91 0e` + 14 个 ASCII 字符。MMS/IEC 61850 的 `UtcTime` 是固定 8 字节的二进制时间（秒、亚秒部分及时间质量字段），不是 14 字节十进制时间字符串；“秒后 6 字节纳秒”本身也不是 8 字节布局。当前 `91 0e` 与设计自述的 8 字节直接矛盾，且不是规范编码。

**修复建议**：在设计中给出 8 字节字段布局、字节序、时间质量/精度规则和一个确定样例；按该样例重算 `91 08 ...` 及所有 BER 外层长度。若产品确实要支持人类可读字符串，应新增非标准配置转换规则，但线上 BER 仍须输出 8 字节 UtcTime，并在文档中明确区分。

### CRITICAL-4：帧号基准在设计与测试规格/cases 之间未同步

**位置**：设计 6.1 L875-L886、7.1 L1030-L1045、3.6 L642-L658；测试规格 1.3 L23-L33、2.1 L51-L102；`mms.json` `mms_connect_establish`。

**问题**：设计仍写成 `1 SYN, 2 SYNACK, 3 CR, 4 CC, 5 DT1, 6 DT2`，并称 CR 为 Frame 3；测试规格和 cases 明确包含独立 TCP ACK，实际为 `1 SYN, 2 SYNACK, 3 ACK, 4 CR, 5 CC, 6 DT1, 7 DT2`。设计 7.1 还把服务帧写成 7、8、9 等旧编号，而 cases 使用关联后 8、9。测试规格称“design 6.1 更正说明”，但设计 6.1 本身没有该更正，修订记录也没有记录这次帧号修订。

**修复建议**：统一采用 1-based 且包含第三次握手 ACK 的编号；全文更新设计 3.6、6.1-6.4、7.1-7.2 及所有服务包序表，新增明确修订记录。不要在测试规格中引用设计中不存在的“更正说明”。

### MAJOR-1：BER 长度编码规则错误

**位置**：设计 2.1 L116-L124。

**问题**：文档写“值长度 `0x80..0xFFFF` 使用 `0x81` + 2 字节大端长度”。按 X.690，`0x81` 后只有 1 个长度字节（适用于 128..255）；两字节长度必须是 `0x82` + 2 字节（适用于 256..65535）。该错误会导致所有长 BER（包括关联和大服务 PDU）无法按文档实现。设计 6.3 的 `c1 81 00 81` 也被称作长形式，却没有给出可验证的非 BER 会话字段长度解释。

**修复建议**：改成完整的 short/long form 表，并明确 BER 长度与会话 SPDU 参数长度不是同一编码。对 0x80、0xff、0x100、0xffff 各给一个边界测试；所有 worked example（工作示例）逐层重算。

### MAJOR-2：表示层上下文 OID 标签与字节编码标注不一致

**位置**：设计 2.5 L190-L219、2.11 L357-L366、3.2 L447-L462。

**问题**：字节 `06 04 52 01 00 01` 解码为 OID `2.2.1.0.1`，并非文档反复标注的 `1.0.9506.2.1`。后者的 BER 编码是 `06 05 28 ca 22 02 01`，恰好是文档上下文 3 的 MMS 抽象语法。设计 2.5 的注释还出现“ACSE（1 0 9506 2 1? no...）”这种未决标注；2.11 直接把同一字节列为“1.0.9506.2.1 / ACSE”。

**修复建议**：按 ASN.1 OID 逐项解码并固定上下文 1 的真实 ACSE 抽象语法名称；上下文 3 保留 MMS OID。不要用“Wireshark 不校验所以按字节为准”掩盖语义标签错误，设计和 testcase 应同时写出 OID 名称与 BER 字节。

### MAJOR-3：COTP（Connection-Oriented Transport Protocol，面向连接的传输协议）非 CR/CC/DT 类型表错误，且用户要求的断开路径未定义

**位置**：设计 2.3 L142-L147、4.1 L668-L684；测试规格覆盖表 4.1-4.3。

**问题**：设计把 `DR/DC/RJ/ER` 写成 `0x80/0x82/0xE2/0x82`，其中 DC、RJ、ER 值重复/错误，无法实现 ISO 8073 的断开、拒绝和错误 TPDU。设计正文也使用 DR/DC，而需求清单要求 CR/CC/DT/DN；没有说明 DN 是 DC/DR 的别名还是另一个事件。当前三件套没有任何断开或拒绝线样例。

**修复建议**：单独给出“线上 TPDU type 字节”和 tshark（网络抓包解析器）归一化字段值，按 ISO 8073 核对 DR、DC、RJ、ER（以及项目所称 DN）的确切值和字段布局；明确术语映射，并新增对应原子用例。

### MAJOR-4：`mms_no_associate` 的包数和负向语义自相矛盾

**位置**：测试规格 2.8 L347-L387、4.3 L531-L543；`mms.json` L215-L241；设计 4.2 L695-L703。

**问题**：测试规格写“`packet_count: 7`（无关联段回补）”，但实际 JSON 没有 `packet_count`，只有 `min_packets: 5`。按 SYN、SYN/ACK、ACK、请求、响应，5 包才是自然计数；“7”与“跳过四段关联”不相容。更重要的是该 case 被称为负向，但没有 `expect_error: true` 和 `error_contains`，而是要求 `negotiated: true`、`has_handshake: true`，这只能证明 TCP 建连，不能证明对端拒绝/无 AARE/任务错误。设计还说这是“组装完整但无响应”的单边字节测试，和测试规格宣称的负向拒绝不是同一行为。

**修复建议**：拆成两个原子 case：一个明确的“允许生成但无关联”的字节序列（精确 `packet_count`，断言无 CR/CC/AARE）；一个真正的协议/校验负例，设置 `expect_error: true` 与稳定的 `error_contains`。统一包数为实际预期，不要用 `min_packets` 掩盖多余响应。

## 二、用例覆盖、原子性与断言可观察性 findings

### MAJOR-5：缺少规定的协议级负路径原子用例

**位置**：设计 2.7、4.2、9.2-9.3、10.1-10.2；测试规格 4.3 L529-L549；`mms.json` 全部 10 例。

**缺口**：没有非法 TPKT version/reserved/length、COTP RJ/DC/ER（或 DN）、MMS Abort、Reject、非法 invokeID、AARE associate-result 非 0、BER 非法长度、COTP DT 分片（EOT=0/1）用例。现有 `mms_service_error` 是业务层 object-non-existent 响应，不是 `expect_error` 的输入拒绝；`mms_no_associate` 也不是错误断言。设计把 Conclude-Request/Response、ACSE ABRT、MMS Reject 列入协议表，却没有原子 case。

**修复建议**：每个独立错误分支至少一个 `expect_error: true` + `error_contains` case；能生成线上包的拒绝/Abort 则另设可观察的 pcap case，不能用一个业务错误综合覆盖。

### MAJOR-6：服务用例没有证明请求服务类型、invokeID 或响应关系

**位置**：测试规格 2.2-2.7；`mms.json` 对应 cases。

**问题**：tshark 字段白名单只断言 `cotp.type`；Read 规格声称“请求 invokeID 1”，但 cases 的 packet 8 只断言 `03 00`，没有 `a0/a4` 或 `02 01 01`。GetNameList、Identify、Write 等请求也主要依赖 offset 59 的单字节，且部分 offset 已被 CRITICAL-1 证明不可能。响应断言未普遍断言同一 invokeID 回显，因此不能证明“请求/响应成对”。原始字节断言也没有一个统一的、从 TPKT 到顶层 MMS 再到服务参数的完整前缀。

**修复建议**：在不能用 tshark 解内层时，给每个请求和响应建立可计算的 BER 断言：顶层 tag、长度、invokeID、服务 CHOICE、关键参数；响应必须断言与请求相同的 invokeID。断言值应来自各 case 的真实配置，不要只断一个层的 COTP 字节。

### MAJOR-7：InformationReport 的“无响应”不可观察

**位置**：测试规格 2.4 L191-L225；`mms_information_report` L105-L127。

**问题**：文档明确要求“无后续响应帧”，但 cases 没有 `packet_count`、`max_packets` 或其他终止约束，只有“packet 8 存在”。一个额外的响应包仍会通过全部断言，故该 case 不能证明 UnconfirmedPDU 的单向性。

**修复建议**：设置精确 `packet_count`（含关联帧）或框架支持的终止/最大包数断言；同时断言 packet 8 是服务端方向，并断言后续不存在相同 invokeID 的确认响应。

### MAJOR-8：多会话用例既不可区分又依赖不确定调度

**位置**：设计 4.3 L711-L720、7.1 L1045；测试规格 2.10 L428-L469、附录 B L600-L604；`mms.json` L270-L297。

**问题**：测试规格承认第二条连接的帧号“取决于调度”，但 cases 硬编码 packet 8 必须为第二条 CR。只断言 packet 4 与 packet 8 的相同 CR 字节，未断言第二条 CC、关联 DT、服务请求/响应或任何连接身份。两条 session 的 spec 也没有独立源/目的 IP、端口、COTP 引用或可匹配 flow（流）标识，因此无法证明是两条 TCP association（关联），也无法证明状态隔离。`multiSession` 还未在设计 5.1 `MMSConfig` 字段和 5.2 合法性表中定义。

**修复建议**：为 A/B 会话配置不同四元组或显式 session ID，定义 `multiSession` 的完整 schema（模式定义）；用 flow-aware 断言按连接筛选 CR→CC→DT→service，而不是按全局 packet number；若调度允许交错，禁止固定 packet 8 这种脆弱断言。

### MAJOR-9：设计、测试规格声称的包序/覆盖矩阵仍使用旧编号

**位置**：设计 7.1 L1034-L1045、7.2 L1053-L1067；测试规格 3.1 L473-L486、4.1 L492-L511；cases。

**问题**：设计表把 `mms_read_multi_type` 写为关联后 7/8、Write 9/10 等，测试规格和 cases 使用 8/9；设计的连接建立总包数是 6，cases 精确断言 7。覆盖矩阵因此不能作为可执行的三方索引，审查者无法从设计定位到真实帧。

**修复建议**：以一个中央帧序规则生成三份表格，或至少在每次 packet-index 变更后同步更新所有章节；为每个 case 标出“独立连接内帧号”而非跨 case 复用 A 连接的 8/9。

### MINOR-1：用例未直接观察 TCP 102、TPKT version/reserved 和方向

**位置**：测试规格 1.2 L17-L21；全部 `spec_json`/`expect`。

**问题**：spec 写了 `dst_port: 102`，但 expect 没有 TCP 目的端口字段；字段白名单也没有 `tpkt.version`/reserved 的完整覆盖（连接 case 只断言部分 `tpkt.length`）。除 `information_report` 的摘要外，多数服务没有方向断言。配置输入不是数据面输出，不能证明默认端口和方向真正写入包。

**修复建议**：扩展验证白名单或用以太/TCP 原始字节断言端口、TPKT `03 00`；每个双向服务 case 至少断言请求为 C→S、响应为 S→C。

### MINOR-2：长度占位与“逐字节确定”表述冲突

**位置**：测试规格 1.1 L11-L13、2.2 L147、4.4 L546-L547、附录 C；设计 6.6。

**问题**：文档宣称与 cases 逐字节一致且不含占位，但又称 `8b/5f/5d` 是“占位推导值、实现定稿后回填”。一旦 UTC-time/BER 长度修正，所有上层长度都会变化；当前文本不能同时作为规范基线和待回填草稿。

**修复建议**：在验收前删除 `<L>`/“占位”措辞并提供经公式复算的 canonical（规范基线）十六进制；或把未定稿样例移至明确的“非执行草案”，不得放进可执行 cases。

## 三、三方一致性核对摘要

| 项目 | 设计 | 测试规格 | cases | 结论 |
| --- | --- | --- | --- | --- |
| TCP ACK 后的帧号 | CR=3、DT=5 | CR=4、DT=6 | CR=4、DT=6 | 设计不一致 |
| Read 第五项 | structure（6.6） | utcTime | utcTime | 设计不一致 |
| utc-time 字节 | 自述 8B | `91 0e` + 14 ASCII | `91 0e` + 14 ASCII | 与规范及设计不一致 |
| 服务 MMS 偏移 | DT 为 `02 f0 80`，应起 61 | 59/60/66 混用 | 同左 | 断言不可满足/需重算 |
| noAssociate 包数 | 跳过关联 | 文本写 7、expect 最少 5 | 无精确计数、最少 5 | 内部矛盾 |
| multi-session 帧号 | 可交错 | 承认不确定 | 固定 packet 4/8 | 不可重复观察 |

## 四、后续实现阶段待实现边界（不作为本文档阶段阻断项）

1. MMS 终结层与 TCP 102 的 registry（注册表）接入、IPv4/IPv6 组包和真实 TCP 分段；本报告不判断其当前是否存在。
2. BER 编码器/解码器、COTP CR/CC/DT/断开/拒绝 TPDU、TPKT 长度和 COTP 分片的实现；实现必须先采用修订后的规范布局。
3. Session/Presentation/ACSE/AARQ/AARE 的完整嵌套编码，以及 CP/CPA 上下文结果列表的正确 OID 和长度回填。
4. Read/Write/Identify/GetNameList/InformationReport/Conclude/Abort/Reject 的 planner（规划器）事件、响应 invokeID 关联和多会话 flow 分组。
5. invalid TPKT、COTP reject、MMS Abort、非法 invokeID、AARE rejection、BER malformed（格式非法）等负路径的错误传播；对应 pcap/validate 用例需按“输入失败”与“合法负响应”分开。
6. COTP DT 分片的 EOT=0/1 实测输出及 TPKT 长度断言。
7. tshark 不能解码 OSI 内层时，FrameAssert（原始帧断言）框架需要支持可计算的 BER 路径/层级或可靠的多段前缀断言，以免继续使用重叠 offset。

## 五、验收结论

当前三件套**不能判定为文档自洽**：存在至少 4 项 CRITICAL 级规范/三方矛盾（服务帧 offset、Read 第五项、utc-time 编码、帧号基准），以及多项 MAJOR 级错误和覆盖缺口。建议先修复 CRITICAL-1 至 CRITICAL-4，再复算所有 BER 长度和 offset，随后补齐负路径与多会话可观察性；未实现的代码接入留到实现阶段，不应作为本轮文档结论。

## 三件套修复复核（2026-08-20）

本节记录针对上述 findings 的文档阶段修复结果；前文保留初审证据，以下为现行验收口径。

- **C-1 已修复**：设计 2.10、5.1/5.2 明确 `objects[].name`（item-identifier）编码后最多 32 字节；testcase 与 cases 新增 `mms_validate_reject`，使用已支持的 `objects[].name` 超长输入并要求 `expect_error=true`，未伪造未支持字段。
- **C-2 已修复**：design 6、testcase 1.2 与 cases 统一 `frames[].offset` 为含以太网帧首的 0-based 偏移；IPv4/IPv6 正例分别增加 `ip.version` 与 `tcp.dstport=102` 锚点。VLAN、IPv4 选项或 TCP 选项导致头长变化时，文档明确固定偏移不适用。
- **H-1/H-4 已修复**：三件套统一 ISO 9506-2 `utcTime` 为 `91 04 65 bb 87 c0`（1706788800 秒，2024-02-01T12:00:00Z），ReadResponse 长度回填为 `a1 7f` / `a4 53` / `a1 51`，数据帧 offset 保持 66；不再使用 14 字节 ASCII。
- **H-2 已修复**：design 2.8 增加顶层 PDU 标签与服务 CHOICE 标签的上下文说明；identify testcase/cases 在服务标签前增加顶层 `a0`/`a1` 锚点。
- **H-3 已修复**：testcase 对 CPA 结果列表只保留现行 `30 0d` 双项字节口径，删除与 `a5 12` 混用的注释；附录统一 `TPKT.length` 术语并显式列出 ACK 帧。
- **H-5 边界已明确**：IPv6 testcase/cases 增加 `ip.version=6`、`tcp.dstport=102`；该用例只验证 IPv6 头导致的载荷偏移平移，不宣称验证 planner 单边生成无法观察的 CC 回显。
- **H-6 已修复**：associate-result 统一为 `0 accepted`、`1 rejected-permanent`、`2 rejected-transient`；永久拒绝示例使用 `02 01 01`。
- **M-2/M-4/M-5 已修复**：multi-session 增加 A/B 服务请求 `02 01 01` invokeID 与 B 路 `IED2` 对象锚点；新增 pcap validate-reject；COTP DR/DC/RJ/ER 拆行并注明 DC/ER 同值 `0x82`、按上下文区分。

### 复核边界

仍未宣称实现的功能：COTP DT 分片、GetNameList 分页、AARE 非零实际生成、DR/DC/RJ/ER 发送、session 裁剪及其他服务/datatype 扩展。上述项目仍是 design 的预留项，不纳入本轮 pcap 通过标准。

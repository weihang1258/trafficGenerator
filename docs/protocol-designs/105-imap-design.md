# #105 imap（IMAP4rev1/IMAP4rev2 · 互联网邮件访问协议，TCP 143 / IMAPS 993）设计契约

> 版本：v1.0.0（P-PIPE 文档轨批次二 · as-built 型；修订记录见 §15）
> 日期：2026-09-29
> 车道：文档车道 #105 imap（批次二 10 协议）
> 旧基线：**无**（本协议从未有过 `NN-imap-design.md`；`docs/protocol-designs/` 下无 imap 任何前稿，`ls | grep -i imap` 实测为空）。本版为**首次成文**，全部内容 as-built 逆向定稿。
> 存量用例：`trafficgen/test/protocol_pcap/cases/imap.json`（**84 例**，机读实测：65 正 + 19 负；ID/顺序/包数/断言与本文逐条对齐）
> 规范基线：① **RFC 9051**（IMAP4rev2，2021，现行标准；标签事务 §2.2.1、literal §4.3、状态机 §3、命令 §6）；② **RFC 3501**（IMAP4rev1，2003，历史标准；本仓代码注释与错误文案大量引此版章节号，如 §2.2.1 tag / §5.1.3 Modified UTF-7 / §6.2.2 AUTHENTICATE 取消）；③ **RFC 2177**（IDLE 扩展；§3 续行 `+ idling`、§4 DONE 与 29 分钟超时 BYE）；④ **RFC 6855**（UTF-8 信箱名）；⑤ **RFC 7162**（CONDSTORE，HIGHESTMODSEQ 缓存失效）；⑥ **RFC 2045/2046/2183**（MIME 体构造：Content-Type/boundary/base64 折行/Content-Disposition）；⑦ **RFC 879**（MSS 下限 536）；⑧ 本机 tshark 3.6.14 `imap.*` 字段表（**18 字段**，`tshark -G fields` 实测）与 **81 份实测 pcap**（`/tmp/mcp-pcaps/imap/`，65 正 + 16 负；包数/字段/帧字节的唯一权威）；⑨ 本仓库落码（`internal/protocol/imap/` 四文件 + 接线，§11）。
> 白话一句：**邮件客户端的"带编号点单"——每句话前面挂一个自己编的单号（tag），服务端答话时把单号原样抄回来；有些答话太长，先说"我要说 N 个字"，然后把 N 个字倒出来（literal）；整个会话分四步走（没登录 → 登录了 → 打开信箱 → 退出），走错步子服务端回 NO/BAD。**

## 0. 沿革、基线继承与旧稿校正声明（门1 必答：基线继承关系）

**本协议无前稿**——`docs/protocol-designs/` 下不存在任何 `imap-*` 文件（机读实测）。因此本版**没有**「承旧稿 / 旧稿过时」的二分表（对照 101-opcua §0 的 17 行校正表：那份表的每一行都以旧稿为被审对象，本协议无此对象）。

本协议的实际"沿革"是**代码内部的一次迁移**（D-IMAP-1），必须写清：

| # | 事项 | HEAD 实测（2026-09-29） | 结论 |
|---|---|---|---|
| 1 | **D-IMAP-1 层链迁移**（扁平 → `[ip,tcp,imap]`） | 已完成。`registry.go:1590` 注册 `imap`（`CategoryTerminal`，`DependsOn ["tcp"]`，`OptionalOn ["tls"]`，**Fields 5 键**）；`chain_planner_translate.go:2667` 层内翻译分支；`strategy_convert.go:1189` `case "imap"`（扁平路径，含 `setDefaultDstPort(&spec, cfg, 143)`）；`strategy_convert.go:8889` 顶层 `imap` 子映射 presence 判死；`protocols.go:45` `"imap": true`；`chain_planner.go:1212` 缺省目的端口 143、`:952` 源端口 0 保持 0 | **迁移完整**；红例族 `imap_migrate_test.go`（4 红例）+ `imap_mime_translate_test.go` 在案 |
| 2 | 存量 84 例顶层形状 | 83/84 例 `spec_json` 顶层键 = **`{layers}` 仅此一键**；1 例（`imap_t064_presence_reject`）为 `{layers, imap}`——**这是 §12-P2 ①点名的判死负例形状**（层链 + 顶层空子映射并存），非残留 | **83/84 零残留 + 1 例判死负例**；无迁移工作量（§12.1） |
| 3 | 层链形状 | `[ip,tcp,imap]` ×82 + `[ip,tcp,tls,imap]` ×2（`imap_t061_imaps_993` / `imap_t082_imaps_chain`） | 与 registry `OptionalOn ["tls"]` 一致 ✓ |
| 4 | 用例顶层键 | `{id,proto,summary,spec_json,expect}` ×82 + 多 `strategy_fc` ×2（`imap_t065_static_pinned_reject` / `imap_t078_default_twoflow`） | 两例 `strategy_fc` 是**多流载体**（flows 门），非旧键残留（§12.1 旧键去向表） |
| 5 | 实现规模 | `planner.go` 943 行 + `layer_gen.go` 274 行；测试四文件共 **136 个 `Test*`**（`planner_test.go` 50 / `planner_testpoints_test.go` 70 / `imap_mime_test.go` 13 / `imap_f2_done_test.go` 3，`grep -c '^func Test'` 实测） | as-built 定稿依据齐备 |
| 6 | 负例 pcap | 19 负例中 **16 例有 `<id>.neg.pcap`**，全部 **0 帧**（`tcpdump -r \| wc -l` 实测）；3 例（`imap_t053_mss_reject` / `imap_t064_presence_reject` / `imap_t065_static_pinned_reject`）**无 neg.pcap 文件**——它们的拒绝发生在**建任务/建策略前**（框架 schema 门 / 顶层判死门 / 静态复制门），根本不进入引擎，故无产物 | 16/16 实测 0 帧；3 例"无产物"是**门位更靠前**，不是缺测 |

**依赖链判定纪律**：以上均为可判题（代码行号 + 机读用例 + pcap 三级对照），直接判定，不问偏好。

**产物过期登记（重要，G-IMAP-1）**：`trafficgen/docs/protocol-pcap-test/imap.md`（**tracked 结果产物**，`git ls-files` 可证）写 "Cases: 84 — pass 84, fail 0, error 0"，末次提交 `793dfee`（**2026-09-19**）。**该提交晚于**判死提交 `0417be5`（2026-09-13，扁平判死泛化全协议 `CheckProtoFlat`）——即**本协议不满足任务书 §"产物过期登记"的判定条件**（"末次提交早于 0417be5"），如实登记为**不适用**，不冒充过期。
**但仍有独立事实须登记**：`trafficgen/docs/protocol-pcap-test/imap/` 目录**不存在（0 个 pcap 文件）**——该文档表格里 81 个 `[pcap](imap/<id>.pcap)` 链接全部指向不存在的路径。故该产物的「84/84 pass」**数字未经今日复跑证实、且无 pcap 留档**。本车道**未跑**该套件，本文档**不以任何形式**（含"今日已跑通"）引用该产物作为套件可跑证据。
**旁证（不得读成"已复跑"）**：本车道为核验断言而**只读**读取了 `/tmp/mcp-pcaps/imap/` 下 **81 份 pcap**（65 正 + 16 负，`ls` 实测；目录 `drwxrwxrwx root root`，pcap 文件 mtime 2026-09-27），机读复核 **137 条 `fields` 断言 + 9 条 `frames` 断言 + 84 例包数**全部一致（§12 自审段）。该目录**不是** tracked 产物，**不构成**"套件今日已复跑"的证据；它只证明**断言与既有 pcap 自洽**。

**imap 特殊性（须写清，不得夸大）**：imap 的用例形状**高度不对称**——84 例里**只有 1 例**（`imap_t078_default_twoflow`）把包数写进 `spec_json` 之外的机器可读断言（`expect.packet_count`），其余 **64 个正例**的包数**只存在于结果产物 `imap.md` 的表格里**，JSON 侧无 `packet_count` 键。这意味着：**仅凭 cases JSON 无法机读判定包数**（G-IMAP-11）。本版 §9 的包数表**由 81 份实测 pcap 逐例 `tcpdump -r | wc -l` 回填**（非从 `imap.md` 抄录——两者已对账一致，见 §9 注），并给出**可复算的包数公式**（§9.1，63/63 非 TLS 正例逐例命中）。

## 1. 范围、profile 与实现状态边界

本版定义 **IMAP4rev1/IMAP4rev2 承载于 TCP 143（明文）/ TLS 993（IMAPS）** 的流量生成：可选服务端问候（greeting）、带标签的命令/响应序列（含 untagged `*` 与 continuation `+`）、IMAP literal（`{N}` 续行）、AUTHENTICATE 取消、CONDSTORE 缓存失效尾注、可选 IDLE（RFC 2177）与可选流水线（pipelining）、MIME 体构造（RFC 2045/2046）。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `imap_tcp_v1`（主） | TCP，fixture 143 | greeting → 命令/响应对（逐条或流水线）→ 可选 IDLE → FIN 四包 | 真实服务器语义（信箱是否存在、认证是否通过、UID 是否有效） |
| `imaps_993_v1` | `[ip,tcp,tls,imap]`，fixture 993 | 同上（**TLS 握手/挥手由 tls 层产出**，本层零断言） | 证书内容、TLS 版本协商结果、SNI 有效性（§1 边界③） |
| `imap_ipv6_v1` | 同上，仅外层 IPv6 | 同上 | 从 IPv4 fixture 推导 IPv6 地址 |

显式边界（"不实现、不声称、不许静默转换"）：
① **不强制 IMAP 状态机**——`planner.go:29-33` 包注释逐字写明「The planner does NOT enforce IMAP state-machine transitions or tag-matching. The user is responsible for providing a syntactically valid dialog」。非法状态转移（未 SELECT 就 FETCH 等）在本版是**用户剧本内容**（回放台词），不是引擎拒绝面（§5.2、G-IMAP-9）。
② **不做 tag 配对校验**——命令 tag 与 tagged 响应 tag 是否一致，planner 不检查（`planner.go:29-33` 同段；C-IMAP-1.4）。配对正确性是**用户责任**（§5.3）。
③ **不做真实 TLS 升级**——`STARTTLS` 在本版是**台词**（`imap_t017_starttls` 只回 `A001 OK STARTTLS completed`，之后**仍在同一明文 TCP 流上**继续 IMAP）；IMAPS 走独立 `tls` 层链，握手由 tls 层产出，**imap 层不感知**。
④ **不实现 FileSource literal 的链路径**——`layer_gen.go:22-29` 逐字声明：FileSource 分支依赖 ctx 携带的 `PayloadCache`（engine 级缓存），`FlowMeta` 不承载，**链路径不可用**（与 tftp layer_gen 对 FileSource 的降级同款）。`LiteralBody` / `LiteralBodyB64` / `MIMEBody` 三路完整可用。
⑤ **不做真实附件文件 IO**——附件字节来自 `data`（裸文本）或 `data_b64`（预编码），planner 只做 base64 折行包装，不读盘。
⑥ **不实现 IDLE 的 29 分钟真实等待**——`planner.go:98-103` 逐字写明：BYE **立即**发出，不真等 29 分钟（C-IMAP-1.2）。
⑦ **不实现 Modified UTF-7 编码**——`AllowUTF8Mailbox=false` 时含高位字节的信箱名**直接拒绝**（`planner.go:193-195`），不代为编码（§7 N-1）。
⑧ **不声称** `keep_idle` 与 `close_after_idle` 有行为差异——两者产出字节**完全相同**（§5.5、G-IMAP-3/G-IMAP-4）。

**实现状态（2026-09-29 实测）**：`imap` 层已注册（`registry.go:1590`，`CategoryTerminal`，`DependsOn ["tcp"]`，`OptionalOn ["tls"]`，`FieldContract {"tcp.dst_port":"143"}`，Fields 5 键）；planner/builder 已落码（`internal/protocol/imap/` 两文件 1217 行）；`allowedProtocols["imap"]=true`（`protocols.go:45`）；层内 translate 已接线（`chain_planner_translate.go:2667`）；缺省目的端口 143（`chain_planner.go:1212`）；顶层判死已接线（`strategy_convert.go:8889`）；84 语义用例已落 `cases/imap.json`。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`、`tcp.srcport`、`imap.*` 字段、offset 54 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。今日 84 例的断言全部为**载体无关**（`imap.line` / `imap.tag` / `imap.command` / `imap.response.status` 均为 TCP payload 层字段，`tcp.dstport` 为传输层字段），故双路径天然兼容；**无任何断言依赖 pcap 专有的文件格式特性**。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, imap]`（引擎自动补 `ip`；最小链 `[tcp, imap]`）；IMAPS 为 `[ip, tcp, tls, imap]`。imap 报文是 **TCP payload 的应用层字节流**，**由 tcp 层负责握手、seq/ack、MSS 分段与挥手**（事件模式，`layer_gen.go:19-29` 逐字声明）。

端口：IMAP 默认 **TCP 143**（`planner.go:75` `DefaultPort = 143`；`chain_planner.go:1212` 补齐；`strategy_convert.go:1195` 扁平路径同款）。IMAPS 为 **993**（用例显式写，`FieldContract` **不强制**——registry 注释逐字："RFC 3501 默认 143；用户显式非标准端口优先（IMAPS 993），不强制"）。fixture 统一 `src_port=14000`、`dst_port=143`（IMAPS 例 993）。

固定偏移：无 VLAN/IP options/TCP options 时，**每帧 IMAP 报文起点为 IPv4 offset 54**（14+20+20）、**IPv6 offset 74**（14+40+20）。**TLS 链（993）下偏移不稳**（TLS record 长度可变），今日 2 例 IMAPS **只断 `tcp.dstport`**，不断 payload 偏移（G-IMAP-10）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**本协议存量 83/84 已是此形**）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 14000, "dst_port": 143}},
    {"imap": {
      "banner": "* OK IMAP ready",
      "commands": [
        {"tag": "A001", "cmd": "LOGIN alice secret", "responses": ["A001 OK LOGIN completed"]},
        {"tag": "A002", "cmd": "SELECT INBOX", "responses": ["* 1 EXISTS", "A002 OK SELECT completed"]},
        {"tag": "A003", "cmd": "LOGOUT", "responses": ["* BYE Logging out", "A003 OK LOGOUT completed"]}
      ]
    }}
  ]
}
```

多流样例（数量只走 `flow_control`/`strategy_fc`；`imap_t078_default_twoflow` 即此形，全缺省双流）：

```json
{
  "layers": [{"ip": {}}, {"tcp": {}}, {"imap": {}}],
  "strategy_fc": {"type": "flows", "value": 2}
}
```

**端口缺省下的流区分**：`[ip:{}, tcp:{}, imap:{}]` 三键全空时，引擎保底 `src_ip=10.0.0.1` / `dst_ip=20.0.0.1` / `src_port=12345+i`（`strategy_convert.go:44-52` 常量），`dst_port=143`（`chain_planner.go:1212`）。实测 `imap_t078_default_twoflow` 两条流为 `10.0.0.1:12345→20.0.0.1:143` 与 `10.0.0.1:12346→20.0.0.1:143`（`tcpdump -nn` 实测），各 7 帧、共 14 帧——**四元组逐流有别，未触发静态复制门**。

## 3. 线格式编码（逐字段，按代码与实测钉）

### 3.1 命令行的帧格式（tagged command，RFC 9051 §2.2.1）

**唯一的"命令"编码函数** `formatCommandLine`（`planner.go:678-683`）：

```
<tag> SP <cmd> CRLF
```

| 字段 | 取值 | 说明 |
|---|---|---|
| `tag` | 1–256 octets，**不含 SP/CR/LF** | 显式 `commands[i].tag`；空则自动 `A%03d`（§5.3） |
| `cmd` | 用户提供的命令行**正文**（不含 tag、不含 CRLF） | 含 CRLF 即判死（N-3）；`AllowUTF8Mailbox=false` 时含高位字节即判死（N-1） |
| 终止符 | **恒 `CRLF`**（`\r\n`） | planner 追加；用户不得自带 |

**cmd 为空**：`planner.go:481-483` / `layer_gen.go:88-90`——**跳过整条命令包**（不产上行帧），但**响应照常产出**。用途：建模"纯服务端轮次"（`imap_t005_empty_cmd_challenge`，服务端单发 `+ challenge`）。

### 3.2 响应的帧格式（三种形态，RFC 9051 §2.2.2/§2.2.3/§2.2.4）

每个 `commands[i].responses[j]` **产出一帧**（非 literal 时），编码 = `resp + CRLF`（`planner.go:555`）。

| 形态 | 前缀 | 有无 tag | 本版处理 |
|---|---|---|---|
| **untagged** | `*` | 无 | 同单行：`resp + CRLF` |
| **continuation** | `+` | 无 | 同单行；literal 头也是 continuation（§3.4） |
| **tagged** | `<tag>` | **有**，须等于该命令的 tag | 同单行；**planner 不校验配对**（§1 边界②） |

**响应 CRLF 判死**：`responses[j]` 含 CR/LF 即拒（N-5，`planner.go:207-211`）——多行响应必须拆成多条 `responses` 条目，或用 literal 机制。

### 3.3 状态行（tagged completion）的三态

`imap.response.status`（tshark 字段）在 tagged 行上取值 **`OK` / `NO` / `BAD`**（RFC 9051 §7.1）：

| 状态 | 语义 | 本版用例 |
|---|---|---|
| `OK` | 成功 | 绝大多数正例 |
| `NO` | 语义失败（可带响应码，如 `[AUTHENTICATIONFAILED]`） | `imap_t015_login_no`、`imap_t020_select_no`、`imap_t023_delete`、`imap_t038_copy`、`imap_t040_no_code` |
| `BAD` | 协议/语法错误（未知命令、错序） | `imap_t041_unknown_bad`、`imap_t007_bye_greeting` |

**tshark 口径（实测，须写清）**：`imap.response.status` **只在 tagged 行上解码**——untagged `*` 行上该字段为空。`imap_t011_capability` 的 notes 逐字记载该踩坑："untagged 包6 不解 response.status，改断 tagged 包7"；`imap_t038_copy` 同款（"NO 只在 tagged 包13 解码，untagged 包12 不解 status"）。**本版所有 `imap.response.status` 断言均落在 tagged 帧**（137 条字段断言机读复核全 OK）。

### 3.4 IMAP literal（`{N}` 续行，RFC 9051 §4.3）——**本协议特有编码**

**语法**：`{` number `}` CRLF *CHAR8 —— 声明"接下来 N 个字节是原始数据"。本版**两侧都可触发**，**编码规则不对称**：

#### 3.4.1 命令侧（client → server，上行）：**占位原样发出，体另起一帧**

`emitCommandWithOptionalLiteral`（`planner.go:481-498` / `layer_gen.go:88-102`）：

1. `hasLiteralPlaceholder(cmd)`（`planner.go:689-704`，字节扫描 `{digits}`）为真时，先发命令帧：`<tag> SP <cmd> CRLF`——**`{N}` 原样保留，不做长度替换**；
2. 再发 **literal 体**为独立帧（up 方向），字节数 = `len(resolveLiteral(cmd))`；
3. `len(body)==0` 时**不产体帧**。

实测（`imap_t008_append_literal`，帧 7/8）：

```
帧7 up  : 41 30 30 32 20 41 50 50 45 4e 44 20 49 4e 42 4f 58 20 7b 35 7d 0d 0a   = "A002 APPEND INBOX {5}\r\n"
帧8 up  : 68 65 6c 6c 6f                                                            = "hello"
```

#### 3.4.2 响应侧（server → client，下行）：**占位被替换成实际长度，体与收尾各一帧**

`emitResponses`（`planner.go:537-552` / `layer_gen.go:119-138`）：

1. `hasLiteralPlaceholder(resp)` 为真时，把**第一个** `{N}` 替换为 `{<实际长度>}CRLF`（`replaceLiteralPlaceholder`，`planner.go:711-726`），再补 `CRLF` 收尾 → 发**头帧**；
2. 发 **literal 体**帧（down），字节数 = `len(literalBody)`；`len==0` 时**不产体帧**；
3. **无条件**发一帧 `CRLF`（2 字节）关掉响应行（RFC 9051 §2.2.4）。

实测（`imap_t036_fetch_literal_down`，帧 11/12/13）：

```
帧11 down: 2a 20 31 20 46 45 54 43 48 20 28 42 4f 44 59 5b 5d 20 7b 35 7d 0d 0a 29 0d 0a
          = "* 1 FETCH (BODY[] {5})\r\n" + ")" + CRLF      ← 用户写的是 {0}，被替换成 {5}
帧12 down: 68 65 6c 6c 6f                                  = "hello"
帧13 down: 0d 0a                                           = CRLF（收尾）
```

#### 3.4.3 两侧的**关键不对称**（代码可生成级细节，必须照此实现）

| 维度 | 命令侧 | 响应侧 |
|---|---|---|
| `{N}` 的 N | **原样发出**（用户写的 N 就是线上的 N） | **被替换**为实际体长度（用户写的 N 被忽略） |
| 体帧 | 有源则发，空源不发 | 有源则发，空源不发 |
| 收尾帧 | **无** | **恒有**（2 字节 `CRLF`） |
| 触发条件 | `cmd` 含 `{N}` | `responses[j]` 含 `{N}` |

**由此产生的既有用例形态**：`imap_t009` / `imap_t036` / `imap_t042` 在响应里写 `{0}` 而配 `literal_body:"hello"` → 线上产出 `{5}`；`imap_t042` 写 `{5}` 配同一 body → 线上同样产出 `{5}`。**两种写法产出相同字节**（G-IMAP-5 登记该语义：占位值不参与校验）。

#### 3.4.4 literal 源的四级优先级

`resolveLiteral`（`planner.go:441-466` / `layer_gen.go:69-84`）：

| 优先级 | 源 | 编码 | 链路径可用性 |
|---:|---|---|---|
| 1 | `mime_body` | 由 `constructMIMEBody` 现场构造（§3.5） | ✅ 可用 |
| 2 | `file_source` | `PayloadCache.GetOrLoad` 读盘 | ❌ **链路径不可用**（§1 边界④，G-IMAP-6） |
| 3 | `literal_body_b64` | `base64.StdEncoding.DecodeString` | ✅ 可用 |
| 4 | `literal_body` | `[]byte(s)` 逐字节 | ✅ 可用 |

**互斥校验**（`planner.go:217-246`）：`literal_body` × `literal_body_b64` 互斥（N-6）；`mime_body` × 前两者互斥（N-14）。**`file_source` 不与任何项做互斥校验**（未入例，G-IMAP-8）。

**长度上限**：`MaxLiteralLen = 100 * 1024 * 1024`（100 MB，`planner.go:96`）。三路分别校验：`literal_body` 原始长度（`:220`）、`literal_body_b64` **解码后**长度（`:228`）、`mime_body` **构造后**长度（`:243`）。三支均未入例（G-IMAP-8）。

### 3.5 MIME 体构造（RFC 2045/2046/2183）

`constructMIMEBody`（`planner.go:821-912`）——纯函数，不碰网络与 planner 状态。**两种形态**：

**SIMPLE**（`parts` 与 `attachments` 都空）：

```
<Headers 逐条>\r\n
Content-Type: text/plain; charset=utf-8\r\n
Content-Transfer-Encoding: 8bit\r\n
\r\n
<text>\r\n
```

**MULTIPART**（`parts` 或 `attachments` 非空）：

```
<Headers 逐条>\r\n
MIME-Version: 1.0\r\n
Content-Type: multipart/mixed; boundary="<boundary>"\r\n
\r\n
--<boundary>\r\n
Content-Type: text/plain; charset=utf-8\r\n
Content-Transfer-Encoding: 8bit\r\n
\r\n
<text>\r\n
[每 parts 项：]
--<boundary>\r\n
<content_type 或 text/plain; charset=utf-8>\r\n
[每 headers 项]\r\n
Content-Transfer-Encoding: 8bit\r\n
\r\n
<body>\r\n
[每 attachments 项：]
--<boundary>\r\n
<content_type 或 application/octet-stream>\r\n
Content-Transfer-Encoding: base64\r\n
Content-Disposition: attachment; filename="<filename>"\r\n
\r\n
<base64(Data)，每行 76 字符（RFC 2045 §6.8）>\r\n
--<boundary>--\r\n
```

**boundary 生成**（`generateMIMEBoundary`，`planner.go:917-920`）：用户显式给 `boundary` 则原样用；否则 `----=_Part_<counter>_<UnixNano>_<rand.Uint64()>`——**进程级 `atomic` 计数器 + 时间戳 + 随机后缀**（`mimeBoundaryCounter`，`planner.go:785`），保证跨 planner run 唯一。

**由此产生的断言纪律（须写清）**：MIME 体的**总长度逐跑漂移**（boundary 后缀随机 → literal `{N}` 值漂移）。故 `imap_t051` / `imap_t080` / `imap_t081` 三例的 notes 逐字记载：**"包11 literal 头 `{N}` 不钉死"**，改由「包 12 首段帧字节」+「离线 `{N}==len` 精确断言（`TestIMAPMIME_*`）」两面覆盖。`imap_t052` 给了**显式 boundary `"b-159"`** → `{N}` 确定（=320，实测帧 8 `tcp.len`），但该例同样只断首段字节。

**附件字节约定（重要，`ParseIMAPConfigFromMap` 逐字注释）**：`attachments[].data` 是**裸文本**（`[]byte(raw)` 逐字节，**不是 base64**）；`attachments[].data_b64` 是**预编码 base64 文本**。`imap_t051`/`t080`/`t081` 用 `data_b64`（README.md 的 base64），`imap_t052` 用 `data: "up-body"`（裸文本，线上被编码为 `dXAtYm9keQ==`）。
**判死教训（代码注释在案）**：层配置若走 **Go JSON 往返**解码，`IMAPAttachment.Data []byte` 会因「裸文本不是合法 base64」而**整包解码失败** → `spec.IMAP` 留 nil → **静默产出空会话**（历史现象：T-051/52/80 实测 7 包空流）。故层路径**必须**走 `core.ParseIMAPConfigFromMap`（`strategy_convert.go:3493`），**禁止** JSON 往返（`chain_planner_translate.go:2667-2676` 逐字记录）。

### 3.6 IDLE 序列（RFC 2177）——六步固定编排

`emitIDLE`（`planner.go:577-617` / `layer_gen.go:149-180`），**触发条件** `commands[i].emit_idle == true && IMAPConfig.IDLE != nil`（缺一即拒，N-9）：

| 步 | 方向 | 内容 | 条件 |
|---:|---|---|---|
| 1 | up | `<tag> SP IDLE CRLF`（`cmd` 被忽略，planner 自造 IDLE） | 恒 |
| 2 | down | `+ idling\r\n`（常量 `IDLEContuation`，`planner.go:107`） | 恒 |
| 3 | down | 每个 `idle.push_responses[j] + CRLF` | 逐项 |
| 4 | up | **`DONE\r\n`（裸，无 tag）**（常量 `IDLEDone`，`planner.go:114`） | 恒 |
| 5 | down | `idle.done_response + CRLF` | `done_response != ""` |
| 6 | down | `* BYE IDLE timeout\r\n`（常量 `IDLETimeoutBye`，`planner.go:103`） | `server_timeout_behavior ∈ {close_after_idle, keep_idle}` |

**第 4 步的规范依据与历史修复**（`planner.go:592-601` 逐字）：RFC 2177 §4 规定 DONE 是对服务端 `+` 提示的**续行响应**，**不是 tagged command**，故**恒裸发**、无 tag 前缀。早期代码在 `DoneTag != cmd.Tag` 时发 `<DoneTag> DONE\r\n`——**那是违反规范的 tagged DONE**，已修。**tshark 后果**：裸 `DONE\r\n` 行上 `imap.command` **为空**，故三例 IDLE 用例改断 `imap.line == "DONE\r\n"`（`imap_t043`/`t044`/`t045`/`t046`/`t047` notes 逐字记载："tshark imap.command 为空是口径所限，改断 imap.line DONE"）。

**`DoneTag` 是死配置（G-IMAP-2）**：`grep -rn DoneTag` 实测——产出路径**零引用**，只在 `planner.go:277-283` 被 Validate 检查（含 SP/CRLF、超长）。`types.go:4968-4975` 的字段注释仍声称"`<DoneTag> DONE\r\n` when DoneTag is set"，**与实现相反**（`planner.go:592-601` 明确说该行为已废除）。

**`keep_idle` 与 `close_after_idle` 产出字节完全相同（G-IMAP-3/G-IMAP-4）**：`planner.go:609-616` 两个 case 分支体**逐字相同**（都发同一个 `IDLETimeoutBye`），之后**都**走 §5.6 的 TCP FIN 四包。实测 `imap_t045_idle_close` 与 `imap_t046_idle_keep` 的 pcap 除时间戳外**逐帧 payload 完全一致**（`tshark -T fields -e tcp.payload` 逐帧比对，两例各 17 条 payload 全部相同），两例包数同为 **24**。**`keep_idle` 声称的"不拆 TCP、复用同一流继续下一命令"未落码**（`types.go:4988-4992` 的字段注释是设计意图）。

### 3.7 流水线双相位（pipelining，RFC 9051 §5.4 / RFC 3501 §2.2.2）

`pipelined_commands == true` 时（`planner.go:626-645` / `layer_gen.go:184-205`），产出顺序**两相位**：

- **相位 1**：**全部命令**按序背靠背发出（每条含可选 literal 体），中间**不插任何响应**；
- **相位 2**：**全部响应**按**命令顺序**发出（每条含 IDLE 编排）。

实测（`imap_t010_pipelined`，帧 5/6 连续两条命令）：

```
帧5 up: "A001 NOOP\r\n"
帧6 up: "A002 NOOP\r\n"     ← 无服务端响应插在中间
```

**tag 计数器的相位行为**：两相位**共用同一个 `autoTagCounter`**（`planner.go:429-433`）——相位 1 顺序消耗 `A001`/`A002`/…，相位 2 复用相位 1 已定的 `tags[i]`（`planner.go:628-638` 存 `tags` 切片），**不重新生成**。空 `tag` 的自动编号在两相位下**仍与命令顺序一致**。

### 3.8 TCP 层职责（本层不产）

事件模式下**本层不产任何 TCP 语义帧**——握手（SYN/SYN-ACK/ACK）、seq/ack 推进、MSS 分段、FIN 四包全部由 `tcp` 层生成器产出（`layer_gen.go:19-29` 逐字）。**校验器强制**：`layer_gen.go:260-273` 的 `RegisterLayerValidator("imap", …)` 在 Validate 后**强制写** `spec.TCP.Handshake = true` / `spec.TCP.Termination = true`（`spec.TCP` 为 nil 时先建），理由逐字："legacy imap planner 恒产 TCP 握手/挥手——spec.TCP 零值 false 必须写默认 true，否则 tcp 层生成器跳过握手/挥手"（smtp/redis/pop3 layer_gen 同款陷阱）。

**MSS**：`spec.TCP.MSS`（默认 1460，`planner.go:61-66`）；下限 **536**（RFC 879，`MinMSS`，`planner.go:71`）；分段规则 = `ceil(payload / MSS)`（`segmentByMSS`，`planner.go:746-763`）。**链路径下 MSS 由 tcp 层生成器执行分段**，本层只产出整条消息事件。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**（declarative / scripted playback）——配置声明 `banner` + `commands[]`（每条含 tag / cmd / responses / 可选 literal / 可选 IDLE），引擎按声明顺序把每条翻译成帧。**引擎内唯一自动应答**是 tcp 层的握手挥手；**imap 层无自动派生**（§5.5）。**IMAP 状态机不由引擎推进**（§1 边界①）——用户写什么就回放什么。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 连接问候与能力发现 | greeting `* OK [CAPABILITY …]` → `CAPABILITY` | `t001`/`t011`/`t054`/`t055`/`t056` |
| ② 明文登录 | `LOGIN user pass` → `OK`/`NO` | `t014`/`t015`/`t054` |
| ③ SASL 认证（含取消） | `AUTHENTICATE PLAIN` → `+` → 完成；`AUTHENTICATE LOGIN` → 两次 `+` → `*` 取消 | `t016` |
| ④ 信箱列举与状态 | `LIST` / `NAMESPACE` / `STATUS` / `SELECT` / `EXAMINE` | `t019`–`t021`/`t026`–`t028` |
| ⑤ 信箱增删改订 | `CREATE` / `DELETE` / `RENAME` / `SUBSCRIBE` / `UNSUBSCRIBE` | `t022`–`t025` |
| ⑥ 邮件检索与读取 | `SEARCH`（非空/空）/ `FETCH FLAGS` / `FETCH BODY[]`（literal 下行） | `t033`–`t036`/`t057` |
| ⑦ 标记与搬运 | `STORE ±FLAGS` / `COPY` / `MOVE` / `UID FETCH` | `t037`–`t039` |
| ⑧ 投递（APPEND + literal 上行） | `APPEND INBOX (\Seen) {N}` → `+` → 体 → `OK` | `t008`/`t029`/`t052`/`t079` |
| ⑨ 附件下载（MIME 多部件） | `FETCH BODY[]` → `{N}` → multipart 体 | `t051`/`t080`/`t081` |
| ⑩ 推送等待（IDLE） | `IDLE` → `+ idling` → `* n EXISTS` → `DONE` → `OK IDLE terminated` → 可选 BYE | `t043`–`t047` |
| ⑪ 长保活（NOOP 轮询） | 连续 `NOOP` → `OK` | `t059` |
| ⑫ 会话终止 | `LOGOUT` → `* BYE` → `<tag> OK` | `t013`；异常中止 `t058` |
| ⑬ 现网厂商形（问候/能力集） | Gmail / Outlook / Dovecot 实录问候 | `t054`/`t055`/`t056` |
| ⑭ IMAPS 993 | `[ip,tcp,tls,imap]` 链 | `t061`/`t082` |
| ⑮ 多事务复合流 | 一连接内 ≥3 动作的业务编排 | `t060`/`t079` |

**五层覆盖逐层结论**：

- **功能层**：RFC 9051 命令表逐条落点——CAPABILITY/NOOP/LOGOUT/STARTTLS/AUTHENTICATE/LOGIN（未认证态）、SELECT/EXAMINE/CREATE/DELETE/RENAME/SUBSCRIBE/UNSUBSCRIBE/LIST/NAMESPACE/STATUS/APPEND/ENABLE（认证态）、CLOSE/UNSELECT/EXPUNGE/SEARCH/FETCH/STORE/COPY/MOVE/UID（已选态），外加扩展 IDLE（RFC 2177）与 CONDSTORE 尾注（RFC 7162）；错误处理 **19 条负例**（§7）；三态 tagged completion（`OK`/`NO`/`BAD`）各有落点。
- **性能层**：literal 跨 MSS 分段（`t051`/`t080`/`t081` 实测 N=6023/5874/5689 → **5 段**；`t052` N=320 → 1 段）；最大包数用例 `t079`（**30 帧**）；最小包数用例 `t007`（**10 帧**）；MSS 下限 536 拒绝（`t053`）；`MaxLiteralLen` 100 MB / `MaxResponsesPerCommand` 10000 / `MaxPushResponses` 1000 / `MaxTagLen` 256 四条上界（§8）。
- **数据场景层**：tag 三形态（`tag.42` 点 / `X-Custom-1` 线 / `001` 纯数字，`t004`）+ 自动递增（`t003`）+ 显式（`t002`）；空 `cmd`（`t005`）；literal 三源（`literal_body` `t008`、`literal_body_b64` `t009`、`mime_body` `t051`/`t052`）；MIME 三形态（多部件+附件 `t051`、空正文+附件 `t080`、纯附件无正文 `t081`）；UTF-8 开/关（`t049`/`t050`）；IDLE 四形态（有 push `t043`、无 push `t044`、close `t045`、keep `t046`、none `t047`）；CONDSTORE 尾注（`t048`）；AUTHENTICATE 取消（`t016`）。
- **地址与流层**：**IPv4 与 IPv6 都覆盖**（`t062` 为 IPv6，offset 74；其余 IPv4，offset 54）；**单流基线** = 全正例（`t001`–`t063` 除 `t078`）；**多流** = `t078`（`strategy_fc.flows=2`，两条流 `12345`/`12346`，各 7 帧）；**流关联（控制流派生数据流）显式不适用**——IMAP **单 TCP 连接承载全部命令与响应**，无副连接、无 `driven_by` 主从关系（与 FTP 控制+数据双通道形成对照：IMAP 的"数据"就在同一连接里以 literal 形式流动）。
- **业务层**：十五个现网场景全部有落点（上表）；**多会话**——本版 `imap` 层**无 `sessions[]` 数组**（对照 ftp/sip 的 `sessions[]`），多会话由**策略级 `flow_control`/`strategy_fc` 多流**承载（`t078` 是唯一多流例，也是唯一带 `strategy_fc` 的正例）；**多事务**——`t057`（同连接两 FETCH）、`t059`（三 NOOP）、`t060`/`t079`（复合流 ≥3 动作）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① 真实状态机推进（未实现，G-IMAP-9）；② tag 配对校验（未实现，§1 边界②）；③ Modified UTF-7 编码（未实现，§1 边界⑦）；④ STARTTLS 真升级（未实现，§1 边界③）；⑤ FileSource literal 链路径（不可用，G-IMAP-6）；⑥ IDLE 29 分钟真实等待（不实现，§1 边界⑥）；⑦ `keep_idle` 与 `close_after_idle` 的行为差异（未落码，G-IMAP-3）；⑧ RST 异常中断（框架 tcp 层能力，本层零断言，A′ 立项 G-IMAP-13）。

## 5. 消息/事务模型与状态机

### 5.1 事务定义

**一次事务 = 一条 client 命令 + 其后的一串 server 响应**（RFC 9051 §2.2.4：一条 tagged 命令可引出任意多条 untagged/continuation 响应，以该 tag 的 tagged 完成响应收尾）。**多事务** = 一个连接内多笔事务按序执行，**事务间有先后依赖与关联标识**（§5.3）。

| 事务族 | 帧构成 | 用例 |
|---|---|---|
| 单响应事务 | 1 命令帧 + 1 响应帧 | `t002`/`t012`/`t017`/`t022`/`t024` |
| 多响应事务 | 1 命令帧 + N 响应帧（untagged… + tagged） | `t011`/`t019`/`t020`/`t023`/`t030`–`t039` |
| literal 事务（上行） | 1 命令帧 + 1 体帧 + 1..N 响应帧 | `t008`/`t029`/`t052` |
| literal 事务（下行） | 1 命令帧 + 1 头帧 + 1 体帧 + 1 收尾帧 + 1 tagged 帧 | `t036`/`t042`/`t051`/`t080`/`t081` |
| IDLE 事务 | 命令 + `+ idling` + N push + `DONE` + 完成响应 + 可选 BYE | `t043`–`t047` |
| 服务端单轮（无命令） | 0 命令帧 + N 响应帧 | `t005` |

### 5.2 IMAP 状态机（RFC 9051 §3）与非法转移

**四态**（RFC 9051 §3 逐字）：

```
   [连接建立]
        ↓ (greeting: * OK / * PREAUTH / * BYE)
  ┌─────────────────────┐
  │ NOT AUTHENTICATED   │  CAPABILITY NOOP LOGOUT STARTTLS AUTHENTICATE LOGIN
  └─────────────────────┘
        ↓ LOGIN OK / AUTHENTICATE OK / PREAUTH greeting
  ┌─────────────────────┐
  │ AUTHENTICATED       │  + SELECT EXAMINE CREATE DELETE RENAME SUBSCRIBE
  └─────────────────────┘    UNSUBSCRIBE LIST NAMESPACE STATUS APPEND IDLE ENABLE
        ↓ SELECT / EXAMINE OK          ↑ CLOSE / UNSELECT  / SELECT 覆盖 / 失败
  ┌─────────────────────┐
  │ SELECTED            │  + CLOSE UNSELECT EXPUNGE SEARCH FETCH STORE COPY MOVE UID
  └─────────────────────┘
        ↓ LOGOUT
  ┌─────────────────────┐
  │ LOGOUT              │  （无合法命令）
  └─────────────────────┘
```

**非法转移逐条列出（本版按 RFC 9051 §6 各命令的 "Valid States" 段提炼）**：

| # | 非法转移 | 规范依据 | 服务端应答 | 本版用例 | 引擎行为 |
|---:|---|---|---|---|---|
| I-1 | **NOT AUTHENTICATED 态发 SELECT / EXAMINE** | RFC 9051 §6.3.1 / §6.3.2（Valid States: Authenticated, Selected） | `NO` 或 `BAD` | `t006`（`A001 NO SELECT failure`）、`t040`（同形） | **回放台词，不拒绝**（§1 边界①） |
| I-2 | **未 SELECT 就 FETCH / STORE / COPY / EXPUNGE / SEARCH** | RFC 9051 §6.4.x（Valid States: Selected） | `BAD` | **今日无例** → A′ 立项（G-IMAP-9） | 同上 |
| I-3 | AUTHENTICATED 态发 LOGIN | RFC 9051 §6.2.3 | `BAD` | **今日无例** → A′ 立项 | 同上 |
| I-4 | AUTHENTICATED/SELECTED 态发 STARTTLS | RFC 9051 §6.2.1（Valid States: Not Authenticated） | `BAD` | **今日无例** → A′ 立项 | 同上 |
| I-5 | AUTHENTICATED 态发 AUTHENTICATE | RFC 9051 §6.2.2 | `BAD` | **今日无例** → A′ 立项 | 同上 |
| I-6 | LOGOUT 态发任何命令 | RFC 9051 §6.1.3 | 无响应（连接已关） | **今日无例** → A′ 立项 | 同上 |
| I-7 | SELECTED 态发 APPEND / STATUS / LIST（**合法**——Selected ⊃ Authenticated 能力集） | RFC 9051 §6.3.x | `OK` | `t079`（APPEND 在 CREATE 之后、SELECT 之前）、`t028`（STATUS） | 合法正例 |
| I-8 | SELECTED 态再发 SELECT（**合法**——隐式 CLOSE 前一信箱） | RFC 9051 §6.3.1 | `OK` | **今日无例** → A′ 立项 | 合法 |
| I-9 | IDLE 期间发非 DONE 命令（**非法**——IDLE 独占连接） | RFC 2177 §3 | `BAD` | **今日无例** → A′ 立项 | 同上 |
| I-10 | 未收到 `+` 续行就发 DONE | RFC 2177 §4 | `BAD` | **今日无例** → A′ 立项 | 同上 |

**诚实声明（关键，不得含糊）**：**上述 I-1…I-10 的"引擎行为"列全部是"回放台词"**——`planner.go:29-33` 逐字声明「The planner does NOT enforce IMAP state-machine transitions or tag-matching. The user is responsible for providing a syntactically valid dialog (LOGIN before SELECT, DONE to exit IDLE, LOGOUT to end)」。**因此 `t006`（未认证态 SELECT）与 `t040` 断的不是"引擎拒绝了非法转移"，而是"用户声明的 NO 台词被如实回放"**。这是**设计上的显式边界**，不是缺陷——但它意味着**状态机维度今日几乎零覆盖**（仅 I-1 与 I-7 有落点），登记为 **G-IMAP-9**。

### 5.3 tag 的取材与配对规则（RFC 9051 §2.2.1）——**本协议特有的事务关联标识**

**tag 的作用**：IMAP 是**带标签事务**协议——客户端给每条命令编一个 tag，服务端在**该命令的完成响应**上原样抄回同一个 tag，从而在**乱序/流水线**场景下把响应与命令配对。

**取材规则（三级）**：

| 级 | 条件 | 取值 | 代码位置 |
|---:|---|---|---|
| 1 | `commands[i].tag` 非空 | **显式原样使用** | `planner.go:649-651`（默认分支）/ `:630-634`（流水线相位 1） |
| 2 | `commands[i].tag` 为空 | **自动 `A%03d`**（`A001`、`A002`…） | `autoTag`，`planner.go:429-433`；`orAuto`，`layer_gen.go:227-232` |
| 3 | 流水线相位 2 | **复用相位 1 已定的 tag**（不重生成） | `planner.go:628-638` 存 `tags[i]`，`:640-645` 复用 |

**`A%03d` 的位数语义**：3 位零填充，计数器 **per-flow**（每次 `Plan`/`Generate` 调用重置为 0）。超过 999 条命令时产出 `A1000`（4 字符，**仍合法**——tag 上限 256）。**自动编号不因显式 tag 而跳号**：`t003` 中前两条命令 `tag` 为空 → `A001`/`A002`；第三条显式 `A003`——**显式值不参与计数**，计数器只由"空 tag 命令"推进（`planner.go:430-433` 的 `autoTagCounter++` 只在 `tag == ""` 分支被调用）。

**配对规则（线格式层面）**：

| 响应形态 | tag 前缀 | 配对语义 |
|---|---|---|
| tagged completion | **`<同一 tag> SP <OK\|NO\|BAD> …`** | **配对锚点**——服务端必须抄回命令的 tag |
| untagged data | `*` | 无 tag；归属"当前命令"（RFC 9051 §2.2.2） |
| continuation | `+` | 无 tag；请求客户端续发（literal / AUTHENTICATE / IDLE） |
| DONE（IDLE 终止） | **无** | RFC 2177 §4：DONE 是**续行响应**，不是 tagged 命令（§3.6） |

**tag 的字符合法性（RFC 9051 §2.2.1）**：`tag = 1*<any ASTRING-CHAR except "+">`，即不得含 SP / CR / LF / `+`。**本版只校验前三条**：

| 校验 | 锚词 | 代码行 | 用例 |
|---|---|---|---|
| 长度 > 256 | `Tag length` | `planner.go:173-175` | `t066` |
| 含 SP / CR / LF | `contains SP/CRLF` | `planner.go:178-180` | `t072` |
| 含 `+` | **未校验** | — | **无例**（G-IMAP-8） |
| 空 tag | **不拒绝**（触发自动编号） | `planner.go:430-433` | `t003`（正例） |

**配对校验：不做（§1 边界②）**。用户写 `tag:"A001"` 而响应写 `"A999 OK …"` 时，planner **照样产出**，引擎不报错、不断言。**配对正确性 = 用户责任**（C-IMAP-1.4）。本版 84 例**全部配对正确**（机读复核：65 正例的 tagged 响应 tag 前缀与所属命令 tag 逐条一致）。

### 5.4 驱动模型（事件模式 vs legacy）

**两条产出路径，语义等价**：

| 路径 | 入口 | TCP 语义 | 用途 |
|---|---|---|---|
| **链路径（生产）** | `IMAPGenerator.Generate`（`layer_gen.go:38-224`） | **由 tcp 层生成器产出**（握手/seq-ack/挥手/MSS 分段） | 84 例全走此路径 |
| legacy 路径 | `Planner.Plan`（`planner.go:296-673`） | **自产**握手 3 包 + 挥手 4 包 + `emitData` 分段 | 单测（`planner_test.go` 等 136 个 `Test*`） |

**`layer_gen.go:21-29` 逐字记录的 divergence**（文档化差异，四条）：① legacy 自产握手/挥手，事件模式不产（validator 强制 `spec.TCP.Handshake/Termination=true`）；② seq/ack、ipID、Timestamp、MSS 分段由 tcp 层处理；③ FileSource literal 在链路径不可用（§1 边界④）；④ 其余（greeting / 命令 / literal / IDLE / 流水线 / MIME）**逐函数复用，不重写**（`formatCommandLine` / `constructMIMEBody` / `replaceLiteralPlaceholder` 等纯函数两路径共用）。

### 5.5 自动派生规则（逐条，不依赖隐含知识）

| # | 自动派生 | 触发条件 | 内容 | 代码行 |
|---:|---|---|---|---|
| 1 | **greeting CRLF 补齐** | `banner != "" && !HasSuffix(banner, "\r\n")` | 追加 `\r\n` | `planner.go:418-424` / `layer_gen.go:51-59` |
| 2 | **tag 自动编号** | `tag == ""` | `A%03d` 自增 | `planner.go:429-433` |
| 3 | **命令 CRLF 追加** | `cmd != ""` | `formatCommandLine + "\r\n"` | `planner.go:485` |
| 4 | **响应 CRLF 追加** | 每个非 literal 响应 | `resp + "\r\n"` | `planner.go:555` |
| 5 | **literal 头长度替换** | 响应含 `{N}` | `{N}` → `{<实际长度>}\r\n` | `planner.go:542` |
| 6 | **literal 收尾 CRLF** | 响应含 `{N}` | 恒发 2 字节 `\r\n` 帧 | `planner.go:552` |
| 7 | **literal 体帧** | 响应含 `{N}` 且 `len(body) > 0` | 发体帧 | `planner.go:545-547` |
| 8 | **命令侧 literal 体帧** | `cmd` 含 `{N}` 且 `len(body) > 0` | 发体帧（**无收尾 CRLF**） | `planner.go:491-497` |
| 9 | **AUTHENTICATE 取消行** | `cancel_after_responses > 0 && j == cancelAfter` | 发 `*\r\n`（常量 `AuthCancelLine`） | `planner.go:532-535` |
| 10 | **CONDSTORE 尾注** | `uid_cache_invalidation == true` | 发 `* OK [HIGHESTMODSEQ 1] mailbox cache invalidated\r\n`（常量 `UIDCacheInvalidationResponse`） | `planner.go:564-566` |
| 11 | **IDLE 六步** | `emit_idle && IDLE != nil` | §3.6 表 | `planner.go:577-617` |
| 12 | **流水线两相位重排** | `pipelined_commands == true` | §3.7 | `planner.go:626-645` |
| 13 | **MIME boundary 生成** | multipart 且 `boundary == ""` | `----=_Part_<n>_<nano>_<rand>` | `planner.go:917-920` |
| 14 | **base64 76 字符折行** | attachment 编码 | `wrapBase64` | `planner.go:926-943` |
| 15 | **TCP 握手/挥手** | 恒 | 由 tcp 层产出；validator 强制 `Handshake/Termination=true` | `layer_gen.go:260-273` |

**无任何"隐含知识"**：以上 15 条是全部自动派生面；除 tcp 层握手挥手外，**imap 层不产生任何用户未声明的字节**。

### 5.6 时间线（帧序）

```
[TCP 握手 3 帧]（tcp 层）
  ↓
banner?（1 帧，down）
  ↓
每 commands[i]（默认分支）：
    cmd?（1 帧，up）
    cmd 含 {N} 且体非空?（1 帧，up）
    每 responses[j]：
        非 literal → 1 帧（down）
        literal   → 头帧(down) + 体帧?(down) + 收尾 CRLF 帧(down)
    uid_cache_invalidation?（1 帧，down）
    emit_idle? → IDLE 六步（§3.6）
  ↓
[TCP FIN 四包]（tcp 层）
```

**流水线分支**：把「每 commands[i]」拆成两个循环——先跑完所有 `cmd?` + literal 体，再跑完所有 responses/IDLE。

## 6. 性能设计与验收

- **目标与边界**：单流全链帧数区间 **[10, 30]**（实测：最小 `t007` 10 帧，最大 `t079` 30 帧）；literal 最大跨段数 **5**（`t051` N=6023 / `t080` N=5874 / `t081` N=5689，MSS 1460）；命令数最大 **8**（`t079`）。吞吐数字待 P4 基准，**本版不写承诺**。
- **依据**：事件逐条产出（`Generate` 顺序 `emit`，无全量聚合）；每帧内存 = 该帧 payload 长度（最大单帧 = literal 首段 1460 字节）；per-flow 局部状态（`autoTagCounter` 是**调用内局部变量**，非共享）；无跨流共享状态；无锁。
- **验收两路（§6.3 强制）**：pcap（`/tmp/mcp-pcaps/imap/`，`<id>.pcap` / 负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `imap.*` 字段值、帧原始 hex 与包数，不只断言"任务没报错"。
- **六类场景落点**：基线（`t001` 16 帧）/ 目标规模（`t079` 30 帧 / `t051` 25 帧）/ 压力上限（literal 5 段 + `t084` Responses 超万拒绝）/ 长时间运行（`t059` 三 NOOP 轮询 + `t043`–`t047` IDLE 多轮）/ 并发交错（`t078` 双流；**并发交错路径为例外不启用**）/ 背压（包数逐例精确对账 + 四条上界守卫 §8）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

**19 条负例，全部实测 0 帧**（16 例有 `.neg.pcap`，实测 0 帧；3 例无产物——门位在建任务前，§0 #6）。锚词与代码字面值逐条对应：

| # | 负例 ID | 故障输入 | 代码锚词（逐字） | 代码行 |
|---:|---|---|---|---|
| N-1 | `imap_t050_utf8_off_reject` | `allow_utf8_mailbox=false` + `cmd` 含 `日本語` | `imap: Commands[%d].Cmd %q contains non-ASCII bytes; set AllowUTF8Mailbox=true or encode as Modified UTF-7 per RFC 3501 §5.1.3 (C-IMAP-1.7)` | `planner.go:194` |
| N-2 | `imap_t053_mss_reject` | `tcp.mss = 100` | `layers: layer %q field %q = %v invalid: out of range [%d,%d]`（tcp 层 schema 门，`mss` Min 536 Max 65535） | `complete.go:325` + `registry.go:68` |
| N-3 | `imap_t063_bad_ip_reject` | `ip.dst = "not-an-ip"` | `invalid IP address: not-an-ip`（框架 `core.ParseIP`） | `convert.go:55` |
| N-4 | `imap_t064_presence_reject` | 层链 + **顶层 `imap: {}` 并存** | `protocol imap no longer accepts a top-level imap sub-config (move it into the imap layer of an [ip,tcp,imap] layers chain)` | `strategy_convert.go:8893` |
| N-5 | `imap_t065_static_pinned_reject` | 显式标量四元组 + `flows=2` + 无动态逃生 | `layers pin a static four-tuple but flows > 1: every flow would emit identical addresses/ports (static copy). …` | `schema/semantic.go:285` |
| N-6 | `imap_t072_tag_space_reject` | `tag: "A 001"` | `imap: Commands[%d].Tag %q contains SP/CRLF (RFC 9051 §2.2.1)` | `planner.go:179` |
| N-7 | `imap_t066_tag_toolong_reject` | `tag` 257 字节 | `imap: Commands[%d].Tag length %d exceeds max %d (RFC 9051 §2.2.1)` | `planner.go:174` |
| N-8 | `imap_t067_cmd_crlf_reject` | `cmd: "NOOP\r\nDELETE 1"` | `imap: Commands[%d].Cmd %q contains CRLF (command injection per RFC 9051 §2.2.1)` | `planner.go:186` |
| N-9 | `imap_t073_resp_crlf_reject` | `responses[0]: "A001 OK\r\nBAD"` | `imap: Commands[%d].Responses[%d] contains CRLF; split into multiple entries or use LiteralBody for multi-line responses` | `planner.go:209` |
| N-10 | `imap_t068_b64_bad_reject` | `literal_body_b64: "!!!not-b64!!!"` | `imap: Commands[%d].LiteralBodyB64 decode error: %v` | `planner.go:226` |
| N-11 | `imap_t074_literal_mutex_reject` | `literal_body` + `literal_body_b64` 并存 | `imap: Commands[%d].LiteralBody and LiteralBodyB64 are mutually exclusive; use one or the other (or FileSource)` | `planner.go:218` |
| N-12 | `imap_t069_emit_idle_no_idle_reject` | `emit_idle: true` 但 `IMAPConfig.IDLE == nil` | `imap: Commands[%d].EmitIDLE=true but IMAPConfig.IDLE is nil` | `planner.go:250` |
| N-13 | `imap_t075_cancel_range_reject` | `cancel_after_responses: 5` > `len(responses)==2` | `imap: Commands[%d].CancelAfterResponses %d > len(Responses) %d (cancel would never fire)` | `planner.go:256` |
| N-14 | `imap_t076_push_crlf_reject` | `idle.push_responses[0]` 含 CRLF | `imap: IDLE.PushResponses[%d] contains CRLF; split into multiple entries` | `planner.go:267` |
| N-15 | `imap_t070_timeout_bad_reject` | `server_timeout_behavior: "explode"` | `imap: IDLE.ServerTimeoutBehavior %q must be one of: "", "none", "close_after_idle", "keep_idle"` | `planner.go:275` |
| N-16 | `imap_t077_donetag_space_reject` | `done_tag: "A 004"` | `imap: IDLE.DoneTag %q contains SP/CRLF` | `planner.go:279` |
| N-17 | `imap_t071_doneresponse_crlf_reject` | `done_response: "A004 OK\r\nBAD"` | `imap: IDLE.DoneResponse contains CRLF; must be single-line` | `planner.go:286` |
| N-18 | `imap_t083_mime_mutex_reject` | `literal_body` + `mime_body` 并存 | `imap: Commands[%d].MIMEBody is mutually exclusive with LiteralBody and LiteralBodyB64` | `planner.go:239` |
| N-19 | `imap_t084_responses_cap_reject` | `responses` 10001 条 | `imap: Commands[%d].Responses count %d exceeds max %d` | `planner.go:205` |

**负例原子性**：每例单一故障注入；单次执行不混注。**N-2/N-3/N-4/N-5 的拒绝位在建任务前**（schema 门 / 框架 IP 门 / 顶层判死门 / 静态复制门），故无 `.neg.pcap`；其余 15 例的拒绝位在 planner `Validate`，**16 例有 neg.pcap 且实测 0 帧**（`imap_t065` 归前一类故 16 = 19 − 3）。**零假成功**：无任何负例产出成功 PCAP 或 `completed/0 packet`。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：

| 分支 | 锚词 | 代码行 | 备注 |
|---|---|---|---|
| `SrcIP` 非法 | `imap: SrcIP %q is not a valid IP address` | `planner.go:144` | **链上被框架 ip 层门抢占**（N-3 先命中），故 imap 层文案在链路径**不可达** |
| `DstIP` 非法 | `imap: DstIP %q is not a valid IP address` | `planner.go:149` | 同上 |
| `MSS < 536`（imap 层自检） | `imap: MSS %d too small (min %d per RFC 879)` | `planner.go:157` | **链上被 tcp 层 schema 门抢占**（N-2 先命中），imap 层文案链路径不可达 |
| `tag` 含 `+` | — | — | **未实现该校验**（RFC 9051 §2.2.1 禁止 `+`） |
| `literal_body` 超 100 MB | `imap: Commands[%d].LiteralBody length %d exceeds max %d` | `planner.go:221` | 无例 |
| `literal_body_b64` 解码后超 100 MB | `imap: Commands[%d].LiteralBodyB64 decoded length %d exceeds max %d` | `planner.go:229` | 无例 |
| `mime_body` 构造后超 100 MB | `imap: Commands[%d].MIMEBody constructed length %d exceeds max %d` | `planner.go:244` | 无例 |
| `push_responses` 超 1000 | `imap: IDLE.PushResponses count %d exceeds max %d` | `planner.go:263` | 无例 |
| `done_tag` 超 256 | `imap: IDLE.DoneTag length %d exceeds max %d` | `planner.go:282` | 无例 |

**不得误报的合法协议事件**：空 `cmd`（`t005`）；`{0}` 占位（`t009`/`t036`）；多响应事务（`t019`/`t030`–`t039`）；IDLE 四形态（`t043`–`t047`）；流水线（`t010`）；MIME 三形态（`t051`/`t052`/`t080`/`t081`）；UTF-8 信箱名开（`t049`）；IPv6（`t062`）；IMAPS 993（`t061`/`t082`）；双流全缺省（`t078`）；无 LOGOUT 的自然结束（`t058`，合法——`terminates=true` 由 tcp 层 FIN 保证）。

## 8. 边界

- **帧长**：单帧 payload 上界 = `MSS`（1460，非末段）；literal 末段 < MSS。**包数区间 [10, 30]**（实测）。
- **literal 长度上界**：`MaxLiteralLen = 100 MB`（`planner.go:96`）——三路（`literal_body` 原长 / `literal_body_b64` 解码后 / `mime_body` 构造后）分别校验。今日最大实测 N = **6023**（`t051`）。
- **responses 条数上界**：`MaxResponsesPerCommand = 10000`（`planner.go:85`）；超即拒（N-19）。
- **push 条数上界**：`MaxPushResponses = 1000`（`planner.go:90`）。
- **tag 长度上界**：`MaxTagLen = 256`（`planner.go:79`，RFC 9051 §2.2.1）；超即拒（N-7）。
- **MSS**：下限 536（RFC 879，`MinMSS`）；上限 65535（tcp 层 schema）；缺省 1460。
- **端口**：显式 143 全正例；**缺省 143 今日无例**（`t078` 走缺省但断言里无 `tcp.dstport`）→ A′ 补例（G-IMAP-13）。IMAPS 显式 993（`t061`/`t082`），**registry `FieldContract` 不强制**（用户值优先）。
- **地址族**：IPv4 82 例 / IPv6 1 例（`t062`）；**异族混写拒绝今日无例** → A′ 立项。
- **协议与地址族解耦**：`t062` 的 `imap.line` 等字段值与 IPv4 例**逐字节相同**，仅偏移从 54 变 74（与 opcua 同款结论）。
- **TLS 链**：`t061`/`t082` 只断 `tcp.dstport=993`；**imap payload 偏移在 TLS 下未钉**（G-IMAP-10）。
- **多流**：`t078` 双流各 7 帧；`flows > 1` 且四元组被显式标量钉死即拒（N-5）。
- 不得产生回绕长度或超量分配（每帧长度由 literal 长度或响应字符串长度一次算定）。

## 9. 原子 ID 与完成定义（84 个唯一语义 ID，顺序为权威）

**顺序 = `cases/imap.json` 数组顺序**（权威）。**包数**由 81 份实测 pcap 逐例 `tcpdump -r | wc -l` 回填，与结果产物 `imap.md` 表格**逐例一致**（84/84 对账，机读）；负例标注为「—（0 帧）」。

| # | ID | 类型 | 覆盖（设计 §） | 包数（实测） |
|---:|---|---|---|---:|
| 1 | `imap_t001_default_session` | 正 | §3.1/§3.2：三命令默认会话基线 | 16 |
| 2 | `imap_t002_tag_explicit` | 正 | §5.3：tag 显式 A001 | 13 |
| 3 | `imap_t003_tag_auto` | 正 | §5.3：空 tag 自动 A001/A002 | 15 |
| 4 | `imap_t004_tag_shapes` | 正 | §5.3：tag 点/线/数字三形 | 17 |
| 5 | `imap_t005_empty_cmd_challenge` | 正 | §3.1：空 Cmd 跳过命令帧 | 12 |
| 6 | `imap_t006_select_wrong_state` | 正 | §5.2 I-1：未认证态 SELECT 台词 | 13 |
| 7 | `imap_t007_bye_greeting` | 正 | §3.1：`* BYE` 问候（最短链） | 10 |
| 8 | `imap_t008_append_literal` | 正 | §3.4.1：命令侧 literal 上行 | 16 |
| 9 | `imap_t009_append_b64_fetch_placeholder` | 正 | §3.4.2/§3.4.4：B64 源 + 响应侧 `{0}` 替换 | 21 |
| 10 | `imap_t010_pipelined` | 正 | §3.7：流水线双相位 | 15 |
| 11 | `imap_t011_capability` | 正 | §3.3：CAPABILITY 任意态 | 14 |
| 12 | `imap_t012_noop` | 正 | §3.3：NOOP 任意态 | 13 |
| 13 | `imap_t013_logout` | 正 | §5.2：LOGOUT + `* BYE` | 11 |
| 14 | `imap_t014_login_ok` | 正 | §3.3：LOGIN 成功（OK） | 13 |
| 15 | `imap_t015_login_no` | 正 | §3.3：LOGIN 失败（NO） | 13 |
| 16 | `imap_t016_authenticate` | 正 | §5.5 #9：AUTHENTICATE 双形 + 取消 | 19 |
| 17 | `imap_t017_starttls` | 正 | §1 边界③：STARTTLS 台词 | 13 |
| 18 | `imap_t018_enable` | 正 | §4：ENABLE IMAP4rev2 | 16 |
| 19 | `imap_t019_select_ok` | 正 | §5.2：SELECT 成功（untagged + tagged） | 16 |
| 20 | `imap_t020_select_no` | 正 | §3.3：SELECT 失败（NO） | 15 |
| 21 | `imap_t021_examine` | 正 | §4：EXAMINE 只读选择 | 16 |
| 22 | `imap_t022_create` | 正 | §4：CREATE 信箱 | 15 |
| 23 | `imap_t023_delete` | 正 | §3.3：DELETE 成功 + 失败（NO） | 17 |
| 24 | `imap_t024_rename` | 正 | §4：RENAME 信箱 | 15 |
| 25 | `imap_t025_subscribe` | 正 | §4：SUBSCRIBE + UNSUBSCRIBE | 17 |
| 26 | `imap_t026_list` | 正 | §4：LIST 信箱列表 | 16 |
| 27 | `imap_t027_namespace` | 正 | §4：NAMESPACE | 16 |
| 28 | `imap_t028_status` | 正 | §4：STATUS 信箱状态 | 16 |
| 29 | `imap_t029_append_flags` | 正 | §3.4.1：APPEND 带 flags + literal | 17 |
| 30 | `imap_t030_close` | 正 | §5.2：CLOSE 已选态 | 18 |
| 31 | `imap_t031_unselect` | 正 | §5.2：UNSELECT 已选态 | 18 |
| 32 | `imap_t032_expunge` | 正 | §5.2：EXPUNGE 已选态 | 19 |
| 33 | `imap_t033_search` | 正 | §4：SEARCH 非空结果 | 19 |
| 34 | `imap_t034_search_empty` | 正 | §4：SEARCH 空结果（`* SEARCH` 无参数） | 19 |
| 35 | `imap_t035_fetch_flags` | 正 | §4：FETCH FLAGS | 19 |
| 36 | `imap_t036_fetch_literal_down` | 正 | §3.4.2：响应侧 literal 三段 | 21 |
| 37 | `imap_t037_store` | 正 | §4：STORE ±FLAGS | 21 |
| 38 | `imap_t038_copy` | 正 | §3.3：COPY 成功 + 失败（NO） | 20 |
| 39 | `imap_t039_move_uid` | 正 | §4：MOVE + UID FETCH | 21 |
| 40 | `imap_t040_no_code` | 正 | §3.3：NO 台词 | 13 |
| 41 | `imap_t041_unknown_bad` | 正 | §3.3：未知命令 BAD | 15 |
| 42 | `imap_t042_rfc8_session` | 正 | §3.4.2：RFC 9051 §8 官方示例会话 | 21 |
| 43 | `imap_t043_idle_push` | 正 | §3.6：IDLE 有 push | 23 |
| 44 | `imap_t044_idle_nopush` | 正 | §3.6：IDLE 无 push | 22 |
| 45 | `imap_t045_idle_close` | 正 | §3.6：IDLE timeout `close_after_idle` | 24 |
| 46 | `imap_t046_idle_keep` | 正 | §3.6：IDLE timeout `keep_idle` | 24 |
| 47 | `imap_t047_idle_none` | 正 | §3.6：IDLE timeout `none` | 23 |
| 48 | `imap_t048_condstore` | 正 | §5.5 #10：CONDSTORE 尾注 | 20 |
| 49 | `imap_t049_utf8_on` | 正 | §1 边界⑦：UTF-8 信箱名开 | 16 |
| 50 | `imap_t050_utf8_off_reject` | **负** | §7 N-1：非 ASCII 信箱名拒绝 | —（0 帧） |
| 51 | `imap_t051_mime_multi` | 正 | §3.5：MIME 多部件 + 双附件（N=6023） | 25 |
| 52 | `imap_t052_mime_append_up` | 正 | §3.5：APPEND MIME 上行（显式 boundary） | 17 |
| 53 | `imap_t053_mss_reject` | **负** | §7 N-2：MSS 100 < 536 | —（0 帧） |
| 54 | `imap_t054_gmail` | 正 | §4 ⑬：Gmail 现网形 | 13 |
| 55 | `imap_t055_outlook` | 正 | §4 ⑬：Outlook 现网形 | 13 |
| 56 | `imap_t056_dovecot` | 正 | §4 ⑬：Dovecot 现网形 | 16 |
| 57 | `imap_t057_two_fetch` | 正 | §5.1：同连接两 FETCH（多事务） | 22 |
| 58 | `imap_t058_abort_no_logout` | 正 | §5.1：无 LOGOUT 断线（FIN 照常） | 16 |
| 59 | `imap_t059_keepalive_noop` | 正 | §5.1：三 NOOP 长保活 | 19 |
| 60 | `imap_t060_composite_a` | 正 | §5.1：复合流 A（登录+取改） | 23 |
| 61 | `imap_t061_imaps_993` | 正 | §2：IMAPS 993（`[ip,tcp,tls,imap]`） | 20 |
| 62 | `imap_t062_v6` | 正 | §2：IPv6 承载 | 13 |
| 63 | `imap_t063_bad_ip_reject` | **负** | §7 N-3：坏 IP | —（0 帧） |
| 64 | `imap_t064_presence_reject` | **负** | §7 N-4：顶层 `imap` 子映射判死 | —（0 帧） |
| 65 | `imap_t065_static_pinned_reject` | **负** | §7 N-5：静态四元组 + flows>1 | —（0 帧） |
| 66 | `imap_t072_tag_space_reject` | **负** | §7 N-6：tag 含空格 | —（0 帧） |
| 67 | `imap_t066_tag_toolong_reject` | **负** | §7 N-7：tag 超 256 | —（0 帧） |
| 68 | `imap_t067_cmd_crlf_reject` | **负** | §7 N-8：cmd 含 CRLF | —（0 帧） |
| 69 | `imap_t073_resp_crlf_reject` | **负** | §7 N-9：响应含 CRLF | —（0 帧） |
| 70 | `imap_t068_b64_bad_reject` | **负** | §7 N-10：B64 解码失败 | —（0 帧） |
| 71 | `imap_t074_literal_mutex_reject` | **负** | §7 N-11：literal 两源互斥 | —（0 帧） |
| 72 | `imap_t069_emit_idle_no_idle_reject` | **负** | §7 N-12：EmitIDLE 无 IDLE | —（0 帧） |
| 73 | `imap_t075_cancel_range_reject` | **负** | §7 N-13：取消位越界 | —（0 帧） |
| 74 | `imap_t076_push_crlf_reject` | **负** | §7 N-14：push 含 CRLF | —（0 帧） |
| 75 | `imap_t070_timeout_bad_reject` | **负** | §7 N-15：超时枚举非法 | —（0 帧） |
| 76 | `imap_t077_donetag_space_reject` | **负** | §7 N-16：DoneTag 含空格 | —（0 帧） |
| 77 | `imap_t071_doneresponse_crlf_reject` | **负** | §7 N-17：DoneResponse 含 CRLF | —（0 帧） |
| 78 | `imap_t083_mime_mutex_reject` | **负** | §7 N-18：MIME 与 literal 互斥 | —（0 帧） |
| 79 | `imap_t084_responses_cap_reject` | **负** | §7 N-19：Responses 超 10000 | —（0 帧） |
| 80 | `imap_t078_default_twoflow` | 正 | §2：全缺省双流（`strategy_fc.flows=2`） | 14 |
| 81 | `imap_t079_composite_b` | 正 | §5.1：复合流 B（8 命令，最长链） | 30 |
| 82 | `imap_t080_mime_empty_text` | 正 | §3.5：MIME 空正文 + 双附件（N=5874） | 25 |
| 83 | `imap_t081_mime_attach_only` | 正 | §3.5：MIME 纯附件无正文（N=5689） | 24 |
| 84 | `imap_t082_imaps_chain` | 正 | §2：IMAPS 实链 993 | 20 |

**ID 顺序注（须写清）**：ID 的数字后缀**不等于 JSON 顺序**——JSON 顺序为 §9 表列（`t072` 在 `t066` 之前、`t078` 在 `t079`–`t082` 之前、`t083`/`t084` 在 `t078` 之前）。**JSON 顺序为权威**（需求文档 §7：ID 顺序 = 未来 JSON 顺序，保持稳定即可）。

### 9.1 包数公式（可复算，63/63 非 TLS 正例逐例命中）

```
包数 = 3 (TCP 握手)
     + 4 (TCP FIN 四包)
     + [banner != ""]                                          → 1
     + Σ 每 commands[i]:
           [cmd != ""]                                         → 1
           [cmd 含 {N} 且 len(literalBody) > 0]                → ceil(len / MSS)
           Σ 每 responses[j]:
               不含 {N}                                        → 1
               含 {N}                                          → 1（头帧）
                                                               + [len(body) > 0] × ceil(len / MSS)
                                                               + 1（收尾 CRLF）
           [uid_cache_invalidation]                            → 1
           [cancel_after_responses > 0]                        → 1
           [emit_idle && IDLE != nil]                          → 1 (IDLE 命令) + 1 (+ idling)
                                                               + len(push_responses)
                                                               + 1 (DONE)
                                                               + [done_response != ""] × 1
                                                               + [timeout ∈ {close_after_idle, keep_idle}] × 1
```

**校验（机读，脚本复算）**：**63 个非 TLS 正例全部命中**（0 例外）。**2 个 TLS 例（`t061`/`t082`）不适用**——TLS 握手/挥手帧由 tls 层产出（各 20 帧，其中 imap 层贡献 13，tls 层贡献 7），公式需加 TLS 项（**今日无独立推导**，见 G-IMAP-10）。

**代表例校验**：`t001` = 3+4+1(banner) + [1+1] + [1+2] + [1+2] = **16** ✓；`t007` = 3+4+1+[1+1] = **10** ✓；`t036` = 3+4+1+[1+1]+[1+2]+[1+1+1+1+1]+[1+1] = **21** ✓；`t043` = 3+4+1+[1+1]+[1+2]+[1+1+1+2+1+1]+[1+1] = **23** ✓；`t079` = 3+4+1+ 8 命令（1 条带 literal）+ 12 响应 + 1 体帧 + … = **30** ✓。

**注（口径）**：§9 表包数与结果产物 `imap.md` 表格**逐例一致**（84/84 机读对账）；两者**均**由实测 pcap 回填，非互抄。`imap_t078_default_twoflow` 的 14 帧 = **两条流各 7 帧**（`7 = 3+4+0 命令+0 banner`，公式按单流算 → 双流翻倍）。

## 10. P1 规范矩阵（八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | 客户端主动 TCP 建连；服务端先发 greeting（RFC 9051 §3） | 场景①–⑮ | `DependsOn ["tcp"]` 单值 + `OptionalOn ["tls"]`（`registry.go:1590`）；greeting 已落码（`planner.go:418-424`） | 无 |
| 2 | 命令/消息表 | 未认证态 6 命令 + 认证态 12 命令 + 已选态 9 命令 + 扩展（IDLE/CONDSTORE）（RFC 9051 §6 + RFC 2177 + RFC 7162） | 场景①–⑮ | 命令是**自由文本**（`cmd` 字符串），planner **不做命令名白名单**——故"命令表"在生成器层面是**开放集** | 无（开放集是设计选择，非缺陷） |
| 3 | 状态机 | 四态 NOT-AUTH/AUTH/SELECTED/LOGOUT + 逐命令 Valid States（RFC 9051 §3 + §6.x） | §5.2 | **不强制**（`planner.go:29-33` 逐字声明）；用户剧本负责 | **G-IMAP-9**（状态机维度覆盖仅 I-1/I-7） |
| 4 | 字段表 | tag（1–256，禁 SP/CR/LF/`+`）+ CRLF 终止 + literal `{N}CRLF` + 三态 completion（RFC 9051 §2.2.1/§2.2.4/§4.3） | 数据场景层 | `formatCommandLine` + `replaceLiteralPlaceholder` + 常量表逐字段 | tag 禁 `+` **未实现**（G-IMAP-8） |
| 5 | 错误处理 | 19 条负例 + 9 个未入例拒绝分支（§7） | 负例 N-1…N-19 | planner 22 种拒绝分支（`planner.go:144-286`）+ 框架门 4 种 | A′ 9 条（§14） |
| 6 | 超时与活性 | IDLE 有 29 分钟服务端超时（RFC 2177 §4）；无 PING 类心跳；NOOP 是保活手段 | 场景⑩⑪ | `IDLETimeoutBye` 立即发出（不真等，`planner.go:98-103`）；NOOP 保活已落码（`t059`） | `keep_idle` 语义未落码（G-IMAP-3） |
| 7 | NAT/代理/被动 | 无被动模式概念（客户端直连） | — | 无 `sessions[].src_port`；多流走策略级 `flow_control` | **显式不适用**被动模式；NAT 穿透为框架面 |
| 8 | 版本/方言 | IMAP4rev1（RFC 3501）/ IMAP4rev2（RFC 9051）；IDLE（RFC 2177）；CONDSTORE（RFC 7162）；UTF-8（RFC 6855）；IMAPS（993） | 场景③④⑩⑫⑭ | 命令为开放集（方言无枚举）；`allow_utf8_mailbox` 二值；IMAPS 走 tls 层 | STARTTLS 真升级未实现（§1 边界③） |

### 10.2 子表①：命令 × 终态矩阵（逐格已覆/立项/不适用）

| 命令族 | T1 正常终态 | T2 配置拒绝 | T3 异常终止（RST） |
|---|---|---|---|
| CAPABILITY | 已覆（`t011`/`t056`） | 已覆（N-6…N-19 代表例，拒绝与命令无关） | A′ 立项（G-IMAP-13） |
| NOOP | 已覆（`t012`/`t059`） | 同上代表已覆 | A′ 立项 |
| LOGOUT | 已覆（`t013`） | 同上 | A′ 立项 |
| STARTTLS | 已覆（`t017`，台词） | 同上 | A′ 立项 |
| AUTHENTICATE | 已覆（`t016`） | 同上 | A′ 立项 |
| LOGIN | 已覆（`t014`/`t015`/`t054`） | 同上 | A′ 立项 |
| SELECT / EXAMINE | 已覆（`t019`/`t020`/`t006`/`t021`） | 同上 | A′ 立项 |
| CREATE/DELETE/RENAME/SUBSCRIBE/UNSUBSCRIBE | 已覆（`t022`–`t025`） | 同上 | A′ 立项 |
| LIST/NAMESPACE/STATUS | 已覆（`t026`–`t028`） | 同上 | A′ 立项 |
| APPEND | 已覆（`t008`/`t029`/`t052`/`t079`） | 同上 | A′ 立项 |
| ENABLE | 已覆（`t018`） | 同上 | A′ 立项 |
| CLOSE/UNSELECT/EXPUNGE | 已覆（`t030`–`t032`） | 同上 | A′ 立项 |
| SEARCH/FETCH/STORE/COPY/MOVE/UID | 已覆（`t033`–`t039`/`t057`） | 同上 | A′ 立项 |
| IDLE | 已覆（`t043`–`t047`） | 同上 | A′ 立项 |
| 未知命令（FOO） | 已覆（`t041` BAD 台词） | 同上 | A′ 立项 |
| 状态机错序 | 已覆（`t006`/`t040` 台词） | 同上 | A′ 立项 |

**逐格重数**：17 行 × 3 列 = 51 格——已覆 **34**（T1 列 17 + T2 列 17）/ A′ 立项 **17**（T3 列 17）/ 不适用 **0**，零空格。34 + 17 = 51 ✓

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **32 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | banner 缺省（无 greeting） | 覆（`t064`/`t065`/`t078`——机读实测**仅 3 例**无 banner；其余 81 例均显式给） |
| 2 | banner 单行带 `[CAPABILITY …]` | 覆（`t006`/`t056`） |
| 3 | banner `* BYE`（拒连问候） | 覆（`t007`） |
| 4 | banner 已带 CRLF | **A′ 立项**（`planner.go:420` 的 `HasSuffix` 分支无例） |
| 5 | tag 显式 | 覆（`t002` 等绝大多数） |
| 6 | tag 空（自动 `A%03d`） | 覆（`t003`） |
| 7 | tag 点形（`tag.42`） | 覆（`t004`） |
| 8 | tag 线形（`X-Custom-1`） | 覆（`t004`） |
| 9 | tag 纯数字（`001`） | 覆（`t004`） |
| 10 | tag 含 SP | 覆负例（`t072`） |
| 11 | tag 超 256 | 覆负例（`t066`） |
| 12 | tag 含 `+` | **A′ 立项**（校验未实现，G-IMAP-8） |
| 13 | `cmd` 空 | 覆（`t005`） |
| 14 | `cmd` 含 CRLF | 覆负例（`t067`） |
| 15 | `cmd` 含高位字节（UTF-8 关） | 覆负例（`t050`） |
| 16 | `cmd` 含高位字节（UTF-8 开） | 覆（`t049`） |
| 17 | 响应单行 untagged（`*`） | 覆（`t019` 等） |
| 18 | 响应 continuation（`+`） | 覆（`t008`/`t016`/`t043`） |
| 19 | 响应 tagged `OK` | 覆（绝大多数） |
| 20 | 响应 tagged `NO` | 覆（`t015`/`t020`/`t023`/`t038`/`t040`） |
| 21 | 响应 tagged `BAD` | 覆（`t041`/`t007`） |
| 22 | 响应含 CRLF | 覆负例（`t073`） |
| 23 | 响应数超 10000 | 覆负例（`t084`） |
| 24 | literal 命令侧（`literal_body`） | 覆（`t008`/`t029`/`t079`） |
| 25 | literal 命令侧（`literal_body_b64`） | 覆（`t009`） |
| 26 | literal 响应侧（`{0}` 被替换） | 覆（`t009`/`t036`） |
| 27 | literal 响应侧（`{5}` 原值） | 覆（`t042`） |
| 28 | literal 两源并存 | 覆负例（`t074`） |
| 29 | `literal_body_b64` 解码失败 | 覆负例（`t068`） |
| 30 | literal 超 100 MB | **A′ 立项**（三支分支无例，G-IMAP-8） |
| 31 | `file_source` literal | **A′ 立项**（链路径不可用，G-IMAP-6） |
| 32 | MIME SIMPLE（无 parts/attachments） | **A′ 立项**（`t083` 虽有 `mime_body:{text:"x"}` 但它是**负例**——`planner.go:237-240` 的互斥检查**先于** `constructMIMEBody` 返回，SIMPLE 构造路径**今日零正例**） |
| 33 | MIME MULTIPART + parts + 双附件 | 覆（`t051`） |
| 34 | MIME 空正文 + 附件 | 覆（`t080`） |
| 35 | MIME 纯附件无正文 | 覆（`t081`） |
| 36 | MIME 显式 boundary | 覆（`t052`） |
| 37 | MIME 自动 boundary | 覆（`t051`/`t080`/`t081`） |
| 38 | MIME 与 literal 并存 | 覆负例（`t083`） |
| 39 | MIME 超 100 MB | **A′ 立项**（`planner.go:244` 分支无例） |
| 40 | attachment `data`（裸文本） | 覆（`t052`） |
| 41 | attachment `data_b64`（预编码） | 覆（`t051`/`t080`/`t081`） |
| 42 | `cancel_after_responses` 合法 | 覆（`t016`） |
| 43 | `cancel_after_responses` 越界 | 覆负例（`t075`） |
| 44 | `uid_cache_invalidation` | 覆（`t048`） |
| 45 | `pipelined_commands` | 覆（`t010`） |
| 46 | `emit_idle` 无 IDLE 配置 | 覆负例（`t069`） |
| 47 | IDLE 有 push | 覆（`t043`） |
| 48 | IDLE 无 push | 覆（`t044`） |
| 49 | IDLE `close_after_idle` | 覆（`t045`） |
| 50 | IDLE `keep_idle` | 覆（`t046`，**与 `t045` 字节等价**，G-IMAP-4） |
| 51 | IDLE `none` | 覆（`t047`） |
| 52 | IDLE `done_response` 缺省 | 覆（`t044`–`t047` 均给了；**缺省分支无例** → A′） |
| 53 | IDLE push 含 CRLF | 覆负例（`t076`） |
| 54 | IDLE 超时枚举非法 | 覆负例（`t070`） |
| 55 | IDLE `done_tag` 含 SP | 覆负例（`t077`） |
| 56 | IDLE `done_tag` 超长 | **A′ 立项**（`planner.go:282` 分支无例） |
| 57 | IDLE `done_response` 含 CRLF | 覆负例（`t071`） |
| 58 | IDLE push 超 1000 | **A′ 立项**（`planner.go:263` 分支无例） |
| 59 | IPv4 载体 | 覆（82 例） |
| 60 | IPv6 载体 | 覆（`t062`） |
| 61 | 异族混写 | **A′ 立项**（无例） |
| 62 | 端口显式 143 | 覆（绝大多数） |
| 63 | 端口显式 993（TLS 链） | 覆（`t061`/`t082`） |
| 64 | 端口缺省（全空层） | **A′ 立项**（`t078` 走缺省 143，但该例**无 `tcp.dstport` 断言**——端口补齐路径无直接证据） |
| 65 | 多流（flows=2） | 覆（`t078`） |
| 66 | 静态四元组 + flows>1 | 覆负例（`t065`） |

**逐行重数（机读）**：66 行 = **已覆 56** + **A′ 立项 10**。立项行号 = **4 / 12 / 30 / 31 / 32 / 39 / 56 / 58 / 61 / 64**（10 行）；其余 56 行均有正例或负例落点。56 + 10 = 66 ✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 连接问候与能力协商（RFC 9051 §3） | `t001`/`t011`/`t054`–`t056` | 已覆 |
| 2 | 明文登录（RFC 9051 §6.2.3） | `t014`/`t015` | 已覆 |
| 3 | SASL 认证（RFC 9051 §6.2.2） | `t016` | 已覆 |
| 4 | 认证取消（`*` 行） | `t016` | 已覆 |
| 5 | 信箱列举与状态（LIST/NAMESPACE/STATUS） | `t026`–`t028` | 已覆 |
| 6 | 打开信箱（SELECT/EXAMINE） | `t019`–`t021` | 已覆 |
| 7 | 信箱增删改订（CREATE/DELETE/RENAME/SUBSCRIBE） | `t022`–`t025` | 已覆 |
| 8 | 邮件检索（SEARCH 非空/空） | `t033`/`t034` | 已覆 |
| 9 | 邮件读取（FETCH FLAGS / BODY[]） | `t035`/`t036`/`t057` | 已覆 |
| 10 | 标记与搬运（STORE/COPY/MOVE/UID） | `t037`–`t039` | 已覆 |
| 11 | 投递（APPEND + literal 上行） | `t008`/`t029`/`t052` | 已覆 |
| 12 | 附件下载（MIME multipart） | `t051`/`t080`/`t081` | 已覆 |
| 13 | 推送等待（IDLE，RFC 2177） | `t043`–`t047` | 已覆 |
| 14 | 长保活（NOOP 轮询） | `t059` | 已覆 |
| 15 | 会话终止（LOGOUT / 自然断线） | `t013`/`t058` | 已覆 |
| 16 | 现网厂商方言（Gmail/Outlook/Dovecot） | `t054`–`t056` | 已覆 |
| 17 | 加密端口（IMAPS 993） | `t061`/`t082` | 已覆 |
| 18 | 多流并发 | `t078` | 已覆 |
| 19 | 复合业务流（≥3 动作） | `t060`/`t079` | 已覆 |
| 20 | 扩展：CONDSTORE 缓存失效 | `t048` | 已覆 |
| 21 | 扩展：UTF-8 信箱名（RFC 6855） | `t049`/`t050` | 已覆 |
| 22 | 真实状态机推进（引擎级） | — | **明确不解决**（G-IMAP-9） |
| 23 | tag 配对校验（引擎级） | — | **明确不解决**（§1 边界②） |
| 24 | STARTTLS 真升级 | — | **明确不解决**（§1 边界③） |
| 25 | FileSource literal（链路径） | — | **明确不解决**（G-IMAP-6） |
| 26 | IDLE 29 分钟真实等待 | — | **明确不解决**（§1 边界⑥） |
| 27 | `keep_idle` 与 `close_after_idle` 行为区分 | — | **明确不解决**（G-IMAP-3） |
| 28 | 真实附件文件 IO | — | **明确不解决**（§1 边界⑤） |

21 覆 + 7 不适用 = 28。✓ **无映射无确认即缺口——本表零缺口**。

### 10.5 三路对照与候选方案对比

三路：① **规范原文**（RFC 9051 + RFC 3501 + RFC 2177 + RFC 6855 + RFC 7162 + RFC 2045/2046/2183 + RFC 879，定"必须是什么"）；② **商业化软件实际行为**（**部分取到**：`t054`/`t055`/`t056` 三例的问候原文来自 Gmail / Outlook / Dovecot 的现网实录，用例 notes 分别标注"gmail 映射：问候原文 openssl 亲验列 P5"/"outlook 映射"/"dovecot 映射：三份实录交叉能力集"——**但"列 P5"意味着逐字核对尚未完成**，且**未抓取真实服务器 pcap 做线字节对照** → G-IMAP-14 待确认）；③ **可靠开源实现思路**（Dovecot 的 IDLE 续行 `+ idling` 与裸 DONE 形态、Thunderbird 的 tag 递增 `A%04d` 惯例——只借鉴"tag 必须唯一且完成响应抄回"这一条思路；**注意**：本实现用 `A%03d`（3 位），Thunderbird 用 4 位，**位数不构成规范要求**）。

三路一致点：tagged command 语法 `<tag> SP <cmd> CRLF`、literal `{N}CRLF` 语法、DONE 裸发无 tag（RFC 2177 §4）、三态 completion `OK`/`NO`/`BAD`。不一致点：**`keep_idle` 与 `close_after_idle` 是否应有行为差异**（RFC 2177 §4 只规定"服务端可发 BYE 并关闭"，未定义 keep_idle 这一档；本实现的 `keep_idle` 是**自造档位**，且与 `close_after_idle` 字节等价 → G-IMAP-3）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `imap` 终结层（本版；pop3/smtp 同构先例） | 命令/响应/tag/literal/IDLE/MIME 可声明可断言；代价 = 一套层（已落码 1217 行） | **采用** |
| B | 直接 tcp 层 + 顶层 payload | 无 tag、无 literal 语义、无 IDLE 编排、无 MIME 构造 → 84 例中绝大多数不可表达 | **否决** |
| C | 拆成"IMAP 基础层 + IMAP 扩展层（IDLE/CONDSTORE）"两层 | IDLE 需要与命令序列**交织**（同一 tag 空间、同一连接时序），跨层无此通道；且 IDLE 只是命令序列中的一个命令 | **否决**（状态在 `Generate` 局部变量，单层内聚更简单） |

## 11. P2 D-IMAP-1 代码设计（八要素；as-built 定稿）

> 状态说明：实现已落码（`internal/protocol/imap/` 两文件 1217 行），本 P2 条目为 P-PIPE 文档轨对既有实现的**逆向定稿**（as-built 定稿），供后续改动的唯一入口。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:4639-5020`） | `IMAPConfig`（5 键）/ `IMAPCommand`（10 键）/ `IMAPMIMEBody`（5 键）/ `IMAPMIMEPart`（3 键）/ `IMAPAttachment`（3 键）/ `IMAPIDLE`（4 键）+ `FlowSpec.IMAP` 槽位（`:1830`） | —（共享文件） |
| `trafficgen/internal/protocol/imap/planner.go` | 常量表 + `Validate`（22 分支）+ `Plan`（legacy：自产握手/挥手/分段）+ 纯函数（`formatCommandLine` / `hasLiteralPlaceholder` / `replaceLiteralPlaceholder` / `segmentByMSS` / `synOptions` / `constructMIMEBody` / `generateMIMEBoundary` / `wrapBase64`） | 943 |
| `trafficgen/internal/protocol/imap/layer_gen.go` | 终结层生成器（`Generate` 事件模式）+ `init()` 注册生成器与校验器（含 TCP 握手/挥手强制） | 274 |
| `trafficgen/internal/protocol/imap/planner_test.go` | 50 个 `Test*` | 1152 |
| `trafficgen/internal/protocol/imap/planner_testpoints_test.go` | 70 个 `Test*` | 1459 |
| `trafficgen/internal/protocol/imap/imap_mime_test.go` | 13 个 `Test*`（MIME 构造面） | 579 |
| `trafficgen/internal/protocol/imap/imap_f2_done_test.go` | 3 个 `Test*` | 123 |
| 接线 6 件 | registry 注册（`layers/registry.go:1590`）/ translate 层内分支（`chain_planner_translate.go:2667`）/ convert 子配置搬运（`strategy_convert.go:1189` + `ParseIMAPConfigFromMap` `:3493`）/ 顶层判死（`strategy_convert.go:8889`）/ protocols 准入（`protocols.go:45`）/ 缺省端口 + 源端口语义（`chain_planner.go:1212` / `:952`） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`planner.go:140-291`）：**只读**（不写默认值——`validate_conventions.md §1.1` 契约，默认值填充在 `Plan`）；`IMAP == nil` 通过（空配置默认流）；分支见 §7 表 + §7 未入例表。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`planner.go:296-673`）：legacy 路径；先 `Validate`，再起 goroutine 流式产出（channel cap 256）；ctx 取消即关。
- `Generate(ctx, req *layers.GenRequest) error`（`layer_gen.go:38-224`）：事件模式；`req.EmitMsg == nil` 即报错（防误接线）；`req.Meta.IMAP == nil` 走零值 `&IMAPConfig{}`。
- 生成器：`Name() "imap"`；`GenEvents()` 返回自身；`EmitEvent` **未接线显式错**（`layer_gen.go:252-254`，防误调）；校验器闭包**强制** `spec.TCP.Handshake = true` / `Termination = true`（`layer_gen.go:260-273`）。

### 11.3 数据结构

- `IMAPConfig{Banner, Commands[], IDLE, PipelinedCommands, AllowUTF8Mailbox}`（`types.go:4678-4725`）——**5 键，与 registry Fields 逐键一致** ✓
- `IMAPCommand{Tag, Cmd, Responses[], LiteralBody, LiteralBodyB64, FileSource, EmitIDLE, CancelAfterResponses, UIDCacheInvalidation, MIMEBody}`（`:4730-4840`）——**10 键**
- `IMAPIDLE{PushResponses[], DoneTag, DoneResponse, ServerTimeoutBehavior}`（`:4961-4992`）——**4 键**
- `IMAPMIMEBody{Headers[], Boundary, Text, Parts[], Attachments[]}`（`:4874-4906`）；`IMAPMIMEPart{ContentType, Body, Headers[]}`（`:4916-4932`）；`IMAPAttachment{Filename, ContentType, Data}`（`:4943-4956`）

**registry 校验面（须写清）**：registry 只验**层顶 5 键存在性**（V9）；`commands`（`list`）/ `idle`（`object`）是嵌套容器，**其内部键（`IMAPCommand` 10 键 / `IMAPIDLE` 4 键）无 registry 校验面**——值语义全归 translate 分支的 `ParseIMAPConfigFromMap` + planner `Validate`（G-IMAP-12）。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry Fields 5 键 allowlist）→ translate（层内 config → `spec.IMAP`，**经 `ParseIMAPConfigFromMap` 而非 JSON 往返**，§3.5 判死教训）→ planner `Validate` → 生成器 `Generate` → 逐帧 `EmitMsg`（greeting → 命令/响应/IDLE → 流水线重排）→ tcp 层生成器补握手/seq-ack/分段/挥手 → writer（PCAP/NIC）。

### 11.5 错误分支

22 种 planner 拒绝（`planner.go:144-286`，§7 表 + §7 未入例表）+ 4 种框架门拒绝（schema 范围门 `complete.go:325` / 框架 IP 门 `convert.go:55` / 顶层判死门 `strategy_convert.go:8893` / 静态复制门 `semantic.go:285`）全部传 task error（**零假成功**——19 负例实测 0 帧）。

**链路径下的文案可达性（须写清，不得冒充）**：`SrcIP`/`DstIP` 非法（`:144`/`:149`）与 `MSS < 536`（`:157`）三条 imap 层文案在**链路径不可达**——框架 ip 层门与 tcp 层 schema 门**先命中**（`t063`/`t053` 的 `error_contains` 实测为框架文案，非 imap 文案）。三条文案只在 legacy 路径（单测）可达。

### 11.6 性能边界

见 §6（事件逐条产出、per-flow 局部 `autoTagCounter`、无跨流共享、无锁；吞吐数字待 P4 基准，不写承诺）。

### 11.7 与现有逻辑的冲突点

- **`DoneTag` 是死配置**（G-IMAP-2）：产出零引用，`types.go:4973-4974` 注释与实现相反。
- **`keep_idle` ≡ `close_after_idle`**（G-IMAP-3）：两 case 分支体逐字相同，且后续都走 FIN。
- **`{N}` 占位值不参与校验**（G-IMAP-5）：命令侧原样发、响应侧被替换。
- **状态机与 tag 配对不强制**（G-IMAP-9 / §1 边界②）：设计选择，非缺陷，但覆盖维度窄。
- **`file_source` 链路径不可用且无互斥校验**（G-IMAP-6 / §7 未入例表）。
- **动态 allowlist 零命中**（`internal/core/layer_dyn.go` 头部，`grep imap` = 0 实测）→ 业务字段动态对象即拒；四元组 `ip`/`tcp` 全开。见 §12.12。
- **registry Fields 5 键与 `IMAPConfig` 5 键逐键一致**，但嵌套键无校验面（G-IMAP-12）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议两文件 + 接线 6 处（registry / protocols / translate / convert / 顶层判死 / chain_planner）；不触及其他协议。cases 回滚 = 恢复 84 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 **83/84 例顶层 = `{layers}` 仅此一键**，第 84 例（`t064`）的 `{layers, imap}` 是 **§12-P2 ①点名的判死负例形状**（层链 + 顶层空子映射并存），非残留；目标形状见 §2 样例且**存量已达标** | §12.1；`cases/imap.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 imap 流量模板；任务 = 多策略合跑 + 总量封顶；框架语义未动；多流走 `strategy_fc`/`flow_control`（`t078`） | 设计 §2 样例 + §12.1 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/**关联标识（tag）**/插入位置（终结层）/时间线。**有长连接，不豁免** | §12.3 + §5 |
| §4 查规范 | RFC 9051 + RFC 3501 + RFC 2177 + RFC 6855 + RFC 7162 + RFC 2045/2046/2183 + RFC 879 + tshark 3.6.14 字段（18 条）与 81 份 pcap 实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["tcp"]` + `OptionalOn ["tls"]`（`registry.go:1590`）；22+4 种拒绝分支；失败传 task error（19 负例实测 0 帧） | §5/§7/§11.5 |
| §6 性能 | 见 §6（六要素齐；吞吐数字标待 P4 基准，不写承诺；pcap/NIC 两路验收明写） | §6 |
| §7 三份文档 | `105-imap-{design,testcase}.md` v1.0.0（本版）+ D-IMAP-1（§11，as-built 定稿）+ T-IMAP（testcase §2，84 ID）。**无旧稿层**（本协议首次成文） | 修订记录 |
| §8 设计先行 | **例外**：本协议为批次二 **as-built 型**（实现与 cases 先行），文档为逆向定稿；顺序差异已在本节显式声明 | 任务书 §"产出" |
| §9 测试三源 | 三源 = RFC 9051/3501/2177/6855/7162/2045/2046/2183/879（§10）+ D-IMAP-1（§11）+ tshark 3.6.14 字段与 **81 份 pcap**（**已到抓包级**：137 条 field 断言 + 9 条 frame 断言 + 84 例包数逐条复核 OK）；84 ID 逐项回指；存量 84 例审计去向 testcase §8 | `105-imap-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审 + 收官隔离复审；红先绿后 | 自审日志 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `imap` 已在 `registry.go:1590` 注册（**不新增层**）；生成表 127 层同代（`fields` 5 键与 registry 逐键一致，机读实测）；**若改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `imap.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/imap/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 项 | 实测 |
|---|---|
| 例数 | **84**（65 正 + 19 负） |
| `spec_json` 顶层键分布 | **`{layers}` ×83**（唯一顶层键，零游离键）+ **`{layers, imap}` ×1**（`t064`，**判死负例**） |
| 层链形状 | `[ip,tcp,imap]` ×82 + `[ip,tcp,tls,imap]` ×2 |
| 用例顶层键 | `{id,proto,summary,spec_json,expect}` ×82 + 加 `strategy_fc` ×2（`t065` 负例 / `t078` 正例） |
| `imap` 层键 union | `{banner, commands, idle, pipelined_commands, allow_utf8_mailbox}`——**5 键，与 registry Fields 逐键一致** ✓ |
| 负例 expect 形状 | 19/19 = `{expect_error, error_contains, notes}`（**三键，含 `notes`**——与严格两键口径不同，见 G-IMAP-15） |
| 正例 expect 形状 | `{fields, has_handshake, notes, terminates}` ×55 + 加 `frames` ×8 + 加 `negotiated` ×1（`t001`）+ `{has_handshake, notes, packet_count}` ×1（`t078`） |

**旧键去向表（每个键写去向）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 本协议**从未用过顶层地址**；IPv6 例已住 `layers[0].ip.{src,dst}`（`t062`） |
| `src_port` | **0** | 已住 `layers[1].tcp.src_port`（82/84 显式写 14000；`t078` 缺省走 `12345+i`） |
| `dst_port` | **0** | 已住 `layers[1].tcp.dst_port`（82/84 显式写 143 或 993） |
| `count` | **0** | 走 `flow_control`/`strategy_fc`（`t078` 用 `strategy_fc.flows=2`） |
| 顶层 `imap` 子映射 | **1**（`t064`，**判死负例**，刻意保留） | 其余 83 例已住 `layers[2].imap` |
| `strategy_fc` / `flow_control` | **2**（`t065` 负例 / `t078` 正例） | 多流载体，**非旧键**（框架级多流门），目标形按需保留 |

**结论**：**本协议存量 83/84 顶层零残留 + 1 例判死负例**——§1 门的动作 = ①**无旧键可删**；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测：非负例 83 例顶层键仅 `layers`）；③A′ 新增例全部沿用纯 layers 形（§13）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① **presence 形状** `{"layers":[…],"imap":{}}` **今日会被拒**——`CheckProtoFlat` **有 imap 分支**（`strategy_convert.go:8889-8894`，`grep` 实测存在），锚词 `protocol imap no longer accepts a top-level imap sub-config`。**`imap_t064_presence_reject` 即此形状**（`{"layers":[…],"imap":{}}`，机读实测），且**空 map 也死**（代码 `v != nil` 判定，`{}` 非 nil）→ **已建例且真红** ✓
- ② 白名单外游离键判死（`unknown field`）：**今日无通用门** → 不建该负例（建了会真绿 = 假通过）→ 缺口 G-IMAP-16。
- ③ 19 负例**每条带锚词**（已齐，§7）。
- ④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

**会话表**：
- `s1` 单连接基线（83 例，各自四元组 `10.0.0.1:14000 → 20.0.0.1:143`；IMAPS 例为 `→ :993`）：greeting? → 命令/响应事务序列 → 可选 IDLE → FIN 四包。
- `s2` 多流（`t078`，`strategy_fc.flows=2`）：两条**独立连接** `:12345` 与 `:12346`，各 7 帧，**会话间状态不串用**（`autoTagCounter` 是 per-`Generate` 局部变量，两流各自从 `A001` 起）。**本版 `imap` 层无 `sessions[]` 数组**（形态差异已声明：多会话由策略级多流承载，与 ftp/sip 的 `sessions[]` 不同）。

**事务序列**：`t1` greeting（服务端单帧，可选）→ `t2` 命令/响应对（每命令 1..N 响应，逐条或流水线两相位）→ `t3` 可选 IDLE 编排（六步）→ `t4` TCP FIN（tcp 层）。每事务四件事：**前置**（前序命令已完成 / 连接已建）、**触发**（client 发 tagged 命令）、**成功**（tagged `OK`）、**失败**（tagged `NO`/`BAD`）——见 §5.1 事务族表 + §5.2 状态表。

**关联关系（tag，本协议特有）**：
- **关联标识 = tag**（§5.3）——命令 tag ↔ 该命令 tagged completion 响应的 tag，**一一配对**。
- **取材**：显式 `tag` > 自动 `A%03d`；流水线相位 2 复用相位 1 的 tag。
- **无派生流**（诚实声明）：**单 TCP 连接承载全部命令与响应，无 `driven_by` 主从关系**；IMAP 的"数据"（邮件体）就在**同一连接**里以 literal 形式流动，**不派生副连接**（与 FTP 控制+数据双通道形成对照）。
- **IDLE 期间的 push 与 DONE**：`+ idling` 无 tag（continuation）；push `* n EXISTS` 无 tag（untagged）；`DONE` 无 tag（RFC 2177 §4 续行）；**唯一带 tag 的是服务端 `done_response`**。

**插入位置**：**终结层**（`[ip,tcp,imap]`，无中间层；IMAPS 为 `[ip,tcp,tls,imap]`，tls 是**可选底座**非中间层）。

**时间线**：消息内严格顺序 / 命令-响应**逐条交替**（默认）或**两相位分离**（流水线）/ IDLE 六步固定编排 / 多流**并行独立**（`t078`，`concurrent` 为例外路径不启用）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组**：`ip.src` / `ip.dst` / `tcp.src_port` / `tcp.dst_port` **五策略全开**（allowlist `internal/core/layer_dyn.go:15-19` 头部实测：`ip`/`tcp`/`udp`/`eth`）；保底 `DefaultSrcPort + i = 12345 + i`（`strategy_convert.go:49` 常量 + worker 注入）；dst 动态与 143 缺省和平共处（显式/动态值非零即不触发补齐）。

**业务字段 5 项全关**（allowlist 无 `imap` 行，`grep -n imap layer_dyn.go` **零命中**实测；对象即拒 `does not support dynamic`）：

| 业务字段 | 开/关 | 理由 |
|---|---|---|
| `banner` | **关** | 问候语是连接级标量，逐流变无意义（逐流变体需求 → A′ 候选） |
| `commands` | **关** | **数组**，无动态形状（列表无允许的解析面） |
| `idle` | **关** | **嵌套对象**，无动态形状 |
| `pipelined_commands` | **关** | 布尔开关 |
| `allow_utf8_mailbox` | **关** | 布尔开关 |

**嵌套键同样全关**（`IMAPCommand` 10 键 / `IMAPIDLE` 4 键）：`tag`（事务标识，逐流变会破坏配对语义）、`cmd`、`responses`（数组）、`literal_body`、`literal_body_b64`、`file_source`（对象）、`emit_idle`、`cancel_after_responses`、`uid_cache_invalidation`、`mime_body`（对象）——逐流变体需求列 A′ 候选（testcase §6.2；今日不冒充覆盖）。

**序号算法实读**：`parseLayerDyn`（`layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go:26`）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go:15-19`）——**`imap` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。

## 13. P3 对接清单（T-IMAP 草稿输入；正文落 testcase 文件）

84 ID（65 正 + 19 负）+ 包数（§9 表，逐例实测）+ 锚词（§7 表）+ fixture 常量（`src_ip=10.0.0.1` / `dst_ip=20.0.0.1` / `src_port=14000` / `dst_port=143`（IMAPS 993）；IPv6 例 `2001:db8::1` → `2001:db8::2`）+ 双通道断言基线（`tcp.dstport` / `imap.*` / offset 54（IPv6 74）frames）+ 存量审计（testcase §2–§5/§8 全量）。

**A′ 候选（15 例）**：
1. `imap_neg_tag_plus`——tag 含 `+`（校验未实现，G-IMAP-8）
2. `imap_neg_literal_too_long`——`literal_body` 超 100 MB（`planner.go:221`）
3. `imap_neg_b64_decoded_too_long`——B64 解码后超 100 MB（`:229`）
4. `imap_neg_mime_too_long`——MIME 构造后超 100 MB（`:244`）
5. `imap_neg_push_too_many`——push 超 1000（`:263`）
6. `imap_neg_donetag_toolong`——DoneTag 超 256（`:282`）
7. `imap_default_port`——删 `dst_port` 断 143 补齐（G-IMAP-13）
8. `imap_banner_crlf`——banner 自带 CRLF（`planner.go:420` `HasSuffix` 分支）
9. `imap_idle_done_default`——`done_response` 缺省（跳过第 5 步）
10. `imap_neg_mixed_family`——IPv4/IPv6 异族混写拒绝
11. `imap_abort_rst`——`tcp.rst` 异常终止（框架 tcp 层能力，本层零断言）
12. `imap_filesource_literal`——FileSource literal（**需先补链路径支持或明确不解决**，G-IMAP-6）
13. `imap_state_fetch_before_select`——未 SELECT 就 FETCH 的 `BAD` 台词（I-2，G-IMAP-9）
14. `imap_keepidle_distinct`——`keep_idle` 与 `close_after_idle` 的行为区分（**需先补实现或明确不解决**，G-IMAP-3）
15. `imap_mime_simple`——`mime_body` 无 parts/attachments 的 SIMPLE 构造路径正例（**今日零正例**，G-IMAP-8）

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| **G-IMAP-1** | **结果文档**：`trafficgen/docs/protocol-pcap-test/imap.md`（**tracked 产物**）写 "Cases: 84 — pass 84, fail 0, error 0"，末次提交 `793dfee`（**2026-09-19**）——**晚于**判死提交 `0417be5`（2026-09-13），**故不满足任务书"产物过期"的判定条件**（如实登记为不适用，不冒充过期）。**但**：`trafficgen/docs/protocol-pcap-test/imap/` **目录不存在（0 个 pcap）**——表格里 81 个 `[pcap](imap/<id>.pcap)` 链接**全部指向不存在的路径**。故「84/84 pass」**数字未经今日复跑证实 + 无 pcap 留档**。本车道**未跑**该套件，**不以任何形式**引用该产物作为可跑证据。**旁证（不得读成"已复跑"）**：本车道只读核验了 `/tmp/mcp-pcaps/imap/` 的 81 份 pcap（非 tracked），仅证明断言与既有 pcap 自洽 | **代码阶段**（P5 重跑套件后重生成该产物 + 补 pcap 目录）；本版**不删不改**（tracked 产物，删除属 P5 动作） |
| **G-IMAP-2** | **`DoneTag` 死配置**：`grep -rn DoneTag` 实测——产出路径**零引用**，只在 `planner.go:277-283` 被 Validate 检查（含 SP/CRLF、超长）；`types.go:4968-4975` 注释声称 "`<DoneTag> DONE\r\n` when DoneTag is set"，**与实现相反**（`planner.go:592-601` 明确记载该行为已废除、恒裸发 DONE） | **P4 裁定**：删字段（连带 `strategy_convert.go:3475` 的解析 + `planner.go:277-283` 两条校验 + N-16 负例 `t077`）**或**修注释为实况；二选一，不得两存 |
| **G-IMAP-3** | **`keep_idle` ≡ `close_after_idle`**：`planner.go:609-616` 两 case 分支体**逐字相同**（都发 `IDLETimeoutBye`），之后**都**走 FIN 四包。`types.go:4988-4992` 声称 `keep_idle` "do NOT teardown the TCP connection（下一命令复用同一流）"——**未落码** | **P4 裁定**：补实现（`keep_idle` 不发 FIN、后续命令续跑）或**明确不解决**并收窄 `t046` 断言口径；用例今日不得声称两者有别 |
| **G-IMAP-4** | **`t045`/`t046` 字节等价**：实测两例 pcap 除时间戳外**逐帧 payload 完全一致**（各 17 条 payload 全同），包数同为 24 → **两例不构成独立原子测试点**（§7 不可再分标准：删其一无独立证据损失） | **P4**：随 G-IMAP-3 裁定——补实现则两例自然分离；不解决则**合并为一例**（`t046` 作废并注原因） |
| **G-IMAP-5** | **`{N}` 占位值不参与校验**：命令侧**原样发出**（用户写的 N 就是线上的 N，与实际体长可不等）；响应侧**被替换**为实际体长（用户写的 N 被忽略）。故 `t009`/`t036` 写 `{0}` 配 5 字节体 → 线上产出 `{5}`；`t042` 写 `{5}` 配同一体 → 同样产出 `{5}`。**两种写法字节等价** | **P4 裁定**：是否校验命令侧 `{N} == len(body)`（RFC 9051 §4.3 要求 N 准确）——若加校验则 `t008`/`t029`/`t052`/`t079` 需重钉；今日不声称校验 |
| **G-IMAP-6** | **`file_source` literal 链路径不可用**：`layer_gen.go:22-29` 逐字声明依赖 ctx 的 `PayloadCache`（engine 级缓存），`FlowMeta` 不承载；且 `file_source` **不与 `literal_body`/`literal_body_b64` 做互斥校验**（`planner.go:217-246` 三支互斥均未含它） | **A′ 候选**：补链路径 PayloadCache 通道 + 补互斥校验；今日不得声称可用 |
| **G-IMAP-7** | **业务字段动态全关**（allowlist 无 `imap` 行，`grep` 零命中） | A′ 候选，不冒充已覆盖（§12.12） |
| **G-IMAP-8** | **未入例的拒绝分支 10 条**：`SrcIP` 非法（`:144`，链路径不可达）/ `DstIP` 非法（`:149`，同）/ `MSS < 536`（`:157`，链路径不可达）/ **tag 含 `+`（未实现校验）** / `literal_body` 超 100 MB（`:221`）/ `literal_body_b64` 解码后超限（`:229`）/ `mime_body` 构造后超限（`:244`）/ `push_responses` 超 1000（`:263`）/ `done_tag` 超 256（`:282`）/ **MIME SIMPLE 构造路径零正例**（`t083` 是负例，互斥检查先于 `constructMIMEBody` 返回） | A′ 补例（§13 第 1–6 条 + 第 15 条）；**tag 含 `+` 需先补校验** |
| **G-IMAP-9** | **状态机维度几乎零覆盖**：planner **不强制** IMAP 状态机（`planner.go:29-33` 逐字声明）；§5.2 的 I-1…I-10 十条非法转移中**仅 I-1（`t006`/`t040`）与 I-7（`t079`/`t028`）有落点**，其余 8 条（I-2…I-6、I-8…I-10）**零用例**。且 `t006`/`t040` 断的是"NO 台词被如实回放"，**不是"引擎拒绝了非法转移"** | **P4 裁定**：是否实现引擎级状态机（代价大，且与"合成测试包，不是真服务器"的契约冲突——`planner.go:31-33` 逐字）；若不实现，A′ 补 8 条"错序台词"用例并**明确断言口径为台词回放** |
| **G-IMAP-10** | **TLS 链下 imap payload 偏移未钉**：`t061`/`t082` 只断 `tcp.dstport=993`，**零 `imap.*` 字段断言、零 frame 断言**；包数公式在 TLS 下**无独立推导**（实测 20 帧 = imap 层 13 + tls 层 7） | A′ 候选：钉 TLS record 边界后的 imap 偏移（需先摸清 tls 层产出的 record 长度序列） |
| **G-IMAP-11** | **包数无机器可读断言**：84 例中**仅 `t078` 一例**把包数写进 `expect.packet_count`；其余 **64 个正例**的包数**只存在于 tracked 结果产物 `imap.md` 的表格里**，JSON 侧无该键 → **仅凭 cases JSON 无法机读判定包数**（对照 opcua 10/10 例带 `packet_count`） | **P4 必做**：为 64 个正例补 `expect.packet_count`（值取 §9 表，已由实测 pcap 回填）；补后覆盖反查门可加机读断言（testcase §9 第 3 行） |
| **G-IMAP-12** | **嵌套键无 registry 校验面**：registry `imap` 层只登记 5 个顶层键（V9 只验顶层存在性）；`commands`（list）/ `idle`（object）内部共 **14 个键**（`IMAPCommand` 10 + `IMAPIDLE` 4）无 registry allowlist → 层配置里写错键名（如 `command` 而非 `commands`、`push` 而非 `push_responses`）**不判死、静默忽略** | **P4 裁定**：是否为嵌套容器补子键 allowlist（框架面，与 opcua G-OPCUA-1 的 `Transport` 键同款）；今日不声称校验 |
| **G-IMAP-13** | **RST 异常终止零覆盖**（§3.15② 后半） | A′ 补例 `imap_abort_rst`（`tcp.rst` 框架能力，本层零断言） |
| **G-IMAP-14** | **第三源（真实服务器线字节）未取到**：`t054`/`t055`/`t056` 三例的问候原文标注"列 P5"（**逐字核对未完成**）；**未抓取真实 Gmail/Outlook/Dovecot 的 IMAP pcap 做线字节对照**；RFC 3501 §6.2.2 等条款号未逐条核对原文 | 待确认：抓真实服务器 pcap 对照，或逐条核对 RFC 原文；确认前按实现钉、不声称合规 |
| **G-IMAP-15** | **19 负例 `expect` 含 `notes` 键**（`{expect_error, error_contains, notes}` 三键）——与严格两键口径（`{expect_error, error_contains}`）不符 | **P4 收窄**：删 19 处 `notes`（notes 内容迁入 testcase 文档） |
| **G-IMAP-16** | **顶层游离键无通用门**：`CheckProtoFlat` 只查 imap 子映射 presence（①），**无白名单外游离键的通用判死**（②）→ 建了会真绿 = 假通过，**今日不建** | 等框架级 unknown-key 白名单（与 moxa G-MOXA-2 / opcua G-OPCUA-1 同款）；**禁加单协议黑名单分支** |

## 15. 修订记录

- v1.0.0（2026-09-29）：P-PIPE #105 文档轨批次二 · **as-built 型首次成文**（本协议**无旧稿**——`docs/protocol-designs/` 下不存在任何 imap 前稿，机读实测）。内容：§0 沿革（D-IMAP-1 迁移六项实测 + 产物过期登记**不适用**的如实判定 + 81 份 pcap 旁证的边界声明）；§1 范围/profile/八条显式边界（**不强制状态机、不做 tag 配对、不做真实 TLS 升级、FileSource 链路径不可用**等）；§2 层链/端口/偏移 + spec_json 样例；§3 线格式逐字段（命令行/三态响应/**literal 两侧不对称**/MIME 构造/IDLE 六步/流水线双相位/TCP 层职责）；§4 十五场景 + 五层覆盖（**流关联显式不适用**——单连接承载全部）；§5 事务模型 + **四态状态机与 I-1…I-10 十条非法转移** + **tag 取材三级与配对规则** + 15 条自动派生 + 时间线；§6 性能与两路验收；§7 **19 条负例锚词表** + 9 条未入例分支；§8 边界（六条上界）；§9 **84 ID 全表 + 可复算包数公式（63/63 非 TLS 正例逐例命中）**；§10 P1 规范矩阵（八项 + 三子表）；§11 D-IMAP-1 as-built 定稿（八要素）；§12 门1 十四行 + 12.1/12.3/12.12 强制展开 + 12-P2（**① 已建例且真红**）；§13 P3 对接 + 14 条 A′ 候选；§14 **16 条缺口**（G-IMAP-1…G-IMAP-16）。
  **自审 3 轮，末轮干净**（机读：84 例 ID/顺序 84/84 一致；`spec_json` 顶层键分布 83+1；层链形状 82+2；包数 84/84 与 pcap 一致；137 条 field 断言 + 9 条 frame 断言逐条对 pcap 复核 0 例外；包数公式 63/63 非 TLS 正例命中；19 负例锚词逐条对代码字面值；缺口 16 条编号连续无重）。

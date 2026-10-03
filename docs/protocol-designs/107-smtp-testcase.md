# #107 smtp（SMTP）测试用例契约

> 版本：v1.0.0（批次二 as-built 文档轨）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/107-smtp-design.md` v1.0.0
> 机器契约：`trafficgen/test/protocol_pcap/cases/smtp.json`（**43 例**；ID 集合、顺序、包数、断言与本版 §2/§3/§4 逐条一致，已机读实测）
> 规范基线：RFC 5321（SMTP）/ 5322（IMF）/ 2045（MIME base64）/ 2046 §5.1.1·§5.1.4（multipart、boundary）/ 2183（Content-Disposition）/ 4954（AUTH）/ 3207（STARTTLS）/ 1870（SIZE）/ 6152（8BITMIME）/ 879（MSS 下限）
> 白话一句：**四十三条检查：三十七条看"正常对话能不能照台词发出来"（投递、扩展、声明式邮件、端口、IPv6、现网 banner、多事务、多流），六条看"配置胡来能不能被拦下"；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **43 个唯一语义 ID：37 正 + 6 负**（负例 N-1…N-6）。派生规则：设计 §3 每个线格式条款、§5 每个自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：

| 项 | 实测 |
|---|---|
| 例数 | 43（37 正 + 6 负） |
| 用例级顶层键 | `{expect,id,proto,spec_json,summary}` ×43 |
| `spec_json` 顶层键 | **`{layers}` ×42** + **`{layers, smtp}` ×1**（`smtp_t002_top_smtp_presence_reject`，**判死负例**，非残留） |
| 层链形 | `[ip,tcp,smtp]` **×43**（零例外；无 `[ip,tcp,tls,smtp]`） |
| 用例级 `strategy_fc` | ×2（`smtp_t024_default_twoflow` / `smtp_t024b_static_pinned_reject`，均 `{"type":"flows","value":2}`）；**不在 `spec_json` 内** |
| `expect` 键频 | `notes`×43、`has_handshake`×37、`negotiated`×36、`terminates`×36、`has_payload`×36、`fields`×36、`frames`×9、`expect_error`×6、`error_contains`×6、`min_packets`×2、`packet_count`×1 |
| 负例 `expect` 键集合 | **6/6 = `{error_contains, expect_error, notes}`**（含 `notes`，非严格两键，G-SMTP-11） |
| `dst_port` 值分布 | 25×40 / 587×1 / 465×1 / 缺省×1（`t024`，实测补齐 25） |
| `src_port` | 42 例显式 12345；`t024` 保底 12345/12346（实测） |

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`/`tcp.srcport`/`tcp.flags`、`smtp.req.command`/`smtp.req.parameter`/`smtp.response.code`、`ipv6.version`、offset 54/190 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线（本机 3.6.14，机读实测）**：`tshark -G fields` 中 `smtp.*` **25 字段**。今日用例实际使用的字段通道：

| 字段 | 类型 | 断言条数 | 涉及用例数 |
|---|---|---:|---:|
| `smtp.req.command` | FT_STRING | 47 | 24 |
| `smtp.response.code` | FT_UINT32 | 39 | 24 |
| `tcp.dstport` | FT_UINT16 | 3 | 3 |
| `tcp.flags` | FT_UINT16 | 3 | 1 |
| `smtp.req.parameter` | FT_STRING | 3 | 1 |
| `tcp.srcport` | FT_UINT16 | 1 | 1 |
| `ipv6.version` | FT_UINT8 | 1 | 1 |
| **合计** | — | **97** | **36** |

（`smtp.req.parameter` 3 条全在 `smtp-basic-session`：帧 5 `client.example.org`、帧 7 `FROM:<alice@example.org>`、帧 9 `TO:<bob@example.com>`。）

**进制纪律（实测）**：`smtp.response.code` 用**十进制串**（`"220"`）；`tcp.flags` 用 `0x` 前缀十六进制且**按位比较**（见 §3 注）；`ipv6.version` 用 `"6"`。

**未被使用的可用字段（A′ 候选）**：`smtp.response`（整行文本）、`smtp.rsp.parameter`、`smtp.command_line`、`smtp.auth.username`/`smtp.auth.password`、`smtp.data.reassembled.length`（DATA 重组长度）、`smtp.data.fragment.count`（DATA 段数）、`smtp.eom`。其中 `smtp.data.reassembled.length` / `smtp.data.fragment.count` 是 **MIME 正文与 MSS 分段的直接可断言面**，今日零使用 → A′ G-SMTP-12。

**动态字段禁止硬编码**：生成期值（TCP ISN、IP ID）不作断言；用例只用固定锚点（`src_port=12345`、`dst_port=25`、banner 原文、命令字、应答码）。

**包数约定（设计 §9 公式，实测校准 37/37）**：单流帧数 = **8**（握手 3 + 挥手 4 + banner 1）+ **Σ_{dialog 元素} [Cmd 帧数 + Response 帧数]** + **[Email 非 nil ? 正文段数 + 1 : 0]**；每帧数 = `ceil((len(原文)+2)/MSS)`；`flows=N` 时 ×N。**今日仅 3/37 正例带包数断言**（G-SMTP-1）；负例无包数键（0 帧）。

**保活/重试/RST 口径**：SMTP 无协议级心跳，`NOOP` 是 RFC 5321 §4.1.1.9 定义的标准保活（`t006` 单次 / `t039` 三次）；重试无协议语义（生成器无时钟）；`t038` 模拟**应用层无 QUIT 断线**，TCP 仍走正常 FIN 四包（`terminates=true`）——**RST 异常终态本协议零用例**（G-SMTP-13）。

## 2. 原子用例索引（43 ID = 37 正 + 6 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count（实测 pcap） |
|---:|---|---|---|---:|
| 1 | `smtp-basic-session` | 正 | §3.1/§3.3：全缺省冒烟（banner 自动生成 + 默认 6 条会话） | 20 |
| 2 | `smtp_t002_top_smtp_presence_reject` | 负 | §7 N-1：顶层 smtp presence 判死 | —（0 帧，**无 pcap 留档**） |
| 3 | `smtp_t003_ehlo_multiline` | 正 | §3.1/§3.7：EHLO 多行能力表（含 SIZE） | 12 |
| 4 | `smtp_t004_multi_rcpt` | 正 | §4③：双 RCPT 群发 | 22 |
| 5 | `smtp_t005_rset` | 正 | §4④：RSET 重置重发 | 24 |
| 6 | `smtp_t006_noop` | 正 | §4⑤：NOOP 保活 | 14 |
| 7 | `smtp_t007_vrfy` | 正 | §4⑥：VRFY 地址探查 | 14 |
| 8 | `smtp_t008_expn` | 正 | §4⑥：EXPN 列表探查 | 14 |
| 9 | `smtp_t009_quit_after_data` | 正 | §3.5：DATA 后直接 QUIT | 18 |
| 10 | `smtp_t010_email_text` | 正 | §3.6：声明式 text-only（非 MIME） | 20 |
| 11 | `smtp_t011_email_alternative` | 正 | §3.6：multipart/alternative | 20 |
| 12 | `smtp_t012_email_attach` | 正 | §3.6/§6：mixed 单附件（4 段分段） | 23 |
| 13 | `smtp_t013_port_587` | 正 | §2：提交端口 587 | 20 |
| 14 | `smtp_t014_port_465` | 正 | §2：SMTPS 端口 465（明文链） | 20 |
| 15 | `smtp_t015_v6` | 正 | §2：IPv6 独立用例（offset 74） | 20 |
| 16 | `smtp_t016_postfix_banner` | 正 | §3.3/§4⑩：Postfix 形 banner | 12 |
| 17 | `smtp_t017_auth_login` | 正 | §3.7：AUTH LOGIN 三步台词 | 18 |
| 18 | `smtp_t018_starttls_script` | 正 | §3.7：STARTTLS 台词（tshark 伪影） | 14 |
| 19 | `smtp_t019_bad_srcip_reject` | 负 | §7 N-2：坏 IP | —（0 帧） |
| 20 | `smtp_t020_mss_reject` | 负 | §7 N-3：MSS 过小 | —（0 帧，**无 pcap 留档**） |
| 21 | `smtp_t021_boundary_reject` | 负 | §7 N-4：boundary 超 70 | —（0 帧） |
| 22 | `smtp_t022_attach_nodata_reject` | 负 | §7 N-5：附件无数据 | —（0 帧） |
| 23 | `smtp_t023_turn` | 正 | §3.4：TURN + 502 | 14 |
| 24 | `smtp_t024_default_twoflow` | 正 | §5/§12：全缺省双流（静态门反例） | 40 |
| 25 | `smtp_t024b_static_pinned_reject` | 负 | §7 N-6：显式标量 + flows=2 | —（0 帧，**无 pcap 留档**） |
| 26 | `smtp_t025_fail_530_auth` | 正 | §3.4：530 台词 | 14 |
| 27 | `smtp_t026_fail_550_mailbox` | 正 | §3.4：550 台词 | 16 |
| 28 | `smtp_t027_fail_554_toolarge` | 正 | §3.4：554 台词 | 18 |
| 29 | `smtp_t028_fail_452_storage` | 正 | §3.4：452 台词 | 16 |
| 30 | `smtp_t029_fail_421_unavail` | 正 | §3.4：421 台词 | 12 |
| 31 | `smtp_t030_fail_503_sequence` | 正 | §3.4：503 台词 | 14 |
| 32 | `smtp_t031_fail_535_authfail` | 正 | §3.4/§3.7：535 台词 | 18 |
| 33 | `smtp_t032_email_html_only` | 正 | §3.6：html-only 单体 | 20 |
| 34 | `smtp_t033_email_mixed_multi` | 正 | §3.6/§6：双附件 mixed（4 段分段） | 23 |
| 35 | `smtp_t034_email_empty_body` | 正 | §3.6：空正文格 | 20 |
| 36 | `smtp_t035_email_attach_only` | 正 | §3.6：纯附件无首体块 | 20 |
| 37 | `smtp_t036_direction_override` | 正 | §3.5：direction 下行改写 | 13 |
| 38 | `smtp_t037_two_mails` | 正 | §5：同连接两封信 | 28 |
| 39 | `smtp_t038_abort_no_quit` | 正 | §4⑮：异常断线（无 QUIT） | 18 |
| 40 | `smtp_t039_keepalive_multi_noop` | 正 | §4⑤/§3.15③：三 NOOP 长保活 | 18 |
| 41 | `smtp_t040_composite_auth_rset_twomail` | 正 | §5：复合流（AUTH+RSET+两封信） | 36 |
| 42 | `smtp_t041_gmail_banner` | 正 | §3.3/§4⑩：Gmail 形 banner | 12 |
| 43 | `smtp_t042_exchange_banner` | 正 | §3.3/§4⑩：Exchange 形 banner | 12 |

**JSON 顺序即上表顺序**（权威）；**本表 `packet_count` 列 = 实测 pcap 帧数**，与设计 §9 逐格一致（机读对账）。

**JSON 实际断言的包数键（只有 3 例，机读实测）**：#1 `min_packets=16`（实测 20）、#4 `min_packets=18`（实测 22）、#24 `packet_count=40`（精确）。**其余 34 例 JSON 无任何包数键**——上表第三列的值来自 pcap 实测，**不是 JSON 里的断言**（G-SMTP-1）。

## 3. 正例逐项断言契约（现状 as-built：最低断言集，实现期可增不可减）

每例均含 `terminates` + `negotiated` + `has_handshake` + `has_payload`（37 正例中 36 例齐四键；#24 只有 `has_handshake`+`packet_count`，机读实测）。以下列各例的**特有断言**。

### 3.1 `smtp-basic-session`（20 帧，19 field + 6 frame）

全缺省层链 + 显式四元组；`smtp: {}`（无 banner/dialog/email）。

- fields（19 条）：帧 1 `tcp.flags=0x002`、`tcp.dstport=25`；帧 2 `tcp.flags=0x012`；帧 3 `tcp.flags=0x010`；帧 4 `smtp.response.code=220`；帧 5 `smtp.req.command=HELO` + `smtp.req.parameter=client.example.org`；帧 6 `250`；帧 7 `MAIL` + `FROM:<alice@example.org>`；帧 8 `250`；帧 9 `RCPT` + `TO:<bob@example.com>`；帧 10 `250`；帧 11 `DATA`；帧 12 `354`；帧 14 `250`；帧 15 `QUIT`；帧 16 `221`。
- frames（6 条，**逐条对 pcap 命中**）：帧 4 offset 54 `32 32 30 20 32 30 2e 30 2e 30 2e 31 20 45 53 4d 54 50 20 74 72 61 66 66 69 63`（= `"220 20.0.0.1 ESMTP trafficgen"`，**banner 自动生成，DstIP 取自 spec**）；帧 5 offset 54 `48 45 4c 4f 20 63 6c 69 65 6e`（`"HELO clien"`）；帧 13 offset 54 `46 72 6f 6d 3a 20 61 6c 69 63`（`"From: alic"`）；帧 13 offset 54 `46 72 6f 6d 3a 20 61 6c 69 63 65 40 65 78 61 6d 70 6c 65 2e 6f 72 67`（`"From: alice@example.org"`，**同帧两条断言，前缀 + 全长**）；帧 15 offset 54 `51 55 49 54 0d 0a`（`"QUIT\r\n"`，**CRLF 追加的直接证据**）；帧 16 offset 54 `32 32 31 20 32 2e 30 2e 30 20 42 79 65 0d 0a`（`"221 2.0.0 Bye\r\n"`）。
- **包数证据**：默认会话 6 条 dialog → 12 帧命令/应答 + banner 1 + 握手 3 + 挥手 4 = 20 ✓。**JSON 断 `min_packets=16`（下限，非精确）**——实际 20 帧，`min_packets` 不能捕获帧数漂移（G-SMTP-1）。

### 3.2 `smtp_t003_ehlo_multiline`（12 帧，3 field）

`smtp.dialog` 2 条：`EHLO client.example.org` / `250-mail.example.org\r\n250-SIZE 10240000\r\n250 HELP`，加 `QUIT`/`221 2.0.0 Bye`。

- fields：帧 4 `smtp.response.code=220`；帧 5 `smtp.req.command=EHLO`；帧 7 `smtp.req.command=QUIT`。
- **多行应答证据（实测 `tshark -V`）**：帧 6 单帧解出 `250-mail.example.org` / `250-SIZE 10240000` / `250 HELP` **三行**（`250-` 续行 + `250 ` 末行）——**内嵌 `\r\n` 由用户原文提供，planner 只追加末尾一个 `\r\n`**（设计 §3.1）。
- **SIZE 是唯一落点**（RFC 1870）：全仓 43 例中 `SIZE` 只在此例出现（机读实测）→ 8BITMIME 零用例（G-SMTP-3）。
- 包数：8 + 2×2 = 12 ✓（实测）。

### 3.3 `smtp_t004_multi_rcpt`（22 帧，3 field）

7 条 dialog：HELO + MAIL + **RCPT×2** + DATA + 正文 Cmd + QUIT。

- fields：帧 9 `smtp.req.command=RCPT`；帧 11 `smtp.req.command=RCPT`；帧 13 `smtp.req.command=DATA`。
- **群发证据**：两轮 RCPT 各一帧（帧 9/11），中间夹应答帧（帧 10 250）；正文 Cmd 结尾 `\r\n.`（手写路径，设计 §3.2）。
- 包数：8 + 7×2 = 22 ✓。**JSON 断 `min_packets=18`（下限）**。

### 3.4 `smtp_t005_rset`（24 帧，3 field）

8 条 dialog：HELO + MAIL + RSET + MAIL + RCPT + DATA + 正文 + QUIT。

- fields：帧 5 `HELO`；帧 9 `RSET`；帧 11 `MAIL`（**RSET 后的第二次 MAIL，证明回放按序推进**）。
- 包数：8 + 8×2 = 24 ✓。

### 3.5 `smtp_t006_noop` / `smtp_t007_vrfy` / `smtp_t008_expn`（各 14 帧，各 3 field）

- `t006`：HELO + NOOP + QUIT → fields 帧 5 `HELO` / 帧 7 `NOOP` / 帧 9 `QUIT`。包数 8+3×2=14 ✓。
- `t007`：HELO + `VRFY alice` + QUIT；应答 `250 2.1.5 Alice Smith <alice@example.org>` → fields 帧 5/7/9。
- `t008`：HELO + `EXPN friends` + QUIT；应答 `250-John <j@example.org>\r\n250 Jane <jane@example.org>`（**第二处多行应答**）→ fields 帧 5/7/9。
- **诚实声明**：`t008` notes 明写"全仓零用例，复审 R4；回放台词，不断言状态机"——EXPN 是可选命令（RFC 5321 §4.1.1.7），本实现只回放。

### 3.6 `smtp_t009_quit_after_data`（18 帧，3 field）

5 条 dialog：HELO + MAIL + RCPT + DATA + QUIT（**DATA 后直接 QUIT，无正文 Cmd**）。

- fields：帧 11 `DATA`；帧 12 `smtp.response.code=354`；帧 14 `221`。
- **断言边界（notes 已载，必读）**：帧 13 是 QUIT 命令帧，tshark 把它与帧 14 的 221 视作**同段重组**（帧 13 单独看 `smtp.req.command` 为空，`_ws.col.Protocol` 仍 SMTP）——故**不断 QUIT 字面**，只断 `221` 存在 + 包数隐含其已发出（设计 §9 断言边界注记）。
- 包数：8 + 5×2 = 18 ✓。

### 3.7 声明式邮件五例（`t010`/`t011`/`t012`/`t032`/`t033`/`t034`/`t035` 中的断言形态）

九例均为"显式 5 条 dialog（HELO/MAIL/RCPT/DATA/QUIT）+ `email`"；正文在 DATA 的 354 之后注入，其后自动 250。

| 例 | email 形态 | field 断言 | frame 断言 |
|---|---|---|---|
| `t010` | text-only（非 MIME） | 帧 12 `354`、帧 14 `250` | 帧 13 offset 54 `46 72 6f 6d 3a 20 61 6c 69 63`（`"From: alic"`） |
| `t011` | multipart/alternative | 帧 12 `354`、帧 14 `250` | 帧 13 offset 54 `46 72 6f 6d 3a 20 61 40 62 2e`（`"From: a@b."`） |
| `t012` | mixed 单附件（README.md，`data_b64`） | 帧 12 `354`、**帧 17** `250` | 帧 13 offset 54 `46 72 6f 6d 3a 20 61 40 62 2e` |
| `t032` | html-only 单体 | 帧 12 `354`、帧 14 `250` | 帧 13 offset 54 `46 72 6f 6d 3a 20 61 40 62 2e` |
| `t033` | mixed 双附件 | 帧 12 `354`、**帧 17** `250` | 帧 13 offset 54 `46 72 6f 6d 3a 20 61 40 62 2e`；**同帧 offset 190** `43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 74 65 78 74 2f 70 6c 61 69 6e`（`"Content-Type: text/plain"`，**正文内偏移**） |
| `t034` | 空正文（仅头） | 帧 12 `354`、帧 14 `250` | 帧 13 offset 54 `46 72 6f 6d 3a 20 61 40 62 2e` |
| `t035` | 纯附件（无首体块） | 帧 12 `354`、帧 14 `250` | 帧 13 offset 190 `43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6f 63 74 65 74 2d 73 74 72 65 61 6d`（`"Content-Type: application/octet-stream"`） |

- **分段证据（实测 `tcp.len`）**：`t012` 帧 13/14/15/16 = **1460/1460/1460/1167**（正文 5483 字节 → 4 段）；`t033` = **1460/1460/1460/1316**（5339 字节 → 4 段）；`t035` 单段 300 字节。段数 = `ceil(正文长/1460)`（设计 §6）。
- **包数证据**：`t012`/`t033` = 8 + 5×2 + 4 + 1 = 23 ✓（**帧 17 的 250 是第 4 段之后的自动应答**）；其余五例 = 8 + 10 + 1 + 1 = 20 ✓。
- **附件真实性（`t012`/`t033` 的 `data_b64` 是仓库真实 `README.md` 3783 字节，`84cfbe6` 已换真数据清零假数据）**。
- **今日断言边界（G-SMTP-12）**：只用 frame 前缀 + 354/250 帧位；**不断 MIME 结构字符串**（如 `Content-Type: multipart/mixed` 完整行、boundary 值、base64 折行）——tshark 的 `smtp.data.reassembled.length` / `smtp.data.fragment.count` 可用但零使用。

### 3.8 `smtp_t013_port_587` / `smtp_t014_port_465`（各 20 帧，各 1 field）

- `t013`：帧 1 `tcp.dstport=587`；`t014`：帧 1 `tcp.dstport=465`。**两例层链均为 `[ip,tcp,smtp]`（明文），无 tls 层**——`t014` notes 明写"只断端口不断言 TLS 握手，真握手另立项"（G-SMTP-2）。
- 包数各 20（默认会话）✓。

### 3.9 `smtp_t015_v6`（20 帧，2 field）

`layers[0].ip = {src:"2001:db8::1", dst:"2001:db8::2"}`。

- fields：帧 4 `ipv6.version=6`；帧 4 `smtp.response.code=220`。
- **协议与地址族解耦证据**：banner 与默认会话字节不变，只有载荷起点从 offset 54 变 **74**（14+40+20）。notes 明写"ipv6.version=6 有回值（落盘实测），不断言降级"。
- 包数 20 ✓（与 IPv4 版同）。

### 3.10 现网 banner 三例（`t016`/`t041`/`t042`，各 12 帧）

| 例 | banner 原文 | dialog | field 断言 |
|---|---|---|---|
| `t016` | `220 mx.example.org ESMTP Postfix` | HELO x / QUIT | 帧 4 `smtp.response.code=220` |
| `t041` | `220 smtp.gmail.com ESMTP - gsmtp` | EHLO x（能力表含 `250-STARTTLS`）+ QUIT | 帧 4 `220`、帧 5 `EHLO` |
| `t042` | `220 EXCH01.example.org Microsoft ESMTP MAIL Service ready` | EHLO x（能力表含 `250-AUTH LOGIN`）+ QUIT | 帧 4 `220`、帧 5 `EHLO` |

- **banner 逐字钉**：三例的 banner 原文写在 spec 里，帧 4 的 `220` 是直接证据；**banner 全文的 frame 断言今日零**（A′ 候选）。
- 包数各 12（8 + 2×2）✓。
- **诚实声明**：`t041` notes 明写"问候原文对照现网 587 口径；STARTTLS 真升级另立项"；`t042` 明写"真服务器对接另立项"（G-SMTP-8）。

### 3.11 `smtp_t017_auth_login`（18 帧，3 field）

5 条 dialog：`EHLO x`（`250-mail.example.org\r\n250-AUTH LOGIN PLAIN\r\n250 HELP`）+ `AUTH LOGIN` / `334 VXNlcm5hbWU6` + base64 用户名 / `334 UGFzc3dvcmQ6` + base64 密码 / `235` + QUIT。

- fields：帧 5 `EHLO`；帧 7 `AUTH`；帧 13 `QUIT`。
- **AUTH 三步证据**：帧 7 命令 `AUTH`，帧 8 `334`，帧 9/10/11/12 是 base64 凭据与 334/235 交替——**`smtp.req.command` 对 base64 行返回空**（`YWxpY2U=` 首 token 非纯字母），故**不断凭据帧**（G-SMTP-12）。
- 包数：8 + 5×2 = 18 ✓。

### 3.12 `smtp_t018_starttls_script`（14 帧，2 field）

3 条 dialog：`EHLO x`（`250-STARTTLS`）+ `STARTTLS` / `220 2.0.0 Ready to start TLS` + QUIT。

- fields：帧 5 `EHLO`；**帧 8** `smtp.response.code=220`（STARTTLS 就绪应答）。
- **tshark 伪影（实测，notes 已载）**：帧 7 的 `smtp.req.command` 被解成 **`STAR`**（截断）且 `_ws.col.Protocol` 变 **`TLS`**——dissector 见 `STARTTLS` 字样即把后续按 TLS 解。**故不断该包原文**，只断包序 + 帧 8 的 220。
- 包数：8 + 3×2 = 14 ✓。

### 3.13 失败码七例（`t025`–`t031`，各 2 field）

**全部是台词版**——响应码写在 `response` 原文里，生成器照发，**不校验引擎是否拦截**（`coverage_gate.py:14-16` 同口径）。

| 例 | 命令 + 失败应答 | field 断言 | 帧数 |
|---|---|---|---|
| `t025_fail_530_auth` | `MAIL FROM` → `530 5.7.0 Authentication required` | 帧 7 `MAIL`、帧 8 `530` | 14 |
| `t026_fail_550_mailbox` | `RCPT TO:<nobody@…>` → `550 5.1.1 …` | 帧 9 `RCPT`、帧 10 `550` | 16 |
| `t027_fail_554_toolarge` | `DATA` → `554 5.3.4 …` | 帧 11 `DATA`、帧 12 `554` | 18 |
| `t028_fail_452_storage` | `RCPT TO` → `452 4.3.1 Insufficient…` | 帧 9 `RCPT`、帧 10 `452` | 16 |
| `t029_fail_421_unavail` | `EHLO x` → `421 4.3.2 Service not available…` | 帧 5 `EHLO`、帧 6 `421` | 12 |
| `t030_fail_503_sequence` | `RCPT TO` → `503 5.5.1 …`（先 RCPT 后 MAIL） | 帧 7 `RCPT`、帧 8 `503` | 14 |
| `t031_fail_535_authfail` | `AUTH LOGIN` → … → `535 5.7.8 …` | 帧 7 `AUTH`、帧 12 `535` | 18 |

- **每例 notes 均明写"回放不断言拦截/状态机"**（如 `t030` "先 RCPT 后 MAIL；回放不断言状态机"）——**本协议层不实现 SMTP 状态机**（设计 §5）。
- **包数公式校验**：`t029` = 8 + 2×2 = 12 ✓；`t030` = 8 + 3×2 = 14 ✓；`t026`/`t028` = 8 + 4×2 = 16 ✓；`t025` = 8 + 3×2 = 14 ✓；`t027` = 8 + 5×2 = 18 ✓；`t031` = 8 + 5×2 = 18 ✓。

### 3.14 `smtp_t023_turn`（14 帧，3 field）

HELO + `TURN` / `502 Command not implemented` + QUIT。

- fields：帧 5 `HELO`、帧 7 `TURN`、帧 9 `QUIT`。
- **502 是 TURN 的标准应答**（RFC 5321 §4.1.1.10 已废弃 TURN，服务器回 502）——**全仓唯一 502 落点**（机读实测）。
- notes 明写"全仓零用例，复审 R4；回放不断言状态机"。

### 3.15 `smtp_t024_default_twoflow`（40 帧，`packet_count=40` + `has_handshake`）

**全缺省层链** `[{ip:{}},{tcp:{}},{smtp:{}}]` + **用例级** `strategy_fc {"type":"flows","value":2}`。

- **唯一带精确 `packet_count` 的正例**：40 = 2 × 20（单流默认会话）✓（实测）。
- **静态复制门反例**（设计 §12.12）：全缺省**无显式标量四元组** → 门不触发（`checkLayerChainStaticCopy` 只查显式标量面）；`src_port` 走保底递增防撞（实测 SYN 帧 1 src=12345、帧 5 src=12346）；`dst_port` 走 FieldContract 补齐 25（实测）。
- notes 明写"§9 陷阱③反例——门只拦显式标量"。

### 3.16 `smtp_t036_direction_override`（13 帧，1 field）

3 条 dialog：HELO/250 + `{"cmd":"NOOP","response":"","direction":"down"}` + QUIT/221。

- fields：**帧 7 `tcp.srcport=25`**（NOOP 走**下行**，源端口是服务端 25）。
- frames：帧 7 offset 54 `4e 4f 4f 50`（`"NOOP"`）。
- **断言边界（notes 已载）**：tshark **不把下行帧解成 `smtp.req.command`**（该字段语义是"请求"），故只断 `tcp.srcport` + frame 原文，**不断 `smtp.req.command`**。
- 包数：8 + 3×2 = 14？**实测 13**——因为第 2 条 dialog 的 `response` 为空（**纯客户端轮次，跳过应答帧**），故 = 8 + (1+1) + (1+0) + (1+1) = 13 ✓。**这是"空 response 跳过"的直接证据**。

### 3.17 `smtp_t037_two_mails`（28 帧，3 field）

10 条 dialog = **两封完整信**（MAIL/RCPT/DATA/正文/250 各两轮）+ HELO + QUIT。

- fields：帧 11 `DATA`、帧 19 `DATA`、帧 20 `354`（**第二封信的 DATA 与其应答**）。
- **多事务证据**：同连接两次 DATA（设计 §5；§3 口径"无多会话 ≠ 无多事务"）。
- 包数：8 + 10×2 = 28 ✓。

### 3.18 `smtp_t038_abort_no_quit`（18 帧，3 field）

5 条 dialog：HELO/MAIL/RCPT/DATA/正文+250，**无 QUIT**。

- fields：帧 11 `DATA`、帧 12 `354`、帧 14 `250`。
- **异常断线证据**：SMTP 层无 QUIT（模拟掉线），但 **`terminates=true` 仍成立**——TCP 层照常走 FIN 四包（`pcaptest.VerifyPcap` 的 `terminates` 判定看最后 3 包的 FIN/RST 位）。**这是"应用层异常 ≠ 传输层异常"的直接证据**。
- 包数：8 + 5×2 = 18 ✓（与有 QUIT 的 `t009` 同为 18，差别在帧 15-18 是 FIN 四包而非 QUIT/221+FIN）。

### 3.19 `smtp_t039_keepalive_multi_noop`（18 帧，2 field）

5 条 dialog：HELO + **NOOP×3** + QUIT。

- fields：帧 7 `NOOP`、帧 11 `NOOP`（**第 1 与第 3 个 NOOP**）。
- **长保活证据**（§3.15③）：同连接 3×NOOP（RFC 5321 §4.1.1.9）。
- 包数：8 + 5×2 = 18 ✓。

### 3.20 `smtp_t040_composite_auth_rset_twomail`（36 帧，3 field）

14 条 dialog = EHLO（能力表）+ AUTH 三步 + **第一封信**（MAIL/RCPT/DATA/正文/250）+ RSET + **第二封信** + QUIT。

- fields：帧 7 `AUTH`、帧 17 `DATA`、帧 27 `DATA`。
- **复合流证据**（§3.15① + `coverage_gate.py` 的 composite 定义）：一条流内多动作（认证 + 两封信 + 重置）。
- 包数：8 + 14×2 = 36 ✓。**全 43 例最大单流帧数**。

**正例总则**：多行应答、多 RCPT、多事务、声明式 MIME、端口变体、IPv6、现网 banner、多流均为正例形态；**只有配置/长度/关联错误进入负例**（失败码台词例仍是正例，因为它们产流成功）。

## 4. 负例契约

负例必须在**相应门**失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。锚词与设计 §7 表一一对应、同序：

| ID | 故障输入（机读实测） | JSON `error_contains` | 归属门 + 代码文案 | 代码位置 |
|---|---|---|---|---|
| `smtp_t002_top_smtp_presence_reject` | 层链 + 顶层 `smtp:{}` | `rejects a top-level smtp sub-config` | 框架 `CheckProtoFlat`：`protocol smtp rejects a top-level smtp sub-config (move it into the smtp layer of an [ip,tcp,smtp] layers chain)` | `strategy_convert.go:8830-8833` |
| `smtp_t019_bad_srcip_reject` | `ip.dst = "not-an-ip"` | `invalid IP address: not-an-ip` | 框架 ip 层：`invalid IP address: %s` | `convert.go:55` |
| `smtp_t020_mss_reject` | `tcp.mss = 100` | `out of range [536,65535]` | 框架 tcp 层 V9 范围门：`layers: layer %q field %q = %v invalid: out of range [%d,%d]` | `layers/complete.go:325` |
| `smtp_t021_boundary_reject` | multipart + `boundary` 71 字符 | `Boundary` | **smtp planner**：`smtp: Email.Boundary length %d exceeds max 70 chars (RFC 2046 §5.1.1 boundary)` | `mime.go:344` |
| `smtp_t022_attach_nodata_reject` | 附件仅 `{filename:"a.bin"}` | `neither Data nor DataB64` | **smtp planner**：`smtp: Email.Attachments[%d] has neither Data nor DataB64 (RFC 2045 §6.8)` | `mime.go:353` |
| `smtp_t024b_static_pinned_reject` | 显式标量四元组 + `flows=2` | `static` | 框架 schema 语义门：`layers pin a static four-tuple but flows > 1: every flow would emit identical addresses/ports (static copy)…` | `schema/semantic.go:285` |

**锚词口径**：`error_contains` 是**子串**判定；6 例均命中（`Boundary` 命中前缀 `smtp: Email.Boundary length`；`static` 命中 `static four-tuple`）。

**负例原子性**：每例单一故障注入；单次执行不得混注。

**C 类边界（必须写清，不得夸大）**：**6 条负例中只有 2 条走 smtp 自己的 validator**（`t021`/`t022` → `Planner.Validate` → `validateSMTPEmail`）。另 4 条走**框架门**：`t002` = `CheckProtoFlat` presence 分支；`t019` = ip 层；`t020` = tcp 层 V9 范围门；`t024b` = schema 静态复制门。存量 notes 已逐例标注（`t019`/`t020` 明写"legacy planner 门由扁平路径覆盖，C 类注记"）。**本契约不声称这 4 条证明了 smtp validator 的能力**。

**expect 键形状注**：存量 6 负例 `expect` = `{expect_error, error_contains, notes}`（**含 `notes`**），与严格两键口径不同 → P4 收窄时删 `notes`（G-SMTP-11）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：`smtp: invalid SrcIP %q (not a valid IP address)`（`planner.go:87`）；`smtp: invalid DstIP %q (not a valid IP address)`（`:92`）；`smtp: TCP.MSS %d too small (min %d per RFC 879)`（`:99`）；`smtp: Email.Boundary %q contains CRLF (RFC 2046 §5.1.1 boundary + injection protection)`（`mime.go:347`）。

**未入用例的静默路径（缺陷候选）**：`direction` 非法值（如 `"sideways"`）——`planner.go:290`/`:305` 按 `== "down"` / `== "up"` 判定，**其余值静默当缺省方向**，无枚举校验、无告警 → G-SMTP-6 裁定"拒绝"或"登记为静默合法"。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 族（设计 §10）+ as-built 落码（设计 §11）+ tshark 3.6.14 `smtp.*` 字段表与 **40 例实测 pcap**（`/tmp/mcp-pcaps/smtp/`，37 正 + 3 负）→ 43 ID（本契约 §2）。第三源"已确认现网行为"当前 = **banner 原文级已到**（Postfix/Gmail/Exchange 三例 `t016`/`t041`/`t042`），但**真实 MTA 的完整会话线字节未取到** → G-SMTP-8（按设计 §5.5 不写死进实现）。

**43 ID 逐项回指（设计 §9 全表）**：#1←§3.1/§3.3；#2←§7 N-1；#3←§3.1/§3.7；#4←§4③；#5←§4④；#6←§4⑤；#7←§4⑥；#8←§4⑥；#9←§3.5；#10←§3.6；#11←§3.6；#12←§3.6/§6；#13←§2；#14←§2；#15←§2；#16←§3.3；#17←§3.7；#18←§3.7；#19←§7 N-2；#20←§7 N-3；#21←§7 N-4；#22←§7 N-5；#23←§3.4；#24←§5/§12；#25←§7 N-6；#26–#32←§3.4；#33–#36←§3.6；#37←§3.5；#38←§5；#39←§4⑮；#40←§4⑤；#41←§5；#42/#43←§3.3。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 5321/5322/2045/2046/2183/4954/3207/1870/6152/879 公开语义 + tshark 3.6.14 `smtp.*` 25 字段实测 + **40 例 pcap 实测**（37 正 + 3 负）+ 仓库落码反推**，**非纯规范反推**（真实 MTA 完整会话线字节未取 → G-SMTP-8）。
- **对账两行**：**要求逻辑点总数 = 98**（八项 8 + 矩阵 39 格 + 变体 30 行 + 商业映射 21 行）；**用例覆盖 50 / 开放立项 27 / 显式不适用 21**，逐表如下：

| 表 | 总格/行 | 已覆 | 立项 | 不适用 |
|---|---:|---:|---:|---:|
| §10.1 八项矩阵 | 8 | 1 | 4 | 3 |
| §10.2 命令×终态矩阵 | 39 | 13 | 12 | 14 |
| §10.3 数据形态变体表 | 30 | 19 | 11 | 0 |
| §10.4 商业行为映射表 | 21 | 17 | 0 | 4 |
| **合计** | **98** | **50** | **27** | **21** |

  50 + 27 + 21 = 98 ✓（逐表重数见设计 §10.1/§10.2/§10.3/§10.4）。
  **粒度声明**：行/格粒度每点 1 计；G-SMTP-1…G-SMTP-13 与 §7 的 6 条负例不折进 98。**反查全绿 ≠ 覆盖全**。
  **§10.2 的 T2 列 13 格全判"不适用"**是本协议的结构性事实（planner 无命令字校验，不存在按命令分的配置拒绝路径），已在设计 §10.2 注明——**不是回避**。
- **门3 抽查候选**：最复杂用例 = **#41 `smtp_t040_composite_auth_rset_twomail`**（36 帧：握手 3 + banner 1 + 14 条 dialog 的 28 帧 + 挥手 4；交织维度 = 命令(8 种)×方向(2)×应答码(6 种)）；**建议门3 抽 #41 + #12**（`smtp_t012_email_attach` 补 MIME 分段面）。

### 5.3 与 `coverage_gate.py` 的关系（实测）

`python3 trafficgen/tools/coverage_gate.py smtp` 实测 **35/35 通过（绿）**，出口 0。检查表四组：

| 组 | 项数 | 内容 |
|---|---:|---|
| 1. 命令 | 12 | HELO/EHLO/MAIL/RCPT/DATA/RSET/NOOP/VRFY/EXPN/TURN/AUTH/QUIT 各有落点 |
| 2. 失败码 | 7 | 530/550/554/452/421/503/535（**台词版也算**） |
| 3. Email 八格 | 8 | text-only/html-only/alternative/mixed-single/mixed-multi/custom-boundary/empty-body/attach-only |
| 4. 多事务/保活/断线/复合/商业 | 8 | direction 在用 / 多事务 / 异常断线 / 长保活 / 复合流 / postfix / gmail / exchange |

**该门是地板线**：只查"有没有例"，不查"测真了"（`coverage_gate.py:12-14` 明写）。**反查 35/35 绿不掩盖 G-SMTP-1（包数断言 3/37）与 G-SMTP-12（MIME 结构零断言）**。

## 6. 覆盖固定动作（CORE_MEMORY §3.15 三项 + A′/B′ 两分类 + §3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接多轮命令（`t004` 双 RCPT、`t037` 两封信、`t040` 认证+两封信+RSET、`t039` 三 NOOP） | 已覆 `t004`/`t037`/`t040`/`t039` |
| ② | 非正常结束 | 正常 FIN 全正例 + QUIT/221；应用层异常 = `t038`（无 QUIT 但 TCP 仍 FIN）；**传输异常 RST 零用例** | 已覆（`t038` 应用层异常）；**RST A′ 立项**（G-SMTP-13） |
| ③ | 长保活 | SMTP 无协议级心跳；NOOP 是 RFC 5321 §4.1.1.9 定义的标准保活 | 已覆 `t039`（三 NOOP）/ `t006`（单 NOOP） |

无空项：① 有 4 例；② 有 1 例 + 1 条 A′ 立项；③ 有 2 例。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 包数面 | 34 个正例补 `packet_count`（公式已实测校准 37/37） | G-SMTP-1 |
| TLS 底座 | `[ip,tcp,tls,smtp]` 组合例（registry 已声明 `OptionalOn ["tls"]`，零用例） | G-SMTP-2 |
| 扩展面 | 8BITMIME 能力表 + `SIZE=` / `BODY=8BITMIME` 参数形态 | G-SMTP-3 |
| email 分支面 | `dialog` 缺省+`email`、`cmd` 空、`direction="up"` 的 Response、mixed 内嵌 alternative、合法自定义 `boundary`、附件 `data`（原始字节）、自动 dot-stuffing | G-SMTP-4 |
| 端口面 | 只缺 `dst_port`（保留其它标量）的缺省正例；异族混写拒绝 | G-SMTP-5 |
| 拒绝分支面 | `invalid SrcIP`/`invalid DstIP`/`MSS too small`/`Boundary contains CRLF`（validator 自身分支）；`direction` 非法值裁定 | G-SMTP-6 |
| 负例留档 | 3 例负例补 pcap 留档（`t002`/`t020`/`t024b` 无文件） | G-SMTP-7 |
| 字段面 | 收编 `smtp.data.reassembled.length` / `smtp.data.fragment.count`（MIME 分段直证）/ `smtp.response` 整行 / `smtp.rsp.parameter` / `smtp.auth.*` | G-SMTP-12 |
| 非正常结束 | `tcp.rst` 补例 | G-SMTP-13 |

**B′（框架面）**：顶层未知键通用门缺失（G-SMTP-9，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态全关（allowlist 无 `smtp` 行，`layer_dyn.go`）/ 负例 `notes` 键收窄（G-SMTP-11）。进设计 §14，「明确不解决 + 迁入计划」。

### 6.3 §3.14 豁免边界审计

**有长连接载体（TCP）→ `sessions[]` 不豁免**（设计 §12.3 会话表 s1）。**但 SMTP 无多会话结构**——`sessions[]` 在 SMTP 无对应物（单连接协议，一封或多封信在同一条连接内），**多会话豁免理由**：协议本身只有一条连接；多流并发由**用例级 `strategy_fc {"type":"flows","value":N}`** 承载（`t024`/`t024b`，实测两流 src_port 12345/12346）；**单包多载荷** = **不适用**（SMTP 每帧一条命令或一条应答或一段正文，无多 question/多 RR 类形态，如实声明）。

**多流 case 要求（§7 多会话 case 要求）**：`t024` 不能只证明"包数翻倍"——它同时证明了两流 `src_port` 保底递增防撞（12345/12346，实测 SYN 帧）+ 全缺省不触发静态门；`t024b` 证明显式标量 + `flows=2` **被拒**（锚词 `static`）。**两例成对，构成静态复制门的放行/拒绝对照**。

## 7. 实现后执行建议

1. **P4 顺序**：①先补包数断言（G-SMTP-1，34 例，公式已校准）；②补 A′ 拒绝分支例（G-SMTP-6）与 email 分支例（G-SMTP-4）；③收编字段断言（G-SMTP-12，`smtp.data.reassembled.length` 直证 MIME 分段）；④负例补 pcap 留档 + 删 `notes` 键（G-SMTP-7/G-SMTP-11）；⑤TLS 底座与扩展面（G-SMTP-2/G-SMTP-3）；⑥全量复跑。**本协议无 §1 迁移步骤**（42/43 顶层零残留，唯一例外是判死负例）。
2. **实测顺序**：先 #1（banner 自动生成 + CRLF 基线），再 #3（多行应答三行），再 #9（空 response 跳过 / QUIT 重组边界），再 #12/#34（MIME 分段 4 段 + 1514 满帧），最后 #15（IPv6 offset 74）、#24（双流保底 +1）、#41（36 帧复合流）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=smtp` 全量不是增量）；门2④ 反查绿后进 P6。
4. 任何 RFC 条款号的具体引用须有规范原文证据（G-SMTP-8 纪律）。

## 8. 存量审计（43 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/smtp.json` **43 例**（37 正 + 6 负）；**14 条 frame 断言逐条对实测 pcap 命中（14/14，机读）**；**97 条 field 断言全绿**（94 条字符串相等 + 3 条 `tcp.flags` 按位比较，见 §3.1 注）；**37 个正例包数公式与 pcap 逐例一致（37/37，机读）**；6 负例实测 **0 帧**（3 例有 `.neg.pcap` 且 0 帧；**另 3 例 `t002`/`t020`/`t024b` 无任何 pcap 留档**）；**42/43 顶层键仅 `{layers}`**（唯一例外 `t002` 是判死负例）；层链 `[ip,tcp,smtp]` ×43；`coverage_gate.py smtp` **35/35 绿**。

**结果文档（`trafficgen/docs/protocol-pcap-test/smtp.md`）**：写 `Cases: 43 — pass 43, fail 0, error 0`（该行由 `b8177fc` 2026-09-17 写入）；`docs/protocol-pcap-test/smtp/` **目录不存在**（`.gitignore:88` 的 `*.pcap` 排除，故永无 tracked pcap）；`/tmp/mcp-pcaps/smtp/` 40 个 pcap 的 mtime 为 **2026-09-27**（历史留档，非今日产出）。→ G-SMTP-10。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **包数断言覆盖率仅 3/37**：`packet_count`×1 + `min_packets`×2；其余 34 例零包数键。§9 公式今日无机器执法（G-SMTP-1）。
2. **`min_packets` 是下限而非精确值**：`smtp-basic-session` 写 16 而实际 20 帧——**帧数漂移 4 帧不会被发现**（G-SMTP-1）。
3. **`tcp.flags` 断言文本长度不统一**：JSON 写 `0x002`/`0x012`/`0x010`，tshark 输出 `0x0002`/`0x0012`/`0x0010`——**判绿靠按位比较**（`pcaptest/verify.go:114-122`），非字符串相等。**不是缺陷，但读者易误判**（设计 §15 注）。
4. **3 例负例无 pcap 留档**：`t002`/`t020`/`t024b` 在 `/tmp/mcp-pcaps/smtp/` **无任何文件**（机读实测：目录共 40 个 pcap = 37 正 + 3 负）；另 3 例有 `.neg.pcap`（0 帧）。**无留档 = 无当日复跑证据**（G-SMTP-7）。
5. **MIME 结构零字段断言**：9 个 email 例只用 frame 前缀 + 354/250 帧位；**boundary 值、`Content-Type: multipart/*` 完整行、base64 折行、附件字节**均无直接断言（G-SMTP-12）。`t012`/`t033` 的附件真实性靠**生成时人工核对**（`84cfbe6` 提交信息"落盘解码与原文逐字节一致"），**无自动化断言**。
6. **`t009`/`t018`/`t036` 各有一条"不断言"边界**（notes 已载）：`t009` 不断 QUIT 字面（tshark 重组）；`t018` 不断 STARTTLS 字面（tshark 截断成 `STAR` 且协议变 TLS）；`t036` 不断下行帧的 `smtp.req.command`（字段语义为"请求"）。**三处均为 dissector 行为限制，非用例缺陷**，但需读者知晓。
7. **失败码七例是台词版**：`t025`–`t031` 只证明"这句台词发得出去"，**不证明引擎拦截**（`coverage_gate.py:14-16` 同口径）。
8. **`t002` 的顶层 `smtp:{}` 是判死形状**：不是旧键残留；P4 不得删（删了该例即失效）。
9. **`direction` 非法值静默当缺省**：`planner.go:290`/`:305` 无枚举校验（G-SMTP-6）。
10. **结果文档 43/43 是历史产物**（G-SMTP-10）：末次改动 `84cfbe6`（2026-09-17），`docs/protocol-pcap-test/smtp/` 0 个 pcap（`.gitignore` 排除），pcap 留档 mtime 2026-09-27；本车道**未跑**该套件，**不以任何形式引用它作为"今日已跑通"证据**。**但 smtp 存量 42/43 顶层零残留（唯一例外是判死负例），43 例今日仍应可跑**——该缺口**不是**"不可跑"，而是"**数字未经今日复跑证实**"。口径与 opcua G-OPCUA-10 / pcep G-PCEP-11 一致。

### 8.3 逐条去向表（43 行）

| 存量 id | 去向 | 改写动作（P4） |
|---|---|---|
| `smtp-basic-session` | **保留** | `min_packets=16` → 补精确 `packet_count=20` |
| `smtp_t002_top_smtp_presence_reject` | **保留** | 删 `notes`；补 pcap 留档 |
| `smtp_t003_ehlo_multiline` | **保留** | 补 `packet_count=12`；可补 `smtp.response` 整行断言 |
| `smtp_t004_multi_rcpt` | **保留** | `min_packets=18` → 补精确 `packet_count=22` |
| `smtp_t005_rset` | **保留** | 补 `packet_count=24` |
| `smtp_t006_noop` | **保留** | 补 `packet_count=14` |
| `smtp_t007_vrfy` | **保留** | 补 `packet_count=14` |
| `smtp_t008_expn` | **保留** | 补 `packet_count=14` |
| `smtp_t009_quit_after_data` | **保留** | 补 `packet_count=18`；QUIT 字面断言受 dissector 限制（§8.2 #6） |
| `smtp_t010_email_text` | **保留** | 补 `packet_count=20`；可补 MIME 结构断言（text-only 无 MIME-Version） |
| `smtp_t011_email_alternative` | **保留** | 补 `packet_count=20`；可补 `Content-Type: multipart/alternative` 行 |
| `smtp_t012_email_attach` | **保留** | 补 `packet_count=23`；可补 `smtp.data.fragment.count=4` + 附件字节断言 |
| `smtp_t013_port_587` | **保留** | 补 `packet_count=20` |
| `smtp_t014_port_465` | **保留** | 补 `packet_count=20`；TLS 底座例另立（G-SMTP-2） |
| `smtp_t015_v6` | **保留** | 补 `packet_count=20`；可补 `ipv6.src/dst` 断言 |
| `smtp_t016_postfix_banner` | **保留** | 补 `packet_count=12`；可补 banner 全文 frame 断言 |
| `smtp_t017_auth_login` | **保留** | 补 `packet_count=18`；可补 `smtp.auth.username` 断言 |
| `smtp_t018_starttls_script` | **保留** | 补 `packet_count=14`；STARTTLS 字面受 dissector 限制（§8.2 #6） |
| `smtp_t019_bad_srcip_reject` | **保留** | 删 `notes`；C 类边界已在 notes 声明，删前须在 §4 表内保留归属说明 |
| `smtp_t020_mss_reject` | **保留** | 删 `notes`；补 pcap 留档 |
| `smtp_t021_boundary_reject` | **保留** | 删 `notes`（**唯一走 smtp validator 的负例之一**） |
| `smtp_t022_attach_nodata_reject` | **保留** | 删 `notes`（**唯一走 smtp validator 的负例之二**） |
| `smtp_t023_turn` | **保留** | 补 `packet_count=14` |
| `smtp_t024_default_twoflow` | **保留** | **已有精确 `packet_count=40`**（唯一）；可补两流 src_port 断言 |
| `smtp_t024b_static_pinned_reject` | **保留** | 删 `notes`；补 pcap 留档 |
| `smtp_t025_fail_530_auth` | **保留** | 补 `packet_count=14` |
| `smtp_t026_fail_550_mailbox` | **保留** | 补 `packet_count=16` |
| `smtp_t027_fail_554_toolarge` | **保留** | 补 `packet_count=18` |
| `smtp_t028_fail_452_storage` | **保留** | 补 `packet_count=16` |
| `smtp_t029_fail_421_unavail` | **保留** | 补 `packet_count=12` |
| `smtp_t030_fail_503_sequence` | **保留** | 补 `packet_count=14` |
| `smtp_t031_fail_535_authfail` | **保留** | 补 `packet_count=18` |
| `smtp_t032_email_html_only` | **保留** | 补 `packet_count=20`；可补 `Content-Type: text/html` 行 |
| `smtp_t033_email_mixed_multi` | **保留** | 补 `packet_count=23`；可补 `smtp.data.fragment.count=4` + 双附件断言 |
| `smtp_t034_email_empty_body` | **保留** | 补 `packet_count=20` |
| `smtp_t035_email_attach_only` | **保留** | 补 `packet_count=20`；可补"无首体块"断言 |
| `smtp_t036_direction_override` | **保留** | 补 `packet_count=13`；下行帧断言受 dissector 限制（§8.2 #6） |
| `smtp_t037_two_mails` | **保留** | 补 `packet_count=28` |
| `smtp_t038_abort_no_quit` | **保留** | 补 `packet_count=18` |
| `smtp_t039_keepalive_multi_noop` | **保留** | 补 `packet_count=18` |
| `smtp_t040_composite_auth_rset_twomail` | **保留** | 补 `packet_count=36` |
| `smtp_t041_gmail_banner` | **保留** | 补 `packet_count=12` |
| `smtp_t042_exchange_banner` | **保留** | 补 `packet_count=12` |

**去向统计**：**保留 43 / 改写 0 / 作废 0**——全部存量用例形状已合规（纯层链形），改写动作均为**增量补断言**（包数 + 字段收编），无一条需删改语义。**本协议存量 42/43 顶层零残留**（唯一例外 `t002` 是判死负例）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

`coverage_gate.py` **已有** `check_smtp`（35 项，实测 35/35 绿）。下列为**建议增补**行（每条均可从本契约与 cases JSON 直接机读，不需新造事实）：

| # | 建议断言 | 依据 | 现状 |
|---:|---|---|---|
| 1 | `len(cases) == 43` 且 ID 集合 = §2 四十三项，顺序一致 | 本契约 §2 | 今日成立 |
| 2 | `spec_json` 顶层键 ⊆ `{layers}`，**例外仅判死负例**（`expect_error=true` 且带顶层 `smtp`） | 本契约 §1；设计 §12.1 | 今日成立 |
| 3 | 非负例顶层键计数 == 0 | 设计 §12.1 | 今日成立 |
| 4 | 37 正例 `packet_count` 按 §9 公式复算一致 | 设计 §9 公式 | **红**（34 例缺键）→ G-SMTP-1 |
| 5 | 6 负例 `expect` 键 == `{expect_error, error_contains}` | 本契约 §4 | **红**（含 `notes`）→ G-SMTP-11 |
| 6 | 负例 `error_contains` ∈ 代码锚词集 `{"rejects flat config field", "invalid IP address", "out of range", "Boundary", "neither Data nor DataB64", "static"}` | 设计 §7 | 今日成立 |
| 7 | 每正例至少一条 frames 断言落在 offset 54（IPv4）或 74（IPv6） | 本契约 §3 | **红**（仅 9/37 例有 frames）→ G-SMTP-1 |
| 8 | 层链形 ⊆ `{[ip,tcp,smtp], [tcp,smtp], [ip,tcp,tls,smtp]}` | 本契约 §1 | 今日成立（43/43 为 `[ip,tcp,smtp]`） |
| 9 | 9 个 email 例至少一例含 `smtp.data.reassembled.length` 或 `smtp.data.fragment.count` 断言 | 本契约 §3.7 | **红**（零使用）→ G-SMTP-12 |

**红项如实标红，不申报"今日已过"**：第 4/5/7/9 行今日为红（对应 G-SMTP-1/G-SMTP-11/G-SMTP-12）。

**另注意**：`trafficgen/docs/protocol-pcap-test/smtp.md` 的 `43/43 pass` 是**历史产物**（G-SMTP-10，末次改动 `84cfbe6` 2026-09-17；`docs/protocol-pcap-test/smtp/` 0 个 pcap——`.gitignore:88` 排除；pcap 留档 mtime 2026-09-27），**不得作为"今日已复跑"依据**（口径与 opcua G-OPCUA-10 / pcep G-PCEP-11 一致）。**但 smtp 存量 42/43 顶层零残留（唯一例外是判死负例），43 例今日仍应可跑**——该提醒**仅限**"数字未经今日复跑证实"。

## 10. 修订记录

- v1.0.0（2026-09-29）：批次二 as-built 文档轨。按 `protocol-doc-requirements.md` v1.3 撰写：形状基线机读实测（§1，含 `expect` 键频与字段通道使用统计）；43 ID 全表 + JSON 顺序权威（§2）；20 组正例逐项断言契约（§3，含 3 处 dissector 边界声明）；6 负例契约 + **C 类边界诚实声明**（§4，**仅 2/6 走 smtp validator**）；三源回指 + 对账四表 98 格（§5）；§3.15 三项 + A′/B′ 分类 + §3.14 豁免审计（§6）；执行建议（§7）；存量审计（§8，**43/43 保留**）；覆盖反查门建议断言行（§9，**4 行今日为红**）。**实测面**：14 条 frame 断言 14/14 命中；97 条 field 断言全绿；37 正例包数公式 37/37 一致；`coverage_gate.py smtp` 35/35 绿。**自审 4 轮（机读脚本复核每轮计数与断言，非手算），末轮干净**。

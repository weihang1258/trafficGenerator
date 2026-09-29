# #106 pop3（POP3，RFC 1939）测试用例契约

> 版本：v1.0.0（P-PIPE 批次二文档轨 as-built；修订记录见 §10）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/106-pop3-design.md` v1.0.0
> 前身基线：`docs/TEST_CASES.md` 的 `T-POP3-1…` 条目（§2839 起，D-POP3-1 P3 先行版）+ `docs/CODE_DESIGN.md` D-POP3-1（§1341 起）。**承其 50 例 ID 集合与断言思路**，冲突处按 cases JSON 与实测 pcap 改正（设计 §0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/pop3.json`（**50/50 ID 与本版 §2 一致，顺序一致**，已机读实测；顶层键 49 例纯 `{layers}` + 1 例 presence 负例）
> 白话一句：**五十条检查：三十五条看正常收信（问候、登录三形、取信、删信、截取、扩展台词、断线、附件下载、现网三家、密文、新网段、多流、复合流），十五条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **50 个唯一语义 ID：35 正 + 15 负**（负例 A 组 11 + B 组 4）。派生规则：设计 §3 每个消息/字段条款、§5 每条驱动/自动派生规则、§7 每行错误处理在本文有对应断言；**断言不得超出设计声明范围**。**一个用例只验证一个协议行为**（§7 原子用例原则）。

**形状基线（2026-09-29 机读实测）**：

| 维度 | 实测 |
|---|---|
| 例数 | **50** |
| 正 / 负 | **35 / 15** |
| 用例顶层键 | `{expect,id,proto,spec_json,summary}` ×50 + `strategy_fc` ×2（t036/t046） |
| `spec_json` 顶层键 | **`{layers}` ×49** + `{layers, pop3}` ×1（**t035 presence 负例，故意**） |
| 层形 | `[ip,tcp,pop3]` ×49 + `[ip,tcp,tls,pop3]` ×1（t032） |
| 正例 `expect` 键形 | `{fields,has_handshake,notes,terminates}` ×30 + 含 `negotiated` ×1（t001）+ 含 `frames` ×3（t037/t038/t039）+ `{has_handshake,notes,packet_count}` ×1（t046） |
| 负例 `expect` 键形 | `{expect_error, error_contains, notes}` ×15（**含 `notes`，非严格两键**，G-POP3-6 口径） |
| `packet_count` 显式用例 | **1**（t046=14）；其余 34 正例**不写 `packet_count`**（包数由 §3 帧位与 fields 承载） |

**注意形状判读**：`t035` 是「**层链 + 顶层空子映射并存 = 判死负例**」形状——它带顶层 `pop3:{}` 是**判死输入本身**，**不是旧键残留**。收官自查「非负例顶层键 = 0」今日成立（49/49）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`、`pop.request.*`、`pop.response.*`、frames 整帧 hex offset 54/74）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关，今日 50 例**均未启用**）；**不设仅单路径可用的断言**。

**TSHARK 基线（本机 3.6.14 实测）**：`tshark -G fields` 中 `pop.*` 共 **19** 字段；50 例**只用 4 个**（`pop.request.command` / `pop.request.parameter` / `pop.response.indicator` / `pop.response.description`）。**进制/取值纪律（实测）**：四字段均为**字符串**（`FT_STRING`），值为**原文**（`+OK`/`-ERR`/`USER`/`alice`/`0 0`/`1 100`/`5 octets`）。

**多行体断言的实测陷阱（重要）**：`pop.response.data`（多行体后续行）在 PDML 里 `show` 值为**空串**（只有 `value` 是 hex），故 `-T fields -e pop.response.data` **恒输出空**——**多行体内容不可用 field 断言**，必须走 `frames` 整帧 hex（t037/t038/t039 三例正是该形态）。**不得**为多行体新增 field 断言（会真绿 = 假通过）。

**断言基线**：81 条 `fields` 断言（逐条对实测 pcap 复跑 **全 OK**）+ 3 条 `frames` 断言（用**校验器同款解析器** `pcaptest.ParseTsharkHex`+`MatchHexOffset` 复跑 **3/3 OK**）+ 70 条行为断言（`has_handshake` 35 + `terminates` 34 + `negotiated` 1）。

**动态字段禁止硬编码**：POP3 层**零生成期随机**（`POP3Generator struct{}` 空结构，无 ISN/ipID 参与——那些在 tcp 层）。唯一"生成期值"是缺省端口 110 与保底 src_port（t046 走 12345/12346），今日 t046 **未断言**该值（G-POP3-14）。

**包数约定（设计 §3.9 公式，46 例 pcap 逐例零误差）**：

```
packet_count = 3（握手） + [banner? 1 : 0] + Σ轮（[cmd? 1 : 0] + [resp 存在? ceil(len(resp_bytes)/1460) : 0]） + 4（挥手）
```

**保活/重试/RST 口径**：POP3 **无协议层保活**（RFC 1939 无 PING/keepalive 类命令）；长保活由 **NOOP 轮次**承载（t027 三 NOOP，语义 = 客户端维持会话）；**无重试/重连**（生成器不建模）；RST 为框架 tcp 层能力，**本协议层零断言**（今日无用例 → A′）；正例恒 FIN 优雅终止（`terminates=true` ×34）。

## 2. 原子用例索引（50 ID = 35 正 + 15 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count（实测 pcap） |
|---:|---|---|---|---:|
| 1 | `pop3_t001_default_session` | 正 | §3.1/§3.2/§3.4：默认会话（banner+USER+PASS+QUIT） | 14 |
| 2 | `pop3_t002_user_empty_skipped` | 正 | §5 规则 3：空 Cmd 只发响应 | 11 |
| 3 | `pop3_t003_apop_login` | 正 | §3.7：APOP 一条登录（32 hex 摘要） | 12 |
| 4 | `pop3_t004_user_in_transaction` | 正 | §3.8 非法转移 #2：事务态 USER 照发 | 18 |
| 5 | `pop3_t005_stat_empty` | 正 | §3.7：STAT 空信箱 `+OK 0 0` | 16 |
| 6 | `pop3_t006_list_multi` | 正 | §3.3：LIST 多行（`+OK 2 messages` + 2 行 + `.`） | 16 |
| 7 | `pop3_t007_list_outofrange` | 正 | §3.8 非法转移 #6：越界 `-ERR` 台词 | 16 |
| 8 | `pop3_t008_retr_maildrop` | 正 | §3.5：RETR 信箱合成（`+OK 5 octets`） | 16 |
| 9 | `pop3_t009_retr_missing` | 正 | §3.8 非法转移 #6：无此信 `-ERR` 台词 | 16 |
| 10 | `pop3_t010_dele` | 正 | §3.7：DELE + RSET 撤销 + 再 DELE | 20 |
| 11 | `pop3_t011_top` | 正 | §3.6：TOP 前 2 行合成 | 16 |
| 12 | `pop3_t012_uidl` | 正 | §3.7：UIDL 多行 + UIDL 1 单行 | 18 |
| 13 | `pop3_t012b_emit_top_no_mailbox_reject` | 负 | §7 N-7（A 组） | —（0 帧） |
| 14 | `pop3_t013_dot_stuffing` | 正 | §3.3：点填充（`.dotline` → `..dotline`） | 16 |
| 15 | `pop3_t014_user_toolong_reject` | 负 | §7 N-1（41>40） | — |
| 16 | `pop3_t015_pass_toolong_reject` | 负 | §7 N-2（256>255） | — |
| 17 | `pop3_t016_cmd_crlf_reject` | 负 | §7 N-3（命令注入） | — |
| 18 | `pop3_t017_resp_crlf_reject` | 负 | §7 N-4（单行响应 CRLF） | — |
| 19 | `pop3_t018_uid_toolong_reject` | 负 | §7 N-5（71>70） | — |
| 20 | `pop3_t019_apop_bad_digest_reject` | 负 | §7 N-6（摘要 7≠32） | — |
| 21 | `pop3_t020_rfc10_sequence` | 正 | RFC §10 官方序列全文抄 | 20 |
| 22 | `pop3_t021_capa` | 正 | RFC 2449 CAPA 台词 | 16 |
| 23 | `pop3_t022_stls` | 正 | RFC 2595 STLS 台词（授权 +OK / 事务 -ERR） | 12 |
| 24 | `pop3_t023_auth` | 正 | RFC 2595 AUTH 三机制台词 | 16 |
| 25 | `pop3_t024_mss_reject` | 负 | §7 N-12（B 组，mss=100<536） | —（无落盘） |
| 26 | `pop3_t025_two_retr` | 正 | §5 多事务①：同连接两 RETR | 18 |
| 27 | `pop3_t026_abort_no_quit` | 正 | §5 多事务②：无 QUIT 断线 | 14 |
| 28 | `pop3_t027_keepalive_noop` | 正 | §5 多事务③：3×NOOP 长保活 | 20 |
| 29 | `pop3_t028_gmail` | 正 | §4 场景⑪：Gmail 形（`recent:` 用户名） | 14 |
| 30 | `pop3_t029_outlook` | 正 | §4 场景⑪：Outlook 形 | 14 |
| 31 | `pop3_t030_dovecot` | 正 | §4 场景⑪：Dovecot 形（CAPA 7 项多行） | 16 |
| 32 | `pop3_t031_composite` | 正 | §4 场景⑮：复合流（6 动作一条流） | 20 |
| 33 | `pop3_t032_pop3s_995` | 正 | §1/§2：POP3S 995 经 tls 层 | 21 |
| 34 | `pop3_t033_v6` | 正 | §2：IPv6 承载（offset 74） | 14 |
| 35 | `pop3_t034_bad_ip_reject` | 负 | §7 N-13（B 组） | —（无落盘） |
| 36 | `pop3_t035_presence_reject` | 负 | §7 N-14（B 组，presence 判死） | —（无落盘） |
| 37 | `pop3_t036_static_pinned_reject` | 负 | §7 N-15（B 组，静态复制） | —（无落盘） |
| 38 | `pop3_t037_mime_multi_attach` | 正 | §3.5 MIME 双附件 + MSS 4 段 | 19 |
| 39 | `pop3_t038_empty_body_retr` | 正 | §3.3 size=0（`+OK 0 octets`） | 16 |
| 40 | `pop3_t039_attach_only` | 正 | §3.5 纯附件无正文 | 19 |
| 41 | `pop3_t040_pass_auth_failed` | 正 | §3.8 非法转移 #2 变体：PASS `-ERR` 台词 | 14 |
| 42 | `pop3_t041_unknown_command` | 正 | §3.8 非法转移 #5：`FOO` → `-ERR` 台词 | 16 |
| 43 | `pop3_t042_maildrop_no_mailbox_reject` | 负 | §7 N-8（A 组） | — |
| 44 | `pop3_t043_maildrop_msgnum_range_reject` | 负 | §7 N-9（A 组） | — |
| 45 | `pop3_t044_top_msgnum_range_reject` | 负 | §7 N-10（A 组） | — |
| 46 | `pop3_t045_emit_both_exclusive_reject` | 负 | §7 N-11（A 组） | — |
| 47 | `pop3_t046_default_twoflow` | 正 | §2/§12.12：全缺省 `flows=2` | 14 |
| 48 | `pop3_t047_quit_bare` | 正 | §3.8 非法转移 #4（合法路径）：未登录直接 QUIT | 10 |
| 49 | `pop3_t048_list_single` | 正 | §3.7：LIST 单封单行 `+OK 1 100` | 16 |
| 50 | `pop3_t049_top_zero_lines` | 正 | §3.6：TOP N=0 仅头 | 16 |

**T-编号对照**：`pop3_tNNN_*` 的 NNN 即前身 `T-POP3-NNN`（T-001…T-049；**T-012b 为 T-012 的姊妹负例**，同号加 b 后缀）。**序号以 cases JSON 顺序为权威**（JSON 中 `pop3_t012b_*` 在 `pop3_t012_uidl` 之后、`pop3_t013_*` 之前）。

**包数公式校验**：46 例有落盘者**全部**用 §1 公式重算并比对实测 pcap，**零误差**（t032 = 公式 14 + tls 层 7 帧 = 21；t046 = 2 × 空会话 7 帧 = 14）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

**正例总则**：多行体内容**只能**走 frames 整帧 hex（§1 陷阱）；单行字段走 `pop.*`；**不得**断言 tcp 层随机值（ISN/ipID/Timestamp）。

### 3.1 `pop3_t001_default_session`（14，唯一含 `negotiated`）

输入：`banner="+OK POP3 server ready"`、`commands=[USER alice/+OK alice, PASS secret/+OK Logged in, QUIT/+OK bye]`；`src_port=13000`、`dst_port=110`。

- 行为：`has_handshake=true`、`negotiated=true`、`terminates=true`。
- fields（6 条）：包 1 `tcp.dstport=110`（**端口基线，缺省 110 的唯一直接证据**）；包 4 `pop.response.indicator=+OK`（banner）；包 5 `pop.request.command=USER` + `pop.request.parameter=alice`；包 9 `pop.request.command=QUIT`；包 10 `pop.response.indicator=+OK`。
- **帧位证据（实测）**：帧 1-3 握手 / 帧 4 banner(down,23B) / 帧 5 USER(up,12B) / 帧 6 resp(11B) / 帧 7 PASS(13B) / 帧 8 resp(15B) / 帧 9 QUIT(6B) / 帧 10 resp(9B) / 帧 11-14 FIN 四包。包数 = 3+1+3×2+4 = **14** ✓
- notes 记录：`POP3 短命令帧恒<80B（frame.len 代理不适用；mqtt/smtp 先例同款不断 has_payload）`——**不断 `has_payload` 的理由**：POP3 命令帧 tcp.len 仅 6–23B，`checkHasPayload` 的 `frame.len>80` 启发式会恒误报（设计 §6 六类场景的"基线"落点）。

### 3.2 `pop3_t002_user_empty_skipped`（11）

输入：`banner=…`、`commands=[{"cmd":"", "response":"+OK send password"}, {QUIT/+OK bye}]`。

- fields（2 条）：包 5 `pop.response.indicator=+OK`（**空 Cmd 的响应占包 5**）；包 6 `pop.request.command=QUIT`。
- **空 Cmd 语义证据（实测）**：帧 4 banner / **帧 5 = 纯响应(down,19B)**（无对应 up 帧）/ 帧 6 QUIT / 帧 7 resp / 帧 8-11 FIN。包数 = 3+1+1+2+4 = **11** ✓（若空 Cmd 未跳过则应为 12）。
- **P5 偏差更正**：前身记「t002 空 Cmd 包位手算错→落盘重钉（包 5 响应/包 6 QUIT）」——本版以 JSON 为准 ✓。

### 3.3 `pop3_t003_apop_login`（12）

输入：`banner="+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>"`（**含 RFC §10 官方 timestamp**）、`commands=[APOP alice c4f1844678c2f18b0f915c267cf01649/+OK maildrop locked and ready, QUIT/+OK bye]`。

- fields（2 条）：包 5 `pop.request.command=APOP`；包 6 `pop.response.indicator=+OK`。
- **摘要长度证据**：摘要 **32** 字符 = `HexDigestLen`（设计 §3.7）——**合法上界**路径，与 t019（7 字符越界）成对。
- **诚实声明**：摘要由**用户原文**提供，`computeAPOPDigest`（`planner.go:695`）**planner 从不调用**（设计 §1 边界④）。**不断言摘要与 timestamp+password 的 MD5 关系**（引擎不计算）。

### 3.4 `pop3_t004_user_in_transaction`（18）

输入：`banner=…`、`commands=[USER/PASS/STAT/USER bob/QUIT]`（5 轮）。

- fields（2 条）：包 5 `pop.request.command=USER`（授权态）；包 11 `pop.request.command=USER`（**事务态，第二次**）。
- **非法转移 #2 证据**：同一 `pop.request.command=USER` 出现在两个包位（5 与 11）——**引擎照发，不拦不补 `-ERR`**（设计 §3.8 架构声明）。包数 = 3+1+5×2+4 = **18** ✓
- **诚实声明**：本用例断的是"**照发**"，**不是**"正确拒绝"——RFC §3 要求服务器回 `-ERR`，本引擎不回（G-POP3-2 明确不解决）。

### 3.5 `pop3_t005_stat_empty`（16）

输入：banner + USER/PASS/STAT(`+OK 0 0`)/QUIT。

- fields（3 条）：包 9 `pop.request.command=STAT`；包 10 `pop.response.indicator=+OK`；包 10 `pop.response.description=0 0`。
- **空信箱证据**：`0 0` = RFC §5 drop listing 格式（`+OK <消息数> <字节数>`）——**零封零字节**的直接证据（与 t048 单封 `1 100` 成对）。

### 3.6 `pop3_t006_list_multi`（16）

输入：banner + USER/PASS + `LIST` 响应 = `"+OK 2 messages\r\n1 100\r\n2 200\r\n.\r\n"`（`multiline=true`）+ QUIT。

- fields（2 条）：包 9 `pop.request.command=LIST`；包 10 `pop.response.indicator=+OK`。
- **多行结构证据（PDML 实测，帧 10）**：`pop.response`(pos 54, 16B) 含 `indicator=+OK`(pos 54,3B) + `description=2 messages`(pos 58,10B)；随后三个 `pop.response.data` 元素：`1 100\r\n`(pos 70)、`2 200\r\n`(pos 77)、`.\r\n`(pos 84)。
- **不断言 `pop.response.data`**：其 `show` 值为**空串**（§1 陷阱），field 断言会真绿 → **多行体内容走 frames**（今日 t006 未建 frames 断言 → A′ 候选，G-POP3-1）。

### 3.7 `pop3_t007_list_outofrange`（16）

输入：banner + USER/PASS + `LIST 5` 响应 = `-ERR no such message, only 2 messages` + QUIT。

- fields（2 条）：包 9 `pop.request.command=LIST`；包 10 `pop.response.indicator=-ERR`。
- **`-ERR` 台词证据**：`indicator=-ERR` 是 RFC §3「negative status indicator」的**大写形态**（MUST upper case）——**由用户 Response 原文承载**，引擎不判越界（设计 §3.8 非法转移 #6）。
- **与 t043 的分工**：本用例走**回放台词**（引擎不拦）；t043 走 **validator 真拦**（合成路径越界）——**两者不可互替**。

### 3.8 `pop3_t008_retr_maildrop`（16）

输入：`mailbox.messages=[{uid u1, headers [From, Subject], body "hello"}, {uid u2, headers [From]}]`；`commands=[…, RETR 1/emit_mail_drop+msg_num 1, QUIT]`。

- fields（2 条）：包 9 `pop.request.command=RETR`；包 10 `pop.response.indicator=+OK`。
- **合成体证据（实测帧 10，tcp.len=51）**：`+OK 5 octets\r\n`（size=5=`len("hello")`，**不含头与空行**）+ `From: a@b.c\r\n` + `Subject: T\r\n` + `\r\n` + `hello\r\n` + `.\r\n`。
- **`size` 语义证据**：`Size` 未设（0）→ 取 `len(bodyText)`=5（设计 §3.3）；与 t038（空体 → `0 octets`）成对。
- **MsgNum 2 空信形态**：`Mailbox.Messages[1]`（uid u2）有头无体——今日**无用例**取该封（A′ 候选，G-POP3-3）。

### 3.9 `pop3_t009_retr_missing`（16）

输入：banner + USER/PASS + `RETR 5` 响应 = `-ERR no such message` + QUIT。

- fields（2 条）：包 9 `pop.request.command=RETR`；包 10 `pop.response.indicator=-ERR`。
- 与 t007 同型（台词版越界），**分属不同命令**（LIST vs RETR）→ 各留一例（§7 原子性）。

### 3.10 `pop3_t010_dele`（20）

输入：banner + USER/PASS + DELE 1 + RSET + DELE 1 + QUIT（6 轮）。

- fields（4 条）：包 9 `DELE`；包 11 `RSET`；包 13 `DELE`；包 15 `QUIT`。
- **帧位证据**：9/10 DELE 对、11/12 RSET 对、13/14 DELE 对、15/16 QUIT 对；包数 = 3+1+6×2+4 = **20** ✓
- **P5 偏差更正**：前身记「t010 补 RSET（DELE 后撤销标记，转离线 3_11_1，包 9/11/13/15 落盘钉死）」——本版以 JSON 为准 ✓。

### 3.11 `pop3_t011_top`（16）

输入：`mailbox.messages=[{uid u1, headers [From], body "l1\nl2\nl3"}]`；`commands=[…, TOP 1 2/emit_top+msg_num 1+top_lines 2, QUIT]`。

- fields（2 条）：包 9 `pop.request.command=TOP`（**`pop.request.parameter` 未断言**——实测值为 `1 2`，A′ 可收编）；包 10 `pop.response.indicator=+OK`。
- **TOP 状态行证据（实测帧 10，tcp.len=31）**：`+OK\r\n`（**无 size**，与 RETR 式不同）+ `From: a@b.c\r\n` + `\r\n` + `l1\r\n` + `l2\r\n` + `.\r\n`（**只前 2 行**，`l3` 不发）——RFC §7 TOP 语义直接证据。

### 3.12 `pop3_t012_uidl`（18）

输入：banner + USER/PASS + `UIDL` 多行(`+OK\r\n1 u1\r\n2 u2\r\n.\r\n`) + `UIDL 1` 单行(`+OK 1 u1`) + QUIT。

- fields（2 条）：包 9 `pop.request.command=UIDL`（多行）；包 11 `pop.request.command=UIDL`（单行带参）。
- **多行/单行对称证据**：包 10 = 多行（`indicator=+OK` + `description` 空 + 3 个 data 元素）、包 12 = 单行（`description=1 u1`）——RFC §7 UIDL 两形态各一。
- **诚实声明**：UID 由用户原文提供，`UID` 空时 planner **不自动生成**（`types.go:6949-6952` 注释口径）——**不断言自动生成**。

### 3.13 `pop3_t013_dot_stuffing`（16）

输入：`mailbox.messages=[{uid u1, headers [From], body ".dotline\nnormal"}]`；`commands=[…, RETR 1/emit_mail_drop, QUIT]`。

- fields（2 条）：包 9 `pop.request.command=RETR`；包 10 `pop.response.indicator=+OK`。
- **点填充证据（实测帧 10，tcp.len=52，`+OK 15 octets`）**：体行 `.dotline` → 线上 **`..dotline\r\n`**（RFC §3 byte-stuffing 逐字：行首终止八位组则 prepend 一个）；`normal\r\n` 不变；终止行 `.\r\n`。
- **size 证据**：15 = `len(".dotline\nnormal")` = 8+1+6 = 15（**未填充前**的体字节）——RFC §11 原文「lines in the message which start with the termination octet need **not** (and **must not**) be counted twice」的直接验证 ✓
- **行尾规范化证据**：输入体用 `\n`，线上输出为 `\r\n`（设计 §3.3 规范化规则）。

### 3.14 `pop3_t020_rfc10_sequence`（20）

输入：RFC §10 官方序列全文抄（USER/PASS/STAT/LIST 多行/RETR 多行/QUIT，6 轮）。

- fields（3 条）：包 5 `USER`；包 9 `STAT`；包 13 `RETR`。
- **官方序列证据**：LIST 响应 `+OK 2 messages\r\n1 120\r\n2 200\r\n.\r\n`、RETR 响应 `+OK 120 octets\r\nFrom: a@b.c\r\n\r\nhello\r\n.\r\n`——与 RFC §10 示例（`+OK 2 320`/`1 120`/`2 200`/`+OK 120 octets`）**数值一致**。
- 包数 = 3+1+6×2+4 = **20** ✓

### 3.15 `pop3_t021_capa`（16）

输入：banner + USER/PASS + `CAPA` 响应 = `+OK Capability list follows` + QUIT。

- fields（2 条）：包 9 `pop.request.command=CAPA`；包 10 `pop.response.indicator=+OK`。
- **诚实声明**：RFC 2449 CAPA 是**扩展**（非 RFC 1939）；本用例是**台词版**——**不做真协商**（设计 §1 边界②/§10.1 第 8 项）。

### 3.16 `pop3_t022_stls`（12）

输入：banner + `STLS`/`+OK Begin TLS negotiation` + `USER alice`/`-ERR Must issue STLS first`（2 轮，**无 PASS/QUIT**）。

- fields（2 条）：包 5 `pop.request.command=STLS`；包 7 `pop.request.command=USER`。
- **台词对称证据**：授权态 `+OK` + 事务态 `-ERR`（RFC 2595 §3 语义的**台词覆盖**）；**不做原地升级**（设计 §1 边界②）。
- 包数 = 3+1+2×2+4 = **12** ✓（最短正例之一）

### 3.17 `pop3_t023_auth`（16）

输入：banner + `AUTH PLAIN`/`+ Ready for authentication` + `AUTH LOGIN`/`+ VXNlcm5hbWU6` + `AUTH CRAM-MD5`/`+ PDEyMzQ1 poseidon` + QUIT。

- fields（3 条）：包 5/7/9 `pop.request.command=AUTH`（三机制各一）。
- **诚实声明**：RFC 2595 AUTH 是**扩展**；三机制是**台词轮次**——**不产 challenge 校验**（设计 §1 边界③）。`+ ` 开头的中间响应（`+ VXNlcm5hbWU6`）走**单行响应**路径（非 `+OK`/`-ERR` 状态行，仍以 CRLF 终止）。

### 3.18 `pop3_t025_two_retr`（18，多事务①）

输入：banner + USER/PASS + RETR 1 + RETR 1 + QUIT（5 轮）。

- fields（2 条）：包 9 `RETR`；包 11 `RETR`。
- **多事务证据**：同一连接内**两次 RETR**（RFC §5「The client may now issue any of the following POP3 commands **repeatedly**」）——包位 9 与 11 各一次。

### 3.19 `pop3_t026_abort_no_quit`（14，多事务②）

输入：banner + USER/PASS + RETR 1(emit_mail_drop) —— **无 QUIT**。

- fields（2 条）：包 9 `pop.request.command=RETR`；包 10 `pop.response.indicator=+OK`。
- **异常断线证据**：`commands` 无 QUIT，但 `terminates=true` 仍成立（**tcp 层照常 FIN 四包**，帧 11-14）——RFC §6 原文「If a session terminates for some reason other than a client-issued QUIT command, the POP3 session does **NOT** enter the UPDATE state」的生成器侧对应：**引擎不区分**，恒 FIN。
- 包数 = 3+1+3×2+4 = **14** ✓

### 3.20 `pop3_t027_keepalive_noop`（20，多事务③）

输入：banner + USER/PASS + NOOP×3 + QUIT（6 轮）。

- fields（2 条）：包 9 `NOOP`；包 13 `NOOP`。
- **长保活证据**：3 轮 NOOP（RFC §5 NOOP 语义 = 无操作，用于维持会话）——包位 9/11/13 各一。
- **诚实声明**：POP3 **无协议层 keepalive 心跳**；NOOP 是客户端侧保活手段（设计 §1 边界⑤/§6 六类场景"长时间运行"落点）。

### 3.21 `pop3_t028_gmail` / 3.22 `pop3_t029_outlook` / 3.23 `pop3_t030_dovecot`（14/14/16，现网三家）

- t028：banner `+OK Gpop ready for requests from 1.2.3.4 abc`、`USER recent:alice@gmail.com`；fields：包 4 `+OK`、包 5 `USER`。
- t029：banner `+OK Outlook POP3 server ready`；fields：包 4 `+OK`、包 5 `USER`。
- t030：banner `+OK Dovecot ready.`、CAPA 7 项多行（`TOP/UIDL/RESP-CODES/PIPELINING/STLS/USER/SASL`）、QUIT `+OK Logging out.`；fields：包 4 `+OK`、包 9 `CAPA`。
- **地板线诚实声明（三例共同）**：断的是"**问候/命令原文照抄**"，**不对接真服务器**、不验证书/口令（设计 §10.4 商业映射表）。**不得**读成"已验证现网兼容"。

### 3.24 `pop3_t031_composite`（20，复合流）

输入：banner + USER/PASS/STAT/RETR 1(合成)/DELE 1/QUIT（6 轮）。

- fields（4 条）：包 5 `USER`；包 9 `STAT`；包 11 `RETR`；包 13 `DELE`。
- **复合流证据**：登录 + 3 个业务动作（STAT/RETR/DELE）**一条流**（设计 §4 场景⑮；coverage_gate "复合流" 检查项的落点）。

### 3.25 `pop3_t032_pop3s_995`（21，POP3S）

输入：`[ip,tcp(dst_port=995),tls,pop3]`；banner + USER/PASS/QUIT。

- fields（2 条）：包 1 `tcp.dstport=995`；包 4 `tls.record.content_type=22`（**TLS handshake 记录**）。
- **帧位证据（实测）**：帧 1-3 握手 / 帧 4 ClientHello(161B) / 帧 5 ServerHello(95B) / 帧 6-9 证书+密钥交换（20/482/77/41B）/ 帧 10 ServerHelloDone(41B) / 帧 11-17 **TLS application_data 承载明文 POP3**（`2b4f4b20…`= `+OK ` 等）/ 帧 18-21 FIN。
- **诚实声明（关键）**：TLS 下 **`pop.*` 不可解**（app data 被 tls 层封装）——**本用例零应用层断言**，只断端口与 TLS 记录类型（设计 §1 profile 表 + G-POP3-13）。包数 = tls 层 7 帧 + pop3 层 14 帧 = **21** ✓

### 3.26 `pop3_t033_v6`（14，IPv6）

输入：`ip.src=2001:db8::1`、`ip.dst=2001:db8::2`；其余同 t001。

- fields（1 条）：包 4 `pop.response.indicator=+OK`（banner，**offset 74**）。
- **协议与地址族解耦证据**：POP3 载荷字节与 IPv4 下**完全一致**，只有起点从 54 变 74（设计 §2）——`pop.*` 字段在 v6 下同样解出 ✓
- **诚实声明**：本用例**不断 `ipv6.src/dst` 字段**（A′ 可收编）；notes 记「字段名无回值则降级注记；包位落盘重钉」。

### 3.27 `pop3_t037_mime_multi_attach`（19，MIME 双附件 + MSS 4 段）

输入：`mailbox.messages=[{uid u1, headers [From, Subject], mime_parts=[{text/plain body "see attaches"}, {text/markdown + base64 + Content-Disposition filename="README.md", body_b64=<仓库真实 README.md 全文>}]}]`；`commands=[USER/PASS, RETR 1(emit_mail_drop), QUIT]`。

- fields（3 条）：包 5 `USER`；包 9 `RETR`；包 10 `pop.response.indicator=+OK`。
- **frames（1 条）**：包 10 **offset 396** = `52 45 41 44 4d 45 2e 6d 64 22`（= `README.md"`）——**整帧偏移**（含 `+OK … octets` 状态行与全部前序体行）。
- **MSS 分段证据（实测）**：帧 10/11/12/13 tcp.len = 1460/1460/1460/1333（**4 段**，末段 1333）——`ceil(payload/1460)` 的直接证据（设计 §3.9/§8）。
- **偏移口径更正（P5 教训）**：前身记「首版 frames 用**载荷偏移**手算 → 校验器口径是**整帧偏移**（含 `+OK octets` 状态行）→ 落盘实测改 288」；`84cfbe6` 换真实 README.md 后**二次重钉为 396**（TEST_CASES.md 仍停 288，G-POP3-7）。
- 包数 = 3+1+3×2+4 = 14 **+ 5 段**（帧 10-13 四段 + QUIT 对）= **19** ✓

### 3.28 `pop3_t038_empty_body_retr`（16，空正文）

输入：`mailbox.messages=[{uid u1, headers [From]}]`（**无 body**）；`commands=[USER/PASS, RETR 1(emit_mail_drop), QUIT]`。

- fields（2 条）：包 9 `RETR`；包 10 `+OK`。
- **frames（1 条）**：包 10 **offset 54** = `2b 4f 4b 20 30 20 6f 63 74 65 74 73`（= `+OK 0 octets`）——**`size=0` 的直接证据**（空体 → `len("")=0`，设计 §3.3）；**同时证明载荷起点 = offset 54**（IPv4 无 options）。
- **体结构证据（实测帧 10，tcp.len=32）**：`+OK 0 octets\r\n` + `From: a@b.c\r\n` + `\r\n`（空行仍在）+ `.\r\n`（**无体行**）。
- **与设计 §3.3 的一致性**：空体时 `writeDotStuffedBody` **直接返回**（不写任何行），但**空行与终止行仍写**（`planner.go:467/473`）✓

### 3.29 `pop3_t039_attach_only`（19，纯附件无正文）

输入：`mailbox.messages=[{uid u1, headers [From, Subject], mime_parts=[单段：text/markdown + base64 + filename="README.md"]}]`（**无 text/plain 首段**）。

- fields（2 条）：包 9 `RETR`；包 10 `+OK`。
- **frames（1 条）**：包 10 **offset 314** = `52 45 41 44 4d 45 2e 6d 64 22`（`README.md"`）——**比 t037 早 82 字节**（少一个 text/plain 段），是"段数影响体长"的直接证据。
- **分段证据**：帧 10-13 四段（同 t037 形态）。
- 包数 **19** ✓

### 3.30 `pop3_t040_pass_auth_failed`（14）

输入：banner + USER alice/`+OK alice` + `PASS wrong`/`-ERR [AUTH] Authentication failed` + QUIT。

- fields（2 条）：包 7 `pop.request.command=PASS`；包 8 `pop.response.indicator=-ERR`。
- **现网最常见失败证据**：RFC §4「After returning a negative status indicator, the server **may close the connection**」——本用例走"**不关连接**"分支（QUIT 继续）✓

### 3.31 `pop3_t041_unknown_command`（16）

输入：banner + USER/PASS + `FOO bar`/`-ERR unknown command` + QUIT。

- fields（2 条）：包 9 `pop.request.command=FOO`；包 10 `pop.response.indicator=-ERR`。
- **非法转移 #5 证据**：RFC §3「A server MUST respond to an **unrecognized, unimplemented, or syntactically invalid** command by responding with a negative status indicator」——引擎侧**照发**，`-ERR` 由用户台词承载（设计 §3.8）。

### 3.32 `pop3_t046_default_twoflow`（14，多流，**唯一显式 `packet_count`**）

输入：`layers=[{ip:{}},{tcp:{}},{pop3:{}}]` + `strategy_fc={type:flows, value:2}`（**全缺省**，无 banner 无命令）。

- 行为：`has_handshake=true`、`packet_count=14`。
- **双流证据（实测）**：帧 1-7 流 1（src_port **12345**）、帧 8-14 流 2（src_port **12346**）——每流 = 3 握手 + 4 挥手 = **7 帧**（**空会话**，无 banner 无命令）；保底端口 = `DefaultSrcPort+i`。
- **静态复制门反例证据（关键）**：本用例与 t036 成对——t036（**显式标量**四元组 + `flows=2`）被 `checkLayerChainStaticCopy` 拒（锚词 `static`），本用例（**全缺省**层）**放行**（`semantic.go:198-200` 原文：仅当层内有任一四元组字段被**显式写成标量**时触发）。**两例必须成对解读**。
- **诚实声明**：本用例**不断**两流四元组不同（`tcp.srcport` 未进 fields）→ A′ 补（G-POP3-14）。

### 3.33 `pop3_t047_quit_bare`（10，最短正例）

输入：banner + `QUIT`/`+OK bye`（**未登录直接退出**，1 轮）。

- fields（3 条）：包 4 `pop.response.indicator=+OK`（banner）；包 5 `pop.request.command=QUIT`；包 6 `pop.response.indicator=+OK`。
- **AUTHORIZATION 态 QUIT 证据**：RFC §4 末「Here is the summary for the QUIT command when used in the **AUTHORIZATION** state: … Possible Responses: `+OK`」+ §6 原文「the POP3 session **terminates** but does **NOT** enter the UPDATE state」——**合法路径**（**不是**非法转移）。
- 包数 = 3+1+1×2+4 = **10** ✓（最短）

### 3.34 `pop3_t048_list_single`（16）

输入：banner + USER/PASS + `LIST 1`/`+OK 1 100` + QUIT。

- fields（3 条）：包 9 `pop.request.command=LIST`；包 10 `pop.response.indicator=+OK`；包 10 `pop.response.description=1 100`。
- **单行 scan listing 证据**：RFC §5 LIST 带参形态 `+OK <msg> <size>`——与 t006（无参多行）**对称**。

### 3.35 `pop3_t049_top_zero_lines`（16）

输入：`mailbox.messages=[{uid u1, headers [From], body "l1\nl2"}]`；`commands=[…, TOP 1 0/emit_top+msg_num 1+top_lines 0, QUIT]`。

- fields（2 条）：包 9 `pop.request.command=TOP`；包 10 `pop.response.indicator=+OK`。
- **N=0 证据（实测帧 10，tcp.len=25）**：`+OK\r\n` + `From: a@b.c\r\n` + `\r\n` + `.\r\n`——**头后直跟终止点**，`l1`/`l2` 均不发（`planner.go:517` 的 `topLines > 0` 守卫）。
- **与 t011 成对**：同一封信、同一 headers，`top_lines` 2 vs 0 → 体行数差异是唯一变量（原子性）。

## 4. 负例契约

负例必须在 validator / 链级门阶段失败并传播为 task error，**不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功**（**实测**：A 组 11 例 pcap 均 **0 帧**、文件名 `<id>.neg.pcap`；B 组 3 例 t024/t035/t036 **无落盘** = 创建期即拒，早于产流）。锚词与设计 §7 表**一一对应、同序**：

### 4.1 A 组：pop3 planner 门（11 例，经 `RegisterLayerValidator` 从链上调用）

| ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（`planner.go` 逐字） | 行 |
|---|---|---|---|---|
| `pop3_t012b_emit_top_no_mailbox_reject` | `emit_top=true` + `msg_num=1`，**无 `mailbox`** | `but Mailbox is nil` | `pop3: Commands[%d].EmitTop=true but Mailbox is nil` | `:168` |
| `pop3_t014_user_toolong_reject` | `USER ` + **41** 字符 | `USER name length` | `pop3: Commands[%d].USER name length %d exceeds max %d (RFC 1939 §6)` | `:181` |
| `pop3_t015_pass_toolong_reject` | `PASS ` + **256** 字符 | `PASS password length` | `pop3: Commands[%d].PASS password length %d exceeds max %d (RFC 1939 §6)` | `:185` |
| `pop3_t016_cmd_crlf_reject` | `Cmd="USER a\r\nDELE 1"` | `contains CRLF` | `pop3: Commands[%d].Cmd %q contains CRLF (command injection per RFC 1939 §3)` | `:144` |
| `pop3_t017_resp_crlf_reject` | `STAT` 响应 `"+OK 1\r\n2"`，`multiline` **未设** | `Multiline=false` | `pop3: Commands[%d].Response contains CRLF but Multiline=false; set Multiline=true for multi-line responses` | `:147` |
| `pop3_t018_uid_toolong_reject` | `mailbox.messages[0].uid` = **71** 字符 | `UID length` | `pop3: Mailbox.Messages[%d].UID length %d exceeds max %d (RFC 1939 §7 UIDL)` | `:133` |
| `pop3_t019_apop_bad_digest_reject` | `APOP alice NOTHEX!`（摘要 **7** 字符） | `APOP digest` | `pop3: Commands[%d].APOP digest length %d, must be %d hex chars (RFC 1939 §6)` | `:198` |
| `pop3_t042_maildrop_no_mailbox_reject` | `emit_mail_drop=true` + `msg_num=1`，**无 `mailbox`** | `EmitMailDrop=true but Mailbox is nil` | `pop3: Commands[%d].EmitMailDrop=true but Mailbox is nil` | `:153` |
| `pop3_t043_maildrop_msgnum_range_reject` | `emit_mail_drop` + `msg_num=5`（信箱 **1** 封） | `out of range` | `pop3: Commands[%d].MsgNum %d out of range [1, %d]` | `:156` |
| `pop3_t044_top_msgnum_range_reject` | `emit_top` + `msg_num=3`（信箱 **1** 封） | `out of range` | `pop3: Commands[%d].MsgNum %d out of range [1, %d]` | `:171` |
| `pop3_t045_emit_both_exclusive_reject` | `emit_mail_drop=true` **且** `emit_top=true` | `mutually exclusive` | `pop3: Commands[%d].EmitTop and EmitMailDrop are mutually exclusive` | `:165` |

### 4.2 B 组：链级/框架门（4 例，先于/独立于 pop3 validator）

| ID | 故障输入 | JSON `error_contains` | 门 | 代码位置 |
|---|---|---|---|---|
| `pop3_t024_mss_reject` | `tcp.mss=100`（<536） | `out of range [536,65535]` | 层字段范围门 | `layers/complete.go:325`（registry `mss` `Min:536`，`registry.go:68`） |
| `pop3_t034_bad_ip_reject` | `ip.dst="not-an-ip"` | `invalid IP address: not-an-ip` | 框架 ip 层门 | `ip` 层 |
| `pop3_t035_presence_reject` | `layers:[…]` **与**顶层 `pop3:{}` **并存** | `no longer accepts a top-level pop3 sub-config` | `CheckProtoFlat` pop3 分支 | `strategy_convert.go:8837-8841` |
| `pop3_t036_static_pinned_reject` | 显式标量四元组 + `strategy_fc{flows:2}` + 无动态逃生 | `static` | 静态复制门 | `schema/semantic.go:198-285` |

### 4.3 锚词口径与原子性

- **`error_contains` 是子串判定**；15 例逐条命中上表（机读实测，设计 §9.2）。
- **负例原子性**：每例**单一**故障注入；单次执行不得混注。**t043/t044 锚词同为 `out of range` 但分属不同分支**（`:156` MailDrop / `:171` TOP）——**删除任一例即失去一条独立分支的直接证据**（§7 不可再分判定标准）。
- **t012b/t042 成对**（EmitTop 版 / EmitMailDrop 版的无信箱门，`:168` vs `:153`）；**t036/t046 成对**（静态门红例 vs 全缺省绿例）。

### 4.4 `expect` 键形状注

存量 15 负例 `expect` = `{expect_error, error_contains, notes}`（**含 `notes`**），与 92-moxa 范式的严格两键不同。**注**：前身 T-POP3-1 未把 `notes` 列为待收窄项（与 opcua G-OPCUA-7 不同）——本版**如实登记现状**（G-POP3-6 子项），**不主张收窄**（notes 是设计意图记录，非断言）。

### 4.5 未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）

| 代码锚词 | 行 | 未入例原因 |
|---|---|---|
| `pop3: SrcIP %q is not a valid IP address` | `:105` | 链形状下地址住 `ip` 层，此门走**扁平路径**（今日无扁平用例） |
| `pop3: DstIP %q is not a valid IP address` | `:110` | 同上 |
| `pop3: MSS %d too small (min %d per RFC 879)` | `:118` | 同上（链上 mss 由 `complete.go` 先拦，见 t024） |
| `pop3: Mailbox has %d messages, max %d` | `:129` | **需 100001 封信**，成本不可接受（前身已登记） |
| `pop3: Commands[%d].APOP digest %q must be hex` | `:201` | **被长度门先拦**（t019 的 `NOTHEX!` 长 7 ≠ 32）；需 **32 字符非 hex** 输入 → A′ `pop3_neg_apop_digest_nonhex` |

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 1939 §3/§4/§5/§6/§7/§9/§10/§11（设计 §10，**原文逐条核对**）+ RFC 2449/2595/879/6528 + D-POP3-1（设计 §11）+ tshark 3.6.14 字段表与 **47 例实测 pcap**（`/tmp/mcp-pcaps/pop3/`）→ 50 ID（本契约 §2）。第三源"已确认现网行为"当前 = **抓包级已到**（本仓引擎产出的 47 例 pcap 逐帧核对），但**真实 POP3 服务器线字节未抓** → G-POP3-2（三家问候原文来自前身记载与 Dovecot 亲验，**地板线**）。

**50 ID 逐项回指（§9.5 要求）**：#1←§3.1/§3.2/§3.4；#2←§5 规则3；#3←§3.7；#4←§3.8#2；#5←§3.7；#6←§3.3；#7←§3.8#6；#8←§3.5；#9←§3.8#6；#10←§3.7；#11←§3.6；#12←§3.7；#13←§7 N-7；#14←§3.3；#15←§7 N-1；#16←§7 N-2；#17←§7 N-3；#18←§7 N-4；#19←§7 N-5；#20←§7 N-6；#21←§3.7(RFC §10)；#22←§3.7(RFC 2449)；#23←§3.7(RFC 2595)；#24←§3.7(RFC 2595)；#25←§7 N-12；#26←§5 多事务①；#27←§5 多事务②；#28←§5 多事务③；#29–31←§4 场景⑪；#32←§4 场景⑮；#33←§1/§2；#34←§2；#35←§7 N-13；#36←§7 N-14；#37←§7 N-15；#38←§3.5；#39←§3.3；#40←§3.5；#41←§3.8#2；#42←§3.8#5；#43←§7 N-8；#44←§7 N-9；#45←§7 N-10；#46←§7 N-11；#47←§2/§12.12；#48←§3.8#4；#49←§3.7；#50←§3.6。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 1939/2449/2595/879/6528 公开语义 + 前身契约（D-POP3-1/T-POP3-1）+ 仓库落码反推 + tshark 3.6.14 字段与 pcap 实测**，**非纯规范反推**（RFC §3 空闲定时器等无时钟面已登记不解决 → G-POP3-11）。
- **对账两行**：**要求逻辑点总数 = 88**（八项 8 行 + 命令×响应矩阵 39 格 + 变体 22 行 + 商业映射 18 行 + 设计 §3.8 非法转移 6 条，逐项去重后 88）；**用例覆盖数 = 52**（八项已覆 4 + 矩阵已覆 23 + 变体已覆 14 + 商业已覆 10 + 非法转移已覆 4 = 55，去重后 52）；**不适用 = 19**（八项 1 + 矩阵 10 + 商业 8 + 非法转移 1 = 20，去重后 19）；**开放立项 = 17**（八项 3 + 矩阵 6 + 变体 8 + 非法转移 1 = 18，去重后 17）。
  **重数校验（逐表，与设计 §10 合计行逐格对账，机读）**：八项 8 = 覆 4 + 立项 3 + 不适用 1 ✓；**矩阵 39 = 覆 23 + 立项 6 + 不适用 10** ✓（与设计 §10.2 合计行同源）；变体 22 = 覆 14 + 立项 8 ✓（机读逐行取末列；行 21 复合态按立项计）；商业 18 = 覆 10 + 明确不解决 8 ✓；非法转移 6 = 覆 4（#2/#4/#5/#6）+ 不适用 1（#3）+ 立项 1（#1）✓。**零"未处置"格**（39 格逐格归类，设计 §10.2 已列逐格点名）。**合计校验：52（覆）+ 19（不适用）+ 17（立项）= 88 ✓**（与"要求逻辑点总数"相等，去重后无剩余）。
  **口径自伤声明（诚实登记）**：本小节初稿曾出现"矩阵已覆 23 / 立项 7 / 不适用 8 + 未处置 1"的**自创口径**，与设计 §10.2 的机读枚举（23/6/10）矛盾——**已按机读枚举改正**；此类"逐格说明与合计行不一致"是本车道本轮的实际自伤（见修订记录），读者**一律以各表合计行为准**。
- **门3 抽查候选**：最复杂用例 = **#38 `pop3_t037_mime_multi_attach`**（19 帧：3 握手 + banner + 3 命令对 + **4 段 MSS 分段体**（1460×3 + 1333）+ 4 挥手；交织维度 = MIME 段数(2)×编码(base64/text)×dot-stuffing×MSS 分段(4)×整帧偏移）；**建议门3 抽 #38 + #47**（`pop3_t046_default_twoflow` 补多流面）。

### 5.3 T-编号与旧 id 对照（设计 §9.1 全表摘要）

`pop3_t001_default_session` ≡ T-POP3-1；`pop3_t002_user_empty_skipped` ≡ T-POP3-2；`pop3_t003_apop_login` ≡ T-POP3-3；`pop3_t004_user_in_transaction` ≡ T-POP3-4；`pop3_t005_stat_empty` ≡ T-POP3-5；`pop3_t006_list_multi` ≡ T-POP3-6；`pop3_t007_list_outofrange` ≡ T-POP3-7；`pop3_t008_retr_maildrop` ≡ T-POP3-8；`pop3_t009_retr_missing` ≡ T-POP3-9；`pop3_t010_dele` ≡ T-POP3-10；`pop3_t011_top` ≡ T-POP3-11；`pop3_t012_uidl` ≡ T-POP3-12；`pop3_t012b_emit_top_no_mailbox_reject` ≡ **T-POP3-12b**（前身 P5 落地时新增的姊妹负例）；`pop3_t013_dot_stuffing` ≡ T-POP3-13；`pop3_t014…t019` ≡ T-POP3-14…19；`pop3_t020_rfc10_sequence` ≡ T-POP3-20；`pop3_t021…t024` ≡ T-POP3-21…24；`pop3_t025…t027` ≡ T-POP3-25…27；`pop3_t028…t031` ≡ T-POP3-28…31；`pop3_t032_pop3s_995` ≡ T-POP3-32；`pop3_t033_v6` ≡ T-POP3-33；`pop3_t034…t036` ≡ T-POP3-34…36；`pop3_t037…t049` ≡ T-POP3-37…49。

**注**：前身 `T-POP3-1` 清单列到 **T-49**，JSON 恰 **50** 例（多出 T-012b）。**序号以 cases JSON 顺序为权威**。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接多轮命令（t025 两 RETR、t027 三 NOOP、t031 六动作、t020 官方六轮、t010 六轮） | 已覆 t025/t027/t031/t020/t010 |
| ② | 非正常结束 | 正常 FIN 全正例（33 例 `terminates=true`）+ 应用层正常终止 = `QUIT`；传输异常 = RST | 已覆（无 QUIT 断线 t026）；**RST A′ 立项**（本层零断言） |
| ③ | 长保活 | POP3 **无协议层心跳**；长保活 = 多 NOOP 轮次 | 已覆 t027（3×NOOP） |

无空项：① 五例；② 一例 + 1 条 A′ 立项；③ 一例。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 多行体断言面 | 多行体内容改用 `frames` 整帧 hex（`pop.response.data` 的 `show` 为空串，**field 断言不可行**） | G-POP3-1 |
| 边界相邻值面 | USER=40 / PASS=255 / UID=70 / APOP digest=32 的**合法上界**各一例 | G-POP3-3 |
| 上界面 | 响应 >512（RFC §3）、参数 >40 的非 USER/PASS 命令 | G-POP3-3 |
| 非法转移面 | 授权态 `STAT`（非法转移 #1）台词例 | G-POP3-2 |
| 终止符面 | 多行响应缺 `.` | G-POP3-4 |
| size 面 | `Size>0` 用户值路径 | G-POP3-5 |
| 端口面 | 删 `dst_port` 断缺省 110 | G-POP3-3 |
| TOP 面 | `TopLines > 体行数`（RFC §7「发整封」） | G-POP3-3 |
| boundary 面 | 自定义 `Boundary` | G-POP3-3 |
| 分段面 | `mss=536` 变更 → 分段数变化 | G-POP3-12 |
| 空形态面 | banner 空（`pop3_no_banner`）/ 空 Response 客户端单轮 | G-POP3-3 |
| APOP 面 | 32 字符非 hex 摘要 | §4.5 |
| 多流面 | t046 补 `tcp.srcport` 断言（两流四元组不同） | G-POP3-14 |
| POP3S 面 | t032 补 `tls.app_data` 原始 hex 断明文内容 | G-POP3-13 |
| 非正常结束 | `tcp.rst` 补例 | ② 的 A′ |

**B′（框架面）**：顶层游离键通用门（G-POP3-9，等框架级 unknown-key 白名单，**不建单协议黑名单分支、不建负例**）/ 业务字段动态（G-POP3-10，allowlist 无 `pop3` 行）。进设计 §14。

### 6.3 3.14 豁免边界审计

**有长连接载体（TCP）→ `sessions[]` 不豁免**——但本协议 `POP3Config` **无 `sessions` 字段**（`types.go:6878-6884`），"多会话"面由**策略级 `flow_control.flows` 整会话复制**承载（t046：两流各 7 帧、状态不串用）——**形态差异已声明**（设计 §12.3 会话表）。**多流（会话内并发流）显式不适用**（单连接串行）。**单包多载荷** = **不适用**（POP3 每帧一个命令或一个响应，无多 question/多 RR 类形态，如实声明）。

**多事务三项未豁免**（t025/t026/t027 各一，§6.1）✓

## 7. 实现后执行建议

1. **P4 顺序**：①先补 A′ 的**边界相邻值 4 例**（USER/PASS/UID/digest 合法上界，成本最低、价值最高）；②补 `pop3_neg_order_stat`（非法转移 #1 台词例）；③多行体断言改 frames（t006/t012/t020/t030 四例）；④t046 补 `tcp.srcport` 断言；⑤全量复跑。**本协议无 §1 迁移步骤**（顶层零残留）。
2. **实测顺序**：先 #1（默认会话 14 帧 + `tcp.dstport=110` 基线），再 #2（空 Cmd 跳过 → 11 帧），再 #5/#48（STAT/LIST 单行 description），再 #6（多行结构 PDML 三 data 元素），再 #8/#38/#39（合成体 size 与 frames 偏移），最后 #32（TLS 21 帧）、#33（IPv6 offset 74）、#47（双流 14 帧）。
3. **二进制与 HEAD 同代确认**（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=pop3` 全量不是增量）；门2④ 反查绿后进 P6。
4. **不得手算包数**：包数一律落盘实测（§1 公式仅供**交叉校验**）；**不得手算 frames 偏移**（前身两次教训：288→396、206→314，§3.27）。
5. **不得为多行体新增 `pop.*` field 断言**（`pop.response.data` 的 `show` 为空串，会真绿 = 假通过，§1）。

## 8. 存量审计（50 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/pop3.json` **50 例**：35 正 + 15 负；**47 例有落盘 pcap**（`/tmp/mcp-pcaps/pop3/`），3 例无落盘（t024/t035/t036，创建期拒）；**81 条 field 断言 + 3 条 frame 断言逐条复跑全 OK**；`coverage_gate pop3` 复跑 **32/32 绿、exit 0**；50/50 ID 顺序与本版 §2 一致；顶层键 49 例纯 `{layers}` + 1 例 presence 负例（t035）；层形 49 例 `[ip,tcp,pop3]` + 1 例 `[ip,tcp,tls,pop3]`（t032）。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **前身行号全漂移**：D-POP3-1 的 `registry.go:828`/`strategy_convert.go:788`/`chain_planner_translate.go:1127`/`types.go:6660` 今日为 `:1580`/`:1273`/`:2634`/`:6878`（G-POP3-8）。
2. **TEST_CASES.md 数字过期**：P5 补遗偏差⑥记 t037/t039 frames 偏移 **288/206**，JSON 实际 **396/314**（`84cfbe6` 换真实 README.md 后二次重钉）（G-POP3-7）。
3. **包数公式前身只给单例速算**（"单会话 14 包量级"），本版从 46 例 pcap 反推通用式并**逐例零误差验证**（设计 §3.9/§9.1）。
4. **前身"存量去向初估 34–36 例"过期**：实际落 50 例（文档自身 P5 补遗段已更正，JSON 为准）。
5. **结果产物 pcap 链接全是死链**：`trafficgen/docs/protocol-pcap-test/pop3.md`（tracked）的 47 行 pcap 链接指向 `pop3/` 子目录，该目录**不存在**（`git ls-files` 0 个、磁盘 0 个）。**注**：该产物末次提交 `84cfbe6`（2026-09-17）**晚于**判死提交 `0417be5`（2026-09-13），**不属"过期产物"类**——本项是「**无 pcap 留档 + 死链**」，**不是**「数字未经复跑」；47/47 包数本轮已用 `/tmp/mcp-pcaps/pop3/` 逐例复核**全对**（G-POP3-6）。
6. **`pop.response.data` 的 `show` 为空串**：多行体内容**不可用 field 断言**（PDML 实测），必须走 frames；今日 t006/t012/t020/t030 四例的多行体**零断言**（G-POP3-1）。
7. **边界相邻值零覆盖**：USER=40 / PASS=255 / UID=70 / APOP digest=32 的**合法上界**无例（只有 +1 越界负例）（G-POP3-3）。
8. **响应 512 上界与「参数≤40」未全量校验**：引擎只校验 USER/PASS 长度（G-POP3-3）。
9. **状态机不 enforcement**（架构选择）：非法转移 1/2/5/6 无自动 `-ERR`；t004 断的是"照发"而非"正确拒绝"（G-POP3-2）。
10. **多行响应终止符不校验**（`Multiline=true` 原样发，漏 `.` 不报错）；**头部不点填充**（RFC 无显式支持亦无显式反例）（G-POP3-4）。
11. **`pop3_t032_pop3s_995` 零应用层断言**：TLS 下 `pop.*` 不可解，只断端口与 TLS 记录类型（G-POP3-13）。
12. **`pop3_t046_default_twoflow` 断言偏弱**：不断两流四元组不同（G-POP3-14）。
13. **`pop3_t033_v6` 断言偏弱**：只断 1 条 banner 字段，不断 `ipv6.src/dst`（设计 §4 地址与流层已声明；A′ 可收编）。
14. **未入例的 5 条拒绝分支**（`:105`/`:110`/`:118`/`:129`/`:201`）——今日零用例（§4.5）。
15. **无协议层保活/重试/重连建模**（RFC 1939 无此类机制）；RST 无例（A′）。

### 8.3 逐条去向表（50 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `pop3_t001_default_session` | T1 | **保留** | 形状已合规；已含 `tcp.dstport=110` 基线 + `negotiated` |
| `pop3_t002_user_empty_skipped` | T2 | **保留** | 已含空 Cmd 跳过证据（11 帧） |
| `pop3_t003_apop_login` | T3 | **保留** | 可补摘要长度断言（32 字符） |
| `pop3_t004_user_in_transaction` | T4 | **保留** | 已断"照发"；**不得**改断"正确拒绝"（G-POP3-2） |
| `pop3_t005_stat_empty` | T5 | **保留** | 已含 `description=0 0` |
| `pop3_t006_list_multi` | T6 | **保留** | 多行体断言改 frames（A′） |
| `pop3_t007_list_outofrange` | T7 | **保留** | `-ERR` 台词已断 |
| `pop3_t008_retr_maildrop` | T8 | **保留** | 可补 `description=5 octets` 断言 |
| `pop3_t009_retr_missing` | T9 | **保留** | 台词已断 |
| `pop3_t010_dele` | T10 | **保留** | 四包位已断（9/11/13/15） |
| `pop3_t011_top` | T11 | **保留** | 可补 `pop.request.parameter=1 2` |
| `pop3_t012_uidl` | T12 | **保留** | 多行体断言改 frames（A′） |
| `pop3_t012b_emit_top_no_mailbox_reject` | T12b | **保留** | 锚词 `but Mailbox is nil` 已断 |
| `pop3_t013_dot_stuffing` | T13 | **保留** | 可补 frames 断 `..dotline`（A′） |
| `pop3_t014_user_toolong_reject` | T14 | **保留** | 可补合法上界 40 例（A′） |
| `pop3_t015_pass_toolong_reject` | T15 | **保留** | 可补合法上界 255 例（A′） |
| `pop3_t016_cmd_crlf_reject` | T16 | **保留** | 已断 |
| `pop3_t017_resp_crlf_reject` | T17 | **保留** | 已断 |
| `pop3_t018_uid_toolong_reject` | T18 | **保留** | 可补合法上界 70 例（A′） |
| `pop3_t019_apop_bad_digest_reject` | T19 | **保留** | 可补 32 字符非 hex 例（A′） |
| `pop3_t020_rfc10_sequence` | T20 | **保留** | 多行体断言改 frames（A′） |
| `pop3_t021_capa` | T21 | **保留** | 台词版已声明 |
| `pop3_t022_stls` | T22 | **保留** | 台词版已声明 |
| `pop3_t023_auth` | T23 | **保留** | 台词版已声明 |
| `pop3_t024_mss_reject` | T24 | **保留** | 无落盘（创建期拒）；锚词来自 `complete.go` |
| `pop3_t025_two_retr` | T25 | **保留** | 多事务①已断 |
| `pop3_t026_abort_no_quit` | T26 | **保留** | 多事务②已断 |
| `pop3_t027_keepalive_noop` | T27 | **保留** | 多事务③已断 |
| `pop3_t028_gmail` | T28 | **保留** | 地板线已声明 |
| `pop3_t029_outlook` | T29 | **保留** | 地板线已声明 |
| `pop3_t030_dovecot` | T30 | **保留** | 多行 CAPA 断言改 frames（A′） |
| `pop3_t031_composite` | T31 | **保留** | 复合流已断 |
| `pop3_t032_pop3s_995` | T32 | **保留** | 可补 `tls.app_data` hex（A′，G-POP3-13） |
| `pop3_t033_v6` | T33 | **保留** | 可补 `ipv6.src/dst`（A′） |
| `pop3_t034_bad_ip_reject` | T34 | **保留** | 无落盘；锚词来自框架 ip 层 |
| `pop3_t035_presence_reject` | T35 | **保留** | **presence 负例形状，勿误读为残留** |
| `pop3_t036_static_pinned_reject` | T36 | **保留** | 无落盘；与 t046 成对 |
| `pop3_t037_mime_multi_attach` | T37 | **保留** | frames 偏移 396 已复跑 OK |
| `pop3_t038_empty_body_retr` | T38 | **保留** | frames 偏移 54 已复跑 OK |
| `pop3_t039_attach_only` | T39 | **保留** | frames 偏移 314 已复跑 OK |
| `pop3_t040_pass_auth_failed` | T40 | **保留** | `-ERR` 台词已断 |
| `pop3_t041_unknown_command` | T41 | **保留** | `FOO` → `-ERR` 已断 |
| `pop3_t042_maildrop_no_mailbox_reject` | T42 | **保留** | 与 t012b 成对 |
| `pop3_t043_maildrop_msgnum_range_reject` | T43 | **保留** | 与 t044 分属不同分支 |
| `pop3_t044_top_msgnum_range_reject` | T44 | **保留** | 同上 |
| `pop3_t045_emit_both_exclusive_reject` | T45 | **保留** | 已断 |
| `pop3_t046_default_twoflow` | T46 | **改写** | 补 `tcp.srcport` 断言（12345/12346，G-POP3-14） |
| `pop3_t047_quit_bare` | T47 | **保留** | 最短正例（10 帧） |
| `pop3_t048_list_single` | T48 | **保留** | 与 t006 对称 |
| `pop3_t049_top_zero_lines` | T49 | **保留** | 与 t011 成对 |

无"作废不注原因"：**0 作废**、**0 等价覆盖**（50 例全部保留，其中 1 例标注待改写）。**本协议存量 50/50 顶层零残留**（唯一顶层 `pop3` 键在 t035 是 presence 负例的**判死输入**，不是残留）。

## 9. 覆盖反查门建议断言行（供主线程合后登记 `coverage_gate.py`；本车道不碰该文件）

现有 `check_pop3`（`coverage_gate.py:204-301`，**32 项，本轮复跑 32/32 绿**）已覆盖命令表/`-ERR` 台词/合成/多行/多事务三项/复合流/MIME 双附件/PASS -ERR/validator 四分支/全缺省双流/现网三家。**建议增补**下列断言行（**每条均可从本契约与 cases JSON 直接机读，不需新造事实**）：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['pop3']) == 50` 且 ID 集合 = §2 五十项，顺序一致 | 本契约 §2 |
| 2 | **非负例**顶层键 ⊆ `{layers}`（**49/49，今日已成立**；t035 为负例豁免） | 本契约 §1；设计 §12.1 |
| 3 | 35 正例 `packet_count`（由 §1 公式推出）与落盘 pcap 帧数一致 | 设计 §3.9 公式 |
| 4 | 15 负例 `error_contains` ⊆ 设计 §7 锚词集（A 组 11 + B 组 4 逐条对码） | 设计 §7/§9.2 |
| 5 | **t035 的 `spec_json` 顶层键 == `{layers, pop3}`**（presence 负例形状点名，防被误读为残留） | 本契约 §1 注 |
| 6 | 每正例至少一条断言落在 `pop.*` 或 frames（**t032 与 t046 为已知例外** → 建议显式白名单并注明理由） | 本契约 §3.25/§3.32 |
| 7 | **不得**出现 `pop.response.data` 的 field 断言（`show` 为空串，恒真绿） | 本契约 §1 陷阱 |
| 8 | t036（静态门红）与 t046（全缺省绿）**必须成对存在**（单边存在 = 门语义失去反例/正例） | 设计 §7 N-15 |
| 9 | t043/t044 锚词同为 `out of range` 但 `msg_num` 分别走 `emit_mail_drop`/`emit_top`（两分支各一，**不可合并**） | 本契约 §4.3 |
| 10 | t012b/t042 锚词分别含 `EmitTop=true but Mailbox is nil` / `EmitMailDrop=true but Mailbox is nil`（两分支各一） | 本契约 §4.1 |

**另注意（诚实登记，不主张"今日已过"）**：现有 32 项反查门**全绿**，但**边界相邻值**（USER=40/PASS=255/UID=70/digest=32 合法上界）、**多行体内容断言**（frames）、**响应 512 上界**、**非法转移 #1** 均**不在反查门内**——**反查全绿 ≠ 覆盖全**（G-POP3-1/G-POP3-3/G-POP3-2）。建议第 1/7/8 条优先登记（机读成本最低、防假绿价值最高）。

## 10. 修订记录

- v1.0.0（2026-09-29）：P-PIPE 批次二文档轨 #106 as-built 定稿。**承前身 T-POP3-1…T-POP3-49 的 50 例 ID 集合与断言思路**；形状基线机读实测（§1，**顶层零残留**，t035 presence 负例形状点名）；81 条 field 断言 + 3 条 frame 断言用**校验器同款解析器**逐条复跑**全 OK**；包数公式 `3+[banner]+Σ轮+4` 与 46 例 pcap **逐例零误差**（§1）；**`pop.response.data` 的 `show` 为空串陷阱**（多行体必须走 frames，§1/§3.6）；冲突处按 JSON/实测改正（前身行号漂移、TEST_CASES 288/206→396/314、存量估算 34-36→50、产物死链）；P3 固定动作（§6）；执行建议（§7，含"不得手算包数/偏移"与"不得为多行体新增 field 断言"两条纪律）；存量审计（§8，50 例逐条去向 + 15 条现状矛盾点）；覆盖反查门建议断言行 10 条（§9）。**自审 6 轮，末轮干净**（同设计 §15 口径；机读脚本复核全部计数与断言，抓出并修复 **11 处自伤**——见设计 §15 修订记录。本文件涉及其中 4 处：fields 81、对账两行口径、行为断言 70、§5.2"未处置格"表述）。

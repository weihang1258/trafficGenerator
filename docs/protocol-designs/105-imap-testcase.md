# #105 imap（IMAP4rev1/IMAP4rev2）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨批次二 · as-built 型）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/105-imap-design.md` v1.0.0（D-IMAP-1）
> 旧基线：**无**（本协议从未有过 imap 用例文档；首次成文）
> 机器契约：`trafficgen/test/protocol_pcap/cases/imap.json`（**84 例**，ID/顺序/包数/断言与本版 §2 **逐条一致**，已机读实测）
> 白话一句：**八十四条检查：六十五条看正常收发（问候、登录、列信箱、读信、投递、附件、等待推送、长保活、加密端口、多流），十九条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **84 个唯一语义 ID：65 正 + 19 负**。派生规则：设计 §3 每个编码条款（命令行/三态响应/literal 两侧不对称/MIME 构造/IDLE 六步/流水线双相位）、§5 每个事务与自动派生行为（15 条）、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：

| 项 | 实测 |
|---|---|
| 例数 | **84**（65 正 + 19 负） |
| 用例顶层键 | `{id,proto,summary,spec_json,expect}` ×82 + 加 `strategy_fc` ×2（`t065`/`t078`） |
| `spec_json` 顶层键 | **`{layers}` ×83（唯一键，零游离键）** + `{layers, imap}` ×1（`t064`，**设计 §12-P2 ①点名的判死负例形状**） |
| 层链形状 | `[ip,tcp,imap]` ×82 + `[ip,tcp,tls,imap]` ×2 |
| `imap` 层键 union | `{banner, commands, idle, pipelined_commands, allow_utf8_mailbox}`——**5 键，与 registry Fields 逐键一致** ✓ |
| 正例 `expect` 键集 | `{fields,has_handshake,notes,terminates}` ×55 + 加 `frames` ×8 + 加 `negotiated` ×1（`t001`）+ `{has_handshake,notes,packet_count}` ×1（`t078`） |
| 负例 `expect` 键集 | `{expect_error, error_contains, notes}` ×19（**三键，含 `notes`**——非严格两键，G-IMAP-15） |
| 断言总量 | **137 条 `fields`** + **9 条 `frames`**（8 例带 frames） |
| `packet_count` 键 | **仅 1 例**（`t078`）——其余 64 正例包数**只在结果产物里**（G-IMAP-11） |

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。今日 84 例断言全部**载体无关**（`imap.line`/`imap.tag`/`imap.command`/`imap.response.status` 为 TCP payload 层字段，`tcp.dstport`/`tcp.srcport` 为传输层字段），故双路径天然兼容。

**TSHARK 基线（本机 3.6.14，实测）**：`imap.*` **18 字段**——`imap.isrequest` / `imap.line` / `imap.request` / `imap.request_tag` / `imap.response` / `imap.response_tag` / `imap.request.command` / `imap.response.command` / `imap.response.status` / `imap.tag` / `imap.command` / `imap.request.folder` / `imap.request.command.uid` / `imap.request.username` / `imap.request.password` / `imap.response_in` / `imap.response_to` / `imap.time`。**本版实际用到 5 个**：`imap.line`、`imap.tag`、`imap.command`、`imap.response.status`、`tcp.dstport`。

**两条 tshark 口径坑（实测踩过，须写清）**：

1. **`imap.response.status` 只在 tagged 行上解码**——untagged `*` 行上该字段为空。`t011` notes 逐字记载："untagged 包6 不解 response.status，改断 tagged 包7"；`t038` 同款。**本版全部 `imap.response.status` 断言均落在 tagged 帧**。
2. **裸 `DONE\r\n` 行的 `imap.command` 为空**（RFC 2177 §4：DONE 是续行响应，不是 tagged 命令，故无命令名可解）。三例 IDLE 用例改断 `imap.line == "DONE\r\n"`（`t043`–`t047` notes 逐字记载："tshark imap.command 为空是口径所限，改断 imap.line DONE"）。

**literal 帧的断言口径（实测踩过）**：literal **体帧**（如 `hello`）不含 CRLF，tshark 的 dissector 会把前后帧**拼行重组**，导致 `imap.command` / `imap.line` 出现跨帧伪影——`t009` notes 逐字记载："包10 FETCH 的 hello 前缀是 tshark 重组视图伪影（包8无 CRLF，dissector 拼行），线包纯净 A003 开头，command 照常解码"；`t079` 同款（"包13 SELECT 纯净（tag helloA004 系重组伪影）"）。**故 literal 体帧一律用 `frames` 断言（整帧 offset 54 hex），不用 `imap.*` 字段**（8 例带 frames：`t009`/`t036`/`t042`/`t051`/`t052`/`t079`/`t080`/`t081`，共 9 条 frame 断言）。

**动态字段禁止硬编码**：生成期值（tag 自动编号、MIME boundary）用**锚点断言**或**离线精确断言**——MIME boundary 逐跑漂移（`generateMIMEBoundary` 时间+随机），故三例 MIME 用例的 `{N}` **不钉死**，改由"包 12 首段帧字节"+ 离线 `{N}==len` 精确断言（`TestIMAPMIME_*`）两面覆盖（`t051`/`t080`/`t081` notes 逐字记载）。

**包数约定（实测公式，设计 §9.1）**：见 §2 表（逐例实测回填）。**63/63 非 TLS 正例逐例命中公式**；2 例 TLS 例（`t061`/`t082`）各 20 帧 = imap 层 13 + tls 层 7（公式在 TLS 下无独立推导，G-IMAP-10）。**负例无 `packet_count`**（16 例有 `.neg.pcap`，实测 0 帧；3 例无产物——门位在建任务前，设计 §0 #6）。

**保活/重试/RST 口径**：协议层**无 PING 类心跳**；`NOOP` 是保活手段（`t059`）；IDLE 的 29 分钟服务端超时**立即发出** BYE、不真等（设计 §1 边界⑥）；`keep_idle` 与 `close_after_idle` **字节等价**（G-IMAP-3/G-IMAP-4）；RST 为框架 tcp 层能力，本协议层**零断言**（A′ 补例 G-IMAP-13）；正例恒 FIN 优雅终止。

## 2. 原子用例索引（84 ID = 65 正 + 19 负，顺序为权威）

**顺序 = `cases/imap.json` 数组顺序**（权威）。**包数**由 81 份实测 pcap 逐例 `tcpdump -r | wc -l` 回填，与结果产物 `imap.md` 表格 84/84 一致（机读对账）。

| # | ID | 类型 | 场景 | 依据链（设计 §） | 包数（实测） | 断言要点 |
|---:|---|---|---|---|---:|---|
| 1 | `imap_t001_default_session` | 正 | 三命令默认会话 | §3.1/§3.2 | 16 | 6 field：`tcp.dstport`(p1)、`imap.line`(p4 greeting)、`imap.tag`+`imap.command`(p5 LOGIN)、`imap.tag`+`imap.command`(p10 LOGOUT) |
| 2 | `imap_t002_tag_explicit` | 正 | tag 显式 A001 | §5.3 | 13 | 2 field：`imap.tag`/`imap.command`(p5) |
| 3 | `imap_t003_tag_auto` | 正 | 空 tag 自动递增 | §5.3 | 15 | 2 field：`imap.command`(p5/p7) |
| 4 | `imap_t004_tag_shapes` | 正 | tag 点/线/数字三形 | §5.3 | 17 | 3 field：`imap.tag`(p5 `tag.42`/p7 `X-Custom-1`/p9 `001`) |
| 5 | `imap_t005_empty_cmd_challenge` | 正 | 空 Cmd 跳过命令帧 | §3.1 | 12 | 1 field：`imap.line`(p5 `+ challenge`) |
| 6 | `imap_t006_select_wrong_state` | 正 | 未认证态 SELECT（I-1 台词） | §5.2 | 13 | 2 field：`imap.command`(p5 SELECT)、`imap.response.status`(p6 NO) |
| 7 | `imap_t007_bye_greeting` | 正 | `* BYE` 问候（最短链） | §3.1 | 10 | 1 field：`imap.line`(p4 `* BYE server busy`) |
| 8 | `imap_t008_append_literal` | 正 | 命令侧 literal 上行 | §3.4.1 | 16 | 1 field：`imap.command`(p7 APPEND) |
| 9 | `imap_t009_append_b64_fetch_placeholder` | 正 | B64 源 + 响应 `{0}` 替换 | §3.4.2/§3.4.4 | 21 | 3 field + **1 frame**（p8 = `68 65 6c 6c 6f`） |
| 10 | `imap_t010_pipelined` | 正 | 流水线双相位 | §3.7 | 15 | 2 field：`imap.command`(p5/p6 连续两命令) |
| 11 | `imap_t011_capability` | 正 | CAPABILITY 任意态 | §3.3 | 14 | 4 field：`imap.command`(p5)、`imap.response.status`(p7/p10) |
| 12 | `imap_t012_noop` | 正 | NOOP 任意态 | §3.3 | 13 | 1 field：`imap.command`(p5) |
| 13 | `imap_t013_logout` | 正 | LOGOUT + `* BYE` | §5.2 | 11 | 2 field：`imap.command`(p5)、`imap.line`(p6) |
| 14 | `imap_t014_login_ok` | 正 | LOGIN 成功 | §3.3 | 13 | 2 field：`imap.command`(p5)、`imap.response.status`(p6 OK) |
| 15 | `imap_t015_login_no` | 正 | LOGIN 失败 | §3.3 | 13 | 2 field：`imap.response.status`(p6 NO) |
| 16 | `imap_t016_authenticate` | 正 | AUTHENTICATE 双形 + 取消 | §5.5 #9 | 19 | 2 field：`imap.command`(p5/p7) |
| 17 | `imap_t017_starttls` | 正 | STARTTLS 台词 | §1 边界③ | 13 | 1 field：`imap.command`(p5) |
| 18 | `imap_t018_enable` | 正 | ENABLE IMAP4rev2 | §4 | 16 | 1 field：`imap.command`(p7) |
| 19 | `imap_t019_select_ok` | 正 | SELECT 成功（untagged+tagged） | §5.2 | 16 | 3 field：`imap.command`(p7/p10)、`imap.response.status`(p9 OK) |
| 20 | `imap_t020_select_no` | 正 | SELECT 失败 | §3.3 | 15 | 2 field：`imap.response.status`(p8 NO) |
| 21 | `imap_t021_examine` | 正 | EXAMINE 只读选择 | §4 | 16 | 1 field：`imap.command`(p7) |
| 22 | `imap_t022_create` | 正 | CREATE 信箱 | §4 | 15 | 1 field：`imap.command`(p7) |
| 23 | `imap_t023_delete` | 正 | DELETE 成功 + 失败 | §3.3 | 17 | 3 field：`imap.command`(p7/p9)、`imap.response.status`(p10 NO) |
| 24 | `imap_t024_rename` | 正 | RENAME 信箱 | §4 | 15 | 1 field：`imap.command`(p7) |
| 25 | `imap_t025_subscribe` | 正 | SUBSCRIBE + UNSUBSCRIBE | §4 | 17 | 2 field：`imap.command`(p7/p9) |
| 26 | `imap_t026_list` | 正 | LIST 信箱列表 | §4 | 16 | 1 field：`imap.command`(p7) |
| 27 | `imap_t027_namespace` | 正 | NAMESPACE | §4 | 16 | 1 field：`imap.command`(p7) |
| 28 | `imap_t028_status` | 正 | STATUS 信箱状态 | §4 | 16 | 1 field：`imap.command`(p7) |
| 29 | `imap_t029_append_flags` | 正 | APPEND 带 flags + literal | §3.4.1 | 17 | 1 field：`imap.command`(p7) |
| 30 | `imap_t030_close` | 正 | CLOSE 已选态 | §5.2 | 18 | 1 field：`imap.command`(p10) |
| 31 | `imap_t031_unselect` | 正 | UNSELECT 已选态 | §5.2 | 18 | 1 field：`imap.command`(p10) |
| 32 | `imap_t032_expunge` | 正 | EXPUNGE 已选态 | §5.2 | 19 | 1 field：`imap.command`(p10) |
| 33 | `imap_t033_search` | 正 | SEARCH 非空结果 | §4 | 19 | 1 field：`imap.command`(p10) |
| 34 | `imap_t034_search_empty` | 正 | SEARCH 空结果 | §4 | 19 | 1 field：`imap.command`(p10) |
| 35 | `imap_t035_fetch_flags` | 正 | FETCH FLAGS | §4 | 19 | 1 field：`imap.command`(p10) |
| 36 | `imap_t036_fetch_literal_down` | 正 | 响应侧 literal 三段 | §3.4.2 | 21 | 1 field + **2 frame**（p11 头帧 `{5}`、p12 体 `hello`） |
| 37 | `imap_t037_store` | 正 | STORE ±FLAGS | §4 | 21 | 4 field：`imap.command`(p10/p13)、`imap.response.status`(p12/p14) |
| 38 | `imap_t038_copy` | 正 | COPY 成功 + 失败 | §3.3 | 20 | 4 field：`imap.command`(p10/p12)、`imap.response.status`(p11 OK/p13 NO) |
| 39 | `imap_t039_move_uid` | 正 | MOVE + UID FETCH | §4 | 21 | 4 field：`imap.command`(p10/p12)、`imap.response.status`(p11/p14) |
| 40 | `imap_t040_no_code` | 正 | NO 台词 | §3.3 | 13 | 1 field：`imap.response.status`(p6 NO) |
| 41 | `imap_t041_unknown_bad` | 正 | 未知命令 BAD | §3.3 | 15 | 2 field：`imap.command`(p7 FOO)、`imap.response.status`(p8 BAD) |
| 42 | `imap_t042_rfc8_session` | 正 | RFC 9051 §8 官方示例 | §3.4.2 | 21 | 2 field + **1 frame**（p11 头帧 `2a 20 31 20 46 45 54 43 48`） |
| 43 | `imap_t043_idle_push` | 正 | IDLE 有 push | §3.6 | 23 | 4 field：`imap.command`(p10/p12)、`imap.line`(p15 `DONE\r\n`)、`imap.command`(p17) |
| 44 | `imap_t044_idle_nopush` | 正 | IDLE 无 push | §3.6 | 22 | 4 field：同上（p14 DONE） |
| 45 | `imap_t045_idle_close` | 正 | IDLE timeout `close_after_idle` | §3.6 | 24 | 4 field：同上（p15 DONE） |
| 46 | `imap_t046_idle_keep` | 正 | IDLE timeout `keep_idle` | §3.6 | 24 | 4 field：同上——**与 `t045` 字节等价**（G-IMAP-4） |
| 47 | `imap_t047_idle_none` | 正 | IDLE timeout `none` | §3.6 | 23 | 4 field：同上（无 BYE，p17 LOGOUT） |
| 48 | `imap_t048_condstore` | 正 | CONDSTORE 尾注 | §5.5 #10 | 20 | 3 field：`imap.command`(p10/p14)、`imap.response.status`(p12) |
| 49 | `imap_t049_utf8_on` | 正 | UTF-8 信箱名开 | §1 边界⑦ | 16 | 1 field：`imap.command`(p7 SELECT) |
| 50 | `imap_t050_utf8_off_reject` | **负** | 非 ASCII 信箱名拒绝 | §7 N-1 | —（0 帧） | `error_contains="non-ASCII"` |
| 51 | `imap_t051_mime_multi` | 正 | MIME 多部件 + 双附件（N=6023） | §3.5 | 25 | 1 field + **1 frame**（p12 首段 `From: a@b.c`） |
| 52 | `imap_t052_mime_append_up` | 正 | APPEND MIME 上行（显式 boundary） | §3.5 | 17 | 1 field + **1 frame**（p8 首段 `From: a@b.c`） |
| 53 | `imap_t053_mss_reject` | **负** | MSS 100 < 536 | §7 N-2 | —（0 帧） | `error_contains="out of range [536,65535]"` |
| 54 | `imap_t054_gmail` | 正 | Gmail 现网形 | §4 ⑬ | 13 | 2 field：`imap.line`(p4)、`imap.command`(p5) |
| 55 | `imap_t055_outlook` | 正 | Outlook 现网形 | §4 ⑬ | 13 | 1 field：`imap.line`(p4) |
| 56 | `imap_t056_dovecot` | 正 | Dovecot 现网形 | §4 ⑬ | 16 | 1 field：`imap.command`(p7) |
| 57 | `imap_t057_two_fetch` | 正 | 同连接两 FETCH（多事务） | §5.1 | 22 | 5 field：`imap.command`(p10/p13/p16)、`imap.response.status`(p12/p15) |
| 58 | `imap_t058_abort_no_logout` | 正 | 无 LOGOUT 断线 | §5.1 | 16 | 2 field：`imap.command`(p10)、`imap.response.status`(p12) |
| 59 | `imap_t059_keepalive_noop` | 正 | 三 NOOP 长保活 | §5.1 | 19 | 2 field：`imap.command`(p7/p11) |
| 60 | `imap_t060_composite_a` | 正 | 复合流 A（登录+取改） | §5.1 | 23 | 6 field：`imap.command`(p5/7/10/13/15/17) |
| 61 | `imap_t061_imaps_993` | 正 | IMAPS 993 | §2 | 20 | 1 field：`tcp.dstport`(p1 = 993) |
| 62 | `imap_t062_v6` | 正 | IPv6 承载 | §2 | 13 | 1 field：`imap.command`(p5) |
| 63 | `imap_t063_bad_ip_reject` | **负** | 坏 IP | §7 N-3 | —（0 帧） | `error_contains="invalid IP address: not-an-ip"` |
| 64 | `imap_t064_presence_reject` | **负** | 顶层 `imap` 子映射判死 | §7 N-4 | —（0 帧） | `error_contains="rejects a top-level imap sub-config"` |
| 65 | `imap_t065_static_pinned_reject` | **负** | 静态四元组 + flows>1 | §7 N-5 | —（0 帧） | `error_contains="static"` |
| 66 | `imap_t072_tag_space_reject` | **负** | tag 含空格 | §7 N-6 | —（0 帧） | `error_contains="contains SP/CRLF"` |
| 67 | `imap_t066_tag_toolong_reject` | **负** | tag 超 256 | §7 N-7 | —（0 帧） | `error_contains="Tag length"` |
| 68 | `imap_t067_cmd_crlf_reject` | **负** | cmd 含 CRLF | §7 N-8 | —（0 帧） | `error_contains="contains CRLF"` |
| 69 | `imap_t073_resp_crlf_reject` | **负** | 响应含 CRLF | §7 N-9 | —（0 帧） | `error_contains="split into multiple entries"` |
| 70 | `imap_t068_b64_bad_reject` | **负** | B64 解码失败 | §7 N-10 | —（0 帧） | `error_contains="decode error"` |
| 71 | `imap_t074_literal_mutex_reject` | **负** | literal 两源互斥 | §7 N-11 | —（0 帧） | `error_contains="mutually exclusive"` |
| 72 | `imap_t069_emit_idle_no_idle_reject` | **负** | EmitIDLE 无 IDLE | §7 N-12 | —（0 帧） | `error_contains="EmitIDLE=true but IMAPConfig.IDLE is nil"` |
| 73 | `imap_t075_cancel_range_reject` | **负** | 取消位越界 | §7 N-13 | —（0 帧） | `error_contains="CancelAfterResponses"` |
| 74 | `imap_t076_push_crlf_reject` | **负** | push 含 CRLF | §7 N-14 | —（0 帧） | `error_contains="PushResponses[0] contains CRLF"` |
| 75 | `imap_t070_timeout_bad_reject` | **负** | 超时枚举非法 | §7 N-15 | —（0 帧） | `error_contains="must be one of"` |
| 76 | `imap_t077_donetag_space_reject` | **负** | DoneTag 含空格 | §7 N-16 | —（0 帧） | `error_contains="DoneTag"` |
| 77 | `imap_t071_doneresponse_crlf_reject` | **负** | DoneResponse 含 CRLF | §7 N-17 | —（0 帧） | `error_contains="DoneResponse contains CRLF"` |
| 78 | `imap_t083_mime_mutex_reject` | **负** | MIME 与 literal 互斥 | §7 N-18 | —（0 帧） | `error_contains="MIMEBody is mutually exclusive"` |
| 79 | `imap_t084_responses_cap_reject` | **负** | Responses 超 10000 | §7 N-19 | —（0 帧） | `error_contains="Responses count"` |
| 80 | `imap_t078_default_twoflow` | 正 | 全缺省双流 | §2 | 14 | **`packet_count=14`** + `has_handshake`（**唯一带 packet_count 的正例**） |
| 81 | `imap_t079_composite_b` | 正 | 复合流 B（8 命令，最长链） | §5.1 | 30 | 8 field + **1 frame**（p10 体 `hello`） |
| 82 | `imap_t080_mime_empty_text` | 正 | MIME 空正文 + 双附件（N=5874） | §3.5 | 25 | 1 field + **1 frame**（p12 首段） |
| 83 | `imap_t081_mime_attach_only` | 正 | MIME 纯附件无正文（N=5689） | §3.5 | 24 | 1 field + **1 frame**（p12 首段） |
| 84 | `imap_t082_imaps_chain` | 正 | IMAPS 实链 993 | §2 | 20 | 1 field：`tcp.dstport`(p1 = 993) |

**ID 顺序注（须写清）**：ID 的数字后缀**不等于 JSON 顺序**——JSON 顺序为 §2 表列（`t072` 在 `t066` 之前、`t078` 在 `t079`–`t082` 之前、`t083`/`t084` 在 `t078` 之前）。**JSON 顺序为权威**（需求文档 §7）。

**T-编号对照**：T-编号 ≡ ID 的数字后缀（`T-001` ≡ `imap_t001_default_session`，余同）。**注意**：`t066`–`t077` 与 `t083`/`t084` 的 JSON 顺序**与数字顺序不一致**（JSON 把负例集中排在 `t063`–`t065` 之后、`t078` 之前），这是历史批次插入的结果，**保持稳定即可，不重排**。

## 3. 正例逐项断言契约（65 例；最低断言集，实现期可增不可减）

每例均含 `has_handshake` + `terminates`（`t078` 为 `packet_count` + `has_handshake`）；帧位由设计 §9.1 公式与实测 pcap 双向确认。以下按**簇**展开（同构例合并说明，逐例 ID 在 §2 表）：

### 3.1 tag 簇（`t001`–`t004`，16/13/15/17 帧）

`t002` 显式 tag：`tag:"A001"` → p5 `imap.tag="A001"` + `imap.command="NOOP"`。
`t003` 空 tag：前两条 `cmd` 无 `tag` → 自动 `A001`/`A002`；第三条显式 `A003`。**断言只断 `imap.command`（p5/p7），不断 `imap.tag`**——自动编号的断言面由 `t002`（显式）与 `t001`（p5 `A001`）承担。
`t004` 三形态：p5 `imap.tag="tag.42"`（点）、p7 `"X-Custom-1"`（线）、p9 `"001"`（纯数字）——**RFC 9051 §2.2.1 tag-char 允许 `.` / `-` / 数字**。
`t001` 基线：p4 `imap.line="* OK IMAP ready\r\n"`（greeting，含转义 CRLF）、p5 LOGIN、p10 LOGOUT；**`negotiated=true`** 是本协议**唯一**一例（其余 64 例无此键）。

### 3.2 空 Cmd 簇（`t005`，12 帧）

`commands[0] = {tag:"A001", cmd:"", responses:["+ challenge"]}` → **p5 为响应帧**（`imap.line="+ challenge\r\n"`），**无命令帧**（设计 §3.1：`cmd==""` 跳过命令包）。**包数证据**：12 = 3+4+1(banner)+0(空 cmd 命令帧)+1(响应)+[1+1](LOGOUT 事务)。

### 3.3 状态台词簇（`t006`/`t040`/`t041`/`t007`，13/13/15/10 帧）

**诚实声明（设计 §5.2）**：这四例断的是**"用户声明的状态台词被如实回放"**，**不是"引擎拒绝了非法状态转移"**——planner 不强制 IMAP 状态机（`planner.go:29-33` 逐字）。`t006`（未认证态 SELECT）+ `t040`（同形）覆盖设计 §5.2 的 **I-1**；`t041` 覆盖未知命令 `BAD`；`t007` 覆盖 `* BYE` 拒连问候（**最短链 10 帧**）。
`t006`/`t040` 的 `imap.response.status` 断言落在 **p6（tagged）**——**不是** untagged 行（tshark 口径，§1）。

### 3.4 literal 簇（`t008`/`t009`/`t029`/`t036`/`t042`，16/21/17/21/21 帧）

**命令侧（上行）**：`t008`/`t029` 的 `cmd` 含 `{5}` + `literal_body:"hello"` → 命令帧（p7）后**跟一个体帧**（`hello`，无 CRLF）。
**响应侧（下行）**：`t036` 的 `responses[0]="* 1 FETCH (BODY[] {0})"` + `literal_body:"hello"` → **三段**：p11 头帧（`{0}` **被替换为 `{5}`**，实测字节 `2a 20 31 20 46 45 54 43 48 20 28 42 4f 44 59 5b 5d 20 7b 35 7d 0d 0a 29 0d 0a`）、p12 体帧（`hello`）、p13 收尾 CRLF 帧（`0d 0a`）。
**`t042` 的对照**：`responses[0]="* 1 FETCH (BODY[] {5})"` + 同一 body → **线上同样产出 `{5}`**——证明**响应侧占位值不参与校验**（设计 G-IMAP-5）。`t042` 的 notes 逐字记载："§8 标题+目录已亲验，P5 逐字抄会话原文"（**逐字核对未完成** → G-IMAP-14）。
**`t009` 的双形态**：`commands[1]` 用 `literal_body_b64:"aGVsbG8="`（解码 = `hello`）+ `commands[2]` 的 FETCH 响应占位。**p8 体帧断言**（`68 65 6c 6c 6f`）——不用 `imap.*` 字段（重组伪影，§1）。

### 3.5 流水线簇（`t010`，15 帧）

`pipelined_commands:true` → **两相位**：p5 `A001 NOOP`、p6 `A002 NOOP` **连续**（无响应插入）；响应随后按序发出。**断言**：`imap.command`(p5/p6) 均为 `NOOP`——**这是"两相位"的直接证据**（默认分支下 p6 会是 `A001 OK` 响应）。**默认逐条对照由 `t003` 承担**（notes 逐字）。

### 3.6 认证簇（`t014`/`t015`/`t016`，13/13/19 帧）

`t014` OK / `t015` NO——`imap.response.status`(p6) 各取一值，构成 §3.3 三态中的两态正例。
`t016` **双形 + 取消**：`commands[0]` AUTHENTICATE PLAIN（`responses:["+", "A001 OK …"]`）；`commands[1]` AUTHENTICATE LOGIN（两次 `+` 挑战）+ **`cancel_after_responses:2`** → 第 2 条响应**之后**插入 client `*\r\n` 取消行（设计 §5.5 #9）。**断言**：`imap.command`(p5/p7) 均为 `AUTHENTICATE`。

### 3.7 信箱管理簇（`t019`–`t028`，15–18 帧）

`t019`/`t020` SELECT 成/败；`t021` EXAMINE；`t022`–`t024` CREATE/DELETE/RENAME；`t025` SUBSCRIBE+UNSUBSCRIBE；`t026` LIST；`t027` NAMESPACE；`t028` STATUS。
**两响应事务的帧位（notes 逐字"包位落盘重钉"）**：SELECT 类命令引出 **untagged + tagged 两帧**，故后续业务命令的帧位**后移 1**（如 `t030` 的 CLOSE 落在 **p10** 而非 p9）——**这是本协议帧位断言最容易错的地方**，8 例 notes 逐字记载该重钉。

### 3.8 已选态簇（`t030`–`t039`，18–21 帧）

CLOSE/UNSELECT/EXPUNGE/SEARCH（非空+空）/FETCH FLAGS/STORE/COPY/MOVE+UID FETCH。
`t034` **SEARCH 空结果**：`responses[0]="* SEARCH"`（无参数）——RFC 9051 §6.4.4：空结果**不是失败**（tagged 仍 `OK`），notes 逐字"空非失败，注记"。
`t038` COPY 成功+失败：`imap.response.status`(p11 OK / p13 NO)——notes 逐字"NO 只在 tagged 包13 解码，untagged 包12 不解 status"。
`t039` MOVE+UID：`imap.command`(p12) = `"UID"`——**tshark 把 `UID FETCH` 的命令名解为 `UID`**（不是 `FETCH`），notes 逐字"UID 逐字不断语义"。

### 3.9 IDLE 簇（`t043`–`t047`，22–24 帧）——**本协议最复杂的编排**

六步编排（设计 §3.6）。实测 `t043` 帧序（`tshark -T fields -e tcp.payload`）：

```
p4  greeting        "* OK IMAP ready\r\n"
p5  A001 LOGIN      p6  A001 OK LOGIN completed
p7  A002 SELECT     p8  * 1 EXISTS      p9  A002 OK SELECT completed
p10 A003 IDLE       ← 第1步（命令）
p11 + idling        ← 第2步（续行）
p12 A003 IDLE       ← **第二次 IDLE 轮**（见下）
p13 + idling        ← 第2步
p14 * 37 EXISTS     ← 第3步（push）
p15 DONE            ← 第4步（裸，无 tag）
p16 A004 OK IDLE terminated   ← 第5步
p17 A005 LOGOUT     p18 * BYE   p19 A005 OK LOGOUT completed
```

**关键实测事实（须写清，不得含糊）**：**`emit_idle:true` 产生两次 IDLE 轮**——第 1 轮来自命令循环（`cmd:"IDLE"` + `responses:["+ idling"]`，p10/p11），第 2 轮来自 `emitIDLE` 编排（p12/p13）。用例 notes 逐字记载："emit_idle 重发 IDLE 轮在包12"。
**DONE 断言口径**：`imap.line="DONE\r\n"`（**不是** `imap.command`——裸 DONE 无命令名可解，§1 口径坑②）。
**四形态差异（实测）**：
- `t043`（有 push）23 帧 = p14 有 push；
- `t044`（无 push）22 帧 = 少 1 帧；
- `t045`（`close_after_idle`）24 帧 = p14 push + **p17 `* BYE IDLE timeout`**；
- `t046`（`keep_idle`）24 帧 = **与 `t045` 逐帧 payload 完全一致**（G-IMAP-4）；
- `t047`（`none`）23 帧 = 无 BYE。
**`t045`/`t046` 字节等价是 confirmed 缺口**（设计 G-IMAP-3/G-IMAP-4）——两例**不构成独立原子测试点**，P4 须随 G-IMAP-3 裁定（补实现则自然分离；不解决则合并）。

### 3.10 扩展簇（`t048`/`t049`/`t050`，20/16/负）

`t048` CONDSTORE：`uid_cache_invalidation:true` → 命令响应之后**追加一帧** `* OK [HIGHMODSEQ 1] mailbox cache invalidated\r\n`（设计 §5.5 #10）。实测 p13 为该尾注帧、p14 为 LOGOUT（notes 逐字"UIDCache 尾注包13"）。
`t049`/`t050` UTF-8 成对：`allow_utf8_mailbox:true` + `SELECT INBOX.日本語` 通过（`t049`）；`false` + 同一命令**拒绝**（`t050`，锚词 `non-ASCII`）。**这一对是本协议唯一的"开关正反例"**。

### 3.11 MIME 簇（`t051`/`t052`/`t080`/`t081`，25/17/25/24 帧）

四例覆盖设计 §3.5 的形态矩阵：

| 用例 | MIME 形态 | parts | attachments | text | boundary | 实测 N |
|---|---|---|---|---:|---|---:|
| `t051` | MULTIPART | 1（text/html） | 2（README.md 3783B b64 + b.txt） | 非空 | 自动 | 6023 |
| `t052` | MULTIPART（**上行 APPEND**） | 0 | 1（u.txt，`data` 裸文本） | `"up"` | **显式 `b-159`** | 0（命令侧占位 `{0}` 原样发） |
| `t080` | MULTIPART | 0 | 2（同 `t051`） | **空** | 自动 | 5874 |
| `t081` | MULTIPART | 0 | 1（README.md） | **空** | 自动 | 5689 |

**断言口径（notes 逐字）**：**p11 的 literal 头 `{N}` 不钉死**（boundary 随机后缀 → `{N}` 逐跑漂移）；改由 **p12 首段帧字节**（`46 72 6f 6d 3a 20 61 40 62 2e 63` = `From: a@b.c`）+ **离线 `{N}==len` 精确断言**（`TestIMAPMIME_*`）两面覆盖。
**`t052` 的特殊性**：MIME 体走**命令侧**（上行，p8 体帧，`tcp.len=320`）；`t051`/`t080`/`t081` 走**响应侧**（下行）。
**`t051`/`t080`/`t081` 的 `{N}` 实测值**由 pcap 提取：6023 / 5874 / 5689——**三例均 > 1460 → 各 5 段**（设计 §6 性能层）。
**判死教训（设计 §3.5）**：这三例曾因层配置走 Go JSON 往返而**静默产出 7 包空流**（`IMAPAttachment.Data []byte` 的 base64 语义）；修复 = 层路径改走 `core.ParseIMAPConfigFromMap`。**`t051`/`t052`/`t080`/`t081` 的 `frames` 断言正是这次修复的回归守卫**。

### 3.12 现网厂商簇（`t054`–`t056`，13/13/16 帧）

`t054` Gmail 形（`* OK Gimap ready for requests from 1.2.3.4 abc`）；`t055` Outlook 形；`t056` Dovecot 形（`* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR …] Dovecot ready.`）。
**诚实声明**：三例的问候原文来自现网实录，但 notes 分别标注"gmail 映射：问候原文 openssl 亲验**列 P5**"/"dovecot 映射：三份实录交叉能力集；telnet 亲验**列 P5**"——**逐字核对尚未完成**，且**未抓真实服务器 pcap 做线字节对照** → G-IMAP-14。

### 3.13 多事务/复合簇（`t057`–`t060`/`t079`，22/16/19/23/30 帧）

`t057` 同连接两 FETCH（§3.15①多轮操作）；`t058` **无 LOGOUT 断线**（`terminates=true` 由 tcp 层 FIN 保证——**IMAP 层无 LOGOUT 也照常 FIN**，notes 逐字"§3 多事务②：IMAP 层无 LOGOUT，TCP 照常 FIN"）；`t059` 三 NOOP 长保活（§3.15③）；`t060` 复合流 A（6 命令）；`t079` 复合流 B（**8 命令，30 帧，最长链**）。`t060` 与 `t079` 是设计 §9"双组合流成对"（notes 逐字"与 T-79 双例成对"）。

### 3.14 载体簇（`t061`/`t062`/`t082`，20/13/20 帧）

`t062` IPv6：`ip.src=2001:db8::1` / `ip.dst=2001:db8::2` → 载荷起点 **offset 74**；`imap.command`(p5) 与 IPv4 例**逐字节相同**（协议与地址族解耦）。
`t061`/`t082` IMAPS 993：`[ip,tcp,tls,imap]` 链 → **只断 `tcp.dstport=993`**；实测 20 帧 = imap 层 13 + **tls 层 7**（`t061` 帧 4 = TLSv1.2 ClientHello 161B，帧 5–16 = TLSv1.3 记录）。**imap payload 偏移在 TLS 下未钉**（G-IMAP-10）；两例 notes 逐字"明文不断言 TLS 握手细节"。

### 3.15 多流簇（`t078`，14 帧）

**全缺省三空层** + `strategy_fc:{type:"flows", value:2}` → 两条独立连接。实测：

```
10.0.0.1:12345 → 20.0.0.1:143   7 帧
10.0.0.1:12346 → 20.0.0.1:143   7 帧
```

**断言**：`packet_count=14` + `has_handshake`（**唯一带 packet_count 的正例**）。**多流证据**：`src_port` 逐流自增（12345/12346，`strategy_convert.go:49` 保底），**四元组逐流有别**，未触发静态复制门。
**对照 `t065`**（负例）：显式标量四元组 + `flows=2` + 无动态逃生 → **static 门拒**。**`t065`/`t078` 是本协议唯一的"静态复制门正反例对"**（notes 逐字"与 T-062 对照"——注：这里 T-062 是 notes 作者的笔误，实际对照对象是 `t078`）。

**正例总则**：多响应事务、literal 双侧、IDLE 四形态、MIME 四形态、流水线、多流均为正例形态，只有配置/长度/编码错误进入负例。

## 4. 负例契约

负例必须在 planner/validator/框架门阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。**19 例全部实测 0 帧**（16 例有 `<id>.neg.pcap`，`tcpdump -r | wc -l` 实测 0；3 例无产物——门位在建任务前）。锚词与设计 §7 表一一对应、同序：

| # | ID | 故障输入（机读实测） | JSON `error_contains` | 代码锚词（逐字） | 门位 | 代码行 |
|---:|---|---|---|---|---|---|
| N-1 | `imap_t050_utf8_off_reject` | `allow_utf8_mailbox=false` + `cmd:"SELECT INBOX.日本語"` | `non-ASCII` | `imap: Commands[%d].Cmd %q contains non-ASCII bytes; …` | planner Validate | `planner.go:194` |
| N-2 | `imap_t053_mss_reject` | `tcp.mss=100` | `out of range [536,65535]` | `layers: layer %q field %q = %v invalid: out of range [%d,%d]` | **tcp 层 schema** | `complete.go:325` |
| N-3 | `imap_t063_bad_ip_reject` | `ip.dst:"not-an-ip"` | `invalid IP address: not-an-ip` | `invalid IP address: %s` | **框架 IP 门** | `convert.go:55` |
| N-4 | `imap_t064_presence_reject` | 层链 + **顶层 `imap:{}` 并存** | `rejects a top-level imap sub-config` | `protocol imap rejects a top-level imap sub-config …` | **顶层判死门** | `strategy_convert.go:8893` |
| N-5 | `imap_t065_static_pinned_reject` | 显式标量四元组 + `flows=2` | `static` | `layers pin a static four-tuple but flows > 1: …` | **静态复制门** | `schema/semantic.go:285` |
| N-6 | `imap_t072_tag_space_reject` | `tag:"A 001"` | `contains SP/CRLF` | `imap: Commands[%d].Tag %q contains SP/CRLF (RFC 9051 §2.2.1)` | planner Validate | `planner.go:179` |
| N-7 | `imap_t066_tag_toolong_reject` | `tag` 257 字节 | `Tag length` | `imap: Commands[%d].Tag length %d exceeds max %d …` | planner Validate | `planner.go:174` |
| N-8 | `imap_t067_cmd_crlf_reject` | `cmd:"NOOP\r\nDELETE 1"` | `contains CRLF` | `imap: Commands[%d].Cmd %q contains CRLF (command injection …)` | planner Validate | `planner.go:186` |
| N-9 | `imap_t073_resp_crlf_reject` | `responses[0]:"A001 OK\r\nBAD"` | `split into multiple entries` | `imap: Commands[%d].Responses[%d] contains CRLF; split into multiple entries …` | planner Validate | `planner.go:209` |
| N-10 | `imap_t068_b64_bad_reject` | `literal_body_b64:"!!!not-b64!!!"` | `decode error` | `imap: Commands[%d].LiteralBodyB64 decode error: %v` | planner Validate | `planner.go:226` |
| N-11 | `imap_t074_literal_mutex_reject` | `literal_body` + `literal_body_b64` | `mutually exclusive` | `imap: Commands[%d].LiteralBody and LiteralBodyB64 are mutually exclusive; …` | planner Validate | `planner.go:218` |
| N-12 | `imap_t069_emit_idle_no_idle_reject` | `emit_idle:true` 无 `idle` | `EmitIDLE=true but IMAPConfig.IDLE is nil` | `imap: Commands[%d].EmitIDLE=true but IMAPConfig.IDLE is nil` | planner Validate | `planner.go:250` |
| N-13 | `imap_t075_cancel_range_reject` | `cancel_after_responses:5` > `len(responses)=2` | `CancelAfterResponses` | `imap: Commands[%d].CancelAfterResponses %d > len(Responses) %d …` | planner Validate | `planner.go:256` |
| N-14 | `imap_t076_push_crlf_reject` | `idle.push_responses[0]` 含 CRLF | `PushResponses[0] contains CRLF` | `imap: IDLE.PushResponses[%d] contains CRLF; …` | planner Validate | `planner.go:267` |
| N-15 | `imap_t070_timeout_bad_reject` | `server_timeout_behavior:"explode"` | `must be one of` | `imap: IDLE.ServerTimeoutBehavior %q must be one of: …` | planner Validate | `planner.go:275` |
| N-16 | `imap_t077_donetag_space_reject` | `done_tag:"A 004"` | `DoneTag` | `imap: IDLE.DoneTag %q contains SP/CRLF` | planner Validate | `planner.go:279` |
| N-17 | `imap_t071_doneresponse_crlf_reject` | `done_response:"A004 OK\r\nBAD"` | `DoneResponse contains CRLF` | `imap: IDLE.DoneResponse contains CRLF; must be single-line` | planner Validate | `planner.go:286` |
| N-18 | `imap_t083_mime_mutex_reject` | `literal_body` + `mime_body` | `MIMEBody is mutually exclusive` | `imap: Commands[%d].MIMEBody is mutually exclusive with LiteralBody and LiteralBodyB64` | planner Validate | `planner.go:239` |
| N-19 | `imap_t084_responses_cap_reject` | `responses` 10001 条 | `Responses count` | `imap: Commands[%d].Responses count %d exceeds max %d` | planner Validate | `planner.go:205` |

**锚词口径**：`error_contains` 是**子串**判定；19 例全部命中代码文案（N-1…N-19 中 15 例前缀 `imap: `，N-2/N-3/N-4/N-5 为框架门文案）。

**负例原子性**：每例单一故障注入；单次执行不混注。**N-2/N-3/N-4/N-5 的拒绝位在建任务前**（schema / 框架 IP / 顶层判死 / 静态复制四道门），故**无 `.neg.pcap`**；其余 15 例的拒绝位在 planner `Validate`，**16 例有 neg.pcap 且实测 0 帧**（16 = 19 − 3）。

**`expect` 键形状注**：存量 19 负例 `expect` = `{expect_error, error_contains, notes}`（**含 `notes`**），与严格两键口径不同——P4 收窄时删 19 处 `notes`（G-IMAP-15）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：设计 §7 未入例表 9 条——`SrcIP` 非法（`planner.go:144`，**链路径被框架 ip 门抢占，imap 文案不可达**）/ `DstIP` 非法（`:149`，同）/ `MSS<536`（`:157`，**链路径被 tcp schema 门抢占**）/ **tag 含 `+`（校验未实现）** / `literal_body` 超 100 MB（`:221`）/ `literal_body_b64` 解码后超限（`:229`）/ `mime_body` 构造后超限（`:244`）/ `push_responses` 超 1000（`:263`）/ `done_tag` 超 256（`:282`）。

**未入用例的静默路径（缺陷候选）**：
- `done_tag` 字段**产出零引用**（死配置，G-IMAP-2）；
- `file_source` **不与任何 literal 源做互斥校验**（G-IMAP-6）；
- registry **不校验嵌套键**（`commands`/`idle` 内部 14 键写错即静默忽略，G-IMAP-12）。

## 5. 覆盖与对账

### 5.1 三源回指行

三源 = ① RFC 9051 / RFC 3501 / RFC 2177 / RFC 6855 / RFC 7162 / RFC 2045·2046·2183 / RFC 879（设计 §10）+ ② D-IMAP-1（设计 §11）+ ③ **本机 tshark 3.6.14 字段表与 81 份实测 pcap**（`/tmp/mcp-pcaps/imap/`）→ 84 ID（本契约 §2）。第三源"已确认现网行为"当前 = **抓包级已到**（本仓引擎产出的 81 份 pcap 逐帧核对：137 条 field + 9 条 frame 断言 0 例外），但**真实服务器线字节未取到**（`t054`–`t056` 的问候原文"列 P5"未逐字核对）→ G-IMAP-14。

**84 ID 逐项回指（设计 §9 表全量）**：#1←§3.1/§3.2；#2–#4←§5.3；#5←§3.1；#6←§5.2；#7←§3.1；#8←§3.4.1；#9←§3.4.2/§3.4.4；#10←§3.7；#11–#15←§3.3；#16←§5.5#9；#17←§1 边界③；#18←§4；#19–#28←§5.2/§3.3/§4；#29←§3.4.1；#30–#35←§5.2/§4；#36←§3.4.2；#37–#39←§4；#40–#41←§3.3；#42←§3.4.2；#43–#47←§3.6；#48←§5.5#10；#49–#50←§1 边界⑦；#51–#52←§3.5；#53←§7 N-2；#54–#56←§4⑬；#57–#60←§5.1；#61–#62←§2；#63–#79←§7 N-3…N-19；#80←§2；#81←§5.1；#82–#83←§3.5；#84←§2。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 9051/3501/2177/6855/7162/2045/2046/2183/879 公开语义 + 本仓落码反推 + tshark 3.6.14 字段与 81 份 pcap 实测**，**非纯规范反推**（RFC 条款号未逐条核对原文 → G-IMAP-14）。
- **对账两行**：**要求逻辑点总数 = 153**（八项 8 行 + 子表① 51 格 + 子表② 66 行 + 子表③ 28 行）；**用例覆盖数 = 112**（八项 1 + 子表① 34 + 子表② 56 + 子表③ 21）；**不适用 = 8**（八项 1 + 子表③ 7）；**开放立项 = 33**（八项 6 + 子表① A′ 17 格 + 子表② 10 行）。

  **逐表重数（机读，脚本复算）**：八项 8 = **覆 1** + **立项 6** + **不适用 1**；子表① 51 格 = **覆 34** + **A′ 17**；子表② 66 行 = **覆 56** + **立项 10**（其中 1 项即 G-IMAP-8 内的「MIME SIMPLE 构造路径零正例」，同为 1 行）；子表③ 28 行 = **覆 21** + **不适用 7**。
  **总数校验**：8 + 51 + 66 + 28 = **153**；覆 1+34+56+21 = **112**；不适用 1+0+0+7 = **8**；立项 6+17+10+0 = **33**。112 + 8 + 33 = **153** ✓
  **粒度声明**：行/格粒度每点 1 计；G-IMAP-1…G-IMAP-16 与 19 负例不折进 153。**反查全绿 ≠ 覆盖全**。子表① 的 A′ 17 格**同为一类**（T3 异常终止，1 条立项的 17 个格子）。
  **八项「覆 1」的口径（诚实声明）**：八项矩阵的判据是「该维度**是否有已落码的专项覆盖**」，而非「该维度是否有任何相关用例」——6 项（命令表 / 状态机 / tag 禁 `+` / 错误处理分支 / IDLE 超时语义 / 版本方言）各自都有**明确的未落码或未覆盖面**（缺口列逐项点名），故按缺口表口径计入立项。**不得读成"imap 只有 1/8 覆盖"**——§2 的 84 例才是覆盖度的权威度量。
- **门3 抽查候选**：最复杂用例 = **`imap_t079_composite_b`**（30 帧：3 握手 + 1 greeting + 8 命令 + 12 响应 + 1 literal 体 + CLO… + 4 FIN；交织维度 = 命令(8)×响应数(1–2)×literal(1)）；次复杂 = **`imap_t051_mime_multi`**（25 帧，MIME 5 段跨 MSS + 双附件 + boundary 随机）。**建议门3 抽 `t079` + `t043`**（IDLE 六步编排，含"双 IDLE 轮"这一非直觉帧位）。

### 5.3 包数公式与逐例校验

公式见设计 §9.1。**机读校验**：**63/63 非 TLS 正例逐例命中**（脚本复算，0 例外）；2 例 TLS 例不适用（各 20 帧 = imap 13 + tls 7）。代表例：`t001`=16 ✓、`t007`=10 ✓、`t036`=21 ✓、`t043`=23 ✓、`t079`=30 ✓。

## 6. P3 固定动作（§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接多命令（`t057` 两 FETCH、`t059` 三 NOOP、`t060` 6 命令、`t079` 8 命令） | 已覆 `t057`/`t059`/`t060`/`t079` |
| ② | 非正常结束 | 正常 = `LOGOUT`（`t013`）+ FIN；**无 LOGOUT 的自然结束**（`t058`）；传输异常 = RST | 已覆（`t013`/`t058`）；RST **A′ 立项**（G-IMAP-13，本层零断言） |
| ③ | 长保活 | 协议层无 keepalive 心跳；`NOOP` 轮询（`t059`）；IDLE 等待（`t043`–`t047`） | 已覆 `t059` + `t043`–`t047` |

无空项：① 有已覆例；② 有已覆例 + 1 条 A′ 立项；③ 有 `t059` 与 IDLE 簇。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

> **A′ 与 G-IMAP 的关系（口径）**：A′ 表是**动作清单**（P4 做什么），G-IMAP-1…16 是**缺口台账**（缺什么）；两者**不是一对一**——一条缺口可拆多条 A′ 动作（如 G-IMAP-8 拆 6 条），多条缺口也可归一个动作类。**故 §5.2 对账两行的「开放立项 33」按缺口台账口径计（八项 6 + 子表① 17 格 + 子表② 10 行），不与 A′ 表条数对账**。

| 类 | 内容 | 落点 |
|---|---|---|
| 拒绝分支面 | 10 条未入例分支（tag 含 `+` / 三条 100 MB 上界 / push 超 1000 / done_tag 超长 / 三条链路径不可达文案 / **MIME SIMPLE 路径零正例**） | G-IMAP-8 |
| 端口缺省面 | 删 `dst_port` 断 143 补齐 | G-IMAP-13 |
| banner 面 | banner 自带 CRLF（`HasSuffix` 分支） | 设计 §10.3 行 4 |
| IDLE 面 | `done_response` 缺省分支 | 设计 §10.3 行 52 |
| MIME SIMPLE 面 | `mime_body` 无 parts/attachments 的 SIMPLE 构造路径（**今日零正例**——`t083` 是负例，互斥检查先于构造返回） | 设计 §10.3 行 32 |
| 地址族面 | 异族混写拒绝 | 设计 §8 |
| 非正常结束 | `tcp.rst` 补例 | G-IMAP-13 |
| FileSource 面 | `file_source` literal（**需先补链路径或明确不解决**） | G-IMAP-6 |
| 状态机面 | 未 SELECT 就 FETCH 等 8 条错序台词 | G-IMAP-9 |
| keep_idle 面 | `keep_idle` 与 `close_after_idle` 的行为区分（**需先补实现**） | G-IMAP-3 |
| TLS 偏移面 | TLS record 边界后的 imap 偏移 | G-IMAP-10 |
| packet_count 面 | 为 64 个正例补 `expect.packet_count` | G-IMAP-11 |
| notes 收窄 | 19 负例删 `notes` | G-IMAP-15 |

**B′（框架面）**：顶层游离键通用门（G-IMAP-16，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态（G-IMAP-7，allowlist 无 `imap` 行）/ 嵌套键 allowlist（G-IMAP-12）/ 结果产物重生成 + pcap 留档（G-IMAP-1）。进设计 §14。

### 6.3 3.14 豁免边界审计

**有长连接载体（TCP）→ `sessions[]` 不豁免**：本协议 `imap` 层**无 `sessions[]` 数组**（形态差异已声明）——多会话由**策略级 `flow_control`/`strategy_fc` 多流**承载（`t078` 双流，各 7 帧，`src_port` 逐流自增 12345/12346）。**多流并发**由 `strategy_fc` 承载（本版 84 例中仅 `t078` 用，另 `t065` 为负例）。**单包多载荷** = **不适用**（IMAP 每条命令/响应是一个独立 TCP payload；literal 多段由 tcp 层 MSS 分段承载，非"一帧多消息"形态，如实声明）。

## 7. 实现后执行建议

1. **P4 顺序**：①先裁定三条 confirmed 缺口——G-IMAP-2（`DoneTag` 死配置：删或修注释）、G-IMAP-3/G-IMAP-4（`keep_idle` 等价：补实现或合并 `t046`）、G-IMAP-5（`{N}` 占位校验）；②补 64 例 `expect.packet_count`（G-IMAP-11，值取 §2 表）；③补 A′ 拒绝分支例；④收窄 19 处 `notes`；⑤全量复跑。**本协议无 §1 迁移步骤**（83/84 顶层零残留，第 84 例是判死负例）。
2. **实测顺序**：先 `t007`（最短链 10 帧基线），再 `t001`（greeting + tag + LOGOUT 锚点），再 `t019`/`t030`（**两响应事务的帧位后移**——本协议最易错点），再 `t043`（IDLE 六步 + **双 IDLE 轮**非直觉帧位），再 `t036`（literal 三段 + 收尾 CRLF），再 `t051`（MIME 5 段跨 MSS），最后 `t062`（IPv6 offset 74）、`t061`（TLS 链）、`t078`（多流）。
3. **binary 与 HEAD 同代确认**（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=imap` 全量不是增量）；门2④ 反查绿后进 P6。
4. 任何 RFC 条款号的具体引用须有规范原文证据（G-IMAP-14 纪律）。

## 8. 存量审计（84 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/imap.json` **84 例**：65 正 + 19 负；**83/84 顶层键仅 `{layers}`**（第 84 例 `t064` 为判死负例形状）；层链 `[ip,tcp,imap]` ×82 + `[ip,tcp,tls,imap]` ×2；`imap` 层键 5 个与 registry Fields 逐键一致；**137 条 field 断言 + 9 条 frame 断言逐条对 81 份实测 pcap 复核 0 例外**；**84/84 包数与 pcap 一致**（65 正例含 `t078` 的 14；19 负例 0 帧）；**63/63 非 TLS 正例命中包数公式**。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **`DoneTag` 是死配置（G-IMAP-2）**：产出零引用，`types.go:4973-4974` 注释与实现相反（`planner.go:592-601` 明确记载已废除）。
2. **`keep_idle` ≡ `close_after_idle`（G-IMAP-3）**：两 case 分支体逐字相同，后续都走 FIN；`types.go:4988-4992` 的"不拆 TCP"未落码。
3. **`t045`/`t046` 字节等价（G-IMAP-4）**：pcap 除时间戳外逐帧 payload 完全一致 → **两例不构成独立原子测试点**。
4. **`{N}` 占位值不参与校验（G-IMAP-5）**：命令侧原样发、响应侧被替换 → `t009`/`t036`（写 `{0}`）与 `t042`（写 `{5}`）字节等价。
5. **`file_source` 链路径不可用且无互斥校验（G-IMAP-6）**。
6. **业务字段动态全关（G-IMAP-7）**：allowlist 无 `imap` 行。
7. **状态机维度几乎零覆盖（G-IMAP-9）**：I-1…I-10 十条非法转移中仅 I-1/I-7 有落点；`t006`/`t040` 断的是"NO 台词被回放"而非"引擎拒绝"。
8. **TLS 链下 imap 偏移未钉（G-IMAP-10）**：`t061`/`t082` 零 `imap.*` 断言。
9. **包数无机器可读断言（G-IMAP-11）**：仅 `t078` 一例带 `packet_count`。
10. **嵌套键无 registry 校验面（G-IMAP-12）**：`commands`/`idle` 内部 14 键写错即静默忽略。
11. **`t054`–`t056` 的现网问候原文"列 P5"未逐字核对（G-IMAP-14）**；未抓真实服务器 pcap。
12. **19 负例 `expect` 含 `notes`（G-IMAP-15）**：与严格两键口径不符。
13. **顶层游离键无通用门（G-IMAP-16）**：不建假绿负例。
14. **结果产物过期登记不适用，但有独立事实（G-IMAP-1）**：`trafficgen/docs/protocol-pcap-test/imap.md`（**tracked**）写 "Cases: 84 — pass 84, fail 0, error 0"，末次提交 `793dfee`（**2026-09-19**）**晚于**判死提交 `0417be5`（2026-09-13）→ **不满足"过期"判定条件**，如实登记为**不适用**。**但**：`trafficgen/docs/protocol-pcap-test/imap/` **目录不存在（0 个 pcap）**——表格里 81 个 `[pcap](imap/<id>.pcap)` 链接全部指向不存在路径，故「84/84 pass」**未经今日复跑证实 + 无 pcap 留档**；本车道未跑该套件，不以任何形式引用该产物。**旁证（不得读成"已复跑"）**：本车道只读核验 `/tmp/mcp-pcaps/imap/` 的 81 份 pcap（**非 tracked**），仅证明断言与既有 pcap 自洽。归属**代码阶段**（P5 重跑套件后重生成 + 补 pcap 目录）。

### 8.3 逐条去向表（84 行）

**结论**：**84/84 全部保留**（0 作废、0 改写 ID、0 等价覆盖），其中 **3 例待 P4 裁定可能合并**（`t045`/`t046` 随 G-IMAP-3；`t083` 随 G-IMAP-5 若加校验则 `t036`/`t042` 需重钉）。

| 存量 id | 去向 | P4 动作 |
|---|---|---|
| `t001`–`t004` | 保留 | 可补 `imap.request.*` 字段（今日零使用） |
| `t005` | 保留 | — |
| `t006`/`t040` | 保留 | **notes 须改口径**：明确写"台词回放，非引擎拒绝"（G-IMAP-9） |
| `t007` | 保留 | — |
| `t008`/`t009`/`t029` | 保留 | 随 G-IMAP-5 裁定（若加命令侧 `{N}` 校验则需重钉） |
| `t010` | 保留 | — |
| `t011`–`t028` | 保留 | 可补 `imap.response.status` 收窄 |
| `t030`–`t035` | 保留 | — |
| `t036` | 保留 | 随 G-IMAP-5 裁定 |
| `t037`–`t041` | 保留 | — |
| `t042` | 保留 | **notes 须补"§8 逐字核对未完成"**（G-IMAP-14）；随 G-IMAP-5 |
| `t043`/`t044`/`t047` | 保留 | **notes 须补"双 IDLE 轮"事实说明**（今日 notes 只说"emit_idle 重发 IDLE 轮在包12"，未解释两次 IDLE 轮的来源） |
| `t045`/`t046` | 保留（**待裁定**） | 随 G-IMAP-3/G-IMAP-4：补实现则分离；不解决则**合并为一例** |
| `t048` | 保留 | — |
| `t049`/`t050` | 保留 | — |
| `t051`/`t052` | 保留 | — |
| `t053` | 保留 | notes 已准确（"锚词 tcp 层 V9 门字面"——实测确为 tcp 层 schema 门 `complete.go:325`）；**无需改** |
| `t054`–`t056` | 保留 | **notes 须补"逐字核对未完成"**（G-IMAP-14） |
| `t057`–`t060` | 保留 | — |
| `t061`/`t062` | 保留 | `t062` 可补 `ipv6.src/dst` 字段 |
| `t063` | 保留 | — |
| `t064` | 保留（**判死负例，刻意保留**） | — |
| `t065` | 保留 | **notes 的"与 T-062 对照"是笔误**（对照对象应为 `t078`），须改 |
| `t066`–`t077` | 保留 | **删 `notes`**（G-IMAP-15） |
| `t078` | 保留 | **唯一带 `packet_count` 的正例**，作为 G-IMAP-11 的补齐模板 |
| `t079` | 保留 | — |
| `t080`/`t081` | 保留 | — |
| `t082` | 保留 | — |
| `t083`/`t084` | 保留 | **删 `notes`**（G-IMAP-15） |

无"作废不注原因"：0 作废，0 等价覆盖（84 例全部保留；`t045`/`t046` 的潜在合并待 G-IMAP-3 裁定）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

建议在主线程合入后，于 `coverage_gate.py` 的 imap 段登记下列断言（**每条均可从本契约与 cases JSON 直接机读，不需新造事实**）：

| # | 建议断言 | 依据 | 今日状态 |
|---:|---|---|---|
| 1 | `len(cases['imap']) == 84` 且 ID 集合 = §2 八十四项，顺序一致 | 本契约 §2 | **绿**（机读实测 84/84 顺序一致） |
| 2 | 非负例例数 == 65 且每例 `spec_json` 顶层键 ⊆ `{layers}` | 本契约 §1；设计 §12.1 | **绿**（83/84 顶层仅 `{layers}`；第 84 例是负例） |
| 3 | 非负例顶层键计数 == 0 | 设计 §12.1 | **绿**（今日已成立） |
| 4 | 65 正例 `packet_count` == §2 表值 | 设计 §9.1 | **红**（仅 1/65 例有该键 → G-IMAP-11） |
| 5 | 19 负例 `expect` 键 == `{expect_error, error_contains}` | 本契约 §4 | **红**（19/19 含 `notes` → G-IMAP-15） |
| 6 | 负例 `error_contains` ∈ 代码锚词集（19 条字面值） | 设计 §7 | **绿**（19/19 逐字命中） |
| 7 | 每正例至少一条断言落在 `imap.*` 或 `tcp.dstport` | 本契约 §3 | **绿** |
| 8 | 8 例带 `frames` 的用例，其 `offset` ∈ `{54, 74}` 且 hex 与 pcap 一致 | 本契约 §3.4/§3.9/§3.11 | **绿**（9/9 条 frame 对 pcap 复核 OK） |
| 9 | `imap` 层键 ⊆ registry `Fields`（5 键） | 设计 §11.3 | **绿**（union 恰为 5 键） |
| 10 | `t045` 与 `t046` 的 payload 集合不相等（**原子性**） | 本契约 §3.9 | **红**（实测逐帧相同 → G-IMAP-4） |

**红项如实标红**（第 4、5、10 行），**不申报"今日已过"**。

**另注意**：`trafficgen/docs/protocol-pcap-test/imap.md`（**tracked**）写 "Cases: 84 — pass 84, fail 0, error 0"，末次提交 `793dfee`（**2026-09-19**）**晚于**判死提交 `0417be5`（2026-09-13）——**不满足任务书"产物过期"判定条件**（如实登记为不适用）。**但** `trafficgen/docs/protocol-pcap-test/imap/` **目录不存在（0 个 pcap）**，表格里 81 个链接全部悬空，故该 84/84 **未经今日复跑证实 + 无 pcap 留档**（G-IMAP-1），**不得作为"今日已复跑"依据**；本车道未跑该套件。

## 10. 修订记录

- v1.0.0（2026-09-29）：P-PIPE #105 文档轨批次二 · **as-built 型首次成文**（本协议**无旧稿**）。内容：§1 形状基线机读实测 + **两条 tshark 口径坑**（`imap.response.status` 仅 tagged 行解码；裸 DONE 无 `imap.command`）+ **literal 帧重组伪影**口径；§2 **84 ID 全表**（ID/类型/场景/依据链/包数/断言要点）；§3 正例 15 簇逐簇断言契约（含 **IDLE 六步的"双 IDLE 轮"实测帧序**、literal 双侧不对称、MIME 四形态矩阵）；§4 **19 负例锚词表**（含门位与代码行）+ 未入例 9 条；§5 三源回指 + 对账两行（**153/112/8/33**）+ 包数公式校验（63/63）；§6 P3 固定动作（§3.15 三项 + A′/B′ 两分类 + 3.14 豁免审计）；§7 执行建议（含实测顺序与**两响应事务帧位后移**这一最易错点）；§8 存量审计（**84/84 保留**，含 3 例待裁定的 P4 动作逐条列明）；§9 **10 条覆盖反查门建议断言行**（**3 条红项如实标红**）。
  **自审 3 轮，末轮干净**（机读：84 例 ID/顺序 84/84 一致；83+1 顶层键分布；82+2 层链形状；84/84 包数对 pcap；137 field + 9 frame 断言 0 例外；63/63 公式命中；19 锚词逐字；10 条反查门断言逐条给今日状态）。

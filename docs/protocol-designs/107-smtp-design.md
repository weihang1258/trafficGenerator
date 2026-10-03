# #107 smtp（SMTP · 简单邮件传输协议，RFC 5321 文本协议 TCP 25/587/465）设计契约

> 版本：v1.0.0（批次二 as-built 文档轨；修订记录见 §15）
> 日期：2026-09-29
> 车道：文档轨（#107 smtp）
> 规范基线：① **RFC 5321**（SMTP：命令/应答模型、状态机、DATA 阶段、行终止）；② **RFC 5322**（Internet Message Format：头/体）；③ **RFC 2045**（MIME：base64、Content-Transfer-Encoding）；④ **RFC 2046 §5.1.1/§5.1.4**（multipart/mixed、multipart/alternative、boundary 规则）；⑤ **RFC 2183**（Content-Disposition: attachment）；⑥ **RFC 4954**（AUTH 扩展）；⑦ **RFC 3207**（STARTTLS）；⑧ **RFC 1870**（SIZE）；⑨ **RFC 6152**（8BITMIME）；⑩ **RFC 879**（MSS 下限 536）；⑪ 本机 tshark 3.6.14 `smtp.*` 字段表（**25 字段**实测）与 `/tmp/mcp-pcaps/smtp/` **40 例实测 pcap**（37 正 + 3 负；包数与帧字节的唯一权威）；⑫ 本仓库落码（`internal/protocol/smtp/` 三文件 + 接线，§11）；⑬ 存量用例 `trafficgen/test/protocol_pcap/cases/smtp.json`（**43 例，权威**）。
> 白话一句：**SMTP 是"邮局窗口对话"——服务器先报一句问候（220），客户端报名字（HELO/EHLO）、报寄件人（MAIL FROM）、报收件人（RCPT TO）、说"我要写信了"（DATA），收到 354 后把信连同结尾的单独一行"."一起发出去，收到 250 表示投递成功，最后 QUIT 挂断。本生成器不判断"这句台词合不合规"，只按配置逐字回放。**

## 1. 范围、profile 与实现状态边界

本版定义 **SMTP（RFC 5321 会话层文本协议）承载于 TCP** 的流量生成：TCP 三次握手 → 服务端 220 问候（banner）→ 逐条命令/应答对（`dialog[]`）→ DATA 阶段（用户手写正文或声明式 `email` 自动构造 MIME 正文）→ TCP 四次挥手。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `smtp_tcp_v1`（主） | TCP，默认 dst_port 25 | 全 13 命令 + 14 应答码 + 声明式 MIME 邮件 | 真实服务器语义（邮箱是否存在、是否要认证） |
| `smtp_submission_v1` | 同上，仅 dst_port 587 | 同上 | 真 STARTTLS/AUTH 协商（§3.7 诚实边界） |
| `smtp_smtps_v1` | 同上，仅 dst_port 465 | 同上（**明文链，不套 tls 层**） | 隐式 TLS 握手（§3.7） |
| `smtp_ipv6_v1` | 同上，仅外层 IPv6 | 同上 | 从 IPv4 fixture 推导 IPv6 地址 |

显式边界（"不实现、不声称、不许静默转换"）：① **不实现 SMTP 状态机**——planner 逐字回放 `dialog[]`，不校验"未 MAIL 就 RCPT"这类非法转移（`planner.go:22-27` 明写；§5 诚实声明）；② **不实现真实 STARTTLS/AUTH**——台词版：`STARTTLS` 命令 + `220 Ready to start TLS` 应答是普通文本对，**不升级 TLS、不产 ClientHello**（§3.7）；③ **不实现真实认证**——`AUTH LOGIN` 三步（334/334/235）是文本回放，凭据是 base64 字面量（§3.7）；④ **不实现真实 dot-stuffing 的手写路径**——用户手写正文时点号转义由用户负责（`planner.go:33-35`）；**声明式 `email` 路径已实现自动 dot-stuffing**（`mime.go:297`）；⑤ 不实现 SMTP 扩展协商的真实语义（EHLO 多行能力表是文本回放）；⑥ 不实现 DKIM/SPF/DMARC、不实现 BDAT/CHUNKING（RFC 3030）、不实现 PIPELINING 的批量语义；⑦ **不声称**本生成器产出的流可被真实 MTA 接受——它是流量生成器，不是 MTA。

**实现状态（2026-09-29 实测）**：`smtp` 层已注册（`layers/registry.go:1563`，`CategoryTerminal`，`DependsOn ["tcp"]`，`OptionalOn ["tls"]`，`FieldContract {"tcp.dst_port": "25"}`，**Fields 3 键**：`banner`/`dialog`/`email`）；生成器 + planner + MIME 构造已落码（`internal/protocol/smtp/` 三非测试文件 928 行 = `planner.go` 415 + `mime.go` 357 + `layer_gen.go` 156）；**85 个 `Test*` 函数**（`planner_test.go` 22 + `planner_mime_test.go` 20 + `planner_testpoints_test.go` 43，`grep -c` 实测）；`allowedProtocols["smtp"]=true`（`protocols.go:55`）；层内 translate 已接线（`chain_planner_translate.go:2650`）；缺省目的端口 25 由 registry FieldContract 承接；43 语义用例已落 `cases/smtp.json`，`/tmp/mcp-pcaps/smtp/` **40 个 pcap 在案**（37 正 + 3 负；**另 3 例负例无任何 pcap 留档**，§14 G-SMTP-7）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`/`tcp.srcport`/`tcp.flags`、`smtp.req.command`/`smtp.req.parameter`/`smtp.response.code`、`ipv6.version`、offset 54/190 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, smtp]`（引擎自动补 `ip`；最小链 `[tcp, smtp]`）。SMTP 报文是 TCP payload 的应用层文本字节流，**由 tcp 层负责握手、seq/ack、MSS 分段与挥手**。

端口：SMTP 默认 **TCP 25**（RFC 5321 §3.1）；提交端口 **587**（RFC 6409）、SMTPS **465**（RFC 8314）同为合法。缺省由 registry `FieldContract{"tcp.dst_port": "25"}` 补齐（用户显式非标准端口优先，不强制）——存量 `smtp_t013_port_587` / `smtp_t014_port_465` 即显式端口例。

固定偏移：无 VLAN/IP options/TCP options 时，**每帧 SMTP 载荷起点为 IPv4 offset 54**（14+20+20）、**IPv6 offset 74**（14+40+20）。MSS 分段后的第 2 段起仍是 offset 54（同帧结构）；`smtp_t033_email_mixed_multi` 帧 13 的 `offset 190` 是**同一帧内正文偏移**（头区之后），不是帧头偏移（§3.6 注）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 25}},
    {"smtp": {"dialog": [
      {"cmd": "HELO client.example.org", "response": "250 mail.example.org"},
      {"cmd": "QUIT", "response": "221 2.0.0 Bye"}
    ]}}
  ]
}
```

声明式邮件样例（`email` 与 `dialog` 并存；**`dialog` 内不得再写正文 Cmd**，否则正文重复）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 25}},
    {"smtp": {
      "email": {"headers": ["From: a@b.c", "Subject: T"], "text_body": "see attach",
                "attachments": [{"filename": "a.bin", "data_b64": "AAEC"}]},
      "dialog": [
        {"cmd": "HELO x", "response": "250 y"},
        {"cmd": "MAIL FROM:<a@b.c>", "response": "250 Ok"},
        {"cmd": "RCPT TO:<d@e.f>", "response": "250 Ok"},
        {"cmd": "DATA", "response": "354 End data with <CR><LF>.<CR><LF>"},
        {"cmd": "QUIT", "response": "221 Bye"}
      ]
    }}
  ]
}
```

多流样例（数量走**用例级** `strategy_fc`，不是 `spec_json` 内的键；存量 `smtp_t024_default_twoflow` 即此形）：

```json
{
  "spec_json": {
    "layers": [{"ip": {}}, {"tcp": {}}, {"smtp": {}}]
  },
  "strategy_fc": {"type": "flows", "value": 2}
}
```

## 3. 线格式编码（按代码与实测钉）

### 3.1 行模型（RFC 5321 §2.3）

SMTP 全部载荷是 **CRLF（`\r\n`）终止的文本行**。planner 对每条 `Cmd` 与 `Response` **无条件追加 `\r\n`**（`planner.go:289` / `:304`）：

| 元素 | 线形态 | 代码 |
|---|---|---|
| 命令 | `<Cmd 原文>` + `\r\n` | `planner.go:289` |
| 应答 | `<Response 原文>` + `\r\n` | `planner.go:304` |
| banner | `<Banner 原文>` + `\r\n` | `planner.go:250` |
| 声明式正文 | `buildSMTPEmailBody()` 全量字节（**已含终止符 `.\r\n`**，不再追加） | `mime.go:51` |
| 正文后的自动应答 | `250 2.0.0 Ok: queued as 1` + `\r\n` | `planner.go:321` |

**多行应答**（EHLO 能力表）：用户把整段作为**单个 `Response` 字符串**给出，内嵌 `\r\n` 原样写出，planner 只在末尾追加一个 `\r\n`（`planner.go:296-309`）。实测 `smtp_t003_ehlo_multiline` 帧 6 解出 `250-mail.example.org` / `250-SIZE 10240000` / `250 HELP` 三行——**`250-` 续行与 `250 ` 末行的区别由用户原文自带，planner 不做行结构解析**（RFC 5321 §4.2.1 的续行语义是用户责任）。

**CRLF 边界**：planner 不校验用户原文是否已含 `\r\n`——含了就双写。存量 43 例中 `Cmd` 内嵌 `\r\n` 的 5 例（`smtp_t004_multi_rcpt`/`smtp_t005_rset`/`smtp_t037_two_mails`/`smtp_t038_abort_no_quit`/`smtp_t040_composite_auth_rset_twomail`）均为**正文 Cmd 结尾 `\r\n.`** 的合法用法（§3.5）。

### 3.2 DATA 阶段与终止符（RFC 5321 §4.1.1.4）

DATA 阶段的语义：客户端发 `DATA` → 服务端回 `354` → 客户端发正文 → 客户端发**单独一行的 `.`** → 服务端回 `250`。

**手写路径**（`Email == nil`）：用户把正文写成一条 `Cmd`，**以 `\r\n.` 结尾**；planner 追加的 `\r\n` 补完 `\r\n.\r\n` 终止符（`planner.go:342-357` 的 `defaultDialog` 即此形）。**dot-stuffing（§4.5.2）由用户负责**（`planner.go:33-35` 明写）。

**声明式路径**（`Email != nil`）：planner 在 `DATA` 命令的 `354` 应答**之后**注入自动构造的正文帧 + 自动 `250` 应答帧（`planner.go:319-323`，与 `layer_gen.go:110-117` 同款）；`mime.go` 内**已实现自动 dot-stuffing**（`dotStuff`，`mime.go:297`：以 `.` 开头的行前置一个 `.`），并已写终止符 `.\r\n`（`mime.go:101`）。

**诚实边界**：自动 dot-stuffing **今日无覆盖用例**（存量 9 个 email 例的 `text_body` 无一以 `.` 开头，机读实测）→ A′ 立项（G-SMTP-4）。

### 3.3 banner（220 问候）

`banner` 缺省为空时**自动生成** `220 <DstIP> ESMTP trafficgen`（`planner.go:241-244`，与 `layer_gen.go:82-84` 同款）。banner **恒发**——RFC 5321 §3.1 要求握手后第一条服务端载荷是 220 问候，缺了不成有效会话（`planner.go:245-248` 明写）。

实测（`smtp-basic-session` 帧 4，offset 54）：`32 32 30 20 32 30 2e 30 2e 30 2e 31 20 45 53 4d 54 50 20 74 72 61 66 66 69 63` = `"220 20.0.0.1 ESMTP trafficgen"`——**DstIP 从 spec 取，不是常量**。

显式 banner 3 例（现网形）：`220 mx.example.org ESMTP Postfix`（`smtp_t016_postfix_banner`）/ `220 smtp.gmail.com ESMTP - gsmtp`（`smtp_t041_gmail_banner`）/ `220 EXCH01.example.org Microsoft ESMTP MAIL Service ready`（`smtp_t042_exchange_banner`）。

### 3.4 命令与应答码表（本版回放面）

**13 命令**（存量实测出现，RFC 5321 §4.1）：`HELO`、`EHLO`、`MAIL`、`RCPT`、`DATA`、`RSET`、`NOOP`、`VRFY`、`EXPN`、`TURN`、`AUTH`（RFC 4954）、`STARTTLS`（RFC 3207）、`QUIT`。

**14 应答码**（存量实测出现）：

| 码 | 语义（RFC 5321 §4.2.3 / §4.3） | 落点 |
|---|---|---|
| 220 | 服务就绪（banner / STARTTLS 就绪） | 全正例 banner；`smtp_t018` 帧 8 |
| 221 | 关闭传输通道（QUIT 应答） | `smtp-basic-session` 帧 16 等 |
| 235 | 认证成功（RFC 4954 §6） | `smtp_t040` |
| 250 | 请求动作完成 | 主应答 |
| 334 | 服务器挑战（AUTH 中间态） | `smtp_t017` / `smtp_t031` / `smtp_t040` |
| 354 | 开始邮件输入（DATA 应答） | 全部 DATA 例 |
| 421 | 服务不可用，关闭通道（**4xx 瞬态**） | `smtp_t029_fail_421_unavail` |
| 452 | 系统存储不足（4xx） | `smtp_t028_fail_452_storage` |
| 502 | 命令未实现（**TURN 应答**） | `smtp_t023_turn` |
| 503 | 命令顺序错（5xx） | `smtp_t030_fail_503_sequence` |
| 530 | 需先认证（5xx） | `smtp_t025_fail_530_auth` |
| 535 | 认证失败（5xx，RFC 4954 §6） | `smtp_t031_fail_535_authfail` |
| 550 | 邮箱不可用（5xx） | `smtp_t026_fail_550_mailbox` |
| 554 | 事务失败（5xx） | `smtp_t027_fail_554_toolarge` |

**回放语义（C 类边界，必须写清）**：上述 7 个失败码是**用户写在 `response` 里的台词**，生成器照发，**不校验引擎是否真的拦截**。覆盖反查门口径同此（`coverage_gate.py:14-16` 明写"失败码台词版也算"）。**不声称**真实 MTA 会给出同样的码。

### 3.5 命令/应答对与方向推断（`planner.go:280-310`）

每条 `dialog[]` 元素产出至多两帧，顺序固定为 **Cmd 帧 → Response 帧**：

| 情形 | 产出 | 代码 |
|---|---|---|
| `Cmd` 非空 | 一帧，方向 = `Direction`（缺省 `"up"`） | `planner.go:284-295` |
| `Response` 非空 | 一帧，方向 = `Direction`（缺省 `"down"`） | `planner.go:299-310` |
| `Cmd` 为空 | 跳过命令帧（建模"纯服务端轮次"） | `planner.go:284` |
| `Response` 为空 | 跳过应答帧（建模"纯客户端轮次"，如正文本身） | `planner.go:299` |
| `Direction == "down"` 且 `Cmd` 非空 | Cmd **走下行** | `planner.go:290-292` |
| `Direction == "up"` 且 `Response` 非空 | Response **走上行** | `planner.go:305-307` |

**方向决定源端口与序列空间**：上行帧 `srcPort=spec.SrcPort`（源 IP 同），下行帧 `srcPort=spec.DstPort`；每帧推进**本方向**的序列号（`emitData` 返回值分别回写 `clientSeq`/`serverSeq`，`planner.go:291-308`）。

`Direction` 覆盖例：`smtp_t036_direction_override` 中 `{"cmd": "NOOP", "response": "", "direction": "down"}` → 帧 7 走**下行**（源端口 25）。该例的 field 断言只有 `tcp.srcport=25`，**不断 `smtp.req.command`**——tshark 不把下行帧解成请求（§9 断言边界）。

### 3.6 声明式邮件正文（MIME 构造，`mime.go`）

`buildSMTPEmailBody`（`mime.go:51`）按 `SMTPEmail` 字段决定结构，**四形态 + 两特例**：

| 形态 | 触发条件 | 头部 | 判定代码 |
|---|---|---|---|
| **text-only**（非 MIME） | 有 `text_body`、无 `html_body`、无附件 | 仅用户 `headers`，**不发 MIME-Version/Content-Type** | `mime.go:58`（`isMIME=false`）+ `:135-137` |
| **html-only**（单体） | 有 `html_body`、无 `text_body`、无附件 | `MIME-Version: 1.0` + `Content-Type: text/html; charset=UTF-8` | `mime.go:70` + `:75` + `:133` |
| **alternative**（双体） | `text_body` 与 `html_body` 均有、无附件 | `MIME-Version` + `Content-Type: multipart/alternative; boundary="…"` | `mime.go:70` + `:116` + `:126-128` |
| **mixed**（附件） | `len(attachments) > 0`（**压过以上全部**） | `MIME-Version` + `Content-Type: multipart/mixed; boundary="…"` | `mime.go:56-58` + `:70` + `:113` + `:141` |

**mixed 的首体块**（`mime.go:144-156`）：`text+html` → 嵌套 `multipart/alternative`（**边界 = 外层边界 + `_ALT`**，`altBoundaryFor`，`mime.go:280`）；仅 text → `text/plain` 块；仅 html → `text/html` 块；**都无 → 首体块跳过，只发附件块**（仍合法 multipart/mixed，`smtp_t035_email_attach_only` 即此格）。

**边界（boundary）**：用户给 `boundary` 用之（`resolveSMTPBoundary`，`mime.go:269`）；缺省为**确定性常量** `----=_SMTP_BOUND_0001`（`mime.go:26`，嵌套用 `----=_SMTP_ALT_0001`，`mime.go:31`）——**固定而非随机**，保证 pcap 可复现。

**附件块**（`buildAttachmentPart`，`mime.go:227`）：`Content-Type`（缺省 `application/octet-stream`）+ `Content-Transfer-Encoding: base64` + `Content-Disposition: attachment; filename="<Filename>"`（RFC 2183）+ 空行 + base64 体。base64 按 **76 字符/行**折行（`base64Wrap`，`mime.go:250`，RFC 2045 §6.8）。`data_b64` 给出时**逐字原样写出，不解码不重编码**（`mime.go:239-241`）。

**头/体分隔**：用户 `headers` 逐条 + `\r\n`，MIME 头按需追加，然后一个空行（`\r\n`）分隔头与体（`mime.go:80`，RFC 5322 §3.6）。

**正文尾部**：正文若非空且不以 `\r\n` 结尾，补一个 `\r\n`，再写 `.\r\n`（`mime.go:93-101`）。

**实测（`smtp_t033_email_mixed_multi` 帧 13，offset 54 起）**：`46 72 6f 6d 3a 20 61 40 62 2e` = `"From: a@b."`；同一帧 `offset 190` 起 `43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 74 65 78 74 2f 70 6c 61 69 6e` = `"Content-Type: text/plain"`——**offset 190 是正文内偏移**（头区 `From: a@b.c\r\nSubject: T\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="----=_SMTP_BOUND_0001"\r\n\r\n--<boundary>\r\n` 之后），不是帧头偏移。

### 3.7 ESMTP 扩展面（现网常用，§4 业务层）

| 扩展 | RFC | 本版实现 | 落点 |
|---|---|---|---|
| **EHLO 多行能力表** | RFC 5321 §4.1.1.1 | 文本回放（用户原文，含 `250-` 续行） | `smtp_t003_ehlo_multiline` / `smtp_t017` / `smtp_t031` / `smtp_t040` / `smtp_t041` / `smtp_t042` |
| **SIZE** | RFC 1870 | 文本回放（`250-SIZE 10240000` 出现在能力表） | `smtp_t003_ehlo_multiline`（**唯一一处**，机读实测） |
| **8BITMIME** | RFC 6152 | **零用例**（能力表未出现该词） | A′ 立项 G-SMTP-3 |
| **STARTTLS** | RFC 3207 | 文本回放（`STARTTLS` + `220 2.0.0 Ready to start TLS`）；**不升级 TLS** | `smtp_t018_starttls_script` |
| **AUTH** | RFC 4954 | 文本回放（`AUTH LOGIN` + 334/334/235 三步）；**不做真认证** | `smtp_t017_auth_login` / `smtp_t031_fail_535_authfail` / `smtp_t040` |

**STARTTLS 的 tshark 伪影（实测，必须写清）**：`smtp_t018` 帧 7 的 `smtp.req.command` 被 tshark 解成 **`STAR`**（截断）且 `_ws.col.Protocol` 变成 **`TLS`**——dissector 见到 `STARTTLS` 字样即把后续字节按 TLS 解。故该例**不断该包原文**，只断包序 + 帧 8 的 `220`（`cases/smtp.json` 该例 notes 已载）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明 banner 与逐条命令/应答台词（或声明式邮件），引擎按固定剧本产出事件序列（banner → 每条 dialog 的 Cmd/Response → [email 注入] → 挥手），tcp 层负责握手与挥手。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 基本投递（HELO/MAIL/RCPT/DATA/QUIT） | 标准五步 | `smtp-basic-session` |
| ② 扩展协商（EHLO 能力表） | 多行 250- 应答 | `smtp_t003_ehlo_multiline` |
| ③ 群发（双 RCPT） | 两轮 RCPT 累积收件人 | `smtp_t004_multi_rcpt` |
| ④ 事务重置（RSET 重发信封） | RSET 后重来 | `smtp_t005_rset` |
| ⑤ 空闲保活（NOOP） | 单/多 NOOP | `smtp_t006_noop` / `smtp_t039_keepalive_multi_noop` |
| ⑥ 地址探查（VRFY/EXPN） | 探测性命令 | `smtp_t007_vrfy` / `smtp_t008_expn` |
| ⑦ 声明式邮件投递（纯文本/双体/附件/空体/纯附件） | DATA 阶段自动构造 MIME | `smtp_t010`/`t011`/`t012`/`t032`/`t033`/`t034`/`t035` |
| ⑧ 提交端口/SMTPS 端口 | 只换端口 | `smtp_t013_port_587` / `smtp_t014_port_465` |
| ⑨ IPv6 产线 | 同上，仅外层 IPv6 | `smtp_t015_v6` |
| ⑩ 现网三家 banner（Postfix/Gmail/Exchange） | 问候原文对照 | `smtp_t016` / `smtp_t041` / `smtp_t042` |
| ⑪ ESMTP 认证与 TLS 升级台词 | AUTH 三步 / STARTTLS | `smtp_t017` / `smtp_t018` / `smtp_t031` / `smtp_t040` |
| ⑫ 失败码台词（7 类） | 4xx/5xx 应答回放 | `smtp_t025`–`t031`（7 例） |
| ⑬ 多事务（同连接两封信） | 两次完整 DATA | `smtp_t037_two_mails` |
| ⑭ 复合流（AUTH+RSET+两封信） | 一条流多动作 | `smtp_t040_composite_auth_rset_twomail` |
| ⑮ 异常断线（无 QUIT） | 掉线模拟 | `smtp_t038_abort_no_quit` |
| ⑯ 多流（flows=2） | 静态复制门反例/正例对 | `smtp_t024_default_twoflow` / `smtp_t024b_static_pinned_reject` |

**五层覆盖逐层结论**：

- **功能层**——13 命令全覆盖 + 14 应答码全覆盖（`coverage_gate.py` 35/35 绿，§9）；错误处理 6 条负例（配置错 3 / 线格式错 1 / 关联错 1 / 载体错 1，§7）。
- **性能层**——MSS 分段（`smtp_t012`/`t033` 正文 5483/5339 字节切成 **4 段**：1460+1460+1460+1167 / 1460+1460+1460+1316，实测）；最大帧 **1514 字节**（以太 MTU 满帧）；MSS 下限 536 拒绝例（`smtp_t020`）。
- **数据场景层**——banner 空/非空（自动生成 + 3 家现网形）；dialog 空（默认会话）/2 条/3 条/4 条/5 条/7 条/8 条/10 条/14 条（实测分布）；`direction` 覆盖；`response` 空（纯客户端轮次）；`cmd` 空（纯服务端轮次）；email 八格全覆（`coverage_gate.py` 实测）；boundary 超 70 拒绝；附件无数据拒绝；多行应答；base64 折行。
- **地址与流层**——IPv4 基线（42 例）+ IPv6 独立用例（`smtp_t015_v6`，offset 74，断言 `ipv6.version=6`）；**单流**基线；多流由用例级 `strategy_fc {"type":"flows","value":2}` 承载（`smtp_t024`，40 帧 = 2×20）；**流关联（控制流派生数据流）显式不适用**——SMTP 单 TCP 连接承载全部命令，无副连接（§12.3）。
- **业务层**——十六场景全部有落点（上表）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① 真实 STARTTLS 升级（未实现，G-SMTP-2）；② 真实 AUTH 认证（未实现）；③ BDAT/CHUNKING（RFC 3030，未实现）；④ PIPELINING 批量语义（RFC 2920，未实现）；⑤ DKIM/SPF/DMARC（未实现）；⑥ 隐式 TLS（SMTPS 465 明文链，`smtp_t014` 只断端口）；⑦ 手写路径的自动 dot-stuffing（用户责任）。

## 5. 消息/事务模型与状态机

**事务定义**：一次命令 + 一次应答（`Cmd` + `Response`）。**多事务** = 一个连接内多对按序执行：`smtp_t037_two_mails`（10 条 dialog = 2 封完整信）、`smtp_t040`（14 条 = AUTH 三步 + 两封信 + RSET）、`smtp_t004_multi_rcpt`（7 条 = 双 RCPT 单封信）。

**SMTP 层无自有状态机——这是本协议最重要的诚实声明**。`planner.go:22-27` 明写："The planner plays back the user-provided Dialog verbatim. It does NOT implement a real SMTP state machine"。生成器**逐条回放**，对"未 MAIL 就 RCPT"、"未 HELO 就 MAIL"、"DATA 未 354 就发正文"这类非法转移**一律不拦、不报错、照发**（RFC 5321 §4.1.4 定义的命令序列规则在本实现中**不执法**）。`smtp_t030_fail_503_sequence` 只是**回放 503 台词**，不是引擎拦截（该例 notes 明写"回放不断言状态机"）。

**规范状态机（RFC 5321 §3.3 / §4.1.4，供读者对照，非本实现）**：

| 阶段 | 合法命令 | 非法转移（规范会回 503，**本实现不拦**） |
|---|---|---|
| 连接建立 | 服务端发 220；客户端发 HELO/EHLO/QUIT | 未问候就 MAIL/RCPT → 503 |
| 信封（MAIL 后） | RCPT、RSET、QUIT | 未 MAIL 就 RCPT → 503；未 RCPT 就 DATA → 503/554 |
| DATA（354 后） | 正文 + `.` 结束 | 正文中出现裸 `.` 行即提前结束 |
| 传输中（MAIL/RCPT 后） | DATA、RSET | — |
| 任意时刻 | NOOP、VRFY、EXPN、AUTH、STARTTLS | — |
| 关闭 | QUIT → 221 | — |

**驱动阶段表（本实现实际产出）**：

| 阶段 | 产出帧 | 用例 |
|---|---|---|
| TCP 握手 | SYN / SYN-ACK / ACK（tcp 层） | 全正例（帧 1-3） |
| 问候 | banner（down，220） | 全正例（帧 4） |
| 命令序列 | 每 dialog 元素：Cmd 帧 + Response 帧 | 全正例 |
| DATA 注入 | 正文帧（up）+ 自动 250（down） | 9 个 email 例 |
| 关闭 | QUIT/221（如有）+ FIN 四包（tcp 层） | 全正例（帧 N-3…N） |

**事件序（`planner.go:236-336`）**：`banner(down)` → 每 dialog：`Cmd(方向按 Direction)` → `Response(方向按 Direction)` → 若 `Email != nil` 且 `isDATACommand(cmd.Cmd)`：`body(up)` + `250(down)`。**TCP 握手/挥手不在本层**（`layer_gen.go:24-27` 明写"生成器不产 TCP 握手/挥手包——防双握手"）。

**自动派生规则**（逐条列出触发条件与内容）：

1. `Banner == ""` → 自动生成 `220 <DstIP> ESMTP trafficgen`（`planner.go:241-244`，`layer_gen.go:82-84`）；banner **恒发**。
2. `Dialog` 为空且 `Email == nil` → `defaultDialog()`（6 条：HELO + MAIL + RCPT + DATA + 正文 + QUIT，`planner.go:346-357`）。
3. `Dialog` 为空且 `Email != nil` → `defaultEmailDialog()`（5 条：HELO + MAIL + RCPT + DATA + QUIT，**无正文 Cmd**，`planner.go:364-372`）。
4. `Email != nil` → 在 `DATA` 命令的 354 之后注入正文帧 + 自动 `250 2.0.0 Ok: queued as 1`（`planner.go:319-323`）。
5. `Cmd == ""` → 跳过命令帧；`Response == ""` → 跳过应答帧。
6. TCP 握手（3 包）与挥手（4 包：FIN-ACK up → ACK down → FIN-ACK down → ACK up）由 tcp 层自动补。
7. 每个 SYN/SYN-ACK 携带 TCP options（MSS + WinScale + SACK-Permitted，`synOptions`，`planner.go:406`）。
8. 源端口未显式给出时由 worker 保底递增（`smtp_t024` 双流：`src_port` 保底 +1 防撞）。

**多流（`flows=N`）**：`smtp_t024_default_twoflow` 用全缺省层链 + `strategy_fc flows=2` → 40 帧（= 2×20 单流），`src_port` 保底递增防撞。**无并发交错**——两流按序展开，与 §5 的"连续非交错"同款诚实声明。

## 6. 性能设计与验收

- **目标与边界**：单流帧数 = **8 + Σ dialog 帧数 + [email: 正文段数 + 1]**（§9 公式）；最大单流 36 帧（`smtp_t040` 复合流）；最大单帧 **1514 字节**（以太 MTU 满帧，`smtp_t012`/`smtp_t033` 帧 13-15）；MSS 默认 **1460**，下限 **536**（RFC 879，`planner.go:59-64`）。
- **跨 MSS 分段**：`segmentByMSS`（`planner.go:382`）把 payload 按 MSS 切段，每段一帧 PSH-ACK，发送方 seq 按段字节数推进（`emitData`，`planner.go:228-234`）。**段数 = ceil(帧长/MSS)**（实测 `smtp_t012` 正文 5483 字节 → 4 段）。空 payload 也产 1 段（`planner.go:386-388`）。
- **依据**：planner 返回 `chan core.PacketConfig`（**流式产出**，`planner.go:122`），不聚合全量包；生成器逐帧 `EmitMsg`（`layer_gen.go`），无跨流共享状态。
- **验收两路**：pcap（`/tmp/mcp-pcaps/smtp/`，`<id>.pcap` / 负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `smtp.req.command`/`smtp.response.code`/`tcp.dstport` 字段、帧原始 hex 与包数，不只断言"任务没报错"。
- **六类场景落点**：基线（`smtp-basic-session`，20 帧）/ 目标规模（`smtp_t040` 复合流 36 帧）/ 压力上限（`smtp_t012`/`t033` 4 段分段 + 1514 满帧）/ 长时间运行（`smtp_t039` 三 NOOP 保活）/ 并发交错（顺序多对承载语义，并发路径不启用）/ 背压（包数公式精确守卫帧数漂移 + MSS 下限守卫）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须被拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功：

| # | 负例 ID | 故障输入 | 锚词（`error_contains`） | 归属门 | 代码行 |
|---:|---|---|---|---|---|
| N-1 | `smtp_t002_top_smtp_presence_reject` | 层链 + 顶层 `smtp:{}` 并存 | `rejects a top-level smtp sub-config` | 框架 `CheckProtoFlat` | `strategy_convert.go:8830-8833` |
| N-2 | `smtp_t019_bad_srcip_reject` | `ip.dst = "not-an-ip"` | `invalid IP address: not-an-ip` | 框架 ip 层 | `convert.go:55` |
| N-3 | `smtp_t020_mss_reject` | `tcp.mss = 100` | `out of range [536,65535]` | 框架 tcp 层 V9 范围门 | `layers/complete.go:325` |
| N-4 | `smtp_t021_boundary_reject` | multipart + `boundary` 71 字符 | `Boundary` | smtp planner | `mime.go:344` |
| N-5 | `smtp_t022_attach_nodata_reject` | 附件既无 `data` 也无 `data_b64` | `neither Data nor DataB64` | smtp planner | `mime.go:353` |
| N-6 | `smtp_t024b_static_pinned_reject` | 显式标量四元组 + `flows=2` | `static` | 框架 schema 语义门 | `schema/semantic.go:285` |

**负例原子性**：每例单一故障注入；单次执行不得混注。

**锚词口径（C 类边界，必须写清）**：**6 条负例中只有 N-4/N-5 走 smtp 自己的 validator**（`Planner.Validate` → `validateSMTPEmail`）。N-1 走框架 `CheckProtoFlat` 的 smtp presence 分支；N-2 走框架 ip 层；N-3 走框架 tcp 层 V9 范围门；N-6 走框架 schema 静态复制门。存量 `cases/smtp.json` 的 notes 已逐例标注此归属（N-2/N-3 明写"legacy planner 门由扁平路径覆盖，C 类注记"）。

**smtp planner 自己的拒绝分支（`Planner.Validate`，`planner.go:84-114`）**：

| 分支 | 锚词 | 代码行 | 今日用例 |
|---|---|---|---|
| `SrcIP` 非 IP | `smtp: invalid SrcIP %q (not a valid IP address)` | `planner.go:87` | **无**（链路径 src 由框架拦）→ A′ G-SMTP-6 |
| `DstIP` 非 IP | `smtp: invalid DstIP %q (not a valid IP address)` | `planner.go:92` | **无**（同上）→ A′ G-SMTP-6 |
| `TCP.MSS < 536` | `smtp: TCP.MSS %d too small (min %d per RFC 879)` | `planner.go:99` | **无**（链路径由框架 V9 门先拦，N-3）→ A′ G-SMTP-6 |
| `Email.Boundary > 70` | `smtp: Email.Boundary length %d exceeds max 70 chars (RFC 2046 §5.1.1 boundary)` | `mime.go:344` | **有**（N-4） |
| `Email.Boundary` 含 CRLF | `smtp: Email.Boundary %q contains CRLF (RFC 2046 §5.1.1 boundary + injection protection)` | `mime.go:347` | **无** → A′ G-SMTP-6 |
| 附件无数据 | `smtp: Email.Attachments[%d] has neither Data nor DataB64 (RFC 2045 §6.8)` | `mime.go:353` | **有**（N-5） |

**未入用例的静默路径（缺陷候选）**：无。planner 的 4 个拒绝分支中 2 个有用例、2 个（CRLF / 扁平 IP/MSS）由框架门先拦。

**不得误报的合法协议事件**：多行 EHLO 应答（`smtp_t003`）；空 `response`（纯客户端轮次）；空 `cmd`（纯服务端轮次）；`direction="down"` 的 Cmd（`smtp_t036`）；`email` 与 `dialog` 并存（9 例）；无 QUIT 断线（`smtp_t038`，`terminates` 仍真——TCP 照常 FIN）；多流全缺省（`smtp_t024`）；`text_body` 为空（`smtp_t034`/`t035`）；附件仅 `data_b64`（存量全 4 例均只用 `data_b64`）。

## 8. 边界

- **帧长**：最大单帧 **1514 字节**（以太 MTU 满帧，`smtp_t012`/`t033` 帧 13-15）；最小载荷帧 6 字节（`DATA\r\n`）。
- **分段**：段数 = `ceil(len(payload)/MSS)`，默认 MSS 1460；MSS 下限 536（RFC 879，`planner.go:59-64`）；`TCP.MSS == 0` → 用 1460（`planner.go:141-144`）。
- **boundary**：≤70 字符且不含 CRLF（RFC 2046 §5.1.1，`mime.go:337-348`）；**仅当 email 是 multipart 时才校验**（附件非空，或 text+html 均有）——text-only 邮件无 boundary（`mime.go:340-342`）。
- **base64 折行**：76 字符/行（RFC 2045 §6.8，`mime.go:250-266`）；`data_b64` 逐字写出不折行（用户责任）。
- **端口**：显式 25（40 例）/ 587（1 例）/ 465（1 例）；缺省 25 由 FieldContract 补齐（`smtp_t024_default_twoflow` 走过该分支，实测 SYN dst_port=25）。**仍缺**"只缺端口、其余标量显式"的形状 → A′ G-SMTP-5。
- **地址族**：IPv4 42 例 + IPv6 1 例（`smtp_t015_v6`，offset 74）；异族混写拒绝 → A′ G-SMTP-5。
- **方向**：`direction` 只接受 `"up"`/`"down"`（`planner.go:290`/`:305` 按 `==` 判定，**其余值一律当缺省方向**，无枚举校验）→ A′ G-SMTP-6。
- **命令字大小写**：`isDATACommand` 用 `EqualFold` + `TrimSpace`（`mime.go:325-327`），故 `data`/`DATA`/` data ` 均触发正文注入；但**其余命令无解析**（纯回放）。
- **正文终止符**：手写路径由用户写 `\r\n.`（planner 补 `\r\n`）；声明式路径自动写 `.\r\n`（`mime.go:101`）。
- 不得产生回绕长度或超量分配（分段按 MSS 切，帧长由 tcp 层与 MTU 决定）。

## 9. 原子 ID 与完成定义（43 个唯一语义 ID，顺序为权威）

**包数公式（实测校准）**：单流帧数 = **8（握手 3 + 挥手 4 + banner 1）+ Σ_{dialog 元素} [Cmd 帧数 + Response 帧数] + [Email 非 nil ? 正文段数 + 1 : 0]**，其中每帧数 = `ceil((len(原文)+2)/MSS)`（`+2` 为追加的 CRLF）；`flows=N` 时总帧数 ×N。**37 个正例公式与实测 pcap 逐例一致（机读实测 37/37）**。

| # | ID | 类型 | 覆盖 | packet_count（实测） |
|---:|---|---|---|---:|
| 1 | `smtp-basic-session` | 正 | §3.1/§3.3：全缺省冒烟（banner 自动生成 + 默认会话） | 20 |
| 2 | `smtp_t002_top_smtp_presence_reject` | 负 | §7 N-1：顶层 smtp presence 判死 | —（0 帧，**无 pcap 留档**） |
| 3 | `smtp_t003_ehlo_multiline` | 正 | §3.1/§3.7：EHLO 多行能力表（SIZE） | 12 |
| 4 | `smtp_t004_multi_rcpt` | 正 | §4 场景③：双 RCPT 群发 | 22 |
| 5 | `smtp_t005_rset` | 正 | §4 场景④：RSET 重置重发 | 24 |
| 6 | `smtp_t006_noop` | 正 | §4 场景⑤：NOOP 保活 | 14 |
| 7 | `smtp_t007_vrfy` | 正 | §4 场景⑥：VRFY 地址探查 | 14 |
| 8 | `smtp_t008_expn` | 正 | §4 场景⑥：EXPN 列表探查 | 14 |
| 9 | `smtp_t009_quit_after_data` | 正 | §3.5：DATA 后直接 QUIT | 18 |
| 10 | `smtp_t010_email_text` | 正 | §3.6：声明式 text-only（非 MIME） | 20 |
| 11 | `smtp_t011_email_alternative` | 正 | §3.6：multipart/alternative | 20 |
| 12 | `smtp_t012_email_attach` | 正 | §3.6/§6：multipart/mixed 单附件（4 段分段） | 23 |
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

**计数对账**：43 = **37 正 + 6 负**。正例中带包数键的仅 **3 例**：`packet_count` 1 例（`smtp_t024_default_twoflow`=40）、`min_packets` 2 例（`smtp-basic-session`=16、`smtp_t004_multi_rcpt`=18）；**其余 34 个正例无任何包数键**（机读实测 `expect` 键频：`packet_count`×1 / `min_packets`×2 / 40 例无）——**包数断言覆盖率仅 3/37 正例**，是本节最重的缺口（G-SMTP-1）。

## 10. 规范矩阵（规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | TCP 客户端主动建连；服务端先发 220 问候（RFC 5321 §3.1） | 场景①–⑯ | `DependsOn ["tcp"]` 单值（`registry.go:1565`）；banner 恒发（`planner.go:245-252`） | 无 |
| 2 | 命令/消息表 | 13 命令（RFC 5321 §4.1 + RFC 4954/3207）+ 14 应答码 | 场景①–⑬ | 无命令表——**纯回放**（`planner.go:280-310`）；命令字由用户原文决定 | 命令字集无 validator（非法命令不拦）→ G-SMTP-3 |
| 3 | 状态机 | RFC 5321 §4.1.4 命令序列规则（未 MAIL 就 RCPT → 503 等） | — | **不实现**（`planner.go:22-27` 明写）；逐条回放 | **明确不解决**（生成器非 MTA，§1 边界①）；503 台词例 `smtp_t030` 不断言执法 |
| 4 | 字段表 | 行模型 CRLF（§2.3）；MAIL/RCPT 参数 `<reverse-path>`/`<forward-path>`（§4.1.1.2/.3）；DATA 终止符 `\r\n.\r\n`（§4.1.1.4） | 全正例 | `planner.go:289`/`:304` CRLF 追加；参数原样回放；终止符两路径（§3.2） | 参数语法（尖括号/域名）不校验 → G-SMTP-3 |
| 5 | 错误处理 | 6 条负例（§7）+ smtp validator 4 分支 | 负例 N-1…N-6 | `planner.go:84-114` + `mime.go:332-355` | 2 分支无用例（G-SMTP-6） |
| 6 | 超时与活性 | RFC 5321 §4.5.3.2 服务超时 5 分钟；NOOP 是标准保活 | 场景⑤/⑮ | NOOP 回放（`smtp_t006`/`t039`）；**无超时字段**（生成器不模拟超时） | **显式不适用**（生成器无时钟语义） |
| 7 | NAT/代理/被动 | SMTP 无被动模式概念（客户端直连） | — | 无 `sessions[].src_port`；多流走用例级 `strategy_fc` | **显式不适用**被动模式；NAT 穿透为框架面 |
| 8 | 版本/方言 | 三端口（25/587/465，RFC 6409/8314）；ESMTP 扩展（EHLO/AUTH/STARTTLS/SIZE/8BITMIME） | 场景②⑧⑪ | 端口不强制（`planner.go:109-113` 明写）；扩展文本回放（§3.7） | 8BITMIME 零用例（G-SMTP-3）；真 STARTTLS/AUTH 未实现（G-SMTP-2） |

**逐行重数（§10.1）**：8 行 = 已覆 **1**（行 1 连接模型，无缺口）+ 立项 **4**（行 2 命令字 validator / 行 4 参数语法 / 行 5 错误处理 2 分支 / 行 8 扩展面）+ 不适用 **3**（行 3 状态机 / 行 6 超时 / 行 7 NAT）。1 + 4 + 3 = 8 ✓

### 10.2 子表①：命令 × 终态矩阵（逐格已覆/立项/不适用）

| 命令 | T1 正常终态 | T2 配置拒绝 | T3 异常终态（无 QUIT 断线） |
|---|---|---|---|
| HELO | 已覆（`smtp-basic-session`/`t004`/`t005`/`t006`/`t007`/`t008`/`t023`/`t025`/`t026`/`t027`/`t028`/`t030`/`t037`/`t038`/`t039`） | 不适用（planner 无命令字校验，纯回放） | 已覆（`smtp_t038`） |
| EHLO | 已覆（`t003`/`t017`/`t029`/`t031`/`t040`/`t041`/`t042`） | 不适用（同上） | A′ 立项（G-SMTP-6） |
| MAIL | 已覆（12 例） | 不适用（同上） | 已覆（`t038`） |
| RCPT | 已覆（13 例） | 不适用（同上） | 已覆（`t038`） |
| DATA | 已覆（15 例） | 不适用（同上） | 已覆（`t038`） |
| RSET | 已覆（`t005`/`t040`） | 不适用（同上） | A′ 立项（G-SMTP-6） |
| NOOP | 已覆（`t006`/`t036`/`t039`） | 不适用（同上） | A′ 立项（G-SMTP-6） |
| VRFY | 已覆（`t007`） | 不适用（同上） | A′ 立项（G-SMTP-6） |
| EXPN | 已覆（`t008`） | 不适用（同上） | A′ 立项（G-SMTP-6） |
| TURN | 已覆（`t023`，502） | 不适用（同上） | A′ 立项（G-SMTP-6） |
| AUTH | 已覆（`t017`/`t031`/`t040`） | 不适用（同上） | A′ 立项（G-SMTP-6） |
| STARTTLS | 已覆（`t018`） | 不适用（同上） | A′ 立项（G-SMTP-6） |
| QUIT | 已覆（全正例除 `t038`） | 不适用（同上） | **不适用**（QUIT 即正常终止） |

**逐格重数**：13 行 × 3 列 = 39 格——已覆 **13**（T1 列，每命令至少一例）/ A′ 立项 **12**（T3 列，除 QUIT 外 12 命令的"无 QUIT 断线"面）/ **不适用 14**（T2 列 13 格——**planner 无命令字校验，不存在按命令分的配置拒绝路径**；+ QUIT 行 T3——QUIT 即正常终止，无异常终态）。零空格。13 + 12 + 14 = 39 ✓

> **T2 列全判"不适用"是本协议的重要诚实声明**：6 条负例（§7 N-1…N-6）都是**配置面/载体面**错误（顶层子映射、坏 IP、MSS、boundary、附件数据、静态复制），**没有一条是"某命令用错"**——因为 planner 不解析命令字（设计 §5）。若未来加命令字校验，T2 列应改为逐命令立项。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **30 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | `banner` 缺省（自动生成 220） | 覆（`smtp-basic-session` 等 40 例） |
| 2 | `banner` 显式（Postfix/Gmail/Exchange） | 覆（`t016`/`t041`/`t042`） |
| 3 | `dialog` 缺省（默认 6 条会话） | 覆（`smtp-basic-session`/`t013`/`t014`/`t015`/`t024` 共 5 例） |
| 4 | `dialog` 缺省 + `email` 非空（`defaultEmailDialog()` 5 条信封） | **A′ 立项**（G-SMTP-4；存量 9 个 email 例**全部显式写 dialog**，机读实测，该分支零走过） |
| 5 | `dialog` 多行应答（内嵌 `\r\n`） | 覆（`t003`/`t017`/`t031`/`t040`/`t041`/`t042`） |
| 6 | `cmd` 空（纯服务端轮次） | **A′ 立项**（G-SMTP-4；`planner.go:284` 有分支） |
| 7 | `response` 空（纯客户端轮次） | 覆（`t036` 第二条 `{"cmd":"NOOP","response":""}`） |
| 8 | `direction="down"`（Cmd 走下行） | 覆（`t036`） |
| 9 | `direction="up"`（Response 走上行） | **A′ 立项**（G-SMTP-4；`planner.go:305` 有分支，存量零用） |
| 10 | `direction` 非法值 | **A′ 立项**（G-SMTP-6；无枚举校验，静默当缺省） |
| 11 | email text-only（非 MIME） | 覆（`t010`） |
| 12 | email html-only（单体） | 覆（`t032`） |
| 13 | email alternative（双体） | 覆（`t011`） |
| 14 | email mixed 单附件 | 覆（`t012`） |
| 15 | email mixed 双附件 | 覆（`t033`） |
| 16 | email mixed 内嵌 alternative（text+html+附件） | **A′ 立项**（G-SMTP-4；`mime.go:145-152` 有分支，存量零用） |
| 17 | email 空正文（仅头 + 终止符） | 覆（`t034`） |
| 18 | email 纯附件（无首体块） | 覆（`t035`） |
| 19 | `boundary` 用户自定义 | **A′ 立项**（G-SMTP-4；`t021` 只覆盖超长拒绝，**合法自定义值零正例**） |
| 20 | `boundary` 超 70 | 覆（`t021`，负） |
| 21 | `boundary` 含 CRLF | **A′ 立项**（G-SMTP-6；`mime.go:347` 有分支） |
| 22 | 附件 `data_b64` 逐字 | 覆（`t012`/`t033`/`t035` 等） |
| 23 | 附件 `data`（原始字节 → base64） | **A′ 立项**（G-SMTP-4；`mime.go:244-247` 有分支，**存量 43 例零用 `data`**） |
| 24 | 附件无数据 | 覆（`t022`，负） |
| 25 | 自动 dot-stuffing（正文行首 `.`） | **A′ 立项**（G-SMTP-4；`mime.go:297` 有分支，存量零用） |
| 26 | 多流 `flows=2` 全缺省 | 覆（`t024`） |
| 27 | 多流 `flows=2` 显式标量 | 覆（`t024b`，负） |
| 28 | IPv6 载体 | 覆（`t015`） |
| 29 | 非默认端口 587/465 | 覆（`t013`/`t014`） |
| 30 | 缺省端口 25（不写 dst_port） | **部分覆**（`t024` 全缺省层链走过 FieldContract 补齐，实测 dst_port=25）；**"只缺端口"形状缺** → A′ G-SMTP-5 |

**逐行重数**：30 行（上表 1–30）——覆 **19** / A′ 立项 **11**（行 4/6/9/10/16/19/21/23/25/30）。19 + 11 = 30 ✓

> 注：行 30 为"部分覆"——`t024` 走过 FieldContract 补齐分支，但"只缺端口"形状仍缺，故计入立项侧；行 1 同时覆盖缺省与显式 banner 两种触发路径。

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 基本投递（HELO/MAIL/RCPT/DATA/QUIT，RFC 5321 §3.3） | `smtp-basic-session` | 已覆 |
| 2 | 扩展协商（EHLO 能力表，RFC 5321 §4.1.1.1） | `t003` | 已覆 |
| 3 | 群发（多 RCPT，§4.1.1.3） | `t004` | 已覆 |
| 4 | 事务重置（RSET，§4.1.1.5） | `t005` | 已覆 |
| 5 | 空闲保活（NOOP，§4.1.1.9） | `t006`/`t039` | 已覆 |
| 6 | 地址探查（VRFY/EXPN，§4.1.1.6/.7） | `t007`/`t008` | 已覆 |
| 7 | 声明式 MIME 投递（RFC 2045/2046） | `t010`–`t012`/`t032`–`t035` | 已覆（8 格） |
| 8 | 提交端口（RFC 6409 587） | `t013` | 已覆 |
| 9 | SMTPS 端口（RFC 8314 465） | `t014` | 已覆（**明文链，不断 TLS**） |
| 10 | 现网三家 banner（Postfix/Gmail/Exchange） | `t016`/`t041`/`t042` | 已覆（问候原文对照） |
| 11 | ESMTP 认证（RFC 4954） | `t017`/`t031`/`t040` | 已覆（**台词版，不做真认证**） |
| 12 | STARTTLS 升级（RFC 3207） | `t018` | 已覆（**台词版，不升级 TLS**） |
| 13 | 失败码处理（7 类 4xx/5xx） | `t025`–`t031` | 已覆（**台词版，不断引擎拦截**） |
| 14 | 多事务（同连接多封信） | `t037`/`t040` | 已覆 |
| 15 | 异常断线 | `t038` | 已覆 |
| 16 | 多流（批量投递） | `t024`/`t024b` | 已覆（放行/拒绝对照） |
| 17 | 真实服务器对接 | — | **明确不解决**（G-SMTP-8；地板线关键字已覆，真对接另立项） |
| 18 | 真 STARTTLS/TLS 握手 | — | **明确不解决**（G-SMTP-2） |
| 19 | 真 AUTH 认证 | — | **明确不解决**（§1 边界③） |
| 20 | BDAT/CHUNKING（RFC 3030） | — | **明确不解决**（§1 边界⑥） |
| 21 | PIPELINING（RFC 2920） | — | **明确不解决**（§1 边界⑥） |

**逐行重数（§10.4）**：21 行 = 已覆 **17**（行 1–16 + 行 17 的地板线关键字面）+ 不适用 **4**（行 18 真 TLS / 行 19 真认证 / 行 20 BDAT / 行 21 PIPELINING）；**立项 0**（本表零缺口——每条商业行为要么有用例落点，要么已显式声明"明确不解决"）。17 + 4 = 21 ✓

### 10.5 三路对照与候选方案对比

三路：① **规范原文**（RFC 5321/5322/2045/2046/2183/4954/3207/1870/6152/879，定"必须是什么"）；② **商业化软件实际行为**（**部分取到**：Postfix/Gmail/Exchange 的 banner 原文已对照回放，`t016`/`t041`/`t042`；真实 MTA 的完整会话线字节未抓包核对 → G-SMTP-8）；③ **可靠开源实现思路**（Postfix `smtpd_banner` 默认 `$myhostname ESMTP`、Go `net/smtp` 的 CRLF 追加与 dot-stuffing 写法——只借鉴"CRLF 终止 + 行首点号转义"两条思路，代码为独立实现）。

三路一致点：CRLF 行模型、DATA 终止符 `\r\n.\r\n`、MIME multipart 结构与 base64 折行 76。不一致点：**命令序列是否执法**——RFC 5321 §4.1.4 要求服务器对非法序列回 503，本生成器**不执法**（明确不解决，§5）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `smtp` 终结层 + 纯回放 `dialog[]`（本版；pop3/imap 同族先例） | 台词可声明可断言；MIME 声明式构造；代价 = 一套层（已落码 928 行） | **采用** |
| B | 直接 tcp 层 + 顶层 payload 字符串 | 无命令/应答结构、无方向语义、无 MIME 构造 → 43 例中 30+ 例不可表达 | **否决** |
| C | 在 A 上加真实 SMTP 状态机（命令序列执法） | 与 trafficgen 契约冲突（生成器非 MTA）；且会拒绝存量 503 台词例 | **否决**（§1 边界①） |

## 11. 代码设计（as-built 逆向定稿）

> 状态说明：实现已落码（`internal/protocol/smtp/` 三非测试文件 928 行），本条为批次二文档轨对既有实现的**逆向定稿**（as-built），作为后续改动的唯一入口。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:7443-7586`） | `SMTPConfig`（`:7469`）/ `SMTPEmail`（`:7520`）/ `SMTPAttachment`（`:7556`）/ `SMTPCommand`（`:7584`）+ `FlowSpec.SMTP` 槽位（`:1864`） | —（共享文件） |
| `trafficgen/internal/protocol/smtp/planner.go` | `Planner.Validate`（3 分支）+ `Plan`（握手 + banner + dialog 回放 + 挥手）+ `segmentByMSS` + `synOptions` | 415 |
| `trafficgen/internal/protocol/smtp/mime.go` | MIME 构造：`buildSMTPEmailBody` + 四形态 + `base64Wrap` + `dotStuff` + `validateSMTPEmail` | 357 |
| `trafficgen/internal/protocol/smtp/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator` + `RegisterLayerValidator`，`init()`） | 156 |
| `planner_test.go` / `planner_mime_test.go` / `planner_testpoints_test.go` | 22 + 20 + 43 = **85 个 `Test*`** | 442/650/1249 |
| 接线 5 件 | registry 注册（`layers/registry.go:1563`，Fields 3 键 + FieldContract 25 + OptionalOn tls）/ translate 层内分支（`layers/chain_planner_translate.go:2650`）/ convert 子配置搬运（`strategy_convert.go:1384-1394`）/ protocols 准入（`protocols.go:55`）/ presence 判死（`strategy_convert.go:8830-8833`）+ 源端口不默认化（`layers/chain_planner.go:966`） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`planner.go:84`）：只读；`SrcIP`/`DstIP` 合法性、`TCP.MSS >= 536`、`Email` 结构校验（boundary + 附件数据）；**端口不校验**（`planner.go:109-113` 明写：587/465 合法，强制 25 会破坏提交/SMTPS 场景）。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`planner.go:117`）：先 `Validate`，再起 goroutine 流式产出。
- `buildSMTPEmailBody(email *core.SMTPEmail) []byte`（`mime.go:51`）：产出完整 DATA payload（含终止符）。
- `validateSMTPEmail(email *core.SMTPEmail) error`（`mime.go:332`）：只读。
- 生成器：`Name() "smtp"`（`layer_gen.go:48`）；`GenEvents()` 返回自身（`:140`）；`EmitEvent` 未接线显式错（防误调，`:145-147`）；`Generate` 逐帧 `EmitMsg`（`:53-138`）。

### 11.3 数据结构

`SMTPConfig{Banner string, Email *SMTPEmail, Dialog []SMTPCommand}`（`types.go:7469-7500`）；`SMTPEmail{Headers []string, TextBody, HTMLBody string, Attachments []SMTPAttachment, Boundary string}`（`:7520-7550`）；`SMTPAttachment{Filename, ContentType string, Data []byte, DataB64 string}`（`:7556-7576`）；`SMTPCommand{Cmd, Response, Direction string}`（`:7584-7602`）。

**JSON 键名（与 Go tag 一致，实测）**：`banner` / `email` / `dialog`；`headers` / `text_body` / `html_body` / `attachments` / `boundary`；`filename` / `content_type` / `data` / `data_b64`；`cmd` / `response` / `direction`。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry Fields 3 键 allowlist）→ translate（层内 config 经 JSON 往返解码为 `core.SMTPConfig`，`chain_planner_translate.go:2650-2666`）→ planner `Validate` → 生成器 `Generate`（banner → dialog 逐条 Cmd/Response → [email 注入]）→ worker（tcp 层补握手、seq/ack、MSS 分段、挥手）→ writer（PCAP/NIC）。

**legacy 路径与链路径的文档化分歧（`layer_gen.go:29-46` 明载）**：legacy `Plan` 自产 TCP 握手与挥手、按 `spec.TCP.MSS` 预分段、每包随机 ISN + 恒 `now` 时间戳；链路径**全部交给 tcp 层生成器**（事件 = 完整 payload，不预分段），seq/时间戳由 tcp 层与 ChainPlanner 统一回填。**两者产出的应用层字节序列一致**。

### 11.5 错误分支

smtp planner 4 种拒绝（`planner.go:87`/`:92`/`:99` + `mime.go:344`/`:347`/`:353`，实为 6 个分支）+ 框架 4 门（N-1/N-2/N-3/N-6）全部传 task error。**无静默降级路径**（§7）。

### 11.6 性能边界

见 §6（流式 chan 产出、per-flow 局部状态、无跨流共享、无锁；吞吐数字待基准，**本版不写承诺**）。

### 11.7 与现有逻辑的冲突点

- `CheckProtoFlat`（`strategy_convert.go`）**有 smtp 分支**（`strategy_convert.go:8830-8833`）：顶层 `smtp` 子映射 presence 判死（**空 map 也死**）→ 与 opcua 的"无分支"相反，本协议 presence 负例**今日可建且为真**（`smtp_t002`）。
- **顶层未知键通用门缺失**：游离顶层键（如 `{layers:[…], bogus: 1}`）今日**不判死**（`CheckProtoFlat` 只查五键 + 各协议子映射白名单）→ presence 负例**不建**（G-SMTP-9）。
- **静态复制门**：`checkLayerChainStaticCopy`（`schema/semantic.go:198`）读 `layers[]` 四元组标量面；smtp 业务字段全关（`layer_dyn.go` allowlist **无 smtp 行**，机读实测）→ 显式标量 + `flows>1` 即拒（`smtp_t024b`）；全缺省不触发（`smtp_t024`）。
- `smtp` **不在** `validateBaseDstPortHandled` 白名单（`chain_planner.go:750-830`，机读实测无 smtp）→ 端口缺省走通用 `FieldContract` 块（值 25）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 3 文件 + 接线 6 处（registry/protocols/translate/convert/presence/chain_planner）；不触及其他协议。cases 回滚 = 恢复 43 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 43 例 **42/43 顶层仅 `{layers}`**；唯一例外 `smtp_t002_top_smtp_presence_reject` 是**判死负例**（层链 + 顶层 `smtp:{}` 并存 = 该例要证的形状本身），**非残留**；目标形状见 §2 样例 | §12.1；`cases/smtp.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 smtp 流量模板；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（终结层）/时间线。有长连接（TCP），不豁免 | §12.3 + §5 |
| §4 查规范 | RFC 5321/5322/2045/2046/2183/4954/3207/1870/6152/879 + tshark 3.6.14 `smtp.*` 25 字段 + **40 例 pcap 实测**（37 正 + 3 负）+ 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["tcp"]` 单值（`registry.go:1565`）+ `OptionalOn ["tls"]`；smtp validator 6 分支 + 框架 4 门；失败传 task error | §5/§7/§11.5 |
| §6 性能 | 见 §6（帧上界 1514 / MSS 1460 / 下限 536 / 段数公式；pcap/NIC 两路验收明写） | §6 |
| §7 三份文档 | `107-smtp-{design,testcase}.md` v1.0.0（本文 + 配套用例文档）+ cases JSON（43 ID） | 修订记录 |
| §8 设计先行 | 本版为 as-built 逆向定稿（批次二口径），先于任何后续改动 | 提交序 |
| §9 测试三源 | 三源 = RFC 族（§10）+ 落码反推（§11）+ tshark 3.6.14 字段与 **40 例 pcap 实测**（已到抓包级：37 正例包数公式逐例一致、14 条 frame 断言逐条命中、97 条 field 断言全绿）；43 ID 逐项回指；存量审计去向 testcase §8 | `107-smtp-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 本文档自审（机读计数复核）N 轮至干净；隔离对抗审查由主线程另派 | 修订记录 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段 3 键全关 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `smtp` 已在 `registry.go:1563` 注册（**不新增层**），Fields 3 键与生成表同代；**若改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `smtp.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/smtp/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/smtp.json` | 43 | **`{layers}` ×42** + **`{layers, smtp}` ×1**（唯一例外是 `smtp_t002` 判死负例） | `[ip,tcp,smtp]` ×43 | 6/6 = `{expect_error, error_contains, notes}` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 本协议**从未用过顶层地址**；已住 `layers[0].ip.{src,dst}`（42 例显式；`t024` 全缺省） |
| `src_port` | **0** | 已住 `layers[1].tcp.src_port`（42 例显式 12345；`t024` 缺省走保底 +1，实测 12345/12346） |
| `dst_port` | **0** | 已住 `layers[1].tcp.dst_port`（42 例显式；`t024` 缺省走 FieldContract 补齐 25，实测 SYN dst_port=25） |
| `count` | **0** | 多流走**用例级** `strategy_fc {"type":"flows","value":N}`（2 例），不是 `spec_json` 内键 |
| 顶层 `smtp` 子映射 | **1**（仅 `smtp_t002` 判死负例） | 配置已住 `layers[2].smtp`（42 例）；该 1 例的顶层键是**判死形状本身**，P4 不得删 |
| `flow_control` | **0** | 本协议多流用例用 `strategy_fc`（用例级），未用 `spec_json.flow_control` |

**结论**：本协议存量 **42/43 顶层零残留**——§1 门的动作 = ①**无旧键可删**；②收官自查行「**非负例**顶层键 = 0」**今日即成立**（机读实测：唯一带顶层键的例是判死负例）；③A′ 新增例全部沿用纯 layers 形。

**presence 负例形状（必点名，设计 §12-P2）**：`smtp_t002_top_smtp_presence_reject` 的 `spec_json` = **层链 + 顶层空子映射并存**（`{"layers":[ip,tcp,smtp], "smtp":{}}`）——这是**判死负例**，不是旧键残留。锚词 `rejects a top-level smtp sub-config`（`strategy_convert.go:8832`），**空 map 也死**（与 mqtt/dns/cwmp 同款）。

目标形状样例见 §2（顶层仅 `layers`）。

### 12.3 §3 强制展开：五件套

- **会话表**：`s1` 单连接基线（全部 40 正例；各自四元组，banner → dialog 对 → [email 注入] → FIN 四包）。**无多会话结构**——SMTP 是单连接协议，`sessions[]` 无对应物（§1 边界）。
- **事务序列**：`t1` TCP 握手（3 包，tcp 层）/ `t2` 问候（banner，220 down）/ `t3` 命令事务（每 dialog 元素一对 Cmd/Response，方向按 `Direction`）/ `t4` DATA 事务（`DATA` → 354 → 正文 → 250，两路径见 §3.2）/ `t5` 关闭（QUIT/221 + FIN 四包）；每事务四件事（前置/触发/成功/失败）见 §5 阶段表 + §4 场景表。
- **关联关系**：**无派生流**（诚实声明：SMTP 单 TCP 连接承载全部命令与正文，无 `driven_by`；DATA 阶段不派生新连接）。
- **插入位置**：终结层（`[ip,tcp,smtp]`，无中间层；`OptionalOn ["tls"]` 允许未来 `[ip,tcp,tls,smtp]` 组合，**今日零用例**，G-SMTP-2）。
- **时间线**：会话内严格顺序（banner → dialog 逐条 → 挥手）/ 多事务顺序展开（`t037` 两封信、`t040` 复合流）/ **无交错**（`concurrent` 为例外路径，本协议不启用）；多流按序展开（`t024` 双流 = 2×20 帧，非交错）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组 2 键开**（`internal/core/layer_dyn.go` 头部 allowlist 实测）：`ip.src`/`ip.dst`/`ip.ttl`、`tcp.src_port`/`tcp.dst_port`、`udp.*`、`eth.*`——即 `ip` 与 `tcp` 层全开；保底自增 `DefaultSrcPort + i`（`strategy_convert.go:49`）；`dst_port` 动态与 25 缺省和平共处（显式/动态值非零即不触发补齐）。

**业务字段 3 项全关**（allowlist **无 `smtp` 行**，`grep` 零命中实测；对象即 `does not support dynamic`）：

| 字段 | 开/关 | 理由 |
|---|---|---|
| `banner` | **关** | 会话身份（问候文本），逐流变无意义（telnet banner 同判） |
| `dialog` | **关** | 会话结构（命令/应答台词序列），列表无动态形状 |
| `email` | **关** | 嵌套对象（MIME 结构 + 附件），无动态形状 |

**序号算法实读**：`parseLayerDyn`（`layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go` 头部）——**`smtp` 无块**（grep 实测零命中）。

**静态复制门**：`checkLayerChainStaticCopy`（`schema/semantic.go:198`）在 `flows>1` 时读 `layers[]` 的四元组标量面；smtp 业务字段全关 → **无动态逃生**，显式标量四元组 + `flows=2` 即拒（`smtp_t024b`，锚词 `static`）；全缺省则放行（`smtp_t024`，锚点 `src_port` 保底 +1）。**这正是 §12.9/§12.10 的直接落点**。

## 13. 对接清单（T-SMTP 草稿输入；正文落 testcase 文件）

43 ID（37 正 + 6 负）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。A′ 候选（见 §14 缺口表）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-SMTP-1 | **包数断言覆盖率仅 3/37 正例**：只有 `smtp-basic-session`（`min_packets=16`）、`smtp_t004_multi_rcpt`（`min_packets=18`）、`smtp_t024_default_twoflow`（`packet_count=40`）三例带包数键；**其余 34 个正例零包数断言**（机读实测 `expect` 键频）。§9 的包数公式今日**无机器执法**——帧数漂移不会被任何用例发现 | A′ 补例（P4）：按 §9 公式为 34 例补 `packet_count`，公式已实测校准（37/37 正例公式与 pcap 一致） |
| G-SMTP-2 | **真 STARTTLS 未实现**：`smtp_t018` 只回放 `STARTTLS` + `220` 台词，**不产 ClientHello/ServerHello**；`registry` 已声明 `OptionalOn ["tls"]` 但**层链 `[ip,tcp,tls,smtp]` 零用例**（机读实测 43/43 层链均为 `[ip,tcp,smtp]`） | A′ 候选：补 tls 底座组合例，或**明确不解决**并在 §1 边界写清。**今日不得声称 TLS 承载已覆盖** |
| G-SMTP-3 | **ESMTP 扩展面覆盖不均**：`8BITMIME`（RFC 6152）**全仓零用例**（能力表未出现该词，机读实测）；`SIZE`（RFC 1870）**仅 1 处**（`smtp_t003`）；命令字集无 validator（非法命令如 `FOO` 不拦，纯回放） | A′ 补例（`8BITMIME` 能力表 + `MAIL FROM:<…> SIZE=1024 BODY=8BITMIME` 参数形态） |
| G-SMTP-4 | **email/声明式路径 6 个分支零用例**：`dialog` 缺省 + `email` 非空（默认信封）、`cmd` 空（纯服务端轮次）、`direction="up"` 的 Response、mixed 内嵌 alternative（text+html+附件）、**合法自定义 `boundary`**、附件 `data`（原始字节→base64）、自动 dot-stuffing（行首 `.`） | A′ 补例（P4）；今日**不得声称已覆盖**（存量 9 个 email 例全部显式写 dialog、全部只用 `data_b64`、无 `text_body` 以 `.` 开头） |
| G-SMTP-5 | **显式端口压倒性**：存量 42/43 例显式写 `dst_port`（25×40 / 587×1 / 465×1）；唯一不写的是 `smtp_t024_default_twoflow`（全缺省层链）——registry `FieldContract{"tcp.dst_port":"25"}` 的补齐分支**今日由该例走过**（实测 SYN 帧 dst_port=25、两流 src_port 保底 12345/12346）。**仍缺**：①「显式删 dst_port 但保留其它四元组标量」的缺省端口正例（`t024` 是**全缺省**，同时缺省了 ip/tcp 全部标量，与"只缺端口"不同形状）；②异族混写（v4 src + v6 dst）拒绝例零 | A′ 补例（`smtp_default_port_only`：仅删 `dst_port` 保留 `ip.src/dst` + `tcp.src_port` / `smtp_neg_mixed_family`） |
| G-SMTP-6 | **smtp validator 未入例分支 3 条 + 非正常结束面**：`invalid SrcIP`（`planner.go:87`）、`invalid DstIP`（`:92`）、`TCP.MSS too small`（`:99`）、`Boundary contains CRLF`（`mime.go:347`）——链路径上前两者与第三者被框架门先拦（N-2/N-3），**validator 自身分支今日零直接证据**；`direction` 非法值无枚举校验（静默当缺省）；12 个命令的"无 QUIT 断线"面零例 | A′ 补例（P4）；`direction` 非法值裁定"拒绝"或"登记为静默合法" |
| G-SMTP-7 | **3 例负例无 pcap 留档**：`smtp_t002_top_smtp_presence_reject` / `smtp_t020_mss_reject` / `smtp_t024b_static_pinned_reject` 在 `/tmp/mcp-pcaps/smtp/` **无任何文件**（机读实测：目录共 40 个 pcap = 37 正 + 3 负）；另 3 例（`t019`/`t021`/`t022`）有 `.neg.pcap` 且 0 帧。**无留档 = 无当日复跑证据** | **代码阶段**（P5 重跑套件后补齐留档）；本版仅登记事实，不得据此声称"6 例负例全部复跑过" |
| G-SMTP-8 | **第三源未取全**：Postfix/Gmail/Exchange 的 **banner 原文已对照**（`t016`/`t041`/`t042`），但**真实 MTA 的完整会话线字节未抓包核对**（如真实 250 应答的扩展码细节、真实 354 文案）；`smtp_t041`/`t042` 的 notes 明写"真服务器对接另立项" | 待确认：抓真实 MTA 会话对照；确认前按实现钉、不声称合规。**风险**：若真实 MTA 的 banner/应答文案与现网形不符，3 个 banner 例的 frames/断言需重钉（**帧数不受影响**） |
| G-SMTP-9 | **顶层未知键通用门缺失**：游离顶层键（如 `{layers:[…], bogus: 1}`）今日**不判死**（`CheckProtoFlat` 只查五键 + 各协议子映射白名单）→ presence 负例今日建了会真绿 = 假通过，**不建** | **框架面**（等框架级 unknown-key 白名单；禁加单协议黑名单分支，kingbase 记忆裁定）。**非本协议可解** |
| G-SMTP-10 | **结果文档过期**：`trafficgen/docs/protocol-pcap-test/smtp.md`（**tracked 产物**，`git ls-files` 可证）写 `Cases: 43 — pass 43, fail 0, error 0`，但该行由 `b8177fc`（**2026-09-17**）写入，末次改动 `84cfbe6`（**2026-09-17**），**晚于**判死提交 `0417be5`（2026-09-13）但**早于今日**；`docs/protocol-pcap-test/smtp/` 目录**不存在（0 个 pcap）**——该目录下 pcap 被 `.gitignore:88`（`*.pcap`）排除，故**永远不可能有 tracked pcap 留档**。本车道**未跑**该套件（`/tmp/mcp-pcaps/smtp/` 的 40 个 pcap 是历史留档，mtime **2026-09-27**，非今日产出）。**故该 43/43 是历史产物、未经今日复跑证实**；本车道**不以任何形式**（含"今日已跑通"）引用它作为套件可跑证据。**但 smtp 存量 42/43 顶层零残留（唯一例外是判死负例）**，43 例今日**仍应可跑**——本缺口**不是**"不可跑"，而是"**数字未经今日复跑证实**" | **代码阶段**（P5 重跑套件后重生成该产物）；本版**不删不改**（tracked 产物，删除属 P5 动作，此处仅登记事实）；口径与 opcua G-OPCUA-10 / pcep G-PCEP-11 一致 |

| G-SMTP-11 | **6 例负例 `expect` 含 `notes` 键**（`{expect_error, error_contains, notes}`），与严格两键口径不同（opcua G-OPCUA-7 同款） | A′ 补例（P4）：删 `notes`；删前须把 notes 内的归属说明（C 类边界）保留在 testcase §4 表内，不得连带丢证据 |
| G-SMTP-12 | **MIME 结构与分段的直接断言面零使用**：9 个 email 例只用 frame 前缀 + 354/250 帧位；**boundary 值、`Content-Type: multipart/*` 完整行、base64 折行、附件字节、正文长度、段数**均无自动化断言。tshark 已提供可用字段 `smtp.data.reassembled.length`（正文重组长度）与 `smtp.data.fragment.count`（段数），**零使用**；`t012`/`t033` 的附件真实性靠**生成时人工核对**（`84cfbe6` 提交信息"落盘解码与原文逐字节一致"），无机器守卫 | A′ 补例（P4）：收编 `smtp.data.reassembled.length` / `smtp.data.fragment.count` / `smtp.response` / `smtp.rsp.parameter` / `smtp.auth.*`；MIME 结构行断言 |
| G-SMTP-13 | **RST 非正常结束零用例**：`t038` 是**应用层**无 QUIT（TCP 仍正常 FIN，`terminates=true`），**传输层 RST 异常终态**本协议零例（框架 tcp 层能力，本层零断言） | A′ 补例（P4）：`smtp_abort_rst`（`tcp.rst` 框架能力） |

## 15. 修订记录

- v1.0.0（2026-09-29）：批次二 as-built 文档轨。按 `protocol-doc-requirements.md` v1.3 撰写：门1 十四行对照表（§12，含 §1/§3/§12 三行强制展开 + §12-P2 presence 负例形状点名）；五层覆盖逐层展开（§4）；逐字段/状态机/驱动规格（§3/§5）；性能与容量（§6）；错误处理锚词表（§7）；边界（§8）；43 原子 ID 全表 + 包数公式实测校准（§9）；规范矩阵八项 + 子表①②③（§10）；代码设计 as-built 定稿（§11）；缺口 G-SMTP-1…G-SMTP-13（§14）。**存量 43 例机读审计**：42/43 顶层零残留（唯一例外 `smtp_t002` 是判死负例）；**14 条 frame 断言逐条对实测 pcap 命中（14/14）**；**97 条 field 断言全绿（94 直接相等 + 3 条 `tcp.flags` 按位比较，见 §9 注）**；**37 个正例包数公式与 pcap 逐例一致（37/37）**；`coverage_gate.py smtp` 实测 **35/35 绿**。自审见下条。**自审 4 轮（机读脚本复核每轮计数与断言，非手算），末轮干净**。
  - 注（`tcp.flags` 断言口径）：`smtp-basic-session` 的 3 条 `tcp.flags` 断言写作 `0x002`/`0x012`/`0x010`，tshark 输出 `0x0002`/`0x0012`/`0x0010`——**这是按位比较（`pcaptest.VerifyPcap` 对 `tcp.flags` 走 `HasTCPFlag` 位判定，`verify.go:114-122`），非字符串相等**，故判绿。文本长度差异不影响语义。

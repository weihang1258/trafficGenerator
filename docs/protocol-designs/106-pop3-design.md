# #106 pop3（Post Office Protocol v3，邮局协议第三版，RFC 1939）设计契约

> 版本：v1.0.0（P-PIPE 批次二 as-built 文档轨；修订记录见 §15）
> 日期：2026-09-29
> 车道：文档轨（批次二 #106 pop3）
> 编号说明：本协议在批次一/二统一编号中取 **106**。仓库内**不存在**旧的 `NN-pop3-design.md` 编号文档；本协议的前身是 **`docs/CODE_DESIGN.md` 的 D-POP3-1 条目**（§1341 起）与 **`docs/TEST_CASES.md` 的 T-POP3-1… 条目**（§2839 起）。本 106 是**独立编号的 as-built 契约**，承 D-POP3-1 的门1 对照表与规范矩阵骨架，**冲突处按今日实现与 cases JSON 钉**（逐条见 §0）。
> 存量用例：`trafficgen/test/protocol_pcap/cases/pop3.json`（**50 例**，35 正 + 15 负；ID 集合/顺序/包数/断言已机读实测，逐条见 §9 与配套 `106-pop3-testcase.md`）
> 规范基线：① **RFC 1939**（Post Office Protocol v3，下称 **spec**；章节号已按 2026-09-29 拉取的 `rfc1939.txt` 原文逐条核对，§2/§3/§4/§5/§6/§7/§9/§10/§11）；② RFC 2449（CAPA 扩展机制）、RFC 2595（STLS/AUTH，台词覆盖）；③ RFC 879（MSS 下限 536）、RFC 6528（随机 ISN）；④ 本机 tshark 3.6.14 `pop.*` 字段表（19 字段，§3.9）与 47 例实测 pcap（`/tmp/mcp-pcaps/pop3/`，包数与字段值的唯一权威）；⑤ 本仓库落码（`internal/protocol/pop3/` 五文件 + 接线六处，§11）；⑥ D-POP3-1（内部契约，非外部规范）
> 白话一句：**收邮件的老式电话亭——先握手建连（TCP 三包），服务器先说一句"我准备好了"（banner），然后一问一答（`USER`/`PASS` 或 `APOP` 过闸，`STAT`/`LIST`/`RETR`/`DELE` 干活），信件正文是多行的、以单独一行 `.` 收尾、行首是点就再补一个点（点填充），最后 `QUIT` 挂断（TCP 四包）。引擎是"照剧本念台词"，不扮真服务器——状态错了也照念。**

## 0. 前身文档校正声明（门1 必答：基线继承关系）

本 106 与前身 `D-POP3-1`（`docs/CODE_DESIGN.md`）/ `T-POP3-1…`（`docs/TEST_CASES.md`）是**同一协议的续号契约**，不是新协议。前身条目保留在磁盘只读参考。逐条给出校正结论（区分"承前身"与"前身已过期"）：

| # | 前身说法 | HEAD 实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | D-POP3-1「状态：P6 已验收（2026-09-17…）」；T-POP3-1「50/50 全绿，反查 32/32」 | `coverage_gate.py pop3` 实跑 **32/32 绿、exit 0**（本轮复跑）；JSON **50 例**机读一致 | **承前身**：验收结论今日仍成立 |
| 2 | D-POP3-1 §1「P4 必修 3 项：①CheckProtoFlat 加 pop3 presence 分支；②补 `setDefaultDstPort(&spec, cfg, 110)`；③pop3.json 2 例改写层链形」 | 三项**均已落码**：`strategy_convert.go:8837-8841`（presence 分支，锚词逐字）、`:1284`（`setDefaultDstPort(&spec, cfg, 110)`）、JSON 50 例全层链形 | **承前身**：3 项已闭 |
| 3 | D-POP3-1 §13「注册表 pop3 Fields 3 键齐」 | `registry.go:1580-1588`：`Category: CategoryTerminal`、`DependsOn ["tcp"]`、`OptionalOn ["tls"]`、`FieldContract {"tcp.dst_port":"110"}`、**Fields 3 键**（banner/commands/mailbox）；生成表 `schemas/v1/generated/layers.generated.json` 中 pop3 条目与 registry **逐键一致**（机读实测，127 层同代） | **承前身** ✓ |
| 4 | D-POP3-1 §1/§4/§13 引用的**代码行号**：`registry.go:828`、`strategy_convert.go:788`、`chain_planner_translate.go:1127`、`types.go:6660/6669/6718` | 实际：`registry.go:1580`、`strategy_convert.go:1273`、`chain_planner_translate.go:2634`、`types.go:6878/6887/6940` | **行号全漂移**（文件增长所致，非语义变化）→ 本版 §11 按 HEAD 重钉（G-POP3-8） |
| 5 | D-POP3-1 §1「目标形状」给**单条完整 spec_json 样例**（`{"layers":[{"ip":…},{"tcp":…},{"pop3":{…}}]}`） | 存量 50 例机读：49 例链形 `[ip,tcp,pop3]` + 1 例 `[ip,tcp,tls,pop3]`（t032）；**顶层键 50/50 = `{layers}`**，唯一例外 t035 为 presence 负例（`{layers, pop3}`，**故意**） | **承前身**：目标形状即存量形状；无迁移工作量 |
| 6 | D-POP3-1 §6「单会话 14 包量级（3 握手 + banner + 3 命令×2 + 4 挥手）」 | 该式仅对 t001 成立；本轮从 46 例 pcap **反推并逐例验证**通用式：`3 + [banner?1] + Σ轮([cmd?1]+[resp?1]) + 4`（每 payload 按 MSS=1460 上取整分段），**46/46 逐例零误差**（§9.1） | **承前身但需一般化**：前身只给单例速算，本版 §9.1 给可复算式 |
| 7 | T-POP3-1「存量去向（2 例 → 改写后初估 34–36 例）」 | 实际落 **50 例**（37 基线 + 13 补遗） | **前身估算已过期**（文档自身 §P5 补遗段已更正为 50，此处以 JSON 为准） |
| 8 | T-POP3-1 P5 补遗偏差⑥「t037/t039 落盘实测改 **288/206**」 | JSON 实际 frames offset = **396 / 314**（提交 `84cfbe6` 2026-09-17 把附件换成仓库真实 `README.md` 全文后**二次重钉**）；本轮用**校验器同款解析器**（`pcaptest.ParseTsharkHex` + `MatchHexOffset`）复跑三例 frames 断言 **3/3 OK** | **TEST_CASES.md 数字过期**（停在 288/206）；本 106 以 JSON 396/314 为准（G-POP3-7） |
| 9 | T-POP3-1 P5 偏差⑤「离线链套件 34/37（t034/t035/t036 三负例 MCP 层门离线未复刻）」+ 偏差⑥「3 超早拒绝无落盘系旧行为：t024/t035/t036」 | `/tmp/mcp-pcaps/pop3/` **47 个 pcap**；缺 3 个恰为 **t024/t035/t036**；其中 t024/t035/t036 在结果产物 `pop3.md` 表格里 pcap 链接为**空**（`[pcap]()`，Packets=0） | **承前身** ✓（缺盘 = 创建期即拒，早于产流）；登记为 G-POP3-6 |
| 10 | T-POP3-1「t024 改 tcp 层 V9 门字面 `out of range [536,65535]`」 | 锚词实测来自 `layers/complete.go:325`（registry `mss` 字段 `Min:536,Max:65535`，`registry.go:68`），**不是** pop3 planner 的门（planner 的 `MSS %d too small` 走扁平路径） | **承前身** ✓；本版 §7 分列两门 |
| 11 | D-POP3-1 §1「会话表：单 TCP 长连接单会话，无 `sessions[]`（豁免多会话扇出）」 | `POP3Config`（`types.go:6878-6884`）**无 sessions 字段**；`chain_planner.go:949` pop3 分支只注记"源端口 0 保持 0" | **承前身** ✓；多会话=整会话复制（`flow_control.flows`），见 §12.3 |
| 12 | D-POP3-1「validator 真拦 16 分支」（列 15 项 + 隐含一项） | `grep -c "return fmt.Errorf" planner.go` = **16**（实测）；逐行 `:105/:110/:118/:129/:133/:144/:147/:153/:156/:165/:168/:171/:181/:185/:198/:201` | **承前身** ✓；本版 §7 逐行列出 |
| 13 | T-POP3-1「无吞吐/并发/内存目标数字（未测）；网卡未跑」 | 本轮**未跑**套件、未跑网卡；`/tmp/mcp-nic-pcaps/pop3/` 目录存在但**本车道未验证其内容** | **承前身**：性能数字仍为待测边界（§6 不写承诺） |
| 14 | 结果产物 `trafficgen/docs/protocol-pcap-test/pop3.md`（**tracked**）写「Cases: 50 — pass 50, fail 0, error 0」 | 末次提交 `84cfbe6`（**2026-09-17**）**晚于**判死提交 `0417be5`（2026-09-13）→ **不属"过期产物"类**；但 `trafficgen/docs/protocol-pcap-test/pop3/` 目录**根本不存在**（`git ls-files` 0 个 pcap、磁盘 0 个），表格里 47 行的 pcap 链接**全是死链** | **产物结论成立、留档缺失**：47/47 包数本轮已用 `/tmp/mcp-pcaps/pop3/` 逐例复核**全对**（§0 注），但**仓库内无 pcap 留档** → G-POP3-6（归属代码阶段） |

**依赖链判定纪律**：以上均为可判题（前身文 → 代码/pcap/JSON 三级对照），直接判定，不问偏好。不可判的（真服务器线字节、空闲定时器行为）标"待确认/明确不解决"并写清处置（G-POP3-2/G-POP3-11）。

**产物复核注（本轮，诚实口径）**：`pop3.md` 的 50 行包数（47 行非零 + 3 行 0）已与 `/tmp/mcp-pcaps/pop3/` 的 47 个 pcap 用 `tshark | wc -l` **逐例对账，零差异**；50 例的 `expect.fields`（共 81 条）与 3 条 `frames` 断言已用**校验器同款解析器**复跑，**全 OK**。**本车道未跑 MCP suite**，故本文档**不以"今日已跑通"形式**引用 `pop3.md` 的 50/50——它是**产物文件**，其"pass"字面来自 2026-09-17 的跑批，本轮只做了**离线断言复核**（口径与 101-opcua G-OPCUA-10 的区分一致：此处**不是**过期产物，是**无 pcap 留档**）。

## 1. 范围、profile 与实现状态边界

本版定义 **POP3（RFC 1939）承载于 TCP 110** 的流量生成：可选服务器问候（banner）、命令/响应回放（AUTHORIZATION → TRANSACTION → UPDATE 三态剧本）、多行响应（点填充 + `.` 终止）、信箱合成响应（RETR 式 maildrop / TOP 式截取）、MIME multipart 正文、POP3S（TLS 承载，端口 995）。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `pop3_tcp_v1`（主） | TCP，fixture 110 | banner → 命令/响应对 → FIN | 真实服务器语义（信箱是否存在、口令是否正确、状态机是否合法） |
| `pop3s_tls_v1` | `[ip,tcp,tls,pop3]`，fixture 995 | 同上，明文 POP3 字节**被 tls 层封装为 application_data** | 真实 TLS 握手细节、证书校验、STLS 原地升级 |
| `pop3_ipv6_v1` | 同上，仅外层 IPv6 | 同上 | 从 IPv4 fixture 推导 IPv6 地址 |

显式边界（"不实现、不声称、不许静默转换"）：① **不 enforce 状态机**——AUTHORIZATION/TRANSACTION/UPDATE 三态**只体现在文档与剧本顺序上**，引擎对错序命令**照发不拦**（§5，架构选择）；② **不实现 STLS 原地升级**——`STLS` 只作为台词命令（RFC 2595 §3 的 `+OK` 与后续 `-ERR` 由用户 Response 原文承载）；③ **不实现真实认证**——`AUTH PLAIN/LOGIN/CRAM-MD5` 是台词轮次，不产 challenge 校验（§3.7）；④ **不计算 APOP 摘要**——`computeAPOPDigest` 是导出的 helper（`planner.go:695`），**planner 从不调用**，摘要由用户原文提供；⑤ **不做空闲 autologout**——RFC §3 的 ≥10 分钟定时器无时钟不断言（G-POP3-11）；⑥ **不校验多行响应终止符**——`Multiline=true` 时响应**原样发**，用户漏写 `.\r\n` 引擎不补（§3.4，G-POP3-4）；⑦ **不实现 UIDL 自动生成**——`POP3Message.UID` 为空则 planner 不补（`types.go:6949-6952` 注释口径）；⑧ **不实现 UID 唯一性/持久性语义**——RFC §7 的跨会话持久性无法在单流生成中表达。

**实现状态（2026-09-29 实测）**：`pop3` 层已注册（`registry.go:1580`，`CategoryTerminal`，`DependsOn ["tcp"]`，`OptionalOn ["tls"]`，Fields 3 键）；planner/builder/生成器已落码（`internal/protocol/pop3/` 五文件 3574 行）；`allowedProtocols["pop3"]=true`（`protocols.go:51`）；层内 translate 已接线（`chain_planner_translate.go:2634`）；扁平 convert 已接线（`strategy_convert.go:1273`）；presence 判死已落（`strategy_convert.go:8837`）；缺省目的端口 110（`chain_planner.go:1206`）；空导入（`cmd/server/main.go:130`）；50 语义用例已落 `cases/pop3.json`。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`、`tcp.flags`、`pop.request.*`、`pop.response.*`、frames 原始 hex offset 54/74）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, pop3]`（引擎自动补 `ip`；最小链 `[tcp, pop3]`）。POP3 报文是 TCP payload 的**文本字节流**，**由 tcp 层负责握手/seq-ack/挥手/MSS 分段**（pop3 层是**纯事件生产者**，`layer_gen.go` 只 `EmitMsg`，不产 TCP 语义帧）。

端口：POP3 默认 **TCP 110**（RFC 1939 §3 原文「the server host starts the POP3 service by listening on TCP port 110」）。缺省由 `registry.go:1582` 的 `FieldContract {"tcp.dst_port":"110"}` + `chain_planner.go:1206` 的 `case "pop3": spec.DstPort = 110` 双路补齐；POP3S = **995**（显式写，用户值优先，不强制 110——`FieldContract` 注释口径）。fixture 统一 `src_port=13000`（除 t046 双流走保底 12345/12346）。

固定偏移：无 VLAN/IP options/TCP options 时，**每帧 POP3 载荷起点为 IPv4 offset 54**（14+20+20）、**IPv6 offset 74**（14+40+20）。多行响应内的行偏移由 §3.3 的拼接规则递推。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**本协议存量 50 例已是此形，无需迁移**）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 13000, "dst_port": 110}},
    {"pop3": {
      "banner": "+OK POP3 server ready",
      "commands": [
        {"cmd": "USER alice", "response": "+OK alice"},
        {"cmd": "PASS secret", "response": "+OK Logged in"},
        {"cmd": "QUIT", "response": "+OK bye"}
      ]
    }}
  ]
}
```

POP3S 形（`OptionalOn: tls` 启用；t032）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 13000, "dst_port": 995}},
    {"tls": {}},
    {"pop3": {"banner": "+OK POP3 server ready", "commands": [{"cmd": "USER alice", "response": "+OK alice"}]}}
  ]
}
```

多流样例（数量只走 `flow_control`；t046 用）：

```json
{
  "layers": [{"ip": {}}, {"tcp": {}}, {"pop3": {}}],
  "flow_control": {"flows": 2}
}
```

## 3. 线格式编码（逐字段；出处 = RFC 1939 章节 + 代码行）

### 3.1 命令（client → server）

RFC 1939 §3 原文钉死：命令 = **大小写不敏感关键字** + 可选参数，**全部以 CRLF 结尾**，关键字与参数由**单个 SPACE** 分隔，关键字 **3 或 4 字符**，**每个参数至多 40 字符**。

| 项 | 值 | 出处 |
|---|---|---|
| 编码 | ASCII 文本 | RFC §3 |
| 行终止 | `CRLF`（`0d 0a`） | RFC §3 |
| 关键字长度 | 3–4 字符 | RFC §3 |
| 参数上界 | 40 字符/参数 | RFC §3 |
| **引擎追加行为** | `cmd.Cmd + "\r\n"`（`layer_gen.go:54`、`planner.go:343`）——**用户不写 CRLF** | 代码 |
| **空 Cmd** | **跳过命令包**（只发响应；服务端单轮，用于 AUTH 的 `+` challenge） | `layer_gen.go:53` |

**总长度公式**：`len(Cmd) + 2` 字节。

### 3.2 响应（server → client）

RFC 1939 §3 原文钉死：响应 = **状态指示符** + 关键字 + 可选附加信息，**以 CRLF 结尾**，**响应至多 512 字符（含 CRLF）**，状态指示符**只有两个**：正向 `+OK`、负向 `-ERR`，且「Servers **MUST** send the `+OK` and `-ERR` in **upper case**」。

| 项 | 值 | 出处 |
|---|---|---|
| 状态指示符 | `+OK` / `-ERR`（**大写强制**） | RFC §3 |
| 响应上界 | 512 字符含 CRLF | RFC §3 |
| **单行模式**（`Multiline=false`，默认） | `Response + "\r\n"`（`layer_gen.go:74-76`） | 代码 |
| **多行模式**（`Multiline=true`） | `Response` **原样发**（用户自带终止符 `\r\n.\r\n`） | `layer_gen.go:73` |
| **空 Response** | **跳过响应包**（客户端单轮） | `layer_gen.go:72` |

**总长度公式**：单行 `len(Response)+2`；多行 `len(Response)`。

### 3.3 多行响应与点填充（dot-stuffing）——负例锚词主要来源

RFC 1939 §3 原文（逐字）：多行响应在首行 + CRLF 之后逐行发送，**每行以 CRLF 结尾**；全部行发完后发一行「**终止八位组**（十进制 046，`.`）+ CRLF」；「If **any line** of the multi-line response **begins with the termination octet**, the line is **"byte-stuffed"** by **pre-pending the termination octet** to that line」；故多行响应以**五个八位组 `CRLF.CRLF`** 终止。客户端侧：行首是终止八位组且后面**跟 CRLF** 则响应结束（该行不算内容）；跟**其他八位组**则剥掉行首那一个终止八位组。

**引擎实现**（`writeDotStuffedBody`，`planner.go:630-643`；`buildMailDropResponse`，`:434-476`）：

| 步骤 | 输出 | 代码行 |
|---|---|---|
| ① 状态行 | `+OK <size> octets\r\n`（`fmt.Fprintf(&b, "+OK %d octets\r\n", size)`） | `:458` |
| ② 每头 | `<header>\r\n`（**头部不点填充**） | `:461-464` |
| ③ 空行 | `\r\n`（头/体分隔） | `:467` |
| ④ 体逐行 | 行首 `.` → **再补一个 `.`**；行尾统一 `\r\n` | `:637-641` |
| ⑤ 终止行 | `.\r\n` | `:473` |

**长度公式**：`len("+OK ") + digits(size) + len(" octets\r\n") + Σ(len(h)+2) + 2 + Σ(len(stuffed_line)+2) + 3`。`size` 取值：`msg.Size > 0` 用用户值，否则 **= `len(bodyText)`（仅体字节，不含头与空行）**（`:451-454`；t038 实测 `+OK 0 octets` 即空体验证）。

**规范化细节**（影响字节级断言）：体按 `strings.TrimRight(bodyText, "\r\n")` 去尾后按 `\n` 切行、每行 `TrimRight("\r")`（`:634-636`）——**输入的行尾形态（`\n`/`\r\n`/无）被统一为 CRLF**，故 §3.3 的 `body: ".dotline\nnormal"` 在线上是 `.dotline\r\n` + `..` 前缀。空体（`len(bodyText)==0`）**直接返回**，不写任何体行（`:631-633`）。

**头部不点填充的依据**（诚实声明）：RFC §3 原文只对「multi-line response 的任意行」给规则，未显式豁免头部；本实现按「点填充是**消息体**的传输层关注点，头部是 RFC 5322 元数据、合法头部不以 `.` 开头」处理（`planner.go:429-433` 注释口径）。**该口径未在 RFC 找到显式反例，也未找到显式支持**——登记为 G-POP3-4 的子项（今日无用例覆盖"头部以 `.` 开头"）。

### 3.4 服务器问候（banner）

RFC 1939 §4 原文：TCP 连接建立后服务器发**一行问候**，「This can be any **positive** response」。APOP 服务器须在问候里带 **timestamp**（RFC §7：`msg-id` 形态、每次必须不同）。

| 项 | 值 | 代码 |
|---|---|---|
| 触发 | `POP3Config.Banner != ""`（空 = **整段跳过**） | `layer_gen.go:44` |
| 方向 | **down**（server → client） | `layer_gen.go:45` |
| 字节 | `Banner + "\r\n"` | `layer_gen.go:45` |
| 时序 | 握手 ACK 之后、第一个命令之前 | `layer_gen.go:44-48` |

### 3.5 信箱合成响应（RETR 式，`EmitMailDrop`）

触发：`cmd.EmitMailDrop == true` 且 `Mailbox != nil`（`layer_gen.go:62`）。**优先级高于用户 `Response`**。`MsgNum` 是 **1-based**，取 `Mailbox.Messages[MsgNum-1]`。

**MIME multipart 路径**（`msg.MIMEParts` 非空时，`planner.go:441-446`）：

| 项 | 规则 | 代码 |
|---|---|---|
| 体 | `buildMultipartBody(parts, boundary)` 取代 `msg.Body` | `:566-610` |
| 头 | `buildMIMEHeaders` **前插两行**：`MIME-Version: 1.0`、`Content-Type: multipart/mixed; boundary="<B>"`，再接用户 headers | `:541-548` |
| 分界符 | 每段 `--<B>\r\n` + 段头 + `\r\n` + 段体；收尾 `--<B>--\r\n` | `:571-608` |
| 段体 | `BodyB64` 非空**优先**（原样发，不解码）；否则 `Body` | `:585-588` |
| 段体行尾规范化 | 已 `\r\n` 结尾→原样；仅 `\n`→去 `\n` 补 `\r\n`；无尾→补 `\r\n`（**防空行**） | `:595-603` |
| 默认边界 | `Boundary` 空 → **确定性常量** `----=_POP3_BOUND_0001`（不用随机，保测试可复现） | `:617-622` |
| 点填充 | **在整段拼装完的体上**统一施加（含分界符与段内容）——点填充是 POP3 传输层关注点，不是 MIME 关注点 | `:469-470` |

### 3.6 截取合成响应（TOP 式，`EmitTop`）

触发：`cmd.EmitTop == true` 且 `Mailbox != nil`（`layer_gen.go:67`）。RFC 1939 §7 TOP 原文：「sends the headers of the message, the blank line separating the headers from the body, and then the number of lines of the indicated message's body」；若请求行数**大于**体行数则发**整封**。

| 项 | 规则 | 代码 |
|---|---|---|
| 状态行 | `+OK\r\n`（**无 size**，与 RETR 式不同） | `:505` |
| 头 | 用户 `msg.Headers` 逐行 + CRLF（**MIME 头不在此路径前插**） | `:508-511` |
| 空行 | `\r\n` | `:514` |
| 体行 | 取**前 `topLines` 行**；`topLines=0` → **仅头**，空行后直接终止行 | `:517-530` |
| 行首点填充 | 同 §3.3（`strings.HasPrefix(line,".")` → 补 `.`） | `:524-526` |
| 终止行 | `.\r\n` | `:533` |

`TopLines` 语义：RFC §7 的 `n` 参数；`0` = 头后直跟终止点（RFC 原文 `TOP 1 0` 语义）。

### 3.7 命令表（RFC §9 逐字 + 引擎行为）

RFC §9 原文给出的**最小命令集**与**可选命令集**（逐字）：

| 命令 | RFC §9 状态归属 | 参数 | 引擎行为 |
|---|---|---|---|
| `USER name` | AUTHORIZATION | name（≤40 字符，§3/§7） | 回放；校验 name 长度（`:179-182`） |
| `PASS string` | AUTHORIZATION | string（≤255 字符，引擎取 `MaxPasswordLen`） | 回放；校验长度（`:183-186`） |
| `APOP name digest` | AUTHORIZATION（可选） | name + **16 八位组 MD5 的 32 位小写 hex** | 回放；校验摘要**长度=32**（`:197-199`）且**可 hex 解码**（`:200-202`） |
| `QUIT` | AUTHORIZATION 与 TRANSACTION | 无 | 回放；AUTHORIZATION 态退出**不进 UPDATE**（RFC §6） |
| `STAT` | TRANSACTION | 无 | 回放；`+OK nn mm` 形态（RFC §5「+OK followed by a single space, the number of messages…a single space, and the size of the maildrop in octets」） |
| `LIST [msg]` | TRANSACTION | 可选 msg | 回放；无参=多行 scan listing，带参=单行 |
| `RETR msg` | TRANSACTION | msg | 回放 / `EmitMailDrop` 合成 |
| `DELE msg` | TRANSACTION | msg | 回放 |
| `NOOP` | TRANSACTION | 无 | 回放 |
| `RSET` | TRANSACTION | 无 | 回放 |
| `TOP msg n` | TRANSACTION（可选） | msg + n | 回放 / `EmitTop` 合成 |
| `UIDL [msg]` | TRANSACTION（可选） | 可选 msg | 回放（**不自动生成 UID**） |
| `CAPA` / `STLS` / `AUTH` | **RFC 1939 之外**（RFC 2449 / RFC 2595） | — | **台词覆盖**，真机制不实现 |

**引擎不做命令白名单**：`FOO bar` 照发（t041 断 `-ERR unknown command` 台词）。命令名的 `switch` **只用于长度/格式校验**（`planner.go:178-204`），未知命令**不报错**。

### 3.8 状态机（三态，RFC §3/§4/§5/§6 逐条）

RFC §3 原文定义：连接打开 + 服务器发完问候 → 进入 **AUTHORIZATION**；客户端成功标识自己 → 进入 **TRANSACTION**；客户端发 `QUIT` → 进入 **UPDATE**，服务器释放资源、道别、**关闭 TCP 连接**。

| 状态 | 进入条件 | 合法命令（RFC §9 逐字） | 退出条件 | 引擎建模 |
|---|---|---|---|---|
| **AUTHORIZATION** | TCP 建连 + 问候发出 | `USER` / `PASS` / `APOP` / `QUIT` | 认证成功 → TRANSACTION；`QUIT` → **直接终止（不进 UPDATE）** | **不建模**：banner 事件后即视为已在该态 |
| **TRANSACTION** | 认证成功 + 信箱加锁打开 | `STAT` / `LIST` / `RETR` / `DELE` / `NOOP` / `RSET` / `QUIT` / `TOP` / `UIDL` | `QUIT` → UPDATE | **不建模**：命令序列原样回放 |
| **UPDATE** | TRANSACTION 态收到 `QUIT` | **无**（服务器删标记信、解锁、关连接） | 连接关闭 | **不建模**：`QUIT` 的响应 + tcp 层 FIN 四包承载 |

**非法转移逐条（RFC 要求 vs 本引擎）**：

| # | 非法转移 | RFC 1939 要求 | 本引擎行为 | 用例证据 |
|---:|---|---|---|---|
| 1 | AUTHORIZATION 态发 `STAT`/`LIST`/`RETR`/`DELE`/`NOOP`/`RSET`/`TOP`/`UIDL` | §3「A server **MUST** respond to a command issued when the session is in an incorrect state by responding with a **negative** status indicator」→ `-ERR` | **照发**（不拦、不自动补 `-ERR`） | 无用例（A′ 立项，G-POP3-3） |
| 2 | TRANSACTION 态发 `USER`/`PASS`/`APOP` | 同上 → `-ERR` | **照发**（**有**用例，断言"照发"） | **t004**（`pop.request.command=USER` 在事务态出现两次） |
| 3 | UPDATE 态发任意命令 | 连接已关，无命令面 | 不建模 | — |
| 4 | 未认证直接 `QUIT` | §6 原文「if the client issues the QUIT command from the AUTHORIZATION state, the POP3 session terminates but does **NOT** enter the UPDATE state」→ 合法，`+OK` | **照发**（合法路径，**非**非法转移） | **t047**（`+OK` → `QUIT` → `+OK`） |
| 5 | 未识别/未实现/语法非法命令（如 `FOO`） | §3「A server MUST respond to an unrecognized, unimplemented, or syntactically invalid command by responding with a **negative** status indicator」→ `-ERR` | **照发**（**有**用例，断 `-ERR` 台词） | **t041**（`FOO bar` → `-ERR unknown command`） |
| 6 | 引用已删信/越界信（`RETR 5` 而只有 2 封） | §5/§7 `-ERR no such message` | **照发**（**有**用例，断 `-ERR` 台词） | **t007**（`LIST 5` → `-ERR no such message, only 2 messages`）、t009、t043/t044（合成路径越界走 **validator 真拦**） |

**架构声明（诚实边界）**：`planner.go` 包注释逐字——「The planner does **NOT** enforce POP3 state-machine transitions. The user is responsible for providing a syntactically valid dialog (USER before PASS, STAT/LIST/RETR/DELE only after authentication, QUIT to end). This matches the trafficgen contract: **synthesize test packets, not a real POP3 server**.」故非法转移 1/2/5/6 的 `-ERR` **由用户 Response 原文承载**（台词版），引擎侧**零自动派生**。

**引擎实际的"状态"**：仅两个隐式标记，且都不用于拦截——① `Banner != ""` 决定是否产第一帧 down；② `Commands[]` 的数组顺序决定事件顺序。**无状态变量、无状态转移函数**。

### 3.9 事件序列与包数（可复算）

`Generate`（`layer_gen.go:30-84`）产出的事件序列（**逐 wire 帧一个事件**，不含 TCP 语义帧）：

```
[banner(down)]  ×(Commands 逐条: [cmd(up)] [resp(down)])
```

其中 `[cmd(up)]` 在 `cmd.Cmd==""` 时**缺席**，`[resp(down)]` 在三种合成条件都不满足时**缺席**。

**tcp 层补齐**：`RegisterLayerValidator`（`layer_gen.go:112-125`）**强制**写 `spec.TCP.Handshake=true` + `spec.TCP.Termination=true`（legacy planner 恒产握手/挥手；`spec.TCP` 零值 false 会让 tcp 层跳过——smtp/redis 同款陷阱）。

**单流包数公式**（**46/46 例 pcap 逐例零误差**，§9.1）：

```
packet_count = 3（握手） + [banner? 1 : 0]
             + Σ_{每命令轮}（ [cmd 非空? 1 : 0] + [resp 存在? ceil(len(resp_bytes)/MSS) : 0] ）
             + 4（挥手 FIN 四包）
MSS = 1460（默认；tcp 层 mss 字段，registry.go:68）
ceil(x/MSS) 对 x=0 也取 1（空载荷仍发一帧，`segmentByMSS` 口径 `planner.go:657-659`）
```

`resp_bytes` 长度：单行 = `len(Response)+2`；多行 = `len(Response)`；`EmitMailDrop` = `len(buildMailDropResponse(msg))`；`EmitTop` = `len(buildTopResponse(msg, n))`。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明 banner 与命令/响应序列，引擎按数组顺序逐条产出事件（banner → 命令对 → 挥手由 tcp 层补），**不做状态机推进、不做响应码决策**。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 默认会话冒烟 | banner → USER/PASS → QUIT | t001 |
| ② 授权三形 | USER+PASS / APOP 一条 / 空 USER 跳过 | t002/t003/t004 |
| ③ 事务态取信 | STAT → LIST（多行）→ RETR → QUIT | t005/t006/t008/t020 |
| ④ 取信失败 | LIST/RETR 越界 `-ERR` | t007/t009 |
| ⑤ 删信与撤销 | DELE → RSET → DELE | t010 |
| ⑥ 截取与标识 | TOP（前 N 行 / N=0 仅头）、UIDL（多行/单行） | t011/t049/t012 |
| ⑦ 扩展协商 | CAPA 列表、STLS 台词、AUTH 三机制 | t021/t022/t023 |
| ⑧ 长保活 | 3×NOOP | t027 |
| ⑨ 异常断线 | RETR 后无 QUIT（tcp 照常 FIN） | t026 |
| ⑩ 大信下载 | MIME 双附件 / 纯附件 / 空正文（MSS 分段） | t037/t039/t038 |
| ⑪ 现网三家 | Gmail（995 + `recent:` 用户名）/ Outlook（995）/ Dovecot（问候+CAPA+QUIT 原文） | t028/t029/t030 |
| ⑫ 密文承载 | POP3S 995 经 tls 层 | t032 |
| ⑬ 新网段 | IPv6 | t033 |
| ⑭ 多流 | 全缺省 `flows=2` | t046 |
| ⑮ 复合流 | 登录 + STAT + RETR + DELE + QUIT 一条流 | t031 |

**五层覆盖逐层结论**：

- **功能层**：RFC §9 全部 12 个最小+可选命令**逐一有例**（USER/PASS/APOP/STAT/LIST/RETR/DELE/NOOP/RSET/TOP/UIDL/QUIT）；RFC 2449/2595 扩展（CAPA/STLS/AUTH）**台词版各一例**；正例 35 条 + 负例 15 条（配置/线格式/状态机/关联/长度/载体六类齐，§7）。
- **性能层**：MSS 分段（t037/t039 实测 4 段下载）；单帧上界（`MaxMessages=100000` 信、`MaxUIDLen=70`）；无吞吐/并发/内存数字（**待测边界**，§6 不写承诺）。
- **数据场景层**：空信箱（t005 `+OK 0 0`）/ 单信（t048 `+OK 1 100`）/ 多信（t006/t012）/ 空正文（t038 `+OK 0 octets`）/ 点填充（t013）/ MIME multipart 双附件（t037）/ 纯附件无正文（t039）/ 越界（t007/t043/t044）/ 超长（t014/t015/t018）/ 非 hex 摘要（t019）。
- **地址与流层**：**IPv4 与 IPv6 独立用例**（t033 v6，offset 74）；**单流基线**（全正例）；**多流**（t046 `flows=2`，保底 src_port 12345/12346）；**流关联（控制流派生数据流）显式不适用**——POP3 是**单 TCP 连接承载全部命令与信件**，无 FTP PASV 式副连接（RFC 1939 无数据通道概念）；**多会话（`sessions[]`）显式不适用**——`POP3Config` 无 `sessions` 字段（`types.go:6878-6884`），多会话由策略级 `flow_control.flows` 整会话复制承载（§12.3）。
- **业务层**：⑮ 场景全部有落点（上表）；现网三家（Gmail/Outlook/Dovecot）**映射地板线**——问候/命令原文照抄，**不对接真服务器**。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① 真实状态机 enforcement（§3.8，架构选择）；② STLS 原地升级（RFC 2595 §3，G-POP3-2）；③ 真实 AUTH 机制（challenge/response 校验）；④ APOP 摘要计算（helper 存在但 planner 不调用）；⑤ 空闲 autologout 定时器（RFC §3 ≥10 分钟，无时钟）；⑥ UID 跨会话持久性（RFC §7，单流不可表达）；⑦ 多行响应终止符校验（verbatim 契约，G-POP3-4）。

## 5. 消息/事务模型与状态机（驱动与交互规格）

**事务定义**：一次命令 + 一次响应（一问一答）。**多事务** = 一个连接内多对按序执行：t004（5 对）、t020（6 对）、t031（6 对）。

**驱动规格**（逐条）：

| # | 规则 | 代码行 |
|---:|---|---|
| 1 | 事件按 `Commands[]` **数组顺序**逐条产出，**不交错** | `layer_gen.go:51` |
| 2 | banner 若非空，**先于所有命令**产出（down） | `layer_gen.go:44-48` |
| 3 | 命令包（up）在 `Cmd != ""` 时产出；`Cmd == ""` **跳过命令包**（服务端单轮） | `layer_gen.go:53` |
| 4 | 响应包（down）优先级：`EmitMailDrop`（需 Mailbox）> `EmitTop`（需 Mailbox）> `Response != ""`；**三者互斥由上到下短路** | `layer_gen.go:61-80` |
| 5 | `Multiline=false`（默认）→ 响应**追加 CRLF**；`true` → **原样发** | `layer_gen.go:73-76` |
| 6 | `Response == ""` 且非合成 → **跳过响应包**（客户端单轮） | `layer_gen.go:72` |
| 7 | TCP 握手（3 包）/ 挥手（4 包）/ seq-ack / MSS 分段 / ipID / Timestamp **全部由 tcp 层生成器产**——pop3 层**零 TCP 语义帧**（防双握手） | `layer_gen.go:16-22` 注释 |
| 8 | `spec.TCP.Handshake` / `Termination` **被 validator 强制校准 true**（防链上零值 false 导致跳过） | `layer_gen.go:119-124` |
| 9 | `cfg == nil`（空层 config）→ 默认化 `&POP3Config{}` = **空会话**（无 banner、无命令） | `layer_gen.go:36-38` |

**自动派生规则汇总**：① `\r\n` 后缀（命令恒加；单行响应恒加）；② 点填充（合成路径）；③ 终止行 `.\r\n`（合成路径）；④ MIME 头前插两行 + 默认边界（MIME 路径）；⑤ `+OK <size> octets` 状态行（`EmitMailDrop`）；⑥ `+OK` 状态行（`EmitTop`）；⑦ TCP 握手/挥手（tcp 层）；⑧ 缺省端口 110（链级 FieldContract）。**除此之外零自动派生**——无状态机补帧、无 `-ERR` 自动生成、无重试/重连。

**确定性**：同一配置必然同一输出（无随机、无时钟依赖）。**唯一非确定项**在 tcp 层（随机 ISN、随机 ipID），pop3 层零随机（`resolveBoundary` 用固定常量而非随机，`planner.go:617-622`）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流包数由 §3.9 公式给出，**无上界承诺**（`Commands` 数组长度不受限，唯 `Mailbox.Messages` 受 `MaxMessages=100000` 守卫）；单帧上界 = TCP MSS（默认 1460）+ 各层头；分段数 = `ceil(payload/MSS)`。**吞吐/并发/内存数字未测 → 本版不写承诺**（诚实边界，与 D-POP3-1 §6 一致）。
- **依据**：事件序列**流式产出**（`Generate` 逐帧 `EmitMsg`，**不聚合**——`layer_gen.go:39-81` 逐事件 emit）；每帧内存 = 该帧 payload（最大 = 一封信的合成体，受 `MaxMessages`/MSS 间接约束）；**无跨流共享状态**；**无锁**（生成器无状态，`POP3Generator struct{}` 空结构）。
- **验收两路（§6.3 强制）**：pcap（`/tmp/mcp-pcaps/pop3/<id>.pcap`、负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）**共用同一断言集**；断言实际 `pop.request.*`/`pop.response.*` 字段、frames 原始 hex 与 `packet_count`，**不只断言"任务没报错"**。
- **六类场景落点（§6.6）**：基线（t001，14 帧）/ 目标规模（t031 复合流 20 帧、t010 删信 20 帧）/ 压力上限（t037 双附件 19 帧含 4 段 MSS 分段）/ 长时间运行（t027 三 NOOP 承载长保活语义）/ 并发交错（**单流顺序，无并发**——多流走 `flow_control` 整会话复制，t046）/ 背压（`packet_count` 精确计数守卫帧数漂移 + `MaxMessages`/`MaxUIDLen` 上界守卫）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 **validator / 链级门** 拒绝并传播为 task error，**不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功**（t012b/t014–t019/t042–t045 实测 pcap 均 **0 帧**；t024/t035/t036 **无落盘**= 创建期即拒）。

**A 组：pop3 planner 门（`planner.go`，锚词逐字）**

| # | 负例 ID | 故障输入 | 代码锚词 | 代码行 |
|---:|---|---|---|---|
| N-1 | `pop3_t014_user_toolong_reject` | `USER ` + 41 字符（>40） | `pop3: Commands[%d].USER name length %d exceeds max %d (RFC 1939 §6)` | `:181` |
| N-2 | `pop3_t015_pass_toolong_reject` | `PASS ` + 256 字符（>255） | `pop3: Commands[%d].PASS password length %d exceeds max %d (RFC 1939 §6)` | `:185` |
| N-3 | `pop3_t016_cmd_crlf_reject` | `Cmd = "USER a\r\nDELE 1"` | `pop3: Commands[%d].Cmd %q contains CRLF (command injection per RFC 1939 §3)` | `:144` |
| N-4 | `pop3_t017_resp_crlf_reject` | `Multiline=false` 且 `Response` 含 CRLF | `pop3: Commands[%d].Response contains CRLF but Multiline=false; set Multiline=true for multi-line responses` | `:147` |
| N-5 | `pop3_t018_uid_toolong_reject` | `Mailbox.Messages[0].UID` 71 字符（>70） | `pop3: Mailbox.Messages[%d].UID length %d exceeds max %d (RFC 1939 §7 UIDL)` | `:133` |
| N-6 | `pop3_t019_apop_bad_digest_reject` | `APOP alice NOTHEX!`（7 字符） | `pop3: Commands[%d].APOP digest length %d, must be %d hex chars (RFC 1939 §6)` | `:198` |
| N-7 | `pop3_t012b_emit_top_no_mailbox_reject` | `emit_top=true` 无 `mailbox` | `pop3: Commands[%d].EmitTop=true but Mailbox is nil` | `:168` |
| N-8 | `pop3_t042_maildrop_no_mailbox_reject` | `emit_mail_drop=true` 无 `mailbox` | `pop3: Commands[%d].EmitMailDrop=true but Mailbox is nil` | `:153` |
| N-9 | `pop3_t043_maildrop_msgnum_range_reject` | `emit_mail_drop` + `msg_num=5`（信箱 1 封） | `pop3: Commands[%d].MsgNum %d out of range [1, %d]` | `:156` |
| N-10 | `pop3_t044_top_msgnum_range_reject` | `emit_top` + `msg_num=3`（信箱 1 封） | `pop3: Commands[%d].MsgNum %d out of range [1, %d]` | `:171` |
| N-11 | `pop3_t045_emit_both_exclusive_reject` | `emit_mail_drop=true` **且** `emit_top=true` | `pop3: Commands[%d].EmitTop and EmitMailDrop are mutually exclusive` | `:165` |

**B 组：链级/框架门（非 pop3 planner）**

| # | 负例 ID | 故障输入 | 代码锚词 | 代码位置 |
|---:|---|---|---|---|
| N-12 | `pop3_t024_mss_reject` | `tcp.mss=100`（<536） | `out of range [536,65535]` | `layers/complete.go:325`（registry `mss` `Min:536`，`registry.go:68`） |
| N-13 | `pop3_t034_bad_ip_reject` | `ip.dst="not-an-ip"` | `invalid IP address: not-an-ip` | 框架 ip 层门 |
| N-14 | `pop3_t035_presence_reject` | `layers:[…]` **与**顶层 `pop3:{}` 并存 | `rejects a top-level pop3 sub-config` | `strategy_convert.go:8839`（`CheckProtoFlat` pop3 分支） |
| N-15 | `pop3_t036_static_pinned_reject` | 显式标量四元组 + `flows=2` + 无动态逃生 | `layers pin a static four-tuple but flows > 1` | `schema/semantic.go:285`（`checkLayerChainStaticCopy`） |

**锚词口径**：`error_contains` 是**子串**判定；15 例逐条命中上表（机读实测，§9.2）。

**负例原子性**：每例**单一**故障注入；单次执行不得混注。**A 组 11 例全部走 `Planner.Validate`**（经 `RegisterLayerValidator` 从链上调用，`chain_planner.go:317`），**B 组 4 例在 pop3 validator 之前/之外**（链级门先于协议校验；t035 的 presence 门在 `CheckProtoFlat`，早于链解析）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：
- `pop3: SrcIP %q is not a valid IP address`（`:105`）——链形状下地址住 `ip` 层，此门走**扁平路径**（今日无扁平用例，G-POP3-3）；
- `pop3: DstIP %q is not a valid IP address`（`:110`）——同上；
- `pop3: MSS %d too small (min %d per RFC 879)`（`:118`）——同上（链上 mss 由 `complete.go` 先拦，见 N-12）；
- `pop3: Mailbox has %d messages, max %d`（`:129`）——**需 100001 封信**才触发，成本不可接受（T-POP3-1 §明确不列缺口已登记）；
- `pop3: Commands[%d].APOP digest %q must be hex`（`:201`）——**与 N-6 同例**（N-6 的 `NOTHEX!` 长 7 ≠ 32，先命中长度门 `:198`；非 hex 门需**32 字符非 hex** 输入，今日零用例 → A′ 补 `pop3_neg_apop_digest_nonhex`）。

**不得误报的合法协议事件**：`-ERR` 台词（t007/t009/t017 之外的 t040/t041/t022）；`FOO` 未知命令（t041）；事务态 `USER`（t004）；无 `QUIT` 断线（t026）；空 `Cmd`（t002）；空 `Response`；`Multiline=true` 原样响应（t006/t012/t020/t030）；`TOP 1 0`（t049）；空正文（t038）；POP3S 995（t032）；IPv6（t033）。

## 8. 边界

- **包数**：由 §3.9 公式给出，**无固定上界**；实测跨度 10（t047 最短：3 握手 + banner + QUIT 对 + 4 挥手）到 21（t032 POP3S 含 7 帧 TLS）与 20（t010/t020/t027/t031）。
- **响应长度**：RFC §3 上界 **512 字符含 CRLF**——**引擎不校验**（`Response` 原样发，无 512 门）→ A′ 立项（G-POP3-3）。
- **参数长度**：RFC §3 上界 **40 字符/参数**——引擎**只对 USER/PASS 校验**（`MaxUsernameLen=40`/`MaxPasswordLen=255`），**其余命令的参数不校验**（如 `LIST`/`RETR`/`DELE`/`TOP` 的 msg 参数、`APOP` 的 name）→ 边界不完整（G-POP3-3）。
- **边界相邻值**：`USER`=40 / `PASS`=255 / `UID`=70 / `APOP digest`=32 的**合法上界**今日**零用例**（只有 +1 越界负例）→ A′ 补 4 例（G-POP3-3）。
- **MSS 分段**：`segmentByMSS`（`planner.go:652-669`）；分段数 = `ceil(len/MSS)`；空载荷仍发 1 帧（`:657-659`）。**无 MSS 变更下的分段数断言**（t037/t039 只用默认 1460）→ A′（G-POP3-12）。
- **信箱规模**：`MaxMessages=100000`（`:72`）；`UID` ≤70（`:81`）。**上界本身零用例**（触发成本不可接受，T-POP3-1 已登记）。
- **端口**：显式 110 全正例；**995** 显式（t032）；**缺省 110 无独立用例**（t046 全缺省断 `packet_count` 但**不断 `tcp.dstport=110`**）→ A′（G-POP3-3）。
- **地址族**：v4/v6 独立用例（t033 为 IPv6）；异族混写拒绝无例 → A′。
- **多流**：`flows=2`（t046）断 `packet_count=14` + `has_handshake`，**不断两流四元组不同**（src_port 12345/12346 未进 fields）→ A′（G-POP3-14）。
- **响应码**：`+OK`/`-ERR` 大写（RFC §3 MUST）——引擎**不校验用户 Response 的大小写**（台词版）；t007/t041 用 `-ERR`，t022 用 `-ERR`，其余 `+OK`。

## 9. 原子 ID 与完成定义（**50 个唯一语义 ID = 35 正 + 15 负**，顺序为权威）

### 9.1 逐例表（ID / 类型 / 覆盖 / 实测包数）

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
| 13 | `pop3_t012b_emit_top_no_mailbox_reject` | 负 | §7 N-7 | —（0 帧） |
| 14 | `pop3_t013_dot_stuffing` | 正 | §3.3：点填充（`.dotline` → `..dotline`） | 16 |
| 15 | `pop3_t014_user_toolong_reject` | 负 | §7 N-1（41>40） | —（0 帧） |
| 16 | `pop3_t015_pass_toolong_reject` | 负 | §7 N-2（256>255） | —（0 帧） |
| 17 | `pop3_t016_cmd_crlf_reject` | 负 | §7 N-3（命令注入） | —（0 帧） |
| 18 | `pop3_t017_resp_crlf_reject` | 负 | §7 N-4（单行响应 CRLF） | —（0 帧） |
| 19 | `pop3_t018_uid_toolong_reject` | 负 | §7 N-5（71>70） | —（0 帧） |
| 20 | `pop3_t019_apop_bad_digest_reject` | 负 | §7 N-6（摘要 7≠32） | —（0 帧） |
| 21 | `pop3_t020_rfc10_sequence` | 正 | RFC §10 官方序列全文抄（USER/PASS/STAT/LIST/RETR/QUIT） | 20 |
| 22 | `pop3_t021_capa` | 正 | RFC 2449 CAPA 台词 | 16 |
| 23 | `pop3_t022_stls` | 正 | RFC 2595 STLS 台词（授权态 +OK / 事务态 -ERR） | 12 |
| 24 | `pop3_t023_auth` | 正 | RFC 2595 AUTH 三机制台词（PLAIN/LOGIN/CRAM-MD5） | 16 |
| 25 | `pop3_t024_mss_reject` | 负 | §7 N-12（mss=100<536） | —（无落盘） |
| 26 | `pop3_t025_two_retr` | 正 | §5 多事务①：同连接两 RETR | 18 |
| 27 | `pop3_t026_abort_no_quit` | 正 | §5 多事务②：无 QUIT 断线 | 14 |
| 28 | `pop3_t027_keepalive_noop` | 正 | §5 多事务③：3×NOOP 长保活 | 20 |
| 29 | `pop3_t028_gmail` | 正 | §4 场景⑪：Gmail 形（`recent:` 用户名） | 14 |
| 30 | `pop3_t029_outlook` | 正 | §4 场景⑪：Outlook 形 | 14 |
| 31 | `pop3_t030_dovecot` | 正 | §4 场景⑪：Dovecot 形（CAPA 7 项多行） | 16 |
| 32 | `pop3_t031_composite` | 正 | §4 场景⑮：复合流（6 动作一条流） | 20 |
| 33 | `pop3_t032_pop3s_995` | 正 | §1/§2：POP3S 995 经 tls 层 | 21 |
| 34 | `pop3_t033_v6` | 正 | §2：IPv6 承载（offset 74） | 14 |
| 35 | `pop3_t034_bad_ip_reject` | 负 | §7 N-13 | —（0 帧） |
| 36 | `pop3_t035_presence_reject` | 负 | §7 N-14（顶层 pop3 presence） | —（无落盘） |
| 37 | `pop3_t036_static_pinned_reject` | 负 | §7 N-15（静态复制） | —（无落盘） |
| 38 | `pop3_t037_mime_multi_attach` | 正 | §3.5 MIME 双附件 + MSS 4 段 | 19 |
| 39 | `pop3_t038_empty_body_retr` | 正 | §3.3 size=0（`+OK 0 octets`） | 16 |
| 40 | `pop3_t039_attach_only` | 正 | §3.5 纯附件无正文 | 19 |
| 41 | `pop3_t040_pass_auth_failed` | 正 | §3.8 非法转移 #2 变体：PASS `-ERR` 台词 | 14 |
| 42 | `pop3_t041_unknown_command` | 正 | §3.8 非法转移 #5：`FOO` → `-ERR` 台词 | 16 |
| 43 | `pop3_t042_maildrop_no_mailbox_reject` | 负 | §7 N-8 | —（0 帧） |
| 44 | `pop3_t043_maildrop_msgnum_range_reject` | 负 | §7 N-9 | —（0 帧） |
| 45 | `pop3_t044_top_msgnum_range_reject` | 负 | §7 N-10 | —（0 帧） |
| 46 | `pop3_t045_emit_both_exclusive_reject` | 负 | §7 N-11 | —（0 帧） |
| 47 | `pop3_t046_default_twoflow` | 正 | §2/§12.12：全缺省 `flows=2` | 14 |
| 48 | `pop3_t047_quit_bare` | 正 | §3.8 非法转移 #4（合法路径）：未登录直接 QUIT | 10 |
| 49 | `pop3_t048_list_single` | 正 | §3.7：LIST 单封单行 `+OK 1 100` | 16 |
| 50 | `pop3_t049_top_zero_lines` | 正 | §3.6：TOP N=0 仅头 | 16 |

**统计**：50 = **35 正 + 15 负**；负例 = A 组 11 + B 组 4。

**包数公式校验（§3.9 逐例）**：46 例有落盘者**全部**用公式重算并比对实测 pcap，**零误差**；t032 = 公式 14 + tls 层 7 帧 = 21 ✓；t046 = 2 × 空会话 7 帧 = 14 ✓；3 例无落盘（t024/t035/t036，创建期拒）。

### 9.2 负例锚词实测表（15 例逐条）

| ID | `error_contains`（JSON 原文） | 命中代码锚词 | 组 |
|---|---|---|---|
| `pop3_t012b_emit_top_no_mailbox_reject` | `but Mailbox is nil` | `:168` | A |
| `pop3_t014_user_toolong_reject` | `USER name length` | `:181` | A |
| `pop3_t015_pass_toolong_reject` | `PASS password length` | `:185` | A |
| `pop3_t016_cmd_crlf_reject` | `contains CRLF` | `:144` | A |
| `pop3_t017_resp_crlf_reject` | `Multiline=false` | `:147` | A |
| `pop3_t018_uid_toolong_reject` | `UID length` | `:133` | A |
| `pop3_t019_apop_bad_digest_reject` | `APOP digest` | `:198` | A |
| `pop3_t024_mss_reject` | `out of range [536,65535]` | `complete.go:325` | B |
| `pop3_t034_bad_ip_reject` | `invalid IP address: not-an-ip` | 框架 ip 层 | B |
| `pop3_t035_presence_reject` | `rejects a top-level pop3 sub-config` | `strategy_convert.go:8839` | B |
| `pop3_t036_static_pinned_reject` | `static` | `semantic.go:285` | B |
| `pop3_t042_maildrop_no_mailbox_reject` | `EmitMailDrop=true but Mailbox is nil` | `:153` | A |
| `pop3_t043_maildrop_msgnum_range_reject` | `out of range` | `:156` | A |
| `pop3_t044_top_msgnum_range_reject` | `out of range` | `:171` | A |
| `pop3_t045_emit_both_exclusive_reject` | `mutually exclusive` | `:165` | A |

**注**：t043/t044 的锚词同为 `out of range`，但**分属不同代码分支**（`:156` MailDrop / `:171` TOP），删除任一例即失去一条独立分支的直接证据（§7 原子性）。

### 9.3 `pop.*` tshark 字段通道（本机 3.6.14 实测，19 字段）

`tshark -G fields` 中 `pop.*` 共 **19** 字段（机读实测）。今日 50 例**只用 4 个**：

| 字段 | 类型 | 语义 | 今日用例 |
|---|---|---|---|
| `pop.request.command` | FT_STRING | 请求命令字（如 `USER`/`QUIT`/`FOO`） | 25 例 |
| `pop.request.parameter` | FT_STRING | 请求参数（如 `alice`/`1`/`1 2`） | t001/t048 等 |
| `pop.response.indicator` | FT_STRING | 状态指示符（`+OK`/`-ERR`） | 26 例 |
| `pop.response.description` | FT_STRING | 状态行描述（如 `0 0`/`1 100`/`5 octets`） | t005/t048/t038 等 |

**未收编字段（A′ 立项，G-POP3-1）**：
- `pop.request.data` / `pop.response.data`：**多行体的后续行**。**实测陷阱**：`pop.response.data` 的 **`show` 值为空串**（PDML 实测 `show=""`，只有 `value` 是 hex）——`-T fields` 下恒输出空，**不能用于断言多行体内容**；多行体内容断言**必须走 `frames` 原始 hex**（t006 帧 10 的 `1 100`/`2 200`/`.` 三行在 PDML 里是三个 `pop.response.data` 元素，位置 70/77/84）。
- `pop.response.tot_len.invalid`（FT_NONE）：512 上界违规标记——**引擎不产违规响应**，故无用例。
- `pop.data.fragment*`（9 字段）：DATA 分片重组，POP3 无 DATA 阶段，**不适用**。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | TCP 客户端主动建连，服务器监听 **110**（§3 逐字） | 场景①–⑮ | `DependsOn ["tcp"]` + `FieldContract tcp.dst_port=110`（`registry.go:1580-1582`）；tcp 层产握手/挥手 | 无 |
| 2 | 命令/消息表 | §9：最小 10 + 可选 3（USER/PASS/QUIT/STAT/LIST/RETR/DELE/NOOP/RSET/APOP/TOP/UIDL） | 场景②–⑦ | 引擎**无命令白名单**（未知命令照发，`:178-204` 只做长度/格式校验） | 命令表覆盖齐（§3.7） |
| 3 | 状态机 | 三态 AUTHORIZATION→TRANSACTION→UPDATE（§3–§6）+ 非法转移 MUST `-ERR`（§3） | 场景②③⑨ | **不建模**（架构选择，§3.8） | 非法转移 1/2/5/6 无自动 `-ERR` → **明确不解决**（G-POP3-2）；非法转移 #1 无用例 → A′ |
| 4 | 字段表 | §3：命令 CRLF 终止 / 参数≤40 / 响应≤512 / `+OK`/`-ERR` 大写 / 点填充 `CRLF.CRLF` | 数据场景层 | `layer_gen.go:53-79` + `planner.go:630-643` | 512 上界与 40 参数上界**未全量校验** → A′（G-POP3-3） |
| 5 | 错误处理 | 15 类负例（§7）+ 5 个未入例分支 | 负例 A/B 组 | 16 个 planner 门（`:105…:201`）+ 4 个链级门 | A′ 5 条（G-POP3-3） |
| 6 | 超时与活性 | §3：空闲 autologout 定时器 **≥10 分钟**（MAY） | 场景⑧（NOOP 长保活） | 无时钟，不断言 | **明确不解决**（G-POP3-11）；NOOP 保活语义由 t027 承载 |
| 7 | NAT/代理/被动 | 无被动模式概念（客户端直连） | — | 无 `sessions[]`/被动端口 | **显式不适用**被动模式；NAT 穿透为框架面 |
| 8 | 版本/方言 | RFC 1939 唯一 profile；RFC 2449 CAPA / RFC 2595 STLS+AUTH 为扩展 | 场景⑦⑪ | CAPA/STLS/AUTH 台词覆盖；`OptionalOn ["tls"]` 支持 POP3S | STLS 真升级 → **明确不解决**（G-POP3-2）；AUTH 真机制 → 同上 |

### 10.2 子表①：命令 × 响应码矩阵（逐格已覆/立项/不适用）

RFC §9 命令表 12 项 × 3 列（正例 / `-ERR` 台词 / validator 真拦）：

| 命令 | 正例（`+OK`） | `-ERR` 台词（回放） | validator 真拦 |
|---|---|---|---|
| USER | 覆 t001/t004 | **A′ 立项**（G-POP3-3；离线 `1_1_3` 无 pcap） | 覆 t014（>40） |
| PASS | 覆 t001/t040 | 覆 t040（`-ERR [AUTH] Authentication failed`） | 覆 t015（>255） |
| APOP | 覆 t003 | A′ 立项 | 覆 t019（摘要非法） |
| STAT | 覆 t005（`+OK 0 0`） | 不适用（RFC §5 无 `-ERR` 面） | 不适用 |
| LIST | 覆 t006/t048 | 覆 t007（越界） | 不适用 |
| RETR | 覆 t008/t013/t026/t037/t038/t039 | 覆 t009（无此信） | 覆 t043（合成越界） |
| DELE | 覆 t010 | A′ 立项（RFC §5 有 `-ERR message already deleted`） | 不适用 |
| NOOP | 覆 t027 | 不适用（无失败分支） | 不适用 |
| RSET | 覆 t010 | 不适用 | 不适用 |
| QUIT | 覆 t001/t047 等 | A′ 立项（RFC §6 有 `-ERR some deleted messages not removed`） | 不适用 |
| TOP | 覆 t011/t049 | A′ 立项（RFC §7 `-ERR no such message`） | 覆 t012b/t044 |
| UIDL | 覆 t012 | A′ 立项（RFC §7 `-ERR no such message`） | 覆 t018（UID>70） |
| CAPA/STLS/AUTH（扩展） | 覆 t021/t022/t023 | 覆 t022（事务态 STLS `-ERR Must issue STLS first`） | 不适用（台词版） |

**逐格重数（39 格逐格归类，零空格）**：

| 列 | 覆 | A′ 立项 | 不适用 | 小计 |
|---|---:|---:|---:|---:|
| 正例（`+OK`） | 13 | 0 | 0 | 13 |
| `-ERR` 台词（回放） | 4 | 6 | 3 | 13 |
| validator 真拦 | 6 | 0 | 7 | 13 |
| **合计** | **23** | **6** | **10** | **39** |

39 = 23 + 6 + 10 ✓ 每格恰归一类，**无"未处置"格**。

**逐格点名列**（与本表同源，机读枚举）：

- **正例列 13 格全覆**：USER(t001/t004) / PASS(t001/t040) / APOP(t003) / STAT(t005) / LIST(t006/t048) / RETR(t008/t013/t026/t037/t038/t039) / DELE(t010) / NOOP(t027) / RSET(t010) / QUIT(t001/t047) / TOP(t011/t049) / UIDL(t012) / CAPA-STLS-AUTH(t021/t022/t023)。
- **台词列覆 4**：`PASS`(t040) / `LIST`(t007) / `RETR`(t009) / `CAPA/STLS/AUTH`(t022)。
- **台词列立项 6**：`USER`（授权态 `-ERR` 无例，离线 `1_1_3` 无 pcap）/ `APOP`（认证失败台词无例）/ `DELE`（RFC §5 `-ERR message already deleted` 无例）/ `QUIT`（RFC §6 `-ERR some deleted messages not removed` 无例）/ `TOP`（RFC §7 `-ERR no such message` 无例）/ `UIDL`（同上无例）。
- **台词列不适用 3**：`STAT` / `NOOP` / `RSET`（RFC §5 三者均只给 `+OK`，无失败响应面）。
- **真拦列覆 6**：`USER`(t014 >40) / `PASS`(t015 >255) / `APOP`(t019 摘要非法) / `RETR`(t043 合成越界) / `TOP`(t012b 无信箱 + t044 越界) / `UIDL`(t018 >70)。
- **真拦列不适用 7**：`STAT` / `LIST` / `DELE` / `NOOP` / `RSET` / `QUIT` / `CAPA/STLS/AUTH`——`LIST`/`DELE`/`QUIT` 的越界或失败面属**回放台词**（不设 validator 门，已入台词列），`STAT`/`NOOP`/`RSET` RFC 无失败面，扩展行不实现机制。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **22 行**：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | banner 空（跳过问候） | **A′ 立项**（`layer_gen.go:44` 分支；t046 走空配置但断言不覆盖 banner 缺失） |
| 2 | banner 非空 | 覆（t001 等 47 例） |
| 3 | banner 含 APOP timestamp | 覆（t003 `<1896.697170952@dbc.mtview.ca.us>`、t028 `1.2.3.4 abc`） |
| 4 | 空 `Cmd`（服务端单轮） | 覆（t002） |
| 5 | 空 `Response`（客户端单轮） | **A′ 立项**（`layer_gen.go:72` 分支今日无例） |
| 6 | 单行响应（自动补 CRLF） | 覆（全正例） |
| 7 | 多行响应（`Multiline=true` 原样） | 覆（t006/t012/t020/t030） |
| 8 | 多行响应缺终止符 | **A′ 立项**（verbatim 契约，G-POP3-4） |
| 9 | 点填充（体行首 `.`） | 覆（t013） |
| 10 | 头部以 `.` 开头 | **A′ 立项**（本实现不点填充头部，G-POP3-4） |
| 11 | `EmitMailDrop` 合成 | 覆（t008/t013/t026/t031/t037/t038/t039） |
| 12 | `EmitTop` 合成 | 覆（t011/t049） |
| 13 | `EmitTop` + `TopLines > 体行数` | **A′ 立项**（RFC §7「发整封」分支） |
| 14 | `TopLines=0`（仅头） | 覆（t049） |
| 15 | 空正文（size=0） | 覆（t038） |
| 16 | 显式 `Size > 0` | **A′ 立项**（`planner.go:451-452` 分支） |
| 17 | MIME multipart 多段 | 覆（t037 双段、t039 单段） |
| 18 | `BodyB64` 非空（优先于 Body） | 覆（t037/t039） |
| 19 | 自定义 `Boundary` | **A′ 立项**（`resolveBoundary` 用户值分支） |
| 20 | 默认边界 `----=_POP3_BOUND_0001` | 覆（t037/t039 未写 boundary） |
| 21 | `UID` 非空 | 覆（t008/t031 等）；**UID 空（不自动生成）** → A′ 立项 |
| 22 | MSS 分段（大信） | 覆（t037/t039 各 4 段） |

**重数（机读逐行取末列）**：覆 **14** + A′ 立项 **8** = 22 ✓（行 21「`UID` 非空」含覆与半立项两态，机读按含"立项"计为立项，故覆 14 / 立项 8）。

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | Gmail POP（`pop.gmail.com:995` 强制 SSL + `recent:` 模式） | t028 | 覆（**地板线**：问候/用户名原文） |
| 2 | Outlook（`outlook.office365.com:995` SSL/TLS） | t029 | 覆（地板线） |
| 3 | Dovecot（问候 `+OK Dovecot ready.` / CAPA 7 项 / QUIT `+OK Logging out.`） | t030 | 覆（地板线，已亲验原文） |
| 4 | 大批量下载（多封 RETR + DELE） | t010/t031 | 覆 |
| 5 | 断点续传式截取（TOP 前 N 行） | t011/t049 | 覆 |
| 6 | 客户端长驻轮询（NOOP 保活） | t027 | 覆 |
| 7 | 扩展协商（CAPA） | t021 | 覆 |
| 8 | 明文升密文（STLS） | t022 | 覆（**台词版**） |
| 9 | 备用认证（AUTH PLAIN/LOGIN/CRAM-MD5） | t023 | 覆（**台词版**） |
| 10 | POP3S 直连 995 | t032 | 覆 |
| 11 | 真实 TLS 握手/证书校验 | — | **明确不解决**（tls 层职责，本层零断言） |
| 12 | 真实 STLS 原地升级 | — | **明确不解决**（G-POP3-2） |
| 13 | 真实 AUTH challenge/response 校验 | — | **明确不解决**（G-POP3-2） |
| 14 | APOP 摘要计算 | — | **明确不解决**（helper 存在，planner 不调用） |
| 15 | 服务端状态机 enforcement | — | **明确不解决**（G-POP3-2） |
| 16 | 空闲 autologout | — | **明确不解决**（G-POP3-11） |
| 17 | UID 跨会话持久性 | — | **明确不解决**（单流不可表达） |
| 18 | 真实信箱/口令校验 | — | **明确不解决**（生成器不连服务器） |

10 覆 + 8 明确不解决 = 18 ✓ 无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比

三路：① **规范原文**（RFC 1939 §3/§4/§5/§6/§7/§9/§10/§11 + RFC 2449/2595/879/6528；本轮已用 `rfc1939.txt` 原文逐条核对章节归属，**纠正了 T-POP3-1 中把 `QUIT` 的 AUTHORIZATION 态细则系于 §6 的表述**——原文在 **§4 末**给该细则，§6 只给 TRANSACTION→UPDATE 的细则）；② **商业化软件实际行为**（**部分取到**：Gmail/Outlook/Dovecot 的问候与 CAPA 原文来自 T-POP3-1 记载与 Dovecot 亲验，**未抓真服务器包**→ 地板线，G-POP3-2 待确认项）；③ **可靠开源实现思路**（Dovecot 的 `login_greeting` 缺省值、RFC §7 UIDL 的 `msg-number SP unique-id` 格式——只借鉴"UIDL 行格式钉死"这一条）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `pop3` 终结层（本版；smtp/imap 同构先例） | 事件流 + 合成响应 + 校验门可声明可断言；代价 = 一套层（已落码 3574 行） | **采用** |
| B | 直接 tcp 层 + 顶层 payload | 无 banner/无命令对/无合成响应 → 50 例中 45 例不可表达 | **否决** |
| C | 在 pop3 层内实现真状态机 enforcement | 会与"回放语义"架构选择冲突（用户剧本可能故意错序，t004 正是该形态） | **否决**（G-POP3-2 明确不解决） |

## 11. P2 D-POP3-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 状态说明：实现已落码（`internal/protocol/pop3/` 五文件），本 P2 条目为 P-PIPE 批次二文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:6878-7000` 区段 + `:1850`） | `POP3Config`/`POP3Command`/`POP3Mailbox`/`POP3Message`/`POP3MIMEPart` + `FlowSpec.POP3` 槽位 | —（共享文件） |
| `trafficgen/internal/protocol/pop3/planner.go` | `Validate`（16 门）+ `Plan`（legacy 回放，含自产握手/挥手）+ 合成函数（maildrop/TOP/MIME/dot-stuffing/分段/synOptions）+ `computeAPOPDigest` | 698 |
| `trafficgen/internal/protocol/pop3/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator` + `RegisterLayerValidator`，`init()`）+ 握手/挥手校准 | 126 |
| `trafficgen/internal/protocol/pop3/planner_test.go` | 37 个 `Test*`（编码面 + Validate 面） | 737 |
| `trafficgen/internal/protocol/pop3/planner_testpoints_test.go` | 75 个 `TestPOP3Point_*`（RFC 章节 → 测试点） | 1275 |
| `trafficgen/internal/protocol/pop3/planner_mime_test.go` | 21 个 `Test*`（MIME multipart 面） | 738 |
| 接线 8 处 | registry 注册（`layers/registry.go:1580`）/ translate 层内分支（`chain_planner_translate.go:2634`）/ convert 子配置搬运 + 缺省端口（`strategy_convert.go:1273-1285`）/ presence 判死（`strategy_convert.go:8837-8841`）/ 源端口注记（`chain_planner.go:949`）/ 缺省端口（`chain_planner.go:1206`）/ protocols 准入（`protocols.go:51`）/ 空导入（`cmd/server/main.go:130`） | — |

**层内/扁平双路**：`chain_planner_translate.go:2634-2648` 的 `case "pop3"` 在 `spec.POP3 != nil` 时**直接 return**（**扁平权威**，层 config 忽略）；否则 `completedConfig`（registry 3 键缺省）+ `json.Marshal`/`Unmarshal` 往返解码为 `core.POP3Config`（**与扁平 `parsePOP3Config` 同 JSON 键、零语义分叉**）。空层 config → 翻译出**非 nil 空 config**（生成器对 nil 也已走默认，双保险）。

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`planner.go:101`）：只读，**不默认化**（默认化归 `Plan`/`validateSpecBase`）；`spec.POP3 == nil` 时**早退通过**（`:122-124`），故空配置默认流合法。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`:213`）：**legacy 回放路径**（自产 TCP 握手/挥手，`:310-382`），**今日链上不用**（链走 `layer_gen.go` 事件模式，防双握手）。
- 生成器：`Name() "pop3"`；`GenEvents()` 返回自身；`EmitEvent` 未接线显式错（防误调，`layer_gen.go:104-106`）；`Generate` 逐帧 `EmitMsg`（`layer_gen.go:30-84`）。

### 11.3 数据结构

`POP3Config{Banner, Commands[], Mailbox}`（`types.go:6878-6884`；**MSS 不在此**——注释明写「MSS is governed by `TCPConfig.MSS`」，`:6882-6883`）。
`POP3Command{Cmd, Response, Multiline, EmitMailDrop, EmitTop, TopLines, MsgNum}`（`:6887-6934`，7 键）。
`POP3Mailbox{Messages[]}`（`:6940-6942`）。
`POP3Message{UID, Headers[], Body, MIMEParts[], Boundary, Size}`（`:6945-6988`，6 键）。
`POP3MIMEPart{Headers[], Body, BodyB64}`（`:6993-7000`，3 键）。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry Fields 3 键 allowlist）→ translate（层内 config → `spec.POP3`）→ `Planner.Validate`（16 门）→ 生成器 `Generate`（banner → 命令/响应对）→ **worker**（tcp 层补握手/挥手/seq-ack/MSS 分段）→ writer（PCAP/NIC）。

### 11.5 错误分支

16 个 planner 门（`:105…:201`）+ 4 个链级门（§7 B 组）全部传 task error（**零假成功**——11 例 A 组负例实测 0 帧；3 例 B 组负例无落盘 = 创建期拒）。

**未入例的 5 条**：`:105`/`:110`（坏 IP，扁平路径）/`:118`（MSS 太小，扁平路径）/`:129`（信箱超 10 万，成本不可接受）/`:201`（APOP 非 hex，被长度门先拦）→ A′ 立项（G-POP3-3）。

### 11.6 性能边界

见 §6（事件流式产出、per-flow 局部状态、无跨流共享、无锁；吞吐数字待测，**不写承诺**）。

### 11.7 与现有逻辑的冲突点

- `CheckProtoFlat`（`strategy_convert.go:8625` 起）**已有 pop3 分支**（`:8837-8841`，锚词 `rejects a top-level pop3 sub-config`）——与 opcua 的"无分支"不同，**本协议 presence 门已落**（t035 有例）。
- **顶层未知键通用门仍缺**：游离顶层键（如 `{layers:[…], bogus: 1}`）今日**不判死**（`CheckProtoFlat` 只查五键 + 各协议子映射白名单）→ **不建该负例**（建了会真绿 = 假通过），登记 G-POP3-9（框架面，等 unknown-key 白名单）。
- 动态 allowlist（`internal/core/layer_dyn.go` 头部）：`pop3` **零命中**实测（`grep -c` = 0）→ 业务字段动态对象即拒；四元组 `ip`/`tcp` 全开。见 §12.12。
- registry `pop3` 有 Fields 3 键 → 层内 `banner`/`commands`/`mailbox` 今日可住；`POP3Config` 的 **MSS 无层内键**（走 `tcp.mss`），**无孤儿键**。
- **legacy `Plan` 与事件模式并存**：`Plan`（`planner.go:213`）仍自产 TCP 握手/挥手，**链上不走**；若误接会**双握手**——`layer_gen.go:16-22` 注释显式记录该 divergence。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 5 文件 + 接线 8 处（registry/protocols/translate/convert/chain_planner×2/main.go）；不触及其他协议。cases 回滚 = 恢复 50 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 50/50 顶层键 = `{layers}`（t035 为 presence 负例，**故意**带顶层 `pop3:{}`）；目标形状见 §2 且**存量已达标** | §12.1；`cases/pop3.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 pop3 流量模板；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（终结层）/时间线。有长连接（单 TCP 会话），**不豁免多事务** | §12.3 + §5 |
| §4 查规范 | RFC 1939 §3/§4/§5/§6/§7/§9/§10/§11 原文 + RFC 2449/2595/879/6528 + tshark 3.6.14 字段与 47 例 pcap 实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["tcp"]` + `OptionalOn ["tls"]`（`registry.go:1580-1581`）；16+4 门；失败传 task error（11 例 0 帧 + 3 例无落盘实测） | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待测，不写承诺；pcap/NIC 两路验收明写） | §6 |
| §7 三份文档 | `106-pop3-{design,testcase}.md` v1.0.0（本对）+ D-POP3-1（`CODE_DESIGN.md:1341`，历史层）+ T-POP3-1…（`TEST_CASES.md:2839`，历史层）+ 50 ID（testcase §2） | 修订记录 |
| §8 设计先行 | 本 as-built 定稿先于后续任何改动；门1 获批 = 本契约定稿 | 提交序 |
| §9 测试三源 | 三源 = RFC 1939/2449/2595/879/6528（§10）+ D-POP3-1（§11）+ tshark 3.6.14 字段与 47 例 pcap 实测（**已到抓包级**：81 条 field 断言 + 3 条 frame 断言逐条复核 OK）；50 ID 逐项回指；存量审计去向 testcase §8 | `106-pop3-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 批次二文档轨自审（脚本机读，见修订记录）+ 收官隔离复审；红先绿后 | 自审日志 |
| §11 白话 | 本文首节白话一句先行 | 本文头注 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段 3 项逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `pop3` 已在 `registry.go:1580` 注册（**不新增层**）；生成表 127 层同代（`fields` 3 键与 registry 逐键一致，机读实测）；**改动 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `pop.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/pop3/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/pop3.json` | 50 | **`{layers}` ×49** + `{layers, pop3}` ×1（t035，presence 负例） | `[ip,tcp,pop3]` ×49 + `[ip,tcp,tls,pop3]` ×1（t032） | 15/15 = `{expect_error, error_contains, notes}` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 本协议从未用过顶层地址；已住 `layers[0].ip.{src,dst}`（50/50） |
| `src_port` | **0** | 已住 `layers[i].tcp.src_port`（显式 13000；t046 走保底 12345+i） |
| `dst_port` | **0** | 已住 `layers[i].tcp.dst_port`（110 ×48、995 ×1；t046 走缺省 110） |
| `count` | **0** | 走 `flow_control`（t046 用 `strategy_fc {type:flows,value:2}`） |
| 顶层 `pop3` 子映射 | **1** | t035 为 **presence 负例**（`{layers:[…], pop3:{}}`，**判死形状，故意保留**）；其余 49 例已住 `layers[i].pop3` |
| `strategy_fc` / `flow_control` | **2** | t036（负例，`flows=2` 触发 static 门）、t046（正例，双流） |

**结论**：**本协议存量 50/50 顶层零残留**（唯一顶层 `pop3` 键在 t035 是**负例的判死输入**，不是残留）——§1 门的动作 = ①**无旧键可删**；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测 49/49 非负例顶层仅 `layers`）；③A′ 新增例全部沿用纯 layers 形（§13）。

**注意形状判读（与 presence 负例口径一致）**：`t035` 是「**层链 + 顶层空子映射并存 = 判死负例**」形状（不是残留）——汇报时必须点名此形状，避免被误读为"顶层残留 1 例"。

目标形状样例见 §2（顶层仅 `layers`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"pop3":{}}` **今日会被拒**（`CheckProtoFlat` 有 pop3 分支，`:8837`）→ **已有例 t035** ✓（与 opcua G-OPCUA-1 的"无分支不建例"相反）。
- ② 白名单外游离键判死（`unknown field`）今日**无通用门** → **不建例**（建了会真绿 = 假通过）→ G-POP3-9。
- ③ 15 例负例**每条带锚词**（已齐，§9.2）✓。
- ④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）✓。

### 12.3 §3 强制展开：五件套

**会话表**：`s1` 单 TCP 长连接单会话（全 50 例；各自四元组，banner → 命令/响应对 → tcp 层 FIN 四包）。**无 `sessions[]` 数组**（`POP3Config` 无该字段）——**多会话由策略级 `flow_control.flows` 整会话复制承载**（t046：两流，src_port 保底 12345/12346，**各 7 帧、状态不串用**）。

**事务序列**：`t1` 建连握手（tcp 层 3 包）/ `t2` 问候（banner，down，可空）/ `t3` 命令轮（`[cmd(up)]` + `[resp(down)]`，逐条按数组序；空 Cmd 跳过命令包=服务端单轮，空 Response 跳过响应包=客户端单轮）/ `t4` 关闭（`QUIT` 的响应 + tcp 层 FIN 四包）。每事务四件事（前置/触发/成功/失败）见 §5 驱动规格表 + §3.8 状态机表。

**关联关系**：**无派生流**（诚实声明：POP3 是单 TCP 连接承载全部命令与信件，**无 FTP PASV 式副连接**、无 `driven_by` 锚定——RFC 1939 全文无数据通道概念）。`EmitMailDrop`/`EmitTop` 的合成响应**在同一连接同一命令轮内**产出，不派生新连接。

**插入位置**：终结层（`[ip,tcp,pop3]`，无中间层）；POP3S 形 `[ip,tcp,tls,pop3]`（tls 为可选底座，`OptionalOn`）。

**时间线**：消息内严格顺序（命令 → 响应）；命令轮按数组序展开；**无交错**（`concurrent` 为例外路径不启用）；多流为**整会话复制**（t046 两流串行）。

**豁免声明**：**有长连接载体（TCP）→ `sessions[]` 不豁免**——本协议的"多会话"面由 `flow_control.flows` 承载（形态差异已声明）；**多事务三项（多轮/异常断线/长保活）各至少一例**（t025/t026/t027），**未豁免**。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src`/`ip.dst`、`tcp.src_port`/`tcp.dst_port` **五策略全开**（allowlist `internal/core/layer_dyn.go:140/149` 实测：`ip` 三键 `src`/`dst`/`ttl`、`tcp` 两键 `src_port`/`dst_port`；`eth` 两键）；保底 `DefaultSrcPort+i`（t046 实测 12345/12346）；dst 动态与 110 缺省和平共处（显式/动态值非零即不触发补齐）。

**业务字段 3 项全关**（allowlist 无 `pop3` 行，`grep -c "pop3" layer_dyn.go` = **0** 实测；对象即拒 `does not support dynamic`）：

| 字段 | 动态 | 理由 |
|---|---|---|
| `banner` | **关** | 问候语无逐流变需求；逐流变会破坏 APOP timestamp 语义（客户端须解析） |
| `commands` | **关** | **序列语义**——数组是事件序列本身，逐流变会破坏事务顺序与索引 |
| `mailbox` | **关** | maildrop 静态信箱；逐流变破坏 RETR/UIDL 的**确定性**（同 MsgNum 应得同信） |

逐流变体需求列 A′ 候选（testcase §6.2；今日按"不冒充覆盖"口径）。

**序号算法实读**：`parseLayerDyn`（`layer_dyn.go:100` 起）/ `layerDynAllowlist`（同文件头部，**无 pop3 行**）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ 静态复制门（`schema/semantic.go:198` `checkLayerChainStaticCopy`，锚词 `layers pin a static four-tuple but flows > 1`）——**`pop3` 无块**，即层内任何对象值 → `does not support dynamic`。

## 13. P3 对接清单（T-POP3 草稿输入；正文落 testcase 文件）

50 ID（35 正 + 15 负）+ packet_count 公式（§3.9）+ 15 条锚词（§9.2）+ fixture 常量（`10.0.0.1`/`20.0.0.1`/`13000`/`110`/`995`）+ 双通道断言基线（`pop.*` 4 字段 + frames 整帧 hex）+ 存量审计（testcase §2–§5/§8 全量）。

**A′ 候选 16 例**：`pop3_neg_apop_digest_nonhex`（32 字符非 hex）/ `pop3_neg_resp_512`（响应 >512）/ `pop3_user_boundary_40`（USER 名 =40）/ `pop3_pass_boundary_255`（PASS =255）/ `pop3_uid_boundary_70`（UID =70）/ `pop3_apop_digest_boundary_32`（摘要 =32 合法）/ `pop3_default_port`（删 `dst_port` 断缺省 110）/ `pop3_no_banner`（banner 空）/ `pop3_empty_response`（空 Response 客户端单轮）/ `pop3_neg_order_stat`（授权态 STAT，非法转移 #1）/ `pop3_multiline_no_terminator`（多行缺 `.`）/ `pop3_top_lines_overflow`（TOP n > 体行数）/ `pop3_explicit_size`（`Size>0`）/ `pop3_custom_boundary`（自定义 boundary）/ `pop3_segmented_small_mss`（mss=536 分段数）/ `pop3_multi_session_port_assert`（t046 补 `tcp.srcport` 断言）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-POP3-1 | **tshark 字段面未收编**：`pop.request.data`/`pop.response.data`（多行体）今日零使用；**实测陷阱**——该二字段的 `show` 值为**空串**，`-T fields` 恒输出空，**不可用于断言多行体内容**，必须走 `frames` 原始 hex | A′：多行体断言改用 frames（`pop.response.data` 收编**不可行**，已在 §9.3 钉死原因） |
| G-POP3-2 | **状态机不 enforcement**（架构选择）：非法转移 1/2/5/6 无自动 `-ERR`；STLS 真升级 / AUTH 真机制 / APOP 摘要计算 / 真实信箱口令校验全部不实现 | **明确不解决**（回放语义是架构选择，C 类如实注明，不冒充）；非法转移 #1（授权态事务命令）**补台词例** → A′ `pop3_neg_order_stat` |
| G-POP3-3 | **边界相邻值零覆盖**：USER=40 / PASS=255 / UID=70 / APOP digest=32 的**合法上界**无用例（只有 +1 越界）；**响应 512 上界与「参数≤40」未全量校验**（引擎只校验 USER/PASS）；**`LIST` 无 validator 门亦无失败台词立项**（设计 §10.2 真拦列不适用格，越界仅由 t007 台词承载）；缺省端口 110 无独立断言；坏 IP/MSS 两门的**扁平路径**无用例 | A′ 补 8 例（§13 前 7 条 + `pop3_default_port`）；512 与 40 上界的**是否补实现**归 P4 裁定 |
| G-POP3-4 | **多行响应终止符不校验**（`Multiline=true` 原样发，漏 `.` 不报错）；**头部不点填充**（RFC §3 只对"multi-line response 的任意行"给规则，未显式豁免头部——本实现按"点填充是体的关注点"处理，**RFC 无显式支持亦无显式反例**） | A′ 补负例 `pop3_multiline_no_terminator`（若判为应拒则 P4 加门）；头部点填充口径**登记为待确认**（G-POP3-4 子项） |
| G-POP3-5 | **`size` 字段语义无独立断言**：`Size>0` 用用户值、否则 = `len(bodyText)`（**不含头与空行**）——t038 的 frames 断言 `+OK 0 octets` 是唯一 size 面证据 | A′ 补 `pop3_explicit_size`（用户值路径） |
| G-POP3-6 | **3 例无落盘 pcap**（t024/t035/t036，创建期即拒，早于产流——旧行为，非缺陷）；**结果产物 `trafficgen/docs/protocol-pcap-test/pop3.md`（tracked）的 47 行 pcap 链接全是死链**——`trafficgen/docs/protocol-pcap-test/pop3/` 目录**根本不存在**（`git ls-files` 0 个、磁盘 0 个） | **代码阶段**（P5 重跑套件后重生成产物 + 补 pcap 留档）；**本版不删不改**（tracked 产物，删除属 P5 动作）。**注**：该产物末次提交 `84cfbe6`（2026-09-17）**晚于**判死提交 `0417be5`（2026-09-13），故**不属"过期产物"类**——本缺口是「**无 pcap 留档 + 死链**」，**不是**「数字未经复跑」。47/47 包数本轮已用 `/tmp/mcp-pcaps/pop3/` 逐例复核**全对** |
| G-POP3-7 | **TEST_CASES.md 数字过期**：`docs/TEST_CASES.md:2839` P5 补遗偏差⑥记「t037/t039 落盘实测改 **288/206**」，JSON 实际为 **396/314**（`84cfbe6` 换真实 README.md 后二次重钉） | 本 106 以 JSON 为准；TEST_CASES.md 由主线程在其归口批次更正（本车道不碰） |
| G-POP3-8 | **D-POP3-1 行号全漂移**：`registry.go:828`→`:1580`、`strategy_convert.go:788`→`:1273`、`chain_planner_translate.go:1127`→`:2634`、`types.go:6660/6669/6718`→`:6878/6887/6940` | 本 106 §11 已按 HEAD 重钉；CODE_DESIGN.md 由主线程归口更正 |
| G-POP3-9 | **顶层游离键无通用门**：`{layers:[…], bogus:1}` 今日不判死（`CheckProtoFlat` 只查五键 + 协议子映射白名单） | **B′（框架面）**：等框架级 unknown-key 白名单；**不建单协议黑名单分支**（kingbase 记忆裁定）；**不建负例**（建了会真绿） |
| G-POP3-10 | **业务字段动态全关**（allowlist 无 `pop3` 行） | A′ 候选，不冒充已覆盖（§12.12 口径） |
| G-POP3-11 | **空闲 autologout 计时器**（RFC §3 ≥10 分钟）无时钟不断言 | **明确不解决**（C 类；T-POP3-1 已登记） |
| G-POP3-12 | **MSS 分段数无独立断言**：`segmentByMSS` 路径唯一证据是 t037/t039 的默认-MSS 分段；**无"mss 变更 → 分段数变化"用例** | A′ 补 `pop3_segmented_small_mss`（mss=536） |
| G-POP3-13 | **POP3S 明文契约与密文载体分离**：t032 只断 `tcp.dstport=995` + `tls.record.content_type=22`；`pop.*` 在 TLS 下**不可解**（app data 被 tls 层封装）——**无任何应用层断言** | **明确不解决**（tls 层职责）；A′ 可选：t032 补 `tls.app_data` 原始 hex 断明文内容（本轮实测 app_data 字段可用，帧 11–17） |
| G-POP3-14 | **t046 双流断言偏弱**：只断 `packet_count=14` + `has_handshake`，**不断两流四元组不同**（src_port 12345/12346 未进 fields） | A′ 补 `tcp.srcport` 断言（§13 末条） |

## 15. 修订记录

- v1.0.0（2026-09-29）：P-PIPE 批次二文档轨 #106 as-built 定稿。新编号（前身为 `CODE_DESIGN.md` D-POP3-1 + `TEST_CASES.md` T-POP3-1…，本协议**无旧 `NN-pop3-design.md`**）；前身校正 **14 项**（§0，含行号全漂移、TEST_CASES 288/206→396/314 过期、包数公式一般化、产物死链/无留档、t035 presence 形状判读）；RFC 1939 章节归属**用 `rfc1939.txt` 原文逐条核对**（纠正前身把 AUTHORIZATION 态 `QUIT` 细则系于 §6 的表述——原文在 §4 末）；三态状态机 + **非法转移 6 条逐条列出**（§3.8）；点填充/多行终止/`+OK`-`-ERR` 大写逐字段规格（§3.3）；**包数公式**从 46 例 pcap 反推并**逐例零误差验证**（§3.9/§9.1）；50 ID 逐条对账（§9）；15 条锚词逐条对码（§9.2）；`pop.*` 19 字段表 + **`pop.response.data` show 空串陷阱**（§9.3）；P1 八项矩阵 + 子表①②③（§10）；D-POP3-1 as-built 定稿（§11）；门1 十四行 + §12.1/12-P2/12.3/12.12（§12）；缺口 **G-POP3-1…G-POP3-14**（§14）。**自审 6 轮，末轮干净**（`/tmp/pop3_audit2.py` 机读脚本，零 issue：50 ID 顺序/正负类型/包数逐行、15 条锚词逐条对码、**27 处代码行号逐行验字**（planner 16 + layer_gen 11 + registry 4 + complete/semantic/strategy_convert/chain_planner×2/protocols/main/types 12）、§10.2 矩阵 39 格逐格归类 + 合计行对账、§10.3 变体 22 行、§10.4 商业 18 行、§3.8 非法转移 6 行、门1 14 行、缺口 14 条、fields 81 + frames 3 + 行为 70 逐条复跑、公式 46/46、`coverage_gate pop3` 32/32 复跑）。

**自审实际抓出并已修 11 处自伤（全部机读发现，非人工目视）**：①fields 条数误报 108（实 **81**）；②§10.2 逐格重数自创口径「23/7/8 + 未处置 1」（机读实为 **23/6/10，零未处置格**）；③§10.3 变体覆/立项 12/10 与机读 **14/8** 不一致；④testcase §5.2 对账两行沿用②的错误口径（含"未处置 1"）；⑤负例「—」列与实测 **0 帧** 口径未区分（12 行）；⑥`chain_planner.go:1203` 行号错（实 **1206**，1203 是 `case "pop3":`）；⑦`registry.go:1582` 的 FieldContract 行号错（实 **1583**，1582 是 OptionalOn）；⑧`terminates` 计数误报 33（实 **34**）；⑨行为断言条数误报 47（实 **70** = 35+34+1）；⑩"接线 6 处"与实际列出的 **8 项** 不符；⑪§9 标题未含 35/15 分解。
**本轮自审暴露的两条最重要教训**：**(a) 逐格说明段落与合计行必须同源机读**——否则同一节内自相矛盾（②③④ 同一根因）；**(b) 代码行号必须逐行验字，不能凭 grep 行号推断**——⑥⑦ 是"取到了同名 token 的邻近行"的典型误钉。

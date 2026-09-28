# #103 ftp（文件传输协议，RFC 959；扩展 RFC 2428 EPSV/EPRT）设计契约

> 版本：v1.0.0（P-PIPE 文档轨批次二 · as-built 契约）
> 日期：2026-09-29
> 车道：文档轨（#103 ftp 续号）
> 旧基线：**无**。本仓 `docs/protocol-designs/` 下**从未有 ftp 设计文档**（机读实测：`find docs -iname '*ftp*'` 仅命中 `06-tftp-*` 与 `248/54-tftp-248-table.md`，TFTP 是另一协议；`INDEX.md` 亦无 ftp 行）。本契约是 ftp 的**首份设计文档**，不是续号重做——故无"旧稿校正表"，§0 改为**基线继承与既有内部契约声明**。
> 存量用例：`trafficgen/test/protocol_pcap/cases/ftp.json`（**141 例 = 136 正 + 5 负**，机读实测；ID 集合/顺序/包数/断言为本文档 §9 与用例文档 §2 的**唯一权威**）
> 规范基线：① **RFC 959**（File Transfer Protocol，下称 **spec**，§3 线格式/§4.1 命令/§4.2 应答码/§5 状态与序列）；② **RFC 2428**（FTP Extensions for IPv6 and NATs：EPSV §3 / EPRT §4 / 500·522 拒绝 §5）；③ **RFC 879**（TCP MSS 下限 536）；④ 本仓库落码（`internal/protocol/ftp/` + `internal/core/` 接线，§11，as-built 逆向定稿）；⑤ 本机 tshark 3.6.14 `ftp.*` 字段表（33 字段）与 **138 例实测 pcap**（`/tmp/mcp-pcaps/ftp/`，2026-09-27 生成；包数与线字节的唯一权威）；⑥ 既有内部契约：`D-FTP-1…4` 设计条目与 `T-FTP-1…21` 测试点编号（散见于代码注释与用例 summary，本契约首次成文收编）
> 白话一句：**FTP 是"一条命令电话线 + 一条随时另开的搬货通道"——电话线上你一句我一句（USER/PASS/PASV/RETR…），搬货时先在电话里说好在哪个门口见面（227 应答或 PORT 命令报端口），然后单独开一条 TCP 把文件搬过去，搬完在电话里回一句 226。引擎按剧本把这些话和这条副连接逐帧回放出来。**

## 0. 基线继承与既有内部契约声明（门1 必答：基线关系）

### 0.1 与既有内部契约的关系

本协议**无旧设计文档**可承，但**有大量既有内部契约**必须先声明继承关系，避免文档与代码/用例对不上：

| 既有内部条目 | 出处（实测行号/位置） | 本契约去向 |
|---|---|---|
| `D-FTP-1` 多会话形状（每会话一条独立控制连接） | `types.go:2436-2458` 注释、`ftp.go:397-403` 包注释、`layer_gen.go:14-15` | §5.2 会话模型 / §11.3 数据结构 |
| `D-FTP-2` 会话级/命令级动态字段（`src_port_dyn`/`banner_dyn`/`cmd_dyn`/`response_dyn`/`payload_dyn`） | `types.go:2452-2456`、`ftp.go:146-212`（`validateDynFields`）、`ftp.go:558-619`（`hasDynFields`/`resolveTx`） | §12.12 动态清单 / §7 拒绝分支 |
| `D-FTP-3` 层字段动态（`ip.src/dst`、`tcp.src_port/dst_port` 五策略） | `layer_dyn.go:12-72`（allowlist 头注明写"D-FTP-3 §4"）、`layer_dyn.go:369-513`（`checkDynShape`） | §12.12 / §7 |
| `D-FTP-4` RFC 2428 EPSV/EPRT + 地址族排序/异族拒绝 | `ftp.go:744-769`（`scanTxForDataPort` 的 EPSV/EPRT 分支）、`ftp.go:862-914`（`parseEPSVPort`/`parseEPRTPort`）、`layer_dyn.go:483`/`565-576` | §3.6 端口推导 / §7 |
| `T-FTP-1…T-FTP-21` 测试点编号 | 用例 `summary` 字段（机读：T-FTP-2/2b/3/4/5/6/10/10b/11/11b/12/18/19/20/21 共 15 个编号在案） | 用例文档 §2 索引表 + §5.3 对照 |
| 结果产物 `trafficgen/docs/protocol-pcap-test/ftp.md` | tracked（`git ls-files` 可证），末次提交 `711423d`（**2026-09-19**） | §14 G-FTP-1（**产物登记**：数字未经今日复跑 + pcap 留档缺失，见 §0.3） |

### 0.2 三条"文档 vs 实现/cases"冲突的判定（as-built 口径）

按任务书"以 cases + 实现为准写成 as-built，冲突记缺口"：机读实测（2026-09-29）发现 **3 处三方（cases JSON / 结果产物 / 真实 pcap）不一致**，逐条裁定如下，全部登记缺口，**本车道不改代码、不改 cases、不改结果产物**：

| # | 冲突 | 机读证据 | 裁定 |
|---|---|---|---|
| 1 | `ftp_file_source`：JSON `min_packets=26` 且无 `packet_count`，结果产物写 26，**真实 pcap 26 帧**——但 `file_source` 载荷 24 字节**根本没上路**（数据通道只有 7 帧：3 握手 + 4 挥手，无 PSH） | `tshark -r ftp_file_source.pcap`：帧 13–19 全部 `tcp.len=0`；对照 `ftp_abort_bytes`（内联载荷）帧 16 有 `tcp.len=10` | **确认缺陷** → G-FTP-2。根因见 §11.5：用例把 `file_source` 写成 `{"source_type":"literal","content":…}`，而 `parseFileSource`（`strategy_convert.go:1984-2016`）只认 `{"literal":…}`/`{"file":…}`/`{"fill":…}`/`{"random":…}`，全零即返回 nil；`layer_gen.go:254-258` 对 `FileSource==nil` **静默不发射**（`return nil`），非失败 |
| 2 | `ftp_file_source_abort`：JSON `packet_count=26`（结果产物 26，真实 pcap 26）——同一根因，`abort_after_bytes` 也无从生效 | 同上 | **确认缺陷** → G-FTP-2 |
| 3 | `ftp_multiflow_multisession`：JSON `packet_count=70`、结果产物 70、**真实 pcap 70**——但**三方一致 ≠ 模型一致**：该用例 `flows=2`，每流 2 会话，两会话的 `src_port_dyn` 都解析成**同一个值**（41000/41001），故两会话共享同一 TCP 连接 key，包数 = 2×35 = 70 而非"2 流 × 2 会话"应得的 84 | `tshark -r ftp_multiflow_multisession.pcap`：帧 1–35 与 36–70 端口序列完全同构，每流仅 **2 条** TCP 连接（41000、41001）而非 4 条 | **设计语义与用例文案不符，包数三方自洽**：用例 `notes` 已自陈"同一流内两个会话共享流序号解析出同值（D-FTP-2 §3 索引域：流内多会话共用 i）"，**已按真实行为钉住**；故**不是缺陷**，是**已声明的语义边界** → 记为 G-FTP-3（文档化，非修复项）。**本契约 §5.2/§12.12 明确写清**：会话级 `src_port_dyn` 按**流序号**解析，同一流内多会话共用同一序号 → 解析同值 → TCP 层合成同一连接 key |

> **口径纪律**：以上三条均为可判题（JSON × 结果产物 × 真实 pcap 三级对照 + 代码行号），直接判定，不问偏好。**不允许**用"结果产物写了 26/70 所以没问题"覆盖 #1/#2（结果产物是 2026-09-27 跑出来的，**未经今日复跑证实**，见 §0.3）。

### 0.3 产物登记（G-FTP-1）

`trafficgen/docs/protocol-pcap-test/ftp.md` 是 **tracked 结果产物**（`git ls-files` 可证），内容 `Cases: 141 — pass 141, fail 0, error 0`。

**先澄清一件容易误判的事（本车道实测）**：该产物**不是**"包数错"的产物，**也不是**"末次提交早于判死提交"的产物：

- **末次提交** `711423d`（**2026-09-19**），**晚于**判死提交 `0417be5`（2026-09-13）→ 任务书字面的"过期"判据**不成立**。
- **该提交是对产物的修正而非破坏**（`git show` 逐行对照实测）：前一版 `01fab60`（2026-09-12）**只有 139 行**，`711423d` 补上缺失的 2 行（`ftp_perf_1000flows`、`ftp_dyn_neg_port_pattern`）并把 `ftp_neg_static_copy` 的包数从 **18 改为 0**（负例应为 0 帧）——**141 行是修正后的正确行数**。
- **行内包数与真实 pcap 逐条一致**：本车道机读全量核对 **138/138 行包数 = 真实 pcap 帧数，0 处不符**（§9.1）。

**故 G-FTP-1 的真实内容是三条窄口径事实（不得夸大）**：

| # | 事实 | 证据 |
|---|---|---|
| ① | **141/141 数字未经本车道今日复跑证实**——本车道**未跑**该套件；产物文件亦**未标注跑测日期**。任务书"末次提交早于 `0417be5`"的字面判据**不成立**，故本项**不是**"过期产物"登记，而是"**数字未经今日复跑证实**"的诚实声明 | `git log -1` = `711423d`（2026-09-19）；本车道未跑套件 |
| ② | **pcap 留档缺失**：`trafficgen/docs/protocol-pcap-test/ftp/` **目录不存在**（`ls` 实测 No such file or directory）→ 产物里 141 条 `[pcap](ftp/…)` 链接**全部悬空** | `ls` 实测 |
| ③ | **3 条负例无 pcap**：`ftp_neg_static_copy`/`ftp_neg_mss_too_small`/`ftp_dyn_neg_port_pattern` 在 `/tmp/mcp-pcaps/ftp/` 无 `.neg.pcap`（138/141 有）；产物对这三行仍标 `pass`（包数 0） | `ls /tmp/mcp-pcaps/ftp \| wc -l` = 138 |

**另注（非缺口，仅口径）**：产物行序为**字母序**，与本契约/用例文档的 **JSON 顺序不同**——引用时必须按 ID 而非行号定位。

**结论**：ftp 的 141 例**今日应可跑**（141/141 顶层键仅 `{layers}`，机读实测；见 §12.1），且**包数经 138 例真实 pcap 逐条复核全对**。归属**代码阶段**（P5 重跑套件后重生成该产物 + 补 pcap 留档）。本版**不删不改**该产物。

## 1. 范围、profile 与实现状态边界

本版定义 **FTP 控制连接（TCP 21）+ 数据连接（被动/主动、默认端口 ≠ 21）** 的流量生成：登录序列、文件/目录操作、数据传输（下载/上传/列表/续传/追加/唯一存储）、异常与失败应答、RFC 2428 扩展模式。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `ftp_control_v1`（主） | TCP，fixture 21 | 单控制连接全部命令/应答序列（§4） | 真实服务器语义（文件是否存在、权限、配额） |
| `ftp_passive_v1` | 同上 + 副连接（PASV/EPSV 协商） | 客户端首 SYN 的数据连接（§3.6） | 真实 PASV 端口分配策略 |
| `ftp_active_v1` | 同上 + 副连接（PORT/EPRT 协商） | **服务端首 SYN** 的数据连接（源口 20） | 真实服务器是否允许 active |
| `ftp_multisession_v1` | 同上，`sessions[]` 多会话 | 每会话独立四元组/序号/握手挥手 | 会话间时序交错（本版按序整块回放） |
| `ftp_ipv6_v1` | 同上，仅外层 IPv6 | 同主 profile（offset 74） | 从 IPv4 fixture 推导 IPv6 地址 |
| `ftp_ext_v1` | 同上，RFC 2428 | EPSV/EPSV 端口推导、EPRT af=2、500/522 拒绝 | EPRT af=1（IPv4 over EPRT，**显式不实现**，`ftp.go:903` 只认 `m=="2"`） |

**显式边界（"不实现、不声称、不许静默转换"）**：① 不实现 FTP 状态机校验——`Response` **逐字回放**，planner 不检查 `USER` 前能否 `RETR`（§5.1）；② 不实现 TLS/FTPS（`OptionalOn: ["tls"]` 是 registry 声明的可选底座，本版 141 例**零用例**，§10.1）；③ 不实现数据通道的**通道级 MSS**（`data_channel.mss` 层内可写但**链路径被忽略**，§8/G-FTP-4）；④ 不实现 `FileSource` 的文件系统真实读取（链路径依赖引擎注入 `PayloadCache`，离线套件不注入 → 静默不发射，G-FTP-2）；⑤ 不实现 EPRT af=1；⑥ 不实现控制连接的 SASL/AUTH、`AUTH TLS` 显式升级；⑦ **不声称** `direction` 字段在链路径决定载荷流向（实测**恒 down**，§6.4/G-FTP-5）；⑧ 不实现会话级/命令级动态的**会话内索引域**（同流多会话共用流序号，G-FTP-3）。

**实现状态（2026-09-29 实测）**：`ftp` 层已注册（`registry.go:1546`，`CategoryTerminal`，`DependsOn ["tcp"]`，`OptionalOn ["tls"]`，**Fields 7 键**）；planner + 终结层生成器已落码（`internal/protocol/ftp/ftp.go` **1197 行** + `layer_gen.go` **369 行**）；`allowedProtocols["ftp"]=true`（`protocols.go:40`）；层内 translate 已接线（`chain_planner_translate.go:2614` → `core.ParseFTPConfigFromMap`，`strategy_convert.go:9145`）；缺省目的端口 21（`chain_planner.go:1207`；扁平路径 `strategy_convert.go:986` `setDefaultDstPort(&spec, cfg, 21)`）；扁平判死已接线（`CheckProtoFlat`→`CheckFTPFlat`，`strategy_convert.go:8626/9123`）；**ftp 链强制 `tcp.concurrent=true`**（`chain_planner_chain.go:487-489` + `isFTPChain`，`chain_planner_util.go:146-149`）；141 语义用例已落 `cases/ftp.json`；**81 个 `Test*` 函数**（10 个 `_test.go` 文件，`grep -c '^func Test'` 实测）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.srcport/dstport`、`tcp.flags`、`ftp.request.command/arg`、`ftp.response.code/arg`、`ip.src/dst`、`ipv6.src/dst`、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, ftp]`（引擎自动补 `ip`；最小链 `[tcp, ftp]`）。FTP 报文是 TCP payload 的**文本行**（`CRLF` 终止），**由 tcp 层负责握手/分段/挥手**；ftp 层只产出"报文事件"（方向 + 完整字节 + 连接端口覆盖）。

端口（实测，§3.6 推导规则）：
- **控制连接**：服务端口缺省 **TCP 21**（`chain_planner.go:1207`）；客户端口缺省 `DefaultSrcPort+i` 保底自增（`strategy_convert.go:49`，fixture 多为 12345）。
- **数据连接（passive）**：客户端口 = 会话控制口 + 1（`ftp.go:676-683`，`ctrlPort==65535` 时回退 1024）；服务端口 = PASV 227 六元组推导 `p1*256+p2`（`ftp.go:920-935`）或 EPSV 229 端口（`ftp.go:868-881`），**无信令时回退 50000**。
- **数据连接（active）**：服务端口 = **20**（`ftp.go:664-666`）；客户端口 = PORT/EPRT 通告值（`ftp.go:748-756`）或控制口 + 1。
- **显式覆盖优先**：`data_channel.src_port/dst_port` 非 0 时直接采用，**优先于信令推导**（`ftp.go:660-661` 先取显式值再判 0）。

固定偏移：无 VLAN/IP options/TCP options 时，**每帧 FTP 文本首字节起点为 IPv4 offset 54**（14+20+20）、**IPv6 offset 74**（14+40+20）。本协议 141 例**只有 3 条 frame 断言**（全在 `ftp_smoke_01`，offset 54），其余 122 例走 `ftp.*`/`tcp.*` 字段通道。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers` + `flow_control`；**存量 141/141 已是此形，零迁移工作量**，§12.1）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 21}},
    {"ftp": {
      "banner": "220 FTP server ready",
      "commands": [
        {"cmd": "USER anonymous", "response": "331 Anonymous login ok"},
        {"cmd": "PASS guest", "response": "230 Logged in"},
        {"cmd": "QUIT", "response": "221 Goodbye"}
      ]
    }}
  ]
}
```

数据通道样例（老形状：顶层 `commands` + `data_channel`，`emit_data_channel` 标记触发；`ftp_retr_passive` 原样）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 21}},
    {"ftp": {
      "banner": "220 FTP ready",
      "commands": [
        {"cmd": "PASV", "response": "227 Entering Passive Mode (20,0,0,1,195,73)"},
        {"cmd": "RETR /data.bin", "response": "150 Opening data connection", "emit_data_channel": true},
        {"cmd": "", "response": "226 Transfer complete"},
        {"cmd": "QUIT", "response": "221 Goodbye"}
      ],
      "data_channel": {"mode": "passive", "direction": "down", "payload": "HELLO FTP DATA"}
    }}
  ]
}
```

多会话样例（`sessions[]` 形状：每会话自带端口与事务序列；数量只走 `flow_control`）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 25000, "dst_port": 21}},
    {"ftp": {
      "sessions": [
        {"src_port": 26000, "transactions": [
          {"commands": [{"cmd": "USER t", "response": "331"}, {"cmd": "QUIT", "response": "221"}]}
        ]},
        {"src_port": 26010, "banner": "220 s2", "transactions": [
          {"commands": [
            {"cmd": "PASV", "response": "227 Entering Passive Mode (20,0,0,1,195,104)"},
            {"cmd": "RETR /a.bin", "response": "150", "emit_data_channel": true},
            {"cmd": "", "response": "226 done"}
          ], "data_channel": {"payload": "FILE-A"}}
        ]}
      ]
    }}
  ],
  "flow_control": {"flows": 3}
}
```

## 3. 线格式与端口推导（逐字段可生成级）

### 3.1 控制通道行格式（RFC 959 §4.1 / §4.2）

| 项 | 规则 | 代码位置 |
|---|---|---|
| 命令行 | `<命令> [<SP> <参数>] <CRLF>`，命令大小写不敏感（RFC 959 §5.3.1） | `layer_gen.go:180`（`cmd+"\r\n"`）/ `ftp.go:361` |
| 应答行 | `<3 位码> <SP> <文本> <CRLF>`；多行用 `<码>-<文本>` 续行 | 逐字回放，planner 不解析（§5.1） |
| 分隔符 | 码与文本之间**必须是字面 SPACE**（RFC 959 §5.4）；解析侧用 `^227 ` 而非 `^227\s` | `ftp.go:826-834` 注释（`\s` 会误吞 `227\t-` 续行） |
| 空命令 | `cmd == ""` **跳过不发**（可建模"仅服务端应答"轮次） | `layer_gen.go:179`/`ftp.go:360` |
| 空应答 | `response == ""` **跳过不发** | `layer_gen.go:184` |
| 空载荷事件 | **绝不单独发射**（会产空 PSH 段）；缓冲后转发 | `layer_gen.go:114-132`（`emitWithSessionClose`） |
| 总长度公式 | 每条命令帧长 = `len(cmd)+2`；每条应答帧长 = `len(response)+2`；banner 帧长 = `len(banner)+2` | 由上两条直接推出 |

### 3.2 命令表（RFC 959 §4.1；存量覆盖）

RFC 959 定义的 **33 条命令**与 141 例覆盖情况（§4.1.1 访问控制 8 条 / §4.1.2 传输参数 5 条 / §4.1.3 服务命令 20 条）。机读实测：存量 `cmd` 字段出现 **36 个不同命令** = RFC 959 全 33 条（**零遗漏**）+ RFC 2428 的 `EPSV`/`EPRT` + 负例用的 `BOGUS`（`ftp_syntax_500` 的未知命令）：

| 命令 | RFC | 存量用例 | 命令 | RFC | 存量用例 |
|---|---|---|---|---|---|
| USER | §4.1.1 | `ftp_smoke_01` 等 | PASV | §4.1.2 | `ftp_retr_passive` |
| PASS | §4.1.1 | `ftp_smoke_01` | PORT | §4.1.2 | `ftp_stor_upload` |
| ACCT | §4.1.1 | `ftp_login_acct` | TYPE | §4.1.2 | `ftp_type_ascii`/`_local`/`_image` |
| CWD | §4.1.1 | `ftp_cwd_550_fail` | STRU | §4.1.2 | `ftp_min_stru` |
| CDUP | §4.1.1 | `ftp_cdup` | MODE | §4.1.2 | `ftp_min_mode` |
| SMNT | §4.1.1 | `ftp_smnt` | RETR | §4.1.3 | `ftp_retr_passive` |
| REIN | §4.1.1 | `ftp_login_rein` | STOR | §4.1.3 | `ftp_stor_upload` |
| QUIT | §4.1.1 | `ftp_smoke_01` 等 | STOU | §4.1.3 | `ftp_stou` |
| PORT | §4.1.2 | `ftp_stor_upload` | APPE | §4.1.3 | `ftp_appe` |
| **EPRT** | **RFC 2428 §4** | `ftp_eprt_active_upload` | ALLO | §4.1.3 | `ftp_allo_stor` |
| **EPSV** | **RFC 2428 §3** | `ftp_epsv_passive_download` | REST | §4.1.3 | `ftp_rest_retr` |
| **PASV** | §4.1.2 | `ftp_retr_passive` | RNFR/RNTO | §4.1.3 | `ftp_rnfr_rnto` |
| ABOR | §4.1.3 | `ftp_abor_completed`/`_midtransfer`/`_idle` | DELE | §4.1.3 | `ftp_file_mgmt` |
| LIST | §4.1.3 | `ftp_list_226_success` | RMD | §4.1.3 | `ftp_file_mgmt` |
| NLST | §4.1.3 | `ftp_nlst` | MKD | §4.1.3 | `ftp_file_mgmt` |
| SITE | §4.1.3 | `ftp_site`/`ftp_502_notimpl` | PWD | §4.1.3 | `ftp_file_mgmt` |
| SYST | §4.1.3 | `ftp_syst` | STAT | §4.1.3 | `ftp_stat`/`_213_file`/`_212_dir` |
| HELP | §4.1.3 | `ftp_help` | NOOP | §4.1.3 | `ftp_min_noop` |

> **命令覆盖的两条诚实声明**：① **正例覆盖 = RFC 959 全 33 条零遗漏**（+RFC 2428 的 `EPSV`/`EPRT` + 负例 `BOGUS`）；② **失败应答覆盖 = 14 条命令有 4xx/5xx 例**（`RETR`/`STOR`/`CWD`/`RNFR`/`DELE`/`TYPE`/`SITE`/`STAT` 等），**其余 22 条命令无失败应答例**（`ACCT`/`ALLO`/`APPE`/`CDUP`/`HELP`/`MKD`/`MODE`/`NLST`/`NOOP`/`PASV`/`PORT`/`PWD`/`QUIT`/`REIN`/`REST`/`RMD`/`RNTO`/`SMNT`/`STOU`/`STRU`/`SYST`/`USER`）→ **A′ 立项 G-FTP-15**（RFC 959 §4.2.1 为其中多数定义了失败码，如 `MKD`→521/550、`RMD`→550、`PWD`→550、`CDUP`→550、`ACCT`→530/503）。③ **RFC 3659 的时间戳类命令（`MDTM`/`SIZE`/`MLSD`）不在本版范围**（本版只做 RFC 959 + RFC 2428，**显式不适用**，非缺口）。

### 3.3 应答码表（RFC 959 §4.2 / §4.2.1；存量覆盖 3 位码全枚举）

机读实测：存量覆盖 **3 位应答码 41 个**（`response` 文本 + `banner` 文本首三位的并集，机读实测；其中 **31 个**另有 `ftp.response.code` 字段断言）。按 RFC 959 §4.2 首位语义分族：

| 族 | 语义（RFC 959 §4.2） | 存量覆盖的码 |
|---|---|---|
| 1xx 正初步（4 个） | 请求已开始，期待另一应答 | **110**（`ftp_retr_110_marker`）、**120**（`ftp_banner_120_greeting`，**出现在 `banner` 键而非 `response`**）、**125**（`ftp_dataconn_125`/`ftp_stou`）、**150**（多例） |
| 2xx 正完成（16 个） | 请求动作已完成 | **200**（`ftp_min_noop`/`ftp_site`）、**202**（`ftp_allo_stor`）、**211**（`ftp_stat`）、**212**（`ftp_stat_212_dir`）、**213**（`ftp_stat_213_file`）、**214**（`ftp_help`）、**215**（`ftp_syst`）、**220**（多例 banner）、**221**（多例 QUIT）、**225**（`ftp_abor_idle`）、**226**（多例）、**227**（`ftp_retr_passive`）、**229**（`ftp_epsv_passive_download`）、**230**（多例登录）、**250**（`ftp_file_mgmt`/`ftp_dataconn_250`）、**257**（`ftp_file_mgmt`） |
| 3xx 正中间（3 个） | 命令被接受，需更多信息 | **331**（多例）、**332**（`ftp_login_acct`）、**350**（`ftp_rnfr_rnto`/`ftp_rest_retr`） |
| 4xx 暂时否（6 个） | 命令未执行，可重试 | **421**（`ftp_service_421`）、**425**（`ftp_dataconn_425`）、**426**（`ftp_abor_midtransfer`）、**450**（`ftp_transfer_450`/`ftp_rnfr_450_fail`）、**451**（`ftp_transfer_451_localerr`）、**452**（`ftp_stor_452_quota`） |
| 5xx 永久否（12 个） | 命令未执行，不应重试 | **500**（`ftp_syntax_500`/`ftp_epsv_500_fallback`）、**501**（`ftp_arg_501`）、**502**（`ftp_502_notimpl`）、**503**（`ftp_badseq_503`）、**504**（`ftp_type_504_badparam`）、**522**（`ftp_eprt_522_reject`，RFC 2428 §5）、**530**（`ftp_login_530`/`_cmd`）、**532**（`ftp_stor_532_nospace`）、**550**（多例 fail 分支）、**551**（`ftp_stor_551_pagetype`）、**552**（`ftp_stor_552_exceedalloc`）、**553**（`ftp_stor_553_filename`） |

> **1xx 的 110 码**（Restart marker，RFC 959 §4.2.1）：应答文本必须是 `MARK yyyy = mmmm` 形式（§3.4.2），存量 `ftp_retr_110_marker` 覆盖。

### 3.4 端口推导（RFC 959 §3.2 / §3.3；RFC 2428 §3 / §4）

**信令扫描**（`scanTxForDataPort`，`ftp.go:744-769`）：**只扫本事务**的命令/应答对，**last-wins**（同事务内后通告者覆盖前者）。

| 模式 | 扫描目标 | 正则 | 推导公式 |
|---|---|---|---|
| passive | **应答**侧 `227` | `(?im)^227 [^\n]*?\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)`（`ftp.go:839`） | `p1*256+p2`，`[0,65535]` 外拒（`ftp.go:930-933`） |
| passive | **应答**侧 `229` | `(?im)^229 [^\n]*?\(\|\|\|(\d+)\|\)`（`ftp.go:862`） | 直接取端口（`ftp.go:868-881`） |
| active | **命令**侧 `PORT` | `(?im)^PORT\s+(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)`（`ftp.go:853`） | `p1*256+p2` |
| active | **命令**侧 `EPRT` | `(?im)^EPRT\s+\|(\d+)\|([^\|]*)\|(\d+)\|`（`ftp.go:892`） | 取第 3 段；**af 必须 = 2**（`ftp.go:903`），af=1 返回 0 |

**推导优先级**（`dataChannelPorts`，`layer_gen.go:290-327`，与 legacy `emitTxDataChannel`/`emitFTPDataChannel` 同规则）：

| 模式 | 客户端口 | 服务端口 |
|---|---|---|
| active | 显式 `dc.src_port` > 信令端口 > `1024`（`ctrlPort==65535`）> `ctrlPort+1` | 显式 `dc.dst_port` > **20** |
| passive | 显式 `dc.src_port` > `1024`（`ctrlPort==65535`）> `ctrlPort+1` | 显式 `dc.dst_port` > 信令端口 > **50000** |

**正则口径（三处显式设计，非偶然）**：① `(?i)` 大小写不敏感（RFC 959 §5.3.1）；② `(?m)` 多行——`^` 匹配**每一行**首，故 `227-Welcome\r\n227 Entering Passive Mode (...)` 能命中末行；③ `^227 ` 用**字面空格**而非 `\s`——`\s` 也匹配 tab/CR/LF，畸形续行 `227\t-Welcome (..)` 会劫持真 227 行（`ftp.go:826-834` 注释逐条记载）；④ `[^\n]*?` **非贪婪**——第一个六元组 wins，贪心会回退到行内**最后一个** `(...)`，服务器塞调试信息时取错元组。

**端口溢出守卫**：`ctrlPort == 65535` 时客户端口回退 **1024**（不回绕 0）——`ftp.go:678-682`。存量 `ftp_port_overflow` 覆盖（实测数据连接口 1024→50000）。

### 3.5 数据通道载荷来源（优先级契约）

`FileSource > PayloadB64 > Payload`（`layer_gen.go:252-263`，与 `ftp.go:1135-1146` 同序）：

| 优先级 | 来源 | 处理 |
|---|---|---|
| 1 | `data_channel.file_source` | `core.PayloadCacheFrom(ctx).GetOrLoad(ctx, *src)`；**cache 为 nil 时直接 `return nil`（不发数据事件，不回落 Payload）**——`layer_gen.go:254-258` |
| 2 | `data_channel.payload_b64` | `base64.StdEncoding.DecodeString` |
| 3 | `data_channel.payload` | `[]byte(payload)` |

**截断**（ABOR，RFC 959 §4.1.4）：`abort_after_bytes > 0 && < len(payload)` 时取前 N 字节（`layer_gen.go:264-266`）；`>= len(payload)` 为 no-op。

**分段**：整块发射，**MSS 分段归 tcp 层**（`layer_gen.go:26-28`）；段数 = `ceil(len(payload)/MSS)`，`MSS` 取链全局 `tcp.mss`（缺省 1460）。**`data_channel.mss` 在链路径被忽略**（G-FTP-4）。

### 3.6 数据通道方向语义（实测钉死，与 `direction` 字段**无关**）

| 模式 | 首 SYN 方向 | 载荷 PSH 方向 | 实测证据 |
|---|---|---|---|
| passive（`ServerFirst=false`） | **client → server** | **client → server**（up） | `ftp_retr_passive.pcap` 帧 13 `12346→49993` SYN；帧 16 `12346→49993` PSH `tcp.len=14` |
| active（`ServerFirst=true`） | **server → client** | **server → client**（down） | `ftp_stor_upload.pcap` 帧 13 `20→12371` SYN；帧 16 `20→12371` PSH `tcp.len=14` |

`layer_gen.go:274-281` 只传 `Up: !isActive` + `ServerFirst: isActive` 两值，**`dc.Direction` 显式丢弃**（`layer_gen.go:273` 的 `_ = dc.Direction`）。tcp 层（`generator.go:1515-1518`）`ServerFirst=true` 时把 `evUp` 强制为 `false` → 载荷恒由 server 发。**结论**：链路径**载荷流向完全由 mode 决定**，`direction` 是死配置 → G-FTP-5。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明控制通道的命令/应答序列 + 可选数据通道载荷，引擎按固定剧本逐帧产出事件（banner → 逐命令/应答 → 数据通道 → 会话末 CloseConn），tcp 层负责握手/分段/挥手与多连接合成。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 登录与会话建立 | banner 220 → USER 331 → PASS 230（或 ACCT 332） | `ftp_smoke_01`/`ftp_login_acct`/`ftp_login_nobanner` |
| ② 认证失败与重试 | PASS → 530；REIN 重初始化；中途 re-USER | `ftp_login_530`/`ftp_login_rein`/`ftp_login_reuser` |
| ③ 文件下载（被动） | PASV 227 → RETR 150 → **数据通道** → 226 | `ftp_retr_passive` |
| ④ 文件上传（主动） | PORT → STOR 150 → **数据通道（服务端首 SYN）** → 226 | `ftp_stor_upload` |
| ⑤ 目录列表 | PASV → LIST 150 → 数据 → 226/250 | `ftp_list_226_success`/`ftp_nlst`/`ftp_dataconn_250` |
| ⑥ 断点续传 | REST 350 → PASV → RETR | `ftp_rest_retr`/`ftp_rest_stor_upload` |
| ⑦ 追加/唯一存储/预分配 | APPE / STOU / ALLO 202 → 数据 | `ftp_appe`/`ftp_stou`/`ftp_allo_stor` |
| ⑧ 文件与目录管理 | MKD 257/PWD 257/RMD 250/DELE 250；RNFR 350 → RNTO 250 | `ftp_file_mgmt`/`ftp_rnfr_rnto` |
| ⑨ 传输中断（ABOR） | 情形①完成→226；情形②中断→426+226；情形③空闲→225 | `ftp_abor_completed`/`_midtransfer`/`_idle` |
| ⑩ 失败分支 | 450/451/452/532/550/551/552/553/425/421/503/500/501/502/504 | 15 例（§3.3 4xx/5xx 行） |
| ⑪ RFC 2428 扩展 | EPSV 229 → RETR；EPRT → STOR；EPSV 500 / EPRT 522 拒绝 | `ftp_epsv_passive_download`/`ftp_eprt_active_upload`/`ftp_epsv_500_fallback`/`ftp_eprt_522_reject` |
| ⑫ 多会话/多流 | 2–3 会话各自独立连接；`flows` 多流各挂数据通道 | `ftp_sessions_dual`/`ftp_3sessions_mixed`/`ftp_multiflow_multisession`/`ftp_perf_1000flows` |
| ⑬ IPv6 产线 | 同上，仅外层 IPv6（12 例） | `ftp_ipv6_data`/`ftp_ipv6_active`/`ftp_ipv6_multiflow` 等 |

**五层覆盖逐层结论**：

- **功能层**：RFC 959 §4.1 命令表 30+ 条覆盖（§3.2）；§4.2 应答码 30 个覆盖（§3.3）；RFC 2428 扩展 4 例。**负例 5 条**（§7）——但**全部是配置/校验类**，**无一条线格式类负例**（A′ 立项 G-FTP-6）。
- **性能层**：MSS 分段两例（`ftp_mss_segmentation` 2528B→2 段；`ftp_dc_mss_override` 2200B→2 段）；多流上限两例（`ftp_perf_100flows` 1400 帧、`ftp_perf_1000flows` **14000 帧**）；`ctrlPort=65535` 溢出守卫一例。§8 给容量与开销公式。
- **数据场景层**：空命令/空应答/空会话（`ftp_empty_session` 7 帧）；二进制载荷 base64（`ftp_payload_b64` 含 NUL）；截断（`ftp_abort_bytes` 1024→10 字节）；banner 缺省（`ftp_login_nobanner`）；非默认端口（`ftp_dataconn_explicit_ports`）；端口回退（`ftp_dataconn_fallback` 50000）。
- **地址与流层**：IPv4 129 例 / **IPv6 12 例**（独立用例，offset 74）；单流基线；**流关联（控制流派生数据通道）覆盖 55 例**（§6.3 主从关系 + 端口推导 + 插入位置 + 截断）；**多会话** 39 例（`sessions[]`）；**多流** 51 例（`strategy_fc type=flows`，值域 {2,3,4,100,1000}）。
- **业务层**：13 类现网场景全部有落点（上表）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① FTPS/TLS 底座（`OptionalOn ["tls"]` 已声明，141 例零用例 → A′ 立项 G-FTP-7）；② EPRT af=1（`ftp.go:903` 显式拒绝，设计不实现）；③ `data_channel.mss` 通道级分段（链路径忽略 → G-FTP-4）；④ `FileSource` 真实文件读取（离线套件无 cache → G-FTP-2）；⑤ `direction` 决定载荷流向（实测死配置 → G-FTP-5）。

## 5. 消息/事务模型与状态机

### 5.1 事务定义与状态机边界

**事务** = 一个 FTP 业务操作（1..M 个命令/应答对 + 至多一条数据通道）。**多事务** = 同一控制连接内多笔事务按序执行，**事务间有先后依赖**（`REST 350 → PASV → RETR`；`RNFR 350 → RNTO 250`；`USER → PASS → ACCT`）。

**ftp 层无自有状态机**（重要，诚实声明）：`FTPConfig` 的 `Response` 是**逐字回放的文本**——planner **不校验** FTP 状态转移（`types.go:2414-2420` 明写"the planner does not validate FTP state transitions, it just plays back the dialog the user specified"）。故"未登录直接 RETR→503"这类**状态机语义由用户写在 `response` 里**（`ftp_badseq_503`），引擎不判断合法性。**握手/挥手/分段/多连接合成**全在 tcp 层（`generator.go:1408-1640`）。

### 5.2 会话模型（`sessions[]`，D-FTP-1）

| 形状 | 判定 | 行为 |
|---|---|---|
| **老形状** | `sessions` 为空 | 顶层 `banner` + `commands`（+ `data_channel`）构成**单控制流**；`srcPort` = 链 tcp 层端口（`layer_gen.go:81-89`，`emitLegacy`） |
| **多会话形状** | `sessions` 非空 | 每会话一条**独立控制连接**：独立端口、独立序号空间、独立握手/teardown；会话内事务按序；**按序整块回放**（第 1 会话跑完握手→事务→挥手，再跑第 2 个，**不交错**） |

**会话端口解析**（`resolveSessionPort`，`layer_gen.go:139-149`）：静态非零 `sess.SrcPort` > 动态 `SrcPortDyn` 按**流序号**解析 > 链 tcp 层端口（`req.Meta.SrcPort`）。

> **诚实声明（G-FTP-3）**：`src_port_dyn`/`banner_dyn` 按 **`spec.FlowIndex`（流序号）**解析，**不是会话序号**（`ftp.go:415-424`/`layer_gen.go:143-147`）。故**同一流内多个会话若都用动态端口，会解析出同一个值** → 两会话合成**同一条 TCP 连接 key**（tcp 层 `conns` map 按 `(src,dst)` 键）。实测 `ftp_multiflow_multisession` 即此形态：flows=2、每流 2 会话、`src_port_dyn inc [41000,41001]` → 每流只见 41000/41001 **两条连接**（70 帧 = 2×35），而非 4 条（84 帧）。**该用例 `notes` 已自陈此行为并已按真实 pcap 钉住**，属**已声明语义边界**，不是缺陷；但**用例文档 §2 与设计必须写清**，不得读成"每会话独立端口"。

**数据通道挂载**（`{parent}:sub-{txIdx}`）：老形状挂 `sub-0`；多会话形状挂 `sub-{txIdx}`（**事务索引取代硬编码 sub-0**，`ftp.go:401-403`）。

### 5.3 事件序与自动派生规则

**老形状事件序**（`emitLegacy`，`layer_gen.go:202-236`）：
`[banner↓]` → 逐命令 `[cmd↑][response↓]` → 命中 `emit_data_channel` 时**紧随该应答之后**插数据通道（`[DC 握手3][DC PSH][DC 挥手4]`，`CloseConn=true`）→ 流末（无独立挥手事件；由 tcp 层 `termination` 补）。

**多会话形状事件序**（`emitSession` + `emitWithSessionClose`，`layer_gen.go:155-199/114-132`）：
`[banner↓]` → 逐事务：逐命令 `[cmd↑][response↓]`，然后**若本事务有数据通道且某命令带 `emit_data_channel`** → 追加 `[DC PSH]`（端口覆盖合成新 key，`CloseConn=true`）→ **会话末事件搭 `CloseConn=true`**。

> **会话形状的数据通道位置与老形状不同（实测，非缺陷）**：多会话形状把数据通道**追加在事务的所有命令之后**（`layer_gen.go:190-194` 在 `for cmd` 循环**之外**）；老形状是**紧随命中命令的应答之后**（`layer_gen.go:222-233` 在 `for cmd` 循环**之内**）。故 `ftp_retr_passive`（老形状）数据通道插在 **150 之后、226 之前**（帧 13–19 在帧 12 与帧 20 之间）；`ftp_multiflow_multisession`（会话形状）数据通道插在 **226 之后**（帧 10 是 226，帧 11–18 才是数据）。**两者都真实、都被 pcap 钉住**，§6.3 给逐形状插入位置表。

**tcp 层自动派生（ftp 链强制 `concurrent=true`）**：

| 派生帧 | 触发条件 | 内容 |
|---|---|---|
| 握手 3 帧 | **首见某 connKey**（`generator.go:1476-1486`） | `ServerFirst=false` → client 首 SYN；`=true` → server 首 SYN（active 数据通道） |
| 数据 PSH 段 | 事件 `Bytes` 非空 | 按 `mss` 分段；`ServerFirst=true` 时**恒 down**（server 发，§3.6） |
| 挥手 4 帧 | 事件 `CloseConn=true`（`generator.go:1570-1578`） | 该 key 立即 FIN/ACK/FIN/ACK，并从 `connOrder` 移除（流末不重复挥手） |
| 流末挥手 | 流结束仍在 `connOrder` 的连接 | 按首见序逐条 4 帧（`generator.go:1620-1630`） |
| 空会话补建连 | 会话零事件（`layer_gen.go:100-102`） | 补一条**无载荷纯控制**事件（端口 = 会话端口）→ 握手 3 + CloseConn 挥手 4 = **7 帧**（`ftp_empty_session` 实测） |
| 空事件流补默认连接 | 终结层零事件且非 CloseConn 拆除 | 补默认连接握手 + 挥手（`generator.go:1586-1592`）——本协议**不达此分支**（ftp 至少产空会话事件） |

**TCP 选项**：SYN/SYN-ACK 携带 `MSS`（`synOptions`，`ftp.go:801-810`：MSS + WinScale 0x07 + SACK-Permitted）。

## 6. 流关联（控制流派生数据流）——本协议核心维度

### 6.1 主从关系

控制连接是**主**，数据连接是**从**，派生关系由 `emit_data_channel` 标记锚定（`txHasDataChannel`，`ftp.go:621-631`：事务有 `DataChannel` **且** 某命令 `EmitDataChannel=true`）。

**主从关系的三个可观察面**（都在 141 例里有断言）：

1. **端口一致性**：数据连接的 server 端口 = 控制通道**同事务**信令通告的端口（`227 (20,0,0,1,195,73)` → 数据连接 `dstport=49993`）。断言例：`ftp_retr_passive` pkt13 `tcp.dstport=49993`、`ftp_txindex_dual` pkt9 `50011`/pkt21 `50012`、`ftp_pasv_isolation` pkt9 `49993`/pkt21 `49994`。
2. **客户端口 = 控制口 + 1**：`ftp_retr_passive` 控制口 12345 → 数据口 12346（实测帧 13）。
3. **插入位置**：数据帧落在控制通道的 150 与 226 之间（老形状）——`ftp_retr_passive` 帧 12=150、13–19=数据、20=226。

### 6.2 事务域隔离（T-FTP-4）

信令扫描**只扫本事务**（`scanTxForDataPort`，`ftp.go:744-769`），**不是整个对话**：

| 用例 | 形态 | 断言 | 实测 |
|---|---|---|---|
| `ftp_txindex_dual` | 单会话双事务，各带 PASV | pkt9 `50011` / pkt21 `50012` | ✓ 两数据流各取本事务端口 |
| `ftp_pasv_isolation` | 事务2 的 PASV 与事务1 不同 | pkt9 `49993` / pkt21 `49994`（**不串 49993**） | ✓ |
| 老形状 `emitLegacy` | 扫描域 = **对话到本命令为止**（`c.Commands[:i+1]`，`layer_gen.go:226-229`） | 前面的 PASV 可见 | ✓ `ftp_retr_passive` |

> **老形状扫描域是"到本命令为止"**（含本命令），**不是"整个对话"**——`layer_gen.go:223-225` 注释明写：只装单命令的事务会让扫描看不到信令端口，数据通道回退 50000/20。

### 6.3 插入位置（两种形状，逐形状实测）

| 形状 | 插入位置 | 用例 | 实测帧位 |
|---|---|---|---|
| 老形状 | **150 应答之后、下一条命令之前**（含 226 之前） | `ftp_retr_passive` | 12=150 → **13–19 数据** → 20=226 |
| 会话形状 | **事务全部命令之后**（226 之后） | `ftp_multiflow_multisession` | 8=150 → 9=226 → **11–18 数据** |

### 6.4 方向与截断

**方向**：passive → 数据载荷 client→server（**与真实 FTP 的 RETR 下载语义相反**）；active → server→client。§3.6 给实测证据；`direction` 字段**不参与**（G-FTP-5）。

**截断（AbortAfterBytes）**：`ftp_abort_bytes` 内联载荷 1024 字节、`abort_after_bytes=10` → 数据 PSH `tcp.len=10`（实测帧 16）。`ftp_abor_midtransfer` 组合 426+226 双应答。

### 6.5 流关联的"不断言面"（诚实声明）

141 例中**没有任何一条断言 `ftp.*` 层级的"数据连接与控制连接关联"语义**（tshark 的 `ftp.setup-frame`/`ftp.command-response.frames` 字段可做此断言，但**存量零使用**）——关联性靠**端口值 + 帧位**间接证明。→ A′ 立项 G-FTP-8（收编 `ftp.setup-frame` 等 33 个 `ftp.*` 字段中未用的 20 个）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

**存量 5 条负例全部是配置/校验类**，锚词与代码字面值逐条对照（机读实测 `cases/ftp.json`）：

| # | 负例 ID | 故障输入 | JSON `error_contains` | 代码锚词（逐字） | 代码位置 |
|---:|---|---|---|---|---|
| N-1 | `ftp_neg_static_copy` | 层链显式标量四元组 + `flows=2` | `static four-tuple` | `layers pin a static four-tuple but flows > 1: every flow would emit identical addresses/ports (static copy). Write the varying field as a dynamic object inside its layer (ip.src/ip.dst, tcp/udp src_port/dst_port)` | `schema/semantic.go:285`（`checkLayerChainStaticCopy`，`:198`） |
| N-2 | `ftp_neg_mss_too_small` | `tcp.mss=100` | `out of range` | `layers: layer %q field %q = %v invalid: out of range [%d,%d]`（mss 范围 `[536,65535]`） | `layers/complete.go:325`；范围 `layers/registry.go:68` |
| N-3 | `ftp_neg_dyn_no_range` | `sessions[0].src_port={"strategy":"inc"}` 无 range + `flows=2` | `range` | `ftp sessions[0].src_port: inc strategy requires a 2-element range` | `ftp.go:164-166`（`validateDynFields`，`:152`） |
| N-4 | `ftp_neg_session_static_copy` | 2 会话固定 `src_port`（20000/20001）+ `flows=2` | `static copy` | `ftp: flows=2 with pinned session src_port emits 2 identical control connections (static copy). Omit src_port (auto-increment per flow), add tuples, or use dynamic session src_port` | `ftp.go:121`（`validateSessionStaticCopy`，`:101`） |
| N-5 | `ftp_dyn_neg_port_pattern` | `tcp.src_port={"strategy":"pattern",…}` | **（空串）** | `layers[1](tcp).src_port: pattern strategy is not supported for layer address/port fields` | `layer_dyn.go:508`（`checkDynShape`，`:369`）；经 `validate_layers.go:1004` 面 |

**负例纪律（存量实测，须如实登记）**：

- **N-1/N-2/N-3/N-4 的 `expect` 键集合 = `{expect_error, error_contains, notes}`**（含 `notes`），与严格两键口径（`{expect_error, error_contains}`）**不符** → G-FTP-9（P4 收窄时删 `notes`）。
- **N-5 的 `error_contains` 为空串**——执行期（`layer_chain_suite_test.go:329`）`want != ""` 才做子串匹配，故 N-5 **只断言"任务失败"，不断言锚词**。这是**唯一一条锚词未钉的负例** → G-FTP-9（P4 补锚词 `pattern strategy is not supported`）。
- **N-1/N-2/N-3/N-4 的失败点不在 ftp planner**：N-1 在 `checkLayerChainStaticCopy`（**schema 层，创建期 400**）、N-2 在 V9 范围校验（**层校验，创建期**）、N-3/N-4 在 **ftp planner `Validate`**（任务启动期，`ftp.go:152`/`:101`）。**N-3/N-4 是 ftp 自有分支，N-1/N-2 是框架分支**——文档与用例必须写清归属，不得笼统称"ftp 校验拒绝"。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：`invalid source IP: %s`（`ftp.go:70`）；`invalid destination IP: %s`（`ftp.go:75`）；`MSS %d too small (min %d per RFC 879)`（`ftp.go:81`，**planner 侧**，与 N-2 的 V9 侧**不是同一分支**）；`ftp %s: list strategy requires a non-empty list`（`ftp.go:173`）；`ftp %s: pattern strategy requires a template and a 2-element range`（`ftp.go:178`）；`ftp %s: pattern range start must not exceed end`（`ftp.go:181`）；`ftp %s: unknown dynamic strategy %q`（`ftp.go:185`）；`ftp %s: %s range start must not exceed end`（`ftp.go:168`）；`does not support dynamic`（`validate_layers.go:1004`）；`unknown field`（V9 未知键）。→ G-FTP-6。

**未入用例的静默路径（缺陷候选，须写清）**：

| 静默路径 | 现象 | 位置 | 缺口 |
|---|---|---|---|
| `file_source` 形状不匹配 | `{"source_type":"literal","content":…}` 解析为 nil → **数据通道静默不发**（不报错、不回落 Payload） | `strategy_convert.go:1984-2016` + `layer_gen.go:254-258` | G-FTP-2 |
| `PayloadCache` 未注入 | 同上（`FileSource != nil` 但 cache nil → `return nil`） | `layer_gen.go:254-258` | G-FTP-2 |
| `data_channel.mss` | 层内可写、链路径**完全忽略**（不报错） | `layer_gen.go` 全文无 `dc.MSS` 读取（`grep` 零命中） | G-FTP-4 |
| `dc.Direction` | 层内可写、链路径**完全忽略**（不报错） | `layer_gen.go:273`（`_ = dc.Direction`） | G-FTP-5 |
| `username`/`password` registry 键 | registry 声明 `Default:"anonymous"`，但 **planner/生成器零读取**（`grep` 实测：`FTPConfig` 无该字段） | `registry.go:1549-1550` | G-FTP-10 |
| `transactions` registry 键 | registry 声明为**层顶层键**，但 `ParseFTPConfigFromMap` 只读 `banner`/`commands`/`data_channel`/`sessions`（**不读顶层 `transactions`**） | `strategy_convert.go:9149-9154` vs `registry.go:1553` | G-FTP-10 |

**不得误报的合法协议事件**：空会话（`ftp_empty_session` 7 帧合法）；空命令跳过（`ftp_retr_passive` 的 `{"cmd":"","response":"226 …"}`）；无 `emit_data_channel` 标记时有 `data_channel` 不发射（`ftp_noflag_no_subflow` 9 帧合法）；`direction` 被忽略（G-FTP-5）；`abort_after_bytes >= len`（no-op，合法）。

## 8. 边界与容量

- **帧长**：控制帧长 = `len(文本)+2`；最小事件帧 = 单字符命令（`tcp.len=3`）；数据帧长 = `min(剩余, MSS)+54`（IPv4）。**实测最大帧**：`ftp_mss_segmentation` 数据 PSH `tcp.len=1460`（以太帧 1514）；`ftp_perf_1000flows` 单流同上。
- **分段**：段数 = `ceil(len(payload)/MSS)`，MSS = 链 `tcp.mss`（缺省 1460）。两例实测：2528B → 2 段；2200B → 2 段（**`dc.mss=536` 未生效**，G-FTP-4）。
- **端口**：控制口 1–65535（`tcp.src_port/dst_port` V9 范围校验）；数据客户端口 `ctrlPort+1` **溢出守卫 65535→1024**（`ftp.go:678-682`，`ftp_port_overflow` 实测）；PASV/EPSV/PORT/EPRT 通告端口 `[0,65535]` 外**推导返回 0**（回落下一优先级）。
- **会话/事务/流规模**：`sessions[]` 无上限（无界列表，V9 跳过）；`transactions[]` 无上限；`flows` 实测上限 **1000**（`ftp_perf_1000flows` → 14000 帧）。
- **连接数**：**同一 `(src,dst)` 端口对 = 同一条 TCP 连接**（tcp 层 `conns` map 键）——故"会话数"与"TCP 连接数"**不等价**（G-FTP-3 实测：2 会话同端口 → 1 条连接）。
- **包数公式（逐形状，已对 138 例 pcap 全量验证）**：
  - **单连接** = `3`（握手）+ `N`（控制帧数，= banner + Σ(每命令 1..2)）+ `4`（挥手）——**无独立 ACK 帧**（事件模式：ACK 不单独发射）。
  - **一条数据连接** = `3` + `ceil(len(payload)/MSS)` + `4`。
  - **一例总包数** = `Σ(每条连接)` × `flows`。
  - **校验**：`ftp_smoke_01` = 3（握手）+ 7（banner 1 + 3 命令×2）+ 4（挥手）= **14** ✓（实测 14）。
  - **收尾规则三态（不可用一条通用式覆盖）**：① **老形状/会话形状有 CloseConn 事件** → 每个 key 的挥手**内联在该事件后**（4 帧/key），流末 `connOrder` 已空、不再补（`generator.go:1570-1578`）；② **空会话** → 补端口专属建连事件（`CloseConn=true`，无载荷）→ 3 + 4 = 7（`ftp_empty_session`）；③ **流末仍有未 CloseConn 的连接** → 按首见序逐条 4 帧（`generator.go:1620-1630`）。**实测无第③态用例**（141 例全部走①②）。
- **不得产生回绕长度或超量分配**：数据载荷整块发射后交 tcp 层分段（无全量聚合）；控制文本逐条 `[]byte(cmd+"\r\n")`。

## 9. 原子 ID 与完成定义（141 个唯一语义 ID，顺序为权威）

**机读统计（2026-09-29）**：141 例 = **136 正 + 5 负**；层形 `[ip,tcp,ftp]` 110 + `[tcp,ftp]` 31；`strategy_fc` 51 例（全 `type=flows`，值域 {2:9, 3:38, 4:2, 100:1, 1000:1}）；IPv6 12 例；`fields` 断言 331 条（122 例）；`frames` 断言 3 条（1 例）；`distinct_values` 断言 58 条。

### 9.1 包数三方对账（cases JSON × 结果产物 × 真实 pcap）

| 项 | 结果 |
|---|---|
| 有 `packet_count` 的正例 | **104**（其余 32 正例只有 `min_packets`） |
| `packet_count == min_packets`（凡两者都有） | **104/104**（零例外） |
| 真实 pcap 帧数 == 结果产物包数 | **138/138**（零例外） |
| 真实 pcap 帧数 == `packet_count`（凡有） | **104/104**（零例外） |
| 真实 pcap 帧数 >= `min_packets` | **136/136**（零例外） |
| 无 pcap 的用例 | **3**（3 条负例） |

> **对账结论**：**包数在 cases JSON / 结果产物 / 真实 pcap 三方完全一致**（这是本协议的一个强项，与 opcua 的"包数全错"形成对照）。**但"三方一致"不等于"模型正确"**——`ftp_file_source`/`ftp_file_source_abort`（载荷未上路）与 `ftp_multiflow_multisession`（会话合并）三方都一致，却是 §0.2 登记的语义问题。

### 9.2 包数族分布（由 138 例实测 pcap 机读得出）

| 包数 | 例数 | 形态 |
|---:|---:|---|
| 7 | 1 | 空会话（3+4） |
| 9 | 1 | 无 emit 标记（不发射子流） |
| 13/14 | 4 | 短登录序列 / banner 缺省 |
| 16 | 18 | 单命令 2 帧 + banner 系 |
| 18 | 9 | 3 命令 / fail 分支 |
| 20/22 | 5 | 多命令 |
| 25–32 | 43 | 数据通道单发（3+3+1+4 或 +2 段） |
| 36–48 | 8 | 多会话 / 动态端口 |
| 60/70 | 6 | 多流 / 多流多会话 |
| 1400/14000 | 2 | 性能（100 / 1000 流） |

### 9.3 逐例 ID 索引

**完整 141 行索引表见用例文档 `103-ftp-testcase.md` §2**（ID / 类型 / 场景 / 依据链 / 包数 / 断言，与 `cases/ftp.json` 逐条一致）。本节只给**分组概览**：

| 分组 | 例数 | ID 前缀 |
|---|---:|---|
| 冒烟/多命令 | 2 | `ftp_smoke_01`、`ftp_multi_command` |
| 流关联（数据通道） | 55 | `ftp_retr_*`/`ftp_stor_*`/`ftp_pasv_*`/`ftp_port_*`/`ftp_dataconn_*`/`ftp_abor_*`/`ftp_appe`/`ftp_stou`/`ftp_nlst`/`ftp_list_*`/`ftp_rest_*`/`ftp_allo_*`/`ftp_payload_b64`/`ftp_abort_bytes`/`ftp_file_source*`/`ftp_epsv_*`/`ftp_eprt_*` 等 |
| 会话/多流 | 12 | `ftp_sessions_*`/`ftp_3sessions_mixed`/`ftp_txindex_dual`/`ftp_pasv_isolation`/`ftp_empty_session`/`ftp_noflag_no_subflow`/`ftp_session_partial_data_tx`/`ftp_multiflow_*` |
| RFC 959 命令全枚举 | 24 | `ftp_min_*`/`ftp_type_*`/`ftp_login_*`/`ftp_rnfr_rnto`/`ftp_file_mgmt`/`ftp_cdup`/`ftp_smnt`/`ftp_syst`/`ftp_help`/`ftp_stat*`/`ftp_site` |
| 应答码分支（成功/失败/中间态） | 22 | `ftp_*_fail`/`ftp_*_success`/`ftp_transfer_*`/`ftp_stor_5*`/`ftp_syntax_500`/`ftp_arg_501`/`ftp_service_421`/`ftp_badseq_503`/`ftp_502_notimpl`/`ftp_type_504_badparam`/`ftp_retr_110_marker`/`ftp_banner_120_greeting`/`ftp_dataconn_125`/`ftp_dataconn_250`/`ftp_dataconn_425` |
| 动态字段（层 + 会话 + 命令 + 载荷） | 35 | `ftp_dyn_*`/`ftp_session_dynamic_ports`/`ftp_ipv6_dyn_*` |
| IPv6 | 12 | `ftp_ipv6_*`/`ftp_epsv_passive_download`/`ftp_eprt_active_upload`（后两者为 v6 fixture） |
| 性能 | 2 | `ftp_perf_100flows`/`ftp_perf_1000flows` |
| 负例 | 5 | `ftp_neg_*`/`ftp_dyn_neg_port_pattern` |

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | 控制连接 TCP 21 + 数据连接独立 TCP（RFC 959 §3.2） | 场景 ①③④ | `DependsOn ["tcp"]`；链强制 `concurrent=true`（`chain_planner_chain.go:487`）；数据通道靠事件端口覆盖合成独立 connKey | 无 |
| 2 | 命令/消息表 | RFC 959 §4.1 命令 30+ 条 + RFC 2428 EPSV/EPRT | 场景 ③–⑬ | 逐字回放，**无命令枚举**（不校验命令合法性，`types.go:2414`） | 无（**设计选择**：不做状态机） |
| 3 | 状态机 | RFC 959 §5 序列（登录前/登录后/传输中） | 场景 ①③⑨ | **无自有状态机**（诚实声明 §5.1）；序列语义由用户写在 `response` | 无（显式不适用） |
| 4 | 字段表 | 命令行/应答行/六元组/EPRT 三元组 | 数据场景层 | §3.1/§3.4 逐字段；正则四处口径（§3.4） | 无 |
| 5 | 错误处理 | RFC 959 §4.2.1 错误码 + §5 序列错误 | 场景 ⑩ | 5 条负例（§7）+ 9 条未入例拒绝分支 | A′ 6 条（G-FTP-6/9） |
| 6 | 超时与活性 | RFC 959 §4.1.3 NOOP 保活；§4.1.1 REIN 重初始化；421 服务超时 | 场景 ⑩（`ftp_min_noop`/`ftp_login_rein`/`ftp_service_421`） | 逐字回放（**无真实保活定时器**，`NOOP` 只是普通命令） | 无（**显式不适用**：生成器无定时器语义） |
| 7 | NAT/代理/被动 | **PASV/EPSV 就是 FTP 的 NAT 穿透机制**（RFC 2428 标题明写） | 场景 ③⑦⑪ | PASV/EPSV/PORT/EPRT 四路推导（§3.4）；`ftp.passive.nat`/`ftp.active.nat` 字段存在但**零使用** | G-FTP-8（NAT 字段未收编） |
| 8 | 版本/方言 | RFC 959 基版 + RFC 2428 扩展；IPv4/IPv6 | 场景 ⑪⑬ | `epsv/eprt` 已落码；IPv6 12 例；**EPRT af=1 显式不实现** | G-FTP-6（af=1 无负例） |

### 10.2 子表①：命令 × 终态矩阵（逐格已覆/立项/不适用）

RFC 959 §4.1 命令 33 条（§4.1.1 八条 + §4.1.2 五条 + §4.1.3 二十条，**存量零遗漏**）× 三终态（T1 正常 / T2 失败应答 / T3 配置拒绝）：

| 命令族 | T1 正常终态 | T2 失败应答 | T3 配置拒绝 |
|---|---|---|---|
| 访问控制（USER/PASS/ACCT/CWD/CDUP/SMNT/REIN/QUIT） | 已覆（`ftp_smoke_01`/`ftp_login_acct`/`ftp_cdup`/`ftp_smnt`/`ftp_login_rein`） | 已覆（`ftp_login_530`/`ftp_login_530_cmd`/`ftp_cwd_550_fail`） | 不适用（命令文本无配置面） |
| 传输参数（PORT/PASV/TYPE/STRU/MODE） | 已覆（`ftp_type_ascii`/`_local`/`_image`/`ftp_min_stru`/`ftp_min_mode`/`ftp_retr_passive`/`ftp_stor_upload`） | 已覆（`ftp_arg_501`/`ftp_type_504_badparam`/`ftp_dataconn_425`） | 不适用 |
| 服务命令（RETR/STOR/STOU/APPE/ALLO/REST/RNFR/RNTO/ABOR/DELE/RMD/MKD/PWD/LIST/NLST/SITE/SYST/STAT/HELP/NOOP） | 已覆（`ftp_retr_passive`/`ftp_stor_upload`/`ftp_stou`/`ftp_appe`/`ftp_allo_stor`/`ftp_rest_retr`/`ftp_rnfr_rnto`/`ftp_abor_*`/`ftp_file_mgmt`/`ftp_list_226_success`/`ftp_nlst`/`ftp_site`/`ftp_syst`/`ftp_stat*`/`ftp_help`/`ftp_min_noop`） | 已覆（`ftp_retr_550_notfound`/`ftp_stor_532_nospace`/`ftp_stor_452_quota`/`ftp_stor_552_exceedalloc`/`ftp_stor_553_filename`/`ftp_stor_551_pagetype`/`ftp_rnfr_450_fail`/`ftp_dele_550_fail`/`ftp_transfer_450`/`ftp_transfer_451_localerr`/`ftp_dataconn_425`/`ftp_badseq_503`/`ftp_syntax_500`/`ftp_502_notimpl`） | 不适用 |
| RFC 2428（EPSV/EPRT） | 已覆（`ftp_epsv_passive_download`/`ftp_eprt_active_upload`） | 已覆（`ftp_epsv_500_fallback`/`ftp_eprt_522_reject`） | **A′ 立项**（EPRT af=1 → 返回 0 静默，G-FTP-6） |
| 未知命令 | 已覆（`ftp_syntax_500` 的 500 应答） | — | **A′ 立项**（未知键 `unknown field`，G-FTP-6） |

**逐格重数**：4 行 × 3 列 = 12 格——已覆 **9**（T1 列 4 + T2 列 4 + 未知命令 T1 1）/ A′ 立项 **2**（EPRT af=1、未知键）/ **不适用 1**（访问控制 T3 代表例——命令文本无配置面，三类命令族同判但只计 1）。9 + 2 + 1 = 12 ✓

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **26 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | 空会话（零事务） | 覆（`ftp_empty_session`，7 帧） |
| 2 | 空命令（`cmd==""`） | 覆（`ftp_retr_passive` 的 226 轮次） |
| 3 | 空应答（`response==""`） | **A′ 立项**（`layer_gen.go:184` 有分支，今日无例） |
| 4 | banner 缺省 | 覆（`ftp_login_nobanner`，13 帧） |
| 5 | banner 非 220（120 延迟问候） | 覆（`ftp_banner_120_greeting`） |
| 6 | 数据通道有 `DataChannel` 但无 `emit` 标记 | 覆（`ftp_noflag_no_subflow`，9 帧） |
| 7 | 内联文本载荷 | 覆（多例） |
| 8 | 内联 base64 载荷（含 NUL） | 覆（`ftp_payload_b64`） |
| 9 | `file_source` 载荷 | **覆但失效**（`ftp_file_source`/`ftp_file_source_abort` —— 形状不匹配致静默不发，G-FTP-2） |
| 10 | `abort_after_bytes` 截断 | 覆（`ftp_abort_bytes` 1024→10） |
| 11 | `abort_after_bytes >= len`（no-op） | **A′ 立项**（`layer_gen.go:264` 分支，今日无例） |
| 12 | 载荷跨 MSS 分段（1 段） | 覆（多数数据例，`tcp.len=14` 单段） |
| 13 | 载荷跨 MSS 分段（2 段） | 覆（`ftp_mss_segmentation`/`ftp_dc_mss_override`） |
| 14 | `data_channel.mss` 通道级覆盖 | **覆但失效**（`ftp_dc_mss_override` 钉现状：被忽略，G-FTP-4） |
| 15 | passive + 信令端口 | 覆（`ftp_retr_passive` 49993） |
| 16 | passive + 无信令（回退 50000） | 覆（`ftp_dataconn_fallback`） |
| 17 | passive + EPSV 229 | 覆（`ftp_epsv_passive_download` 50010） |
| 18 | active + PORT 信令 | 覆（`ftp_stor_upload` 12371） |
| 19 | active + EPRT af=2 | 覆（`ftp_eprt_active_upload`） |
| 20 | active + 无信令（回退 ctrl+1，server 20） | 覆（`ftp_active_retr`/`ftp_active_appe`） |
| 21 | 显式 `src_port`/`dst_port` 覆盖信令 | 覆（`ftp_dataconn_explicit_ports`） |
| 22 | `ctrlPort==65535` 溢出回退 1024 | 覆（`ftp_port_overflow`） |
| 23 | `direction` 决定载荷流向 | **覆但失效**（实测恒由 mode 决定，G-FTP-5；`ftp_stor_upload` 声明 up 实测 down） |
| 24 | 单会话多事务（各挂数据通道） | 覆（`ftp_txindex_dual`/`ftp_pasv_isolation`/`ftp_session_partial_data_tx`） |
| 25 | 多会话（2–3 个） | 覆（`ftp_sessions_dual`/`ftp_3sessions_mixed`/`ftp_sessions_mixed_mode`） |
| 26 | 多流 × 数据通道 / 多流 × 多会话 | 覆（`ftp_multiflow_data`/`ftp_multiflow_multisession`） |

**逐行重数**：26 行中 **A′ 立项 2 行**（行 3 空应答、行 11 `abort_after_bytes >= len`），其余 **24 行已覆**（其中行 9/14/23 三条标"覆但失效"——有落点但行为与字面不符，分别对应 G-FTP-2/G-FTP-4/G-FTP-5）。24 + 2 = 26 ✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 匿名/具名登录（RFC 959 §4.1.1） | `ftp_smoke_01`/`ftp_login_acct` | 已覆 |
| 2 | 认证失败处理 | `ftp_login_530`/`ftp_login_530_cmd` | 已覆 |
| 3 | 文件下载（RETR，NAT 环境走 PASV） | `ftp_retr_passive`/`ftp_ipv6_data` | 已覆 |
| 4 | 文件上传（STOR，防火墙内走 PORT） | `ftp_stor_upload`/`ftp_active_appe` | 已覆 |
| 5 | 目录列表（LIST/NLST） | `ftp_list_226_success`/`ftp_nlst` | 已覆 |
| 6 | 大文件续传（REST） | `ftp_rest_retr`/`ftp_rest_stor_upload` | 已覆 |
| 7 | 唯一存储（STOU）/追加（APPE） | `ftp_stou`/`ftp_appe` | 已覆 |
| 8 | 传输中断（ABOR）三情形 | `ftp_abor_completed`/`_midtransfer`/`_idle` | 已覆 |
| 9 | 空间/配额/权限失败 | `ftp_stor_532_nospace`/`ftp_stor_452_quota`/`ftp_stor_553_filename` | 已覆 |
| 10 | 目录与文件管理 | `ftp_file_mgmt`/`ftp_rnfr_rnto`/`ftp_cdup` | 已覆 |
| 11 | IPv6 产线（RFC 2428） | 12 例 IPv6 | 已覆 |
| 12 | 多客户端并发（多会话/多流） | `ftp_multiflow_multisession`/`ftp_perf_1000flows` | 已覆（**但会话端口解析域为流序号**，G-FTP-3） |
| 13 | FTPS（AUTH TLS / 隐式 990） | — | **明确不解决**（G-FTP-7；`OptionalOn ["tls"]` 已声明但零用例） |
| 14 | 真实文件系统读取（`file_source`） | — | **明确不解决**（G-FTP-2；离线套件无 PayloadCache） |
| 15 | 通道级 MSS（`data_channel.mss`） | — | **明确不解决**（G-FTP-4） |

**重数**：覆 **12** / 明确不解决 **3** = 15 ✓ 无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比

三路：① **规范原文**（RFC 959 §3/§4/§5 + RFC 2428 §3/§4/§5 + RFC 879，定"必须是什么"）；② **商业化软件实际行为**（**未取到**：真实 FTP 服务器/客户端线字节未抓包核对——本车道用的是**本仓引擎自产 pcap**，属"自证"而非"外部对照" → G-FTP-11 待确认）；③ **可靠开源实现思路**（vsftpd/proftpd 的 PASV 端口分配策略、`lftp` 的 EPSV 优先——只借鉴"PASV 端口必须与控制连接同源地址"这一条思路）。三路一致点：命令/应答行格式、六元组编码、EPSV/EPRT 语法；**不一致点**：**载荷流向**（真实 FTP 的 RETR 是 server→client，本引擎链路径 passive 恒 client→server，§3.6/G-FTP-5）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `ftp` 终结层 + tcp 层 `concurrent` 多连接（本版，pop3/smtp 同构先例） | 多会话/数据通道可声明可断言；代价 = 一套层（已落码 1566 行） | **采用** |
| B | 直接 tcp 层 + 顶层 payload 拼接 | 无命令/应答结构、无端口推导、无多连接 → 141 例中 139 例不可表达 | **否决** |
| C | 拆"控制层 ftp-ctrl + 数据层 ftp-data"两层 | 数据连接端口依赖控制通道信令（跨层状态传递），框架层间无此通道 | **否决**（状态在 `scanTxForDataPort` 单层内聚更简单） |

## 11. P2 D-FTP-1 代码设计（CORE_MEMORY §8 八要素；as-built 定稿）

> 状态说明：实现已落码（`internal/protocol/ftp/` 两文件 + core 接线），本条为**逆向定稿**（as-built），供后续改动的唯一入口。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:2406-2545` + `:1696`） | `FTPConfig`/`FTPSession`/`FTPTransaction`/`FTPCommand`/`FTPDataChannel` + `FlowSpec.FTP` 槽位 | —（共享文件） |
| `trafficgen/internal/protocol/ftp/ftp.go` | legacy planner：`Validate`（6 分支）+ `planSessions` + `Plan` + 端口推导四正则 + `emitFTPDataChannel`/`emitTxDataChannel` + 分段 | **1197** |
| `trafficgen/internal/protocol/ftp/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator` + `RegisterLayerValidator`，`init()`）+ `emitLegacy`/`emitSession`/`emitDataChannel`/`dataChannelPorts`/`resolveSessionPort`/`emitWithSessionClose` | **369** |
| 测试 10 文件 | `ftp_data_test.go` 1044 / `ftp_coverage_test.go` 564 / `ftp_testpoints_test.go` 432 / `ftp_dyn_test.go` 319 / `ftp_filesource_test.go` 316 / `ftp_sessions_test.go` 260 / `ftp_perf_test.go` 124 / `chain_equivalence_ftp_test.go` 83 / `epsv_eprt_test.go` 81 / `ftp_ipv6_test.go` 60 | **3283**（**81 个 `Test*`**） |
| 接线 7 件 | registry 注册（`layers/registry.go:1546`）/ 层内 translate（`chain_planner_translate.go:2614`）/ `ParseFTPConfigFromMap`（`strategy_convert.go:9145`）/ convert 缺省口（`strategy_convert.go:986`）/ protocols 准入（`protocols.go:40`）/ 链缺省口（`chain_planner.go:1207`）/ 链强制 concurrent（`chain_planner_chain.go:487` + `isFTPChain` `chain_planner_util.go:146`）/ 扁平判死（`strategy_convert.go:8626`→`9123`） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`ftp.go:67`）：源/目的 IP 可解析；`TCP.MSS >= 536`（`ftp.go:79-83`）；`validateDynFields`（`:84`）；`validateSessionStaticCopy`（`:87`）。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`ftp.go:215`）：`Sessions` 非空 → `planSessions`（`:234-237`）；否则单控制流路径（`:239-391`）。
- `planSessions`（`ftp.go:404`）：逐会话独立 `sessSpec`（端口覆盖 + 动态解析）、独立 `flowID`/`packetIndex`/`ipID`/ISN、独立握手/banner/事务/teardown。
- 生成器：`Name() "ftp"`（`layer_gen.go:36`）；`GenEvents()` 返回自身（`:342`）；`EmitEvent` 未接线显式错（`:347-349`，防误调）；`Generate` 逐事件 `EmitMsg`（`:44-108`）。

### 11.3 数据结构

`FTPConfig{Banner, Commands[], DataChannel, Sessions[]}`（`types.go:2428-2437`）；`FTPSession{SrcPort, Banner, Transactions[], SrcPortDyn, BannerDyn}`（`:2450-2458`）；`FTPTransaction{Commands[], DataChannel}`（`:2464-2467`）；`FTPCommand{Cmd, Response, EmitDataChannel, CmdDyn, ResponseDyn}`（`:2470-2495`）；`FTPDataChannel{Mode, SrcPort, DstPort, Direction, Payload, PayloadB64, MSS, AbortAfterBytes, FileSource, PayloadDyn}`（`:2525-2545`）。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry Fields 7 键 allowlist + `checkLayerDynObjects`）→ `translateTerminalConfig` 的 `case "ftp"`（`chain_planner_translate.go:2614`：扁平内容为空时用 `ParseFTPConfigFromMap` 覆盖 `spec.FTP`）→ Meta 直传（`chain_planner_translate.go:214-218` `FTP: spec.FTP`）→ 链强制 `tcp.concurrent=true` → 生成器 `Generate`（老形状 `emitLegacy` / 多会话 `emitSession`）→ 逐事件 `EmitMsg`（端口覆盖）→ tcp 层（`generator.go:1443-1640`：按 connKey 独立握手/恢复 seq/CloseConn 内联挥手/流末统一挥手）→ worker（builder）→ writer（PCAP/NIC）。

### 11.5 错误分支与静默路径

**6 个 planner 拒绝分支**（全部传 task error）：`invalid source IP`（`ftp.go:70`）/ `invalid destination IP`（`:75`）/ `MSS %d too small`（`:81`）/ `validateDynFields` 5 种（`:165/168/173/178/181/185`）/ `validateSessionStaticCopy`（`:121`）。

**静默路径 6 条**（§7 表，全部**不报错**）：`file_source` 形状不匹配（G-FTP-2）/ `PayloadCache` 未注入（G-FTP-2）/ `data_channel.mss` 忽略（G-FTP-4）/ `dc.Direction` 忽略（G-FTP-5）/ `username`/`password` 未读（G-FTP-10）/ 顶层 `transactions` 未读（G-FTP-10）。

> **G-FTP-2 根因链（完整，机读逐行核对）**：用例写 `{"source_type":"literal","content":"…"}` → `ParseFTPConfigFromMap`（`strategy_convert.go:9156`）调 `parseFileSource(getMap(m,"data_channel"))` → `parseFileSource`（`:1984-2016`）先取 `cfg["file_source"]` 子映射，再**只认 `file`/`literal`/`fill`/`random` 四键**（`:1990/1993/1996/2002`），**`source_type`/`content` 均不在列** → 四字段全零 → `:2012-2014` 返回 **nil** → `dc.FileSource = nil`，`dc.Payload = ""`（用例未写 `payload`），`dc.AbortAfterBytes = 8`（仅 `_abort` 例）→ `layer_gen.go:252-266`：`FileSource` nil 跳过第一分支、`PayloadB64` 空跳过第二分支 → `payloadBytes = []byte("")`（len 0）；`AbortAfterBytes > 0 && 8 < 0` **为假** → `payloadBytes` 仍为空 → `emitMsg` 发 `Bytes: []byte{}` 且 `CloseConn: true` → tcp 层 `generator.go:1519` 的 `!(len(ev.Bytes) == 0 && closeAfter)` 取反 **为真** → **跳过数据段**，只走握手 + CloseConn 挥手 = **7 帧**。**与实测完全吻合**：`tshark -r ftp_file_source.pcap` 数据连接帧 13–19 共 7 帧、`tcp.len` 全 0 ✓

### 11.6 性能边界

见 §8（逐事件流式产出、per-flow 局部状态、无跨流共享、无锁；控制文本逐条分配）。**吞吐数字待 P5 基准**，本版不写承诺。

### 11.7 与现有逻辑的冲突点

- `CheckFTPFlat`（`strategy_convert.go:9123`）**有 ftp 专分支**（`CheckProtoFlat` `:8626-8628` 首行即 `if protocol == "ftp" { return CheckFTPFlat(cfg) }`）：拒顶层 `src_ip/dst_ip/src_port/dst_port/count` 五键 + 顶层 `ftp` 子映射。**ftp 是唯一有专分支的协议**（其余走通用五键 + 逐协议子映射白名单）。
- **顶层未知键通用门仍缺**：游离顶层键（如 `{layers:[…], bogus: 1}`）今日**不判死** → presence 负例今日建了会真绿 = **假通过，不建**（G-FTP-9，与 opcua G-OPCUA-1 同款；**禁加单协议黑名单分支**）。
- **动态 allowlist**（`layer_dyn.go:18-72`）：`ftp` **零命中**（`grep -c '"ftp"' layer_dyn.go` = 0 实测）→ **ftp 层业务字段动态对象即拒**；业务字段动态走 `spec.FTP`（`sessions[].src_port` 等，**不经层 allowlist**，由 `validateDynFields` 管）。四元组 `ip`/`tcp` 全开。
- registry `ftp` **Fields 7 键**：`username`/`password`/`banner`/`sessions`/`transactions`/`commands`/`data_channel`。其中 `username`/`password`/`transactions` **无消费者**（G-FTP-10）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert `internal/protocol/ftp/` 两源文件 + 接线 8 处（registry/protocols/translate/ParseFTPConfigFromMap/convert/chain_planner/chain_planner_chain/isFTPChain）；不触及其他协议。cases 回滚 = 恢复 141 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 **141/141 顶层键仅 `{layers}`**（+51 例 `strategy_fc`），**零残留、零迁移工作量**；目标形状见 §2 三例（单流/数据通道/多会话） | §12.1；`cases/ftp.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 ftp 流量模板；任务 = 多策略合跑 + 总量封顶；数量走 `flow_control`（51 例实测） | §2 样例；§9 统计 |
| §3 五件套 | 见 §12.3 强制展开：会话表 / 事务序列 / **流关联（本协议核心）** / 插入位置（终结层）/ 时间线。**有长连接，不豁免** | §12.3 + §6 |
| §4 查规范 | RFC 959 + RFC 2428 + RFC 879 + tshark 3.6.14 `ftp.*` 33 字段 + **138 例实测 pcap** + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["tcp"]`（`registry.go:1546`）；6 个 planner 拒绝分支 + 4 框架/校验分支；5 条负例（§7） | §5/§7/§11.5 |
| §6 性能 | 见 §8（6.1–6.8 要素齐；吞吐数字标待 P5 基准；pcap/NIC 两路验收明写） | §8 |
| §7 三份文档 | `103-ftp-{design,testcase}.md` v1.0.0（本对）+ D-FTP-1（§11，as-built 定稿）+ T-FTP（testcase §2，141 ID） | 修订记录 |
| §8 设计先行 | 本协议**无旧设计文档**（§0.1 实测），本对为**首份文档**；as-built 型（实现与 cases 已在，文档逆向定稿） | §0.1 |
| §9 测试三源 | 三源 = RFC 959/2428/879（§10）+ D-FTP-1（§11）+ tshark 3.6.14 字段与 **138 例 pcap 实测**（包数 138/138 三方一致，§9.1）；141 ID 逐项回指；存量审计 testcase §8 | `103-ftp-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 本车道自审（见修订记录）+ 收官隔离复审 | 修订记录 |
| §11 白话 | 本文首节白话一句 | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；**业务字段 5 类开 / 6 类关** + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `ftp` 已在 `registry.go:1546` 注册（**不新增层**）；Fields 7 键；**若改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `ftp.*`/`tcp.*` + frames 三通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/ftp/`（138 例） | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/ftp.json` | 141 | **`{layers}` ×85 + `{layers, strategy_fc}` ×56**（`strategy_fc` 是**数量声明**，非旧键；**零游离键**） | `[ip,tcp,ftp]` ×110 + `[tcp,ftp]` ×31 | 5/5 = `{expect_error, error_contains, notes}` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 已住 `layers[i].ip.src/dst`（100/99 例显式写；IPv6 例写 `ipv6` 值） |
| `src_port` | **0** | 已住 `layers[i].tcp.src_port`（96 例显式写；其余走保底 `12345+i`） |
| `dst_port` | **0** | 已住 `layers[i].tcp.dst_port`（94 例显式写；其余走缺省 21） |
| `count` | **0** | 走 `flow_control`（51 例 `strategy_fc type=flows`） |
| 顶层 `ftp` 子映射 | **0** | 已住 `layers[i].ftp`（141/141）；`CheckFTPFlat`（`strategy_convert.go:9133`）判死其 presence |
| `strategy_fc` | **56** | **合法**：策略级数量声明（`{"type":"flows","value":N}`），非旧扁平键；`layer_chain_suite_test.go:238-243` 转 `spec.Count` |

**结论**：**本协议存量 141/141 顶层零残留**——§1 门的动作 = ①**无旧键可删**；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测：141/141 顶层 ∈ `{layers, strategy_fc}`）；③A′ 新增例全部沿用纯 layers 形。

目标形状样例见 §2（单流/数据通道/多会话三例）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"ftp":{}}` 今日**会被拒**（`CheckFTPFlat` `strategy_convert.go:9133` 专分支，`if v, ok := cfg["ftp"]; ok && v != nil` → 返回"no longer accepts a top-level ftp sub-config"）——**与 opcua/moxa 不同，ftp 有专分支** ✓。但**存量 141 例无此负例** → A′ 立项（G-FTP-9）。② 白名单外游离键判死（`unknown field`）今日**无通用门** → G-FTP-9，**不建**（建了会真绿 = 假通过）。③ 5 负例每条带锚词（4 条有，1 条空串 → G-FTP-9）。④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

**① 会话表**（`sessions[]` 形状；老形状为单隐式会话）：

| 会话 | 形态 | 端口 | 用例 |
|---|---|---|---|
| 老形状单会话 | `sessions` 空 → 单控制流 + `sub-0` 数据通道 | 链 tcp 端口 | 102 例 |
| `s1`/`s2`/`s3` 多会话 | 每会话独立四元组/序号/握手/teardown，**按序整块回放** | `sess.src_port`（静态/动态） | 39 例（`ftp_sessions_dual`/`ftp_3sessions_mixed`/`ftp_ipv6_sessions_mixed` 等） |
| 数据通道（每事务至多一条） | `{parent}:sub-{txIdx}`，独立四元组/序号/握手/teardown | §3.4 推导 | 55 例 |

**② 事务序列**（每事务四件事：前置/触发/成功/失败）：
- **前置**：控制连接已建立（tcp 层自动握手）；本事务所需的信令命令（PASV/PORT/EPSV/EPRT）已在**本事务内**出现（事务域隔离，§6.2）。
- **触发**：命令带 `emit_data_channel=true`（`txHasDataChannel`，`ftp.go:621`）。
- **成功**：数据通道发射（握手 3 + 载荷段 + 挥手 4），控制通道随后（老形状）或之前（会话形状）有 226/250（§6.3）。
- **失败**：无 `emit` 标记 → 不发射（`ftp_noflag_no_subflow`）；或 `response` 写失败码（450/550 等）→ 控制通道只有应答，无数据连接（`ftp_transfer_450`/`ftp_retr_550_notfound` 等 15 例）。

**③ 关联关系（本协议核心）**：控制流派生数据流，**主从关系**由 `emit_data_channel` 锚定；**端口一致性**（数据 server 口 = 本事务信令通告口）与**客户端口 +1**是关联的两个可观察面（§6.1）。**无 `driven_by` 字段**——关联靠**事件端口覆盖合成 connKey**（tcp 层 `conns` map）实现。**多会话**：各会话独立，**会话间不共享状态**（但**同流内多会话若端口解析同值会合成同一连接**，G-FTP-3）。

**④ 插入位置**：终结层（`[ip,tcp,ftp]`，无中间层）；数据通道挂在**触发它的事务**下（§6.3 两形状位置不同）。

**⑤ 时间线**：会话内严格顺序；事务内命令/应答交替；数据通道插入位置逐形状（§6.3）；多会话按序整块（**不交错**）；多流由 worker 按 flowIdx 展开（`flows` 51 例）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组层**（`layer_dyn.go:18-21` allowlist 实测）：

| 字段 | 开/关 | 五策略 | 序号算法 | 存量用例 |
|---|---|---|---|---|
| `ip.src` | **开** | fixed/inc/rand/list/**pattern**（IPv4/IPv6 双面） | `genIPValue`（`layer_dyn.go:576+`）；IP 范围按地址族比较（`checkIPRangeOrder`，`:483`） | `ftp_dyn_ip_src_inc`/`_rand`/`_list`/`_fixed`、`ftp_ipv6_dyn_src_inc`/`_rand`/`_list` |
| `ip.dst` | **开** | 同上 | 同上 | `ftp_dyn_ip_dst_inc`/`_rand`/`_fixed`、`ftp_ipv6_dyn_dst_fixed` |
| `tcp.src_port` | **开** | fixed/inc/rand/list（**pattern 拒绝**） | `ResolvePortValue`（`tuple_generator.go:300`） | `ftp_dyn_tcp_srcport_inc`/`_rand`/`_list`/`_fixed`；负例 `ftp_dyn_neg_port_pattern` |
| `tcp.dst_port` | **开** | 同上 | 同上 | `ftp_dyn_tcp_dstport_inc`/`_rand` |
| `ip.ttl` | **开**（allowlist 有，本协议零用例） | — | — | — |

**业务字段**（**ftp 层零 allowlist 行**，`grep -c '"ftp"' layer_dyn.go` = **0** 实测 → 层内业务字段写动态对象即 `does not support dynamic`）：

| 业务字段 | 层内动态 | 会话内动态 | 五策略 | 序号算法 | 存量用例 |
|---|---|---|---|---|---|
| `sessions[].src_port` | **拒**（层 allowlist 无 ftp） | **开** | fixed/inc/rand/list/pattern | `ResolvePortValue(sess.SrcPortDyn, spec.FlowIndex)`（`ftp.go:415`/`layer_gen.go:143`）——**按流序号，非会话序号**（G-FTP-3） | `ftp_dyn_sessport_rand`/`_list`/`_fixed`/`_wraparound`、`ftp_session_dynamic_ports` |
| `sessions[].banner` | **拒** | **开** | 同上 | `ResolveStringValue(sess.BannerDyn, spec.FlowIndex)`（`ftp.go:420-424`/`layer_gen.go:160-164`） | `ftp_dyn_banner_inc`/`_rand`/`_fixed`/`_pattern`、`ftp_banner_dyn_list` |
| `transactions[].commands[].cmd` | **拒** | **开** | 同上 | `ResolveStringValue(cmd.CmdDyn, i)`（`resolveTx`，`ftp.go:606-610`） | `ftp_dyn_cmd_inc`/`_rand`/`_list`/`_fixed`、`ftp_dyn_command_pattern` |
| `transactions[].commands[].response` | **拒** | **开** | 同上 | `ResolveStringValue(cmd.ResponseDyn, i)`（`ftp.go:611-615`） | `ftp_dyn_resp_inc`/`_rand`/`_list`/`_fixed`、`ftp_response_dyn` |
| `transactions[].data_channel.payload` | **拒** | **开** | 同上 | `ResolveStringValue(dc.PayloadDyn, i)`（`ftp.go:581-587`） | `ftp_dyn_payload_inc`/`_rand`/`_list`/`_fixed`、`ftp_dyn_payload` |
| `banner`（顶层，老形状） | **拒** | **不适用**（老形状无动态面，`FTPConfig` 无 `BannerDyn`） | — | — | — |
| `commands[].cmd/response`（顶层，老形状） | **拒** | **不适用**（`FTPCommand` 有 `CmdDyn`/`ResponseDyn`，但 `emitLegacy` **不调 `resolveTx`** → 老形状动态字段**不生效**） | — | — | — |
| `data_channel.payload`（顶层，老形状） | **拒** | **不适用**（同上，`emitLegacy` 不调 `resolveTx`） | — | — | — |
| `data_channel.mode/src_port/dst_port/direction/mss/abort_after_bytes` | **拒** | **关**（无动态形状） | — | — | — |

> **老形状动态字段不生效（G-FTP-12，须写清）**：`FTPCommand.CmdDyn`/`ResponseDyn` 与 `FTPDataChannel.PayloadDyn` 由 `parseFTPCommands`（`strategy_convert.go:2193-2194`）/`parseFTPDataChannel`（`:2424`）**无条件解析**（老形状与多会话形状共用同一 parse 函数），但 `emitLegacy`（`layer_gen.go:202-236`）**不调用 `resolveTx`** → 老形状写动态字段**被解析但不生效**（静默）。存量 35 例动态用例**全部用 `sessions[]` 形状**（机读实测：动态站点全部落在 `sessions[]` 内），故**未暴露**。

**序号算法实读行号**：`parseLayerDyn`（`layer_dyn.go:78`）/ `checkDynShape`（`:369`）/ `genIPValue`（`:576+`）/ `ResolvePortValue`（`tuple_generator.go:300`）/ `ResolveStringValue`（`:310`）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go:18-72`，**`ftp` 无块**）。

## 13. P3 对接清单（T-FTP 草稿输入；正文落 testcase 文件）

141 ID（136 正 + 5 负）+ 包数/锚词 + fixture 常量 + 三通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。

**A′ 候选（12 条，P4 立项）**：`ftp_neg_top_ftp_presence`（顶层 `ftp` 子映射判死，`CheckFTPFlat` 已有分支）/ `ftp_neg_unknown_top_key`（**不建**，无通用门，G-FTP-9）/ `ftp_neg_port_pattern_anchor`（N-5 补锚词）/ `ftp_neg_mss_planner`（`ftp.go:81` planner 侧，与 N-2 不同分支）/ `ftp_neg_bad_ip`（`:70`/`:75`）/ `ftp_neg_dyn_list_empty`（`:173`）/ `ftp_neg_dyn_pattern_no_range`（`:178`）/ `ftp_neg_dyn_unknown_strategy`（`:185`）/ `ftp_neg_dyn_field`（`does not support dynamic`，`validate_layers.go:1004`）/ `ftp_empty_response`（`layer_gen.go:184` 分支）/ `ftp_abort_noop`（`abort_after_bytes >= len`）/ `ftp_tls_ftps`（G-FTP-7）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 三要素（现象/证据/归属） | 去向 |
|---|---|---|---|
| **G-FTP-1** | 结果产物：数字未经今日复跑 + pcap 留档缺失 | **现象**：`trafficgen/docs/protocol-pcap-test/ftp.md` 标 141/141 pass，但 ① **141/141 数字未经本车道今日复跑证实**（本车道未跑套件；产物未标跑测日期）；② `docs/protocol-pcap-test/ftp/` 目录**不存在**，141 条 `[pcap](ftp/…)` 链接**全悬空**；③ 3 条负例无 `.neg.pcap`。**证据**：`git log -1` = `711423d`（2026-09-19，**晚于**判死提交 `0417be5` → 字面“过期”判据**不成立**）；`ls trafficgen/docs/protocol-pcap-test/ftp` = No such file or directory；`ls /tmp/mcp-pcaps/ftp \| wc -l` = 138。**注（重要，不得读成缺陷）**：`711423d` 是对产物的**修正**（`01fab60` 只 139 行 → 该提交补 2 行 + 把 `ftp_neg_static_copy` 包数 18 改 0）；且**行内包数与真实 pcap 138/138 一致**（§9.1）。**归属**：**代码阶段**（P5 重跑后重生成 + 补 pcap 留档）。另注：产物行序为字母序，与 JSON 顺序不同，引用须按 ID | 代码阶段；本版**不删不改** tracked 产物 |
| **G-FTP-2** | `file_source` 形状不匹配致数据通道**静默不发** | **现象**：`ftp_file_source`/`ftp_file_source_abort` 的 `file_source` 写 `{"source_type":"literal","content":…}`，`parseFileSource`（`strategy_convert.go:1984-2016`）只认 `literal`/`file`/`fill`/`random` 四键 → 解析 nil → `layer_gen.go:252-263` 走空 `Payload` → tcp 层跳过空载荷 CloseConn 事件（`generator.go:1519`）→ 数据连接只有 7 帧（3 握手 + 4 挥手，**无 PSH**）。**证据**：`tshark -r ftp_file_source.pcap` 帧 13–19 `tcp.len` 全 0；对照 `ftp_abort_bytes`（内联）帧 16 `tcp.len=10`；`ftp.go:783-785` 空载荷产空段的路径**未走到**（因 `CloseConn` 守卫）。**归属**：**cases 或代码**（P4 裁定：改 cases 写正确形状 `{"literal":…}`，或扩 `parseFileSource` 认 `source_type`/`content` 别名；**本车道不改**）。**连带**：`abort_after_bytes` 亦无从生效（同一根因）。**风险**：`http_file_source_literal` 用正确形状 `{"source_type":"literal","literal":…}`（多一个 `source_type` 冗余键），且离线套件**不注入 PayloadCache** → **http 同形例今日同样静默不发**（实测帧 4 `tcp.len=140` 说明 http 走的是另一分支——http 生成器对 nil cache 有回落，ftp 无） | P4 裁定（改 cases 或扩 parse）；同时评估离线套件是否应注入 PayloadCache |
| **G-FTP-3** | 会话级 `src_port_dyn` 按**流序号**解析，同流多会话解析同值 → 合成同一 TCP 连接 | **现象**：`ftp_multiflow_multisession`（flows=2、每流 2 会话、`src_port_dyn inc [41000,41001]`）实测每流仅 **2 条** TCP 连接（41000/41001），70 帧 = 2×35，而非 4 条连接的 84 帧。**证据**：`tshark -r ftp_multiflow_multisession.pcap` 帧 1–35 与 36–70 端口序列同构；`ftp.go:415` / `layer_gen.go:143` 用 `spec.FlowIndex`（非会话序号）。**归属**：**设计语义**（用例 `notes` 已自陈并已按真实 pcap 钉住）——**不是缺陷，是已声明边界**；本契约 §5.2/§12.12 首次成文写清。**去向**：P4 若需"每会话独立端口"，须引入**会话序号**索引域（新设计项）；否则维持现状并在用例文案保持自陈 | P4 裁定（维持 + 文档化，或新增会话序号域） |
| **G-FTP-4** | `data_channel.mss` 链路径**完全忽略** | **现象**：`ftp_dc_mss_override` 写 `mss=536`、载荷 2200B，实测**按链全局 1460 分 2 段**（若生效应为 536×5 段）；层内可写、**不报错**。**证据**：`grep -n 'dc.MSS' layer_gen.go` **零命中**；`ftp.go:693-696`（legacy 路径）读 `dc.MSS`，链路径不读；实测 28 帧 = 3+2+4 + 控制 15 + 4。**归属**：**代码**（P4：扩 `MessageEvent` 携带 per-conn MSS，或删该层字段避免死配置）。用例 `notes` 已自陈"B 类缺口登记" | P4 裁定（补实现或删字段） |
| **G-FTP-5** | `dc.Direction` 链路径**完全忽略**，载荷流向恒由 `mode` 决定 | **现象**：链路径 passive 恒 client→server（**与真实 FTP RETR 语义相反**）、active 恒 server→client；`ftp_stor_upload` 声明 `direction=up` 实测**数据载荷方向为 up**（巧合一致）；`ftp_retr_passive` 声明 `down` 实测 **up**（**与声明相反**）。**证据**：`layer_gen.go:273` `_ = dc.Direction`；`generator.go:1515-1518` `ServerFirst=true` 强制 `evUp=false`；`tshark -r ftp_retr_passive.pcap` 帧 16 `12346→49993`（client 发）。**归属**：**代码**（P4：把 `direction` 接进事件载荷方向，或删该字段并收窄用例文案）。**口径纪律**：**不得**把"direction 声明 down、实测 up"读成"用例错"——用例只是钉了现状 | P4 裁定（接线或删字段 + 用例文案同步） |
| **G-FTP-6** | 线格式/配置类负例覆盖不足 | **现象**：5 条负例**全是配置/校验类**；**无一条线格式负例**（畸形 227 六元组、畸形 EPRT、`^\|2\|` 缺段、端口越界 65536、多行 227 续行劫持、`227\t` tab 分隔）。9 条未入例拒绝分支（§7）。**证据**：`cases/ftp.json` 负例机读全表（§7）。**归属**：**P4 补例**（`ftp_neg_malformed_pasv` / `ftp_neg_eprt_af1` / `ftp_neg_port_overflow_signal` 等）。**注**：畸形信令**今日不报错**（推导返回 0 → 回落下一优先级），故这类负例**不能写 `expect_error`**，只能写"推导回落"的**正例**（钉回落行为） | P4 补例（正例形式钉回落） |
| **G-FTP-7** | FTPS/TLS 底座零用例 | **现象**：registry `OptionalOn: ["tls"]`（`registry.go:1548`）声明可选底座，141 例**零用例**（`grep -c '"tls"' cases/ftp.json` = 0）。**证据**：机读。**归属**：**P4 补例或显式不解决**（`AUTH TLS` 显式升级 / 隐式 990 均未实现） | P4 裁定 |
| **G-FTP-8** | tshark `ftp.*` 33 字段中 **29 个零使用**（含流关联专用字段） | **现象**：本机 tshark 3.6.14 `ftp.*` 字段 **33 个**（实测 `tshark -G fields \| awk '$3 ~ /^ftp\./'`）；存量只用 `ftp.request.command`/`ftp.request.arg`/`ftp.response.code`/`ftp.response.arg` **4 个**；**`ftp.setup-frame`/`ftp.command-response.frames`/`ftp.passive.port`/`ftp.passive.ip`/`ftp.active.port`/`ftp.active.ip`/`ftp.epsv.port`/`ftp.eprt.port`/`ftp.eprt.af`/`ftp.current-working-directory` 等 29 个零使用**（33 总 − 4 已用）。**证据**：字段名直方图（§6.5）。**归属**：**P4 收编**（尤其 `ftp.setup-frame` 是**流关联的官方断言通道**，可把 §6.1 的"关联性"从间接证明升级为直接断言） | P4 补 field 断言 |
| **G-FTP-9** | 负例 `expect` 形状不符 + 锚词未钉 + 缺 presence 负例 | **现象**：① 5 条负例 `expect` 键集合 = `{expect_error, error_contains, notes}`（**含 `notes`**），与严格两键口径不符；② `ftp_dyn_neg_port_pattern` 的 `error_contains` = **空串**（执行期只判"失败"，不判锚词）；③ 顶层 `ftp` 子映射 presence 负例**存量零条**（`CheckFTPFlat` `strategy_convert.go:9133` **已有分支**，可建）；④ 游离顶层未知键**无通用门**（`unknown field`），**不建**（假通过）。**证据**：机读 §7 表 + `layer_chain_suite_test.go:329`（`want != ""` 才匹配）。**归属**：**P4**（删 `notes`、补锚词、补 presence 负例、**禁加单协议黑名单分支**） | P4 补/收窄 |
| **G-FTP-10** | registry 3 键无消费者（死配置） | **现象**：`registry.go:1546-1557` 声明 `username`（Default `"anonymous"`）/`password`（Default `"anonymous"`）/`transactions` 三键，但 ① `FTPConfig` **无 `Username`/`Password` 字段**（`types.go:2428-2437`），planner/生成器零读取；② `ParseFTPConfigFromMap`（`strategy_convert.go:9149-9154`）**只读 `banner`/`commands`/`data_channel`/`sessions`**，**不读顶层 `transactions`**（`transactions` 只在 `sessions[]` 内消费）。**证据**：`grep` 实测（§7 静默路径表）。**归属**：**P4**（登记或删——三键层内可写但无效，属死配置）。**风险**：用户写 `{"ftp":{"transactions":[…]}}` 会**静默无效**（无 `sessions` 时走老形状，`transactions` 被忽略） | P4 裁定（删键或接线） |
| **G-FTP-11** | 第三源（真实服务器/客户端线字节）未取到 | **现象**：本版对照用的 138 例 pcap **全部是本仓引擎自产**（"自证"），**未抓真实 vsftpd/proftpd 或 lftp 的线字节**。**证据**：`/tmp/mcp-pcaps/ftp/` 时间戳 2026-09-27（本仓跑出）。**归属**：**待确认**（抓真实 FTP 会话对照，尤其**载荷流向**与 PASV 端口分配策略）。**风险（须写清）**：若真实 RETR 确为 server→client 而本引擎 passive 恒 client→server，则 G-FTP-5 从"语义存疑"升级为"**与现网不符**"，涉及 **55 条流关联用例的载荷方向断言口径**（当前用例只断端口与帧位，**不断载荷方向**，故包数不受影响） | 待确认（抓包对照） |
| **G-FTP-12** | 老形状动态字段**被解析但不生效** | **现象**：`parseFTPCommands`（`strategy_convert.go:2193-2194`）/`parseFTPDataChannel`（`:2424`）**无条件**解析 `CmdDyn`/`ResponseDyn`/`PayloadDyn`（老形状与 `sessions[]` 共用 parse 函数），但 `emitLegacy`（`layer_gen.go:202-236`）**不调 `resolveTx`** → 老形状写动态字段**静默无效**。**证据**：`grep -n 'resolveTx' layer_gen.go` → 仅 `emitSession`（`:175-177`）命中；存量 35 例动态用例**全部用 `sessions[]` 形状**（机读实测），故未暴露。**归属**：**代码**（P4：`emitLegacy` 补 `resolveTx`，或删老形状的 dyn 解析避免误以为生效） | P4 裁定 |
| **G-FTP-13** | T-编号体系不完整 | **现象**：用例 `summary` 中仅 **15 个 `T-FTP-*` 编号**在案（T-FTP-2/2b/2 sessions/3/4/5/6/10/10b/11/11b/12/18/19/20/21），**T-FTP-1/7/8/9/13–17 无对应用例**（`grep` 机读零命中）。**证据**：`cases/ftp.json` 的 `summary` 字段机读全表（用例文档 §5.3）。**归属**：**文档**（本契约已以 **141 个 JSON ID 为唯一权威**，T-编号降为历史对照；如需补齐须由 P4 重建编号体系，**不得**据 T-编号反推用例集完整性） | 文档阶段已收编（§5.3 对照表）；编号体系重建列 P4 |
| **G-FTP-14** | 4 处 `summary` 帧数与实测不符 | **现象**：`ftp_retr_passive`（summary 说 28 帧，实测 27）、`ftp_stor_upload`（说 28，实测 27）、`ftp_dyn_command_pattern`（说 46，实测 44）、`ftp_dyn_payload`（说 46，实测 44）。**证据**：`tshark -r <id>.pcap \| wc -l` 逐例实测；`ftp_retr_passive` 的 `notes` 已给出正确拆解（"控制 18 + 数据 9 = 27"），仅 `summary` 未同步。**归属**：**cases 文案**（`summary` 是描述字段、**不是断言**，故**不影响执行结果**；P4 改写 summary 使与包数一致）。**注**：`packet_count`/`min_packets` 与实测一致，**断言无误** | P4 改文案（不影响断言与执行） |
| **G-FTP-15** | 22 条命令无失败应答用例 | **现象**：机读实测 **14 条命令**有 4xx/5xx 失败应答例，**22 条无**（`ACCT`/`ALLO`/`APPE`/`CDUP`/`HELP`/`MKD`/`MODE`/`NLST`/`NOOP`/`PASV`/`PORT`/`PWD`/`QUIT`/`REIN`/`REST`/`RMD`/`RNTO`/`SMNT`/`STOU`/`STRU`/`SYST`/`USER`）。**证据**：逐例解析 `cmd` × `response` 配对，取 response 首位属于 4 或 5 者（用例文档 §8.1 机读表）。**归属**：**P4 补例**（RFC 959 §4.2.1 为其中多数定义了失败码：`MKD` 521/550、`RMD` 550、`PWD` 550、`CDUP` 550、`ACCT` 530/503、`ALLO` 504/552、`APPE` 532/550、`STOU` 450/550、`REST` 501/554）。**注**：`QUIT`/`PASV`/`PORT` 的失败语义较边缘，可不补 | P4 补例（按 RFC 959 §4.2.1 逐命令） |

## 15. 修订记录

- v1.0.0（2026-09-29）：P-PIPE 文档轨批次二 · as-built 契约首版。ftp **首份设计文档**（§0.1 实测：本仓从无 ftp 设计文档）；§0.2 三条三方冲突裁定（`ftp_file_source`/`ftp_file_source_abort` 载荷静默不发 = G-FTP-2；`ftp_multiflow_multisession` 会话合并 = G-FTP-3 已声明语义）；§0.3 产物登记（G-FTP-1）；§1 profile 六档 + 八条显式边界；§3 逐字段可生成级（命令表/应答码表/四路端口推导/四处正则口径/载荷优先级）；§4 十三类现网场景 + 五层覆盖；§5 会话模型与自动派生（含**两形状数据通道插入位置差异**）；**§6 流关联专章**（主从关系/事务域隔离/插入位置/方向与截断/不断言面）；§7 负例锚词表 + 6 条静默路径；§8 边界与容量（**逐形状包数公式，不写伪通用式**）；§9 三方包数对账（**138/138 一致**）+ 逐例索引；§10 P1 八项矩阵 + 三子表；§11 as-built D-FTP-1（含 **G-FTP-2 完整根因链**）；§12 门1 十四行 + §12.1/§12.3/§12.12 强制展开 + 12-P2；§13 A′ 候选 12 条；**§14 缺口 15 条**（G-FTP-1…G-FTP-15）。
  **自审 3 轮，末轮干净**（机读脚本复核，非手算）。第 1 轮：34 项计数/直方图全对（141 例、331 field 断言、55 数据通道实例、138 例 pcap 三方包数一致、41 应答码、36 命令）。第 2 轮（结构审）捕获并修复 **5 处**：① 缺口表缺 G-FTP-13（T-编号不完整）/G-FTP-14（4 处 summary 帧数不符）而用例文档已引用；② §14 G-FTP-1 行内 `ls … | wc -l` 竖线未转义致表格列数破；③ §3.3 应答码数写 30（实际 41）、§3.2 未声明命令覆盖数；④ §0.3 原稿误判 `711423d` 为"重排致错位"——`git show` 实测该提交是**修正**（139→141 行 + 修 1 处包数），已按实测改写；⑤ §12 门1 表 §1 行"全仓 27 协议"措辞。第 3 轮（完备性审）捕获并修复 **1 处**：§3.2 未声明 22 条命令无失败应答例（补 G-FTP-15）。另修正 2 处 `generator.go` 行号引用（1516/1521→1519/1515-1518，`grep` 复核）。**第 3 轮全部机读断言 0 失败**。

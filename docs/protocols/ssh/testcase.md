# SSH-2 用例契约

> 版本 v1.1；日期 2026-09-30；机器权威：`trafficgen/test/protocol_pcap/cases/ssh.json`。
> 白话：一条正例把 TCP 建连、SSH 协商、认证、会话通道和关闭串起来；断言钉住包字段和原始字节，而不是只看任务是否报错。

## 1. 三源与执行口径

用例由 RFC 4252/4253/4254/8308、设计契约和当前 SSH encoder/生成器三源派生。MCP/pcap/NIC 应消费同一 JSON；真实执行顺序是建策略/任务→生成→落盘或网卡抓包→tshark 校对。本文不把历史结果文档当今日执行证据。

层链严格为 `[ip,tcp,ssh]`；地址只在 ip，端口只在 tcp，数量只在 `flow_control`。无 VLAN、IPv4/TCP option 时 SSH payload offset=54；IPv6=74；TCP data offset 变化时按实际头长定位。BPP `packet_length` 是 payload 起点的 uint32 BE，值为 `1+payload_len+padding_len`，不含自身和 MAC。版本行不属于 BPP；NEWKEYS 后 dummy MAC/padding 不能证明真实加密。

## 2. 测试点清单（T1–T6）

| 门 | 必测点 | 当前去向 |
|---|---|---|
| T1 三源 | RFC 字段/顺序、实现 encoder、tshark fields/frames | 正例 §3；未测项 §5 |
| T2 原子功能 | TCP 三次握手、KEXINIT、DH、NEWKEYS、service、auth、channel、FIN | `ssh-basic-session` |
| T3 数据边界 | 大端长度、padding、string 长度、message number、offset 54 | `fields` + `frames` |
| T4 会话三项 | 同流多轮操作已覆；异常结束由 FIN 已覆；长保活/rekey 缺口登记 | §4、G-SSH-1/2 |
| T5 存量逐条去向 | 原存量 ID 与正例断言保留，顺序/阈值/fields/frames/notes 不改 | §3 |
| T6 失败与反查 | 负例必须纯 `expect_error,error_contains`；正例不得只断言成功状态 | `ssh-invalid-scenario`、`ssh-invalid-server-version-crlf`；反查 §6 |

## 3. 存量 ID（1 正例、2 负例）

| # | ID | 类型 | 设计回指 | `min_packets` | fields / frames |
|---:|---|---|---|---:|---:|
| 1 | `ssh-basic-session` | 正 | 设计 §3/§4；RFC 4253 §6–§8、RFC 4252 §5、RFC 4254 §5–§6 | 20（历史结果 23，未作今日证据） | 11 fields、11 frames |
| 2 | `ssh-invalid-scenario` | 负 | 设计 §5.1；SSH `Validate` | — | `expect_error` + `error_contains` |
| 3 | `ssh-invalid-server-version-crlf` | 负 | 设计 §5.1；RFC 4253 §4.2 | — | `expect_error` + `error_contains` |

正例 `spec_json` 是严格层链 `[ip{10.0.0.1→20.0.0.1}, tcp{12345→22}, ssh{}]`，无顶层旧键且无 `flow_control`，因此只证明单流基线；两个负例也只使用同一层链和 `ssh` 层字段。保留正例 ID、数组顺序、包阈值、fields、frames、notes，不凭文档重算新数字。

## 4. 原子断言

### 4.1 TCP 与 SSH 阶段

- packet 1：`tcp.flags=0x002`、`tcp.dstport=22`。
- packet 2：`tcp.flags=0x012`；packet 3：`tcp.flags=0x010`。
- `has_handshake=true`、`negotiated=true`、`has_payload=true`、`terminates=true`。
- notes 记录双向 KEXINIT、KEXDH_INIT/REPLY、双向 NEWKEYS、SERVICE、USERAUTH_SUCCESS、CHANNEL_DATA、EOF、双方 CLOSE；本例版本字段为空，故不产生 banner；这些 notes 是溯源，不替代可执行 fields/frames。

### 4.2 BPP 字段

`ssh.packet_length_encrypted`：packet 4=`0000037c`、6=`0000002c`、8=`0000000c`、10=`0000001c`、12=`0000003c`、13=`0000000c`、14=`0000002c`。这些值验证大端长度、padding 和 payload 结构；不验证真实密码学。

### 4.3 原始帧

所有 offset=54，按连续字节前缀匹配：

| packet | hex 前缀 | 语义 |
|---:|---|---|
| 6 | `00 00 00 2c 06 1e 00 00 00 20` | length 44、KEXDH_INIT(30)、e string 32B |
| 8 | `00 00 00 0c 0a 15` | length 12、NEWKEYS(21) |
| 10 | `00 00 00 1c 0a 05 00 00 00 0c 73 73 68 2d 75 73 65 72 61 75 74 68` | SERVICE_REQUEST(5)、`ssh-userauth` |
| 12 | `00 00 00 3c 08 32 00 00 00 05 61 6c 69 63 65` | USERAUTH fixture anchor、用户名 alice |
| 13 | `00 00 00 0c 0a 34` | USERAUTH_SUCCESS(52) |
| 14 | `00 00 00 2c 13 5a 00 00 00 07 73 65 73 73 69 6f 6e` | CHANNEL_OPEN(90)、session |
| 15 | `00 00 00 1c 0a 5b` | OPEN_CONFIRMATION(91) |
| 16 | `00 00 00 1c 0c 5e 00 00 00 00 00 00 00 06 65 78 69 74 0d 0a` | CHANNEL_DATA(94)、recipient 0、`exit\r\n` |
| 17 | `00 00 00 0c 06 60 00 00 00 00` | CHANNEL_EOF(96)、recipient 0 |
| 18 | `00 00 00 0c 06 61 00 00 00 00` | CHANNEL_CLOSE(97)、recipient 0 |
| 19 | `00 00 00 0c 06 61` | 对端 CHANNEL_CLOSE(97) |

## 5. 覆盖矩阵与缺口

| 面 | 已覆 | 缺口（不冒充已覆） |
|---|---|---|
| 功能 | TCP、KEX、NEWKEYS、service、password success、session data/EOF/CLOSE、FIN | failure/retry、publickey、keyboard-interactive、hostbased、DISCONNECT、global/channel request、extended data、EXT_INFO、banner（当前正例版本字段为空） |
| 性能 | 20 包下界、KEXDH 32B e、固定 BPP 长度、逐帧原始字节 | MSS 分段、padding 4/255、长 output、并发、资源耗尽、吞吐/内存基准 |
| 数据 | IPv4、22、BE uint32、string、message number、默认剧本、版本 CR/LF 负例 | IPv6、非默认端口、算法列表边界、空/超长/NUL、非法 sender/packet size |
| 地址/流 | 单流四元组；无派生控制/媒体流 | 多独立会话、`flow_control` 多流、IPv6 |
| 业务 | 认证后 session + `exit` + 正常关闭 | exec/shell/pty、失败重试、长 stdout/stderr、转发 |

**§3.15 三项固定动作**：①同流多轮操作：已覆（KEX→service/auth→channel）；②非正常结束：SSH 层异常中断/失败消息无 JSON，G-SSH-2；③长保活：SSH rekey 字段不触发，G-SSH-1。无长连接豁免不适用，SSH 明确是长 TCP 会话。

## 6. 负例、反查和缺口

当前 cases 有 1 个正例和 2 个负例。正例证明可观察的默认主路径；负例证明未知 scenario 和版本 CR/LF 的 validator 错误传播。仍不能宣称其他 validator 行、认证变体和动态边界已覆盖。P4 应继续逐条建立纯负例（不得混入成功 fields/frames）：用户名/密码 NUL、MSS 边界、channel sender/maximum packet、认证失败/retry、未触发 KEX/错误状态；每例绑定代码实际 `error_contains` 锚词。

机器反查门：ID 集合严格为 `{"ssh-basic-session","ssh-invalid-scenario","ssh-invalid-server-version-crlf"}`；正例含四个布尔断言、`min_packets=20`；fields 包含 packet 4/6/8/10/12/13/14 的完整长度值；frames 恰 11 条且 offset=54，packet 集合为 `{6,8,10,12,13,14,15,16,17,18,19}`；packet 16 含 message 94、recipient 0、data length 6、`exit\r\n`；两个负例均仅含 `expect_error,error_contains`，`spec_json` 顶层只含 `layers`。

| 缺口 | 现象 | 归属 |
|---|---|---|
| G-SSH-1 | `rekey_after` 只解析，不触发 re-KEX | P4：实现并补例，或删除字段 |
| G-SSH-2 | 认证/消息变体、动态业务字段、其余 validator 负例和多流未全覆盖 | P4：先补 schema/translator/allowlist，再补例 |
| G-SSH-3 | 当前无今日 MCP/NIC 全量执行证据 | P5：真实建任务、生成、tshark 与 NIC 复跑 |
| G-SSH-4 | dummy 密码学不是互操作 SSH | 独立能力立项；当前只承诺 wire-shaped |

## 7. 修订与自审

- v1.1（2026-09-30）：修正旧稿“flat 存量”结论；按当前唯一 JSON 逐字段重列；补 T1–T6、§3.15、反查门、失败路径和缺口迁入计划。
- 自审 2 轮：逐条核对 JSON ID/键/断言值和 frame offsets；再核对设计矩阵、失败路径及正负例口径；末轮干净。

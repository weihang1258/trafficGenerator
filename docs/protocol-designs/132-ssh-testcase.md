# #132 SSH-2 用例契约

> 版本 v1.0；日期 2026-09-29；机器权威：`trafficgen/test/protocol_pcap/cases/ssh.json`。存量只有 1 例，本文不虚构额外 JSON ID。用例文档承担可执行断言，设计文档承担生成规格；两者不是一对一镜像。

## 1. 执行与断言口径

测试输入经层链 planner 生成 TCP+SSH；pcap 与 NIC 输出共用同一用例契约。无 VLAN、IPv4/TCP options 时 SSH 应用字节 offset 为 54；IPv6 为 74；实际 TCP options 时按 TCP data offset 定位。正例必须同时验证 TCP 建连、SSH 版本/KEX/auth/channel 载荷、BPP `packet_length` 大端字段和 TCP 终止；不能用“任务未报错”替代字节/字段断言。

BPP `packet_length` 位于 SSH payload 起点，值为 `1+payload_len+padding_len`；MAC 不计入。版本行是 `SSH-2.0-...\r\n`，不属于 BPP。后 NEWKEYS 的内容在本实现只是可解析的 dummy padding/MAC，不能据此断言真实加密或服务器互操作。

## 2. JSON 逐 ID 索引（唯一存量集合）

| # | ID | 场景/依据链 | 包数 | 断言 |
|---:|---|---|---:|---|
| 1 | `ssh-basic-session` | RFC 4253 §4.2/§6/§7/§8/§11 + RFC 4252 §5 + RFC 4254 §5–§6；完整默认 session | `min_packets=20`，结果文档记录 23 | `has_handshake=true`, `negotiated=true`, `terminates=true`, `has_payload=true`; TCP packet 1 SYN flags `0x002`, dstport `22`; packet 2 SYN-ACK `0x012`; packet 3 ACK `0x010`; encrypted BPP packet_length at packets 4/6/8/10/12/13/14 = `0000037c/0000002c/0000000c/0000001c/0000003c/0000000c/0000002c`; raw frames below |

**机器契约与结果文档差异**：JSON 的 `expect.min_packets=20` 是执行阈值，`trafficgen/docs/protocol-pcap-test/ssh.md` 记录已存结果为 23 包；本稿不把过期结果文档当今日复跑证据（见 §5）。`expect.frames` 共 11 条；JSON `notes` 明确 f3 版本 banner，f4/f5 KEXINIT，f6 KEXDH_INIT，f7 KEXDH_REPLY，f8/f9 NEWKEYS，f10 SERVICE_REQUEST，f11 SERVICE_ACCEPT，f13 USERAUTH_SUCCESS，f16 CHANNEL_DATA，f17 EOF，f18/f19 CLOSE。

### 2.1 原始帧断言（cases JSON 原文逐条）

所有 offset 均为 54，hex 按连续字节比较：

| packet | offset | expected prefix/bytes | 语义依据 |
|---:|---:|---|---|
| 6 | 54 | `00 00 00 2c 06 1e 00 00 00 20` | BPP length 44；msg 30；DH init string length 32 |
| 8 | 54 | `00 00 00 0c 0a 15` | BPP length 12；padding 10；NEWKEYS 21 |
| 10 | 54 | `00 00 00 1c 0a 05 00 00 00 0c 73 73 68 2d 75 73 65 72 61 75 74 68` | BPP length 28；padding 10；SERVICE_REQUEST 5；string length 12 and `ssh-userauth` |
| 12 | 54 | `00 00 00 3c 08 32 00 00 00 05 61 6c 69 63 65` | BPP length 60；padding 8；USERAUTH_SUCCESS/fixture payload anchor per cases |
| 13 | 54 | `00 00 00 0c 0a 34` | BPP length 12；padding 10；USERAUTH_SUCCESS 52 |
| 14 | 54 | `00 00 00 2c 13 5a 00 00 00 07 73 65 73 73 69 6f 6e` | BPP length 44；padding 19；CHANNEL_OPEN 90; session string |
| 15 | 54 | `00 00 00 1c 0a 5b` | BPP length 28；padding 10；CHANNEL_OPEN_CONFIRMATION 91 |
| 16 | 54 | `00 00 00 1c 0c 5e 00 00 00 00 00 00 00 06 65 78 69 74 0d 0a` | BPP length 28；padding 12；CHANNEL_DATA 94; recipient 0; string length 6 `exit\r\n` |
| 17 | 54 | `00 00 00 0c 06 60 00 00 00 00` | BPP length 12；padding 6；CHANNEL_EOF 96; recipient 0 |
| 18 | 54 | `00 00 00 0c 06 61 00 00 00 00` | BPP length 12；padding 6；CHANNEL_CLOSE 97; recipient 0 |
| 19 | 54 | `00 00 00 0c 06 61` | BPP length 12；padding 6；CHANNEL_CLOSE 97 |

> `packet_length` 前缀、padding byte、message number 是可观察的；后 NEWKEYS MAC/padding filler 不得被当作密码学证明。cases 的 JSON `fields` 另外钉住 packets 4/6/8/10/12/13/14 的 `ssh.packet_length_encrypted` 值，上表与其一致。

## 3. 五层覆盖审计

### 功能层

已覆盖：TCP SYN/SYN-ACK/ACK；版本 banner（notes，非 fields）；KEXINIT 双向；KEXDH_INIT/REPLY；NEWKEYS 双向；SERVICE_REQUEST/ACCEPT；USERAUTH_SUCCESS；session channel open/confirmation/data/EOF/双方 close；FIN teardown。未在存量 JSON 原子覆盖：USERAUTH_FAILURE、BANNER、INFO_REQUEST/RESPONSE、publickey/keyboard-interactive/hostbased、DISCONNECT、IGNORE/UNIMPLEMENTED/DEBUG、global request、extended data、window adjust、channel request/success/failure、EXT_INFO。它们有实现函数但没有 cases ID，不能冒充已覆盖。

### 性能层

已覆盖一条完整 session 的最小可观察 BPP 帧和 23 包结果阈值；DH init 的 32B `string(e)`、固定 packet lengths 和 TCP options/MSS 的框架路径可断言。未覆盖 KEXINIT name-list 最大值、KEXDH_REPLY 长度边界、超 MSS 长 output、padding 4/255 相邻边界和大 payload 分段；列 G-SSH-7。

### 数据场景层

已覆盖默认端口 22、BE `uint32` packet length、string length+bytes、message number、空/默认 auth/channel 生成出的字节。未覆盖 IPv6、非默认端口、算法 name-list 变体、空/最大/非法 string、CR/LF/NUL validator、非法 channel sender/packet size、所有认证字段和值域；列 G-SSH-8。

### 地址与流层

已覆盖单流 IPv4 四元组和端口 22。SSH 本身无控制/媒体派生流，流关联不适用；多会话不是 `SSHConfig` 原生语义，由外层 flow_control 负责。IPv6、非默认端口和多独立会话缺少 JSON 例，列 G-SSH-8。

### 业务层

已覆盖现网基线：认证后打开 session、发送 `exit\r\n`、EOF、双方 CLOSE。未覆盖 exec/shell/pty、失败重试、publickey、长 stdout/stderr、转发等已实现 scenario；列 G-SSH-7。

## 4. 存量审计、负例与覆盖反查门

| ID/项目 | 去向 | 结论 |
|---|---|---|
| `ssh-basic-session` | 保留；不改 ID、顺序、包阈值、fields、frames、notes | 当前唯一存量集成冒烟 |
| 配置错误（CR/LF、NUL、MSS、channel） | 未进入 JSON | G-SSH-9；应为纯 `expect_error,error_contains`，不能夹带成功 frames |
| 线格式错误（长度/非法消息） | 未进入 JSON | G-SSH-7；BPP 为 builder 内部固定格式，暂无 fault injection case |
| 状态/关联错误（无 KEX、无 auth、错误 channel） | 未进入 JSON | G-SSH-7 |
| 载体错误（IPv6/非默认端口/NIC） | 未进入 JSON | G-SSH-8 |

建议 `coverage_gate.py` 反查行（静态可机读）：

1. ID 集合严格等于 `{"ssh-basic-session"}`；顺序不可变。
2. `ssh-basic-session.expect.min_packets == 20`，并含 handshake/negotiated/terminates/has_payload 四布尔断言。
3. packet 1/2/3 的 flags 为 `0x002/0x012/0x010`，packet 1 dstport 为 22。
4. fields 包含完整 packet_length 集合 `{4,6,8,10,12,13,14}` 及预期十六进制值。
5. frames 数量为 11；每个 frame offset 为 54；packet 集合为 `{6,8,10,12,13,14,15,16,17,18,19}`。
6. frame packet 16 原始字节包含 message 94、recipient 0、data length 6、`exit\r\n`；17/18/19 包含 message 96/97/97。
7. 非负例 spec_json 当前含顶层旧键；命中目标层链迁移审计 G-SSH-2，不得宣称扁平判死已过。
8. pcap 与 NIC 执行必须复用同一 ID/断言集；无今日 NIC 证据不得报 NIC 通过。

## 5. 产物过期登记与缺口

`trafficgen/docs/protocol-pcap-test/ssh.md` tracked，末次提交为 2026-08-16，早于 `0417be5`（2026-09-13 扁平判死）；其“Cases: 1 — pass 1”及 23 包 pcap 不能证明今日复跑，归属 P5 重跑。当前文档只把 JSON 作为权威。

| 缺口 | 现象/证据 | 归属 |
|---|---|---|
| G-SSH-7 | 传输/认证/连接层已实现消息、scenario、边界没有对应原子 JSON；五层功能/性能/业务覆盖不完整 | P4 用例扩充 |
| G-SSH-8 | IPv6、非默认端口、动态算法/字段、非法输入、MSS/长度边界、多会话未覆盖 | P4 用例扩充 |
| G-SSH-9 | Validator 错误分支无纯负例，不能验证错误传播/锚词 | P4 用例扩充 |
| G-SSH-10 | 唯一存量仍为 flat spec_json（src/dst/ports/count/ssh），未迁 `[layers]` 形 | P4 实现/迁移 |
| G-SSH-11 | 层 schema 无 SSH Fields，且 translateTerminalConfig 无 ssh 分支；非空层配置的生产链可达性未证明 | P4 实现 |
| G-SSH-12 | wire-shaped BPP 使用 dummy DH/key/signature/MAC/padding，不是真实加密或互操作 SSH | 明确待实现边界 |
| G-SSH-13 | `RekeyAfter` 文档称触发 re-KEX，但 planner/generator 忽略该字段 | P4 实现或删字段 |
| G-SSH-14 | 结果文档/pcap 早于 0417be5，未今日复跑 | P5 重跑 |

## 6. 修订记录与自审

- v1.0（2026-09-29）：按唯一 `ssh-basic-session` JSON 逐条抄录 ID、包阈值、fields、11 frames 与 notes；补五层覆盖、反查门、存量去向和 G-SSH-7…14。
- 自审 1 轮，末轮干净；待独立覆盖审查。

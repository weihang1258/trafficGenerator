# SSH-2 设计契约（as-built）

> 版本 v1.1；日期 2026-09-30；依据 RFC 4251/4252/4253/4254/4256/8308 与当前 Go 实现。
> 本文是 SSH 层链实现的事实契约；`test/protocol_pcap/cases/ssh.json` 是机器断言唯一权威。
>
> 白话：SSH 先在 TCP 上交换版本行，再按二进制包顺序完成密钥交换、认证和会话通道；当前生成器产生可解析的线格式样本，不实现真实密码学互操作。

## 1. 范围、依赖与边界

SSH 是 TCP 上的终结层：`ssh` 依赖 `tcp`，默认目的端口 22；TCP 层负责 SYN/ACK、序号、MSS 分段和 FIN，SSH 层只产生应用事件。目标配置只有层链：

```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345,"dst_port":22}},{"ssh":{}}],"flow_control":{"flows":1}}
```

`ip` 层承载地址，`tcp` 层承载端口，数量只在 `flow_control`。SSH 业务字段住 `ssh` 层；不得再使用顶层 `src_ip`、`dst_ip`、`src_port`、`dst_port`、`count` 或协议子映射。

已实现：版本行、KEXINIT、KEXDH_INIT/REPLY、NEWKEYS、EXT_INFO（可选）、SERVICE、用户认证、channel/global request、可选 DISCONNECT。未实现真实 DH、host key、签名、加密、压缩和 MAC 校验；NEWKEYS 后是可解析的 dummy MAC/填充线格式，不能声称可登录真实 SSH 服务端。`rekey_after` 当前只解析，不触发 re-KEX，登记为 G-SSH-1。

## 2. 配置与调用路径

`registry.go:1616-1619` 注册 `ssh` 终结层，`DependsOn=["tcp"]`，`FieldContract tcp.dst_port=22`。`chain_planner.go:1225` 提供端口缺省。legacy `strategy_convert.go:1495` 可把旧入口的 `ssh` 子映射读入 `FlowSpec.SSH`；层链路径由 `ChainPlanner` 将终结层配置传至 `FlowMeta.SSH`（`chain_planner_translate.go:307-309`），生成器 `SSHGenerator.Generate` 逐事件向 TCP 发送 payload。

SSH 层配置字段：`server_version`、`client_version`、算法 name-list、`kex`、`auth_methods`、`ext_info`、`channels`、`rekey_after`、`disconnect_on_close`、`scenario`、`command`、`stdout`、`stderr`。空 auth/channel 使用默认 password-success/session 剧本；`scenario` 支持 `exec`、`shell`、`pty-exec`、`publickey`、`auth_fail_retry`、`long_output`。版本字段任一非空时按 server→client 发版本行；均空则跳过版本交换。

### D1–D8 设计对照

| 门 | 结论 | 证据/缺口 |
|---|---|---|
| D1 层链唯一真相 | 目标形状只有 `[ip,tcp,ssh]`，地址/端口/数量各归属正确层 | §1、registry |
| D2 策略与任务 | 单 SSH 会话模板由策略 `flow_control` 复制；任务总量由任务层封顶 | 框架语义；SSH 无自有多会话数组 |
| D3 五件套 | 会话 s1；事务 t1 版本、t2 KEX、t3 service/auth、t4 channel、t5 teardown；无派生数据流；SSH 插入 TCP 后；顺序固定 | §4 |
| D4 规范三路 | RFC 定义线格式；本仓实现定义 dummy 边界；tshark/pcap 字段和 frame 断言校准 | §3、cases |
| D5 依赖错误 | TCP 前置；Validate 错误必须传播为任务失败，不得 0 包假成功 | `ssh` Validate / 负例 cases |
| D6 性能 | 逐事件流式生成；TCP 承担 MSS；边界见 §6，不承诺未测吞吐 | §6 |
| D7 三源与矩阵 | RFC、实现、机器 cases 逐项对照；功能/数据/地址/业务矩阵见 §5 | §5 |
| D8 实现边界 | dummy 密码学、rekey 和业务动态暂不宣称；每项均登记迁入位置，不作为已支持能力 | G-SSH-1/2 |

## 3. 线格式

SSH BPP 使用大端字段：

| 偏移 | 字段 | 规则 |
|---:|---|---|
| 0 | `packet_length` | uint32；从 padding length 起计，不含自身和 MAC |
| 4 | `padding_length` | uint8；至少 4，最多 255 |
| 5 | payload | message number + 字段 |
| 5+payload | padding | 随机填充，默认 block=8 对齐 |
| 末尾 | MAC | NEWKEYS 后 dummy 32B；之前无 MAC |

`packet_length = 1 + payload_len + padding_len`。SSH string/name-list 为 `uint32_be length + bytes`；版本行是 `SSH-2.0-<software>\r\n`，不属于 BPP。无 VLAN、无 IP/TCP option 时应用起点 IPv4 为 offset 54、IPv6 为 74；实际 TCP data offset 优先。

消息最小字段表：KEXINIT(20) 为 cookie + 十个 name-list + follows + reserved；KEXDH_INIT(30) 为 `string(e)`；KEXDH_REPLY(31) 为 `string(K_S)+string(f)+string(signature)`；NEWKEYS(21) 只有消息号；SERVICE_REQUEST/ACCEPT(5/6) 为 service string；USERAUTH_REQUEST(50)、FAILURE(51)、SUCCESS(52) 按 RFC 4252 字段；CHANNEL_OPEN(90)、OPEN_CONFIRMATION(91)、DATA(94)、EOF(96)、CLOSE(97)、REQUEST(98) 按 RFC 4254 字段。EXT_INFO(7) 按 RFC 8308 的扩展数组编码。

## 4. 状态、事务和失败

状态顺序：`TCP_ESTABLISHED → VERSION_EXCHANGED（可跳过） → KEXINIT → KEXDH → NEWKEYS → SERVICE → USERAUTH → CHANNEL → TCP_CLOSE`。默认 channel 依次 open/confirm、发送 `exit\r\n`、EOF、双方 CLOSE。认证失败走配置的 retry 或中断；DISCONNECT 终止后续 channel。每个事务明确：前置状态、触发消息、成功下一步、失败分支。SSH 是单 TCP 会话，无控制/媒体派生流；多独立会话由外层 `flow_control` 复制，当前 JSON 未覆盖。

## 5. 规范→场景→代码→缺口矩阵

### 5.1 八项规范矩阵

| 规范面 | 业务场景 | 当前代码/用例 | 结论 |
|---|---|---|---|
| 连接模型 | TCP 长连接、多轮业务 | TCP layer + `ssh-basic-session`（默认版本字段为空，跳过 banner） | 已覆盖 |
| 消息表 | KEX、认证、channel | encoders/scenario + frame anchors | 主路径覆盖；变体见 G-SSH-2 |
| 状态机 | 握手→KEX→auth→channel→关闭 | scenario/SSHGenerator | 已覆盖默认序列 |
| 字段/字节序 | BPP 长度、padding、string、message number | `buildBPP`；cases fields/frames | 已覆盖可观察字段 |
| 错误处理 | 参数非法、认证失败、异常关闭 | Validate/Scenario | 非法 scenario、版本 CR/LF 已覆盖；其余负例 G-SSH-2 |
| 活性 | rekey、长输出 | `long_output` 分支 | rekey 未触发，G-SSH-1 |
| NAT/代理 | 单 TCP 承载 | 无 SSH 专用代理语义 | 框架面，不适用 |
| 版本/方言 | SSH-2、EXT_INFO | RFC 4253/8308 encoder | 正例无 banner；EXT_INFO 变体缺口 |

### 5.2 命令/响应矩阵（主路径）

| 请求/阶段 | 成功 | 失败/变体 |
|---|---|---|
| VERSION | 双向 banner | 空版本跳过 |
| KEXINIT | 双向 20 | 算法列表/EXT_INFO 变体 G-SSH-2 |
| KEXDH | INIT→REPLY | 密码学真实验证不在范围 |
| NEWKEYS | 双向 21 | dummy MAC，不声称真实加密 |
| SERVICE | REQUEST→ACCEPT | 服务拒绝 G-SSH-2 |
| USERAUTH | password→SUCCESS | failure/retry、publickey 等 G-SSH-2 |
| CHANNEL | open→confirm→data→EOF/CLOSE | request/global/extended data G-SSH-2 |

### 5.3 数据形态与现网映射

已覆：IPv4、默认端口 22、BPP 大端长度、KEXDH 32B e、认证用户名 alice、session `exit\r\n`、TCP 建连/终止；本存量用例因版本字段为空而不覆盖 banner。缺口：IPv6、非默认端口、MSS 分段、算法列表边界、空/超长输入、用户名/密码 NUL、客户端版本 CR/LF、各认证方法、长 stdout/stderr、异常中断。现网三路结论：RFC 定字段和顺序；实现是 dummy wire-shape；真实 OpenSSH 互操作未验证，不把它写成通过。

## 6. 性能设计与验收

生成器逐事件发送，不聚合整段会话；每事件只持有当前 BPP payload，TCP worker 负责分段。当前基线为 1 会话、最小可观察 20 包阈值，历史结果 23 包；未测吞吐、并发、内存和长时间压力，不作数字承诺。验收必须分别记录 pcap 与 NIC；两者共用 cases 断言。本车道未执行今日 MCP/NIC 重跑，G-SSH-3 登记为 P5 重跑。

## 7. 层链、动态和缺口

会话五件套：s1 为单 TCP 会话；t1–t5 如 §4；无 `driven_by`（无派生流）；插入 `[ip,tcp,ssh]` 终结层；事件严格顺序。地址/端口可使用框架 dynamic；SSH 业务字段当前无 dynamic allowlist，按 fixed 使用，不能宣称 inc/rand/list/pattern。需补业务动态时改 registry/schema、translator 和 worker 序号算法，并为每一策略建例（G-SSH-2）。

| 缺口 | 现象 | 迁入计划 |
|---|---|---|
| G-SSH-1 | `rekey_after` 解析但不触发 re-KEX | P4：实现状态机触发并补 KEX 序列例，或删除字段 |
| G-SSH-2 | 认证/算法/channel/error/IPv6/动态等变体尚未全覆盖；业务字段层内翻译与 allowlist 需逐项审计 | P4：先补 layer Fields/translator/dynamic 设计，再加原子正负例 |
| G-SSH-3 | 当前结果文档/pcap 未证明今日真实流程重跑 | P5：MCP 建任务→真实生成→tshark 校准 pcap 与 NIC |
| G-SSH-4 | dummy DH/key/signature/MAC 不能真实互操作 | 独立协议能力立项；未立项前保持 wire-shaped 边界 |

## 8. 修订与自审

- v1.1（2026-09-30）：按当前 JSON 和实现重写；删除“唯一用例仍 flat”的过期结论，补 D1–D8、矩阵、五件套、性能和缺口迁入计划。
- 自审 2 轮：第一轮核对层链/端口/offset/JSON 对账，第二轮核对 RFC 消息顺序、动态边界和缺口表；末轮干净。

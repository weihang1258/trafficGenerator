# #132 SSH-2 设计契约（as-built）

> 版本 v1.0；日期 2026-09-29；规范：RFC 4251（架构/线类型）、RFC 4252（用户认证）、RFC 4253（传输/BPP/KEX）、RFC 4254（连接层）、RFC 4256（keyboard-interactive）、RFC 8308（EXT_INFO）。
> 实现：`trafficgen/internal/protocol/ssh/`；默认 TCP 端口 22。本文只描述当前生成器实际产生的线格式，不把模板字节描述成可认证的 SSH 实现。

## 1. 范围与实现边界

SSH 是 TCP 上的三层会话协议：版本交换明文行 → SSH Binary Packet Protocol（BPP）→ 传输层/KEX、用户认证层、连接层消息。事件生成器由 TCP 层负责 SYN、ACK、序号、MSS 分段和 FIN；SSH 层逐事件交付版本行或完整 BPP 帧。legacy `Planner.Plan` 自产 TCP 握手/挥手，事件模式不自产，避免双握手。

已实现：SSH-2 版本行、KEXINIT、KEXDH_INIT/REPLY、NEWKEYS、可选 EXT_INFO、SERVICE、用户认证消息、channel/global request 消息和可选 DISCONNECT。未实现真实密码学：DH 公钥、host key、签名、padding、MAC 是占位/伪随机字节；NEWKEYS 后仍使用明文可解析的 BPP 形状加 dummy MAC，不能被真实 SSH 终端验证。`RekeyAfter` 只解析不触发 re-KEX。层内配置翻译没有 `ssh` 专用分支，当前存量 `ssh:{}` 空配置可依靠 nil 默认；非空层字段是否可达列为 G-SSH-1。

## 2. 目标配置与调用路径

目标形状是纯层链，旧顶层字段不得出现：

```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345,"dst_port":22}},{"ssh":{}}]}
```

`registry.go:1614` 注册终结层 `ssh`，依赖 `tcp`，FieldContract 为 `tcp.dst_port=22`；`chain_planner.go:1225` 缺省目的端口 22。`strategy_convert.go:1495` 的 legacy `case "ssh"` 将顶层子映射解析为 `FlowSpec.SSH`；`parseSSHConfig`（约 2438）承接字段。事件模式 `SSHGenerator.Generate` 从 `FlowMeta.SSH` 取配置，向 `EmitMsg` 发送 `MessageEvent{Up, Bytes}`；TCP 生成器包装为线上的 TCP payload。

配置字段：`server_version`, `client_version`, `kex_algorithms`, `host_key_algorithms`, `encryption_algorithms`, `mac_algorithms`, `compression_algorithms`, `kex`, `auth_methods[]`, `ext_info`, `channels[]`, `rekey_after`, `disconnect_on_close`, `scenario`, `command`, `stdout`, `stderr`。空版本双方均空时跳过版本交换；任一非空时按 server→client 顺序补齐双方默认 `SSH-2.0-trafficgen_1.0`。空 auth/channel 分别补 password→success 与 session channel 默认剧本。`scenario` 覆盖手写 auth/channel，合法值为 `exec`, `shell`, `pty-exec`, `publickey`, `auth_fail_retry`, `long_output`。

## 3. BPP 总体线格式（RFC 4253 §6）

每个二进制包按大端排列：

| 偏移 | 字段 | 长度/规则 |
|---:|---|---|
| 0 | `packet_length` | uint32 BE；从 padding_length 字节开始计数，不含本 4B，也不含 MAC；公式 `1 + payload_len + padding_len` |
| 4 | `padding_length` | uint8；至少 4，最多 255 |
| 5 | payload | `message_number(1B) + message fields` |
| 5+P | random padding | P 字节；使 `4+1+payload_len+P` 为 cipher block 整数倍，默认 block=8，AES-CTR=16，AEAD 形状按 block=1 |
| 5+P+payload_len | MAC | NEWKEYS 后 dummy 32B；NEWKEYS 前无 MAC |

padding 算法从 `P=4` 起取第一个满足 `(5 + payload_len + P) mod block_size = 0` 的值。`packet_length` 不计 MAC。实现 `buildBPP` 以 `packet_length || padding_length || payload || padding || MAC` 生成；payload 内 uint32/string 均 BE。变长 `string` 是 `uint32_be length + length bytes`，允许空串；`name-list` 同一线编码，只是内容为逗号分隔名称。版本行不是 BPP：`SSH-2.0-<softwareversion>\r\n`，不得含 CR/LF。

无 VLAN、IPv4 无 option、TCP 无 option 时，BPP 起点为以太帧 offset 54；IPv6 为 offset 74；TCP options 使 payload offset 由实际 TCP data offset 决定。BPP 头第一个字节在该起点，`packet_length` 四字节从该处开始。

## 4. 传输层与 KEX 消息

### 4.1 版本交换

server 先发版本行，client 后发；实现只有在两者配置至少一个非空时发两行，否则跳过。版本字符串长度为 `len("SSH-2.0-")+software+2`，软件字段由配置提供或默认 `trafficgen_1.0`。

### 4.2 SSH_MSG_KEXINIT（20，RFC 4253 §7.1）

payload 偏移：0 message=20；1–16 cookie（16B）；17 起连续十个 `name-list`：kex、server_host_key、encryption_c2s、encryption_s2c、mac_c2s、mac_s2c、compression_c2s、compression_s2c、languages_c2s、languages_s2c；随后 `first_kex_packet_follows` boolean 1B=0；最后 reserved uint32 BE=0。长度公式：`1+16+4*Σ(len(each list)+4)+1+4`（十个 list，空 list 仍含 4B 长度）。client/server 各一帧；默认算法列表见 `encoders.go:28-43`。

### 4.3 DH 与 NEWKEYS

`SSH_MSG_KEXDH_INIT`（30）：offset 0 type，offset 1 `string(e)`，总长 `1+4+|e|`；curve25519 默认 `|e|=32`，P-256/384/521 为 65/97/133，DH group14/16/18 为 256/384/512。仅是代表性 dummy bytes。

`SSH_MSG_KEXDH_REPLY`（31）：offset 0 type，随后 `string(K_S)`, `string(f)`, `string(signature)`，总长 `1+4+|K_S|+4+|f|+4+|sig|`；当前调用分别 294、|e|、256 bytes，均非真实 key/signature。

`SSH_MSG_NEWKEYS`（21）payload 仅 1B message，client/server 各发一帧；实现随后选择 AES-CTR 的 BPP 对齐并追加 32B dummy MAC，但不执行 negotiated cipher/MAC。

`SSH_MSG_EXT_INFO`（7，RFC 8308 §2.2，可选）：offset 0 type，offset 1 uint32 `nr_extensions`，每项 `string(name)+string(value)`；默认产生 `ext-info-c`/`ext-info-s` 空 value。

## 5. 三层消息表

### 5.1 传输层（RFC 4253）

| 编号 | 名称 | 当前编码/触发 |
|---:|---|---|
| 1 | DISCONNECT | `uint32 reason + string description + string language_tag`；可由 auth 或 disconnect_on_close 触发 |
| 2 | IGNORE | `string(data)` |
| 3 | UNIMPLEMENTED | `uint32(receive_sequence)` |
| 4 | DEBUG | `boolean + string(message) + string(language_tag)` |
| 20 | KEXINIT | 双向固定协商列表 |
| 21 | NEWKEYS | 双向各一 |
| 30/31 | KEXDH_INIT/REPLY | dummy DH 交换 |

### 5.2 用户认证层（RFC 4252/4256）

| 编号 | 名称 | 字段顺序 |
|---:|---|---|
| 5/6 | SERVICE_REQUEST/ACCEPT | `string(service_name)`；固定先 `ssh-userauth` |
| 50 | USERAUTH_REQUEST | `string(user)+string(service="ssh-connection")+string(method)`，password 追加 `boolean(change)+string(password)[+string(new)]`；publickey 追加 `boolean(has_sig)+string(algorithm)+string(blob)[+string(signature)]`；keyboard-interactive 追加 `string(submethods)`；hostbased 追加 algorithm/blob/host/user/signature |
| 51 | USERAUTH_FAILURE | `name-list methods + boolean partial_success` |
| 52 | USERAUTH_SUCCESS | 无字段 |
| 53 | USERAUTH_BANNER | `string(message)+string(language_tag)` |
| 60/61 | INFO_REQUEST/RESPONSE | request: name/instruction/language/uint32 prompts/(prompt+echo)；response: uint32 count/strings |

### 5.3 连接层（RFC 4254）

| 编号 | 名称 | 字段顺序 |
|---:|---|---|
| 80/81/82 | GLOBAL_REQUEST/SUCCESS/FAILURE | request=`string(name)+boolean(want_reply)+name-specific`；success 可带 uint32 bound port；failure 无字段 |
| 90 | CHANNEL_OPEN | `string(type)+uint32 sender+uint32 initial_window+uint32 max_packet`，direct/forwarded/x11 再追加规范字段 |
| 91/92 | OPEN_CONFIRMATION/FAILURE | confirmation: recipient/sender/window/max_packet；failure: recipient/reason/string description/string language |
| 93 | WINDOW_ADJUST | recipient + bytes_to_add |
| 94/95 | CHANNEL_DATA/EXTENDED_DATA | recipient +（extended 另有 data_type）+ string(data) |
| 96/97 | EOF/CLOSE | recipient |
| 98 | CHANNEL_REQUEST | recipient + string(request_type)+boolean(want_reply)+类型字段（pty/exec/shell/env/subsystem/signal/exit-status/exit-signal/window-change/x11-req） |
| 99/100 | CHANNEL_SUCCESS/FAILURE | 当前仅编号常量，未由 channel encoder 产生 |

所有多字节消息字段均 uint32 BE；channel `sender_channel` 为 0 时生成器从 0 起自增。`maximum_packet_size=0` 被 Validate 拒绝；`0xffffffff` sender 保留值被拒绝。

## 6. 状态机、事务与业务场景

状态：`TCP_ESTABLISHED → VERSION_EXCHANGED（可跳过） → KEXINIT双方 → KEXDH → NEWKEYS双方 → SERVICE → USERAUTH → CHANNEL → TCP_CLOSE`。同一输入按配置顺序确定性地产生同一事件类型序列（cookie/padding 内容依 math/rand 状态变化）。DISCONNECT 终止 channel 阶段。SSH 层是单 TCP 会话；流关联不适用，无控制流派生数据流；多会话不在 SSHConfig 内建，外层 flow_control 才能重复独立四元组。多事务体现为认证尝试序列与 channel 请求/数据序列。

现网场景：密码认证后的 exec/shell/pty、publickey 探测+签名、失败重试、长 stdout/stderr、端口转发 global request。默认场景是 password success、session open/confirm、`exit\r\n` data、EOF、双方 CLOSE。当前唯一存量 case 是完整 session smoke；scenario 变体已有单元/集成测试但不在 cases JSON。

## 7. 校验、边界与错误契约

`Validate` 校验 IP（若非空）、TCP MSS [536,65535]、版本/算法列表无 CR/LF、auth 用户名/密码/新密码无 NUL、channel 保留 sender/零最大包、disconnect reason 非零、scenario 枚举。合法失败返回 `ssh: ...` 锚词，任务不得产生成功流。BPP 的 padding 上限 255；string 长度为 uint32，当前编码器未单独拒绝超 uint32（Go slice 实际上限）。MSS 分段数为 `ceil(payload_len/MSS)`，SSH 层不重组 TCP。

性能边界：KEXINIT 长度随十个 name-list 线性增长；KEXDH_REPLY 随 dummy key/f/signature 长度增长；长 output 随 channel data 分段增长；每个事件仅持有当前帧，TCP worker 负责实际段化。真实加密、压缩、MAC 校验、服务端状态验证均不承诺。

## 8. 门1 §1–§14 对照表

| § | 本协议满足方式 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 目标顶层仅 `layers`；旧 flat 键去向见 §9.1；存量仅 1 例仍为旧 flat 形，列 G-SSH-2 | §2/§9.1/cases |
| §2 策略/任务 | SSH 配置是单会话剧本；多流由外层 flow_control | §2/§6 |
| §3 五件套 | 单 TCP 会话表、事务序列、无派生流、终结层插入、状态时间线均展开 | §6/§9.3 |
| §4 查规范 | RFC 4251/4252/4253/4254/4256/8308 与代码逐字段对照 | §1/§4/§5 |
| §5 依赖与错误 | `ssh` DependsOn `tcp`；Validate 锚词和传播规则 | registry:1614；§7 |
| §6 性能 | BPP padding/帧长、MSS、dummy key 长度、长 output 边界 | §3/§7 |
| §7 三份文档 | design/testcase/cases 同 ID；现存 1 例逐条登记 | §9/testcase §2 |
| §8 设计先行 | 本文为当前实现逆向定稿；未实现项列缺口 | §1/§10 |
| §9 测试三源 | RFC + 实现 + cases/pcap 字节断言 | testcase §2–§4 |
| §10 评审闭环 | 本轮自审并声明待独立审查 | §11 |
| §11 白话 | SSH 是 TCP 上先明文报版本、再 BPP 协商和会话的加密 shell 对话 | 标题/§1 |
| §12 动态字段 | IP/TCP 四元组走层策略；SSH 业务字段当前无动态 allowlist，列 G-SSH-3 | §9.4 |
| §13 schema 派生 | ssh registry 已注册终结层，当前无专用 Fields | registry:1614 |
| §14 真实流程 | pcap/NIC 共用 packet/frame 断言；本车道未复跑 NIC | testcase §5 |

## 9. 强制展开

### 9.1 旧键去向与目标 spec_json

存量 `cases/ssh.json` 只有 `ssh-basic-session`，顶层 `spec_json` 键为 `src_ip,dst_ip,src_port,dst_port,count,ssh`，不是层链。目标去向：`src_ip,dst_ip → layers[].ip.src/dst`；`src_port,dst_port → layers[].tcp.src_port/dst_port`；`count → flow_control`；`ssh → layers[].ssh`。目标完整例：

```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345,"dst_port":22}},{"ssh":{}}],"flow_control":{"flows":1}}
```

不修改 cases；差距登记 G-SSH-2。

### 9.2 会话五件套

会话 `s1`：TCP 4-tuple `10.0.0.1:12345→20.0.0.1:22`，TCP 握手→版本→KEX→NEWKEYS→service/auth/channel→SSH close→TCP FIN。事务 `t1` 版本、`t2` KEX、`t3` service/auth、`t4` channel、`t5` teardown。每项由前置、触发、成功输出和失败校验组成。关联：无父子流/`driven_by`；所有 SSH 消息共用 s1。插入位置：`[ip,tcp,ssh]` 的终结层。时间线严格按 §6。

### 9.3 动态字段清单

四元组 `ip.src`, `ip.dst`, `tcp.src_port`, `tcp.dst_port` 由框架层动态策略按 flow index 解析；SSH registry 没有业务动态 allowlist，`server_version`, 算法 name-list, KEX, auth/channel 字段均不能声明 fixed/inc/rand/list/pattern 的逐流对象，列 G-SSH-3。事件序号由 `SSHGenerator.Generate` 的 emit 顺序推进；BPP cookie/padding/MAC 依 `math/rand`，不是可复现的 flow-index 算法。`RekeyAfter` 无效，列 G-SSH-4。

## 10. 缺口登记

| 缺口 | 现象与证据 | 归属阶段 |
|---|---|---|
| G-SSH-1 | registry 只有 FieldContract 无 SSH Fields；`chain_planner_translate.go` 无 `case "ssh"`，非空 `layers[].ssh` 配置缺少明确搬运路径 | 实现/P4 |
| G-SSH-2 | 存量唯一 case 仍使用顶层 src/dst/port/count/ssh，目标层链未迁移 | 实现/P4 |
| G-SSH-3 | SSH 业务字段无动态策略 allowlist，五种策略及流序号算法不可达 | 实现/P4 |
| G-SSH-4 | `RekeyAfter` 字段声明“触发 re-KEX”，planner/generator 均不读取 | 实现/P4；应删除或实现 |
| G-SSH-5 | `trafficgen/docs/protocol-pcap-test/ssh.md` 末次提交 2026-08-16，早于 0417be5（2026-09-13），结果文档已过期且不能证明当前复跑 | 代码/P5 重跑 |
| G-SSH-6 | 当前 BPP 为 wire-shaped dummy bytes：不执行真实 cipher、MAC、DH、签名，真实 SSH server 验证不可用 | 明确实现边界；若需互操作另立实现 |

## 11. 修订记录与自审

- v1.0（2026-09-29）：按 SSH 实现、registry、strategy parser、唯一 cases JSON 逆向编写；登记 G-SSH-1…6。
- 自审 1 轮，末轮干净；待独立代码设计逻辑审查与用例覆盖审查。

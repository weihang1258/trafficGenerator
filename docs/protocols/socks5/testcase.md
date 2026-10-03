# SOCKS5 测试用例契约（文档轨）

> 版本：v1.1.0（2026-09-30）。权威机器文件：`trafficgen/test/protocol_pcap/cases/socks5.json`。本轮已将存量两例迁为严格层链形状；真实 suite/pcap 重跑仍属待执行，不把静态断言当 pass。

## T1–T6 原子测试清单

| ID | 测试点 | 输入/输出与断言 | 状态 |
|---|---|---|---|
| T1 | greeting/method/no-auth | `[ip,tcp,socks5]`；`05 01 00`→`05 00`；tshark `socks.version=5`、method=0 | cases `socks5-connect-basic` |
| T2 | CONNECT domain/reply | ATYP=3、长度 15、目标端口 80、成功 BND `0.0.0.0:0`；request 长 22、reply 长 10 | cases `socks5-connect-basic` |
| T3 | RFC1929 password | username `alice`/password `secret`，线字节 `01 05 alice 06 secret`；成功 auth response | `socks5_over_tls` 内层，由 TLS 加密，不能直接断言明文 socks 字段 |
| T4 | TLS substrate | `[ip,tcp,tls,socks5]`、tcp dst 1080；`decode_as=tcp.port==1080,tls`；握手 record type 22 且 length 非零 | cases `socks5_over_tls` |
| T5 | 终止与失败边界 | TCP 握手/挥手；REP 非零不发 data；auth/method failure 关闭 | 代码单测；pcap 负例待补 |
| T6 | 地址/命令/拒绝矩阵 | IPv4/domain/IPv6、CONNECT/BIND/UDP、UDP/FileSource/MSS 错误锚词 | 现有 builder/layer tests；正例与 gate 缺口见 B′ |

## C1–C6 组合与负向覆盖

| ID | 输入 | 预期 |
|---|---|---|
| C1 | no-auth + domain CONNECT | greeting→method→request/reply→termination，四个 frames 与 JSON 完全一致 |
| C2 | password + TLS | 外层 TLS record 可解码；内层 SOCKS 不用明文字段断言 |
| C3 | `REP != 0` + data | reply 仍输出，data 事件数为 0，随后 TCP 终止 |
| C4 | layer terminal 带 UDP relay | 在 generator/validator 报 `udp relay sub-flow not supported on layer chains` |
| C5 | data `FileSource` | 报 `file_source not supported on layer chains`，不得 completed/0 |
| C6 | flat 顶层字段、presence、静态复制、bad MSS | 旧字段拒绝；presence/static-copy 不得假绿；MSS<536 失败 |

## 用例索引与逐例断言

1. `socks5-connect-basic`：`spec_json` 顶层仅 `layers`，层序为 ip→tcp→socks5，tcp dst_port=1080。期望握手、协商、终止；保留 JSON 中 13 个 fields 和 4 个 frame 断言。IPv4 payload offset=54；域名 `www.example.com` 为 15 字节，端口 80 为 `00 50`。实际包号必须以新 suite 落盘 pcap 校准。
2. `socks5_over_tls`：`spec_json` 顶层仅 `layers`，层序为 ip→tcp→tls→socks5，tcp dst_port=1080。期望握手、payload、终止；`decode_as` 固定 `tcp.port==1080,tls`，只断言 packet 1 tcp dstport 和 packet 4 TLS type/length。密码协商在加密 application data 内，不把 `socks.version` 当可见断言。

## 负例、边界与缺口

必须覆盖 greeting method=0xff、RFC1929 status 非零、REP 0x01–0xff、IPv4/域名/IPv6 三 ATYP、域名 0/1/255/256、用户名密码 1/255/256、MSS=536 与 535、UDP FRAG、BIND、动态四元组五策略、static-copy 和 presence。当前 cases 只含两个正例，以上未落入的点均是缺口，不得用两例冒充全覆盖。

现有断言可反查的不可再分点：功能 greeting/method、no-auth、password、CONNECT、TLS、termination；数据 VER/CMD/RSV/ATYP、domain length、BE port、credentials、TLS record；地址流 1080、单 tuple、domain、TLS tuple。未覆盖或待实测：IPv4/IPv6 对称独立例、BIND、REP failure、UDP relay/FRAG、MSS 长数据、动态整格、复杂现网组合。

## 规范要求到用例矩阵

| 规范/设计条目 | 机器用例或代码测试 | 当前状态 |
|---|---|---|
| RFC 1928 §3 greeting/method | `socks5-connect-basic`, `socks5_over_tls`; `layer_gen_test.go` | 正例有；method=0xff 缺口 |
| RFC 1928 §4 CMD/ATYP | `socks5-connect-basic`（CONNECT/domain）；`socks5_test.go` builder tests | IPv4/IPv6/BIND/UDP 正例未入 cases |
| RFC 1928 §6 REP | basic 成功 reply；`socks5_test.go` 回复字节测试 | 非零 REP pcap 缺口 |
| RFC 1928 §7 UDP/FRAG | `layer_gen_test.go` validator negative | 链拒绝已测；legacy FRAG/UDP 不属于链路 |
| RFC 1929 §2–§3 | TLS password 组合；`socks5_test.go` auth tests | 明文 password 与非零 status pcap 缺口 |
| 设计 D3/D4/D6 | 两例 offset/hex；validator negative tests | 缺真实 suite 重钉与缺目标负例 |

命令/响应逐格与地址变体逐格均以缺口表为准；当前两条机器 case 不能冒充 RFC 全覆盖。


规范来源为 RFC 1928 §3–§7、RFC 1929 §2–§3；实现来源为 `socks5.go`、`layer_gen.go`、registry 和 chain planner；机器来源为 cases JSON 与 layer tests。验收必须依次 MCP 建任务、真实引擎生成、tshark 校对 pcap；禁止只跑离线 builder、只断言无错误或只数包。负例也必须经 MCP 传播真实错误锚词。

PCAP 之外的 NIC 验收应在真实接口过滤 TCP 1080，并记录 TLS/校验和 offload 影响。性能测试尚无基准，补齐时必须覆盖基线、目标规模、压力上限、长时间运行、并发交错、资源耗尽/背压，并断言吞吐、延迟、内存、CPU、积压和失败。

## 缺口计划

| 编号 | 计划 |
|---|---|
| G-SOCKS5-1 | 用新层链 cases 跑全量，按真实 pcap 重钉 packet/field/frame |
| G-SOCKS5-2 | 修复 registry 1080 与通用 80 缺省冲突并加失败例 |
| G-SOCKS5-3 | 登记 socks5 presence/static-copy 专属 gate |
| G-SOCKS5-4 | 对域名 >255 明确 reject/truncate 契约并补边界例 |
| G-SOCKS5-5 | 补 ATYP、BIND、REP、MSS、UDP scope 的 A′/B′ 例 |
| G-SOCKS5-6 | 保持 layer UDP relay 拒绝，legacy UDP 另行标注 |
| G-SOCKS5-7 | 补业务字段动态 allowlist 与 fixed/inc/rand/pattern/list 整格 |
| G-SOCKS5-8 | 补商业软件版本抓包并映射至少一条复杂现网场景（当前无商业证据，不宣称已覆盖） |
| G-SOCKS5-9 | 明确省略 `dst_addr`/`dst_port` 的零值目标行为，或改为拒绝；补对应负例，防止空层/缺字段假绿 |

本轮自审两轮：第一轮逐项核对 T1–T6/C1–C6、两例顶层白名单、负例锚词与真实流程；第二轮逐条核对 JSON 顺序、字段数量、offset/hex 约束与缺口未伪覆盖，末轮干净。

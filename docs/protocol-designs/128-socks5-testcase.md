# 128 SOCKS5 用例契约（as-built）

## 1. 测试原则和形状基线

本文件是独立测试点契约，不与设计章节一对一映射。权威顺序为 `trafficgen/test/protocol_pcap/cases/socks5.json`：当前 2 个 ID。cases + 实现优先；两例均为 flat 形状，当前 suite 在 `CheckProtoFlat` 阶段报错而未产生可判定 pcap，故存量断言按“应有线形/今日阻断”分别记录，不伪报 pass。协议 payload 起点：IPv4 offset 54；TLS 例不可把加密 record 当明文 SOCKS 解码。

不可再分覆盖点：

- 功能：greeting、method response、CONNECT request/reply、password auth、TLS 内层信令、TCP 终止。
- 性能：TCP handshake/termination、TLS handshake records、MSS/长数据分段；当前 cases 无吞吐目标。
- 数据：VER/CMD/RSV/ATYP、domain length/no NUL、BE port、RFC1929 credentials、TLS record content type/length。
- 地址与流：1080 destination port、单 TCP tuple、domain target、TLS 同一 tuple；动态 tuple/static-copy 与 IPv6 独立点仍为 gap。
- 业务：no-auth proxy CONNECT、username/password proxy CONNECT、TLS substrate；BIND/UDP relay 不适用，因 layer generator 明确拒绝 UDP relay 且存量无 BIND case。

## 2. 原子用例索引（严格按 JSON 顺序）

| # | ID | 类型 | 场景/依据链 | packet_count / 当前结果 | 断言摘要 |
|---:|---|---|---|---|---|
| 1 | `socks5-connect-basic` | 正 | TCP handshake → RFC1928 no-auth method → CONNECT domain → reply → termination | `min_packets=9`；当前 flat 门 error | `has_handshake=true`、`negotiated=true`、`terminates=true`；13 fields；4 frames |
| 2 | `socks5_over_tls` | 正 | TCP → TLS → RFC1929 password SOCKS5 signaling → TLS records → termination | 无 packet_count；当前 flat 门 error | `has_handshake=true`、`has_payload=true`、`terminates=true`；3 fields（tcp 1 + tls 2）；`decode_as` `tcp.port==1080,tls` |

JSON 顺序、ID、键名和 `decode_as` 以上述文件为唯一权威；`socks` 是 flat parser 的子映射键，不能改写成 `socks5`。

## 3. 正例逐项断言契约

### 3.1 `socks5-connect-basic`

spec_json 原样基线：`src_ip=10.0.0.1`、`dst_ip=20.0.0.1`、`src_port=12345`、`dst_port=1080`、`count=1`、`socks={}`。目标线形应迁为 layers，但本 case 不在文档侧改 JSON。

- expect：`has_handshake=true`、`negotiated=true`、`terminates=true`、`min_packets=9`。
- fields（逐条保持 JSON）：packet 1 `tcp.flags=0x002`、`tcp.dstport=1080`；packet 2 `tcp.flags=0x012`；packet 3 `tcp.flags=0x010`；packet 4 `socks.version=5`、`socks.auth_method=0`；packet 5 `socks.version=5`；packet 6 `socks.version=5`、`socks.command=1`、`socks.port=80`；packet 7 `socks.version=5`、`socks.dst=0.0.0.0`、`socks.port=0`。
- frames：packet 4 offset 54 `05 01 00`；packet 5 offset 54 `05 00`；packet 6 offset 54 `05 01 00 03 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d 00 50`；packet 7 offset 54 `05 00 00 01 00 00 00 00 00 00`。
- 线算术：`www.example.com` 长 15（0x0f），request 长 `7+15=22`，port 80=`00 50`；reply 为 IPv4 BND `0.0.0.0:0`，故长 10。cases notes 所称 10 帧 = 3 握手 + 4 数据 + 3 终止；当前 suite 先被 flat 门阻断，不能把 notes 当今日复跑证据。

### 3.2 `socks5_over_tls`

spec_json layers 为 `tcp` → `tls` → `socks5`，socks5 配置 `auth_method=password`、`username=alice`、`password=secret`、`dst_addr=target.example.com`、`dst_port=8080`；顶层仍有四元组 `10.0.0.1:13000 → 20.0.0.1:1080`，这正触发 flat rejection。

- expect：`has_handshake=true`、`has_payload=true`、`terminates=true`。
- fields：packet 1 `tcp.dstport=1080`；packet 4 `tls.record.content_type=22` 且 `tls.record.length` nonzero。
- decode_as：`tcp.port==1080,tls`。packet 4 是 TLS handshake（content type 22）；后续 SOCKS greeting/auth/request/reply 字节在 application_data 内，不应直接断言 `socks.version`。
- 内层关键字节（实现 probe）：password request 为 `01 05 61 6c 69 63 65 06 73 65 63 72 65 74`；TLS 作为 transformer 包住 6 个 SOCKS records，外层共 7 个握手 records 后进入 application data。此类帧数是实现观测，不改 JSON 中未声明的 `packet_count`。

## 4. 负例契约与非法转换

存量 JSON 没有负例。以下是应有的负向测试点，不能把它们冒充现有 ID：

| 负点 | 输入 | 期望锚词/结果 | 状态 |
|---|---|---|---|
| N-1 presence | `{"layers":[...],"socks5":{}}` | 应拒绝 presence；当前 socks5 无 CheckProtoFlat 分支，probe 可完成 11 帧 | G-SOCKS5-3，禁止建假绿 |
| N-2 UDP relay | layer terminal socks5 + `udp` object | `UDP relay is not supported in layer chains` | layer_gen.go:52/validator:159，已覆盖单测 |
| N-3 FileSource | data message with FileSource | `FileSource data is not supported in layer chains` | layer_gen.go:56/validator:163，已覆盖单测 |
| N-4 static copy | 2 flows + static IP/ports | `layers pin a static four-tuple... static copy` | framework gate，已探针确认 |
| N-5 bad MSS | tcp mss=500 | framework `out of range [536,65535]` | validator 前置门，非 socks5 自身锚词 |
| N-6 flat shape | 任一现有 case 的顶层四元组 | `protocol socks5 no longer accepts flat config field src_ip` | 当前两正例均此状态 |

非法状态转换：未 method response 就 auth/request；auth failure 后继续 request；REP 非零仍发 relay；TLS handshake 未完成就按 SOCKS 明文解析；TCP 关闭后发送新 SOCKS 消息。RFC1928 §3/§6、RFC1929 §2 要求拒绝或关闭。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 1928 §3–§7 + RFC 1929 §2–§3（协议字段、状态、清晰文本警告）→ design §2–§5；实现 `socks5.go`/`layer_gen.go`/registry/chain planner → design §7/§11；cases JSON + layer tests + machine probes → 本文 §2–§4。三源共同约束 2 个存量 ID；cases 顺序不重排。

### 5.2 对账两行

- 不可再分点总数 = **25**（§1 清单逐条计：功能 6 + 性能 3 + 数据 5 + 地址流 6 + 业务 3 = 23，另 BIND 正路径、UDP relay 正路径 2 点不适用）。其中存量 expect 声明可反查 **20**（功能 6 + 性能 2 + 数据 5 + 地址流 4 + 业务 3），缺口/未覆盖 **3**（MSS 长数据分段、动态 tuple/static-copy、IPv6 独立点），不适用 **2**；20+3+2=25 ✓。**粒度声明**：每清单点计 1；G-SOCKS5-1…10 不折进 25。**另**：两例今日执行被 flat 门阻断（G-SOCKS5-1），"可反查"指 expect 声明存在且可机读，非"今日已执行通过"。
- 存量 ID 对账：cases JSON **2** = 本文 §2 **2** = 审计 §8 **2**；当前 suite 可执行成功数 **0/2**（均 flat rejection），不是协议线格式失败。

### 5.3 T-编号与设计回指

`socks5-connect-basic` ≡ T-SOCKS5-T1 ≡ design S-SOCKS5-02/04/05；`socks5_over_tls` ≡ T-SOCKS5-T2 ≡ design S-SOCKS5-03/10。

## 6. P3 固定动作

### 6.1 §3.15 三项

| 项 | 对照 | 结论 |
|---|---|---|
| 同连接多轮操作 | method → optional auth → request/reply → data | 已覆结构；无多 request 例 |
| 非正常结束 | REP failure / RFC1929 failure 应关闭 | A′：无存量负例；REP builder 有覆盖 |
| 长保活 | SOCKS 本身无 heartbeat；TCP/TLS 保活属 substrate | 不适用，理由是 RFC SOCKS 无保活事务 |

### 6.2 A′/B′

A′：IPv4/IPv6/domain 三 ATYP、BIND 正例、REP 非零、domain 255/256 边界、username/password 255 边界、MSS 长 payload、UDP FRAG、multi-flow。B′：presence/static-copy/flat-kill、业务动态 allowlist、coverage gate 与过期结果重生。

### 6.3 3.14 豁免边界

SOCKS5 有 TCP 长连接，因此不豁免会话/终止检查；单 TCP tuple 无派生多流。UDP relay 若使用 legacy planner 是第二 flow，但 layer chain 明确拒绝，不能借 legacy 覆盖链路径。

## 7. 实现后执行建议

先修/迁移两个 cases 为纯 layers：IP 进入 `layers[0].ip`，端口进入 tcp，配置进入 terminal `socks5`，并显式 `dst_port=1080`；再以 suite 全量运行。先检查 task error 是否真实传播，再检查 packet_count、tshark fields、frames 和 `decode_as`。TLS 例强制 TLS decode；不以 encrypted record 上的 SOCKS dissector 字段作断言。

## 8. 存量审计

### 8.1 现状

`cases/socks5.json` 共 2 例，顺序与 §2 一致；1 例 flat no-auth、1 例 layers+TLS 但同时带 flat 四元组。两例 suite 均被 `CheckProtoFlat` 拒绝，故原 JSON 的正例 expect 尚未得到今日执行证据。tracked `trafficgen/docs/protocol-pcap-test/socks5.md` 的历史数字亦不可引用：末次提交 c7c1dda（2026-08-31）早于 0417be5（2026-09-13），且 pcap 子目录不存在。

### 8.2 逐 ID 去向

| ID | 去向 | 原因/动作 |
|---|---|---|
| `socks5-connect-basic` | 改写 | 保留 no-auth CONNECT 语义；迁移 flat 四元组和 `socks` 到 layers，显式钉 1080；迁移后重钉 min_packets/fields/frames |
| `socks5_over_tls` | 改写 | 保留 TLS+password 语义；删除 flat 顶层四元组，补 IP/tcp 到 layers；继续 `decode_as` 强制 TLS；迁移后重跑 20-frame 观测 |

无作废例、无等价覆盖例；当前 0/2 pass 是门阻断，不支持删例结论。

## 9. 附：覆盖反查门建议断言行

供主线程登记 `coverage_gate.py`，本车道不碰该文件。每行应可静态机读：

| # | 建议断言 | 今日状态 |
|---:|---|---|
| 1 | `len(cases['socks5']) == 2` 且 ID 顺序等于 §2 | 已成立 |
| 2 | 每例 `spec_json` 顶层键仅 `{layers}`；无 `src_ip/dst_ip/src_port/dst_port/count/socks` 游离键 | 红：2/2 有 flat 键 |
| 3 | 每例 terminal layer 为 `socks5`，其前置依赖包含 `tcp` | #2 已是 layers；#1 迁移后检查 |
| 4 | no-auth case 包含 request `05 01 00`、method `05 00`、CONNECT domain ATYP `03`、reply `05 00` | JSON frames 已声明；今日未因 flat 门执行 |
| 5 | TLS case `decode_as` 等于 `tcp.port==1080,tls`，且 packet 4 `tls.record.content_type=22` | JSON 已声明；今日未因 flat 门执行 |
| 6 | TLS case 不使用明文 `socks.version` 字段断言 | 已成立 |
| 7 | password request 的 `ULEN=5`、`PLEN=6` 与 alice/secret 字节长度一致 | layer test/probe；cases 仅间接声明 |
| 8 | 成功 reply 后才允许 data；`Rep!=0` 时 data 事件数为 0 | layer_gen_test 已有 Rep=1；cases 未声明 |
| 9 | domain length ≤255；超过 255 的输入应有明确 truncate/reject 断言 | 红：当前只截断，无 case |
| 10 | `dst_port` 显式为 1080，不接受通用默认 80 替代 | 红：chain 缺省冲突 G-2 |
| 11 | tracked 结果产物不得以 c7c1dda 的旧 pass 数字作为今日复跑证据 | 红/待 P5 重生 |
| 12 | UDP/FileSource rejection 锚词必须分别命中 layer generator/validator | 已有单测，建议 gate 静态查锚词 |

## 10. 修订记录

- v1.0（2026-09-29）：按 RFC、实现、layer tests、probes 和 `cases/socks5.json` 建立两例 as-built 契约；明确 flat 门阻断、TLS decode、三 ATYP、端口冲突、UDP/FileSource 拒绝和过期结果产物。
- 自审 3 轮，末轮干净（第 3 轮为脚本机读：ID 顺序、expect 键、13 fields/4 frames、frames hex 逐串、对账计数、门建议行全过）。

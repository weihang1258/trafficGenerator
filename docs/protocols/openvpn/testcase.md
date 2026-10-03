# #137 openvpn（OpenVPN）测试用例契约

> 版本：v2.0.0（2026-09-30，P1–P4 as-built）
> 配套设计：`137-openvpn-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/openvpn.json`

## 1. 原则与形状基线

当前机器契约只有 **1 个正例、0 个负例**。它验证 UDP 1194 的 V2 reset/data 基线；不应被解释为完整 OpenVPN 覆盖。该例已迁移为纯层链：顶层仅 `layers`、`flow_control`，链序为 `ip,udp,openvpn`；业务参数住 `openvpn` 层，地址/端口住 `ip`/`udp` 层。PCAP 与 NIC 必须复用同一 JSON 断言。

## 1.1 测试点总览（T1–T3）

| 来源 | ID 粒度 | 落点 |
|---|---|---|
| 规范原文与 dissector | T1：V2 reset/data 基线 | `openvpn_udp1194_reset_data` |
| 代码分支/validator | T2：非法组合、计数、负载、静态密钥、TLS 组合、MTU/MSS、fragment、keepalive、exit、inner IP | testcase §4 缺口矩阵 |
| 现网常用场景 | T3：基线 + V1/V3、auth-user-pass、keepalive、soft-reset、exit、static-key、inner IP、IPv6、非默认端口 | design §11，用例待补 |

§3.15 显式三项：普通复位/数据交换（已覆）、同连接多轮交易如 rekey/keepalive（待补）、非正常结束如 exit-notify（待补）；其中后两项目前无正例，因此 §3.15 在本协议判待补。

## 1.2 用例与包数校准

包数与随机值关系以真实 pcap 为准；frames/offset 断言禁止按公式手写。当前正例包数基准：默认 `data_packet_count=5`。

## 2. 原子用例索引

| # | ID | 类型 | 场景/依据 | 包数 | 断言 |
|---:|---|---|---|---:|---|
| 1 | `openvpn_udp1194_reset_data` | 正 | OpenVPN V2 UDP 基线；OpenVPN `ssl_pkt.h` opcode 与 Wireshark dissector | ≥12（实测 12） | UDP dstport 1194；opcode 07/08/09；keyid 0；control sessionid 非零且包2等于包1；data peerid 非零且包4等于包3；offset 42 字节 38/48 |

## 3. `openvpn_udp1194_reset_data` 断言

输入为严格层链 `spec_json.layers=[ip,udp,openvpn]` 与 `flow_control.flows=1`（UDP 1194、默认 V2、默认 data count 5）。包序：

1. packet 1：`udp.dstport=1194`，`openvpn.opcode=0x07`，`openvpn.keyid=0`，`openvpn.sessionid` 非零，offset 42 为 `38`（`0x07<<3`）。
2. packet 2：`openvpn.opcode=0x08`，sessionid 与 packet 1 相同。
3. packet 3：`openvpn.opcode=0x09`，peerid 非零，offset 42 为 `48`（`0x09<<3`）。
4. packet 4：peerid 与 packet 3 相同。
5. packet 12：最后一个默认数据报存在；总帧数实测 12 = 2 reset + 10 data。

session ID 和 peer ID 是运行期随机值，因此只断言非零与跨包相等，不硬编码数值。控制 payload 内 TLS 字节为合成结构，不断言真实 TLS 完整性或密码学认证。

## 4. 负例与待补行为面

当前 JSON 没有负例，以下每项应独立新增（不得用一个综合失败例代替）：

| 建议 ID | 输入/行为 | 锚词或可观察结果 |
|---|---|---|
| `openvpn_neg_proto` | proto 非 udp/tcp | `openvpn proto must be` |
| `openvpn_neg_tcp_chain` | layer-chain proto=tcp | `proto=tcp is not supported` |
| `openvpn_neg_version` | version 非 1/2/3 | `version must be` |
| `openvpn_neg_keyid` | key_id=8 | `key_id max is 7` |
| `openvpn_neg_cipher` | 未知 data_cipher | `unsupported data_cipher` |
| `openvpn_neg_auth` | 未知 auth_alg | `unsupported auth_alg` |
| `openvpn_neg_tlscrypt` | tls_crypt_v2 无 tls_crypt | `tls_crypt_v2 requires` |
| `openvpn_neg_v1_tls` | V1 + tls_auth/tls_crypt | `V1 does not support` |
| `openvpn_neg_count` | data_packet_count=1001 | `data_packet_count must be` |
| `openvpn_neg_payload` | data_payload >16384 | `data_payload must be` |
| `openvpn_neg_static` | static key 与 tls_auth 或错误 key 长度 | `mutually exclusive` / `exactly 256` |
| `openvpn_neg_auth_user` | 空/超长/控制字符用户名密码 | `auth_user` / `auth_pass` |
| `openvpn_neg_fragment` | fragment_size=63 或 1501 | `fragment_size` |
| `openvpn_neg_keepalive` | restart ≤ ping | `ping must be less than restart` |
| `openvpn_neg_exit` | exit-notify TCP 或 count>3 | `exit_notify` |
| `openvpn_neg_mtu_mss` | tun_mtu/MSS 冲突 | `tunnel capacity` / `MSS` |
| `openvpn_neg_inner_ip` | 非法 IP、v4/v6 混写、非法 proto | `valid IP` / `same address family` / `supported list` |

负例只保留 `expect_error` + `error_contains`，且必须验证任务终态失败、无成功 PCAP，不能只调用 validator 单元函数。

## 5. 五层覆盖审计

**功能**：存量只覆盖 V2 UDP reset + data；V1/V3、static key、tls-auth、tls-crypt、auth-user-pass、keepalive、soft reset、exit-notify、inner IP、所有错误分支待补。

**性能**：存量只覆盖默认 5 对数据。待补 1/1000/>1000 count、payload 边界、fragment 边界、MSS 分段、多个 inner IP。

**数据**：存量覆盖 opcode 07/08/09、keyid=0、共享 session/peer 关系。待补 keyid 1/7、V1/V3、各 cipher/HMAC、TLS 版本、fragment 字段、内层 checksum/长度。

**地址与流**：存量只覆盖 outer UDP IPv4 默认端口。待补 IPv6、非默认端口、内层 IPv4/IPv6、混合地址族拒绝；TCP layer-chain 是明确拒绝路径，不得伪报为正例。

**业务**：存量只覆盖单 flow 基线。待补静态密钥、认证、保活、重协商、退出通知和真实隧道内层业务；协议无已实现多会话/控制派生子流。

## 6. 存量去向

| ID | 去向 | 原因/动作 |
|---|---|---|
| `openvpn_udp1194_reset_data` | 保留，已迁移 | 保留基线断言；当前为纯层链，包数与随机值关系不变；IPv4/UDP 层字段与双输出说明齐 |

无作废例。由于只有一个 ID，不能从现有集合证明任何其它协议行为。

## 7. 本轮 C1–C6 验证与旧稿残留清理

- C1 严格层链：正例顶层仅 `layers`、`flow_control`，无 `openvpn`、`count`、地址或端口旧键。
- C2 端口/地址：IPv4 地址住 `ip`，UDP 端口住 `udp`，OpenVPN 业务住 `openvpn`。
- C3 流控：`flow_control.flows=1`，不再用旧 `count`。
- C4 失败路径：当前 0 负例，不宣称失败覆盖；§4 为独立矩阵缺口。
- C5 文档一致：原子用例索引、存量去向、反查门与缺口登记同为 1 正 0 负，无过期数量。
- C6 旧稿：design §1 的平面旧形警告不再适用于当前例，但保留为历史教训；本轮不再复制 `137-openvpn-*` 的旧平面示例作为目标。

## 8. 真实流程与断言边界

本轮未运行 MCP 建任务、引擎生成、tshark 校对或 NIC 抓包，因此不得将文档/JSON 收口宣称为套件通过。后续必须按 §14 三步执行，并以落盘 pcap 校准包号、偏移和字段。

## 9. 覆盖反查门建议

供主线程登记 `coverage_gate.py`，本车道不修改：

1. `len(cases['openvpn']) == 1`，ID 顺序与本文 §2 一致。
2. 当前例在迁移后标记为纯层链；`spec_json` 顶层键仅 `layers`、`flow_control`，层序为 `ip,udp,openvpn`。
3. 正例 `min_packets >= 12`，且默认配置精确包数为 12。
4. packet 1/2 opcode 为 `0x07/0x08`，packet 3 opcode 为 `0x09`。
5. packet 1/2 sessionid 相等且非零；packet 3/4 peerid 相等且非零。
6. frame offset 42 的 packet 1/3 分别为 `38`/`48`。
7. 负例新增后每个 `expect` 只有 `expect_error,error_contains`，锚词来自 planner 原文。
8. pcap/NIC 使用同一 ID、同一字段与 frames 断言。

## 10. 缺口登记

- **G-OPENVPN-1**：层链迁移已完成，当前 JSON 为严格 `layers` + `flow_control`；旧稿平面形仅作历史证据。已关闭。
- **G-OPENVPN-2**：1/1 正例、0 负例，未覆盖 17 个 validator 错误面及 V1/V3、加密包装、静态密钥、内层 IP、IPv6；归属 P4 用例扩展。
- **G-OPENVPN-3**：`layer_dyn.go` 无 openvpn allowlist，业务字段动态对象会被拒；归属 P4 动态字段裁定/实现。
- **G-OPENVPN-4**：加密/HMAC/tag 是 filler，不能证明真实互操作；归属明确实现边界，不计当前通过度。
- **G-OPENVPN-5**：legacy TCP path 存在但 layer-chain validator 拒绝 TCP；归属传输层实现阶段。
- **G-OPENVPN-6**：`trafficgen/docs/protocol-pcap-test/openvpn.md` 末次提交 `e7e7d1c`（2026-08-27）早于 `0417be5`，且当前 worktree 无 `docs/protocol-pcap-test/openvpn/` pcap 目录；归属 P5 重跑并重生成产物。

## 12. T1–T6 静态测试闭环

| ID | 测试审计结论 | 证据 |
|---|---|---|
| T1 | JSON 可解析，唯一 ID 与本文 §2 同序；当前总量 1，正/负为 1/0 | `cases/openvpn.json`；本例唯一 ID |
| T2 | 正例从严格 `layers` 入口提交，层序固定 `[ip,udp,openvpn]`，流控独立 | `spec_json.layers` 与 `flow_control.flows=1` |
| T3 | 当前无负例；不把设计中的 validator 缺口伪造成机器覆盖 | §4 独立负例矩阵；`expect_error` 数量为 0 |
| T4 | 地址只在 `ip`，端口只在 `udp`，业务只在 `openvpn`；无顶层旧键 | 唯一正例逐键对账；与设计 §14 D1/D4 一致 |
| T5 | 协议特有断言覆盖 V2 reset/data opcode、key-id、session/peer 关联和线偏移 | packet 1–4 fields；frames offset 42 的 `38`/`48` |
| T6 | 本轮只做静态对账，不宣称套件、PCAP 或 NIC 运行通过 | testcase §8；后续执行复用同一 JSON |

## 13. C1–C6 六项收口

| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | JSON 可解析、ID 唯一且与本文索引一致 | 已静态核对，1/1 |
| C2 | 严格层链、顶层白名单及地址/端口/业务归属 | 唯一正例 `[ip,udp,openvpn]`，顶层仅 `layers`、`flow_control` |
| C3 | V2 reset/data 的 opcode、key-id、session/peer、offset 42 | packet fields 与 frames 断言分别落地 |
| C4 | 失败路径只登记真实代码锚词，不虚造负例 | 0 负例；§4 保留独立待补输入 |
| C5 | ID、summary、断言与 design/代码锚点交叉一致 | `planner.go`、`layer_gen.go`、`registry.go`、`layer_dyn.go` 已回查 |
| C6 | PCAP/NIC 双输出及 suite 结果如实登记 | 本轮未运行，不能写成通过 |

## 14. 修订记录

- v2.0.1（2026-10-01）：补齐 T1–T6/C1–C6 静态审计，保持 1 正例、0 负例、严格层链和未运行边界。自审 2 轮，末轮干净。

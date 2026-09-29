# #137 openvpn（OpenVPN）测试用例契约

> 版本：v1.0.0（2026-09-29，as-built）
> 配套设计：`137-openvpn-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/openvpn.json`

## 1. 原则与形状基线

当前机器契约只有 **1 个正例、0 个负例**。它验证 UDP 1194 的 V2 reset/data 基线；不应被解释为完整 OpenVPN 覆盖。该例仍使用旧平面 `spec_json`（`count` + `openvpn`），不是目标层链形；P4 应迁移为 `layers=[udp,openvpn]`，并保持同一可观察断言。PCAP 与 NIC 必须复用同一 JSON 断言。

## 2. 原子用例索引

| # | ID | 类型 | 场景/依据 | 包数 | 断言 |
|---:|---|---|---|---:|---|
| 1 | `openvpn_udp1194_reset_data` | 正 | OpenVPN V2 UDP 基线；OpenVPN `ssl_pkt.h` opcode 与 Wireshark dissector | ≥12（实测 12） | UDP dstport 1194；opcode 07/08/09；keyid 0；control sessionid 非零且包2等于包1；data peerid 非零且包4等于包3；offset 42 字节 38/48 |

## 3. `openvpn_udp1194_reset_data` 断言

输入为 `spec_json.count=1, openvpn={}`（迁移后为 one flow、UDP 1194、默认 V2、默认 data count 5）。包序：

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
| `openvpn_udp1194_reset_data` | 保留并改写 | 保留基线断言；P4 将 `spec_json` 迁为纯层链，包数与随机值关系不变；补 IPv4/UDP 层字段与双输出说明 |

无作废例。由于只有一个 ID，不能从现有集合证明任何其它协议行为。

## 7. 覆盖反查门建议

供主线程登记 `coverage_gate.py`，本车道不修改：

1. `len(cases['openvpn']) == 1`，ID 顺序与本文 §2 一致。
2. 当前例在迁移前标记 legacy；P4 后 `spec_json` 顶层键仅 `layers`，层序为 `udp,openvpn`（可含 `ip`）。
3. 正例 `min_packets >= 12`，且默认配置精确包数为 12。
4. packet 1/2 opcode 为 `0x07/0x08`，packet 3 opcode 为 `0x09`。
5. packet 1/2 sessionid 相等且非零；packet 3/4 peerid 相等且非零。
6. frame offset 42 的 packet 1/3 分别为 `38`/`48`。
7. 负例新增后每个 `expect` 只有 `expect_error,error_contains`，锚词来自 planner 原文。
8. pcap/NIC 使用同一 ID、同一字段与 frames 断言。

## 8. 缺口登记

- **G-OPENVPN-1**：唯一 case 使用 legacy 平面键，证据为 JSON `spec_json` 含 `count/openvpn`；归属 P4 层链迁移。
- **G-OPENVPN-2**：1/1 正例、0 负例，未覆盖 17 个 validator 错误面及 V1/V3、加密包装、静态密钥、内层 IP、IPv6；归属 P4 用例扩展。
- **G-OPENVPN-3**：`layer_dyn.go` 无 openvpn allowlist，业务字段动态对象会被拒；归属 P4 动态字段裁定/实现。
- **G-OPENVPN-4**：加密/HMAC/tag 是 filler，不能证明真实互操作；归属明确实现边界，不计当前通过度。
- **G-OPENVPN-5**：legacy TCP path 存在但 layer-chain validator 拒绝 TCP；归属传输层实现阶段。
- **G-OPENVPN-6**：`trafficgen/docs/protocol-pcap-test/openvpn.md` 末次提交 `e7e7d1c`（2026-08-27）早于 `0417be5`，且当前 worktree 无 `docs/protocol-pcap-test/openvpn/` pcap 目录；归属 P5 重跑并重生成产物。

## 9. 修订记录

- v1.0.0（2026-09-29）：按实现、registry、strategy conversion、现有 JSON 和过期产物事实撰写；自审 1 轮，末轮干净。

# #136 RDP 测试用例契约

> 版本：v1.3.0（2026-10-01，静态闭环校准）
> 机器契约：`trafficgen/test/protocol_pcap/cases/rdp.json`（9/9 ID 与本文 §2 一致，严格层链形）
> 规范/设计依据：RFC 1006 §4、ISO 8073、T.125、MS-RDPBCGR §2.2.1；配套设计：`docs/protocols/rdp/design.md`
> 白话一句：当前有一条 27 帧的默认 RDP 连接烟雾和八条 validator/layer 负例；后续仍需把每个阶段、边界和失败路径拆成可独立判定的例子。

## 1. 原子性、输出与断言口径

本协议当前 JSON 有 1 个正例、8 个负例。用例断言使用 `min_packets`、`negotiated`、`terminates`、`directional`、`tcp.*` 和原始 `frames`；tshark 3.6 的 TCP/3389 没有可用 RDP dissector，不能伪造 `rdp.*` 字段断言。`decode_as` 的 `tcp.port==3389,echo` 仅用于抑制 LBMSRS 启发式误报，不是协议解析证据。pcap 与 NIC 应共用本契约；当前只保留 IPv4 offset 54。

负例执行期只允许 `expect_error,error_contains`，必须 task error、零成功 PCAP，不得以“未 panic”代替失败断言。

## 2. JSON ID 索引（权威顺序）

| # | ID | 类型 | 场景/依据 | 包数 | 当前断言 |
|---:|---|---|---|---:|---|
| 1 | `rdp_tcp3389_x224_mcs` | 正 | RFC 1006 §4；ISO 8073；T.125；MS-RDPBCGR §2.2.1；默认 standard RDP 建连至 MCS | 至少 27 | `tcp.dstport=3389`；`tcp.len` 19/19/361/8/11；TCP negotiated、directional、terminates；offset 54 的 TPKT/X.224/MCS 原始前缀 |
| 2–9 | `rdp_nondefault_port_neg`, `rdp_invalid_security_neg`, `rdp_tls_chain_neg`, `rdp_client_name_overflow_neg`, `rdp_geometry_low_neg`, `rdp_color_depth_neg`, `rdp_channel_count_neg`, `rdp_channel_name_ascii_neg` | 负 | Planner/layer validator 错误分支 | — | 每例 `expect` 严格为 `expect_error,error_contains`，锚词分别来自 `planner.go:305-370` / `layer_gen.go:278-288` |

JSON 中 9 例均采用严格层链；非负例顶层无 `count`、地址或协议业务字段。8 个负例分别把故障放在 `tcp`/`rdp` 层，`expect` 键集合严格为 `{expect_error,error_contains}`。数量由外层任务/策略 `flow_control` 承载（当前例未显式设置）。

逐帧断言：包 4 `03 00 00 13 0e e0`（CR），包 5 `03 00 00 13 0e d0`（CC），包 6 `03 00 01 69 02 f0 00`（MCS Connect-Initial），包 8 `03 00 00 0a 02 f0 00`，包 9 `03 00 00 08 02 f0 00`，包 10 `03 00 00 0b 02 f0 00`。现有 notes 说明这些字节由 `/tmp/probe-iana/rdp.pcap` 核对，并记录 LBMSRS/echo 解析限制。

## 3. 五层覆盖反查

**功能层**：已覆盖 TCP/X.224 CR/CC、TPKT、MCS Initial 的代表字节；未覆盖 Connect Response 之外的 Erect/Attach/Join、安全 Exchange、Client Info、License、Capability、active data、Shutdown、Negotiation Failure、Channel-Join failure。

**性能层**：已有 27 帧基线和 361B MCS payload；未覆盖 MSS 分段、最小/最大 PDU、ClientName/desktop/channel/RSA 长度边界、31 channel。

**数据层**：已有默认空 RDP 配置；未覆盖 Cookie、requested-protocol 位图、standard/tls/nla/nla_ex、UTF-16 凭据、base64、虚拟通道 payload、非法编码和截断/长度不匹配。

**地址与流层**：已有 IPv4 单流、TCP 3389；未覆盖 IPv6、默认端口补齐、非默认端口拒绝、混合地址族、RST。RDP 没有协议级派生流，流关联不适用。

**业务层**：未覆盖 full_session、cliprdr、rdpdr、rdpsnd、drdynvc、键鼠输入、位图输出、多事务和异常结束。多会话不适用；框架多 flow 另计。

## 4. 覆盖最小清单与建议补例

以下是从 MS-RDPBCGR/相关扩展和代码分支反推的原子测试点，不宣称已在 JSON 中存在：

| 建议 ID | 独立测试点 | 期望锚点/可观察结果 |
|---|---|---|
| `rdp_default_port` | 删除 dst_port，验证 3389 补齐 | `tcp.dstport=3389` |
| `rdp_nondefault_port_neg` | dst_port=3390 | `DstPort must be 3389` |
| `rdp_ipv6` | IPv6 TCP 承载 | 同一 TPKT 前缀，IPv6 offset |
| `rdp_cookie` | CR Cookie | Cookie 原始字节出现在 CR |
| `rdp_protocol_standard` | standard/0x1 | Negotiation protocols LE `01 00 00 00` |
| `rdp_invalid_security_neg` | 未知 security_layer | `SecurityLayer` |
| `rdp_tls_chain_neg` | tls/nla 链 | `not supported on the layer chain` |
| `rdp_client_name_overflow_neg` | >16 UTF-16LE bytes | `clientName must be <= 16 bytes` |
| `rdp_geometry_min` / `rdp_geometry_adjacent_neg` | width/height 200 与 199 | `desktopWidth/Height` |
| `rdp_channel_max` / `rdp_channel_overflow_neg` | 31 与 32 channels | `channelCount` |
| `rdp_channel_name_ascii_neg` | >7 或非 ASCII | `too long` / `7-bit ASCII` |
| `rdp_skip_join` | 跳过 channel join | Join 帧数减少且后续仍有 security |
| `rdp_skip_security` / `rdp_skip_license` / `rdp_skip_capability` | 阶段开关 | 对应帧消失，后续顺序稳定 |
| `rdp_cliprdr` | clipboard format list | MCS channel id 1004、CLIPRDR msgType |
| `rdp_rdpdr` | device list announce | RDPDR component/packetId |
| `rdp_rdpsnd` | quality/wave | RDPSND msgType |
| `rdp_drdynvc` | dynamic channel create | DRDYNVC command/channel |
| `rdp_input` | keyboard/mouse FastPath | FastPath action/length |
| `rdp_bitmap` | FastPath bitmap output | output action/update code |
| `rdp_channel_join_failure` | channel result=4 | confirm result 4, later phases continue |
| `rdp_payload_b64` | base64 event payload | decoded bytes, not base64 text |
| `rdp_mss_fragment` | payload > MSS | multiple TCP segments, aggregate bytes preserved |
| `rdp_rst_neg` | abnormal termination | `tcp.flags.reset==1` |

这些属于 G-RDP-5/G-RDP-6 待实现测试覆盖，不得加入“已通过”统计。

## 5. 存量审计

| 存量 ID | 去向 | 原因/动作 |
|---|---|---|
| `rdp_tcp3389_x224_mcs` | 保留并迁移形状 | 代表性原始字节和 TCP 终止断言有价值；P4 将 `spec_json` 固定为 `{layers:[tcp,rdp]}`；补充 MCS Response/Attach/Join/Shutdown 帧位断言仍属后续缺口 |

无作废例。当前保留 1 个正例并新增 8 个原子负例；27 帧综合烟雾仍不能作为所有 RDP 行为的覆盖证明。

## 6. 缺口登记

- **G-RDP-1 已关闭（P4）**：cases 已迁移为严格层链；机器证据为 `spec_json.layers=[tcp(dst_port=3389),rdp]`，顶层旧键计数为 0。
- **G-RDP-2 已补机器形状（静态闭环）**：已加入 8 个 `expect` 严格双键负例，锚词来自 `planner.go:305-370` 与 `layer_gen.go:278-288`；task error/零成功 PCAP 仍待真实执行确认。
- **G-RDP-3**：TCP/3389 无 tshark RDP dissector，`decode_as echo` 只能清除 LBMSRS 启发式误报；证据：cases notes；归属断言策略/工具确认。
- **G-RDP-4**：层链 TLS/NLA/NLA-EX 显式拒绝，legacy 的 TLS 占位不适用于链上；证据：`layer_gen.go:282-288`；归属实现边界，不计当前覆盖。
- **G-RDP-5**：RDP 业务字段没有动态 allowlist；归属动态字段立项。
- **G-RDP-6**：只有 IPv4 单流和小规模 baseline，未验证 IPv6、NIC、MSS、长度/值域边界、RST；归属后续扩量与真实流程。
- **G-RDP-7**：tracked 结果产物未在本车道重跑，不能作为今日 pcap 证据；归属 P5 重跑后重生成。

## 7. 覆盖反查门建议断言行

1. `len(cases['rdp']) == 9`，ID 顺序等于 `[rdp_tcp3389_x224_mcs, rdp_nondefault_port_neg, rdp_invalid_security_neg, rdp_tls_chain_neg, rdp_client_name_overflow_neg, rdp_geometry_low_neg, rdp_color_depth_neg, rdp_channel_count_neg, rdp_channel_name_ascii_neg]`；所有 `spec_json` 顶层仅 `{layers}`。
2. 正例 `expect` 保留 `min_packets >= 27`、`negotiated=true`、`directional=true`、`terminates=true`。
3. 6 条 `frames` 断言的 packet/offset/hex 与本文 §2 一致；offset=54 仅适用于当前 IPv4 形。
4. `rdp` registry 依赖只含 `tcp`，默认目的端口为 3389。
5. 非负例顶层旧键计数迁移后为 0；负例 expect 键严格为 `{expect_error,error_contains}`。
6. 建成负例后，锚词必须来自 `Planner.Validate` / layer validator 文案，且失败任务不产生成功 PCAP。
7. 迁移后 pcap 与 NIC 使用同一 ID/断言集合；过期 `rdp.md` 不得作为今日复跑证据。

## 8. D/T/C 闭环与执行边界

### D（设计）

| D1 | 层链唯一真相：`spec_json` 顶层仅 `layers`；地址/端口/数量分别归 IP/TCP/任务 `flow_control`。 |
|---|---|
| D2 | RDP 依赖 TCP，链上强制 TCP handshake/termination；默认目的端口 3389。 |
| D3 | 一条 TCP 会话承载 X.224、MCS、安全、能力、活动数据和关闭，无派生控制/媒体流。 |
| D4 | 标准安全层是当前链上实现边界；TLS/NLA/NLA-EX 由 validator 拒绝，不计已覆盖。 |

### T（测试）

| T1 | 正例必须同时断言 TCP 状态、数量下界和方向；当前例为 `min_packets=27`、`negotiated/terminates/directional=true`。 |
|---|---|
| T2 | 关键字段用 `tcp.dstport`/`tcp.len` 断言；关键协议字节用 offset+hex 断言，当前各 6 条。 |
| T3 | 当前正例覆盖 CR/CC、MCS Connect-Initial 和代表性 MCS PDU；未把 notes 当作可执行断言。 |
| T4 | 负例若加入，只能有 `expect_error`、`error_contains` 两键，并须验证 task error 与零成功 PCAP。 |
| T5 | 动态与边界清单逐项登记；未进入 JSON 的项目不得计入通过数。 |
| T6 | 本车道未执行 MCP/PCAP/NIC 重跑；历史 `/tmp/probe-iana/rdp.pcap` 仅作字节来源，不能作今日执行证据。 |

### C（覆盖）

| 覆盖面 | 当前机器证据 | 未覆盖边界 |
|---|---|---|
| 功能 | 1 个正例、8 个 validator/layer 负例、27 帧下界、6 fields、6 frames | MCS Response/Attach/Join、安全 Exchange、Client Info、License、Capability、active data、Negotiation/Join failure 独立正例 |
| 数据/动态 | 空 RDP 配置；TCP 四元组由框架策略处理 | cookie、协议位图、UTF-16、base64、业务字段 fixed/inc/rand/list/pattern allowlist |
| 性能/边界 | MCS 361B payload、IPv4 offset 54 | MSS 分段、RSA 64/128/256/512B、宽高 200/32768 及相邻值、31/32 channel |
| 地址/终止 | IPv4、TCP/3389、双向、正常 FIN；非默认端口负例已登记 | IPv6、RST、NIC 实抓；负例 task error 传播仍待运行 |

以上 C 表只描述已存在的机器断言和明确缺口；不能由设计字段表推导“已支持”。

## 9. 修订记录

- v1.3.0（2026-10-01）：静态校准为 1 正例 + 8 个严格双键负例；补齐真实 planner/layer validator 锚词与负例去向，未运行 suite/PCAP/NIC。
- v1.2.0（2026-10-01）：补齐 D/T/C 闭环、动态/边界覆盖矩阵及 MCP/PCAP/NIC 未运行边界。
- v1.1.0（2026-09-30）：P4 将唯一存量 case 的 `spec_json` 迁移为严格层链并补写 `tcp.dst_port=3389`；关闭 G-RDP-1，其他覆盖缺口保持待实现边界。自审 2 轮，末轮干净；待独立用例覆盖审查。

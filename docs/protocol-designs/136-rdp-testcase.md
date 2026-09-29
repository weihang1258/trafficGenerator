# #136 RDP 测试用例契约

> 版本：v1.0.0（2026-09-29，P-PIPE 文档轨 as-built）
> 机器契约：`trafficgen/test/protocol_pcap/cases/rdp.json`（1/1 ID 与本文 §2 一致，当前仍为旧平面形）
> 配套设计：`docs/protocol-designs/136-rdp-design.md`
> 白话一句：当前只有一条 27 帧的默认 RDP 连接烟雾，后续必须把每个阶段、边界和失败路径拆成可独立判定的例子。

## 1. 原子性、输出与断言口径

本协议当前 JSON 只有 1 个正例、无负例。用例断言使用 `min_packets`、`negotiated`、`terminates`、`directional`、`tcp.*` 和原始 `frames`；tshark 3.6 的 TCP/3389 没有可用 RDP dissector，不能伪造 `rdp.*` 字段断言。`decode_as` 的 `tcp.port==3389,echo` 仅用于抑制 LBMSRS 启发式误报，不是协议解析证据。pcap 与 NIC 应共用本契约；当前只保留 IPv4 offset 54。

负例执行期只允许 `expect_error,error_contains`，必须 task error、零成功 PCAP，不得以“未 panic”代替失败断言。

## 2. JSON ID 索引（权威顺序）

| # | ID | 类型 | 场景/依据 | 包数 | 当前断言 |
|---:|---|---|---|---:|---|
| 1 | `rdp_tcp3389_x224_mcs` | 正 | RFC 1006 §4；ISO 8073；T.125；MS-RDPBCGR §2.2.1；默认 standard RDP 建连至 MCS | 至少 27 | `tcp.dstport=3389`；`tcp.len` 19/19/361/8/11；TCP negotiated、directional、terminates；offset 54 的 TPKT/X.224/MCS 原始前缀 |

JSON 中该例为 `spec_json: {count:1, rdp:{}}`，这与目标层链契约不一致，登记 G-RDP-1；不可将其现状描述为纯层链通过。

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

这些属于 G-RDP-2/G-RDP-5/G-RDP-6 待实现测试覆盖，不得加入“已通过”统计。

## 5. 存量审计

| 存量 ID | 去向 | 原因/动作 |
|---|---|---|
| `rdp_tcp3389_x224_mcs` | 保留但改写形状 | 代表性原始字节和 TCP 终止断言有价值；P4 将 `spec_json` 从平面 `{count,rdp}` 改为 `{layers:[tcp,rdp]}`，并重新生成 pcap；补充 MCS Response/Attach/Join/Shutdown 帧位断言 |

无作废例。当前只有 1 个 ID，不能把 27 帧综合冒烟当作所有 RDP 行为的覆盖证明。

## 6. 缺口登记

- **G-RDP-1**：cases 顶层仍有 `count` 与 `rdp` 子映射，未满足层链唯一真相；证据：`rdp.json:7-10`；归属 P4 层形迁移。
- **G-RDP-2**：无任何 `expect_error` 例，validator/planner 的错误分支和 task error 传播没有机器证据；证据：cases 仅 1 正例，`planner.go:305-382` 多分支；归属 P4 原子负例。
- **G-RDP-3**：TCP/3389 无 tshark RDP dissector，`decode_as echo` 只能清除 LBMSRS 启发式误报；证据：cases notes；归属 P4 断言策略/工具确认。
- **G-RDP-4**：层链 TLS/NLA/NLA-EX 显式拒绝，legacy 的 TLS 占位不适用于链上；证据：`layer_gen.go:282-288`；归属实现边界，不计当前覆盖。
- **G-RDP-5**：RDP 业务字段没有动态 allowlist，scenario/data/channel 字段无法声明 fixed/inc/rand/list/pattern；证据：registry 仅 `tcp.dst_port`，`layer_dyn.go` 无 rdp 行；归属 P4 动态字段。
- **G-RDP-6**：只有 IPv4 单流和小规模 baseline，未验证 IPv6、NIC、MSS、长度/值域边界、RST；证据：现有唯一 ID；归属 P5 MCP/NIC 与扩量。
- **G-RDP-7**：`trafficgen/docs/protocol-pcap-test/rdp.md` 是 tracked 结果产物，末次提交 `e7e7d1c`（2026-08-27）早于 `0417be5`（2026-09-13），本车道未复跑且无今日 pcap；归属代码阶段 P5 重跑后重生成。

## 7. 覆盖反查门建议断言行

1. `len(cases['rdp']) == 1`，ID 顺序等于 `[rdp_tcp3389_x224_mcs]`；迁移后 `spec_json` 顶层仅 `{layers}`。
2. 正例 `expect` 保留 `min_packets >= 27`、`negotiated=true`、`directional=true`、`terminates=true`。
3. 6 条 `frames` 断言的 packet/offset/hex 与本文 §2 一致；offset=54 仅适用于当前 IPv4 形。
4. `rdp` registry 依赖只含 `tcp`，默认目的端口为 3389。
5. 非负例顶层旧键计数迁移后为 0；负例 expect 键严格为 `{expect_error,error_contains}`。
6. 建成负例后，锚词必须来自 `Planner.Validate` / layer validator 文案，且失败任务不产生成功 PCAP。
7. 迁移后 pcap 与 NIC 使用同一 ID/断言集合；过期 `rdp.md` 不得作为今日复跑证据。

## 8. 修订记录

- v1.0.0（2026-09-29）：按 `rdp.json`、RDP planner/layer generator、types、registry、strategy_convert 编写；登记 1 个存量例的保留去向、层形缺口、五层覆盖缺口、7 条缺口和 7 条覆盖门建议。自审 1 轮，末轮干净；待独立用例覆盖审查。

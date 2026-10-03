# Gnutella 测试用例契约

> 版本：v2.1.0（T1–T6 修订）；日期：2026-10-01；机器契约：`trafficgen/test/protocol_pcap/cases/gnutella.json`（已改为顶层仅 `layers`；translator 接线完成后须重新提交校准，缺口见设计 GNT-D1）。

## 1. 对账和测试原则

JSON 共 **20 例：14 正、6 负**，ID 顺序与本文 §2 一致。每个 `spec_json` 目标形状是可直接提交的策略配置：顶层仅 `layers`（本协议没有本批 `flow_control`）；地址在 `ip`，端口在 `tcp`，事件在 `gnutella`。**cases 的层链形状已迁移，但 translator 尚无 `case "gnutella"`（GNT-D1），业务配置尚不能经严格层链真实执行；待补转换接线后按真实流程校准。** 正例断言输出字段/帧，不以“不报错”代替；负例 `expect` 严格只有 `expect_error` 与 `error_contains`。

三源回指：规范为 Gnutella 0.6 handshake/message header/payload wire profile；设计为 `docs/protocols/gnutella/design.md §4–§8`；现网行为以 LimeWire/gtk-gnutella 风格公开 wire 行为为待抓包确认项，已落入 S1–S14 的可观察形状。代码分支为 `internal/protocol/gnutella/layer_gen.go:305-458`、`builder.go`。

## 2. 原子测试点清单与存量审计

| # | ID | 类型 | 规范/设计点→代码分支 | JSON 去向 |
|---:|---|---|---|---|
| 1 | `gnutella_handshake_ipv4` | 正 | CONNECT/200、能力头→握手状态机 | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 2 | `gnutella_ping_pong` | 正 | PING/PONG GUID→ping map | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 3 | `gnutella_query_queryhit` | 正 | QUERY/QUERY_HIT QueryID→query map | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 4 | `gnutella_push` | 正 | ServentID/FileIndex→queryHits | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 5 | `gnutella_vendor_message` | 正 | Vendor 固定头/长度→builder | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 6 | `gnutella_forward_ttl_hops` | 正 | TTL−1/Hops+1→转发分支 | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 7 | `gnutella_multi_queryhit` | 正 | 多结果/同 QueryID→results 分支 | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 8 | `gnutella_multi_stream` | 正 | 两四元组状态隔离→connection loop | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 9 | `gnutella_multi_connection` | 正 | 两连接生命周期→connection loop | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 10 | `gnutella_ipv6` | 正 | IPv6 outer/offset 74→profile | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 11 | `gnutella_ipv4_ipv6_same_payload` | 正 | 双栈独立 fixture→地址族分支 | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 12 | `gnutella_binary_vendor_payload` | 正 | binary payload→builder 原字节 | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 13 | `gnutella_mss_message_reassembly` | 正 | 23B header+PayloadLength 跨 MSS→TCP 分段 | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 14 | `gnutella_frame_boundary` | 正 | 零长、TTL/Hops、uint32 边界→builder/validator | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 15 | `gnutella_neg_handshake` | 负 | 首行/CRLF fault→handshake 锚词 | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 16 | `gnutella_neg_message_header` | 负 | descriptor/header fault→descriptor 锚词 | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 17 | `gnutella_neg_ttl_hops` | 负 | TTL+Hops 回绕→ttl 锚词 | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 18 | `gnutella_neg_query_correlation` | 负 | 未发送 QueryHit→query 锚词 | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 19 | `gnutella_neg_payload_encoding` | 负 | 地址宽度→address 锚词 | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |
| 20 | `gnutella_neg_transport_profile` | 负 | 目的端口→port 锚词 | JSON 已落为严格层链形状；translator 接线后待真实执行（GNT-D1） |

存量 JSON 20 条逐条审计：14 条正例与 6 条负例全部保留原 ID、summary、expect 和业务事件；顶层地址/端口已迁入 `ip`/`tcp` 层，业务配置已归入 `gnutella` 层。因 translator 没有 `case "gnutella"`，严格层链尚不能真实执行，登记为 **GNT-D1 待接线**；接线后须重新校准包数与帧断言。无作废项、无等价替代项。registry 已注册，但“已注册”不等于层链入口已接通。

## 3. 业务场景和强度

数据场景：S2/S6/S15 覆盖空 payload、TTL 0/255、Hops 0/255；S3 覆盖 NUL criteria；S5/S13 覆盖文本与二进制 Vendor；S7/S15 覆盖结果数量和 uint32 边界；N2/N5 覆盖 descriptor/地址非法。业务场景：S1 握手，S2 PING→PONG，S3 QUERY→HIT，S4 HIT→PUSH，S6 转发，S7 多 HIT，S9/S10 多连接。现网场景：S10 多连接节点发现、S11/S12 双栈、S14 长消息；商业行为→用例映射见设计 §4.4。

正交矩阵：地址族×连接数由 S1/S9/S10/S11/S12 覆盖；消息类型×关联由 S2–S7 覆盖；边界×错误由 S15/N1–N5 覆盖；MSS×业务由 S14。动态整格：本协议当前业务字段只接受显式 fixed bytes，四元组按 connection 显式值；`flows>1` 与 inc/rand/list/pattern 尚未开放，不能伪称已覆盖，列为设计 §7 后续 schema 立项。

§3.15 三项：同连接多轮操作=S15（PING、QUERY、HIT、PUSH）；非正常结束=N1/N2/N3/N6 错误传播；长保活=当前 Gnutella 生成器无自动 keepalive，立项由后续 `time`/保活事件 schema 表达，不能用短连接例冒充。

## 4. 正例断言契约

每条正例必须有 `packet_count` 或 `min_packets`、至少一个可观察字段/稳定 frame；JSON 中 S1–S7、S9–S15 当前确有这些断言；但因 translator 尚未接通，不能把它们报告为严格层链已运行。GNT-D1 完成后需重新提交全部 14 条正例并以真实 pcap 重钉包数/帧。应用 payload offset：IPv4 为 54，IPv6 为 74；消息头为 `MessageID(16)|Descriptor|TTL|Hops|PayloadLength LE(4)`。S14 以 TCP `len=1460/1460/139` 验证跨段，不能把 TCP 段边界当消息边界。

## 5. 负例契约

| ID | 输入 | 锚词 |
|---|---|---|
| N1 `gnutella_neg_handshake` | `wire_fault=bad_handshake_line` | `handshake` |
| N2 `gnutella_neg_message_header` | `wire_fault=bad_descriptor` | `descriptor` |
| N3 `gnutella_neg_ttl_hops` | TTL 200 + Hops 100 | `ttl` |
| N4 `gnutella_neg_query_correlation` | QUERY_HIT 引用未发送 Query | `query` |
| N5 `gnutella_neg_payload_encoding` | v4 profile 的 16B PONG 地址 | `address` |
| N6 `gnutella_neg_transport_profile` | dst_port 6347 | `port` |

错误必须从 validator/planner 传播为 task error，不产生成功 PCAP、completed/0 packet 或成功断言。当前 N1–N6 的锚词与旧直连 validator 文案一致；GNT-D1 层链转换完成后必须逐例复核提交入口仍传播相同锚词，不能仅凭旧 JSON 断言通过。代码真实文案锚词见 `layer_gen.go:450-470`。

## 6. 机器对账

以 JSON 解析为准：20 条 ID、14 正例（有 `packet_count`）、6 负例（仅两项 expect 键）。本文与 JSON 的 ID 集合和顺序一致；不存在 `*-spec-mapping.md`，因此无额外 mapping 文件可对账。正式门2仍需全量 suite、二进制同代和覆盖反查；本次只做文档与 cases 改造，不宣称执行结果。

## 8. T1–T6 / C1–C6 对账状态

| 条目 | 结论 | 证据或缺口 |
|---|---|---|
| T1 三源依据 | 已有 | §1/设计 §4；规范、商业行为、开源实现分别回指 |
| T2 测试点清单 | 已有 | §2 的 20 个不可再分 ID；JSON 同序 |
| T3 三类场景 | 已有 | §3 数据、业务、现网场景及正交矩阵 |
| T4 §3.15 | 已有 | §3 同连接多轮、异常结束、长保活逐项登记；长保活为 GNT-T4 缺口 |
| T5 存量审计 | 已有 | §2 全 20 条逐条保留；旧业务字段已迁入层 |
| T6 负例契约 | 已有 | §5 N1–N6 仅 `expect_error`/`error_contains`，锚词逐项对账 |
| C1 顶层白名单 | 已完成形状迁移 | 20/20 `spec_json` 顶层仅 `layers` |
| C2 地址/端口归层 | 已完成形状迁移 | `ip`/`tcp` 层均含承载字段；gnutella 业务在终结层 |
| C3 正例断言 | 待真实校准 | 14 例保留历史 pcap 断言；GNT-C3：translator 接线后重跑 |
| C4 负例纯净 | 已有 | 6 例仅两项错误断言 |
| C5 ID/数量对账 | 已有 | 20 ID，14 正 + 6 负，顺序一致 |
| C6 真实流程 | 未执行 | 本任务不启动 suite/服务；GNT-C6 归 P5 |

## 9. 修订记录

- v2.1.0（2026-10-01）：补齐 T1–T6/C1–C6；cases 完成严格层链形状迁移，记录 GNT-D1/GNT-C3/GNT-C6 待实现或待验证边界。
- v2.0.0（2026-09-30）：补齐三源回指、测试点清单、三类场景、正交矩阵、§3.15 三项、逐条存量审计和负例真错误契约；对账 20 例并登记 GNT-D1 层链迁移缺口。

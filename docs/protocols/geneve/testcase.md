# GENEVE 测试用例契约（文档轨）

> 版本：v1.2.0（2026-10-01）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/geneve.json`  
> 依据：RFC 8926 §§3–5、RFC 768、RFC 791、RFC 8200。当前 20 例是严格层链目标形状；因 G-GENEVE-1/2 未闭环，不宣称 suite 已通过。

## T1 形状、来源和执行边界

每条 `spec_json` 都是目标 MCP strategy config：顶层只保留 `layers`/框架字段；outer 地址住 `layers.ip`，端口住 `layers.udp`，业务住 `layers.geneve`，inner 地址住 `geneve.inner`。20/20 已清除旧顶层地址、端口和 count。负例的 `wire_fault` 住 GENEVE 层。

规范要求→业务场景→代码现状→缺口：RFC 8926 base/options/VNI/flags→14 个正例逐项表达→`layer_gen.go:216-401` 可生成/校验→严格层翻译尚缺；RFC 768/8200 UDP carrier/checksum→四种地址族与 checksum 例→UDP/IP 层已有→端到端待跑；非法字段→6 个负例→wire-fault validator 已有→task error 传播待实证。

三源状态：RFC 是字段/线格式唯一规范源；本仓库生成器和测试是实现源；商业设备/现网抓包尚未取得，不能宣称现网覆盖（G-GENEVE-5）。

## T2 原子清单

| # | ID | 类型 | datagram | 覆盖点 |
|---:|---|---|---:|---|
| 1 | `geneve_ipv4_outer_ipv4_inner` | 正 | 1 | outer/inner IPv4、TEB、VNI |
| 2 | `geneve_ipv4_outer_ipv6_inner` | 正 | 1 | outer IPv4/inner IPv6 |
| 3 | `geneve_ipv6_outer_ipv4_inner` | 正 | 1 | outer IPv6 checksum/inner IPv4 |
| 4 | `geneve_ipv6_outer_ipv6_inner` | 正 | 1 | 双 IPv6 地址隔离 |
| 5 | `geneve_vni_boundary` | 正 | 2 | 0 与 0xffffff |
| 6 | `geneve_version_flags` | 正 | 3 | version 0、OAM、Critical |
| 7 | `geneve_options_single` | 正 | 1 | class/type/length/data |
| 8 | `geneve_options_multiple` | 正 | 3 | 空/单/多 option 顺序 |
| 9 | `geneve_multi_vni` | 正 | 4 | 多 VNI/inner 成对 |
| 10 | `geneve_multi_flow` | 正 | 6 | 3 flow、上下行、端口/identity |
| 11 | `geneve_inner_vlan_ethernet` | 正 | 1 | inner 802.1Q |
| 12 | `geneve_empty_inner_payload` | 正 | 1 | 完整 Ethernet/IP 头 |
| 13 | `geneve_mss_not_applicable` | 正 | 1 | UDP 单报文、无 TCP/MSS |
| 14 | `geneve_pcap_nic_consistency` | 正 | 2 | PCAP/NIC 方向对照 |
| 15 | `geneve_neg_header_truncated` | 负 | 0 | header 锚词 |
| 16 | `geneve_neg_reserved_version_flags` | 负 | 0 | version 锚词 |
| 17 | `geneve_neg_option_length` | 负 | 0 | option 锚词 |
| 18 | `geneve_neg_vni_protocol` | 负 | 0 | vni 锚词 |
| 19 | `geneve_neg_udp_carrier_inner` | 负 | 0 | port 锚词 |
| 20 | `geneve_neg_checksum` | 负 | 0 | checksum 锚词 |

## T3 正例断言

正例验收必须断言 packet count、UDP/6081、base header、VNI/TEB、inner identity；按场景再断言 outer/inner family、options、VLAN、flags、checksum。无 options 时 base/inner offset 为 IPv4 42/50、IPv6 62/70；option 每 4 bytes 后移 inner offset，base 永远 8 bytes。

- `geneve_vni_boundary` 必须逐字节看到 `00 00 65 58 00 00 00 00` 与 `00 00 65 58 ff ff ff 00`。
- `geneve_options_single/multiple` 必须校验 Opt Len=总 option bytes/4、option 顺序和 inner 偏移。
- `geneve_multi_flow` 只做 distinct/成对 identity 断言，不假设跨 flow 到达顺序；当前不是动态字段能力证明。
- `geneve_empty_inner_payload` 仍须有 MAC/EtherType/IP 头并校验 UDP length。
- `geneve_pcap_nic_consistency` 的 NIC 复验由外部授权编排执行，过滤 `udp port 6081`，记录 offload 边界。

## T4 负例、错误传播和未覆盖

| ID | 故障 | 当前锚词 | 代码证据 |
|---|---|---|---|
| header_truncated | base header <8 | `header` | `layer_gen.go:371-373` |
| reserved_version_flags | version/保留位非法 | `version` | `layer_gen.go:374-375` |
| option_length | 对齐/Opt Len/长度错误 | `option` | `layer_gen.go:376`、`328-350` |
| vni_protocol | VNI 越界或 protocol 不匹配 | `vni` | `layer_gen.go:377-379`、`320-357` |
| udp_carrier_inner | 非 UDP/6081 或 inner 截断 | `port` | `layer_gen.go:380-382`、`394-401` |
| checksum | checksum 故障 | `checksum` | `layer_gen.go:383-385` |

负例必须经真实 MCP→任务→引擎流程拒绝，禁止未知层拒绝、completed/0 packet、成功 PCAP 或仅 outer UDP 假成功。当前所有 suite、PCAP、NIC 和 checksum 实证均为待跑。

动态覆盖矩阵（按 CORE_MEMORY §12）：GENEVE 四元组和业务字段的 fixed/inc/rand/list/pattern 均无可执行例；原因是层 schema/translation 尚未闭环，登记为 G-GENEVE-7，不以静态多 datagram 冒充动态覆盖。多会话/事务不适用；多 datagram 是独立封装，不是隐式会话。

## T5 审计门与执行计划

| 审计项 | 当前结论 |
|---|---|
| ID 数量/顺序 | 20，14 正 + 6 负，与 JSON 一致 |
| 顶层旧键 | 20/20 清除；仅严格层链和框架键 |
| 正例 observable 断言 | 已有 count/fields/raw frames，接线后须以实际 PCAP 校准 |
| 负例 | 6 例仅 `expect_error` + `error_contains`，接线后验 task error |
| 层翻译 | 缺 G-GENEVE-2，当前不能执行 |
| JSON 解析 | `python3 -m json.tool trafficgen/test/protocol_pcap/cases/geneve.json` |

接线后必须全量运行 20 例，先确认 server 与 HEAD 同代，再 tshark/raw frame 对账，最后按授权 NIC 复验；不能只跑新增例或只断言任务不报错。性能六项和动态整格在 G-GENEVE-6/7 关闭前均不得宣称完成。

本版自审：两轮。第一轮逐项核对 RFC→清单→JSON ID 与正负路径；第二轮复核层链旧键、锚词、offset、未运行边界和动态缺口，末轮干净。

# ISIS（中间系统到中间系统，IS-IS）测试用例设计

> 版本：v1.0.1（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/38-isis-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/isis.json`
> 状态：`isis` 层尚未实现；本文定义实现后的 PCAP（抓包文件）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则

用例从设计 §1（两个二层 carrier profile）、§2（不变式/配置）、§3（Common Header/offset）、§4（四类 PDU）、§5（标准 TLV/地址族）、§6（checksum/length/状态）和 §7（错误处理）逐项派生。

IS-IS 是 Ethernet 直接承载的二层协议，不走 IP/TCP/UDP；因此单事件 `packet_count=1`，四事件邻接序列为 4，双事件地址族序列为 2。EtherType 0x8870 profile 的 PDU 起点为 offset 14；LLC profile 的 PDU 起点为 offset 17。正例断言 EtherType/LLC 原始字节和 `isis.*` 字段，避免仅依赖解析器名称。负例 `expect` 严格只有 `expect_error`、`error_contains`，不对失败帧作断言。

PDU Length（PDU 长度）只计算 PDU 本身，不计算 Ethernet/LLC 头和最小帧 padding（填充）。所有 `frames.hex` 从 PDU 起点或 carrier 字段起点断言；自动 checksum 只以 `nonzero` 观察，数值复算属于实现单测契约。

## 2. 用例索引

| # | ID | 类型 | 覆盖 | 事件/报文数 | packet_count |
|---:|---|---|---|---:|---:|
| 1 | `isis_l1_iih_llc` | 正 | LLC、L1 LAN IIH、System ID、Area | 1 | 1 |
| 2 | `isis_l2_iih_llc` | 正 | LLC、L2 IIH、Circuit Type、priority | 1 | 1 |
| 3 | `isis_l1_iih_ethertype` | 正 | EtherType 0x8870、L1 IIH | 1 | 1 |
| 4 | `isis_l2_iih_ethertype` | 正 | EtherType 0x8870、L2 IIH | 1 | 1 |
| 5 | `isis_l1_lsp_ipv4` | 正 | L1 LSP、TLV 1/132、length/checksum | 1 | 1 |
| 6 | `isis_l2_lsp_ipv6` | 正 | L2 LSP、TLV 232、IPv6 TLV profile | 1 | 1 |
| 7 | `isis_l1_lsp_tlv_order` | 正 | 多标准 TLV 顺序/长度 | 1 | 1 |
| 8 | `isis_l1_csnp` | 正 | CSNP range、TLV 9/LSP Entry | 1 | 1 |
| 9 | `isis_l2_psnp` | 正 | PSNP TLV 9、L2 | 1 | 1 |
| 10 | `isis_length_checksum` | 正 | PDU/LSP length、Fletcher checksum | 1 | 1 |
| 11 | `isis_area_system_id` | 正 | Area、System ID、LSP ID | 1 | 1 |
| 12 | `isis_neighbor_up_sequence` | 正 | IIH/IIH/LSP/PSNP、状态顺序 | 4 | 4 |
| 13 | `isis_ipv4_ipv6_tlv_profiles` | 正 | 独立 IPv4/IPv6 TLV profile | 2 | 2 |
| 14 | `isis_neg_profile` | 负 | 未知 wire profile | — | — |
| 15 | `isis_neg_identifier` | 负 | System ID 长度错误 | — | — |
| 16 | `isis_neg_state` | 负 | 非法邻接状态事件 | — | — |
| 17 | `isis_neg_address_family` | 负 | IPv4/IPv6 profile 混用 | — | — |
| 18 | `isis_neg_duplicate_area` | 负 | Area shorthand 与显式 TLV 1 重复 | — | — |
| 19 | `isis_neg_ip_carrier` | 负 | IP/UDP carrier | — | — |
| 20 | `isis_neg_mixed_carrier` | 负 | LLC 与 EtherType 混用 | — | — |
| 21 | `isis_neg_header` | 负 | Common Header 非法 | — | — |
| 22 | `isis_neg_level_type` | 负 | L1/L2 与 PDU type 不一致 | — | — |
| 23 | `isis_neg_length` | 负 | PDU length/TLV 越界 | — | — |
| 24 | `isis_neg_vendor_tlv` | 负 | 未登记厂商 TLV | — | — |
| 25 | `isis_neg_checksum` | 负 | LSP Fletcher checksum 错误 | — | — |

每个负例的 `expect` 严格只有 `expect_error` 与 `error_contains`；`wire_fault` 不应让错误字节生成成功 PCAP。

## 5. 三方一致性检查清单

1. 本文、设计 §8 和 JSON 均有 25 个唯一 ID，顺序一致；正例 13 个、负例 12 个。
2. 正例 `packet_count=[1,1,1,1,1,1,1,1,1,1,1,4,2]`；负例不含 `packet_count`、`fields` 或 `frames`。当前共 25 个用例（13 正、12 负）。
3. 13 个正例均有 `has_payload=true`、`fields` 与 `frames`；LLC PDU offset 只使用 17，EtherType PDU offset 只使用 14。
4. LLC 正例均断言 `fe fe 03` 和 NLPID `83`；EtherType 正例均断言 `88 70`，没有把两种 carrier 混为一个 frame。
5. Common Header PDU types、IIH/LSP/SNP 长度公式、TLV type/length、CSNP/PSNP LSP Entry 16-byte 结构在 design/testcase/JSON 闭环。
6. LSP checksum 仅作非零 PCAP observable；文档明确要求实现单测逐字节复算 Fletcher-16，避免未经验证的 checksum 常数。
7. IPv4/IPv6 profile 只使用 TLV 132/232（并保留 TLV236 完整字段待实现），“IPv6”用例不出现 IP header。
8. 负例 `expect` 恰有两个键，且均要求 task error；不对错误 PCAP 作结构断言。

## 6. 实现后执行建议

先执行 JSON 语法、ID 唯一性、正负 expect 结构、PDU offset 和 hex 静态检查；层注册后按 S1–S13 验证 LLC/EtherType、IIH、LSP、CSNP、PSNP、TLV、checksum/length、状态和地址族，再执行 N1–N7 错误传播。真实 tshark 若缺少 IS-IS dissector，应以 EtherType/LLC/PDU 原始字节和 `decode_as` fixture 作为补充证据，不能凭固定 `frame.protocols` 字符串宣称通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 13 个 ISO 10589 二层正例和 7 个负例；覆盖 LLC/EtherType、L1/L2 IIH、LSP、CSNP、PSNP、标准 TLV、System ID/Area、PDU length、Fletcher checksum、邻接状态和 IPv4/IPv6 TLV 边界。
- v1.0.1（2026-08-20）：修正 LLC 802.3 length/padding 断言，补齐 LAN ID、CSNP 端点、事件固定字段和 5 条缺失负例。

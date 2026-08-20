# ISIS（中间系统到中间系统，IS-IS）设计与用例对抗审查

> 审查对象：`docs/protocol-designs/38-isis-design.md`、`docs/protocol-designs/38-isis-testcase.md`、`trafficgen/test/protocol_pcap/cases/isis.json`
> 审查日期：2026-08-20
> 审查属性：设计文档阶段；不检查 Go（编程语言）实现，不宣称 `isis` 层已注册或 suite（测试套件）已运行。
> 结论：完成三轮审查（含独立反驳），最后一轮 clean（通过）。

## 1. 审查口径

本审查保留两个独立视角：

- **规格可实现性视角（代码逻辑替代项）**：逐字段检查 ISO 10589 Common Header、LLC/EtherType 互斥载体、PDU type/Level、IIH/LSP/CSNP/PSNP 固定字段、PDU Length、LSP Fletcher-16、System ID/Area、TLV 1/9/132/232、邻接状态和 IPv4/IPv6 地址族隔离。
- **用例覆盖视角**：逐项反查设计 §7 负例表、§8 场景表和 testcase §5；检查原始 carrier bytes、PDU offset、length 前缀、TLV 顺序、LSP checksum observable、状态事件原子化，以及负例 `expect` 结构。

不执行 Go 实现、MCP suite 或真实 tshark；未注册层的结果不被虚报为运行结果。

## 2. 规格可实现性审查

### 2.1 已确认

1. **二层载体边界明确**：`iso10589_llc` 使用 802.3 length + `FE FE 03` + NLPID `83`，PDU offset=17；`iso10589_ethertype` 使用 EtherType `0x8870`，PDU offset=14；两者不混用。
2. **Common Header 完整**：NLPID、header length、version/extension、ID length、PDU type、version、reserved、max area addresses 均有宽度和网络字节序。
3. **PDU type/Level 分开**：L1/L2 IIH、LSP、CSNP、PSNP 各有独立类型；Circuit Type 与 level 需一致，不用一个宽松 enum 覆盖。
4. **固定长度可复算**：IIH fixed fields=19，LSP fixed body=20，CSNP fixed body=24，PSNP fixed body=8；PDU length 不含二层头/padding；SNP 的 TLV 9 entry=16 bytes。
5. **TLV 不编造厂商值**：设计只列标准 TLV 1/9/132/232/236；TLV 236 value 不完整时拒绝，未登记 type=250 的负例不输出损坏 PDU。
6. **System ID/Area 语义独立**：System ID 固定 6 bytes；Area 由 TLV 1 显式编码；LSP ID 的 pseudonode/fragment 不被截断或从 MAC 推导。
7. **checksum 语义隔离**：仅 LSP 使用 Fletcher-16；IIH/CSNP/PSNP 不伪造 LSP checksum；文档要求实现阶段值级复算而非只检查非零。
8. **状态与 wire 分离**：四事件序列显式标注 Down/Initializing/Up；状态是 session metadata，不被错误编码成 PDU。
9. **IPv4/IPv6 隔离**：IP 地址族只出现在 TLV 132/232 profile；正例没有 IPv4/IPv6 outer header。

### 2.2 实现阶段守护项（非当前文档 finding）

| 项目 | 当前契约 | 实现前必须补充 |
|---|---|---|
| 802.3 length/padding | LLC length 明确包含必要最小帧 padding；PDU Length 不含 padding | 以 builder（构造器）实际 length 语义验证短帧/最小帧边界 |
| EtherType 解析 | 0x8870 与原始 bytes 断言 | 确认目标 tshark 版本是否自动解码 IS-IS，必要时添加 decode_as |
| Fletcher-16 | PCAP 仅 `nonzero` | 用 ISO 10589 fixture 验证计算覆盖范围、奇偶长度和零 checksum 位置 |
| TLV 236 | 明确待完整字段表 | 取得 RFC 5308 fixture 后再允许 IPv6 Reachability 正例 |
| VLAN | 说明 offset +4 边界，正例无 VLAN | 单独增加 VLAN carrier case；不要把 14/17 固定 offset 复用于 VLAN |
| 状态机 | 静态 metadata | API→planner→worker→PCAP 传播、重传/超时和多邻居隔离测试 |

这些是实现完成定义，不是本阶段缺陷。

## 3. 用例覆盖对抗审查

### 3.1 正例逐条核对

| ID | 设计覆盖 | JSON observable | 结果 |
|---|---|---|---|
| `isis_l1_iih_llc` | LLC/L1 IIH/System ID/Area | LLC bytes、offset 17、type/length/IDs | 通过 |
| `isis_l2_iih_llc` | LLC/L2 IIH/Circuit/priority | LLC bytes、L2 type、priority/LAN ID | 通过 |
| `isis_l1_iih_ethertype` | EtherType/L1 IIH | eth.type、offset 14、common header | 通过 |
| `isis_l2_iih_ethertype` | EtherType/L2 IIH | eth.type、L2 type/circuit | 通过 |
| `isis_l1_lsp_ipv4` | L1 LSP/Area/IPv4 TLV | PDU length, TLV 1/132, checksum | 通过 |
| `isis_l2_lsp_ipv6` | L2 LSP/IPv6 TLV | TLV 232, L2 type, no outer IP | 通过 |
| `isis_l1_lsp_tlv_order` | TLV order/length | `[1,132]`, `[3,4]`, sequence | 通过 |
| `isis_l1_csnp` | CSNP range/TLV9 | start/end IDs, entry count/fields | 通过 |
| `isis_l2_psnp` | PSNP/TLV9 | L2 type, entry count, no range | 通过 |
| `isis_length_checksum` | PDU/LSP length/checksum | length=34, checksum nonzero | 通过 |
| `isis_area_system_id` | Area/System/LSP ID | distinct identity fields | 通过 |
| `isis_neighbor_up_sequence` | state and atomic events | 4 packets, types `[15,15,18,26]`, states | 通过 |
| `isis_ipv4_ipv6_tlv_profiles` | address-family separation | packet 1 TLV132, packet 2 TLV232, offsets | 通过 |

### 3.2 负例逐条核对

| ID | 设计错误行 | JSON expect | 结果 |
|---|---|---|---|
| `isis_neg_profile` | unknown profile | 仅 `expect_error` + `profile` | 通过 |
| `isis_neg_identifier` | System ID 长度 | 仅 `expect_error` + `system` | 通过 |
| `isis_neg_state` | 非法事件状态 | 仅 `expect_error` + `state` | 通过 |
| `isis_neg_address_family` | IPv4/IPv6 混用 | 仅 `expect_error` + `address` | 通过 |
| `isis_neg_duplicate_area` | Area shorthand/TLV 1 重复 | 仅 `expect_error` + `area` | 通过 |
| `isis_neg_ip_carrier` | IP/UDP/TCP carrier | 仅 `expect_error` + `carrier` | 通过 |
| `isis_neg_mixed_carrier` | LLC 与 EtherType 混用 | 仅 `expect_error` + `carrier` | 通过 |
| `isis_neg_header` | Common Header fault | 仅 `expect_error` + `header` | 通过 |
| `isis_neg_level_type` | Level/type/circuit mismatch | 仅 `expect_error` + `level` | 通过 |
| `isis_neg_length` | PDU/TLV length fault | 仅 `expect_error` + `length` | 通过 |
| `isis_neg_vendor_tlv` | unregistered TLV | 仅 `expect_error` + `tlv` | 通过 |
| `isis_neg_checksum` | LSP Fletcher fault | 仅 `expect_error` + `checksum` | 通过 |

## 4. 三方静态一致性

审查脚本加载 JSON，并与设计 §8、testcase §2/§3/§4 手工反查，结果如下：

- ID 总数 25，均唯一；正例 13 个、负例 12 个；顺序一致。
- 正例 `packet_count=[1,1,1,1,1,1,1,1,1,1,1,4,2]`；负例均没有 `packet_count`。
- 13 个正例都有 `has_payload=true`、`fields` 和 `frames`；LLC 例都有 802.3 length/LLC/NLPID carrier bytes 与 PDU offset 17，EtherType 例都有 `88 70` 与 PDU offset 14；多事件例逐包保留 EtherType 证据。
- LLC 例均包含 802.3 length、`fe fe 03` 与 NLPID `83` 证据；EtherType 例均包含 `88 70` 与 PDU NLPID `83`，没有 carrier 交叉混用。
- PDU type/length 前缀与公式闭环：IIH 33=`0x21`、LSP 34=`0x22`/40=`0x28`/46=`0x2e`、CSNP 50=`0x32`、PSNP 34=`0x22`；LLC 802.3 length 对 PDU 33/40/36/50 分别为 `0x2e`/`0x2e`/`0x2e`/`0x35`；S12 每事件类型序列为 15/15/18/26。
- `isis_neg_*` 的 `expect` 恰有两个键，无 fields、frames、packet_count、notes 等结构断言。
- checksum 只以非零 observable 固定；没有把未经复算的 fixture 常数当作跨样本事实。

## 5. Findings（发现项）

### F-01（已修复：IIH PDU length 前缀）

第 1 轮自审初稿把 IIH 的 PDU Length 误写为 32（`0x20`），但固定字段=19、Common Header=8、TLV 1 的 value=4（长度字节+3-byte area），TLV header+value=6，应为 `8+19+6=33`（`0x21`）。已同步修正设计公式、testcase 场景、JSON frames 和 audit 闭环，当前无 `00 20` 的 IIH length 残留。

### F-02（已修复：CSNP/PSNP 结构分离）

第 1 轮逐字段复查确认 CSNP 固定字段为 Source ID+Start/End LSP ID（24 bytes），PSNP 固定字段只有 Source ID（8 bytes）；当前分别为 PDU Length=50/34，且 JSON 对 PSNP 不断言 CSNP range，避免把二者的 SNP body 混用。

### F-03（保留为实现边界：TLV 236 与 VLAN）

TLV 236 的完整 IPv6 Reachability value、Ethernet VLAN 的 length/offset/padding 和 tshark 自动解码在设计阶段没有伪造；文档以独立实现守护项说明。IPv6 TLV 232 正例仍是可完整复算的 16-byte interface address，且无 IP 外层。

## 6. 自审记录与结论

IS-IS ISO 10589 的 LLC/EtherType carrier、Common Header、L1/L2 IIH、LSP、CSNP、PSNP、标准 TLV、System ID/Area、PDU length、LSP checksum、邻接状态与 IPv4/IPv6 TLV profile 均形成 design/testcase/JSON 闭环。负例只验证错误终态，未将未实现层运行结果冒充成功。

完成 **三轮审查**：第 1 轮逐字段复算发现 F-01（IIH 32→33）和 F-02（CSNP/PSNP 固定体混淆）并同步修正；独立反驳轮又确认 LLC length/padding、6-byte LAN ID、CSNP 端点未显式配置、事件固定字段缺失和 5 类错误未覆盖；第 3 轮修正 JSON、testcase 与设计并复核 ID/包数/offset/length/负例结构，**最后一轮 clean（通过）**。

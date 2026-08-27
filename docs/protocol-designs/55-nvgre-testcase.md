# NVGRE（网络虚拟化 GRE，Network Virtualization using Generic Routing Encapsulation）测试用例契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/55-nvgre-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/nvgre.json`
> 状态：`nvgre` 层尚未注册；本文定义实现后的 PCAP/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 21 个条目：14 个目标正例、6 个目标负例，以及 1 个注册前置占位。当前 JSON 只保留 `nvgre_neg_unregistered`，其 `expect` 必须为 `expect_error=true`、`error_contains="unknown layer"`；占位不计入 20 个 NVGRE 语义 ID，不能用拒绝、0 包或空 PCAP 冒充协议行为通过。注册后移除占位，再按本文索引顺序加入 14 个正例和 6 个负例。

NVGRE 是 IP protocol 47 的 GRE 封装。无外层 VLAN、IPv4 options、IPv6 extension header 时，GRE flags 在 IPv4/IPv6 外层 offset 34/54，Key 在 38/58，inner Ethernet 在 42/62。GRE 头必须先按 K 位解析；NVGRE 无 TCP/MSS 分段，若输出框架被底层 IP 分片，验证端必须按 IP fragment（分片）重组后再断言 inner Ethernet。正例实现后每条至少有 `packet_count` 或 `min_packets`、可观测 outer/GRE/inner fields 和稳定 `frames`；负例 `expect` 严格只有 `expect_error` 与 `error_contains`。

动态外层 checksum、IP ID、MAC/IP fixture 可用 `nonzero`、`distinct_values` 或 `same_as_packet` 约束，不硬编码运行期随机值。关键固定字节为 `20 00 65 58`（flags/version、GRE protocol）和 4-byte Key；VSID/Flow ID 由 `Key=VSID(24)|FlowID(8)` 解析，不伪造未注册的 `nvgre.*` tshark 字段。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 实现后证据 |
|---:|---|---|---|---|
| 1 | `nvgre_basic_ipv4_inner_ipv4` | 正 | outer IPv4 + GRE + inner Ethernet/IPv4 | protocol 47、0x6558、Key、inner EtherType 0x0800 |
| 2 | `nvgre_outer_ipv6_inner_ipv4` | 正 | outer IPv6 + GRE + inner IPv4 | IPv6 Next Header=47、inner 0x0800 |
| 3 | `nvgre_outer_ipv4_inner_ipv6` | 正 | outer IPv4 + GRE + inner IPv6 | outer protocol 47、inner 0x86dd |
| 4 | `nvgre_basic_ipv6_inner_ipv6` | 正 | outer/inner IPv6 独立 fixture | outer/inner IPv6 字段与 Key |
| 5 | `nvgre_vsid_zero_flow_zero` | 正 | VSID=0、Flow ID=0 显式保留 | Key `00 00 00 00`，不被默认覆盖 |
| 6 | `nvgre_vsid_max_flow_max` | 正 | VSID=0xffffff、Flow ID=0xff | Key `ff ff ff ff`，不截断 |
| 7 | `nvgre_multi_vsid` | 正 | 多 VSID，Key 高 24-bit 隔离 | distinct VSID/inner frame 关联 |
| 8 | `nvgre_multi_flow_same_vsid` | 正 | 同 VSID 多 Flow ID | 高 24-bit 相同、低 8-bit distinct |
| 9 | `nvgre_inner_vlan` | 正 | 内层 802.1Q VLAN | TPID/VID/inner EtherType |
| 10 | `nvgre_inner_ethernet_boundary` | 正 | MAC、空/最小 payload、Ethernet 边界 | 42/62 起点、长度边界 |
| 11 | `nvgre_outer_inner_family_matrix` | 正 | 四种 outer/inner family 组合 | 四个独立 fixture 的 family 矩阵 |
| 12 | `nvgre_mtu_reassembly` | 正 | 大 inner frame 分片/重组 | Key 和重组 inner bytes |
| 13 | `nvgre_pcap_nic_consistency` | 正 | PCAP 与 NIC capture 一致性 | 两输出 Key/inner 前缀相同 |
| 14 | `nvgre_key_endian_and_ttl` | 正 | Key 网络字节序、TTL/Hop Limit 边界 | `12 34 56 7a`、TTL/HopLimit=0/255 |
| 15 | `nvgre_neg_gre_flags_protocol` | 负 | K/保留 flags、version、protocol 错误 | `flags`/`protocol`/`version` |
| 16 | `nvgre_neg_key_vsid_flow` | 负 | Key 缺失、VSID/Flow ID 越界/字节序 | `key`/`vsid`/`flow` |
| 17 | `nvgre_neg_inner_ethernet_vlan` | 负 | inner Ethernet/MAC/VLAN/截断 | `inner`/`ethernet`/`vlan` |
| 18 | `nvgre_neg_address_family` | 负 | outer/inner family/EtherType mismatch | `address`/`family`/`ethertype` |
| 19 | `nvgre_neg_carrier_length` | 负 | 非 GRE carrier、长度回绕/截断 | `carrier`/`protocol`/`length` |
| 20 | `nvgre_neg_vsid_flow_isolation` | 负 | VSID/Flow 串用、未声明复制 | `vsid`/`flow`/`isolation` |
| 21 | `nvgre_neg_unregistered` | 占位 | 当前层注册前置 | `unknown layer`，不计语义覆盖 |

## 3. 线上编码和偏移断言

无外层扩展时，NVGRE packet（包）布局为：

```text
Outer Ethernet(14) | Outer IPv4(20) or IPv6(40) |
GRE FlagsAndVersion(2)=20 00 | Protocol(2)=65 58 | Key(4) |
Inner Ethernet DstMAC(6) | SrcMAC(6) | [802.1Q(4)] | EtherType(2) | Inner L3...
```

IPv4 outer 的 GRE offset 为 34，Key offset 为 38，inner Ethernet offset 为 42；IPv6 outer 对应 54、58、62。断言必须用实际 outer IP header length/extension chain；禁止把 IPv4 的 34/38/42 套到 IPv6，或把有 VLAN/options 的 fixture 仍按常量读取。

Key bytes 按大端为 `VSID[23:16] | VSID[15:8] | VSID[7:0] | FlowID`。例如 VSID=`0x123456`、FlowID=`0x7a` 的 raw frame（原始帧）应在 Key offset 出现 `12 34 56 7a`。GRE flags/version 仅 K 位：`20 00`；protocol 必须 `65 58`。Inner EtherType 为 `08 00`（IPv4）或 `86 dd`（IPv6），其后才是内层 IP 头。

## 4. 正例逐项断言契约

1. **`nvgre_basic_ipv4_inner_ipv4`**：outer IPv4/47 携带 inner Ethernet/IPv4；断言 protocol 47、offset 34 的 `20 00 65 58`、Key、inner MAC/EtherType 和内层 UDP/TCP 业务字段。
2. **`nvgre_outer_ipv6_inner_ipv4`**：outer IPv6 Next Header=47、inner EtherType 0x0800；断言 offset 54/58/62，不能把 outer IPv6 自动变成 inner IPv6。
3. **`nvgre_outer_ipv4_inner_ipv6`**：outer IPv4/47、inner EtherType 0x86dd；断言 inner IPv6 Next Header 与地址，不复用 IPv4 inner header 长度。
4. **`nvgre_basic_ipv6_inner_ipv6`**：独立 outer/inner IPv6 fixture；断言两层 IPv6 payload length、Next Header 和 inner MAC 关联。
5. **`nvgre_vsid_zero_flow_zero`**：显式 VSID=0、Flow ID=0；断言 Key 四字节全零仍线上出现，不能因零值触发默认 VSID/Flow。
6. **`nvgre_vsid_max_flow_max`**：VSID=0xffffff、FlowID=0xff；断言 Key `ff ff ff ff` 和长度不回绕。
7. **`nvgre_multi_vsid`**：至少两个 VSID；断言 Key 高 24-bit distinct、每个 inner MAC/IP/payload 与 VSID 关联，无跨 VSID 复制。
8. **`nvgre_multi_flow_same_vsid`**：同 VSID 使用两个 Flow ID；断言 Key 高 24-bit 相同、低 8-bit distinct，inner flow 不串用。
9. **`nvgre_inner_vlan`**：内层显式 802.1Q；断言 TPID、VID/TCI 和随后 EtherType/inner IP 偏移，不能将 inner VLAN 当 outer VLAN。
10. **`nvgre_inner_ethernet_boundary`**：覆盖空 payload、最小 inner Ethernet 和 MAC 广播/组播显式值；断言 inner frame 长度与 payload 一致，不能只发 outer headers。
11. **`nvgre_outer_inner_family_matrix`**：四个独立 fixture 覆盖 outer/inner IPv4/IPv6 四组合；分别断言 outer protocol/Next Header、inner EtherType 与对应 L3 header。
12. **`nvgre_mtu_reassembly`**：inner frame 大于单个底层 MTU 时发生显式 IP 分片/重组；先按 IPv4/IPv6 fragment（分片）重组再断言每个 datagram 的 Key、inner Ethernet 和完整 payload，不能把分片当多个 VSID frame。
13. **`nvgre_pcap_nic_consistency`**：同一 fixture 分别输出 PCAP 和 NIC capture；断言两者 protocol/Key/inner MAC/EtherType/payload 稳定前缀相同，允许 checksum offload 差异并记录抓包接口。
14. **`nvgre_key_endian_and_ttl`**：显式 VSID `0x123456`/Flow `0x7a` 与 outer TTL/Hop Limit 边界；断言 Key `12 34 56 7a`、TTL/HopLimit=0/255 不被默认化或交换字节。

合法 VSID=0、Flow ID=0、空 inner payload、显式广播/组播 MAC、单个 TTL=0 数据包、不同 VSID 的独立 datagram 和 NIC checksum offload 属于正例行为；只有封装、配置、长度或关联错误进入负例。

## 5. 负例契约

负例必须在 planner/validator 处失败并传播为 task error，不得产生成功 PCAP、completed/0 packet 或只含 outer IP/GRE 的假成功。每个负例执行期 `expect` 只允许 `expect_error` 与 `error_contains`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `nvgre_neg_gre_flags_protocol` | K 缺失、C/R/S/s/reserved/version 非法或 GRE protocol 非 `0x6558` | `flags`、`protocol` 或 `version` |
| `nvgre_neg_key_vsid_flow` | Key 缺失/截断、VSID 大于 24-bit、Flow ID 大于 8-bit、主机序字节或 Key 溢出 | `key`、`vsid` 或 `flow` |
| `nvgre_neg_inner_ethernet_vlan` | inner MAC/帧截断、VLAN VID/TCI 越界或 EtherType 缺失 | `inner`、`ethernet` 或 `vlan` |
| `nvgre_neg_address_family` | outer/inner IP version、EtherType、protocol 47 或 IPv4/IPv6 header 不匹配 | `address`、`family` 或 `ethertype` |
| `nvgre_neg_carrier_length` | UDP/TCP/裸 IP carrier、GRE/inner frame 截断、长度回绕或超 frame_max | `carrier`、`length` 或 `protocol` |
| `nvgre_neg_vsid_flow_isolation` | 跨 VSID/Flow 引用 inner frame、未声明广播复制或状态串用 | `vsid`、`flow` 或 `isolation` |
| `nvgre_neg_unregistered` | `proto=nvgre` 且 layers 含未注册 `nvgre` | **`unknown layer`** |

## 6. PCAP/NIC 与静态检查

1. 运行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/nvgre.json`，确认当前 JSON 恰有一个 `nvgre_neg_unregistered` 条目，`proto=nvgre`，`expect_error=true`，`error_contains` 精确为 `unknown layer`。
2. 当前机器 ID 集合仅包含占位；占位不计入 20 个语义 ID。注册后 JSON 必须按本文 §2 顺序补入 14 个正例和 6 个负例。
3. 正例实现后每条应有 `packet_count`/`min_packets`、已注册 IP/IPv6/GRE/Ethernet 字段和稳定 frames；不得伪造未注册 `nvgre.*` tshark 字段。Key/inner Ethernet bytes 使用真实 outer header length 定位。
4. 多 VSID/Flow 使用 raw Key、inner MAC/IP/payload、方向和 distinct 约束，不假设并行 worker 的包调度顺序；IP 分片用 fragment offset/ID 重组后断言。
5. `nvgre_pcap_nic_consistency` 必须分别驱动 PCAP 与 NIC capture；捕获端记录 checksum offload 差异但不能放宽 GRE flags/protocol/Key/inner bytes。
6. 负例 `expect` 只能包含 `expect_error`、`error_contains`；占位的 unknown layer 不得冒充协议语义负例已执行。

## 7. 三方一致性表

设计 §9、本文 §2 和未来 JSON 必须保持同一 20 个语义 ID、同一顺序；当前 JSON 另有一个不计入语义覆盖的注册前置占位。

```text
nvgre_basic_ipv4_inner_ipv4
nvgre_outer_ipv6_inner_ipv4
nvgre_outer_ipv4_inner_ipv6
nvgre_basic_ipv6_inner_ipv6
nvgre_vsid_zero_flow_zero
nvgre_vsid_max_flow_max
nvgre_multi_vsid
nvgre_multi_flow_same_vsid
nvgre_inner_vlan
nvgre_inner_ethernet_boundary
nvgre_outer_inner_family_matrix
nvgre_mtu_reassembly
nvgre_pcap_nic_consistency
nvgre_key_endian_and_ttl
nvgre_neg_gre_flags_protocol
nvgre_neg_key_vsid_flow
nvgre_neg_inner_ethernet_vlan
nvgre_neg_address_family
nvgre_neg_carrier_length
nvgre_neg_vsid_flow_isolation
```

## 8. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 NVGRE 正例、6 个严格负例和 1 个未注册占位，覆盖 RFC 7637 GRE/K/Key、VSID/Flow ID、inner Ethernet/VLAN、outer/inner IPv4/IPv6、矩阵、多 VSID、多 Flow、边界、IP 分片重组、PCAP/NIC 和错误传播；当前仅提交设计与用例契约，不修改 Go 实现。

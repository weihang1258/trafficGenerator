# GENEVE（通用网络虚拟化封装，Generic Network Virtualization Encapsulation）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/56-geneve-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/geneve.json`  
> 状态：`geneve` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§12 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `geneve_neg_unregistered`，其 `expect` 必须为 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

GENEVE 是 UDP/6081 数据面封装。无 VLAN、IP options、IPv6 extension headers 和 options 时，IPv4 outer 的基础头起点为 offset（偏移）42，IPv6 outer 为 62；固定 8-byte base header（基础头）为 `00 00 65 58 VV VV VV 00`，其中首字节低 6 bits 是 Opt Len（选项长度，4-byte units），`VV VV VV` 是 24-bit VNI。无 options 的 inner Ethernet 起点分别为 50、70；options 每增加 4 bytes，inner 起点增加 4。UDP datagram 是封装边界，不能使用 TCP stream（TCP 字节流）规则代替。

正例实现后需要 `packet_count`/`min_packets`、可观察字段、options 和稳定 raw frames（原始帧）；负例执行期 `expect` 只能包含 `expect_error`、`error_contains`。动态值用 nonzero/distinct/same_as 断言，不能猜测随机常量。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定 datagram 数 |
|---:|---|---|---|---:|
| 1 | `geneve_ipv4_outer_ipv4_inner` | 正 | IPv4 outer/UDP 6081 + Ethernet/IPv4 inner | 1 |
| 2 | `geneve_ipv4_outer_ipv6_inner` | 正 | IPv4 outer 与 IPv6 inner 独立 fixture | 1 |
| 3 | `geneve_ipv6_outer_ipv4_inner` | 正 | IPv6 outer/UDP 6081 与 IPv4 inner | 1 |
| 4 | `geneve_ipv6_outer_ipv6_inner` | 正 | IPv6 outer/inner 双栈 fixture | 1 |
| 5 | `geneve_vni_boundary` | 正 | VNI=0 与 VNI=0xffffff 24-bit 边界 | 2 |
| 6 | `geneve_version_flags` | 正 | version=0、OAM/Critical flags、reserved=0 | 3 |
| 7 | `geneve_options_single` | 正 | 单 option、class/type/reserved/length/data | 1 |
| 8 | `geneve_options_multiple` | 正 | 多 option 顺序与 Opt Len 累计 | 3 |
| 9 | `geneve_multi_vni` | 正 | 同 outer 载体下多 VNI datagram 隔离 | 4 |
| 10 | `geneve_multi_flow` | 正 | 多 flow、四元组/VNI/options/inner identity 隔离 | 6 |
| 11 | `geneve_inner_vlan_ethernet` | 正 | inner 802.1Q、MAC/EtherType/TCI | 1 |
| 12 | `geneve_empty_inner_payload` | 正 | 空 payload 但完整 inner Ethernet header | 1 |
| 13 | `geneve_mss_not_applicable` | 正 | UDP 不协商 MSS、不生成 TCP handshake | 1 |
| 14 | `geneve_pcap_nic_consistency` | 正 | PCAP 与 NIC 输出、方向、options/inner 一致 | 2 |
| 15 | `geneve_neg_header_truncated` | 负 | 基础头少于 8 bytes | — |
| 16 | `geneve_neg_reserved_version_flags` | 负 | version 非零或 flags/reserved 非法 | — |
| 17 | `geneve_neg_option_length` | 负 | Opt Len、option length、data 截断/不对齐 | — |
| 18 | `geneve_neg_vni_protocol` | 负 | VNI 超 24-bit 或 protocol type 不匹配 | — |
| 19 | `geneve_neg_udp_carrier_inner` | 负 | 非 UDP/错误 6081 或 inner frame 截断 | — |
| 20 | `geneve_neg_checksum` | 负 | IPv6 零 checksum 或非零校验和错误 | — |

## 3. 正例逐项断言契约

1. **`geneve_ipv4_outer_ipv4_inner`**：一条 IPv4/UDP datagram，outer `ip.proto=17`、`udp.dstport=6081`；offset 42 的基础头 `00 00 65 58 00 13 88 00`（VNI 5000）；inner Ethernet 起点 50，EtherType `0x0800`，内层 IPv4 地址与 MAC 和 fixture 一致，`packet_count=1`。
2. **`geneve_ipv4_outer_ipv6_inner`**：outer IPv4、protocol type `0x6558`，inner EtherType `0x86dd`；基础头 offset 42，inner Ethernet offset 50，inner IPv6 version/address 与 outer IPv4 独立，`packet_count=1`。
3. **`geneve_ipv6_outer_ipv4_inner`**：outer `ipv6.nxt=17`、UDP/6081，基础头 offset 62，inner Ethernet offset 70、EtherType `0x0800`；outer IPv6 与 inner IPv4 地址独立，`packet_count=1`。
4. **`geneve_ipv6_outer_ipv6_inner`**：outer/inner 都是 IPv6，outer Next Header=17，offset 62/70 断言基础头和 inner IPv6；不能混淆两层地址，`packet_count=1`。
5. **`geneve_vni_boundary`**：两条 datagram 的 VNI 分别为 0 和 `0xffffff`；基础头分别 `00 00 65 58 00 00 00 00`、`00 00 65 58 ff ff ff 00`，均按 24-bit 解析，`packet_count=2`。
6. **`geneve_version_flags`**：三条 datagram 分别为 flags 全零、OAM bit、Critical bit；version 均为 0、保留位全零、VNI=1，基础头首两字节分别 `00 00`、`00 80`、`00 40`（按网络线序字段读取），`packet_count=3`。不得把 OAM/Critical 误当连接状态。
7. **`geneve_options_single`**：一条 datagram 有一个 option；断言基础头 Opt Len、class/type、第 4 字节高 3 bits reserved=0、低 5 bits Length、data 字节和 inner 起点均按 4-byte units 计算，options 不改变基础头 offset，`packet_count=1`。
8. **`geneve_options_multiple`**：三条 datagram 至少使用两种 option 列表（空、单项、多项）；每条 Opt Len 等于实际 options bytes/4，option 顺序与 data 保持，`packet_count=3`。
9. **`geneve_multi_vni`**：四条同 outer 四元组 datagram 使用至少两个 VNI；每个 VNI 与 inner MAC/IPv4 fixture 成对，distinct VNI 可观察，options/inner 不跨 datagram 覆盖，`packet_count=4`。
10. **`geneve_multi_flow`**：六条 datagram 至少包含三个 flow；断言 source UDP port、VNI、option data 或 inner MAC/IP/payload 组合 distinct，同 flow 状态一致、跨 flow 不串用，不假设跨 flow 到达顺序，`packet_count=6`。
11. **`geneve_inner_vlan_ethernet`**：inner 起点 50（IPv4 outer）先出现 dst/src MAC、`0x8100`、TCI 和 `0x0800`；VLAN tag 只增加 inner offset，基础头仍从 42 开始且长 8 bytes，`packet_count=1`。
12. **`geneve_empty_inner_payload`**：inner payload 长度为零，但完整 dst/src MAC 与 EtherType `0x0800` 存在；UDP length 按 `8+8+options_bytes+inner_frame_length` 复算，`packet_count=1`。
13. **`geneve_mss_not_applicable`**：一条 UDP/6081 datagram，断言无 TCP SYN/SYN-ACK、MSS option 或 TCP termination；基础头仍长 8 bytes，`packet_count=1`。显式 MSS 输入不能改变 UDP 封装。
14. **`geneve_pcap_nic_consistency`**：同一 fixture 分别写 PCAP 并在指定 NIC 捕获；两条方向明确的 UDP/6081 datagram 均有 version/Opt Len/VNI/protocol type/options/inner MAC/EtherType，NIC 过滤器为 `udp port 6081`。checksum offload 时以 wire bytes/解析器结果为准，`packet_count=2`。

## 4. 负例契约

每个负例必须在 planner/validator 失败并传播为 task error；不能产生成功 PCAP、completed/0 packet 或只剩 outer UDP 的假成功。`expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `geneve_neg_header_truncated` | GENEVE 基础头少于 8 bytes | `header` 或 `length` |
| `geneve_neg_reserved_version_flags` | version 非 0、flags/reserved 非法 | `version`、`flag` 或 `reserved` |
| `geneve_neg_option_length` | Opt Len 与 options 总长不一致、option data 截断或非 4-byte 对齐 | `option` 或 `length` |
| `geneve_neg_vni_protocol` | VNI 负数/超过 `0xffffff`，或 protocol type 与 inner 不一致 | `vni` 或 `protocol` |
| `geneve_neg_udp_carrier_inner` | TCP/裸 IP/错误 UDP port，或 Ethernet/VLAN/IP inner 截断 | `transport`、`port` 或 `inner` |
| `geneve_neg_checksum` | IPv6 checksum 为零或 checksum 不匹配 | `checksum` |

合法的 IPv4 UDP zero checksum、VNI=0、Opt Len=0、Length=0 option、空 inner payload（仍含 Ethernet header）、OAM/Critical 显式 flags 和多 flow 乱序由正例覆盖，不能误报为负例。

## 5. 三方一致性和静态检查

1. 设计 §10、本文 §2、注册后的 JSON 和审计必须保持同一 20 个语义 ID、同一顺序，14 正例 + 6 负例；当前 JSON 另有一个不计数的 `geneve_neg_unregistered`。
2. 未来 14 个正例均有 `packet_count`、`fields`/稳定 carrier 字段、options 和 `frames`；6 个负例的 `expect` 只能有 `expect_error`、`error_contains`。当前未注册 JSON 只验证 placeholder 结构。
3. 固定 offsets 为 IPv4/UDP GENEVE=42、IPv6/UDP=62；无 options inner Ethernet=50/70；options 每增加 4 bytes，inner 起点增加 4；基础头永远 8 bytes。
4. Raw frames 只固定可复核的 version/flags/Opt Len/protocol/VNI/EtherType/option reserved+Length/稳定地址字节；动态 flow 端口和地址使用 nonzero/distinct，禁止猜测常量。
5. `protocol_type=0x6558` 时必须断言完整 inner Ethernet；inner IPv4/IPv6、MAC/VLAN、VNI、options 和 payload 按 fixture 独立验证，不能由 outer family 改写。
6. `geneve_mss_not_applicable` 不测试 TCP handshake/MSS/termination；成功证据是 UDP 单 datagram 和基础头。
7. IPv4 UDP checksum 可为零或正确非零；IPv6 UDP checksum 必须非零且正确；NIC capture 需记录接口、过滤器和 offload 观察边界。
8. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/geneve.json` 应成功；当前数组只能含 `geneve_neg_unregistered`，且 `proto=geneve`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `geneve` layer 后，先检查 JSON parser、ID 顺序、正负 expect 键集合、基础头/option offsets 和 tshark 字段注册，再运行 1–14 的 PCAP/NIC 正例和 15–20 的错误传播。若 tshark 没有 `geneve.*` 字段，使用稳定 raw frames 与通用 `udp`/`ip`/`ipv6`/`eth`/`vlan` 字段，不自创解析字段。当前阶段不得将唯一 placeholder 运行结果报告为 GENEVE suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 GENEVE 正例与 6 个严格负例，覆盖 RFC 8926 基础头/version/flags/option length/options、UDP/6081、VNI、protocol type、outer/inner 双栈、inner Ethernet/VLAN、多 VNI/flow、MSS 不适用、边界、checksum、PCAP/NIC 和错误传播；不修改 Go 实现。

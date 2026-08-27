# VXLAN（虚拟可扩展局域网，Virtual eXtensible LAN）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/54-vxlan-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/vxlan.json`  
> 状态：`vxlan` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§11 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `vxlan_neg_unregistered`，其 `expect` 必须为 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

VXLAN 是 UDP/4789 数据面封装，不生成 TCP handshake（握手）或 termination（终止）。无 VLAN、IP options 时，IPv4 outer 的 VXLAN 起点为 offset（偏移）42，IPv6 outer 为 62；固定 8-byte header 为 `08 00 00 00 VV VV VV 00`，其中 `VV VV VV` 是 24-bit VNI。Inner Ethernet 起点分别是 50、70；单 VLAN 时分别为 54、74。UDP datagram 是封装边界，不能用 TCP stream 重组规则代替。

正例实现后需要 datagram `packet_count`/`min_packets`、可观察字段和稳定 raw frames（原始帧）；负例执行期 `expect` 只能包含 `expect_error`、`error_contains`。动态值（例如多流端口）用 nonzero/distinct 断言，不能在 frame 中猜测随机值。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定 datagram 数 |
|---:|---|---|---|---:|
| 1 | `vxlan_ipv4_outer_ipv4_inner` | 正 | IPv4 outer/UDP 4789 + IPv4 inner Ethernet | 1 |
| 2 | `vxlan_ipv4_outer_ipv6_inner` | 正 | IPv4 outer 与 IPv6 inner 独立 fixture | 1 |
| 3 | `vxlan_ipv6_outer_ipv4_inner` | 正 | IPv6 outer/UDP 4789 与 IPv4 inner | 1 |
| 4 | `vxlan_ipv6_outer_ipv6_inner` | 正 | IPv6 outer 与 IPv6 inner 双栈组合 | 1 |
| 5 | `vxlan_vni_boundary` | 正 | VNI=0 与 VNI=0xffffff 24-bit 边界 | 2 |
| 6 | `vxlan_i_flag_reserved` | 正 | I flag=1、保留位全零、固定 8-byte header | 1 |
| 7 | `vxlan_inner_vlan_ethernet` | 正 | inner 802.1Q、MAC/EtherType/TCI | 1 |
| 8 | `vxlan_multi_vni` | 正 | 同一 outer 载体下多 VNI datagram 隔离 | 4 |
| 9 | `vxlan_multi_flow` | 正 | 多 flow、四元组/VNI/inner identity 隔离 | 6 |
| 10 | `vxlan_mss_not_applicable` | 正 | UDP 不协商 MSS、不生成 TCP handshake、单 datagram | 1 |
| 11 | `vxlan_empty_inner_payload` | 正 | 空 payload 但完整 inner Ethernet header | 1 |
| 12 | `vxlan_outer_inner_independent` | 正 | outer/inner 地址族和字段独立 | 2 |
| 13 | `vxlan_pcap_nic_capture` | 正 | PCAP 与 NIC 输出、方向、过滤器一致 | 2 |
| 14 | `vxlan_udp_checksum_profiles` | 正 | IPv4 checksum 规则与 IPv6 非零 checksum | 2 |
| 15 | `vxlan_neg_header_truncated` | 负 | VXLAN header 少于 8 bytes | — |
| 16 | `vxlan_neg_reserved_flags` | 负 | I flag 未置位或 flags/reserved 非零 | — |
| 17 | `vxlan_neg_vni_overflow` | 负 | VNI 超出 24-bit 或编码污染保留字节 | — |
| 18 | `vxlan_neg_udp_carrier` | 负 | 非 UDP、错误 destination port 或错误 outer Next Header | — |
| 19 | `vxlan_neg_inner_frame` | 负 | inner Ethernet/MAC/VLAN/EtherType/IP 长度截断或不一致 | — |
| 20 | `vxlan_neg_checksum` | 负 | IPv6 零 checksum 或非零校验和错误 | — |

## 3. 载体和固定字节断言

1. **`vxlan_ipv4_outer_ipv4_inner`**：一条 IPv4/UDP datagram，outer `ip.proto=17`、`udp.dstport=4789`；offset 42 的 VXLAN header 固定 `08 00 00 00 00 13 88 00`（VNI 5000）；inner Ethernet 起点为 50，offset 62 的 inner EtherType 为 `0x0800`，inner IPv4 地址和 MAC 与 fixture 一致，`packet_count=1`。
2. **`vxlan_ipv4_outer_ipv6_inner`**：outer IPv4、inner EtherType `0x86dd`；outer IPv4 不改变 inner IPv6 header，offset 42/50 分别断言 VXLAN header 和 inner Ethernet 起点（inner EtherType 在 62），`packet_count=1`。
3. **`vxlan_ipv6_outer_ipv4_inner`**：outer `ipv6.nxt=17`、UDP/4789，VXLAN offset 62，inner offset 70、EtherType `0x0800`；outer IPv6 与 inner IPv4 地址独立，`packet_count=1`。
4. **`vxlan_ipv6_outer_ipv6_inner`**：outer/inner 都是 IPv6，outer Next Header=17，offset 62/70 断言 VXLAN 和 inner IPv6；不把两层地址混淆，`packet_count=1`。
5. **`vxlan_vni_boundary`**：两条 datagram 的 VNI 分别为 0 和 `0xffffff`；header 前缀分别 `08 00 00 00 00 00 00 00`、`08 00 00 00 ff ff ff 00`，两个 VNI 均按 24-bit 解析，`packet_count=2`。
6. **`vxlan_i_flag_reserved`**：固定 VNI=1，flags 为 `08`，VXLAN 8 bytes 中三个前置 reserved 和尾部 reserved 均为零；不能出现 `0x80`/`0x01` 等伪 I flag，`packet_count=1`。
7. **`vxlan_inner_vlan_ethernet`**：inner 起点 50（IPv4 outer）先出现 dst/src MAC、`0x8100`、TCI 和 `0x0800`；VLAN tag 只增加 inner offset，VXLAN header 仍从 42 开始且长 8 bytes，`packet_count=1`。
8. **`vxlan_multi_vni`**：四条同 outer 四元组的 datagram 使用至少两个 VNI；每个 `vxlan.vni` 与 inner MAC/IPv4 fixture 成对，distinct VNI 可观察，不能跨 datagram 覆盖，`packet_count=4`。
9. **`vxlan_multi_flow`**：六条 datagram 至少包含三个 flow；断言 source UDP port、VNI、inner MAC/IP 或 payload 的组合 distinct，同 flow 状态一致、跨 flow 不串用；不假设跨 flow 到达顺序，`packet_count=6`。
10. **`vxlan_mss_not_applicable`**：一条 UDP/4789 datagram，断言无 TCP SYN/SYN-ACK、无 TCP MSS option、无 TCP termination；VXLAN header 仍为 8 bytes，`packet_count=1`。显式 MSS 输入不得改变封装。
11. **`vxlan_empty_inner_payload`**：inner payload 长度为零，但完整 dst/src MAC 和 EtherType `0x0800` 存在；outer UDP length 能由 `8 + 8 + inner frame length` 复算，`packet_count=1`。
12. **`vxlan_outer_inner_independent`**：两条独立 fixture，一条 outer IPv4/inner IPv6，一条 outer IPv6/inner IPv4；分别断言 `ip.version`、`ipv6.nxt`、inner EtherType 和 inner 地址族，不能由 outer family 自动改写 inner，`packet_count=2`。
13. **`vxlan_pcap_nic_capture`**：同一 fixture 分别写 PCAP 并在指定 NIC 捕获；两条方向明确的 UDP/4789 datagram 均有 VXLAN flags/VNI、inner MAC/EtherType，NIC 过滤器为 `udp port 4789`。校验和卸载时以 wire bytes/解析器结果为准，`packet_count=2`。
14. **`vxlan_udp_checksum_profiles`**：IPv4 outer fixture 允许 checksum=0 或正确非零；IPv6 outer fixture 必须 checksum 非零且正确。两条 datagram 的 UDP length 和 checksum 覆盖完整 VXLAN payload，`packet_count=2`。

## 4. 负例契约

每个负例必须在 planner/validator 失败并传播为 task error；不能产生成功 PCAP、completed/0 packet 或只剩 outer UDP 的假成功。`expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `vxlan_neg_header_truncated` | VXLAN payload 少于 8 bytes | `header` 或 `length` |
| `vxlan_neg_reserved_flags` | I flag=0、flags/reserved 非零 | `flag` 或 `reserved` |
| `vxlan_neg_vni_overflow` | VNI 为负数、超过 `0xffffff` 或污染 reserved byte | `vni` |
| `vxlan_neg_udp_carrier` | 非 UDP、错误 UDP destination port 或 outer Next Header | `transport` 或 `port` |
| `vxlan_neg_inner_frame` | inner MAC/VLAN/EtherType/IP 截断或长度冲突 | `inner` 或 `length` |
| `vxlan_neg_checksum` | IPv6 checksum 为零或 checksum 不匹配 | `checksum` |

合法的 IPv4 UDP zero checksum、VNI=0、空 inner payload（仍含 Ethernet header）和多 flow 乱序由正例覆盖，不能误报为负例。

## 5. 三方一致性和静态检查

1. 设计 §9、本文 §2、注册后的 JSON 和 audit（对抗审查）必须保持同一 20 个语义 ID、同一顺序，14 正例 + 6 负例；当前 JSON 另有一个不计入语义覆盖的 `vxlan_neg_unregistered`。
2. 未来 14 个正例均有 `packet_count`、`fields`/稳定载体字段和 `frames`；6 个负例的 `expect` 只能有 `expect_error`、`error_contains`。当前未注册 JSON 只验证 placeholder 结构。
3. 固定 offsets 为 IPv4/UDP VXLAN=42、IPv6/UDP=62；无 VLAN inner Ethernet=50/70；有 VLAN=54/74。VXLAN header 永远 8 bytes。
4. Raw frames 只固定可复核的 flags/reserved/VNI/EtherType/稳定地址字节；随机 flow 端口和动态地址使用 nonzero/distinct，禁止猜测常量。
5. IPv4 UDP checksum 可为零或正确非零；IPv6 UDP checksum 必须非零且正确。NIC capture 需记录接口、过滤器和 offload 观察边界。
6. `vxlan_mss_not_applicable` 不测试 TCP handshake/MSS/termination；它的成功证据是 UDP 单 datagram 和固定 VXLAN header。
7. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/vxlan.json` 应成功；当前数组只能含 `vxlan_neg_unregistered`，且 `proto=vxlan`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `vxlan` layer 后，先做 JSON parser、ID 顺序、正负 expect 键集合、frame offset 和 tshark 字段注册检查，再运行 1–14 的 PCAP/NIC 正例和 15–20 的错误传播。若 tshark 没有 `vxlan.*` 字段，使用稳定 raw frames 与通用 `udp`/`ip`/`ipv6`/`eth`/`vlan` 字段，不自创解析字段。当前阶段不得将唯一 placeholder 运行结果报告为 VXLAN suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 VXLAN 数据面正例与 6 个严格负例，覆盖 RFC 7348 header/VNI/I flag、UDP/4789、outer/inner 双栈、inner Ethernet/VLAN、multi-VNI/flow、MSS 不适用、边界、checksum、PCAP/NIC 和错误传播；不修改 Go 实现。

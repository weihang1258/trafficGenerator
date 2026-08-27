# VXLAN（虚拟可扩展局域网，Virtual eXtensible LAN）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与 PCAP（抓包文件）用例契约；`vxlan` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/54-vxlan-testcase.md`、`trafficgen/test/protocol_pcap/cases/vxlan.json`  
> 规范基线：RFC 7348（VXLAN），RFC 768（UDP），RFC 791（IPv4），RFC 8200（IPv6）。

## 1. 范围、证据等级和未注册边界

本设计定义 RFC 7348 的 VXLAN 数据报封装：外层 IP/UDP、UDP destination port（目的端口）4789、8-byte VXLAN header（报头）以及一个 inner Ethernet frame（内层以太网帧）。设计覆盖 IPv4/IPv6 outer（外层）与 IPv4/IPv6 inner（内层）的独立组合、VNI（VXLAN Network Identifier，VXLAN 网络标识符）、I flag（有效标志位）、内层 VLAN、多个 VNI/flow（流）、MSS（最大报文段长度）边界和输出验证。

本版不定义 VTEP（VXLAN Tunnel Endpoint，VXLAN 隧道端点）控制面、组播学习、ARP/ND 抑制、GBP、VXLAN-GPE、Geneve、非以太网 payload 或控制报文。VXLAN 数据面只能承载完整 inner Ethernet frame；不能把任意 UDP payload、裸 IP 包或 Geneve header 静默当作 VXLAN。

当前仓库没有注册 `vxlan` layer、planner（规划器）、validator（校验器）或生成器。`cases/vxlan.json` 只保留一个 `vxlan_neg_unregistered` 占位，必须为 `expect_error=true` 且 `error_contains="unknown layer"`；占位不计入下文 20 个语义 ID。注册前的拒绝、0 包或空 PCAP 都不是 VXLAN 行为通过。

## 2. 推荐配置和协议栈

推荐的层链是 `[ip, udp, vxlan]` 或 `[ipv6, udp, vxlan]`；层链的外层地址族决定 outer IP，VXLAN 配置中的 inner fixture 独立决定 inner Ethernet 后的 EtherType 和 IP 版本：

```json
{
  "layers": [{"ip": {}}, {"udp": {}}, {"vxlan": {}}],
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.20",
  "src_port": 40000,
  "dst_port": 4789,
  "vxlan": {
    "vni": 5000,
    "i_flag": true,
    "inner": {
      "src_mac": "02:00:00:00:10:01",
      "dst_mac": "02:00:00:00:10:02",
      "ether_type": "ipv4",
      "src_ip": "10.10.0.1",
      "dst_ip": "10.10.0.2",
      "payload_b64": "AQIDBA=="
    }
  }
}
```

配置键是测试契约，不是当前实现承诺：

| 配置键 | 约束 |
|---|---|
| `src_ip`/`dst_ip` | outer IP 地址；IPv4 与 IPv6 必须按 outer profile 成对编码，不由 inner 地址自动推导。 |
| `src_port`/`dst_port` | UDP 端口；正例 destination 固定 4789，source 可显式变化；错误端口进入负例。 |
| `vni` | 0–16,777,215 的 24-bit 无符号值；不得写入第 4 个 VNI 字节。 |
| `i_flag` | 正例必须为 `true`，线上 flags byte 为 `0x08`；未设置或保留位非零进入负例。 |
| `inner` | 必须是完整 Ethernet fixture；`src_mac`、`dst_mac`、`ether_type`、地址族、payload 和长度相互一致。 |
| `inner.vlan` | 可选的内层 802.1Q VLAN；VLAN tag 属于 inner frame，不改变 VXLAN header 的固定 8-byte 长度。 |
| `inner.payload_b64` | 可复现二进制 payload；长度计算使用解码后的字节，不使用 Base64 文本长度。 |
| `udp_checksum` | `auto` 由实现计算；IPv4 可按 RFC 768 使用零校验和或非零正确校验和，IPv6 必须非零且正确。 |
| `mss` | 仅是 outer TCP 配置时适用；VXLAN outer transport 是 UDP，本协议不协商、不应用 TCP MSS。显式写入 VXLAN 的 MSS 必须拒绝或被测试标为不适用，不能改变 datagram 分片语义。 |
| `flow_count`/`flow_id` | 多流 fixture 的生成控制；不同 flow 必须保持各自四元组、VNI 和 inner MAC/IP 状态隔离。 |
| `wire_fault` | 仅负例故障注入口：`header_truncated`、`reserved_flags`、`vni_overflow`、`wrong_udp_port`、`inner_truncated`、`checksum`。不是合法线上字段。 |

## 3. VXLAN 8-byte header 逐字节布局

VXLAN header 起点记为 `V`，固定 8 字节，网络字节序：

| 相对 offset | 宽度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 1 | Flags | I flag 为 bit 3（值 `0x08`）；其余 7 bits 保留且必须为 0。 |
| 1 | 3 | Reserved | 必须为 `00 00 00`。 |
| 4 | 3 | VNI | 24-bit big-endian VNI，范围 `0x000000`–`0xffffff`。 |
| 7 | 1 | Reserved | 必须为 `00`。 |

当 I flag 置位时，VNI 才表示有效 VXLAN 网络标识符；本版所有数据面正例都要求 I flag 置位。`VNI=0` 是 RFC 7348 可编码的边界值，仍必须保留 24-bit 布局；`VNI=0xffffff` 是最大合法值。flags、三个保留字节、三个 VNI 字节和尾部保留字节不得因 inner frame 长度变化而移动。

无 VLAN、无 IP options（IP 选项）、无 TCP options 时，VXLAN 起点固定为：

| outer carrier | `V` offset | 计算 |
|---|---:|---|
| Ethernet + IPv4 + UDP | 42 | 14 + 20 + 8 |
| Ethernet + IPv6 + UDP | 62 | 14 + 40 + 8 |

VXLAN header 后紧接 inner Ethernet destination MAC（6）、source MAC（6）、可选 VLAN tag（4）和 EtherType（2）。因此无 VLAN 的 inner Ethernet 起点分别为 50 或 70；有一个 VLAN tag 时为 54 或 74。实现不能把 outer UDP payload 起点误当成 VXLAN inner 起点，也不能把 Ethernet FCS 当作 inner payload。

## 4. Outer IP/UDP 载体

1. UDP destination port 必须为 4789。源端口可变化，但不能用源端口代替 VNI 或协议识别。
2. IPv4 outer 使用 protocol 17；IPv6 outer 使用 Next Header（下一报头）17。outer 地址族只决定 outer header，不改变 VXLAN 8-byte header 和 inner Ethernet 编码。
3. IPv4 UDP checksum 允许按 RFC 768 使用 `0x0000` 表示未计算，也允许使用正确非零值；若给出非零值，必须覆盖 IPv4 pseudo-header、UDP header 和 payload。IPv6 UDP checksum 不得为零，必须覆盖 IPv6 pseudo-header。
4. UDP length 必须等于 8 + 8 + inner Ethernet frame length；IP total/payload length 必须包含 UDP 全部字节。长度不能使用分段前后错误的 Base64 字符数。
5. UDP datagram 是 VXLAN 封装边界。底层抓包若出现大包分段或网卡卸载，验证器必须在可见线速 PCAP 上重组/解释后再断言；不能把 TCP stream 规则套用于 VXLAN。
6. Outer IPv4/IPv6 和 inner IPv4/IPv6 是独立 fixture 维度。禁止从 outer IPv6 推导 inner IPv6，或从 inner 地址族反向改变 outer IP header。

## 5. Inner Ethernet frame

Inner frame 必须至少包含 destination MAC、source MAC、EtherType 和 payload。正例支持以下 EtherType：

| `ether_type` | 线上值 | 约束 |
|---|---:|---|
| `ipv4` | `0x0800` | inner IPv4 header 的 version/protocol/地址与 fixture 一致。 |
| `ipv6` | `0x86dd` | inner IPv6 header 的 version/Next Header/地址与 fixture 一致。 |
| `vlan_ipv4` | `0x8100` 后跟 `0x0800` | 802.1Q TCI、inner EtherType 和 IPv4 payload 长度一致。 |
| `vlan_ipv6` | `0x8100` 后跟 `0x86dd` | 802.1Q TCI、inner EtherType 和 IPv6 payload 长度一致。 |

内层 MAC 是 VXLAN payload 的一部分，必须原样保留；不能替换为 outer MAC。内层 IP 的 checksum、Hop Limit/TTL、地址和 payload 由 inner fixture 独立验证。Inner frame 不能截断在 MAC、VLAN、EtherType 或 IP header 中；长度必须能由实际字节复算。

## 6. Flow、VNI 和状态隔离

同一 UDP 传输可承载多个 VNI；不同 VNI 的 datagram 必须在 payload 中独立编码，不能共享或覆盖 VNI。多 flow fixture 至少改变 source UDP port、VNI 或 inner MAC/IP 中的一项，并断言：

- 每个 flow 的 outer 四元组、VNI 和 inner identity（身份）在自身 datagram 内保持一致；
- 同一 VNI 的多个 flow 不串用 inner MAC/IP 或 payload sequence；
- 不同 VNI 的 datagram 不被合并为一个 VXLAN message；
- flow order（流顺序）只在相同 flow 内断言，不能假设跨 flow 的全局到达顺序；
- `flow_count` 必须产生可观察的 datagram 数，不能只创建配置对象而没有 PCAP 帧。

VXLAN 本身没有 TCP 式 handshake（握手）或 termination（终止）；`has_handshake` 和 `terminates` 不适用于正例。每个正例以 UDP datagram 数、方向、字段和稳定 raw frame（原始帧）断言；不要凭空增加握手包。

## 7. MSS、分片和边界

VXLAN outer transport 是 UDP，因此不存在 VXLAN 层的 MSS 协商。若实现配置了 TCP MSS，MSS 只影响明确存在的 TCP inner payload（如果未来支持），不得改变当前 UDP datagram 的 VXLAN header offset、VNI 或 inner Ethernet bytes。本版 `vxlan_mss_not_applicable` 只验证“没有 MSS 字段/协商、没有 TCP handshake、一个封装仍是一个 UDP datagram”；不把大 UDP datagram 自动拆成 TCP segment。

IP fragmentation（分片）是 outer IP 层独立行为，不是 VXLAN message segmentation（消息分段）。未请求分片时，正例使用 DF（IPv4）或 IPv6 正常单 datagram；若将来支持 outer fragmentation，必须新增专门契约验证分片重组后 VXLAN header 只出现一次。本版不把任意片段视为成功 VXLAN。

边界必须覆盖：inner payload 为空但 Ethernet header 完整、VNI=0、VNI=0xffffff、单 VLAN、最大明确支持的 inner frame 长度以及 inner payload 长度计算。零 payload 不是零长度 inner frame；Ethernet header 仍存在。

## 8. PCAP/NIC 断言和 tshark 证据

实现注册后，先用 `tshark -G fields | grep -E '\tvxlan\.'` 检查目标环境。正例只使用目标环境实际注册的 VXLAN 字段和通用载体字段；若环境没有 `vxlan.*` 字段，则用稳定 raw frames 加 `udp.dstport`、`ip.proto`/`ipv6.nxt`、长度和偏移断言，不自创字段名。推荐观察：

- `udp.dstport=4789`、`udp.length`、`ip.proto=17` 或 `ipv6.nxt=17`；
- `vxlan.flags`/I flag、`vxlan.vni`（若已注册）；
- inner `eth.dst`、`eth.src`、`eth.type`、`vlan.id`；
- inner `ip.version`/`ip.src`/`ip.dst` 或 `ipv6.src`/`ipv6.dst`；
- checksum 状态/原始 checksum 字段，但不把网卡 checksum offload（校验和卸载）显示为生成器错误。

PCAP output（输出）正例必须断言封装 datagram 的方向、数量、outer UDP/4789、VXLAN header 稳定字节、VNI/I flag、inner MAC/EtherType 和 inner 地址族。NIC（网卡）模式除同样字段外，还必须说明抓包接口和过滤器，建议使用 `udp port 4789`；若启用 checksum offload，验证器应同时看 wire bytes 和解析器 checksum 状态，不能只看本机发送前的 socket 状态。

推荐固定 frame offset（无 VLAN/IP options）：IPv4 outer 的 VXLAN header 在 42，IPv6 outer 在 62；VXLAN flags/VNI 的 raw 前缀可分别写为：

```text
08 00 00 00 VV VV VV 00
```

其中 `VV VV VV` 是 fixture 明确给出的 3-byte VNI。VNI 动态时使用字段断言或逐字节稳定 fixture，不把随机值写死。

## 9. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例、6 个负例；顺序必须与 testcase（测试用例契约）及注册后的 JSON 完全一致。当前 JSON 只含不计数的注册前置占位。

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

## 10. 负例和错误传播契约

负例必须在 planner/validator 处失败并传播为 task error（任务错误），不能输出成功 PCAP、completed/0 packet 或只剩 outer UDP 的假成功。每个负例执行期 `expect` 只能包含 `expect_error` 与 `error_contains`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `vxlan_neg_header_truncated` | payload 少于固定 8-byte VXLAN header | `header` 或 `length` |
| `vxlan_neg_reserved_flags` | I flag=0、保留 flags/bytes 非零 | `flag` 或 `reserved` |
| `vxlan_neg_vni_overflow` | VNI 为负数、超过 `0xffffff` 或占用保留 byte | `vni` |
| `vxlan_neg_udp_carrier` | TCP/裸 IP/错误 UDP destination port/Next Header | `transport` 或 `port` |
| `vxlan_neg_inner_frame` | inner MAC、VLAN、EtherType 或 IP payload 截断/长度冲突 | `inner` 或 `length` |
| `vxlan_neg_checksum` | IPv6 checksum 为零或 checksum 不匹配 | `checksum` |

合法的 IPv4 UDP zero checksum、VNI=0、空 inner payload（仍有 Ethernet header）和多 flow 乱序不是错误；它们必须由各自正例覆盖。错误传播必须保留原始原因，不能以通用“0 packets”替代验证错误。

## 11. 三方契约和实现后检查

1. 本文 §9、`54-vxlan-testcase.md` §2、未来注册后的 `vxlan.json` 和审计文档必须保持同一 20 个语义 ID、同一顺序，14 正例 + 6 负例；当前 JSON 另有一个不计数的 `vxlan_neg_unregistered`。
2. 未来 14 个正例均需有 datagram `packet_count`/`min_packets`、方向/字段和稳定 `frames`；6 个负例的 `expect` 键集合必须恰为 `expect_error`、`error_contains`。
3. 正例 raw offsets 必须与 outer IP 头长度一致：IPv4/UDP=42，IPv6/UDP=62；inner Ethernet 起点分别为 50、70（无 VLAN）。
4. VXLAN header 固定 8 bytes，flags=`08`、reserved=0、VNI 为 3 bytes、末尾 reserved=0；inner VLAN 只能增加 inner offset，不得移动 VXLAN header。
5. outer/inner IPv4/IPv6、MAC、VNI、flow 和 payload 必须按 fixture 独立断言；不因地址族或 flow 数量隐式改写另一层。
6. `vxlan_mss_not_applicable` 不得断言 TCP handshake、TCP MSS option 或 TCP termination；UDP 单 datagram 是该场景的可观察结果。
7. IPv4 checksum 允许零或正确非零；IPv6 UDP checksum 必须非零且正确。NIC checksum offload 只能影响观察方式，不能降低线格式契约。
8. 当前未注册阶段只能运行唯一 placeholder，并期待 `unknown layer`；不得把该占位计入 20 个语义场景或声称 suite 通过。

## 12. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 VXLAN 数据面正例与 6 个严格负例，覆盖 RFC 7348 的 8-byte header、VNI/I flag、UDP/4789、outer/inner 双栈、inner Ethernet/VLAN、multi-VNI/flow、MSS 不适用、边界、checksum、PCAP/NIC 和错误传播；不修改 Go 实现。

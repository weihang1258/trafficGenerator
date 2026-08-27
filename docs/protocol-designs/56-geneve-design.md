# GENEVE（通用网络虚拟化封装，Generic Network Virtualization Encapsulation）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与 PCAP（抓包文件）用例契约；`geneve` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/56-geneve-testcase.md`、`trafficgen/test/protocol_pcap/cases/geneve.json`  
> 规范基线：RFC 8926（GENEVE）、RFC 768（UDP）、RFC 791（IPv4）、RFC 8200（IPv6）。

## 1. 范围、证据等级和未注册边界

本设计定义 RFC 8926 的 GENEVE 数据面封装：外层 IPv4/IPv6、UDP destination port（目的端口）6081、GENEVE 基础头、可变长度 options（选项）以及 inner payload（内层载荷）。本版以 Ethernet（以太网）inner payload 为主，并独立覆盖 inner IPv4/IPv6 地址族、VNI（Virtual Network Identifier，虚拟网络标识符）、版本、flags、option length 和 option bytes（选项字节）。

本版不定义控制面、隧道端点发现、MAC 学习、加密、Geneve over TCP/QUIC、VXLAN-GPE 或把 VXLAN 头当作 GENEVE 头。GENEVE 不是 VXLAN 的别名；protocol type（协议类型）、option 编码和 UDP 端口必须按本契约编码。

当前仓库没有注册 `geneve` layer、planner（规划器）、validator（校验器）或生成器。`cases/geneve.json` 只保留一个 `geneve_neg_unregistered` 占位，必须为 `expect_error=true` 且 `error_contains="unknown layer"`；占位不计入下文 20 个语义 ID。注册前的拒绝、0 包或空 PCAP 不是 GENEVE 行为通过。

## 2. 推荐配置和协议栈

推荐层链为 `[ip, udp, geneve]` 或 `[ipv6, udp, geneve]`。外层地址族只决定 outer IP（外层 IP）头；GENEVE 配置中的 inner fixture（内层固定样本）独立决定 protocol type、Ethernet、IPv4/IPv6 和 payload。

```json
{
  "layers": [{"ip": {}}, {"udp": {}}, {"geneve": {}}],
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.20",
  "src_port": 42000,
  "dst_port": 6081,
  "geneve": {
    "vni": 5000,
    "version": 0,
    "oam": false,
    "critical": false,
    "protocol_type": "ethernet",
    "options": [],
    "inner": {
      "src_mac": "02:00:00:00:20:01",
      "dst_mac": "02:00:00:00:20:02",
      "ether_type": "ipv4",
      "src_ip": "10.20.0.1",
      "dst_ip": "10.20.0.2",
      "payload_b64": "AQIDBA=="
    }
  }
}
```

配置键是测试契约，不是当前实现承诺：

| 配置键 | 约束 |
|---|---|
| `src_ip`/`dst_ip` | outer 地址；IPv4 与 IPv6 必须按 outer profile（档案）成对编码，不能由 inner 地址族推导。 |
| `src_port`/`dst_port` | UDP 端口；正例 destination 固定 6081，错误端口进入负例。 |
| `version` | GENEVE version 为 2-bit，RFC 8926 当前正例必须为 0；非零拒绝。 |
| `oam`/`critical` | flags 的 bit 7/6；除显式 OAM/critical 正例外，其余保留位必须为 0。 |
| `vni` | 0–16,777,215 的 24-bit 无符号值；不得写入第 4 个 VNI 字节。 |
| `protocol_type` | 2-byte EtherType；Ethernet inner payload 使用 `0x6558`，IPv4/IPv6 直接载荷可用 `0x0800`/`0x86dd`，必须与实际 payload 一致。 |
| `options` | 每个 option header 4 bytes；data 长度必须是 4-byte units（4 字节单位）；基础头 option length 必须等于全部 option bytes/4。 |
| `inner` | Ethernet fixture 时必须有 dst/src MAC、EtherType 和完整 payload；不能静默截断或替换 outer MAC。 |
| `inner.vlan` | 可选的 inner 802.1Q VLAN；属于 inner payload，不改变 GENEVE 基础头固定 8 bytes。 |
| `payload_b64` | Base64（基于 64 个字符的二进制编码）解码后才参与长度计算；不能使用文本长度。 |
| `udp_checksum` | `auto` 计算；IPv4 可为零或正确非零，IPv6 必须非零且正确。 |
| `mss` | GENEVE outer transport 是 UDP，本层不协商、不应用 TCP MSS（最大报文段长度）；写入 GENEVE 的 MSS 只能拒绝或标记不适用。 |
| `flow_count`/`flow_id` | 多流生成控制；每条流的四元组、VNI、options 和 inner identity（身份）必须隔离。 |
| `wire_fault` | 仅负例故障注入口：`header_truncated`、`reserved_bits`、`option_length`、`vni_overflow`、`wrong_udp_port`、`inner_truncated`、`checksum`。不是合法线上字段。 |

## 3. GENEVE 基础头逐字节布局

GENEVE 基础头起点记为 `G`，固定 8 bytes，网络字节序：

| 相对 offset | 宽度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 1 | Ver(2) + Opt Len(6) | version 在 bit 7–6，正例为 0；Opt Len 是 options 总长度/4，范围 0–63。 |
| 1 | 1 | OAM/Critical/Reserved | OAM bit 7、Critical bit 6；bit 5–0 保留且必须为 0。 |
| 2 | 2 | Protocol Type | Ethernet 为 `0x6558`；其他类型必须由 profile 明确声明并与 payload 一致。 |
| 4 | 3 | VNI | 24-bit big-endian VNI，范围 `0x000000`–`0xffffff`。 |
| 7 | 1 | Reserved | 必须为 `00`。 |

`Opt Len=0` 表示无 options。`Opt Len=n` 表示基础头后紧跟 `n*4` bytes options；基础头不能把 option header 或 data 算入 VNI/inner payload。无 outer IP options/extension headers 时，基础头起点为：

| outer carrier | `G` offset | 计算 |
|---|---:|---|
| Ethernet + IPv4 + UDP | 42 | 14 + 20 + 8 |
| Ethernet + IPv6 + UDP | 62 | 14 + 40 + 8 |

无 options 时 inner payload 起点为 50 或 70；有 `n` 个 option-length units 时起点为 `50+n*4` 或 `70+n*4`。任何 options 都不能移动 GENEVE 基础头本身。基础头固定 raw prefix（原始前缀）示例：

```text
00 00 65 58 VV VV VV 00
```

其中首字节的低 6 bits 为 options 总长度/4，`VV VV VV` 是明确 fixture 的 3-byte VNI。若 OAM/critical 置位，第二字节必须仅出现对应 bit。

## 4. Options 编码与校验

每个 option 按 RFC 8926 编码：

```text
Option Class(2) | Type(1) | Reserved(3) + Length(5) | Option Data(Length*4)
```

`Option Class` 为 network byte order 的 16-bit class；`Type` 为 8-bit；第 4 字节高 3 bits 为 reserved（保留位，必须为 0），低 5 bits 为 Length，单位为 4 bytes。每个 option 总长度为 `4 + Length*4` bytes。Options 总字节数必须是 4 的倍数，且基础头 `Opt Len` 必须精确等于总字节数/4。

- 版本 0 的正例可使用空 options、一个 option、多个 option 和最大明确支持长度；实现不能因 options 为空而增加伪造 option。
- `Length=0` 合法，表示 option header 后没有 data；`Length>0` 时 data 必须完整存在。
- options 按线上顺序保留；不能按 class/type 排序、合并或跨 datagram 串接。
- 未识别 option class 的处理由 OAM/Critical 语义决定；本设计的负例只验证结构长度和保留位，不能声称实现了任意厂商 option。
- Option 第 4 字节高 3 bits 为 reserved，必须为零；低 5 bits 是 Length。保留 flags、option data 截断、Opt Len 与实际 options 不一致必须在 validator/planner 阶段失败，不能输出仅有外层 UDP 的假成功。

## 5. Outer IP/UDP 载体

1. UDP destination port 必须是 6081；源端口可变化，但不能代替 VNI、protocol type 或 options。
2. IPv4 outer 使用 protocol 17；IPv6 outer 使用 Next Header 17。outer family 不能改变 GENEVE 8-byte base header。
3. IPv4 UDP checksum 可为 `0x0000` 或正确非零值；IPv6 UDP checksum 不得为零，必须覆盖 IPv6 pseudo-header、UDP header 和完整 GENEVE payload。
4. UDP length 必须等于 `8 + 8 + options_bytes + inner_payload_bytes`；IP total/payload length 必须包含 UDP 全部字节。长度计算使用解码后的 payload 和 option bytes。
5. UDP datagram 是 GENEVE 封装边界。底层抓包若出现 IP 分片或卸载，验证器应重组/解释后再断言，不能套用 TCP stream 规则。
6. outer IPv4/IPv6 与 inner IPv4/IPv6 是独立 fixture 维度，四种组合均可声明；禁止由一个地址族静默改写另一层。

## 6. Inner payload

默认 protocol type 为 `0x6558`（Transparent Ethernet Bridging，透明以太网桥接），此时 inner payload 必须是完整 Ethernet frame：

```text
DstMAC(6) | SrcMAC(6) | [802.1Q VLAN(4)] | EtherType(2) | L3/payload(N)
```

支持的 Ethernet fixture EtherType：

| inner `ether_type` | 线上值 | 约束 |
|---|---:|---|
| `ipv4` | `0x0800` | inner IPv4 version、protocol、长度、checksum 和地址自洽。 |
| `ipv6` | `0x86dd` | inner IPv6 version、Next Header、payload length 和地址自洽。 |
| `vlan_ipv4` | `0x8100` + `0x0800` | TCI/VID、后续 EtherType 和 IPv4 payload 长度一致。 |
| `vlan_ipv6` | `0x8100` + `0x86dd` | TCI/VID、后续 EtherType 和 IPv6 payload 长度一致。 |

若 profile 使用 `protocol_type=0x0800` 或 `0x86dd`，payload 是对应裸 L3 内容，不能再伪造 Ethernet header；本版正例以 Ethernet protocol type 为主，专门的裸 L3 变体不计入 20 个 ID。inner MAC 是 payload 的一部分，不能替换为 outer MAC。空 payload 仍必须保留完整 Ethernet header（含 EtherType），不得变成零长度 frame。

## 7. VNI、options 和 flow 隔离

同一 UDP 传输可携带多个 VNI；每个 datagram 的 options、VNI 和 inner frame 独立编码。多 flow fixture 至少改变 source UDP port、VNI、option data 或 inner MAC/IP 中一项，并断言：

- 每个 flow 的 outer 四元组、VNI、option bytes 和 inner identity 在自身 datagram 内保持一致；
- 同一 VNI 的多个 flow 不串用 options、inner MAC/IP 或 payload sequence（序列）；
- 不同 VNI 的 datagram 不合并为一个 GENEVE message（消息）；
- options 顺序只在同一 datagram 内断言，不能假设跨 flow 的全局到达顺序；
- `flow_count` 必须产生可观察的 UDP datagram，不能只建立配置对象。

GENEVE 没有 TCP 式 handshake（握手）或 termination（终止）；正例不设置 `has_handshake`/`terminates`。OAM/critical 是 header flags，不是连接状态。

## 8. MSS、分片和边界

GENEVE outer transport 是 UDP，不存在本层 MSS 协商。`geneve_mss_not_applicable` 只验证没有 TCP handshake、MSS option 或 TCP termination，且一次封装仍为一个 UDP datagram。大 inner frame 不得被自动拆为多个 GENEVE datagram；若未来支持 outer IP fragmentation，必须新增分片重组专门契约。

边界至少覆盖：version=0、Opt Len=0、Length=0 option、VNI=0、VNI=`0xffffff`、OAM/critical 单独置位、多个 options、空 inner payload（Ethernet header 完整）、单 VLAN、最大明确支持 inner frame 长度、UDP/6081、IPv4 zero checksum 和 IPv6 non-zero checksum。显式 0 不能被默认值覆盖。

## 9. PCAP/NIC 断言和 tshark 证据

实现注册后先用 `tshark -G fields | grep -E '\tgeneve\.'` 检查目标环境。正例只使用实际注册的 `geneve.*` 字段和通用 carrier 字段；若环境没有 Geneve dissector（解析器），使用 raw frames 加 `udp.dstport`、`ip.proto`/`ipv6.nxt`、长度和真实偏移断言，不自创字段名。

推荐观察：

- `udp.dstport=6081`、`udp.length`、`ip.proto=17` 或 `ipv6.nxt=17`；
- `geneve.version`、`geneve.opt_len`、OAM/Critical flags、`geneve.protocol`、`geneve.vni`（若已注册）；
- `geneve.option.*` 的 class/type/length（若已注册）；
- inner `eth.dst`、`eth.src`、`eth.type`、`vlan.id`；
- inner `ip.version`/`ip.src`/`ip.dst` 或 `ipv6.src`/`ipv6.dst`；
- checksum 原始字段和解析状态；NIC checksum offload（校验和卸载）差异不能直接判为生成器错误。

PCAP output（输出）正例必须断言 datagram 方向、数量、UDP/6081、基础头固定字节、VNI、protocol type、options 长度/内容、inner MAC/EtherType 和地址族。NIC 模式还必须记录捕获接口和建议过滤器 `udp port 6081`，同时依据 wire bytes（线上字节）和解析器结果检查卸载边界。

## 10. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例、6 个负例；顺序必须与 testcase 及注册后的 JSON 完全一致。当前 JSON 只有不计数的注册前置占位。

| # | ID | 类型 | 覆盖 | 约定 datagram 数 |
|---:|---|---|---|---:|
| 1 | `geneve_ipv4_outer_ipv4_inner` | 正 | IPv4 outer/UDP 6081 + Ethernet/IPv4 inner | 1 |
| 2 | `geneve_ipv4_outer_ipv6_inner` | 正 | IPv4 outer 与 IPv6 inner 独立 fixture | 1 |
| 3 | `geneve_ipv6_outer_ipv4_inner` | 正 | IPv6 outer/UDP 6081 与 IPv4 inner | 1 |
| 4 | `geneve_ipv6_outer_ipv6_inner` | 正 | IPv6 outer/inner 双栈 fixture | 1 |
| 5 | `geneve_vni_boundary` | 正 | VNI=0 与 VNI=0xffffff 24-bit 边界 | 2 |
| 6 | `geneve_version_flags` | 正 | version=0、OAM/Critical flags 和保留位 | 3 |
| 7 | `geneve_options_single` | 正 | 单 option、class/type/reserved/length/data | 1 |
| 8 | `geneve_options_multiple` | 正 | 多 option 顺序与 option length 累计 | 3 |
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

## 11. 负例和错误传播契约

负例必须在 planner/validator 处失败并传播为 task error（任务错误），不能输出成功 PCAP、completed/0 packet 或只剩 outer UDP 的假成功。每个负例执行期 `expect` 只能包含 `expect_error` 与 `error_contains`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `geneve_neg_header_truncated` | GENEVE 基础头少于 8 bytes | `header` 或 `length` |
| `geneve_neg_reserved_version_flags` | version 非 0、保留 flags/byte 非零 | `version`、`flag` 或 `reserved` |
| `geneve_neg_option_length` | Opt Len 与 options 总长不一致、option data 截断或非 4-byte 对齐 | `option` 或 `length` |
| `geneve_neg_vni_protocol` | VNI 为负数/超过 `0xffffff`，或 protocol type 与 inner 不一致 | `vni` 或 `protocol` |
| `geneve_neg_udp_carrier_inner` | TCP/裸 IP/错误 UDP port，或 Ethernet/VLAN/IP inner 截断 | `transport`、`port` 或 `inner` |
| `geneve_neg_checksum` | IPv6 checksum 为零或 checksum 不匹配 | `checksum` |

合法的 IPv4 UDP zero checksum、VNI=0、Opt Len=0、Length=0 option、空 inner payload（仍有 Ethernet header）、OAM/critical 显式 flags 和多 flow 乱序由正例覆盖，不能误报为负例。错误传播必须保留原始原因，不能以通用“0 packets”替代验证错误。

## 12. 三方契约和实现后检查

1. 本文 §10、`56-geneve-testcase.md` §2、未来注册后的 `geneve.json` 和审计文档必须保持同一 20 个语义 ID、同一顺序，14 正例 + 6 负例；当前 JSON 另有一个不计数的 `geneve_neg_unregistered`。
2. 未来 14 个正例均需有 datagram `packet_count`/`min_packets`、方向/字段和稳定 `frames`；6 个负例的 `expect` 键集合必须恰为 `expect_error`、`error_contains`。
3. 正例 raw offsets 必须与 outer IP 头长度一致：IPv4/UDP GENEVE=42，IPv6/UDP=62；无 options 的 inner Ethernet 起点为 50/70；options 每增加 4 bytes，inner 起点增加 4。
4. GENEVE 基础头永远 8 bytes；version=0、Opt Len=options_bytes/4、flags 保留位为零、VNI 为 3 bytes、尾部 reserved=0；options 不得改变基础头字段位置。
5. `protocol_type=0x6558` 时必须解析完整 inner Ethernet；inner IPv4/IPv6、MAC、VLAN、VNI、options 和 payload 按 fixture 独立断言，不能因 outer family 或 flow 数量隐式改写。
6. `geneve_mss_not_applicable` 不得断言 TCP handshake/MSS option/termination；UDP 单 datagram 和固定基础头是成功证据。
7. IPv4 UDP checksum 允许零或正确非零；IPv6 UDP checksum 必须非零且正确。NIC offload 只能影响观察方式，不能降低线格式契约。
8. 当前未注册阶段只能运行唯一 placeholder，并期待 `unknown layer`；不得把该占位计入 20 个语义场景或声称 suite 通过。

## 13. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 GENEVE 数据面正例和 6 个严格负例，覆盖 RFC 8926 基础头/version/flags/option length/options、UDP/6081、VNI、protocol type、outer/inner 双栈、inner Ethernet/VLAN、多 VNI/flow、MSS 不适用、边界、checksum、PCAP/NIC 和错误传播；不修改 Go 实现。

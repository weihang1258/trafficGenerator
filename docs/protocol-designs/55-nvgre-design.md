# NVGRE（网络虚拟化 GRE，Network Virtualization using Generic Routing Encapsulation）设计契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：仅设计与 PCAP（抓包文件）用例契约；`nvgre` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。
> 配套文件：`docs/protocol-designs/55-nvgre-testcase.md`、`trafficgen/test/protocol_pcap/cases/nvgre.json`
> 规范基线：RFC 7637（NVGRE）及 RFC 2784/2890（GRE 基础头与扩展），项目仅实现可审计的 NVGRE over GRE 线协议档案。

## 1. 范围、profile 和未注册边界

本版定义 NVGRE 数据面封装：外层 IPv4/IPv6 承载 GRE，GRE 封装内层 Ethernet（以太网）帧；覆盖单 VSID（Virtual Subnet ID，虚拟子网标识）、多 VSID、多 Flow ID（流标识）、内层 IPv4/IPv6、内层 VLAN、IP 分片/重组和生命周期。控制面、NHRP、ARP/ND 代理、隧道端点发现、策略路由、加密和云厂商私有扩展不由本 profile（协议档案）推导。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `nvgre_v1` | IPv4/IPv6 + GRE | GRE Key、VSID/Flow ID、inner Ethernet、inner IPv4/IPv6、可选 VLAN | 隧道建立、端点发现、MAC 学习或业务可达性 |
| `nvgre_multi_vsid` | IPv4/IPv6 + GRE | 同一 fixture（固定样本）中显式多个 VSID 和 Flow ID | 未声明的跨 VSID 转发或广播复制 |
| `nvgre_boundary` | IPv4/IPv6 + GRE | 24-bit VSID、8-bit Flow ID 和内层帧边界 | 超范围值的截断、回绕或隐式修正 |

当前仓库没有注册 `nvgre` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/nvgre.json` 只保留一个 `nvgre_neg_unregistered` 的 `expect_error=true`、`error_contains="unknown layer"` 占位；该占位不计入下文 20 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 NVGRE 行为通过。

## 2. 协议栈、承载和固定偏移

推荐层链为 `[ip, gre, nvgre]`，其中 `nvgre` 是 GRE 上的 Ethernet terminal layer（终结层）。实现应自动补齐外层 Ethernet 和 IP；若配置明确选择 IPv6，不得改写成 IPv4。NVGRE 使用 IP protocol（协议号）47 的 GRE，不使用 UDP、TCP 或裸 Ethernet 作为替代载体。

无 VLAN、无 IP options（IP 选项）且无外层扩展头时，固定偏移如下：

| 观察点 | IPv4 外层 | IPv6 外层 |
|---|---:|---:|
| GRE flags/version | 34 = Ethernet 14 + IPv4 20 | 54 = Ethernet 14 + IPv6 40 |
| GRE protocol | 36 | 56 |
| GRE Key | 38 | 58 |
| inner Ethernet destination MAC | 42 | 62 |
| inner Ethernet source MAC | 48 | 68 |
| inner EtherType | 54 | 74 |

GRE base header（基础头）为 4 字节；NVGRE 必须设置 Key Present（K）位，因而 Key 字段紧随其后，占 4 字节。IPv4 外层 inner Ethernet 起点为 42，IPv6 外层为 62。若外层 IPv4 options、IPv6 extension header、外层 VLAN 或显式内层 VLAN 存在，断言必须根据实际头长度定位，不能继续使用上述常量。

## 3. GRE/NVGRE 线上编码

### 3.1 GRE flags、protocol 和 Key

NVGRE GRE 头遵循 RFC 2784/7637：

```text
FlagsAndVersion(2) | ProtocolType(2) | Key(4) | InnerEthernetFrame(N)
```

`FlagsAndVersion` 的确定值为 `0x2000`（K=1；C、R、S、s、Recursion 和 Version 均为 0）；`ProtocolType` 必须为 `0x6558`（Transparent Ethernet Bridging，透明以太网桥接）。C、R、S 或 s 位被置位、Version 非零、保留位非零或协议类型不是 `0x6558` 时，必须拒绝，不得当作 NVGRE 成功解析。

GRE Key 按网络字节序编码：

```text
Key(32) = VSID(24) << 8 | FlowID(8)
```

VSID 使用 Key 的高 24 位，合法范围为 `0x000000`–`0xffffff`；Flow ID 使用低 8 位，合法范围为 `0x00`–`0xff`。Key 不得按主机字节序写入，不得把 VSID 截断为 16 位，也不得把 Flow ID 混入 VSID。比如 VSID=`0x123456`、FlowID=`0x7a` 时，Key bytes 为 `12 34 56 7a`。

### 3.2 Inner Ethernet

Inner Ethernet frame（内层以太网帧）至少包含：

```text
DstMAC(6) | SrcMAC(6) | [802.1Q VLAN(4)] | EtherType(2) | Payload(N)
```

默认不插入 VLAN；若显式配置 VLAN，TPID 必须为 `0x8100`（或 profile 明确声明的 `0x88a8`），TCI 的 VID 必须在 12-bit 范围内，inner EtherType 仍需与内层 payload 一致。内层 EtherType `0x0800` 表示 IPv4，`0x86dd` 表示 IPv6；inner Ethernet 不得被误读成 outer IP 或直接拼接成裸 L3 payload。广播/组播 MAC 只有在 fixture 明确给出时才出现。

## 4. Outer/inner 地址族和封装语义

外层 IPv4 EtherType 为 `0x0800`、IP protocol 为 47；外层 IPv6 EtherType 为 `0x86dd`、Next Header（下一头）为 47。内层 IPv4/IPv6 是独立 fixture 字段，由 inner EtherType 选择；outer 和 inner address family（地址族）可独立组合，因此至少验证 outer IPv4 + inner IPv6 与 outer IPv6 + inner IPv4，而不能由 outer family 静默改写 inner EtherType。

IPv4 outer header 必须正确填充 total length、TTL 和 checksum；IPv6 outer header 必须填充 payload length、Hop Limit 和 Next Header=47。内层 IPv4 的 checksum/length 和内层 IPv6 的 payload length/Next Header 也必须自洽。外层/内层源目的地址不得在 builder（构造器）中互换，inner frame 的 MAC 与 inner IP 地址属于同一 inner fixture。

NVGRE 是无连接封装。每个 GRE packet（包）保留独立 VSID/Flow ID/inner frame 关联；不能自动生成握手、Keepalive、ARP、ND、MAC 学习或无限广播。多 VSID/multi-flow 只发送配置声明的 frame，跨 VSID 状态混用属于错误。

## 5. 配置 typedef（类型定义）和校验契约

以下是设计契约，不是当前存在的 Go struct（结构体）：

```go
type NVGREConfig struct {
    Profile       string           `json:"profile"`
    Outer         NVGREOuter       `json:"outer"`
    VSIDs         []NVGREVSID      `json:"vsids"`
    WireFault     string           `json:"wire_fault"` // 仅负例
}

type NVGREOuter struct {
    SrcIP, DstIP  string           `json:"src_ip"`
    IPVersion     uint8            `json:"ip_version"` // 4 or 6
    TTLOrHopLimit uint8            `json:"ttl_or_hop_limit"`
}

type NVGREVSID struct {
    VSID          uint32           `json:"vsid"`     // 0..0xffffff
    FlowID        uint8            `json:"flow_id"`  // 0..0xff
    Inner         NVGREInner      `json:"inner"`
}

type NVGREInner struct {
    SrcMAC, DstMAC string           `json:"src_mac"`
    VLAN           *uint16          `json:"vlan,omitempty"`
    EtherType      uint16           `json:"ethertype"`
    SrcIP, DstIP   string           `json:"src_ip"`
    Payload        []byte           `json:"payload"`
    PayloadB64     string           `json:"payload_b64"`
}
```

`Validate` 必须覆盖：profile、outer IP version/address family、IP protocol 47、GRE flags/version、protocol `0x6558`、Key Present、VSID 24-bit、Flow ID 8-bit、inner MAC/EtherType、inner VLAN VID、inner IP family/EtherType、长度和 checksum、VSID/FlowID 状态隔离、wire fault 选择及传输层组合。`wire_fault` 只能注入负例并传播为 task error，不得被忽略或变成线上字段。

### 5.1 合法默认与显式值

实现可以提供 profile 默认值（例如 outer TTL/Hop Limit=64、Flow ID=0），但显式 `0` 必须保留，不能用“空值即默认”覆盖 VSID=0、FlowID=0、TTL/Hop Limit=0 等边界。VSID 是合法 24-bit 值，VSID=0 不应因数值为零而被当成缺失；只有未提供字段才使用默认值。重复 VSID 只有在 Flow ID 或 inner flow 明确不同且 fixture 声明允许时才合法。

## 6. 多 VSID、多 Flow、分段与生命周期

单个 outer flow 可携带多个声明的 NVGRE packet，但每个 packet 的 Key 必须保持其 VSID/Flow ID，inner frame 不得串包。至少两个 VSID 和两个 Flow ID 的 fixture 必须验证：

- 相同 VSID、不同 Flow ID 的 Key 仅低 8 位不同；
- 不同 VSID、相同 Flow ID 的 Key 高 24 位不同；
- 多 VSID 的 inner MAC/IP/payload 关联不会交叉；
- 组合顺序由 fixture 声明，不能依赖并行 worker（工作进程）的偶然调度。

当 inner payload 或整个封装帧跨底层 MTU 时，IP 分片/重组属于底层 IP 行为；NVGRE 本身不产生 TCP 握手，也不把底层分片边界当作 Ethernet frame 边界。若输出为 PCAP，每个 NVGRE datagram 必须可独立解析；若通过 NIC（网卡）输出，捕获端可因 offload（卸载）出现校验和差异，但 GRE flags、protocol、Key 和 inner Ethernet 字节必须可观察。

建议生命周期为：

```text
配置校验 → outer IP/GRE 构造 → Key(VSID/FlowID) → inner Ethernet → 输出
                                              ↘ 下一声明 frame
```

不存在 tunnel open/close 状态。配置错误、载体错误、线格式错误、VSID/Flow ID 越界、inner family 不匹配必须由 planner/validator 失败并传播为 task error；不得产生 completed/0 packet 或只含 outer IP 的假成功。

## 7. 边界和错误处理

至少覆盖以下边界：VSID=0、VSID=1、VSID=`0xffffff`；Flow ID=0、1、`0xff`；inner payload 为空、最小 Ethernet frame、最大明确支持 payload；VLAN VID=0 和 4095；outer TTL/Hop Limit=0/1/255；inner IPv4/IPv6；Key 字节序；多 VSID 和多 Flow；外层 IPv4/IPv6 与内层 IPv4/IPv6 四种组合；IP 分片/重组；显式关闭任务。

以下必须拒绝并传播 task error：

1. 非 IP protocol 47、非 GRE carrier、UDP/TCP/裸 IP 伪装 NVGRE；
2. GRE protocol 非 `0x6558`；K 位缺失，C/R/S/s/reserved/version 非法；
3. Key 缺失、长度不足、主机字节序或 Key 解析溢出；
4. VSID 大于 `0xffffff`、Flow ID 大于 `0xff` 或不完整 Key；
5. inner Ethernet 截断、MAC 长度错误、VLAN TCI/VID 越界；
6. inner EtherType 与 inner IP version 不匹配，inner IP/length/checksum 不一致；
7. outer/inner 地址或协议字段互换、IPv4/IPv6 头长度与偏移不一致；
8. 多 VSID/Flow 的引用串用、未声明的跨 VSID 广播或隐式复制；
9. 负 payload/长度回绕、超出 frame_max 或按不受限长度分配内存。

合法的 VSID=0、Flow ID=0、空 inner payload、广播/组播 MAC（显式配置）、TTL=0 的单个不转发数据包、不同 VSID 的独立 frame 和 PCAP/NIC 捕获中的 checksum offload 不应被误报为 planner error；只有配置、封装或长度/关联错误进入负例。

## 8. 实现集成和完成定义

实现时应：

1. 在 layer registry（层注册表）登记 `nvgre` 为 GRE terminal layer，并支持 outer `ip` 或 `ipv6`；
2. 在配置转换器增加 outer、VSID、Flow ID、inner Ethernet/VLAN 和 wire fault 配置，保留显式 binary（二进制）payload；
3. 新增 NVGRE planner/generator，严格写入 `FlagsAndVersion=0x2000`、`ProtocolType=0x6558` 和 32-bit Key；
4. 复用 outer IPv4/IPv6 builder，但不能复用普通 GRE 的无 Key 语义；
5. 在 PCAP/NIC 测试中按 outer family 和真实头长定位 GRE/Key/inner Ethernet，使用 tshark（抓包解析器）字段与 raw frames（原始帧）双重断言；
6. 先做 Key/flags/VSID/FlowID/inner frame 逐字节单测，再做 planner→worker→PCAP/NIC 全链路测试和 `-race`（竞态检测）；
7. 注册前禁止把 20 个语义正负例加入可执行 suite，只有 `unknown layer` 占位可运行。

完成定义：注册 `[ip|ipv6]→gre→nvgre` 层链；可生成合规 GRE/NVGRE 头、Key、inner Ethernet/VLAN、IPv4/IPv6 frame；outer/inner 地址族、VSID/Flow ID、多 VSID、多 flow、边界、IP 分片/重组和错误传播均可观察；20 个语义 ID 的正负断言和 PCAP/NIC 证据完成。

## 9. 原子 ID 与三方一致性

设计、testcase 和未来 JSON 必须按以下同一顺序使用 20 个唯一语义 ID：14 个正例、6 个负例。当前 JSON 只放额外的 `nvgre_neg_unregistered` 前置占位，不计入 20 个语义 ID。

| # | ID | 类型 | 覆盖 |
|---:|---|---|---|
| 1 | `nvgre_basic_ipv4_inner_ipv4` | 正 | outer IPv4 + GRE + inner Ethernet/IPv4 |
| 2 | `nvgre_outer_ipv6_inner_ipv4` | 正 | outer IPv6 + GRE + inner IPv4，Next Header=47 |
| 3 | `nvgre_outer_ipv4_inner_ipv6` | 正 | outer IPv4 + GRE + inner IPv6，EtherType=0x86dd |
| 4 | `nvgre_basic_ipv6_inner_ipv6` | 正 | outer/inner IPv6 独立 fixture |
| 5 | `nvgre_vsid_zero_flow_zero` | 正 | VSID=0、Flow ID=0 显式保留 |
| 6 | `nvgre_vsid_max_flow_max` | 正 | VSID=0xffffff、Flow ID=0xff |
| 7 | `nvgre_multi_vsid` | 正 | 多 VSID，Key 高 24-bit 隔离 |
| 8 | `nvgre_multi_flow_same_vsid` | 正 | 同 VSID 多 Flow ID，低 8-bit 隔离 |
| 9 | `nvgre_inner_vlan` | 正 | 内层 802.1Q VLAN、VID/TCI/EtherType |
| 10 | `nvgre_inner_ethernet_boundary` | 正 | MAC、空/最小 payload、Ethernet 边界 |
| 11 | `nvgre_outer_inner_family_matrix` | 正 | outer/inner IPv4/IPv6 四组合独立 fixture |
| 12 | `nvgre_mtu_reassembly` | 正 | 大 inner frame 分段后完整重组 |
| 13 | `nvgre_pcap_nic_consistency` | 正 | PCAP 与 NIC capture（网卡捕获）Key/inner 字节一致 |
| 14 | `nvgre_key_endian_and_ttl` | 正 | Key 网络字节序、TTL/Hop Limit 边界 |
| 15 | `nvgre_neg_gre_flags_protocol` | 负 | K/保留 flags、version、protocol 0x6558 错误 |
| 16 | `nvgre_neg_key_vsid_flow` | 负 | Key 缺失、VSID/Flow ID 越界或字节序错误 |
| 17 | `nvgre_neg_inner_ethernet_vlan` | 负 | inner Ethernet/MAC/VLAN/截断错误 |
| 18 | `nvgre_neg_address_family` | 负 | outer/inner IP family、EtherType 或 protocol mismatch |
| 19 | `nvgre_neg_carrier_length` | 负 | 非 GRE carrier、长度回绕或 frame 截断 |
| 20 | `nvgre_neg_vsid_flow_isolation` | 负 | 多 VSID/Flow 状态串用、未声明复制 |

## 10. 修订记录

- v1.0.0（2026-08-20）：建立 RFC 7637 NVGRE over GRE 设计契约，覆盖 GRE protocol 0x6558、K/Key、24-bit VSID、8-bit Flow ID、inner Ethernet/VLAN、outer/inner IPv4/IPv6、多 VSID、多 Flow、边界、IP 分片/重组、PCAP/NIC 和 20 个语义 ID；当前仅提交设计与用例契约，不修改 Go 实现。

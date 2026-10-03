# GENEVE 设计契约（文档轨）

> 版本：v1.2.0（2026-10-01）  
> 范围：D1–D8；本次只改设计、测试契约和 cases，不改 Go。  
> 规范：RFC 8926 §§3–5；RFC 768；RFC 791；RFC 8200。  
> 机器契约：`trafficgen/test/protocol_pcap/cases/geneve.json`。

## D1 现状、范围与边界

GENEVE 是 UDP/6081 承载的封装：outer IPv4/IPv6、8-byte base header、可选 options 和 inner Ethernet frame。本版覆盖 outer/inner 四种地址族组合、VNI 边界、OAM/Critical flags、options、inner VLAN、多 VNI、多 flow、空 payload 和 IPv6 UDP checksum。

仓库已有 GENEVE 终结层生成器/validator（`trafficgen/internal/protocol/geneve/layer_gen.go:62-401`）、核心配置类型（`trafficgen/internal/core/encapsulation.go:236-283`）和 `[ip,udp,geneve]` 注册（`trafficgen/internal/core/layers/registry.go:1731-1739`）。但 registry 的 `geneve` 没有 Fields，`ChainPlanner.translateTerminalConfig` 没有 `geneve` 分支；严格层链里的配置因此不能可靠回填 `spec.Geneve`，这是当前阻塞缺口，不宣称 cases 已通过。

不覆盖控制面、端点发现、MAC 学习、加密、GENEVE over TCP/QUIC、VXLAN-GPE、厂商 option 语义或 NIC offload 的非 wire 结果。

## D2 严格层链与配置权威

顶层只允许 `layers`、`flow_control`、策略/任务框架字段和 `output`。outer 地址和端口必须住层内，GENEVE 业务字段也必须住 `geneve` 层；inner 地址属于 `geneve.inner`：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "198.51.100.20"}},
    {"udp": {"src_port": 42000, "dst_port": 6081}},
    {"geneve": {"vni": 5000, "protocol_type": "ethernet", "options": [],
      "inner": {"src_mac": "02:00:00:00:20:01", "dst_mac": "02:00:00:00:20:02",
        "ether_type": "ipv4", "src_ip": "10.20.0.1", "dst_ip": "10.20.0.2",
        "payload_b64": "AQIDBA=="}}}
  ]
}
```

20/20 cases 已移除顶层 `src_ip`、`dst_ip`、`src_port`、`dst_port`、`count`，并将 outer 值迁入 `ip`/`udp` 层。不得恢复旧扁平形。当前层配置仍因 D8 缺口不能完成生产翻译。

## D3 规范字段与线布局

| 相对偏移 | 宽度 | 字段 | 约束/代码证据 |
|---:|---:|---|---|
| 0 | 1 | Ver(2)+Opt Len(6) | version=0；options 总字节/4，0–63；`layer_gen.go:216-232` |
| 1 | 1 | OAM/Critical/Reserved | bit7/bit6 可置位，低 6 bits 为零 |
| 2 | 2 | Protocol Type | Ethernet `0x6558` |
| 4 | 3 | VNI | 24-bit big-endian，0–`0xffffff`；`layer_gen.go:320-325` |
| 7 | 1 | Reserved | `00` |

无 options 时，IPv4 outer 的 base/inner offset 为 42/50，IPv6 outer 为 62/70；options 每增加 4 bytes，inner offset 增加 4，base offset 不变。

## D4 Options、inner 与载体

Option 为 `Class(2)|Type(1)|Reserved(3)+Length(5)|Data(Length*4)`，按输入顺序编码。data 必须 4-byte 对齐、reserved 必须为零、单 option 长度不超过 31 units、总 options 不超过 63 units；校验在 `layer_gen.go:328-350`。`protocol_type=0x6558` 时 inner 必须是完整 Ethernet fixture；空 payload 仍保留 Ethernet/IP 头。UDP destination 固定 6081；IPv6 UDP checksum 必须非零且正确。

## D5 状态、数量、多报文与动态

GENEVE 无 TCP handshake、MSS 协商或 termination。`datagrams[]` 表示有序的独立数据报；每项可独立 VNI、options、inner、方向和源端口，生成器逐项产生一个 event（`layer_gen.go:79-115`）。多 flow 不以静态复制充数：当前实现只消费显式 `datagrams[].src_port`，未实现层链动态对象，因此动态四元组和业务字段均为缺口；不得把 `src_port` 保底递增写成 GENEVE 已支持能力。数量应走 `flow_control`，不是顶层 `count`。

D5 覆盖矩阵：

| 维度 | 已覆盖 cases | 缺口 |
|---|---|---|
| outer IPv4/IPv6 × inner IPv4/IPv6 | `geneve_ipv4_outer_*`、`geneve_ipv6_outer_*` | 翻译接线后复跑 |
| VNI 0/最大值 | `geneve_vni_boundary` | 无 |
| flags 全零/OAM/Critical | `geneve_version_flags` | 无 |
| options 空/单/多 | `geneve_options_single`、`geneve_options_multiple` | 无 |
| 单报文/多 VNI/多 flow | `geneve_*_multi_*` | flow_control 语义待接线 |
| 动态 fixed/inc/rand/list/pattern | 无 | G-GENEVE-7 |

## D6 错误处理与不适用项

必须在输出前拒绝：version/保留位非法、VNI 越界、option 对齐或长度不一致、非 TEB protocol、inner 截断、非 UDP/6081，以及 checksum 故障。现有生成器的 wire-fault 锚词实现于 `layer_gen.go:362-401`；层翻译缺口修复后，错误必须沿 task error 返回，不得 completed/0 packet 或只输出 outer UDP。负例不得被未知层拒绝冒充 GENEVE 错误通过。

## D7 性能、输出与验收

目标路径应逐 datagram 流式生成，不聚合全部 inner frames，使用仓库有界队列/缓冲。当前没有 GENEVE 专项基准，吞吐、并发会话/流、单 datagram 最大报文、内存、CPU、队列上限和 NIC 丢包预算均待确认，不写承诺数字。验收分两路：PCAP 用 tshark/raw frame 校验字段、offset、长度和 checksum；授权 NIC 使用 `udp port 6081`，以 wire bytes 为准并记录 checksum offload 边界。性能测试待实现后覆盖基线、目标规模、压力上限、长跑、并发交错、背压六项。

## D8 实现接口、缺口与回滚

实现阶段需：

1. 为 registry `geneve` 补 Fields/默认值（至少 `vni`、flags、protocol/options/inner 的层配置形状）；
2. 在 `translateTerminalConfig` 增加严格 JSON 往返 + `DisallowUnknownFields`，将 `term.Config` 写入 `spec.Geneve`，并传播解码错误；
3. 补动态字段契约与 `flow_control` 的多 flow 语义；
4. 用本文件 20 个 cases 跑真实 MCP→引擎→PCAP→tshark，再做 NIC 验收。

回滚只撤销上述实现提交，保留严格层链 cases 和本契约。现状缺口：

| 编号 | 现象 | 分类 | 计划 |
|---|---|---|---|
| G-GENEVE-1 | 层已注册但 Fields 为空，层配置无机器字段契约 | 代码 | 补 registry Fields |
| G-GENEVE-2 | `translateTerminalConfig` 缺 geneve 分支 | 代码 | 补严格层→`spec.Geneve` 翻译 |
| G-GENEVE-3 | 20 例尚未真实 suite 全量运行 | 测试 | 接线后全量 PCAP，负例验 task error |
| G-GENEVE-4 | NIC/checksum offload 无证据 | 测试 | 授权接口抓包复验 |
| G-GENEVE-5 | RFC 之外的商业行为未取证 | 待确认 | 取授权设备文档/抓包后再写结论 |
| G-GENEVE-6 | 性能六项无基准 | 性能 | 实现后测量并回填 |
| G-GENEVE-7 | fixed/inc/rand/list/pattern 动态格未实现/未覆盖 | 代码+测试 | 先定字段消费与序号算法，再补整格 cases |

## 20 个语义 ID

正例 14 个：`geneve_ipv4_outer_ipv4_inner`、`geneve_ipv4_outer_ipv6_inner`、`geneve_ipv6_outer_ipv4_inner`、`geneve_ipv6_outer_ipv6_inner`、`geneve_vni_boundary`、`geneve_version_flags`、`geneve_options_single`、`geneve_options_multiple`、`geneve_multi_vni`、`geneve_multi_flow`、`geneve_inner_vlan_ethernet`、`geneve_empty_inner_payload`、`geneve_mss_not_applicable`、`geneve_pcap_nic_consistency`。

负例 6 个：`geneve_neg_header_truncated`、`geneve_neg_reserved_version_flags`、`geneve_neg_option_length`、`geneve_neg_vni_protocol`、`geneve_neg_udp_carrier_inner`、`geneve_neg_checksum`。

本版自审：两轮。第一轮逐项核对 D1–D8、严格层链、代码现状和 G 缺口；第二轮逐项对照 20 个 ID、D/T/C 结论和未运行边界，末轮干净。

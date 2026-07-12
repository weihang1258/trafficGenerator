# IPv6 迁移指南

> 日期: 2026-07-10 | 状态: 规划阶段

---

## 概述

当前引擎仅支持 IPv4。本指南列出将 IPv6 全链路接入所需的具体改动。

### 涉及的文件

| 文件 | 改动 | 工作量 |
|------|------|--------|
| `internal/core/builder.go` | ⬆️ 大 — 新增 IPv6 头部构建 | 2-3 天 |
| `internal/core/buffer.go` | ⬇️ 小 — 校验和函数提取 | 0.5 天 |
| `internal/protocol/tcp/tcp.go` | ⬇️ 小 — 校验和适配 | 0.5 天 |
| `internal/protocol/udp/udp.go` | ⬇️ 小 — 校验和适配 | 0.5 天 |
| `internal/protocol/icmp/icmp.go` | ⬆️ 中 — 新增 ICMPv6 支持 | 1 天 |
| `internal/protocol/dns/dns.go` | ⬇️ 小 — AAAA 查询类型 | 0.5 天 |
| `internal/protocol/http/http.go` | ⬇️ 小 — 校验和适配 | 0.5 天 |
| `internal/output/pcap.go` | ⬇️ 小 — 链接类型支持 | 0.5 天 |
| `internal/core/types.go` | ⬇️ 小 — L3Config 扩展 | 0.5 天 |
| `trafficgen/web/src/` | ⬆️ 中 — IP 输入区分 v4/v6 | 1 天 |
| `trafficgen/web/src/api/index.ts` | ⬇️ 小 — IP 类型定义 | 0.5 天 |

---

## 1. L3 头部构建 (`builder.go`)

### 当前问题

```go
// builder.go:104-170 — buildL3() 只有 IPv4 逻辑
func (b *Builder) buildL3(config PacketConfig, payloadLen int) []byte {
    header := make([]byte, 20)
    header[0] = 0x45              // 硬编码 IPv4, IHL=5
    header[147] = srcIP.To4()     // To4() 使 IPv6 地址变为 nil
    // ...
}
```

### 方案

```go
// 新增: buildIPv6() 方法
func (b *Builder) buildIPv6(config PacketConfig, payloadLen int) ([]byte, error) {
    // IPv6 头部 = 40 字节固定部分 + 扩展头（可选）
    header := make([]byte, 40)

    // Version (4) + Traffic Class (8) + Flow Label (20)
    // header[0:4] = version(4) + traffic_class(8) + flow_label(20)

    // Payload Length
    binary.BigEndian.PutUint16(header[4:6], uint16(payloadLen))

    // Next Header (协议类型: TCP=6, UDP=17, ICMPv6=58)
    header[6] = config.L3.Protocol

    // Hop Limit (TTL 在 IPv6 中叫 Hop Limit)
    header[7] = config.L3.TTL

    // Source Address (16 字节)
    srcIP := net.ParseIP(config.L3.SrcIP)
    if srcIP != nil {
        copy(header[8:24], srcIP.To16())
    }

    // Destination Address (16 字节)
    dstIP := net.ParseIP(config.L3.DstIP)
    if dstIP != nil {
        copy(header[24:40], dstIP.To16())
    }

    return header, nil
}

// 修改: buildL3() 根据 IP 版本分发
func (b *Builder) buildL3(config PacketConfig, payloadLen int) ([]byte, error) {
    srcIP := net.ParseIP(config.L3.SrcIP)
    if srcIP != nil && srcIP.To16() != nil && strings.Contains(srcIP.String(), ":") {
        return b.buildIPv6(config, payloadLen)
    }
    // 原有 IPv4 逻辑保持不变
    return b.buildIPv4(config, payloadLen), nil
}
```

### IPv6 校验和差异

| 项目 | IPv4 | IPv6 |
|------|------|------|
| 伪头部源地址 | 4 字节 | 16 字节 |
| 伪头部目的地址 | 4 字节 | 16 字节 |
| 伪头部协议字段 | 存在 | 不存在（Next Header 在固定头中） |
| 伪头部长度字段 | 不存在 | 存在（Payload Length） |
| TCP/UDP 校验和 | 可选（通常为 0） | **必须**（RFC 2460 要求） |

---

## 2. 校验和函数重构 (`buffer.go`)

### 当前问题

`calculateTCPChecksum` 和 `calculateUDPChecksum` 中，伪头部构建代码重复，且硬编码 4 字节 IP 地址：

```go
// buffer.go:270-296 — 硬编码 4 字节地址
pseudoHeader[0:4] = srcIP.To4()     // ❌ IPv6 会变 nil
pseudoHeader[4:8] = dstIP.To4()     // ❌ IPv6 会变 nil
pseudoHeader[8] = 0
pseudoHeader[9] = 6                   // TCP 协议号
```

### 方案

```go
// 提取公共伪头部构建函数
type pseudoHeader struct {
    srcIP    net.IP
    dstIP    net.IP
    protocol uint8
    length   uint16
}

func buildPseudoHeader(ph pseudoHeader) []byte {
    src := ph.srcIP.To16()
    dst := ph.dstIP.To16()

    // 判断 IP 版本
    if isIPv6(ph.srcIP) {
        // IPv6 伪头部: 40 字节
        // 0-15:  源地址 (16 字节)
        // 16-31: 目的地址 (16 字节)
        // 32-33: 上层数据包长度
        // 34:   下一个头部
        // 35-39: 保留 (0)
        header := make([]byte, 40)
        copy(header[0:16], src)
        copy(header[16:32], dst)
        binary.BigEndian.PutUint16(header[32:34], ph.length)
        header[34] = ph.protocol
        return header
    }

    // IPv4 伪头部: 12 字节 (原有逻辑)
    header := make([]byte, 12)
    copy(header[0:4], ph.srcIP.To4())
    copy(header[4:8], ph.dstIP.To4())
    header[8] = 0
    header[9] = ph.protocol
    binary.BigEndian.PutUint16(header[10:12], ph.length)
    return header
}
```

---

## 3. 协议层改动

### 3.1 TCP (`protocol/tcp/tcp.go`)

```go
// 校验和调用改为版本感知
checksum := calculateTCPChecksum(pseudoHeader{
    srcIP:    net.ParseIP(config.L3.SrcIP),
    dstIP:    net.ParseIP(config.L3.DstIP),
    protocol: 6,
    length:   uint16(len(header) + len(payload)),
})
```

### 3.2 UDP (`protocol/udp/udp.go`)

同 TCP 改动，protocol 改为 17。

### 3.3 ICMP — 新增 ICMPv6 支持

```go
// 新增 ICMPv6 类型
const (
    TypeICMPv6EchoRequest  = 128
    TypeICMPv6EchoReply    = 129
)

// 新增: buildICMPv6Payload() 函数
// 校验和计算方式不同:
//   - ICMPv4: 校验和只覆盖 ICMP 头部 + 数据
//   - ICMPv6: 校验和覆盖 ICMPv6 头部 + 数据 + 伪头部 (类似 TCP/UDP)
```

### 3.4 DNS — 新增 AAAA 记录支持

```go
// 已有 dns.query_type = 28 (AAAA)，前端需支持选择
// DNS planner 生成响应时:
//   - A 查询 → 响应 IP 地址 (IPv4)
//   - AAAA 查询 → 响应 IPv6 地址
```

### 3.5 HTTP — 校验和适配

HTTP 在 TCP 之上，TCP 校验和已适配 IPv6 则 HTTP 自动受益。

---

## 4. L3Config 类型扩展 (`types.go`)

```go
// 当前
type L3Config struct {
    SrcIP    string
    DstIP    string
    Protocol uint8
    TTL      uint8
    IPID     uint16
}

// 改为
type L3Config struct {
    SrcIP    string
    DstIP    string
    Protocol uint8
    TTL      uint8
    IPID     uint16
    // IPv6 扩展头 (可选)
    ExtensionHeaders []ExtensionHeader
    // 分片相关 (可选)
    Flags      uint8   // DF=2, MF=1
    FragOffset uint16
}

type ExtensionHeader struct {
    Type     uint8  // 0=逐跳选项, 43=路由, 60=目标选项, 51=认证, 50=ESP
    Data     []byte
}
```

---

## 5. 输出层改动 (`pcap.go`)

### PCAP 链接类型

```go
// 当前: 硬编码 Ethernet (DLT_EN10MB = 1)
pcapLinkType = 1

// IPv6 场景: 保持 Ethernet 链接类型
// (IPv6 包也是封装在以太网帧中的，pcap 文件格式不变)
// 只需确保 IPv6 地址正确生成，pcap 文件本身兼容
```

**结论**：PCAPWriter 不需要改。IPv6 包也是以太网帧，pcap 的 Ethernet link type 不变。

### 时间戳精度

当前 PCAPWriter 使用微秒精度（除以 1000 丢弃纳秒部分）。这是 pcap v2.4 格式的限制，不需要改。

---

## 6. 前端改动

### 6.1 IP 输入组件

```typescript
// 新增: IPv6 地址验证
const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/

// 策略配置表单中:
// 源IP / 目的IP 输入框增加 placeholder 提示
// "输入 IPv4 (如 192.168.1.1) 或 IPv6 (如 2001:db8::1)"
```

### 6.2 IP 类型自动推断

```typescript
// 根据 IP 格式自动切换显示的配置参数
const isIPv6 = (ip: string) => ip.includes(':')

// 基础模式:
//   IPv4 → 显示 TOS、DF 位
//   IPv6 → 显示 Traffic Class、Hop Limit

// 专家模式:
//   IPv4 → 显示 IP 选项、分片
//   IPv6 → 显示 Flow Label、扩展头
```

### 6.3 校验规则

```typescript
// IP 输入框校验
const validateIP = (ip: string) => {
  if (ip.includes(':')) {
    // IPv6 校验
    return net.isIPv6(ip) ? '' : '请输入有效的 IPv6 地址'
  }
  // IPv4 校验
  return net.isIPv4(ip) ? '' : '请输入有效的 IPv4 地址'
}
```

---

## 7. 验证计划

### 单元测试

| 测试 | 说明 |
|------|------|
| `buildIPv4()` 现有测试 | 不变，确保不破坏 |
| `buildIPv6()` 新增 | 验证 IPv6 头部 40 字节、地址、TTL、Next Header |
| `calculateTCPChecksum()` IPv6 | 验证 16 字节地址的伪头部和校验和 |
| `calculateUDPChecksum()` IPv6 | 同上 |
| `buildICMPv6Payload()` | 验证 ICMPv6 头部 + 校验和 |
| DNS AAAA 响应 | 验证 AAAA 查询的正确响应包 |

### 集成测试

| 场景 | 验证 |
|------|------|
| TCP over IPv4 | 确保现有功能不变 |
| TCP over IPv6 | 验证三次握手 + 数据 + 挥手完整序列 |
| UDP over IPv6 | 验证 DNS AAAA 查询响应 |
| ICMPv6 Echo | 验证请求/响应 |
| PCAP 文件 | 验证 IPv6 包正确写入 pcap 文件 |
| Wireshark 验证 | 所有生成的包在 Wireshark 中正确解码 |

---

## 8. 实施顺序建议

```
Day 1-2: 重构校验和函数（提取公共 pseudo-header 构建）
  └─ 同时支持 IPv4 和 IPv6 伪头部

Day 3-4: 新增 buildIPv6() + 修改 buildL3() 分发逻辑
  └─ TCP 校验和适配

Day 5: 协议层适配
  └─ UDP / ICMPv6 / DNS AAAA

Day 6: 前端 IP 输入适配
  └─ IPv6 验证 / placeholder / 动态参数显示

Day 7: 集成测试 + Wireshark 验证
  └─ 生成 TCP/UDP/ICMP over IPv6 包，Wireshark 解码验证
```

---

## 9. 不在此次迁移范围的内容

以下 IPv6 相关功能**本次不做**，后续再议：

| 功能 | 原因 |
|------|------|
| **IPv6 扩展头**（逐跳选项/路由/ESP） | 高级特性，使用率低，预留 ExtensionHeader 结构体 |
| **ICMPv6 邻居发现**（NDP/RS/RA/NS/NA） | 替代 ARP 的功能，后续按需添加 |
| **IPv6 自动配置**（SLAAC/DHCPv6） | 不适用于流量生成器 |
| **MPLS over IPv6** | 运营商特性，太超前 |
| **IPv6 地址生成策略**（EUI-64/临时地址） | 后续在 Schema 层补充策略类型 |

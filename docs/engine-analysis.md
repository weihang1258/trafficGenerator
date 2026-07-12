# FlowB 引擎深度分析报告

> 日期: 2026-07-10 | 状态: 分析阶段

---

## 目录

1. [当前架构全景](#1-当前架构全景)
2. [数据流转全流程](#2-数据流转全流程)
3. [各层缺失分析](#3-各层缺失分析)
4. [引擎优化点](#4-引擎优化点)
5. [可扩展性评估](#5-可扩展性评估)
6. [易用性分析](#6-易用性分析)
7. [功能覆盖性检查](#7-功能覆盖性检查)
8. [修复优先级建议](#8-修复优先级建议)

---

## 1. 当前架构全景

### 三级流水线

```
 REST API (HTTP)
    │
    ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ ConfigWorker │────▶│ PacketWorker │────▶│ OutputWorker│
│   × 4 个     │     │   × 8 个    │     │   × 1 个    │
│ 配置生成器   │     │  包构建器   │     │  输出写入器  │
└─────────────┘     └─────────────┘     └─────────────┘
     │                   │                   │
     ▼                   ▼                   ▼
 读取策略             构建二进制包           PCAP 文件
 调用 Planner        计算校验和             网卡注入
 生成 PacketConfig    应用限速             存储到 RingBuffer
```

### 关键数据结构链

```
Strategy (DB)
  │
  ▼  StrategyModelToTask()  ──── 硬编码字段映射
FlowSpec
  │
  ▼  ProtocolPlanner.Plan()   ──── 协议特定的包序列生成
PacketConfig (channel)
  │
  ▼  Builder.Build()           ──── 自底向上: L4→L3→L2
[]byte (以太帧)
  │
  ▼  OutputWorker.writePacket()
  ├─▶ PacketWriter.WritePackets()  (PCAP / 网卡)
  └─▶ RingBuffer.Put()             (API 检索)
```

### 当前支持的协议

| 协议 | 包序列 | 状态 |
|------|--------|------|
| **TCP** | SYN→SYN-ACK→ACK→[数据+ACK×N]→FIN→ACK×3 | ✅ 可用 |
| **UDP** | 请求包 + 可选响应包 | ✅ 可用 |
| **HTTP** | TCP握手→HTTP请求/响应×N→TCP关闭 | ✅ 可用 |
| **DNS** | 查询→可选响应 | ✅ 可用 |
| **ICMP** | Echo请求→Echo响应 | ✅ 可用 |
| **ARP** | 请求/响应 | ✅ 可用 |
| **混合流量** | 多协议按比例并行，BPS 分配 | 🔄 P0.5 待实现 |

---

## 2. 数据流转全流程

### Step 1: REST API → 引擎

```
用户点击"启动任务"
  │
  ▼
POST /api/v1/tasks/{id}/start
  │
  ▼
TaskHandler.Start()
  ├─ 加载 TaskModel + StrategyModel 从数据库
  ├─ 调用 StrategyModelToTask() 逐个策略转换
  │   └─ 硬编码字段提取: cfg["src_ip"], cfg["tcp"].(map)["mss"] 等
  ├─ 解析 output_config → 创建 PCAPWriter 或 InterfaceWriter
  ├─ 调用 engine.SubmitTask() 提交每个策略子任务
  │   └─ 生成复合 ID: "{taskID}-{strategyID}"
  └─ 更新 DB 状态为 running，预留端口
```

### Step 2: ConfigWorker → 包配置生成

```
ConfigWorker 从 taskChan 读取 Task
  │
  ▼
调用 planner.Plan(ctx, task.Spec)
  │
  ▼
Planner 按协议逻辑生成包序列
  ├─ TCP: 握手包 → [数据段 + ACK] × N → 挥手包
  ├─ HTTP: TCP握手 → [HTTP请求+响应]×N → TCP关闭
  └─ ...
  │
  ▼
每个包生成一个 PacketConfig
  ├─ 填充 L2: src/dst MAC, EtherType, VLAN
  ├─ 填充 L3: src/dst IP, Protocol, TTL, IPID
  ├─ 填充 L4: src/dst port, seq, ack, flags
  └─ Payload: 用户数据或协议内嵌数据
  │
  ▼
configChan ← PacketConfig (逐个发送)
```

### Step 3: PacketWorker → 二进制包构建

```
PacketWorker 从 configChan 读取 PacketConfig
  │
  ▼
TokenBucket.Wait() — 限速等待
  │
  ▼
Builder.Build(config) — 自底向上构建
  ├─ buildL4() → TCP/UDP/ICMP 头部
  ├─ buildL3() → IPv4 头部 (含校验和)
  ├─ buildL2() → 以太网头部 (含 VLAN)
  └─ 拼接: L2 + L3 + L4 + Payload
  │
  ▼
packetChan ← PacketOutput{Data: []byte, Metadata: {...}}
```

### Step 4: OutputWorker → 写入输出

```
OutputWorker 从 packetChan 读取 PacketOutput
  │
  ▼
writePacket():
  ├─ 查找 outputWriters[task_id]
  ├─ writer.WritePackets([packet])
  │   ├─ PCAPWriter → 写入文件 (含 pcap 头部 + 时间戳 + 数据)
  │   └─ InterfaceWriter → pcap.OpenLive → 网卡注入
  └─ buffer.Put(packet, "combined") → RingBuffer
```

---

## 3. 各层缺失分析

### 3.1 L2 (数据链路层) — 缺失

| 当前支持 | 缺失 | 影响 |
|---------|------|------|
| src/dst MAC | **802.1ad (Q-in-Q)** | 运营商级 VLAN 标记无法模拟 |
| EtherType 自动 | **Preamble / SFD** | 不是必须的（gopacket/pcap 处理） |
| 802.1Q VLAN | **EtherType 自定义** | 无法模拟非 IPv4 载荷 |
| — | **FCS (Frame Check Sequence)** | pcap 格式通常包含，但当前不生成 |
| — | **MPLS 标签** | 运营商/广域网场景不可用 |
| — | **VLAN 优先级 (PCP/DEI)** | 只有 priority 字段，没有 DEI 位 |

### 3.2 L3 (网络层) — 缺失最多

| 当前支持 | 缺失 | 影响 |
|---------|------|------|
| src/dst IP (IPv4) | **IPv6 完全缺失** | `To4()` 调用使 IPv6 地址全部无效 |
| TTL | **IP 标识符独立控制** | 目前用 Seq 的低 16 位代替，不可控 |
| TOS (1 字节) | **DSCP / ECN 独立控制** | 合在 TOS 一个字节里，用户无法单独设 DSCP |
| IHL 固定为 5 | **IP 选项字段** | 无法添加 record route, timestamp, security 等选项 |
| Flags 固定为 DF | **MF 位 / 分片偏移** | 无法构造分片包 |
| Protocol 字段 | **IPv6 扩展头** | 不适用（没有 IPv6） |
| 自动校验和 | **IPv6 无校验和** | 需要不同的构建逻辑 |

**IPv6 改造点**（硬编码在 builder.go 中）:
- `buildL3()` 只有 IPv4 逻辑（`header[0] = 0x45`, `To4()`）
- 需要新的 `buildIPv6()` 方法
- 伪头部校验和需要 16 字节 IPv6 地址
- PCAPWriter 的 link type 需要从 Ethernet(1) 改为支持 IPv6 的其他类型

### 3.3 L4 (传输层) — 缺失

| 当前支持 | 缺失 | 影响 |
|---------|------|------|
| src/dst port | **TCP 选项 (MSS/SACK/时间戳/WScale)** | 无法构造真实的 TCP 握手协商 |
| Seq/Ack | **紧急指针 (URG)** | URG 标志支持但 pointer 字段固定为 0 |
| Flags (SYN/ACK/FIN/PSH) | **TCP 数据偏移可变** | 固定为 5 (20 字节无选项) |
| Window Size | **SCTP 协议** | 多流传输不可用 |
| MSS (MSS 是 planner 概念) | **UDP 长度覆盖** | 自动计算，不可覆盖 |
| — | **ICMPv6** | 只有 ICMPv4 |
| — | **ICMP 类型扩展** | 只有 Echo 请求/响应 |

### 3.4 应用层 — 缺失

| 当前支持 | 缺失 | 影响 |
|---------|------|------|
| HTTP 方法/URI/Header/Body | **HTTP/2 支持** | 只能模拟 HTTP/1.1 |
| Keep-Alive | **TLS/SSL 握手** | 无法模拟 HTTPS 流量 |
| 多事务 | **HTTP 响应状态码** | 硬编码 200 OK |
| Think Time | **响应体内容自定义** | 响应体固定为 "OK" |

### 3.5 引擎内部 — 缺失

| 组件 | 问题 | 影响 |
|------|------|------|
| **策略转换** | `strategy_convert.go` 用 `getString(cfg, "tcp")` 扁平映射，不递归 | 嵌套的 TCP 配置结构体无法正确映射 |
| **IPv4/IPv6 判断** | 没有根据 IP 版本自动选择构建路径 | IPv6 任务会静默生成错误的 IPv4 包 |
| **包大小检查** | 没有 MTU 检查或分片逻辑 | 超 MTU 的包会直接发出 |
| **流级别统计** | 只有全局 packets/bytes | 无法按流统计每个 Flow 的包数/字节 |
| **任务超时** | 没有基于时间的自动停止 | 任务只能靠 count 耗尽或手动停止 |
| **优先级队列** | taskChan 是 FIFO | 大任务可能阻塞小任务 |

---

## 4. 引擎优化点

### 4.1 性能优化

| 优化 | 当前问题 | 改进方案 | 预期收益 |
|------|---------|---------|---------|
| **PCAP 写入去 Sync** | 每批包都 `file.Sync()` | 异步刷盘 / 批量 Sync | 吞吐量提升 5-10x |
| **包复制优化** | RingBuffer.Put() 每次都复制包数据 | 使用 `sync.Pool` 复用 buffer | 减少 GC 压力 |
| **通道容量** | configChan/packetChan = QueueSize×2 | 根据包大小动态调整 | 减少背压 |
| **统计采样** | 每个包都更新统计计数器 | 每 N 包采样一次 | 减少原子操作 |
| **多 OutputWorker** | 只有 1 个 OutputWorker | 支持多 worker + resequencing | 利用多核 |

### 4.2 代码结构优化

| 问题 | 建议 |
|------|------|
| Builder 是一个 struct 但全是方法，不需要实例 | 改为包级函数或单例 |
| `buildTCP` 中 checksum 重复计算 pseudo-header | 提取公共 pseudo-header 构建函数 |
| `calculateTCPChecksum` 和 `calculateUDPChecksum` 几乎相同 | 提取公共 checksum 函数 |
| ProtocolPlanner 在 core/worker.go 和 protocol/protocol.go 各一份 | 统一到 core 包，删除 protocol 包的 dead code |

---

## 5. 可扩展性评估

### 5.0 混合流量类型（已定义未接入，P0.5 必做）

`core/types.go` 中定义了 `BatchSpec`、`TrafficClass`、`TupleConfig`、`GlobalConfig`、`StrategyConfig` 五种类型，**目前在整个 `internal/` 目录中零引用**（grep 确认），但已决策为必做核心功能。

这些类型的用途是**批量/混合流量生成**：

```go
// 意图: 一次任务包含多个流量类别
type BatchSpec struct {
    Classes []TrafficClass  // 多个流量类
    Global  GlobalConfig    // 全局设置
}

type TrafficClass struct {
    ID             string                 // 类别标识
    Type           string                 // 协议类型
    BPS            string                 // 该类别的比特率
    FlowsPerSecond int                    // 每秒流数
    FlowCount      int                    // 总流数
    Tuples         TupleConfig            // 4元组生成策略
    Config         map[string]interface{} // 协议配置
}

type TupleConfig struct {
    SrcIP   StrategyConfig  // 源IP生成策略
    DstIP   StrategyConfig  // 目的IP生成策略
    SrcPort StrategyConfig  // 源端口生成策略
    DstPort StrategyConfig  // 目的端口生成策略
}
```

**影响**：
- 这些类型是**混合流量生成**（多种流量类别共享一个任务、按比例分配带宽）的数据结构基础
- 当前引擎只支持单策略单任务，不支持多流量类混合
- ✅ 已决策为 P0.5 必做功能，将在 Phase 1 后立即实施

**结论**：
- ✅ **已决策——必做（P0.5 优先级）**。混合流量是核心功能，需在 Phase 1 完成后立即实施。
- 这些类型作为实现基础，需接入引擎流水线：
  - `BatchSpec` → 任务级包装，包含多个 `TrafficClass`
  - `TrafficClass` → 单个流量类，含协议/BPS/4元组策略
  - `TupleConfig` → 4元组生成策略，确保每类流量不冲突
  - 每个 `TrafficClass` 独立分配 TokenBucket 限速

### 5.0.5 速率限制 — 两层未接线

引擎和 API 都有速率限制的代码骨架，但**两层都未生效**。

#### 第一层：引擎级 PacketWorker 限速（BPS）

```go
// engine.go:193 — 每个 PacketWorker 的 TokenBucket 被创建为 rate=0（不限速）
rateLimiter := NewTokenBucket(0, 65536)  // No rate limit by default
```

- `TokenBucket` 算法正确：`Allow()` 和 `Wait()` 实现无误
- 但 `rate=0` 时 `Allow()` 直接返回 `true`（无条件放行）— 等于不限速
- 引擎有 `SetClassRateLimit(classID, bps)` 方法（`engine.go:466-478`），但 `task_handler.Start()` **从未调用**
- 用户在策略中设置的 BPS（如 "200k"）只被解析为字符串存储在 `FlowSpec.BPS`，**从未传入 TokenBucket**

**根因链**：
```
用户设置 flow_control: {type: "bps", value: 200000}
  → strategy_convert.go 解析为 spec.BPS = "200k"
  → planner.Plan() 读取 spec.BPS 但只用于...
  → ❌ 没有任何代码调用 engine.SetClassRateLimit()
  → PacketWorker 的 TokenBucket.rate = 0 → 完全不限速
```

**修复方案**：在 `task_handler.Start()` 中，对每个 engine task 调用：
```go
bpsInt, _ := ParseBPS(spec.BPS)
engine.SetClassRateLimit(engineTaskID, bpsInt)
```
并在 `PacketWorker` 中使用对应 `classID` 的 `rateLimiter` 而非独立的。

#### 第二层：API 级速率限制

```go
// config.go:238-240 — RateLimitConfig 从配置文件加载
v.SetDefault("rate_limit.enabled", true)
v.SetDefault("rate_limit.requests_per_second", 100)
v.SetDefault("rate_limit.burst", 200)
```

- `RateLimitConfig` 结构体定义完整（`Enabled/RPS/Burst`）
- 配置值加载到 `ServerConfig.RateLimit`
- 但 `server.go` 的中间件链中**没有任何速率限制器**
- `response.go` 中定义了 `CodeRateLimitExceeded = 429` 也从未被使用

**总结**：两层限速都是"代码骨架在，没接线"。API 级相对简单（加一个 Gin 中间件），引擎级需要深入接线到 task 提交流程。

### 5.1 协议扩展

**当前注册方式**（main.go 硬编码）：
```go
app.engine.RegisterPlanner(tcp.NewPlanner())
app.engine.RegisterPlanner(udp.NewPlanner())
// ... 逐个手动注册
```

**问题**：
- `protocol.Registry` 定义了插件注册机制但完全未使用
- 每个协议的 `init()` 函数中 `protocol.Register()` 被注释掉
- 添加新协议需要改 main.go + 改 API handler + 改前端

**目标方案**：
```
协议包内部:
  func init() { protocol.Register(NewPlanner()) }  // 自动注册

main.go:
  app.engine.RegisterPlanner(protocol.Get("tcp"))     // 从 Registry 读取
  app.engine.RegisterPlanner(protocol.Get("udp"))     // 零改动添加
  // 新增协议只需放一个包，自动发现

API handler:
  // 从 engine.ListProtocols() 动态获取可用协议
  // 不再硬编码协议列表
```

### 5.2 Schema 驱动扩展

当前 `FlowSpec` 是一个静态 Go struct：
```go
type FlowSpec struct {
    SrcIP   string
    DstIP   string
    // ... 固定字段
    TCP  *TCPConfig
    UDP  *UDPConfig
}
```

**问题**：
- 添加新协议参数需要修改 struct
- `strategy_convert.go` 的映射代码要手动增加
- 前端不知道有哪些参数可用

**目标方案**：
```go
// 每个协议提供一个 Schema 定义
type ParameterSchema struct {
    Name        string
    Type        string    // "string", "number", "bool", "select", "ip", "mac"
    Default     interface{}
    Group       string    // "网络层", "传输层", "TCP高级"
    IsCommon    bool      // true = 基础模式显示, false = 专家模式
    Required    bool
    Validation  string    // "ipv4", "ipv6", "port", "range:0-255"
    Description string
}

// TCPPlanner 实现 SchemaProvider 接口
func (p *Planner) Schema() []ParameterSchema {
    return []ParameterSchema{
        {Name: "src_port", Type: "number", Default: 1234, Group: "传输层", IsCommon: true, ...},
        {Name: "mss", Type: "number", Default: 1460, Group: "TCP高级", IsCommon: false, ...},
        {Name: "window_size", Type: "number", Default: 65535, Group: "TCP高级", IsCommon: false, ...},
        // 前端根据这个自动生成表单
        // 基础模式: 只显示 IsCommon=true 的参数
        // 专家模式: 显示全部参数
    }
}
```

---

## 6. 易用性分析

### 6.1 当前痛点

| 痛点 | 场景 | 严重性 |
|------|------|--------|
| **SEQ 号硬编码** | TCP 流的 clientSeq 从 1000 开始，serverSeq 从 2000 开始。如果用户想模拟多个独立流，它们会共享同样的初始 SEQ | 中 |
| **无包大小预览** | 用户填完参数后不知道生成的包多大，可能超过 MTU | 中 |
| **无模板保存** | 用户每次创建策略要从头填，无法保存常用配置 | 高 |
| **参数名不直观** | 前端显示"值策略选择器"而不是"源 IP"，普通用户看不懂 | 中 |
| **无协议建议** | 用户选了 TCP 但端口填了 53，不会提醒这通常是 DNS 端口 | 低 |
| **IP 自动推断缺失** | 选了"网卡注入"输出后，应该自动填充源 MAC 和源 IP | 低 |

### 6.2 建议改进

| 改进 | 说明 |
|------|------|
| **智能默认值** | 根据协议自动设端口(HTTP→80, DNS→53, DHCP→67/68)、MSS(1460)、Window(65535) |
| **实时预览** | 参数配置时实时显示"你将生成: SYN → SYN-ACK → ACK → DATA(1460B) → FIN → ..." |
| **模板系统** | 常用配置保存为模板，一键加载 |
| **冲突检测** | 源/目端口相同提醒、IP 版本冲突提醒、VLAN 范围提醒 |
| **校验增强** | 端口范围 1-65535、VLAN ID 1-4094、MSS 536-65535 |

---

## 7. 功能覆盖性检查

### 7.1 与行业标准流量工具对比

| 功能 | FlowB 当前 | hping3 | Scapy | Ostinato | 评估 |
|------|-----------|--------|-------|----------|------|
| TCP 自定义标志 | ✅ | ✅ | ✅ | ❌ | 基础可用 |
| TCP 选项 (MSS/SACK/TS) | ❌ | ✅ | ✅ | ❌ | **需补** |
| IP 分片 | ❌ | ✅ | ✅ | ❌ | **需补** |
| IPv6 | ❌ | ✅ | ✅ | ✅ | **需补** |
| VLAN / QinQ | ⚠️ 单层 | ✅ | ✅ | ❌ | 需扩展 |
| 包速率精确控制 | ⚠️ 未接线 | ✅ | ❌ | ✅ | 需修 bug |
| 多接口负载均衡 | ❌ | ❌ | ❌ | ✅ | **需补** |
| 协议组合流 | ❌ | ❌ | ✅ | ✅ | **需补** |
| 流量持续时间控制 | ✅ | ✅ | ✅ | ✅ | 已实现 |
| pcap 输入/输出 | ✅ 输出 | ✅ | ✅ | ✅ | 已实现 |
| 重放 (replay) | ❌ | ❌ | ✅ | ✅ | **需补** |
| 包延迟/抖动 | ❌ | ❌ | ✅ | ❌ | 可选 |
| 包乱序 | ❌ | ❌ | ✅ | ❌ | 可选 |

### 7.2 遗漏功能清单

#### 必须补（影响专业使用）

| # | 功能 | 原因 | 工作量 |
|---|------|------|--------|
| 1 | **IPv6 全链路支持** | IPv4/IPv6 双栈是网络测试的基本需求 | 大 |
| 2 | **TCP 选项字段** | TCP 握手必须协商 MSS，否则连接不可靠 | 中 |
| 3 | **速率限制接线** | TokenBucket 创建了但从未传入实际 BPS 值 | 小 |
| 4 | **DSCP/ECN 独立控制** | QoS 测试的核心需求 | 小 |
| 5 | **IP 分片支持** | 测试 MTU/Path MTU 发现场景 | 中 |
| 6 | **包大小/MTU 预览** | 用户无法预估生成流量是否符合预期 | 小 |

#### 应该补（提升专业性）

| # | 功能 | 原因 | 工作量 |
|---|------|------|--------|
| 7 | **pcap 重放功能** | 测试中常需要重放捕获的流量 | 大 |
| 8 | **多接口负载均衡** | 端口组仅支持单选接口 | 中 |
| 9 | **协议注册插件化** | 当前硬编码，添加协议需改多文件 | 中 |
| 10 | **Schema 驱动表单** | 前后端参数不同步是持续维护负担 | 大 |
| 11 | **协议模板/场景** | 常用流量模式（SYN flood, DNS amplification...） | 中 |
| 12 | **HTTP 响应自定义** | 当前只返回 200 OK + "OK" 体 | 小 |

#### 可选（锦上添花）

| # | 功能 | 原因 | 工作量 |
|---|------|------|--------|
| 13 | **流量整形 (traffic shaping)** | 模拟突发/间隙/突发模式 | 大 |
| 14 | **包延迟/重排序** | 模拟真实网络条件 | 大 |
| 15 | **PCAPng 格式** | 现代标准，支持注释/接口描述 | 中 |
| 16 | **MPLS / GRE / VXLAN 隧道** | 广域网/数据中心场景 | 大 |
| 17 | **SCTP / QUIC 协议** | 现代传输层协议 | 大 |
| 18 | **TLS 模拟 (ClientHello)** | 安全测试基础 | 大 |

---

## 8. 修复优先级建议

### Phase 1: 修 bug + 补基础（1-2 周）

```
P0 - 必须立刻修复:
  ├─ 速率限制接线 (engine.go:193 TokenBucket(0,...) 传入实际 BPS)
  ├─ CPU 监控 (system.go 返回 0 的 TODO)
  └─ Settings 持久化 (settings_handler.go 内存存储)

P0.5 - 核心功能（混合流量，必做）:
  ├─ BatchSpec/TrafficClass 接入引擎流水线
  │   ├─ Engine 支持 BatchSpec 输入，拆分为多个 TrafficClass 子任务
  │   ├─ 每个 TrafficClass 独立 TokenBucket 限速
  │   ├─ 4元组生成策略 (TupleConfig: inc/random/pattern)
  │   └─ 多类流量共享同一输出 (PCAP/Interface)
  ├─ TupleConfig 实现 (ValueCycler/ValueRandom 适配 IP/Port 范围)
  ├─ 前端混合流量配置界面
  │   ├─ Step 2 扩展为流量类配置
  │   ├─ 每类独立协议/BPS/4元组设置
  │   └─ 添加/删除/排序流量类
  └─ 前端 TaskCreate.vue 适配 BatchSpec 提交

P1 - 专业必备:
  ├─ DSCP/ECN 独立控制 (builder.go 拆 TOS 为 DSCP+ECN)
  ├─ TCP 数据偏移支持选项 (builder.go 固定 0x50)
  └─ 参数验证增强 (端口/VLAN/MSS 范围检查)
```

### Phase 2: IPv6 + Schema 化（2-3 周）

```
P2 - IPv6 全链路:
  ├─ buildL3 增加 IPv6 分支
  ├─ 校验和改为 IP 版本适配
  ├─ DNS 支持 AAAA 查询
  └─ 前端 IP 输入区分 v4/v6

P3 - Schema 驱动:
  ├─ 定义 ParameterSchema 接口
  ├─ 每个 Planner 实现 Schema()
  ├─ strategy_convert.go 改为 Schema 驱动映射
  └─ 前端根据 Schema 自动生成表单
```

### Phase 3: 协议扩展 + 引擎增强（3-4 周）

```
P4 - 插件化协议注册:
  ├─ 删除 protocol/ 包的 dead code
  ├─ 统一 ProtocolPlanner 接口到 core 包
  ├─ main.go 改为自动发现注册
  └─ API handler 动态列出协议

P5 - 引擎能力扩展:
  ├─ 多 PacketWorker + resequencing
  ├─ 包大小预览 / MTU 检查
  ├─ PCAP 重放功能 (读 pcap → 生成 PacketConfig)
  └─ 多接口轮询输出
```

### Phase 4: 高级功能（持续迭代）

```
P6 - 流量场景:
  ├─ 协议模板 (SYN flood, DNS amp, HTTP 压力测试...)
  ├─ 流量持续时间控制
  ├─ 多协议混合流
  └─ 时间分布 (定时触发)

P7 - 输出增强:
  ├─ pcapng 格式
  ├─ PCAP 旋转清理
  ├─ 实时压缩输出
  └─ 多输出同时写入
```

---

## 附录: 硬编码值完整清单

### builder.go

| 位置 | 硬编码值 | 说明 | 建议 |
|------|---------|------|------|
| L2 header 大小 | 14 字节 | 以太网头部固定大小 | 可配置 |
| VLAN TPID | 0x8100 | 802.1Q | 增加 802.1ad (0x88A8) |
| L3 header[0] | 0x45 | IPv4 + IHL=5 (无选项) | 需要时支持选项 |
| L3 header[1] | 0x00 | DSCP=0, ECN=0 | 独立 DSCP/ECN 参数 |
| L3 Flags | 0x4000 | DF 位 (不分片) | 可配置 DF/MF/offset |
| L3 TTL 缺省 | 64 | 默认 TTL | 合理，保持 |
| L3 Protocol | 配置传入 | ICMP=1, TCP=6, UDP=17 | 保持 |
| TCP header[12] | 0x50 | Data Offset=5 (无选项) | 支持 TCP 选项 |
| TCP header[13] | config.L4.Flags | 用户控制 | 保持 |
| TCP Window 缺省 | 65535 | 最大窗口 | 合理，保持 |
| TCP Urgent Ptr | 0 | 固定为 0 | 支持 URG 指针 |
| UDP checksum | 含伪头部 | 标准计算 | 保持 |

### 协议 Planner 中

| 位置 | 硬编码值 | 建议 |
|------|---------|------|
| TCP clientSeq | 1000 | 可配置或随机 |
| TCP serverSeq | 2000 | 可配置或随机 |
| HTTP dstPort 缺省 | 80 | 保持（标准） |
| DNS dstPort 缺省 | 53 | 保持（标准） |
| ICMP 数据 | "ping" | 可配置 |
| ICMP ID/Sequence | 同值 | 可独立配置 |

---

*报告完成。以上分析基于对引擎全部核心代码的直接阅读和 Agent 辅助分析。*

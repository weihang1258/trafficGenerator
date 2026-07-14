现在我完整地阅读了 TCP 规划器中的所有代码以及核心类型定义。让我从函数到函数，详尽地逐条列举每个分支和场景。

---

## 全面 TCP 规划器场景列举

### 函数：`Validate`（第 42-63 行）

| # | 场景 | 输入描述 | 预期输出 | 代码分支 |
|---|---|---|---|---|
| T1 | Source IP validation failure | `spec.SrcIP` 非空但格式无效（例如 `"256.1.1.1"`、`"not-an-ip"`） | `error`："invalid source IP: ..." | 第 44-47 行：`if spec.SrcIP != ""` → `if net.ParseIP(spec.SrcIP) == nil` |
| T2 | Source IP empty | `spec.SrcIP` 为空字符串 `""` | 跳过校验，无错误 | 第 44 行：`if spec.SrcIP != ""` 为 false |
| T3 | Destination IP validation failure | `spec.DstIP` 非空但格式无效 | `error`："invalid destination IP: ..." | 第 49-52 行：`if spec.DstIP != ""` → `if net.ParseIP(spec.DstIP) == nil` |
| T4 | Destination IP empty | `spec.DstIP` 为空字符串 `""` | 跳过校验，无错误 | 第 49 行：`if spec.DstIP != ""` 为 false |
| T5 | Source port zero | `spec.SrcPort == 0` | `error`："source port is required" | 第 56-58 行：`if spec.SrcPort == 0` |
| T6 | Destination port zero | `spec.DstPort == 0` | `error`："destination port is required" | 第 59-61 行：`if spec.DstPort == 0` |
| T7 | 所有字段有效 | SrcIP 为空或有效 IPv4/IPv6，DstIP 为空或有效 IPv4/IPv6，SrcPort 和 DstPort 均为非零 | `nil` | 到达第 63 行 `return nil` |

**备注：** 空 IP 被静默接受。`net.ParseIP` 接受 IPv4 和 IPv6。

---

### 函数：`synOptions`（第 69-76 行）

| # | 场景 | 输入描述 | 预期输出 | 代码分支 |
|---|---|---|---|---|
| T8 | MSS > 0 | `mss = 1460`（默认）或任何非零的 `uint16` | `[]core.TCPOption{KIND=MSS, data=mss_bytes, KIND=SACK-Permit}` | 第 71-73 行：`if mss > 0` → 附加 MSS 选项 |
| T9 | MSS == 0 | `mss = 0` | `[]core.TCPOption{KIND=SACK-Permit}`（仅 SACK 许可） | 第 71 行：`if mss > 0` 为 false → 跳过 MSS 附加 |

**备注：** SACK-Permitted 选项总是被添加（无 MSS 选项时的最小大小缓冲区为 2）。

---

### 函数：`Plan` -- 入口（第 78-81 行）

| # | 场景 | 输入描述 | 预期行为 | 代码分支 |
|---|---|---|---|---|
| T10 | 验证失败 | 任何导致 Validate 返回错误的输入 | 立即返回 `nil, error`；不创建通道，不启动 goroutine | 第 79-80 行：`if err := p.Validate(spec); err != nil { return nil, err }` |
| T11 | 验证通过 | 所有字段对 Validate 有效 | 创建缓冲通道，启动 goroutine，返回 `configChan, nil` | 第 83-376 行：后续所有代码 |

---

### Plan Goroutine -- `tcpConfig` 默认值（第 91-100 行）

| # | 场景 | 输入描述 | 预期行为 | 代码分支 |
|---|---|---|---|---|
| T12 | tcpConfig 为 nil | `spec.TCP` 为 nil（FlowSpec 中未设置） | 分配默认的 `TCPConfig{Handshake: true, Termination: true, MSS: DefaultMSS (1460), WindowSize: DefaultWindowSize (65535)}` | 第 93-100 行：`if tcpConfig == nil` |
| T13 | tcpConfig 非 nil | `spec.TCP` 指向一个有效结构体 | 使用提供的 `TCPConfig` 内容，不做任何更改 | 第 93 行：`if tcpConfig == nil` 为 false |

---

### Plan Goroutine -- `winSize` 默认值（第 114-117 行）

| # | 场景 | 输入描述 | 预期行为 | 代码分支 |
|---|---|---|---|---|
| T14 | WindowSize > 0 | `tcpConfig.WindowSize = 65535`（默认）或任何非零值 | `winSize = tcpConfig.WindowSize` | 第 115-116 行：`if tcpConfig.WindowSize > 0` |
| T15 | WindowSize == 0 | `tcpConfig.WindowSize = 0`（零值 / 显式零） | `winSize = 65535`（回退到字面常量） | 第 115 行：`if tcpConfig.WindowSize > 0` 为 false |

---

### Plan Goroutine -- `effectiveTTL` 默认值（第 122-125 行）

| # | 场景 | 输入描述 | 预期行为 | 代码分支 |
|---|---|---|---|---|
| T16 | spec.TTL 非零 | `spec.TTL` 被显式设置（例如 128、255） | `effectiveTTL = spec.TTL`（使用提供值） | 第 122-123 行：`if effectiveTTL == 0` 为 false |
| T17 | spec.TTL 为零 | `spec.TTL` 为零值（uint8 默认值） | `effectiveTTL = DefaultTTL (64)` | 第 123-124 行：`if effectiveTTL == 0` |

---

### Plan Goroutine -- 握手分支（第 130-205 行）

| # | 场景 | 输入描述 | 预期行为 | 代码分支 |
|---|---|---|---|---|
| T18 | Handshake == true | `tcpConfig.Handshake = true`（默认，或显式设置） | 发送 SYN、SYN-ACK、ACK 3 个数据包 | 第 130 行：`if tcpConfig.Handshake` |
| T19 | Handshake == false | `tcpConfig.Handshake = false` | 跳过整个握手；不发送任何数据包，序列号不变 | 第 130 行：`if tcpConfig.Handshake` 为 false |

**在 Handshake == true 内：**
| # | 场景 | 预期输出 | 备注 |
|---|---|---|---|
| T18a | SYN 数据包（客户端 → 服务器） | packetIndex=0，Direction="up"，Flags=FlagSYN，Seq=clientSeq(1000)，WindowSize=winSize，TCPOptions=synOpts。然后 packetIndex=1，clientSeq=1001 | 第 132-154 行 |
| T18b | SYN-ACK 数据包（服务器 → 客户端） | packetIndex=1，Direction="down"，Flags=SYN\|ACK，Seq=serverSeq(2000)，Ack=clientSeq(1001)，WindowSize=winSize，TCPOptions=synOpts。然后 packetIndex=2，serverSeq=2001 | 第 157-180 行 |
| T18c | ACK 数据包（客户端 → 服务器） | packetIndex=2，Direction="up"，Flags=FlagACK，Seq=clientSeq(1001)，Ack=serverSeq(2001)，WindowSize=winSize，TC POptions=nil。然后 packetIndex=3 | 第 183-204 行 |

---

### Plan Goroutine -- 数据段分支（第 208-273 行）

| # | 场景 | 输入描述 | 预期行为 | 代码分支 |
|---|---|---|---|---|
| T20 | Payload 非空（数据发送） | `len(spec.Payload) > 0` | 进入数据分段逻辑 | 第 208 行：`if len(spec.Payload) > 0` |
| T21 | Payload 为空/无数据 | `len(spec.Payload) == 0`，或 `spec.Payload` 为 nil | 跳过整个数据段块 | 第 208 行：`if len(spec.Payload) > 0` 为 false |

**数据段内的 MSS 默认值：**
| # | 场景 | 输入描述 | 预期行为 | 代码分支 |
|---|---|---|---|---|
| T22 | MSS == 0（在 TCPConfig 中） | `tcpConfig.MSS = 0` | `mss = int(0) = 0` → 回退到 `DefaultMSS (1460)` | 第 210-213 行：`if mss == 0` |
| T23 | MSS > 0 | `tcpConfig.MSS` 为非零（例如 1460、536、65535） | `mss = int(tcpConfig.MSS)` 按原样使用 | 第 210 行：`if mss == 0` 为 false |

**数据段循环（第 216-272 行）：**
| # | 场景 | 输入描述 | 预期行为 | 代码分支 |
|---|---|---|---|---|
| T24 | 精确有效载荷：payload 长度 < MSS | Payload 小于一个 MSS（例如 100 字节，MSS=1460） | 一次迭代：segmentSize = len(payload)=100。一个数据包 + 一个 ACK = 2 个数据包。packetIndex 增加 2 | 第 216-272 行；第 218-219 行：`if segmentSize > mss` 为 false |
| T25 | 精确有效载荷：payload 长度 == MSS | Payload 恰好等于一个 MSS（例如 1460 字节） | 一次迭代：segmentSize = 1460。2 个数据包 | 第 216-272 行；第 218-219 行：`if segmentSize > mss` 为 false（相等意味着没有分段） |
| T26 | 大型有效载荷：payload 长度 > MSS | Payload 大于一个 MSS（例如 3000 字节，MSS=1460） | 多次迭代：第 1 次：segmentSize=1460，第 2 次：segmentSize=1460，第 3 次：segmentSize=80。总共 6 个数据包（每段 2 个）。packetIndex 增加 6 | 第 216-272 行；第 218-219 行：`if segmentSize > mss` 对前 N-1 次为 true，对最后一次为 false |
| T27 | 极长有效载荷 | 非常大的 Payload（例如 1MB） | N = ceil(len(payload)/mss) 次迭代。每个段产生 2 个数据包。如果 N > 128 且通道在其他地方没有被消耗，通道（缓冲区=256）会阻塞 | 第 216-272 行；循环一直运行直到 payload 被消耗完 |

**在每次数据段迭代内：**
| # | 场景 | 预期输出 |
|---|---|---|
| T26a/T24a | DATA 数据包（客户端 → 服务器） | Direction="up"，Flags=PSH\|ACK，Seq=clientSeq，Ack=serverSeq，Payload=payload[:segmentSize]。然后 packetIndex++，clientSeq += uint32(segmentSize) |
| T26b/T24b | ACK 数据包（服务器 → 客户端） | Direction="down"，Flags=FlagACK，Seq=serverSeq，Ack=clientSeq（更新后的值），WindowSize=0（uint16 零值——见备注）。然后 packetIndex++ |

**关于数据 ACK 的备注：** WindowSize 在 DATA ACK 数据包上未明确设置，因此默认为 0。在许多真实场景中这是不现实的，但功能上并非错误（ACK 中的零窗口是合法的，只是限制性很强）。

---

### Plan Goroutine -- 终止分支（第 276-373 行）

| # | 场景 | 输入描述 | 预期行为 | 代码分支 |
|---|---|---|---|---|
| T28 | Termination == true | `tcpConfig.Termination = true`（默认，或显式设置） | 发送 FIN、ACK、FIN、ACK 4 个数据包 | 第 276 行：`if tcpConfig.Termination` |
| T29 | Termination == false | `tcpConfig.Termination = false` | 跳过终止块；不发送 FIN/ACK 数据包 | 第 276 行：`if tcpConfig.Termination` 为 false |

**在 Termination == true 内（4 个数据包顺序）：**
| # | 场景 | 预期输出 | 备注 |
|---|---|---|---|
| T28a | 客户端 FIN | Direction="up"，Flags=FIN\|ACK，Seq=clientSeq，Ack=serverSeq，WindowSize=winSize。然后 packetIndex++，clientSeq++ | 第 278-300 行 |
| T28b | 服务器 ACK | Direction="down"，Flags=FlagACK，Seq=serverSeq，Ack=clientSeq，WindowSize=0（未设置）。然后 packetIndex++ | 第 303-324 行；窗口再次为零 |
| T28c | 服务器 FIN | Direction="down"，Flags=FIN\|ACK，Seq=serverSeq，Ack=clientSeq，WindowSize=winSize。然后 packetIndex++，serverSeq++ | 第 327-349 行 |
| T28d | 客户端 ACK | Direction="up"，Flags=FlagACK，Seq=clientSeq，Ack=serverSeq，WindowSize=0（未设置）。packetIndex 在数据包发送后未增加（goroutine 结束） | 第 352-372 行；这是最后一个操作 |

---

### 组合场景（多阶段交互）

结合握手 + 数据 + 终止标志以覆盖所有流模式：

| # | 场景 | Handshake | Payload | Termination | 总数据包数 | 行为 |
|---|---|---|---|---|---|---|
| T30 | 完整 TCP 流（默认） | true | 非空 | true | 3 + 2N + 4 | 完整三向握手 → N 个数据段（每个有 ACK）→ 四次挥手 |
| T31 | 仅握手，无数据，无终止 | true | 空/nil | false | 3 | 仅 SYN/SYN-ACK/ACK |
| T32 | 仅握手 + 数据，无终止 | true | 非空 | false | 3 + 2N | 握手 → 数据 → 无 FIN 序列 |
| T33 | 仅握手 + 终止，无数据 | true | 空/nil | true | 3 + 4 | 握手 → 终止立即跟随（无数据） |
| T34 | 无握手，无数据，无终止 | false | 空/nil | false | 0 | 没有发送任何数据包（空流） |
| T35 | 无握手，有数据，无终止 | false | 非空 | false | 2N | 段在 no-handshake 状态下发送 |
| T36 | 无握手，无数据，有终止 | false | 空/nil | true | 4 | 没有建立连接的情况下发送终止（非真实） |
| T37 | 无握手，有数据，有终止 | false | 非空 | true | 2N + 4 | 没有建立连接的情况下发送数据 + 终止（非真实） |

**备注：** 场景 T34-T37 是可能的，但对现实网络来说是不正常的——它们发送数据/终止数据包，而没有事先的握手机制来建立序列号。

---

### 不存在/缺失的场景（应存在但未实现）

| # | 场景 | 描述 | 影响 |
|---|---|---|---|
| M1 | 上下文取消被忽略 | goroutine 中未检查 `ctx.Done()` | 如果调用者取消上下文，goroutine 会泄漏并继续运行。所有对 `configChan` 的发送都是裸发送——没有 `select` 使用 `ctx.Done()` |
| M2 | VLAN 被静默丢弃 | `spec.VLAN` 从未复制到 `L2Config.VLAN` | FlowSpec 中的 VLAN 配置被忽略 |
| M3 | 未检查 Count/Duration/BPS | `spec.Count`、`spec.Duration`、`spec.BPS` 在 `Plan()` 中从未被读取 | 调用者/引擎必须处理流约束。这个规划器总是产生一次性的包序列 |
| M4 | 初始化函数被注释掉 | `protocol.Register(NewPlanner())` 在第 381 行被注释掉 | 规划器永远不会自动注册；调用者必须手动调用 `NewPlanner()` |
| M5 | 最后一个终止 ACK 后 packetIndex 没有增加 | 在 T28d 后没有 packetIndex++ | 良性（goroutine 结束），但与之前数据包的递增模式不一致 |
| M6 | 数据 ACK 和终止 ACK 数据包的 WindowSize 为零 | 数据 ACK（T26b）、终止 ACK#1（T28b）、终止 ACK#2（T28d）都没有设置 WindowSize | 这些数据包的 L4Config.WindowSize 为 0。这在真实场景中是非典型的 |

---

### 边缘情况和边界条件

| # | 场景 | 输入 | 行为 |
|---|---|---|---|
| E1 | Payload 确切地是 MSS 的倍数 | Payload = 2920（2 * 1460），MSS = 1460 | 恰好 2 次循环迭代；每次完全消耗 MSS；没有剩余 |
| E2 | Payload 非零但短于 MSS | Payload = 1 字节，MSS = 1460 | 一次迭代；segmentSize = 1；1 个 DATA 包 + 1 个 ACK |
| E3 | MSS 设置得非常小 | MSS = 1，Payload = 1000 | 1000 次迭代；每个数据包携带 1 字节有效载荷 |
| E4 | MSS 非常大（> 典型 MTU） | MSS = 65535，Payload = 100000 | 2 次迭代：segmentSize=65535，然后 segmentSize=34465 |
| E5 | 有效载荷长度等于 MSS + 1 | Payload = 1461，MSS = 1460 | 2 次迭代：segmentSize=1460，然后 segmentSize=1 |
| E6 | 源 IP 和目的 IP 都为空 | SrcIP=""，DstIP="" | 通过验证。flowID = "--0-0"（格式奇怪。如果端口也是 0，验证会失败） |
| E7 | 仅源 IP 有效，目的 IP 为空 | SrcIP="10.0.0.1"，DstIP="" | 通过验证。flowID = "10.0.0.1--80-443"。所有数据包中，DstIP 为空字符串 |
| E8 | 仅目的 IP 有效，源 IP 为空 | SrcIP=""，DstIP="10.0.0.2" | 通过验证。flowID = "-10.0.0.2-80-443"。所有数据包中，SrcIP 为空字符串 |
| E9 | IP 地址是 IPv6 | SrcIP="::1"，DstIP="fe80::1" | 通过验证（net.ParseIP 接受）。flowID = "::1-fe80::1-80-443"（带冒号的字符串 OK） |
| E10 | 端口 65535（uint16 最大值） | SrcPort=65535，DstPort=65535 | 通过验证（非零）。正确使用 |
| E11 | tcpConfig 非 nil，但所有布尔值为 false 且 MSS/WindowSize 为零 | TCPConfig{false, false, 0, 0, 0, 0, 0} | Handshake=false，Termination=false。MSS=0 导致 MSS 回退。WindowSize=0 导致 winSize 回退。另请参阅 T22（数据段期间的 MSS 回退） |
| E12 | Channel 被消费者阻塞（消费者停止读取） | 任何产生超过 256 个事件的场景 | **GOROUTINE 泄漏：** 第 256 次发送到 configChan 会永久阻塞。没有 `ctx.Done` 检查，没有退出路径 |

---

### 总结

**文件：** `/home/weihang/trafficGenerator/trafficgen/internal/protocol/tcp/tcp.go`

- **3 个正常路径函数**（构造器、名称、init——都是平凡的）
- **11 个不同的 Validate 代码路径**（T1-T7，包括 IP/端口验证）
- **2 个 synOptions 路径**（T8-T9：有/无 MSS 选项）
- **2 个 Plan 入口路径**（T10-T11：验证通过/失败）
- **2 个 tcpConfig 默认值路径**（T12-T13）
- **2 个 winSize 默认值路径**（T14-T15）
- **2 个 effectiveTTL 路径**（T16-T17）
- **2 个 Handshake 路径**（T18-T19）
- **2 个 Data 路径**（T20-T21）
- **2 个 MSS 默认值路径**（T22-T23）
- **数据段循环中 4 个有效载荷大小条目**（T24-T27）
- **每个数据段迭代中 2 个子路径**（DATA + ACK 数据包）
- **2 个 Termination 路径**（T28-T29）
- **终止阶段内 4 个子路径**（T28a-T28d）
- **8 个握手/数据/终止组合场景**（T30-T37）
- **6 个缺失/错误场景**（M1-M6——最严重的是缺少上下文取消检查）
- **12 个附加边界边缘情况**（E1-E12）

**最关键的发现：** `ctx` 参数在 goroutine 中完全未被使用。所有对 `configChan` 的发送都是裸发送，没有 `select { case ...: case <-ctx.Done(): }`。如果消费者停止读取或上下文被取消，goroutine 会永久泄漏。E12 具体记录了这种泄漏情况。
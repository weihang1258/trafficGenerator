# 引擎功能完善与性能优化设计

> 设计日期：2026-07-10
> 范围：FlowB 流量生成引擎（Go 实现）的功能补全、Bug 修复、性能优化
> 状态：设计阶段（待评审）

---

## 0. 背景与目标

引擎是 FlowB 的根本。当前引擎能跑，但存在三类问题：

1. **写了没接上**：速率限制、CPU 监控、设置持久化都是"代码在、功能没生效"
2. **核心功能缺失**：混合流量（一个任务多协议按比例并行）类型已定义但未接入流水线
3. **参数不专业 + 性能浪费**：网络工程师常用参数（DSCP/ECN/分片/TCP选项）被写死忽略；每个包有多余的内存分配和系统调用

本设计统一解决上述问题，目标是让引擎**功能完整、参数专业、性能高效**。

**设计原则：**

- **向后兼容**：现有 API 调用方式和策略数据格式不变，改动只影响引擎内部逻辑
- **渐进式**：按 Bug 修复 → 混合流量 → 参数增强 → 性能优化的顺序落地，每步独立可运行、可测试
- **配置驱动**：参数通过策略传入，所有可调参数都有合理缺省值
- **分层隔离**：每层（L2/L3/L4）改动只影响该层，不交叉污染
- **可观测**：每个改动附带清晰日志和统计，出了问题能定位

---

## 1. Phase 1：修 Bug（P0，立即修复）

三个 Bug 都是"功能写了但没接上"或"占位符没实现"，修复为外科手术式精准改动。

### 1.1 Bug 1：速率限制没接上（最严重）

**现状（已核实代码）：**

- `engine.go:193`：每个 PacketWorker 拿到 `TokenBucket(0, 65536)`，`0 = 不限速`
- `engine.go:466` 的 `SetClassRateLimit()` 方法已定义，但全代码无人调用
- `worker.go:274`：限速用写死的 `estimatedSize := int64(1500)`，不是真实包大小
- 结果：策略里设 `bps: "200k"` 完全不生效，引擎全速跑

**修复设计：**

```
提交任务时（SubmitTask）：
  1. 解析 task.Spec.BPS 字符串（"200k" -> 200000，复用 ParseBPS）
  2. 若 BPS > 0，创建 TokenBucket(rate, burst)，存入 rateLimiters[classID]
  3. 否则不创建（不限速）

打包工处理时（PacketWorker.processConfig）：
  1. 先用 buildFunc 构造出真实数据包（拿到真实字节数）
  2. 按 config.ClassID 查找对应的 TokenBucket
  3. 用真实字节数调用 tokenBucket.Wait(ctx, realSize)
  4. 再写入输出队列
```

**关键改动点：** 限速检查从"打包前（估算 1500）"挪到"打包后（真实字节数）"，限速才精确。TokenBucket 按 ClassID 索引，为 Phase 2 每类独立限速铺路。

**改动文件：** `engine.go`（SubmitTask 创建桶）、`worker.go`（processConfig 改用真实字节 + 按 ClassID 查桶）

### 1.2 Bug 2：CPU 监控返回 0

**现状（已核实）：** `system.go:56` 直接写死 `CpuUsage: 0`，注释为 `// TODO`。

**修复设计：** 用 `syscall.Getrusage(syscall.RUSAGE_SELF)` 采集进程级 CPU 时间（Go 的 `runtime` 包不提供进程 CPU 时间，需用 syscall）。引擎启动时记录起始墙钟时间和初始 CPU 时间（`rusage.Utime` 用户态 + `rusage.Stime` 内核态），每次查询时计算：

```
CPU占用率 = (当前进程CPU时间 - 初始进程CPU时间) / (经过墙钟时间 × CPU核数) × 100%
```

CPU 核数用 `runtime.NumCPU()`。这是进程自身的 CPU 占用率（不是整机）。整机占用需读 `/proc/stat`（Linux 专属），本期不做。

**改动文件：** `system.go`（GetStatus 实现 CPU 计算）、`engine.go`（启动时记录 CPU 时间基准，存 startWallClock 和 startCPUTime）

### 1.3 Bug 3：设置不保存

**现状（已核实）：** `settings_handler.go` 的 `SettingsConfig` 只存内存，重启即丢；改 `buffer_size`、`log_level` 对运行中的引擎毫无影响（根本没传给引擎）。

**修复设计：**

```
0. 引擎启动时（server.go 初始化阶段）从 DB 读 settings 行，构造 EngineConfig
   传给 NewEngine。这样保存的设置"重启后"才生效。
1. 数据库新增 settings 表（单行配置）
2. SettingsHandler 持有 db 引用：Get 从库读，Update 写库
3. 可生效设置项在 Update 时同步应用到引擎：
   - log_level：调用 zap 动态调整日志级别（立即生效）
   - max_tasks：立即生效（提交任务时检查）
   - buffer_size：标记"重启引擎后生效"（运行时改环形缓冲区大小需重建，风险大）
4. UI 上对"需重启生效"的设置项明确标注
```

**取舍说明：** `buffer_size` 运行时改不了（环形缓冲区固定大小，改大小要重建），设计为"保存后下次启动生效"。这是合理的工程取舍。

**改动文件：** `settings_handler.go`（加 db 读写 + 应用到引擎）、`storage/models.go`（新增 Settings 模型）、`storage/db.go`（新增 settings CRUD）、`server.go`（启动时读 DB settings 构造 EngineConfig）、`engine.go`（SubmitTask 检查 max_tasks）

---

## 2. Phase 2：混合流量（P0.5 核心功能）

### 2.1 通俗解释

**单协议任务**（现状）：一个任务只跑一种协议，如"生成 100 个 TCP 流"。

**混合流量任务**（目标）：一个任务里**同时**跑多种协议，每种按设定比例分配带宽。例如：

```
一个"模拟办公室网络"任务：
  ├─ TCP 网页流量    占 50% 带宽（200 个流）
  ├─ UDP 视频流      占 30% 带宽（50 个流）
  └─ ICMP 心跳探测   占 20% 带宽（1000 个流）
```

三类流量**同时**跑，**共享**同一个输出（同一 pcap 文件或同一网卡），每类**独立限速**。这样才能模拟真实网络——真实网络从不是单一协议。

### 2.2 现状与差距

已定义但未接入的类型（`types.go:180-220`）：

- `BatchSpec`：容器，装多个流量类
- `TrafficClass`：一类流量，含协议、带宽、流数、4元组策略
- `TupleConfig`：怎么生成"源IP/目的IP/源端口/目的端口"
- `StrategyConfig`：固定/递增/随机/模式/列表

**差距：** `SubmitTask()` 只接受单个 `Task`（单个 `FlowSpec` 单协议），`ConfigWorker` 只处理单协议。整条流水线没有"批量"入口。

### 2.3 数据流设计

```
用户提交 BatchSpec 任务
        │
        ▼
   Engine.SubmitTask()
        │  解析每类 BPS，为每类创建独立 TokenBucket
        │  （key = "任务ID:类ID"，存入 rateLimiters）
        ▼
   taskChan ──► ConfigWorker
        │
        │  检测到 task.Batch != nil → 进入批量模式
        │
        │  ┌─────────────┬─────────────┬─────────────┐
        │  ▼             ▼             ▼             ▼
        │  TCP类        UDP类         ICMP类        ...（并发）
        │  │             │             │
        │  │ 4元组生成器  │             │
        │  │ (100个流,   │  (50个流)   │  (1000个流)
        │  │  每流一组    │             │
        │  │  唯一4元组)  │             │
        │  │             │             │
        │  ▼             ▼             ▼
        │  TCP规划器     UDP规划器     ICMP规划器
        │  │             │             │
        │  │ 每流产出     │             │
        │  │ 一串包配置   │             │
        │  │             │             │
        │  └─────────────┴─────────────┘
        │                 │
        │     全部汇入同一个 configChan
        │     （每个包配置带 class_id 标签）
        ▼
   PacketWorker（多个并发）
        │  按 config.ClassID 查找对应 TokenBucket
        │  用真实包字节数限速（每类独立）
        ▼
   OutputWorker → 同一个输出（pcap/网卡）
```

### 2.4 关键设计决策

**决策 1：BatchSpec 嵌入 Task，不新建类型**

```go
type Task struct {
    // ... 现有字段 ...
    Spec  FlowSpec   `json:"spec"`   // 单协议模式用这个
    Batch *BatchSpec `json:"batch"`  // 混合流量模式用这个（二选一）
}
```

`ConfigWorker` 判断：`task.Batch != nil` 走批量模式，否则走现有单协议模式。**单协议任务完全不受影响**（向后兼容）。

**决策 2：每类并发，共享输出**

批量模式下，每个 `TrafficClass` 起一个 goroutine，各自调用对应协议的规划器。所有 goroutine 把产出的包配置塞进**同一个** `configChan`。用 `sync.WaitGroup` 等所有类跑完，再回调 `onTaskDone`。

多类流量天然交织（交错进队列），输出 pcap 里包就是混合的，符合真实网络特征。

**决策 3：4元组生成器（TupleGenerator）**

新增组件，把 `TupleConfig` 转成实际 4 元组：

```
输入: TupleConfig{
    SrcIP:   {strategy: "inc", range: ["10.0.0.1", "10.0.0.254"], step: 1},
    DstIP:   {strategy: "fixed", value: "192.168.1.1"},
    SrcPort: {strategy: "rand", range: [1024, 65535], seed: 42},
    DstPort: {strategy: "list", list: ["80", "443"]},
}
输出: 每次调用 Next() 返回一组 (srcIP, dstIP, srcPort, dstPort)
      第1次: 10.0.0.1, 192.168.1.1, 50000, 80
      第2次: 10.0.0.2, 192.168.1.1, 38912, 443
      ...
```

每个流量类用自己的 `TupleGenerator`，给自己的流编索引，**保证同类流不冲突**。不同类之间天然不冲突（协议/端口不同）。

**实现要点：** IP 递增（`strategy: "inc"`）不是简单整数递增，需将 IP 地址解析为 4 字节整数，按字节递增（`10.0.0.1` → `10.0.0.2` → ... → `10.0.0.255` → `10.0.1.0`），超出 range 上限时回绕或停止。端口递增同理。TupleGenerator 需**类型感知**：对 IP 字段做字节级运算，对端口字段做整数运算。`list` 策略按序循环取值；`rand` 策略带 seed 保证可复现。

**决策 4：每类独立限速**

每个 `TrafficClass` 的 BPS 在提交时解析成独立 TokenBucket（key = "任务ID:类ID"）。包配置里带 `class_id`，PacketWorker 按 `class_id` 找桶限速。这样"TCP 占 50%、UDP 占 30%"才精确可控。复用 Phase 1 建好的"按 ClassID 查 TokenBucket"基础设施。

**已知限制（v1）：** 当前默认单 PacketWorker，限速用阻塞 `Wait()`。若某类 BPS 设得很低，worker 会在该类桶上阻塞睡眠（如 1500 字节 / 200kbps ≈ 60ms），期间其他类的包在通道里排队干等，导致低速率类拖累高速率类、类间并非完全独立。多数场景下各类 BPS 充裕（`Wait()` 立即返回不阻塞），影响可忽略；极端低速率配比下才会显现。彻底解决需优化项⑥（多 PacketWorker + 重排序，见 §4.3），但⑥已暂缓，故作为 v1 已知限制。

**决策 5：TrafficClass.Config 转 FlowSpec**

`TrafficClass.Config` 是 `map[string]interface{}`（灵活但无类型）。批量模式下需把它转成对应协议的 `FlowSpec`。

现有 `strategy_convert.go` 的 `StrategyModelToTask` 已含 map->FlowSpec 的字段映射逻辑，但与 `*storage.StrategyModel` 耦合，不能直接用于 `TrafficClass.Config`。**需先抽取**：把 map->FlowSpec 的核心逻辑拆成独立函数（如 `mapToFlowSpec(cfg map[string]interface{}, protocol string) FlowSpec`），`StrategyModelToTask` 和混合流量两条路径共用此函数，不重复造轮子。

### 2.5 持续时间与流数控制

- `TrafficClass.FlowCount`：该类生成多少个流（每个流是一完整通信）
- `GlobalConfig.DurationSeconds`：若 >0，给任务 context 设超时，到点所有类停止
- `TrafficClass.FlowsPerSecond`：流创建速率——**本期降级**：先按"一次性生成所有流"实现，`FlowsPerSecond` 作为预留字段，UI 标注"高级选项，暂未生效"

**取舍说明：** `FlowsPerSecond`（流速率控制）需精密定时调度，复杂度高且日常使用少。先做"按数量生成"把核心混合能力跑通，流速率留后续。符合"不常用的降级"原则。

### 2.6 改动文件

- `types.go`：Task 加 `Batch *BatchSpec` 字段
- `engine.go`：SubmitTask 处理 BatchSpec，为每类建 TokenBucket
- `worker.go`：ConfigWorker.processTask 增加批量模式分支（每类并发 + WaitGroup）
- 新增 `tuple_generator.go`：TupleGenerator 实现
- `strategy_convert.go`：抽取 `mapToFlowSpec` 公共函数，TrafficClass.Config 和 StrategyModel 两条路径共用

---

## 3. Phase 3：协议参数完善（P1 专业必备）

### 3.1 目标

引擎要"足够专业，网络工程师常用参数都要有"。现在有些参数**类型里有、但构建时被写死忽略**。本节把这些参数真正接通。

### 3.2 参数全景图

```
┌─────────────────────────────────────────────────────────┐
│ L2 以太网层                                              │
│  ✓ 源/目的MAC   ✓ VLAN ID   ✓ VLAN优先级   ✓ EtherType  │
├─────────────────────────────────────────────────────────┤
│ L3 IP层                                                  │
│  ✓ 源/目的IP   ✓ TTL   ✓ IPID                            │
│  ✗ DSCP（差分服务码点）   ← 写死 0                        │
│  ✗ ECN（显式拥塞通知）    ← 写死 0                        │
│  ✗ 分片标志（DF/MF）      ← 写死 DF                       │
│  ✗ 分片偏移               ← 写死 0                        │
├─────────────────────────────────────────────────────────┤
│ L4 传输层                                                │
│  ✓ 源/目的端口   ✓ 序列号   ✓ 确认号   ✓ 标志位   ✓ 窗口  │
│  ✗ TCP选项（MSS/窗口缩放/SACK/时间戳）  ← 数据偏移写死 5  │
├─────────────────────────────────────────────────────────┤
│ 应用层（各协议）                                          │
│  ✓ HTTP方法/URI/头/体   ✓ DNS域名/类型   ✓ ICMP类型/码   │
│  （IPv6 的 DNS AAAA 留单独的 IPv6 迁移）                 │
└─────────────────────────────────────────────────────────┘
```

✓ = 已支持并接通，✗ = 类型里有但构建时忽略（要修）

### 3.3 三个要补的参数块

**块 1：DSCP + ECN 独立控制（L3）**

现状：`FlowSpec.TOS` 字段存在，但 `L3Config` 里没这个字段，builder 直接写 `header[1] = 0`。

- **DSCP**（6位）：标记流量优先级。语音标 EF（加速转发）、视频标 AF41、背景流量标 BE。网络设备靠它做 QoS 排队
- **ECN**（2位）：路由器拥塞时在包里打标记，让发送方减速，比直接丢包温和

设计：`L3Config` 加 `DSCP uint8` 和 `ECN uint8`，builder 里 `header[1] = (DSCP << 2) | (ECN & 0x03)`。FlowSpec 保留 `TOS` 兼容老接口（传 TOS 整字节），新接口分开传 DSCP/ECN。

**块 2：IP 分片控制（L3）**

现状：`builder.go:126` 写死 `0x4000`（DF=1，不分片）。

- **DF**（1位）：1 = 不许分片，包太大就丢弃并回 ICMP 错误
- **MF**（1位）：1 = 后面还有分片，0 = 最后一片
- **FragOffset**（13位）：这一片在原包里的字节位置

设计：`L3Config` 加 `Flags uint8`（含 DF/MF/保留位）和 `FragOffset uint16`。builder 里 `header[6:8] = (Flags << 13) | (FragOffset & 0x1FFF)`。默认 `Flags=DF`（兼容现状），用户可设 MF+Offset 手动构造分片包。

**块 3：TCP 选项（L4）**

现状：`builder.go:203` 写死 `header[12] = 0x50`（数据偏移=5，即20字节，无选项）。

常用 TCP 选项：

- **MSS**（最大段大小）：握手时协商每包最多带多少数据
- **Window Scale**（窗口缩放）：把窗口从16位扩到30位（高带宽链路必需）
- **SACK-Permitted**（选择性确认许可）：丢包时只重传缺失部分
- **Timestamp**（时间戳）：测算往返时延、防止序列号回绕

设计：`L4Config` 加 `TCPOptions []TCPOption` 字段。builder 根据选项数量动态计算数据偏移（不再写死 5），逐个编码选项字节。TCP 握手规划器自动在 SYN 包带 MSS/SACK/WindowScale（符合真实抓包特征）。

### 3.4 参数验证增强

现状：`ValidateTask` 基本只查"协议认不认识"，数值范围几乎不查。补这些校验（提交时拦截，给清晰错误）：

| 参数 | 校验规则 | 错误示例 |
|------|---------|---------|
| 端口 | 0-65535 | "源端口 70000 超出范围" |
| VLAN ID | 0-4095 | "VLAN ID 5000 无效" |
| VLAN 优先级 | 0-7 | "VLAN 优先级 9 无效" |
| MSS | 536-65535 | "MSS 100 太小" |
| TTL | 1-255 | "TTL 0 无效" |
| DSCP | 0-63 | "DSCP 70 超出6位范围" |
| IP 格式 | 合法 IPv4 | "源IP格式错误" |
| FlowCount | >0 | "流数必须大于0" |

验证集中在 `core` 包的新 `validate.go`，每个协议规划器调自己那部分。

### 3.5 优先级

1. **DSCP/ECN**（最先做）—— QoS 测试是刚需，改动小
2. **IP 分片**（其次）—— 分片测试场景常见，改动小
3. **TCP 选项**（最后）—— 改动稍大（动态算数据偏移），但价值高

全部做完后，引擎 L2-L4 "网络工程师常用参数"覆盖度达标。更深参数（IP 选项、TCP MD5 签名、IPv6 扩展头）留 IPv6 迁移及后续。

### 3.6 改动文件

- `types.go`：L3Config 加 DSCP/ECN/Flags/FragOffset；L4Config 加 TCPOptions
- `builder.go`：buildL3 读 DSCP/ECN/Flags/FragOffset；buildTCP 动态数据偏移 + 选项编码
- 新增 `validate.go`：参数范围校验
- `strategy_convert.go`：新字段映射
- 各协议 planner：TCP 握手带选项

---

## 4. Phase 4：性能优化

### 4.1 瓶颈清单（已逐个核实代码）

```
瓶颈                            位置              影响          风险
─────────────────────────────────────────────────────────────────────
① PCAP 每批强制刷盘              pcap.go:114      写盘慢10倍+    低
② PCAP 每包两次系统调用          pcap.go:103,107  系统调用多     低
③ PCAP 每包分配16字节头          pcap.go:89       GC压力        低
④ RingBuffer 每包复制一次        buffer.go:52-54  内存翻倍      低
⑤ Builder 每包4-5次分配          builder.go       GC压力        低
⑥ 重排序未启用->只能单打包工       worker.go:318    不能多核并行  高
```

### 4.2 第一档：低风险高回报（本期做）

**优化①②③：PCAP 写入重构**

现状每个包：分配16字节头 → 写头（系统调用）→ 写数据（系统调用）→ 每批结束 fsync 刷盘。

改成：

```
- 用 bufio.Writer 包一层（内存缓冲，攒够一批再写）
- 16字节头用栈上数组（不再 make）
- 头和数据拼成一个切片，一次 Write 写完（系统调用减半）
- fsync 只在关闭文件/轮转时调用，不每批刷
  （崩溃最多丢最后几批，对流量生成可接受）
- 时间戳改为**循环内每包独立调 `time.Now()`**（现状是循环外取一次、整批共享；不用 config.Timestamp，因为规划器在计划时设 Timestamp 且整条流复用同一值，粒度更粗）
```

预计：PCAP 输出吞吐提升 5-10 倍。

**优化④：RingBuffer 去重复制**

现状：打包工造好包 → RingBuffer.Put 又 `make + copy` 一份。包是新建切片，没人在复用，复制纯属浪费。

改成：Put 直接持有原切片引用，不复制。前提是打包工保证每次返回新切片（现状已是如此）。省一次分配 + 一次拷贝。

**优化⑤：Builder 单缓冲区构建**

现状：L2 `make(14)` + L3 `make(20)` + L4 `make(20)` + 总拼 `make(0, total)` + 4次 append = 每包 4-5 次分配。

改成：一次 `make([]byte, 0, 预估总长)`，各层直接往这个缓冲区写（固定偏移量写各字段），一次分配搞定。配合 `sync.Pool` 复用缓冲区，进一步降 GC 压力。

### 4.3 第二档：高风险高回报（暂缓）

**优化⑥：重排序 + 多打包工并行**

现状（`worker.go:318` 注释明说）：重排序代码删了，因为"单打包工保证顺序"。这意味着**只用 1 个打包工**，多核 CPU 利用不起来，这是吞吐量天花板。

启用多打包工：

- 配置 2-4 个打包工，包构建并行，吞吐随核数提升
- 但多工并发会让包乱序（工A和工B同时处理同一流的包，谁先完成不确定）
- 需要重排序器：按 flow_id + packet_index 缓冲重排，按序释放
- Python 参考引擎有现成逻辑可借鉴

**风险：** 重排序器要做缓冲、查表、级联释放，逻辑复杂，易出 bug（死锁、内存涨、乱序没修干净）。

**决策：** 第一档（①-⑤）先做完，稳赚不赔。第二档（重排序）作为**可选增强**，等第一档落地、基准测试确认单工瓶颈确实是天花板后再上。

### 4.4 配套：性能可观测

- **基准测试**：写 `engine_bench_test.go`，测单协议/混合流量在不同包大小下的 PPS 和 BPS
- **实时指标**：现有 `current_pps`/`current_bps` 已有，修完速率限制后这些数值真实反映
- **GC 监控**：`system.go` 已有内存指标，补上 GC 暂停次数/时长（`runtime.MemStats` 里有）

### 4.5 取舍总结

| 优化项 | 做/不做 | 理由 |
|--------|--------|------|
| ①②③ PCAP重构 | 本期做 | 风险低，写盘吞吐提升明显 |
| ④ RingBuffer去复制 | 本期做 | 风险低，省内存省分配 |
| ⑤ Builder单缓冲 | 本期做 | 风险低，降GC压力 |
| ⑥ 重排序+多工 | 暂缓 | 风险高，等基准测试确认瓶颈再上 |
| 基准测试 | 本期做 | 优化的前提，必须有数据 |

### 4.6 改动文件

- `pcap.go`：bufio 包裹、单次写、栈上头、按需 fsync、每包时间戳
- `buffer.go`：Put 去掉复制
- `builder.go`：单缓冲区构建 + sync.Pool
- 新增 `engine_bench_test.go`：基准测试
- `system.go`：补 GC 指标

---

## 5. 实施顺序（依赖关系）

```
Phase 1：修 Bug（P0）          ← 让现有功能真正生效
   ├─ 速率限制接线（顺带建好"按类ID查TokenBucket"的基础设施）
   ├─ CPU 监控
   └─ 设置持久化
        │
        ▼ （速率限制的基础设施在下一步复用）
Phase 2：混合流量（P0.5）       ← 核心功能
   ├─ TupleGenerator（4元组生成器）
   ├─ BatchSpec 流水线接入 ConfigWorker
   ├─ 每类独立限速（复用 Phase 1 的基础设施）
   └─ 持续时间控制
        │
        ▼ （Builder 改动集中做，避免反复改同一个文件）
Phase 3：参数完善（P1）         ← 专业参数补全
   ├─ DSCP/ECN
   ├─ IP 分片
   ├─ TCP 选项
   └─ 参数验证
        │
        ▼ （Builder 优化要在参数改动稳定后做，否则反复返工）
Phase 4：性能优化               ← 把浪费省回来
   ├─ PCAP 写入重构
   ├─ RingBuffer 去复制
   ├─ Builder 单缓冲
   └─ 基准测试
```

**依赖说明：**

- Phase 1 的速率限制要改成"按 ClassID 查 TokenBucket"，这正是 Phase 2 每类限速要用的，先做 Phase 1 等于铺路
- Phase 3 和 Phase 4 都改 `builder.go`，先做参数（功能）再做优化（性能），避免优化完又因加参数返工
- 每个 Phase 完成后独立交付、独立测试，不存在"半成品不能跑"

---

## 6. 测试策略

### 6.1 测试网口

真实发包测试使用网口 **`enp135s0f0np0`**。该网口用于：

- 真实流量输出测试（output_mode = interface）：验证包能从网卡发出
- 抓包验证：用 `tcpdump`/`wireshark` 在对端或同口抓包，核对包字段（DSCP/ECN/标志位/TCP选项）正确性
- 限速验证：发包到网口，用对端流量统计核对实际 BPS 是否符合设定

### 6.2 单元测试（每个改动都配）

- **速率限制**：设 BPS=100k，生成 1000 包，验证实际字节/耗时符合限速
- **CPU 监控**：跑满一个工，验证 CpuUsage > 0 且合理
- **设置持久化**：Update 后重启进程，Get 验证值保留；验证 log_level 动态生效
- **混合流量**：提交 3 类 BatchSpec，验证每类流数正确、输出包混合、每类独立限速生效
- **参数**：DSCP=46 的包抓字节验证 `header[1] = (46<<2)`；TCP 选项编码后数据偏移正确；分片包 FragOffset 正确
- **验证**：端口 70000、VLAN 5000、MSS 100 等非法值被拦截并返回清晰错误

### 6.3 基准测试（Phase 4 配套）

- 单协议 TCP/UDP/HTTP 在 64/512/1500 字节下的 PPS
- 混合流量 3 类的聚合 PPS
- PCAP 写入吞吐（优化前后对比，量化提升）

### 6.4 回归保障

- 现有测试全绿才能进下一 Phase
- 每个改动跑 `go test ./...`，关键路径加 `go test -race`（查并发竞争）
- 混合流量的并发路径必须过 `-race`

---

## 7. 不在本设计范围（留后续）

- **IPv6 全链路**：见 `docs/ipv6-migration.md`，独立专项
- **MCP 外部 API**：待单独沟通需求后设计
- **插件化协议注册**：删除 `protocol/` 包 dead code、统一 ProtocolPlanner 接口、自动发现注册，留后续 Phase
- **重排序 + 多打包工并行**：见 4.3，暂缓，等基准测试确认瓶颈
- **PCAP 重放**：读 pcap → 生成 PacketConfig，留后续
- **流速率控制（FlowsPerSecond）**：见 2.5，本期降级

---

## 8. 改动文件汇总

| 文件 | 涉及 Phase | 改动概述 |
|------|-----------|---------|
| `internal/core/engine.go` | 1, 2 | 速率限制接线、CPU 基准、SubmitTask 处理 BatchSpec、max_tasks 检查 |
| `internal/core/worker.go` | 1, 2 | processConfig 真实字节限速、ConfigWorker 批量模式 |
| `internal/core/buffer.go` | 4 | RingBuffer.Put 去复制 |
| `internal/core/builder.go` | 3, 4 | DSCP/ECN/分片/TCP选项、单缓冲构建 |
| `internal/core/types.go` | 2, 3 | Task.Batch、L3Config/L4Config 新字段 |
| `internal/core/strategy_convert.go` | 2, 3 | 抽取 mapToFlowSpec 公共函数、新字段映射 |
| `internal/core/validate.go`（新增） | 3 | 参数范围校验 |
| `internal/core/tuple_generator.go`（新增） | 2 | 4元组生成器（IP/端口类型感知） |
| `internal/core/engine_bench_test.go`（新增） | 4 | 基准测试 |
| `internal/api/rest/system.go` | 1, 4 | CPU 监控、GC 指标 |
| `internal/api/rest/settings_handler.go` | 1 | 设置持久化、应用到引擎 |
| `internal/api/rest/server.go` | 1 | 启动时读 DB settings 构造 EngineConfig |
| `internal/storage/models.go` | 1 | Settings 模型 |
| `internal/storage/db.go` | 1 | settings CRUD |
| `internal/output/pcap.go` | 4 | bufio、单次写、按需 fsync、循环内每包时间戳 |

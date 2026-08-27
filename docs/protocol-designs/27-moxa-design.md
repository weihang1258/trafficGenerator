# Moxa NPort（串口服务器透传）协议设计

> 版本：v1.0.0（初稿）
> 设计日期：2026-08-18
> 范围：Moxa NPort 串口设备联网服务器（serial device server，串口服务器透传）在【透明透传】（transparent passthrough，亦称 TCP Server/Real COM 模式）下的流量生成设计。TCP 连接 = 串口数据容器的裸字节流透传，无应用层帧。
> 实现位置：`trafficgen/internal/protocol/moxa/`（终结层生成器 + 校验器，规划中）、`trafficgen/internal/core/layers/registry.go`（层注册，规划中）、`trafficgen/internal/core/types.go`（`MOXAConfig` 定义，规划中）、`trafficgen/internal/core/strategy_convert.go`（`moxa` flat 键解析，规划中）
> 配套参考：层链配置架构（18-layer-config-design.md）；同类"TCP 终结层 + 配置经 flat 键直传"先例：enip（12-enip-design.md）、modbus（13-modbus-design.md）、doip（05-doip-design.md）
> 说明：本协议核心是**无帧裸字节流**，因此本设计的主体简单（无帧不难）；实现难度集中在"映射到本项目的层链架构"与"负路径校验"上，这两部分是本文档的重点。

### 0. 术语约定（glossary，先读，避免歧义）

| 术语 | 中文解释 / 定义 | 备注 |
|------|----------------|------|
| 串口服务器（device server / serial device server） | 把串口设备（RS-232/422/485）接入 TCP/IP 网络的设备 | 本设计对象 = NPort 系列 |
| 透明透传（transparent passthrough） | 串口字节原样在 TCP 上转发，网络侧无帧结构 | 本设计 v1 唯一模式 |
| 主站（master / host） | 连 NPort 的应用主机（PLC 上位机、采集程序等） | 生成器扮演的角色 |
| up / down | up = 主站→NPort（客户端发）；down = NPort→主站（服务器回） | 与事件模式 `MessageEvent.Up` 一一对应 |
| 数据块（stream block） | 配置流的最小单元：方向 + 一段字节 | §2.1 |
| 数据口 / 配置口 | TCP 4800 = 数据监听口（v1 目标）；UDP 4800 = 配置管理口（待定，§3.2） | 同名双口辨析见 §1.4 |
| 事件流（event stream） | 终结层产出 `MessageEvent` 的流，tcp 层逐段消费 | §3.1 |
| MSS | 最大段大小（maximum segment size），tcp 层分段粒度 | §6 S2 |

---

## 目录

1. [概述](#1-概述)
2. [数据类型与编码](#2-数据类型与编码)
3. [消息结构](#3-消息结构)
4. [状态机](#4-状态机)
5. [配置类型定义](#5-配置类型定义)
6. [包序列场景（HexDump S1-Sn）](#6-包序列场景hexdump-s1-sn)
7. [与 testcase 文档的映射索引](#7-与-testcase-文档的映射索引)
8. [实现集成点](#8-实现集成点)
9. [错误处理](#9-错误处理)
10. [扩展字段映射](#10-扩展字段映射)
11. [修订记录](#11-修订记录)

---

## 1. 概述

### 1.1 定位（这一章回答"我们到底在生成什么"）

**Moxa NPort** 是台湾 MOXA（四零四科技）生产的**串口设备联网服务器**（device server）：把串口（RS-232/422/485）设备接入 TCP/IP 网络。一侧是物理串口（接 PLC、条码扫描枪、仪表、门禁控制器等），另一侧是以太网口。设备把串口收到的字节**原样**在网络上转发，也把网络收到的字节原样写到串口——这就是"串口透传"（serial port passthrough）。

本项目关注的是 NPort 的**协议侧**（网络侧 = 从远处主站视角看 NPort）。NPort 有多种网络角色（operating mode，运行动作模式）：

| 模式（mode） | 网络侧长相 | 典型应用 |
|------|-----------|---------|
| **TCP Server**（TCP 服务器） | 主站主动 TCP 连接 NPort 的监听端口，双向透明传 | 单主站轮询串口设备 |
| **TCP Client / Real COM**（TCP 客户端） | NPort 主动发起 TCP 连接主站口 | 主站为服务端 |
| **UDP** | 无连接：NPort 把串口字节装进 UDP 数据报发给远端 | 广播/单播数据获取 |
| **Pair Connection**（配对连接） | 两台 NPort 互连透明传 | 串口线延长 |

**本设计（v1）只做模式 1：透明透传（TCP Server 语义）**——主站在一个 TCP 连接上连到 NPort，连接建立后，TCP 载荷（payload）即串口数据，**没有任何应用层帧结构**。TCP 连接的字节流只是"串口数据的容器"。

**不做**（明确非目标）：
- NPort 的**配置协议**（UDP 4800 口的管理报文，见 §1.2）——字节布局无法核实，见 §3 详述，**只在本文档标注"待定"，绝不编造字节**。
- TCP Client / UDP / Pair Connection 模式——v1 只做 TCP Server。
- 真实 NPort 的加密通道、Web Console、SNMP 管理面。

### 1.2 为什么"几乎无事可做"却要单独设计

从协议栈看，透明透传 = 纯 TCP + 裸字节，看起来可以直接用项目的 tcp 层生成器 + spec.Payload。但把它建模为独立协议有三个实际原因：

1. **管线口径（生成器视角）**：tcp 层的"独立 tcp flow"只有**单向单段** payload 语义（`tcp.go`/layers `TCPGenerator` 的 `Meta.Payload` 单段数据）。透明透传需要**多段、可双向、可分段（MSS）**的串口数据流——本项目里等价物是**报文事件流**（message event stream，`layers.MessageEvent` 事件流：方向 + 完整字节，由 tcp 层按 MSS 分段并负责握手/seq-ack/挥手）。moxa 终结层生成器 = 把"串口字节块序列"翻译成事件流的薄层。
2. **配置形态（spec 口径）**：串口字节块序列（长度、内容、方向、间隔）需要结构化的 `MOXAConfig`，直接落在 `spec` 上（flat 键 `moxa`，modbus/dnp3/enip 同款先例），而不是堆进 tcp 层 schema。
3. **校验（Validate 口径）**：串口字节流有既有的合法性边界（空载荷、超 MSS、非 2-元组、串口参数范围），需要 `moxa` 协议级 validator（RegisterLayerValidator 先例），负路径要能**显式拒绝**——这正是本项目 Testing Policy 强调的失败路径（spec-impl 审计的教训）。

所以 moxa 层注册为**终结层**（terminal layer，末层），`DependsOn=["tcp"]`，配置**零负载落 layers 数组条目**、经 `spec.MOXA` flat 键携带、`FlowMeta` 直传生成器——与 enip/doip/gbt32960/modbus/mqtt/nfs/smb/tds 完全同构。

### 1.3 层注册（本项目架构的落点）

| 项 | 值 | 出处 |
|----|----|------|
| 层名（name） | `moxa` | §8 实现集成点 |
| 角色（category） | **终结层**（terminal） | 18-layer-config-design.md §5.1 |
| 硬依赖（depends_on） | `["tcp"]` | tcp 层自动补全；载体会话由 tcp 层生成器生产 |
| optional_on | 无 | v1 不做 tls/加密 |
| 层 config（layers 数组条目） | **零负载** `{"moxa":{}}` | 配置全量走 `spec.MOXA` flat 键（enip 同款） |
| 默认目的端口 | **4800**（见 §1.4 争议） | strategy_convert `case "moxa"` 默认化 |
| 默认源端口 | 0 保持（等价于显式 src_port） | 与 modbus/mqtt 同款：不默认化 |

`{"moxa":{}}` 自动补全为 `[ip → tcp → moxa]`；用户写 `{"tcp":{}},{"moxa":{}}` 显式等价。

### 1.4 端口歧义：4800 是"数据口"还是"配置口"？（必须讲清）

**必须澄清的行业事实**：Moxa NPort 有两个 4800——容易混，本项目定为：

1. **UDP 4800**：NPort 的**配置/管理协议端口**（设备搜索、参数读写，见 §3）。这是 UDP，不是用户数据通道。
2. **TCP 4800**：部分 NPort 型号（如 NPort 5110/5610 系列）出厂**默认数据监听口**。用户数据透明透传默认监听 TCP 4800。

| 项 | 值 |
|----|----|
| 传输 | TCP（数据） / UDP（配置） |
| 数据默认监听口 | **TCP 4800**（NPort 5110/5610 等型号出厂默认） |
| 配置口 | **UDP 4800** |
| 本设计默认 dst_port | 4800（TCP 数据承载。用例显式写 `dst_port: 4800` 保证明晰） |

**测试排布纪律**：用例全部**显式**写 `dst_port: 4800`（不依赖默认化），并把 dst_port 纳入断言（`tcp.dstport == 4800`）——这样"项目生成的是 TCP 数据流"与"NPort 配置协议是 UDP 4800"的边界在用例里可被直接观测。

### 1.5 与"直接用 tcp 层 + 顶层 payload"的对照（为什么值得一层）

一个自然的反对意见是：透明透传就是纯 TCP，直接发 tcp flow 加顶层 `payload` 不就行了？下表给出本设计坚持独立协议层的**每一处差异**，以及对生成结果/校验的可观测影响：

| 维度 | 直接 tcp 层 + 顶层 payload | moxa 层（本设计） | 差异的可观测影响 |
|------|---------------------------|------------------|-----------------|
| 数据段数 | **1 段**（tcp 层 `Meta.Payload` 单段） | **多段**：stream 每块一个 MessageEvent，各成段（或合并） | `packet_count`：多段用例（S3 4 块 = 4 段）必多段才能表达"串口连续流" |
| 方向 | 单向（客户端→服务器） | **双向**：`direction:"down"` 块走事件模式 down 分支，src/dst 端口对换 | `tcp.srcport==4800` 于 down 段才能被断言（S3） |
| 配置形态 | 扁平 payload 字符串，无结构 | 结构化 `stream[]` 数组（块 = 方向 + 内容） | `spec_json` 里 `{"moxa":{...}}` flat 键结构；非纯字符串 |
| 校验边界 | tcp 层 schema：无块级约束 | 块级：空块、超长（>2048）、非法方向、非法 b64、sessions>1 拒绝 | **负路径**（expect_error）只能在 moxa 层存在（Testing Policy 失败路径） |
| 端口缺省 | 需要调用方自己填 | `case "moxa"` 默认 4800 | 缺省即发到 NPort 数据口；显式纪律（§1.4） |
| 归属 | tcp（运输层语义） | terminal（**协议语义**：串口透传） | 计分板/归类（CategoryTerminal），后续可加 TCP Client/UDP/Pair 模式互斥 |

结论：不是"多写一层没用的代码"，而是**段数、方向、结构配置、块级校验**这四件事在 tcp 层 schema 上都没有表达位。moxa 层的价值 = 把这四件事变成可声明、可校验、可断言的配置——这正是 enip/modbus/dnp3 走同一条路的理由。

### 1.6 典型拓扑（测试场景的来源）

| 拓扑 | 拓扑描述 | 对应测试场景 |
|------|---------|-------------|
| 点对点轮询（single） | 一台主站连一台 NPort（单串口设备），定时轮询 | S1/S2/S3（up 请求、down 响应） |
| 多主站/多串口（multi） | 多台主机各自连 NPort 的多个串口会话 | S4（多 flow，src_port 递增） |
| 二进制设备（binary） | 串口侧是仪表/条码枪，字节可能是任意 0x80+ 值 | S5（payload_b64 二进制） |
| IPv6 环境（v6） | 新产线 IPv6 网段，NPort 支持 IPv6 型号 | S6 |

> 每行拓扑 = 一个正向用例家族（§7 映射）。注意真实 NPort 是多串口多监听端口（§4.3）：v1 的多会话用多 flow 表达，已是上述"multi"拓扑的忠实投影。

---

## 2. 数据类型与编码

透明透传**没有应用层帧，自然没有协议自身的数值/字符串编码规则**。但生成器与校验器仍有以下"数据类型"层面的定义（这些是**配置层**的类型，不是线上字节）：

### 2.1 串口字节块（StreamBlock，数据块）

配置流的最小单元。一个数据块 = 一段连续串口字节，在某一时刻由 TCP 注入（或由对端回报）。

| 配置字段 | 类型 | 语义 |
|---------|------|------|
| `payload` | string / 字节序列 | 字节块内容（文本或二进制，二进制用 `payload_b64`） |
| `payload_b64` | string（Base64） | 二进制载荷；与 `payload` 互斥，`payload_b64` 优先 |
| `direction` | "up" / "down"（默认 "up"） | 主站→NPort（客户端→服务器，方向=请求 up） / NPort→主站（down） |

### 2.2 编码事实

| 维度 | 值 | 说明 |
|------|----|------|
| 字节序 | 无（无数值字段） | — |
| 文本编码 | UTF-8 原样透传 | 载荷字节不确定义编码，按原始字节发 |
| 二进制 | `payload_b64` 解码后原样 | 防 JSON 无法表达任意字节（WEB 控制台/HexDump 可核） |
| 帧界限 | **无帧** | TCP 不分应用层消息，字节流连续（§3.1） |

### 2.3 长度上限（校验口）

| 项 | 上限 | 出处 |
|------|------|------|
| 单块 payload 长度 | ≤ 2048 字节（`MaxBlockBytes`） | §9 错误表 E-B1（避免无界配置） |
| 单块长度与 MSS | 可 > MSS | tcp 层按 MSS 分段（分段语义 = TCP 层，不是应用层） |
| VLAN 标记 | 本项目配置层 | 经 spec.VLAN，见 §10 |

### 2.4 与默认 port 的关系

默认 `dst_port=4800` 是**TCP 数据口**；配置管理协议（UDP 4800）在本版本不生成报文（§3 详述），只在文档层面与测试层面（负路径身位）占有"4800"这个名字。

---

## 3. 消息结构

### 3.1 数据面：无帧裸字节流（唯一真实的消息结构）

透明透传的数据面**没有消息结构**。TCP 载荷 = 串口数据容器：

```
TCP 段（每段一个包）:
  direction: up / down
  tcp.flags: 0x18 (PSH|ACK)
  payload:   <串口字节块（≤1 个 MSS）>

段之间不注入任何应用层字节；多个字节块可能拼进同一条 TCP 段
（连续 up 块合并），也可能被 MSS 拆成多段。
```

对**生成器**的含义（也是本项目实现时唯一要做的事）：
1. 一个"报文事件"（`MessageEvent`）= 一个配置里的数据块（方向 + 完整字节）。
2. tcp 层消费事件流，按 MSS 分段，逐段产出 `(up, PSH|ACK)` 包；**段间不插独立 ACK**（piggyback，事件模式语义，见 layers generator.go）。这天然实现了"MSS 分段由 tcp 层负责"。
3. 连续同向块：各为一个独立事件 → 产生多条独立 TCP 段。区块结构与实际 TCP 段不必一一对应（这也符合真实 NPort：串口字节是连续流，网络侧分段由 NPort 固件决定，无应用层契约）。

### 3.2 配置/管理面：UDP 4800 配置协议（字节布局：待定）

**标注"待定"的依据（诚实纪律）**：NPort 配置协议是 Moxa 私有协议（设备搜索、参数读写），没有公开的 RFC/标准文档可核实其字节布局。本设计**不编造任何字节**。仅记录**可被间接佐证的事实**：

| 项 | 事实 | 佐证来源 |
|----|------|---------|
| 端口 | UDP 4800 | Moxa 官方文档/业界共识：诊断与配置报文走 UDP 4800 |
| 用途 | 设备搜索（发现局域网内 NPort）、读写参数、重启 | Moxa NPort 管理文档 |
| 载荷协议 | 魔数 + 类型 + 命令 + 数据的私有二进制结构 | **待定**（无公开字节级规范） |
| 魔数（magic） | 常见反推：连续魔数字节 + 类型字节开头 | **待定** —— 不列数值 |
| 类型（type）/ 命令（command）字节 | 搜索/读/写/重启 命令字 | **待定** —— 不列数值 |

**本项目 v1 的处置**：
- 配置面（UDP 4800 管理报文）**不生成**，不进生成器，不在 HexDump 场景里出现；
- 文档 §3.2/§5 只记录"存在 UDP 4800 配置协议，字节布局待定"这一个事实边界，并在负路径上做**身份区分**（§9 N-2：数据面不许把配置报文裸字节塞进 TCP 而自以为正常）；
- 若后续取得可核实的字节级资料（Moxa SDK 头文件、抓包、第三方实现的公开描述），再据实补 §3.2 字节布局与 S 场景，**修订记录（§11）明示**。

### 3.3 非目标消息面

- 无 TCP RST 带外信号（真实 NPort 会因串口断开/超时 RST 长连接，本项目不建模——挥手/终止由 tcp 层 schema 控制）。
- 无 keep-alive（NPort 的 TCP keep-alive 是 socket 级参数数分钟级，不在包级流量里体现）。
- 无串口状态事件（DTR/DSR/break 等信号：这些是串口侧信号，TCP 上无标准表达）。

### 3.4 "无帧"的推论：帧界限不确定性与测试固定性

"无帧"带来一个测试特有问题：**字节流上不存在可依赖的分界**，TCP 段的切法由 tcp 层生成器按 MSS 决定——所以：

1. **用例不应对"一块 = 一段"做假设**。当前事件模式（§8.2）下每块 1 段（S3 的 4 块 = 4 数据段，段间无独立 ACK）；**若未来实现相邻块合并**（NPort 固件的真实行为），段数会变。因此多段用例的断言定位在**段内容方向与端口**（`tcp.srcport`、hex 首字节）与会计（每块 1 包），**不断言精确段边界**——可变部分不带入断言（Testing Policy 第 5 条：断言可观测结果）。
2. **期望精确包数的用例**（S1 `packet_count=8`、S2=9、S3=11、S4=24）只在事件模式（段间无独立 ACK，§8.2）下成立。若未来实现改为"段间插对端 ACK"（legacy 模式，generator 的 `Meta.Payload` 分支），各计数需同步重推；本文档按当前生成器语义（事件模式）给确定性计数。
3. **真实 NPort 对段边界零契约**（固件合并/拆包自由）——文档这条即诚实边界：我们的"确定性"是生成器语义的确定性，不是 NPort 行为的确定性。差异表（§4.6）已记载。

### 3.5 与生成器/断言自洽的关系（多包 seq/ack 可观测性）

一个 moxa 数据流分布在多个 TCP 段上，测试需要**跨段的可观测量**来证明"这是一条连续串口字节流（而不是 N 条独立 TCP 小流）"：

1. **TCP 序号连续性**：相邻数据段的 `tcp.seq` 差 = 前段的 payload 长度（`seq_{n+1} == seq_n + len(seg_n)`）。这是"同一字节流被 MSS 切开"的最强证据。
2. **piggyback 语义**：事件模式（§8.2）下**段间不插独立对端 ACK**——数据段的 `tcp.ack` 指对端当前 seq；挥手 FIN 的 ACK 追认末段。legacy 抑制：若实现切到 `Meta.Payload` 分支才有"每段后独立 ACK"。
3. **事件与段的解耦**：§3.4 已说明段边界可变——所以用例**只断言 seq 连续性**（可观测值），不断言"哪一段对应哪一个配置块"。

`pcaptest` 的 `fields` 断言提供 `tcp.seq`/`tcp.ack` 逐包值；`same_as_packet`/指定 packet 号可表达 seq/ack 的等式关系（框架不提供跨包算术，退化为"两个段 seq 互不相同且第二段 seq != 0"也是 Process 级守卫——见 §6 S2 注）。该约束已在 §8.4 A2/A5 验收项里体现为"断言可观测结果"。

### 3.6 "配置字节不进数据面"的边界落实（N-2 的全貌）

§9 N-2（`moxa_neg_config_packet`）不是凭空造的规则，它落实三条实际边界：
- **诚实边界**（文档）：UDP 4800 配置协议字节主布局"待定"（§3.2），因此任何"像配置报文"的字节都不该出现在数据面并被自证正常。
- **实现边界**（验收）：validator 对 payload 前 3 字节 = `0x5a 0x5a 0x5a`（测试自定义标记）的块拒绝——这是一个**受控探针**：测试想确认"配置报文字节若误入 stream 会不会被当普通串口数据发出去"，预期是"拒绝"。正式实现可在字节核定后把探针前缀换成真实魔数，收窄拒绝面。
- **测试边界**（用例）：`moxa_neg_config_packet` 用 expect_error 断言任务失败（工具语义：validate 拒绝即 PASS）。

三者咬合：文档诚实 → 实现设闸 → 测试观测。这才是"负路径覆盖"在"待定"情况下该有的形状。

---

## 4. 状态机

### 4.1 TCP 连接生命周期（== 唯一的会话状态机）

透明透传的会话状态机**就是 TCP 连接生命周期本身**，由 tcp 层生成器负责（握手 → 数据 → 挥手）。moxa 终结层只在"数据"阶段向事件流写入字节块，不在握手/挥手阶段产任何报文。

```
                    ┌──────────────────────────────────────┐
                    │              moxa flow               │
                    │  （一条 TCP 连接 = 一个串口会话）       │
                    └──────────────────────────────────────┘
   SYN(up,0x02) ──► SYN-ACK(down,0x12) ──► ACK(up,0x10)
        │  TCP 层生成器（tcp schema：handshake 默认 true）
        ▼
   ★ ESTABLISHED（数据阶段：串口字节流）★
        │  事件流驱动：每一个数据块 = 一个 MessageEvent
        │    up 块   → (up, 0x18 PSH|ACK, payload=MSS 段)
        │    down 块 → (down, 0x18 PSH|ACK, src/dst 端口对换, payload=MSS 段)
        ▼
   终止（tcp schema：termination 默认 true）
   FIN|ACK(up) ─► ACK(down) ─► FIN|ACK(down) ─► ACK(up)
   （或 rst=true 时：RST|ACK(up)，跳过挥手）
```

**状态机结论：moxa 层无自有状态**。所有握手/seq-ack/挥手/分段状态都在 tcp 层（TCPGenerator）。moxa 层只是"按配置顺序把字节块翻译成事件"的**纯函数式**驱动（会读生成器级别状态：列车 ID 等，见 §4.3）。

### 4.2 引擎状态位（工程状态机）

| 状态 | 进入 | 语义 |
|------|------|------|
| `flow 级` | generate_traffic 创建 | 一个 flow = 一串会话配置（sessions 数组，见 §5） |
| `套接字级` | tcp 层握手完成 | 连接就绪，数据事件可发 |
| `数据流级` | 生成器按配置逐块 emit | 字节块序列；step/nop 控制时序 |
| `会话级` | sessions[i] 开始 | 每条会话独立（§4.3） |

### 4.3 多会话（sessions）：串口多路复用

真实 NPort（如 NPort 5130，3 口）可以同时透传多条串口；本项目用**多 flow**（sessions>1 → 策略级 flow_control `{"type":"flows","value":N}`）或**单 flow 一串会话**两种方式表达。

**v1 只实现"多会话 = 多 flow"**（与 modbus/dnp3/enip 的"链一次一个 flow"纪律一致）：

| 路径 | 机制 | 局限 |
|------|------|------|
| `sessions` 数组 | 生成器级：同一条 4-tuple 上连续产生 N 条会话（复用 TCP 连接？——**否**） | v1 **不支持**：不在一条 TCP 连接上顺序复用（真实 NPort 单连接即单串口，多串口 = 多监听端口 = 多 4-tuple）。生成器 + validator 双拒绝（enip session_count 同款先例） |
| **多 flow** | 策略级 `strategy_fc: {"type":"flows","value":N}` → worker 自动递增 src_port（12345+i）产 N 条独立 4-tuple / 独立 TCP 连接 | **v1 采用**。每条 flow 一条 TCP 连接 = 一个串口会话，src_port 递增模拟真实多主站/多刷 |

负条件下（`sessions>1` 在单 flow 里）的显式拒绝见 §9 E-S3。多 flow 覆盖散落在用例 `moxa_sessions_multi`（§6 S4）。

### 4.5 时序（timing）：块间空转与速率（v1 取舍）

串口透传的"节奏"来自两个源，本设计按 v1 裁剪：

| 源 | 表达 | v1 | 说明 |
|----|------|----|------|
| 块间停顿（真实的串口 byte clock / 设备应答延时） | `pack_ms`（`MOXAConfig.Pack`） | **不实现**（预留字段，规划 = 相邻块间 `SessionState.Step` 空转） | 见 §5.1 字段注释；负路径/验收不含它 |
| 整体速率（主站轮询节奏） | 策略级 bps（task/strategy 层 flow control） | 可用 | `strategy_fc`/`strategy_stats` 既有能力，非协议层职责 |

**为什么 `pack_ms` 不在 v1 实现**：
1. 它能被**策略级 bps** 覆盖 95% 的用途（给整体流限速，等效于拉大块间隔）；
2. 块级空转在事件模式里的落点是 `SessionState.Step`，改一次驱动链路（enip 同款字段也是"规划未实现"），为单一时序字段改驱动不值；
3. 测试框架对块间停顿的断言（时间戳间隔）`-race` 下不稳定（计时断言易 flaky）——留到有稳定断言手段再做。

**真实 NPort 的节奏不可复刻**：串口波特率、字节到达是被测设备的物理属性，生成器只保证"块序列 + 可选速率"，不断言包间微秒级时距（与真实快照行为一致，§4.6 差异表已记）。

### 4.6 与 legacy 语义的差异（文档化 divergence，先例 enip/modbus）

| 维度 | 真实 NPort（不作网络契约） | 本项目生成 |
|------|---------------------------|-----------|
| 串口字节到达时刻 | 设备任意时刻到达，NPort 立即转发 | 生成器按配置序列顺序 emit |
| TCP 段边界 | NPort 固件决定（可合并/可拆） | tcp 层按 MSS 分段，事件独立成段 |
| idle 行为 | 无数据时纯 keep-alive（静默） | 无数据块时静默（挥手前） |
| up/up 背靠背 | 同一条段合并 | 两个独立事件 → 两条段（无契约，测试用 exact count 断言固定） |


---

## 5. 配置类型定义

### 5.1 `MOXAConfig`（Go struct 草案）

配置经 `spec.MOXA`（`core.FlowSpec.MOXA *MOXAConfig`）flat 键携带，layers 数组条目零负载（`{"moxa":{}}`）。以下为类型定义与字段语义（`core/types.go` 规划）：

```go
// MOXAConfig 是 Moxa NPort 透明透传（TCP Server 模式）的配置。
// 一次性 flow = 一串串口字节块（stream），由 moxa 终结层生成器把每个
// 块翻译成一个 MessageEvent（方向 + 完整字节），TCP 语义（握手/seq-ack/
// 挥手/MSS 分段）交给 tcp 层生成器（enip/modbus 同款纪律）。
type MOXAConfig struct {
    // Stream 是串口字节流：按序逐块 emit。每个块是一个方向 + 一段字节。
    // 缺省 = 单块 up payload "hello"（冒烟）。空 Stream 与空块是校验错误
    // （§9 E-T1）。
    Stream []MOXAStreamBlock `json:"stream,omitempty"`

    // Pack 是为对齐真实 NPort 行为的可选时序字段：块间停顿（毫秒）。
    // 缺省 0 = 背靠背立即发送。实现定位：等价于相邻块之间
    // SessionState.Step 的空转（见 §4.2 "数据流级"状态）。
    Pack uint32 `json:"pack_ms,omitempty"`

    // Sessions 与多流展开。v1 只支持 Sessions<=1（一条 TCP 连接 = 一条
    // 串口会话）；>1 由生成器 + validator 双拒绝（enip session_count 同款
    // 先例），多会话用策略级 flow_control {"type":"flows"} 表达
    // （§4.3 多 flow）。
    Sessions int `json:"sessions,omitempty"`
}

// MOXAStreamBlock 是串口字节流的一个块。
type MOXAStreamBlock struct {
    // Direction 是方向：空 / "up"（默认）= 主站→NPort（客户端→服务器）；
    // "down" = NPort→主站（服务器回字节，客户端应答）。
    Direction string `json:"direction,omitempty"`
    // Payload 是文本载荷（UTF-8 原样发）。
    Payload string `json:"payload,omitempty"`
    // PayloadB64 是二进制载荷（Base64）；与 Payload 互斥，优先于 Payload
    // （byte 无法进 JSON 的直接给 b64）。
    PayloadB64 string `json:"payload_b64,omitempty"`
}
```

### 5.2 字段默认、范围与校验（对应 §9 错误表）

| 字段 | 类型 | 默认 | 合法范围 / 约束 | 负面 → E 编号 |
|------|------|------|----------------|--------------|
| `stream` | array | `[{payload:"hello"}]` | 非空；每块非空 | E-T1 |
| `stream[].direction` | string | `""` = "up" | `""`/`"up"`/`"down"` | E-T2 |
| `stream[].payload` | string | `""` | 与 `payload_b64` 二选一且非空 | E-T1 |
| `stream[].payload_b64` | string | `""` | 合法 Base64；非空则优先 | E-T3 |
| `stream[].payload` 长度 | — | — | ≤ 2048 字节 | E-B1 |
| `pack_ms` | uint32 | 0 | —（实现期定位：事件间空转） | — |
| `sessions` | int | 1 | ≤ 1（v1） | E-S3 |
| 顶层 `dst_port` | uint16 | 4800 | 1..65535；显式覆盖默认 | E-T4 复用 tcp 校验 |

### 5.3 tcp 层 schema 的联动语义

`tcp` schema（chain 自动补全）在本协议上的生效语义：

| tcp 字段 | 本协议语义 |
|---------|-----------|
| `handshake`（默认 true） | 必须 true：透明透传的串口会话必然先建 TCP 连接。显式 false = 校验拒绝（E-T5） |
| `termination`（默认 true） | 可 false（长连接不主动挥手）。默认 true 对应"测试会话发完即断"。RST 由 `rst` 控制 |
| `mss` | 分段粒度：payload 超 MSS → 多段（S2/S3 覆盖）；MSS 有效范围校验走 validateSpecBase |

### 5.4 TCP Server 语义提醒（生成方向）

本协议是 **degraded/server 语义的表达**：客户端（本生成器）主动连接并**先发**串口（up），服务器（NPort）回下数据（down）。因此：
- 第一个数据块默认 `up`（客户端说话）。
- `direction:"down"` 块 = 服务器（NPort）回给串口设备主人的数据——**不换 IP 方向**，只换 TCP 段的方向（src/dst 端口对换），由 tcp 层事件模式处理（generator.go 的 `!ev.Up` 分支）。
- 与 SIP/Modbus 等"客户端请求-服务器应答"对象模型一致，无需额外配置。

### 5.5 默认端口（4800 两家之辨）

`validateSpecBase` 的 `dst_port` 默认化：`case "moxa": spec.DstPort = 4800`。这是 **TCP 数据口**（NPort 出厂默认监听）。UDP 4800 配置协议不生成（§3.2）。用户显式写 `dst_port` 时 4800 默认被覆盖（用户 > 默认）。用例一律显式写 4800 并把 `tcp.dstport==4800` 纳入断言（§1.4 纪律）。

### 5.6 配置实例（spec_json 样例，与 testcase 文档 §2 对应）

以下每个块可直接作为 pcap 用例的 `spec_json`（用例文件 `cases/moxa.json`、`27-moxa-testcase.md` §2、§7 索引与本表互引）。

**实例 1 — S1 单向上行（最简冒烟）**

```json
{
  "layers": [
    {"tcp": {}},
    {"moxa": {}}
  ],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "src_port": 0,
  "dst_port": 4800,
  "moxa": {
    "stream": [{"payload": "hello"}]
  }
}
```

> 说明：`dst_port` 是**顶层 spec 字段**（enip/modbus 同款：端口属于 4-tuple，不属于层 config）；`{"moxa":{}}` 层条目**零负载**，数据全在 `moxa` flat 键。

**实例 2 — S2 超 MSS 分段（多段串口数据）**

```json
{
  "layers": [
    {"tcp": {"mss": 1460}},
    {"moxa": {}}
  ],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "dst_port": 4800,
  "moxa": {
    "stream": [{"payload": "<2000 个 A>"}]
  }
}
```

> 注：上例示意结构（payload 用占位符）。完整测试需 **2000 字节** payload（>MSS1460 且 ≤2048 = E-B1 之下，见下"冲突修正"）：用例文件里内联 2000 个 `A`（单行 JSON，json.load 可解析；`<2000 个 A>` 是书写占位符）。

**实例 3 — S3 双向流（pattern 多段，响应方向）**

```json
{
  "layers": [
    {"tcp": {"mss": 536}},
    {"moxa": {}}
  ],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "dst_port": 4800,
  "moxa": {
    "stream": [
      {"direction": "up",   "payload": "WR（48 字节）"},
      {"direction": "down", "payload": "RT（48 字节）"},
      {"direction": "up",   "payload": "WR"},
      {"direction": "down", "payload": "RT"}
    ]
  }
}
```

**实例 4 — S4 多会话（策略级多 flow）**

```json
{
  "strategy_fc": {"type": "flows", "value": 3},
  "layers": [
    {"tcp": {}},
    {"moxa": {}}
  ],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "dst_port": 4800,
  "moxa": {
    "stream": [{"payload": "hello"}]
  }
}
```

> S4 顶层不写 `src_port`（worker 递增 12345/12346/12347），见 §6 S4。

**实例 5 — S6 IPv6 载体**

```json
{
  "layers": [
    {"tcp": {}},
    {"moxa": {}}
  ],
  "src_ip": "2001:db8::1",
  "dst_ip": "2001:db8::2",
  "dst_port": 4800,
  "moxa": {
    "stream": [{"payload": "hello"}]
  }
}
```

> S2-M-Size 冲突修正（**重要一致性**）：§6 S2 原本以 3000 字节做分段示例，但 3000 > `MaxBlockBytes`(2048) = E-B1 负路径，两者矛盾。修正：S2 分段用例 payload 取 **1600 + 1600 = 3200 → 但 3200 仍 >2048**。可用：`payload` 单块上限 2048 与 MSS 分段上限（1460）之间必有间隙——**单块即可被分段**。取 **2000 字节**（>1460, ≤2048）：MSS1460 时拆成 1460 + 540 两段，同时在 E-B1 之下。testcase 文档与 case 文件统一用 **2000**（`"A"×2000`）。这避免"用例自相矛盾地同时满足分段与超长拒绝"。

### 5.7 期望帧摘要（从 §6 场景抽取的断言，实施对照表）

以下把 §6 各正场景的**可断言观察量**抽取成表，可作为 `expect` 的直接来源（`27-moxa-testcase.md` §3 与 cases JSON 共用）：

| 场景 | 断言类型 | 值 | 说明 |
|------|---------|----|------|
| S1 | `packet_count` | 8 | 3 握手 + 1 数据段 + 4 挥手（事件模式无独立 ACK，§8.2） |
| S1 | `has_handshake` / `negotiated` / `terminates` | true | 首包 SYN；有 SYN+ACK；尾 3 包内 FIN |
| S1 | `fields.tcp.dstport`（packet 4） | 4800 | 数据包目标端口 |
| S1 | `frames.packet=4` offset=54 | `68 65 6c 6c 6f` | "hello" |
| S2 | `packet_count` | 9 | 3 握手 + 2 数据段（1460+540）+ 4 挥手 = 9 |
| S2 | `frames.packet=4`/`packet=5` offset=54 | `41` | 段1=包4、段2=包5（无独立 ACK） |
| S2 | `has_payload` | true | 段帧长 1514>80（唯一适用者） |
| S3 | `packet_count` | 11 | 3 握手 + 4 数据块 + 4 挥手 = 11（每块 1 包） |
| S3 | `directional` | true | ≥2 个不同 ip.src |
| S3 | `fields.tcp.srcport`（packet 5） | 4800 | 首个 down 包 src_port=4800（端口对换） |
| S3 | `frames`（packet 4 / packet 5, offset 54） | `57 52` / `52 54` | "WR"/"RT" |
| S4 | `packet_count` | 24 | 3 流 × 8 包（stream FC flows=3） |
| S4 | `fields[0].distinct_values` tcp.srcport（distinct_exclude=[4800]） | [12345,12346,12347] | 多流聚合 |
| S4 | `fields[0].distinct_values` tcp.dstport（distinct_exclude=[12345,12346,12347]） | [4800] | 恒为 4800（滤握手/挥手下行包 dst=客户口） |
| S5 | `packet_count` | 8 | 同 S1 结构 |
| S5 | `frames.packet=4` offset=54 | `68 61 68 61` | "haha" |
| S6 | `packet_count` | 8 | 同 S1 结构（IPv6） |
| S6 | `fields.ipv6.src` / `ipv6.dst` | 2001:db8::1 / 2001:db8::2 | IPv6 载体 |
| S6 | `frames.packet=4` offset=74 | `68 65 6c 6c 6f` | "hello" |

> 事件模式（§8.2）下数据段**不插独立对端 ACK**（piggyback），故 S1/S5/S6=8、S2=9、S3=11、S4=24 全部精确确定，均用 `packet_count` 而无需 `min_packets`。仅 S2 因段帧长 1514>80 设 `has_payload`；其余正向载荷帧长 ≤80（补零到 60），不设该断言（VerifyPcap `frame.len>80` 阈值）。

---

## 6. 包序列场景（HexDump S1-Sn）

> 约定：以下场景的**字节**是**本项目生成器将产出的确定性字节**（TCP 握手/挥手由 tcp 层生成器按固定语义产出）。**没有任何字节来自"待定"的配置协议**（§3.2）。IPv4 时以太网头 14B + IPv4 头 20B + TCP 头 20B = TCP 载荷偏移 **54**；TCP 带选项（SYN 带 MSS 选项）时握手载荷偏移 60。IPv6 时偏移 **74**（40B IPv6 头）。

### S1 单向上行字节流（固定 payload 单块）

- 场景：主站连 NPort，发送一块固定串口数据 "hello"。
- 配置：`dst_port:4800, moxa:{stream:[{payload:"hello"}]}`（tcp 默认握手/挥手）。
- 包序列（`packet_count = 8`）：
  - **计数会计**：握手 3（SYN/SYN-ACK/ACK）+ 数据阶段 1（数据段 1，事件模式无对端 ACK）+ 挥手 4（FIN/ACK/FIN/ACK）= **8**（§8.2 事件模式纪律）。

| # | 方向 | flags | 载荷 | 载荷偏移 | 说明 |
|---|------|-------|------|---------|------|
| 1 | up | 0x02 SYN | — | — | 握手 |
| 2 | down | 0x12 SYN\|ACK | — | — | 握手 |
| 3 | up | 0x10 ACK | — | — | 握手 |
| 4 | up | 0x18 PSH\|ACK | `68 65 6c 6c 6f` | 54 | 数据（"hello"） |
| 5 | up | 0x11 FIN\|ACK | — | — | 挥手 |
| 6 | down | 0x10 ACK | — | — | 挥手 |
| 7 | down | 0x11 FIN\|ACK | — | — | 挥手 |
| 8 | up | 0x10 ACK | — | — | 挥手 |

- **hex $S1-1（packet 4, offset 54）**：`68 65 6c 6c 6f` —— 客户端发串口数据。
- **hex $S1-2（packet 1, offset 34）**：`00 02`（SYN flags 简验证，可选）。

### S2 超 MSS 分段（多段串口数据）

- 场景：主站发一条 > MSS 的串口数据（2000 字节，**受限于单块上限 2048 = E-B1，见 §5.6 冲突修正**），tcp 层按 MSS（默认 1460）拆成 2 段，段间 piggyback（事件模式无独立 ACK，§8.2）。
- 配置：`mss:1460`（tcp 层默认），`stream:[{payload:"A"×2000}]`（"A" 0x41 → `1460 + 540` 两段；2000 在 E-B1 之下、在 MSS 之上，恰是"可分段的正向"与"超长拒绝的负向"之间的合法夹缝）。
- 包序列（`packet_count = 9`）：握手 3 + 数据阶段 `(up,PSH|ACK,1460B 0x41)` → `(up,PSH|ACK,540B 0x41)`（段间无独立 ACK）+ 挥手 4 = **9**。段1=包4、段2=包5。
- **hex $S2-1（packet 4, offset 54）**：`41 × 前若干字节` —— 断言首 byte `41`。**hex $S2-2（packet 5, offset 54）**：`41` —— 第二段（540B）首字节同为 A（事件模式下段间无 ACK 包，段2 紧跟段1）。
  - 注：下界断言（FrameAssert 首字节 + `has_payload` 1514>80 + packet_count=9）足以证明分段，全部 2000 字节逐字节断言没必要（Testing Policy：断言可观测结果而非穷举）。
- **seq 会计（MSS 分段正确性的可观测佐证）**：两数据段的 TCP 序号连续（2nd 段的 `tcp.seq == 1st 段的 seq + 1460`）。事件模式段间**无独立对端 ACK**（piggyback，§3.1/§8.2）：每段 `tcp.ack` = 对端当前 seq（常数），不是"对端 ACK 同值确认"的独立回包。用例断言两段 `tcp.seq` 的算术关系（`fields` 用两个包的 `tcp.seq`；若框架不支持跨包算术，则退化为断言"第二段 `tcp.seq` 非 0 且与首段不同" + `has_payload` + packet_count=9（段间无 ACK 包的可观测证据），见 testcase 文档 §4.2）。
- 场景价值：**"payload 超长 > MSS"是强制负路径（E-B2）的反面**——这个 S 场景是"超长但合法（被分段）"的正向对照。

### S3 双向流（请求 + 响应，pattern 多段）

- 场景：主站连 NPort 后发两条 up 数据（pattern payload），NPort 回两条 down（response）。演示"转发到串口、串口回填"的典型轮询。
- 配置：`tcp:{mss:536}`（最小合法 MSS，§9 E-B2 对照边界），`stream:[{up,payload:"WR"}×48B pattern, {down,"RT"}×48B pattern, {up,"WR"}, {down,"RT"}]` —— 用固定文本代替 pattern 表达式（本项目配置无 pattern 语法，**payload 即字面量**；多条块即为"多段"）。
- 包序列（`packet_count = 11`）：握手 3 + 数据阶段 4 块各 1 包（`up(0x18 WR)`→`down(0x18 RT)`→`up(0x18 WR)`→`down(0x18 RT)`，事件模式每块 1 包、段间无独立 ACK，§8.2）+ 挥手 4 = **11**。数据块 1=包4（WR）、块 2=包5（RT）。
- **hex $S3-1（第一个 up 数据包=包4, offset 54）**：`57 52`（"WR"）。**hex $S3-2（第一个 down 数据包=包5, offset 54）**：`52 54`（"RT"；此包 **src_port=4800、dst_port=客户端**——断言 `tcp.srcport==4800`）。
- 场景价值：双向断言（`directional:true`）+ 服务器字节方向端口对换（事件模式 down 分支）。

### S4 多会话（多 flow）

- 场景：策略级 `strategy_fc:{"type":"flows","value":3}`，把同一 moxa 配置生成 3 条独立 TCP 连接（worker 自动递增 src_port 12345/12346/12347）。
- 包序列（`packet_count = 24`）：3 × (握手 3 + 数据 1 + 挥手 4) = **24**（各 flow 完整，事件模式无独立 ACK）。
- 断言（多流聚合，`fields[].distinct_values` + `distinct_exclude`）：`tcp.srcport` 恰取 `["12345","12346","12347"]` 且无其他（distinct_exclude 滤掉下行握手/挥手包 src=4800）；`tcp.dstport` 全 = 4800（distinct_exclude 滤掉下行包 dst=12345-47）。
- **hex $S4-1**：任一条连接的首个数据包 offset 54 `68 65 6c 6c 6f`（"hello"）。调度交织非确定，**不逐包定位**（§—— 用 flows 覆盖 + distinct_values 断言，这是本项目多流用例的既定纪律）。
- 场景价值：多串口会话 = 多连接语义（§4.3 v1 取舍的直接体现）。

### S5 二进制载荷（payload_b64）

- 场景：串口传二进制（如仪表帧），Base64 表达：`A1`（0x01 0x02 0x1f 0x1b...），取 `aGFoYQ==`（= "haha"）做示例。
- 配置：`stream:[{payload_b64:"aGFoYQ=="}]`（解码 = "haha" → 68 61 68 61）。
- **hex $S5-1（数据包 offset 54）**：`68 61 68 61` = `aGFoYQ==` 解码。双向佐证：Base64 解码正确、二进制原样透传。

### S6 IPv6 载体

- 场景：IPv6 环境下的透明透传（NPort 支持 IPv6 型号），仅换 IP 版本，字节流/序列同 S1。
- 配置：`src_ip:"2001:db8::1", dst_ip:"2001:db8::2"`。
- **hex $S6-1（数据包 offset 74 = 14+40+20）**：`68 65 6c 6c 6f`。断言 `ipv6.src==2001:db8::1`、`ipv6.dst==2001:db8::2`、`tcp.dstport==4800`。
- 注意：TCP 校验和覆盖 IPv6 伪头（RFC 8200 §8.1），合法帧要求 checksum 非 ILLEGAL——专家信息断言覆盖。

### 负向场景（N，无包）

负路径**不产出包**（任务被拒绝），无 hex（HexDump 场景只覆盖正向）。负向列于 §9 并映射到 testcase 文档 §5 的 expect_error 用例。HexDump 断言惯性陷阱提示：**不要**给 expect_error 用例写 frames 断言（VerifyPcap 对 ExpectError 直接返回空问题，frames 检查被跳过）。

### 6.1 帧解剖（frame anatomy）：数据段的可观测部位

对任何 S 场景的数据段，用下表钉死"哪一段字节是串口数据"，供测试在 FrameAssert 里取 offset：

| 载体 | 载荷偏移（offset） | 计算 | 场景 |
|------|-------------------|------|------|
| 以太网 + IPv4 + TCP（无选项） | **54** | 14 + 20 + 20 | S1-S5 |
| 以太网 + IPv4 + TCP（SYN 带选项） | 60 | 14+20+20+4（MSS 选项 4B）×... （此值仅对握手/带选项段成立） | 握手包 |
| 以太网 + IPv6 + TCP | **74** | 14 + 40 + 20 | S6 |
| 以太网 + VLAN + IPv4 + TCP | 58 | 14+4 + 20 + 20 |（VLAN，扩展） |

> 帧头不带 VLAN 时 offset=54；带 VLAN 每加一层在帧头吃 4 字节。用例都不带 VLAN（§10 映射存在但用例从简）。

**FrameAssert 语义提示**：`FrameAssert` 在 offset 处做 **十六进制前缀匹配**（verify.go `MatchHexOffset`），断言的 hex 不必覆盖整包——只放载荷首字节足够证明"串口数据在正确位置、内容正确"。S2 中我们只断言首字节 `41`（无需全 1460 字节），正是该语义的用法。

### 6.2 IP 版本与校验和专家信息（S6 的隐含断言）

S6（IPv6）在 WatchExpertInfo 里的含义（verify.go `CheckExpertInfo`）：
- TCP 校验和覆盖 IPv6 伪头（RFC 8200 §8.1），tshark `tcp.checksum.status` 若为 4（ILLEGAL）= 帧缺陷（0x0000 校验和），用例 FAIL；
- v1 语义：TCP 校验和由 tcp 层生成器计算（先例：IPv6 伪头计算已有），专家信息断言**自动覆盖**（CheckExpertInfo 是全用例默认跑），不额外配置 expect 字段。

### 6.3 单块长度 × MSS 的关系（分段矩阵，S2 的量化背景）

测试在选 payload 大小时必须在三条约束里取交，单一来源是 §2.3/§5.1：

| 约束 | 数值 | 来源 |
|------|------|------|
| payload 必须 > MSS 才触发分段 | MSS 由 tcp.mss 定（默认 1460；S3 用 536） | tcp schema |
| payload 必须 ≤ `MaxBlockBytes`(2048) 才合法（否则 E-B1） | 2048 | §2.3 |
| 分段后每段 ≤ MSS | 1460 / 536 | tcp 层 |

组合出的合法取值窗口（**单位字节简表**）：

| MSS | 可触发分段的最小 payload | ≤E-B1 的最大 payload | 段数 | 例 |
|-----|------------------------|---------------------|------|----|
| 1460 | 1461 | 2048 | 2（1460+540@2000） | S2（用 2000） |
| 536 | 537 | 2048 | 4（536×3 + 392@2000） | 若需要更多段 |

> 结论：**payload=2000 是通用的"分段定义段"**（1460 下 2 段、536 下 4 段，均 ≤2048）。S2 选 2000、MSS1460；S3 用短块（48B）演示双向而不分段。若未来需要"3+ 段且单块合法"，只能靠降 MSS（如 536）；用超过一个块（多块各成段）仍是另一种多段来源（但那是事件多段而非 MSS 拆分，两种语义不同——§3.4 已区分）。


---

## 7. 与 testcase 文档的映射索引

用例编号（正向 T-MOXA-S<n>-<m>，负向 T-MOXA-NEG<n>）与 `27-moxa-testcase.md`、`cases/moxa.json` 一一对应（id 命名 `moxa_*`）：

| 设计场景 | 用例编号 | 用例 id（JSON） | 断言要点 |
|---------|---------|----------------|---------|
| S1 单向上行（固定 payload 单块） | T-MOXA-S1-01 | `moxa_single_up` | packet_count=8、握手/挥手、tcp.dstport=4800、hex 首块 |
| S1 变体：payload 内容 | T-MOXA-S1-02 | 并入 `moxa_single_up` | hex 前缀匹配 68 65 6c 6c 6f @54（payload 帧长 60<80，不设 has_payload） |
| S2 超 MSS 分段 | T-MOXA-S2-01 | `moxa_multi_segment` | 数据段 >MSS、hex 手字节、段数 |
| S3 双向流 | T-MOXA-S3-01 | `moxa_bidirectional` | directional、tcp.srcport=4800 于 down 段、up/down hex |
| S4 多会话（多 flow） | T-MOXA-S4-01 | `moxa_sessions_multi` | distinct tcp.srcport [12345,12346,12347]、dstport 恒 4800 |
| S5 二进制 payload | T-MOXA-S5-01 | `moxa_binary_payload` | hex = b64 解码结果 |
| S6 IPv6 载体 | T-MOXA-S6-01 | `moxa_ipv6` | ipv6.src/dst、tcp.dstport=4800、hex 偏移 74 |
| N-1 空 payload | T-MOXA-NEG-01 | `moxa_neg_empty_payload` | expect_error、error_contains |
| N-2 字节块为配置报文 | T-MOXA-NEG-02 | `moxa_neg_config_packet` | expect_error（显式拒绝"配置字节班车"） |
| N-3 sessions>1 | T-MOXA-NEG-03 | `moxa_neg_sessions_multi` | expect_error（v1 拒绝，多会话走多 flow） |
| N-4 handshake=false | T-MOXA-NEG-04 | `moxa_neg_no_handshake` | expect_error |
| N-5 非法 base64 | T-MOXA-NEG-05 | `moxa_neg_bad_b64` | expect_error |
| N-6 超长单块 | T-MOXA-NEG-06 | `moxa_neg_oversize` | expect_error（E-B1，>2048） |
| N-7 非法方向 | T-MOXA-NEG-07 | `moxa_neg_bad_direction` | expect_error、error_contains（E-T2，"moxa: invalid direction"） |

---

## 8. 实现集成点

> 以下为**规划**（本文档是设计稿，代码未写）的落点清单；各点均按先例（enip/doip/modbus）位置对齐。

### 8.1 文件与函数

| # | 位置 | 动作 |
|---|------|------|
| I1 | `trafficgen/internal/core/types.go` | 新增 `MOXAConfig` + `MOXAStreamBlock`（§5.1），`FlowSpec.MOXA *MOXAConfig` |
| I2 | `trafficgen/internal/core/layers/registry.go` | 注册层：`Name:"moxa", Category:CategoryTerminal, DependsOn:["tcp"]`（零 config 字段注释同 enip） |
| I3 | `trafficgen/internal/core/strategy_convert.go` | `case "moxa":` 解析 `spec.MOXA = parseMOXAConfig(cfg["moxa"])`；`dst_port` 缺省 4800（modbus 同款） |
| I4 | `trafficgen/internal/core/layers/chain_planner.go` | `validateSpecBase` 加 `case "moxa":` 两项：`SrcPort==0` 保持（modbus 同款）；`DstPort==0 → 4800` |
| I5 | `trafficgen/internal/core/layers/chain_planner.go` | `drive()` 的 `meta` 注入 `MOXA: spec.MOXA` |
| I6 | `trafficgen/internal/protocol/moxa/moxa.go`（新） | `Planner{}.Validate`：§9 全错误表；`Planner{}.Plan`：默认端口后落层链（`NewChainPlanner("moxa")` 先例） |
| I7 | `trafficgen/internal/protocol/moxa/layer_gen.go`（新） | `MOXAGenerator`：genEvents + `Generate`（逐块 emit MsgEvent）+ `GenEvents` 标记 + E-前端拒绝（enip 同款纪律） |
| I8 | `trafficgen/internal/protocol/moxa/moxa_test.go`（新） | 单测（spec 派：§9 每行 + §6 每场景）；review 后跑 `go test -race` |
| I9 | `trafficgen/internal/core/convert.go` | `validProtocols` 两处加 `"moxa": true`（单/批）；`validateSpec(t)` 加注册（先例 list） |
| I10 | `trafficgen/cmd/server/main.go` | 注册 `protocol.Register(&moxa.Planner{})` |

### 8.2 生成器行为契约（事件模式的细节）

图 `MOXAGenerator.Generate` 伪序（含错误路径排空，tftp P4a 样板）：

```
1. req.Meta.MOXA == nil → 显式 error（spec.moxa 缺失；validator 先拒绝，双保险）
2. stream 缺省 → [{payload:"hello"}]（冒烟）；空 stream → error（E-T1）
3. 每块：
   a. 合并 payload / payload_b64（b64 优先；都空 → E-T1）
   b. length > MaxBlockBytes(2048) → E-B1
   c. direction 规范化（""/"up"→Up=true；"down"→Up=false；其他 → E-T2）
   d. select ctx.Done（取消双路径，tftp 样板）
   e. EmitMsg({Up, Bytes: payload})
4. 返回（事件流关闭 → tcp 层进入挥手）
```

**关键纪律**（继承 modbus/enip）：
- 生成器不得跳过 validator 的拒绝（多重跳拒绝）。
- 多 flow 展开（worker 的 `flowCount>1` 自动递增 src_port）不属协议层，生成器不需要感知；`sessions>1` 才由生成器拒绝（E-S3，enip session_count 同款位置）。
- 事件流错误经 `select ctx.Done → return ctx.Err()` 逃生（防 transport 停消费后挂死）。

### 8.3 测试接线（协议 pcap 框架）

- case 文件：`trafficgen/test/protocol_pcap/cases/moxa.json`（§7 表，13 例 = 6 正 + 7 负）。
- 断言工具全可用：`has_payload`/`directional`/`has_handshake`/`terminates`/`negotiated`/`packet_count`/fields/`frames`（FrameAssert 前缀匹配）/`expect_error`+`error_contains`。
- 多会话（S4）用 `strategy_fc: {"type":"flows","value":3}`（pcaptest.StrategyFC，多流用例先例见 sv）——worker 递增 src_port，`distinct_values` 聚合断言。
### 8.4 实现验收标准（Definition of Done，与测试策略挂钩）

代码实现（I1-I10 全部落地）后，验收必须满足以下才可视为"完成"（映射回 CLAUDE.md Testing Policy 八条）：

| # | 验收项 | 对应 Policy |
|---|--------|------------|
| A1 | `go build ./...` + `go vet ./...` + `go test ./internal/protocol/moxa/ -race` 全绿 | — |
| A2 | 单测覆盖 §9 错误表**每一行**（E-T1..E-T5、E-B1、E-S3、N-2），负向必须断言返回的错误字符串（error_contains 等价物），不只断言失败 | Policy §1（spec 驱动）、§3（一行一测） |
| A3 | 单测覆盖 §6 每个正向场景（S1-S6）：断言 `MessageEvent` 序列（方向 + 字节正确）与 tcp 层分段交互（T-MOXA-S1-01..S6-01） | Policy §1 |
| A4 | 每个 validator 拒绝理由都能**观测到任务失败**（e2e：流经 API→engine 后 task.status=failed）——不许"吞错成 0 包成功" | Policy §4（集成）、已知 0-packet guard 陷阱 |
| A5 | `moxa_*` pcap 用例（13 例 = 6 正 + 7 负）经 `CASE_PROTO=moxa go test ./test/protocol_pcap/ -run TestProtocolPcapDrive` 全 PASS（tshark 校验） | Policy §4（端到端） |
| A6 | pcap 用例的 expect_error 全部确实失败（`tools_testdrive.go` runOneCasePcap 语义：validate 拒绝即 PASS、产出空流即 FAIL） | Policy §2（失败路径） |
| A7 | `-race` 下 e2e 全跑无竞态 | Policy §6 |

> 注意 A4/A6 是"负路径双层"在验收层的体现：validator 拒绝了（A2），还必须穿透到任务状态失败（A4/A6）——这正是本项目审计教训（planner 错误被吞成 0 包成功）的直接对冲。

### 8.5 实现风险登记（risks，实施前先读）

| 风险 | 等级 | 说明 | 缓解 |
|------|------|------|------|
| R1：tcp 层事件模式对 down 块的处理（src/dst 端口对换）未经验证 | 中 | S3 依赖事件模式 `!ev.Up` 分支正确交换端口；若 tcp 层该分支有缺，down 包方向错 | 实施时先用 S3 用例跑，验证 `tcp.srcport==4800`（A5 前置） |
| R2：`strategy_fc: flows` 与终结层共存 | 中 | S4 依赖 worker 自动递增 src_port；若 moxa 终结层不透明地吞掉该机制，多流不展开 | 与 sv/enip 的多流用例对比，确认 `distinct_values` 断言生效 |
| R3：`MaxBlockBytes=2048` 与 MSS 分段的交叠 | 低 | 2000B 块在 MSS1460 下分段——需 tcp 层确信按 MSS 拆；若事件模式对超 MSS 事件不拆而整发，S2 失效 | S2 用例即回归守卫 |
| R4：validator 前置校验吞到 generate 层 | 低 | 生成器前端显式检查（I7）若漏，validator 被绕过 → 空流 | A4/A6 验收 + 生成器前端重复拒绝 |
| R5：UDP 4800 字节布局（待定）被误当"已知" | 高（诚实性） | 若实施者手痒开始编 magic/type 值，即破坏本文档边界 | §3.2 明示 + §9.2 探针拒绝 + §11 修订触发点 |
| R6：多 flow 用例的包数跨 tcp 层 ACK 布局漂移 | 中 | S4 的 24 包依赖于固定握手/挥手结构；若挥手语义变，计数碎 | 事件模式段间无独立 ACK（§8.2），计数确定；仍保留 distinct_values 聚合兜底（§5.7） |

> 治理：R1/R2/R6 由 A5 pcap 套件兜底；R3 由 A2 单测 + A5;R4 由 A4/A6;R5 是文档承诺，违反即违反 §3.2 诚实边界。

---

## 9. 错误处理

> 校验发生在两个层面，双层兜底（enip 纪律）：**validator 层**（`Planner.Validate`，经 `RegisterLayerValidator` 挂到链上，任务创建即同步拒绝）与**生成器层**（Generate 前端显式检查，防"validator 被绕过 → 驱动失败被吞成 0 包空流"——本项目已知契约陷阱 chain_planner.go:266-270 的 0-packet guard）。**ExpectError 用例断言任务失败（Testing Policy 第 4 条：失败必须可被观测）。**

### 9.1 错误表（每行 = 一个测试项）

| ID | 条件 | 校验层 | 错误消息要点 | testcase | 文档出处 |
|----|------|--------|------------|----------|---------|
| E-T1 | stream 缺省/空 / 块 payload 与 payload_b64 双空 | validator | "moxa: empty stream block or payload required" | T-MOXA-NEG-01 | §5.1 |
| E-T2 | direction 非法（非 ""/up/down） | validator | "moxa: invalid direction %q, want up|down" | T-MOXA-NEG-07 | §5.1 |
| E-T3 | payload_b64 非法 Base64 | validator | "moxa: invalid payload_b64: %v" | T-MOXA-NEG-05 | §5.1 |
| E-B1 | 单块 payload > MaxBlockBytes(2048) | validator + 生成器 | "moxa: block %d payload %d exceeds max %d" | T-MOXA-NEG-06 | §2.3/§5.1 |
| E-B2 | payload > MSS 但 ≤ 2048（合法，被分段） | 无（正向） | — | T-MOXA-S2-01 | §6 S2 |
| E-S3 | sessions > 1 | validator + 生成器 | "moxa: sessions=%d>1 not supported (multi-sessions: use strategy flow_control flows)" | T-MOXA-NEG-03 | §4.3/§5.1 |
| E-T4 | dst_port 越域 | validateSpecBase | tcp 既有："dst_port N invalid" | （复用 tcp 负例，不单列） | §5.5 |
| E-T5 | tcp.handshake=false | validator（结构） | "moxa: tcp.handshake must be true (serial passthrough needs a TCP connection)" | T-MOXA-NEG-04 | §5.3 |
| N-2 | `config` 文本字节混入 stream（配置/数据混装） | validator（受控） | "moxa: config-packet bytes in stream are not supported (see §3.2)" | T-MOXA-NEG-02 | §3.2/§9.2 |

### 9.2 负路径用例语义（贡献第二个教训：别把"待定"当"能做"）

T-MOXA-NEG-02（`moxa_neg_config_packet`）是本文档**特意加的一条负路径**，与"配置协议字节待定"配套：把一段形如配置报文的字节（魔数 + 命令——**不含真实魔数值**，只是让 payload 以 `0x5a 0x5a 0x5a ...` 这类"看起来像私有协议头"开头）塞进 stream 的 payload，**数据面把它当普通串口字节是"违背本设计的诚实边界"**（字节布局未核实，不能披着"数据面"外衣发送并自证正常）。处置：validator 拒绝该形态（判断依据：payload 前 3 字节 = 0x5a×3，这是测试自定义标记，非协议字节；正式实现可改为拒绝语义明确的"疑似配置报文"前缀，等 §3.2 字节核定后再收窄）。

> 辨析：这不违背"透明透传 = 任意字节"——真实 NPort 对任意串口字节都透传。这条负路径约束的是**测试用例自身**的诚实性（不能假装"待定的配置字节已经被我们发送并断言"），是文档边界对测试边界的传导，不是 NPort 协议限制。

### 9.3 运行期错误（无）

生成器是纯函数式驱动，无运行期可恢复错误（无超时、无握手失败的模拟）。ctx 取消 → 直接返回 ctx.Err()（既有的取消双路径）。**不模拟**"连接被对端拒绝/串口设备无响应"（这些属于真实 NPort 环境行为，不在流量生成范围内）。

---

## 10. 扩展字段映射

| 本设计字段 | 是否生成器使用 | 对应 legacy / 通用 spec | 说明 |
|-----------|--------------|------------------------|------|
| `src_ip/dst_ip` | 是 | FlowSpec 通用 | IPv4/IPv6 载体（S6 覆盖 IPv6） |
| `src_port` | 是 | FlowSpec 通用 | 主站端临时端口；多 flow 由 worker 递增（S4） |
| `dst_port` | 是 | FlowSpec 通用 | NPort 数据监听口（默认 4800，用例显式） |
| `src_mac/dst_mac` | 是 | FlowSpec 通用 | L2 直通（测试框架自动推导，无需用例设置） |
| `vlan_id/vlan_priority` | 是 | FlowSpec.VLAN | 经 worker 传播到包 L2（NPort 常用于产线隔离 VLAN） |
| `ttl/tos/dscp` | 是 | FlowSpec 通用 | L3 直通 |
| `tcp.handshake/termination/rst/mss/window_size/initial_seq` | tcp 层 | spec.TCP | 见 §5.3 |
| `payload`（顶层） | 否（moxa 用 stream 内 payload） | FlowSpec.Payload | 不混用：moxa 数据块在 `stream[].payload`；顶层 payload 由策略层忽略（或未来做"顶层 payload 作为单块"的便利映射——v1 不做） |
| `sessions` cfg 字段 | 否（v1 拒绝>1） | 多流展开扩展位 | §4.3 |
| `pack_ms` | 规划（时序扩展，v1 可能不实现） | SessionState 空转 | §5.1 |
| `payload_b64` | 是 | S5 用例 | 二进制透传 |

**明确的"不映射"**：本协议无 cip/params（enip 的 from_response）、无 transactions（modbus）、无 scenario（dnp3）——串口字节流的"响应"就是 down 方向块。VLAN 与 IPv6 等通用字段的映射完整（见上表），负路径不影响这些映射。

---

## 11. 修订记录

| 版本 | 日期 | 内容 |
|------|------|------|
| v1.0.0 | 2026-08-18 | 初稿。透明透传（TCP Server 语义）v1；UDP 4800 配置协议标注"待定"（不编造字节）；层注册/配置类型/6 个正向场景（S1-S6）/7 条负向用例（N-1..N-7，覆盖 §9.1 错误表错误行 + §9.2 N-2）；实现集成点 8 处。**改动历史补记**：任务为续跑，此初稿即终止态（含"待定"标注本身是设计决定，非遗漏）。第 2 轮复审补：S3 用例补齐 down 段 `tcp.srcport=4800` 与 dstport `distinct_exclude`（F4）；负例删惰性 `has_handshake/terminates/packet_count` 字段与 `§4.7` 声明对齐（F6）；N-7 方向负例独立成行（§7 表、§9.1 E-T2 各 1 行），`12 例→13 例`（F6）。 |

**下一次修订触发点**（自动翻新条件，写入此录以便后人）：
1. 取得可核实的 NPort 配置协议（UDP 4800）字节级资料 → 补 §3.2/§5/§6 的配置面场景与 §9.2 收窄。
2. 决定实现 `pack_ms`（块间停顿）→ 补 §4.2/§5.1/§8.2。
3. 决定做 TCP Client / UDP / Pair Connection 模式 → 扩 §1.1/§6。
4. tcp 层事件模式或 `strategy_fc: flows` 语义变动 → 复核 §5.7/§8.5 R1/R2/R6 的断言假设。

### 11.1 与既有文档的交叉引用（一致性承继）

| 文档 | 关系 |
|------|------|
| `18-layer-config-design.md`（层链配置架构） | 终结层注册/依赖/optional_on 的母文档 |
| `12-enip-design.md` / `13-modbus-design.md` | "TCP 终结层 + flat 键直传"先例，本设计 v1 对齐其行文与结构 |
| `00-unimplemented-list.md`（协议差距清单） | moxa 为待实现项（本设计为其实现前置） |
| `17-dnp3-design.md` 等其余协议设计 | 六章式/十一节式结构承继（本设计采用既有 section 编号体系） |
| `27-moxa-testcase.md` + `cases/moxa.json` | 本文档 §7 的直接下游（用例与断言必须与 §5.7/§6 一致） |

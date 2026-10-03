# #149 TCP（传输控制协议）设计契约

> 版本：v1.0.0（P-PIPE 文档轨批次二 as-built）  
> 日期：2026-09-29  
> 车道：文档轨；本版**不宣称 TCP 已完成 layer-chain 迁移**。  
> 配套用例：`docs/protocol-designs/149-tcp-testcase.md`  
> 机器基线：`trafficgen/test/protocol_pcap/cases/tcp.json`（10 例 = 7 正 + 3 负）

## 0. 范围与边界

TCP 是传输底座，不是终端业务层：本版只定义 TCP 的连接控制、序号/确认号、窗口、MSS、数据分段和终止行为；不定义 HTTP、FTP、TLS 等业务 session，也不把 TCP 自身包装成业务 session。生成器输出 Ethernet/IP/TCP 帧，payload 只是可选字节串。

本版记录当前机器契约和 P4 改造边界。`tcp.json` 的正例仍采用旧 flat 形状，因此不能把现状描述成统一层链已完成；P4 只负责迁移契约、接线和回归，不能借文档提前宣称 suite、pcap 或 NIC 已通过。

## 1. 旧键去向与目标形

### 1.1 当前存量（as-built）

10 例均为 `spec_json` 形状：7 个正例带 `layers:[{"tcp":{}}]`，但与 flat 四元组/`count` **并存**，3 个负例纯 flat（无 `layers`）；部分例追加顶层 `payload` 与 `tcp` 子映射。`layers` 因此尚不是权威配置形状——这是存量事实，不是迁移完成。

### 1.2 门1 §1–§14 对照表

| § | 本协议满足方式 | 证据 |
|---:|---|---|
| 1 | 层链唯一真相；旧 flat 形状和目标形分列登记 | 本文 §1.1、§1.3 |
| 2 | TCP 为传输底座，链目标为 `ip → tcp` | 本文 §0、§2 |
| 3 | 无业务 session；握手、数据、终止和五件套豁免明确 | 本文 §3–§4 |
| 4 | 连接控制、MSS、窗口、RST 的行为矩阵 | 本文 §4–§7 |
| 5 | planner/core 依赖、错误锚词与失败传播 | 本文 §8、§10 |
| 6 | 包数、分段、窗口和内存/流式验收边界 | 本文 §5–§6、§9 |
| 7 | 设计、测试、结果文档分别独立 | `149-tcp-design.md`、`149-tcp-testcase.md`、P5 待生成结果 |
| 8 | 设计先行，P4 仅列迁移边界 | 本文 §11 |
| 9 | 规范要求、代码现状、用例断言三源回指 | 本文 §4–§8、配套 testcase §5 |
| 10 | 缺口与修订按隔离复审闭环 | 本文 §13 |
| 11 | 白话结论是不宣称 layer-chain 已完成 | 本文 §0、§13 |
| 12 | 动态字段与序号算法逐项列出代码位置 | 本文 §12 |
| 13 | schema/layer registry 迁移作为 P4 目标，不冒充现状 | 本文 §1.3、§11 |
| 14 | 真实 REST/引擎/pcap/NIC 流程待 P5，当前无通过证据 | 本文 §11、§13 |

### 1.3 旧键去向附表

以下附表逐键登记 `tcp.json` 实际出现的 8 个顶层键和 6 个 `tcp.*` 子键；它不是门1十四行本身：

| # | 旧键 | 旧语义 | 目标去向（P4） | 当前状态 |
|---:|---|---|---|---|
| 1 | `layers` | 层链容器（7 正例带，形 `[{"tcp":{}}]`） | 保留并扩为 `[ip, tcp]` 权威形 | 已存在但非权威（flat 键并存） |
| 2 | `src_ip` | 源地址 | `layers[].ip.src` | 尚未迁移 |
| 3 | `dst_ip` | 目的地址 | `layers[].ip.dst` | 尚未迁移 |
| 4 | `src_port` | TCP 源端口 | `layers[].tcp.src_port` | 尚未迁移 |
| 5 | `dst_port` | TCP 目的端口 | `layers[].tcp.dst_port` | 尚未迁移 |
| 6 | `count` | 流数量/执行次数 | 顶层 `strategy_fc`/`flow_control` | 尚未迁移；现存为 flat `count` |
| 7 | `payload` | TCP 数据字节 | `layers[].tcp.payload`（或事件 payload 约定） | 尚未迁移 |
| 8 | `tcp` | TCP 子映射容器（flat 顶层） | 并入 `layers[].tcp` 后删除顶层容器 | 尚未迁移 |
| 9 | `tcp.handshake` | 是否发 SYN/SYN-ACK/ACK | `layers[].tcp.handshake` | 尚未迁移 |
| 10 | `tcp.termination` | 是否发 FIN 四步 | `layers[].tcp.termination` | 尚未迁移 |
| 11 | `tcp.mss` | SYN MSS 选项、分段上限 | `layers[].tcp.mss` | 尚未迁移 |
| 12 | `tcp.window_size` | TCP 窗口 | `layers[].tcp.window_size` | 尚未迁移 |
| 13 | `tcp.initial_seq` | 客户端初始序号 | `layers[].tcp.initial_seq` | 尚未迁移 |
| 14 | `tcp.rst` | RST 替代 FIN | `layers[].tcp.rst` | 尚未迁移 |

### 1.3 目标形（迁移目标，不是当前通过形）

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 80, "handshake": true,
              "termination": true, "mss": 1460, "window_size": 65535,
              "initial_seq": 1000, "rst": false,
              "payload": "hello"}}
  ],
  "strategy_fc": {"type": "flows", "value": 1}
}
```

目标形中的 TCP 层仍是传输层配置，不等同于终端业务 session。迁移完成的判据应是：非负例顶层 flat 键清零、层内键可由 registry/validator 接受、负例仍在预期阶段拒绝、旧行为的包数和字段断言逐条保持。

**registry 现状（as-built，防止误读）**：TCP planner 已在生产接线——`cmd/server/main.go:323` 显式 `app.engine.RegisterPlanner(tcp.NewPlanner())`（`tcp.go:434-437` 的全局 `protocol.Register` 自注册为注释，实际不生效）。但仓库**没有** TCP 的 layer schema/Fields/DependsOn 层注册（对照 dns/pop3 等已登记层）；"层内键可由 registry/validator 接受"是 P4 目标，不是现状。

## 2. 协议栈与输出

推荐目标链为 `ip → tcp`；IPv4 起点为 Ethernet(14)+IPv4(20)+TCP(20/含选项)，IPv6 由 `core.EtherTypeFor` 和 `core.L3Base` 选择地址族。TCP planner 位于 `trafficgen/internal/protocol/tcp/tcp.go`，帧构造在 `trafficgen/internal/core/builder.go` 的 `writeTCP`/`encodeTCPOptions`，公共字段和 `TCPConfig` 在 `trafficgen/internal/core/types.go`。

当前 planner 直接消费 `core.FlowSpec`。`Plan` 先 `Validate`，再通过 channel 流式发出 `PacketConfig`；不聚合全流。序列和 IP ID 的随机缺省意味着未经显式配置时只能断言关系和标志，不能钉死绝对 ISN。

## 3. 连接控制与五件套豁免

TCP 传输底座的五件套审计为：

1. 同连接内多轮业务操作；
2. 非正常结束；
3. 长保活；
4. 多载荷/分段；
5. 重传/恢复。

本协议**不定义业务 session**，故第 1 项（同连接多轮业务操作）豁免：TCP 只负责一次连接骨架，业务层（HTTP/FTP 等）负责多轮。第 3 项长保活也不在 TCP planner 的本版契约中：没有 keepalive/think-time 事件；由上层长期会话协议覆盖。第 5 项真实重传/拥塞恢复不模拟，不能从连续 ACK 推导“重传已实现”。

适用项：握手/终止覆盖正常连接控制；`rst:true` 覆盖非正常 RST 终止；payload + MSS 覆盖数据分段。对应例见 testcase §3–§5。此处是协议底座的明确豁免，不为凑覆盖伪造业务 session。

## 4. 状态与握手

默认 `Handshake=true`、`Termination=true`、MSS=1460、窗口=65535；无 TCP 子配置时由 `tcp.go:113-120` 建立这些默认值。握手顺序是 SYN、SYN-ACK、ACK（`tcp.go:159-234`）。SYN/SYN-ACK 携带 MSS、Window Scale(7)、SACK Permitted，选项由 `synOptions`（`tcp.go:85-96`）生成。

`handshake:false` 跳过前三包，payload 可直接从 PSH-ACK 开始；`termination:false` 不发 FIN 四步。`rst:true` 时发单个 RST-ACK，且 `tcp.go:331` 的 `!tcpConfig.RST` 条件阻止 FIN。

## 5. 数据与 MSS

payload 非空时按 `tcpConfig.MSS` 分段，0 回退 1460（`tcp.go:237-301`）；每段发送一个 PSH-ACK，随后一个反向 ACK。每段序号按 payload 字节数递增，ACK 指向对端下一个序号。MSS 校验在 `tcp.go:67-74`：显式值必须为 536..65535；公共转换前的数值范围校验在 `core/validate.go:65-76`。

## 6. 窗口与字段

`window_size` 为 16 位 TCP Window 字段；0 使用默认 65535（planner 的 `winSize` 逻辑，`tcp.go:143-148`）。握手双方使用同一有效窗口。Window Scale 是 SYN 选项，不把后续 tshark 放大值误写成握手原始字段值。

## 7. 终止与 RST

正常终止是 FIN、ACK、FIN、ACK，FIN 消耗一个序号。RST 是互斥替代路径：数据后发 RST-ACK，不再追加 FIN。`tcp-rst-replaces-fin-payload-0123` 是唯一现存 RST 正例；它证明“替换”而不是“先 FIN 后 RST”。

## 8. 校验与失败传播

端口由 `core.ValidateConfigRanges` 做 0..65535 范围保护，防止转换为 uint16 时静默回绕（`core/validate.go:47-55`）；TCP `initial_seq` 在 `ValidateProtocolSubConfigs` 的 `case "tcp"` 拒绝负值（`core/validate.go:65-76`）。planner 再校验 IP、非零端口、MSS（`tcp.go:43-77`）。负例必须在 planner/validator 阶段返回错误，不能完成为 0 包成功任务。

当前三条负例及锚词：MSS 500 → `too small`；`initial_seq=-1` → `initial_seq`；`dst_port=65536` → `dst_port 65536 invalid`。这些都是现状 flat 输入的错误契约，不是迁移后新层校验已完成的证据。

## 9. 包数模型

无 payload、默认握手和终止：3 握手 + 4 终止 = 7 包。无握手、无终止且有 payload：每个数据段 1 个 PSH-ACK + 1 个 ACK。RST 正例：3 握手 + 数据/ACK + 1 RST；具体包数随 payload 分段变化。`min_packets` 只表达下界，`packet_count` 才表达精确值；动态随机 ISN 不改变包数。

## 10. 依赖与非目标

TCP planner 依赖 `core.FlowSpec`、`PacketConfig`、L3/L4 builder；不依赖任何业务协议编码器。非目标包括：真实 socket/connect、拥塞控制、滑动窗口调度、SACK 重传、定时器驱动重传、TLS/HTTP/FTP 语义、业务响应内容。

## 11. P4 改造边界与验收

P4 允许：①为 TCP 层注册字段与载体关系；②把 flat 字段迁入 `ip`/`tcp` 层；③将 `count` 改为 flow-control；④保持 planner 的包序、标志、MSS、窗口、RST 语义；⑤把 10 个旧 ID 的断言映射到新形。

P4 不允许：①把 TCP 宣称为 terminal/business layer；②虚构 keep-alive、重传或业务 session；③把未运行的 suite/pcap/NIC 写成通过；④用随机 ISN 的偶然值冒充确定性契约。只有代码迁移、用例重写、pcap/NIC 实证均完成后，才可在后续文档改状态。

## 12. 动态字段与序号算法

### 12.1 动态字段

| 字段 | 动态/固定口径 | 代码位置 |
|---|---|---|
| `src_ip`,`dst_ip`,`src_port`,`dst_port` | 当前由 `FlowSpec` 固定；目标层形可接策略值 | `core/strategy_convert.go:219-225`；目标接线待 P4 |
| `payload` | 当前 bytes 固定；目标层内 payload/事件值 | `tcp.go:236-301` |
| `mss` | 固定或缺省 1460；分段长度动态 | `tcp.go:239-249` |
| `window_size` | 固定或缺省 65535 | `tcp.go:143-148` |
| `initial_seq` | 显式固定；0 表示随机缺省 | `tcp.go:122-132` |
| `handshake`,`termination`,`rst` | 布尔控制分支 | `tcp.go:158-159`, `304-331` |
| `count`/flows | 当前 flat 执行控制；目标移至 flow-control | `strategy_convert.go` 与任务调度层；P4 接线待定 |

### 12.2 序号算法

客户端 `clientSeq` 取 `spec.TCP.InitialSeq`；为 0 时在 `tcp.go:122-132` 用 `rand.Uint32()`。服务端 `serverSeq` 当前始终由 `rand.Uint32()` 生成。SYN 消耗客户端一个序号，SYN-ACK 消耗服务端一个序号；数据段按 `segmentSize` 增加客户端序号；FIN 各消耗一个序号。ACK 使用对端下一序号。`packetIndex` 从 0 单调递增，用于流内输出顺序；IP ID 从随机起点递增（`tcp.go:133-141`）。

只有设置 `initial_seq` 且测试同时固定/观测另一方向所需关系时，才能断言绝对 raw 序号；tshark relative seq 的展示必须与 raw 字段分开记录。

## 13. 当前缺口与修订记录

- 非负例仍有 flat 顶层键；尚无 TCP layer-chain 迁移证据。
- 当前 cases 没有真正的大于 MSS payload，因此 MSS 多段行为虽有代码和核心测试，未由本 10 例机读钉死。
- 无真实重传、keepalive、业务多轮 session、NIC 或 tracked pcap 证据。
- v1.0.0（2026-09-29）：建立 TCP 底座设计契约，记录 10 例现状、迁移去向、五件套豁免、动态字段和序号算法；未修改代码/JSON，未宣称测试通过。
- v1.0.1（2026-09-29）：隔离复审修正：§1.2 增补真正的 §1–§14 门1 对照表，原 14 个旧键去向降为 §1.3 附表；§1.3 末补记 registry as-built 现状（main.go:323 已显式接线，tcp.go 全局自注册为注释，layer schema/Fields 注册缺失属 P4）。

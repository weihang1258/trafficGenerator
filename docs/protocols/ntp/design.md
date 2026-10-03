# #138 NTP（Network Time Protocol）设计文档

> 版本：v1.0.0（as-built）  
> 日期：2026-09-29  
> 状态：按当前 Go 实现、层注册和 `cases/ntp.json` 编写；不把未进入机器契约的分支宣称为已验收。  
> 配套用例：`testcase.md`；机器契约：`trafficgen/test/protocol_pcap/cases/ntp.json`。

## D1 范围、规范与实现边界

NTP 是 UDP 终结层协议，默认服务端口 123。基本时间报文按 RFC 5905 §7.3 编码；Mode=6 控制报文沿 RFC 1305 Appendix B 的 ntpd control header；扩展字段和认证尾部按 RFC 7822 §4 的长度/对齐约束处理。当前实现路径为 `trafficgen/internal/protocol/ntp/{planner.go,layer_gen.go}`，核心配置为 `internal/core/types.go:NTPConfig`，层注册在 `internal/core/layers/registry.go`，策略映射在 `internal/core/strategy_convert.go`。

当前 JSON 仅证明：空 NTP 配置经 `[udp,ntp]` 生成一个 client request。服务器、广播、对称、控制、私有模式、响应、重复发送、扩展、MAC、IPv6 等代码分支存在，但没有当前 cases 的可执行断言，列入缺口而不是当前覆盖。

### D1-P1 规范要求→场景→现状→缺口矩阵

| 规范要求 | 业务场景 | 代码现状 | 缺口/用例 |
|---|---|---|---|
| RFC 5905 §7.3 LI/VN/Mode、48-byte 基本头 | NTPv4 client request | `planner.go:421-540` 已编码；空层默认 Mode=3/VN=4 | `ntp_smoke_01`；其余模式 G-NTP-2 |
| RFC 5905 §7.3 Stratum/Poll/Precision/四时间戳 | client/server/broadcast | `planner.go:477-540` 已编码 | G-NTP-2/G-NTP-4 |
| RFC 5905 §7.3 Mode 1–7 | symmetric、client、server、broadcast、private | `layer_gen.go:69-208` 分支存在 | G-NTP-2 |
| RFC 1305 Appendix B 控制头 | Mode=6 request/response | `planner.go:567-625` 已编码，校验 5-bit opcode | G-NTP-2/G-NTP-4 |
| RFC 7822 §4 扩展/认证长度与对齐 | 扩展、MAC 尾部 | `planner.go:477-526` 已编码；校验上限与编码安全上限不一致 | G-NTP-4 |
| RFC 5905 §7.3 IPv4/IPv6 承载 | 地址族和端口变体 | IP/UDP 承载层负责 | G-NTP-1 |
| RFC 5905 §7.3 重复轮询 | RepeatCount 多报文 | generator 按事件流式展开 | G-NTP-1 |
| RFC 5905 §7.3 错误值拒绝 | 非法 LI/VN/Mode/Stratum 等 | `planner.go:124-185` 返回精确错误 | G-NTP-3 |

### D1 三张子表

**命令/消息×响应码矩阵**（NTP 没有 HTTP 式响应码；以消息模式/响应事件表示）：

| 消息形态 | 请求 | 响应/配对 | 当前用例 |
|---|---|---|---|
| client Mode=3 | 已覆 | Mode=4 可选配对 | `ntp_smoke_01` 仅请求；配对 G-NTP-2 |
| server Mode=4 | 已实现 | 独立响应 | G-NTP-2 |
| broadcast Mode=5 | 已实现 | 无配对 | G-NTP-2 |
| symmetric Mode=1/2 | 已实现 | 对端模式可选配对 | G-NTP-2 |
| control Mode=6 | 已实现 | R-bit 配对 | G-NTP-2/G-NTP-4 |
| private Mode=7 | 已实现 | 无配对 | G-NTP-2 |

**数据形态变体表：**

| 形态 | 规范/代码结论 | 用例/缺口 |
|---|---|---|
| 48-byte 基本头 | 已实现，网络字节序 | `ntp_smoke_01` |
| 12-byte control 头 + 0–468-byte data | 已实现，超界拒绝 | G-NTP-2/G-NTP-4 |
| extension（4-byte 对齐） | 已实现但 65529–65531 存在 Length 溢出风险 | G-NTP-4 |
| MAC 0/16/20 bytes | 已校验 | G-NTP-4 |
| IPv4/IPv6、默认/显式端口 | 承载层实现 | G-NTP-1 |

**商业行为→用例映射表：**

| 现网行为 | 来源/确认方式 | 用例映射 |
|---|---|---|
| ntpd client 向 UDP/123 发 Mode=3、VN=4 请求 | RFC 5905 §7.3 + 已有 tshark 探针 | `ntp_smoke_01` |
| ntpd server 返回 Mode=4 | RFC 5905 §7.3；补跑 PCAP 后确认 | G-NTP-2（待确认） |
| broadcast/peer/control 使用专用模式 | RFC 5905 §7.3、RFC 1305 App. B；补跑字段断言 | G-NTP-2（待确认） |

### D2 三路对照与候选方案

| 走法 | 规范原文 | 商业行为 | 开源实现思路 | 取舍 |
|---|---|---|---|---|
| 空配置 client | RFC 5905 §7.3 | ntpd probe 默认 UDP/123、Mode=3 | chrony/ntpd 均以 48-byte 基本头起步 | 当前采用，最小可执行 smoke |
| 显式 Mode=6 control | RFC 1305 App. B | `ntpq` 使用 control header、Sequence/OpCode | ntpd control header 12 bytes + data | 已实现，待机器例验证 |
| 业务响应配对 | RFC 5905 §7.3 | client/server request-response | 事件序列中回显 OriginTS | 已实现，待机器例验证 |

## D2 严格层链与配置权威

唯一目标形状为 `[udp,ntp]`：UDP 层承载端口，NTP 层承载业务配置；顶层只允许 `layers` 及框架流控/输出键。当前 `ntp.json` 的 1/1 用例顶层仅有 `layers`，不存在旧 flat 地址、端口、count 或顶层协议映射。当前代码只对空 `ntp` 层走生成器缺省；非空 `ntp` 层配置尚未由层翻译接入，不能宣称已支持。空 NTP 层默认生成 NTPv4 client request；默认目的端口 123 由 UDP/链规划路径收敛。

## D3 线格式、状态与业务矩阵

基本报文固定 48-byte，网络字节序；Mode 1–7、Mode 6 控制头、扩展/MAC 布局和 NTP timestamp 见原 §3。事件矩阵为 client request/response、server response、broadcast、symmetric、control、private；当前仅 client request 进入机器用例，其他项逐项登记 G-NTP-1/G-NTP-2。NTP 为单 UDP datagram，不产生父子数据流。

## D4 依赖与错误传播

依赖 `udp` 承载层及其 IP 层默认；planner/validator 负责 Version、Mode、LI、Stratum、扩展、MAC、控制长度和 IP 合法性。错误必须传播到 task error，禁止 completed/0 packet 或仅输出外层 UDP。原 §7 锚词表是后续负例的一故障一用例清单。

## D5 性能、输出与验收

生成按事件流式展开，不聚合重复报文；基本报文 48-byte，控制最大 480-byte，扩展按 4-byte 对齐。PCAP 与授权 NIC 共用同一 JSON 和字段断言集；本轮未运行，吞吐、并发、内存、队列背压和丢包数字均待确认，不作完成声明。

## D6 接口、动态和冲突点

实现路径为 strategy conversion → NTPConfig → validator → planner/generator → UDP/IP/Ethernet；四元组动态字段归属 IP/UDP 层，`TransmitTS` 是 planner wall-clock 值，只断言 nonzero，当前不宣称 NTP 业务字段支持 fixed/inc/rand/list/pattern。冲突点是未覆盖分支和旧 tracked 产物，均按缺口登记；未消费字段不得进入当前配置，待有可消费层时按 G-NTP-8 的迁入计划接线。

## D7 门1与迁移审计

旧键去向为：地址进入 IP 层、端口进入 UDP 层、数量进入 `flow_control`；NTP 业务进入 `ntp` 层。当前唯一 case 已满足严格层链，层序不可交换；负例若故意测试 presence/旧键，应明确作为错误注入，不得清洗成正例。

## D8 回滚与完成边界

本轮只改设计、测试契约与 NTP cases，不改 Go、全局门禁或其他协议。实现前不得宣称未覆盖分支或双输出通过；后续回滚仅撤销本协议新增文档/cases 变更，缺口编号随契约版本保留。完成需逐项关闭 G-NTP-1 至 G-NTP-8，并以同一 JSON 完成 PCAP/NIC 验收。

## 2. 配置形状、层链与默认值

目标形状是层链唯一真相；当前唯一机器用例为：

```json
{
  "layers": [{"udp": {}}, {"ntp": {}}]
}
```

`ntp` 是 UDP 的终结层，registry 依赖 `udp`，生成器通过 `FlowMeta.NTP` 直传，当前 registry 不在 ntp layer schema 中声明业务字段。旧策略转换路径可从顶层 `ntp` 子映射填充 `NTPConfig`，但 `translateTerminalConfig` 当前没有 ntp 分支，因此非空 `layers[].ntp` 不会填充 `FlowMeta.NTP`；这是待实现边界，不作为本轮 cases 能力。空 `ntp` 映射或 nil 配置默认 NTPv4 client：Mode=3、Version=4、Poll=6、Precision=-6；Stratum=0 合法且不被错误默认覆盖。

## 3. 线格式与字段布局

### 3.1 基本报文（Mode ≠ 6）

NTP payload 起点记为 N。固定头长度 48 字节，总长为 `48 + Σ(4 + align4(value_length)) + trailer_length`。所有多字节整数为网络字节序（大端）；时间戳为 32-bit seconds + 32-bit fractional seconds 的 64-bit NTP timestamp，epoch 为 1900-01-01 UTC。

| offset | 宽度 | 字段 | 配置/约束 |
|---:|---:|---|---|
| 0 | 1 | LI(2)  VN(3)  Mode(3) | `LeapIndicator` 0–3；Version 3/4；Mode 1–7 |
| 1 | 1 | Stratum | 0–16 |
| 2 | 1 | Poll | int8，默认 6 |
| 3 | 1 | Precision | int8，默认 -6 |
| 4 | 4 | Root Delay | `RootDelay` 秒转 16.16 定点 |
| 8 | 4 | Root Dispersion | `RootDispersion` 秒转 16.16 定点 |
| 12 | 4 | Reference ID | `ReferenceID` |
| 16 | 8 | Reference Timestamp | `RefTimestamp`；零时间编码为 0 |
| 24 | 8 | Origin Timestamp | `OriginTS`；零时间编码为 0 |
| 32 | 8 | Receive Timestamp | `ReceiveTS`；零时间编码为 0 |
| 40 | 8 | Transmit Timestamp | `TransmitTS`；client request 自动使用当前时间，故动态且非零 |

无认证时基本报文长度为 48。RFC 7822 扩展从 offset 48 开始，每项为 `Type(2) | Length(2) | Value | zero padding to 4-byte boundary`。为使 `4 + align4(value_length)` 不超过 65535，单项 Value 的线格式安全上限是 65528 字节；当前 validator 仍允许 65531，65529–65531 在编码时会使 16 位 Length 溢出，登记为待修复边界。认证尾部由 `KeyID(4)` 与 MAC 字节组成，MAC 长度只允许 0、16 或 20。

### 3.2 控制报文（Mode=6）

控制报文不使用 48-byte 基本头，总长为 `12 + len(ControlData)`，其中 `len(ControlData) ≤ 468`。offset 0 为 LI/VN/Mode，offset 1 为 R/E/M/OpCode，offset 2/4/6/8/10 依次为大端 Sequence、StatusWord、AssociationID、Offset、Count（Count 等于 data 长度），offset 12 起为 ControlData。RequestCode 为 5-bit，范围 0–31。

### 3.3 承载和地址

应用层 payload 由 UDP 终结层封装；IPv4/IPv6 均由底层 IP 层决定。无 VLAN/IP options 时，NTP payload offset 为 Ethernet 14 + IPv4 20 + UDP 8 = 42，或 Ethernet 14 + IPv6 40 + UDP 8 = 62。每个 NTP 事件对应一个 UDP datagram。当前唯一 case 未显式 IP，因此只验证 UDP/NTP 字段；IPv4、IPv6、非默认端口必须补独立用例。

## 4. 业务场景分析

### D3 依赖与错误处理矩阵

| 依赖 | 失败返回 | 继续/中断 | 重试与超时 |
|---|---|---|---|
| `udp` 承载层及 IP 层 | validator/planner error | 中断任务，禁止 0 包成功 | 不自动重试；任务超时由通用 worker 控制 |
| NTP Version/Mode/LI/Stratum 校验 | 精确 `ntp: ...` 锚词 | 中断提交 | 不重试 |
| control opcode/data 长度 | `RequestCode` 或 `ControlData` 锚词 | 中断提交 | 不重试 |
| extension/MAC 长度 | `Extensions` 或 `MAC length` 锚词 | 中断提交 | 不重试 |

### D4 性能设计与双路验收

| 指标 | 当前依据/边界 | 验收 |
|---|---|---|
| 吞吐 | 单事件一个 UDP datagram；具体 pps/bps 待基准 | PCAP 统计包/字节；NIC tcpdump 同字段统计 |
| 并发 | 多策略由通用任务层调度；NTP 单流无子流 | PCAP 多 flow；NIC 观察四元组 |
| 内存/队列 | generator 流式，不聚合 RepeatCount；队列/环形缓冲遵通用上限 | 资源监测并检查背压/丢包 |
| CPU | worker 并行度由通用 pipeline 配置 | 记录 CPU 与实际吞吐 |
| 场景 | 基线、目标规模、压力上限、长跑、交错、资源耗尽/背压 | 六类均需 PCAP 与 NIC 分别验收；当前登记 G-NTP-1/G-NTP-7 |

### D5 八要素实现清单

| 要素 | NTP 结论 |
|---|---|
| 文件 | `internal/protocol/ntp/{planner.go,layer_gen.go}`；层注册/转换文件；本轮只改三份契约产物 |
| 接口 | `NTPGenerator.Generate(ctx, *layers.GenRequest) error`；`Planner.Plan(ctx, core.FlowSpec)` |
| 结构 | `NTPConfig`、`MessageEvent`、UDP/IP/Ethernet 层链 |
| 流程 | 配置→校验→模式事件→UDP datagram→IP/Ethernet |
| 错误 | validator 锚词传播到任务 error，不生成成功 PCAP |
| 性能边界 | 48-byte 基本头、control 12+468、扩展 4-byte 对齐 |
| 冲突点 | 非空 ntp 层翻译未接入；扩展安全上限与 validator 不一致；均登记 G-NTP-4/G-NTP-8 |
| 回滚 | 仅回滚本协议三份文档/cases，代码与全局文件不动 |


现网典型场景是客户端向 UDP/123 发送时间同步请求；服务器返回 Mode=4 response；局域网还存在 broadcast Mode=5 与 peer symmetric Mode=1/2；ntpd 控制工具使用 Mode=6。生成器按声明式事件顺序生成，不等待真实服务端刺激：client `IsResponse` 时 request 后立即补 response；server 直接生成 response；broadcast/symmetric/control 按 `RepeatCount` 展开；`PollInterval` 只用于时间戳递进，不在 planner 内 sleep，速率由 worker pacing 承担。

会话表：

| 会话 | 载体 | 事务序列 | 关联 |
|---|---|---|---|
| NTP client | UDP 单流 | request（可选 response） | response 的 OriginTS 取 request TransmitTS |
| broadcast/symmetric | UDP 单流 | 重复公告或 peer packet | 每次迭代由 `RepeatCount`/`PollInterval` 定序 |
| control | UDP 单流 | control request（可选 response） | response 复用 Sequence |

NTP 本身无控制流派生数据流、父子流或多流关联；多会话并发由框架层负责，当前 NTP JSON 未覆盖。

## 5. 状态机与生成路径

配置 → `strategy_convert.go` 解析 `ntp` 子映射 → `NTPConfig` → validator（Version/Mode/LI/Stratum/MAC/扩展/控制数据）→ chain planner 或 legacy planner → `NTPGenerator.Generate`/`Planner.Plan` → MessageEvent/PacketConfig → UDP → IP/Ethernet。

状态集合为 `Ready`、`Emitting`、`Done`、`Cancelled`、`Error`。Ready 进入 Emitting；每次成功 Emit 按模式推进；context cancel 进入 Cancelled；EmitMsg nil 或 validator 错误进入 Error；repeat 完成进入 Done。同一输入（除当前时间戳和随机 IPID/临时源端口）按模式产生同序事件。

| 模式 | 事件顺序 |
|---|---|
| 1/2 symmetric | 每次一个 peer packet；`IsResponse` 再补反向 mode |
| 3 client | request；`IsResponse` 时再补 server response，OriginTS=请求 tx |
| 4 server | response，方向为对端 |
| 5 broadcast | 每次一个 broadcast packet，tx 时间按 `PollInterval` 递进 |
| 6 control | request；`IsResponse` 时补同 Sequence 的 response |
| 7 private | basic header |

## 6. 性能与容量

基本报文固定 48-byte payload；控制报文最大 480 bytes（12+468）；扩展长度受 16-bit length 表达能力限制并按 4-byte 对齐。单 UDP datagram 不跨 MSS 分段；外层 IP/UDP/Ethernet 的帧长度另加各层头部和 Ethernet 最小帧填充。RepeatCount 只增加流式事件，不聚合 payload；队列和缓冲的容量约束由通用 pipeline 承担。大扩展、468/469 控制数据相邻边界、MAC 长度相邻值尚无 JSON 覆盖。

## 7. 错误处理

| 锚词 | 触发 |
|---|---|
| `LeapIndicator` | LI > 3 |
| `Version` | Version 非 3/4（注意策略转换默认 4，显式 0 在 validator 路径是非法/在默认化路径需分层核对） |
| `Mode 0 reserved` | Mode=0 |
| `Mode` | Mode > 7 |
| `Stratum` | Stratum > 16 |
| `MAC length` | MAC 非 0/16/20 |
| `Extensions` | extension value > 65531（当前 validator 上限；其中 65529–65531 对齐后会溢出 16 位 Length，待 Go 修复） |
| `RequestCode` | Mode=6 且 >31 |
| `ControlData` | Mode=6 且长度 >468 |
| `SrcIP` / `DstIP` | 非法 IP |

错误必须从 validator/planner 传播到任务终态；当前 ntp JSON 没有负例，错误契约尚未被机器用例锁定。

## 8. 五层覆盖与实现状态

- **功能层**：当前只证明 client request；server/broadcast/symmetric/control/private、response 和错误分支待补。
- **性能层**：固定 48-byte、control 480-byte 上界已在实现；边界与重复流待补。
- **数据层**：默认 LI/VN/Mode/Stratum/Poll 与动态 xmt 已断言；时间、定点数、扩展、MAC、控制字段值域待补。
- **地址与流层**：UDP 终结层已注册；IPv4/IPv6、默认/非默认端口、源端口和多会话待补。NTP 无流关联，显式不适用。
- **业务层**：当前只覆盖现网 client probe；request/response、broadcast、peer、control 和多会话待补。

## 9. §9 建议（不冒充当前实现）

建议先补默认/非默认端口与 IPv4/IPv6，再按 client response、server、broadcast、symmetric、control 顺序拆原子 case；随后补 RFC 7822 extension/MAC、边界负例和多会话。每个新增行为必须同时更新 design、testcase、cases JSON，不能用综合 smoke 替代字段/边界断言。

## 10. 门1 §1–§14 对照表

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 存量唯一 case 顶层仅 `layers`；目标为 `[udp,ntp]`，无顶层 ntp 子映射 | §2；`cases/ntp.json` |
| §2 策略/任务 | legacy 顶层 `ntp` 子映射可转换为 NTPConfig；本轮严格层链的非空 ntp 层仍待翻译接线；任务总量/流控制由框架承载 | §2；`strategy_convert.go:1231`；G-NTP-8 |
| §3 五件套 | client 单 UDP 会话；request/可选 response；无派生流；插入 UDP 终结层；按事件顺序生成 | §4–§5；`layer_gen.go:35` |
| §4 查规范 | RFC 5905 §7.3、RFC 1305 App. B、RFC 7822 §4；字段依据见 §3 | §1、§3 |
| §5 依赖与错误 | registry `ntp` 依赖 `udp`；validator 锚词见 §7；失败应传播任务终态 | `registry.go:161`；`planner.go:119` |
| §6 性能 | 48-byte 基本头、480-byte control 上界、扩展 4-byte 对齐 | §6 |
| §7 三份文档 | design/testcase/cases 同一 `ntp_smoke_01`，顺序和断言一致 | §2；testcase §2 |
| §8 设计先行 | 本稿按现有实现 as-built，未实现面登记缺口 | §8、§11 |
| §9 测试三源 | RFC + Go 实现 + tshark/cases 现有字段断言 | §1、testcase §3 |
| §10 评审闭环 | 本轮自审与机读对账；待独立隔离复审 | §12 |
| §11 白话 | NTP client 通过 UDP/123 发送带当前时间戳的 NTPv4 请求 | §1；testcase §1 |
| §12 动态清单 | 四元组按框架策略；业务动态字段仅 transmit timestamp 已实测非零 | §12.12 |
| §13 schema 派生 | `ntp` 已在 registry 注册，依赖 UDP，无重复 fields | `registry.go:161` |
| §14 真实流程 | 同一 JSON 契约应覆盖 pcap 与 NIC；本车道不执行 live 回归 | testcase §7 |

### 10.1 §1 强制展开：旧键去向与完整样例

`ntp.json` 仅 1 例，`spec_json` 顶层键集合为 `{layers}`。旧 flat 键 `src_ip`、`dst_ip`、`src_port`、`dst_port`、`count`、顶层 `ntp` 子映射均未出现；目标去向是层链/框架承载，NTP 业务目标位置为 `layers[1].ntp`。完整样例见 §2 代码块。当前无旧键迁移工作量，但新增例不得恢复 flat 形状；在 ntp 层翻译接线完成前，不得新增非空业务配置正例。

### 10.2 §3 强制展开：五件套

会话表见 §4；事务为 client request（可选 server response），response 的 OriginTS 关联 request TransmitTS；无控制/数据派生流，故流关联项不适用；插入位置为 UDP 终结层 `[udp,ntp]`；时间线是单 datagram 事件，生成器不等待网络刺激，`PollInterval` 仅决定重复包时间戳。

### 10.3 §12.1/§12.3/§12.12 强制展开

- **§12.1/§12.3/§12.12**：按 `docs/CORE_MEMORY.md` 对动态字段与层链归属的要求，旧键逐项为 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/顶层 `ntp`：现有 1/1 case 均不存在；目标形仅 `layers`。
- **§12.3**：五件套同 §10.2；NTP 无父子流和多事务连接，单 UDP 事务不适用长连接/保活/FIN/RST。
- **§12.12**：四元组 `ip.src`、`ip.dst`、`udp.src_port`、`udp.dst_port` 由统一 layer dynamic strategy 解析，按 zero-based `FlowIndex` 取值并在范围末尾回绕；当前 ntp layer 没有业务 allowlist，不能宣称 `ntp.*` 业务字段支持 fixed/inc/rand/list/pattern。`TransmitTS` 由 planner 使用 `time.Now()` 生成，不是策略动态字段；当前 case 只断言 nonzero。

## 11. 缺口登记

| 缺口 | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-NTP-1 | 只有 smoke，未覆盖 IPv4/IPv6、非默认端口和四元组策略 | `ntp.json` 仅 1 ID；层代码支持 UDP 终结 | P4 用例扩展 |
| G-NTP-2 | server/client response、broadcast、symmetric、control、private 分支无 cases | `layer_gen.go:70-205` | P4 用例扩展 |
| G-NTP-3 | validator 每个错误分支无负例及任务终态断言 | `planner.go:124-185`；JSON 无 `expect_error` | P4 失败用例 |
| G-NTP-4 | extension、MAC、定点数、控制 468-byte 边界无可执行观察；且 extension validator 上限 65531 与 4-byte 对齐后的 16 位 Length 安全上限 65528 不一致 | `NTPConfig` 字段与 builder 存在，JSON 未引用；`planner.go` 校验 65531、builder 按 4 字节对齐 | P4 数据/性能与 Go 修复 |
| G-NTP-5 | NTP 业务字段未接入五策略动态 allowlist；TransmitTS 为 wall-clock 动态值 | `layer_gen.go` 无业务策略解析，case 仅 nonzero | P2/P4 设计裁定 |
| G-NTP-6 | tracked 旧结果早于扁平判死基线，不能作为今日回归证据 | `trafficgen/docs/protocol-pcap-test/ntp.md` 末次提交 `e7e7d1c`（2026-08-27）早于 `0417be5`（2026-09-13） | P5 重跑产物 |
| G-NTP-7 | pcap/NIC 双输出本车道未执行实测 | 本车道仅文档审计，未启动 live DB/NIC | P5 双输出回归 |
| G-NTP-8 | 非空 `layers[].ntp` 尚未翻译到 `FlowMeta.NTP`，业务层配置会落入生成器缺省路径 | `chain_planner_translate.go` 未含 `case "ntp"`；本轮只使用空层 smoke | Go 接线后再补 cases |

## 12. 修订记录与自审

- v1.0.0（2026-09-29）：按实现、registry、strategy_convert 和 `ntp.json` 编写；加入 §1–§14 门1、§12.1/§12.3/§12.12、五层覆盖、存量审计、缺口和过期产物登记。自审 2 轮，末轮干净；待独立隔离复审。
- v1.0.1（2026-10-01）：复核 `translateTerminalConfig` 后确认非空 `layers[].ntp` 尚未注入 `FlowMeta.NTP`；补充 G-NTP-8，并将该能力排除在当前 cases 覆盖外。独立审查又确认 extension 对齐上限与 §12 引用问题，修正文档并完成 2 轮自审，末轮干净；待独立隔离复审。

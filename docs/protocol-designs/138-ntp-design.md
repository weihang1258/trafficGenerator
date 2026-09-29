# #138 NTP（Network Time Protocol）设计文档

> 版本：v1.0.0（as-built）  
> 日期：2026-09-29  
> 状态：按当前 Go 实现、层注册和 `cases/ntp.json` 编写；不把未进入机器契约的分支宣称为已验收。  
> 配套用例：`138-ntp-testcase.md`；机器契约：`trafficgen/test/protocol_pcap/cases/ntp.json`。

## 1. 范围、规范与实现边界

NTP 是 UDP 终结层协议，默认服务端口 123。基本时间报文按 RFC 5905 §7.3 编码；Mode=6 控制报文沿 RFC 1305 Appendix B 的 ntpd control header；扩展字段和认证尾部按 RFC 7822 §4 的长度/对齐约束处理。当前实现路径为 `trafficgen/internal/protocol/ntp/{planner.go,layer_gen.go}`，核心配置为 `internal/core/types.go:NTPConfig`，层注册在 `internal/core/layers/registry.go`，策略映射在 `internal/core/strategy_convert.go`。

当前 JSON 仅证明：空 NTP 配置经 `[udp,ntp]` 生成一个 client request。服务器、广播、对称、控制、私有模式、响应、重复发送、扩展、MAC、IPv6 等代码分支存在，但没有当前 cases 的可执行断言，列入缺口而不是当前覆盖。

## 2. 配置形状、层链与默认值

目标形状是层链唯一真相；当前唯一机器用例为：

```json
{
  "layers": [{"udp": {}}, {"ntp": {}}]
}
```

`ntp` 是 UDP 的终结层，registry 依赖 `udp`，生成器通过 `FlowMeta.NTP` 直传，不在 ntp layer schema 中重复声明字段。策略转换读取 `ntp` 子映射并填充 `NTPConfig`；NTP 默认目的端口 123 在 ChainPlanner 校验/默认路径收敛。空 `ntp` 映射或 nil 配置默认 NTPv4 client：Mode=3、Version=4、Poll=6、Precision=-6；Stratum=0 合法且不被错误默认覆盖。

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

无认证时基本报文长度为 48。RFC 7822 扩展从 offset 48 开始，每项为 `Type(2) | Length(2) | Value | zero padding to 4-byte boundary`；`NTPExt.Value` 最大 65531，生成器负责 4-byte 对齐。认证尾部由 `KeyID(4)` 与 MAC 字节组成，MAC 长度只允许 0、16 或 20。

### 3.2 控制报文（Mode=6）

控制报文不使用 48-byte 基本头，总长为 `12 + len(ControlData)`，其中 `len(ControlData) ≤ 468`。offset 0 为 LI/VN/Mode，offset 1 为 R/E/M/OpCode，offset 2/4/6/8/10 依次为大端 Sequence、StatusWord、AssociationID、Offset、Count（Count 等于 data 长度），offset 12 起为 ControlData。RequestCode 为 5-bit，范围 0–31。

### 3.3 承载和地址

应用层 payload 由 UDP 终结层封装；IPv4/IPv6 均由底层 IP 层决定。无 VLAN/IP options 时，NTP payload offset 为 Ethernet 14 + IPv4 20 + UDP 8 = 42，或 Ethernet 14 + IPv6 40 + UDP 8 = 62。每个 NTP 事件对应一个 UDP datagram。当前唯一 case 未显式 IP，因此只验证 UDP/NTP 字段；IPv4、IPv6、非默认端口必须补独立用例。

## 4. 业务场景分析

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
| `Extensions` | extension value > 65531 |
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
| §2 策略/任务 | `ntp` 子映射转换为 NTPConfig；任务总量/流控制由框架承载 | §2；`strategy_convert.go:1231` |
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

`ntp.json` 仅 1 例，`spec_json` 顶层键集合为 `{layers}`。旧 flat 键 `src_ip`、`dst_ip`、`src_port`、`dst_port`、`count`、顶层 `ntp` 子映射均未出现；去向是由层链/框架默认承载，NTP 配置目标为 `layers[1].ntp`。完整样例见 §2 代码块。当前无旧键迁移工作量，但新增例不得恢复 flat 形状。

### 10.2 §3 强制展开：五件套

会话表见 §4；事务为 client request（可选 server response），response 的 OriginTS 关联 request TransmitTS；无控制/数据派生流，故流关联项不适用；插入位置为 UDP 终结层 `[udp,ntp]`；时间线是单 datagram 事件，生成器不等待网络刺激，`PollInterval` 仅决定重复包时间戳。

### 10.3 §12.1/§12.3/§12.12 强制展开

- **§12.1**：旧键逐项为 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/顶层 `ntp`：现有 1/1 case 均不存在；目标形仅 `layers`。
- **§12.3**：五件套同 §10.2；NTP 无父子流和多事务连接，单 UDP 事务不适用长连接/保活/FIN/RST。
- **§12.12**：四元组 `ip.src`、`ip.dst`、`udp.src_port`、`udp.dst_port` 由统一 layer dynamic strategy 解析，按 zero-based `FlowIndex` 取值并在范围末尾回绕；当前 ntp layer 没有业务 allowlist，不能宣称 `ntp.*` 业务字段支持 fixed/inc/rand/list/pattern。`TransmitTS` 由 planner 使用 `time.Now()` 生成，不是策略动态字段；当前 case 只断言 nonzero。

## 11. 缺口登记

| 缺口 | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-NTP-1 | 只有 smoke，未覆盖 IPv4/IPv6、非默认端口和四元组策略 | `ntp.json` 仅 1 ID；层代码支持 UDP 终结 | P4 用例扩展 |
| G-NTP-2 | server/client response、broadcast、symmetric、control、private 分支无 cases | `layer_gen.go:70-205` | P4 用例扩展 |
| G-NTP-3 | validator 每个错误分支无负例及任务终态断言 | `planner.go:124-185`；JSON 无 `expect_error` | P4 失败用例 |
| G-NTP-4 | extension/MAC/定点数/控制 468-byte 边界无可执行观察 | `NTPConfig` 字段与 builder 存在，JSON 未引用 | P4 数据/性能 |
| G-NTP-5 | NTP 业务字段未接入五策略动态 allowlist；TransmitTS 为 wall-clock 动态值 | `layer_gen.go` 无业务策略解析，case 仅 nonzero | P2/P4 设计裁定 |
| G-NTP-6 | tracked 旧结果早于扁平判死基线，不能作为今日回归证据 | `trafficgen/docs/protocol-pcap-test/ntp.md` 末次提交 `e7e7d1c`（2026-08-27）早于 `0417be5`（2026-09-13） | P5 重跑产物 |
| G-NTP-7 | pcap/NIC 双输出本车道未执行实测 | 本车道仅文档审计，未启动 live DB/NIC | P5 双输出回归 |

## 12. 修订记录与自审

- v1.0.0（2026-09-29）：按实现、registry、strategy_convert 和 `ntp.json` 编写；加入 §1–§14 门1、§12.1/§12.3/§12.12、五层覆盖、存量审计、缺口和过期产物登记。自审 2 轮，末轮干净；待独立隔离复审。

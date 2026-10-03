# #138 NTP 测试用例契约

> 版本：v1.0.0（as-built）  
> 日期：2026-09-29  
> 配套设计：`design.md`；机器契约：`trafficgen/test/protocol_pcap/cases/ntp.json`。  
> 白话一句：**一条检查确认空 NTP 层链会发出 UDP/123 上的 NTPv4 client 请求，并携带非零发送时间戳。**

## 1. 测试原则和形状基线

cases JSON 是权威。当前共 1 个唯一 ID，1 正例、0 负例。`spec_json` 顶层唯一键为 `layers`，层序为 `[udp,ntp]`；没有顶层 flat 地址、端口、count 或顶层 `ntp` 子映射。该例使用空 `ntp` 层，只验证生成器缺省；非空 `layers[].ntp` 尚无层翻译接线，不能由本例推导业务配置已生效。正例 expect 含 `packet_count` 和 fields/notes；当前没有失败任务契约。pcap 与 NIC 应复用这份同一 JSON；本车道不执行 live 回归。

### T1 三源回指

| 测试点 | 规范来源 | 设计来源 | 现网/代码证据 | 当前去向 |
|---|---|---|---|---|
| client 默认请求 | RFC 5905 §7.3 | design §3.1、§4、§5 | `ntp/layer_gen.go:69-89`；已有 tshark 探针 | `ntp_smoke_01` |
| 默认 UDP/123、VN=4、Mode=3 | IANA/RFC 5905 §7.3 | design §2、§3 | `layer_gen.go:37-55`、UDP 默认端口 | `ntp_smoke_01` |
| response/server/broadcast/peer/control | RFC 5905 §7.3；RFC 1305 App. B | design §4–§7 | `layer_gen.go:91-208` | G-NTP-2，补例后以 PCAP 确认 |
| 非法配置拒绝 | RFC 5905 §7.3；RFC 7822 §4；RFC 1305 App. B | design §7 | `planner.go:124-185` 精确锚词 | G-NTP-3，补纯负例 |

### T2 测试点清单（先行）

| 规范条文 | 业务场景 | 代码分支 | 当前用例/缺口 |
|---|---|---|---|
| §7.3 LI/VN/Mode | 默认 client | `buildClientRequest` | `ntp_smoke_01`；Mode 1–7 G-NTP-2 |
| §7.3 时间戳/Stratum/Poll | 未同步 client | `buildBasicHeader`/`buildClientRequest` | `ntp_smoke_01`；其余字段 G-NTP-4 |
| §7.3 response/broadcast/symmetric/private | 模式事件序列 | `layer_gen.go` mode switch | G-NTP-2 |
| RFC 1305 App. B | control request/response | `buildControlRequest/Response` | G-NTP-2/G-NTP-4 |
| RFC 7822 §4 | extension/MAC 长度边界 | `buildNTPPacket` + validator | G-NTP-4 |
| RFC 5905 承载变体 | IPv4/IPv6、端口、RepeatCount | UDP/IP layers + repeat loop | G-NTP-1 |
| 错误条款 | 非法 LI/VN/Mode/Stratum/MAC/extension/control/IP | `validateNTPConfig` | G-NTP-3 |

### T3 颗粒度与强度

- **数据场景**：LI/VN/Mode/Stratum/Poll/xmt 已在 smoke 中拆为字段断言；枚举逐值、0/最大/越界、扩展对齐、MAC 0/16/20、control 0/468/469、IPv4/IPv6 尚分别登记 G-NTP-1/G-NTP-3/G-NTP-4。
- **业务场景**：client request 已覆盖；request→response、broadcast 重复、symmetric 配对、control request→response、非正常拒绝分别登记 G-NTP-2/G-NTP-3。NTP 是单 datagram 协议，无父子数据流。
- **现网场景**：默认 ntpd client probe 已有实测字段；server/broadcast/peer/control 和地址族现网行为须用 PCAP/NIC 实测后再钉值。
- **强度**：当前 smoke 是最小原子点；动态整格（四元组五策略、业务字段策略）不能宣称已覆盖，因 NTP 终结层尚无业务 allowlist，见 G-NTP-5。

### T4 §3.15 三项边界

NTP 无长连接、无同连接多轮操作和保活机制：

1. 同连接多轮操作：不适用；UDP 每事件独立 datagram。RepeatCount 多报文属于 G-NTP-1，不冒充长连接事务。
2. 非正常结束：不适用；无 FIN/RST 生命周期。非法配置拒绝由 G-NTP-3 覆盖。
3. 长保活：不适用；PollInterval/RepeatCount 仅生成事件时间序列，不由 NTP generator sleep；长跑与背压性能属于 G-NTP-1/G-NTP-7。


NTP 时间戳由运行期当前时间生成，不把具体值硬编码；只断言 `ntp.xmt` nonzero。字段值格式按 cases 原文：端口和整数使用十进制字符串。

## 2. 原子用例索引（与 JSON 同序）

| # | ID | 类型 | 场景/依据 | 包数 | 断言 |
|---:|---|---|---|---:|---|
| 1 | `ntp_smoke_01` | 正 | RFC 5905 §7.3；空配置 NTPv4 client request；UDP 默认端口 | 1 | `udp.dstport=123`；`ntp.flags.vn=4`；`mode=3`；`li=0`；`stratum=0`；`ppoll=6`；`ntp.xmt` nonzero |

该例验证一个不可再分的默认 client 行为面；动态 xmt 的非零性是可观察结果，不等同于固定时间值。

## 3. 正例断言契约

### 3.1 `ntp_smoke_01`

`spec_json` 为：

```json
{"layers":[{"udp":{}},{"ntp":{}}]}
```

必须生成 1 个 UDP datagram。断言：

- `udp.dstport` = `123`：IANA/RFC 5905 默认服务端口，经策略/链校验默认化。
- `ntp.flags.vn` = `4`：NTPv4 默认版本。
- `ntp.flags.mode` = `3`：client request。
- `ntp.flags.li` = `0`：未声明闰秒指示。
- `ntp.stratum` = `0`：未同步 client 请求。
- `ntp.ppoll` = `6`：默认 poll exponent。
- `ntp.xmt` nonzero：planner 用当前 NTP epoch 时间生成 transmit timestamp。

不对具体 source port、IP、reference ID、root delay、root dispersion、origin/receive timestamp 做固定断言：它们由框架默认或空配置零值决定，且 source port/时间存在运行期变化。

## 4. 负例契约

当前 JSON 没有 `expect_error` 用例，因此不宣称覆盖 validator 负路径。设计 §7 的错误锚词必须在 P4 逐错误拆成纯 `{expect_error,error_contains,notes}` 契约，至少覆盖非法 IP、LI、Version、Mode、Stratum、MAC 长度、extension 长度、control RequestCode 和 ControlData 上界。

### T6 失败路径与断言规则

后续每个失败用例必须经任务提交实际触发拒绝，`expect` **恰为** `{"expect_error":true,"error_contains":"<planner.go 精确锚词>"}`（允许另有纯 `notes` 注记，但不得出现 `packet_count`、`fields`、`frames`）。当前没有负例，故 T6 结论为待补 G-NTP-3，而非成功覆盖。锚词来源为 design §7 与 `planner.go:133-181`：`LeapIndicator`、`Version`、`Mode 0 reserved`、`Mode`、`Stratum`、`MAC length`、`Extensions`、`RequestCode`、`ControlData`；非法 IP 锚词需先由承载层实际拒绝文案确认，不提前编写。

## 5. 五层覆盖与对账

- **功能**：已覆盖 client request 默认状态（Mode=3）；其余 Mode 1/2/4/5/6/7、response 和负路径待补。
- **性能**：当前只观察单 48-byte 基本头承载的 1 datagram；控制 480-byte 上界、扩展上界、重复发送和相邻边界待补。
- **数据**：VN/Mode/LI/Stratum/Poll 与 xmt nonzero 已断言；Root 定点数、时间戳零值、扩展/MAC/控制字段待补。
- **地址与流**：UDP 终结层与默认 dst port 已断言；IPv4/IPv6、显式四元组、非默认端口和多会话待补。无父子流关联，NTP 流关联不适用；非空 NTP 业务层配置待 Go 接线后再测。
- **业务**：真实 client probe 已覆盖；server response、broadcast、symmetric peer、ntpd control、多会话待补。

三方对账：JSON ID 顺序 = `[ntp_smoke_01]`；本表 ID/包数/字段与 JSON 完全一致；设计 §2/§3/§8 对同一默认行为描述一致。

## 6. P3 固定动作与覆盖反查建议

当前仅提供建议，不修改 `coverage_gate.py`。主线程可登记以下静态可机读断言：

1. JSON ID 集合恰为 `ntp_smoke_01`，且 `packet_count=1`。
2. 非负例 `spec_json` 顶层键集合恰为 `{layers}`。
3. layer names 恰为 `udp,ntp`，顺序不可交换。
4. `udp.dstport` 断言值为 `123`。
5. NTP flags 三项断言恰为 `vn=4, mode=3, li=0`。
6. `ntp.stratum=0`、`ntp.ppoll=6`、`ntp.xmt nonzero` 均存在。
7. 正例无错误契约；负例计数为 0（当前集合）。
8. pcap 与 NIC 运行均读取同一 cases 文件，不另造路径专用断言。

## 7. 实现后执行建议

先跑单例并保存 pcap，再跑 suite；用 tshark 对 `udp.dstport`、`ntp.flags.*`、`ntp.stratum`、`ntp.ppoll`、`ntp.xmt` 做字段级断言。随后补 IPv4/IPv6 和各模式 cases；错误 case 必须确认任务终态为失败而不是 0 包成功。NIC 路径用同一 JSON 与同一断言集，记录接口和 pcap 文件。

## 8. 存量审计

| ID | 去向 | 原因 |
|---|---|---|
| `ntp_smoke_01` | 合入 | 唯一现有 NTP case；与当前 `[udp,ntp]` 实现、默认值和字段断言一致 |

无其他旧 ID；没有可作废或改写的存量例。

## 9. 过期产物登记

`trafficgen/docs/protocol-pcap-test/ntp.md` 为 tracked 旧产物，末次提交 `e7e7d1cba8754d2063642cd5c2ceee8e39ad6acf`（2026-08-27）早于扁平形判死基线 `0417be5`（2026-09-13）。本车道不修改或引用其结果；P5 重跑 suite 后再生成。该登记不等于当前 case 不可执行，只表示旧数字不能作为今日回归证据。

## 10. 缺口登记

| 缺口 | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-NTP-1 | 仅有 1 个默认 client smoke，未覆盖其余模式/response/重复 | JSON 仅 `ntp_smoke_01`；generator 有 Mode 分支 | P4 用例扩展 |
| G-NTP-2 | 无任何负例，validator 错误未被任务终态契约锁定 | `expect_error` 计数为 0；设计 §7 锚词表 | P4 失败用例 |
| G-NTP-3 | IPv4/IPv6、非默认端口和显式四元组无独立测试 | spec_json 无 ip/port layers | P4 地址与流 |
| G-NTP-4 | extension、MAC、control 12-byte/468-byte 边界无字段级断言；extension 65529–65531 还暴露 16 位 Length 对齐溢出待修复边界 | `NTPConfig` 支持字段，JSON 未引用；`planner.go` validator 上限 65531、builder 按 4 字节对齐 | P4 数据/性能与 Go 修复 |
| G-NTP-5 | NTP 业务字段无 fixed/inc/rand/list/pattern 动态策略用例；xmt 是 wall-clock 动态值 | layer generator 无 ntp业务 allowlist；case 仅 nonzero | P2/P4 动态字段 |
| G-NTP-6 | 旧 tracked 结果文档过期且未经本轮复跑 | 2026-08-27 < 2026-09-13 | P5 产物重生成 |
| G-NTP-7 | pcap/NIC 双输出本车道未实测 | 本文档阶段未启动 live DB/NIC | P5 双输出回归 |
| G-NTP-8 | 非空 `layers[].ntp` 尚未翻译到生成器配置 | `chain_planner_translate.go` 未含 `case "ntp"`；本例只使用空层 | Go 接线后再补业务配置 cases |

## T1 形状、来源与执行边界

本契约以 `ntp.json` 为机器权威，唯一 ID 顺序为 `ntp_smoke_01`（1 正例、0 负例）。配置严格为 `[udp,ntp]` 层链：端口在 UDP 层，NTP 业务字段在 NTP 层；顶层不得出现地址、端口、count 或顶层 `ntp` 子映射。当前只声明该例可观测的生成结果，不把未运行的 pcap/NIC 或未登记分支算作通过。

## T2 原子 ID 与包数

| # | ID | 类型 | packet_count | 依据 |
|---:|---|---|---:|---|
| 1 | `ntp_smoke_01` | 正 | 1 | RFC 5905 §7.3；设计 D2–D3 |

## T3 正例断言

`ntp_smoke_01` 必须产生一个 UDP datagram：`udp.dstport=123`、`ntp.flags.vn=4`、`ntp.flags.mode=3`、`ntp.flags.li=0`、`ntp.stratum=0`、`ntp.ppoll=6`，且 `ntp.xmt` nonzero。xmt 由运行期当前 NTP epoch 时间生成，不固定具体值；源端口、地址、reference/root 字段遵循框架默认，不作本例硬断言。

## T4 负例与错误传播

当前无负例，不能宣称覆盖 validator 失败路径。设计 D6 列出的非法 IP、LI、Version、Mode、Stratum、MAC、extension、RequestCode、ControlData 等故障，后续必须一故障一用例，`expect` 严格使用 `expect_error`、`error_contains`（可有纯注记），并确认任务终态为 error，不得 completed/0 packet。

## T5 覆盖与审计

| 审计项 | 当前结论 |
|---|---|
| JSON 可解析、ID 唯一、顺序一致 | 1/1，对账通过 |
| 正/负比例 | 1/0；无负例 |
| 顶层旧键 | 正例 1/1 清除，仅 `{layers}` |
| 层与字段归属 | `[udp,ntp]`；端口在 UDP，业务在 NTP |
| 动态字段 | xmt 仅断言 nonzero，不硬编码 wall-clock 值 |
| pcap/NIC | 本轮未执行，不作通过声明 |

## T6 缺口与执行计划

先以同一 JSON 跑 PCAP 正例并用 tshark 校验字段，再跑授权 NIC 抓包复验同一断言集；随后按 client response、server、broadcast、symmetric、control、IPv4/IPv6、非默认端口、扩展/MAC、控制边界和负例逐项扩展。性能验收补齐基线、目标规模、压力上限、长跑、交错和背压六项；当前均登记为设计 G-NTP-1 至 G-NTP-8，不提前宣称。

## C1–C6 覆盖清单

| ID | 检查 | 结论 |
|---|---|---|
| C1 | 正例顶层白名单 | 绿；1/1 正例仅 `{layers}`，无旧 flat/协议游离键 |
| C2 | 层链形状与字段归属 | 绿；唯一正例为严格 `[udp,ntp]`，端口由 UDP 承载，业务层为空壳 |
| C3 | registry 空壳登记 | 绿；registry 注册 ntp 但无业务字段，G-NTP-8 登记非空翻译缺口 |
| C4 | 负例契约 | ⏳待补 G-NTP-3；0 负例，故当前无双键 `{expect_error,error_contains}` 可核验 |
| C5 | 存量 ID 去向 | 绿；`ntp_smoke_01` 在 §2 与存量审计逐条登记 |
| C6 | spec-mapping 对账 | 绿（备注：未发现 NTP `*-spec-mapping.md`）；无 mapping 文件可对账 |

本节与上文 T1–T6 的关系：C1–C6 是 cases 静态门；T6 的 pcap/NIC 双输出运行要求仍按本车道未执行边界登记 G-NTP-7。

本版自审两轮：第一轮逐条核对 T1–T6、C1–C6 与 JSON 的 ID、顶层键、层序、包数和字段；第二轮复核负例纯契约、动态时间戳、未运行边界及缺口编号，末轮干净。



- v1.0.0（2026-09-29）：按 `ntp.json` 逐条建立索引、断言、五层对账、存量审计、过期产物登记、缺口与覆盖反查建议。自审 2 轮，末轮干净；待独立隔离复审。
- v1.0.1（2026-10-01）：复核层翻译路径后确认非空 `layers[].ntp` 尚未接线；唯一空层 smoke 不扩写无法执行的业务 cases，并登记 G-NTP-8。独立审查发现 extension 对齐上限问题后同步登记 G-NTP-4；自审 2 轮，末轮干净；待独立隔离复审。

# #138 NTP 测试用例契约

> 版本：v1.0.0（as-built）  
> 日期：2026-09-29  
> 配套设计：`138-ntp-design.md`；机器契约：`trafficgen/test/protocol_pcap/cases/ntp.json`。  
> 白话一句：**一条检查确认空 NTP 层链会发出 UDP/123 上的 NTPv4 client 请求，并携带非零发送时间戳。**

## 1. 测试原则和形状基线

cases JSON 是权威。当前共 1 个唯一 ID，1 正例、0 负例。`spec_json` 顶层唯一键为 `layers`，层序为 `[udp,ntp]`；没有顶层 flat 地址、端口、count 或顶层 `ntp` 子映射。正例 expect 含 `packet_count` 和 fields/notes；当前没有失败任务契约。pcap 与 NIC 应复用这份同一 JSON；本车道不执行 live 回归。

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

## 5. 五层覆盖与对账

- **功能**：已覆盖 client request 默认状态（Mode=3）；其余 Mode 1/2/4/5/6/7、response 和负路径待补。
- **性能**：当前只观察单 48-byte 基本头承载的 1 datagram；控制 480-byte 上界、扩展上界、重复发送和相邻边界待补。
- **数据**：VN/Mode/LI/Stratum/Poll 与 xmt nonzero 已断言；Root 定点数、时间戳零值、扩展/MAC/控制字段待补。
- **地址与流**：UDP 终结层与默认 dst port 已断言；IPv4/IPv6、显式四元组、非默认端口和多会话待补。无父子流关联，NTP 流关联不适用。
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
| `ntp_smoke_01` | 保留 | 唯一现有 NTP case；与当前 `[udp,ntp]` 实现、默认值和字段断言一致 |

无其他旧 ID；没有可作废或改写的存量例。

## 9. 过期产物登记

`trafficgen/docs/protocol-pcap-test/ntp.md` 为 tracked 旧产物，末次提交 `e7e7d1cba8754d2063642cd5c2ceee8e39ad6acf`（2026-08-27）早于扁平形判死基线 `0417be5`（2026-09-13）。本车道不修改或引用其结果；P5 重跑 suite 后再生成。该登记不等于当前 case 不可执行，只表示旧数字不能作为今日回归证据。

## 10. 缺口登记

| 缺口 | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-NTP-1 | 仅有 1 个默认 client smoke，未覆盖其余模式/response/重复 | JSON 仅 `ntp_smoke_01`；generator 有 Mode 分支 | P4 用例扩展 |
| G-NTP-2 | 无任何负例，validator 错误未被任务终态契约锁定 | `expect_error` 计数为 0；设计 §7 锚词表 | P4 失败用例 |
| G-NTP-3 | IPv4/IPv6、非默认端口和显式四元组无独立测试 | spec_json 无 ip/port layers | P4 地址与流 |
| G-NTP-4 | extension、MAC、control 12-byte/468-byte 边界无字段级断言 | `NTPConfig` 支持字段，JSON 未引用 | P4 数据/性能 |
| G-NTP-5 | NTP 业务字段无 fixed/inc/rand/list/pattern 动态策略用例；xmt 是 wall-clock 动态值 | layer generator 无 ntp业务 allowlist；case 仅 nonzero | P2/P4 动态字段 |
| G-NTP-6 | 旧 tracked 结果文档过期且未经本轮复跑 | 2026-08-27 < 2026-09-13 | P5 产物重生成 |
| G-NTP-7 | pcap/NIC 双输出本车道未实测 | 本文档阶段未启动 live DB/NIC | P5 双输出回归 |

## 11. 修订记录

- v1.0.0（2026-09-29）：按 `ntp.json` 逐条建立索引、断言、五层对账、存量审计、过期产物登记、缺口与覆盖反查建议。自审 2 轮，末轮干净；待独立隔离复审。

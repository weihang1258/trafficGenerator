# JTT905（JT/T 905-2014）测试用例契约

> 版本：v2.0.1（2026-10-01，层链迁移后的 as-built 对账）
> 机器真相：`trafficgen/test/protocol_pcap/cases/jtt905.json`，13 例（9 正、4 负），JSON 顺序为本文件唯一 ID 顺序。
> 本轮只登记现有契约；未有落盘证据的字节/包数均标为待 P5 重跑，不宣称 suite 或 NIC 已通过。

## 1. T1 三源回指与测试范围

| 来源 | 规范/行为面 | 设计条目 | 用例 |
|---|---|---|---|
| JT/T 905-2014 消息表、SmallChi/JT905 金向量 | 7E 定界、转义、XOR、12B 头、签到/心跳/签退/应答 | design §1、§2.1、§3 | T1–T7、T9、T14 |
| planner 实际错误文案 | ISU 号、车牌、Result、BCD 位数校验 | design §3、§8 G-JTT905-4 | T10–T13 |
| 现网行为 | TCP/10700 长连接、请求后中心应答 | design §2.3；无在库 pcap | T1/T4/T6；真实平台抓包待确认 |

## 2. T2 测试点清单与矩阵

规范→场景→代码分支→用例：

| 测试点 | 场景 | 分支/输出 | ID |
|---|---|---|---|
| TCP 握手、10700、挥手 | 基线会话 | TCP planner + collector | T1–T7、T9、T14 正例 |
| 7E/体长/ISU BCD/SN/XOR | 单签到 | JTT905 builder/parser | T2 |
| 签到业务体字段 | license/qualification/plate/时间 | buildCheckInBody | T3 |
| 空心跳与应答 | 自定义 heartbeat + response | procedures 编排 | T4/T7 |
| 签退业务体 | 时间、计费、次数、方式 | buildCheckOutBody | T5 |
| 0x8001 与 0x0001 | 双向 5B 应答；T6 的 `0x0001` 使用实现缺省 `ReplyMsgId=0x8300`，仅验证应答引用字段，不宣称生成 0x8300 下行消息 | response binding | T6/T14 |
| 位置块 | alarm/status/lat/lng/speed/direction/time | optional position | T9 |
| Result 枚举 0/1/2 | 成功/失败/消息有误 | response body | T6/T14 |
| 非法边界 | ISU/车牌/Result/BCD | ValidateConfig 返回错误 | T10–T13 |

正交矩阵：IPv4×单流已覆盖；Result 0/1/2 已覆盖，3 当前为负例；业务体×心跳/应答组合由 T1/T4/T6/T14 覆盖。IPv6、动态策略、multi-flow、7D01、SN 回绕为缺口，见 design §8。断言边界以 JSON `frames`/`fields` 为准，待 P5 从落盘 pcap 校准。

## 3. T3 原子用例索引

| # | ID | 类型 | 单一行为 | 包数 |
|---:|---|---|---|---:|
| 1 | `jtt905_t1_baseline` | 正 | 自动签到→应答→心跳→应答→签退→应答，含握手/挥手 | 12 |
| 2 | `jtt905_t2_envelope_header` | 正 | 7E、MsgId、纯体长、ISU BCD、SN、XOR、末 7E | 7 |
| 3 | `jtt905_t3_checkin_body` | 正 | 签到 license/qualification/plate/BCD 时间 | 7 |
| 4 | `jtt905_t4_heartbeat_pair` | 正 | 空心跳、SN 递增、平台 SN 与 ReplySN 绑定 | 8 |
| 5 | `jtt905_t5_checkout_body` | 正 | 签退计费字段、双时间、总次数、方式 | 7 |
| 6 | `jtt905_t6_resp_pair` | 正 | 0x8001/0x0001 双向 5B 应答 | 9 |
| 7 | `jtt905_t7_escape_bytes` | 正 | MsgNum=0x7E 的 7D02 线上转义 | 7 |
| 8 | `jtt905_t9_position_block` | 正 | 位置基本块八个可观察字段 | 7 |
| 9 | `jtt905_t10_neg_isu_11digits` | 负 | ISU 号 11 位拒绝 | — |
| 10 | `jtt905_t11_neg_plate_7ascii` | 负 | 7 字节车牌拒绝 | — |
| 11 | `jtt905_t12_neg_result_3` | 负 | Result=3 拒绝（当前实现口径） | — |
| 12 | `jtt905_t13_neg_bcd_digits` | 负 | BCD 时间位数错误拒绝 | — |
| 13 | `jtt905_t14_result_enum` | 正 | Result=1 与 Result=2 逐值线上字节 | 10 |

JSON 对账：9 正/4 负；正例 packet_count `[12,7,7,8,7,9,7,7,10]`，总和 74；正例 fields 24、frames 50；负例无成功断言。

## 4. T4 三项通用业务覆盖

- **同连接多轮操作**：T1 自动多轮，T4/T6/T14 自定义多消息；已覆盖。
- **非正常结束**：T10–T13 是配置拒绝而非业务应答失败；缺口 `G-JTT905-6`，待补 Result 非零真实事件序列和终止断言。
- **长保活/心跳**：T1/T4/T7/T14 生成心跳形，但间隔、3/5 次、多次回绕尚无 pcap 证据；缺口 `G-JTT905-3`。
- **应答消息引用**：T6 覆盖 `0x8001` 对签到和 `0x0001` 对应答引用；`0x0001` 的 `ReplyMsgId=0x8300` 是实现缺省引用值，不等同于已生成 0x8300 消息。

## 5. T5 存量逐条审计

13 条存量 JSON ID 全部保留并在 §3 有一对一条目；无重复、无虚构、无删除。历史合集 C-01…C-38 不属于当前机器契约：能映射的已归入 T1–T14，不能映射的（多 ISU、IPv6、7D01、动态、异常状态）登记为 design §8 缺口，不冒充已覆盖。

## 6. T6 失败路径与可观察断言

T10–T13 每例均为 `expect_error=true`、带唯一 `error_contains`，没有 `packet_count`/`frames` 成功断言：

| ID | 输入 | 锚词 |
|---|---|---|
| T10 | `isu_id="12345678901"` | `ISUId "12345678901" must be 12 digits` |
| T11 | `plate_no="A123456"` | `PlateNo length 7 > 6` |
| T12 | procedure `result=3` | `Result 3 > 2` |
| T13 | `on_duty_power_on_time="20240803"` | `OnDutyPowerOnTime "20240803" must be 12 digits (yyyyMMddHHmm)` |

正例断言输出字段而非只断言对象存在：端口、TCP flags、TCP len、MsgId、SN、应答体、转义字节、位置字段均以 JSON `fields`/`frames` 钉定；这些数值尚待 P5 落盘复核。负例必须经真实 MCP 任务提交后确认错误传播，当前不写“0 帧已验证”。所有 4 个负例 `expect` 严格仅含 `expect_error` 与 `error_contains`。

## 7. C 契约与未运行边界

- **C1 层链**：13/13 `spec_json.layers` 严格为 `[ip,jtt905]`；无顶层业务子映射、flat 地址/端口或顶层 `count`。
- **C2 数量承载**：13/13 未声明 `flow_control`，均为单流案例；多流/数量策略尚未覆盖，不能从 `packet_count` 反推生成配置数量。
- **C3 正负分界**：9 个正例才有 `packet_count`/`fields`/`frames`；4 个负例仅验证错误传播，不得写成功 PCAP 或 completed-0。
- **C4 负例形状**：4/4 `expect` 严格仅 `{expect_error,error_contains}` 两键。

以上为 JSON 结构审计结果，不是运行结果。当前未运行 MCP 任务、suite、pcap/tshark 或 NIC tcpdump；因此包数、偏移、线字节和错误传播均待 P5 实跑，不宣称通过。

## 8. 执行与覆盖缺口

执行顺序为 MCP 建任务→真实生成/落盘→tshark 或字节脚本逐字段核对；全量跑 13 条，不以增量或离线 planner 代替。NIC tcpdump、IPv6、多 ISU/flow、动态五策略、7D01、SN=65535 回绕、Result=3 最终标准裁定均待 design §8 的 G-JTT905-2…7 计划。

## 9. 修订记录

- v2.0.1（2026-10-01）：按 C4 删除四个负例的 `expect.notes`；同步明确 T6 的 `0x0001` 仅携带缺省引用 `0x8300`，不代表生成 0x8300 下行消息，并校正三源与原子索引回指。四个负例 `expect` 严格仅含 `expect_error` 与 `error_contains`。 
- v2.0.0（2026-09-30）：按 T1–T6 重写为现有 JSON 的 13 例契约，去掉过期合集拆分声明和 38 条未接线 C-ID；补三源、测试点矩阵、三项业务覆盖、存量去向与失败路径。
- v1.0.0（2026-09-29）：历史 13 例 as-built 版本，内容保留于 git 历史。

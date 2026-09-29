# JTT905（JT/T 905-2014）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨批次二 as-built）  
> 日期：2026-09-29  
> 配套设计：`docs/protocol-designs/02-03-04-jt808-jt809-jtt905-design.md`（Part C，JTT905 相关段落）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/jtt905.json`（**13/13 ID 顺序一致，9 正 + 4 负；已用 Python 机读核对**）  
> 白话一句：**九条检查 JTT905 TCP 会话、签到/心跳/签退、应答、转义和位置/业务体；四条确认非法 ISU 号、车牌、Result 和 BCD 时间会被 planner 拒绝。**

## 1. 形状基线

本版只描述机器契约实际存在的 13 条，不把配套设计中尚未落入 cases JSON 的抽象 C-01…C-38 冒充已覆盖。

| 项 | 机读值 |
|---|---:|
| 总例数 | **13** |
| 正例 / 负例 | **9 / 4** |
| ID 顺序 | `jtt905_t1_baseline`, `jtt905_t2_envelope_header`, `jtt905_t3_checkin_body`, `jtt905_t4_heartbeat_pair`, `jtt905_t5_checkout_body`, `jtt905_t6_resp_pair`, `jtt905_t7_escape_bytes`, `jtt905_t9_position_block`, `jtt905_t10_neg_isu_11digits`, `jtt905_t11_neg_plate_7ascii`, `jtt905_t12_neg_result_3`, `jtt905_t13_neg_bcd_digits`, `jtt905_t14_result_enum` |
| case 顶层键 | 13/13 均为 `{expect,id,proto,spec_json,summary}` |
| `proto` | 13/13 为 `jtt905` |
| `spec_json` 顶层键 | **13/13 严格为 `{layers}`**；无顶层 `jtt905`、四元组或 `count` |
| 层形 | 13/13 为 `[ip,jtt905]`；地址在 `layers[0].ip`，业务配置在 `layers[1].jtt905` |
| 正例 `expect` | 9/9 有 `has_handshake=true`、`negotiated=true`、`terminates=true`；`packet_count` 共 9 条；`has_payload=true` 为 7 条（T4/T7 未声明该键） |
| 正例断言 | `fields` 共 **24** 条，`frames` 共 **50** 条；`expect.notes` 9/9 有 |
| 负例 `expect` | 4/4 为 `{expect_error,error_contains,notes}`；无 `packet_count`、`fields` 或 `frames` |

**证据口径**：JSON 中的 `frames`、`tcp.len`、MsgId、XOR、转义、字段偏移均是契约待核对内容；本轮没有宣称测试通过、PCAP 复跑或 NIC 证据。所有标注“P5”的字节/落盘核对均记为**待 P5 重跑**。

## 2. 形状与协议基线

配套设计 Part C 描述 JTT905 为 TCP/10700 会话，7E 定界、7D 转义、XOR 校验，业务主线为签到 → 心跳 → 签退。存量实现的实际 MsgId 以代码/JSON 相关摘要为准：签到 `0x0B03`、心跳 `0x0002`、中心应答 `0x8001`、签退 `0x0B04`；不能把设计较早段落中的 `0x1001/0x1002` 当作本 cases 契约。

- `jtt905_t1_baseline` 的摘要写明自动会话：3 握手 + 6 消息 + 3 挥手 = 12 帧。
- 单消息正例从 TCP 建连后的第 4 帧开始；包数必须以 JSON 的 `packet_count` 为准，不由设计摘要推算。
- T2/T3 的 `tcp.len=62`、T5 的 `tcp.len=106`、T7 的 `tcp.len=16`、T9 的 `tcp.len=87` 是已有机器断言，不表示本次已重新采集。
- T4 显式验证 `initial_sn=50` 与 `platform_initial_sn=60` 的绑定面；T6/T14 显式验证应答流水和消息 ID 绑定。
- T7 的 `initial_sn=126` 对应头内 `0x7e` 线上转义为 `7d 02`；这是 JTT905/808 族转义证据，待 P5 重跑确认。

## 3. 原子用例索引

| # | ID | 类型 | 实际覆盖 | 包数 | fields | frames |
|---:|---|---|---|---:|---:|---:|
| 1 | `jtt905_t1_baseline` | 正 | 自动签到→应答→心跳→应答→签退→应答；端口、SYN、PSH、MsgId 序 | 12 | 3 | 6 |
| 2 | `jtt905_t2_envelope_header` | 正 | 7E 定界、MsgId、纯体长、ISU BCD6、初始 SN、XOR、末定界 | 7 | 2 | 8 |
| 3 | `jtt905_t3_checkin_body` | 正 | license、qualification、plate、BCD 时间体字节 | 7 | 2 | 4 |
| 4 | `jtt905_t4_heartbeat_pair` | 正 | 空心跳体、SN 递增、中心应答平台 SN/绑定 | 8 | 3 | 3 |
| 5 | `jtt905_t5_checkout_body` | 正 | 签退业务体、双时间、BCD/数值字段、总次数、签退方式 | 7 | 2 | 6 |
| 6 | `jtt905_t6_resp_pair` | 正 | `0x8001` 与 `0x0001` 两种 5B 应答及绑定 | 9 | 4 | 6 |
| 7 | `jtt905_t7_escape_bytes` | 正 | `0x7e → 7d 02` 转义及帧长变化 | 7 | 2 | 3 |
| 8 | `jtt905_t9_position_block` | 正 | 位置块 alarm/status/经纬度/速度/方向/时间字节 | 7 | 2 | 8 |
| 9 | `jtt905_t10_neg_isu_11digits` | 负 | 11 位 `isu_id` 拒绝 | — | — | — |
| 10 | `jtt905_t11_neg_plate_7ascii` | 负 | 7 字节 ASCII `plate_no` 拒绝（上限 6） | — | — | — |
| 11 | `jtt905_t12_neg_result_3` | 负 | 嵌套 procedure 的 `result=3` 拒绝 | — | — | — |
| 12 | `jtt905_t13_neg_bcd_digits` | 负 | 8 位 `on_duty_power_on_time` 拒绝（要求 12 位） | — | — | — |
| 13 | `jtt905_t14_result_enum` | 正 | 中心应答 `result=1` 与 `result=2` 逐值线上字节 | 10 | 4 | 6 |

## 4. 正例断言契约

以下只抄录机器契约中的可观察断言，不增加未在 JSON 出现的字段。

### 4.1 `jtt905_t1_baseline`（12 帧）

`isu_id=103456789012`、`initial_sn=100`、`heartbeat_count=1`。断言：帧 1 `tcp.dstport=10700`、帧 1 `tcp.flags=0x002`、帧 4 `tcp.flags=0x018`；帧 4–9 偏移 55 的 MsgId 序为 `0b03,8001,0002,8001,0b04,8001`。MsgId 序待 P5 重跑。

### 4.2 `jtt905_t2_envelope_header`（7 帧）

显式签到 procedure，`initial_sn=7`。断言帧 1 目的端口 10700、帧 4 `tcp.len=62`；帧 4 偏移 54/55/57/59/65/67/114/115 分别钉 `7e`、`0b 03`、`00 2f`、ISU BCD `10 34 56 78 90 12`、SN `00 07`、`00 00`、XOR `a8`、`7e`。帧长和字节均待 P5 重跑。

### 4.3 `jtt905_t3_checkin_body`（7 帧）

签到体配置 `business_license=BL20240001`、`qualification_code=QC1101080001`、`plate_no=A12345`、`on_duty_power_on_time=202408030800`。帧 4 `tcp.len=62`；偏移 67、83、102、108 分别断言 license、qualification、plate、BCD 时间字节。体字节待 P5 重跑。

### 4.4 `jtt905_t4_heartbeat_pair`（8 帧）

`initial_sn=50`，自定义 heartbeat + center response，`platform_initial_sn=60`。断言帧 1 目的端口 10700、帧 4/5 PSH+ACK `0x018`；帧 4 偏移 54 为完整 `7e 00 02 00 00 10 34 56 78 90 12 00 32 b8 7e`，帧 5 偏移 65 为 `00 3c`，偏移 67 为 `00 32 00 02 00`。待 P5 重跑。

### 4.5 `jtt905_t5_checkout_body`（7 帧）

签退配置含 K 值、上下班时间、里程/营收/次数、`total_operations=12`、`sign_type=1`。断言帧 1 目的端口 10700、帧 4 `tcp.len=106`；偏移 108/110/116/153/157/158 分别为 `05 12`、上班 BCD、下班 BCD、总次数 `00 00 00 0c`、签退方式 `01`、XOR `c9`。待 P5 重跑。

### 4.6 `jtt905_t6_resp_pair`（9 帧）

签到后显式中心通用应答和 ISU 通用应答，二者 `result=0`。帧 1 目的端口 10700，帧 4/5/6 的 flags 均为 `0x018`；帧 5 偏移 55/65/67 为 `80 01`、`00 00`、`00 05 0b 03 00`；帧 6 对应 `00 01`、`00 06`、`00 00 83 00 00`。ReplySN/ReplyId 绑定待 P5 重跑。

### 4.7 `jtt905_t7_escape_bytes`（7 帧）

`initial_sn=126`、heartbeat procedure。断言帧 1 目的端口 10700、帧 4 `tcp.len=16`；帧 4 偏移 54/66/69 为 `7e`、`7d 02`、`7e`。转义增量待 P5 重跑。

### 4.8 `jtt905_t9_position_block`（7 帧）

签到含 position：`alarm_flag=1`、`status_flag=2`、`lat=12222222`、`lng=132444444`、`speed=60`、`direction=0`、时间 `240803080000`。断言帧 1 目的端口 10700、帧 4 `tcp.len=87`；偏移 67、71、75、79、83、85、86、92 分别钉报警、状态、纬度、经度、速度、方向、时间、附加 6B。待 P5 重跑。

### 4.9 `jtt905_t14_result_enum`（10 帧）

签到 → center response `result=1` → heartbeat → center response `result=2`。断言帧 1 目的端口 10700，帧 4/5/6 flags 为 `0x018`；帧 5 偏移 55/65/67 为 `80 01`、`00 00`、`00 05 0b 03 01`；帧 7 对应 `80 01`、`00 01`、`00 06 00 02 02`。该例补齐 Result 1/2 逐值正例；字节待 P5 重跑。

## 5. 负例契约

负例的 `expect` 实际键集合为 `{expect_error,error_contains,notes}`，因此本契约只要求 planner/ValidateConfig 失败并命中 JSON 子串；JSON 没有声明负例包数，不得补写“0 帧已实测”。

| ID | 注入 | `error_contains` | 设计/实现锚 |
|---|---|---|---|
| `jtt905_t10_neg_isu_11digits` | `isu_id="12345678901"` | `ISUId "12345678901" must be 12 digits` | `ValidateConfig` 顶层标量；设计 5C.1 Phone/ISU 12 位原则 |
| `jtt905_t11_neg_plate_7ascii` | `plate_no="A123456"` | `PlateNo length 7 > 6` | planner `ValidateConfig`；存量实现上限为 6 ASCII |
| `jtt905_t12_neg_result_3` | procedure `center_general_response,result=3` | `Result 3 > 2` | `ValidateConfig` 遍历嵌套 procedures；当前线契约为 0–2 |
| `jtt905_t13_neg_bcd_digits` | `on_duty_power_on_time="20240803"` | `OnDutyPowerOnTime "20240803" must be 12 digits (yyyyMMddHHmm)` | planner 位数校验 |

**设计差异登记**：配套设计 Part C.4/5C.1 仍列 Result 3 及若干旧字段/旧消息面；当前 cases 与实现摘要明确以 Result 0–2、`isu_id`、JTT905 实际业务字段为准。该差异不能被本 4 条负例表述为“设计全覆盖”。

## 6. 覆盖对账

### 6.1 机器契约对账

- 13 条 ID：JSON 顺序与 §3 一致。
- 9 正例 + 4 负例 = 13。
- 13/13 `spec_json` 顶层键严格 `{layers}`；无扁平顶层业务子映射。
- 正例 `packet_count` 总和为 **74**（12+7+7+8+7+9+7+7+10）；正例 `fields` **24**；`frames` **50**。
- 负例 `expect_error` **4/4**；`error_contains` **4/4**；无正例字段/包数键。

### 6.2 与配套设计的诚实对账

配套设计 Part C §8C 列出 38 条设计级测试点；当前机器契约只有 13 条，不能宣称其余 25 条已接线。尤其是设计中的 C-01…C-38 与 JSON 的 `jtt905_t*` ID 不是一对一映射，本文以机器 ID 为唯一权威。

已落入本契约的设计面：签到/心跳/签退主线、中心/ISU 应答、MsgSN/平台 SN、7E 定界与转义、位置块、部分业务体、部分 Result 枚举、4 个 planner 负例。未落入或不完整的设计面登记在 §7。

## 7. P3 固定动作与缺口（G-JTT905-N）

### 7.1 三项固定动作

| 固定动作 | 本契约结论 |
|---|---|
| 同连接/同流多轮操作 | **已覆盖**：T1 自动多轮；T4/T6/T14 自定义多消息；但未覆盖设计要求的 heartbeat×3/×5 全量形状 |
| 非正常结束 | **缺口**：现有 4 负例是配置拒绝，不是业务应答失败后的状态机结束；待 P5/P4 增例 |
| 长保活/心跳 | **部分覆盖**：T1/T4/T7/T14 有心跳，但无实际间隔断言，待 P5 重跑 |

### 7.2 缺口清单

| 编号 | 缺口 | 现状与建议 |
|---|---|---|
| G-JTT905-1 | 设计与实现消息 ID/字段命名不一致 | 配套设计仍有 `0x1001/0x1002` 与 Phone/Driver 字段，而机器契约使用 `0x0B03/0x0B04`、`isu_id`、出租车业务字段；统一设计或另附勘误后再扩例 |
| G-JTT905-2 | C-01…C-38 设计面未全映射 | 仅 13 条 JSON；补例前不得宣称 38 条设计测试覆盖 |
| G-JTT905-3 | Result=3 设计/实现口径冲突 | 设计列 0–3，当前负例明确 3 拒绝；需标准/实现裁定，并更新设计或 cases |
| G-JTT905-4 | 签到/签退业务体字段断言不足 | T3/T5 主要用 `tcp.len` 与 frames；待 P5 重跑并逐字段对齐真实 body |
| G-JTT905-5 | 0x7D 转义未覆盖 | T7 只有 `0x7E→7D02`；补 `0x7D→7D01` 真字节例 |
| G-JTT905-6 | Result=0/1/2 仅部分逐值 | T6 覆盖 0，T14 覆盖 1/2；ISU 方向逐值和 Result=3 的最终裁定仍缺 |
| G-JTT905-7 | 心跳间隔、回绕和多心跳缺例 | 无 `heartbeat_count=3/5`、实际间隔、`initial_sn=65535` 回绕断言 |
| G-JTT905-8 | 多 ISU/flow 隔离缺例 | 无设计 C-21/C-22 形状；待多 flow 集成测试 |
| G-JTT905-9 | 负例未声明 packet outcome | 机器契约无 `packet_count=0`；不得凭经验补成已验证 0 帧，待完整执行链补证据 |
| G-JTT905-10 | IPv6、NIC、真实 PCAP 链接缺证据 | 当前 cases 为 IPv4 层形；本轮不宣称 NIC 或 PCAP 复跑，均待 P5 |

## 8. 执行建议

1. P4 先裁定 G-JTT905-1/G-JTT905-3 的设计与实现权威，再补 C-01…C-38 中能落到实际 schema 的缺口；不要先改机器契约数字。
2. P5 按 JSON 顺序重跑 9 条正例，逐条核对 `packet_count`、24 条 fields、50 条 frames；尤其核对 T1/T2/T4/T7/T14 的 MsgId、SN、XOR 与转义。
3. 单独跑 4 条负例，记录 planner 错误传播和是否产生输出；只有取得执行证据后，才可在文档写负例帧数。
4. 增加 `0x7d` 转义、heartbeat interval/回绕、multi-ISU、ISU Result 方向和 IPv6/NIC 覆盖后，重新机读本表。
5. 若按设计恢复 0–3 Result，必须同步修改 T12 的负例语义和错误锚，不得让设计与 cases 并存两套枚举真相。

## 9. 存量审计

- **保留 13**：所有 JSON ID 均有对应 §3 条目，未发现重复或虚构 ID。
- **改写 0**：本次只建立 as-built 文档，不改机器契约。
- **作废 0**：没有删除任何存量例。
- **待补 10 个缺口**：见 G-JTT905-1…G-JTT905-10；这些是文档/测试覆盖缺口，不把它们伪装成现有例。
- `spec_json` 扁平残留审计：**0 条**；13 条全部纯 `{layers}`，因此不存在需要清理的顶层业务子映射。

## 10. 反查门断言

供主线程合入后登记，本文不修改 gate 文件：

1. `len(cases['jtt905']) == 13`，ID 集合和顺序严格等于 §3。
2. 正/负分布为 9/4；负例 ID 恰为 T10–T13。
3. 13/13 `spec_json` 顶层键严格 `{layers}`，层形严格 `[ip,jtt905]`。
4. 正例 `packet_count` 按 JSON 为 `[12,7,7,8,7,9,7,7,10]`；总和 74。
5. 正例 fields 总数 24、frames 总数 50；负例无 fields/frames/packet_count。
6. 负例 `error_contains` 严格匹配四个 JSON 字符串，不得把设计旧错误文案替换进去。
7. T1 MsgId 序、T7 `7d 02`、T14 Result 1/2 字节钉均标记为待 P5 重跑，不得登记为已复跑证据。

## 11. 修订记录

- v1.0.0（2026-09-29）：新建 JTT905 as-built 测试用例契约；按机器 JSON 机读核对 13/13 ID 顺序、9 正/4 负、13 个 `{layers}` 顶层形、24 条 fields、50 条 frames、正例包数总和 74；登记设计与当前实现的消息 ID/Result 枚举差异及 G-JTT905-1…10 缺口。自审 2 轮，末轮干净。所有未有本轮执行证据的内容均标为待 P5 重跑。

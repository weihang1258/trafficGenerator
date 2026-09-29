# JT809（JT/T 809-2019）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨批次二 as-built）  
> 日期：2026-09-29  
> 配套设计：`docs/protocol-designs/02-03-04-jt808-jt809-jtt905-design.md` Part B（JT809）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/jt809.json`（14/14 ID 与本文 §2 同序，机读核对）  
> 实现：`trafficgen/internal/protocol/jt809/`；链层入口为 `layer_gen.go` 的 `PlanWithConfig` 路径

> 白话一句：**十四条检查覆盖主链登录/注销、2019 信封与登录体、保活、断开/关闭、从链路双流、转义和登录应答；三条检查越界配置被拒绝。本文记录机器契约现状，不声称本轮 pcap/NIC 重跑通过。**

## 1. 测试原则和形状基线

用例按机器契约逐条登记；一个用例只钉一个协议行为或一组不可拆的线格式事实。实现以 JT809 当前线层为准：`5B` 起始符、`5D` 结束符、未转义内容上的 CRC16、整体转义；2011/2013 头长 22B，2019 头长 30B（追加 8B `time_sec`）；`MsgLength` 是整帧长度 `1 + header + body + 2 + 1`。

**2026-09-29 机读形状核对：**

| 项 | 值 |
|---|---|
| 例数 | **14**（11 正 + 3 负） |
| ID 顺序 | `jt809_t1_baseline` … `jt809_t14_login_resp_body`，以 JSON 顺序为权威 |
| 例顶层键 | 14/14 均为 `{expect,id,proto,spec_json,summary}` |
| `spec_json` 顶层键 | **14/14 均为 `{layers}`**；无顶层 `jt809`、无 flat 四元组、无 `count` |
| 层形 | **`[ip,jt809]` ×14**；地址住 `layers[0].ip`，业务配置住 `layers[1].jt809` |
| 正/负 | 11 正（均 `packet_count`）+ 3 负（`expect_error`） |
| 正例包数 | 7 帧 ×7、8 帧 ×2、13 帧 ×1、14 帧 ×1 |
| 正例字段断言 | **35 条**；`frames` 线字节断言共 **59 条**（逐例由 JSON 机读计数） |
| 负例 `expect` | 3/3 含 `expect_error`、`error_contains`、`notes`；因此**不是**严格仅两键的“干净负例”形状 |

**证据边界：**上述数字来自 JSON 机读。`expect.fields`、`expect.frames` 是机器契约要求，不等于本轮重新抓取；本文不声称 pcap 复跑、NIC 抓包或测试通过。实际执行应待 P5 重跑。

## 2. 原子用例索引（14 ID = 11 正 + 3 负）

| # | ID | 类型 | 覆盖行为 | 包数 | 字段断言 | frames 断言 |
|---:|---|---|---|---:|---:|---:|
| 1 | `jt809_t1_baseline` | 正 | 主链 `0x1001` 登录 + `0x1003` 注销，3 握手 + 2 消息 + 3 挥手 | 8 | 7 | 2 |
| 2 | `jt809_t2_envelope_header` | 正 | 2019 30B 头、整帧长度、版本/时间/加密占位/CRC | 7 | 2 | 17 |
| 3 | `jt809_t3_login_body` | 正 | 2019 登录体 `UserId/Password/GNSS/DownLinkIP/Port` | 7 | 2 | 7 |
| 4 | `jt809_t4_keepalive_pair` | 正 | `0x1005` → `0x1006` 空体及双方向 SN | 8 | 3 | 6 |
| 5 | `jt809_t5_disconnect` | 正 | `0x1007`，ErrorCode=1 | 7 | 2 | 3 |
| 6 | `jt809_t6_close_notify` | 正 | `0x1008`，ReasonCode=2，EncryptFlag/Key | 7 | 2 | 4 |
| 7 | `jt809_t7_slave_dual_flow` | 正 | 主链 + 从链两条 TCP 4-tuple、`0x9001` VerifyCode、同 GroupID | 14 | 6 | 4 |
| 8 | `jt809_t8_slave_resp_negative` | 正 | `0x9002` Result=1 从链应答 | 13 | 4 | 3 |
| 9 | `jt809_t9_escape_bytes` | 正 | `0x5B/0x5D` 内容触发双 escape，帧长 74 | 7 | 2 | 5 |
| 10 | `jt809_t10_logout` | 正 | `0x1003` UserId + Password 12B 体 | 7 | 2 | 4 |
| 11 | `jt809_t11_neg_gnss_overflow` | 负 | `gnss_center_id=1000000000` 越界 | — | — | — |
| 12 | `jt809_t12_neg_version_flag` | 负 | `version_flag=3` 越界 | — | — | — |
| 13 | `jt809_t13_neg_error_code` | 负 | `main_disconnect.error_code=3` 越界 | — | — | — |
| 14 | `jt809_t14_login_resp_body` | 正 | `0x1002` Result(1B)+VerifyCode(4B) | 7 | 3 | 4 |

## 3. 正例逐项契约

### 3.1 `jt809_t1_baseline`（8 帧）

输入为 `10.0.0.1 → 20.0.0.1`、`gnss_center_id=291`、`initial_sn=100`，顺序为 `main_login`、`main_logout`。契约要求主链 TCP 8812，首三帧为 SYN/SYN-ACK/ACK，消息帧为第 4、5 帧，末三帧为挥手；字段断言共 7 条，frames 钉第 4 帧 `10 01`、第 5 帧 `10 03`（offset 63）。

### 3.2 `jt809_t2_envelope_header`（7 帧）

2019 形：`version_flag=2`、`version_bytes=010000`、`time_sec=1700000000`、`initial_sn=7`。第 4 帧 TCP payload 的整帧长度为 84：`1 + 30 + 50 + 2 + 1`；frames 逐字节钉 `5B`、MsgLength `00 00 00 54`、SN `7`、MsgId `10 01`、GNSS `0x123`、Version `010000`、Encrypt/Key、Time `1700000000`、CRC `22 6D`、尾 `5D`。这些是契约断言，待 P5 重跑复核。

### 3.3 `jt809_t3_login_body`（7 帧）

2019 登录体输入：GNSS=1001、UserId=2002、Password=`pw123456`、DownLinkIP=`192.168.1.100`、Port=8813、Time=1700000000。登录体为 50B，整帧长度为 84；frames 钉 MsgId `10 01`、UserId `00 00 07 D2`、password 原字节、GNSS `00 00 03 E9`、IP 原字节、端口 `D5 53`。

### 3.4 `jt809_t4_keepalive_pair`（8 帧）

输入 `initial_sn=50`、`platform_initial_sn=60`，流程为 `main_keepalive`、`main_keepalive_resp`。第 4 帧为 `0x1005`、SN=50，第 5 帧为 `0x1006`、SN=60；二者均空体（MsgLength=26，即 `1+22+0+2+1`）。

### 3.5 `jt809_t5_disconnect`（7 帧）

`main_disconnect`、`error_code=1`。第 4 帧 MsgId=`10 07`，体中 ErrorCode=`01`；主链端口为 8812，消息后进入 TCP 挥手。

### 3.6 `jt809_t6_close_notify`（7 帧）

`main_close`、`reason_code=2`，并设置 `encrypt_flag=1`、`encrypt_key=9999`。第 4 帧头中钉 EncryptFlag=`01`、Key=`00 00 27 0F`，体中 ReasonCode=`02`；该例登记的是加密占位字段，不代表真实加密。

### 3.7 `jt809_t7_slave_dual_flow`（14 帧）

主链为下级发起 `10.0.0.1:12345 → 20.0.0.1:8812`，从链为上级发起 `20.0.0.1:8812 → 10.0.0.1:8813`；主链消息后才打开从链 TCP，最终主链先挥手、从链后挥手。第 8 帧为从链 `0x9001`，SN=5、VerifyCode=`0x12345678`；两条流共享 GroupID。契约字段钉主链 8812、从链 SYN 8813、从链方向和端口，frames 钉 MsgLength=30、MsgId=`90 01`、SN=5、VerifyCode。

### 3.8 `jt809_t8_slave_resp_negative`（13 帧）

仅配置从链 `slave_connect_resp`、Result=1；主链无消息面但仍有主链握手与挥手。从链第 7 帧为 `0x9002`，TCP payload length=27，MsgId=`90 02`，体 Result=`01`，方向为从链 8813 → 上级。这里“negative”是业务 Result，不是 `expect_error` 负例。

### 3.9 `jt809_t9_escape_bytes`（7 帧）

2011/2013 形 `version_flag=1`，`down_link_port=0x5B5D`。原始内容中的 `5B`、`5D` 在线上分别变为 `5A 01`、`5E 01`；未转义整帧 72B，加两个扩位后为 74B。契约钉首尾 `5B/5D`、转义字节、CRC `49 D4`，待 P5 重跑核对。

### 3.10 `jt809_t10_logout`（7 帧）

`gnss_center_id=291`、UserId=777、Password=`logout88`、InitialSN=9，流程为 `main_logout`。第 4 帧 MsgId=`10 03`，体为 UserId `00 00 00 03` + password 字节；全流程仍含主链握手和挥手。

### 3.11 `jt809_t14_login_resp_body`（7 帧）

`main_login_resp`，Result=0、VerifyCode=`0x12345678`、InitialSN=3。第 4 帧为上级方向 `0x1002`，整帧 TCP length=31：`1 + 22 + 5 + 2 + 1`；体钉 Result=`00`、VerifyCode=`12 34 56 78`、CRC=`9A F1`。

## 4. 负例契约

3 个负例都在 planner/validator 阶段拒绝；JSON 未给出成功包数或字段断言。`expect.notes` 仍存在，故不能把它们描述为严格的 `{expect_error,error_contains}` 两键形状。

| # | ID | 输入 | `error_contains` | 代码锚/拦截面 |
|---:|---|---|---|---|
| N-1 | `jt809_t11_neg_gnss_overflow` | `gnss_center_id=1000000000` | `out of range [0,999999999]` | registry V9 首拦截；planner `ValidateConfig` 同义锚 `GNSSCenterId … > 999999999` |
| N-2 | `jt809_t12_neg_version_flag` | `version_flag=3` | `out of range [0,2]` | registry V9 首拦截；planner `VersionFlag 3 > 2` |
| N-3 | `jt809_t13_neg_error_code` | `main_disconnect.error_code=3` | `ErrorCode 3 > 2` | 嵌套 `procedures` 由 `ValidateConfig` 遍历拒绝；V9 不下探该字段 |

负例的“无成功 PCAP/无 completed-0 假成功”是执行要求，不是本轮已验证结果；待 P5 重跑时必须验证错误传播。

## 5. 覆盖与实现对账

### 5.1 设计覆盖

配套设计 Part B 的主链登录、注销、断开通知、双 TCP 主/从链路、MsgSN、2019 登录体、加密占位与转义等要求，已由 14 例中的对应输入/frames 契约登记。当前 cases JSON **没有**设计文档旧清单中的车辆容器 `0x1200/0x1300/0x1400/0x1500/0x1600`、从链容器 `0x9100/0x9600` 例，因此不能宣称这些面已覆盖。

### 5.2 as-built 增量与设计差异

实现当前为 `5B/5D + CRC16 + 22/30B` 信封，且登录体为 `UserId + Password(8) + [2019 GNSS(4)] + DownLinkIP(32) + Port(2)`；这与合集设计中“无起止符、32B 固定头、无显式校验、25B 登录体”的旧描述不一致。本文以 cases JSON、`builder.go` 和 `jt809.go` 实现为准，不把旧设计描述当作当前线事实。

合集设计未覆盖当前实现和 cases 已出现的：

- `0x1005` 主链保活、`0x1006` 主链保活应答（T-4）；
- `0x1008` 主链关闭通知（T-6）；
- 2019 30B 头的固定 `time_sec`、CRC16 和整帧 MsgLength 口径（T-2）；
- `0x1002` Result+VerifyCode 登录应答体的当前线钉（T-14）；
- `0x9001/0x9002` 从链连接及其双流时序的当前线钉（T-7/T-8）；
- `0x5B/0x5D` 转义字节 `5A01/5E01` 的当前实现口径（T-9）。

上述设计未覆盖、实现已含的差异统一登记为缺口 **G-JT809-N**，不得虚构为合集设计已有依据。

## 6. P3 固定动作

### 6.1 §3.15 三项

| 项 | JT809 对照 | 状态 |
|---|---|---|
| 同连接/同流内多轮操作 | 主链登录→业务/保活→注销；T-1、T-4、T-10 覆盖当前已编排消息面 | 已覆盖（仅当前 16 型链路管理面） |
| 非正常结束 | `0x1007` ErrorCode、`0x1008` ReasonCode；T-5/T-6 | 已覆盖 |
| 长保活 | 当前有单对 `0x1005→0x1006`，无重复保活次数/长时序压力例 | **G-JT809-1：待补** |

### 6.2 A′/B′

- **A′（协议面待补）：** 0x1200/0x1300/0x1400/0x1500/0x1600 与 0x9100/0x9600 容器；从链注销/保活/断开/关闭族；结果枚举逐值；MsgSN 回绕；多平台并发；车辆头字段；文件/位置/报警子体；2011/2013 与 2019 全版本对照；长保活重复次数。
- **B′（框架/形状面）：** 负例 `expect` 仍带 `notes`，不是严格二键负例，登记 **G-JT809-2**；其余 14 例 `spec_json` 已无顶层游离键，未发现 flat 残留。

## 7. P5 执行建议

1. 先按 JSON 顺序重跑 14 例，负例必须观察 task error，不能只看“0 包完成”。
2. 正例逐帧核对 `packet_count`、TCP 方向/端口和 35 条字段断言，并按 `frames` offset 复核 59 条线字节断言。
3. T-2 固定 `time_sec=1700000000`，确认 2019 头不会因运行时钟漂移；T-9 确认转义后 CRC 与尾界；T-7/T-8 确认主从 4-tuple、顺序和 GroupID。
4. 生成 pcap 后再做 tshark/NIC 对账；本文件不声称 NIC 证据或 pcap 重跑通过。
5. 补写合集设计缺口 G-JT809-N 前，不得把旧 32B/无 CRC 口径继续当作实现契约。

## 8. 存量审计（14 例逐条去向）

| ID | 去向 | 现状/后续 |
|---|---|---|
| `jt809_t1_baseline` | 保留 | 主链基线；P5 重跑 |
| `jt809_t2_envelope_header` | 保留 | 2019 头与 CRC 线钉；P5 重跑 |
| `jt809_t3_login_body` | 保留 | 登录体字段；P5 重跑 |
| `jt809_t4_keepalive_pair` | 保留 | 0x1005/0x1006 增量覆盖；补设计缺口 |
| `jt809_t5_disconnect` | 保留 | 0x1007；P5 重跑 |
| `jt809_t6_close_notify` | 保留 | 0x1008 增量覆盖；补设计缺口 |
| `jt809_t7_slave_dual_flow` | 保留 | 双流/GroupID/0x9001；P5 重跑 |
| `jt809_t8_slave_resp_negative` | 保留 | 0x9002 Result=1 业务负路径；P5 重跑 |
| `jt809_t9_escape_bytes` | 保留 | 双 escape；P5 重跑 |
| `jt809_t10_logout` | 保留 | 注销体；P5 重跑 |
| `jt809_t11_neg_gnss_overflow` | 保留 | registry/planner 锚；P5 错误传播 |
| `jt809_t12_neg_version_flag` | 保留 | registry/planner 锚；P5 错误传播 |
| `jt809_t13_neg_error_code` | 保留 | 嵌套 ValidateConfig 锚；P5 错误传播 |
| `jt809_t14_login_resp_body` | 保留 | 0x1002 wire 例；补设计缺口 |

统计：**保留 14，作废 0，等价覆盖 0；缺口 3 个主项**（G-JT809-N 设计覆盖差异、G-JT809-1 长保活、G-JT809-2 负例形状）。

## 9. 覆盖反查建议

1. `len(cases['jt809']) == 14`，ID 集合及顺序等于本文 §2。
2. 14/14 `spec_json` 顶层键严格为 `{layers}`；层形严格为 `[ip,jt809]`。
3. 正例数 11，负例数 3；正例包数分布为 7×7、8×2、13×1、14×1。
4. 正例字段断言总数为 35；frames 断言总数为 59。
5. 负例锚词集合包含 `out of range [0,999999999]`、`out of range [0,2]`、`ErrorCode 3 > 2`。
6. P5 后所有正例应满足 handshake/termination；双流例应满足主链 8812、从链 8813 与同 GroupID。
7. 不把 `0x1005/0x1006/0x1008`、CRC16、2019 30B 头等 as-built 增量倒写成合集设计已有条款。

## 10. 现状缺口清单

| 编号 | 缺口 | 影响 | 处理 |
|---|---|---|---|
| G-JT809-N | 合集设计未覆盖 0x1005/0x1006/0x1008、CRC16/22/30B 信封、0x9001/0x9002 当前线形、0x1002 当前体形、转义口径 | 设计→实现回指不完整 | P4 补 JT809 专属设计增量；本稿如实登记 |
| G-JT809-1 | 仅一对保活，无重复/长时序保活 | §3.15 长保活覆盖不足 | 增加重复保活与 SN 递增例 |
| G-JT809-2 | 3 个负例 `expect` 带 `notes` | 负例键形不严格 | 若框架契约要求纯两键，P4 清理并更新文档 |
| G-JT809-3 | 车辆容器/报警/定位/静态信息等设计面在当前 14 例中为零 | 不能宣称 JT809 业务全覆盖 | 按实现实际支持面补 cases；不以旧设计清单代替实测 |
| G-JT809-4 | 未有本轮 pcap/NIC 证据 | 线字节和包数尚待执行确认 | P5 重跑、tshark 与 NIC 分开留证 |

## 11. 修订记录

- v1.0.0（2026-09-29）：新建 JT809 as-built cases 契约。机读核对 14 例、11 正/3 负、ID 顺序、`{layers}` 顶层形、`[ip,jt809]` 层形、正例包数分布、35 条字段断言与 59 条 frames 断言；登记合集设计与当前实现的结构差异，特别标明设计未覆盖但实现已含的 0x1005/0x1006/0x1008 及当前 5B/5D+CRC16 信封；不宣称 pcap/NIC 重跑。自审 **2 轮，末轮干净**。
- v1.0.1（2026-09-29）：隔离复审修正 3 处：§1 与 §10 正例包数分布 7×8 → **7×7**（实际 T2/T3/T5/T6/T9/T10/T14）；§9 P5 复核步骤 frames 断言数 52 → **59**（与 §1/§10 对齐）。

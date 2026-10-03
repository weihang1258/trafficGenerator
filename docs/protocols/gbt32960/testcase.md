# GBT32960 测试用例契约

> 版本：v1.1.0（2026-09-30，层链文档轨）
> 配套设计：`docs/protocols/gbt32960/design.md` v1.2.0（设计文档按 JSON 实测 116 条对账）
> 机器契约：`trafficgen/test/protocol_pcap/cases/gbt32960.json`（116/116 ID 与本文 §2 一致，顺序一致）
> 白话一句：**七十条正例覆盖车端/平台端 TCP 消息编排、字段边界、校验与多流；四十六条负例验证配置、承载、长度和迁移残留会被拒绝。**

## 1. 测试原则和形状基线

用例从设计文档 §1–§9 的报文格式、12 个命令、配置校验、BCC、TCP 承载和层链迁移要求派生。每个 ID 只钉一个主要行为；负例保留故意注入的坏形状，不把它们误报为正例残留。

**2026-09-29 机读实测基线：**

| 项 | 值 |
|---|---:|
| 总例数 | **116** |
| 正例 / 负例 | **70 / 46** |
| `proto` | `gbt32960` ×116 |
| 正例包数 | `packet_count` ×70；值分布：9×1、11×34、12×1、13×12、14×1、15×11、17×4、21×2、22×1、26×1、31×1、57×1 |
| 负例包数 | 无 `packet_count`，均 `{expect_error,error_contains}` |
| 正例握手/协商/终止 | `has_handshake=true`、`negotiated=true`、`terminates=true`：70/70 |
| 正例断言 | `fields` 合计 64 条；`frames` 存在 62/70；`directional` 存在 12/70；例级 `expect.notes` 存在 69/70 |
| 负例 `expect` 形状 | `{expect_error,error_contains}` 严格 46/46 | 锚词已与 `trafficgen/internal/protocol/gbt32960/gbt32960.go`、`builder.go`、`trafficgen/internal/core/layers/chain_planner.go` 的拒绝分支逐项核对；迁移三例由 `strategy_convert.go`/层链检查分支提供锚词 |

**`spec_json` 顶层键分布（逐例机读，不做推断）：**

| 顶层键集合 | 数量 | 口径 |
|---|---:|---|
| `{layers}` | **112** | 常规形状；正负例均有（含两例 TCP MSS 层参数） |
| `{group_id,layers}` | **1** | `gbt_t117_multiflow_2vehicles`，多流分组 |
| `{gbt32960,layers}` | **1** | `gbt_neg_presence_top_gbt32960`，故意 presence 负例 |
| `{layers,src_ip}` | **1** | `gbt_neg_stray_src_ip`，故意 flat 字段负例 |
| `{count,layers}` | **1** | `gbt_neg_stray_count`，故意 flat 字段负例 |

正例的非负迁移面为 `{layers}`（112 例总数包含两例 TCP MSS 参数）；`{group_id,layers}` 是调度分组元数据，不是协议顶层配置。负例的 `gbt32960`、`src_ip`、`count` 故意保留以验证拒绝门。

**层链形状（由每层键序机读）：** `{tcp,gbt32960}` ×111；`{ip,tcp,gbt32960}` ×4；`{ip,udp,gbt32960}` ×1。UDP 载体只有 `gbt_t208_udp_carrier_rejected`，预期拒绝；IPv4/IPv6 例均在层链内显式承载。

## 2. 原子用例索引（JSON 顺序为权威）

以下列表按 JSON 原始顺序逐项抄录；`P` 为正例，`N` 为负例。包数为 `packet_count`，负例记 `—`。

| # | ID | 类 | 包数 | 主要覆盖 |
|---:|---|:---:|---:|---|
| 1 | `gbt_t001_login_full` | P | 11 | 登入完整流 |
| 2 | `gbt_t007b_subsys_codes` | P | 11 | 子系统编码 |
| 3 | `gbt_t008b_multi_infobody` | P | 13 | 多信息体 |
| 4 | `gbt_t011_ack_data` | P | 11 | 0x0C 确认数据 |
| 5 | `gbt_t013_remote_control` | P | 17 | 远程控制 |
| 6 | `gbt_t015_response_flags_01` | P | 13 | 下一上行 0x01 |
| 7 | `gbt_t016_response_flags_02` | P | 11 | 下一上行 0x02 |
| 8 | `gbt_t017_response_flags_03` | P | 9 | 下一上行 0x03 |
| 9 | `gbt_t021_vin_pad_20` | P | 11 | VIN 空格补齐 |
| 10 | `gbt_t029b_serial_65531` | P | 11 | 流水号上边界 |
| 11 | `gbt_t033_encrypt_03` | P | 11 | AES128 标记 |
| 12 | `gbt_t038_alarm_bit1` | P | 15 | 报警 bit1 |
| 13 | `gbt_t044_bcd_time` | P | 17 | BCD 时间 |
| 14 | `gbt_t049_report_times` | P | 15 | 上报时间 |
| 15 | `gbt_t052_full_2reports` | P | 15 | 两条上报 |
| 16 | `gbt_t053_platform` | P | 14 | 平台登入 |
| 17 | `gbt_t074_heartbeat` | P | 11 | 平台心跳 |
| 18 | `gbt_t079_reissue` | P | 17 | 补报 |
| 19 | `gbt_t093_logout_serial_inherit` | P | 15 | 登出继承流水号 |
| 20 | `gbt_t094_logout_serial_42` | P | 13 | 登出指定流水号 |
| 21 | `gbt_t101_bcc_inject` | P | 11 | BCC 注入 |
| 22 | `gbt_t107b_is_trans_battery_false` | P | 13 | 不传电池数据 |
| 23 | `gbt_t036_alarm_zero` | P | 13 | 报警全零 |
| 24 | `gbt_t037_alarm_all_ones` | P | 13 | 报警全一 |
| 25 | `gbt_t044b_utc_time` | P | 11 | 时区时间 |
| 26 | `gbt_t018_unsupported_resp` | P | 15 | 不支持应答 |
| 27 | `gbt_t088_empty_params` | P | 15 | 空参数 |
| 28 | `gbt_t033b_encrypt_04` | P | 11 | SM2 标记 |
| 29 | `gbt_t033c_encrypt_05` | P | 11 | SM4 标记 |
| 30 | `gbt_t061_status_trace` | P | 21 | 状态追踪 |
| 31 | `gbt_t084_zero_reports` | P | 11 | 零报告 |
| 32 | `gbt_t077_no_heartbeat` | P | 11 | 无心跳 |
| 33 | `gbt_t002_bcc_verify` | P | 11 | BCC 校验 |
| 34 | `gbt_t004_bcc_index_oob` | N | — | BCC 索引越界 |
| 35 | `gbt_t008_min_infobody` | P | 13 | 最小信息体 |
| 36 | `gbt_t010_hb_platform_vin` | P | 12 | 平台 VIN |
| 37 | `gbt_t019_resp_flags_invalid` | N | — | 应答标志非法 |
| 38 | `gbt_t020_vin_17b` | P | 11 | VIN 17B |
| 39 | `gbt_t022_vin_18b` | N | — | VIN 超长 |
| 40 | `gbt_t023_vin_nonascii` | N | — | VIN 非 ASCII |
| 41 | `gbt_t024_vin_empty` | N | — | VIN 缺失 |
| 42 | `gbt_t025_platform_empty_vin` | P | 11 | 平台空 VIN |
| 43 | `gbt_t026_sim_20b` | P | 11 | SIM 20B |
| 44 | `gbt_t028_sim_21b` | N | — | SIM 超长 |
| 45 | `gbt_t030_serial_65532` | N | — | 流水号上溢 |
| 46 | `gbt_t030b_serial_zero` | N | — | 流水号零值 |
| 47 | `gbt_t030c_vin_ioq` | N | — | VIN I/O/Q |
| 48 | `gbt_t031_encrypt_01` | P | 11 | 明文标记 |
| 49 | `gbt_t032_encrypt_02_rsa` | P | 13 | RSA 标记 |
| 50 | `gbt_t034_encrypt_invalid` | N | — | 加密值非法 |
| 51 | `gbt_t035_encrypt_default` | P | 11 | 加密默认值 |
| 52 | `gbt_t038b_alarm_bit19` | P | 13 | 报警 bit19 |
| 53 | `gbt_t039_alarm_9hex` | N | — | 报警 hex 长度 |
| 54 | `gbt_t040_alarm_badhex` | N | — | 报警非 hex |
| 55 | `gbt_t040b_alarm_3hex` | N | — | 报警短 hex |
| 56 | `gbt_t040c_alarm_maxlevel_4` | N | — | 报警等级越界 |
| 57 | `gbt_t043_report_alarm_override` | P | 15 | 上报报警覆盖 |
| 58 | `gbt_t045_login_time_default` | P | 11 | 登入时间默认 |
| 59 | `gbt_t046_login_time_badfmt` | N | — | 登入时间格式 |
| 60 | `gbt_t046b_login_time_no_tz` | N | — | 登入时间时区 |
| 61 | `gbt_t046c_login_time_oob` | N | — | 登入时间越界 |
| 62 | `gbt_t047_logout_default_no_reports` | P | 11 | 登出默认时间 |
| 63 | `gbt_t048a_logout_before_login` | N | — | 登出早于登入 |
| 64 | `gbt_t055_control_position` | P | 15 | 控制位置 |
| 65 | `gbt_t056_reissue_after_reports` | P | 21 | 上报后补报 |
| 66 | `gbt_t062_report_over_trace` | P | 17 | 追踪超报告 |
| 67 | `gbt_t063_trace_index_oob` | N | — | 追踪索引越界 |
| 68 | `gbt_t063b_trace_index_dup` | N | — | 追踪索引重复 |
| 69 | `gbt_t064_default_vehicle_body` | P | 13 | 默认车身体 |
| 70 | `gbt_t065_custom_fields_hex` | P | 13 | 自定义 hex |
| 71 | `gbt_t066_custom_odd_len` | N | — | 自定义奇数长度 |
| 72 | `gbt_t067_custom_nonhex` | N | — | 自定义非 hex |
| 73 | `gbt_t068_report_custom_override` | P | 15 | 自定义覆盖 |
| 74 | `gbt_t070_seq_ack_progression` | P | 11 | 确认序列 |
| 75 | `gbt_t071_mss_100` | N | — | MSS 过小 |
| 76 | `gbt_t072_default_port` | P | 11 | 默认端口 |
| 77 | `gbt_t076_platform_user_13` | N | — | 用户名超长 |
| 78 | `gbt_t078_heartbeat_negative` | N | — | 心跳值非法 |
| 79 | `gbt_t082_role_invalid` | N | — | Role 非法 |
| 80 | `gbt_t083_role_default` | P | 11 | Role 默认 |
| 81 | `gbt_t085_reports_1000` | P | 31 | 大量上报 |
| 82 | `gbt_t086_control_type_missing` | N | — | 控制类型缺失 |
| 83 | `gbt_t087_rc_resp_invalid` | N | — | 控制应答非法 |
| 84 | `gbt_t089_bcc_flip_frame` | P | 11 | BCC 翻转帧 |
| 85 | `gbt_t095_platform_domain` | P | 11 | 平台域名 |
| 86 | `gbt_t096_subsys_count_zero` | N | — | 子系统数零 |
| 87 | `gbt_t096a_code_length_zero` | N | — | 编码长度零 |
| 88 | `gbt_t097_subsys_codes_mismatch` | N | — | 编码数不符 |
| 89 | `gbt_t098_max_alarm_config` | N | — | 报警等级越界 |
| 90 | `gbt_t099_platform_id_18` | N | — | 平台 ID 超长 |
| 91 | `gbt_t100_connect_id` | P | 11 | ConnectID |
| 92 | `gbt_t027_sim_empty` | P | 11 | SIM 空值 |
| 93 | `gbt_t102_custom_65532` | N | — | 数据长度越界 |
| 94 | `gbt_t103_custom_over_mss` | N | — | MSS budget 越界 |
| 95 | `gbt_t108_logout_fail_teardown` | P | 15 | 登出失败挥手 |
| 96 | `gbt_t109_logout_serial_65532` | N | — | 登出流水号越界 |
| 97 | `gbt_t110_logout_time_badfmt` | N | — | 登出时间格式 |
| 98 | `gbt_t111_report_alarm_badhex` | N | — | 上报报警坏 hex |
| 99 | `gbt_t112_report_custom_odd` | N | — | 上报自定义奇数 |
| 100 | `gbt_t113_platform_pwd_21` | N | — | 平台密码超长 |
| 101 | `gbt_t114_platform_encseq_17` | N | — | 加密序列超长 |
| 102 | `gbt_t115_bcc_index_negative` | N | — | BCC 索引负数 |
| 103 | `gbt_t116_platform_hb_no_login` | P | 11 | 无登入心跳 |
| 104 | `gbt_t117_multiflow_2vehicles` | P | 26 | 双车辆多流 |
| 105 | `gbt_t118_dataunit_65531` | P | 57 | 数据单元上限 |
| 106 | `gbt_neg_presence_top_gbt32960` | N | — | 顶层 `gbt32960` 残留 |
| 107 | `gbt_neg_stray_src_ip` | N | — | 顶层 `src_ip` 残留 |
| 108 | `gbt_neg_stray_count` | N | — | 顶层 `count` 残留 |
| 109 | `gbt_t201_resp04_next_uplink` | P | 11 | 下一上行 0x04 |
| 110 | `gbt_t202_reissue_only_resp01` | P | 13 | 补报确认 |
| 111 | `gbt_t203_ipv4_layer_fixture` | P | 11 | IPv4 层链 |
| 112 | `gbt_t204_ipv6_layer_fixture` | P | 11 | IPv6 层链 |
| 113 | `gbt_t208_udp_carrier_rejected` | N | — | UDP 承载拒绝 |
| 114 | `gbt_t210_heartbeat_and_reports_line` | P | 15 | 心跳与上报编排 |
| 115 | `gbt_t211_vin_10b_default_pad` | P | 11 | VIN 默认补齐 |
| 116 | `gbt_t205_multiflow_dynamic_srcport` | P | 22 | 多流动态源端口 |

## 3. 正例断言契约（按族聚合）

70 条正例均要求 TCP 三阶段可观察结果：握手、协商、按顺序的 GBT32960 payload、挥手；具体 `fields`/`frames` 仍以 JSON 为唯一机器断言来源。以下按行为族聚合，覆盖 ID 不改变 §2 的权威顺序。

| 行为族 | ID 范围/成员 | 现状断言重点 |
|---|---|---|
| 登入、登出、确认、响应标志 | #1–#10、#19–#20、#26–#27、#62、#74、#95、#109–#110 | 0x01/0x04/0x0C 命令序列、VIN/SIM/流水号、0xFE 与下一上行响应结果；`packet_count` 9/11/13/15/17 |
| 信息体与报警 | #3、#12、#22–#24、#30–#31、#35、#52、#57、#64、#69–#70、#73、#81、#98 | 默认/最小/自定义信息体、报警边界、状态追踪、控制和大批量上报；字段断言由 `frames` 与 64 条 `fields` 覆盖 |
| 时间、编码、加密、VIN/SIM | #9–#11、#13–#14、#25、#28–#29、#33、#38、#42–#43、#48–#51、#58、#80、#92、#115 | BCD/时区、补齐、加密枚举、字符及边界值；动态时间例不硬编码运行时值 |
| 平台登入、心跳和平台扩展 | #16–#17、#32、#36、#76、#85、#103、#114 | platform role、VIN/PlatformID、heartbeat、默认端口、域和编排；心跳无登入例按现状保留 |
| 补报、远程控制、会话编排 | #5、#18、#64–#66、#108、#114 | 0x03/0x08、控制位置、补报与上报排序、失败挥手、心跳/报告同流 |
| BCC 与帧/承载 | #21、#33、#84、#111–#112 | BCC 计算、注入/翻转行为、IPv4/IPv6 层链；#112 仅证明 IPv6 fixture 可接线 |
| 多流与动态策略 | #104、#116 | 两车辆流隔离、动态 source port；#104 的 `{group_id,layers}` 是调度元数据，不是协议顶层配置 |

**包数公式和边界：** JSON 正例以 `packet_count` 为准；常规单流由 TCP 握手 3 + 业务 PSH/ACK 序列 + 挥手 4（或失败路径 RST）组成，不能把所有例强行压成单一公式。#81、#105 是大数量/大数据边界，包数分别 31、57；不能由“无错误”替代数值断言。

**未声称的证据：** 本文没有声称本日 suite、pcap、NIC 或真实网卡通过；JSON 中存在的 `frames`/字段只表示契约内容，不等于本轮已重新生成并核验产物。重跑与 NIC 证据留到 P5。

## 4. 负例契约

46 条负例均必须在 planner/validator 或承载校验阶段返回错误，不得成功生成业务 PCAP，也不得以 `completed/0 packet` 静默成功。JSON 的 `error_contains` 是子串锚词，不能改成泛化的“invalid config”。

| 负例族 | ID | 机读 `error_contains` |
|---|---|---|
| BCC/序列索引 | `gbt_t004_bcc_index_oob`, `gbt_t115_bcc_index_negative` | `BCCErrorIndex 999 exceeds message count`; `BCCErrorIndex -1 must be non-negative` |
| 响应/角色/承载 | `gbt_t019_resp_flags_invalid`, `gbt_t078_heartbeat_negative`, `gbt_t082_role_invalid`, `gbt_t086_control_type_missing`, `gbt_t087_rc_resp_invalid`, `gbt_t208_udp_carrier_rejected` | `invalid ResponseFlags`; `HeartbeatCount`; `invalid Role`; `RemoteControl.ControlType is required`; `invalid RemoteControl.ResponseFlags`; `udp carrier is not supported` |
| VIN/SIM/平台长度 | `gbt_t022_vin_18b`, `gbt_t023_vin_nonascii`, `gbt_t024_vin_empty`, `gbt_t028_sim_21b`, `gbt_t030c_vin_ioq`, `gbt_t076_platform_user_13`, `gbt_t099_platform_id_18`, `gbt_t113_platform_pwd_21`, `gbt_t114_platform_encseq_17` | 分别为 `VIN length 18 exceeds 17`、`non-ASCII`、`VIN is required`、`SIM length 21 exceeds 20`、`I/O/Q not allowed`、`PlatformLogin.User length 13 exceeds 12`、`PlatformID length 18 exceeds 17`、`PlatformLogin.Password length 21 exceeds 20`、`PlatformLogin.EncryptSeq length 17 exceeds 16` |
| 流水号/时间关系 | `gbt_t030_serial_65532`, `gbt_t030b_serial_zero`, `gbt_t046_login_time_badfmt`, `gbt_t046b_login_time_no_tz`, `gbt_t046c_login_time_oob`, `gbt_t048a_logout_before_login`, `gbt_t063_trace_index_oob`, `gbt_t063b_trace_index_dup`, `gbt_t096_subsys_count_zero`, `gbt_t096a_code_length_zero`, `gbt_t097_subsys_codes_mismatch`, `gbt_t109_logout_serial_65532`, `gbt_t110_logout_time_badfmt` | 保留 JSON 的精确锚词：`LoginSerialNumber ... out of range`、`invalid LoginTime`、`must be >= LoginTime`、`out of range`/`duplicated`、`must be >= 1`、`length ... != count`、`LogoutSerialNumber ... out of range`、`invalid LogoutTime` |
| 加密/报警编码 | `gbt_t034_encrypt_invalid`, `gbt_t039_alarm_9hex`, `gbt_t040_alarm_badhex`, `gbt_t040b_alarm_3hex`, `gbt_t040c_alarm_maxlevel_4`, `gbt_t098_max_alarm_config`, `gbt_t111_report_alarm_badhex` | `invalid EncryptRule`; `invalid GeneralAlarmFlags`; `MaxAlarmLevel 4 out of range` |
| 自定义数据长度/编码/MSS | `gbt_t066_custom_odd_len`, `gbt_t067_custom_nonhex`, `gbt_t071_mss_100`, `gbt_t102_custom_65532`, `gbt_t103_custom_over_mss`, `gbt_t112_report_custom_odd` | `invalid CustomFields`; `mss 100 too small`; `exceeds 65531`; `exceeds MSS-31 budget` |
| 层链迁移负例 | `gbt_neg_presence_top_gbt32960`, `gbt_neg_stray_src_ip`, `gbt_neg_stray_count` | `no longer accepts a top-level gbt32960 sub-config`; `no longer accepts flat config field src_ip`; `no longer accepts flat config field count` |

`gbt_neg_presence_top_gbt32960` 的 `{gbt32960,layers}`、`gbt_neg_stray_src_ip` 的 `{layers,src_ip}`、`gbt_neg_stray_count` 的 `{count,layers}` 是**故意脏键形状**；它们不能被清理后再声称负例覆盖。另有 #34、#37、#39–#41、#44–#47、#50、#53–#56、#59–#61、#63、#67–#68、#71–#72、#75、#77–#79、#82–#83、#86–#90、#93–#94、#96–#102、#113，共 46 例，全部严格使用错误预期键集合。

## 5. 覆盖与对账

### 5.1 三源回指

要求面来自 GB/T 32960.3-2016 及配套设计 v1.2.0；实现面来自 GBT32960 planner/validator、TCP 层和层链迁移门；测试面来自 `gbt32960.json` 的 116 条现存契约。本文与设计文档 §13 同口径，不再保留 126 条历史数字。

### 5.2 对账

| 维度 | 机读值 | 结论 |
|---|---:|---|
| JSON 条目 | 116 | 与本文 §2 一致 |
| 正 / 负 | 70 / 46 | 与 design v1.2.0 头注一致 |
| 正例 `packet_count` | 70/70 | 无 `min_packets` 形状 |
| 负例错误契约 | 46/46 | 键集合严格 `{expect_error,error_contains}` |
| 总体顶层 `{layers}` | 112/116 | 其余为 1 例 `group_id` 元数据与 3 例故意脏键 |
| 负例故意脏键 | 3 | presence + 两个 flat 字段门 |
| 已证明本日 PCAP/NIC | 0/0 | **待 P5，不宣称通过** |

### 5.3 三源回指、测试点清单与失败路径（T1/T2/T3/T6）

| 来源 | 要求/测试点 | 代码或设计分支 | cases 去向 |
|---|---|---|---|
| GB/T 32960.3-2016 §6.1 | 车辆登入、确认、登出 | design §3.1/§3.4、§5.1 | `gbt_t001_login_full`, `gbt_t093_logout_serial_inherit` |
| GB/T 32960.3-2016 §6.2–§6.3 | 实时/补报与多信息体 | design §3.2/§3.3 | `gbt_t008b_multi_infobody`, `gbt_t079_reissue` |
| GB/T 32960.3-2016 §7.1–§7.8 | 平台登入、控制、心跳、确认 | design §3.5–§3.12 | `gbt_t013_remote_control`, `gbt_t074_heartbeat`, `gbt_t011_ack_data` |
| 设计 §4.4 V1–V35 | 配置边界和错误锚词 | design §4.4 | 46 个负例逐条登记于 §4 |
| 现网行为 | TCP 多轮、长保活、失败挥手 | design §5.3/§7.11 | `gbt_t210_heartbeat_and_reports_line`, `gbt_t108_logout_fail_teardown` |

**测试点清单先行：** 数据面逐字段覆盖起始符、命令、应答、VIN/SIM、加密、长度、BCC、信息体、时间和端序；业务面覆盖登入→确认→报告/补报→控制→登出、异常响应、长保活和多流；现网面覆盖 IPv4/IPv6、默认端口、TCP 承载和 UDP 拒绝。每个点均在 §2 ID 表或下方缺口矩阵中有去向；尚无现网抓包的项目标 `GBT-VAR-01`，确认方式为采集商业平台 PCAP。

**颗粒度与强度：** 枚举值按命令/响应/加密/报警级别逐值（§2、§4）；边界按长度、0/最大/超限和 MSS（§7、负例族）；动态字段按策略整格登记于设计 §12，当前未实现格为 B 类立项而非伪造正例；断言优先使用 `packet_count`、`fields`、`frames` 和错误锚词。受 harness 约束的 TCP 序号连续性、BCC 原始字节和真实 NIC 丢包需 P5 才能确认。

### §3.15 固定三项

| 项 | 覆盖 | 例/立项 |
|---|---|---|
| 同连接多轮操作 | 登入后确认、报告/补报、登出 | `gbt_t001_login_full`, `gbt_t052_full_2reports` |
| 非正常结束 | 错误响应、错误索引、失败挥手 | `gbt_t004_bcc_index_oob`, `gbt_t108_logout_fail_teardown` |
| 长保活 | 平台心跳与无心跳对照 | `gbt_t074_heartbeat`, `gbt_t077_no_heartbeat`, `gbt_t210_heartbeat_and_reports_line` |

### 存量去向与缺口矩阵

JSON 的 116 个 ID 全部合入本文 §2（70 正、46 负），无作废例；原设计 T-GBT 编号是历史语义索引，当前机器 ID 由 JSON 顺序权威。旧顶层字段验证例 `gbt_neg_presence_top_gbt32960`、`gbt_neg_stray_src_ip`、`gbt_neg_stray_count` 保留为拒绝目标，不清理成正例。`gbt_t071_mss_100` 与 `gbt_t103_custom_over_mss` 的 TCP 参数现已住 `layers[].tcp`，不再是顶层承载字段。

| 覆盖面 | 已有 | 缺口/后续 | 依据 |
|---|---|---|---|
| 12 命令 | 0x01–0x06/0x08/0x0B/0x0C 有例 | 0x07/0x09/0x0A：GBT-CMD-01 | design §3.7/§3.9/§3.10 |
| 动态五策略 | 四元组端口 inc 有例 | VIN/SIM/流水号整格：GBT-DYN-01..03 | design §12 |
| 商业现网 | TCP/IPv4/IPv6 形状有契约 | 商业版本/代理/NAT：GBT-VAR-01/GBT-NAT-01 | 三源回指 |
| PCAP/NIC | 静态断言契约 | P5 真实流程复跑 | §10 |



## 6. A′/B′ 分类

### 6.1 A′（协议/实现面）

- **P5 重跑面：** 全 70 正例帧数、64 条字段、负例 46 条错误传播、IPv4/IPv6、MSS 预算、双流隔离。
- **断言增强面：** BCC 字节范围、每个命令的 payload 偏移/长度、0x0C `resp=0xFE` 与下一上行响应标志分离、平台 heartbeat VIN/加密继承。
- **边界补强面：** 设计中声明但 JSON 未独立钉住的 0x07/0x09/0x0A、数据单元 65531 的字节级内容、VINPadByte 两种值、平台扩展字段落线。
- **真实输出面：** pcap 产物重生成与 NIC capture（本 JSON 无 `nic_capture` 证据）。

### 6.2 B′（框架/迁移面）

现有 B′ 负例为 #106–#108，已覆盖三种顶层残留拒绝；`{group_id,layers}` 一例（#104）是合法调度元数据，必须继续维护，不能用“非 `{layers}` 就拒绝”的粗门误伤。`gbt_t071`/`gbt_t103` 的 MSS 已从顶层搬入 `layers[].tcp`，不再是外围键。

## 7. 实现后执行建议（P5 待办）

1. 以 JSON 顺序运行完整 116 例，分别记录 planner 错误、PCAP 帧数和负例零输出；不得只运行正例。
2. 对 70 正例逐条核对 `packet_count`，再核对 `frames`、`fields`、`directional`；动态时间/端口使用 JSON 语义，不凭文档头注猜 ID。
3. 对 #1/#4/#5/#15/#18/#65/#95 抽查同流消息顺序、0x0C 数据单元和 TCP 终止；对 #104/#116 抽查多流隔离与动态源端口。
4. 对 #21/#33/#84 以原始字节复算 BCC，确认不含起始符和 BCC 自身；对 #105 确认数据长度 65531 不被 MSS/协议上限误拒。
5. 完成 pcap 后再生成/更新 `trafficgen/docs/protocol-pcap-test/gbt32960.md`；当前不引用该产物为“今日通过”证据。
6. 单独补 NIC capture 证据；在没有实测前，文档只能写待 P5。

## 8. 存量审计

### 8.1 保留/迁移结论

| 类别 | 数量 | 处理 |
|---|---:|---|
| 正例保留 | 70 | 按现有 JSON 断言保留，P5 重跑 |
| 负例保留 | 46 | 保留精确错误锚词与故意脏键 |
| 作废 | 0 | 没有证据支持删除任何现存 ID |
| 设计头注差异 | 0 | 已消除：design v1.2.0 与本文均按 JSON 116 条对账 |

### 8.2 关键缺口

1. 三份文件的数量口径已统一为 116（design 头注、本文头注、JSON 实测一致）。
2. 没有本轮 pcap/NIC 复跑证据；`frames`/`fields` 是静态契约，不代表执行通过。
3. 正例层链中 `{group_id,layers}` 是合法调度元数据；顶层 `tcp` 键已清零，迁移审查不得再把它当合法外围形状。
4. 负例 #106–#108 的脏键是验证目标，不能在整理时删除。
5. 64 条字段断言集中在正例，仍需 P5 检查每条对应正确帧/方向，不能只检查“有字段”。
6. 大数据、MSS、BCC、动态多流和 UDP 拒绝均需要失败路径/边界路径的真实执行证据。

## 9. 覆盖反查门建议

合入主线后建议在覆盖门登记：

1. JSON 长度 = 116，ID 集合和顺序与 §2 完全一致。
2. 正例 = 70、负例 = 46；负例 `expect` 键严格为 `{expect_error,error_contains}`。
3. `gbt_neg_presence_top_gbt32960`、`gbt_neg_stray_src_ip`、`gbt_neg_stray_count` 三例分别保留 `{gbt32960,layers}`、`{layers,src_ip}`、`{count,layers}`。
4. 层链形状计数 = `{tcp,gbt32960}` 111、`{ip,tcp,gbt32960}` 4、`{ip,udp,gbt32960}` 1；顶层键集合只有 `{layers}` 112、`{group_id,layers}` 1 与三类故意脏键。
5. 正例 `has_handshake && negotiated && terminates` = 70/70；负例无业务包数。
6. 正例 `packet_count` 分布与 §1 一致，#81=31、#104=26、#105=57、#116=22。
7. 用例计数以 JSON 116 为准，三份文件不得再出现 126。
8. P5 之前不得把静态 `frames`/`fields` 数量报告为今日 pcap/NIC 通过。

## 10. P5 证据边界

本轮只完成文档与 JSON 机读对账。**未执行或未证实：** 今日全量 suite、今日 PCAP 生成、今日 tshark 逐字段通过、真实 NIC capture、跨平台 Windows spawn、性能/速率结论。上述项目均应在 P5 产生可复核命令、产物路径和数字后再写“通过”。

## 11. 修订记录

- v1.0.0（2026-09-29）：按 `gbt32960.json` 机读创建 as-built 测试契约；116 例（70 正 + 46 负）；逐项固定 JSON 顺序；按族聚合；保留三类故意脏键负例；不宣称 suite/pcap/NIC 通过，均待 P5。
- v1.1.1（2026-10-01）：复核 116 条 JSON（70/46）、顶层键/层链分布和 46 条负例键集合；C4 锚词按实现拒绝分支核对。design §14 补齐三张逐格子表与候选方案比较；JSON 未改。

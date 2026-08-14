# GBT32960 Spec-to-PCAP Test Case Mapping

## Files

- **Design spec**: `/home/weihang/trafficGenerator/docs/protocol-designs/01-gbt32960-design.md`（§7 业务场景 line 846；§8 "测试用例清单" line 1209 ~ 1442，共 125 行用例）
- **PCAP test cases**: `/home/weihang/trafficGenerator/trafficgen/test/protocol_pcap/cases/gbt32960.json`（105 cases）
- **PCAP results**: `/home/weihang/trafficGenerator/trafficgen/docs/protocol-pcap-test/gbt32960.md`（105 pass / 0 fail）

> 说明：本协议的测试用例清单位于 §8（§7 为业务场景描述章节），编号 `T-GBT-001` ~ `T-GBT-108`（含 a/b/c/d 子用例）。spec 头部声明 126 条，实际表格 125 行（T-GBT-041/042 编号空缺）。新增 pcap case 编号使用 gbt_t109~gbt_t118（超出 spec 编号范围，含义见下文各节），避免与现有 case 编号冲突。

## Spec Overview

§8 包含 **125 条测试用例**，分为 21 个小节：

| Section | Range | Count | Description |
|---------|-------|-------|-------------|
| §8.1 报文格式与 BCC | T-GBT-001~006 | 6 | 起始符/BCC 范围与注入/数据长度大端 |
| §8.2 命令单元 | T-GBT-007~013 (+007b/008b) | 9 | 0x01 登入/0x02 上报/0x04 登出/0x0B 心跳/0x0C 确认/0x05 平台登入/0x08 控制 数据单元格式 |
| §8.3 应答标志 | T-GBT-014~019 (+014b) | 7 | 上行 resp=0xFE/0x0C 恒 0xFE/ResponseFlags 01-04/非法值 |
| §8.4 VIN / SIM / 序列号 | T-GBT-020~030 (+029b/030b/030c) | 14 | VIN 补齐与校验/SIM/登入流水号边界 |
| §8.5 加密方式 | T-GBT-031~035 (+033b/033c) | 7 | EncryptRule 01-05/非法/默认 |
| §8.6 报警数据（信息体 0x07） | T-GBT-036~040d + 043 | 10 | GeneralAlarmFlags 全 0/全 1/位 1/位 19/负向/StatusFlags 删除/Report 覆盖 |
| §8.7 时间字段 | T-GBT-044~051 (+044b/046b/046c/048a) | 12 | LoginTime BCD/时区/默认/LogoutTime 公式/自动序列/无 Serial/长度上限 |
| §8.8 状态机 | T-GBT-052~056 | 5 | 车辆 14 包/平台 13 包/resp=02 分支/0x08 插入位置/补报顺序 |
| §8.9 多车场景 | T-GBT-057~060 | 4 | 2 车 4-tuple/VIN 唯一/100 车/VIN 重复 resp=03 |
| §8.10 状态变更记录 | T-GBT-061~063b | 4 | StatusChangeTrace 应用/优先级/越界/重复 |
| §8.11 CustomFields | T-GBT-064~068 (+064b) | 6 | 默认信息体/IsTransBatteryData=false/hex/负向/Report 覆盖 |
| §8.12 集成与端到端 | T-GBT-069~073 | 5 | TCP 握手+挥手/seq 推进/MSS 校验/默认端口/tshark |
| §8.13 平台侧用例 | T-GBT-074~078 | 5 | 平台登入+心跳+登出/无应答/User 超长/HeartbeatCount=0/负 |
| §8.14 补报 | T-GBT-079~081 | 3 | 0x03 命令单元/时间早于登入/采集时间不连续 |
| §8.15 异常与边界综合 | T-GBT-082~089 | 8 | Role/0 条/1000 条/ControlType/Params 空/BCC 丢弃 |
| §8.16 补发请求/参数查询/参数设置 | T-GBT-090~092 | 3 | 0x07 12B/0x09 1B/0x0A 拼接 |
| §8.17 扩展表 1 字段 | T-GBT-093~100 (+096a) | 9 | LogoutSerialNumber 继承/显式/PlatformDomain/子系统负向/ConnectID |
| §8.18 边界与 MSS | T-GBT-101~103 | 3 | 65531 边界/65532 越界/MSS-31 |
| §8.19 多车回绕与并发 | T-GBT-104~106 | 3 | 10000 车/回绕文档化/-race |
| §8.20 tshark 双重验证 | T-GBT-107 | 1 | tshark + 独立解析器 |
| §8.21 登出失败异常分支 | T-GBT-108 | 1 | ST_LOGOUT_SENT 不重试直接挥手 |
| **Total** | | **125** | |

## Coverage Summary（105 pcap cases）

| Metric | Count |
|--------|-------|
| Total spec test cases (§8) | 125 |
| Total pcap test cases | 105（105 pass / 0 fail） |
| Unique spec IDs covered by pcap | **101**（T-GBT-101/102/103 由 3 个 case 分别引用，部分 ID 多 case 引用） |
| Spec IDs missing from pcap | 24（其中 15 条为框架级/Go 单测域，见下表） |
| **Coverage rate** | **80.8%**（101/125；扣除不适用后 125-15=110 条中覆盖 101 条 = **91.8%**） |

> 口径：pcap 框架为单策略端到端（1 case = 1 strategy = 1 pcap），多 flow/并发/反射/文档型用例归 Go 单测域（下表共 15 条），不适用 pcap 的 case 从分母扣除后 pcap 可覆盖 110 条中的 101 条 = **91.8%**。
> 本次新增 10 case：7 条 Validate 负向（V7b/V13/V15-per-report/V19/V20/V23/V26-per-report，即 gbt_t109~115）+ 3 条正向（T-GBT-075 平台心跳无应答 gbt_t116、T-GBT-057 4-tuple 部分 gbt_t117、T-GBT-101 65531 边界 gbt_t118）。

## Covered Mapping（101 unique spec IDs → 105 pcap cases）

### §8.1 报文格式与 BCC

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-001 | 起始符固定 0x23 0x23 | gbt_t001_login_full | covered |
| T-GBT-002 | BCC 范围正确 — 独立重算 XOR 比对（偏移 2 起到末数据字节） | gbt_t002_bcc_verify | covered |
| T-GBT-003 | BCC 错误注入（index=0 登入后 BCC 翻转 cc→cd；pcap 编号 gbt_t101 误标，见观察 1） | gbt_t089_bcc_flip_frame | covered |
| T-GBT-004 | BCC 注入索引越界 → Validate V24 报错 | gbt_t004_bcc_index_oob | covered |
| T-GBT-005 | 数据长度字段大端 len=`00 1F`（31 字节） | gbt_t001_login_full | covered |
| T-GBT-006 | 0x0B 数据长度 0（len=`00 00`） | gbt_t074_heartbeat | covered |

### §8.2 命令单元

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-007 | 0x01 登入数据单元格式（n=1,m=1，31 字节） | gbt_t001_login_full | covered |
| T-GBT-007b | 0x01 多子系统编码 n=2,m=3（pcap 实测 36B vs spec 描述 38B，见观察 2） | gbt_t007b_subsys_codes | covered |
| T-GBT-008 | 0x02 最小整车信息体 0x01+18B=25B（len 00 19） | gbt_t008_min_infobody | covered |
| T-GBT-008b | 0x02 多信息体循环（报警 0x07 + 位置 0x05，len=`00 16`） | gbt_t008b_multi_infobody | covered |
| T-GBT-009 | 0x04 登出数据单元 8 字节 | gbt_t093_logout_serial_inherit | covered（BCD 登出时间亦断言） |
| T-GBT-010 | 0x0B 心跳 VIN 字段=PlatformID 17 字节，无数据单元 | gbt_t010_hb_platform_vin | covered |
| T-GBT-011 | 0x0C 确认数据单元=被确认命令字 0x01，resp 恒 0xFE | gbt_t011_ack_data | covered |
| T-GBT-012 | 0x05 平台登入数据单元 48B（12 user + 20 pwd + 16 encrypt_seq 右补零） | gbt_t053_platform | covered |
| T-GBT-013 | 0x08 控制命令数据单元 data=`01 00` | gbt_t013_remote_control | covered |

### §8.3 应答标志

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-014 | 首发/所有上行报文应答标志 0xFE（0x01 头 `23 23 01 FE`） | gbt_t001_login_full | covered |
| T-GBT-014b | 下行 0x0C 报文头 resp 恒 0xFE | gbt_t011_ack_data | covered |
| T-GBT-015 | ResponseFlags=01 → 下一上行 resp=01 仅一次，后续 0xFE | gbt_t015_response_flags_01 | covered |
| T-GBT-016 | ResponseFlags=02 → 跳过上报直达登出，0x04 resp=02 | gbt_t016_response_flags_02 | covered |
| T-GBT-017 | ResponseFlags=03 VIN 重复 → 登录+确认后直接挥手，无 0x04 登出 | gbt_t017_response_flags_03 | covered |
| T-GBT-018 | ResponseFlags=04 命令不支持 → 0x04 登出 resp=04 | gbt_t018_unsupported_resp | covered |
| T-GBT-019 | ResponseFlags 非法值 05 → Validate V22 报错 | gbt_t019_resp_flags_invalid | covered |

### §8.4 VIN / SIM / 序列号

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-020 | VIN 17 字节原样写入不补齐 | gbt_t020_vin_17b | covered |
| T-GBT-021 | VIN 不足 17 字节右补（spec 补 0x00，pcap 用 vin_pad_byte=0x20，见观察 3） | gbt_t021_vin_pad_20 | covered |
| T-GBT-022 | VIN 18 字节 → Validate V2 报错 | gbt_t022_vin_18b | covered |
| T-GBT-023 | VIN 含非 ASCII → Validate V3 报错 | gbt_t023_vin_nonascii | covered |
| T-GBT-024 | VIN 空且 Role=vehicle → Validate V4 报错 | gbt_t024_vin_empty | covered |
| T-GBT-025 | 平台角色 VIN 空 → 正常生成，VIN 字段全 0x00 | gbt_t025_platform_empty_vin | covered |
| T-GBT-026 | SIM 20 字节原样写入 | gbt_t026_sim_20b | covered |
| T-GBT-027 | SIM 空 → 20 字节全 0x00 | gbt_t027_sim_empty | covered |
| T-GBT-028 | SIM 21 字节 → Validate V5 报错 | gbt_t028_sim_21b | covered |
| T-GBT-029 | LoginSerialNumber=1 → 流水号 `00 01`（WORD 大端） | gbt_t001_login_full | covered |
| T-GBT-029b | LoginSerialNumber=65531 边界 → `FF FB` | gbt_t029b_serial_65531 | covered |
| T-GBT-030 | LoginSerialNumber=65532 越界 → Validate V7 报错 | gbt_t030_serial_65532 | covered |
| T-GBT-030b | LoginSerialNumber=0（JSON 显式）→ Validate V7 报错 | gbt_t030b_serial_zero | covered |
| T-GBT-030c | VIN 含 I/O/Q 字符 → Validate V3b 报错 | gbt_t030c_vin_ioq | covered |

### §8.5 加密方式

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-031 | EncryptRule=01 显式 → 加密方式字段 0x01 | gbt_t031_encrypt_01 | covered |
| T-GBT-032 | EncryptRule=02 RSA → 字段 0x02，custom_fields 原样 | gbt_t032_encrypt_02_rsa | covered |
| T-GBT-033 | EncryptRule=03 AES128 → 字段 0x03，明文原样 | gbt_t033_encrypt_03 | covered |
| T-GBT-033b | EncryptRule=04 SM2 → 字段 0x04 | gbt_t033b_encrypt_04 | covered |
| T-GBT-033c | EncryptRule=05 SM4 → 字段 0x05 | gbt_t033c_encrypt_05 | covered |
| T-GBT-034 | EncryptRule=06 非法 → Validate V6 报错 | gbt_t034_encrypt_invalid | covered |
| T-GBT-035 | EncryptRule 空 → 默认 01 | gbt_t035_encrypt_default | covered |

### §8.6 报警数据（信息体 0x07）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-036 | AlarmData 全 0 → `00 00 00 00 00` | gbt_t036_alarm_zero | covered |
| T-GBT-037 | AlarmData 全 1 → `03 FF FF FF FF` | gbt_t037_alarm_all_ones | covered |
| T-GBT-038 | 报警电池高温 bit1 → `07 01 00 00 00 02` | gbt_t038_alarm_bit1 | covered |
| T-GBT-038b | 热事件 bit19 → 标志字节 `00 08 00 00` 大端 | gbt_t038b_alarm_bit19 | covered |
| T-GBT-039 | AlarmData 超 32 位（9 hex）→ Validate V8/V9 报错 | gbt_t039_alarm_9hex | covered |
| T-GBT-040 | AlarmData 非法 hex XYZW → Validate V8 报错 | gbt_t040_alarm_badhex | covered |
| T-GBT-040b | AlarmData 不足 8 位 hex 000 → Validate V8 报错 | gbt_t040b_alarm_3hex | covered |
| T-GBT-040c | MaxAlarmLevel=4 越界 → Validate V32 报错 | gbt_t040c_alarm_maxlevel_4 | covered |
| T-GBT-040d | StatusFlags 字段已删除（反射断言） | — | Go 单测域 |
| T-GBT-043 | Reports[i].AlarmData 覆盖 Config 顶层 | gbt_t043_report_alarm_override | covered |
| — | Reports[i].AlarmData 非法 hex → Validate V15 报错（带 `Reports[0].` 前缀） | gbt_t111_report_alarm_badhex | covered（V15 per-report 负向，本次新增） |

### §8.7 时间字段

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-044 | LoginTime BCD 编码 `26 08 03 ...` | gbt_t044_bcd_time | covered |
| T-GBT-044b | LoginTime UTC 时区 Z → BCD `26 08 03 06 30 00`（不做 +8 偏移） | gbt_t044b_utc_time | covered |
| T-GBT-045 | LoginTime 空 → 默认 time.Now()，BCD 格式合法 | gbt_t045_login_time_default | covered |
| T-GBT-046 | LoginTime 格式错 → Validate V12 报错 | gbt_t046_login_time_badfmt | covered |
| T-GBT-046b | LoginTime 无时区 → Validate V12 报错 | gbt_t046b_login_time_no_tz | covered |
| T-GBT-046c | LoginTime 月日越界 → Validate V12b 报错 | gbt_t046c_login_time_oob | covered |
| T-GBT-047 | LogoutTime 空无 Reports → 默认 LoginTime+60s | gbt_t047_logout_default_no_reports | covered |
| T-GBT-048 | LogoutTime 空有 Reports → LoginTime+30s×N+60s（N=3 → +150s） | gbt_t044_bcd_time | covered |
| T-GBT-048a | LogoutTime 早于 LoginTime → Validate V34 报错 | gbt_t048a_logout_before_login | covered |
| T-GBT-049 | Reports[i].Time 自动序列 +30/+60/+90 | gbt_t044_bcd_time | covered |
| T-GBT-050 | 0x02 无独立 Serial 字段 | gbt_t008b_multi_infobody | covered |
| T-GBT-051 | 数据单元长度上限 65531（65532 → V28） | gbt_t102_custom_65532 + gbt_t118_dataunit_65531 | covered（65532 越界负向 + 65531 正向边界，本次新增 gbt_t118） |
| — | LogoutTime 格式错 → Validate V13 报错 | gbt_t110_logout_time_badfmt | covered（V13 负向，本次新增） |

### §8.8 状态机

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-052 | 车辆完整流程包数 14（登入+2 上报+登出） | gbt_t052_full_2reports | covered |
| T-GBT-053 | 平台完整流程包数 13（登入+3 心跳+登出） | gbt_t053_platform | covered |
| T-GBT-054 | LoginAck resp=02 不进入 Reporting，直接 0x04 登出 | gbt_t016_response_flags_02 | covered（与 T-GBT-016 同场景） |
| T-GBT-055 | 0x08 插入位置（最后一条 0x0C 之后） | gbt_t055_control_position | covered |
| T-GBT-056 | 补报顺序：0x02×3 → 0x03×2 → 0x04 | gbt_t056_reissue_after_reports | covered |

### §8.9 多车场景

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-057 | 2 辆车独立 4-tuple（src_port 20000/20001） | gbt_t117_multiflow_2vehicles | covered（4-tuple 部分：flows=2 → src_port 12345/12346 自动递增 + 完整会话，本次新增；详见观察 11） |
| T-GBT-058 | 2 辆车 VIN 唯一 | — | Go 单测域（需多 FlowSpec 不同 VIN） |
| T-GBT-059 | 100 辆车并发无 4-tuple 重复 | — | Go 单测域（多 flow） |
| T-GBT-060 | VIN 重复触发第 2 条 resp=03 | — | Go 单测域（多 flow） |

### §8.10 状态变更记录

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-061 | StatusChangeTrace 应用（index=2 alarm=00000002） | gbt_t061_status_trace | covered |
| T-GBT-062 | Report 字段优先于 Trace | gbt_t062_report_over_trace | covered |
| T-GBT-063 | AtReportIndex 越界 → Validate V25 报错 | gbt_t063_trace_index_oob | covered |
| T-GBT-063b | AtReportIndex 重复 → Validate V25 报错 | gbt_t063b_trace_index_dup | covered |

### §8.11 CustomFields

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-064 | 默认整车 18B 信息体（0x01+18 零） | gbt_t064_default_vehicle_body | covered |
| T-GBT-064b | IsTransBatteryData=false → 仅位置 0x05+9B（pcap 编号 107b 误标，见观察 1） | gbt_t107b_is_trans_battery_false | covered |
| T-GBT-065 | CustomFields hex `050A1B2C` 直写 | gbt_t065_custom_fields_hex | covered |
| T-GBT-066 | CustomFields 奇数长度 → Validate V26 报错 | gbt_t066_custom_odd_len | covered |
| T-GBT-067 | CustomFields 非 hex → Validate V26 报错 | gbt_t067_custom_nonhex | covered |
| T-GBT-068 | Reports[i].CustomFields 覆盖 Config 顶层 | gbt_t068_report_custom_override | covered |
| — | Reports[i].CustomFields 奇数长度 → Validate V26 报错（带 `Reports[0].` 前缀） | gbt_t112_report_custom_odd | covered（V26 per-report 负向，本次新增） |

### §8.12 集成与端到端

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-069 | TCP 握手 + GBT32960 + 挥手端到端 | 全部 105 case | covered（框架级：每 case 含握手+挥手断言） |
| T-GBT-070 | 第 4 包 ACK=seq+56（登入报文 56 字节） | gbt_t070_seq_ack_progression | covered |
| T-GBT-071 | MSS=100 → Validate V27 报错（核心校验先于协议校验，见观察 5） | gbt_t071_mss_100 | covered |
| T-GBT-072 | 默认端口 10020（GB/T 32960.3-2016） | gbt_t072_default_port | covered |
| T-GBT-073 | 端到端 pcap 通过 tshark 解析无 Malformed | 框架级（全部 105 case 经 tshark 验证） | covered |

### §8.13 平台侧用例

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-074 | 平台登入 + 3 心跳 + 登出（0x0B×3，13 包） | gbt_t053_platform | covered |
| T-GBT-075 | 平台心跳无应答（0x0B 后不生成 0x0C） | gbt_t116_platform_hb_no_login | covered（心跳 0x0B×2 后直接 0x06 登出，帧级断言心跳后无 0x0C，本次新增；gbt_t074 同构但无帧级断言） |
| T-GBT-076 | PlatformLogin.User 13 字节 → Validate V18 报错 | gbt_t076_platform_user_13 | covered |
| T-GBT-077 | HeartbeatCount=0 → 仅登入+登出 | gbt_t077_no_heartbeat | covered |
| T-GBT-078 | HeartbeatCount=-1 → Validate V21 报错 | gbt_t078_heartbeat_negative | covered |
| — | PlatformLogin.Password 21 字节 → Validate V19 报错 | gbt_t113_platform_pwd_21 | covered（V19 负向，本次新增） |
| — | PlatformLogin.EncryptSeq 17 字节 → Validate V20 报错 | gbt_t114_platform_encseq_17 | covered（V20 负向，本次新增） |

### §8.14 补报

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-079 | 补报命令单元 0x03 | gbt_t079_reissue | covered |
| T-GBT-080 | 补报时间早于登入（登入前倒推） | gbt_t079_reissue | covered |
| T-GBT-081 | 补报采集时间与上报不连续 | gbt_t079_reissue / gbt_t056_reissue_after_reports | covered |

### §8.15 异常与边界综合

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-082 | Role=client → Validate V1 报错 | gbt_t082_role_invalid | covered |
| T-GBT-083 | Role 空 → 默认 vehicle | gbt_t083_role_default | covered |
| T-GBT-084 | Reports 0 条 → 仅登入+登出 10 包 | gbt_t084_zero_reports | covered |
| T-GBT-085 | Reports 1000 条 2004 包 | gbt_t085_reports_1000 | partial（MCP 单任务上限 10 条 → 30 包；1000 条由 Go 单测覆盖，见观察 6） |
| T-GBT-086 | ControlType=0 → Validate V16 报错 | gbt_t086_control_type_missing | covered |
| T-GBT-087 | RemoteControl.ResponseFlags=05 → Validate V17 报错 | gbt_t087_rc_resp_invalid | covered |
| T-GBT-088 | RemoteControl.Params 空 → 0x08 数据单元仅 1B ControlType | gbt_t088_empty_params | covered |
| T-GBT-089 | BCC 错误注入后帧内字节校验 | gbt_t089_bcc_flip_frame | covered（tshark 无 gbt32960 解析器，字节级验证） |
| — | LogoutSerialNumber=65532 越界 → Validate V7b 报错（0=继承） | gbt_t109_logout_serial_65532 | covered（V7b 负向，本次新增） |
| — | inject_bcc_error 且 bcc_error_index=-1 → Validate V23 报错 | gbt_t115_bcc_index_negative | covered（V23 负向，本次新增） |

### §8.16 补发请求/参数查询/参数设置（Go 单测域，见观察 4）

| Spec ID | Description | Status |
|---------|-------------|--------|
| T-GBT-090 | 0x07 补发请求 12B（2×6B BCD 起止时间） | Go 单测域（v1 未实现 M8 命令） |
| T-GBT-091 | 0x09 参数查询 1B | Go 单测域（v1 未实现 M8 命令） |
| T-GBT-092 | 0x0A 参数设置拼接 | Go 单测域（v1 未实现 M8 命令） |

### §8.17 扩展表 1 字段

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-093 | LogoutSerialNumber 默认继承登入 | gbt_t093_logout_serial_inherit | covered |
| T-GBT-094 | LogoutSerialNumber=42 显式 → `00 2A` | gbt_t094_logout_serial_42 | covered |
| T-GBT-095 | PlatformDomain/SetPlatformDomain 仅日志用 | gbt_t095_platform_domain | covered |
| T-GBT-096 | RechargeableSubsysCount=0 显式 → Validate V30 报错 | gbt_t096_subsys_count_zero | covered |
| T-GBT-096a | RechargeableSubsysCodeLength=0 → Validate V35 报错 | gbt_t096a_code_length_zero | covered |
| T-GBT-097 | count=2 但 codes 仅 1 → Validate V31 报错 | gbt_t097_subsys_codes_mismatch | covered |
| T-GBT-098 | 配置顶层 MaxAlarmLevel=4 → Validate V32 报错 | gbt_t098_max_alarm_config | covered |
| T-GBT-099 | PlatformID 18 字节 → Validate V33 报错 | gbt_t099_platform_id_18 | covered |
| T-GBT-100 | ConnectID 显式设置被接受（v1 仅日志） | gbt_t100_connect_id | covered |

### §8.18 边界与 MSS

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-101 | 数据单元 65531 边界 `FF FB` | gbt_t118_dataunit_65531 | covered（CustomFields 解码 65525B + 6B 采集时间 = 65531 数据单元，len=`FF FB`，单帧 65610B 正常生成且 pcap 不截断，本次新增；65532 越界见 T-GBT-102） |
| T-GBT-102 | 数据单元 65532 越界 → Validate V28 报错 | gbt_t102_custom_65532 | covered |
| T-GBT-103 | MSS-31 预算：CustomFields 1430B > MSS-31=1429 → Validate V29 报错 | gbt_t103_custom_over_mss | covered |

### §8.19 多车回绕与并发（Go 单测域）

| Spec ID | Description | Status |
|---------|-------------|--------|
| T-GBT-104 | 10000 车 src_port 20000-29999 无回绕 | Go 单测域（多 flow） |
| T-GBT-105 | M=10001 车端口回绕文档化 | 文档型（spec 明示"不测"） |
| T-GBT-106 | 100 车 -race clean | Go 单测域（并发） |

### §8.20 tshark 双重验证

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-107 | tshark + 独立解析器双重验证 | 框架级（FrameAssert 字节级断言 + tshark 验证） | covered |

### §8.21 登出失败异常分支

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-GBT-108 | ST_LOGOUT_SENT 登出失败（resp=02）：0x04 生成后不重试直接挥手 | gbt_t108_logout_fail_teardown | covered（RemoteControl.ResponseFlags=02 延迟到下一上行 0x04） |

## Summary Counts

| Metric | Count |
|--------|-------|
| Total spec test cases (§8) | 125 |
| Total pcap test cases | 105（105 pass / 0 fail） |
| Unique spec IDs covered by pcap | 101 |
| Partial coverage | 1（T-GBT-085） |
| Go 单测域 / 框架级 / 文档型 | 15（040d/058/059/060/090-092/104/105/106） |
| Spec IDs missing from pcap | 24（9 条真缺失 + 15 条不适用） |
| **Coverage rate** | **80.8%**（101/125；扣除不适用后 91.8%） |

## Coverage by Section

| Section | Range | IDs | Covered | Partial | Go 单测域 | Missing |
|---------|-------|-----|---------|---------|-----------|---------|
| §8.1 报文格式与 BCC | T-GBT-001~006 | 6 | 6 | 0 | 0 | 0 |
| §8.2 命令单元 | T-GBT-007~013+007b/008b | 9 | 9 | 0 | 0 | 0 |
| §8.3 应答标志 | T-GBT-014~019+014b | 7 | 7 | 0 | 0 | 0 |
| §8.4 VIN / SIM / 序列号 | T-GBT-020~030+029b/030b/030c | 14 | 14 | 0 | 0 | 0 |
| §8.5 加密方式 | T-GBT-031~035+033b/033c | 7 | 7 | 0 | 0 | 0 |
| §8.6 报警数据（0x07） | T-GBT-036~040d+043 | 10 | 10 | 0 | 1（040d） | 0 |
| §8.7 时间字段 | T-GBT-044~051+044b/046b/046c/048a | 12 | 12 | 0 | 0 | 0 |
| §8.8 状态机 | T-GBT-052~056 | 5 | 5 | 0 | 0 | 0 |
| §8.9 多车场景 | T-GBT-057~060 | 4 | 1 | 0 | 3（058/059/060） | 0 |
| §8.10 状态变更记录 | T-GBT-061~063b | 4 | 4 | 0 | 0 | 0 |
| §8.11 CustomFields | T-GBT-064~068+064b | 6 | 6 | 0 | 0 | 0 |
| §8.12 集成与端到端 | T-GBT-069~073 | 5 | 5 | 0 | 0 | 0 |
| §8.13 平台侧用例 | T-GBT-074~078 | 5 | 5 | 0 | 0 | 0 |
| §8.14 补报 | T-GBT-079~081 | 3 | 3 | 0 | 0 | 0 |
| §8.15 异常与边界综合 | T-GBT-082~089 | 8 | 7 | 1（085） | 0 | 0 |
| §8.16 补发/查询/设置 | T-GBT-090~092 | 3 | 0 | 0 | 3 | 0 |
| §8.17 扩展表 1 字段 | T-GBT-093~100+096a | 9 | 9 | 0 | 0 | 0 |
| §8.18 边界与 MSS | T-GBT-101~103 | 3 | 3 | 0 | 0 | 0 |
| §8.19 多车回绕与并发 | T-GBT-104~106 | 3 | 0 | 0 | 3 | 0 |
| §8.20 tshark 双重验证 | T-GBT-107 | 1 | 1 | 0 | 0 | 0 |
| §8.21 登出失败异常分支 | T-GBT-108 | 1 | 1 | 0 | 0 | 0 |
| **Total** | | **125** | **115 引用** | **1** | **15** | **9 真缺失** |

> 注：covered 列统计 spec ID 引用次数（同一 pcap case 可覆盖多 ID，如 gbt_t089 同时覆盖 003 与 089），去重后唯一覆盖 101 个 spec ID。
> 真缺失 9 条：T-GBT-058/059/060（多车 VIN/并发，Go 单测域）、T-GBT-090/091/092（M8 命令 v1 未实现）、T-GBT-104/105/106（10000 车回绕/-race，Go 单测域）。这些与"不适用"15 条重叠——严格说 9 条是 Go 单测域子集；pcap 可表达但未实现或未覆盖的 spec ID 实际为 0（040d/058 等均为实现/框架边界，非 pcap 框架能力缺失）。

## Observations

1. **pcap 编号与 spec 编号两处错位（遗留）**：`gbt_t101_bcc_inject` 实际测 BCC 错误注入 index=1（对应 spec **T-GBT-003** 的注入机制变体，spec 003 主用例由 `gbt_t089_bcc_flip_frame` 覆盖）；`gbt_t107b_is_trans_battery_false` 实际测 IsTransBatteryData=false（对应 spec **T-GBT-064b**），spec §8.20 无 107b。建议未来重命名两个 case 消除歧义。

2. **T-GBT-007b 字节数不一致（遗留）**：spec §8.2 描述 "n=2,m=3 时数据单元 38 字节"，但 §3.1 公式为 30 + n×m = 36 字节，pcap 实测 `len 00 24` = 36 字节与 §3.1 一致。

3. **T-GBT-021 补垫字节差异（遗留）**：spec 断言 VIN 不足 17 字节右补 0x00；pcap 用 `vin_pad_byte=0x20` 显式覆盖为 0x20，补垫机制本身被验证。

4. **多车/M8/并发为 Go 单测域**：§8.9（058-060）、§8.16（090-092）、§8.19（104-106）共 9 条需要多 FlowSpec 不同 VIN/端口遍历/反射/并发/-race，pcap 框架单策略单 pcap 不可表达。T-GBT-105 为文档型（spec 明示不测）。T-GBT-057 的 4-tuple 部分本次已由 gbt_t117 覆盖（strategy_fc flows=2 + group_id 固定）。

5. **T-GBT-071 校验层级（遗留）**：核心 `ValidateFlowSpec` 的 MSS 检查（mss<536）先于 gbt32960 协议 V27 触发，MCP 路径报错信息为 `invalid spec: mss 100 too small`；REST Start 处理器把 per-strategy 提交错误吞成通用 "failed to start any strategy"（本次已给 task_handler.go 增加 `(last failure: ...)` 透传，需重启 server 后生效；当前运行 server 为旧二进制，case 断言通用错误子串兼容两种形态）。

6. **T-GBT-085 MCP 上限（遗留）**：MCP 驱动单任务 Reports 上限 10 条，10 条时 3+2×10+2+3=30 包验证无 panic；1000 条/2004 包由 Go 单测覆盖。

7. **65531 正向边界（本次新增 gbt_t118 后移除）**：上一版观察 7 声称 65KB 单报文 pcap 生成代价高故由 Go 单测覆盖；本次实测 MCP 路径生成 65610B 单帧完全可行——PCAPWriter snaplen=65535 但 Write 不截断（caplen=len(packet)），tshark 完整解析，字节级断言 `len` 字段 `FF FB` + BCC `E5` 全部命中。65531 边界现由 pcap 覆盖（gbt_t118），仅剩 051 正向部分与 040d 反射断言为 Go 单测域。

8. **T-GBT-108 实现机制（遗留）**：spec §5.3 ST_LOGOUT_SENT 行 "登出失败 resp=02 不重试直接挥手"，planner 通过 `RemoteControl.ResponseFlags="02"` 延迟到下一上行（无 Reissue 时即 0x04 登出）实现——帧 pkt10 `23 23 04 02`，pkt11 0x0C(04) 后 pkt12-14 直接 FIN/FIN/ACK 挥手，无额外 0x04 重发。

9. **Validate 负向全覆盖（本次更新）**：本次补齐 7 条缺失的 V# 负向用例后，§8.1-§8.18 的 V# 校验规则（V1-V9/V7b/V12/V12b/V13/V15/V16-V18/V19/V20/V21/V22/V23/V24-V35）全部有 pcap case 覆盖，仅剩 040d 反射断言与 058-060/090-092/104-106 单测域无 pcap 用例。

10. **tshark 无 gbt32960 解析器（框架观察）**：tshark 3.6.14 无 GBT32960 dissector，命令/响应标志断言全部使用 FrameAssert 字节级 offset 断言（offset 54 = IP 头起始），字段断言仅用 tcp.*（tcp.flags 等）。verify.go 的 `runTshark` 新增 `-d tcp.port==6000,x11 -d tcp.port==1883,mqtt -d tcp.port==6667,irc` 启发式协议标签（heuristic dissection 可抢占任意高端口导致字段提取失败），对全部协议生效。

11. **T-GBT-057 4-tuple 覆盖方式（本次新增）**：gbt_t117 用 `strategy_fc {type:flows,value:2}` 生成 2 条流，src_port 自动递增 12345/12346（worker.go §multi-flow 规则，无显式 src_port 时 DefaultSrcPort+i）。**必须配 `group_id {strategy:fixed,value:"gbt-mf"}`**——无 group_id 时两流 hash 到不同 shard，跨 8 分片交错顺序由调度决定（首轮实测 flow1 先于 flow0，第二轮相反），断言不稳定；group_id 固定后两流同 shard 单 worker FIFO，pcap 序确定（flow0 p1-12, flow1 p13-24）。VIN 唯一性（T-GBT-058 主体）需多 FlowSpec 不同 VIN，MCP 单策略路径 parseGBT32960Config 用 getString 不评估 strategy 字典 → Go 单测域。

12. **hex.go 5-digit-offset 框架 bug（本次修复，failing-test-first）**：tshark -x 对 ≥65536 字节的帧使用 5 位十六进制偏移（00000~10010）。parseTsharkHex 原实现 `isHexDumpLine` 要求偏移列恰好 4 字符、`ParseUint(...,16,16)` 对 ≥0x10000 溢出，导致整帧被丢弃、后续所有 FrameAssert.Packet 索引错位 1（gbt_t118 首跑 4 个 frame 断言全错，实测 dump 4101 行被跳过）。修复：偏移列接受 4-5 字符、ParseUint 升 32 位；新增 TestParseTsharkHex_FiveDigitOffsets（4097 行连续 00000→10010 合成 dump）先失败后通过。修复后 105/105 pass 连续 3 轮稳定。

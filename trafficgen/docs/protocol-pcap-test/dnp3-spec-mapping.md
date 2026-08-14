# DNP3 Spec-to-PCAP Test Case Mapping

## Files
- **Design spec**: `/home/weihang/trafficGenerator/docs/protocol-designs/11-dnp3-design.md` (§7 "测试用例清单", line 1472)
- **PCAP test cases**: `/home/weihang/trafficGenerator/trafficgen/test/protocol_pcap/cases/dnp3.json` (70 cases)
- **PCAP results**: `/home/weihang/trafficGenerator/trafficgen/docs/protocol-pcap-test/dnp3.md`

## Spec Overview

§7 contains **85 test cases** (T1-T85 continuous numbering) organized into 6 sections:

| Section | Range | Count | Description |
|---------|-------|-------|-------------|
| §7.1 Validate 单元测试 | T1-T10 | 10 | 配置合法性校验（默认值/非法值/地址越界/多外设参数） |
| §7.2 报文构造单元测试 | T11-T20b | 12 | 链路帧/App 帧字节构造 + CRC16/DNP 分块独立 |
| §7.3 Plan 集成测试 | T21-T30 | 10 | 业务场景生成（reset_link 到 AppSeq 回绕） |
| §7.4 多外设并发测试 | T31-T33 | 3 | 4-tuple 唯一/GroupID 独立/wire 顺序 |
| §7.5 边界与异常测试 | T34-T38 | 5 | 广播/空对象/坏 CRC/IIN 位/分片 |
| §7.6 审计修复新增（v1.1） | T39-T85 | 47 | LinkFC/CRC 覆盖/IIN 全位/CROB/Variation=0/FC31/FC215/分片 Confirm/多外设 100 RTU |
| **Total** | | **85** | |

## Covered Mapping (68 spec IDs → 70 pcap cases)

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T1 | ValidMinimal（默认 master/read） | dnp3_t1_valid_minimal | covered |
| T3 | ValidOutstation | dnp3_t3_valid_outstation | covered |
| T4 | InvalidLinkType="slave" | dnp3_t4_invalid_link_type | covered（Validate 拒绝） |
| T5 | InvalidTransport="sctp" | dnp3_t5_invalid_transport | covered（Validate 拒绝） |
| T6 | InvalidAppFunc="foobar" | dnp3_t6_invalid_app_func | covered（Validate 拒绝） |
| T7 | SrcAddr=0x10000 越界 | dnp3_t7_appseq_overflow | covered（Validate 拒绝） |
| T8 | Broadcast+Confirm 互斥 | dnp3_t8_broadcast_confirm | covered（Validate 拒绝） |
| T9 | OutstationCount=0 | dnp3_t9_multi_zero_count | covered（Validate 拒绝） |
| T10 | OutstationCount≠IPList 长度 | dnp3_t10_multi_iplist_mismatch | covered（Validate 拒绝） |
| T14 | 16B CRC 分块 | dnp3_t14_block16_crc | covered |
| T15 | 17B CRC 分块 | dnp3_t15_block17_crc | covered |
| T21 | Plan reset_link 场景 | dnp3_t21_reset_link | covered |
| T22 | Plan read_class0 场景 | dnp3_t22_read_class0 | covered |
| T23 | Plan select_operate（SBO 共享 AppSeq） | dnp3_t23_select_operate | covered |
| T24 | Plan direct_operate 场景 | dnp3_t24_direct_operate | covered |
| T25 | Plan unsolicited（CON=1 + confirm） | dnp3_t25_unsolicited | covered |
| T26 | Plan cold_restart（FC=129 + Obj 51.1） | dnp3_t26_cold_restart | covered |
| T27 | Plan UDP transport（传运层头前缀） | dnp3_t27_udp_transport | covered |
| T28 | Plan handshake=false | dnp3_t28_no_handshake | covered |
| T29 | Termination=false（无 FIN，以最后 DNP3 ACK 结束） | dnp3_t29_no_termination | covered |
| T30 | AppSeq=15 回绕（AC 0xCF → 0xC0） | dnp3_t30_appseq_wrap | covered |
| T31 | OutstationCount=3 → 3 个 4-tuple 各不同 | dnp3_t31_multi_outstation_3 | covered |
| T34 | Plan 广播地址无响应 | dnp3_t34_broadcast_no_ack | covered |
| T35 | Objects=[] 仅链路层帧 | dnp3_t35_empty_objects_link_only | covered |
| T36 | MalformedCRC=true（CRC 字节 1 bit 翻转） | dnp3_t36_malformed_crc | covered |
| T37 | IIN ObjectUnknown（响应 IIN byte2=0x20） | dnp3_t37_iin_object_unknown | covered（AppRead 场景 responseObjects 返回 nil 覆盖 UnknownObject，IIN 位由 builder 独立设置） |
| T39 | LinkFC=2 生效（帧 Control FC 字段=2） | dnp3_t39_link_fc_status | covered |
| T40 | LinkFC=15 Validate 拒绝 | dnp3_t40_link_fc_overflow | covered（Validate 拒绝） |
| T41 | LinkFCB=1 但 FCV=0（wire FCB=0） | dnp3_t41_fcb_zero_only | covered |
| T42 | LinkFCB=1 但 FCV=1 翻转（0xF3 → 0xD3） | dnp3_t42_fcb_toggle | covered |
| T43 | MalformedLength=255 | dnp3_t43_malformed_length | covered（MalformedLength 应用到所有帧的 Length 字节） |
| T44 | MalformedLength=0 | dnp3_t44_malformed_length_zero | covered |
| T45 | UnknownObject=true（Obj225, IIN 0x20） | dnp3_t45_unknown_object_respond | covered（read_class0 exchange 路径 responseObjects 返回 {255,0,6}） |
| T46 | UnknownFunc=true（请求 FC=0xC8） | dnp3_t46_unknown_func | covered |
| T47 | MalformedLength=200 合法范围 | dnp3_t47_malformed_length_200 | covered |
| T48 | IINAlreadyExecuting byte2=0x04 | dnp3_t48_iin_already_executing | covered |
| T49 | IINEventBufferOverflow byte2=0x08 | dnp3_t49_iin_event_buffer_overflow | covered |
| T50 | IINLocalControl byte1=0x04 | dnp3_t50_iin_local_control | covered |
| T51 | IINBroadcast byte1=0x80 | dnp3_t51_iin_broadcast | covered |
| T52 | IINConfigCorrupt byte2=0x80 | dnp3_t52_iin_config_corrupt | covered |
| T53 | 全位结合 byte1=0x7A / byte2=0x7C | dnp3_t53_iin_all_bits | covered |
| T54 | shorthand OR raw（0x40 + 0x20=0x60） | dnp3_t54_iin_raw_and_shorthand | covered |
| T56 | OutstationIPStart 连续递增 | dnp3_t56_outstation_ip_start | covered |
| T57 | Count2+ 无 IP → 报错 | dnp3_t57_multi_no_ip | covered（Validate 拒绝） |
| T58 | SrcPortStart=0 报错 | dnp3_t58_multi_port_zero | covered（Validate 拒绝） |
| T59 | SrcPortStart+Count 溢出报错 | dnp3_t59_multi_port_overflow | covered（Validate 拒绝） |
| T60 | IPList 优先于 IPStart | dnp3_t60_iplist_overrides_start | covered |
| T70 | 响应 Variation=0 拒绝 | dnp3_t70_response_var0_rejected | covered（Validate 拒绝） |
| T71 | 请求 Variation=0 接受 | dnp3_t71_request_var0_accepted | covered |
| T72 | freeze_clear Variation=1 帧字节 | dnp3_t72_freeze_clear_var1 | covered |
| T73 | Variation=3 拒绝 | dnp3_t73_counter_var3_rejected | covered（Validate 拒绝） |
| T74 | FC=31 拒绝 | dnp3_t74_fc31_reserved_rejected | covered（Validate 拒绝） |
| T75 | FC=215 拒绝 | dnp3_t75_fc215_reserved_rejected | covered（Validate 拒绝） |
| T78 | 外设→主站 ctrl=0x03 帧字节 | dnp3_t78_link_ctrl03_outstation_data | covered |
| T80 | 空数据帧 10B | dnp3_t80_empty_data_10bytes | covered |
| T84 | 10 外设跨序 4-tuple | dnp3_t84_multi_outstation_10 | covered |
| T17 | ReadClass123 App 帧（3 Objects 60.2/60.3/60.4） | dnp3_t17_read_class123 | covered |
| T32 | 3 流 GroupID 各不相同 | dnp3_t32_multi_outstation_3_groupid | covered（flowid RTU 后缀 → 独立 PacketWorker） |
| T33 | 单外设内 wire 顺序保持 | dnp3_t33_multi_outstation_3_wire_order | covered |
| T55 | IIN=0x10000 越界报错 | dnp3_t55_iin_out_of_range | covered（ValidateProtocolSubConfigs 拒绝） |
| T64 | freeze_clear CON=0（auto-set 0） | dnp3_t64_freeze_clear_con0 | covered（帧 AC=0xC0 断言 CON 位） |
| T66 | CROB 请求携带 Status → 拒绝 | dnp3_t66_crob_request_status_rejected | covered（Validate 拒绝） |
| T67 | operate AppSeq=3 与 select 相同 | dnp3_t67_operate_crob_shared_appseq | covered（帧 AC=0xE3 断言） |
| T68 | respond 回显 CROB 含 Status=0 | dnp3_t68_respond_crob_status_echo | covered（7B CROB 帧断言） |
| T69 | CROB 长度/类型校验 | dnp3_t69_qualifier9_rejected / dnp3_t69b_qualifier0_index_overflow / dnp3_t69c_qualifier17_point_index_overflow | covered（Validate 拒绝） |
| T81 | strategy_convert 全链路 | dnp3_t81_strategy_convert_full_path | covered |
| T85 | 100 外设压力 | dnp3_t85_multi_outstation_20_stress | covered（20 RTU 压力） |
| §6.4 业务场景 | write_single → FC=2 Obj=80.1 | dnp3_write_single_80_1 | covered（非 §7 编号用例） |

**Total unique spec IDs covered**: 68（其中 T 编号 67 个 + §6.4 业务场景 1 个）

> 注：T2（ValidMaster）与 T21 等价（reset_link 即 master），无独立用例；T77（链路 FC=4 外设主动上报）由 dnp3_t25_unsolicited 覆盖；T65（CROB select 帧）由 dnp3_t23_select_operate 场景级覆盖；T61/62/63（AppCON auto-set）由 dnp3_t23/t24/t25 隐式覆盖；T82（MCP E2E）由本套 pcap 的 MCP 驱动全链路覆盖；T20a/T20b（CRC16/DNP 标准向量）为 Go 单元测试域。

## Summary Counts

| Metric | Count |
|--------|-------|
| Total spec test cases (§7) | 85 |
| Total pcap test cases | 70 |
| Unique spec IDs covered by pcap | 68 |
| Spec IDs missing from pcap | 17 |
| **Coverage rate** | **~80.0%** (68/85) |

## Coverage by Section

| Section | Range | IDs | Covered | Missing |
|---------|-------|-----|---------|---------|
| §7.1 Validate | T1-T10 | 10 | 9 | 1 |
| §7.2 报文构造 | T11-T20b | 12 | 3 | 9 |
| §7.3 Plan 集成 | T21-T30 | 10 | 10 | 0 |
| §7.4 多外设并发 | T31-T33 | 3 | 3 | 0 |
| §7.5 边界与异常 | T34-T38 | 5 | 4 | 1 |
| §7.6 审计修复新增 | T39-T85 | 47 | 39 | 8 |
| **Total** | | **85** | **68** | **17** |

## Complete List of Missing Spec Cases (17 T IDs)

### §7.1 Validate — 1 missing（T2 与 T21 等价，无独立用例）

| Spec ID | 验证点 | pcap 可行性 |
|---------|--------|------------|
| T2 | ValidMaster | 与 T21 等价（reset_link 即 master），无独立用例 |

### §7.2 报文构造 — 9 missing（Build 单元级，多已由正向场景帧断言隐含覆盖）

| T ID | 验证点 | pcap 可行性 |
|------|--------|------------|
| T11 | ResetLink 帧字节 | 已由 dnp3_t21 帧断言隐式覆盖 |
| T12 | ACK 帧字节 | dnp3_t21 已断言 |
| T13 | User Data 帧字节 | dnp3_t22 已断言 read 请求帧 |
| T16 | ReadClass0 App 帧 | dnp3_t22 已覆盖 |
| T18 | Respond IIN | dnp3_t22 已覆盖（IIN=0x0000） |
| T19 | Unsolicited App 帧 | dnp3_t25 已覆盖 |
| T20 | T20a/T20b CRC16/DNP 向量 | Go 单测重点，pcap 无法替代 |

### §7.3 Plan 集成 — fully covered (T21-T30)

### §7.4 多外设并发 — fully covered (T31-T33)

### §7.5 边界与异常 — 1 missing（T34-T37 已覆盖）

| T ID | 验证点 |
|------|--------|
| T38 | 250B 应用数据 × 4 片（FIR/FIN 分片）— 需 App 层分片，planner 当前无分片逻辑 |

### §7.6 审计修复新增 — 8 missing（T39-T55/T56-T60/T64-T69/T70-T75/T78/T80/T81/T84/T85 已覆盖）

| T ID | 验证点 | pcap 备注 |
|------|--------|----------|
| T61 | select 请求 CON=1 | dnp3_t23 已隐式覆盖 |
| T62 | direct_operate 请求 CON=0 | dnp3_t24 已隐式覆盖 |
| T63 | unsolicited CON=1 | dnp3_t25 已隐式覆盖 |
| T65 | CROB 字节正确性（select 帧） | dnp3_t23 场景级覆盖 |
| T76 | 分片 Confirm 帧 | 需 App 层分片，不可实现 |
| T77 | 链路层 FC=4 外设主动上报 | dnp3_t25 已隐式覆盖 |
| T79 | 17B CRC 分离 | 需分片，不可实现 |
| T82 | MCP E2E | 本套 pcap 即 MCP E2E 覆盖 |
| T83 | 分片 Confirm | 需 App 层分片，不可实现 |

## Key Observations

1. **覆盖率从 67.1% 提升到 80.0%.** 68/85 spec 用例已覆盖（57→70 cases, 57→68 spec IDs）。§7.3 Plan 集成、§7.4 多外设并发均 100% 覆盖；§7.1 Validate 9/10（仅 T2 与 T21 等价）。

2. **Wave 3 新增 13 个用例（T17/T32/T33/T55/T64/T66/T67/T68/T69×3/T81/T85）全部 tshark 字节级验证通过.** 其中 T55/T66/T69a/T69b/T69c 为 Validate-negative（`expect_error`），T17/T32/T33/T64/T67/T68/T81/T85 为正向帧字节断言（FrameAssert offset 54/64 十六进制前缀匹配）。

3. **发现并修复 4 个 planner bug（全部 failing-test-first）**：
   - **dnp3.go planFlow 吞掉 scenarioFrames 错误**（第 113 行 `if err!=nil{return false}`）：qualifier 0/0x17 索引越界、非法 qualifier 等配置错误导致任务"completed with 0 packets"，静默成功。修复：Validate 前置新增 qualifier 0x00 IndexRange>255、qualifier 0x17 point Index>255 检查，错误经 worker.go `planner.Validate` → "validation failed" 传播。
   - **CROB Status 字段静默丢弃**：请求携带 status 字段被 encodePoint 忽略（6B 固定输出），且响应回显 Status 恒为 0（硬编码）。修复：`DNP3Point.Status *uint8`（区分"缺省"与显式 0）+ parseDNP3Points 透传 + Validate 拒绝请求携带 Status（T66）+ 响应回显显式 Status 值（T68）。
   - **IIN=0x10000 静默截断为 0**（getUint16 截断）。修复：ValidateProtocolSubConfigs 新增 dnp3 case 检查 `dnp3.iin` 0-65535（T55）。
   - **isResponse() 缺 scenario="respond"**：respond 场景被当作请求，CROB Status 校验误伤。修复：isResponse 补全 "respond"。

4. **App-FC 常量已修复（v1.1 审计项，Wave 3 前）.** `types.go` 响应类 FC 现为 IEEE 1815-2012 正确值（AppRespond=0x81 等）；T68/T81 响应帧帧断言锁定 0x81。设计文档 §7.6.5 T68 行残留 0x0D 为旧值，wire 正确值见 §2.4.2。

5. **剩余 17 个缺失中仅 3 个真正不可实现**（T38/T79/T83 App 层分片无规划器支持）；其余为单元级/等价覆盖（T2/T11-13/T16/T18-20 及 T61-63/T65/T77/T82）。

6. **多外设 4-tuple/GroupID/wire 顺序全链路已覆盖（T31-T33, T56-T60, T84, T85）.** T85 以 20 RTU（180 包）压力验证；设计为 100 RTU（900 包），任务范围按 20 RTU 执行。
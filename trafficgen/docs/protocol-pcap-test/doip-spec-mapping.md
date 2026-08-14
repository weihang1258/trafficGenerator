# DOIP Spec-to-PCAP Test Case Mapping

## Files

- **Design spec**: `/home/weihang/trafficGenerator/docs/protocol-designs/05-doip-design.md` (§7 "测试用例（T-001 ~ T-203）", line 1021)
- **PCAP test cases**: `/home/weihang/trafficGenerator/trafficgen/test/protocol_pcap/cases/doip.json` (115 cases)
- **PCAP results**: `/home/weihang/trafficGenerator/trafficgen/docs/protocol-pcap-test/doip.md`

## Spec Overview

§7 标题范围为 T-001~T-203，实际表格 14 个小节共 **213 行用例**（含子编号 T021a-g/T022a-c/T027a/T119a/T120a 共 13 行，以表格行数计）：

| Section | Range | Count | Description |
|---------|-------|-------|-------------|
| §7.1 报文格式基础 | T001-T020 | 20 | 14 种 PayloadType 头 8B+载荷字节构造 + 默认方向 |
| §7.2 路由激活 | T021-T030(+a/b/c) | 21 | RC/AT 值域、OEM 变长、V1 拒绝、激活失败/二次确认、SA 一致性 |
| §7.3 诊断消息 | T031-T050 | 20 | UDS 0x10/22/27/34/36/37/3E 字节构造、BlockSeq 回绕、响应 SID/NRC |
| §7.4 诊断确认 | T051-T070 | 20 | 0x8002 Ack/0x8003 Nack 格式、NackCode 值域、MaxDataSize 边界 |
| §7.5 车辆发现 | T071-T090 | 20 | 公告次数/FAR/SyncStatus 值域、V1 载荷 32B、EID/VIN 规则 |
| §7.6 DoIP Entity Status | T091-T100 | 10 | 0x4001/0x4002 格式、NodeType/MaxSockets/MaxDataSize 值域（v2.0.0 新增） |
| §7.7 电源模式 | T101-T110 | 10 | 0x4003/0x4004、PM 值域、IPv4/IPv6 广播、单播、V1 拒绝 |
| §7.8 心跳 | T111-T120(+T119a/T120a) | 12 | 0x0007/0x0008 方向、SA 一致、探活插入诊断、FlowID 后缀 |
| §7.9 通用 NACK | T121-T130 | 10 | NackCode 0x00-0x04 值域、方向固定 down、发送时机 |
| §7.10 IPv6 场景 | T131-T140 | 10 | 广播/单播/心跳/全流程 IPv6、RFC 2464 多播 MAC |
| §7.11 边界值 | T141-T160 | 20 | PV 拒绝、PayloadLength 边界、MSS、UserData 0~65536B、OEM 255B、Direction 大小写 |
| §7.12 状态机阶段顺序 | T161-T170 | 10 | 阶段顺序/跳过/失败、多 ECU、GroupID、FlowID 后缀 |
| §7.13 集成测试 | T171-T185 | 15 | 端到端 22 包、8 ECU、ctx/并发、IPv6、二次确认/失败端到端 |
| §7.14 错误处理 | T186-T200 | 15 | InvPV/越界、UDS 未知 SID、Pacer 间隔、Termination、总包数 |
| **Total** | | **213** | |

## Covered Mapping (186 spec IDs → 115 pcap cases)

### §7.1 报文格式基础（T001-T020，20/20）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T001 | DoIP 头 8B V2（02 FD 00 01 00 00 00 00） | doip_s1_variant_request_up | covered |
| T002 | InverseProtocolVersion=0xFD | doip_s1_variant_request_up | covered |
| T003 | 0x0001 广播发现 PayloadLength=0 | doip_s1_variant_request_up | covered |
| T004 | 0x0002 EID 发现 Payload=6B | doip_t004_eid_request | covered |
| T005 | 0x0003 VIN 发现 Payload=17B | doip_t005_vin_request | covered |
| T006 | 0x0004 公告 PayloadLength=33 FAR=0x00 Sync=0x00 | doip_s1_discovery_broadcast | covered |
| T007 | 0x0004 公告 3 次 | doip_s1_discovery_broadcast | covered |
| T008 | 0x0005 路由激活 SA=0x0E80 AT=0x00 PL=7 | doip_s2_routing_activation | covered |
| T009 | 0x0006 Success RC=0x10 PL=9 | doip_s2_routing_activation | covered |
| T010 | 0x0007 心跳请求 PayloadLength=0 | doip_s5_alive_check | covered |
| T011 | 0x0008 心跳应答 PL=2 SA=0x0E80 | doip_alive_response | covered |
| T012 | 0x4001 Entity Status 请求 PL=0 | doip_s7_entity_status | covered |
| T013 | 0x4002 Entity Status 应答 PL=7 | doip_s7b_entity_down_default | covered |
| T014 | 0x4003 电源模式请求 PL=0 | doip_power_mode | covered |
| T015 | 0x4004 电源模式应答 PL=1 PM=0x01 | doip_power_mode_response | covered |
| T016 | 0x8001 诊断消息 SA/TA/UDS 10 03 PL=6 | doip_s3_diag_uds10 | covered |
| T017 | 0x8002 Ack PL=7 PrevDiag=10 03 | doip_s3_diag_uds10 | covered |
| T018 | 0x8003 Nack NackCode=0x02 PrevDiag 副本 | doip_s4_diag_nack | covered（ASCII 偏差见 Observation 3） |
| T019 | 0x0000 Generic NACK NackCode=0x01 PL=1 | doip_s8_generic_nack | covered |
| T020 | 默认 Direction 空值走默认方向 | doip_s7b_entity_down_default | covered（Direction 缺省→down 发 0x4002） |

### §7.2 路由激活（T021-T030+变体，21 行，20 覆盖）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T021 | RC=0x10 Success 通过 | doip_s2_routing_activation | covered |
| T021a | RC=0x00 Unknown SA 通过 | doip_s11_activation_fail | covered |
| T021b | RC=0x01 Unknown SA 失败 | doip_rc_0x01 | covered |
| T021c | RC=0x04 拒绝 | doip_rc_0x04 | covered（0x0006 RC=0x04，FIN 后结束） |
| T021d | RC=0x05 拒绝 | doip_rc_0x05 | covered |
| T021e | RC=0x07 拒绝 | doip_rc_0x07 | covered |
| T021f | RC=0x11 二次确认 | doip_rc_0x11_confirm | covered（0x0005×2+0x0006×2） |
| T021g | RC=0x12 拒绝 | doip_rc_0x12 | covered（Validate 拒绝） |
| T022 | ActivationType=0x00 Default | doip_s2_routing_activation | covered |
| T022a | ActivationType=0x01 WWH-OBD | doip_at_0x01 | covered |
| T022b | ActivationType=0xE0 OEM | doip_at_0xe0 | covered |
| T022c | ActivationType=0x02 拒绝 | doip_at_0x02 | covered（Validate 拒绝） |
| T023 | OEM-specific=4B 变长 | doip_s2_variant_oem4b | covered（"01020304" 按 ASCII 8 字节→PL=15，见 Observation 3） |
| T024 | OEM-specific=0B PL=7 | doip_s2_routing_activation | covered |
| T025 | V1+OEM 拒绝 | doip_v1_oem | covered（Validate 拒绝） |
| T026 | 激活失败关闭 TCP（FIN 无诊断） | doip_s11_activation_fail | covered |
| T027 | 二次确认子阶段 0x0005×2+0x0006×2 | doip_rc_0x11_confirm | covered |
| T027a | 二次确认最终 RC=0x05 | doip_rc_0x11_confirm | **not-expressible**（配置仅单 ResponseCode 字段，最终应答恒 0x10） |
| T028 | 0x8001 SA 与 0x0005 一致 | doip_sa_consistent | covered |
| T029 | 0x8001 SA 不一致拒绝 | doip_sa_mismatch | covered（Validate 拒绝） |
| T030 | 0x8001 TA 与 0x0006 SLA 一致 | doip_sa_consistent | covered |

### §7.3 诊断消息（T031-T050，20 行，20 覆盖）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T031 | UDS 0x10 0x03 | doip_s3_diag_uds10 | covered |
| T032 | UDS 0x22 0xF190 | doip_s4_diag_nack | covered（did 按 ASCII 字节，UserData=22 66 31 39 30） |
| T033 | UDS 0x27 0x01 请求 seed | doip_uds_27_seed_request | covered（UserData=27 01） |
| T034 | UDS 0x27 0x02 发送 key | doip_uds_27_send_key | covered（UserData=27 02 55 66 77 88） |
| T035 | UDS 0x27 奇数响应带 seed | doip_uds_27_odd_response | covered（UserData=67 01 11 22 33 44） |
| T036 | UDS 0x27 偶数响应无 key | doip_uds_27_even_response | covered（UserData=67 02） |
| T037 | UDS 0x27 偶数响应+Key 非空拒绝 | doip_uds_27_even_response_key | covered（Validate 拒绝） |
| T038 | UDS 0x36 BlockSeq=0x01 | doip_s10_big_transfer | covered |
| T039 | UDS 0x36 BlockSeq 回绕 n=256 | doip_uds_blockseq_wrap | covered（BlockSeq=0x00） |
| T040 | UDS 0x36 BlockSeq 回绕 n=257 | doip_uds_blockseq_wrap | covered（BlockSeq=0x01） |
| T041 | UDS 0x34 RequestDownload | doip_s10_big_transfer | covered |
| T042 | UDS 0x37 RequestTransferExit | doip_s10_big_transfer | covered |
| T043 | UDS 0x3E TesterPresent | doip_uds_3e_tester_present | covered |
| T044 | UDS 正向响应 SID 自动 | doip_uds_22_response_sid | covered（首字节 0x62） |
| T045 | UDS 否定响应格式 | doip_uds_nrc | covered（UserData=7F 22 11） |
| T046 | UDS NRC 优先 IsResponse | doip_uds_nrc | covered（NRC 优先） |
| T047 | UDS NRC=0x00 拒绝 | doip_uds_nrc_0x00 | **impl-divergence**（0 判定未设置→普通 22，不拒绝） |
| T048 | UDS NRC=0xFF 拒绝 | doip_uds_nrc_0xff | covered（Validate 拒绝） |
| T049 | UDS NRC=0x7F 通过 | doip_uds_nrc_0x7f | covered（UserData=7F 22 7F） |
| T050 | UDS HasSubFunction auto | doip_s3_diag_uds10 | covered |

### §7.4 诊断确认（T051-T070，20 行，15 覆盖）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T051 | 0x8002 AckCode=0x00 | doip_s3_diag_uds10 | covered |
| T052 | 0x8002 AckCode=0x01 拒绝 | doip_ack_code_0x01 | covered（Validate 拒绝） |
| T053 | 0x8002 PayloadLength=5+M | doip_s3_diag_uds10 | covered |
| T054 | 0x8003 PL=5+M（V1 同格式） | — | **not-expressible**（实现中 0x8003 始终 V2 头；V1+Message 场景无法单独构造 0x8003） |
| T055 | 0x8002 PrevDiag=UserData 副本 | doip_s3_diag_uds10 | covered |
| T056 | 0x8003 NackCode=0x02 | doip_s4_diag_nack | covered |
| T057 | 0x8003 NackCode=0x03 | doip_nack_0x03 | covered |
| T058 | 0x8003 NackCode=0x04 | doip_nack_0x04 | covered |
| T059 | 0x8003 NackCode=0x06 | doip_nack_0x06 | covered |
| T060 | 0x8003 NackCode=0x00 拒绝 | doip_nack_0x00 | covered（Validate 拒绝） |
| T061 | 0x8003 NackCode=0x01 拒绝 | doip_nack_0x01 | covered（Validate 拒绝） |
| T062 | 0x8003 NackCode=0x09 拒绝 | doip_nack_0x09 | covered（Validate 拒绝） |
| T063 | 0x8003 PrevDiag 4096B | — | **pcap-infeasible**（4096B 载荷需巨帧，超 MTU 场景不在 pcap 域） |
| T064 | 0x8001 UserData ≤ MaxDataSize | doip_maxdata_4000 | covered（4000B ≤ 4095 通过） |
| T065 | 0x8001 UserData > MaxDataSize | doip_maxdata_5000 | covered（Validate 拒绝） |
| T066 | UserData=65535B 理论边界 | — | **pcap-infeasible**（需 65539B 单帧，超 MTU） |
| T067 | UserData=65536B 通过 | — | **pcap-infeasible** |
| T068 | UserData>4GB 拒绝 | — | **pcap-infeasible**（理论边界，单测域） |
| T069 | NackCode=nil 走 Ack | doip_s3_diag_uds10 | covered |
| T070 | NackCode 非 nil 走 Nack | doip_s4_diag_nack | covered |

### §7.5 车辆发现（T071-T090，20 行，20 覆盖）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T071 | 0x0004 公告默认 3 次 | doip_s1_discovery_broadcast | covered |
| T072 | AnnouncementCount=1 | doip_announce_1 | covered |
| T073 | 0x0004 FAR=0x00 | doip_s1_discovery_broadcast | covered |
| T074 | FAR=0x10 通过 | doip_far_0x10 | covered |
| T075 | FAR=0x11 拒绝 | doip_far_0x11 | covered（Validate 拒绝） |
| T076 | FAR=0x20 拒绝 | doip_far_0x20 | covered |
| T077 | FAR=0x40 拒绝 | doip_far_0x40 | covered |
| T078 | 0x0004 SyncStatus=0x00 | doip_s1_discovery_broadcast | covered |
| T079 | SyncStatus=0x10 通过 | doip_sync_0x10 | covered |
| T080 | SyncStatus=0x01 拒绝 | doip_sync_0x01 | covered（Validate 拒绝） |
| T081 | 0x0004 PL=33 V2 | doip_s1_discovery_broadcast | covered |
| T082 | V1 PL=32 | doip_v1_announce_32b | covered（01 FE + 32B 载荷） |
| T083 | EID 空+DstMAC 有效 → EID=MAC | doip_eid_from_dstmac | covered（EID=001122334455） |
| T084 | EID 空+DstMAC 空 → 6B 0 | doip_eid_from_default_mac | covered（默认 DstMAC 02:00:00:00:00:02） |
| T085 | EID 空+DstMAC 非法 → 6B 0 | doip_eid_invalid_mac | **impl-divergence**（MCP 层拒非法 MAC，fallback 不可达） |
| T086 | DstMAC 过长拒绝 | doip_eid_oversized_mac | covered（MCP 拒绝 invalid MAC format） |
| T087 | EID 显式 6B | doip_s1_discovery_broadcast | covered |
| T088 | EID 长度非法拒绝 | doip_eid_short | covered（Validate 拒绝） |
| T089 | VIN ASCII 17B | doip_s1_discovery_broadcast | covered |
| T090 | VIN 长度非法拒绝 | doip_vin_short | covered（Validate 拒绝） |

### §7.6 Entity Status（T091-T100，10 行，10 覆盖）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T091 | 0x4001 请求无 Payload | doip_s7_entity_status | covered |
| T092 | 0x4002 应答 7B | doip_s7b_entity_down_default | covered |
| T093 | NodeType=0x00 | doip_entity_gateway | covered |
| T094 | NodeType=0x01 Node | doip_s7b_entity_down_default | covered |
| T095 | NodeType=0x02 拒绝 | doip_entity_nodetype_0x02 | covered（Validate 拒绝） |
| T096 | MaxOpenSockets=255 | doip_entity_sockets_255 | covered（tshark 十进制显示 255） |
| T097 | Cur≤Max 通过 | doip_entity_cur_le_max | covered（1≤2） |
| T098 | Cur>Max 拒绝 | doip_entity_cur_gt_max | covered（Validate 拒绝） |
| T099 | MaxDataSize=4095 | doip_s7b_entity_down_default | covered |
| T100 | MaxDataSize=0 | doip_entity_maxdata_0 | covered（0→不触发 MaxDataSize 校验） |

### §7.7 电源模式（T101-T110，10 行，10 覆盖）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T101 | 0x4003 请求无 Payload | doip_power_mode | covered |
| T102 | 0x4004 应答 PL=1 PM=0x01 | doip_power_mode_response | covered |
| T103 | PM=0x00 | doip_pm_0x00 | covered |
| T104 | PM=0x01 | doip_power_mode_response | covered |
| T105 | PM=0x02 | doip_pm_0x02 | covered |
| T106 | PM=0x03 拒绝 | doip_pm_0x03 | covered（Validate 拒绝） |
| T107 | 广播 IPv4 255.255.255.255 | doip_pm_broadcast_ipv4 | covered |
| T108 | 广播 IPv6 ff02::1 | doip_pm_broadcast_ipv6 | covered（+RFC 2464 MAC） |
| T109 | 单播 | doip_pm_unicast | covered |
| T110 | V1+PowerMode 拒绝 | doip_v1_pm | covered（Validate 拒绝） |

### §7.8 心跳（T111-T120+变体，12 行，9 覆盖）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T111 | 0x0007 down 通过 | doip_s5_alive_check | covered |
| T112 | 0x0008 up 通过 | doip_alive_response | covered |
| T113 | 0x0008 SA 与 0x0005 一致 | doip_alive_sa_consistent | covered |
| T114 | 0x0008 SA 不一致拒绝 | doip_alive_sa_mismatch | covered（Validate 拒绝） |
| T115 | 0x0007 插入诊断中 | doip_alive_mid_messages | covered（0x0007 在 2 个诊断事务后） |
| T116 | 0x0008 紧跟 0x0007 | — | **not-expressible**（planner 单方向语义：一配置一方向） |
| T117 | 心跳超时单边 | doip_s5_alive_check | covered（仅 0x0007） |
| T118 | FlowID 后缀 :tcp:alive | — | **not-expressible**（Go 单测域，pcap 无 FlowID 可见性） |
| T119 | 0x0007 up 拒绝 | doip_dir_invalid | **impl-divergence**（direction 校验仅查值域，不按 PayloadType 限制方向） |
| T119a | 0x0007 down 通过 | doip_s5_alive_check | covered |
| T120 | 0x0008 down 拒绝 | — | **not-expressible**（同 T119：无方向-类型校验） |
| T120a | 0x0008 up 通过 | doip_alive_response | covered |

### §7.9 通用 NACK（T121-T130，10 行，9 覆盖）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T121 | NackCode=0x00 | doip_generic_nack_0x00 | covered |
| T122 | NackCode=0x01 | doip_s8_generic_nack | covered |
| T123 | NackCode=0x02 | doip_generic_nack_0x02 | covered |
| T124 | NackCode=0x03 | doip_generic_nack_0x03 | covered |
| T125 | NackCode=0x04 | doip_generic_nack_0x04 | covered |
| T126 | NackCode=0x05 拒绝 | doip_generic_nack_0x05 | covered（Validate 拒绝） |
| T127 | GenericNack 方向固定 down | doip_s8_generic_nack | covered |
| T128 | GenericNack up 拒绝 | — | **not-expressible**（GenericNack 无 direction 字段，见 Observation 4） |
| T129 | GenericNack 在 0x0006 后 | doip_s8_generic_nack | covered |
| T130 | 0x0000 PayloadLength=1 | doip_s8_generic_nack | covered |

### §7.10 IPv6 场景（T131-T140，10 行，9 覆盖）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T131 | IPv6 Discovery 广播 ff02::1 | doip_ipv6_discovery | covered |
| T132 | IPv6 PowerMode 广播 | doip_pm_broadcast_ipv6 | covered（DstIP=ff02::1） |
| T133 | IPv6 单播路由激活 | doip_ipv6_activation | covered |
| T134 | IPv6 诊断 0x8001+0x8002 | doip_ipv6_activation | covered（IPv6 TCP 偏移 74） |
| T135 | IPv6 心跳 | doip_ipv6_alive | covered（0x0007 over IPv6） |
| T136 | IPv6 MAC RFC 2464 | doip_pm_broadcast_ipv6 | covered（33:33:00:00:00:01） |
| T137 | IPv6 Entity Status | doip_ipv6_entity | covered（0x4002 over IPv6） |
| T138 | IPv6 全流程端到端 | doip_full_flow_22_ipv6 | covered（16 包：2 诊断事务） |
| T139 | IPv6 多 ECU | — | **not-expressible**（多 ECU 需 strategy_flow_control 多流，pcap 驱动不支持） |
| T140 | IPv6+V1 | doip_ipv6_v1 | covered（01 FE 头 over IPv6） |

### §7.11 边界值（T141-T160，20 行，16 覆盖）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T141 | PV=0x00 拒绝 | doip_pv_0x00 | **impl-divergence**（0 默认化为 0x02，不拒绝） |
| T142 | PV=0x03 拒绝 | doip_pv_0x03 | covered（Validate 拒绝） |
| T143 | PV=0xFF 拒绝 | doip_pv_0xff | covered（Validate 拒绝） |
| T144 | InvPV 不匹配拒绝 | — | **not-expressible**（实现自动计算 InvPV，无配置字段） |
| T145 | PayloadLength=0 | doip_s1_variant_request_up 等 | covered（四类请求 length=0） |
| T146 | PL=0xFFFFFFFF 理论边界 | — | **pcap-infeasible**（u32 理论边界，单测域） |
| T147 | MSS=0 拒绝 | doip_mss_fallback | **impl-divergence**（MSS=0 走 fallback 1460，不拒绝；H5 允许二选一） |
| T148 | MSS=1460 默认 | doip_mss_fallback | covered（fallback 行为验证） |
| T149 | UserData=0B | doip_userdata_empty | covered（0x8001 PL=4） |
| T150 | UserData=65535B | — | **pcap-infeasible**（65539B 单帧超 MTU） |
| T151 | UserData=65536B | — | **pcap-infeasible** |
| T152 | OEM=0B → PL=7 | doip_s2_routing_activation | covered |
| T153 | OEM=4B hex → PL=11 | doip_s2_variant_oem4b | **impl-divergence**（JSON 字符串按 ASCII 字节，4 字符=8B → PL=15） |
| T154 | OEM=255B | doip_oem_255b | covered（ASCII 255 字符 → PL=262） |
| T155 | Direction="" 走默认 | doip_s7b_entity_down_default | covered |
| T156 | Direction="UP" 大小写不敏感 | doip_dir_upper | covered（等价 "up"） |
| T157 | Direction="invalid" 拒绝 | doip_dir_invalid | covered（Validate 拒绝） |
| T158 | LogicalAddress=0x0000 | doip_la_0x0000 | **impl-divergence**（0 默认化为 0x0001，0x0000 不可达） |
| T159 | LogicalAddress=0xFFFF | doip_la_ffff | covered |
| T160 | TesterAddress=0x0000 | doip_sa_zero_boundary | **impl-divergence**（0 默认化为 0x0E80） |

### §7.12 状态机阶段顺序（T161-T170，10 行，7 覆盖）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T161 | 完整 5 阶段顺序 | doip_full_flow_22 | covered（Discovery→Entity→Activation→Messages→AliveCheck） |
| T162 | 无 Discovery 直接激活 | doip_no_discovery_direct_activation | covered |
| T163 | 无 Activation 直接 Messages 拒绝 | doip_messages_without_activation | covered（Validate 拒绝） |
| T164 | 激活失败跳过 Messages | doip_s11_activation_fail | covered |
| T165 | AliveCheck 插入 Messages 中间 | doip_alive_mid_messages | covered（0x0007 在诊断事务后、挥手前） |
| T166 | PowerMode 在 TCP 挥手后 | doip_power_mode_after_teardown | **impl-divergence**（0x4004 为包 1，在 TCP 全部阶段之前） |
| T167 | GenericNack 在 Activation 后 | doip_s8_generic_nack | covered |
| T168 | 多 ECU 各自完整流程 | — | **not-expressible**（多 ECU） |
| T169 | GroupID 路由同 worker | — | **not-expressible**（Go 单测域） |
| T170 | FlowID 后缀六类 | — | **not-expressible**（Go 单测域） |

### §7.13 集成测试（T171-T185，15 行，9 覆盖）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T171 | 单 ECU 端到端 | doip_full_flow_22 | covered（21 包：公告替代 0x0001，见 Observation 6） |
| T172 | 8 ECU 端到端 | — | **not-expressible**（多 ECU） |
| T173 | ctx 取消中断 | — | **not-expressible**（Go 单测域） |
| T174 | PacketWorkers=8 并发 | — | **not-expressible**（Go 单测域） |
| T175 | PacketWorkers=8 阶段顺序 | — | **not-expressible**（Go 单测域） |
| T176 | PacketWorkers=8 FlowID | — | **not-expressible**（Go 单测域） |
| T177 | IPv6 全流程端到端 | doip_full_flow_22_ipv6 | covered |
| T178 | IPv6 PowerMode 广播 | doip_pm_broadcast_ipv6 | covered（T132 同 case） |
| T179 | IPv6 Discovery+TCP+PowerMode | doip_full_flow_22_ipv6 | covered |
| T180 | 多 ECU IPv6 混合 | — | **not-expressible**（多 ECU） |
| T181 | 二次确认端到端 | doip_rc_0x11_confirm | covered（10 包） |
| T182 | 激活失败端到端 | doip_s11_activation_fail | covered |
| T183 | Entity Status 端到端 | doip_full_flow_22 | covered（0x4002 在公告后、握手前） |
| T184 | 大文件 TransferData | doip_s10_big_transfer / doip_big_transfer_segmented | covered（MSS 分段：>MSS-40 分两段） |
| T185 | 0x8003 Nack 端到端 | doip_s4_diag_nack | covered |

### §7.14 错误处理（T186-T200，15 行，12 覆盖）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T186 | InvPV=0x00 不匹配拒绝 | — | **not-expressible**（实现自动计算 InvPV） |
| T187 | 0x0000 NackCode=0xFF 拒绝 | doip_generic_nack_0x05 | covered（0x05 已是上限，0xFF 同路径 Validate 拒绝） |
| T188 | 0x8002 AckCode=0x01 拒绝 | doip_ack_code_0x01 | covered |
| T189 | 0x8001 SA=0x0000 边界 | doip_sa_zero_boundary | **impl-divergence**（0 默认化，见 T160） |
| T190 | 0x8001 TA=0xFFFF 边界 | doip_ta_ffff_boundary | **impl-divergence**（TA≠0 且≠LogicalAddress 被拒；仅 LA=0xFFFF 时可验证字节） |
| T191 | UDS 未知 SID 拒绝 | doip_uds_unknown_sid | covered（Validate 拒绝） |
| T192 | 0x22+HasSubFunction=true 拒绝 | doip_uds_22_subfunction | covered（Validate 拒绝） |
| T193 | 0x10+HasSubFunction=false 仍输出 | doip_uds_10_nosubfunc_false | **impl-divergence**（false 时跳过 sub-function 字节；spec 要求仍输出） |
| T194 | Announcement Pacer 间隔 | — | **not-expressible**（Go 单测域） |
| T195 | Termination=false 无 FIN | doip_termination_false | covered |
| T196 | Termination=true 有 FIN | doip_s2_routing_activation | covered |
| T197 | UserData>MaxDataSize 拒绝 | doip_maxdata_5000 | covered |
| T198 | EID 与 DstMAC 一致 | doip_eid_from_dstmac | covered |
| T199 | 多 ECU VIN 唯一 | — | **not-expressible**（多 ECU） |
| T200 | 完整诊断流程总包数 | doip_full_flow_22 | covered（21 包，见 Observation 6） |

**Total unique spec IDs covered**: 186（covered 174 + impl-divergence 12；not-expressible 20 + pcap-infeasible 7）

## Summary Counts

| Metric | Count |
|--------|-------|
| Total spec test cases (§7) | 213 |
| Total pcap test cases | 115 |
| Unique spec IDs covered by pcap | 186（174 covered + 12 divergence-已断言） |
| Spec IDs missing from pcap | 27（20 not-expressible + 7 pcap-infeasible） |
| **Coverage rate** | **87.3%** (186/213) |
| 不可达域（多 ECU/Go 单测/4GB 理论边界） | 27 条全部有归因，无遗留缺口 |

## Coverage by Section

| Section | Range | Rows | Covered | Divergence | Not-expressible | Infeasible |
|---------|-------|------|---------|-----------|-----------------|------------|
| §7.1 报文格式基础 | T001-T020 | 20 | 20 | 0 | 0 | 0 |
| §7.2 路由激活 | T021-T030(+变体) | 21 | 20 | 0 | 1 (T027a) | 0 |
| §7.3 诊断消息 | T031-T050 | 20 | 19 | 1 (T047) | 0 | 0 |
| §7.4 诊断确认 | T051-T070 | 20 | 15 | 0 | 1 (T054) | 4 (T063/T066/T067/T068) |
| §7.5 车辆发现 | T071-T090 | 20 | 19 | 1 (T085) | 0 | 0 |
| §7.6 Entity Status | T091-T100 | 10 | 10 | 0 | 0 | 0 |
| §7.7 电源模式 | T101-T110 | 10 | 10 | 0 | 0 | 0 |
| §7.8 心跳 | T111-T120(+变体) | 12 | 8 | 1 (T119) | 3 (T116/T118/T120) | 0 |
| §7.9 通用 NACK | T121-T130 | 10 | 9 | 0 | 1 (T128) | 0 |
| §7.10 IPv6 场景 | T131-T140 | 10 | 9 | 0 | 1 (T139) | 0 |
| §7.11 边界值 | T141-T160 | 20 | 11 | 5 (T141/T147/T153/T158/T160) | 1 (T144) | 3 (T146/T150/T151) |
| §7.12 状态机顺序 | T161-T170 | 10 | 6 | 1 (T166) | 3 (T168/T169/T170) | 0 |
| §7.13 集成测试 | T171-T185 | 15 | 9 | 0 | 6 (T172/T173/T174/T175/T176/T180) | 0 |
| §7.14 错误处理 | T186-T200 | 15 | 9 | 3 (T189/T190/T193) | 3 (T186/T194/T199) | 0 |
| **Total** | | **213** | **174** | **12** | **20** | **7** |

注：Divergence 列计入总覆盖（186 = 174 纯 covered + 12 divergence-已断言；见 Summary Counts 口径）。行数按 §7 表格实际行数（含子编号）。

## Missing Cases 归因（27 条）

**not-expressible（20 条，planner 单方向语义/配置字段缺失/Go 单测域）**：
- T027a（二次确认最终 RC=0x05）：配置仅单 ResponseCode 字段，最终应答恒 0x10（代码注释确认）
- T054（V1 0x8003 格式）：实现 0x8003 恒 V2 头，无 V1 独立构造路径（见 Key Observations 9，潜在可表达待验证）
- T116（0x0008 紧跟 0x0007）：planner 单方向语义，一配置一方向
- T118/T169/T170/T173-T176/T194（FlowID 后缀/GroupID 路由/ctx 取消/PacketWorkers/Pacer 间隔）：Go 单测域，pcap 无内部状态可见性
- T120/T128（方向-类型固定校验）：Validate 仅查 direction 值域，无按 PayloadType 的方向限制（T119 已作为 divergence 记录，T120/T128 同路径）
- T139/T168/T172/T180/T199（多 ECU）：pcap 驱动无 strategy_flow_control，单 flow 无法表达 3/8 ECU
- T144/T186（InvPV 不匹配）：实现自动计算 InvPV，无配置字段

**pcap-infeasible（7 条，4GB/65535B 理论边界或超 MTU 载荷）**：
- T063（PrevDiag 4096B）、T066/T067/T150/T151（UserData 65535B/65536B 单帧超 MTU）、T068/T146（PayloadLength u32 理论边界）

## Key Observations

1. **§7.1 报文格式基础 20/20 是唯一满覆盖章节**；§7.2 路由激活 20/21、§7.5 车辆发现 19/20、§7.6 Entity Status 10/10、§7.7 电源模式 10/10、§7.9 通用 NACK 9/10 接近满覆盖。最低仍是 §7.13 集成（9/15，多 ECU 不可表达 6 条）。

2. **spec-vs-impl 差异 12 处全部已固化断言**（divergence case 明确标注"实现差异"并断言实际行为）：
   - T047（NRC=0 默认化不拒绝）、T085（MAC 非法被 MCP 层前置拒绝，EID 6B-0 fallback 不可达）、T119（无方向-类型校验）、T141（PV=0 默认化 0x02）、T147（MSS=0 fallback 1460，H5 二选一已选 fallback）、T153（OEM 字符串按 ASCII 字节）、T158/T160/T189（0 值默认化，0x0000 不可达）、T166（PowerMode 在 TCP 之前）、T190（TA=0xFFFF 仅当 LA=0xFFFF 时通过）、T193（HasSubFunction=false 跳过 sub-function 字节，spec 要求仍输出）。

3. **字符串字段按原始 ASCII 字节发送（getByteSlice 非 hex 解码）**：OEM="01020304"→8 个 ASCII 字节（PL=15 vs spec T023 断言 hex 4B→PL=11）；did="f190"→4 字节 66 31 39 30。T023/T018/T032 覆盖成立（结构路径验证），字节级数值与 spec 表不符，已作为 T153 divergence 记录。如需 hex 字节请用 JSON 数字数组（如 did=[241,144]）。

4. **planner 阶段顺序与 spec §4 一致，但 UDP 阶段先于 TCP 全部阶段**：实测包序 = Discovery(UDP)→EntityStatus(UDP)→PowerMode(UDP)→握手(TCP)→Activation→Messages→AliveCheck→GenericNack→挥手。T166（PowerMode 在挥手后）因此不可满足；T115/T165（AliveCheck 插入 Messages 中间）实现为 Messages 完成后、挥手前单发 0x0007。

5. **tshark 字段显示格式要点**：doip.max_sockets/sockets、doip.diag_ack_code/diag_nack_code 按十进制显示（FT_UINT8 无 BASE_HEX）；doip.type/source_address 等按 0x 十六进制；uds.sa.type 十六进制、uds.sa.seed/key 为无冒号 hex 串；doip.uds_payload 字段不存在（UDS 载荷由 UDS dissector 解析，用 uds.* 字段断言）。

6. **"22 包"口径**：T171/T200 的 spec 22 包含 0x0001 发现请求；本实现用 0x0004 公告×3 替代（planner 的 down 语义），实测 21 包（3+1+3+2+8+1+3）。T138/T177 IPv6 全流程同样 21 包。包序与阶段顺序断言不受影响。

7. **二次确认（T021f/T027/T181）完整覆盖**：RC=0x11+ConfirmationRequired=true → 0x0005→0x0006(RC=0x11)→0x0005→0x0006(RC=0x10) 共 10 包，与 spec §4.3 子阶段一致。

8. **测试方法论**：115 个 case 中 Validate 拒绝类（ExpectError）27 个，全部经 MCP 层实际报错验证（error_contains 断言精确错误串）；字节级断言 90+ 处 frames hex（帧偏移 IPv4 UDP=42/TCP=54、IPv6 UDP=62/TCP=74）。

9. **T054（V1 0x8003 格式）待验证**：spec §7.4 断言 V1 头下 0x8003 构造。实现 0x8003 恒用 V2 头（PV=0x02），无 V1 独立路径，暂列 not-expressible。若 lead 判定"V1 头+0x8003"必须可表达，可评估在 builder 层增加 V1 头选择字段（超出 pcap 测试域）。

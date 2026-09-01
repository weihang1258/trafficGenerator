# HL7 v2.x over MLLP（医疗信息交换标准 / 最小下层协议）测试用例契约

> 版本：v2.1.1（测试用例）
> 日期：2026-09-01
> 配套设计：`docs/protocol-designs/68-hl7-design.md`（v2.1.1）
> 机器契约：`trafficgen/test/protocol_pcap/cases/hl7.json`（proto key：`hl7`；本版不写文件，当前 JSON 仅含注册前置占位）
> 状态：按《协议设计文档与用例文档需求文档 v1.3》完成独立重审（审查员 rr-hl7：行为面 145 点、confirmed findings 2 CRITICAL + 8 MAJOR + 12 MINOR），本版为修复轮产物：25 条 → **95 条（62 正 + 33 负）**；经 v2.1.0 修复轮 → 复验轮（V 系列）→ 关单点验，**rr-hl7 判定 clean 关单**（confirmed findings = 0）。记录见 §9。
> 规范基线：HL7 v2.5（Chapter 2/9/10，字段号/表 0103/0276 按 v2.5）、MLLP 封装、IANA TCP 2575。

## 1. 测试原则和未注册边界

用例按《需求文档 v1.3》从规范（HL7 v2.5 + MLLP）与设计 §2–§8 派生：**可测试行为面全枚举**（消息类型 × 段/字段 × 值域 × 边界 × 错误分支 × 载体 × 场景 × 交互），用例 = 不可再分的测试点（本版 95 条 = 62 正 + 33 负，对应 rr-hl7 枚举的 145 行为面点）。依据列标注出处；不要求与设计章节一对一映射。**pcap 与 port_group/NIC 两种输出路径使用同一份用例契约**（同一 ID、同一断言、同一包数，C-7，与 64-cwmp/66-doh 同形）。

当前 JSON 只保留 `hl7_neg_unregistered` 注册前置占位（`proto=hl7`、`expect_error=true`、`error_contains` 精确为 `unknown layer`）；占位的拒绝、0 包或空 PCAP 不得报告为 HL7 行为通过。

**断言字段以 tshark 3.6.14 实测为准**：hl7 dissector 绑定 `tcp.port 2575`（`-G decodes`）。默认可提取：`hl7.segment`（**整段原始文本**非段名，多段逗号拼接）、`hl7.field`（每段首值即段名）、`hl7.message.type`/`hl7.event.type`、`hl7.malformed`。偏好门控默认不提取（harness 不支持 `-o` 传参，不作断言字段）：`hl7.llp.sob`/`hl7.llp.eob`/`hl7.raw`/`hl7.raw.segment`。标准载体字段 `tcp.stream`、`tcp.len`、`tcp.dstport`、`tcp.flags.*`、`ip.version`、`ipv6.nxt` 照常可用。**非 2575 端口实测不按 hl7 解码**（登记在册的启发式实测不触发，D-4）——非默认端口用例的 fields 断言必须带 `-d tcp.port==<N>,hl7` DecodeAs 提示（harness 已实证支持）或全 frames hex 断言。MSA-2↔MSH-10 关联用 `same_as_packet`；动态值用 `nonzero`/`distinct_values`。

**动态字段禁止硬编码**：MSH-10/MSA-2、MSH-7/EVN-2、PID-3 为运行期/策略值（fixture 显式固定的用例除外，各例声明）；不声称临床业务成功/患者真实/身份认证通过——ACK `AA` 只断言线上格式、关联与响应码。

**包数约定**（实现期校准值）：单事务（消息→ACK 各 1 段）= 3+2+4 = **9**；`ack_mode=null` 消息只 1 包；N 笔全 ACK = 3+2N+4；跨段每加 1 段 +1；多会话/并发 = 各会话之和，第二会话握手包号 = 前会话总包数 + 1。负例无 packet_count。

## 2. 原子用例索引

| # | ID | 类型 | 载体 | 覆盖（一句话） | 依据 | 包数 |
|---:|---|---|---|---|---|---:|
| 1 | `hl7_adt_a01_ipv4` | 正 | TCP/IPv4 | ADT^A01 基线：MSH/EVN/PID/PV1 + 自动 ACK（§3.4/§3.5/§5.2） | 设计§3.4/§3.5 | 9 |
| 2 | `hl7_adt_a02_transfer` | 正 | TCP/IPv4 | ADT^A02 转科：EVN-1=A02、PV1-3 位置更新 | 设计§3.5 | 9 |
| 3 | `hl7_adt_a03_discharge` | 正 | TCP/IPv4 | ADT^A03 出院：EVN-1=A03、PV1-45 离院时间/PV1-36 离院方式 | 设计§3.5 | 9 |
| 4 | `hl7_oru_r01_results` | 正 | TCP/IPv4 | ORU^R01：OBR + 多 OBX 序号/值类型/线上顺序 | 设计§3.5 | 9 |
| 5 | `hl7_siu_s12_appointment` | 正 | TCP/IPv4 | SIU^S12：SCH/AIS 段（v2.5 字段号：SCH-4 原因/SCH-10 开始/SCH-11 结束、AIS-3 USI——D-1 修正） | v2.5 规范 Chapter 10+设计§3.5 | 9 |
| 6 | `hl7_ack_success_association` | 正 | TCP/IPv4 | ACK `AA` 关联焦点：MSA-2 same_as、ACK MSH-10 distinct | 设计§5.1/§5.2 | 9 |
| 7 | `hl7_nak_error_segment` | 正 | TCP/IPv4 | NAK `AE`+ERR 段：合法协议行为正例 | 设计§3.5/§5.1 | 9 |
| 8 | `hl7_ack_ar_reject` | 正 | TCP/IPv4 | NAK `AR` 拒绝确认 + ERR 段（NAK 第二形态） | 设计§3.8/§5.1 | 9 |
| 9 | `hl7_mllp_frame_bytes` | 正 | TCP/IPv4 | MLLP 起止块逐字节 + 段 CR≠终止 CR + 帧长公式独立断言（D-7） | MLLP+设计§3.1/§3.6 | 9 |
| 10 | `hl7_component_subcomponent` | 正 | TCP/IPv4 | 组件 `^`（PID-5 XPN）与子组件 `&`（OBR-2 EI） | 设计§3.2 | 9 |
| 11 | `hl7_field_repetition` | 正 | TCP/IPv4 | 重复 `~`（PID-3 多标识） | 设计§3.2 | 9 |
| 12 | `hl7_pid3_cx_components` | 正 | TCP/IPv4 | PID-3 CX 五组件结构显式断言 | v2.5 规范 PID-3 CX+设计§3.5 | 9 |
| 13 | `hl7_escape_f` | 正 | TCP/IPv4 | 转义 `\F\`：字面字段分隔符不解析为字段 | 设计§3.3 | 9 |
| 14 | `hl7_escape_s` | 正 | TCP/IPv4 | 转义 `\S\`：字面组件分隔符 | 设计§3.3 | 9 |
| 15 | `hl7_escape_r` | 正 | TCP/IPv4 | 转义 `\R\`：字面重复分隔符 | 设计§3.3 | 9 |
| 16 | `hl7_escape_e` | 正 | TCP/IPv4 | 转义 `\E\`：字面转义字符 | 设计§3.3 | 9 |
| 17 | `hl7_escape_t` | 正 | TCP/IPv4 | 转义 `\T\`：字面子组件分隔符 | 设计§3.3 | 9 |
| 18 | `hl7_escape_h_n` | 正 | TCP/IPv4 | 转义 `\H\`/`\N\`：高亮开始/恢复成对 | 设计§3.3 | 9 |
| 19 | `hl7_escape_hex` | 正 | TCP/IPv4 | 转义 `\Xdd\`：单十六进制字节（`\X0D\`=CR 字面） | 设计§3.3 | 9 |
| 20 | `hl7_escape_hex_multibyte` | 正 | TCP/IPv4 | 转义 `\Xdddd\`：多字节变体（`\X0D0A\` 两字节） | 设计§3.3（\Xdd.. 语法） | 9 |
| 21 | `hl7_multi_transaction_long_connection` | 正 | TCP/IPv4 | 同连接 3 笔事务：MSH-10 distinct、MSA-2 各自配对 | 设计§5.1/§5.4 | 13 |
| 22 | `hl7_tcp_mss_reassembly` | 正 | TCP/IPv4 | 长消息跨 MSS 分段 + 第二帧粘连；重组字段落最后一个 TCP segment（C-15） | 设计§2/§8 | 10 |
| 23 | `hl7_ipv6_transport` | 正 | TCP/IPv6 | IPv6/TCP/2575 基线：ipv6.nxt=6、offset 74 | 设计§2/§8 | 9 |
| 24 | `hl7_ipv6_multi_transaction` | 正 | TCP/IPv6 | IPv6 上多事务两笔（v6 地址族 × 多事务交叉） | 设计§2/§5.1 | 11 |
| 25 | `hl7_multi_session_isolation` | 正 | TCP/IPv4 | 多会话双四元组：控制 ID/PID/时间策略隔离 | 设计§5.4 | 18 |
| 26 | `hl7_concurrent_sessions` | 正 | TCP/IPv4 | 并发会话交错回放（C-1 翻案纳入） | 设计§5.4 v2.1（cwmp⑦/doh #27 同判例） | 18 |
| 27 | `hl7_port_nondefault` | 正 | TCP/IPv4 | 非默认端口 2675（C-3；tshark 非 2575 不解码须 `-d` DecodeAs） | 设计§2 v2.1（实测 D-4） | 9 |
| 28 | `hl7_version_profiles` | 正 | TCP/IPv4 | MSH-12 版本值域 2.5/2.8 + MSH-11 P/T | 设计§3.4/§3.8 | 11 |
| 29 | `hl7_processing_id_d` | 正 | TCP/IPv4 | MSH-11=`D`（Table 0103：D=Debugging 调试——N-2 官方语义修正） | v2.5 规范 Table 0103 | 9 |
| 30 | `hl7_ack_code_domain` | 正 | TCP/IPv4 | MSA-1 值域 AA/AE/AR（值域扫描例，N-5 备注保留合并） | 设计§3.8 | 13 |
| 31 | `hl7_ack_disabled` | 正 | TCP/IPv4 | `ack_mode=null`：无 ACK 帧 | 设计§5.2 | 8 |
| 32 | `hl7_ack_override_null` | 正 | TCP/IPv4 | 消息级 `ack=null` 覆盖会话级 auto（覆盖分支） | 设计§5.2/§6 ack 键 | 12 |
| 33 | `hl7_s2c_receiver_role` | 正 | TCP/IPv4 | s2c 发起方向/role=receiver：生成器侧为接收方（C-6） | 设计§6 role/§5.2② | 9 |
| 34 | `hl7_ack_rule_separators` | 正 | TCP/IPv4 | ACK 派生规则③：MSH-1/MSH-2 与请求相同 | 设计§5.2③ | 9 |
| 35 | `hl7_ack_rule_swap` | 正 | TCP/IPv4 | ACK 派生规则④：MSH-3/4↔MSH-5/6 收发对调（四槽 diff 断言） | 设计§5.2④ | 9 |
| 36 | `hl7_ack_rule_new_ts` | 正 | TCP/IPv4 | ACK 派生规则⑤：MSH-7 为新运行期时间戳（nonzero、定宽 14 位 UTC） | 设计§5.2⑤/D-5 渲染规则 | 9 |
| 37 | `hl7_ack_trigger_oru` | 正 | TCP/IPv4 | ACK 派生规则⑥ per-type：ACK^R01（触发事件回带） | 设计§5.2⑥ | 9 |
| 38 | `hl7_ack_minimal_form` | 正 | TCP/IPv4 | ACK 最小形态：MSH+MSA 两段（段结构下界） | 设计§3.5/§5.2 | 9 |
| 39 | `hl7_msh_app_fac_fields` | 正 | TCP/IPv4 | MSH-3..6 四槽请求侧 presence（发送/接收应用与机构） | 设计§3.4 | 9 |
| 40 | `hl7_msh7_ts_format` | 正 | TCP/IPv4 | MSH-7 定宽 TS 格式：UTC YYYYMMDDHHMMSS 14 位（D-5 渲染规则） | 设计§3.4/D-5 | 9 |
| 41 | `hl7_msh9_structure` | 正 | TCP/IPv4 | MSH-9 三组件结构：code^event^structure 显式断言 | 设计§3.4 | 9 |
| 42 | `hl7_msh8_populated` | 正 | TCP/IPv4 | MSH-8 安全字段携带值（ST≤40 非空形态） | 设计§3.4 | 9 |
| 43 | `hl7_msh8_empty_slot` | 正 | TCP/IPv4 | 空槽渲染：MSH-8 留空 + PID 中段空槽不折叠（C-8） | 设计§3.8/§5.2 D-5 尾随策略 | 9 |
| 44 | `hl7_msh15_16_empty` | 正 | TCP/IPv4 | MSH-15/16 留空：尾随空槽截至最后非空字段（C-9/D-5 策略） | 设计§3.4/D-5 | 9 |
| 45 | `hl7_evn2_time_format` | 正 | TCP/IPv4 | EVN-2 事件时间定宽 14 位（同 MSH-7 渲染规则） | 设计§3.5/D-5 | 9 |
| 46 | `hl7_set_id_fields` | 正 | TCP/IPv4 | 集合 ID 字段：PID-1/PV1-1 恒 `1` | v2.5 规范+设计§3.5 | 9 |
| 47 | `hl7_z_segment_passthrough` | 正 | TCP/IPv4 | Z 段显式配置透传（C-14；D-3 矛盾解决后） | 设计§1 v2.1/§6 Validate | 9 |
| 48 | `hl7_custom_field_separator` | 正 | TCP/IPv4 | 自定义 `field_separator`（如 `#`）正文随声明 | 设计§6 | 9 |
| 49 | `hl7_custom_encoding_chars` | 正 | TCP/IPv4 | 自定义 `encoding_chars`（如 `@~\!`）正文随声明 | 设计§6 | 9 |
| 50 | `hl7_pv1_class_outpatient` | 正 | TCP/IPv4 | PV1-2=`O` 门诊（值域第二值） | v2.5 规范 PV1-2+设计§3.5 | 9 |
| 51 | `hl7_pv1_class_emergency` | 正 | TCP/IPv4 | PV1-2=`E` 急诊（值域第三值） | v2.5 规范 PV1-2 | 9 |
| 52 | `hl7_obx_valuetype_ce` | 正 | TCP/IPv4 | OBX-2=`CE` 值类型（第三形态：OBX-5 为编码值） | v2.5 规范 OBX-2 | 9 |
| 53 | `hl7_result_status_pending` | 正 | TCP/IPv4 | 结果状态处理中：OBX-11=`P`、OBR-25=`P` | v2.5 规范+设计§3.5 | 9 |
| 54 | `hl7_result_status_corrected` | 正 | TCP/IPv4 | 结果状态更正：OBX-11=`C`、OBR-25=`C` | v2.5 规范 | 9 |
| 55 | `hl7_boundary_msh9_len15` | 正 | TCP/IPv4 | MSH-9 恰 15 字符上界（显式边界断言） | 设计§8（需求 v1.3 恰等上界） | 9 |
| 56 | `hl7_boundary_msh10_msa2_len20` | 正 | TCP/IPv4 | MSH-10 恰 20 + ACK MSA-2 恰 20（同值双断言） | 设计§8 | 9 |
| 57 | `hl7_boundary_msh12_len60` | 正 | TCP/IPv4 | MSH-12 恰 60 字符上界 | 设计§8 | 9 |
| 58 | `hl7_boundary_msh7_ts_max` | 正 | TCP/IPv4 | MSH-7 语法最长合法形态 24 字符（textual 上界 26 的语法实现，D-5 注） | 设计§8 v2.1 注 | 9 |
| 59 | `hl7_msa3_text` | 正 | TCP/IPv4 | MSA-3 文本消息可选携带 | v2.5 规范 MSA-3+设计§3.5 | 9 |
| 60 | `hl7_err_fields` | 正 | TCP/IPv4 | ERR 段字段焦点：ERR-2 错误位置/ERR-3 码/ERR-4 严重级/ERR-5 本地码（N-3 修正） | v2.5 规范 ERR+设计§3.5 | 9 |
| 61 | `hl7_mllp_multi_frame_burst` | 正 | TCP/IPv4 | 3 帧粘连同段（多帧/段扩展形态，均 ack=null） | 设计§2/§8 | 8 |
| 62 | `hl7_control_id_inc_strategy` | 正 | TCP/IPv4 | control_id inc 策略跨消息递增显式断言 | 设计§6 策略 | 13 |
| 63 | `hl7_neg_framing_sob_missing` | 负 | — | 载荷缺起始块 `0x0b`（直接以 `MSH|` 开头） | MLLP | — |
| 64 | `hl7_neg_framing_eob_missing` | 负 | — | 帧未闭合：流结束无 `0x1c 0x0d`（截断帧） | MLLP | — |
| 65 | `hl7_neg_framing_eob_malformed` | 负 | — | 结束块形态错：`0x1c` 后无 `0x0d` | MLLP | — |
| 66 | `hl7_neg_framing_control_byte` | 负 | — | 正文出现未转义 `0x1c`（提前闭合 EOB；同族备选 `0x0b`） | MLLP+设计§3.3 | — |
| 67 | `hl7_neg_segment_first_not_msh` | 负 | — | 首段非 MSH（如 EVN 开头） | 设计§3.2 | — |
| 68 | `hl7_neg_segment_no_cr` | 负 | — | 段未以 CR 结尾 | 设计§3.2 | — |
| 69 | `hl7_neg_segment_after_eob` | 负 | — | `0x1c 0x0d` 之后追加段 | 设计§3.1 | — |
| 70 | `hl7_neg_segment_name_invalid` | 负 | — | 段名非法（非 3 字符/未知段名） | 设计§3.2 | — |
| 71 | `hl7_neg_msh1_invalid` | 负 | — | MSH-1 缺失或长度≠1 | 设计§3.2 | — |
| 72 | `hl7_neg_msh2_invalid` | 负 | — | MSH-2 长度≠4 | 设计§3.2 | — |
| 73 | `hl7_neg_separator_mismatch` | 负 | — | 正文实际分隔符与 MSH-2 声明不一致 | 设计§3.2 | — |
| 74 | `hl7_neg_escape_invalid` | 负 | — | 非法转义序列（`\X` 十六进制不成对） | 设计§3.3 | — |
| 75 | `hl7_neg_msh9_missing` | 负 | — | MSH-9 缺失 | 设计§3.4 | — |
| 76 | `hl7_neg_msh10_missing` | 负 | — | MSH-10 缺失 | 设计§3.4 | — |
| 77 | `hl7_neg_msh11_missing` | 负 | — | MSH-11 缺失 | 设计§3.4 | — |
| 78 | `hl7_neg_msh12_missing` | 负 | — | MSH-12 缺失 | 设计§3.4 | — |
| 79 | `hl7_neg_msh9_domain` | 负 | — | MSH-9 消息代码/触发事件不在值域（如 `XYZ^Q99^XYZ_Q99`） | 设计§3.4 | — |
| 80 | `hl7_neg_ack_msa2_mismatch` | 负 | — | 派生 ACK 的 MSA-2 ≠ 请求 MSH-10 | 设计§5.1 | — |
| 81 | `hl7_neg_ack_no_msh9` | 负 | — | ACK 缺 MSH-9=ACK | 设计§5.2⑥ | — |
| 82 | `hl7_neg_ack_no_msa` | 负 | — | ACK 缺 MSA 段 | 设计§3.5 | — |
| 83 | `hl7_neg_ack_code_invalid` | 负 | — | MSA-1 确认码非 AA/AE/AR（如 `XX`） | 设计§3.8 | — |
| 84 | `hl7_neg_carrier_udp` | 负 | — | UDP 载体（层链 `[{"udp":{}},{"hl7":{}}]`） | 设计§2 | — |
| 85 | `hl7_neg_carrier_no_tcp` | 负 | — | 层链缺 tcp（hl7 直连 ip） | 设计§2 | — |
| 86 | `hl7_neg_port_invalid` | 负 | — | 非法端口（0/65536） | 设计§2 | — |
| 87 | `hl7_neg_len_msh9` | 负 | — | MSH-9 >15 字符 | 设计§8 | — |
| 88 | `hl7_neg_len_msh10` | 负 | — | MSH-10 >20 字符 | 设计§8 | — |
| 89 | `hl7_neg_len_msh12` | 负 | — | MSH-12 >60 字符 | 设计§8 | — |
| 90 | `hl7_neg_len_msh7` | 负 | — | MSH-7 >26 字符（textual 上界） | 设计§8 | — |
| 91 | `hl7_neg_len_msa2` | 负 | — | MSA-2 >20 字符 | 设计§8 | — |
| 92 | `hl7_neg_event_mismatch` | 负 | — | EVN-1 与 MSH-9 触发事件不一致（MSH-9=ADT^A01 + `EVN|A02|`，C-13 失败用例先行） | 设计§3.5 | — |
| 93 | `hl7_neg_address_family_mixed` | 负 | — | 地址族混合：`[ipv6]` 层配 IPv4 字面量（C-11） | 设计§6 | — |
| 94 | `hl7_neg_required_segment_missing` | 负 | — | ADT^A01 缺必需业务段 PID（D-6：按 MSH-9 结构声明必需段集） | 设计§6 Validate v2.1 | — |
| 95 | `hl7_neg_z_segment_unconfigured` | 负 | — | 未显式声明的 Z 段（段表白名单外且无 allow 标志，D-3 联动） | 设计§1 v2.1/§6 | — |

## 3. 线上编码与偏移断言

层链 `[tcp, hl7]`，无 VLAN/IP options/TCP options 的数据承载段，MLLP 帧首字节（应用层 payload 第 1 字节 = `0x0b`）起点：IPv4 offset 54、IPv6 offset 74。SYN/SYN-ACK 段可带 TCP options，固定偏移只对数据承载段成立。断言分层：

1. **MLLP 帧字节（frames hex 权威断言）**：数据帧 payload 首字节 `0B`、末两字节 `1C 0D`；`hl7.llp.sob`/`hl7.llp.eob` 偏好门控不作字段断言。段内 CR（`0D`）与 MLLP 终止 CR（`1C` 后的 `0D`）分开识别。
2. **段名/段序列与消息类型**：段存在性/序列一律 frames hex（段 ID+`|`：`4D 53 48 7C`=`MSH|`、`45 56 4E 7C`=`EVN|`、`50 49 44 7C`=`PID|`、`50 56 31 7C`=`PV1|`、`53 43 48 7C`=`SCH|`、`41 49 53 7C`=`AIS|`、`4F 42 52 7C`=`OBR|`、`4F 42 58 7C`=`OBX|`、`4D 53 41 7C`=`MSA|`、`45 52 52 7C`=`ERR|`、`5A 42 45 7C`=`ZBE|`（Z 段例））；`hl7.segment`/`hl7.field` 仅人工核对辅助。MSH-9 优先 `hl7.message.type`/`hl7.event.type`，后备帧字节（`41 44 54 5E 41 30 31`=`ADT^A01`、`41 43 4B 5E 52 30 31`=`ACK^R01` 等）。MSA-2 关联 `same_as_packet` 指向请求帧 MSH-10 槽位字节。
3. **MSH 分隔符**：帧应用起点起 `0B 4D 53 48 7C 5E 7E 5C 26 7C` = `VT MSH|^~\&|`——MSH-1/MSH-2 字节级断言；自定义分隔符用例按声明替换对应字节。
4. **TCP 重组（C-15 钉死）**：segment 边界≠MLLP 帧边界。跨段消息按 `tcp.stream` 重组后断言完整帧；**重组 PDU 的 `hl7.*` 字段落在最后一个 TCP segment**（实测：前段字段空、末段有字段）；关闭重组（desegment off）时用逐段 frames hex 断言跨段切分位置——双口径并存，字段断言以重组口径为准。
5. **多会话/并发包号规则**：多会话展开整块回放（第二会话 SYN 包号 = 前会话总包数 + 1）；`concurrent: true` 交错回放；跨会话关联断言用 `tcp.stream` 区分。

## 4. 正例逐项断言契约

约定 packet_count 见 §2 表；以下 fields/frames 为最低断言集，实现期可增不可减。默认 fixture 地址 `192.0.2.68 → 198.51.100.68`、`tcp.dstport=2575`；请求帧应用起点起 `0B 4D 53 48 7C 5E 7E 5C 26 7C`；各例标注的 fixture 定值以帧字节 ASCII/hex 精确断言。

1. **`hl7_adt_a01_ipv4`**（TCP，packet_count=9）：请求帧（包 4）：MSH-9 段内 `41 44 54 5E 41 30 31 5E 41 44 54 5F 41 30 31`（`ADT^A01^ADT_A01`）；段序列 hex `4D 53 48 7C`/`45 56 4E 7C`/`50 49 44 7C`/`50 56 31 7C` 按先后；EVN-1=`A01`（`45 56 4E 7C 41 30 31 7C`）与 MSH-9 触发事件一致；MSH-7/EVN-2 槽 nonzero；PID-3 存在、PID-7/PID-8 槽存在（`7C 4D 7C`=`|M|`）；PV1-2=`I`。ACK 帧（包 5）：`41 43 4B 5E 41 30 31`（`ACK^A01`）、`4D 53 41 7C 41 41 7C`（`MSA|AA|`）、MSA-2 same_as 包 4 MSH-10。
2. **`hl7_adt_a02_transfer`**（TCP，packet_count=9）：EVN-1=`A02`（`45 56 4E 7C 41 30 32 7C`）、MSH-9 `ADT^A02`；PV1-3 组件 `WARD^2^BED9` hex 存在；ACK 关联同规则。
3. **`hl7_adt_a03_discharge`**（TCP，packet_count=9）：EVN-1=`A03`、MSH-9 `ADT^A03`；PV1 段含离院时间槽（PV1-45）与离院方式槽（PV1-36）hex nonzero；ACK 关联同规则。
4. **`hl7_oru_r01_results`**（TCP，packet_count=9）：MSH-9 `4F 52 55 5E 52 30 31`；`4F 42 52 7C` 与 ≥2 个 `4F 42 58 7C`；OBX-1 递增（`4F 42 58 7C 31 7C`/`4F 42 58 7C 32 7C`）；OBX-2 `NM`/`ST`、OBX-3 三组件、OBX-5/OBX-6 槽、OBX-11=`F`（`7C 46 0D`）；OBR-4 三组件、OBR-25=`F`；ACK 关联。
5. **`hl7_siu_s12_appointment`**（TCP，packet_count=9）：MSH-9 `53 49 55 5E 53 31 32`；`53 43 48 7C`/`41 49 53 7C`（无 EVN/PID/PV1）；SCH-1 EI 子组件 `APPT-9001&HIS`（`26`）；**SCH-4 预约原因 `SURGERY` 槽存在（第 4 字段）**、**SCH-10 开始时间槽 nonzero（第 10 字段）**、SCH-11 结束时间槽 nonzero；**AIS-3 USI 三组件 `4D 52 49 5E`（`MRI^`，第 3 字段）**；ACK 关联。
6. **`hl7_ack_success_association`**（TCP，packet_count=9）：ACK 帧 MSH-9 `ACK^A01`、`4D 53 41 7C 41 41 7C`、MSA-2 `same_as_packet` 请求 MSH-10、ACK MSH-10 `distinct_values`；MSH-3/4=请求 MSH-5/6 hex 存在性；ACK MSH-7 槽 nonzero；MSH-11/12 同请求（`7C 50 7C 32 2E 38`）。
7. **`hl7_nak_error_segment`**（TCP，packet_count=9）：配置 `ack={"code":"AE","err_segments":[...]}`；ACK `4D 53 41 7C 41 45 7C`、`45 52 52 7C`（`ERR|`）存在、ERR-4 严重级槽、ERR-5 本地应用错误码与文本槽（N-3 修正：本地码 CWE，非 HL70357 域码）；MSA-2 仍 same_as 请求 MSH-10。
8. **`hl7_ack_ar_reject`**（TCP，packet_count=9）：配置 `ack={"code":"AR","err_segments":[...]}`；ACK `4D 53 41 7C 41 52 7C`、ERR 段存在；MSA-2 关联同规则——AR=应用拒绝语义，正例。
9. **`hl7_mllp_frame_bytes`**（TCP，packet_count=9）：固定策略值使帧长确定：payload 首字节 `0B`（offset 54）、末两字节 `1C 0D`；EVN 段尾 `0D` 后紧跟 `50 49 44`（段 CR 是段终止符）；末段 PV1 尾 `0D 1C 0D`；**显式断言帧总长 = §3.6 公式值 `1+Σ(len(seg)+1)+2`（D-7 独立断言）**；ACK 帧同样断言。
10. **`hl7_component_subcomponent`**（TCP，packet_count=9）：PID-5 `DOE^JOHN^A`（`5E`）hex 存在；ORU 消息内 OBR-2 `ORD-1001&HIS`（`26`）；与 MSH-2 声明字符一致。
11. **`hl7_field_repetition`**（TCP，packet_count=9）：PID-3 `PAT1^^^HOSP^MR~PAT2^^^HOSP^MR2`（`7E`）hex 存在；与 MSH-2 第 2 字符一致；ACK 照常。
12. **`hl7_pid3_cx_components`**（TCP，packet_count=9）：PID-3 槽内 `ID^^^HOSP^MR` 五组件形态（4 个 `5E`）hex 存在——CX 组件结构（ID 号^检查位^检查位方案^授权机构^标识类型——Assigning Authority 在 CX.4，v2.5；与 #1/#11 fixture 一致）；ACK 关联。
13. **`hl7_escape_f`**（TCP，packet_count=9）：OBX-5（OBX-2=`ST`）携带 `\F\`（`5C 46 5C`）hex；原样落线、字段数不变（`\F\` 不产生真实 `7C`）。
14. **`hl7_escape_s`**（TCP，packet_count=9）：OBX-5 携带 `\S\`（`5C 53 5C`）；原样落线、不产生真实 `5E`、组件数不变。
15. **`hl7_escape_r`**（TCP，packet_count=9）：OBX-5 携带 `\R\`（`5C 52 5C`）；原样落线、不产生真实 `7E`。
16. **`hl7_escape_e`**（TCP，packet_count=9）：OBX-5 携带 `\E\`（`5C 45 5C`）；原样落线、不产生真实 `5C`、不启动新转义解析。
17. **`hl7_escape_t`**（TCP，packet_count=9）：OBX-5 携带 `\T\`（`5C 54 5C`）；原样落线、不产生真实 `26`。
18. **`hl7_escape_h_n`**（TCP，packet_count=9）：OBX-5 携带 `\H\`文本`\N\`（`5C 48 5C`/`5C 4E 5C`）成对 hex；原样落线、不改结构。
19. **`hl7_escape_hex`**（TCP，packet_count=9）：OBX-5 携带 `\X0D\`（`5C 58 30 44 5C`）hex；原样落线为 5 字节转义文本、**不**产生真实 `0D` 段终止/控制字节、段数不变。
20. **`hl7_escape_hex_multibyte`**（TCP，packet_count=9）：OBX-5 携带 `\X0D0A\`（4 个十六进制数字=2 字节）hex；原样落线、成对合法、不产生真实 CR LF 控制效果。
21. **`hl7_multi_transaction_long_connection`**（TCP，packet_count=13）：单 `tcp.stream`：ADT^A01→ACK、ORU^R01→ACK、SIU^S12→ACK 按序；3 请求 MSH-10 `distinct_values` 恰 3 值、每笔 MSA-2 same_as 对应请求；末 ACK（包 9）后才挥手。
22. **`hl7_tcp_mss_reassembly`**（TCP，packet_count=10）：小 MSS 使长 ORU 跨 2 段，短消息（ack=null）粘连同段；断言：按 `tcp.stream` 重组——重组 PDU 的 `hl7.*` 字段落在**最后一个 TCP segment**（实测 pkt 前段空/末段有字段，C-15 钉死）；两个 `0B` 起始、两个 `1C 0D` 终止（frames hex）；消息数=2≠segment 数；**关闭重组的逐段 hex 口径**（desegment off 时按段内字节断言跨段边界切分位置）双口径写明。
23. **`hl7_ipv6_transport`**（TCP，packet_count=9）：`2001:db8::68 → 2001:db8:bb::68`；`ipv6.nxt=6`、offset 74 起 `0B 4D 53 48 7C ...`、MLLP/HL7 字节同 v4；ACK 关联照常。
24. **`hl7_ipv6_multi_transaction`**（TCP，packet_count=11）：IPv6 fixture 同连接两笔 ADT^A01→ACK、ORU^R01→ACK；MSH-10 distinct、MSA-2 各配对；offset 74 断言。
25. **`hl7_multi_session_isolation`**（TCP，packet_count=18）：会话 1（42680）ADT^A01→ACK、会话 2（42681）ORU^R01→ACK 起点=包 10；`tcp.stream` distinct、会话间 MSH-10/PID-3 `distinct_values`、第二会话 SYN=包 10、MSA-2 配对不跨会话。
26. **`hl7_concurrent_sessions`**（TCP，packet_count=18）：`concurrent: true` 双会话交错回放（42680/42681）；断言两 `tcp.stream` 交错但各会话事务配对完整、MSH-10/PID-3 互不串用、MSA-2 匹配本会话请求——MLLP 单连接串行确认不约束生成器级多连接交错。
27. **`hl7_port_nondefault`**（TCP，packet_count=9）：`tcp.dstport=2675`；**断言带 `-d tcp.port==2675,hl7` DecodeAs 提示**（实测非 2575 载荷 tshark 不按 hl7 解码、启发式不触发——D-4），字段断言同 #1 或全 frames hex；planner 不得静默改写端口。
28. **`hl7_version_profiles`**（TCP，packet_count=11）：同连接两笔：`7C 50 7C 32 2E 35`（`|P|2.5`）与 `7C 54 7C 32 2E 38`（`|T|2.8`）联合 hex；ACK 各自关联。
29. **`hl7_processing_id_d`**（TCP，packet_count=9）：单笔 MSH-11=`D` 消息；断言 MSH 段内处理 ID 槽 `7C 44 7C`（`|D|`）存在——值域 P/T/D 第三值；ACK 照常。
30. **`hl7_ack_code_domain`**（TCP，packet_count=13）：3 笔消息 ACK 分别 AA/AE/AR：`4D 53 41 7C 41 41 7C`/`4D 53 41 7C 41 45 7C`/`4D 53 41 7C 41 52 7C` 依次；MSA-2 各自配对。
31. **`hl7_ack_disabled`**（TCP，packet_count=8）：单消息无 ACK；连接内仅 1 业务帧（包 4 后无反向数据包）；MLLP/MSH 断言照常。
32. **`hl7_ack_override_null`**（TCP，packet_count=12）：会话 `ack_mode=auto`，3 笔消息中第 2 笔事件级 `ack=null`：断言第 1/3 笔有 ACK（MSA-2 各配对）、第 2 笔后无反向帧（包序断言）——消息级覆盖优先于会话级。
33. **`hl7_s2c_receiver_role`**（TCP，packet_count=9）：会话 `role=receiver`、事件 `direction=s2c`：业务消息由对端发向本端（生成器渲染 s2c 方向帧），ACK 方向反转回 c2s；断言帧方向（`tcp.src/dst` 对调）与 MSA-2 关联照常——双向覆盖闭合。
34. **`hl7_ack_rule_separators`**（TCP，packet_count=9）：ACK 帧 offset 起同前缀 `0B 4D 53 48 7C 5E 7E 5C 26 7C`（`VT MSH|^~\&|`）——派生 ACK 分隔符与请求逐字节一致。
35. **`hl7_ack_rule_swap`**（TCP，packet_count=9）：请求 MSH-3=`HIS`/MSH-4=`GH`/MSH-5=`LIS`/MSH-6=`GH`（fixture 固定）；ACK 帧断言 MSH-3 槽=`LIS`、MSH-5 槽=`HIS`（`4C 49 53`/`48 49 53` hex 定位）——对调规则逐槽验证。
36. **`hl7_ack_rule_new_ts`**（TCP，packet_count=9）：ACK 帧 MSH-7 槽 nonzero 且为 `YYYYMMDDHHMMSS` 定宽 14 位数字（hex 数位断言）——epoch→UTC 渲染规则可观察。
37. **`hl7_ack_trigger_oru`**（TCP，packet_count=9）：请求 ORU^R01 → ACK 帧 MSH-9 `41 43 4B 5E 52 30 31 5E 41 43 4B`（`ACK^R01^ACK`）——非 A01 请求的派生形态。
38. **`hl7_ack_minimal_form`**（TCP，packet_count=9）：ACK 帧仅 `4D 53 48 7C`...`4D 53 41 7C`（MSH+MSA，无 EVN/PID 等）——派生 ACK 的段结构下界合法形态。
39. **`hl7_msh_app_fac_fields`**（TCP，packet_count=9）：fixture 固定 `HIS`/`GH`/`LIS`/`GH`；断言 MSH 段内 `7C 48 49 53 7C`（`|HIS|`）与 `7C 4C 49 53 7C`（`|LIS|`）等四槽 hex 依序存在。
40. **`hl7_msh7_ts_format`**（TCP，packet_count=9）：timestamp 策略 epoch→UTC 渲染；断言 MSH-7 槽恰 14 位数字 hex（定宽、无时区后缀的缺省形态）。
41. **`hl7_msh9_structure`**（TCP，packet_count=9）：`41 44 54 5E 41 30 31 5E 41 44 54 5F 41 30 31`（`ADT^A01^ADT_A01`）完整 15 字符三组件——第三组件=消息结构声明（`<code>_<event>`）。
42. **`hl7_msh8_populated`**（TCP，packet_count=9）：fixture `MSH-8=CONF-01`；断言 MSH-8 槽 `7C 43 4F 4E 46 2D 30 31 7C` hex——非空安全字段落线。
43. **`hl7_msh8_empty_slot`**（TCP，packet_count=9）：断言 MSH 段 `7C 7C`（`||`）空槽形态、PID 段中段空槽（PID-2 空 `50 49 44 7C 31 7C 7C`）——空可选字段以空槽表示、不折叠错位。
44. **`hl7_msh15_16_empty`**（TCP，packet_count=9）：断言 MSH 段终止 CR 紧随 MSH-12 值（无尾随 `7C 7C` 空槽——D-5 策略：尾随空槽截至最后非空字段）；帧长公式值随策略可计算。
45. **`hl7_evn2_time_format`**（TCP，packet_count=9）：EVN-2 槽恰 14 位数字 hex（`45 56 4E 7C 41 30 31 7C` 后非空定宽槽）。
46. **`hl7_set_id_fields`**（TCP，packet_count=9）：`50 49 44 7C 31 7C`（`PID|1|`）、`50 56 31 7C 31 7C`（`PV1|1|`）hex——集合 ID 断言。
47. **`hl7_z_segment_passthrough`**（TCP，packet_count=9）：fixture 显式声明 Z 段（如 `ZBE|custom|data`）；断言帧内 `5A 42 45 7C`（`ZBE|`）原样落线、段 CR 正常、ACK 照常——显式声明的 Z 段放行。
48. **`hl7_custom_field_separator`**（TCP，packet_count=9）：fixture `field_separator="#"`；断言帧内段/字段分隔字节为 `23`、MSH-1 槽位字符同步为 `#`（`4D 53 48 23`）——正文与声明一致。
49. **`hl7_custom_encoding_chars`**（TCP，packet_count=9）：fixture `encoding_chars="@~\!"`；断言组件分隔用 `40`（`@`）、子组件用 `21`（`!`）、MSH-2 槽=声明 4 字符——编码字符族随配置。
50. **`hl7_pv1_class_outpatient`**（TCP，packet_count=9）：PV1 段 `50 56 31 7C 31 7C 4F 7C`（`PV1|1|O|`）——门诊类别。
51. **`hl7_pv1_class_emergency`**（TCP，packet_count=9）：`50 56 31 7C 31 7C 45 7C`（`PV1|1|E|`）——急诊类别。
52. **`hl7_obx_valuetype_ce`**（TCP，packet_count=9）：OBX `7C 43 45 7C`（`|CE|`）、OBX-5 为 `码^文本^体系` 三组件——CE 值类型下观察值的组件形态。
53. **`hl7_result_status_pending`**（TCP，packet_count=9）：OBX 段尾 `7C 50 0D`、OBR 段尾 `7C 50 0D`（`|P`+CR）——P=处理中（final 之外的合法状态）。
54. **`hl7_result_status_corrected`**（TCP，packet_count=9）：`7C 43 0D` 双段——C=更正形态。
55. **`hl7_boundary_msh9_len15`**（TCP，packet_count=9）：fixture `ADT^A01^ADT_A01` 恰 15 字符；断言整槽 15 字节 hex 且被接受（恰等上界合法）。
56. **`hl7_boundary_msh10_msa2_len20`**（TCP，packet_count=9）：fixture MSH-10 恰 20 字符（`CID20260901083045AAB`）；断言请求 MSH-10 槽 20 字节、ACK MSA-2 槽 same_as 且同 20 字节——两端恰等上界。
57. **`hl7_boundary_msh12_len60`**（TCP，packet_count=9）：fixture 显式 60 字符版本 ID；断言 MSH-12 槽 60 字节被接受、ACK 同版本。
58. **`hl7_boundary_msh7_ts_max`**（TCP，packet_count=9）：fixture 显式 TS `20260901083045.1234+0800`（14+1+4+5=24，TS 语法最长合法形态）；断言被接受且原样落线——设计 §8 注明：26 为数据字典 textual 上界、24 为语法上界，validator 按 textual 长度检查、不构造语法非法串。
59. **`hl7_msa3_text`**（TCP，packet_count=9）：ACK 配置附 MSA-3 文本（如 `OK`）；断言 `4D 53 41 7C 41 41 7C ... 7C 4F 4B`（MSA-3 槽）存在——可选第三字段携带形态。
60. **`hl7_err_fields`**（TCP，packet_count=9）：NAK ACK 的 ERR 段：ERR-2 错误位置槽（ERL 形态 `PID^1^1^1`）、ERR-3 HL7 错误码槽、ERR-4=`E`（`7C 45 7C`）、ERR-5 本地应用错误码槽（CWE）——按 v2.5 字段号断言（ERR-1=ELD 复合、错误位置在 ERR-2）。
61. **`hl7_mllp_multi_frame_burst`**（TCP，packet_count=8）：3 条短消息（ack=null）粘连同一 TCP segment 一次到达；断言 3 个 `0B` 起始与 3 个 `1C 0D` 终止、段边界按 MLLP 块切分（不按 segment 数=1 误判消息数=1）。
62. **`hl7_control_id_inc_strategy`**（TCP，packet_count=13）：fixture `control_id={"strategy":"inc","range":[1000,9999],"step":1}`；3 笔事务 MSH-10 依次为 `1000`/`1001`/`1002`（hex 定值断言）——策略可观察且会话内唯一。

**正例总则**：每条实现后至少含 `packet_count`/`min_packets`、载体与方向断言、`has_payload`（`0B`/`1C 0D` 帧字节 + `hl7.*` 实测字段）、可观察 fields、稳定 frames hex；动态值只用关联/存在性断言。合法协议事件（AA/AE/AR、`ack_mode=null`、空槽、恰等上界、粘连多帧、Z 段透传、s2c 方向）均为正例形态；只有配置、线格式、段/字段结构、必需字段、确认关联、载体端口、长度上界错误进入负例（§5）。

## 5. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；执行期 `expect` 严格只有 `expect_error`、`error_contains`。**逐故障输入原子拆分：一行一例，钉死该行注入的单一 `wire_fault`/配置变异**（C-2）；主锚词钉死（N-4），与设计 §7 表一一对应：

| # | ID | `wire_fault` 注入口 | 故障输入（单一注入） | 主锚词（备选） |
|---:|---|---|---|---|
| 63 | `hl7_neg_framing_sob_missing` | `framing_sob_missing` | 载荷缺起始块 `0x0b`（直接以 `MSH|` 开头） | `mllp`（framing） |
| 64 | `hl7_neg_framing_eob_missing` | `framing_eob_missing` | 帧未闭合：流结束无 `0x1c 0x0d`（截断帧） | `mllp`（framing） |
| 65 | `hl7_neg_framing_eob_malformed` | `framing_eob_malformed` | 结束块形态错：`0x1c` 后无 `0x0d` | `mllp`（framing） |
| 66 | `hl7_neg_framing_control_byte` | `framing_control_byte` | 正文出现未转义 `0x1c`（提前闭合 EOB；同族备选 `0x0b`） | `mllp`（framing） |
| 67 | `hl7_neg_segment_first_not_msh` | `segment_first_not_msh` | 首段非 MSH（如 EVN 开头） | `msh`（segment） |
| 68 | `hl7_neg_segment_no_cr` | `segment_no_cr` | 段未以 CR 结尾 | `segment`（msh） |
| 69 | `hl7_neg_segment_after_eob` | `segment_after_eob` | `0x1c 0x0d` 之后追加段 | `segment`（msh） |
| 70 | `hl7_neg_segment_name_invalid` | `segment_name_invalid` | 段名非法（非 3 字符/未知段名） | `segment`（msh） |
| 71 | `hl7_neg_msh1_invalid` | `msh1_invalid` | MSH-1 缺失或长度≠1 | `separator`（field） |
| 72 | `hl7_neg_msh2_invalid` | `msh2_invalid` | MSH-2 长度≠4 | `separator`（field） |
| 73 | `hl7_neg_separator_mismatch` | `separator_mismatch` | 正文实际分隔符与 MSH-2 声明不一致 | `separator`（field） |
| 74 | `hl7_neg_escape_invalid` | `escape_invalid` | 非法转义序列（`\X` 十六进制不成对） | `escape`（field） |
| 75 | `hl7_neg_msh9_missing` | `msh9_missing` | MSH-9 缺失 | `msh`（required） |
| 76 | `hl7_neg_msh10_missing` | `msh10_missing` | MSH-10 缺失 | `msh`（required） |
| 77 | `hl7_neg_msh11_missing` | `msh11_missing` | MSH-11 缺失 | `msh`（required） |
| 78 | `hl7_neg_msh12_missing` | `msh12_missing` | MSH-12 缺失 | `msh`（required） |
| 79 | `hl7_neg_msh9_domain` | `msh9_domain` | MSH-9 消息代码/触发事件不在值域（如 `XYZ^Q99^XYZ_Q99`） | `msh`（type） |
| 80 | `hl7_neg_ack_msa2_mismatch` | `ack_msa2_mismatch` | 派生 ACK 的 MSA-2 ≠ 请求 MSH-10 | `ack`（correlation） |
| 81 | `hl7_neg_ack_no_msh9` | `ack_no_msh9` | ACK 缺 MSH-9=ACK | `ack`（correlation） |
| 82 | `hl7_neg_ack_no_msa` | `ack_no_msa` | ACK 缺 MSA 段 | `ack`（msa） |
| 83 | `hl7_neg_ack_code_invalid` | `ack_code_invalid` | MSA-1 确认码非 AA/AE/AR（如 `XX`） | `ack`（correlation） |
| 84 | `hl7_neg_carrier_udp` | `carrier_udp` | UDP 载体（层链 `[{"udp":{}},{"hl7":{}}]`） | `carrier`（transport） |
| 85 | `hl7_neg_carrier_no_tcp` | `carrier_no_tcp` | 层链缺 tcp（hl7 直连 ip） | `layer`（carrier） |
| 86 | `hl7_neg_port_invalid` | `port_invalid` | 非法端口（0/65536） | `port`（transport） |
| 87 | `hl7_neg_len_msh9` | `len_msh9` | MSH-9 >15 字符 | `length`（limit） |
| 88 | `hl7_neg_len_msh10` | `len_msh10` | MSH-10 >20 字符 | `length`（limit） |
| 89 | `hl7_neg_len_msh12` | `len_msh12` | MSH-12 >60 字符 | `length`（limit） |
| 90 | `hl7_neg_len_msh7` | `len_msh7` | MSH-7 >26 字符（textual 上界） | `length`（limit） |
| 91 | `hl7_neg_len_msa2` | `len_msa2` | MSA-2 >20 字符 | `length`（limit） |
| 92 | `hl7_neg_event_mismatch` | `event_mismatch` | EVN-1 与 MSH-9 触发事件不一致（MSH-9=ADT^A01 + `EVN|A02|`，C-13 失败用例先行） | `event`（consistency） |
| 93 | `hl7_neg_address_family_mixed` | `address_family_mixed` | 地址族混合：`[ipv6]` 层配 IPv4 字面量（C-11） | `address`（family） |
| 94 | `hl7_neg_required_segment_missing` | `required_segment_missing` | ADT^A01 缺必需业务段 PID（D-6：按 MSH-9 结构声明必需段集） | `segment`（required） |
| 95 | `hl7_neg_z_segment_unconfigured` | `z_segment_unconfigured` | 未显式声明的 Z 段（段表白名单外且无 allow 标志，D-3 联动） | `z`（segment） |

合法协议事件不进负例（防误报）：合法转义序列、重复字段、空槽、TCP 分段/粘连/多帧同段、IPv4/IPv6、AA/AE/AR、`ack_mode=null`、动态值、MSH-15/16 留空、恰等上界、显式声明的 Z 段、s2c 方向。负例不得污染合法格式：每条故障只改变对应一项协议前提；错误保留最具体来源，不得自动补齐缺失 ID 或重排消息。

## 6. 五层覆盖映射（v1.3 行为面对照，按 ID 引用防错位）

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 消息类型族（1-8）、编码族（9-20）、ACK 族（6/7/8/30-38）、负例 33 行 | 消息类型 ADT^A01/A02/A03、ORU^R01、SIU^S12、AA/AE/AR、ack 关闭/覆盖/s2c 各一例；MLLP 帧字节、组件/子组件/重复、转义族逐序列拆分（\F\\S\\R\\E\\T\\H\\N\\X 单字节\\X 多字节）；负例 33 行逐故障输入（framing×4、段结构×4、分隔符/转义×4、MSH×5、ACK×4、载体×3、长度×5、一致性/地址/段集/Z×4） |
| 性能 | 21（MSS 重组+粘连）、61（3 帧粘连）、55-58（恰等上界）+长度负例 | 跨段重组（C-15 字段落尾段口径）；帧长公式独立断言（#9，D-7）；字段长度上界边界与越界 |
| 数据场景 | 11/12（重复/CX）、13-20（转义族）、27-29（版本/处理 ID）、48-54（值域族）、55-58（边界） | MSH-12 版本、MSH-11 P/T/D、PV1-2 I/O/E、OBX-2 类型、结果状态 F/P/C、转义值域、自定义分隔符/编码字符、恰等上界 |
| 地址与流 | 1（v4 单流基线）、23-24（v6/v6 多事务）、25（多会话）、26（并发会话） | v4+v6；流关联不适用保留声明（HL7 无派生流，理由成立——rr-hl7 修复轮提醒：只翻并发会话这一条）；多流不适用保留 |
| 业务 | 1-5（入院/转科/出院/检验/预约现网日常）、7/8（NAK 错误/拒绝）、21（批量长连接）、25/26（多系统并行） | 现网 HIS/LIS 对接场景优先 |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/hl7.json` 通过；当前数组恰含 1 条 `hl7_neg_unregistered`：`proto=hl7`、层链 `[{"tcp":{}},{"hl7":{}}]`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
2. 实现注册 `hl7` 层后：移除占位，按 §2 顺序补入 95 个语义用例；ID、顺序与设计 §9/本文 §2 一致（脚本核验）。
3. 正例每条含 `packet_count`（或 `min_packets`）+ `fields` + `frames`；`fields` 只用 §1 实测存在的 tshark 字段；非 2575 端口例带 `-d` DecodeAs 提示。
4. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields；`error_contains` 用 §5 主锚词。
5. **pcap/NIC 双输出**：两输出路径共用本契约（同一 cases JSON、同一 tshark 字段/frames 断言），NIC 路径抓包口差异不改变断言语义（C-7）。
6. 断言包号引用跨会话/跨连接时用 `tcp.stream`+会话起点规则；动态值用 `same_as_packet`/`distinct_values`/`nonzero`。
7. MLLP 帧字节按字节断言；段 CR ≠ 终止 CR；TCP segment 边界不得替代 MLLP 帧边界（C-15 双口径）。
8. 负例覆盖 33 个可实现故障输入逐行传播为 task error；`unknown layer` 占位不得冒充协议语义负例已执行。

## 8. 三方一致性表

设计 §9、本文 §2、实现后 `hl7.json` 保持同一 95 个语义 ID、同一顺序（当前 JSON 另有占位，不计入）：

```text
hl7_adt_a01_ipv4
hl7_adt_a02_transfer
hl7_adt_a03_discharge
hl7_oru_r01_results
hl7_siu_s12_appointment
hl7_ack_success_association
hl7_nak_error_segment
hl7_ack_ar_reject
hl7_mllp_frame_bytes
hl7_component_subcomponent
hl7_field_repetition
hl7_pid3_cx_components
hl7_escape_f
hl7_escape_s
hl7_escape_r
hl7_escape_e
hl7_escape_t
hl7_escape_h_n
hl7_escape_hex
hl7_escape_hex_multibyte
hl7_multi_transaction_long_connection
hl7_tcp_mss_reassembly
hl7_ipv6_transport
hl7_ipv6_multi_transaction
hl7_multi_session_isolation
hl7_concurrent_sessions
hl7_port_nondefault
hl7_version_profiles
hl7_processing_id_d
hl7_ack_code_domain
hl7_ack_disabled
hl7_ack_override_null
hl7_s2c_receiver_role
hl7_ack_rule_separators
hl7_ack_rule_swap
hl7_ack_rule_new_ts
hl7_ack_trigger_oru
hl7_ack_minimal_form
hl7_msh_app_fac_fields
hl7_msh7_ts_format
hl7_msh9_structure
hl7_msh8_populated
hl7_msh8_empty_slot
hl7_msh15_16_empty
hl7_evn2_time_format
hl7_set_id_fields
hl7_z_segment_passthrough
hl7_custom_field_separator
hl7_custom_encoding_chars
hl7_pv1_class_outpatient
hl7_pv1_class_emergency
hl7_obx_valuetype_ce
hl7_result_status_pending
hl7_result_status_corrected
hl7_boundary_msh9_len15
hl7_boundary_msh10_msa2_len20
hl7_boundary_msh12_len60
hl7_boundary_msh7_ts_max
hl7_msa3_text
hl7_err_fields
hl7_mllp_multi_frame_burst
hl7_control_id_inc_strategy
hl7_neg_framing_sob_missing
hl7_neg_framing_eob_missing
hl7_neg_framing_eob_malformed
hl7_neg_framing_control_byte
hl7_neg_segment_first_not_msh
hl7_neg_segment_no_cr
hl7_neg_segment_after_eob
hl7_neg_segment_name_invalid
hl7_neg_msh1_invalid
hl7_neg_msh2_invalid
hl7_neg_separator_mismatch
hl7_neg_escape_invalid
hl7_neg_msh9_missing
hl7_neg_msh10_missing
hl7_neg_msh11_missing
hl7_neg_msh12_missing
hl7_neg_msh9_domain
hl7_neg_ack_msa2_mismatch
hl7_neg_ack_no_msh9
hl7_neg_ack_no_msa
hl7_neg_ack_code_invalid
hl7_neg_carrier_udp
hl7_neg_carrier_no_tcp
hl7_neg_port_invalid
hl7_neg_len_msh9
hl7_neg_len_msh10
hl7_neg_len_msh12
hl7_neg_len_msh7
hl7_neg_len_msa2
hl7_neg_event_mismatch
hl7_neg_address_family_mixed
hl7_neg_required_segment_missing
hl7_neg_z_segment_unconfigured
```

## 9. 修订记录

- v1.0.0（2026-08-20）：旧稿首版（14 正 + 6 负）。
- v2.1.1（2026-09-01，复验 V 轮收尾）：rr-hl7 复验 25/27 CLOSED，V 系列六项小修——**V-1**（MAJOR）#56 fixture 19 字符→恰 20 字符 `CID20260901083045AAB`（恰等上界真正测到）；V-2 #61 包数 10→8（3 帧 ack=null 粘连 1 段 = 3+1+4）；V-3 设计散文 11 处旧 ID/旧计数同步新 ID 与 95；V-4 §6 映射表 #60→#61、段结构×5→×4；V-5 #66 单一注入钉死 `0x1c`（`0x0b` 记同族备选）；V-6 #12 CX 示例改 `ID^^^HOSP^MR`（授权方在 CX.4）。修复后送 rr-hl7 关单复验。
- v2.0.0（2026-08-31）：v1.1 隔离审查轮重写（18 正 + 6 负），tshark 实测断言基线固化。
- v2.0.1（2026-09-01）：12 项修复（`hl7.segment` 语义更正为整段文本、偏好门控写明、长度上界负例、字段断言落地），25 条 = 18 正 + 7 负。
- v2.1.0（2026-09-01，v1.3 重审修复轮）：rr-hl7 行为面 145 点全枚举重审（2C/8M/12M）后重出：25 条 → **95 条（62 正 + 33 负）**。关键修复：**C-2**（CRITICAL）负例逐故障输入原子拆分 7→33 行（一行一例单一注入、主锚词钉死）；**D-1**（CRITICAL）SCH/AIS 字段号按 v2.5 修正——SCH-4 预约原因/SCH-10 开始/SCH-11 结束（原 SCH-7/11/12）、AIS-3 USI（原 AIS-2；AIS-2 Segment Action Code v2.4 已废），#5 与设计 §3.5/§6 fixture 三处同步；**C-1** 并发会话翻案纳入（#26；流关联/多流不适用声明按 rr-hl7 提醒合理保留）；**C-3** 非默认端口正例（#27，带 `-d` DecodeAs——D-4 实测口径）；**C-4** 恰等上界边界例（#55-58：MSH-9 恰 15、MSH-10/MSA-2 恰 20、MSH-12 恰 60、MSH-7 语法最长 24 并声明 textual 26/语法 24 差异）；**C-6** s2c/role=receiver 例（#33）；**C-7** pcap/NIC 双输出声明（§1/§7）；**D-2** 负例表删除 2 个不可实现输入（「非 2575 且未显式配置」不可达、「把 NAK 当成功」无注入点）；**D-3** Z 段矛盾解决（显式声明放行 + #47 正例 + 未声明 Z 段负例）；**C-12** RST 不适用声明（设计 §5.4）；**C-13** EVN-1↔MSH-9 一致性负例 #92（失败用例先行）+ Validate 行；**D-6** 必需段集校验声明 + 负例 #94；**C-11** 地址族混合负例 #93；**C-15** 重组字段落尾段口径钉死（#22）；**D-7** 帧长公式独立断言（#9）；**D-5** 尾随空槽策略 + epoch→UTC 定宽 14 位渲染规则入文（#40/#43/#44/#45）；**N-1** §3.6 字节示例 CR `30 44`→`0D`；**N-2** MSH-11 `T`=Training（Table 0103）修正（#29）；**N-3** ERR 字段注修正（ERR-2=错误位置、ERR-5=本地码，#60/#7）；**N-4** 主锚词钉死。扩量正例：转义族 1→8 例拆分（#13-20）、ACK 派生规则 §5.2 逐条拆分（#32-38）、PV1-2/OBX-2/结果状态值域（#50-54）、MSH 字段族（#39-46）、集合 ID/Z 段/MSA-3/ERR/粘连扩展/inc 策略（#46-49/#59-62）。

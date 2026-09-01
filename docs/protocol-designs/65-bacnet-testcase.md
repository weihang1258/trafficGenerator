# BACnet（楼宇自动化控制网络数据通信协议，ASHRAE 135）测试用例契约

> 版本：v2.1.0（测试用例）
> 日期：2026-09-01
> 配套设计：`docs/protocol-designs/65-bacnet-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/bacnet.json`（proto key：`bacnet`；本版不写文件，当前 JSON 仅含注册前置占位）
> 状态：按《协议设计文档与用例文档需求文档 v1.3》完成行为面全枚举重审修复轮（审查员 rr-bacnet：行为面 181 点，✓123/半23/✗35；confirmed findings 10 条（5C+3D+2N）+1 拍板项按判例升格），本版 v2.1.0 为修复轮产物：53 → **97 例（55 正 + 42 负）**，待 rr-bacnet 复验。v1.1 流程的 14 项审查修复（v2.0.1）记录见 §9。
> 修订记录：v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-20 旧稿（旧稿见 git 历史；旧稿 14+6 粗粒度用例全部重排为 38+15 原子用例）。v2.0.1 见 §9。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 **97 个唯一语义 ID：55 个正例 + 42 个负例**（rr-bacnet 行为面 181 点全枚举，比率约 1.9 点/例）。**ID 权威 = 本文 §2**（v2.1 D-1：设计 §9 改簇级覆盖图景，不持有逐 ID 镜像表）。派生规则：设计 §3 每个编码条款（每 BVLC 功能、每 NPDU 变体、每 APDU 类型、每服务、每应用标签族、每长度档）、§5 每个状态/事务/关联行为、§7 每行错误处理在本文有对应断言；断言不得超出设计（并追溯到 ASHRAE 135 条款 / bacnet-stack 参考实现）声明范围。**一个用例只验证一个协议行为**（v1.1 §7 原子原则）。

当前 JSON 只保留一个 `bacnet_neg_unregistered` 注册前置占位：`proto=bacnet`、`expect_error=true`、`error_contains` 精确为 `unknown layer`；该占位不计入 97 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 BACnet 行为通过。注册后移除占位，按本文 §2 顺序补入 55 个正例与 42 个负例。

**输出契约（pcap/NIC 双输出，C-2）**：本契约的用例同时服务于 pcap（抓包文件）与 port_group/NIC（网卡）两种输出路径——两路径共用同一份 cases JSON、同一 tshark 字段/帧字节断言，NIC 路径仅抓包口不同，不改变断言语义（与 64-cwmp/66-doh/67-onvif/68-hl7/70-megaco 同形）。**并发会话（v2.1 翻案纳入，C-1）**：`concurrent: true` 交错回放正例 47——单会话事件序仍受设计 §5 状态机约束，并发只作用于生成器级多连接交错（判例 cwmp⑦/doh#24/onvif#56/hl7#26/megaco#45）；流关联显式不适用声明保留（设计 §4：单 UDP 流承载全部信令与数据）。**UDP 无连接口径（N-2）**：无握手/挥手/RST/保活/重连语义——正例不携带 `has_handshake`/`terminates`；重传由 events[] 显式编排（重复 invoke 同 ID 帧序列），协议层重传定时器不实现（设计 §8 声明）。

**TSHARK 实测基线（本机 3.6.14，`-G fields`/`-G protocols` 核验 + 手工构造 pcap 实证，非臆造）**：本机有完整 BACnet dissector（协议注册名 `bvlc`/`bacnet`/`bacapp`）。**UDP 源或目的端口 = 47808 才自动解码**（实测：同字节在 47809 上只显示为普通 UDP），fixture 端口 47808 为硬约束。实测可用的关键字段：

| 层 | 字段（实测值样例） |
|---|---|
| BVLC | `bvlc.type`(0x81)、`bvlc.function`(0x00–0x0b)、`bvlc.result`(0x0000/0x0030)、`bvlc.reg_ttl`(600)、`bvlc.bdt_ip`/`bvlc.bdt_port`/`bvlc.bdt_mask`、`bvlc.fdt_ip`/`bvlc.fdt_port`/`bvlc.fdt_ttl`/`bvlc.fdt_timeout`、`bvlc.fwd_ip`/`bvlc.fwd_port` |
| NPDU | `bacnet.version`(1)、`bacnet.control`(0x00/0x04/0x20/0x84)、`bacnet.control_net`/`control_dest`/`control_src`/`control_expect`/`control_prio_high`/`control_prio_low`（布尔）、`bacnet.dnet`/`dlen`/`hopc`、`bacnet.snet`/`slen`、`bacnet.mesgtyp`(0x00/0x01) |
| APDU | `bacapp.type`(0–7)、`bacapp.pduflags`(0x0c/0x08)、`bacapp.segmented_request`/`more_segments`/`SA`、`bacapp.max_adpu_size`(0–5)、`bacapp.response_segments`、`bacapp.invoke_id`、`bacapp.sequence_number`、`bacapp.window_size`、`bacapp.confirmed_service`(12/14/15/5/17)、`bacapp.unconfirmed_service`(0/1/2/7/8)、`bacapp.NAK`/`SRV`、`bacapp.error_class`(2)、`bacapp.error_code`(32)、`bacapp.reject_reason`(5)、`bacapp.abort_reason`(11)、`bacapp.vendor_identifier`(15) |
| 服务参数 | `bacapp.who_is.low_limit`(0)/`high_limit`(100)、`bacapp.objectType`(0/8)、`bacapp.instance_number`(1/100)、`bacapp.property_identifier`(85/77)、`bacapp.processId`(1)、`bacapp.object_name` |
| 值/标签 | `bacapp.present_value.real`(22.5)/`.uint`/`.int`/`.double`/`.boolean`/`.enum_index`/`.char_string`/`.octet_string`/`.bit_string`/`.null`、`bacapp.application_tag_number`(0–12)、`bacapp.context_tag_number`、`bacapp.tag_class`、`bacapp.LVT`、`bacapp.named_tag`(6/7 开闭)、`bacapp.string_character_set`(0/4) |
| 分段重组 | `bacapp.fragment.count`(2)、`bacapp.reassembled.length`(14)、`bacapp.reassembled.in` |
| 载体 | `udp.srcport`/`udp.dstport`/`udp.length`、`ip.version`、`ipv6.nxt`、`frame.number`/`frame.len` |

**五个实测注意**：① **`bvlc.length` 是 dissector 计算值而非线上原值**（功能 >0x08 恒 4、0x04 恒 10、<0x09 为头值；Wireshark `packet-bvlc.c` 584–639 行）——线上 Length 用 frames offset 44–45 的 2 字节 hex 断言，或用 `udp.length`（= 8+payload）换算断言；② **无 `present_value.date`/`present_value.time` 字段**——Date/Time 标签断言走 `bacapp.application_tag_number`(10/11) + frames hex；③ `application_tag_number`/`tag_class`/`LVT` 等在多值报文中为逗号分隔列表，逐值断言优先用单值字段（`present_value.*`）或 frames；④ **`present_value.uint`/`present_value.enum_index` 只在属性值上下文（ComplexACK/COV 通知的 propertyValue 内）可过滤**——I-Am（max-APDU/厂商 ID）、DCC（enable/disable）等服务参数里的同型值是 dissector 纯文本节点，`-T fields` 提取为空（本机 3.6.14 构造 pcap 实测：I-Am 帧 `bacapp.present_value.uint`/`enum_index` 均为空串，而 RPM 应答内 Unsigned 值 `present_value.uint=42` 可提取），此类断言一律走 frames hex（正例 1/25/31/44），不得对服务参数用 `present_value.*` 字段；⑤ **非 47808 端口不自动解码**——非默认端口用例（46）的 fields 断言须带 `-d udp.port==47809,bacnet` DecodeAs 提示，或全 frames hex 断言（hl7 #27 判例口径；harness 已实证支持 `-d`）。

**动态字段禁止硬编码**：Invoke ID、设备实例、属性值、TTL/lifetime 为生成期值时用 `same_as_packet`/`distinct_values`/`nonzero` 或 fixture 钉死值断言；本版 fixture 把 Invoke ID/实例/值全部钉死（见 §3 常量表），帧字节按设计 §3 公式可精确预算（本文 §4 已按构造 pcap 逐字节验证样本锚定）。

**包数约定**（设计 §5：UDP 无连接）：**每个 UDP 数据报 = 1 包**，无握手/挥手帧（`has_handshake`/`terminates` 均不适用，恒 false 不写入 expect）；正例 `packet_count` = 事件序列产出的数据报数（自动派生帧计入）。实现期以实际输出校准，断言以 fields/frames 为准；负例无 packet_count。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖（设计 §） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `bacnet_bvlc_unicast_baseline` | 正 | §3.1/§3.6：0x0A + Who-Is→I-Am 基线 | 2 |
| 2 | `bacnet_min_frame` | 正 | §3.7/§8：无参数 Who-Is 最小帧 | 1 |
| 3 | `bacnet_bvlc_broadcast` | 正 | §3.1/§4①：0x0B + 定向广播 + 2×I-Am | 3 |
| 4 | `bacnet_bvlc_forwarded` | 正 | §3.1：Forwarded-NPDU(6B 源地址) | 1 |
| 5 | `bacnet_bvlc_register_foreign` | 正 | §3.1：RFD(TTL 600/0)→Result 0x0000 | 4 |
| 6 | `bacnet_bvlc_result_nak` | 正 | §3.1：RFD→Result 0x0030 NAK | 2 |
| 7 | `bacnet_bvlc_write_bdt` | 正 | §3.1：Write-BDT→Result | 2 |
| 8 | `bacnet_bvlc_read_bdt` | 正 | §3.1：Read-BDT→Ack(表项) | 2 |
| 9 | `bacnet_bvlc_read_fdt` | 正 | §3.1：Read-FDT→Ack(TTL/超时) | 2 |
| 10 | `bacnet_bvlc_delete_fdt` | 正 | §3.1：Delete-FDT→Result | 2 |
| 11 | `bacnet_bvlc_distribute_broadcast` | 正 | §3.1：Distribute-Broadcast(载 Who-Is) | 1 |
| 12 | `bacnet_npdu_dest_address` | 正 | §3.2：DNET/DLEN=6+DADR 与 DLEN=0 广播/HopCount | 2 |
| 13 | `bacnet_npdu_src_address` | 正 | §3.2：SNET/SLEN/SADR | 2 |
| 14 | `bacnet_npdu_router_discovery` | 正 | §3.2：Who-Is-Router→I-Am-Router | 2 |
| 15 | `bacnet_npdu_priority` | 正 | §3.2：优先级 01/10/11 | 3 |
| 16 | `bacnet_read_property` | 正 | §3.3/§3.6：RP→ComplexACK(Real) | 2 |
| 17 | `bacnet_read_property_array_index` | 正 | §3.6：数组下标 [2] 与 [0]（整组）回显 | 4 |
| 18 | `bacnet_read_property_multiple` | 正 | §3.6：RPM 多属性多值 | 2 |
| 19 | `bacnet_write_property` | 正 | §3.6：WP(布尔+优先级)→SimpleACK | 2 |
| 20 | `bacnet_write_property_no_priority` | 正 | §3.6：无 [4] 缺省优先级 | 2 |
| 21 | `bacnet_who_has_i_have` | 正 | §3.6：Who-Has(按名[3]/按对象 ID[2])→I-Have | 4 |
| 22 | `bacnet_subscribe_cov` | 正 | §3.6：SubscribeCOV→SimpleACK | 2 |
| 23 | `bacnet_cov_notification` | 正 | §3.6：UnconfirmedCOVNotification | 1 |
| 24 | `bacnet_subscribe_cov_cancel` | 正 | §3.6：取消订阅→SimpleACK | 2 |
| 25 | `bacnet_device_communication_control` | 正 | §3.6：DCC→SimpleACK | 2 |
| 26 | `bacnet_error_response` | 正 | §3.3/§3.6：Error(class/code 32/40 组合, Invoke) | 4 |
| 27 | `bacnet_reject` | 正 | §3.3：Reject(reason 5) | 2 |
| 28 | `bacnet_abort` | 正 | §3.3：Abort(SRV/reason 11) | 2 |
| 29 | `bacnet_segmented_request` | 正 | §3.3：分段请求+SegmentACK | 3 |
| 30 | `bacnet_segmented_complex_ack` | 正 | §3.3：分段应答+重组字段 | 4 |
| 31 | `bacnet_i_am_capabilities` | 正 | §3.6/§8：I-Am 分段能力 0/1/2 变体 | 3 |
| 32 | `bacnet_app_tag_encoding` | 正 | §3.4：13 种应用标签全枚举（含 Boolean 双值） | 3 |
| 33 | `bacnet_object_id_boundary` | 正 | §3.5/§8：实例 0/0x3FFFFF、类型 0/128 | 4 |
| 34 | `bacnet_invoke_id_boundary` | 正 | §3.3/§8：Invoke ID 0/255 | 4 |
| 35 | `bacnet_multi_transaction` | 正 | §5/§4⑩：单会话多事务递增 | 6 |
| 36 | `bacnet_ipv6` | 正 | §2/§8：IPv6 fixture(偏移 62) | 2 |
| 37 | `bacnet_multi_session` | 正 | §5/§8：双客户端多会话展开 | 4 |
| 38 | `bacnet_large_charstring` | 正 | §8/§3.4：1024B 字符串(扩展长度档) | 2 |
| 39 | `bacnet_invoke_id_adjacent` | 正 | 边界相邻值：invoke 1（min+1）/254（max-1）（设计 §3.3/§8，C-4） | 4 |
| 40 | `bacnet_instance_adjacent` | 正 | 边界相邻值：实例 1（min+1）/0x3FFFFE（max-1）（设计 §3.5/§8，C-4） | 4 |
| 41 | `bacnet_object_type_boundaries` | 正 | 边界值：类型 127（标准末值）/1023（10 位满值）（设计 §3.5/§8，C-4） | 4 |
| 42 | `bacnet_priority_boundaries` | 正 | 边界值：优先级 1（最高）/显式 16（最低）（设计 §3.6/§8，C-4/N-3 升格） | 4 |
| 43 | `bacnet_window_size_boundaries` | 正 | 边界值：proposed window 1/255（设计 §3.3/§8，C-4） | 7 |
| 44 | `bacnet_vendor_id_max` | 正 | 边界值：厂商 ID 65535（u16 上界）（设计 §3.6/§8，C-4） | 1 |
| 45 | `bacnet_ttl_max` | 正 | 边界值：RFD TTL 65535（u16 上界）（设计 §3.1/§8，C-4） | 2 |
| 46 | `bacnet_port_nondefault` | 正 | 非默认端口：显式声明 47809 + DecodeAs 口径（设计 §2/§8，C-5） | 2 |
| 47 | `bacnet_concurrent_sessions` | 正 | 并发会话：concurrent:true 双客户端交错回放（C-1 翻案）（设计 §4/§5 v2.1，判例同 megaco#45） | 4 |
| 48 | `bacnet_who_has_limits` | 正 | Who-Has [0]/[1] 设备实例范围过滤对（D-2①）（ASHRAE 135 Clause 21/设计§3.6） | 2 |
| 49 | `bacnet_rpm_multi_object` | 正 | RPM 双对象多属性（D-2②）（设计§3.6/§4③） | 2 |
| 50 | `bacnet_dcc_variants` | 正 | DCC 三变体：enable(0)/disable-initiation(2)/[0]缺省（D-2③）（设计§3.6） | 6 |
| 51 | `bacnet_subscribe_cov_unconfirmed` | 正 | SubscribeCOV issue-confirmed=false（[2] 存在且 FALSE，D-2④）（设计§3.6） | 2 |
| 52 | `bacnet_confirmed_request_sa` | 正 | Confirmed-Request SA bit1=1（接受分段响应，D-3①）（设计§3.3） | 2 |
| 53 | `bacnet_npdu_global_broadcast` | 正 | DNET=0xFFFF 全局广播路由形态（D-3④，含 DNET 65535 边界）（Annex J/设计§3.2） | 1 |
| 54 | `bacnet_bdt_multi_entry` | 正 | BDT/FDT 多表项 N=2（D-3⑥）（设计§3.1） | 4 |
| 55 | `bacnet_charstring_ucs2` | 正 | CharacterString charset 4（UCS-2 编码变体，N-3 升格）（设计§3.4/§8） | 2 |
| 56 | `bacnet_neg_bvlc_type` | 负 | §7：BVLC Type ≠0x81 | — |
| 57 | `bacnet_neg_bvlc_function` | 负 | §7：BVLC Function ∉0x00–0x0B 明文功能域 | — |
| 58 | `bacnet_neg_bvlc_secure` | 负 | §7：Secure-BVLL 0x0C 被当明文产生 | — |
| 59 | `bacnet_neg_bvlc_length_min` | 负 | §7：BVLC Length <4 | — |
| 60 | `bacnet_neg_bvlc_length_mismatch` | 负 | §7：BVLC Length ≠ 4+功能负载实际字节 | — |
| 61 | `bacnet_neg_bvlc_length_forwarded` | 负 | §7：Forwarded-NPDU(0x04) Length 未计入 6B 原始源地址 | — |
| 62 | `bacnet_neg_npdu_version` | 负 | §7：NPDU Version ≠0x01 | — |
| 63 | `bacnet_neg_npdu_dest_missing` | 负 | §7：Control bit5=1 而 DNET/HopCount 缺失 | — |
| 64 | `bacnet_neg_npdu_src_len_zero` | 负 | §7：Control bit3=1 而 SLEN=0 | — |
| 65 | `bacnet_neg_npdu_reserved_bits` | 负 | §7：Control 保留位 bit6/bit4 置 1 | — |
| 66 | `bacnet_neg_npdu_no_message_type` | 负 | §7：Control bit7=1 而 Message Type 缺失 | — |
| 67 | `bacnet_neg_npdu_dlen_invalid` | 负 | §7：DLEN ∉{0,6} | — |
| 68 | `bacnet_neg_apdu_type_invalid` | 负 | §7：APDU 首字节高 4 位 >7 | — |
| 69 | `bacnet_neg_apdu_header_confirmed` | 负 | §7：Confirmed-Request 头部不完整 | — |
| 70 | `bacnet_neg_apdu_header_simpleack` | 负 | §7：SimpleACK <3 字节 | — |
| 71 | `bacnet_neg_service_confirmed_unimplemented` | 负 | §7：Confirmed Service Choice 不在 §1 子集 | — |
| 72 | `bacnet_neg_service_unconfirmed_invalid` | 负 | §7：Unconfirmed Service Choice ∉{0,1,2,7,8} | — |
| 73 | `bacnet_neg_tag_lvt_mismatch` | 负 | §7：LVT=4 而内容仅 2 字节 | — |
| 74 | `bacnet_neg_tag_open_unmatched` | 负 | §7：开标签无同号闭标签配对 | — |
| 75 | `bacnet_neg_tag_boolean_lvt` | 负 | §7：Boolean 应用标签 LVT=2 | — |
| 76 | `bacnet_neg_tag_context_number` | 负 | §7：上下文标签号超出服务 ASN.1 定义 | — |
| 77 | `bacnet_neg_object_type_overflow` | 负 | §7：对象类型 >1023 | — |
| 78 | `bacnet_neg_object_instance_overflow` | 负 | §7：对象实例 >4194303 | — |
| 79 | `bacnet_neg_object_iam_not_device` | 负 | §7：I-Am 设备标识对象类型 ≠8 | — |
| 80 | `bacnet_neg_property_id_vendor` | 负 | §7：属性 ID >511 而未声明厂商私有 | — |
| 81 | `bacnet_neg_property_index_negative` | 负 | §7：数组下标为负 | — |
| 82 | `bacnet_neg_priority_range` | 负 | §7：WriteProperty 优先级 ∉1–16 | — |
| 83 | `bacnet_neg_error_class_range` | 负 | §7：error-class 越域 | — |
| 84 | `bacnet_neg_invoke_mismatch` | 负 | §7：应答 | — |
| 85 | `bacnet_neg_invoke_reuse` | 负 | §7：同一会话未完成事务期间复用同一 Invoke ID | — |
| 86 | `bacnet_neg_segment_extra_fields` | 负 | §7：SEG=0 却携带 Sequence Number/Window Size 字段 | — |
| 87 | `bacnet_neg_segment_missing_fields` | 负 | §7：SEG=1 缺 Sequence Number/Window Size 字段 | — |
| 88 | `bacnet_neg_segment_window_zero` | 负 | §7：Proposed Window Size=0 | — |
| 89 | `bacnet_neg_segment_sequence_skip` | 负 | §7：Sequence Number 回绕/跳变 | — |
| 90 | `bacnet_neg_carrier_layer_missing` | 负 | §7：层链缺 udp | — |
| 91 | `bacnet_neg_carrier_tcp` | 负 | §7：TCP 载体声明 | — |
| 92 | `bacnet_neg_port_undeclared` | 负 | §7：端口 ≠47808 而未显式声明 | — |
| 93 | `bacnet_neg_address_family_mismatch` | 负 | §7：IPv6 地址配 IPv4 层链 | — |
| 94 | `bacnet_neg_address_family_derived` | 负 | §7：从 IPv4 fixture 推导 IPv6 地址 | — |
| 95 | `bacnet_neg_state_ack_no_request` | 负 | §7：ACK/Error 事件无前置确认请求 | — |
| 96 | `bacnet_neg_state_iam_no_whois` | 负 | §7：I-Am 事件无前置 Who-Is | — |
| 97 | `bacnet_neg_state_cov_no_subscribe` | 负 | §7：COV 通知事件无前置订阅 | — |
| — | `bacnet_neg_unregistered` | 占位 | 当前层注册前置 | — |

## 3. 线上编码和偏移断言

层链 `[udp, bacnet]`，无 VLAN 与 IP options 时 **BVLC 首字节起点为 IPv4 offset（偏移）42（Ethernet 14 + IPv4 20 + UDP 8）、IPv6 offset 62**（构造 pcap 实测：54 字节帧的 12B UDP payload 从 42 起，`frame.len - udp payload = 42`）。NPDU 在 offset 46（BVLC 头 4B 后），APDU 起点随 NPDU 路由字段变长（无路由字段时 offset 48）。断言分层：

1. **载体与方向（fields 权威断言）**：客户端帧 `udp.srcport=47808`、`udp.dstport=47808`（设备帧端口互换方向相反、IP 对调）；`ip.version=4`（IPv6 fixture 断言 `ipv6.nxt=17` 且不得出现 v4 地址）；`udp.length = 8 + BVLC Length`（换算断言线上长度一致性）。
2. **BVLC/NPDU/APDU（fields + frames 双通道）**：fields 按 §1 实测表断言（`bvlc.type=0x81`、`bvlc.function`、`bacnet.version=1`、`bacnet.control`、`bacapp.type`、服务选择等）；frames 断言在 offset 42 起校验关键字节——BVLC 头（`81 <func> <len BE 2B>`）、NPDU（`01 <control>`）、APDU 首字节（PDU 类型高 4 位）、标签字节（如 Who-Is 限值 `09/19`、Real 值 `44 41b40000` 大端）。**线上 BVLC Length 用 frames offset 44–45 断言，不用 `bvlc.length` 字段**（§1 注意①）。
3. **分段重组**：分段 APDU 断言 `bacapp.fragment.count`、`bacapp.reassembled.length` 与末段重组字段（tshark 实测自动重组）；单段断言只对非分段报文使用。
4. **多会话包号规则**：`sessions[]` 按多会话展开整块回放——先跑完第 1 个会话全部事件再跑第 2 个，不交错；**第二会话首包号 = 前一会话总包数 + 1**（如用例 37 会话 2 首包 = 3）。跨会话关联断言用源 IP 区分，不硬编码全局包号。

**fixture 常量**（帧字节可按设计 §3 公式精确预算；各用例只列差异项）：客户端 A `192.0.2.66:47808`、客户端 B `192.0.2.67:47808`、设备/BBMD `198.51.100.66:47808`（IPv6 地址 `2001:db8::65` → `2001:db8::100:65`，端口均为 47808——地址与端口分离书写，N-1 修正）；广播目的 `198.51.100.255` + 广播 MAC `ff:ff:ff:ff:ff:ff`；设备实例 100（I-Am 基线）/200（广播第二设备）/5（COV 目标）；读写对象 `analog-input:1`（类型 0 实例 1）；属性 present-value(85)/object-name(77)；vendor_id 15；max_apdu 1476（基线）/1024（变体）；segmentation 3 none（基线）/0 both、1 transmit、2 receive（用例 31 三变体）；invoke_id 从 1 递增（边界用例 0/255）；Real 值 22.5（`44 41b40000`）；WriteProperty 布尔 TRUE（`11`）+ 优先级 8；process_id 1、lifetime 600、time_remaining 540；RFD TTL 600 与 0（用例 5 两笔，0=立即到期合法边界）；**无符号/枚举整数编码一律取最短式**（内容 ≤4B 时 LVT 直存，如 max-APDU 1476=`22 05c4`、厂商 15=`22 000f`、1476 扩展式 `25 02 05c4` 不使用——设计 §3.4 钉死策略）；BDT 表项 `192.0.2.88:47808` mask `255.255.255.0`；FDT 表项 `192.0.2.99:47808` TTL 300 超时 120；Forwarded 原始源 `192.0.2.99:47808`；DNET/SNET 2001；DCC duration 0/disable(1)/password `pass`；Who-Has 对象名 `ai-1`；长字符串 1024B fixture 填充；帧 hex 锚定样本均经构造 pcap 实测（见 §4 逐条）。

## 4. 正例逐项断言契约

以下 fields/frames 为最低断言集，实现期可增不可减；每例含 `packet_count`（或 `min_packets`）+ 载体方向断言 + `has_payload=true`；帧 hex 按设计 §3 公式 + §3 常量预算（标注"实测"者已经构造 pcap 验证）。方向简写：C=客户端 A、D=设备、B=客户端 B、BBMD=BBMD 侧。

1. **`bacnet_bvlc_unicast_baseline`**（2）：帧 1（C→D）`udp.length=20`、frames offset 42 `81 0a 00 0c 01 00 10 08 09 00 19 64`（实测逐字节）；`bvlc.function=0x0a`、`bacnet.version=1`、`bacnet.control=0x00`、`bacapp.type=1`、`bacapp.unconfirmed_service=8`、`bacapp.who_is.low_limit=0`、`bacapp.who_is.high_limit=100`。帧 2（D→C）`81 0a 00 15 01 00 10 00 c4 02000064 22 05c4 91 03 22 000f`（实测逐字节；无符号最短式，UDP payload 21B=0x15）；`bacapp.unconfirmed_service=0`、`bacapp.objectType=8`、`bacapp.instance_number=100`、`bacapp.vendor_identifier=15`；max-APDU 1476（`22 05c4`）与分段能力 3 none（`91 03`）由 frames hex 断言（`present_value.uint` 在 I-Am 上下文不可过滤，§1 注意④）。
2. **`bacnet_min_frame`**（1）：frames offset 42 `81 0a 00 08 01 00 10 08`（BACnet/IP 最小帧，实测帧 50B）；`udp.length=16`、`bacapp.unconfirmed_service=8`、Who-Is 无参数（`bacapp.who_is.low_limit`/`high_limit` 不出现——fields 断言该两字段缺失）。
3. **`bacnet_bvlc_broadcast`**（3）：帧 1（C→`198.51.100.255`）frames `81 0b 00 0c 01 00 10 08 09 00 19 64`；`bvlc.function=0x0b`、目的 IP 为定向广播。帧 2/3（D→C）两个 I-Am：`bacapp.instance_number` `distinct_values=[100,200]`、`bacapp.vendor_identifier=15`；两帧 `application_tag_number` 序列同为 `12,2,9,2`。
4. **`bacnet_bvlc_forwarded`**（1）：BBMD→C 帧 frames offset 42 `81 04 00 0e c0 00 02 63 ba c0 01 00 10 08`（实测同构：type/func/len + 6B 源地址 `192.0.2.99:47808` + NPDU/APDU）；`bvlc.function=0x04`、`bvlc.fwd_ip=192.0.2.99`、`bvlc.fwd_port=47808`、`bacapp.unconfirmed_service=8`。
5. **`bacnet_bvlc_register_foreign`**（4）：帧 1（C→D）`81 05 00 06 02 58`（TTL 600）；`bvlc.function=0x05`、`bvlc.reg_ttl=600`。帧 2（D→C）`81 00 00 06 00 00`；`bvlc.function=0x00`、`bvlc.result=0x0000`。帧 3/4 第二笔 RFD TTL=0（立即到期合法边界，§8）：`81 05 00 06 00 00`（`bvlc.reg_ttl=0`，实测）→ Result `0x0000` 同帧 2。
6. **`bacnet_bvlc_result_nak`**（2）：RFD 同用例 5 帧 1；帧 2 `81 00 00 06 00 30`；`bvlc.result=0x0030`（Register-FD NAK，合法错误路径，不得判失败）。
7. **`bacnet_bvlc_write_bdt`**（2）：帧 1（C→D）`81 01 00 0e c0 00 02 58 ba c0 ff ff ff 00`（1 表项：IP 192.0.2.88+端口 47808+掩码 /24）；`bvlc.function=0x01`、`bvlc.bdt_ip=192.0.2.88`、`bvlc.bdt_port=47808`、`bvlc.bdt_mask=ffffff00`（实测）。帧 2 Result `0x0000`。
8. **`bacnet_bvlc_read_bdt`**（2）：帧 1 `81 02 00 04`（Read-BDT 无负载）；帧 2（D→C）`81 03 00 0e c0 00 02 58 ba c0 ff ff ff 00`；`bvlc.function=0x03`、表项三字段同用例 7。
9. **`bacnet_bvlc_read_fdt`**（2）：帧 1 `81 06 00 04`；帧 2（D→C）`81 07 00 0e c0 00 02 63 ba c0 01 2c 00 78`（地址 192.0.2.99:47808 + TTL 300 + 超时 120，payload 14B）；`bvlc.function=0x07`、`bvlc.fdt_ip=192.0.2.99`、`bvlc.fdt_ttl=300`、`bvlc.fdt_timeout=120`（实测）。
10. **`bacnet_bvlc_delete_fdt`**（2）：帧 1 `81 08 00 0a c0 00 02 63 ba c0`（6B 外部设备地址）；`bvlc.function=0x08`。帧 2 Result `0x0000`。
11. **`bacnet_bvlc_distribute_broadcast`**（1）：C→BBMD 帧 `81 09 00 0c 01 00 10 08 09 00 19 64`（Distribute 承载 Who-Is）；`bvlc.function=0x09`、`bacapp.unconfirmed_service=8`。
12. **`bacnet_npdu_dest_address`**（2）：帧 1（C→D）frames offset 42 `81 0a 00 12 01 20 07 d1 06 <DADR 6B> ff 10 08`（control 0x20 + DNET 2001 + DLEN 6 + DADR + HopCount 0xFF + APDU）；`bacnet.control=0x20`、`bacnet.control_dest=true`、`bacnet.dnet=2001`、`bacnet.dlen=6`、`bacnet.hopc=255`。帧 2（DLEN=0 广播目的变体，无 DADR，§8）frames `81 0a 00 0c 01 20 07 d1 00 ff 10 08`（实测逐字节）；`bacnet.dnet=2001`、`bacnet.dlen=0`、`bacnet.hopc=255`（DLEN=0=DNET 内广播，DADR 缺省）。
13. **`bacnet_npdu_src_address`**（2）：帧 1 为普通 Who-Is（同用例 1 帧 1）；帧 2（D→C）frames `81 0a 00 1c 01 08 07 d1 06 <SADR 6B> 10 00 c4 02000064 22 05c4 91 03 22 000f`（control 0x08 + SNET 2001 + SLEN 6 + SADR + I-Am 最短式，payload 28B=0x1c）；`bacnet.control=0x08`、`bacnet.control_src=true`、`bacnet.snet=2001`、`bacnet.slen=6`。
14. **`bacnet_npdu_router_discovery`**（2）：帧 1（C→D）frames `81 0a 00 09 01 84 00 ff ff`（control 0x84：网络层消息+期望回复，Message Type 0x00，DNET FFFF，payload 9B）；`bacnet.control=0x84`、`bacnet.control_net=true`、`bacnet.mesgtyp=0x00`。帧 2（D→C）`81 0a 00 09 01 80 01 07 d1`（control 0x80：网络层消息必须 bit7=1（设计 §3.2），Message Type 0x01，DNET 2001，payload 9B，实测逐字节）；`bacnet.control=0x80`、`bacnet.control_net=true`、`bacnet.mesgtyp=0x01`。
15. **`bacnet_npdu_priority`**（3）：三帧 Who-Is，NPDU control 分别 `0x01`（Urgent）/`0x02`（Critical Equipment）/`0x03`（Life Safety）——frames 逐帧断言 control 字节与 `bacnet.control_prio_high`/`control_prio_low` 布尔组合（01=false,true；10=true,false；11=true,true；实测解码树逐位）。
16. **`bacnet_read_property`**（2）：帧 1（C→D）frames `81 0a 00 11 01 04 00 05 01 0c 0c 00000001 19 55`（实测同构）；`bacnet.control=0x04`、`bacapp.type=0`、`bacapp.max_adpu_size=5`、`bacapp.invoke_id=1`、`bacapp.confirmed_service=12`、`bacapp.objectType=0`、`bacapp.instance_number=1`、`bacapp.property_identifier=85`。帧 2（D→C）`81 0a 00 17 01 00 30 01 0c 0c 00000001 19 55 3e 44 41b40000 3f`（实测）；`bacapp.type=3`、`bacapp.invoke_id=1`（与请求同值，`same_as_packet`）、`bacapp.present_value.real=22.5`（大端 IEEE 754）。
17. **`bacnet_read_property_array_index`**（4）：事务 1 请求在用例 16 基础上追加 `29 01`（ctx2 下标 1，LVT 1，Length 0x13）；应答回显 `29 01` 后再 `[3]` 值；frames 断言 ctx2 字节 `2901` 两帧同值。事务 2 下标 0=整个数组（§8 合法边界）：请求 `81 0a 00 13 01 04 00 05 01 0c 0c 00000001 19 55 29 00`（实测逐字节）、应答 `81 0a 00 19 01 00 30 01 0c 0c 00000001 19 55 29 00 3e 44 41b40000 3f`（payload 25B=0x19，实测逐字节）；断言 frames 字节 `2900` 两帧同值 + `bacapp.present_value.real=22.5`。
18. **`bacnet_read_property_multiple`**（2）：帧 1（C→D）`81 0a 00 15 01 04 00 05 02 0e 0c 00000001 1e 09 55 09 4d 1f`（RPM：ctx0 对象 ID + **开[1]** `1e` + ctx0 属性 85 + ctx0 属性 77 + 闭[1] `1f`，payload 21B=0x15，实测逐字节——`19` 为 LVT1 错误形态，tshark 实证属性标签全丢失，已勘误）；`bacapp.confirmed_service=14`、`bacapp.objectType=0`、`bacapp.instance_number=1`。帧 2 ComplexACK 双属性值：`bacapp.property_identifier` `distinct_values=[85,77]`、`present_value.real=22.5` 与 `present_value.char_string=ai-1`（charset 0）。
19. **`bacnet_write_property`**（2）：帧 1（C→D）`81 0a 00 16 01 04 00 05 02 0f 0c 00000001 19 55 3e 11 3f 49 08`（实测同构：值开[3]+布尔 TRUE `11`+闭[3]+优先级 ctx4=8）；`bacapp.confirmed_service=15`、`bacapp.present_value.boolean=true`。帧 2（D→C）`81 0a 00 09 01 00 20 02 0f`（SimpleACK，实测）；`bacapp.type=2`、`bacapp.invoke_id=2`、`bacapp.confirmed_service=15`（回显服务选择）。
20. **`bacnet_write_property_no_priority`**（2）：请求同用例 19 但**无 `49 08` 尾巴**（[4] 缺省，缺省语义=优先级 16）；`udp.length` 比用例 19 帧 1 少 2；SimpleACK 正常返回。
21. **`bacnet_who_has_i_have`**（4）：事务 1 帧 1（C→D）frames `81 0a 00 0f 01 00 10 07 3d 05 00 61692d31`（Who-Has：ctx3 对象名 CharacterString `3d`=ctx3 LVT5 + 长度 5 + charset 0 + "ai-1"，payload 15B=0x0f）；`bacapp.unconfirmed_service=7`、`bacapp.object_name=ai-1`、`bacapp.string_character_set=0`。帧 2（D→C）I-Have：`bacapp.unconfirmed_service=1`、三个应用标签（设备 ID/对象 ID/对象名）`application_tag_number=12,12,7`。事务 2 **[2] 按对象 ID 分支**（§3.6 二选一）：帧 3（C→D）`81 0a 00 0d 01 00 10 07 2c 00000001`（ctx2 ObjectID analog-input:1，payload 13B=0x0d，实测逐字节）、帧 4（D→C）`81 0a 00 19 01 00 10 01 c4 02000064 c4 00000001 75 05 00 61692d31`（I-Have 应答同型，payload 25B=0x19，实测逐字节）；断言帧 3 `bacapp.objectType=0`、`bacapp.instance_number=1`、帧 4 标签列表 `12,12,7`。
22. **`bacnet_subscribe_cov`**（2）：帧 1（C→D）`81 0a 00 16 01 04 00 05 03 05 09 01 1c 02000005 29 01 3a 0258`（process 1 `0901`/对象 device:5/issue-confirmed TRUE `2901`/lifetime 600 `3a 0258`，payload 22B=0x16，实测逐字节）；`bacapp.confirmed_service=5`、`bacapp.processId=1`、`bacapp.objectType=8`、`bacapp.instance_number=5`。帧 2 SimpleACK（`20 03 05`）。
23. **`bacnet_cov_notification`**（1）：D→C 帧 `81 0a 00 22 01 00 10 02 09 01 1c 02000005 2c 02000005 3a 021c 4e 09 55 2e 44 41c00000 2f 4f`（[0]进程 1 `0901`、[1]发起设备 device:5、[2]对象 device:5、[3]剩余 540 `3a 021c`、开[4] `4e` {ctx0 属性 85 + **开[2] `2e`** + Real 24.0 `44 41c00000` + **闭[2] `2f`**} 闭[4] `4f`，payload 34B=0x22，实测逐字节——`1e/1f` 为 ctx1 误编，tshark 实证 real 解不出且出幻影字段，已勘误）；`bacapp.unconfirmed_service=2`、`bacapp.processId=1`、`bacapp.present_value.real=24.0`。
24. **`bacnet_subscribe_cov_cancel`**（2）：帧 1 仅 `[0]`+`[1]`（`09 01 1c 02000005`，[2][3] 均缺省=取消，payload 17B=0x11）；`udp.length` 比用例 22 帧 1 少 5（[2]+[3]=2B+3B）；帧 2 SimpleACK。
25. **`bacnet_device_communication_control`**（2）：帧 1（C→D）`81 0a 00 16 01 04 00 05 04 11 0a 0000 19 01 2d 05 00 70617373`（[0] duration 0 `0a 0000`、[1] disable=1 `1901`、[2] password "pass" `2d 05 00 70617373` 实占 7B，payload 22B=0x16，实测逐字节）；`bacapp.confirmed_service=17`；disable=1 由 frames hex `19 01` 断言（`present_value.enum_index` 在 DCC 上下文不可过滤，§1 注意④）。帧 2 SimpleACK（`20 04 11`）。
26. **`bacnet_error_response`**（4）：事务 1 帧 1 RP（invoke 5）同用例 16 形态；帧 2（D→C）`81 0a 00 0d 01 00 50 05 0c 91 02 91 20`（payload 13B=0x0d，实测同构）；`bacapp.type=5`、`bacapp.invoke_id=5`（`same_as_packet`）、`bacapp.confirmed_service=12`、`bacapp.error_class=2`、`bacapp.error_code=32`、`bacapp.application_tag_number=9,9`。事务 2 **code 40 组合**（write-access-denied，§3.6 组合子集）：帧 3 RP（invoke 6）、帧 4（D→C）`81 0a 00 0d 01 00 50 06 0c 91 02 91 28`（payload 13B=0x0d，实测逐字节）；断言 `bacapp.error_class=2`、`bacapp.error_code=40`、invoke 6 `same_as_packet`。
27. **`bacnet_reject`**（2）：帧 2（D→C）`81 0a 00 09 01 00 60 02 05`（payload 9B，实测）；`bacapp.type=6`、`bacapp.invoke_id=2`、`bacapp.reject_reason=5`。
28. **`bacnet_abort`**（2）：帧 2（D→C）`81 0a 00 09 01 00 71 02 0b`（payload 9B，SRV=1）；`bacapp.type=7`、`bacapp.SRV=true`、`bacapp.invoke_id=2`、`bacapp.abort_reason=11`。
29. **`bacnet_segmented_request`**（3）：分段 **WriteProperty** 请求，值 = 465B CharacterString（`75 fe 01d2 00` + 465B 内容，扩展长度档）：未分段 APDU = 485B > 协商 max-APDU 480B（码 3）→ 天然跨段，2 段 + SegmentACK。帧 1（C→D）首段 `81 0a 00 14 01 04 0c 23 06 00 02 0f 0c 00000001 09 55 3e`（APDU 首字节 `0c`=Confirmed-REQ+SEG+MOR，max-segs=2/max-APDU=480B `23`、invoke 6、seq 0、window 2、service 0f + ctx0 对象 ID + ctx1 属性 + 开[3]，payload 16B=0x14，实测逐字节）；`bacapp.segmented_request=true`、`bacapp.more_segments=true`、`bacapp.sequence_number=0`、`bacapp.window_size=2`、`bacapp.confirmed_service=15`。帧 2 末段（首字节 `08`=仅 SEG、MOR=0）`81 0a 01 e5 01 04 08 23 06 01 02 0f 75 fe 01d2 00 <465B 内容> 3f 49 08`（服务数据 473B + 头 6 + NPDU 2 + BVLC 4 = BVLC Length 485=0x1e5，实测逐字节解码）；断言 `bacapp.segmented_request=true`、`bacapp.more_segments=false`、`bacapp.sequence_number=1`、`bacapp.confirmed_service=15`、`bacapp.fragment.count=2`、`bacapp.reassembled.length=481`（两段服务数据 8+473，实测）。帧 3（D→C）SegmentACK `81 0a 00 0a 01 00 41 06 01 02`（payload 10B，**SRV=1 设备侧**，实测逐字节）；`bacapp.type=4`、`bacapp.SRV=true`、`bacapp.invoke_id=6`、`bacapp.sequence_number=1`、`bacapp.window_size=2`。（v2.0.0 原稿为 RP 请求末段携带 ctx3 值标签的形态——RP 请求无 ctx3 且 8B 不需分段，已勘误。）
30. **`bacnet_segmented_complex_ack`**（4）：帧 1（C→D）RP 请求（invoke 7）；帧 2（D→C）分段 ComplexACK 首段 `3c 07 00 04 0c 0c 00000001 19 55 3e`（SEG|MOR、invoke 7、seq 0、window 4、ACK 头+对象/属性+开[3]）；帧 3 末段 `38 07 01 04 0c 44 41b40000 3f`（仅 SEG、seq 1、Real+闭[3]）；帧 4（C→D）SegmentACK `81 0a 00 0a 01 00 40 07 01 04`（**SRV=0 客户端侧**；NPDU control 0x00 与用例 29 帧 3 统一——SegmentACK 不期望回复，实测）；断言 `bacapp.fragment.count=2`、`bacapp.reassembled.length` = 两段服务数据字节数和 14（8+6，实测重组行为）、`bacapp.sequence_number` `distinct_values=[0,1]`、SRV=0 由 frames 首字节 `40` 断言（布尔 false 在 `-T fields` 为空串，不走字段断言）。
31. **`bacnet_i_am_capabilities`**（3）：D→C 三帧 I-Am 能力变体（无符号最短式）：帧 1 `81 0a 00 15 01 00 10 00 c4 020000c8 22 0400 91 00 22 000f`（实例 200/max-APDU 1024/分段能力 0 both/厂商 15，实测逐字节）、帧 2 `81 0a 00 15 01 00 10 00 c4 020000c9 22 0400 91 01 22 000f`（实例 201/分段能力 1 transmit，实测逐字节）、帧 3 `81 0a 00 15 01 00 10 00 c4 020000ca 22 0400 91 02 22 000f`（实例 202/分段能力 2 receive，实测逐字节）；断言 `bacapp.objectType=8`、`bacapp.vendor_identifier=15`、`bacapp.instance_number` `distinct_values=[200,201,202]`；max-APDU 1024（`22 0400`）与分段能力 0/1/2（`91 00`/`91 01`/`91 02`）由 frames hex 断言（`present_value.uint` 在 I-Am 上下文不可过滤，§1 注意④；不与用例 1 做跨用例 distinct——用例独立回放，无合跑语义）。
32. **`bacnet_app_tag_encoding`**（3）：帧 1 RPM 请求（多属性）；帧 2（D→C）ComplexACK 承载 13 种应用标签值（Null `00`/Boolean `11`/Unsigned `21 2a`/Int `31 …`/Real `44 41b40000`/Double `55 40566000…`/OctetString `65 …`/CharString `75 …`/BitString `85 …`/Enumerated `91 …`/Date `a4 …`/Time `b4 …`/ObjectID `c4 02000064`）；断言 `bacapp.application_tag_number` 覆盖 `0,1,2,3,4,5,6,7,8,9,10,11,12`（distinct_values 全 13 值）、`present_value.real=22.5`、`present_value.uint`、`present_value.boolean`、`present_value.char_string`、`present_value.bit_string`、`present_value.octet_string` 各取值（Date/Time 用 frames hex 断言，§1 注意②）。帧 3（D→C）追加 ComplexACK 携 **Boolean FALSE**（`3e 10 3f`：开[3] + tag1 LVT=0=FALSE 无内容字节 + 闭[3]，D-2⑤）——Boolean 双值（TRUE `11`/FALSE `10`）全覆盖。
33. **`bacnet_object_id_boundary`**（4）：两笔 RP 事务——事务 1 对象 `analog-input:0`（实例 0），事务 2 对象实例 `0x3FFFFF`（4194303）+ 类型 128（私有，proprietar 域首值）；断言 `bacapp.instance_number` `distinct_values=[0,4194303]`、私有类型帧 `bacapp.objectType=128`、四帧 invoke 关联正确；frames 断言对象 ID 字节 `0c 00000000` 与 `0c 203fffff`（类型 128<<22 | 0x3FFFFF = 0x203FFFFF，大端）。
34. **`bacnet_invoke_id_boundary`**（4）：两笔 RP 事务 invoke 分别 0 与 255；`bacapp.invoke_id` `distinct_values=[0,255]`、每笔 ACK 与请求 invoke `same_as_packet`；frames 断言请求/应答 invoke 字节 `00`/`ff`。
35. **`bacnet_multi_transaction`**（6）：单会话序列 Who-Is→I-Am→RP(invoke 1)→ACK→WP(invoke 2)→ACK；断言 6 帧方向交替（C/D 端口互换）、`bacapp.invoke_id` 请求序列 `1,2`、ACK 回显 `1,2`、各帧服务选择正确（`8,0,12,12,15,15`）；事件序即帧序（声明式回放）。
36. **`bacnet_ipv6`**（2）：IPv6 fixture（`2001:db8::65 → 2001:db8::100:65`，端口 47808）；断言 `ipv6.nxt=17`、BVLC 首字节 offset **62**、Who-Is/I-Am 字节与用例 1 完全一致（同一逻辑报文，仅外层 IP 头不同，frames 62 起与用例 1 frames 42 起逐字节相同）；不得出现 `ip.version=4`。
37. **`bacnet_multi_session`**（4）：会话 1（客户端 A，设备实例 100）与会话 2（客户端 B，设备实例 300）各 Who-Is→I-Am；断言两流源 IP `distinct_values=[192.0.2.66,192.0.2.67]`、**会话 2 首包号 = 3**（多会话展开，前会话 2 包+1）、两会话 I-Am 实例 `distinct`、各自 invoke/事件状态不串用。
38. **`bacnet_large_charstring`**（2）：帧 1 RP（object-name 属性，invoke 8）；帧 2（D→C）ComplexACK 值为 1024B CharacterString：标签 `75 fe 0401 00`（LVT=5 + 长度标记 254 + 2 字节大端长度 1025=0x0401（charset 字节+1024 内容）+ charset 0）+ 1024B 内容；UDP payload = 4+2+3+5+2+1+4+1025+1 = 1047、`udp.length=1055`、帧 1089B <1518 单帧不分片；`bacapp.present_value.char_string` 长度 1024、`bacapp.LVT=5`、frames 断言扩展长度标记 `75 fe 04 01`。
39. **`bacnet_invoke_id_adjacent`**（4）：两笔 RP 事务 invoke 分别 **1（最小+1）与 254（最大-1）**；断言 `bacapp.invoke_id` `distinct_values=[1,254]`、每笔 ACK 与请求 invoke `same_as_packet`；frames 断言请求/应答 invoke 字节 `01`/`fe`。
40. **`bacnet_instance_adjacent`**（4）：两笔 RP 事务对象实例 **1 与 4194302（0x3FFFFE）**；frames 断言对象 ID 字节 `0c 00000001` 与 `0c 003ffffe`（大端）；`bacapp.instance_number` `distinct_values=[1,4194302]`。
41. **`bacnet_object_type_boundaries`**（4）：两笔 RP 事务对象类型 **127（标准末值）与 1023（10 位满值）**（实例取 1）；frames 断言对象 ID 字节 `0c 1fc00001`（127<<22|1）与 `0c 3fc00001`（1023<<22|1）；类型 1023 帧 `bacapp.objectType=1023`——与正例 33 的类型 0/128 构成标准域首末/私有域首末四点。
42. **`bacnet_priority_boundaries`**（4）：两笔 WP 事务优先级 **ctx4=1 与显式 16**（`49 01`/`49 10`）；与正例 20 缺省（无 [4]=语义 16）构成三种 wire 形态（显式 1/显式 16/缺省 16）；各→SimpleACK 正常返回；frames 断言尾字节 `4901`/`4910`。
43. **`bacnet_window_size_boundaries`**（7）：两笔分段 WriteProperty（各 2 段）：事务 1 **window=1**（逐段确认：seg0→SegmentACK→seg1→SegmentACK，4 帧）；事务 2 **window=255**（整窗确认：seg0→seg1→SegmentACK，3 帧）；frames 断言 APDU window 字节 `01`/`ff`——window 是**提议值不是实际段数**（§3.3），2 段报文可携 window 255；越域 0 由负例校验。
44. **`bacnet_vendor_id_max`**（1）：I-Am 厂商 ID **65535**（u16 上界，无符号最短式 `22 ffff`）；frames 断言 `22 ffff`（`present_value.uint` 在 I-Am 上下文不可过滤，§1 注意④）；`bacapp.vendor_identifier` 同理走 frames。
45. **`bacnet_ttl_max`**（2）：帧 1（C→D）`81 05 00 06 ff ff`；`bvlc.reg_ttl=65535`（u16 上界，与正例 5 的 600/0 构成常用值/0/上界三点）；帧 2 Result `0x0000`。
46. **`bacnet_port_nondefault`**（2）：显式声明 `src_port=dst_port=47809` 的 Who-Is→I-Am，**BACnet 字节与用例 1 完全一致**（同一逻辑报文，仅 UDP 端口不同）；断言 `udp.srcport=47809`、`udp.dstport=47809`；**非 47808 端口 tshark 不自动解码（§1 实测）——fields 断言须带 `-d udp.port==47809,bacnet` DecodeAs，或全 frames hex 断言**（hl7 #27 判例口径）；planner 不得静默改写端口（负例 35 校验未声明即拒）。
47. **`bacnet_concurrent_sessions`**（4）：`concurrent: true` 双客户端（A `192.0.2.66` / B `192.0.2.67`）交错回放各自 Who-Is→I-Am；断言两会话**交错**（帧序源 IP 交替出现，非整块串行）、各自 I-Am 事务配对完整、设备实例（100/300）与事件状态互不串用——单会话内事件序仍受 §5 状态机约束，并发只作用于生成器级多连接交错（判例口径）；与正例 37 多会话按序整块展开分立。
48. **`bacnet_who_has_limits`**（2）：Who-Has 携 **[0] low-limit 与 [1] high-limit 范围过滤对**（0/100）+ [2] 对象 ID 分支；→I-Have；frames 断言 ctx0/ctx1 限值标签字节 `09 00`/`19 64` 与 ctx2 `2c`——[0][1] 成对出现（§3.6），与正例 21 的无范围形态分立。
49. **`bacnet_rpm_multi_object`**（2）：RPM 请求 **双对象**（analog-input:1 与 device:5，各双属性 85/77）：两个 ReadAccessSpecification 依次 [0]对象+开[1]{属性对}闭[1]；ComplexACK 应答双对象多值；断言 `bacapp.objectType` `distinct_values=[0,8]`、`bacapp.instance_number` `distinct_values=[1,5]`、`property_identifier` 覆盖 [85,77]——与正例 18 单对象双属性分立（§3.6"可重复多对象"）。
50. **`bacnet_dcc_variants`**（6）：三笔 DCC 事务：① **enable(0)** 带 [0] duration 30（`19 00`+`0a 1e`）；② **disable-initiation(2)** 带 [0] duration 0（`19 02`）；③ **[0] time-duration 缺省** + disable(1)（帧内无 `0a` 字节，`19 01`）；各→SimpleACK；frames 断言 [1] 枚举字节 `1900`/`1902`/`1901` 与 ③ 无 [0] 字节形态——三变体与正例 25（disable+duration+password）构成 §3.6 三值枚举+[0]可选全形态。
51. **`bacnet_subscribe_cov_unconfirmed`**（2）：SubscribeCOV 携 [0] process/[1] 对象/**[2] issue-confirmed=false（`29 00`，存在且 FALSE）**/[3] lifetime；→SimpleACK；frames 断言 `2900`——与正例 22（[2] 存在且 TRUE `2901`）、正例 24（[2][3] 均缺省=取消）构成 [2] 三种 wire 形态（存在 TRUE/存在 FALSE/缺省）。
52. **`bacnet_confirmed_request_sa`**（2）：RP 请求 APDU 首字节 **SA bit1=1（`02`=类型 0+SA）**：客户端宣告可接受分段响应；→ComplexACK（非分段，SA 只是能力声明）；frames 断言首字节 `02`（与正例 16 的 `00` 对照）——§3.3 表 bit1 语义的唯一直接证据例。
53. **`bacnet_npdu_global_broadcast`**（1）：Who-Is 携 control 0x20 + **DNET=0xFFFF + DLEN=0 + HopCount 0xFF**（全局广播：向所有网络广播）；frames `81 0a 00 0c 01 20 ff ff 00 ff 10 08`；`bacnet.dnet=65535`、`bacnet.dlen=0`、`bacnet.hopc=255`——与正例 12 的远程定向 DNET 2001 分立；**NPDU 路由 DNET 与用例 14 NLM 消息体内 DNET 字节同形不同义**（设计 §3.2 声明，本例钉死路由侧语义）。
54. **`bacnet_bdt_multi_entry`**（4）：帧 1（C→D）Write-BDT **2 表项**（`81 01 00 18 <表项1 10B><表项2 10B>`，Length=4+10×2=0x18）；帧 2 Result `0x0000`；帧 3 Read-FDT（`81 06 00 04`）；帧 4 Read-FDT-Ack **2 表项**（`81 07 00 18 <10B><10B>`）；frames 断言两功能 Length 字节 `00 18`；`bvlc.bdt_ip` `distinct_values=[192.0.2.88,192.0.2.90]`、`bvlc.fdt_ip` distinct 两值——N=0 空表（Length=4）为 §8 声明边界，N=1 由正例 7/9 覆盖。
55. **`bacnet_charstring_ucs2`**（2）：帧 1 RP（object-name，invoke 9）；帧 2（D→C）ComplexACK 值为 **charset 4（UCS-2）** CharacterString：`75 03 04 4e2d`（tag7 LVT=3：1B charset `04` + 2B UCS-2 内容 `4e2d`）；断言 `bacapp.string_character_set=4`、frames 断言 `7503 044e2d`——与正例 18 的 charset 0（ANSI）分立，覆盖 §3.4 字符集值域两种形态。

**正例总则**：每条实现后至少含 `packet_count`（或 `min_packets`）+ 载体与方向断言 + `has_payload=true` + fields/frames 断言；帧 hex 均可由设计 §3 公式 + fixture 常量精确预算（"实测"标注者已经构造 pcap 验证）；动态值只用存在与关联断言（`same_as_packet`/`distinct_values`/`nonzero`）。合法协议事件（BVLC-Result NAK、Error/Reject/Abort 应答、Who-Is 无参数、无优先级写入、COV 取消、数组下标 0、max-segs=0、空字符串）均为正例形态，只有配置、线格式、状态、关联、长度错误进入负例（设计 §7）。**合并变体与代表值声明（v2.1 更新）**：同形值域变体并入现有例多帧——Who-Has [2] 分支、数组下标 0、DLEN=0、TTL=0、分段能力 1/2、Error code 40、Boolean FALSE 分别并入正例 21/17/12/5/31/26/32。**v2.1 由声明升格为例的值域**（C-4/C-5/D-2/D-3/N-3）：charset 4（正例 55）、优先级边界 1/显式 16（42）、invoke 1/254（39）、实例 1/0x3FFFFE（40）、类型 127/1023（41）、window 1/255（43）、厂商 ID 65535（44）、TTL 65535（45）、非默认端口 47809（46）、SA bit（52）、全局广播 DNET 0xFFFF（53）、BDT/FDT 多表项（54）、Who-Has 范围对（48）、RPM 双对象（49）、DCC 三变体（50）、COV issue-confirmed=false（51）、并发会话（47）。**仍按设计 §8 代表值策略只测代表值、不逐值设例**——LVT 255 四字节长度档（内容 >65535B 单帧不可达）、SegmentACK NAK bit1（正例 29/30 覆盖非 NAK 形态，字段一致性由负例校验）、max-segs=0（每笔确认请求 max-segs/max-APDU 字节高 4 位即 0，如 `00 05`/`0c 23`，全确认服务正例覆盖）、BVLC-Result NAK 其余 5 码（0x0010/0x0020/0x0040/0x0050/0x0060，正例 6 测 0x0030 代表）、Reject/Abort/Error 码族其余值（正例 26/27/28 各测 1–2 代表值，码表值域为设计 §8 声明、validator 校验兜底）、max-APDU 码 0/1/2/4（正例 1/31 覆盖码 5/4，其余档位 §8 声明）。

## 5. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 UDP 外壳的假成功；执行期 `expect` 键集合**严格为** `{expect_error, error_contains}`。**逐故障输入原子拆分（C-3）：一行一例，钉死该行注入的单一 `wire_fault`/配置变异；主锚词为钉死的单一字面值**（不再是候选列表），与设计 §7 表一一对应（42 行同序）：

| # | ID | `wire_fault` 注入口 | 故障输入（单一注入） | 主锚词 |
|---:|---|---|---|---|
| 56 | `bacnet_neg_bvlc_type` | `bvlc_type` | BVLC Type ≠0x81（如 0x80/0x82/0xFF） | `type` |
| 57 | `bacnet_neg_bvlc_function` | `bvlc_function` | BVLC Function ∉0x00–0x0B 明文功能域（如 0x0D/0xFF） | `function` |
| 58 | `bacnet_neg_bvlc_secure` | `bvlc_secure` | Secure-BVLL 0x0C 被当明文产生（§1 边界：只观察外层） | `secure` |
| 59 | `bacnet_neg_bvlc_length_min` | `bvlc_length_min` | BVLC Length <4（如 3，头自身都不完整） | `length` |
| 60 | `bacnet_neg_bvlc_length_mismatch` | `bvlc_length_mismatch` | BVLC Length ≠ 4+功能负载实际字节（如 >UDP payload） | `length` |
| 61 | `bacnet_neg_bvlc_length_forwarded` | `bvlc_length_forwarded` | Forwarded-NPDU(0x04) Length 未计入 6B 原始源地址 | `length` |
| 62 | `bacnet_neg_npdu_version` | `npdu_version` | NPDU Version ≠0x01（如 0x00/0x02） | `version` |
| 63 | `bacnet_neg_npdu_dest_missing` | `npdu_dest_missing` | Control bit5=1 而 DNET/HopCount 缺失 | `dnet` |
| 64 | `bacnet_neg_npdu_src_len_zero` | `npdu_src_len_zero` | Control bit3=1 而 SLEN=0（源长度不能为空） | `snet` |
| 65 | `bacnet_neg_npdu_reserved_bits` | `npdu_reserved_bits` | Control 保留位 bit6/bit4 置 1（恒 0） | `control` |
| 66 | `bacnet_neg_npdu_no_message_type` | `npdu_no_message_type` | Control bit7=1 而 Message Type 缺失 | `control` |
| 67 | `bacnet_neg_npdu_dlen_invalid` | `npdu_dlen_invalid` | DLEN ∉{0,6}（BACnet/IP 合法域；如 DLEN=1，其他值属其他链路 MAC 长度，本版不产生——D-3③） | `dlen` |
| 68 | `bacnet_neg_apdu_type_invalid` | `apdu_type_invalid` | APDU 首字节高 4 位 >7（如 0x80–0xFF） | `apdu` |
| 69 | `bacnet_neg_apdu_header_confirmed` | `apdu_header_confirmed` | Confirmed-Request 头部不完整（缺 max-segs 字节，仅 2 字节） | `header` |
| 70 | `bacnet_neg_apdu_header_simpleack` | `apdu_header_simpleack` | SimpleACK <3 字节（仅 2 字节） | `header` |
| 71 | `bacnet_neg_service_confirmed_unimplemented` | `service_confirmed_unimplemented` | Confirmed Service Choice 不在 §1 子集（如 34 ReadRange） | `service` |
| 72 | `bacnet_neg_service_unconfirmed_invalid` | `service_unconfirmed_invalid` | Unconfirmed Service Choice ∉{0,1,2,7,8}（如 3） | `service` |
| 73 | `bacnet_neg_tag_lvt_mismatch` | `tag_lvt_mismatch` | LVT=4 而内容仅 2 字节（长度与内容不符） | `lvt` |
| 74 | `bacnet_neg_tag_open_unmatched` | `tag_open_unmatched` | 开标签无同号闭标签配对（如 0x3E 无 0x3F） | `tag` |
| 75 | `bacnet_neg_tag_boolean_lvt` | `tag_boolean_lvt` | Boolean 应用标签 LVT=2（合法仅 0=FALSE/1=TRUE） | `tag` |
| 76 | `bacnet_neg_tag_context_number` | `tag_context_number` | 上下文标签号超出服务 ASN.1 定义 | `tag` |
| 77 | `bacnet_neg_object_type_overflow` | `object_type_overflow` | 对象类型 >1023（10 位溢出，如 1024） | `object` |
| 78 | `bacnet_neg_object_instance_overflow` | `object_instance_overflow` | 对象实例 >4194303（22 位溢出，如 4194304） | `instance` |
| 79 | `bacnet_neg_object_iam_not_device` | `object_iam_not_device` | I-Am 设备标识对象类型 ≠8（device） | `object` |
| 80 | `bacnet_neg_property_id_vendor` | `property_id_vendor` | 属性 ID >511 而未声明厂商私有（如 512/0xFFFFF） | `property` |
| 81 | `bacnet_neg_property_index_negative` | `property_index_negative` | 数组下标为负（如 -1） | `property` |
| 82 | `bacnet_neg_priority_range` | `priority_range` | WriteProperty 优先级 ∉1–16（如 0/17） | `priority` |
| 83 | `bacnet_neg_error_class_range` | `error_class_range` | error-class 越域（合法 0–7 与 64–65535；如 8 或 65536）——D-3⑦ | `error` |
| 84 | `bacnet_neg_invoke_mismatch` | `invoke_mismatch` | 应答（ACK/Error/Reject/Abort/SegmentACK）Invoke ID ≠ 触发请求的 Invoke ID | `invoke` |
| 85 | `bacnet_neg_invoke_reuse` | `invoke_reuse` | 同一会话未完成事务期间复用同一 Invoke ID | `invoke` |
| 86 | `bacnet_neg_segment_extra_fields` | `segment_extra_fields` | SEG=0 却携带 Sequence Number/Window Size 字段 | `segment` |
| 87 | `bacnet_neg_segment_missing_fields` | `segment_missing_fields` | SEG=1 缺 Sequence Number/Window Size 字段 | `segment` |
| 88 | `bacnet_neg_segment_window_zero` | `segment_window_zero` | Proposed Window Size=0（合法 1–255） | `window` |
| 89 | `bacnet_neg_segment_sequence_skip` | `segment_sequence_skip` | Sequence Number 回绕/跳变（非窗口内单调递增） | `sequence` |
| 90 | `bacnet_neg_carrier_layer_missing` | `carrier_layer_missing` | 层链缺 udp（`[{"bacnet":{}}]` 直连） | `carrier` |
| 91 | `bacnet_neg_carrier_tcp` | `carrier_tcp` | TCP 载体声明（BACnet/IP 仅 UDP，Annex J） | `carrier` |
| 92 | `bacnet_neg_port_undeclared` | `port_undeclared` | 端口 ≠47808 而未显式声明（静默回退禁止） | `port` |
| 93 | `bacnet_neg_address_family_mismatch` | `address_family_mismatch` | IPv6 地址配 IPv4 层链（`[ip,udp,…]` 形态） | `family` |
| 94 | `bacnet_neg_address_family_derived` | `address_family_derived` | 从 IPv4 fixture 推导 IPv6 地址（须独立 fixture） | `address` |
| 95 | `bacnet_neg_state_ack_no_request` | `state_ack_no_request` | ACK/Error 事件无前置确认请求 | `state` |
| 96 | `bacnet_neg_state_iam_no_whois` | `state_iam_no_whois` | I-Am 事件无前置 Who-Is（自动应答关闭时） | `state` |
| 97 | `bacnet_neg_state_cov_no_subscribe` | `state_cov_no_subscribe` | COV 通知事件无前置订阅 | `state` |

合法协议事件不进负例（防误报，同设计 §7 防误报清单）：BVLC-Result NAK、Error/Reject/Abort 应答、Who-Is 无参数、缺省优先级、COV 取消、数组下标 0、max-segs=0、空字符串。

## 6. 五层覆盖映射

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 1–28、31、48–52、54（正）；56–97（负） | 12 种 BVLC 功能每功能正例（+多表项 54）、8 种 APDU 类型（0/1/2/3/4/5/6/7 分别由 16/1/19/16/29/26/27/28 覆盖，+SA bit 52）、10 服务每服务正例（+Who-Has 范围对 48/RPM 双对象 49/DCC 三变体 50/COV 三形态 22/51/24）、NLM 1 对、失败路径 4 形态（NAK/Error/Reject/Abort）；负例 42 行逐故障输入与设计 §7 同序 |
| 性能 | 2、29、30、38、43 | 最小帧 8B、APDU 分段双向跨段（seq/window/SegmentACK/重组）、window 边界 1/255（43）、1024B 大字符串（扩展长度档、单帧 1476 内上界）；发包速率由框架既有配置承载（v1.1 §10 口径） |
| 数据场景 | 15、17、20、24、31、32、33、34、39–42、44、45、48、50、51、53、55；负 67/77–83/88 | 13 种应用标签全枚举（含 Boolean 双值）、LVT 三档、charset 0/4（55）、NPDU 优先级 4 值、数组下标/优先级/COV [2][3] 条件缺省、I-Am 能力变体（0/1/2）、边界族：对象 ID（0/满值 33 + 相邻 40/41）、Invoke ID（0/255 34 + 相邻 39）、优先级 1/16（42）、window 1/255（43）、厂商 65535（44）、TTL 0/600/65535（5/45）、DNET 2001/0xFFFF（12/53）、SA bit（52）；非法值拒绝（负例 67/77–83/88 值域类）；仍只测代表值的部分见设计 §8 与 §4 正例总则声明 |
| 地址与流 | 1（v4 单流基线）、36（v6）、37（多会话双四元组按序展开）、47（并发交错）、46（非默认端口 47809+DecodeAs）、12/13/53（NPDU 层路由地址） | v4+v6 必覆盖；**并发会话 v2.1 翻案纳入**（47，`concurrent: true`）；流关联显式不适用保留（设计 §4：单 UDP 流承载全部信令与数据，无控制/数据分离）；非默认端口显式声明合法通道（46） |
| 业务 | 1/3/21/48（发现）、16–18/49（轮询/批量）、19/20/42（控制下发）、22–24/51（COV 订阅告警）、25/50（远程管理）、26–28/6（失败路径）、35（单客户端多事务）、37（多客户端按序）、47（多客户端并发运营） | 楼宇自控现网日常场景优先（发现-轮询-控制-订阅-管理链）；多 BMS 并发轮询（47）为 BAS 常态 |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/bacnet.json` 通过；当前数组恰含 1 条 `bacnet_neg_unregistered`：`proto=bacnet`、层链 `[{"udp":{}},{"bacnet":{}}]`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
2. 实现注册 `bacnet` 层后：移除占位，按 §2 顺序补入 97 个语义用例；**ID 权威 = 本文 §2**（设计 §9 为簇级覆盖图景+权威指针，v2.1 D-1），`bacnet.json` 与本文 §2/§8 三方同序（脚本核验）。
3. 正例每条含 `packet_count`（或 `min_packets`）+ `fields` + `frames`；`fields` 只用 §1 实测存在的 tshark 字段（`bvlc.*`/`bacnet.*`/`bacapp.*`/`udp.*`/`ip.version`/`ipv6.nxt`/`frame.*`）；**线上 BVLC Length 不用 `bvlc.length` 字段断言**（计算值，§1 注意①），走 frames offset 44–45 或 `udp.length` 换算。
4. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields。
5. 正例不携带 `has_handshake`/`terminates`（UDP 无连接，恒 false）；跨会话断言用源 IP + 多会话展开起点规则（§3.4），不硬编码全局包号；动态值用 `same_as_packet`/`distinct_values`/`nonzero`。
6. 端口 47808 为默认断言通道（tshark 自动解码依赖，§1 实测）；非默认端口（46）**显式声明即合法**——fields 断言须带 `-d udp.port==47809,bacnet` DecodeAs 或走 frames hex（§1 注意⑤）；未显式声明的非 47808 端口仍拒（负例）。
7. 若实现期实证发现设计 §3 布局与真实行为不符（如 Date/Time 标签字段细节），设计 §3 与本文 §4 对应断言同步校准，并在两文档修订记录登记。
8. **注册时 JSON notes 同步修正项**（v2.0.1 登记，本版不改 JSON）：当前 `bacnet.json` 占位条目的 notes 仍写旧稿口径的"20 条/14+6"等统计，实现注册 `bacnet` 层、按 §2 顺序补入 97 个语义用例时，必须同步把每条 notes 改写为本文 §2 对应行的覆盖描述（并核对 packet_count 与断言通道），不得保留占位期陈旧 notes。
9. **pcap/NIC 双输出（C-2）**：两输出路径共用本契约（同一 cases JSON、同一 tshark 字段/frames 断言），NIC 路径抓包口差异不改变断言语义；不设仅单路径可用的断言。
10. **负例原子性（C-3）**：42 行负例每行恰注入一个故障；`wire_fault` 取值集合 = §5 表 42 值（三方同序：设计 §6 枚举/§7 表/本文 §5 表）；主锚词为单一钉死字面值，无候选列表。

## 8. 三方一致性表

设计 §9（簇级图景）、本文 §2、实现后 `bacnet.json` 保持同一 97 个语义 ID、同一顺序（当前 JSON 另有占位，不计入）：

```text
bacnet_bvlc_unicast_baseline
bacnet_min_frame
bacnet_bvlc_broadcast
bacnet_bvlc_forwarded
bacnet_bvlc_register_foreign
bacnet_bvlc_result_nak
bacnet_bvlc_write_bdt
bacnet_bvlc_read_bdt
bacnet_bvlc_read_fdt
bacnet_bvlc_delete_fdt
bacnet_bvlc_distribute_broadcast
bacnet_npdu_dest_address
bacnet_npdu_src_address
bacnet_npdu_router_discovery
bacnet_npdu_priority
bacnet_read_property
bacnet_read_property_array_index
bacnet_read_property_multiple
bacnet_write_property
bacnet_write_property_no_priority
bacnet_who_has_i_have
bacnet_subscribe_cov
bacnet_cov_notification
bacnet_subscribe_cov_cancel
bacnet_device_communication_control
bacnet_error_response
bacnet_reject
bacnet_abort
bacnet_segmented_request
bacnet_segmented_complex_ack
bacnet_i_am_capabilities
bacnet_app_tag_encoding
bacnet_object_id_boundary
bacnet_invoke_id_boundary
bacnet_multi_transaction
bacnet_ipv6
bacnet_multi_session
bacnet_large_charstring
bacnet_invoke_id_adjacent
bacnet_instance_adjacent
bacnet_object_type_boundaries
bacnet_priority_boundaries
bacnet_window_size_boundaries
bacnet_vendor_id_max
bacnet_ttl_max
bacnet_port_nondefault
bacnet_concurrent_sessions
bacnet_who_has_limits
bacnet_rpm_multi_object
bacnet_dcc_variants
bacnet_subscribe_cov_unconfirmed
bacnet_confirmed_request_sa
bacnet_npdu_global_broadcast
bacnet_bdt_multi_entry
bacnet_charstring_ucs2
bacnet_neg_bvlc_type
bacnet_neg_bvlc_function
bacnet_neg_bvlc_secure
bacnet_neg_bvlc_length_min
bacnet_neg_bvlc_length_mismatch
bacnet_neg_bvlc_length_forwarded
bacnet_neg_npdu_version
bacnet_neg_npdu_dest_missing
bacnet_neg_npdu_src_len_zero
bacnet_neg_npdu_reserved_bits
bacnet_neg_npdu_no_message_type
bacnet_neg_npdu_dlen_invalid
bacnet_neg_apdu_type_invalid
bacnet_neg_apdu_header_confirmed
bacnet_neg_apdu_header_simpleack
bacnet_neg_service_confirmed_unimplemented
bacnet_neg_service_unconfirmed_invalid
bacnet_neg_tag_lvt_mismatch
bacnet_neg_tag_open_unmatched
bacnet_neg_tag_boolean_lvt
bacnet_neg_tag_context_number
bacnet_neg_object_type_overflow
bacnet_neg_object_instance_overflow
bacnet_neg_object_iam_not_device
bacnet_neg_property_id_vendor
bacnet_neg_property_index_negative
bacnet_neg_priority_range
bacnet_neg_error_class_range
bacnet_neg_invoke_mismatch
bacnet_neg_invoke_reuse
bacnet_neg_segment_extra_fields
bacnet_neg_segment_missing_fields
bacnet_neg_segment_window_zero
bacnet_neg_segment_sequence_skip
bacnet_neg_carrier_layer_missing
bacnet_neg_carrier_tcp
bacnet_neg_port_undeclared
bacnet_neg_address_family_mismatch
bacnet_neg_address_family_derived
bacnet_neg_state_ack_no_request
bacnet_neg_state_iam_no_whois
bacnet_neg_state_cov_no_subscribe
```

## 9. 修订记录

- v2.1.0（2026-09-01，v1.3 行为面全枚举重审修复轮）：rr-bacnet 181 点重审（✓123/半23/✗35；10 条 confirmed）后重出：53 → **97 例（55 正 + 42 负）**。关键修复：**C-1**（CRITICAL）并发会话翻案纳入——废除"UDP 无连接故不适用"声明（与 megaco #45 UDP 判例相斥），新增 `concurrent: true` 正例 47；**C-2**（CRITICAL）pcap/NIC 双输出同一契约声明补入（§1/§7.9）；**C-3**（CRITICAL）负例原子拆分 15→42 行（一行一故障、主锚词钉死单一字面值、`wire_fault` 42 值三方同序）；**C-4** 边界相邻值正例簇 39-45（invoke 1/254、实例 1/0x3FFFFE、类型 127/1023、优先级 1/显式 16、window 1/255、厂商 65535、TTL 65535）；**C-5** 非默认端口正例 46（47809 + `-d` DecodeAs，§1 注意⑤）；**D-1** ID 权威改本文 §2（设计 §9 改簇级图景）；**D-2** 五处声明形态补例：Who-Has 范围对（48）、RPM 双对象（49）、DCC 三变体（50）、COV issue-confirmed=false（51）、Boolean FALSE（并入 32 帧 3）；**D-3** 值域缺口：SA bit 例（52）、全局广播 DNET 0xFFFF 例（53，与 NLM 体 DNET 同形不同义区分声明）、BDT/FDT 多表项例（54）、error-class 越域负例、扩展标签 0xF/DLEN≠0/6/Vendor NLM≥0x80/码族代表值策略为设计 §8 声明；**N-1** IPv6 fixture 地址端口分离书写；**N-2** UDP 无连接 RST/保活/重连不适用与 TSM 重传 events[] 编排口径声明（§1）；**N-3**（拍板按判例升格）charset 4（55）与优先级 1/16（42）升格正例。既有 38 例编号与断言不变（仅 32 增帧 3）。

- v1.0.0（2026-08-20）：旧稿首版（14 正 + 6 负，粗粒度语义用例，无线格式断言细节）。
- v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代旧稿（旧稿见 git 历史）。以 bacnet-stack 参考实现 + 本机 tshark 3.6.14 构造 pcap 实证为基线重排为 53 条（38 正 + 15 负）：每 BVLC 功能、每 NPDU 变体、每 APDU 类型、每服务、每标签族、每关联规则、每边界（最小帧 8B/Invoke 0/255/实例 0/0x3FFFFF/私有类型 128/优先级 1–16/1024B 字符串扩展长度档）各一例，负例 15 类锚词逐类与设计 §7 对应同序；索引表五列格式（覆盖列引用设计 § 编号）；实测固化三条断言通道注意（`bvlc.length` 为计算值、无 present_value.date/time 字段、多值字段逗号分隔）、端口 47808 解码硬约束、UDP 无连接（无握手/挥手、每数据报 1 包、多会话展开包号规则）；§4 每例给出按设计 §3 公式预算的帧 hex（"实测"标注者已经构造 pcap 逐字节验证）；新增 §6 五层映射、§8 三方一致性表。状态：**待独立隔离审查**。
- v2.0.1（2026-09-01）：按独立隔离审查 14 项问题清单（8 MAJOR + 6 MINOR）逐项修复，全部帧字节改动经构造 pcap + tshark 3.6.14 复验可解码且值正确：B01 用例 22 帧 1 BVLC Length 0x17→0x16（payload 22B）、用例 24 差值"少 6"→"少 5"；B02 用例 23 Length 0x23→0x22、值包裹标签 `1e/1f`→`2e/2f`（ctx2 开闭，实证 `1e` 时 real 不可解且出幻影字段）；B03 用例 25 帧 1 Length 0x17→0x16（密码 ctx2 实占 7B）；B04 用例 18 开[1] `19`→`1e`（实证 `19` 时属性标签全丢失）；B05 删除/改写用例 1/25/31 的 `present_value.uint`/`present_value.enum_index` 不可过滤断言（§1 新增实测注意④），改 frames hex 断言；B06 用例 14 帧 2 NPDU control 0x00→0x80（网络层消息必须 bit7=1，帧 `81 0a 00 09 01 80 01 07 d1`）；B07 用例 29 由"RP 请求末段带 ctx3"改为天然跨段的分段 WriteProperty（465B CharacterString，未分段 APDU 485B > max-APDU 480B，seg1 14B/seg2 479B，reassembled.length=481 实测）；B09 用例 29 帧 3 SegmentACK SRV=1（`41`）、用例 30 帧 4 NPDU control 0x04→0x00 统一口径（SRV=0 由 frames `40` 断言）；B10 I-Am 全部改无符号最短式（`22 05c4`/`22 000f`/`22 0400`，用例 1/13/31 帧同步，I-Am payload 23→21B、帧 65→63B）；B11 同形变体并入多帧（用例 5 TTL=0、12 DLEN=0、17 下标 0、21 Who-Has[2]、26 Error code 40、31 分段能力 1/2，packet_count 相应 4/2/4/4/4/3），其余值域在设计 §8 代表值策略声明；B12 删用例 31 跨用例 distinct_values；B13 负例 44 统一为设计表述"Unconfirmed 不在 {0,1,2,7,8}"；B14 §7 新增注册时 JSON notes 同步修正项（本版不改 JSON）。状态：**审查修复完成、待复验关闭**。

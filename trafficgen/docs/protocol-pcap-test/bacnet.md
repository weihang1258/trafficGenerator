# bacnet Pcap Test Results

Cases: 97 — pass 97, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| bacnet_abort | Abort 应答（71 02 0b，SRV=1 设备侧） | pass | 2 | [pcap](bacnet/bacnet_abort.pcap) |
| bacnet_app_tag_encoding | ComplexACK 承载 13 种应用标签值（标签 0-12 逐一：null/bool/uint/int/real/double/octet/char/bit/enum/date/time/objectID）+ 追加 Boolean FALSE（10 无内容字节） | pass | 4 | [pcap](bacnet/bacnet_app_tag_encoding.pcap) |
| bacnet_bdt_multi_entry | Write-BDT 双表项（len 0x18）+ Read-FDT-Ack 双表项 | pass | 4 | [pcap](bacnet/bacnet_bdt_multi_entry.pcap) |
| bacnet_bvlc_broadcast | 定向广播 Who-Is（0x0b）→ 双 I-Am（实例 100/200 distinct） | pass | 3 | [pcap](bacnet/bacnet_bvlc_broadcast.pcap) |
| bacnet_bvlc_delete_fdt | Delete-FDT-Entry（6B 外部设备地址）→ Result | pass | 2 | [pcap](bacnet/bacnet_bvlc_delete_fdt.pcap) |
| bacnet_bvlc_distribute_broadcast | Distribute-Broadcast（0x09 承载 Who-Is，静默转发无 Result） | pass | 1 | [pcap](bacnet/bacnet_bvlc_distribute_broadcast.pcap) |
| bacnet_bvlc_forwarded | BBMD Forwarded-NPDU（0x04）：6B 原始源地址 192.0.2.99:47808 + 内层 Who-Is | pass | 1 | [pcap](bacnet/bacnet_bvlc_forwarded.pcap) |
| bacnet_bvlc_read_bdt | Read-BDT（无负载 len 4）→ Ack 单表项 | pass | 2 | [pcap](bacnet/bacnet_bvlc_read_bdt.pcap) |
| bacnet_bvlc_read_fdt | Read-FDT → Ack 表项（192.0.2.99 TTL 300 超时 120） | pass | 2 | [pcap](bacnet/bacnet_bvlc_read_fdt.pcap) |
| bacnet_bvlc_register_foreign | RFD TTL 600 与 0（立即到期合法边界）→ Result 0x0000 ×2 | pass | 4 | [pcap](bacnet/bacnet_bvlc_register_foreign.pcap) |
| bacnet_bvlc_result_nak | RFD→Result 0x0030（Register-FD NAK 合法错误路径） | pass | 2 | [pcap](bacnet/bacnet_bvlc_result_nak.pcap) |
| bacnet_bvlc_unicast_baseline | Who-Is(0-100)→I-Am 单播基线：BVLC 0x0a/len12、I-Am u16 宽度 22 000f、厂商 15 | pass | 2 | [pcap](bacnet/bacnet_bvlc_unicast_baseline.pcap) |
| bacnet_bvlc_write_bdt | Write-BDT 单表项（192.0.2.88:47808 掩码 /24）→ Result | pass | 2 | [pcap](bacnet/bacnet_bvlc_write_bdt.pcap) |
| bacnet_charstring_ucs2 | charset 4（UCS-2）CharacterString：7505 04 4e2d6587 | pass | 2 | [pcap](bacnet/bacnet_charstring_ucs2.pcap) |
| bacnet_concurrent_sessions | concurrent 双客户端交错（up 帧源 IP 交替，各自事务配对完整） | pass | 4 | [pcap](bacnet/bacnet_concurrent_sessions.pcap) |
| bacnet_confirmed_request_sa | Confirmed-REQ 首字节 SA bit1=1（02）客户端声明接受分段响应 | pass | 2 | [pcap](bacnet/bacnet_confirmed_request_sa.pcap) |
| bacnet_cov_notification | UnconfirmedCOVNotification 单帧（开[4] ctx0 属性+开[2] Real 24.0 闭[2] 闭[4]） | pass | 1 | [pcap](bacnet/bacnet_cov_notification.pcap) |
| bacnet_dcc_variants | DCC 三变体：enable+duration 30 / disable-initiation+duration 0 / 缺省 [0]+disable 1 | pass | 6 | [pcap](bacnet/bacnet_dcc_variants.pcap) |
| bacnet_device_communication_control | DCC duration 0+disable 1+password pass（[2] ctx3 CharacterString 实占 7B） | pass | 2 | [pcap](bacnet/bacnet_device_communication_control.pcap) |
| bacnet_error_response | Error 应答 invoke 配对（class 2 property + code 32/40 两组合） | pass | 4 | [pcap](bacnet/bacnet_error_response.pcap) |
| bacnet_i_am_capabilities | I-Am 能力三变体（分段能力 0/1/2 + max-APDU 1024，无符号最短式） | pass | 3 | [pcap](bacnet/bacnet_i_am_capabilities.pcap) |
| bacnet_instance_adjacent | 实例 1 与 4194302（0x3FFFFE）相邻值 | pass | 4 | [pcap](bacnet/bacnet_instance_adjacent.pcap) |
| bacnet_invoke_id_adjacent | Invoke 1 与 254 相邻值（ACK 回显） | pass | 4 | [pcap](bacnet/bacnet_invoke_id_adjacent.pcap) |
| bacnet_invoke_id_boundary | Invoke ID 0 与 255 边界（ACK 回显 same_as_packet） | pass | 4 | [pcap](bacnet/bacnet_invoke_id_boundary.pcap) |
| bacnet_ipv6 | IPv6 承载（2001:db8::65→2001:db8::100:65）：BVLC 首字节 offset 62，字节与用例 1 一致 | pass | 2 | [pcap](bacnet/bacnet_ipv6.pcap) |
| bacnet_large_charstring | 1024B CharacterString（扩展长度档 fe 0401）单帧 1089B 不分片 | pass | 2 | [pcap](bacnet/bacnet_large_charstring.pcap) |
| bacnet_min_frame | 无参数 Who-Is 8B BACnet/IP 最小帧（低/高限缺省，字段缺失断言） | pass | 1 | [pcap](bacnet/bacnet_min_frame.pcap) |
| bacnet_multi_session | 双会话按序整块展开（会话 2 首包 = 3；src .66/.67 distinct；实例 100/300） | pass | 4 | [pcap](bacnet/bacnet_multi_session.pcap) |
| bacnet_multi_transaction | 单会话六帧序列 Who-Is→I-Am→RP(1)→ACK→WP(2)→ACK（方向交替 invoke 递增） | pass | 6 | [pcap](bacnet/bacnet_multi_transaction.pcap) |
| bacnet_neg_address_family_derived | 从 IPv4 fixture 推导 IPv6 地址 | pass | 0 | [pcap]() |
| bacnet_neg_address_family_mismatch | IPv6 地址配 IPv4 层链 | pass | 0 | [pcap]() |
| bacnet_neg_apdu_header_confirmed | Confirmed-Request 头部不完整 | pass | 0 | [pcap]() |
| bacnet_neg_apdu_header_simpleack | SimpleACK <3 字节 | pass | 0 | [pcap]() |
| bacnet_neg_apdu_type_invalid | APDU 首字节高 4 位 >7 | pass | 0 | [pcap]() |
| bacnet_neg_bvlc_function | BVLC Function ∉0x00–0x0B 明文功能域 | pass | 0 | [pcap]() |
| bacnet_neg_bvlc_length_forwarded | Forwarded-NPDU Length 未计 6B 源地址 | pass | 0 | [pcap]() |
| bacnet_neg_bvlc_length_min | BVLC Length <4 | pass | 0 | [pcap]() |
| bacnet_neg_bvlc_length_mismatch | BVLC Length ≠ 4+功能负载实际字节 | pass | 0 | [pcap]() |
| bacnet_neg_bvlc_secure | Secure-BVLL 0x0C 被当明文产生 | pass | 0 | [pcap]() |
| bacnet_neg_bvlc_type | BVLC Type ≠0x81（如 0x80/0x82/0xFF） | pass | 0 | [pcap]() |
| bacnet_neg_carrier_layer_missing | 层链缺 udp（[bacnet] 直连） | pass | 0 | [pcap]() |
| bacnet_neg_carrier_tcp | TCP 载体声明（BACnet/IP 仅 UDP，Annex J） | pass | 0 | [pcap]() |
| bacnet_neg_error_class_range | error-class 越域（8） | pass | 0 | [pcap]() |
| bacnet_neg_invoke_mismatch | 应答 Invoke ≠ 触发请求 Invoke | pass | 0 | [pcap]() |
| bacnet_neg_invoke_reuse | 未完成事务期间复用同一 Invoke ID | pass | 0 | [pcap]() |
| bacnet_neg_npdu_dest_missing | Control bit5=1 而 DNET/HopCount 缺失 | pass | 0 | [pcap]() |
| bacnet_neg_npdu_dlen_invalid | DLEN ∉{0,6} | pass | 0 | [pcap]() |
| bacnet_neg_npdu_no_message_type | Control bit7=1 而 Message Type 缺失 | pass | 0 | [pcap]() |
| bacnet_neg_npdu_reserved_bits | Control 保留位 bit6/bit4 置 1 | pass | 0 | [pcap]() |
| bacnet_neg_npdu_src_len_zero | Control bit3=1 而 SLEN=0 | pass | 0 | [pcap]() |
| bacnet_neg_npdu_version | NPDU Version ≠0x01 | pass | 0 | [pcap]() |
| bacnet_neg_object_iam_not_device | I-Am 设备标识对象类型 ≠8 | pass | 0 | [pcap]() |
| bacnet_neg_object_instance_overflow | 对象实例 >4194303（22 位溢出） | pass | 0 | [pcap]() |
| bacnet_neg_object_type_overflow | 对象类型 >1023（10 位溢出，如 1024） | pass | 0 | [pcap]() |
| bacnet_neg_port_undeclared | 端口 ≠47808 未显式声明（静默回退禁止） | pass | 0 | [pcap]() |
| bacnet_neg_priority_range | 优先级 ∉1–16（0） | pass | 0 | [pcap]() |
| bacnet_neg_property_id_vendor | 属性 ID >511 未声明厂商私有 | pass | 0 | [pcap]() |
| bacnet_neg_property_index_negative | 数组下标为负（-1） | pass | 0 | [pcap]() |
| bacnet_neg_segment_extra_fields | SEG=0 却携带 seq/window | pass | 0 | [pcap]() |
| bacnet_neg_segment_missing_fields | SEG=1 缺 seq/window | pass | 0 | [pcap]() |
| bacnet_neg_segment_sequence_skip | seq 回绕/跳变 | pass | 0 | [pcap]() |
| bacnet_neg_segment_window_zero | 提议窗口 0（合法 1-255） | pass | 0 | [pcap]() |
| bacnet_neg_service_confirmed_unimplemented | 确认服务不在子集（如 ReadRange 34） | pass | 0 | [pcap]() |
| bacnet_neg_service_unconfirmed_invalid | 非确认服务 ∉{0,1,2,7,8} | pass | 0 | [pcap]() |
| bacnet_neg_state_ack_no_request | ACK/Error 事件无前置确认请求 | pass | 0 | [pcap]() |
| bacnet_neg_state_cov_no_subscribe | COV 通知无前置订阅（注入通道；正例 23 钉单帧通知合法） | pass | 0 | [pcap]() |
| bacnet_neg_state_iam_no_whois | I-Am 无前置 Who-Is（注入通道；正例 31 钉独立宣告合法） | pass | 0 | [pcap]() |
| bacnet_neg_tag_boolean_lvt | Boolean 应用标签 LVT=2 | pass | 0 | [pcap]() |
| bacnet_neg_tag_context_number | 上下文标签号超出服务 ASN.1 定义 | pass | 0 | [pcap]() |
| bacnet_neg_tag_lvt_mismatch | LVT=4 而内容仅 2 字节 | pass | 0 | [pcap]() |
| bacnet_neg_tag_open_unmatched | 开标签无同号闭标签配对 | pass | 0 | [pcap]() |
| bacnet_npdu_dest_address | NPDU 目的说明符：DNET 2001+DLEN 6+DADR+Hop（帧 1）/ DLEN=0 网内广播变体（帧 2） | pass | 2 | [pcap](bacnet/bacnet_npdu_dest_address.pcap) |
| bacnet_npdu_global_broadcast | NPDU 全局广播（DNET FFFF+DLEN 0+Hop FF，路由侧语义钉死） | pass | 1 | [pcap](bacnet/bacnet_npdu_global_broadcast.pcap) |
| bacnet_npdu_priority | NPDU 网络优先级三值：0x01/0x02/0x03（Who-Is ×3） | pass | 3 | [pcap](bacnet/bacnet_npdu_priority.pcap) |
| bacnet_npdu_router_discovery | 网络层消息对：Who-Is-Router(0x00, DNET FFFF)→I-Am-Router(0x01, DNET 2001) | pass | 2 | [pcap](bacnet/bacnet_npdu_router_discovery.pcap) |
| bacnet_npdu_src_address | NPDU 源说明符：I-Am 携 SNET 2001+SLEN 6+SADR（帧 2） | pass | 2 | [pcap](bacnet/bacnet_npdu_src_address.pcap) |
| bacnet_object_id_boundary | 对象 analog-input:0 与私有类型 128 实例 0x3FFFFF（0c 00000000 / 0c 203fffff） | pass | 4 | [pcap](bacnet/bacnet_object_id_boundary.pcap) |
| bacnet_object_type_boundaries | 类型 127（标准末值）与 1023（10 位满值）：0c 1fc00001 / 0c 3fc00001 | pass | 4 | [pcap](bacnet/bacnet_object_type_boundaries.pcap) |
| bacnet_port_nondefault | 显式 47809（src=dst）：BACnet 字节与用例 1 一致，DecodeAs 解码 | pass | 2 | [pcap](bacnet/bacnet_port_nondefault.pcap) |
| bacnet_priority_boundaries | WP 优先级显式 1 与显式 16（4901/4910 三形态之二） | pass | 4 | [pcap](bacnet/bacnet_priority_boundaries.pcap) |
| bacnet_read_property | RP 请求（control 04 期望回复）→ ComplexACK Real 22.5 大端 | pass | 2 | [pcap](bacnet/bacnet_read_property.pcap) |
| bacnet_read_property_array_index | RP ctx2 下标 1 与 0（整个数组合法边界），应答回显下标 | pass | 4 | [pcap](bacnet/bacnet_read_property_array_index.pcap) |
| bacnet_read_property_multiple | RPM 单对象双属性（开[1] 85+77 闭[1]）→ ComplexACK 双值 | pass | 2 | [pcap](bacnet/bacnet_read_property_multiple.pcap) |
| bacnet_reject | Reject 应答（60 02 05 missing-required-parameter） | pass | 2 | [pcap](bacnet/bacnet_reject.pcap) |
| bacnet_rpm_multi_object | RPM 双对象（ai:1 与 device:5 各双属性）→ ComplexACK 双对象多值 | pass | 2 | [pcap](bacnet/bacnet_rpm_multi_object.pcap) |
| bacnet_segmented_complex_ack | 分段 ComplexACK（窗口 4，SRV=0 客户端 SegmentACK） | pass | 4 | [pcap](bacnet/bacnet_segmented_complex_ack.pcap) |
| bacnet_segmented_request | 分段 WriteProperty（465B CharacterString 天然超 480）两段+SegmentACK（SRV=1） | pass | 3 | [pcap](bacnet/bacnet_segmented_request.pcap) |
| bacnet_subscribe_cov | SubscribeCOV（process 1/device:5/issue-confirmed TRUE/lifetime 600）→ SimpleACK | pass | 2 | [pcap](bacnet/bacnet_subscribe_cov.pcap) |
| bacnet_subscribe_cov_cancel | SubscribeCOV 取消形态（[2][3] 均缺省）→ SimpleACK | pass | 2 | [pcap](bacnet/bacnet_subscribe_cov_cancel.pcap) |
| bacnet_subscribe_cov_unconfirmed | SubscribeCOV [2] 存在且 FALSE（2900）+ lifetime | pass | 2 | [pcap](bacnet/bacnet_subscribe_cov_unconfirmed.pcap) |
| bacnet_ttl_max | RFD TTL 65535（u16 上界）→ Result | pass | 2 | [pcap](bacnet/bacnet_ttl_max.pcap) |
| bacnet_vendor_id_max | I-Am 厂商 ID 65535（u16 上界 22 ffff） | pass | 1 | [pcap](bacnet/bacnet_vendor_id_max.pcap) |
| bacnet_who_has_i_have | Who-Has 名字分支（ctx3 CharacterString）→ I-Have；[2] 对象 ID 分支 → I-Have | pass | 4 | [pcap](bacnet/bacnet_who_has_i_have.pcap) |
| bacnet_who_has_limits | Who-Has [0][1] 范围对（0/100）+ [2] 对象 ID 分支 → I-Have | pass | 2 | [pcap](bacnet/bacnet_who_has_limits.pcap) |
| bacnet_window_size_boundaries | 窗口 1 逐段确认（4 帧）与窗口 255 整窗确认（3 帧）——提议值非段数 | pass | 7 | [pcap](bacnet/bacnet_window_size_boundaries.pcap) |
| bacnet_write_property | WP 布尔 TRUE + 优先级 8（49 08）→ SimpleACK | pass | 2 | [pcap](bacnet/bacnet_write_property.pcap) |
| bacnet_write_property_no_priority | WP 缺省优先级（无 49 xx 尾巴 = 语义 16）→ SimpleACK | pass | 2 | [pcap](bacnet/bacnet_write_property_no_priority.pcap) |

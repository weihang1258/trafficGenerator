# mmse Pcap Test Results

Cases: 100 — pass 100, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| mmse_acknowledge_ind | 延迟链 Figure 5：通知 / 确认 / 取回 / 确认，新 TID 关联 | pass | 34 | [pcap](mmse/mmse_acknowledge_ind.pcap) |
| mmse_addressing_types | 地址四形态（PLMN/IPv4/IPv6/邮箱） | pass | 9 | [pcap](mmse/mmse_addressing_types.pcap) |
| mmse_concurrent_sessions | 并发会话交错回放（双 UA 四元组 concurrent:true） | pass | 18 | [pcap](mmse/mmse_concurrent_sessions.pcap) |
| mmse_delivery_ind_expired | 递送报告：Status=Expired 变体（无 TID） | pass | 17 | [pcap](mmse/mmse_delivery_ind_expired.pcap) |
| mmse_delivery_ind_retrieved | 递送报告：MsgID 回指 send-conf，Status=Retrieved（无 TID） | pass | 17 | [pcap](mmse/mmse_delivery_ind_retrieved.pcap) |
| mmse_encoding_long_integer | Long-integer 大端 4B/3B（定宽补零） | pass | 9 | [pcap](mmse/mmse_encoding_long_integer.pcap) |
| mmse_encoding_text_string | Encoded-string-value 两形态（裸 + VL+charset） | pass | 18 | [pcap](mmse/mmse_encoding_text_string.pcap) |
| mmse_encoding_value_length_uintvar | Value-length 0x1F+Uintvar 长值长形态 | pass | 9 | [pcap](mmse/mmse_encoding_value_length_uintvar.pcap) |
| mmse_from_insert_token | From insert-address-token 形态（0x89 0x01 0x81） | pass | 9 | [pcap](mmse/mmse_from_insert_token.pcap) |
| mmse_get_uri_auto_derived | GET URI 自动派生（取自通知 content_location 路径） | pass | 16 | [pcap](mmse/mmse_get_uri_auto_derived.pcap) |
| mmse_http_keepalive_multi_transaction | 同连接多事务严格配对（POST/GET/POST 三笔 keep-alive） | pass | 13 | [pcap](mmse/mmse_http_keepalive_multi_transaction.pcap) |
| mmse_ipv6 | IPv6 单流（2001:db8:bb::71 → 2001:db8:bb::1） | pass | 9 | [pcap](mmse/mmse_ipv6.pcap) |
| mmse_long_integer_max_4b | Long-integer 4B 满值 0xFFFFFFFF 上界 | pass | 9 | [pcap](mmse/mmse_long_integer_max_4b.pcap) |
| mmse_message_class_values | Message-Class 四值（4 fixture，单 ID 单 spec） | pass | 36 | [pcap](mmse/mmse_message_class_values.pcap) |
| mmse_mss_large_multipart | 跨 MSS ≥3 段重组（MSS=536，>3KB 附件） | pass | 16 | [pcap](mmse/mmse_mss_large_multipart.pcap) |
| mmse_multi_session | 多会话展开：提交 / 通知 / 取回三独立四元组 | pass | 26 | [pcap](mmse/mmse_multi_session.pcap) |
| mmse_multipart_length_invariant | multipart 长度自洽不变式独立断言 | pass | 9 | [pcap](mmse/mmse_multipart_length_invariant.pcap) |
| mmse_multipart_media_gif | 媒体 part image/gif（媒体码 0x9D + GIF magic） | pass | 9 | [pcap](mmse/mmse_multipart_media_gif.pcap) |
| mmse_multipart_media_part | 媒体 part jpeg（well-known 码 0x9E + magic bytes） | pass | 9 | [pcap](mmse/mmse_multipart_media_part.pcap) |
| mmse_multipart_part_headers | part 头（charset/name/ID/Location） | pass | 9 | [pcap](mmse/mmse_multipart_part_headers.pcap) |
| mmse_multipart_related_root | multipart/related start/type + SMIL 根 part | pass | 9 | [pcap](mmse/mmse_multipart_related_root.pcap) |
| mmse_neg_body_on_bodyless | wire_fault body_on_bodyless injection (anchor: body) | pass | 0 | [pcap]() |
| mmse_neg_carrier_content_type | wire_fault carrier_content_type injection (anchor: content-type) | pass | 0 | [pcap]() |
| mmse_neg_carrier_no_http | wire_fault carrier_no_http injection (anchor: layer) | pass | 0 | [pcap]() |
| mmse_neg_carrier_port | wire_fault carrier_port injection (anchor: port) | pass | 0 | [pcap]() |
| mmse_neg_carrier_profile | wire_fault carrier_profile injection (anchor: carrier) | pass | 0 | [pcap]() |
| mmse_neg_content_type_missing | wire_fault content_type_missing injection (anchor: content-type) | pass | 0 | [pcap]() |
| mmse_neg_head_first_not_8c | wire_fault head_first_not_8c injection (anchor: message-type) | pass | 0 | [pcap]() |
| mmse_neg_head_order_tid_first | wire_fault head_order_tid_first injection (anchor: order) | pass | 0 | [pcap]() |
| mmse_neg_head_order_version_missing | wire_fault head_order_version_missing injection (anchor: header) | pass | 0 | [pcap]() |
| mmse_neg_length_content_length | wire_fault length_content_length injection (anchor: length) | pass | 0 | [pcap]() |
| mmse_neg_length_long_int_over | wire_fault length_long_int_over injection (anchor: long-integer) | pass | 0 | [pcap]() |
| mmse_neg_length_long_int_zero | wire_fault length_long_int_zero injection (anchor: long-integer) | pass | 0 | [pcap]() |
| mmse_neg_length_tid_over | wire_fault length_tid_over injection (anchor: transaction-id) | pass | 0 | [pcap]() |
| mmse_neg_length_uintvar_over | wire_fault length_uintvar_over injection (anchor: uintvar) | pass | 0 | [pcap]() |
| mmse_neg_length_value_length | wire_fault length_value_length injection (anchor: value-length) | pass | 0 | [pcap]() |
| mmse_neg_mandatory_delivery_date | wire_fault mandatory_delivery_date injection (anchor: mandatory) | pass | 0 | [pcap]() |
| mmse_neg_mandatory_delivery_msgid | wire_fault mandatory_delivery_msgid injection (anchor: mandatory) | pass | 0 | [pcap]() |
| mmse_neg_mandatory_delivery_status | wire_fault mandatory_delivery_status injection (anchor: mandatory) | pass | 0 | [pcap]() |
| mmse_neg_mandatory_delivery_to | wire_fault mandatory_delivery_to injection (anchor: mandatory) | pass | 0 | [pcap]() |
| mmse_neg_mandatory_from | wire_fault mandatory_from injection (anchor: mandatory) | pass | 0 | [pcap]() |
| mmse_neg_mandatory_notif_class | wire_fault mandatory_notif_class injection (anchor: mandatory) | pass | 0 | [pcap]() |
| mmse_neg_mandatory_notif_expiry | wire_fault mandatory_notif_expiry injection (anchor: mandatory) | pass | 0 | [pcap]() |
| mmse_neg_mandatory_notif_location | wire_fault mandatory_notif_location injection (anchor: mandatory) | pass | 0 | [pcap]() |
| mmse_neg_mandatory_notif_size | wire_fault mandatory_notif_size injection (anchor: mandatory) | pass | 0 | [pcap]() |
| mmse_neg_mandatory_recipients | wire_fault mandatory_recipients injection (anchor: mandatory) | pass | 0 | [pcap]() |
| mmse_neg_mandatory_response_status | wire_fault mandatory_response_status injection (anchor: response-status) | pass | 0 | [pcap]() |
| mmse_neg_msgid_delivery | wire_fault msgid_delivery injection (anchor: message-id) | pass | 0 | [pcap]() |
| mmse_neg_msgid_read_rec | wire_fault msgid_read_rec injection (anchor: message-id) | pass | 0 | [pcap]() |
| mmse_neg_multipart_data_len | wire_fault multipart_data_len injection (anchor: data) | pass | 0 | [pcap]() |
| mmse_neg_multipart_headers_len | wire_fault multipart_headers_len injection (anchor: multipart) | pass | 0 | [pcap]() |
| mmse_neg_multipart_partnum_mismatch | wire_fault multipart_partnum_mismatch injection (anchor: part) | pass | 0 | [pcap]() |
| mmse_neg_multipart_partnum_over | wire_fault multipart_partnum_over injection (anchor: overflow) | pass | 0 | [pcap]() |
| mmse_neg_multipart_partnum_zero | wire_fault multipart_partnum_zero injection (anchor: part) | pass | 0 | [pcap]() |
| mmse_neg_multipart_start_dangling | wire_fault multipart_start_dangling injection (anchor: start) | pass | 0 | [pcap]() |
| mmse_neg_pdu_type_unassigned | wire_fault pdu_type_unassigned injection (anchor: unknown) | pass | 0 | [pcap]() |
| mmse_neg_pdu_type_unsupported | wire_fault pdu_type_unsupported injection (anchor: message-type) | pass | 0 | [pcap]() |
| mmse_neg_sequence_ack_first | wire_fault sequence_ack_first injection (anchor: sequence) | pass | 0 | [pcap]() |
| mmse_neg_sequence_conf_orphan | wire_fault sequence_conf_orphan injection (anchor: sequence) | pass | 0 | [pcap]() |
| mmse_neg_sequence_notifyresp_orphan | wire_fault sequence_notifyresp_orphan injection (anchor: sequence) | pass | 0 | [pcap]() |
| mmse_neg_sequence_response_first | wire_fault sequence_response_first injection (anchor: order) | pass | 0 | [pcap]() |
| mmse_neg_tid_acknowledge | wire_fault tid_acknowledge injection (anchor: transaction) | pass | 0 | [pcap]() |
| mmse_neg_tid_notifyresp | wire_fault tid_notifyresp injection (anchor: transaction) | pass | 0 | [pcap]() |
| mmse_neg_tid_send_conf | wire_fault tid_send_conf injection (anchor: transaction) | pass | 0 | [pcap]() |
| mmse_neg_value_application_header | wire_fault value_application_header injection (anchor: application-header) | pass | 0 | [pcap]() |
| mmse_neg_value_charset | wire_fault value_charset injection (anchor: charset) | pass | 0 | [pcap]() |
| mmse_neg_value_empty_string | wire_fault value_empty_string injection (anchor: text-string) | pass | 0 | [pcap]() |
| mmse_neg_value_message_class | wire_fault value_message_class injection (anchor: message-class) | pass | 0 | [pcap]() |
| mmse_neg_value_notif_expiry_absolute | wire_fault value_notif_expiry_absolute injection (anchor: expiry) | pass | 0 | [pcap]() |
| mmse_neg_value_previously_sent | wire_fault value_previously_sent injection (anchor: previously-sent) | pass | 0 | [pcap]() |
| mmse_neg_value_priority | wire_fault value_priority injection (anchor: priority) | pass | 0 | [pcap]() |
| mmse_neg_value_read_status | wire_fault value_read_status injection (anchor: read-status) | pass | 0 | [pcap]() |
| mmse_neg_value_reply_charging | wire_fault value_reply_charging injection (anchor: reply-charging) | pass | 0 | [pcap]() |
| mmse_neg_value_response_status | wire_fault value_response_status injection (anchor: response-status) | pass | 0 | [pcap]() |
| mmse_neg_value_status | wire_fault value_status injection (anchor: status) | pass | 0 | [pcap]() |
| mmse_neg_value_yesno | wire_fault value_yesno injection (anchor: delivery-report) | pass | 0 | [pcap]() |
| mmse_no_frames_after_fin | Closed 终态后无新帧，FIN×2 挥手，无 RST | pass | 9 | [pcap](mmse/mmse_no_frames_after_fin.pcap) |
| mmse_notification_ind | m-notification-ind 必选集 + From（content_length=99 逐字节复算） | pass | 8 | [pcap](mmse/mmse_notification_ind.pcap) |
| mmse_notification_minimal | 通知仅必选集（71B 反向复算） | pass | 8 | [pcap](mmse/mmse_notification_minimal.pcap) |
| mmse_notifyresp_deferred | 通知-确认链：Deferred + Report-Allowed=Yes | pass | 16 | [pcap](mmse/mmse_notifyresp_deferred.pcap) |
| mmse_partnum_max_127 | partNum 恰 127 部件数上界（每 part 最小 5B） | pass | 9 | [pcap](mmse/mmse_partnum_max_127.pcap) |
| mmse_port_nondefault | 非默认端口 8002（Content-Type 触发解码） | pass | 9 | [pcap](mmse/mmse_port_nondefault.pcap) |
| mmse_priority_low | Priority=Low（值域第三值 0x80） | pass | 9 | [pcap](mmse/mmse_priority_low.pcap) |
| mmse_read_rec_ind | 读取报告：Read-Status=Read，MsgID 回指 send-conf | pass | 17 | [pcap](mmse/mmse_read_rec_ind.pcap) |
| mmse_read_status_deleted | 读取报告：Read-Status=Deleted-without-being-read 变体 | pass | 17 | [pcap](mmse/mmse_read_status_deleted.pcap) |
| mmse_report_allowed_no | Report-Allowed=No（0x81，Yes/No 闭合） | pass | 16 | [pcap](mmse/mmse_report_allowed_no.pcap) |
| mmse_response_status_error_values | Response-Status 1.0 其余 7 错误值（7 fixture） | pass | 63 | [pcap](mmse/mmse_response_status_error_values.pcap) |
| mmse_retrieve_conf_immediate | 通知-取回链：TID 复用通知（immediate retrieve） | pass | 17 | [pcap](mmse/mmse_retrieve_conf_immediate.pcap) |
| mmse_send_conf_error | send_conf Error-service-denied + Response-Text；HTTP 200 仍成立 | pass | 9 | [pcap](mmse/mmse_send_conf_error.pcap) |
| mmse_send_conf_ok | send_conf Ok + TID same_as + Message-ID; HTTP 200 != MMS 状态 | pass | 9 | [pcap](mmse/mmse_send_conf_ok.pcap) |
| mmse_send_req_cc_only | 仅 Cc 收件人（To/Bcc 缺席合法形态） | pass | 9 | [pcap](mmse/mmse_send_req_cc_only.pcap) |
| mmse_send_req_ipv4 | m-send-req 必选集 + multipart 完整体（含 Sender-Visibility=Show） | pass | 9 | [pcap](mmse/mmse_send_req_ipv4.pcap) |
| mmse_send_req_optional_headers | 可选头全集（Cc/Bcc/Visibility=Hide/Priority=High/Delivery-Time） | pass | 9 | [pcap](mmse/mmse_send_req_optional_headers.pcap) |
| mmse_text_string_quote | Text-string Quote 形态（首字符分隔符前置 0x7F） | pass | 9 | [pcap](mmse/mmse_text_string_quote.pcap) |
| mmse_tid_max_32 | Transaction-ID 恰 32B 策略上界（content_length=120） | pass | 8 | [pcap](mmse/mmse_tid_max_32.pcap) |
| mmse_time_absolute_form | 绝对 token 时间形态（Expiry + Delivery-Time） | pass | 9 | [pcap](mmse/mmse_time_absolute_form.pcap) |
| mmse_uintvar_max_4b | Uintvar 4B 载荷上界（part dataLen=0x200000） | pass | 1445 | [pcap](mmse/mmse_uintvar_max_4b.pcap) |
| mmse_value_length_max_30 | Value-length 恰 30（短形态上界） | pass | 9 | [pcap](mmse/mmse_value_length_max_30.pcap) |
| mmse_version_10 | MMS-Version=1.0（线码 0x90） | pass | 9 | [pcap](mmse/mmse_version_10.pcap) |
| mmse_version_13 | MMS-Version=1.3（线码 0x93） | pass | 9 | [pcap](mmse/mmse_version_13.pcap) |

# edp Pcap Test Results

Cases: 89 — pass 89, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| edp_cmdid_long | 64B 长 cmdid 关联 | pass | 11 | [pcap](edp/edp_cmdid_long.pcap) |
| edp_cmdreq_binary | 命令二进制载荷（req/resp 均 4B） | pass | 11 | [pcap](edp/edp_cmdreq_binary.pcap) |
| edp_cmdreq_cmdresp | 命令事务（cmdid 关联、resp 非空文本） | pass | 11 | [pcap](edp/edp_cmdreq_cmdresp.pcap) |
| edp_cmdresp_empty | resp_len=0 条件缺省（无 resp_len/resp 字节） | pass | 11 | [pcap](edp/edp_cmdresp_empty.pcap) |
| edp_concurrent_sessions | 并发会话交错回放（concurrent:true，包总数不变仅交错） | pass | 22 | [pcap](edp/edp_concurrent_sessions.pcap) |
| edp_connack_refused | CONNRESP rtn=2 拒绝路径 + 连接关闭（无业务帧） | pass | 9 | [pcap](edp/edp_connack_refused.pcap) |
| edp_connack_rtn1 | CONNRESP rtn=1（协议错误）合法错误路径 | pass | 9 | [pcap](edp/edp_connack_rtn1.pcap) |
| edp_connreq_devid_ipv4 | 方式 1 连接 + CONNRESP rtn=0，IPv4 单流基线 | pass | 9 | [pcap](edp/edp_connreq_devid_ipv4.pcap) |
| edp_connreq_userid | 方式 2 连接（0xC0、空 devid、userid+authinfo） | pass | 9 | [pcap](edp/edp_connreq_userid.pcap) |
| edp_datapoint_value_types | type1 JSON 值类四种（int/float/string/对象） | pass | 10 | [pcap](edp/edp_datapoint_value_types.pcap) |
| edp_devid_u16_max | devid u16 上界 65,535B | pass | 53 | [pcap](edp/edp_devid_u16_max.pcap) |
| edp_disconnect | DISCONNECT + 挥手（2 字节最小帧 4000） | pass | 10 | [pcap](edp/edp_disconnect.pcap) |
| edp_heartbeat_multi | 周期心跳 3 轮（单连接重复心跳事务） | pass | 15 | [pcap](edp/edp_heartbeat_multi.pcap) |
| edp_ipv6 | IPv6 独立 fixture（connect，offset 74） | pass | 9 | [pcap](edp/edp_ipv6.pcap) |
| edp_ipv6_savedata | IPv6 全事务（connect+savedata，offset 74） | pass | 10 | [pcap](edp/edp_ipv6_savedata.pcap) |
| edp_json_u16_adjacent | json 邻位上界-1 65534（u16 65534） | pass | 54 | [pcap](edp/edp_json_u16_adjacent.pcap) |
| edp_json_u16_max | json 精确上界 65535（u16 65535） | pass | 54 | [pcap](edp/edp_json_u16_max.pcap) |
| edp_keep_time_boundary | keep_time 0xFFFF 满值 | pass | 9 | [pcap](edp/edp_keep_time_boundary.pcap) |
| edp_keep_time_min | keep_time=1 最小非零 | pass | 9 | [pcap](edp/edp_keep_time_min.pcap) |
| edp_long_devid | 64B 长 devid/apikey（2 字节 varint） | pass | 9 | [pcap](edp/edp_long_devid.pcap) |
| edp_msgid_max | msg_id u16 满值 0xFFFF | pass | 10 | [pcap](edp/edp_msgid_max.pcap) |
| edp_mss_large_bin | 16,350B bin 跨 MSS 重组（3 字节档下界 16,384） | pass | 21 | [pcap](edp/edp_mss_large_bin.pcap) |
| edp_multi_frame_segment | 多帧粘连（两帧一个 TCP 段，coalesce 流式定界合法形态） | pass | 10 | [pcap](edp/edp_multi_frame_segment.pcap) |
| edp_multi_session | 双设备双四元组多会话展开（第二会话包号=前会话总包+1） | pass | 20 | [pcap](edp/edp_multi_session.pcap) |
| edp_multi_transaction_keepalive | 单连接多事务全链（接入→上报→心跳→命令→断开） | pass | 16 | [pcap](edp/edp_multi_transaction_keepalive.pcap) |
| edp_neg_auth_apikey_empty | 方式 1 apikey 空串（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_auth_authinfo_empty | 方式 2 authinfo 空串（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_auth_devid_empty | 方式 1 devid 空串（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_auth_userid_empty | 方式 2 userid 空串（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_bin_desc_invalid | type2 desc 非法 JSON（截断/非对象）（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_bin_desc_no_dsid | type2 desc 无 ds_id 字段（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_bin_desc_over | desc ≥65,536B（wire 口径恰值即拒）（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_bin_over_3mb | bin_len ≥3MB（wire 口径恰值即拒）（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_carrier_udp | UDP 载体判拒（tcp-only 族，BuildLayersPlanner 预检纵深） | pass | 0 | [pcap]() |
| edp_neg_cmdid_correlation | CMDRESP cmdid 与 CMDREQ 不匹配（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_conn_flag | 连接标志非 0x40/0xC0（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_conn_protocol_name | 协议名 ≠ EDP（如 EDQ）（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_conn_version | 协议版本 ≠ 1（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_connack_rtn_range | connack_rtn 取 0–9 值域外值（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_json_invalid | JSON 载荷非法（截断/非对象）（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_json_over_u16 | json >65,535（u16 溢出）（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_layer_chain | 层链缺 tcp（DependsOn 自动补全结构不可达——书面豁免注入通道）（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_msgid_correlation | SAVEACK msg_id ≠ SAVEDATA 消息编号（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_port_conflict | 端口/载体声明矛盾（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_remainlen_5byte | 变长编码第 5 字节仍置延续位（豁免行）（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_remainlen_mismatch | 剩余长度 ≠ 消息体实际字节数（豁免行：builder 恒正确编码）（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_remainlen_truncated | 报文截断（体短于 remainlen 声明，豁免行）（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_savedata_format | 数据格式标志越域（0x00/0x06/0xFF）（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_state_after_disconnect | DISCONNECT 后继续排业务事件（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_state_after_reject | CONNRESP rtn≠0 后继续排业务事件（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_state_no_connect | 事件序列不以 connect 开头（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_type_unimplemented | ENCRYPT 0xE0/0xF0 边界不实现（注入走负例）（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_neg_type_unknown | 未知消息类型值（不在 §3.2 表内）（契约 §7 一行一注入；validator 即拒 + 主锚词） | pass | 0 | [pcap]() |
| edp_pingreq_pingresp | 心跳单轮（2 字节最小帧 c000/d000） | pass | 11 | [pcap](edp/edp_pingreq_pingresp.pcap) |
| edp_port_nondefault | 非默认端口 12472（端口由配置覆盖，EDP 帧与端口无关） | pass | 9 | [pcap](edp/edp_port_nondefault.pcap) |
| edp_pushdata_binary | 透传二进制不透明载荷 | pass | 10 | [pcap](edp/edp_pushdata_binary.pcap) |
| edp_pushdata_deliver | 平台→设备下发透传 | pass | 10 | [pcap](edp/edp_pushdata_deliver.pcap) |
| edp_pushdata_upload | 设备→平台透传（文本载荷，无应答） | pass | 10 | [pcap](edp/edp_pushdata_upload.pcap) |
| edp_remainlen_1byte_max | 1 字节档上界（remainlen 127 → 7f） | pass | 10 | [pcap](edp/edp_remainlen_1byte_max.pcap) |
| edp_remainlen_2byte_max | 2 字节档上界（remainlen 16383 → ff 7f） | pass | 21 | [pcap](edp/edp_remainlen_2byte_max.pcap) |
| edp_remainlen_3byte_max | 3 字节档上界（remainlen 2097151 → ff ff 7f） | pass | 1446 | [pcap](edp/edp_remainlen_3byte_max.pcap) |
| edp_remainlen_4byte_band | 4 字节档下界（remainlen 2097152 → 80 80 80 01） | pass | 1446 | [pcap](edp/edp_remainlen_4byte_band.pcap) |
| edp_remainlen_multibyte | 2 字节变长编码下界（remainlen 128 → 80 01） | pass | 10 | [pcap](edp/edp_remainlen_multibyte.pcap) |
| edp_saveack_err_code | SAVEACK err_code=1（非零结果码变体） | pass | 11 | [pcap](edp/edp_saveack_err_code.pcap) |
| edp_saveack_msgid | SAVEACK msg_id 关联回带（err_code=0） | pass | 11 | [pcap](edp/edp_saveack_msgid.pcap) |
| edp_savedata_bin_empty | type2 × flag 0x00 + bin_len=0 边界（合法空二进制） | pass | 10 | [pcap](edp/edp_savedata_bin_empty.pcap) |
| edp_savedata_deliver | 平台→设备 SAVEDATA 同构方向（下行无应答） | pass | 10 | [pcap](edp/edp_savedata_deliver.pcap) |
| edp_savedata_type1_flag00 | 存储 type1（flag 0x00） | pass | 10 | [pcap](edp/edp_savedata_type1_flag00.pcap) |
| edp_savedata_type1_flag40 | 存储 type1（flag 0x40） | pass | 10 | [pcap](edp/edp_savedata_type1_flag40.pcap) |
| edp_savedata_type1_flag80 | 存储 type1（flag 0x80） | pass | 10 | [pcap](edp/edp_savedata_type1_flag80.pcap) |
| edp_savedata_type1_fulljson | 存储 type1（flag 0xC0） | pass | 10 | [pcap](edp/edp_savedata_type1_fulljson.pcap) |
| edp_savedata_type1_token | 存储 type1（flag 0xC0） | pass | 10 | [pcap](edp/edp_savedata_type1_token.pcap) |
| edp_savedata_type2_bin | type2 Bin flag 0xC0（desc+u32+bin） | pass | 10 | [pcap](edp/edp_savedata_type2_bin.pcap) |
| edp_savedata_type2_flag40 | type2 Bin flag 0x40（desc+u32+bin） | pass | 10 | [pcap](edp/edp_savedata_type2_flag40.pcap) |
| edp_savedata_type2_flag80 | type2 Bin flag 0x80（desc+u32+bin） | pass | 10 | [pcap](edp/edp_savedata_type2_flag80.pcap) |
| edp_savedata_type3_flag40 | 存储 type3（flag 0x40） | pass | 10 | [pcap](edp/edp_savedata_type3_flag40.pcap) |
| edp_savedata_type3_flag80 | 存储 type3（flag 0x80） | pass | 10 | [pcap](edp/edp_savedata_type3_flag80.pcap) |
| edp_savedata_type3_flagc0 | 存储 type3（flag 0xC0） | pass | 10 | [pcap](edp/edp_savedata_type3_flagc0.pcap) |
| edp_savedata_type3_simple | 存储 type3（flag 0x00） | pass | 10 | [pcap](edp/edp_savedata_type3_simple.pcap) |
| edp_savedata_type3_value_object | type3 值域变体 {"loc":{"lon":117.48,"lat":39.96}} | pass | 10 | [pcap](edp/edp_savedata_type3_value_object.pcap) |
| edp_savedata_type3_value_string | type3 值域变体 {"status":"online"} | pass | 10 | [pcap](edp/edp_savedata_type3_value_string.pcap) |
| edp_savedata_type4_flag00 | 存储 type4（flag 0x00） | pass | 10 | [pcap](edp/edp_savedata_type4_flag00.pcap) |
| edp_savedata_type4_flag80 | 存储 type4（flag 0x80） | pass | 10 | [pcap](edp/edp_savedata_type4_flag80.pcap) |
| edp_savedata_type4_flagc0 | 存储 type4（flag 0xC0） | pass | 10 | [pcap](edp/edp_savedata_type4_flagc0.pcap) |
| edp_savedata_type4_time | 存储 type4（flag 0x40） | pass | 10 | [pcap](edp/edp_savedata_type4_time.pcap) |
| edp_savedata_type5_flag00 | 存储 type5（flag 0x00） | pass | 10 | [pcap](edp/edp_savedata_type5_flag00.pcap) |
| edp_savedata_type5_flag40 | 存储 type5（flag 0x40） | pass | 10 | [pcap](edp/edp_savedata_type5_flag40.pcap) |
| edp_savedata_type5_flagc0 | 存储 type5（flag 0xC0） | pass | 10 | [pcap](edp/edp_savedata_type5_flagc0.pcap) |
| edp_savedata_type5_string | 存储 type5（flag 0x80） | pass | 10 | [pcap](edp/edp_savedata_type5_string.pcap) |

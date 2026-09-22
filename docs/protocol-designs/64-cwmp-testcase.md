# CWMP（CPE 广域网管理协议 / TR-069）测试用例契约

> 版本：v3.1.2（测试用例，v1.2 行为面全量重出 + 复验关单轮 + 落地勘误）
> 日期：2026-09-22
> 配套设计：`docs/protocol-designs/64-cwmp-design.md`（v2.2.2）
> 机器契约：`trafficgen/test/protocol_pcap/cases/cwmp.json`（pcap 文件输出与 `port_group`/NIC 网口输出共用本契约，断言字段两路径一致，需求文档 v1.3 §8.2-7）
> 状态：**已落地运行**（B6 40a479b 实现，150 例 clean；#34 D-CWMP-1 配置承载迁层后 153 例全绿×2）。修轮 M1 起正例按六行为族抽钉 `fields`/`frames` 字段断言，其余正例保持结构三件套（packet_count/has_handshake/terminates）——字段面为按族抽样口径，非逐例全字段覆盖（TEST_CASES T-CWMP 修轮注记同源）。
> 依据：`protocol-doc-requirements.md` v1.2——本文按**可测试行为面全枚举**重出（独立审查员 rr-cwmp 枚举约 210–230 测试点），废除 v2.0/v2.1 的 20 ID 固定契约；每条用例设「依据」列（TR-069 章节 / 设计 §，规范优先），不与设计章节一一映射。

## 1. 测试原则（v1.2）

1. **用例 = 不可再分的测试点**：一条用例只验证一个可独立判定真伪的行为点（一个 RPC 的请求/响应形状、一个字段值、一个错误码、一个边界、一种载体/地址族、一个状态转移、一个关联规则）。原 v2.1 的合并 fixture（`cwmp_inform_event_codes` 四次 fixture、`cwmp_fault_soap` 三段、`cwmp_download_transfer_complete` 三途径）按原子原则拆分为独立用例。
2. **覆盖完整性**：按规范枚举行为面核对遗漏（功能=RPC×请求/响应×错误路径；数据=字段×值域×边界；编码=HTTP/SOAP/XML 形态；载体=TCP×IPv4/IPv6×会话形态；性能=大报文/边界帧）。遗漏即缺陷，不因设计未声明而豁免。
3. **依据链**：断言依据 TR-069（Amendment 6 Corrigendum 1）章节优先，设计文档具体化其次；标注于 §2 索引「依据」列。标注「校准」的值实现期以 tshark/原文回对后钉死。
4. **断言可执行**：字段名与值以本机 `tshark -G fields` 实测为准（无 `cwmp.*` 专用字段；断言落 `http.*`/`tcp.*`/`ipv6.nxt` + frames hex 前缀）。负例执行期严格只有 `expect_error, error_contains` 两键，锚词与设计 §7 表一致。
5. **包数约定**：正常会话 = 3 握手 + 2×事务对数 +（副连接块 9）+ 4 挥手（收尾空 POST/204 对含在事务对数内）；**失败会话无收尾对**（= 3 + 2×事务对数 + 4）。多会话第二会话握手包号 = 前会话总包数 + 1。约定数字为实现基线（非 RFC 消息数），实现采用不同 ACK 合并/分段方式时同步更新四件套。

## 2. 用例索引（行为面全枚举，§4 正例 / §5 负例契约逐条对应）

用例总数 **150** = 112 正 + 38 负（契约规划数；**v3.1.2 落地实测：153 = 110 正 + 43 负**——规划到落地拆分/合并有漂移，以 cases/cwmp.json 为准）（原 v2.1 的 20 ID 全部被下方枚举吸收；`cwmp_inform_event_codes` 四次 fixture 拆为 4 条事件例、`cwmp_download_transfer_complete` 三途径拆为独立条目、`cwmp_fault_soap` 保留主语义并新增 Fault 正例族）。索引「依据」列标注规范章节或设计 §（规范优先，不要求与设计章节一一映射）。

| # | ID | 类型 | 载体 | 覆盖（一句话） | 依据 | 包数 |
|---:|---|---|---|---|---|---:|
| 1 | `cwmp_inform_ipv4` | 正 | TCP/IPv4 | IPv4/7547 单流基线：Inform(2 PERIODIC)→InformResponse→空 POST→204 收尾 | A.3.3.1/§3.7.1 Table 7 | 11 |
| 2 | `cwmp_inform_event_bootstrap` | 正 | TCP/IPv4 | 事件 0 BOOTSTRAP（首次引导）Inform | Table 8/A.3.3.1 | 11 |
| 3 | `cwmp_inform_event_boot` | 正 | TCP/IPv4 | 事件 1 BOOT（重启引导）Inform | Table 8 | 11 |
| 4 | `cwmp_inform_event_value_change` | 正 | TCP/IPv4 | 事件 4 VALUE CHANGE Inform | Table 8 | 11 |
| 5 | `cwmp_inform_event_tc_mdownload` | 正 | TCP/IPv4 | 事件 7 TRANSFER COMPLETE + M Download 同 Inform 携带（同因事件必须同帧，§3.7.1.5） | Table 8/§3.7.1.5 | 11 |
| 6 | `cwmp_connection_request` | 正 | TCP/IPv4 | ACS→CPE 反向连接：GET/401 digest/GET+Authorization/200 空体 + 新会话 Inform(6 CONNECTION REQUEST) | §3.2.2/Table 8 | 22 |
| 7 | `cwmp_get_parameter_values` | 正 | TCP/IPv4 | GetParameterValues + GetParameterNames 事务（数组编码、部分路径、Writable） | A.3.2.2/A.3.2.3 | 15 |
| 8 | `cwmp_set_parameter_values` | 正 | TCP/IPv4 | SetParameterValues：ParameterKey、Status 0/1 各一（两笔事务） | A.3.2.1 Table 15–17 | 15 |
| 9 | `cwmp_download_transfer_complete` | 正 | TCP/IPv4 | Download→DownloadResponse(1)→新会话 Inform(7+M Download)→TransferComplete→TransferCompleteResponse | A.3.2.8/A.3.3.2 | 26 |
| 10 | `cwmp_download_flow_correlation` | 正 | TCP/IPv4 | 流关联：Download 驱动独立副连接（CPE→文件服务器 HTTP GET，driven_by） | §3.4.3/§5 | 24 |
| 11 | `cwmp_upload_transfer_complete` | 正 | TCP/IPv4 | Upload→UploadResponse(1)→新会话 TransferComplete（CommandKey 关联） | A.4.1.5 | 26 |
| 12 | `cwmp_reboot_command_key` | 正 | TCP/IPv4 | Reboot→RebootResponse→新会话 Inform(1 BOOT+M Reboot，CommandKey 同值) | A.3.2.9/Table 8 | 26 |
| 13 | `cwmp_fault_soap` | 正 | TCP/IPv4 | ACS 对 GetRPCMethods 回 Fault（faultcode=Server、faultstring=CWMP fault、detail cwmp:Fault）且会话继续 | §3.5/A.5.1 | 13 |
| 14 | `cwmp_http_keepalive_multi_transaction` | 正 | TCP/IPv4 | 同连接多事务交替（Inform→GetRPCMethods→SetParameterValues→空 POST→204），无 pipelining | §3.7.3 Figure 3/§3.4.6 | 17 |
| 15 | `cwmp_ipv6` | 正 | TCP/IPv6 | IPv6 单流 Inform 会话 | §2/§8 | 11 |
| 16 | `cwmp_multi_session` | 正 | TCP/IPv4 | 多会话展开双四元组：ID/cookie/DeviceId/事务状态互不串用 | §5 | 30 |
| 17 | `cwmp_mss_large_soap` | 正 | TCP/IPv4 | 大 SOAP envelope（≥32768B）跨 MSS 分段重组 | §3.5 32KB 条款/§8 | 33 |
| 18 | `cwmp_get_parameter_attributes` | 正 | TCP/IPv4 | GetParameterAttributes 请求/响应（ParameterAttributeStruct：Name/Notification/AccessList） | A.3.2.4 | 11 |
| 19 | `cwmp_set_parameter_attributes` | 正 | TCP/IPv4 | SetParameterAttributes（NotificationChange/Notification/AccessListChange/AccessList[]），响应 Body 仅含空 `<SetParameterAttributesResponse/>` 元素 | A.3.2.5 | 11 |
| 20 | `cwmp_add_object` | 正 | TCP/IPv4 | AddObject（ObjectName 尾点路径+ParameterKey）→InstanceNumber+Status | A.3.2.6 | 11 |
| 21 | `cwmp_delete_object` | 正 | TCP/IPv4 | DeleteObject（含实例号精确路径）→Status | A.3.2.7 | 11 |
| 22 | `cwmp_factory_reset_bootstrap` | 正 | TCP/IPv4 | FactoryReset（无参数）→新会话 Inform(0 BOOTSTRAP) | A.3.2.10/Table 8 | 28 |
| 23 | `cwmp_schedule_download` | 正 | TCP/IPv4 | ScheduleDownload（StartTime/CompleteTime/SuccessURL/FailureURL/MaxRetries）→ScheduleDownloadResponse{Status,StartTime}；新会话 Inform(3 SCHEDULED+M ScheduleDownload) | A.3.2.11/Table 8 | 28 |
| 24 | `cwmp_schedule_upload` | 正 | TCP/IPv4 | ScheduleUpload→ScheduleUploadResponse{Status,StartTime} | Annex A（节号回对校准） | 11 |
| 25 | `cwmp_autonomous_transfer_complete` | 正 | TCP/IPv4 | AutonomousTransferComplete（CPE 主动通知，无前导 ACS 请求）→空 `<AutonomousTransferCompleteResponse/>` + 新会话 Inform(10 AUTONOMOUS TRANSFER COMPLETE) | A.3.3.3/Table 8 | 24 |
| 26 | `cwmp_request_download` | 正 | TCP/IPv4 | CPE RequestDownload(FileType)→响应 Body 仅含空 `<RequestDownloadResponse/>` 元素；新会话 Inform(9 REQUEST DOWNLOAD)→ACS 下发 Download | A.3.3.4/Table 8 | 30 |
| 27 | `cwmp_kicked` | 正 | TCP/IPv4 | ACS Kicked(CommandKey)→KickedResponse{KickURL,RequestID}；新会话 Inform(5 KICKED) | A.3.2.16（节号回对校准）/Table 8 | 26 |
| 28 | `cwmp_inform_diagnostics_complete` | 正 | TCP/IPv4 | 事件 8 DIAGNOSTICS COMPLETE Inform（TR-181 诊断高频） | Table 8 | 11 |
| 29 | `cwmp_inform_retry_401` | 正 | TCP/IPv4 | 会话级 digest 挑战：Inform→401→带 Authorization 重发（RetryCount>0）→InformResponse | §3.4.4/§3.2.1.1 | 13 |
| 30 | `cwmp_get_parameter_values_empty_response` | 正 | TCP/IPv4 | GetParameterValues 无匹配参数→空 ParameterList（合法不报错） | A.3.2.2/设计§7 | 11 |
| 31 | `cwmp_get_parameter_names_nextlevel_0` | 正 | TCP/IPv4 | GetParameterNames NextLevel=0（递归全层） | A.3.2.3 | 11 |
| 32 | `cwmp_get_parameter_names_nextlevel_1` | 正 | TCP/IPv4 | GetParameterNames NextLevel=1（仅下一层） | A.3.2.3 | 11 |
| 33 | `cwmp_get_parameter_names_root_path` | 正 | TCP/IPv4 | GetParameterNames ParameterPath=""（根路径） | A.3.2.3 | 11 |
| 34 | `cwmp_get_parameter_names_empty_response` | 正 | TCP/IPv4 | GetParameterNames 无匹配→空 ParameterList | A.3.2.3 | 11 |
| 35 | `cwmp_set_parameter_values_multi_param` | 正 | TCP/IPv4 | SetParameterValues 单笔 ≥2 参数 | A.3.2.1 | 13 |
| 36 | `cwmp_set_parameter_values_fault_multi_param` | 正 | TCP/IPv4 | SetParameterValuesFault ≥2 逐参数形态（faultcode=Client、主 FaultCode 9003 + 逐参数 9007） | §3.5 示例 | 13 |
| 37 | `cwmp_download_response_status_0_times` | 正 | TCP/IPv4 | DownloadResponse Status=0 直接成功：StartTime/CompleteTime 必现 | A.3.2.8 | 11 |
| 38 | `cwmp_download_cred_target_fields` | 正 | TCP/IPv4 | Download Username/Password/TargetFileName 非空字段 | A.3.2.8 | 11 |
| 39 | `cwmp_download_https_url` | 正 | TCP/IPv4 | Download URL https 形态（§3.4.3 文件传输服务器协议面） | §3.4.3 | 11 |
| 40 | `cwmp_download_delay_success` | 正 | TCP/IPv4 | DelaySeconds 非 0 成功路径：跨会话后副连接+TC（非 0 禁同会话执行的正向面） | A.3.2.8 | 35 |
| 41 | `cwmp_upload_put_flow_correlation` | 正 | TCP/IPv4 | Upload PUT 副连接流关联（与 Download 对称） | §3.4.3 | 24 |
| 42 | `cwmp_upload_response_status_0` | 正 | TCP/IPv4 | UploadResponse Status=0 直接成功 | A.4.1.5 | 11 |
| 43 | `cwmp_transfer_complete_fault_9010` | 正 | TCP/IPv4 | TransferComplete FaultCode=9010（文件传输失败核心上报路径）+ StartTime/CompleteTime | A.3.3.2 Table 41–43 | 13 |
| 44 | `cwmp_reboot_empty_command_key` | 正 | TCP/IPv4 | Reboot 空 CommandKey（合法） | A.3.2.9 | 11 |
| 45 | `cwmp_get_rpc_methods_cpe_to_acs` | 正 | TCP/IPv4 | GetRPCMethods CPE→ACS（CPE 待发请求直接 POST，无需空 POST 递送） | A.3.1.1 | 13 |
| 46 | `cwmp_parameter_key_same_session` | 正 | TCP/IPv4 | SetParameterValues(ParameterKey=K)→同会话后继 AddObject 携带同一 ParameterKey（跨事务关联） | A.3.2.1 | 15 |
| 47 | `cwmp_fault_id_echo` | 正 | TCP/IPv4 | Fault 响应回带请求 cwmp:ID（成功/Fault 均须回带） | Table 4 | 11 |
| 48 | `cwmp_soapaction_present_empty` | 正 | TCP/IPv4 | SOAP POST 的 SOAPAction 空值行存在（正向断言） | §3.4.1 | 11 |
| 49 | `cwmp_xml_escape_full` | 正 | TCP/IPv4 | XML 转义全件套：&lt; &gt; &quot; &apos;（&amp; 已有基线例） | §3.5/XML 1.0 | 11 |
| 50 | `cwmp_param_value_utf8` | 正 | TCP/IPv4 | 参数值 UTF-8 多字节（非 ASCII） | XML/§3.5 | 11 |
| 51 | `cwmp_param_value_empty_string` | 正 | TCP/IPv4 | 参数值空串 value=""（区别于空 ParameterList） | A.3.3.1 | 11 |
| 52 | `cwmp_currenttime_negative_offset` | 正 | TCP/IPv4 | CurrentTime 负时区偏移 -hh:mm 形态 | Table 37 | 11 |
| 53 | `cwmp_inform_paramlist_multi` | 正 | TCP/IPv4 | Inform ParameterList ≥2 参数 | Table 37–39 | 11 |
| 54 | `cwmp_event_code_len_upper` | 正 | TCP/IPv4 | EventCode string(64) 上界 + Event CommandKey string(32) 上界 | Table 37 注 | 11 |
| 55 | `cwmp_manufacturer_len_upper` | 正 | TCP/IPv4 | DeviceId.Manufacturer string(64) 上界 | Table 39 | 11 |
| 56 | `cwmp_download_filesize_nonzero` | 正 | TCP/IPv4 | Download FileSize 非 0 值 | A.3.2.8 | 11 |
| 57 | `cwmp_filetype_enum_2_web` | 正 | TCP/IPv4 | FileType "2 Web Content" | Table 33 | 11 |
| 58 | `cwmp_filetype_enum_4_tone` | 正 | TCP/IPv4 | FileType "4 Tone File" | Table 33 | 11 |
| 59 | `cwmp_filetype_enum_5_ringer` | 正 | TCP/IPv4 | FileType "5 Ringer File" | Table 33 | 11 |
| 60 | `cwmp_filetype_enum_6_stored` | 正 | TCP/IPv4 | FileType "6 Stored Firmware Image" | Table 33 | 11 |
| 61 | `cwmp_filetype_vendor_x` | 正 | TCP/IPv4 | FileType 厂商扩展 "X <OUI> <id>" 形态 | Table 33 | 11 |
| 62 | `cwmp_id_special_values` | 正 | TCP/IPv4 | cwmp:ID 值域：string(32) 上界、空串与特殊字符（空格/UTF-8/标点，schema 无 pattern） | Table 4 | 11 |
| 63 | `cwmp_content_type_charset` | 正 | TCP/IPv4 | Content-Type 带 charset 变体 text/xml; charset="utf-8" | §3.4.1 | 11 |
| 64 | `cwmp_delayseconds_large` | 正 | TCP/IPv4 | DelaySeconds uint 大值边界 | A.3.2.8 | 11 |
| 65 | `cwmp_paramname_255` | 正 | TCP/IPv4 | 参数名 string(256) 相邻值 255 常规 | A.3.2.2 | 11 |
| 66 | `cwmp_cpe_fault_9000` | 正 | TCP/IPv4 | CPE 对未支持方法回 9000 Method not supported（ACS 调未实现方法的最常见错误路径） | Table 87 | 11 |
| 67 | `cwmp_cpe_fault_9005` | 正 | TCP/IPv4 | CPE Fault 9005 Invalid parameter name | Table 87 | 11 |
| 68 | `cwmp_cpe_fault_9008` | 正 | TCP/IPv4 | CPE Fault 9008 Non-writable parameter | Table 87 | 11 |
| 69 | `cwmp_cpe_fault_9001` | 正 | TCP/IPv4 | CPE Fault 9001 Request denied | Table 87 | 11 |
| 70 | `cwmp_cpe_fault_9002` | 正 | TCP/IPv4 | CPE Fault 9002 Internal error | Table 87 | 11 |
| 71 | `cwmp_cpe_fault_9004` | 正 | TCP/IPv4 | CPE Fault 9004 Resources exceeded | Table 87 | 11 |
| 72 | `cwmp_cpe_fault_9006` | 正 | TCP/IPv4 | CPE Fault 9006 Invalid parameter type | Table 87 | 11 |
| 73 | `cwmp_cpe_fault_9009` | 正 | TCP/IPv4 | CPE Fault 9009 Notification rejected | Table 87 | 11 |
| 74 | `cwmp_cpe_fault_9011` | 正 | TCP/IPv4 | CPE Fault 9011 Upload failure（TransferComplete FaultStruct 内） | Table 87/43 | 13 |
| 75 | `cwmp_cpe_fault_9012` | 正 | TCP/IPv4 | CPE Fault 9012 File transfer server authentication failure | Table 87/43 | 13 |
| 76 | `cwmp_cpe_fault_9013` | 正 | TCP/IPv4 | CPE Fault 9013 Unsupported protocol for file transfer | Table 87/43 | 13 |
| 77 | `cwmp_cpe_fault_9014` | 正 | TCP/IPv4 | 传输失败细分段下界 9014 | Table 87/43 | 13 |
| 78 | `cwmp_cpe_fault_9020` | 正 | TCP/IPv4 | 传输失败细分段上界 9020 | Table 87/43 | 13 |
| 79 | `cwmp_cpe_fault_9800_vendor` | 正 | TCP/IPv4 | 厂商段下界 9800 | Table 87 | 11 |
| 80 | `cwmp_cpe_fault_9899_vendor` | 正 | TCP/IPv4 | 厂商段上界 9899 | Table 87 | 11 |
| 81 | `cwmp_acs_fault_8000` | 正 | TCP/IPv4 | ACS 对 CPE 请求回 8000 Method not supported | Table 88 | 11 |
| 82 | `cwmp_acs_fault_8001` | 正 | TCP/IPv4 | ACS 8001 Request denied | Table 88 | 11 |
| 83 | `cwmp_acs_fault_8003` | 正 | TCP/IPv4 | ACS 8003 Invalid arguments | Table 88 | 11 |
| 84 | `cwmp_acs_fault_8004` | 正 | TCP/IPv4 | ACS 8004 Resources exceeded | Table 88 | 11 |
| 85 | `cwmp_acs_fault_8006` | 正 | TCP/IPv4 | ACS 8006（语义回对校准） | Table 88 | 11 |
| 86 | `cwmp_acs_fault_8800_vendor` | 正 | TCP/IPv4 | ACS 厂商段下界 8800 | Table 88 | 11 |
| 87 | `cwmp_digest_auth_params` | 正 | TCP/IPv4 | digest Authorization 参数逐项（username/realm/nonce/uri/response/cnonce/nc/qop=auth/algorithm，opaque 原样回带） | §3.4.5/RFC 7616 | 15 |
| 88 | `cwmp_digest_stale_true` | 正 | TCP/IPv4 | digest stale=true 重挑战路径（nonce 过期→重挑战→重发成功） | RFC 7616 | 17 |
| 89 | `cwmp_chunked_envelope` | 正 | TCP/IPv4 | chunked 传输编码 SOAP envelope（Transfer-Encoding: chunked） | §3.4.6/§2 | 13 |
| 90 | `cwmp_http_redirect_chain` | 正 | TCP/IPv4 | ACS 重定向链 302→302→200（≤5 跳、重定向 URL 不持久化） | §3.4.2 | 13 |
| 91 | `cwmp_namespace_1_1` | 正 | TCP/IPv4 | namespace 协商 cwmp-1-1（Inform 携带 SupportedCWMPVersions 或直接 1-1 形态） | §3.7.4/A.6 Table 89 | 11 |
| 92 | `cwmp_namespace_1_2` | 正 | TCP/IPv4 | namespace 协商 cwmp-1-2（1.3/1.4 复用） | §3.7.4/A.6 Table 89 | 11 |
| 93 | `cwmp_empty_post_content_length_zero` | 正 | TCP/IPv4 | 空 POST 带 Content-Length:0 形态 | §3.4.1 | 11 |
| 94 | `cwmp_request_uri_variant` | 正 | TCP/IPv4 | 请求 URI 变体（非根路径带 query） | §3.4.1 | 11 |
| 95 | `cwmp_cookie_echo_session` | 正 | TCP/IPv4 | 会话内 Set-Cookie→逐请求回带 Cookie same_as | §3.4.2/RFC 6265 | 13 |
| 96 | `cwmp_concurrent_sessions` | 正 | TCP/IPv4×2 | 并发会话：双 CPE 四元组交错回放（concurrent: true），状态/ID/cookie 不串用 | §4 业务层/§3.7.1 | 22 |
| 97 | `cwmp_cr_busy_503` | 正 | TCP/IPv4 | CR 忙：CPE 会话占用时对 Connection Request 回 503（合法，不进负例） | §3.2.2 | 16 |
| 98 | `cwmp_ipv6_cr_download` | 正 | TCP/IPv6 | IPv6 上的 Connection Request + Download 副连接 | §4 地址流 | 35 |
| 99 | `cwmp_envelope_32768_boundary` | 正 | TCP/IPv4 | envelope 恰 32768 字节（32KB 下界恰值） | §3.5 | 33 |
| 100 | `cwmp_envelope_32769` | 正 | TCP/IPv4 | envelope 32769 字节（下界 +1 相邻值） | §3.5 | 33 |
| 101 | `cwmp_large_download_response_mss` | 正 | TCP/IPv4 | ACS→CPE 方向大报文：GetParameterValuesResponse 大 ParameterList（≥32768B）跨 MSS | §3.5 32KB 双向/§8 | 33 |
| 102 | `cwmp_large_fault_mss` | 正 | TCP/IPv4 | 大 Fault（长 FaultString）跨 MSS 分段 | §3.5 | 15 |
| 103 | `cwmp_min_frame_inform` | 正 | TCP/IPv4 | 最小合法 Inform（字段全必选最小形态） | §3.4.1/A.3.3.1 | 11 |
| 104 | `cwmp_fault_8005_resend` | 正 | TCP/IPv4 | Inform 收 8005 Retry request Fault→原样重发 Inform（envelope 不变）→会话继续 | §3.7.1.6/A.5.2 | 13 |
| 105 | `cwmp_inform_fault_terminate` | 正 | TCP/IPv4 | Inform 收非 8005 Fault（8002）→会话失败终止（无空 POST，直接挥手） | §3.7.1.4/A.5.2 | 9 |
| 106 | `cwmp_inform_paramlist_empty` | 正 | TCP/IPv4 | Inform 空 ParameterList（空表合法不报错，无 ParameterValueStruct） | A.3.3.1/A.3.2.2 | 11 |
| 107 | `cwmp_event_array_64_full` | 正 | TCP/IPv4 | Inform Event 数组恰 64 项（上界恰值合法） | Table 37 | 11 |
| 108 | `cwmp_param_name_256_upper` | 正 | TCP/IPv4 | 参数名恰 256 字符（string(256) 上界恰值，区别于 >256 负例） | A.3.2.2 | 11 |
| 109 | `cwmp_oui_uppercase_hex` | 正 | TCP/IPv4 | DeviceId ManufacturerOUI 段六位大写十六进制（`^[0-9A-F]{6}$`） | Table 39 | 11 |
| 110 | `cwmp_download_filesize_zero` | 正 | TCP/IPv4 | Download FileSize=0（0=大小未知，合法且不产生超量分配） | A.3.2.8 | 11 |
| 111 | `cwmp_cr_username_percent_encoding` | 正 | TCP/IPv4 | CR Authorization username 百分号编码（空格→`%20`，RFC 3986） | §3.4.4 | 22 |
| 112 | `cwmp_acs_port_nondefault` | 正 | TCP/IPv4 | ACS 端口非默认（17547）：端口由 ACS URL 决定，全栈语义不变 | §3.2.1/§3.1 | 11 |
| 113 | `cwmp_neg_profile_mismatch` | 负 | — | profile 与 namespace 版本不匹配（如 cwmp_ipv6_v1 配 SOAP 1.2 命名空间） | 设计 §7 | — |
| 114 | `cwmp_neg_namespace_soap12` | 负 | — | envelope 命名空间为 SOAP 1.2（http://www.w3.org/2003/05/soap-envelope） | 设计 §7 | — |
| 115 | `cwmp_neg_layer_chain_missing_http` | 负 | — | 层链缺 http（tcp→cwmp 直连） | 设计 §7 | — |
| 116 | `cwmp_neg_port_carrier_conflict` | 负 | — | 端口/载体声明矛盾（https profile 配明文端口组合） | 设计 §7 | — |
| 117 | `cwmp_neg_http_method_not_post` | 负 | — | SOAP 承载方法非 POST（GET/PUT 承载 envelope） | 设计 §7 | — |
| 118 | `cwmp_neg_soapaction_nonempty` | 负 | — | SOAP POST 的 SOAPAction 带非空值 | 设计 §7 | — |
| 119 | `cwmp_neg_content_type_wrong` | 负 | — | Content-Type 非 text/xml（application/json） | 设计 §7 | — |
| 120 | `cwmp_neg_content_length_mismatch` | 负 | — | Content-Length 与实体实际长度不符 | 设计 §7 | — |
| 121 | `cwmp_neg_digest_auth_missing` | 负 | — | 401 挑战后重发缺 Authorization | 设计 §7 | — |
| 122 | `cwmp_neg_digest_auth_wrong` | 负 | — | Authorization 摘要计算错误仍继续 | 设计 §7 | — |
| 123 | `cwmp_neg_xml_truncated` | 负 | — | XML 实体截断（envelope 未闭合） | 设计 §7 | — |
| 124 | `cwmp_neg_xml_malformed` | 负 | — | XML 不合法（标签错配） | 设计 §7 | — |
| 125 | `cwmp_neg_envelope_namespace_wrong` | 负 | — | envelope 命名空间非 SOAP 1.1 URI | 设计 §7 | — |
| 126 | `cwmp_neg_body_missing` | 负 | — | Envelope 缺 Body | 设计 §7 | — |
| 127 | `cwmp_neg_response_suffix_missing` | 负 | — | 响应方法名缺 Response 后缀 | 设计 §7 | — |
| 128 | `cwmp_neg_fault_structure_wrong` | 负 | — | Fault 结构不符（faultstring≠CWMP fault / detail 缺 cwmp:Fault） | 设计 §7 | — |
| 129 | `cwmp_neg_first_txn_not_inform` | 负 | — | 会话首事务非 Inform | 设计 §7 | — |
| 130 | `cwmp_neg_request_after_empty_post` | 负 | — | 空 POST 后继续发请求 | 设计 §7 | — |
| 131 | `cwmp_neg_cpe_sends_acs_method` | 负 | — | CPE 发送 ACS 侧方法（方向错，如 CPE 发 SetParameterValues 给 ACS） | 设计 §7 | — |
| 132 | `cwmp_neg_continue_after_fault` | 负 | — | Fault 后继续同事务（未按 §3.7.1.4） | 设计 §7 | — |
| 133 | `cwmp_neg_fault_responds_fault` | 负 | — | 用 Fault 响应 Fault | 设计 §7 | — |
| 134 | `cwmp_neg_response_responds_response` | 负 | — | 响应另一个响应 | 设计 §7 | — |
| 135 | `cwmp_neg_reboot_before_session_end` | 负 | — | 会话未终止即编排重启（同会话 Reboot 后无收尾直接新会话） | 设计 §7 | — |
| 136 | `cwmp_neg_id_mismatch` | 负 | — | 响应 cwmp:ID 与请求不匹配 | 设计 §7 | — |
| 137 | `cwmp_neg_commandkey_orphan` | 负 | — | TransferComplete CommandKey 无来源 Download/Upload | 设计 §7 | — |
| 138 | `cwmp_neg_driven_by_broken` | 负 | — | flows[].driven_by 引用不存在的事务/字段 | 设计 §7 | — |
| 139 | `cwmp_neg_param_name_over_256` | 负 | — | 参数名 >256 字符 | 设计 §7 | — |
| 140 | `cwmp_neg_command_key_over_32` | 负 | — | CommandKey >32 字符 | 设计 §7 | — |
| 141 | `cwmp_neg_invalid_event_code` | 负 | — | 事件码非法值（如 "13 INVALID"/小写/未知码） | 设计 §7 | — |
| 142 | `cwmp_neg_invalid_fault_code` | 负 | — | FaultCode 非法值（如 9999/负值） | 设计 §7 | — |
| 143 | `cwmp_neg_invalid_filetype` | 负 | — | FileType 非法枚举（"7 Unknown"/空） | 设计 §7 | — |
| 144 | `cwmp_neg_event_array_over_64` | 负 | — | Event 数组 >64 项 | 设计 §7 | — |
| 145 | `cwmp_neg_truncated_entity` | 负 | — | 超长实体截断（Content-Length 声明 > 实际生成体，实体不完整） | 设计 §7 | — |
| 146 | `cwmp_neg_m_download_without_7` | 负 | — | M Download 事件无同帧 7 TRANSFER COMPLETE | 设计 §7 | — |
| 147 | `cwmp_neg_m_reboot_without_1` | 负 | — | M Reboot 事件无同帧 1 BOOT | 设计 §7 | — |
| 148 | `cwmp_neg_m_upload_without_7` | 负 | — | M Upload 事件无同帧 7 TRANSFER COMPLETE | 设计 §7 | — |
| 149 | `cwmp_neg_inform_bootstrap_with_boot` | 负 | — | 0 BOOTSTRAP 与 1 BOOT 同帧组合（非法：两码互斥，一为首次引导一为重启引导） | 设计 §7 | — |
| 150 | `cwmp_neg_url_userinfo` | 负 | — | Download URL 含 userinfo 组件（§3.5 禁止） | 设计 §7 | — |
## 3. 线上编码与偏移断言（继承 v2.1，基线不变）

无 VLAN、无 IP options、无 TCP options 时，HTTP 应用载荷起点：IPv4 offset **54**（Eth 14 + IPv4 20 + TCP 20）、IPv6 offset **74**（14 + 40 + 20）。HTTP 消息边界由 Content-Length（或合法 chunked）界定；TCP 分段边界不是 HTTP/SOAP 消息边界（§3.4.6 禁 pipelining，请求与响应严格交替）。SOAP 1.1 envelope 从应用载荷起点起：`3C 73 6F 61 70 3A 45 6E 76 65 6C 6F 70 65`（`<soap:Envelope`）。断言字段全部落 `http.*`/`tcp.*`/`ipv6.nxt` 实测字段 + frames hex 前缀（本机 3.6.14 无 `cwmp.*` 字段，`tshark -G fields` 实测核验）。标注「校准」的断言值实现期以实测/原文回对后钉死，不臆造。

## 4. 正例逐项断言契约

1. **`cwmp_inform_ipv4`**（TCP/IPv4，packet_count=11）：POST Inform offset 54 起 `50 4F 53 54`；SOAPAction 空值行存在；Content-Type text/xml；`http.content_length` nonzero；InformResponse `200`；cwmp:ID 响应回带同值；收尾空 POST 无 SOAPAction/Content-Type、响应 `204`。
2. **`cwmp_inform_event_bootstrap`**（TCP/IPv4，packet_count=11）：Inform EventCode 段 frames 含 `30 20 42 4F 4F 54 53 54 52 41 50`（`0 BOOTSTRAP`）。
3. **`cwmp_inform_event_boot`**（TCP/IPv4，packet_count=11）：frames 含 `31 20 42 4F 4F 54`（`1 BOOT`）。
4. **`cwmp_inform_event_value_change`**（TCP/IPv4，packet_count=11）：frames 含 `34 20 56 41 4C 55 45 20 43 48 41 4E 47 45`。
5. **`cwmp_inform_event_tc_mdownload`**（TCP/IPv4，packet_count=11）：frames 同时含 `37 20 54 52 41 4E 53 46 45 52 20 43 4F 4D 50 4C 45 54 45` 与 `4D 20 44 6F 77 6E 6C 6F 61 64`（同帧同因事件）；两事件的 Event CommandKey 段 frames same_as（同值，均回带原 Download 请求的 CommandKey）。
6. **`cwmp_connection_request`**（TCP/IPv4，packet_count=22）：CR 侧 GET 请求行 `47 45 54 20`；`401` 后 `WWW-Authenticate: Digest` 含 `realm`/`nonce`/`opaque`/`qop="auth"`/`algorithm=MD5`；重发 GET 的 `Authorization` 头含 `username`/`realm`/`nonce`/`uri`/`response`/`cnonce`/`nc`/`qop="auth"`/`algorithm`，`opaque` 原样回带；`200` 空体；新会话 Inform 事件码 `36 20 43 4F 4E 4E 45 43 54 49 4F 4E 20 52 45 51 55 45 53 54`（`6 CONNECTION REQUEST`）。
7. **`cwmp_get_parameter_values`**（TCP/IPv4，packet_count=15）：请求 Body 含 `GetParameterNames`/`ParameterPath`/`NextLevel`；响应 ParameterInfoStruct `Writable`；GetParameterValues 响应 ParameterValueStruct Name/Value。
8. **`cwmp_set_parameter_values`**（TCP/IPv4，packet_count=15）：请求含 `ParameterKey`（第 1 笔为空串——合法且保持为空；第 2 笔 32 字符上界恰值）；两笔响应 Status 段 frames 分别含 `3C 53 74 61 74 75 73 3E 30 3C` 与 `3E 31 3C`（`<Status>0<`/`>1<`）。
9. **`cwmp_download_transfer_complete`**（TCP/IPv4，packet_count=26）：DownloadResponse Status=1 段 frames；TransferComplete CommandKey 与 Download 同值（跨会话关联）；FaultCode=0。
10. **`cwmp_download_flow_correlation`**（TCP/IPv4，packet_count=24）：副连接独立四元组（新源端口）；副连接 GET URI 与 Download.URL 一致；主会话挥手在副连接完成后（包序：DownloadResponse 对 → 副连接块 → 空 POST/204 → 挥手）。
11. **`cwmp_upload_transfer_complete`**（TCP/IPv4，packet_count=26）：UploadResponse Status=1；副连接 PUT（`50 55 54 20`）流关联；TC CommandKey 同值。
12. **`cwmp_reboot_command_key`**（TCP/IPv4，packet_count=26）：RebootResponse 存在；会话 1 挥手先于会话 2（终止后才重启）；两 CommandKey same_as。
13. **`cwmp_fault_soap`**（TCP/IPv4，packet_count=13）：Fault 帧含 `43 57 4D 50 20 66 61 75 6C 74`（`CWMP fault`）；`faultcode` 段含 `53 65 72 76 65 72`；Fault 后会话继续（有后续事务+收尾对）。
14. **`cwmp_http_keepalive_multi_transaction`**（TCP/IPv4，packet_count=17）：包序严格请求-响应交替；中段 204（应答非空 POST）不关连接；收尾空 POST/204。
15. **`cwmp_ipv6`**（TCP/IPv6，packet_count=11）：`ipv6.nxt=6`；应用载荷 offset 74 起同 v4 字节（同一逻辑 envelope）。
16. **`cwmp_multi_session`**（TCP/IPv4，packet_count=30）：两会话 src_port distinct；`cwmp:ID` 各自递增；DeviceId SerialNumber 不同；第二会话握手包号 = 前会话总包数+1。
17. **`cwmp_mss_large_soap`**（TCP/IPv4，packet_count=33）：`http.content_length` ≥32768；tcp 流重组后 envelope 完整（`3C 2F 73 6F 61 70 3A 45 6E 76 65 6C 6F 70 65 3E` 收尾）；段数 = ceil(32768/1460)≈23。
18. **`cwmp_get_parameter_attributes`**（TCP/IPv4，packet_count=11）：请求 Body 含 `GetParameterAttributes`/`ParameterNames`；响应含 `Notification` 段 frames 与 `AccessList`。
19. **`cwmp_set_parameter_attributes`**（TCP/IPv4，packet_count=11）：请求含 `SetParameterAttributes`/`NotificationChange`；响应 200，SOAP Body 仅含空 `<SetParameterAttributesResponse/>` 元素（无子参数；响应方法名 = 请求方法名 + `Response`）。
20. **`cwmp_add_object`**（TCP/IPv4，packet_count=11）：请求 ObjectName 值以 `2E 3C`（`.<`）收尾；响应含 `InstanceNumber` 与 `Status`。
21. **`cwmp_delete_object`**（TCP/IPv4，packet_count=11）：请求 ObjectName 含实例号段；响应含 `Status`。
22. **`cwmp_factory_reset_bootstrap`**（TCP/IPv4，packet_count=28）：会话 1 FactoryReset 请求/响应 Body 仅含空 `<FactoryResetResponse/>` 元素→收尾；会话 2 Inform 事件 `30 20 42 4F 4F 54 53 54 52 41 50`。
23. **`cwmp_schedule_download`**（TCP/IPv4，packet_count=28）：请求含 `ScheduleDownload`/`StartTime`/`MaxRetries`；响应含 `Status`/`StartTime`；Inform frames 同时含 `33 20 53 43 48 45 44 55 4C 45 44`（`3 SCHEDULED`）与 `4D 20 53 63 68 65 64 75 6C 65 44 6F 77 6E 6C 6F 61 64`。
24. **`cwmp_schedule_upload`**（TCP/IPv4，packet_count=11）：请求含 `ScheduleUpload`/`StartTime`；响应含 `Status`/`StartTime`。
25. **`cwmp_autonomous_transfer_complete`**（TCP/IPv4，packet_count=24）：通知无前导 ACS 请求（包序：POST 直发）；FaultStruct 段存在；Inform frames 含 `31 30 20 41 55 54 4F 4E 4F 4D 4F 55 53`；ACS 应答 Body 仅含空 `<AutonomousTransferCompleteResponse/>` 元素（A.3.3.3，按 cwmp-1-2.xsd 校准）；随后收尾空 POST/204 终止。
26. **`cwmp_request_download`**（TCP/IPv4，packet_count=30）：请求含 `RequestDownload`/`FileType`；响应 Body 仅含空 `<RequestDownloadResponse/>` 元素；Inform frames 含 `39 20 52 45 51 55 45 53 54 20 44 4F 57 4E 4C 4F 41 44`；后继 Download 请求存在。
27. **`cwmp_kicked`**（TCP/IPv4，packet_count=26）：请求含 `Kicked`；响应含 `KickURL`/`RequestID`；Inform frames 含 `35 20 4B 49 43 4B 45 44`（`5 KICKED`）。
28. **`cwmp_inform_diagnostics_complete`**（TCP/IPv4，packet_count=11）：frames 含 `38 20 44 49 41 47 4E 4F 53 54 49 43 53 20 43 4F 4D 50 4C 45 54 45`。
29. **`cwmp_inform_retry_401`**（TCP/IPv4，packet_count=13）：首 Inform 后 `401`；重发 Inform 逐字节含 `41 75 74 68 6F 72 69 7A 61 74 69 6F 6E 3A 20 44 69 67 65 73 74`（`Authorization: Digest`）；RetryCount 段 frames 含非零（`3E 30 3C` 之外的 `3E 31 3C`）。
30. **`cwmp_get_parameter_values_empty_response`**（TCP/IPv4，packet_count=11）：响应 ParameterList 段 frames 含 `2F 3E`（自闭合空表）且无 ParameterValueStruct 子元素。
31. **`cwmp_get_parameter_names_nextlevel_0`**（TCP/IPv4，packet_count=11）：请求 NextLevel 段 frames 含 `3E 30 3C`（`>0<`）。
32. **`cwmp_get_parameter_names_nextlevel_1`**（TCP/IPv4，packet_count=11）：请求 NextLevel 段 frames 含 `3E 31 3C`（`>1<`）。
33. **`cwmp_get_parameter_names_root_path`**（TCP/IPv4，packet_count=11）：请求 ParameterPath 段 frames 含 `2F 3E`（空元素）。
34. **`cwmp_get_parameter_names_empty_response`**（TCP/IPv4，packet_count=11）：响应 ParameterList 自闭合空表。
35. **`cwmp_set_parameter_values_multi_param`**（TCP/IPv4，packet_count=13）：请求 ParameterList 含 2 个 ParameterValueStruct（ParameterValueStruct 出现 2 次）。
36. **`cwmp_set_parameter_values_fault_multi_param`**（TCP/IPv4，packet_count=13）：detail 含 2 个 SetParameterValuesFault 元素；各含 FaultCode 段 `39 30 30 37`（`9007`）；主 FaultStruct FaultCode 段 frames 含 `39 30 30 33`（`9003`）；主 faultcode 段 frames 含 `43 6C 69 65 6E 74`（`Client`）。
37. **`cwmp_download_response_status_0_times`**（TCP/IPv4，packet_count=11）：响应含 `3C 53 74 61 72 74 54 69 6D 65 3E`（`<StartTime>`）与 `3C 43 6F 6D 70 6C 65 74 65 54 69 6D 65 3E`；Status=0。
38. **`cwmp_download_cred_target_fields`**（TCP/IPv4，packet_count=11）：请求含 `Username`/`Password`/`TargetFileName` 元素各一。
39. **`cwmp_download_https_url`**（TCP/IPv4，packet_count=11）：请求 URL 段 frames 含 `68 74 74 70 73 3A 2F 2F`（`https://`）。
40. **`cwmp_download_delay_success`**（TCP/IPv4，packet_count=35）：会话 1 DownloadResponse(1) 且同会话无副连接/无 TC；会话 2（DelaySeconds 到期后）副连接 GET + TransferComplete。
41. **`cwmp_upload_put_flow_correlation`**（TCP/IPv4，packet_count=24）：副连接 PUT（`50 55 54 20`）独立四元组；driven_by 主从引用成立。
42. **`cwmp_upload_response_status_0`**（TCP/IPv4，packet_count=11）：响应 Status 段 frames 含 `3E 30 3C`。
43. **`cwmp_transfer_complete_fault_9010`**（TCP/IPv4，packet_count=13）：FaultCode 段 frames 含 `39 30 31 30`（`9010`）；`<StartTime>`/`<CompleteTime>` 存在。
44. **`cwmp_reboot_empty_command_key`**（TCP/IPv4，packet_count=11）：请求 CommandKey 段 frames 含 `2F 3E`。
45. **`cwmp_get_rpc_methods_cpe_to_acs`**（TCP/IPv4，packet_count=13）：GetRPCMethods 请求为 CPE 发起的 POST（CpeRequests 状态，§3.7.1 Table 7：CPE 有待发请求直接 POST，不经空 POST 递送）——方向断言：POST 帧发送方为 CPE 侧 IP:port（与 Inform 同向），响应 SOAP Body 含空语义 `MethodList` 回带（`GetRPCMethodsResponse`）+ACS 侧 MethodList 区分。
46. **`cwmp_parameter_key_same_session`**（TCP/IPv4，packet_count=15）：AddObject ParameterKey 段与 SetParameterValues ParameterKey 段 frames same_as（同会话 ACS 侧携带同一 ParameterKey，跨事务关联）。包数按 Table 10 紧凑编排基线（ACS 请求可内嵌于对前序请求的响应中）；实现期按实际编排结构校准包数。
47. **`cwmp_fault_id_echo`**（TCP/IPv4，packet_count=11）：Fault 响应 Header 段 cwmp:ID 与请求同值（frames same_as）。
48. **`cwmp_soapaction_present_empty`**（TCP/IPv4，packet_count=11）：请求头区 frames 含 `53 4F 41 50 41 63 74 69 6F 6E 3A 0D 0A`（`SOAPAction:` 空值 CRLF）。
49. **`cwmp_xml_escape_full`**（TCP/IPv4，packet_count=11）：参数值 frames 含 `26 61 6D 70 3B`/`26 6C 74 3B`/`26 67 74 3B`/`26 71 75 6F 74 3B`/`26 61 70 6F 73 3B` 各一。
50. **`cwmp_param_value_utf8`**（TCP/IPv4，packet_count=11）：value 段 frames 含多字节 UTF-8 序列（非 ASCII 字节 ≥1）。
51. **`cwmp_param_value_empty_string`**（TCP/IPv4，packet_count=11）：ParameterValueStruct 存在且 Value 段 frames 含 `3E 3C`。
52. **`cwmp_currenttime_negative_offset`**（TCP/IPv4，packet_count=11）：CurrentTime 段 frames 含 `2D 30 35 3A 30 30`（`-05:00`）。
53. **`cwmp_inform_paramlist_multi`**（TCP/IPv4，packet_count=11）：ParameterValueStruct 出现 2 次。
54. **`cwmp_event_code_len_upper`**（TCP/IPv4，packet_count=11）：64/32 字符边界值填充（长度断言以重组后字节计数）。
55. **`cwmp_manufacturer_len_upper`**（TCP/IPv4，packet_count=11）：Manufacturer 值 64 字符边界。
56. **`cwmp_download_filesize_nonzero`**（TCP/IPv4，packet_count=11）：FileSize 段 frames 含非零十进制。
57. **`cwmp_filetype_enum_2_web`**（TCP/IPv4，packet_count=11）：frames 含 `32 20 57 65 62 20 43 6F 6E 74 65 6E 74`。
58. **`cwmp_filetype_enum_4_tone`**（TCP/IPv4，packet_count=11）：frames 含 `34 20 54 6F 6E 65 20 46 69 6C 65`。
59. **`cwmp_filetype_enum_5_ringer`**（TCP/IPv4，packet_count=11）：frames 含 `35 20 52 69 6E 67 65 72 20 46 69 6C 65`。
60. **`cwmp_filetype_enum_6_stored`**（TCP/IPv4，packet_count=11）：frames 含 `36 20 53 74 6F 72 65 64 20 46 69 72 6D 77 61 72 65 20 49 6D 61 67 65`。
61. **`cwmp_filetype_vendor_x`**（TCP/IPv4，packet_count=11）：FileType 段 frames 含 `58 20 30 30 31 31 32 32 20`（`X 001122 `）。
62. **`cwmp_id_special_values`**（TCP/IPv4，packet_count=11）：ID 段 string(32) 上界（32 字符）；空串与特殊字符（空格/UTF-8/标点）取值；响应回带同值（成功与 Fault 均须）。
63. **`cwmp_content_type_charset`**（TCP/IPv4，packet_count=11）：请求头 frames 含 `63 68 61 72 73 65 74 3D 22 75 74 66 2D 38 22`。
64. **`cwmp_delayseconds_large`**（TCP/IPv4，packet_count=11）：DelaySeconds 段十进制大值（回对校准 uint 上界断言）。
65. **`cwmp_paramname_255`**（TCP/IPv4，packet_count=11）：ParameterName 255 字符。
66. **`cwmp_cpe_fault_9000`**（TCP/IPv4，packet_count=11）：Fault detail FaultCode 段 frames 含 `39 30 30 30`；faultcode=Server。
67. **`cwmp_cpe_fault_9005`**（TCP/IPv4，packet_count=11）：FaultCode 段含 `39 30 30 35`。
68. **`cwmp_cpe_fault_9008`**（TCP/IPv4，packet_count=11）：FaultCode 段含 `39 30 30 38`。
69. **`cwmp_cpe_fault_9001`**（TCP/IPv4，packet_count=11）：FaultCode 段含 `39 30 30 31`。
70. **`cwmp_cpe_fault_9002`**（TCP/IPv4，packet_count=11）：FaultCode 段含 `39 30 30 32`。
71. **`cwmp_cpe_fault_9004`**（TCP/IPv4，packet_count=11）：FaultCode 段含 `39 30 30 34`。
72. **`cwmp_cpe_fault_9006`**（TCP/IPv4，packet_count=11）：FaultCode 段含 `39 30 30 36`。
73. **`cwmp_cpe_fault_9009`**（TCP/IPv4，packet_count=11）：FaultCode 段含 `39 30 30 39`。
74. **`cwmp_cpe_fault_9011`**（TCP/IPv4，packet_count=13）：FaultCode 段含 `39 30 31 31`。
75. **`cwmp_cpe_fault_9012`**（TCP/IPv4，packet_count=13）：FaultCode 段含 `39 30 31 32`。
76. **`cwmp_cpe_fault_9013`**（TCP/IPv4，packet_count=13）：FaultCode 段含 `39 30 31 33`。
77. **`cwmp_cpe_fault_9014`**（TCP/IPv4，packet_count=13）：FaultCode 段含 `39 30 31 34`。
78. **`cwmp_cpe_fault_9020`**（TCP/IPv4，packet_count=13）：FaultCode 段含 `39 30 32 30`。
79. **`cwmp_cpe_fault_9800_vendor`**（TCP/IPv4，packet_count=11）：FaultCode 段含 `39 38 30 30`；faultcode=Client。
80. **`cwmp_cpe_fault_9899_vendor`**（TCP/IPv4，packet_count=11）：FaultCode 段含 `39 38 39 39`。
81. **`cwmp_acs_fault_8000`**（TCP/IPv4，packet_count=11）：FaultCode 段含 `38 30 30 30`；会话继续（CPE 不重发——非 8005）。
82. **`cwmp_acs_fault_8001`**（TCP/IPv4，packet_count=11）：FaultCode 段含 `38 30 30 31`。
83. **`cwmp_acs_fault_8003`**（TCP/IPv4，packet_count=11）：FaultCode 段含 `38 30 30 33`。
84. **`cwmp_acs_fault_8004`**（TCP/IPv4，packet_count=11）：FaultCode 段含 `38 30 30 34`。
85. **`cwmp_acs_fault_8006`**（TCP/IPv4，packet_count=11）：FaultCode 段含 `38 30 30 36`。
86. **`cwmp_acs_fault_8800_vendor`**（TCP/IPv4，packet_count=11）：FaultCode 段含 `38 38 30 30`。
87. **`cwmp_digest_auth_params`**（TCP/IPv4，packet_count=15）：Authorization 头 frames 含 `6E 6F 6E 63 65 3D`（nonce=）/`75 72 69 3D`（uri=）/`63 6E 6F 6E 63 65 3D`（cnonce=）/`6E 63 3D`（nc=）/`72 65 73 70 6F 6E 73 65 3D`（response=）/`6F 70 61 71 75 65 3D`（opaque=，与 401 挑战同值）/`61 6C 67 6F 72 69 74 68 6D 3D`（algorithm=）/`71 6F 70 3D 61 75 74 68`（qop=auth）。
88. **`cwmp_digest_stale_true`**（TCP/IPv4，packet_count=17）：第二次 401 的 WWW-Authenticate 含 `73 74 61 6C 65 3D 74 72 75 65`（`stale=true`）；重发 Authorization 成功。
89. **`cwmp_chunked_envelope`**（TCP/IPv4，packet_count=13）：请求头含 `54 72 61 6E 73 66 65 72 2D 45 6E 63 6F 64 69 6E 67 3A 20 63 68 75 6E 6B 65 64`；chunk 边界帧存在；流重组后与 Content-Length 等价形态字节一致。
90. **`cwmp_http_redirect_chain`**（TCP/IPv4，packet_count=13）：响应 `33 30 32` ×2；Location 头存在；最终 `32 30 30`；跳数 ≤5；重定向 URL 不持久化（重发 POST envelope 与首次 frames same_as）。
91. **`cwmp_namespace_1_1`**（TCP/IPv4，packet_count=11）：envelope cwmp 命名空间 frames 含 `75 72 6E 3A 64 73 6C 66 6F 72 75 6D 2D 6F 72 67 3A 63 77 6D 70 2D 31 2D 31`。
92. **`cwmp_namespace_1_2`**（TCP/IPv4，packet_count=11）：frames 含 `63 77 6D 70 2D 31 2D 32`。
93. **`cwmp_empty_post_content_length_zero`**（TCP/IPv4，packet_count=11）：空 POST 头 frames 含 `43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 30`。
94. **`cwmp_request_uri_variant`**（TCP/IPv4，packet_count=11）：POST 行含路径+`3F` query。
95. **`cwmp_cookie_echo_session`**（TCP/IPv4，packet_count=13）：首响应 Set-Cookie 头存在；后续每请求 Cookie 头存在且值 same_as。
96. **`cwmp_concurrent_sessions`**（TCP/IPv4×2，packet_count=22）：两连接帧交错（包序非整块）；两 src_ip distinct；各自 cwmp:ID 递增独立。
97. **`cwmp_cr_busy_503`**（TCP/IPv4，packet_count=16）：CR GET 后 `35 30 33`（`503`）；原 CPE 会话继续不受影响。
98. **`cwmp_ipv6_cr_download`**（TCP/IPv6，packet_count=35）：`ipv6.nxt=6`；CR 401/200 流程同 v4 字节；副连接 v6 四元组独立。
99. **`cwmp_envelope_32768_boundary`**（TCP/IPv4，packet_count=33）：`http.content_length`=32768 精确；重组完整。
100. **`cwmp_envelope_32769`**（TCP/IPv4，packet_count=33）：`http.content_length`=32769。
101. **`cwmp_large_download_response_mss`**（TCP/IPv4，packet_count=33）：响应方向大数据跨 ~23 段；重组后 envelope 完整收尾。
102. **`cwmp_large_fault_mss`**（TCP/IPv4，packet_count=15）：Fault 响应跨 ≥2 段；重组后 `CWMP fault` 完整。
103. **`cwmp_min_frame_inform`**（TCP/IPv4，packet_count=11）：`http.content_length` 为最小合法值（实现期以最小 fixture 实测钉死）。
104. **`cwmp_fault_8005_resend`**（TCP/IPv4，packet_count=13）：Inform 收 Fault（faultcode=Server、FaultCode 段 frames 含 `38 30 30 35`（`8005`））→原样重发 Inform（重发 envelope frames 与首次 Inform frames same_as，不得改变任何内容）→InformResponse 正常到达（会话继续）。
105. **`cwmp_inform_fault_terminate`**（TCP/IPv4，packet_count=9）：Inform 收 Fault（FaultCode 段 frames 含 `38 30 30 32`（`8002`））→会话失败终止：无重发、无后续事务、无收尾空 POST，Fault 应答后直接挥手（FIN）。
106. **`cwmp_inform_paramlist_empty`**（TCP/IPv4，packet_count=11）：Inform Body ParameterList 空表（重组后无 `ParameterValueStruct` hex）；InformResponse 正常返回（空表合法不报错）。
107. **`cwmp_event_array_64_full`**（TCP/IPv4，packet_count=11）：Inform Event 数组 `soap-enc:arrayType` 恰 64 项（上界恰值合法）；成员 EventStruct 编码完整。
108. **`cwmp_param_name_256_upper`**（TCP/IPv4，packet_count=11）：GetParameterValues ParameterNames 恰 256 字符（重组后字节计数 = 256；与 >256 负例相邻）。
109. **`cwmp_oui_uppercase_hex`**（TCP/IPv4，packet_count=11）：DeviceId ManufacturerOUI 段六位大写十六进制（`^[0-9A-F]{6}$` 实测比对；Manufacturer 为 string(64) 自由文本，不在本断言面）。
110. **`cwmp_download_filesize_zero`**（TCP/IPv4，packet_count=11）：Download FileSize=0（=大小未知，合法路径；生成器不产生超量分配）。
111. **`cwmp_cr_username_percent_encoding`**（TCP/IPv4，packet_count=22）：CR Authorization username 含百分号编码（空格→`%20`，RFC 3986/§3.4.4）；digest 其余参数同 `cwmp_connection_request`。
112. **`cwmp_acs_port_nondefault`**（TCP/IPv4，packet_count=11）：会话目的端口 17547（非默认 7547）——`tcp.dst_port` 断言；SOAP/HTTP 断言面与 `cwmp_inform_ipv4` 基线一致（端口由 ACS URL 决定，§3.2.1）。

**正例总则**：每条至少含 packet_count、载体与方向断言、`has_payload`、可观察字段（`http.request.method`/`http.response.code`/`http.content_length` 等）与稳定 frames hex 前缀；动态值（cwmp:ID、cookie、时间戳、CommandKey）只用 presence/nonzero/same_as_packet/distinct 断言，不枚举固定运行期值。合法 Fault 响应、Status=1、401 挑战、204 空体、503 忙、8005 重发均为正例行为，不得误报 planner error。

## 5. 负例契约（逐故障输入原子拆分）

负例必须在 planner/validator 阶段失败并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或仅 TCP/HTTP 外壳的假成功。执行期 `expect` 严格只有 `{"expect_error","error_contains"}` 两个键。主锚词与设计 §7 表一致（可并列备选）：

| # | ID | 类 | 故障输入 | 主锚词（备选） |
|---:|---|---|---|---|
| 1 | `cwmp_neg_profile_mismatch` | profile | profile 与 namespace 版本不匹配（如 cwmp_ipv6_v1 配 SOAP 1.2 命名空间） | `profile`（—） |
| 2 | `cwmp_neg_namespace_soap12` | namespace | envelope 命名空间为 SOAP 1.2（http://www.w3.org/2003/05/soap-envelope） | `namespace`（—） |
| 3 | `cwmp_neg_layer_chain_missing_http` | carrier | 层链缺 http（tcp→cwmp 直连） | `carrier`（—） |
| 4 | `cwmp_neg_port_carrier_conflict` | carrier | 端口/载体声明矛盾（https profile 配明文端口组合） | `carrier`（—） |
| 5 | `cwmp_neg_http_method_not_post` | method | SOAP 承载方法非 POST（GET/PUT 承载 envelope） | `method`（—） |
| 6 | `cwmp_neg_soapaction_nonempty` | http | SOAP POST 的 SOAPAction 带非空值 | `http`（—） |
| 7 | `cwmp_neg_content_type_wrong` | content-type | Content-Type 非 text/xml（application/json） | `content-type`（—） |
| 8 | `cwmp_neg_content_length_mismatch` | length | Content-Length 与实体实际长度不符 | `length`（—） |
| 9 | `cwmp_neg_digest_auth_missing` | auth | 401 挑战后重发缺 Authorization | `auth`（—） |
| 10 | `cwmp_neg_digest_auth_wrong` | auth | Authorization 摘要计算错误仍继续 | `auth`（—） |
| 11 | `cwmp_neg_xml_truncated` | xml | XML 实体截断（envelope 未闭合） | `xml`（—） |
| 12 | `cwmp_neg_xml_malformed` | xml | XML 不合法（标签错配） | `xml`（—） |
| 13 | `cwmp_neg_envelope_namespace_wrong` | envelope | envelope 命名空间非 SOAP 1.1 URI | `envelope`（—） |
| 14 | `cwmp_neg_body_missing` | soap | Envelope 缺 Body | `soap`（—） |
| 15 | `cwmp_neg_response_suffix_missing` | fault | 响应方法名缺 Response 后缀 | `fault`（—） |
| 16 | `cwmp_neg_fault_structure_wrong` | fault | Fault 结构不符（faultstring≠CWMP fault / detail 缺 cwmp:Fault） | `fault`（—） |
| 17 | `cwmp_neg_first_txn_not_inform` | session | 会话首事务非 Inform | `session`（—） |
| 18 | `cwmp_neg_request_after_empty_post` | state | 空 POST 后继续发请求 | `state`（—） |
| 19 | `cwmp_neg_cpe_sends_acs_method` | state | CPE 发送 ACS 侧方法（方向错，如 CPE 发 SetParameterValues 给 ACS） | `state`（—） |
| 20 | `cwmp_neg_continue_after_fault` | state | Fault 后继续同事务（未按 §3.7.1.4） | `state`（—） |
| 21 | `cwmp_neg_fault_responds_fault` | sequence | 用 Fault 响应 Fault | `sequence`（—） |
| 22 | `cwmp_neg_response_responds_response` | sequence | 响应另一个响应 | `sequence`（—） |
| 23 | `cwmp_neg_reboot_before_session_end` | sequence | 会话未终止即编排重启（同会话 Reboot 后无收尾直接新会话） | `sequence`（—） |
| 24 | `cwmp_neg_id_mismatch` | correlation | 响应 cwmp:ID 与请求不匹配 | `correlation`（—） |
| 25 | `cwmp_neg_commandkey_orphan` | command | TransferComplete CommandKey 无来源 Download/Upload | `command`（—） |
| 26 | `cwmp_neg_driven_by_broken` | correlation | flows[].driven_by 引用不存在的事务/字段 | `correlation`（—） |
| 27 | `cwmp_neg_param_name_over_256` | length | 参数名 >256 字符 | `length`（—） |
| 28 | `cwmp_neg_command_key_over_32` | parameter | CommandKey >32 字符 | `parameter`（—） |
| 29 | `cwmp_neg_invalid_event_code` | value | 事件码非法值（如 "13 INVALID"/小写/未知码） | `value`（—） |
| 30 | `cwmp_neg_invalid_fault_code` | value | FaultCode 非法值（如 9999/负值） | `value`（—） |
| 31 | `cwmp_neg_invalid_filetype` | value | FileType 非法枚举（"7 Unknown"/空） | `value`（—） |
| 32 | `cwmp_neg_event_array_over_64` | length | Event 数组 >64 项 | `length`（—） |
| 33 | `cwmp_neg_truncated_entity` | length | 超长实体截断（Content-Length 声明 > 实际生成体，实体不完整） | `length`（—） |
| 34 | `cwmp_neg_m_download_without_7` | value | M Download 事件无同帧 7 TRANSFER COMPLETE | `value`（—） |
| 35 | `cwmp_neg_m_reboot_without_1` | value | M Reboot 事件无同帧 1 BOOT | `value`（—） |
| 36 | `cwmp_neg_m_upload_without_7` | value | M Upload 事件无同帧 7 TRANSFER COMPLETE | `value`（—） |
| 37 | `cwmp_neg_inform_bootstrap_with_boot` | value | 0 BOOTSTRAP 与 1 BOOT 同帧组合（非法：两码互斥，一为首次引导一为重启引导） | `value`（—） |
| 38 | `cwmp_neg_url_userinfo` | value | Download URL 含 userinfo 组件（`http://user:pass@host/file.bin`，§3.5 禁止 URL userinfo） | `value`（—） |

负例不能用「0 包」、空 PCAP 或任务成功替代错误传播；动态 ID 缺失/错配不得由 planner 自动补齐。

## 6. 五层覆盖映射（v1.2 行为面对照）

| 层面 | 落点 |
|---|---|
| 功能 | RPC 面：11 新增 baseline RPC 正例 + 存量 RPC 扩展例（§4 前 58 条）；Fault 逐值正例族（CPE 9000–9899、ACS 8000–8800 编排）；负例 38 条逐故障输入；DU/QueuedTransfers 范围外（设计 §1 显式声明） |
| 性能 | 大 envelope 双向（`cwmp_mss_large_soap`/`cwmp_large_download_response_mss`）、32KB 边界两态（32768/32769）、大 Fault 跨段、最小合法 Inform |
| 数据场景 | 值域例：XML 转义全件套/UTF-8/空串/负时区偏移/多参数/长度上界（EventCode 64/CommandKey 32/Manufacturer 64/参数名 256 恰值）/FileType 全枚举+厂商 X/ID 值域/charset 变体/FileSize 0 与非 0/DelaySeconds 三态/NextLevel 0/1/空表/RetryCount>0 |
| 地址与流 | v4 基线 + `cwmp_ipv6` + `cwmp_ipv6_cr_download`；单流基线；多会话展开 + 并发会话（`cwmp_concurrent_sessions`）；流关联 Download GET / Upload PUT 两条副连接 |
| 业务 | 周期 Inform、CR 主动排查（含忙 503）、批量参数管理（Values/Names/Attributes）、对象管理（Add/DeleteObject）、四传输下发 + 两完成上报、RequestDownload/Kicked、Reboot/FactoryReset、重定向链、digest 认证（会话级 + stale + 参数逐项） |

## 7. 机器契约与一致性

1. `cwmp.json` 注册时按本文 §2 全量 150 条生成；当前仅 `cwmp_neg_unregistered` 占位（`expect_error=true`、`error_contains="unknown layer"`），不计入语义用例。
2. 正例均有 packet_count/载体/方向/`has_payload`/字段与 frames 断言；负例 `expect` 键集合恰为 `{expect_error, error_contains}`。
3. 负例主锚词与设计 §7 表一致；「校准」标注项实现期回对后同步四件套。
4. 包数按 §1.5 公式复核：正常会话 = 3 握手 + 2×事务对数 +（副连接块 9）+ 4 挥手；失败会话无收尾对；多会话/并发按块顺序计。
5. 断言字段全部实测（无 `cwmp.*` 臆造）；hex 前缀与设计 §3 一致。

## 8. 修订记录

- v3.1.1（2026-09-01，二轮复验关单轮）：rr-cwmp 二轮复验 MAJOR 六项全部 CLOSED。关单修复：**V-11** #87 digest 断言补全 `nc=`/`uri=`/`opaque=`（与挑战同值）/`algorithm=` hex；**R-3** #109 断言面改为仅 ManufacturerOUI（Manufacturer 为自由文本）；**R-4** 修订记录笔误 #143→#149；**R-5** #46 补 Table 10 紧凑编排包数校准说明；**R-6** 新增正例 #112 `cwmp_acs_port_nondefault`（非默认端口落点），RST/异常中断由设计 §4 显式声明不适用（FIN 挥手统一）。计数 149→**150 = 112 正 + 38 负**，负例编号 112–149→113–150；修订记录 v2.1.1/v2.1.0 日期纠正为 2026-09-01（与设计文档同轮同期）。
- v3.1.0（2026-09-01，复验修复轮）：rr-cwmp 复验 6 项 MAJOR（V-01~V-06）+ MINOR 全项修复。**V-01** 新增 Fault 原子例 `cwmp_fault_8005_resend`（#104，Inform 收 8005→原样重发，重发 envelope frames same_as）与 `cwmp_inform_fault_terminate`（#105，Inform 收非 8005（8002）→会话失败终止：无空 POST、直接挥手）；faultcode=Client 断言面落在 #36（补 `43 6C 69 65 6E 74` hex 与主 FaultCode `39 30 30 33` hex，与 #13 的 Server 面合成二值覆盖）。**V-02** #46 断言校正：TransferComplete 的 CommandKey 来自触发它的 Download/Upload/Reboot 请求、不回带 SetParameterValues 的 ParameterKey（cwmp-1-2.xsd：SetParameterValuesResponse 仅含 Status、TransferComplete 无 ParameterKey 参数）——改断言同会话后继 AddObject 请求携带同一 ParameterKey，ID 改 `cwmp_parameter_key_same_session`，包数 17→15。**V-03** #19/#22/#26 响应措辞改为「Body 仅含空 `<SetParameterAttributesResponse/>`/`<FactoryResetResponse/>`/`<RequestDownloadResponse/>` 元素」（响应方法名 = 请求方法名 + Response，非空 HTTP 体）。**V-04** 新增负例 `cwmp_neg_url_userinfo`（#143，Download URL 含 userinfo 组件，§3.5 禁止；设计 §7 `cwmp_neg_length` 行补该输入，锚 `value`）。**V-06** §2/§4 与设计 v2.2 翻案及事件码 14/15 实现子集口径同步。**规范回对修正（cwmp-1-2.xsd）**：#25 AutonomousTransferComplete 响应改为空 `<AutonomousTransferCompleteResponse/>` 元素（A.3.3.3 存在该空 Response 元素；此前误写"204 空响应"），并同步 §2 覆盖描述。计数 140（103 正+37 负）→ **149（111 正+38 负）**：新增正例 #104/#105（Fault 原子例）与 #106–#111（设计 §8 断言归属逐项落地的缺失原子例：Inform 空 ParameterList、Event 数组满 64、参数名 256 恰值、OUI 六位大写、FileSize=0、CR 用户名百分号编码——v1.3 覆盖审回补）；新增负例 #149（URL userinfo）；负例 §2 编号 104–140→112–149；§5 负例表补第 38 行。
- v3.0.0（2026-09-01）：按《需求文档 v1.2》行为面全量重出，取代 v2.1.1 的 20 ID 契约（旧稿见 git 历史）。独立审查员 rr-cwmp 枚举行为面 210–230 测试点、缺口约 70%；本版 140 条（103 正 + 37 负）对其 C-01~C-83 缺失清单全项落地——11 个 baseline RPC 正例（C-01~C-12）、存量 RPC 扩展（C-13~C-35）、值域逐点（C-36~C-49）、Fault 逐值正例族（C-50~C-58）、负例 6 类 32 输入逐输入原子拆分 + 事件组合 4 条（C-59/C-60）、编码形态（digest 参数逐项/stale/chunked/重定向/namespace 协商，C-68~C-75，其中 chunked/重定向/并发会话/CR 503/失败重试为 v1.2 覆盖审翻案项）、载体与会话（并发会话/CR 忙 503/v6 副连接/32KB 两态/双向大报文/最小帧，C-76~C-83）。原 v2.1 合并 fixture 按原子原则拆分（`cwmp_inform_event_codes` 四次 fixture → 4 条事件例；三途径、三段 Fault 各自成例）。140 与审查上界 210–230 的差额为同输入多锚词候选与 PLAUSIBLE 变体的归并（原子原则内合并计数，不减行为面）；「校准」标注项实现期回对钉死。
- v2.1.1（2026-09-01）：v1.1 隔离审查 N01–N03 修复（全 204、B 式收尾统一、修订史纠正）。
- v2.1.0（2026-09-01）：v1.1 隔离审查 23 项清单修复（2C/8M/13N）。
- v2.0.0（2026-08-31）：按需求文档 v1 重写，取代 2026-08-20 旧稿。
- v1.0.0（2026-08-20）：旧稿首版。
- v3.1.2（2026-09-22，落地勘误轮）：收官隔离复审 L2 处置——头部「尚未实现」状态行改为已落地现状（B6 40a479b + #34 迁层 153 例）；§2 计数补落地实测 153=110 正+43 负（原 150=112+38 为契约规划数）；修轮 M1 六行为族抽钉 fields/frames（登记于 TEST_CASES T-CWMP 修轮注记）。

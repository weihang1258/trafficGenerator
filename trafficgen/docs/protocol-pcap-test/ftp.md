# ftp Pcap Test Results

Cases: 97 — pass 97, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| ftp_3sessions_mixed | 3 会话混合操作：会话1 无事务（空）+会话2 RETR+会话3 LIST，独立端口/序号 | pass | 61 | [pcap](ftp/ftp_3sessions_mixed.pcap) |
| ftp_502_notimpl | RFC 959 §4.2.1 502 命令未实现（SITE 站点命令不支持） | pass | 16 | [pcap](ftp/ftp_502_notimpl.pcap) |
| ftp_abor_active_mode | 组合：ABOR 中断主动模式上传（PORT+STOR active，426+226 双响应） | pass | 31 | [pcap](ftp/ftp_abor_active_mode.pcap) |
| ftp_abor_completed | RFC 959 §4.1.3 ABOR 情形①：传输已完成→226（无 426） | pass | 31 | [pcap](ftp/ftp_abor_completed.pcap) |
| ftp_abor_idle | RFC 959 §5.4 ABOR 空闲：无进行中传输→225 Data connection open | pass | 16 | [pcap](ftp/ftp_abor_idle.pcap) |
| ftp_abor_midtransfer | RFC 959 §4.1.3/§5.4 ABOR 情形②：传输中中断→426+226 双响应（abort_after_bytes 截断） | pass | 31 | [pcap](ftp/ftp_abor_midtransfer.pcap) |
| ftp_abort_bytes | AbortAfterBytes 截断：1024 字节 payload 只发前 10 字节 | pass | 27 | [pcap](ftp/ftp_abort_bytes.pcap) |
| ftp_active_appe | 组合：主动模式追加（PORT+APPE direction=up） | pass | 29 | [pcap](ftp/ftp_active_appe.pcap) |
| ftp_active_retr | 组合：主动模式下载（PORT+RETR direction=down，server 20 首 SYN） | pass | 29 | [pcap](ftp/ftp_active_retr.pcap) |
| ftp_allo_stor | RFC 959 §4.1.3 ALLO 预分配（含 R 双参数）→202→PASV→STOR | pass | 29 | [pcap](ftp/ftp_allo_stor.pcap) |
| ftp_appe | RFC 959 §4.1.3 APPE 追加存储：150→数据→226（被动上传） | pass | 29 | [pcap](ftp/ftp_appe.pcap) |
| ftp_arg_501 | RFC 959 §4.2 TYPE 参数非法→501（syntax 家族：参数错误） | pass | 16 | [pcap](ftp/ftp_arg_501.pcap) |
| ftp_badseq_503 | RFC 959 §5.4 坏序列：无登录直接 RETR→503 Bad sequence | pass | 16 | [pcap](ftp/ftp_badseq_503.pcap) |
| ftp_banner_120_greeting | RFC 959 §5.4/§4.2.1 延迟问候：banner 120 Service ready in 5 minutes（后再 220） | pass | 14 | [pcap](ftp/ftp_banner_120_greeting.pcap) |
| ftp_banner_dyn_list | T-FTP-10b: banner_dyn list 逐流轮转（层链），220 横幅按流变 | pass | 20 | [pcap](ftp/ftp_banner_dyn_list.pcap) |
| ftp_cdup | RFC 959 §4.1.1 CDUP 切父目录（CWD 特例，响应码同 CWD 家族） | pass | 18 | [pcap](ftp/ftp_cdup.pcap) |
| ftp_cwd_550_fail | RFC 959 §5.4 CWD→550 目录不存在（fail 分支） | pass | 16 | [pcap](ftp/ftp_cwd_550_fail.pcap) |
| ftp_dataconn_125 | RFC 959 §4.2.1 125 已开数据连接变体（150 替代）+226 | pass | 27 | [pcap](ftp/ftp_dataconn_125.pcap) |
| ftp_dataconn_250 | RFC 959 §3.2/§5.4 完成码 250 变体：LIST→150→数据→250（226 的合法替代） | pass | 27 | [pcap](ftp/ftp_dataconn_250.pcap) |
| ftp_dataconn_425 | RFC 959 §4.2.1/§5.4 数据连接失败：425 Can't open data connection | pass | 18 | [pcap](ftp/ftp_dataconn_425.pcap) |
| ftp_dataconn_explicit_ports | RFC 959 端口推导最高优先级：显式 src/dst 覆盖 PASV 信令 | pass | 27 | [pcap](ftp/ftp_dataconn_explicit_ports.pcap) |
| ftp_dataconn_fallback | RFC 959 §3.2 端口推导回退：无 PASV/PORT 信令→server 50000 | pass | 25 | [pcap](ftp/ftp_dataconn_fallback.pcap) |
| ftp_dc_mss_override | dc.mss 数据通道级 MSS 覆盖（B 类缺口钉现状）：链路径当前忽略该字段、按链全局 MSS=1460 分段 | pass | 28 | [pcap](ftp/ftp_dc_mss_override.pcap) |
| ftp_dele_550_fail | RFC 959 §5.4 DELE→550 删除被拒（fail 分支） | pass | 16 | [pcap](ftp/ftp_dele_550_fail.pcap) |
| ftp_dyn_command_pattern | T-FTP-11: cmd_dyn pattern 逐流动态（层链），RETR 文件名按流变；46 帧 = 2×23 | pass | 44 | [pcap](ftp/ftp_dyn_command_pattern.pcap) |
| ftp_dyn_payload | T-FTP-12: data_channel payload_dyn pattern 逐流动态（层链）；46 帧 = 2×23 | pass | 44 | [pcap](ftp/ftp_dyn_payload.pcap) |
| ftp_empty_session | T-FTP-5: 空会话合法（层链）——仅握手 3 + 挥手 4 = 7 包，连接端口 = 会话 src_port | pass | 7 | [pcap](ftp/ftp_empty_session.pcap) |
| ftp_file_mgmt | RFC 959 §4.1.3 文件管理四连：MKD 257/PWD 257/RMD 250/DELE 250 | pass | 22 | [pcap](ftp/ftp_file_mgmt.pcap) |
| ftp_file_source | FileSource literal 文件读取：数据通道载荷来自 file_source | pass | 26 | [pcap](ftp/ftp_file_source.pcap) |
| ftp_file_source_abort | 组合：FileSource 文件读取 + AbortAfterBytes 截断 | pass | 26 | [pcap](ftp/ftp_file_source_abort.pcap) |
| ftp_help | RFC 959 §4.1.3 HELP（RFC 允许 USER 之前调用）：214 | pass | 16 | [pcap](ftp/ftp_help.pcap) |
| ftp_ipv6_active | 组合：IPv6 + active 模式上传（ip 层 v6 + PORT+STOR server 首 SYN） | pass | 27 | [pcap](ftp/ftp_ipv6_active.pcap) |
| ftp_ipv6_data | IPv6 全程含被动下载：ip 层 2001:db8::/32 + PASV+RETR 数据通道 | pass | 29 | [pcap](ftp/ftp_ipv6_data.pcap) |
| ftp_list_226_success | RFC 959 §5.4 LIST→150→数据→226 成功完成（success 分支，补 226） | pass | 27 | [pcap](ftp/ftp_list_226_success.pcap) |
| ftp_login_530 | RFC 959 §4.2.1/§5.4 认证失败：PASS→530 Not logged in | pass | 14 | [pcap](ftp/ftp_login_530.pcap) |
| ftp_login_530_cmd | RFC 959 §5.4 未登录发命令→530（USER 前 RETR 之外的 530 家族） | pass | 14 | [pcap](ftp/ftp_login_530_cmd.pcap) |
| ftp_login_acct | RFC 959 §4.1.1/§5.4 需账户登录：USER→331→PASS→332→ACCT→230 | pass | 16 | [pcap](ftp/ftp_login_acct.pcap) |
| ftp_login_nobanner | RFC 959 §5.4 banner 缺席：握手后直发 USER | pass | 13 | [pcap](ftp/ftp_login_nobanner.pcap) |
| ftp_login_rein | RFC 959 §4.1.1 REIN 重初始化：登录→REIN→220→重新登录 | pass | 20 | [pcap](ftp/ftp_login_rein.pcap) |
| ftp_login_reuser | RFC 959 §4.1.1 中途 re-USER：冲掉已供凭证重新登录 | pass | 18 | [pcap](ftp/ftp_login_reuser.pcap) |
| ftp_min_mode | RFC 959 §5.1/§4.1.2 MODE S 流模式（最小实现成员） | pass | 16 | [pcap](ftp/ftp_min_mode.pcap) |
| ftp_min_noop | RFC 959 §5.1 最小实现：NOOP→200（无参数无动作） | pass | 16 | [pcap](ftp/ftp_min_noop.pcap) |
| ftp_min_stru | RFC 959 §5.1/§4.1.2 STRU R 记录结构（最小实现成员） | pass | 16 | [pcap](ftp/ftp_min_stru.pcap) |
| ftp_mss_segmentation | MSS 分段（层链）：超长 payload 触发 tcp 层默认 MSS=1460 分段，数据通道段数随 payload 长度增长 | pass | 28 | [pcap](ftp/ftp_mss_segmentation.pcap) |
| ftp_multi_command | 多命令无数据通道（层链）：6 命令全双包，20 帧 = 3 握手 + banner + 6×2 + 4 终止 | pass | 20 | [pcap](ftp/ftp_multi_command.pcap) |
| ftp_multiflow_data | 多流×数据通道组合：flows=3 每流 PASV+RETR 含独立数据通道（端口逐流隔离） | pass | 72 | [pcap](ftp/ftp_multiflow_data.pcap) |
| ftp_multiflow_multisession | 组合：多流×多会话×数据通道（flows=2，每流 2 会话各挂数据通道） | pass | 70 | [pcap](ftp/ftp_multiflow_multisession.pcap) |
| ftp_neg_dyn_no_range | 动态策略 inc 无 range（层链）→ 任务启动 validateDynFields 拒绝 | pass | 0 | [pcap]() |
| ftp_neg_mss_too_small | MSS<536 拒绝（层链）：tcp 层 mss=100 → V9 范围拒绝（RFC 879 最小 536） | pass | 0 | [pcap]() |
| ftp_neg_session_static_copy | 会话静态复制拒绝（层链）：两个会话固定 src_port + flows>1 → 任务启动 validateSessionStaticCopy 拒绝 | pass | 0 | [pcap]() |
| ftp_neg_static_copy | 层链静态复制拒绝：ip/tcp 层显式标量四元组 + flows>1 → 400 static four-tuple（Task 5 后扁平已死，负例改层链锚词） | pass | 0 | [pcap]() |
| ftp_nlst | RFC 959 §4.1.3 NLST 名单列表（纯文件名流，区别于 LIST 详情） | pass | 27 | [pcap](ftp/ftp_nlst.pcap) |
| ftp_nlst_226_success | RFC 959 §5.4 NLST→150→数据→226 名单成功完成 | pass | 27 | [pcap](ftp/ftp_nlst_226_success.pcap) |
| ftp_noflag_no_subflow | T-FTP-6: 事务有 DataChannel 但无 emit 标记（层链）→ 不发射子流 | pass | 9 | [pcap](ftp/ftp_noflag_no_subflow.pcap) |
| ftp_passive_stor | 组合：被动模式上传（PASV+STOR direction=up，client 首 SYN） | pass | 29 | [pcap](ftp/ftp_passive_stor.pcap) |
| ftp_pasv_isolation | T-FTP-4: 后事务数据流取本事务 PASV 端口（层链），不串前事务 49993 | pass | 32 | [pcap](ftp/ftp_pasv_isolation.pcap) |
| ftp_payload_b64 | PayloadB64 二进制载荷：base64 解码后上路（含 NUL 字节） | pass | 27 | [pcap](ftp/ftp_payload_b64.pcap) |
| ftp_perf_1000flows | 性能压力测试（层链）：1000 流 × USER/PASS/QUIT = 14000 帧 | pass | 14000 | [pcap](ftp/ftp_perf_1000flows.pcap) |
| ftp_perf_100flows | 性能测试（层链）：100 流 × USER/PASS/QUIT = 1400 帧，验证吞吐无异常 | pass | 1400 | [pcap](ftp/ftp_perf_100flows.pcap) |
| ftp_port_overflow | RFC 959 §3.2 ctrlPort=65535 溢出守卫：客户端口回退 1024（不回绕 0） | pass | 25 | [pcap](ftp/ftp_port_overflow.pcap) |
| ftp_port_pasv_dual | RFC 959 §3.3 PORT+PASV 双协商：两端都声明非默认端口（最终走 passive） | pass | 29 | [pcap](ftp/ftp_port_pasv_dual.pcap) |
| ftp_response_dyn | T-FTP-11b: response_dyn pattern 逐流动态（层链），331/332 文本按流变 | pass | 22 | [pcap](ftp/ftp_response_dyn.pcap) |
| ftp_rest_retr | RFC 959 §4.1.3 REST 断点续传：REST→350→PASV→RETR（服务端续传点） | pass | 31 | [pcap](ftp/ftp_rest_retr.pcap) |
| ftp_rest_stor_upload | 组合：REST 续传 + STOR 上传续传（REST→350→PASV→STOR→数据） | pass | 31 | [pcap](ftp/ftp_rest_stor_upload.pcap) |
| ftp_retr_110_marker | RFC 959 §4.2.1/§3.4.2 110 Restart marker（Block 模式传输中响应，文本必须 'MARK yyyy = mmmm'） | pass | 25 | [pcap](ftp/ftp_retr_110_marker.pcap) |
| ftp_retr_550_notfound | RFC 959 §5.4 RETR→550 文件不存在（fail 分支，无数据通道） | pass | 18 | [pcap](ftp/ftp_retr_550_notfound.pcap) |
| ftp_retr_passive | T-FTP-2: PASV+RETR 下载（层链），数据通道挂载在 150 与 226 之间；28 帧 = 控制通道 19 + 数据通道 9 | pass | 27 | [pcap](ftp/ftp_retr_passive.pcap) |
| ftp_rnfr_450_fail | RFC 959 §5.4 RNFR→450 改名源文件忙（fail 分支，无 RNTO） | pass | 16 | [pcap](ftp/ftp_rnfr_450_fail.pcap) |
| ftp_rnfr_rnto | RFC 959 §4.1.3/§5.4 改名序列：RNFR→350→RNTO→250（350 中间态） | pass | 18 | [pcap](ftp/ftp_rnfr_rnto.pcap) |
| ftp_service_421 | RFC 959 §4.2 服务端超时 421：命令响应后连接将关闭（会话中途服务不可用） | pass | 14 | [pcap](ftp/ftp_service_421.pcap) |
| ftp_session_dynamic_ports | T-FTP-10: 会话 src_port_dyn inc [20000..20003]（层链），4 流各不同端口；48 帧 = 4×12 | pass | 48 | [pcap](ftp/ftp_session_dynamic_ports.pcap) |
| ftp_session_partial_data_tx | 组合：单会话 3 事务，仅第 2 事务挂数据通道（部分发射） | pass | 29 | [pcap](ftp/ftp_session_partial_data_tx.pcap) |
| ftp_sessions_dual | T-FTP-2 sessions: 双会话（RETR+LIST，层链），独立 TCP 连接、独立数据通道 | pass | 46 | [pcap](ftp/ftp_sessions_dual.pcap) |
| ftp_sessions_mixed_mode | 组合：双会话跨模式（会话1 passive 下载 + 会话2 active 上传） | pass | 46 | [pcap](ftp/ftp_sessions_mixed_mode.pcap) |
| ftp_site | RFC 959 §4.1.3 SITE 站点参数（服务器特定）：200 | pass | 16 | [pcap](ftp/ftp_site.pcap) |
| ftp_smnt | RFC 959 §4.1.1 SMNT 结构挂载：SMNT→250 | pass | 16 | [pcap](ftp/ftp_smnt.pcap) |
| ftp_smoke_01 | FTP 控制通道冒烟（层链 [ip,tcp,ftp]）：USER/PASS/QUIT（RFC 959 §4.1），14 帧 = 3 握手 + banner + 3 命令×2 + 4 终止 | pass | 14 | [pcap](ftp/ftp_smoke_01.pcap) |
| ftp_stat | RFC 959 §4.1.3 STAT 传输间状态查询（控制连接回复 211） | pass | 16 | [pcap](ftp/ftp_stat.pcap) |
| ftp_stat_212_dir | RFC 959 §4.2.1 STAT 目录→212 Directory status | pass | 16 | [pcap](ftp/ftp_stat_212_dir.pcap) |
| ftp_stat_213_file | RFC 959 §4.2.1 STAT 带路径参数→213 File status（数据经控制连接） | pass | 16 | [pcap](ftp/ftp_stat_213_file.pcap) |
| ftp_stor_452_quota | RFC 959 §4.2.1 STOR→452 存储配额不足（fail 分支，区别 532 账户） | pass | 18 | [pcap](ftp/ftp_stor_452_quota.pcap) |
| ftp_stor_532_nospace | RFC 959 §5.4 STOR→532 存储空间不足（fail 分支） | pass | 18 | [pcap](ftp/ftp_stor_532_nospace.pcap) |
| ftp_stor_550 | RFC 959 §7 官方示例场景：STOR→550 Access denied→QUIT（拒绝后退出） | pass | 18 | [pcap](ftp/ftp_stor_550.pcap) |
| ftp_stor_551_pagetype | RFC 959 §4.2.1 STOR→551 页类型未知（transient，页结构场景） | pass | 22 | [pcap](ftp/ftp_stor_551_pagetype.pcap) |
| ftp_stor_552_exceedalloc | RFC 959 §4.2.1 STOR→552 超出存储分配（transient） | pass | 18 | [pcap](ftp/ftp_stor_552_exceedalloc.pcap) |
| ftp_stor_553_filename | RFC 959 §4.2.1 STOR→553 文件名不允许（fail） | pass | 18 | [pcap](ftp/ftp_stor_553_filename.pcap) |
| ftp_stor_upload | T-FTP-2b: PORT+STOR 上传（层链），数据方向=up（client→server）；28 帧 | pass | 27 | [pcap](ftp/ftp_stor_upload.pcap) |
| ftp_stou | RFC 959 §4.1.3 STOU 唯一存储：125 已开数据连接变体 + 上传 | pass | 29 | [pcap](ftp/ftp_stou.pcap) |
| ftp_syntax_500 | RFC 959 §4.2/§5.4 语法错误命令→500（syntax 家族代表：未知命令） | pass | 16 | [pcap](ftp/ftp_syntax_500.pcap) |
| ftp_syst | RFC 959 §4.1.3 SYST 系统类型：215 UNIX Type: L8 | pass | 16 | [pcap](ftp/ftp_syst.pcap) |
| ftp_transfer_450 | RFC 959 §5.4 RETR→450 文件不可用（无数据通道发射） | pass | 18 | [pcap](ftp/ftp_transfer_450.pcap) |
| ftp_transfer_451_localerr | RFC 959 §4.2.1 451 本地处理错误（transient 分支）：RETR→150→451（服务器内部错误中断） | pass | 18 | [pcap](ftp/ftp_transfer_451_localerr.pcap) |
| ftp_txindex_dual | T-FTP-3: 单会话双事务（层链），两条数据流各取本事务 PASV 端口 50011/50012 | pass | 32 | [pcap](ftp/ftp_txindex_dual.pcap) |
| ftp_type_504_badparam | RFC 959 §4.2.1 TYPE→504 参数未实现（如 TYPE E EBCDIC 在纯 ASCII 服务器） | pass | 16 | [pcap](ftp/ftp_type_504_badparam.pcap) |
| ftp_type_ascii | RFC 959 §4.1.2 TYPE A ASCII 默认类型 + A N 格式参数 | pass | 18 | [pcap](ftp/ftp_type_ascii.pcap) |
| ftp_type_image | RFC 959 §4.1.2 TYPE I Image 二进制（最小实现成员） | pass | 16 | [pcap](ftp/ftp_type_image.pcap) |
| ftp_type_local | RFC 959 §4.1.2 TYPE L 8 本地字节类型（必带第二参数） | pass | 16 | [pcap](ftp/ftp_type_local.pcap) |

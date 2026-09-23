# xmrmining Pcap Test Results

Cases: 64 — pass 64, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| xmrmining_blob_max | blob 407B 合法上界 blob_max | pass | 10 | [pcap](xmrmining/xmrmining_blob_max.pcap) |
| xmrmining_blob_nonce_offset | blob nonce 偏移 39/4B 帧偏移 182 断言 | pass | 12 | [pcap](xmrmining/xmrmining_blob_nonce_offset.pcap) |
| xmrmining_concurrent_sessions | 双矿机并发会话交错回放（concurrent） | pass | 24 | [pcap](xmrmining/xmrmining_concurrent_sessions.pcap) |
| xmrmining_getjob | getjob 请求/响应 result=job 对象 | pass | 11 | [pcap](xmrmining/xmrmining_getjob.pcap) |
| xmrmining_id_correlation | 多事务 id 按值配对 login/submit/keepalived | pass | 14 | [pcap](xmrmining/xmrmining_id_correlation.pcap) |
| xmrmining_ipv6 | IPv6 独立 fixture（2001:db8::74 → 2001:db8::100:74） | pass | 9 | [pcap](xmrmining/xmrmining_ipv6.pcap) |
| xmrmining_job_notify | job 通知现代 job 全字段（矿池→矿机恒 down） | pass | 10 | [pcap](xmrmining/xmrmining_job_notify.pcap) |
| xmrmining_job_notify_legacy | legacy 三字段 job（blob/job_id/target，无 algo/height/seed_hash/id） | pass | 10 | [pcap](xmrmining/xmrmining_job_notify_legacy.pcap) |
| xmrmining_keepalive_alias | keepalive 别名 method（mo-pool） | pass | 11 | [pcap](xmrmining/xmrmining_keepalive_alias.pcap) |
| xmrmining_keepalived | keepalived 请求/响应 KEEPALIVED | pass | 11 | [pcap](xmrmining/xmrmining_keepalived.pcap) |
| xmrmining_lifecycle | 单会话多事务全链生命周期 | pass | 17 | [pcap](xmrmining/xmrmining_lifecycle.pcap) |
| xmrmining_line_packing | job 通知+submit 请求 pack_next 粘连单段 | pass | 11 | [pcap](xmrmining/xmrmining_line_packing.pcap) |
| xmrmining_login_extensions | login 响应带 extensions [algo,keepalive] | pass | 9 | [pcap](xmrmining/xmrmining_login_extensions.pcap) |
| xmrmining_login_job_ipv4 | login 请求/响应全字段 IPv4 单流基线 | pass | 9 | [pcap](xmrmining/xmrmining_login_job_ipv4.pcap) |
| xmrmining_login_reject | login 错误响应 + 连接关闭 | pass | 9 | [pcap](xmrmining/xmrmining_login_reject.pcap) |
| xmrmining_login_rigid | login 带可选 rigid=rig-01 | pass | 9 | [pcap](xmrmining/xmrmining_login_rigid.pcap) |
| xmrmining_mss_large_jobid | job_id 1500 字符通知行 1892B 跨 MSS 2 段 | pass | 11 | [pcap](xmrmining/xmrmining_mss_large_jobid.pcap) |
| xmrmining_multi_session | 双矿机双四元组多会话按序整块展开 | pass | 24 | [pcap](xmrmining/xmrmining_multi_session.pcap) |
| xmrmining_neg_carrier_missing_tcp | 层链缺 tcp | pass | 0 | [pcap]() |
| xmrmining_neg_carrier_port_conflict | 端口与载体声明矛盾 | pass | 0 | [pcap]() |
| xmrmining_neg_carrier_udp | UDP 载体声明 | pass | 0 | [pcap]() |
| xmrmining_neg_framing_crlf | 行尾 0d0a（CRLF，spec 统一裸 LF） | pass | 0 | [pcap]() |
| xmrmining_neg_framing_length_prefix | 行前置 4 字节长度前缀取代换行定界 | pass | 0 | [pcap]() |
| xmrmining_neg_framing_no_lf | 末行无 LF 裸结束 | pass | 0 | [pcap]() |
| xmrmining_neg_hex_blob_nonhex | blob 含非法 hex 字符（如 g） | pass | 0 | [pcap]() |
| xmrmining_neg_hex_blob_odd | blob 奇数长度 hex | pass | 0 | [pcap]() |
| xmrmining_neg_hex_blob_overflow | blob 解码 ≥408B（超上界 407B） | pass | 0 | [pcap]() |
| xmrmining_neg_hex_blob_short | blob 解码 <43B（39+4+nonceSize 下界） | pass | 0 | [pcap]() |
| xmrmining_neg_hex_nonce | nonce 非 8 hex | pass | 0 | [pcap]() |
| xmrmining_neg_hex_prefix | hex 字段带 0x 前缀（本协议全部无前缀） | pass | 0 | [pcap]() |
| xmrmining_neg_hex_result | submit result 非 64 hex | pass | 0 | [pcap]() |
| xmrmining_neg_hex_seed_hash | seed_hash 非 64 hex | pass | 0 | [pcap]() |
| xmrmining_neg_hex_target | target 非 4/8 字节 | pass | 0 | [pcap]() |
| xmrmining_neg_id_notify_fake | job 通知携带伪 id（本协议省略 id 成员） | pass | 0 | [pcap]() |
| xmrmining_neg_id_resp_mismatch | 响应 id ≠ 请求 id（按值配对违例） | pass | 0 | [pcap]() |
| xmrmining_neg_id_reuse | 同会话未完成事务复用同一 id | pass | 0 | [pcap]() |
| xmrmining_neg_job_session_mismatch | submit/getjob/keepalived 的 params.id ≠ 本会话 session id | pass | 0 | [pcap]() |
| xmrmining_neg_job_unknown | submit 的 job_id 不来自本会话已收 job | pass | 0 | [pcap]() |
| xmrmining_neg_json_notobject | 某行为 JSON 数组/标量（非对象顶层） | pass | 0 | [pcap]() |
| xmrmining_neg_json_truncated | 行内容截断（login 对象无闭合，缺尾部） | pass | 0 | [pcap]() |
| xmrmining_neg_json_unclosed | 字符串未闭合（login params 字符串缺引号） | pass | 0 | [pcap]() |
| xmrmining_neg_method_btc_array | mining.subscribe 数组 params 混入（比特币 stratum 形态） | pass | 0 | [pcap]() |
| xmrmining_neg_method_direction | 矿机事件发 job 通知（方向违例） | pass | 0 | [pcap]() |
| xmrmining_neg_method_unknown | 未知 method（block_template 混入，§1 边界） | pass | 0 | [pcap]() |
| xmrmining_neg_params_getjob_missing | getjob 缺 id 字段 | pass | 0 | [pcap]() |
| xmrmining_neg_params_keepalived_missing | keepalived 缺 id 字段 | pass | 0 | [pcap]() |
| xmrmining_neg_params_login_missing | login 缺 login 字段 | pass | 0 | [pcap]() |
| xmrmining_neg_params_login_type | login login 非字符串（如数字） | pass | 0 | [pcap]() |
| xmrmining_neg_params_submit_missing | submit 缺 nonce 字段 | pass | 0 | [pcap]() |
| xmrmining_neg_params_submit_type | submit job_id 非字符串 | pass | 0 | [pcap]() |
| xmrmining_neg_prop_fake_success | 任务报 completed/0 packet 假成功 | pass | 0 | [pcap]() |
| xmrmining_neg_prop_swallowed | validator 已知 hex/状态错误被吞 | pass | 0 | [pcap]() |
| xmrmining_neg_result_id_missing | login 响应 result 对象缺 id 成员（xmrig-impl parseLogin code=1） | pass | 0 | [pcap]() |
| xmrmining_neg_state_after_close | 会话关闭后继续排事件 | pass | 0 | [pcap]() |
| xmrmining_neg_state_after_login_reject | login 失败后继续排业务事件 | pass | 0 | [pcap]() |
| xmrmining_neg_state_first_login | 首条应用消息非 login（如直接 job 通知） | pass | 0 | [pcap]() |
| xmrmining_neg_state_submit_before_login | 未 login 成功先 submit | pass | 0 | [pcap]() |
| xmrmining_nonce_boundary | nonce 0/满值边界 00000000/ffffffff | pass | 14 | [pcap](xmrmining/xmrmining_nonce_boundary.pcap) |
| xmrmining_port_nondefault | 非默认端口 3333 显式声明 | pass | 9 | [pcap](xmrmining/xmrmining_port_nondefault.pcap) |
| xmrmining_submit_accept | submit 请求/响应 OK | pass | 12 | [pcap](xmrmining/xmrmining_submit_accept.pcap) |
| xmrmining_submit_algo | submit 带可选 algo=rx/0 | pass | 12 | [pcap](xmrmining/xmrmining_submit_algo.pcap) |
| xmrmining_submit_reject | submit 拒绝（Low difficulty share），会话继续 | pass | 12 | [pcap](xmrmining/xmrmining_submit_reject.pcap) |
| xmrmining_submit_sig | submit 带可选 sig(64B)/commitment(32B) | pass | 12 | [pcap](xmrmining/xmrmining_submit_sig.pcap) |
| xmrmining_target_length | target 8 字节（b88d060000000000，16 hex） | pass | 12 | [pcap](xmrmining/xmrmining_target_length.pcap) |

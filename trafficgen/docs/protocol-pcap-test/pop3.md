# pop3 Pcap Test Results

Cases: 50 — pass 50, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| pop3_t001_default_session | T-001: 默认会话冒烟 | pass | 14 | [pcap](pop3/pop3_t001_default_session.pcap) |
| pop3_t002_user_empty_skipped | T-002: USER 空名跳过 | pass | 11 | [pcap](pop3/pop3_t002_user_empty_skipped.pcap) |
| pop3_t003_apop_login | T-003: APOP 一条登录 | pass | 12 | [pcap](pop3/pop3_t003_apop_login.pcap) |
| pop3_t004_user_in_transaction | T-004: 事务态 USER 照发 | pass | 18 | [pcap](pop3/pop3_t004_user_in_transaction.pcap) |
| pop3_t005_stat_empty | T-005: STAT 空信箱 | pass | 16 | [pcap](pop3/pop3_t005_stat_empty.pcap) |
| pop3_t006_list_multi | T-006: LIST 多信 | pass | 16 | [pcap](pop3/pop3_t006_list_multi.pcap) |
| pop3_t007_list_outofrange | T-007: LIST 越界 | pass | 16 | [pcap](pop3/pop3_t007_list_outofrange.pcap) |
| pop3_t008_retr_maildrop | T-008: RETR 信箱合成 | pass | 16 | [pcap](pop3/pop3_t008_retr_maildrop.pcap) |
| pop3_t009_retr_missing | T-009: RETR 无此信 | pass | 16 | [pcap](pop3/pop3_t009_retr_missing.pcap) |
| pop3_t010_dele | T-010: DELE 删信 + RSET 撤销 | pass | 20 | [pcap](pop3/pop3_t010_dele.pcap) |
| pop3_t011_top | T-011: TOP 合成 | pass | 16 | [pcap](pop3/pop3_t011_top.pcap) |
| pop3_t012_uidl | T-012: UIDL 多行单行 | pass | 18 | [pcap](pop3/pop3_t012_uidl.pcap) |
| pop3_t012b_emit_top_no_mailbox_reject | T-012: TOP 无信箱拒绝 | pass | 0 | [pcap]() |
| pop3_t013_dot_stuffing | T-013: RETR 点填充 | pass | 16 | [pcap](pop3/pop3_t013_dot_stuffing.pcap) |
| pop3_t014_user_toolong_reject | T-014: USER 超长拒绝 | pass | 0 | [pcap]() |
| pop3_t015_pass_toolong_reject | T-015: PASS 超长拒绝 | pass | 0 | [pcap]() |
| pop3_t016_cmd_crlf_reject | T-016: 命令 CRLF 注入拒绝 | pass | 0 | [pcap]() |
| pop3_t017_resp_crlf_reject | T-017: 单行响应 CRLF 拒绝 | pass | 0 | [pcap]() |
| pop3_t018_uid_toolong_reject | T-018: UID 超长拒绝 | pass | 0 | [pcap]() |
| pop3_t019_apop_bad_digest_reject | T-019: APOP 摘要非法拒绝 | pass | 0 | [pcap]() |
| pop3_t020_rfc10_sequence | T-020: RFC 官方示例序列 | pass | 20 | [pcap](pop3/pop3_t020_rfc10_sequence.pcap) |
| pop3_t021_capa | T-021: CAPA 扩展列表 | pass | 16 | [pcap](pop3/pop3_t021_capa.pcap) |
| pop3_t022_stls | T-022: STLS 台词 | pass | 12 | [pcap](pop3/pop3_t022_stls.pcap) |
| pop3_t023_auth | T-023: AUTH 三机制 | pass | 16 | [pcap](pop3/pop3_t023_auth.pcap) |
| pop3_t024_mss_reject | T-024: MSS 过小拒绝 | pass | 0 | [pcap]() |
| pop3_t025_two_retr | T-025: 同连接两 RETR | pass | 18 | [pcap](pop3/pop3_t025_two_retr.pcap) |
| pop3_t026_abort_no_quit | T-026: RETR 后无 QUIT 断线 | pass | 14 | [pcap](pop3/pop3_t026_abort_no_quit.pcap) |
| pop3_t027_keepalive_noop | T-027: 三 NOOP 长保活 | pass | 20 | [pcap](pop3/pop3_t027_keepalive_noop.pcap) |
| pop3_t028_gmail | T-028: 现网 Gmail 形 | pass | 14 | [pcap](pop3/pop3_t028_gmail.pcap) |
| pop3_t029_outlook | T-029: 现网 Outlook 形 | pass | 14 | [pcap](pop3/pop3_t029_outlook.pcap) |
| pop3_t030_dovecot | T-030: 现网 Dovecot 形 | pass | 16 | [pcap](pop3/pop3_t030_dovecot.pcap) |
| pop3_t031_composite | T-031: 复合流登录+取删 | pass | 20 | [pcap](pop3/pop3_t031_composite.pcap) |
| pop3_t032_pop3s_995 | T-032: POP3S 端口 995 | pass | 21 | [pcap](pop3/pop3_t032_pop3s_995.pcap) |
| pop3_t033_v6 | T-033: v6 承载冒烟 | pass | 14 | [pcap](pop3/pop3_t033_v6.pcap) |
| pop3_t034_bad_ip_reject | T-034: 坏 IP 拒绝 | pass | 0 | [pcap]() |
| pop3_t035_presence_reject | T-035: 顶层 pop3 判死 | pass | 0 | [pcap]() |
| pop3_t036_static_pinned_reject | T-036: 显式标量双流拒绝 | pass | 0 | [pcap]() |
| pop3_t037_mime_multi_attach | T-037: RETR 双附件下载 | pass | 16 | [pcap](pop3/pop3_t037_mime_multi_attach.pcap) |
| pop3_t038_empty_body_retr | T-038: RETR 空正文信 | pass | 16 | [pcap](pop3/pop3_t038_empty_body_retr.pcap) |
| pop3_t039_attach_only | T-039: RETR 纯附件无正文 | pass | 16 | [pcap](pop3/pop3_t039_attach_only.pcap) |
| pop3_t040_pass_auth_failed | T-040: PASS 密码错 -ERR | pass | 14 | [pcap](pop3/pop3_t040_pass_auth_failed.pcap) |
| pop3_t041_unknown_command | T-041: 未知命令 -ERR | pass | 16 | [pcap](pop3/pop3_t041_unknown_command.pcap) |
| pop3_t042_maildrop_no_mailbox_reject | T-042: RETR 合成无信箱拒绝 | pass | 0 | [pcap]() |
| pop3_t043_maildrop_msgnum_range_reject | T-043: RETR 信号越界拒绝 | pass | 0 | [pcap]() |
| pop3_t044_top_msgnum_range_reject | T-044: TOP 信号越界拒绝 | pass | 0 | [pcap]() |
| pop3_t045_emit_both_exclusive_reject | T-045: 双合成互斥拒绝 | pass | 0 | [pcap]() |
| pop3_t046_default_twoflow | T-046: 全缺省双流放行 | pass | 14 | [pcap](pop3/pop3_t046_default_twoflow.pcap) |
| pop3_t047_quit_bare | T-047: 未登录直接退出 | pass | 10 | [pcap](pop3/pop3_t047_quit_bare.pcap) |
| pop3_t048_list_single | T-048: LIST 单封单行 | pass | 16 | [pcap](pop3/pop3_t048_list_single.pcap) |
| pop3_t049_top_zero_lines | T-049: TOP 零行仅头 | pass | 16 | [pcap](pop3/pop3_t049_top_zero_lines.pcap) |

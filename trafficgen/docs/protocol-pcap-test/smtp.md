# smtp Pcap Test Results

Cases: 43 — pass 43, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| smtp-basic-session | SMTP (端口 25) 冒烟：完整 TCP 握手 + HELO/MAIL/RCPT/DATA/QUIT 命令对话 + 终止 | pass | 20 | [pcap](smtp/smtp-basic-session.pcap) |
| smtp_t002_top_smtp_presence_reject | T-002: 顶层smtp presence判死 | pass | 0 | [pcap]() |
| smtp_t003_ehlo_multiline | T-003: EHLO多行能力表 | pass | 12 | [pcap](smtp/smtp_t003_ehlo_multiline.pcap) |
| smtp_t004_multi_rcpt | T-004: 双RCPT群发 | pass | 22 | [pcap](smtp/smtp_t004_multi_rcpt.pcap) |
| smtp_t005_rset | T-005: RSET中断重来 | pass | 24 | [pcap](smtp/smtp_t005_rset.pcap) |
| smtp_t006_noop | T-006: NOOP保活 | pass | 14 | [pcap](smtp/smtp_t006_noop.pcap) |
| smtp_t007_vrfy | T-007: VRFY地址探查 | pass | 14 | [pcap](smtp/smtp_t007_vrfy.pcap) |
| smtp_t008_expn | T-008: EXPN列表探查 | pass | 14 | [pcap](smtp/smtp_t008_expn.pcap) |
| smtp_t009_quit_after_data | T-009: DATA后直接QUIT | pass | 18 | [pcap](smtp/smtp_t009_quit_after_data.pcap) |
| smtp_t010_email_text | T-010: Email声明式纯文本 | pass | 20 | [pcap](smtp/smtp_t010_email_text.pcap) |
| smtp_t011_email_alternative | T-011: Email alternative双体 | pass | 20 | [pcap](smtp/smtp_t011_email_alternative.pcap) |
| smtp_t012_email_attach | T-012: Email附件mixed+base64 | pass | 20 | [pcap](smtp/smtp_t012_email_attach.pcap) |
| smtp_t013_port_587 | T-013: 提交端口587 | pass | 20 | [pcap](smtp/smtp_t013_port_587.pcap) |
| smtp_t014_port_465 | T-014: SMTPS端口465 | pass | 20 | [pcap](smtp/smtp_t014_port_465.pcap) |
| smtp_t015_v6 | T-015: v6承载冒烟 | pass | 20 | [pcap](smtp/smtp_t015_v6.pcap) |
| smtp_t016_postfix_banner | T-016: 现网Postfix形banner | pass | 12 | [pcap](smtp/smtp_t016_postfix_banner.pcap) |
| smtp_t017_auth_login | T-017: AUTH LOGIN三步 | pass | 18 | [pcap](smtp/smtp_t017_auth_login.pcap) |
| smtp_t018_starttls_script | T-018: STARTTLS台词到220 | pass | 14 | [pcap](smtp/smtp_t018_starttls_script.pcap) |
| smtp_t019_bad_srcip_reject | T-019: 坏目的IP拒绝（validator门） | pass | 0 | [pcap]() |
| smtp_t020_mss_reject | T-020: MSS过小拒绝 | pass | 0 | [pcap]() |
| smtp_t021_boundary_reject | T-021: boundary超长拒绝 | pass | 0 | [pcap]() |
| smtp_t022_attach_nodata_reject | T-022: 附件无数据拒绝 | pass | 0 | [pcap]() |
| smtp_t023_turn | T-023: TURN命令回放 | pass | 14 | [pcap](smtp/smtp_t023_turn.pcap) |
| smtp_t024_default_twoflow | T-024: 全缺省双流（静态复制门反例：无显式标量不触发，src_port保底+1） | pass | 40 | [pcap](smtp/smtp_t024_default_twoflow.pcap) |
| smtp_t024b_static_pinned_reject | T-024b: 显式标量四元组flows=2拒绝（静态复制门正例） | pass | 0 | [pcap]() |
| smtp_t025_fail_530_auth | T-025: 530 需认证拒绝 | pass | 14 | [pcap](smtp/smtp_t025_fail_530_auth.pcap) |
| smtp_t026_fail_550_mailbox | T-026: 550 邮箱不可用 | pass | 16 | [pcap](smtp/smtp_t026_fail_550_mailbox.pcap) |
| smtp_t027_fail_554_toolarge | T-027: 554 事务失败 | pass | 18 | [pcap](smtp/smtp_t027_fail_554_toolarge.pcap) |
| smtp_t028_fail_452_storage | T-028: 452 存储不足 | pass | 16 | [pcap](smtp/smtp_t028_fail_452_storage.pcap) |
| smtp_t029_fail_421_unavail | T-029: 421 服务不可用 | pass | 12 | [pcap](smtp/smtp_t029_fail_421_unavail.pcap) |
| smtp_t030_fail_503_sequence | T-030: 503 坏序列 | pass | 14 | [pcap](smtp/smtp_t030_fail_503_sequence.pcap) |
| smtp_t031_fail_535_authfail | T-031: 535 认证失败 | pass | 18 | [pcap](smtp/smtp_t031_fail_535_authfail.pcap) |
| smtp_t032_email_html_only | T-032: Email 纯 HTML 单体 | pass | 20 | [pcap](smtp/smtp_t032_email_html_only.pcap) |
| smtp_t033_email_mixed_multi | T-033: Email 双附件 mixed | pass | 23 | [pcap](smtp/smtp_t033_email_mixed_multi.pcap) |
| smtp_t034_email_empty_body | T-034: Email 空正文 | pass | 20 | [pcap](smtp/smtp_t034_email_empty_body.pcap) |
| smtp_t035_email_attach_only | T-035: Email 纯附件无正文 | pass | 20 | [pcap](smtp/smtp_t035_email_attach_only.pcap) |
| smtp_t036_direction_override | T-036: direction 下行改写 | pass | 13 | [pcap](smtp/smtp_t036_direction_override.pcap) |
| smtp_t037_two_mails | T-037: 同连接两封信 | pass | 28 | [pcap](smtp/smtp_t037_two_mails.pcap) |
| smtp_t038_abort_no_quit | T-038: DATA 后无 QUIT 断线 | pass | 18 | [pcap](smtp/smtp_t038_abort_no_quit.pcap) |
| smtp_t039_keepalive_multi_noop | T-039: 三 NOOP 长保活 | pass | 18 | [pcap](smtp/smtp_t039_keepalive_multi_noop.pcap) |
| smtp_t040_composite_auth_rset_twomail | T-040: 复合流 AUTH+RSET+两封信 | pass | 36 | [pcap](smtp/smtp_t040_composite_auth_rset_twomail.pcap) |
| smtp_t041_gmail_banner | T-041: 现网 Gmail 形 banner | pass | 12 | [pcap](smtp/smtp_t041_gmail_banner.pcap) |
| smtp_t042_exchange_banner | T-042: 现网 Exchange 形 banner | pass | 12 | [pcap](smtp/smtp_t042_exchange_banner.pcap) |

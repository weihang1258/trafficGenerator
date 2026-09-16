# smtp Pcap Test Results

Cases: 25 — pass 25, fail 0, error 0

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

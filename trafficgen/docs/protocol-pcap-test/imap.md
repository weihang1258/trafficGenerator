# imap Pcap Test Results

Cases: 84 — pass 84, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| imap_t001_default_session | T-001: 默认会话冒烟 | pass | 16 | [pcap](imap/imap_t001_default_session.pcap) |
| imap_t002_tag_explicit | T-002: tag 显式 A001 | pass | 13 | [pcap](imap/imap_t002_tag_explicit.pcap) |
| imap_t003_tag_auto | T-003: tag 自动递增 | pass | 15 | [pcap](imap/imap_t003_tag_auto.pcap) |
| imap_t004_tag_shapes | T-004: tag 点线数字三形 | pass | 17 | [pcap](imap/imap_t004_tag_shapes.pcap) |
| imap_t005_empty_cmd_challenge | T-005: 空 Cmd 服务端单轮 | pass | 12 | [pcap](imap/imap_t005_empty_cmd_challenge.pcap) |
| imap_t006_select_wrong_state | T-006: 未认证态 SELECT 错序 | pass | 13 | [pcap](imap/imap_t006_select_wrong_state.pcap) |
| imap_t007_bye_greeting | T-007: BYE 问候拒绝连接 | pass | 10 | [pcap](imap/imap_t007_bye_greeting.pcap) |
| imap_t008_append_literal | T-008: APPEND LiteralBody 上行 | pass | 16 | [pcap](imap/imap_t008_append_literal.pcap) |
| imap_t009_append_b64_fetch_placeholder | T-009: APPEND B64 与 FETCH 占位 | pass | 21 | [pcap](imap/imap_t009_append_b64_fetch_placeholder.pcap) |
| imap_t010_pipelined | T-010: 流水线双相位 | pass | 15 | [pcap](imap/imap_t010_pipelined.pcap) |
| imap_t011_capability | T-011: CAPABILITY 任意态 | pass | 14 | [pcap](imap/imap_t011_capability.pcap) |
| imap_t012_noop | T-012: NOOP 任意态 | pass | 13 | [pcap](imap/imap_t012_noop.pcap) |
| imap_t013_logout | T-013: LOGOUT 任意态 | pass | 11 | [pcap](imap/imap_t013_logout.pcap) |
| imap_t014_login_ok | T-014: LOGIN 成功 | pass | 13 | [pcap](imap/imap_t014_login_ok.pcap) |
| imap_t015_login_no | T-015: LOGIN 失败 NO | pass | 13 | [pcap](imap/imap_t015_login_no.pcap) |
| imap_t016_authenticate | T-016: AUTHENTICATE 双形与取消 | pass | 19 | [pcap](imap/imap_t016_authenticate.pcap) |
| imap_t017_starttls | T-017: STARTTLS 台词 | pass | 13 | [pcap](imap/imap_t017_starttls.pcap) |
| imap_t018_enable | T-018: ENABLE 台词 | pass | 16 | [pcap](imap/imap_t018_enable.pcap) |
| imap_t019_select_ok | T-019: SELECT 成功 | pass | 16 | [pcap](imap/imap_t019_select_ok.pcap) |
| imap_t020_select_no | T-020: SELECT 失败 NO | pass | 15 | [pcap](imap/imap_t020_select_no.pcap) |
| imap_t021_examine | T-021: EXAMINE 台词 | pass | 16 | [pcap](imap/imap_t021_examine.pcap) |
| imap_t022_create | T-022: CREATE 信箱 | pass | 15 | [pcap](imap/imap_t022_create.pcap) |
| imap_t023_delete | T-023: DELETE 信箱 | pass | 17 | [pcap](imap/imap_t023_delete.pcap) |
| imap_t024_rename | T-024: RENAME 信箱 | pass | 15 | [pcap](imap/imap_t024_rename.pcap) |
| imap_t025_subscribe | T-025: SUBSCRIBE 与 UNSUBSCRIBE | pass | 17 | [pcap](imap/imap_t025_subscribe.pcap) |
| imap_t026_list | T-026: LIST 信箱列表 | pass | 16 | [pcap](imap/imap_t026_list.pcap) |
| imap_t027_namespace | T-027: NAMESPACE 台词 | pass | 16 | [pcap](imap/imap_t027_namespace.pcap) |
| imap_t028_status | T-028: STATUS 信箱状态 | pass | 16 | [pcap](imap/imap_t028_status.pcap) |
| imap_t029_append_flags | T-029: APPEND 带 flags | pass | 17 | [pcap](imap/imap_t029_append_flags.pcap) |
| imap_t030_close | T-030: CLOSE 已选择态 | pass | 18 | [pcap](imap/imap_t030_close.pcap) |
| imap_t031_unselect | T-031: UNSELECT 已选择态 | pass | 18 | [pcap](imap/imap_t031_unselect.pcap) |
| imap_t032_expunge | T-032: EXPUNGE 已选择态 | pass | 19 | [pcap](imap/imap_t032_expunge.pcap) |
| imap_t033_search | T-033: SEARCH 非空结果 | pass | 19 | [pcap](imap/imap_t033_search.pcap) |
| imap_t034_search_empty | T-034: SEARCH 空结果 | pass | 19 | [pcap](imap/imap_t034_search_empty.pcap) |
| imap_t035_fetch_flags | T-035: FETCH flags | pass | 19 | [pcap](imap/imap_t035_fetch_flags.pcap) |
| imap_t036_fetch_literal_down | T-036: FETCH body literal 下行 | pass | 21 | [pcap](imap/imap_t036_fetch_literal_down.pcap) |
| imap_t037_store | T-037: STORE 加减 flag | pass | 21 | [pcap](imap/imap_t037_store.pcap) |
| imap_t038_copy | T-038: COPY 成功与失败 | pass | 20 | [pcap](imap/imap_t038_copy.pcap) |
| imap_t039_move_uid | T-039: MOVE 与 UID FETCH | pass | 21 | [pcap](imap/imap_t039_move_uid.pcap) |
| imap_t040_no_code | T-040: NO 失败码台词 | pass | 13 | [pcap](imap/imap_t040_no_code.pcap) |
| imap_t041_unknown_bad | T-041: 未知命令 BAD 台词 | pass | 15 | [pcap](imap/imap_t041_unknown_bad.pcap) |
| imap_t042_rfc8_session | T-042: RFC 9051 §8 官方示例会话 | pass | 21 | [pcap](imap/imap_t042_rfc8_session.pcap) |
| imap_t043_idle_push | T-043: IDLE 有 push | pass | 23 | [pcap](imap/imap_t043_idle_push.pcap) |
| imap_t044_idle_nopush | T-044: IDLE 无 push | pass | 22 | [pcap](imap/imap_t044_idle_nopush.pcap) |
| imap_t045_idle_close | T-045: IDLE timeout close_after_idle | pass | 24 | [pcap](imap/imap_t045_idle_close.pcap) |
| imap_t046_idle_keep | T-046: IDLE timeout keep_idle | pass | 24 | [pcap](imap/imap_t046_idle_keep.pcap) |
| imap_t047_idle_none | T-047: IDLE timeout none | pass | 23 | [pcap](imap/imap_t047_idle_none.pcap) |
| imap_t048_condstore | T-048: CONDSTORE 尾注正例 | pass | 20 | [pcap](imap/imap_t048_condstore.pcap) |
| imap_t049_utf8_on | T-049: UTF-8 开正例 | pass | 16 | [pcap](imap/imap_t049_utf8_on.pcap) |
| imap_t050_utf8_off_reject | T-050: UTF-8 关拒绝 | pass | 0 | [pcap]() |
| imap_t051_mime_multi | T-051: FETCH MIMEBody 双附件下载 | pass | 25 | [pcap](imap/imap_t051_mime_multi.pcap) |
| imap_t052_mime_append_up | T-052: APPEND MIMEBody 上行 | pass | 17 | [pcap](imap/imap_t052_mime_append_up.pcap) |
| imap_t053_mss_reject | T-053: MSS 过小拒绝 | pass | 0 | [pcap]() |
| imap_t054_gmail | T-054: 现网 Gmail 形 | pass | 13 | [pcap](imap/imap_t054_gmail.pcap) |
| imap_t055_outlook | T-055: 现网 Outlook 形 | pass | 13 | [pcap](imap/imap_t055_outlook.pcap) |
| imap_t056_dovecot | T-056: 现网 Dovecot 形 | pass | 16 | [pcap](imap/imap_t056_dovecot.pcap) |
| imap_t057_two_fetch | T-057: 同连接两 FETCH | pass | 22 | [pcap](imap/imap_t057_two_fetch.pcap) |
| imap_t058_abort_no_logout | T-058: FETCH 后无 LOGOUT 断线 | pass | 16 | [pcap](imap/imap_t058_abort_no_logout.pcap) |
| imap_t059_keepalive_noop | T-059: 三 NOOP 长保活 | pass | 19 | [pcap](imap/imap_t059_keepalive_noop.pcap) |
| imap_t060_composite_a | T-060: 复合流 A 登录+取改 | pass | 23 | [pcap](imap/imap_t060_composite_a.pcap) |
| imap_t061_imaps_993 | T-061: IMAPS 端口 993 显式通过 | pass | 20 | [pcap](imap/imap_t061_imaps_993.pcap) |
| imap_t062_v6 | T-062: v6 承载冒烟 | pass | 13 | [pcap](imap/imap_t062_v6.pcap) |
| imap_t063_bad_ip_reject | T-063: 坏 IP 拒绝 | pass | 0 | [pcap]() |
| imap_t064_presence_reject | T-064: 顶层 imap 判死 | pass | 0 | [pcap]() |
| imap_t065_static_pinned_reject | T-065: 显式标量双流拒绝 | pass | 0 | [pcap]() |
| imap_t066_tag_toolong_reject | T-066: Tag 超长拒绝 | pass | 0 | [pcap]() |
| imap_t067_cmd_crlf_reject | T-067: 命令 CRLF 注入拒绝 | pass | 0 | [pcap]() |
| imap_t068_b64_bad_reject | T-068: B64 解码错拒绝 | pass | 0 | [pcap]() |
| imap_t069_emit_idle_no_idle_reject | T-069: EmitIDLE 无 IDLE 拒绝 | pass | 0 | [pcap]() |
| imap_t070_timeout_bad_reject | T-070: Timeout 枚举错拒绝 | pass | 0 | [pcap]() |
| imap_t071_doneresponse_crlf_reject | T-071: DoneResponse CRLF 拒绝 | pass | 0 | [pcap]() |
| imap_t072_tag_space_reject | T-072: Tag 含空格拒绝 | pass | 0 | [pcap]() |
| imap_t073_resp_crlf_reject | T-073: 单行响应 CRLF 拒绝 | pass | 0 | [pcap]() |
| imap_t074_literal_mutex_reject | T-074: LiteralBody 与 B64 互斥拒绝 | pass | 0 | [pcap]() |
| imap_t075_cancel_range_reject | T-075: CancelAfter 越界拒绝 | pass | 0 | [pcap]() |
| imap_t076_push_crlf_reject | T-076: Push 含 CRLF 拒绝 | pass | 0 | [pcap]() |
| imap_t077_donetag_space_reject | T-077: DoneTag 含空格拒绝 | pass | 0 | [pcap]() |
| imap_t078_default_twoflow | T-078: 全缺省双流放行 | pass | 14 | [pcap](imap/imap_t078_default_twoflow.pcap) |
| imap_t079_composite_b | T-079: 复合流 B 创建+取删 | pass | 30 | [pcap](imap/imap_t079_composite_b.pcap) |
| imap_t080_mime_empty_text | T-080: FETCH MIME 空正文双附件 | pass | 25 | [pcap](imap/imap_t080_mime_empty_text.pcap) |
| imap_t081_mime_attach_only | T-081: FETCH MIME 纯附件无正文 | pass | 24 | [pcap](imap/imap_t081_mime_attach_only.pcap) |
| imap_t082_imaps_chain | T-082: IMAPS 实链形 993 | pass | 20 | [pcap](imap/imap_t082_imaps_chain.pcap) |
| imap_t083_mime_mutex_reject | T-083: MIMEBody 与 Literal 互斥拒绝 | pass | 0 | [pcap]() |
| imap_t084_responses_cap_reject | T-084: Responses 超 1 万拒绝 | pass | 0 | [pcap]() |

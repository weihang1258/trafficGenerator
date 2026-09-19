# sip Pcap Test Results

Cases: 43 — pass 43, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| sip_302_redirect | T-SIP-33: 302 呼转重定向（RFC 3261 §8.1.3.4：Contact 新目标→重发 INVITE；无条件呼转语义） | pass | 13 | [pcap](sip/sip_302_redirect.pcap) |
| sip_basic_dialog | 冒烟：TCP 3握手+五消息dialog(INVITE/200/ACK/BYE/200)+4挥手=12包（存量等价迁移） | pass | 12 | [pcap](sip/sip_basic_dialog.pcap) |
| sip_body_multipart | T-SIP-42: multipart/mixed 双体（RFC 5621：SDP+application/isup 信令体共存；现网 PSTN 网关面） | pass | 12 | [pcap](sip/sip_body_multipart.pcap) |
| sip_busy_reject | T-SIP-21: 486 Busy 拒绝非正常结束（§3.15 非正常结束②；INVITE→486→ACK=3 消息+TCP=10 包；无 BYE） | pass | 10 | [pcap](sip/sip_busy_reject.pcap) |
| sip_callflow_complete | T-SIP-24: 组合流二（§9.11 组合流≥2 条≥3 动作；INVITE→180→200→ACK→PRACK→200→BYE→200=8 消息+TCP=15 包；含 180 临时+PRACK 确认） | pass | 15 | [pcap](sip/sip_callflow_complete.pcap) |
| sip_cancel | T-SIP-20: CANCEL 取消未应答呼叫（§3.15 非正常结束①；INVITE→180→CANCEL→200→487→ACK=6 消息+TCP=13 包；无 BYE 序列） | pass | 13 | [pcap](sip/sip_cancel.pcap) |
| sip_compact_form | T-SIP-37: 紧凑形头方言（RFC 3261 §20 compact：v=/f=/t=/i=/l=；§9.10 常见方言面） | pass | 12 | [pcap](sip/sip_compact_form.pcap) |
| sip_default_port | T-SIP-16: sip 层无端口→dst 缺省 5060 | pass | 12 | [pcap](sip/sip_default_port.pcap) |
| sip_early_media_183 | T-SIP-30: 183 早期媒体+PRACK（RFC 3262 提前振铃音/回铃媒体；现网运营商彩铃面） | pass | 13 | [pcap](sip/sip_early_media_183.pcap) |
| sip_empty_dialog | T-SIP-18: 空 dialog→7 包最小联结（nil-config 合同） | pass | 7 | [pcap](sip/sip_empty_dialog.pcap) |
| sip_flat_presence | T-SIP-2: 顶层 sip presence 判死（空 map 也死） | pass | 0 | [pcap]() |
| sip_flat_static_port | T-SIP-3: sip 层静态端口+flows=2 拒（12.9，门扩扫 sip 层） | pass | 0 | [pcap]() |
| sip_hdr_case_mix | T-SIP-43: 头名大小写混写透传（RFC 3261 §7.3 头名大小写不敏感；fRoM/cALL-iD/CsEq 现网乱写面） | pass | 12 | [pcap](sip/sip_hdr_case_mix.pcap) |
| sip_hdr_completion | T-SIP-4: 无头 INVITE→Call-ID/Via/CSeq/Max-Forwards 全生成（RFC 3261 §8.1.1.4） | pass | 12 | [pcap](sip/sip_hdr_completion.pcap) |
| sip_hdr_user_wins | T-SIP-5: 显式 CSeq:7+Call-ID→保留+200 响应回显（user 头赢三态） | pass | 9 | [pcap](sip/sip_hdr_user_wins.pcap) |
| sip_hold_resume | T-SIP-31: 呼叫保持/恢复（HOLD RFC 3264 §6：re-INVITE a=sendonly→a=sendrecv；现网保持键语义） | pass | 16 | [pcap](sip/sip_hold_resume.pcap) |
| sip_info_dtmf | T-SIP-32: INFO 带 DTMF（RFC 2976 会话中带外信令；IVR 按键场景） | pass | 14 | [pcap](sip/sip_info_dtmf.pcap) |
| sip_invite_401_challenge | T-SIP-35: INVITE 401 质询重发（§22.1 呼叫鉴权：401→ACK→INVITE+Authorization→200→ACK；代理鉴权面，与注册鉴权 T-25 分面） | pass | 13 | [pcap](sip/sip_invite_401_challenge.pcap) |
| sip_long_auth_uri | T-SIP-39: 超长头+长 URI（§9.8 超长面：512B 级 Digest 头+226B 参数化长 URI；与 MSS 分段例构成头长/消息长正交） | pass | 9 | [pcap](sip/sip_long_auth_uri.pcap) |
| sip_message_im | T-SIP-36: MESSAGE 页模式即时消息（RFC 3428；SIP 短信/IM 现网面） | pass | 9 | [pcap](sip/sip_message_im.pcap) |
| sip_mss_segment | T-SIP-10: 3000B body→MSS 1460 分段 3 段 | pass | 11 | [pcap](sip/sip_mss_segment.pcap) |
| sip_options | T-SIP-7: OPTIONS 方法枚举+200 | pass | 9 | [pcap](sip/sip_options.pcap) |
| sip_options_keepalive | T-SIP-22: dialog 内 OPTIONS 保活（§3.15 保活+会话内探活；INVITE→200→ACK→OPTIONS→200→BYE→200=7 消息+TCP=14 包） | pass | 14 | [pcap](sip/sip_options_keepalive.pcap) |
| sip_port_dyn | T-SIP-17: sip.src_port 动态 inc+flows=2（E1 逐流端口池，2 流×12=24 包） | pass | 24 | [pcap](sip/sip_port_dyn.pcap) |
| sip_refer_transfer | T-SIP-28: REFER 盲转（RFC 3515：REFER+Refer-To→NOTIFY(sipfrag) 进展上报→BYE；现网话机转移键语义） | pass | 16 | [pcap](sip/sip_refer_transfer.pcap) |
| sip_register | T-SIP-6: REGISTER 方法枚举+200 | pass | 9 | [pcap](sip/sip_register.pcap) |
| sip_register_digest_auth | T-SIP-25: REGISTER 摘要鉴权完整序列（§9.10 现网规范面：REGISTER→401(WWW-Authenticate)→REGISTER(Authorization Digest)→200；主流注册器无一例外面） | pass | 11 | [pcap](sip/sip_register_digest_auth.pcap) |
| sip_register_expire0 | T-SIP-26: REGISTER 刷新+注销（Expires:0 递减=RFC 3261 §10.2.2 注销；注册生命周期 §3.2 面） | pass | 11 | [pcap](sip/sip_register_expire0.pcap) |
| sip_reinvite_refresh | T-SIP-19: 会话内 re-INVITE 刷新（§3.15 多轮操作+会话内重协商；INVITE→200→ACK→re-INVITE→200→ACK→BYE→200=8 消息+TCP 3握4挥=15 包） | pass | 15 | [pcap](sip/sip_reinvite_refresh.pcap) |
| sip_rtp_down | T-SIP-12: RTP down 方向+显式 media 端口（src 30000/dst 30001→线上 src=30001/dst=30000） | pass | 10 | [pcap](sip/sip_rtp_down.pcap) |
| sip_rtp_filesource | T-SIP-14: RTP FileSource literal 'pay'→帧 payload 实字节（FileSource 优先合同） | pass | 10 | [pcap](sip/sip_rtp_filesource.pcap) |
| sip_rtp_media | T-SIP-11: RTP 媒体子流（EmitMedia+frames:2/PT 0→UDP 5004 两帧；14 包） | pass | 14 | [pcap](sip/sip_rtp_media.pcap) |
| sip_sdp_body | T-SIP-9: SDP body 无 Content-Length 头→自动补（RFC 合同 sip.go:308-314） | pass | 9 | [pcap](sip/sip_sdp_body.pcap) |
| sip_sdp_port | T-SIP-13: SDP m=audio 6007020→RTP src=6007020（scanSDPMediaPorts 合同） | pass | 10 | [pcap](sip/sip_sdp_port.pcap) |
| sip_sdp_video_multistream | T-SIP-41: SDP 双流音视频+DTMF 载荷（§5.14 多 m= 行：audio 0/8+video 96+telephone-event 101；与单音频 sdp_body 分格） | pass | 12 | [pcap](sip/sip_sdp_video_multistream.pcap) |
| sip_status_class_enum | T-SIP-23: 状态码枚举补格（§9.20 4xx/5xx/6xx 大类覆盖；INVITE→486→ACK=10 包） | pass | 13 | [pcap](sip/sip_status_class_enum.pcap) |
| sip_status_codes | T-SIP-8: 响应码枚举 100/180/200/404（INVITE 多响应+404 拒绝路径） | pass | 15 | [pcap](sip/sip_status_codes.pcap) |
| sip_subscribe_notify_mwi | T-SIP-29: SUBSCRIBE/NOTIFY MWI 留言灯（RFC 3265 事件框架+RFC 3842 message-summary body；现网语音信箱面） | pass | 13 | [pcap](sip/sip_subscribe_notify_mwi.pcap) |
| sip_tel_uri_utf8 | T-SIP-40: tel: URI 互通+UTF-8 显示名（RFC 3966 tel 互通 RFC 3261 §19.1.6；现网 E.164 拨号面） | pass | 12 | [pcap](sip/sip_tel_uri_utf8.pcap) |
| sip_two_calls_sequential | T-SIP-27: 同流两通连续呼叫（独立 Call-ID 独立命运：呼A 成+B 拒；§3.1-3.3 独立会话语义+§9.9 现实 UA 行为） | pass | 15 | [pcap](sip/sip_two_calls_sequential.pcap) |
| sip_update_session_timer | T-SIP-34: UPDATE 会话定时刷新（RFC 3311 不占 INVITE 事务槽；RFC 4028 Session-Expires 面板） | pass | 12 | [pcap](sip/sip_update_session_timer.pcap) |
| sip_v6 | T-SIP-15: ip 层 v6→IP 透明正例（9.24 地址族对称） | pass | 12 | [pcap](sip/sip_v6.pcap) |
| sip_via_chain | T-SIP-38: 多跳代理 Via 链+Record-Route/Route（3 跳路径拓扑头；§9.10 代理链现网面） | pass | 12 | [pcap](sip/sip_via_chain.pcap) |

# sip Pcap Test Results

Cases: 76 — pass 76, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| sip_100_trying_retrans | T-SIP-44: 100 Trying+同 CSeq 请求重传（RFC 3261 §17.1.1.2 UDP 重传语义：T1 间隔重发原请求；§21.1.1 1xx provisional） | pass | 13 | [pcap](sip/sip_100_trying_retrans.pcap) |
| sip_302_redirect | T-SIP-33: 302 呼转重定向（RFC 3261 §8.1.3.4：Contact 新目标→重发 INVITE；无条件呼转语义） | pass | 13 | [pcap](sip/sip_302_redirect.pcap) |
| sip_491_glare | T-SIP-53: 491 Request Pending glare（RFC 3261 §14.2：双方同发 re-INVITE 竞争；响应码枚举 491 格） | pass | 13 | [pcap](sip/sip_491_glare.pcap) |
| sip_basic_dialog | 冒烟：TCP 3握手+五消息dialog(INVITE/200/ACK/BYE/200)+4挥手=12包（存量等价迁移） | pass | 12 | [pcap](sip/sip_basic_dialog.pcap) |
| sip_body_multipart | T-SIP-42: multipart/mixed 双体（RFC 5621：SDP+application/isup 信令体共存；现网 PSTN 网关面） | pass | 12 | [pcap](sip/sip_body_multipart.pcap) |
| sip_busy_reject | T-SIP-21: 486 Busy 拒绝非正常结束（§3.15 非正常结束②；INVITE→486→ACK=3 消息+TCP=10 包；无 BYE） | pass | 10 | [pcap](sip/sip_busy_reject.pcap) |
| sip_callflow_complete | T-SIP-24: 组合流二（§9.11 组合流≥2 条≥3 动作；INVITE→180→200→ACK→PRACK→200→BYE→200=8 消息+TCP=15 包；含 180 临时+PRACK 确认） | pass | 15 | [pcap](sip/sip_callflow_complete.pcap) |
| sip_cancel | T-SIP-20: CANCEL 取消未应答呼叫（§3.15 非正常结束①；INVITE→180→CANCEL→200→487→ACK=6 消息+TCP=13 包；无 BYE 序列） | pass | 13 | [pcap](sip/sip_cancel.pcap) |
| sip_compact_form | T-SIP-37: 紧凑形头方言（RFC 3261 §20 compact：v=/f=/t=/i=/l=；§9.10 常见方言面） | pass | 12 | [pcap](sip/sip_compact_form.pcap) |
| sip_conference_join | T-SIP-46: 会议加入+名册事件（RFC 4579 焦点 URI+RFC 4575 conference-info；多方会议面） | pass | 12 | [pcap](sip/sip_conference_join.pcap) |
| sip_default_port | T-SIP-16: sip 层无端口→dst 缺省 5060 | pass | 12 | [pcap](sip/sip_default_port.pcap) |
| sip_early_media_183 | T-SIP-30: 183 早期媒体+PRACK（RFC 3262 提前振铃音/回铃媒体；现网运营商彩铃面） | pass | 13 | [pcap](sip/sip_early_media_183.pcap) |
| sip_empty_dialog | T-SIP-18: 空 dialog→7 包最小联结（nil-config 合同） | pass | 7 | [pcap](sip/sip_empty_dialog.pcap) |
| sip_flat_presence | T-SIP-2: 顶层 sip presence 判死（空 map 也死） | pass | 0 | [pcap]() |
| sip_flat_static_port | T-SIP-3: sip 层静态端口+flows=2 拒（12.9，门扩扫 sip 层） | pass | 0 | [pcap]() |
| sip_forked_invite | T-SIP-45: 并行分叉 INVITE 竞速（RFC 3261 §3.1.2.1/3266：代理分叉多支路多 tag，一支 486 一支 200——多方同时振铃面） | pass | 13 | [pcap](sip/sip_forked_invite.pcap) |
| sip_hdr_case_mix | T-SIP-43: 头名大小写混写透传（RFC 3261 §7.3 头名大小写不敏感；fRoM/cALL-iD/CsEq 现网乱写面） | pass | 12 | [pcap](sip/sip_hdr_case_mix.pcap) |
| sip_hdr_completion | T-SIP-4: 无头 INVITE→Call-ID/Via/CSeq/Max-Forwards 全生成（RFC 3261 §8.1.1.4） | pass | 12 | [pcap](sip/sip_hdr_completion.pcap) |
| sip_hdr_user_wins | T-SIP-5: 显式 CSeq:7+Call-ID→保留+200 响应回显（user 头赢三态） | pass | 9 | [pcap](sip/sip_hdr_user_wins.pcap) |
| sip_history_info_fwd | T-SIP-52: History-Info 呼转链（RFC 4244：302 重定向后重发带历史条目；与 T-33 素呼转分面=带审计链版） | pass | 13 | [pcap](sip/sip_history_info_fwd.pcap) |
| sip_hold_resume | T-SIP-31: 呼叫保持/恢复（HOLD RFC 3264 §6：re-INVITE a=sendonly→a=sendrecv；现网保持键语义） | pass | 16 | [pcap](sip/sip_hold_resume.pcap) |
| sip_ims_pheaders | T-SIP-51: IMS 私有头面板（RFC 3325 P-Asserted-Identity/P-Preferred-Identity+RFC 3323 Privacy；现网运营商网里面） | pass | 12 | [pcap](sip/sip_ims_pheaders.pcap) |
| sip_info_dtmf | T-SIP-32: INFO 带 DTMF（RFC 2976 会话中带外信令；IVR 按键场景） | pass | 14 | [pcap](sip/sip_info_dtmf.pcap) |
| sip_interleaved_two_calls | T-SIP-54: 同连接两呼交错（§9.9 并发交错字面要求：A/B 两 Call-ID 事务重叠序 INV-A/180-A/INV-B/200-A/ACK-A/200-B/ACK-B/BYE-A/BYE-B；与 T-27 顺序版分面） | pass | 18 | [pcap](sip/sip_interleaved_two_calls.pcap) |
| sip_invite_401_challenge | T-SIP-35: INVITE 401 质询重发（§22.1 呼叫鉴权：401→ACK→INVITE+Authorization→200→ACK；代理鉴权面，与注册鉴权 T-25 分面） | pass | 13 | [pcap](sip/sip_invite_401_challenge.pcap) |
| sip_long_auth_uri | T-SIP-39: 超长头+长 URI（§9.8 超长面：512B 级 Digest 头+226B 参数化长 URI；与 MSS 分段例构成头长/消息长正交） | pass | 9 | [pcap](sip/sip_long_auth_uri.pcap) |
| sip_medias_bidirectional | T-SIP-72: medias 双向交替（WP-B：up/down 同点 round-robin=RFC 3550 真双向；显式端口分面；7+6+4=17 包） | pass | 16 | [pcap](sip/sip_medias_bidirectional.pcap) |
| sip_medias_filesource | T-SIP-76: medias file_source 沿用（Task 12 合同经多流形态；literal 3B→1 帧） | pass | 10 | [pcap](sip/sip_medias_filesource.pcap) |
| sip_medias_interleave | T-SIP-73: interleave 交错调度（WP-B：T=4 G=3→gap 2/1/1；RTP 与信令帧序钉死=§3.12 写死可复现；14 包） | pass | 14 | [pcap](sip/sip_medias_interleave.pcap) |
| sip_medias_port_dyn | T-SIP-75: medias src_port 动态 inc+flows=2（E1 同款整格；2 流×(7+2+4)=26 包） | pass | 22 | [pcap](sip/sip_medias_port_dyn.pcap) |
| sip_message_im | T-SIP-36: MESSAGE 页模式即时消息（RFC 3428；SIP 短信/IM 现网面） | pass | 9 | [pcap](sip/sip_message_im.pcap) |
| sip_mss_segment | T-SIP-10: 3000B body→MSS 1460 分段 3 段 | pass | 11 | [pcap](sip/sip_mss_segment.pcap) |
| sip_neg_medias_mutex | T-SIP-74: 负例 media+medias 同给互斥判死（create-time 400） | pass | 0 | [pcap]() |
| sip_neg_sessions_dialog_mutex | T-SIP-61: 负例 sessions+dialog 同给互斥判死（create-time 400） | pass | 0 | [pcap]() |
| sip_neg_sessions_empty | T-SIP-62: 负例空 sessions 数组（同锚词面，不给静默退化） | pass | 0 | [pcap]() |
| sip_neg_sessions_static | T-SIP-63: 负例 sessions 内标量端口+flows=2（12.9 扩扫执法） | pass | 0 | [pcap]() |
| sip_offerless_3pcc | T-SIP-48: offerless INVITE/3PCC（RFC 3725 流 I：无 SDP INVITE→200 带 offer→ACK 带 answer；offer/answer 方向翻转面） | pass | 12 | [pcap](sip/sip_offerless_3pcc.pcap) |
| sip_options | T-SIP-7: OPTIONS 方法枚举+200 | pass | 9 | [pcap](sip/sip_options.pcap) |
| sip_options_keepalive | T-SIP-22: dialog 内 OPTIONS 保活（§3.15 保活+会话内探活；INVITE→200→ACK→OPTIONS→200→BYE→200=7 消息+TCP=14 包） | pass | 14 | [pcap](sip/sip_options_keepalive.pcap) |
| sip_port_dyn | T-SIP-17: sip.src_port 动态 inc+flows=2（E1 逐流端口池，2 流×12=24 包） | pass | 24 | [pcap](sip/sip_port_dyn.pcap) |
| sip_publish_presence | T-SIP-49: PUBLISH 在线状态（RFC 3903 事件状态发布；SIP-ETag/SIP-If-Match 软状态刷新合同） | pass | 11 | [pcap](sip/sip_publish_presence.pcap) |
| sip_reason_q850 | T-SIP-50: Reason:Q.850 释放原因（RFC 3326：PSTN 互通释放码 cause=16 normal clearing；与 T-44 重传/普通 BYE 分面） | pass | 12 | [pcap](sip/sip_reason_q850.pcap) |
| sip_refer_transfer | T-SIP-28: REFER 盲转（RFC 3515：REFER+Refer-To→NOTIFY(sipfrag) 进展上报→BYE；现网话机转移键语义） | pass | 16 | [pcap](sip/sip_refer_transfer.pcap) |
| sip_register | T-SIP-6: REGISTER 方法枚举+200 | pass | 9 | [pcap](sip/sip_register.pcap) |
| sip_register_digest_auth | T-SIP-25: REGISTER 摘要鉴权完整序列（§9.10 现网规范面：REGISTER→401(WWW-Authenticate)→REGISTER(Authorization Digest)→200；主流注册器无一例外面） | pass | 11 | [pcap](sip/sip_register_digest_auth.pcap) |
| sip_register_expire0 | T-SIP-26: REGISTER 刷新+注销（Expires:0 递减=RFC 3261 §10.2.2 注销；注册生命周期 §3.2 面） | pass | 11 | [pcap](sip/sip_register_expire0.pcap) |
| sip_reinvite_refresh | T-SIP-19: 会话内 re-INVITE 刷新（§3.15 多轮操作+会话内重协商；INVITE→200→ACK→re-INVITE→200→ACK→BYE→200=8 消息+TCP 3握4挥=15 包） | pass | 15 | [pcap](sip/sip_reinvite_refresh.pcap) |
| sip_replaces_attended | T-SIP-47: Replaces 询转（RFC 3891+3515：REFER 带 Replaces=有接续转移，NOTIFY 上报 200 OK；与 T-28 盲转分面） | pass | 16 | [pcap](sip/sip_replaces_attended.pcap) |
| sip_rtp_down | T-SIP-12: RTP down 方向+显式 media 端口（src 30000/dst 30001→线上 src=30001/dst=30000） | pass | 10 | [pcap](sip/sip_rtp_down.pcap) |
| sip_rtp_filesource | T-SIP-14: RTP FileSource literal 'pay'→帧 payload 实字节（FileSource 优先合同） | pass | 10 | [pcap](sip/sip_rtp_filesource.pcap) |
| sip_rtp_media | T-SIP-11: RTP 媒体子流（EmitMedia+frames:2/PT 0→UDP 5004 两帧；14 包） | pass | 14 | [pcap](sip/sip_rtp_media.pcap) |
| sip_sdp_body | T-SIP-9: SDP body 无 Content-Length 头→自动补（RFC 合同 sip.go:308-314） | pass | 9 | [pcap](sip/sip_sdp_body.pcap) |
| sip_sdp_port | T-SIP-13: SDP m=audio 6007020→RTP src=6007020（scanSDPMediaPorts 合同） | pass | 10 | [pcap](sip/sip_sdp_port.pcap) |
| sip_sdp_video_multistream | T-SIP-41: SDP 双流音视频+DTMF 载荷（§5.14 多 m= 行：audio 0/8+video 96+telephone-event 101；与单音频 sdp_body 分格） | pass | 12 | [pcap](sip/sip_sdp_video_multistream.pcap) |
| sip_sessions_callid_fixed | T-SIP-70: call_id fixed 动态（12.15 整格⑦；两流同 Call-ID=显式声明） | pass | 18 | [pcap](sip/sip_sessions_callid_fixed.pcap) |
| sip_sessions_callid_pattern | T-SIP-69: call_id pattern 动态（12.15 整格⑥；flows=2 逐流 Call-ID） | pass | 18 | [pcap](sip/sip_sessions_callid_pattern.pcap) |
| sip_sessions_derived_callid | T-SIP-59: Call-ID 缺省派生（12.4 确定性：{flowIdx}-{sessIdx}@{srcIP}；端口缺省派生 12345+M*flow+idx 防撞） | pass | 18 | [pcap](sip/sip_sessions_derived_callid.pcap) |
| sip_sessions_explicit_wins | T-SIP-60: 显式赢三级（消息头 > session.call_id > 派生；user-wins 合同不变） | pass | 9 | [pcap](sip/sip_sessions_explicit_wins.pcap) |
| sip_sessions_port_fixed | T-SIP-67: sessions src_port fixed（12.15 整格④；fixed=两流同值=显式声明语义） | pass | 18 | [pcap](sip/sip_sessions_port_fixed.pcap) |
| sip_sessions_port_inc | T-SIP-64: sessions src_port inc+flows=2（12.15 整格①；group_id 固定） | pass | 18 | [pcap](sip/sip_sessions_port_inc.pcap) |
| sip_sessions_port_list | T-SIP-66: sessions src_port list 轮转（12.15 整格③） | pass | 18 | [pcap](sip/sip_sessions_port_list.pcap) |
| sip_sessions_port_pattern | T-SIP-68: sessions src_port pattern（12.15 整格⑤；模板 {n} 流序号替换） | pass | 18 | [pcap](sip/sip_sessions_port_pattern.pcap) |
| sip_sessions_port_rand | T-SIP-65: sessions src_port rand seed 钉（12.15 整格②；seed=7 可复现） | pass | 18 | [pcap](sip/sip_sessions_port_rand.pcap) |
| sip_sessions_two_dialogs | T-SIP-58: 双会话独立面（§3.1-3.3：独立 call_id/独立四元组/独立生命周期；2×(3+2+4)=18 包） | pass | 18 | [pcap](sip/sip_sessions_two_dialogs.pcap) |
| sip_sessions_v6 | T-SIP-71: v6 双会话对称格（9.24：fd00 端点×多会话；缺省端口派生同构） | pass | 18 | [pcap](sip/sip_sessions_v6.pcap) |
| sip_status_class_enum | T-SIP-23: 状态码枚举补格（§9.20 4xx/5xx/6xx 大类覆盖；INVITE→486→ACK=10 包） | pass | 13 | [pcap](sip/sip_status_class_enum.pcap) |
| sip_status_codes | T-SIP-8: 响应码枚举 100/180/200/404（INVITE 多响应+404 拒绝路径） | pass | 15 | [pcap](sip/sip_status_codes.pcap) |
| sip_status_enum_4xx | T-SIP-55: 4xx 响应码枚举长尾（§9.20 响应码表=数据场景清单：403/408/480/481/488 五格；与既有 401/404/486/487/491 分格） | pass | 22 | [pcap](sip/sip_status_enum_4xx.pcap) |
| sip_status_enum_56xx | T-SIP-56: 5xx/6xx 响应码枚举（§9.20：503 服务不可用+600 全局忙；与 500/603 分格） | pass | 13 | [pcap](sip/sip_status_enum_56xx.pcap) |
| sip_subscribe_notify_mwi | T-SIP-29: SUBSCRIBE/NOTIFY MWI 留言灯（RFC 3265 事件框架+RFC 3842 message-summary body；现网语音信箱面） | pass | 13 | [pcap](sip/sip_subscribe_notify_mwi.pcap) |
| sip_tel_uri_utf8 | T-SIP-40: tel: URI 互通+UTF-8 显示名（RFC 3966 tel 互通 RFC 3261 §19.1.6；现网 E.164 拨号面） | pass | 12 | [pcap](sip/sip_tel_uri_utf8.pcap) |
| sip_two_calls_sequential | T-SIP-27: 同流两通连续呼叫（独立 Call-ID 独立命运：呼A 成+B 拒；§3.1-3.3 独立会话语义+§9.9 现实 UA 行为） | pass | 15 | [pcap](sip/sip_two_calls_sequential.pcap) |
| sip_update_session_timer | T-SIP-34: UPDATE 会话定时刷新（RFC 3311 不占 INVITE 事务槽；RFC 4028 Session-Expires 面板） | pass | 12 | [pcap](sip/sip_update_session_timer.pcap) |
| sip_v6 | T-SIP-15: ip 层 v6→IP 透明正例（9.24 地址族对称） | pass | 12 | [pcap](sip/sip_v6.pcap) |
| sip_v6_port_dyn | T-SIP-57: v6×多流矩阵格（§9.23 地址族×结构：fd00 双栈端点+src/dst 端口动态+flows=2；4 包=2 流×(req+resp)） | pass | 18 | [pcap](sip/sip_v6_port_dyn.pcap) |
| sip_via_chain | T-SIP-38: 多跳代理 Via 链+Record-Route/Route（3 跳路径拓扑头；§9.10 代理链现网面） | pass | 12 | [pcap](sip/sip_via_chain.pcap) |

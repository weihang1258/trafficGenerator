# ldap Pcap Test Results

Cases: 22 — pass 22, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| ldap_attributes_custom | T-12 attributes 自定义：AttributeSelection [cn, mail]（非 RootDSE 15） | pass | 12 | [pcap](ldap/ldap_attributes_custom.pcap) |
| ldap_ber_long_form_length | T-2 BER 长形长度字节：15 属性 RootDSE searchReq 消息 >127B → 外层 SEQUENCE 30 84 长形 4B 长度前缀（RFC 4511 §4.1.1） | pass | 13 | [pcap](ldap/ldap_ber_long_form_length.pcap) |
| ldap_bind_anonymous | T-4 匿名 bind（缺省）：bindRequest name 空 OCTET STRING+simple [0] 空 | pass | 12 | [pcap](ldap/ldap_bind_anonymous.pcap) |
| ldap_bind_simple | T-5 simple bind：bind_dn=cn=admin,dc=test+bind_password=s3cret 入 bindRequest（name+0x80 密码串字节钉） | pass | 12 | [pcap](ldap/ldap_bind_simple.pcap) |
| ldap_bind_version2 | T-6 version=2：bindRequest version INTEGER 字节 02（缺省 03 由 T-1 承接） | pass | 12 | [pcap](ldap/ldap_bind_version2.pcap) |
| ldap_composite_multi_round | T-14 复合大场景（9.50）：rounds=2+equality filter+非匿名 bind+自定义属性 ≥3 类交织；16 包 | pass | 17 | [pcap](ldap/ldap_composite_multi_round.pcap) |
| ldap_filter_equality | T-9 equality filter：filter_type=equality+search_filter=uid+filter_value=alice → 0xa3 CHOICE+断言值 | pass | 12 | [pcap](ldap/ldap_filter_equality.pcap) |
| ldap_message_id_increment | T-3 messageID 递增钉：rounds=2 → bind id {1,4}/search id {2,5}/unbind id 3 | pass | 18 | [pcap](ldap/ldap_message_id_increment.pcap) |
| ldap_neg_filter_type_invalid | T-负例 filter_type_invalid | pass | 0 | [pcap]() |
| ldap_neg_message_id_overflow | T-22 负例：message_id_base=32767+rounds=2 → base+3r+2 超限 | pass | 0 | [pcap]() |
| ldap_neg_result_code_range | T-负例 result_code_range | pass | 0 | [pcap]() |
| ldap_neg_scope_invalid | T-负例 scope_invalid | pass | 0 | [pcap]() |
| ldap_neg_size_limit_negative | T-负例 size_limit_negative | pass | 0 | [pcap]() |
| ldap_neg_version_invalid | T-负例 version_invalid | pass | 0 | [pcap]() |
| ldap_result_invalid_credentials | T-10 result_code=49：bindResponse+searchResDone resultCode 0x31（invalidCredentials 失败分支） | pass | 12 | [pcap](ldap/ldap_result_invalid_credentials.pcap) |
| ldap_rounds_two | T-11 rounds=2 多轮：两完整 bind/search 序+messageID 续编（17 包） | pass | 17 | [pcap](ldap/ldap_rounds_two.pcap) |
| ldap_scope_single_level | T-7 scope=singleLevel(1)：searchRequest scope ENUMERATED 字节 01 | pass | 12 | [pcap](ldap/ldap_scope_single_level.pcap) |
| ldap_scope_whole_subtree | T-8 scope=wholeSubtree(2)：searchRequest scope 字节 02 | pass | 12 | [pcap](ldap/ldap_scope_whole_subtree.pcap) |
| ldap_search_base_dn | T-15 search_base_dn 显式：dc=corp,dc=com（非 RootDSE 空串） | pass | 12 | [pcap](ldap/ldap_search_base_dn.pcap) |
| ldap_session_full | T-1 全会话（smoke 改写，等价覆盖）：握手3+bindReq/bindResp+searchReq/entry/done+unbind+挥手4=12 包；protocolOp 六标签逐帧 | pass | 13 | [pcap](ldap/ldap_session_full.pcap) |
| ldap_size_time_limit | T-16 size_limit=10+time_limit=60：searchRequest 两 INTEGER 字节钉 | pass | 12 | [pcap](ldap/ldap_size_time_limit.pcap) |
| ldap_unbind_suppressed | T-13 unbind=false：无 0x42 帧，末 done 后径直挥手（11 包） | pass | 12 | [pcap](ldap/ldap_unbind_suppressed.pcap) |

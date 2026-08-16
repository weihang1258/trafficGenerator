# smb Pcap Test Results

Cases: 279 — pass 279, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| smb_terr042_logon_failure_setup | T042: SESSION_SETUP LOGON_FAILURE | pass | 17 | [pcap](/tmp/mcp-pcaps/smb/smb_terr042_logon_failure_setup.pcap) |
| smb_terr126_negotiate_error | T126/T135/T202: ErrorOnCommand=negotiate + Status=0xC000000D(INVALID_PARAMETER) → NEGOTIATE resp 错误, 无 SESSION_SETUP/LOGOFF, 直接 TCP teardown, 8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/smb/smb_terr126_negotiate_error.pcap) |
| smb_terr128_treeconnect_error | T128/T059/T140: ErrorOnCommand=tree_connect + Status=0xC00000CC(BAD_NETWORK_NAME) → TC resp 错误 (体仅 SS=16 无 ShareType), 跳过 CREATE, teardown 仅 LOGOFF, 18 包 | pass | 19 | [pcap](/tmp/mcp-pcaps/smb/smb_terr128_treeconnect_error.pcap) |
| smb_terr129_create_error | T129/T079: ErrorOnCommand=create 经 MCP 生效 → CREATE resp Status=0xC0000034, 跳过 READ/WRITE/CLOSE, 仅 TREE_DISCONNECT+LOGOFF, 22 包 | pass | 23 | [pcap](/tmp/mcp-pcaps/smb/smb_terr129_create_error.pcap) |
| smb_terr130_read_error | T130/T090/T145: ErrorOnCommand=read + Status=0xC0000020(END_OF_FILE), READ Offset=999999 超 EOF → resp 错误体 SS=17+DataOffset=0; CLOSE+TD+LOGOFF 仍执行, 26 包 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_terr130_read_error.pcap) |
| smb_terr131_write_error | T131: WRITE 错误 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_terr131_write_error.pcap) |
| smb_terr132_close_error | T132: CLOSE 错误 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_terr132_close_error.pcap) |
| smb_terr133_td_error | T133: TREE_DISCONNECT 错误 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_terr133_td_error.pcap) |
| smb_terr134_logoff_error | T134: LOGOFF 错误 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_terr134_logoff_error.pcap) |
| smb_terr136_logon_failure | T136/T127/T140b: ErrorOnCommand=session_setup + Status=0xC000006D(LOGON_FAILURE) → 3 轮 NTLM 仍发, 最后一轮 resp (p11) 错误体 SS=9+Offset/Length=0; 仅 LOGOFF, 16 包 | pass | 17 | [pcap](/tmp/mcp-pcaps/smb/smb_terr136_logon_failure.pcap) |
| smb_terr137_138_td_logoff_cmd | T137/T138: CREATE 错误后 TD/LOGOFF Command | pass | 23 | [pcap](/tmp/mcp-pcaps/smb/smb_terr137_138_td_logoff_cmd.pcap) |
| smb_terr139_error_flags | T139: 错误响应 Flags | pass | 23 | [pcap](/tmp/mcp-pcaps/smb/smb_terr139_error_flags.pcap) |
| smb_terr140a_create_err_ss | T140a: CREATE 错误响应体 SS=89 | pass | 23 | [pcap](/tmp/mcp-pcaps/smb/smb_terr140a_create_err_ss.pcap) |
| smb_tneg_T226_dialect_invalid | T226/V1: Dialects=[0x9999] 非法值 → Validate 拒绝 (不在 MS-SMB2 §3.2.1 allowed list) | pass | 0 | [pcap]() |
| smb_tneg_T227_smb1_string | T227/T239/V2: Dialects=[NT LM 0.12] SMB1 字符串 → Validate 拒绝 (必须用 0x0202+ 数值) | pass | 0 | [pcap]() |
| smb_tneg_T228_authmech_invalid | T228/V11: AuthMechanism=digest 非法值 → Validate 拒绝 (必须是 ntlm/kerberos/anonymous/guest) | pass | 0 | [pcap]() |
| smb_tneg_T229_anon_rounds3 | T229/V14: AuthMechanism=anonymous + AuthRounds=3 → Validate 拒绝 (anonymous 只能 1 轮) | pass | 0 | [pcap]() |
| smb_tneg_T230_rounds_oob | T230/V13: AuthRounds=10 超范围 → Validate 拒绝 (必须 1-3) | pass | 0 | [pcap]() |
| smb_tneg_T230a_ntlm_rounds1 | T230a/V15: AuthMechanism=ntlm + AuthRounds=1 → Validate 拒绝 (ntlm 只能 2 或 3 轮) | pass | 0 | [pcap]() |
| smb_tneg_T231_disposition_oob | T231/V21: CreateDisposition=9 超范围 → Validate 拒绝 (必须 0-5) | pass | 0 | [pcap]() |
| smb_tneg_T232_share_no_unc | T232/V18: TreeConnectShare=share (无 \\ 前缀) → Validate 拒绝 (必须 UNC \\server\share) | pass | 0 | [pcap]() |
| smb_tneg_T233_optype_invalid | T233/V23: OpType="delete" 非合法值 → ValidateConfig 拒绝 (OpType must be read/write/close/...) | pass | 0 | [pcap]() |
| smb_tneg_T234_errorcmd_invalid | T234/V28: ErrorOnCommand="foo" 非合法值 → ValidateConfig 拒绝 (ErrorOnCommand must be negotiate/session_setup/...) | pass | 0 | [pcap]() |
| smb_tneg_T235_errstatus_unknown | T235/V31: ErrorResponseStatus=0x12345678 不在 knownStatusCodes 列表 → ValidateConfig 拒绝 (must be a known NT status code) | pass | 0 | [pcap]() |
| smb_tneg_T236_maxtransact_oob | T236/V32: MaxTransactSize=16777216 (0x01000000) 超 NBSS 24-bit 上限 → ValidateConfig 拒绝 (exceeds NBSS limit) | pass | 0 | [pcap]() |
| smb_tneg_T237_sharetype_oob | T237/V19: ShareType=9 不在 {0,1,2} 合法值 → ValidateConfig 拒绝 (must be 0(DISK)/1(PIPE)/2(PRINT)) | pass | 0 | [pcap]() |
| smb_tneg_T238_errstatus_no_errcmd | T238/V29: ErrorResponseStatus 非零但 ErrorOnCommand 空 → ValidateConfig 拒绝 (ErrorOnCommand must be set when ErrorResponseStatus is non-zero) | pass | 0 | [pcap]() |
| smb_tneg_T239_smb1 | T239: SMB1 dialect 拒绝 | pass | 0 | [pcap]() |
| smb_tneg_T240_preauth_algo_invalid | T240/V10: PreauthIntegrityHashAlgorithms=[0x0002] 仅 0x0001 (SHA-512) 合法 → ValidateConfig 拒绝 (only supports 0x0001 SHA-512) | pass | 0 | [pcap]() |
| smb_tpos001_default_dialects | T001: 默认 5 dialects | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos001_default_dialects.pcap) |
| smb_tpos005_encrypt_ctx | T005: 0x0311 Encryption ctx | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos005_encrypt_ctx.pcap) |
| smb_tpos006_security_mode | T006: SecurityMode=0x01 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos006_security_mode.pcap) |
| smb_tpos008_client_caps | T008: ClientCapabilities=0x03 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos008_client_caps.pcap) |
| smb_tpos009_clientguid_random | T009: ClientGuid 随机非零 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos009_clientguid_random.pcap) |
| smb_tpos010_clientguid_fixed | T010: ClientGuid 固定 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos010_clientguid_fixed.pcap) |
| smb_tpos011_resp_dialect | T011: resp DialectRevision | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos011_resp_dialect.pcap) |
| smb_tpos012_serverguid_random | T012: resp ServerGuid 随机 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos012_serverguid_random.pcap) |
| smb_tpos013_maxtransact_65536 | T013: MaxTransactSize=65536 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos013_maxtransact_65536.pcap) |
| smb_tpos014_maxread_1048576 | T014: MaxReadSize=1048576 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos014_maxread_1048576.pcap) |
| smb_tpos015_maxwrite_1048576 | T015: MaxWriteSize=1048576 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos015_maxwrite_1048576.pcap) |
| smb_tpos016_resp_securitybuffer | T016: resp SecurityBuffer 非空 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos016_resp_securitybuffer.pcap) |
| smb_tpos017_nego_cmd | T017: NEGOTIATE req Command | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos017_nego_cmd.pcap) |
| smb_tpos018_req_flags | T018: req Flags=0 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos018_req_flags.pcap) |
| smb_tpos019_resp_flags | T019: resp Flags=1 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos019_resp_flags.pcap) |
| smb_tpos020_resp_credit | T020: resp CreditResponse | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos020_resp_credit.pcap) |
| smb_tpos064_impersonation | T064: ImpersonationLevel=2 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos064_impersonation.pcap) |
| smb_tpos073_create_treeid | T073: CREATE req TreeId 复用 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos073_create_treeid.pcap) |
| smb_tpos100_write_dataoffset | T100: WRITE DataOffset=112 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos100_write_dataoffset.pcap) |
| smb_tpos101_close | T101: 显式 close 操作 → 双 CLOSE (planner 已发隐式 CLOSE 又发显式, bug 证据), 26 包; CLOSE#1 msg_id=6, CLOSE#2 msg_id=7 | pass | 25 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos101_close.pcap) |
| smb_tpos102_close_cmd | T102: CLOSE req Command 0x0006 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos102_close_cmd.pcap) |
| smb_tpos103_close_structsize | T103: CLOSE req StructureSize=24 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos103_close_structsize.pcap) |
| smb_tpos104_close_fileid | T104: CLOSE req FileId 复用 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos104_close_fileid.pcap) |
| smb_tpos105_close_resp_ss | T105: CLOSE resp StructureSize=60 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos105_close_resp_ss.pcap) |
| smb_tpos106_close_resp_eof | T106: CLOSE resp EndOfFile=0 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos106_close_resp_eof.pcap) |
| smb_tpos107_write_through | T107: WRITE_THROUGH Flags=0x01 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos107_write_through.pcap) |
| smb_tpos108_read_mincount | T108: READ MinimumCount | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos108_read_mincount.pcap) |
| smb_tpos109_write_10kb | T109: WRITE 10KB 多段 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos109_write_10kb.pcap) |
| smb_tpos110_read_10kb | T110: READ 10KB 多段 | pass | 34 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos110_read_10kb.pcap) |
| smb_tpos113_kerberos_full | T113: Kerberos 会话 25 包 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos113_kerberos_full.pcap) |
| smb_tpos114_cmd_sequence | T114: 命令序列 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos114_cmd_sequence.pcap) |
| smb_tpos115_msgid_monotonic | T115: MessageId 单调递增 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos115_msgid_monotonic.pcap) |
| smb_tpos116_msgid_pair | T116: MessageId 请求=响应 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos116_msgid_pair.pcap) |
| smb_tpos117_nego_msgid0 | T117: NEGOTIATE MessageId=0 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos117_nego_msgid0.pcap) |
| smb_tpos11_full_session_ops2 | T112: 完整会话 NTLM3 + read(4096) + write(10B) → 30 包; WRITE req p20/resp p21 (命令体 StructureSize 31 00/11 00), CLOSE req p22 (18 00) | pass | 31 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos11_full_session_ops2.pcap) |
| smb_tpos120_logoff_msgid | T120: LOGOFF MessageId=9 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos120_logoff_msgid.pcap) |
| smb_tpos121_skip_negotiate | T121: IncludeNegotiate=false → 无 NEGOTIATE, 第一个 SMB2 PDU 是 SESSION_SETUP (p4, MessageId=0), 会话 26 包 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos121_skip_negotiate.pcap) |
| smb_tpos122_skip_treeconnect | T122: IncludeTreeConnect=false | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos122_skip_treeconnect.pcap) |
| smb_tpos123_skip_teardown | T123: IncludeTeardown=false | pass | 25 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos123_skip_teardown.pcap) |
| smb_tpos124_pdu_count | T124: 默认 20 SMB PDU | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos124_pdu_count.pcap) |
| smb_tpos125_pdu_count_2op | T125: 2 ops 22 SMB PDU | pass | 31 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos125_pdu_count_2op.pcap) |
| smb_tpos141_empty_filename | T141: 空文件名 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos141_empty_filename.pcap) |
| smb_tpos142_long_filename | T142: 超长文件名 255 字符 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos142_long_filename.pcap) |
| smb_tpos143_long_path | T143: 超长路径 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos143_long_path.pcap) |
| smb_tpos144_read_len0 | T144/T146: READ Length=0 + WRITE 空 Data → req Length=0, resp DataLength=0/Count=0 (V25 零长度合法边界), 28 包 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos144_read_len0.pcap) |
| smb_tpos147_dialectcount_1 | T147: DialectCount=1 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos147_dialectcount_1.pcap) |
| smb_tpos148_dialectcount_5 | T148: DialectCount=5 默认 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos148_dialectcount_5.pcap) |
| smb_tpos149_auth_rounds_default | T149: AuthRounds=0 按机制默认 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos149_auth_rounds_default.pcap) |
| smb_tpos150_maxtransact_1024 | T150: MaxTransactSize=1024 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos150_maxtransact_1024.pcap) |
| smb_tpos151_maxread_512 | T151: MaxReadSize=512 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos151_maxread_512.pcap) |
| smb_tpos152_maxwrite_256 | T152: MaxWriteSize=256 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos152_maxwrite_256.pcap) |
| smb_tpos153_dialect_0202 | T153: 单 dialect 0x0202 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos153_dialect_0202.pcap) |
| smb_tpos154_fileid_zero_default | T154: FileId 默认随机 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos154_fileid_zero_default.pcap) |
| smb_tpos155_fileid_user | T155: FileId 用户指定 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos155_fileid_user.pcap) |
| smb_tpos156_157_multiflow_2_sessions_sesid | T156/T157: strategy_fc flows=2 → 2 个 SESSION_SETUP resp 各自非零 SessionId 且互不相同 (全局原子唯一); 56 包 | pass | 58 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos156_157_multiflow_2_sessions_sesid.pcap) |
| smb_tpos158_170a_multiflow_treeid_per_session | T158/T170a: 两会话 TREE_CONNECT resp TreeId 各自=1 (会话内从 1 递增, 无全局串扰); p13 与 p41 TreeId 均=1, 各自会话内后续包保持 | pass | 58 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos158_170a_multiflow_treeid_per_session.pcap) |
| smb_tpos161_162_multiflow_guid_different | T161/T162: 两会话 ClientGuid/ServerGuid 各自不同 (applyDefaults 每流 rand.Read 重新生成); 帧断言 p4/p32 的 GUID 16B 不重复 | pass | 58 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos161_162_multiflow_guid_different.pcap) |
| smb_tpos164_multiflow_msgid_independent | T164: 两会话 MessageId 各自从 0 递增 (0-9), 不跨流共享; p4 会话 A NEGO=0, p32 会话 B NEGO=0 | pass | 58 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos164_multiflow_msgid_independent.pcap) |
| smb_tpos167_multiflow_4tuple_independent | T167: 多会话独立 4-tuple — 会话 B src_port=12346 (auto-increment 12345+i), dst_port 恒 445 | pass | 58 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos167_multiflow_4tuple_independent.pcap) |
| smb_tpos171_0311_preauth_ctx | T171: SMB3.1.1 NEGOTIATE req 含 Preauth Integrity 协商上下文 (ContextType=0x0001) @ 帧162=01 00 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos171_0311_preauth_ctx.pcap) |
| smb_tpos172_185_preauth_hash_hex64 | T172: Preauth HashAlgorithms[0]=0x0001 (SHA-512) @ 帧174=01 00 (T185 PreauthIntegrityHashValue 64B 全 0 占位由 ctx data 长度覆盖) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos172_185_preauth_hash_hex64.pcap) |
| smb_tpos173_preauth_salt_deterministic | T173: Preauth Salt 32B 非全 0 — 帧 184 起 salt[8:16] 确定性字节 92 99 a0 a7 ae b5 bc c3 (i*7+0x5A) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos173_preauth_salt_deterministic.pcap) |
| smb_tpos174_0311_encrypt_ctx | T174: SMB3.1.1 Encryption 协商上下文 ContextType=0x0002 @ 帧210=02 00, Cipher[0]=0x0001 @ 帧220=01 00 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos174_0311_encrypt_ctx.pcap) |
| smb_tpos175_encrypt_ccm | T175: AES-CCM 默认 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos175_encrypt_ccm.pcap) |
| smb_tpos176_encrypt_gcm | T176: AES-GCM | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos176_encrypt_gcm.pcap) |
| smb_tpos177_encrypt_sessionflags | T177: EncryptionRequired SessionFlags | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos177_encrypt_sessionflags.pcap) |
| smb_tpos178_179_transform_protocolid | T178/T179: TRANSFORM_HEADER | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos178_179_transform_protocolid.pcap) |
| smb_tpos180_182_transform_flags_msgsize | T180+T182: TRANSFORM_HEADER — Flags=Encrypted @ 帧100=01 00 (p12 TREE_CONNECT req); OriginalMessageSize=100 @ 帧94=64 00 00 00 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos180_182_transform_flags_msgsize.pcap) |
| smb_tpos181_transform_sesid | T181: TRANSFORM SessionId | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos181_transform_sesid.pcap) |
| smb_tpos182_transform_msgsize | T182: OriginalMessageSize | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos182_transform_msgsize.pcap) |
| smb_tpos183_184_signing_flags_signature | T183+T184: SigningRequired=true — 请求 Flags bit3 SIGNED @ 帧74=08 00 00 00 (p4), 响应=09 00 00 00 (p5); 签名占位非零确定性 @ 帧106=7ed8328c... | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos183_184_signing_flags_signature.pcap) |
| smb_tpos186_e2e_pcap | T186: E2E Plan→Worker→PCAP — tshark 解析 SMB2, 包 4=NEGOTIATE req, 包 5=NEGOTIATE resp | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos186_e2e_pcap.pcap) |
| smb_tpos187_188_e2e_cmd_parse | T187/T188: E2E tshark 解析每个 SMB2 包 Command — NEGOTIATE=0, SESSION_SETUP=1, TREE_CONNECT=3, CREATE=5, READ=8, CLOSE=6, TREE_DISCONNECT=4, LOGOFF=2 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos187_188_e2e_cmd_parse.pcap) |
| smb_tpos189_e2e_flags_direction | T189: E2E tshark Flags — 请求包 smb2.flags.response=0, 响应包=1 (全序列抽样) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos189_e2e_flags_direction.pcap) |
| smb_tpos190_e2e_sesid_nonzero | T190: E2E — SESSION_SETUP resp#1 (p7) 后所有包 SessionId 非零 (smb2.sesid nonzero) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos190_e2e_sesid_nonzero.pcap) |
| smb_tpos191_e2e_treeid_nonzero | T191: E2E — TREE_CONNECT resp (p13) 后所有包 TreeId 非零 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos191_e2e_treeid_nonzero.pcap) |
| smb_tpos192_e2e_msgid_sequence | T192: E2E — smb2.msg_id 单调递增 0-9 (NEGO=0, SETUP 1-3, TC=4, CREATE=5, READ=6, CLOSE=7, TD=8, LOGOFF=9) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos192_e2e_msgid_sequence.pcap) |
| smb_tpos194_e2e_nbss_length | T194: E2E — 包 4 NBSS length == SMB2 PDU 字节数 (帧 55-57 大端 = 0x00 00 b9 = 185 = 4+64+117) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos194_e2e_nbss_length.pcap) |
| smb_tpos195_e2e_tcp_handshake_teardown | T195: E2E — 包 1-3 TCP 3-way 握手 + 最后 4 包 TCP 挥手 (FIN/ACK/FIN/ACK) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos195_e2e_tcp_handshake_teardown.pcap) |
| smb_tpos195a_e2e_fail_spec_reject | T195a: E2E 失败 spec 全链路拒绝 — Dialects=[0x9999] → Plan 失败 → 任务 error, 无 pcap 生成 | pass | 0 | [pcap]() |
| smb_tpos196_197_protocolid_structsize | T196/T197: SMB2 头偏移 0-3 ProtocolId=FE 53 4D 42 (NEGOTIATE req p4 帧偏移 58); 偏移 4-5 StructureSize=40 00 (64 LE) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos196_197_protocolid_structsize.pcap) |
| smb_tpos197_structsize_all | T197: 头 StructureSize 全 40 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos197_structsize_all.pcap) |
| smb_tpos198_creditcharge_21plus | T198: SMB 2.1+ (默认协商 0x0311) NEGOTIATE req CreditCharge=1 → 偏移 6-7 (帧 64) = 01 00; 对照 T199 (0x0202) = 00 00 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos198_creditcharge_21plus.pcap) |
| smb_tpos199_credit_0202 | T199: 2.0.2 CreditCharge=0 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos199_credit_0202.pcap) |
| smb_tpos1_negotiate | T001/T111-S1: 默认完整会话 28 包: NEGOTIATE(5 dialects)+NTLM3+TreeConnect+Create+Read(分段)+Close+Teardown; SMB2 头偏移 58 (Eth14+IPv4 20+TCP 20+NBSS 4) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos1_negotiate.pcap) |
| smb_tpos200_201_status_success | T200/T201: SMB2 头偏移 8-11 Status — 请求 (p4 NEGOTIATE req) 与成功响应 (p5 NEGOTIATE resp) 均为 00 00 00 00 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos200_201_status_success.pcap) |
| smb_tpos201_resp_status_success | T201: resp Status=0 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos201_resp_status_success.pcap) |
| smb_tpos203_206_cmd_offsets | T203-T206: SMB2 头偏移 12-13 Command — NEGOTIATE(p4)=00 00 / SESSION_SETUP(p6)=01 00 / CREATE(p14)=05 00 / READ(p16)=08 00 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos203_206_cmd_offsets.pcap) |
| smb_tpos204_cmd_setup | T204: Command=1 SESSION_SETUP | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos204_cmd_setup.pcap) |
| smb_tpos205_cmd_create | T205: Command=5 CREATE | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos205_cmd_create.pcap) |
| smb_tpos206_cmd_read | T206: Command=8 READ | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos206_cmd_read.pcap) |
| smb_tpos207_208_flags | T207/T208: SMB2 头偏移 16-19 Flags — 请求 (p4)=00 00 00 00, 响应 (p5)=01 00 00 00 (SMB2_FLAGS_SERVER_TO_REDIR) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos207_208_flags.pcap) |
| smb_tpos208_resp_flags | T208: resp Flags=1 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos208_resp_flags.pcap) |
| smb_tpos209_219_msgid_offset | T209/T219: MessageId 位于偏移 24-31 (帧 82) — NEGOTIATE req = 00x8 (MessageId=0), 且偏移 14-15 CreditRequest=1f 00 非零 (证明 MessageId 不在偏移 16) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos209_219_msgid_offset.pcap) |
| smb_tpos210_217_treeid_offset | T210/T217: TreeId 位于偏移 36-39 (帧 94, 非 28) — TREE_CONNECT resp (p13) = 01 00 00 00 (服务端首个 tree, 会话内计数器从 1 起) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos210_217_treeid_offset.pcap) |
| smb_tpos211_218_sesid_offset | T211/T218: SessionId 位于偏移 40-47 (帧 98, 非 32) — SESSION_SETUP req#1 (p6) 尚为 00x8 (未分配), resp#1 (p7) 起 tshark 解析出非零 sesid, req#2 (p8) 复用同一会话 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos211_218_sesid_offset.pcap) |
| smb_tpos212_signature | T212: SMB2 头偏移 48-63 Signature (帧 106) — 默认无签名, 16B 全 0 占位 (NEGOTIATE req p4) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos212_signature.pcap) |
| smb_tpos213_214_credits | T213/T214: 偏移 14-15 CreditRequest/CreditResponse — 请求 (p4)=1f 00, 成功响应 (p5)=1f 00, 均非零 (授予信用) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos213_214_credits.pcap) |
| smb_tpos214_credit_response | T214: resp CreditResponse 非零 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos214_credit_response.pcap) |
| smb_tpos215_216_nextcmd_reserved | T215/T216: 单命令 PDU — 偏移 20-23 NextCommand (帧 78)=00 00 00 00, 偏移 32-35 Reserved (帧 90)=00 00 00 00 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos215_216_nextcmd_reserved.pcap) |
| smb_tpos216_reserved | T216: Reserved=0 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos216_reserved.pcap) |
| smb_tpos217_treeid_offset | T217: TreeId 偏移 36-39 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos217_treeid_offset.pcap) |
| smb_tpos218_sesid_offset | T218: SessionId 偏移 40-47 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos218_sesid_offset.pcap) |
| smb_tpos219_msgid_offset | T219: MessageId 偏移 24-31 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos219_msgid_offset.pcap) |
| smb_tpos21_ntlm3_msgid | T021/T118/T119: NTLM 三阶段 SESSION_SETUP; resp#1 (p7) Status=0xC0000016 且分配 SessionId, req#2 (p8) 复用; MessageId 1-3; TREE_CONNECT=4; CREATE=5 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos21_ntlm3_msgid.pcap) |
| smb_tpos220_create_nameoffset | T220: CREATE req 命令体偏移 44-45 NameOffset (帧 166)=78 00 (120 = 64 头 + 56 固定体), 偏移 46-47 NameLength=10 00 (16B = file.txt UTF-16LE) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos220_create_nameoffset.pcap) |
| smb_tpos221_write_dataoffset | T221: WRITE DataOffset | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos221_write_dataoffset.pcap) |
| smb_tpos222_read_dataoffset | T222: READ resp 命令体偏移 2 DataOffset (帧 124)=50 (80 = 64 头 + 16 固定体); 偏移 0-1 StructureSize=11 00 (17) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos222_read_dataoffset.pcap) |
| smb_tpos223_negotiate_sboffset | T223: NEGOTIATE resp 命令体偏移 56-57 SecurityBufferOffset (帧 178)=80 00 (128 = 64 头 + 64 固定体) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos223_negotiate_sboffset.pcap) |
| smb_tpos224_querydir_outbuf | T224: QUERY_DIRECTORY OutputBufferOffset | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos224_querydir_outbuf.pcap) |
| smb_tpos225_transform_header | T225: EncryptionRequired=true + dialect 0x0311 → 认证完成后 PDU 以 52B TRANSFORM_HEADER 包裹: TREE_CONNECT req/resp (p12/p13) 偏移 0-3 (帧 58)=FD 53 4D 42, 内层 SMB2 头移至帧 110; SESSION_SETUP resp (p7) 保持明文 FE 53 4D 42 且 SessionFlags=04 00 (EncryptData) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos225_transform_header.pcap) |
| smb_tpos22_ntlm_2rounds | T022: AuthRounds=2 → 2 对 SESSION_SETUP (p6-9), MessageId 1-2, resp#1 Status=0xC0000016, 会话 26 包 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos22_ntlm_2rounds.pcap) |
| smb_tpos23_kerberos_2rounds | T023: kerberos AuthRounds=2 → 2 对 SESSION_SETUP (p6-9), resp#1 成功 (非 ntlm 无 MORE_PROCESSING), 会话 26 包 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos23_kerberos_2rounds.pcap) |
| smb_tpos241_query_directory | T241-T247/T233: QUERY_DIRECTORY op → cmd=0x0E, FileInformationClass=37(0x25), FileName='*' UTF-16LE, FileNameOffset=96; resp SS=9+OutputBufferOffset=64, 26 包 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos241_query_directory.pcap) |
| smb_tpos248_query_info | T248-T252/T233: QUERY_INFO op → cmd=0x10, InfoType=0(File), FileInfoClass=4(FileBasicInfo), OutputBufferLength=40; resp SS=9, 26 包 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos248_query_info.pcap) |
| smb_tpos24_anonymous | T024/T114: anonymous 一阶段认证 → 24 包; 仅 1 对 SESSION_SETUP (p6-7), MessageId: NEGO=0, SETUP=1, TC=2, CREATE=3, READ=4 | pass | 25 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos24_anonymous.pcap) |
| smb_tpos253_lock | T253-T255/T233: LOCK op → cmd=0x0A, req SS=0x30(48), LockCount=1, LOCK_ELEMENT Offset=0/Length=4096/Flags=0x02 EXCLUSIVE, 26 包 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos253_lock.pcap) |
| smb_tpos256_257_258_nbss_default | T256+T257+T258: 默认 transport='direct' NBSS 头 4B — NBSS[0]=00 (Session Message, 帧54), NBSS[1:4] 大端长度 0xB0=176 (帧55-57) == 紧随其后的 SMB2 PDU 字节数 (帧 58-233) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos256_257_258_nbss_default.pcap) |
| smb_tpos256_nbss_type | T256: NBSS type=0x00 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos256_nbss_type.pcap) |
| smb_tpos257_258_nbss_len | T257/T258: NBSS 长度大端 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos257_258_nbss_len.pcap) |
| smb_tpos259_260_nbss_lengths | T259/T260: 自定义 PDU 长度 — max_read_size=200 → READ resp 200B NBSS=00 00 C8; max_read_size=268 → NBSS=00 01 0C | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos259_260_nbss_lengths.pcap) |
| smb_tpos25_guest_1round | T025: guest AuthRounds=1 → 1 对 SESSION_SETUP (p6-7) resp 成功, 会话 24 包 (guest 默认 1 轮) | pass | 25 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos25_guest_1round.pcap) |
| smb_tpos261_262_transport_port | T261+T262: Transport='direct' (默认) dst_port=445; Transport='netbios' dst_port=139 — 用 tshark 字段断言 (默认 spec + netbios spec) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos261_262_transport_port.pcap) |
| smb_tpos261_port_445 | T261: 默认端口 445 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos261_port_445.pcap) |
| smb_tpos262_netbios_139 | T262: Transport=netbios → TCP dstport=139 + NBSS 4B 前缀 00 00 00 b0 (长度 176), 28 包 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos262_netbios_139.pcap) |
| smb_tpos262b_netbios_port | T262: Transport='netbios' → dst_port=139 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos262b_netbios_port.pcap) |
| smb_tpos263_266_tcp_handshake_psh | T263+T266: 完整 TCP 3-way 握手 (p1=SYN, p2=SYN-ACK, p3=ACK, 帧 flags 0x002/0x012/0x010) + PSH-ACK 承载 SMB2 (p4 flags=0x018, 帧 4) + NBSS 4B 前缀存在 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos263_266_tcp_handshake_psh.pcap) |
| smb_tpos263_nbss_prefix | T263: NBSS 前缀存在 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos263_nbss_prefix.pcap) |
| smb_tpos264_265_handshake_teardown | T264/T265: 3 握 4 挥 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos264_265_handshake_teardown.pcap) |
| smb_tpos264_tcp_4way_teardown | T264+T265: TCP 挥手 — 末 4 包含 FIN/ACK/FIN/ACK 序列 (HasHandshake=true + Terminates=true) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos264_tcp_4way_teardown.pcap) |
| smb_tpos266_psh_ack | T266: PSH-ACK 承载 SMB2 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos266_psh_ack.pcap) |
| smb_tpos267_mss_segmentation | T267: READ 4096B 响应跨 3 TCP 段 (MSS 1460) — smb2 PDU 覆盖 3 包, READ resp 头在 p17 后续段在 p18-19 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos267_mss_segmentation.pcap) |
| smb_tpos268_seq_ack_progression | T268: TCP seq/ack 递增 — 会话 A 第 5 包 seq = 第 4 包 seq+负载; 第 13 包 ack = 第 12 包 seq+len | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos268_seq_ack_progression.pcap) |
| smb_tpos269_nbss_max | T269: NBSS 长度最大 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos269_nbss_max.pcap) |
| smb_tpos26_27_setup_cmd_sesid0 | T026/T027: SESSION_SETUP req#1 Command=0x0001 @帧70 + SessionId=全 0 (未分配) @帧98; 16 字节全零 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos26_27_setup_cmd_sesid0.pcap) |
| smb_tpos270_nbss_zero | T270: NBSS 长度 0 (理论) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos270_nbss_zero.pcap) |
| smb_tpos271_285_structsize_default | T271-T281/T284/T285: 默认会话各命令体 StructureSize (命令体偏移 0-1, 帧 122): NEGOTIATE req 24 00(36)/resp 41 00(65); SESSION_SETUP req 19 00(25)/resp 09 00(9); TREE_CONNECT req 09 00(9)/resp 10 00(16); CREATE resp 59 00(89); CLOSE req 18 00(24)/resp 3c 00(60); READ req 31 00(49)/resp 11 00(17); TREE_DISCONNECT req 04 00(4); LOGOFF req 04 00(4) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos271_285_structsize_default.pcap) |
| smb_tpos281_read_resp_ss | T281: READ resp SS=17 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos281_read_resp_ss.pcap) |
| smb_tpos282_283_write_structsize | T282/T283: WRITE 命令体 StructureSize — req (p20) 偏移 0-1=31 00(49), resp (p21)=11 00(17); 会话 30 包 (read 4096 + write 10B) | pass | 31 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos282_283_write_structsize.pcap) |
| smb_tpos283_write_resp_ss | T283: WRITE resp SS=17 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos283_write_resp_ss.pcap) |
| smb_tpos28_29_setup_sesid_assign_reuse | T028/T029: resp#1 SessionId 非零 (服务端分配) @帧98; req#2 SessionId == resp#1 (复用) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos28_29_setup_sesid_assign_reuse.pcap) |
| smb_tpos296_read_fileid_offset | T296: READ FileId 偏移 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos296_read_fileid_offset.pcap) |
| smb_tpos2_dialects_0210 | T002: 自定义 dialects [0x0202,0x0210] → DialectCount=2, 服务端选中 0x0210 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos2_dialects_0210.pcap) |
| smb_tpos305c_cap_degrade | T305c/T301/T309: dialects=[0x0202] + ClientCapabilities=0x03 → 能力降级 0x02 (SelectedDialect<0x0300 清 bit0 Encryption), CreditCharge=0, 28 包 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos305c_cap_degrade.pcap) |
| smb_tpos30_31_setup_status_sequence | T030/T031: resp#1 Status=0xC0000016 @帧66 (MORE_PROCESSING), resp#2 Status=0x00000000 SUCCESS | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos30_31_setup_status_sequence.pcap) |
| smb_tpos32_33_34_setup_body_fields | T032/T033/T034: req#1 SecurityBufferOffset=88 @帧134, PreviousSessionId=0 @帧138; PreviousSessionId=0x1234 → @帧138=34 12 00 00 00 00 00 00 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos32_33_34_setup_body_fields.pcap) |
| smb_tpos34_previous_sesid_nonzero | T034: PreviousSessionId=0x1234 → req#1 命令体偏移 16-23 @帧138 = 34 12 00 00 00 00 00 00 (LE) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos34_previous_sesid_nonzero.pcap) |
| smb_tpos35_36_setup_sessionflags | T035/T036: resp SessionFlags — 默认 00 00 @帧124; EncryptionRequired=true → 04 00 (bit2 EncryptData) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos35_36_setup_sessionflags.pcap) |
| smb_tpos37_38_channel_capabilities | T037/T038: req#1 Channel=0 @帧130 + Capabilities=DFS 0x01 @帧126 (capabilities 字段硬编码 0x01) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos37_38_channel_capabilities.pcap) |
| smb_tpos39_40_secmode_signing | T039/T040: req#1 SecurityMode — 默认 01 (SigningEnabled) @帧125; SigningRequired=true → 03 (bit0+bit1) @帧125 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos39_40_secmode_signing.pcap) |
| smb_tpos3_dialect_0202 | T003/T301: 单 dialect 0x0202 → DialectCount=1, CreditCharge=0 (SMB 2.0.2 规则), resp DialectRevision=0x0202; context 仍附带 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos3_dialect_0202.pcap) |
| smb_tpos41_custom_securityblob | T041: SecurityBlob=自定义 → req#1 SecurityBufferLength 匹配 + blob 内容 = 0x60 0x82 0x01 0x00 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos41_custom_securityblob.pcap) |
| smb_tpos43_44_ntlm_challenge_auth | T043/T044: NTLM 三阶段 blob — resp#1 CHALLENGE type=2 @帧138, req#2 AUTH type=3 @帧154 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos43_44_ntlm_challenge_auth.pcap) |
| smb_tpos45_no_auth | T045: IncludeAuth=false → 跳过 SESSION_SETUP (p6 起即 TREE_CONNECT), 会话 22 包; 无认证会话 SessionId=0 (TREE_CONNECT req 帧偏移 98 全 0) | pass | 23 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos45_no_auth.pcap) |
| smb_tpos46_treeconnect_share | T046: 默认共享 \\server\share 14 字符 → PathLength=0x1c(28), 服务端 ShareType=0x00 (DISK), 分配 TreeId | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos46_treeconnect_share.pcap) |
| smb_tpos47_ipc_pipe | T047/T056: IPC$ 命名管道共享 \\server\IPC$ 13 字符 → PathLength=0x1a(26), resp ShareType=0x01 (PIPE) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos47_ipc_pipe.pcap) |
| smb_tpos48_tree_cmd | T048: TREE_CONNECT req Command | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos48_tree_cmd.pcap) |
| smb_tpos49_treeid_zero | T049: TREE_CONNECT req TreeId=0 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos49_treeid_zero.pcap) |
| smb_tpos4_0311_preauth | T004/T171: 单 dialect 0x0311 → SMB3.1.1 含 Preauth+Encryption 两个 NegotiateContext (ContextCount=2), Ciphers=[0x0001,0x0002] | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos4_0311_preauth.pcap) |
| smb_tpos50_treeid_assign | T050: TREE_CONNECT resp TreeId 分配 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos50_treeid_assign.pcap) |
| smb_tpos51_sesid_reuse | T051: TREE_CONNECT req SessionId 复用 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos51_sesid_reuse.pcap) |
| smb_tpos52_pathoffset | T052: TREE_CONNECT PathOffset=72 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos52_pathoffset.pcap) |
| smb_tpos53_pathlength | T053: TREE_CONNECT PathLength=26 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos53_pathlength.pcap) |
| smb_tpos54_tree_resp_ss | T054: TREE_CONNECT resp StructureSize=16 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos54_tree_resp_ss.pcap) |
| smb_tpos55_sharetype_disk | T055: ShareType DISK=0 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos55_sharetype_disk.pcap) |
| smb_tpos56_sharetype_pipe | T056: ShareType PIPE=1 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos56_sharetype_pipe.pcap) |
| smb_tpos57_sharetype_print | T057: ShareType PRINT=2 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos57_sharetype_print.pcap) |
| smb_tpos58_maximal_access | T058: MaximalAccess=0x001F1FFF | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos58_maximal_access.pcap) |
| smb_tpos60_skip_treeconnect | T060: IncludeTreeConnect=false | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos60_skip_treeconnect.pcap) |
| smb_tpos61_create_file | T061/T063: CREATE 默认打开 file.txt → NameOffset=0x78(120), Name='file.txt' UTF-16LE @242, CreateDisposition=1 (open), resp CreateAction=1 (opened) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos61_create_file.pcap) |
| smb_tpos62_create_cmd | T062: CREATE req Command 0x0005 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos62_create_cmd.pcap) |
| smb_tpos63_create_structsize | T063: CREATE req StructureSize=57 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos63_create_structsize.pcap) |
| smb_tpos65_create_access | T065: CREATE req DesiredAccess | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos65_create_access.pcap) |
| smb_tpos66_create_attr | T066: FileAttributes=0x80 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos66_create_attr.pcap) |
| smb_tpos67_create_shareaccess | T067: ShareAccess=0x07 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos67_create_shareaccess.pcap) |
| smb_tpos68_disposition_open | T068: CreateDisposition=1 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos68_disposition_open.pcap) |
| smb_tpos69_disposition_create | T069: CreateDisposition=2 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos69_disposition_create.pcap) |
| smb_tpos70_create_options | T070: CreateOptions=0 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos70_create_options.pcap) |
| smb_tpos71_nameoffset | T071: NameOffset=120 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos71_nameoffset.pcap) |
| smb_tpos72_namelength | T072: NameLength=16 (file.txt) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos72_namelength.pcap) |
| smb_tpos74_resp_fileid | T074: CREATE resp FileId 非全 0 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos74_resp_fileid.pcap) |
| smb_tpos75_resp_ss | T075: CREATE resp StructureSize=89 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos75_resp_ss.pcap) |
| smb_tpos77_resp_eof | T077: CREATE resp EndOfFile=0 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos77_resp_eof.pcap) |
| smb_tpos78_resp_attr | T078: CREATE resp FileAttributes=0x80 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos78_resp_attr.pcap) |
| smb_tpos7_signing_required | T007/T183/T184/T040: SigningRequired=true → 全部 req Flags=0x08(SIGNED)/resp=0x09, SecurityMode=0x03, Signature 占位非零, 28 包 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos7_signing_required.pcap) |
| smb_tpos80_create_collision | T080: OBJECT_NAME_COLLISION | pass | 23 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos80_create_collision.pcap) |
| smb_tpos81_read_default | T081/T083/T084/T087/T089: READ 默认 4096B → req Length=0x1000, resp DataLength=0x1000, resp 头+1460B 数据在 p17 (MSS 分段), p18-19 纯数据 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos81_read_default.pcap) |
| smb_tpos82_read_cmd | T082: READ req Command 0x0008 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos82_read_cmd.pcap) |
| smb_tpos83_read_structsize | T083: READ req StructureSize=49 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos83_read_structsize.pcap) |
| smb_tpos84_read_length | T084: READ req Length=4096 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos84_read_length.pcap) |
| smb_tpos85_read_offset | T085: READ req Offset=0 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos85_read_offset.pcap) |
| smb_tpos86_read_fileid | T086: READ req FileId | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos86_read_fileid.pcap) |
| smb_tpos89_read_resp_datalen | T089: READ resp DataLength=4096 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos89_read_resp_datalen.pcap) |
| smb_tpos91_write_data | T091/T093/T094/T095/T099: WRITE 10B 数据 → req DataOffset=0x70, Length=10, data 'ABCDEFGHIJ' @帧 170; resp Count=10 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos91_write_data.pcap) |
| smb_tpos92_write_cmd | T092: WRITE req Command 0x0009 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos92_write_cmd.pcap) |
| smb_tpos93_write_structsize | T093: WRITE req StructureSize=49 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos93_write_structsize.pcap) |
| smb_tpos95_write_length | T095: WRITE req Length=10 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos95_write_length.pcap) |
| smb_tpos96_write_offset | T096: WRITE req Offset=0 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos96_write_offset.pcap) |
| smb_tpos97_write_resp_cmd | T097: WRITE resp Command | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos97_write_resp_cmd.pcap) |
| smb_tpos98_write_resp_ss | T098: WRITE resp StructureSize=17 | pass | 27 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos98_write_resp_ss.pcap) |
| smb_tpos_T271_neg_req_structsize | T271: NEGOTIATE req 命令体 StructureSize=0x0024(36) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T271_neg_req_structsize.pcap) |
| smb_tpos_T272_neg_resp_structsize | T272: NEGOTIATE resp 命令体 StructureSize=0x0041(65) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T272_neg_resp_structsize.pcap) |
| smb_tpos_T273_ss_req_structsize | T273: SESSION_SETUP req 命令体 StructureSize=0x0019(25) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T273_ss_req_structsize.pcap) |
| smb_tpos_T274_ss_resp_structsize | T274: SESSION_SETUP resp 命令体 StructureSize=0x0009(9) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T274_ss_resp_structsize.pcap) |
| smb_tpos_T275_tree_req_structsize | T275: TREE_CONNECT req 命令体 StructureSize=0x0009(9) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T275_tree_req_structsize.pcap) |
| smb_tpos_T276_tree_resp_structsize | T276: TREE_CONNECT resp 命令体 StructureSize=0x0010(16) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T276_tree_resp_structsize.pcap) |
| smb_tpos_T277_create_resp_structsize | T277: CREATE resp 命令体 StructureSize=0x0059(89) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T277_create_resp_structsize.pcap) |
| smb_tpos_T278_close_req_structsize | T278: CLOSE req 命令体 StructureSize=0x0018(24) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T278_close_req_structsize.pcap) |
| smb_tpos_T279_close_resp_structsize | T279: CLOSE resp 命令体 StructureSize=0x003C(60) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T279_close_resp_structsize.pcap) |
| smb_tpos_T280_read_req_structsize | T280: READ req 命令体 StructureSize=0x0031(49) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T280_read_req_structsize.pcap) |
| smb_tpos_T284_tree_disc_structsize | T284: TREE_DISCONNECT StructureSize=0x0004(4) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T284_tree_disc_structsize.pcap) |
| smb_tpos_T285_logoff_structsize | T285: LOGOFF StructureSize=0x0004(4) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T285_logoff_structsize.pcap) |
| smb_tpos_T286_protocolid_all_frames | T286: 完整会话所有 SMB2 PDU 偏移 0-3 = FE 53 4D 42 (ProtocolId) @帧4@58 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T286_protocolid_all_frames.pcap) |
| smb_tpos_T287_cmd_sequence | T287: 完整会话 Command 序列 (SMB2 头偏移 12, @帧70) = 0,0,1,1×3对,3,3,5,5,8,8,6,6,4,4,2,2 (NEGOTIATE/SESSION_SETUP×3/TREE_CONNECT/CREATE/READ/CLOSE/TREE_DISC/LOGOFF 请求+响应) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T287_cmd_sequence.pcap) |
| smb_tpos_T288_flags_sequence | T288: 完整会话 Flags 序列 (SMB2 头偏移 16, @帧74): 所有请求 Flags=0, 所有响应 Flags=0x01 (SERVER_TO_REDIR) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T288_flags_sequence.pcap) |
| smb_tpos_T289_msgid_sequence | T289: 完整会话 MessageId 序列 (SMB2 头偏移 24, @帧82) = 0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9 (10 对) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T289_msgid_sequence.pcap) |
| smb_tpos_T290_sessionid_persistent | T290: 会话建立后所有 PDU SessionId 相同 (帧12=TREE_CONNECT req/帧14=CREATE req/帧20=CLOSE req, same_as 断言) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T290_sessionid_persistent.pcap) |
| smb_tpos_T291_treeid_persistent | T291: TREE_CONNECT resp 后所有 PDU TreeId 相同 @帧14@94=01000000 + 帧16@94=同 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T291_treeid_persistent.pcap) |
| smb_tpos_T292_fileid_persistent | T292: CREATE resp 后 READ/CLOSE FileId 相同 (file_id 固定 00112233...) @帧15@186 + 帧16@138 + 帧20@130 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T292_fileid_persistent.pcap) |
| smb_tpos_T293_ntlm_3phase_securityblob | T293: NTLM 三阶段 SecurityBlob 变化 req1=type1 NEGOTIATE @帧6@154=01000000 + resp1=type2 CHALLENGE @帧7@138=02000000 + req2=type3 AUTH @帧8@154=03000000 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T293_ntlm_3phase_securityblob.pcap) |
| smb_tpos_T294_negotiate_ctx_count_ge1 | T294: dialect 0x0311 NEGOTIATE req NegotiateContextCount=2>=1 @帧4@154=0200 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T294_negotiate_ctx_count_ge1.pcap) |
| smb_tpos_T295_0202_no_ctx | T295: 0x0202 NegotiateContext | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T295_0202_no_ctx.pcap) |
| smb_tpos_T297_treeconnect_utf16le | T297: TREE_CONNECT Path 以 UTF-16LE 编码 (\server\share 14 字符 28 字节) @帧12@130=5c005c007300650072007600650072005c0073006800610072006500 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T297_treeconnect_utf16le.pcap) |
| smb_tpos_T298_create_name_utf16le | T298: CREATE Name (file.txt) 以 UTF-16LE 编码 8 字符 16 字节 @帧14@178=660069006c0065002e00740078007400 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T298_create_name_utf16le.pcap) |
| smb_tpos_T299_error_resp_flags | T299: 错误 CREATE 响应仍设 SERVER_TO_REDIR (ErrorOnCommand=create → resp Flags@帧74=01000000) | pass | 23 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T299_error_resp_flags.pcap) |
| smb_tpos_T300_error_resp_cmd | T300: 错误 CREATE 响应 Command 仍为 CREATE (ErrorOnCommand=create → resp Command@帧70=0500) | pass | 23 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T300_error_resp_cmd.pcap) |
| smb_tpos_T301_credit_0202 | T301: dialect=0x0202 NEGOTIATE req CreditCharge=0 (SMB 2.0.2 reserved, MS-SMB2 §2.2.1.2) @帧64=0000 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T301_credit_0202.pcap) |
| smb_tpos_T301_credit_0202_resp | T301: 0x0202 resp CreditCharge | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T301_credit_0202_resp.pcap) |
| smb_tpos_T302_credit_0210 | T302: dialect=0x0210 NEGOTIATE req CreditCharge=1 (SMB2.1+, MS-SMB2 §2.2.1.2) @帧64=0100 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T302_credit_0210.pcap) |
| smb_tpos_T302b_respdialect_0210 | T302b: dialects=[0x0202,0x0210] 协商选中最高 0x0210 → NEGOTIATE resp DialectRevision @帧126=1002 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T302b_respdialect_0210.pcap) |
| smb_tpos_T303_dialect_0300_credit | T303: dialect=0x0300 → CreditCharge=1 @帧4@64=0100 + DialectRevision@158=0003 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T303_dialect_0300_credit.pcap) |
| smb_tpos_T304_credit_0311 | T304: dialect=0x0311 NEGOTIATE req CreditCharge=1 @帧64=0100 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T304_credit_0311.pcap) |
| smb_tpos_T305_client_caps_0 | T305: ClientCapabilities=0 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T305_client_caps_0.pcap) |
| smb_tpos_T305a_resp_credit_0202 | T305a: dialect=0x0202 所有响应 CreditCharge=0 (SMB 2.0.2 响应不消耗信用, MS-SMB2 §2.2.1.2) @帧5/7/13/21/25 @64=0000 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T305a_resp_credit_0202.pcap) |
| smb_tpos_T305b_0202_allresp_credit0 | T305b: 0x0202 完整会话所有 resp CreditCharge=0 @帧5,7,9,11,13,15,19,21,23,25@64=0000 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T305b_0202_allresp_credit0.pcap) |
| smb_tpos_T305c_cap_0202 | T305c: dialect=0x0202 时 ClientCapabilities 降级为 0x00000002 (LEASING, 2.x 无 multi-channel) @帧130=02000000 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T305c_cap_0202.pcap) |
| smb_tpos_T305d_cap_0311 | T305d: dialect=0x0311 时 ClientCapabilities=0x00000003 (DFS\|LEASING) @帧130=03000000 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T305d_cap_0311.pcap) |
| smb_tpos_T306_client_capabilities_03 | T306: ClientCapabilities=0x03 → NEGOTIATE req 命令体偏移 8-11=03000000 @帧4@130 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T306_client_capabilities_03.pcap) |
| smb_tpos_T307_server_caps | T307: resp ServerCapabilities | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T307_server_caps.pcap) |
| smb_tpos_T307_server_caps_03 | T307: ServerCapabilities=0x03 → NEGOTIATE resp 命令体偏移 24-27 @帧5@146=03000000 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T307_server_caps_03.pcap) |
| smb_tpos_T308_respdialect_0311 | T308: dialect=0x0311 → NEGOTIATE resp DialectRevision=0x0311 @帧126=1103 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T308_respdialect_0311.pcap) |
| smb_tpos_T309_respdialect_0202 | T309: dialect=0x0202 → NEGOTIATE resp DialectRevision=0x0202 @帧126=0202 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T309_respdialect_0202.pcap) |
| smb_tpos_T310_ctx_offset_aligned | T310: NegotiateContextOffset 8B 对齐 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T310_ctx_offset_aligned.pcap) |
| smb_tpos_T310_negotiate_ctx_offset_8b_aligned | T310: SMB3.1.1 NegotiateContextOffset 8B 对齐 @帧4@150=68000000 (0x68=104, 104%8=0) | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T310_negotiate_ctx_offset_8b_aligned.pcap) |
| smb_tpos_T311_preauth_salt_length_32 | T311: Preauth SaltLength=32 (0x20) @帧4@172=2000 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T311_preauth_salt_length_32.pcap) |
| smb_tpos_T311_salt_len_32 | T311: Preauth SaltLength=32 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T311_salt_len_32.pcap) |
| smb_tpos_T312_ciphercount | T312: CipherCount=2 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T312_ciphercount.pcap) |
| smb_tpos_T313_no_compression_ctx | T313: Compression ctx 不实现 — 两 ctx 类型分别为 0x0001/0x0002 无 0x0003 @帧4@162=0100 + @帧4@210=0200 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T313_no_compression_ctx.pcap) |
| smb_tpos_T314_0311_must_have_preauth | T314: dialect 0x0311 必须有 Preauth ContextType=0x0001 @帧4@162=0100 | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T314_0311_must_have_preauth.pcap) |
| smb_tpos_T314_0311_preauth_ctx | T314: 0x0311 必有 Preauth ctx | pass | 29 | [pcap](/tmp/mcp-pcaps/smb/smb_tpos_T314_0311_preauth_ctx.pcap) |

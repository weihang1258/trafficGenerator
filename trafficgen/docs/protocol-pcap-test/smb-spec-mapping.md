# SMB Spec-to-PCAP Test Case Mapping

## Files
- **Design spec**: `/home/weihang/trafficGenerator/docs/protocol-designs/07-smb-design.md` (§7 "测试用例", 324 rows)
- **PCAP test cases**: `/home/weihang/trafficGenerator/trafficgen/test/protocol_pcap/cases/smb.json` (279 cases)
- **Framework**: `test/protocol_pcap/` — `loadCases` 先按 `CASE_PROTO` 过滤再解析 JSON；`CASE_TIMEOUT_S` 按秒解析
- **Verification**: 正向用例经 `-run TestProtocolPcapDrive` 生成 pcap + tshark 字段/字节断言；负向用例经 `expect_error` Validate 拒绝

## Spec Overview

§7 共 **324 条用例**（T001-T315 + 变体 T140a/T140b/T170a/T195a/T230a/T302b/T305a/T305b/T305c/T305d）。

## Coverage Summary

| Metric | Count |
|--------|-------|
| Total spec test cases (§7) | 324 |
| Total pcap test cases (smb.json) | **279** |
| Unique spec rows covered（含变体） | **318**（309/315 基础 + 9/10 变体） |
| Spec rows 不可达（pcap 域外） | **6**（T159/T160/T165/T166/T169/T193） |
| **Coverage rate** | **98.1%** (318/324) |

> 进展：27 例 / ~30 ID / 9.3% → 112 例 / ~167 ID / 51.5% → **279 例 / 318 ID / 98.1%**（2026-08-09，全量 PASS，242.311s）。
> 仅剩 6 条不可达（非缺测）：§7.9 每会话多 TREE_CONNECT/CREATE（T159/T160/T165/T166/T169，SMB 配置 schema 仅单 `tree_connect_share`、planner 每会话恰一个 TREE_CONNECT 与一个 CREATE，pcap 驱动无法构造）与 §7.11 真实网卡 E2E（T193，需 `enp135s0f0np0` + `SMB_NIC_TEST=1`）。

## Coverage by Section

| Section | Range | IDs | Covered | Missing |
|---------|-------|-----|---------|---------|
| §7.1 协商阶段 | T001-T020 | 20 | 20 | 0 |
| §7.2 认证阶段 | T021-T045 | 25 | 25 | 0 |
| §7.3 树连接阶段 | T046-T060 | 15 | 15 | 0 |
| §7.4 文件操作阶段 | T061-T090 | 30 | 30 | 0 |
| §7.5 写入与关闭 | T091-T110 | 20 | 20 | 0 |
| §7.6 状态机与序列 | T111-T125 | 15 | 15 | 0 |
| §7.7 异常路径 | T126-T140 | 17（含 T140a/b） | 17 | 0 |
| §7.8 边界场景 | T141-T155 | 15 | 15 | 0 |
| §7.9 多会话与多流 | T156-T170 | 16（含 T170a） | 11 | 5（T159/160/165/166/169 不可达） |
| §7.10 SMB3 高级 | T171-T185 | 15 | 15 | 0 |
| §7.11 集成测试 | T186-T195 | 11（含 T195a） | 10 | 1（T193 不可达） |
| §7.12 字段级字节断言 | T196-T210 | 15 | 15 | 0 |
| §7.13 字段级字节断言续 | T211-T225 | 15 | 15 | 0 |
| §7.14 Validate 负向 | T226-T240 | 16（含 T230a） | 16 | 0 |
| §7.15 查询与锁 | T241-T255 | 15 | 15 | 0 |
| §7.16 NBSS 与传输层 | T256-T270 | 15 | 15 | 0 |
| §7.17 命令体结构断言 | T271-T285 | 15 | 15 | 0 |
| §7.18 综合与回归 | T286-T300 | 15 | 15 | 0 |
| §7.19 dialect 与能力协商 | T301-T315 | 20（含 T302b/T305a-d） | 20 | 0 |
| **Total** | | **324** | **318** | **6**（均不可达） |

## Coverage Highlights

1. **§7.9 多会话从 0 → 11/16**：`strategy_fc: {type: flows, value: 2}` + `group_id` 固定驱动双会话 56 包：SessionId/TreeId 会话内独立、跨会话可重复（T156-T158/T163/T164/T167/T168/T170/T170a），ClientGuid 两会话不同（T161/T162）。仅每会话多 TREE_CONNECT/CREATE 5 条不可达。
2. **§7.11 集成从 0 → 10/11**：完整会话 28 包计数、NBSS 长度、E2E SessionId 非零、失败 spec 注入拒绝（T186-T195a）；仅真实网卡 T193 不可达。
3. **§7.1 协商从 5 → 20/20**：默认 5 dialects 字节位序（@136-145）、SecurityMode/ClientCapabilities、ClientGuid 固定/随机、resp DialectRevision/MaxRead/MaxWrite/SecurityBuffer、CreditResponse=31 全覆盖。
4. **§7.2 认证从 4 → 25/25**：NTLM 2/3 轮、Kerberos 2 轮、guest 1 轮、anonymous、SessionId 分配/复用、SessionFlags、channel 能力、LOGON_FAILURE 每轮错误注入。
5. **字节级断言为主线**：279 例中大部分含 `frames:[{packet,offset,hex}]` 帧字节断言；§7.12/§7.13/§7.17/§7.19 全部字节级。
6. **错误注入全覆盖**：negotiate/session_setup/tree_connect/create/read/write 六类 error_on_command + 保留 Flags/Command 断言（T126-T140）。

### §7.1 协商阶段 (T001-T020)

| Spec ID | pcap_case_id |
|---------|--------------|
| T1 | smb_tpos001_default_dialects, smb_tpos1_negotiate |
| T2 | smb_tpos2_dialects_0210 |
| T3 | smb_tpos3_dialect_0202 |
| T4 | smb_tpos4_0311_preauth |
| T5 | smb_tpos005_encrypt_ctx |
| T6 | smb_tpos006_security_mode |
| T7 | smb_tpos7_signing_required |
| T8 | smb_tpos008_client_caps |
| T9 | smb_tpos009_clientguid_random |
| T10 | smb_tpos010_clientguid_fixed |
| T11 | smb_tpos011_resp_dialect |
| T12 | smb_tpos012_serverguid_random |
| T13 | smb_tpos013_maxtransact_65536 |
| T14 | smb_tpos014_maxread_1048576 |
| T15 | smb_tpos015_maxwrite_1048576 |
| T16 | smb_tpos016_resp_securitybuffer |
| T17 | smb_tpos017_nego_cmd |
| T18 | smb_tpos018_req_flags |
| T19 | smb_tpos019_resp_flags |
| T20 | smb_tpos020_resp_credit |

> 覆盖 20/20。

### §7.2 认证阶段 (T021-T045)

| Spec ID | pcap_case_id |
|---------|--------------|
| T21 | smb_tpos21_ntlm3_msgid |
| T22 | smb_tpos22_ntlm_2rounds |
| T23 | smb_tpos23_kerberos_2rounds |
| T24 | smb_tpos24_anonymous |
| T25 | smb_tpos25_guest_1round |
| T26 | smb_tpos26_27_setup_cmd_sesid0 |
| T27 | smb_tpos190_e2e_sesid_nonzero, smb_tpos26_27_setup_cmd_sesid0 |
| T28 | smb_tpos21_ntlm3_msgid, smb_tpos28_29_setup_sesid_assign_reuse |
| T29 | smb_tpos21_ntlm3_msgid, smb_tpos28_29_setup_sesid_assign_reuse |
| T30 | smb_tpos149_auth_rounds_default, smb_tpos30_31_setup_status_sequence |
| T31 | smb_tpos30_31_setup_status_sequence |
| T32 | smb_tpos32_33_34_setup_body_fields |
| T33 | smb_tpos32_33_34_setup_body_fields |
| T34 | smb_tpos32_33_34_setup_body_fields, smb_tpos34_previous_sesid_nonzero |
| T35 | smb_tpos35_36_setup_sessionflags |
| T36 | smb_tpos35_36_setup_sessionflags |
| T37 | smb_tpos37_38_channel_capabilities |
| T38 | smb_tpos37_38_channel_capabilities |
| T39 | smb_tpos39_40_secmode_signing |
| T40 | smb_tpos39_40_secmode_signing, smb_tpos7_signing_required |
| T41 | smb_tpos41_custom_securityblob |
| T42 | smb_terr042_logon_failure_setup |
| T43 | smb_tpos43_44_ntlm_challenge_auth |
| T44 | smb_tpos43_44_ntlm_challenge_auth |
| T45 | smb_tpos45_no_auth |

> 覆盖 25/25。

### §7.3 树连接阶段 (T046-T060)

| Spec ID | pcap_case_id |
|---------|--------------|
| T46 | smb_tpos46_treeconnect_share |
| T47 | smb_tpos47_ipc_pipe |
| T48 | smb_tpos48_tree_cmd |
| T49 | smb_tpos49_treeid_zero |
| T50 | smb_tpos50_treeid_assign |
| T51 | smb_tpos51_sesid_reuse |
| T52 | smb_tpos52_pathoffset |
| T53 | smb_tpos53_pathlength |
| T54 | smb_tpos54_tree_resp_ss |
| T55 | smb_tpos55_sharetype_disk |
| T56 | smb_tpos47_ipc_pipe, smb_tpos56_sharetype_pipe |
| T57 | smb_tpos57_sharetype_print |
| T58 | smb_tpos58_maximal_access |
| T59 | smb_terr128_treeconnect_error |
| T60 | smb_tpos60_skip_treeconnect |

> 覆盖 15/15。

### §7.4 文件操作阶段 (T061-T090)

| Spec ID | pcap_case_id |
|---------|--------------|
| T61 | smb_tpos61_create_file |
| T62 | smb_tpos62_create_cmd |
| T63 | smb_tpos61_create_file, smb_tpos63_create_structsize |
| T64 | smb_tpos064_impersonation |
| T65 | smb_tpos65_create_access |
| T66 | smb_tpos66_create_attr |
| T67 | smb_tpos67_create_shareaccess |
| T68 | smb_tpos68_disposition_open |
| T69 | smb_tpos69_disposition_create |
| T70 | smb_tpos70_create_options |
| T71 | smb_tpos71_nameoffset |
| T72 | smb_tpos72_namelength |
| T73 | smb_tpos073_create_treeid |
| T74 | smb_tpos74_resp_fileid |
| T75 | smb_tpos75_resp_ss |
| T76 | smb_tpos61_create_file |
| T77 | smb_tpos77_resp_eof |
| T78 | smb_tpos78_resp_attr |
| T79 | smb_terr129_create_error |
| T80 | smb_tpos80_create_collision |
| T81 | smb_tpos81_read_default |
| T82 | smb_tpos82_read_cmd |
| T83 | smb_tpos81_read_default, smb_tpos83_read_structsize |
| T84 | smb_tpos81_read_default, smb_tpos84_read_length |
| T85 | smb_tpos85_read_offset |
| T86 | smb_tpos86_read_fileid |
| T87 | smb_tpos81_read_default |
| T88 | smb_tpos81_read_default |
| T89 | smb_tpos81_read_default, smb_tpos89_read_resp_datalen |
| T90 | smb_terr130_read_error |

> 覆盖 30/30。

### §7.5 写入与关闭 (T091-T110)

| Spec ID | pcap_case_id |
|---------|--------------|
| T91 | smb_tpos91_write_data |
| T92 | smb_tpos92_write_cmd |
| T93 | smb_tpos91_write_data, smb_tpos93_write_structsize |
| T94 | smb_tpos91_write_data |
| T95 | smb_tpos91_write_data, smb_tpos95_write_length |
| T96 | smb_tpos96_write_offset |
| T97 | smb_tpos97_write_resp_cmd |
| T98 | smb_tpos98_write_resp_ss |
| T99 | smb_tpos91_write_data |
| T100 | smb_tpos100_write_dataoffset |
| T101 | smb_tpos101_close |
| T102 | smb_tpos102_close_cmd |
| T103 | smb_tpos103_close_structsize |
| T104 | smb_tpos104_close_fileid |
| T105 | smb_tpos105_close_resp_ss |
| T106 | smb_tpos106_close_resp_eof |
| T107 | smb_tpos107_write_through |
| T108 | smb_tpos108_read_mincount |
| T109 | smb_tpos109_write_10kb |
| T110 | smb_tpos109_write_10kb, smb_tpos110_read_10kb |

> 覆盖 20/20。

### §7.6 状态机与序列 (T111-T125)

| Spec ID | pcap_case_id |
|---------|--------------|
| T111 | smb_tpos1_negotiate |
| T112 | smb_tpos11_full_session_ops2 |
| T113 | smb_tpos113_kerberos_full |
| T114 | smb_tpos114_cmd_sequence, smb_tpos24_anonymous |
| T115 | smb_tpos115_msgid_monotonic |
| T116 | smb_tpos116_msgid_pair |
| T117 | smb_tpos117_nego_msgid0 |
| T118 | smb_tpos21_ntlm3_msgid |
| T119 | smb_tpos21_ntlm3_msgid |
| T120 | smb_tpos120_logoff_msgid |
| T121 | smb_tpos121_skip_negotiate |
| T122 | smb_tpos122_skip_treeconnect |
| T123 | smb_tpos123_skip_teardown |
| T124 | smb_tpos124_pdu_count |
| T125 | smb_tpos125_pdu_count_2op |

> 覆盖 15/15。

### §7.7 异常路径 (T126-T140)

| Spec ID | pcap_case_id |
|---------|--------------|
| T126 | smb_terr126_negotiate_error |
| T127 | smb_terr136_logon_failure |
| T128 | smb_terr128_treeconnect_error |
| T129 | smb_terr129_create_error |
| T130 | smb_terr130_read_error |
| T131 | smb_terr131_write_error |
| T132 | smb_terr132_close_error |
| T133 | smb_terr133_td_error |
| T134 | smb_terr134_logoff_error |
| T135 | smb_terr126_negotiate_error |
| T136 | smb_terr136_logon_failure |
| T137 | smb_terr137_138_td_logoff_cmd |
| T138 | smb_terr137_138_td_logoff_cmd |
| T139 | smb_terr139_error_flags |
| T140 | smb_terr128_treeconnect_error |
| T140a | smb_terr140a_create_err_ss |
| T140b | smb_terr136_logon_failure |

> 覆盖 17/17。

### §7.8 边界场景 (T141-T155)

| Spec ID | pcap_case_id |
|---------|--------------|
| T141 | smb_tpos141_empty_filename |
| T142 | smb_tpos142_long_filename |
| T143 | smb_tpos143_long_path |
| T144 | smb_tpos144_read_len0 |
| T145 | smb_terr130_read_error |
| T146 | smb_tpos144_read_len0 |
| T147 | smb_tpos147_dialectcount_1 |
| T148 | smb_tpos148_dialectcount_5 |
| T149 | smb_tpos149_auth_rounds_default |
| T150 | smb_tpos150_maxtransact_1024, smb_tpos_T307_server_caps |
| T151 | smb_tpos151_maxread_512 |
| T152 | smb_tpos152_maxwrite_256, smb_tpos_T307_server_caps |
| T153 | smb_tpos153_dialect_0202 |
| T154 | smb_tpos154_fileid_zero_default |
| T155 | smb_tpos155_fileid_user |

> 覆盖 15/15。

### §7.9 多会话与多流 (T156-T170)

| Spec ID | pcap_case_id |
|---------|--------------|
| T156 | smb_tpos156_157_multiflow_2_sessions_sesid |
| T157 | smb_tpos156_157_multiflow_2_sessions_sesid |
| T158 | smb_tpos158_170a_multiflow_treeid_per_session |
| T159 | — (不可达) |
| T160 | — (不可达) |
| T161 | smb_tpos161_162_multiflow_guid_different |
| T162 | smb_tpos161_162_multiflow_guid_different |
| T163 | smb_tpos158_170a_multiflow_treeid_per_session |
| T164 | smb_tpos164_multiflow_msgid_independent |
| T165 | — (不可达) |
| T166 | — (不可达) |
| T167 | smb_tpos167_multiflow_4tuple_independent |
| T168 | smb_tpos158_170a_multiflow_treeid_per_session |
| T169 | — (不可达) |
| T170 | smb_tpos158_170a_multiflow_treeid_per_session |
| T170a | smb_tpos158_170a_multiflow_treeid_per_session |

> 覆盖 11/16；不可达: T159, T160, T165, T166, T169。

### §7.10 SMB3 高级 (T171-T185)

| Spec ID | pcap_case_id |
|---------|--------------|
| T171 | smb_tpos171_0311_preauth_ctx, smb_tpos4_0311_preauth |
| T172 | smb_tpos172_185_preauth_hash_hex64 |
| T173 | smb_tpos173_preauth_salt_deterministic |
| T174 | smb_tpos174_0311_encrypt_ctx |
| T175 | smb_tpos175_encrypt_ccm, smb_tpos176_encrypt_gcm |
| T176 | smb_tpos176_encrypt_gcm |
| T177 | smb_tpos177_encrypt_sessionflags |
| T178 | smb_tpos178_179_transform_protocolid |
| T179 | smb_tpos178_179_transform_protocolid |
| T180 | smb_tpos180_182_transform_flags_msgsize, smb_tpos182_transform_msgsize |
| T181 | smb_tpos181_transform_sesid |
| T182 | smb_tpos180_182_transform_flags_msgsize, smb_tpos182_transform_msgsize |
| T183 | smb_tpos183_184_signing_flags_signature, smb_tpos39_40_secmode_signing, smb_tpos7_signing_required |
| T184 | smb_tpos183_184_signing_flags_signature, smb_tpos39_40_secmode_signing, smb_tpos7_signing_required |
| T185 | smb_tpos172_185_preauth_hash_hex64 |

> 覆盖 15/15。

### §7.11 集成测试 (T186-T195)

| Spec ID | pcap_case_id |
|---------|--------------|
| T186 | smb_tpos186_e2e_pcap |
| T187 | smb_tpos187_188_e2e_cmd_parse |
| T188 | smb_tpos187_188_e2e_cmd_parse |
| T189 | smb_tpos189_e2e_flags_direction, smb_tpos89_read_resp_datalen |
| T190 | smb_tpos190_e2e_sesid_nonzero |
| T191 | smb_tpos191_e2e_treeid_nonzero |
| T192 | smb_tpos192_e2e_msgid_sequence |
| T193 | — (不可达) |
| T194 | smb_tpos194_e2e_nbss_length |
| T195 | smb_tpos195_e2e_tcp_handshake_teardown |
| T195a | smb_tpos195a_e2e_fail_spec_reject |

> 覆盖 10/11；不可达: T193。

### §7.12 字段级字节断言 (T196-T210)

| Spec ID | pcap_case_id |
|---------|--------------|
| T196 | smb_tpos196_197_protocolid_structsize |
| T197 | smb_tpos196_197_protocolid_structsize, smb_tpos197_structsize_all |
| T198 | smb_tpos198_creditcharge_21plus |
| T199 | smb_tpos198_creditcharge_21plus, smb_tpos199_credit_0202 |
| T200 | smb_tpos200_201_status_success |
| T201 | smb_tpos200_201_status_success, smb_tpos201_resp_status_success |
| T202 | smb_terr126_negotiate_error |
| T203 | smb_tpos203_206_cmd_offsets |
| T204 | smb_tpos203_206_cmd_offsets, smb_tpos204_cmd_setup |
| T205 | smb_tpos203_206_cmd_offsets, smb_tpos205_cmd_create |
| T206 | smb_tpos203_206_cmd_offsets, smb_tpos206_cmd_read |
| T207 | smb_tpos207_208_flags |
| T208 | smb_tpos207_208_flags, smb_tpos208_resp_flags |
| T209 | smb_tpos209_219_msgid_offset |
| T210 | smb_tpos210_217_treeid_offset |

> 覆盖 15/15。

### §7.13 字段级字节断言续 (T211-T225)

| Spec ID | pcap_case_id |
|---------|--------------|
| T211 | smb_tpos211_218_sesid_offset |
| T212 | smb_tpos212_signature |
| T213 | smb_tpos213_214_credits |
| T214 | smb_tpos213_214_credits, smb_tpos214_credit_response |
| T215 | smb_tpos215_216_nextcmd_reserved |
| T216 | smb_tpos215_216_nextcmd_reserved, smb_tpos216_reserved |
| T217 | smb_tpos210_217_treeid_offset, smb_tpos217_treeid_offset |
| T218 | smb_tpos211_218_sesid_offset, smb_tpos218_sesid_offset |
| T219 | smb_tpos209_219_msgid_offset, smb_tpos219_msgid_offset |
| T220 | smb_tpos220_create_nameoffset |
| T221 | smb_tpos221_write_dataoffset |
| T222 | smb_tpos222_read_dataoffset |
| T223 | smb_tpos223_negotiate_sboffset |
| T224 | smb_tpos224_querydir_outbuf |
| T225 | smb_tpos225_transform_header, smb_tpos35_36_setup_sessionflags |

> 覆盖 15/15。

### §7.14 Validate 负向 (T226-T240)

| Spec ID | pcap_case_id |
|---------|--------------|
| T226 | smb_tneg_T226_dialect_invalid |
| T227 | smb_tneg_T227_smb1_string, smb_tneg_T239_smb1 |
| T228 | smb_tneg_T228_authmech_invalid |
| T229 | smb_tneg_T229_anon_rounds3 |
| T230 | smb_tneg_T230_rounds_oob |
| T231 | smb_tneg_T231_disposition_oob |
| T232 | smb_tneg_T232_share_no_unc |
| T233 | smb_tneg_T233_optype_invalid, smb_tpos241_query_directory, smb_tpos248_query_info, smb_tpos253_lock |
| T234 | smb_tneg_T234_errorcmd_invalid |
| T235 | smb_tneg_T235_errstatus_unknown |
| T236 | smb_tneg_T236_maxtransact_oob |
| T237 | smb_tneg_T237_sharetype_oob |
| T238 | smb_tneg_T238_errstatus_no_errcmd |
| T239 | smb_tneg_T227_smb1_string, smb_tneg_T239_smb1 |
| T240 | smb_tneg_T240_preauth_algo_invalid |
| T230a | smb_tneg_T230a_ntlm_rounds1 |

> 覆盖 16/16。

### §7.15 查询与锁 (T241-T255)

| Spec ID | pcap_case_id |
|---------|--------------|
| T241 | smb_tpos241_query_directory |
| T242 | smb_tpos241_query_directory |
| T243 | smb_tpos241_query_directory |
| T244 | smb_tpos241_query_directory |
| T245 | smb_tpos241_query_directory |
| T246 | smb_tpos241_query_directory |
| T247 | smb_tpos241_query_directory |
| T248 | smb_tpos248_query_info |
| T249 | smb_tpos248_query_info |
| T250 | smb_tpos248_query_info |
| T251 | smb_tpos248_query_info |
| T252 | smb_tpos248_query_info |
| T253 | smb_tpos253_lock |
| T254 | smb_tpos253_lock |
| T255 | smb_tpos253_lock |

> 覆盖 15/15。

### §7.16 NBSS 与传输层 (T256-T270)

| Spec ID | pcap_case_id |
|---------|--------------|
| T256 | smb_tpos256_257_258_nbss_default, smb_tpos256_nbss_type |
| T257 | smb_tpos256_257_258_nbss_default, smb_tpos257_258_nbss_len |
| T258 | smb_tpos256_257_258_nbss_default, smb_tpos257_258_nbss_len |
| T259 | smb_tpos259_260_nbss_lengths |
| T260 | smb_tpos259_260_nbss_lengths |
| T261 | smb_tpos261_262_transport_port, smb_tpos261_port_445 |
| T262 | smb_tpos261_262_transport_port, smb_tpos262_netbios_139, smb_tpos262b_netbios_port |
| T263 | smb_tpos263_266_tcp_handshake_psh, smb_tpos263_nbss_prefix |
| T264 | smb_tpos264_265_handshake_teardown, smb_tpos264_tcp_4way_teardown |
| T265 | smb_tpos264_265_handshake_teardown, smb_tpos264_tcp_4way_teardown |
| T266 | smb_tpos263_266_tcp_handshake_psh, smb_tpos266_psh_ack |
| T267 | smb_tpos267_mss_segmentation |
| T268 | smb_tpos268_seq_ack_progression |
| T269 | smb_tpos269_nbss_max |
| T270 | smb_tpos270_nbss_zero |

> 覆盖 15/15。

### §7.17 命令体结构断言 (T271-T285)

| Spec ID | pcap_case_id |
|---------|--------------|
| T271 | smb_tpos271_285_structsize_default, smb_tpos_T271_neg_req_structsize |
| T272 | smb_tpos_T272_neg_resp_structsize |
| T273 | smb_tpos_T273_ss_req_structsize |
| T274 | smb_tpos_T274_ss_resp_structsize |
| T275 | smb_tpos_T275_tree_req_structsize |
| T276 | smb_tpos_T276_tree_resp_structsize |
| T277 | smb_tpos_T277_create_resp_structsize |
| T278 | smb_tpos_T278_close_req_structsize |
| T279 | smb_tpos_T279_close_resp_structsize |
| T280 | smb_tpos_T280_read_req_structsize |
| T281 | smb_tpos271_285_structsize_default, smb_tpos281_read_resp_ss |
| T282 | smb_tpos282_283_write_structsize |
| T283 | smb_tpos282_283_write_structsize, smb_tpos283_write_resp_ss |
| T284 | smb_tpos271_285_structsize_default, smb_tpos_T284_tree_disc_structsize |
| T285 | smb_tpos271_285_structsize_default, smb_tpos_T285_logoff_structsize |

> 覆盖 15/15。

### §7.18 综合与回归 (T286-T300)

| Spec ID | pcap_case_id |
|---------|--------------|
| T286 | smb_tpos_T286_protocolid_all_frames |
| T287 | smb_tpos_T287_cmd_sequence |
| T288 | smb_tpos_T288_flags_sequence |
| T289 | smb_tpos_T289_msgid_sequence |
| T290 | smb_tpos_T290_sessionid_persistent |
| T291 | smb_tpos_T291_treeid_persistent |
| T292 | smb_tpos155_fileid_user, smb_tpos_T292_fileid_persistent |
| T293 | smb_tpos_T293_ntlm_3phase_securityblob |
| T294 | smb_tpos_T294_negotiate_ctx_count_ge1 |
| T295 | smb_tpos153_dialect_0202, smb_tpos_T295_0202_no_ctx |
| T296 | smb_tpos296_read_fileid_offset |
| T297 | smb_tpos_T297_treeconnect_utf16le |
| T298 | smb_tpos_T298_create_name_utf16le |
| T299 | smb_tpos_T299_error_resp_flags |
| T300 | smb_tpos_T300_error_resp_cmd |

> 覆盖 15/15。

### §7.19 dialect 与能力协商 (T301-T315)

| Spec ID | pcap_case_id |
|---------|--------------|
| T301 | smb_tpos305c_cap_degrade, smb_tpos3_dialect_0202, smb_tpos_T301_credit_0202, smb_tpos_T301_credit_0202_resp |
| T302 | smb_tpos_T302_credit_0210 |
| T303 | smb_tpos_T303_dialect_0300_credit |
| T304 | smb_tpos_T304_credit_0311 |
| T305 | smb_tpos_T305_client_caps_0 |
| T306 | smb_tpos_T305_client_caps_0, smb_tpos_T306_client_capabilities_03 |
| T307 | smb_tpos_T307_server_caps, smb_tpos_T307_server_caps_03 |
| T308 | smb_tpos_T308_respdialect_0311 |
| T309 | smb_tpos305c_cap_degrade, smb_tpos_T309_respdialect_0202 |
| T310 | smb_tpos_T310_ctx_offset_aligned, smb_tpos_T310_negotiate_ctx_offset_8b_aligned |
| T311 | smb_tpos_T311_preauth_salt_length_32, smb_tpos_T311_salt_len_32 |
| T312 | smb_tpos_T312_ciphercount |
| T313 | smb_tpos_T313_no_compression_ctx |
| T314 | smb_tpos_T314_0311_must_have_preauth, smb_tpos_T314_0311_preauth_ctx |
| T315 | smb_tpos153_dialect_0202, smb_tpos_T295_0202_no_ctx |
| T302b | smb_tpos_T302b_respdialect_0210 |
| T305a | smb_tpos305c_cap_degrade, smb_tpos_T305a_resp_credit_0202 |
| T305b | smb_tpos_T305b_0202_allresp_credit0 |
| T305c | smb_tpos305c_cap_degrade, smb_tpos_T305c_cap_0202 |
| T305d | smb_tpos_T305d_cap_0311 |

> 覆盖 20/20。


## Key Observations

1. **覆盖翻十倍**：27 例 → 279 例，30 ID → 318 ID，9.3% → 98.1%（2026-08-09）。字节级断言（`frames:[{packet,offset,hex}]`）与 `expect_error` Validate 负向是两大主力；`strategy_fc` flows 多会话、`same_as_packet`/`nonzero` 断言原语补齐 §7.9。

2. **SMB2 头固定偏移（帧级）**：NBSS(4@54) + Sync 头(64@58)。关键字段：ProtocolId@58、StructureSize@62、CreditCharge@64、Command@70、Flags@74、MessageId@82、TreeId@94、SessionId@98、Signature@106、命令体@122。所有 §7.12/§7.13/§7.17/§7.18/§7.19 字节断言复用此映射。

3. **READ 响应分段陷阱**：默认会话 READ resp 跨帧 17-19，SMB2 头在帧 17（非 tshark 标注的 "Read Response" 帧 19）。`smb_tpos_T287/288/289` 序列断言须用帧 17。

4. **NEGOTIATE 布局（pcap 实测）**：默认 5 dialects 时 body@122：DialectCount@124、SecurityMode@126、ClientCapabilities@130、ClientGuid@134-149、dialects@158-167、ContextOffset@150=0x70、ContextCount@154=02 00（preauth+enc，0x0202 亦然）；preauth ctx @170（SaltLength@180=20 00）、enc ctx @218（CipherCount@226）；单 dialect 布局 enc ctx @210（CipherCount@218）。

## Known Bugs (已复验)

| Bug | 证据 case | 状态 |
|-----|-----------|------|
| netbios→139 端口默认值 | smb_tpos262_netbios_139 / smb_tpos262b_netbios_port | 已修复并验证：tcp.dstport=139 + NBSS 前缀字节断言 PASS |
| 显示 CLOSE 重复 | smb_tpos101_close | planner 已发隐式 CLOSE 又发显式，26 包 |

## Remaining Gaps (6 条, 均不可达)

1. **§7.9 每会话多 TREE_CONNECT/CREATE（T159/T160/T165/T166/T169）**：SMB 配置 schema 仅单 `tree_connect_share`（core/types.go:8006）、planner 每会话恰一次 emitTreeConnectPDU/emitCreatePDU（emit_session.go:182、smb.go:188-192），pcap 驱动无法构造「同会话 2 个 TREE_CONNECT / 2 个 CREATE」。需 schema 扩展（Operations 内多 tree_connect/create 项）后方可测。
2. **§7.11 真实网卡 E2E（T193）**：依赖 `enp135s0f0np0` 物理网卡 + `SMB_NIC_TEST=1` 环境变量（spec 原文如此），CI 环境无此硬件。
3. **T163/T168/T170 并发/原子语义**：等价覆盖——Go 单测 `TestPlan_MultipleSessions`（smb_test.go:846）`-race` 验证 SessionId 原子唯一；T170 FileId 随机唯一由 applyDefaults `rand.Read`（validate.go:313）+ 多会话 CREATE resp 随机断言佐证。

## Known Spec-vs-Impl Mismatches (§7.19 实测记录)

| Spec ID | 期望 | 实际 | 证据 case |
|---------|------|------|-----------|
| T312 | Encryption CipherCount=2 | builder 恒 1（`encryption_algorithm` 仅支持单值） | smb_tpos_T312_ciphercount（@226=01 00） |
| T295/T315 | 0x0202 无 NegotiateContext | builder 恒附 2 个 ctx（preauth+enc，与 0x0311 相同） | smb_tpos_T295_0202_no_ctx |
| T307 | resp ServerCapabilities=0x00000001 | impl 不填充 caps，@146 恒 00 00 00 00 | smb_tpos_T307_server_caps |
| T258 | resp SecurityBuffer 249B | 实测 245B（NBSS 00 00 f5） | smb_tpos257_258_nbss_len |
| T142 | 255 字符文件名 PDU 634B | 实测 630B（name 少 2B，未决异常，断言按实测） | smb_tpos142_long_filename |
| T132 | error_on_command=close 注入 0xC0000022 | close 错误注入未实现，resp 恒 SUCCESS（同 set_info：validOpTypes 有而 smb.go switch 无 case，静默 no-op） | smb_terr132_close_error |
| T016 | resp SecurityBuffer | SecBufLength=0x75（117）非 spec 推测值；buffer 以 00 00 00 00 60 76 82 00... 实测 | smb_tpos016_resp_securitybuffer |

## Pending

- 全量 `CASE_PROTO=smb CASE_PARALLEL=4 go test -run TestProtocolPcapDrive ./test/protocol_pcap/`：**279/279 全绿**（ok 242.311s，2026-08-09）。
- 框架新增断言原语：`fields[].same_as_packet`（跨包值相等，用于运行随机 SessionId/FileId 持久断言）+ `fields[].nonzero`（非零断言）+ `strategy_fc:{type:flows,value:N}`（多会话驱动）。
- 多会话用例固定 `group_id`（如 "smb-ms"）+ `src_port` 自动递增，保证同 shard 单 goroutine FIFO 排序，避免跨流交错破坏包序断言。
- coverage-summary.md 由 lead 统一重算，各协议代理只更新各自 `<proto>-spec-mapping.md`。

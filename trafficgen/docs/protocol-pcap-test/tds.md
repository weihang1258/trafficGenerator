# tds Pcap Test Results

Cases: 131 — pass 131, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| tds_attention | T-161/162: Attention 包 Type=0x06 Length=8 无 body + DONE_ATTN → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_attention.pcap) |
| tds_attention_idle_confirm | T-168: 无活动请求时 Attention — 服务器仍回 DONE_ATTN (0x20) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_attention_idle_confirm.pcap) |
| tds_attention_pktid_increment | T-167: Attention PacketID = 当前包 PacketID + 1 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_attention_pktid_increment.pcap) |
| tds_done_rowcount_2g | T-208: RowCount=2147483647 (2^31-1) 8B LE | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_done_rowcount_2g.pcap) |
| tds_done_rowcount_4gb | T-209: RowCount=2^32-1 → 8B 0xFFFFFFFF | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_done_rowcount_4gb.pcap) |
| tds_done_rowcount_5e9 | T-208: DONE_COUNT RowCount=5e9 → 8B LE 00 F2 05 2A 01 00 00 00 (0x12A05F200) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_done_rowcount_5e9.pcap) |
| tds_inject_error_class13_deadlock | T-145: Class=13 死锁错误 → ERROR(Number1205, Class13) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_inject_error_class13_deadlock.pcap) |
| tds_inject_error_class14 | T-144: Class=14 权限错误 → ERROR(Number229, Class14), 5 类兼容级别 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_inject_error_class14.pcap) |
| tds_inject_error_continue | T-149: 错误后继续批 — 语句1 ERROR+DONE_ERROR, 语句2 SELECT 正常 DONE_COUNT(RowCount=1) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_inject_error_continue.pcap) |
| tds_inject_error_split | T-148: 错误消息超 packet_size(512) → 响应分包 3 个 TDS 包 (pkt9/10/11) | pass | 17 | [pcap](/tmp/mcp-pcaps/tds/tds_inject_error_split.pcap) |
| tds_inject_error_syntax | T-136/137/138/140/141/142/143/146: 语法错误 'SELECT FROM' → ERROR(Class15, Len0x48, Number102, State1) + DONE_ERROR, ERROR 在 DONE 前 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_inject_error_syntax.pcap) |
| tds_inject_error_tds71 | T-139: TDS 7.1 下 ERROR LineNumber 2B USHORT | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_inject_error_tds71.pcap) |
| tds_inject_info_class10 | T-157: INFO Class=10 兼容转换为 0 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_inject_info_class10.pcap) |
| tds_inject_info_loginack_order | T-160: 登录响应 INFO 在 LOGINACK 前 (5701/5703 → AD) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_inject_info_loginack_order.pcap) |
| tds_inject_info_usemaster | T-151/152/153/156/158/159: USE master → INFO(5701, Class0, State2) + ServerName/ProcName B_VARCHAR + DONE 正常 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_inject_info_usemaster.pcap) |
| tds_inject_infocoexist | T-155: INFO 与 ERROR 共存 — INFO 5701 先发, ERROR 102 后发, DONE_ERROR 收尾 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_inject_infocoexist.pcap) |
| tds_inject_login_fail | T-147: 登录失败 → ERROR(Number18456, Class14) + DONE_ERROR 后连接关闭, 会话全跳过 (9 包) | pass | 11 | [pcap](/tmp/mcp-pcaps/tds/tds_inject_login_fail.pcap) |
| tds_integration_full_flow | T-215: 端到端集成 — PRELOGIN(0x12)→LOGIN7(0x10,TDSVersion 04 00 00 74)→SQL Batch(0x01)→响应(0x04) (INT-01/02) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_integration_full_flow.pcap) |
| tds_login7_client_lcid | T-024 扩展: client_lcid=0x0409 → LOGIN7 Collation 字段 4B LE | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_login7_client_lcid.pcap) |
| tds_login7_custom | T-023/T-028/T-029: HostName/Database/ClientID MAC 自定义 → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_login7_custom.pcap) |
| tds_login7_database_language | T-028/T-030 扩展: database+language 字段 → ibDB/ibLang 偏移表与 Data 区 UCS-2 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_login7_database_language.pcap) |
| tds_login7_db_only_default_user | T-024 扩展: database 显式 user 缺省 'sa' — ibDatabase 项 + Data | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_login7_db_only_default_user.pcap) |
| tds_login7_default | T-016/T-024/T-025/T-027/T-030: 默认 LOGIN7 (TDS 7.4, sa/password, ODBC, trafficgen) → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_login7_default.pcap) |
| tds_login7_empty_password | T-026: Password 空串 → cchPassword=0, ibPassword 指向 Data 区 → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_login7_empty_password.pcap) |
| tds_login7_feature_ext | T-039: TDS 7.4 + FeatureExt SESSIONRECOVERY (id=0x01) → LOGIN7 含 FeatureExt 选项 → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_login7_feature_ext.pcap) |
| tds_login7_optionflags1 | T-031: OptionFlags1=0xE0 位解析 (fDumpLoad\|fUseDB\|fDatabase\|fSetLang) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_login7_optionflags1.pcap) |
| tds_login7_password_obfuscate | T-025: 密码混淆算法 — 'password' 每字节高4位↔低4位互换再 XOR 0xA5 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_login7_password_obfuscate.pcap) |
| tds_login7_tds71 | T-017: TDS 7.1 版本 → LOGIN7 TDSVersion wire `71 00 00 00` → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_login7_tds71.pcap) |
| tds_login7_tds72 | T-018: TDS 7.2 版本 → LOGIN7 TDSVersion wire `02 00 09 72` (BE), LOGINACK 0x72090002 → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_login7_tds72.pcap) |
| tds_login7_tds73a | T-019: TDS 7.3A 版本 → LOGIN7 TDSVersion wire `03 00 0a 73` (BE), LOGINACK 0x730a0003 → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_login7_tds73a.pcap) |
| tds_login7_typeflags | T-032: TypeFlags=0x01 (fSQLType=TSQL) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_login7_typeflags.pcap) |
| tds_login_info_tokens | T-151/T-154: 登录响应含 INFO 5701/5703 → Class=0, 多条收集 → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_login_info_tokens.pcap) |
| tds_mars_2sessions | T-186/192: MARS 2 会话各 1 SQL → OutstandingRequestCount=2, 共享 SPID → 13 包 | pass | 15 | [pcap](/tmp/mcp-pcaps/tds/tds_mars_2sessions.pcap) |
| tds_mars_3sessions | T-192: 3 会话 → OutstandingRequestCount=3 (MARS 活动请求计数) | pass | 17 | [pcap](/tmp/mcp-pcaps/tds/tds_mars_3sessions.pcap) |
| tds_mars_3sessions_err_isolate | T-190: 会话 A 报错仅 A 收 ERROR — B 的 DONE 正常 (0x10 RowCount=1) | pass | 15 | [pcap](/tmp/mcp-pcaps/tds/tds_mars_3sessions_err_isolate.pcap) |
| tds_mars_3sessions_multi_done | T-189: 会话内 3 语句 → 2 个 DONE_MORE + 1 个 DONE_FINAL | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_mars_3sessions_multi_done.pcap) |
| tds_mars_3sessions_txn_indep | T-193/T-194: MARS 3 会话各自 TransactionDescriptor (A=5, B=7, C=0) | pass | 21 | [pcap](/tmp/mcp-pcaps/tds/tds_mars_3sessions_txn_indep.pcap) |
| tds_mars_attention_cancel | T-191: MARS 会话 A 定向 Attention → 仅 A 的 DONE_ATTN (0x20) | pass | 17 | [pcap](/tmp/mcp-pcaps/tds/tds_mars_attention_cancel.pcap) |
| tds_mars_two_sessions_interleave | T-216: MARS 2 会话字节流交错 — A 请求→B 请求→响应按会话归并 | pass | 15 | [pcap](/tmp/mcp-pcaps/tds/tds_mars_two_sessions_interleave.pcap) |
| tds_mars_txn_isolation | T-217: MARS 事务隔离 — 会话 A 事务中(TransactionID=5) vs B(0) → ALL_HEADERS.TransactionDescriptor 独立 | pass | 17 | [pcap](/tmp/mcp-pcaps/tds/tds_mars_txn_isolation.pcap) |
| tds_prelogin_encrypt_notsup | T-008: ENCRYPTION=0x02 (not_sup) → 服务器回 ENCRYPT_NOT_SUP (0x02) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_prelogin_encrypt_notsup.pcap) |
| tds_prelogin_encrypt_on | T-005: encrypt_mode=1 → PRELOGIN ENCRYPTION 数据=0x01 (ENCRYPT_ON)，11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_prelogin_encrypt_on.pcap) |
| tds_prelogin_encrypt_required | T-007: ENCRYPTION=0x03 (req) → 服务器回 ENCRYPT_ON (0x01) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_prelogin_encrypt_required.pcap) |
| tds_prelogin_mars_off | T-013: MARS=0x00 (关闭) — PRELOGIN MARS 选项值字节 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_prelogin_mars_off.pcap) |
| tds_prelogin_versions | T-001/T-011/T-012: PRELOGIN VERSION+THREADID+MARS+TERMINATOR 协商 → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_prelogin_versions.pcap) |
| tds_rpc_batch_two_procs | T-202: 单会话 2 个 RPC → 各自 RPC 请求/响应 (DONEPROC) 隔离 → 每 RPC 独立结果 | pass | 15 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_batch_two_procs.pcap) |
| tds_rpc_longname | T-097/T-116: RPC 存储过程长名 'foo3' (US_VARCHAR) → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_longname.pcap) |
| tds_rpc_param_bigint_max | T-112: RPC 参数 BIGINT 值 2^63-1 → 8B LE FF FF FF FF FF FF FF 7F → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_bigint_max.pcap) |
| tds_rpc_param_bigint_null | T-210 扩展: bigint NULL → 8B 全 0 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_bigint_null.pcap) |
| tds_rpc_param_bignvarchar | T-110 扩展: nvarchar(max) 非 NULL → PLP 编码 UCS-2 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_bignvarchar.pcap) |
| tds_rpc_param_bit_null | T-111: BIT 参数 NULL — TYPE_INFO 0x32 + 0x00 (差异: spec 期望 BITNTYPE 0x68) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_bit_null.pcap) |
| tds_rpc_param_byref | T-108: RPC 参数 fByRefValue=1 (OUTPUT) → StatusFlags=0x01 → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_byref.pcap) |
| tds_rpc_param_decimal | T-080 扩展: decimal(10,2) 参数 → DECIMALNTYPE 0x6C + 4B 类型信息 + BYTELEN 值 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_decimal.pcap) |
| tds_rpc_param_defaultvalue | T-107: RPC 参数 fDefaultValue=1 → StatusFlags=0x02 + int 值 0 → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_defaultvalue.pcap) |
| tds_rpc_param_empty_default | T-118: 空参数名 + fDefaultValue → `00 02` StatusFlags 位解析 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_empty_default.pcap) |
| tds_rpc_param_empty_name | T-106: RPC 参数名为空 → B_VARCHAR len=0 (00) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_empty_name.pcap) |
| tds_rpc_param_int4_null | T-210: INT4 NULL 参数 → 4B 全 0 → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_int4_null.pcap) |
| tds_rpc_param_plp_chunking | T-206: PLP chunk ≤4096 — 9000B varchar(max) → 3 chunks (4096+4096+808) | pass | 19 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_plp_chunking.pcap) |
| tds_rpc_param_tinyint | T-109 变体: TINYINT 参数 → TypeInt1 0x34 + 1B 值 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_tinyint.pcap) |
| tds_rpc_param_uniqueidentifier | T-114: RPC 参数 UNIQUEIDENTIFIER → 24 + 10 + 16B GUID → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_uniqueidentifier.pcap) |
| tds_rpc_param_varbinary | T-099 扩展: varbinary 参数 → TypeBigVarBin 0xA5 + maxlen + 2B len + 原始字节 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_varbinary.pcap) |
| tds_rpc_param_varbinary_null | T-211 扩展: varbinary NULL → 2B 0xFFFF (CHARBIN_NULL) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_varbinary_null.pcap) |
| tds_rpc_param_varchar_max | T-203: varchar(max) 参数 → TYPE_INFO A7+FF FF+Collation → PLP body → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_varchar_max.pcap) |
| tds_rpc_param_varchar_max_multichunk | T-204/T-206: varchar(max) 4112B 值 → PLP 已知长度 8B(0x1010) + 2 chunk(4096+16) 分块 ≤4096 → 多段 | pass | 16 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_varchar_max_multichunk.pcap) |
| tds_rpc_param_varchar_max_null | T-212: varchar(max) NULL → PLP_NULL 8B 0xFF×8 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_varchar_max_null.pcap) |
| tds_rpc_param_varchar_null | T-211: varchar NULL 参数 → 2B 0xFFFF (CHARBIN_NULL) → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_varchar_null.pcap) |
| tds_rpc_param_xml_json_udt | T-219: RPC 参数 xml/json/udt → TYPE_INFO 0xF1/0xF4/0xF0 + PLP 编码 (COV-09) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_param_xml_json_udt.pcap) |
| tds_rpc_params | T-098/099/105/109/110: RPC sp_executesql 带 @stmt varchar 参数 + int 参数 → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_params.pcap) |
| tds_rpc_procid_short | T-096/T-100/T-102/103/104: RPC sp_executesql ProcID=10 短形式 (FF FF 0A 00) 无参数 → DONEINPROC+RETURNSTATUS+DONEPROC → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_procid_short.pcap) |
| tds_rpc_returnvalue_unreachable | T-122: RETURNVALUE 输出参数 — buildRPCResponse 固定 DONEINPROC+RETURNSTATUS+DONEPROC | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_rpc_returnvalue_unreachable.pcap) |
| tds_sql_begin_then_commit | T-173/T-178 变体: SQL BEGIN TRAN → 请求 TransactionDescriptor=0 但 ENVCHANGE 8 合成 | pass | 15 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_begin_then_commit.pcap) |
| tds_sql_colname_unicode | T-050: 列名含中文 '数据' — COLMETADATA ColName UCS-2 4B | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_colname_unicode.pcap) |
| tds_sql_column_metadata_two_groups | T-085: 组间 COLMETADATA 独立 — 2 语句各 1 列 (INT4 'c') | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_column_metadata_two_groups.pcap) |
| tds_sql_curcmd_transparent | T-061: CurCmd 任意值 (0xC1) 透传 — DONE CurCmd 字段 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_curcmd_transparent.pcap) |
| tds_sql_curcmd_transparent_v2 | T-061 变体: CurCmd=0x0000 请求透传 — DONE CurCmd 固定 0x0000 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_curcmd_transparent_v2.pcap) |
| tds_sql_dml_declare | T-071: DECLARE 无结果集仅 DONE | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_dml_declare.pcap) |
| tds_sql_dml_delete_2to40 | T-068: DELETE 影响 2^40 行 → 8B RowCount | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_dml_delete_2to40.pcap) |
| tds_sql_dml_expect_rows_0_final | T-067: DML expect_rows=0 — DONE 0x10 RowCount=0 (有效 0) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_dml_expect_rows_0_final.pcap) |
| tds_sql_dml_insert_zero | T-067: INSERT 0 行 → DONE_COUNT RowCount=0 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_dml_insert_zero.pcap) |
| tds_sql_dml_update | T-066: UPDATE 影响 5 行 → DONE_COUNT RowCount=5 (无结果集) → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_dml_update.pcap) |
| tds_sql_dml_update_then_select | T-070: DML 后跟 SELECT — 首 DONE 带 DONE_MORE (0x11) 次 DONE 0x10 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_dml_update_then_select.pcap) |
| tds_sql_empty_result_set | T-048: 空结果集 SELECT — 无 ROW 仅 COLMETADATA + DONE | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_empty_result_set.pcap) |
| tds_sql_error_batch_continue | T-073: 批中一条失败后续继续 — 失败 0x12 后续 0x10 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_error_batch_continue.pcap) |
| tds_sql_error_class13_deadlock | T-145: Class=13 死锁 — ERROR Class=13 + DONE 0x12 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_error_class13_deadlock.pcap) |
| tds_sql_error_class14_perm | T-144: Class=14 权限错误 — ERROR Class=14 + DONE 0x12 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_error_class14_perm.pcap) |
| tds_sql_error_class20 | T-074: ERROR Class=20 严重错误 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_error_class20.pcap) |
| tds_sql_error_class20_srverror | T-074: Class=20 严重错误 → DONE_SRVERROR (0x100) 结果集丢弃 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_error_class20_srverror.pcap) |
| tds_sql_error_num_reserved | T-146: 错误号 < 20001 保留范围 — ERROR number=19999 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_error_num_reserved.pcap) |
| tds_sql_error_unique_constraint | T-072: 唯一约束失败 ERROR(16) + DONE_ERROR | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_error_unique_constraint.pcap) |
| tds_sql_multi | T-081/082/083/084: SQL 'SELECT 1; SELECT 2; SELECT 3' → 3 结果集, 前 2 DONE_MORE → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_multi.pcap) |
| tds_sql_multi_error_isolation | T-086: 中间语句报错, 组 3 仍正常返回 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_multi_error_isolation.pcap) |
| tds_sql_multi_no_semicolon | T-087: 批语句间无分号仍按批解析 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_multi_no_semicolon.pcap) |
| tds_sql_multi_semicolon_empty | T-051: SQL 含空语句 'select 1;;select 2' — 不额外生成 DONE | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_multi_semicolon_empty.pcap) |
| tds_sql_result_set_isolation | T-091: DONE 后列上下文重置 — 组2 ROW 前无 COLMETADATA 时 tshark 解析 (包 9) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_result_set_isolation.pcap) |
| tds_sql_select | T-041/042/043/044/045/046: SQL Batch SELECT 'foo' as 'bar' → ALL_HEADERS + UCS-2 SQLText + COLMETADATA/ROW/DONE → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_select.pcap) |
| tds_sql_select_tds71 | T-047: TDS 7.1 下 SQL Batch SELECT → DONE RowCount 4B (非 8B) → 11 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_select_tds71.pcap) |
| tds_sql_select_two_groups | T-081/082: 两个 SELECT 语句 → 2 组 COLMETADATA+ROW+DONE (首 DONE 带 DONE_MORE) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_select_two_groups.pcap) |
| tds_sql_tabname_colinfo_unreachable | T-090: 浏览模式 TABNAME/COLINFO — 实现不合成 → 记录不可配置 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_tabname_colinfo_unreachable.pcap) |
| tds_sql_txn_begin_done_inxact | T-075: 事务中 DML → DONE_INXACT(0x04) 位 (spec 定义; SQL Server 不置位) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_sql_txn_begin_done_inxact.pcap) |
| tds_transmgr_begin_commit | T-171/174: TransMgr BEGIN(5)+COMMIT(7) → ENVCHANGE Type 8/9 + DONE → 13 包 | pass | 15 | [pcap](/tmp/mcp-pcaps/tds/tds_transmgr_begin_commit.pcap) |
| tds_transmgr_begin_payload | T-181: TM_BEGIN_XACT(5) ISOLATION_LEVEL=0x02 + payload 字节可观测 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_transmgr_begin_payload.pcap) |
| tds_transmgr_commit_payload_chain | T-182: TM_COMMIT_XACT(7) fBeginXact=1 连锁 — COMMIT 后开新事务 | pass | 17 | [pcap](/tmp/mcp-pcaps/tds/tds_transmgr_commit_payload_chain.pcap) |
| tds_transmgr_promote | T-184: TM_PROMOTE_XACT(6) → 仅 DONE 无 ENVCHANGE (planner 未合成 ENVCHANGE 15) | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_transmgr_promote.pcap) |
| tds_transmgr_rollback | T-175: ROLLBACK → ENVCHANGE Type 10 同构 | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_transmgr_rollback.pcap) |
| tds_transmgr_savepoint | T-180: SAVE TRAN (request_type=9) — 无 ENVCHANGE 仅 DONE | pass | 13 | [pcap](/tmp/mcp-pcaps/tds/tds_transmgr_savepoint.pcap) |
| tds_validate_bad_type | V-TDS-005: type 非法 ('bogus') → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_empty_sql | T-076: Validate 负向 — 空 SQL 文本 → 应报错 (V-TDS-020 空批拒绝) | pass | 0 | [pcap]() |
| tds_validate_error_class | V-TDS-060: ERROR 注入 class=5 < 11 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_feature_7_3 | V-TDS-015: FeatureExt 非 7.4 版本 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_feature_ack_hex | V-TDS-018: FeatureExt ack_data 非 hex → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_feature_data_hex | V-TDS-017: FeatureExt data 非 hex → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_feature_unknown_id | V-TDS-016: FeatureId=0x77 未知 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_info_class | V-TDS-061: INFO 注入 class=15 > 10 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_login_field_len | V-TDS-008: UserName 129 字符 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_login_too_long | T-021: Validate 负向 — LOGIN7 Length > 128K-1 (MaxLoginLen) → 应报错 (V-TDS-007 字段超长) | pass | 0 | [pcap]() |
| tds_validate_mars_prereq | T-195: Validate 负向 — 多会话未协商 MARS → 应报错 (V-TDS-038 前置条件) | pass | 0 | [pcap]() |
| tds_validate_missing_sql | V-TDS-006: type=sql_batch 但 sql 缺失 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_no_requests | V-TDS-004: requests 为空 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_no_sessions | V-TDS-003: sessions 为空 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_packet_size | V-TDS-002: packet_size=128 超下限 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_param_maxlen | V-TDS-026: varchar max_len=9000 非 max → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_param_precision | V-TDS-027: decimal precision=40 > 38 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_param_scale | V-TDS-028: decimal scale=20 > precision=10 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_param_type | V-TDS-025: 参数类型 'datetime' 不在白名单 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_procid_too_big | V-TDS-023: ProcId=20 > 15 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_procname_and_id | V-TDS-024: ProcName 与 ProcId 同时指定 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_procname_too_long | T-117: Validate 负向 — RPC ProcName > MaxProcNameBytes (1046) → 应报错 (V-TDS-022) | pass | 0 | [pcap]() |
| tds_validate_save_payload | V-TDS-035: TM_SAVE_XACT (9) payload 空 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_transmgr_type | V-TDS-034: trans_mgr request_type=99 未知 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_txn_no_begin | V-TDS-036: transaction_id=5 但无 BEGIN 前置 → 拒绝 | pass | 0 | [pcap]() |
| tds_validate_version | V-TDS-001: version 非法 (0x12345678) → 拒绝 | pass | 0 | [pcap]() |

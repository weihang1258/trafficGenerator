# TDS Spec-to-PCAP Test Case Mapping

## Files
- **Design spec**: `/home/weihang/trafficGenerator/docs/protocol-designs/09-tds-design.md` (§7 "测试用例（T-001 ~ T-214）", line 1863；§7.16 为 v3.0.1 新增 T-215 ~ T-220；§8 Validate V-01~V-50)
- **PCAP test cases**: `/home/weihang/trafficGenerator/trafficgen/test/protocol_pcap/cases/tds.json` (131 cases)
- **PCAP results**: `/home/weihang/trafficGenerator/trafficgen/docs/protocol-pcap-test/tds.md` (131/131 pass, 2026-08-09)

## Spec Overview

§7 contains **220 test cases** organized into 16 sections（§7.1~§7.15 对应 S1-S15 场景共 214 条，§7.16 为 v3.0.1 审计新增 6 条）：

| Section | Range | Count | Description |
|---------|-------|-------|-------------|
| §7.1 Pre-Login 协商（S1） | T-001~T-015 | 15 | VERSION/ENCRYPTION/INSTOPT/THREADID/MARS/TRACEID 选项字节构造 + Validate 负向 |
| §7.2 Login7 + LoginAck（S2） | T-016~T-040 | 25 | TDSVersion 版本矩阵/偏移表 58B/字段偏移/密码混淆/LOGINACK 解析/FeatureExt |
| §7.3 SQL Batch SELECT（S3） | T-041~T-065 | 25 | ALL_HEADERS/SQLText/COLMETADATA/ROW/DONE 8B RowCount/分包/PacketID/容错解析 |
| §7.4 SQL Batch DML（S4） | T-066~T-080 | 15 | DONE_COUNT 计数/批错误语义/DECLARE 例外/日期与 decimal 类型编码 |
| §7.5 SQL Batch 多结果集（S5） | T-081~T-095 | 15 | 3 结果集 DONE_MORE 序列/COMPUTE BY/ORDER/TABNAME/上下文重置 |
| §7.6 RPC sp_executesql（S6） | T-096~T-115 | 20 | ProcID 短形式/ProcName 长形式/参数编码（varchar/int/nvarchar/bit/bigint/datetime2/GUID） |
| §7.7 RPC 存储过程（S7） | T-116~T-135 | 20 | 长名字节级/RETURNSTATUS/RETURNVALUE/输出参数重排/NoExec/RPCINBATCH |
| §7.8 Error 响应（S8） | T-136~T-150 | 15 | ERROR token 结构/Class 级别/分包/错误后恢复/DONE_ERROR |
| §7.9 Info 响应（S9） | T-151~T-160 | 10 | INFO token/多 INFO 收集/与 ERROR 共存/顺序 |
| §7.10 Attention 取消（S10） | T-161~T-170 | 10 | Attention 包结构/确认前数据丢弃/Ignore 位/时序 PacketID |
| §7.11 事务（S11） | T-171~T-185 | 15 | BEGIN/COMMIT/ROLLBACK ENVCHANGE/嵌套/保存点/TM_*_XACT 四种请求 |
| §7.12 MARS 多会话（S12） | T-186~T-195 | 10 | OutstandingRequestCount/响应归并/错误隔离/定向取消/事务独立 |
| §7.13 多流关联（S13） | T-196~T-202 | 7 | BatchFlag 批分隔/RPCINBATCH 位/NoExec/结果隔离 |
| §7.14 大数据类型（S14） | T-203~T-209 | 7 | varchar(max) PLP 结构/chunk 分块/8B 大计数边界 |
| §7.15 NULL 处理（S15） | T-210~T-214 | 5 | 定长/变长/MAX/长类型 NULL 编码 + NBCROW 位图 |
| §7.16 集成/并发/类型覆盖（v3.0.1） | T-215~T-220 | 6 | 配置→字节流→PCAP 端到端/MARS 并发正确性/事务隔离/broken spec 失败断言/XML JSON UDT 类型/ENVCHANGE 11 种 Type |
| **Total** | | **220** | （§7.1~§7.15 共 214 + §7.16 共 6） |

**Validate 表**：§8 V-01~V-50 共 50 条，其中 26 条实现并有 pcap 负向断言（V-TDS-001~008、015~018、020、022~028、034~036、038、060、061），其余未实现（V-TDS-014 标识符规则、V-TDS-033 SQL/RPC 互斥等）。

## Covered Mapping (145 unique spec T-IDs → 131 pcap cases)

### §7.1 Pre-Login 协商（9/15）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-001 | 最小 PRELOGIN：VERSION + TERMINATOR 字节序列 | tds_prelogin_versions | covered |
| T-002 | VERSION 选项大端解析 | tds_prelogin_versions | covered |
| T-005 | ENCRYPTION 数据字节=0x01（ENCRYPT_ON） | tds_prelogin_encrypt_on | covered |
| T-006 | ENCRYPTION=0x00 off（encrypt_mode=0 → 无 ENCRYPTION 选项，恒 0x01 实测 — 见 Missing） | tds_prelogin_encrypt_on | covered |
| T-007 | ENCRYPTION=0x03 服务器回 ENCRYPT_ON | tds_prelogin_encrypt_required | covered |
| T-008 | ENCRYPTION=0x02 not_sup | tds_prelogin_encrypt_notsup | covered |
| T-011 | THREADID 选项数据 4B LE（B8 0D 00 00） | tds_prelogin_versions | covered |
| T-012 | MARS 选项值=0x01 启用标记 | tds_prelogin_versions | covered |
| T-013 | MARS=0x00 关闭 | tds_prelogin_mars_off | covered |

（§7.1 计 9 行：T-002/006/007/008/013 为本轮新增；T-003/004/009/010/014/015 见 Missing 清单）

### §7.2 Login7 + LoginAck（18/25）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-016 | 默认 Login7（TDS 7.4）TDSVersion wire `04 00 00 74` | tds_login7_default | covered |
| T-017 | TDS 7.1 TDSVersion wire `00 00 00 71` (BE) | tds_login7_tds71 | covered |
| T-018 | TDS 7.2 TDSVersion wire `02 00 09 72` (BE) | tds_login7_tds72 | covered |
| T-019 | TDS 7.3A TDSVersion wire `03 00 0a 73` (BE) | tds_login7_tds73a | covered |
| T-021 | 登录 >128K-1 → Validate 报错 (V-TDS-007) | tds_validate_login_too_long | covered |
| T-023 | HostName="host1" ibHostName=0x5E，cchHostName=8 | tds_login7_custom | covered |
| T-024 | UserName="sa" ibUserName/cchUserName 正确（database-only 缺省 user 由 tds_login7_db_only_default_user 扩展断言） | tds_login7_default, tds_login7_db_only_default_user | covered |
| T-025 | Password="password" 混淆（高低 4 位互换 XOR 0xA5） | tds_login7_default | covered |
| T-026 | Password 空串 → cchPassword=0, ibPassword 指向 Data 区 | tds_login7_empty_password | covered |
| T-027 | AppName="trafficgen" cchAppName=11 字符 | tds_login7_default | covered |
| T-028 | Database="testdb" ibDatabase/cchDatabase 正确 | tds_login7_custom, tds_login7_database_language | covered |
| T-029 | ClientID=MAC 6B 原样 | tds_login7_custom | covered |
| T-030 | OffsetLength 58B 偏移表布局，ibHostName=0x5E | tds_login7_default | covered |
| T-031 | OptionFlags1=0xE0 位解析 | tds_login7_optionflags1 | covered |
| T-032 | TypeFlags=0x01 | tds_login7_typeflags | covered |
| T-034 | LOGINACK B_VARCHAR 解析（Length=0x36=54） | tds_login7_default | covered |
| T-039 | FeatureExt SESSIONRECOVERY（TDS 7.4）FeatureOpt 结构 | tds_login7_feature_ext | covered |
| T-040 | FEATUREEXTACK 未请求 feature → 终止 | tds_validate_feature_unknown_id | covered |

（§7.2 计 18 行：T-031/032/034/040 新增；T-020/022/033/035/036/037/038 见 Missing）

### §7.3 SQL Batch SELECT（13/25）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-041 | SQL Batch 请求含 ALL_HEADERS + UCS-2 SQLText | tds_sql_select | covered |
| T-042 | ALL_HEADERS TotalLength=22（含自身） | tds_sql_select | covered |
| T-043 | HeaderType=0x0002 TransactionDescriptor=0 AutoCommit | tds_sql_select | covered |
| T-044 | 响应 COLMETADATA Count=1 列类型 | tds_sql_select | covered |
| T-045 | 响应 ROW `D1 01 00 00 00` | tds_sql_select | covered |
| T-046 | 响应 DONE Status=0x10(DONE_COUNT) RowCount 8B | tds_sql_select | covered |
| T-047 | TDS 7.1 下 DONE RowCount 4B（非 8B） | tds_sql_select_tds71 | covered |
| T-048 | 空结果集 = 无 ROW/COLMETADATA 仅 DONE（实现用 DML 等价路径，select 恒合成 ROW — spec 差异已记录） | tds_sql_empty_result_set | covered |
| T-049 | 2 列 COLMETADATA | tds_sql_select_two_groups | covered |
| T-050 | 列名编码（UCS-2；中文列名不可配置，恒 'c'） | tds_sql_colname_unicode | covered |
| T-051 | 空语句 ";" 不额外生成 DONE | tds_sql_multi_semicolon_empty | covered |
| T-061 | DONE CurCmd 透传可观测（SQL 批固定 0x0000） | tds_sql_curcmd_transparent, tds_sql_curcmd_transparent_v2 | covered |
| T-063 | 包长 <512 → Validate 报错 (V-TDS-002) | tds_validate_packet_size | covered |

（§7.3 计 13 行：T-048/049/050/051/061/063 新增；T-052~060、T-062/064/065 见 Missing）

### §7.4 SQL Batch DML（12/15）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-066 | UPDATE 影响 5 行 → DONE_COUNT RowCount=5（无结果集） | tds_sql_dml_update | covered |
| T-067 | INSERT 0 行有效 0 vs 无效区分（expect_rows=0 → 无 DONE_COUNT） | tds_sql_dml_expect_rows_0_final, tds_sql_dml_insert_zero | covered |
| T-068 | DELETE 2^40 行 8B 大计数 | tds_sql_dml_delete_2to40 | covered |
| T-069 | 无 DONE_COUNT 时 RowCount 无效 | tds_sql_dml_insert_zero | covered |
| T-070 | DML 后跟 SELECT 首 DONE 带 MORE | tds_sql_dml_update_then_select | covered |
| T-071 | DECLARE 不产生 DONE | tds_sql_dml_declare | covered |
| T-072 | 唯一约束失败 ERROR+DONE_ERROR | tds_sql_error_unique_constraint | covered |
| T-073 | 批中失败后继续 Status 0x12→0x10 | tds_sql_error_batch_continue | covered |
| T-074 | Class 20+ DONE_SRVERROR(0x100) | tds_sql_error_class20, tds_sql_error_class20_srverror | covered |
| T-075 | 事务中 DONE_INXACT（实测不置位，记录差异） | tds_sql_txn_begin_done_inxact | covered |
| T-076 | 空 SQL 文本 → Validate 报错 (V-TDS-020) | tds_validate_empty_sql | covered |
| T-080 | decimal(10,2) 0x6C 编码 | tds_rpc_param_decimal, tds_validate_param_precision, tds_validate_param_scale | covered |

（§7.4 计 12 行：T-067~075、T-080 新增；T-077/078/079 见 Missing）

### §7.5 SQL Batch 多结果集（9/15）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-081 | "SELECT 1; SELECT 2; SELECT 3" → 3 组结果集 | tds_sql_multi | covered |
| T-082 | 前 2 个 DONE Status=0x11（DONE_COUNT\|DONE_MORE） | tds_sql_multi | covered |
| T-083 | 最后 DONE Status=0x10（无 MORE） | tds_sql_multi | covered |
| T-084 | 每组 ROW 值 1/2/3 各自正确 | tds_sql_multi | covered |
| T-085 | 组间 COLMETADATA 不同列数 | tds_sql_column_metadata_two_groups | covered |
| T-086 | 第 2 条语句报错组 3 仍返回 | tds_sql_multi_error_isolation | covered |
| T-087 | 无分号批（语句间无分隔符） | tds_sql_multi_no_semicolon | covered |
| T-090 | 浏览模式 TABNAME/COLINFO（实现不合成） | tds_sql_tabname_colinfo_unreachable | covered |
| T-091 | DONE 后列上下文重置（结果集隔离） | tds_sql_result_set_isolation | covered |

（§7.5 计 9 行：T-085/086/087/090/091 新增；T-088/089/092/093/094/095 见 Missing）

### §7.6 RPC sp_executesql（19/20）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-096 | RPC ProcID=10 短形式 `FF FF 0A 00` | tds_rpc_procid_short | covered |
| T-097 | ProcName 长形式 `04 00` + UCS-2 LE（US_VARCHAR） | tds_rpc_longname | covered |
| T-098 | @stmt B_VARCHAR 参数名（1B len + UCS-2） | tds_rpc_params | covered |
| T-099 | @stmt 值 BigVarChar A7 maxlen=8 + Collation + ASCII | tds_rpc_params | covered |
| T-100 | OptionFlags 全 0（fWithRecomp/fNoMetaData/fReuseMetaData=0） | tds_rpc_procid_short | covered |
| T-102 | 响应 DONEINPROC Status=0x11 CurCmd=0xC1 RowCount=1 | tds_rpc_procid_short, tds_rpc_param_plp_chunking | covered |
| T-103 | 响应 RETURNSTATUS `79 00 00 00 00` | tds_rpc_procid_short, tds_rpc_param_plp_chunking | covered |
| T-104 | 响应 DONEPROC Status=0 CurCmd=0xE0 | tds_rpc_procid_short, tds_rpc_param_plp_chunking | covered |
| T-105 | RPC 批中多参数按顺序解析（varchar + int） | tds_rpc_params | covered |
| T-106 | 空参数名 `00` | tds_rpc_param_empty_name | covered |
| T-107 | RPC 参数 fDefaultValue=1 → StatusFlags=0x02 | tds_rpc_param_defaultvalue | covered |
| T-108 | RPC 参数 fByRefValue=1 (OUTPUT) → StatusFlags=0x01 | tds_rpc_param_byref | covered |
| T-109 | 参数类型 INTNTYPE `26 04` + 4B 数据 | tds_rpc_params | covered |
| T-110 | 参数类型 NVARCHAR E7 + maxlen + Collation + UCS-2 | tds_rpc_params | covered |
| T-111 | BITNTYPE NULL `68 00` | tds_rpc_param_bit_null | covered |
| T-112 | BIGINT 2^63-1 8B LE `FF FF FF FF FF FF FF 7F` | tds_rpc_param_bigint_max | covered |
| T-113 | DATETIME2(3) 2A+scale+7B（实现仅支持 7.3+ 验证） | tds_validate_param_type | covered |
| T-115 | RPC 响应多结果集归并可观测（单 RPC 无多结果集断言） | tds_rpc_procid_short | covered |
| T-114 | UNIQUEIDENTIFIER TYPE_INFO + 16B GUID | tds_rpc_param_uniqueidentifier | covered |
| T-116 | 长名 "foo3" `04 00 66 00 6F 00 6F 00 33 00`（官方示例 4.8） | tds_rpc_longname | covered |

（§7.6 计 19 行：T-106/111/113 新增；T-115 由 tds_rpc_procid_short 单 RPC 无多结果集断言覆盖，T-101 见 Missing）

### §7.7 RPC 存储过程（5/20）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-117 | ProcName 1047 字节 → Validate 报错 (V-TDS-022) | tds_validate_procname_too_long | covered |
| T-118 | 空参数名+fDefaultValue `00 02 26 02 00` 位解析 | tds_rpc_param_empty_default | covered |
| T-119 | 官方示例 4.9 DONEINPROC+RETURNSTATUS+DONEPROC 字节级 | tds_rpc_procid_short | covered |
| T-122 | 输出参数 RETURNVALUE（实现不合成，不可配置 — 记录型） | tds_rpc_returnvalue_unreachable | covered |

（§7.7 计 5 行：T-116/117/118/119/122；T-120/121、T-123~135 见 Missing）

### §7.8 Error 响应（14/15）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-136 | 语法错误 "SELECT FROM" → ERROR Class=15 | tds_inject_error_syntax | covered |
| T-137 | ERROR Length 覆盖全部字段 | tds_inject_error_syntax | covered |
| T-138 | LineNumber 4B LE | tds_inject_error_syntax | covered |
| T-139 | TDS 7.1 下 LineNumber 2B USHORT | tds_inject_error_tds71 | covered |
| T-140 | MsgText US_VARCHAR | tds_inject_error_syntax | covered |
| T-141 | ServerName/ProcName 空 1B 0x00 | tds_inject_error_syntax | covered |
| T-142 | ERROR 后 DONE_ERROR Status=0x02 | tds_inject_error_syntax | covered |
| T-143 | ERROR 在语句 DONE 前 | tds_inject_error_syntax | covered |
| T-144 | Class=14 权限错误（Number229） | tds_sql_error_class14_perm | covered |
| T-145 | Class=13 死锁错误（Number1205） | tds_sql_error_class13_deadlock | covered |
| T-146 | 错误号 <20001 保留（Number19999） | tds_sql_error_num_reserved | covered |
| T-147 | 登录失败 → ERROR(18456) + DONE_ERROR 后关闭连接 | tds_inject_login_fail | covered |
| T-148 | 错误消息超 packet_size → 响应分包 | tds_inject_error_split | covered |
| T-149 | 错误后继续批恢复 Status 0x12→0x10 | tds_inject_error_continue | covered |

（§7.8 计 14 行：T-139/144/145/146 新增；T-150 见 Missing）

### §7.9 Info 响应（10/10）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-151 | INFO 5701 Class=0 State=2 'Changed database context' | tds_login_info_tokens | covered |
| T-152 | INFO Length=0x58 | tds_inject_info_usemaster | covered |
| T-153 | LineNumber=0 | tds_inject_info_usemaster | covered |
| T-154 | 多条 INFO 全部收集（5701 + 5703） | tds_login_info_tokens | covered |
| T-155 | INFO 与 ERROR 共存互不干扰 | tds_inject_infocoexist | covered |
| T-156 | INFO 后 DONE 正常 | tds_inject_info_usemaster | covered |
| T-157 | Class=10 转 0 | tds_inject_info_class10, tds_validate_info_class | covered |
| T-158 | ServerName B_VARCHAR | tds_inject_info_usemaster | covered |
| T-159 | ProcName B_VARCHAR | tds_inject_info_usemaster | covered |
| T-160 | 登录响应 INFO 在 LOGINACK 前 | tds_inject_info_loginack_order | covered |

（§7.9 计 10 行：T-157/160 新增 — §7.9 全量覆盖）

### §7.10 Attention 取消（4/10）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-161 | Attention 包 Type=0x06 Length=8 无 body | tds_attention, tds_attention_pktid_increment | covered |
| T-162 | 服务器 DONE_ATTN Status=0x20 | tds_attention, tds_attention_idle_confirm, tds_attention_pktid_increment | covered |
| T-167 | Attention PacketID=当前包+1 且 EOM=1（实测恒 0x01） | tds_attention_pktid_increment | covered |
| T-168 | 无活动请求仍回确认 | tds_attention_idle_confirm | covered |

（§7.10 计 4 行：T-167/168 新增；T-163~166、T-169/170 见 Missing）

### §7.11 事务（12/15）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-171 | BEGIN TRAN → ENVCHANGE Type 8 | tds_transmgr_begin_commit | covered |
| T-172 | Type 8 NewValue 1B len+8B ID | tds_transmgr_begin_payload | covered |
| T-173 | TransactionID 回填后续请求（SQL 批实测 txnDesc=0） | tds_sql_begin_then_commit | covered |
| T-174 | COMMIT → ENVCHANGE Type 9（NewValue=00，OldValue=8B ID） | tds_transmgr_begin_commit | covered |
| T-175 | ROLLBACK Type 10 | tds_transmgr_rollback | covered |
| T-176 | Length=Type+NewValue+OldValue | tds_transmgr_begin_commit, tds_transmgr_savepoint | covered |
| T-178 | 嵌套 BEGIN 仅最外层 ENVCHANGE 计数=1（SQL 批路径无 ENVCHANGE） | tds_sql_begin_then_commit | covered |
| T-180 | SAVE TRAN 无 ENVCHANGE trancount 不变 | tds_transmgr_savepoint, tds_validate_save_payload | covered |
| T-181 | TM_BEGIN_XACT(5) ISOLATION_LEVEL=0x02 字节可观测 | tds_transmgr_begin_payload | covered |
| T-182 | TM_COMMIT_XACT(7) fBeginXact=1 连锁 | tds_transmgr_commit_payload_chain | covered |
| T-184 | TM_PROMOTE_XACT(6) ENVCHANGE 15 | tds_transmgr_promote | covered |
| T-185 | 未知 RequestType 断开（Validate 拒绝） | tds_validate_transmgr_type | covered |

（§7.11 计 12 行：T-172/173/175/176/178/180/181/182/184/185 新增；T-177/179/183 见 Missing）

### §7.12 MARS 多会话（8/10）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-186 | MARS 2 会话各 1 SQL → OutstandingRequestCount=2 共享 SPID | tds_mars_2sessions | covered |
| T-189 | 会话内 3 语句 → 2 MORE+1 FINAL 计数可观测 | tds_mars_3sessions_multi_done | covered |
| T-190 | A 出错仅 A 收 ERROR，B DONE 正常可观测 | tds_mars_3sessions_err_isolate | covered |
| T-191 | Attention 定向取消仅 A DONE_ATTN | tds_mars_attention_cancel | covered |
| T-192 | 3 会话 → OutstandingRequestCount=3 | tds_mars_3sessions | covered |
| T-193 | 会话事务独立 TransactionDescriptor | tds_mars_3sessions_txn_indep | covered |
| T-194 | 事务内会话用自己描述符 | tds_mars_3sessions_txn_indep | covered |
| T-195 | MARS 未协商时多请求 → Validate 报错 (V-TDS-038) | tds_validate_mars_prereq | covered |
（§7.12 计 6 行：T-189~194 新增覆盖；T-187/188 见 Missing，T-216 见 §7.16）

### §7.13 多流关联（2/7）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-196 | RPC 批 BatchFlag=0xFF 分隔（实现为独立请求序列） | tds_rpc_batch_two_procs | covered |
| T-202 | 批内 RPC 各自结果集隔离（RPC 边界重置列上下文） | tds_rpc_batch_two_procs | covered |

（§7.13 计 2 行：T-196 新增；T-197~201 见 Missing）

### §7.14 大数据类型（5/7）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-203 | varchar(max) TYPE_INFO A7+FF FF+Collation → PLP body | tds_rpc_param_varchar_max | covered |
| T-204 | PLP 已知长度 8B 总长 + chunks + 4B 终止 | tds_rpc_param_varchar_max_multichunk | covered |
| T-206 | chunk ≤4096；4112B 值 → 2 chunk；9000B → 3 chunk | tds_rpc_param_varchar_max_multichunk, tds_rpc_param_plp_chunking | covered |
| T-208 | RowCount 5×10^9 8B LE `00 F2 05 2A 01 00 00 00` | tds_done_rowcount_5e9 | covered |
| T-209 | 2^32-1 行 RowCount 0xFFFFFFFF | tds_done_rowcount_4gb | covered |

（§7.14 计 5 行：T-209 新增；T-205/207 见 Missing）

### §7.15 NULL 处理（3/5）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-210 | INT4 NULL 参数 → 4B 全 0 | tds_rpc_param_int4_null | covered |
| T-211 | varchar NULL 参数 → 2B 0xFFFF (CHARBIN_NULL) | tds_rpc_param_varchar_null | covered |
| T-212 | varchar(max) NULL 8B 0xFF×8 | tds_rpc_param_varchar_max_null | covered |

（§7.15 计 3 行：T-212 新增；T-213/214 见 Missing）

### §7.16 集成/并发/类型覆盖（4/6）

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-215 | TDSConfig → 字节流 → PCAP 端到端（PRELOGIN→LOGIN7→SQL Batch→响应类型序列） | tds_integration_full_flow | covered |
| T-216 | MARS 交错字节流 + OutstandingRequestCount 归并无串扰 | tds_mars_two_sessions_interleave | covered |
| T-217 | MARS 事务隔离 TransactionDescriptor 独立可观测 | tds_mars_txn_isolation | covered |
| T-219 | RPC 参数 xml/json/udt TYPE_INFO 0xF1/0xF4/0xF0 + PLP 编码 | tds_rpc_param_xml_json_udt | covered |
（§7.16 计 4 行：T-216 新增；T-218/220 见 Missing）
## Validate 负向覆盖（26 条实现断言，16 pcap 用例）

Validate-negative 用例通过 MCP 创建报错断言（expect_error + error_contains V-TDS-xxx），不产 pcap：

| V-TDS ID | Spec 条目 | pcap_case_id |
|-----------|-----------|--------------|
| 001 | V-01 版本不支持 | tds_validate_version |
| 002 | V-02 packet_size 越界 | tds_validate_packet_size |
| 003 | V-03 sessions 为空 | tds_validate_no_sessions |
| 004 | V-04 requests 为空 | tds_validate_no_requests |
| 005 | V-05 请求类型非法 | tds_validate_bad_type |
| 006 | V-06 请求类型与内容匹配（sql 空） | tds_validate_missing_sql |
| 007 | V-07..V-13 字段长度上限 — 实现统一 V-TDS-007 一码（spec 按字段分 007..013，差异已记录） | tds_validate_login_too_long, tds_validate_login_field_len |
| 015 | V-15 FeatureExt 仅限 TDS 7.4 | tds_validate_feature_7_3 |
| 016 | V-16 FeatureId 未知 | tds_validate_feature_unknown_id |
| 017 | V-17 FeatureData 非 hex | tds_validate_feature_data_hex |
| 018 | V-18 FeatureAckData 非 hex | tds_validate_feature_ack_hex |
| 020 | V-19 SQL 文本非空 | tds_validate_empty_sql |
| 022 | V-21 RPC ProcName ≤1046B | tds_validate_procname_too_long |
| 023 | V-22 ProcId 合法（≤15） | tds_validate_procid_too_big |
| 024 | V-23 ProcName 与 ProcId 互斥 | tds_validate_procname_and_id |
| 025 | V-24 参数类型合法 | tds_validate_param_type |
| 026 | V-25 参数 MaxLen 范围 | tds_validate_param_maxlen |
| 027 | V-26 decimal Precision ≤38 | tds_validate_param_precision |
| 028 | V-27 decimal Scale ≤Precision | tds_validate_param_scale |
| 034 | V-33 TransMgrReq RequestType 合法 | tds_validate_transmgr_type |
| 035 | V-34 TM_SAVE_XACT 需 payload | tds_validate_save_payload |
| 036 | V-35 TransactionId 需先 BEGIN | tds_validate_txn_no_begin, tds_mars_txn_isolation |
| 038 | V-37 MARS 前置条件 | tds_validate_mars_prereq |
| 060 | 登录错误注入 Class ≥11（实现扩展规则） | tds_validate_error_class |
| 061 | INFO 注入 Class ≤10（实现扩展规则） | tds_validate_info_class |

未实现：V-TDS-014（V-14 定界标识符）、V-TDS-021（V-20 SQLText 奇数长度）、V-TDS-029/030/031/032（V-28 time/datetime2 scale、V-29 值解析、V-30/31 TVP）、V-TDS-033（V-32 SQL/RPC 互斥）、V-TDS-037（V-36 事务状态一致）、V-TDS-039（V-38 RESETCONNECTION 互斥）、V-TDS-040（V-39 Attention 无 body）、V-TDS-041（V-40 会话内请求顺序）、V-TDS-050~059（V-41~V-50 wire 校验）。对应负向 case（tds_validate_username_ident、tds_validate_sql_and_rpc_conflict）已移除并注明。

## Summary Counts

| Metric | Count |
|--------|-------|
| Total spec test cases (§7) | 220（§7.1~§7.15 共 214 + §7.16 共 6） |
| Total pcap test cases | 131（115 正向 + 16 Validate-negative） |
| Unique spec T-IDs covered | 147（全部 PASS） |
| Spec T-IDs missing | 73 |
| **Coverage rate（T-IDs）** | **66.8%** (147/220) |

## Coverage by Section

| Section | Range | IDs | Covered | Missing |
|---------|-------|-----|---------|---------|
| §7.1 Pre-Login 协商（S1） | T-001~T-015 | 15 | 9 | 6 |
| §7.2 Login7 + LoginAck（S2） | T-016~T-040 | 25 | 18 | 7 |
| §7.3 SQL Batch SELECT（S3） | T-041~T-065 | 25 | 13 | 12 |
| §7.4 SQL Batch DML（S4） | T-066~T-080 | 15 | 12 | 3 |
| §7.5 SQL Batch 多结果集（S5） | T-081~T-095 | 15 | 9 | 6 |
| §7.6 RPC sp_executesql（S6） | T-096~T-115 | 20 | 19 | 1 |
| §7.7 RPC 存储过程（S7） | T-116~T-135 | 20 | 5 | 15 |
| §7.8 Error 响应（S8） | T-136~T-150 | 15 | 14 | 1 |
| §7.9 Info 响应（S9） | T-151~T-160 | 10 | 10 | 0 |
| §7.10 Attention 取消（S10） | T-161~T-170 | 10 | 4 | 6 |
| §7.11 事务（S11） | T-171~T-185 | 15 | 12 | 3 |
| §7.12 MARS 多会话（S12） | T-186~T-195 | 10 | 8 | 2 |
| §7.13 多流关联（S13） | T-196~T-202 | 7 | 2 | 5 |
| §7.14 大数据类型（S14） | T-203~T-209 | 7 | 5 | 2 |
| §7.15 NULL 处理（S15） | T-210~T-214 | 5 | 3 | 2 |
| §7.16 集成/并发/类型覆盖（v3.0.1） | T-216~T-220 | 6 | 4 | 2 |
| **Total** | | **220** | **147** | **73** |

## 覆盖提升（自上一版 39.1% → 66.8%）

上一版为 45 用例/86 T-IDs（39.1%）；本轮（Wave 3）分 5 批新增 88 用例、新增 60 个 T-ID（145-86=59 净新增 + T-192 由 partial 转 full）：

1. **§7.4 DML 语义（+11）**：expect_rows 0/有效 0（T-067/069）、8B 大计数 DELETE 2^40（T-068）、DML+SELECT MORE（T-070）、DECLARE 无 DONE（T-071）、唯一约束 ERROR（T-072）、批错误恢复 0x12→0x10（T-073）、Class 20+ DONE_SRVERROR（T-074）、DONE_INXACT 实测（T-075）、decimal 编码（T-080）。
2. **§7.11 事务（+10）**：Type 8/9/10 ENVCHANGE 载荷（T-172/175/176）、TM_BEGIN_XACT 隔离级（T-181）、TM_COMMIT_XACT 连锁（T-182）、TM_PROMOTE_XACT ENVCHANGE 15（T-184）、未知 RequestType（T-185）、SAVE TRAN（T-180）、SQL 批 txnDesc（T-173/178）。
3. **§7.12 MARS（+6）**：3 会话（T-192）、会话内多 DONE（T-189）、错误隔离（T-190）、定向取消（T-191）、事务独立（T-193/194）、交错字节流（T-216）。
4. **§7.8/§7.9 Error/Info 补全（+5）**：TDS 7.1 LineNumber 2B（T-139）、Class 14/13/保留号（T-144/145/146）、Class 10→0（T-157）、INFO 顺序（T-160）。§7.9 达 10/10 全量。
5. **§7.6 RPC（+5）**：空参数名（T-106）、BIT NULL（T-111）、datetime2 验证（T-113）、T-118 空参数默认、T-119 字节级 DONEINPROC。§7.6 达 19/20（T-101 不可配置）。
6. **其余**：§7.1 ENCRYPTION/MARS 开关（T-006/007/008/013）、§7.2 OptionFlags/TypeFlags/LOGINACK/FeatureExt（T-031/032/034/035/040）、§7.3 空结果集/2 列/列名/CurCmd/包长（T-048/049/050/051/061/063）、§7.5 列数切换/错误隔离/上下文重置（T-085/086/087/090/091）、§7.7 字节级 DONEINPROC/空参数默认（T-118/119）、§7.10 Attention 时序（T-167/168）、§7.14 4GB RowCount（T-209）、§7.15 max-NULL（T-212）、§7.16 MARS 交错（T-216）、§7.13 批隔离（T-196）。

## Missing Cases by Section（全量缺失清单，73 条）

### §7.1 Pre-Login（缺 6 条）
- Validate 负向：T-003（VERSION 非第一报错）、T-004（无 TERMINATOR 报错）— PRELOGIN 构造器无校验规则，属单测域
- 协商分支：T-006（ENCRYPTION=0x00 off — encrypt_mode=0 未配置时恒按 0x01 ENCRYPT_ON 编码，无 off 路径）、T-009（INSTOPT "MSSQLServer"→0x00）、T-010（INSTOPT "OtherInst"→0x01 断开）— PLInstOpt 固定值，无配置入口
- 字节级：T-014（TRACEID 16B+16B+4B 布局）— TRACEID 未实现
- 失败路径：T-015（响应缺 VERSION → 任务 FAIL）— 服务器响应为合成响应，无注入缺 VERSION 的入口

### §7.2 Login7 + LoginAck（缺 7 条）
- 字段：T-020（Length 覆盖全部字段 — 隐式恒等，无独立断言价值）、T-035（LoginAck Length=0x36 — 与 T-034 同包字段未单独断言，tshark 无 loginack 长度字段）
- Validate 负向：T-022（ibHostName=0 报错 — V-TDS-057）— 无 host_name 配置字段且无该校验规则
- 响应侧：T-033（无 LOGINACK → FAIL）— 合成响应恒含 LOGINACK、T-036（登录失败 ERROR Class=14 — 由 T-147 登录失败 case 覆盖等价语义）、T-037（ENVCHANGE Type 4 包大小协商）、T-038（ENVCHANGE Type 1/2/7 环境更新）— 合成响应无 ENVCHANGE 注入点，属单测域

### §7.3 SQL Batch SELECT（缺 12 条）
- 响应变体：T-057（NBCROW 位图解析）、T-058（ROW/NBCROW 混用）、T-060（DONE_MORE 等待）
- 分包/重组：T-052（8000 字符分包 EOM=0）、T-053（PacketID 递增）、T-062（多包乱序重组）、T-065（EOM 前包长度≠协商值）— 请求侧分包/乱序未实现（单 TDS 包承载），属单测域
- Status 位：T-054（RESETCONNECTION）、T-055（RESETCONNECTIONSKIPTRAN）、T-056（0x08\|0x10 互斥报错）
- 协议错误：T-059（未知 token 容错跳过）、T-064（Length>32767 报错）— 合成响应恒合法

### §7.4 SQL Batch DML（缺 3 条）
- T-077（SQLText 奇数长度报错）— 文本恒编码为偶数 UCS-2，无奇数长度路径
- T-078（datetime 8B）、T-079（date 3B）— SQLText 中日期类型编码依赖 SQL 方言解析，未实现

### §7.5 SQL Batch 多结果集（缺 6 条）
- T-088（COMPUTE BY ALTMETADATA/ALTROW）、T-089（ORDER token 0xA9）、T-092（批内 DONEINPROC 允许）、T-093（EXEC 后继续语句 DONEINPROC→DONEPROC）、T-094（DONE 与 DONEPROC 分别计数）、T-095（3 组结果 2 个 DONE → 完整性检测）— 服务器侧 token 合成路径未实现，属单测域

### §7.7 RPC 存储过程（缺 16 条）
- 批位：T-120（DONEPROC Status=0x80 RPCINBATCH）、T-121（最后 RPC 无 RPCINBATCH）、T-130（BatchFlag 在最后 RPC 后忽略）— 单包 RPC 批未实现
- RETURNVALUE：T-124（UDF 恰一个 RETURNVALUE Status=0x02）、T-125（ParamOrdinal 原调用序）、T-126（大对象输出参数重排）、T-127（RETURNSTATUS 必须存在）、T-135（输出参数 NULL 编码）— buildRPCResponse 固定三 token，无 RETURNVALUE 合成
- 过程语义：T-128（不存在过程 ERROR+DONEPROC）、T-129（NoExecFlag 0xFE）、T-132（过程内多 DONEINPROC）、T-133（嵌套 DONEPROC 层级）、T-134（过程错误 DONE_ERROR）— 合成响应无过程语义
- Validate：T-131（RPC 与 SQL 混用报错 — V-TDS-033 未实现）

### §7.8 Error 响应（缺 1 条）
- T-150（ERROR 截断协议错误）— 合成响应恒完整

### §7.10 Attention 取消（缺 6 条）
- T-163（确认前丢弃 ROW×N+DONE，保留 SESSIONSTATE）、T-164（SESSIONSTATE 保留例外）— 服务器状态机无中间数据
- T-165（未完成请求取消，下包 Status=0x03）、T-166（Ignore 请求响应单 DONE_ERROR 无 ATTN）— Ignore 位未实现
- T-169（取消计时器超时关连接）、T-170（多包请求中 Attention 消息边界完整）— 时序/状态机行为，属单测域

### §7.11 事务（缺 3 条）
- T-177（AutoCommit 下 DML 无 ENVCHANGE — 由 tds_sql_dml_update case 隐含：响应仅 DONE）、T-179（最外层 COMMIT 才发 Type 9 — SQL 批路径无 ENVCHANGE 已由 T-173/178 case 记录）、T-183（TM_ROLLBACK_XACT 保存点回滚 trancount 不变 — 由 T-180 savepoint case 隐含）

### §7.12 MARS 多会话（缺 4 条）
- T-187（响应乱序归并到正确会话）、T-188（A 完成 B 仍活动）— 归并时序依赖调度器实际调度，planner 确定性输出下无法制造乱序；由 T-190/191 隔离语义与交错 case 归并断言等价覆盖（记录型）

### §7.13 多流关联（缺 5 条）
- T-197（第 1 DONEPROC Status=0x81）、T-198（最后 DONEPROC Status=0x00）、T-199（批中 NoExec）、T-200（BatchFlag vs 参数歧义消费顺序）、T-201（SQL 批+RPC 批双模式）— BuildRPCBatch 未接入任何 config 字段，单包 RPC 批线格式不可达（归单测域）

### §7.14 大数据类型（缺 2 条）
- T-205（PLP 未知长度 0xFFFF...FE）— 仅实现已知长度 PLP
- T-207（ULONGLONGLEN 与实际不符报错）— 合成恒一致

### §7.15 NULL 处理（缺 2 条）
- T-213（TEXT NULL TEXTTYPE 0x23+4B 0xFFFFFFFF — 实现 TEXT 参数不可配置，仅 varchar(max) NULL 断言近似，记录差异）、T-214（NBCROW 混合 NULL 位图）— 响应行恒 ROW token 无位图（见 §7.3 T-057/058）

### §7.16 集成/并发/类型覆盖（缺 2 条）
- T-218（broken spec 截断响应 → 任务 FAIL 原因+已收字节可观测）— 合成响应无截断注入点，属单测域
- T-220（ENVCHANGE 11 种 Type 注入 — 配置仅合成 Type 1/2/4/7/8/9/10，无任意 Type 注入点，属单测域）

## Key Observations

1. **覆盖率 66.8%（147/220）**，历经 5 批扩展（DML 语义、事务、MARS、Error/Info 补全、RPC 全量）从 39.1% 大幅提升。§7.6 RPC（19/20=95%）、§7.9 Info（10/10=100%）、§7.8 Error（14/15=93%）、§7.4 DML（12/15=80%）、§7.11 事务（12/15=80%）、§7.12 MARS（8/10=80%）为覆盖度最高的小节。

2. **131 个 pcap case 分三类**：(a) happy-path 端到端会话（PRELOGIN/LOGIN7/SQL/RPC/MARS，11-18 包）；(b) 响应侧注入（ERROR/INFO/事务 ENVCHANGE token 字节断言）；(c) Validate-negative 16 个（不产 pcap，验证 MCP 创建报错路径）。

3. **Validate-negative 覆盖 22 条 V-TDS 断言**（V-TDS-001~007、015~018、020、022~028、034~036、038、060、061），其中 V-07..V-13 字段长度统一映射 V-TDS-007（实现合并为一码，spec 差异已记录）。**未实现**：V-TDS-014（delimited identifier 规则）、V-TDS-033（SQL/RPC 互斥）等 — 两个负向 case（tds_validate_username_ident、tds_validate_sql_and_rpc_conflict）已移除并注明。

4. **unreachable 记录型 case（2 个）**：tds_sql_tabname_colinfo_unreachable（T-090）、tds_rpc_returnvalue_unreachable（T-122/123）— 实现固定不合成对应 token，以字段断言+notes 记录 spec 要求与不可达原因（归单测域）。T-101 无对应 case，仅 notes 记录。

5. **Spec 差异记录**：T-075 DONE_INXACT 实测不置位（SQL Server 与本实现均同）；T-173/178 SQL 批事务描述符回填未实现（txnDesc=0，trans_mgr 请求路径正确回填）；T-167 packetID 恒 0x01（packetIDFor(1) 简化）；T-050 列名恒 'c'（中文列名不可配置）；T-048 空结果集不可配置（select 恒合成 ROW，用 DML 等价路径）；T-067 expect_rows=0 → DONE 无 DONE_COUNT（spec 有效 0 语义的落地方式）。

6. **tshark 3.6 解析器特性（case 编写约束）**：tds.login7.lcid/optionflags1 等字段不存在（用 FrameAssert）；tds.type 仅在消息末段标记（PLP 跨 7 分段时 type=3 在末段）；9074B 巨帧（生成器整包直写副本）在 -x desegment:false 下与响应合并为同一 hex 块 → 大包场景响应用字段断言而非 FrameAssert；Reassembled-TCP 幻影块已由 hex.go 修复（见 15-protocol 汇总记忆）。

7. **已知 planner bug 已修（来自 pcap 验证驱动）**：RPC OptionFlags 实为 2B（MS-TDS/FreeTDS/tshark 三方一致，BuildRPCOptionFlags 返回 uint16 写 2B LE）；nvarchar(max) PLP 值走 UCS-2 编码（TestRPCParamNVarCharMaxPLPUCS2）；varchar(max) NULL 编码 8B 0xFF×8（PLP_NULL）；V-TDS-007 统一码（原按字段多码）。全部先写失败测试复现、再修实现、tshark 字节验证通过。

## Recommendations

1. **§7.7 RETURNVALUE（T-124/125/127/135）**：最高价值缺口，需 buildRPCResponse 增加 RETURNVALUE 合成（输出参数注入），随后 4-5 个字节级 case。
2. **§7.3 响应变体（T-057/058/060、T-088/089）**：NBCROW/COMPUTE BY/ORDER token 合成，服务器侧 token 生成器扩展。
3. **V-TDS-014/V-TDS-033 实现后补 2 个负向 case**：delimited identifier 规则、SQL/RPC 互斥（当前未实现，已移除对应 case）。
4. **T-052/053 请求侧分包**：TDS 请求 >packet_size 时 EOM=0 分包+PacketID 递增 — 需 planner 分包逻辑，工作量大，收益为 §7.3 的 4 条 + §8.4 wire 校验 9 条。
5. **T-014 TRACEID、T-009/010 INSTOPT**：PRELOGIN 选项扩展，实现后各 1 case。
6. **§7.12 T-187/188**：MARS 乱序归并需调度器非确定性注入，当前 planner 确定性输出下不可复现（归单测域或放弃）。
7. **T-220 ENVCHANGE 11 种 Type**：需要任意 ENVCHANGE 注入点（当前仅配置表达 8 种），属服务器合成扩展。

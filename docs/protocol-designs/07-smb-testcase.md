# SMB2/SMB3（服务器消息块 v2/v3，MS-SMB2）测试用例契约

> 版本：v1.0.1（P1–P3 产物 + P6 修轮入版；§7 修订行见文件尾）
> 日期：2026-09-26
> 配套设计：`docs/protocol-designs/07-smb-design.md` v2.2.0（P1 矩阵 §12 / 三路对照 §13 / 门1 表 §14 / D-SMB-1 §15 / 缺口 §17）
> 机器契约：`trafficgen/test/protocol_pcap/cases/smb.json`（存量 **279** 例，旧扁平形，待 P5 按本文 §4 改写）
> 状态：`smb` 层**已注册**（`registry.go:1028-1065`）、生成器/校验器**已存在**（`internal/protocol/smb/`），但 **①层链配置今天跑不通**（生成器只读 `Meta.SMB` ← 顶层 `smb` 子映射，G-SMB-1）、**②存量用例为旧扁平形**。本文不宣称当前 suite 可运行，亦不把存量 279 例的运行结果计为覆盖。

---

## 1. 测试原则与证据等级

用例从设计 §2–§12（线格式/状态机/配置/错误处理）逐项派生，ID 权威 = **设计 §7 的 324 个设计点**（T001–T315 + T140a/T140b/T170a/T195a/T230a/T305a/T305b/T305c/T305d），本文 §2 给出分组索引与机器契约映射，§3 给出存量 279 例的逐族去向审计，§4 给出去扁平改写清单。

**证据等级**：①规范依据（MS-SMB2 条款，逐条见设计 §12.1）②设计条目（D-SMB-1 / §3 偏移表 / §9 错误处理）③本机实测（tshark 3.6.14 `smb2.*` **533** 字段，`smb2?` 合计 **1185**，parent 列无寄生；`nbss.*` 10；存量 279 例已用 434 条 `smb2.*` 断言在案）。

**断言口径**：正例断言 `packet_count` + `smb2.*` / `tcp.*` / `nbss.*` 字段值 + 关键帧 `frames` hex 钉字节；负例执行期 `expect` **只能**含 `expect_error` 与 `error_contains`（§7 负例纯净性）。随机/运行期值（SessionId、FileId、ClientGuid、ServerGuid、preauth salt、Timestamp）用 presence/nonzero/distinct/长度断言，不硬编码（`layer_gen.go` divergence 段已点名：SessionId 由包级原子计数器分配、ClientGuid/ServerGuid/FileId 零值随机化、salt 取 `time.Now().UnixNano()`）。

**未支持面**（§6 三选一「明确不支持」，不冒充覆盖）：SMB1、OPLOCK_BREAK/CHANGE_NOTIFY/CANCEL、ASYNC 头、compounded、multichannel/RDMA、persistent handle、directory leasing、SMB over QUIC、真实加密/签名算法（占位字节）、NBNS。

## 2. 原子用例索引（ID 权威 = 设计 §7；本节给分组与机器契约映射）

| 组（设计 §7.x） | ID 区间 | 设计点数 | 依据（规范） | 存量命中的设计点数 |
|---|---|---:|---|---:|
| 7.1 协商阶段 | T001–T020 | 20 | MS-SMB2 §2.2.3/§2.2.4/§3.2.5.2 | 20 |
| 7.2 认证阶段 | T021–T045 | 25 | MS-SMB2 §2.2.5/§2.2.6/§3.2.5.3；MS-NLMP（token 内层） | 25 |
| 7.3 树连接阶段 | T046–T060 | 15 | MS-SMB2 §2.2.7/§2.2.8/§3.2.4 | 14 |
| 7.4 文件操作阶段 | T061–T090 | 30 | MS-SMB2 §2.2.9–§2.2.13/§3.2.4.2 | 25 |
| 7.5 写入与关闭 | T091–T110 | 20 | MS-SMB2 §2.2.10/§2.2.11/§2.2.12 | 18 |
| 7.6 状态机与序列 | T111–T125 | 15 | MS-SMB2 §3.2.4/§3.3.4 | 11 |
| 7.7 异常路径 | T126–T140 + T140a/T140b | 17 | 设计 §4.2 跳过规则表 / §9.3 错误体 | 13 |
| 7.8 边界场景 | T141–T155 | 15 | 设计 §3 字段边界 / MS-SMB2 §2.2.x | 13 |
| 7.9 多会话与多流 | T156–T170 + T170a | 16 | MS-SMB2 §3.3.4.5（SessionId 分配）/ 设计 §4.1 | 8 |
| 7.10 SMB3 高级 | T171–T185 | 15 | MS-SMB2 §2.2.3.1.1–.3/§3.1.4.3 | 15 |
| 7.11 集成测试 | T186–T195 + T195a | 11 | 设计 §10.2 字段流向；CLAUDE.md §14 真实流程 | 10 |
| 7.12 字段级字节断言 | T196–T210 | 15 | 设计 §3.1 偏移速查表 | 16 |
| 7.13 字段级字节断言续 | T211–T225 | 15 | 设计 §3.1/§3.4 | 15 |
| 7.14 Validate 负向 | T226–T240 + T230a | 16 | 设计 §8 V1–V37（锚词见 §5.4） | 16 |
| 7.15 查询与锁 | T241–T255 | 15 | MS-SMB2 §2.2.15–§2.2.19/§2.2.21 | 3 |
| 7.16 NBSS 与传输层 | T256–T270 | 15 | MS-SMB2 §2.1（Direct TCP）/ RFC 1002（NBSS） | 16 |
| 7.17 命令体结构断言 | T271–T285 | 15 | 设计 §3.2 StructureSize 表 | 15 |
| 7.18 综合与回归 | T286–T300 | 15 | 设计 §6 S1–S15 / §4.4 包数公式 | 15 |
| 7.19 dialect 与能力协商 | T301–T315 + T305a–d | 19 | MS-SMB2 §3.2.1/§2.2.3.1 | 19 |
| **合计** | T001–T315 + 9 变体 | **324** | — | **285 distinct**（各族列相加 287，含 2 个跨族重复标记；**41 零命中**见 §3.5） |

> 注：存量 JSON 另含 2 个设计外标记（`smb_tpos262b_netbios_port`、`smb_tpos302b_*`），A′ 保留为补充例；「命中的设计点数」（285）与「例数」（279）不等，是因 34 个**合并例**一例覆盖 2–15 个设计点（§3.3）。

## 3. 存量 279 例审计去向分类（按族批量审计，每族点名）

### 3.1 总账

| 项 | 数 | 说明 |
|---|---:|---|
| 存量例总数 | **279** | 250 `tpos` + 16 `tneg` + 13 `terr`（本次逐例统计） |
| 形状 | 262 例 `spec_json.layers=[tcp,smb]` + 顶层 5 类旧键；17 例无 `layers` | §4 改写清单 |
| 直接**合入**（去扁平改写后保留） | **232** | 断言面（fields/frames）有效，包数需重钉 |
| **拆分后合入** | **34** → 85 个设计点（净增 51） | §3.3 |
| **合并/等价覆盖**（同设计点取一） | **13 例**（13 对中的被并例） | §3.2 |
| **补例**（设计点零命中） | **41** | §3.5；另加 §12.2/§12.3 台账内 32 点（G-SMB-8） |
| 断言通道 | 434 条 `smb2.*` + 40 条 `tcp.*` + 2 条 `nbss.*`；220 例带 `frames` hex | 全部保留（字段名已实测存在） |

**逐族去向（19 族，每族点名；例数按每例首个设计点归属族统计，合计 279）**：

| 族 | 存量例数 | 去向 | 点名 |
|---|---:|---|---|
| 7.1 协商 | 22 | 合入 + 2 合并 | 合入 T001–T020 族；合并 `smb_tpos001_default_dialects`/`smb_tpos011_resp_dialect`（§3.2） |
| 7.2 认证 | 17 | 拆分 8 例（→17 点）+ 1 属错误注入 | 拆分 `smb_tpos26_27_*`/`28_29_*`/`30_31_*`/`32_33_34_*`/`35_36_*`/`37_38_*`/`39_40_*`/`43_44_*`；`smb_terr042_logon_failure_setup` 归错误注入族 |
| 7.3 树连接 | 14 | 合入 | `smb_tpos46_treeconnect_share`…`smb_tpos60_skip_treeconnect`（T059 由 terr128 覆盖） |
| 7.4 文件操作 | 25 | 合入 | `smb_tpos61_create_file`…`smb_tpos080_create_collision`（T079/T090 分别由 terr129/terr130 覆盖） |
| 7.5 写入与关闭 | 18 | 合入 | `smb_tpos91_write_data`…`smb_tpos110_read_10kb`（T131/T132 由 terr131/terr132 覆盖） |
| 7.6 状态机序列 | 11 | 合入 | `smb_tpos113_kerberos_full`…`smb_tpos125_pdu_count_2op`（T118/T119 借认证族例，见 §3.5） |
| 7.7 异常路径 | 12 | 合入 + 1 拆分 | terr126/128/129/130/131/132/133/134/136/139/140a + 拆分 `smb_terr137_138_td_logoff_cmd` |
| 7.8 边界 | 13 | 合入 | `smb_tpos141_empty_filename`…`smb_tpos155_fileid_user` |
| 7.9 多会话与多流 | 5 | 拆分 3 例（→6 点）+ 合入 2 例 | 拆分 `smb_tpos156_157_*`/`158_170a_*`/`161_162_*`；合入 `smb_tpos164_multiflow_msgid_independent`/`smb_tpos167_multiflow_4tuple_independent`（**带顶层 `group_id`，保留**） |
| 7.10 SMB3 高级 | 12 | 拆分 4 例（→8 点）+ 2 合并 | 拆分 `172_185_*`/`178_179_*`/`180_182_*`/`183_184_*`；合并 `smb_tpos_T305c_cap_0202`（§3.2） |
| 7.11 集成 | 9 | 拆分 1 例 + 合入 | 拆分 `smb_tpos187_188_e2e_cmd_parse`；`smb_tpos195a_e2e_fail_spec_reject` 属负例（无 layers，§3.4） |
| 7.12 字段断言 | 14 | 拆分 5 例 + 合入 | 拆分 `196_197_*`/`200_201_*`/`203_206_*`（→4 点）/`207_208_*`；余合入 |
| 7.13 字段断言续 | 15 | 拆分 4 例 + 合入 | 拆分 `209_219_*`/`210_217_*`/`211_218_*`/`213_214_*`/`215_216_*`；余合入 |
| 7.14 Validate 负向 | 16 | 合入（补层链形状，§3.4） | `smb_tneg_T226_dialect_invalid`…`smb_tneg_T239_smb1`（16 例，锚词见 §5.4） |
| 7.15 查询与锁 | 3 | 合入 | `smb_tpos241_query_directory`/`248_query_info`/`253_lock`（T242–T247/T249–T252/T254/T255 零命中，§3.5） |
| 7.16 NBSS 与传输 | 17 | 拆分 6 例（→13 点）+ 4 合并 | 拆分 `256_257_258_*`/`257_258_*`/`259_260_*`/`261_262_*`/`263_266_*`/`264_265_*`；合并 `smb_tpos256_nbss_type`/`261_port_445`/`263_nbss_prefix`/`264_tcp_4way_teardown` |
| 7.17 命令体结构 | 16 | 拆分 2 例（→17 点）+ 1 合并 | 拆分 `smb_tpos271_285_structsize_default`（T271–T285）/`282_283_*`；合并 `smb_tpos_T271_neg_req_structsize` |
| 7.18 综合与回归 | 15 | 合入 | `smb_tpos_T286_protocolid_all_frames`…`smb_tpos_T300_error_cmd_field` + `smb_tpos296_read_fileid_offset` |
| 7.19 dialect 与能力 | 25 | 合入 + 5 合并 | T301–T315 + T305a–d 族；合并 `T301_credit_0202_resp`/`T307_server_caps`/`T310_ctx_offset_aligned`/`T311_salt_len_32`/`T314_0311_preauth_ctx` |

> 全族**零作废的删除面**：除 §3.2 的被并例与 §3.3 的拆分改写外，无一条因「设计错误」删除（§9.14 不许只搬运子集充数）。

### 3.2 13 对重复标记（同设计点两例 → 合并保留一例）

| 设计点 | 例 A（保留） | 例 B（并/作废） | 理由 |
|---|---|---|---|
| T001 | `smb_tpos1_negotiate` | `smb_tpos001_default_dialects` | 同断言面（默认 dialect 集）；A 覆盖面更广 |
| T011 | `smb_tpos11_full_session_ops2` | `smb_tpos011_resp_dialect` | B 的断言（resp dialect）已含于 A 的 resp 断言 |
| T256 | `smb_tpos256_257_258_nbss_default` | `smb_tpos256_nbss_type` | B 的 NBSS type=0x00 并入 A |
| T261 | `smb_tpos261_262_transport_port` | `smb_tpos261_port_445` | 同点 |
| T263 | `smb_tpos263_266_tcp_handshake_psh` | `smb_tpos263_nbss_prefix` | 同点 |
| T264 | `smb_tpos264_265_handshake_teardown` | `smb_tpos264_tcp_4way_teardown` | 同点（挥手 4 包口径需重钉，见 §4.2） |
| T271 | `smb_tpos271_285_structsize_default` | `smb_tpos_T271_neg_req_structsize` | 同点 |
| T301 | `smb_tpos_T301_credit_0202` | `smb_tpos_T301_credit_0202_resp` | 响应面并入请求例（CreditCharge 双面仍需两断言，同例内两断言不违反原子性判据——同一字段同一取值面） |
| T305c | `smb_tpos305c_cap_degrade` | `smb_tpos_T305c_cap_0202` | 同点 |
| T307 | `smb_tpos_T307_server_caps_03` | `smb_tpos_T307_server_caps` | 同点 |
| T310 | `smb_tpos_T310_negotiate_ctx_offset_8b_aligned` | `smb_tpos_T310_ctx_offset_aligned` | 同点 |
| T311 | `smb_tpos_T311_preauth_salt_length_32` | `smb_tpos_T311_salt_len_32` | 同点 |
| T314 | `smb_tpos_T314_0311_must_have_preauth` | `smb_tpos_T314_0311_preauth_ctx` | 同点 |

### 3.3 34 个合并例 → 85 个原子例（§7 原子用例原则：一例只验一个测试点）

| 合并例（存量） | 覆盖设计点 | 拆分后（P5 新建） |
|---|---|---|
| `smb_tpos26_27_setup_cmd_sesid0` | T026/T027 | 2 例 |
| `smb_tpos28_29_setup_sesid_assign_reuse` | T028/T029 | 2 例 |
| `smb_tpos30_31_setup_status_sequence` | T030/T031 | 2 例 |
| `smb_tpos32_33_34_setup_body_fields` | T032/T033/T034 | 3 例 |
| `smb_tpos35_36_setup_sessionflags` | T035/T036 | 2 例 |
| `smb_tpos37_38_channel_capabilities` | T037/T038 | 2 例 |
| `smb_tpos39_40_secmode_signing` | T039/T040 | 2 例 |
| `smb_tpos43_44_ntlm_challenge_auth` | T043/T044 | 2 例 |
| `smb_tpos156_157_multiflow_2_sessions_sesid` | T156/T157 | 2 例 |
| `smb_tpos158_170a_multiflow_treeid_per_session` | T158/T170a | 2 例 |
| `smb_tpos161_162_multiflow_guid_different` | T161/T162 | 2 例 |
| `smb_tpos172_185_preauth_hash_hex64` | T172/T185 | 2 例 |
| `smb_tpos178_179_transform_protocolid` | T178/T179 | 2 例 |
| `smb_tpos180_182_transform_flags_msgsize` | T180/T182 | 2 例 |
| `smb_tpos183_184_signing_flags_signature` | T183/T184 | 2 例 |
| `smb_tpos187_188_e2e_cmd_parse` | T187/T188 | 2 例 |
| `smb_tpos196_197_protocolid_structsize` | T196/T197 | 2 例 |
| `smb_tpos200_201_status_success` | T200/T201 | 2 例 |
| `smb_tpos203_206_cmd_offsets` | T203/T204/T205/T206 | 4 例 |
| `smb_tpos207_208_flags` | T207/T208 | 2 例 |
| `smb_tpos209_219_msgid_offset` | T209/T219 | 2 例 |
| `smb_tpos210_217_treeid_offset` | T210/T217 | 2 例 |
| `smb_tpos211_218_sesid_offset` | T211/T218 | 2 例 |
| `smb_tpos213_214_credits` | T213/T214 | 2 例 |
| `smb_tpos215_216_nextcmd_reserved` | T215/T216 | 2 例 |
| `smb_tpos256_257_258_nbss_default` | T256/T257/T258 | 3 例 |
| `smb_tpos257_258_nbss_len` | T257/T258 | 2 例（与上行重叠 2 点，§3.2 已把 T256 对合并，此处按 NBSS 长度面保留一例） |
| `smb_tpos259_260_nbss_lengths` | T259/T260 | 2 例 |
| `smb_tpos261_262_transport_port` | T261/T262 | 2 例 |
| `smb_tpos263_266_tcp_handshake_psh` | T263/T266 | 2 例 |
| `smb_tpos264_265_handshake_teardown` | T264/T265 | 2 例 |
| `smb_tpos271_285_structsize_default` | T271–T285 | 15 例（逐命令体 StructureSize 各一例） |
| `smb_tpos282_283_write_structsize` | T282/T283 | 2 例 |
| `smb_terr137_138_td_logoff_cmd` | T137/T138 | 2 例 |

> 计数口径：34 个合并例 → **85 个设计点**（30 例各 2 点 + 2 例各 3 点（`32_33_34`/`256_257_258`）+ 1 例 4 点（`203_206`）+ 1 例 15 点（`271_285`）= 60+6+4+15 = 85），逐族相加 17+6+8+2+20+13+17+2 = 85，净增 51 例；其中 5 处点与 §3.2 的重复对重叠（T257/T258/T261/T263/T264/T265/T271 面），实际落例以设计 §7 的 324 点为准逐点建例。

### 3.4 17 例无 `layers`（16 `tneg` + `tpos195a`）

现状 `spec_json` = `{"src_ip": ..., "dst_ip": ..., "smb": {...}}`（无 `layers`）。去向：**合入但必须补层链形状**——负例改为「层链 + 层内非法值」（`{"layers":[{"ip":{...}},{"tcp":{}},{"smb":{"dialects":["0x9999"]}}]}`），并保持 `expect` 只有 `expect_error` + `error_contains`（锚词见 §5.4）。

### 3.5 41 个设计点零命中（P5 必须补例）

`T059/T076/T079/T087/T088/T090/T094/T099/T111/T112/T118/T119/T127/T135/T140/T140b/T145/T146/T159/T160/T163/T165/T166/T168/T169/T170/T193/T202/T242/T243/T244/T245/T246/T247/T249/T250/T251/T252/T254/T255/T315`（按 §7.3/7.4/7.5/7.6/7.7/7.8/7.9/7.11/7.12/7.13/7.15 分布；与 §12.2/§12.3 台账内 32 点部分重叠，union 见 §5.5）。
> 说明：T059/T079/T090/T131/T132 在存量中由对应错误注入例（terr128/terr129/terr130/terr131/terr132）间接承载，但按「一例一点」原子口径仍需在 P5 拆为独立例或在改写时加注记（计为「间接命中」，仍列零命中清单位）。

## 4. 去扁平改写清单（P5 动作，本文只列不改）

### 4.1 改写规则（逐键去向 = 设计 §14.1 表）

| 旧位置 | 新位置 | 例数 |
|---|---|---:|
| 顶层 `src_ip` / `dst_ip` | `layers[i].ip.src` / `.dst` | 279 |
| 顶层 `smb.<34 键>` | `layers[i].smb.<同名字段>` | 279 |
| 顶层 `tcp` 子映射 | `layers[i].tcp.<同名键>` | 1（`smb_tpos268_seq_ack_progression`） |
| 顶层 `group_id` | **保留顶层**（1.11 白名单：跨流绑定框架字段） | 5 |
| `count` | `flow_control.flows` | 0（存量无） |

### 4.2 包数与断言纪律

1. **禁止照抄旧包数**（§14.6）：legacy 挥手 3 包（`internal/protocol/smb/smb.go:310-317`）vs 链路径 tcp 层 4 包（`layer_gen.go` divergence 段）→ 262 例已钉 `packet_count` **必须全量重跑重钉**；断言数值一律以真实 pcap 校准（§9.31/§14.20）。
2. `smb2.*` 字段断言（434 条）与 `frames` hex（220 例）**原样保留**（字段名已实测存在）。
3. 逐字节断言走 `frames` hex 钉（偏移基准 = SMB2 PDU 起点，设计 §6 约定）。

### 4.3 必补的两类链级负例（方案 v2 §2 链级红例必含清单 ①②）

| # | 形状 | 期望 |
|---|---|---|
| ① presence | `{"layers":[{"tcp":{}},{"smb":{}}], "smb": {}}`（层链 + 顶层同名空子映射并存） | 判死；锚词含 `sub-config`（G-SMB-1 实现后） |
| ② 白名单外游离键 | `{"layers":[...], "src_mac": "..."}` / 顶层 `ttl` / 顶层 `smb` 非空 | 判死（1.11–1.13） |

## 5. P3 固定动作（CORE_MEMORY §3.15/A′/B′/§9.52/§3.14/三源）

### 5.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内多轮操作 | 同 TCP 连接内 NTLM 多轮 SESSION_SETUP（Type1→MORE+Type2→Type3→SUCCESS）；同连接多 op 序列（read→write→read）；同会话多 TreeId（S3/S13）与多 FileId | 已覆：T021/T022（多轮）+ T111/T112（多 op）+ T159/T160（多树/多句柄）+ T165/T166（多流区分） |
| ② | 非正常结束 | 9 个 `ErrorOnCommand` 值 × 错误响应 + 跳过规则表拆解（negotiate→直接 teardown；session_setup→仅 LOGOFF；tree_connect→仅 LOGOFF；create→TREE_DISCONNECT+LOGOFF…）；Include* 跳过面 | 已覆：terr126/128/129/130/131/132/133/134/136/137_138/139/140a/042 + T121/T122/T123；**载体会话中断形**（服务端不回、mid-flow FIN/RST）→ 立项 **G-SMB-5** |
| ③ | 长保活 | SMB2 ECHO 保活（0x000D）+ 同连接多事务长保活；TCP keep-alive 归 tcp 层 | **缺例**：设计 §7 零命中、存量零例 → A′ 补例（§5.2）+ G-SMB-5（载体会话中断面） |

无空项。②的载体会话中断面进 B′（G-SMB-5），不删用例。

### 5.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流/地址族/长保活）

**A′（现有引擎可构建 → 324 设计点内已覆 或 A′ 补例，P5 并入）**：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | 19 命令 × req/resp 结构、StructureSize 表、偏移表、字节序（LE/NBSS BE）、字段值域与边界、编码（UTF-16LE/FILETIME/GUID）、错误体形状 | 已覆 T196–T225/T271–T285/T140a/T140b；未覆盖命令成功面 4（FLUSH/IOCTL/ECHO/SET_INFO）与错误码 6 码零例 → A′ 补例（G-SMB-8） |
| 业务 | 会话全流程、多轮认证、错误注入提前拆解、Include* 跳过、多 op 序列、ECHO 保活 | 已覆 T111–T125/terr 13 例；**ECHO 保活与同连接多事务** → A′ 补例 T-22 族 |
| 现网 | Windows/Samba dialect 集与签名策略、IPC$ 管道树连接、445/139 两档 | 已覆 T046–T058/T261/T262；现网取证 → **G-SMB-3** |
| 多流 | 多会话独立 SessionId/GUID/四元组/MessageId、同会话多 TreeId/FileId、并发隔离 | 已覆 T156–T170a |
| 地址族 | IPv4（存量主面）**与 IPv6** | IPv4 已覆；**IPv6 格缺失**（设计 §7 未列 IPv6 例、存量零例：`smb_tpos*` 无 ipv6）→ A′ 补例 **T-21 族**（`[ipv6,tcp,smb]` 同 fixture 同字节口径） |
| 长保活 | ECHO 保活 + 同连接多事务 | A′ 补例（与业务面同组） |

**B′（引擎结构缺口 → D-SMB-1「明确不解决 + 迁入计划」，见设计 §17）**：**G-SMB-1**（层链配置消费 + 顶层子映射判死，P4 首要动作）、**G-SMB-2**（NTLMSSP 权威重叠，跨协议，P4 前必裁）、**G-SMB-3**（现网/MS-SMB3 取证）、**G-SMB-4**（多会话形状与 multichannel 边界）、**G-SMB-5**（载体会话中断/超时/长保活面）、**G-SMB-6**（明确不支持面收口）、**G-SMB-7**（文案口径分裂）、**G-SMB-8**（台账内 32 点覆盖缺口）、**G-SMB-9**（存量改写与重钉）。

### 5.3 3.14 豁免边界审计

本协议**有长连接**（SMB2 over 长生命周期 TCP；会话内多事务），故 `sessions[]` 面**不豁免**——多会话语义由 `flow_control.flows=N` + 逐流独立四元组/状态承担（设计 §13.2 方案 C 裁定；`layer_gen.go` 自述「单会话恒一个 flow」）。多流并发与单消息多载荷两项各至少一例：**多流并发** = T156/T157/T158/T170a（多会话独立状态）+ T165/T166（同会话多树/多句柄区分）；**单消息多载荷** = T294（单 NEGOTIATE 内多 negotiate context）+ T241（单 QUERY_DIRECTORY 响应内多 ID_BOTH_DIR_INFO 条目）+ T293（NTLM 三 blob 序列）。两项均有，无豁免逃逸。

### 5.4 负例锚词与实现口径（G-SMB-7 待统一）

存量 16 例负例锚词（实测）走**实现英文文案**（`internal/protocol/smb/validate.go`）：`dialect 0x9999` / `SMB1 dialect string` / `auth_mechanism must be` / `anonymous auth can only be 1 round` / `AuthRounds must be 1-3` / `ntlm auth can only be 2 or 3 rounds` / `CreateDisposition must be 0-5` / `TreeConnectShare must be UNC path` / `OpType must be` / `ErrorOnCommand must be` / `known NT status code` / `MaxTransactSize exceeds NBSS limit` / `ShareType must be` / `ErrorOnCommand must be set` / `PreauthIntegrityHashAlgorithms only supports 0x0001`。

**设计 §8 的 V1–V37 文案为中文**（如 "dialect %s 不在 MS-SMB2 §3.2.1 允许列表（dialect 0x0202 起算）"）→ 三方口径分裂，处置：**以实现英文文案为锚词权威**，设计 §8 补注英文锚词（G-SMB-7）。另：设计 §5/§8 的 OpType 清单漏 `lock`/`ioctl`（实现 `constants.go:134-145` 含），属设计侧勘误。

### 5.5 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **规范/官方文档反推**（MS-SMB2 §2.2.1.2/§2.2.3–§2.2.19/§3.2/§3.3、MS-FSCC §2.4.18、MS-ERREF、MS-NLMP、RFC 1002），**非**引擎能力面反推；引擎侧仅作现状取证（`registry.go:1028-1065`、`internal/protocol/smb/*`、`cases/smb.json` 279 例、tshark `smb2.*` 533 字段实测）。
- **对账两行**：**规范逻辑点总数 = 112**（设计 §12.1 八项 8 行 + §12.2 命令×终态矩阵 76 格 + §12.3 数据形态变体表 28 行）；**用例覆盖数 = 50**（八项 7 行落点 + 矩阵 22 格 + 变体 21 行），另 **不适用/明确不支持 30**（八项 1 行 + 矩阵 27 格 + 变体 2 行）、**缺口 32**（矩阵 27 格 = SUCCESS 4 + 错误码 7 + 无响应 16；变体 5 行）：50 + 30 + 32 = 112 无遗漏。反查 324/324 ≠ 覆盖全；此对账为覆盖审计的有效口径。
- **台账粒度声明（防误读）**：112 点按设计 §12 的行/格粒度计数（八项按行、矩阵按格、变体按行）——行/格内的子面缺口（如 §12.1 行内 G-SMB-1/2/3、§7 全量 41 个零命中点）另登设计 §17 与本文 §3.5，**不折进 112 点**、也不冒充覆盖。
- **缺口去向**：矩阵无响应列 16 格 → **G-SMB-5**；矩阵命令面 11 格（success 4 + 错误码 7）与变体 5 行 → **G-SMB-8**；8+30+32 = 112 且 32 = 16 + 16（G-SMB-5 覆盖 16、G-SMB-8 覆盖 16）。

### 5.6 三源回指行

MS-SMB2（头布局/命令体/negotiate contexts/状态机）+ MS-FSCC §2.4.18（ID_BOTH_DIR_INFO）+ MS-ERREF（NTSTATUS）+ MS-NLMP（认证内层 token）→ D-SMB-1（设计 §15）→ `trafficgen/test/protocol_pcap/cases/smb.json`（P5 落 324 点）。ID 权威 = 设计 §7（324 = 315 + 9 变体）；对账 324 = 283 已命中 + 41 零命中。**pcap 与 NIC 同一契约**：同一 `spec_json` 走 pcap 输出（`/tmp/mcp-pcaps/smb/`）与 `port_group`/NIC 输出；NIC 例需显式环境开关（沿 T193 口径），且两路断言同一组 `smb2.*` 字段与 `frames` hex。

### 5.7 性能设计与验收（CORE_MEMORY §6.1–6.8 要素）

| 要素 | 内容 |
|---|---|
| 6.1/6.2 性能目标与资源预算 | **协议能力维度**（§10 口径 1）：单流最大 PDU = NBSS ≤ 0xFFFFFF（校验上限 16777215，T152/T236）、READ/WRITE Data 上限由 `MaxReadSize`/`MaxWriteSize` 声明；并发会话数 = `flow_control.flows`；队列/缓冲上限由框架 `buffer_size` 承担（协议侧无自有队列）；**无协议级吞吐承诺数字**（诚实待确认，§6.5：待 P5 基准） |
| 6.3 双路验收 | pcap 输出（`/tmp/mcp-pcaps/smb/`，tshark 校字段+frames hex）与 `port_group`/NIC 输出（tcpdump 抓 `tcp port 445`；无网卡环境按 T193 口径显式开启）同契约同断言 |
| 6.4 实现路径依据 | O(n) 流式：逐 PDU 事件渲染 → tcp 层分段，无全量聚合；内存 = 单流常量 + 单 PDU 缓冲；无锁、无共享可变状态（SessionId 计数器为包级原子）；MSS 分段段数 = ⌈PDU/MSS⌉ |
| 6.5 未实测数字 | 吞吐/延迟/内存上限**未做基准，标待确认**，不写成承诺 |
| 6.6/6.7 性能测试六类 | 基线（T111 全会话）、目标规模（多流 ≥8）、压力上限（PDU 上限 T152/T269 附近）、长时间运行（ECHO 保活多事务，A′ 补例）、并发交错（T156–T170a + `-race` 口径）、资源耗尽/背压（框架 buffer 溢出面，非协议本地）；断言实际吞吐/内存/队列积压，不许只断言"任务没报错" |
| 6.8 | 功能正确但超预算即不合格——验收以 pcap 字段 + 帧字节 + 资源观测为准 |

## 6. P6 修轮：覆盖台账实况与重分类（2026-09-27）

> 本节是 P6 打回修轮（`p6-review.md` G2/G4）要求的台账落纸：**不改契约降要求**，逐条记录 P5 落码实况、逐点重分类与立项。分母冻结口径：`cases/smb.json` **296 例**（279 存量 + P6 补 17 原子例）+ `probe_smb.json` 12 例 = 联合 suite **308 例**。

### 6.1 设计点零命中 6 点逐点重分类（G2）

| 设计点 | 实况 | 分类 | 去向 |
|---|---|---|---|
| T165/T166 | 同会话多树/多句柄区分（与 T159/T160 同根：唯一 TREE_CONNECT/CREATE 块） | **引擎不可表达 → 明确不解决**（入 §17 清单 + G-SMB-10，与 T159/T160 同项） | 「流间区分」面由 T156–T170a 多流例（独立四元组/独立 SessionId）覆盖；句柄面由 T292/T296 显式 FileId 例代表；本项不单独立项 |
| T193 | NIC 双路开关 | **归 NIC 口径** | 契约 §5.7 6.3 行（`port_group`/NIC 输出同契约同断言，环境开关沿 T193 口径）；P6 补 `probe_pcap_nic_consistency`（pcap 路）+ 本节登记 |
| T159/T160 | 同会话第 2 TREE_CONNECT / ops 内第 2 CREATE（多树/多句柄） | **引擎不可表达 → 明确不解决**（入 §17 清单 + G-SMB-10） | 唯一 TREE_CONNECT 块（`layer_gen.go:279-280`）/唯一 CREATE 块（`:303-313`），无第 2 treeID/fileID 面；多树/多句柄需引擎多句柄状态机（framework backlog） |
| T169 | 同连接多事务长保活 | **间接命中 + 补例代表** | `probe_echo_liveness`（多轮 ECHO 同连接）+ `probe_ops_multi_round`（read→write→close 同连接）；纯"多事务长保活"无独立例，由两 probe 例共同代表（注记，不折进 Blocker） |

### 6.2 G-SMB-8 台账 16 点实况

| # | 点 | 实况 |
|---|---|---|
| ① | 未覆盖命令成功面 4（FLUSH/IOCTL/ECHO/SET_INFO） | FLUSH/IOCTL：**引擎可表达**（`layer_gen.go` ops 分支已实现 `flush`/`ioctl`），P6 未补例（低价值，登记进 G-SMB-11 迁移计划）；ECHO：`probe_echo_liveness` 已覆盖；SET_INFO：**引擎不可表达**（ops 模型 `validOpTypes` 无 set_info），入"明确不解决" |
| ② | 未覆盖错误码（0xC0000120/7B/0021/03E3/0080 共 5 + 0xC0000022 存量 terr131/terr132 于 write/close） | **P6 全部补例**：T501（0022/ACCESS_DENIED 于 create，与存量 write/close 面互补）、T502（0120）、T503（007B）、T504（0021）、T505（03E3）、T506（0080），六例各钉 `error_response_status` 与 `smb2.nt_status` 落盘值 |
| ③ | 变体取值面 5 | CreateDisposition 0/3/4/5：**P6 补 4 例**（T510/T513/T514/T515）；CreateAction 其余 3 值：**引擎不可表达**（响应恒 1，`body_create.go:54` 纯函数调用点硬编码）；FileInformationClass 其余类：**P6 补 2 例**（T522/T523）；InfoType 1/2/3：**P6 补 2 例**（T520/T521）；FileInfoClass 其余类：**P6 补 T520 内断言**（3=FileFsVolumeInformation） |
| ④ | 41 设计点零命中（ID 级） | 35 点经 summary/notes **引用面命中**（legacy 存量面，非新引用）；6 点 ID 级零命中按 §6.1 重分类（2 补例/1 归 NIC/2 不解决/1 间接代表，全表已闭） |
| ⑤ | 34 合并例需拆 85 原子例 | **实况：ID 集零增零删（279→279，P5 未拆）**；P6 以独立原子例补 17 例覆盖上述缺口（非改写存量 ID）。拆分改写（改 ID）**需 team-lead 裁定**（涉及 ID 集变更与 248 表重做），本修轮不动 |

### 6.3 13 对重复标记取一实况

实况：13 对**两两并存**（ID 集零删）。理由：两例各自在调试/回归时提供比对价值，删一例收益为零而破坏 ID 集增量证据链。**待裁定**：如果 team-lead 要求严格按 §3.2 执行取一，可另开修轮（需同步 248 表与 `deep_audit` 口径）。

### 6.4 IPv6 族实况

P5 前：仅 `probe_ipv6_session` 1 例。P6 补：`smb_tpos530_ipv6_default_session`（IPv6 载体默认会话，帧偏移 +20）、`smb_tpos531_ipv6_close_session`（IPv6 显式 close，CLOSE 恰一对）、`smb_tpos532_ipv6_netbios_139`（跨族组合面：IPv6 + 139 载体），family 共 4 例（含 probe）。**口径**：IPv6 族例覆盖「地址族」面，不代表 T165/T166 的同会话多树/多句柄面（该面已按 §6.1 并入 G-SMB-10）。

### 6.5 补例清单（P6，17 例）

| ID | 面 |
|---|---|
| `smb_tpos501_err_create_access_denied` … `smb_tpos506_err_write_bad_netpath` | 错误码面 6 例（0xC0000022/0120/007B/0021/03E3/0080） |
| `smb_tpos510_disposition_0` / `513/3` / `514/4` / `515/5` | CreateDisposition 变体 4 例 |
| `smb_tpos520_query_info_filesystem` / `521_query_info_security` | InfoType 1/2 + FileInfoClass 变体 2 例 |
| `smb_tpos522_query_directory_infoclass_1` / `523_infoclass_2` | FileInformationClass 变体 2 例 |
| `smb_tpos530/531/532_ipv6_*` | IPv6 族 3 例 |

### 6.6 prose 口径（G4）

存量例 summary/notes 中的包数 prose 与 pin 矛盾（如 T144/T158/T011，43 处），pin 经 tshark 复核正确、prose 为存量残留；**P6 未全量刷新**（改 43 例 prose 属批量文本工程，不动断言），登记为 G-SMB-12 迁移项（P5 分批改写遗留口径）。

## 7. 修订记录

- v1.0.1（2026-09-27）：P6 修轮——新增 §6 覆盖台账实况与重分类（零命中 6 点逐点重分类、G-SMB-8 台账 16 点实况、13 对取一实况、IPv6 族实况、P6 补 17 例清单、G4 prose 口径登记）；分母冻结口径更新为 296+12=308。
- v1.0.0（2026-09-26）：P1–P3 产物。建立 324 设计点分组索引（§2）、存量 279 例逐族去向审计（§3：232 直接合入 / 34 拆分→85 点 / 13 合并取一 / 41 零命中补例）、去扁平改写清单（§4）、P3 固定动作（§5：§3.15 三项 / A′/B′ / 3.14 / 9.52 对账 112=50+30+32 / 三源回指 / 性能要素）。**如实记录**：层链配置今天跑不通（G-SMB-1）、NTLMSSP 权威重叠（G-SMB-2）、锚词中英分裂（G-SMB-7）；未运行任何 suite。

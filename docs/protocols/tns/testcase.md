# TNS（Oracle Net / SQL*Net）测试用例契约

> 版本：v1.1.0（2026-09-30，层链迁移审计版）
> 配套设计：`docs/protocols/tns/design.md`（D1–D8）
> 机器契约：`trafficgen/test/protocol_pcap/cases/tns.json`
> 历史参考：`_archive_31-tns-testcase.md`、`docs/protocol-designs/90-tns-testcase.md`
> 状态：只做文档与用例形状核对；本分支未运行 suite/MCP，不宣称任何 pcap 或 NIC 结果。

## T1 形状与执行边界

现行 JSON 为 **24 例 = 14 正 + 10 负**，而历史设计契约是 **26 个目标 ID = 18 正 + 8 负**；两者不是同一清单。JSON 已落地的 24 个 ID 逐一列于 §T2；历史目标中的 `tns_multi_flow`、`tns_ttc_types_legacy`、`tns_nic_path`、`tns_multi_query_rounds`、`tns_abort_rst` 等未落地 ID 不得伪装为现行机器用例。A′ 仅指向现有负例与缺口：状态机/方向由 `tns_neg_state_skip`、`tns_neg_server_type_in_c2s`、`tns_neg_bad_direction` 承载，多流由 `tns_dyn_srcport` 承载；其余 A′ 目标登记到设计 G-TNS-1/2/3/6/8/11，不扩写 JSON。

地址只住 `layers[].ip`，端口只住 `layers[].tcp`/`layers[].udp`，数量走策略 `flow_control` 或用例兄弟键 `strategy_fc`；正例 `spec_json` 顶层只有 `layers`。`tns_neg_presence_top_level_tns`（顶层空 `tns`）与 `tns_neg_stray_src_mac`（顶层 `src_mac`）是故意保留的判死输入，不得清洗成正例。

本车道不启动服务、不调用 MCP，因此所有包数、字段值和 frames 断言均来自设计值与历史基线，标注 `pending-suite`，必须由真实 pcap 校准后才能宣称为已验证。

## T2 原子 ID 与包数

| # | ID | 类型 | 场景 | 包数 |
|---:|---|---|---|---:|
| 1 | `tns_connect_accept` | 正 | CONNECT→ACCEPT→DATA×2，1521 | 11 |
| 2 | `tns_refuse` | 正 | CONNECT→REFUSE，禁 DATA | 9 |
| 3 | `tns_redirect` | 正 | CONNECT→REDIRECT，不重连 | 9 |
| 4 | `tns_ttc_sqlnet_session` | 正 | CONNECT→ACCEPT→DATA×4 | 13 |
| 5 | `tns_ipv6_connect` | 正 | IPv6 CONNECT→ACCEPT | 9 |
| 6 | `tns_multi_session` | 正 | 两会话独立 CONNECT→ACCEPT | 18 |
| 7 | `tns_header_fields` | 正 | 公共头全字段 + DATA flags | 11 |
| 8 | `tns_session_null_default` | 正 | 空层配置默认一条 DATA | 8 |
| 9 | `tns_neg_udp` | 负 | UDP 载体判死 | 0 |
| 10 | `tns_neg_packet_type` | 负 | 未知 type 判死 | 0 |
| 11 | `tns_neg_length` | 负 | 长度下界判死 | 0 |
| 12 | `tns_neg_checksum` | 负 | checksum 模式冲突 | 0 |
| 13 | `tns_neg_data_flags` | 负 | 非零 DATA flags | 0 |
| 14 | `tns_neg_state_skip` | 负 | ACCEPT 前 DATA 跳步 | 0 |
| 15 | `tns_neg_server_type_in_c2s` | 负 | 服务端类型出现在 c2s | 0 |
| 16 | `tns_neg_bad_direction` | 负 | 非法 direction | 0 |
| 17 | `tns_neg_presence_top_level_tns` | 负 | 层链 + 顶层空 `tns` | 0 |
| 18 | `tns_neg_stray_src_mac` | 负 | 顶层 `src_mac` 游离键 | 0 |
| 19 | `tns_data_flags_zero` | 正 | DATA flags=0 专项 | 11 |
| 20 | `tns_nonstd_port` | 正 | 目的端口 9999 显式 | 9 |
| 21 | `tns_body_constants` | 正 | 双会话覆盖四类 body | ≥19 |
| 22 | `tns_dyn_srcport` | 正 | `tcp.src_port` inc + flows=2 | ≥18 |
| 23 | `tns_ipv4_baseline` | 正 | IPv4 裸形基线 | 9 |
| 24 | `tns_refuse_session` | 正 | sessions 内 REFUSE | ≥18 |

多会话与多流用例的实际帧数受调度影响，故 #21/#22/#24 用 `min_packets` 下界断言，其余正例用 `packet_count`。**包数公式**（历史口径，待校准）：`3（握手）+ 事件数 + 4（FIN 四包）`，多会话按会话求和。

## T3 正例断言

- 头部通道：`tns.length`（非零或具体值）、`tns.packet_checksum=0x0000`、`tns.header_checksum=0x0000`、`tns.type`（1/2/4/5/6）、`tns.reserved_byte=00`、`tns.data_flag=0x0000`。
- 载体通道：`ip.version`/`ipv6.version`、`tcp.srcport`/`tcp.dstport`/`tcp.flags`，多会话用 `distinct_values` 加 `distinct_exclude` 排除对端固定口。
- 原始字节通道：IPv4 TNS 头起点 54、type 58、reserved 59、header checksum 60、DATA flags 62；IPv6 起点 74、type 78。所有 offset 断言在跑完 pcap 后复钉。
- IPv6 例（#5）断言 TNS 字节不随地址族变化；IPv4 例（#23）提供对称下限基线。
- #21 双会话覆盖 CONNECT/ACCEPT/REFUSE/DATA 四类 body；#22 断言 `tcp.srcport` distinct 为 `12345/12346` 并驱动 `flows=2`。
- 空配置例（#8）证明缺省派生一条 DATA，并断言 `tns.length=10`、`tcp.dstport=1521`。

所有正例的 `expect` 必须同时含数量断言与至少一个字段或 frames 断言；不得只断言"任务未失败"。

## T4 负例与错误传播

负例 `expect` 严格只含 `expect_error` 与 `error_contains`：

| ID | 输入故障 | 锚词 |
|---|---|---|
| `tns_neg_udp` | 链夹 `udp` | `tcp` |
| `tns_neg_packet_type` | `type=127`（数值形） | `type` |
| `tns_neg_length` | `wire_fault.length=7` | `length` |
| `tns_neg_checksum` | disabled 模式下非零 checksum | `checksum` |
| `tns_neg_data_flags` | DATA `data_flags=1` | `data_flags` |
| `tns_neg_state_skip` | ACCEPT 前 DATA | `state violation` |
| `tns_neg_server_type_in_c2s` | ACCEPT 出现在 c2s | `must not appear in the client->server direction` |
| `tns_neg_bad_direction` | `direction:"sideways"` | `direction` |
| `tns_neg_presence_top_level_tns` | 顶层空 `tns` 子映射 | `no longer accepts a top-level tns sub-config` |
| `tns_neg_stray_src_mac` | 顶层 `src_mac` | `config mixes layers with flat four-tuple field src_mac` |

错误必须在层链或 planner/validator 边界拒绝并传播为 task error；不得产出成功 PCAP、completed/0 packet 或只有 TCP 外壳的假成功。锚词必须与实际错误文本一致，不允许放宽为"任务不失败"。

## T5 覆盖与审计

| 审计项 | 结论 |
|---|---|
| ID 数量与顺序 | 24，本文与 JSON 顺序一致 |
| 正/负比例 | 14 / 10 |
| 顶层键 | 正例仅 `layers`；唯二例外是两条故意判死负例 |
| 链形 | `[ip,tcp,tns]` ×23 + `[ip,udp,tns]` ×1（负例） |
| 用例驱动器 | `strategy_fc` 仅出现在 `tns_dyn_srcport`，不混入 `spec_json` |
| 地址族 | IPv4 与 IPv6 各有独立正例 |
| 会话/流 | `sessions[]` 与 `flows=2` 各有正例 |
| 负例纯净性 | 10/10 仅 `expect_error` + `error_contains` |
| JSON 解析 | `python3 -m json.tool trafficgen/test/protocol_pcap/cases/tns.json` |
| 实跑证据 | 本分支未运行 suite/MCP，包数与字段待校准 |

对账：现行 24 例覆盖连接控制、数据 flags、多会话、多流、地址族、动态端口与 10 类错误分支；缺口为七种未实现类型、DATA 负载形态、TNS over TLS、RST 异常终止、非标端口 `decode_as` 与 NIC 路径（见设计 §D8）。

## T6 缺口和执行计划

1. 复核目标层 registry/translation/校验接线（G-TNS-1），使层内 `events`/`sessions` 真正被消费。
2. 失败用例先行补 `sessions[1..n]`、状态机、direction 守卫（G-TNS-2），再补 validator。
3. 裁定并删除 `payload_profile`/`reconnect` 死字段（G-TNS-3），同批改写引用它们的用例。
4. 由通用 schema 门验证顶层 TNS presence 与白名单游离键（G-TNS-4），不新增单协议黑名单。
5. 运行阶段按真实流程执行：建策略建任务 → 引擎落盘 pcap → TShark `tns.*` 与 frames 校准 → 逐条复钉包数与偏移 → NIC 复用同一契约复验。
6. 抓包取得第二来源后，另行设计七种类型与 TTC 负载（G-TNS-6），不得混入当前用例集。

## A′ 去向与 N3 命名对账

历史 26-ID 契约中的四个 A′ 目标不等于现行 JSON 的四个新增正例：

| 历史 A′ 面 | 现行 JSON 承载/去向 |
|---|---|
| 多流 `tns_multi_flow` | `tns_dyn_srcport`（`strategy_fc` flows=2）；不另造 ID |
| 非正常结束 `tns_abort_rst` | 未落地；设计 G-TNS-11/范围边界登记，不能宣称 JSON 覆盖 |
| NIC `tns_nic_path` | 未落地；本车道禁 NIC，归执行阶段缺口 |
| 同连接多轮 `tns_multi_query_rounds` | 未落地；现有 `tns_ttc_sqlnet_session` 只有 DATA×4 事件，不能把历史目标 ID 冒充已存在 |

负例编号按现行 JSON 的实际 ID 对账，不沿用历史表的 T-TNS-N 编号：现行 `tns_neg_length` 是第三个负例位置（N3 位置），`tns_neg_stray_src_mac` 才是旧 26-ID 目标中的 N3 语义（游离键）。两者必须同时保留原始机器 ID；不得为了编号重命名 JSON。



| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | 连接控制三类分支 | CONNECT→ACCEPT / REFUSE / REDIRECT 各有正例 |
| C2 | 数据与 flags | DATA×2、DATA×4、`data_flags=0` 专项与非法 flags 负例齐 |
| C3 | 多会话与多流 | `tns_multi_session`、`tns_dyn_srcport`、`tns_refuse_session` 覆盖会话/流维度；历史 `tns_multi_flow` 未落地 |
| C4 | 地址族与头部字段 | IPv4/IPv6 各有基线；公共头字段与 frames 偏移有专项断言 |
| C5 | 错误处理 | 10 条负例均带锚词，覆盖载体、类型、长度、checksum、flags、状态机、方向、顶层游离键；N3 语义与 JSON 顺序位置分开登记 |
| C6 | 双通道与全量校准 | 文档车道未运行 suite/MCP，故不宣称 pcap/NIC 全绿；待实现与运行阶段补跑 |

## 修订记录

| 版本 | 日期 | 内容 |
|---|---|---|
| v1.1.0 | 2026-09-30 | 层链迁移审计：按现行 24 例（14 正 + 10 负）重写 T1–T6 与 C1–C6；标注两条故意判死负例、`strategy_fc` 驱动键、pending-suite 与未运行边界；不伪造断言数值 |
| v1.0.0 | 2026-09-27 | P1–P3 文档轨初版（协议 #90），建立 26 ID 目标清单与存量 12 例审计 |

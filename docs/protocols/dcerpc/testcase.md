# DCERPC（分布式计算环境远程过程调用，DCE/RPC）测试用例契约

> 版本：v2.1.0（行为面全枚举，ID 权威；静态闭环校准）
> 日期：2026-10-01
> 配套设计：`docs/protocols/dcerpc/design.md` v2.1.0
> 机器契约：`trafficgen/test/protocol_pcap/cases/dcerpc.json`（机读核实：80 例=48 正+32 负；ID 唯一且与本文 §2 同序）
> 状态：文档与当前机器契约静态对账完成；本轮未运行 suite/Go 测试/服务端，未做 PCAP/NIC 验证，不报告运行通过。

## 1. 测试原则

用例从设计 §2–§8 逐项派生；ID 权威=本文 §2（80 例），cases/dcerpc.json 与本文同序同集合（机读已核实 §2 顺序=JSON 顺序、正/负类型一致）。验证先 TCP stream 重组再按 frag_len 切 PDU；TCP record ≠ PDU 边界。auth trailer 只断言 type/level/长度/边界/opaque。正例断言 packet_count、`dcerpc.*` fields + frames offset 54（IPv4 TCP 载体 payload 起点 14+20+20）hex 钉；负例 expect 恰 {expect_error, error_contains} 单锚词。

## 2. 原子用例索引（ID 权威——80 = 48 正 + 32 负）

| # | ID | 型 | 覆盖 |
|---:|---|---|---|
| 1 | dcerpc_epm_ipv4_bind_lookup | 正 | TCP/135 EPM bind→lookup→response 基线（IPv4） |
| 2 | dcerpc_epm_ipv6_bind_lookup | 正 | IPv6 独立 EPM session（ipv6.nxt=6） |
| 3 | dcerpc_dynamic_ipv4_profile | 正 | EPM 查询→动态端口（显式）独立 session 调用 |
| 4 | dcerpc_dynamic_ipv6_profile | 正 | 同上 IPv6 |
| 5 | dcerpc_common_header_fields | 正 | 七型 PDU 混排：ver/type/flags/drep/frag/auth/call_id 逐字段 |
| 6 | dcerpc_bind_multi_context | 正 | 一 BIND 双 context+双 transfer syntax、result 逐项对应 |
| 7 | dcerpc_bind_single_context_min | 正 | 最小合法 BIND（单 ctx 单 syntax） |
| 8 | dcerpc_bind_ack_secondary_address | 正 | secondary address "1025" 长度前缀+对齐 |
| 9 | dcerpc_bind_ack_secondary_empty | 正 | secondary address 空串形态 |
| 10 | dcerpc_bind_ack_rejected_result | 正 | result=2 provider rejection 传播 |
| 11 | dcerpc_bind_ack_assoc_group | 正 | assoc_group_id 显式值回带 |
| 12 | dcerpc_alter_context | 正 | 已绑定 association 新增 context→ALTER_RESP |
| 13 | dcerpc_alter_context_resp_reject | 正 | ALTER_RESP rejected→该 context 后续拒（负例侧呼应） |
| 14 | dcerpc_request_response_ndr | 正 | REQUEST/RESPONSE call_id 同值、opnum、NDR scalar+struct |
| 15 | dcerpc_fault_status | 正 | REQUEST→FAULT status、call 终态 |
| 16 | dcerpc_ndr_pointer_array_union | 正 | pointer referent+conformant array 三计数+union 单 arm |
| 17 | dcerpc_ndr_scalars_hyper | 正 | 8B hyper 对齐/LE |
| 18 | dcerpc_ndr_utf16_string | 正 | UTF-16 max/offset/actual 2B code unit |
| 19 | dcerpc_ndr_conformant_array | 正 | max/offset/actual+元素 LE |
| 20 | dcerpc_ndr_unique_pointer_null | 正 | referent=0 NULL 语义 |
| 21 | dcerpc_ndr_struct_padding | 正 | 尾部 padding 计入 stub |
| 22 | dcerpc_auth_trailer_opaque | 正 | auth_len>0、pad/trailer 闭合、opaque credentials |
| 23 | dcerpc_auth_pad_2bytes | 正 | pad=2 与实际填充一致 |
| 24 | dcerpc_auth_type_level_variants | 正 | type/level 组合矩阵代表值 |
| 25 | dcerpc_multi_context_call_session | 正 | 2 session×2 ctx×并发 2 call 隔离 |
| 26 | dcerpc_fragment_first_last | 正 | REQUEST 拆 2 片 FIRST/LAST+重组 |
| 27 | dcerpc_fragment_three_pieces | 正 | 3 片（首/中/末）flags 矩阵 |
| 28 | dcerpc_multi_pdu_back_to_back | 正 | 多 PDU 背靠背（PDU≠TCP record 观察面） |
| 29 | dcerpc_frag_len_min | 正 | 最小合法 PDU（BIND frag_len 下限附近） |
| 30 | dcerpc_call_id_boundary | 正 | call_id 0 与 4294967295 |
| 31 | dcerpc_call_id_adjacent | 正 | 相邻值 1/2 应答配对 |
| 32 | dcerpc_opnum_boundary | 正 | opnum 0 与 65535 |
| 33 | dcerpc_context_id_zero | 正 | context_id=0 最小值 |
| 34 | dcerpc_alloc_hint_variants | 正 | alloc_hint 0 与≠实际 stub（合法提示） |
| 35 | dcerpc_request_object_uuid | 正 | PFC_OBJECT_UUID 置位+16B object UUID |
| 36 | dcerpc_response_cancel_count | 正 | cancel_count>0 |
| 37 | dcerpc_fault_status_boundary | 正 | status 边界值（rpc_s 域） |
| 38 | dcerpc_empty_stub | 正 | 合法 empty stub |
| 39 | dcerpc_prebound_profile | 正 | fixture 声明 prebound（跳 bind 直接调用合法面） |
| 40 | dcerpc_multi_session_sequential | 正 | 多会话按序整块展开 |
| 41 | dcerpc_concurrent_sessions | 正 | concurrent 交错（up 帧源 IP 交替） |
| 42 | dcerpc_max_xmit_recv_frag | 正 | max_xmit/max_recv 变体（5840/0xFFFF 边界） |
| 43 | dcerpc_epm_tower_variants | 正 | tower 长度/UUID/端口边界（EPM response 内观察） |
| 44 | dcerpc_epm_annotation | 正 | annotation 长度前缀字符串 |
| 45 | dcerpc_bind_ack_reject_then_altctx | 正 | reject 后 ALTER 换 syntax 成功 |
| 46 | dcerpc_large_stub | 正 | 1024B 级 stub（frag_len 扩展） |
| 47 | dcerpc_port_dynamic_declared | 正 | 动态端口显式声明（非 135，tshark DecodeAs 口径） |
| 48 | dcerpc_uuid_encoding_authority | 正 | MS/AD 混合端序 UUID 逐字节钉（编解码权威） |
| 49 | dcerpc_neg_version_not5 | 负 | version≠5 | header |
| 50 | dcerpc_neg_version_minor_not0 | 负 | minor≠0 | version |
| 51 | dcerpc_neg_packet_type_unknown | 负 | 未知 type | packet |
| 52 | dcerpc_neg_packet_type_reserved | 负 | 不产生型（如 SHUTDOWN=6） | packet |
| 53 | dcerpc_neg_flags_first_no_last | 负 | FIRST 置位无 LAST | fragment |
| 54 | dcerpc_neg_flags_last_no_first | 负 | LAST 置位无 FIRST | fragment |
| 55 | dcerpc_neg_drep_not_le | 负 | drep≠10000000 | drep |
| 56 | dcerpc_neg_frag_len_lt16 | 负 | frag_len<16 | frag |
| 57 | dcerpc_neg_frag_len_mismatch | 负 | frag_len≠实际 | length |
| 58 | dcerpc_neg_auth_len_over | 负 | auth_len 越 frag_len-24 | auth |
| 59 | dcerpc_neg_call_id_reuse | 负 | 并发 call_id 撞车 | call |
| 60 | dcerpc_neg_call_mismatch | 负 | 应答 call 与 open 集不符 | call |
| 61 | dcerpc_neg_state_ack_no_call | 负 | 应答无前置请求 | state |
| 62 | dcerpc_neg_state_request_unbound | 负 | bound 前 request | state |
| 63 | dcerpc_neg_context_duplicate | 负 | 同 BIND context_id 重复 | context |
| 64 | dcerpc_neg_context_unknown | 负 | 引用未 accepted context | context |
| 65 | dcerpc_neg_syntax_mismatch | 负 | rejected 后仍用该 context | syntax |
| 66 | dcerpc_neg_uuid_version_missing | 负 | abstract syntax version 缺字段 | uuid |
| 67 | dcerpc_neg_alloc_hint_negative | 负 | alloc_hint 越域 | hint |
| 68 | dcerpc_neg_ndr_alignment | 负 | NDR padding 缺失 | ndr |
| 69 | dcerpc_neg_ndr_array_count | 负 | count 越 stub | array |
| 70 | dcerpc_neg_ndr_union_unknown | 负 | 未知 discriminant | union |
| 71 | dcerpc_neg_ndr_stub_overflow | 负 | stub 越界 | ndr |
| 72 | dcerpc_neg_auth_pad_invalid | 负 | pad_length≠实际填充 | trailer |
| 73 | dcerpc_neg_auth_trailer_over | 负 | trailer 越 frag_len | trailer |
| 74 | dcerpc_neg_auth_verifier_len | 负 | auth_len 与 credentials 不符 | verifier |
| 75 | dcerpc_neg_carrier_layer_missing | 负 | 缺 tcp 载体 | carrier |
| 76 | dcerpc_neg_carrier_udp | 负 | udp 载体声明 | carrier |
| 77 | dcerpc_neg_port_undeclared | 负 | 非默认端口未声明 | port |
| 78 | dcerpc_neg_address_family_mismatch | 负 | IPv4/IPv6 混地址族 | family |
| 79 | dcerpc_neg_uuid_width | 负 | UUID 非 16B 渲染宽 | uuid |
| 80 | dcerpc_neg_assoc_group_width | 负 | assoc_group 超宽 | width |



## 3. 三源回指与测试点清单

三源为：① Open Group C706 §12.5 connection-oriented PDU、NDR/UUID；MS-RPCE §2.2.2.1/§2.2.1.1.1 endpoint mapper 与 UUID；RFC 793 TCP 载体；②设计契约 §0–§15（尤其 §3–§7、§14）；③本仓 `trafficgen/internal/protocol/dcerpc/planner.go`、builder/生成器与注册/翻译/载体校验（`trafficgen/internal/core/layers/registry.go`、`chain_planner_translate.go`、`validate_layers.go`、`complete.go`）。商业行为（Windows RPC 先 135 EPM 查询、再以 dynamic endpoint 建独立 TCP）映射 #1–4、47；无法取到真实 Windows 线字节的项目标记待确认，确认方式为抓取 Windows RPC endpoint-mapper 会话并用 tshark 重组。

| 规范条文 | 业务场景 | 代码分支/断言 | 覆盖或缺口 |
|---|---|---|---|
| C706 §12.5 common header | v5/0、drep、七种 PDU | builder header；#5、29–32、49–58 | 已覆盖；不产生型由 #51–52 拒绝 |
| C706 §12.5.2 BIND/ACK | 单/多 context、syntax、secondary、accept/reject | bind/ack planner；#6–13、45、63–66 | 已覆盖 |
| C706 §12.5.3 call | request/response/fault、call_id、opnum | request planner；#14–15、25、30–37、59–62 | 已覆盖 |
| C706 NDR | scalar/hyper/pointer/array/union/string/alignment | stub 原样与 frames；#16–21、34、68–71 | 字节面已覆盖；NDR 语义由注入负例表达 |
| MS-RPCE endpoint mapper | 135 查询与 dynamic 新连接 | `sessions[].dst_port`；#1–4、47 | 已覆盖；真实产品抓包为待确认 |
| auth verifier | opaque credentials、pad/trailer 长度 | `validateAuth`/builder；#22–24、72–74 | 边界覆盖；不解密凭据 |
| RFC 793 TCP | 重组、record≠PDU、分片 | TCP writer 与重组断言；#26–28、40–41 | 已覆盖 |
| C706 connectionless/UDP | CL profile | 当前 TCP-only 层链 | 缺口 D-DCERPC-1，需先核对 C706 §12.6 再立项 |

清单先行结论：规范字段/状态/错误/形态均在上表落到 ID；每个负例只注入一个 `wire_fault` 或一个自然守卫，断言真实 `error_contains` 锚词，不以“任务未报错”代替结果。协议特有三轴单独钉住：#35 覆盖 `PFC_OBJECT_UUID=0x80` 请求分支；#26–29 对照多片 `FIRST/MID/LAST` 与单 PDU `0x03` 闭合标志；#43 覆盖 EPM 真 tower 的 floor/UUID/端口结构，而非仅把 tower 当 opaque stub。代码依据分别为 `builder.go` 的 `pfcObjUUID`/`buildRequest`、`buildEventFrames` flags，以及 `casegen_test.go` 的 `epmTowerResp` 构造。

## 4. 颗粒度、三类场景与 §3.15

- 数据场景：#17 的 8B 对齐、#18 UTF-16 2B code unit、#19 三计数数组、#20 NULL referent、#21 padding、#29 frag 下限、#30–34 边界、#42 max xmit/recv、#46 large stub、#48 UUID 混合端序；负向 #49–58、#66–80 覆版本、长度、域宽、NDR、auth、载体与地址族。
- 业务场景：#1–4 EPM→dynamic；#6–13 协商与拒绝；#14–15 调用终态；#25 多 session/多 call；#26–28 分片与背靠背 PDU；#40 顺序会话；#41 交错会话。两个三动作复合流为 #1（bind→lookup→dynamic call）和 #25（两 session×context×call）。
- 现网场景：#1–4 主流 EPM 双栈；#22–24 opaque auth；#40–41 多会话顺序/交错；#45 reject 后换 context；#47 显式 dynamic port。真实 Windows 版本/代理/NAT 字节仍待抓包确认，不能由本地生成器冒充现网证据。
- 动态整格：当前 JSON 没有 `flows>1` 或策略对象（机读：`strategy`/`flows`/`count`/`flow_control` 出现 0 次）；因此五策略动态字段没有已覆盖格，不把静态例宣称为动态覆盖。设计已登记 D-DCERPC-3；待 resolver 落地后，必须分别增加 `ip/tcp` 四元组及 `sessions[].src_port/dst_port` 的 fixed/inc/rand/list/pattern，并以流序号、seed、回绕断言。
- §3.15：同连接多轮操作 = #5/#25/#28；非正常结束 = #10/#13/#15 以及负例 #59–65；长保活 = 当前 DCE/RPC 生成器没有 keepalive/长闲置时序，立项 D-DCERPC-2（需 C706/MS-RPCE 现网抓包确认 keepalive 语义后再落例）。该项不是空白，已登记编号与确认方式。

## 5. 负例契约与断言边界

#49–80 的 `expect` 恰含 `expect_error`、`error_contains` 两键（机读 32/32）；32 个锚词与设计 §7 的 `DescribeDCERPCWireFault`/planner 错误路径及链级载体校验一致（其中 29 例走 `wire_fault` 注入，`carrier_layer_missing`/`carrier_udp`/`address_family_mismatch` 3 例走链级自然形状：`[ip,dcerpc]` 缺 tcp、 `[ip,udp,dcerpc]` udp 载体声明、混合地址族）。负例不含 `packet_count` 或 `frames` 成功断言：创建期拒绝以错误锚词为唯一可观察结果，链级载体/地址族拒绝不产生任务 pcap。正例 `expect` 均为 `{fields,frames,packet_count}` 三键（机读 48/48），同时断言 packet_count、`dcerpc.*`/`tcp.*`/`ipv6.*` 字段或 offset 54 frames；TCP stream 先重组，再按 `frag_len` 切 PDU。harness 无法独立断言真实 TCP segment 边界、包间时序及 opaque credential 内容，故以 frames/字段和“PDU≠record”可观察面替代并明确边界。

## 6. 存量逐条审计与 JSON 对账

80 条存量 ID 全部纳入 §2：#1–48 正例合入，#49–80 负例合入；0 条作废，0 条仅等价覆盖，旧占位 `dcerpc_neg_unregistered` 已随注册移除。机读核实：JSON 80 条，正例 48、负例 32；ID 集合与 §2 同序；正例顶层 `spec_json` 仅 `{layers}`（48/48），层序全部 `[ip,tcp,dcerpc]`（48/48）；负例 `expect` 仅 `{expect_error,error_contains}`（32/32），`spec_json` 仅 `{layers}`（32/32）；负例层序 30×`[ip,tcp,dcerpc]`+1×`[ip,dcerpc]`（缺 tcp）+1×`[ip,udp,dcerpc]`（udp 声明）。6 例动态端口正例（dynamic_ipv4/ipv6、multi_context_call_session、multi_session_sequential、concurrent_sessions、port_dynamic_declared）通过 `sessions[].dst_port` 住在 dcerpc 层结构中，未游离到顶层；`decode_as` 顶层键仅这 6 例使用。

| 对账项 | 结果 | 证据 |
|---|---:|---|
| JSON 总例数 | 80 | `cases/dcerpc.json` 顶层数组（机读核实） |
| 正/负 | 48 / 32 | §2 ID 49 起为负例；机器扫描 `expect_error` |
| ID 集合/顺序 | 80/80 | testcase §2 与 JSON `id` 顺序一致（机读逐位比对） |
| 正例顶层白名单 | 48/48 | 每个 `spec_json` 仅 `layers`；层序全部 `[ip,tcp,dcerpc]` |
| 正例 expect 键 | 48/48 | 均为 `{fields,frames,packet_count}` 三键 |
| 负例严格键 | 32/32 | `expect` 仅两键；`spec_json` 仅 `layers`，其中 29 例带 `wire_fault`、3 例链级自然形状 |
| summary T-去向 | 不适用 | 本协议不使用独立 T-编号，主索引为 testcase §2 的 80 ID |

## 7. 覆盖反查建议（本轮不跑 suite）

1. 机读断言 JSON 数量=80、ID 与本文 §2 完全同序；正/负=48/32。
2. 正例 `spec_json` 顶层键集合仅 `{layers}`；层序为 ip/ipv6→tcp→dcerpc，负例仍走同一任务提交入口。
3. 负例 `expect` 键集合仅 `{expect_error,error_contains}`，每个锚词与 `DescribeDCERPCWireFault` 或 planner 自然拒绝文案相同。
4. 抽 #1、#25、#41：分别核对 EPM/dynamic、会话隔离、交错源地址；抽 #26、#27 核对 FIRST/MID/LAST；抽 #48 核对 UUID 混合端序 frames。
5. 性能六类需在代码阶段经 pcap/NIC 两路测量；本次按任务要求不运行 suite。

## 12. 层链迁移审计（T1-T6，静态收口）

| ID | 测试审计结论 | 证据 |
|---|---|---|
| T1 | JSON 可解析、ID 唯一且与本文 §2 同序；总量 80，正/负 48/32 | 当前 `cases/dcerpc.json` 机读对账 |
| T2 | 正例与负例均从 `layers` 入口提交；48 个正例严格 `[ip,tcp,dcerpc]` | §6 对账表；负例链级形状按故障保留 |
| T3 | 32 个负例保留故意错误输入；`expect` 恰为 `{expect_error,error_contains}` | 29 个 `wire_fault` 注入 + 3 个自然载体/地址族负例 |
| T4 | 地址只在 `ip` 层、端口只在 `tcp` 层、业务只在 `dcerpc` 层；IPv6 仍按实际 JSON 走 `ip` 内地址 | 全量 `spec_json` 顶层白名单与层序审计 |
| T5 | PFC_OBJECT_UUID、单 PDU FIRST/LAST 闭合、EPM tower 三个协议特有观察面分别有独立断言 | #35、#28–29、#43；代码锚词见 §3 |
| T6 | 本轮只做静态对账，未改变字段、帧断言或负例语义 | 设计 §16；三文件 diff 与 JSON 机读核对 |

## 13. 六项测试覆盖清单（C1-C6）

| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | JSON 可解析、80 个 ID 唯一且与 §2 同序 | 已静态对账，80/80 |
| C2 | 严格层链、地址/端口/业务归属和顶层白名单 | 48 正例全 `[ip,tcp,dcerpc]`；负例故障形状保留 |
| C3 | PFC_OBJECT_UUID=0x80、单 PDU flags=0x03、分片 FIRST/MID/LAST、EPM 真 tower | #35、#26–29、#43 分别覆盖；代码锚词 `pfcObjUUID`、`buildEventFrames`、`epmTowerResp` |
| C4 | 32 个负例的单故障/自然载体分类与双键断言 | 29 注入 + 3 自然形状；32/32 `expect` 恰两键 |
| C5 | ID、summary、`error_contains` 与设计/代码锚词交叉一致 | §2、§5、设计 §7 与 `DescribeDCERPCWireFault` 对账 |
| C6 | pcap/NIC 双输出与 suite 全量执行状态如实登记 | 本轮未运行；不得宣称运行通过，待后续执行阶段完成 |

## 14. 修订记录

- v2.1.0（2026-09-30）：按 CORE §4/§3.15/§9 补三源回指、测试点清单、三类场景、动态覆盖边界、§3.15 长保活立项、负例契约和 80 例逐项 JSON 对账；未改 cases 语义，未运行 suite；自审 2 轮，末轮干净。

## 9. 簇级断言要点

- **①双 profile×地址族（1-4）**：EPM 会话 BIND interface E1AF8308-...A0FA v3.0 + opnum=2 lookup；dynamic 会话端口显式且≠135；两 session call_id/assoc/ctx 不串用；IPv6 断言 ipv6.nxt=6。
- **②common header（5、29-32）**：16B 逐字段；frag_len 含全部；call_id 0/最大/相邻。
- **③④⑤BIND/ALTER/调用（6-15、35-38、42、45）**：context 编码/结果对应/FAULT 终态/empty stub 合法。
- **⑥NDR（16-21）**：对齐 padding 计入 stub、pointer NULL 语义、array 三计数、union 单 arm、UTF-16 code unit。
- **⑦auth（22-24）**：pad 0-3 与实际一致、credentials opaque presence/length。
- **⑧分片与多 PDU（26-28）**：FIRST/LAST 闭合、同 call_id、背靠背多 PDU。
- **⑨多会话多调用（25、40-41）**：会话整块展开/交错、并发 call distinct。
- **⑩UUID 权威（48）**：混合端序逐字节。
- **⑪负例（49-80）**：一行一注入单锚词；expect 恰两键。

## 10. 断言通道纪律

fields 优先 `dcerpc.*`（P4 前用 `tshark -G fields | grep dcerpc` 实证；不存在时退化 `tcp.*`+`tcp.payload` 偏移断言，帧 hex 权威=frames offset 54 逐字节钉）。多出现字段按帧逗号并集断言（bacnet P5 先例）；`frag_len` 断言走 fields 或帧字节（dissector 计算值口径先跑后钉）。has_payload（frame.len>80）不适用短 PDU 帧——不设。动态端口例用 decode_as（顶层键）。

## 11. 存量审计

占位 1 例 `dcerpc_neg_unregistered`（旧扁平形 spec）随注册移除（契约 §1）；无存量语义用例。

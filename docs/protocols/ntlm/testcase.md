# NTLM 测试用例契约（文档轨）

> 版本：v1.2.0（2026-09-30）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/ntlm.json`  
> 依据：MS-NLMP、MS-SMB2 §3.2.5.3/§3.3.5.2.4、RFC 4178、RFC 4559、RFC 2743。当前是否通过 suite 以真实流程结果为准。

## T1 形状、来源与执行边界

本清单从规范字段/状态、设计契约 D1–D8 和已确认的现网核对计划派生。21 个唯一 ID 按 JSON 顺序排列：15 个正例、6 个负例。正例 spec_json 全部使用严格层链：地址在 `layers.ip`，端口在 `layers.tcp`，业务在 `layers.ntlm`；顶层不出现旧地址、端口、count 或协议子映射。当前不把静态 JSON 或未知层拒绝当作 NTLM 行为通过。

## T2 ID 与数量清单

| # | ID | 类型 | 目标 packet_count |
|---:|---|---|---:|
| 1 | `ntlm_smb_ipv4_v2_basic` | 正 | 11 |
| 2 | `ntlm_smb_ipv6_v2_basic` | 正 | 11 |
| 3 | `ntlm_http_negotiate_v2` | 正 | 11 |
| 4 | `ntlm_negotiate_flags_version` | 正 | 15 |
| 5 | `ntlm_challenge_target_info` | 正 | 11 |
| 6 | `ntlm_authenticate_security_buffers` | 正 | 11 |
| 7 | `ntlm_ntlmv2_blob_av_pairs` | 正 | 11 |
| 8 | `ntlm_mic_session_key_opaque` | 正 | 11 |
| 9 | `ntlm_spnego_outer_separation` | 正 | 11 |
| 10 | `ntlm_multi_session_isolation` | 正 | 15 |
| 11 | `ntlm_multi_flow_streams` | 正 | 17 |
| 12 | `ntlm_retry_auth_failure` | 正 | 13 |
| 13 | `ntlm_record_boundary_offsets` | 正 | 15 |
| 14 | `ntlm_pcap_nic_consistency` | 正 | 11 |
| 15 | `ntlm_http_negotiate_v6` | 正 | 11 |
| 16 | `ntlm_neg_message_truncated` | 负 | 0 |
| 17 | `ntlm_neg_security_buffer` | 负 | 0 |
| 18 | `ntlm_neg_offsets_overlap_overflow` | 负 | 0 |
| 19 | `ntlm_neg_flags_target_info` | 负 | 0 |
| 20 | `ntlm_neg_v2_blob_av_pairs` | 负 | 0 |
| 21 | `ntlm_neg_carrier_profile` | 负 | 0 |

正例必须在实现后断言 packet_count/min_packets、carrier、方向、stream 和稳定 raw frame；动态值只用 presence/nonzero/distinct/same_as/length。当前生成器已注册 NTLM 层并提供缺省 SMB2 档，但本文件仍不把静态 JSON 或单元测试结果冒充 suite/PCAP/NIC 运行通过。负例执行期 expect 只能含 `expect_error`、`error_contains`。

## T3 数据与业务测试点

| 测试面（规范要求） | 用例 | 必须观察的结果 |
|---|---|---|
| 三消息与状态 | #1/#2/#3/#12/#15 | Type 1→2→3；SMB2 MORE→SUCCESS 或 HTTP 401→2xx；retry/最终拒绝不假成功 |
| SecurityBuffer | #6/#13 | Len/MaxLen/Offset little-endian，Len≤MaxLen，边界不越界/重叠，空 LM 不冒充 NT response |
| flags/Version/编码 | #4 | Type 1/2/3 交集；Version 仅声明时 8 bytes；UTF-16 长度为偶数 |
| TargetInfo/AV_PAIR | #5/#7 | AvId/AvLen/value 边界，EOL 收尾；NTLMv2 proof 16 bytes + blob |
| MIC/session key | #8 | 16-byte MIC/opaque key 的长度与边界；不比较无授权密钥值 |
| SPNEGO 外层 | #9 | OID、ASN.1 outer 与 inner NTLMSSP 起点分离 |
| 地址族 | #1/#2/#3/#15 | IPv4/IPv6 × SMB/HTTP 四格独立，不能以一族代表另一族 |
| 多会话/多流/分段 | #10/#11 | session、四元组、challenge 独立；按 TCP stream 重组后保持顺序 |
| PCAP/NIC | #14 | `tcp port 445` 或 `tcp port 80/443` 下 carrier、方向、token 长度/raw bytes 一致 |

## T4 失败路径与错误锚词

| ID | 故障输入 | `error_contains` 允许锚词 |
|---|---|---|
| `ntlm_neg_message_truncated` | 固定头/Type 1/2/3 截断 | `message`、`signature`、`truncated` |
| `ntlm_neg_security_buffer` | Len/MaxLen、Unicode 或承载非法 | `buffer`、`length`、`unicode` |
| `ntlm_neg_offsets_overlap_overflow` | 越界、回绕、字段重叠 | `offset`、`overflow`、`overlap` |
| `ntlm_neg_flags_target_info` | flags 不兼容、TargetInfo/EOL 非法 | `flags`、`target`、`capability` |
| `ntlm_neg_v2_blob_av_pairs` | proof/blob/AV_PAIR 非法 | `response`、`blob`、`av` |
| `ntlm_neg_carrier_profile` | 非 TCP、错误端口、SMB/HTTP/SPNEGO 混用 | `carrier`、`profile`、`spnego`、`transport` |

每个负例必须在 planner/validator 失败并传播 task error；不得产生成功 PCAP、`completed/0 packet` 或仅有承载外壳的假成功。

## T5 复杂场景、长连接与缺口

NTLM 有长连接载体，故 `sessions[]` 不豁免。多轮认证由 #1/#2/#12 覆盖，非正常最终拒绝由 #12 覆盖；载体无响应、FIN/RST、代理/CONNECT、TLS opaque 属 G-NTLM-5。多会话/多流由 #10/#11 覆盖，单消息多载荷由 #5–#8 覆盖。NTLMv1/LM 属 G-NTLM-6，不能从 NTLMv2 正例推断覆盖。

现网行为核对清单：Windows/AD、Samba、impacket 的 SMB2/SPNEGO 与裸 NTLMSSP，以及 IIS/curl HTTP Negotiate；需授权回环抓包或官方文档证据后逐条映射，未确认项保持缺口。

## T6 对账、运行与审计

- 清单出处：规范/官方文档反推（MS-NLMP、MS-SMB2、RFC 4178、RFC 4559、RFC 2743），不是从现有引擎能力反推。
- 逻辑点对账：21 个语义 ID（15 正+6 负）；另有 G-NTLM-1/3/4/5/6 跨切面缺口，不冒充已覆盖。
- JSON 校验：`python3 -m json.tool trafficgen/test/protocol_pcap/cases/ntlm.json`。
- 实现注册后按真实流程执行：MCP 建任务 → 引擎生成 PCAP/NIC → tshark/raw frame 逐字段核对；新增或迁移后必须全量运行，不以增量绿代替。
- 性能验收补齐基线、目标规模、压力上限、长时间、并发交错、背压六类；当前无实测数字，不写承诺。

本版自审：两轮。第一轮逐项核对 T1–T6、21 个 ID、层链顶层白名单、正负 expect 形状和缺口；第二轮复核 packet_count、动态断言边界、失败锚词及未运行声明，末轮干净。

## 静态迁移闭环对账（T1–T6）

| ID | 核对项 | 结论与证据 |
|---|---|---|
| T1 | 数量、ID、顺序、正负分类 | `ntlm.json` 可解析；21/21 ID 唯一且与 §T2 同序；15 正例 + 6 负例。 |
| T2 | 严格层链与顶层白名单 | 21/21 的 `spec_json` 使用 `[ip,tcp,ntlm]`；地址仅在 `ip`，端口仅在 `tcp`，业务仅在 `ntlm`；正例顶层旧键为 0。P-HTTP 的 `http` 可选底座是设计目标形，本批机器用例按现有自封帧实现不添加空 `http` 层。 |
| T3 | 正例可观察断言 | 15/15 正例均有 `packet_count`、非空 `fields`、非空 `frames`；packet_count 序列为 `11,11,11,15,11,11,11,11,11,15,17,13,15,11,11`。 |
| T4 | 负例纯净性与锚词 | 6/6 负例 `expect` 严格为 `expect_error` + `error_contains`，无 packet/fields/frames/notes；锚词与六类 `wire_fault` 及载体拒绝面对应。 |
| T5 | 语义面与缺口去向 | 三消息、双 profile、IPv4/IPv6、多会话、多流分段、重试、边界、SPNEGO、MIC/session-key opaque 均有 ID 落点；代理/中断、现网核对、NTLMv1/LM 等按 G-NTLM-1/3/4/5/6 登记，不机械新增静态例。 |
| T6 | 存量去向与运行边界 | 旧 20/21 例逐 ID 保留，未改写断言或伪造运行结果；JSON/tool 与 diff-check 为静态门，suite/MCP/NIC 本轮未运行。 |

## C1–C6 覆盖闭环

| ID | 覆盖要求 | 静态结论 |
|---|---|---|
| C1 | JSON 语法、ID 唯一、数量对账 | 21/21 可解析且唯一；§T2、设计 §11、JSON 三方同序。 |
| C2 | 层链、地址/端口/业务归属 | 21/21 为 `[ip,tcp,ntlm]`；无正例顶层旧字段；IPv4/IPv6 地址均住 `ip`，445/80 端口均住 `tcp`。 |
| C3 | 规范字段、状态、组合场景 | #1–#15 覆盖 Type 1/2/3、SMB2/HTTP 状态、SecurityBuffer、flags/Version、TargetInfo/AV、blob、SPNEGO、MIC、重试、多会话/多流和四格地址族；不能由正例推断 G 缺口。 |
| C4 | 失败传播与严格双键 | #16–#21 全部仅含严格双键；message/buffer/offset/flags/blob/carrier 六类锚词分别可检索，禁止成功 PCAP 或 `completed/0 packet` 冒充失败验证。 |
| C5 | 同流多轮、非正常结束、长保活 | 多轮/重试与最终拒绝由 #1/#2/#3/#12 覆盖，多会话/分段由 #10/#11 覆盖；载体无响应/FIN/RST、代理/CONNECT/TLS opaque 进入 G-NTLM-5，不用单请求例冒充。 |
| C6 | PCAP/NIC 双路校准 | 本轮只完成静态契约闭环；真实 MCP→PCAP/NIC→tshark 全量执行仍是实现验收条件，不能宣称已通过。 |

### 静态闭环自审

第一轮逐条核对 D/T/C 对应、21 个 ID、层链、packet_count、正负 expect 键集合和锚词；第二轮复核 JSON 字段归属、G 缺口迁入计划、未运行边界及本文件与设计契约的同序关系，末轮干净。

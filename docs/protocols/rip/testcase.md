# RIP 测试用例契约（文档轨）

> 版本：v1.3.0（2026-10-01）
> 机器契约：`trafficgen/test/protocol_pcap/cases/rip.json`（71 例）
> 依据：RFC 1058、RFC 2453、RFC 2080、RFC 4822，以及设计契约 D1–D8。
> 当前状态：52 个正例已静态迁移为 `ip→udp→rip` 严格层链，19 个负例保留单故障输入形状；本版不宣称 PCAP/NIC 已运行。

## T1 形状、来源与执行边界

JSON 是机器权威，当前 71 个唯一 ID 按文件顺序排列：52 正例、19 负例。52 个正例已静态迁移为严格 `ip→udp→rip` 层链：地址在 IP 层、端口在 UDP 层、RIP 业务在 RIP 层；顶层仅保留 `layers`，或框架允许的 `layers + group_id`。原有正例 `count` 均为 1，已删除。19 个负例继续保留 legacy 单故障输入形状，且 `expect` 严格只有 `expect_error` 与 `error_contains`；当前没有故意设计的 presence 负例，G-RIP-3 只登记统一框架规则待补。这是为保留真实拒绝契约，不是成功例旧键残留。当前代码复核仍显示 registry 的 RIP `Fields` 为空、生成 schema 的 `rip.fields` 为空、terminal switch 没有 `case "rip"`，因此本轮只完成静态契约迁移，运行验证待 G-RIP-1/G-RIP-2 接线后进行。

PCAP 和授权 NIC 必须复用同一 JSON 与断言集。历史 `rip.md` 只有 1/1 且早于当前判死基线，无本轮 pcap，不计今日证据。代码阶段必须按 MCP→引擎→tshark 真实流程全量执行；负例必须是真 task error，不得用离线绿或 completed/0 packet 冒充。

## T2 规范测试点与原子 ID

| 测试面 | 覆盖情况 |
|---|---|
| Command Request/Response、v1/v2/ng | 已有对应正例；RIPng Request 属 A′ 缺口 |
| v2 RTE、v1 RTE、RIPng RTE | 已有字段与 raw hex 断言 |
| simple/MD5、认证拆包 | T-POS-8/9/24/25/27/27b |
| request_full、triggered、rounds | T-POS-1/1b/7/13/18/29/30 |
| 组播/广播/单播、split/poison | T-POS-4/5/6/10/12/32、T-ERR-14/15/18 |
| 路由数 0/1/25/26/50/51 | T-EDGE 与 T-POS 拆包族 |
| metric、mask、prefix、AFI、domain 边界 | T-EDGE-1…22 |
| 多路由器 3/8/100 与 group_id | T-POS-16/17/28、T-EDGE-22 |
| 错误传播 | T-ERR 19 行，单故障单例 |

原子 ID 与 JSON 顺序如下（`packet_count` 是 UDP 报文数；负例为 `—`）：

| # | ID | 类型 | 包数 |
|---:|---|---|---:|
| 1 | rip_tpos1_request_full | 正 | 2 |
| 2 | rip_tpos1b_user_routes | 正 | 2 |
| 3 | rip_tpos4_v1_broadcast | 正 | 1 |
| 4 | rip_tpos6_multicast_ttl | 正 | 1 |
| 5 | rip_tpos7_rounds | 正 | 3 |
| 6 | rip_tpos8_simple_auth | 正 | 1 |
| 7 | rip_tpos9_md5_auth | 正 | 1 |
| 8 | rip_tpos27_auth_25_routes | 正 | 2 |
| 9 | rip_tpos27b_auth_26_routes | 正 | 2 |
| 10 | rip_tpos14_ripng | 正 | 1 |
| 11 | rip_tpos10_split_horizon | 正 | 1 |
| 12 | rip_tpos12_poison_reverse | 正 | 1 |
| 13 | rip_tedge6_zero_routes | 正 | 1 |
| 14 | rip_tedge11_default_route | 正 | 1 |
| 15 | rip_tpos33_domain | 正 | 1 |
| 16 | rip_terr14_multicast_overrides | 正 | 1 |
| 17 | rip_tpos5_unicast | 正 | 1 |
| 18 | rip_tpos10_route_poison | 正 | 1 |
| 19 | rip_tpos13_triggered | 正 | 1 |
| 20 | rip_tpos15_ripng_default | 正 | 1 |
| 21 | rip_tpos24_simple_auth_16b | 正 | 1 |
| 22 | rip_tpos29_version_default | 正 | 1 |
| 23 | rip_tpos32_v1_multicast_broadcast | 正 | 1 |
| 24 | rip_tedge7_25_entries | 正 | 1 |
| 25 | rip_tedge19_domain_ffff | 正 | 1 |
| 26 | rip_tedge10_51_entries | 正 | 3 |
| 27 | rip_tedge12_ip_bcast_err | 负 | — |
| 28 | rip_tedge13_mask_zero | 正 | 1 |
| 29 | rip_tedge14_mask_ffff | 正 | 1 |
| 30 | rip_tedge15_mask_noncontig | 正 | 1 |
| 31 | rip_tedge16_ripng_len0 | 正 | 1 |
| 32 | rip_tedge17_ripng_len128 | 正 | 1 |
| 33 | rip_tedge18_ripng_len129_err | 负 | — |
| 34 | rip_tedge1_metric0_err | 负 | — |
| 35 | rip_tedge20_default_routes | 正 | 1 |
| 36 | rip_tedge21_routers_empty | 正 | 1 |
| 37 | rip_tedge22_routers_100_inc | 正 | 100 |
| 38 | rip_tedge2_metric1 | 正 | 1 |
| 39 | rip_tedge3_metric16 | 正 | 1 |
| 40 | rip_tedge4_metric17_err | 负 | — |
| 41 | rip_tedge5_metric255_err | 负 | — |
| 42 | rip_tedge8_26_entries | 正 | 2 |
| 43 | rip_tedge9_50_entries | 正 | 2 |
| 44 | rip_terr10_password_17b | 负 | — |
| 45 | rip_terr11_ip_invalid | 负 | — |
| 46 | rip_terr12_mask_invalid | 负 | — |
| 47 | rip_terr13_nh_v6 | 负 | — |
| 48 | rip_terr15_split_poison | 正 | 1 |
| 49 | rip_terr16_router_empty | 负 | — |
| 50 | rip_terr17_authdatalen0 | 负 | — |
| 51 | rip_terr18_multicast_split | 正 | 1 |
| 52 | rip_terr19_afi_ffff_explicit | 负 | — |
| 53 | rip_terr1_version_v3 | 负 | — |
| 54 | rip_terr3_command_update | 负 | — |
| 55 | rip_terr5_afi3 | 负 | — |
| 56 | rip_terr6_afi_ffff | 负 | — |
| 57 | rip_terr7_auth_sha256 | 负 | — |
| 58 | rip_terr8_auth_v1 | 负 | — |
| 59 | rip_terr9_auth_ng | 负 | — |
| 60 | rip_tpos16_3_routers | 正 | 3 |
| 61 | rip_tpos17_100_routers | 正 | 100 |
| 62 | rip_tpos18_default_routes | 正 | 1 |
| 63 | rip_tpos1b_request_full_4tuple | 正 | 2 |
| 64 | rip_tpos20_50_entries | 正 | 2 |
| 65 | rip_tpos21_51_entries | 正 | 3 |
| 66 | rip_tpos22_host_mask | 正 | 1 |
| 67 | rip_tpos23_ripng_128 | 正 | 1 |
| 68 | rip_tpos25_md5_authdatalen20 | 正 | 1 |
| 69 | rip_tpos28_8_routers | 正 | 8 |
| 70 | rip_tpos30_command_default | 正 | 1 |
| 71 | rip_tpos3_26_entries | 正 | 2 |

## T3 正例断言契约

每个正例必须保留 `packet_count` 和可观察字段/raw frame 断言；不得只断言任务不报错。

- IPv4 RIP 头 offset=42；RIPng IPv6 头 offset=62。v1 首条目从 46，v2 首条目从 66；MD5 trailer 从报文内容的认证长度后开始。
- `rip_tpos1_request_full` 必须验证 Request 头 `01 02 00 00`、自动 Response 头 `02 02 00 00`、两包数量和默认路由族。
- v1/v2/ng 必须分别断言版本、地址族、目标地址和端口；RIPng 只能使用 `ripng.*` 字段。
- 认证必须断言 simple type/password，MD5 key ID/AuthDataLen/sequence/trailer；认证首包最多 24 条，后续包无认证 trailer。
- 组播/广播必须断言 `ip.dst` 与 TTL；单播必须断言用户目标和默认 TTL；split horizon 过滤、poison reverse 改 metric=16、组播跳过过滤分别独立断言。
- 26/50/51 条路由和认证满包必须断言每包数量/长度及首末条目 raw bytes；FlowID/PacketIndex 属内部元数据，PCAP 不可观察，保留单测覆盖声明。
- 动态多 router 必须断言聚合后的 distinct 源端口/group_id，不能硬编码跨流顺序；不把 server 固定端口混入聚合。
- 合法边界必须保留：metric 1/16、掩码 0/全一/非连续、PrefixLen 0/128、domain ffff、密码 16B、AuthDataLen 20。

## T4 负例、失败路径与错误锚词

负例 `expect` 已收敛为严格只含 `expect_error` 和 `error_contains` 两个契约键；故障输入形状仍保留，直到层链接线完成。每例单一故障，经真实任务流程验证失败，禁止成功 PCAP 或 completed/0 packet。

| ID | 故障 | `error_contains` |
|---|---|---|
| rip_terr1_version_v3 | version=v3 | `invalid version` |
| rip_terr3_command_update | command=update | `invalid command` |
| rip_tedge1_metric0_err | metric=0 | `metric must be >= 1` |
| rip_tedge4_metric17_err / rip_tedge5_metric255_err | metric>16 | `metric must be <= 16` |
| rip_terr5_afi3 | AFI=3 | `invalid AFI` |
| rip_terr6_afi_ffff / rip_terr19_afi_ffff_explicit | AFI=ffff | `AFI=0xFFFF is reserved for authentication` |
| rip_terr7_auth_sha256 | auth=sha256 | `invalid auth type` |
| rip_terr8_auth_v1 | v1 + auth | `RIP v1 does not support authentication` |
| rip_terr9_auth_ng | ng + auth | `RIPng does not support authentication` |
| rip_terr10_password_17b | password 17B | `simple auth password must be <= 16 bytes` |
| rip_terr17_authdatalen0 | MD5 AuthDataLen=0 | `md5 auth_data_len must be > 0` |
| rip_tedge12_ip_bcast_err | route broadcast IP | `broadcast address cannot be used as route` |
| rip_terr11_ip_invalid | invalid route IP | `invalid IP address` |
| rip_terr12_mask_invalid | invalid mask | `invalid subnet mask` |
| rip_terr13_nh_v6 | v2 IPv6 next hop | `next_hop must be IPv4` |
| rip_terr16_router_empty | empty router object | `at least one field must be non-empty` |
| rip_tedge18_ripng_len129_err | PrefixLen=129 | `prefix_len must be <= 128` |

## T5 覆盖、三源、性能和真实流程

规范逻辑点来源是 RFC 四篇和设计 D1–D8，不是从现有 JSON 反推。当前 71 例覆盖：52 正、19 负；数据边界、三版本、认证、拆包、多 router、组播/单播和过滤族均已登记。RIP 无连接内多会话；rounds、多 router、拆包承载 §3.15 等价面。RIPng Request、业务动态五策略、真实设备抓包、MD5 真 HMAC、并发交错仍是缺口，不得报成已覆盖。

性能六类计划：单报文基线；50/51 路由目标规模；25 条满包与 100 router 压力；rounds 长序列；多 router 交错观测；队列/缓冲背压与失败传播。验收必须测实际包数、字段、长度、内存/队列与错误终态，不只测 race 或“不报错”。

## T6 存量审计、缺口、执行计划与 C1–C6

### 存量审计

71/71 例语义保留，0 作废。当前 52 正例已清零顶层 `count`/`src_port`/`rip` 等旧键：地址、端口和业务键均已进入对应层；4 个正例保留框架级 `group_id`。19 负例保留单故障输入形状，`expect` 严格仅含 `expect_error` 和 `error_contains`。代码复核确认的当前运行阻塞是 registry `rip.fields={}`、生成 schema 同样为空、terminal translate 无 `case "rip"`（G-RIP-1/G-RIP-2）；接线完成后全量 MCP 跑包、先跑后钉。

### 缺口表

| 缺口 | 现象 | 计划 |
|---|---|---|
| G-RIP-1 | registry 无 RIP Fields，层内业务键被拒 | 代码阶段补 13 个业务字段并重跑 schema |
| G-RIP-2 | translate 无 RIP 分支 | 代码阶段增加层内解码 |
| G-RIP-3 | 顶层 RIP presence 当前不判死 | 框架白名单修复后增加 presence 负例 |
| G-RIP-4 | 正例顶层旧键已归零；19 个负例保留 legacy 单故障输入形状 | 接线后只迁移/复核负例所需的 presence 形状；不得把失败输入改成成功层链 |
| G-RIP-5 | RIP 业务动态 allowlist 缺失 | 定语义后补 fixed/inc/rand/list/pattern 矩阵 |
| G-RIP-8 | MD5 真 HMAC 未确认 | 授权设备包或厂商文档确认 |
| G-RIP-9 | 商业行为未本轮抓包 | 授权设备/FRR 对照抓包 |
| G-RIP-10 | 离线 harness 剥层绕过校验 | 跨协议框架票 |
| G-RIP-11 | 结果产物 1/1 且过期 | P5 全量 71 例后重生成 |

### 执行计划

1. 代码阶段补 Fields、translate、schema 和统一 presence 门。
2. 按旧键去向迁移 cases，严格保留 71 个语义 ID；负例只保留单一错误输入。
3. 同代 server 经 MCP 建策略/任务，跑全量 PCAP，tshark 逐字段核对并复算 raw offset。
4. 用同一 JSON 在授权 NIC 路径复验；全量绿后再做覆盖反查和性能六项。

### C1–C6 审查门

| ID | 检查 | 当前结论 |
|---|---|---|
| C1 | JSON 可解析、71 ID 唯一且顺序一致 | 绿：71/71；52 正、19 负；静态扫描通过 |
| C2 | 非负例严格层链、无旧键 | 绿：52/52 正例为 `layers` 或 `layers + group_id`，地址/端口/业务键均入层 |
| C3 | 地址/端口/业务字段归属正确 | 绿：52/52 正例分别落 `ip`/`udp`/`rip` 层；运行解码仍待 G-RIP-1/2 |
| C4 | 19 负例单故障且锚词逐字一致 | 绿：19/19 `expect` 均严格为 `expect_error` + `error_contains`，锚词齐全 |
| C5 | 规范点、字段、边界和错误路径有 ID | 绿（RIPng Request、动态和现网证据登记缺口） |
| C6 | PCAP/NIC 同契约并有本批产物 | 红：未重跑，旧 1/1 不作证据 |

本版自审两轮：第一轮逐项核对 T1–T6、C1–C6、71 个 ID、正负比例、旧键去向和空壳例外；第二轮复核 offsets、认证拆包、负例锚词、未运行边界与不适用声明，末轮干净。

- v1.3.0（2026-10-01）：52 个正例完成严格 `ip→udp→rip` 静态迁移，19 个负例保留单故障输入形状并完成 C4 收敛；运行仍待 G-RIP-1/G-RIP-2。自审两轮，末轮干净。
- v1.2.0（2026-10-01）：复核当前 registry、生成 schema 与 terminal translate，确认空壳阻塞仍在；52 正例不迁移，19 负例保留故障形状。自审两轮，末轮干净。
- v1.0.1（2026-09-28）：文档先行初稿，登记 G-RIP-1…G-RIP-11。

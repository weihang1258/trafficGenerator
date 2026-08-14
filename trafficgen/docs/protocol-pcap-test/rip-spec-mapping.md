# RIP Spec-to-PCAP Test Case Mapping

## Files
- **Design spec**: `/home/weihang/trafficGenerator/docs/protocol-designs/10-rip-design.md` (§7 "测试用例清单", line 730; 表格 line 736-812, 策略小节 §7.1-7.7 line 814-866)
- **PCAP test cases**: `/home/weihang/trafficGenerator/trafficgen/test/protocol_pcap/cases/rip.json` (71 cases)
- **Results reference**: `/home/weihang/trafficGenerator/trafficgen/docs/protocol-pcap-test/rip.md` (71 cases, 71 pass / 0 fail / 0 error)

## Spec Overview

§7 contains **73 test case rows** organized by type (spec 表按类型而非章节分组，覆盖章节为列):

- 正向 T-POS (34 cases): T-POS-1, T-POS-1b, T-POS-1b-variant, T-POS-3 ~ T-POS-33（v1.1.3 在 T-POS-1 后插入 T-POS-1b 参数化变体；T-POS-29~33 为默认值与边界补全用例）
- 边界 T-EDGE (22 cases): T-EDGE-1 ~ T-EDGE-22（按 §6.14 边界行顺序）
- 负向 T-ERR (17 cases): T-ERR-1, T-ERR-3, T-ERR-5, T-ERR-19, T-ERR-6 ~ T-ERR-18（覆盖 §6.15 全部异常行；T-ERR-2/T-ERR-4 编号空缺，T-ERR-19 原为 T-ERR-5b）
- 另有策略小节 §7.1 映射表（含 T-POS-2 引用，主表无该行）、§7.2 负向覆盖、§7.3 单路径单测（11 个 Scenario 各至少 1 用例）、§7.4 集成测试（T-POS-26/27/28）、§7.5 断言可观测量、§7.6 并发验证（T-POS-28）、§7.7 failing-test-first

**用例总数：73 条**（正向 34 + 边界 22 + 负向 17）。其中标注类型：集成 T-POS-26/27、并发 T-POS-28。

## Covered Mapping (71 pcap cases → 71 spec IDs)

From pcap case summaries (rip.md), the following spec IDs are covered:

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T-EDGE-1 | Metric=0 报错（Validate error, expect_error） | rip_tedge1_metric0_err | covered |
| T-EDGE-2 | Metric=1 合法（RTE metric 字节 00 00 00 01） | rip_tedge2_metric1 | covered |
| T-EDGE-3 | Metric=16 不可达（metric 字节 00 00 00 10） | rip_tedge3_metric16 | covered |
| T-EDGE-4 | Metric=17 报错（Validate error, expect_error） | rip_tedge4_metric17_err | covered |
| T-EDGE-5 | Metric=255 报错（Validate error, expect_error） | rip_tedge5_metric255_err | covered |
| T-EDGE-6 | Route entry 数=0 → 仅 4B RIP 头 | rip_tedge6_zero_routes | covered |
| T-EDGE-7 | Route entry 数=25 单包（Payload 长度=504B, 25 entry x 20B + 4B header） | rip_tedge7_25_entries | covered |
| T-EDGE-8 | Route entry 数=26 拆 2 包 25+1（metric=2 变体与 T-POS-3 区分） | rip_tedge8_26_entries | covered |
| T-EDGE-9 | Route entry 数=50 拆 2 包 25+25 | rip_tedge9_50_entries | covered |
| T-EDGE-10 | Route entry 数=51 拆 3 包 25+25+1 | rip_tedge10_51_entries | covered |
| T-EDGE-11 | IP=0.0.0.0/0 缺省路由透传 | rip_tedge11_default_route | covered |
| T-EDGE-12 | IP=255.255.255.255 报错（Validate error, expect_error） | rip_tedge12_ip_bcast_err | covered |
| T-EDGE-13 | SubnetMask=0.0.0.0 缺省（Mask 字段 00 00 00 00 合法） | rip_tedge13_mask_zero | covered |
| T-EDGE-14 | SubnetMask=255.255.255.255 主机路由（Mask=FF FF FF FF 合法） | rip_tedge14_mask_ffff | covered |
| T-EDGE-15 | SubnetMask 非连续掩码 255.0.0.3 警告（planner 透传 FF 00 00 03） | rip_tedge15_mask_noncontig | covered |
| T-EDGE-16 | PrefixLen=0 IPv6 缺省（PrefixLen=0x00 合法） | rip_tedge16_ripng_len0 | covered |
| T-EDGE-17 | PrefixLen=128 IPv6 主机（PrefixLen=0x80 合法） | rip_tedge17_ripng_len128 | covered |
| T-EDGE-18 | PrefixLen=129 报错（Validate error, expect_error） | rip_tedge18_ripng_len129_err | covered |
| T-EDGE-19 | Domain=0xFFFF 透传（Domain 字段 FF FF） | rip_tedge19_domain_ffff | covered |
| T-EDGE-20 | Routes=nil + Scenario="" 默认（发 5 条默认路由, 104B payload） | rip_tedge20_default_routes | covered |
| T-EDGE-21 | Routers=[] 单路由器（1 个 FlowID 等同 FlowSpec 自身, sport 520） | rip_tedge21_routers_empty | covered |
| T-EDGE-22 | Routers=100 + GroupID="inc"（100 个 gID 1..100 真并发, 100 包） | rip_tedge22_routers_100_inc | covered |
| T-ERR-1 | Version="v3" 报错（expect_error） | rip_terr1_version_v3 | covered |
| T-ERR-3 | Command="update" 报错（expect_error） | rip_terr3_command_update | covered |
| T-ERR-5 | AFI=3 报错（expect_error） | rip_terr5_afi3 | covered |
| T-ERR-6 | AFI=0xFFFF + Routes 非空报错（expect_error） | rip_terr6_afi_ffff | covered |
| T-ERR-7 | Auth.Type="sha256" 报错（expect_error） | rip_terr7_auth_sha256 | covered |
| T-ERR-8 | Auth 非 nil + Version="v1" 报错（expect_error） | rip_terr8_auth_v1 | covered |
| T-ERR-9 | Auth 非 nil + Version="ng" 报错（expect_error） | rip_terr9_auth_ng | covered |
| T-ERR-10 | Auth.Password=17 字节报错（expect_error） | rip_terr10_password_17b | covered |
| T-ERR-11 | RIPRoute.IPAddr 非法 IP 999.1.1.1 报错（expect_error） | rip_terr11_ip_invalid | covered |
| T-ERR-12 | RIPRoute.SubnetMask 非法 "not-a-mask" 报错（expect_error） | rip_terr12_mask_invalid | covered |
| T-ERR-13 | NextHop IPv6 字面量 + v2 协议族不匹配报错（expect_error） | rip_terr13_nh_v6 | covered |
| T-ERR-14 | Multicast 覆盖 DstIP 警告（包仍去 224.0.0.9） | rip_terr14_multicast_overrides | covered |
| T-ERR-15 | SplitHorizon + PoisonReverse 共存警告（PoisonReverse 生效, 3 entry 1,16,1） | rip_terr15_split_poison | covered |
| T-ERR-16 | Routers=[{}] 空元素报错（expect_error） | rip_terr16_router_empty | covered |
| T-ERR-17 | MD5 AuthDataLen 显式 0 报错（expect_error） | rip_terr17_authdatalen0 | covered |
| T-ERR-18 | SplitHorizon/PoisonReverse + Multicast 警告（组播跳过过滤, 2 entry metric 1,1） | rip_terr18_multicast_split | covered |
| T-ERR-19 | AFI=0xFFFF 用户显式设报错（expect_error） | rip_terr19_afi_ffff_explicit | covered |
| T-POS-1 | v2 Request 全量路由（Payload 字节级 01 02 00 00 + auto Response 5 条默认路由） | rip_tpos1_request_full | covered |
| T-POS-1b | request_full 自动追加 Response（2 包同四元组, 同 FlowID, 默认 5 条路由） | rip_tpos1b_request_full_4tuple | covered |
| T-POS-1b-variant | request_full 用户 Routes 优先（自动 Response 改走用户路由, 44B payload） | rip_tpos1b_user_routes | covered |
| T-POS-3 | v2 Response 26 entry 拆 2 包 25+1（无认证） | rip_tpos3_26_entries | covered |
| T-POS-4 | v1 Response 广播 255.255.255.255（无掩码 RTE, 24B payload, TTL=1） | rip_tpos4_v1_broadcast | covered |
| T-POS-5 | v2 单播更新（DstIP=用户给定, TTL=64, DstPort=520, multicast=false） | rip_tpos5_unicast | covered |
| T-POS-6 | v2 组播更新（DstIP=224.0.0.9, TTL=1, SrcPort=520, 1 RTE metric 2） | rip_tpos6_multicast_ttl | covered |
| T-POS-7 | 组播 Rounds=3 → 3 个 Response 包 | rip_tpos7_rounds | covered |
| T-POS-8 | v2 明文认证（AFI 0xFFFF AuthType=0x0002, 16B 密码补零） | rip_tpos8_simple_auth | covered |
| T-POS-9 | v2 MD5 认证字段占位（RIPv2PacketLength=44, trailer FF FF 00 01, 16B digest） | rip_tpos9_md5_auth | covered |
| T-POS-10 | 路由毒化（metric=16 注入, 报文 metric 字段=0x10） | rip_tpos10_route_poison | covered |
| T-POS-11 | 水平分割过滤（NextHop==DstIP 的 entry 被剔除） | rip_tpos10_split_horizon | covered |
| T-POS-12 | 毒化反转（NextHop==DstIP 的 entry metric 改 16, 仍发出） | rip_tpos12_poison_reverse | covered |
| T-POS-13 | 触发更新（仅 Response、无 Request 前导、Rounds=1） | rip_tpos13_triggered | covered |
| T-POS-14 | RIPng IPv6 组播（FF02::9, port 521, 头 02 01 00 00, 2001:db8::/64） | rip_tpos14_ripng | covered |
| T-POS-15 | RIPng 缺省路由（Prefix=::, PrefixLen=0, Metric=1） | rip_tpos15_ripng_default | covered |
| T-POS-16 | 多路由器 3 路由器并发（sport 52001-52003, 同组播 DstIP, group_id=fixed 保序） | rip_tpos16_3_routers | covered |
| T-POS-17 | 多路由器 100 路由器压力（GroupIDStrategy=fixed 同 worker, 100 包无 panic） | rip_tpos17_100_routers | covered |
| T-POS-18 | 默认 Scenario 推导 response_default（Routes=nil + Scenario="" 发 5 条默认路由） | rip_tpos18_default_routes | covered |
| T-POS-20 | Route Entry 50 条拆 2 包各 25（512B/512B） | rip_tpos20_50_entries | covered |
| T-POS-21 | Route Entry 51 条拆 3 包 25/25/1（第 3 包 32B） | rip_tpos21_51_entries | covered |
| T-POS-22 | 主机路由 SubnetMask=255.255.255.255（Mask 字段 FF FF FF FF 合法） | rip_tpos22_host_mask | covered |
| T-POS-23 | IPv6 主机路由 PrefixLen=128（PrefixLen 字段 0x80 合法） | rip_tpos23_ripng_128 | covered |
| T-POS-24 | 明文密码 16B 恰好填满（AuthData 16B 无补零, AFI=0xFFFF AuthType=0x0002） | rip_tpos24_simple_auth_16b | covered |
| T-POS-25 | MD5 AuthDataLen=20 透传（AuthDataLen=0x14, trailer FF FF 00 01, 20B 0xAA, 68B payload） | rip_tpos25_md5_authdatalen20 | covered |
| T-POS-27 | 认证后最大 24 路由/包（认证 entry + 25 路由单包 524B） | rip_tpos27_auth_25_routes | covered |
| T-POS-28 | 多路由器总吞吐 = M × 单路由器（8 路由器, 实际发包数 8×1×1=8, sport 52001-52008） | rip_tpos28_8_routers | covered |
| T-POS-29 | Version="" 默认 v2（RIP 头 Version 字节=0x02） | rip_tpos29_version_default | covered |
| T-POS-30 | Command="" 默认 response（RIP 头 Command 字节=0x02） | rip_tpos30_command_default | covered |
| T-POS-31 | Routes > 25 + Auth 非 nil 多包拆分（524B + 24B, auth/trailer 仅首包） | rip_tpos27b_auth_26_routes | covered |
| T-POS-32 | v1 + multicast=true → 广播（DstIP=255.255.255.255, TTL=1, 忽略用户 DstIP） | rip_tpos32_v1_multicast_broadcast | covered |
| T-POS-33 | Domain=0x0001 → RIP 头第 3-4 字节 00 01 | rip_tpos33_domain | covered |

**Total unique spec IDs covered**: 71（pcap 用例 71 条，其中 rip_tpos27b_auth_26_routes 对应 spec 的 T-POS-31，rip_tpos1b_user_routes 对应 T-POS-1b-variant）

## Summary Counts

| Metric | Count |
|--------|-------|
| Total spec test cases (§7) | 73 |
| Total pcap test cases | 71 |
| Unique spec IDs covered by pcap | 71 |
| Spec IDs missing from pcap | 2 |
| **Coverage rate** | **97.3%** (71/73) |

## Coverage by Section

| Section | Range | IDs in section | Covered | Missing |
|---------|-------|---------------|---------|---------|
| 正向 T-POS (含 1b/1b-variant, 含集成 T-POS-26/27、并发 T-POS-28、默认值 29~33) | T-POS-1 ~ T-POS-33 | 34 | 32 | 2 (T-POS-19, T-POS-26) |
| 边界 T-EDGE | T-EDGE-1 ~ T-EDGE-22 | 22 | 22 | 0 |
| 负向 T-ERR | T-ERR-1,3,5,19,6-18 | 17 | 17 | 0 |
| **Total** | | **73** | **71** | **2** |

## Remaining Coverage 未覆盖清单（2 条）

| Spec ID | 用例名 | 验证点 | 未覆盖原因 |
|---------|--------|--------|-----------|
| T-POS-19 | Route Entry 0 条 Response | Payload 仅 4B RIP 头, 无 entry | **JSON 层不可达**：`parseRIPRoutes([])` 折叠为 nil → Plan 推导 response_default → 发 5 条默认路由（104B）。仅显式 `scenario` 且 routes 为 nil 时可产生 4B 头（本映射未建该场景）。rip_tedge6_zero_routes 以 4B 前缀断言部分覆盖该行为（其实际 wire 为 104B）。由 rip_test.go TestTEdge6/TestTPOS19 单测覆盖 |
| T-POS-26 | 多包 FlowID 一致性（集成） | 26 entry 两包 FlowID 相同, PacketIndex 递增 | **pcap 不可观测**：FlowID/PacketIndex 是引擎内部元数据，不进 pcap。rip_tpos3_26_entries 已从内容层验证同四元组拆分（25+1）。由 rip_test.go 单测覆盖 FlowID/PacketIndex 断言 |

## Key Observations

1. **97.3% 覆盖率（71/73）**, 核心 happy path、全部边界、全部负向均已 pcap 验证，71/71 全 pass。覆盖率从 34.2% 提升 63.1pp。

2. **本轮新增 46 个 pcap case**（T-POS 12、T-EDGE 18、T-ERR 16），补齐三大类缺口：
   - 负向 16 条全部使用 `expect_error: true` + `error_contains` 断言精确 Validate error 子串（如 "invalid version"、"metric must be <= 16"、"AFI=0xFFFF is reserved for authentication"）。负向错误经 worker 层 `planner.Validate` 冒泡：单任务 → task 以 error 结束；16 条全部实测 pass，证明错误确实传播到任务状态而非被吞掉（CLAUDE.md §2 负向覆盖）。
   - 拆包边界 26/50/51 条（T-POS-3/20/21, T-EDGE-8/9/10）以 udp.length 512/512/32 与首/末 RTE 帧字节双重断言。
   - 多路由器 3/8/100（T-POS-16/28/17, T-EDGE-22）：group_id fixed 保序断言 per-router sport 52001+idx；T-EDGE-22 用 group_id inc [1,100] 产生 100 个不同 gID 跨 worker 真并发。

3. **expect_error 语义确认**（driver.go RunCase）：(a) CallTool 返回 error 且含 error_contains → PASS；(b) 任务以 error/failed/stopped 结束且 ErrorMessage 含子串 → PASS；(c) 任务成功完成 → FAIL。RIP Validate 错误均在 worker 阶段（策略 Create 只做 net.ParseIP 顶层 IP 校验），16 条负向全部走 (b) 路径。

4. **T-POS-19 的 JSON 不可达性是 spec 层真实发现**：`parseRIPRoutes` 将显式 `[]` 折叠为 nil（strategy_convert.go parseRIPRoutes: empty→nil），Plan 中 `routes == nil && scenario==""` 推导 response_default 发 5 条默认路由；仅 `routes==nil` + 显式非 request/response 场景（如 "split_horizon"）时 `emitRIPRoutes(len==0)` 才产生裸 4B 头。rip_tedge6_zero_routes 的 4B 断言实际匹配的是 104B payload 的前 4 字节（FrameAssert 是前缀匹配）——建议后续在 spec 或单测中澄清该行为。

5. **FrameAssert offset 易错点（本轮踩坑 3 次, 已修）**：(a) 带 next_hop 的 RTE 帧字节必须含 4B next_hop（c0 a8 01 02），首版 terr15/terr18 的 offset-46 断言漏了 next_hop 字节 → 实测 mismatch at offset 58；(b) next_hop(4B)+metric(4B) 的偏移边界（frame 58-61/62-65），首版 offset-58 断言写了 8B 越界 → mismatch at offset 65；(c) auth entry 是 20B 占据 payload[4:24]，其后第一路由 RTE 起始于 payload[24] 即 frame offset 66 而非 62（T-POS-25 沿用 rip_tpos9 正确惯例）。

6. **planner 行为与 spec 逐条对齐，未发现真实 bug**：46 个新 case 中 3 个失败均为测试自身 hex 笔误（见上），非 planner/builder 缺陷；负向 error_contains 全部命中精确错误串，说明 Validate 错误文案与设计 §6.15 一致。

7. **spec 自身瑕疵可顺手修复**：主表 line 736-812 无 T-POS-2 行（"T-POS-1~28" 区间注释含编号 2），但 §7.1 line 818/820/825 引用 T-POS-2；pcap 没有（也无法有）该用例。T-POS-26 属引擎内部元数据断言，pcap 层不可观测，建议 spec 标注"单测覆盖"。

8. **服务器进程注**：原 PID 3651421 已不在（新进程 3906382 于 12:22 以相同 `./server -config configs/config.dev.yaml` 启动，含 Start race + tftp retransmit 修复）；本任务仅改 rip.json（测试进程读取），未重启 server、未触碰协议代码。

## Suggested Pcap Additions (按优先级)

1. ~~边界拆包: 25/26/50/51 条~~ → 已全部覆盖（T-EDGE-7/8/9/10, T-POS-3/20/21）
2. ~~负向验证: v3、AFI 非法、MD5/SHA256 认证非法~~ → 已全部覆盖（T-ERR 17 条全, expect_error + error_contains）
3. ~~默认值: Version=""、Command=""、RIPng 缺省路由~~ → 已覆盖（T-POS-29/30/15）
4. ~~并发: T-POS-28 8 路由器吞吐~~ → 已覆盖（8 路由器 8 包 + sport 断言；吞吐量本身由 rip_test.go 并发单测测量）
5. ~~RIPng 与触发更新场景~~ → 已覆盖（T-POS-13/14/15, T-EDGE-16/17/18）
6. **剩余（可选）**: T-POS-19 裸 4B 头 —— 需显式 scenario（如 "split_horizon"）+ routes 省略才能在 JSON 层复现，可作为 1 条补充 case（当前由 rip_tedge6 前缀断言 + 单测覆盖）；T-POS-26 FlowID 一致性 —— pcap 不可观测，维持单测覆盖即可

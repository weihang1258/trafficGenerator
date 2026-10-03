# SCTP 测试用例契约（文档轨）

> 版本：v1.1.0（2026-09-30）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/sctp.json`  
> 依据：RFC 4960 §3.1–§3.3、§5.1、§6.8、§9.1–§9.2；配套设计：`docs/protocols/sctp/design.md`。

## T1 三源、形状和执行边界

三源为 RFC 4960、设计文档 D1–D8、现有 SCTP pcap/tshark 3.6.14 观测。真实 SCTP 栈和授权 NIC 本轮未重新取证，不能写成已通过。每条 `spec_json` 是可直接提交的策略配置：11/11 顶层只有 `layers`，层链均为 `[ip,sctp]`；地址在 ip，端口和业务字段在 sctp，数量若增加只走 `flow_control`。

正例的 20 条 frames、19 条 fields、8 条 packet_count 断言来自既有磁盘 pcap 的逐条复算；这不是本轮重新运行 suite。随机 Tag、TSN、cookie、HB nonce、IP ID 不做固定字节断言。

## T2 测试点清单和原子 ID

| # | ID | 类型 | 测试点→代码分支→缺口/证据 |
|---:|---|---|---|
| 1 | `sctp_t1_baseline_assoc` | 正 | 四路握手、三路关闭 → planner 基线 → RFC §5.1/§9.2 |
| 2 | `sctp_t2_handshake_bytes` | 正 | 双 Tag、VTag、cookie 参数 → handshake builder → RFC §3.3.2/§3.3.3 |
| 3 | `sctp_t3_data_bidir` | 正 | up/down DATA、PPID → DATA builder → §3.3.1 |
| 4 | `sctp_t4_fragment_flags` | 正 | B/middle/E、TSN 连续 → splitter → §3.3.1 |
| 5 | `sctp_t5_heartbeat_primary` | 正 | 两对 heartbeat → heartbeat builder → §3.3.5/§3.3.6；令牌字节 G-SCTP-3 |
| 6 | `sctp_t6_altpath_multihoming` | 正 | 地址参数、备用源/目的 → AltPath emitter → §3.3.2.1 |
| 7 | `sctp_t7_abort` | 正 | ABORT 替代关闭 → abort branch → §9.1 |
| 8 | `sctp_t8_explicit_tsn_sid` | 正 | TSN/SID/SSN/PPID 全头 → DATA parser → §3.3.1 |
| 9 | `sctp_t9_neg_altpath_v6` | 负 | AltPath IPv6 → Validate → 锚词 `only IPv4 multi-homing` |
| 10 | `sctp_t10_neg_frag_small` | 负 | fragment_size=1 → registry V9 → 锚词 `out of range [16,1000000]` |
| 11 | `sctp_t11_neg_frag_upper` | 负 | fragment_size=1000001 → registry V9 → 同锚词 |

包数：T1/T2=7，T3=9，T4=14，T5=11，T6=9，T7=5，T8=8；均为存量 pcap 复算值。负例不含成功包数或 frames 断言。

## T3 颗粒度、场景和断言边界

数据场景覆盖 chunk 类型、Tag 显式/随机、PPID 0/1000/47、分片 flags、端口、AltPath 地址参数和 fragment_size 边界；未覆盖的空 payload、整除分片、IPv6、动态五策略、chunk 字段越界和 checksum 面均登记设计缺口。业务场景覆盖单关联多 DATA、ABORT、主/备用保活；现网场景仅到本仓库 pcap/tshark，商业或内核栈行为待授权抓包确认。

正交矩阵为：IPv4 主路径 ×（基线/双 Tag/DATA/分片/HB/AltPath/ABORT）；随机与显式字段；正常与错误；单流与待补多流。frames 断言验证原始线字节，fields 断言验证 tshark 可观察值，packet_count 验证总帧数；方向通过帧内 IP/端口排列观察，不依赖生成器 Direction 元字段。随机面不得钉值。

## T4 §3.15 三项

- 同连接/同流多轮操作：T-3 双向 DATA、T-4 连续分片。
- 非正常结束：T-7 ABORT 替代 SHUTDOWN。
- 长保活：T-5 两对主路径 HEARTBEAT，T-6 备用路径探测。

SCTP 无 TCP RST；SACK/ERROR 未接线，因此不伪造其覆盖。

## T5 存量逐条去向

11/11 全部保留；8 个正例删除 `has_handshake`、`negotiated`、`terminates` 三个 TCP no-op 键；3 个负例删除 `notes`，使机器 expect 严格为 `expect_error` 与 `error_contains`；T-6 同时修正错误 notes。无作废、无等价吞并、无迁移例；未来 G-SCTP 缺口须新增 ID，不覆盖现有 ID。

## T6 失败路径、审计和执行计划

T-9 必须在任务期返回 `only IPv4 multi-homing`；T-10/T-11 必须在建链期返回 `out of range [16,1000000]`。三条负例的 `expect` 严格只有 `expect_error` 与 `error_contains`，不含 packet_count/frames。实现阶段按 MCP 建策略/任务 → 引擎生成 PCAP → tshark 逐字段校对；之后在授权网卡 `enp135s0f0np0` tcpdump 复验同一断言集。失败不得报 completed/0 packet 假成功。

| 审计项 | 结论 |
|---|---|
| ID/顺序 | 11 个，JSON 顺序一致 |
| 正/负 | 8/3 |
| 层链/顶层键 | 11/11 `[ip,sctp]`，顶层零游离业务键 |
| 断言 | 20 frames + 19 fields + 8 packet_count；来自既有 pcap，未本轮重跑 |
| 负例 | 3/3 有真实代码锚词，严格两键 |
| 规范/设计映射 | T-1–T-11 逐条回指 D3/D4/D6 与 RFC 条款 |

本版自审：两轮。第一轮逐条核对 T1–T6、三项场景、11 个 ID、正负 expect 和层链；第二轮复核 JSON 实际键、负例锚词、包数声明和未运行边界，末轮干净。

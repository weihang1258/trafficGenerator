# #123 arp（ARP 地址解析协议，RFC 826）测试用例契约

> 版本：v1.0.0（批次二文档车道 P1–P3，as-built 型）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/123-arp-design.md` v1.0.0（D-ARP-1 as-built）
> 旧基线：**本协议无旧编号用例文档**（`docs/protocol-designs/` 无 `NN-arp-testcase.md`）。权威承接 = `docs/TEST_CASES.md` §T-ARP-1…12（已验收清单）+ `docs/CODE_DESIGN.md` §D-ARP-1 P3 清单
> 机器契约：`trafficgen/test/protocol_pcap/cases/arp.json`（**12/12 ID 与本版 §2 一致，顺序一致，已机读实测**；`spec_json` 顶层键 = `{layers}` ×11 + `{layers,arp}` ×1（T-8 presence 判死负例））
> 白话一句：**十二条检查：四条看正常收发（一问一答、28 字节整格、显式地址、单发宣告），八条看胡来能不能被拦下（操作码越界、四种地址格式错、IP 头混入、顶层旧键、静态复制）；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **12 个唯一语义 ID：4 正 + 8 负**（负例 N-1…N-8）。派生规则：设计 §3 每个字段条款、§5 每个事务/自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**（原子性，§7 口径）。

**形状基线（2026-09-29 机读实测）**：12/12 例顶层键 = `{expect,id,proto,spec_json,summary}`；`spec_json` 顶层键 = **`{layers}` ×11 + `{layers,arp}` ×1**（T-8，**presence 判死执法对象**，见 §4 形状说明）——**本协议 11 个非负例顶层零残留**，无 §1 迁移工作量；层形 `[eth,arp]` ×11 + `[eth,ip,arp]` ×1（T-7 拒例）；4 正例 `expect` 键 = `{packet_count, fields, notes, frames}`（**含 notes，非严格三键**，G-ARP-8）；8 负例 `expect` 键 = **严格两键** `{expect_error, error_contains}`（8/8 实测）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`eth.dst/src/type`、`arp.opcode`、offset 14 frames）；NIC 经框架 `port_group` 输出；不设仅单路径可用的断言。**网卡路今日未跑**（设计 §6 如实口径）。

**字段使用分布（机读实测）**：4 个字段名共 8 条——`eth.dst` ×3（T-1 两条 + T-4 一条）、`arp.opcode` ×3（T-1 两条 + T-4 一条）、`eth.type` ×1（T-2）、`eth.src` ×1（T-3）。**TSHARK 基线（本车道实测）**：本机 tshark **3.6.14 有 arp dissector**——`tshark -G fields` 中 `arp.*` **51 个唯一字段**；4 份正例 pcap 全部解码（`frame.protocols = eth:ethertype:arp`，`_ws.col.Protocol = ARP`），**零 malformed**。可用字段通道分级（设计 §9.1）：**已用** = `arp.opcode` + `eth.dst/src/type`；**可用未用（A′）** = `arp.hw.type`（十进制 `1`）、`arp.proto.type`（`0x0800`）、`arp.hw.size`/`arp.proto.size`（`6`/`4`）、`arp.src.hw_mac`/`arp.src.proto_ipv4`/`arp.dst.hw_mac`/`arp.dst.proto_ipv4`（实测与 sha/spa/tha/tpa 逐字节一致）；**待确认** = `arp.isgratuitous/isannouncement/isprobe` 族（G-ARP-7）。

**断言基线**：今日 12 例断言总量 = **20 条 frame + 8 条 field**（4 正例：6+5+6+3 frames / 4+1+1+2 fields）；**20/20 + 8/8 经 `audit_arp.py` 对生成器语义模型逐条复算全对**（`/tmp/wt5-arp/audit_arp.py`，本车道落盘）；4 份正例 pcap 经 tshark 逐帧复核一致。**偏移基 = 帧首**（ARP 体起 **offset 14**），无 +54 跨距（设计 §2；L2-only 族与 L3 族的核心差异，历史教训：P5 首轮 3 例钉红即偏移基误用）。

**动态字段禁止硬编码**：本协议**无生成期随机值**（无 ISN/ipID/seq——无传输层），帧字节**全确定**，可整格钉死。唯一非确定面 = pcap 时间戳（落盘时刻，`pcap.go:154` 兜底），**不入断言**。

**包数约定（实测公式，设计 §9）**：`oper∈{缺省,1} → 2 帧`（request up + reply down）；`oper=2 → 1 帧`（announce down）。**无握手/挥手**（L2-only 无 TCP 生命周期）。**4/4 正例与实测 pcap 逐例一致**；8 负例今日语义 = **0 帧成功产出**。**负例 pcap 证据基（诚实分级，本车道实测）**：4 个 task-time validator 拒例（T-6/T-9/T-10/T-11）落盘 `<id>.neg.pcap` = **24B header-only（0 帧）**✓；4 个 create-time 400 拒例（T-5/T-7/T-8/T-12）中 **T-5/T-7/T-8 无落盘 pcap**（MCP 调用即被拒，`driver.go:102-115` 不落盘——这是 create-time 拒例的**正常形态**，非证据缺失）；**T-12 落盘 176B/2 帧文件系陈旧遗留**（mtime 2026-09-22 12:53，早于修轮提交 c7f6dec 12:57——首跑红例 [strategy_fc 放 spec_json 内不触发] 时代的产物，与今日负例语义矛盾，**不得作为证据引用**，登记 G-ARP-1 附注）。

**保活/重试/RST 口径**：**全部不适用**——RFC 826 无保活/重试计时器；L2-only 无 TCP，故无 FIN/RST 面（设计 §4 显式声明）。正例帧序即全部生命周期。

## 2. 原子用例索引（12 ID = 4 正 + 8 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count（实测） | 断言形状 |
|---:|---|---|---|---:|---|
| 1 | `arp_t1_baseline_pair` | 正 | §5：op=1 缺省配对（广播问+单播答） | 2 | 4 fields + 6 frames |
| 2 | `arp_t2_bytes_full` | 正 | §3.1：28B 五段整格字节钉 | 2 | 1 field + 5 frames |
| 3 | `arp_t3_explicit_addrs` | 正 | §5：四地址显式覆盖（层键优先） | 2 | 1 field + 6 frames |
| 4 | `arp_t4_single_reply` | 正 | §5：op=2 单发宣告（勘误形） | 1 | 2 fields + 3 frames |
| 5 | `arp_t5_neg_operation` | 负 | §7 N-1：`operation=3` 区间拒 | —（0 帧） | `expect_error` + 锚词 |
| 6 | `arp_t6_neg_sender_ip` | 负 | §7 N-2：sender_ip 格式拒 | —（0 帧） | 同上 |
| 7 | `arp_t7_neg_ip_carrier` | 负 | §7 N-3：IP 载体混入拒 | —（0 帧） | 同上 |
| 8 | `arp_t8_neg_presence` | 负 | §7 N-4：顶层 arp presence 判死 | —（0 帧） | 同上 |
| 9 | `arp_t9_neg_sender_mac` | 负 | §7 N-5：sender_mac 格式拒 | —（0 帧） | 同上 |
| 10 | `arp_t10_neg_target_mac` | 负 | §7 N-6：target_mac 格式拒 | —（0 帧） | 同上 |
| 11 | `arp_t11_neg_target_ip` | 负 | §7 N-7：target_ip 格式拒 | —（0 帧） | 同上 |
| 12 | `arp_t12_neg_static_copy` | 负 | §7 N-8：静态 MAC + flows=2 拒 | —（0 帧） | 同上 |

**T-编号对照（设计 §9 全表摘要）**：T-ARP-1…12 ≡ #1…#12，**一一对应，无虚例**（与 opcua 旧稿 T4/T8 虚例不同）。**序号以 cases JSON 顺序为权威**（本表顺序即 JSON 顺序，机读实测一致）。

**JSON 来源沿革**：T-1…T-8 由 `ef3bfb5`（P5）首建（8 例）；T-9…T-12 由 `c7f6dec`（收官隔离复审修轮 M1/M2）补建。**本协议无扁平存量例**（`git log --follow cases/arp.json` 实证：首建即层链形）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count` + 非空 `fields` + 非空 `frames`；帧位由 §1 公式与实测 pcap 双向确认。**全部断言经 audit_arp.py 对生成器语义模型（`layer_gen.go:32-62`）逐字节复算**。

### 3.1 `arp_t1_baseline_pair`（2 帧，op=1 缺省）

`layers = [{eth:{src_mac:"aa:bb:cc:dd:ee:01",dst_mac:"aa:bb:cc:dd:ee:02"}}, {arp:{}}]`。

- `packet_count=2`。
- **fields（4）**：p1 `eth.dst="ff:ff:ff:ff:ff:ff"`（**广播请求**）、p1 `arp.opcode="1"`；p2 `arp.opcode="2"`、p2 `eth.dst="aa:bb:cc:dd:ee:01"`（**单播应答回问方**）。
- **frames（6，offset 基 = 帧首）**：p1@14 `00 01 08 00 06 04 00 01`（htype 0001 + ptype 0800 + hlen 06 + plen 04 + oper 0001）；p1@38 `0a 00 00 02`（tpa=10.0.0.2 缺省）；p2@20 `00 02`（oper=2）；p2@22 `aa bb cc dd ee 02`（sha=targetMAC，**角色互换**）；p2@32 `aa bb cc dd ee 01`（tha=senderMAC）；p2@38 `0a 00 00 01`（tpa=senderIP）。
- **缺省证据**：notes 记载 sender_ip=10.0.0.1/target_ip=10.0.0.2 由生成器补（设计 §5 自动派生规则⑤）；帧序从落盘 pcap 钉（P5 校准）。
- **无 IP/传输层证据**：断言全落在 offset 14–41 段，无 54 跨距；tshark `frame.protocols = eth:ethertype:arp`。

### 3.2 `arp_t2_bytes_full`（2 帧，28B 五段整格）

同 §3.1 配置（`arp:{}` 缺省）。

- `packet_count=2`；**field（1）**：`eth.type="0x0806"`。
- **frames（5）——28B 体五段全覆盖（9.5 全字段有例）**：p1@14 `00 01 08 00 06 04 00 01`（htype/ptype/hlen/plen/oper）；p1@22 `aa bb cc dd ee 01`（sha）；p1@28 `0a 00 00 01`（spa）；p1@32 `00 00 00 00 00 00`（**tha 全零 = RFC 826 请求语义**）；p1@38 `0a 00 00 02`（tpa）。
- **偏移基证据**：五段覆盖 14–41 连续 28B —— 任一字段若按 +54 基断则必然红。

### 3.3 `arp_t3_explicit_addrs`（2 帧，四地址显式）

`arp = {sender_mac:"11:22:33:44:55:66", target_mac:"66:55:44:33:22:11", sender_ip:"192.168.10.5", target_ip:"192.168.10.1"}`（eth 层仍给默认 MAC）。

- `packet_count=2`；**field（1）**：p1 `eth.src="11:22:33:44:55:66"`。
- **frames（6）**：p1@22 `11 22 33 44 55 66`（sha=**arp 层 sender_mac**）；p1@28 `c0 a8 0a 05`（spa=192.168.10.5）；p1@38 `c0 a8 0a 01`（tpa=192.168.10.1）；p2@22 `66 55 44 33 22 11`（sha=target_mac）；p2@32 `11 22 33 44 55 66`（tha=sender_mac）；p2@38 `c0 a8 0a 05`（tpa=sender_ip）。
- **层键优先证据**：notes 明写"ARP 层 sender_mac 覆盖 eth 层推导"——ether src 与 sha **同一字节**（双钉），证明 `firstNonEmpty(arp.sender_mac, spec.SrcMAC, …)`（`layer_gen.go:44`）语义。

### 3.4 `arp_t4_single_reply`（1 帧，op=2 单发宣告）

`arp = {operation:2}`。

- `packet_count=1`；**fields（2）**：p1 `eth.dst="aa:bb:cc:dd:ee:01"`（**单播，非广播**）、p1 `arp.opcode="2"`。
- **frames（3）**：p1@20 `00 02`（oper=2）；p1@22 `aa bb cc dd ee 02`（sha=targetMAC）；p1@32 `aa bb cc dd ee 01`（tha=senderMAC）。
- **勘误证据（本协议最重要的行为面）**：D-ARP-1 裁定 3 记载 legacy `buildARPPacket` 对 op=2 **硬编码广播 + 请求形**（字节错位）；重建修正为**对端角色单播宣告**。本用例的 `eth.dst=sender_mac` 与角色互换成对，即该勘误的执法证据（legacy `arp.go:101-103` 今为生产不可达代码，G-ARP-2）。

**正例总则**：ARP 三形态（缺省配对/整格字节/显式覆盖/单发宣告）均为正例；只有配置/值域/格式错误进入负例。**无 min_packets 宽松形**——4/4 用精确 `packet_count`（对照 telnet G-TELNET-16 的系统性弱点，本协议无此问题）。

## 4. 负例契约

负例必须在 create-time（400）或 task-time（validator/构造期）失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或假成功（**今日语义 = 0 帧成功产出；pcap 证据分级见 §1**——4 task-time 例有 24B header-only 落盘证据，4 create-time 例不落盘为正常形态，T-12 落盘件系陈旧遗留不得引用）。锚词与设计 §7 表一一对应、同序（代码逐字）：

| # | ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（逐字） | 代码行 | 时机 |
|---:|---|---|---|---|---|---|
| 5 | `arp_t5_neg_operation` | `arp:{operation:3}` | `out of range [1,2]` | `layers: layer "arp" field "operation" = 3 invalid: out of range [1,2]` | `complete.go:325` | create-time（400） |
| 6 | `arp_t6_neg_sender_ip` | `arp:{sender_ip:"not-an-ip"}` | `invalid sender_ip` | `arp: invalid sender_ip "not-an-ip"` | `layer_gen.go:151` | task-time（validator） |
| 7 | `arp_t7_neg_ip_carrier` | 层链 `[eth, ip, arp]` | `must not have an ip/transport carrier` | `layers: layer "arp" (l2) must not have an ip/transport carrier, got "ip" at position 1` | `complete.go:355` | create-time（400） |
| 8 | `arp_t8_neg_presence` | `layers + 顶层 arp:{}` | `no longer accepts a top-level arp` | `protocol arp no longer accepts a top-level arp sub-config (move it into the arp layer of a [eth,arp] layers chain)` | `strategy_convert.go:9108-9110` | create-time（400） |
| 9 | `arp_t9_neg_sender_mac` | `arp:{sender_mac:"zz:bb:cc:dd:ee:01"}` | `invalid sender_mac` | `arp: invalid sender_mac "zz:…"` | `layer_gen.go:158` | task-time（validator） |
| 10 | `arp_t10_neg_target_mac` | `arp:{target_mac:"nope"}` | `invalid target_mac` | `arp: invalid target_mac "nope"` | `layer_gen.go:163` | task-time（validator） |
| 11 | `arp_t11_neg_target_ip` | `arp:{target_ip:"999.0.0.1"}` | `invalid target_ip` | `arp: invalid target_ip "999.0.0.1"` | `layer_gen.go:154` | task-time（validator） |
| 12 | `arp_t12_neg_static_copy` | 静态 eth MAC + `strategy_fc{flows:2}`（**case 顶层键**） | `static four-tuple` | `layers pin a static four-tuple but flows > 1: every flow would emit identical addresses/ports (static copy). Write the varying field as a dynamic object inside its layer (ip.src/ip.dst, tcp/udp src_port/dst_port)` | `semantic.go:285`（扫描面 `:214` 含 eth） | create-time（400） |

**锚词口径**：`error_contains` 是**子串**判定；8 例均命中代码文案的子串（前缀 `layers: `/`arp: `/`protocol arp ` 不影响）。

**负例原子性**：每例单一故障注入；单次执行不得混注。**T-5 与 T-12 的注入位置差异（易错点）**：T-12 的 `strategy_fc` 必须放 **case 顶层**（suite harness 的 `StrategyFC` 面，`driver.go:96-100` → MCP `strategy_flow_control` 参数），放 `spec_json` 内不触发静态门——**T-12 首跑红例实录**（arp 记忆教训 2）。

**负例纯净性**：8/8 `expect` 键集合 = **严格两键** `{expect_error, error_contains}`（机读实测），无 `notes`、无成功包结构断言混入——**本协议存量已达标**（对照 opcua G-OPCUA-7 的含-notes 形）。

**presence 负例形状（CORE_MEMORY presence-negative-case-shape 口径，必须点名）**：T-8 的形状是**层链 + 顶层空子映射并存**（`{"layers":[…],"arp":{}}`）——这是**判死执法对象**，不是旧键残留、不是层链不彻底。执法门 = `CheckProtoFlat` 的 rawWrapChains arp 行（`strategy_convert.go:9100`）；**空 map 也死**（`v != nil` 判定）。**验收口径**：本协议 11 个非负例顶层键 = 0（仅 `{layers}`），**今日成立**。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：

| 分支 | 锚词 | 代码行 | 说明 |
|---|---|---|---|
| IPv6 文本入 sender_ip/target_ip | `invalid sender_ip`（构造期后缀 `: want IPv4`） | `layer_gen.go:133-137` | 层校验器 `net.ParseIP` 放行 v6 → 构造期 `To4()` 拒（**两段式**，设计 §3.2） |
| op 非数值（浮点/负值） | `not a numeric value in [1,2]` | `complete.go:311-313` | V9 不可转换分支，今日无例 |
| 顶层五键扁平（src_ip 等） | `no longer accepts flat config field src_ip` | `strategy_convert.go:8635-8637` | 五键通用门，arp 无专用例 |
| 顶层游离未知键 | `unknown field` 通用门**不存在** | — | **不建**（会真绿 = 假通过，G-ARP-9） |

**不得误报的合法协议事件**：`arp:{}` 空层（合法缺省，T-1/T-2 即证）；`operation` 显式 0（V9 放行→1）；eth 层 MAC 与 arp 层 sender_mac 并存（层键优先，T-3）；`flows>1` + eth MAC 动态对象（合法多流，A′ 正例）；tpa=255.255.255.255（合法 IPv4，语义由用户负责）。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 826（报文格式图 + Packet Generation/Reception 两段）（设计 §10）+ D-ARP-1（设计 §11）+ tshark 3.6.14 `arp.*` 字段表（**51 字段**）与 **4 份正例实测 pcap**（`/tmp/mcp-pcaps/arp/`）→ 12 ID（本契约 §2）。第三源"已确认现网行为"当前 = **抓包级已到**（本仓引擎产出的 4 例 pcap 逐帧复核，另 8 负例 0 帧），但**真实网关/主机的 ARP 应答字节样本未取到** → G-ARP-7（按设计 §10.5 不写死进实现）。

**12 ID 逐项回指（§9.5 要求）**：#1←设计 §5；#2←§3.1；#3←§5；#4←§5；#5←§7 N-1；#6←§7 N-2；#7←§7 N-3；#8←§7 N-4；#9←§7 N-5；#10←§7 N-6；#11←§7 N-7；#12←§7 N-8。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 826 公开语义 + `TEST_CASES.md` §T-ARP-1…12 已验收清单 + 仓库落码反推 + tshark 3.6.14 字段与 4 例 pcap 实测**，**非纯规范反推**（真实网关字节样本未取到 → G-ARP-7；`arp.isgratuitous` 族语义未核对）。
- **对账两行**：**要求逻辑点总数 = 47**（八项 8 行 + 矩阵 6 格 + 变体 23 行 + 商业映射 10 行 = 8 + 6 + 23 + 10 = 47）；**用例覆盖数 = 31**（八项已覆 5 + 矩阵已覆 4 + 变体已覆 13 + 商业已覆 4 = 26；**加 5 个 ts/harness 面**（presence 判死 / 载体拒 / 静态复制拒 / 负例严格两键 / 断言精确 packet_count）= **31**）；**不适用 = 7**（八项 3 + 矩阵 2 + 商业 0 + 变体 0 = 5；**加 2 个协议级不适用面**（L2-only 无 RST / 无保活）= 7）；**开放立项 = 9**（变体立项 9 + 八项 0 + 矩阵 0）。31 + 7 + 9 = **47** ✓
  **粒度声明**：行/格粒度每点 1 计；G-ARP-1…G-ARP-9 不折进 47。**反查全绿 ≠ 覆盖全**（§9.52 原文）。逐表重数见设计 §10.1（八项 8 = 覆 5 + 不适用 3）/§10.2（6 格 = 覆 4 + 不适用 2）/§10.3（23 行 = 覆 13 + 立项 9 + 不解决 1）/§10.4（10 行 = 覆 4 + 不解决 6）。
- **门3 抽查候选**：最复杂用例 = **#3 `arp_t3_explicit_addrs`**（6 frame + 1 field：四地址显式覆盖 12 字节跨两帧角色互换，交织维度 = 帧向(2)×字段角色(4)×层覆盖优先级(arp 层 vs eth 层)）；**建议门3 抽 #3 + #4**（#4 补勘误语义面：op=2 单播 vs legacy 广播）。

### 5.3 T-编号与旧 id 对照（设计 §9 全表摘要）

T-ARP-1 ≡ `arp_t1_baseline_pair`；T-ARP-2 ≡ `arp_t2_bytes_full`；T-ARP-3 ≡ `arp_t3_explicit_addrs`；T-ARP-4 ≡ `arp_t4_single_reply`；T-ARP-5…12 ≡ `arp_t5_neg_operation`/`arp_t6_neg_sender_ip`/`arp_t7_neg_ip_carrier`/`arp_t8_neg_presence`/`arp_t9_neg_sender_mac`/`arp_t10_neg_target_mac`/`arp_t11_neg_target_ip`/`arp_t12_neg_static_copy`（编号与 JSON 顺序**完全一致**，无偏移）。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | **不适用**：ARP 是无连接单帧对等问询，一个流 = 一次问询（1–2 帧）即完整生命周期；无会话概念可承载多轮 | **显式不适用**（设计 §4/§12.3 豁免声明）；多流由 `strategy_fc` 承载 → A′ 正例（§13 #7） |
| ② | 非正常结束 | **不适用**：L2-only 无 TCP 生命周期（无 FIN/RST 面）；op=2 单发亦非"异常"（合法宣告形） | **显式不适用**（无 RST 断言面，设计 §10.2 T3 列） |
| ③ | 长保活 | **不适用**：RFC 826 无保活/重试计时器（无计时器字段） | **显式不适用**（设计 §10.1 八项 #6） |

无空项：① 显式不适用 + 理由 + A′ 多流正例；② 显式不适用 + 理由（L2-only）；③ 显式不适用 + 理由（协议无计时器）。**本协议是"三项全不适用"的协议**（四协议 L2-only 族共性，goose/sv/isis 同款）。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| tshark 通道面 | 收编 `arp.hw.type/proto.type/hw.size/proto.size/src.*/dst.*` 8 字段——今日零使用（**可用但未收编**） | G-ARP-4 |
| oper 形态面 | 显式 `operation:1` / 显式 `operation:0`（V9 放行→1） / op 非数值拒 | 设计 §10.3 #2/#4/#6 |
| 地址拒面 | IPv6 文本入 sender_ip（构造期 `want IPv4`） | 设计 §10.3 #13 |
| 链形面 | 单层 `[arp]` 自动补 eth / 框架默认 MAC 面 | 设计 §10.3 #15/#16 |
| 多流面 | 动态 eth MAC + flows=2 正例（§2 多流样例） | 设计 §10.3 #20 |
| 扁平门面 | 顶层 `src_ip` 五键门 arp 专用例 | 设计 §10.3 #21 |
| VLAN 面 | `[eth, vlan, arp]` 探针例（先探针定断言面） | 设计 §10.3 #22 |
| 负例纯净面 | 4 正例删 `notes` 键 | G-ARP-8 |

**B′（框架面）**：顶层游离键通用门（G-ARP-9，等框架级 unknown-key 白名单，**禁加单协议黑名单分支**）/ 静态复制门指引文案不含 eth（G-ARP-5）/ `arp.isgratuitous` 族收编（G-ARP-7 确认后归 G-ARP-4）/ gratuitous+probe 自宣告形（G-ARP-6，明确不解决）。进设计 §14。

### 6.3 3.14 豁免边界审计

**有长连接载体？→ 无**：arp 是 L2-only（`DependsOn ["eth"]`，无 TCP/UDP），`sessions[]` **显式不适用**——arp 层 registry 5 键无 `sessions`（机读实测），且 ARP 协议本身无会话复用概念。**多流并发**由策略级 `strategy_fc {"type":"flows"}` 承载（今日零正例 → A′）；**单包多载荷** = **不适用**（一帧一 ARP 报文，无多 question/多 RR 类形态，如实声明）。**L2-only 族豁免对照**：goose/sv/isis/arp 四协议同款（设计 §12.3 声明）。

## 7. 实现后执行建议

1. **P4 顺序**：①先修 G-ARP-8（4 正例删 `notes`，内容本版 §3 已承载）；②补 A′ tshark 通道（G-ARP-4：`arp.src.hw_mac` 等 8 字段收编，注意 `arp.proto.type` 是 `0x0800` hex 串、`arp.hw.type` 是十进制 `1`）；③补 A′ oper/地址/链形/多流例（§6.2 前六类）；④全量复跑。**本协议无 §1 迁移步骤**（11 非负例顶层零残留）。
2. **实测顺序**：先 #1（缺省配对 2 帧 + 广播/单播对照），再 #2（28B 五段偏移基=14 全钉），再 #4（op=2 单播宣告勘误面），再 #3（层键优先双钉），最后 8 负例（4 create-time 400 + 4 task-time 锚词）。
3. **门2 四项**：①顶层旧键零残留（**今日成立**：非负例 11/11 仅 `{layers}`）；②`CASE_PROTO=arp` 全量不是增量，负例带锚词；③二进制与 HEAD 同代（`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；④反查绿（`python3 trafficgen/tools/coverage_gate.py arp`，本车道实测 **22/22 绿**，exit 0）。
4. **服务端验证 = 服务器重编重启**（h323 教训）；pcap 落 `/tmp/mcp-pcaps/arp/`；**网卡路须补跑**（D-ARP-1 遗留"网卡未跑"，如实登记）。
5. 任何 RFC 826 条款号的具体引用须有规范原文证据（G-ARP-7 纪律）；`arp.isgratuitous` 族字段**不得**在确认前写进断言。

## 8. 存量审计（12 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/arp.json` **12 例**：4 正例带精确 `packet_count`（2/2/2/1），**与实测 pcap 帧数 4/4 逐例一致**（`tshark -r … | wc -l`）；8 负例 `expect` 键集合 = **严格两键**（**今日语义** = 0 帧成功产出——4 个 task-time 拒例有 24B header-only 落盘证据，4 个 create-time 拒例不落盘为正常形态，T-12 落盘 176B 系首跑红例时代的陈旧遗留、不得引用，§1 证据分级）；11/11 非负例 `spec_json` 顶层键仅 `{layers}`（**零残留**），T-8 = `{layers,arp}`（presence 判死执法对象）；**20 条 frame + 8 条 field 断言逐条经 audit_arp.py 复算全对**；层内 `arp` 5 键与 registry Fields 逐键一致（机读实测）；帧长恒 60B（含 18B 零填充，4/4 例 tshark `frame.len=60` 实证）。

**上报产物对账（重要，G-ARP-1）**：`trafficgen/docs/protocol-pcap-test/arp.md`（**tracked 产物**）写 "Cases: 12 — pass 12, fail 0, error 0"，12 行逐例表（包数 2/2/2/1/0×8）；末次提交 `c7f6dec`（**2026-09-22**）**晚于**判死提交 `0417be5`（2026-09-13）——**不属** opcua G-OPCUA-10 "过期产物"口径。但 `docs/protocol-pcap-test/arp/` **目录不存在**（0 个 pcap），文档 4 处 `(arp/<id>.pcap)` 链接全断 + 8 处空链接 `[pcap]()`。**本车道未跑该套件**，故本文档**不以任何形式**（含"今日已跑通"）引用该产物作为套件可跑证据。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **legacy 双轨生产不可达（G-ARP-2）**：`arp.go`（266 行）的 `Planner/Plan/buildARPPacket/buildARPReply` + 死常量 `DefaultTTL` 无生产注册（唯一调用点 = REST 集成测试）；其 op=2 语义与生产**相反**（广播 vs 单播宣告）。45 个 legacy `Test*`（716 行）测的是死面；生产路径只有 `arp_chain_test.go` 4 个测试。**读者不得把 `arp.go` 注释当生产语义。**
2. **正例覆盖面窄（G-ARP-3）**：12 例中正例仅 4 条，oper 值域只走"缺省"与"2"两个；显式 1/显式 0/非数值拒/IPv6 文本拒/单层链/默认 MAC/动态 MAC 多流/五键门/VLAN 链 —— **今日零用例**。
3. **tshark 通道零收编（G-ARP-4）**：8 个地址/长度字段实测可用（§1 TSHARK 基线），今日只用 `arp.opcode` + `eth.*`。**不是被迫，是未收编**。
4. **`arp.isgratuitous` 族待确认（G-ARP-7）**：dissector 派生位语义未对 RFC 5227 核对；真实网关字节样本未取到。
5. **负例 pcap 证据分级（§1 诚实分级）**：T-5/T-7/T-8（create-time 400）**无落盘 pcap**——MCP 调用即被拒（`driver.go:102-115`），不落盘是该拒例时机的**正常形态**，非证据缺失；**T-12 的 `arp_t12_neg_static_copy.neg.pcap`（176B/2 帧，mtime 2026-09-22 12:53）系首跑红例时代（strategy_fc 放置修正前）的陈旧遗留**，与今日 create-time 拒语义矛盾，**不得作为证据引用**（登记 G-ARP-1 附注；修复动作 = 重跑套件时删除/覆盖该陈旧文件）。
6. **gratuitous/probe 形不可表达（G-ARP-6）**：D-ARP-1 裁定 6 "oper=2 可承载同等语义"经 RFC 对照**不成立**（oper=2 是对端宣告，spa/tpa 为对端角色；自宣告须 oper=1+spa==tpa）——本章按 §0 #9 校正口径登记。
7. **静态复制门指引文案不含 eth（G-ARP-5）**：`semantic.go:285` 指引写 "ip.src/ip.dst, tcp/udp src_port/dst_port"——对 L2-only 用户是错误指引（照写会被 V-carrier 拒）。
8. **4 正例含 `notes` 键（G-ARP-8）**：与严格三键口径不同形（负例 8/8 已严格两键）。
9. **结果产物 pcap 留档断链（G-ARP-1）**：见 §8.1。
10. **FlowID/PacketIndex/Timestamp 不回填（注记，不立项）**：L2-only 发射分支与生成器均不设；下游零消费（`internal/output/` grep 零命中 FlowID；`pcap.go:154` 时间戳兜底 time.Now）；**无断言面受影响**。D-ARP-1 修轮 L3 YAGNI 裁定延续。
11. **spec MAC 面半面注记（设计 §0 #4 / §8）**：L2-only 门只护 IP/端口（空/0），`spec.SrcMAC/DstMAC` 在无 eth 层显式值时保留框架默认 `02:00:00:00:00:01/02`——生成器经 `firstNonEmpty` 消费它，行为正确；仅"spec 面全空"的表述对该两键不成立（如实，不立项）。

### 8.3 逐条去向表（12 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `arp_t1_baseline_pair` | T1 | **保留** | 删 `notes`（G-ARP-8）；可补 `arp.src.hw_mac`/`arp.dst.proto_ipv4` field 断言（G-ARP-4） |
| `arp_t2_bytes_full` | T2 | **保留** | 删 `notes`；五段 frame 可转 `arp.hw.type/proto.type/hw.size/proto.size` + `src/dst.*` field 通道（G-ARP-4） |
| `arp_t3_explicit_addrs` | T3 | **保留** | 删 `notes`；可补 `arp.src.hw_mac=11:22:33:44:55:66` field 断言 |
| `arp_t4_single_reply` | T4 | **保留** | 删 `notes`；可补 `arp.src.proto_ipv4=10.0.0.2` field 断言 |
| `arp_t5_neg_operation` | T5 | **保留** | 形状已合规（严格两键）；可补 op 非数值姊妹例（A′） |
| `arp_t6_neg_sender_ip` | T6 | **保留** | 同上；可补 IPv6 文本姊妹例（A′） |
| `arp_t7_neg_ip_carrier` | T7 | **保留** | 同上（V-carrier 执法证据，锚词不改） |
| `arp_t8_neg_presence` | T8 | **保留** | 同上（**presence 判死执法对象，形状须点名**——§4） |
| `arp_t9_neg_sender_mac` | T9 | **保留** | 同上（复审 M1 补例） |
| `arp_t10_neg_target_mac` | T10 | **保留** | 同上（复审 M1 补例） |
| `arp_t11_neg_target_ip` | T11 | **保留** | 同上（复审 M1 补例） |
| `arp_t12_neg_static_copy` | T12 | **保留** | 同上（复审 M2 补例；`strategy_fc` 须留 case 顶层） |

**无"作废不注原因"：0 作废，0 等价覆盖**——12 例全部保留（仅 4 正例删 `notes` + 可选补 field 通道）+ A′ 新增 9 例。**本协议 11 非负例顶层零残留**（与 opcua/telnet/isis 等共多个协议同为纯层链形）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

> **现状说明**：`coverage_gate.py` **已有 `check_arp`**（`:4588-4633`，**22 项**，本车道实测 `python3 trafficgen/tools/coverage_gate.py arp` → **22/22 绿**，exit 0）。下列为**增量建议**（现有 22 项之外的补强），每条均可从本契约与 cases JSON 直接机读，不需新造事实。

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['arp']) == 12` 且 ID 集合 = §2 十二项，顺序一致 | 本契约 §2 |
| 2 | 12/12 例 `spec_json` 顶层键 ⊆ `{layers}` ∪ `{arp}`（**后者仅 T-8 presence 负例**） | 本契约 §1；设计 §12.1 |
| 3 | 4 正例 `packet_count` == `2 if oper∈{缺省,1} else 1`（由 spec 推出，**精确等值**） | 设计 §9 公式 |
| 4 | 4 正例 `expect` 键 == `{packet_count, fields, frames}`（**P4 删 `notes` 后**） | 本契约 §1；G-ARP-8 |
| 5 | 8 负例 `expect` 键 == `{expect_error, error_contains}`（**今日已成立**） | 本契约 §4 |
| 6 | 负例 `error_contains` ∈ 代码锚词集 `{"out of range [1,2]", "invalid sender_ip", "invalid target_ip", "invalid sender_mac", "invalid target_mac", "must not have an ip/transport carrier", "no longer accepts a top-level arp", "static four-tuple"}` | 设计 §7 |
| 7 | 非负例顶层键计数 == 0（**今日已成立**） | 设计 §12.1 |
| 8 | 每正例至少一条 frames 断言落在 **offset 14–41**（28B 体段，**偏移基=帧首**）——非 54 | 本契约 §1/§3 |
| 9 | 12/12 例 `spec_json.layers` **不含** `ip`（T-7 除外——该例是载体拒执法对象）且末层名 == `"arp"` | 设计 §12.3 |
| 10 | 12/12 例无 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count` 顶层键（L2-only 无四元组面） | 设计 §1/§12.1 |
| 11 | `strategy_fc` 若出现，必在 case 顶层（非 `spec_json` 内）——T-12 首跑红例口径 | 本契约 §4 |

**另注意**：`trafficgen/docs/protocol-pcap-test/arp.md` 的 12/12 pass **提交晚于判死提交**（`c7f6dec` 2026-09-22 > `0417be5` 2026-09-13），**不属**过期产物口径；但 `docs/protocol-pcap-test/arp/` **目录不存在**（0 个 pcap，4 处链接全断）→ **不得据该文档认为 pcap 可查**（G-ARP-1，归属代码阶段）。该缺口与 opcua G-OPCUA-10 **口径不同**（opcua 是"末次提交早于判死提交"），与 telnet G-TELNET-3 **口径相同**——不得混用。**附注（本车道实测）**：`/tmp/mcp-pcaps/arp/` 落盘面 4 负例中 **T-5/T-7/T-8 无 pcap 文件**（create-time 400 不落盘，正常形态）、**T-12 有 176B/2 帧陈旧遗留文件**（首跑红例时代产物，不得引用）——§1 证据分级已逐条列明，重跑套件时须清理该陈旧文件。

## 10. 修订记录

- v1.0.0（2026-09-29）：批次二文档车道 P1–P3，**as-built 首次成文**（本协议无旧编号用例文档）。形状基线机读实测（§1：顶层键分布 11+1 / 4 正 8 负 / 负例严格两键 8/8）；**20 条 frame + 8 条 field 断言经 audit_arp.py 对生成器语义模型逐条复算全对**（脚本自身 2 处 bug 修正：以太头字节序、eth.dst/src 索引）；包数公式 oper 二值与实测 **4/4 逐例一致**；4 份正例 pcap tshark 逐帧复核（60B pad + `frame.protocols = eth:ethertype:arp`）；tshark 3.6.14 arp dissector **51 字段** + 通道分级（A′ 立项 G-ARP-4）；**偏移基=帧首**专节钉死（L2-only 族与 L3 族核心差异）；P3 固定动作（§6，三项全显式不适用 + 理由）；执行建议（§7）；存量审计（§8，12/12 保留 + 9 类矛盾点）；覆盖反查门增量建议 11 行（§9，现有 `check_arp` 22/22 已绿）。自审 3 轮，末轮干净。

# 27-Moxa 复核审查报告（验收态维持确认）

> 审查日期：2026-08-19
> 审查属性：文档阶段复核（非从头审查）
> 审查对象：`27-moxa-design.md`、`27-moxa-testcase.md`、`cases/moxa.json` 三件套
> 结论：**通过，验收态保持。无新发现。**

---

## 1. 审查方法

对照 memory 记录（moxa-design-accepted-2026-08.md）的四个关键修复点逐项复核，并对三件套做程序化一致性校验（Python 脚本而非肉眼抽查）：

1. JSON 13 例 id ↔ testcase §1.2/§5 索引表 ↔ design §7 映射表三方兜底；
2. 包数 design §5.7/§6 ↔ testcase §4 走查 ↔ JSON expect.packet_count 三方比对；
3. 帧断言偏移与锚定对象（数据面 vs 握手平凡值）逐包核对；
4. 7 负例的结构断言（has_handshake/terminates/packet_count/has_payload/negotiated/directional/frames）程序化扫描；
5. error_contains 三处（design §9.1 ↔ testcase §4.7 ↔ JSON）逐条比对。

---

## 2. 四项已验收修复的复核结果（全部保持）

### 2.1 S3 down 段断言锚定数据面端口（验收项 1）— 保持

`moxa_bidirectional` expect.fields 含 `{packet:5, field:"tcp.srcport", value:"4800"}`。

- 包序推演（S3，mss 536）：包 1 SYN / 包 2 SYN+ACK / 包 3 ACK / **包 4 = 第一个 up 数据段（WR）** / **包 5 = 第一个 down 数据段（RT，src_port=4800, dst_port=客户端口）** / 6-8 挥手。
- packet 5 是由 tcp 层事件模式 `!ev.Up` 分支产出的**数据面服务器方向包**，srcport=4800 是 NPort 数据口——不是握手包的平凡值（SYN 包 srcport 是客户端 12345，SYN+ACK 包 srcport 才是服务器 4800，但那是握手平凡值）。packet 5 锚定 down 数据段，是 R1 风险（设计 §8.5）的直接守卫。与 design §5.7、§6 S3、testcase §3.6/§4.3 三处行文一致。

### 2.2 负例键统一（验收项 2）— 保持

程序化扫描 7 负例 expect 键：仅 `expect_error` + `error_contains`，**无任何结构断言**（has_handshake / negotiated / terminates / packet_count / has_payload / directional / frames 全部 absent）。JSON 与 testcase §4.7 表格一致（负例无包、任务拒绝即 PASS 工具语义）。

### 2.3 包数三方一致（验收项 3）— 保持

| 用例 | design §5.7 | testcase §4 | JSON | 一致 |
|------|------------|-------------|------|------|
| moxa_single_up | 8 | 8（§4.1） | 8 | ✓ |
| moxa_multi_segment | 9 | 9（§4.2） | 9 | ✓ |
| moxa_bidirectional | 11 | 11（§4.3） | 11 | ✓ |
| moxa_sessions_multi | 24 | 24（§4.4） | 24 | ✓ |
| moxa_binary_payload | 8 | 8（§4.5） | 8 | ✓ |
| moxa_ipv6 | 8 | 8（§4.6） | 8 | ✓ |

会计均按事件模式纪律（握手 3 + 数据 N + 挥手 4，段间无独立 ACK），与 design §8.2/§5.7 一致。

### 2.4 MCP 冒烟基线（验收项 4）— 保持

`moxa` 层尚未注册（设计稿为规划态，§8.1 I1-I10 未落地）。memory 记录"未注册层时冒烟 0/7/6 是预期行为"仍然成立：`flowb_run_protocol_suite` 对新协议（未注册层）的正向用例会因层不可构建而失败——这是**实现前置**，不是文档缺陷。文档已明示三件套处于设计验收态、实现在规划中（design §8「本文档是设计稿，代码未写」）。

---

## 3. 一致性程序化校验（全绿）

| 校验项 | 结果 |
|--------|------|
| JSON 语法 + 13 例 | OK |
| JSON id 顺序 = testcase §1.2/§5 索引表 = design §7 表 | 完全一致（三方集合相等） |
| S2 payload 长度 = 2000（0x41×2000，MSS1460 → 2 段 1460+540，≤2048 不撞 E-B1） | OK |
| N-6 payload 长度 = 3000（>2048 → E-B1 拒绝） | OK |
| N-2 探针 `"ZZZ"` 编码 = `5a 5a 5a`（受控探针，非真实魔数） | OK |
| S2 帧断言 packet4/packet5 offset=54 hex `41`（段 1=包 4/段 2=包 5） | 与 §5.7/§6 S2 一致 |
| S3 帧断言 packet4 `57 52`（WR）/packet5 `52 54`（RT）offset 54 | 与 §5.7/§6 S3 一致 |
| S6 帧断言 offset=74（14+40+20）hex `68 65 6c 6c 6f` | 与 §6.1 帧解剖一致 |
| S4 distinct_values：srcport [12345,12346,12347] + distinct_exclude [4800]；dstport [4800] + distinct_exclude [12345,12346,12347] | 与 §5.7/§6 S4 一致 |
| 7 负例 error_contains 三处逐字一致（design §9.1 ↔ testcase §4.7 ↔ JSON） | OK |
| has_payload：仅 S2=true（帧长 1514>80），其余为正用例显式 false（帧长 ≤80 阈值） | 符合 verify.go 语义 |
| IPv4 覆盖 5 正例（S1/S2/S3/S4/S5）、IPv6 1 例（S6）| 双载体覆盖满足 |

---

## 4. 新发现文档缺陷扫描（无）

在已验收基线上重点复查以下通常容易回退/新引入的点，均未发现缺陷：

1. **帧偏移**：不作握手平凡值锚定之外，还复核了 SYN 带选项包的偏移（§6.1 注 60 仅对握手包成立，数据段无选项恒 54/74），用例无一处误用。
2. **字节序/长度**：本协议无帧无数值字段（§2.2），无字节序问题可查；S5 b64 `sGFoYQ==` → `68 61 68 61`（"haha"）解码正确且与断言一致。
3. **多流会话覆盖**：S4 用 `strategy_fc flows=3` + 聚合断言，且负例 N-3（sessions=3）成对覆盖"v1 单 flow 拒绝、多会话走策略 flows"，正负闭环。
4. **负路径覆盖**：7 负例映射 design §9.1 错误表全部 8 行中可单列的 7 行（E-T4 dst_port 越域承继 tcp 既有负例，不重复造）；外加 §9.2 独有 N-2（配置字节不进数据面）——覆盖不低于验收基线。
5. **断言可观测性**：所有正向断言锚定数据面可观察量（payload hex、数据面端口、ipv6 地址、包计数、聚合 distinct 值），没有"仅结构存在"的惰性断言；S2 的 seq 连续性说明（design §6 S2 注）已按框架能力（无跨包算术）退化为"非 0 且不同"的守护表述并写明，未过度承诺。
6. **MSS/2048 边界**：S2（2000B = 可分段正向）与 N-6（3000B = 超长拒绝）成对，且 2000 恰在 MSS1460 与 MaxBlockBytes2048 的合法夹缝中（§6.3 分段矩阵可复算）；testcase §1.1 对"payload 超长"正负交点的解释与 design §5.6 冲突修正一致。

---

## 5. 结论

三件套维持 2026-08-18 三轮对抗审查后的验收态，无退化、无新缺陷。

- 已验收的 4 项修复（S3 down 段数据面断言、负例键统一、包数三方一致、冒烟基线语义）全部原样保持；
- 程序化一致性校验（id/包数/偏移/error_contains/payload 长度/负例结构断言扫描）全绿；
- 代码实现仍未落地（design §8 明示规划态），MCP 冒烟 0/7/6 属预期，不构成文档回归。

**建议**：维持 "27-Moxa 设计稿验收态" 标签。下一触发点是代码实现开始（§8.1 I1-I10），届时按 design §8.4 DoD（A1-A7）验收，并验证 N-2 探针前缀是否需随 UDP 4800 字节核定收窄（design §11 修订触发点 1）。
# #92 moxa（Moxa NPort 串口透传）测试用例契约

> 版本：v1.2.0（2026-10-01 迁移后复审）
> 日期：2026-10-01
> 配套设计：`docs/protocols/moxa/design.md` v1.2.0（D-MOXA-1）
> 旧基线：`docs/protocol-designs/27-moxa-testcase.md` v1.0.0（13 例；思路继承不搬码，历史参考）
> 机器契约：`trafficgen/test/protocol_pcap/cases/moxa.json`（23 例：11 正 + 12 负；正例严格层链，结构负例保留故意游离键/错误载体形状）
> 白话一句：**二十三条检查：十一条看正常收发与边界，十二条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **23 个唯一语义 ID：11 正 + 12 负**（原 13 例加 10 条 P2/P4 边界与结构检查；负例含 N-1…N-7 及结构拒绝例）。派生规则：设计 §3 每个块条款、§5 每个事务/关联行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-10-01 机读实测）**：23/23 例顶层记录键结构一致；`spec_json` 顶层仅 `layers` 的正常正例 11/11，3 条结构负例故意带顶层游离键或错误载体；其余 9 条负例为严格层链输入。11 条正例 `expect` 均含 `packet_count`；12 条负例 `expect` 键集合严格为 `{expect_error,error_contains}`。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport/srcport`、`tcp.flags`、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线**：本机无 moxa dissector（`tshark -G fields | grep -i moxa` = **0 行**，tshark 3.6.14）——**不得使用任何 `moxa.*` 字段**。可用通道：① `tcp.dstport/srcport`；② `tcp.flags`/`tcp.seq`/`tcp.len`；③ `ipv6.src/dst`；④ frames `offset/hex`（块首字节，IPv4 offset 54 / IPv6 offset 74）。块-段映射按 `tcp.seq` 连续性佐证（S2）。

**动态字段禁止硬编码**：生成期值用 `same_as_packet`/`distinct_values`/`nonzero` 断言（S4 端口聚合已用）。

**包数约定**：单流 = 3（握手）+ N（数据段数）+ 4（FIN 四包挥手）。数据帧从帧 4 起；实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count。

**保活/重试/RST 口径**：moxa 层无 PING 类消息，不设正例亦不得进负例；RST 为框架 tcp 层能力，本协议层不新增断言（A′ 补例 G-MOXA-5 除外）；正例恒 FIN 优雅终止。

## 2. 原子用例索引（23 ID = 11 正 + 12 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count |
|---:|---|---|---|---:|
| 1 | `moxa_single_up` | 正 | §3.1：up 单块基线（IPv4） | 8 |
| 2 | `moxa_multi_segment` | 正 | §3.1/§8：2000B 跨段（1460+540） | 9 |
| 3 | `moxa_bidirectional` | 正 | §5：双向四事务交替 | 11 |
| 4 | `moxa_sessions_multi` | 正 | §5：三流展开（flows=3） | 24 |
| 5 | `moxa_binary_payload` | 正 | §3.1：b64 二进制透传 | 8 |
| 6 | `moxa_ipv6` | 正 | §2：IPv6 独立用例 | 8 |
| 7 | `moxa_neg_empty_payload` | 负 | §7：N-1 空块 | — |
| 8 | `moxa_neg_config_packet` | 负 | §7：N-2 探针拒绝 | — |
| 9 | `moxa_neg_sessions_multi` | 负 | §7：N-3 sessions 越界 | — |
| 10 | `moxa_neg_no_handshake` | 负 | §7：N-4 载体违例 | — |
| 11 | `moxa_neg_bad_b64` | 负 | §7：N-5 非法 b64 | — |
| 12 | `moxa_neg_oversize` | 负 | §7：N-6 超限（3000B） | — |
| 13 | `moxa_neg_bad_direction` | 负 | §7：N-7 非法方向 | — |
| 14 | `moxa_neg_top_moxa_presence_reject` | 负 | §12-P2：顶层 moxa presence | — |
| 15 | `moxa_neg_stray_src_ip` | 负 | §12-P2：顶层游离地址键 | — |
| 16 | `moxa_neg_carrier_udp` | 负 | §12-P2：错误 UDP 载体 | — |
| 17 | `moxa_up_multi` | 正 | A′ B2：连续 up 多块 | 10 |
| 18 | `moxa_down_only` | 正 | A′ B3：纯 down 单块 | 8 |
| 19 | `moxa_block_max` | 正 | A′ 单块 2048B 边界 | 9 |
| 20 | `moxa_default_port` | 正 | A′ 目的端口缺省 | 8 |
| 21 | `moxa_neg_mixed_family` | 负 | A′ 异族 IP | — |
| 22 | `moxa_abort_rst` | 正 | A′ 非正常 RST 终止 | 5 |
| 23 | `moxa_neg_block_over` | 负 | A′ 单块 2049B 越界 | — |

T-编号对照：T-MOXA-S1…S6 ≡ #1…#6；T-MOXA-N1…N7 ≡ #7…#13；P2/P4 结构与边界例 ≡ #14…#23（与 JSON 顺序一致）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count` + 载体与方向断言 + 块首 frames 断言；块 hex 均可由 fixture 精确预算（`hello`=`68 65 6c 6c 6f`；`A`=`41`；`WR`=`57 52`；`RT`=`52 54`；`haha`=`68 61 68 61`）。

### 3.1 `moxa_single_up`（8）

单块 up "hello"。帧 4（offset 54）hex `68 65 6c 6c 6f`；`tcp.dstport=4800`（帧 4）+ `tcp.flags=0x018`（帧 4）；`has_handshake`/`negotiated`/`terminates` 全 true。不设 `has_payload`（帧长 60 ≤ 80 阈值）。

### 3.2 `moxa_multi_segment`（9）

单块 2000×`A`（机读 `len==2000` 实测），`mss=1460` → 2 段（1460+540），≤2048 不撞 E-B1。帧 4/帧 5（offset 54）hex 首字节 `41`；`has_payload=true`（段帧 1514 > 80，唯一适用者）；`tcp.dstport=4800`（帧 4）。段间无独立 ACK（事件模式），段 2 紧跟段 1。

### 3.3 `moxa_bidirectional`（11）

`mss=536`，四块 up/down 交替（`WR`/`RT`各 2B，48B 说法为旧稿笔误——机读实测 payload 长 = **2**，不断言 48B）。帧 4（up）hex `57 52` + `tcp.dstport=4800`；帧 5（down）hex `52 54` + `tcp.srcport=4800`（端口对换直接证据）；`directional=true`；`tcp.dstport` 聚合恒 4800（`distinct_exclude` 滤握手/挥手下行包 dst=客户端源端口）。

### 3.4 `moxa_sessions_multi`（24）

`strategy_fc={"type":"flows","value":3}`（case 执行器的策略封包；不属于 `spec_json` 业务层），3 流 × 8 包 = 24。`tcp.srcport` 聚合恰 `["12345","12346","12347"]`（`distinct_exclude:["4800"]` 滤下行）；`tcp.dstport` 聚合恒 `["4800"]`（`distinct_exclude` 滤 12345–47）。不逐包定位（多流调度无固定包位）。

### 3.5 `moxa_binary_payload`（8）

`payload_b64="aGFoYQ=="` → `68 61 68 61`（帧 4，offset 54）；`tcp.dstport=4800`；握手/挥手同 S1。双向佐证：解码正确 + 二进制原样透传。

### 3.6 `moxa_ipv6`（8）

IPv6 地址对（`2001:db8::1 → 2001:db8::2`），块 hex 同 S1 但 offset **74**；`ipv6.src/dst` + `tcp.dstport=4800`（帧 4）。TCP 校验和覆盖 IPv6 伪头由专家信息自动覆盖。

**正例总则**：超 MSS 但 ≤2048 的块、`down` 方向块、合法 `payload_b64` 均为正例形态，只有配置/线格式/状态/关联/长度错误进入负例。

## 4. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；`expect` 键集合**严格为** `{expect_error,error_contains}`。锚词与设计 §7 表一一对应、同序：

| ID | 故障输入 | `error_contains` |
|---|---|---|
| `moxa_neg_empty_payload` | 空 stream / 空 payload | `moxa: empty stream block or payload required` |
| `moxa_neg_config_packet` | 前 3 字节 `ZZZ`（`0x5a`×3 受控探针；机读 `payload="ZZZ"`） | `moxa: config-packet bytes in stream are not supported` |
| `moxa_neg_sessions_multi` | `sessions=3`（`moxa.sessions` 机读实测） | `moxa: sessions=3>1 not supported` |
| `moxa_neg_no_handshake` | `tcp.handshake=false`（仅层内 `tcp`，迁移后无顶层重复键） | `moxa: tcp.handshake must be true` |
| `moxa_neg_bad_b64` | `payload_b64="%%%"` | `moxa: invalid payload_b64` |
| `moxa_neg_oversize` | 3000B 单块（机读 `len==3000` 实测） | `moxa: block 0 payload 3000 exceeds max 2048` |
| `moxa_neg_bad_direction` | `direction="sideways"` | `moxa: invalid direction` |

### 4.1 新增负例锚词

| ID | 类型 | `error_contains` |
|---|---|---|
| `moxa_neg_top_moxa_presence_reject` | 负 | `no longer accepts a top-level moxa sub-config` |
| `moxa_neg_stray_src_ip` | 负 | `no longer accepts flat config field src_ip` |
| `moxa_neg_carrier_udp` | 负 | `carrier` |
| `moxa_neg_mixed_family` | 负 | `same IP version` |
| `moxa_neg_block_over` | 负 | `exceeds max` |

`moxa_neg_top_moxa_presence_reject`、`moxa_neg_stray_src_ip` 与 `moxa_neg_carrier_udp` 是结构边界负例；它们故意不代表合法生产配置。

**负例原子性**：每例单一故障注入；单次执行不得混注。

## 5. 覆盖与对账

### 5.1 三源回指行

Moxa datasheet operation modes（TCP Server 主站建连透明传）+ D-MOXA-1（设计 §11）+ tshark 通道实测（`tcp.*`/frames，`moxa.*` 零字段）→ 23 ID（本契约 §2）。第三源"已确认现网行为"当前 = **未确认级**（G-MOXA-4，按 §5.5 不写死进实现）。UDP 4800 配置面字节**不进用例**（N-2 探针除外）。

### 5.2 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **旧基线契约 + datasheet modes + 仓库落码反推 + tshark 通道实测**（moxa 无公开线格式规范，`moxa.*` 零字段），**非纯规范反推**。块字节通道见设计 §2（offset 54/74 机读口径）。
- **对账两行**：**要求逻辑点总数 = 63**（八项 8 行 + 矩阵 15 格 + 变体 20 行 + 商业映射 8 行 + 用例形状 12 点〔23 ID 中扣除探针声明的重复计数〕）；**用例覆盖数 = 50**（八项 8 + 矩阵已覆 8 + 变体已覆 15 + 商业已覆 4 + 待确认 1 + 形状已覆 23 + N-2 探针声明 1）；**不适用 = 6**（变体 1 + 商业 3 + 次要合法 4 中 2 计入本项，其余见 A′）。50 + 6 + 7 = 63；开放 7 格（矩阵 A′） = 立项覆盖（§9.36 口径，不冒充今日可跑）。
  **粒度声明**：行/格粒度每点 1 计；G-MOXA-1…G-MOXA-7 不折进 63。**反查全绿 ≠ 覆盖全**（§9.52 原文）。
- **门3 抽查候选**：最复杂用例 = **#3 `moxa_bidirectional`**（4 块双向交替，up/down×端口对换×hex 双通道）；交织维度 = 块(4)×方向(2)×端口对换×终态(FIN)。若按 9.49/9.50 下限偏弱在"并发交错"面，**建议门3 抽 #3 + #4**（`moxa_sessions_multi` 补多流面）。

### 5.3 T-编号与旧 id 对照（设计 §9 全表摘要）

### 5.3 T-编号与新增 ID 对照

原 13 例：`moxa_single_up` ≡ T-MOXA-S1；`moxa_multi_segment` ≡ T-MOXA-S2；`moxa_bidirectional` ≡ T-MOXA-S3；`moxa_sessions_multi` ≡ T-MOXA-S4；`moxa_binary_payload` ≡ T-MOXA-S5；`moxa_ipv6` ≡ T-MOXA-S6；`moxa_neg_empty_payload` ≡ T-MOXA-N1；`moxa_neg_config_packet` ≡ T-MOXA-N2；`moxa_neg_sessions_multi` ≡ T-MOXA-N3；`moxa_neg_no_handshake` ≡ T-MOXA-N4；`moxa_neg_bad_b64` ≡ T-MOXA-N5；`moxa_neg_oversize` ≡ T-MOXA-N6；`moxa_neg_bad_direction` ≡ T-MOXA-N7。

新增 10 例去向：`moxa_neg_top_moxa_presence_reject`（P2 presence，负，无 packet_count）；`moxa_neg_stray_src_ip`（P2 游离键，负，无 packet_count）；`moxa_neg_carrier_udp`（P2 错误载体，负，无 packet_count）；`moxa_up_multi`（B2，正，10）；`moxa_down_only`（B3，正，8）；`moxa_block_max`（2048B，正，9）；`moxa_default_port`（缺省端口，正，8）；`moxa_neg_mixed_family`（异族地址，负，无 packet_count）；`moxa_abort_rst`（RST，正，5）；`moxa_neg_block_over`（2049B，负，无 packet_count）。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接四块交替（#3，up→down→up→down）→ 多轮 up 连续（A′ `moxa_up_multi`） | 已覆 #3；A′ 补例 **#14**（连续 up 多块） |
| ② | 非正常结束 | 正常 FIN 全正例；应用层正常终止报文 = **无**（moxa 无终止类型）；网络层异常 = RST | A′ 补例 **`moxa_abort_rst`**（`tcp.rst=true`，框架能力，本层零断言）+ 负例 7 条 |
| ③ | 长保活 | 协议层无 keepalive 语义（设计 §4 显式不适用）；长会话 = 同连接多块 + 多流展开 | #3/#4 承载（>2 块） |

无空项：① 有已覆例 + 1 条 A′ 补例；② 有负例面 + 1 条 A′ 补例；③ 有 #3/#4。

### 6.2 A′/B′ 两分类表

**A′（迁移后边界与结构面）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 层链化 | registry `Fields` 已含 stream/sessions + translate `case "moxa"` 层内分支 | G-MOXA-1 已关闭，用例 #1–#23 已迁移 |
| 方向面 | 纯 down 单块 | #15 `moxa_down_only`（B3） |
| 连续面 | 连续 up 多块 | #14 `moxa_up_multi`（B2） |
| 边界精化 | 单块 =2048 精确边界 | #16 `moxa_block_max`（先跑后钉段数） |
| 端口面 | dst_port 缺省补齐 4800 | #17 `moxa_default_port`（删键不断言值） |
| 地址族面 | 异族混写/非法 IP | #18 `moxa_neg_mixed_family`（validator 有分支，今日无例） |
| 非正常结束 | `tcp.rst` 补例 | ② 的 `moxa_abort_rst`（G-MOXA-5） |
| 现网面 | 出厂默认口实证 | G-MOXA-4 |

**B′（框架面）**：`CheckProtoFlat` moxa presence 分支（G-MOXA-2，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态（G-MOXA-3，allowlist 无 `moxa` 行）/ `pack_ms`（G-MOXA-7，明确不解决）。进设计 §14，「明确不解决 + 迁入计划」。用例侧 N-2 钉现状（探针前缀，G-MOXA-6）。

### 6.3 3.14 豁免边界审计

**有长连接载体 → `sessions[]` 不豁免**（设计 §12.3 会话表 s1/s2/s3；`sessions>1` 拒绝 N-3 + 多流展开 #4）；多流并发 #4；单包多载荷 = **不适用**（moxa 块恒单字节段、无多 question/多 RR 类形态，如实声明）。

## 7. 实现后执行建议

1. **后续执行顺序**：G-MOXA-3/4/6/7 先按缺口取得代码或规范证据，再更新对应文档与用例；G-MOXA-1 的 Fields/translate/23 例迁移已完成。
2. **实测顺序**：先 S1/S5（块 hex 与 8 包基线），再 S2（2000B 分段与 `has_payload`），再 S3（down 端口对换），最后 S6（IPv6 offset 74）、S4（多流聚合）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=moxa` 全量不是增量）；门2④ 反查绿后进 P6。
4. 任何出厂默认口的具体断言须有独立手册证据和失败优先测试（设计 §1.2 ⑤ 纪律）。

## 8. 历史存量审计（13 例逐条去向，迁移已完成）

### 8.1 存量实测面（2026-09-27）

历史迁移前 `cases/moxa.json` **13 例**：6 正带 `packet_count`（8/9/11/24/8/8，全符合 `3+N+4` 公式：S4 = 3×8）；7 负 `expect` 键集合严格 `{expect_error,error_contains}`；S2 payload 机读 `len==2000`；N-6 payload 机读 `len==3000`；S3 四块 payload 机读各 `len==2`（旧稿"48 字节"为笔误，本版 §3.3 校正）；N-4 顶层 `tcp:{"handshake":false}` 与层内同值并存（机读实测）。

### 8.2 历史迁移前矛盾点（已关闭项留档）

1. **历史存量跑的是过渡态混合形，不是纯层链**：`spec_json` 的 `layers=[{tcp:{}},{moxa:{}}]` 只是**空壳**（`moxa` 层 config 恒 `{}`，既不校验也不消费），真实配置住顶层 `moxa` 子映射 + 顶层四元组。旧 id 的 packet_count 断言**今日有效**，但顶层键断言迁移前是**违规形**，当前 JSON 已清除生产正例残留。
2. **S3 "48 字节"笔误**：旧稿 design §6 S3 称 48B pattern 块，机读四块各 2B（`WR`/`RT`）。包数 11 不变（每块 1 包），hex 断言不变；迁移不因笔误改包数。
3. **N-4 双写**：顶层 `tcp:{"handshake":false}` 与 `layers[0].tcp:{"handshake":false}` 同值并存——迁移后只保留层内配置；当前 JSON 已无该正例残留。
4. **历史存量未覆盖精确边界**：2048 精确边界 / 缺省端口 / 异族混写 / 纯 down / 连续 up 多块；迁移后已由 A′ #14–#18 覆盖。

### 8.3 逐条去向表（13 行）

| 存量 id | T-编号 | 去向 | 改写动作（G-MOXA-1 落地时） |
|---|---|---|---|
| `moxa_single_up` | T-MOXA-S1 | **改写** | 目标形状化（`ip` 层地址 + `tcp` 层端口 + `moxa` 层 stream）；packet_count 8 不变 |
| `moxa_multi_segment` | T-MOXA-S2 | **改写** | 同上；2000B 内联保留；packet_count 9 不变 |
| `moxa_bidirectional` | T-MOXA-S3 | **改写** | 同上；"48B" 笔误不带入（2B 实测为准） |
| `moxa_sessions_multi` | T-MOXA-S4 | **改写** | `strategy_fc` 转正 `flow_control`；四元组留空走保底递增 |
| `moxa_binary_payload` | T-MOXA-S5 | **改写** | 同 S1 动作 |
| `moxa_ipv6` | T-MOXA-S6 | **改写** | 地址迁 `ip` 层；offset 74 不变 |
| `moxa_neg_empty_payload` | T-MOXA-N1 | **改写** | `moxa` 子映射迁层内；锚词不变 |
| `moxa_neg_config_packet` | T-MOXA-N2 | **改写** | 同上 |
| `moxa_neg_sessions_multi` | T-MOXA-N3 | **改写** | 同上 |
| `moxa_neg_no_handshake` | T-MOXA-N4 | **已改写** | 顶层 `tcp` 已删，只留层内 `tcp.handshake:false` |
| `moxa_neg_bad_b64` | T-MOXA-N5 | **改写** | 同 N1 动作 |
| `moxa_neg_oversize` | T-MOXA-N6 | **改写** | 同上；3000B 内联保留 |
| `moxa_neg_bad_direction` | T-MOXA-N7 | **改写** | 同上 |

无"作废不注原因"：0 作废，0 等价覆盖（全部改写 + 6 新增）。

## 9. 层链迁移审计（T1-T6，2026-10-01）

| ID | 结论 | 证据/去向 |
|---|---|---|
| T1 | 23 条用例逐条对账；11 正 + 12 负，ID 无重复 | JSON 机读审计 |
| T2 | 11 条正例全部为 `[ip,tcp,moxa]`，地址/端口/moxa 业务字段均在对应层 | JSON `spec_json.layers` |
| T3 | 9 条结构正常负例同样使用层链；3 条结构负例保留故意游离键或错误 UDP 载体 | 负例设计意图与锚词 |
| T4 | §3.15 三项均有例或立项：多轮操作、RST、长保活不适用均已登记 | 设计 §5/§14 |
| T5 | 历史 13 例全部保留并扩展为当前 23 例；无作废未登记 | 设计 §8.3 与当前 JSON |
| T6 | pcap/NIC 同一断言契约；本批未运行 suite/NIC，不宣称全量通过 | testcase §1 输出契约 |

## 10. 六项覆盖清单（C1-C6）

| ID | 结论 |
|---|---|
| C1 | 规范/设计/现网三源回指已列；现网默认端口仍待确认 |
| C2 | 正例覆盖单块、分段、双向、多流、二进制、IPv6、连续 up、纯 down、2048 边界及 RST |
| C3 | 12 条负例均有 `expect_error` 与 `error_contains`；非法 payload、方向、sessions、握手、长度、地址族、结构与载体均有覆盖 |
| C4 | 端口聚合与方向断言使用 `distinct_exclude`；帧 offset/hex 与 packet_count 保留 |
| C5 | 动态业务字段五策略未开放，G-MOXA-3 登记；`strategy_fc` 是执行器策略封包，不是 `spec_json` 层链字段 |
| C6 | JSON 对账为 23 IDs = 11 正 + 12 负；正例层链 11/11；本批未跑 suite/NIC |

## 11. 覆盖缺口与迁移去向

- G-MOXA-2：presence 判死与游离键负例已落地并覆盖；保持框架级白名单入口。
- G-MOXA-3：业务字段动态五策略未开放，后续补矩阵与失败例。
- G-MOXA-4/G-MOXA-6：默认端口现网证据及配置探针字节待确认。
- G-MOXA-7：`pack_ms` 未实现，维持不携带该键。

## 12. 修订记录

- v1.2.0（2026-10-01）：修正文档迁移后 stale claims，核对 23 例当前 JSON、负例纯净性、层链形状及缺口状态。未跑 suite/NIC，不宣称全量通过。自审两轮，末轮干净。
- v1.1.0（2026-10-01）：完成 T1-T6/C1-C6 层链迁移审计；同步 23 例（11 正 + 12 负）与缺口去向。未跑 suite/NIC，不宣称全量通过。自审两轮，末轮干净。

- v1.0.0（2026-09-27）：P-PIPE #92 文档轨 P1–P3。旧稿 27-* 13 ID / packet_count / 锚词 / fixture 全量继承（思路参考不搬码）；S3 "48B" 笔误机读校正（§3.3/§8.2）；新增形状基线机读实测（§1）、P3 固定动作（§6）、执行建议（§7）、存量审计（§8，13/13 改写）。P3 自审 2 轮，末轮干净（历史记录）。

# OSPF（开放最短路径优先）v2 测试用例设计

> 版本：v2.0.0（P3 完整产物）
> 日期：2026-09-27
> 配套设计：`docs/protocol-designs/83-ospf-design.md` v2.0.0（D-OSPF-1 草稿 §15；门1 获批=定稿）
> 机器契约：`trafficgen/test/protocol_pcap/cases/ospf.json`（20 例，1729 行；链形 `[ip,ospf]` 已对但层内全空，P4 按 §5 去向表改写）
> 状态：`ospf` 层已注册、builder/planner/generator 已落码（`registry.go:940`，`internal/protocol/ospf/` 四文件 905 行，15 个单元测试函数），D-OSPF-1 未定稿——P4 落码前以门1 获批版为准，不宣称当前 suite 可运行。
> 旧基线：`docs/protocol-designs/37-ospf-testcase.md` v1.0.0（逐条核对见 design §18.2）。

## 1. 测试原则

用例由设计 §1–§8 逐项派生，共 20 个唯一 ID，正例 12 个、负例/边界 8 个，顺序与设计 §7 及 JSON 完全一致。OSPFv2 是直接封装在 IPv4 Protocol 89 的 raw IP（裸 IP）协议，不是 TCP/UDP 会话；因此单报文正例 `packet_count=1`，六事件邻接交换为 `packet_count=6`。IPv4 无 option 时 OSPF header 起点是 `offset 34 = Ethernet 14 + IPv4 20`。正例每条有 `packet_count`、`has_payload`、至少一个字段或 frame（帧）断言；负例和 RFC5340 边界例的 `expect` **只能**包含 `expect_error` 与 `error_contains`，不对失败 PCAP 作结构断言。

固定 frame 只锚定 OSPF 公共头的前四字节（Version、Type、Packet Length），避免把自动 checksum 的未验证常量写死。OSPF packet checksum 和 LSA checksum 以 `nonzero` observable（可观察断言）检查；实际实现单测还必须按实现逐字节复算：packet checksum 与 LSA checksum 同用 RFC 1071 ones-complement `checksum()`（`builder.go:38`），LSA 面先清零 header checksum 字节再求和（`buildLSA :119-122`）——v1 底稿"Fletcher-16、排除 LS age"表述作废（design §10 裁定）。所有 IPv4 应用 offset 均为 34；IPv6 不使用 IPv4 offset，也不把 OSPFv2 checksum/LSA body 复制过去。

- 每个正例都有 `packet_count`、非空 `fields`、非空 `frames`、`has_payload=true`（实测 12/12 四项齐全）；`directional` 11 例 `false` + 1 例 `true`（仅 #10 六事件邻接交换为 `true`）。
- 字段全部来自 `tshark -G fields` 已注册的 `ospf.*` / `ip.*`；不写未经独立复算的固定 checksum 十六进制值。
- frames 只用可复算前缀（Version/Type/Length 组合：`02 01 00 30/34/2c`、`02 02 00 34`、`02 03 00 24`、`02 04 00 40/3c`、`02 05 00 40` 八类 + #10 六事件短前缀 `02 01/02/02/03/04/05`）；运行时随机/长度校验字段不进 frames。
- 每个负例的 `expect` 恰有两个键：`expect_error` 与 `error_contains`；无 `packet_count`/`fields`/`frames`（实测 8/8 合规）。
- 本协议无端口、无握手：`has_handshake` 零出现（实测 0/20），`terminates` 零出现（实测 0/20），不虚构建连包数；`notes` 12/12。
- 多事件例（#10）按事件序断言 packet 1..6；状态（Init→Full）只作配置携带与方向面断言，不作保留字段面断言（`neighbor_state` 不进线，design §10）。
- **严格解码边界（P1 实测，诚实声明）**：`ospf` 子映射经 `parseSubconfigJSON`（`strategy_convert_helpers.go:21-30`）用**普通 `json.Unmarshal`（无 `DisallowUnknownFields`）** 解码——未知键被静默忽略、不进 `ValidationErrors`。因此负例不得依赖"未知键被拒"，必须依赖 `planner.go` 的语义校验（8 负例锚词逐字见 §4）。P4 若要把未知键变红，需另立守卫（G-OSPF-4，跨协议共享面上报主线程）。
- **数量键边界（P1 实测）**：存量 20/20 无 `flow_control`/`strategy_fc`，数量全靠顶层旧键 `count=1`（20/20）；P4 按 design §14.1 逐例补兄弟键 `strategy_fc`（`flows` = packet_count，负例 `value=1` 占位）。

## 2. 原子用例索引（与设计、JSON 同序）

| # | ID | 类型 | 覆盖 | packet_count |
|---:|---|---|---|---:|
| 1 | `ospf_hello_dr_bdr` | 正 | Hello mask/timer/priority/DR/BDR/neighbor | 1 |
| 2 | `ospf_hello_neighbors` | 正 | 两个邻居、长度增长 | 1 |
| 3 | `ospf_dbd_master` | 正 | DBD I/M/MS、MTU、DD sequence、Router-LSA header | 1 |
| 4 | `ospf_dbd_slave` | 正 | DBD slave flags/sequence | 1 |
| 5 | `ospf_lsr_router_lsa` | 正 | LSR type 1 三元组 | 1 |
| 6 | `ospf_lsr_network_lsa` | 正 | LSR type 2 三元组 | 1 |
| 7 | `ospf_lsu_router_lsa` | 正 | Router-LSA flags/link/metric | 1 |
| 8 | `ospf_lsu_network_lsa` | 正 | Network-LSA mask/attached routers | 1 |
| 9 | `ospf_lsack` | 正 | 两个 LSA headers | 1 |
| 10 | `ospf_neighbor_full_exchange` | 正 | Hello→DBD→LSR→LSU→LSAck、状态 | 6 |
| 11 | `ospf_ipv4_transport` | 正 | IPv4 Protocol 89、TTL、IDs | 1 |
| 12 | `ospf_checksum_length` | 正 | packet/LSA length、两类 checksum | 1 |
| 13 | `ospf_neg_udp` | 负 | UDP 载体（`wire_fault.kind=carrier`） | — |
| 14 | `ospf_neg_ipv6_v2` | 负 | IPv6 不得复用 RFC2328 IPv4（v6 地址） | — |
| 15 | `ospf_neg_version` | 负 | version=3（首中 `:24` 分支） | — |
| 16 | `ospf_neg_type` | 负 | 未知 packet type | — |
| 17 | `ospf_neg_length` | 负 | packet length 故障（`declared_length`） | — |
| 18 | `ospf_neg_area` | 负 | malformed Area ID（`wire_fault area_id`） | — |
| 19 | `ospf_neg_router_id` | 负 | malformed Router ID | — |
| 20 | `ospf_ipv6_rfc5340_boundary` | 边界负例 | RFC5340 独立 profile 未实现 | — |

packet_count 序列（正例 12 个，按序）：`[1,1,1,1,1,1,1,1,1,6,1,1]`（总包数 17）。

## 3. Positive（正例）断言契约

### 3.1 `ospf_hello_dr_bdr`（T-OSPF-S1）

一个 IPv4 OSPFv2 Hello，`packet_length=48`，offset 34 frame 前缀 `02 01 00 30`。24-byte 公共头之后是固定 20-byte Hello body 和一个 4-byte neighbor Router ID。断言 `router_id=1.1.1.1`、`area_id=0.0.0.0`、mask `255.255.255.0`、Hello/Dead=`10/40`、priority=1、DR=`10.0.0.2`、BDR=`10.0.0.3`、neighbor=`2.2.2.2` 以及 OSPF checksum 非零。该例不把 224.0.0.5 推断成 DR。

### 3.2 `ospf_hello_neighbors`（T-OSPF-S2）

Hello 有两个邻居 `2.2.2.2,3.3.3.3`，`packet_length=52`，offset 34 前缀 `02 01 00 34`，断言 neighbor count=2。该例单独证明邻居列表每个 Router ID 增加 4 bytes，而不是让一个邻居例覆盖列表边界。

### 3.3 `ospf_dbd_master`（T-OSPF-S3）

DBD `packet_length=52`，前缀 `02 02 00 34`，Interface MTU=1500，I/M/MS 全置位（observable `flags=0x07`），DD sequence=100，携带一个 type 1 Router-LSA header。DBD 只携带 LSA header，不伪造完整 LSA body。

### 3.4 `ospf_dbd_slave`（T-OSPF-S4）

独立 DBD slave 用例，前缀仍为 `02 02 00 34`，断言 I/M/MS 清零、DD sequence=101 和 type 1 header。master/slave 不能合并为一个 flags 可选的宽松断言，否则会漏掉状态方向错误。

### 3.5 `ospf_lsr_router_lsa`（T-OSPF-S5）

LSR `packet_length=36`，前缀 `02 03 00 24`，请求 `lsa_type=1`、LSID=`1.1.1.1`、advertising Router=`1.1.1.1`。每个 LSR request 固定 12 bytes；字段三元组必须分别断言。

### 3.6 `ospf_lsr_network_lsa`（T-OSPF-S6）

LSR 同为 36 bytes，但 `lsa_type=2`、LSID=`10.0.0.2`、advertising Router=`1.1.1.1`。LSID 是 DR 接口地址；该例避免只测试 Router-LSA type=1。

### 3.7 `ospf_lsu_router_lsa`（T-OSPF-S7）

LSU `packet_length=64`，前缀 `02 04 00 40`，包含 count=1 和一个 36-byte Router-LSA。断言 LSA type=1、LSA length=36、flags=0、link count=1、link type=2、metric=10 和 LSA checksum 非零。长度公式为 `24 + 4 + 36 = 64`。

### 3.8 `ospf_lsu_network_lsa`（T-OSPF-S8）

LSU `packet_length=60`，前缀 `02 04 00 3c`，包含一个 32-byte Network-LSA：mask=`255.255.255.0`、attached routers=`1.1.1.1,2.2.2.2`、LSID=`10.0.0.2`。长度公式为 `24 + 4 + (20 + 4 + 8) = 60`，断言 LSA length=32，避免将 LSU packet length 和 LSA length 混同。

### 3.9 `ospf_lsack`（T-OSPF-S9）

LSAck `packet_length=64`，前缀 `02 05 00 40`，携带两个 20-byte LSA headers，分别是 type 1/2、LSID `1.1.1.1/10.0.0.2`、length `36/32`。只断言 header，不把 LSA body 错塞进 LSAck。

### 3.10 `ospf_neighbor_full_exchange`（T-OSPF-S10）

六个 raw IPv4 OSPF 报文按事件顺序发送：Hello（Init）、DBD master（ExStart）、DBD slave（Exchange）、LSR（Loading）、LSU（Loading）、LSAck（Full）。`packet_count=6`，每个事件占一个 packet；断言每包 type、DBD flags、LSU count、LSAck count 及方向（本例唯一 `directional=true`）。状态字段必须按独立 session 维护（仅携带，不进线——design §10），不得跨 packet 猜测或隐式补响应。

### 3.11 `ospf_ipv4_transport`（T-OSPF-S11）

Hello `packet_length=44`（无邻居，前缀 `02 01 00 2c`），源 `10.0.0.9`、目的 224.0.0.5、TTL=1。断言 `ip.version=4`、`ip.proto=89`、`ip.ttl=1`、目的地址、Router ID=`10.10.10.10`、Area ID=`0.0.0.1` 和非零 checksum。OSPF 没有端口字段，不能用 TCP/UDP 端口替代协议号。

### 3.12 `ospf_checksum_length`（T-OSPF-S12）

含一个 Router-LSA 的 LSU，`packet_length=64`，Area ID=`0.0.0.2`、Router ID=`3.3.3.3`，目的 `224.0.0.6`（AllDRouters），断言 OSPF packet checksum 和 LSA checksum 均非零，packet length=64、LSA length=36。实现单测必须再验证 packet checksum 与 LSA checksum 的数值和 ones-complement（反码）计算（同一 `checksum()` 函数，`builder.go:38`），而非仅满足非零。

- frames offset 单档实测：**34**（全部 17 帧，含 #10 六事件短前缀）；hex 八类前缀：`02 01 00 30`（#1）/ `02 01 00 34`（#2）/ `02 02 00 34`×2（#3/#4）/ `02 03 00 24`×2（#5/#6）/ `02 04 00 40`×2（#7/#12）/ `02 04 00 3c`（#8）/ `02 05 00 40`（#9）/ `02 01 00 2c`（#11）+ #10 六事件短前缀 `02 01/02/02/03/04/05`，与 design §3 Type/长度表逐值一致。
- 字段去重口径实测 34 个（`ospf.*` 30 + `ip.*` 4）：`ospf.advrouter/area_id/checksum/db.dd_sequence/db.interface_mtu/dbd/hello.active_neighbor/hello.backup_designated_router/hello.designated_router/hello.hello_interval/hello.network_mask/hello.router_dead_interval/hello.router_priority/link_state_id/ls.number_of_lsas/lsa/lsa.chksum/lsa.id/lsa.length/lsa.network.attchrtr/lsa.network.netmask/lsa.number_of_links/lsa.router.linkid/lsa.router.linktype/lsa.router.metric0/msg/packet_length/srcrouter/v2.router.lsa.flags/version` + `ip.dst/ip.proto/ip.ttl/ip.version`；逐个对 `tshark -G fields`（本机 3.6.14，`ospf.*` 324 字段）**命中 34/34，零自创**（P1 实测，见 §9.6）。

## 4. Negative（负例）契约

8 个负例必须都以任务错误终止，`error_contains` 逐字对已落码锚词（P1 实测行号，非设计臆造；`invalid packet_type` 底层串出自 `builder.go:34`）：

| # | ID | 故障输入（存量形状） | `error_contains` | 代码锚点（实测） |
|---:|---|---|---|---|
| 13 | `ospf_neg_udp` | `wire_fault={kind:carrier,value:udp}` | `ip` | `planner.go:41-42`（串含 "carrier must be ip protocol 89"） |
| 14 | `ospf_neg_ipv6_v2` | v6 src/dst（`2001:db8::1→ff02::5`）+ version=2 + `rfc2328_ipv4` | `rfc5340` | `planner.go:31-32/:34-35`（串含 "rfc5340/OSPFv3 is IPv6"） |
| 15 | `ospf_neg_version` | version=3 + `rfc2328_ipv4` | `version` | `planner.go:24` 首中分支（串 "version/profile uses rfc5340…" 同时含 `version` 与 `rfc5340`；不走 `:44-45` 纯 version 分支） |
| 16 | `ospf_neg_type` | `packet_type=unknown` | `type` | `planner.go:55-56` 经 `packetTypeFromString`（`builder.go:34`） |
| 17 | `ospf_neg_length` | `wire_fault={kind:declared_length}` | `length` | `planner.go:73-74` |
| 18 | `ospf_neg_area` | `wire_fault={kind:area_id,value:malformed}` | `area` | `planner.go:66-67`（自然非法 area 为 `:69-70`） |
| 19 | `ospf_neg_router_id` | `router_id=not-an-ip` | `router` | `planner.go:62-63` |
| 20 | `ospf_ipv6_rfc5340_boundary` | version=3 + `profile=rfc5340_ipv6` + v6 地址 | `rfc5340` | `planner.go:24-25` |

不允许通过空 PCAP、0 packet 或忽略错误来满足断言。**注意 §1 严格解码声明**：#13/#17/#18 的 `wire_fault` 三键（`carrier/declared_length/area_id`）对 `OSPFWireFault`（`routing.go:166-169`）全量合法——真正生效的判死路径是 planner 语义校验（`:41/:73/:66`），P4 改写时保持层内触发源。`ospf_ipv6_rfc5340_boundary` 不等同 OSPFv3 正例：未来实现 RFC5340 时，应新增独立正例并重新定义其 IPv6 offset、Next Header、Instance ID、checksum 和 LSA 断言。

## 5. 存量 20 例逐条去向审计（§9.14；P1 存量实测，P4 按本表执行）

存量现状（2026-09-27 实测，`cases/ospf.json` 1729 行）：20/20 链形为 `layers=[{"ip":{}},{"ospf":{}}]`（**链形已对**），但层内全空——地址/TTL/数量/业务全在顶层（旧扁平形）。顶层键双形状：18 例 `['count','dst_ip','layers','ospf','src_ip','ttl']` + 2 例（#14/#20）`['count','dst_ip','layers','ospf','src_ip']`（无 `ttl`，v6 拒绝触发源）；20/20 无 `flow_control`/`strategy_fc`（数量全靠顶层 `count=1`）。去向：12 正例全部**合入**（层链整形后保留语义，期望值不照抄——先跑后钉）；8 负例全部**合入**（锚词已对真实代码行，见 §4）。

| # | ID | 去向 | 改写要点 |
|---:|---|---|---|
| 1 | `ospf_hello_dr_bdr` | 合入 | `src_ip/dst_ip/ttl/count`→`layers[0].ip` + `strategy_fc.flows=1`；`ospf` 子映射（Hello 15 键）→`layers[1]` |
| 2 | `ospf_hello_neighbors` | 合入 | 同上；双邻居保留（52B 长度增长面） |
| 3 | `ospf_dbd_master` | 合入 | 同上；MTU/flags 全置/seq 100/LSA header 保留 |
| 4 | `ospf_dbd_slave` | 合入 | 同上；flags 清零/seq 101 保留（与 #3 分立） |
| 5 | `ospf_lsr_router_lsa` | 合入 | 同上；type 1 三元组保留 |
| 6 | `ospf_lsr_network_lsa` | 合入 | 同上；type 2 三元组保留（LSID=DR 地址面） |
| 7 | `ospf_lsu_router_lsa` | 合入 | 同上；Router-LSA flags/link/metric/length 保留 |
| 8 | `ospf_lsu_network_lsa` | 合入 | 同上；Network-LSA mask/attached/length 保留 |
| 9 | `ospf_lsack` | 合入 | 同上；双 header（type 1/2）保留 |
| 10 | `ospf_neighbor_full_exchange` | 合入 | 同上；6 事件保留（`directional=true` 保持）；补 `flows=6` |
| 11 | `ospf_ipv4_transport` | 合入 | 同上；`src_ip=10.0.0.9`（单播源语义）+ 无邻居 44B 保留 |
| 12 | `ospf_checksum_length` | 合入 | 同上；`dst=224.0.0.6` + 双 checksum nonzero 保持 |
| 13 | `ospf_neg_udp` | 合入 | `carrier` wire_fault 留层内走拒（`ip` 锚词） |
| 14 | `ospf_neg_ipv6_v2` | 合入 | v6 src/dst 留层内走拒（IPv6 无可住层，按 1.12 拒绝通道表达，不删触发源） |
| 15 | `ospf_neg_version` | 合入 | version=3 留层内走拒（首中 `:24` 分支，`version` 锚词） |
| 16 | `ospf_neg_type` | 合入 | 非法 packet_type 留层内走拒（`type` 锚词） |
| 17 | `ospf_neg_length` | 合入 | 事件外 `wire_fault declared_length` 留层内；锚词 `length` 已对 |
| 18 | `ospf_neg_area` | 合入 | 事件外 `wire_fault area_id` 留层内；锚词 `area` 已对 |
| 19 | `ospf_neg_router_id` | 合入 | 非法 router_id 留层内；锚词 `router` 已对 |
| 20 | `ospf_ipv6_rfc5340_boundary` | 合入 | `rfc5340_ipv6` + version=3 + v6 地址留层内走拒（`rfc5340` 锚词） |

作废 0 例，等价覆盖 0 例（无重复语义可合并）。

## 6. 三方一致性清单

1. 设计、本文和 JSON 各有相同的 20 个 ID、相同顺序、12 正例与 8 负例/边界。
2. 正例 packet_count 序列为 `[1,1,1,1,1,1,1,1,1,6,1,1]`（总包数 17）；负例没有 packet_count。
3. 12 个正例都有 `has_payload=true`、fields 和 frames，并逐包观察 OSPF Type 及八类前缀；`ip.proto=89` 全正例显式断言（12/12）；`directional=true` 仅 #10。
4. Hello 的单/双/零邻居、DBD 的主/从、LSR 的 type 1/2、LSU 的 Router/Network、LSAck 双 header、多事件邻接、transport 单播面、双 checksum 面均有独立场景。
5. checksum 明确为 RFC 1071 ones-complement（packet 与 LSA 同一函数，design §10 裁定）；PCAP 不虚构固定 checksum 常量，`checksum_mode` 后三值只走 A′ T-21。
6. IPv6/RFC5340 只有拒绝用例，未将 OSPFv3 当作正例。
7. `ospf` 层已注册、代码已落码；P4 层链整形后跑全量 suite（`CASE_PROTO=ospf`）与 tshark 验证才算完成，不以"任务不失败"充数。

## 7. 实现后执行顺序

先执行 JSON 语法、ID 顺序、正负 expect 结构、offset/hex 静态检查；再按 1–12 验证 Hello、DBD、LSR、LSU、LSAck、邻接交换、transport、checksum/length，最后按 13–20 验证每个拒绝路径和错误传播。tshark 对 Hello 计时器/DR 面（`ospf.hello.*`）与 DBD/LSA 扩展字段（`ospf.db.*`/`ospf.lsa.*`/`ospf.v2.router.lsa.*`）与 LSR 三元组字段已在存量断言中实证可读；若个别字段在目标版本未识别，以原始 offset bytes、IP protocol 和实现单测为补充证据，不凭名称字符串宣称通过。

## 8. 修订记录

- v2.0.0（2026-09-27）：P3 完整产物。新增 §5 存量 20 例逐条去向审计表（旧扁平形→层链目标形，P4 执行）、§9 固定动作（§3.15 三项 / A′B′ 两分类 / 9.52 对账 / 3.14 豁免审计 / 三源回指 / 断言契约核对 / 性能验收与六类场景）；§4 锚词表改为对已落码行号实测（含 version=3 首中分支注记）；§1 状态与严格解码边界更正（层已注册、普通 `json.Unmarshal` 未知键静默、20/20 缺数量键）；§3 补 frames 八类前缀与字段 34/34 命中实测；LSA checksum 口径按 design §10 裁定更正（RFC 1071 风格，作废 Fletcher-16）。
- v1.0.0（2026-08-20，`37-ospf-*`）：建立 12 个正例与 8 个负例/边界，覆盖 RFC 2328 IPv4、Hello/DBD/LSR/LSU/LSAck、Router/Network LSA、邻接状态、DR/BDR、checksum/length、IPv4 Protocol 89 及 RFC5340 独立边界。

## 9. P3 固定动作（CORE_MEMORY §3.15 / §9.52 / §9.14 / 覆盖审计要求面）

### 9.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | ospf 无连接——对照落"同会话多报文序列"：Hello → DBD（主/从）→ LSR → LSU → LSAck（#10 六包，Init→Full 携带）；DBD 主从分立（#3/#4）为同报文类多轮 | 已覆：#10 多轮 + #3/#4 分立 |
| ② | 非正常结束 | 载体错/v6 地址/version/type/length/area/router 八类拒收，全部 task error 终态 | 已覆：#13–#20（8 负例，锚词逐字见 §4） |
| ③ | 长保活 | ospf 无自有保活/重传确认语义（无连接）→ 显式记**不适用**；Hello 周期重发 → **B′ 立项 G-OSPF-2**（RFC 2328 计时器章节精确语义待确认） | 不适用 + B′ 立项（显式声明，不用"待确认"逃逸） |

无空项。

### 9.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流/地址族/断言通道六类）

A′（引擎可构建 → 20 ID 内已覆；**A′ 补例建议 = T-21/T-22**（对称缺格），并入与否由主线程定，不影响 §2 的 20 ID 权威口径）：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | mask/计时器/priority/DR/BDR/0–2 邻居 / MTU/flags/sequence / LSR 三元组 type 1/2 / Router flags-link-metric / Network mask-attached / 双 header | #1/#2/#11/#3/#4/#5/#6/#7/#8/#9 已覆；非法形 → 负例 #15/#16/#17/#18/#19 |
| 业务 | Hello→DBD→LSR→LSU→LSAck 状态变迁/主从分立/双 LSA 类型切换 | #10/#3/#4/#5/#6/#7/#8 已覆；载体/地址违规 → 负例 #13/#14/#20 |
| 现网 | 路由器 Hello/DR 选举/DB 交换/LSA 泛洪/邻接全流程 | #1–#12 已覆外壳；**抓包级确认 → G-OSPF-1**（确认方式：抓路由器回环包）；周期调度差异面 → G-OSPF-1 |
| 多流 | 六事件扇出（#10）+ 主从分立（#3/#4）+ 双 LSA 类型（#5/#6/#7/#8） | #10/#3–#8 已覆；多会话并发交织序 → G-OSPF-2（不假设调度器交织顺序）；**`checksum_mode` 三值缺格 → A′ T-21**；**DBD 空摘要缺格 → A′ T-22** |
| 地址族 | IPv4 全覆；IPv6 只有拒绝例（OSPFv3 另议） | #14/#20 已覆（拒绝通道）；**IPv6 无正例**=显式设计决策（design §1），不是缺口 |
| 断言通道 | `ospf.*` 30 + `ip.*` 4 = 去重 34 字段（34/34 实测命中）+ frames hex 八类前缀 offset 34 单档 | 全正例双通道；checksum 只 nonzero；`notes` 12/12 |

B′（引擎结构缺口 → D-OSPF-1「明确不解决 + 迁入计划」，见 design §17 G-OSPF-2/G-OSPF-4）：认证扩展（AuType≠0）、扩展 LSA 类型（type 3–7/AS-external/opaque）、定时器调度语义（Hello 周期重发、DD 重传）、多会话并发交织序假设、未知 ospf 键拒绝守卫（→ G-OSPF-4，跨协议共享面上报主线程）。

### 9.3 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **规范反推**（RFC 2328 OSPFv2 五类报文；精确章节号待 G-OSPF-1），**非**引擎能力面反推。引擎侧只作现状取证：`ospf` 已注册（`registry.go:940`）/白名单（`protocols.go:46`）/builder+planner+generator 已落码（`internal/protocol/ospf/` 905 行，15 个测试函数）/`cases/ospf.json` 20 例（旧扁平形）/tshark `ospf.*` 324 字段实测。第三源"已确认现网行为"当前=未确认级，挂 G-OSPF-1。
- **对账两行**：**规范逻辑点总数 = 57**（design §13.1 八项 8 行 + §13.2 报文×邻接状态矩阵 36 格 + §13.3 数据形态变体表 13 行 = 57 格/行）；**用例覆盖数 = 42**（八项 8 行全有结论 + 矩阵 21 格〔已覆 10 + 负例通道 11〕+ 变体 13 行，全部由 20 个语义 ID 承载）；**不适用 = 15**（矩阵 15 格，显式声明不适用≠缺口）。42 + 15 = 57 ✓ 无遗漏。
- **口径说明（防误读）**：上行的 57 点按"已覆 21（含负例通道 11）/不适用 15/正例直覆 21"归并计入 42；八项 8 行按"已覆"归并计 1 点/行；变体 13 行逐行有例。P4 新增的 4 例链级红例（presence/白名单/TCP 载体/缺 ip，design §14-P2）为**矩阵外项**，不计入本对账总数（新建后单独列）。**反查 20/20 绿 ≠ 覆盖全**——反查只证明清单内的点有例，本对账才证明清单本身全（§9.52 原文）。

### 9.4 3.14 豁免边界审计

- 本协议**无连接**（单向 IPv4 组播/单播报文，无 tcp/udp 载体）——但 §3.14 明示"豁免 `sessions[]` 不等于豁免多流覆盖"。本文**不主张任何豁免**：多报文序列由 `events[]` 显式声明（design §14.3 会话表），且 #10 覆盖 6 包邻接扇出。
- **多流并发**：已覆 #10（6 事件五类报文序）+ #3/#4（主从分立）+ #5/#6/#7/#8（双 LSA 类型面）。
- **单包多载荷**：双邻居（#2）、双 request 面（#5/#6 分立两例）、双 header（#9）、完整 LSA body（#7/#8）已覆 → 显式记已覆；扩展 LSA 变体 → B′（G-OSPF-2），不是豁免逃逸。
- **多事务**：同会话内 Hello→DBD→LSR→LSU→LSAck 多轮（#10）已覆。
- 结论：多流、单包多载荷、多包序列三项各有结论，无逃逸。

### 9.5 三源回指行

RFC 2328（五类报文 Type/公共头/Hello 计时器/DR 面/DBD I-M-MS/LSR 三元组/LSU count+LSA/LSAck）→ **D-OSPF-1**（design §15）→ `trafficgen/test/protocol_pcap/cases/ospf.json`（20 例）。第三源"已确认的现网行为"当前为**未确认级**（design §13.4 ②），挂 G-OSPF-1 且按 §5.5 不写死进实现。ID 权威 = 本文 §2（12 正 + 8 负）。

### 9.6 断言契约核对结论（与 design §1/§7/§15 一致）

1. **20 ID 契约核对**：本文 §2 与 design §7 逐 ID、逐序、逐类型、逐 `packet_count` 一致——12 正例（`[1,1,1,1,1,1,1,1,1,6,1,1]`，总包数 17）+ 8 负例（`expect` 只有 `expect_error`/`error_contains`，锚词 `ip/rfc5340/version/type/length/area/router/rfc5340` 逐字对 `planner.go` 真实行）。
2. **存量审计（§9.14）**：见 §5 去向表。20 例链形已对但层内全空（顶层四键 + `ospf` 子映射 + 无 `strategy_fc`），P4 按去向表逐例改写，**不搬运旧期望值**（逗号拼接多值/frames 前缀等先跑后钉）。
3. **断言通道核对**：34 个字段（`ospf.*` 30 + `ip.*` 4）逐个注册命中（`tshark -G fields` 324 个中的 30 + IP 核心 4，34/34 精确命中）；frames hex 八类前缀 offset 34 单档实测；`has_handshake`/`terminates` 零出现（无连接协议诚实口径）；`notes` 12/12。
4. **packet_count 纪律**：§2 的约定值随 P4 **先跑后钉**（§9.31/§14.6），以落盘 pcap 实测校准；#10 的 6 已在存量断言中给出，需 P5 复核事件数与包数一一对应。

### 9.7 性能设计与验收（§6.1–6.8 要素；细目见 design §15）

- 目标口径：O(n) 流式——`Generate` 单报文直发 + 事件序 for 循环直发 `req.Emit`，无按包增长结构、无全量聚合（design §15 主流程）；无锁无 sleep（事件驱动，非定时器模型）。
- 两路验收（§6.3）：**pcap 路**——suite 全量落盘 `/tmp/mcp-pcaps/ospf/`，tshark 逐字段校对；**NIC 路**——过滤器 `ip proto 89`，测试网口按 testing-interface 记忆（`enp135s0f0np0`），关注组播目的与 TTL=1 在线上可见。
- 六类场景（§6.6）P5 跑测覆盖：基线（#1 单包）/目标规模（#10 六包事件）/压力上限（`strategy_fc.flows=N` 大 N × 事件序）/长时间运行/并发交错（#10 多事件）/资源耗尽背压（队列满走既有 pipeline 语义）。
- 失败边界（§6.5 诚实待确认）：吞吐/并发/内存目标数字待 P4 基准后定，本契约不写承诺数字；功能正确但超预算按 §6.8 视为不合格。

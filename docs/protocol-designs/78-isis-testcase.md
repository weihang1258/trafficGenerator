# IS-IS（中间系统到中间系统，ISO 10589）测试用例契约

> 版本：v1.0.0（P3 文档轨产物；Lane A #78 isis）
> 日期：2026-09-27
> 配套设计：`docs/protocol-designs/78-isis-design.md` v1.0.0（D-ISIS-1 草稿 §11；门1 获批=定稿）
> 机器契约：`trafficgen/test/protocol_pcap/cases/isis.json`（现存 **25** 例，2063 行；旧混合形——顶层 `src_mac` + 空层 + 顶层 `isis` 子映射，P4 按 §5 去向表改写）
> 状态：**设计阶段**。`isis` 层已注册、builder/planner/generator 已落码（`registry.go:946`，`internal/protocol/isis/` 1251 行，21 个单元测试函数），D-ISIS-1 未定稿——P4 落码前以门1 获批版为准，**不宣称当前 suite 可运行**。本文不跑 suite、不启动服务器；ID 权威 = 本文 §2。
> 旧基线：`docs/protocol-designs/38-isis-testcase.md` v1.0.1（逐条核对见 design §14）。

## §1 测试原则与形状基线

- **形状基线（CORE_MEMORY §1）**：`spec_json` 必须是**纯 layers** 形——MAC 只住 `eth` 层（`src_mac`/`dst_mac`）、业务只住 `isis` 层条目、数量只走 `flow_control`；顶层只允许 `layers`/`flow_control` 家族/`output`（§1.11）。**正例顶层键 = 0**（白名单外即红）。
  **本协议存量实况（实测）**：25/25 例为旧混合形——24 例顶层键 `['isis','layers','src_mac']`（顶层 `src_mac` 影子 + 空层 + 顶层 `isis` 子映射）+ 1 例（#19）`['isis','layers']`；`layers` 24/24 = `[{"eth":{}},{"isis":{}}]` 全空 + 1 例 `[{"ip":{}},{"isis":{}}]`（拒绝触发源）；25/25 无 `flow_control`/`strategy_fc`；`src_ip/dst_ip/src_port/dst_port/count/ttl` 零出现。P4 按 §5 去向表逐例改写，只"守住"无"迁移旧扁平"负担（L2-only 无 IP/端口旧键），改写纪要见设计 §12.1。
- **载体**：`isis` 为 L2-only 终结层，链形 `[eth, isis]`。链含 `ip`/`tcp`/`udp`（`[ip,isis]`/`[eth,tcp,isis]`）判死（V7b `complete.go:337-356`，锚词 `carrier`）。**IP/端口面不存在**（设计 §2）。
- **MAC**：`eth.src_mac` 为 fixture（存量 24/25 `02:00:00:00:10:01`）；目的组播恒 `:15`（→ G-ISIS-5），存量零 `eth.dst` 断言。
- **方向与状态（本协议特有）**：`neighbor_state` 只携带不进线（设计 §12.3）；所有正例 `directional=false`（实测 13/13），`has_handshake`/`terminates`/`notes` 零出现（实测 0/25）。
- **断言通道（实测）**：主通道 = tshark `isis.*`（本机 TShark 3.6.14 实测 **498** 字段，口径 `tshark -G fields | awk -F'\t' '$1=="F" && $3 ~ /^isis[.]/' | wc -l`）；用例去重 **28** 字段，28/28 注册命中，零自创（§6.3 明细）。辅通道 = `frames` hex（三档 offset：12 = 二层类型/长度、14 = LLC 起、17 = PDU 首字节 `83` 起；仅 LLC profile 有 offset 17）。
- **固定 checksum 纪律**：存量 8 个 LSP checksum 为固定 hex（`0xb792` 等，见 §3）；实现单测已逐字节复算（`TestLSPFletcherChecksumVariation`），P5 必须**先跑后钉**复核实现单测与 pcap 一致性——固定值今日不断言为跨样本事实（§8.6 注记）。
- **负例纪律（§14.11/§14.12）**：`expect` 键集合严格为 `{"expect_error","error_contains"}`（实测 12/12）；锚词与 validator/链校验字面值一一对应（设计 §7）。
- **包数公式**：单 PDU 事件 `packet_count = 1`；`events[N]` 序列 `packet_count = N`（事件与包一一对应，无隐式补发）。所有约定值按 §9.31/§14.20 **先跑后钉**。

## §2 原子用例索引（25 ID = 13 正 + 12 负，顺序为权威）

「P4」列：存量改写动作（§5 去向表）；A′ 补例 T-ISIS-26..30 见 §8.2（P4 落盘，不影响本表 25 ID 权威口径）。

| # | T-ID | JSON ID | 类型 | 覆盖 | P4 | packet_count |
|---:|---|---|---|---|---|---:|
| 1 | T-ISIS-01 | `isis_l1_iih_llc` | 正 | LLC、L1 LAN IIH、System ID、Area | 合入 | 1 |
| 2 | T-ISIS-02 | `isis_l2_iih_llc` | 正 | LLC、L2 IIH、Circuit Type、priority | 合入 | 1 |
| 3 | T-ISIS-03 | `isis_l1_iih_ethertype` | 正 | EtherType 0x8870、L1 IIH | 合入 | 1 |
| 4 | T-ISIS-04 | `isis_l2_iih_ethertype` | 正 | EtherType 0x8870、L2 IIH | 合入 | 1 |
| 5 | T-ISIS-05 | `isis_l1_lsp_ipv4` | 正 | L1 LSP、TLV 1/132、length/checksum | 合入 | 1 |
| 6 | T-ISIS-06 | `isis_l2_lsp_ipv6` | 正 | L2 LSP、TLV 232、IPv6 TLV profile | 合入 | 1 |
| 7 | T-ISIS-07 | `isis_l1_lsp_tlv_order` | 正 | 多标准 TLV 顺序/长度 | 合入 | 1 |
| 8 | T-ISIS-08 | `isis_l1_csnp` | 正 | CSNP range、TLV 9/LSP Entry | 合入 | 1 |
| 9 | T-ISIS-09 | `isis_l2_psnp` | 正 | PSNP TLV 9、L2 | 合入 | 1 |
| 10 | T-ISIS-10 | `isis_length_checksum` | 正 | PDU/LSP length、Fletcher checksum | 合入 | 1 |
| 11 | T-ISIS-11 | `isis_area_system_id` | 正 | Area、System ID、LSP ID | 合入 | 1 |
| 12 | T-ISIS-12 | `isis_neighbor_up_sequence` | 正 | IIH/IIH/LSP/PSNP、状态顺序 | 合入 | 4 |
| 13 | T-ISIS-13 | `isis_ipv4_ipv6_tlv_profiles` | 正 | 独立 IPv4/IPv6 TLV profile | 合入 | 2 |
| 14 | T-ISIS-14 | `isis_neg_profile` | 负 | 未知 wire profile | 合入 | — |
| 15 | T-ISIS-15 | `isis_neg_identifier` | 负 | System ID 长度错误 | 合入 | — |
| 16 | T-ISIS-16 | `isis_neg_state` | 负 | 非法邻接状态事件 | 合入 | — |
| 17 | T-ISIS-17 | `isis_neg_address_family` | 负 | IPv4/IPv6 profile 混用 | 合入 | — |
| 18 | T-ISIS-18 | `isis_neg_duplicate_area` | 负 | Area 简写与显式 TLV 1 重复 | 合入 | — |
| 19 | T-ISIS-19 | `isis_neg_ip_carrier` | 负 | IP 载体（`[ip,isis]`） | 合入 | — |
| 20 | T-ISIS-20 | `isis_neg_mixed_carrier` | 负 | LLC 与 EtherType 混用 | 合入 | — |
| 21 | T-ISIS-21 | `isis_neg_header` | 负 | Common Header 非法 | 合入 | — |
| 22 | T-ISIS-22 | `isis_neg_level_type` | 负 | L1/L2 与 PDU type 不一致 | 合入 | — |
| 23 | T-ISIS-23 | `isis_neg_length` | 负 | PDU length/TLV 越界 | 合入 | — |
| 24 | T-ISIS-24 | `isis_neg_vendor_tlv` | 负 | 未登记厂商 TLV | 合入 | — |
| 25 | T-ISIS-25 | `isis_neg_checksum` | 负 | LSP Fletcher checksum 错误 | 合入 | — |

> packet_count 序列（正例 13 个，按序）：`[1,1,1,1,1,1,1,1,1,1,1,4,2]`（总包数 17）。与设计 §9 逐值一致。

## §3 正例逐项断言契约

> 通则：①每条正例 `expect` 含 `packet_count` + `has_payload=true` + 非空 `fields` + 非空 `frames`（实测 13/13 四项齐全）；②字段断言用 `isis.*`（28 去重字段，§6.3）；③载体字节走 frames hex（三档 offset）；④负例零混入。

1. **`isis_l1_iih_llc`**（T-ISIS-01）：LLC L1 LAN IIH，TLV 1（`03 49 00 01`）。断言 `isis.irpd=0x83`、`isis.len=27`、`isis.sysid_len=6`、`isis.type=15`、`circuit_type=0x01`、`source_id=0102.0304.0506`、`holding_timer=30`、`pdu_length=33`、`priority=100`、`lan_id=0102.0304.0506.01`、`area_address=03490001`。frames：off12 `00 2e`（802.3 length 46）/ off14 `fe fe 03` / off17 `83 1b 01 06 0f 01 00 00`（公共头 8B）。
2. **`isis_l2_iih_llc`**（T-ISIS-02）：LLC L2 IIH。`isis.type=16`、`circuit_type=0x02`、`source_id=0a0b.0c0d.0e0f`、`holding_timer=45`、`priority=64`、`lan_id=0a0b.0c0d.0e0f.02`、`area_address=03490002`；其余公共头同 #1。frames off17 尾字节 `10`（L2 type）区别于 #1 的 `0f`。
3. **`isis_l1_iih_ethertype`**（T-ISIS-03）：字段面与 #1 逐值相同（`isis.type=15` 等 11 字段）；frames：off12 `88 70` / off14 `fe fe 03 83 1b 01 06 0f 01`（LLC+公共头整体前置，生成器 `layer_gen.go:73-76`）。本例与 #1 构成 carrier 对称对。
4. **`isis_l2_iih_ethertype`**（T-ISIS-04）：字段面与 #2 逐值相同；frames off14 尾 `10 01`（L2）。与 #2 构成 carrier 对称对。
5. **`isis_l1_lsp_ipv4`**（T-ISIS-05）：LLC L1 LSP，TLV 1 + TLV 132（`c0 00 02 01`=192.0.2.1）。`isis.type=18`、`lsp.pdu_length=39`、`remaining_life=120`、`lsp_id=0102.0304.0506.00-00`、`sequence_number=0x00000001`、`checksum=0xb792`（固定值，P5 先跑后钉）、`is_type=1`。frames LLC 三档。
6. **`isis_l2_lsp_ipv6`**（T-ISIS-06）：ET L2 LSP，TLV 232（`2001:db8::1`）。`isis.type=20`、`lsp.pdu_length=45`、`lsp_id=0a0b.0c0d.0e0f.00-01`、`sequence_number=0x00000007`、`checksum=0xdeea`、`is_type=2`。**L2 LSP 无 LLC 例** → A′ T-ISIS-26。
7. **`isis_l1_lsp_tlv_order`**（T-ISIS-07）：ET L1 LSP，TLV 1 + TLV 132（与 #5 同 TLV 集，sequence=2、`checksum=0xb593`）。本例证明 TLV 顺序与长度编码面；与 #5 构成 carrier 对称（LLC/ET）+ sequence 递进对。
8. **`isis_l1_csnp`**（T-ISIS-08）：LLC L1 CSNP，TLV 9 单 entry（`00 78 01 02 03 04 05 06 00 00 00 00 00 01 00 01`）。`isis.len=33`、`isis.type=24`、`csnp.pdu_length=51`、`source_id=0102.0304.0506`、`start_lsp_id=0102.0304.0506.00-00`、`end_lsp_id=0102.0304.0506.ff-ff`、`clv.type=9`。frames off12 `00 36`（LLC(3)+PDU(51)=54）。**CSNP 无 ET 例** → A′ T-ISIS-27。
9. **`isis_l2_psnp`**（T-ISIS-09）：ET L2 PSNP，TLV 9 单 entry。`isis.len=17`、`isis.type=27`、`psnp.pdu_length=35`、`source_id=0a0b.0c0d.0e0f`、`clv.type=9`。**PSNP 无 LLC 例** → A′ T-ISIS-28。
10. **`isis_length_checksum`**（T-ISIS-10）：ET L1 LSP，TLV 132，大 sequence。`lsp.pdu_length=33`、`remaining_life=300`、`sequence_number=0x10203040`、`checksum=0x7e7e`（固定值，P5 先跑后钉）。本例为 checksum/length observable 专用面。
11. **`isis_area_system_id`**（T-ISIS-11）：LLC L2 LSP，TLV 1（`05 49 00 02 00 03`，双 area）。`isis.type=20`、`lsp.pdu_length=35`、`remaining_life=90`、`lsp_id=1122.3344.5566.03-02`、`sequence_number=0x00000009`、`checksum=0x0629`、`is_type=2`。Area/System/LSP ID 三身份同例面。
12. **`isis_neighbor_up_sequence`**（T-ISIS-12）：ET 四事件（全 `wire_profile=iso10589_ethertype`）：p1 IIH（Initializing，字段面同 #3）/ p2 IIH（Up，同字段）/ p3 LSP（Up，`pdu_length=33`、`remaining_life=120`、`sequence=0x00000001`、`checksum=0x5e3e`、`is_type=1`）/ p4 **L1** PSNP（`isis.len=17`、`isis.type=26`、`psnp.pdu_length=35`、`clv.type=9`）。`packet_count=4`，逐包断言 p1..p4。状态只作配置携带，不作 wire 字段断言。
13. **`isis_ipv4_ipv6_tlv_profiles`**（T-ISIS-13）：ET 双事件 LSP：p1 L1（`address_profile=ipv4_basic`，TLV 132，`clv.type=132`、`clv_ipv4_int_addr=192.0.2.1`、`checksum=0x5e3e`）/ p2 L2（`address_profile=ipv6_basic`，TLV 232，`clv.type=232`、`clv_ipv6_int_addr=2001:db8::1`、`checksum=0x22e2`）。独立地址族 profile 面；`packet_count=2`。

- frames 三档重数实测：**offset 12 ×17 / offset 14 ×17 / offset 17 ×5 = 39 帧**（LLC 例 5 例各 3 帧 = 15；ET 单包 6 例各 2 帧 = 12；#12 四事件 8 帧；#13 双事件 4 帧；15+12+8+4=39 ✓）。
- 字段 28 去重（§6.3）：`isis.irpd/len/sysid_len/type`（×17/17/17/17 包）+ `isis.hello.*` 7 字段（×6 包）+ `isis.lsp.*` 6 字段（×8 包）+ `isis.csnp.*` 5 字段（×1）+ `isis.psnp.*` 3 字段（×2）+ `clv.type` 3 面（LSP×2/CSNP×1/PSNP×2）+ `clv_ipv4/clv_ipv6_int_addr`（各 1）。

## §4 负例契约

12 个负例必须都以任务错误终止，`error_contains` 逐字对已落码锚词（P1 实测行号；#15 底层串出自 `builder.go:50`，#19 出自链校验 `complete.go:355`）：

| # | ID | 故障输入（存量形状） | `error_contains` | 代码锚点（实测） |
|---:|---|---|---|---|
| 14 | `isis_neg_profile` | `wire_profile=unknown_profile` | `profile` | `planner.go:28`（串含 "unknown wire profile"） |
| 15 | `isis_neg_identifier` | `system_id="0102"`（非 6 字节） | `system` | `builder.go:50` 经 `parseSystemID`（串 "system id … must be 6 bytes"） |
| 16 | `isis_neg_state` | `events[0]` kind=lsp + `neighbor_state=Down` | `state` | `planner.go:154`（串 "Down is only valid for IIH"） |
| 17 | `isis_neg_address_family` | `ipv4_basic` + TLV 232 | `address` | `planner.go:192`（串 "address family mismatch"） |
| 18 | `isis_neg_duplicate_area` | `area_addresses` + 显式 TLV 1 | `area` | `planner.go:58`（串 "duplicate area address source"） |
| 19 | `isis_neg_ip_carrier` | 链 `[ip,isis]`（唯一非 eth 链） | `carrier` | `complete.go:355` V7b（串 'must not have an ip/transport carrier'） |
| 20 | `isis_neg_mixed_carrier` | LLC 覆盖 + ethertype profile / `wire_fault kind=mixed_carrier` | `carrier` | `planner.go:66/69`（串 "mixed carrier"） |
| 21 | `isis_neg_header` | `wire_fault={kind:header,header_length:7}` | `header` | `planner.go:74`（串 "bad header … must be 8"） |
| 22 | `isis_neg_level_type` | `wire_fault={kind:level_type,pdu_type:20,circuit_type:2}` + level l1 | `level` | `planner.go:79`（串 "level/type mismatch"） |
| 23 | `isis_neg_length` | `wire_fault={kind:length,pdu_length:27}` | `length` | `planner.go:83/86`（串 "length mismatch"） |
| 24 | `isis_neg_vendor_tlv` | TLV type=250 | `tlv` | `planner.go:91`（串 "unsupported tlv type"） |
| 25 | `isis_neg_checksum` | `checksum_mode=manual` + `wire_fault{kind:checksum}` | `checksum` | `planner.go:102`（串 "bad LSP checksum"） |

不允许通过空 PCAP、0 packet 或忽略错误来满足断言。**注意 §1 固定 checksum 纪律**：#25 的 `wire_fault checksum` 是 planner 语义拒（`:101-103`），与 #10 的固定 hex 断言无关——P4 改写时保持层内触发源。`area_addresses` 仅 #18 使用（唯一简写用户，→ G-ISIS-2）；`p2p_hello` 零用例（→ G-ISIS-4）；TLV 236 零用例（→ A′ T-ISIS-30）。

## §5 存量 25 例逐条去向审计（§9.14；P1 存量实测，P4 按本表执行）

存量现状（2026-09-27 实测，`cases/isis.json` 2063 行）：25/25 旧混合形（24 例顶层 `['isis','layers','src_mac']` + 1 例 `['isis','layers']`）；`layers` 24/24 空 `[{"eth":{}},{"isis":{}}]` + 1 例 `[{"ip":{}},{"isis":{}}]`；25/25 无 `flow_control`/`strategy_fc`（数量今日无键）。去向：13 正例全部**合入**（层链整形后保留语义，期望值不照抄——先跑后钉）；12 负例全部**合入**（锚词已对真实代码行，见 §4）。

| # | ID | 去向 | 改写要点 |
|---:|---|---|---|
| 1 | `isis_l1_iih_llc` | 合入 | 顶层 `src_mac`→`layers[0].eth`；`isis` 子映射（IIH 7 键）→`layers[1]`；补 `flow_control.flows=1` |
| 2 | `isis_l2_iih_llc` | 合入 | 同上；L2 面（holding 45/priority 64）保留 |
| 3 | `isis_l1_iih_ethertype` | 合入 | 同上；ET 载体保留（与 #1 对称对） |
| 4 | `isis_l2_iih_ethertype` | 合入 | 同上；ET 载体保留（与 #2 对称对） |
| 5 | `isis_l1_lsp_ipv4` | 合入 | 同上；TLV 1+132、seq 1、`checksum=0xb792` 先跑后钉复核 |
| 6 | `isis_l2_lsp_ipv6` | 合入 | 同上；TLV 232、seq 7 保留 |
| 7 | `isis_l1_lsp_tlv_order` | 合入 | 同上；与 #5 同 TLV 集、seq 2 保留（顺序面） |
| 8 | `isis_l1_csnp` | 合入 | 同上；range 端点 + TLV 9 保留（`00 36` length 面） |
| 9 | `isis_l2_psnp` | 合入 | 同上；无 range 面保留 |
| 10 | `isis_length_checksum` | 合入 | 同上；大 sequence `0x10203040` + `checksum=0x7e7e` 先跑后钉复核 |
| 11 | `isis_area_system_id` | 合入 | 同上；双 area TLV + 独立 LSP ID 保留 |
| 12 | `isis_neighbor_up_sequence` | 合入 | 同上；4 事件保留；补 `flows=4`（事件数=包数一一对应） |
| 13 | `isis_ipv4_ipv6_tlv_profiles` | 合入 | 同上；双事件保留；补 `flows=2` |
| 14 | `isis_neg_profile` | 合入 | `unknown_profile` 留层内走拒（`profile` 锚词） |
| 15 | `isis_neg_identifier` | 合入 | 非法 system_id 留层内走拒（经 `builder.go:50`） |
| 16 | `isis_neg_state` | 合入 | Down+lsp 事件留层内走拒（`state` 锚词） |
| 17 | `isis_neg_address_family` | 合入 | profile/TLV 混用留层内走拒（`address` 锚词） |
| 18 | `isis_neg_duplicate_area` | 合入 | 简写+显式 TLV 1 留层内走拒（`area` 锚词；简写键本身 → G-ISIS-2） |
| 19 | `isis_neg_ip_carrier` | 合入 | `[ip,isis]` 链留层内走拒（V7b `carrier`；按 1.12 拒绝通道表达，不删触发源） |
| 20 | `isis_neg_mixed_carrier` | 合入 | LLC 覆盖 + `wire_fault` 留层内走拒（`carrier` 锚词） |
| 21 | `isis_neg_header` | 合入 | `wire_fault header` 留层内；锚词 `header` 已对 |
| 22 | `isis_neg_level_type` | 合入 | `wire_fault level_type` 留层内；锚词 `level` 已对 |
| 23 | `isis_neg_length` | 合入 | `wire_fault length` 留层内；锚词 `length` 已对 |
| 24 | `isis_neg_vendor_tlv` | 合入 | TLV 250 留层内走拒（`tlv` 锚词） |
| 25 | `isis_neg_checksum` | 合入 | `wire_fault checksum` 留层内；锚词 `checksum` 已对 |

作废 0 例，等价覆盖 0 例（无重复语义可合并；#3/#1 与 #7/#5 为 carrier 对称对，各有独立载体面，不合并）。

## §6 三方一致性清单

1. 设计、本文和 JSON 各有相同的 25 个 ID、相同顺序、13 正例与 12 负例。
2. 正例 packet_count 序列为 `[1,1,1,1,1,1,1,1,1,1,1,4,2]`（总包数 17）；负例没有 packet_count（实测 12/12）。
3. 13 个正例都有 `has_payload=true`、`directional=false`、非空 fields 和 frames（实测 13/13 四项齐全）；`has_handshake`/`terminates`/`notes` 零出现。
4. L1/L2 IIH、L1/L2 LSP、CSNP、PSNP、多事件邻接、双地址族、transport 双载体面均有独立场景；R4D/R5D/R6D/R7D 四 carrier 缺格 → A′ T-ISIS-26..29（设计 §10.2）。
5. checksum 今日为固定 hex，PCAP 口径以实现单测逐字节复算为准，P5 先跑后钉复核（§1 纪律）。
6. IPv4/IPv6 只有 TLV profile 面（`clv_ipv4/clv_ipv6_int_addr` 各 1 例），无 IP 外层；TLV 236 只有 A′ 补例（T-ISIS-30）。
7. `isis` 层已注册、代码已落码；P4 层链整形后跑全量 suite（`CASE_PROTO=isis`）与 tshark 验证才算完成，不以"任务不失败"充数。

## §7 实现后执行顺序

先执行 JSON 语法、ID 顺序、正负 expect 结构、offset/hex 静态检查；再按 #1–#13 验证 IIH、LSP、CSNP、PSNP、TLV、checksum/length、状态和地址族，最后按 #14–#25 验证每个拒绝路径和错误传播。tshark 对 IIH 面（`isis.hello.*`）与 LSP/CSNP/PSNP 扩展字段（`isis.lsp.*/csnp.*/psnp.*`）与 TLV 面已在存量断言中实证可读（28/28）；若个别字段在目标版本未识别，以原始 offset bytes、EtherType/LLC 载体和实现单测为补充证据，不凭名称字符串宣称通过。

## §8 P3 固定动作（CORE_MEMORY §3.15 / §9.52 / §9.14 / 覆盖审计要求面）

### §8.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | isis 无连接——对照落"同事件序多 PDU 序列"：IIH → IIH → LSP → PSNP（#12 四包，Initializing→Up 携带）；双地址族 LSP 对（#13 两包）为同报文类多轮 | 已覆：#12 多轮 + #13 分立 |
| ② | 非正常结束 | profile/system/state/address/area/carrier×2/header/level/length/tlv/checksum 十二类拒收，全部 task error 终态 | 已覆：#14–#25（12 负例，锚词逐字见 §4） |
| ③ | 长保活 | isis 无自有保活/重传确认语义（无连接二层信令）→ 显式记**不适用**；Hello/CSNP 周期重发 → **B′ 立项 G-ISIS-8**（ISO 计时器章节精确语义待确认） | 不适用 + B′ 立项（显式声明，不用"待确认"逃逸） |

无空项。

### §8.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流/地址族/断言通道六类）

A′（引擎可构建 → P4 落盘 T-ISIS-26..30；**ID 与断言在本文即定稿**，不影响 §2 的 25 ID 权威口径）：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | IIH holding/priority/LAN ID/circuit / LSP remaining/sequence/is-type / CSNP range / TLV 1/9/132/232 / 非法形 | #1–#13 已覆；非法形 → 负例 #14–#25；**TLV 236 缺格 → A′ T-ISIS-30** |
| 业务 | IIH→LSP→SNP 状态变迁/L1-L2 分级/双地址族切换 | #12/#13/#5/#6 已覆；状态违规 → #16 |
| 现网 | LAN Hello/LSP 泛洪/数据库同步/邻接全流程 | #1–#13 已覆外壳；**抓包级确认 → G-ISIS-7**（确认方式：抓路由器回环包） |
| 多流 | 四事件扇出（#12）+ 双事件扇出（#13）+ 同 TLV 集双载体（#5/#7） | #12/#13/#5/#7 已覆；多会话并发交织序 → G-ISIS-8；**carrier 对称缺格 → A′ T-ISIS-26..29** |
| 地址族 | TLV 地址族双 profile（IPv4/IPv6 各一正例） | #5/#6/#13 已覆；**无 IP 外层**=显式设计决策（design §1），不是缺口 |
| 断言通道 | `isis.*` 28 去重字段（28/28 实测命中）+ frames hex 三档 offset | 全正例双通道；checksum 固定值 P5 先跑后钉；`directional` 13/13 false |

A′ 补例（P4 落盘，本文定稿 ID 与覆盖）：

| T-ID | 覆盖 | packet_count |
|---|---|---:|
| T-ISIS-26 | L2 LSP over LLC（R4D 缺格对称） | 1 |
| T-ISIS-27 | L1 CSNP over EtherType（R5D 缺格对称） | 1 |
| T-ISIS-28 | PSNP over LLC（R6D 缺格对称，L1/L2 任一） | 1 |
| T-ISIS-29 | 多事件序列 over LLC（R7D 缺格对称，#12 四事件 LLC 形） | 4 |
| T-ISIS-30 | TLV 236 IPv6 Reachability（通用编码直传面） | 1 |

B′（引擎结构缺口 → D-ISIS-1「明确不解决 + 迁入计划」，见 design §13 G-ISIS-2..8）：`area_addresses` 编码（G-ISIS-2）、CSNP 事件（G-ISIS-3，先修 bug）、P2P IIH（G-ISIS-4）、L1 组播 MAC（G-ISIS-5）、`manual` checksum（G-ISIS-6）、认证/扩展 TLV（G-ISIS-8）、周期重发定时器（G-ISIS-8）、多会话交织序（G-ISIS-8）、isis 层业务动态（G-ISIS-8）、未知 isis 键拒绝守卫（G-ISIS-1，跨协议共享面上报主线程）。

### §8.3 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **规范反推**（ISO 10589 四类 PDU × L1/L2 分级 + TLV 登记表逐项枚举），**非**引擎能力面反推。引擎侧只作现状取证：`isis` 已注册（`registry.go:946`）/白名单（`protocols.go:41`）/builder+planner+generator 已落码（`internal/protocol/isis/` 1251 行，21 个测试函数）/`cases/isis.json` 25 例（旧混合形）/tshark `isis.*` 498 字段实测。第三源"已确认现网行为"当前=未确认级，挂 G-ISIS-7。
- **对账两行**：**规范逻辑点总数 = 58**（design §10.1 八项 8 行 + §10.2 PDU×载体/状态矩阵 32 格 + §10.3 数据形态变体表 12 行 + §12.2 商业映射表 6 行 = 58 点）；**用例覆盖数 = 47**（八项 8 行全有结论 + 矩阵 22 格〔已覆 22〕+ 变体 11 行 + 映射 6 行，全部由 25 个语义 ID 承载）；**不适用 = 6**（矩阵 6 格，显式声明不适用≠缺口）；**缺口→A′通道 = 5**（矩阵 carrier 缺格 4 + 变体 TLV 236 缺行 1 → T-ISIS-26..30）。47 + 6 + 5 = 58 ✓ 无遗漏。
- **口径说明（防误读）**：上行的 58 点按"已覆 47（含矩阵已覆 22）/不适用 6/A′通道 5"归并计入；八项 8 行按"已覆"归并计 1 点/行。P4 新增的 4 例链级红例（presence/白名单/transport 载体/裸链，design §12-P2）为**矩阵外项**，不计入本对账总数（新建后单独列）。**反查 25/25 绿 ≠ 覆盖全**——反查只证明清单内的点有例，本对账才证明清单本身全（§9.52 原文）。

### §8.4 3.14 豁免边界审计

- 本协议**无连接**（单向二层组播 PDU，无 tcp/udp 载体）——但 §3.14 明示"豁免 `sessions[]` 不等于豁免多流覆盖"。本文**不主张任何豁免**：多 PDU 序列由 `events[]` 显式声明（design §12.3 会话表），且 #12 覆盖 4 包邻接扇出、#13 覆盖 2 包地址族扇出。
- **多流并发**：已覆 #12（4 事件四类 PDU 序）+ #13（双 LSP 地址族面）+ #5/#7（同 TLV 集双载体面）。
- **单包多载荷**：TLV 1+132 双 TLV（#5/#7）、双 area（#11）、双地址族分立（#13 双事件）已覆 → 显式记已覆；扩展 TLV 变体 → B′（G-ISIS-8），不是豁免逃逸。
- **多事务**：同事件序内 IIH→LSP→PSNP 多轮（#12）已覆。
- 结论：多流、单包多载荷、多包序列三项各有结论，无逃逸。

### §8.5 三源回指行

ISO 10589（四类 PDU Type/公共头/IIH 计时器/LSP checksum/CSNP range/PSNP entry/TLV 登记表；精确章节待 G-ISIS-7）→ **D-ISIS-1**（design §11）→ `trafficgen/test/protocol_pcap/cases/isis.json`（25 例）。第三源"已确认的现网行为"当前为**未确认级**（design §10.4 ②），挂 G-ISIS-7 且按 §5.5 不写死进实现。ID 权威 = 本文 §2（13 正 + 12 负）。

### §8.6 断言契约核对结论（与 design §1/§8/§11 一致）

1. **25 ID 契约核对**：本文 §2 与 design §9 逐 ID、逐序、逐类型、逐 `packet_count` 一致——13 正例（`[1×11,4,2]`，总包数 17）+ 12 负例（`expect` 只有 `expect_error`/`error_contains`，锚词 `profile/system/state/address/area/carrier/carrier/header/level/length/tlv/checksum` 逐字对已落码行）。
2. **存量审计（§9.14）**：见 §5 去向表。25 例旧混合形（顶层 `src_mac` + 空层 + 顶层 `isis` 子映射 + 无 `flow_control`），P4 按去向表逐例改写，**不搬运旧期望值**（checksum 固定 hex、`clv.*` 逗号多值、frames 前缀等先跑后钉）。
3. **断言通道核对**：28 个字段逐个注册命中（`tshark -G fields` 498 个中的 28，28/28 精确命中，零自创）；frames hex 三档 offset（12 ×17 / 14 ×17 / 17 ×5 = 39 帧）实测；`has_handshake`/`terminates`/`notes` 零出现（L2 无连接协议诚实口径）。
4. **packet_count 纪律**：§2 的约定值随 P4 **先跑后钉**（§9.31/§14.6），以落盘 pcap 实测校准；#12 的 4 与 #13 的 2 已在存量断言中给出，需 P5 复核事件数与包数一一对应。

### §8.7 性能设计与验收（§6.1–6.8 要素；细目见 design §11）

- 目标口径：O(n) 流式——`Generate` 单 PDU 直发 + 事件序 for 循环直发 `req.Emit`，无按包增长结构、无全量聚合（design §11 主流程）；无锁无 sleep（事件驱动，非定时器模型）。
- 两路验收（§6.3）：**pcap 路**——suite 全量落盘 `/tmp/mcp-pcaps/isis/`，tshark 逐字段校对；**NIC 路**——过滤器 `ether proto 0x8870`，测试网口按 testing-interface 记忆（`enp135s0f0np0`），关注组播目的与最小帧 padding 在线上可见。
- 六类场景（§6.6）P5 跑测覆盖：基线（#1 单包）/目标规模（#12 四包事件）/压力上限（`flow_control.flows=N` 大 N × 事件序）/长时间运行/并发交错（#13 双事件）/资源耗尽背压（队列满走既有 pipeline 语义）。
- 失败边界（§6.5 诚实待确认）：吞吐/并发/内存目标数字待 P4 基准后定，本契约不写承诺数字；功能正确但超预算按 §6.8 视为不合格。

## §9 修订记录

- v1.0.0（2026-09-27）：P3 完整产物。新增 §5 存量 25 例逐条去向审计表（旧混合形→层链目标形，P4 执行）、§8 固定动作（§3.15 三项 / A′B′ 两分类 + A′ 补例 T-ISIS-26..30 / 9.52 对账 58=47+6+5 / 3.14 豁免审计 / 三源回指 / 断言契约核对 / 性能验收与六类场景）；§4 锚词表改为对已落码行号实测（含 V7b carrier 与 #15 builder 底层串注记）；§1 状态与固定 checksum 纪律更正（层已注册、checksum 固定值 P5 先跑后钉）；§3 补 frames 三档 offset 与字段 28/28 命中实测。
- v1.0.1（2026-08-20，`38-isis-*`）：建立 13 个 ISO 10589 二层正例和 12 个负例；覆盖 LLC/EtherType、L1/L2 IIH、LSP、CSNP、PSNP、标准 TLV、System ID/Area、PDU length、Fletcher checksum、邻接状态和 IPv4/IPv6 TLV 边界。

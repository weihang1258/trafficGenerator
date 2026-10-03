# IS-IS（中间系统到中间系统，ISO 10589）设计契约

> 版本：v1.0.0（P1–P2 文档轨产物；Lane A #78 isis）
> 日期：2026-09-27
> 车道：A 文档轨（REDO capable fresh write；旧基线 `38-isis-design.md` v1.0.1 只读参照，不修改；38→78 沿革见 §14）
> 配套文件：`docs/protocol-designs/78-isis-testcase.md`、`trafficgen/test/protocol_pcap/cases/isis.json`（现存 25 例，2063 行）
> 规范基线：ISO 10589（IS-IS 域内路由）；IP 集成 RFC 1195；TE 扩展 RFC 5305；IPv6 扩展 RFC 5308（精确章节号待 G-ISIS-7，不写死）
> **层链唯一真相**：本契约全文示例只有纯 `layers` 形——MAC 只住 `eth` 层（`src_mac`/`dst_mac`）、业务只住 `isis` 层条目、数量只走 `flow_control`；顶层只允许 `layers`/`flow_control` 家族/`output`（CORE_MEMORY §1.11–1.13）。任何顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`、`src_mac` 影子、`isis` 子映射都判违规。
> **注册与落码现状（P1 实测，行号真实）**：`isis` 终结层已注册（`layers/registry.go:946`，`CategoryTerminal + DependsOn ["eth"]`，L2-only `[eth→isis]` 链，注释 `:935`）；白名单已登记（`core/protocols.go:41`）；wire 编码 `internal/protocol/isis/builder.go`（447 行）+ 校验器 `planner.go`（226 行）+ 终结层生成器 `layer_gen.go`（184 行）+ 单元测试 `isis_test.go`（394 行，21 个测试函数）已落码；D-ISIS-1 未定稿——P4 落码前以门1 获批版为准，**不宣称当前 suite 可运行**。本文不修改任何 Go 实现。
> **命名注记**：`docs/protocol-designs/78-probe_smb-design.md` 已存在（不同 basename，和平共存；本车道不碰 probe_smb 任何文件）。旧 `38-isis-*` 留盘，去向审计见 §14。

## §0 白话一句

IS-IS 是路由器之间直接在二层以太网上互喊"我是谁、我连着谁"的协议（不经过 IP，没有端口也没有握手，比如邻居打招呼 IIH、链路状态 LSP、数据库同步 CSNP/PSNP，共四种报文）；它的层和生成代码其实已经在了（单元测试 21 个），问题是 25 条老用例还是旧写法（源 MAC 全放顶层、层内全空、业务键还在顶层子映射里），本契约把每条老用例怎么改、代码里还藏着哪几个真 bug 全部写清，等批准后实现轨照表施工。

## §1 范围、证据等级与 profile 边界

本版定义 ISO 10589 的 LAN IS-IS 基础 PDU：Level-1/Level-2 LAN IIH（Hello 报文）、LSP（链路状态报文）、CSNP（完整序列号报文）、PSNP（部分序列号报文）。协议直接承载在以太网二层，不经过 IPv4、IPv6、TCP 或 UDP。

本版定义两个相互独立的 wire profile：

| profile | 二层承载 | PDU 起点（无 VLAN） | 适用边界 |
|---|---|---:|---|
| `iso10589_llc` | IEEE 802.3 length 字段 + LLC `FE FE 03` + NLPID `83` | offset 17（以太网 14 + LLC 3） | ISO 10589/ISO 8802-2 LLC 载体 |
| `iso10589_ethertype` | EtherType `0x8870` + LLC `FE FE 03` + NLPID `83` | offset 14（LLC+PDU 整体起点） | EtherType 0x8870 载体 |

存量实测（`cases/isis.json`，25 例）：`iso10589_ethertype` 19 例、`iso10589_llc` 5 例、`unknown_profile` 1 例（负例）。EtherType profile 下生成器把 LLC 头整体前置进 payload（`layer_gen.go:73-76`），故两种 profile 的 frames 断言起点均为 offset 12（二层类型/长度字段）与 offset 14（`fe fe 03` 起）；只有 LLC profile 另有 offset 17（PDU 首字节 `83` 起）断言——存量 frames 共 39 帧：offset 12 ×17、offset 14 ×17、offset 17 ×5。

| 证据等级 | 本版固定内容 | 不在本版伪造的内容 |
|---|---|---|
| 二层载体 | Ethernet 14B、802.3 length/0x8870 双 profile、LLC `fe fe 03`、最小帧 padding（LLC(3)+PDU 补齐 46B） | 真实邻接、DIS 选举结果、网卡可达性 |
| Common Header | NLPID=0x83、Length Indicator、Version/Protocol ID Extension=1、ID Length=6、PDU Type、Version=1、Reserved=0、Max Area | 未声明的状态字节或线上邻居状态 |
| IIH/LSP/CSNP/PSNP | 固定字段位置/宽度/网络字节序、PDU Length 回填、LSP Fletcher-16 | 未配置的数据库内容或隐式邻居响应 |
| TLV | Type(1)+Length(1)+Value；仅 1/9/132/232/236 五个已登记类型 | 厂商 TLV、私有扩展、未定义字段表的新类型 |

`isis.len`（Length Indicator）语义：固定头长度值——IIH/LSP 为 27、CSNP 为 33、PSNP 为 17（实现常量 `builder.go:149/156/163/169`）；`isis.*.pdu_length` 为含 TLV 的完整 PDU 长度。两者不混同。

## §2 不变式与配置（存量形状声明，P1 实测不美化）

不变式：

1. IS-IS PDU 必须位于 `[eth, isis]` 链；`[ip, isis]`（或任何含 Network/Transport 层的载体）由链校验 V7b 拒绝（`complete.go:337-356`，锚词 `carrier`）。
2. Common Header 固定 8 字节：NLPID=0x83、Length Indicator（27/33/17 按 PDU 类）、Version/Protocol ID Extension=1、ID Length=6、PDU Type、Version=1、Reserved=0、Max Area=0。
3. System ID 为 6 字节（`xxxx.xxxx.xxxx` 或 12 hex）；LSP ID 为 8 字节（System ID 6 + Pseudonode 1 + Fragment 1）；Area 由 TLV 1 显式携带，不从 System ID/MAC 猜测。`area_addresses` 便捷形今日**只做互斥校验、不参与编码**（→ G-ISIS-2）。
4. PDU Length 从 PDU 起点计到最后一个非填充 PDU 字节，含 Common Header 与固定字段/TLV，不含 Ethernet/LLC 头与最小帧 padding；按最终编码字节数网络字节序回填。
5. LSP Checksum 为 ISO 10589 Fletcher-16（实现 `osiFletcherChecksum`，`builder.go:376-428`，Wireshark `osi_check_and_get_checksum` 同款算法）；`checksum_mode=auto` 在长度、LSP ID、序列号、TLV 完成后计算并回填（`buildLSP :214-250`，计算调用 `:247`）。`manual` 模式今日**被接受但不生效**（恒自动计算 → G-ISIS-6）。IIH/CSNP/PSNP 不伪造 LSP checksum。
6. 每个 IIH/LSP/CSNP/PSNP 事件只生成一个原子 PDU；planner 不得隐式补发邻居响应、LSP 或 SNP。
7. Level 由配置显式指定：L1 LAN IIH type=15、L2 LAN IIH type=16；L1 LSP type=18、L2 LSP type=20；L1 CSNP type=24、L2 CSNP type=25；L1 PSNP type=26、L2 PSNP type=27。`p2p_hello` 被 planner 接受但 builder 拒绝（→ G-ISIS-4）。
8. 邻接状态是事件可观察的元数据标注（`neighbor_state`：`""`/`Init`/`Initializing`/`Up`/`Down`），不是额外 wire 字段；`Down` 只允许 IIH 事件（`planner.go:153-155`）。
9. planner/validator 错误必须传播为 task error 终态，不能完成但 0 包或输出损坏 PCAP。
10. Ethernet 目的 MAC 今日恒为 `01:80:c2:00:00:15`（`layer_gen.go:13` 单值）；L1 应为 AllL1ISs `:14` 存疑（→ G-ISIS-5）。

**存量 25 例 `spec_json` 实测形状（2026-09-27，`cases/isis.json` 2063 行）**：`layers` 25/25 为 `[{"eth":{}},{"isis":{}}]` 空条目（24 例）或 `[{"ip":{}},{"isis":{}}]`（1 例，即 `isis_neg_ip_carrier` 拒绝触发源）；顶层键两种形状：24 例 `isis/layers/src_mac` + 1 例 `isis/layers`（无 `src_mac`）；25/25 **全缺 `flow_control`/`strategy_fc`**；`src_ip/dst_ip/src_port/dst_port/count/ttl` 零出现。旧混合形（顶层 `src_mac` + 空层 + 顶层 `isis` 子映射），P4 按 §12.1 去向表逐例改写，不搬运旧期望值（先跑后钉）。

目标层链为 `eth → isis`（L2-only 直挂，无 IP/端口语义）。以下为目标形状样例（P4 改写目标；`flow_control` 为 `spec_json` 兄弟键）：

```json
{
  "spec_json": {
    "layers": [
      {"eth": {"src_mac": "02:00:00:00:10:01"}},
      {"isis": {
        "wire_profile": "iso10589_llc",
        "level": "l1",
        "pdu_type": "lan_hello",
        "system_id": "0102.0304.0506",
        "holding_timer": 30,
        "priority": 100,
        "lan_id": "01020304050601",
        "tlvs": [{"type": 1, "value_hex": "03 49 00 01"}]
      }}
    ]
  },
  "flow_control": {"flows": 1}
}
```

多事件邻接样例（`events` 住 `isis` 层条目内）：

```json
{
  "spec_json": {
    "layers": [
      {"eth": {"src_mac": "02:00:00:00:10:01"}},
      {"isis": {
        "wire_profile": "iso10589_ethertype",
        "level": "l1",
        "pdu_type": "events",
        "system_id": "0102.0304.0506",
        "events": [
          {"kind": "iih", "pdu_type": "lan_hello", "level": "l1",
           "system_id": "0102.0304.0506", "neighbor_state": "Initializing",
           "holding_timer": 30, "priority": 64,
           "lan_id": "01020304050601",
           "tlvs": [{"type": 1, "value_hex": "03 49 00 01"}]},
          {"kind": "lsp", "pdu_type": "lsp", "level": "l1",
           "system_id": "0102.0304.0506", "neighbor_state": "Up",
           "lsp_id": "0102030405060000", "remaining_lifetime": 120,
           "sequence": 1, "partition": 0, "circuit_type": 1,
           "checksum_mode": "auto",
           "tlvs": [{"type": 132, "value_hex": "c0 00 02 01"}]}
        ]
      }}
    ]
  },
  "flow_control": {"flows": 1}
}
```

配置键（`routing.go` 实测：`ISISConfig :271-294` 22 键 / `ISISEvent :309-` 16 键 / `ISISWireFault :330-` 6 键 / `ISISLLCConfig :303-` 3 键 / `ISISTLV :297-` 2 键）：

| 键 | 类型/约束 | 语义 |
|---|---|---|
| `wire_profile` | `iso10589_llc` / `iso10589_ethertype`（空=llc） | 二层承载，不写进 PDU |
| `level` | `l1` / `l2`（空=l1） | 邻接/数据库层级 |
| `pdu_type` | `lan_hello`、`lsp`、`csnp`、`psnp`、`events`（空=lan_hello） | PDU 语义；`p2p_hello` 仅 planner 放行（→ G-ISIS-4） |
| `system_id` | 6 字节 | Source ID 与 SNP Source ID 的显式身份 |
| `holding_timer` / `priority` / `lan_id` | int / int / 7 字节 | IIH 面：保活秒数、优先级、LAN ID（System ID 6 + circuit 1） |
| `lsp_id` / `remaining_lifetime` / `sequence` / `partition` / `circuit_type` | 8 字节 / int×4 | LSP 面字段 |
| `start_lsp_id` / `end_lsp_id` | 8 字节 | CSNP 范围端点；单 PDU 形必填 |
| `tlvs` | 标准 TLV 数组 | 每项 `type`、`value_hex`；只允许 1/9/132/232/236 |
| `area_addresses` | 字符串数组 | 今日只做与显式 TLV 1 互斥校验，不编码（→ G-ISIS-2） |
| `address_profile` | `ipv4_basic` / `ipv6_basic` | 地址族 TLV 组合声明，不是 IP 外层 |
| `checksum_mode` / `checksum` | `auto`/`manual` / int | 今日恒自动计算，`manual` 值不生效（→ G-ISIS-6） |
| `llc` | `{dsap, ssap, control}` | LLC 头覆盖（缺省 fe/fe/03）；存量仅负例使用 |
| `events` | 有序数组 | 每项 `kind`（`iih/lsp/psnp/csnp`）、`level`、`neighbor_state` 及完整 PDU 字段；CSNP 事件今日恒错（→ G-ISIS-3） |
| `wire_fault` | 仅负例 | 注入 carrier/version/length/checksum/TLV 边界错误，不代表合法线格式 |

## §3 公共头与二层载体

Common Header（PDU 起点）按网络字节序为：

```text
byte 0       NLPID = 0x83
byte 1       Length Indicator = 27（IIH/LSP）/ 33（CSNP）/ 17（PSNP）
byte 2       Version/Protocol ID Extension = 0x01
byte 3       ID Length = 0x06
byte 4       PDU Type = 15/16/18/20/24/25/26/27
byte 5       Version = 0x01
byte 6       Reserved = 0x00
byte 7       Max Area Addresses = 0x00（0 表 3）
```

LLC profile 字节顺序：`Ethernet(dst 6 | src 6 | 802.3 length 2) | LLC(FE FE 03) | NLPID 83 …`，Common Header 首字节 `83` 在无 VLAN 帧 offset 17。EtherType profile：`Ethernet(dst 6 | src 6 | 88 70) | LLC(FE FE 03) | NLPID 83 …`（生成器把 LLC 头前置进 payload，`layer_gen.go:73-76`），offset 14 起为 `fe fe 03 83 …`。存量 frames 如 `isis_l1_iih_ethertype` offset 14 `fe fe 03 83 1b 01 06 0f 01` 即此形状实证。

LLC 802.3 length 字段 = LLC(3) + PDU + padding（补齐 46B 最小载荷）：PDU=33 时为 `00 2e`、PDU=51（CSNP 单 entry）时为 `00 36`（存量 #1/#8 frames 实证）。EtherType profile offset 12 恒为 `88 70`。

## §4 PDU 线格式

### §4.1 LAN IIH（Type 15/16）

Common Header 后固定字段 19 字节：Circuit Type 1（L1=`0x01`，L2=`0x02`，与 level 一致）| Source ID 6 | Holding Timer 2（秒，网络字节序）| PDU Length 2（含 Common Header 与全部 TLV）| Priority 1 | LAN ID 7（System ID 6 + circuit 1）。无 TLV 时 PDU Length=27；TLV 1（value 4B，如 `03 49 00 01`）时为 33（存量 #1/#2 断言 `isis.hello.pdu_length=33` 实证）。

### §4.2 LSP（Type 18/20）

Common Header 后固定字段 20 字节：PDU Length 2 | Remaining Lifetime 2 | LSP ID 8 | Sequence Number 4 | Checksum 2（Fletcher-16）| Type Block 1（bit7=Partition，低 2 位=IS type 1/2；实现 `builder.go:229`）。无 TLV 时 PDU Length=28（8 字节公共头 + 20 字节固定字段；Length Indicator 仍为固定头长度值 27）。存量公式实证：TLV 1(6B)+TLV 132(6B) → 39（#5）；TLV 232(18B) → 45（#6）；TLV 132(6B) → 33（#10，`sequence=0x10203040`）；TLV 1(8B) → 35（#11）。

### §4.3 CSNP（Type 24/25）

Common Header 后固定字段：PDU Length 2 | Source ID 6 | Source Circuit 1（恒 `0x00`，`buildCSNP :308`）| Start LSP ID 8 | End LSP ID 8，共 25 字节；Length Indicator=33。TLV 9 LSP Entry 每项 16 字节（Remaining Life 2 + LSP ID 8 + Sequence 4 + Checksum 2）；单 entry 时 PDU Length=51（存量 #8 实证：`isis.csnp.pdu_length=51`、`start=0102.0304.0506.00-00`、`end=0102.0304.0506.ff-ff`）。

### §4.4 PSNP（Type 26/27）

Common Header 后固定字段：PDU Length 2 | Source ID 6 | Source Circuit 1（恒 `0x00`，`buildPSNP :339`），共 9 字节；Length Indicator=17。TLV 9 单 entry 时 PDU Length=35（存量 #9 L2 PSNP / #12p4 L1 PSNP 实证）。PSNP 没有 CSNP 的 start/end range 字段。

## §5 标准 TLV profile 与地址族

TLV 编码统一为 `Type(1) | Length(1) | Value(Length)`（实现 `encodeTLVs`，`builder.go:106-117`）。本版只允许以下已登记类型（实现 `isKnownTLV`，`planner.go:220-226`）：

| TLV | 名称 | 本版 profile | value 约束 | 存量 |
|---:|---|---|---|---|
| 1 | Area Addresses | 基础 | 每个 area 3–13 字节，TLV value 可含多个 length-prefixed area | #1/#2/#7/#11/#12p1p2（`isis.hello.area_address` ×6） |
| 9 | LSP Entries | `snp` | 每项固定 16 字节；仅 CSNP/PSNP（他处用即拒，`planner.go:93-95`） | #8/#9/#12p4 |
| 132 | IP Interface Addresses | `ipv4_basic` | 每个 IPv4 地址 4 字节 | #5/#7/#10/#12p3/#13p1 |
| 232 | IPv6 Interface Addresses | `ipv6_basic` | 每个 IPv6 地址 16 字节 | #6/#13p2 |
| 236 | IPv6 Reachability | `ipv6_basic` | 通用 TLV 编码直传；无存量用例 | 缺失 → A′ T-ISIS-30 |
| 250 | — | 无（拒绝） | 未登记厂商类型，锚词 `tlv` | 仅 #24 负例 |

`address_profile` 语义校验（`validateAddressProfile`，`planner.go:182-204`）：`ipv4_basic` 要求 TLV 132 在场且无 TLV 232，反之亦然；profile 与 TLV 混用即拒（锚词 `address`，存量 #17 实证）。

IPv4 与 IPv6 仅作为 TLV 地址族 profile，不改变二层载体：帧仍不含 IP header（存量 28 个去重断言字段中零 `ip.*`/`eth.*`，见 testcase §1）。

## §6 Checksum、长度和邻接状态

`checksum_mode=auto` 只对 LSP 生效。编码流程：先写 Common Header、LSP 固定字段（checksum 置零）、标准 TLV，再按 ISO 10589 Fletcher-16（Wireshark `osi_check_and_get_checksum` 同款，`osiFletcherChecksum(pdu, 12, pduLen-12, 24)`，`builder.go:247`）计算并回填。用例今日把 8 个 LSP checksum 断言为固定 hex（`0xb792` 等）——P5 必须先跑后钉复核实现单测与 pcap 一致性（testcase §8.6 注记）。IIH/CSNP/PSNP 不出现伪造的 `lsp.checksum`。

长度公式（均为 PDU 内长度，存量逐值实证）：

- LAN IIH：`27 + Σ(TLV 2+value)`；TLV 1(value 4) 时 33。
- LSP：`27 + Σ(TLV 2+value)`；TLV 1+132(12) 时 39；TLV 232(18) 时 45；TLV 132(6) 时 33；TLV 1(8) 时 35。
- CSNP：`33 + 2 + 16×entry_count`；单 entry 时 51。
- PSNP：`17 + 2 + 16×entry_count`；单 entry 时 35。

邻接事件采用显式 `events`：如 `iih`(Initializing) → `iih`(Up) → `lsp`(Up) → `psnp`(Up)（存量 #12 四事件实证）。事件顺序是可观察的发送序，不是额外 PDU；`neighbor_state` 不进线。不能因一个 IIH 自动生成对端 IIH 或 SNP。

## §7 负例与错误处理

12 个负例锚词全部逐字对已落码字符串（P1 实测行号，非臆造）：

| # | ID | 故障输入 | `error_contains` | 代码锚点（实测） |
|---:|---|---|---|---|
| 14 | `isis_neg_profile` | `wire_profile=unknown_profile` | `profile` | `planner.go:28`（串含 "unknown wire profile"） |
| 15 | `isis_neg_identifier` | `system_id="0102"`（非 6 字节） | `system` | `builder.go:50` 经 `parseSystemID`（串 "system id … must be 6 bytes"） |
| 16 | `isis_neg_state` | `events[0]` kind=lsp + `neighbor_state=Down` | `state` | `planner.go:154`（串 "invalid neighbor state … Down is only valid for IIH"） |
| 17 | `isis_neg_address_family` | `ipv4_basic` + TLV 232 | `address` | `planner.go:192`（串 "address family mismatch"） |
| 18 | `isis_neg_duplicate_area` | `area_addresses` + 显式 TLV 1 | `area` | `planner.go:58`（串 "duplicate area address source"） |
| 19 | `isis_neg_ip_carrier` | 链 `[ip, isis]` | `carrier` | `complete.go:355` V7b（串 'must not have an ip/transport carrier'；链校验先于 planner，planner 侧填假值注记见 `planner.go:61-63`） |
| 20 | `isis_neg_mixed_carrier` | LLC 覆盖 + ethertype profile / `wire_fault kind=mixed_carrier` | `carrier` | `planner.go:66/69`（串 "mixed carrier"） |
| 21 | `isis_neg_header` | `wire_fault{kind:header, header_length:7}` | `header` | `planner.go:74`（串 "bad header … must be 8"） |
| 22 | `isis_neg_level_type` | `wire_fault{kind:level_type, pdu_type:20, circuit_type:2}` + level l1 | `level` | `planner.go:79`（串 "level/type mismatch"） |
| 23 | `isis_neg_length` | `wire_fault{kind:length, pdu_length:27}` | `length` | `planner.go:83/86`（串 "length mismatch"） |
| 24 | `isis_neg_vendor_tlv` | TLV type=250 | `tlv` | `planner.go:91`（串 "unsupported tlv type"） |
| 25 | `isis_neg_checksum` | `checksum_mode=manual` + `wire_fault{kind:checksum}` | `checksum` | `planner.go:102`（串 "bad LSP checksum"） |

`wire_fault` 仅为失败优先测试注入入口（`ISISWireFault` 6 键：`kind/value/header_length/pdu_length/pdu_type/circuit_type`），不代表合法线上 PDU。所有负例只要求 `expect_error=true` 和 `error_contains`，禁止以"损坏 PCAP 生成成功"作为通过条件。

## §8 场景语义、包数公式与性能设计验收

IS-IS 二层 PDU 没有 TCP 握手/终止：单事件 `packet_count=1`；四事件邻接序列 `packet_count=4`；双事件地址族序列 `packet_count=2`（存量序列 `[1,1,1,1,1,1,1,1,1,1,1,4,2]`，正例总包数 17）。每个事件必须提供其 PDU 的完整固定字段和 TLV；事件 kind/状态不是省略必填 wire 字段的理由。原始 Ethernet frame 可能因最小帧规则有 padding，但断言只定位 PDU 起点和 PDU Length，不把 padding 计入 PDU。

包数公式：单 PDU 事件 `packet_count = 1`；`events[N]` 序列 `packet_count = N`（事件与包一一对应，无隐式补发——`layer_gen.go:90-101` 逐事件 Emit 实证）。

**性能设计与验收（CORE_MEMORY §6.1–6.8）**：

- 目标与边界（§6.1/6.2/6.5）：O(n) 流式——逐事件渲染直发 `req.Emit`，无按包增长结构、无全量聚合（`layer_gen.go:43-101` emit 闭包 + 事件 for 循环）；单事件最大 ≈ CSNP 单 entry fixture 级（PDU 51B + LLC 3B + padding）；无锁无 sleep（事件驱动，非定时器模型）。吞吐/并发/内存目标数字待 P4 基准后定，本契约不写承诺数字。
- 实现路径依据（§6.4）：L2-only 直发分支（`chain_planner.go:1200-1222`，`out` chan 256，末层生成器直驱，`pkt.L3` 清空、`EtherType` 强制 `0x8870`）；确定性内存（单 PDU 最大 fixture 级字节）；`SharedTokenBucket` 按类限速面沿既有引擎语义。
- 两路验收（§6.3）：**pcap 路**——suite 全量落盘（默认 `/tmp/mcp-pcaps/isis/`），tshark `isis.*` 字段 + frames hex 双通道；**NIC 路**——过滤器 `ether proto 0x8870`，测试网口按 testing-interface 记忆（`enp135s0f0np0`），关注组播目的 MAC 与最小帧 padding 在线上可见。
- 六类场景（§6.6）P5 跑测覆盖：基线（#1 单包）/目标规模（#12 四包事件）/压力上限（`flow_control.flows=N` 大 N × 事件序）/长时间运行/并发交错（#13 双事件）/资源耗尽背压（队列满走既有 pipeline 语义）。
- 失败边界（§6.7/6.8）：断言实际包数字段值与包数，不只断言"任务没有报错"；功能正确但超预算按 §6.8 视为不合格。

## §9 用例集合摘要（ID 权威在 testcase §2；本表与之逐值一致）

| # | T-ID | JSON ID | 类型 | packet_count |
|---:|---|---|---|---:|
| 1 | T-ISIS-01 | `isis_l1_iih_llc` | 正 | 1 |
| 2 | T-ISIS-02 | `isis_l2_iih_llc` | 正 | 1 |
| 3 | T-ISIS-03 | `isis_l1_iih_ethertype` | 正 | 1 |
| 4 | T-ISIS-04 | `isis_l2_iih_ethertype` | 正 | 1 |
| 5 | T-ISIS-05 | `isis_l1_lsp_ipv4` | 正 | 1 |
| 6 | T-ISIS-06 | `isis_l2_lsp_ipv6` | 正 | 1 |
| 7 | T-ISIS-07 | `isis_l1_lsp_tlv_order` | 正 | 1 |
| 8 | T-ISIS-08 | `isis_l1_csnp` | 正 | 1 |
| 9 | T-ISIS-09 | `isis_l2_psnp` | 正 | 1 |
| 10 | T-ISIS-10 | `isis_length_checksum` | 正 | 1 |
| 11 | T-ISIS-11 | `isis_area_system_id` | 正 | 1 |
| 12 | T-ISIS-12 | `isis_neighbor_up_sequence` | 正 | 4 |
| 13 | T-ISIS-13 | `isis_ipv4_ipv6_tlv_profiles` | 正 | 2 |
| 14 | T-ISIS-14 | `isis_neg_profile` | 负 | — |
| 15 | T-ISIS-15 | `isis_neg_identifier` | 负 | — |
| 16 | T-ISIS-16 | `isis_neg_state` | 负 | — |
| 17 | T-ISIS-17 | `isis_neg_address_family` | 负 | — |
| 18 | T-ISIS-18 | `isis_neg_duplicate_area` | 负 | — |
| 19 | T-ISIS-19 | `isis_neg_ip_carrier` | 负 | — |
| 20 | T-ISIS-20 | `isis_neg_mixed_carrier` | 负 | — |
| 21 | T-ISIS-21 | `isis_neg_header` | 负 | — |
| 22 | T-ISIS-22 | `isis_neg_level_type` | 负 | — |
| 23 | T-ISIS-23 | `isis_neg_length` | 负 | — |
| 24 | T-ISIS-24 | `isis_neg_vendor_tlv` | 负 | — |
| 25 | T-ISIS-25 | `isis_neg_checksum` | 负 | — |

packet_count 序列（正例 13 个，按序）：`[1,1,1,1,1,1,1,1,1,1,1,4,2]`（总包数 17）。A′ 补例 T-ISIS-26..30 见 testcase §8.2（P4 落盘，不影响本表 25 ID 权威口径）。

## §10 P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：矩阵三张子表——①PDU×载体/状态矩阵（§10.2）②数据形态变体表（§10.3）③商业行为→用例映射表（§12.2）。条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号；无遗漏留白。
> **L2-only 载体铁律（逐矩阵行重申）**：isis 直挂 eth（registry `DependsOn ["eth"]`，`registry.go:946`）——IP/TCP/UDP 载体判死（V7b `complete.go:337-356` 链中含 Network/Transport 层即错；goose/sv/arp 同族先例）；IS-IS 无端口、无握手、无 TTL 语义；五件套时间线诚实写"建连面无"。

### §10.1 八项规范矩阵

| # | 规范要求（ISO/RFC + 本契约节） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：无连接二层信令；IIH 组播 Hello 发现，LSP 泛洪，SNP 同步；无握手、无重传确认；一事件 = 一 frame（ISO 10589；本契约 §1） | 路由器 LAN 邻居发现；LSP 泛洪后 SNP 对账 | 已实现：生成器单事件直发 + 事件序逐包 Emit（`layer_gen.go:24-101`；L2-only 直发分支 `chain_planner.go:1200-1222`，`EtherType` 强制 `0x8870 :1222`）+ V7b 载体守卫（`complete.go:337-356`） | P4 只做层链整形 + 链级红例 + casegen（§11） |
| 2 | 命令消息表：IIH 15/16、LSP 18/20、CSNP 24/25、PSNP 26/27（ISO 10589；本契约 §4） | 四类控制动作全表逐消息编码；L1/L2 分级 | 已实现：`pduTypeForIIH/LSP/CSNP/PSNP`（`builder.go:204/253/318/347`）+ `buildSinglePDU :112-133` + frames `83 1b/21/11` 前缀实测 39 帧全对 | P5 逐例先跑后钉（frames 三档 offset 实测） |
| 3 | 状态机：IS-IS 无连接；主机侧唯一有序面 = IIH（Initializing→Up）→ LSP → SNP；多邻居状态隔离（ISO 10589；本契约 §2.1/§6） | 邻居上线后 LSP 泛洪与 SNP 确认 | 已实现：事件 `neighbor_state` 元数据直通（`routing.go:309-` 16 键之一；生成器/builder 不消费状态，只携带——`buildEventPDU :136-157` 只读报文类字段）；`Down` 非 IIH 拒（`planner.go:153-155`） | 多会话并发交错序 → B′（G-ISIS-8，不假设调度器交织顺序） |
| 4 | 字段表：8 字节公共头（NLPID/Length/Extension/ID长/Type/Version/Reserved/MaxArea）；IIH 19B 固定；LSP 20B 固定；CSNP 25B；PSNP 9B；TLV 1/9/132/232/236（ISO 10589；本契约 §3–§5） | 单/双邻居 IIH；L1/L2 LSP；CSNP range；PSNP entry；地址族 TLV | 已实现：`commonHeader :123` + `buildIIH :174` + `buildLSP :214`（Type Block `:229`）+ `buildCSNP :286`（Source Circuit 恒零 `:308`）+ `buildPSNP :326`（恒零 `:339`）+ `encodeTLVs :106` | TLV 22/128/129/135/137 reachability、认证 TLV 10 → G-ISIS-8； area 简写 → G-ISIS-2 |
| 5 | 错误处理：profile / identifier / state / address-family / duplicate-area / carrier×2 / header / level-type / length / vendor-tlv / checksum 十二类拒收（本契约 §7） | 脏包、错配、伪造字段一律 task error，零假成功 | 已实现：12 锚词逐字对 §7 表（`planner.go` 全行实测 + V7b `complete.go:355` + `builder.go:50`） | 链级红例 4 例 P4 新增（presence/白名单/transport 载体/裸链，§12-P2） |
| 6 | 超时活性：Holding Timer 邻居保活；Remaining Lifetime 老化；CSNP/PSNP 周期同步（本契约 §4/§6） | 邻居掉线检测；LSP 老化重传 | 已实现：计时器字段必发（IIH/LSP body 面）；周期定时器 = 明确不支持（§8），不立项 | 无缺口（显式不适用 ≠ 缺口；周期调度面归引擎调度器，不归本协议；周期重发面 → G-ISIS-8 B′） |
| 7 | NAT/代理：IS-IS 是二层域内信令，无 NAT 遍历语义；无被动模式概念（本契约 §1） | 同 LAN 路由交换 | 不适用（显式声明，不用"待确认"逃逸）：无 IS-IS 层语义可测，无用例 | 无缺口（显式不适用 ≠ 缺口） |
| 8 | 版本方言：LAN IIH / P2P IIH / MT/TLV 扩展 / 认证扩展（本契约 §1/§5） | LAN 邻接；P2P 链路另议 | 已实现：LAN IIH 双 level（`buildIIH :174`）；白名单 `protocols.go:41`；P2P planner 放行但 builder 拒 → G-ISIS-4 | 现网 DIS 选举/计时器行为抓包确认 → G-ISIS-7；P2P/认证/扩展 TLV 另议 → G-ISIS-4/G-ISIS-8 |

### §10.2 子表①：PDU×载体/状态矩阵（逐格已覆/缺失/不适用）

行=PDU 形状，列=仲裁轴（A 合法编码面 / B 状态元数据面 / C 拒绝通道 / D carrier 双 profile 面）：

| PDU \ 面 | A 合法编码 | B 状态元数据 | C 拒绝通道 | D 双 profile |
|---|---|---|---|---|
| R1 L1 IIH | 已覆 #1/#3 | 不适用（单包无状态） | 已覆 #21（header）/#22（level） | 已覆 LLC #1 + ET #3 |
| R2 L2 IIH | 已覆 #2/#4 | 不适用 | 已覆 #22 通道 | 已覆 LLC #2 + ET #4 |
| R3 L1 LSP | 已覆 #5/#7/#10/#11 | 不适用 | 已覆 #23（length）/#24（vendor）/#25（checksum） | 已覆 LLC #5 + ET #7 |
| R4 L2 LSP | 已覆 #6 | 不适用 | 已覆 #17（addr-family） | **缺失**（仅 ET #6，无 LLC 例 → A′ T-ISIS-26） |
| R5 L1 CSNP | 已覆 #8 | 不适用 | 已覆 #23 通道 | **缺失**（仅 LLC #8，无 ET 例 → A′ T-ISIS-27） |
| R6 PSNP | 已覆 #9（L2）/#12p4（L1） | 已覆 #12（序列内 Up） | 已覆 #23 通道 | **缺失**（无 LLC 例 → A′ T-ISIS-28） |
| R7 多事件序列 | 已覆 #12（4 事件）/#13（2 事件） | 已覆 #12（Initializing→Up） | 已覆 #16（state） | **缺失**（全 ET，无 LLC 多事件 → A′ T-ISIS-29） |
| R8 checksum/length | 已覆 #10 | 不适用 | 已覆 #25 | 已覆 ET #10 + LLC #5（checksum 双面） |

**逐格重数（8 行 × 4 列 = 32 格，可复核）**：**已覆 22 格**（R1: A/C/D、R2: A/C/D、R3: A/C/D、R4: A/C、R5: A/C、R6: A/B/C、R7: A/B/C、R8: A/C/D）；**不适用 6 格**（R1B、R2B、R3B、R4B、R5B、R8B，单 PDU 无状态面）；**缺失 4 格**（R4D、R5D、R6D、R7D，均为 LLC/ET 对称 carrier 缺格 → A′ T-ISIS-26..29）。22 + 6 + 4 = 32 ✓ **逐格有结论、无空格**。

### §10.3 子表②：数据形态变体表（协议相关全部形态逐项）

| 变体维度 | 形态 | 对应用例 | 备注 |
|---|---|---|---|
| IIH 面 | holding 30/45、priority 100/64/64、LAN ID 显式 7B、circuit 0x01/0x02 | #1/#2/#3/#4/#12p1p2 | `isis.hello.*` 7 字段 ×6 包；L1/L2 分立两例 |
| LSP 面 | remaining 120/300/90、sequence 1/2/7/9/`0x10203040`、is_type 1/2、LSP ID 显式 8B | #5/#6/#7/#10/#11/#12p3/#13 | `isis.lsp.*` 6 字段 ×8 包；大 sequence 面 #10 |
| CSNP 面 | range start/end 8B 端点、TLV 9 单 entry、pdu_length 51、`isis.len` 33 | #8 | `isis.csnp.*` 5 字段；事件内 CSNP 今日恒错（→ G-ISIS-3） |
| PSNP 面 | TLV 9 单 entry、无 range、pdu_length 35、`isis.len` 17 | #9/#12p4 | `isis.psnp.*` 3 字段 ×2 包；L1/L2 各一 |
| TLV 1 Area 面 | value `03 49 00 01`/`03 49 00 02`/`05 49 00 02 00 03` | #1/#2/#7/#11/#12 | `isis.hello.area_address` ×6；重复来源拒 → #18 |
| 地址族面 | TLV 132（`c0 00 02 01`）/ TLV 232（`20 01 0d b8 … 01`）+ profile 双向互斥 | #5/#6/#10/#13/#17 | `clv_ipv4/clv_ipv6_int_addr` 各 1；混用拒 #17 |
| TLV 236 面 | 通用编码直传（代码接受，无特判） | **缺失** → A′ T-ISIS-30 | `isKnownTLV :220-226` 含 236 但零用例 |
| 厂商 TLV 面 | type 250 拒绝 | #24（`tlv` 锚词） | 未登记类型一律拒 |
| carrier 面 | 802.3 length `00 2e`/`00 36`、LLC `fe fe 03`、EtherType `88 70`、padding | 39 帧三档 offset | offset 12 ×17 / 14 ×17 / 17 ×5 |
| checksum 面 | LSP Fletcher-16 回填；固定 hex 8 例待 P5 复核 | #5/#6/#7/#10/#11/#12p3/#13 | nonzero + 实现单测逐字节复算；`manual` 不生效 → G-ISIS-6 |
| level 面 | L1/L2 × PDU type 推导（15/16/18/20/24/25/26/27） | #1–#13（`isis.type` ×17 包） | 错配拒 → #22；`p2p_hello` 不一致 → G-ISIS-4 |
| 多包事件面 | 4 事件邻接（IIH/IIH/LSP/PSNP）+ 2 事件地址族（LSP/LSP） | #12/#13 | `neighbor_state` 只携带不进线；CSNP 事件缺失 → G-ISIS-3 |

12 行：已覆 11 行 + 缺失 1 行（TLV 236 → A′ T-ISIS-30）。

### §10.4 P1 三路对照（CORE_MEMORY §4.12–4.15）

**①规范原文**：ISO 10589（IS-IS 域内路由）为"必须是什么"底线；RFC 1195（IP 集成/Integrated IS-IS）、RFC 5305（TE TLV 22）、RFC 5308（IPv6 TLV 232/236）为地址族与扩展边界。精确章节号待 G-ISIS-7（§5.5 不写死）。

**②现网行为**：LAN L1/L2 Hello（holding/priority/LAN ID/DIS 选举通告）、L1/L2 LSP 泛洪、CSNP/PSNP 数据库同步为现网通用形态。出处确认方式：抓现网/回环 IS-IS 包核对 Type/载体/MAC 面（**立项 G-ISIS-7**：现网级确认前相关条目按 §5.5 标"待确认"，不写死进实现）。

**③开源实现思路**：Wireshark IS-IS 解析器（本机 3.6.14 实测 `isis.*` **498** 字段——断言通道权威；用例去重 28 字段 28/28 命中，零自创）；实现注释已引 `packet-isis-lsp.c dissect_isis_lsp` 与 `packet-isis-snp.c dissect_isis_csnp`（`builder.go:153-169`）为固定头长度依据；本仓库已落码 builder/planner/generator（1251 行）为 wire 真相；只借鉴字段语义与拆解思路。FRR `isisd` 等实现思路待确认（→ G-ISIS-7，不预支版本号与文件名）。

**三路结论一致性**：三路在"PDU Type 七值（15/16/18/20/24/25/26/27）、8B 公共头、IIH 19B 固定、LSP Fletcher-16、TLV 1/9/132/232 面"五点一致。取舍：①内层编码字节以 builder 编码 + tshark 读回为准，先跑后钉；②DIS 选举间隔、重传策略、厂商扩展差异面未到确认级 → G-ISIS-7，不写死。

### §10.5 候选方案对比（§4.17）

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| A 结构化声明式回放 | profile/events（kind/level/system_id/tlvs）结构化 + wire 由 builder 纯函数产出（同族 goose/sv L2-only 范式；`chain_planner.go:1200` 直发分支） | 字段可结构化断言；双 carrier 可开；与已收官族同构 | 多会话交织序不假设 | O(n) 流式；复杂度低；双 profile 兼容 | **采用（已落码）** |
| B 生 hex 回放 | 整 frame hex 覆盖 | 最简单 | 字段不可断言；TLV 变体即死 | 动态零分 | 仅作负例特殊形逃生口 |
| C 完整 IS-IS 状态机模拟器 | 自动 DIS 选举/补邻居响应/重传定时/LSP 泛洪应答 | 真实度高 | 超出声明式回放族边界；与 §3.13"不许隐式编排"冲突 | 复杂度高、收益无 fixture 面支撑 | 不选 |

## §11 D-ISIS-1 P2 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 体裁：文件清单/接口签名/数据结构/主流程/错误分支/性能边界/回滚方式。isis wire 面已落码，D-ISIS-1 覆盖"已落码对接 + P4 层链整形差量"，不重发明 wire。

**文件清单（已落码 5 + P4 新建 1 + 接线/守卫，已落码行号实测）**：

| 文件 | 职责 |
|---|---|
| internal/protocol/isis/builder.go（已落码，447 行） | wire 纯函数：`parseSystemID :47` / `encodeTLVs :106` / `commonHeader :123` / `parseLANID :129` / `buildIIH :174` / `buildLSP :214`（Type Block `:229`，checksum 回填 `:247`）/ `parseLSPID :269` / `buildCSNP :286`（Source Circuit 恒零 `:308`）/ `buildPSNP :326` / `osiFletcherChecksum :376`；常量：NLPID/头长/Type 15–27/circuit/LLC `fe fe 03`/最小载荷 46 |
| internal/protocol/isis/planner.go（已落码，226 行） | `Planner.Validate :18`（profile `:24-29`、system `:35-42`、lspid `:44-51`、address `:52-54`、area `:57-59`、mixed-carrier `:65-70`、header `:72-76`、level `:78-80`、length `:82-87`、tlv `:89-99`、checksum `:101-106`、events `:108-132`）+ `validateEvent :138` + `validateLevelAndType :160` + `validateAddressProfile :182` + `isKnownTLV :220` |
| internal/protocol/isis/layer_gen.go（已落码，184 行） | `ISISGenerator.Generate :24`（`Emit` 空拒、无 events 走默认单 PDU `:39-41`；ET 前置 LLC `:73-76`、LLC 垫 padding `:77-80`；事件序 `:90-101` 逐包 Emit）/ `buildSinglePDU :112`（缺省 l1/lan_hello）/ `buildEventPDU :136`（CSNP 事件恒错 `:152` → G-ISIS-3）/ `defaultLLC :160` / `padPayload :168` / 双注册 `:181-184` 生成器+校验器；`DefaultDstMAC :13` 单值 `:15`（→ G-ISIS-5） |
| internal/core/routing.go（已落码） | `ISISConfig :271-294`（22 键）+ `ISISTLV :297`（2 键）+ `ISISLLCConfig :303`（3 键）+ `ISISEvent :309-`（16 键）+ `ISISWireFault :330-`（6 键） |
| internal/protocol/isis/isis_test.go（已落码，394 行） | 单元测试 21 个（6 构建 + padding/checksum 各 1 + 11 负例校验 + 2 合法；P4 复用，不改口径） |
| internal/protocol/isis/casegen_test.go（P4 NEW） | 一次性生成器：25 例（13 正+12 负）契约计数逐例 add()，落 test/protocol_pcap/cases/isis.json（层链整形后形状；不搬运旧期望值，先跑后钉） |
| 接线件（已落码，P4 只验证） | registry `registry.go:946`（`DependsOn ["eth"]` L2-only + `eth :47-52` src/dst_mac）→ schemagen（生成表 `isis`：terminal/`depends_on ["eth"]`/`fields {}`，业务键走 FlowMeta 直传）；`translate:170` Meta.ISIS + `:711-712` 空配置保底；`generator.go:488-494` Meta 注记；`chain_planner.go:645/748/883/1200/1222` L2-only 名单/放行/直发/EtherType 强制；`strategy_convert.go:738-740` 顶层子映射解析；`protocols.go:41` 白名单；`layer_dyn.go:21` eth 动态开关 |
| P4 新增守卫 | ①`CheckProtoFlat` 补 `isis` 顶层同名子映射 presence 判死分支（`strategy_convert.go:8322` 加 `if protocol == "isis"` 项 + `rawWrapChains :8541-8546` 加 `"isis": "[eth,isis]"`——跨协议共享面，**主线程定夺，车道不自改**，→ G-ISIS-1）；②validate_layers 预检：白名单外游离键拒/`[ip,tcp,isis]` transport 载体拒（V7b 含 Transport 即错）/裸 `[isis]` 拒（DependsOn 缺失）——单载体，无 OptionalOn 面 |

**接口签名**（已落码，P4 落码钉死有无差量）：`parseSystemID/parseLSPID/parseLANID/parseHexSpace/hexByte/encodeTLVs/commonHeader` / `buildIIH/buildLSP/buildCSNP/buildPSNP/pduTypeFor*` / `osiFletcherChecksum/cMod` / `Planner.Validate(spec) error` / `ISISGenerator.Generate(ctx, req) error` / `validateEvent/validateLevelAndType/validateAddressProfile/hasTLV/isKnownTLV`。

**数据结构**：沿 `ISISConfig`（22 键：wire_profile/level/pdu_type/system_id/holding_timer/priority/lan_id/tlvs/lsp_id/remaining_lifetime/sequence/partition/circuit_type/checksum_mode/address_profile/area_addresses/start_lsp_id/end_lsp_id/events/checksum/llc/wire_fault）+ `ISISEvent`（16 键）+ 层链目标形状（§12.1 样例：MAC 住 `eth`、业务住 `isis` 条目、数量走兄弟 `flow_control`）。

**主流程**：validateSpec（含 P4 新增 presence 守卫 + validate_layers V7b 预检）→ 单 PDU 渲染（`buildSinglePDU` 四分支）或事件序渲染（`buildEventPDU` 四分支）→ L2-only 直发分支逐包 Emit（`chain_planner.go:1200-1222`）→ worker（flowCount 恒 ≥1）→ pcap/NIC。

**错误分支（§5.2）**：①`wire_fault` 六键注入拒（profile/system/state/address/area/carrier/header/level/length/tlv/checksum 十二锚，行号见 §7）；②自然守卫：未知 profile（`:28`）/非法 system/lsp id（经 `builder.go:50/271`）/地址族错配（`:191-202`）/重复 area（`:58`）/混合载体（`:66-70`）/TLV 非法（`:90-99`）/非法事件（`:108-132`）；③validate_layers 预检同步拒（V7b carrier/presence/白名单/transport 载体/缺 eth）。全部传播为 task error，零假成功。

**依赖声明（§5.1）**：依赖 `eth` 层（唯一载体，MAC + 802.3 length/EtherType + LLC）；无 `ip`/`tcp`/`udp` 依赖（§12-P2 把此列成守卫）；无外部 DIS/采集器依赖。**不含端口与 IP 依赖**（isis 无端口/IP 语义；`mapToFlowSpec` 填的 10.0.0.1/20.0.0.1/12345/80 为假值，终结层校验/L2 分支不消费——`planner.go:61-63` 注记）。

**性能边界（§6.1–6.8 摘要，详见 §8）**：O(n) 流式逐事件直发，无全量聚合；单事件最大 fixture 级（CSNP 单 entry PDU 51B）；无锁无 sleep；pcap（`/tmp/mcp-pcaps/isis/`）+ NIC（`ether proto 0x8870`，`enp135s0f0np0`）双路；回归口径 suite 耗时 ±10%；六类场景 P5 跑测；吞吐/并发/内存目标数字待 P4 基准后定（§6.5，不写承诺）。

**与现有逻辑冲突点（§8.7）**：①`strategy_convert.go:738-740` 仅解析顶层 `isis` 子映射，无 presence 判死分支——P4 补 `CheckProtoFlat` 项 + 层条目解析迁移（§12-P2 实证缺口；跨协议共享面，主线程定夺）；②`parseSubconfigJSON`（`strategy_convert_helpers.go:21-30`）为普通 `json.Unmarshal`（无 `DisallowUnknownFields`）——isis 子映射未知键静默忽略，负例不得依赖未知键拒绝（→ G-ISIS-1 同源）；③G-ISIS-2..6（shorthand/csnp-event/p2p/MAC/manual 五处已落码行为缺口，P4 修）；④生成表 `isis.fields {}`（业务键走 FlowMeta 直传），P4 只验证无过期（`TestLayersGeneratedMatchesRegistry`）。

**回滚方式（§8.8）**：P4 差量全量 revert（casegen + 25 例改写 + presence 守卫）；已落码 wire 面不动；无数据迁移面。

## §12 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：`src_ip/dst_ip/src_port/dst_port/count/ttl` 零存量、P4 不引入；顶层 `src_mac` 24 例迁入 `eth` 层；顶层 `isis` 子映射迁入 `layers[1]`；数量走兄弟键 `flow_control`（`flows` = packet_count）；目标形状 spec_json 样例见 §12.1；存量 25 例逐键去向见 §12.1 去向表；非负例 `spec_json` 顶层键=0（`spec_json` 只留 `layers` + 兄弟 `flow_control`，presence 负例见 §12-P2） | 本契约 §2（存量形状实测：24+1 双形状）+ §12.1 样例与去向表 |
| §2 策略/任务 | 策略=单 IS-IS PDU 模板（自带 `flow_control` flows/bps/time）；任务=多策略合跑+总量封顶；框架语义未动 | 本契约 §10.1 #1 + §11 |
| §3 五件套 | 见 §12.3 强制展开：单 profile 会话表/事务序列/关联关系/插入位置/时间线；**L2 无连接诚实写"建连面无"**，不虚构 handshake 包数（存量 `has_handshake` 0/25、`terminates` 0/25）；单包协议按 §3.14 豁免顶层 `sessions[]`（`events[]` 承载邻接隔离，不豁免多流覆盖） | 本契约 §12.3 + 用例 #12/#13 |
| §4 查规范 | ISO 10589 + RFC 1195/5305/5308（文档级引用，精确章节待 G-ISIS-7）+ tshark `isis.*` 498 字段实测（用例去重 28：28/28 命中，零自创）+ 已落码 builder wire 真相 + §10 矩阵 8 行+三子表 + 三路对照（§10.4） | 本契约 §10 |
| §5 依赖与错误 | `DependsOn ["eth"]`（registry.go:946；单载体、无 OptionalOn 面——isis 无端口/IP/传输层语义）；12 负例锚词表逐字（行号实测，见 §7）；失败返回 task error（零假成功） | 本契约 §2/§7 + §11 错误分支 |
| §6 性能 | 单事件流式、O(n)、无锁无 sleep；pcap/NIC 双路验收；目标数字待 P4 基准（§6.5 不写承诺）；六类场景清单见 §11 | §8 性能段 + testcase §8.7 |
| §7 三份文档 | 78-isis-{design,testcase}.md v1.0.0（行为面权威）+ D-ISIS-1（本契约 §11 草稿，门1 获批=定稿）+ T-ISIS（testcase §8 草稿）+ 生成表已含 isis（P4 只跑 `TestLayersGeneratedMatchesRegistry` 验证无过期） | 修订记录 §16 |
| §8 设计先行 | 本条目 P1–P2 先于 P4 层链整形开工；门1 获批=D-ISIS-1 定稿=开工门 | 提交序 |
| §9 测试三源 | 三源=ISO 条款（文档级，精确章节待 G-ISIS-7）+ D-ISIS-1 + tshark `isis.*` 498 字段已实证（用例去重 28）+ builder wire 真相 + 现网 DIS/计时器形态（未确认级→G-ISIS-7）；25 ID 正负对账 | T-ISIS（testcase §8.5/§8.3） |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123 报告）+ 收官隔离复审 + 修轮；红先绿后 | /tmp/pipe/78-isis/p123-report.md |
| §11 白话 | 每阶段白话一句先行 | 本契约 §0 + 汇报 |
| §12 动态清单 | 见 §12.4 强制展开：MAC=`eth` 层（`src_mac` 五策略全开，`dst_mac` 固定组播不开）；业务字段逐个列开/不开+理由；序号算法位置诚实"待 P4 定"（不编行号，§5.7） | 本契约 §12.4 |
| §13 schema 派生 | registry isis 行（单载体 `DependsOn ["eth"]`；业务键经 FlowMeta 直传 `translate:170` + `generator.go:488-494`）→ schemagen 重跑验证；struct 标签字面量锁 | §11 接线件 |
| §14 真实流程 | suite 经 MCP 建任务→引擎生成→tshark `isis.*` 字段 + frames hex 双通道；先跑后钉；pcap 落 `/tmp/mcp-pcaps/isis/` | 用例 §1/§7 |

### §12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

旧键清单（五键 + `ttl` + `src_mac` + 本协议顶层子映射 + 缺失的数量键；25 例实测）：

| 旧键 | 去向 |
|---|---|
| `src_ip` / `dst_ip` / `src_port` / `dst_port` / `count` | 25/25 零出现 → P4 不引入（L2-only 无 IP/端口/数量旧键语义；数量只走 `flow_control`） |
| `ttl` | 零出现 → 不引入（L2 无 TTL） |
| `src_mac`（顶层，24/25） | → `layers[0].eth.src_mac`（fixture `02:00:00:00:10:01` 起各例保留；今日顶层影子与 layers 并存走 `checkLayerFlatConflict`（`schema/semantic.go:183-192`）400，新建形状必须已迁入层内） |
| 顶层 `isis` 子映射（25/25） | → `layers[1]` 中 `{"isis": {...}}` 条目（正例业务键全量迁入，零残留；`ISISConfig` 22 键见 `routing.go:271-294`；#12 的 `events[4]`、#13 的 `events[2]` 进层内；`neg_ip_carrier` 的 `[ip,isis]` 链留层内走拒，按 1.12 拒绝通道表达，不删触发源） |
| 缺失的数量键（25/25 全缺） | → 兄弟键 `flow_control`（`{"flows": N}`，N=packet_count：单包例 1；#12 为 4；#13 为 2；负例 `{"flows": 1}` 占位——拒绝发生在 Plan 前，flowCount 不触发多发） |

**存量 25 例改写清单（逐键；P4 执行，§9.14 存量审计落点 testcase §5）**：实测 24 例顶层键 = `['isis','layers','src_mac']` + 1 例（#19）= `['isis','layers']`（无 `src_mac`），`layers` 24/24 = `[{"eth":{}},{"isis":{}}]` + 1 例 `[{"ip":{}},{"isis":{}}]`（链形拒绝触发源）。逐键去向：

| 现状 | 去向（P4 改写） |
|---|---|
| 顶层 `src_mac`（24 例 `02:00:00:00:10:01`） | 删除顶层键；写进 `layers[0]`（`{"eth": {"src_mac": ...}}`） |
| `layers` 内 `{"eth":{}}` / `{"isis":{}}` 空条目 | 填入迁移值（eth 条目填 src_mac；isis 条目填顶层 `isis` 子映射全部业务键 + 事件内字段） |
| 兄弟 `flow_control` | 25 例全缺，逐例补（`{"flows": packet_count}`；负例 `{"flows": 1}`） |
| 负例 `wire_fault`（#20/#21/#22/#23/#25：mixed_carrier/header/level_type/length/checksum） | 随 `isis` 子映射进 `layers[1].isis`，拒绝语义不变（锚词 `carrier/header/level/length/checksum` 已对 `planner.go:66/74/79/83/102`） |
| #19 `[ip,isis]` 链 | 保持链形（拒绝触发源），`isis` 业务进层条目，锚词 `carrier` 走 V7b（`complete.go:355`） |

改写后必须满足：非负例 `spec_json` 顶层键 = 0（`spec_json` 只留 `layers`；`flow_control` 为兄弟键）；负例 `expect` 键集合为 `{expect_error, error_contains}`（12/12 已合规，P4 保持）。`expect` 内键为 harness 断言键，不计顶层白名单。

完整单包样例（目标形状；`flow_control` 为 `spec_json` 兄弟键）：见 §2 样例（LLC L1 IIH，`flows=1`）。

### §12.2 子表③：商业行为→用例映射表（CORE_MEMORY §4.16；缺此表按 §4.22 记缺口）

| # | 商业行为（产品+行为） | 出处 | 对应用例 | 状态 |
|---|---|---|---|---|
| 1 | LAN 邻居 Hello（holding/priority/LAN ID/circuit，L1/L2 分级） | 现网通用形态（ISO 10589 同构） | #1/#2（LLC L1/L2）/#3/#4（ET L1/L2） | 已映射；**现网抓包级确认** → G-ISIS-7（确认方式：抓路由器回环/现网包） |
| 2 | LSP 泛洪（remaining/sequence/is-type/LSP ID + 地址族 TLV） | 现网通用形态 | #5（L1+v4）/#6（L2+v6）/#7（TLV 序）/#10（大 sequence）/#11（Area+System） | 已映射；确认 → G-ISIS-7 |
| 3 | 数据库同步（CSNP range + TLV 9 / PSNP entry） | 现网通用形态 | #8（CSNP）/#9（PSNP）/#12p4（序列内 PSNP） | 已映射 |
| 4 | 邻接全流程（IIH→IIH→LSP→PSNP + Initializing→Up） | 现网通用形态 | #12（4 事件）/#13（双地址族 2 事件） | 已映射 |
| 5 | 脏包/错配/伪造字段拒收（planner/链校验拒） | 引擎行为（planner+V7b 真实锚词行） | #14–#25（12 负例，锚词逐字见 §7） | 已映射 |
| 6 | 边界编码（802.3 length、LLC/ET 双载体、双 checksum 面、长度公式） | ISO 编码面 | #1/#5（LLC `00 2e`）/#8（`00 36`）/#3–#7（ET `88 70`）/#10（checksum+长度） | 已映射 |

注：本表凡记"现网通用形态"但未落抓包证据的，一律挂 G-ISIS-7 且不写死进实现（§5.5）。

### §12.3 §3 强制展开：五件套（单 profile，L2 无连接）

会话表：

| 会话 | profile | 四元组（诚实：无 IP/端口、无握手） | 生命周期（诚实：无建连/无挥手） |
|---|---|---|---|
| s1 | iso10589 LAN（LLC/ET 双载体） | `eth.src_mac` 单播源 + 组播目的（今日恒 `:15`，→ G-ISIS-5），无端口 | IIH → LSP → SNP（单 PDU 序列，无建连） |

事务序列（单事务四件事 §3.4–3.7）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| t1 hello 邻居发现 | s1 路由器在线（member 前置无） | 发 IIH（holding/priority/LAN ID/Area TLV） | 对端 Initializing；tshark `isis.type=15/16` + `hello.*` 命中 | 未知 profile → task error（#14，`profile`）；载体错 → #19（`carrier`） |
| t2 LSP 泛洪 | t1 已发（Initializing/Up） | 发 LSP（remaining/sequence/is-type + 地址族 TLV） | `lsp.*` 命中 + checksum 回填 | 非法 system → #15；地址族混用 → #17；厂商 TLV → #24 |
| t3 SNP 确认 | t2 已发（Up） | 发 CSNP（range + TLV 9）/ PSNP（TLV 9） | `csnp.*/psnp.*` 命中 | length 故障 → #23；事件内 CSNP 今日恒错 → G-ISIS-3 |
| t4 邻接扇出 | 各事件独立 PDU 字段 | 按事件序逐包 Emit（`layer_gen.go:90-101`） | 邻接隔离（#12 四包、#13 两包） | 状态串用 → #16（`state`）；交织序不假设（G-ISIS-8） |

关联关系（§3.8–3.10 三件事）：本协议**无控制流驱动数据流**（无 `driven_by` 派生流），但有**同事件序内 IIH→LSP→SNP 语义关联**：归属会话 s1（`events[].system_id/level` 继承层配置）、归属报文组（同 System/Level）、由 `kind` 序列决定——与 CWMP 范本差异点诚实声明：isis 无副流派生，`events[]` 承载"多 PDU 有序序列"。

插入位置：终结层——isis bytes 经 eth 直传（L2-only 直发分支 `chain_planner.go:1200-1222`，`EtherType` 强制 `0x8870 :1222`，`pkt.L3` 清空）；LLC profile PDU 起点 offset 17（frames 5 帧实测），EtherType profile LLC+PDU 起点 offset 14（frames 17 帧实测）。

时间线：**顺序**——同会话内 t1→t2→t3 严格报文序；会话间并发但输出不假设全局包序，只断言包内字段与隔离；无"长传输分片让位"面（单 PDU）；控制可中插动作=无。§3.12 的调度方式在本协议落点为"按事件序逐包 Emit"。

### §12.4 §12 强制展开：动态字段清单

| 字段 | 住处 | 开策略 | 理由 |
|---|---|---|---|
| `src_mac` | eth 层 | fixed/inc/rand/list/pattern 全开 | §12.2 MAC 必备；多源并发锚点（`layer_dyn.go:21` eth 开关实证） |
| `dst_mac` | eth 层 | 不开（组播 fixture 钉死；恒 `:15` 今日值，L1/L2 拆分待 G-ISIS-5） | 目的须按 level 语义；动态目的池无需求 |
| `wire_profile`/`pdu_type`/`level` | isis 层 | 不开（双载体/四 PDU/双 level 各自独立模板） | 载体与报文类切换 = 换策略（§2.5），不用动态冒充 |
| `system_id`/`lan_id`/`lsp_id` | isis 层 | 不开（fixture 钉死；多 SystemID 池待立项） | 多路由器并发面 → G-ISIS-8 |
| `holding_timer`/`sequence`/`priority` | isis 层 | 不开（fixture 钉死；sequence 显式事件值） | 计时/序号语义值，非按流变化量 |
| `tlvs`/`events` | isis 层 | 不开（fixture 钉死字节；扇出结构静态声明） | TLV 变体靠多策略（§2.5），事件扇出与动态正交 |
| isis 层 allowlist | — | 今日 isis 层无动态开关（`layer_dyn.go` 无 isis 条目） | isis 业务动态 → G-ISIS-8（适用性待 P4 定） |

序号算法代码位置：**待 P4 定**（D-ISIS-1 定稿后 casegen/层链整形落码时钉死文件+行号；此处不编行号——§5.7）。静态复制禁令（§12.9）执法面：`checkLayerChainStaticCopy`（`schema/semantic.go:204-`，`eth` 在列、`layerTupleFields("eth")=[src_mac,dst_mac] :415-417`）——`flows>1` + 层内静态 `src_mac` 即拒，逃生口=层内动态对象。

### §12-P2 presence 负例形状（链级红例必含①）

层链+顶层空子映射并存=判死负例（presence 负例形状，非残留）：`{"layers":[{"eth":{}},{"isis":{}}],"isis":{}}`（顶层空 `isis:{}` 与层链并存）必须 planner/validator 拒——**但 isis 当前 `CheckProtoFlat` 无同名子映射分支**（`strategy_convert.go:8322-8555` 有 http/dns/mqtt/…/radius 等分支，**无 isis**；`rawWrapChains :8541-8546` 仅含 pppoe/ldap/rtmp/rtsp/pptp/vnc/xmpp/sctp/jt808/jtt905/arp/icmp，**无 isis**）：P4 须补 `isis` presence 判死分支（`error_contains` 含顶层键锚词 `rejects a top-level isis sub-config`），否则 presence 形静默过（顶层先填 spec 赢层配置——隔离复审 F1 探针同构）。跨协议共享面，**主线程定夺，车道不自改**（→ G-ISIS-1）。白名单外游离键（如顶层 `src_mac` 与 layers 并存——`checkLayerFlatConflict :183-192` 已有守卫，P4 加例）判死负例见 §11。另注：isis 单 L2 载体 → 链中夹 `tcp`/`udp`（`[eth,tcp,isis]`/`[ip,udp,isis]`）判死负例（V7b 含 Transport 即错）；裸链 `[isis]` 判死负例（`DependsOn ["eth"]` 缺失由 validate_layers 拒绝）。P4 链级红例共 4 例 + 收官自查行「非负例 `spec_json` 顶层键=0」。

## §13 缺口立项清单（有缺口写"缺口立项"，不许空着）

| 立项号 | 缺口 | 确认方式（三选一） | 去向 |
|---|---|---|---|
| G-ISIS-1 | presence 守卫缺失：`CheckProtoFlat :8322-8555` 无 `isis` 同名子映射分支；`rawWrapChains :8541-8546` 无 isis 条目；`parseSubconfigJSON` 普通 `json.Unmarshal` 未知键静默忽略（`strategy_convert_helpers.go:21-30`） | 读 `strategy_convert.go` 现状 + 引擎负例实测 | P4 补守卫（跨协议共享面，主线程定夺，车道不改）；未知键面评估是否框架级统一 `DisallowUnknownFields` |
| G-ISIS-2 | `area_addresses` 简写 dead：只做互斥校验（`planner.go:57-59`），从不参与编码（builder/layer_gen 零读取） | 读 `builder.go`/`layer_gen.go` 全文 | P4 二选一：实现编码（TLV 1 自动合成）或按 1.12 删键（用例配置里删掉该字段，不登记保留） |
| G-ISIS-3 | CSNP 事件恒错：`buildEventPDU :152` 把 `ev.PDUType` 当 `startLSPID` 传、`endLSPID` 传空 → `parseLSPID` 必错；`ISISEvent` 无 start/end 键 | 读 `layer_gen.go:136-157` + 单测复现 | P4 修（事件加端点键或复用顶层端点）+ 回归单测；修前事件内 CSNP 不得写例 |
| G-ISIS-4 | `p2p_hello` planner/builder 不一致：`validateLevelAndType :171` 放行，`buildSinglePDU :112-133` 无分支报 `unsupported pdu_type` | 读 `planner.go:160-177` + `layer_gen.go:112-133` | P4 二选一：实现 P2P IIH 编码或 planner 拒（另立 P2P profile 时重议） |
| G-ISIS-5 | L1 目的组播 MAC 存疑：代码恒 `01:80:c2:00:00:15`（`:13`），L1 应为 AllL1ISs `:14` 未区分；存量零 `eth.dst` 断言 | 查 ISO 10589 组播地址节 + 抓包 | 确认前按 §5.5 标待确认，不写死；P4 修或立边界 |
| G-ISIS-6 | `checksum_mode=manual`/`checksum` 不生效：校验放行（`:104-106`）但 builder 恒自动计算（`:214-250` 无 manual 分支） | 读 `builder.go:214-250` | P4 二选一：实现 manual 回填或按 1.12 删键 |
| G-ISIS-7 | 现网证据升级 + ISO/RFC 精确章节复核：DIS 选举/计时器/泛洪行为的"已确认现网"级证据；ISO 10589 精确章节号；FRR 等开源实现版本/文件 | 抓包（抓路由器回环/现网包核对 Type/载体/MAC 面）+ 查原文 | P4 前置确认项，不挡开工；确认前相关条目按 §5.5"待确认"不写死 |
| G-ISIS-8 | B′ 行为面：认证 TLV 10/扩展 TLV 22/128/129/135/137/周期重发定时器/多会话并发交织序/isis 层业务动态（`layer_dyn.go` 无 isis 条目）/多 SystemID 池 | 查 ISO/RFC 相关节 + 引擎序号算法现状（P4 定） | B′→D-ISIS-1"明确不解决+迁入计划"（确认后进 §10.2 空白格）；A′ 补例 T-ISIS-26..30 先行 |

## §14 与 38 旧文档逐条核对 + 38→78 沿革（10.2）

旧基线：`38-isis-design.md` v1.0.1（235 行）+ `38-isis-testcase.md` v1.0.1（67 行），2026-08-20"设计阶段：`isis` 层尚未实现，不宣称 suite 可运行"。

逐条核对（design §1–§9 / testcase §1–§7）：

- §1 范围（保留+扩）：双 profile/offset 14/17 表不动；"层尚未实现"段按实测改写为已注册已落码（registry.go:946 + 1251 行四文件 + 21 单测）；新增 TLV 236 行与证据等级表。
- §2 配置表（保留，语义收紧）：业务键语义不变；新增 `address_profile` 双向互斥注记 + `area_addresses`/`manual`/`p2p_hello` 三处"接受但不生效/不一致"诚实声明（G-ISIS-2/4/6）；`events` 加 CSNP 恒错注记（G-ISIS-3）；`DefaultDstMAC` 单值注记（G-ISIS-5）。
- §3 线格式（保留，补实测）：补 Type→frames 前缀对照（39 帧三档 offset）+ Length Indicator/PDU Length 双长度口径 + Type Block/Source Circuit 恒零实现行。
- §4 事件状态（保留，补不消费声明）：`neighbor_state` 只携带不进线（`buildEventPDU` 全库只读报文类字段实证）。
- §5 TLV（保留，改名以正名义）：IPv4/IPv6 为 TLV profile 非 IP 外层口径保留；TLV 250 拒绝例 + TLV 236 缺失例新增。
- §6 负路径表（保留，锚词实测化）：10 行故障表 → §7 十二锚词行表（含 V7b carrier 与首错分支注记）。
- §7–§8 场景表（25 ID 逐条保留，packet_count 序列 `[1×11,4,2]` 不变，总包数 17）。
- testcase：25 ID 集合/顺序/正负比（13 正+12 负）全保持；§5 三方清单 → §6（加 28/28 注册命中 + 39 帧重数实测）；新增 §5 存量逐条审计 + §8 P3 固定动作。

无旧条目被静默删除。旧文档留盘只读，本契约不回写 38-* 任何字节。

## §15 P1/P2 对抗自重审结论（10.11；过 3 轮，末轮干净）

- **P1（§10 矩阵）**：R1 自重审发现 §10.2 初稿把 R6B/R7B 记为"不适用"→ 实读 `neg_state` 与 #12 事件后改"已覆"（#16 + #12 序列内 Up），重数 22+6+4=32 复算一致；R2 逐行核八项矩阵"代码现状"列全部行号实读源文件（builder/planner/layer_gen/routing/chain_planner/complete/translate/generator/registry/protocols/layer_dyn/schema），无编造行号（registry 取 HEAD=工作树一致值 946；translate 无 `case "isis"` 分支如实记为 passthrough+nil-guard 两行）；R3 末轮干净。
- **P2（§11 D-条目）**：R1 自审发现初稿"顶层 `isis` 子映射迁入层条目"未点名引擎今日仍读顶层（`strategy_convert.go:738-740`）→ 补冲突点①并标跨协议共享面主线程定夺；R2 抓出初稿遗漏 `buildEventPDU :152` CSNP 传参错位（读全 `layer_gen.go:136-157` 浮出）→ 立 G-ISIS-3；R3 末轮干净。
- P3 结论见 testcase §8 与 p123 报告（过 3 轮，末轮干净）。

三阶段设计侧合计修正 4 处（2 处矩阵归类、1 处冲突点遗漏、1 处代码 bug 浮出立项），末轮均干净。

### §15.1 文档逐条自核对结论（10.1：对规范逐条核对）

- ISO 10589（四类 PDU Type 值、8B 公共头、IIH 19B 固定/LSP Fletcher-16/CSNP range/PSNP entry、System/LSP ID、Area TLV、L1/L2 分级）→ §3/§4 逐条有落点；RFC 1195/5305/5308（地址族与扩展边界）→ §5。精确章节号挂 G-ISIS-7 不写死（§5.5）。
- 与旧需求文档逐条核对（10.2）：见 §14。

## §16 修订记录

- v1.0.0（2026-09-27）：P1–P2 完整产物。新增 §10 P1 八项规范矩阵 + 三子表（PDU×载体/状态矩阵、数据形态变体表、§12.2 商业映射表）/ 三路对照 §10.4 / 候选方案 §10.5；§12 门1 §1–§14 十四行表（§1/§3/§12 强制展开 + 目标形状 spec_json 双样例 + presence 形状 §12-P2）；§11 D-ISIS-1 P2 代码设计草稿；§13 缺口立项（G-ISIS-1..8）；§14 沿革核对；§15 自重审结论。§1 重写为 profile＋已注册边界（注册行号 registry.go:946 实测）；§2 增补 25 例存量形状声明（旧混合形 24+1 双形状，P4 改写）；§7 增补锚词→代码行表；§9 新增 25-ID 摘要表（与 testcase §2 逐值一致）。
- v1.0.1（2026-08-20，`38-isis-*`）：建立 ISO 10589 LAN IS-IS 设计契约；覆盖 LLC/EtherType 载体、L1/L2 IIH、LSP、CSNP、PSNP、标准 TLV、System ID/Area、PDU length、LSP Fletcher-16、邻接状态和 IPv4/IPv6 TLV 边界；厂商 TLV 与未证实扩展保持待实现。

# BGP（边界网关协议，Border Gateway Protocol v4）设计契约

> 版本：v1.0.0（P1–P3 文档轨产物；#80 bgp）
> 日期：2026-09-26
> 车道：并发管线车道 A（文档轨）｜协议号：**80**（ledger 队列位；文件按新编号 `80-bgp-*.md`）
> 配套文件：`docs/protocols/bgp/testcase.md`、`trafficgen/test/protocol_pcap/cases/bgp.json`（现存 43 例：20 正 + 23 负）、旧基线 `docs/protocols/bgp/_archive_36-bgp-design.md` + `_archive_36-bgp-testcase.md`（2026-08-20，归档产物；逐条核对见本契约 §12说明）
> 规范基线：RFC 4271（报文格式 §4 / 路径属性 §5 / 错误处理 §6 / FSM §8 / UPDATE 收发 §9）；IPv6 传输范围参照 RFC 2545；MP_REACH 归 RFC 4760、能力协商归 RFC 5492、4-octet ASN 归 RFC 6793（§11 B′）。
> **层链唯一真相**：本契约目标形状只有纯 `layers` 形——地址只住 `ip` 层（`src`/`dst`）、端口只住 `tcp` 层（`src_port`/`dst_port`）；数量由 case 级 `strategy_fc` 承载，不混入 `spec_json`。顶层只允许 `layers`/流控与跨流绑定框架键/`output`（CORE_MEMORY §1.11–1.13）。任何顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/顶层 `bgp` 子映射都判违规；`events`/`sessions` 已接入 `bgp` 层。
> **注册现状**：`bgp` 层**已注册**（`registry.go:1357`；P1 写作时 1012，后续车道合并续漂，锚词逐字在；`CategoryTerminal` + `DependsOn ["tcp"]` + `FieldContract {"tcp.dst_port":"179"}`），`allowedProtocols["bgp"]=true`（`core/protocols.go:22`），`NewChainPlanner("bgp")` 已在 `trafficgen/cmd/server/main.go:500` 注册（空白导入 `:22`）。本文**不宣称本次跑过 suite、不启动服务器**；所有"已落码/未落码"结论均标实测出处。

---

## 1. 范围、证据等级与已落码边界

本设计定义 BGP-4（version=4，RFC 4271）在 TCP/179 单连接上的**事件编排会话**生成契约：双向 OPEN 交换 → KEEPALIVE/UPDATE → 可选 NOTIFICATION 终结 → TCP 挥手。生成器是**声明式脚本化回放**：所有应用事件必须显式配置，不自动插入 OPEN/KEEPALIVE/响应，不模拟定时器协商、路由收敛、重传。

**证据等级三档（本契约纪律）**：

| 档 | 可写内容 | 是否固定线字节 |
|---|---|---|
| ①规范原文级 | 通用头（marker/length/type）、OPEN/KEEPALIVE/UPDATE/NOTIFICATION 布局、6 类路径属性编码、前缀截断规则、错误码表、hold time 语义 | 是——逐字节可断言 |
| ②dissector 实测级 | 本机 TShark 3.6.14 `bgp.*` 字段名与取值（**784** 个 F 字段中有断言价值的见 §3.9）、`decode` 行为 | 是——但仅作断言通道，不改写线真相 |
| ③实现现状级 | 本仓库 `internal/protocol/bgp/*` + 链路（registry/translate/drive/Meta）的已落码能力边界（哪些事件 kind 有 builder、事件面走哪条通道） | 是——作为"今日可达/不可达"的判据 |

**已落码边界（实测，2026-09-26 HEAD）**：

- 生成器：`internal/protocol/bgp/layer_gen.go`（109 行）——`Generate`（`:15`）+ `emitEvents`（`:52`）+ `defaultDualEvents`（`:85`，P0b-2 缺省 6 事件流）；`BGPGenerator.GenEvents/EmitEvent`（`:101-104`）。
- 字节原语：`internal/protocol/bgp/builder.go`（518 行）——`BuildOpen`（P6 行 `:295`；P1 写作时 261）/`BuildKeepalive`（P6 行 `:315`；P1 写作时 281）/`BuildEvent`（P6 行 `:326`；P1 写作时 292）/`buildOpenEvent`（P6 行 `:348`；P1 写作时 314）/`BuildUpdate`（P6 行 `:385`；P1 写作时 351）/`encodePrefix`（P6 行 `:428`；P1 写作时 394）/`encodeAttributes`（P6 行 `:441`；P1 写作时 407，+34 漂移族）/`appendPathAttr`（P6 行 `:513`；P1 写作时 479）/`BuildNotification`（P6 行 `:541`；P1 写作时 507）；`ValidateConfig`（`:66`）+ `validateEventConfig`（`:109`）+ `validateUpdateEvent`（`:175`）。
- 状态机校验：`internal/protocol/bgp/planner.go`（160 行）——`Validate`（`:14`）+ `validateSessionConfig`（`:39`，逐 session 独立状态机）+ `validateEventSequence`（`:65`）+ legacy `Plan`（`:110`，直调回归面）。
- 链路：`BGP: spec.BGP` 经 `FlowMeta` 直传生成器（`chain_planner_translate.go:114`）；终结层 nil-默认（`:702-703`）；层翻译在 `chain_planner_translate.go:791` 严格 JSON 往返进入 `spec.BGP`；`mapToFlowSpec` case `"bgp"`（`strategy_convert.go:1661-1667`）；Go 单测 `bgp_test.go`（字节级 + 状态机级）。
- **事件面已接线**：registry `bgp` Fields 包含 `events`/`sessions`（`registry.go:1371-1379`），层 config 经 `completedConfig` + JSON 往返进入 BGP spec；顶层 `bgp` 子映射由 `CheckProtoFlat` 判死（`strategy_convert.go:8750-8755`）。因此正例事件面统一住 `bgp` 层；负例 `bgp_neg_presence_top_level_bgp` 专门守旧键门。

- 当前 `cases/bgp.json` **43 例（20 正 + 23 负）**构成存量审计基线（testcase §8）。正例已采用纯层链；负例保留故障注入或白名单门形状。

---

## 2. 推荐配置、层链与事件形状

### 2.1 层链

唯一合法链形：**`[ip, tcp, bgp]`**（IPv6 地址族同住 `ip` 层，不新增层）。`bgp` 是**终结层**（`CategoryTerminal`），`DependsOn ["tcp"]` 单值。

**目标形状（当前可运行的唯一正例形；事件面已由 registry + translate 接线，见 §1）**：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.80", "dst": "198.51.100.80"}},
    {"tcp": {"src_port": 45080}},
    {"bgp": {
      "wire_profile": "bgp_rfc4271_ipv4_unicast",
      "events": [
        {"kind": "open", "direction": "c2s", "version": 4, "my_as": 64512, "hold_time": 90, "identifier": "192.0.2.1"},
        {"kind": "open", "direction": "s2c", "version": 4, "my_as": 64513, "hold_time": 90, "identifier": "192.0.2.2"},
        {"kind": "keepalive", "direction": "c2s"},
        {"kind": "keepalive", "direction": "s2c"}
      ]
    }}
  ]
}
```

- **`tcp.dst_port` 不写**：由 `bgp` 层 `FieldContract {"tcp.dst_port": "179"}`（`registry.go:1357-1358`）经通用 FieldContract 块（`chain_planner.go` 通用块，`validateBaseDstPortHandled` 之外的 amqp/bgp 同款）补齐；用户显式写 tcp 层 `dst_port` 时用户值优先（`:607-620`），非 179 仍可作 TCP 载体（旧基线 §1 不变式②延续）。

**旧形去向（§12.1 机读，历史记录）**：旧阶段 19 例曾用空层链 + 顶层四元组 + 顶层 `bgp` 事件面；现 43 例全部收敛为纯层链。`bgp_neg_udp` 为 `[ip,udp,bgp]` 载体负例（锚词 `tcp`），不是旧残留。

### 2.2 层内配置键（**唯一权威 = registry `Fields`**；P6 实测 13 键（11 原键 + `events`/`sessions`），`registry.go:1360-1379`；P1 写作时 `:1012-1027`）

| 键 | 类型 | 默认 | 语义 | 证据 |
|---|---|---|---|---|
| `transport` | string | `""` | 载体声明；非空非 `tcp` 即拒（`planner.go:20-27`） | registry + planner |
| `version` | uint8 | 0→4 | 层内默认 OPEN version（`normalized`，`builder.go:46-61`） | registry |
| `asn` | uint32 | 0→64512 | 层内默认 My AS | registry |
| `hold_time` | uint16 | 0 | 层内默认 hold time（0 = 不启用保持计时器，RFC 4271 §4.2） | registry |
| `identifier` | string | `""`→192.0.2.1 | 层内默认 BGP identifier | registry |
| `marker` | list | [] | 层内默认 marker 覆盖；非全 `ff` 即拒 | registry + `builder.go:92-99` |
| `length` | uint16 | 0 | 顶层长度覆盖；非 0 时须 ∈ 19..4096 | registry + `builder.go:100-102` |
| `wire_profile` | string | `""`→`bgp_rfc4271_ipv4_unicast` | 模板名；非默认值即拒 `profile %q unsupported`（`builder.go:80-82`） | registry |
| `capabilities` | list | [] | 非空即拒（RFC 5492 面未实现，B′） | registry + `builder.go:83-85` |
| `update` | list | [] | 非空即拒（旧扁平遗留守卫） | registry + `builder.go:86-88` |
| `notification` | list | [] | 非空即拒（旧扁平遗留守卫） | registry + `builder.go:89-91` |

**层字段范围校验（V9）**：白名单制——`events`/`sessions` 已登记为 `bgp` 层字段并由 translate JSON 往返解码；其余未知键 → `layers: layer "bgp": unknown field %q`（`complete.go:293`）。顶层旧 `bgp` 子映射由 G-BGP-6 门拒绝。

### 2.3 事件形状（今日唯一通道 = `layers[].bgp` 子映射；`core/types.go:92-140`）

`BGPConfig` 14 个 JSON 键；`BuildEvent`（P6 行 `builder.go:326`；P1 写作时 292）实际消费的事件面：

| 事件键 | 被消费？ | 消费点 / 备注 |
|---|---|---|
| `kind` | ✅ | `validateEventConfig`（P6 行 `:113`；P1 写作时 109）+ `BuildEvent` dispatch（P6 行 `:330` 起；P1 写作时 296-308）：`open`/`keepalive`/`update`/`notification`/`wire_fault` |
| `direction` | ✅ | 非 `s2c` 即上行（`layer_gen.go:72`；`planner.go:151` 同款）；非法值拒 `must be c2s or s2c`（`builder.go:166-168`） |
| `version`/`my_as`/`hold_time`/`identifier` | ✅ 仅 `open` | `buildOpenEvent`（P6 行 `:348` 起；P1 写作时 314-346）；`my_as` 为 uint32 专防 JSON 静默绕回（`types.go:113` 注释） |
| `withdrawn_prefixes`/`nlri` | ✅ 仅 `update` | `BuildUpdate`（P6 行 `:385`；P1 写作时 351）；`validateIPv4Prefix`（P6 行 `:245`；P1 写作时 211，非 IPv4 → `address` 锚词） |
| `attributes` | ✅ 仅 `update` | `encodeAttributes`（P6 行 `:441`；P1 写作时 407）；`origin` 指针式（IGP=0 可辨，`types.go:128`） |
| `error_code`/`error_subcode` | ✅ 仅 `notification` | 仅允许 4/0（P6 行 `:140`；P1 写作时 507-513），余者 B′/#34 |
| `fault_kind`/`value` | ✅ 仅 `wire_fault` | **验证边界指令**：`marker`/`length`/`type` 三值，命中即拒，永不产线字节（`:136-160`） |
| `transport`（层内） | ✅ | 仅 `tcp`/空（`planner.go:20`） |
| `sessions[]` | ✅ | 每项 `{src_port, events[]}`；`>1` 时逐 session 独立连接（`layer_gen.go:35-42`）；`==1` 时提升 events（`:44-46`，mongodb 同款契约） |

### 2.4 wire_profile 登记值与能力边界（实测）

| wire_profile | 语义 | 今日状态 |
|---|---|---|
| `bgp_rfc4271_ipv4_unicast` | RFC 4271 IPv4 单播主模板（默认，`builder.go:18/57-59`） | ✅ 可生成（43 例中正例在用） |
| 其他一切值（含 `bgp_mp_reach_ipv6_pending`、`bgp_ipv6_mp_reach`） | 未登记模板 | ❌ 拒绝，锚词 `profile`（`builder.go:80-82`；单测 `bgp_test.go:95-111`） |

**关键现状**：`wire_profile` **不参与任何字节构造**——同模板内字节只由事件字段决定。跨版本差异（MP_REACH/能力/4-octet ASN）今日零支持 → B′（§11.2）。

---

## 3. 线格式权威（逐字段，P4 builder 硬对照表；RFC 4271 §4）

### 3.1 通用报文头（RFC 4271 §4.1；19 字节；`builder.go:247-259` prelude/finalize）

| 偏移 | 字段 | 宽度 | 值域/语义 | 出处 |
|---|---|---|---|---|
| 0–15 | Marker | 16B | 全 `0xff`；否则拒（锚词 `marker`） | RFC §4.1；`builder.go:92-99/:140-142` |
| 16–17 | Length | 2B 大端 | 含头总长，19 ≤ length ≤ 4096；按编码后字节回填 | RFC §4.1；`builder.go:257-259` |
| 18 | Type | 1B | 1 OPEN / 2 UPDATE / 3 NOTIFICATION / 4 KEEPALIVE；余者拒（锚词 `type`/`unknown message type`） | RFC §4.1；`builder.go:153-157` |

### 3.2 OPEN（RFC 4271 §4.2；body 10 字节 + 空可选参数；总长 29 = `00 1d`）

| 偏移 | 字段 | 宽度 | 值域/语义 |
|---|---|---|---|
| 19 | Version | 1B | 恒 4；余者拒（锚词 `version`） |
| 20–21 | My AS | 2B 大端 | 0–65535；超限拒（锚词 `as`/`my_as`）；4-octet ASN 归 B′ |
| 22–23 | Hold Time | 2B 大端 | 秒；0 = 不启用；**RFC 要求 0 或 ≥3（§4.2）；今日校验对 1–2 以 `hold_time` 锚词拒绝，且有专用负例** |
| 24–27 | BGP Identifier | 4B IPv4 | 非零 IPv4；即使 IPv6 transport 仍为 IPv4（RFC 4271 §4.2；旧基线 §1 不变式④） |
| 28 | Opt Params Length | 1B | 本模板恒 0；能力参数归 B′ |

OPEN 金向量（`bgp_test.go:18-30`）：`ffffffffffffffffffffffffffffffff001d0104fc00005ac000020100`（AS 64512=`fc 00`，hold 90=`00 5a`，id 192.0.2.1）。

### 3.3 KEEPALIVE（RFC 4271 §4.4；恒 19 字节）

无 body：marker + `00 13` + type `04`（P6 行 `builder.go:315` 起；P1 写作时 281-287；单测 `:32-43`）。只能出现在 OPEN 交换成功后；connect 例不自动增发（`defaultDualEvents` 只用于 events 缺省 nil，显式 `[]` = connect-only，`layer_gen.go:53-57`）。

### 3.4 UPDATE（RFC 4271 §4.3；P6 行 `builder.go:385` 起；P1 写作时 351-389）

顺序：`Withdrawn Routes Length(2)` + withdrawn + `Total Path Attribute Length(2)` + 属性 + NLRI。任一长度区超 65535 即拒（`:371-373`）；总长超 4096 即拒（`:381-384`，锚词 `4096`）。

IPv4 前缀 = `prefix length(1B)` + `ceil(plen/8)` 个最高有效地址字节（P6 行 `encodePrefix :428` 起；P1 写作时 394-400）：`203.0.113.0/24` = `18 cb 00 71`；`192.0.2.1/32` = `20 c0 00 02 01`。prefix length 0 今日拒（P6 行 `validateIPv4Prefix :245` 起；P1 写作时 219-222），对应缺口立项 G-BGP-8（补专用负例并固定拒绝锚词）。

属性编码（本模板固定，flags/type/length 逐字段）：

| 属性 | Flags | Type | Value | 出处 |
|---|---|---|---|---|
| ORIGIN | `0x40` | 1 | 1B：0 IGP / 1 EGP / 2 INCOMPLETE（1/2 → #13/#14） | RFC §5.1.1 |
| AS_PATH | `0x40` | 2 | segment type（本模板恒 AS_SEQUENCE=2；AS_SET 未实现 → B′）+ count + 2B ASN 列表 | RFC §5.1.2 |
| NEXT_HOP | `0x40` | 3 | 4B IPv4（非法值拒 → #37） | RFC §5.1.3 |
| MULTI_EXIT_DISC | `0x80` | 4 | 4B 无符号（0 值缺席；缺席面由 T4 覆盖） | RFC §5.1.4 |
| LOCAL_PREF | `0x40` | 5 | 4B 无符号 | RFC §5.1.5 |
| COMMUNITIES | `0xc0` | 8 | 每 community 4B；`NO_EXPORT=0xffffff01`（`NO_ADVERTISE` → #15；`ASN:N` 数值形拒 → 现状钉死） | RFC §5.1.6（well-known 研读注记） |

长度一律 one-octet；值长 ≥256 走扩展长度编码——本模板不支持，拒（P6 行 `appendPathAttr :513` 起，锚词 `extended-length` 在 `:515`；P1 写作时 479-486，单测 `:514-526`；pcap 例立项 extended-length 无 ID）。

全属性 UPDATE 金向量（`bgp_test.go:255-279`，length `00 42`=66，path_attr_len=39；§12-P0 复算见 testcase §1）：
`ffffffffffffffffffffffffffffffff00420200000027400101004002040201fc00400304c00002018004040000006440050400000064c00804ffffff0118cb0071`

### 3.5 NOTIFICATION（RFC 4271 §4.5；P6 行 `builder.go:541` 起；P1 写作时 507-518）

body = `Error Code(1)` + `Error Subcode(1)` + Data。本模板仅 Hold Timer Expired（4/0，空 data，总长 21=`00 15`；金向量 `...0015030400`，单测 `:318-332`）。其余错误码（含 Cease 6 → #34，锚词 `error_code`）今日拒 + B′（§11.2）。

### 3.6 状态机约束（RFC 4271 §8 精简可观察版；`planner.go:65-108`）

- OPEN 须成对（两方向各一）；单 OPEN 拒 `exactly two`（`:104-106` → #32）。
- KEEPALIVE/UPDATE 须在任一 OPEN 后；否则拒 `state violation`（`:86-90`；UPDATE 面有 N8，KEEPALIVE 面 → #33）。
- OPEN 不得出现在应用事件之后（`:81-83` → #30）。
- NOTIFICATION 须在 OPEN 后（单测 `:387-393` → #38）且为最后应用事件（`:95-98`；单测 `:395-404` → #31）。
- 多会话：每条 session 独立跑同一状态机（`:46-53`；单测 `:429-445`）。

### 3.7 包数、帧偏移

无额外 TCP option、每事件一 TCP data segment 时：`packet_count = 3（SYN/SYN-ACK/ACK）+ 应用事件数 + 4（FIN 终止）`。IPv4 payload 起点 offset **54**（14+20+20）；IPv6 起点 offset **74**（14+40+20）。固定 offset 仅用于未分段帧；MSS 分段走 TCP stream 重组（tcp 层；`chain_planner.go` MSS 门 `MinMSS 536/RFC 879`）。

### 3.8 地址族与 MP_REACH 边界

IPv6 transport 只改变 IP 外层（TCP 仍 179，identifier 仍 IPv4，NLRI 仍 IPv4）。IPv6 NLRI 需 MP_REACH_NLRI（RFC 4760）——AFI/SAFI/下一跳/SNPA/编码今日全无 → 输入拒 `address`（`validateIPv4Prefix :216-218`；N9）。`bgp_mp_reach_ipv6_pending` 输入拒 `profile`（N2）。

### 3.9 dissector 断言通道（本机 TShark 3.6.14 实测，`bgp` 协议已注册，F 字段 784 个）

本契约断言只用以下实测存在字段：`bgp.type`、`bgp.length`、`bgp.marker`、`bgp.open.version`、`bgp.open.myas`、`bgp.open.holdtime`、`bgp.open.identifier`、`bgp.open.opt.len`、`bgp.prefix_length`、`bgp.update.withdrawn_routes.length`、`bgp.update.path_attributes.length`、`bgp.update.path_attribute.origin`、`bgp.update.path_attribute.as_path_segment.*`、`bgp.update.path_attribute.next_hop`、`bgp.update.path_attribute.multi_exit_disc`、`bgp.update.path_attribute.local_pref`、`bgp.update.path_attribute.community*`、`bgp.notify.major_error`、`bgp.notify.minor_error_expired`，外层 `ipv6.version`/`tcp.dstport`/`tcp.srcport`。其余 `bgp.*`（MP_REACH/route-refresh/大段扩展）不得写入断言——无规范/实现双支撑。

---

## 4. 会话状态机与自动派生（设计权威）

### 4.1 状态集合

`transport-connect → OPEN 交换中 → Established → {UPDATE|KEEPALIVE}* → [NOTIFICATION] → TCP 挥手`。只约束可观察事件顺序，不承诺路由器真实 FSM 重传/定时器。

### 4.2 非法转移（拒绝 + 锚词；§7 全表）

见 §3.6 与 §7：`state`（状态机）/`last`（NOTIFICATION 非末）/`exactly two`（OPEN 不成对）/`version`/`as`/`address`/`marker`/`length`/`type`/`profile`/`identifier`/`next_hop`/`4096`/`error_code`。全部经 planner/validator 层拒绝并使任务进入错误终态（零假成功纪律，§7）。

### 4.3 自动派生帧（生成器自动补的内容，逐条列出）

1. TCP 三次握手（SYN/SYN-ACK/ACK）——tcp 层生成器（`generator.go:846-931`；`handshake` 缺省 true `:895`）。
2. TCP 四步 FIN 挥手——`termination` 缺省 true（`:896`）；RST 面 → #18（tcp 层 `rst` 键已登记，P4 实测行为）。
3. 多会话：distinct `SrcPort` 首用即独立握手/挥旧握新（`generator.go:878` 注释口径）。
4. **不派生**：OPEN/KEEPALIVE/响应一律不自动补（`layer_gen.go:53-57` connect-only 语义；旧基线 §4 延续）。

---

## 5. 依赖声明与端口契约

- 依赖 = `DependsOn ["tcp"]` 单值（今日行 `registry.go:1357`），无 `TransportOn`/`OptionalOn`/`InnerRequired`；`[udp,bgp]` 链非法（N1，锚词 `tcp`）。
- 端口契约 `FieldContract {"tcp.dst_port": "179"}`（同上）；用户显式写 tcp 层 `dst_port` 优先（`chain_planner.go:607-620`）。
- 失败传播：planner/validator 错误 → 任务错误终态；`wire_fault` 三 kind 在校验层直接拒（`builder.go:140-157`），永不产线字节。

---

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **6.1/6.2 目标**：单流事件数 ≤ 6（默认流）/常规 ≤ 10；单报文 ≤ 4096 B（硬拒）；并发会话数随 `strategy_fc.flows` / `sessions[]` 线性；内存上限 = 单 flow O(1)（事件逐条编码即发，无全量收集：`emitEvents` 循环 + `Plan` 通道 16）。
- **6.3 双路验收**：pcap 输出（suite 落盘 `/tmp/mcp-pcaps/bgp/`）与真实网卡输出（NIC=`enp135s0f0np0`，测试记忆口径）用同一份用例契约（§8.2⑦）。
- **6.4 依据**：逐事件流式（`layer_gen.go:66-77`）、无锁无共享状态（唯一可变 = 循环下标）、限速由框架 `SharedTokenBucket`/任务父桶承载（§2 策略/任务语义，不重复定义）。
- **6.5 数字纪律**：吞吐包/秒、bps 目标标「待 P4 基准」，不写承诺。
- **6.6 六类场景**：基线（T1 connect）/目标规模（T9 双会话）/压力上限（#35 4096 边界）/长时间（#11 多轮）/并发交错（#12/#20 多会话）/资源耗尽（extended-length 立项 + 缓冲背压走框架）。
- **6.7 断言**：实际包数/字段值/hex + 拒绝终态；不许只断言"任务没有报错"。
- **6.8**：功能正确但超 4096/内存预算仍不合格（硬拒已落码 `:381-384`）。

---

## 7. 错误处理与错误传播

| # | 输入故障 | 必须拒绝的原因 | 稳定错误关键词 | 用例 |
|---|---|---|---|---|
| 1 | UDP 或缺 TCP 层 | BGP 只承载在 TCP | `tcp` | N1 ✅ |
| 2 | 未登记 profile | 未知模板不降级 | `profile` | N2 ✅ |
| 3 | marker 非全 `ff` | 通用头非法 | `marker` | N3 ✅ |
| 4 | length<19/>4096/不符 | 报文边界非法 | `length` | N4 ✅ |
| 5 | type ∉ 1–4 | 未知消息类型 | `type`/`unknown message type` | N5 ✅ |
| 6 | OPEN version ≠ 4 | BGP-4 profile 不匹配 | `version` | N6 ✅ |
| 7 | My AS > 65535 | 2 字节字段不可编码 | `as`/`my_as` | N7 ✅ |
| 8 | IPv6 NLRI 于 IPv4 模板 | 地址族不匹配 | `address` | N9 ✅ |
| 9 | Established 前 UPDATE/KEEPALIVE（无 OPEN） | 邻接状态非法 | `state` | N8 ✅（UPDATE 面；KEEPALIVE 面 → #33） |
| 10 | hold_time 1–2 | RFC 4271 §4.2（0 或 ≥3） | `hold_time` | `bgp_a_neg_hold_time_small` ✅ |
| 11 | 非法 BGP identifier（非 IPv4/零地址） | 4B identifier 不可编码 | `identifier` | #36 ✅（A′） |
| 12 | 非法 NEXT_HOP（非 IPv4） | 4B IPv4 不可编码 | `next_hop` | #37 ✅（A′） |
| 13 | UPDATE 编码超 4096 | 报文边界非法 | `4096` | #35 ✅（A′） |
| 14 | NOTIFICATION 非 4/0 错误码 | 本模板仅 Hold Timer Expired | `error_code` | #34 ✅（A′） |

---

## 8. 存量审计口径

当前 43 例均已纳入本契约：20 个正例采用 `[ip,tcp,bgp]` 纯层链；动态复制例在 case 顶层使用 `strategy_fc`，并在 `spec_json` 内用 `group_id` 绑定流序，23 个负例逐条保留可观察拒绝路径；负例只断言 `expect_error` + `error_contains`。旧归档 `_archive_36-bgp-*` 的线语义延续见本契约 §3/§7；本次不恢复归档文件、不改代码。

---

## 9. 用例集合摘要（ID 权威在 testcase §2）

存量 43 ID（20 正 + 23 负）均登记于 testcase §2；包数公式 §3.7；负例 expect 纯净（仅 `expect_error` + `error_contains`）。

---

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 规范项（§4） | 规范要求（RFC 4271，附节号） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 §4.1 | TCP 单连接，双向对等；默认端口 179（§4.1/§8） | 直连接入 + 双会话并存 | `DependsOn ["tcp"]`；FieldContract 179；多会话展开已落码 | 无（#12 补 UPDATE 多会话面） |
| 2 | 消息表 §4.2 | OPEN/UPDATE/NOTIFICATION/KEEPALIVE 四报文 + 头（§4.1–§4.5） | 建连→保活→路由通告→异常终结 | 四 builder 全落码（§1） | 无（#11 补多轮 UPDATE） |
| 3 | 状态机 §4.3 | 建连—业务—释放允许动作（§8 精简可观察版） | 乱序/缺 OPEN/重复 OPEN/NOTIF 位置 | `validateEventSequence` 全分支落码 | 无（#30–#33/#38 补 pcap 例） |
| 4 | 字段表 §4.4 | 逐字段取值/长度/端序/缺省（§3 全表） | 全属性通告/边界前缀/零 hold/非法小 hold | 大端 + 长度回填落码；1–2 以 `hold_time` 锚词拒绝 | 无（`bgp_a_neg_hold_time_small` 覆盖） |
| 5 | 错误处理 §4.5 | 错误码/异常分支（§6：6.1 头/6.2 OPEN/6.3 UPDATE/6.4 Hold/6.5 FSM/6.6 Cease） | 坏头/坏版本/坏属性/超时终结 | 头/OPEN/UPDATE/地址族落码；其余码拒 | #34 + B′（§11.2） |
| 6 | 超时与活性 §4.6 | Hold Timer（§4.2，0 或 ≥3s，协商取小）；KEEPALIVE 周期 | 长保活会话 | KEEPALIVE 报文可发；**定时器/协商不模拟** | N/A（声明式回放无定时器，§10.5 取舍） |
| 7 | NAT/代理 §4.7 | BGP 无被动模式；NAT 下四元组可变 | 多会话源端口区分 | sessions[].src_port + distinct 断言 | 无 |
| 8 | 版本/方言 §4.8 | BGP-4；MP_REACH/能力/4-octet ASN 扩展 | IPv6 transport；IPv6 NLRI（扩展） | transport 面落码；扩展面全拒 | B′（B1–B4） |

### 10.2 子表①：报文×会话状态矩阵（4×5=20 格；✅=pcap 已覆 / #数字=A′补例 ID）

| 报文＼状态 | 无 OPEN | 单 OPEN（交换不完整） | 双 OPEN 后 | NOTIF 后 | 多会话 |
|---|---|---|---|---|---|
| OPEN | ✅ T2 | #32（`exactly two`） | #30（`state`） | #30（同分支） | ✅ T9 |
| KEEPALIVE | #33（`state`） | #32（同分支） | ✅ T2 | #31（`last`） | ✅ T9 |
| UPDATE | ✅ N8 | #32（同分支） | ✅ T3（T4/T7 同格） | #31（同分支） | #12 |
| NOTIFICATION | #38（`state`） | #32（同分支） | ✅ T5 | #31（`last`） | #20 |

重数：覆 7（T2、T9×2、N8、T3、T5、#38 = 7）+ 缺 13 = 20 ✓。缺口 13 格 → 7 个 ID（#30/#31/#32/#33/#38/#12/#20，同分支合并；#32 占 4 格，#30/#31 各占 3 格）。

### 10.3 子表②：数据形态变体表（22 行）

| # | 变体 | 结论 | 证据/去向 |
|---|---|---|---|
| V1 | marker 全 `ff` | ✅ | frames hex（T2） |
| V2 | length 最小 19 / 超 4096 | ✅/A′ | T10 ✅；超限 → #35 |
| V3 | type 1–4 / 未知 | ✅ | T2–T5 + N5 |
| V4 | version=4 / ≠4 | ✅ | T2 + N6 |
| V5 | AS 2 字节 / 溢出 | ✅ | T2 + N7 |
| V6 | hold 90 / 0 / 1–2 | ✅ | T2/T6 ✅；1–2 → `bgp_a_neg_hold_time_small`（`hold_time` 锚词） |
| V7 | identifier 合法 / 非法 | ✅/A′ | T2 ✅；非法 → #36 |
| V8 | 可选参数 0 / 非零能力 | ✅/B′ | T2 ✅；能力 → B2 |
| V9 | ORIGIN 0 / 1 / 2 | ✅/A′ | 0 ✅ T3；1/2 → #13/#14 |
| V10 | AS_PATH SEQUENCE / SET | ✅/B′ | ✅ T3；SET → B5 |
| V11 | NEXT_HOP 合法 / 非法 | ✅/A′ | ✅ T3；非法 → #37 |
| V12 | MED 有值 / 缺席 | ✅ | T3 / T4 |
| V13 | LOCAL_PREF | ✅ | T3 |
| V14 | COMMUNITIES NO_EXPORT / NO_ADVERTISE | ✅/A′ | ✅ T3；→ #15 |
| V15 | withdrawn 有 / 空 | ✅ | T4 / T3 |
| V16 | NLRI /24 / /32 / /0 | ✅/立项 | ✅ T3/T7；/0 立项无 ID |
| V17 | IPv6 transport / IPv6 NLRI | ✅ | T8 / N9 |
| V18 | 多会话 / sessions==1 提升 | ✅/N/A | T9 ✅；单会话提升 pcap 不可区分（单测 `:476-499`）→ N/A 注记 |
| V19 | 空 events（connect）/ 缺省 nil（默认流） | ✅/A′ | T1 ✅；nil 默认 6 事件流（`:85-99`）→ #17 |
| V20 | wire_fault 三 kind | ✅ | N3/N4/N5 |
| V21 | 属性值超长（扩展长度） | 立项 | 单测 `:514-526`；pcap 立项无 ID |
| V22 | NOTIF 4/0 / 其他码 | ✅/A′ | T5 ✅；Cease 6 → #34 |

重数：覆 11（V1/V3/V4/V5/V6/V12/V13/V15/V17/V18/V20）+ 缺 9 行（V2→#35、V7→#36、V9→#13/#14、V11→#37、V14→#15、V16→立项无 ID、V19→#17、V21→立项无 ID、V22→#34）+ B′ 2 行（V8/V10）= 22 ✓。

### 10.4 关联关系专节（§3.8–3.10）

BGP 单 TCP 连接内无派生数据/媒体流——**无 `driven_by` 关联，不适用**（诚实声明，非缺口）。多会话（`sessions[]`）是**多会话展开**（整块回放：session[0] 全流程跑完再跑 session[1]，包号续接；术语表定义），不是并发交错（`concurrent` 面不适用，无该键）。时间线：会内严格顺序（状态机强制）/ 多会话整块 / 多流（`flows=N`）并发（9.39 互斥：`flows>1` 时四元组须动态化，见 §12）。

### 10.5 候选方案对比（§4.17）与三路对照（§4.12–4.15）

| 走法（真实存在） | 来源 | 优劣 | 结论 |
|---|---|---|---|
| A 事件面显式回放（本契约） | 本仓库已落码（`layer_gen.go`；postgresql/tns/mongodb 同款 P0a 模式） | 简单确定；不模拟定时器/收敛 | ✅ 采用 |
| B 路由器 FSM 全仿真（含定时器/重传/碰撞检测 RFC §8/§6.8） | FRR `bgpd`（`bgp_open.c`/`bgp_packet.c`，github FRRouting/frr master） | 真实但复杂度/非确定性超出生成器定位 | ❌（定位不符；需求是可复现流量） |
| C pcap 回放 | 框架 replay 模式 | 零编码成本；不可参数化 | ❌（要逐流动态与故障注入） |

三路对照结论：规范（RFC 4271 全文）定底线；现网（Cisco 默认 hold 180/keepalive 60 协商取小——cisco社区/noction 口径；JunOS 默认 hold 90/keepalive 30——juniper 文档口径；FRR OPEN 带能力——frr 文档口径）定"真跑面"；开源实现（FRR bgpd）定走法参照。不一致点：现网定时器协商 vs 生成器无定时器 → 取舍：**事件全显式，hold 值只作字节面**（T2 用 90、T6 用 0 覆盖两档语义；180/60 默认值不硬编码，无需 case）。

### 10.6 子表③：商业行为→用例映射表（6 行）

| # | 商业行为（出处） | 映射 | 结论 |
|---|---|---|---|
| C1 | TCP/179 固定对等（Cisco/FRR 文档） | T1 | ✅ |
| C2 | hold 协商取小、0 合法（RFC §4.2；Cisco/JunOS 文档） | T2/T6（显式两档） | ✅（协商过程 N/A，见 C-注记） |
| C3 | keepalive 周期发送（现网定时器） | — | N/A（无定时器；KEEPALIVE 只作显式事件） |
| C4 | OPEN 携带能力（FRR bgpd） | — | B′（B2） |
| C5 | identifier = Router-ID（IPv4 语义） | T2/T8 | ✅ |
| C6 | 现网 4-octet ASN（AS_TRANS） | — | B′（B3） |

重数：覆 3 + N/A 1 + B′ 2 = 6 ✓。

---

## 11. P2 D-BGP-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

### 11.1 文件清单（P4 动作，**本轨道不执行**）

1. `trafficgen/internal/core/types.go`（`BGPConfig/BGPEvent/BGPUpdateAttributes/BGPSession :92-140`；`FlowSpec.BGP :1681`）——增事件键时改。
2. `trafficgen/internal/protocol/bgp/builder.go` ——报文编码 + 顶层/事件校验（G-BGP-7：今日 hold 1–2 在 **`bgp_a_neg_hold_time_small`** 以 `hold_time` 锚词拒绝，已在 cases 落例；若后续校验收紧需同步更新该例锚词）。
3. `trafficgen/internal/protocol/bgp/planner.go` ——状态机 + legacy Plan（回归面，不动）。
4. `trafficgen/internal/protocol/bgp/layer_gen.go` ——链路生成器（不动；事件源切换见 5）。
5. `trafficgen/internal/core/layers/registry.go` ——`Fields` 已增 `events`/`sessions`（G-BGP-5① closed，`registry.go:1357-1379`；P1 写作时 1012）。
6. `trafficgen/internal/core/layers/chain_planner_translate.go` ——增 `case "bgp"`（JSON 往返解码层 config → `spec.BGP`；G-BGP-5②；postgresql `:2006` 先例）+ drive `Meta.BGP` 已就绪（`:114`，不动）。
7. `trafficgen/internal/core/strategy_convert.go` ——`CheckProtoFlat` 增 `bgp` presence 分支（G-BGP-6；dns/mqtt 先例）。
8. `trafficgen/test/protocol_pcap/cases/bgp.json` ——43 例已对齐 §12.1；后续增删例须同步更新 testcase §2 与本契约 §12.1 机读行。
9. `trafficgen/tools/coverage_gate.py` ——若有 `check_<proto>` 登记制，B 轨认领（门2 出口 0）。

### 11.2 接口签名（示意，P4 落码钉死）

`BuildOpen(*BGPConfig) / BuildKeepalive() / BuildEvent(BGPEvent) / BuildUpdate(*BGPEvent) / BuildNotification(*BGPEvent) / ValidateConfig / validateEventConfig / validateUpdateEvent / validateIPv4Prefix / encodePrefix / encodeAttributes / appendPathAttr / (Planner).Validate+Plan / (BGPGenerator).Generate` ——现状签名即契约（`builder.go`/`planner.go`/`layer_gen.go` 行号见 §1）；新增 = translate 侧 JSON 解码（无新 wire 接口）。

### 11.3 数据结构（现状 + 扩展）

现状 `types.go:92-140`（14 键 config / 12 键 event / 6 键 attributes / 2 键 session）。扩展：registry `Fields` += `events`（list）/`sessions`（list）+ translate 解码复用同一 struct（零新 struct）。

### 11.4 主流程

`ValidateSpec`（端口契约补 179）→ `translateTerminalConfig`（G-BGP-5 后：层 config → `spec.BGP`）→ `drive`（`Meta.BGP` 直传）→ `BGPGenerator.Generate`（`validateSessionConfig` → 逐 session `emitEvents` → `BuildEvent`）→ tcp 层封套（握手/分段/挥手）→ pcap/NIC。

### 11.5 错误分支（§5.2）

§7 十四行逐行：校验层拒（`ValidateConfig/validateEventConfig/validateEventSequence`）→ `Generate` 返回 err → 任务错误终态。`wire_fault` 永不产字节。hold 小值分支由 `bgp_a_neg_hold_time_small` 覆盖。

### 11.6 性能边界（§6.1–6.8 摘要，详见本契约 §6）

单报文 ≤4096（硬拒）；单流 O(1) 内存；事件数常规 ≤10；吞吐待 P4 基准。

### 11.7 与现有逻辑的冲突点（§8.7）

- 层翻译在 `chain_planner_translate.go:791` 走严格 JSON 往返，与其他协议本地块无键冲突。
- `FlowSpec.BGP` 接收端：`Meta :114` + `mapToFlowSpec :1661-1667`；层翻译与 presence 门（`strategy_convert.go:8750-8755`）配合收敛为"层优先、flat 判死"。
- `validateBaseDstPortHandled` 未含 bgp——通用契约块生效中，不动。

### 11.8 回滚方式（§8.8）

registry/translate/CheckProtoFlat 三处独立提交；任一处回滚都视为回归事故：cases 43 例的 `bgp_neg_presence_top_level_bgp`、静态复制门和正例层链会先红。回滚前先把受影响的例号登记到本契约 §14。

---

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

> 证据三选一（§15.2）：文档章节 / 代码行 / 用例号。写不出 = 缺口立项，不许空着。

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 正例 20/20 为纯 `[ip,tcp,bgp]` 层链；顶层业务/承载键仅在 5 个判死负例中按门验证；目标 spec_json 样例见 §2.1 | 本契约 §2.1 + §12.1；`cases/bgp.json` 机读 |
| §2 策略/任务 | 策略 = 单 bgp 流量模板；数量由 case 级 `strategy_fc` 承载（flows/bps/time）；任务 = 多策略合跑 + 总量封顶（父桶）；框架语义未动（bgp 不在 worker/task 特判名单） | `internal/core/worker.go:307-316`；本契约 §2.1 |
| §3 五件套 | 见 §12.3 强制展开：会话表（s1/s2 无派生流声明）/ 事务序列（t1–t4 四件事）/ 关联关系（无 driven_by，§10.4）/ 插入位置（终结层）/ 时间线（会内顺序 + 多会话整块 + 多流并发）。**有长连接载体，不豁免** | 本契约 §12.3 + §10.4；T9 |
| §4 查规范 | RFC 4271（§4/§5/§6/§8/§9 节号级，无二手解读）+ RFC 2545（传输）+ RFC 4760/5492/6793（B′边界）；TShark 3.6.14 `bgp.*` 784 字段实测；八项矩阵 + 子表①②③ + 候选对比 | 本契约 §3/§10 |
| §5 依赖与错误 | 依赖 = `DependsOn ["tcp"]`（`registry.go:1357`）；端口契约 179；`wire_fault` 3 kind + §7 十四行；失败传 task error（零假成功） | 本契约 §5/§7/§11.5 |
| §6 性能 | 见本契约 §6（6.1–6.8 要素）：逐事件流式、单 flow O(1)、无锁无共享；pcap/NIC 双路（NIC=`enp135s0f0np0`）；吞吐标「待 P4 基准」 | 本契约 §6 |
| §7 三份文档 | `design.md` + `testcase.md`（本目录）+ D-BGP-1（本契约 §11，门1 获批 = 定稿）+ T-BGP（testcase §2，43 ID）+ generated schema（`layers.bgp` 已有，不新增层） | 修订记录 |
| §8 设计先行 | 本条目先于实现；门1 获批 = D-BGP-1 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = RFC 4271 条款（§3/§10 逐表列节号）+ D-BGP-1（§11）+ 已确认现网行为（Cisco/JunOS/FRR 口径见 §10.5/③）；43 ID 逐项回指；用例去向见 testcase §8 | `testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 `/tmp/pipe/80-bgp/p123-report.md` §3）+ 收官隔离复审 + 修轮；红先绿后 | 报告 §3 |
| §11 白话 | 汇报首句先行白话结论 | 报告 §0 |
| §12 动态清单 | 见 §12.12 强制展开：四元组 = `ip`/`tcp` 层（当前实测开放 fixed/inc/rand；allowlist `layer_dyn.go:17-21`；`bgp` 不在 allowlist → 业务字段对象必拒）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | 本契约 §12.12 |
| §13 schema 派生 | `bgp` 已在 registry 注册（`registry.go:1357-1379`，13 键；generated `layers.bgp` 含 field_contract 179；**不新增层**）；`allowedProtocols["bgp"]`（`protocols.go:22`）；`main.go:500` 已注册 ChainPlanner；**P4 改 registry `Fields` 必须重跑 schemagen**（§13.18/13.19） | 本契约 §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `bgp.*` + frames hex 双通道 → 先跑后钉（§9.31/§14.20）；pcap 落 `/tmp/mcp-pcaps/bgp/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-26）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 纯净 |
|---|---:|---|---|---|
| `cases/bgp.json` | 43 | 正例 `{layers}` ×19 + `{layers,group_id}` ×1；动态例另有 case 级 `strategy_fc`；负例白名单/流控故障另带结构键 | 正例 `[ip,tcp,bgp]` ×20；`bgp_neg_udp` 为 `[ip,udp,bgp]` 载体负例 | ✅ 23/23 只有 `expect_error` + `error_contains` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 当前出现例数 | 去向/门 |
|---|---:|---|
| `src_ip` / `dst_ip` | 正例 0；负例无合法扁平形 | `layers[i].ip.src/dst` |
| `src_port` | 正例 0；会话源端口住 `tcp` 层或 `bgp.sessions[]` 业务编排 | `layers[i].tcp.src_port` |
| `dst_port` | 正例 0；179 由 FieldContract 补齐 | `layers[i].tcp.dst_port`（显式才写） |
| `count` | 1（`bgp_neg_flat_count`） | 负例仅守门；正例数量走 `strategy_fc` |
| 顶层 `bgp` 子映射 | 1（`bgp_neg_presence_top_level_bgp`） | 负例仅守门；正例事件住 `layers[].bgp` |
| `src_mac` | 1（`bgp_neg_stray_src_mac`） | 负例仅守门；正例不出现 |
| 缺 `ip` 层 | 0 个正例 | 正例统一 `[ip,tcp,bgp]`；`bgp_neg_udp` 是 `[ip,udp,bgp]` 载体负例 |

**结论**：当前 20 个正例已通过层链迁移门；5 个负例（39–43）分别守顶层协议、平坦数量、游离 MAC、静态复制和 hold-time 边界。数量例的 `strategy_fc` 是 case 级流控，不属于 `spec_json` 顶层旧键。

目标形状样例见 §2.1（顶层仅 `layers` + 结构性数量键；`bgp` 层内 `events`/`sessions` 已接线）。

### 12.3 §3 强制展开：五件套

**会话表**：

| 会话 | 四元组 | 生命周期 | 用例 |
|---|---|---|---|
| `s1`（单会话基线） | `ip.src/dst` + `tcp.(src)→179` | SYN 三握 → OPEN×2 → KA/UPDATE* → [NOTIF] → FIN 四way | T1–T8/T10 |
| `s2`（多会话展开） | 第二 `sessions[].src_port`，独立四元组 | 与 s1 完全独立的握手→事件→挥手；**整块回放不交错** | T9/#12/#20 |

**事务序列（单事务四件事 §3.4–3.7）**：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| `t1` 建连+OPEN 交换 | TCP 握手完成 | c2s OPEN → s2c OPEN | Established（双 OPEN 齐） | OPEN 缺/错位 → 任务 error（`state`/`exactly two`） |
| `t2` 保活/通告 | `t1` Established | KA / UPDATE（含属性+NLRI） | 会话继续 | 乱序事件 → error；坏属性 → error |
| `t3` 异常终结 | `t1` Established | s2c NOTIFICATION(4/0) | TCP 挥手 | NOTIF 位置错 → error（`last`） |
| `t4` 正常终结 | 任意 Established 态 | 无应用事件（connect）或事件跑完 | TCP 挥手 | RST（tcp 层能力，A′ 后半） |

**关联关系（§3.8–3.10）**：见 §10.4——**无派生流**，无 `driven_by`；不许用"同一模板连续重复发射"冒充编排（§3.13；多轮 UPDATE 必须 #11 真多事件）。

**插入位置**：终结层（`CategoryTerminal`，`DependsOn ["tcp"]`）——BGP 报文直接落 TCP payload；链上无中间层。

**时间线**：单会话严格顺序；多会话整块顺序；多流并发（`flows=N` 跨流不假设包序）。无分片让位面；无中插动作（BGP 无 ABOR/STAT 类）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组（`ip`/`tcp` 层，当前已实测开放的策略）**：

| 字段 | 住处 | 开策略 | 依据 |
|---|---|---|---|
| `src`（src_ip） | `ip` 层 | fixed/inc/rand 已实测；list 由 `checkDynShape` 支持但当前无 BGP 专用例（G-BGP-10）；pattern 在 IP/端口类型上明确拒绝（G-BGP-11） | allowlist `layer_dyn.go:18`，策略分支 `:478-506` |
| `dst`（dst_ip） | `ip` 层 | fixed/inc/rand 已实测；list 由 `checkDynShape` 支持但当前无 BGP 专用例（G-BGP-10）；pattern 在 IP/端口类型上明确拒绝（G-BGP-11） | 同上 |
| `src_port` | `tcp` 层 | fixed/inc/rand 已实测；list 由 `checkDynShape` 支持但当前无 BGP 专用例（G-BGP-10）；pattern 明确拒绝（G-BGP-11）；未写动态时保底 `12345+i`（`worker.go:307-308`，`DefaultSrcPort=12345`，`strategy_convert.go:49`） | allowlist `layer_dyn.go:19`，策略分支 `:478-506` |
| `dst_port` | `tcp` 层 | fixed/inc/rand 已实测；list 由 `checkDynShape` 支持但当前无 BGP 专用例（G-BGP-10）；pattern 明确拒绝（G-BGP-11）；179 契约下动态值≠179 仍可跑（用户显式优先，`chain_planner.go:607-620`） | 同上 + 端口契约 |

**业务字段（`bgp` 层/事件内，逐个列开/不开 + 理由）**：

| 字段 | 开 | 理由 |
|---|---|---|
| `wire_profile` | ❌ 关 | 模板选择器，逐流变无业务意义 |
| `transport` | ❌ 关 | 载体选择器（同 h323 判例"结构选择器"） |
| `events[]`/`sessions[]` 整块 | ❌ 关 | 会话剧本；逐流变等价多套剧本，应由多策略表达（§2.2） |
| `version`/`my_as`/`hold_time`/`identifier` | ❌ 关 | 会话身份面；且 `bgp` 不在动态 allowlist，对象即 `does not support dynamic`——逐流多 AS/多标识需求列为独立 profile 立项 |
| `nlri`/`withdrawn_prefixes`/`attributes` | ❌ 关 | 业务剧本字段逐流变会破坏用例原子性；若需动态路由模板，新增 profile 立项 |
| `error_code`/`subcode` | ❌ 关 | 负例语义，逐流变破坏用例原子性 |
| `wire_fault` | ❌ 关 | 负例唯一注入口，非业务字段 |

**序号算法代码位置（实读，不编行号——§5.7）**：`layer_dyn.go:78` `parseLayerDyn` → `:369` `checkDynShape` → `:770` `resolveLayerTuple(spec,i)`（`worker.go:316` 调用，保底自增 `:307-308` 在前，动态覆盖在后）；值算法 `tuple_generator.go:26` `Next(index)`（inc 回绕 `:164`；rand 可复现 `:181` seed+index；端口 `:194`；单值解析 `:290/:300/:310`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- **①层链+顶层空子映射并存**：`{"layers":[…],"bgp":{}}` 由 `CheckProtoFlat` bgp presence 分支拒绝（`strategy_convert.go:8750-8755`）→ 守例 `bgp_neg_presence_top_level_bgp`。
- **②白名单外游离键判死（1.11–1.13）**：顶层 `src_mac`（`bgp_neg_stray_src_mac`）、`count`（`bgp_neg_flat_count`）各有守例。
- **③一切负例 `expect_error` 带错误锚词**：23 负例逐条锚词见 testcase §2 索引与 §4。
- **④收官自查行**：「非负例顶层键 = 0」——正例 20/20 的 `spec_json` 只有 `layers`；动态例的 `group_id` 位于 `spec_json` 的结构性绑定键，`strategy_fc` 位于 case 顶层流控白名单。
- **载体负例**：`[ip,udp,bgp]`（N1，锚词 `tcp`）。

---

## 13. P3 对接清单（T-BGP 草稿输入；正文落 testcase 文件）

43 ID（20 正 + 23 负）→ testcase §2；§3.15 三项→ testcase §6.1；A′/B′→ testcase §6.2；§9.50 复合大场景→ testcase §6.5；规范行对账→ testcase §5.2。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-BGP-1…G-BGP-4 | 当前没有对应未决项；编号本身不构成能力声明或覆盖统计项 | 发现具体缺口时新增完整条目，不以空号代替缺口描述 |
| G-BGP-5 | ~~`events`/`sessions` 进 `bgp` 层~~ 已完成：registry 增键 + translate 严格 JSON 往返 + cases 正例全量迁入 | 已由 43 例正/负契约覆盖；后续只做回归维护 |
| G-BGP-6 | ~~`CheckProtoFlat` 无 `bgp` presence 分支~~ 已完成：顶层 `bgp` 子映射拒绝，游离键/静态复制门由负例守护 | `bgp_neg_presence_top_level_bgp`、`bgp_neg_flat_count`、`bgp_neg_stray_src_mac`、`bgp_neg_static_copy_multiflow` |
| G-BGP-7 | hold_time 1–2 已由现有校验以 `hold_time` 锚词拒绝；`bgp_a_neg_hold_time_small` 已纳入 43 例 | 若实现文案变化，先更新该负例锚词再合并 |
| G-BGP-8 | RFC 4271 prefix length 0 当前拒绝，但缺少专用 cases 负例 | 增加 `expect_error` + `error_contains: "prefix length"` 的专用负例；在补例前不计入已覆行 |
| G-BGP-9 | RFC 4271 扩展长度属性当前拒绝，但缺少专用 cases 负例 | 增加 `expect_error` + `error_contains: "extended-length"` 的专用负例；在补例前不计入已覆行 |
| G-BGP-10 | `ip.src`/`ip.dst`/`tcp.src_port`/`tcp.dst_port` 的 `list` 策略由通用校验支持，但当前没有 BGP 专用正例 | 增加一例 BGP 动态 `list` 覆盖并核对四元组展开结果；补例前不计入 BGP 动态覆盖 |
| G-BGP-11 | IP/端口字段的 `pattern` 策略由通用校验明确拒绝，但当前没有 BGP 专用负例 | 增加一例 BGP `pattern` 负例并固定 `pattern strategy is not supported` 锚词；补例前不计入 BGP 动态拒绝覆盖 |
| B1–B5 | MP_REACH / 能力 / 4-octet ASN / refresh-graceful-auth-MD5 / AS_SET+扩展长度 | B′：当前 profile 未纳入；按 RFC 4760/5492/6793 建立独立 profile 立项，新增后补对应正/负例。（RFC 4760/5492/6793；testcase §6.2） |

- v1.1.1（2026-10-01，独立终审 M1/M2/M3 回填）：registry 行号更新至 `1357-1379`；数量承载与已实测动态策略表述对齐现状；未运行 suite、服务或 MCP。
- v1.0.0（2026-09-26）：P1–P3 初稿。旧基线 36-bgp-* 逐节比对延续；RFC 4271 三路对照（Cisco/JunOS/FRR 口径）；P1 矩阵 8+20+22+6；P2 D-BGP-1 八要素；门1 十四行齐；缺口 G-BGP-5/6/7 + B1–B5。

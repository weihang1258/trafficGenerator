# OSPF（开放最短路径优先）v2 设计契约

> 版本：v2.0.0（P1–P3 完整产物）
> 日期：2026-09-27
> 状态：P1 八项规范矩阵（§13）+ 三子表 + 三路对照与候选方案对比（§13.4/§13.5）+ 门1 §1–§14 十四行表（§14，§1/§3/§12 强制展开）+ P2 D-OSPF-1 代码设计草稿（§15）+ P3 对接清单与缺口立项（§16/§17）已落盘；**`ospf` 层已注册、builder/planner/generator 已落码**（`registry.go:940`，`internal/protocol/ospf/` 四文件共 905 行，15 个单元测试函数），但 20 例存量仍为旧扁平形、D-OSPF-1 未定稿——P4 落码前以门1 获批版为准，不宣称当前 suite 可运行。本契约不修改 Go 实现。
> 配套文件：`docs/protocol-designs/83-ospf-testcase.md`、`trafficgen/test/protocol_pcap/cases/ospf.json`
> 规范基线：RFC 2328（OSPFv2）；IPv4 直接承载 Protocol 89。RFC 5340（OSPFv3）仅为独立边界。
> 旧基线：`docs/protocol-designs/37-ospf-design.md` v1.0.0（设计阶段口径"层尚未实现"已按实测更正，逐条核对见 §18.2）。
> **层链唯一真相**：本契约目标形状只有纯 `layers` 形（`[ip,ospf]`，raw-IP 直挂、无传输层、无端口语义）+ 兄弟键 `strategy_fc` 走数量；存量 20 例的顶层扁平键随 P4 按 §14.1 去向表改写。

## 1. 范围、证据等级与 profile 边界

本版定义 RFC 2328 的 OSPFv2（OSPF 第 2 版）IPv4 profile（档案）。OSPFv2 直接封装在 IPv4 中，IP Protocol（协议号）为 **89**；它没有 TCP/UDP 端口。本文覆盖五类 OSPFv2 packet（报文）：Hello、Database Description（DBD，数据库描述）、Link State Request（LSR，链路状态请求）、Link State Update（LSU，链路状态更新）和 Link State Acknowledgment（LSAck，链路状态确认）。

| 证据等级 | 本版固定内容 | 不在本版伪造的内容 |
|---|---|---|
| IPv4 载体 | IPv4、Protocol=89、Router ID、Area ID、TTL、单播/224.0.0.5/224.0.0.6 目的地址 | 真实邻接、路由收敛或网卡可达性 |
| OSPFv2 公共头 | Version=2、Type、Packet Length、Router ID、Area ID、Checksum、AuType 和 8 字节 Authentication 字段的位置/宽度/网络字节序 | 未声明的认证算法、密钥或线上邻居状态 |
| Hello | 网络掩码、Hello/Dead interval、Options、优先级、DR/BDR 和邻居 Router ID 列表 | 由实现自行决定的选举结果；用例显式提供 DR/BDR |
| DBD | Interface MTU、Options、I/M/MS 标志、DD sequence 和 LSA header 列表 | 未配置的数据库摘要或隐式邻居事件 |
| LSR/LSU/LSAck | 请求三元组、LSA header、Router-LSA/Network-LSA 的基本 body 和长度 | 外部路由、AS-external/opaque/扩展 LSA 的未声明字段 |
| RFC 5340 profile | 仅作为独立 IPv6 边界说明 | 不把 OSPFv2 的 IPv4 头、IPv4 checksum 或 LSA body 复制成 OSPFv3 |

`rfc2328_ipv4` 是本版唯一的正例 wire profile（线格式档案）名。RFC 5340 OSPFv3（IPv6 OSPF）需要独立的 `rfc5340_ipv6` profile：其 IPv6 pseudo-header/checksum 处理、Instance ID、认证/安全扩展和 LSA 语义不能由本版 OSPFv2 默认化。`ospf_ipv6_rfc5340_boundary` 只验证该 profile 边界，不宣称生成 OSPFv3 正例；`ospf_neg_ipv6_v2` 明确拒绝用 `rfc2328_ipv4` 伪装 IPv6。

不变式：

1. OSPFv2 只能位于 IPv4 后，IPv4 Protocol 必须是 89；UDP/TCP 载体、缺 IPv4 或不完整层链拒绝。
2. OSPF 公共头固定为 24 字节，`packet_length` 包含公共头和 OSPF body，按编码字节数回填，最小值为 24。
3. OSPFv2 的 checksum 是 OSPF packet 的 16-bit ones-complement checksum（不含 IPv4 header checksum，且计算排除 8-byte Authentication 字段——实现 `builder.go:70` `buildMessage`）；`AuType=0` 时 Authentication 字段仍占 8 字节并填充为零值。LSA checksum 与 OSPF packet checksum 用**同一** RFC 1071 风格 `checksum()` 函数（`builder.go:38`；`buildLSA :107-124` 先清零 LSA header checksum 字节再对整 LSA 求和）——v1 底稿"Fletcher-16"表述作废（§10 裁定）。
4. Router ID 和 Area ID 都是 4 字节 IPv4 格式标识；它们不是根据 `src_ip`、`dst_ip` 或 multicast（组播）地址自动猜测。
5. LSA header 固定 20 字节；其中 LSA `length` 包含该 LSA 自身的 20 字节 header。OSPF packet 的 `packet_length` 还必须包含 LSU 的 4 字节 LSA count。
6. Hello、DBD、LSR、LSU、LSAck 的事件必须原子化；planner（规划器）不得偷偷补发响应或把邻居状态变成额外报文。
7. planner/validator（校验器）失败必须传播到 task error（任务错误）终态，不能"完成但 0 包"。
8. OSPFv2 的默认 TTL 为 1；组播 Hello 使用 224.0.0.5，DR/BDR 相关 LSU/LSAck 可以显式使用 224.0.0.6。TTL、目的地址和单播/组播行为必须由配置或 profile 明确。

**已注册/已落码现状（P1 实测，行号真实）**：`ospf` 终结层已注册（`registry.go:940`，`CategoryTerminal + DependsOn ["ip"]`，`FieldContract {"ip.protocol": "89"}`，注释 `registry.go:933-935` P3 T5 raw-IP 链，RFC 2328 注记 `:941`）；配置结构 `OSPFConfig`（`routing.go:66-90` 23 键）/`OSPFEvent`（`:143-164` 19 键，`neighbor_state` 仅携带不消费——§10 诚实声明）/`OSPFWireFault`（`:166-169` 2 键）+ `OSPFDDFlags`（`:93`）/`OSPFLSAHeader`（`:100`）/`OSPFLink`（`:112`）/`OSPFLSA`（`:120`）/`OSPFRequest`（`:136`）；wire 编码 `internal/protocol/ospf/builder.go`（264 行：`packetTypeFromString :21` 五分支、未知拒 `:34`；`checksum :38` RFC 1071；`ospfHeader :53`；`buildMessage :70`；`buildLSAHeader :92`；`buildLSA :107`；`parseSequence :126`；`buildHelloBody :146`；`buildDDBody :165`；`flagsByte :181`；Type 常量 `1..5 :13-17`）；planner/validator `internal/protocol/ospf/planner.go`（109 行：`Validate :17`；锚词行见 §7 表）；终结层生成器 `internal/protocol/ospf/layer_gen.go`（261 行：`Generate :20` 空 `Emit` 拒、无 events 时空 `packet_type` 仍可走默认 hello `:27`；单报文 `buildFromConfig :109`；事件序 `cfg2` 继承 RouterID/AreaID `:61-69` + `buildFromEvent :171`；`kindToType :228`；`multiDstFor :244` 恒 `224.0.0.5`；`dirName :251`；双注册 `:258-259` 生成器+校验器）；白名单已登记（`protocols.go:46`）；顶层 `ospf` 子映射解析（`strategy_convert.go:730-732`，`parseSubconfigJSON` 普通 `json.Unmarshal` 无 `DisallowUnknownFields`）；`Meta.OSPF` 直传（`chain_planner.go:1369` / `chain_planner_translate.go:168` / `generator.go:492`）；raw-IP 自驱（`isRawIPChain :54-57` 含 `ospf`，`:40-51` 链中夹 tcp/udp 即否；`transportProtocol :227/:241` 末层/倒二层看 `ospf`→`ProtocolOSPF`）；`ProtocolOSPF=89`（`core/builder.go:64`）；生成表含 `ospf`（`layers.generated.json:2526`，`depends_on ["ip"]`，`field_contract ip.protocol=89`，`fields {}`——业务键走 `OSPFConfig` 经 FlowMeta 直传，见 §15 接线件）；单元测试 15 个（`ospf_test.go` 271 行）。`layers[]` 空条目 `{"ospf":{}}` 走默认 hello（`layer_gen.go:27`，P0b-2 口径），无握手无保活语义。

## 2. 层链、载体与公共配置（存量形状声明，P1 实测不美化）

**存量 20 例 `spec_json` 实测形状（2026-09-27，`cases/ospf.json` 1729 行）**：`layers` 20/20 为 `[{"ip":{}},{"ospf":{}}]` 空条目（链形已对、无层内值）；顶层键两种形状：18 例 `count/dst_ip/layers/ospf/src_ip/ttl` + 2 例 `count/dst_ip/layers/ospf/src_ip`（`ospf_neg_ipv6_v2` 与 `ospf_ipv6_rfc5340_boundary` 无 `ttl`，其 src/dst 为 v6 地址——拒绝触发源，见 §14.1）；`ospf` 子映射正例 12/12 含 `version/profile/packet_type/router_id/area_id/auth_type/checksum_mode` + 按报文类附加键（Hello 类 +`network_mask/hello_interval/dead_interval/options/priority/designated_router/backup_designated_router/neighbors`；DBD 类 +`interface_mtu/flags/dd_sequence/lsa_headers/options`；LSR 类 +`requests`；LSU 类 +`lsas`；LSAck 类 +`lsa_headers`；#10 为 `events[6]`）；20/20 **全缺 `flow_control`/`strategy_fc`**（数量全靠 `count=1` 顶层旧键：20/20 `count=1`）。旧扁平形，P4 按 §14.1 去向表逐例改写，不搬运旧期望值（先跑后钉）。

**正例 `expect` 实测**：12 正例 `directional` 11 例 `false` + 1 例 `true`（仅 #10 六事件邻接交换为 `true`——逐包断言方向面）；`has_payload` 12/12 `true`；`has_handshake` 0/20（raw-IP 族诚实口径，无连接无握手）；`terminates` 0/20；`notes` 12/12。`frames` 17 帧全 offset 34：`02 01 00 30`（Hello 单邻居 48B）/ `02 01 00 34`（Hello 双邻居 52B）/ `02 01 00 2c`（Hello 无邻居 44B，#11）/ `02 02 00 34`×2（DBD master/slave）/ `02 03 00 24`×2（LSR）/ `02 04 00 40`×2（LSU Router-LSA，#7/#12）/ `02 04 00 3c`（LSU Network-LSA）/ `02 05 00 40`（LSAck）+ #10 六事件短前缀 `02 01/02/02/03/04/05`，与 §3 Type/长度表逐值一致。

目标层链为 `ip → ospf`（raw-IP 直挂）。以下字段是设计配置（旧扁平形样例，P4 按 §14.1 改写为纯 layers 形——地址/TTL 进 `layers[0].ip`、业务进 `layers[1].ospf`、数量走兄弟键 `strategy_fc`）：

```json
{
  "layers": [{"ip": {}}, {"ospf": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "224.0.0.5",
  "ttl": 1,
  "ospf": {
    "version": 2,
    "profile": "rfc2328_ipv4",
    "router_id": "1.1.1.1",
    "area_id": "0.0.0.0",
    "packet_type": "hello",
    "checksum_mode": "auto"
  }
}
```

`ospf` 是 IPv4 terminal（终结层），不是 TCP/UDP terminal。单报文用 `packet_type` 及对应字段，多报文邻接场景用有序 `events`（`neighbor_state` 为 session 可观察语义携带，不进线——§10）。

| 键 | 类型 | 约束 | 语义 |
|---|---|---|---|
| `version` | uint8 | 正例为 `2` | OSPF 版本；与 profile 和 IPv4 载体绑定 |
| `profile` | string | `rfc2328_ipv4`；RFC 5340 另行注册 | 版本化编码选择，不直接写入 wire（线格式） |
| `packet_type` | enum | `hello`、`db_description`、`link_state_request`、`link_state_update`、`link_state_acknowledgment` | 五种 OSPFv2 报文 |
| `router_id` | IPv4 string | 必填且格式有效 | OSPF Router ID，4 字节 |
| `area_id` | IPv4 string | 必填且格式有效 | Area ID，4 字节；普通区域可为 `0.0.0.0` |
| `checksum_mode` | enum | `auto`/`invalid`/`zero`/`bad`（空=auto） | 根据最终 OSPF 字节计算 checksum；后三者为错误/零注入（实现单测面，存量用例仅用 `auto`） |
| `auth_type` | uint16 | `0` 为无认证 | AuType；Authentication 始终保留 8 字节 |
| `network_mask` | IPv4 string | 仅 Hello | 接口网络掩码 |
| `hello_interval` | uint16 | 仅 Hello，非负 | 秒 |
| `dead_interval` | uint32 | 仅 Hello，非负 | 秒 |
| `options` | uint8 | 仅 Hello/DBD | OSPF Options |
| `priority` | uint8 | 仅 Hello | DR/BDR 选举优先级 |
| `designated_router` | IPv4 string | 仅 Hello | DR 接口地址；未选举时可为 `0.0.0.0` |
| `backup_designated_router` | IPv4 string | 仅 Hello | BDR 接口地址；未选举时可为 `0.0.0.0` |
| `neighbors` | IPv4 array | 仅 Hello | 已知邻居 Router ID，逐个 4 字节编码 |
| `interface_mtu` | uint16 | 仅 DBD | 接口 MTU |
| `flags` | object | 仅 DBD | `init`/`more`/`master` 三个标志 |
| `dd_sequence` | uint32 | 仅 DBD | Database Description sequence |
| `requests` | array | 仅 LSR | 每项为 `lsa_type`、`link_state_id`、`advertising_router` |
| `lsas` | array | 仅 LSU | LSA 完整 body；本版基本支持 Router/Network LSA |
| `lsa_headers` | array | DBD/LSAck | 每项 20 字节 LSA header |
| `wire_fault` | object | 仅负例 | planner 边界注入（`carrier/declared_length/area_id` 三值实证），不代表合法线上报文 |
| `events` | array | 多事件场景 | 每项带 `kind`、方向和该报文字段；按顺序发送 |

### 2.1 方向、邻接状态和事件

每个事件可以显式给出 `direction`（`c2s` 或 `s2c`）与 `neighbor_state`。状态是 session（会话）可观察语义，不替代 wire 字段：

```text
Down → Init → ExStart → Exchange → Loading → Full
```

本版的 `ospf_neighbor_full_exchange` 将 Hello、DBD、LSR、LSU、LSAck 拆成六个原子事件，显式观察 Init、ExStart、Exchange、Loading、Full；实现不得把"到达 Full"编码成一个不存在的 OSPF 报文。真实邻接状态机还包括 2-Way、Attempt、退邻接和重传定时器，它们不在单个静态 PCAP（抓包文件）契约中自动推断。**`neighbor_state` 不进线**：`buildFromEvent`（`layer_gen.go:171-226`）只读事件的报文类字段，`NeighborState` 全库零消费（§10 诚实声明）。

## 3. OSPFv2 公共头和校验

### 3.1 公共头

IPv4 无 option 时 OSPF payload（载荷）起点为 `offset 34 = Ethernet 14 + IPv4 20`；启用 VLAN/IP option 时必须使用实际 header length。公共头按网络字节序为：

```text
byte 0       Version = 2
byte 1       Type = 1..5
byte 2..3    Packet Length（包含 24 字节公共头）
byte 4..7    Router ID
byte 8..11   Area ID
byte 12..13  Checksum
byte 14..15  AuType
byte 16..23  Authentication（8 字节）
byte 24..    Body
```

Type 定义（实现常量 `builder.go:13-17`）：

| Type | 名称 | 本版 body |
|---:|---|---|
| 1 | Hello | 网络掩码、计时器、Options、优先级、DR/BDR、邻居列表 |
| 2 | Database Description | MTU、Options、I/M/MS、DD sequence、LSA headers |
| 3 | Link State Request | LSA type、LSID、advertising Router ID 三元组 |
| 4 | Link State Update | LSA count + 完整 LSA |
| 5 | Link State Acknowledgment | 一个或多个 LSA header |

### 3.2 Checksum 和长度规则

`checksum_mode=auto` 时编码器先构造 Version/Type/Length/Router ID/Area ID/AuType/Authentication/body，再按 RFC 2328 的 OSPF packet checksum 规则计算并回填公共头 checksum；计算范围排除 8-byte Authentication 字段。用例只将 packet checksum 作为非零可观察值；不会把某个 IP、时间戳或实现版本的常数 checksum 当成跨样本事实。`AuType=0` 的 Authentication 是 8 字节保留字段，不可缩短公共头。每个 LSA 的 checksum 与 OSPF packet checksum 用**同一** RFC 1071 ones-complement `checksum()`（`builder.go:38`），计算时 LSA header 的 checksum 字节先清零（`buildLSA :119-122`）——v1 底稿"Fletcher-16、排除 LS age"表述作废（§10 裁定）。

长度示例：

- Hello：`24 + 20 + 4×neighbor_count`；无邻居为 44，一个邻居为 48，两个邻居为 52。
- DBD：`24 + 8 + 20×lsa_header_count`；一个 LSA header 为 52。
- LSR：`24 + 12×request_count`；一个 request 为 36。
- LSU：`24 + 4 + Σ(LSA length)`；一个 36-byte Router-LSA 为 64，一个 32-byte Network-LSA 为 60。
- LSAck：`24 + 20×lsa_header_count`；两个 header 为 64。

所有长度均按编码后的字节数回填。MSS（最大报文段长度）或其他外层分段出现时，`packet_length` 仍是 OSPF stream（流）消息长度，而 PCAP `packet_count` 应按真实 IPv4 segment（分段）和重组断言调整。

## 4. Hello、DBD、LSR、LSU、LSAck 语义

### 4.1 Hello

Hello 固定 body 为：Network Mask 4、HelloInterval 2、Options 1、Priority 1、DeadInterval 4、Designated Router 4、Backup Designated Router 4，再跟零个或多个 Neighbor Router ID（各 4 字节）。本版固定非平凡的 DR、BDR、优先级、计时器和邻居列表，避免只断言版本/类型。Hello 通常发往 224.0.0.5，TTL 1；实现应允许显式 src/dst 覆盖，但不得把目的组播地址替代 Router ID/DR 字段。

### 4.2 Database Description

DBD body 的固定部分为 Interface MTU 2、Options 1、I/M/MS flags 1、DD sequence 4，共 8 字节，随后为零个或多个 20-byte LSA headers。`ospf_dbd_master` 断言 I/M/MS 全置位（`flagsByte :181`，observable `flags=0x07`）和 sequence 100；`ospf_dbd_slave` 独立断言标志清零、sequence 101。DBD 的 LSA header 只描述摘要，不携带完整 LSA body。

### 4.3 Link State Request

每个 LSR request 是 12 字节：LSA type 4、Link State ID 4、Advertising Router 4。Router-LSA（type 1）和 Network-LSA（type 2）分开用例，避免只覆盖请求长度而漏掉类型/身份三元组。

### 4.4 Link State Update 和 LSA

LSU body 首先是 4-byte number-of-LSAs，随后串联完整 LSA。

LSA 公共 header：Age 2、Options 1、LS type 1、Link State ID 4、Advertising Router 4、Sequence 4、Checksum 2、Length 2，共 20 字节。Length 包含该 header。

- Router-LSA（type 1）body：Flags 1、保留 1、Link count 2、每个 link 12 字节（Link ID 4、Link Data 4、Link Type 1、TOS 0 1、Metric 2）。本版用一个 type 2 transit link、metric 10，LSA length 为 36。
- Network-LSA（type 2）body：Network Mask 4 + Attached Router IDs；两个 attached Router ID 时 LSA length 为 32。LSID 是 DR 接口地址 `10.0.0.2`，Advertising Router 是 `1.1.1.1`。

本版不把 AS-external-LSA、NSSA-LSA、opaque-LSA、extended-LSA、TOS 扩展或完整拓扑推断塞进 Router/Network 基础用例；新增类型必须独立 profile/case 和长度证据（→ G-OSPF-2）。

### 4.5 Link State Acknowledgment

LSAck 只携带一个或多个 20-byte LSA headers，不携带完整 LSA body。`ospf_lsack` 同时确认 Router-LSA 和 Network-LSA，断言 count、类型、LSID 和 Length，避免只检查 packet type。

## 5. IPv6 RFC 5340 边界

OSPFv3 的 IPv6 profile 不等于"把 IPv4 profile 的 `ip.proto=89`、公共头 offset 34、OSPF checksum 和 Router/Network LSA body 原样搬到 IPv6"。实现 RFC 5340 时必须单独明确：

1. IPv6 Next Header=89、IPv6 payload 起点和 Hop Limit，而不是 IPv4 header/TTL 断言；
2. OSPFv3 header 的 Instance ID、reserved bits 和 checksum 计算边界；
3. OSPFv3 的 LSA header/body 版本差异以及 link-local/interface scope；
4. 认证/安全扩展和 IPv6 地址字段；
5. 独立的正例、失败优先测试和 PCAP 证据。

本版的 `ospf_ipv6_rfc5340_boundary` 使用独立 `rfc5340_ipv6` profile 名，但在代码未实现阶段要求 task error `rfc5340`；它不是 IPv6 OSPF 正例。这样既保留需求边界，又不把 IPv4 OSPFv2 的 pseudo-header（伪首部）或 LSA 字节冒充 OSPFv3。

## 6. 校验和失败处理

planner/validator 必须拒绝（锚词→代码行实测，`planner.go`，P1 逐字核对；`invalid packet_type` 底层串出自 `builder.go:34`）：

| 错误 | 条件 | 稳定错误锚点 |
|---|---|---|
| 载体 | `wire_fault.kind=carrier`（UDP/TCP 注入） | `ip`（`planner.go:41-42`，串含 "carrier must be ip protocol 89"） |
| v6 地址 | IPv4 profile 配 v6 src/dst | `rfc5340`（`planner.go:31-32/:34-35`，串含 "rfc5340/OSPFv3 is IPv6"） |
| profile/version | `rfc5340_ipv6` profile 或 version=3（含 version=3+IPv4 profile——首中 `:24` 分支，串 "version/profile uses rfc5340" 同时含 `version` 与 `rfc5340` 两锚） | `rfc5340`/`version`（`planner.go:24-25`；纯 version 拒 `:44-45`） |
| type | 非法 packet_type / 非法 event kind | `type`（`planner.go:55-56` 经 `packetTypeFromString`；空 type 无 events `:58-59`；事件 kind `:103-106`） |
| length | `wire_fault.kind=declared_length` | `length`（`planner.go:73-74`） |
| Router/Area ID | 非 4-byte IPv4 格式/`wire_fault.kind=area_id` | `router`（`:62-63`）/`area`（`:66-70`） |
| checksum_mode | 非法 checksum_mode 值 | `checksum`（`:76-79`，串 "invalid checksum_mode"） |
| LSA | 非法 lsa/link_state_id/link_id/lsa_type | `lsa`/`link`（`:82-100`） |
| IPv6 profile | RFC 5340 未实现或 IPv4 profile 被复用 | `rfc5340` |

错误必须从 planner 传播到 task error，不能输出损坏 PCAP 后返回 completed。应用层邻接事件（例如状态为 Full）不是错误，也不能用 `expect_error` 替代其 wire 断言。

## 7. 场景与包数映射

OSPFv2 是 raw IPv4（裸 IPv4）报文，不走 TCP 握手，因此单报文正例的 `packet_count=1`；多事件场景按显式事件数计算。小报文、无 IP option、无 VLAN 的 IPv4 OSPF payload 起点为 offset 34。

| # | JSON id | 类型 | 事件/报文数 | packet_count | 主要 observable（可观察锚点） |
|---:|---|---|---:|---:|---|
| 1 | `ospf_hello_dr_bdr` | 正 | 1 | 1 | Hello 计时器、mask、priority、DR/BDR、neighbor、checksum |
| 2 | `ospf_hello_neighbors` | 正 | 1 | 1 | 两个邻居和 length=52 |
| 3 | `ospf_dbd_master` | 正 | 1 | 1 | MTU、I/M/MS、DD sequence、Router-LSA header |
| 4 | `ospf_dbd_slave` | 正 | 1 | 1 | flags 清零、sequence=101 |
| 5 | `ospf_lsr_router_lsa` | 正 | 1 | 1 | type 1 request 三元组 |
| 6 | `ospf_lsr_network_lsa` | 正 | 1 | 1 | type 2 request 三元组 |
| 7 | `ospf_lsu_router_lsa` | 正 | 1 | 1 | Router-LSA flags/link/metric/length |
| 8 | `ospf_lsu_network_lsa` | 正 | 1 | 1 | Network-LSA mask/attached routers/length |
| 9 | `ospf_lsack` | 正 | 1 | 1 | 两个 LSA headers |
| 10 | `ospf_neighbor_full_exchange` | 正 | 6 | 6 | Hello→DBD→LSR→LSU→LSAck 与状态 |
| 11 | `ospf_ipv4_transport` | 正 | 1 | 1 | IPv4 protocol 89、TTL、Area/Router ID |
| 12 | `ospf_checksum_length` | 正 | 1 | 1 | packet/LSA length 和两个 checksum |
| 13 | `ospf_neg_udp` | 负 | — | — | 仅 task error（`ip`） |
| 14 | `ospf_neg_ipv6_v2` | 负 | — | — | 仅 task error（`rfc5340`），拒绝 v2/IPv6 复用 |
| 15 | `ospf_neg_version` | 负 | — | — | 仅 task error（`version`，version=3 首中 `:24` 分支） |
| 16 | `ospf_neg_type` | 负 | — | — | 仅 task error（`type`） |
| 17 | `ospf_neg_length` | 负 | — | — | 仅 task error（`length`） |
| 18 | `ospf_neg_area` | 负 | — | — | 仅 task error（`area`） |
| 19 | `ospf_neg_router_id` | 负 | — | — | 仅 task error（`router`） |
| 20 | `ospf_ipv6_rfc5340_boundary` | 负/边界 | — | — | 仅 task error（`rfc5340`），独立 RFC5340 profile |

packet_count 序列（正例 12 个，按序）：`[1,1,1,1,1,1,1,1,1,6,1,1]`（总包数 17）。

## 8. 场景、包数与实现完成定义

1. 注册 IPv4→`ospf` 层，协议号 89，默认 TTL 1，并拒绝 UDP/TCP/缺 IPv4。
2. 对公共头逐字段写失败优先单测：version/type/length/router ID/area ID/checksum/AuType/authentication。
3. 对 Hello、DBD master/slave、LSR 两种 LSA type、LSU Router/Network LSA、LSAck 多 header 写独立单测；每个长度和字节序都要由编码结果断言。
4. 对 API→engine→PCAP 集成路径验证 20 个 case 的正/负分支；负例必须是 task error，不得 0 包成功。
5. 对 `ospf_neighbor_full_exchange` 验证事件顺序和状态隔离；不以一条 packet type 断言替代五类报文覆盖。
6. 用 IPv4 protocol 89、TTL、224.0.0.5/224.0.0.6 和实际 OSPF checksum 做 PCAP/NIC（网卡）验证；MSS 不适用于 IP 层分片时必须使用重组语义。
7. RFC 5340 OSPFv3 作为独立工作项：取得规范/fixture 后再注册 `rfc5340_ipv6` 正例，不得改写本版 IPv4 case。

## 10. 已知裁定与待确认（P1 实测诚实声明，§5.5）

- **LSA checksum 算法裁定**：实现 `checksum()`（`builder.go:38` RFC 1071 ones-complement，奇长补零参与计算）同时服务 OSPF packet checksum（`buildMessage :70-90`）与 LSA checksum（`buildLSA :107-124`，先清零 `lsa[16:18]` 再对整 LSA 求和）——v1 底稿三处"Fletcher-16、排除 LS age"表述作废。用例断言口径以 nonzero + 实现单测逐字节复算为准（testcase §1）。
- **`neighbor_state` 状态元数据**：`OSPFEvent.NeighborState`（`routing.go:143-164` 19 键之一）builder/layer_gen 全库零消费——`buildFromEvent :171-226` 只读报文类字段；多邻居/邻接隔离的"状态"面由 tshark 报文类字段面（`ospf.msg` 序列）验证，不由保留字段验证（testcase #10 的 `directional=true` 为方向面断言，非状态字段断言）。
- **`version=3` 首中分支**：`ospf_neg_version`（version=3 + `rfc2328_ipv4`）实际命中 `planner.go:24`（`Version == 3` 即拒），其错误串 "version/profile uses rfc5340…" 同时含 `version` 与 `rfc5340` 两锚——`error_contains=version` 由此成立，不走 `:44-45` 纯 version 分支（§6 表已注记）。
- **TTL 面（P1 实测，诚实声明）**：存量 `ttl` 18/20 为 1（两 v6 负例无 `ttl` 键）；当前生成器硬编码 `TTL=1`（`layer_gen.go:44-45` 单报文 emit 闭包 / `:81` 事件 emit），finalEmit 仅 `TTL==0` 时填充（`chain_planner.go:1429-1430`）故生成器值恒胜出——存量顶层 `ttl=1` 与硬编码值巧合一致。`ip` 层缺省 `ttl=64`（`registry.go:35`）当前不触发。P4 层链整形后用户层 `ip.ttl` 是否透传以整形后实测为准（此处不预支"用户层值优先"结论）。
- **存量 `wire_fault` 三值**：`carrier`（#13）/`declared_length`（#17）/`area_id`（#18）——`OSPFWireFault{kind,value}`（`routing.go:166-169`）；`checksum` 类故障当前无存量负例（`checksum_mode: invalid|zero|bad` 为成功路径注入，见 A′ T-21）。

## 11. 引用与缩写（沿 §13.4 三路口径）

- RFC 2328（OSPFv2）、RFC 5340（OSPFv3 独立边界）；wireshark OSPF 解析器（本机 3.6.14 实测 `ospf.*` 324 字段——断言通道权威，用例去重 34 字段）；本仓库已落码 builder/planner/generator（`internal/protocol/ospf/` 905 行）为 wire 真相；只借鉴字段语义与拆解思路。

## 13. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：矩阵三张子表——①报文×邻接状态矩阵（§13.2）②数据形态变体表（§13.3）③商业行为→用例映射表（§14.2）。条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号；无遗漏留白。
> **raw-IP 载体铁律（逐矩阵行重申）**：ospf 直挂 ip（registry `DependsOn ["ip"]`，`FieldContract ip.protocol=89`）——TCP/UDP 载体判死（链中夹 tcp/udp 层即错，`isRawIPChain :40-51` 含 tcp/udp 即否；igmp/pim 同族先例）；OSPF 无端口语义；无握手，五件套时间线诚实写"建连面无"。

### 13.1 八项规范矩阵

| # | 规范要求（RFC + 本契约节） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：无连接 raw-IP 信令；Hello 组播发现，DBD/LSR/LSU/LSAck 单播交换；无握手、无重传确认；一事件 = 一 PCAP frame（RFC 2328；本契约 §1） | 路由器 Hello 邻居发现；邻接形成后 DB 交换与 LSA 泛洪 | 已实现：生成器单事件直发（`layer_gen.go:20-107` 单报文直发 + 事件序逐包 Emit；s2c→down 由 raw-IP 分支交换 L3 源目）+ raw-IP 自驱（`chain_planner.go:1241-1370` isRawIPChain 分支，`meta.OSPF :1369`，L3.Protocol 由生成器固写 89） | P4 只做层链整形+链级红例+casegen（§15） |
| 2 | 命令消息表：Hello `1`/DBD `2`/LSR `3`/LSU `4`/LSAck `5`（RFC 2328；本契约 §3） | 五类控制动作全表逐消息编码 | 已实现：`packetTypeFromString`（`builder.go:21-35` 五分支；未知拒 `:34`）+ `kindToType`（`layer_gen.go:228-242` 事件面同构）+ frames `02 01/02/03/04/05` 实测 17 帧全对 | P5 逐例先跑后钉（frames 全 offset 34 单档，存量实测） |
| 3 | 状态机：OSPF 无连接状态机；主机侧唯一有序面 = Hello（Init）→ DBD（ExStart/Exchange）→ LSR/LSU（Loading）→ LSAck（Full）；DR/BDR 选举按 priority；多邻居状态隔离（RFC 2328；本契约 §2.1） | 邻居上线后交换 DB；DR 切换；LSA 泛洪确认 | 已实现：事件 `neighbor_state/direction` 元数据直通（`routing.go:143-164` 19 键；生成器/builder 不消费 `neighbor_state`，仅携带——§10 诚实声明）；`dirName` 逐包方向（`:251-256`） | 多会话并发交错序 → B′（G-OSPF-2，不假设调度器交织顺序） |
| 4 | 字段表：24 字节公共头（Version 2 + Type + Length + Router/Area + Checksum + AuType + 8B Auth）；Hello 计时器/mask/DR/BDR/邻居；DBD MTU/flags/sequence；LSR 三元组；LSA header/body（RFC 2328；本契约 §1/§3–§4） | 单邻居/多邻居 Hello；主从 DBD；两类 LSR；Router/Network LSU；多 header LSAck | 已实现：`ospfHeader :53` + `buildHelloBody :146` + `buildDDBody :165`（`flagsByte :181`）+ `buildLSAHeader :92`/`buildLSA :107`（checksum §10 裁定）+ `parseSequence :126` | 扩展 LSA 类型（3–7/AS-external/opaque）→ G-OSPF-2；AuType≠0 → G-OSPF-2 |
| 5 | 错误处理：载体 / v6 地址 / profile-version / type / length / area / router / checksum_mode / LSA 九类拒收（本契约 §6） | 脏包、错配、伪造字段一律 task error，零假成功 | 已实现：8 锚词行见 §6 表（`planner.go` 全行实测；锚词逐字对 §6：`ip :41`/`rfc5340 :24/31/34`/`version :24/44`/`type :55`/`length :73`/`area :66/69`/`router :62`/`checksum :76`） | 链级红例 4 例 P4 新增（presence/白名单/TCP 载体/缺 ip，§14-P2） |
| 6 | 超时活性：HelloInterval/RouterDeadInterval 邻居保活；DeadInterval 过期即失效；DD/LSR 重传定时器（本契约 §4） | 邻居掉线检测；DB 交换重传 | 已实现：计时器字段必发（Hello body 面）；周期定时器 = 明确不支持（§16），不立项 | 无缺口（显式不适用 ≠ 缺口；周期调度面归引擎调度器，不归本协议；Hello 周期重发面 → G-OSPF-2 B′） |
| 7 | NAT/代理：OSPF 是域内路由信令（TTL=1 组播 Hello + 单播交换），无 NAT 遍历语义；源地址为单播 fixture，目的为组播/单播按事件语义（RFC 2328；本契约 §2） | 同域路由交换 | 不适用（显式声明，不用"待确认"逃逸）：无 OSPF 层语义可测，无用例 | 无缺口（显式不适用 ≠ 缺口） |
| 8 | 版本方言：OSPFv2（Version=2）/ OSPFv3（RFC 5340，独立 profile）/ 认证扩展（AuType≠0）/ 扩展 LSA（本契约 §1/§5） | IPv4 域内路由；v3/认证/扩展另议 | 已实现：Version 恒 2（`ospfHeader :55` `hdr[0]=2`）；v3 双拒（`planner.go:24/31-35`）；白名单 `protocols.go:46` | 现网 DR/邻接行为抓包确认 → G-OSPF-1；认证/扩展 LSA/IPv6 另协议另议 → G-OSPF-2 |

### 13.2 子表①：报文×邻接状态矩阵（逐格已覆/缺失）

行=报文形状，列=邻接状态面：

| 报文 \ 状态面 | 合法编码面 | 状态/方向元数据 | 非法载体/拒绝通道 | 版本边界 |
|---|---|---|---|---|
| Hello（单邻居 DR/BDR） | 已覆 #1（`224.0.0.5` AllSPFRouters） | 不适用（单包无状态） | 负例通道 #13（carrier→`ip`） | 不适用 |
| Hello（多邻居/无邻居 transport 面） | 已覆 #2（双邻居 52B）/#11（无邻居 44B + `ip.version/dst`） | 不适用 | 负例通道 #13 | 已覆 #14 通道（v6 + version=2 → `rfc5340`） |
| DBD（master/slave） | 已覆 #3（I/M/MS 全置 + seq 100）/#4（清零 + seq 101） | 不适用（flags 即方向语义） | 负例通道 #13 | 不适用 |
| LSR（type 1/2 三元组） | 已覆 #5（type 1）/#6（type 2） | 不适用 | 负例通道 #16（未知 type→`type`） | 不适用 |
| LSU（Router-LSA） | 已覆 #7（flags/link/metric/length 36） | 不适用 | 负例通道 #17（declared_length→`length`） | 不适用 |
| LSU（Network-LSA） | 已覆 #8（mask/attached/length 32） | 不适用 | 负例通道 #17 | 不适用 |
| LSAck（多 header） | 已覆 #9（type 1/2 双 header） | 不适用 | 负例通道 #18/#19（area/router） | 不适用 |
| 多事件邻接交换 | 已覆 #10（6 事件五类报文序） | 已覆 #10（Init→Full 携带 + `directional=true`） | 不适用 | 已覆 #20 通道（`rfc5340_ipv6` → `rfc5340`） |
| checksum/length observable 面 | 已覆 #12（双 checksum nonzero + 双 length） | 不适用 | 负例通道 #17 | 已覆 #15 通道（version=3 首中 `:24`，`version` 锚） |

注：矩阵按**报文×状态仲裁轴**排——本引擎只做路由器侧报文生成（声明式回放族），对端动态应答只由 tshark 字段面验证。**逐格重数（9 行 × 4 列 = 36 格，逐格枚举，可复核）**：**已覆 10 格**（R1c1←#1、R2c1←#2/#11、R3c1←#3/#4、R4c1←#5/#6、R5c1←#7、R6c1←#8、R7c1←#9、R8c1←#10、R8c2←#10、R9c1←#12）；**负例通道 11 格**（R1c3/R2c3/R3c3←#13、R4c3←#16、R5c3/R6c3/R9c3←#17、R7c3←#18/#19、R2c4←#14、R8c4←#20、R9c4←#15）；**不适用 15 格**（R1c2、R1c4、R2c2、R3c2、R3c4、R4c2、R4c4、R5c2、R5c4、R6c2、R6c4、R7c2、R7c4、R8c3、R9c2）。10 + 11 + 15 = 36 ✓ **逐格有结论、无空格**。

### 13.3 子表②：数据形态变体表（协议相关全部形态逐项）

| 变体维度 | 形态 | 对应用例 | 备注 |
|---|---|---|---|
| kind×Type | hello `02 01`/dbd `02 02`/lsr `02 03`/lsu `02 04`/lsack `02 05` | #1–#12（frames 17 帧逐类；#10 六事件短前缀） | `packetTypeFromString` 五分支全覆；未知 kind 拒 → `builder.go:34`（`neg_type` 经 `planner.go:55`） |
| Hello 面 | mask/计时器/priority/DR/BDR/0–2 邻居 | #1/#2/#11 | `ospf.hello.*` 6 字段实测命中；该例不把 224.0.0.5 推断成 DR |
| DBD 面 | MTU/Options/I-M-MS 全置/清零/DD sequence/LSA header | #3/#4 | `ospf.db.*` + `ospf.dbd`（`0x07`/`0x00`）实测命中；master/slave 分立两例 |
| LSR 面 | type 1/2 三元组（LSID + advertising router） | #5/#6 | `ospf.lsa/link_state_id/advrouter` 3 字段；每 request 12B |
| LSU Router 面 | flags/link count/link type/metric/LSA length 36 | #7 | `ospf.v2.router.lsa.flags` + `lsa.number_of_links/router.linkid/linktype/metric0` 5 字段 |
| LSU Network 面 | mask/attached routers/LSA length 32/LSID=DR 地址 | #8 | `ospf.lsa.network.netmask/attchrtr` 2 字段；packet/LSA 双 length 不混同 |
| LSAck 面 | 双 20B header（type 1/2、LSID、length 36/32） | #9 | `ospf.lsa/lsa.id/lsa.length` 逗号双值面（tshark 版本相关，先跑后钉） |
| 多包事件 | 6 事件邻接（Hello/DBD×2/LSR/LSU/LSAck） | #10 | `directional=true` 唯一例；状态按独立 session 维护 |
| 载体不变量 | `ip.proto=89`、TTL=1（存量 18/20）、AllSPFRouters `224.0.0.5`×11 | #1–#12 全正例 + #11 独立例（`ip.version/dst`） | `FieldContract ip.protocol=89`；TTL 由 `ip` 层值注入 |
| checksum | packet + LSA 双 nonzero（同一 RFC 1071 函数，§10 裁定） | #1（packet）/#7（LSA）/#12（双面） | 固定常量不钉 frames；`checksum_mode` 后三值 → A′ T-21 |
| 目的分布 | 组播 Hello `224.0.0.5` / AllDRouters `224.0.0.6`（#12） | #1–#11（组播）/#12（组播 DR） | 存量分布见 §2（11/1/余 8 单播语义由事件面定） |
| version 面 | Version 恒 2（首字节 `02`） | #1–#12（frames 首字节全 `02` + `ospf.version=2`） | 实现 `hdr[0]=2`（`ospfHeader :55`） |
| profile 面 | rfc2328_ipv4（12 正）/ rfc5340 拒绝（2 负） | #1–#12/#14/#20 | `profile`+`version` 双锚（`planner.go:24`） |

### 13.4 P1 三路对照（CORE_MEMORY §4.12–4.15）

**①规范原文**：RFC 2328（OSPFv2）全文为"必须是什么"底线；Type/头长/载体/状态语义四面已逐节落本契约 §1/§3–§4。精确章节号待 G-OSPF-1（§5.5 不写死）。

**②现网行为**：路由器 Hello 邻居发现（目的 `224.0.0.5`、TTL=1）、DR/BDR 选举通告、DB 交换与 LSA 泛洪为现网通用形态。出处确认方式：抓现网/回环 OSPF 包核对 Type/目的/TTL 面（**立项 G-OSPF-1**：现网级确认前相关条目按 §5.5 标"待确认"，不写死进实现）。

**③开源实现思路**：wireshark OSPF 解析器（本机 3.6.14 实测 `ospf.*` 324 字段——断言通道权威；用例去重 34 字段）；本仓库已落码 builder/planner/generator（`internal/protocol/ospf/` 905 行）为 wire 真相；只借鉴字段语义与拆解思路。

**三路结论一致性**：三路在"Type 五值（`1..5`）、24B 公共头、Hello 计时器/DR 面、DBD I/M/MS、LSR 三元组、LSU count+完整 LSA、TTL=1、Protocol=89"八点一致。取舍：①内层编码字节以 builder 编码 + tshark 读回为准，先跑后钉；②现网 DR 选举间隔、重传策略差异面未到确认级 → G-OSPF-1，不写死。

### 13.5 候选方案对比（§4.17）

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| A 结构化声明式回放 | profile/events（kind/direction/requests/lsas/lsa_headers）结构化 + wire 由 builder 纯函数产出（同族 igmp/pim 路由终结层范式） | 字段可结构化断言；动态面可开；与已收官族同构 | 多会话交织序不假设 | O(n) 流式；复杂度低；单 profile 兼容 | **采用（已落码）** |
| B 生 hex 回放 | 整 packet hex 覆盖 | 最简单 | 字段不可断言；LSA 变体即死 | 动态零分 | 仅作负例特殊形逃生口 |
| C 完整 OSPF 状态机模拟器 | 自动补邻居响应/重传定时/DR 选举 | 真实度高 | 超出声明式回放族边界；与 §3.13"不许隐式编排"冲突 | 复杂度高、收益无 fixture 面支撑 | 不选 |

## 14. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §14.1 强制展开：旧键 `src_ip/dst_ip/ttl/count` 四键迁入 `ip` 层/`flow_control` 家族；顶层 `ospf` 子映射迁入 `layers[1]`；数量走兄弟键 `strategy_fc`（`flows` = packet_count，见 §14.1）；目标形状 spec_json 样例见 §14.1；存量 20 例逐键去向见 §14.1 去向表；非负例 `spec_json` 顶层键=0（`spec_json` 只留 `layers` + 兄弟 `strategy_fc`，presence 负例见 §14-P2） | 本契约 §2（存量形状实测：18+2 双形状）+ §14.1 样例与去向表 |
| §2 策略/任务 | 策略=单 OSPF 报文模板（自带 `strategy_fc` flows/bps/time）；任务=多策略合跑+总量封顶；框架语义未动 | 本契约 §13.1 #1 + §15 |
| §3 五件套 | 见 §14.3 强制展开：单 profile 会话表/事务序列/关联关系/插入位置/时间线；**无连接组播单播诚实写"建连面无"**，不虚构 handshake 包数（存量 `has_handshake` 0/20）；单包协议按 §3.14 豁免顶层 `sessions[]`（`events[]` 承载邻接隔离，不豁免多流覆盖） | 本契约 §14.3 + 用例 #10 |
| §4 查规范 | RFC 2328（编号级引用，精确章节待 G-OSPF-1）+ tshark `ospf.*` 324 字段实测（用例去重 34：`ospf.*` 30 + `ip.*` 4，34/34 命中）+ 已落码 builder wire 真相 + §13 矩阵 8 行+三子表 + 三路对照（§13.4） | 本契约 §13 |
| §5 依赖与错误 | `DependsOn ["ip"]`（registry.go:940；单载体、无 OptionalOn 面——ospf 无端口/传输层语义）；`FieldContract ip.protocol=89`（`core/builder.go:64` `ProtocolOSPF` + 生成器固写）；8 负例锚词表逐字（行号实测，见 §6）；失败返回 task error（零假成功） | 本契约 §2/§6 + §15 错误分支 |
| §6 性能 | 单事件流式渲染无全量聚合；pcap/NIC 双路验收；吞吐/并发/内存目标待 P4 基准后定（§6.5 诚实待确认，不写承诺数字）；六类场景清单见 §15 | §15 性能设计与验收 |
| §7 三份文档 | 83-ospf-{design,testcase}.md v2.0.0（行为面权威）+ D-OSPF-1（本契约 §15 草稿，门1 获批=定稿）+ T-OSPF（testcase §9 草稿）+ generated schema（ospf 已在生成表内 `layers.generated.json:2526`，P4 只跑 `TestLayersGeneratedMatchesRegistry` 验证无过期） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 层链整形开工；门1 获批=D-OSPF-1 定稿=开工门 | 提交序 |
| §9 测试三源 | 三源=RFC 条款（编号级，精确章节待 G-OSPF-1）+ D-OSPF-1 + tshark `ospf.*` 324 字段已实证（用例去重 34） + builder wire 真相 + 现网 DR/邻接形态（未确认级→G-OSPF-1）；20 ID 正负对账 | T-OSPF（testcase §9） |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123 报告）+ 收官隔离复审 + 修轮；红先绿后 | /tmp/pipe/83-ospf/p123-report.md |
| §11 白话 | 每阶段白话一句先行 | 汇报 |
| §12 动态清单 | 见 §14.12 强制展开：地址=`ip` 层（五策略全支持）；业务字段逐个列开/不开+理由；序号算法位置诚实"待 P4 定"（不编行号，§5.7） | 本契约 §14.12 |
| §13 schema 派生 | registry ospf 行（§13 单载体 `DependsOn ["ip"]`；`FieldContract ip.protocol=89` 由终结层生成器固写 + `transportProtocol :227/:241` 双看位）→ schemagen 重跑验证；struct 标签字面量锁 | §15 接线件 |
| §14 真实流程 | suite 经 MCP 建任务→引擎生成→tshark `ospf.*` 字段 + frames hex 双通道；先跑后钉；pcap 落 `/tmp/mcp-pcaps/ospf/` | 用例 §1/§7 |

### 14.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

旧键清单（`src_ip`/`dst_ip`/`ttl`/`count` + 本协议顶层子映射 `ospf` + 缺失的数量键）：

| 旧键 | 去向 |
|---|---|
| `src_ip` | → `layers[0].ip.src`（fixture `10.0.0.1` 起各例保留；#11 的 `10.0.0.9` 为单播源语义，保留） |
| `dst_ip` | → `layers[0].ip.dst`（分布保留：`224.0.0.5`×11 AllSPFRouters / `224.0.0.6`×1 AllDRouters / v6 两负例 `2001:db8::1→ff02::5` 留层内走拒，见下） |
| `ttl` | → `layers[0].ip.ttl`（18/20 为 1；两 v6 负例无 `ttl` 键——拒绝触发源在地址族面，不补） |
| `count` | → 删除顶层键；数量走兄弟键 `strategy_fc`（`{"type":"flows","value":N}`，N=packet_count：单包例 1；#10 为 6；正例总包数 17；负例 `value=1` 占位——拒绝发生在 Plan 前，flowCount 不触发多发） |
| 顶层 `ospf` 子映射 | → `layers[1]` 中 `{"ospf": {...}}` 条目（正例业务键 `version/profile/packet_type/router_id/area_id/auth_type/checksum_mode` + 报文类附加键全量迁入，零残留；`OSPFConfig` 23 键见 `routing.go:66-90`；#10 的 `events[6]` 进层内） |
| 缺失的数量键 | → 兄弟键 `strategy_fc`（20/20 全缺，逐例补） |

**存量 20 例改写清单（逐键；P4 执行，§9.14 存量审计落点）**：实测 18 例顶层键 = `['count','dst_ip','layers','ospf','src_ip','ttl']` + 2 例（#14/#20）= `['count','dst_ip','layers','ospf','src_ip']`（无 `ttl`），`layers` 20/20 = `[{"ip":{}},{"ospf":{}}]`（链形已对但层内全空——旧扁平形把地址/TTL/业务全放顶层）。逐键去向：

| 现状 | 去向（P4 改写） |
|---|---|
| 顶层 `src_ip`（18 例 `10.0.0.1` + #11 `10.0.0.9` + 2 例 v6） | 删除顶层键；写进 `layers[0]`（`{"ip": {"src": ..., "dst": ..., "ttl": 1}}`；v6 两例 `src/dst` 留层内走 `planner.go:31-35` 拒绝通道，按 1.12 拒绝通道表达，不删触发源） |
| 顶层 `dst_ip`（20/20） | 删除顶层键；写进 `layers[0].ip.dst`（分布保留，见上表） |
| 顶层 `ttl`（18/20 全为 1） | 删除顶层键；写进 `layers[0].ip.ttl` |
| 顶层 `count`（20/20 全为 1） | 删除顶层键；数量走兄弟键 `strategy_fc`（`flows` = packet_count） |
| `layers` 内 `{"ip":{}}` / `{"ospf":{}}` 空条目 | 填入顶层迁移值（ip 条目填 src/dst/ttl；ospf 条目填顶层 `ospf` 子映射全部业务键 + 事件内 `wire_fault`） |
| 兄弟 `strategy_fc` | 20 例全缺，逐例补（`{"type":"flows","value":packet_count}`；负例 `value=1`） |
| 负例 `wire_fault`（#13/#17/#18：`carrier/declared_length/area_id`） | 随 `ospf` 子映射进 `layers[1].ospf`，拒绝语义不变（锚词 `ip/length/area` 已对 `planner.go:41/73/66`） |

改写后必须满足：非负例 `spec_json` 顶层键 = 0（`spec_json` 只留 `layers`；`strategy_fc` 为兄弟键）；负例 `expect` 键集合为 `{expect_error, error_contains}`（8/8 已合规，P4 保持；实测见 §14.2）。`expect` 内键为 harness 断言键，不计顶层白名单。

完整 Hello 样例（目标形状；`strategy_fc` 为 `spec_json` 兄弟键）：

```json
{
  "spec_json": {
    "layers": [
      {"ip": {"src": "10.0.0.1", "dst": "224.0.0.5", "ttl": 1}},
      {"ospf": {"version": 2, "profile": "rfc2328_ipv4",
        "packet_type": "hello", "router_id": "1.1.1.1", "area_id": "0.0.0.0",
        "auth_type": 0, "checksum_mode": "auto",
        "network_mask": "255.255.255.0", "hello_interval": 10,
        "dead_interval": 40, "options": 2, "priority": 1,
        "designated_router": "10.0.0.2",
        "backup_designated_router": "10.0.0.3",
        "neighbors": ["2.2.2.2"]}}}
  ,
  "strategy_fc": {"type": "flows", "value": 1}
}
```

多事件邻接样例（#10；`events` 住 ospf 层内，`directional=true`）：

```json
{
  "spec_json": {
    "layers": [
      {"ip": {"src": "10.0.0.1", "dst": "224.0.0.5", "ttl": 1}},
      {"ospf": {"version": 2, "profile": "rfc2328_ipv4",
        "router_id": "1.1.1.1", "area_id": "0.0.0.0",
        "auth_type": 0, "checksum_mode": "auto",
        "events": [
          {"kind": "hello", "direction": "c2s", "neighbor_state": "Init",
           "router_id": "1.1.1.1", "area_id": "0.0.0.0",
           "network_mask": "255.255.255.0", "hello_interval": 10,
           "dead_interval": 40, "priority": 1,
           "designated_router": "10.0.0.2",
           "backup_designated_router": "10.0.0.3",
           "neighbors": ["2.2.2.2"]},
          {"kind": "db_description", "direction": "c2s",
           "neighbor_state": "ExStart",
           "flags": {"init": true, "more": true, "master": true},
           "dd_sequence": 100, "lsa_headers": []}
        ]}}}
  ,
  "strategy_fc": {"type": "flows", "value": 6}
}
```

### 14.2 子表③：商业行为→用例映射表（CORE_MEMORY §4.16；缺此表按 §4.22 记缺口）

| # | 商业行为（产品+行为） | 出处 | 对应用例 | 状态 |
|---|---|---|---|---|
| 1 | 路由器 Hello 邻居发现（目的 `224.0.0.5`，TTL=1，mask/计时器/DR/BDR） | 现网通用形态（RFC 2328 同构） | #1/#2（Hello 单/双邻居）/#11（transport 面） | 已映射；**现网抓包级确认** → G-OSPF-1（确认方式：抓路由器回环包） |
| 2 | DB 数据库交换（主从 flags/sequence + LSA header 摘要） | 现网通用形态 | #3/#4（master/slave 分立） | 已映射；确认 → G-OSPF-1 |
| 3 | 缺失 LSA 请求（Router/Network 两类三元组） | 现网通用形态 | #5/#6（type 1/2 分立） | 已映射 |
| 4 | LSA 泛洪（Router-LSA flags/link/metric + Network-LSA mask/attached）/ 泛洪确认（双 header） | 现网通用形态 | #7（Router）/#8（Network）/#9（LSAck）/#12（双 checksum 面） | 已映射 |
| 5 | 邻接全流程（Hello→DBD→LSR→LSU→LSAck + Init→Full） | 现网通用形态 | #10（6 事件） | 已映射 |
| 6 | 脏包/错配/伪造字段拒收（planner 拒） | 引擎行为（planner 真实锚词行） | #13–#20（8 负例，锚词逐字见 §6） | 已映射 |
| 7 | 边界编码（无邻居 44B、双 checksum nonzero、双 length） | RFC 2328 编码面 | #11（44B transport）/#12（checksum+长度）/#2（52B 邻居增长） | 已映射 |

注：本表凡记"现网通用形态"但未落抓包证据的，一律挂 G-OSPF-1 且不写死进实现（§5.5）。

### 14.3 §3 强制展开：五件套（单 profile，无连接）

会话表：

| 会话 | profile | 四元组（诚实：无端口、无握手） | 生命周期（诚实：无建连/无挥手） |
|---|---|---|---|
| s1 | rfc2328_ipv4 | `ip.src` 单播 + `ip.dst` 组播（Hello `224.0.0.5`）/单播（DBD/LSR/LSU/LSAck 对端），TTL=1 | Hello → DBD → LSR → LSU → LSAck（单 datagram 序列，无建连） |

事务序列（单事务四件事 §3.4–3.7）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| t1 hello 邻居发现 | s1 路由器在线（member 前置无） | 发 Hello（mask/计时器/DR/BDR/邻居） | 对端 Init；tshark `ospf.msg=1` + `hello.*` 命中 | v6 地址 → task error（#14 通道，`rfc5340` 锚词）；载体错 → #13（`ip`） |
| t2 db 交换 | t1 已发（Init） | 发 DBD master（I/M/MS 全置 + seq）/ slave（清零 + seq+1）+ LSA header 摘要 | `ospf.dbd/db.dd_sequence` 命中 | 未知 kind → task error（#16 通道，`type` 锚词） |
| t3 lsa 请求 | t2 已发（Exchange） | 发 LSR（type 1/2 三元组） | `link_state_id/advrouter` 命中 | length 故障 → task error（#17 通道） |
| t4 泛洪与确认 | t3 已发（Loading） | 发 LSU（count + 完整 LSA）→ LSAck（双 header） | `lsa.length/chksum` + header 面命中 | area/router 非法 → task error（#18/#19 通道） |
| t5 邻接扇出 | 各事件独立报文类字段 | 按事件序逐包 Emit（`layer_gen.go:60-100`） | 邻接隔离（#10 6 包）；`directional=true` 仅 #10 | 状态串用 → task error；交织序不假设（G-OSPF-2） |

关联关系（§3.8–3.10 三件事）：本协议**无控制流驱动数据流**（无 `driven_by` 派生流），但有**同事件序内 hello→lsack 语义关联**：归属会话 s1（`events[].router_id/area_id` 继承层配置 `layer_gen.go:61-69`）、归属报文组（同 Router/Area）、由 `kind` 序列决定——与 CWMP 范本差异点诚实声明：ospf 无副流派生，`events[]` 承载"多报文有序序列"（本契约 §6）。
| 管道分支 | 路由面动作 |
|---|---|
| 单报文直发 | `buildFromConfig :109` 按 `packet_type` 渲染后 `emit`；目的取 `Meta.DstIP` 缺省 `224.0.0.5`（`:100-107`） |
| 多事件序列 | 事件序即发送序；`neighbor_state` 只携带不进线（§10）；方向 c2s→up/s2c→down（`:251-256`），下行 L3 源目由 raw-IP 分支交换 |

插入位置：终结层——ospf bytes 经 IPv4 `Protocol=89` 直传（`transportProtocol` 看末层/倒二层 `case "ospf"`，`chain_planner_util.go:227/241`；L3.Protocol/TTL 由生成器固写 `Protocol=OSPF/TTL=1`，`layer_gen.go:44-45/:81`；raw-IP 分支另注 `spec.TTL` 入 meta（`chain_planner.go:1363-1367`）但对 ospf 无覆盖——finalEmit 仅 `TTL==0` 时填充（`:1429-1430`），而生成器已置 1；层链目标形下用户层 `ip.ttl` 以 P4 整形后实测为准）；IP 无 option 时 OSPF 起点 offset 34（frames 17 帧全 offset 34 单档实测）。

时间线：**顺序**——同会话内 t1→t2→t3→t4 严格报文序；会话间并发但输出不假设全局包序，只断言包内字段与隔离；无"长传输分片让位"面（单 datagram）；控制可中插动作=无（ospf 无 ABOR/STAT 类动作）。§3.12 的调度方式在本协议落点为"按事件序逐包 Emit"。

### 14.12 §12 强制展开：动态字段清单

| 字段 | 住处 | 开策略 | 理由 |
|---|---|---|---|
| `src`（src_ip） | ip 层 | fixed/inc/rand/list/pattern 全开 | §12.2 地址必备；多路由器并发锚点 |
| `dst`（dst_ip） | ip 层 | fixed（组播 fixture 钉死；多组播/单播地址池待立项） | 目的须按事件语义（组播 Hello vs 单播交换）；动态目的池 → G-OSPF-3 |
| `ttl` | ip 层 | 不开（恒 1，由层值注入） | 故障值只走负例拒绝通道，不做动态 |
| `profile`/`packet_type` | ospf 层 | 不开（五类报文各自独立模板） | profile/报文类切换 = 换策略（§2.5），不用动态冒充 |
| `router_id`/`area_id` | ospf 层 | 不开（fixture 钉死；多 ID 池待立项） | 多路由器/Area 并发面 → G-OSPF-3 |
| `neighbors`/`requests`/`lsas`/`lsa_headers` | ospf 层 events[] | 不开（fixture 钉死字节） | LSA 变体靠多策略（§2.5），不用动态冒充 |
| `hello_interval`/`dead_interval`/`dd_sequence` | ospf 层 | 不开（fixture 钉死；sequence 显式事件值） | 计时/序号语义值，非按流变化量 |
| `events` | ospf 层 | 不开（扇出结构静态声明） | 多流靠显式事件（§3.1），与动态正交 |

序号算法代码位置：**待 P4 定**（D-OSPF-1 定稿后 casegen/层链整形落码时钉死文件+行号；此处不编行号——§5.7）。

### 14-P2 presence 负例形状（链级红例必含①）

层链+顶层空子映射并存=判死负例（presence 负例形状，非残留）：`{"layers":[{"ip":{}},{"ospf":{}}],"ospf":{}}`（顶层空 `ospf:{}` 与层链并存）必须 planner/validator 拒——**但 ospf 当前 `CheckProtoFlat` 无同名子映射分支**（`strategy_convert.go:8322-8560` 有 http/dns/mqtt/cwmp/megaco/hl7/mmse/ntlm/ocsp/sstp 等分支，**无 ospf**；`rawWrapChains :8541-8546` 仅含 pppoe/ldap/rtmp/rtsp/pptp/vnc/xmpp/sctp/jt808/jt809/jtt905/arp/icmp，**无 ospf**；实测 `grep -n '"ospf"'` 仅 `:730-732` 解析分支）：P4 须补 `ospf` presence 判死分支（`error_contains` 含顶层键锚词 `rejects a top-level ospf sub-config`），否则 presence 形静默过（顶层先填 spec 赢层配置——隔离复审 F1 探针同构）。白名单外游离键（如顶层 `src_mac`——`ttl` 已迁 `ip` 层，顶层出现即游离）判死负例见 §15。**另注**：ospf 单 raw-IP 载体 → 链中夹 `tcp`/`udp` 层（`[ip,tcp,ospf]` / `[ip,udp,ospf]`）判死负例（`isRawIPChain :40-51` 含 tcp/udp 即否，转 transport 分支出错）；链缺 `ip`（`[ospf]` 裸链）判死负例（`DependsOn ["ip"]` 缺失由 validate_layers 拒绝）。P4 链级红例共 4 例 + 收官自查行「非负例 `spec_json` 顶层键=0」。

## 15. D-OSPF-1 P2 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批=定稿）

> 体裁：文件清单/接口签名/数据结构/主流程/错误分支/性能设计与验收/回滚方式。ospf wire 面已落码，D-OSPF-1 覆盖"已落码对接 + P4 层链整形差量"，不重发明 wire。

**文件清单（已落码 4 + P4 新建 1 + 接线/守卫 2，已落码行号实测）**：

| 文件 | 职责 |
|---|---|
| internal/protocol/ospf/builder.go（已落码，264 行） | wire 纯函数：`packetTypeFromString`（`:21` 五分支，未知拒 `:34`）/`checksum`（`:38` RFC 1071 ones-complement）/`ospfHeader`（`:53` 24B 公共头，version 恒 2）/`buildMessage`（`:70` 组装 + checksum 回填，Authentication 排除面）/`buildLSAHeader`（`:92`）/`buildLSA`（`:107` 同一 checksum 函数 `:119-122`，§10 裁定）/`parseSequence`（`:126`）/`buildHelloBody`（`:146`）/`buildDDBody`（`:165`）/`flagsByte`（`:181`）/Type 常量 `1..5`（`:13-17`） |
| internal/protocol/ospf/planner.go（已落码，109 行） | `Planner.Validate`（`:17`：rfc5340 拒 `:24`、v6 地址 `:31-35`、carrier `:41`、version `:44`、packet_type `:54-59`、router `:62`、area `:66-70`、length `:73`、checksum_mode `:76-79`、LSA `:82-100`、events `:103-106`） |
| internal/protocol/ospf/layer_gen.go（已落码，261 行） | `OSPFGenerator.Generate`（`:20-107`：`Emit` 空拒、默认 hello `:27`、事件序 `:60-100` 逐包 Emit；L3 固写 `Protocol=OSPF/TTL=1`（单报文 `:44-45`、事件 `:81`））/`buildFromConfig`（`:109`）/`buildBody`（`:122`）/`buildFromEvent`（`:171`，`neighbor_state` 不消费 §10）/`kindToType`（`:228`）/`multiDstFor`（`:244` 恒 `224.0.0.5`）/`dirName`（`:251`）/双注册（`:258-259` 生成器+校验器） |
| internal/core/routing.go（已落码） | `OSPFConfig`（`:66-90` 23 键）+ `OSPFDDFlags`（`:93`）+ `OSPFLSAHeader`（`:100`）+ `OSPFLink`（`:112`）+ `OSPFLSA`（`:120`）+ `OSPFRequest`（`:136`）+ `OSPFEvent`（`:143-164` 19 键）+ `OSPFWireFault`（`:166-169` 2 键） |
| internal/protocol/ospf/ospf_test.go（已落码，271 行） | 单元测试 15 个（P4 复用，不改口径） |
| internal/protocol/ospf/casegen_test.go（P4 NEW） | 一次性生成器：20 例（12 正+8 负）契约计数逐例 add()，落 test/protocol_pcap/cases/ospf.json（层链整形后形状） |
| 接线件（已落码，P4 只验证） | registry `registry.go:940`（`DependsOn ["ip"]` 单载体 + `FieldContract ip.protocol=89`）；`chain_planner_util.go:227/241` 末层/倒二层协议号 89；`chain_planner.go:1369` raw-IP 分支 `meta.OSPF` + `chain_planner.go:645/883` raw 名单；`strategy_convert.go:730-732` 子配置解析；`generator.go:492` FlowMeta.OSPF；`protocols.go:46` 白名单 + `protocols_test.go` 同步；schemagen 重跑验证无过期 |
| P4 新增守卫 | ①`CheckProtoFlat` 补 `ospf` 顶层同名子映射 presence 判死分支（`strategy_convert.go:8322` 加 `if protocol == "ospf"` 项——协议本地文件，车道内可改；当前缺失为 §14-P2 实证缺口）；②validate_layers 预检：白名单外游离键拒/链夹 tcp/udp 拒（`isRawIPChain :40-51` 含 tcp/udp 即否，转 transport 分支出错）/缺 ip 拒（DependsOn 缺失）——单载体，无 OptionalOn 面 |
| tools/coverage_gate.py | check_ospf（准入接线/关键件/守卫/用例面四段，P4 登记——当前 grep 计 0，出口 2 视红） |

**接口签名**（已落码，P4 落码钉死有无差量）：`packetTypeFromString(s) (byte, error)` / `checksum(b) uint16` / `ospfHeader/buildMessage/buildLSAHeader/buildLSA/parseSequence/buildHelloBody/buildDDBody/flagsByte` / `Planner.Validate(spec) error` / `OSPFGenerator.Generate(ctx, req) error`。

**数据结构**：沿 `OSPFConfig`（`routing.go:66` 23 键：version/packet_type/router_id/area_id/profile/auth_type/checksum_mode + Hello/DBD/LSR/LSU/LSAck/events/wire_fault）+ 层链目标形状（§14.1 样例：地址/TTL 住 `ip`、业务住 `ospf` 条目、数量走兄弟 `strategy_fc`）。

**主流程**：validateSpec（含 P4 新增 presence 守卫 + validate_layers 预检）→ 单报文渲染（`buildFromConfig` 按 `packet_type` 分支）或事件序渲染（`buildFromEvent` 五分支）→ `emit(directionFor)` → 下行 L3 源目交换（raw-IP 分支）→ worker（flowCount 恒 ≥1；`resolveLayerTuple` 后 `Plan`）→ pcap/NIC。

**错误分支（§5.2）**：①`wire_fault` 三值注入拒（`carrier :41`/`declared_length :73`/`area_id :66`，锚词进断言）；②自然守卫：rfc5340（`:24`）/v6 地址（`:31-35`）/非法 version（`:44`）/非法 packet_type（`:54-59`，底层串 `builder.go:34`）/非法 router/area（`:62-70`）/非法 checksum_mode（`:76-79`）/非法 LSA（`:82-100`）/非法 event kind（`:103-106`）；③validate_layers 预检同步拒（presence/白名单/tcp-udp 载体/缺 ip）。全部传播为 task error，零假成功。

**依赖声明（§5.1）**：依赖 `ip` 层（唯一载体，寻址+TTL+Protocol=89）；无 `tcp`/`udp` 依赖（§14-P2 把此列成守卫）；无外部 DR/采集器依赖。**不含端口依赖**（ospf 无端口语义；多流自动递增的 `HasExplicitSrcPort` 面对 ospf 生成器无副作用——生成器不读端口字段，实测注记）。

**性能设计与验收（§6.1–6.8）**：O(n) 流式——逐事件渲染直发 Emit 无全量聚合（单报文直发 + 事件序 for 循环直发，无缓冲增长结构）；确定性内存（单事件最大=单 LSU fixture 级字节）；无锁无 sleep（事件驱动，非定时器模型）；pcap 路实测 + NIC 路注记（过滤器 `ip proto 89`，测试网口按 testing-interface 记忆）；回归口径=ospf.json 全量 suite 耗时 ±10%；六类场景（基线/目标规模/压力上限/长运行时/并发交错/背压）P5 跑测覆盖；边界诚实声明：吞吐/并发/内存目标数字待 P4 基准后定（§6.5，不写承诺）。

**与现有逻辑冲突点（§8.7）**：①`strategy_convert.go:730-732` 仅解析顶层 `ospf` 子映射，无 presence 判死分支——P4 补 `CheckProtoFlat` 项（§14-P2 实证缺口；协议本地文件，车道内可改）；②`parseSubconfigJSON`（`strategy_convert_helpers.go:21-30`）为**普通 `json.Unmarshal`（无 `DisallowUnknownFields`）**——ospf 子映射未知键静默忽略，负例不得依赖未知键拒绝（P4 如需把未知键变红另立守卫，见 G-OSPF-4）；schemagen 生成表已含 ospf（`layers.generated.json:2526`，`fields {}` 因业务键走 FlowMeta 直传），P4 只验证无过期（`TestLayersGeneratedMatchesRegistry`）。

**回滚方式（§8.8）**：P4 差量全量 revert（casegen + 20 例改写 + presence 守卫 + coverage 登记）；已落码 wire 面不动；无数据迁移面。

## 16. P3 测试对接清单与缺口立项（T-OSPF 草稿输入；正文落 testcase 文件）

- §3.15 三项：①同会话多轮序列（Hello→DBD→LSR→LSU→LSAck，状态变迁）→#10（6 事件邻接交换）已覆；②非正常结束→8 负例全覆（#13–#20）；③长保活→ospf 无自有保活语义=不适用（显式声明，Hello 周期属路由器调度面，不归本协议）+ Hello 周期重发面 → B′ G-OSPF-2。逐项一例或立项，无空项（明细见 testcase §9.1）。
- A′/B′ 两分类表：见 testcase §9.2（A′=引擎可构建→20 ID 内已覆 + A′ 补例建议 T-21（`checksum_mode` invalid/zero/bad 三值 observable）/T-22（DBD 零 LSA header 空摘要边界）；B′=引擎结构缺口→G-OSPF-2 进 D-条目"明确不解决+迁入计划"）。
- 9.52 对账两行：见 testcase §9.3（清单出处声明 + 对账两行：总数 57 = 已覆 42 + 不适用 15；另 +4 P4 新增链级红例为矩阵外项）。
- 3.14 豁免边界审计：见 testcase §9.4（本协议无连接但**不主张多流豁免**：多事件扇出 #10 已覆；单包多载荷=双邻居/双 request/双 header/双 LSA 面已覆；`events[]` 承载邻接序列，多事务已覆）。
- 三源回指行：见 testcase §9.5（第三源"已确认现网行为"当前=未确认级，挂 G-OSPF-1）。
- 断言通道：fields 用 `ospf.*`（去重 34 已实证，注册命中 34/34，见 §13.3 备注行）+ frames hex（offset 34 单档 8 类前缀实测）。

## 17. 缺口立项清单（有缺口写"缺口立项"，不许空着）

| 立项号 | 缺口 | 确认方式（三选一） | 去向 |
|---|---|---|---|
| G-OSPF-1 | 现网证据升级 + RFC 精确章节复核：路由器 Hello/DR 选举/DB 交换/LSA 泛洪行为的"已确认现网"级证据；RFC 2328 精确章节号 | 抓包（抓路由器回环/现网包核对 Type/目的/TTL 面）+ 查 RFC 原文 | P4 前置确认项，不挡开工；确认前相关条目按 §5.5"待确认"不写死 |
| G-OSPF-2 | B′ 行为面：认证扩展（AuType≠0）/扩展 LSA 类型（type 3–7、AS-external/opaque）/定时器调度（Hello 周期重发、DD 重传）/多会话并发交织序假设 | 查 RFC 2328 相关章节 + 抓包（问谁：无，文档+包即确认） | B′→D-OSPF-1"明确不解决+迁入计划"（确认后进 §13.2 空白格） |
| G-OSPF-3 | 动态多路由器 ID 池/多 Area 并发（§14.12 `dst`/`router_id` 不开面）+ A′ 补例 T-21（checksum_mode 三值）/T-22（DBD 空摘要边界） | 查引擎序号算法现状（P4 定） | A′ 补例并入与否由主线程定，不影响 §7 的 20 ID 权威口径 |
| G-OSPF-4 | 严格解码守卫：`ospf` 子映射未知键当前静默忽略（`parseSubconfigJSON` 普通 `json.Unmarshal`，`strategy_convert_helpers.go:21-30`），按 13.26 口径未知键应显式拒绝 | 读 `strategy_convert_helpers.go` 现状 + 引擎负例实测 | P4 评估是否框架级统一加 `DisallowUnknownFields`（属跨协议共享面，须上报主线程，不车道自改） |

## 18. P1/P2/P3 对抗自重审结论（10.11；过 3 轮，末轮干净）

- **P1（§13 矩阵）**：R1 自重审发现 §13.2 逐格重数初稿把 R2c3/R3c3 双重认领给 #13 通道与链级红例两处 → 改为负例通道单列、链级红例仅 §14-P2 矩阵外 4 例，10+11+15=36 复算一致；R2 逐行核八项矩阵的"代码现状"列行号全部实读源文件（builder/planner/layer_gen/routing/chain_planner/chain_planner_util/protocols），无编造行号（registry.go:940 HEAD=工作树一致；旧报告 909 系 stale，以实测为准）；R3 末轮干净。
- **P2（§15 D-条目）**：R1 自审发现 §5 行初稿"白名单 protocols.go:45"为旧报告误植 → 按实测改正 46；R2 补落 `CheckProtoFlat` 无 ospf 同名子映射分支的 presence 缺口（`strategy_convert.go:8322-8560` 实证缺失 + `rawWrapChains :8541-8546` 无 ospf，§14-P2 立为 P4 必补项；旧报告 403-407/8515 系 stale 行号，作废）；R3 末轮干净。
- **P3（testcase §9 + §16/§17）**：R1 自审发现 9.52 对账初稿"总数 58"为 pim 模板残留 → 改为 8+36+13=57 点、42+15=57 两行对账并加粒度声明；R2 核 §13.2 矩阵逐格重数 + §16 断言通道 34 字段逐个对 tshark 注册表（34/34 精确命中，`ospf.*` 324 中取 30 + `ip.*` 4）+ 锚词 8 个逐字对 planner.go 真实字符串（含 version=3 首中 `:24` 分支的双锚说明）；R3 末轮干净。

三阶段合计修正 6 处（2 处算术：矩阵逐格重数 + 9.52 对账口径、2 处行号 stale（registry 909→940、convert 403/8515→8322/8541）、1 处守卫缺口浮出落 §14-P2、1 处模板残留），末轮均干净。

### 18.1 文档逐条自核对结论（10.1：对规范逐条核对）

- RFC 2328（五类报文 Type 1..5、24B 公共头、Hello 计时器/DR 面、DBD I/M/MS+DD sequence、LSR 三元组、LSU count+完整 LSA、LSAck 多 header、Router-LSA/Network-LSA 基础 body、Area/Router ID、AuType、IPv4 Protocol 89/TTL 1/224.0.0.5/224.0.0.6）→ §3/§4 逐条有落点；RFC 5340（OSPFv3 独立 profile）→ §5 边界。精确章节号挂 G-OSPF-1 不写死（§5.5）。
- 与旧需求文档（v1.0.0 design/testcase）逐条核对（10.2）：见 §18.2。

### 18.2 与旧文档逐条核对结论（10.2）

v1.0.0 `37-ospf-design.md` §1–§8 / `37-ospf-testcase.md` §1–§7 逐条：§1 范围（保留+扩，profile 表不动，"层尚未实现/仅设计阶段"段按实测改写为已注册已落码）；§2 配置表（保留，业务键语义不变；新增 `checksum_mode` 后三值 + `wire_fault` 三值实证注记）；§3 线格式（保留，补 Type→frames 前缀实测对照 + LSA checksum §10 裁定作废 Fletcher-16）；§4 事件状态（保留，补 `neighbor_state` 不消费诚实声明）；§5 SSM→RFC5340 边界（保留，改名以正名义）；§6 负路径表（保留，锚词实测化为 §6 锚词行表 + version=3 首中分支注记）；§7–§8 场景表（20 ID 逐条保留，packet_count 序列 `[1×11,6,1]` 不变）。无旧条目被静默删除。

## 19. 修订记录

- v2.0.0（2026-09-27）：P1–P3 完整产物。新增 §13 P1 八项规范矩阵 + 三子表（报文×邻接状态矩阵、数据形态变体表、P1 三路对照 §13.4、候选方案对比 §13.5）；§14 门1 §1–§14 十四行表（§1/§3/§12 强制展开 + 目标形状 spec_json 样例 + presence 负例形状）；§15 D-OSPF-1 P2 代码设计草稿；§16 P3 对接清单；§17 缺口立项（G-OSPF-1/2/3/4）；§18 自重审与核对结论。§1 重写为 profile＋已注册边界（注册行号 registry.go:940 实测，HEAD=工作树一致）；§2 增补 20 例存量形状声明（旧扁平形 18+2 双形状，P4 改写）；§6–§7 增补锚词→代码行表；§10 新增四项裁定（LSA checksum RFC1071 风格作废 Fletcher-16、`neighbor_state` 不消费、version=3 首中分支、缺省 TTL/目的）。
- v1.0.0（2026-08-20，`37-ospf-*`）：建立 RFC 2328 OSPFv2 IPv4 设计契约；覆盖 Hello、DBD、LSR、LSU、LSAck、Router/Network LSA、邻接状态、DR/BDR、checksum/length、IPv4 Protocol 89 和 20 个原子正/负/边界 case；RFC5340 保持独立 profile 边界。

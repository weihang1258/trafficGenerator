# OSPF（开放最短路径优先）v2 设计与用例对抗审查

> 审查对象：`docs/protocol-designs/37-ospf-design.md`、`docs/protocol-designs/37-ospf-testcase.md`、`trafficgen/test/protocol_pcap/cases/ospf.json`  
> 审查日期：2026-08-20  
> 审查属性：设计文档阶段；不检查 Go（编程语言）实现，不宣称 `ospf` 层已注册或 suite（测试套件）已运行。  
> 结论：完成两轮自审，最后一轮 clean（通过）。

## 1. 审查口径

本审查保留两个独立视角：

- **规格可实现性视角（代码逻辑替代项）**：逐字段检查 RFC2328 IPv4 载体、OSPFv2 24-byte 公共头、Type 1..5、网络字节序、packet/LSA length、checksum、Hello/DBD/LSR/LSU/LSAck、Router/Network LSA、邻接状态和 DR/BDR；检查 RFC5340 IPv6 profile 是否被隔离而非被 IPv4 字节冒充。
- **用例覆盖视角**：逐项反查设计 §6 错误表和 §7 场景表；检查正例 observable、34 offset、length/frame 前缀、原子事件；检查负例的 `expect` 是否只包含 `expect_error` 与 `error_contains`。

本轮不执行 Go 实现或 MCP（模型上下文协议）suite。发现若依赖未来 layer（层）字段名，仅作为实现契约检查，不虚报运行时结果。

## 2. 规格可实现性审查

### 2.1 已确认

1. **载体边界明确**：OSPFv2 直接位于 IPv4 Protocol 89，无 TCP/UDP 端口；默认 TTL=1。`layers=[ip,ospf]` 与 UDP 负例区分清楚。
2. **公共头完整**：Version、Type、Packet Length、Router ID、Area ID、Checksum、AuType、8-byte Authentication 的位置和宽度明确；长度包含 24-byte header。
3. **五类 packet 分离**：Hello、DBD、LSR、LSU、LSAck 各自有独立 body 公式，DBD master/slave 分成两个用例，避免 flags 被宽松化。
4. **LSA 结构可复算**：LSA header 固定 20 bytes；Router-LSA 一链为 36 bytes，Network-LSA 两 attached routers 为 32 bytes；LSU 的 4-byte LSA count 与 LSA length 分开定义。
5. **checksum 不伪造常量**：design/testcase 仅断言 checksum 非零，并要求实现专用测试按 RFC 2328 复算；packet checksum 排除 Authentication 字段，LSA checksum 独立使用 Fletcher-16 并排除 LS age；没有把某个 fixture 的 checksum 常数推广为所有样本。
6. **标识和 DR/BDR 显式**：Router ID、Area ID、Network Mask、DR、BDR、neighbor IDs 由配置提供，不由 IP 或组播目的地址猜测。
7. **状态和事件原子化**：六事件场景逐包表达 Init/ExStart/Exchange/Loading/Full；邻接状态不是一个隐式“成功”包。
8. **IPv6 profile 隔离**：`rfc5340_ipv6` 仅作为独立边界；IPv4 `offset 34`、IPv4 OSPF checksum、Router/Network LSA body 未用于 OSPFv3 正例。`ospf_neg_ipv6_v2` 和 boundary case 均为错误传播契约。
9. **错误传播明确**：载体、version/profile、type、length、Area/Router ID、checksum、Hello/DBD/LSR/LSU 边界和 IPv6 profile 错误均要求 task error，不允许完成但 0 包。

### 2.2 实现阶段守护项（非当前文档 finding）

| 项目 | 当前契约 | 实现前必须补充 |
|---|---|---|
| dissector 字段名 | `ospf.*` 作为实现后解码字段契约 | 以实际 tshark 版本确认字段名/值格式，再同步 JSON |
| checksum | `nonzero` PCAP observable | builder 单测按 RFC2328 packet ones-complement 复算并排除 Authentication；LSA Fletcher-16 复算并排除 LS age，覆盖 odd/even body 和 AuType |
| Router-LSA | 一个基础 transit link | link type、TOS、不同 Link Data 语义和多 link 通过独立 fixture/case 扩展 |
| Network-LSA | mask + 两个 attached Router IDs | attached 数量边界、无 attached、LSID/DR 语义集成测试 |
| 状态机 | 静态事件状态标注 | API→planner→worker→PCAP 传播、重传/超时/邻接隔离测试 |
| IP fragmentation | 说明 packet length/重组边界 | 真正 IP 分片或超长消息的动态重组断言；不能沿用 34 offset |
| RFC5340 | 独立 profile 边界负例 | 取得 OSPFv3 fixture 后另写 IPv6 header/Instance ID/checksum/LSA 正例 |

这些是实现完成定义，不是当前设计阶段缺陷。

## 3. 用例覆盖对抗审查

### 3.1 正例逐条核对

| id | 设计覆盖 | JSON observable | 结果 |
|---|---|---|---|
| `ospf_hello_dr_bdr` | Hello mask/timer/priority/DR/BDR/neighbor/checksum | 34 offset 前缀、字段和 checksum | 通过 |
| `ospf_hello_neighbors` | 两个 neighbor、长度增量 | length=52、count=2、邻居列表 | 通过 |
| `ospf_dbd_master` | MTU、I/M/MS、sequence、Router-LSA header | flags=0x07、LSA header fields | 通过 |
| `ospf_dbd_slave` | slave flags/sequence | flags=0、sequence=101 | 通过 |
| `ospf_lsr_router_lsa` | LSR type 1 三元组 | type/LSID/advertising Router/checksum | 通过 |
| `ospf_lsr_network_lsa` | LSR type 2 三元组 | type/LSID/advertising Router | 通过 |
| `ospf_lsu_router_lsa` | Router-LSA body | count/type/length/link/metric/checksum | 通过 |
| `ospf_lsu_network_lsa` | Network-LSA body | mask/attached Router IDs/LSA length | 通过 |
| `ospf_lsack` | two LSA headers | count/types/LSIDs/lengths/checksum | 通过 |
| `ospf_neighbor_full_exchange` | atomic state/event progression | six packet types, state and counts | 通过 |
| `ospf_ipv4_transport` | IPv4 protocol 89/TTL/IDs | ip.version/proto/ttl/dst and IDs | 通过 |
| `ospf_checksum_length` | packet/LSA length and checksum | two nonzero checksums, lengths, IDs | 通过 |

### 3.2 负例逐条核对

| id | 设计错误行 | JSON expect | 结果 |
|---|---|---|---|
| `ospf_neg_udp` | UDP/缺 IPv4 carrier | 仅 `expect_error` + `ip` | 通过 |
| `ospf_neg_ipv6_v2` | IPv6 复用 RFC2328 IPv4 profile | 仅 `expect_error` + `rfc5340` | 通过 |
| `ospf_neg_version` | version/profile 不匹配 | 仅 `expect_error` + `version` | 通过 |
| `ospf_neg_type` | 未知 packet type | 仅 `expect_error` + `type` | 通过 |
| `ospf_neg_length` | 声明长度小于 header | 仅 `expect_error` + `length` | 通过 |
| `ospf_neg_area` | malformed Area ID | 仅 `expect_error` + `area` | 通过 |
| `ospf_neg_router_id` | malformed Router ID | 仅 `expect_error` + `router` | 通过 |
| `ospf_ipv6_rfc5340_boundary` | RFC5340 独立 profile 尚未实现 | 仅 `expect_error` + `rfc5340` | 通过 |

## 4. 三方静态一致性

审查脚本加载 JSON 并对设计/测试索引手工逐项反查，结果如下：

- ID 总数为 20，均唯一；设计 §7、测试 §2、JSON 顺序一致。
- 正例 12 个，`packet_count=[1,1,1,1,1,1,1,1,1,6,1,1]`；8 个负例/边界没有 `packet_count`。
- 12 个正例全部有 `has_payload=true`、`fields` 和 `frames`；每个 frame offset 都是 34，且前缀分别匹配 OSPF Type/Length。
- 正例的 OSPFv2 `version=2` 和 `ip.proto=89` observable 一致；IPv6 只出现在两个独立错误边界 case，不存在 IPv6 OSPFv2 成功 frame。
- 负例的 `expect` 恰有两个键，无 fields、frames、packet_count、notes 等额外断言。
- 长度闭环：Hello=48/52/44，DBD=52，LSR=36，Router-LSA LSU=64，Network-LSA LSU=60，LSAck=64；frame 前缀与这些值的十六进制一致。

## 5. Findings（发现项）

### F-01（已修复：Network-LSA LSU 长度）

初始自审把两个 attached Router ID 的 Network-LSA LSU 暂写成 68 bytes，并在 frame 前缀使用 `00 44`。逐字段复算后确认：LSA body 是 4-byte Network Mask + 8-byte attached Router IDs，LSA 总长为 `20+12=32`；LSU 总长应为 `24+4+32=60`，即 `00 3c`。已同步修正 design 的公式、testcase 的场景说明、JSON `packet_length=60`、LSA length=32 和 frame 前缀；当前无 68/`00 44` 残留。

### F-02（已修复：Hello body/length 的邻居边界）

逐字段检查确认 Hello 固定 body 是 20 bytes（不含公共 24-byte header），每个 Neighbor Router ID 4 bytes；一个邻居为 48、两个邻居为 52、无邻居为 44。已在 design、testcase 和 JSON 分别覆盖三种长度；当前长度公式与 frame 前缀一致。

### F-03（保留为实现边界：RFC5340）

OSPFv3 的 IPv6 header、Instance ID、checksum pseudo-header、LSA 结构和认证扩展没有在本阶段伪造。`ospf_neg_ipv6_v2` 与 `ospf_ipv6_rfc5340_boundary` 的负例结构是有意设计：它们证明 profile 不能静默复用 OSPFv2，而不是宣称 OSPFv3 已实现。

## 6. 结论和自审记录

OSPFv2 RFC2328 的 IPv4 Protocol 89 载体、24-byte header、Hello、DBD master/slave、LSR Router/Network 请求、LSU Router/Network LSA、LSAck、checksum/length、Router/Area ID、DR/BDR、邻接状态及负例传播均形成 design/testcase/JSON 闭环。没有执行未实现层，也没有把 IPv4 OSPFv2 bytes、checksum 或固定 offset 冒充 RFC5340 OSPFv3。

完成 **两轮自审**：第 1 轮逐字节复算发现 F-01（Network-LSA LSU 68→60）和 F-02（Hello 邻居长度边界）并同步修正；第 2 轮检查 ID 顺序、包数、offset、frame 前缀、LSA length、负例键和 IPv6 profile 隔离，未发现新问题；**最后一轮 clean（通过）**。

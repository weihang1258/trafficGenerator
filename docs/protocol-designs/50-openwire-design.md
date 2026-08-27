# OpenWire（ActiveMQ 原生线协议，ActiveMQ OpenWire）设计契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：仅设计与 PCAP（抓包文件）用例契约；`openwire` 层尚未注册，不修改 Go（编程语言）planner（规划器），不宣称当前 suite（测试套件）可运行。
> 配套文件：`docs/protocol-designs/50-openwire-testcase.md`、`trafficgen/test/protocol_pcap/cases/openwire.json`
> 规范基线：ActiveMQ OpenWire protocol specification（OpenWire 协议规范）、ActiveMQ command/data structure（命令/数据结构）定义和 TCP（传输控制协议）。

## 1. 范围、profile 和未注册边界

OpenWire 是 ActiveMQ broker（消息代理）使用的二进制 TCP 应用协议。它通过 WireFormatInfo 协商版本/选项，再传输 Connection、Session、Producer、Consumer、Message、Ack、Transaction 和 Error 等 command（命令）。OpenWire 不是 AMQP、STOMP 或 JMS API；不能把任意 TCP payload 标为 OpenWire。

本版覆盖：

- TCP/IPv4、TCP/IPv6，默认目的端口 61616；
- WireFormatInfo negotiation（线格式协商）、connection/session/producer/consumer 生命周期；
- Message、MessageDispatch、MessageAck、Response、ExceptionResponse 和 RemoveInfo；
- persistent（持久化）、transaction（事务）、commit/rollback、ACK mode（确认模式）和 redelivery（重投递）标志；
- 多连接、多 session、多 producer/consumer、queue/topic destination（队列/主题目的地）；
- command length、type、correlation、destination、transaction、ack 和状态错误负路径。

不覆盖：TLS/SSL 加密、OpenWire over WebSocket、AMQP/STOMP/MQTT、broker 路由/持久化存储实现、JMS 业务对象序列化、真实 selector（选择器）执行、压缩算法和集群拓扑。TLS 只能作为未来独立外层边界，未解密时不得断言 OpenWire 字段。

当前仓库没有注册 `openwire` layer（层）、planner、validator（校验器）或生成实现。所有语义 ID 都是未来契约；当前 JSON 仅使用 `expect_error=true` 与 `error_contains=unknown layer` 占位，不能把拒绝或 0 包报告为 OpenWire 通过。

## 2. 协议栈、端口和偏移

推荐层链为 `[ip, tcp, openwire]`。OpenWire 明文默认 TCP destination port（目的端口）为 61616，源端口由 fixture（固定样本）显式提供。UDP、裸 IP、HTTP、WebSocket、AMQP 和 STOMP 不得静默当作本版载体。

无 VLAN（虚拟局域网）、无 IP options（IP 选项）和无 TCP options 时，TCP application payload（应用载荷）起点为 IPv4 offset（偏移）54（Ethernet 14 + IPv4 20 + TCP 20），IPv6 offset 为 74（14 + IPv6 40 + TCP 20）。TCP segment（分段）边界不是 OpenWire command 边界；必须按长度前缀重组完整 command，MSS（最大报文段长度）分段不能改变 command 语义。

OpenWire 的具体长度/编码字段由协商 wire format（线格式）决定。设计期 JSON 不固定随机 command ID、producer ID、consumer ID、session ID 或 broker response ID；未来正例使用字段存在性、同包关联或 raw frame（原始帧）稳定前缀断言。

## 3. 配置 typedef（类型定义）

以下为设计期配置形状，不是当前 Go struct（结构体）：

```json
{
  "layers": [{"tcp": {}}, {"openwire": {}}],
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.20",
  "src_port": 40000,
  "dst_port": 61616,
  "openwire": {
    "profile": "activemq_openwire_v12",
    "wire_format": {"version": 12, "tight_encoding": true, "cache_enabled": true},
    "connections": [{
      "connection_id": 1,
      "events": [
        {"kind": "wire_format_info", "direction": "c2s"},
        {"kind": "connection_info", "direction": "c2s"},
        {"kind": "connection_ack", "direction": "s2c"},
        {"kind": "session_info", "session_id": 1, "direction": "c2s"}
      ]
    }]
  }
}
```

| 键 | 类型/约束 | 语义 |
|---|---|---|
| `profile` | `activemq_openwire_v12`、`activemq_openwire_legacy` | 明确 OpenWire 版本/命令能力；未知 profile 拒绝 |
| `wire_format` | `version`、`tight_encoding`、`cache_enabled`、可选 max frame | 协商双方共同使用；不能只改变一侧编码 |
| `connections` | 有序连接数组 | 每个连接独立 TCP 四元组、command ID 和实体表 |
| `connection_id` | 非负 fixture 标识 | connection/session/response 关联；不等于运行期 wire command ID |
| `events` | 有序 command 事件数组 | planner 只生成显式事件，不自动补业务命令 |
| `kind` | `wire_format_info`、`connection_info`、`connection_ack`、`session_info`、`producer_info`、`consumer_info`、`message`、`dispatch`、`ack`、`transaction`、`response`、`exception`、`remove`、`shutdown` | command 类型和状态机事件 |
| `session_id`/`producer_id`/`consumer_id` | 同连接内唯一 | command 与 session/entity 关联；不同连接不得复用状态 |
| `destination` | `queue://name` 或 `topic://name` | 目的地类型和名称，非空且按事件一致 |
| `message_id` | 显式或运行期生成 | message、dispatch、ack、response 的关联键 |
| `ack_mode` | `auto`、`client`、`individual`、`dups_ok` | consumer/ack 语义；不从 destination 猜测 |
| `persistent` | bool | Message 持久化标志；只编码声明值，不声称 broker 已落盘 |
| `transaction` | `id`、`kind`（begin/commit/rollback） | 事务边界；跨 session 或重复终止必须拒绝 |
| `body`/`body_b64` | 文本或 base64 二进制，二选一 | Message payload；长度必须与命令声明一致 |
| `wire_fault` | 仅负例 | `short_frame`、`bad_type`、`length_overrun`、`state_order`、`correlation`、`transaction` 等 |

## 4. Frame 与 command 编码边界

OpenWire command 由 wire format 协商的长度、data structure type（数据结构类型）和字段序列组成。实现注册后必须从实际 OpenWire 版本字段表生成，不能把 AMQP frame header、STOMP line 或 Java serialization（Java 序列化）头混入。

逻辑布局为：

```text
CommandLength | DataStructureType | CommandFields | optional frame terminator
```

具体 `CommandLength` 宽度、type 编号、tight encoding（紧凑编码）、boolean packing（布尔打包）、short/long string、cached object reference（缓存对象引用）和字段顺序必须由 `profile` 确定。长度必须覆盖协议定义的 command bytes，不得因 TCP 分段重算。未知 type、长度小于最小 command、长度越过 stream、声明长度与 body 不一致必须失败。

常见逻辑命令及关联：

| 命令 | 方向/状态 | 必须关联 |
|---|---|---|
| `WireFormatInfo` | 双向协商首阶段 | version、tight/cache/max frame |
| `ConnectionInfo` | client→broker | connection ID、client identity |
| `ConnectionInfo` response/ack | broker→client | 同一 connection |
| `SessionInfo` | client→broker | connection ID、session ID |
| `ProducerInfo`/`ConsumerInfo` | client→broker | session ID、producer/consumer ID、destination |
| `Message` | client→broker | producer/session、message ID、destination、persistent/transaction |
| `MessageDispatch` | broker→client | consumer/session、message ID、destination、redelivery |
| `MessageAck` | client→broker | consumer/session、message ID、ack mode |
| `TransactionInfo` | 双向 | connection/session、transaction ID、begin/commit/rollback |
| `Response`/`ExceptionResponse` | broker→client | correlation/request command ID、success/error |
| `RemoveInfo`/`ShutdownInfo` | 双向/终止 | entity/connection ID、终止状态 |

字符串、destination、ID 和 body 的长度/编码必须严格遵循 profile；任意未声明字段不得依赖默认值。动态 ID 不写死 frames，使用 `same_as_packet` 或 nonzero（非零）观察。

## 5. 连接与 session 状态机

推荐的单连接序列：

```text
TCP SYN/SYN-ACK/ACK
  → WireFormatInfo 双向协商
  → ConnectionInfo
  ← ConnectionInfo response/ack
  → SessionInfo
  → ProducerInfo / ConsumerInfo
  → Message / MessageDispatch / MessageAck
  → TransactionInfo commit/rollback（如显式）
  → RemoveInfo / ShutdownInfo
  → TCP FIN/ACK
```

状态不变式：

| 状态 | 允许事件 | 必须保持 |
|---|---|---|
| `TransportReady` | `wire_format_info` | 必须是首个 OpenWire command，版本/profile 一致 |
| `Negotiating` | 对端 WireFormatInfo、ConnectionInfo | 协商字段兼容；连接 ID 不漂移 |
| `Connected` | `session_info`、connection close | connection 已建立；实体表独立 |
| `SessionOpen` | producer/consumer、transaction | session ID 存在且属于当前 connection |
| `Streaming` | message/dispatch/ack、heartbeat | producer/consumer、destination、message ID 关联 |
| `Transactional` | begin、message、ack、commit/rollback | transaction ID 不跨 session；终止只发生一次 |
| `Closing` | remove/shutdown/response | 关闭后不得生成新业务 command；最终 TCP termination |
| `Error` | malformed、长度/关联/状态错误 | planner/validator → engine（引擎）→ task error；不得 completed/0 packet |

每个连接有独立 wire format、connection/session/entity/message/transaction 状态。多连接的 command 调度不保证交错顺序；验证应使用 tcp.stream、源端口 distinct（不同）或同包关联字段，不硬编码跨连接 packet index。

## 6. Message、ACK、持久化与事务

`Message` 必须引用已存在的 producer/session 和 destination，并明确 message ID、body、persistent、priority/expiration 等声明属性。`MessageDispatch` 只能引用已注册 consumer/session 和既有 message；redelivery 是显式字段，不能因重复 body 自动推断。`MessageAck` 的 ack mode、consumer、message ID 和 transaction 作用域必须一致；未知 message ACK、跨 consumer ACK、重复 individual ACK 按 profile 拒绝或显式幂等。

持久化标志只表示 command 中的 persistent property；它不证明 broker 磁盘写入。事务必须显式 begin→message/ack→commit 或 rollback；commit/rollback 后不能追加同一 transaction 的 command。跨 session transaction、重复 commit、无 begin 的 commit、rollback 后重用事务 ID 和事务内 ACK 作用域错误均为 task error。

多流由同一连接内多个 session/producer/consumer 或多个 destination 表达。每个 entity 的 message ID、ack 和 transaction 关联独立；不能把 queue/topic 名称当作全局 session ID。多会话应在同一 TCP 连接内验证 session 状态隔离；多连接状态隔离另由独立 TCP 四元组覆盖。

## 7. IPv4/IPv6 和边界

IPv4 外层 EtherType 为 `0x0800`；IPv6 外层 EtherType 为 `0x86dd`，TCP Next Header（下一头）为 6。相同 OpenWire fixture 在 IPv4/IPv6 中协议版本、command type、字段顺序、长度和 payload bytes 必须一致，仅外层地址族与 payload offset 改变；不要在同一 layer-chain 顶层 IPv4 配置中混入 session 级 IPv6。

边界至少覆盖：最小 WireFormatInfo、frame length=最小值、空 Message body、body 跨多个 TCP segments、short string 长度 0/255/256（256 应按 profile 拒绝）、destination 为空、重复/越界 command ID、transaction 空/重复终止、unknown command type、长度加法溢出和最大明确可分配 body。不得默认分配超大 body；任何 uint32/uint64 溢出必须失败而不能回绕。

## 8. 错误处理与实现集成点

以下输入必须由 planner/validator 拒绝并传播为 task error：未知 profile/command、非 TCP carrier、错误端口/地址、WireFormatInfo 缺失或版本不兼容、command length 越界、实体未建立、session/producer/consumer 跨 connection、destination 非法、message/dispatch/ack correlation 错误、transaction 状态回退、commit/rollback 重复、close 后继续发送和非法 short string/body length。

合法 redelivery、业务 exception response、持久化属性、transaction rollback 和 broker shutdown 是协议事件正例，不应被验证器误报为 planner 错误；它们与 malformed input task error 分层。

实现时应：

1. 在 layer registry 登记 `openwire` 为 TCP terminal layer，自动补 `ip→tcp`；当前未注册阶段只保留 `openwire_neg_unregistered` 前置占位，不计入 24 个语义 ID；
2. 在 core/types.go 和 strategy converter（策略转换器）增加 profile/connection/session/entity/event 配置，保留显式 bytes；
3. 新增 OpenWire planner/generator，复用 TCP handshake、MSS segmentation 和 IPv4/IPv6 builder，不能复用 AMQP frame parser；
4. 按 connection→session→entity 建立状态，编码 WireFormatInfo、command length/type、message/ack/transaction 和 close；
5. 将 planner 错误接入 task 生命周期；实现前禁止把语义正例加入可执行 suite；
6. 先做逐字节 frame/type/length/correlation 单测，再做 planner→worker→TCP PCAP/NIC（网卡）全链路测试和 `-race`（竞态检测）。

## 9. 场景与三方 ID

共 25 个唯一 ID：15 个目标正例、9 个目标负例，以及 1 个未注册层前置占位。当前 JSON 仅包含该占位，统一 `expect_error=true`、`error_contains=unknown layer`；实现后前 15 项改为 PCAP 断言，后 9 项保留严格 Validate（校验）负例。

| # | ID | 类型 | 覆盖 |
|---:|---|---|---|
| 1 | `openwire_wire_format_ipv4` | 正 | IPv4 WireFormatInfo 协商与首 command |
| 2 | `openwire_wire_format_ipv6` | 正 | IPv6/TCP 协商、Next Header=6 |
| 3 | `openwire_connection_session` | 正 | ConnectionInfo、SessionInfo 生命周期 |
| 4 | `openwire_producer_consumer` | 正 | ProducerInfo、ConsumerInfo、destination |
| 5 | `openwire_message_persistent` | 正 | Message、persistent 属性、body |
| 6 | `openwire_dispatch_ack` | 正 | MessageDispatch、MessageAck、correlation |
| 7 | `openwire_transaction_commit` | 正 | begin→message→commit |
| 8 | `openwire_transaction_rollback` | 正 | begin→message→rollback |
| 9 | `openwire_multi_flow` | 正 | 多 session/producer/consumer/destination |
| 10 | `openwire_multi_connection` | 正 | 多 TCP 连接和状态隔离 |
| 11 | `openwire_message_body_segmentation` | 正 | body 跨 TCP segments、重组长度 |
| 12 | `openwire_exception_response` | 正 | ExceptionResponse 与 request correlation |
| 13 | `openwire_remove_shutdown` | 正 | RemoveInfo、ShutdownInfo 生命周期 |
| 14 | `openwire_ipv4_ipv6_same_payload` | 正 | 独立双栈 fixture、逻辑 payload 一致 |
| 15 | `openwire_ack_modes` | 正 | auto/client/individual ACK 边界 |
| 16 | `openwire_neg_short_frame` | 负 | command header/length 截断 |
| 17 | `openwire_neg_unknown_command` | 负 | 未知 data structure type |
| 18 | `openwire_neg_length_overrun` | 负 | command length 越界/溢出 |
| 19 | `openwire_neg_state_order` | 负 | 未协商/未建 session 先发业务 command |
| 20 | `openwire_neg_correlation` | 负 | response/ack/message 跨实体关联 |
| 21 | `openwire_neg_transaction` | 负 | commit/rollback 重复或跨 session |
| 22 | `openwire_neg_entity_scope` | 负 | producer/consumer/session 跨 connection |
| 23 | `openwire_neg_destination` | 负 | queue/topic/destination 非法 |
| 24 | `openwire_neg_carrier_profile` | 负 | 非 TCP、错误端口或 profile 不兼容 |

## 10. 修订记录

- v1.0.0（2026-08-20）：建立 OpenWire TCP、WireFormatInfo、连接/session、producer/consumer、message/dispatch/ack、事务、持久化、多连接/多流、IPv4/IPv6、边界和负路径设计；当前仅提交设计/用例契约，不修改 Go 实现。

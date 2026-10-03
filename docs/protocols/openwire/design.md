# OpenWire 设计契约（as-built 审计版）

> 版本：v2.1.0（2026-10-01）  
> 范围：仅本文件、`testcase.md`、`trafficgen/test/protocol_pcap/cases/openwire.json`。  
> 结论：当前 OpenWire 仍走 **flat 业务配置 + `[tcp, openwire]` 层链**；本轮不伪造迁移为严格层链，不修改 Go/schema。

## 1. 范围和权威事实

OpenWire 是 ActiveMQ 的明文二进制 TCP 协议。当前实现覆盖 loose、non-cached 的合成线格式：WireFormatInfo、Connection/Session、Producer/Consumer、Message、Dispatch/Ack、Transaction、Response/Exception、Remove/Shutdown。默认 TCP 目的端口为 61616。

代码证据：

- `trafficgen/internal/core/types.go:834-928`：`OpenWireConfig`、连接、事件、事务和三种 `wire_fault`。
- `trafficgen/internal/core/layers/registry.go:1749-1755`：终结层依赖 `tcp`，Fields **仅有 `profile`**，FieldContract 为 `tcp.dst_port=61616`。
- `trafficgen/internal/core/layers/chain_planner_translate.go:756` 起：没有 OpenWire 层配置到 `spec.OpenWire` 的翻译分支；配置经 `spec.OpenWire` 直传。
- `trafficgen/internal/core/strategy_convert.go:1467-1475`：flat `openwire` 子映射解析到 `spec.OpenWire`。
- `trafficgen/internal/protocol/openwire/layer_gen.go`、`builder.go`：事件校验、编码、TCP 自驱路径。

因此当前 JSON 的真实可表达形状是：`layers` 仅声明 `tcp`/`openwire`，地址、端口和完整 `openwire` 业务对象仍在 `spec_json` 顶层。严格层链 `{layers:[ip,tcp,openwire]}` 且业务键放入 `layers[].openwire` 会因 registry unknown field 或缺少 translate 而失败，登记为 `G-OW-1`，不在本轮改 cases 冒充迁移完成。

## 2. as-built 配置形状

```json
{
  "layers": [{"tcp": {}}, {"openwire": {}}],
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.20",
  "src_port": 40001,
  "dst_port": 61616,
  "openwire": {
    "profile": "activemq_openwire_v12",
    "connections": [{
      "connection_id": 1,
      "client_id": "client-a",
      "src_port": 40001,
      "events": [{"kind": "wire_format_info", "direction": "c2s"}]
    }]
  }
}
```

这是当前 `openwire.json` 24 条 case 的共同形状：24/24 可解析，`layers` 顺序为 `tcp → openwire`，旧 flat 地址/端口/业务字段尚未迁移。该形状不满足 CORE §1 的最终层链门，不能写成“严格层链已完成”。

### 2.1 实现字段清单

| 位置 | 当前支持 | 证据/边界 |
|---|---|---|
| `profile` | `activemq_openwire_v12`、`activemq_openwire_legacy`、空值缺省 v12 | `ValidateConfig`；未知 profile 拒绝 |
| `wire_format.version` | 缺省 12；编码为 loose | `builder.go:204-211` |
| `tight_encoding`、`cache_enabled` | `true` 拒绝 | `layer_gen.go:671-677` |
| `connections[]`、`events[]` | 显式连接与有序事件 | 每连接独立状态表 |
| 事件 kind | wire format、connection/session、producer/consumer、message/dispatch/ack、transaction、response/exception、remove/shutdown | 未知 kind 拒绝 |
| destination | `queue://name`、`topic://name` | 空名/其他 scheme 拒绝 |
| `ack_mode` | auto/client/individual/dups_ok | 生成器映射 0/2/3/0 |
| body/body_b64 | 二选一语义，按 TCP MSS 分段 | 不声称 broker 持久化 |
| `wire_fault.kind` | short_frame、bad_type、length_overrun | 注入即 task error |

## 3. 连接、事件与错误状态

单连接事件顺序由 `validateConnection` 校验：首个事件必须 WireFormatInfo；ConnectionInfo 建立连接；SessionInfo 建立 session；实体、消息、事务按引用关系校验；Remove/Shutdown 后不允许新业务事件。Dispatch/Ack 必须引用已知 message，Response/Exception 的显式 correlation 必须命中已发出的 client command。

TCP 事件路径由 TCP 层负责握手、MSS 分段和挥手；显式连接地址（`connections[].src_ip/dst_ip`）触发 OpenWire 自驱路径，生成器自行产出完整 TCP 包。该双栈自驱分支已在代码单测覆盖，但 PCAP 运行证据仍属 `G-OW-2`。

错误必须传播为 task error，不得以 completed/0 packet 或只含 ACK 的结果冒充负例通过。当前稳定错误锚词来自实现：`frame`、`length`、`command`、`type`、`state`、`session`、`correlation`、`message`、`transaction`、`entity`、`connection`、`destination`、`port`、`profile`。

## 4. 规范要求 → 场景 → 代码 → 缺口（D1）

| 规范/行为面 | 业务场景 | 代码现状 | 结论/缺口 |
|---|---|---|---|
| TCP 长连接、WireFormatInfo 首 command | 建连协商 | `validateConnection` + `BuildWireFormatInfo` | 正例 1、2；PCAP 待 G-OW-2 |
| Connection/Session 生命周期 | 建连、建 session | `connState` | 正例 3、9、10；现网互通未确认 |
| Producer/Consumer/destination | 注册实体、queue/topic | `destinationParts`、实体表 | 正例 4、9、15；负例 23 |
| Message/Dispatch/Ack 关联 | 投递、dispatch、确认 | `messages` 与 consumer 表 | 正例 5、6、15；负例 20 |
| Transaction begin/commit/rollback | 事务提交/回滚 | `txOpen/txDone` | 正例 7、8；负例 21 |
| length/type/body | 帧编码、跨 MSS | `frameCommand`、builder | 正例 11；负例 16–18 |
| Exception/Remove/Shutdown | 业务异常与关闭 | 对应 builder/state | 正例 12、13；状态负例 19 |
| IPv4/IPv6 | 两种外层地址族 | 自驱读取连接地址 | 正例 2、14；PCAP 待 G-OW-2 |
| TLS/WebSocket/压缩/selector/集群 | 非本 profile | 无对应实现/解密证据 | G-OW-3，不纳入明文覆盖 |

## 5. 三张审计子表（D2）

### 5.1 命令/结果矩阵

| 命令结果 | 成功 | 错误 | cases |
|---|---|---|---|
| WireFormatInfo | v12 协商 | 缺失/未知 profile | 1、2、16、24 |
| Connection/Session | 建立并关联 | 未建立、跨 scope | 3、19、22 |
| Producer/Consumer | 实体注册 | 非法 session/destination | 4、23 |
| Message/Dispatch/Ack | message correlation | 未知实体/message | 5、6、20 |
| Transaction | begin→commit/rollback | 无 begin/重复终止 | 7、8、21 |
| Response/Exception | correlation | 未知 correlation | 12、20 |
| Remove/Shutdown | 终止 | close 后新 command | 13、19 |

### 5.2 数据形态矩阵

| 形态 | 覆盖 | 现状 |
|---|---|---|
| IPv4/IPv6 | 1、2、14 | 有自驱生成器；未跑 PCAP |
| 单连接多事件/事务 | 3–9、15 | 有显式 events 状态机 |
| 多 TCP 连接 | 10、14 | 连接级源端口/地址；未跑 PCAP |
| 长 body/TCP 分段 | 5、11 | 有 body builder 与 MSS；长度需复跑校准 |
| queue/topic、ACK mode | 4、6、15、23 | 已实现固定枚举 |
| malformed frame/type/length | 16–18 | 仅 validator 注入拒绝，不构造坏 PCAP |
| TLS/WebSocket/压缩 | 无 | G-OW-3 |

### 5.3 商业行为→用例映射

| 行为 | cases | 证据状态 |
|---|---|---|
| ActiveMQ 默认 61616/WireFormatInfo | 1、2 | 代码与协议资料；真实 broker 抓包待确认 |
| 同连接建立 session、实体并投递 | 3–6、9、15 | generator 事件链；现网待确认 |
| commit/rollback | 7、8 | generator 状态机；版本差异待确认 |
| 多连接隔离 | 10、14 | 代码连接状态；现网待确认 |
| exception/graceful shutdown | 12、13 | builder/state；现网字段待确认 |

## 6. D3–D8 实现契约

| ID | 结论 |
|---|---|
| D3 依赖/错误 | 依赖 TCP、profile、连接/session/entity 状态；失败返回 task error，中断，不重试配置错误。 |
| D4 性能 | 事件逐条流式编码；body 在事件级编码后交给 TCP MSS 分段；不承诺未经测量的吞吐/内存数字。 |
| D5 八要素 | 文件、接口、结构、流程、错误、边界、冲突、回滚均以当前实现为准；仅三份契约文件可回滚。 |
| D6 动态 | 当前 cases 仅固定值；registry/layer_dyn 未开放 OpenWire 业务动态字段，`flows`/inc/rand/list/pattern 登记 G-OW-4。 |
| D7 层链门 | 当前不是严格层链：地址/端口/业务仍 flat；严格迁移依赖 registry Fields + translate，不在本轮伪造。 |
| D8 真实流程 | 本轮不跑 suite/server/MCP/NIC；PCAP 数值和 dissector 结果不得宣称已验证，登记 G-OW-2。 |

## 7. 缺口登记

| 缺口 | 现象与证据 | 收口方式 |
|---|---|---|
| G-OW-1 | registry 的 OpenWire Fields 只有 `profile`，translate 无 OpenWire 分支；业务键进 `layers[].openwire` 会 unknown field/缺配置 | 代码阶段补 Fields、translate、schema 生成并逐例迁移；不得登记保留豁免 |
| G-OW-2 | 本轮明确未跑 suite/server/PCAP/NIC；packet_count、帧锚和 IPv6 自驱仅来自静态旧证据 | 真实流程跑通后按实际 pcap 重钉；此前不宣称 PASS |
| G-OW-3 | TLS/WebSocket/压缩/selector/集群没有当前明文 profile 或解密证据 | 独立承载/解密方案与证据后另立范围 |
| G-OW-4 | `flows>1` 及业务字段动态策略没有 OpenWire schema/layer_dyn 入口 | 代码补字段后逐策略整格用例；当前不冒充动态覆盖 |
| G-OW-5 | 当前无真实 ActiveMQ broker/版本抓包，商业行为映射只有规范与代码证据 | 搭 ActiveMQ 版本矩阵抓包，逐行为回指 case |

## 8. 六项静态审查（C1–C6）

| ID | 结论 |
|---|---|
| C1 | JSON 可解析，24 个 ID 唯一；design/testcase/JSON 顺序一致。 |
| C2 | 当前 24 条均为 as-built flat 形，不能声称层链迁移完成；旧键保留事实已登记 G-OW-1。 |
| C3 | `layers` 当前为 `[tcp, openwire]`；地址/端口/业务由 flat spec 携带，未伪造严格层链。 |
| C4 | 15 条正例保留可观察 expect；9 条负例 expect **严格仅 `expect_error` 与 `error_contains` 两键**，锚词来自实现。 |
| C5 | 多连接、事务、分段、ACK、异常和关闭均有独立 ID；未支持动态/承载变体已登记 G-*。 |
| C6 | 本轮只允许三文件范围；不改 Go、schema、LAYERCHAIN_INDEX 或其他协议。 |

## 9. 修订记录

- v2.1.0（2026-10-01）：按当前 registry/translate/generator 和 JSON as-built 重审；撤销“严格层链已迁移”虚假结论，补 D1–D8、三张矩阵、G-OW-1…5 与 C1–C6。
- v2.0.0（历史草稿）：曾把未被当前 schema/translate 支持的业务层链写成已完成，现以本版 as-built 审计为准。

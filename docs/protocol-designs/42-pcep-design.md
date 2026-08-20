# PCEP（路径计算元素通信协议，Path Computation Element communication Protocol）设计契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：仅设计与用例契约；不修改 Go（编程语言）实现，不宣称 `pcep` 层已注册或当前 PCAP（抓包文件）套件可运行。
> 配套文件：`docs/protocol-designs/42-pcep-testcase.md`、`trafficgen/test/protocol_pcap/cases/pcep.json`、`docs/protocol-designs/audit/42-pcep-adversarial-audit.md`
> 规范基线：RFC 5440（PCEP，TCP 4189）、RFC 8231（stateful PCE，有状态 PCE）、RFC 8281（PCE-initiated LSP/delegation，PCE 发起 LSP/委托）。

## 1. 范围、profile 边界与证据等级

本版定义 RFC 5440 的 PCEP 基础会话：TCP destination port（目的端口）4189、Open、Keepalive、PCReq、PCRep、PCNtf 和 PCErr；覆盖 IPv4 与 IPv6 endpoint（端点）地址族、PCEP common header（公共头）、message length（消息长度）、object header（对象头）、request/session 关联、LSP/ERO/RRO/Metric 和对象 flags（标志）。每个显式 PCEP event（事件）对应一个 TCP application payload（应用载荷）；planner（规划器）不自动补 Open、Keepalive、响应、重试或 teardown（拆除）之外的消息。

| profile | 规范范围 | 允许内容 | 明确不从本版推导 |
|---|---|---|---|
| `pcep_rfc5440_ipv4` | RFC 5440 IPv4 RSVP-TE endpoint | Open、Keepalive、PCReq、PCRep、PCNtf、PCErr；IPv4 END-POINT、ERO/RRO、Metric | 真实 CSPF、RSVP 状态、路由计算结果 |
| `pcep_rfc5440_ipv6` | RFC 5440 IPv6 endpoint | 同上；IPv6 END-POINT、IPv6 ERO/RRO subobject | 把 IPv6 地址压缩/改写成 IPv4，或混用地址族 |
| `pcep_rfc8231_stateful` | RFC 8231 stateful extension（有状态扩展） | 仅显式声明的 LSP/SRP/同步语义；必须同时标注 RFC 5440 base session | 自动维护 LSP 数据库、自动同步、隐式 PCUpd/PCInitiate |
| `pcep_rfc8281_delegation` | RFC 8281 delegation/profile（委托档案） | 显式 LSP delegate/remove/create flags 与 SRP；必须在 stateful profile 上声明 | 把 delegate flag 当作 RFC 5440 基础能力，或自动发起 LSP |
| `pcep_unknown_extension` | 未注册扩展 | 不生成 | 未知消息/对象/扩展 TLV 的成功 PCAP |

RFC 8231/RFC 8281 只作为显式 profile 边界；基础 `pcep_rfc5440_*` 不接受 LSP/SRP 的 stateful-only 字段。RFC 8281 的 delegation 是 LSP object/SRP flags 的语义，不新增一个虚构的 message type。若实现尚未注册扩展 profile，相关 JSON 正例按设计契约保留，不能报告为已运行通过。

不变式：

1. PCEP 只能位于 `tcp` 后，TCP destination port 必须为 4189；正例无 UDP/裸 IP 载体。
2. TCP stream（字节流）中的每条 PCEP message 从 common header 开始：Version/Flags、Message-Type、Message Length；Version=1 的 version bit 为 `0x20`，Flags 保留位为零。
3. Message Length 是从 common header 起始到该 PCEP message 末尾的总长度，最小为 4；长度必须与 TCP stream 中实际消息边界一致，不以 Ethernet padding（填充）或 TCP segment length 冒充。
4. 每个 object 的四字节 object header 含 Object-Class、Object-Type/flags 和 Object-Length；Object-Length 至少为 4、必须按 4 字节对齐，并且不得越过 message length。
5. `session_id` 只作为会话关联元数据；RFC 5440 OPEN object 的 SID（session ID）若显式写在线上，必须在同一会话内一致，跨会话隔离。
6. request ID、LSP PLSP-ID、SRP-ID 和 endpoint 地址均按事件显式配置；不从前一条请求静默继承。
7. planner/validator（校验器）错误必须传播为 task error（任务错误）终态，不能 completed（完成）但 0 包。

## 2. 层链、TCP 方向与公共配置

推荐层链：

```json
{
  "layers": [{"tcp": {}}, {"pcep": {}}],
  "src_ip": "192.0.2.10",
  "dst_ip": "192.0.2.20",
  "src_port": 40000,
  "dst_port": 4189,
  "pcep": {
    "profile": "pcep_rfc5440_ipv4",
    "events": [
      {"kind": "open", "direction": "c2s", "keepalive": 30, "deadtime": 120, "sid": 7},
      {"kind": "keepalive", "direction": "s2c"}
    ]
  }
}
```

| 键 | 约束 | 语义 |
|---|---|---|
| `profile` | 四个已列 profile | 选择地址族和扩展边界，不写入 common header |
| `events` | 非空有序数组 | 每项生成一个 PCEP application message |
| `kind` | `open`、`keepalive`、`pcreq`、`pcrep`、`pcntf`、`pcerr`；扩展显式 `pcupd`/`pcinitiate` | 与 RFC message type 一一对应，不自动补响应 |
| `direction` | `c2s` 或 `s2c` | TCP stream 方向；PCC→PCE 或 PCE→PCC 仅由事件显式指定 |
| `sid`/`session_id` | 0–255 的显式整数/会话键 | Open SID 和会话关联；同一 session 不得漂移 |
| `request_id` | 32-bit | PCReq/PCRep/PCNtf/错误关联的 request ID |
| `endpoint` | IPv4 或 IPv6 source/destination | 由 profile 决定；不能同时填写两族 |
| `objects` | 有序 object 数组 | 每个对象含 class/type/flags/body；编码后回填 object length |
| `wire_fault` | 仅负例 | `length`、`type`、`object_length`、`keepalive`、`session`、`address_family` 等错误注入，不是合法字段 |

TCP MSS 分段不改变 PCEP message 边界；若一个 message 被拆到多个 TCP segment，PCAP 断言必须在重组后的 PCEP packet 上观察。TCP direction 不得用交换 src/dst 端口后再猜测事件方向。

## 3. RFC 5440 common header、长度与对象

### 3.1 Common header

PCEP message 的四字节 common header 为：

```text
byte 0: Version（高 3 bit）| Flags（低 5 bit）；Version=1 => 0x20
byte 1: Message-Type
byte 2..3: Message Length（network byte order，含 common header）
```

本版使用的 message type（消息类型）为：

| Type | 名称 |
|---:|---|
| 1 | Open |
| 2 | Keepalive |
| 3 | PCErr |
| 4 | PCNtf |
| 6 | PCReq |
| 7 | PCRep |
| 10 | PCUpd（仅 RFC 8231 profile） |
| 12 | PCInitiate（仅 RFC 8231/RFC 8281 profile） |

正例无 IPv4 option、无 VLAN，TCP payload 起点固定为 offset 54（Ethernet 14 + IPv4 20 + TCP 20）。所有 `frames` 从 offset 54 断言 common header 的已确认字节，例如 Open `20 01 00 10`、Keepalive `20 02 00 04`；具体对象长 body 的完整十六进制由实现 fixture（固定样本）另行绑定，不在设计阶段猜测。

### 3.2 Message/Object length

Message Length 包括 common header 和全部 objects；Keepalive 固定为 4。Open 通常为 16（4-byte common header + 12-byte OPEN object），但用例同时要求 `pcep.msg_length` 可观察而不是只信固定常量。一个消息中可含多个 objects，编码顺序必须保持配置顺序。

Object header 的长度为 4 字节，`Object-Length` 包含 object header；Object-Class、Object-Type 和 P/I flags 必须和对应 object body 匹配。以下错误必须拒绝：message length 小于 4、声明长度大于 TCP stream 剩余字节、object length 小于 4、object length 非 4 字节对齐、object length 越过 message boundary、未知 class/type 或 object 与 message kind 不匹配。

### 3.3 Checksum/length 证据

PCEP 不在 RFC 5440 common header 中使用独立 checksum；TCP checksum 由 TCP 层负责。不要虚构 `pcep.checksum` 字段或把 TCP checksum 当 PCEP 字段。正例 fields 只使用 `tshark -G fields` 已注册字段，长度使用 `pcep.msg_length`/`pcep.object_length`；负例只检查错误传播。

## 4. RFC 5440 消息与对象语义

### 4.1 Open/Keepalive/session

OPEN object 使用注册字段 `pcep.obj.open.pcep_version`、`pcep.obj.open.flags`、`pcep.obj.open.keepalive`、`pcep.obj.open.deadtime`、`pcep.obj.open.sid`。Open 的 Keepalive/DeadTimer 是会话参数，不代表 planner 自动插入周期性 Keepalive。Keepalive message 不带 object，且必须是 common header 长度 4。会话中的两个方向 Open 应各自显式配置；SID 不是从 TCP 端口推导的随机值。

### 4.2 PCReq/PCRep

PCReq 至少含 RP（Request Parameters）、END-POINT、可选 BANDWIDTH、ERO、RRO、Metric、LSPA 等对象；PCRep 以 request ID 关联响应，可含 NO-PATH 或路径对象。字段断言使用已注册的 `pcep.obj.rp.*`、`pcep.request_id`、`pcep.obj.end_point.*`、`pcep.obj.bandwidth`、`pcep.obj.metric.*` 和 `pcep.obj.ero/rro.*`。请求与响应必须按 `request_id` 关联，但未提供成功路径计算器时不宣称 cost/path correctness（路径正确性）。

ERO/RRO 的 IPv4/IPv6 subobject 必须保留 L（loose，松散）/X/flags/attribute、prefix length 和地址族；IPv4 profile 不得出现 IPv6 subobject，反之亦然。Metric 的 type、flags（Cost/Bound）和 IEEE float metric value 必须独立编码，不把 metric 当作 bandwidth。

### 4.3 PCNtf/PCErr

PCNtf 用 Notification object，使用已注册的 `pcep.obj.notification.type` 和 `.value`；通知不是 PCRep 的隐式响应。PCErr 使用 PCEP-ERROR object，`pcep.error.type`/`pcep.error.value` 表示错误码，`pcep.obj.error.type` 是对象类型字段；两者不应混淆。错误事件仍是一个正常方向的 PCEP message，只有 `wire_fault`/非法配置才要求 task error。

## 5. RFC 8231 stateful 与 RFC 8281 delegation profile

`pcep_rfc8231_stateful` 是显式扩展 profile，基础 Open/Keepalive/PCReq/PCRep/PCErr 仍采用 RFC 5440 common header；LSP object 使用 `pcep.obj.lsp.plsp-id`、`pcep.obj.lsp.flags.*`，SRP object 使用 `pcep.obj.srp.id-number`、`.flags.*`。扩展能力 TLV 的注册字段（例如 `pcep.stateful-pce-capability.*`）只有在配置声明 capability 时才出现。此 profile 不自动维护数据库、同步所有 LSP 或生成 PCUpd/PCInitiate。

`pcep_rfc8281_delegation` 必须嵌套/声明 stateful capability；delegate/remove/create/administrative/operational flags 只表达显式 LSP/SRP 事件。RFC 8281 不改变 RFC 5440 的 Open/Keepalive 基本格式，也不允许在 base profile 中静默接受 delegate flag。扩展正例只验证注册的 LSP/SRP 字段和 profile metadata；任何未注册扩展对象仍走负例。

## 6. IPv4/IPv6、multi-request 与 multi-session

IPv4 profile 使用 `pcep.obj.end_point.source_ipv4_address`/`destination_ipv4_address` 及 `pcep.subobj.ipv4.ipv4`；IPv6 profile 使用对应 IPv6 字段和 `pcep.subobj.ipv6.ipv6`。endpoint、ERO、RRO 的地址族必须一致；混用、缺失或将 IPv6 压入 IPv4 object 都是 address-family 错误。

`multi_request` 在同一 TCP session 中按显式事件发送多个 PCReq，再发送 request_id 对应的多个 PCRep；每一请求独立携带 endpoint/metric/ERO，不能复用前一个请求对象。`sessions` 是多个独立 TCP 4189 flows，每个 flow 有自己的端口、SID、Open 和 teardown；会话之间的 SID/request ID 不得串联。每个 flow 的 packet count（包数）包括 3-way handshake、显式 application messages 和四包 TCP teardown。

## 7. 负例与错误传播

| ID | 故障 | 稳定错误锚点 |
|---|---|---|
| `pcep_neg_malformed_length` | common/message length 小于 4、截断或超出 TCP stream | `length` |
| `pcep_neg_unknown_type` | 未知 message type 或 kind/type 不一致 | `type` |
| `pcep_neg_object_length` | object length 小于 4、非 4 对齐或越过 message | `object` |
| `pcep_neg_keepalive` | Keepalive 带 object、长度非 4 或字段错误 | `keepalive` |
| `pcep_neg_session_id` | 同一 session 两个 Open SID 不一致/响应跨 SID | `session` |
| `pcep_neg_address_family` | IPv4 profile 携 IPv6 或 endpoint/ERO/RRO 混族 | `address` |
| `pcep_neg_stateful_without_profile` | base RFC 5440 profile 携 LSP/SRP/delegate | `stateful` |

所有负例 JSON 的 `expect` 严格只有 `expect_error` 与 `error_contains`；不得以成功但 0 packet、忽略损坏字段或一条 TCP ACK 满足断言。

## 8. 24 个场景与完成定义

| # | ID | 类型 | 覆盖 | application events | packet_count |
|---:|---|---|---|---:|---:|
| 1 | `pcep_open_keepalive` | 正 | Open、Keepalive、SID、common length | 3 | 10 |
| 2 | `pcep_open_bidirectional` | 正 | 双向 Open/Keepalive 与 TCP direction | 4 | 11 |
| 3 | `pcep_keepalive_direction` | 正 | 两方向 Keepalive 不自动补发 | 6 | 13 |
| 4 | `pcep_pcreq_ipv4_ero_metric` | 正 | IPv4 PCReq、RP/endpoint/ERO/metric | 4 | 11 |
| 5 | `pcep_pcrep_ipv4_ero_rro` | 正 | IPv4 PCRep、RRO/metric/request ID | 4 | 11 |
| 6 | `pcep_pcntf_and_pcerr` | 正 | PCNtf、PCErr、notification/error | 6 | 13 |
| 7 | `pcep_multi_request` | 正 | 多 request/response、request ID 隔离 | 7 | 14 |
| 8 | `pcep_ipv6_address_family` | 正 | IPv6 endpoint/ERO/RRO | 4 | 11 |
| 9 | `pcep_lsp_object_flags` | 正 | RFC 8231 LSP/SRP、PLSP-ID | 4 | 11 |
| 10 | `pcep_rro_ipv4_ipv6` | 正 | 单 profile 内 route subobject flags | 4 | 11 |
| 11 | `pcep_metric_flags` | 正 | Cost/Bound 与 metric value | 4 | 11 |
| 12 | `pcep_tcp_direction` | 正 | c2s/s2c、4189 端口方向 | 5 | 12 |
| 13 | `pcep_multi_session` | 正 | 两个独立 TCP sessions/SID | 8 | 22 |
| 14 | `pcep_stateful_rfc8231_profile` | 正 | stateful capability profile 边界 | 3 | 10 |
| 15 | `pcep_delegation_rfc8281_profile` | 正 | delegation flags（delegate/create/remove 分离事件） | 3 | 10 |
| 16 | `pcep_common_header_length` | 正 | version/type/message length | 4 | 11 |
| 17 | `pcep_object_flags` | 正 | P/I object flags、LSPA flags | 3 | 10 |
| 18–24 | `pcep_neg_*` | 负 | length/type/object/keepalive/session/address/stateful | — | — |

完成定义：层注册 `tcp→pcep` 且默认 destination port 4189；实现 common header、消息/对象长度边界和 TCP reassembly（重组）；实现六类 RFC 5440 message 及 IPv4/IPv6 endpoint/ERO/RRO/metric；正例逐项覆盖 24 IDs 的 fields/frames；负例从 planner→engine→task error 传播；stateful/delegation 只有显式 profile 才开放；未注册扩展不被伪装成成功基础 PCEP。

## 9. 修订记录

- v1.0.0（2026-08-20）：建立 17 个 RFC 5440 正例和 7 个严格负例，覆盖 TCP 4189、common/message/object length、Open/Keepalive/PCReq/PCRep/PCNtf/PCErr、LSP/ERO/RRO/Metric/flags、IPv4/IPv6、多 request、多 session、方向和 RFC 8231/8281 profile 边界。

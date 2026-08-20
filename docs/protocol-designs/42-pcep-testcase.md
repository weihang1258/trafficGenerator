# PCEP（路径计算元素通信协议，Path Computation Element communication Protocol）测试用例设计

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/42-pcep-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/pcep.json`
> 状态：`pcep` 层尚未实现；本文定义未来实现后的 PCAP 断言，不宣称当前套件可运行。

## 1. 测试原则与 tshark 字段证据

本套件由设计文档 §1–§7 逐项派生，共 24 个唯一 ID：17 个正例、7 个负例，三份文档和 JSON 顺序完全一致。PCEP 使用 TCP/4189，不是 UDP 或裸 IP；无 VLAN、无 IPv4 options、TCP 无 options 的正例中，TCP application payload 起点固定为 offset 54。每个正例都必须有 `packet_count`、`fields` 和 `frames`；每个负例的 `expect` 严格只有 `expect_error`、`error_contains`。

在写入 JSON 前执行：

```text
tshark -G fields | grep '\tpcep\.'
```

本版 JSON 的正例字段只选自该命令已注册的字段：`pcep.msg`、`pcep.version`、`pcep.flags`、`pcep.msg_length`、`pcep.object_type`、`pcep.object_length`、`pcep.request_id`、`pcep.obj.open.*`、`pcep.obj.rp.*`、`pcep.obj.end_point.*`、`pcep.subobj.ipv4.*`、`pcep.subobj.ipv6.*`、`pcep.obj.metric.*`、`pcep.obj.notification.*`、`pcep.error.*`、`pcep.obj.lsp.*`、`pcep.obj.srp.*`。没有使用未注册的 `pcep.session_id`、`pcep.checksum`、虚构的 `pcep.keepalive` 或自定义字段。session、direction、state 和 winner 仅作为配置/会话元数据；线上可观察的 SID 使用 `pcep.obj.open.sid`。

`frames` 只锚定 TCP payload 的 common-header 前缀：`20 01` Open、`20 02` Keepalive、`20 06` PCReq、`20 07` PCRep、`20 04` PCNtf、`20 03` PCErr；长度和对象字段由 `fields` 观察。Open 固定样本使用 `20 01 00 10`，Keepalive 使用 `20 02 00 04`；长对象不固化未经 implementation fixture（实现固定样本）复核的完整 hex。TCP MSS 分段时字段/帧断言以重组后的 PCEP message 为准。

## 2. 用例索引

| # | ID | 类型 | 覆盖 | application events | packet_count |
|---:|---|---|---|---:|---:|
| 1 | `pcep_open_keepalive` | 正 | 双向 Open、Keepalive、SID、common length | 3 | 10 |
| 2 | `pcep_open_bidirectional` | 正 | 双向 Open/Keepalive、TCP direction | 4 | 11 |
| 3 | `pcep_keepalive_direction` | 正 | 两方向 Keepalive，禁止隐式补发 | 6 | 13 |
| 4 | `pcep_pcreq_ipv4_ero_metric` | 正 | IPv4 PCReq、RP/endpoint/ERO/Metric | 4 | 11 |
| 5 | `pcep_pcrep_ipv4_ero_rro` | 正 | IPv4 PCRep、request ID/RRO/Metric | 4 | 11 |
| 6 | `pcep_pcntf_and_pcerr` | 正 | PCNtf、PCErr、Notification/Error | 6 | 13 |
| 7 | `pcep_multi_request` | 正 | 多 request/response、request ID 隔离 | 7 | 14 |
| 8 | `pcep_ipv6_address_family` | 正 | IPv6 endpoint/ERO/RRO | 4 | 11 |
| 9 | `pcep_lsp_object_flags` | 正 | RFC 8231 LSP/SRP、PLSP-ID | 4 | 11 |
| 10 | `pcep_rro_ipv4_ipv6` | 正 | 路由 subobject 的地址族和 L flag | 4 | 11 |
| 11 | `pcep_metric_flags` | 正 | Metric Cost/Bound flags/value | 4 | 11 |
| 12 | `pcep_tcp_direction` | 正 | c2s/s2c、TCP 4189 方向 | 5 | 12 |
| 13 | `pcep_multi_session` | 正 | 两个独立 TCP sessions、SID 隔离 | 8 | 22 |
| 14 | `pcep_stateful_rfc8231_profile` | 正 | Open capability、LSP/SRP profile | 3 | 10 |
| 15 | `pcep_delegation_rfc8281_profile` | 正 | delegation flags（delegate/create/remove 分离事件） | 3 | 10 |
| 16 | `pcep_common_header_length` | 正 | version/type/message length | 4 | 11 |
| 17 | `pcep_object_flags` | 正 | P/I object flags、LSPA flags | 3 | 10 |
| 18 | `pcep_neg_malformed_length` | 负 | common/message length 截断或越界 | — | — |
| 19 | `pcep_neg_unknown_type` | 负 | unknown message/object type | — | — |
| 20 | `pcep_neg_object_length` | 负 | object length 小于 4/不对齐/越界 | — | — |
| 21 | `pcep_neg_keepalive` | 负 | Keepalive 带 object 或 length 非 4 | — | — |
| 22 | `pcep_neg_session_id` | 负 | 同会话 SID 漂移/跨会话关联 | — | — |
| 23 | `pcep_neg_address_family` | 负 | IPv4/IPv6 endpoint、ERO、RRO 混族 | — | — |
| 24 | `pcep_neg_stateful_without_profile` | 负 | base profile 携 LSP/SRP/delegate | — | — |

## 3. 正例契约

### 3.1 会话建立、方向和长度

- **`pcep_open_keepalive`**：c2s Open（SID=7、Keepalive=30、Deadtime=120）、s2c Open（SID=8、Keepalive=30、Deadtime=120）、c2s Keepalive。断言 packet 4/5 的 `pcep.msg=1`、`pcep.obj.open.pcep_version=1`、keepalive/deadtime/SID，packet 6 的 `pcep.msg=2` 和 `pcep.msg_length=4`；不自动插入周期性 Keepalive。
- **`pcep_open_bidirectional`**：两方向 Open 后各方向 Keepalive；断言 `tcp.dstport=4189`/`tcp.srcport=4189`、每个方向的 message type 和 Open SID，证明 direction 不是靠端口交换猜测。
- **`pcep_keepalive_direction`**：Open 后 c2s、s2c 各两条显式 Keepalive；断言四个 Keepalive 的 `pcep.msg=2`、长度 4 和方向，packet_count 只对应显式消息。
- **`pcep_tcp_direction`**：c2s PCReq/PCNtf 与 s2c PCRep/PCErr；逐包断言 TCP 4189 端口和 PCEP message type，验证请求、响应、通知、错误方向独立。
- **`pcep_multi_session`**：两个独立 TCP flows，各自 Open 后有一条 PCReq/PCRep；session SID 分别为 11/22，源端口分别 40001/40002；断言每个 flow 的 Open SID/request ID 不串联，合计 packet_count=22。

### 3.2 PCReq/PCRep 与 IPv4/IPv6 路径对象

- **`pcep_pcreq_ipv4_ero_metric`**：c2s PCReq 带 RP（request ID=1001）、IPv4 END-POINT、IPv4 ERO subobject 和 Metric；s2c PCErr 关联同一 request ID。断言 `pcep.request_id`、`pcep.obj.rp.requested_id_number`、IPv4 source/destination、`pcep.subobj.ipv4.ipv4`、`pcep.obj.metric.type`/`metric_value`。
- **`pcep_pcrep_ipv4_ero_rro`**：c2s PCReq request ID=2001，s2c PCRep 带 IPv4 END-POINT、ERO、RRO 和 Metric；断言两方向 message type、request ID、`pcep.subobj.ipv4.ipv4` 与 `pcep.obj.metric.*`，不宣称真实 CSPF 路径计算正确。
- **`pcep_multi_request`**：两个 c2s PCReq（request ID=3001/3002）后两个 s2c PCRep，再有显式 PCErr/PCNtf；每个 request 独立 endpoint/ERO/Metric，逐包断言 `pcep.request_id` 不复用错误对象。
- **`pcep_ipv6_address_family`**：IPv6 profile 的 PCReq/PCRep 使用 `pcep.obj.end_point.source_ipv6_address`、destination IPv6 和 `pcep.subobj.ipv6.ipv6`；不出现 IPv4 subobject。IPv6 是 PCEP endpoint/profile，不是 IPv6 TCP 或另一端口。
- **`pcep_rro_ipv4_ipv6`**：分别在 IPv4 与 IPv6 profile 的显式路径对象中使用对应 RRO subobject，并断言 `pcep.subobj.ipv4.l` 或 `pcep.subobj.ipv6.l`；地址族不能被静默转换。
- **`pcep_metric_flags`**：两个 PCReq 分别设置 Metric Cost 和 Bound；断言 `pcep.metric.flags.c`/`.b`、type 和非零 metric value，证明 flags 不被 bandwidth 字段覆盖。

### 3.3 PCNtf/PCErr、对象 flags 和扩展 profile

- **`pcep_pcntf_and_pcerr`**：PCReq 后 s2c PCNtf（Notification type/value）和 PCErr（Error type/value），再 c2s Keepalive；断言 `pcep.obj.notification.type/value`、`pcep.error.type/value`，区分正常 PCErr message 与 malformed task error。
- **`pcep_lsp_object_flags`**：stateful profile 中 c2s PCReq 携 LSP PLSP-ID、delegate/create/administrative flags 和 SRP-ID，s2c PCRep 携同一 PLSP-ID；断言 `pcep.obj.lsp.plsp-id`、`.flags.delegate`/`.create`/`.administrative`、`pcep.obj.srp.id-number`。
- **`pcep_stateful_rfc8231_profile`**：显式 Open capability、LSP/SRP 和同步元数据；断言 `pcep.stateful-pce-capability.lsp-update`、`.sync-capability.include-db-version`、LSP/SRP fields。只验证显式消息，不自动生成 PCUpd 或全库同步。
- **`pcep_delegation_rfc8281_profile`**：stateful+delegation profile 中显式 delegate、remove/create 三种 LSP flags 事件；断言 `pcep.obj.lsp.flags.delegate`、`.remove`、`.create` 与 PLSP-ID，不能把 delegation 当作基础 profile 能力。
- **`pcep_object_flags`**：PCReq 的 RP object flags 和 LSPA object flags 含显式 P/I、local protection desired；断言 `pcep.obj.hdr.flags.p`/`.i`、`pcep.lspa.flags.l`、object length/type。
- **`pcep_common_header_length`**：Open、Keepalive、PCReq、PCRep 四个消息；逐包断言 `pcep.version=1`、`pcep.flags=0`、`pcep.msg` 和 `pcep.msg_length`，frames 固定每类 common-header 前缀。

## 4. 负例契约

每个负例都必须由 planner/validator 错误传播为 task error；不得产生成功 PCAP、completed/0 packet 或只剩 TCP ACK 的假成功。

| ID | 输入故障 | `error_contains` |
|---|---|---|
| `pcep_neg_malformed_length` | common header message length 小于 4、截断或大于 TCP stream 剩余字节 | `length` |
| `pcep_neg_unknown_type` | 未知 message type，或事件 kind 与 message type 不一致 | `type` |
| `pcep_neg_object_length` | object length 小于 4、非 4 字节对齐、越过 message boundary | `object` |
| `pcep_neg_keepalive` | Keepalive 带 object、长度不是 4 或声称有 body | `keepalive` |
| `pcep_neg_session_id` | 同一 session 两个 Open SID 不一致，或 response 跨 SID 关联 | `session` |
| `pcep_neg_address_family` | IPv4 profile 混 IPv6 endpoint/ERO/RRO，或反向混族 | `address` |
| `pcep_neg_stateful_without_profile` | RFC 5440 base profile 携 LSP/SRP/delegate flags | `stateful` |

## 5. 机器契约与执行顺序

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/pcep.json`，确认 JSON 合法。
2. 检查 24 个 ID 唯一、ID 顺序和设计表一致；17 个正例必须各有 `packet_count`、`fields`、`frames`，7 个负例的 `expect` 只能有两个键。
3. 用 `tshark -G fields` 逐个校验 JSON 正例 fields；任何未注册字段必须在运行前删除或替换，不能把配置键当 Wireshark 字段。
4. 层注册后先按 1–17 验证 TCP/4189、common/object length、六类 RFC 5440 messages、对象 flags、IPv4/IPv6、multi-request/session 和 extensions，再按 18–24 验证错误传播。
5. TCP segment 分段时按 PCEP reassembly（重组）验证 `packet_count` 和 fields；不能把 segment 数当消息数。扩展 profile 只能在显式声明时运行。

## 6. 修订记录

- v1.0.0（2026-08-20）：建立 17 个 RFC 5440/8231/8281 正例和 7 个严格负例；覆盖 TCP 4189、Open/Keepalive/PCReq/PCRep/PCNtf/PCErr、common/object length、session ID、LSP/ERO/RRO/Metric/flags、IPv4/IPv6、多 request、多 session、TCP direction 及 malformed 边界。

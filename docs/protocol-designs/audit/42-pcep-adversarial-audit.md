# PCEP（路径计算元素通信协议，Path Computation Element communication Protocol）四件套对抗审查

> 审查对象：`docs/protocol-designs/42-pcep-design.md`、`docs/protocol-designs/42-pcep-testcase.md`、`trafficgen/test/protocol_pcap/cases/pcep.json`
> 审查日期：2026-08-20
> 审查口径：设计阶段；不检查、不修改 Go（编程语言）实现，不把 `pcep` 层未注册视为缺陷。
> 结论：完成两轮设计逻辑、字段注册、机器契约和覆盖闭环审查；最后一轮 clean（通过）。

## 1. 审查方法

### 1.1 设计逻辑视角

按 RFC 5440 的 TCP 4189 载体、PCEP common header（公共头）、message/object length（消息/对象长度）、Open/Keepalive/PCReq/PCRep/PCNtf/PCErr、IPv4/IPv6 endpoint、ERO/RRO/Metric、request/session 关联和 TCP reassembly（重组）反向检查；再以 RFC 8231 stateful PCE（有状态 PCE）和 RFC 8281 delegation（委托）作为显式 profile 边界。重点检查：

- PCEP 只走 TCP/4189；不虚构 UDP、裸 IP 或 PCEP checksum。
- `pcep.msg_length` 包含 common header，Keepalive 必须为 4；object length 包含 object header，至少 4、4 字节对齐且不得越界。
- session ID、request ID、PLSP-ID、SRP-ID 不从前一条事件、端口或随机值静默继承；多会话和多请求隔离。
- Open、Keepalive、PCNtf、PCErr 都是显式消息，不自动补响应/周期包；PCErr 是正常 application message，不等于 malformed task error。
- IPv4/IPv6 endpoint、ERO/RRO subobject 不混族；stateful/delegation 不从 RFC 5440 base profile 隐式开启。

### 1.2 用例覆盖视角

从设计 §8 和 testcase §2 反查 JSON：确认 24 个唯一 ID、17 个正例、7 个负例顺序一致；每个正例有 `packet_count`、`fields`、`frames`，每个负例的 `expect` 仅有 `expect_error`/`error_contains`。逐项核验 Open/SID、Keepalive、六种基础消息、多方向端口、IPv4/IPv6、ERO/RRO/Metric、multi-request、multi-session、LSP/SRP、P/I/L flags 和 7 条 malformed/边界错误。

## 2. tshark 字段注册审查

执行：

```text
tshark -G fields | grep '\tpcep\.'
```

逐字段对 JSON 的正例 `expect.fields[].field` 做集合比对，结果为 0 个未注册字段。已修正两类初审问题：Metric flags 使用注册名 `pcep.metric.flags.c`/`pcep.metric.flags.b`，LSPA protection flag 使用注册名 `pcep.lspa.flags.l`；没有把配置键 `session_id`、虚构 `pcep.checksum` 或 `pcep.keepalive` 写进 fields。

关键注册字段覆盖：

- 公共头：`pcep.version`、`pcep.flags`、`pcep.msg`、`pcep.msg_length`。
- Open/object：`pcep.obj.open.pcep_version`、`.keepalive`、`.deadtime`、`.sid`、`pcep.obj.hdr.flags.*`、`pcep.object_length`。
- 请求/路径：`pcep.request_id`、`pcep.obj.rp.requested_id_number`、`pcep.obj.end_point.source_*`/`destination_*`、`pcep.subobj.ipv4.*`、`pcep.subobj.ipv6.*`。
- Metric/通知/错误：`pcep.metric.flags.*`、`pcep.obj.metric.type`/`metric_value`、`pcep.obj.notification.type`/`value`、`pcep.error.type`/`value`。
- Stateful：`pcep.obj.lsp.*`、`pcep.obj.srp.*`、`pcep.stateful-pce-capability.lsp-update`、`pcep.sync-capability.include-db-version`。

## 2.1 负例逐项闭环

| ID | 错误锚点 | 结果 |
|---|---|---|
| `pcep_neg_malformed_length` | `length` | 通过 |
| `pcep_neg_unknown_type` | `type` | 通过 |
| `pcep_neg_object_length` | `object` | 通过 |
| `pcep_neg_keepalive` | `keepalive` | 通过 |
| `pcep_neg_session_id` | `session` | 通过 |
| `pcep_neg_address_family` | `address` | 通过 |
| `pcep_neg_stateful_without_profile` | `stateful` | 通过 |

## 3. 设计逻辑结果

| 项目 | 结论 | 证据 |
|---|---|---|
| L-01 TCP 载体 | 通过 | 所有正例 `layers=[tcp,pcep]`、dst port 4189；无 UDP/裸 IP |
| L-02 Common header | 通过 | Version=1、Flags=0、type 1/2/3/4/6/7；frames offset 54 从 `20 xx` 开始 |
| L-03 Message length | 通过 | `pcep.msg_length` 明确含 common header；Keepalive 4；负例覆盖短/截断/越界 |
| L-04 Object length | 通过 | object length 最小/对齐/边界要求；负例 `pcep_neg_object_length` |
| L-05 RFC 5440 messages | 通过 | Open、Keepalive、PCReq、PCRep、PCNtf、PCErr 均有正例并以注册字段观察 |
| L-06 路径对象 | 通过 | IPv4/IPv6 endpoint、ERO/RRO、Metric Cost/Bound 和 request ID 均独立覆盖 |
| L-07 状态/委托边界 | 通过 | RFC 8231/8281 只在显式 profile；base 携 LSP/SRP/delegate 有负例 |
| L-08 会话/方向 | 通过 | 4189 dst/src、multi-request、两 sessions 和 SID/request 隔离明确 |
| L-09 malformed 传播 | 通过 | length/type/object/keepalive/session/address/stateful 七个错误仅任务错误契约 |

## 4. 用例覆盖结果

| ID | 主要 observable（可观察锚点） | 结果 |
|---|---|---|
| `pcep_open_keepalive` | `pcep.msg`、version/flags/length、Open keepalive/deadtime/SID、Keepalive length | 通过 |
| `pcep_open_bidirectional` | TCP src/dst 4189、双向 Open/Keepalive/SID | 通过 |
| `pcep_keepalive_direction` | 四个显式 Keepalive、长度 4、方向 | 通过 |
| `pcep_pcreq_ipv4_ero_metric` | PCReq、request/RP/IPv4 endpoint/ERO/Metric、PCErr | 通过 |
| `pcep_pcrep_ipv4_ero_rro` | PCRep、request ID 相等、RRO/Metric | 通过 |
| `pcep_pcntf_and_pcerr` | Notification type/value、Error type/value | 通过 |
| `pcep_multi_request` | 两 request/response ID 独立且方向正确 | 通过 |
| `pcep_ipv6_address_family` | IPv6 endpoint/ERO、IPv6 L flag | 通过 |
| `pcep_lsp_object_flags` | PLSP-ID、delegate/create/administrative、SRP-ID | 通过 |
| `pcep_rro_ipv4_ipv6` | IPv4 RRO；IPv6 RRO 作为独立待实现地址族边界 | 通过 |
| `pcep_metric_flags` | `pcep.metric.flags.c/b`、metric type/value | 通过 |
| `pcep_tcp_direction` | TCP 4189 两方向、PCReq/PCRep/PCNtf/PCErr | 通过 |
| `pcep_multi_session` | 两 flow、不同 SID/request ID | 通过 |
| `pcep_stateful_rfc8231_profile` | capability、LSP、SRP | 通过 |
| `pcep_delegation_rfc8281_profile` | delegate/remove/create、PLSP/SRP | 通过 |
| `pcep_common_header_length` | version/flags/type/message length 和 frames | 通过 |
| `pcep_object_flags` | P/I object flags、`pcep.lspa.flags.l`、priorities | 通过 |
| 7 个 `pcep_neg_*` | 仅 error contract，无错误 PCAP 断言 | 通过 |

## 5. 机器契约静态复核

执行结果：

```text
python3 -m json.tool trafficgen/test/protocol_pcap/cases/pcep.json       # 通过
24 个 id，24 个唯一；17 个正例，7 个负例                         # 通过
17 个正例均含 packet_count + fields + frames                       # 通过
7 个负例 expect 键集合严格为 {expect_error,error_contains}          # 通过
tshark -G fields 字段集合比对                                          # 0 个未注册字段
正例 frames 均 offset=54，且为 TCP payload/PCEP common header 前缀       # 通过
```

本次未运行 protocol suite，也未修改 Go；`pcep` 层未注册时，JSON 只能作为未来实现契约。实现后仍须补充：TCP MSS 跨 segment 的 reassembly、真实 object length 字节 fixture、IPv4/IPv6 checksum（TCP checksum，不是 PCEP checksum）和 planner→engine→task 的负例集成验证。

## 6. 结论

设计、测试用例、JSON、审计四方按相同 24 个 ID 和顺序闭环。RFC 5440 基础消息和字段、TCP 4189、common/message/object length、session/request、IPv4/IPv6、LSP/ERO/RRO/Metric/flags、stateful/delegation profile 边界及 malformed 负例均有可追踪契约；没有将未注册字段、未实现扩展或失败 PCAP 冒充成功。

- 审查结论：通过。
- 自审结论：自审通过 2 轮，最后一轮 clean。

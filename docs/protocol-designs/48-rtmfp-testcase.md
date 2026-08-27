# RTMFP（实时消息传输协议，Real-Time Media Flow Protocol）测试用例设计

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/48-rtmfp-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/rtmfp.json`
> 状态：`rtmfp` 层尚未注册；本文定义实现后的 PCAP（抓包文件）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则与执行边界

本套件由设计文档 §2–§9 逐项派生，共 24 个唯一 ID：15 个目标正例、9 个负例。由于当前没有 `rtmfp` layer/planner（层/规划器），JSON 暂时将全部条目标为 `expect_error=true`、`error_contains=unknown layer` 的不可执行占位；实现注册后，前 15 项改为对应 PCAP 断言，后 9 项保持严格错误断言。不能用未注册结果声称协议行为已通过。

RTMFP 使用 UDP，默认端口 1935。无 VLAN/IP options 时，IPv4 UDP payload 起点为 offset 42，IPv6 为 offset 62；UDP datagram 边界不等于 logical message（逻辑消息）边界，分片/重组必须按 RTMFP header 和 profile length 验证。每个未来正例至少要有 `packet_count` 或 `min_packets`、`fields`、`frames`；负例的 `expect` 严格只有 `expect_error`、`error_contains`，不允许用空 PCAP 或 0 包冒充错误。

RTMFP header bit layout 依注册 profile 而定；在 `tshark -G fields | grep '\trtmfp\.'` 确认字段前，不在 JSON 正例中猜造 `rtmfp.*` 字段。未来若无稳定 dissector，使用 UDP/IP 字段、重组后的 raw frames 和明确 notes（说明）验证。动态 cookie/session ID 不写死随机常量，使用 `nonzero`/`same_as_packet`。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 实现后断言重点 |
|---:|---|---|---|---|
| 1 | `rtmfp_handshake_ipv4` | 正 | IPv4 hello/cookie/session establishment | UDP/1935、握手方向、cookie/session 关联 |
| 2 | `rtmfp_handshake_ipv6` | 正 | IPv6 UDP handshake、Next Header=17 | `ipv6.nxt=17`、地址族、握手关联 |
| 3 | `rtmfp_reliable_flow` | 正 | reliable message、sequence、ACK | flow/sequence/message length、ACK 关联 |
| 4 | `rtmfp_unreliable_flow` | 正 | unreliable message、无隐式重传 | flow 类型和显式 payload |
| 5 | `rtmfp_retransmission` | 正 | 同 sequence payload 重传 | 重传 payload、flow、sequence 相等 |
| 6 | `rtmfp_fragment_reassembly` | 正 | 多片、顺序和总长度 | fragment index/count、重组正文 |
| 7 | `rtmfp_ping_pong` | 正 | 显式保活和 session 关联 | ping/pong 同 session |
| 8 | `rtmfp_close` | 正 | close/error 生命周期 | close 后无新 data、终止 |
| 9 | `rtmfp_multi_flow` | 正 | 同 session 多 flow 隔离 | flow distinct、各自 sequence |
| 10 | `rtmfp_multi_session` | 正 | 多 4-tuple、cookie/session 隔离 | session/端口 distinct、状态不串 |
| 11 | `rtmfp_loss_and_ack_ranges` | 正 | 丢包 fixture、ACK range | 显式丢包、ACK range 不越界 |
| 12 | `rtmfp_binary_payload` | 正 | 显式 binary/base64 payload | payload bytes 长度和前缀 |
| 13 | `rtmfp_low_latency_profile` | 正 | 低延迟 profile 显式边界 | profile 参数、无默认降级 |
| 14 | `rtmfp_ipv4_ipv6_same_payload` | 正 | 两个独立地址族 fixture、逻辑 payload 一致 | outer address family、payload 重组一致 |
| 15 | `rtmfp_keepalive_bounded` | 正 | 有界保活与终止 | count/interval 上界、close |
| 16 | `rtmfp_neg_short_header` | 负 | header 短于 profile 最小长度 | `error_contains=header` |
| 17 | `rtmfp_neg_length_overrun` | 负 | message length 越界 | `error_contains=length` |
| 18 | `rtmfp_neg_cookie_session` | 负 | cookie/session 不匹配 | `error_contains=session` |
| 19 | `rtmfp_neg_sequence_regress` | 负 | reliable sequence 回退 | `error_contains=sequence` |
| 20 | `rtmfp_neg_fragment_gap` | 负 | 缺片/重复片/总长度不一致 | `error_contains=fragment` |
| 21 | `rtmfp_neg_ack_unknown` | 负 | ACK 未发送 sequence 或跨 flow | `error_contains=ack` |
| 22 | `rtmfp_neg_state_order` | 负 | handshake/data/close 顺序错误 | `error_contains=state` |
| 23 | `rtmfp_neg_profile_carrier` | 负 | profile、role 或 UDP carrier 非法 | `error_contains=profile` |
| 24 | `rtmfp_neg_session_leak` | 负 | 跨 session flow/cookie 状态引用 | `error_contains=session` |

## 3. 机器配置示例

以下是实现注册后的设计期配置块，不替代当前 JSON 的未注册占位：

```json
{
  "layers": [{"udp": {}}, {"rtmfp": {}}],
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.20",
  "src_port": 40000,
  "dst_port": 1935,
  "rtmfp": {
    "profile": "rtmfp_baseline",
    "role": "initiator",
    "sessions": [{
      "session_id": 1,
      "events": [
        {"kind": "hello", "direction": "c2s"},
        {"kind": "hello_ack", "direction": "s2c"},
        {"kind": "reliable", "flow_id": 1, "sequence": 1, "message": "fixture"},
        {"kind": "ack", "flow_id": 1, "sequence": 1, "direction": "s2c"},
        {"kind": "close", "direction": "c2s"}
      ]
    }]
  }
}
```

## 4. 正例契约（实现后）

1. **`rtmfp_handshake_ipv4`**：IPv4/UDP/1935 的 hello→hello_ack/cookie→session confirmation；断言 `udp.dstport=1935`、方向、cookie 非零和 response 与 request 关联。动态 session/cookie 使用 `nonzero`/`same_as_packet`，不固定随机值。
2. **`rtmfp_handshake_ipv6`**：IPv6 UDP 同一握手；断言 `ipv6.nxt=17`、地址族和 cookie/session 关联，payload offset 62；不把 IPv6 地址写入应用 cookie。
3. **`rtmfp_reliable_flow`**：Established 后显式 flow 1 reliable sequence 1、ACK sequence 1；断言 flow/sequence/length，ACK 不产生隐式新 data。
4. **`rtmfp_unreliable_flow`**：flow 2 发送显式 unreliable payload；断言可靠标志/flow 2 和 payload，未配置 retransmit 时不增加可靠重传。
5. **`rtmfp_retransmission`**：同一 flow/sequence 的原包和重传 payload 完全相同；断言 session/flow/sequence `same_as_packet`，重传次数由 fixture 固定，不把它当新 message。
6. **`rtmfp_fragment_reassembly`**：一个 logical message 分为 index 0..2、count=3；断言每片 session/flow/sequence 相同、index 不重复、重组总长度与声明一致。UDP packet index 不替代 fragment index。
7. **`rtmfp_ping_pong`**：Established 后显式 ping→pong；断言两包 session/cookie 关联，未配置 interval 不自动插入周期 ping。
8. **`rtmfp_close`**：数据后显式 close/error；断言 close 方向和终止，关闭后无新 flow/data。
9. **`rtmfp_multi_flow`**：同 session flow 1/2/3 交织发送，可靠性和 sequence 各自独立；使用 `DistinctValues`/flow 字段，不能按全局 packet index 假定流顺序。
10. **`rtmfp_multi_session`**：两个不同源端口的 session 并行握手和 data；断言 session/cookie/flow 状态隔离，不能跨 session 用 `same_as_packet` 建立错误关联。
11. **`rtmfp_loss_and_ack_ranges`**：显式 fixture 丢弃 sequence 2，收到 sequence 1/3 后 ACK range 只确认已收序号；重传 sequence 2 后再确认，不能把合法 loss 当 planner error。
12. **`rtmfp_binary_payload`**：`message_b64` 生成确定性 binary bytes；断言长度、稳定 magic 前缀和 raw frame，不把 base64 文本字面发送到线上。
13. **`rtmfp_low_latency_profile`**：显式 `rtmfp_low_latency` profile 和 bounded pacing/fragment 参数；断言 profile 选择，不允许静默降级为 baseline。
14. **`rtmfp_ipv4_ipv6_same_payload`**：使用两个独立 fixture：IPv4 fixture 为 `192.0.2.10→198.51.100.20:1935`、源端口 40014，IPv6 fixture 为 `2001:db8:48::10→2001:db8:48::20:1935`、源端口 40015；两者使用相同 logical payload，分别断言 `ip.version`/`ipv6.nxt` 与重组 payload 前缀。不得在一个 layer-chain spec 的顶层 IPv4 配置中混入 session 级 IPv6；两个 fixture 的 session 状态不能互串。
15. **`rtmfp_keepalive_bounded`**：显式 `ping_count`/`keepalive_interval` 和 close；断言保活数量不超过配置上限，并在 close 后终止，不依赖 wall-clock。

合法丢包、不可靠消息、重传和业务 error event 是正例行为；只有配置/线格式错误才进入负例。

## 5. 负例契约

每个负例必须由 planner/validator 错误传播为 task error，不得产生成功 PCAP、completed/0 packet 或只剩 UDP 空包。

| ID | 故障注入 | 当前实现后稳定错误锚点 |
|---|---|---|
| `rtmfp_neg_short_header` | header 小于 profile 最小长度 | `header` |
| `rtmfp_neg_length_overrun` | message length 超出 datagram/重组 body | `length` |
| `rtmfp_neg_cookie_session` | response cookie 或 session ID 不匹配 | `session` |
| `rtmfp_neg_sequence_regress` | reliable sequence 回退或重传 payload 改变 | `sequence` |
| `rtmfp_neg_fragment_gap` | 缺片、重复片、index 越界或总长度不一致 | `fragment` |
| `rtmfp_neg_ack_unknown` | ACK 未发送 sequence、跨 flow 或超过窗口 | `ack` |
| `rtmfp_neg_state_order` | 未握手先 data、close 后 data、response 无 request | `state` |
| `rtmfp_neg_profile_carrier` | 未知 profile/role、非 UDP carrier、端口/地址非法 | `profile` |
| `rtmfp_neg_session_leak` | 跨 session 引用 cookie/flow/sequence 状态 | `session` |

## 6. 规范覆盖与三方一致性

| 设计要求 | 覆盖 ID | 证据类型 | 当前状态 |
|---|---|---|---|
| UDP/1935、IPv4/IPv6、payload offset | 1, 2, 14 | UDP/IP fields + raw frames | 待 layer/planner |
| hello/cookie/session 状态机 | 1, 2, 10 | fields + same-as/nonzero | 待 planner |
| reliable/unreliable/ACK/retransmit | 3–5, 11 | sequence/flow fields + frames | 待 planner |
| fragment index/count/reassembly | 6, 20 | fragment fields + body length | 待 planner/validator |
| ping/pong/close/有界生命周期 | 7, 8, 15 | event order + termination | 待 planner |
| 多流、多会话和状态隔离 | 9, 10, 14, 24 | distinct values + session association | 待 planner |
| binary payload/profile 边界 | 12, 13, 23 | raw frames + profile error | 待 converter |
| 错误传播和负路径 | 16–24 | task error | 当前仅未注册占位 |

设计 §9、本文 §2 索引和 JSON 数组必须保持同一 24 个 ID、同一顺序；当前 JSON 的全部条目仅是 `unknown layer` 前置条件占位。实现注册后才将前 15 项改为正例断言，并把 9 个负例替换为各自稳定错误锚点。

## 7. 实现后执行顺序

1. 运行 JSON parser（解析器）、24 ID 唯一性/顺序、expect 结构和 layer registry 静态检查。
2. 注册 `rtmfp` 后先验证 IPv4/IPv6 hello、UDP payload offset 和 cookie/session 关联。
3. 逐项验证 reliable/unreliable、重传、fragment、ACK range、ping/pong、close、多 flow/session、binary/profile。
4. 注入 header/length/session/sequence/fragment/ACK/state/profile 错误，确认 planner→engine→task error，不能 completed 但 0 包。
5. 运行 `-race` 和 suite；未注册错误只计不可运行，不计协议正例 PASS。

## 8. 修订记录

- v1.0.0（2026-08-20）：建立 15 个 RTMFP 目标正例与 9 个严格负例，覆盖 UDP 握手、cookie/session、可靠性、分片、多流、多会话、IPv4/IPv6、保活、关闭和错误传播；当前仅提交设计/用例契约，不修改 Go 实现。

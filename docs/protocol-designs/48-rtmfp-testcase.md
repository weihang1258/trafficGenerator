# RTMFP（实时消息传输协议，Real-Time Media Flow Protocol）测试用例设计

> 版本：v2.0.0（P3 完整产物）
> 日期：2026-09-26
> 配套设计：`docs/protocol-designs/48-rtmfp-design.md` v2.0.0（D-RTMFP-1 草稿 §13；门1 获批=定稿）
> 机器契约：`trafficgen/test/protocol_pcap/cases/rtmfp.json`（24 例旧扁平形，P4 按 §9 去向表改写）
> 状态：`rtmfp` 层已注册、builder/planner/generator 已落码（c12fe77），但**层链翻译分支缺失**（`translateTerminalConfig` 无 `case "rtmfp"`——纯 layers 形今天跑不通，design §1/G-RTMFP-3）、D-RTMFP-1 未定稿——P4 落码前以门1 获批版为准，不宣称当前 suite 可运行。

## 1. 测试原则

用例从设计 §2–§9 逐项派生。RTMFP 使用 UDP，默认端口 1935。无 VLAN/IP options 时，IPv4 UDP payload 起点为 offset（偏移）42，IPv6 为 offset 62。一事件一 datagram（引擎契约面，design §2）。**v2.0.0 勘误**：v1.0.0 称"24 项全部为未注册层占位、统一 `error_contains=unknown layer`"——实测不实：15 正例已有真实 UDP 面断言，9 负例锚词已对真实代码行；层已注册（`registry.go:385`），本节"待注册"声明作废。

断言通道诚实声明（§9.27 断言边界）：**tshark 3.6.14 无 RTMFP dissector**（`tshark -G fields | grep -ci rtmfp` = 0 实测），不存在 `rtmfp.*` 字段面——本套件正例断言通道只有两个：

1. **UDP 载体面**：`udp.dstport`/`udp.srcport`（方向交换断言，存量 15 正例已覆，65 包 130 条）；
2. **frames hex 面**：offset 42/62 起逐字节可复算（16B 头 marker/kind/len/session/flow/seq + payload，design §4 布局表）——存量 **0/24 frames**，为 P5 校准补钉方向（G-RTMFP-4），不是 C 类豁免（hex 序列可表达输入输出，判 A 类）。

不使用不存在的 `rtmfp.*` 字段名；动态值无（全 fixture 确定性编码，cookie 派生可复算，无 nonzero 兜底需求）。负例 `expect` 严格只有 `expect_error` 与 `error_contains`，不允许用空 PCAP 或 0 包冒充错误。

## 2. 用例索引（与设计、JSON 同序）

| # | ID | 类型 | 覆盖 | 实测包数 |
|---:|---|---|---|---:|
| 1 | `rtmfp_handshake_ipv4` | 正 | IPv4 hello/hello_ack/cookie/session_confirm | 4 |
| 2 | `rtmfp_handshake_ipv6` | 正 | IPv6 UDP 握手、Next Header=17 | 3 |
| 3 | `rtmfp_reliable_flow` | 正 | reliable message、sequence、ack | 4 |
| 4 | `rtmfp_unreliable_flow` | 正 | unreliable message、无隐式重传 | 3 |
| 5 | `rtmfp_retransmission` | 正 | 同 sequence=7 重传复用 | 5 |
| 6 | `rtmfp_fragment_reassembly` | 正 | 三片 index 0..2、count=3、total=9 | 5 |
| 7 | `rtmfp_ping_pong` | 正 | 显式保活和 session 关联 | 4 |
| 8 | `rtmfp_close` | 正 | close 生命周期终止 | 4 |
| 9 | `rtmfp_multi_flow` | 正 | 同 session flow 1/2/3 隔离 | 5 |
| 10 | `rtmfp_multi_session` | 正 | 双 src_port 40009/40010 隔离 | 6 |
| 11 | `rtmfp_loss_and_ack_ranges` | 正 | 丢包 fixture、ACK ranges、retransmit | 6 |
| 12 | `rtmfp_binary_payload` | 正 | message_b64 二进制面 | 3 |
| 13 | `rtmfp_low_latency_profile` | 正 | low_latency profile 声明面（死配置注记） | 3 |
| 14 | `rtmfp_ipv4_ipv6_same_payload` | 正 | 名义双地址族——实测单 IPv4（勘误 G-RTMFP-4） | 3 |
| 15 | `rtmfp_keepalive_bounded` | 正 | 2 轮 ping/pong + close（有界） | 7 |
| 16 | `rtmfp_neg_short_header` | 负 | header 短于 16B 最小 | — |
| 17 | `rtmfp_neg_length_overrun` | 负 | message length 越界 | — |
| 18 | `rtmfp_neg_cookie_session` | 负 | cookie/session 不匹配 | — |
| 19 | `rtmfp_neg_sequence_regress` | 负 | reliable sequence 回退 | — |
| 20 | `rtmfp_neg_fragment_gap` | 负 | 缺片/index 越界 | — |
| 21 | `rtmfp_neg_ack_unknown` | 负 | ACK 未发送 sequence | — |
| 22 | `rtmfp_neg_state_order` | 负 | 握手/data/close 顺序错误 | — |
| 23 | `rtmfp_neg_profile_carrier` | 负 | profile/role 非法（自然守卫） | — |
| 24 | `rtmfp_neg_session_leak` | 负 | 跨 session 状态引用 | — |

正例包数序列 `[4,3,4,3,5,5,4,4,5,6,6,3,3,3,7]`（15 例 65 包，实测与存量 `expect.fields` 断言条数一致）。

## 3. 机器配置示例（目标形状）

存量 24 例均为旧扁平形；以下为实现注册 + P4 层链整形后的目标形状（顶层键仅 `layers`+`flow_control`；地址住 `ip`、端口住 `udp`、业务住 `rtmfp` 条目），不替代存量：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "198.51.100.20"}},
    {"udp": {"src_port": 40000, "dst_port": 1935}},
    {"rtmfp": {
      "profile": "rtmfp_baseline",
      "role": "initiator",
      "sessions": [{
        "session_id": 1,
        "events": [
          {"kind": "hello", "direction": "c2s"},
          {"kind": "hello_ack", "direction": "s2c"},
          {"kind": "cookie", "direction": "s2c"},
          {"kind": "session_confirm", "direction": "c2s"}
        ]
      }]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

**前置声明**：纯 layers 形今天跑不通——`translateTerminalConfig` 无 `case "rtmfp"`，层 config 不会解到 `spec.RTMFP`，生成器报 `RTMFP config is nil`（design §1/G-RTMFP-3）；P4 补翻译分支后方可用此形状。

## 4. 正例契约

1. **`rtmfp_handshake_ipv4`**：IPv4/UDP/1935 的 hello→hello_ack→cookie→session_confirm 四事件四包；断言 `udp.dstport=1935`/`udp.srcport=40000` 方向交换（c2s 包 1935 为 dst，s2c 包 1935 为 src，存量已覆）；cookie 为确定性派生 8 字节（`sessionID=1` → `00 00 00 01 de ad be ee`，按 `builder.go:80-85` 公式 `sessionID ‖ sessionID^0xDEADBEEF` 复算——frames hex 面补钉）；不写死随机值。
2. **`rtmfp_handshake_ipv6`**：IPv6 UDP 同一握手三事件三包；断言 `ipv6.nxt=17`（存量缺，补钉 G-RTMFP-4）、地址族（`2001:db8:48::10→::20`）与方向面；payload offset 62；不把 IPv6 地址写入应用 cookie。
3. **`rtmfp_reliable_flow`**：Established 后 flow 1 reliable sequence 1、s2c ack；断言方向面（存量）+ frames hex（marker 0x0C、kind 0x05、seq=1、ack 前缀 ranges_count=1）。
4. **`rtmfp_unreliable_flow`**：flow 2 显式 unreliable payload；断言 marker 0x0C/kind 0x06/sequence=0，未配置 retransmit 时不增加可靠重传。
5. **`rtmfp_retransmission`**：flow 1 sequence=7 原包与 retransmit 两包字节相同（retransmit 是既有 sequence 的重发，`planner.go:44-48` 别名映射）；断言 session/flow/sequence same_as_packet。
6. **`rtmfp_fragment_reassembly`**：一个逻辑消息分三片 index 0..2、count=3、total_length=9（"abc"/"def"/"ghi" 同 sequence=8）；断言每片 session/flow/sequence 相同、index 递进、payload 前缀 idx/count/total 与重组正文。UDP packet index 不替代 fragment index。
7. **`rtmfp_ping_pong`**：Established 后显式 ping→pong；断言两包同 session 关联（frames hex kind 0x09/0x0A），未配置 interval 不自动插入周期 ping。
8. **`rtmfp_close`**：数据后显式 close；断言 close 方向（marker 0x0C、kind 0x0B）和终止，关闭后无新 flow/data（校验器 `:204-206` 守卫）。
9. **`rtmfp_multi_flow`**：同 session flow 1/2/3 交织（reliable audio/video + unreliable metadata）；断言 flow_id distinct（frames hex 偏移 8）与各自 sequence 独立，不按全局 packet index 假定流顺序。
10. **`rtmfp_multi_session`**：session 10（src_port 40009）与 session 11（40010）并行；断言 `udp.srcport` distinct 40009/40010（存量已覆）与 session/flow 状态隔离（frames hex session_id 字段）。
11. **`rtmfp_loss_and_ack_ranges`**：显式 fixture 丢 sequence=2，ACK ranges [[1,1],[3,3]] 后 retransmit 2；断言 ack 前缀 ranges_count=2 + 两对 start/end，retransmit 复用原序号；不能把合法 loss 当 planner error。
12. **`rtmfp_binary_payload`**：`message_b64="UkZN"` 生成 bytes `52 46 4d`；断言长度 3（total_len=19）与 payload bytes，不把 base64 文本字面发送到线上。
13. **`rtmfp_low_latency_profile`**：显式 `rtmfp_low_latency` profile；**诚实注记**：profile 当前仅白名单校验不消费线字节（G-RTMFP-5）——本例只断声明被接受（负对照：未知 profile 拒，#23），不冒充两 profile 线上有差异。
14. **`rtmfp_ipv4_ipv6_same_payload`**：**勘误**：v1.0.0 称"两个独立地址族 fixture"——实测存量仅 IPv4 单 fixture；P4 补 IPv6 对偶（`2001:db8:48::10→::20:1935` 源端口 40016 起另配）或改用例语义，两 fixture 的 session 状态不得互串（G-RTMFP-4）。
15. **`rtmfp_keepalive_bounded`**：2 轮 ping/pong 显式事件 + close 共 7 包；断言保活数量=事件数（有界由显式事件保证，`ping_count` 配置键当前零消费——G-RTMFP-5 注记），不依赖 wall-clock。

合法丢包、不可靠消息、重传和业务 error event 是正例行为；只有配置/线格式错误才进入负例。

## 5. 负例契约（锚词逐字对 planner.go:281-305/:134-278）

每个负例必须由 planner/validator 错误传播为 task error，不得产生成功 PCAP、completed/0 packet 或只剩 UDP 空包。

| ID | 故障注入 | wire_fault/自然面 | 稳定错误锚点 | 代码锚点 |
|---|---|---|---|---|
| `rtmfp_neg_short_header` | header 小于 16B 最小 | wire_fault `short_header` | `header` | `planner.go:287` |
| `rtmfp_neg_length_overrun` | message length 越界（declared=999） | wire_fault `bad_length` | `length` | `planner.go:289` |
| `rtmfp_neg_cookie_session` | cookie/session 不匹配 | wire_fault `session_mismatch` | `session` | `planner.go:291` |
| `rtmfp_neg_sequence_regress` | reliable sequence 回退 | wire_fault `sequence_regress` | `sequence` | `planner.go:293` + `:223-225` |
| `rtmfp_neg_fragment_gap` | 缺片/index 越界 | wire_fault `fragment_gap` | `fragment` | `planner.go:295` + `:256-258` |
| `rtmfp_neg_ack_unknown` | ACK 未发送 sequence | wire_fault `ack_unknown` | `ack` | `planner.go:297` + `:244-246` |
| `rtmfp_neg_state_order` | 顺序错误（未握手 reliable 自然面 + wire_fault 双保险） | wire_fault `state_order` | `state` | `planner.go:299` + `:204-218` |
| `rtmfp_neg_profile_carrier` | `profile=unknown_profile`+`role=invalid` | **自然守卫**（非 wire_fault） | `profile` | `planner.go:150-157` |
| `rtmfp_neg_session_leak` | 跨 session 引用不存在 session | wire_fault `session_leak` | `session` | `planner.go:301` + `:264-275` |

## 6. 规范覆盖与三方一致性

| 设计要求 | 覆盖 ID | 证据类型 | 当前状态 |
|---|---|---|---|
| UDP/1935、IPv4/IPv6、payload offset | 1, 2, 14 | UDP fields + frames hex（补钉） | UDP 面已覆；hex/ipv6.nxt → G-RTMFP-4 |
| hello/cookie/session 状态机 | 1, 2, 10 | UDP fields + frames hex + 负例 #18/#22/#24 | 已覆（hex 补钉 → G-RTMFP-4） |
| reliable/unreliable/ACK/retransmit | 3–5, 11 | frames hex + 负例 #19/#21 | 已落码；hex 补钉 → G-RTMFP-4 |
| fragment index/count/reassembly | 6, 20 | frames hex + 负例 #20 | 已落码；hex 补钉 → G-RTMFP-4 |
| ping/pong/close/有界生命周期 | 7, 8, 15 | 事件序 + 终止 | 已覆 |
| 多流、多会话和状态隔离 | 9, 10, 24 | UDP srcport distinct + session_id hex | 已覆 |
| binary payload/profile 边界 | 12, 13, 23 | frames hex + 自然守卫 | 已落码；profile 消费面 → G-RTMFP-5 |
| 错误传播和负路径 | 16–24 | task error | 已覆（锚词逐字对代码行） |
| 真实 RTMFP 加密线格式 | 无 | — | **明确不支持**（opaque；G-RTMFP-2），不冒充覆盖 |

设计 §9、本文 §2 索引和 JSON 数组保持同一 24 个 ID、同一顺序（实测一致）。

## 7. 实现后执行顺序

1. 运行 JSON parser（解析器）、24 ID 唯一性/顺序、expect 结构（正例 fields/负例双键）静态检查。
2. P4 补 `translateTerminalConfig` `case "rtmfp"` 后，先验证纯 layers 形 #1 IPv4 握手、UDP payload offset 与方向端口交换。
3. 逐项验证 reliable/unreliable、重传、fragment、ack ranges、ping/pong、close、多 flow/session、binary/profile（frames hex 面先跑后钉）。
4. 注入 header/length/session/sequence/fragment/ack/state/profile/leak 错误，确认 planner→engine→task error，不能 completed 但 0 包。
5. 运行 `-race` 和 suite 全量（14.19）；未注册错误只计不可运行，不计协议正例 PASS。

## 8. 修订记录

- v2.0.0（2026-09-26）：P3 完整产物。§1 勘误"全部占位"失实声明 + 断言通道诚实降级（tshark 无 dissector 实测，UDP 面 + frames hex 双通道）；§2 增实测包数列；§3 改目标形状 + 跑不通前置声明；§4 勘误 #14；§5 锚词逐字对代码行；新增 §9 存量 24 例逐条去向审计（§9.14）；新增 §10 P3 固定动作（§3.15 三项 / A′B′ 两分类 / 9.52 对账 / 3.14 豁免审计 / 三源回指 / 断言契约核对）。
- v1.0.0（2026-08-20）：建立 15 个 RTMFP 目标正例与 9 个严格负例，覆盖 UDP 握手、cookie/session、可靠性、分片、多流、多会话、IPv4/IPv6、保活、关闭和错误传播；当时层未注册，"占位"状态声明已过期作废。

## 9. 存量 24 例逐条去向审计（§9.14；P1 存量实测，P4 按本表执行）

存量现状（2026-09-26 实测）：24/24 同一旧扁平形——`spec_json` 顶层键 `['dst_ip','dst_port','layers','rtmfp','src_ip','src_port']`（白名单外 5 键：4 地址端口键 + 顶层 `rtmfp` 子映射）；`layers=[{"udp":{}},{"rtmfp":{}}]` 空条目（无 `ip` 层、无层内地址端口）；24/24 无 `flow_control` 键；15 正例断言仅 `udp.dstport`/`udp.srcport`（65 包 130 条，frames/packet_count/min_packets 0/24）；9 负例 `expect={expect_error,error_contains}` 已合规。去向：15 正例全部**合入**（层链整形后保留语义；断言值照抄——UDP 面已实测，hex 面先跑后钉）；9 负例全部**合入**（锚词已对真实代码行）。

| # | ID | 去向 | 改写要点 |
|---:|---|---|---|
| 1 | `rtmfp_handshake_ipv4` | 合入 | 顶层四键→`ip`/`udp` 层；`rtmfp` 子映射→`layers[2].rtmfp`；补 `flow_control.flows=1`；cookie 派生 hex 断言 P5 补 |
| 2 | `rtmfp_handshake_ipv6` | 合入 | 同 #1 + `ip` 层填 IPv6 地址（`2001:db8:48::10→::20`）；`ipv6.nxt=17` 断言补钉 → G-RTMFP-4 |
| 3 | `rtmfp_reliable_flow` | 合入 | 同 #1；frames hex（kind 0x05/ack 前缀）P5 补 |
| 4 | `rtmfp_unreliable_flow` | 合入 | 同 #1；kind 0x06/seq=0 hex 补 |
| 5 | `rtmfp_retransmission` | 合入 | 同 #1；重传字节 same_as_packet 断言补 |
| 6 | `rtmfp_fragment_reassembly` | 合入 | 同 #1；三片 idx/count/total hex 断言补 |
| 7 | `rtmfp_ping_pong` | 合入 | 同 #1；kind 0x09/0x0A 补 |
| 8 | `rtmfp_close` | 合入 | 同 #1；kind 0x0B + 终止断言补 |
| 9 | `rtmfp_multi_flow` | 合入 | 同 #1；flow_id distinct（hex 偏移 8）补 |
| 10 | `rtmfp_multi_session` | 合入 | 同 #1；`sessions[1].src_port=40010` 保留事件级覆盖；srcport distinct 存量已覆 |
| 11 | `rtmfp_loss_and_ack_ranges` | 合入 | 同 #1；ack 前缀 ranges_count=2 hex 补 |
| 12 | `rtmfp_binary_payload` | 合入 | 同 #1；b64 解码 bytes hex 补 |
| 13 | `rtmfp_low_latency_profile` | 合入 | 同 #1；profile 不消费线字节注记（G-RTMFP-5），不冒充差异断言 |
| 14 | `rtmfp_ipv4_ipv6_same_payload` | 合入+补齐 | 同 #1；**补 IPv6 对偶 fixture 或改语义**（v1 称双地址族实测单 IPv4——G-RTMFP-4） |
| 15 | `rtmfp_keepalive_bounded` | 合入 | 同 #1；`ping_count` 零消费注记（G-RTMFP-5）；7 包断言保留 |
| 16 | `rtmfp_neg_short_header` | 合入 | 负例改写同正例形状；`header` 已对 `planner.go:287` |
| 17 | `rtmfp_neg_length_overrun` | 合入 | 同上；`length` 对 `:289` |
| 18 | `rtmfp_neg_cookie_session` | 合入 | 同上；`session` 对 `:291` |
| 19 | `rtmfp_neg_sequence_regress` | 合入 | 同上；`sequence` 对 `:293` |
| 20 | `rtmfp_neg_fragment_gap` | 合入 | 同上；`fragment` 对 `:295` |
| 21 | `rtmfp_neg_ack_unknown` | 合入 | 同上；`ack` 对 `:297` |
| 22 | `rtmfp_neg_state_order` | 合入 | 同上；`state` 对 `:299`（+自然面双保险保留） |
| 23 | `rtmfp_neg_profile_carrier` | 合入 | 同上；`profile` 对 `:150-157`（自然守卫面保留） |
| 24 | `rtmfp_neg_session_leak` | 合入 | 同上；`session` 对 `:301` |

作废 0 例，等价覆盖 0 例（无重复语义可合并）。

## 10. P3 固定动作（CORE_MEMORY §3.15 / §9.52 / §9.14 / 覆盖审计要求面）

### 10.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 同会话多事务编排：握手→数据→ack→重传→保活→close（#3/#5/#11 单会话 4–6 事务）+ 同会话多流交织（#9）+ 多会话并行（#10） | 已覆：#3/#5/#9/#10/#11 |
| ② | 非正常结束 | wire_fault 8 值 + 自然守卫（profile/role/state/leak）全部 task error 终态 | 已覆：#16–#24（9 负例，锚词逐字见 §5） |
| ③ | 长保活 | ping/pong 显式事件有界面（#7 单轮/#15 两轮+close）；周期自动保活调度 → **明确不支持**（design §11.1 #6，声明式回放族） | 已覆：#7/#15 + 明确不支持（显式声明，不用"待确认"逃逸） |

无空项。

### 10.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流/地址族/断言通道六类）

A′（引擎可构建 → 24 ID 内已覆；**A′ 补例建议 = T-26（error kind——builder `:194-201`/planner `:100-101` 已支持无用例）/T-27（#14 IPv6 对偶 fixture）**，并入与否由主线程定，不影响 §2 的 24 ID 权威口径）：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | 16B 头六字段/12 kind/cookie 派生/fragment 四元组/ack ranges/payload 三形态 | #1–#12 已覆；error kind → A′ T-26；hex 断言面 → G-RTMFP-4 |
| 业务 | 握手状态机/序号单调/重传复用/ack 越界/leak/有界保活 | #1–#11/#15 已覆；负面 #16–#24 已覆 |
| 现网 | FMS/Flash Player 会话形态/真实线格式/加密面 | 外壳已覆（概念面）；**抓包级确认 → G-RTMFP-1**；真实线格式+加密 → B′ G-RTMFP-2 |
| 多流 | 同会话多流（#9）+ 多会话（#10）+ 丢包窗口（#11） | 已覆；无缺格 |
| 地址族 | IPv4（#1）/IPv6（#2 独立例）；#14 对偶缺格 | #1/#2 已覆；**#14 IPv6 对偶 → A′ T-27** |
| 断言通道 | UDP 面（存量 130 条已覆）+ frames hex（0/24 → G-RTMFP-4 补钉，A 类不豁免） | 双通道；无 `rtmfp.*` 字段面（tshark 实测 0——诚实降级） |

B′（引擎结构缺口 → D-RTMFP-1「明确不解决 + 迁入计划」，见 design §15 G-RTMFP-2）：真实 Adobe RTMFP 线格式（变长 chunk/scrambled mask）、HMAC-SHA256 握手、AES-128 会话加密、NAT traversal 语义、周期自动保活调度（明确不支持，非 B′）。

### 10.3 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **规范反推**（Adobe RTMFP spec/RFC 7016 informational 概念面，精确章节待 G-RTMFP-1）+ design v2.0.0 §11 矩阵，**非**引擎能力面反推。引擎侧只作现状取证：`rtmfp` 已注册（`registry.go:385`）/白名单（`protocols.go:47`）/builder+planner 已落码（c12fe77，910 行）/`cases/rtmfp.json` 24 例（旧扁平形）/tshark 无 dissector 实测（0 字段）。第三源"已确认现网行为"当前=未确认级，挂 G-RTMFP-1。
- **对账两行**：**规范逻辑点总数 = 50**（design §11.1 八项 8 行 + §11.2 事件×会话状态矩阵 28 格 + §11.3 数据形态变体表 14 行）；**用例覆盖数 = 41**（八项 8 行全有结论 + 矩阵 20 格〔已覆 8 + 缺口→用例通道 12〕+ 变体 13 行，全部由 24 个语义 ID 承载）；**不适用 = 8**（矩阵 R1c2/R1c4/R3c4/R4c4/R5c4/R6c3/R6c4/R7c3，显式声明不适用≠缺口）；**A′/立项 = 1**（变体 kind 面 error 半格 → T-26）。41 + 8 + 1 = 50 ✓ 无遗漏。**反查 24/24 绿 ≠ 覆盖全**——反查只证明清单内的点有例，本对账才证明清单本身全（§9.52 原文）。
- **粒度声明（防误读）**：按 design §11 的行/格粒度计数；变体 kind 面 1 行的 error 子值（12 值中 1 个）另登 A′ T-26，**不折进 50 点重复计、也不冒充覆盖**；profile 不消费线字节（G-RTMFP-5）不改变"声明面已覆"的计数口径（#13/#23 正负对照已覆）。

### 10.4 3.14 豁免边界审计

- 本协议**UDP 无连接**——但 §3.14 明示"豁免 `sessions[]` 不等于豁免多流覆盖"。本文**不主张任何豁免**：`sessions[]` 由 design §12.3 会话表显式声明，且 #10 覆盖多会话扇出隔离。
- **多流并发**：已覆 #9（同会话 flow 1/2/3）/#10（双会话双 src_port），两维度各一例。
- **单包多载荷**：RTMFP 一事件一 datagram（引擎契约面），无单包多载荷结构——同会话多流交织（#9）即"一逻辑会话多载荷流"的规范对应面，已覆；分片重组（#6）承载大消息多包面。
- 结论：多流、多会话、多事务三项各有结论，无逃逸。

### 10.5 三源回指行

Adobe RTMFP specification + RFC 7016（informational，实践记录）→ **D-RTMFP-1**（design §13）→ `trafficgen/test/protocol_pcap/cases/rtmfp.json`（24 例）。第三源"已确认的现网行为"当前为**未确认级**（design §11.4 ②），挂 G-RTMFP-1 且按 §5.5 不写死进实现。ID 权威 = 本文 §2（15 正 + 9 负）。

### 10.6 断言契约核对结论（与 design §1/§8/§9 一致）

1. **24 ID 契约核对**：本文 §2 与 design §9 逐 ID、逐序、逐类型、逐实测包数一致——15 正例（`[4,3,4,3,5,5,4,4,5,6,6,3,3,3,7]`，65 包）+ 9 负例（`expect` 只有 `expect_error`/`error_contains`，锚词 `header/length/session/sequence/fragment/ack/state/profile` 逐字对 planner.go:281-305/:134-278 真实代码行）。
2. **断言通道核对**：存量 130 条 UDP 面断言逐条可复算（方向交换 c2s/s2c）；frames hex 面为 P5 先跑后钉补钉方向（G-RTMFP-4），不照抄 v1 口径（v1 无 hex 断言）；不使用不存在的 `rtmfp.*` 字段。
3. **诚实声明核对**：tshark 无 dissector（实测 0 字段）、纯 layers 形今天跑不通（翻译分支缺失）、profile/role/keepalive_interval/ping_count 死配置、#14 单 IPv4 勘误——四处均已在 design/本文落字，无冒充覆盖。

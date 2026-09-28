# #99 ldp（标签分发协议，Label Distribution Protocol）测试用例契约

> 版本：v1.0.1（P-PIPE 文档轨 P1–P3；v1.0.1 补结果文档过期登记 G-LDP-8）
> 日期：2026-09-28
> 配套设计：`docs/protocol-designs/99-ldp-design.md` v1.0.1（D-LDP-1）
> 旧基线：`docs/protocol-designs/41-ldp-testcase.md` v1.0.0（25 例；思路继承不搬码）
> 机器契约：`trafficgen/test/protocol_pcap/cases/ldp.json`（25/25 ID 与本版 §2 一致，顺序一致，已机读实测；**现状=违规过渡形：非负例顶层残留 70 处，合规层链形待代码阶段收敛，G-LDP-1/G-LDP-3**）
> 白话一句：**二十五条检查：十四条看正常对话（打招呼、对暗号、报地址、发标签、撤标签、说再见、多邻居并行），十一条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **25 个唯一语义 ID：14 正 + 11 负**（继承旧稿计数，负例 N1–N11）。派生规则：设计 §3 每个消息/TLV 条款、§4/§9 每个状态与邻接行为、§6 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-28 机读实测）**：25/25 例顶层键 = `{expect,id,proto,spec_json,summary}`（无 `strategy_fc`/`notes` 顶层键；`notes` 仅在 S14 的 `expect` 内，值为「首帧为 UDP 发现 Hello（混合载体），TCP 握手由 negotiated/terminates 断言」——**该 notes 文本有误**：S14 `expect` 键 = `{directional,fields,frames,has_handshake,has_payload,notes,packet_count,terminates}`，**无 `negotiated`**（全套件 25 例零出现），且 `has_handshake=false`（混合载体首帧为 UDP Hello）。正确表述：握手态由 `has_handshake`/`terminates`/`directional` 与 fields/frames 断言，非 `negotiated`；notes 属 cases JSON 内容，**本车道不改 JSON**，登记为代码阶段随改写例一并订正）；`spec_json` 顶层键 = `{layers,src_ip,dst_ip,src_port,dst_port,ldp}` ×24 + `{layers,ldp}` ×1（N1 `ldp_neg_carrier` 无四元组）；层形 `[tcp,ldp]` ×18、`[udp,ldp]` ×5、`[ip,ldp]` ×1（S14）、`[eth,ldp]` ×1（N1）；14 正例 `expect` 均含 `packet_count`；11 负例 `expect` 键集合严格为 `{expect_error,error_contains}`（干净）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`ldp.*` 字段 + `tcp.srcport/dstport` + `udp.srcport/dstport` + offset 42/54 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线**：本机 tshark **有 ldp dissector**（`tshark -G fields | grep -c '^ldp\.'` = **262 字段**，实测）——与 moxa 的"零字段"情形相反，**可用 `ldp.*` 原生字段断言**。可用通道：① `ldp.hdr.version/pdu_len/ldpid.lsr/ldpid.lsid`；② `ldp.msg.type/len/id/ubit`；③ `ldp.msg.tlv.type/len/value`；④ 具体 TLV 字段（`ldp.msg.tlv.hello.hold/targeted`、`ldp.msg.tlv.addrl.addr_family/addr`、`ldp.msg.tlv.ipv4.taddr`、`ldp.msg.tlv.fec.*`、`ldp.msg.tlv.sess.*`）；⑤ `tcp.srcport/dstport`、`udp.srcport/dstport`；⑥ frames `offset/hex`（PDU 首字节，TCP offset 54 / UDP offset 42）。

**动态字段禁止硬编码**：生成期值用 `same_as_packet`/`distinct_values`/`nonzero` 断言（本套件暂无动态例；A′ 候选见 §6.2）。

**包数约定**：TCP 单 session = 3（握手）+ N（应用事件数）+ 4（FIN 四包挥手）；UDP 每 Hello PDU = 1 packet；多 session 按 session 求和（S13 = 2×11）。数据帧从帧 4 起（TCP）/ 帧 1 起（UDP）；实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count。

**保活/重试/RST 口径**：ldp 有 KeepAlive 消息类型（0x0201），S2 为双向 KeepAlive 正例；协议层无重试/重传语义（声明式回放，设计 §11.1 第 6 项显式不适用）；RST 为框架 tcp 层能力，本协议层不新增断言；正例恒 FIN 优雅终止（UDP 例无 FIN）。

## 2. 原子用例索引（25 ID = 14 正 + 11 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count |
|---:|---|---|---|---:|
| 1 | `ldp_tcp_initialization` | 正 S1 | §3.4：TCP/646、公共头、双向 Initialization、session 参数 | 9 |
| 2 | `ldp_tcp_keepalive` | 正 S2 | §3.4：双向 KeepAlive（0x0201） | 11 |
| 3 | `ldp_address_ipv4` | 正 S3 | §3.5：Address List IPv4（0x0300/0x0101） | 10 |
| 4 | `ldp_label_mapping_ipv4` | 正 S4 | §3.6：IPv4 /24 FEC + Generic Label 0x12345 | 10 |
| 5 | `ldp_label_request_ipv4` | 正 S5 | §3.6：IPv4 /24 Label Request（0x0401，仅 FEC） | 10 |
| 6 | `ldp_label_withdraw_ipv4` | 正 S6 | §3.6：Mapping 后 Withdraw（0x0402） | 11 |
| 7 | `ldp_label_release_ipv4` | 正 S7 | §3.6：Mapping 后 Release（0x0403） | 11 |
| 8 | `ldp_label_mapping_host32` | 正 S8 | §3.6：IPv4 /32 host route（label 0xABCDE） | 10 |
| 9 | `ldp_udp_targeted_hello` | 正 S9 | §3.3：targeted discovery、UDP/646 双向端口 | 1 |
| 10 | `ldp_udp_parallel_hellos` | 正 S10 | §3.3：basic discovery 两方向、parallel neighbors 入口 | 2 |
| 11 | `ldp_notification_shutdown` | 正 S11 | §3.7：Notification/Status TLV（0x0001/0x0300） | 10 |
| 12 | `ldp_ordered_dod_allocation` | 正 S12 | §3.6：ordered control + downstream-on-demand Request/Mapping | 11 |
| 13 | `ldp_tcp_multi_session` | 正 S13 | §9：multi-session、双 LSR/并行 TCP 四元组 | 22 |
| 14 | `ldp_dual_adjacency` | 正 S14 | §4：basic + targeted 双 adjacency 混合载体 | 12 |
| 15 | `ldp_neg_carrier` | 负 N1 | §6 N1：缺少 UDP/TCP 载体（eth 判死） | — |
| 16 | `ldp_neg_port` | 负 N2 | §6 N2：非 646 端口 | — |
| 17 | `ldp_neg_ipv6_profile` | 负 N3 | §6 N3：未定义 IPv6 profile | — |
| 18 | `ldp_neg_pdu_length` | 负 N4 | §6 N4：PDU length 注入 | — |
| 19 | `ldp_neg_message_length` | 负 N5 | §6 N5：Message length 注入 | — |
| 20 | `ldp_neg_tlv_length` | 负 N6 | §6 N6：TLV length 注入 | — |
| 21 | `ldp_neg_unknown_message` | 负 N7 | §6 N7：unknown message（事件 kind `wire_fault` 非法 kind 路径） | — |
| 22 | `ldp_neg_label_bounds` | 负 N8 | §6 N8：label >20-bit | — |
| 23 | `ldp_neg_prefix_bounds` | 负 N9 | §6 N9：IPv4 prefix length >32 | — |
| 24 | `ldp_neg_state` | 负 N10 | §6 N10：Initialization 前 KeepAlive | — |
| 25 | `ldp_neg_checksum` | 负 N11 | §6 N11：checksum 故障注入 | — |

T-编号对照：T-LDP-S1…S14 ≡ #1…#14；T-LDP-N1…N11 ≡ #15…#25（与设计 §7 一一对应）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count` + 载体与方向断言 + PDU 首字节 frames 断言；PDU hex 可由 fixture 精确预算。

### 3.1 `ldp_tcp_initialization`（9）

TCP client 192.0.2.1:50000→192.0.2.2:646，三次握手后 c2s/s2c 各发一条 Initialization。帧 4 公共头：`ldp.hdr.version=1`、`ldp.hdr.pdu_len=32`、`ldp.hdr.ldpid.lsr=192.0.2.1`、`ldp.hdr.ldpid.lsid=0`；`ldp.msg.type=0x0200`、`ldp.msg.len=22`、`ldp.msg.id=0x0000000a`、`ldp.msg.tlv.type=0x0500`、`ldp.msg.tlv.len=14`；`tcp.dstport=646`。帧 4/5（offset 54）hex 锚定完整 PDU（10B 公共头 + 消息头 + TLV）。

### 3.2 `ldp_tcp_keepalive`（11）

S1 后双向 KeepAlive（0x0201），4 应用事件。`ldp.msg.type=0x0201`、`ldp.msg.len=4`（无参数）、`ldp.hdr.pdu_len=14`；offset 54 frame 验证空参数 KeepAlive。

### 3.3 `ldp_address_ipv4`（10）

Initialization 双向后 c2s 发 Address（0x0300），Address List TLV type=0x0101、Address Family=1、地址 192.0.2.1。断言 `ldp.msg.type=0x0300`、`ldp.msg.tlv.type=0x0101`、`ldp.msg.tlv.addrl.addr_family=1` 与已注册地址字段。

### 3.4 `ldp_label_mapping_ipv4`（10）

c2s 对 `203.0.113.0/24` 发 Label Mapping（0x0400），FEC Element Type=2、AF=1、prefix length=24，Generic Label=0x12345。断言 FEC TLV（type=0x0100）与 Generic Label TLV（type=0x0200）双 TLV；frame 锚定 FEC 截断到 3 个前缀字节 + 4 字节 label。

### 3.5 `ldp_label_request_ipv4`（10）

c2s 对同一 /24 发 Label Request（0x0401），**只携带 FEC TLV**，不凭空添加 Generic Label。断言 `ldp.msg.type=0x0401` + FEC type/AF/length/prefix value。

### 3.6 `ldp_label_withdraw_ipv4`（11）

先有 Mapping，再由 c2s Withdraw（0x0402）撤销该 /24 与 label 0x12345。4 应用事件；断言 0x0402 与 0x0403 不混（Withdraw ≠ Release）。

### 3.7 `ldp_label_release_ipv4`（11）

先有 Mapping，再由 c2s Release（0x0403）释放该 /24 binding（绑定）。断言 0x0403 与相同 FEC/label。

### 3.8 `ldp_label_mapping_host32`（10）

对 `192.0.2.1/32` 发 Label Mapping，label=0xABCDE。断言 FEC prefix length=32、prefix value 为完整 4 字节地址，防 `/32` 被错截为 /24。

### 3.9 `ldp_udp_targeted_hello`（1）

UDP 192.0.2.1:646→192.0.2.2:646 发 targeted Hello（0x0100），Hold Time=15、Targeted bit=1、IPv4 transport address=192.0.2.1。断言 `udp.srcport=udp.dstport=646`、`ldp.hdr.pdu_len=30`、`ldp.msg.type=0x0100`、`ldp.msg.tlv.hello.hold=15`、`ldp.msg.tlv.hello.targeted=1`、`ldp.msg.tlv.ipv4.taddr=192.0.2.1`；offset 42 frame。该例不生成 TCP 握手，targeted ≠ basic multicast。

### 3.10 `ldp_udp_parallel_hellos`（2）

UDP/646 两方向各一条 basic Hello，2 包；两包均断言 src/dst port=646 与 Hello message type，frame 分别固定 c2s 与 s2c 的 LSR ID。用于 parallel neighbors 发现面，不把两个方向合并成一个 PDU。

### 3.11 `ldp_notification_shutdown`（10）

Initialization 双向后由 s2c 发 Notification（0x0001），Status TLV type=0x0300、Status Data=0x0000000A，随后 TCP 正常终止。Notification 是合法应用事件，**不能当作 planner 错误**（与 N7 unknown message 的拒绝面区分）。

### 3.12 `ldp_ordered_dod_allocation`（11）

配置 `label_control=ordered`、`label_advertisement=downstream_on_demand`；c2s Request /24，s2c 返回 Mapping + 0x12345。断言 0x0401/0x0400 顺序，证明 Request/Mapping 顺序与 DoD 语义不被 DU 替换。

### 3.13 `ldp_tcp_multi_session`（22）

两个独立 TCP session 使用 `sessions[].src_port` 50000/50001、各自不同 LSR ID（192.0.2.1/192.0.2.3），各 4 事件（双向 Initialization + 双向 KeepAlive）→ 每 session 11 包，共 22。只对端口集合与各 session 的公共头/应用 frame 作断言，不假设 worker（工作进程）交织顺序；四元组不能共享 session state。

### 3.14 `ldp_dual_adjacency`（12）

同一对 LSR 同时存在 basic UDP Hello adjacency 与 targeted UDP Hello adjacency，并另建一条 TCP session（`adjacencies[]` 三元素）；2（UDP）+ 10（TCP 3+3+4）= 12 包。断言 UDP Hello targeted bit 与 TCP/646 Initialization 的 message type/LSR ID，证明 targeted/basic 发现与 TCP session 载体边界互不替代。该例走 `isCarrierMixedChain` 自产完整包分支（设计 §4），链形 `[ip,ldp]` 无 tcp/udp 层。

**正例总则**：`/32` host route、targeted Hello、Notification、dual/multi-session 均为正例形态，只有配置/线格式/状态/载体错误进入负例。

## 4. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；`expect` 键集合**严格为** `{expect_error,error_contains}`。锚词与设计 §6 表一一对应、同序：

| ID | 故障输入 | `error_contains` | 代码出处 |
|---|---|---|---|
| `ldp_neg_carrier` | 层链 `[eth,ldp]`、`carrier="raw"` | `carrier` | `builder.go:458` `unknown carrier %q` |
| `ldp_neg_port` | UDP 源端口非 646（目的 646） | `port` | `planner.go:29` |
| `ldp_neg_ipv6_profile` | IPv6 outer transport + 未定义 profile | `profile` | `planner.go:37/39` |
| `ldp_neg_pdu_length` | `fault_kind="pdu_length"` | `pdu` | `builder.go:325` |
| `ldp_neg_message_length` | `fault_kind="message_length"` | `message` | `builder.go:325` |
| `ldp_neg_tlv_length` | `fault_kind="tlv_length"` | `tlv` | `builder.go:325` |
| `ldp_neg_unknown_message` | **事件 kind `wire_fault`**（非法 kind，非 config 级 `fault_kind`；实测 `events[2]={kind:"wire_fault"}`，嵌套 `fault_kind`/`value` 被静默丢弃） | `unknown` | `builder.go:503` `event 2: unknown kind "wire_fault"` |
| `ldp_neg_label_bounds` | `fault_kind="label_bounds"`（或 label 0x100000） | `label` | `builder.go:325` + `:520` |
| `ldp_neg_prefix_bounds` | IPv4 FEC `/33` | `prefix` | `builder.go:309` |
| `ldp_neg_state` | 无 Initialization 先发 KeepAlive | `state` | `builder.go:530`（**唯一有 init 守卫的 kind**；Address/标签消息无守卫，G-LDP-7） |
| `ldp_neg_checksum` | `fault_kind="checksum"` | `checksum` | `builder.go:325` |

**负例原子性**：每例单一故障注入；单次执行不得混注。故障注入字段是测试契约，不是 RFC 5036 合法配置；失败不得产生可被误认为成功的 PCAP。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 5036（LDP Specification 全文 + §3.4/§3.5 FEC 语义）+ D-LDP-1（设计 §12）+ 本机 tshark `ldp.*` 262 字段实测 → 25 ID（本契约 §2）。第三源"已确认现网行为"当前 = **厂商实现行为未到抓包级**（Cisco/Juniper 的 DU 默认、DoD 需显式配置等以 RFC 语义为准，设计 §11.5 已注明）。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 5036 原文反推**（§3.1–3.7 逐节、§4 状态、§6 错误）+ D-LDP-1 as-built 落码 + tshark `ldp.*` 262 字段实测，**非从现有用例反推**。
- **对账两行**：**要求逻辑点总数 = 89**（八项 8 行 + 子表① 27 格 + 子表② 18 行 + 子表③ 11 行 + 用例形状 25 点〔25 ID 逐点〕）；**用例覆盖数 = 72**（八项 8 + 子表① 已覆 19 + 子表② 12 + 子表③ 8 + 形状 25）；**不适用 = 7**（子表① 3〔Hello/Initialization/Notification 的 T3 状态拒绝格〕+ 子表② 1〔IPv6 正向形态〕+ 子表③ 3〔TCP MD5/AO、GTSM、VPN/VC FEC〕）；**开放 10 格**（子表② 变体 A′ 5 + 子表① T3 列 A′ 5）= 立项覆盖（§9.36 口径，不冒充今日可跑）。72 + 7 + 10 = 89 ✓
  **粒度声明**：行/格粒度每点 1 计；G-LDP-1…G-LDP-6 不折进 89。**反查全绿 ≠ 覆盖全**（§9.52 原文）。
- **门3 抽查候选**：最复杂用例 = **#14 `ldp_dual_adjacency`**（3 adjacency 混合载体：basic UDP + targeted UDP + TCP session，12 包跨两种传输层）；交织维度 = 邻接(3)×载体(2)×方向(2)×终态(有 FIN/无 FIN)。若按 9.49/9.50 下限偏弱在"并发交错"面，**建议门3 抽 #14 + #13**（`ldp_tcp_multi_session` 补多会话独立状态面）。

### 5.3 T-编号与旧 id 对照（设计 §7 全表摘要）

`ldp_tcp_initialization` ≡ T-LDP-S1；`ldp_tcp_keepalive` ≡ T-LDP-S2；`ldp_address_ipv4` ≡ T-LDP-S3；`ldp_label_mapping_ipv4` ≡ T-LDP-S4；`ldp_label_request_ipv4` ≡ T-LDP-S5；`ldp_label_withdraw_ipv4` ≡ T-LDP-S6；`ldp_label_release_ipv4` ≡ T-LDP-S7；`ldp_label_mapping_host32` ≡ T-LDP-S8；`ldp_udp_targeted_hello` ≡ T-LDP-S9；`ldp_udp_parallel_hellos` ≡ T-LDP-S10；`ldp_notification_shutdown` ≡ T-LDP-S11；`ldp_ordered_dod_allocation` ≡ T-LDP-S12；`ldp_tcp_multi_session` ≡ T-LDP-S13；`ldp_dual_adjacency` ≡ T-LDP-S14；`ldp_neg_carrier` ≡ T-LDP-N1；`ldp_neg_port` ≡ T-LDP-N2；`ldp_neg_ipv6_profile` ≡ T-LDP-N3；`ldp_neg_pdu_length` ≡ T-LDP-N4；`ldp_neg_message_length` ≡ T-LDP-N5；`ldp_neg_tlv_length` ≡ T-LDP-N6；`ldp_neg_unknown_message` ≡ T-LDP-N7；`ldp_neg_label_bounds` ≡ T-LDP-N8；`ldp_neg_prefix_bounds` ≡ T-LDP-N9；`ldp_neg_state` ≡ T-LDP-N10；`ldp_neg_checksum` ≡ T-LDP-N11。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP session 多事件序列（#6 Withdraw：Initialization→Mapping→Withdraw；#12：Request→Mapping） | 已覆 #6/#12；A′ 补例 **`ldp_multi_txn_roundtrip`**（连续 Mapping→Request→Withdraw→Release 四轮；计 1 例） |
| ② | 非正常结束 | 正常 FIN 全 TCP 正例；应用层正常终止报文 = **Notification/Shutdown**（#11）；异常注入 = 11 条负例 | 已覆 #11 + N1–N11 |
| ③ | 长保活 | 协议层 **有** KeepAlive 消息（0x0201）——#2 双向 KeepAlive 正例；长会话 = 同连接多事件 + 多 session 展开 | 已覆 #2/#13 |

无空项：① 有已覆例 + 1 条 A′ 补例；② 有正常终止报文 + 11 条负例；③ 有 #2/#13（LDP 的 KeepAlive 是**应用层消息**，非 tcp keepalive 选项）。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 层链化 | registry `Fields` 补 ldp 键 + translate 严格解码分支 | G-LDP-1，用例 #1–#25 全依赖 |
| 端口面 | `src_port` 缺省补齐（TCP 保底递增） | `ldp_default_srcport`（变体 7） |
| 端口面 | `dst_port` 缺省补齐 646 | `ldp_default_port`（变体 8，删键不断言值） |
| 边界精化 | FEC /0 边界 | `ldp_fec_prefix0`（变体 11） |
| 边界精化 | label 下界 0 | `ldp_label_min`（变体 15） |
| 边界精化 | label 上界 1048575 | `ldp_label_max`（变体 16） |
| 多事务 | 同 session 四轮操作 | ① 的 `ldp_multi_txn_roundtrip` |
| 现网面 | 厂商 LDP 实现行为实证 | 未立项（设计 §11.5 已注明以 RFC 为准） |

**B′（框架面）**：`CheckProtoFlat` ldp presence 分支（G-LDP-2，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态（G-LDP-4，allowlist 无 `ldp` 行）/ IPv6 profile（G-LDP-6，需独立规范与 fixture）。进设计 §15，「明确不解决 + 迁入计划」。用例侧 N1 钉现状（eth 载体判死）。

### 6.3 3.14 豁免边界审计

**有长连接载体 → `sessions[]` 不豁免**（设计 §13.3 会话表 s1–s4；多 session #13 + 双邻接 #14）；多流并发 = **显式不适用**（LDP 无会话内并发流，一条 TCP session 承载一条事件序列，设计 §8 已声明）；单包多载荷 = **显式不适用**（一个 PDU 一个消息，无多 question/多 RR 类形态，如实声明）。

## 7. 覆盖反查门建议断言行（供主线程合后登记 coverage gate，本车道不碰 `coverage_gate.py`）

以下为 `check_ldp(cases)` 的建议检查项，供主线程在 P4 落码后登记：

| # | 检查项 | 判据 |
|---:|---|---|
| 1 | 白名单收 ldp | `protocols.go` 含 `"ldp": true` |
| 2 | registry ldp 行 | `DependsOn: []string{"udp"}` + `TransportOn: []string{"udp", "tcp"}` |
| 3 | registry ldp Fields 补全（G-LDP-1 落码后） | `fields` 键数 = **14**（`LDPConfig` 全键：transport/wire_profile/carrier/events/sessions/adjacencies/lsr_id/label_space/hold_time/targeted/keepalive_time/label_control/label_advertisement/fault_kind；脚本复算 `types.go:544-559`） |
| 4 | translate ldp 严格解码分支（G-LDP-1 落码后） | `chain_planner_translate.go` 含 `case "ldp":` 且含 `"ldp layer config decode"` |
| 5 | FlowMeta.LDP 直传 | `chain_planner_translate.go` 含 `LDP:   spec.LDP` |
| 6 | FlowMeta.LDP 字段 | `generator.go` 含 `LDP        *core.LDPConfig` |
| 7 | FlowSpec.LDP 字段 | `types.go` 含 `LDP       *LDPConfig` |
| 8 | main.go 空导入 + ChainPlanner | `internal/protocol/ldp` 在 `main.go` 且 `NewChainPlanner("ldp")` 在册 |
| 9 | 顶层游离键判死（**框架级通用门**，非单协议分支） | 框架级 unknown-key 白名单落码后，顶层游离键由**通用门**判死；**禁止**加 `protocol ldp no longer accepts a top-level ldp sub-config` 这类单协议黑名单分支（CORE_MEMORY §1.13 + kingbase 裁定，G-LDP-2）。今日该项**不适用**（通用门未落码） |
| 10 | 目的端口缺省 646 | `chain_planner.go` 含 `case "ldp":` 与 `spec.DstPort = 646` |
| 11 | 混合载体分支 | `chain_planner_util.go` 含 `isCarrierMixedChain` 且 `chain_planner.go` 含 `isCarrierMixedChain(p.name, chain) && spec.LDP != nil` |
| 12 | generated schema ldp 条目同代 | `layers.generated.json` 的 `ldp.depends_on == ["udp"]` 且 `transport_on == ["udp","tcp"]` |
| 13 | 顶层 ldp presence 零残留（非负例） | 无「有 `layers` + 顶层 `ldp` dict + 非 `expect_error`」的例；存量 14 例命中，**待代码阶段收敛**（**今日红**） |
| 14 | 正例顶层键白名单（§1.11/§1.13 判据：非负例顶层键 = 0） | 非负例顶层键 ⊆ `{layers, strategy_fc, ttl, flow_control, output, output_config, group_id}`；存量 70 处残留（14 × 5）**待代码阶段收敛**（**今日红**） |
| 15 | 9 种消息类型全覆盖 | cases 中 `ldp.msg.type` 断言集 ⊇ `{0x0001,0x0100,0x0200,0x0201,0x0300,0x0400,0x0401,0x0402,0x0403}` |
| 16 | 负例锚词 11/11 | 11 负例 `error_contains` 集 = `{carrier,port,profile,pdu,message,tlv,unknown,label,prefix,state,checksum}` |
| 17 | 负例 expect 纯净 | 11/11 `expect` 键严格 `{expect_error,error_contains}` |
| 18 | packet_count 公式 | 14 正例 = `3+N+4`（UDP 例 = N），多 session 求和 |
| 19 | dual_adjacency 混合载体 | 存在 `carrier=dual_adjacency` 且 `adjacencies` 长度 = 3 的例 |

**注**：第 3/4/9/13/14 项今日为红（G-LDP-1/G-LDP-2 未落码），属**登记在案的缺口**，不得作为"今日已过"申报。

## 8. 存量审计（25 例逐条去向）

### 8.1 存量实测面（2026-09-28）

`cases/ldp.json` **25 例**：14 正带 `packet_count`（9/11/10/10/10/11/11/10/1/2/10/11/22/12，全符合 §1 包数约定）；11 负 `expect` 键集合严格 `{expect_error,error_contains}`；顶层键 `{layers,src_ip,dst_ip,src_port,dst_port,ldp}` ×24 + `{layers,ldp}` ×1；层形 `[tcp,ldp]` ×18 / `[udp,ldp]` ×5 / `[ip,ldp]` ×1 / `[eth,ldp]` ×1。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **存量跑的是过渡态混合形，不是纯层链**：`spec_json` 的 `layers=[{tcp:{}},{ldp:{}}]` 只是**空壳**（`ldp` 层 config 恒 `{}`，既不校验也不消费——`chain_planner_translate.go:756` 只建空 `LDPConfig`），真实配置住顶层 `ldp` 子映射 + 顶层四元组。旧 id 的 packet_count 断言**今日有效**，但顶层键断言今日是**违规形**。
2. **「今日能绿」不成立——须先接入离线 suite（复跑实测）**：ldp **未接入** `layer_chain_suite_test.go`——`chainSuiteProtos`（`:70-78`）不含 `ldp`、空白导入块（`:43-63`，含块注释 `:43` 与右括号 `:63`；导入行 `:44-62`）不含 `internal/protocol/ldp`（`git log -p -S 'protocol/ldp"' -- trafficgen/test/protocol_pcap/layer_chain_suite_test.go` 零命中；**须带该路径过滤**——不带时另有 2 个 commit 命中该字符串：`81cefc7`（server 侧注册 ldp 规划器）、`cabc0b4`（本修轮），二者都不涉及该离线 suite）。实跑 `CHAIN_PROTO=ldp go test -run TestLayerChainSuite ./test/protocol_pcap/` → **FAIL，25/25 全红**，错因 `layers: generator not implemented for layer "ldp"`（ldp 生成器未链接，与 `CheckProtoFlat` 无关）。在**副本**补 ldp 空导入 + `chainSuiteProtos["ldp"]=true` 后重跑 → **25/25 PASS（36.8s）**，此时才复现下述机制。故正确表述为「**接入离线 suite 后**可绿」；接入属代码阶段改动，不在文档阶段做。
   机制本身（接入后）：离线 suite（`:225-231`）剥离 `layers` 后把顶层扁平键**直传** `core.MapToFlowSpec`，**不经** `CheckProtoFlat`。
3. **MCP 真实路径会 400（实测）**：`schema/semantic.go:130` 对全部协议调 `CheckProtoFlat`；实调 `CheckProtoFlat("ldp", {layers, src_ip:"192.0.2.1"})` → `"protocol ldp no longer accepts flat config field src_ip (…)"`。故存量 25 例**不是合法 MCP 任务 spec**（违反 §14.1/§14.2）。
4. **顶层 ldp presence 不判死**：`CheckProtoFlat` 无 ldp 分支（`grep -c` = 0）→ 今日建 presence 负例会**真绿 = 假通过**，故不建（G-LDP-2）。实调 `CheckProtoFlat("ldp", {layers, ldp:{}})` → `""`（空，不判死）。
5. **结果文档过期（G-LDP-8）**：`trafficgen/docs/protocol-pcap-test/ldp.md` 写 "Cases: 25 — pass 25, fail 0, error 0"，但该文件末次提交 `91f2487`（2026-08-30）**早于**判死提交 `0417be5`（2026-09-13）两周；`cases/ldp.json` 末改 `ed62038`（2026-08-30）同日；`docs/protocol-pcap-test/ldp/` 目录**不存在**（`ls` 实测 `No such file or directory`，0 个 pcap，表内 14 条 `[pcap](ldp/*.pcap)` 全为死链）。**该 25/25 pass 是过期产物，不代表今日可跑**。**ldp 特例**：与 pcep 不同，ldp 连"去五键即可用"的低成本解封路径也没有——今日经 MCP 建策略 **24/25 例 400**（五键在；唯一例外 `ldp_neg_carrier` 不带五键，create 通过但任务期 `ldp: unknown carrier "raw"` 失败），且 ldp **从未接入离线 suite**（`chainSuiteProtos` 与空白导入块均无 ldp），实跑 `CHAIN_PROTO=ldp go test -run TestLayerChainSuite ./test/protocol_pcap/` → **FAIL，25/25 全红**（错因 `layers: generator not implemented for layer "ldp"`）。解封须先补 G-LDP-1 并接入 suite（详见 §8.2 第 2 条与设计 §0 产物过期登记）。
6. **存量未覆盖精确边界**：FEC /0、label 0 / 1048575、缺省 `src_port`/`dst_port`、同 session 四轮操作**今日零用例**；另有 §11.2 T3 列 5 格（Address/标签消息 init 前置守卫未落码）。**A′ 候选合计 11 例**：子表② 变体 5 + 子表① T3 5 + §3.15① 多事务 1。

### 8.3 逐条去向表（25 行）

| 存量 id | T-编号 | 去向 | 改写动作（G-LDP-1 落地时） |
|---|---|---|---|
| `ldp_tcp_initialization` | T-LDP-S1 | **改写** | 目标形状化（`ip` 层地址 + `tcp` 层端口 + `ldp` 层 events）；packet_count 9 不变 |
| `ldp_tcp_keepalive` | T-LDP-S2 | **改写** | 同上；packet_count 11 不变 |
| `ldp_address_ipv4` | T-LDP-S3 | **改写** | 同上；packet_count 10 不变 |
| `ldp_label_mapping_ipv4` | T-LDP-S4 | **改写** | 同上；packet_count 10 不变 |
| `ldp_label_request_ipv4` | T-LDP-S5 | **改写** | 同上；packet_count 10 不变 |
| `ldp_label_withdraw_ipv4` | T-LDP-S6 | **改写** | 同上；packet_count 11 不变 |
| `ldp_label_release_ipv4` | T-LDP-S7 | **改写** | 同上；packet_count 11 不变 |
| `ldp_label_mapping_host32` | T-LDP-S8 | **改写** | 同上；packet_count 10 不变 |
| `ldp_udp_targeted_hello` | T-LDP-S9 | **改写** | 地址迁 `ip` 层、端口迁 `udp` 层；offset 42 不变；packet_count 1 不变 |
| `ldp_udp_parallel_hellos` | T-LDP-S10 | **改写** | 同上；packet_count 2 不变 |
| `ldp_notification_shutdown` | T-LDP-S11 | **改写** | 同 S1 动作；packet_count 10 不变 |
| `ldp_ordered_dod_allocation` | T-LDP-S12 | **改写** | 同上；packet_count 11 不变 |
| `ldp_tcp_multi_session` | T-LDP-S13 | **改写** | `sessions[]` 迁层内；packet_count 22 不变 |
| `ldp_dual_adjacency` | T-LDP-S14 | **改写** | `adjacencies[]` 迁层内；链形 `[ip,ldp]` 保持；packet_count 12 不变 |
| `ldp_neg_carrier` | T-LDP-N1 | **改写** | `ldp` 子映射迁层内；锚词 `carrier` 不变 |
| `ldp_neg_port` | T-LDP-N2 | **改写** | 同上 |
| `ldp_neg_ipv6_profile` | T-LDP-N3 | **改写** | 同上 |
| `ldp_neg_pdu_length` | T-LDP-N4 | **改写** | 同上 |
| `ldp_neg_message_length` | T-LDP-N5 | **改写** | 同上 |
| `ldp_neg_tlv_length` | T-LDP-N6 | **改写** | 同上 |
| `ldp_neg_unknown_message` | T-LDP-N7 | **改写** | 同上 |
| `ldp_neg_label_bounds` | T-LDP-N8 | **改写** | 同上 |
| `ldp_neg_prefix_bounds` | T-LDP-N9 | **改写** | 同上 |
| `ldp_neg_state` | T-LDP-N10 | **改写** | 同上 |
| `ldp_neg_checksum` | T-LDP-N11 | **改写** | 同上 |

无"作废不注原因"：0 作废，0 等价覆盖（全部改写 + 6 新增）。

## 9. 实现后执行建议

1. **代码阶段顺序**：G-LDP-1（registry Fields + translate 严格解码分支 + MapToFlowSpec 顶层收敛 + schemagen 重跑）→ 存量 25 例改写（删顶层旧键）→ 先跑后钉 25 例 → 补 A′ 11 条（子表② 变体 5 + 子表① T3 5 + `ldp_multi_txn_roundtrip`）→ 全量复跑。
2. **实测顺序**：先 S1/S2（TCP 基线与 KeepAlive 11 包），再 S9/S10（UDP offset 42），再 S4/S5/S8（FEC /24 与 /32），再 S6/S7（Withdraw/Release 区分），再 S11/S12，最后 S13（多 session 聚合）、S14（混合载体）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=ldp` 全量不是增量）；门2④ 反查绿后进 P6。
4. 混合载体例（S14）走 `isCarrierMixedChain` 自产完整包分支，实现期须确认 UDP Hello 与 TCP 会话的包序与 packet_count 12 一致。
5. 任何厂商 LDP 实现行为的具体断言须有独立抓包证据和失败优先测试（设计 §11.5 纪律）。

## 10. 修订记录

- v1.0.0（2026-09-28）：P-PIPE #99 文档轨 P1–P3。旧稿 41-* 25 ID / packet_count / 锚词 / fixture 全量继承（思路参考不搬码）；新增形状基线机读实测（§1）、tshark 262 字段基线（§1，与 moxa 零字段情形相反）、P3 固定动作（§6）、覆盖反查门建议行（§7）、执行建议（§9）、存量审计（§8，25/25 改写）；补 A′ 候选（子表② 5 + 子表① T3 5 + 多事务 1 = 11 例）。P1–P3 合并自审 3 轮，末轮全量重核干净（结论见 `/tmp/pipe/doc-lanes/ldp.md` §3）。

# LDP（标签分发协议，Label Distribution Protocol）测试用例设计

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/41-ldp-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/ldp.json`
> 审查记录：`docs/protocol-designs/audit/41-ldp-adversarial-audit.md`
> 状态：`ldp` 层尚未注册；本文定义实现后的 PCAP（抓包文件）断言，不宣称当前套件可运行。

## 1. 测试原则与固定事实

用例从设计 §1（RFC 5036 范围/profile）、§2（UDP/TCP 载体与端口）、§3（公共头、消息、TLV、FEC、标签）、§4（session/adjacency（邻接）状态）、§5（checksum/长度/偏移）和 §6（错误传播）逐项派生。

- 正例必须有 `packet_count`、`fields` 和 `frames` 三类契约；每个字段名必须来自本机 `tshark -G fields`，本套件不写未注册 nested 字段。
- 正例使用 IPv4；UDP discovery 的 LDP payload（载荷）offset（偏移）为 42，TCP session 在无 option、未分段时为 54。
- UDP/646 每个 Hello PDU 为一个 packet；TCP 每条 session 为 `3 + 应用事件数 + 4` 包。两条 TCP session 的包数相加，不依赖调度交织顺序。
- 负例的 `expect` **严格只允许** `expect_error` 与 `error_contains`，不出现 packet_count、fields、frames、has_payload 等键。
- LDP 自身没有 checksum；`tcp.checksum`/`udp.checksum` 与 `ip.checksum` 只属于外层协议，不能写成 LDP checksum 断言。
- `/32` 是 IPv4 Prefix FEC 的合法 host route；Generic Label 的有效值为 0–1048575。IPv6 transport/profile 负例独立拒绝，不降级为 IPv4。

## 2. 用例索引

| # | ID | 类型 | 覆盖 | 载体 | packet_count |
|---:|---|---|---|---|---:|
| 1 | `ldp_tcp_initialization` | 正 S1 | TCP/646、公共头、Initialization、session 参数 | TCP | 9 |
| 2 | `ldp_tcp_keepalive` | 正 S2 | 双向 KeepAlive | TCP | 11 |
| 3 | `ldp_address_ipv4` | 正 S3 | Address List IPv4 | TCP | 10 |
| 4 | `ldp_label_mapping_ipv4` | 正 S4 | IPv4 /24 FEC + Generic Label | TCP | 10 |
| 5 | `ldp_label_request_ipv4` | 正 S5 | IPv4 /24 Label Request | TCP | 10 |
| 6 | `ldp_label_withdraw_ipv4` | 正 S6 | Mapping 后 Withdraw | TCP | 11 |
| 7 | `ldp_label_release_ipv4` | 正 S7 | Mapping 后 Release | TCP | 11 |
| 8 | `ldp_label_mapping_host32` | 正 S8 | IPv4 /32 host route | TCP | 10 |
| 9 | `ldp_udp_targeted_hello` | 正 S9 | targeted discovery、UDP/646 双向端口 | UDP | 1 |
| 10 | `ldp_udp_parallel_hellos` | 正 S10 | basic discovery 两方向（目的为 all-routers 组播）、parallel neighbors 入口 | UDP | 2 |
| 11 | `ldp_notification_shutdown` | 正 S11 | Notification/Status TLV | TCP | 10 |
| 12 | `ldp_ordered_dod_allocation` | 正 S12 | ordered control + downstream-on-demand Request/Mapping | TCP | 11 |
| 13 | `ldp_tcp_multi_session` | 正 S13 | multi-session、双 LSR/并行 TCP 四元组 | TCP×2 | 22 |
| 14 | `ldp_dual_adjacency` | 正 S14 | basic + targeted 双 adjacency 互不混淆 | UDP+TCP | 12 |
| 15 | `ldp_neg_carrier` | 负 N1 | 缺少 UDP/TCP 载体 | — | — |
| 16 | `ldp_neg_port` | 负 N2 | 非 646 端口 | — | — |
| 17 | `ldp_neg_ipv6_profile` | 负 N3 | 未定义 IPv6 profile | — | — |
| 18 | `ldp_neg_pdu_length` | 负 N4 | PDU length 越界/不一致 | — | — |
| 19 | `ldp_neg_message_length` | 负 N5 | Message length 不一致 | — | — |
| 20 | `ldp_neg_tlv_length` | 负 N6 | TLV length 不一致 | — | — |
| 21 | `ldp_neg_unknown_message` | 负 N7 | unknown message | — | — |
| 22 | `ldp_neg_label_bounds` | 负 N8 | label >20-bit | — | — |
| 23 | `ldp_neg_prefix_bounds` | 负 N9 | IPv4 prefix length >32 | — | — |
| 24 | `ldp_neg_state` | 负 N10 | Initialization 前 KeepAlive | — | — |
| 25 | `ldp_neg_checksum` | 负 N11 | UDP transport checksum 故障 | — | — |

## 3. 正向用例契约

### 3.1 `ldp_tcp_initialization`（S1）

TCP client（客户端）192.0.2.1:50000→192.0.2.2:646，三次握手后 c2s/s2c 各发送 Initialization。每条初始化包含 Common Session Parameters TLV；预期 9 包。packet 4 的公共头断言 version=1、PDU length=32、LSR ID=192.0.2.1、Label Space ID=0；message type=0x0200、message length=22、message ID=0x0000000a、TLV type=0x0500、TLV length=14、session version=1、keepalive=30、max PDU=4096。frame 从 offset 54 锚定完整初始化 payload。

### 3.2 `ldp_tcp_keepalive`（S2）

S1 后发送双向 KeepAlive（0x0201），预期 11 包。packet 6 断言 message type=0x0201、message length=4、message ID=0x0000000b、PDU length=14，并以 offset 54 frame 验证无参数 KeepAlive。

### 3.3 `ldp_address_ipv4`（S3）

Initialization 后由 c2s 发送 Address（0x0300），Address List TLV type=0x0101，Address Family=1，地址 192.0.2.1。预期 10 包；packet 6 断言 message/TLV type、TLV length=6、`ldp.msg.tlv.addrl.addr_family=1` 和已注册地址字段。

### 3.4 `ldp_label_mapping_ipv4`（S4）

c2s 对 `203.0.113.0/24` 发送 Label Mapping（0x0400），FEC Element Type=2、AF=1、prefix length=24，Generic Label=0x12345。预期 10 包；frame 从 offset 54 锚定 FEC 截断到 3 个前缀字节及 4 字节 label。

### 3.5 `ldp_label_request_ipv4`（S5）

c2s 对同一 /24 发送 Label Request（0x0401），只携带 FEC TLV，不凭空添加 Generic Label。预期 10 包；fields/frames 同时守护消息类型、FEC type/AF/length 和 `/24` prefix value。

### 3.6 `ldp_label_withdraw_ipv4`（S6）

先有 Mapping，再由 c2s Withdraw（0x0402）撤销该 /24 与 label 0x12345。预期 11 包，packet 7 是 Withdraw；不把 Withdraw 与 Release 混为同一 message type。

### 3.7 `ldp_label_release_ipv4`（S7）

先有 Mapping，再由 c2s Release（0x0403）释放该 /24 binding（绑定）。预期 11 包；packet 7 断言 0x0403 与相同 FEC/label。

### 3.8 `ldp_label_mapping_host32`（S8）

对 `192.0.2.1/32` 发送 Label Mapping，label=0xABCDE。预期 10 包；断言 FEC prefix length=32、prefix value 为完整 4 字节地址和 Generic Label，防止 `/32` 被错误截断为 /24。

### 3.9 `ldp_udp_targeted_hello`（S9）

UDP 192.0.2.1:646→192.0.2.2:646 发送 targeted Hello（0x0100），Hold Time=15，Targeted bit=1，IPv4 transport address=192.0.2.1。预期 1 包，offset 42 frame；fields 同时断言 UDP 两端口、公共头、Hello hold/targeted 和 transport address。该例不生成 TCP 握手，targeted 不等于 basic multicast。

### 3.10 `ldp_udp_parallel_hellos`（S10）

UDP/646 两方向各一条 basic Hello，预期 2 包；两包均断言 src/dst port=646 和 Hello message type，frame 分别固定 c2s 与 s2c 的 LSR ID。用于 parallel neighbors 的发现面，不把两个方向合并成一个 PDU。

### 3.11 `ldp_notification_shutdown`（S11）

Initialization 双向后由 s2c 发送 Notification（0x0001），Status TLV type=0x0300，Status Data=0x0000000A，随后 TCP 正常终止。预期 10 包；Notification 是合法应用事件，不能当作 planner 错误。

### 3.12 `ldp_ordered_dod_allocation`（S12）

配置 `label_control=ordered`、`label_advertisement=downstream_on_demand`；c2s Request /24，s2c 返回 Mapping + 0x12345。预期 11 包，packet 6/7 分别断言 0x0401/0x0400，证明 Request/Mapping 顺序与 DoD 语义不被 DU 替换。

### 3.13 `ldp_tcp_multi_session`（S13）

两个独立 TCP session 使用源端口 50000/50001、各自不同 LSR ID，均完成 Initialization + KeepAlive，预期 22 包。只对端口集合和各 session 的公共头/应用 frame 作断言，不假设 worker（工作进程）交织顺序；四元组不能共享 session state。

### 3.14 `ldp_dual_adjacency`（S14）

同一对 LSR 同时存在 basic UDP Hello adjacency 与 targeted UDP Hello adjacency，并另建一条 TCP session；预期 UDP 两包加 TCP 10 包共 12 包。断言 UDP Hello targeted bit 与 TCP/646 Initialization 的 message type/LSR ID，证明 targeted/basic 发现与 TCP session 载体边界互不替代。若实现将 adjacency 作为独立配置对象，必须按 `adjacencies` 显式绑定；不能由一个 Hello 隐式生成两个邻居。

## 4. 负向用例契约

每个负例的 `expect` 严格为：`{"expect_error": true, "error_contains": "<keyword>"}`。

| ID | 输入故障 | `error_contains` |
|---|---|---|
| `ldp_neg_carrier` | raw/缺 UDP-TCP carrier | `carrier` |
| `ldp_neg_port` | UDP 源端口 645、目的 646 | `port` |
| `ldp_neg_ipv6_profile` | IPv6 outer transport + pending IPv6 profile | `profile` |
| `ldp_neg_pdu_length` | PDU length fault | `pdu` |
| `ldp_neg_message_length` | Message length fault | `message` |
| `ldp_neg_tlv_length` | TLV length fault | `tlv` |
| `ldp_neg_unknown_message` | unknown message type 0x7fff | `unknown` |
| `ldp_neg_label_bounds` | Generic Label=0x100000 | `label` |
| `ldp_neg_prefix_bounds` | IPv4 FEC `/33` | `prefix` |
| `ldp_neg_state` | 无 Initialization 先发 KeepAlive | `state` |
| `ldp_neg_checksum` | UDP checksum fault | `checksum` |

故障注入字段是测试契约，不是 RFC 5036 合法配置；失败不得产生可被误认为成功的 PCAP。

## 5. 三方闭环与覆盖清单

1. 设计、本文和 JSON 必须拥有相同 25 个 ID、相同顺序；正例 14 个、负例 11 个。
2. JSON 每个正例必须同时存在 `packet_count`、`fields`、`frames`；负例不得存在其中任意键。
3. 正例 packet_count 依次为 `[9,11,10,10,10,11,11,10,1,2,10,11,22,12]`（另有 N1–N11 负例）；TCP offset=54、UDP offset=42；多 session 不绑定固定交织顺序。
4. 字段仅使用本机已注册的 `ldp.*`、`ip.proto`、`tcp.*`、`udp.*`；未知 nested 名称必须在实现后重新运行 tshark 探针后才可加入。
5. RFC 5036 关键字节可复算：Version=1、PDU length 从实际 PDU body 回填；message length 含 Message ID；TLV length 不含 TLV 头；/24 只带 3 个 prefix octets；/32 带 4 个；label 高 12 bits 为零。
6. 正例覆盖 basic/targeted discovery、TCP session、Initialization/KeepAlive/Address/Mapping/Request/Withdraw/Release/Notification、DU/DoD、independent/ordered、/24 与 /32、dual/multi-session；负例覆盖 carrier/port/profile/多级 length/unknown/label/prefix/state。

## 6. 实现后执行建议

先做 JSON 语法、ID 唯一性、正负 expect 结构和字段注册静态检查；层注册后按 S1–S14 分组运行，MSS 分段时改为 stream 重组断言。再逐条运行 N1–N11，确认 planner/validator 错误传播到 task error 终态。IPv6 profile、VPN/VC FEC、能力扩展和 TCP MD5/AO 取得独立规范与 fixture 后另建 profile，不修改本套件契约。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 14 个正例、11 个负例，闭环 RFC 5036 IPv4 LDP 双载体与错误边界；所有正例包含 packet_count/fields/frames。

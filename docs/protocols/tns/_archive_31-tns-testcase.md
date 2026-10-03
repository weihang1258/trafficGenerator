# TNS（Oracle Net/SQL*Net，Oracle 网络服务）测试用例设计

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/31-tns-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/tns.json`  
> 状态：`tns` 层尚未实现；本文只定义实现完成后的 pcap 断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则

本批用例从设计 §2、§3、§4、§5、§8 的每个固定字段和错误行派生。正例必须有 `packet_count`、握手/终止断言以及至少一个 `fields` 或 `frames`；负例的 `expect` 只能有 `expect_error` 和 `error_contains`，不对失败时的 pcap 作结构断言。

TNS 的可确定字节只有公共 8 字节包头和 DATA 的 flags。CONNECT/ACCEPT/REFUSE/REDIRECT 的包体，以及 TTC/SQL*Net 字节，受 Oracle 版本和协商影响，因此 JSON 使用 `payload_profile`，不写未经核实的 payload 十六进制。帧断言只观察固定头字段：

| 以太网帧偏移（IPv4） | 以太网帧偏移（IPv6） | 字节 | 语义 |
|---:|---:|---|---|
| 56 | 76 | `00 00` | packet checksum=0 |
| 58 | 78 | `01/02/04/05/06` | packet type |
| 59 | 79 | `00` | reserved |
| 60 | 80 | `00 00` | header checksum=0 |
| 62 | 82 | `00 00` | DATA flags=0（只对 DATA） |

TNS header 起点是 IPv4 offset 54、IPv6 offset 74；因此 header type 位于起点+4。`length` 的确切数值由未来 profile 编码后的 payload 决定，正例用 `tns.length` 的 `nonzero` 断言，并由 planner 的长度一致性测试验证 `length == 8 + payload bytes`，不伪造未知包体长度。

## 2. 包数和事件序

公共 TCP 小载荷约定为 3 个握手包 + 每个 TNS event（事件）一个应用数据包 + 4 个 FIN 终止包：

| 场景 | 应用事件 | packet_count |
|---|---|---:|
| CONNECT→ACCEPT | 2 | 9 |
| CONNECT→ACCEPT→DATA×2 | 4 | 11 |
| CONNECT→ACCEPT→DATA×4 | 6 | 13 |
| 两条 CONNECT→ACCEPT 流 | 2×2 | 18 |

不把 TCP ACK 或 TNS header 误算为额外应用包；MSS 分段和 ACK 合并会在实现阶段改变包数时同步修订三方文件。

## 3. 用例索引

| # | id | 类型 | 场景/覆盖 | 包数 |
|---:|---|---|---|---:|
| 1 | `tns_connect_accept` | 正 | CONNECT、ACCEPT、DATA 双向、TCP 1521 | 11 |
| 2 | `tns_refuse` | 正 | CONNECT→REFUSE，禁止 DATA | 9 |
| 3 | `tns_redirect` | 正 | CONNECT→REDIRECT，当前流不重连 | 9 |
| 4 | `tns_ttc_sqlnet_session` | 正 | TTC/SQL*Net profile 顺序，4 个 DATA | 13 |
| 5 | `tns_ipv6_connect` | 正 | IPv6、帧偏移 74 | 9 |
| 6 | `tns_multi_session` | 正 | 两条独立流、端口隔离 | 18 |
| 7 | `tns_header_fields` | 正 | length/checksum/type/reserved/header checksum/flags | 11 |
| 8 | `tns_neg_udp` | 负 | UDP 载体拒绝 | — |
| 9 | `tns_neg_packet_type` | 负 | 未知 type 拒绝 | — |
| 10 | `tns_neg_length` | 负 | 长度边界拒绝 | — |
| 11 | `tns_neg_checksum` | 负 | checksum 模式冲突拒绝 | — |
| 12 | `tns_neg_data_flags` | 负 | v1 非零 DATA flags 拒绝 | — |

## 4. 正例契约

### 4.1 `tns_connect_accept`（T-TNS-S1）

配置 `layers=[tcp,tns]`、`dst_port=1521`，事件依次为 CONNECT `connect_basic`、ACCEPT `accept_basic`、DATA `ttc_connect`、DATA `ttc_accept`，所有 DATA `data_flags=0`。

预期 11 包。packet 4/5 的 type 分别为 `0x01/0x02`，packet 6/7 的 type 均为 `0x06`；4 个应用包的 `tns.length` 非零，checksum/header checksum/reserved 均为零。IPv4 frame offset 58 的单字节断言为 `01`、`02`、`06`、`06`，offset 62（数据包 6、7）均为 `00 00`。

### 4.2 `tns_refuse`（T-TNS-S2）

事件为 CONNECT `connect_basic`、REFUSE `refuse_basic`，`reconnect=false`。预期 9 包；packet 4 type=`01`，packet 5 type=`04`，整个应用序列没有 DATA。REFUSE 原因字段不作字节断言，因为原因码和文本编码未定稿。

### 4.3 `tns_redirect`（T-TNS-S3）

事件为 CONNECT `connect_basic`、REDIRECT `redirect_basic`，`reconnect=false`。预期 9 包；packet 4/5 type=`01/05`，packet 5 后无第二个 SYN，也无 DATA。重定向地址仅由 profile 表达，不断言猜测的地址字节。

### 4.4 `tns_ttc_sqlnet_session`（T-TNS-S4）

事件为 CONNECT、ACCEPT、DATA `ttc_connect`、DATA `ttc_accept`、DATA `sqlnet_request`、DATA `sqlnet_response`。预期 13 包；packet 6、7、8、9 均为 DATA，四个 DATA flags 均为 `00 00`，profile 顺序由 `spec_json` 保持。用例只证明 TNS 包头和事件调度，不声称 SQL 语句、认证或 TTC 类型码的具体值。

### 4.5 `tns_ipv6_connect`（T-TNS-S5）

地址为 `2001:db8::1`→`2001:db8::2`，事件 CONNECT→ACCEPT，目的端口 1521。预期 9 包；packet 4 `ipv6.version=6`、`tcp.dstport=1521`，packet 4/5 的 type 位于 offset 78，分别为 `01/02`；header checksum 和 packet checksum 仍为零。TNS 字节不因 IP 版本变化。

### 4.6 `tns_multi_session`（T-TNS-S6）

配置两个 sessions，源端口 12345、12346；每条流只有 CONNECT→ACCEPT。预期 18 包，`tcp.dstport` 只有 1521，`tcp.srcport` distinct values（去重值）为 12345/12346。每流独立拥有 packet type `01/02`、correlator/TNS state（若实现提供）；不以全局 packet 序号推断跨流事件顺序。

### 4.7 `tns_header_fields`（T-TNS-S7）

事件为 CONNECT、ACCEPT、DATA `ttc_connect`、DATA `ttc_accept`。预期 11 包，应用包的 `tns.length` 必须非零且等于重组包字节数；packet/header checksum=0，reserved=0，type=1/2/6/6，DATA flags=0。帧断言使用 offset 56/58/59/60/62（IPv4），避免把未知 CONNECT/ACCEPT payload 当作规范字节。

## 5. 负例契约

负例 `expect` 只能包含下列两个键，确保失败发生在 planner/validator（校验器）边界而不是产生一个“0 包成功”的假阳性：

| id | 输入 | `error_contains` |
|---|---|---|
| `tns_neg_udp` | `layers=[udp,tns]` | `tcp` |
| `tns_neg_packet_type` | event type=`0x7f` | `type` |
| `tns_neg_length` | `wire_fault.length=7` | `length` |
| `tns_neg_checksum` | `checksum_mode=disabled` 且 packet checksum 非零 | `checksum` |
| `tns_neg_data_flags` | DATA `data_flags=1` | `data_flags` |

`wire_fault` 是未来实现的测试注入入口，不是合法 TNS payload。若实现采用不同错误文本，先更新设计和 JSON 的稳定错误锚点，再运行 suite；不能放宽到只断言任务不失败。

## 6. 三方一致性检查

1. 本文 12 个 id 与 JSON 数组一一对应，id 唯一。
2. 7 个正例均有 packet_count、fields 和/或 frames；5 个负例仅有 expect_error/error_contains。
3. 正例包数严格按设计 §7 的事件数公式计算；多会话为每流 9 包的和。
4. IPv4 frame offset 只使用 56/58/59/60/62（均从 TNS offset 54 推导）；IPv6 只使用 76/78/79/80/82（从 offset 74 推导）。
5. Frame hex 只表达包头固定字节和 DATA flags，不包含未核实 TTC/SQL*Net/CONNECT 内部字段。

## 7. 实现后执行建议

先运行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/tns.json` 和静态 id/负例检查；层注册后先执行 S1/S7，确认 header length 与重组字节，再执行 REFUSE/REDIRECT 状态门，最后执行 IPv6、多会话和 TTC/SQL*Net profile 顺序。任何 profile 的具体 payload 都须有独立 wire fixture（线上样例）和失败优先测试。

## 8. 修订记录

- v1.0.0（2026-08-20）：建立 TNS 12 条原子用例；固定包头/flags 可观察字节，覆盖五种应用包类型、TTC/SQL*Net 顺序、IPv4/IPv6、多会话和五个负例；明确不编造版本相关 payload。

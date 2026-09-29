# #139 MySQL 用例契约

> 版本：v1.0.0（P-PIPE 文档轨，as-built）  
> 日期：2026-09-29  
> 权威：`trafficgen/test/protocol_pcap/cases/mysql.json`（机读 1 例）；设计依据 `139-mysql-design.md`。  
> 本文 §2 与 cases JSON 逐条一致（ID/顺序/包数/断言/帧 hex 原文）；不作设计文档的摘要镜像。

## 1. 审计与口径

存量审计：`cases/mysql.json` 现存 ID 集合 = {`mysql-basic-session`}，无旧 ID 需要改写或作废；该 ID 保留为权威正例。同一 ID 跨 design §1/§5、testcase §2、cases JSON 三方一致。

包数口径：`min_packets=9` 是机器契约下限；case notes 自述实际生成 10 帧（3 握手 + 3 数据 + 4 FIN）。testcase 与 design 均按“≥9、实测 10”表述，不修改 JSON。

当前 `mysql-basic-session` 的 `spec_json` 是旧 flat 形（顶层 src_ip/dst_ip/src_port/dst_port/count/mysql）。本文按 cases 现状如实记录，不把它改写为层链形；迁移缺口记 G-MYSQL-3（design §11）。pcap 与 `port_group`/NIC 输出共用本文件与 JSON 的同一契约。

## 2. 逐 ID 索引（与 cases JSON 逐条一致）

| ID | 场景 | 依据链 | 包数 | 断言 |
|---|---|---|---|---|
| mysql-basic-session | MySQL 3306 冒烟：完整 TCP 握手 + 服务器问候（8.0.36）+ 登录请求 + OK 响应 + 终止 | MySQL 官方 Client/Server Protocol（packet header / handshake / OK）；design §4–§5 | min_packets=9（实测 10） | expect：has_handshake=true、negotiated=true、terminates=true、has_payload=true；fields 10 条；frames 4 条（下表） |

`mysql-basic-session` 字段断言（fields，逐条原文）：

| packet | field | value |
|---|---|---|
| 1 | tcp.flags | 0x002 |
| 1 | tcp.dstport | 3306 |
| 2 | tcp.flags | 0x012 |
| 3 | tcp.flags | 0x010 |
| 4 | mysql.packet_length | 74 |
| 4 | mysql.packet_number | 0 |
| 5 | mysql.packet_length | 80 |
| 5 | mysql.packet_number | 1 |
| 6 | mysql.packet_length | 7 |
| 6 | mysql.packet_number | 2 |

`mysql-basic-session` 帧字节断言（frames，hex 原文）：

| packet | offset | hex |
|---|---|---|
| 4 | 54 | `4a 00 00 00 0a 38 2e 30 2e 33 36` |
| 5 | 54 | `50 00 00 01 05 a0 08 00 00 00` |
| 5 | 90 | `72 6f 6f 74` |
| 6 | 54 | `07 00 00 02 00 00 00 02 00 00 00` |

原 notes（保留语义）：f4 问候包负载首字节 0x0a=protocol 10，'8.0.36' 版本，thread_id=1，salt，0x6d...=mysql_native_password；f5 登录包 0xa005=CLIENT_PROTOCOL_41|CLIENT_SECURE_CONNECTION，max_packet=8(0x08)，用户 'root' 在帧偏移 95（帧头 54+负载 41）；f6 OK 包 0x00=OK，server status 0x0002；10 帧 = 3 握手 + 3 数据 + 4 终止；f7-10 为 FIN 挥手（0x0011/0x0010/0x0011/0x0010）。**勘误**：上表 frames 断言 offset 90 才是 'root' 的实测正确偏移（54 帧头 + 4 MySQL 包头 + 负载内偏移 32）；原 note 的 54+41=95 是 JSON 自带的算术错，本文不改 JSON、以 frames 表 90 为准。

## 3. 五层覆盖

- 功能：现有 1 例覆盖“握手+问候+认证+OK+终止”主链；COM_QUERY/result-set/ERR/prepare 等 design §6 能力当前无用例——记入缺口（G-MYSQL-1），不伪报覆盖。
- 性能：无 MSS 分段/大包边界用例；design §7 的 536/1460/0xFFFFFF 边界未被断言——同属 G-MYSQL-1。
- 数据场景：Greeting 74B、登录 80B、OK 7B 的长度与字节序已断言；charset/scramble/lenenc 变体未覆盖——缺口。
- 地址与流：仅 IPv4 单流；IPv6 与非默认端口无用例——缺口（默认 3306 已由 packet 1 tcp.dstport 断言）。流关联不适用（design §3.1 理由）。
- 业务：仅基础登录会话；多事务/多会话无用例，G-MYSQL-1。

## 4. 负例纪律

当前 JSON 无 `expect_error=true` 用例。design §8 全部 validator 锚词（SrcIP/DstIP、MSS、CharacterSet、AuthPlugin、Scramble、MaxPacketSize、Opcode、BodyEncoding、ReplyEncoding、ReplyMode、StmtID）均未锚定负例；补充时逐锚词一条、执行期只有 expect_error/error_contains，不混成功结构断言。以上全部登记 G-MYSQL-1。

## 5. 缺口登记（与 design §11 同集）

G-MYSQL-1 负例与扩展正例缺失；G-MYSQL-2 动态五策略未接线；G-MYSQL-3 flat spec_json 未迁移层链；G-MYSQL-4 RSA/TLS/multi-result 待实现边界；G-MYSQL-5 过期产物 `trafficgen/docs/protocol-pcap-test/mysql.md`（e7e7d1c，2026-08-27）。

## 6. 覆盖反查门建议（同 design §12，机读可判定）

同 design §12 六条；其中 2/3/6 当前预期为红，4 部分红（FIN 序列仅 notes 无字段断言）。

## 7. 自审结论

自审 3 轮，末轮干净。机读复核：§2 表 ID/顺序与 JSON 完全一致；fields=10、frames=4、min_packets=9 逐值核对通过；缺口 5 条与 design §11 一致；负例与五层覆盖描述未把缺口伪报为已覆盖。

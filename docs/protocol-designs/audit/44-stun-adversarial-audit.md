# STUN（NAT 穿越会话工具，Session Traversal Utilities for NAT）四件套对抗审查

> 审查对象：`docs/protocol-designs/44-stun-design.md`、`docs/protocol-designs/44-stun-testcase.md`、`trafficgen/test/protocol_pcap/cases/stun.json`
> 审查日期：2026-08-20
> 审查属性：设计文档阶段；不检查 Go（编程语言）实现，不宣称 `stun` 层已注册或 suite（测试套件）已运行。
> 规范基线：RFC 5389、RFC 8489；TURN（中继穿透，Traversal Using Relays around NAT）边界参考 RFC 5766、RFC 5780。

## 1. 审查方法

本审查采用两个独立视角，并执行两轮以上自审：

1. **线格式逻辑视角**：逐字段检查 20-byte STUN header、type/class/method 编码、Message Length、magic cookie、transaction ID、attribute type/length/padding、IPv4/IPv6 XOR 地址、HMAC-SHA1 MESSAGE-INTEGRITY 和 CRC-32 FINGERPRINT 截止点，以及 UDP/TCP/TLS framing。
2. **用例覆盖视角**：从设计每个规范表、属性、载体、状态/事务和负例反查 testcase/JSON；检查 packet_count、注册字段、frames offset、动态值处理和负例 expect 结构。

执行的静态命令：

```text
tshark -G fields | grep -E '\tstun\.'
python3 -m json.tool trafficgen/test/protocol_pcap/cases/stun.json
```

目标 tshark 输出确认 `stun.*` 字段已注册，包括 type/class/method/length/cookie/id、TCP frame length、attribute family/address/port、username/realm/nonce/error/unknown、HMAC、XOR address/port 和 CRC-32；因此 JSON 没有引用自创字段或 `classicstun.*` 字段。

## 2. 规格可实现性审查

### 2.1 已确认

1. **20-byte header 闭环**：design 明确 `type(2)+length(2)+cookie(4)+id(12)`；JSON frames 在 UDP/IPv4 offset 42、UDP/IPv6 offset 62、TCP offset 54 固定 `type/length/cookie` 的稳定 bytes，动态 ID 不被硬编码。
2. **type/class/method 不混淆**：Binding request/success/error 分别为 `0x0001/0x0101/0x0111`；文档同时要求 `stun.type.class` 和 `stun.type.method`，并明确低两位必须为 0，不把 method/class 线性相加。
3. **Message Length 与 padding 分层**：长度只计 attributes，但包含每个属性的 header/value/padding；Attribute Length 不含 padding。stun_attribute_padding 用 USERNAME 长度 3、消息长度 8 和最后一个零 padding byte 做可观察例证。
4. **cookie/ID 动态边界正确**：cookie 固定 `21 12 a4 42`；transaction ID 使用 tshark `stun.id` 的 nonzero/same_as_packet，不写随机常量。多事务要求不同 ID，重传要求同 ID。
5. **XOR 地址族独立**：IPv4 XOR 以 cookie mask，IPv6 XOR 以 cookie+transaction ID mask；正例只断言 family 和非零解析字段，不编造异或结果常量。
6. **认证/指纹没有虚构动态值**：MESSAGE-INTEGRITY 和 FINGERPRINT 仅以 registered attribute type、nonzero 值观察；设计规定 HMAC 修改后的 Message Length 截止点和 fingerprint CRC 截止点必须由实现单测逐字节复算。
7. **载体边界清楚**：UDP 每个 datagram 是一条消息；TCP 使用 STUN framing 而非 segment 边界；TLS 无密钥时仅观察 TLS record，不伪造明文 STUN 字段。
8. **RFC 8489 与 TURN/5780 隔离**：RFC 8489 正例仅使用本版已定义 Binding/认证字段；RFC 5766 Allocate 等和 RFC 5780 NAT behavior discovery 只在独立负例边界拒绝，未误纳入 Binding。
9. **合法 error 与非法输入分层**：401 Unauthorized 是认证错误正例；420/UNKNOWN-ATTRIBUTES 应独立建例；header、cookie、length、attribute、integrity、transport、TURN boundary 故障是 task error。

### 2.2 实现阶段守护项（不是当前文档 finding）

| 项目 | 当前契约 | 实现前必须验证 |
|---|---|---|
| TCP packet_count | 单事务约定 8，多事务约定 12 | 实际 ACK 合并、分段和应用包号；如不同，四件套同步更新 |
| TLS packet_count | session 约定 16 | TLS record 分割/握手 fixture；无密钥不检查 STUN dissector |
| HMAC key | short-term password、long-term MD5(username:realm:password) 分层 | 实现覆盖范围、Length 回填、SHA-1 20 bytes 和错误 key |
| RFC 8489 新认证 | USERHASH/PASSWORD-ALGORITHM/SHA-256 未写正例 | 取得完整字段表和 fixture 后单独扩展，不能借本版字段名猜测 |
| FINGERPRINT | CRC-32 XOR 0x5354554e | 确认 CRC-32 多项式/输入截止点、Message Length 含 8-byte fingerprint |
| TLS 解密 | 当前只看 encrypted records | 提供密钥时需另加解密 fixture，不能复用明文 offset 断言 |
| layer registry | 当前不假定已注册 | 实现后先 query registry，再运行 suite；未注册只能 rejected/not runnable |

## 3. 正例覆盖反查

| ID | 设计锚点 | JSON 可观察结果 | 结论 |
|---|---|---|---|
| `stun_binding_udp_request` | UDP/IPv4、header、cookie/type/class/method | type/length/cookie/id、offset 42 | 通过 |
| `stun_binding_udp_success_ipv4` | success、IPv4 XOR/MAPPED、ID 关联 | type/class/method、family/address/port、same ID | 通过 |
| `stun_binding_udp_success_ipv6` | UDP/IPv6、IPv6 XOR | Next Header、family=2、XOR IPv6/port、offset 62 | 通过 |
| `stun_binding_udp_error` | error、ERROR-CODE、UNKNOWN-ATTRIBUTES | 0x0111、401、reason、不混用 comprehension-optional 属性、same ID | 通过 |
| `stun_binding_tcp_request` | TCP framing | TCP port、tcp_frame_length、STUN header、8 packets | 通过 |
| `stun_binding_tls_session` | TLS carrier confidentiality | port 5349、TLS 22/23 records、16 packets | 通过 |
| `stun_auth_attributes` | USERNAME/REALM/NONCE | registered fields and nonzero length | 通过 |
| `stun_integrity_fingerprint` | HMAC/FINGERPRINT semantics | types 0x0008/0x8028, nonzero hmac/crc | 通过 |
| `stun_attribute_padding` | Attribute Length/padding | length=3, message length=8, trailing zero | 通过 |
| `stun_retransmission` | same transaction retransmit | IDs 1=2=3, stable headers | 通过 |
| `stun_multi_transaction_udp` | multi transaction isolation | success→request1, error→request2 ID links | 通过 |
| `stun_multi_transaction_tcp` | multi transaction/session | two application exchanges, ID links | 通过 |
| `stun_ipv6_address_attributes` | IPv6 outer + IPv4/IPv6 attributes | family 1 mapped and family 2 xor | 通过 |
| `stun_rfc8489_profile` | RFC 8489 compatibility | Binding fields/username only | 通过 |
| `stun_binding_mapped_both` | MAPPED/XOR comparison | both types and address/port fields | 通过 |

## 4. 负例覆盖反查

| ID | 设计错误行 | JSON `expect` | 结论 |
|---|---|---|---|
| `stun_neg_header_short` | header <20 | only error/header | 通过 |
| `stun_neg_type_reserved_bits` | reserved/low type bits | only error/type | 通过 |
| `stun_neg_length_alignment` | length not 4-byte aligned | only error/length | 通过 |
| `stun_neg_length_overrun` | length exceeds payload | only error/length | 通过 |
| `stun_neg_bad_cookie` | bad cookie | only error/cookie | 通过 |
| `stun_neg_attribute_length` | attribute/padding overrun | only error/attribute | 通过 |
| `stun_neg_bad_integrity` | bad HMAC | only error/integrity | 通过 |
| `stun_neg_transport_mismatch` | carrier/framing mismatch | only error/transport | 通过 |
| `stun_neg_turn_boundary` | TURN/5780 enters Binding | only error/turn | 通过 |

## 5. 三方静态一致性

已用 Python（编程语言）读取 JSON 并进行结构核对，结果：

- 总数 24，ID 唯一；15 个正例在前、9 个负例在后，顺序与 design §9/testcase §2/audit 表一致。
- 正例 `packet_count` 为 `[1,2,2,2,8,16,1,1,1,3,4,12,2,1,2]`；负例全部无 `packet_count`。
- 15 个正例都有 `packet_count + fields + frames`；9 个负例的 `expect` 键集合严格是 `expect_error/error_contains`。
- 明文 offset 公式一致：Ethernet 14 + IPv4 20 + UDP 8 = 42；Ethernet 14 + IPv6 40 + UDP 8 = 62；Ethernet 14 + IPv4 20 + TCP 20 = 54。TLS record 也从 54 开始。
- 只有稳定值进入 frames：Binding type、Message Length、cookie、attribute type/length/family；动态 transaction ID、HMAC、CRC、XOR 值、nonce/mapped address 不被写成固定动态常量。
- `stun.att.*` 和 `stun.*` 字段均在 tshark -G fields 输出中；TLS 仅引用 `tls.record.*` 已注册字段。
- design/testcase/audit 明确 TURN/5780 不是 Binding 本版实现范围，JSON 用 `stun_neg_turn_boundary` 单独守边界。

## 6. Findings（发现项）及修复记录

### F-01（第 1 轮自审发现并修复）：动态值不得进入 frames

初稿审查时重点检查了所有 frame hex。发现若把 transaction ID、XOR 地址、HMAC 或 CRC 写成 fixture 常量，会与“不要编造固定动态值”的要求冲突。已修订 design §2/§5、testcase §1/§3 和 JSON：frames 只保留 `00 01`/`01 01`/`01 11`、长度、cookie、attribute type/length/family；`stun.id`/HMAC/CRC/XOR 字段改为 `nonzero` 或 `same_as_packet`，并在文档明确实现期逐字节复算。

### F-02（第 1 轮自审发现并修复）：TLS 不可见明文边界

初稿复查载体表时确认 TLS 应用数据没有解密密钥，不能在 TLS case 里要求 `stun.type` 或 STUN offset bytes。已将 TLS 正例改成只观察 `tcp.dstport=5349`、TLS handshake/application record type 和 record length；STUN header/attribute 只在明文 UDP/TCP 正例覆盖。

### F-03（第 2 轮反驳审查确认无新增缺陷）：负例结构和 ID 闭环

逐个解析 JSON 后确认 9 个负例的 `expect` 恰只有两个键，无 packet_count/fields/frames；正例都有三件断言。按 ID、packet_count、offset、注册字段、TURN 边界反查 design/testcase/JSON，未发现新增不一致。

## 7. 自审结论

STUN 20-byte header、type/class/method/length/cookie/transaction ID、UDP/TCP/TLS 载体、Binding request/success/error、XOR/MAPPED address、认证属性、HMAC/CRC 语义、IPv4/IPv6、重传、多事务和 RFC 5766/5780 边界均已形成四方闭环。当前没有 Go 修改或实现通过声明。

完成 **两轮自审**：第 1 轮发现并修复动态值 frames 和 TLS 明文边界；第 2 轮逐 ID/字段/offset/packet_count/负例结构反驳复核，最后一轮 clean（通过）。

**自审通过 2 轮，最后一轮 clean。**

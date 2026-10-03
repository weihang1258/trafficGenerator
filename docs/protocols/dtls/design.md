# DTLS（数据报传输层安全，Datagram Transport Layer Security）设计契约

> 版本：v1.2.0（D1–D8 完成；运行期边界诚实登记）
> 日期：2026-10-01
> 状态：DTLS 层已注册；20 个语义用例已落入本目录 testcase 与 cases JSON。实现缺口仍按 D-DTLS-1 登记，不把未实现能力写成已验收。
> 配套文件：`docs/protocols/dtls/testcase.md`、`trafficgen/test/protocol_pcap/cases/dtls.json`
> 规范基线：RFC 6347（DTLS 1.2）、RFC 4347（DTLS 1.0）、RFC 8446 §4.1/§5（TLS 1.3 记录/握手语义，仅作为边界参考）、RFC 768（UDP）。

## 1. 范围、证据等级和注册边界

本版定义 DTLS over UDP（基于 UDP 的 DTLS）数据面：DTLS 1.0/1.2 记录层、epoch（密钥代际）、48-bit sequence number（序列号）、握手消息分片与重组、HelloVerifyRequest cookie（Cookie 验证）、flight retransmission（飞行重传）、ChangeCipherSpec、alert、application data，以及 IPv4/IPv6、多会话和多流隔离。

DTLS 的记录头在加密前可直接观察；进入加密 epoch 后，PCAP/NIC（网卡）只能观察 content type、版本、epoch、序列号和密文长度，不能把随机密文字节解释为明文握手字段、alert level 或应用数据内容。只有显式提供的解密 fixture（固定样本）/实现单测才可断言加密内层；不得以“tshark（抓包解析器）解析成功”替代密钥证据。

当前仓库已注册 `dtls` layer、planner（规划器）、validator（校验器）。`cases/dtls.json` 收录 20 个语义 ID（14 正 + 6 负）；无未注册占位例。

## 2. 推荐配置和协议栈

推荐层链为 `[ip, udp, dtls]`；IPv6 地址同样住 `ip` 层（`src`/`dst` 写 v6 字面量），与 JSON 实况一致。DTLS 的默认 destination port（目的端口）为 4433（`dtls` 层 `FieldContract: udp.dst_port=4433`），source port（源端口）由 fixture 显式指定（正例用 44330）。事件是对象而非字符串：每个事件以 `kind` 声明形态、以 `up` 声明方向。配置是实现契约，不是当前注册承诺；下例是 `cases/dtls.json` 实际形状的压缩：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.63", "dst": "198.51.100.63"}},
    {"udp": {"src_port": 44330, "dst_port": 4433}},
    {"dtls": {"sessions": [{"events": [
      {"kind": "handshake", "up": true,  "handshake": {"type": 1, "body": "FEFD…"}},
      {"kind": "handshake", "up": false, "handshake": {"type": 2, "body": "FEFD…"}},
      {"kind": "ccs", "up": true},
      {"kind": "appdata", "up": true, "epoch": 1, "ciphertext_len": 16},
      {"kind": "alert",   "up": false, "epoch": 1, "ciphertext_len": 2}
    ]}]}}
  ],
  "flow_control": {"flows": 1}
}
```

| 配置键 | 住处 | 约束 |
|---|---|---|
| `src`/`dst` 地址 | `ip` 层 | UDP 四元组地址；正例默认目的端口 4433，不能把 DTLS 改成 TCP/TLS。 |
| `src_port`/`dst_port` | `udp` 层 | UDP 四元组端口；正例默认目的端口 4433。 |
| 流数量 | `flow_control` | `{"flows": N}`；顶层不写 `count`。 |
| `dtls.sessions[]` | `dtls` 终结层 | 每个会话独立端点覆盖（`src_ip`/`src_port`/`dst_port`/`version`）与事件列；会话内是事务的有序序列，按会话顺序整块回放。 |
| `dtls.version` | `dtls` 层 | 会话级或事件级 `"1.0"`/`"1.2"`；`1.0` 线版本 `fe ff`，`1.2` 线版本 `fe fd`；版本字段和 ClientHello offered version 必须自洽。 |
| `epoch`/`seq` | `dtls` 层事件 | 均为指针三态：缺席按状态机推进，显式 0 被采纳。epoch 为 16-bit；record `seq` 为 48-bit 大端，不能截断、回绕或跨会话共享。 |
| `cookie` | `dtls` 层事件 | 仅 `handshake.type=3`（HelloVerifyRequest）合法；`handshake.cookie` 为 hex，长度前缀自动等于实际 cookie 字节数，不硬编码运行期随机数。 |
| `handshake` | `dtls` 层事件 | 消息头含 `type`、24-bit `length`、`message_seq`、`fragment_offset`、`fragment_length`；分片必须可重组且不重叠。 |
| `ciphertext_len` | `dtls` 层事件 | 加密 epoch 的 payload 只声明长度（确定性 opaque 填充），无密钥时禁止断言明文。 |
| `events` | `dtls` 层会话 | 有序事件对象列表；每个事件以 `kind`（`handshake`/`ccs`/`alert`/`appdata`）与 `up` 声明形态和方向；握手、CCS、alert 和应用数据不得越序或跨会话引用。 |
| `src_ip`/`src_port`/`dst_port` | `dtls.sessions[]` 会话内 | 会话端点覆盖（层内字段，非顶层旧键）；`dst_port` 会话间必须一致。 |
| `session_id` | 不适用 | 当前实现以 `sessions[]` 顺序和会话端点覆盖隔离；不新增顶层会话键。 |
| `wire_fault` | `dtls` 层 | 仅负例故障注入口：`record_length`、`version_epoch`、`sequence_overflow`、`fragment_bounds`、`cookie_state`、`carrier_udp`。不是线上字段。 |
| `mss` | 不适用 | UDP/DTLS 不协商 TCP MSS；显式设置只能拒绝或标记不适用，不得生成 TCP handshake。 |

## 3. UDP 载体、数据报边界和固定偏移

DTLS 使用 UDP，不提供 TCP 字节流语义。一个 UDP datagram（数据报）可以携带一个或多个完整 DTLS records（记录），也可以因实现的分片策略承载一个完整记录；记录的 13-byte header（头部）中的 Length 才是记录边界。实现不得跨 session 拼接 datagram，也不得按 UDP payload 尾部默默截断记录。

无 Ethernet VLAN、IPv4 options（选项）或 IPv6 extension header（扩展头）时，DTLS record 起点为：

| 载体 | record 起点 | 计算 |
|---|---:|---|
| Ethernet + IPv4 + UDP | 42 | 14 + 20 + 8 |
| Ethernet + IPv6 + UDP | 62 | 14 + 40 + 8 |

UDP destination port 正例为 4433；IPv4 `ip.proto=17`，IPv6 `ipv6.nxt=17`。IPv4 UDP checksum 可为零或正确非零；IPv6 UDP checksum 必须非零且正确。NIC checksum offload（校验和卸载）差异只能改变观察方法，不能改变 wire bytes（线上字节）契约。

## 4. DTLS record header 逐字节布局

record 起点记为 `R`，固定头长 13 bytes，网络字节序：

```text
ContentType(1) | Version(2) | Epoch(2) | SequenceNumber(6) | Length(2) | Fragment(Length)
```

| 相对 offset | 宽度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 1 | Content Type | 20=ChangeCipherSpec、21=alert、22=handshake、23=application data；未知类型拒绝。 |
| 1 | 2 | Version | DTLS 1.0 为 `fe ff`，DTLS 1.2 为 `fe fd`；同一 session 不可无声明切换。 |
| 3 | 2 | Epoch | 初始明文 epoch=0；完成密钥切换后按状态递增。epoch 不能倒退或跨会话复用。 |
| 5 | 6 | Sequence Number | 48-bit big-endian；同一 epoch 单调递增，重传不得让它回绕；不同 epoch 可从 0 重新开始。 |
| 11 | 2 | Length | 仅覆盖 fragment 字节，不包含 13-byte record header；必须与 UDP 中实际 bytes 完全一致。 |
| 13 | n | Fragment | 明文 handshake/alert 等仅在未加密 fixture 可解码；加密后按 opaque payload 处理。 |

固定 raw prefix（原始前缀）示例（DTLS 1.2、epoch 0、sequence 0、空 fragment）：`16 fe fd 00 00 00 00 00 00 00 00 00 00`。示例仅用于稳定边界断言；运行期随机端口、cookie、加密内容不得硬编码。

## 5. Content Type、epoch 和序列空间

DTLS 1.0/1.2 初始握手记录使用 epoch 0。`ChangeCipherSpec` 是 content type 20 的独立记录；在传统 DTLS 1.2 profile 中，CCS 前后的加密状态切换使后续记录进入新的 epoch。Alert 为 type 21，application data 为 type 23；加密后只能断言外层记录头及长度，不能声称看到 alert 的两个明文字节或应用协议。

每个方向分别维护 epoch 与 48-bit record sequence。实现必须保证：

- 同一 epoch 内每个新发送的 record（包括重传）都必须使用严格递增、不回退的 record sequence；重传复用原 handshake message 的 `message_seq`/fragment 语义，但不能复用 record sequence。达到 `0xffffffffffff` 后不得静默回绕，必须报 overflow 或停止该 epoch。
- epoch 变化不能把旧 epoch 的 sequence、cipher state（密码状态）或 replay window（重放窗口）带入新 epoch。
- 多会话即使使用相同四元组模板，也必须独立计数；多流输出不以全局 sequence 代替会话 sequence。
- 加密 payload 的 Length 包括显式 nonce/认证标签等在线 profile 定义的密文字节，但不把 UDP/TLS 外层头算入。

## 6. Handshake header、fragmentation 和 reassembly

每个 handshake message（握手消息）在 record fragment 内使用 12-byte header：

```text
MessageType(1) | Length(3) | MessageSeq(2) | FragmentOffset(3) | FragmentLength(3) | Body(...)
```

`Length` 是完整消息 body 长度；`FragmentOffset`/`FragmentLength` 是本片在完整 body 中的偏移/长度。实现必须支持一个消息跨多个 records/datagrams，按 `message_seq` 和 offset 重组；片段不能越界、重叠或把不同 message_seq 拼接。完整 body 收齐前不能推进依赖该消息的状态。握手消息的 record content type 必须为 22，握手 header 的 24-bit 字段按网络序编码，不能用主机序 32-bit 值直接写入线。

正例至少覆盖 ClientHello、ServerHello、Certificate/ServerKeyExchange（按 profile）、Finished 的消息序号，以及一条跨 record 的分片和乱序到达后重组。DTLS 1.2 的 HelloVerifyRequest 属于服务端握手消息，cookie exchange 必须在第二个 ClientHello 中携带完整 cookie；DTLS 1.0 fixture 可显式关闭 cookie，不得因版本切换伪造 1.2-only 字段。

## 7. Cookie exchange、重传、超时和关闭

DTLS 1.2 无状态 cookie 流程为：客户端 ClientHello（无 cookie）→ 服务端 HelloVerifyRequest（含 cookie）→ 客户端带 cookie 的第二个 ClientHello → 正常 ServerHello/握手。Cookie 的长度前缀和实际 bytes 必须一致；服务端不能在 cookie 未验证时接受后续握手或产生 application data。为防止运行期随机性，PCAP 断言 cookie 只使用 presence、长度、前后相等或非零等动态断言，不猜测固定值。

握手以 flight 为重传单位。超时应重发未确认 flight，重传不得推进握手状态两次、重复分配 session 或产生跨 epoch 的非法记录；达到重试上限应报告 timeout/error，而不是 `completed` 且 0 packets。异常关闭可发送 alert 后关闭 UDP session；若 alert 已加密，PCAP 只断言 type=21、epoch 和长度，明文 reason 由解密 fixture/单测断言。

## 8. 加密边界和 RFC 8446 参考

DTLS 1.2 的 record payload 在握手密钥建立后可能为密文；明文 record header 仍携带 type/version/epoch/sequence/length。RFC 8446 的 TLS 1.3 内层 content type 保护语义不能直接冒充 DTLS 1.2 的外层 header；若未来支持 DTLS 1.3，应新增版本/profile，不得把 TLS 1.3 record 的末尾内层类型当作公开 DTLS 字段。

无解密密钥的 PCAP/NIC 证据仅包括 UDP/4433、方向、record header、epoch/sequence、长度、TCP 不存在，以及可观察的握手明文记录。不得断言 `handshake.type`、cookie 内容、alert level/description 或 application payload 出现在加密 record 中。提供解密 key log（密钥日志）时也必须记录解密条件和工具版本，避免把解析器推测当线上证据。

## 9. IPv4/IPv6、多会话和多流

outer IPv4 与 IPv6 是独立 fixture 维度，不能由 DTLS record version 或 inner 应用 payload 推导。每个 session 至少拥有独立 UDP 四元组、epoch/sequence、cookie 状态、重传计时器和 close 状态。多 flow 可以共享目的端口 4433，但必须以四元组或 `sessions[]` 顺序隔离，不能串用握手片段、cookie、重传 flight 或 application data。

DTLS 没有 TCP handshake/MSS/FIN。UDP datagram 的顺序、丢失和重复是正常传输条件；验证器对重传按 message_seq/flight 语义去重，而不是把重复 datagram 当新握手。实现若提供 timeout fixture，必须可观察重传次数与最终错误，不能静默成功。

## 10. 边界、异常和错误传播

至少覆盖：record Length=0、Length 最大值附近、epoch=0/1、sequence=0/最大值附近、IPv4/IPv6、cookie 空/非空、握手单片与跨 record 分片、乱序重组、CCS→加密 alert/application data、重传超时、异常 alert close、多会话和 UDP 载体错误。显式 0 不能被默认值覆盖。

负例必须在 planner/validator 处失败并传播为 task error，不能输出成功 PCAP、`completed/0 packet` 或只剩 UDP 外壳的假成功。负例执行期 `expect` 只能包含 `expect_error` 与 `error_contains`。

| ID | 故障输入 | 拒绝通道 | 目标 `error_contains` |
|---|---|---|---|
| `dtls_neg_record_truncated` | `wire_fault="record_length"`：record header 少于 13 bytes 或 Length 超出 datagram | `validateWireFault` 注入拒 | `record`（备选 `length`） |
| `dtls_neg_version_epoch` | `wire_fault="version_epoch"`：未声明版本、未知 content type、epoch 倒退/跨会话复用 | `validateWireFault` 注入拒 | `version`（备选 `epoch`/`type`） |
| `dtls_neg_sequence_overflow` | `wire_fault="sequence_overflow"`：sequence 超过 48-bit、同 epoch 回绕或重复（含重传复制 sequence） | `validateWireFault` 注入拒 | `sequence`（备选 `overflow`） |
| `dtls_neg_fragment_bounds` | handshake 24-bit 长度/offset/fragment length 越界、重叠或错误拼接（自然非法配置） | `handshakeBody` 自然守卫拒 | `fragment`（备选 `handshake`） |
| `dtls_neg_cookie_state` | cookie 出现在非 HelloVerifyRequest（type≠3）或长度不符（自然非法配置） | `handshakeBody` 自然守卫拒 | `cookie`（备选 `state`） |
| `dtls_neg_udp_carrier` | TCP/裸 IP/错误 UDP 端口、UDP checksum/载荷边界错误 | `validate_layers` 预检拒 | `udp`（备选 `transport`/`checksum`） |

`cases/dtls.json` 当前实际锚词取每行首选（`record`/`version`/`sequence`/`fragment`/`cookie`/`udp`），与 `wire_fault` 六值枚举逐值对应（`DescribeDTLSWireFault` 单权威）。

## 11. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例、6 个负例；顺序与 `testcase.md` T3 及 `dtls.json` 完全一致。`dtls_v10_legacy_record` 已按实测使用 12 包；`dtls_record_boundary_lengths` 使用 6 包，Length=0 由链级单测承接。本节及 §13–§14 用例引用一律用 `#n`（= `testcase.md` T3 的序号），跨文档结构性引用用 `T1`–`T6`（= `testcase.md` 章节）。


| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `dtls_ipv4_v12_basic` | 正 | IPv4/UDP 4433、DTLS 1.2 基本握手记录 | 12 |
| 2 | `dtls_ipv6_v12_basic` | 正 | IPv6/UDP 4433、DTLS 1.2 独立 fixture | 12 |
| 3 | `dtls_v10_legacy_record` | 正 | DTLS 1.0 `fe ff` record/version 边界 | 12 |
| 4 | `dtls_v12_cookie_exchange` | 正 | ClientHello、HelloVerifyRequest、带 cookie 的 ClientHello | 16 |
| 5 | `dtls_handshake_fragmentation` | 正 | 单握手消息跨 records 的 fragment header | 10 |
| 6 | `dtls_handshake_reassembly` | 正 | 分片乱序重组、message_seq/offset 完整性 | 10 |
| 7 | `dtls_epoch_sequence_transition` | 正 | epoch 0→1、每方向 48-bit sequence 独立递增 | 14 |
| 8 | `dtls_ccs_alert_application` | 正 | CCS、alert、application data 外层类型与关闭 | 16 |
| 9 | `dtls_retransmission_timeout` | 正 | flight 重传、超时、异常关闭/最终错误 | 18 |
| 10 | `dtls_multi_session_isolation` | 正 | 两个独立 session 的 cookie/epoch/sequence/关闭 | 24 |
| 11 | `dtls_multi_flow` | 正 | 多四元组、多方向流和不串用状态 | 12 |
| 12 | `dtls_record_boundary_lengths` | 正 | 空 record、最大附近 Length、UDP datagram 边界 | 6 |
| 13 | `dtls_pcap_nic_consistency` | 正 | PCAP/NIC 方向、4433、record header 一致 | 16 |
| 14 | `dtls_encrypted_opaque_boundary` | 正 | 加密后的外层字段可见、内层明文不可声称可见 | 10 |
| 15 | `dtls_neg_record_truncated` | 负 | record header/Length 截断 | — |
| 16 | `dtls_neg_version_epoch` | 负 | version/content type/epoch 非法 | — |
| 17 | `dtls_neg_sequence_overflow` | 负 | 48-bit sequence 溢出、回绕或重复 | — |
| 18 | `dtls_neg_fragment_bounds` | 负 | handshake 分片边界/重叠/拼接错误 | — |
| 19 | `dtls_neg_cookie_state` | 负 | cookie 状态、重传状态或握手顺序错误 | — |
| 20 | `dtls_neg_udp_carrier` | 负 | UDP/4433 载体、checksum 或 datagram 边界错误 | — |

## 12. PCAP/NIC 观察与实现完成定义

实现注册后先检查 `tshark -G fields | grep -E '\tdtls\.'`。若环境没有 DTLS dissector，使用通用 `udp.dstport`、`ip.proto`/`ipv6.nxt`、record raw bytes、长度和实际偏移；不自创 `dtls.*` 字段。明文 fixture 可使用 handshake header 字节断言，密文 fixture 只能使用外层 record 字段。

PCAP 正例必须断言方向、UDP/4433、record 数量/长度、版本、epoch、sequence、content type 和必要的 IPv4/IPv6 family。NIC 模式必须记录捕获接口和过滤器 `udp port 4433`，说明 checksum offload 与密文边界。多会话/多流不假设全局到达顺序，只断言每个 session 内的状态和序列关系。

完成定义：注册 `dtls` layer；逐字节验证 13-byte record header、48-bit sequence、12-byte handshake header 和 cookie/flight 状态；planner→worker→UDP output 完整路径能传播正负结果；-race（竞态检测）和集成测试覆盖多会话计数、重传计时器、关闭；无解密 PCAP/NIC 不声称看见加密内层。

三方契约必须保持本文 §11、`testcase.md` T3、`dtls.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例。

## 13. CORE 对照与实施门

### 13.1 P1 八项矩阵

| 规范要求 | 业务场景 | 代码现状 | 缺口/证据 |
|---|---|---|---|
| 连接模型：UDP 数据报、无 TCP 字节流（RFC 6347 §3.1） | 单会话与多会话握手 | `layers: ip→udp→dtls`，会话写入 `dtls.sessions[]` | 以 #1/#2/#11 验证会话隔离 |
| 消息/响应：ClientHello/HelloVerifyRequest/ServerHello（RFC 6347 §4.2） | cookie 交换与继续握手 | `events[]` 表达顺序 | #4；响应码不适用，见 13.2 |
| 状态机：epoch、CCS、关闭（RFC 6347 §4.1） | epoch 0→1、alert close | `epoch`/`seq` 指针与 `kind` 事件 | #7/#8 |
| 字段：13-byte record、48-bit sequence（RFC 6347 §4.1.1） | 长度/序号/字节序边界 | raw frame 与字段断言 | #1/#3/#12 |
| 错误：截断、非法版本、序号回绕 | task error 传播 | 负例 `expect_error` + 锚词 | #15–#20；运行期错误文案仍需实现实测确认 |
| 活性：flight 重传与超时（RFC 6347 §4.2.4） | 丢 flight 后重传并失败 | `retransmission_timeout` 事件形状 | #9；计时器边界待实现校准 |
| NAT/代理：四元组隔离 | 多 flow/session | 四元组住 `ip`/`udp` 层 | #10/#11 |
| 版本方言：DTLS 1.0/1.2 | `fe ff` 与 `fe fd` | `dtls` 层版本字段 | #1/#3；DTLS 1.3 不在本协议实现范围 |

### 13.2 子表

| 命令/消息×响应 | 覆盖 | 用例 |
|---|---|---|
| ClientHello→HelloVerifyRequest | 已覆盖 | #4 |
| ClientHello(cookie)→ServerHello | 已覆盖 | #1/#4 |
| CCS→encrypted records | 已覆盖 | #8 |
| alert→关闭 | 已覆盖 | #8/#9 |
| 非法 record/version/sequence/fragment/cookie/carrier→task error | 已覆盖契约 | #15–#20 |

| 数据形态变体 | 覆盖 | 用例 |
|---|---|---|
| IPv4/IPv6 | 已覆盖 | #1/#2 |
| DTLS 1.0/1.2 | 已覆盖 | #3/#1 |
| 单片/分片/乱序 | 已覆盖 | #5/#6 |
| epoch 0/1、48-bit 序号边界 | 已覆盖 | #7/#12 |
| 明文/密文 opaque | 已覆盖 | #8/#14 |
| 单会话/多会话/多流 | 已覆盖 | #1/#10/#11 |

| 商业行为 | 用例映射 | 证据/确认方式 |
|---|---|---|
| OpenSSL/主流 DTLS 服务端 cookie challenge | #4 | RFC 6347 §4.2；以 PCAP 复核 |
| flight 重传与超时关闭 | #9 | RFC 6347 §4.2.4；以 PCAP/NIC 复核 |
| 双地址族 UDP/4433 | #2/#13 | RFC 6347 §3.1；指定 NIC 抓包复核 |

### 13.3 三路对照与候选方案

| 规范原文 | 商业软件行为 | 开源实现思路 | 取舍 |
|---|---|---|---|
| RFC 6347 §4.2 cookie/flight | OpenSSL 常见 cookie challenge、超时重发 | OpenSSL `ssl/d1_*.c` 状态机按 flight 管理 | 采用显式 events，避免把密文误解析为明文 |
| RFC 6347 §4.1 record header | Wireshark/tshark 只可靠显示外层字段 | Wireshark `packet-dtls.c` 以 epoch/sequence 解剖 | 采用 raw+通用 UDP 兜底 |

| 候选方案 | 优点 | 代价 | 结论 |
|---|---|---|---|
| 显式 `sessions[].events[]` 层链 | 可表达顺序、隔离、重传 | 配置较长 | 采用；符合层链唯一真相 |
| 顶层 events/四元组旧扁平写法 | 迁移短 | 违反顶层白名单且无法表达多会话 | 不采用 |

### 13.4 依赖、错误、性能与八要素

- 依赖：`ip` 提供地址族，`udp` 提供端口和数据报边界，`dtls` 依赖会话状态（`BuildFrames` 逐会话独立 `dtlsWalker`；空/缺 `sessions` 即发一条最小 ClientHello 基线 datagram）；失败返回 task error，负例中断，不生成成功 PCAP；重传只对未确认 flight，超时达到上限中断。具体超时数值须由实现配置/实测确认。
- 性能验收：目标数字待 P5 基准确认；必须记录包/秒、bit/s、并发 session/flow、最大 record、内存、队列积压、CPU。PCAP 路校验 record 字段和数量，NIC 路用 `udp port 4433` 校验方向/卸载差异；基线、目标规模、压力、长跑、交错、背压六档均需测量。
- 八要素：文件为 `dtls` 层注册与本目录两文档/cases；接口为层链 spec 与 task error；结构为 `ip→udp→dtls`、sessions/events；流程为握手→CCS→密文→关闭；错误为 #15–#20；性能边界为上述六档与资源指标；冲突点为旧顶层字段、TCP/MSS 语义、无密钥明文断言；回滚为移除 dtls 注册及语义 cases，保留文档归档，不恢复旧扁平例。

### 13.5 动态字段清单与门 1

| 字段 | 策略 | 序号/代码位置 |
|---|---|---|
| `ip.src`/`ip.dst` | fixed/inc/rand/list/pattern，按通用 dynamic_value | 层链动态求值；以 flow index 确定 |
| `udp.src_port`/`udp.dst_port` | fixed/inc/rand/list/pattern；dst 默认 4433 | flow index；未写动态时 src_port 自动递增保底 |
| 会话身份 | 会话端点覆盖 `src_ip`/`src_port`/`dst_port`（静态覆盖声明；动态策略待补） | `dtls.sessions[]` 顺序 + 会话 `src_ip`/`src_port` 覆盖（本目录 14 正例皆静态，无五策略用例） |
| cookie | 不固定值；presence/length/same-as 断言 | JSON hex fixture（`handshake.cookie`），`handshakeBody` 自动组长度前缀 |
| epoch/seq | 不由用户动态模板生成；状态机递增（缺席+1，声明采纳并前推，显式 0 有效） | 每方向、每 epoch 独立计数（`dtlsWalker.cur`/`ctr`/`msgCtr`） |
| record ciphertext | opaque；只指定 `ciphertext_len`（确定性 `0xA5` 填充） | event 顺序，不断言随机 bytes |
| `flow_control.flows` | `flow_control` | `flows=N` 复制策略；会话内端点覆盖按 `sessions[]` 顺序隔离。 |

门 1：旧键 `src_ip/dst_ip`→`ip.src/dst`，`src_port/dst_port`→`udp`，`count`→`flow_control.flows`，顶层 `dtls` 子映射→`dtls` 层；完整例见 §2。§3 五件套为 sessions 表（`sessions[]`）、事务序列（events）、关联关系（session ID→四元组/状态）、插入位置（flight 重传可插在未确认事件后）、时间线（按 session 顺序，跨 session 可交错）。§12 清单见本节表。

## 14. D/T/C 追踪与迁移缺口登记

### 14.1 D-DTLS-1 代码设计结论

D-DTLS-1 的实现接线已完成（代码依据）：`dtls` 层已注册（`trafficgen/internal/core/layers/registry.go:958`，`DependsOn ["udp"]`、`TransportOn ["udp"]`、`FieldContract udp.dst_port=4433`、Fields = `sessions`/`wire_fault`）；严格往返解码在 `chain_planner_translate.go:2503`（四级 `DisallowUnknownFields`）；record/handshake 编码、epoch/seq/msg_seq 单解析权威在 `trafficgen/internal/protocol/dtls/builder.go`（`dtlsWalker`、`handshakeBody`、`putRecord`）；六类错误入口在 `planner.go`（3 走 `wire_fault` 注入、2 走自然守卫、1 走 `validate_layers` 预检）。本文只把已观察到的接口形状写入契约，不把未在本目录 cases 中证明的动态策略或真实计时行为扩大为实现承诺。

### 14.2 T-DTLS 原子追踪

T-DTLS-01…14 对应 §11 的 14 个正例，逐项覆盖地址族、版本、cookie、分片/重组、epoch/sequence、CCS/alert/application、重传、多会话/多流、长度边界、PCAP/NIC 和 opaque 加密边界；T-DTLS-N01…N06 对应六个负例，分别覆盖 record、version/epoch、sequence、fragment、cookie 和 UDP carrier 错误。`testcase.md` T3 与 JSON 数组顺序是当前 ID 权威。

### 14.3 C-DTLS 行为对照

| 行为来源 | 对照结论 | 用例落点 |
|---|---|---|
| RFC 4347/6347 record、cookie、flight 语义 | 采用 DTLS 1.0/1.2 的 13-byte record 与 12-byte handshake header；cookie 和重传按事件序列表达 | #4/#5/#6/#9 |
| OpenSSL/主流 DTLS cookie challenge 与关闭形态 | 采用 ClientHello→HelloVerifyRequest→带 cookie ClientHello，并把关闭作为 alert/epoch 外层断言 | #4/#8/#9 |
| tshark/PCAP 可见性边界 | 无解密证据只断言 outer record 字段、长度与 raw bytes，不声称加密内层明文 | #8/#14 |

缺口仍为：真实超时计时（G-DTLS-3）、动态五策略整格（G-DTLS-2）、IPv6 交叉格（G-DTLS-4）、商业设备取证（G-DTLS-5）与性能六档（G-DTLS-6）待补，逐条见 `testcase.md` T6；当前 cases 已按层链形状与已落地 planner 能力登记，不把缺口写成已实现。本轮为静态闭合（文档+JSON 对账），**未跑 suite/PCAP/NIC**。

- 对账：设计 §11 与 JSON 的 packet_count 对账为 12/12/12/16/10/10/14/16/18/24/12/6/16/10（#1–#14 顺序），负例无成功包数。

## 15. 运行期边界与验收状态

本轮只完成静态契约闭合：`dtls.json` 机读对账、层链形状、设计矩阵和用例映射均已核对；未运行 suite、未写/复核 PCAP、未起服务、未做 NIC 抓包。因此以下内容一律是**待验证**而不是已验收：timeout/重传真实计时与 retry 上限；四元组和业务字段的 `fixed/inc/rand/list/pattern` 五种动态策略；PCAP 解析结果；NIC 方向、校验和卸载；性能六档数字。

| 未验证边界 | 当前诚实口径 | 进入验收的证据 |
|---|---|---|
| timeout、flight 重传、retry 上限 | #9 仅是声明式事件序列，计时器数值未钉 | 同代服务端经 suite 生成 PCAP，校对重传次数与最终 error/alert |
| 五种动态策略 | 当前 14 正例均为静态标量，未宣称支持/覆盖 | 逐字段逐策略用例；验证可复现、轮转、回绕和输出差异 |
| PCAP/NIC | #13 是契约场景，未执行真实流程 | MCP→引擎→PCAP/NIC→tshark/raw 逐字段证据 |
| 性能 | 无基准承诺 | 基线、目标规模、压力、长跑、交错、背压六档，记录吞吐/并发/内存/队列/CPU/失败 |

`tshark` 对 Length=0 的 DTLS record 会标记 Malformed，不能把零长 record 当作干净正例；零长语义只由 `TestDTLSChain_ZeroLengthRecord` 链级单测承接。无 DTLS dissector 或无解密 key 时，必须退回通用 UDP/IP 字段和稳定 raw bytes，不得把解析器推测写成线上字段。

## 16. 门1三行展开（可审计版）

| CORE 行 | DTLS 对照与证据 |
|---|---|
| §1 旧键去向 | `src_ip/dst_ip`→`layers[].ip.src/dst`；`src_port/dst_port`→`layers[].udp.src_port/dst_port`；`count`→策略 `strategy_fc`（本 20 例均为单流，故无数量键）；顶层 `dtls` 子映射→`layers[].dtls`；完整例见 §2。机读结果为 20/20 正负例均仅 `spec_json.layers` 顶层键。 |
| §3 五件套 | 会话表=`dtls.sessions[]`；事务序列=`events[]`；关联关系=会话端点覆盖与独立 walker 状态；插入位置=未确认 flight 后的重传事件；时间线=会话内有序、会话间可交错；无控制/数据分离长连接，长保活已立项 `D-DTLS-KEEPALIVE-1`，不伪称覆盖。 |
| §12 动态清单 | `ip.src/dst`、`udp.src_port/dst_port` 的五策略为能力待验证；cookie/epoch/seq/密文由协议状态机或 opaque 长度生成，不是用户动态模板；序号算法在 `trafficgen/internal/protocol/dtls/builder.go` 的 `dtlsWalker.nextRecord`/`nextMsgSeq`。 |

## 17. 静态机读对账

`dtls.json` 实测总数 20（正例 14、负例 6）；ID 顺序与 §11、`testcase.md` T3 相同。`spec_json` 顶层键分布为 `{"layers"}:20`；层链分布为 `ip→udp→dtls`:19、故意 presence 负例 `ip→tcp→dtls`:1；六个负例 `expect` 恰为 `expect_error` + `error_contains`。三项 `wire_fault` 锚词已对照 `trafficgen/internal/core/dtls.go:131-144`，其余三项对照 `trafficgen/internal/protocol/dtls/builder.go` 的 `fragment`/`cookie` 守卫及层校验 `udp` 锚词。


- v1.2.0（2026-10-01）：补齐运行期边界、tshark 零长陷阱、门1三行展开和机读形状对账；保持故意 `ip→tcp→dtls` presence 负例。
- v1.1.0（2026-09-30）：按 CORE 对齐层链、三源矩阵、性能/错误/动态字段及门 1；修正注册状态、配套路径与 DTLS 1.0 实测包数。
- v1.1.1（2026-10-01）：配置示例与字段表按实际形状修正（事件对象 `kind`/`up`、`epoch`/`seq`、`ciphertext_len`、`handshake.cookie`、会话覆盖四键）；负例表补拒绝通道与首选锚词；动态字段表按实测注明静态现状；缺口按 `testcase.md` G-DTLS-1…7 回指；未改 JSON。
- v1.0.0（2026-08-20）：建立 DTLS 1.0/1.2 记录层、epoch/48-bit sequence、握手分片、cookie、重传/超时、CCS/alert/application data、加密边界、IPv4/IPv6、多会话/多流和 PCAP/NIC 契约。

# KERBEROS（Kerberos V5，网络认证协议）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与 PCAP（抓包文件）用例契约；`kerberos` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/59-kerberos-testcase.md`、`trafficgen/test/protocol_pcap/cases/kerberos.json`  
> 规范基线：RFC 4120（Kerberos V5）、RFC 6113（Kerberos Pre-Authentication）、RFC 3961（加密/校验框架）、RFC 4121（AES 加密类型）、RFC 4178（GSS-API SPNEGO 边界，仅作应用载体参考）。

## 1. 范围、证据等级和未注册边界

本设计定义 Kerberos V5 数据面：UDP/TCP destination port（目的端口）88、AS（认证服务）交换、TGS（票据授予服务）交换、应用端 AP（应用协议）交换、KRB-ERROR、票据和 principal（主体）/realm（领域）标识、RFC 6113 pre-authentication（预认证）边界，以及 TCP record length framing（记录长度封装）。覆盖 IPv4/IPv6、重传、多会话/多流、时间偏差和 replay（重放）边界。

Kerberos 消息是 ASN.1 DER（抽象语法表示法/可区分编码）结构。未提供解密密钥时，PCAP/NIC（网卡）只能断言外层 IP/UDP/TCP、端口、TCP 记录长度、Kerberos 应用标签、消息方向和可见的明文错误字段；`EncryptedData`（加密数据）中的 cipher、ticket session key（票据会话密钥）、Authenticator（认证器）和加密内层字段一律视为 opaque（不透明），不得从解析器推断明文。随机 nonce（随机数）、ticket、session key、ctime/cusec 等运行期值只能用 presence、nonzero、distinct 或 same_as 断言，不能硬编码。

当前仓库没有注册 `kerberos` layer、planner（规划器）、validator（校验器）或生成器。`cases/kerberos.json` 只保留一个 `kerberos_neg_unregistered` 占位，必须为 `expect_error=true` 且 `error_contains="unknown layer"`；占位不计入下文 20 个语义 ID。注册前的拒绝、0 包或空 PCAP 不是 Kerberos 行为通过。

## 2. 推荐配置和协议栈

推荐层链为 `[ip, udp, kerberos]` 或 `[ipv6, udp, kerberos]`；TCP 传输使用 `[ip, tcp, kerberos]` 或 IPv6 对应链。实现配置是契约，不是当前注册承诺：

```json
{
  "layers": [{"ip": {}}, {"udp": {}}, {"kerberos": {}}],
  "src_ip": "192.0.2.59",
  "dst_ip": "198.51.100.59",
  "src_port": 40159,
  "dst_port": 88,
  "kerberos": {
    "version": 5,
    "transport": "udp",
    "realm": "EXAMPLE.TEST",
    "client_principal": "user@EXAMPLE.TEST",
    "service_principal": "krbtgt/EXAMPLE.TEST@EXAMPLE.TEST",
    "exchange": "as",
    "preauth": {"required": true, "etype": 18},
    "opaque_encrypted_data": true
  }
}
```

| 配置键 | 约束 |
|---|---|
| `src_ip`/`dst_ip`、`src_port`/`dst_port` | 外层四元组；正例 destination 固定 88。UDP 与 TCP 是独立 fixture，不能用 TCP framing 解释 UDP。 |
| `transport` | 只能为 `udp` 或 `tcp`；UDP 保留 datagram 边界，TCP 每条消息必须有 4-byte big-endian record length。 |
| `version` | 只支持 Kerberos V5；应用标签必须与 KDC（密钥分发中心）消息类型一致，不伪造 V4。 |
| `realm`/`principal` | DER 中的 realm 与 name-string 结构完整；比较时保持大小写/组件边界，不把字符串拼进加密字段。 |
| `exchange`/`events` | `as`、`tgs`、`ap` 和 error 状态按顺序声明；状态不得跨 session 复用。 |
| `preauth` | RFC 6113 pre-auth 类型、method-data 和 error-data 的结构边界；PA-ENC-TIMESTAMP 的加密部分不透明。 |
| `nonce`/`ctime`/`cusec`/`till` | 显式 0 必须保留；动态值用 nonzero/same_as；skew 由时间窗口配置，不猜测运行期时钟。 |
| `ticket`/`session_key`/`authenticator` | 只声明存在、etype、长度和关联关系；没有解密证据时不得断言加密内字段。 |
| `tcp_record_length` | 4-byte unsigned big-endian，长度只覆盖完整 KerberosMessage，不包含自身 4 bytes；最大值和截断进入负例。 |
| `wire_fault` | 仅负例故障注入口：`record_truncated`、`record_length`、`tag`、`encrypted_boundary`、`replay`、`carrier`。不是合法线上字段。 |
| `flow_count`/`session_id` | 每个 AS/TGS/AP 会话独立 nonce、ticket、时间、重放窗口和 TCP framing 状态；不得跨流拼接。 |

## 3. 外层传输和固定偏移

Kerberos 使用 UDP 或 TCP 端口 88。无 Ethernet VLAN、IPv4 options 或 IPv6 extension header 时：

| 载体 | Kerberos 起点 | 计算 |
|---|---:|---|
| Ethernet + IPv4 + UDP | 42 | 14 + 20 + 8 |
| Ethernet + IPv6 + UDP | 62 | 14 + 40 + 8 |
| Ethernet + IPv4 + TCP（无 TCP options） | 54 | 14 + 20 + 20 |
| Ethernet + IPv6 + TCP（无 TCP options） | 74 | 14 + 40 + 20 |

UDP payload 的完整 datagram 是消息边界；一个 datagram 不得被静默拼接到另一 session。TCP 是字节流：每条 Kerberos message 前有四字节网络序长度，允许 TCP segment 边界切分或合并，但接收端必须按长度重组，不能把 segment 尾部当消息尾部。

IPv4 使用 `ip.proto=17`（UDP）或 `6`（TCP）；IPv6 使用 `ipv6.nxt=17` 或 `6`。IPv4 UDP checksum 可为零或正确非零；IPv6 UDP checksum 必须非零且正确。TCP handshake、ACK、FIN/RST 属于载体证据，不属于 Kerberos ASN.1 message packet count。

## 4. Kerberos V5 消息封装和 ASN.1 顶层标签

RFC 4120 顶层消息使用 application-specific constructed tag：

| 消息 | 顶层 tag（DER） | 语义 |
|---|---:|---|
| `KRB-ERROR` | `[APPLICATION 30]`（常见首字节 `0x7e`） | 错误、时间偏差、预认证要求等 |
| `AS-REQ` | `[APPLICATION 10]`（`0x6a`） | client→AS 请求 |
| `AS-REP` | `[APPLICATION 11]`（`0x6b`） | AS→client 回复 |
| `TGS-REQ` | `[APPLICATION 12]`（`0x6c`） | client→TGS 请求 |
| `TGS-REP` | `[APPLICATION 13]`（`0x6d`） | TGS→client 回复 |
| `AP-REQ` | `[APPLICATION 14]`（`0x6e`） | client→service 应用认证 |
| `AP-REP` | `[APPLICATION 15]`（`0x6f`） | service→client 应用回复 |
| `KRB-SAFE`/`KRB-PRIV` | `[APPLICATION 20]`/`21` | 可选应用保护消息；本版只要求不误判为 AS/TGS |

首字节只是稳定 tag 证据，完整 DER 长度仍需按编码解析。`pvno=5` 和 `msg-type` 必须与顶层 tag 互相一致；未知 tag、错误 msg-type、非 DER 长度或越界结构必须失败。BER（基本编码规则）可接受的宽松解析不能改变线上生成契约：生成器必须输出 definite-length DER。

## 5. AS/TGS/AP 交换状态

最小 AS 路径为 `AS-REQ → AS-REP`；需要预认证时，KDC 可先返回 `KRB-ERROR` 的 `KDC_ERR_PREAUTH_REQUIRED`，随后 client 使用 METHOD-DATA 选择 PA-ENC-TIMESTAMP 等 RFC 6113 方法重新发送 AS-REQ，最后接收 AS-REP。`AS-REP.ticket` 与 `enc-part` 的加密内容在无 key 时只能断言存在、etype 和长度。

最小 TGS 路径为 `TGS-REQ → TGS-REP`：TGS-REQ 包含服务票据（通常为 `krbtgt/...`）和 AP-REQ/Authenticator 的加密边界；TGS-REP 返回目标 service ticket。不能把 TGS-REP 的 ticket 当 AS-REP 的 ticket，不能跨 realm 或 principal 复用。

最小 AP 路径为 `AP-REQ → AP-REP`（AP-REP 可选，取决于 mutual authentication）：AP-REQ 的 ticket 与 authenticator 均可加密；客户端 principal、服务 principal、realm 和会话关联只能由明文 fixture/解密 key 证明。重放同一 AP-REQ 应触发 replay 检测或错误，不能再次建立新会话。

状态推进只在完整消息验证后发生。TCP 重组未收齐、UDP datagram 截断、KRB-ERROR 或预认证失败不得静默转为成功 AS/TGS/AP 流程。

## 6. RFC 6113 预认证边界

`KDC_ERR_PREAUTH_REQUIRED` 的 `e-data` 是 METHOD-DATA 序列；每个 PA-DATA 具有 `padata-type` 和 `padata-value` 长度边界。正例至少覆盖：

- 第一次 AS-REQ 无 PA-DATA，KRB-ERROR 明确要求预认证；
- 第二次 AS-REQ 带 PA-ENC-TIMESTAMP（或明确声明的 RFC 6113 方法），其 `EncryptedData` 的 etype、kvno、cipher 长度可见，cipher 明文不可见；
- METHOD-DATA 中多个候选方法保持线上顺序，不以最后项覆盖前项；未知但结构正确的 PA 类型只在 profile 明确允许时保留；
- PA-TGS-REQ 的 AP-REQ 载体与 AS 预认证不可混淆，不能因为都有 padata-value 就断言同一种语义。

时间戳、nonce、盐、密钥派生参数、ticket session key 和 authenticator 字段只可在拥有解密 key 的 fixture 中逐字段断言。无 key 的 PCAP 只能断言 PA-DATA type/长度、外层 `EncryptedData` etype/长度和错误码等公开边界。

## 7. Ticket、principal、realm 和加密不透明边界

`PrincipalName` 的 name-type、name-string 数量和每个 KerberosString 的 DER 长度必须自洽；realm 是独立字段，不能将 `user@REALM` 当单一 name-string 偷换。服务主体通常为 `krbtgt/REALM@REALM` 或 `service/host@REALM`，但具体组件由 fixture 显式声明。不同 session 可以共享 realm，却必须有独立 nonce/ticket/sequence/replay state。

`Ticket` 的 `tkt-vno=5`、realm、sname 和 `enc-part` 外壳可观察；`EncTicketPart` 及其 flags、key、caddr、authorization-data 在无解密证据时不可断言。`EncryptedData` 的 `etype`、可选 `kvno`、cipher bytes 长度可断言，但 cipher 内容是随机/密文，不得写固定 raw frame。`EncKDCRepPart`、`EncAPRepPart`、`Authenticator` 同理。

任何“tshark 已解析 ticket”结果都不能替代 key evidence（密钥证据）。提供 keytab/key log 时必须把解密条件和工具版本记录在测试环境中；未提供时，断言范围止于不透明边界。

## 8. Nonce、时间偏差、重放和重传

AS-REQ/TGS-REQ 中 nonce 是请求关联字段；正常 reply 应以 same_as 关联对应请求，但不同请求不得意外共享 nonce。`ctime/cusec`、`authtime/starttime/endtime/renew-till` 只有明文或解密 fixture 才能逐字段断言。允许的 clock skew（时钟偏差）必须显式配置；超出窗口应产生 `KRB_AP_ERR_SKEW` 或 KDC 错误，而不是成功建立会话。

KDC/service 应维护 replay cache（重放缓存）或等效去重状态。相同 authenticator/nonce/时间组合的重复 AP-REQ 在同一 service session 中应被拒绝或标记 replay；网络层重传若是同一请求，可重复相同 bytes，但不能生成新的独立 ticket 或推进状态两次。TCP reconnect、UDP retry 和 transport switch 必须在新连接/流边界重新处理 record framing，不得跨连接拼接半条消息。

序列/重传的 packet_count 只计算线上帧；timeout 后最终错误必须显式可观察，不得 `completed` 且 0 packet。随机 ticket/session key/nonce 使用 `presence`、`nonzero`、`distinct`、`same_as`，禁止常量猜测。

## 9. IPv4/IPv6、多会话和多流

IPv4 与 IPv6 是独立 fixture 维度；外层地址族不会改变 Kerberos DER、realm 或 principal。每个 session 至少拥有独立四元组、exchange state、nonce、ticket association、时间窗口和 replay cache。多 flow 可以共享目的端口 88，但不得串用 AS-REP、TGS ticket、AP authenticator 或 TCP record buffer。

同一逻辑交互从 UDP 切换 TCP 时，必须建立新的 TCP 连接并在每条消息前编码四字节长度；不能把 UDP payload 的 datagram 边界复制成 TCP 记录，也不能把 TCP 前缀加到 UDP。多会话输出不假设全局到达顺序，只断言每个 flow 内状态。

## 10. 边界、异常和错误传播

至少覆盖：UDP 单消息、TCP 4-byte length、TCP 多消息合并、TCP segment 切分、record length=0/最大附近、DER 长度短/长形式、顶层 tag/msg-type 不一致、KRB-ERROR、PREAUTH_REQUIRED、PA-DATA 截断、ticket/EncryptedData opaque、nonce/time skew、replay、重传、UDP↔TCP 切换、IPv4/IPv6、多会话和错误端口。

负例必须在 planner/validator（规划器/校验器）处失败并传播为 task error，不能输出成功 PCAP、`completed/0 packet` 或只有 UDP/TCP 外壳的假成功。负例执行期 `expect` 只能包含 `expect_error` 与 `error_contains`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `kerberos_neg_truncated_record` | UDP/TCP Kerberos message 或 DER header 截断、字段越界 | `record`、`length` 或 `truncated` |
| `kerberos_neg_tcp_length` | TCP 4-byte length 与消息不符、溢出或跨连接拼接 | `tcp`、`length` 或 `framing` |
| `kerberos_neg_message_tag` | 非 V5、顶层 application tag/msg-type 不匹配、非法 DER | `tag`、`version` 或 `message` |
| `kerberos_neg_encrypted_boundary` | EncryptedData 外壳/etype/cipher 长度截断，或伪造解密内字段 | `encrypted`、`cipher` 或 `boundary` |
| `kerberos_neg_time_nonce_replay` | nonce 关联错误、skew 超窗、重复 authenticator/replay | `time`、`nonce` 或 `replay` |
| `kerberos_neg_udp_carrier` | 非 UDP/TCP 88、错误 checksum、错误 IP family 或载荷边界 | `transport`、`port`、`udp` 或 `checksum` |

## 11. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例和 6 个负例；顺序必须与 `59-kerberos-testcase.md` §2 及未来注册后的 `kerberos.json` 完全一致。当前 JSON 只有不计数的注册前置占位。

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `kerberos_ipv4_udp_as_basic` | 正 | IPv4/UDP 88、V5 AS 基本交换 | 4 |
| 2 | `kerberos_ipv6_udp_as_basic` | 正 | IPv6/UDP 88 独立 AS fixture | 4 |
| 3 | `kerberos_tcp_record_framing` | 正 | TCP/88、4-byte length、合并/切分消息 | 8 |
| 4 | `kerberos_as_req_as_rep` | 正 | AS-REQ/AS-REP、nonce/realm/principal 外壳 | 4 |
| 5 | `kerberos_tgs_req_tgs_rep` | 正 | TGS-REQ/TGS-REP、krbtgt 与 service ticket 边界 | 6 |
| 6 | `kerberos_ap_req_ap_rep` | 正 | AP-REQ/AP-REP、ticket/authenticator opaque | 6 |
| 7 | `kerberos_krb_error_preauth_required` | 正 | KRB-ERROR PREAUTH_REQUIRED 与错误数据 | 4 |
| 8 | `kerberos_preauth_rfc6113` | 正 | RFC 6113 METHOD-DATA/PA-ENC-TIMESTAMP 边界 | 6 |
| 9 | `kerberos_ticket_principal_realm` | 正 | Ticket、realm、principal 组件与关联 | 6 |
| 10 | `kerberos_encrypteddata_opaque` | 正 | EncryptedData etype/长度可见、内层不可声称 | 6 |
| 11 | `kerberos_nonce_time_skew` | 正 | nonce 关联、时间窗口、合法 skew 边界 | 6 |
| 12 | `kerberos_replay_retransmission` | 正 | 请求重传去重、replay 检测和 timeout | 8 |
| 13 | `kerberos_multi_session_flow` | 正 | IPv4/IPv6、多会话/多流和 UDP↔TCP 隔离 | 12 |
| 14 | `kerberos_pcap_nic_consistency` | 正 | PCAP/NIC 方向、端口、record/DER 外壳一致 | 8 |
| 15 | `kerberos_neg_truncated_record` | 负 | UDP/TCP/DER 截断 | — |
| 16 | `kerberos_neg_tcp_length` | 负 | TCP length prefix 错误/溢出/串流 | — |
| 17 | `kerberos_neg_message_tag` | 负 | 版本、tag、msg-type、DER 非法 | — |
| 18 | `kerberos_neg_encrypted_boundary` | 负 | EncryptedData 边界或伪造内层 | — |
| 19 | `kerberos_neg_time_nonce_replay` | 负 | skew、nonce、replay 或重传状态错误 | — |
| 20 | `kerberos_neg_udp_carrier` | 负 | 传输协议/端口/checksum/载荷错误 | — |

## 12. PCAP/NIC 观察和实现完成定义

实现注册后先检查 `tshark -G fields | grep -E '\tkerberos\.'`。若环境没有 Kerberos dissector（解析器），使用通用 `udp.dstport`、`tcp.dstport`、`ip.proto`/`ipv6.nxt`、TCP length prefix 的 raw bytes、DER 顶层 tag 和真实偏移；不自创 `kerberos.*` 字段。

PCAP 正例必须断言方向、UDP/TCP 88、IPv4/IPv6 family、TCP 4-byte framing（若适用）、顶层 application tag、可见错误码/PA-DATA 长度和 packet_count。EncryptedData 内层只在明确 keytab/key log 解密 fixture 中断言。NIC 模式必须记录捕获接口和过滤器 `udp port 88 or tcp port 88`，说明 checksum offload、TCP 重组和加密边界。

完成定义：注册 `kerberos` layer；逐字节验证 DER 顶层 tag、V5/msg-type、TCP 记录长度、realm/principal 组件、PA-DATA 长度和 EncryptedData 外壳；planner→worker→UDP/TCP output 完整路径能传播正负结果；-race（竞态检测）和集成测试覆盖多会话 nonce/replay、重传和 UDP/TCP 切换；无解密 PCAP/NIC 不声称看见 ticket/session key/authenticator 内层。

三方契约必须保持本文 §11、`59-kerberos-testcase.md` §2、未来 `kerberos.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `kerberos_neg_unregistered`，且唯一预期为 `unknown layer`。

## 13. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 Kerberos V5 正例和 6 个严格负例，覆盖 RFC 4120、RFC 6113 pre-auth、UDP/TCP 88、TCP record length、AS/TGS/AP、KRB-ERROR、ticket/principal/realm、EncryptedData opaque、nonce/time skew/replay、IPv4/IPv6、多会话/多流、PCAP/NIC 和错误传播；不修改 Go 实现。

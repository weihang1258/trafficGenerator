# TLS 1.3 层链设计契约

> 版本：v1.1.0（2026-09-30）
> 范围：D1–D8；只改本文、配套 testcase 与 TLS cases，不改 Go 实现。
> 机器契约：`trafficgen/test/protocol_pcap/cases/tls.json`（15 例，顺序与 ID 权威）。
> 依据：RFC 8446、RFC 6066、RFC 7301、RFC 5280、RFC 1035；仓库 TLS 层代码与现有 cases。
> 状态：TLS 层链实现已存在；本文不宣称本轮重新运行 suite 或 NIC。

## D1 范围、角色与边界

TLS 在本仓库是 TCP 内的事件变换层，不是独立传输层。目标链固定为：

```text
[ip, tcp, tls, <terminal>]
```

本版只承诺 TLS 1.3、client 角色、ECDSA P-256 测试证书，以及内层终结层事件到 TLS ApplicationData record 的封装。TLS 不实现真实密码学，不声称生成字节可完成真实 TLS 栈握手；不覆盖 TLS 1.0–1.2、server/mTLS、PSK、0-RTT、OCSP、Alert/close_notify、文件证书或其他 key type。TLS 无 `sessions[]`、派生数据流或独立长保活语义；一次链是一个 TCP 连接。

TLS 是 9 个可选承载方（http、dns、mqtt、ftp、smtp、pop3、imap、socks5、sip）的可选底座；显式写入 `tls` 才启用。sstp 的强依赖补全由其自身契约负责，不能由本文虚构额外成功路径。

## D2 严格层链与配置权威

层链是唯一配置真相。非负例顶层只允许任务元数据、`spec_json.layers` 与策略框架字段；地址只在 `ip`，端口只在 `tcp`，TLS 参数只在 `tls`，流数只在 case 顶层 `strategy_fc`。不得把这些字段复制到顶层或 `spec_json` 顶层。

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 443}},
    {"tls": {}},
    {"http": {}}
  ]
}
```

`tls` 层字段：`version`、`sni`、`alpn`、`role`、`cert`。缺省值分别是 `tls1.3`、空 SNI、默认 ALPN `["h2","http/1.1"]`、`client` 和默认证书。`cert` 子键为 `subject`、`san`、`key_type`、`not_before`、`not_after`。

唯一保留的混合形状是负例 `tls-neg-flat`：它故意在完整层链旁放置 `src_ip`，用于验证 flat config 被拒绝；它不是迁移残留。

## D3 连接模型、事件与时间线

TCP 负责 SYN/SYN-ACK/ACK、序号、MSS 分段、FIN 和连接方向。TLS 生成器消费终结层 `MessageEvent`，先注入 7 个握手 record，再逐事件生成 ApplicationData record，并保留方向；它不重新生成 HTTP 等应用协议。

单流基线时间线为：3 个 TCP 握手包 → 7 个 TLS 握手 record → 2 个内层应用事件 → 4 个 TCP 终止包，共 16 帧。多流由 `strategy_fc: {"type":"flows","value":2}` 驱动，每流独立完整生成；TLS 没有 `sessions[]` 或跨连接关联。

握手 record 顺序与方向固定：ClientHello(1, up)、ServerHello(2, down)、EncryptedExtensions(8, down)、Certificate(11, down)、CertificateVerify(15, down)、Finished(20, down)、Finished(20, up)。

## D4 线格式、字段与偏移

无 VLAN、IP/TCP options 时，以太帧中 TCP payload 从 offset 54 开始，TLS record 头从 54 开始，record 明文从 59 开始。record 为 `content_type(1) + version(2, 0x0303) + length(2, big-endian) + payload`；握手消息为 `type(1) + uint24 length(3) + body`。握手 content type 为 22，内层事件为 23；单条明文上限为 16385，超限应分 record 后再由 TCP 分段。

ClientHello 包含 TLS 1.3 supported_versions、cipher suites、groups、signature algorithms、key_share、ALPN，SNI 非空时包含 server_name。EncryptedExtensions 回选 `alpn[0]`。Certificate 是 TLS 1.3 certificate_list，承载真实 X.509 DER；证书默认 CN/SAN/日期等由 certgen 填充。

cases 的稳定断言只钉握手类型、content type、SNI/ALPN、X.509 名称和 offset 59 的应用明文，不钉证书 DER 或 record 长度。现有确定性缺口 G-TLS-1：ECDSA DER 长度可能在进程间浮动，未来若需长度断言必须先修复确定性并重测。

## D5 动态字段、流数与包数

四元组动态字段复用框架策略。TLS 业务动态只开放：`sni`、`cert.subject`、`cert.san`；三者按 flow index 解析，支持 string 面的 fixed/list/pattern。`version`、`role`、`alpn`、`cert.key_type` 和证书日期关闭动态：它们是协议常量、形状门尚未提供逐流语义，或会改变证书/握手结构。

静态四元组在 `flows>1` 时必须拒绝，防止静默复制；动态端口与业务动态值使用同一 flow index。单流目标 16 帧，多流目标为 `16 × flows`；cases 当前用 `min_packets`，不是精确 `packet_count`。

## D6 校验、错误传播与负例

结构错误必须在建任务/验证期传播为 task error，不得返回 completed/0 packet 或只剩 TCP 外壳。当前 6 个负例及锚词如下：

| ID | 故障 | `error_contains` |
|---|---|---|
| `tls-neg-flat` | 顶层 `src_ip` 混入层链 | `no longer accepts flat config field src_ip` |
| `tls-neg-static-copy` | flows=2 且四元组全静态 | `static four-tuple` |
| `tls-neg-dyn-closed-version` | version 使用动态对象 | `does not support dynamic` |
| `tls-cert-neg-dyn-keytype` | cert.key_type 使用动态对象 | `does not support dynamic` |
| `tls-cert-neg-keytype-value` | key_type=rsa-2048 | `not supported yet` |
| `tls-cert-neg-bad-date` | not_before 非 RFC3339 | `invalid RFC3339 timestamp` |

已知但未入 cases 的拒绝面必须登记为缺口，而不是声称覆盖：非 1.3、非 client、SNI/ALPN/SAN 超长、证书对象/子键/DN/日期顺序错误、string 面 inc/rand、record 分片、IPv6、默认端口、RST、close_notify。

## D7 输出、验收与性能边界

PCAP 与 NIC 是两条输出路径，但共用同一 cases 与断言集合；本轮只维护机器契约，不宣称 NIC 或 suite 已运行。PCAP 断言应同时覆盖 tshark 字段和原始 frames；NIC 验收应以 wire bytes 为准并记录 checksum/offload 边界。

实现路径是逐事件转发，不能收集全部内层消息；队列与缓冲遵循仓库有界约束。当前没有可信的 TLS 吞吐、并发、内存或丢包基线，文档不写达成数字。G-TLS-14 记录现有 `has_payload` 为通用帧长启发式，不能单独证明 ApplicationData。

## D8 接口、缺口计划与回滚

当前层生成器接口是事件变换：读取 `req.Layer.Config` 与内层事件，生成握手及 ApplicationData；`TransformEvents()` 必须为 true，TCP 是 transport owner。证书生成器只接受 `ecdsa-p256`。任何后续修改必须同时更新 registry/schema、validator、translate、生成器、PCAP/NIC 断言与本文。

| 缺口 | 现状 | 计划/边界 |
|---|---|---|
| G-TLS-1 | ECDSA DER 长度非确定 | 代码阶段修复后再增加长度断言；本轮不改代码 |
| G-TLS-2 | 层链无 close_notify | 明确保持边界，或另立实现与 cases |
| G-TLS-3 | 版本/角色/长度拒绝面未全入例 | 新增负例后再纳入机器契约 |
| G-TLS-4 | 16385 分片/空事件未入例 | 需要内层大消息 fixture 后补例 |
| G-TLS-5 | IPv6 未覆盖 | 新增 IPv6 正例并重钉 offset |
| G-TLS-6 | 仅支持 ecdsa-p256 | 无需求不扩展 |
| G-TLS-7 | RST 属 TCP 层，TLS 无断言 | 需要时由 TCP 契约补例 |
| G-TLS-8 | 默认 443 未入例 | 新增删 dst_port 正例 |
| G-TLS-9 | 未与真实 TLS 栈抓包对照 | 取得第三源前不声称互操作 |
| G-TLS-10 | 通用顶层白名单/flat tls 迁移未完成 | 等框架级白名单；不加 TLS 特例 |
| G-TLS-11 | schema 与生成器的变换标记语义不一致 | 代码阶段统一 |
| G-TLS-12 | 历史结果无本轮 pcap 留档 | P5 重跑后重生成产物 |
| G-TLS-13 | http-inner 未钉 record 长度 | G-TLS-1 修复后再补 |
| G-TLS-14 | has_payload 非 TLS 专用断言 | 工具阶段增加 content_type=23 断言 |
| G-TLS-15 | 正例仅 min_packets | 稳定后再收窄单流精确包数 |
| G-TLS-16 | 动态端口字符串路径未独立验证 | 代码/fixture 阶段确认类型语义 |

回滚仅恢复本文、配套 testcase 与 TLS cases；本轮不改 Go、全局文档、其他协议、suite 服务或旧稿。

## C1–C6 收口核对

- **C1 配置权威**：非负例层链唯一，flat 负例明确豁免。
- **C2 覆盖**：15 个唯一 ID 覆盖 9 正、6 负；未覆盖面全部进入缺口表。
- **C3 错误**：6 个负例均为单一故障并带精确子串锚词。
- **C4 动态**：sni、cert.subject、cert.san 逐字段列出；关闭字段列出理由。
- **C5 输出**：PCAP/NIC 共用断言；未运行不冒充已运行。
- **C6 证据**：offset 54/59、7 条握手顺序、16/32 下界与 DER 非确定性边界均已标注。

本版自审两轮：第一轮逐项核对 D1–D8、C1–C6、层链唯一真相、15 个 ID 与缺口；第二轮复核握手顺序、offset、错误锚词、负例豁免和“未运行”表述，末轮干净。

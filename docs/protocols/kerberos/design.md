# Kerberos V5 设计契约（as-built）

> 版本：v1.1.0（层链契约对齐）  
> 日期：2026-09-30  
> 机器契约：`trafficgen/test/protocol_pcap/cases/kerberos.json`  
> 配套测试契约：`docs/protocols/kerberos/testcase.md`

## D1 范围、依据和边界

本版覆盖 RFC 4120 §5.1–§5.4、§6、§7，RFC 6113 的 PA-DATA/METHOD-DATA 边界，RFC 3961/4121 的加密数据外壳，以及 UDP/TCP 88 承载。已实现消息类型为 AS-REQ/REP、TGS-REQ/REP、AP-REQ/REP 和 KRB-ERROR；输出为 definite-length DER。未提供 keytab/key log 时，PCAP/NIC 只证明外层载体、应用 tag、pvno/msg-type、公开 realm/principal、错误码、padata 和 `EncryptedData` 外壳，不能证明 ticket、session key、authenticator 或密文内层。

不在本版承诺：Kerberos V4、非 88 端口、GSS-API/SPNEGO 应用封装、真实 KDC 密码学验证、keytab 解密、跨连接 TCP 半记录拼接、协议级性能承诺。代码和 cases 已注册；现有 suite 产物记录 20/20 通过（`trafficgen/docs/protocol-pcap-test/kerberos.md`），本轮文档不重新执行，NIC 仍无证据。

## D2 严格层链和配置权威

地址只住 `layers[].ip`，端口只住 `layers[].udp` 或 `layers[].tcp`，Kerberos 业务和会话只住 `layers[].kerberos`，数量只由用例驱动器或 `flow_control` 表达。顶层不得出现 `src_ip`、`dst_ip`、`src_port`、`dst_port`、`count` 或顶层 `kerberos` 业务映射。

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.59", "dst": "198.51.100.59"}},
    {"udp": {"src_port": 40159, "dst_port": 88}},
    {"kerberos": {"sessions": [{"events": [
      {"kind": "as_req", "up": true},
      {"kind": "as_rep", "up": false}
    ]}]}}
  ]
}
```

会话端点覆盖（`sessions[].src_ip/src_port/dst_port`）仍属于 Kerberos 层内的会话编排字段，不是顶层承载字段；它只用于独立 flow 的显式隔离。`sessions[]` 中每个 event 是一条完整 Kerberos 消息。

| 旧/扁平键 | 目标去向 | 当前证据 |
|---|---|---|
| `src_ip`/`dst_ip` | `layers[].ip.src/dst` | `chain_planner_translate.go` 的 ip 层翻译；20 例机读审计 |
| `src_port`/`dst_port` | `layers[].udp/tcp.src_port/dst_port` | registry FieldContract=88；20 例机读审计 |
| `count` | `flow_control`/用例驱动器 | cases 无顶层 count |
| 顶层 `kerberos` | `layers[].kerberos` | `translateTerminalConfig` 的 kerberos 分支 |
| `sessions[].src_ip/src_port` | Kerberos 层 session 覆盖 | `KerberosSession`；仅多会话例使用 |

## D3 承载、线格式和固定偏移

Kerberos 终结层依赖 `udp`，并允许单一 `udp` 或 `tcp` 承载；双载体同时出现在一条链上必须拒绝。UDP 每个 event 生成一个 datagram；TCP 每条消息前置 4-byte unsigned big-endian length，长度不含前缀，允许 TCP segment 切分或合并。

无 VLAN、IPv4 options、IPv6 extension headers 时：IPv4/UDP 起点 42，IPv6/UDP 起点 62，IPv4/TCP 起点 54，IPv6/TCP 起点 74。IPv4 使用 `ip.proto=17/6`，IPv6 使用 `ipv6.nxt=17/6`；IPv6 UDP checksum 必须为正确非零值。TCP handshake/ACK/FIN/RST 属于承载帧，不计 Kerberos event packet_count。

## D4 DER 字段和消息状态

顶层 application tag 与 msg-type 映射固定：AS-REQ 10/0x6a、AS-REP 11/0x6b、TGS-REQ 12/0x6c、TGS-REP 13/0x6d、AP-REQ 14/0x6e、AP-REP 15/0x6f、KRB-ERROR 30/0x7e；`pvno=5`。DER 长度必须 definite-length 且边界自洽。`PrincipalName` 分开编码 name-type 与 name-string 组件，realm 不并入组件。

状态由 `sessions[].events[]` 顺序显式编排：AS 请求/回复、预认证错误后重试、TGS 请求/回复、AP 请求/回复。KRB-ERROR 不得被解释成成功 reply；消息未完整生成、tag 与 msg-type 不一致、`krb_error` 缺 error_code 时拒绝。PA-DATA 保持声明顺序，PA-ENC-TIMESTAMP 与 PA-TGS-REQ 的 value 只在外壳层可观察。

## D5 规范—业务—代码—缺口矩阵

| 规范要求 | 业务场景 | 代码现状 | 用例/缺口 |
|---|---|---|---|
| UDP/TCP 88 与边界（RFC 4120 §6） | datagram、4B TCP record、切分/合并 | `registry.go`、`planner.go`、`builder.go` | #1–3、#14；NIC 待本轮复验 |
| AS/TGS/AP 交换（RFC 4120 §5.4） | 请求—回复与方向 | `kindTable`、`plan.go` | #4–6、#9 |
| KRB-ERROR/PREAUTH（RFC 4120 §5.9、RFC 6113） | PREAUTH_REQUIRED、METHOD-DATA、重试 | `krb_error`/`padataSeq` | #7–8 |
| Ticket/principal/EncryptedData | 外壳字段与 opaque 边界 | `ticket`、`encryptedData` | #5–6、#9–10 |
| nonce/time/replay | 关联、skew、重传、拒绝 | event 状态与负例守卫 | #11–12、#19 |
| 地址族/会话隔离 | IPv4/IPv6、独立 session | ip 层与 `sessions[]` | #1–2、#13；IPv6/TCP 多会话交叉待 NIC 复验 |

### 命令/消息×响应码矩阵

| 请求/消息 | 正常响应/状态 | 错误响应 | 覆盖 |
|---|---|---|---|
| AS-REQ | AS-REP | KRB_ERR PREAUTH_REQUIRED、SKEW | #1、#4、#7、#11 |
| TGS-REQ | TGS-REP | 结构/tag/replay 错误 | #5、#8–10、#19 |
| AP-REQ | AP-REP | replay 拒绝 | #6、#12 |
| TCP record | 按长度重组 | 长度/截断错误 | #3、#15–16 |

### 数据形态变体矩阵

| 维度 | 已覆盖 | 缺口/边界 |
|---|---|---|
| 地址族 | IPv4、IPv6 独立正例 | IPv6/TCP 仍待运行校准 |
| 承载 | UDP、TCP；TCP 4B length | 双载体拒绝有负例 |
| 消息 | AS/TGS/AP/KRB-ERROR | SAFE/PRIV 明确不适用 |
| 会话 | 单 session、sessions[] 多 flow | 当前多 session cases 为 UDP fixture |
| 密文 | etype/kvno/长度 opaque | 无 key 不解密 |

### 商业行为→用例映射

| 行为 | 用例 | 证据/确认方式 |
|---|---|---|
| KDC UDP/88 AS 与预认证重试 | #1、#7–8 | RFC 4120/6113；PCAP 复验 |
| KDC TCP/88 length framing | #3 | RFC 4120 §6；PCAP 复验 |
| service AP mutual authentication/replay | #6、#12 | RFC 4120 §3.2；授权 NIC/PCAP 复验 |

商业设备版本和现网抓包尚未作为本轮证据；未确认项保持待验证，不写成已通过。

## D6 三路对照与候选方案

规范决定 tag、字段和状态顺序；本仓库 `internal/protocol/kerberos` 决定已实现 DER/分帧形状；独立实现/商业行为只作为待确认对照，不替代 RFC。

| 方案 | 优点 | 代价 | 结论 |
|---|---|---|---|
| A：`sessions[].events[]` 作为单一终结层编排 | 保留一消息一 event、会话隔离和 TCP framing | spec 较长 | 采用；与现有 planner/builder 一致 |
| B：把 AS/TGS/AP 每消息拆成多个层 | 字段看似更细 | 破坏一条 DER 消息边界，无法表达 TCP record | 不采用 |
| C：顶层 flat 地址/端口/kerberos | 迁移短 | 违反 CORE 层链唯一真相 | 仅历史形，已清除 |

## D7 性能、错误和输出验收

planner 逐 event 生成，builder 逐消息编码，不聚合整个会话；队列和缓冲遵循仓库有界约束。当前没有本轮吞吐/CPU/内存基准，不能写承诺数字。实现后性能验收必须覆盖基线、目标规模、压力上限、长时运行、并发交错、资源耗尽/背压六档，并分别记录 PCAP 与授权 NIC 的包/秒、bit/s、并发 session/flow、最大记录、内存、队列积压和失败/丢包。

六类负例分别在 planner/validator、自然非法 event 或层链预检拒绝：截断、TCP length、tag、EncryptedData boundary、time/nonce/replay、carrier。错误必须传播为 task error，不得 completed/0 packet 或只输出 UDP/TCP 外壳。`wire_fault` 只用于负例注入，不是线上业务字段。

## D8 依赖、错误传播、重试、超时和回滚

| 阶段 | 依赖 | 失败行为 | 重试/超时边界 |
|---|---|---|---|
| 层注册/翻译 | `registry.go`、`chain_planner_translate.go` | 缺终结层、未知字段或双载体在预检报错 | 不重试配置错误；由任务驱动器超时 |
| `Planner.Validate` | `core.KerberosConfig`、`buildMessage` | `wire_fault`、未知 kind、tag/msg-type、缺 `error_code`、端口冲突报错 | 不重试确定性非法输入 |
| `Generate`/builder | `udp` 或 `tcp` 载体、`EmitMsg` | builder/下游错误原样传播，禁止 completed/0 packet 假成功 | 仅由上层任务取消；ctx 取消返回 `ctx.Err()` |
| PCAP/NIC 验收 | 引擎、tshark、授权网口 | 缺产物、字段不符或丢包判失败 | 本轮不执行；后续按任务超时终止，不把重试当协议语义 |

接口为 layer translation → `core.KerberosConfig`/`KerberosSession`/`KerberosEvent` → `Planner.Validate` → `Planner.Plan` → builder；注册入口为 `registry.go`，层翻译在 `chain_planner_translate.go`，类型与错误锚词在 `core/kerberos.go`。冲突点是 UDP/TCP 双载体、TCP framing 与 UDP datagram 语义、动态 opaque bytes 和无 key 解密边界。回滚只移除 Kerberos 注册/接线提交，保留文档和 cases，不恢复扁平正例。

### 动态字段与序列算法（八元素）

八个验收元素固定为：载体、地址族、端口/四元组、消息序列、方向、DER/tag、业务可见字段、错误/边界。`sessions[]` 外层按数组顺序遍历；每个 session 内按 `events[]` 顺序生成一条消息；每条消息先 `kind→tag/msg-type` 校验，再编码 DER；UDP 原样发出，TCP 加 4-byte big-endian 长度；方向决定端点交换，session 覆盖只在该 session 生效。`nonce`、时间、principal、etype/kvno/cipher_len、padata 是事件级动态字段，未声明时取代码 fixture 默认值；opaque cipher 不被解释。该算法不跨 session 共享 replay、ticket 或 TCP 缓冲状态。

### Gate-1（静态闭环）

| 门项 | 必须满足 | 当前结论 |
|---|---|---|
| 配置权威 | 正例仅 `layers`；地址/端口/业务分层 | 通过，20/20 机读 |
| 注册与翻译 | registry、FieldContract、终结层 translate 可定位 | 通过，代码路径已注册 |
| 正负边界 | 14 正例、6 负例；负例 expect 仅两键 | 通过，负例锚词非空 |
| 规范映射 | AS/TGS/AP/ERROR、DER、UDP/TCP framing 有回指 | 通过，D5/T2 |
| 执行证据 | MCP→PCAP→tshark，必要时 NIC | 未执行本轮；登记 G-KERBEROS-1 |

完成定义：20 个 ID 与 cases 同序，14 正/6 负；正例字段/raw/packet_count 与真实产物对齐，负例错误锚词可观察；-race 与集成路径覆盖会话隔离、重传和 UDP/TCP 切换；无 key 不声称看到密文内层。当前文档轨不宣称本轮 PCAP/NIC 已执行。

## D1–D8 状态、缺口和门 1 对照

| ID | 结论 | 证据/缺口 |
|---|---|---|
| D1 | 范围与 RFC 边界已定 | 本文 D1 |
| D2 | 20 例严格层链已落地 | cases 全量机读；顶层旧键零残留 |
| D3 | 双载体/偏移/4B framing 已定 | 本文 D3；#3/#16 |
| D4 | DER、状态和会话编排已定 | `planner.go`/`builder.go`；#4–12 |
| D5 | 三张矩阵已列 | 本文 D5；IPv6/TCP 交叉仍待复验 |
| D6 | 三路与候选方案已列 | 本文 D6；商业第三源待确认 |
| D7 | 流式、错误和六档性能计划已列 | 本文 D7；性能数字待实测 |
| D8 | 接口、冲突、回滚已列 | 本文 D8 |

| § | 本协议满足方式 | 证据 |
|---|---|---|
| §1 | 旧地址/端口/count 全迁层链；协议业务在 kerberos 层 | D2；cases 20 例 |
| §2 | 单策略会话模板，数量由 flow_control/驱动器 | D2、D7 |
| §3 | sessions/events、状态关联、插入位置、时间线 | D4；#12–13 |
| §4 | RFC 4120/6113 字段与错误矩阵 | D1、D5 |
| §5 | 依赖与失败传播 | D7–D8 |
| §6 | 流式路径与 PCAP/NIC 六档验收 | D7 |
| §7 | design/testcase/cases 三件套 | 文件路径 |
| §8 | 先文档、后实现；回滚边界明确 | D8 |
| §9 | 规范→设计→代码→cases 逐项映射 | D5、testcase T2 |
| §10 | 文档两轮自审，独立复审另行执行 | 修订记录 |
| §11 | 文首白话范围结论 | 文首 |
| §12 | 四元组和业务动态/opaque 字段边界 | D2、D4 |
| §13 | registry/schema/translation 已接线 | D8；代码路径 |
| §14 | MCP→引擎→PCAP/NIC→tshark 为执行计划 | D7、testcase T5 |

## C1–C6 审查结论

| ID | 结论 |
|---|---|
| C1 | JSON 可解析，20 个 ID 唯一且顺序与本文/测试契约一致。 |
| C2 | 14 个正例均为 `[ip,udp|tcp,kerberos]`；6 个负例保留唯一故障，双载体例仅作为故意判死输入。 |
| C3 | 顶层无地址、端口、count 或协议业务键；端口在承载层，会话覆盖在 kerberos 层。 |
| C4 | 6 个负例 `expect` 严格只有 `expect_error`、`error_contains`。 |
| C5 | AS/TGS/AP、PREAUTH、opaque、nonce/skew/replay、IPv4/IPv6、多 session、TCP framing 均有对应例；性能/NIC 是待执行缺口。 |
| C6 | 本轮限定 Kerberos 三文件范围；JSON 已合规无需改动，不改 Go、全局索引或其他协议。 |

## 缺口登记

| 缺口 | 现象 | 计划 |
|---|---|---|
| G-KERBEROS-1 | 本轮未重新执行 MCP→PCAP/NIC→tshark | 注册路径同代后全量重跑 20 例 |
| G-KERBEROS-2 | IPv6/TCP、多 session UDP↔TCP 交叉未在现有 fixture 中完整表达 | 补独立层链例并先跑后钉 |
| G-KERBEROS-3 | 商业设备行为和 keytab 解密证据未取证 | 授权抓包/key log 后单独扩展 |
| G-KERBEROS-4 | 性能六档无本轮实测数字 | 实现后基线、压力、长跑、背压复验 |
| G-KERBEROS-5 | 层链未接入 `inc/rand/list/pattern` 动态对象，flows>1 只能静态复制 | 先补 schema/translate/序号算法，再补动态整格用例；未接入前不称动态覆盖 |
| G-KERBEROS-6 | 长保活/空闲超时无协议级计时器语义 | 立项确认生成器是否需要保活表达；确认前不以 TCP 握手帧冒充长保活用例 |

## D9 §4 P1 八项规范矩阵（逐项结论）

| 规范要求 | 业务场景 | 代码现状 | 缺口/用例 |
|---|---|---|---|
| 连接模型：UDP datagram、TCP stream | KDC/服务端 88 端口请求应答 | `builder.go:390-415` 按载体分帧；TCP 每消息 4B BE 长度 | IPv6/TCP 交叉未落 fixture：G-KERBEROS-2；#1–3、#14 |
| 命令/消息表 | AS、TGS、AP、ERROR 请求/响应 | `builder.go:28-41` kind→tag/msg-type；`core/kerberos.go:51-58` | SAFE/PRIV 不属于当前终结层输入；#4–12、#14 |
| 状态机 | 预认证重试、TGS、互认证、replay/skew | `planner.go:56-64` 逐 event 预演；事件序列由 `sessions[].events[]` 给出 | 现网 KDC 状态差异待授权抓包；#7–8、#11–12 |
| 字段表 | DER tag、长度、principal、nonce、etype、padata | `der.go:19-50`；`builder.go:173-220`、`:281-304` | keytab 解密不在无密钥生成边界；#4–11 |
| 错误处理表 | 截断、长度、tag、加密边界、replay、载体 | `planner.go:67-75` 与 `core/kerberos.go:140-154` 六锚词 | 负例拒绝需真实 MCP 流程复验；#15–20 |
| 超时与活性 | 重传、skew、TCP 建连/释放 | 当前只表达事件顺序与错误事件，不维护计时器 | 真实超时/长时基准：G-KERBEROS-4；#11–14 |
| NAT/代理/被动模式 | 多 session 端点覆盖、方向回送 | `core/kerberos.go:31-46`；TCP `src_ip` 覆盖由链预检拒绝 | UDP 多 session↔TCP 交叉：G-KERBEROS-2；#13 |
| 版本/方言 | V5、RFC 6113 PA-DATA、RFC 3961/4121 外壳 | `builder.go:118-159` PA-DATA 分型，DER definite-length；仅 V5 | 商业版本/方言尚待取证：G-KERBEROS-3；#7–10 |

### 三张 §4 子表

**命令×响应码：** AS-REQ→AS-REP（#1、#4），AS-REQ→KRB-ERROR 7→重试（#7–8）；TGS-REQ→TGS-REP（#5、#9）；AP-REQ→AP-REP（#6、#10）；重复 AP-REQ→replay 41（#12）；skew→25（#11）；TCP record→长度/截断负例（#3、#15–16）。每格均有正例或负例结论。

**数据形态变体：** IPv4/IPv6（#1/#2）；UDP/TCP（#1–2/#3）；短 DER/长 DER（#4/#3）；AS/TGS/AP/ERROR（#4–12）；PA type 1/2/150 与空值（#5、#7–8）；etype 17/18/23、kvno 有无、cipher 长度 16/36/52/64/700（#6、#10）；单/三 session（#1–12/#13）。IPv6/TCP 和 TCP session override 交叉是 G-KERBEROS-2，不伪称已覆盖。

**商业行为→用例：** MIT kinit 预认证轮回→#1、#7–8；MIT/Heimdal 风格 TCP 4B record→#3；服务票据互认证→#5–6、#9–10；重传/replay 与 skew→#11–12；多客户端端点隔离→#13；PCAP/NIC 同口径→#14。商业软件版本和抓包尚未取得，确认方式为授权环境抓包后逐格比对 tshark/raw frame（G-KERBEROS-3）。

### 三路对照与候选方案

| 规范原文 | 商业软件行为（待确认） | 开源实现思路 | 结论 |
|---|---|---|---|
| RFC 4120 §5.2–§5.4.2：tag、字段、状态 | MIT/Heimdal 的 AS/TGS/AP 序列与预认证重试 | MIT krb5/Heimdal 的状态机按消息序列推进 | 规范定 DER/状态；商业证据补测，不把猜测写成现状 |
| RFC 4120 §6：TCP 4B BE length | KDC 切换 TCP 后按 record 组帧 | krb5 TCP framing 以完整 record 解码 | 采用每 event 一 record，允许 segment 切分 |
| RFC 6113：METHOD-DATA/PA-DATA | 常见 KDC 按 type 顺序返回 preauth | krb5 padata decoder 保持 type/value 顺序 | 采用声明顺序，#7–8 验证 |

| 候选方案 | 优点 | 代价 | 选择 |
|---|---|---|---|
| 单终结层 `sessions[].events[]` | 保持一消息一边界，天然支持 UDP/TCP | 配置较长 | 采用；与 `Planner`/builder 一致 |
| AS/TGS/AP 各自拆成层 | 配置局部短 | 破坏 DER 消息与 TCP record 边界 | 不采用 |
| 顶层 flat 地址/业务 | 迁移表面简单 | 违反 CORE §1.11 层链白名单 | 不采用，20 例均清除 |

## D10 §5 依赖与错误处理、§6 性能验收

| 依赖/阶段 | 失败返回与处置 | 重试/超时 |
|---|---|---|
| ip+udp/tcp→kerberos 翻译 | 缺承载、双承载、混合地址族返回 chain error，任务失败 | 配置错误不重试；任务取消遵循 context |
| `Planner.Validate`→`buildMessage` | wire fault、未知 kind、tag/msg-type 不一致、缺 error_code 返回错误 | 不重试确定性错误 |
| `sessions/events`→builder | builder 错误原样传播，禁止 completed/0 packet 假成功 | 仅任务层取消；TCP 长连接不由 Kerberos 计时器维护 |
| PCAP/NIC→tshark | 缺文件、字段/tag/方向/丢包任一失败 | 由验收任务超时终止，不把重试当协议语义 |

性能验收必须记录包/秒、bit/s、并发 session/flow、最大 DER record、内存、队列积压、CPU 及失败/丢包，覆盖基线、目标规模、压力上限、长时、并发交错、背压六档。实现路径是逐 event/逐 frame 流式处理，不全量聚合；无基准不写承诺数字。PCAP 路由用 `output_type=pcap`，tshark 校验 `udp port 88 or tcp port 88` 的方向、tag、length、字段；网卡路由用授权 port group，tcpdump 在真实接口捕获后用同一字段断言，并对比 PCAP/NIC 包数、方向和丢包。

## D11 §8 八要素与 §12 动态字段清单

| 要素 | 定论 |
|---|---|
| 文件 | `trafficgen/internal/core/kerberos.go`、`internal/protocol/kerberos/{planner,builder,der}.go`、`internal/core/layers/{registry,chain_planner_translate,validate_layers}.go`、本设计/用例/cases |
| 接口 | layer translate→`core.KerberosConfig`→`Planner.Validate`→`BuildFrames`/Generate→PCAP/NIC |
| 结构 | `layers[ip,udp|tcp,kerberos]`; `sessions[]`→`events[]`; event→DER message |
| 流程 | 预检载体→校验事件→kind/tag→DER→UDP datagram 或 TCP 4B record |
| 错误 | 六 `wire_fault` 锚词及自然非法 event 均传播为 task error |
| 性能边界 | 六档验收；有界队列、逐帧输出；数字待实测 |
| 冲突点 | 双载体、TCP framing、session endpoint override、opaque cipher 与无 key 边界 |
| 回滚 | 移除注册/接线提交；保留三件套和已落地层链 cases，不恢复 flat 形 |

| 字段 | 策略 | 序号/代码位置 |
|---|---|---|
| src/dst IP、src/dst port | 当前 `fixed`（层值）；`sessions[].src_ip/src_port/dst_port` 仅显式 session override；未实现五种 dynamic 对象 | session 遍历 `builder.go:450–481`；链字段在 `chain_planner_translate.go` |
| `kind`、`up`、`msg_type` | `fixed`/按声明顺序；msg_type 缺省由 kind 派生，显式冲突拒绝 | `core/kerberos.go:48–58`; `builder.go:28–41,343–347` |
| realm/crealm/cname/sname/name_type | `fixed`，逐 event 生效；未声明走 fixture 默认 | `core/kerberos.go:60–70`; `builder.go:173–242` |
| nonce/till/ctime/cusec/stime/susec | `fixed`，按 event 序列使用；不宣称自动递增 | `core/kerberos.go:80–95`; `builder.go:174–220,281–304` |
| etype/kvno/cipher_len/body | `fixed`；cipher 仅确定性 opaque 填充，不解释密文 | `core/kerberos.go:71–78,103–105`; `builder.go:68–86` |
| padata type/value_len、error_code/e_text | `fixed`，padata 保声明顺序；error_code 只在 `krb_error` 必填 | `core/kerberos.go:93–101,108–113`; `builder.go:118–159,273–304` |
| sessions/events | `list` 顺序；不提供隐式复制或跨 session 共享序号 | `builder.go:450–532` |

本版本明确记录：策略级 `inc/rand/list/pattern` 动态对象尚未接入 Kerberos 终结层，当前所有业务字段是 fixed/list 声明；若需 flows>1 动态复制，立项 G-KERBEROS-5（先补 schema/translate/序号算法，再补整格用例），不得把静态重复称动态覆盖。序号算法当前是 session 数组索引+event 数组索引，不跨 session 共享 replay/ticket/TCP buffer。

## D12 §15 门1 三行展开

| 门1行 | 对照 |
|---|---|
| §1 旧键去向 | `src_ip/dst_ip`→`layers[].ip`；`src_port/dst_port`→`layers[].udp/tcp`；`count`→`flow_control`/驱动器；顶层 `kerberos`→`layers[].kerberos`；完整例见 D2，20 条 `spec_json` 均仅顶层 `layers`。 |
| §3 五件套 | 会话表=`sessions[]`；事务序列=`events[]`；关联=`nonce/ticket/replay`按 session；插入位置=终结层事件；时间线=数组顺序。Kerberos 无独立数据流关联，仍以 #13 多 session 和 #5–6 多事务证明。 |
| §12 清单 | 四元组与业务字段逐项见 D11；当前 fixed/list 声明，代码位置见表；动态五策略未接入登记 G-KERBEROS-5。 |

## 修订记录

- v1.2.0（2026-10-01）：补齐 P1 八项矩阵、三子表、三路对照、候选方案、依赖错误、PCAP/NIC 双路性能、八要素、动态字段和门1三行；校正为当前 20 例 as-built。
- v1.1.0（2026-09-30）：按 D1–D8、门 1、C1–C6 重写为 as-built 层链契约；对账 20 例、14/6 和实际 packet_count；登记 PCAP/NIC、交叉地址族、第三源与性能缺口；不修改 Go 实现。
- v1.0.0（2026-08-20）：历史设计稿，保留为参考。

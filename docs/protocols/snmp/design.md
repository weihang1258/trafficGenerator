# SNMP（v1/v2c/v3 over UDP）设计契约

> 版本：v1.2.0（2026-10-01，文档轨）
> 范围：D1–D8；本轮只改设计、用例和 cases JSON，不改 Go 实现。
> 规范：RFC 1157、RFC 3411–3417、X.690；机器契约：`trafficgen/test/protocol_pcap/cases/snmp.json`。
> 状态：SNMP layer 已注册并依赖 UDP，但复杂协议字段仍由 converter 从旧顶层子映射读取；严格层链迁移后的 case 暂不能运行，见 G-SNMP-10。

## D1 范围、证据与边界

SNMP 是管理器/代理间的 BER 编码管理报文。本文覆盖 v1/v2c/v3 USM 的消息结构、Get/GetNext/Set/GetBulk/Response、v1 Trap、v2 Trap、Inform、VarBind 值类型和 UDP 承载。当前唯一可执行证据是 v2c 风格单 OID Get（wire-version=1）；其余是目标契约或待实现边界，不能计入已覆盖行为。

不承诺 TCP、TLS、SSH 承载、真实 Agent 状态发现、重传协议语义、SHA-2/AES-192/256 的互操作性。代码接受部分这些名称但会回退到已实现算法，不能据此声称算法已验证。

## D2 严格层链与配置权威

目标形状：地址只在 `ip` 层，端口只在 `udp` 层，所有 SNMP 字段只在 `snmp` 层；顶层只保留 `layers`、`flow_control`/策略框架字段和 `output`。最小承载可省略 `ip`，由框架补齐：

```json
{
  "layers": [
    {"udp": {"src_port": 12345, "dst_port": 161}},
    {"snmp": {"version": 1, "community": "public", "pdu_type": 0,
      "var_binds": [{"name": "1.3.6.1.2.1.1.1.0"}]}}
  ]
}
```

`src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/顶层 `snmp` 子映射均不是目标形。当前 registry 的 SNMP `Fields` 为空，`strategy_convert.go` 仍读取顶层 `cfg.snmp`；因此本轮迁移 JSON 后，需先补层字段消费和 converter 接线，不能把旧形状保留为豁免。

## D3 线格式与偏移

所有 BER 元素为 `Tag | Length | Value`，多字节整数为大端 two's-complement。长度 `<128` 为一字节，`128–255` 使用 `81 nn`，`256–65535` 使用 `82 nn nn`；后续偏移须随长度字节数递推。IPv4 无 VLAN/IP options 时 SNMP payload 起点为以太网偏移 42（14+20+8），IPv6 为 62。

v1/v2c 外层为 `30 Len {02 01 version, 04 community, PDU}`。标准 PDU 是隐式构造序列：`request-id INTEGER | field1 INTEGER | field2 INTEGER | VarBindList SEQUENCE`；Get/GetNext/Set/Response 标签分别 `a0/a1/a3/a2`，GetBulk 为 `a5`，Inform 为 `a6`，v2 Trap 为 `a7`，Report `a8` 当前不在 validator 允许范围。v1 Trap `a4` 例外：enterprise OID、agent-addr、generic-trap、specific-trap、timestamp、VarBindList，无 request-id/error 字段。

VarBindList 为 `30` 包裹多个 VarBind；每个 VarBind 为 `30 {06 OID, value TLV}`。OID 第一字节为 `40*arc0+arc1`，后续弧为 base-128。支持 NULL `05`、INTEGER `02`、OCTET STRING `04`、OID `06`、IpAddress `40`、Counter32 `41`、Gauge32 `42`、TimeTicks `43`、Opaque `44`、Counter64 `46` 及 exception tags `80/81/82`。未知 type 当前回退 NULL，是 G-SNMP-7，不得当作严格拒绝。

v3 外层字段顺序为 version=3、msgID、msgMaxSize、msgFlags、securityModel=3、securityParameters、scopedPDU。USM 依次含 engineID、boots、time、userName、authParameters、privParameters。MD5/SHA-1 HMAC 与 AES-128-CFB 为实际路径；SHA-2、DES、AES-192/256 和简化 IV 的边界须标待实现，不宣称 RFC 互操作。

## D4 配置、状态与默认值

`version`：0=v1、1=v2c、3=v3；v1/v2c community 默认 `public`；Get 默认 PDU，Get 类 VarBind 至少一项；GetBulk 的 `non_repeaters`/`max_repetitions` 默认 0/1；request-id=0 时生成随机起点并按迭代递增。Agent/Query 目的端口默认 161，Trap/Inform 默认 162；源端口沿框架默认值。`repeat_count<=0` 按 1，`poll_interval` 只控制迭代间等待。

一个 UDP datagram 是一个事务：up 请求或 Trap；`is_response=true` 时每个请求后立即发同 request-id 的 down Response。无连接会话、握手、FIN/RST、父子流关联和 keepalive；重复请求是有序 datagram 序列，不是隐式多会话。

validator 必须拒绝：非法 version/PDU、v1/v2c 空 community、v3 缺 auth password、priv 无 auth、非法 auth/priv、非法 engine ID、Get 类空 VarBind、空/非法 OID、端口越界和混合地址族。错误必须传播为任务失败，不得返回 completed/0 packet 或静默修正。

## D5 驱动、流和性能

路径为 `layers → validator → converter/FlowMeta → SNMP generator → UDP datagram → pcap/NIC`。生成器按 repeat 顺序 emit request，再按 `is_response` emit response，间隔期间响应 context cancel。每个事件一个 datagram；不聚合全部报文。协议级容量边界为 IPv4 UDP payload ≤65507，BER 长形长度和 VarBind 数量必须受该上限约束；当前未实现 SNMP 专属上限守卫，登记 G-SNMP-8。

PCAP 与 NIC 共用同一 cases JSON、字段和 raw-frame 断言；NIC 通过 tcpdump 捕获，必须以线上字节核验 checksum/offload 边界。当前只有历史 pcap 结果说明，未复跑不宣称通过。

## D6 错误、待实现与回滚

当前实现已注册 UDP 终结层，但层内 SNMP Fields 为空，严格目标配置无法到达现有 converter。优先补 `snmp` FieldContract、层内 translate/converter、顶层 presence 判死和错误传播；随后补 v2/v3/长形/负例测试。回滚只撤销本轮文档与 cases 迁移，不改 Go；不允许通过恢复旧顶层字段绕过严格层链。

## D7 五层覆盖与缺口矩阵

| 面 | 当前证据 | 缺口 |
|---|---|---|
| 功能 | 仅 v1/v2c 风格 Get 单 OID | GetNext/Set/GetBulk/Response/Trap/Inform/v3/Report |
| 性能 | 单小 datagram | 0x81/0x82、UDP 上界、repeat/多流、背压 |
| 数据 | version/community/OID/error-status | 全部 BER value tags、OID base-128、边界/非法 |
| 地址与流 | IPv4、默认 161 | IPv6、非默认端口、混合拒绝；连接流不适用 |
| 业务 | 单次请求 | repeat/response、Trap/Inform、USM；无连接多会话不适用 |

## D8 缺口、接口与验收

| 编号 | 现象 | 计划 |
|---|---|---|
| G-SNMP-1 | 顶层协议配置与层链共存的 presence 判死未统一 | 框架白名单拒绝旧形 |
| G-SNMP-2 | JSON 仅 1 个 Get | 注册层字段后补行为面原子例 |
| G-SNMP-3 | 长形 BER/OID base-128 无证据 | raw frame 用例校准 0x81/0x82 与偏移 |
| G-SNMP-4 | value tags 未覆盖 | 每 tag 独立正例/负例 |
| G-SNMP-5 | SNMP 业务字段无 dynamic allowlist | 明确 allowlist 后补 fixed/inc/rand/list/pattern |
| G-SNMP-6 | v3 回退算法/简化 IV | 仅支持真实互操作算法，或明确拒绝 |
| G-SNMP-7 | OID 弧约束弱、未知 type 回退 NULL | validator 严格化并先写失败例 |
| G-SNMP-8 | payload 上界/截断 BER 无守卫 | planner 任务错误传播 |
| G-SNMP-9 | tracked pcap 产物缺失/历史数字未复跑 | 重新跑 PCAP/NIC 并留证 |
| G-SNMP-10 | 迁移后 `snmp` 层字段无法被当前 converter 消费 | 补 FieldContract/translate；完成前 JSON 不得回退旧形 |

接口契约：新增层字段消费必须保持 `SNMPGenerator.Generate(ctx,*layers.GenRequest) error`；失败返回 task error；流式事件仍为 `layers.MessageEvent`。实现前不改代码。

## C1–C6 设计验收

- **C1**：PCAP/NIC 共用 cases JSON、字段和 raw 断言；当前未宣称 NIC 已验证。
- **C2**：UDP 无保活/重试/FIN/RST；这些是 SNMP 不适用项，重复 request 另作业务例。
- **C3**：单 datagram 事务；无多会话、多流、父子关联，不硬凑用例。
- **C4**：负例必须互斥、一次只注入一个错误，且只断 `expect_error/error_contains`。
- **C5**：所有顶层业务/承载旧键禁止豁免；层字段未接线登记 G-SNMP-10。
- **C6**：文档阶段不宣称套件通过；实现后按六类性能场景和 PCAP/NIC 双路径复验。

## D1 P1 规范矩阵（八项）

| # | 规范要求 | 业务场景 | 代码现状 | 缺口/用例 |
|---|---|---|---|---|
| 1 | 连接模型：RFC 3417 UDP 无连接报文 | 管理器发 Get/代理回 Response | `planner.go:304-307` 按 datagram 生成 | 正例 `snmp_smoke_01`；多轮见 G-SNMP-2 |
| 2 | 消息：RFC 3416 §4.2 Get/GetNext/Set/GetBulk/Response/Trap/Inform | 读取、修改、告警、通知 | `planner.go:722-777` 有 PDU 编码 | G-SNMP-2，逐 PDU 用例 |
| 3 | 状态：请求与可选响应按 request-id 关联 | 请求→响应或失败终止 | `layer_gen.go:65-78` 顺序发射 | G-SNMP-2 |
| 4 | 字段：X.690 TLV、OID base-128、VarBind value tags | 单/多 OID、边界长度 | `planner.go:660-770` 编码；未知 value 回退 NULL | G-SNMP-3/4/7 |
| 5 | 错误：非法版本、PDU、OID、USM 参数须拒绝 | 配置错误不产成功包 | `planner.go:172-301` validator 返回错误 | G-SNMP-7/8；负例待补 |
| 6 | 活性：UDP 无协议级 keepalive；轮询由应用控制 | repeat/poll_interval | `layer_gen.go:44-87` 支持 repeat 与取消 | G-SNMP-2 |
| 7 | 地址与端口：RFC 3417 默认 161，Trap/Inform 162；同族地址 | IPv4/IPv6、定制端口 | chain planner 默认端口；IP 在承载层 | IPv6/端口矩阵待补 |
| 8 | 方言：v1/v2c/v3 USM，RFC 3414 算法边界 | 社区字符串、USM auth/priv | v3 字段在 `core.SNMPConfig`，层翻译未接 | G-SNMP-6/10 |

### 三张子表

**命令×响应/结果矩阵（RFC 3416 §4.2）**

| 请求/消息 | 成功结果 | 错误/失败结果 | 当前覆盖 |
|---|---|---|---|
| Get/GetNext/Set | Response error-status=0 | noSuchName/badValue/readOnly/genErr | Get 最小正例；其余 G-SNMP-2 |
| GetBulk | Response 的非重复/重复结果 | tooBig/genErr | G-SNMP-2 |
| v1 Trap/v2 Trap | 单向通知 | 参数/编码错误 | G-SNMP-2 |
| Inform | Response | 超时/错误 status | G-SNMP-2 |
| v3 Report/USM | security report 或成功 Response | auth/priv/engine 错误 | G-SNMP-6 |

**数据形态变体表**

| 形态 | 要求/边界 | 现状与去向 |
|---|---|---|
| OID | 首两弧合并、后续 base-128、空/非法拒绝 | 正例覆盖普通 OID；G-SNMP-3/7 |
| VarBind value | NULL、INTEGER、OCTET STRING、OID、IpAddress、Counter/Gauge/TimeTicks/Opaque/Counter64、exception | 编码函数支持集合；G-SNMP-4 逐 tag |
| BER 长度 | 短形、0x81、0x82，父子长度一致 | G-SNMP-3/8 |
| 地址/端口 | IPv4/IPv6 对称、161/162/定制端口 | 当前仅默认端口 evidence；G-SNMP-2 |
| v3 USM | engine/user/auth/priv 字段组合 | validator 部分覆盖；G-SNMP-6 |

**商业行为→用例映射表**

| 现网行为 | 证据级别/确认方式 | 用例 |
|---|---|---|
| 监控系统对 sysDescr 发 v1/v2c Get | RFC 3416 + 当前 pcap 字段记录 | `snmp_smoke_01` |
| Trap 发往 162 | RFC 3417；需抓主流 agent pcap 确认 | 待确认，G-SNMP-2 |
| v3 USM auth/priv | RFC 3414；需抓 Net-SNMP/WLC pcap | 待确认，G-SNMP-6 |

## D2 三路对照与候选方案

| 依据 | 结论 |
|---|---|
| RFC 1157、3416/3417、3414、X.690 | 以 BER 字节、PDU tag、默认端口和 USM 约束为底线 |
| Net-SNMP 5.x / Wireshark 3.6 现网行为 | 以社区字符串、OID、error-status 和 Trap/Inform 方向作为抓包确认面；当前仅有单 Get 证据 |
| Go 标准库 `encoding/binary` + 本仓库 `planner.go` | 保持流式 datagram 生成，复用已有 OID/BER 编码路径，不引入第二套协议模型 |

| 真实方案 | 优点 | 代价 | 选择 |
|---|---|---|---|
| A：层终结生成器直接消费 `SNMPConfig`（当前骨架） | 与 UDP 事件面一致、流式、改动小 | 需要补层字段解码/translate | 选 A，G-SNMP-10 |
| B：在层 translator 内完整构建 SNMPConfig | 层链配置闭环、字段可校验 | 需维护全量字段映射和严格解码 | 作为 G-SNMP-10 实施方案 |

## D3–D8 实施契约

- **依赖与错误（D3）**：依赖 `udp` 层承载、`ip/ipv6` 层地址和 task validator；字段解码或 validator 失败返回 task error、停止该策略、不重试；上下文取消立即停止；轮询等待由 `poll_interval` 控制，未设专用超时。BER 长度/UDP payload 越界必须在 planner 前拒绝（G-SNMP-8）。
- **性能与验收（D4）**：目标值待基准确认，不写承诺数字；路径必须保持每事件一个 datagram、无全量收集，复用有界队列和既有 worker。验收同时走 pcap（tshark 字段+raw BER）和网卡（tcpdump 后校验 checksum/offload）；基线、目标规模、压力、长跑、并发交错、背压六类均登记 G-SNMP-9。
- **八要素（D5）**：改动文件为 `internal/protocol/snmp/layer_gen.go`、`chain_planner_translate.go`/层字段注册及对应测试；接口保持 `SNMPGenerator.Generate(context.Context,*layers.GenRequest) error`；结构使用 `SNMPConfig`/`SNMPVarBind`；流程为 layer→validator→generator→udp；错误按上项传播；边界为 UDP payload 65507 与 BER 长度；冲突点是旧顶层 converter；回滚为撤销层字段/translator/用例迁移，保留现有 planner。
- **动态字段（D6）**：四元组地址/端口由 `ip`/`udp` 层承载，策略支持范围须以层字段注册为准；当前 SNMP 业务字段没有动态 allowlist，`version/community/PDU/var_binds/request_id` 均不开动态，不能暗示按流自动变化。序号算法位置：框架动态解析在层策略路径；SNMP `request_id` 仅在 `layer_gen.go:48-72` 按 repeat 递增。补齐 fixed/inc/rand/list/pattern 五格立项 G-SNMP-5。
- **D8**：每个无证据行为均有 G-SNMP 编号和迁入计划；不以旧顶层协议映射绕过层链。SNMP 无长连接、无派生数据流，`sessions[]`/父子流关联在本协议不适用，仍需用 repeat、截断、Trap/Inform 例覆盖对应业务边界。

## 门1 §15 对照表

| CORE 行 | SNMP 对照与证据 |
|---|---|
| §1 | 旧 `src_ip/dst_ip/src_port/dst_port/count` 与顶层 `snmp` 均迁入 `ip`/`udp`/`snmp` 层；完整例见 `testcase.md:24-28`，当前字段消费缺口 G-SNMP-10。 |
| §2 | 策略数量走 `flow_control.flows`；本 case 未写数量，按单流。 |
| §3 | 会话表=无连接 datagram；事务序列=request→可选 response；关联=request-id；插入位置=每次 repeat 之间；时间线=顺序 emit，`poll_interval` 间隔。 |
| §4–§11 | 规范、错误、性能和回滚分别见本文 D1、D3–D5。 |
| §12 | 四元组住 `ip`/`udp`；业务动态均未开且列入 G-SNMP-5；repeat request-id 算法 `layer_gen.go:48-72`。 |
| §13–§14 | schema/真实 MCP、pcap/NIC 验收在 G-SNMP-9/10 完成后执行。 |

完整 `spec_json` 例：

```json
{"layers":[{"udp":{}},{"snmp":{"var_binds":[{"name":"1.3.6.1.2.1.1.1.0"}]}}]}
```

## 修订与自审

v1.2.0（2026-10-01）：补 D1 八项矩阵、三张子表、D2 三路对照与候选方案、D3–D8 实施契约及 §15 门1 对照；严格保留 G-SNMP-10 的实现阻塞，不宣称 suite 通过。
自审 2 轮，末轮干净：逐项核对 CORE §1/§3/§4/§5/§6/§8/§12/§15、层链唯一真相、BER 边界、错误传播、动态字段和缺口去向。

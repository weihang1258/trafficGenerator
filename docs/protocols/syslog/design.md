# #131 syslog 设计契约

> 版本：v1.2.0（2026-10-01，静态闭环）
> 范围：D1–D8；本轮只改本协议文档与 cases，不改 Go、schema 或全局索引。
> 依据：RFC 5424 §6、RFC 3164 §4、RFC 5426 §6、RFC 6587 §3–§4、RFC 5425。
> 机器契约：`trafficgen/test/protocol_pcap/cases/syslog.json`。

## D1 规范矩阵（P1）

|规范要求|业务场景|代码现状|缺口/结论|
|---|---|---|---|
|连接模型：UDP datagram；TCP/TLS stream|采集器接收一条 syslog 消息|UDP planner/layer generator 已接线；TCP/TLS layer path 拒绝|UDP 已覆盖；TCP/TLS 为 G-SYSLOG-3|
|消息/响应：syslog 无响应|单向发送日志|每事件输出一个上行 datagram|无响应状态机，适用|
|状态：编码后发送|单消息或消息序列|validator→generator→UDP/IP/Ethernet|同流多消息与异常/保活需 A′ 用例|
|字段：PRI、VERSION、HEADER、SD、MSG|RFC5424 默认消息与 BSD 变体|legacy validator/encoder 有实现；registry 仅登记无 Fields 的 `syslog` terminal|层字段与 translate/presence 登记缺 G-SYSLOG-1|
|错误：非法值、长度、SD、UDP 上限拒绝|坏配置任务失败|validator 返回 error|须由真实 task 端到端钉住|
|活性：UDP 无握手/保活|独立 datagram|无连接状态|适用；TCP/TLS另立|
|NAT/代理：仅依赖 IP/UDP|普通 IPv4/IPv6 传输|通用 IP/UDP 层负责|IPv6 cases 待补|
|版本/方言：5424、3164、6587 framing|RFC5424、BSD、TCP framing|RFC5424/BSD encoder；TCP path 未接线|G-SYSLOG-3|

### 三张子表

**命令/响应码矩阵（syslog 无命令/响应）**

|消息动作|成功|错误|结论|
|---|---|---|---|
|发送 UDP datagram|输出 1 个消息 datagram|编码/校验失败则 task error|已实现，`syslog_smoke_01`|
|发送 TCP/TLS stream|无|层链拒绝|G-SYSLOG-3|

**数据形态变体表**

|形态|状态|证据/缺口|
|---|---|---|
|RFC5424、空字段 NILVALUE|已实现|planner.go；冒烟 raw payload|
|RFC5424 显式 header/SD|legacy encoder 有路径|层 Fields/translate 未登记，G-SYSLOG-1|
|RFC3164 BSD|legacy encoder 有路径|无 cases，G-SYSLOG-7|
|BOM、octet-counting、non-transparent|部分 legacy 路径|BOM 现状需裁定；TCP 未接线，G-SYSLOG-3/G-SYSLOG-5|
|IPv4/IPv6|IPv4 现有|IPv6 cases 待补，G-SYSLOG-7|

**商业行为→用例映射表**

|现网行为|用例|来源/状态|
|---|---|---|
|UDP/514、RFC5424、PRI 与 NILVALUE|`syslog_smoke_01`|IANA 514 + RFC5424；PCAP 现有|
|BSD/3164|待建 A′|用 tcpdump/tshark 抓一条主流收集器包确认|
|TCP/TLS framing|待建|待层链接线后用 RFC6587/RFC5425 对照|

### 三路对照

|规范原文|商业软件行为|可靠开源实现思路|取舍|
|---|---|---|---|
|RFC5424 §6：PRI/VERSION/HEADER/SD|常见收集器接受 UDP/514 与 NILVALUE|rsyslog/syslog-ng 先编码完整消息再交 UDP|以 RFC5424 为底线，当前以 UDP 为可执行面|
|RFC3164 §4：BSD 时间与 TAG|兼容收集器仍接收 BSD|rsyslog 以格式选择器分派 encoder|现有 legacy encoder 继续存在，待 cases 钉实行为|
|RFC6587 §3–§4：TCP framing|现代收集器常用 octet-counting|syslog-ng 以 stream frame 解码|层链未接线前拒绝，不伪称支持|

### 候选方案

|方案|真实走法|优点|代价|选择|
|---|---|---|---|---|
|A|UDP 一 datagram 一消息（RFC5426）|实现短、边界明确、与现有 generator 对齐|无可靠传输|当前选择|
|B|TCP octet-counting（RFC6587 §3）|适合长消息与可靠 stream|需 TCP 状态、分帧和 teardown|G-SYSLOG-3 后再选|
|C|TCP non-transparent（RFC6587 §4）|兼容换行分隔设备|MSG 不能含 LF，边界歧义|与 B 比较后再定|

## D2 严格层链与配置权威

目标配置只能把地址放 `ip` 层、端口放 `udp` 层、业务字段放 `syslog` 层，顶层仅放 `layers`、`flow_control` 家族和 `output`。目标形状：

```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"udp":{"src_port":12345,"dst_port":514}},{"syslog":{"facility":1,"severity":6,"version":1,"msg":"hello"}}]}
```

当前 JSON 使用严格 `[udp,syslog]` 空配置，默认 IP/端口与默认消息均由引擎补全；本例不含顶层业务映射。显式层内业务键尚不能执行（registry `syslog` 的 `Fields` 为空），这是 G-SYSLOG-1（补 Fields、translate、presence 白名单），不是把业务键移回顶层的理由。

## D3 线格式与字段

RFC5424：`<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA [SP MSG]`；PRI=`facility*8+severity`，facility 0–23、severity 0–7，VERSION=1，空字段为 `-`。RFC3164 为 `<PRI>Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MSG`。最小默认 payload 为 `<14>1 - - - - - -`，17 字节；无 VLAN/IP options 时起点为 42。IP ID/校验和动态，不进 raw 断言。

## D4 消息、事务与流

UDP 一 datagram 对应一条消息，无握手、响应、挥手或 keepalive。实现语义是：`messages` 为空或恰有一项时编码一条消息并由 `count` 复制（缺省 1）；`messages` 多于一项时每项各发一个 datagram 且忽略 `count`（`planner.go:402-423`、`emitUDP:573-583`）。这里的 `count` 是旧业务配置的单消息重复次数，不是策略流数量；严格层链的流数量只能由 `flow_control: {"type":"flows","value":N}` 表达。当前 case 为空配置、默认 1 包。

syslog 无控制流/数据流关联；长连接事务不适用。若未来补多消息，必须逐条区分 payload；不得以复制单包冒充会话编排。

## D5 依赖、接口与主流程

依赖 `syslog→udp→ip`；流程为层链校验→syslog validator→事件流编码→UDP/IP/Ethernet→PCAP/NIC writer。规划接口为 `Validate(spec) error`、`Plan(ctx,spec) (<-chan PacketConfig,error)`；编码只保留当前消息缓冲，不聚合全量。

## D6 错误处理

非法 IP、facility>23、severity>7、非法 format/version/transport/framing、非 RFC3339 timestamp、字段空格/超长、SD 空/未闭合/非法参数、UDP payload 超限、TCP/TLS 层链均应在输出前返回 task error；不得静默修正或产出 completed/0 packet。真实锚词以 planner/layer generator 文案为准：`Facility`、`Severity`、`Version 0 unsupported`、`Format`、`not supported by the layer chain yet`、`not a valid RFC 3339 timestamp`、`exceeds`、`unclosed SD-ELEMENT`、`encoded message exceeds UDP payload limit`。

## D7 性能、输出与验收

生成器按消息事件流输出，单条消息之外不持有全量集合；无跨流协议锁。不得臆造吞吐、并发、内存数字。代码阶段须分别测基线、目标规模、压力上限、长跑、并发交错、背压，并断言包/比特率、延迟、内存、CPU、队列和失败。PCAP 与授权 NIC 共用本 JSON 的字段/raw 断言；当前仅有 PCAP 证据，禁在本轮宣称 NIC 已验收。

## D8 八要素、缺口与回滚

|要素|本协议结论|
|---|---|
|文件|`internal/protocol/syslog/`、`internal/core/layers/`（代码阶段）；本轮仅三份指定文件|
|接口|`Validate`、`Plan`、层 generator 事件输出|
|结构|`ip→udp→syslog`；数量走 `flow_control`|
|流程|校验→编码→封装→PCAP/NIC|
|错误|D6 锚词对应 task error|
|性能边界|D7 六类测量；当前无承诺数字|
|冲突点|registry Fields 空、TCP/TLS 未接线、legacy count 与严格数量分工冲突|
|回滚|仅回退本协议三文件；代码阶段另按提交回退 registry/translate/接线|

|缺口|证据|迁入计划|
|---|---|---|
|G-SYSLOG-1|registry `syslog` Fields 为空，显式层业务键无法 translate/presence 校验|先登记字段与白名单，再迁显式配置并重跑 cases|
|G-SYSLOG-2|legacy 默认 facility/severity 与层默认来源需统一|先写 failing test，再统一默认来源|
|G-SYSLOG-3|TCP/TLS layer generator 明确拒绝|完成 transport、framing、stream 生命周期后建例|
|G-SYSLOG-4|RFC 5424/3164 各长度上界未全强制|按代码边界补校验或登记新的实现任务|
|G-SYSLOG-5|BOM 编码路径与 RFC5424 推荐线形存在差异|裁定后同步 encoder 与断言|
|G-SYSLOG-6|`sign_blocks` 尚非 RFC5848 syslog-sign wire model|另立 RFC5848 设计与 cases|
|G-SYSLOG-7|当前仅 1 正例、0 负例；没有 presence-negative case|代码可执行后补原子负例与 BSD/SD/IPv6/multi-message cases；presence 负例须待通用白名单门接线后再建|
|G-SYSLOG-8|本轮未运行 suite/NIC|授权真实流程后生成结果证据|

## C1–C6 对账

|ID|结论|
|---|---|
|C1|目标正例顶层仅 `layers`；当前 JSON 无顶层业务映射，顶层残留为零。显式业务字段的层内 Fields/translate/presence 缺口登记 G-SYSLOG-1，未机械伪迁移。|
|C2|层链为 `[udp,syslog]`，默认 dst 514；当前 count=1 语义来自空配置默认单消息，不伪造 `flow_control`。|
|C3|显式 Fields/translate/presence 缺口登记 G-SYSLOG-1，未机械伪迁移。|
|C4|当前无负例；规划锚词逐字取自代码，未来 expect 仅 `expect_error` 与 `error_contains`。|
|C5|唯一 ID 与 testcase 对账；包数、端口、PRI、msg、offset 42 raw 均有证据。|
|C6|未发现 syslog-spec-mapping 文件；无需额外对账。|

## D9 动态字段清单（CORE §12）

|字段|策略|序号/代码位置|本轮结论|
|---|---|---|---|
|src/dst IPv4|未显式配置，使用通用 IP 默认|通用 IP 层 generator；本例不对动态值断言|不在 syslog 业务层重复配置|
|src_port|未显式配置，使用 flow 默认 12345|通用 UDP 层 generator；本例不对源端口断言|不在业务层重复配置|
|dst_port|固定默认 514|UDP 层默认值|由 `udp.dstport=514` 断言|
|facility/severity/version|固定默认 1/6/1|syslog validator/encoder 默认路径|由 PRI、facility、level 断言|
|msg/header/SD|默认 NILVALUE 消息|syslog planner 默认路径|由 `syslog.msg` 与 offset 42 raw 断言|
|按流变化|未启用|本例无 `flow_control.flows>1`，无序号算法|不宣称自动变化|

## D10 门1/门2 对照（CORE §15）

|门项|旧键去向|本轮证据|
|---|---|---|
|地址/端口|旧顶层地址端口不使用；地址归 `ip`、端口归 `udp`|spec_json 顶层仅 `layers`，形状 `[udp,syslog]`，默认地址/端口由层补全|
|数量|旧顶层 `count` 不使用；策略数量归 `flow_control`|本例仅默认单消息、1 包，不伪造数量字段|
|五件套|会话/事务/关联/插入/时间线|UDP 单 datagram、无会话/关联；按 CORE §3.14/§3.15，三项均标为不适用并以当前单包断言覆盖|
|动态三行|四元组、业务字段、序号算法|见 D9；本例不启用按流变化|

完整目标 spec_json 例：
```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"udp":{"src_port":12345,"dst_port":514}},{"syslog":{"facility":1,"severity":6,"version":1,"msg":"hello"}}]}
```
该例是 G-SYSLOG-1 完成后的目标形状；当前可执行例仍为无业务字段的默认层链，避免把未接线字段伪称已支持。

自审：两轮。第一轮逐项回查 D1–D10/C1–C6 与 CORE §1/§3/§4/§5/§6/§8/§12/§15，核对唯一例、顶层残留为零、动态清单和门表；第二轮复核 offset 42、默认端口、真实锚词、目标例与未运行边界；末轮干净。

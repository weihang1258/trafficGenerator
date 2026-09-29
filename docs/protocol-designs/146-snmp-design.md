# #146 snmp（SNMPv1/v2c/v3 · BER/UDP）设计契约

> 版本：v1.0.0（P-PIPE 批次二，as-built 逆向定稿）
> 日期：2026-09-29；车道：文档轨（#146 snmp，初编 #134 后改号）
> 存量用例：`trafficgen/test/protocol_pcap/cases/snmp.json`（**1 例**，唯一权威；`snmp_smoke_01`）
> 规范基线：RFC 1157（v1）、RFC 3416（v2 PDU）、RFC 3417（传输）、RFC 3414（USM）、RFC 3411/3412/3413（体系/消息处理）、ASN.1 BER X.690；实现：`trafficgen/internal/protocol/snmp/` 与公共 UDP 层。
> 白话一句：**管理器把一个 BER 编码的请求（版本、社区/USM、PDU、OID）装进 UDP 161；陷阱和 Inform 发往 162。**

## 0. 实现边界与现状

SNMP 是 UDP 终结层：registry `internal/core/layers/registry.go:164` 注册 `snmp`，依赖 `udp`；`layer_gen.go:101-109` 注册生成器/校验器；`chain_planner_translate.go:53-60` 经 `FlowMeta.SNMP` 传入生成器；`strategy_convert.go:1397-1440` 从 `cfg.snmp` 搬运配置；准入在 `internal/core/protocols.go:55`；缺省端口由 `chain_planner.go:1054-1067` 按 PDU 选择 161/162。

当前可执行形状是存量的层链加顶层协议子映射（层 registry 的 Fields 为空，复杂 SNMP 配置不能住在层项）：

```json
{"layers":[{"udp":{}},{"snmp":{}}],"snmp":{"var_binds":[{"name":"1.3.6.1.2.1.1.1.0"}]}}
```

实现不提供 TCP/TLS/SNMP-over-SSH；不实现真实 Manager/Agent 状态发现、重传、引擎发现交互。v3 支持 USM 报文构造：MD5/SHA-1 HMAC、AES-128-CFB；SHA-2/AES-192/256 名称可校验但实现回退到已实现算法并保留配置元数据，**不得声称对应算法已在线验证**（`planner.go:11-17`）。

输出：pcap 与 NIC 共用 cases JSON；UDP 无握手、FIN/RST、保活或连接终止断言。无 VLAN/IP options 时 IPv4 UDP payload 起点为以太网偏移 42（14+20+8），IPv6 为 62（14+40+8）。

## 1. 协议栈、端口、事务

推荐链：`[ip,udp,snmp]`；最小链 `[udp,snmp]`，IP 由框架补齐。Agent 查询端口 UDP **161**，Trap/Inform 目的端口 UDP **162**（RFC 3417）。源端口沿框架默认 12345，显式值优先。

事务是一个 UDP 数据报：请求（up）可选响应（down）。`RepeatCount=N` 产生 N 个请求；`IsResponse=true` 每请求后立即产生同 request-id 的响应；`PollInterval` 仅在迭代间等待。无连接会话、控制/数据流关联、父子流或多会话状态；这些维度对 UDP 单报文模型不适用。请求与响应关联键是 PDU request-id（`RequestID=0` 时随机起点，随后按迭代序号递增）。

## 2. 配置契约与默认值

`core.SNMPConfig`（`internal/core/types.go:7609-7657`）：

|字段|类型/取值|缺省与线面|
|---|---|---|
|`version`|uint8，0=v1、1=v2c、3=v3|converter 缺省 1；BER INTEGER 0/1/3|
|`community`|string|v1/v2c 缺省 `public`；BER OCTET STRING|
|`user_name`|string|v3 USM userName；v1/v2c 不用|
|`auth_protocol`|none/md5/sha1/sha224/sha256/sha384/sha512|v3；空/none 不认证|
|`auth_password`|string|auth 非 none 时必填|
|`priv_protocol`|none/des/aes128/aes192/aes256|priv 非 none 必须先有 auth|
|`priv_password`|string|隐私密钥来源|
|`authoritative_engine_id`|hex，1–32 bytes|v3 USM engineID；空可作 discovery|
|`authoritative_engine_boots/time`|uint32|v3 USM engineBoots/time，BER INTEGER|
|`pdu_type`|0 Get、1 GetNext、2 Set、3 GetBulk、4 TrapV1、5 TrapV2、6 Inform|缺省 0；标签见 §3|
|`request_id`|uint32|0=随机起点递增；BER signed INTEGER 表示|
|`non_repeaters`|uint8|GetBulk 第一控制整数，缺省 0|
|`max_repetitions`|uint8|GetBulk 第二控制整数；0 在 builder 中按 1|
|`var_binds`|array|Get/GetNext/Set/GetBulk 至少一项；Trap/Inform 可空|
|`is_response`|bool|false；true 改用 Response PDU 0xa2|
|`response_error/index`|uint8|响应 error-status/index，缺省 0|
|`response_values`|array|非空时替代响应 varBinds|
|`enterprise`/`agent_addr`|OID/IPv4|v1 Trap，空分别用 `1.3.6.1.4.1.3.1.1`/`0.0.0.0`|
|`generic_trap`/`specific_trap`/`time_stamp`|uint8/uint8/uint32|v1 Trap 专用；generic 0–6|
|`poll_interval`/`repeat_count`|int|毫秒间隔；repeat<=0 按 1|
|`engine_id_override`|string|当前 planner 的兼容字段，v3 engineID 仍来自 authoritative 字段|
|`max_size`/`context_name`|uint32/string|v3 msgMaxSize 缺省 484；scopedPDU contextName 缺省空|

`SNMPVarBind`（`types.go:7659-7666`）是 `name` dotted OID、`type` BER tag、`value` 原始值体（不含 tag/length）、`str_value` 的 OCTET STRING 便利输入。空 SNMP 配置在 generator 中归一为默认流；legacy planner 同样允许 nil 并默认 v1 Get。

校验锚词：版本非法 `snmp: Version ... is not a valid SNMP version`；v1/v2c 空 community `snmp: Community empty`；v3 auth 缺密码 `AuthProtocol ... AuthPassword empty`；priv 无 auth `PrivProtocol ... AuthProtocol is none`；非法 auth/priv `not in supported list`；engineID 非 hex/长度越界；PDU >6 `PDUType ... not in supported list`；空 VarBinds（Get 类）`VarBinds empty`；空/非法 OID `VarBinds[i].Name ...`。源/目的 IP 跨族、端口 >65535 也拒绝。

## 3. BER 线格式（代码可生成级）

所有多字节整数为 BER 大端 two's-complement；OID 后续弧为 base-128，每字节高位为 continuation。每个元素是 `Tag | Length | Value`。长度 `L<128` 为 1 字节 `L`；`128≤L≤255` 为 `81 nn`；`256≤L≤65535` 为 `82 nn nn`（大端）；总 TLV 长度 `1 + len(Length) + L`。因此长形长度前缀在长度本身之后，所有后续偏移随 `len(Length)` 增加。

### 3.1 v1/v2c 消息

外层 `SEQUENCE 0x30`：

|相对偏移|字段|编码/长度|
|---:|---|---|
|0|version|INTEGER `02 LL VV`，LL=1（值 0/1）|
|`T(version)`|community|OCTET STRING `04 L C`，长度 C|
|`T(version)+T(community)`|PDU|context-specific constructed，长度 `P`|

总长 `M = T(version)+T(community)+P`，消息 = `30 Len(M) body`。v1/v2c builder：`planner.go:786-791`。

标准 PDU（Get 0xa0 / GetNext 0xa1 / Response 0xa2 / Set 0xa3 / GetBulk 0xa5 / Inform 0xa6 / v2 Trap 0xa7 / Report 0xa8）是 **[N] IMPLICIT SEQUENCE**：PDU tag 后直接拼字段，不再放 0x30。布局：`request-id INTEGER`、`field1 INTEGER`、`field2 INTEGER`、`VarBindList SEQUENCE 0x30`。Get/GetNext/Set/Response 的 field1=error-status、field2=error-index；GetBulk 的 field1=non-repeaters、field2=max-repetitions。PDU 总长 `1+Len(P)+P`，`P=T(id)+T(field1)+T(field2)+T(VBL)`；编码 `planner.go:719-740`。

v1 Trap（0xa4）例外布局：`enterprise OID`、`agent-addr IpAddress`、`generic-trap INTEGER`、`specific-trap INTEGER`、`time-stamp TimeTicks`、`VarBindList`，无 request-id/error 字段；`P=ΣT(fields)`，实现 `planner.go:743-768`。PDU 标签全集定义于 `planner.go:90-100`。Report 0xa8 是标签常量，但当前 `PDUType` validator 仅允许 0–6，故 Report 属待实现边界。

### 3.2 VarBind、OID 与值

VarBindList = `SEQUENCE OF VarBind`：`30 Len(sum VarBind)`；每 VarBind = `30 Len(OID_TLV + Value_TLV)`。OID `06 Len body`；第一值 `40*arc0+arc1`（常见 1.3 = **0x2b**），后续弧 base-128。实现 `encodeOID`/`encodeArc`：`planner.go:558-595`。

|类型|tag|Value 规则|
|---|---:|---|
|NULL|`05`|长度 0；Type=0 在请求中也归 NULL|
|INTEGER|`02`|最小有符号大端，必要时 00/ff 符号扩展|
|OCTET STRING|`04`|原始 bytes；空 Value 且 StrValue 非空则 UTF-8 字节|
|OBJECT IDENTIFIER|`06`|OID body（tag/length 仍由 VarBind value TLV 给出）|
|IpAddress|`40`|4-byte IPv4|
|Counter32|`41`|非负大端，必要时 00 前缀|
|Gauge32|`42`|同上|
|TimeTicks|`43`|同上|
|Opaque|`44`|原始 bytes|
|Counter64|`46`|非负大端|
|noSuchObject/noSuchInstance/endOfMibView|`80/81/82`|异常值，长度 0|

未知 type 当前回退 NULL（`planner.go:659-703`），不报错；这是待补的严格 validator 行为。VarBind OID 必须非空、弧非负整数；当前未限制首弧 0–2/第二弧规范范围，列为缺口。

### 3.3 v3 消息与 USM

外层仍 `30 Len`，依次为：`msgVersion INTEGER(3)`；`msgID INTEGER`；`msgMaxSize INTEGER`（缺省 484）；`msgFlags OCTET STRING`（reportable bit 0x04、priv 0x02、auth 0x01）；`msgSecurityModel INTEGER(3=USM)`；`msgSecurityParameters OCTET STRING`；`scopedPDU`。

USM 参数是 OCTET STRING 内的 `SEQUENCE`：`engineID OCTET STRING`、`engineBoots INTEGER`、`engineTime INTEGER`、`userName OCTET STRING`、`authParameters OCTET STRING`（auth 开启时 12-byte placeholder/digest）、`privParameters OCTET STRING`（priv 时 8-byte salt）。ScopedPDU = `SEQUENCE{contextEngineID OCTET STRING, contextName OCTET STRING, PDU}`；priv 开启时改为加密 OCTET STRING。代码顺序与长度递推在 `planner.go:853-957`。

USM auth：实现 RFC 3414 风格 password/engineID 派生后 HMAC，MD5/SHA-1 为真实路径；SHA-2 仅接受并回退。priv：AES-128-CFB 真实路径；DES/AES-192/256 接受并回退/标记。当前 AES IV 简化为 salt padded 16 bytes（`planner.go:1167-1183`），不是完整 RFC 3826 IV，故不声称互操作。

## 4. 生成状态与业务场景

生成器 `SNMPGenerator.Generate`（`layer_gen.go:28-89`）复制配置 → repeat 归一 → request-id 基准 → 循环：检查 context、emit up request/trap、若 `IsResponse` emit down response、非末次等待 PollInterval。UDP 层将每 MessageEvent 变成一个 datagram；方向 down 交换 MAC/IP/端口。无重试、重连、FIN/RST、保活、流关联；多消息仅 repeat 序列。

现网场景：① Manager Get 单 OID（存量 smoke）；② GetNext/Set/GetBulk；③ Agent Response；④ v1/v2c Trap/Inform；⑤ v3 USM discovery/auth/priv；⑥ 多 VarBind/异常值。当前 JSON 只证明①；其余为待补行为面。

性能边界：单 datagram payload 受 UDP/IP 最大报文约束（IPv4 UDP payload ≤65507，当前 SNMP builder 未显式守卫）；BER 长形长度最多实现 0x7f 个长度字节但 SNMP 实际应受 UDP 上限；无跨流共享状态。报文长度公式均为 TLV 递推，长度进入 128/256 时分别增加 1/2 个 length 字节。

## 5. 五层覆盖结论

- **功能**：存量只覆盖 v1 Get；GetNext/Response/Set/GetBulk/Trap/Inform/v3/Report 未入 cases。
- **性能**：大 VarBind、长形 0x81/0x82、UDP 上界、多流并发未入 cases；UDP 分片属 IP 层，SNMP 本层不切片。
- **数据**：OID 1.3、NULL 请求覆盖；其它 10 值类型、OID base-128 边界、空/最大 community、v3 字段未覆盖。
- **地址与流**：存量 IPv4 UDP；IPv6、非默认端口、混合 IP 拒绝未覆盖；流关联/连接状态不适用（单 datagram）。
- **业务**：单 Get 有例；多 VarBind、多事务 repeat、Trap/Inform、v3 USM、多会话不适用或待实现（generator 只有单流事件序列）。

## 6. 门1 §1–§14 十四行对照表

|§|本协议怎么满足|证据|
|---|---|---|
|1 层链唯一真相|存量使用 `[udp,snmp]`，复杂配置仍顶层 `snmp`，无游离 `src_ip/dst_ip/count`|§0；cases JSON|
|2 策略/任务|策略配置映射为 FlowSpec；任务级数量/流控由框架承载，SNMP repeat 在协议配置内|`strategy_convert.go:1397`；§2|
|3 五件套|会话表=无（UDP 单报）；事务=每 datagram 请求/可选响应；关联=request-id；插入=UDP 终结层；时间线=up→down→interval|§1/§4；`layer_gen.go:65-85`|
|4 查规范|RFC 1157/3411–3417/3414 与 X.690；BER 取值逐项列于 §3|§3|
|5 依赖与错误|依赖 UDP；validator 锚词及传播边界列于 §2；生成器 EmitMsg nil 显式报错|registry:164；`layer_gen.go:38-42`|
|6 性能|BER 长度公式、UDP 上界、payload 起点和无分段边界|§4；§5|
|7 三份文档|design/testcase/cases 三方唯一 ID `snmp_smoke_01`，1 包和字段一致|§0；testcase §2|
|8 设计先行|本版按落码反推，未承诺未实现类型|全文边界|
|9 测试三源|RFC + 代码 + 唯一 cases/pcap 结果（结果文件过期登记）|§7；testcase §5|
|10 评审闭环|本文自审并标注待独立审查；缺口不冒充覆盖|§7/§8|
|11 白话|首部白话句定义 UDP BER 管理报文|标题注记|
|12 动态字段|四元组由 ip/udp 框架策略承载；SNMP 业务字段无动态 allowlist；request-id=0 随机起点|§2/§4；`layer_gen.go:48-71`|
|13 schema 派生|snmp registry terminal、DependsOn udp、Fields 空；无需新增 schema|`registry.go:164`|
|14 真实流程|配置→converter→ChainPlanner/FlowMeta→validator→Generate→UDP→pcap/NIC|§0；`chain_planner_translate.go:53-60`|

### 6.1 §1 旧键去向与目标形

存量 1/1 顶层键为 `layers` + `snmp`；没有顶层 `src_ip`、`dst_ip`、`src_port`、`dst_port`、`count`、`strategy_fc`、`flow_control`。`dst_port` 缺省由 chain planner 写入 161；var_binds 在顶层 snmp 子映射经 converter 解析。目标完整例见 §0。presence 负例（层链与顶层空 snmp 并存）当前框架不应宣称可拒，登记 G-SNMP-1。

### 6.2 §3 五件套展开

|项|SNMP as-built|
|---|---|
|会话表|无连接会话；每 flow 独立 datagram 序列|
|事务序列|request/trap up；`IsResponse` 时 response down；repeat 次数按配置|
|关联关系|response 的 request-id 与 request 相等；IP/UDP 方向反转|
|插入位置|UDP 后 terminal `snmp`|
|时间线|每次 emit 顺序确定；repeat 间 PollInterval；无 FIN/RST|

### 6.3 §12 动态字段清单

`ip.src/dst`、`udp.src_port/dst_port` 使用框架的 fixed/inc/rand/list/pattern（序号由 flow tuple generator/FlowIndex 决定）；snmp `request_id` 不是动态策略字段：0 时每次运行随机基准，随后 `base+i`。`var_binds`、community、USM、PDUType 等业务字段无 `snmp` layer dynamic allowlist，不能声称支持五策略流间变化；这属于 G-SNMP-5。

## 7. 缺口登记

|缺口|现象/证据|归属阶段|
|---|---|---|
|G-SNMP-1|唯一 case 的层链+顶层 `snmp` 形状；通用 presence/游离键判死未在 `CheckProtoFlat` 登记，不能虚建负例|框架 P4|
|G-SNMP-2|存量仅 v1 Get 1 例；其余 PDU、v2 Trap/Inform、v3、Report 无 JSON 证据|协议 P4|
|G-SNMP-3|BER 0x81/0x82、OID base-128、长 community/VarBind 无 pcap 断言|协议 P4|
|G-SNMP-4|除 NULL/OID 默认外的值 tags（02/04/06/40/41/42/43/44/46/80–82）无用例|协议 P4|
|G-SNMP-5|SNMP 业务字段没有 dynamic allowlist；fixed/inc/rand/list/pattern 五策略未实现/未覆盖|框架 P4|
|G-SNMP-6|v3 SHA-2/AES-192/256 接受但回退，AES IV 为简化实现；不具备对应互操作保证|协议 P4/边界|
|G-SNMP-7|validator 未严格限制 OID 首/第二弧；未知 VarBind type 静默回退 NULL|协议 P4|
|G-SNMP-8|UDP 最大 payload/截断 BER/长度不匹配/非法状态无负例，生成器未对 payload 上界作 SNMP 专属守卫|协议 P4|
|G-SNMP-9|`docs/protocol-pcap-test/snmp.md` tracked 末次提交 `e7e7d1c`（2026-08-27）早于 0417be5（2026-09-13），且 pcap 目录不存在；1/1 数字未经当前套件复跑证实|代码阶段 P5|

## 8. 修订与自审

v1.0.0（2026-09-29）：按实现、registry、converter、唯一 cases JSON 逆向定稿；覆盖 BER 字段/长度/偏移公式、v1/v2c/v3 USM、PDU/VarBind、五层、门1 十四行、缺口。**自审 2 轮，末轮干净**：机读核对 1 个 ID、1 包、6 个 fields、顶层形状、registry/接线行号与缺口编号；未运行 pcap 套件，故不宣称今日测试通过。

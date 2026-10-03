# #136 RDP（MS-RDPBCGR）设计契约

> 版本：v1.3.0（2026-10-01，静态闭环校准）
> 机器实现：`trafficgen/internal/protocol/rdp/`；机器用例：`trafficgen/test/protocol_pcap/cases/rdp.json`
> 规范基线：RFC 1006 §4、ISO 8073、T.125、MS-RDPBCGR §2.2.1；实现与用例以本契约为准。
> 白话一句：RDP 先在 TCP/3389 上做 X.224 连接协商，再完成 MCS/GCC 建会话，随后交换安全、登录、许可证和能力数据，最后关闭连接。

## 0. 范围与实现边界

本契约覆盖 RDP over TCP 的默认 standard security 形态：TCP 三次握手 → X.224 CR/CC（含 RDP Negotiation）→ MCS Connect-Initial/Response → Erect-Domain → Attach-User → I/O Channel Join → Security Exchange → Client Info → License → Capability Exchange → Shutdown/Disconnect → TCP 四次挥手。默认目的端口为 3389（MS-RDPBCGR §1.3）。

链上生成器由 TCP 层负责握手、序号、MSS 分段和挥手；RDP 终结层只通过 `MessageEvent{Up,Bytes}` 产出应用消息（`layer_gen.go:56-249`）。legacy planner 仍自带 TCP，但本契约以层链实现为准。TLS/NLA/NLA-EX、真实 CredSSP/密码学不属于当前层链实现：validator 拒绝这些安全层（`layer_gen.go:282-288`），不得把占位能力写成已实现。

## 1. 层链、端口与配置真相

推荐形状为 `{"layers":[{"tcp":{"dst_port":3389}},{"rdp":{...}}]}`；registry 将 `rdp` 注册为 `CategoryTerminal`、依赖 `tcp`（`registry.go:1618-1621`）。RDP 业务和承载字段均不放顶层；数量走 `flow_control`。

完整最小形状：
```json
{"layers":[{"tcp":{"dst_port":3389}},{"rdp":{}}]}
```

存量 JSON 已是严格层链 `{layers:[{tcp:{dst_port:3389}},{rdp:{}}]}`；层链 validator 会将 TCP Handshake/Termination 强制为 true（`layer_gen.go:294-299`）。

## 2. 配置字段与默认值

| 字段 | 类型/默认 | 生成作用与校验 |
|---|---|---|
| `security_layer` | string，空/`standard` | standard 产 Security Exchange；`tls`,`nla`,`nla_ex` 在层链拒绝；其他值拒绝（`planner.go:325-331`） |
| `requested_protocols` | uint32，按安全层推导 | Negotiation Request 的 LE 位图 |
| `restricted_admin`,`redirected_auth` | bool，false | Negotiation flags |
| `cookie` | string，空 | CR 前置 Cookie 字节 |
| `client_name` | string，空 | UTF-16LE 固定 16B；最大 8 字符/16B |
| `client_build`,`keyboard_layout/type/sub_type/function_key` | uint32，0 | Client Core |
| `desktop_width/height` | uint16，1920/1080 | 允许 200..32768 |
| `color_depth` | uint16，5 | 允许 1..5 |
| `high_color_depth`,`supported_color_depths`,`connection_type` | uint16,uint16,uint8 | Client Core |
| `server_selected_protocol` | uint32，0 | Server/Core 回显 |
| `encryption_methods`,`ext_encryption_methods` | uint32，standard 缺省 0x2 | Client Security |
| `domain`,`user_name`,`password`,`alternate_shell`,`working_dir` | string，空 | Client Info UTF-16LE |
| `channels` | list，空 | 每项 `name` ≤7 个 7-bit ASCII 字符；最多 31；Channel Join |
| `auto_logon`,`info_unicode`,`info_logon_notify`,`info_compression` | bool，false | Client Info flags |
| `code_page`,`flags2` | uint32/uint16，0 | Client Info |
| `skip_mcs_channel_join`,`skip_security_exchange`,`skip_license`,`skip_capability` | bool，false | 跳过对应阶段；当前 case 使用默认值 |
| `force_rdp_version` | uint32，按安全层推导 | Client/Server Core version |
| `encryption_level`,`encryption_method` | uint32，standard 默认 2/2 | Server Security |
| `server_random` | bytes，确定性 32B | Server Security，截断/零填充至 32B |
| `server_cert_version` | uint32，1 | 最小 V1 证书占位 |
| `security_exchange_rsa_key_bytes` | int，128 | dummy encryptedClientRandom 长度 |
| `scenario` | string，空 | `scenario.go` 填充默认 channels/events/responses，用户值优先 |
| `data_events` | list | FastPath、CLIPRDR、RDPDR、RDPSND、DRDYNVC 等上行/下行事件 |
| `server_responses` | list | 服务器能力、FastPath、虚拟通道响应 |

配置→validator→generator→writer 路径：层链 schema 验证后，translate 生成 `RDPConfig`，`RegisterLayerValidator` 调 `Planner.Validate` 并同步 TCP 开关，`RDPGenerator.Generate` 调 `applyScenarioDefaults`，按固定阶段编码 PDU 并 EmitMsg；TCP worker 再加握手、序号、分段、挥手。

## 3. 线格式与字节规则

### 3.1 TPKT/X.224

TPKT（RFC 1006 §4）为 4B：`version=0x03`、reserved=0、`length uint16 BE`（含自身）。X.224 CR/CC 头：LI、code `0xe0/0xd0`、DST-REF 2B、SRC-REF 2B、class 1B；DT 头固定 `02 f0 00`。当前正例 IPv4 无 VLAN/options 时应用字节起点为 Ethernet+IPv4+TCP = offset 54。

CR 在 X.224 头后放可选 Cookie，再放 8B Negotiation Request：type=1、flags、length=8（LE uint16）、requestedProtocols（LE uint32）。CC 放 type=2 response 或 type=3 failure，字段同形。安全层推导：standard=0x1、tls=0x2、nla=0xa、nla_ex=0x2a（`deriveRequestedProtocols:929-943`）。

### 3.2 MCS/GCC

MCS Connect-Initial 是 APPLICATION 101（`7f 65`）BER 长度，包含 calling/called domain selector、upwardFlag、target/minimum/maximum DomainParameters 和 GCC Connect-Data；Connect-Response 是 APPLICATION 102（`7f 66`）并含 result/connectId/domain/userData。BER 长度短形 0..127 为 1B，长形为大端长度（`encodeBERLength:2111-2124`）。DomainParameters 的 7 个 INTEGER 为 RDP 实际无前导零 unsigned convention；GCC H.221 t124Identifier 固定 20B。

Erect-Domain 为 `04 00 00`；Attach-User Request `28`；Confirm 为 `2c result initiator(2B BE)`，默认 user ID 1001；Channel Join Request/Confirm 使用 `38/3c`、initiator/channel 2B BE、confirm result 1B。I/O channel 1003 必加入；静态 channels 映射为 1004 起，最多到 1031。

### 3.3 RDP Security/Info/Capability

standard Security Exchange：security header flags `0x0080`、长度 uint32 LE、dummy encryptedClientRandom（默认 128B；可配置 64/128/256/512），真实 RSA 不执行。Client Info 的前 18B 为 codePage 4、flags 2、flags2 2、五个 UTF-16LE 字段长度各 2，随后字段字节。Client Core 固定 218B，宽高在偏移 4/6，颜色深度偏移 8，clientName 偏移 20 长 16。

License Request/Client License Info：`bMsgType, flags, wMsgSize`，均 LE，固定空数据时 4B。Demand Active/Confirm Active 使用 Share Control/Data 头；Confirm Active 含 5 个能力集（General、Bitmap、Input、MultiFragmentUpdate、FrameAcknowledge）。Server Synchronize/Control/Font Map 是 Share Data PDU。

### 3.4 活动数据

每个 `data_events` 事件最多形成一个消息（超 MSS 由 TCP 层分段）。支持 `fastpath_input_keyboard/mouse`、`cliprdr_*`、`rdpdr_*`、`rdpsnd_*`、`drdynvc_create`、`rdpgfx_surface_command`；payload 非空时使用用户字节，否则使用编码器默认值。`PayloadB64` 用标准 base64 解码；未知 type 在有 payload 且指定 channel 时原样包装，否则跳过。ServerResponses 支持 bitmap/palette/surface、license、virtual-channel 等形态。

## 4. 状态机、事务与业务场景

状态：`TCP_ESTABLISHED → X224_NEGOTIATED → MCS_CONNECTED → USER_ATTACHED → CHANNELS_JOINED → ACTIVE → CLOSING → TCP_CLOSED`。同一输入确定地产生同一阶段序列；非法安全层/端口/字段在 validator 失败。Channel Join failure（响应 result=4）不终止后续阶段，符合 planner 的继续策略。

业务场景：桌面登录（standard + Client Info）、剪贴板（cliprdr）、设备重定向（rdpdr）、音频（rdpsnd）、动态图形（drdynvc）、键鼠输入、位图输出、单连接断开。多事务是同一 TCP 连接内按序的 MCS/安全/能力/数据事件；不存在控制流派生数据流，因此流关联不适用。多会话不适用：一个 RDPConfig 生成一个 TCP 会话；多 flow 由框架 `flow_control` 承载，当前 case 未启用。

## 5. 性能、边界与输出

单 PDU 不跨 MSS 的 case 由一个 PSH-ACK 承载；`segmentByMSS` 对更大 payload 按 MSS 上取整分段，默认 MSS 1460，最小 MSS 约束常量 536。最大静态 channel 数 31，Channel ID 1004..1031。Client Name 上限 16 UTF-16LE 字节；desktop 宽高边界 200/32768；RDP Security Exchange 默认 128B，可扩到 512B。输出 pcap 与 NIC 使用同一 cases 断言；NIC 需 tcpdump 捕获真实 TCP/IP 帧，PCAP 用 offset 54（IPv4）或按外层 IPv6 头重新计算，当前 case 仅 IPv4。

## 6. 错误契约

| 错误条件 | 锚词/代码 |
|---|---|
| RDP 配置缺失 | `RDP config is required` (`planner.go:306-308`) |
| 源/目的地址非法 | `invalid source IP` / `invalid destination IP` (`:309-318`) |
| 非 3389 目的端口 | `DstPort must be 3389` (`:319-323`) |
| 未知安全层 | `SecurityLayer ... not in {standard,tls,nla,nla_ex}` (`:325-331`) |
| ClientName 超长 | `clientName must be <= 16 bytes` (`:333-336`) |
| 宽高越界 | `desktopWidth must be 200-32768` / height (`:338-345`) |
| 颜色深度非法 | `colorDepth must be 1/2/3/4/5` (`:346-352`) |
| channel 数/名/编码非法 | `channelCount` / `too long` / `7-bit ASCII` (`:355-370`) |
| TLS/NLA 层链不可用 | `SecurityLayer ... not supported on the layer chain` (`layer_gen.go:286-288`) |

负例必须只断 `expect_error,error_contains`，任务终态为 error 且不得产成功 PCAP；现有 cases 无负例，故这些分支尚未由机器契约覆盖。

## 7. 五层覆盖与当前缺口

- **功能层**：现有 case 仅默认 CR/CC、MCS Connect Initial/Response、X.224/MCS 字节；未独立覆盖安全、Info、License、Capability、活动通道及失败状态。
- **性能层**：现有基线 27 帧；未覆盖 MSS 跨段、最大 channel、最大 ClientName/宽高相邻值、RSA key 长度边界。
- **数据场景层**：未覆盖 Cookie、flags、协议位图、安全层变体、UTF-16、base64、虚拟通道 payload、非法长度/编码。
- **地址与流层**：只有 IPv4 单流；IPv6、默认/非默认端口、混合地址族、MSS 分段未覆盖。流关联不适用。
- **业务层**：只覆盖最小连接烟雾；full_session、多事务、剪贴板/设备/音频/图形/键鼠、channel failure、异常 RST 未覆盖。

主要缺口：G-RDP-3 tshark TCP/3389 无 RDP dissector，只能 raw bytes，`decode_as echo` 是临时工具策略；G-RDP-4 TLS/NLA 层链拒绝且无真实密码学；G-RDP-5 scenario/业务字段动态策略未接入；G-RDP-6 IPv6/NIC/大报文边界未验证；G-RDP-7 tracked `trafficgen/docs/protocol-pcap-test/rdp.md` 未在本车道重跑，结果文档不能作为今日 pcap 证据。G-RDP-2 的 8 个负例已完成静态形状闭环，task error/零成功 PCAP 待执行期确认。

## 8. D/T/C 设计—测试—覆盖闭环

### D（设计约束）

- **D1 层链**：唯一目标形状是 `[tcp,rdp]`（可由框架外层补 IP）；RDP 依赖 TCP，目的端口默认且必须为 3389，TCP handshake/termination 由 validator 强制打开。
- **D2 会话**：单一 TCP 流按 X.224 → MCS → standard security/info/license/capability → active events → shutdown/FIN 顺序生成；无派生数据流。
- **D3 数据**：RDP 业务字段位于 `rdp` 层；地址、端口、数量分别由外层 IP/TCP/任务 `flow_control` 承载。业务字段当前没有动态 allowlist。
- **D4 边界**：TLS/NLA/NLA-EX、真实 CredSSP/密码学不属于层链实现；validator 明确拒绝，不能写成已支持。

### T（测试来源与执行）

- 规范来源：RFC 1006 §4、ISO 8073、T.125、MS-RDPBCGR §2.2.1；实现来源：registry、chain planner、RDP validator/generator；机器来源：`rdp.json`。
- 当前 1 个正例和 8 个负例均来自机器 JSON；正例断言 27 帧下界、TCP negotiated/directional/terminates、`tcp.dstport=3389`、6 个 `tcp.len`/6 个 offset+hex 原始前缀；负例 `expect` 严格只有 `expect_error` 与 `error_contains`，锚词来自 `planner.go:305-370` / `layer_gen.go:278-288`。notes 是溯源信息，不替代断言。
- 本车道没有实际 MCP、tshark/PCAP 或 NIC 重跑；历史 pcap 仅作字节核对来源，不能作为 2026-10-01 的执行证据。

### C（当前覆盖与真实缺口）

| 面 | 已有机器证据 | 未运行/未覆盖边界 |
|---|---|---|
| 功能 | 1 个正例、8 个 validator/layer 负例、CR/CC、TPKT、MCS Connect-Initial 原始锚点；正常双向 TCP 终止 | MCS Response/Attach/Join、安全 Exchange、Client Info、License、Capability、active data、Negotiation/Join failure 独立正例 |
| 数据/动态 | 默认空 RDP 配置；TCP 四元组由框架策略处理 | Cookie、协议位图、UTF-16、base64、虚拟通道；RDP 业务字段 fixed/inc/rand/list/pattern 动态策略未接线 |
| 性能/边界 | 361B MCS payload；27 帧基线 | MSS 分段、RSA key 64/128/256/512B、ClientName 16B及超限、宽高 200/32768及相邻值、31/32 channel |
| 地址/流 | IPv4 单流、TCP 3389、offset 54、非默认端口拒绝负例 | IPv6、混合地址族、RST、NIC 实抓；RDP 无派生流；负例 task error 传播仍待运行 |

C 表只计 JSON 中实际存在的断言；设计字段、编码器分支或历史 pcap 不等于覆盖。

## 9. 门1 §1–§14 对照表

| § | 满足方式 | 证据 |
|---|---|---|
| §1 层链唯一真相 | `[tcp,rdp]`；存量 JSON 已迁移，顶层仅 `layers` | §1；cases/rdp.json |
| §2 策略/任务 | RDP 配置是策略，task 由框架调度；当前单 flow | `types.go:7053-7166` |
| §3 五件套 | s1 单 TCP 会话；MCS/安全/能力/数据事务按序；无派生流；终结层插入；TCP→RDP→关闭时间线 | §4；`layer_gen.go:82-249` |
| §4 查规范 | RFC 1006、ISO 8073、T.125、MS-RDPBCGR、MS-RDPELE/FS/CLIPRDR 等 | §3 |
| §5 依赖与错误 | rdp 依赖 tcp；planner 与 layer validator 拒绝非法输入 | registry:1618；§6 |
| §6 性能 | MSS、PDU、channel、字段边界有上限；未作吞吐承诺 | §5 |
| §7 三份文档 | 本 design/testcase 与 cases JSON；当前 JSON 1 正例 + 8 负例，ID/场景/断言三方一致 | §1；testcase §2 |
| §8 设计先行 | 本文 as-built 记录已落实现状，未承诺未来能力 | §0 |
| §9 测试三源 | 规范 + 代码 + `rdp.json`/既有 pcap 说明；旧结果需重跑 | §7；testcase §3 |
| §10 评审闭环 | 文档自审；独立审查待主线程执行 | 修订记录 |
| §11 白话 | 首段白话及阶段解释 | 本文首段 |
| §12 动态字段 | 四元组由框架支持；RDP 业务字段无 allowlist 动态接线，登记 G-RDP-5 | §7；`layer_dyn.go` |
| §13 schema 派生 | registry 已注册 rdp，Fields 仅 tcp.dst_port | `registry.go:1618-1621` |
| §14 真实流程 | validator→generator→TCP worker→PCAP/NIC；现有 pcap 为旧结果 | §1/§5/§7 |

### §1 强制展开：旧键去向与目标形状

| 旧键 | 出现 | 去向 |
|---|---:|---|
| `count` | —（当前 cases 无此旧键） | 删除；数量走 `flow_control` |
| 顶层 `rdp` | 1 | 搬入 `layers[].rdp` |
| 顶层地址/端口 | 0 | 地址入 `layers[].ip`，端口入 `layers[].tcp` |
| `strategy_fc` | 0 | 框架级 flow_control |

目标完整例：
```json
{"layers":[{"ip":{"src":"192.0.2.1","dst":"192.0.2.2"}},{"tcp":{"src_port":40000,"dst_port":3389}},{"rdp":{"security_layer":"standard","client_name":"WINCLIENT","desktop_width":1920,"desktop_height":1080,"channels":[{"name":"cliprdr"}],"data_events":[{"type":"fastpath_input_keyboard"}],"server_responses":[{"type":"bitmap_update"}]}}],"flow_control":{"flows":1}}
```

### §3 强制展开：五件套

会话表：s1 = 一个四元组 TCP/3389，单向 client/server；事务序列 t1 TCP/X.224、t2 MCS、t3 security/info/license、t4 capabilities、t5 active events、t6 shutdown。关联关系：无父子/派生流（RDP 虚拟 channel 是同一 TCP 流内逻辑 channel）。插入位置：`tcp` 之后的 terminal `rdp`。时间线：TCP handshake→CR/CC→MCS→Join→security/info/license/capability→events/responses→shutdown/disconnect→FIN。

### §12 强制展开：动态字段

四元组 `ip.src/dst`、`tcp.src_port/dst_port` 由框架策略处理；RDP `client_name`、Cookie、desktop、channels、data payload、server response 等业务字段当前没有 `rdp` 动态 allowlist，不能声称支持 fixed/inc/rand/list/pattern 的逐流展开。事件序号是配置切片顺序（`Generate` 的 `for range`：`layer_gen.go:207-235`），Channel ID 是 `1004+i`（`layer_gen.go:130-147`）；无随机业务序号。

## 10. 修订记录

- v1.2.0（2026-10-01）：静态校准为 1 正例 + 8 个严格双键负例，补齐真实 planner/layer validator 锚词、D/T/C 负例状态与执行边界；未运行 suite/PCAP/NIC。
- v1.1.0（2026-09-30，P4 层迁移定稿）：唯一存量 case 改为严格 `[tcp,rdp]` 层链。

# #99 ldp（标签分发协议，Label Distribution Protocol）设计契约

> 版本：v1.0.1（P-PIPE 文档轨 P1–P3；v1.0.1 补结果文档过期登记 G-LDP-8）
> 日期：2026-09-28
> 车道：A 文档轨（Lane A，#99 ldp 续号）
> 旧基线：`docs/protocol-designs/41-ldp-design.md` v1.0.0 + `41-ldp-testcase.md` v1.0.0（25 例 = 14 正 + 11 负）
> 存量用例：`trafficgen/test/protocol_pcap/cases/ldp.json`（25/25 ID 与 41 版一致、顺序一致，已机读实测；**现状=违规过渡形：非负例顶层残留 70 处（顶层 ldp 子映射 + 顶层四元组与 layers 并存），合规层链形待代码阶段收敛，G-LDP-1/G-LDP-3**）
> 规范基线：① RFC 5036（LDP Specification）；② RFC 5036 §3.4/§3.5（IPv4 FEC 语义）；③ 本仓库落码（`internal/protocol/ldp/` 四文件 + 接线 6 处，§11.1）；④ 本机 tshark 实测（**ldp dissector 在册，262 个 `ldp.*` 字段**，实测）；⑤ 旧基线设计文档（内部契约，非外部规范）
> 白话一句：**路由器之间互相打招呼、对暗号、然后互相报"哪个网段用哪个标签"的一套话术；引擎里它是一层薄皮——把配置里写好的一串话术按顺序编成字节，握手和挥手交给 TCP，发现用的 Hello 交给 UDP。**

## 0. 41→99 沿革与旧稿过期声明校正（门1 必答：基线继承关系）

本 #99 与旧稿 `41-ldp-*` 是**同一协议的重做契约**，不是新协议。旧稿保留在磁盘只读参考，本契约逐条校正旧稿已过时的状态声明：

| # | 旧稿说法（41-*） | HEAD 实测（2026-09-28） | 校正结论 |
|---|---|---|---|
| 1 | "`ldp` 层尚未注册，不宣称当前 MCP 套件或 PCAP 用例可运行"（design §5 头注、testcase §8） | `registry.go:1383` 已注册 `ldp`（`CategoryTerminal`、`DependsOn ["udp"]`、`TransportOn ["udp","tcp"]`、**无 Fields**）；`internal/protocol/ldp/` 四文件已落码（`builder.go` 537 行、`layer_gen.go` 213、`planner.go` 145、`ldp_test.go` 699，`wc -l` 实测）；51 个 `Test*`（`grep -c` 实测）；`main.go:100` 空导入 + `:548` `NewChainPlanner("ldp")` | "尚未注册/不可运行"已过时；本契约 §11 为 as-built 逆向定稿 |
| 2 | 旧稿 spec_json 样例全部顶层扁平键（design §2 样例：`src_ip/dst_ip/src_port/dst_port` + 顶层 `ldp`） | 存量 25/25 例为**判死形状**（顶层协议子映射 + 顶层四元组与 `layers` 并存）：非负例顶层残留 **70 处**（14 正例 × 5 键 `src_ip/dst_ip/src_port/dst_port/ldp`），全体残留 **121 处**（N1 只带 `ldp`，10 负例 × 5 + 1）；逐键例数 `src_ip` 24 / `dst_ip` 24 / `src_port` 24 / `dst_port` 24 / `ldp` 25（机读实测） | 旧样例形 = **违规过渡形**（§1.4/§1.5/§1.11/§1.13 判死）；合规层链形**需代码阶段先补**（G-LDP-1）后方可改写例；本契约 §2 样例只给纯层链形 |
| 3 | 旧稿称"配置经 flat 键携带"（隐含层内无键可行） | `chain_planner_translate.go:756` 对 ldp **只建空配置**（`if term.Name=="ldp" && spec.LDP==nil { spec.LDP = &core.LDPConfig{} }`），**不**像 bgp(`:747`)/pim(`:780`)/moxa(`:3304`) 那样 JSON 往返严格解码层内 config | 层内化**未做**——registry 无 `Fields` + translate 无解码分支，层内 `events`/`carrier` 今日无处可住 → G-LDP-1 |
| 4 | 旧稿 §7 称"25 个闭环用例" | 存量 JSON 25/25 ID 与 41 版一致、顺序一致；14 正例 `packet_count` 全符合 `3+N+4`（9/11/10/10/10/11/11/10/1/2/10/11/22/12，机读实测）；11 负例 `expect` 键严格 `{expect_error,error_contains}` | 计数与 ID 继承有效；**但用例形状是过渡态**（校正项 2） |
| 5 | 旧稿 §3.2/§3.6 声明的 tshark 字段 | `tshark -G fields` 实测 `ldp.*` 字段 **262 个**，旧稿点名的 `ldp.hdr.version/pdu_len/ldpid.lsr/ldpid.lsid`、`ldp.msg.ubit/type/len/id`、`ldp.msg.tlv.type/len/value`、`ldp.msg.tlv.hello.hold/targeted`、`ldp.msg.tlv.addrl.addr_family/addr`、`ldp.msg.tlv.ipv4.taddr` 全部在册 | 字段面声明**有效**，非臆造；本契约 §3 沿用 |
| 6 | 旧稿 §6 错误表 11 行锚词 | 逐条对码实测（见 §7 表"代码出处"列）：11/11 全部命中代码字面值 | 锚词继承有效 |
| 7 | 旧稿 design:6 / testcase:7 引用 `docs/protocol-designs/audit/41-ldp-adversarial-audit.md` | **该目录不存在**（`ls` 实测 `No such file or directory`） | 死引用；本契约不引用该路径 |

**产物过期登记（重要）**：`trafficgen/docs/protocol-pcap-test/ldp.md` 写 "Cases: 25 — pass 25, fail 0, error 0"，但该文件末次提交 `91f2487`（2026-08-30），**早于**判死提交 `0417be5`（2026-09-13）两周；`cases/ldp.json` 末改 `ed62038`（2026-08-30）同日；`docs/protocol-pcap-test/ldp/` 目录**不存在**（`ls` 实测 `No such file or directory`，0 个 pcap 文件，表内 14 个 `[pcap](ldp/*.pcap)` 链接全为死链）。**该结果文档是过期产物，25/25 pass 不代表今日可跑**——读者不得据此判断套件可用。

**ldp 特例（与 pcep 的关键差异，须一并登记）**：pcep 存量 24 例今日 create 400 全红但**离线 suite 已接入**（`chainSuiteProtos` 含 pcep），去五键即可复跑；**ldp 两处皆红**——① 今日经 MCP 建策略**24/25 例 400**（`CheckProtoFlat` 五键循环 `strategy_convert.go:8632` 命中顶层四元组；唯一例外 `ldp_neg_carrier` 不带五键，create 通过但任务期 `ldp: unknown carrier "raw"` 失败，锚词 `carrier` 命中），② ldp **从未接入离线 suite**——`chainSuiteProtos`（`layer_chain_suite_test.go:70-78`）与空白导入块（`:43-63`，含块注释 `:43` 与右括号 `:63`；导入行 `:44-62`）均无 ldp，实跑 `CHAIN_PROTO=ldp go test -run TestLayerChainSuite ./test/protocol_pcap/` → **FAIL，25/25 全红**（14 正例 + 11 负例），错因 `layers: generator not implemented for layer "ldp"`。故这份「25/25 pass」**不代表今日可跑**，且**连"去五键即可用"的 pcep 式低成本解封路径也不存在**——须先补 G-LDP-1（registry `Fields` + translate 解码分支）并接入离线 suite。

**依赖链判定纪律**：以上均为可判题（旧文→代码→用例三级对照），直接判定，不问偏好。

## 1. 范围、证据等级与 profile 边界

LDP（Label Distribution Protocol，标签分发协议）控制 MPLS（多协议标签交换）标签绑定。RFC 5036 将发现和会话分开：基本发现使用 UDP/646 Hello；LDP session（会话）使用 TCP/646。Hello 的目的地址、TTL 或 GTSM（广义 TTL 安全机制）策略不在本版伪造为单一固定值；每个用例明确载体、方向和端口。

| 证据等级 | 本版固定 | 不在本版声称 |
|---|---|---|
| UDP discovery（发现） | UDP/646、Hello 的 LDP PDU/common header（公共头）和 Hello Common Parameters（Hello 公共参数） | 真实多播邻居发现、TTL/GTSM 的部署策略 |
| TCP session | TCP/646、三次握手、LDP PDU 公共头、Initialization、KeepAlive、Address、Label Mapping/Request/Withdraw/Release、Notification | TCP MD5/AO、TLS、真实 LSP（标签交换路径）转发 |
| FEC（转发等价类） | IPv4 Prefix FEC、/24 与 /32 host route（主机路由） | IPv6 FEC、VPN/VC/PW FEC、流量工程扩展 |
| label（标签） | Generic Label TLV（通用标签 TLV（类型-长度-值））20-bit 范围 0–1048575；显式边界值 | 由平台保留/特殊标签的转发语义 |
| 地址族 | IPv4 transport 与 IPv4 FEC；IPv6 transport/profile 未定义则拒绝 | 不把 IPv6 outer IP（外层 IP）或 IPv6 TLV 假装成 RFC 5036 IPv4 profile |

`ldp_rfc5036_ipv4_basic` 是本版唯一正向 profile。IPv6 transport/profile 的负例必须独立拒绝，不能因为 LDP common header 相同而混入 IPv4 profile。未知消息、TLV 或 malformed（畸形）输入只作为拒绝契约，不是成功 PCAP。

**实现状态（2026-09-28 实测，与旧稿"尚未注册"已不同）**：`ldp` 层已注册（`registry.go:1383`）、planner/validator/生成器已落码（`internal/protocol/ldp/` 四文件共 1594 行）、`allowedProtocols["ldp"]=true`（`protocols.go:46`）、25 语义用例已落 `cases/ldp.json`。旧稿"代码未写"描述已过时（§0 表）。

**但协议侧未达符合态**：层是空壳（registry 无 `Fields`、translate 无 `case "ldp"` 解码分支），配置只能住顶层 `ldp` 子映射；25 例因此全部违反 §1.13 白名单制（非负例顶层残留 70 处）。合规层链形**须代码阶段先补**（G-LDP-1），当前不宣称符合。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`ldp.*` 字段 + `tcp.srcport/dstport` + `udp.srcport/dstport` + offset 42/54 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

## 2. 层链、载体、方向与配置

UDP discovery 层链为 `ip → udp → ldp`，TCP session 层链为 `ip → tcp → ldp`。IPv4 正例显式给出 `ip.src`/`ip.dst`、方向和端口：Hello 的源/目的端口均为 646；TCP 的客户端临时源端口为 50000、对端目的端口为 646，反向报文为 646→50000。端口不是"协议推断"的替代物，正例仍需写正确层链。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers` + `flow_control`；**目标形状声明**：registry `ldp` Fields 今日为空，层内 `events`/`carrier` 键今日无处可住，故此形**今天跑不通，需先补代码** G-LDP-1，§1.9 口径）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.1", "dst": "192.0.2.2"}},
    {"tcp": {"src_port": 50000, "dst_port": 646}},
    {"ldp": {"wire_profile": "ldp_rfc5036_ipv4_basic", "carrier": "tcp_session",
             "events": [{"kind": "initialization", "direction": "c2s", "message_id": 10}]}}
  ],
  "flow_control": {"flows": 1}
}
```

UDP discovery 目标形状（`[ip,udp,ldp]`）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.1", "dst": "192.0.2.2"}},
    {"udp": {"src_port": 646, "dst_port": 646}},
    {"ldp": {"wire_profile": "ldp_rfc5036_ipv4_basic", "carrier": "udp_discovery",
             "events": [{"kind": "hello", "direction": "c2s", "hold_time": 15, "targeted": true}]}}
  ],
  "flow_control": {"flows": 1}
}
```

**配置键表（as-built 逆向定稿；键数口径 = 脚本复算，禁手算）**

承载分两层：`LDPConfig` **14 键**（`types.go:544-559`，`json` tag 实测）+ `LDPEvent` **13 键**（`types.go:585-599`）；另有 `LDPSession` 4 键、`LDPAdjacency` 8 键（嵌套结构，见 §12.3）。

| 配置键 | 承载 | 落码状态 | 约束 | 语义 |
|---|---|---|---|---|
| `transport` | config | 已落码 | `udp`/`tcp` | 载体选择（与 `carrier` 并存，后者为事件模型） |
| `wire_profile` | config | 已落码 | 正例固定 `ldp_rfc5036_ipv4_basic` | IPv4 LDP RFC 5036 基础线格式；未知/IPv6 profile 拒绝 |
| `carrier` | config | 已落码 | `udp_discovery`/`tcp_session`/`dual_adjacency` | 载体和 packet 计数模型 |
| `events` | config | 已落码 | 数组，顺序显式 | 事件序列（kind 见下） |
| `sessions` | config | 已落码 | 独立会话数组 | 多 session/parallel neighbors 按 TCP 四元组隔离 |
| `adjacencies` | config | 已落码 | 独立邻接数组 | dual_adjacency 混合载体三元素（basic/targeted/session） |
| `lsr_id` | config | 已落码 | IPv4 地址 | LDP Identifier 的 LSR ID |
| `label_space` | config | 已落码 | 0–65535 | LDP Identifier 的 Label Space ID |
| `hold_time` | config | 已落码 | 0–65535 秒 | Hello Common Parameters 的 Hold Time |
| `targeted` | config | 已落码 | 布尔 | Hello targeted bit |
| `keepalive_time` | config | 已落码 | 1–65535 秒 | Common Session Parameters 的 KeepAlive Time |
| `label_control` | config | **字段在、无消费** | `independent`/`ordered` | `types.go:556` 有字段，但 `grep -rn LabelControl internal/protocol/ldp/` **零命中**——**不校验、不影响行为** |
| `label_advertisement` | config | 已落码 | `downstream_unsolicited`/`downstream_on_demand` | 下游标签分发纪律（DU/DoD）；非法值拒（`builder.go:486`） |
| `fault_kind` | config | 已落码 | 6 种合法值 | `pdu_length`/`message_length`/`tlv_length`/`label_bounds`/`unknown_message`/`checksum`；未知值拒（`builder.go:326`） |
| `kind` | event | 已落码 | 9 种合法值 | `hello`/`initialization`/`keepalive`/`address`/`label_mapping`/`label_request`/`label_withdraw`/`label_release`/`notification`；未知值拒（`builder.go:503` `unknown kind`） |
| `direction` | event | 已落码 | `c2s`/`s2c` | 应用事件方向；UDP Hello 也必须明确 |
| `message_id` | event | 已落码 | uint32 | Message ID |
| `lsr_id` / `receiver_lsr_id` | event | 已落码 | IPv4 地址 | 本端/对端 LSR ID（Initialization） |
| `hold_time` / `keepalive_time` | event | 已落码 | 见上 | 事件级覆盖 config 级 |
| `targeted` | event | 已落码 | 布尔 | 事件级 Hello 标记 |
| `fec` | event | 已落码 | 字符串 CIDR | IPv4 Prefix FEC；`/len > 32` 由 `resolveFEC` 拒（`builder.go:309`） |
| `prefix_length` | event | **字段在、无范围校验** | uint8 | `types.go` 有字段，但**无 0–32 校验**；越界靠 `fec` 字符串后缀路径拒绝 |
| `label` | event | 已落码 | 0–1048575 | Generic Label；>20-bit 拒（`builder.go:520`） |
| `addresses` | event | 已落码 | IPv4 地址数组 | Address List TLV 载荷 |
| `status_code` | event | 已落码 | uint32 | Notification Status Data |

**规范要求面 ≠ as-built 面（三键未落码，显式标注）**：

| 键 | 状态 | 说明 |
|---|---|---|
| `version` | **未落码（目标形状）** | `LDPConfig`/`LDPEvent` 均无此字段；版本为 builder 内部常量 `ldpVersion = 1`（`builder.go:15`）。RFC 5036 基础 profile 恒 1，故无配置面需求 |
| `hello_requested` | **未落码（目标形状）** | 全仓 `grep -rn hello_requested\|HelloRequested internal/` = **0 命中**；RFC 5036 §3.5.2 Hello 有 R bit，代码未实现 |
| `label_control` | **未落码（见上表）** | 字段在但零消费 |

**静默丢弃风险（实测）**：`version`/`hello_requested` 经 `MapToFlowSpec` 传入时**不报错**——`parseSubconfigJSON` 用裸 `json.Unmarshal`（无 `DisallowUnknownFields`，`strategy_convert_helpers.go:21-30`），未知键被静默丢弃（`validationErrors=[]`）。同机制导致 N7 事件内嵌套 `fault_kind`/`value` 键被丢弃（§6 N7 注）。

Initialization 的 Common Session Parameters TLV 必须携带协议版本、KeepAlive Time、标签分发纪律、Loop Detection（环路检测）位、Path Vector Limit（路径向量上限）、Max PDU Length、Receiver LSR Identifier 和 Receiver Label Space Identifier。无配置的 capability（能力）不自动添加。

## 3. RFC 5036 线格式

### 3.1 PDU common header（公共头）

每个 LDP PDU（协议数据单元）以 10 字节公共头开始：

```text
Version (2) | PDU Length (2) | LSR ID (4) | Label Space ID (2)
```

Version 在 RFC 5036 基础 profile 为 1；PDU Length 是后续 PDU（不含 Version、PDU Length 本身）的字节数，按实际编码回填。LSR ID 为 IPv4 地址，Label Space ID 为无符号 16-bit。Wireshark（网络分析器）已注册可使用字段：`ldp.hdr.version`、`ldp.hdr.pdu_len`、`ldp.hdr.ldpid.lsr`、`ldp.hdr.ldpid.lsid`。

### 3.2 Message header（消息头）与 TLV

每个消息为 `U bit + Message Type (15 bits) | Message Length (2) | Message ID (4) | Parameters`。Message Length 不含 4 字节 Type/Length，但含 Message ID 和参数；类型未知且 U=0 必须产生 Notification/错误或使输入拒绝，本设计的 unknown message 负例统一在 planner/validator 拒绝。TLV 为 `U/ F bits + Type (14 bits) | Length (2) | Value`，TLV Length 只计算 Value，不含 4 字节 TLV 头。

本机 tshark 注册并允许出现在正例断言的字段为：`ldp.msg.ubit`、`ldp.msg.type`、`ldp.msg.len`、`ldp.msg.id`、`ldp.msg.tlv.type`、`ldp.msg.tlv.len`、`ldp.msg.tlv.value`，以及下列具体 TLV 字段。设计和 JSON 不使用未在本机注册的 nested（嵌套）字段。

**消息类型与 TLV 类型常量（as-built，`builder.go:27-46` 实测）**：

| 常量 | 值 | 常量 | 值 |
|---|---|---|---|
| `msgNotification` | 0x0001 | `tlvFEC` | 0x0100 |
| `msgHello` | 0x0100 | `tlvAddressList` | 0x0101 |
| `msgInitialization` | 0x0200 | `tlvGenericLabel` | 0x0200 |
| `msgKeepAlive` | 0x0201 | `tlvStatus` | 0x0300 |
| `msgAddress` | 0x0300 | `tlvHelloParams` | 0x0400 |
| `msgLabelMapping` | 0x0400 | `tlvSessionParams` | 0x0500 |
| `msgLabelRequest` | 0x0401 | `tlvTransportAddress` | 0x0401 |
| `msgLabelWithdraw` | 0x0402 | — | — |
| `msgLabelRelease` | 0x0403 | — | — |

### 3.3 Discovery Hello

Hello 消息类型为 0x0100。Hello Common Parameters TLV 类型为 0x0400，Value 为 Hold Time、Targeted/Requested/GTSM bits 和保留位；Transport Address TLV（0x0401）可声明 IPv4 transport address（运输地址），本版用 IPv4 地址。UDP/646 discovery 每条独立 PDU，方向由 UDP 四元组表示；targeted Hello 使用点对点目的地址，不把它写成基本多播发现。

### 3.4 Initialization 与 KeepAlive

Initialization 消息类型为 0x0200；其 Common Session Parameters TLV 类型为 0x0500，Value **14 字节**，字段包括 Session Protocol Version、Session KeepAlive Time、Label Advertisement Discipline、Loop Detection、Path Vector Limit、Max PDU Length、Receiver LSR/Label Space（`builder.go:126` 实测 14 字节 Value）。KeepAlive 消息类型为 0x0201，参数为空。TCP session 只有三次握手后才发送 LDP application（应用）事件；初始化通常为双向各一条，再由 KeepAlive 双向确认，但本版不自动填充未配置事件。

### 3.5 Address

Address 消息类型为 0x0300；Address List TLV 类型为 0x0101，Value 为 Address Family（地址族）和 IPv4 地址列表。正例只使用 Address Family IPv4=1。Wireshark 字段为 `ldp.msg.tlv.addrl.addr_family` 与 `ldp.msg.tlv.addrl.addr`。

### 3.6 Label Mapping、Request、Withdraw、Release

四类消息类型依次为：Label Mapping 0x0400、Label Request 0x0401、Label Withdraw 0x0402、Label Release 0x0403。IPv4 Prefix FEC TLV 使用 type=0x0100，其 Value 为 FEC Element Type=2、Address Family=1、prefix length 和 `ceil(prefix length/8)` 个前缀字节。/32 host route 仍是 Prefix FEC 的 prefix length=32，不另造 IPv4 host TLV。

Label Mapping 在 FEC TLV 后携带 Generic Label TLV type=0x0200，Label Request 只需 FEC。Withdraw/Release 的事件必须显式给出 FEC；若携带 label，断言 label 与原绑定一致。Label 只占 20-bit 有效值，线上的 Generic Label Value 为 32-bit 字段但高 12 bits 必须为零；常规范围和边界 0、1048575 纳入测试。

`independent` control（独立控制）允许先发送 Mapping，再收到 Request；`ordered` control（有序控制）要求先有上游/下游可达或请求状态，具体响应由实现 profile 定义。`downstream_unsolicited` 与 `downstream_on_demand` 必须在 Initialization 语义中可观察；不能把 DU 与 DoD 互换。基础 profile 不自动生成对端响应或标签分配。

### 3.7 Notification

Notification 消息类型为 0x0001，携带 Status TLV type=0x0300；Status Data 由 E/F bits 与 Status Code 构成，可用已定义的 No Error/Shutdown 等 RFC 5036 状态。Notification 是合法会话事件；未知消息、非法长度和非法标签输入则是 planner/validator 错误，不应以空 PCAP 成功结束。

## 4. 会话、邻接和状态约束

```text
UDP/646 Hello（basic 或 targeted discovery）
              ↓
TCP/646 connect
              ↓
Initialization（双方）→ KeepAlive（双方）
              ↓
Address / Label Request / Mapping / Withdraw / Release
              ↓
Notification（可选）或 TCP FIN
```

- UDP Hello 和 TCP session 是两种不同载体；不能用 UDP packet 代替 TCP 握手，也不能把 TCP PDU 当 discovery。
- 一条 TCP session 按四元组和 LDP Identifier 隔离；两个 parallel neighbors 可以共享目的端口 646，但源临时端口或 LSR ID 必须不同。
- `targeted=true` 只改变 Hello 的目标/标记语义；它不自动建立第二条 TCP session。
- Initialization 两方向完成后才允许 KeepAlive、Address 和标签消息；Notification 可作为最后事件。**as-built 偏差**：该状态约束**仅 KeepAlive 已落码**（`builder.go:530`）；Address/标签消息的 init 前置守卫**未实现**（实跑 `ValidateConfig` 对 address/label_* before init 返回 `<nil>`）——本条为**目标形状**（G-LDP-7），实现与用例按 §11.2 T3 列登记。
- Label Mapping/Request/Withdraw/Release 的 FEC 必须在 IPv4 profile 内，/0–/32 边界合法；IPv6 前缀不是 IPv4 FEC 的替代写法。
- 所有 PDU/message/TLV length 按编码后实际长度回填；声明长度与边界不一致必须拒绝。
- 各事件方向必须在同一 session 的 transport 上编码；不要把一个方向的 LSR ID 或 label space 泄漏到另一 session。

**混合载体链（as-built，`chain_planner_util.go:64`）**：`isCarrierMixedChain` 判定——ldp 且链中**无**用户显式 `tcp` 层时走自产完整包路径（UDP Hello 与 TCP 会话混合，生成器自设 L3/L4/Payload）；用户显式写 `tcp` 层则走 plain event path（TCP 语义交 tcp 层）。该分支仅当 `spec.LDP.Adjacencies` 非空时激活（`chain_planner.go:1390`）。

## 5. Checksum、长度与传输断言

LDP 自身不定义独立 checksum；TCP/UDP checksum 属于传输层伪首部校验，IPv4 header checksum 属于 IP 层。正例可断言已注册的 `ip.proto`、`tcp.srcport`/`tcp.dstport`、`udp.srcport`/`udp.dstport`、`tcp.checksum` 或 `udp.checksum` 存在/非零（具体验证器是否呈现校验状态由 output backend（输出后端）决定），不能把"LDP checksum"写进协议字段。

IPv4 TCP application payload offset（载荷偏移）在无额外 option 时为 Ethernet 14 + IPv4 20 + TCP 20 = 54；UDP LDP payload offset 为 Ethernet 14 + IPv4 20 + UDP 8 = 42。固定 offset 仅用于未分段 frame（帧）；TCP MSS 分段必须按 stream 重组后检查，packet_count 计实际 segment。

在本版建议的无额外 TCP option、每个应用事件单独一个 segment 模型中：

- UDP 每个 Hello PDU 为 1 packet。
- TCP 每个 session 的 packet_count = 3（SYN/SYN-ACK/ACK）+ 应用事件数 + 4（FIN 终止）。
- 多 session 先按 session 求和，不假定调度交织顺序。

**存量实测符合度（机读 2026-09-28）**：14 正例 packet_count = `[9,11,10,10,10,11,11,10,1,2,10,11,22,12]`，逐例验证符合上式——S13 多 session 22 = 2×11（每 session 4 事件 → 3+4+4）；S14 dual_adjacency 12 = 2（UDP Hello）+ 10（TCP 3+3+4）。

## 6. 错误处理

| # | 输入故障 | 必须拒绝 | 稳定关键词 | 代码出处 |
|---|---|---|---|---|
| N1 | `ldp` 终结层缺 TCP/UDP 或 carrier 不匹配 | LDP 只允许本版明确载体 | `carrier` | `builder.go:458` `unknown carrier %q` |
| N2 | UDP 非 646 或 TCP 非 646 | 端口不满足 RFC 5036 | `port` | `planner.go:29` `udp_discovery source port must be 646` |
| N3 | 未定义 IPv6 transport/profile | 不能混用 IPv4 FEC/profile | `profile` | `planner.go:37/39` |
| N4 | PDU Length 与实际 PDU 不一致/超出 | PDU 边界非法 | `pdu` | `builder.go:325` `fault injection "pdu_length"` |
| N5 | Message Length 与消息 body 不一致 | message 边界非法 | `message` | 同上 `"message_length"` |
| N6 | TLV Length 与 Value 不一致 | TLV 边界非法 | `tlv` | 同上 `"tlv_length"` |
| N7 | unknown Message Type（未知消息类型） | 不能伪造基础 profile 语义 | `unknown` | **实测走两条独立路径**：① config 级 `fault_kind="unknown_message"` → `builder.go:326` `fault injection "unknown_message"`；② **存量用例实际走事件 kind 路径**——`events[2] = {kind:"wire_fault"}`（`wire_fault` **不在 9 项合法 kind 内**）→ `builder.go:503` `event 2: unknown kind "wire_fault"`。事件内嵌套的 `fault_kind`/`value` 键**被静默丢弃**（`LDPEvent` 无此 json 键 + 裸 `json.Unmarshal`，见 §2 末）。**N8/N9 路径不同**：二者均为**合法 kind + 越界值**——N8 走 `builder.go:520` label 20-bit 范围守卫（`label exceeds 20-bit bound`，前置 `:512` 先 `resolveFEC`），N9 走 `builder.go:309` `resolveFEC` 的 FEC 前缀长度守卫（`FEC prefix length %d out of range (max 32)`）；`label_bounds` 只是 `CheckFault` 的 config 级合法 kind（`builder.go:325`），`prefix_bounds` **不是** `CheckFault` 认的标识符（全库 `grep -rn prefix_bounds internal/` 仅命中测试注释） |
| N8 | Generic Label 高位非零或 >1048575 | 20-bit label 越界 | `label` | 同上 `"label_bounds"` + `builder.go:520` `label exceeds 20-bit bound` |
| N9 | FEC prefix length <0 或 >32 | IPv4 Prefix FEC 越界 | `prefix` | `builder.go:309` `FEC prefix length %d out of range (max 32)` |
| N10 | Initialization 前发送 KeepAlive/Address/label | 会话状态错误 | `state` | `builder.go:530` `keepalive before initialization (invalid session state)` |
| N11 | UDP transport checksum 故障 | checksum 注入被识别并拒绝 | `checksum` | `builder.go:325` `fault injection "checksum"` |

错误必须由 planner/validator 传播到 task error（任务错误）终态，不得报告 completed with 0 packets（完成但 0 包）。负例 `expect` 不对失败 PCAP、packet count 或字段作断言。

**其他已落码拒绝分支（今日无对应用例 → A′ 候选）**：`builder.go:446-537`（`ValidateConfig` 全体）另有 `ldp: config is required`、`at least one event required`、`session %d has no events`、`adjacency %d unknown kind %q`、`adjacency %d (session) has no events`、`adjacency %d unknown carrier %q`、`unknown label advertisement %q`、`event %d: kind is required`、`event %d: direction must be c2s or s2c`、`event %d: unknown kind %q`、`event %d: FEC is required for %s`、`event %d: label is required for label_mapping`、`unknown fault kind %q`。

## 7. 场景、包数与实现完成定义

四件套 ID 顺序闭环如下（顺序为权威，= JSON 顺序）：

`ldp_tcp_initialization`、`ldp_tcp_keepalive`、`ldp_address_ipv4`、`ldp_label_mapping_ipv4`、`ldp_label_request_ipv4`、`ldp_label_withdraw_ipv4`、`ldp_label_release_ipv4`、`ldp_label_mapping_host32`、`ldp_udp_targeted_hello`、`ldp_udp_parallel_hellos`、`ldp_notification_shutdown`、`ldp_ordered_dod_allocation`、`ldp_tcp_multi_session`、`ldp_dual_adjacency`、`ldp_neg_carrier`、`ldp_neg_port`、`ldp_neg_ipv6_profile`、`ldp_neg_pdu_length`、`ldp_neg_message_length`、`ldp_neg_tlv_length`、`ldp_neg_unknown_message`、`ldp_neg_label_bounds`、`ldp_neg_prefix_bounds`、`ldp_neg_state`、`ldp_neg_checksum`。

本套件使用 25 个唯一 ID，顺序为 14 个正例 `S1–S14` 后 11 个负例 `N1–N11`。正例分别覆盖 basic/targeted Hello、Initialization 参数、KeepAlive、Address、四种标签消息、/32、双 session、双 adjacency 和 Notification；负例覆盖载体/端口/profile/各级长度/unknown message/label/FEC/state/checksum。每个正例在 testcase 与 JSON 中保持相同 packet_count、fields、frames；负例严格只有 `expect_error` 和 `error_contains`。

后续实现完成定义：注册 UDP/TCP→LDP 终结层；实现 common header、Hello/Initialization/KeepAlive/Address/label 消息/Notification；完成 IPv4 Prefix FEC /0–/32、20-bit label、DU/DoD 与 independent/ordered 配置验证；对两种载体、方向、TCP 多 session、targeted Hello 和 transport/profile 边界写集成测试；验证长度/状态/错误传播和 checksum 由真实 output 观察。IPv6 profile、VPN/VC FEC、capability、TCP MD5/AO、真实邻居发现和 MPLS forwarding 均明确待实现。

## 8. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置是剧本（`events[]` 逐条声明方向与内容），引擎按序产出 PDU，TCP/UDP 层承担传输语义。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 邻居发现（basic） | UDP/646 双向 Hello | S10（`ldp_udp_parallel_hellos`） |
| ② 定向邻居（targeted） | UDP/646 单条 targeted Hello | S9（`ldp_udp_targeted_hello`） |
| ③ 会话建立 | TCP 握手 → 双向 Initialization → KeepAlive | S1/S2 |
| ④ 地址通告 | Initialization 后 Address List | S3 |
| ⑤ 标签分发（DU） | Mapping / Request / Withdraw / Release | S4/S5/S6/S7/S8 |
| ⑥ 有序 + DoD | Request → Mapping（按需） | S12 |
| ⑦ 会话拆除 | Notification/Shutdown → TCP FIN | S11 |
| ⑧ 多邻居并行 | 两条独立 TCP session | S13 |
| ⑨ 双邻接并存 | basic + targeted UDP + TCP session | S14 |

**五层覆盖逐层结论**：功能层——9 种消息类型各有正例（Hello/Initialization/KeepAlive/Address/Mapping/Request/Withdraw/Release/Notification 全覆盖）+ 拒绝分支 11 类负例；性能层——多 session 22 包（S13）、双邻接混合载体 12 包（S14）、单包最小面（S9 = 1 包）；数据场景层——label 0x12345/0xABCDE、FEC /24 与 /32、Hold Time 15、Address Family=1、Status Data 0x0000000A；地址与流——**仅 IPv4**（IPv6 为负例 N3，协议本身 RFC 5036 基础 profile 不含 IPv6，显式声明非缺口）、单流基线（S1）、多会话（S13）；**流关联（控制流派生数据流）显式不适用**：LDP 无派生数据流，标签分发本身即控制面；**多流（会话内并发流）显式不适用**：一条 TCP session 承载一条事件序列。业务层——多会话（S13）+ 双邻接（S14）+ 多事务（S4–S7 各自「Mapping → 后续操作」两事务序列）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① TCP MD5/AO 签名（RFC 5925，本版不生成）；② GTSM TTL 策略（部署策略，非线格式）；③ 真实 LSP 转发（本版只做控制面）；④ `independent` control 的自动响应（基础 profile 不自动生成对端响应，§3.6 已声明）。

## 9. 消息/事务模型与状态机

**事务定义**：一条 session 内一次完整的应用事件交互。**多事务** = 一条 session 内多事件按序执行：S1（c2s/s2c 双向 Initialization 两事务）、S4（Initialization + Mapping）、S6（Mapping → Withdraw 两事务依赖）。

| 状态（tcp 层拥有） | ldp 层动作 | 用例 |
|---|---|---|
| `CLOSED` | 无（UDP Hello 不经 tcp 状态机） | S9/S10 |
| `ESTABLISHED`（握手后） | Initialization 事件 → 0x0200 PDU；KeepAlive → 0x0201；Address → 0x0300；label 四消息 → 0x04xx；Notification → 0x0001 | S1–S8, S11, S12 |
| 终止（FIN 四包） | 事件流关闭 → tcp 层挥手 | 全 TCP 正例 |

**状态约束（as-built `builder.go:530`）**：Initialization 之前出现 **KeepAlive** → 拒绝 `keepalive before initialization (invalid session state)`（N10）。**仅此一条已落码**；Address/标签消息的 init 前置守卫未实现（G-LDP-7，§4/§11.2 T3 列）。

**自动派生规则**：① TCP 握手/FIN 由 tcp 层自动补（事件模式无独立 ACK）；② 空 `events` 且 carrier 为空 → validator 拒 `at least one event required`（**无空配置默认流**，与 moxa 的单块 "hello" 默认不同）；③ 无配置的 capability 不自动添加（§2 末）。

**多会话展开**：`sessions[]` 数组**整块**顺序回放（每 session 3+N+4，包号起点 = 前 session 总包数 + 1，§5 术语表口径）；S13 = 2 session × 11 包 = 22。**dual_adjacency 混合载体**由 `isCarrierMixedChain` 分支自产完整包（§4），不走 plain event path。

## 10. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流全链 ≤22 包（S13 两 session 之和，最大）；单 session 最大 11 包（4 事件）；UDP 单包最小面（S9 = 1 包）；无超 MSS 分片用例（LDP PDU 均为短报文，最大 S1 = 32 字节 PDU，远小于 MSS）。吞吐数字待 P4 基准，**本版不写承诺**（§6.5）。
- **依据**：事件序列流式展开（`parseLDPEvents` 逐事件 `append` payload，`builder.go:348`；planner 逐 PDU emit，无全量收集）；每 PDU 内存 = PDU 长度 + 各层头开销（O(PDU)）；无跨流共享状态；无锁（消息类型/TLV 类型为只读常量 `builder.go:27-46`）。
- **验收两路**：pcap（`/tmp/mcp-pcaps/ldp/`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `ldp.*` 字段序列与帧 hex，不只断言"任务没报错"。
- **六类场景落点**：基线（S1，9 包）/ 目标规模（S13，22 包双 session）/ 压力上限（S14，混合载体 12 包）/ 长时间运行（多 session 整块展开承载）/ 并发交错（顺序多 session 承载语义，并发路径为例外不启用）/ 背压（`packet_count` 精确计数守卫段数漂移）。

## 11. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 11.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | UDP/646 发现 + TCP/646 会话双载体；主站主动建连（RFC 5036 §2.5/§2.7） | 场景①–⑨ | `DependsOn ["udp"]` + `TransportOn ["udp","tcp"]`（`registry.go:1383`）；`isCarrierMixedChain` 混合分支 | 无 |
| 2 | 命令/消息表 | 9 种消息类型（§3 表，`builder.go:27-34` 常量实测） | 场景③–⑨ | `parseLDPEvents` 9 分支（`builder.go:361-414`） | 无 |
| 3 | 状态机 | 握手—初始化—保活—业务—释放（§4/§9） | S1–S8, S11 | tcp 层拥有状态；ldp 层守 `keepalive before initialization`（`builder.go:530`） | 无 |
| 4 | 字段表 | 消息 9 kind + config 14 键 + event 13 键（§2 表；`types.go:544-559`/`:585-599`） | 数据场景层 | builder 直传 + 长度/方向/label/FEC 校验 | 层内化未做（G-LDP-1）；`version`/`hello_requested`/`label_control` 三键未落码 |
| 5 | 错误处理 | 11 类负例（§6 表） | 负例 N1–N11 | planner/validator 11 种拒绝分支（§6 代码出处列） | 无（锚词已钉死 11/11） |
| 6 | 超时与活性 | Hello Hold Time（RFC 5036 §3.5.2）+ KeepAlive Time（§3.5.4）；生成器不模拟超时重传 | S1（KeepAlive Time=30）/ S9（Hold Time=15） | 字段可配（`hold_time`/`keepalive_time`）；无定时器 | **显式不适用**定时器（声明式回放无运行时超时），无缺口 |
| 7 | NAT/代理/被动 | 无被动模式概念（LDP 双向对等，双方均可发起 Hello） | S10（双向 Hello） | 无 NAT 特殊处理 | **显式不适用**被动模式；NAT 穿透为框架面 |
| 8 | 版本/方言 | 唯一 profile `ldp_rfc5036_ipv4_basic`；IPv6 明确不解决（N3） | 正例 14 | `planner.go:36-39` IPv6 拒绝分支 | IPv6 profile 待独立规范 |

### 11.2 子表①：消息类型×传输终态矩阵（逐格已覆/立项/不适用；**适配声明**：LDP 无"响应码"概念——通知类消息（Notification）以 Status TLV 承载状态码，故以「消息类型 × 传输终态」为等价口径，对照 moxa §10.2 适配先例）

| 消息类型 | T1 正常 FIN 终态 | T2 配置拒绝 | T3 状态拒绝（init 前置守卫） |
|---|---|---|---|
| Hello 0x0100 | 已覆（S9/S10） | 已覆（N2 端口/N7 unknown 代表例） | 不适用（UDP 发现无 TCP 状态机；`builder.go` 无 Hello 状态守卫） |
| Initialization 0x0200 | 已覆（S1/S13/S14） | 已覆（N4/N5/N6 长度代表例） | 不适用（init 本身即状态起点，无前置守卫需求） |
| KeepAlive 0x0201 | 已覆（S2） | 已覆（同上代表例） | **已覆（N10 state）**——唯一有 init 守卫者（`builder.go:530`） |
| Address 0x0300 | 已覆（S3） | 已覆（同上代表例） | **A′ 立项**（实测 `ValidateConfig` 对 address-before-init 返回 `<nil>`：**无守卫**；§6 补行） |
| Label Mapping 0x0400 | 已覆（S4/S8/S12） | 已覆（N8 label/N9 prefix） | **A′ 立项**（同上，带 FEC 后仍 `<nil>`） |
| Label Request 0x0401 | 已覆（S5/S12） | 已覆（N9 prefix） | **A′ 立项**（同上） |
| Label Withdraw 0x0402 | 已覆（S6） | 已覆（同上代表例） | **A′ 立项**（同上） |
| Label Release 0x0403 | 已覆（S7） | 已覆（同上代表例） | **A′ 立项**（同上） |
| Notification 0x0001 | 已覆（S11） | 已覆（N7 unknown 代表例） | 不适用（RFC 5036 §3.5.1 Notification 可在任意状态发出，**无 init 前置**） |

**逐格重数**：9 行 × 3 列 = 27 格——已覆 **19** / A′ 立项 **5** / 不适用 **3**，零空格。

**T3 列判定依据（实跑 `ValidateConfig`，脚本输出）**：
```
address before init (with FEC)          -> <nil>      ← 无守卫
label_mapping before init (with FEC)    -> <nil>      ← 无守卫
label_request before init (with FEC)    -> <nil>      ← 无守卫
label_withdraw before init (with FEC)   -> <nil>      ← 无守卫
label_release before init (with FEC)    -> <nil>      ← 无守卫
notification before init (with FEC)     -> <nil>      ← 无守卫（RFC 语义上亦无需）
keepalive before init                   -> ldp: event 0: keepalive before initialization (invalid session state)
```
`builder.go` 内 `seenInit` **仅守卫 `keepalive`**（`:529`）；全包 `grep -rn 'invalid session state'` 只有 `:530` 一处。故 **T3 列只有 KeepAlive 格已覆**，其余 5 格为 A′ 立项（CORE_MEMORY §9.36：不许冒充已覆盖）。同时 **§4 的设计声明**"Initialization 两方向完成后才允许 KeepAlive、Address 和标签消息"**与实现不符**——Address/标签消息的 init 前置守卫**未落码**，该声明属**目标形状**（G-LDP-7）。

### 11.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **18 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | UDP Hello basic（c2s） | 覆（S10 帧 1） |
| 2 | UDP Hello basic（s2c） | 覆（S10 帧 2） |
| 3 | UDP Hello targeted bit=1 | 覆（S9） |
| 4 | UDP 源端口非 646 | 覆（N2） |
| 5 | TCP 目的端口 646 | 覆（全 TCP 正例断言） |
| 6 | TCP 源端口显式 50000/50001 | 覆（S13） |
| 7 | TCP 源端口缺省（保底递增） | A′ 立项（补例 `ldp_default_srcport`：删 `src_port` 只断言补齐行为） |
| 8 | 目的端口缺省（补齐 646） | A′ 立项（补例 `ldp_default_port`：删 `dst_port` 不断言值） |
| 9 | FEC /24（3 前缀字节） | 覆（S4/S5/S6/S7/S12） |
| 10 | FEC /32（4 前缀字节 host route） | 覆（S8） |
| 11 | FEC /0 边界 | A′ 立项（补例 `ldp_fec_prefix0`） |
| 12 | FEC /33 越界 | 覆（N9） |
| 13 | label 0x12345（常规） | 覆（S4/S6/S7/S12） |
| 14 | label 0xABCDE（大值） | 覆（S8） |
| 15 | label 边界 0 | A′ 立项（补例 `ldp_label_min`） |
| 16 | label 边界 1048575 | A′ 立项（补例 `ldp_label_max`） |
| 17 | label >20-bit | 覆（N8） |
| 18 | IPv6 transport/profile | 覆（N3 负例；RFC 5036 基础 profile 不含 IPv6，**显式不适用为正向形态**） |

12 覆 + 5 立项 + 1 不适用 = 18。✓

### 11.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 邻居发现（RFC 5036 §2.4 basic discovery） | S9/S10 | 已覆 |
| 2 | 会话建立与保活（§2.5/§3.5） | S1/S2 | 已覆 |
| 3 | 地址通告（§3.5.5） | S3 | 已覆 |
| 4 | 标签分发 DU（§2.6 downstream unsolicited） | S4/S5/S6/S7/S8 | 已覆 |
| 5 | 标签分发 DoD（§2.6 downstream on demand） | S12 | 已覆 |
| 6 | 有序控制（§2.6 ordered control） | S12 | 已覆 |
| 7 | 会话拆除（§3.5.1 Notification；Unilateral Shutdown 状态码见 §3.5.1.2.4） | S11 | 已覆 |
| 8 | 多邻居并行部署 | S13 | 已覆 |
| 9 | TCP MD5/AO 认证（RFC 5925） | — | **明确不解决**（v1 范围外，§1 显式边界） |
| 10 | GTSM TTL 安全（RFC 5082） | — | **明确不解决**（部署策略，非线格式） |
| 11 | VPN/VC FEC、流量工程扩展（RFC 4447 §5.2/§5.3 PW FEC 元素） | — | **明确不解决**（v1 范围外） |

8 覆 + 3 不适用 = 11。✓无映射无确认即缺口——本表零缺口。

### 11.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：①规范原文（RFC 5036，定"必须是什么"：10 字节公共头 + 消息头 + TLV 三层结构、9 种消息类型、双载体）；②商业化软件实际行为（Cisco IOS/Juniper Junos 的 LDP 实现：Initialization 双向、KeepAlive 保活、DU 为默认分发模式、DoD 需显式配置——本版以 RFC 语义为准，不声称模拟厂商定时器行为）；③可靠开源实现思路（本仓库同族先例：bgp/pim/pcep 的"终结层 + 事件流 + flat 键直传"，只借鉴思路）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `ldp` 终结层 + 双载体（本版；bgp/pim/pcep 同构先例） | 9 种消息类型/双载体/多 session/双邻接四事可声明可断言；代价 = 一套薄层（已落码 1594 行） | **采用** |
| B | 拆成 `ldp_udp` + `ldp_tcp` 两层 | 双载体共享同一 PDU 编码器，拆层即重复编码逻辑，且 common header 完全相同 | **否决** |
| C | 并入 `mpls` 层 | mpls 是数据面封装（标签栈），ldp 是控制面协议（分发标签）——文法不兼容，合并即错 | **否决** |

## 12. P2 D-LDP-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 状态说明：实现已落码（`internal/protocol/ldp/` 四文件），本 P2 条目为 P-PIPE 文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口；P4 在本协议内为"缺口收敛"（§14），不另开新层。

### 12.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:544-590` + `:1725`） | `LDPConfig/LDPSession/LDPAdjacency/LDPEvent` 配置类型 + `FlowSpec.LDP` 槽位 | —（共享文件） |
| `trafficgen/internal/protocol/ldp/planner.go` | `Validate`（载体/端口/profile 拒绝）+ `Plan`（事件展开） | 145 |
| `trafficgen/internal/protocol/ldp/builder.go` | PDU 编码（`BuildPDU`/`buildMessage`/9 种事件分支/`CheckFault`/`ValidateConfig`） | 537 |
| `trafficgen/internal/protocol/ldp/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator("ldp")` + validator 注册，`init()`） | 213 |
| `trafficgen/internal/protocol/ldp/ldp_test.go` | 51 个 `Test*`（Validate 拒绝面 + PDU 编码面 + 生成器面） | 699 |
| 接线 6 件 | registry 注册（`layers/registry.go:1383`）/ translate Meta 直传（`chain_planner_translate.go:165`）/ convert 子配置搬运（`strategy_convert.go:1734`）/ protocols 准入（`protocols.go:46`）/ main.go 空导入 + ChainPlanner（`main.go:100/:548`）/ 混合载体分支（`chain_planner_util.go:64` + `chain_planner.go:1390`） | — |

### 12.2 接口签名

- `Validate(spec core.FlowSpec) error`（`planner.go:18`）：`LDP==nil` 通过（空配置默认流）；`carrier=udp_discovery` 且 `SrcPort` 非 0/646 → 拒 `port`；IPv6 地址 + profile 不匹配 → 拒 `profile`。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`planner.go`）：先 Validate；`parseLDPConfig` 产出 payload 序列 + 方向位；逐 PDU emit。
- `ValidateConfig(cfg *core.LDPConfig) error`（`builder.go:446`）：carrier/adjacency/session/event 四级校验（§6 其他分支列）。
- `CheckFault(faultKind string) error`（`builder.go:321`）：6 种合法注入 kind 各返回 `ldp: fault injection %q`；未知 kind 返回 `unknown fault kind %q`。
- 生成器：`Name() "ldp"`；`GenEvents()` 事件生成器；`Generate` 逐 PDU emit（`layer_gen.go`）。

### 12.3 数据结构

`LDPConfig{Transport, WireProfile, Carrier, Events[], Sessions[], Adjacencies[], LSRID, LabelSpace, HoldTime, Targeted, KeepaliveTime, LabelControl, LabelAdvertisement, FaultKind}`；`LDPSession{SrcPort, SrcLSRID, DstLSRID, Events[]}`；`LDPAdjacency{Kind, Carrier, Direction, MessageID, Targeted, SrcPort, DstPort, Events[]}`；`LDPEvent{Kind, Direction, MessageID, LSRID, ...}`（`types.go:544-599` 全量，无新增；分段 `LDPConfig` 544-559 / `LDPSession` 563-568 / `LDPAdjacency` 573-582 / `LDPEvent` 585-599，与 §2 一致）。

### 12.4 主流程

配置 → validator（载体/端口/profile 3 分支 + ValidateConfig 四级）→ planner（事件展开为 PDU 序列）→ worker（TCP 层补握手/seq-ack/挥手/MSS 分段；UDP 层补数据报/checksum；dual_adjacency 走自产完整包分支）→ writer（PCAP/NIC）。

### 12.5 错误分支

11 种 validator 拒绝各对应 planner/生成器双层守卫（§6 表）；全部传 task error（零假成功——N 系列守卫）。§6 末另有 13 个已落码但今日无例的分支（A′ 候选）。

### 12.6 性能边界

见 §10（逐 PDU 流式、per-flow 局部状态、无跨流共享、无锁；吞吐数字待 P4 基准）。

### 12.7 与现有逻辑的冲突点

- `CheckProtoFlat`（`strategy_convert.go:8625` 起）**无 ldp 分支**（`grep -c 'protocol ldp no longer'` = 0 实测）：顶层 `ldp` 子映射 presence 不判死——属缺口 G-LDP-2（禁加单协议黑名单分支，等框架级 unknown-key 白名单；kingbase 记忆裁定）。
- 动态 allowlist（`internal/core/layer_dyn.go:18-21`）：`ldp` 零命中实测 → 业务字段动态对象即拒；四元组 `ip`/`tcp`/`udp`/`eth` 全开。见 §13.12。
- registry `ldp` Fields 为空（生成表 `fields: {}` 实测）→ 层内 `events`/`carrier` 键无处可住，目标形状（§2）需 P4 补 Fields + translate 分支（G-LDP-1）。
- `chain_planner_translate.go:756` 对 ldp 只建空配置——与 bgp(`:747`)/pim(`:780`)/moxa(`:3304`) 的严格解码路径不一致，是层内化缺失的直接体现。

### 12.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 4 文件 + 接线 6 处（registry/protocols/translate/convert/main/chain_planner_util）；不触及其他协议。cases 回滚 = 恢复 25 例 JSON（产物文件，非文档）。

## 13. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §13.1 强制展开：存量 25/25 为**违规过渡形**（非负例顶层残留 70 处：`src_ip/dst_ip/src_port/dst_port/ldp` 与 `layers` 并存，= §1.13 白名单制下的判死形状）；合规层链形**待代码阶段收敛**（G-LDP-1）；目标形状见 §2 样例；presence 判死形状缺口 G-LDP-2 | §13.1；`cases/ldp.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 ldp 流量模板，自带 `flow_control`；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §13.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（终结层）/时间线。有长连接（TCP session），不豁免 | §13.3 + §9 |
| §4 查规范 | RFC 5036 全文 + §3.4/§3.5 FEC 语义 + 落码反推 + tshark 262 字段实测；八项矩阵 + 子表①②③ | §11 |
| §5 依赖与错误 | `DependsOn ["udp"]` + `TransportOn ["udp","tcp"]`（`registry.go:1383`）；11 种拒绝分支；失败传 task error | §4/§6/§12.5 |
| §6 性能 | 见 §10（6.1–6.8 要素齐；吞吐数字标待 P4 基准，不写承诺） | §10 |
| §7 三份文档 | `99-ldp-{design,testcase}.md` v1.0.1（草稿层）+ D-LDP-1（§12，门1 获批 = 定稿）+ T-LDP（testcase §2，25 ID）+ 旧稿 41-* 为历史层；`docs/protocol-pcap-test/ldp.md` 为**过期产物**（G-LDP-8） | 修订记录 |
| §8 设计先行 | P1–P3 先于 P4 缺口收敛；门1 获批 = D-LDP-1 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = RFC 5036（§11.1）+ D-LDP-1（§12）+ tshark `ldp.*` 262 字段实测（替代"已确认现网行为"档，厂商行为未到抓包级）；25 ID 逐项回指；存量 25 例审计去向 testcase §8 | `99-ldp-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 `/tmp/pipe/doc-lanes/ldp.md` §3）+ 收官隔离复审；红先绿后 | 自审日志 §3 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §13.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §13.12 |
| §13 schema 派生 | `ldp` 已在 `registry.go:1383` 注册（**不新增层**）；`allowedProtocols["ldp"]=true`（`protocols.go:46`）；Meta 已直传；**P4 补 registry Fields 必须重跑 schemagen** | §12.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `ldp.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/ldp/` | testcase §9 |

### 13.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-28）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 纯净 |
|---|---|---|---|---|
| `cases/ldp.json` | 25 | `{layers, src_ip, dst_ip, src_port, dst_port, ldp}` ×24（N1 `ldp_neg_carrier` 无四元组，只有 `{layers, ldp}`）；顶层 `ldp` 子映射 25/25；**非负例顶层残留 70 处**（14 × 5 键），**全体 121 处** | `[tcp,ldp]` ×18、`[udp,ldp]` ×5、`[ip,ldp]` ×1（S14 混合载体）、`[eth,ldp]` ×1（N1 判死载体） | ✅ 11/11 只有 `{expect_error,error_contains}` |

**合规判据（§1.11/§1.13 白名单制）**：非负例顶层键必须为 **0**——白名单仅 `layers`/`strategy_fc`/`ttl`/`flow_control`/`output`/`output_config`/`group_id`。按此判据，存量 25/25 例**全部违规**：顶层 `ldp` 子映射与顶层四元组同 `layers` 并存，正是 §1.13 点名的判死形状。

**层壳状态（判死之外的第二重违规）**：`layers` 里的 `{"ldp": {}}` 是**空壳**——`registry.go:1383` 无 `Fields`、`chain_planner_translate.go` 无 `case "ldp"` 解码分支（只有 `:756` 建空 `LDPConfig`），层内配置**不被解码**；真实配置只能住顶层 `ldp` 子映射。即"层链形"今日**表达不了 ldp 配置**。

**旧键去向表（§15.3 要求"每个键写去向"；本协议全部为"待代码阶段收敛"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` | **24**（除 N1） | 待代码阶段收敛 → 迁 `layers[i].ip.src`（G-LDP-1） |
| `dst_ip` | **24** | 待代码阶段收敛 → 迁 `layers[i].ip.dst` |
| `src_port` | **24** | 待代码阶段收敛 → 迁 `layers[i].tcp/udp.src_port`；TCP 可删（保底 `12345+i`）；UDP Hello 必须显式 646 |
| `dst_port` | **24** | 待代码阶段收敛 → 迁 `layers[i].tcp/udp.dst_port`；**或删**（由 646 缺省补齐，A′ `ldp_default_port` 验证） |
| `count` | **0** | 走 `flow_control`（本套件无多流例） |
| 顶层 `ldp` 子映射 | **25** | 待代码阶段收敛 → **迁 `layers[i].ldp`**（须先补 registry `Fields` + translate 解码分支，G-LDP-1） |

**结论**：本协议**不是符合态**，是有实质迁移工作量的违规过渡形。§1 门的动作 = ①补 registry `Fields`（config 14 键：transport/wire_profile/carrier/events/sessions/adjacencies/lsr_id/label_space/hold_time/targeted/keepalive_time/label_control/label_advertisement/fault_kind）；②加 translate 严格解码分支（层内 ldp→`spec.LDP`，bgp/pim/moxa 范式）；③`MapToFlowSpec` 顶层收敛；④25 例整体改写；⑤新增 A′ 例 11 条（子表② 变体 5 + 子表① T3 5 + 多事务 1）全部纯 layers 形；⑥收官自查行「非负例顶层键 = 0」由 **70 → 0**。

目标形状样例见 §2（顶层仅 `layers`+`flow_control`）。

### 13-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"ldp":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 ldp 分支，`grep -c` = 0 实测；实调 `CheckProtoFlat("ldp",{layers,ldp:{}})` 返回 `""`）→ **不建该负例**（建了会真绿 = 假通过）→ 缺口 G-LDP-2 登记。② 白名单外游离键判死由**框架级 unknown-key 白名单通用门**承担（**禁加单协议黑名单分支**，§1.13 + kingbase 裁定）——该通用门落码后建一条 A′。③ 11 负例每条带锚词（已齐，§6）。④ 收官自查「非负例顶层键 = 0」（代码阶段收敛后执行）。
- **离线 suite 接入状态（复跑实测）**：ldp **未接入** `layer_chain_suite_test.go`（`chainSuiteProtos` 与空白导入均无 ldp）；直接跑 `CHAIN_PROTO=ldp go test -run TestLayerChainSuite ./test/protocol_pcap/` → **FAIL 25/25**，错因 `generator not implemented for layer "ldp"`。副本补接入后 → **25/25 PASS（36.8s）**。故本套件「接入后可绿」，非「今日能绿」；接入属代码阶段。

### 13.3 §3 强制展开：五件套

会话表：`s1` 单 TCP session 基线（S1–S8/S11/S12，各自四元组，SYN→事件→FIN 四包挥手）/ `s2` 多 session（S13，两条 session 各 `src_port` 50000/50001，LSR ID 192.0.2.1/192.0.2.3）/ `s3` UDP discovery 会话（S9/S10，无 TCP 状态机）/ `s4` 双邻接混合（S14，UDP 两包 + TCP session 一条）。事务：`t1` 建连（握手，tcp 层）/ `t2` 发现（Hello，UDP）/ `t3` 初始化+保活（0x0200/0x0201）/ `t4` 标签操作（0x04xx）/ `t5` 终止（Notification 或 FIN）；每事务四件事（前置/触发/成功/失败）见 §9 状态机 + §8 场景表。关联关系：**无派生流**（诚实声明：LDP 无控制流派生数据流，标签分发本身即控制面，无 `driven_by`）。插入位置：终结层（`[ip,tcp,ldp]` / `[ip,udp,ldp]`，无中间层）。时间线：事件内严格顺序 / 多 session 整块顺序展开（S13 不假设跨 session 全局包序，只断言聚合与各 session 公共头）/ 无交错（`concurrent` 为例外路径不启用）。

### 13.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst`、`tcp.src_port/dst_port`、`udp.src_port/dst_port` 五策略全开（allowlist `internal/core/layer_dyn.go:18-21` 实测四行：`ip`/`tcp`/`udp`/`eth`；保底 `12345+i`（常量 `strategy_convert.go:49`，注入点 `worker.go:308`）；dst 动态与 646 缺省和平共处——显式/动态值非零即不触发补齐）。

**业务字段 13 项全关**（allowlist 无 `ldp` 行，`grep -c "ldp" layer_dyn.go` = 0 实测；对象即拒）：`wire_profile`（profile 选择器）/ `carrier`（载体选择器）/ `events[]`（会话剧本）/ `sessions[]`（会话结构）/ `adjacencies[]`（邻接结构）/ `lsr_id`·`label_space`（LDP Identifier）/ `hold_time`·`keepalive_time`（定时参数）/ `targeted`（Hello 标记）/ `label_control`·`label_advertisement`（分发纪律）/ `fault_kind`（注入键）——逐流变体需求列 A′ 候选（testcase §6.2；今日按 §9.36 口径不冒充覆盖）。

序号算法实读：`parseLayerDyn`（`layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`strategy_convert.go:49` 常量 + `worker.go:308` 注入）/ allowlist 白名单（`layer_dyn.go:18-21`）——**`ldp` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。

## 14. P3 对接清单（T-LDP 草稿输入；正文落 testcase 文件）

25 ID（14 正 + 11 负）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。A′ 候选 **11 例**（三组口径，勿混）：**① 子表② 变体 5**：`ldp_default_srcport`（变体 7）/ `ldp_default_port`（变体 8）/ `ldp_fec_prefix0`（变体 11）/ `ldp_label_min`（变体 15）/ `ldp_label_max`（变体 16）；**② 子表① T3 列 5**（init 前置守卫未落码，G-LDP-7）：`ldp_neg_address_before_init` / `ldp_neg_mapping_before_init` / `ldp_neg_request_before_init` / `ldp_neg_withdraw_before_init` / `ldp_neg_release_before_init`；**③ §3.15① 多事务 1**：`ldp_multi_txn_roundtrip`。

## 15. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-LDP-1 | registry `ldp` Fields 为空 + translate 无 `case "ldp"` 解码分支（`:756` 只建空配置）→ 层内 `events`/`carrier`/`adjacencies` 无处可住；25 例顶层残留 121 处（非负例 70 处） | **代码阶段首动作**；收官「非负例顶层键=0」由 70→0 |
| G-LDP-2 | `CheckProtoFlat` 无 ldp 分支 → presence 形今日不判死 | P4 先实测再建例；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单） |
| G-LDP-3 | 存量 25 例顶层旧键残留（非负例 70 处；顶层 `ldp` 子映射 25/25） | **待代码阶段收敛**，随 G-LDP-1 改写例 |
| G-LDP-4 | 业务字段动态全关（allowlist 无 `ldp` 行） | A′ 候选，不冒充已覆盖（§9.36 口径） |
| G-LDP-5 | 41-ldp 两份文档引用不存在的 `docs/protocol-designs/audit/41-ldp-adversarial-audit.md` | 99 版不再引用；41 版留只读历史 |
| G-LDP-6 | IPv6 transport/profile 未定义（N3 只做拒绝面） | 取得独立规范与 fixture 后另建 profile，不修改本套件契约 |
| G-LDP-7 | **init 前置守卫只落码 KeepAlive**（`builder.go:529`）；Address/标签消息的 init 前置未实现，§4 声明属目标形状 | 代码阶段补 `seenInit` 守卫 + 5 条 T3 负例（§14 A′ ② 组）；守卫落码前 §4 声明不得作为 as-built 行为引用 |
| G-LDP-8 | **结果文档过期**：`trafficgen/docs/protocol-pcap-test/ldp.md` 写 "Cases: 25 — pass 25, fail 0, error 0"，末次提交 `91f2487`（2026-08-30）早于判死提交 `0417be5`（2026-09-13）两周；`cases/ldp.json` 末改 `ed62038`（2026-08-30）同日；`docs/protocol-pcap-test/ldp/` 目录**不存在**（0 个 pcap，表内 14 条 `[pcap](ldp/*.pcap)` 全为死链）；今日 MCP 建策略 **24/25 例 400**（五键在；唯一例外 `ldp_neg_carrier` 任务期 `ldp: unknown carrier "raw"`），离线 suite **未接入**（`chainSuiteProtos`/空白导入块均无 ldp），实跑 `CHAIN_PROTO=ldp` **25/25 全红** | 代码阶段（P5 重跑套件后**重生成**该产物）；在此之前读者**不得**据此判断套件可跑（§0 产物过期登记） |

## 16. 修订记录

- v1.0.1（2026-09-28）：补**结果文档过期登记**（G-LDP-8）——`docs/protocol-pcap-test/ldp.md` 的 "25/25 pass" 为过期产物（末次提交 `91f2487` 2026-08-30 < 判死提交 `0417be5` 2026-09-13；pcap 目录不存在；今日 MCP 建策略 24/25 例 400、离线 suite 未接入实跑 25/25 全红），登记于 §0 + §15，不得作为"套件可跑"依据；含 ldp 与 pcep 的特例差异（ldp 无"去五键即可用"路径）。仅文档，不动 JSON/代码。
- v1.0.0（2026-09-28）：P-PIPE #99 文档轨 P1–P3。续号：41→99 沿革与 7 项过期校正（§0）；存量 25 例机读审计（顶层残留形状、expect 形状、ID 顺序一致、包数公式符合度）；§13.1/13.3/13.12 强制展开 + 13-P2；D-LDP-1 as-built 定稿（§12）；缺口 G-LDP-1…G-LDP-7。P1–P3 合并自审 3 轮（首轮抓出标注/去向/顺序 3 处，次轮抓出适配声明/性能双路 2 处，第三轮抓出计数/行号/形状基线/对账算术 6 处，末轮全量重核干净；结论见 `/tmp/pipe/doc-lanes/ldp.md` §3）。

# DCERPC（分布式计算环境远程过程调用，DCE/RPC）设计契约

> 版本：v2.1.0（行为面全枚举，层链形；静态闭环校准）
> 日期：2026-10-01
> 状态：文档与当前机器契约静态对账完成；本轮未运行 suite、Go 测试、服务端或 NIC/PCAP 验证，不报告运行绿。行为面重写（ID 权威=testcase §2）+ v2.0.2 勘误保持有效。
> 配套文件：`docs/protocols/dcerpc/testcase.md`、`trafficgen/test/protocol_pcap/cases/dcerpc.json`
> 规范基线：The Open Group C706（DCE 1.1 RPC：RPC 协议规范第 12 章 connection-oriented PDU/编解码权威）、MS-RPCE（Windows 现网行为面：2.2.2.1 common header/2.2.1.1.1 UUID 编码/endpoint-mapper tower）、RFC 793（TCP 载体）。

## 0. 端序与编码权威

- common header 整数字段（frag_len/auth_len/call_id）与全部 PDU body 整数按 DataRepresentation 声明编码；**fixture 钉 little-endian**（drep=`0x00000010`：int LE + ASCII char + IEEE float）。drep≠`10000000` 拒（负例通道——v1.0.0 §3"drep 固定假设网络大端"系笔误，C706 明文按 drep）。
- NDR stub scalar 同 LE；MS/AD **UUID 混合端序**（前 3 组 LE：`12345678-1234-1234-1234-123456789abc` → `78 56 34 12 34 12 34 12 12 34 12 34 56 78 9a bc`，MS-RPCE §2.2.1.1.1）——UUID 编解码权威单点（builder uuidEncode/uuidDecode），用例逐字节钉。
- auth trailer 只断言 type/level/pad 长度/边界/存在性；NTLM/KERBEROS credentials、signature、MIC、session key 一律 opaque bytes 不伪造（安全限制，沿 v1.0.0）。

## 1. 范围、profile 和层链

本设计定义 DCE/RPC version 5 over TCP 的连接型协议：TCP/135 endpoint mapper（EPM）查询 profile 与 EPM 返回 dynamic endpoint 后的业务调用 profile。auth_len≠0 的认证 trailer 只做边界与 opaque 断言。

**P-EPM**：TCP destination port 135，BIND EPM interface（E1AF8308-5D1F-11C9-91A4-08002B14A0FA v3.0）→ endpoint-map REQUEST（opnum=2）→ RESPONSE。
**P-DYNAMIC**：独立 TCP session，destination port 为显式声明值（不得从 135 推导），目标 interface BIND 后 REQUEST/RESPONSE。

推荐链 `[ip, tcp, dcerpc]` 或 `[ipv6, tcp, dcerpc]`；udp 载体（connectionless CL 模式）不产生。目标形状（严格层链）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.63", "dst": "198.51.100.63"}},
    {"tcp": {"src_port": 40063, "dst_port": 135}},
    {"dcerpc": {"sessions": [
      {"src_ip": "192.0.2.63", "events": [
        {"kind": "bind", "call_id": 1,
         "contexts": [{"context_id": 0,
           "abstract": "e1af8308-5d1f-11c9-91a4-08002b14a0fa", "abstract_version": [3, 0],
           "syntaxes": [{"uuid": "8a885d04-1ceb-11c9-9fe8-08002b104860", "version": [2, 0]}]}],
         "respond": {"ack": "bind_ack", "secondary": "1025",
                     "results": [{"context_id": 0, "result": 0, "reason": 0,
                                  "uuid": "8a885d04-1ceb-11c9-9fe8-08002b104860", "version": [2, 0]}]}},
        {"kind": "request", "call_id": 2, "context_id": 0, "opnum": 2,
         "alloc_hint": 16, "stub": "010400010400", "respond": {"ack": "response", "stub": "010400"}}
      ]}
    ]}
  }
]}
```

（旧 v1.0.0 §2 的顶层 src_ip/dst_ip/src_port/dst_port 示例随 v2.0.0 作废；端口只住 tcp 层；顶层 dcerpc 子映射与 layers 并存=判死。）

## 2. 配置键

| 配置键 | 约束 |
|---|---|
| `sessions` | 每个 session 一条独立 TCP 连接（EPM 会话与 dynamic 会话各自显式声明，状态不跨 session 复用）；会话内 `events[]` 有序。 |
| `events[].kind` | `bind` / `alter_ctx`（请求）/ `request`；应答经 `respond` 声明（`bind_ack`/`alter_ctx_resp`/`response`/`fault`）。 |
| `contexts[]` | `context_id`(u16)、`abstract`(UUID 字符串)+`abstract_version`[major,minor]、`syntaxes[]`(UUID+version)；同一 BIND/ALTER 内 context_id 不重复；每 context 至少 1 个 transfer syntax。 |
| `call_id` | u32；同一调用的 request 与 response/fault 同值；并发调用 distinct；缺省由 callWalker 迭代（起 1，声明值采纳并推进）。 |
| `opnum` | u16。`alloc_hint` | u32 提示值，可≠实际 stub 长度（合法）。 |
| `stub` | hex 字符串；空串=合法 empty stub。 |
| `respond.results[].result` | 0=acceptance、2=provider_rejection；reason 值沿 C706。 |
| `auth` | `{type, level, context_id, credentials(hex), pad}`；credentials 只 opaque。 |
| `wire_fault` | 仅负例注入口（处置表见 §7），不是合法线上字段。 |

## 3. Common Header（16B）

| 相对 offset | 宽度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 1 | Version | 固定 `5`，≠5 拒。 |
| 1 | 1 | VersionMinor | 固定 `0`，≠0 拒（minor 1 仅 auth 语义差异，不产生）。 |
| 2 | 1 | PacketType | BIND=11/BIND_ACK=12/ALTER_CONTEXT=14/ALTER_CONTEXT_RESP=15/REQUEST=0/RESPONSE=2/FAULT=3 七型产生；REJECT(1)/SHUTDOWN(6)/CANCEL(8)/ORPHANED(17)/PING(1_CL) 等其余不产生（负例值域兜底）。 |
| 3 | 1 | PacketFlags | PFC_FIRST_FRAG=0x01、PFC_LAST_FRAG=0x02、PFC_PENDING_CANCEL=0x04、PFC_OBJECT_UUID=0x80（仅 REQUEST；v2.0.1 勘误——0x20 系 PFC_DID_NOT_EXECUTE，tshark 位序实证）；分片首/末标志必须闭合（有 FIRST 的调用必有 LAST），非分片恒 0x03。 |
| 4 | 4 | DataRepresentation | fixture 恒 `10 00 00 00`（LE int+ASCII+IEEE）；≠拒。 |
| 8 | 2 | FragLength | LE；从 header 起计含 body/pad/auth trailer；≥16；须与实际 PDU 字节一致。 |
| 10 | 2 | AuthLength | LE；凭据长度不含 header；=0 无 trailer，>0 须有 verifier 且 `auth_len ≤ frag_len-24`。 |
| 12 | 4 | CallId | LE；零值合法（边界正例）；关联规则见裁定6。 |

## 4. PDU 固定字段

### 4.1 BIND(11)/ALTER_CONTEXT(14)
body：`max_xmit_frag(2) max_recv_frag(2) assoc_group_id(4) num_context_items(1) reserved(1) reserved2(2)` + context list。context element：`context_id(2) num_transfer_syntaxes(1) reserved(1)` + abstract UUID(16)+version(4) + 每 transfer syntax UUID(16)+version(4)。ALTER 只声明新增/替换 context，编码同 BIND。

### 4.2 BIND_ACK(12)/ALTER_CONTEXT_RESP(15)
BIND_ACK/ALTER_CONTEXT_RESP body 两型共享 header_t（C706 §12.5.4.2）：`max_xmit_frag(2) max_recv_frag(2) assoc_group_id(4) sec_addr_len(2)` + `sec_addr(len 字节，按 4B 对齐 pad)` + `n_results(2) reserved(2)` + result list（每项 `result(2) reason(2) transfer_uuid(16) version(4)`）。BIND_ACK 携 secondary port 串；ALTER_CONTEXT_RESP `sec_addr_len=0` 恒写（v2.0.2 勘误：tshark 对 ALTER_CONTEXT_RESP 实解出 Scndry Addr len/Num results——现网分解器两型共用解析，与 C706 正文 ALTER 小节省略字段列表的取舍见 §10）。result=0 acceptance / 2 provider rejection；rejected context 后续调用拒（状态机）。

### 4.3 REQUEST(0)/RESPONSE(2)/FAULT(3)
REQUEST body：`alloc_hint(4) context_id(2) opnum(2)` +（PFC_OBJECT_UUID 置位）object UUID(16) + stub。RESPONSE body：`alloc_hint(4) context_id(2) cancel_count(1) reserved(1)` + stub。FAULT body：`alloc_hint(4) context_id(2) cancel_count(1) reserved(1) status(4) reserved2(4)` + stub。同一 call_id 一对一关联 REQUEST 与 RESPONSE/FAULT；FAULT 后该调用终态。

### 4.4 Auth trailer（auth_len>0）
stub 后 pad 至 4B 对齐，随后 verifier：`auth_type(1) auth_level(1) auth_pad_length(1) auth_reserved(1) auth_context_id(2) credentials(auth_len)`。pad 字节计入 frag_len；pad_length ∈ 0-3 须与实际填充一致。auth_len = 6 + credentials 数（verifier 语义长，pad 不计）。

## 5. NDR 可观察契约

stub 按 drep LE 编码 scalar；复合值起始自然对齐（2→2/4→4/8→8），padding 计入 stub 长度。unique/ref/full pointer referent 4B（NULL 语义=0）；conformant array 前置 max_count(4)（varying 再加 offset(4)+actual_count(4)）；union 按 discriminant 宽度对齐后仅出现对应 arm；UTF-16 字符串 max/offset/actual 按 2B code unit 计。stub 内容 opaque（引擎不解析 NDR 语义，帧字节照抄声明）；NDR 越界/溢出/未知 discriminant 经 `wire_fault` 注入通道拒（ndr_alignment/ndr_array_count/ndr_union_unknown/ndr_stub_overflow 四故障值），非法字符/错宽等声明面错误由 UUID/域宽/hex 自然守卫同步拒。

## 6. Fragment 与 TCP record boundary

PDU 超 record 时按同一 call_id/context_id 分片：每片自含 16B header+frag_len，首片 PFC_FIRST_FRAG、末片 PFC_LAST_FRAG。fixture 分片由 `fragments: n`（request/respond 内）声明，引擎按 stub 均分产 n 片（首 01/中 00/末 02）；**非分片 PDU 恒 PFC_FIRST_FRAG|PFC_LAST_FRAG=0x03**（真实栈行为；tshark 对 0 flags 视作 Fragment:Mid 延迟解析——P5 实证勘误）。多 PDU 背靠背（引擎每 PDU 一 TCP 段）覆盖"PDU≠TCP record"观察面；真跨 segment 重组属 NIC/栈行为不产生（裁定7）。v1.0.0 #13"合并 segment"例改"背靠背多 PDU"口径。

## 7. wire_fault 逐值处置表（32 值；v2.1.0 机读校准——32 注入常量定义齐，cases 实际 29 例走注入+3 例走链级自然形状）

- **A. wire_fault 注入通道（29 例经本通道被拒；`carrier_layer_missing`/`carrier_udp`/`address_family_mismatch` 三例走 §7-C 链级自然形状，无 `wire_fault` 键）**：version_not5（header）/version_minor_not0（version）/packet_type_unknown（packet）/packet_type_reserved（packet，8 型不产生兜底）/flags_first_no_last（fragment）/flags_last_no_first（fragment）/drep_not_le（drep）/frag_len_lt16（frag）/frag_len_mismatch（length）/auth_len_over（auth）/call_id_reuse（call）/call_mismatch（call）/state_ack_no_call（state）/state_request_unbound（state）/context_duplicate（context）/context_unknown（context）/syntax_mismatch（syntax）/uuid_version_missing（uuid）/alloc_hint_negative（hint）/ndr_alignment+ndr_stub_overflow（ndr）/ndr_array_count（array）/ndr_union_unknown（union）/auth_pad_invalid+auth_trailer_over（trailer）/auth_verifier_len（verifier）/port_undeclared（port）/uuid_width（uuid）/assoc_group_width（width）——括号内为 DescribeDCERPCWireFault 主锚词（error_contains 断言字面）。
- **B. payload 语义面自然守卫（约 12 条，同步 validator 分支——非法配置同步拒，不经注入）**：state_request_unbound（request 前 bound）/state_ack_no_call（respond 前 request——§4.3 一 call 一应答关联）/context_duplicate（同 BIND 内 ID 重复）/context_unknown（引用未 accepted）/syntax_mismatch（rejected 后仍用）/alloc_hint_negative（u32 域负值）/uuid_width+version_missing（UUID 32-hex+缺字段）/context_syntax（≥1 transfer syntax）/ndr 四注入对立面（stub opaque 无 NDR 自然守卫）/auth pad/type/level/cred-hex 域宽（trailer/verifier 锚词）/call_id_reuse+call_mismatch（并发撞车/应答配对）。
- **C. 载体面自然守卫（3 条链形预检——创建面同步拒，无任务产物）**：① 缺 tcp 载体（carrier，`trafficgen/internal/core/layers/validate_layers.go` dcerpc 预检块）；② 混合地址族（family，同块预检）；③ udp 载体声明经 transport-dup 门报 carrier 专用错（`trafficgen/internal/core/layers/complete.go` tcp-only 分支，`%s chain: udp carrier is not supported — %s rides tcp only (carrier)`）。
- 32 注入值定义见 `trafficgen/internal/core/dcerpc.go` 常量与 DescribeDCERPCWireFault（cases 同序 32 锚词；三方同表：testcase §2 ↔ dcerpc.go ↔ cases error_contains）。

## 8. 边界与安全限制

16B 头最小帧；frag_len=16（无 body BIND 不产生——16 仅理论下限，正例取最小合法 BIND）；auth_len=0/>0 两态；CallId 0/最大/相邻值；opnum 0/65535；context_id 0；assoc_group 0/显式值；secondary address 空串/"1025" 两态；多 context/多 syntax/多 call/多 session；IPv4/IPv6 同构；auth pad 0-3 四态。认证失败只能表现 fault/明确拒绝；不伪造密文/MIC/签名/session key。

## 9. 簇级覆盖图景（v1.3——ID 权威在 testcase §2）

①EPM/dynamic 双 profile×双地址族（4）；②common header 字段与边界（4）；③BIND/ACK 族（多 ctx/单 ctx 最小/secondary/rejected/assoc_group/max_frag 5）；④ALTER 族（2）；⑤调用族（request/response NDR/fault/empty stub/object_uuid/cancel_count/status 边界 7）；⑥NDR 族（pointer/array/union/string/scalars/struct padding 6）；⑦auth 族（主形态/pad 四态/type-level 变体 3）；⑧分片与多 PDU（3）；⑨多会话多调用（3）；⑩边界值族（call_id/opnum/context_id/frag_len/alloc_hint/assoc_group 8）；⑪负例 32（逐故障单锚词）。

## 10. 修订记录

- v2.1.0（2026-10-01，静态闭环校准）：状态行去除 P5 全绿执行断言；§13 文件清单改为 planner/builder+共享层接线；§13.3 补链级 concurrent 强制与 session dst_port 覆盖；新增 §13.5 当前 JSON 机读对账（80=48+32、形状/键集/wire_fault 分布/decode_as 6 例、IPv6 走 ip 层内地址）；未改 cases 语义，未运行 suite。
- v2.0.2（2026-09-24，P6 修轮）：§4.2 ALTER_CONTEXT_RESP body 改为与 BIND_ACK 同 header_t（assoc_group(4)+sec_addr_len(2)=0 恒写）——取舍理由：C706 正文 ALTER 小节省略两字段，但 wireshark dcerpc 共用解析按 header_t 解（Scndry Addr len/Num results 实解出）；以现网分解器（tshark/wireshark dcerpc 共用解析实证）为准绳，实现 buildBindAck 两型同体一致；§5 末句限定为 wire_fault 注入通道语义；§7 收敛为落码实况拆分。
- v2.0.1（2026-09-24，P4 据实勘误）：§4 verifier `auth_context_id` 4→2（MS-RPCE 2.2.2.1.1 u16 权威；builder/authTrailer 一致）并钉 `auth_len = 6 + credentials` 公式。
- v2.0.0（2026-09-24，v1.3 行为面重写）：ID 权威迁 testcase §2（80=48 正+32 负）；负例 6 粗组拆 32 行逐故障单锚词（§7 处置表 17 自然+15 注入）；旧扁平示例迁层链（§1）；drep 端序勘误（C706 按 drep 编码，fixture 钉 LE——v1.0.0 §3"网络大端"系笔误）；新增 UUID 混合端序编解码权威（§0）；PDU 产生域钉七型+不产生 8 型（裁定4）；#14 NIC 一致性例改 pcap 内一致性口径；#13 合并 segment 例改背靠背多 PDU；fragment 生成面收窄为 fixture 声明 `fragments`（裁定7）；既有决策未改：auth opaque 安全限制、EPM/dynamic 双 profile、TCP record≠PDU 边界观察面。
- v1.0.0（2026-08-20）：初稿 20 ID（14 正+6 负粗组），见 git 历史。

## 11. P1 规范矩阵（CORE §4.19–§4.22）

### 11.1 八项矩阵

| 规范要求 | 业务场景 | 代码现状 | 缺口结论 |
|---|---|---|---|
| 连接模型：connection-oriented TCP、主动建连（C706 §12.5） | EPM 135 与 dynamic 独立 session | `trafficgen/internal/protocol/dcerpc/builder.go` Generator 走 TCP 层；`sessions[]` 显式分连接，链计划层强制 `concurrent=true` | 已覆盖：#1–4 |
| 命令/消息：七种产生 PDU 及请求-应答 | BIND/ALTER/REQUEST/RESPONSE/FAULT | builder 与 `Plan` 按 `events[].kind/respond.ack` 编码 | 已覆盖：#5–15 |
| 状态机：bound、accepted context、open call | 绑定后调用、拒绝后禁止调用 | `trafficgen/internal/protocol/dcerpc/planner.go` validateSession 校验状态与 call 配对 | 已覆盖：#59–65 |

**注意**：当前 JSON 负例仅 3 例走链级/自然形状（carrier×2、family×1，均无 `wire_fault`），其余 29 例走 `wire_fault` 注入通道；§7-B 所述“自然守卫”其余分支由链级单测逐条覆盖，不由 cases JSON 覆盖。
| 字段：header、NDR、UUID、auth trailer | 边界、对齐、opaque credentials | `builder.go` 按 LE/drep 编码；stub 原样写入 | 已覆盖：#16–24、29–38、48 |
| 错误：长度、状态、载体、语义拒绝 | wire_fault 单故障注入 | `validateWireFault` 返回带锚词错误；自然守卫同步拒绝 | 已覆盖：#49–80 |
| 活性：fragment、call 完成、TCP 重组 | 分片、背靠背 PDU、多调用 | `fragments` 逐 PDU 生成；TCP record 不作为 PDU 边界 | 已覆盖：#25–28、40–41 |
| NAT/代理/端点发现：EPM 返回 secondary endpoint | 135 查询后 dynamic 端口新连接 | `sessions[].dst_port` 显式声明，禁止从 135 推导 | 已覆盖：#3、4、47 |
| 版本/方言：v5.0、drep、MS UUID | LE fixture、混合端序 UUID | validator 固定 v5/0/drep；`uuidEncode` 单点 | 已覆盖：#5、30、48；CL 模式列入缺口 D-DCERPC-1 |

### 11.2 子表①：命令 × 响应码矩阵

| 请求/消息 | 正常结果 | 拒绝/异常 | 用例 |
|---|---|---|---|
| BIND | acceptance | provider rejection | #6–11、49–52、63 |
| ALTER_CONTEXT | acceptance | provider rejection | #12–13、65 |
| REQUEST | RESPONSE | FAULT、未绑定、未知 context | #14–15、25、61–65 |
| RESPONSE | call_id 配对 | mismatch、无 open call | #14、59–61 |
| FAULT | status 终态 | status 边界 | #15、37 |
| CANCEL/ORPHANED/SHUTDOWN/PING | 不生成 | 类型值拒绝 | #51–52 |

### 11.3 子表②：数据形态变体

| 形态 | 结论 | 用例 |
|---|---|---|
| IPv4 / IPv6 | 两族独立覆盖 | #1–4、41 |
| 单/多 context、单/多 syntax | 逐项编码和结果对应 | #6–7、25 |
| scalar、hyper、pointer、array、union、UTF-16 | stub 字节与对齐覆盖 | #16–21、32 |
| PFC_OBJECT_UUID=0x80 + 16B object UUID | REQUEST 对象标识分支；flags 与 UUID 同时断言 | #35 |
| 非分片单 PDU flags=0x03 | FIRST/LAST 同片闭合；与多片 01/00/02 对照 | #28–29、26–27 |
| 空 stub、large stub、fragment | 边界与分片覆盖 | #26–29、38、46 |
| auth_len=0、opaque credentials、pad 0–3 | trailer 边界覆盖；不解密 | #22–24 |
| EPM 135、显式 dynamic endpoint | 新连接且端口不推导 | #1–4、47 |
| EPM 真 tower（多 floor、UUID、端口） | endpoint-mapper RESPONSE 内 tower 结构与边界 | #43 |
| 混合端序 UUID | 逐字节权威 | #48 |

### 11.4 子表③：商业行为 → 用例映射

| 现网行为（出处） | 用例 | 结论 |
|---|---|---|
| Windows RPC endpoint mapper 先查后连（MS-RPCE §3.3） | #1–4、47 | 已覆盖 |
| 多接口协商与拒绝回退（MS-RPCE §2.2.2） | #6、10、12、13、45 | 已覆盖 |
| 同连接并发 call、故障终态 | #15、25、31、37 | 已覆盖 |
| 大 stub 分片、多个 PDU 背靠背 | #26–28、46 | 已覆盖 |
| opaque NTLM/Kerberos verifier | #22–24 | 已覆盖边界；凭据内容不伪造 |
| CL/UDP connectionless profile | — | 缺口 D-DCERPC-1，需查 C706 §12.6 后再立项 |

### 11.5 三路对照与方案取舍

规范以 Open Group C706 §12.5 和 MS-RPCE §2.2.2.1 定义 PDU/UUID；商业行为以 Windows RPC endpoint mapper 的“135 查询、dynamic 新连接”行为为准，已映射 #1–4、47；开源实现参考 Wireshark `packet-dcerpc.c` 的公共 header/tower 定界与 Samba `librpc/ndr` 的对齐思路，实际编码仍由本包单点实现。三路一致采用 v5 connection-oriented；auth 密文不从开源实现复制。

| 方案 | 真实走法 | 优点 | 代价 | 结论 |
|---|---|---|---|---|
| A | `[ip,tcp,dcerpc]`，events 驱动完整 PDU | 复用 TCP、层链单一真相、可表达 session/事务 | 不产生 CL/UDP | 采用 |
| B | raw dcerpc 自带 TCP/连接管理 | 可独立重放 record | 与 tcp 层重复、破坏层链边界 | 否决 |
| C | 只回放 fixture 字节 | 对复杂 PDU 精确 | 无动态 session/call 状态校验 | 仅作 frames 断言，不作主路径 |

## 12. 依赖、错误处理与性能

### §5 依赖与错误处理（CORE §5.1–§5.5）

本节的依赖、失败返回、会话动作、重试与超时表是实现边界；未能由当前代码或规范核实的 CL/UDP profile 已登记为 D-DCERPC-1，不写成支持能力。

### 12.1 依赖与错误表（CORE §5）

| 依赖 | 失败返回 | 会话动作 | 重试/超时 |
|---|---|---|---|
| `ip` 层地址族与 `tcp` 载体 | `carrier`/`family` 校验错误 | 创建任务中断 | 不重试；创建期立即返回 |
| BIND accepted context | `state`/`context` 锚词 | 不产后续 request | 不重试；调用者修 spec |
| call_id open 集 | `call` 锚词 | 当前任务中断 | 不重试；无协议层自动重发 |
| frag/auth 长度与 stub | `length`/`auth`/`trailer` | 当前 PDU 拒绝 | 不重试 |
| wire_fault 注入器 | 带 `anchor` 的 error | 负例任务失败 | 不重试；超时由 task runner 负责 |

### 12.2 性能设计与验收（CORE §6）

路径保持生成器流式：每个 session 逐 event 产出，不汇总全部 PDU；队列沿通用有界 worker 队列，单 PDU 内存为 header+stub+auth 的线性大小。验收目标先采用代码可证明边界：单 stub 受 `frag_len`/分片配置限制，session/call 数量随输入线性增长；吞吐、CPU、RSS 的具体数字标为待基准确认，不伪造承诺。基线、目标规模、压力上限、长时间、并发交错、背压六类均须测包/秒、bit/s、RSS、CPU、队列积压和失败数。

pcap 路：写盘后用 tshark 重组 TCP，逐 PDU核验 `dcerpc.*`、方向、call_id、frag_len 与 frames offset 54；网卡路：启用 NIC capture，对同一字段集合核验实际线速、丢包与顺序。两路都必须包含 #25/#41 交错和 #26/#27 分片，不能以“任务完成”替代输出断言。

## 13. P2 八要素（CORE §8）

1. **文件**：`trafficgen/internal/protocol/dcerpc/planner.go`、`builder.go` 与共享层注册/翻译/载体校验（`trafficgen/internal/core/layers/registry.go`、`chain_planner_translate.go`、`validate_layers.go`、`complete.go`）；本次文档和 `cases/dcerpc.json` 是验收入口。
2. **接口**：`Planner.Validate(spec core.FlowSpec) error`；生成器 `Name/GenEvents/Generate`（无独立 `layer_gen.go`）；配置入口为 `layers[].dcerpc.sessions[]`。
3. **结构**：`sessions[] → events[] → contexts/respond/auth`；每 session 独立四元组、状态、call 集合。多会话在链计划层强制 `concurrent=true`（`chain_planner_chain.go` isDCERPCChain 分支），按 session SrcPort/DstPort 合成独立连接；动态端口则是 `sessions[].dst_port` 显式声明（实现对 generator `EmitMsg` 的 `DstPort` 覆盖），链级缺省端口由 `tcp` 层承载。
4. **流程**：层校验 → translate → session 状态校验 → BIND/ALTER → request → response/fault → TCP writer。
5. **错误**：失败带稳定锚词；创建期链级错误无任务产物，planner 错误传播为 task error；负例只断言错误。
6. **性能边界**：流式、每流局部状态；大 stub 以分片控制内存；共享队列/worker 的总速率由上层限速器负责。
7. **冲突点**：TCP record 与 PDU 边界不同；ALTER 响应采用 Wireshark 共用 header_t；opaque auth 不解密；CL/UDP 尚未进入本 profile。
8. **回滚**：回退本协议 planner/builder/generator 接线及本协议三份产物；不改其他协议；恢复本文件上一版本即可。

## 13.5 当前 JSON 对账注记（静态校准，2026-10-01）

机读事实：80 例=48 正+32 负；ID 唯一且 testcase §2 同序；正例 `spec_json` 顶层键集合仅 `{layers}`（48/48），层序全部 `[ip,tcp,dcerpc]`（48/48）；正例 `expect` 均为 `{fields,frames,packet_count}` 三键（48/48）；负例 `expect` 仅 `{expect_error,error_contains}`（32/32），`spec_json` 顶层仅 `{layers}`（32/32）；负例中 29 例走 `wire_fault` 注入，另 3 例走链级自然形状（缺 tcp 载体 `[ip,dcerpc]`、udp 载体声明 `[ip,udp,dcerpc]`、混合地址族）；`decode_as` 顶层键仅 6 例动态端口正例使用；JSON 无 `strategy`/`flows`/`count`/`flow_control` 对象。IPv6 正例（epm_ipv6、dynamic_ipv6）当前走 `ip` 层内 IPv6 地址（无独立 `ipv6` 层），断言 `ipv6.nxt=6`；与早期“[ipv6,tcp,dcerpc]”表述不一致，以当前 JSON 为准。

## 14. 动态字段清单与序号算法（CORE §12）

动态值的通用解析入口是 `trafficgen/internal/core/layers/checkLayerDynObjects`（层字段白名单与形状校验）及 worker 的 flow index 解析路径；本协议终结层 `sessions[].src_port/dst_port`、event 业务字段当前仍为标量解析。下表逐字段说明，不把静态样例冒充动态覆盖。

| 字段 | 支持策略 | 序号/依据 | 结论 |
|---|---|---|---|
| `ip.src`/`ip.dst` | fixed/inc/rand/list/pattern | 通用 layer dynamic；worker 按 flow index，尾部回绕 | 已开放，配置住 ip 层 |
| `tcp.src_port`/`tcp.dst_port` | fixed/inc/rand/list/pattern | 通用 TCP dynamic；worker 按 flow index，尾部回绕 | 已开放，配置住 tcp 层 |
| `sessions[].src_port`/`sessions[].dst_port` | fixed only | `dcerpc/builder.go` `sessionPort` 与事件 SrcPort/DstPort 覆盖；无 dynamic resolver | 缺口 D-DCERPC-3：补终结层 dynamic resolver，迁入 sessions 字段并逐策略补例 |
| `call_id` | fixed/default walker | `dcerpc/builder.go` `callWalker.request`；未声明从 1 递增，声明值推进游标 | 当前无 dynamic 对象 |
| `context_id` / `opnum` / `alloc_hint` | fixed only | `dcerpc/planner.go` 标量范围校验；builder 按声明写入 | 缺口 D-DCERPC-3：补业务字段 dynamic resolver 后再逐策略补例 |
| `stub` / UUID / auth credentials | fixed opaque hex | `dcerpc/builder.go` `stubBytes`/`uuidEncode`/`authTrailer` 原样或规范编码 | 缺口 D-DCERPC-3：先定义安全允许的动态输入，再补 resolver；凭据不可由动态测试伪造 |

D-DCERPC-3 是明确迁入计划：在 dcerpc 终结层增加字段级 dynamic_value 解码，按 worker flow index 调用通用 fixed/inc/rand/list/pattern 解析，保持层链住处不变；完成后为四元组与每个开放业务字段增加整格用例。当前 JSON 无 `flow_control`/策略对象，故无动态正例。

### 14.1 动态整格缺口矩阵

| 字段组 | fixed | inc | rand(seed) | list | pattern | 状态 |
|---|---|---|---|---|---|---|
| ip/tcp 四元组 | 已有静态层形 | D-DCERPC-3 | D-DCERPC-3 | D-DCERPC-3 | D-DCERPC-3 | 通用层路径待动态整格校准 |
| session ports | 已有 6 例显式值 | D-DCERPC-3 | D-DCERPC-3 | D-DCERPC-3 | D-DCERPC-3 | 需终结层 resolver |
| call/context/opnum/alloc_hint | 静态 | D-DCERPC-3 | D-DCERPC-3 | D-DCERPC-3 | D-DCERPC-3 | 需业务字段 resolver |
| stub/UUID/auth | 静态 opaque | D-DCERPC-3 | D-DCERPC-3 | D-DCERPC-3 | D-DCERPC-3 | 先定安全输入边界 |

---

## 15. 门1 §1–§14 对照表（CORE §15.1–§15.3）

### 15.1 §1 强制展开：旧键去向与完整 spec_json

旧格式 `src_ip`/`dst_ip` → `layers[0].ip.src/dst`；`src_port`/`dst_port` → `layers[1].tcp.src_port/dst_port`；`count` → 独立 `flow_control`（本轮无数量例）；顶层 `dcerpc` 子映射 → `layers[2].dcerpc`。当前 80 例顶层 spec_json 只有 `layers`。

```json
{"layers":[{"ip":{"src":"192.0.2.63","dst":"198.51.100.63"}},{"tcp":{"src_port":40063,"dst_port":135}},{"dcerpc":{"sessions":[{"events":[{"kind":"bind","contexts":[],"respond":{"ack":"bind_ack"}}]}]}}]}
```

### 15.2 §3 强制展开：五件套

| 会话表 | 事务序列 | 关联关系 | 插入位置 | 时间线 |
|---|---|---|---|---|
| `sessions[]`，各自 src/dst port、生命周期 | bind/alter → request → response/fault；同 session 可多 event | call_id 关联 request 与 response/fault；context_id 关联 bind result | EPM 135 session 先行，dynamic endpoint 为独立 session；事件端口覆盖 TCP conn key | 默认按 session 顺序；`concurrent=true` 时按 event 轮转交错；TCP writer 负责握手/挥手 |

### 15.3 §12 强制展开

四元组动态字段：`ip.src/dst`、`tcp.src_port/dst_port` 已由通用层 dynamic 支持 fixed/inc/rand/list/pattern，按 worker flow index 解析；终结层 session ports 与业务字段见 D-DCERPC-3，当前仅 fixed/default walker。call_id 序号算法为 `dcerpc/builder.go:callWalker.request`（未声明从 1 递增，声明值推进游标）。

| 条目 | 满足方式 | 证据 |
|---|---|---|
| §1 层链 | 地址在 ip、端口在 tcp、业务在 dcerpc；顶层仅 layers | 本文 §1；JSON 全 80 例 |
| §2 策略任务 | 单 dcerpc 模板；多流数量由 flow_control 承载 | CORE §2；当前无数量例 |
| §3 五件套 | session 表/事务序列/关联/插入位置/时间线 | 本文 §2、§13.3–4 |
| §4 规范 | C706、MS-RPCE、RFC 793 + 三张子表 | 本文 §11 |
| §5 依赖错误 | 依赖层、锚词、停止与不重试 | 本文 §12.1 |
| §6 性能 | 流式边界、六类场景、pcap/NIC 双路 | 本文 §12.2 |
| §7 三文档 | design、testcase、cases 三者同 ID 集 | testcase §2；JSON 80 |
| §8 设计 | 文件/接口/结构/流程/错误/性能/冲突/回滚 | 本文 §13 |
| §9 测试 | 规范→设计→现网三源逐 ID 回指 | testcase §5 |
| §10 评审 | 修改后逐条自审；本轮未跑 suite | 本次报告 |
| §11 表达 | 文档使用中文结论与证据路径 | 全文 |
| §12 动态 | 四元组与业务字段策略、序号、静态复制边界 | 本文 §14 |
| §13 schema | 层注册表为机器契约，本文不复制 schema | `layers` 形状 |
| §14 真实流程 | MCP 建任务→引擎→tshark；本轮不执行 | testcase §1/§4 |

完整严格层链样例见 §1；旧 `src_ip/dst_ip/src_port/dst_port/count` 和顶层 `dcerpc` 均无去向残留，均已迁入对应层或由 flow_control 承载。 

## 16. 层链迁移契约（D1-D8，静态收口）

| ID | 结论 | 证据/去向 |
|---|---|---|
| D1 | 地址只住 `layers[].ip`；端口只住 `layers[].tcp`；数量只住独立 `flow_control` | 当前 80 例 `spec_json` 顶层仅 `layers`；正例无顶层地址、端口、`count` |
| D2 | DCERPC 是依赖 TCP 的终结层，标准链固定为 `[ip,tcp,dcerpc]`；IPv6 地址仍由 `ip` 层承载 | JSON 48 正例层序全为 `[ip,tcp,dcerpc]`；§13.5 已记录 IPv6 实际形状 |
| D3 | TCP 握手、序号、分段与挥手由 TCP 层负责；DCERPC 只生成 PDU 事件 | `trafficgen/internal/protocol/dcerpc/builder.go` `buildEventFrames`；§6 明确 PDU 与 TCP record 边界 |
| D4 | `sessions[]`、`events[]`、PDU 字段、tower 与 `wire_fault` 均住 `layers[].dcerpc` | `chain_planner_translate.go` 翻译入口；正例/29 个注入负例逐层对账 |
| D5 | 顶层 `dcerpc` 子映射不得作为正例配置入口；presence 负例保留并判死 | 当前 80 例无顶层 `dcerpc`；不把缺载体负例误报为 presence 例 |
| D6 | 数量与速率由策略/任务 `flow_control` 承载，不从 DCERPC `sessions` 或顶层 `count` 推导 | 当前 JSON 无数量对象；§14 明确动态/流控边界 |
| D7 | 负例保留故意错误输入；自然载体负例不强行添加 `wire_fault` | 32 负例：29 个注入，缺 tcp/udp/混族 3 个保留链级自然形状 |
| D8 | PFC_OBJECT_UUID、单 PDU flags、EPM 真 tower 三个协议特有观察面均有独立 ID；未实现 CL/UDP、业务动态整格、keepalive 只登记缺口 | #35、#28–29、#43；D-DCERPC-1/2/3，未伪造支持或运行结果 |

### 16.1 静态收口结论

当前仅声称三文件的文档/机器契约静态闭环：80=48+32，ID 顺序、层链、正负断言键集和负例双键均已对账。未运行 suite、Go 测试、服务端或 NIC/PCAP；未修改 Go、schema、其他文档或 `LAYERCHAIN_INDEX`。自审两轮：第一轮逐项核对 D1-D8、三协议特有观察面、顶层白名单与负例形状；第二轮复核代码锚词、JSON 80=48+32 及三文件交叉引用，末轮干净。

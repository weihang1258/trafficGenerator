# DCERPC（分布式计算环境远程过程调用，DCE/RPC）设计契约

> 版本：v2.0.0（行为面全枚举，层链形）
> 日期：2026-09-24
> 状态：P5 全绿（2026-09-24，80/80 ×2，dcerpc 层已注册翻转）；行为面重写（ID 权威=testcase §2）+ v2.0.1 P4/P5 据实勘误（§3/§4/§6/§7——修订记录在案）。
> 配套文件：`docs/protocol-designs/63-dcerpc-testcase.md`、`trafficgen/test/protocol_pcap/cases/dcerpc.json`
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
BIND_ACK body：`max_xmit_frag(2) max_recv_frag(2) assoc_group_id(4) sec_addr_len(2) sec_addr(port 字符串按 4B 对齐 pad)` + `n_results(2) reserved(2)` + result list（每项 `result(2) reason(2) transfer_uuid(16) version(4)`）。ALTER_CONTEXT_RESP body：`max_xmit_frag(2) max_recv_frag(2)` + result list。result=0 acceptance / 2 provider rejection；rejected context 后续调用拒（状态机）。

### 4.3 REQUEST(0)/RESPONSE(2)/FAULT(3)
REQUEST body：`alloc_hint(4) context_id(2) opnum(2)` +（PFC_OBJECT_UUID 置位）object UUID(16) + stub。RESPONSE body：`alloc_hint(4) context_id(2) cancel_count(1) reserved(1)` + stub。FAULT body：`alloc_hint(4) context_id(2) cancel_count(1) reserved(1) status(4) reserved2(4)` + stub。同一 call_id 一对一关联 REQUEST 与 RESPONSE/FAULT；FAULT 后该调用终态。

### 4.4 Auth trailer（auth_len>0）
stub 后 pad 至 4B 对齐，随后 verifier：`auth_type(1) auth_level(1) auth_pad_length(1) auth_reserved(1) auth_context_id(2) credentials(auth_len)`。pad 字节计入 frag_len；pad_length ∈ 0-3 须与实际填充一致。auth_len = 6 + credentials 数（verifier 语义长，pad 不计）。

## 5. NDR 可观察契约

stub 按 drep LE 编码 scalar；复合值起始自然对齐（2→2/4→4/8→8），padding 计入 stub 长度。unique/ref/full pointer referent 4B（NULL 语义=0）；conformant array 前置 max_count(4)（varying 再加 offset(4)+actual_count(4)）；union 按 discriminant 宽度对齐后仅出现对应 arm；UTF-16 字符串 max/offset/actual 按 2B code unit 计。全部校验在 stub 边界内，越界/溢出/未知 discriminant=拒。

## 6. Fragment 与 TCP record boundary

PDU 超 record 时按同一 call_id/context_id 分片：每片自含 16B header+frag_len，首片 PFC_FIRST_FRAG、末片 PFC_LAST_FRAG。fixture 分片由 `fragments: n`（request/respond 内）声明，引擎按 stub 均分产 n 片（首 01/中 00/末 02）；**非分片 PDU 恒 PFC_FIRST_FRAG|PFC_LAST_FRAG=0x03**（真实栈行为；tshark 对 0 flags 视作 Fragment:Mid 延迟解析——P5 实证勘误）。多 PDU 背靠背（引擎每 PDU 一 TCP 段）覆盖"PDU≠TCP record"观察面；真跨 segment 重组属 NIC/栈行为不产生（裁定7）。v1.0.0 #13"合并 segment"例改"背靠背多 PDU"口径。

## 7. wire_fault 逐值处置表（32 值；P4 落码据实勘误——bacnet 15+27 先例）

- **拟定自然面守卫**（配置可表达、validator 同步拒）：call_id_reuse（并发撞车）；call_mismatch（应答 call 与 open 集不符）；state_ack_no_call（应答无前置请求）；state_request_unbound（bound 前 request）；context_duplicate（同 BIND 内 ID 重复）；context_unknown（引用未 accepted context）；syntax_mismatch（rejected 后仍用）；alloc_hint_negative（u32 域）；ndr_alignment（padding 缺失）；ndr_array_count（count 越界）；ndr_union_unknown（未知 discriminant）；ndr_stub_overflow（stub 越界）；auth_pad_invalid（pad_length≠实际）；auth_trailer_over（trailer 越 frag_len）；auth_verifier_len（auth_len 与 credentials 不符）；context_syntax（UUID/version 缺字段）；frag_flags_first_no_last（FIRST 无 LAST）——计 17。
- **拟定仅注入/结构不可达**（builder 恒渲染正确字节）：version_not5、version_minor_not0、packet_type_unknown、packet_type_reserved（8 型不产生）、drep_not_le、frag_len_lt16、frag_len_mismatch、auth_len_over、auth_verifier_len、auth_pad_invalid（pad 与实际填充 builder 恒一致）、auth_trailer_over、flags_last_no_first、flags_first_no_last（分片 flags 由引擎管理，配置不可达——v2.0.1 勘误：从自然面移注入口）、uuid_width（UUID 非 16B 渲染恒对）、assoc_group_width、carrier_layer_missing、carrier_udp、port_undeclared、address_family_mismatch——计 20 注入/12 自然（负例 32 全经 wire_fault 注入通道或载体自然形状落码，锚词三方同表）。
- 17+15=32 可复算；P4 落码逐值对照实况勘误（bacnet M2 教训：对着代码真行为，不对着意图）。

## 8. 边界与安全限制

16B 头最小帧；frag_len=16（无 body BIND 不产生——16 仅理论下限，正例取最小合法 BIND）；auth_len=0/>0 两态；CallId 0/最大/相邻值；opnum 0/65535；context_id 0；assoc_group 0/显式值；secondary address 空串/"1025" 两态；多 context/多 syntax/多 call/多 session；IPv4/IPv6 同构；auth pad 0-3 四态。认证失败只能表现 fault/明确拒绝；不伪造密文/MIC/签名/session key。

## 9. 簇级覆盖图景（v1.3——ID 权威在 testcase §2）

①EPM/dynamic 双 profile×双地址族（4）；②common header 字段与边界（4）；③BIND/ACK 族（多 ctx/单 ctx 最小/secondary/rejected/assoc_group/max_frag 5）；④ALTER 族（2）；⑤调用族（request/response NDR/fault/empty stub/object_uuid/cancel_count/status 边界 7）；⑥NDR 族（pointer/array/union/string/scalars/struct padding 6）；⑦auth 族（主形态/pad 四态/type-level 变体 3）；⑧分片与多 PDU（3）；⑨多会话多调用（3）；⑩边界值族（call_id/opnum/context_id/frag_len/alloc_hint/assoc_group 8）；⑪负例 32（逐故障单锚词）。

## 10. 修订记录

- v2.0.1（2026-09-24，P4 据实勘误）：§4 verifier `auth_context_id` 4→2（MS-RPCE 2.2.2.1.1 u16 权威；builder/authTrailer 一致）并钉 `auth_len = 6 + credentials` 公式。
- v2.0.0（2026-09-24，v1.3 行为面重写）：ID 权威迁 testcase §2（80=48 正+32 负）；负例 6 粗组拆 32 行逐故障单锚词（§7 处置表 17 自然+15 注入）；旧扁平示例迁层链（§1）；drep 端序勘误（C706 按 drep 编码，fixture 钉 LE——v1.0.0 §3"网络大端"系笔误）；新增 UUID 混合端序编解码权威（§0）；PDU 产生域钉七型+不产生 8 型（裁定4）；#14 NIC 一致性例改 pcap 内一致性口径；#13 合并 segment 例改背靠背多 PDU；fragment 生成面收窄为 fixture 声明 `fragments`（裁定7）；既有决策未改：auth opaque 安全限制、EPM/dynamic 双 profile、TCP record≠PDU 边界观察面。
- v1.0.0（2026-08-20）：初稿 20 ID（14 正+6 负粗组），见 git 历史。

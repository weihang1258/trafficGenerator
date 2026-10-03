# #122 rtsp（RTSP）测试用例契约

> 版本：v1.0.0（批次二文档车道，as-built 型）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/122-rtsp-design.md` v1.0.0
> 旧基线：**无**（`docs/protocol-designs/` 下无 `NN-rtsp-*` 稿，`ls | grep rtsp` 零命中）；非设计型基线三源 = 结果产物 `trafficgen/docs/protocol-pcap-test/rtsp.md`（tracked，12 行 pass 表）+ `CASE_PCAP_MAPPING.md:261-273` 的 `RTSP.1.1`–`RTSP.1.9` 参考场景表 + 代码注释引用的 `/tmp/l7_planner_design/testcases_rtsp.md`（**该目录在 HEAD 不存在**，死引用，设计 §0 #2）
> 机器契约：`trafficgen/test/protocol_pcap/cases/rtsp.json`（**12 例 = 11 正 + 1 负**，ID/顺序与本版 §2 一致，已机读实测；顶层键已是纯层链形，零残留）
> 白话一句：**十二条检查：十一条看正常收发（OPTIONS 冒烟、五方法全序、SDP body、404、暂停结束、URI 两种写法、自定义头、RTP 媒体、方向覆盖、复合大场景、状态码缺省），一条看空 dialog 能不能被拦下；每条只查一件事。今日 12/12 已实跑通过。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **12 个唯一语义 ID：11 正 + 1 负**（负例 N-1）。派生规则：设计 §3 每个消息/字段/头条款、§5 每个事务/自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-30 机读复核）**：12/12 例顶层键 = `{expect,id,proto,spec_json,summary}`；`spec_json` 顶层键 = **`{layers}` ×12（唯一键，零游离键、零顶层 `rtsp` 子映射）**——本协议存量**顶层零残留**，无 §1 迁移工作量（设计 §12.1）；链形 = **`[ip,rtsp]` ×12**（无例外，链上无 tcp/udp）；**11 正例均含 `packet_count`，1 负例无包数**；1 负例 `expect` 键集合 = `{expect_error,error_contains}`（严格两键）。

`expect` 键分布实测：`{fields,has_handshake,notes,packet_count,terminates}` ×2（#1/#2）、`{has_handshake,notes,packet_count,terminates}` ×3（#5/#8/#10）、`{notes,packet_count,terminates}` ×6（#3/#4/#6/#7/#9/#12）、`{error_contains,expect_error}` ×1（#11）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`、`tcp.flags`、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线**：本机 tshark 3.6.14；11 个正例 pcap 全部被解码（`rtsp.*` dissector 可用），负例在 Validate 阶段拒绝且无 pcap。**今日 12 例只用了 5 个断言通道**：`packet_count`（11 例）、`has_handshake`（5 例）、`terminates`（11 例）、`tcp.dstport`（2 例）、`tcp.flags`（2 例）。**`rtsp.*` 专用字段零使用、frames 零使用** → A′ 立项（G-RTSP-7）。

**动态字段禁止硬编码**：生成期值（`Session` 15 位 hex / `ssrc` / `seq` / `ts` / TCP ISN / IP ID）**全随机且链路径无 seed 入口**（设计 §5.2/G-RTSP-12）→ 用例**只能**断言格式（`^[0-9a-f]{15}$`）或跨包相等关系，**不得**断言字面值。今日 12 例**未断言任何生成期值**。

**包数约定（实测公式，设计 §9）**：

```
packet_count = 7（3 握手 + 4 挥手）
             + Σ ceil(render_len(m) / MSS)          ← 今日恒 1（最大消息 126B < 1460）
             + (任一消息 emit_media ? max(media.frames,1) : 0)
```

**逐例实测**：9/17/9/9/13/11/9/**16**/9/**18**/—/9。**#8/#10 的 16/18 已写入 JSON `packet_count`，并与结果产物表一致。**

**源端口口径（必读，防假红）**：链路径 rtsp 源端口规则为 **0 保持 0**（`chain_planner.go:996` raw 链同列），单流时 worker **不注入** `12345+i` → **实测报文客户端源端口 = 0**。任何断言 `tcp.srcport == 12345` 的用例会假红；断言 `tcp.srcport` 存在非 0 值同样假红。今日 12 例**未断言 srcport**（正确）。

**方向口径（必读，防假绿）**：raw 链路径下 `layer_gen.go:53` 把**每一包** `PacketConfig.Direction` 改写为 `"up"`（防 raw-IP drive 二次换向）→ **`Direction` 字段对 12 例全部恒 `"up"`，包括 RTP 帧**。方向**只能**经 `ip.src` / `udp.srcport` 观测（设计 §3.5 诚实边界，G-RTSP-4）。

**保活/重试/RST 口径**：协议层无 PING 类保活；`GET_PARAMETER` 保活（RFC 2326 §10.8）与 `Session: timeout`（§12.37）**未实现、零用例**（A′）；重试/重连**未实现**；**RST 零覆盖**（自建 TCP 恒 FIN 优雅终止，G-RTSP-14）；正例恒 4 包挥手终止。

## 2. 原子用例索引（12 ID = 11 正 + 1 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | 依据（规范优先） | packet_count（实测） |
|---:|---|---|---|---|---:|
| 1 | `rtsp_options_smoke` | 正 | §3.1/§3.3.1/§2：OPTIONS 基线 + CSeq 自动补 + 554 缺省 | RFC 2326 §10.1/§12.17 | 9 |
| 2 | `rtsp_play_session_full` | 正 | §3.3.2/§3.3.3/§5.3：五方法全序 + Session 签发与回显 | RFC 2326 §12.37/附录 A | 17 |
| 3 | `rtsp_describe_sdp_body` | 正 | §3.3.4：SDP body 逐字节透传 + Content-Length/Content-Type 自动补 | RFC 2326 §12.14/§12.16；RFC 4566 | 9 |
| 4 | `rtsp_response_404` | 正 | §3.2：404 reason 缺省 `Not Found` | RFC 2326 §10.2 | 9 |
| 5 | `rtsp_pause_teardown` | 正 | §5.3：PLAY/PAUSE/TEARDOWN 三事务 | RFC 2326 §10.5/§10.6/§10.7 | 13 |
| 6 | `rtsp_uri_explicit_and_default` | 正 | §3.3 规则 9：URI 缺省构造 + 显式值入请求行 | RFC 2326 §12.10 | 11 |
| 7 | `rtsp_headers_custom` | 正 | §3.3：用户头与自动 CSeq 共存、自动头在用户头之前 | RFC 2326 §12 | 9 |
| 8 | `rtsp_emit_media_rtp` | 正 | §3.5/§12.3：RTP 子流 + SETUP Transport 双侧端口 + 流关联 | RFC 2326 §12.39；RFC 3550 §5.1 | **16** |
| 9 | `rtsp_direction_explicit` | 正 | §3.4：显式 `direction` 覆盖方法推断（服务器主动消息） | RFC 2326 §10.6；RFC 7826 §13.4 | 9 |
| 10 | `rtsp_composite_full_session_media` | 正 | §4：五方法 + RTP + 自定义头 + SDP 四类交织 | RFC 2326 §10/§12；RFC 3550 | **18** |
| 11 | `rtsp_neg_dialog_required` | 负 | §7 N-1：空 dialog → Validate 拒绝 | 设计 §7.1 | —（实测 0 包） |
| 12 | `rtsp_status_text_default` | 正 | §3.2：200 无 `status_text` → reason `OK` 缺省 | RFC 2326 §10.2 | 9 |

**T-编号对照（沿用 JSON `summary` 内的自编号，权威顺序以 cases JSON 为准）**：T-1 ≡ #1；T-2 ≡ #2；T-3 ≡ #3；T-4 ≡ #4；T-5 ≡ #5；T-6 ≡ #6；T-7 ≡ #7；T-8 ≡ #8；T-9 ≡ #9；T-10 ≡ #10；T-11 ≡ #11；T-12 ≡ #12。**T-1…T-12 连续无缺号**（与 opcua 旧稿 T4/T8 虚例不同）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `terminates=true`（末 3 包内有 FIN/RST）；帧位由 §1 公式与实跑双向确认。**帧号约定**：帧 1–3 = 握手，帧 4… = 信令（每消息 1 帧，今日无分段），末 4 帧 = 挥手。

### 3.1 `rtsp_options_smoke`（9）

配置：`layers[0].ip={src:"10.0.0.1",dst:"20.0.0.1"}`；`layers[1].rtsp.dialog=[{method:"OPTIONS"},{status_code:200,status_text:"OK"}]`。

- 现有断言：`packet_count=9`、`has_handshake=true`、`terminates=true`；`tcp.dstport=554`（帧 1、帧 4）；`tcp.flags="0x011"`（帧 8）。
- **实跑报文原文**：帧 4 = `OPTIONS rtsp://20.0.0.1/media RTSP/1.0\r\nCSeq: 1\r\n\r\n`（51B）；帧 5 = `RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n`（28B）。
- **可断言项（A′）**：`tcp.flags` 逐帧（帧 1 `0x002`、帧 2 `0x012`、帧 3 `0x010`、帧 4/5 `0x018`、帧 6 `0x011`、帧 7 `0x010`、帧 8 `0x011`、帧 9 `0x010`）；`rtsp.cseq` 帧 4/5 = 1。
- **缺口（G-RTSP-3）**：历史说明曾把单流源端口写成 `12345`；实际链路径单流源端口保持 **0**（仅多流由 worker 注入递增端口）。当前 JSON 已改为真实口径。

### 3.2 `rtsp_play_session_full`（17）

配置：dialog = OPTIONS/200、DESCRIBE/200(body=`v=0\r\n`)、SETUP/200、PLAY/200、TEARDOWN/200（共 10 消息）。

- 现有断言：`packet_count=17`、`has_handshake=true`、`terminates=true`；`tcp.dstport=554`（帧 4）；`tcp.flags="0x010"`（帧 17）。
- **实跑报文原文（CSeq 全序）**：帧 4 `OPTIONS …CSeq: 1`；帧 5 `200 OK…CSeq: 1`；帧 6 `DESCRIBE …CSeq: 2`；帧 7 `200 OK…CSeq: 2` + `Content-Type: application/sdp` + `Content-Length: 5` + body；帧 8 `SETUP …CSeq: 3`；帧 9 `200 OK…CSeq: 3` + **`Session: <15hex>`（首次签发）**；帧 10 `PLAY …CSeq: 4` + `Session: <同值>`；帧 11 `200 OK…CSeq: 4` + 同 Session；帧 12 `TEARDOWN …CSeq: 5` + 同 Session；帧 13 `200 OK…CSeq: 5` + 同 Session。
- **包数证据**：7 + 10×1 + 0 = 17 ✓。
- **可断言项（A′）**：① **CSeq 双向同号**（帧 4/5=1、6/7=2、8/9=3、10/11=4、12/13=5）；② **Session 跨包相等**（帧 9 与帧 10/11/12/13 同值，`same_as_packet` 形）；③ 帧 7 `Content-Length: 5` = `len("v=0\r\n")`；④ `rtsp.session` 字段格式 `^[0-9a-f]{15}$`。
- **未覆**：SETUP **无 Transport**（该例 `media` 未配置）——正确行为（设计 §3.3.3 守卫）；帧 11（PLAY 响应）**无 RTP-Info**（`media==nil`）——正确。

### 3.3 `rtsp_describe_sdp_body`（9）

配置：dialog = DESCRIBE、200(body=`"v=0\r\no=- 0 0 IN IP4 20.0.0.1\r\n"`，30B)。

- 现有断言：`packet_count=9`、`terminates=true`。
- **实跑报文原文**：帧 5 = `RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: 30\r\n\r\nv=0\r\no=- 0 0 IN IP4 20.0.0.1\r\n`（109B）。
- **可断言项（A′）**：① `Content-Length: 30` = body 字节长（**含 CRLF 计数**）；② body **逐字节透传**（两行 CRLF 结尾，frames 断言）；③ `Content-Type: application/sdp` 自动补。
- **现状**：SDP body 的长度与透传行为已在设计实测记录中钉死；cases 当前仍未使用 `fields`/`frames` 文本断言，专用 `rtsp.*` 字段收编列 A′。

### 3.4 `rtsp_response_404`（9）

配置：dialog = DESCRIBE、`{status_code:404}`（**无 `status_text`**）。

- 现有断言：`packet_count=9`、`terminates=true`。
- **实跑报文原文**：帧 5 = `RTSP/1.0 404 Not Found\r\nCSeq: 1\r\n\r\n`（35B）。
- **可断言项（A′）**：`rtsp.status_code`=404 + `rtsp.status_string`=`Not Found`（须先 `tshark -G fields` 实测字段名，G-RTSP-7）。

### 3.5 `rtsp_pause_teardown`（13）

配置：dialog = PLAY/200、PAUSE/200、TEARDOWN/200（6 消息）。

- 现有断言：`packet_count=13`、`has_handshake=true`、`terminates=true`。
- **实跑**：帧 4/5 = PLAY 对（48B/28B）、帧 6/7 = PAUSE 对（49B/28B）、帧 8/9 = TEARDOWN 对（52B/28B）。
- **现状**：`packet_count=13` 与公式一致，cases 说明已校正。

### 3.6 `rtsp_uri_explicit_and_default`（11）

配置：dialog = OPTIONS（无 uri）、200、DESCRIBE（`uri:"rtsp://20.0.0.1/live.sdp"`）、200。

- 现有断言：`packet_count=11`、`terminates=true`。
- **分支区分**：帧 4 使用缺省 `rtsp://20.0.0.1/media`，帧 6 使用不同的显式 `rtsp://20.0.0.1/live.sdp`，两条请求行分别证明缺省构造与显式 URI。

### 3.7 `rtsp_headers_custom`（9）

配置：dialog = OPTIONS（`headers:["User-Agent: trafficgen"]`）、200。

- 现有断言：`packet_count=9`、`terminates=true`。
- **实跑报文原文**：帧 4 = `OPTIONS rtsp://20.0.0.1/media RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: trafficgen\r\n\r\n`（75B）——**自动头（CSeq）在用户头之前**（设计 §3.3 前置块规则）。
- **可断言项（A′）**：头序（CSeq 行 index < User-Agent 行 index）；帧 5 响应**无** User-Agent（用户头不跨消息泄漏）。

### 3.8 `rtsp_emit_media_rtp`（16）

配置：dialog = OPTIONS/200、DESCRIBE/200(body=`v=0\r\n`)、SETUP/200、PLAY（**`emit_media:true`**）/200；`media={direction:"down",frames:1}`。

- 现有断言：`packet_count=16`、`has_handshake=true`、`terminates=true`。
- **实跑口径**：媒体 1 帧；`emit_media` 挂 PLAY 请求，因此 PLAY 响应不产生 RTP-Info。
- **包数证据**：7 + 8×1 + 1 = **16** ✓（结果产物表内亦记 16）。
- **流关联证据（本协议必答项）**：① SETUP 请求/响应的 `client_port` 同值（5004-5005）；② 响应追加 `server_port=5004-5005`；③ **实际 RTP 帧端口 = 5004↔5004**，与头同源（设计 §12.3 端口推导链）。**头与帧同源是本例最核心的可断言关系**。
- **当前状态**：旧的“跑后校准”说明已由 cases 的 `packet_count=16` 及媒体配置 `frames:1` 落实；PLAY 请求触发媒体，响应无 RTP-Info。

### 3.9 `rtsp_direction_explicit`（9）

配置：dialog = OPTIONS（**`direction:"down"`**）、200（**`direction:"up"`**）。

- 现有断言：`packet_count=9`、`terminates=true`。
- **实跑报文原文**：帧 4 = `OPTIONS rtsp://20.0.0.1/media RTSP/1.0\r\nCSeq: 1\r\n\r\n`（51B）但**发出方 = 20.0.0.1**（L3 已按 `direction:"down"` 翻转）；帧 5 = `200 OK` 但**发出方 = 10.0.0.1**（L3 已按 `direction:"up"` 翻转）。
- **可断言项（A′）**：`ip.src` 帧 4 = `20.0.0.1`、帧 5 = `10.0.0.1`——**这是唯一能证明 direction 覆盖生效的通道**（`Direction` 字段恒 `"up"`，见 §1 方向口径）。
- **注意**：现有 `packet_count=9` 与 #1（同样 9 包、同样两条消息）**包数相同**——本用例的**唯一区分度**在 L3 方向，而今日**未断言 `ip.src`** → 删掉两个 `direction` 字段用例仍绿。P4 须补 `ip.src` 断言。

### 3.10 `rtsp_composite_full_session_media`（18）

配置：dialog = OPTIONS(自定义头)/200、DESCRIBE/200(body=`v=0\r\n`)、SETUP/200、PLAY(**`emit_media:true`**)/200、TEARDOWN/200（10 消息）；`media={direction:"down",frames:1}`。

- 现有断言：`packet_count=18`、`has_handshake=true`、`terminates=true`。
- **实跑口径**：1 个 RTP 媒体帧插在 PLAY 请求与响应之间；PLAY 响应无 RTP-Info。
- **实跑**：帧 4/5 OPTIONS 对（75B/28B）、6/7 DESCRIBE 对（52B/83B）、8/9 SETUP 对（99B/126B）、10 PLAY 请求（74B）、**11 RTP（172B UDP）**、12 PLAY 响应（54B）、13/14 TEARDOWN 对（78B/54B）、15–18 挥手。
- **包数证据**：7 + 10 + 1 = **18** ✓（结果产物表内亦记 18）。
- **复合性（设计 §4 场景⑩）**：四类交织 = 五方法序（方法面）× 自定义头（头面）× SDP body（体面）× RTP 子流（媒体面）→ **门3 抽查首选**（§5.2）。
- **现状**：#8/#10 已改为 `frames:1`，并新增 `packet_count`；未知 `packets`/`payload` 键已删除。

### 3.11 `rtsp_status_text_default`（9）

配置：dialog = OPTIONS、`{status_code:200}`（**无 `status_text`**）。

- 现有断言：`packet_count=9`、`terminates=true`。
- **实跑报文原文**：帧 5 = `RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n`（28B）。
- **与 #4 的关系**：同语义分支的 200 面（#4 是 404 面）——**两例合起来覆盖 `rtspReasonPhrase` 的两个取值**，但 45 值表中其余 43 值零例（G-RTSP-10）。

**正例总则**：多消息一帧、多事务多对、媒体子流、自定义头、SDP body 均为正例形态；只有配置错误进入负例。

## 4. 负例契约

负例必须在 `Validate`/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功（**实测 0 包**）。

| ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（`rtsp.go` 逐字） | 代码行 |
|---|---|---|---|---|
| `rtsp_neg_dialog_required` | `{"rtsp":{"dialog":[]}}` | `dialog is required` | `rtsp: dialog is required (config.rtsp.dialog must contain at least one message)` | `rtsp.go:111-112` |

**锚词口径**：`error_contains` 是**子串**判定；命中代码文案（前缀 `rtsp: `）。**实测**：`ValidateSpec` 直接拒，锚词命中，**0 包**。

**负例原子性**：单一故障注入；单次执行不得混注。

**`expect` 键形状注**：负例 `expect` 严格为 `{expect_error, error_contains}` 两键。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：`invalid source IP: %s`（`rtsp.go:94`，链路径不可达——`ip.src` 先被 `ValidateLayers` 拦）；`invalid destination IP: %s`（`:99`，同）；`MSS %d too small (min %d per RFC 879)`（`:105`，链路径不可达——rtsp 层无 MSS 键，`chain_planner.go:1303-1312` 另有前置拦截）。**唯一可达分支 = `dialog is required`**（`:112`，`{"rtsp":{}}` 实测也命中此分支）。

**未入用例的静默路径（缺陷候选，G-RTSP-9）**：

| 输入 | 实测行为 | 代码行 |
|---|---|---|
| `{"dialog":[{}]}` | 该消息渲染为 nil → 跳过；**总包数 7，无错误** | `rtsp.go:234-237`/`:317-320` |
| `{"dialog":[{"method":"OPTIONS","direction":"sideways"}]}` | 方向非法 → 跳过；**总包数 7，无错误** | `:242-244` |
| `media` 有配置但无任何 `emit_media:true` | `media` 被解析、永不消费；**0 个 RTP 帧，无错误** | `:259` 条件不满足 |
| `[ip,tcp,rtsp]` 链（放 tcp 层） | `Plan` 返回 **0 包，无错误**（G-RTSP-2） | `chain_planner_util.go:44-51` |

**已通的判死门（可建负例，会真红）**：顶层 `rtsp` 子映射 presence——`{"layers":[…],"rtsp":{}}` 实测文案 `protocol rtsp no longer accepts a top-level rtsp sub-config (move it into the rtsp layer of a [ip,rtsp] layers chain)`（`strategy_convert.go:9100-9116` `rawWrapChains`）。**A′ 可建此负例**（与 opcua/moxa 的"不建"相反）。

**未通的判死门（不得建负例，建了会真绿）**：游离顶层未知键——`{"layers":[…],"bogus":1}` 实测 `CheckProtoFlat("rtsp", …)` 返回**空串**（不判死）→ G-RTSP-15。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 2326 §10/§12/附录 A + RFC 7826 + RFC 3550 §5.1 + RFC 4566 + RFC 879（设计 §10）+ 本契约 as-built 定稿（设计 §11）+ tshark 3.6.14 与 **12 例实跑**（**今日已到抓包级**：离线链套件 12/12 PASS；11 个正例逐例包数与帧位在 §3，负例 Validate 拒绝且无 pcap）→ 12 ID（本契约 §2）。第三源"已确认现网行为"当前 = **抓包级已到**（本仓引擎产出的正例 pcap 逐帧核对），但**真实服务器/开源实现的线字节未取到** → G-RTSP-8。

**12 ID 逐项回指**：#1←设计 §3.1/§3.3.1/§2；#2←§3.3.2/§3.3.3/§5.3；#3←§3.3.4；#4←§3.2；#5←§5.3；#6←§3.3 规则 9；#7←§3.3；#8←§3.5/§12.3；#9←§3.4；#10←§4；#11←§7 N-1；#12←§3.2。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 2326/7826/3550/4566 公开语义 + 仓库落码反推 + tshark 3.6.14 与 12 例实跑**，**非纯规范反推**（真实服务器线字节未取 → G-RTSP-8）。
- **对账两行**：**要求逻辑点总数 = 98**（八项 8 行 + 矩阵 36 格 + 变体 45 行 + 商业映射 17 行 —— 但八项 8 行与子表①②③有重叠，故**按子表三张独立计数**：36 + 45 + 17 = **98**）；**用例覆盖数 = 50**（矩阵已覆 18 + 变体已覆 23 + 商业已覆 9）；**不适用 = 1**（变体 45 行第 45 行“多会话”）；**开放立项 = 47**（矩阵 A′ 18 + 变体 A′ 21 + 商业 A′ 4 + 商业缺口立项 4）。50 + 1 + 47 = 98 ✓
  **粒度声明**：行/格粒度每点 1 计；**G-RTSP-1…G-RTSP-15 不折进 98**。**反查全绿 ≠ 覆盖全**。逐表重数见设计 §10.2（36 格 = 覆 18 + A′ 18 + 不适用 0）/§10.3（45 行 = 覆 23 + A′ 21 + 不适用 1）/§10.4（17 行 = 覆 9 + A′ 4 + 不解决 4）。
- **门3 抽查候选**：最复杂用例 = **#10 `rtsp_composite_full_session_media`**（18 帧：3 握手 + 10 信令（含自定义头、SDP body、Transport 双侧）+ 1 RTP（UDP 子流）+ 4 挥手；交织维度 = 方法(5)×方向(2)×体有无(2)×载体(2：TCP/UDP)）；**建议门3 抽 #10 + #8**（`rtsp_emit_media_rtp` 补纯媒体面）。

### 5.3 逐例断言强度评估（对抗审查用）

| # | `packet_count` | `fields` | `frames` | 唯一区分度 | 删掉该例会丢什么证据 |
|---:|---|---|---|---|---|
| 1 | 有 | 3 条 | 无 | OPTIONS 面 + 554 | 554 缺省 + OPTIONS 请求行 |
| 2 | 有 | 2 条 | 无 | **五方法 + Session 生命周期** | **CSeq/Session 关联（本协议核心）** |
| 3 | 有 | 无 | 无 | SDP body 透传 | Content-Length 计算 + 多行体 |
| 4 | 有 | 无 | 无 | 404 reason 缺省 | 非 200 状态行渲染 |
| 5 | 有 | 无 | 无 | 三事务 | PAUSE 方法面 |
| 6 | 有 | 无 | 无 | **URI 两写法** | 缺省 `/media` 与显式 `/live.sdp` |
| 7 | 有 | 无 | 无 | 用户头 + 自动头共存 | 头序规则 |
| 8 | 有 | 无 | 无 | **RTP 子流 + Transport 双侧** | **流关联（本协议必答项）** |
| 9 | 有 | 无 | 无 | **direction 覆盖** | **弱**：无 `ip.src` 断言（§3.9） |
| 10 | 有 | 无 | 无 | 复合交织 | 复合集成（非原子） |
| 11 | — | — | — | 负例锚词 | 唯一负例 |
| 12 | 有 | 无 | 无 | 200 reason 缺省 | 与 #4 互补 |

**结论**：12 例中 #9 的区分度仍需 `ip.src` 字段断言；#6 已通过不同 URI 字面区分；#8/#10 已具包数守卫；#3/#4/#7/#9/#12 仍无字段断言。整体断言以 `packet_count` 为主，`rtsp.*` 字段仍列 A′（G-RTSP-7）。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接多对事务（#2 五对、#5 三对、#10 五对） | **已覆** #2/#5/#10 |
| ② | 非正常结束 | 正常终止 = 自建 TCP 四次挥手（全正例）；**RST 零覆盖** | 已覆（挥手）；RST **A′ 立项**（G-RTSP-14——**注意本层自建 TCP，RST 需生成器构造，非框架能力**） |
| ③ | 长保活 | 协议层无 PING；`GET_PARAMETER`（§10.8）/`Session: timeout`（§12.37）**未实现** | **A′ 立项**（G-RTSP-10） |

无空项：① 有已覆例；② 有已覆例 + 1 条 A′ 立项；③ 1 条 A′ 立项（如实标红，不申报已过）。

### 6.2 A′/B′ 两分类表

**A′（P4 接线，本协议范围内）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 方法面 | `GET_PARAMETER`/`SET_PARAMETER`/`ANNOUNCE`/`RECORD`/`REDIRECT`/`PLAY_NOTIFY` 六方法 | G-RTSP-10 |
| 状态码面 | 454/455/表外码 | G-RTSP-10 |
| 头面 | RTP-Info 自动（**改挂 PLAY 响应**）/CSeq 用户重同步/Session 用户供给/Transport 用户覆盖/Content-Length 用户给 | G-RTSP-4/G-RTSP-10 |
| 媒体面 | 多帧（`frames:2`）/PT/FrameSize/端口/up 方向/file_source | G-RTSP-10 |
| 载体面 | IPv6（URI 方括号 + offset 74）/跨 MSS 分段 | G-RTSP-10 |
| 端口面 | 非默认控制端口（**须先补 rtsp 层端口键**） | G-RTSP-3 |
| 流面 | `flow_control.flows=3` 多流 | G-RTSP-11 |
| 负例面 | 顶层 `rtsp` 子映射 presence（**今日已通，会真红**） | 设计 §12-P2 |
| 静默路径转判死 | 空消息 / 非法 `direction`（**须先改实现**） | G-RTSP-9 |
| 非正常结束 | RST 补例（**须先生成器构造**） | G-RTSP-14 |
| 复现面 | 链路径注入 `initial_seq` | G-RTSP-12 |
| field 面 | 收编 `rtsp.*` 字段（**须先 `tshark -G fields` 实测**） | G-RTSP-7 |
| 产物面 | 重跑后补 `docs/protocol-pcap-test/rtsp/` pcap 留档 | G-RTSP-6 |

**B′（框架面）**：游离顶层未知键通用门（G-RTSP-15，等框架级 unknown-key 白名单，**不单独立项**）/ 层内业务字段动态（G-RTSP-3，allowlist 无 `rtsp` 行）。进设计 §14。

### 6.3 3.14 豁免边界审计

**有长连接载体（TCP）→ `sessions[]` 不豁免**——但本协议 raw 链**没有 `sessions[]` 数组**（单连接），故"多会话"面**显式不适用**（设计 §12.3/G-RTSP-11，链形态决定，非遗漏）；多流并发由策略级 `flow_control {"flows": N}` 承载（本版 12 例未用，存量单 flow）；**单包多载荷** = **不适用**（RTSP 每消息一个请求行/状态行，无多 question/多 RR 类形态，如实声明）；**流关联 = 适用且已覆**（#8/#10，控制流派生 RTP 媒体子流）——**本协议不豁免此项**。

## 7. 实现后执行建议

1. **cases 变更已落地**：#1 源端口说明校正、#5 包数说明校正、#6 显式 URI 改为 `/live.sdp`、#8/#10 改为 `frames:1` 并补 `packet_count`，媒体 notes 明确 PLAY 请求触发时响应无 RTP-Info。
2. **实测顺序**：先 #1（9 包基线 + 554）→ #2（CSeq/Session 关联，本协议核心）→ #3/#4/#12（reason/body 面）→ #5（三事务）→ #6/#7/#9（URI/头/方向面）→ #8/#10（媒体 + 复合，最后）。
3. **复跑方法（本车道已用，可复现）**：在 `trafficgen/test/protocol_pcap/layer_chain_suite_test.go` 的协议空导入块**临时**加 `_ "…/internal/protocol/rtsp"`（基线**不含 rtsp**，G-RTSP-2 同源问题），执行
   `CHAIN_PROTO=rtsp go test ./test/protocol_pcap/ -run TestLayerChainSuite -count=1` → **12/12 PASS**；**跑完必须回滚**（本车道已回滚，`git status --short` 零改动）。
4. **门2③ 二进制同代**：`find trafficgen -name '*.go' -newer <server-binary>` 无输出；门2② 全量（`CASE_PROTO=rtsp` 全量不是增量）；门2④ 反查绿后进 P6。
5. 任何 RFC 条款号的具体引用须有规范原文证据（G-RTSP-8 纪律）。

## 8. 存量审计（12 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/rtsp.json` **12 例**：11 正，其中 **11 例带 `packet_count`**（9/17/9/9/13/11/9/16/9/18/9）；1 负 `expect` 键集合 `{expect_error,error_contains}`（严格两键），实测 **0 包**；12/12 顶层键仅 `{layers}`（**零残留**）；链形 `[ip,rtsp]` ×12；**`fields` 断言仅 2 例**（#1 三条、#2 两条，共 5 条），**`frames` 断言 0 例**，**`rtsp.*` 字段 0 例**。**本车道今日实跑 12/12 PASS**（离线链套件，临时空导入已回滚）。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **历史 notes 矛盾已在本次修订清理**：① #1 单流源端口改为 **0**；② #5 包数改为 **13**；③ #8/#10 明确 `emit_media` 挂请求时响应无 RTP-Info（G-RTSP-4）。
2. **死配置已清理**：#8/#10 的 `media` 仅保留实际解析键（`direction`/`frames`），未知 `packets`/`payload` 已删除。
3. **#8/#10 已补 `packet_count`** → 帧数漂移由机器契约守卫。
4. **#6 显式 URI 已改为 `/live.sdp`**，与缺省 `/media` 区分。
5. **#9 无 `ip.src` 断言** → direction 覆盖未验证（§3.9）。
6. **`[ip,tcp,rtsp]` 静默 0 包**（G-RTSP-2）——链形态纪律今日靠"用户不写 tcp"维持，无代码守卫。
7. **结果产物 pcap 全悬空**（G-RTSP-6）——`docs/protocol-pcap-test/rtsp/` 目录不存在，11 条链接失效；**注意该文件末次提交 `ddfb40b` 2026-09-20 晚于判死提交 `0417be5` 2026-09-13，故不是"过期产物"，是"产物缺失"**。
8. **`rtsp.*` 字段零使用**（G-RTSP-7）。
9. **静默路径 4 条**（G-RTSP-9）：空消息 / 非法 direction / `media` 无 `emit_media` / `[ip,tcp,rtsp]`。
10. **状态机零执法**（G-RTSP-9）：455 永不自动产出；方法序非法可原样生成。
11. **链路径不可复现**（G-RTSP-12）：`initial_seq` 不可达。
12. **端口不可配**（G-RTSP-3）：rtsp 层无端口键 + 不能放 tcp 层。
13. **`SampleRate` 死字段**（G-RTSP-1）。

### 8.3 逐条去向表（12 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `rtsp_options_smoke` | T-1 | **保留** | 改 `notes` 源端口口径；补 `tcp.flags` 逐帧 + `rtsp.cseq` |
| `rtsp_play_session_full` | T-2 | **保留** | 补 CSeq 双向同号 + Session `same_as_packet` 断言；补 `rtsp.session` 格式 |
| `rtsp_describe_sdp_body` | T-3 | **保留** | 补 `Content-Length: 30` + body frames 断言（"跑后校准"落地） |
| `rtsp_response_404` | T-4 | **保留** | 补 `rtsp.status_code`/`rtsp.status_string` |
| `rtsp_pause_teardown` | T-5 | **改写** | **改 `notes` 算术**（15→13） |
| `rtsp_uri_explicit_and_default` | T-6 | **改写** | **显式 URI 改不同字面**（如 `/live.sdp`）否则分支不可区分 |
| `rtsp_headers_custom` | T-7 | **保留** | 补头序断言（CSeq index < User-Agent index） |
| `rtsp_emit_media_rtp` | T-8 | **改写** | ① 补 `packet_count=16`；② **删死配置 `packets`/`payload`**（改 `frames:2` 或改断言口径）；③ 改 `notes`（RTP-Info 事实）；④ 补端口同源断言（`client_port`=实际 UDP 端口） |
| `rtsp_direction_explicit` | T-9 | **改写** | **补 `ip.src` 断言**（帧 4=20.0.0.1 / 帧 5=10.0.0.1）否则分支不可区分 |
| `rtsp_composite_full_session_media` | T-10 | **改写** | ① 补 `packet_count=18`；② 删死配置；③ 改 `notes` |
| `rtsp_neg_dialog_required` | T-11 | **保留** | 严格两键负例：`expect_error` + `error_contains`；A′ 补顶层子映射 presence 负例 |
| `rtsp_status_text_default` | T-12 | **保留** | 补 `rtsp.status_string`=`OK` |

**统计**：**保留 7**（#1/#2/#3/#4/#7/#11/#12，各带补断言动作）、**改写 5**（#5/#6/#8/#9/#10）、**作废 0**、**等价覆盖 0**。**本协议存量 12/12 顶层零残留**（链形 12/12 恒 `[ip,rtsp]`）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

建议在主线程合入后，于 `coverage_gate.py` 的 rtsp 段登记下列断言（**每条均可从本契约与 cases JSON 直接机读，不需新造事实**）：

| # | 建议断言 | 依据 | 今日红/绿 |
|---:|---|---|---|
| 1 | `len(cases['rtsp']) == 12` 且 ID 集合 = §2 十二项，顺序一致 | 本契约 §2 | **绿** |
| 2 | 12/12 例 `spec_json` 顶层键 ⊆ `{layers}`（**本协议零游离键**） | 本契约 §1；设计 §12.1 | **绿** |
| 3 | 12/12 例链形 == `[ip,rtsp]`（**链上不得出现 tcp/udp**） | 设计 §2/G-RTSP-2 | **绿**（存量） |
| 4 | 11 正例 `packet_count == 7 + Σceil(len/MSS) + (emit_media ? max(frames,1) : 0)`；#8=16、#10=18 已具字段 | 设计 §9 公式 | **绿** |
| 5 | 1 负例 `expect` 键 == `{expect_error, error_contains}` | 本契约 §4 | **绿** |
| 6 | 负例 `error_contains` ∈ 代码锚词集 `{"dialog is required", "invalid source IP", "invalid destination IP", "MSS"}` | 设计 §7.1/§7.2 | **绿** |
| 7 | 非负例顶层键计数 == 0（**今日已成立**） | 设计 §12.1 | **绿** |
| 8 | 每正例至少一条 frames 断言落在 offset 54（IPv4）或 74（IPv6） | 本契约 §3 | **红**（frames 零使用，G-RTSP-7） |
| 9 | 无任何用例断言 `tcp.srcport`（**单流源端口实测 = 0**，断非 0 会假红） | 设计 §2/§11.7 | **绿** |
| 10 | 无任何用例断言 `PacketConfig.Direction == "down"`（**raw 链恒改写为 `"up"`**，断 down 会假绿） | 设计 §3.5/G-RTSP-4 | **绿** |
| 11 | `media` 块内不得出现 `packets`/`payload` 键（**解析集不含，已清理**） | 设计 §3.5/G-RTSP-1 | **绿** |
| 12 | 顶层 `rtsp` 子映射 presence 负例存在且锚词 ∈ `{"no longer accepts a top-level rtsp sub-config"}` | 设计 §12-P2 | **红**（A′ 未建，但**门已通**可建） |
| 13 | `notes` 内不得出现与实测相反的 RTP-Info 声明（已改写） | 设计 §3.3.5/G-RTSP-4 | **绿** |

**红项汇总**：**6 条红**（#4/#5/#8/#11/#12/#13）——按任务书要求**如实标红，不申报"今日已过"**。**绿项 7 条**。

## 10. 修订记录

- **v1.1.1（2026-10-01，C4 修订）**：唯一负例删除 `expect.notes`，严格收窄为 `expect_error` + `error_contains` 两键；同步负例形状、存量审计、反查门与设计文档。自审 2 轮，末轮干净。

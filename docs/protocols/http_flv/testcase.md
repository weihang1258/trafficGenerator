# #120 http_flv（HTTP-FLV）测试用例契约

> 版本：v1.0.0（批次二 as-built 文档轨）
> 日期：2026-09-29
> 配套设计：`docs/protocols/http_flv/design.md` v1.0.0（D-HTTPFLV-1）
> 旧基线：`docs/protocol-designs/45-http-flv-testcase.md` v3.0.0（文档列 15 例，实际 JSON 15 例；**承其 ID 集合与顺序**，冲突处按实测 pcap 与代码事实改正，见设计 §0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/http_flv.json`（**15 例，ID 与顺序与本版 §2 逐条一致，已机读实测**；顶层键 = `{http_flv, layers}`，见 §1）
> 白话一句：**十五条检查：十二条看正常收发（请求行、200 与 `video/x-flv`、三种 FLV 标签、空标签、边界长度、两轮保活、多会话、多流、IPv6），三条看胡来能不能被拦下；每条只查一件事。**
>
>> **文档阶段裁定（G-HTTPFLV-1）**：本协议当前属于“有 registry Fields、无 translate case”的空接线例外。层内 `http_flv` 配置暂不可执行，故 cases JSON 保持现状，不硬迁为不可调用形状；代码阶段先补 translator 接线，再迁移 15 例并全量复跑。当前 `spec_json` 顶层 `http_flv` 残留是已登记的待实现边界，不计作本阶段文档缺陷。

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **15 个唯一语义 ID：12 正 + 3 负**（负例 N-1/N-2/N-3）。派生规则：设计 §3 每个线格式条款、§5 每个事务/自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-10-01 机读实测复核）**：15 例仍全部维持过渡形状；**15/15 例的 `spec_json` 顶层键都是 `{http_flv, layers}`，不是纯 `{layers}`**。逐例性质判定（G-HTTPFLV-1 裁定，2026-10-01）：**12 正例的顶层 `http_flv` 全部是违规残留**——9 例（#1/#2/#3/#4/#5/#7/#10/#11/#12）为空 `{}`、3 例（#6/#8/#9）带业务值；**3 负例的顶层 `http_flv` 是业务校验的输入载体，不是故意的 presence 负例**（无任何负例以"证明框架拒绝层链 + 顶层同名键并存"为目的；该 presence 形状今日不被拒，设计 §12-P2 已裁定 P4 不建假负例）。正例顶层键在 translator 缺口关闭前不伪迁；负例保留业务输入以维持锚词可验证性。

| 项 | 实测值 |
|---|---|
| 例数 | **15**（12 正 + 3 负） |
| 例顶层键 | `{expect, id, proto, spec_json, summary}` ×15 |
| `spec_json` 顶层键 | **`{http_flv, layers}` ×15** —— 顶层 `http_flv` **15/15 存在**：正例 **12/12 均为违规残留**（空 `{}` ×9：#1/#2/#3/#4/#5/#7/#10/#11/#12；有值 ×3：#6/#8/#9）；负例 ×3 是业务校验输入，不是 presence 负例（G-HTTPFLV-1） |
| 层链形 | `[ip, http, http_flv]` ×15（层内 `http_flv` 条目恒 `{}`，零负载；正例因此不能宣称业务配置已住层内） |
| 正例 `expect` 键 | `{packet_count, directional, fields?, frames?}`；**`directional` 恒 `true`** ×12；`fields` 6 例有 / 6 例无；`frames` 8 例有 / 4 例无 |
| 负例 `expect` 键 | **严格两键** `{expect_error, error_contains}` ×3 ✓ |
| 共用 spec | **8 例 spec_json 完全相同**（#1/#2/#3/#4/#5/#7/#10/#12） |

### 1.1 逐例顶层 `http_flv` 键性质判定表（G-HTTPFLV-1 裁定，2026-10-01 机读复核）

**判定依据**：① `expect.expect_error` 为真 = 业务失败路径用例，其顶层 `http_flv` 是触发 validator 的业务输入 → **不是 presence 负例**；② `expect_error` 为假 = 成功路径用例，其顶层 `http_flv` 不参与层链配置，只被 `strategy_convert.go:832` 单读一次 → **违规残留**（CORE §1.11 顶层白名单不含协议子映射）。**本协议零条故意 presence 负例**（该形状今日不被拒，设计 §12-P2 裁定 P4 不建假负例，建了会真绿＝假通过）。

| # | ID | 正/负 | 顶层 `http_flv` 值 | 性质判定 | 处理 |
|---:|---|---|---|---|---|
| 1 | `http_flv_get_header` | 正 | `{}` | **违规残留** | 保留现状；P4 补 translate case 后删除该键 |
| 2 | `http_flv_header_flags` | 正 | `{}` | **违规残留** | 同上 |
| 3 | `http_flv_script_tag` | 正 | `{}` | **违规残留** | 同上 |
| 4 | `http_flv_audio_aac` | 正 | `{}` | **违规残留** | 同上 |
| 5 | `http_flv_video_avc` | 正 | `{}` | **违规残留** | 同上 |
| 6 | `http_flv_empty_tag` | 正 | `{flags:1, tags:[…], rounds:1}` | **违规残留**（带业务值） | 同上，迁入计划见设计 G-HTTPFLV-1 |
| 7 | `http_flv_minimal_tags` | 正 | `{}` | **违规残留** | 同上 |
| 8 | `http_flv_tag_boundary` | 正 | `{flags:5, tags:[…data_size_override…], rounds:1}` | **违规残留**（带业务值） | 同上 |
| 9 | `http_flv_keep_alive` | 正 | `{flags:5, rounds:2}` | **违规残留**（带业务值） | 同上 |
| 10 | `http_flv_multi_session` | 正 | `{}` | **违规残留** | 同上；名实不符另计 G-HTTPFLV-5 |
| 11 | `http_flv_ipv6` | 正 | `{}` | **违规残留** | 同上 |
| 12 | `http_flv_multi_stream` | 正 | `{}` | **违规残留** | 同上；名实不符另计 G-HTTPFLV-5 |
| 13 | `http_flv_neg_truncated_tag` | 负 | `{tags:[{type:"unknown",…}], rounds:1}` | **业务校验输入**（非 presence 负例） | 保留；断言 `error_contains="tag"` 依赖它命中 `planner.go:91` |
| 14 | `http_flv_neg_length_mismatch` | 负 | `{flags:5, rounds:-1}` | **业务校验输入**（非 presence 负例） | 保留；断言 `error_contains="rounds"` 依赖它命中 `planner.go:83` |
| 15 | `http_flv_neg_validate` | 负 | `{flags:255, rounds:1}` | **业务校验输入**（非 presence 负例） | 保留；断言 `error_contains="flags"` 依赖它命中 `planner.go:80` |

**空/有值分布（机读）**：正例 12 = 空 `{}` ×9（#1/#2/#3/#4/#5/#7/#10/#11/#12）+ 有值 ×3（#6/#8/#9）；负例 3 = 有值 ×3。**层内 `layers[].http_flv` 15/15 恒 `{}`**——即 15 例均无法证明"层内配置可执行"，该能力今日为零（G-HTTPFLV-1，§9 建议断言行 7/9 如实标红）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`、`http.request.method/uri`、`http.response.code`、`http.content_type`、`ipv6.nxt`、frame 原始 hex）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。**本协议 15 例今日只走 pcap 路径**（离线套件），NIC 路径未复跑（设计 G-HTTPFLV-10）。

**TSHARK 基线**：本机 tshark 3.6.14 对 HTTP/TCP/IPv6 有稳定 dissector。**今日 15 例实际只用 6 个字段名**（去重）：`tcp.dstport`、`http.request.method`、`http.request.uri`、`http.response.code`、`http.content_type`、`ipv6.nxt`。旧稿 testcase §1 列举的 `http.request.version`、`http.connection`、`tcp.srcport`、`tcp.stream`、`ip.version` **零使用**（设计 §0 #15）。**FLV 无 tshark dissector**，故 FLV 字节一律用 `frames` 原始 hex 断言（`tcp.payload` 可辅助定位，但不作断言通道）。

**断言基线**：今日 15 例只用 `packet_count` + `directional` + `fields`（6 字段名）+ `frames`（10 条）；**`has_handshake`/`terminates`/`has_payload`/`negotiated`/`min_packets`/`decode_as`/`nic_capture`/`notes` 全部零使用**（机读实测）。**10 条 frame 断言已逐条对实测 pcap 复核（10/10 字节一致）**。

**动态字段禁止硬编码**：FLV 内无生成期可变值（timestamp 恒 0、StreamID 恒 0、DataSize 由 `len(data)` 定）；HTTP 侧 `Content-Length` 随 body 长度确定，**非随机**。

**包数约定（实测公式，设计 §9）**：单流 = 3（TCP 握手）+ 2×`rounds`（GET/200 对）+ 4（FIN 四包）= **`7 + 2×rounds`**。校验：rounds=1 → 9（11 例 ✓）；rounds=2 → 11（#9 ✓）。负例无 `packet_count`（实测 3 例 pcap 均 **0 帧**）。

**保活/重试/RST 口径**：`rounds>1` 时前几轮 `Connection: keep-alive`、末轮 `close`（`layer_gen.go:186`）；**协议无重试/无心跳**；RST 为框架 tcp 层能力，本协议层**零断言**（A′ 补例，设计 G-HTTPFLV-7）；正例恒 FIN 优雅终止。

## 2. 原子用例索引（15 ID = 12 正 + 3 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count（实测） | 断言形态 |
|---:|---|---|---|---:|---|
| 1 | `http_flv_get_header` | 正 | §3.1：GET 请求行 + Host + HTTP/1.1 | 9 | fields×3 + frames×1 |
| 2 | `http_flv_header_flags` | 正 | §3.1：200 + `video/x-flv` | 9 | fields×2 + frames×1 |
| 3 | `http_flv_script_tag` | 正 | §3.5：AMF0 onMetaData 6 键 | 9 | frames×1 |
| 4 | `http_flv_audio_aac` | 正 | §3.6：AAC seq header | 9 | frames×1 |
| 5 | `http_flv_video_avc` | 正 | §3.7：AVC seq header | 9 | frames×1 |
| 6 | `http_flv_empty_tag` | 正 | §8：DataSize=0 边界（**名义**，§9.2a） | 9 | frames×1 |
| 7 | `http_flv_minimal_tags` | 正 | §3.5–3.7：三标签齐备 | 9 | frames×3 |
| 8 | `http_flv_tag_boundary` | 正 | §8：UI24 DataSize 边界（**声明**，§9.2b） | 9 | frames×1 |
| 9 | `http_flv_keep_alive` | 正 | §3.1：rounds=2 两对 GET/200 | 11 | fields×2 |
| 10 | `http_flv_multi_session` | 正 | §5：多会话（**名义**，§9.2c） | 9 | fields×2 |
| 11 | `http_flv_ipv6` | 正 | §2：IPv6 外层（offset 74） | 9 | fields×3 |
| 12 | `http_flv_multi_stream` | 正 | §5：多流 StreamID=0（**名义**，§9.2d） | 9 | fields×2 |
| 13 | `http_flv_neg_truncated_tag` | 负 | §7 N-1：未知 tag 类型 | —（实测 0 帧） | `{expect_error, error_contains}` |
| 14 | `http_flv_neg_length_mismatch` | 负 | §7 N-2：rounds 负值 | —（实测 0 帧） | 同上 |
| 15 | `http_flv_neg_validate` | 负 | §7 N-3：flags 保留位 | —（实测 0 帧） | 同上 |

**T-编号对照**：本版沿用旧稿 `45-http-flv-testcase` §2 的 15 项顺序（**JSON 顺序 = 本表顺序 = 权威**，机读实测一致）。**序号以 cases JSON 顺序为准**。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count` + `directional`；帧位由 §1 公式与实测 pcap 双向确认。**offset 为帧绝对偏移**。

### 3.1 `http_flv_get_header`（9）

`layers=[{ip:{src:192.0.2.10,dst:198.51.100.20}},{http:{method:GET,uri:/live/test.flv,version:HTTP/1.1}},{http_flv:{}}]`；顶层 `http_flv={}`。

- `packet_count=9`、`directional=true`。
- `fields`：p4 `tcp.dstport=80`、p4 `http.request.method=GET`、p4 `http.request.uri=/live/test.flv`。
- `frames`：p4 @54 = `47 45 54 20 2f 6c 69 76 65 2f 74 65 73 74 2e 66 6c 76 20 48 54 54 50 2f 31 2e 31 0d 0a`（`GET /live/test.flv HTTP/1.1\r\n`，29B）。
- **实测复核**：帧 4 tcp payload 起点 54 ✓；帧 1–3 握手、帧 6–9 FIN 四包 ✓。

### 3.2 `http_flv_header_flags`（9）

spec 同 #1（**逐字节相同**）。

- `fields`：p5 `http.response.code=200`、p5 `http.content_type=video/x-flv`。
- `frames`：p5 @119 = `43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 63 6c 6f 73 65 0d 0a 0d`（`Connection: close\r\n\r`，20B）。
- **诚实声明（§9.2a）**：该 frame 断言落在 **HTTP 头**，**不覆盖 FLV header 的 signature/version/flags/DataOffset/PreviousTagSize0**（旧稿 testcase §4.1 声称覆盖 FLV header，与实测不符）。FLV header 实际位置 @140（`46 4c 56 01 05 00 00 00 09 00 00 00 00`）。

### 3.3 `http_flv_script_tag`（9）

spec 同 #1（走默认三标签模板：script + audio + video）。

- `frames`：p5 @132 = `6c 6f 73 65 0d 0a 0d 0a 46 4c 56 01 05 00 00 00 09 00 00 00`（`lose\r\n\r\n` + FLV header 9B + `PreviousTagSize0` 首 2B，20B）。
- **实测复核**：帧 5 FLV@140，assert@132 起 20 字节覆盖 `lose\r\n\r\n`（8B）+ `FLV 01 05 00 00 00 09`（9B）+ `00 00 00`（PrevTagSize0 首 3B）✓。
- **实测 FLV body 内容**：script tag type=18、DataSize=**139**、PreviousTagSize=150；其后 audio tag type=8、DataSize=4；video tag type=9、DataSize=48（§3.5–3.7 复算一致）。

### 3.4 `http_flv_audio_aac`（9）

spec 同 #1。

- `frames`：p5 @139 = `0a 46 4c 56 01 05 00 00 00 09 00 00 00 00 12 00 00 8b 00 00`（20B）。
- **实测复核**：`0a`（`Content-Length` 末位）+ FLV header 9B + `PreviousTagSize0` 4B + tag0 `12` + DataSize `00 00` ✓。
- **实测音频 tag 内容**（设计 §3.6）：type=8、DataSize=4、data = `a5 00 11 90`（首字节 `a5` = AAC/22kHz/16-bit/**stereo**）。
- **诚实声明**：frame 断言**不覆盖** audio tag 的 data 首字节 `a5`（旧稿 §4.4 声称"frame 固定 `08` 与 `a0`"，与实测 `a5` 不符，设计 §0 #6）；AAC raw（PacketType=1）**实现不可达**。

### 3.5 `http_flv_video_avc`（9）

spec 同 #1。

- `frames`：p5 @146 = `00 00 09 00 00 00 00 12 00 00 8b 00 00 00 00 00 00 00 02 00`（20B）。
- **实测复核**：assert@146 起 20 字节 = FLV header 尾 3B（DataOffset `00 00 09`）+ `PreviousTagSize0` 4B + tag0 `12 00 00 8b` + tag0 data 首字节 `00` + … ✓。
- **诚实声明**：frame 断言**不覆盖** video tag 的 `17` 首字节（旧稿 §4.5 声称"frame 固定 `09` 与 `17 00 00 00`"，与实测不符）；AVC NALU（PacketType=1）/ end-of-sequence（2）**实现不可达**（设计 §3.7）。

### 3.6 `http_flv_empty_tag`（9）

顶层 `http_flv={flags:1, tags:[{type:script,timestamp:0,data:[]}], rounds:1}`；**层内 `http_flv` 仍 `{}`**。

- `frames`：p5 @119 = **与 #2 逐字节相同**（`Connection: close\r\n\r`）。
- **实测线内容**：FLV flags=**`01`**（顶层 `flags:1` 生效 ✓）；tag0 type=18、**DataSize=139**（**不是 0**）。
- **诚实声明（§9.2a）**：摘要称 "Empty script tag with **DataSize=0**"，**实际 DataSize=139**——`resolveTag` 的 script 分支在 `Data` 为空时**不产空 tag，而产 139 字节默认 onMetaData**（设计 §3.5/§8）。且 frame 断言**未覆盖任何 FLV 字节**，与 #2 完全重复。**本用例今日不满足"删除后失去直接证据"的原子判据** → P4 改写（G-HTTPFLV-2）。

### 3.7 `http_flv_minimal_tags`（9）

spec 同 #1。

- `frames`：p5 @132 / @139 / @146（三条，与 #3/#4/#5 **同一组字节**、同一帧、同 offset）。
- **实测复核**：三条 20B 断言逐条字节一致 ✓。
- **诚实声明**：三条断言覆盖的是 **FLV header 区**（+ tag0 头部），**未分别覆盖 script/audio/video 三个 tag 的各自 data**（旧稿 §4.7 声称"三个 tag 各自至少观察 tag type/DataSize/timestamp/PreviousTagSize"，与实测不符）。

### 3.8 `http_flv_tag_boundary`（9）

顶层 `http_flv={flags:5, tags:[{type:script,timestamp:0,data:[39B AMF0…],data_size_override:65536}], rounds:1}`。

- `frames`：p5 @132 = `6f 73 65 0d 0a 0d 0a 46 4c 56 01 05 00 00 00 09 00 00 00 00`（20B）。
- **实测线内容**：tag0 type=18、TagHeader 声明 **DataSize=65536**、实际 data **39 字节**、PreviousTagSize=**50**（`11+39`，按**实际**长度算，非声明值）。
- **诚实声明（§9.2b）**：① 摘要称 "24-bit DataSize boundary"，但 **65536 远在 UI24 内（上限 16777215），不是边界**；② frame 断言**只覆盖 FLV header**，**未覆盖 DataSize 三字节**（@152 起 `01 00 00`）。**UI24 满值（0xffffff）今日零用例** → A′ 立项（G-HTTPFLV-6）。

### 3.9 `http_flv_keep_alive`（11）

顶层 `http_flv={flags:5, rounds:2}`。

- `packet_count=11`、`directional=true`。
- `fields`：p4 `http.request.method=GET`、p5 `http.response.code=200`。
- **包数证据**：rounds=2 → `7 + 2×2` = 11 ✓。
- **实测复核**：帧 4/5 = 第 1 轮（`Connection: keep-alive`，FLV@145）；帧 6/7 = 第 2 轮（`Connection: close`，FLV@140）；两轮 FLV flags 均 `05`、body 均 249B；帧 8–11 FIN 四包 ✓。
- **诚实声明**：`fields` 只断言帧 4/5（第 1 轮），**未断言第 2 轮存在**（旧稿 §4.9 声称"分别断言第二 transaction 的 GET 与第二组 tag"，与实测不符）；`tcp.stream` 恒 0（同一连接）**未断言**。

### 3.10 `http_flv_multi_session`（9）

spec **与 #1 逐字节相同**（顶层 `http_flv={}`）。

- `fields`：p4 `http.request.method=GET`、p5 `http.response.code=200`。
- **实测线内容**：**单会话**——`tcp.stream` 恒 `0`、仅 1 对 GET/200、9 帧。
- **诚实声明（§9.2c）**：摘要称 "Multiple independent TCP sessions with isolated state"，**实现无多会话能力**（`HTTPFLVConfig` 无 `sessions` 字段，`Generate` 只按 `rounds` 循环，设计 §5/G-HTTPFLV-5）。**本用例今日断言与单会话实现一致（故绿），但摘要声称的语义未被验证**；且 spec 与 #1 相同 → **删除后无证据损失** → P4 改写。

### 3.11 `http_flv_ipv6`（9）

`layers[0].ip={src:2001:db8::1, dst:2001:db8::2}`；其余同 #1。

- `fields`：p4 `ipv6.nxt=6`、p4 `tcp.dstport=80`、p4 `http.request.method=GET`。
- **协议与地址族解耦证据（实测）**：帧 4/5 的 HTTP 起点 **74**（= 14+40+20）、FLV 起点 **160**（= 74+86）；FLV 字节与 IPv4 例**完全相同**（`46 4c 56 01 05 00 00 00 09`）。
- **诚实声明**：无 frame 断言（旧稿 §4.11 声称"FLV header offset 139"作废，实测 160；设计 §0 #3）。

### 3.12 `http_flv_multi_stream`（9）

spec **与 #1 逐字节相同**（顶层 `http_flv={}`）。

- `fields`：p4 `http.request.method=GET`、p5 `http.response.code=200`。
- **实测线内容**：**单会话**（同 #10）。
- **诚实声明（§9.2d）**：摘要称 "Multiple streams with StreamID=0"，**实现无多流能力**；`StreamID` 恒 `00 00 00` 是**实现常量**（`builder.go:77`），**不是"多流映射"的结果**。spec 与 #1 相同 → P4 改写。

**正例总则**：`rounds>1`、IPv6、`DataSizeOverride`、空 `Tags`（走默认模板）均为正例形态；只有配置错误（flags/rounds/tag 类型）进入负例。

## 4. 负例契约（C4 对账）

本节对应审查清单 C4：三条负例均保留真实拒绝锚词，且 `expect` 不混入任何成功断言键。

负例必须在 validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功（**实测 3 例 pcap 均 0 帧**，文件名 `<id>.neg.pcap`）。锚词与设计 §7 表一一对应、同序（代码逐字，`planner.go` 实测行号）：

| ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（`planner.go` 逐字） | 代码行 |
|---|---|---|---|---|
| `http_flv_neg_truncated_tag` | `tags[0].type="unknown"` | `tag` | `http_flv: tag[%d] unknown type %q` | `planner.go:91` |
| `http_flv_neg_length_mismatch` | `rounds=-1` | `rounds` | `http_flv: rounds %d must be >= 0` | `planner.go:83` |
| `http_flv_neg_validate` | `flags=255` | `flags` | `http_flv: flags 0x%02x has reserved bits set (only bit0=video, bit2=audio allowed)` | `planner.go:80` |

**锚词口径**：`error_contains` 是**子串**判定；三例分别命中 `tag` / `rounds` / `flags`（均含前缀 `http_flv: `）。

**负例原子性**：每例单一故障注入；单次执行不得混注。三例 `expect` 键集合**严格两键** = `{expect_error, error_contains}` ✓（机读实测，合需求 §7 负例纯净性；**无 `notes` 键**，与 opcua 存量不同）。

**语义命名偏差（G-HTTPFLV-3，设计 §0 #9）**：① `http_flv_neg_truncated_tag` 名为"截断"，**实际注入的是未知 tag 类型**（`wire_fault="truncated"` 今日零用例）；② `http_flv_neg_length_mismatch` 名为"长度不一致"，**实际注入的是 rounds 负值**（`previous_size_override` 今日零用例）。**两例摘要与注入不符，P4 改写。**

**validator 三分支全集（设计 §7）**：`HTTPFLV == nil` → 通过；`Flags & 0x05 != Flags` → 拒；`Rounds < 0` → 拒；`Tags[i].Type ∉ {script,audio,video}` → 拒。**除这三支外无其它拒绝分支**（旧稿 testcase §5 的三行故障描述中，"tag header 少于 11B"、"DataSize 超过剩余 body"、"method 非 GET"、"HTTP/1.0"、"sessions=0"、"缺 TCP"、"非法地址"**均无对应实现**，设计 §0 #8）。

**未入用例的拒绝/失败分支（A′ 立项，不得冒充已覆盖）**：

| 分支 | 代码位置 | 今日用例 |
|---|---|---|
| `wire_fault="truncated"`（body > 16） | `builder.go:214-219` | **零**（G-HTTPFLV-3） |
| `wire_fault="truncated"`（body ≤ 16） | `builder.go:215-217` | **零** |
| `PreviousSizeOverride` 注入 | `buildFLVTag:64-66` | **零**（G-HTTPFLV-3） |
| `EmitMsg == nil` | `planner.go:29-31` | 单测覆盖，**无用例** |
| `EmitEvent` 直调 | `planner.go:67-69` | 单测覆盖，**无用例** |
| inner stream closed before body event | `layer_gen.go:199` | **零** |

## 5. 覆盖与对账

### 5.1 三源回指行

Adobe FLV Spec v10.1 + AMF0 Spec + RFC 9112/9110（设计 §10）+ D-HTTPFLV-1（设计 §11）+ tshark 3.6.14 字段表与 **15 例实测 pcap**（`/tmp/mcp-pcaps/http_flv/`，**2026-09-29 本车道复跑**）→ 15 ID（本契约 §2）。第三源"已确认现网行为"当前 = **抓包级已到**（本仓引擎产出的 15 例 pcap 逐帧核对），但**真实 HTTP-FLV 服务器（nginx-rtmp/SRS）的线字节未取到** → G-HTTPFLV-8（按 §5.5 不写死进实现）。

**15 ID 逐项回指（设计 §9 表）**：#1←§3.1；#2←§3.1；#3←§3.5；#4←§3.6；#5←§3.7；#6←§8；#7←§3.5–3.7；#8←§8；#9←§3.1/§5；#10←§5；#11←§2；#12←§5；#13←§7 N-1；#14←§7 N-2；#15←§7 N-3。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **Adobe FLV/AMF0 公开语义 + RFC 9112/9110 + 旧基线契约 + 仓库落码反推 + tshark 3.6.14 字段与 pcap 实测**，**非纯规范反推**（Adobe spec 的 AMF0 键序强制力未逐条核对 → G-HTTPFLV-8）。
- **对账两行**：**要求逻辑点总数 = 67**（八项 8 行 + 矩阵 27 格 + 变体 20 行 + 商业映射 12 行）；**用例覆盖数 = 35**（八项已覆 5 + 矩阵已覆 13 + 变体已覆 12 + 商业已覆 5）；**不适用 = 9**（八项 1 + 矩阵 2 + 商业 6）；**开放立项/缺口 = 23**（八项 2 + 矩阵 A′ 12 + 变体立项 8 + 商业名义缺口 1）。35 + 9 + 23 = 67 ✓
  **粒度声明**：行/格粒度每点 1 计；G-HTTPFLV-1…G-HTTPFLV-11 不折进 67。**反查全绿 ≠ 覆盖全**（§9.52 原文）。逐表重数见设计 §10.1（八项 8 = 覆 5 + 立项 2 + 不适用 1）/§10.2（27 格 = 覆 13 + A′ 12 + 不适用 2）/§10.3（20 行 = 覆 12 + 立项 8）/§10.4（12 行 = 覆 5 + 不适用 6 + 名义缺口 1）。
  **粒度声明**：行/格粒度每点 1 计；G-HTTPFLV-1…G-HTTPFLV-11 不折进 67。**反查全绿 ≠ 覆盖全**（§9.52 原文）。
- **门3 抽查候选**：最复杂用例 = **#9 `http_flv_keep_alive`**（11 帧：握手 3 + 两对 GET/200 + FIN 4；交织维度 = 轮次(2)×Connection 值(2)×FLV 起点(2)）；**建议门3 抽 #9 + #8**（`tag_boundary` 补 DataSizeOverride 面）。

### 5.3 旧 id 对照

旧稿 `45-http-flv-testcase.md` §2 的 15 项与本版 **ID 集合与顺序完全一致**（机读实测），无 T-编号重排。旧稿 §4 的"未来正例逐项断言"（12 条）今日**部分未落地**（§9.2 四条偏差 + §3 各条诚实声明），**本版以实测为准**。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接 `rounds` 对 GET/200（#9 两轮） | 已覆 #9 |
| ② | 非正常结束 | 正常 FIN 全正例 + `Connection: close`；应用层正常终止 = 末轮 close；传输异常 = RST（框架 tcp 层能力） | 已覆（FIN 全正例）；RST **A′ 立项**（G-HTTPFLV-7，本层零断言） |
| ③ | 长保活 | HTTP/1.1 keep-alive（#9 第 1 轮 `Connection: keep-alive`）；**协议无心跳/无超时重试** | 已覆 #9 |

无空项：① 有已覆例；② 有已覆例 + 1 条 A′ 立项；③ 有 #9。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| **层内配置面（最高优先）** | 补 `case "http_flv"` 使层内 `flags/rounds/tags` 生效，15 例 `spec_json` 迁纯 `layers` 形 | **G-HTTPFLV-1** |
| 断言语义面 | #2/#6/#8 断言改落 FLV 字节（含 DataSize 三字节）；#10/#12 摘要改写或补实现 | G-HTTPFLV-2 |
| 负例语义面 | #13/#14 摘要改写；补 `wire_fault` / `previous_size_override` 例 | G-HTTPFLV-3 |
| 边界面 | DataSize UI24 满值 / Timestamp 非零回绕 / 非默认端口 / 异族混写 | G-HTTPFLV-6 |
| 标签变体面 | script 自定义 `Data` 透传；`flags=0x04`；`flags=0x00`；rounds=3 包数外推 | G-HTTPFLV-2 |
| 非正常结束 | `tcp.rst` 补例 | G-HTTPFLV-7 |
| 死代码面 | `buildAudioAACData`/`buildVideoAVCData` 删或接线 | G-HTTPFLV-11 |

**B′（框架面）**：`CheckProtoFlat` 无 `http_flv` 子映射判死分支 + 无游离顶层键通用门（G-HTTPFLV-1，等框架级 unknown-key 白名单，**禁加单协议黑名单**）/ 业务字段动态（allowlist 无 `http_flv` 行，G-HTTPFLV-2）/ NIC 双输出复跑（G-HTTPFLV-10）/ 结果文档重生成（G-HTTPFLV-9）。进设计 §14，「明确不解决 + 迁入计划」。

### 6.3 3.14 豁免边界审计

**有长连接载体（TCP）→ `sessions[]` 不豁免**；但本协议**无 `sessions[]` 数组**（`HTTPFLVConfig` 无 `sessions` 字段，设计 §5）——多会话语义**未实现**（G-HTTPFLV-5），**形态差异已声明**；多流并发由策略级 `flow_control {"flows": N}` 承载（本版 15 例未用，存量单 flow）；**单包多载荷** = **不适用**（HTTP-FLV 每响应一个 FLV body，无多 question/多 RR 类形态，如实声明）。

## 7. 实现后执行建议

1. **P4 顺序**：①**先补 `case "http_flv"`**（G-HTTPFLV-1）→ 层内配置生效；②15 例 `spec_json` 迁纯 `layers` 形（删顶层 `http_flv` 子映射，值搬入层内）；③改写 #2/#6/#8 断言（落 FLV 字节 + DataSize 精确断言）；④改写 #10/#12 语义（多会话未实现）；⑤改写 #13/#14 摘要；⑥补 A′ 例（`wire_fault`/`previous_size_override`/flags 变体/边界/RST）；⑦全量复跑。
2. **实测顺序**：先 #1（请求行 @54 基线），再 #3（FLV header @140 基线），再 #4/#5（tag 内容），再 #9（两轮 + FLV 起点 145/140 差），最后 #11（IPv6 起点 74/160）。
3. 二进制与 HEAD 同代确认（门2③）；门2② 全量（`CASE_PROTO=http_flv` 全量不是增量）；门2④ 反查绿后进 P6。
4. 任何 Adobe spec 条款号的具体引用须有规范原文证据（G-HTTPFLV-8 纪律）。

## 8. 存量审计（15 例逐条去向）

### 8.1 存量实测面（2026-09-29 本车道复跑）

`cases/http_flv.json` **15 例**：12 正带 `packet_count`（9×11 + 11×1），**与实测 pcap 帧数 12/12 逐例一致**（`tshark -r … | wc -l`）；3 负 `expect` 键集合严格两键，实测 pcap 均 **0 帧**；**15/15 顶层键 = `{http_flv, layers}`**。逐例性质复核：正例 12/12 是违规残留（空 `{}` ×9：#1/#2/#3/#4/#5/#7/#10/#11/#12；有值 ×3：#6/#8/#9）；负例 3/3 是业务校验输入，不是故意 presence 负例；层链恒 `[ip, http, http_flv]` 且层内 `http_flv` 条目恒 `{}`；**10 条 frame 断言逐条对实测 pcap 复核（10/10 字节一致）**；8 例 `spec_json` **完全相同**。

**今日复跑证据（2026-09-29）**：
- 套件：`PCAP_ROOT=/tmp/mcp-pcaps MCP_API_KEY=dev-mcp-key CASE_PROTO=http_flv go test ./test/protocol_pcap/ -run TestProtocolPcapDrive -count=1` → **PASS**，`http_flv 15/15`。
- pcap 全部 **2026-09-29 01:11** 重新生成（非陈旧产物）。
- 包数 12/12 一致；frame 断言 10/10 一致。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **顶层 `http_flv` 子映射 15/15 残留（G-HTTPFLV-1，最高优先）**：**层内 http_flv 配置今日不被解码**（`chain_planner_translate.go` 的 `switch term.Name` 无 `case "http_flv"`，`grep` 零命中；`:789-806` 块只补默认值、不读 `term.Config`）。**实测**：层内 `{flags:1,rounds:2}` → 最终 `flags=0x5 rounds=1`（值全丢）；顶层 `{flags:1,rounds:2}` → 生效。**今日唯一活着的配置载体是顶层子映射**，而它违反 CORE_MEMORY §1 顶层白名单，且 `CheckProtoFlat` **无 http_flv 子映射判死分支**（`:8643` 只判顶层 `http`）→ 违规形状今日**不被拒**。§1 目标形状今日**不可达**；收官自查「非负例顶层键 = 0」**今日不成立**（**如实标红**）。
2. **断言语义偏差 4 条（G-HTTPFLV-2）**：§9.2 的 a/b/c/d —— #6 "DataSize=0" 实为 139；#8 "24-bit 边界" 实为 65536 且断言未覆盖；#10/#12 多会话/多流未实现；8 例共用同一 spec（#10/#12 删除后无证据损失）。
3. **负例语义与注入不符（G-HTTPFLV-3）**：#13 名为"截断"实为未知 tag 类型；#14 名为"长度不一致"实为 rounds 负值；`wire_fault`/`previous_size_override` 已落码零用例。
4. **多会话/多流未实现（G-HTTPFLV-5）**：`HTTPFLVConfig` 无 `sessions`/`streams` 字段；#10/#12 实测单会话（`tcp.stream` 恒 0、1 对 GET/200）。
5. **旧稿错误表 5/8 行未落码（设计 §0 #8）**：testcase §5 描述的"tag header 少于 11B"、"DataSize 超过剩余 body"、"method 非 GET"、"HTTP/1.0"、"sessions=0"、"缺 TCP"、"非法地址"**均无实现**。
6. **旧稿"字段优先使用"是意图非事实（设计 §0 #15）**：`http.connection`/`tcp.stream`/`ip.version`/`http.request.version`/`tcp.srcport` 今日**零使用**。
7. **死代码（G-HTTPFLV-11）**：`buildAudioAACData`（`builder.go:173`）与 `buildVideoAVCData`（`builder.go:193`）**零生产调用方**；前者内部 `if/else if` 链无操作（`builder.go:174-185`）。
8. **结果文档过期（G-HTTPFLV-9）**：tracked 产物 `trafficgen/docs/protocol-pcap-test/http_flv.md` 写 "Cases: 15 — pass 15"，但末次提交 `e7e7d1c`（**2026-08-27**）早于判死提交 `0417be5`（2026-09-13）；`docs/protocol-pcap-test/http_flv/` **0 个 pcap**（目录不存在），文档内 15 条 pcap 链接**全部死链**。**本车道今日已另行复跑**（§8.1），故 15/15 今日成立——但**过期产物本身不得作为依据**。归属**代码阶段**（P5 重跑套件后重生成该产物）。
9. **NIC 双输出未复跑（G-HTTPFLV-10）**：本车道只跑 pcap 离线套件。

### 8.3 逐条去向表（15 行）

| 存量 id | 去向 | 改写动作（P4） |
|---|---|---|
| `http_flv_get_header` | **保留** | 形状迁层内；请求行断言有效 |
| `http_flv_header_flags` | **改写** | frame 断言 @119 落在 HTTP 头 → 改落 FLV header（@140） |
| `http_flv_script_tag` | **保留** | 形状迁层内；断言覆盖 FLV header + tag0 头部 |
| `http_flv_audio_aac` | **保留** | 可补 audio tag data 首字节 `a5` 断言 |
| `http_flv_video_avc` | **保留** | 可补 video tag data 首字节 `17` 断言 |
| `http_flv_empty_tag` | **改写** | 语义（DataSize=0）未实现且未断言；与 #2 断言重复 → 改断 `flags=0x01` + 实 tag 内容 |
| `http_flv_minimal_tags` | **保留** | 三条断言覆盖 FLV header 区；可扩为逐 tag 断言 |
| `http_flv_tag_boundary` | **改写** | 断 FLV header 非 DataSize；65536 非边界 → 改断 DataSize 三字节 + 补 UI24 满值例 |
| `http_flv_keep_alive` | **保留** | 包数 11 与两轮断言有效；可补第 2 轮断言 + `Connection` 值断言 |
| `http_flv_multi_session` | **改写** | 多会话未实现；spec 与 #1 等价 → 补实现或改写摘要/断言 |
| `http_flv_ipv6` | **保留** | `ipv6.nxt=6` + offset 74/160 路径有效 |
| `http_flv_multi_stream` | **改写** | 同 #10；StreamID 恒 0 是常量非多流结果 |
| `http_flv_neg_truncated_tag` | **改写** | 语义是"未知 tag 类型"非"截断"；补 `wire_fault` 例 |
| `http_flv_neg_length_mismatch` | **改写** | 语义是"rounds 负值"非"长度不一致"；补 `previous_size_override` 例 |
| `http_flv_neg_validate` | **保留** | flags 保留位锚词正确 ✓ |

**去向统计：0 作废；保留 9（#1/#3/#4/#5/#7/#9/#11/#15 + 形状迁移）；改写 6（#2/#6/#8/#10/#12/#14）。**

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

建议在主线程合入后，于 `coverage_gate.py` 的 http_flv 段登记下列断言（**每条均可从本契约与 cases JSON 直接机读，不需新造事实**；**红项如实标红，不得申报"今日已过"**）：

| # | 建议断言 | 依据 | 今日判定 |
|---:|---|---|---|
| 1 | `len(cases['http_flv']) == 15` 且 ID 集合 = §2 十五项，顺序一致 | 本契约 §2 | **绿**（机读实测） |
| 2 | 15/15 例 `spec_json` 顶层键 == `{layers}`（**零游离键**） | 本契约 §1；设计 §12.1 | **红**（15/15 含 `http_flv`，G-HTTPFLV-1） |
| 3 | 12 正例 `packet_count == 7 + 2×rounds` | 设计 §9 公式 | **绿**（12/12 实测一致） |
| 4 | 3 负例 `expect` 键 == `{expect_error, error_contains}` | 本契约 §4 | **绿**（严格两键） |
| 5 | 负例 `error_contains` ∈ 代码锚词集 `{"tag","rounds","flags"}` | 设计 §7 | **绿** |
| 6 | 非负例顶层键计数 == 0 | 设计 §12.1 | **红**（15 处残留） |
| 7 | `translate` 有 `case "http_flv":`（层 config → spec.HTTPFLV） | 设计 §11.7 | **红**（今日无该 case，G-HTTPFLV-1） |
| 8 | 每正例至少一条 frames 断言落在 FLV header 区（offset ≥ 载体起点+响应头长） | 本契约 §3 | **红**（#2/#6 落在 HTTP 头；#9/#10/#11/#12 无 frames） |
| 9 | 层内 `layers[].http_flv` 非空（配置住层内） | 设计 §12.1 | **红**（15/15 为 `{}`） |

**另注意**：`trafficgen/docs/protocol-pcap-test/http_flv.md` 的 "15/15 pass" 是**过期产物**（G-HTTPFLV-9，末次提交 `e7e7d1c` 2026-08-27 早于判死提交 `0417be5` 2026-09-13；`docs/protocol-pcap-test/http_flv/` 0 个 pcap），**不得作为"今日已复跑"依据**（口径与 pcep G-PCEP-11 / opcua G-OPCUA-10 一致）。**但本车道今日已另行复跑**（§8.1：15/15 绿、12/12 包数、10/10 frame），该证据来源是 `/tmp/mcp-pcaps/http_flv/`，**不是**过期产物。

## 10. 修订记录

- v1.0.0（2026-09-29）：批次二文档轨 as-built 首版。**承 45-http-flv-testcase 的 15 ID / 顺序 / 锚词思路**；形状基线机读实测（§1，**顶层 15/15 残留 `http_flv`**）；**今日复跑证据**（15/15 绿、12/12 包数一致、10/10 frame 一致，§8.1）；**断言语义偏差 4 条**（§9.2 a–d）；负例语义与注入不符 2 条（§4）；存量审计 15 行去向（§8.3，保留 9 + 改写 6）；P3 固定动作（§6）；执行建议（§7）；覆盖反查门建议断言行 9 条（§9，**4 绿 5 红，红项如实标红**）。自审见汇报。

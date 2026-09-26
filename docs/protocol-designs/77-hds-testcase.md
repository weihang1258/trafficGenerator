# HDS（Adobe HTTP Dynamic Streaming，Adobe HTTP 动态流）测试用例契约

> 版本：v1.0.0（P1–P3 产物，由 `47-hds` 基线重建）
> 日期：2026-09-27
> 配套设计：`docs/protocol-designs/77-hds-design.md` v1.0.0（P1 矩阵 §10/三路对照 §11/门1表 §12/D-HDS-1 §13）
> 机器契约：`trafficgen/test/protocol_pcap/cases/hds.json`（17 例已落地可执行）
> 状态：P3 固定动作（§3.15/A′/B′/9.52/3.14/三源回指）已落盘 §8；`hds` 层已注册已实现（47 基线的 `unknown layer` 占位已作废）；本文断言以 `cases/hds.json` 实测形状为准，不宣称 suite 已跑（G-HDS-4）。

## 1. 测试原则和注册状态

用例从设计 §2–§8 逐项派生，共 17 个唯一 ID：13 个正例和 4 个负例，顺序 = JSON 数组序。47 基线的第 18 ID（`hds_neg_unregistered`，`unknown layer` 占位）因注册完成而作废，不继承——当前 JSON 无占位，17 例全部是可执行语义用例。

HDS 是 HTTP/TCP 应用层 body 变换器族（设计 §2）：断言通道为已注册 `http.*`/`tcp.*`/`ip.*` 字段 + frames hex（P4 补）；tshark 无专用 HDS dissector，不自创 `hds.*` 字段名（P4 前 `tshark -G fields` 实证，G-HDS-4）。无 VLAN/IP/TCP options 时 HTTP 载荷起点 IPv4 offset 54（14+20+20）；IPv6 同住 `ip` 层，偏移不断言（`hds_ipv6` 当前无 `ipv6.nxt` 断言，弱点已登记，P4 补）。

动态值（session  URI 变体、Base64 bootstrap、fragment body）以 fixture 精确断言为主；跨流递增/随机面待 P4 动态清单落地后补 presence/nonzero/distinct/same_as。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定包数 |
|---:|---|---|---|---:|
| 1 | `hds_manifest_ipv4` | 正 | IPv4/TCP/HTTP GET、F4M root/media | 9 |
| 2 | `hds_bootstrap_abst` | 正 | Base64 短路 bootstrap、abst 头（形状） | 9 |
| 3 | `hds_asrt_segment_runs` | 正 | 双 fragment bootstrap 响应 200（run 字节不断言） | 9 |
| 4 | `hds_afrt_fragment_runs` | 正 | 同上（timestamp/duration 不断言） | 9 |
| 5 | `hds_fragment_f4f` | 正 | F4F URI、200、`video/f4f`（mdat 字节不断言） | 9 |
| 6 | `hds_manifest_bootstrap_fragment` | 正 | 三 session 串行顺序（包 4/5/6/8 URI 序） | 13 |
| 7 | `hds_keepalive_fragments` | 正 | 同连接双 fragment GET/response 边界 | 11 |
| 8 | `hds_multi_session` | 正 | 双 manifest session 串行（同 4-tuple，真隔离待 G-HDS-3） | 11 |
| 9 | `hds_ipv6` | 正 | IPv6，应用字节语义不变 | 9 |
| 10 | `hds_mss_reassembly` | 正 | mss=536 跨段（response 在包 6，`min_packets: 8`） | ≥8 |
| 11 | `hds_live_update` | 正 | 双 bootstrap session 同 URI（单调扩展不断言） | 11 |
| 12 | `hds_vod_end` | 正 | recorded 形状（FIN 语义不断言） | 9 |
| 13 | `hds_boundary_box` | 正 | 单字节 body 最小形状（size 公式不断言） | 9 |
| 14 | `hds_neg_manifest` | 负 | 空 id/stream_type/media → `manifest` | — |
| 15 | `hds_neg_bootstrap` | 负 | bootstrap session 无 media → `bootstrap` | — |
| 16 | `hds_neg_fragment` | 负 | fragment session 无 fragments → `fragment` | — |
| 17 | `hds_neg_session_state` | 负 | 未知 kind → `unknown`（真跨 session 串用待 G-HDS-3） | — |

包数规律（一 session 一 GET 一 200 = +2 包）：单 session 9；双 session 11；三 session 13；MSS 例 `min_packets: 8`（response 包 6 = 分段证据）。`src_port` 41000–41016 逐例连续（#1→#17），`dst_port` 全 80，顶层 `http` 子映射 0 例。

## 3. 正例逐项断言契约

1. **`hds_manifest_ipv4`**：IPv4/TCP/41000→80，单 manifest session。断言包 4 `http.request.method=GET`、包 4 `http.request.uri=/live/channel.f4m`、包 5 `http.response.code=200`，`packet_count=9`。
2. **`hds_bootstrap_abst`**：单 bootstrap session（fixture Base64 解码为 127B `abst` 盒，内嵌 `asrt`+`afrt`，已实证）。断言包 4 method/uri（`/live/channel.bootstrap`）、包 5 code 200，`packet_count=9`。run 表字节不断言（P4 frames 补，G-HDS-1）。
3. **`hds_asrt_segment_runs`**：双 fragment fixture 的单 bootstrap session。断言包 4 method、包 5 code 200，`packet_count=9`。segment 起点/单调性不断言（走 Base64 短路，生成路径无 pcap 覆盖，G-HDS-1）。
4. **`hds_afrt_fragment_runs`**：同 #3 形状。断言包 4 method、包 5 code 200，`packet_count=9`。timestamp/duration/discontinuity 不断言（实现无 indicator 字节，G-HDS-3）。
5. **`hds_fragment_f4f`**：单 fragment session。断言包 4 method/uri（`/live/channel/Seg1-Frag1`）、包 5 code 200，`packet_count=9`。mdat 字节与 `video/f4f` Content-Type 不断言（P4 frames 补）。
6. **`hds_manifest_bootstrap_fragment`**：三 session 串行（manifest→bootstrap→fragment）。断言包 4 URI（f4m）、包 5 code 200、包 6 URI（bootstrap）、包 8 URI（Seg1-Frag1），`packet_count=13`。顺序由数组序保证，错序不拒（G-HDS-2）。
7. **`hds_keepalive_fragments`**：同连接双 fragment（Frag1/Frag2）。断言包 4/6 两 URI、包 5/7 两 code 200，`packet_count=11`。各自 Content-Length/body 边界独立（变换器恒 keep-alive）。
8. **`hds_multi_session`**：双 manifest session（`/live/session_a.f4m`、`/live/session_b.f4m`，同 4-tuple 串行）。断言包 4/6 两 URI、包 5/7 两 code 200，`packet_count=11`。真 4-tuple 隔离待 G-HDS-3。
9. **`hds_ipv6`**：IPv6 地址 fixture 的单 manifest session。断言包 4 URI、包 5 code 200，`packet_count=9`。`ipv6.nxt`/地址族/偏移 74 不断言（弱点，P4 补）。
10. **`hds_mss_reassembly`**：`tcp.mss=536` 单 manifest session。断言包 4 URI、包 6（非包 5）code 200——一位后移即跨段证据，`min_packets: 8`。重组后 XML 完整性不断言（P4 frames 补）。
11. **`hds_live_update`**：双 bootstrap session 同 URI。断言包 4/6 两 URI、包 5/7 两 code 200，`packet_count=11`。run 表单调扩展不断言（G-HDS-3）。
12. **`hds_vod_end`**：`stream_type=recorded` 单 manifest session。断言包 4 URI、包 5 code 200，`packet_count=9`。FIN 终止语义不断言（keep-alive 恒置覆盖配置值，G-HDS-3）。
13. **`hds_boundary_box`**：单字节 body（`X`）fragment session。断言包 4 URI、包 5 code 200，`packet_count=9`。size=8+payload 公式不断言（G-HDS-2）。

## 4. 负例契约

每个负例必须在 planner/validator 失败并传播为 task error；不能产生成功 PCAP 或假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`（17 例全量审计：4 负例零混入包结构断言）：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `hds_neg_manifest` | 空 id/stream_type/media 的 manifest session | `manifest` |
| `hds_neg_bootstrap` | 无 media 的 bootstrap session | `bootstrap` |
| `hds_neg_fragment` | 无 fragments 的 fragment session | `fragment` |
| `hds_neg_session_state` | 未知 kind（`unknown`） | `unknown` |

`sessions` 空（`sessions is required`）、非法 Base64（`bootstrap base64 decode`）无 pcap 例，P4 补（G-HDS-1）。链级红例（缺 http 载体/顶层 hds presence/游离键）P4 补（G-HDS-1）。合法的三 kind、live/recorded 字面、Base64 双形态、keep-alive 串行由正例覆盖，不能误报为负例。

## 5. 三方一致性和静态检查

1. 设计 §8 的 17 个 ID、本文 §2、`cases/hds.json` 数组为同一组 ID、同一顺序：13 正例 + 4 负例（机器校验 `ids==design` 已通过）。
2. 13 正例均有 `packet_count`（#10 为 `min_packets`）+ `http.request.*`/`http.response.code` 字段；4 负例 `expect` 只有 `expect_error`、`error_contains`。
3. F4M/abst/asrt/afrt/mdat 的父子长度、run 单调、timescale 一致、引用交叉当前不断言——缺口已入 G-HDS-2/B′，不冒充覆盖。
4. manifest→bootstrap→fragment 顺序仅由 sessions 数组序表达；validator 无顺序检查，错序 fixture 归 G-HDS-2。
5. `live`/`recorded` 为字面透传；`recorded` 无终止行为差（G-HDS-3）。
6. IPv4/IPv6 以地址字面区分（同住 `ip` 层）；多 session 以同连接串行为准，不依赖全局交织包序。
7. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/hds.json` 通过；顶层键恒 `layers`+`hds`（17/17），顶层 `http` 0 例，`flow_control` 0 例（P4 迁层补，G-HDS-1）。

## 6. 实现后执行建议

G-HDS-1 迁层改写后，先跑全量（`CASE_PROTO=hds` 全量非增量）拿实际 pcap 再钉 frames（先跑后钉，不照抄 §3 包数）；urious/mss/双 session 包号按落盘 pcap（tshark）复核。`tshark -G fields` 实证字段名（禁 `hds.*` 自创）；盒字节走 frames hex（abst 头 `0000007f 61627374` 起，127B fixture 基线已实证）。

## 7. 修订记录

- v1.0.0（2026-09-27）：P1–P3 产物。由 47 基线重建：17 ID（占位删除）逐例断言契约 + 弱断言登记（asrt/afrt/mdat 无 frames、ipv6 无地址族断言、size 公式无）+ §8 P3 固定动作。47 基线三方 ID/顺序/覆盖已逐条核对（结论见 p123 报告）。

## 8. P3 固定动作（CORE_MEMORY §3.15/§9.52/§9.14/覆盖审计要求面）

### 8.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 三 session 串行（#6）+ 双 fragment（#7） | 已覆：#6/#7 |
| ② | 非正常结束 | 4 守卫负例（配置错分支） | 已覆半程：#14–#17；FIN/RST mid-transaction + 服务端 abort→立项 G-HDS-3（含） |
| ③ | 长保活 | keep-alive 双 fragment（#7）+ 双 bootstrap 轮询形状（#11） | 已覆：#7/#11（恒置语义） |

无空项。②的服务端主动面进 B′（G-HDS-3），不删用例。

### 8.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流四类审计）

A′（现有引擎可构建→17 ID 内已覆或 P4 fixture 可建）：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | 三 kind 分支/三 Content-Type/双地址族/MSS 分段/最小形状 | #1/#2/#5/#9/#10/#13 已覆（形状层） |
| 业务 | 三阶段串行/keep-alive 多事务/双 session | #6/#7/#8 已覆（顺序层） |
| 现网 | 明文 GET .f4m/内联 bootstrap/片段寻址 | #1/#2/#5 已覆（形状层） |
| 多流 | 同连接多 session/N/A 真并发 | #6–#8/#11 已覆串行面；真并发→G-HDS-3 |

B′（引擎结构缺口→G-HDS-2/3/4 进 D-条目"明确不解决+迁入计划"，见 design §15 缺口立项）：G-HDS-2（validator/断言语义鸿沟 11 点）、G-HDS-3（状态/连接语义 6 点）、G-HDS-4（规范复核 + 字段实证，确认项）。G-HDS-1 为 P4 必含，不进 B′。

### 8.3 9.52 对账两行 + 清单出处声明

- 清单出处声明：本清单来源=规范/官方文档反推（Adobe HDS spec + 2014-05 Errata + RFC 9112/9110 + design §10 矩阵），非引擎能力面反推。
- 对账两行：规范逻辑点总数=42（design §10.2 矩阵 30 格 + §10.3 变体 12 行）；用例覆盖数=20 点（矩阵 13 格 + 变体 7 行，17 ID 形状层），P4 必含 8 点（G-HDS-1 迁层 scope），B′ 立项 14 点（G-HDS-2/3；G-HDS-4 为确认项不计覆盖点），合计 42 无遗漏。反查 17/17 绿≠覆盖全，此对账为覆盖审计有效口径。

### 8.4 3.14 豁免边界审计

`sessions[]` 显式声明不豁免（本协议有 keep-alive 长连接 + 多 session，sessions[] 必写，design §12.3）。真多流并发缺（#8 同 4-tuple 串行）→ G-HDS-3，不豁免逃逸；单 body 多盒（abst 嵌 asrt/afrt）→ #2 形状已覆。两项均有去向，无豁免逃逸。

### 8.5 三源回指行

Adobe HDS spec（F4M/bootstrap/fragment/寻址）+ Errata（afrt 约束）+ RFC 9112/9110（HTTP 载体）→ D-HDS-1（design §13）→ `test/protocol_pcap/cases/hds.json`（17 例）。ID 权威=本文 §2（13 正+4 负）；对账 17=13+4。

### 8.6 断言契约核对结论（与 design §8 一致）

本文 §2 的 17 ID 与 design §8 逐 ID、逐序、逐类型核对一致（13 正 #1–#13 + 4 负 #14–#17，包数约定值相同：9×8/13×1/11×3/≥8×1）。存量审计（9.14）：47 基线 `hds_neg_unregistered` 占位作废（注册完成），无存量语义用例遗留。断言通道：fields 用 `http.request.method/uri` + `http.response.code`（实测形状；P4 实证全字段名 + 补 frames）；动态面待 P4 动态清单落地。

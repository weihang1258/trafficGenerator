# HDS（Adobe HTTP Dynamic Streaming，Adobe HTTP 动态流）设计契约

> 版本：v1.0.0（P1–P3 产物，由 `47-hds` 基线重建）
> 日期：2026-09-27
> 状态：P1 规范矩阵 + 门1 十四行表 + P2 D-HDS-1 草稿 + P3 对接清单已落盘。`hds` 层**已注册已实现**（与 47 基线"未注册"不同，见 §1），不修改 Go 实现，不宣称 suite 已跑；P4 为迁层改写（G-HDS-1）+ 缺口择机，非新建。
> 配套文件：`docs/protocol-designs/77-hds-testcase.md`、`trafficgen/test/protocol_pcap/cases/hds.json`（17 例已落地）
> 基线：`docs/protocol-designs/47-hds-design.md` + `47-hds-testcase.md`（v1.0.0，2026-08-20，未注册期契约；逐条核对见本报告 §②/p123 报告）
> 规范基线：Adobe HTTP Dynamic Streaming Specification（含 2014-05 Errata：afrt 约束）、HTTP/1.1（RFC 9112/9110）、TCP。

## 1. 范围、实现状态和承载边界

HDS 是用 HTTP GET 取 F4M manifest、bootstrap、F4F media fragment 的流媒体协议。F4M 是 XML 清单（含内联 Base64 bootstrap）；bootstrap 是描述 segment/fragment 时间线的二进制元数据（`abst` 根盒嵌 `asrt`/`afrt` 运行表）；F4F 是按 URI 寻址的 fragment 容器（本实现为 `mdat` 盒）。HDS 不是独立 IP 协议，`hds` 是 TCP→HTTP 之上的终结层。

本版覆盖：F4M XML（声明、`http://ns.adobe.com/f4m/1.0` namespace、media、bootstrapInfo、live/recorded 字面）；bootstrap `abst`/`asrt`/`afrt` 盒（长度、版本、timescale、segment/fragment run 编码）；F4F 请求 URI 与 `mdat` 盒；HTTP/1.1 GET/200、Content-Type、Content-Length、keep-alive 恒置串行；IPv4/IPv6、MSS 分段、多 session 串行、同连接多资源链；空/缺字段 manifest、非法 Base64、无 media、无 fragment、未知 kind 六类负路径（自然守卫）。

不覆盖：HTTPS/TLS 解密、HTTP/2/3、RTMFP、编解码器、H.264/AAC 语义、DRM、CDN、无限 live 生成、discontinuity profile（`fragmentDuration=0` 指示字节实现未产生，见 G-HDS-3）、`size=1` 扩展长度与 `size=0` 尾延（实现恒 32 位 size，见 G-HDS-2）。TLS 可作未来独立 `tls→tcp→http→hds` 链；未解密时不断言明文。

实现状态（47 基线最大变化）：`hds` 已注册（`registry.go:490`：Category=Terminal、DependsOn=`http`、字段 `profile`/`wire_fault`、FieldContract `tcp.dst_port=80`；生成表同值已落盘）+ planner/validator/生成器已落地（`internal/protocol/hds/planner.go:180-185` init 注册、`builder.go` 三 builder、`cmd/server/main.go:62` 空白导入 + `:492` 接线 planner）。`cases/hds.json` 17 例（13 正 + 4 负）已是可执行机器契约，无 `unknown layer` 占位——47 基线的第 18 ID（`hds_neg_unregistered`）因注册完成而作废，不继承。

## 2. 推荐配置、层链和载体 profile

主层链 `[ip, tcp, http, hds]`（IPv6 与 IPv4 同住 `ip` 层，本仓库无 `ipv6` 层，kerberos/ntlm 先例；fixture 用 v6 地址）。链上缺 `http` 层即结构性错误，Plan/Validate 期同步拒绝（`validate_layers.go:503`，锚词 `requires the http carrier layer`；carrier 单测 `chain_planner_http_carrier_test.go:30` 钉死）。

与 http 的分工（isHTTPRPCInner 面，CORE_MEMORY §1 http 底座口径）：`hds` **不在** `isHTTPRPCInner` 之列（`layer_gen.go:76-81` 仅 GBT/GetWork/CWMP/DOH/ONVIF/MMSE/NTLM/OCSP 七家透传族）。HDS 是 body 变换器族（与 hls/http_flv 同构）：hds 终结层只产 body 事件（F4M 文本/bootstrap 字节/F4F 字节，`planner.go:22` 每 session 一事件），http 层经 `generateHDSTransformer`（`hds_transformer.go:25`）包成 GET/200 帧——manifest→`application/f4m+xml`、bootstrap→`application/octet-stream`、fragment→`video/f4f`。GBT 族是反过来（内层自封完整 HTTP 帧、http 层原样透传），两者不可混淆。

目标形状（顶层键仅 `layers`+`flow_control`；当前 17 例尚未达标，差量见 §12.1/G-HDS-1）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.47", "dst": "198.51.100.47"}},
    {"tcp": {"src_port": 41000, "dst_port": 80}},
    {"http": {}},
    {"hds": {"profile": "hds_http1", "sessions": [{"kind": "manifest", "uri": "/live/channel.f4m"}]}}
  ],
  "flow_control": {"flows": 1}
}
```

| 配置键 | 约束 |
|---|---|
| `profile` | `hds_http1`（注册表缺省）；实现透传值，不分支 |
| `transport`/端口 | 仅 TCP；明文 80（FieldContract 补齐）；非默认端口暂无例（P4 补，G-HDS-1） |
| `sessions[]` | 有序事件编排会话（见 §12.3）；整块串行回放，不交错 |
| `kind` | `manifest`/`bootstrap`/`fragment`；其他值 validator 拒（锚词 `unknown session kind`） |
| `uri` | 非空 request-target；manifest kind 缺省回落 `Manifest.uri`，再缺省回落 `/live/channel.f4m` |
| `wire_fault` | 仅负例注入口：**当前未消费**（G-HDS-2；负例全走自然守卫） |

## 3. F4M manifest 结构

`buildF4MManifest`（`builder.go:15`）按固定模板序列化，属性顺序稳定：XML 声明 → `<manifest xmlns="http://ns.adobe.com/f4m/1.0">` → `<id>` → `<streamType>`（原样写 `live`/`recorded`，**无行为分支**，G-HDS-3）→ 每 media 一行自闭合 `<media bitrate href/url streamId bootstrapInfoId/>`（仅非空属性成行）→ 每 bootstrapInfo 一行（Base64 原样内联）→ 闭合。特殊字符 `xmlEscape` 转义（`builder.go:66`）。

约束：`id`、`stream_type` 非空，至少一项 media（validator `planner.go:155` 与 builder 同口径三检查，锚词 `manifest id is required`/`manifest stream_type is required`/`at least one media entry`）。以下**不校验**（G-HDS-2）：`streamType` 取值集合、`streamId` 唯一性与非空、`bitrate` 符号、`bootstrapInfoId` 与 `bootstrap_infos[].id` 交叉引用、XML 截断/非法（validator 不解析 XML，只查三字段存在）。

manifest body 的 HTTP `Content-Length` 由变换器按实际字节数填写（`hls_transformer.go:181` 共用 builder，`len(body)`），恒正确——Content-Length 边界错无注入面（G-HDS-2）。

## 4. Bootstrap 二进制编码

全盒 `UI32 size + 4B type + payload` 大端，`size` 含 8 字节头（`builder.go:125-130` 同构三处）。`abst` 为根，payload 定序：version(1,恒0)+flags(3,恒0)+bootstrapVersion(UI32,恒1)+profile(UI8,恒0)+live(UI8,恒0)+update(UI8,恒0)+timescale(UI32,恒1000)+currentMediaTime(UI64,0)+smpteTimeCodeOffset(SI64,0)+movieIdentifier(长度前缀空串)+serverEntryCount(0)+qualityEntryCount(0)+drmData(空)+metadata(空)+asrtCount(1)+asrt盒+afrtCount(1)+afrt盒。`asrt`（`builder.go:134`）：version/flags + qualityEntryCount(0) + segmentRunEntryCount(UI32,按 fragments 去重 segment 数) + 按 segment 升序 `(firstSegment, fragmentsPerSegment)`。`afrt`（`builder.go:176`）：version/flags + timescale(UI32,恒1000，与 abst 一致，合 Errata timescale 相等约束）+ qualityEntryCount(0) + fragmentRunEntryCount + 每项 `(firstFragment UI32, timestamp UI64, duration UI32)`——**无 discontinuity 指示字节**（47 基线 §4.3 的 `duration==0→indicator` 在实现中不存在，见 G-HDS-3）。

Base64 短路：bootstrap session 优先采用 `bootstrap_infos[]` 首个非空 `Base64` 解码字节（`planner.go:67-75`，非法 Base64 锚词 `bootstrap base64 decode`）；无 Base64 才按 media fragments 生成 abst/asrt/afrt。后果：当前 asrt/afrt 用例（fixture 均带 Base64）走短路分支，**生成路径无 pcap 覆盖**（仅单测 `hds_test.go` 覆盖，P4 补例，G-HDS-1）。

以下**不校验**（G-HDS-2）：box size 越界/`<8`、count 与剩余字节一致性、run 单调性/重叠/回退、afrt/abst timescale 一致性（实现恒相等故形状成立）、`size=1`/`size=0` 拒绝（实现恒 32 位 size，既不产生也不检查）。

## 5. F4F media fragment 与 HTTP/TCP 状态机

fragment session 取 `media.fragments[0]`（**首个**，其余忽略；空则锚词 `no fragments configured`），body 取 `Body`/`BodyB64`（`resolveBody`，非法 Base64 回落文本；双空回落 `dummy fragment content`），包成单 `mdat` 盒（`builder.go:208`，size=8+len）。fragment sequence/timestamp/duration 与 afrt 的关联**不检查**（G-HDS-2）；URI 编号与 fragment 字段的关联不检查（URI 原样取 `s.URI`）。

单 session 状态机（变换器恒 keep-alive，`hds_transformer.go:71/76` 传字面 `true`——配置 `keep_alive:false` **被覆盖**，VOD 例亦然，G-HDS-3）：

```text
TCP SYN/SYN-ACK/ACK → GET <uri> ← 200 + Content-Type + body → [下一 session 同连接串行] → FIN/ACK
```

不变式：request 先于 response；manifest→bootstrap→fragment 仅由 `sessions[]` 数组序保证（validator 不强制顺序，错序不拒，G-HDS-2）；每 response 独立 Content-Length/body 边界；多 session 同一 4-tuple 串行（`SrcPort` 事件字段未消费，无真多连接，G-HDS-3）。

## 6. IPv4/IPv6、多会话与边界

IPv4/IPv6 同住 `ip` 层（地址字面区分，无 `ipv6` 层）。应用字节与地址族无关（同一 fixture 换地址即 IPv6 例，`hds_ipv6`）。MSS 经 `tcp.mss`（`hds_mss_reassembly` 用 536，`min_packets` + response 包号后移一位即分段证据）。`hds_multi_session` 实为同 4-tuple 双 manifest session 串行（src_port 皆 41007，无独立四元组）——"多会话隔离"名不副实，P4 真隔离（G-HDS-3）。`hds_boundary_box` 为单字节 body 形状例（size=8+payload 不断言，G-HDS-2）。UI32/UI64 溢出、超大 body（`0xffffffff` 分配禁令同 47 基线，不断言）无例（G-HDS-2/3）。

## 7. 错误处理与完成定义

负例经 planner/validator 在策略创建期失败并传播为 task error（零假成功；注册 validator `planner.go:118`）。当前四负例锚词：`manifest`（三字段空）、`bootstrap`（bootstrap session 无 media）、`fragment`（无 fragments）、`unknown`（未知 kind，经 transformer `hdsContentType` 与 validator 双锚 `unknown HDS session kind`/`unknown session kind`）。

| 错误 | 稳定锚点 |
|---|---|
| sessions 空 | `sessions is required` |
| manifest 空/缺 id/stream_type/media | `manifest` |
| bootstrap/fragment 缺 media/fragments | `bootstrap`/`fragment`/`manifest/media required` |
| 未知 kind | `unknown session kind` |
| Base64 非法 | `bootstrap base64 decode` |
| 缺 http 载体（链级，待 P4 例） | `requires the http carrier layer` |
| 层链+顶层 `hds` 空映射并存（待 P4 守卫+例） | `no longer accepts a top-level hds sub-config` |

完成定义：F4M/abst/asrt/afrt/mdat 逐字节生成；HTTP/TCP 状态、keep-alive 串行、MSS 重组、IPv4/IPv6 有 pcap 例；G-HDS-1 迁层后每负例传播为 task error；链级红例（载体缺失/presence/白名单游离）齐备。

## 8. 17 个语义场景和 packet_count 映射

共 17 个唯一 ID（13 正 + 4 负），顺序 = `cases/hds.json` 数组序（v1.3 ID 顺序即 JSON 顺序）。包数为契约值（P2 资产先跑后钉；每增一 session +2 包：9→11→13，与一 session 一 GET 一 200 一致）：

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
| 11 | `hds_live_update` | 正 | 双 bootstrap session 同 URI（单调扩展不断言，G-HDS-3） | 11 |
| 12 | `hds_vod_end` | 正 | recorded 形状（FIN 语义不断言；keep-alive 仍恒置，G-HDS-3） | 9 |
| 13 | `hds_boundary_box` | 正 | 单字节 body 最小形状（size 公式不断言，G-HDS-2） | 9 |
| 14 | `hds_neg_manifest` | 负 | 空 id/stream_type/media → `manifest` | — |
| 15 | `hds_neg_bootstrap` | 负 | bootstrap session 无 media → `bootstrap` | — |
| 16 | `hds_neg_fragment` | 负 | fragment session 无 fragments → `fragment` | — |
| 17 | `hds_neg_session_state` | 负 | 未知 kind → `unknown`（真跨 session 串用待 G-HDS-3） | — |

## 9. 修订记录

- v1.0.0（2026-09-27）：P1–P3 产物。由 47 基线重建：注册完成（47 基线"未注册"作废，18 ID→17 ID，占位 ID 删除）；核对 http 体变器分工（isHTTPRPCInner 排除）；逐例标注弱断言（asrt/afrt/mdat 无 frames）；死字段清单（Method/Version/KeepAlive/WireFault/SrcPort/ManifestURI/Rounds/BootstrapBytes/URL/SizeOverride）；G-HDS-1–4 缺口立项；门1 十四行表 + D-HDS-1 草稿 + P3 对接清单。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（三张子表：①资源×结果矩阵 §10.2；②数据形态变体表 §10.3；③商业行为→用例映射 §11.2）。条目三选一：已覆 / P4 必含（G-HDS-1 迁层 scope）/ B′（明确不解决+迁入计划）。

### 10.1 八项规范矩阵

| # | 规范要求（条款） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：短事务 HTTP GET→200；同连接串行多资源；无控制/数据分离（Adobe HDS spec；本契约 §5） | 播放器取 manifest 后按序取 bootstrap/fragment | 已实现：单 TCP 连接 sessions 串行，keep-alive 恒置 | 真多连接无（G-HDS-3） |
| 2 | 命令消息表：manifest/bootstrap/fragment 三 GET → 200 + 三 Content-Type（本契约 §3–§5） | 三阶段播放启动；独立 fragment 刷新 | 已实现：kind 三分支 + Content-Type 映射（`hds_transformer.go:86`） | 顺序不强制（G-HDS-2） |
| 3 | 状态机：响应先于请求禁；bootstrap 依赖 manifest（bootstrapInfoId）；fragment 依赖 run 表（本契约 §5） | 错序/孤立 fragment 请求 | 状态仅由数组序保证；validator 无顺序/引用检查 | G-HDS-2 |
| 4 | 字段表：F4M（id/streamType/media/bootstrapInfo）；abst/asrt/afrt 定序大端字段；timescale；run 表；mdat size 含头（Adobe spec + Errata afrt 约束；本契约 §3/§4） | 跨播放器互操作；时间线换算 | 已实现 builder；abst/afrt timescale 恒 1000 一致 | 语义校验全缺（G-HDS-2） |
| 5 | 错误处理：空/缺字段/非法 Base64/无 media/未知 kind（本契约 §7） | 坏配置、坏 fixture | 4 负例自然守卫 | wire_fault 未消费；盒语义错直通（G-HDS-2） |
| 6 | 超时活性：keep-alive 复用；live 轮询更新（Adobe live 语义；本契约 §5） | 直播 bootstrap 轮询 | keep-alive 恒置；live_update 形状例 | 单调更新不断言；超时值走 http 层语义（G-HDS-3） |
| 7 | NAT/代理：明文 HTTP 经代理（Host/绝对 URI）；HTTPS 未解密只断言 carrier（RFC 9112 §3；本契约 §5） | 企业网代理后点播 | transformer 按 `DstIP` 填 Host | 代理形/443 opaque 无例（G-HDS-3 确认项） |
| 8 | 版本方言：f4m 1.0 namespace；streamType live/recorded；profile `hds_http1`（本契约 §2/§3） | 点播 vs 直播 | namespace 钉死；streamType 原样写无分支 | recorded 行为差无（G-HDS-3）；discontinuity/size 扩展（G-HDS-2/3） |

### 10.2 子表①：资源×结果矩阵（30 格 = 已覆 13 + P4 必含 6 + B′ 11）

| 资源 \ 结果 | 200 正例 | 配置错 | 线格式错 | 状态错 | 关联错 | 载体错 |
|---|---|---|---|---|---|---|
| manifest GET | 已覆 #1 | 已覆 #14 | B′ G-HDS-2（XML 截断/非法不校验） | 已覆 #6（顺序 URI 序） | B′ G-HDS-2（bootstrapInfoId 引用） | P4 G-HDS-1（缺 http 链级红例） |
| bootstrap GET | 已覆 #2 | 已覆 #15 | B′ G-HDS-2（box 越界/<8） | 已覆 #6 | B′ G-HDS-2（timescale 一致） | P4 G-HDS-1 |
| fragment GET | 已覆 #5 | 已覆 #16 | B′ G-HDS-2（mdat 截断） | 已覆 #6 | B′ G-HDS-2（编号 vs run 表） | P4 G-HDS-1 |
| keep-alive 多事务 | 已覆 #7 | P4 G-HDS-1（sessions 空无 pcap 例） | B′ G-HDS-2（无截断注入面） | 已覆 #7（Frag1→Frag2 序） | B′ G-HDS-2（timestamp 单调） | P4 G-HDS-1 |
| 多会话 | 已覆 #8（串行形状） | 已覆 #17 | B′ G-HDS-2 | B′ G-HDS-3（跨 session 串用，真隔离） | B′ G-HDS-3（session 状态隔离） | P4 G-HDS-1 |

### 10.3 子表②：数据形态变体表（12 行 = 已覆 7 + P4 必含 2 + B′ 3）

| 变体维度 | 形态 | 对应用例 | 备注 |
|---|---|---|---|
| 地址族×载体 | IPv4/HTTP、IPv6/HTTP | #1/#9 | 对称满格；无裸 TCP profile（http 载体强制，设计如此） |
| 方法/版本 | GET + HTTP/1.1 恒定 | #1–#13 全例 | transformer 硬编码；非 GET/他版本拒绝面→G-HDS-2 |
| stream_type | live/recorded 字面 | #1–#11/#12 | 形状已覆；行为差无→G-HDS-3 |
| media 属性 | bitrate/streamId/href/引用 Id 形状 | #1 | 交叉引用校验→G-HDS-2 |
| bootstrap 编码 | 内联 Base64 / 生成式 | #2–#4（短路）/ 生成路径无 pcap 例→P4 G-HDS-1 | 单测覆盖生成路径 |
| timescale | abst=afrt=1000 恒等 | 形状成立 | 不一致负例→G-HDS-2 |
| URI 形态 | path-absolute；SegN-FragM | #5 | 非法/percent 形→G-HDS-2 |
| keep-alive | 恒置串行 | #7/#11 | close 语义（VOD false 被覆盖）→G-HDS-3 |
| TCP 形态 | MSS 分段重组 | #10 | 粘连/丢包由 TCP 层语义承载 |
| 长度边界 | 单字节最小形状 | #13 | size=8+payload 公式不断言→G-HDS-2 |
| 端口 | 80（FieldContract） | #1–#13 全例 | 非默认端口无例→P4 G-HDS-1 |
| Host | 按 DstIP 填 | 形状成立 | 代理绝对 URI 形→G-HDS-3 确认项 |

## 11. 三路对照与候选方案对比（CORE_MEMORY §4.12–4.18）

### 11.1 三路对照

①规范原文：Adobe HDS Specification（F4M XML 清单 + 内联 bootstrap；abst/asrt/afrt 盒；SegN-FragM 寻址）+ 2014-05 Errata（afrt flags=0、timescale 与 abst 一致——实现恒 1000/1000，形状合规）+ RFC 9112/9110（GET/200/Content-Length/keep-alive）。盒内 profile/live/update/currentMediaTime/smpte/字符串表等定序字段以 47 基线 §4.1 为准，Adobe spec PDF 逐字节复核记 G-HDS-4 确认项。
②现网行为：Adobe 系 origin 以明文 HTTP GET 供 `.f4m`（单文件单 XML 描述，源：Unified Streaming/HDS 文档与 GlobalDots HDS 综述）；播放器先取 manifest、解内联 bootstrap、再按 run 表取 fragment。确认方式：G-HDS-4（Adobe spec PDF 复核 + 回环抓包核对三 Content-Type 与包序）。
③开源实现思路：tshark 无专用 HDS dissector（P4 前跑 `tshark -G fields` 实证 http/ip/tcp 字段名，不自创 `hds.*` 字段）；盒解析走 frames hex（47 基线 §13 同口径）。

三路一致：短事务 GET→200 + body 三形态 + timescale 一致；取舍：discontinuity/size 扩展/真多连接属 B′，不入本契约。

### 11.2 子表③：商业行为→用例映射表（§4.16）

| 商业行为（出处） | 用例编号 | 无映射项+确认方式 |
|---|---|---|
| Origin 供 manifest（明文 GET .f4m） | #1/#9 | — |
| 播放器解内联 bootstrap | #2（短路形状） | 生成式 bootstrap pcap 例→P4 G-HDS-1 |
| 按 run 表取 fragment（SegN-FragM） | #5 | 编号↔run 表一致性→G-HDS-2 |
| 直播 bootstrap 轮询更新 | #11（形状） | 单调扩展断言→G-HDS-3 |
| 点播播完（recorded 终止） | #12（形状） | FIN 终止语义→G-HDS-3 |
| 代理后点播/443 opaque | 缺口→G-HDS-3 确认项（查 RFC 9112 §3 + 抓包） | 待确认 |

### 11.3 候选方案对比（§4.17）

| 方案 | 走法 | 优 | 劣 | 结论 |
|---|---|---|---|---|
| A body 变换器 | hds 产 body 事件、http 包 GET/200 帧（hls/http_flv 同构） | 复用 http 层语义（Host/Content-Length/keep-alive）；实现已落地 | keep-alive/版本恒定，无协商面 | **采用（现状）** |
| B 透传 | hds 自封完整 HTTP 帧、http 原样转发（gbt 族同款） | 帧字节全控 | HDS 事件本非 HTTP 帧；与 gbt 族分工混淆；重写已工作代码 | 不选 |
| C 自封直连 tcp | hds 终结层直驱 tcp，不经 http | 少一层 | 重复造 HTTP 轮子，违"能依赖绝不重复" | 不选 |

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：顶层 `hds` 子映射（17/17 例）迁入 `layers[]` hds 条目；顶层 `http` presence 已判死；数量补 `flow_control`（17/17 例缺失）；非负例顶层键清零目标（P4 G-HDS-1；当前工作形状说明见 §12-P2） | 本契约 §2 + §12.1；`cases/hds.json`（全量审计值见 §12.1） |
| §2 策略/任务 | 策略=单 HDS 流量模板（自带 flow_control）；任务=多策略合跑+总量封顶；框架语义未动 | 本契约 §1/§13-P2 |
| §3 五件套 | 见 §12.3 强制展开：sessions 事件编排/事务序列/关联（bootstrapInfoId+run 表，单通道无 driven_by）/插入位置/时间线；真多连接不豁免→G-HDS-3 | 本契约 §12.3 + 用例 #6/#7/#8 |
| §4 查规范 | Adobe HDS spec + Errata + RFC 9112/9110 + 现网 origin 行为 + tshark（无 hds 专用字段，frames 通道）；P1 矩阵 8 行+三子表 | 本契约 §10/§11 |
| §5 依赖与错误 | DependsOn `http`（已注册）；4 自然守卫负例 + 2 链级红例（P4）；`wire_fault` 未消费（G-HDS-2）；失败→task error | 本契约 §2/§7 + §13-P2 错误分支 |
| §6 性能 | 声明式回放：O(n) 流式逐 session EmitMsg 无聚合；pcap/NIC 同一契约；数字待 P4 基准（诚实待确认）；六类场景清单见 §13-P2 | §13-P2 性能设计与验收 |
| §7 三份文档 | 77-hds-{design,testcase}.md v1.0.0（ID 权威=testcase §2）+ D-HDS-1（本契约 §13 草稿，门1 获批=定稿）+ T-HDS（testcase §8 草稿）+ schemagen（P4 重跑，层数+0，字段有变才重跑） | 修订记录 |
| §8 设计先行 | P1–P3 先于 P4 迁层改写；门1 获批 = D-HDS-1 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源=Adobe 规范条款 + D-HDS-1 + tshark http/tcp/ip 字段 + 现网 origin 行为；17 ID 正负对账；三源回指行见 testcase §8 | T-HDS（testcase §8） |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123 报告）+ 收官隔离复审 + 修轮；红先绿后 | /tmp/pipe/77-hds/p123-report.md |
| §11 白话 | 每阶段白话一句先行 | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组=ip/tcp 层（框架五策略）；业务字段逐个列开/不开+理由；序号算法位置诚实"待 P4 定" | 本契约 §12.12 |
| §13 schema 派生 | registry hds 行（DependsOn http/FieldContract 80）已在生成表；迁层后重跑 schemagen；struct 标签字面量锁 | §13-P2 接线件 |
| §14 真实流程 | suite 经 MCP 建任务→引擎生成→tshark `http.*`/`tcp.*`/`ip.*` + frames 双通道；先跑后钉；pcap 落 `/tmp/mcp-pcaps/hds/` | 用例 §1/§6 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

全量审计（`cases/hds.json` 17/17 例）：顶层键恒为 `layers`+`hds`；`layers[]` 内 `{"hds": {}}` 恒空（业务 100% 住顶层 `hds` 子映射）；`flow_control` 0 例；`wire_fault` 0 例。

| 旧键 | 去向（P4 G-HDS-1） |
|---|---|
| 顶层 `hds` 子映射（profile/keep_alive/manifest/sessions） | → `layers[]` 中 `{"hds": {...}}` 条目（业务键全量迁入）；迁入后顶层 `hds` presence 判死（新增守卫 `no longer accepts a top-level hds sub-config`，http 族 `http` 守卫同款 `strategy_convert.go:373/:8340`） |
| `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count` | 已在层链（`CheckProtoFlat` 全协议门）；`count`→`flow_control.flows`（17 例补键） |
| 顶层 `http` 子映射 | 已判死（hds 在列），17 例零出现 |

目标形状见 §2（顶层键仅 `layers`+`flow_control`；`hds` 业务进层内条目）。

### 12.3 §3 强制展开：五件套

- 会话表：sessions[] 即事件编排会话（单 TCP 连接内整块串行；例 #6 三 session：manifest→bootstrap→fragment；例 #8 双 manifest）。四元组=链级 tcp（全例单 4-tuple）。
- 事务序列（单事务四件事）：t1 manifest（前置：建连；动作：GET f4m；成功：200+F4M→可取 bootstrap；失败：空字段→`manifest` task error）；t2 bootstrap（前置：t1 或 fixture 自带 manifest；动作：GET bootstrap；成功：200+abst→可取 fragment；失败：无 media→`bootstrap`）；t3 fragment（前置：t2/run 表；动作：GET SegN-FragM；成功：200+mdat；失败：无 fragments→`fragment`）。
- 关联：`media.bootstrap_info_id ↔ bootstrap_infos[].id` + fragment（segment/fragment/timestamp）↔ run 表（归属会话/事务/双字段决定）；无独立副流、无 `driven_by`（单通道协议，与 CWMP 范本差异诚实声明）；**代码不校验引用**（G-HDS-2）。
- 插入位置：终结层——hds 产 body 事件 → http 层包帧 → tcp 分段/握手/挥手。
- 时间线：sessions 数组序串行；会话间无交错（真并发→G-HDS-3）。

### 12.12 §12 强制展开：动态字段清单

| 字段 | 住处 | 开策略 | 理由 |
|---|---|---|---|
| `src`/`dst` | ip 层 | fixed/inc/rand/list/pattern 全开（框架通用） | §12.2 四元组必备；多流锚点 |
| `src_port` | tcp 层 | 全开 + 保底 `12345+i` | §12.2/§2.8 |
| `dst_port` | tcp 层 | fixed（80 fixture；非默认 P4 补例） | tshark 解码约束 |
| `manifest.id`/`uri` | hds 层 | pattern/inc，待 P4 定 | 多流区分锚点候选 |
| `stream_type` | hds 层 | list（live/recorded），待 P4 定 | 枚举全覆盖 |
| `bitrate`/`stream_id` | hds 层 | inc/pattern，待 P4 定 | 业务变化面 |
| `timestamp`/`duration` | hds 层 | inc（时间线推进），待 P4 定 | 单调性断言前提 |
| `body`/`BodyB64` | hds 层 | pattern/rand（seed+序号），待 P4 定 | 载荷变化面 |
| `kind` 序列 | hds 层 | list 轮转，待 P4 定 | 三分支覆盖 |
| `method`/`version`/`keep_alive` | — | 不开 | transformer 恒 GET/HTTP/1.1/keep-alive，无消费点（死字段，见 §13） |
| 静态复制拒绝 | 框架 §12.9 | flows>1 无动态→拒/告警（P4 用例补） | 现状 17 例无 flow_control，缺省单流 |

序号算法代码位置：待 P4 定（D-HDS-1 定稿后 builder/planner 落序号算法时钉死文件行号；此处不编行号——§5.7）。

### 12-P2 presence 负例形状（链级红例必含①）

P4 必含（G-HDS-1）：`{"layers":[...],"hds":{}}`（顶层空 `hds:{}` 与层链并存）必须拒，`error_contains` 含 `top-level hds sub-config`。白名单外游离键（如顶层 `src_mac`）判死负例见 §13-P2。**当前 17 例的"层链+顶层 hds 共存"是迁层前工作形状**（`strategy_convert.go:602` 主动解析顶层 `hds`，pipe_gate 仅查顶层 `http` 共存），非 presence 负例——G-HDS-1 迁入后此形状才转判死，汇报必须点名此翻转，防误读为层链不彻底。

## 13. D-HDS-1 P2 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批=定稿）

> 体裁：文件清单/接口签名/数据结构/主流程/错误分支/性能设计与验收/回滚方式。hds 已实现，本条目=现状忠实记录 + G-HDS-1 迁层计划。

**文件清单（现状 3 + P4 改写/新增）**：

| 文件 | 职责 |
|---|---|
| `internal/protocol/hds/builder.go`（存量） | `buildF4MManifest`(:15)/`buildBootstrapBox`(:78)/`buildASRTBox`(:134)/`buildAFRTBox`(:176)/`buildF4FFragment`(:208) + helpers |
| `internal/protocol/hds/planner.go`（存量） | `HDSGenerator.Generate`(:22, 每 session 一 body 事件) + `validateHDSConfig`(:118) + `validateManifest`(:155) + init 注册 generator/validator(:180-185) |
| `internal/protocol/http/hds_transformer.go`（存量） | `generateHDSTransformer`(:25, 包 GET/200 三 Content-Type) + `hdsContentType`(:86) |
| 接线件（存量已通） | types.go `HDSConfig/HDSSession/HDSManifest/HDSMedia/HDSBootstrapInfo/HDSFragment`(:478-534)；FlowMeta.HDS（generator.go:349）；translate Meta 直传(:118)+空配置默认(:746)+Rounds 默认(:749)；strategy_convert `case "hds"`(:602)；registry 行(:490)；validate carrier(:503)；main.go 空白导入(:62)+planner(:492)；protocols.go 白名单(:37)+carrier 单测(:30)；maptoflow/schema 顶层 http 守卫（:373/:8340 同款） |
| P4 改写（G-HDS-1） | strategy_convert `case "hds"` 改读层内条目 + 新增顶层 `hds` presence 守卫（CheckProtoFlat 同款文案）；translate 层载荷逐键入 spec.HDS；cases 17 例改写（业务进层 + 补 `flow_control` + 链级红例：载体缺失/presence/游离键）；coverage_gate `check_hds`；schemagen 重跑（字段有变才需） |
| 死字段处置（P4 如实处理） | Method/Version/KeepAlive/WireFault/SrcPort/ManifestURI/Rounds/BootstrapBytes 无消费点：或消费（KeepAlive→Connection 头、SrcPort→真多连接与 G-HDS-3 联动）或删除，不悬空；media `url=` 属性有消费（`builder.go:40`），保留；47 基线 `SizeOverride` 从未存在，不引入 |

**接口签名**（现状，P4 钉死序号算法时增补）：`buildF4MManifest(m, profile)` / `buildBootstrapBox(media, profile)` / `buildF4FFragment(body)` / `validateHDSConfig(spec)` / `generateHDSTransformer(ctx, req)`。
**数据结构**：见 types.go:478-534（`HDSSession.Rounds` translate 默认 1 但无消费点，P4 或消费或删）。
**主流程**：validateSpec→逐 session build body→EmitMsg→http 变换器包帧→tcp→pcap/NIC。
**错误分支（§5.2）**：①自然守卫 6 锚词（§7 表）；②validate_layers 载体预检（存量）；③P4 新增：顶层 hds presence、白名单游离、sessions 空 pcap 例。全部→task error，零假成功。
**依赖声明（§5.1）**：依赖 `http` 层（GET/200/Content-Length/keep-alive）+ `tcp` 层（握手/分段/挥手）；无外部密钥/证书依赖。
**性能设计与验收（§6.1–6.8）**：O(n) 流式——逐 session 渲染直发 EmitMsg，无全量聚合；确定性内存（单 session body，无按包增长结构）；无锁无 sleep（事件驱动）；pcap 路实测 + NIC 路同契约（过滤器 `tcp port 80`，checksum offload 不断言）；回归口径=hds.json 全量 suite 耗时 ±10%；六类场景（基线/目标规模/压力上限/长运行时/并发交错/背压）P5 跑测覆盖；边界诚实声明：吞吐/并发/内存目标数字待 P4 基准后定（§6.5，不写承诺）。
**与现有逻辑冲突点（§8.7）**：http 层在 hds 链中作 body→帧变换器（hls/http_flv 同款分工，非透传族）；`DependsOn ["http"]` 使无 http 链天然不可达（mmse 同款，`carrier_no_http` 无需豁免——hds 无裸 TCP profile）；FieldContract 80 与 fixture 显式端口共存；迁层时 `case "hds"` 双轨禁并存（flat 判死后无双轨，goose 同款纪律）。
**回滚方式（§8.8）**：P4 改写 revert 单提交（cases + convert + translate + gate 块）；registry/schemagen 无变更不需回退；无数据迁移面。

## 14. P3 测试对接清单（T-HDS 草稿输入；正文落 testcase 文件）

- §3.15 三项：①同连接多轮操作→#6/#7（已覆）；②非正常结束→4 守卫负例已覆半程，FIN/RST mid-transaction + 服务端 abort→G-HDS-3；③长保活→#7/#11（已覆，恒置语义）。无空项。
- A′/B′ 两分类表：见 testcase §8（A′=引擎可构建→17 ID 内已覆；B′=G-HDS-2/3/4 进 D-条目"明确不解决+迁入计划"，G-HDS-1 为 P4 必含不进 B′）。
- 9.52 对账两行：见 testcase §8（规范逻辑点 42 = 已覆 20 + P4 必含 8 + B′ 14；清单出处=Adobe 规范反推）。
- 3.14 豁免边界审计：见 testcase §8（sessions[] 必写不豁免；真并发缺→G-HDS-3；单 body 多盒 abst 嵌套→#2 形状已覆）。
- 三源回指行：见 testcase §8。
- 断言通道：fields 用 `http.*`/`tcp.*`/`ip.*`/`ipv6.nxt`（P4 实证钉死字段名，不自创 `hds.*`）+ frames hex 钉盒字节（P4 补）；动态 id/serial/nonce 类用 presence/nonzero/distinct/same_as。

## 15. 缺口立项清单（有缺口写"缺口立项"，不许空着）

| 立项号 | 缺口 | 确认方式（三选一） | 去向 |
|---|---|---|---|
| G-HDS-1 | 顶层 `hds` 子映射迁层（17 例改写 + presence 守卫 + `flow_control` 补齐 + 链级红例载体/presence/游离 + 生成式 bootstrap 与非默认端口 pcap 例 + `check_hds`） | 照 §12.1 去向表改写（问谁：无，形状确定） | P4 必含（D-HDS-1 §13；门2 ①顶层零残留硬门） |
| G-HDS-2 | validator/断言语义鸿沟：XML 语义、box 越界/count/run 单调/timescale 一致/引用交叉/URI-kind 一致、size 公式断言、wire_fault 未消费、非 GET 拒绝 | 查 Adobe spec PDF + 抓回环包（与 G-HDS-4 同源确认） | B′→D-HDS-1"明确不解决+迁入计划"（P4 fixture 可构建性待定） |
| G-HDS-3 | 状态/连接语义：真多连接隔离（SrcPort 消费）、live 单调更新断言、recorded FIN 终止、keep_alive=false 生效、discontinuity/size 扩展、代理形/443 opaque | 查 Adobe live 语义 + 抓包（问谁：无，抓包即确认） | B′→D-HDS-1"明确不解决+迁入计划" |
| G-HDS-4 | 规范逐字节复核（盒内定序字段）+ `tshark -G fields` 字段实证 + 先跑后钉 frames | 查 Adobe spec PDF + 本机 tshark | P4 前置确认项，不挡开工 |

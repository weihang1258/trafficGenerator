# #125 sctp（Stream Control Transmission Protocol · RFC 4960，IP proto 132，raw-IP 自驱终层）设计契约

> 版本：v1.0.0（as-built 文档轨；修订记录见 §15）
> 日期：2026-09-29
> 车道：批次二文档轨（#125 sctp）
> 旧基线：**无**——`docs/protocol-designs/` 下**从无 sctp 设计/用例文档**（机读实测：`ls docs/protocol-designs/ | grep -i sctp` 零命中；`INDEX.md` 无 sctp 行）。本 #125 是**首次成文**，非续号重审。存量实现与用例均已在 D-SCTP-1（P-PIPE 车道）落码落库，本契约按 as-built 逆向定稿。
> 存量用例：`trafficgen/test/protocol_pcap/cases/sctp.json`（**11 例 = 8 正 + 3 负**，ID/顺序/包数/断言本版逐条机读对账，§9；**11/11 例 `spec_json` 顶层键仅 `{layers}`，零残留**）
> 规范基线：① **RFC 4960**（SCTP，下称 **spec**——章节号已对 rfc-editor.org 原文核实：§3.1 公共头 / §3.2 Chunk 通用格式 / §3.3.1–3.3.13 Chunk 定义 / §5.1 关联建立（四路握手）/ §6.8 CRC32c 校验和）；② **RFC 9260**（4960 的 2022 修订版，**未逐条核对**，缺口 G-SCTP-14）；③ 本机 tshark **3.6.14** `sctp.*` 字段表（`srcport/dstport/verification_tag/checksum/chunk_type/chunk_flags/chunk_length/data_tsn/data_sid/data_ssn/data_payload_proto_id/init_initiate_tag/initack_initiate_tag/cookie` 等实测在册）与 9 个磁盘 pcap（`/tmp/mcp-pcaps/sctp/`，8 正 + t9 的 0 帧 neg.pcap；文件日期 2026-09-27）；④ 本仓库落码（`internal/protocol/sctp/` 两文件 + 接线九处，§11）；⑤ 协议文档需求 v1.3 与 `116-ngap-design.md`（同族参照：ngap 是 SCTP 承载的应用层；**其 M-1 是应用面 PER 编码问题，与本层 SCTP 承载面无关**——两车道结论互不搬用）
> 白话一句：**SCTP 自成一个"带序号收据的邮政系统"——先四步握手换暗号（INIT→INIT-ACK 带 Cookie→COOKIE-ECHO 回信→COOKIE-ACK），然后按条寄包裹（DATA 块带 TSN/SID/SSN/PPID），顺手发心跳探测备用地址（HEARTBEAT），最后三步告别（SHUTDOWN→ACK→COMPLETE）或直接摔门（ABORT）。本生成器把这套流程按配置剧本重放，不实现重传/拥塞控制/SACK。**

## 0. 首次成文声明与既有产物校正（门1 必答：基线继承关系）

**无旧稿可承**：本协议在 `docs/protocol-designs/` 下没有任何前序设计或用例文档。本节对既有实现、既有产物与任务书表述做逐条对照校正（这是门1 的"基线"面）：

| # | 既有说法/产物 | HEAD 实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | 任务书提示"Chunk 类型（DATA 0/**PAYLOAD 1**/INIT 1/INIT-ACK 2/HEARTBEAT 4/...）" | RFC 4960 §3.3 chunk 类型表：**0=DATA（Payload Data）、1=INIT**——type 1 只有一个名字 INIT，**不存在独立的 "PAYLOAD" chunk 类型** | 任务书笔误，本版按 RFC 原文写（§3.2）；依赖链判定纪律：可判题直接判，不问偏好 |
| 2 | 任务书提示"存量 11 例" | 机读实测 **11 例**（8 正 + 3 负），ID 唯一、顺序稳定 | 一致 ✓ |
| 3 | `trafficgen/docs/protocol-pcap-test/sctp.md`（tracked 产物）写 `Cases: 11 — pass 11, fail 0, error 0`，末次提交 `94adc3c`（**2026-09-21**） | 判死提交 `0417be5`（2026-09-13）**是** 94adc3c 的祖先（`git merge-base --is-ancestor` 实测✓）→ 末次提交**晚于**判死提交 → **按批次二任务书口径，本产物不属于"过期产物"**，不登记为该类缺口（ngap §0 #3 同判） | 不登记产物过期缺口；但 `docs/protocol-pcap-test/sctp/` 目录不存在（**0 个 pcap 留档**，与全仓共性一致：`ls -d docs/protocol-pcap-test/*/` = 0）——登记为事实注记（§14 表后注记），非缺口 |
| 4 | 上条产物中的 pcap 链接指向 `sctp/<id>.pcap` | 磁盘 pcap 在 `/tmp/mcp-pcaps/sctp/`（8 正 + 1 neg，9 文件；t10/t11 为建链期拒绝无 pcap） | 本车道**未重跑引擎**；§9 断言全部对**磁盘既有 pcap** 机读复算（47/47 零不符，取证边界见 §0 末） |
| 5 | 任务书要求"参考同族 ngap（#116）…但不要复制其结论" | ngap 的 M-1 是 **NGAP-PDU 位域（应用面）**问题；本层是 SCTP **承载面本身**，线格式逐帧实测无位域问题；但本车道发现**独立于 ngap 的 M-1**（CRC 覆盖范围，§3.8/M-1） | 两车道 M-1 互不相关 ✓；本车道 M-1 为新发现（且经独立复算钉死，非搬用） |
| 6 | 代码注释/用例 notes 多处引 "RFC 4960 **§3.5.1**"（HEARTBEAT，`sctp.go:30`、t5 notes） | rfc-editor.org 实测：HEARTBEAT = **§3.3.5**（§3.3 Chunk Definitions 序列 3.3.1–3.3.13）；§3.5 不存在 | **引用漂移**（§3.5.1 → §3.3.5）；同类：随机初始 TSN 的出处引 "RFC 6525 §5.1"（`sctp.go:216`）——RFC 6525 是流重配置扩展，该出处**疑似错位**，本版标注待核（G-SCTP-14）。本版正文一律按已核实的 RFC 章节号引用 |
| 7 | `sctp.go` 包注释（:24-36）与 `emitSCTPHeartbeats` 注释（:749-750）声称 AltPath 子流 "the GroupID is inherited from the parent so both paths route to one PacketWorker" | `emit`/`emitHB`（`sctp.go:225-248/791-814`）构造 `PacketConfig` **从不写 GroupID 或 `Metadata["group_id"]`**（grep 全包零命中）→ worker 回退 4 元组哈希（`shard_router.go:140-152`），备用路径与主路径**不保证同 worker** | 注释**过度声明**；`flowID + ":hb"` 后缀把心跳拆成独立 flow。存量 T-6 断言（fields 的 `ip.src`）不依赖跨 worker 保序，**不假绿**；登记 G-SCTP-5 附表 |
| 8 | `types.go:2836-2853` 注释：`VerificationTag` = "the tag the server should put in packets it sends to the client"、`InitiateTag` = "the tag the client puts in the Verification Tag field of packets it sends to the server" | planner 实映射（`sctp.go:198-205`）：`VerificationTag` → **INIT 的 InitiateTag 参数值**（客户端宣告 tag）+ down 帧的 VTag；`InitiateTag` → **INIT-ACK 的 InitiateTag 参数值**（服务端宣告 tag）+ up 帧的 VTag。T-2 实测：f2 INIT-ACK VTag=`12345678`(=config `verification_tag`)、f3 COOKIE-ECHO VTag=`87654321`(=config `initiate_tag`) | **两条注释同义反复、且键名与内容方向易混**：config `verification_tag` 配的是**客户端**宣告 tag，config `initiate_tag` 配的是**服务端**宣告 tag（"initiate_tag"这个键名容易误读成配 INIT 发起方）。行为本身 RFC 自洽（§5.1 VTag=对端宣告 tag），本版 §3.7 映射表钉死 |

**依赖链判定纪律**：以上均为可判题（产物→代码→pcap→RFC 原文四级对照），直接判定，不问偏好。不可判的（RFC 9260 差异面、RFC 6525 §5.1 出处）标"待确认"并写清确认方式（G-SCTP-14）。

**本车道取证边界（诚实声明，重要）**：本车道**未重跑引擎**。§9 的"逐条一致"是**存量 cases JSON 的断言 × 磁盘上既有 pcap（`/tmp/mcp-pcaps/sctp/`，文件日期 2026-09-27）** 的机读对账结果：**20 条 frame 断言 + 19 条 field 断言 + 8 条包数断言，47/47 零不符**（复算脚本口径：tshark `-T json -x` 逐帧比对）。这不等于"今日复跑套件绿"。

## 1. 范围、profile 与实现状态边界

本版定义 **SCTP（RFC 4960）作为 IP proto 132 的 raw-IP 自驱传输层**流量生成：四路关联建立（INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK）、可选 HEARTBEAT（主路径/AltPath 多宿）、DATA 块序列（含分片 B/E/middle）、三路 SHUTDOWN 或 ABORT 突断。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `sctp_v4_v1`（主，唯一实现） | SCTP over IPv4，链 `[ip, sctp]` | 4 握手 → [HB 对] → DATA 序列（可分片）→ 3 路 SHUTDOWN 或 ABORT | 真实端点语义（SACK 应答、重传、拥塞窗口） |
| `sctp_altpath_v1` | 同上 + `heartbeats.alt_path` | 备用 4 元组心跳子流 + INIT/INIT-ACK 携带 IPv4 Address 参数 | 真实多宿主切换/ASCONF/ADD-IP |
| `sctp_v6_v1` | — | **结构支持、未取证**（Validate 不拒 IPv6 父地址；`EtherTypeFor`/`writeL3v6` 在册；**今日零用例**，G-SCTP-6） | 从 IPv4 推导 IPv6 行为 |

显式边界（"不实现、不声称、不许静默转换"）：① **不实现 SACK**——`buildSACKChunk`（type 3）与 `buildERRORChunk`（type 9）在 `sctp.go:689/718` 已落码但**零调用点**（grep 实测），DATA 帧后无任何确认块；② **不实现重传/拥塞控制/流控**——TSN 只自增不回卷重传，aRwnd 恒 65535；③ **不实现真实多流调度**——SID/SSN 是 per-chunk 配置直通值（无 per-stream 状态机、SSN 不自增）；④ **不实现 ASCONF/ADD-IP/动态地址重配置**——多宿只覆盖"心跳探测备用地址"形态；⑤ **不实现 AUTH/FORWARD-TSN/I-DATA**（RFC 4895/3758/9260 扩展）；⑥ **AltPath 仅 IPv4**（`Validate` `sctp.go:137/149` 显式拒 v6，锚词 `only IPv4 multi-homing`）且须与父路径同族（`:140/152`）；⑦ 不声称产出的流可被真实 SCTP 端点无差错接收（M-1：填充帧 CRC 范围缺陷，§3.8）。

**实现状态（2026-09-29 实测）**：`sctp` 层已注册（`registry.go:2071`，`CategoryTerminal`，`DependsOn ["ip"]`，**Fields 8 键**）；生成表同代（`schemas/v1/generated/layers.generated.json` 的 sctp 条目 = terminal / ["ip"] / 同 8 键同区间，机读实测逐键一致）；planner/生成器已落码（`internal/protocol/sctp/sctp.go` **835 行** + `layer_gen.go` **72 行**；测试 6 文件 **61 个 `Test*`**，`grep -c` 实测）；`allowedProtocols["sctp"]=true`（`protocols.go:54`）；层内 translate 已接线（`chain_planner_translate.go:2863`）；顶层 presence 判死已接线（`strategy_convert.go:9098` rawWrapChains）；raw-IP 自驱判定已列名（`chain_planner_util.go:40-58`）；端口语义豁免已列名（`chain_planner.go:799/996`）；`cmd/server/main.go:145` 空导入。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`sctp.srcport/dstport`、`sctp.chunk_type`、`ip.src`、frames offset 46）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。存量 11 例全部只用两路径均可观察的字段。

## 2. 协议栈、端口和固定偏移

推荐层链为 **`[ip, sctp]`**——sctp 是 **raw-IP 自驱终层**：SCTP 自成 L4（IP proto 132，`builder.go:61` `ProtocolSCTP`），链上**没有 tcp/udp 层**，sctp 层生成器把 legacy `Plan` 产出的每个 `PacketConfig` 直送 `Emit`，由框架 builder 组装完整以太帧（`isRawIPChain`，`chain_planner_util.go:40-58`）。存量 **11/11 例**层链均为 `[ip, sctp]`（机读实测）。

> **方向纪律（`layer_gen.go:55`）**：生成器把**每一帧**强制 `pkt.Direction = "up"`（xmpp/vnc 同款防双换）。legacy `Plan` 已按方向**自行交换** src/dst IP、端口与 MAC（`sctp.go:270-421` 逐 emit 自管），raw-IP 驱动若再对 down 包做 L3 换向会**双换**出错。故"方向"语义只体现在**帧内的地址/端口排列**上（§3.7 逐帧表），不体现在 `Direction` 元字段。

端口：**无协议级缺省**（`strategy_convert.go:1134-1140` 注释明写不静默改 80/38412；`chain_planner.go:799/996` 双豁免名单——目的端口 0 合法）。存量 11/11 例显式写 `12345/5000`（5000 为**中性端口**：刻意避开 38412(NGAP)/2905(M3UA) 等现网特征值——t1 notes 自陈，特征端口/PPID 会触发 tshark 启发式 dissector 误报 Malformed；本车道 8 个正例 pcap 实测 0 malformed）。`src_port` 缺席 → worker 按 `12345+i` 保底注入（`worker.go:307-309`，多流）；`dst_port` 缺席 → **0 上包**（链路径无缺省，flat 路径才会落通用 80——两路径不一致见 G-SCTP-4 附注）。

**固定偏移（无 VLAN / 无 IP options——SCTP 无 options 概念，IPv4 无 extension）**：

| 层 | 起点 | 长度 | 说明 |
|---|---:|---:|---|
| Ethernet II | 0 | 14 | `02:00:00:00:00:01` → `02:00:00:00:00:02`（up 方向；MAC 由 spec 缺省） |
| IPv4 | 14 | 20 | 无 options；TTL 缺省 **64**（`DefaultTTL`，`sctp.go:50`）；IP ID 从随机值起**逐帧 +1**（`sctp.go:209-214`） |
| SCTP 公共头 | 34 | 12 | SrcPort(2) + DstPort(2) + VerificationTag(4) + **CRC32c 校验和(4)**（`builder.go:1304-1313` + `fillSCTPChecksum:1326`） |
| **首个 chunk** | **46** | 变长 | chunk Type(1) + Flags(1) + Length(2) + Value；**Value 填充到 4 字节边界**（`buildChunk`，`sctp.go:474-483`） |
| DATA 块的用户载荷 | **62** | 变长 | = 46 + 16（DATA value 头：TSN 4 + SID 2 + SSN 2 + PPID 4） |
| IPv6 载体（未取证，G-SCTP-6） | 14 | 40 | chunk 起点 **74**；结构支持（`writeL3v6`，`builder.go:1220`） |

**帧长公式（实测复算，8 个 pcap 70 帧零例外）**：

```
chunk_len = 4 + len(chunk_value)            # Length 字段含 4B 头，不含填充
padded    = (chunk_len + 3) &^ 3            # 4 字节边界填充（buildChunk sctp.go:476-477）
frame.len = max(60, 46 + padded)            # 60 = 以太网最小帧（builder.go MinEthernetFrame）
```

**校验**（全帧 `tshark frame.len` 实测）：f1 INIT `chunk_len=20` → 66 ✓；f2 INIT-ACK 56 → 102 ✓；f3 COOKIE-ECHO 36 → 82 ✓；f4 COOKIE-ACK 4 → 50，**被以太网最小帧抬到 60** ✓；DATA("ping") 20 → 66 ✓；HEARTBEAT 24 → 70 ✓；带 Alt 参数 INIT 28 → 74 ✓（t6 f1）；分片首段 32 → 78 ✓、末段 20 → 66 ✓（t4 f5/f11）；ABORT 4 → 60 ✓。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**本协议存量 11/11 例已是此形，零迁移工作量**）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"sctp": {"src_port": 12345, "dst_port": 5000}}
  ]
}
```

带业务字段的完整形状（等价于 T-3 + T-8 组合的声明面）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"sctp": {
      "src_port": 12345, "dst_port": 5000,
      "verification_tag": 305419896, "initiate_tag": 2271560481,
      "chunks": [{"direction": "up", "tsn": 100, "sid": 5, "ssn": 7, "ppid": 47, "data": "m3ua"}],
      "heartbeats": {"count": 2, "alt_path": {"alt_src_ip": "10.0.0.9", "alt_dst_ip": "20.0.0.9"}},
      "abort": false, "fragment_size": 0
    }}
  ]
}
```

多流样例（数量只走 `flow_control`；本协议存量未用——端口动态不可用，见 G-SCTP-3，多流只能靠 `ip.src/dst` 动态变址）：

```json
{
  "layers": [
    {"ip": {"src": {"strategy": "inc", "range": ["10.0.1.1", "10.0.1.2"], "step": 1}, "dst": "20.0.0.1"}},
    {"sctp": {"src_port": 12345, "dst_port": 5000}}
  ],
  "flow_control": {"flows": 2}
}
```

## 3. 线格式编码（逐字段，按代码 + pcap 双向钉）

### 3.1 SCTP 公共头（12 字节，RFC 4960 §3.1；`builder.go:1304-1313`）

| 偏移（帧内） | 字段 | 尺寸 | 端序 | 取值 |
|---:|---|---:|---|---|
| 34 | SrcPort | 2 | 大端 | up 帧 = spec.SrcPort；down 帧 = spec.DstPort（端口互换在 planner emit 处完成） |
| 36 | DstPort | 2 | 大端 | 同上反向 |
| 38 | VerificationTag | 4 | 大端 | §3.7 逐帧表（RFC 4960 §5.1：INIT 恒 0，其后各帧带**对端宣告 tag**） |
| 42 | Checksum | 4 | 大端 | **CRC32c（Castagnoli，RFC 4960 §6.8）**——覆盖范围见 §3.8/M-1 |

tshark 进制纪律（实测）：`sctp.srcport/dstport`、`sctp.chunk_type`、`sctp.chunk_flags`、`sctp.data_tsn`、`sctp.data_sid`、`sctp.data_ssn`、`sctp.data_payload_proto_id` 用**十进制串**；`sctp.verification_tag`/`sctp.checksum` 用 `0x` 前缀十六进制串；`sctp.chunk_length` 十进制。存量 19 条 field 断言全部落在十进制面（chunk_type/srcport/dstport/ip.src）。

### 3.2 Chunk 通用头与填充（RFC 4960 §3.2；`buildChunk`，`sctp.go:474-483`）

| chunk 偏移 | 字段 | 尺寸 | 说明 |
|---:|---|---:|---|
| 0 | Type | 1 | §3.2 类型表 |
| 1 | Flags | 1 | 各类型专属（§3.4/§3.6） |
| 2 | Length | 2 大端 | = `4 + len(Value)`，**含 4B 头、不含填充** |
| 4 | Value | 变长 | 后填充 `pad = (Length+3) &^ 3 - Length` 个零字节 |

**实现的两遍编码在此退化为一次**：`buildChunk` 先算 `padded = (length + 3) &^ 3` 一次分配，Length 写未填充值、缓冲按填充值分配——与 ngap 的"chunk 层负责补齐"同构。

**Chunk 类型表（RFC 4960 §3.3，值域全表；本实现状态逐行标注）**：

| Type | 名称 | RFC 章节 | 本实现 |
|---:|---|---|---|
| 0 | Payload Data (DATA) | §3.3.1 | **入线**（chunks 配置；分片 B/E） |
| 1 | Initiation (INIT) | §3.3.2 | **入线**（握手第 1 帧） |
| 2 | Initiation Acknowledgement (INIT ACK) | §3.3.3 | **入线**（握手第 2 帧，携 State Cookie） |
| 3 | Selective Acknowledgement (SACK) | §3.3.4 | **死代码**（builder 在册零调用，G-SCTP-11） |
| 4 | Heartbeat Request (HEARTBEAT) | §3.3.5 | **入线**（T-5/T-6；代码/notes 引用漂移为 "§3.5.1"，G-SCTP-14） |
| 5 | Heartbeat Acknowledgement (HEARTBEAT ACK) | §3.3.6 | **入线**（echo HB Info） |
| 6 | Abort Association (ABORT) | §3.3.7 | **入线**（abort=true；T-7） |
| 7 | Shutdown Association (SHUTDOWN) | §3.3.8 | **入线**（优雅关闭第 1 步） |
| 8 | Shutdown Acknowledgement (SHUTDOWN ACK) | §3.3.9 | **入线** |
| 9 | Operation Error (ERROR) | §3.3.10 | **死代码**（builder + 9 个 EC* Cause 常量零消费，G-SCTP-11） |
| 10 | Cookie Echo (COOKIE ECHO) | §3.3.11 | **入线**（回显 32B cookie） |
| 11 | Cookie Acknowledgement (COOKIE ACK) | §3.3.12 | **入线**（4B 空块） |
| 12/13 | Reserved (ECNE/CWR) | — | 不实现 |
| 14 | Shutdown Complete (SHUTDOWN COMPLETE) | §3.3.13 | **入线**（T bit=0：发送方有 TCB） |
| 15+/64+/128+/192+ | AUTH/扩展/试验段 | — | 不实现 |

常量在册：`ChunkDATA…ChunkSHUTDOWNComplete` **13 值**（`sctp.go:54-66`，覆盖 §3.3.1–§3.3.13 的 13 个已分配类型；12/13 保留位无常量）；分片 flags `ChunkFlagBeginEnd=0x03/Begin=0x02/End=0x01/Middle=0x00`（`:69-78`）；EC* Cause Code 9 值（`:81-90`，**全部零消费**）。

### 3.3 INIT（type 1）与 INIT-ACK（type 2）

**INIT value（固定 16B + 可选参数；`buildINITChunk`，`sctp.go:494-505`；RFC 4960 §3.3.2）**：

| value 偏移 | 字段 | 尺寸 | 端序 | 取值 |
|---:|---|---:|---|---|
| 0 | InitiateTag | 4 | 大端 | = config `verification_tag`（0 → `randNonZeroTag()` 随机非零，`:198-201`）；**common header 的 VTag 字段此时恒 0**（RFC 4960 §5.1，T-2 f1 @38 实测 `00 00 00 00`） |
| 4 | aRwnd | 4 | 大端 | **恒 65535** |
| 8 | OS (Num Outbound Streams) | 2 | 大端 | **恒 10**（不配置化，G-SCTP-12） |
| 10 | MIS (Num Inbound Streams) | 2 | 大端 | **恒 10** |
| 12 | InitialTSN | 4 | 大端 | `rand.Uint32()` 随机（`:219`；注释引 RFC 6525 §5.1 疑似错位，G-SCTP-14）；per-chunk 显式 `tsn` 可钉首帧 |
| 16+ | 可选参数 | 8/个 | — | **IPv4 Address 参数**（type 5，见下）× AltPath.SrcIP 声明的客户端备用地址数 |

**长度公式**：`INIT chunk_len = 20 + 8×altIP数`（实测 T-1/T-2 无 alt = 20、T-6 带 1 alt = 28 ✓）。

**INIT-ACK value（16B 固定 + State Cookie 参数 + 可选 IPv4 参数；`buildINITAckChunk`，`sctp.go:512-527`；RFC 4960 §3.3.3）**：固定 16B 同布局（InitiateTag = config `initiate_tag`、aRwnd 65535、OS/MIS 10/10、InitialTSN = serverTSN 随机）+ **State Cookie 参数**（type 7；Length = `4 + 32` = 36；cookie 为 `rand.Read` 的 **32 随机字节**，`sctp.go:279-280`）+ IPv4 参数（type 5）× AltPath.DstIP 数。**长度公式**：`INIT-ACK chunk_len = 56 + 8×altIP数`（实测 56/64 ✓）。

**IPv4 Address 参数（type 5；`buildIPv4AddrParam`，`sctp.go:533-543`；RFC 4960 §3.3.2.1）**：`Type(2)=5 + Length(2)=8 + IPv4(4)`，**无保留字段**（RFC 4960 口径，非 2960 的 8+2）。**语义**：INIT 只携带**发送方**（客户端）的 AltPath.SrcIP；INIT-ACK 只携带**服务端**的 AltPath.DstIP（`sctp.go:261-269`）——T-6 f1 @66 实测 `00 05 00 08 0a 00 00 09`（type 5 len 8 + 10.0.0.9）✓。**v6 拒绝**：非法 IPv4 → 参数静默不产出 nil（`:534-536`），由 Validate 前置拒绝（锚词 `invalid AltPath.SrcIP`/`only IPv4 multi-homing`，§7）。

### 3.4 DATA（type 0）与分片

**DATA value（`buildDATAChunkWithFlags`，`sctp.go:567-575`；RFC 4960 §3.3.1）**：

| value 偏移 | 字段 | 尺寸 | 端序 | 取值 |
|---:|---|---:|---|---|
| 0 | TSN | 4 | 大端 | per-chunk 显式 `tsn`，或 per-direction 计数器（clientTSN/serverTSN，随机初值自增 `:360-368`）；**显式 tsn 不推进计数器**（分片从 tsn 向前走 i） |
| 4 | SID | 2 | 大端 | per-chunk `sid` 直通（缺省 0；**无 per-stream 状态**，§1 边界③） |
| 6 | SSN | 2 | 大端 | per-chunk `ssn` 直通（缺省 0，**不自增**） |
| 8 | PPID | 4 | 大端 | per-chunk `ppid` 直通（缺省 0；T-8 钉 47） |
| 12 | 用户数据 | len(data) | — | `data` 字符串字节或字节数组（`parseSCTPChunks` 双形，`strategy_convert.go:6584-6625`）；FileSource 可供源（`resolveSCTPChunkData`，`sctp.go:446-456`：FileSource 优先于 inline Data，无 cache 时**跳过该 chunk 不回退**——FTP 同款优先级契约） |

**长度公式**：`DATA chunk_len = 16 + len(data)`（实测 "ping"/"m3ua" 4B → 20 ✓；分片首段 16B → 32 ✓、末段 4B → 20 ✓）。

**Flags（RFC 4960 §3.3.1 B/E 位；`splitDATAChunk`，`sctp.go:593-618`）**：

| Flags 值 | B | E | 语义 | 入线场景 |
|---:|---|---|---|---|
| 0x03 | 1 | 1 | 完整未分片消息 | 缺省（fragment_size=0 或 payload ≤ fragment_size） |
| 0x02 | 1 | 0 | 分片首段 | fragment_size>0 且多段 |
| 0x00 | 0 | 0 | 分片中段 | 同上 |
| 0x01 | 0 | 1 | 分片末段 | 同上 |

**分片算法**：`fragment_size`（registry V9 区间 [16, 1000000]，`registry.go:2078`）> 0 且 len(data) > fragment_size 时按 fragment_size 切段（T-4：100B@16 → 7 段 = 6×16+1×4；**同一条消息各段共享 SID/SSN/PPID**、TSN 连续 500→506）。**空载荷合法**：data 为空仍产 1 个 B+E 块（`sctp.go:592-595` 注释：RFC 4960 §3.3.1 允许零用户数据）——今日无用例（A′，§10.3 行 20）。**U（unordered）位不实现**（恒 0）。

### 3.5 HEARTBEAT（type 4）与 HEARTBEAT-ACK（type 5）

（`buildHEARTBEATChunk/…AckChunk`，`sctp.go:662-679`；RFC 4960 §3.3.5/§3.3.6——代码/notes 引 "§3.5.1" 为引用漂移，G-SCTP-14）

| value 偏移 | 字段 | 尺寸 | 取值 |
|---:|---|---:|---|
| 0 | Heartbeat Info 参数 Type | 2 | **恒 1** |
| 2 | 参数 Length | 2 | `4 + 16` = 20 |
| 4 | Info 令牌 | 16 | 4B magic `0x48425443`（"HBTC"）+ 4B 迭代计数 i + 8B `rand.Read` 随机（`sctp.go:819-823`）——**ACK 原样回显**（T-5 语义；字节今日无用例钉，G-SCTP-13） |

**长度公式**：`chunk_len = 24`（实测 70 ✓）。**插入位置**：COOKIE-ACK 之后、首 DATA 之前；无 DATA 时在 SHUTDOWN 之前（`sctp.go:302-318` 代码序，t1 notes 自陈）。**HEARTBEAT-ACK 端口互换**：down 帧以 spec.DstPort 为源（`sctp.go:832` 注释"matching INIT-ACK's port-swap pattern"）。

### 3.6 关闭：SHUTDOWN 三路（type 7/8/14）与 ABORT（type 6）

（RFC 4960 §3.3.8/§3.3.9/§3.3.13/§3.3.7）

| 块 | value | chunk_len | Flags | 语义 |
|---|---|---:|---|---|
| SHUTDOWN | Cumulative TSN Ack 4B 大端 | 8 | 0x00 | = `serverTSN - 1`（`sctp.go:404-410`：服务端最后已发 TSN）。**服务端无 DATA 时 serverTSN 为随机初值 → 该值无意义**（G-SCTP-10，与 ngap G-NGAP-7 同构） |
| SHUTDOWN ACK | 无 | 4 | 0x00 | — |
| SHUTDOWN COMPLETE | 无 | 4 | 0x00 | **T bit（flags bit0）= 0**：发送方持有 TCB（正常关闭方，`sctp.go:634-638` 注释） |
| ABORT | 无 Cause | 4 | 0x00 | **T=0**：关联已知（非 T=1 的"无 TCB"形态，`sctp.go:641-655` 注释）；**替代**三路关闭非叠加（T-7 实测 5 帧 = 4 握手 + 1 ABORT ✓） |

### 3.7 VerificationTag 逐帧映射（RFC 4960 §5.1；T-2 双 Tag 实测钉死）

宣告 tag：客户端宣告 = config `verification_tag`（INIT 的 InitiateTag 参数，T-2 = `0x12345678`）；服务端宣告 = config `initiate_tag`（INIT-ACK 的 InitiateTag 参数，T-2 = `0x87654321`）。缺省（=0）→ `randNonZeroTag()` 每侧独立随机（`:198-205`）。

| 帧 | 方向（帧内地址排列） | common header VTag @38 | T-2 实测 | T-1 实测（随机） |
|---|---|---|---|---|
| INIT | up（10.0.0.1→20.0.0.1） | **0**（RFC §5.1：INIT 恒 0） | `00 00 00 00` ✓ | 0x00000000 ✓ |
| INIT-ACK | down（20.0.0.1→10.0.0.1） | 客户端宣告 tag | `12 34 56 78` ✓ | 0x680257af |
| COOKIE-ECHO | up | 服务端宣告 tag | `87 65 43 21` ✓ | 0x9e2c4ea8 |
| COOKIE-ACK | down | 客户端宣告 tag | `12 34 56 78` ✓ | 0x680257af |
| HEARTBEAT / DATA(up) / SHUTDOWN / SHUTDOWN-COMPLETE / ABORT | up | 服务端宣告 tag | —（T-1/T-5/T-6/T-7 实测同 COOKIE-ECHO 值 ✓） | 0x9e2c4ea8 |
| HEARTBEAT-ACK / DATA(down) / SHUTDOWN ACK | down | 客户端宣告 tag | —（同 INIT-ACK 值 ✓） | 0x680257af |

### 3.8 CRC32c 校验和（RFC 4960 §6.8）与 **M-1（confirmed finding）**

`fillSCTPChecksum`（`builder.go:1326-1333`）：CRC32c Castagnoli（多项式 0x1EDC6F41 反射形），计算前把 checksum 字段置零，`crc32.Checksum(packet[l4Start:])` 写回 `packet[l4Start+8:l4Start+12]`。调用点在 `Build`（`builder.go:427-429`）——**在以太网填充之后**（`Build` :329-331 先把总长抬到 MinEthernetFrame 60）。

**M-1：CRC32c 覆盖范围把以太网填充字节算进去了（confirmed finding，代码级 + pcap 级双实证）**。RFC 4960 §6.8 要求 CRC 覆盖"整个 SCTP 包"——SCTP 包的长度由 IP 总长定界（公共头 + 全部 chunk 含 chunk 级 4 字节填充），**以太网填充不属于 SCTP 包**。本实现的 CRC 以 `packet[l4Start:]`（缓冲区尾）为界，帧短于 60 字节被填充时把填充零字节一并计入。

**实证（本车道独立复算，反射多项式 0x82F63B78 自写表）**：8 个正例 pcap 共 **70 帧，其中 30 帧被填充**（IP 总长 < 46 → 帧长抬到 60）；**30/30 帧的存储 CRC = "含填充"口径计算值，且 ≠ "IP 总长定界"口径计算值**；另 40 帧未被填充，两口径重合、存储 CRC 与 IP 定界口径一致 ✓。即：**凡被以太网填充的 SCTP 帧，其线上的 CRC32c 对符合 RFC 定界的接收端必然校验失败**。tshark 3.6.14 对全部帧报 `sctp.checksum.status=2`（Unverified——该校验缺省关闭），**存量 47 条断言零条覆盖 checksum 面**，故 11 例全绿而未捕获（"绿 ≠ 对"实例）。

**修复方向（代码阶段，本车道不改码）**：CRC 按 IP 总长定界的 SCTP 区域计算（或在以太网填充前计算）。**修复后帧长不变**（只动 4 字节），§9 包数公式与全部 frames/fields 断言不受影响；新增 `sctp.checksum` 断言须按修复后口径钉。**波及面**：同一 builder 代码服务 ngap（#116）——ngap 文档 §3.1 声称"填充字节计入 CRC（RFC 4960 §6.8 要求覆盖含填充的整段）"，**该结论与 RFC 定界口径相悖，本车道以独立复算为准、不采信**；ngap 的 pcap 中同样存在被填充帧，其存量断言同样零覆盖该面。

### 3.9 死代码与未接线面（as-built 诚实清单）

`buildSACKChunk`（`sctp.go:689-708`，SACK value = CumTSN(4)+aRwnd(4)+gap 数(2)+dup 数(2)+blocks+dups）、`buildERRORChunk`（`:718-743`，空 causes 时缺省 No User Data cause 9）与 9 个 `EC*` Cause 常量（`:81-90`）**零调用点**（grep 实测仅定义处命中）。`subflow.go` 的第二套 SCTP 组装器（`buildSCTPINITChunk :534` OS/MIS=1、`buildSCTPCookieEchoChunk :566` 空 cookie、`buildSCTPDATAChunk :576` SID/SSN/PPID 恒 0）属 `EmitSubFlow` 死分支（G-SCTP-5）。`buildDATAChunk`（无 flags 变体，`sctp.go:560-562`）仅被测试引用。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明块序列（chunks/heartbeats/abort）与双 Tag，引擎按固定剧本产出事件序列（4 握手→HB 对→DATA 序列→关闭），SCTP 自管 L4 无传输层介入。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 信令关联建立（NGAP/M3UA/S1AP 类前置） | 4 握手 + 显式双 Tag 钉 | #1 #2 |
| ② 信令双向消息交换 | DATA up/down 各带 PPID | #3 |
| ③ 大消息分片传输 | fragment_size 切段 B/E/middle | #4 |
| ④ 主路径保活探测 | HEARTBEAT 对 ×2 | #5 |
| ⑤ 多宿主备用路径探测 | AltPath 4 元组心跳 + 地址参数宣告 | #6 |
| ⑥ 异常中断 | ABORT 替代三路关闭 | #7 |
| ⑦ 协议字段显式钉（TSN/SID/SSN/PPID） | DATA 全头 | #8 |
| ⑧ 配置边界拒绝 | AltPath 族约束 / fragment 范围 | #9 #10 #11 |
| ⑨ 现网特征端口/PPID（38412/2905/PPID 60） | — | **明确不解决**：用例刻意取中性值避开 tshark 启发式误报（t1 notes 自陈）；特征值场景由 ngap（#116）车道承载 |
| ⑩ 多流并发关联 | — | A′ 立项（G-SCTP-3：端口不可动态，多流受限） |

**五层覆盖逐层结论**：

- **功能层**——8 类入线块（INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK/DATA/HEARTBEAT/HEARTBEAT-ACK/SHUTDOWN 三路/ABORT）正例 8/8 覆盖；错误处理 3 条负例（§7）；SACK/ERROR 死代码显式登记（G-SCTP-11）。
- **性能层**——最小帧 60（COOKIE-ACK/SHUTDOWN 系 4B 块被最小帧抬高）、最大实测帧 110（t6 f2 带 alt 参数 INIT-ACK）；分片跨段（T-4 7 段）；块长度 uint16 上界 65535（registry fragment_size 上界 1e6 是配置面不是线面）；多流并发见 G-SCTP-3。**吞吐数字待 P4 基准，本版不写承诺**（§6.5）。
- **数据场景层**——边界值：fragment_size 下界 1（T-10）/上界+1（T-11）/显式 0 缺省（全正例）；空载荷 DATA 未入例（A′）；Tag 随机与显式双形态（T-1/T-2）；PPID 0/1000/47 三值；SID/SSN 显式（T-8）与缺省 0。
- **地址与流层**——**IPv4 单族已覆**；IPv6 结构支持未取证（G-SCTP-6）；单流基线（全部正例）；**流关联（本协议特有形态）= AltPath 多宿子流**：备用 4 元组心跳 + `flowID+":hb"` 后缀 + INIT/INIT-ACK 地址参数宣告（#6）——**但 GroupID 继承是注释声称未落码**（G-SCTP-5 附表），跨 worker 保序不保证；多会话/多事务显式不适用（SCTP 关联=会话，消息面无请求-响应配对语义；`sessions[]` 无 registry 键）。
- **业务层**——十场景九落点一立项（上表）；多事务不适用（同上）。

## 5. 消息/事务模型与状态机

**事务定义**：SCTP 无请求-响应配对语义（面向消息传输，非事务协议）；本生成器的"事务"= 关联生命周期阶段。

**四路握手 vs TCP 三握手（RFC 4960 §5.1 vs RFC 9293，逐条差异）**：

| 维度 | TCP 三握手 | SCTP 四握手（本实现） |
|---|---|---|
| 消息数 | 3（SYN/SYN-ACK/ACK） | **4**（INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK） |
| 第 3/4 步角色 | 第 3 步 ACK 可携数据（合并） | 第 3 步 COOKIE-ECHO 只回显 cookie，**不携数据**；第 4 步 COOKIE-ACK 后才可发 DATA |
| 身份机制 | 32bit 序号（ISN） | **32bit VerificationTag**（INIT 恒 0，其后恒带对端宣告 tag）+ 双向独立 InitialTSN |
| 防历史连接 | 无状态化 SYN-ACK（SYN flood 弱点） | **State Cookie**（INIT-ACK 携带 32B cookie → COOKIE-ECHO 原样回显；服务端本可无状态，本实现 cookie 为随机 32B 非 RFC §5.1.3 的加密 MAC——测试语义，诚实声明） |
| 协商参数 | MSS/窗口/SACK-permitted（TCP options） | InitiateTag/aRwnd/OS/MIS/InitialTSN + 地址参数（本实现 aRwnd 65535、OS/MIS 10/10 恒定） |
| 多流/多宿 | 无 | **OS/MIS 流协商 + 地址参数多宿宣告**（本实现 OS/MIS 恒 10/10；多宿宣告落线 T-6） |
| 关闭 | FIN 四包 / RST | **SHUTDOWN 三路**（携带 cum TSN ack）/ **ABORT** 单帧突断（本实现 T bit=0） |
| 校验和 | 16bit 反码（伪头） | **CRC32c 全包**（无伪头；范围缺陷 M-1） |
| 载体 | tcp 层（proto 6） | 自成 L4（proto 132），链上无 tcp/udp |

**状态机**：**本层无自有状态机**——线性硬序剧本（`sctp.go:250-421`）：INIT→INIT-ACK→COOKIE-ECHO→COOKIE-ACK→[HB 对]×count→[DATA 序列（chunks 顺序，分片连续）]→[SHUTDOWN 三路 | ABORT]。同一输入必然同一输出（除随机面：tag/TSN/IPID/cookie/HB nonce——G-SCTP-10 附确定性纪律：**存量断言零钉随机面**，机读实测；未来新增断言不得钉这五类）。引擎在某状态遇非法事件 = 配置校验拒绝（§7），无运行期状态迁移判定。

**自动派生规则（生成器自动补出的帧，逐条）**：① 四握手 4 帧恒产（不可关）；② `heartbeats` 非 nil → count 对（缺省 1）恒产（T-6 只给 alt_path 不给 count → 1 对 ✓）；③ 三路关闭 3 帧恒产，`abort=true` 时换 1 帧 ABORT（**替代非叠加**）；④ 32B cookie 每轮随机、COOKIE-ECHO 原样回显（一致性由单测 `TestPlanCookieEchoMatchesINITACK` 钉，非 pcap 断言——回显一致性静态钉不可为）；⑤ TCP 无关——无握手挥手概念，`has_handshake/negotiated/terminates` 三键恒 false（§9 形状注记）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流帧数 = 7（空配置）+ 2×HB 对 + ΣDATA 分片 + (abort ? −2 : 0)，实测范围 **5–14**（t7 5 / t4 14）；帧长 60–110 实测；块长度 uint16 上界。**吞吐数字待 P4 基准，本版不写承诺**。
- **依据**：`Plan` 在 goroutine 内**流式产出**（`configChan` 容量 256，`sctp.go:175`），无全量包聚合；每帧内存 = 该帧长度；无跨流共享状态；无锁（局部变量 + `time.Now()` 快照）。
- **验收两路（§6.3 强制）**：pcap（`/tmp/mcp-pcaps/sctp/`，正例 `<id>.pcap` / 任务期负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `sctp.*` 字段、`ip.src`、帧原始 hex 与包数，不只断言"任务没报错"。
- **六类场景落点（§6.6）**：基线（#1，7 帧）/ 目标规模（#4 分片 14 帧）/ 压力上限（#5 双 HB 对 + #6 多宿）/ 长时间运行（HB 周期承载语义，未做长跑）/ 并发交错（多流受限 G-SCTP-3，顺序展开承载）/ 背压（`packet_count` 精确计数守卫帧数漂移 + fragment_size V9 区间守卫）。
- **确定性边界（须写清）**：**五类随机面非确定性**（`rand` 无种子）——client/server Tag、双向 InitialTSN、IP ID、32B cookie、HB nonce 后 8B。同一配置两次运行这五类字节不同。存量断言零覆盖（机读实测），不构成 flaky 风险；**任何未来新增断言不得钉这五类**。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须被拒绝并传播为 task error，不得产出成功 PCAP 或假成功。**分两类**：

**A 类：建链期拒绝（create-time，registry V9 层字段范围门，无 pcap）**

| # | 负例 ID | 故障输入 | 锚词 | 拦截点 |
|---:|---|---|---|---|
| N-1 | `sctp_t10_neg_frag_small` | `fragment_size=1`（区间下界内−15） | `out of range [16,1000000]` | registry V9（`complete.go:325`，`validate_layers.go:1321+` 用户链 V9） |
| N-2 | `sctp_t11_neg_frag_upper` | `fragment_size=1000001`（上界+1） | 同上 | 同上 |

**B 类：任务期校验器拒绝（task-time，产出 0 帧 pcap）**

| # | 负例 ID | 故障输入 | 锚词 | 拦截点 |
|---:|---|---|---|---|
| N-3 | `sctp_t9_neg_altpath_v6` | `heartbeats.alt_path.alt_src_ip` = IPv6（`2e01::46`） | `only IPv4 multi-homing` | planner `Validate`（`sctp.go:137`；实测 `sctp_t9_neg_altpath_v6.neg.pcap` = 24 字节 0 帧 ✓） |

**负例原子性**：每例单一故障注入；单次执行不得混注。t10/t11 无 pcap（A 类）、t9 有 0 帧 pcap（B 类）——两类判别与磁盘产物一致 ✓。

**`Validate` 全部 9 条拒绝分支（`sctp.go:102-167`，逐条列，未入例标 A′ 立项）**：

| # | 锚词（代码字面值） | 行 | 入例 |
|---:|---|---:|---|
| 1 | `invalid source IP: %s` | 107 | ✗ A′ |
| 2 | `invalid destination IP: %s` | 115 | ✗ A′ |
| 3 | `invalid AltPath.SrcIP: %s`（不可解析） | 134 | ✗ A′ |
| 4 | `AltPath.SrcIP %s is IPv6; only IPv4 multi-homing is supported (RFC 4960 §3.3.2.1 type 5)` | 137 | ✓ N-3 |
| 5 | `AltPath.SrcIP %s is IPv4 but parent SrcIP is IPv6; multi-homing requires same address family (RFC 4960 §6.4)` | 140 | ✗ A′ |
| 6 | `invalid AltPath.DstIP: %s` | 146 | ✗ A′ |
| 7 | `AltPath.DstIP %s is IPv6; only IPv4 multi-homing is supported …` | 149 | ✗ A′（SrcIP 先判） |
| 8 | `AltPath.DstIP %s is IPv4 but parent DstIP is IPv6 …` | 152 | ✗ A′ |
| 9 | `sctp.fragment_size=%d is below minimum %d (RFC 4960 §3.3.1 requires >=1 byte per fragment)` | 162 | **层内不可达**——registry V9 [16,1e6] 先拦（1–15 落 V9、显式 0 过 V9 且 planner 跳过、负值落 V9 not-a-number）；与 ngap 分支 13 同判"不可达"（G-SCTP-14） |

**9 条中 1 条入例，7 条 A′ 立项，1 条层内不可达**（另 2 条 V9 锚入例）。

**validate.go:109-121 的 flat 分支（`verification_tag/initiate_tag ≥ 0`、顶层 `sid`/`ssn` 0-65535）**：链路径不可达（flat 顶层 sctp 子映射已被 CheckProtoFlat 判死），且 `sid`/`ssn` 在 schema 形状里位于 `chunks[]` 内不在子映射顶层——**双重死分支**（G-SCTP-2）。

**不得误报的合法协议事件**：随机 Tag/TSN/cookie/HB nonce/IP ID（§6 确定性边界）；多宿双 alt 同例（#6）；abort 替代关闭（#7）；分片多段（#4）。

## 8. 边界

- **帧长**：下界 **60**（以太网最小帧：COOKIE-ACK/SHUTDOWN 系/ABORT 裸 46+4 被抬高）；上界实测 **110**（t6 f2 INIT-ACK 带 1 个 alt 参数）；chunk `Length` uint16 理论上界 65535（未触）。
- **AltPath**：仅 IPv4 + 与父路径同族（N-3 + 分支 5/8）；alt MAC 4 键可覆盖（`sctp.go:775-789` 非空才覆盖，空回退父值）；端口恒继承父（`emitHB` 只换 IP/MAC）；`flowID` 加 `":hb"` 后缀（T-6 fields 面 ip.src 已证子流真实换源 10.0.0.9/20.0.0.9 ✓）。
- **分片**：同消息共享 SID/SSN/PPID、TSN 连续；`fragment_size=0` = 不分片（B+E 单块）；显式 `tsn` 只钉首段，后续段 +i 递增且**不推进方向计数器**（`sctp.go:360-368`）。
- **端口**：无协议级缺省；dst_port 缺席链路径 0 上包（flat 路径才会落通用 80——两路径行为不一致，G-SCTP-4 附注）；src 缺席多流 worker `12345+i` 保底。
- **地址族**：IPv4 已覆；IPv6 结构支持未取证（G-SCTP-6）；**父子异族混写不拒绝**——writeL3v4 对 v6 地址静默写零地址（`builder.go:1178-1196` 只 warn），且 EtherType 恒按父 src 决定（`sctp.go:235`）→ 混写产损坏帧（G-SCTP-4，§4 要求"混合拒绝"未实现）。
- **多流**：端口动态不可用（G-SCTP-3）；flows>1 + 全静态四元组被 schema 门拒（`semantic.go:285`）；多流只能 ip 动态变址（§2 样例）。
- 不得产生回绕长度或超量分配：帧长由 `buildChunk` 一次算定；`configChan` 容量 256 有界。

## 9. 原子 ID 与完成定义（11 个唯一语义 ID = 8 正 + 3 负，顺序为权威）

| # | ID | 类型 | 覆盖 | 包数断言 | 实测帧数 |
|---:|---|---|---|---|---:|
| 1 | `sctp_t1_baseline_assoc` | 正 | §3.3/§3.6/§3.7：4 握手 + 3 关闭基线（chunk_type 序 1/2/10/11/7/8/14） | `packet_count: 7` | 7 ✓ |
| 2 | `sctp_t2_handshake_bytes` | 正 | §3.3/§3.7：显式双 Tag + VTag 逐帧钉 + cookie 参数头 | 7 | 7 ✓ |
| 3 | `sctp_t3_data_bidir` | 正 | §3.4：DATA 双向（TSN 随机不钉，SID/SSN/PPID/payload 钉） | 9 | 9 ✓ |
| 4 | `sctp_t4_fragment_flags` | 正 | §3.4：分片三 flags（B/×5/E）+ TSN 连续 500→506 | 14 | 14 ✓ |
| 5 | `sctp_t5_heartbeat_primary` | 正 | §3.5：HB 对 ×2 主路径（chunk_type 4/5 交替） | 11 | 11 ✓ |
| 6 | `sctp_t6_altpath_multihoming` | 正 | §3.3/§3.5：AltPath 子流（ip.src 换源）+ INIT 携 IPv4 参数 | 9 | 9 ✓ |
| 7 | `sctp_t7_abort` | 正 | §3.6：ABORT 替代三路关闭（替代非叠加） | 5 | 5 ✓ |
| 8 | `sctp_t8_explicit_tsn_sid` | 正 | §3.4：DATA 全头逐字节（TSN/SID/SSN/PPID/载荷） | 8 | 8 ✓ |
| 9 | `sctp_t9_neg_altpath_v6` | 负 B | §7 N-3：AltPath IPv6 拒 | — | 0（neg.pcap 24B ✓） |
| 10 | `sctp_t10_neg_frag_small` | 负 A | §7 N-1：fragment_size=1 V9 下界拒 | — | 无 pcap ✓ |
| 11 | `sctp_t11_neg_frag_upper` | 负 A | §7 N-2：fragment_size=1000001 V9 上界拒 | — | 无 pcap ✓ |

**包数公式（实测复算，8/8 正例逐例一致）**：

```
帧数 = 4（握手）+ 2×heartbeat对数（缺省 1）+ Σ_每个 chunk 的分片数（⌈len(data)/fragment_size⌉，size≤0 时 1）
     + (abort ? 1 : 3)
```

校验：#1/#2 可选 0 → 7 ✓；#3 DATA 2 → 9 ✓；#4 分片 7 → 14 ✓；#5 HB 4 → 11 ✓；#6 HB 2 → 9 ✓；#7 abort → 5 ✓；#8 DATA 1 → 8 ✓。**8/8 与实测 pcap 帧数逐例一致**。

**断言规模（机读实测，2026-09-29）**：**20 条 frames 断言 + 19 条 fields 断言 + 8 条包数断言 = 47 条**。**全部对磁盘 pcap 逐条复算，零不符**（tshark `-T json -x` frame_raw 比对 + 字段值比对）。

**断言字段分布**：`sctp.chunk_type` ×**15**、`sctp.srcport` ×**1**、`sctp.dstport` ×**1**、`ip.src` ×**2**（= 19 条），另 frames 原始 hex ×**20**（VTag/chunk 头/cookie 参数头/DATA 全头/载荷）。**零条**断言 `sctp.verification_tag`（随机/十六进制面）、`sctp.data_tsn`（随机面）、`sctp.checksum`（M-1 面）、`sctp.cookie`（随机面）、`sctp.init_initiate_tag`/`sctp.initack_initiate_tag`（参数值面）——M-1 与随机面未被覆盖（§3.8/§6）。

### 9.1 形状基线注记（§1 形状自查）

11/11 例顶层键 = `{expect,id,proto,spec_json,summary}`；`spec_json` 顶层键 = **`{layers}` ×11（唯一键，零游离键）**；层形 `[ip,sctp]` ×11；8 正例 expect 键 = `{frames, has_handshake, negotiated, notes, packet_count, terminates}`（#1/#3/#5/#6/#7 加 `fields`）——其中 **`has_handshake/negotiated/terminates` 三键恒 false**（TCP 语义键，runner 仅在 true 时检查 → 惰性 no-op，G-SCTP-9）；3 负例 expect 键 = `{expect_error, error_contains, notes}`（含 notes，非严格两键，G-SCTP-15）。

### 9.2 M-1 摘要（详见 §3.8）

**CRC32c 覆盖范围把以太网填充字节计入**（30/70 帧受影响，独立复算 30/30 双口径实证；tshark status=2 不捕获、存量断言零覆盖）。修复：按 IP 总长定界计算。修复后帧长与全部存量断言不变。归属：代码阶段（P4）。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求（RFC 4960） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | 关联（association）四路建立，客户端主动（§5.1） | ①⑧ | 4 握手落码（`sctp.go:250-294`）；VTag 语义逐帧正确（§3.7 T-2 实测） | 无 |
| 2 | 命令/消息表 | Chunk 类型 §3.3.1–3.3.13 | ①–⑥ | 11 常量 + 7 值入线；SACK/ERROR builder 死代码（G-SCTP-11）；cookie 为随机 32B 非 §5.1.3 加密 MAC（诚实边界） | G-SCTP-11 |
| 3 | 状态机 | 关联状态图（CLOSED→…→ESTABLISHED→SHUTDOWN-SENT…） | 全场景 | **无状态机**——线性硬序剧本，无状态迁移判定 | 显式不适用（本层无状态机，§5） |
| 4 | 字段表 | 公共头 §3.1 + chunk §3.2/§3.3.x | 数据场景层 | 逐字段落码 + pcap 双向钉（§3）；**M-1 CRC 范围缺陷** | M-1（§3.8） |
| 5 | 错误处理 | 配置非法须拒绝并传播 | ⑧ | 9 条 `Validate` 分支 + 2 条 V9 区间锚 + CheckProtoFlat presence 判死 | 8 分支未入例（G-SCTP-14）；presence 无红例（G-SCTP-7） |
| 6 | 超时与活性 | HEARTBEAT 探测路径（§8.3/§3.3.5）；T1-INIT cookie 生存期 | ④⑤ | HEARTBEAT/ACK 落码（T-5/T-6）；无 cookie 生存期/重试计时器（测试语义） | 无（计时器属协议栈行为，显式不适用） |
| 7 | NAT/代理/被动 | 无被动模式概念（双端对等发起） | — | 无 sessions[]；多流走策略级 flow_control（端口动态受限 G-SCTP-3） | **显式不适用**被动模式 |
| 8 | 版本/方言 | RFC 4960（2022 起 RFC 9260 取代）；IPv4/IPv6 双栈 | 全正例 | 单 profile v4；v6 结构支持未取证（G-SCTP-6）；RFC 9260 差异未核对（G-SCTP-14）；条款引用漂移（§3.5.1→§3.3.5） | G-SCTP-6/14 |

逐项重数：8 行 = 覆 **3**（连接模型/超时活性/字段表布局面）+ 立项 **3**（消息表 G-SCTP-11/错误处理 G-SCTP-14/版本方言 G-SCTP-6+14）+ 不适用 **2**（状态机/NAT 被动）。3+3+2 = 8 ✓

### 10.2 子表①：阶段 × 终态矩阵（逐格已覆/立项/不适用）

| 阶段 | T1 正常终态 | T2 配置拒绝 | T3 异常中断 |
|---|---|---|---|
| INIT | 已覆（#1/#2 字节钉） | 已覆（#9–#11 代表例：拒绝与阶段无关的配置面） | 不适用（异常中断为关联级，见下） |
| INIT-ACK | 已覆（#2 VTag/cookie 参数头） | 同上代表已覆 | 不适用（同上） |
| COOKIE-ECHO | 已覆（#2 回显长度钉） | 同上代表已覆 | 不适用 |
| COOKIE-ACK | 已覆（#1 4B 头钉） | 同上代表已覆 | 不适用 |
| DATA(up) | 已覆（#3/#8 全头） | 同上代表已覆 | 不适用 |
| DATA(down) | 已覆（#3 PPID 面） | 同上代表已覆 | 不适用 |
| 分片序列 | 已覆（#4 三 flags + TSN 连续） | **已覆（#10/#11 fragment_size 专属拒绝）** | 不适用 |
| HEARTBEAT 主路径 | 已覆（#5 交替对） | 同上代表已覆 | 不适用 |
| AltPath 子流 | 已覆（#6 换源 + 地址参数） | **已覆（#9 AltPath 专属拒绝）** | 不适用 |
| SHUTDOWN 三路 | 已覆（全正例） | 同上代表已覆 | 不适用 |
| ABORT | 已覆（#7） | 同上代表已覆 | **已覆（#7 即异常中断生成面）** |

逐格重数：11 行 × 3 列 = 33 格——已覆 **23**（T1 列 11 + T2 列 11 + T3 列 1）/ 不适用 **10**（T3 列：SCTP 异常中断只有关联级 ABORT 一种形态且已覆，无"逐阶段异常注入"概念）。23 + 10 = 33 ✓

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **22 行**，每行均有正例/负例落点或立项结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | IPv4 主路径（唯一已取证载体） | 覆（全正例） |
| 2 | 显式双 Tag（verification_tag + initiate_tag） | 覆（#2，VTag 逐帧钉） |
| 3 | 随机 Tag（缺省 0 → randNonZeroTag） | 覆（#1/#3 等；不钉值——§6 确定性纪律） |
| 4 | DATA up 单 chunk 显式全头 | 覆（#8，20B 全头逐字节） |
| 5 | DATA down + PPID 显式 | 覆（#3 f6，PPID 1000） |
| 6 | 双 chunk 双向序列 | 覆（#3） |
| 7 | 分片多段（100B@16 → 7 段） | 覆（#4，B/×5/E + TSN 500→506） |
| 8 | 分片整除边界（len == fragment_size） | **A′ 立项**（单测 `TestSCTP_FragmentSize_ExactlyFitNoFragment` 在册，cases 无） |
| 9 | PPID 特征值（47 非标准码） | 覆（#8） |
| 10 | heartbeat count=2 | 覆（#5） |
| 11 | heartbeat 缺省 count（=1） | 覆（#6 只给 alt_path） |
| 12 | AltPath src+dst 双侧 | 覆（#6，INIT 携 src 参数 + 心跳双换源） |
| 13 | AltPath 仅 src / 仅 dst（部分覆盖） | **A′ 立项**（`sctp.go:262-269/775-789` 部分覆盖分支无用例） |
| 14 | AltPath.SrcIP v6 拒 | 覆（#9） |
| 15 | AltPath.DstIP v6 拒（对称分支） | **A′ 立项**（分支 7，G-SCTP-14） |
| 16 | abort=true 替代关闭 | 覆（#7） |
| 17 | fragment_size=0 缺省（不分片） | 覆（全正例缺省形态） |
| 18 | fragment_size=1 下界拒 | 覆（#10） |
| 19 | fragment_size=1000001 上界拒 | 覆（#11） |
| 20 | chunks 空载荷 DATA（零用户数据 B+E） | **A′ 立项**（`sctp.go:592-595` 分支无用例） |
| 21 | IPv6 载体 | **A′ 立项**（G-SCTP-6） |
| 22 | 父子异族混写拒绝 | **A′ 立项**（G-SCTP-4：今日产损坏帧非拒绝） |

覆 13 + A′ 立项 9 = 22 ✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 电信信令关联建立（NGAP/M3UA 承载前置） | #1/#2 | 已覆 |
| 2 | 信令双向消息交换 | #3/#8 | 已覆 |
| 3 | 大消息分片传输 | #4 | 已覆 |
| 4 | 主路径保活探测 | #5 | 已覆 |
| 5 | 多宿主备用路径探测 | #6 | 已覆 |
| 6 | 异常中断（ABORT） | #7 | 已覆 |
| 7 | 配置边界拒绝（错配防护） | #9/#10/#11 | 已覆 |
| 8 | 显式协议字段钉（互通调试） | #2/#8 | 已覆 |
| 9 | 现网特征端口/PPID 场景（38412/2905/PPID 60） | — | **明确不解决**（中性值避 tshark 误报，t1 notes 自陈；特征值场景归 ngap 车道） |
| 10 | 多流并发关联 | — | **A′ 立项**（G-SCTP-3：端口动态缺失） |

覆 8 + 不解决 1 + A′ 1 = 10 ✓

### 10.5 三路对照与候选方案对比

三路：①规范原文（RFC 4960，章节号已核实，定"必须是什么"）；②商业化软件实际行为（**未取到**：真实 SCTP 栈/Linux 内核 sctp 模块的线字节未抓包核对 → G-SCTP-14 待确认；tshark 解码面已到抓包级）；③可靠开源实现思路（Linux kernel sctp 的 csum 与 Wireshark dissector 的定界差异正是 M-1 的裁决依据——Wireshark 按 tvb 缓冲计算故 status=Unverified 不报错，内核按 IP 总长定界会拒收）。三路一致点：四握手/VTag 语义/块布局/填充规则；不一致点：CRC 定界（实现 vs RFC）——M-1。

| 方案 | 走法 | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `sctp` 终结层，raw-IP 自驱复用 legacy planner（本版，D-SCTP-1 裁定1） | 全消息面单源复用零分叉；代价 = 一层接线（已落码） | **采用（既成）** |
| B | SCTP 承载面内嵌 ngap 层 | ngap 需自管块字节 → 与"层链单一真相"冲突 | 否决（ngap 实际也走了 raw 自驱） |
| C | sctp 作为 tcp/udp 层变体 | proto 132 非 TCP/UDP，tcp 层握手/分段语义全部错位 | 否决 |

## 11. P2 D-SCTP-1 代码设计（CORE_MEMORY §8 八要素；as-built 逆向定稿）

> 状态说明：实现已落码（`internal/protocol/sctp/` 两文件 + 共享面），本 P2 条目为文档轨对既有实现的**逆向定稿**，供后续改动的唯一入口；P4 在本协议内为"缺口收敛"（§14），不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:2835-2928` + `:1698` + `:2044`） | `SCTPConfig`/`SCTPChunk`/`SCTPHeartbeatConfig`/`SCTPAltPath` + `SCTPMinFragmentSize=16` + `FlowSpec.SCTP` 槽位 + `SubFlowSpec`（sctp 分支注释） | —（共享文件） |
| `trafficgen/internal/protocol/sctp/sctp.go` | planner：`Validate`（9 分支）+ `Plan`（剧本）+ chunk 构造 13 个 + 分片/心跳/文件源辅助 | 835 |
| `trafficgen/internal/protocol/sctp/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator` + `RegisterLayerValidator`，`init()`）；每帧强制 Direction="up" | 72 |
| `internal/protocol/sctp/*_test.go` 6 文件 | **61 个 `Test*`**（Validate 面 8 + Plan 面 20 + HB/多宿 18 + 分片/数据面 11 + ABORT 6 + 文件源 5 + cookie 1 + CRC 共享面在 `builder_test.go:933`） | **2471**（314+54+621+305+694+483，`wc -l` 实测） |
| 接线 9 件 | registry（`registry.go:2071`）/ translate + 端口回填（`chain_planner_translate.go:2863-2887`）/ convert flat（`strategy_convert.go:795/1134`）/ ParseSCTPConfigFromMap（`:3959`）/ presence 判死（`:9098`）/ protocols 准入（`protocols.go:54`）/ 端口语义豁免（`chain_planner.go:799/996`）/ raw-IP 判定（`chain_planner_util.go`）/ main 空导入（`cmd/server/main.go:145`） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`sctp.go:102`）：父 IP 可解析 → AltPath 存在时 Alt IP 可解析 + IPv4-only + 与父同族 → fragment_size 下界（链内不可达）。**9 条拒绝分支**（§7 表）。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`sctp.go:170`）：先 `Validate`，再起 goroutine 流式产出（容量 256）。
- 生成器：`Name() "sctp"`；`GenEvents()` 恒 nil（raw 自驱同款）；`Generate` 把 legacy `Plan` 每帧强制 `Direction="up"` 后 `Emit`（`layer_gen.go:55`）；`RegisterLayerValidator` 挂 `Planner.Validate`（`:69`，不注册则 AltPath 锚全漏）。
- 共享面：`writeSCTP`（`builder.go:1304`，VTag 复用 `L4Config.Ack` 槽位）+ `fillSCTPChecksum`（`:1326`）+ `l4Length` sctp=12（`:951`）。

### 11.3 数据结构

`SCTPConfig{VerificationTag, InitiateTag uint32; Chunks []SCTPChunk; Heartbeats *SCTPHeartbeatConfig; Abort bool; FragmentSize int}`（`types.go:2835-2866`，6 字段）；`SCTPChunk{TSN uint32, SID, SSN uint16, PPID uint32, Data []byte, Direction string, FileSource *filesystem.FileSource}`（`:2908-2928`，7 字段）；`SCTPHeartbeatConfig{Count int, AltPath *SCTPAltPath}`（`:2880-2888`）；`SCTPAltPath{SrcIP, DstIP, SrcMAC, DstMAC string}`（`:2893-2898`，4 键）。

**registry Fields（8 键）与 struct 对齐**：6 业务键（verification_tag/initiate_tag/chunks/heartbeats/abort/fragment_size）+ src_port/dst_port 端口 2 键（1.12 补位：SCTP 端口无层可住——tcp/udp 层不适用 proto 132，端口住本层经 translate 回填 spec）= 8 ✓；生成表逐键一致（§1）。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry Fields 8 键 allowlist + V9 区间）→ CheckProtoFlat（顶层 sctp presence 判死）→ translate（`ParseSCTPConfigFromMap` 复用扁平解析单一真相 + 端口非零显式回填 spec，dyn 对象跳过）→ worker 逐流（src 缺席 `12345+i` 保底）→ `isRawIPChain` 判定 → `flowMetaFor` 带 `SCTP`（`chain_planner.go:1530`）→ `Generator.Generate` → legacy `Planner.Plan`（4 握手 → HB 对 → DATA 序列 → 关闭）→ 逐帧 Emit → builder（SCTP 公共头 + CRC32c）→ writer（PCAP/NIC）。

### 11.5 错误分支

9 种 planner 拒绝（`sctp.go:102-167`）+ 2 种 V9 区间锚（`complete.go:325`）+ presence 判死（`strategy_convert.go:9098`）全部传 task error（零假成功——t9 实测 0 帧 pcap，t10/t11 建链期无 pcap）。**静默行为两处**：`chunks[].tsn/sid/ssn/ppid` 越界经 `getUint32/getUint16` **静默截断**（G-SCTP-2）；父路径异族混写**静默产损坏帧**（G-SCTP-4）。

### 11.6 性能边界

见 §6（流式产出、per-flow 局部状态、无跨流共享、无锁；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- `CheckProtoFlat` **有 sctp 分支**（rawWrapChains，`strategy_convert.go:9098`）→ 顶层 `sctp` 子映射 presence **今日已判死**（含空 map）。**红例无用例**（G-SCTP-7）——建了会真绿（真绿非假绿，与 opcua G-OPCUA-1 相反）。
- **动态 allowlist 无 sctp 行**（`grep -c 'sctp' layer_dyn.go` = 0 实测）→ 层内**任何键**（含 src_port/dst_port）的对象值 → `does not support dynamic`（`validate_layers.go:1006`）；对照 ngap/h323/mpls/telnet/sip/radius 六协议端口 2 键已开（D-*-1 决策 E1 系列）→ G-SCTP-3。
- **`emitSCTPSubFlow`（`subflow.go:373-520`）**：`SubFlowSpec.Protocol` 注释声明接受 "sctp"，但 `EmitSubFlow` 全仓仅 ftp.go:738/1192 以硬编码 "tcp" 调用；顶层 `sub_flows` 键解析进 `spec.SubFlows`（`strategy_convert.go:1839`）后**无任何消费者**——sctp planner 不读 SubFlows。且该分支的 INIT-ACK 用 `buildSCTPINITChunk`（chunk type **1** 非 2）、COOKIE-ECHO 空 cookie（G-SCTP-5）。
- **registry 与生成表同代**：generated JSON 8 键逐键一致（§1 机读实测）。P4 若改 registry Fields 必须重跑 schemagen。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 2 文件 + 接线 9 处；不触及其他协议。cases 回滚 = 恢复 11 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：**11/11 例顶层 = `{layers}`**（唯一键，零游离键）；目标形状见 §2 样例且**存量已达标**（本协议无迁移工作量） | §12.1；`cases/sctp.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 sctp 流量模板；任务 = 多策略合跑 + 总量封顶；多流走 `flow_control`（存量未用，§2 样例） | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（AltPath 多宿子流 = 本协议特有流关联形态）/插入位置（raw-IP 终层）/时间线。有关联载体，不豁免 | §12.3 + §4/§5 |
| §4 查规范 | RFC 4960（章节号对 rfc-editor.org 核实）+ tshark 3.6.14 字段与 9 pcap 实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["ip"]` 单值（`registry.go:2071`）；9+2 种拒绝分支 + presence 判死；失败传 task error（t9 0 帧 / t10/t11 无 pcap 实测） | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待 P4 基准；pcap/NIC 两路验收明写；五类随机面确定性纪律写清） | §6 |
| §7 三份文档 | `125-sctp-{design,testcase}.md`（本对）+ cases JSON 11 例 + D-SCTP-1（§11）；**无旧基线**（§0） | 修订记录 |
| §8 设计先行 | **例外**：本协议实现与用例先于文档存在（D-SCTP-1 已落码落库），本版为 as-built 逆向定稿；§14 缺口为后续入口 | §0 说明 |
| §9 测试三源 | 三源 = RFC 4960（§10）+ D-SCTP-1（§11）+ tshark 3.6.14 字段与 pcap 实测（**已到抓包级**：9 pcap 在案，47 条断言逐条复算 OK）；11 ID 逐项回指；存量 11 例审计去向 testcase §8 | `125-sctp-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 `/tmp/pipe/doc-lanes/sctp.md`）+ 收官隔离复审；红先绿后 | 自审日志 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组 **ip 2 键开、sctp 端口 0 键开**（allowlist 无 sctp 行）；业务 6 键逐个列关 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `sctp` 已在 `registry.go:2071` 注册（**不新增层**）；生成表 8 键与 registry 逐键一致（机读实测）；**P4 若改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `sctp.*` + `ip.*` + frames 三通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/sctp/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 项 | 例数 | 详情 |
|---|---:|---|
| 总例数 | **11** | 8 正 + 3 负 |
| `spec_json` 顶层键 = `{layers}` | **11/11** | 唯一顶层键，**零游离键、零顶层 sctp 子映射、零顶层四元组** |
| 层链形 | **11/11** | 全部 `[ip, sctp]`（两层） |
| 用例外层键 = `{expect,id,proto,spec_json,summary}` | **11/11** | 无 `strategy_fc`/`flow_control`/`group_id` 附加 |
| 负例 `expect` 键 = `{expect_error, error_contains, notes}` | **3/3** | 含 `notes`（非严格两键，G-SCTP-15） |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 本协议**从未用过顶层地址**；11/11 已住 `layers[0].ip.{src,dst}` |
| `src_port` | **0** | 已住 `layers[1].sctp.src_port`（11/11 显式写 12345）——1.12 补位（SCTP 端口无 tcp/udp 层可住） |
| `dst_port` | **0** | 已住 `layers[1].sctp.dst_port`（11/11 显式写 5000） |
| `count` | **0** | 走 `flow_control`（本版未用） |
| 顶层 `sctp` 子映射 | **0** | 已住 `layers[1].sctp`（11/11）；presence 判死已接线（`strategy_convert.go:9098`） |
| `strategy_fc` / `flow_control` / `group_id` | **0** | 本协议无多流用例 |

**结论**：**本协议存量 11/11 顶层零残留**——§1 门的动作 = ①无旧键可删；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测 11/11 顶层仅 `layers`）；③A′ 新增例全部沿用纯 layers 形（§13）。目标形状样例见 §2。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"sctp":{}}` **今日会被拒**（`CheckProtoFlat` rawWrapChains 有 sctp，`strategy_convert.go:9098`，空 map 也死）→ **红例今日建了会真绿（真绿非假绿）**，但**存量无用例** → A′ 补例（G-SCTP-7，ngap_flat_presence 范式）。
- ② 白名单外**任意未知键**（如 `{layers:[…], bogus:1}`）今日**不判死**（CheckProtoFlat 只查五键 + presence 白名单）→ 框架级问题，非 sctp 特有（ngap G-NGAP-11 同款，禁加单协议黑名单分支）。
- ③ 3 负例每条带锚词（已齐，§7）。
- ④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

**会话表**：`s1` 单 SCTP 关联基线（#1–#8 全部，各自四元组，4 握手 → [HB 对] → DATA 序列 → 3 路关闭或 ABORT）。**无 `sessions[]` 形态**（registry 无该键）；多会话 = 策略级多流（本版未用）。#6 的 AltPath 心跳是**同一关联内的备用路径子流**（非第二会话）——诚实声明：flowID 带 `:hb` 后缀使其成为独立 flow 元素，但协议语义仍是单关联（同端口、同 VTag 空间）。

**事务序列**：`t1` 关联建立（INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK，RFC 4960 §5.1）/ `t2` 保活探测（HEARTBEAT/HEARTBEAT-ACK 对，§3.3.5/§3.3.6）/ `t3` 消息交换（DATA 块序列，§3.3.1，无响应配对语义）/ `t4` 关联拆除（SHUTDOWN 三路 §9.2 语义 或 ABORT §9.1 语义）。每事务四件事（前置/触发/成功/失败）：**前置 = 前序阶段完成（引擎不校验，剧本硬序）**；**触发 = 配置键**（chunks/heartbeats/abort）；**成功 = 对应帧产出**；**失败 = 配置校验拒绝（§7）**——协议层无"过程失败"概念（无 ERROR 块接线，G-SCTP-11）。

**关联关系**：**AltPath 多宿子流 = 本协议唯一的流关联形态**（诚实声明其双面性）：主从关系 = 备用心跳子流关联主关联（INIT/INIT-ACK 携带地址参数宣告 → 备用心跳有协议依据，RFC 4960 §3.3.2.1）；实现面 = flowID `:hb` 后缀 + 注释声称的 GroupID 继承**未落码**（G-SCTP-5 附表）→ 跨 worker 保序不保证。**无派生数据流**（与 FTP 控制+数据不同——SCTP 多宿是同一关联的路径冗余，不是副连接）。

**插入位置**：**raw-IP 自驱终结层**（`[ip, sctp]`，链上无 tcp/udp 中间层；SCTP 自成 L4 proto 132，§2）。

**时间线**：帧内严格顺序（Eth→IP→SCTP→chunk）；阶段顺序**硬编码**（握手 → HB → DATA → 关闭，与配置书写顺序无关——chunks 数组内序保留、三类配置块间序固定）；多流整块回放（未启用）；无交错（`concurrent` 未启用）。T-1 实测 chunk_type 序 1/2/10/11/7/8/14 即时间线的直接断言。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组**：`ip.src/dst` **开**（allowlist 首行，`layer_dyn.go:15`）；**`sctp.src_port/dst_port` 关**——`layerDynAllowlist` 无 sctp 行（`grep -c` layer_dyn.go = **0** 实测），层内端口对象 → `does not support dynamic`（`validate_layers.go:1006`）。**对照**：ngap/h323/mpls/telnet/sip/radius 六协议端口 2 键已开（D-*-1 决策 E1 系列）——sctp 是同族唯一端口动态缺失者（G-SCTP-3）。后果：SCTP 多流端口池不可为；CORE_MEMORY §12 的"src_port/dst_port 五策略"要求今日不满足。

**业务字段 6 项全关**（同上 allowlist 实测；对象即拒）：

| # | 业务键 | 开/关 | 理由 |
|---:|---|---|---|
| 1 | `verification_tag` | **关** | 关联身份标识，逐流变破坏 tag↔VTag 回显语义 |
| 2 | `initiate_tag` | 关 | 同上（对端宣告面） |
| 3 | `chunks` | **关** | 列表型结构选择器；块序=剧本，逐流变无解析面（data 内容可动态但无轮转需求，A′ 候选） |
| 4 | `heartbeats` | 关 | 对象型（count/alt_path）；结构选择器 |
| 5 | `abort` | 关 | 布尔开关（关闭形态选择器） |
| 6 | `fragment_size` | 关 | 标量；V9 区间 [16,1e6] 已限 |

**序号算法实读**：TSN per-direction 双计数器（`sctp.go:219-220` 随机初值；`:360-368` 自增——显式 tsn 分片走 `startTSN+i` 不推进计数器）；IP ID 全流计数器（`:209-214`，随机初值逐帧 +1）；packetIndex 全流递增（`:208/247`）；HB 迭代计数（`:821-822`）；worker 保底端口 `12345+i`（`worker.go:307-309`）。allowlist 白名单（`layer_dyn.go:14` 头部 `layerDynAllowlist`）——**sctp 无块**，层内任何对象值 → `does not support dynamic`。

**动态用例覆盖**：**零**（11 例全静态）。五策略（fixed/inc/rand/list/pattern）× (ip.src/dst) 的 sctp 用例今日无用例；静态四元组 + flows>1 会被 schema 门拒（`semantic.go:285`）。→ G-SCTP-3。

## 13. P3 对接清单（T-SCTP 输入；正文落 testcase 文件）

11 ID（8 正 + 3 负）+ 包数/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。**A′ 候选 12 例**（按缺口）：`sctp_presence_neg`（顶层 sctp 子映射 presence 判死红例）/ `sctp_neg_bad_src_ip`（IP 不可解析）/ `sctp_neg_alt_dst_v6`（对称分支 7）/ `sctp_neg_alt_family`（分支 5/8 同族约束）/ `sctp_neg_mixed_family`（父子异族，G-SCTP-4 修复后）/ `sctp_neg_sid_overflow`（chunks[0].sid=65536，G-SCTP-2 修复后拒或钉截断行为）/ `sctp_empty_data`（零载荷 DATA）/ `sctp_frag_exact_fit`（len==fragment_size）/ `sctp_altpath_src_only`（部分覆盖）/ `sctp_ipv6`（G-SCTP-6，M-1 修复后含 checksum 复算）/ `sctp_multi_stream`（双 SID 双 chunk，G-SCTP-12）/ `sctp_hb_token`（HB 令牌钉，G-SCTP-13）。**M-1 修复后须重钉**：新增 checksum 断言按 IP 定界口径。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| **G-SCTP-1（=M-1，confirmed finding）** | **CRC32c 覆盖范围把以太网填充字节计入**：`fillSCTPChecksum` 以 `packet[l4Start:]` 为界（`builder.go:1326-1333`），且在 `Build` 以太网填充（:329-331 抬到 60）**之后**调用（`:427-429`）→ 帧短于 60 被填充时 CRC 含填充零字节，与 RFC 4960 §6.8 的"按 IP 总长定界的 SCTP 包"口径不符。**实证**：8 pcap 70 帧中 30 帧被填充，30/30 存储值=含填充口径、≠IP 定界口径；另 40 帧两口径重合 ✓。tshark `checksum.status=2`（Unverified）不捕获；存量 47 断言零覆盖该面 | **代码阶段（P4）**：按 IP 总长定界计算（或填充前计算）。修复后帧长与全部存量断言不变；新增 checksum 断言按修复后口径钉。**波及 ngap**（同一 builder；其文档 §3.1 "填充计入 CRC 是 RFC 要求"结论与本车道复算相悖，不采信） |
| **G-SCTP-2** | **chunks[].tsn/sid/ssn/ppid 越界静默截断**：`parseSCTPChunks` 经 `getUint32/getUint16`（float64→uint 转换，`strategy_convert.go:6865/6889`）——超宽值（如 sid=65536）静默截断为错值，无拒绝无告警；chunks 是 list 型无 V9 区间。**另**：`validate.go:109-121` 的顶层 `sid`/`ssn` 范围校验是**双重死分支**（链路径 flat 子映射已判死 + 键位在 chunks[] 内不在子映射顶层） | A′：补范围校验（chunks 逐项 Validate 分支）+ 负例 `sctp_neg_sid_overflow`；validate.go 死分支裁定删除或改造 |
| **G-SCTP-3** | **sctp 层动态字段 0 键开放**：`layerDynAllowlist` 无 sctp 行（`grep -c 'sctp' layer_dyn.go` = 0 实测）→ 端口 2 键不可动态（对照 ngap/h323/mpls/telnet/sip/radius 六协议 E1 决策已开）；flows>1 + 全静态四元组被 schema 门拒（`semantic.go:285`）→ 多流只能靠 ip 动态变址。CORE_MEMORY §12 四元组五策略要求今日不满足 | A′：补 allowlist 行 + `parseLayerDyn` sctp case + 动态用例（ngap_port_dyn 范式：端口池 inc + ip inc） |
| **G-SCTP-4** | **父路径异族混写不拒绝**：Validate 只查 AltPath 与父同族，父 src/dst 互检缺失；混写时 EtherType 恒按父 src（`sctp.go:235`）、writeL3v4 对 v6 地址静默写零地址（`builder.go:1178-1196` 只 warn）→ 产损坏帧（§4 覆盖最小清单要求"混合拒绝"）。**附注**：dst_port 缺省在 flat 路径落通用 80、链路径 0——两路径不一致，一并裁定 | A′：Validate 补父子同族约束（锚词仿 `same address family`）+ 负例；端口缺省两路径对齐裁定 |
| **G-SCTP-5** | **`emitSCTPSubFlow` SCTP 分支 wire 缺陷 + 死代码**：INIT-ACK 帧用 `buildSCTPINITChunk`（chunk type **1** 非 2，`subflow.go:428`）；COOKIE-ECHO 空 cookie 恒 `{10,0,0,4}`（INIT-ACK 从不携 State Cookie）；SHUTDOWN cumTSN 传自身 `clientTSN`。该分支全仓不可达（`EmitSubFlow` 仅 ftp.go 以硬编码 tcp 调用）；**顶层 `sub_flows` 键解析后无消费者**（`strategy_convert.go:1839` → spec.SubFlows 零读取；GroupID 继承为注释声称、未落码） | 裁定（框架面）：删除 sctp/udp 死分支 + 移除 SubFlows 解析，或修复接线 + 补例；若保留必须修 type 1→2 与 cookie 回显 |
| **G-SCTP-6** | **IPv6 主路径未取证**：Validate 不拒 v6 父地址（`sctp.go:103-118` 只查可解析），`EtherTypeFor`/`writeL3v6` 结构性支持 `[ip,sctp]` v6 链（chunk 起点 74），今日 0 例 0 断言 | A′ 补例 `sctp_ipv6`（M-1 修复后含 checksum 复算）；修复前不声称 v6 可用 |
| **G-SCTP-7** | **顶层 sctp presence 判死已接线、无红例**：rawWrapChains 含 `sctp:"[ip,sctp]"`（`strategy_convert.go:9098`）——红例今日建了会真绿（真绿非假绿），但 11 例中无此形状 | A′ 补例 `sctp_presence_neg`（锚词 `rejects a top-level sctp sub-config`，ngap_flat_presence 范式） |
| **G-SCTP-8** | **t6 notes 自相矛盾且与实测不符**：frames 断言（f1 offset **66** = `00 05 00 08 0a 00 00 09`）机读正确 ✓；但 note2 写 "offset**74** 实测钉：00 05 00 **0a**+IP 4B"（偏移 74 越过帧尾 74=帧长、长度 0x0a≠0x08），且与同例 note1（offset 66 len 8 ✓）矛盾 | P4 改写 note2（cases JSON 断言面无恙——notes 非 machine-executed） |
| **G-SCTP-9** | **8 正例恒带 `has_handshake/negotiated/terminates: false` 三键**：TCP 语义键（runner 仅 true 时检查 → no-op 噪声键；SCTP 的四握手/三关闭已由 chunk_type 断言承载）；ngap 等同族协议无此三键 | A′ 清理：删除三键（纯形状整形，不改变断言语义） |
| **G-SCTP-10** | **SHUTDOWN cumTSN 随机语义**：`shutdownTSN = serverTSN - 1`（`sctp.go:404-410`）——服务端无 DATA 时 serverTSN 是随机初值，减 1 后无意义（ngap G-NGAP-7 同构；RFC 4960 §9.2 要求"本端已收到的最高累积 TSN"）。今日无用例钉值（随机面不可钉） | A′ 裁定：服务端缺省 DATA 时给确定性锚（或文档声明该值测试语义）；不改则记"明确不解决" |
| **G-SCTP-11** | **SACK/ERROR 死代码**：`buildSACKChunk`/`buildERRORChunk`/9 个 `EC*` 常量零调用（grep 实测）；DATA 后无确认块（协议核心面 SACK 未接线）；ERROR/Cause 不可配置 | **明确不解决**（生成器重放范围，重传/确认语义属协议栈）+ 死代码裁定删除或保留为未来接线入口；A′ 若立项须新增配置键 + 用例 |
| **G-SCTP-12** | **多流（SID/SSN）wire 例缺**：per-chunk sid/ssn 配置直通（#8 单 chunk sid=5），同关联双 SID 双 chunk 组合零用例；INIT OS/MIS 恒 10/10 不配置化 | A′ 补例 `sctp_multi_stream`（两 chunk 异 SID，钉各自 SSN）；OS/MIS 配置化裁定（不解决则登记） |
| **G-SCTP-13** | **HEARTBEAT 令牌无断言**：info = "HBTC" magic + 迭代计数 + 8B 随机（`sctp.go:819-823`）；#5 frames 为空数组，magic/counter 今日零断言（单测 `TestSCTPHeartbeat_HBInfoMagic` 在册） | A′ 收编：#5 补 frames 断言（magic 4B + counter 可钉，随机 8B 不钉） |
| **G-SCTP-14** | **Validate 8 分支未入例 + 规范引用面**：§7 表分支 1/2/3/5/6/7/8 未入例、分支 9 层内不可达（V9 先拦）；**引用漂移**：代码/notes 引 "RFC 4960 §3.5.1"（HEARTBEAT 实为 §3.3.5，已对 rfc-editor.org 核实）、随机 TSN 出处引 "RFC 6525 §5.1" 疑似错位；RFC 9260（2022 修订）差异未核对；真实 SCTP 栈线字节未取（第三源缺） | A′ 补例 7 条（分支 9 登记"层内不可达"）；引用修正随代码阶段；RFC 9260/内核栈核对 = 待确认（取 RFC 9260 原文 + Linux kernel sctp 抓包对照） |

| **G-SCTP-15** | **负例 expect 恒带 `notes` 键（3/3，非严格两键）**：负例机器契约应为严格两键 `expect_error`/`error_contains`，`notes` 是文档性键混入机器面——coverage 反查门「负例 expect 键集合」断言今日红（testcase §9 行 4，如实标红） | P4 形状清理：3 负例删 `notes`（文案并入 `summary`），门断言转绿 |

**产物日期注记（非缺口）**：`docs/protocol-pcap-test/sctp.md` 末次提交 94adc3c（2026-09-21）**晚于**判死提交 0417be5（2026-09-13）→ 不满足批次任务书的产物过期登记判据（G-PCEP-11 口径），不登记为缺口；`docs/protocol-pcap-test/sctp/` 目录不存在（0 pcap 留档）为全仓共性（ngap §0 #4 同判）。本车道未重跑引擎（§0 取证边界）。

## 15. 修订记录

- v1.0.0（2026-09-29）：批次二文档轨 #125 **首次成文**（本协议此前无任何设计/用例文档，§0）。as-built 逆向定稿：存量 11 例（8 正 + 3 负）逐条机读对账（**11/11 顶层零残留**）；**47 条断言（20 frame + 19 field + 8 包数）全部对磁盘 pcap 复算零不符**（§9）；帧长公式 `max(60, 46+pad4(chunk_len))` 对 70 帧零例外（§2）；**M-1 confirmed finding**（CRC32c 覆盖范围含以太网填充，30/70 帧双口径实证，§3.8）；四路握手 vs TCP 三握手逐条差异（§5）；VTag 双向映射表按 T-2 双 Tag 实测钉死（§3.7）；引用漂移钉死（§3.5.1→§3.3.5，rfc-editor.org 核实）；八项矩阵 + 子表①②③（33 格 = 覆 23 + 不适用 10；22 行 = 覆 13 + A′ 9；10 行 = 覆 8 + 不解决 1 + A′ 1）；门1 十四行齐 + §12.1/12-P2/12.3/12.12 四展开；缺口 **G-SCTP-1…G-SCTP-15**；覆盖反查门增量建议 6 条（testcase §9，既有 check_sctp 21 行之上）。**未跑引擎**（§0 取证边界）。自审见 `/tmp/pipe/doc-lanes/sctp.md`。

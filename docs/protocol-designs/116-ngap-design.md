# #116 ngap（NG Application Protocol · 5G 核心网 N2 接口信令，3GPP TS 38.413，SCTP 承载）设计契约

> 版本：v1.0.0（as-built 文档轨；修订记录见 §15）
> 日期：2026-09-29
> 车道：批次二文档轨（#116 ngap）
> 旧基线：**无**——`docs/protocol-designs/` 下**从无 ngap 设计/用例文档**（机读实测：`ls docs/protocol-designs/ | grep -i ngap` 零命中；`INDEX.md` 无 ngap 行；`00-unimplemented-list.md` 无 ngap 行）。本 #116 是**首次成文**，非续号重审。存量实现与用例均已在 `D-NGAP-1`（P-PIPE #17 车道）落码落库，本契约按 as-built 逆向定稿。
> 存量用例：`trafficgen/test/protocol_pcap/cases/ngap.json`（**17 例 = 12 正 + 5 负**，ID/顺序/包数/断言本版逐条机读对账，§9/§12.1）
> 规范基线：① **3GPP TS 38.413**（NG Application Protocol (NGAP)，下称 **spec**——NGAP-PDU/过程码/criticality/IE 定义与 SCTP 承载）；② **3GPP TS 38.412**（NG signalling transport——SCTP 关联、PPID、流标识）；③ **RFC 4960**（SCTP：块类型、4 步握手、3 步拆链、CRC32c 校验和、Verification Tag）；④ 本机 tshark **3.6.14** `ngap.*` 字段表（**1119 字段**，实测）与 15 个实测 pcap（`/tmp/mcp-pcaps/ngap/`，包数与偏移的唯一权威）；⑤ 本仓库落码（`internal/protocol/ngap/` 三文件 + 接线六处，§11）；⑥ 公开资料/假设（逐处标注，未达验证级 → 缺口）
> 白话一句：**5G 基站（gNB）和核心网（AMF）之间的"上岗对话"——先在 SCTP 上四步握手建一条可靠管道，然后基站自报家门（NGSetupRequest），核心网回一句"收到"（NGSetupResponse），中间按需穿插手机注册、NAS 透传、会话建立、上下文释放，最后三步拆链。本实现把这些消息写成"结构上像 NGAP"的字节，**不是**严格 PER 编码。**

## 0. 首次成文声明与既有产物校正（门1 必答：基线继承关系）

**无旧稿可承**：本协议在本仓 `docs/protocol-designs/` 下**没有任何前序设计或用例文档**。故本版不存在"旧稿过时/臆造/包数全错"类的沿革校正表；取而代之，本节对**既有实现与既有产物**做一次逐条对照校正（这是本协议门1 的"基线"面）。

| # | 既有说法/产物 | HEAD 实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | `ngap.go:36-38` 头注自述："Simplified ASN.1 PER — structurally valid NGAP-PDU frames that DPI systems and protocol analyzers recognize, but **not full-compliance** with 3GPP TS 38.413 encoding rules (e.g., no constraint-based length determinants)" | 实测：tshark **能**解出 `ngap.procedureCode` 与 `ngap.criticality`，**但解出的 PDU choice 与 criticality 值与实现写入的值不一致**（§3.2 M-1）；IE 容器**完全不解**（无任何 `ngap.<IE名>` 字段产生） | **头注"analyzers recognize"过谦/失准**：procedureCode 可识别，**choice 与 criticality 系统性误读**，IE 层不识别。本版 §3 按字节钉死，M-1 立项 |
| 2 | `types.go:8762-8765` 自述："The planner builds correct NGAP-PDU structures: choice index + procedureCode + criticality + protocolIEs" | 实测：四个字段**都在**且偏移固定（§3.3），**但 choice/criticality 的线值不是 PER 编码值**（写整字节 0/1/2，PER 要求写 2 bit 到字节高位） | 措辞"correct … structures"应读作"**结构位序正确**"；**位域编码不正确**（M-1） |
| 3 | `trafficgen/docs/protocol-pcap-test/ngap.md`（**tracked 产物**）写 `Cases: 17 — pass 17, fail 0, error 0`，末次提交 `45016f3`（**2026-09-19**） | 末次提交 **2026-09-19 晚于**判死提交 `0417be5`（2026-09-13）→ **按批次二任务书口径，本产物不属于"过期产物"**，不登记为该类缺口 | **不登记产物过期缺口**（与 opcua G-OPCUA-10 / thrift G-THRIFT-10 的判据不同，差别在日期） |
| 4 | 上条产物中的 pcap 链接指向 `ngap/<id>.pcap` | `trafficgen/docs/protocol-pcap-test/ngap/` **目录不存在**（**0 个 pcap**，`ls` 实测） | **全仓共性**：`trafficgen/docs/protocol-pcap-test/` 下**没有任何协议子目录**（机读：`ls -d */ \| wc -l` = **0**），非 ngap 特有；登记为事实，不单独立缺口 |
| 5 | 任务书提示"存量 17 例" | 机读实测 **17 例**（12 正 + 5 负），ID 唯一、顺序稳定 | 一致 ✓ |
| 6 | 任务书提示"NGAP 是 SCTP 承载的 ASN.1 PER 编码协议，PER 编码（对齐/非对齐）与 ProcedureCode/Criticality 是核心" | 实测：SCTP 承载**完全正确**（块类型/握手/拆链/校验和/vtag 逐帧实证，§3.5/§3.6）；**PER 编码是实现的最弱面**（M-1：choice/criticality 位域错位、IE 容器非 PER） | 本版把"**承载正确**"与"**PER 编码不合规**"两件事**分开写清**，不含糊 |

**依赖链判定纪律**：以上均为可判题（产物→代码→pcap 三级对照），直接判定，不问偏好。不可判的（TS 38.413 具体条款号与文本、真实 AMF/gNB 线字节）标"待确认"并写清确认方式（G-NGAP-4/G-NGAP-5）。

**本车道取证边界（诚实声明，重要）**：本车道**未重跑引擎**。§9/§12.1 的"逐条一致"是**存量 cases JSON 的断言 × 磁盘上既有 pcap（`/tmp/mcp-pcaps/ngap/`，文件日期 2026-09-27）** 的机读对账结果（**148 条 field 断言 + 3 条 frame 断言 + 12 条包数断言，零不符**，§9 复算脚本口径）。这不等于"今日复跑套件绿"。

**ngap 特殊性（须写清，不得夸大）**：ngap 是本批**已链化、已注册、已接线、已有 17 例**的协议——**不是**"层是空壳、cases 改不动"的那一类（见 `docs-first-workflow` 记忆的例外条款）。其层链为 `[ip, ngap]`（**raw-IP 自驱终层**，无 tcp/udp 传输层，终层自产完整以太帧）。

## 1. 范围、profile 与实现状态边界

本版定义 **NGAP（3GPP TS 38.413）承载于 SCTP** 的流量生成：SCTP 4 步关联建立、NG Setup 过程、可选 UE 相关过程（初始 UE 消息 / 上下行 NAS 透传 / PDU 会话资源建立 / UE 上下文释放）、SCTP 3 步关联拆除。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `ngap_sctp_v4_v1`（主，唯一实现） | SCTP over IPv4，fixture 端口 38412 | 4 步握手 → NGSetup 对 → 可选过程（0–6 帧）→ 3 步拆链 | 真实 AMF/gNB 语义（UE 是否注册、切片是否可用、鉴权结果） |
| `ngap_sctp_v6_v1` | — | **不实现**（`Validate` 显式拒绝 IPv6，`ngap.go:149/154`） | — |

显式边界（"不实现、不声称、不许静默转换"）：① **不实现 IPv6**——`Validate` 在 `ngap.go:146-156` 对 SrcIP/DstIP 做 `To4()==nil` 判定并拒绝（锚词 `only IPv4 is supported`，用例 `ngap_neg_v6` 覆盖）；② **不实现严格 PER 编码**——PDU 头三字段按整字节写（M-1），IE 容器用 `count(2,BE) + {id(2,BE), crit(1), len(1), value}` 自定形（§3.4），**非** ASN.1 PER 的 length determinant / 对齐位域；③ **不实现以下 TS 38.413 过程**：InitialContextSetup、Paging、Handover（含 HandoverPreparation/ResourceAllocation/Cancel/Notification/Success/Failure）、PathSwitchRequest、UEContextModification、NGReset、ErrorIndication、OverloadStart/Stop、AMF 配置更新、RAN 配置更新、Trace、LocationReporting、Warning 系列、所有 `unsuccessfulOutcome` 过程（§10.4 逐条列）；④ **不实现 SCTP 分片/多流复用**——所有 DATA 块恒用 **SID=1**、**SSN=0**、单块 B+E 完整消息（`buildDATAChunk`，`ngap.go:483-491`）；⑤ **不实现 SCTP 拥塞控制/重传/心跳（HEARTBEAT chunk）**；⑥ **不实现 SACK/多块捆绑**；⑦ **不声称**产出的流可被真实 AMF 接受（PER 不合规，M-1）。

**实现状态（2026-09-29 实测）**：`ngap` 层已注册（`registry.go:1823`，`CategoryTerminal`，`DependsOn ["ip"]`，**Fields 14 键**）；planner 已落码（`internal/protocol/ngap/ngap.go` **895 行** + `layer_gen.go` **74 行** + `ngap_test.go` **974 行**，`wc -l` 实测；**54 个 `Test*`** 函数，`grep -c '^func Test'` 实测）；`allowedProtocols["ngap"]=true`（`protocols.go:49`）；层内 translate 已接线（`chain_planner_translate.go:1458`）；平面 convert 已接线（`strategy_convert.go:1226`）；`CheckProtoFlat` 顶层 presence 判死已接线（`strategy_convert.go:8954`）；动态端口 allowlist 已登记（`layer_dyn.go:57`）；raw-IP 自驱判定已列名（`chain_planner_util.go:54/57`）；端口语义豁免已列名（`chain_planner.go:763/996`）；`main.go:123` 空导入 + `main.go:601` `NewChainPlanner("ngap")`。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`sctp.srcport/dstport`、`sctp.chunk_type`、`sctp.data_payload_proto_id`、`ngap.procedureCode`、frames offset 62）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。本版 17 例全部只用两路径均可观察的字段（无 pcap 专属字段）。

## 2. 协议栈、端口和固定偏移

推荐层链为 **`[ip, ngap]`**——ngap 是 **raw-IP 自驱终层**：链上**没有 tcp/udp 层**，ngap 层生成器自行组装**完整以太帧**（Eth + IPv4 + SCTP + chunk），框架的传输分支不介入（`isRawIPChain`，`chain_planner_util.go:40-58`；生成器 `Generate` 把 legacy `Plan` 产出的每个 `PacketConfig` 直送 `Emit`，`layer_gen.go:32-57`）。存量 **17/17 例**层链均为 `[ip, ngap]`（机读实测）。

> **方向纪律（`layer_gen.go:28-31/51`）**：生成器把**每一帧**强制 `pkt.Direction = "up"`。原因：legacy `Plan` 的 `emitSCTP` 已按方向**自行交换** src/dst IP、端口与 MAC（`ngap.go:282-309` 逐 emit 自管），raw-IP 驱动若再对 down 包做 L3 换向会**双换**出错（h323/mpls 同款先例）。故"方向"语义只体现在**帧内的地址/端口/MAC 排列**上，不体现在 `Direction` 元字段。

端口：NGAP/AMF 规范端口 **SCTP 38412**（3GPP TS 38.413）。层内 `dst_port` 缺席 → translate 补 **38412**（`chain_planner_translate.go:1567`，镜像 `setDefaultDstPort`，`strategy_convert.go:1229`）；`src_port` 缺席 → translate **不动**（保持 0），由 worker 按 `12345+i` 保底注入（单流即 12345）。存量 16/17 例显式写端口 `12345/38412`，1 例（`ngap_default_port`）只给 `{"ngap": {}}` 验证缺省面。

**固定偏移（无 VLAN / 无 IP options / 无 TCP——SCTP 无 options 概念）**：

| 层 | 起点 | 长度 | 说明 |
|---|---:|---:|---|
| Ethernet II | 0 | 14 | `02:00:00:00:00:01` → `02:00:00:00:00:02`（up 方向；MAC 由 spec 缺省） |
| IPv4 | 14 | 20 | 无 options；TTL 缺省 **64**（`DefaultTTL`，`ngap.go:60`）；IP ID 从随机值起**逐帧 +1**（`ngap.go:270-275`） |
| SCTP 公共头 | 34 | 12 | SrcPort(2) + DstPort(2) + VerificationTag(4) + **CRC32c 校验和(4)**（`builder.go:1308-1313` + `fillSCTPChecksum`） |
| **首个 chunk** | **46** | 变长 | chunk Type(1) + Flags(1) + Length(2) + Value；**Value 填充到 4 字节边界**（`buildChunk`，`ngap.go:432-441`） |
| DATA chunk 内的 **NGAP-PDU** | **62** | 变长 | = 46 + 16（DATA value 头：TSN 4 + SID 2 + SSN 2 + PPID 4） |

**帧长公式（实测复算，15 个 pcap 全帧零例外）**：

```
chunk_len = 4 + len(chunk_value)            # Length 字段含 4B 头，不含填充
padded    = (chunk_len + 3) &^ 3            # 4 字节边界填充
frame.len = max(60, 46 + padded)            # 60 = 以太网最小帧（不含 FCS）
```

其中 DATA 块的 `chunk_value` 长度 = `12 + len(ngap_pdu)`，故 `chunk_len = 16 + len(ngap_pdu)`。**校验**：`ngap_sctp_setup_basic` f1 INIT `chunk_len=20` → `46+20=66` ✓；f4 COOKIE-ACK `chunk_len=4` → `46+4=50`，**被以太网最小帧抬到 60** ✓；f5 DATA `chunk_len=57` → `padded=60` → `106` ✓；`ngap_ta_drx` f5 `chunk_len=71` → `padded=72` → `118` ✓（实测帧长全表见 §8）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"ngap": {"src_port": 12345, "dst_port": 38412}}
  ]
}
```

带可选过程与业务字段（`ngap_all_procedures` 的等价形状）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"ngap": {
      "src_port": 12345, "dst_port": 38412,
      "initial_ue_message": true, "initial_nas": "rr",
      "downlink_nas": "dl", "uplink_nas": "ul",
      "pdu_session_setup": {"pdu_session_id": 1, "sst": 1, "sd": 1},
      "ue_context_release": true
    }}
  ]
}
```

多流样例（数量只走 `strategy_fc`/`flow_control`；`ngap_port_dyn` 用 `group_id` 钉单 worker FIFO 保序）：

```json
{
  "layers": [
    {"ip": {"src": {"strategy": "inc", "range": ["10.0.1.1", "10.0.1.2"], "step": 1}, "dst": "20.0.0.1"}},
    {"ngap": {"src_port": {"strategy": "inc", "range": [20000, 20001], "step": 1},
              "dst_port": {"strategy": "fixed", "value": 38412}}}
  ],
  "group_id": {"strategy": "fixed", "value": "ngap-port-dyn"}
}
```

## 3. 线格式编码（逐字段，按代码 + pcap 双向钉）

### 3.1 SCTP 公共头（12 字节，`builder.go:1308-1313`）

| 偏移（帧内） | 字段 | 尺寸 | 端序 | 取值 |
|---:|---|---:|---|---|
| 34 | SrcPort | 2 | 大端 | up 帧 = spec.SrcPort；down 帧 = spec.DstPort |
| 36 | DstPort | 2 | 大端 | 同上，反向 |
| 38 | VerificationTag | 4 | 大端 | 见 §3.6 表（RFC 4960 §5.1.1：INIT 恒 0，其后各帧带对端 tag） |
| 42 | Checksum | 4 | 大端 | **CRC32c（Castagnoli，RFC 4960 §6.8）**，覆盖整段 SCTP（公共头 + 全部 chunk），计算时本字段置 0 |

**校验和实证**：本车道独立复算（自写 CRC32c 反射多项式 `0x82F63B78`，逐帧比对）——`ngap_sctp_setup_basic` 9 帧、`ngap_all_procedures` 16 帧、`ngap_ta_drx` 9 帧**共 34 帧全部 OK**。填充字节计入 CRC（RFC 4960 §6.8 要求覆盖含填充的整段）。

### 3.2 NGAP-PDU 头三字段（**M-1 缺陷所在，逐 bit 钉死**）

`buildNGAPInitiating` / `buildNGAPSuccess`（`ngap.go:525-545`）写出：

| PDU 偏移 | 字段 | 实现写法（尺寸） | 实测字节（`ngap_sctp_setup_basic`） |
|---:|---|---|---|
| 0 | choice | **整字节**：`PDUInitiatingMessage=0` / `PDUSuccessfulOutcome=1` / `PDUUnsuccessfulOutcome=2` | f5 `00`（init）/ f6 `01`（impl 意图 = successfulOutcome） |
| 1 | procedureCode | 1 字节 | f5 `15`=21 / f6 `15`=21 |
| 2 | criticality | **整字节**：`CritReject=0` / `CritIgnore=1` / `CritNotify=2` | f5 `00`（reject）/ f6 `01`（impl 意图 = ignore） |
| 3.. | IE 容器 | §3.4 | — |

**M-1：choice 与 criticality 的位域与 tshark 的 aligned-PER 读法不一致（confirmed finding）**。

tshark 3.6.14 的 `packet-ngap.c` 按 **ASN.1 aligned PER** 解 NGAP-PDU：`NGAP-PDU ::= CHOICE { initiatingMessage, successfulOutcome, unsuccessfulOutcome }` 是 **3 个可选值的 CHOICE**，PER 取其 **2 bit** 放在**字节 0 的高 2 位**；`Criticality ::= ENUMERATED { reject, ignore, notify }` 同理取 **2 bit** 放在**字节 2 的高 2 位**。

本车道以**变异探针**（改一字节 → 重跑 tshark）钉死边界，结果（`ngap_pdu_session.pcap` f6，PDU 起点文件偏移 598）：

| 实现写入字节 0 | tshark 解出 `ngap.NGAP_PDU` | 说明 |
|---:|---|---|
| `0x00`–`0x1F`（32 值） | `0` = initiatingMessage | 高 2 bit = `00` |
| `0x20`–`0x3F`（32 值） | `1` = successfulOutcome | 高 2 bit = `01` |
| `0x40`–`0x5F`（32 值） | `2` = unsuccessfulOutcome | 高 2 bit = `10` |
| `0x60`–`0xFF`（160 值） | **无 NGAP 解**（dissector 放弃） | 高 2 bit = `11`（保留） |

| 实现写入字节 2 | tshark 解出 `ngap.criticality` | 说明 |
|---:|---|---|
| `0x00`–`0x3F` | `0` = reject | 高 2 bit = `00` |
| `0x40`–`0x7F` | `1` = ignore | 高 2 bit = `01` |
| `0x80`–`0xBF` | `2` = notify | 高 2 bit = `10` |
| `0xC0`–`0xFF` | `3` | 高 2 bit = `11`（越界值） |

**结论（两处系统性错位）**：
1. **choice**：实现写 `0x01` 表达 successfulOutcome，但 tshark 读高 2 bit = `00` → 解成 **initiatingMessage**。**每一帧 successfulOutcome（NGSetupResponse / PDUSessionResourceSetupResponse / UEContextReleaseComplete）都被解成 initiatingMessage**。正确 PER 线值应为 **`0x20`**（= `0x01 << 6`）。
2. **criticality**：实现写 `0x01` 表达 ignore，但 tshark 读高 2 bit = `00` → 解成 **reject**。正确 PER 线值应为 **`0x40`**（= `0x01 << 6`）；`notify` 应为 `0x80`。**即：实现写入的所有 `ignore` 都被读成 `reject`，所有 `reject` 恰好也读成 `reject`（巧合正确）。**

**本车道已实测验证的修复方向**（仅供 P4 参考，本车道不改代码）：把 f6 的字节 0 由 `0x01` 改 `0x20`、字节 2 由 `0x01` 改 `0x40` 后，tshark 输出变为 `NGAP_PDU=1`（successfulOutcome）、`criticality=1`（ignore）——**与实现意图一致**。修复后**帧长不变**（同字节数，仅位值变），故 §9 包数公式与全部 frames 断言**不受影响**；但 `ngap.procedureCode` 之外的字段断言（今日无用例断言 criticality，见 §9）需重钉。

**为何 17 例今日仍全绿**：存量 151 条断言中**零条**断言 `ngap.NGAP_PDU` 或 `ngap.criticality`（机读实测，§9）；断言只落在 `ngap.procedureCode`（不受影响，它在字节 1、整字节对齐）与 `sctp.*`/frames。故 M-1 **不被任何存量断言捕获**——这正是"绿 ≠ 对"的实例。

### 3.3 NGAP-PDU 总长度公式（实测复算，零例外）

```
len(NGAP-PDU) = 3 + 2 + Σ(4 + len(IE_value_i))       # 头3B + 容器count(2B) + 各IE
             = 5 + Σ(4 + len_i)
```

各消息实测值（`/tmp/mcp-pcaps/ngap/`，chunk_len 扣除 16B DATA 头得 PDU 长）：

| 消息 | proc | choice | crit | IE 数 | Σ(4+len) | **PDU 长** | 帧长 | 出处 |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| NGSetupRequest（缺省） | 21 | 0 | 0 | 3 | 36 | **41** | 106 | 全正例 f5 |
| NGSetupRequest（TA×2 + DRX=2） | 21 | 0 | 0 | 3 | 50 | **55** | 118 | `ngap_ta_drx` f5 |
| NGSetupResponse（`AMF-TEST-01`） | 21 | 1 | 1 | 1 | 15 | **20** | 82 | 全正例 f6 |
| NGSetupResponse（`AMF-EDGE-07`） | 21 | 1 | 1 | 1 | 15 | **20** | 82 | `ngap_amf_name` f6 |
| InitialUEMessage（NAS=`hello`） | 15 | 0 | 1 | 5 | 49 | **54** | 118 | `ngap_initial_ue` f7 |
| InitialUEMessage（NAS=`nas`，RAN-UE=42） | 15 | 0 | 1 | 5 | 47 | **52** | 114 | `ngap_ue_ids` f7 |
| InitialUEMessage（NAS=`rr`） | 15 | 0 | 1 | 5 | 46 | **51** | 114 | `ngap_all_procedures` f7 |
| DownlinkNASTransport（`downbytes`） | 4 | 0 | 1 | 3 | 29 | **34** | 98 | `ngap_dl_nas` f7 |
| DownlinkNASTransport（`dl`） | 4 | 0 | 1 | 3 | 22 | **27** | 90 | `ngap_all_procedures` f8 |
| UplinkNASTransport（`upbytes`） | 46 | 0 | 1 | 3 | 27 | **32** | 94 | `ngap_ul_nas` f7 |
| UplinkNASTransport（`ul`） | 46 | 0 | 1 | 3 | 22 | **27** | 90 | `ngap_all_procedures` f9 |
| PDUSessionResourceSetupRequest | 29 | 0 | 0 | 3 | 33 | **38** | 102 | `ngap_pdu_session` f7 |
| PDUSessionResourceSetupResponse | 29 | 1 | 1 | 3 | 33 | **38** | 102 | `ngap_pdu_session` f8 |
| UEContextReleaseCommand | 41 | 0 | 0 | 2 | 14 | **19** | 82 | `ngap_ue_release` f7 |
| UEContextReleaseComplete | 41 | 1 | 1 | 2 | 14 | **19** | 82 | `ngap_ue_release` f8 |

**PDU 长恒为奇数/偶数不定**——因 IE value 长度各异；**chunk 层负责补齐到 4 字节边界**（§2 帧长公式），故 `ngap_sctp_setup_basic` f5 `chunk_len=57`（奇数）由 `padded=60` 承载。

### 3.4 ProtocolIE-Container 与 ProtocolIE-Field（自定形，**非 PER**）

`buildIEContainer`（`ngap.go:549-556`）+ `buildIE`（`ngap.go:561-568`）：

| 结构 | 布局 | 端序 | 备注 |
|---|---|---|---|
| ProtocolIE-Container | `count`(2B) + 各 IE 顺序拼接 | **count 大端 uint16** | **非 PER**：PER 的 `SEQUENCE OF SIZE(0..65535)` 用 length determinant，不是裸 2B 大端 |
| ProtocolIE-Field | `id`(2B) + `criticality`(1B) + `value-length`(1B) + `value`(N) | id 大端；crit/len 整字节 | **非 PER**：PER 的 IE id 是 16 bit 对齐、criticality 是 2 bit、open type 长度用 length determinant 分片；此处 `len` 单字节 ⇒ **value ≥ 128 字节时 `byte(len)` 溢出截断**（G-NGAP-2） |

**tshark 实测**：**容器完全不解**——对任一 NGAP 帧跑 `-T pdml`，产生的 `ngap.*` 字段**仅有** `ngap.NGAP_PDU` / `ngap.<choice>_element` / `ngap.procedureCode` / `ngap.criticality` 四个；**没有任何 IE 级字段**（`ngap.id` / `ngap.AMFName` / `ngap.NAS_PDU` / `ngap.RAN_UE_NGAP_ID` … 全部不产生），**也无 `_ws.malformed` 告警**（15 个 pcap 实测 malformed=0）。即 dissector 在解完 PDU 头后静默停下。

**IE id 常量表**（`ngap.go:100-112`，值取 TS 38.413 §9.3 ProtocolIE-ID）：

| 常量 | 值 | 名称 | 出现消息 |
|---|---:|---|---|
| `IEID_AMFName` | 1 | AMFName | NGSetupResponse |
| `IEID_DefaultPagingDRX` | 21 | DefaultPagingDRX | NGSetupRequest |
| `IEID_NASPDU` | 38 | NAS-PDU | IUE / DL NAS / UL NAS |
| `IEID_GlobalRANNodeID` | 72 | GlobalRANNodeID | NGSetupRequest |
| `IEID_SupportedTAList` | 83 | SupportedTAList | NGSetupRequest |
| `IEID_RANUENGAPID` | 85 | RAN-UE-NGAP-ID | IUE / DL NAS / UL NAS / PDU-Sess Req/Res / UERelease Cmd/Cpl |
| `IEID_RRCEstablishmentCause` | 90 | RRCEstablishmentCause | InitialUEMessage |
| `IEID_UEContextRequest` | 112 | UEContextRequest | InitialUEMessage |
| `IEID_UserLocationInfo` | 121 | UserLocationInformation | InitialUEMessage |
| `IEID_AMFUENGAPID` | 10 | AMF-UE-NGAP-ID | DL NAS / UL NAS / PDU-Sess Req/Res / UERelease Cmd/Cpl |
| `IEID_PDUSessionResourceSetupListSUReq` | 77 | PDUSessionResourceSetupListSUReq | PDU-Sess Setup Request |
| `IEID_PDUSessionResourceSetupListSURes` | 78 | PDUSessionResourceSetupListSURes | PDU-Sess Setup Response |

**IE criticality 取值（TS 38.413 逐 IE 钉死，实现一致）**：`GlobalRANNodeID`/`SupportedTAList`/`AMFName`/`NAS-PDU`/`RAN-UE-NGAP-ID`/`AMF-UE-NGAP-ID`/`UserLocationInformation`/`PDUSessionResourceSetupList*` = **reject(0)**；`DefaultPagingDRX`/`RRCEstablishmentCause`/`UEContextRequest` = **ignore(1)**。实测逐 IE 复算一致（§9 附表）。

### 3.5 各 IE value 编码（逐字段，字节偏移实测）

**GlobalRANNodeID（id=72，crit=reject）** —— `encodeGlobalGNBID`（`ngap.go:626-639`），实测 `00 08 08 60 f4 10 04 00 00 00 01`（11B）：

| value 偏移 | 字段 | 尺寸 | 实测 | 说明 |
|---:|---|---:|---|---|
| 0 | choice | 1 | `00` | globalGNB-ID |
| 1 | 内层长度 | 1 | `08` | `len(PLMN)+5` = 3+5 |
| 2..4 | PLMN Identity | 3 | `08 60 f4` | MCC=460/MNC=1（§3.5.1） |
| 5 | BIT STRING 长度 | 1 | `04` | 4 字节 = 32 bit |
| 6..9 | gNB-ID | 4 | `00 00 00 01` | 大端 uint32 |

**SupportedTAList（id=83，crit=reject）** —— `encodeSupportedTAList`（`ngap.go:643-667`）：

| 项 | 尺寸 | 说明 |
|---|---:|---|
| `count` | 1 | SEQUENCE OF 项数（**非 PER**） |
| 每项：PLMN | 3 | TA 的 PLMN |
| 每项：BroadcastPLMN count | 1 | **恒 `01`**（1 项，与 TA 的 PLMN 同值） |
| 每项：BroadcastPLMN PLMN | 3 | 同上重复 |
| 每项：TAC count | 1 | TAC 个数（空则回退 `[1]`） |
| 每项：TAC | 3×n | **每 TAC 大端 3 字节** |

实测：缺省（1 TA / 1 TAC=1）→ `01 60 f4 10 01 60 f4 10 01 00 00 01`（12B）；`ngap_ta_drx`（2 TA）→ `02 60 f4 10 01 60 f4 10 02 00 00 64 00 00 c8 11 f4 50 01 11 f4 50 01 00 01 2c`（26B）——第 1 项 TAC 列表 `02` 后跟 `00 00 64`(100) `00 00 c8`(200)，第 2 项 PLMN `11 f4 50`(MCC=411/MNC=5)、TAC `00 01 2c`(300) ✓。

**DefaultPagingDRX（id=21，crit=ignore）** —— 1 字节枚举 `0..3`（vrf128/vrf256/vrf512/vrf1024，`ngap.go:118-122`）。实测缺省 `00`、`ngap_ta_drx` 显式 2 → `02` ✓。

**AMFName（id=1，crit=reject）** —— 裸字符串字节（**无长度前缀**，长度由 IE 的 value-length 字段承载）。实测缺省 `41 4d 46 2d 54 45 53 54 2d 30 31` = `AMF-TEST-01`（11B）；`ngap_amf_name` → `41 4d 46 2d 45 44 47 45 2d 30 37` = `AMF-EDGE-07`（11B，**同长**故 PDU 形状同构、仅字节变，用例 frames 断言正是钉这一点）。

**RAN-UE-NGAP-ID（id=85，crit=reject）** —— `encodeRANUENGAPID`（`ngap.go:611-615`）：**4 字节大端**。实测缺省 `00 00 00 01`；`ngap_ue_ids` 显式 42 → `00 00 00 2a` ✓。

**AMF-UE-NGAP-ID（id=10，crit=reject）** —— `encodeAMFUENGAPID`（`ngap.go:618-622`）：**2 字节大端（`uint16(id)` 截断）**——**不是** spec 的 4 字节/3 字节形态。缺省 1 → `00 01`；`ngap_ue_ids` 显式 424242 → `uint16(424242)` = **`0x67932` & 0xFFFF = `0x7932`**，但**实测该用例 f7 未出现 id=10 IE**（InitialUEMessage 不含 AMF-UE-NGAP-ID，见下）→ **该截断行为今日无用例覆盖**（G-NGAP-2）。

**NAS-PDU（id=38，crit=reject）** —— `encodeNASPDU`（`ngap.go:670-675`）：`len`(2B 大端) + 裸字节。实测 `hello`(5) → `00 05 68 65 6c 6c 6f`；`downbytes`(9) → `00 09 64 6f 77 6e 62 79 74 65 73`；`upbytes`(7) → `00 07 75 70 62 79 74 65 73`；`nas`(3) → `00 03 6e 61 73` ✓。

**UserLocationInformation（id=121，crit=reject）** —— `buildUserLocationInfo`（`ngap.go:842-857`）：`choice`(1)=`01`（userLocationInformationNR）+ `len(NR-CGI)`(1)=`07` + NR-CGI（PLMN 3B + `00 00 00 21`）+ `len(TAI)`(1)=`06` + TAI（PLMN 3B + TAC 3B `00 00 01`）。**恒 16 字节，PLMN 恒缺省 460/1**（不随配置变）。实测全例 `01 07 60 f4 10 00 00 00 21 06 60 f4 10 00 00 01` ✓。

**RRCEstablishmentCause（id=90，crit=ignore）** —— 1 字节，**恒 `04`**（mo-Data，`ngap.go:749` 硬编码）。

**UEContextRequest（id=112，crit=ignore）** —— 1 字节，**恒 `00`**（requested，`ngap.go:750` 硬编码）。

**PDUSessionResourceSetupListSUReq/SURes（id=77/78，crit=reject）** —— `buildPDUSessionSetupList`（`ngap.go:803-816`）：`count`(1)=`01` + `PDUSessionID`(1) + `transfer-len`(2B 大端) + transfer。transfer（`encodePDUSessionSetupTransfer`，`ngap.go:679-698`）恒 **11 字节**：`00 04`（S-NSSAI 长度）+ S-NSSAI（SST 1B + SD 3B）+ PDUSessionID(1) + 填充 `00 01 02 03`。实测 `01 01 00 0b 00 04 01 00 00 01 01 00 01 02 03`（15B）：count=1、PDUSessionID=1、transfer-len=11、`00 04`、S-NSSAI=`01 00 00 01`（SST=1,SD=1）、PDUSessionID 重复 `01`、填充 `00 01 02 03` ✓。**Request 与 Response 的 list IE 内容逐字节相同**，唯一差异是 IE id（77 vs 78）。

**缺省回退规则**：SST=0 → 1（eMBB）；SD=0 → 1；PDUSessionID=0 → 1（`ngap.go:680-687/804-807`）；TACs 空 → `[1]`；SupportedTAList 空 → 单 TA `{460,1,[1]}`；GlobalRANNodeID 的 PLMN 两值**同时为 0** 才回退缺省（`ngap.go:711`，**只给 MCC 不给 MNC 时不会回退**，见 G-NGAP-3）；gNBID=0 → 1；AMFName 空 → `AMF-TEST-01`；RANUENGAPID=0 → 1；AMFUENGAPID=0 → 1。

### 3.6 SCTP 块与握手/拆链（逐帧实测）

`buildChunk`（`ngap.go:432-441`）写 `Type(1) + Flags(1) + Length(2,BE)` 并把 value 补齐到 4 字节边界；**Length 含 4B 头、不含填充**。

| 块 | Type | Flags | value 布局 | 实测 chunk_len |
|---|---:|---:|---|---:|
| INIT | 1 | 0 | InitiateTag(4) + aRwnd(4)=65535 + OS(2)=10 + MIS(2)=10 + InitialTSN(4) | 20 |
| INIT-ACK | 2 | 0 | 同 INIT（16B）+ State Cookie 参数 `Type(2)=7 + Len(2)=36 + cookie(32)` | 56 |
| COOKIE-ECHO | 10 | 0 | cookie 原样 32B | 36 |
| COOKIE-ACK | 11 | 0 | 空 | 4 |
| DATA | 0 | **`0x03`**（B+E） | TSN(4,BE) + SID(2)=1 + SSN(2)=0 + PPID(4)=60 + PDU | 16+PDU长 |
| SHUTDOWN | 7 | 0 | highest-TSN-acked(4) | 8 |
| SHUTDOWN-ACK | 8 | 0 | 空 | 4 |
| SHUTDOWN-COMPLETE | 14 | 0 | 空 | 4 |

**握手 4 帧与 Verification Tag 流转**（`ngap.go:320-341`，实测逐帧核对）：

| 帧 | 方向 | 块 | VerificationTag | 值（实测 `ngap_sctp_setup_basic`） |
|---:|---|---|---:|---|
| 1 | up | INIT | **恒 0**（RFC 4960 §5.1.1） | `0x00000000` |
| 2 | down | INIT-ACK | = 对端 INIT 的 InitiateTag | `0xcb257058` |
| 3 | up | COOKIE-ECHO | = 对端 INIT-ACK 的 InitiateTag | `0xa8e384df` |
| 4 | down | COOKIE-ACK | = 客户端 tag | `0xcb257058` |
| 5+ | 双向 | DATA | 各自带对端 tag（up→server tag，down→client tag） | `0xa8e384df` / `0xcb257058` |
| 7 | up | SHUTDOWN | server tag | `0xa8e384df` |
| 8 | down | SHUTDOWN-ACK | client tag | `0xcb257058` |
| 9 | up | SHUTDOWN-COMPLETE | server tag | `0xa8e384df` |

**Tag 取值来源（非确定性）**：`clientVerTag`/`serverVerTag` 缺省由 `randNonZeroTag()`（`ngap.go:512-519`）生成——**每次运行不同**（G-NGAP-6）。故存量断言**零条**断言 vtag 数值（机读实测），只断言 `sctp.chunk_type`。

**TSN 与 IP ID（非确定性）**：`clientTSN`/`serverTSN` 初值 `rand.Uint32()`（`ngap.go:278-279`），DATA 每帧 **各方向独立 +1**（`ngap.go:316`）；IP ID 从 `uint16(rand.Uint32())` 起逐帧 +1（`ngap.go:270-275`）。**三者均不可断言**，存量断言同样零覆盖。

**SHUTDOWN 的 TSN 取值（可疑点，G-NGAP-7）**：`ngap.go:406-409` 写 `shutdownTSN = serverTSN; if >0 {--}`，即"**服务器**下一个待用 TSN 减 1"。RFC 4960 §9.2 的 Cumulative TSN Ack 语义是"**本端已收到的最高 TSN**"（由**发送 SHUTDOWN 的一方**报告它从对端收到的最高 TSN）。up 方向发 SHUTDOWN 报告的是**它从服务器收到的**最高 TSN——用 `serverTSN-1` 语义方向正确，但**当服务端一帧未发时 `serverTSN` 是随机初值**（非 0），减 1 后是随机数，**语义无意义**。实测 `ngap_sctp_setup_basic` f7 SHUTDOWN 的 value = `9c 3b 22 b8`（随机）——**今日无用例断言**。

### 3.7 PLMN Identity 编码（nibble 布局，逐位钉）

`encodePLMN`（`ngap.go:575-599`），3GPP TS 38.413 §9.3.1.1 nibble 布局 `MCC2 MCC1 | MNC3 MCC3 | MNC1 MNC2`：

| 字节 | 高 nibble | 低 nibble |
|---:|---|---|
| 0 | MCC digit 2 | MCC digit 1 |
| 1 | MNC digit 3（2 位 MNC 时**填 `0xF`**） | MCC digit 3 |
| 2 | MNC digit 1 | MNC digit 2 |

**实测**：MCC=460/MNC=1（2 位）→ `60 f4 10`（`mccDigits=[0,6,4]` → `b0=(6<<4)|0=0x60`；`b1=(0xF<<4)|4=0xf4`；`b2=(1<<4)|0=0x10`）✓；MCC=411/MNC=5 → `11 f4 50`（`b0=(1<<4)|1=0x11`；`b1=(0xF<<4)|4=0xf4`；`b2=(5<<4)|0=0x50`）✓；**3 位 MNC 分支**（`mnc>=100`）今日**无用例**（G-NGAP-8）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明"要跑哪些过程"，引擎按**固定剧本**产出帧序列（4 步握手 → NGSetup 对 → 可选过程按固定顺序 → 3 步拆链）。**ngap 层无自有状态机**：所有顺序在 `Plan` 里硬编码（`ngap.go:320-420`），无请求-响应配对检查、无状态迁移判定。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① NG 关联建立（基站开机首件事） | INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK → NGSetupRequest → NGSetupResponse | #1（`ngap_sctp_setup_basic`）全正例 |
| ② 基站自报家门（gNB 身份 + 支持 TA + 寻呼 DRX） | NGSetupRequest 携 GlobalRANNodeID/SupportedTAList/DefaultPagingDRX | #10（`ngap_ta_drx`，TA×2+DRX=2）、#12（`ngap_amf_name`，AMF 侧名） |
| ③ UE 初始接入（手机开机注册） | InitialUEMessage 携 NAS Registration Request | #4（`ngap_initial_ue`）、#11（`ngap_ue_ids`，UE ID 显式） |
| ④ 下行 NAS 透传（核心网下发） | DownlinkNASTransport | #5（`ngap_dl_nas`） |
| ⑤ 上行 NAS 透传（基站上报） | UplinkNASTransport | #6（`ngap_ul_nas`） |
| ⑥ PDU 会话资源建立（用户面通道） | PDUSessionResourceSetupRequest（AMF→gNB）→ Response（gNB→AMF） | #7（`ngap_pdu_session`） |
| ⑦ UE 上下文释放（去附着/超时） | UEContextReleaseCommand（AMF→gNB）→ Complete（gNB→AMF） | #8（`ngap_ue_release`） |
| ⑧ 完整生命周期（注册→透传→会话→释放） | 全部过程顺序串接 | #9（`ngap_all_procedures`，16 帧） |
| ⑨ 多基站/多 UE 并发（产线压力） | 逐流独立四元组，端口池轮转 | #15（`ngap_port_dyn`，2 流 × 9 帧） |
| ⑩ 缺省端口（不写端口） | translate 补 38412 | #14（`ngap_default_port`） |

**五层覆盖逐层结论**：

- **功能层**——SCTP 关联建立/拆除（4+3 帧）正例 12/12 覆盖；NGSetup 对、InitialUEMessage、DL/UL NAS、PDUSessionSetup 对、UEContextRelease 对**六类过程全部有正例**；错误处理 **5 条负例**（§7），其中 2 条为**建链期拒绝**（presence 判死 / 静态四元组拒）、3 条为**任务期校验器拒绝**（IPv6 / SST 越界 / NAS 超长）。
- **性能层**——帧长上界实测 **118**（`ngap_initial_ue` f7 / `ngap_ta_drx` f5），下界 **60**（以太网最小帧，COOKIE-ACK / SHUTDOWN 系列）；**无 MSS/分段概念**（raw-IP 自驱，ngap 层直接产完整以太帧，SCTP 无分片实现）；SCTP 块长度上界 65535（uint16），NAS-PDU 配置上界 4096 字节（`Validate`，`ngap.go:203-211`）；多流并发 2 流（#15）实测端口池逐流轮转正确。**吞吐数字待 P4 基准，本版不写承诺**（CORE_MEMORY §6.5）。
- **数据场景层**——PLMN 2 位 MNC（缺省 460/1、`ngap_ta_drx` 460/1 与 411/5 两组）、gNB-ID、TAC 列表（1 项/2 项）、DRX 枚举（0/2）、AMF 名字符串（缺省与自定义**等长**与**变长**两种形态）、NAS-PDU 长度（3/5/7/9 字节）、UE ID（缺省 1 / 显式 42）、SST/SD（缺省与显式 1/1）、PDUSessionID（1）。**值域边界**：SST 上界+1 = 300 拒绝（#16）；NAS 上界+1 = 4097 拒绝（#17）。
- **地址与流层**——**IPv4 单族**：IPv6 显式拒绝（#13，锚词 `only IPv4 is supported`），**不适用层显式声明**（§10.3 行 24）；单流基线（#1–#12 除 #15）；多流 2 条（#15，`flow_control.flows=2`，逐流 IP+端口双动态）；**流关联（控制流派生数据流）显式不适用**——NGAP 单条 SCTP 关联承载全部信令，无副连接、无 `driven_by`；**多会话（`sessions[]`）显式不适用**——ngap 层 registry Fields **无 `sessions` 键**（§12.1），多会话只能靠策略级多流表达。
- **业务层**——十场景全部有落点（上表）；多事务 = 一个 SCTP 关联内多对过程消息（#9 六对）；多会话 = 策略级多流（#15）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① IPv6 承载（未实现，`Validate` 拒绝——**这属"错误分支"不是"次要合法行为"**，已作负例 #13）；② 严格 PER 编码（未实现，M-1，**不得**声称合规）；③ SCTP 分片/多流复用/HEARTBEAT/SACK（未实现，§1 边界④⑤⑥）；④ 全部 `unsuccessfulOutcome` 过程与 InitialContextSetup/Paging/Handover 等过程（未实现，§10.4）；⑤ 真实 AMF/gNB 协议语义（注册成功/鉴权/切片可用性）。

## 5. 消息/事务模型与状态机

**事务定义**：一次请求 + 一次响应（或单向消息）。**多事务** = 一个 SCTP 关联内多对按序执行：#9 六对（NGSetup 对 + IUE 单发 + DL 单发 + UL 单发 + PDU-Sess 对 + UERelease 对）、#7/#8 各一对、#2 一对。

**ngap 层无自有状态机**：`Plan` 是**线性剧本**，不检查前置条件、不做状态迁移判定、不校验请求-响应配对。**帧序列由配置开关直接决定**（`ngap.go:320-420`）：

| 阶段 | 产出帧 | 触发条件 | 方向 | 用例 |
|---|---|---|---|---|
| ① SCTP 关联建立 | INIT / INIT-ACK / COOKIE-ECHO / COOKIE-ACK（4 帧） | **恒发** | up/down 交替 | 全 12 正例 |
| ② NG Setup | NGSetupRequest（proc 21, init）+ NGSetupResponse（proc 21, success） | **恒发**（`ngap.go:346-354`，无条件） | up / down | 全 12 正例 |
| ③ InitialUEMessage | 1 帧（proc 15, init） | `initial_ue_message=true` | **up** | #4/#9/#11 |
| ④ DownlinkNASTransport | 1 帧（proc 4, init） | `len(downlink_nas)>0` | **down** | #5/#9 |
| ⑤ UplinkNASTransport | 1 帧（proc 46, init） | `len(uplink_nas)>0` | **up** | #6/#9 |
| ⑥ PDUSessionResourceSetup | Request（proc 29, init, **down**）+ Response（proc 29, success, **up**） | `pdu_session_setup != nil` | down / up | #7/#9 |
| ⑦ UEContextRelease | Command（proc 41, init, **down**）+ Complete（proc 41, success, **up**） | `ue_context_release=true` | down / up | #8/#9 |
| ⑧ SCTP 关联拆除 | SHUTDOWN / SHUTDOWN-ACK / SHUTDOWN-COMPLETE（3 帧） | **恒发** | up/down/up | 全 12 正例 |

**阶段③–⑦的固定顺序**（与配置书写顺序**无关**）：IUE → DL NAS → UL NAS → PDU-Sess 对 → UERelease 对（`ngap.go:356-403` 的代码顺序即剧本顺序）。**#9 实测帧位印证**：f7 IUE(15) → f8 DL(4) → f9 UL(46) → f10/f11 PDU-Sess(29/29) → f12/f13 UERelease(41/41) ✓。

**方向语义（本协议的方向与常规相反，须写清）**：**AMF 侧发起的下行消息（PDU-Sess Setup Request、UERelease Command、DL NAS）在 SCTP 上是 down**；**gNB 侧的上行消息（NGSetupRequest、IUE、UL NAS）是 up**。这符合 TS 38.413 的发起方语义（NGSetup/IUE/UL NAS 由 gNB 发起，PDU-Sess/UERelease/DL NAS 由 AMF 发起）。**用例 `ngap_dl_nas` 正是钉这一点**（proc 4 在 f7 且 `ngap_all_procedures` f8 同位置）。

**请求-响应关联规则（任务书点名项，逐条写清）**：NGAP 用**两个 UE 标识配对**一个 UE 上下文——`RAN-UE-NGAP-ID`（gNB 分配）与 `AMF-UE-NGAP-ID`（AMF 分配）。本实现的行为：

| 消息 | 携带的 UE ID | 实测 |
|---|---|---|
| InitialUEMessage（up, proc 15） | **仅 RAN-UE-NGAP-ID(85)**（gNB 首次上报，AMF 尚未分配） | `ngap_ue_ids` f7：`55 00 04 00 00 00 2a`（id=85, len=4, 值 42）——**无 id=10** ✓ 符合 spec |
| DownlinkNASTransport（down, proc 4） | **AMF-UE-NGAP-ID(10) + RAN-UE-NGAP-ID(85)** | `ngap_dl_nas` f7：`00 0a 00 02 00 01`（id=10, len=2, 值 1）+ `00 55 00 04 00 00 00 01`（id=85, 值 1） ✓ |
| UplinkNASTransport（up, proc 46） | 同上两 ID | `ngap_ul_nas` f7 同形 ✓ |
| PDUSessionResourceSetupRequest/Response | 同上两 ID | `ngap_pdu_session` f7/f8 同形 ✓ |
| UEContextReleaseCommand/Complete | 同上两 ID | `ngap_ue_release` f7/f8 同形 ✓ |

**诚实声明（关联面）**：本实现的"配对"是**静态回显**——同一个 `RANUENGAPID`/`AMFUENGAPID` 配置值被**原样写进所有相关消息**，引擎**不校验**请求与响应是否真的一致（无配对检查代码，`grep` 实测）。即：关联**形式正确**（ID 出现在该出现的消息里），**但引擎不保证**它——正确性由配置决定。用例 #11（`ngap_ue_ids`）只断言"显式 UE ID 进 IUE PDU"（RAN-UE=42 实测 `00 00 00 2a`），**不断言跨消息配对一致性**（G-NGAP-5）。

**自动派生规则（逐条列，不依赖隐含知识）**：① `initial_ue_message=true` 且 `initial_nas` 为空 → 自动生成**最小 5GS Registration Request NAS-PDU**（`buildDefaultNASPDU`，`ngap.go:868-895`，**40 字节**：`7e 00 41 79 00` + mobile identity 长度(13+3=16) + SUCI(1) + PLMN(3) + routing indicator(2) + protection scheme(1) + home network key id(1) + MSIN 10 位数字 + 5GMM 能力(3) + UE 安全能力(6) + 请求 NSSAI(7)）；② NGSetupRequest/Response **恒发**，无开关；③ SCTP 握手/拆链**恒发**，无开关；④ `close` 类开关**不存在**（对比 opcua 的 `close`）——ngap 恒拆链；⑤ SupportedTAList 空 → 单 TA `{460,1,[1]}`；⑥ GlobalRANNodeID 空 → `{460,1,1}`；⑦ 各 IE 的 criticality 硬编码（§3.4 表），不可配。

**配置 → 帧的完整路径**：层链配置 → `ValidateLayers`（registry Fields 14 键 allowlist）→ `chain_planner_translate.go:1458`（层内 config → `spec.NGAP` + 端口双态）→ worker 逐流动态解析（`layer_dyn.go:834-846`，端口池）→ `isRawIPChain` 分支（`chain_planner.go:1497`）→ `flowMetaFor` 带 `NGAP` → ngap `Generator.Generate`（`layer_gen.go:32`）→ legacy `Planner.Plan`（`ngap.go:217`）→ 逐帧 `Emit`（`Direction` 强制 up）→ builder（SCTP 头 + CRC32c）→ writer（PCAP/NIC）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流帧数 **9 + 可选过程帧数**，实测上界 **16**（#9 全过程）；帧长上界实测 **118**（`ngap_initial_ue` f7）、下界 **60**；SCTP 块长度 uint16 上界 65535；NAS-PDU 配置上界 **4096 字节**（`ngap.go:203-211`）。**吞吐数字待 P4 基准，本版不写承诺**（§6.5）。
- **依据**：`Plan` 在 goroutine 内**流式产出**（`configChan` 容量 256，`ngap.go:222`），无全量包聚合；每帧内存 = 该帧长度（最小 60B / 最大 118B 实测）；无跨流共享状态；无锁（局部变量 + `time.Now()` 快照）。
- **验收两路（§6.3 强制）**：pcap（`/tmp/mcp-pcaps/ngap/`，正例 `<id>.pcap` / 任务期负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `sctp.*` 字段、`ngap.procedureCode`、帧原始 hex 与包数，不只断言"任务没报错"。**本版 17 例全部只用两路径均可观察的字段**。
- **六类场景落点（§6.6）**：基线（#1，9 帧）/ 目标规模（#9 全过程 16 帧）/ 压力上限（#15 双流 18 帧 + 逐流端口池）/ 长时间运行（多流承载语义，本版未做长跑）/ 并发交错（多流顺序展开承载，并发路径未启用）/ 背压（`packet_count` 精确计数守卫帧数漂移 + NAS-PDU 4096 上界守卫）。
- **确定性边界（须写清）**：**vtag / TSN / IP ID 三者非确定性**（`rand` 无种子，§3.6）——同一配置两次运行的这三类字节**不同**。存量断言**零覆盖**这三者（机读实测），故不构成 flaky 风险；但**任何未来新增断言不得钉这三者**。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须被拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或假成功。**分两类**：

**A 类：建链期拒绝（create-time，schema 门，无 pcap）**

| # | 负例 ID | 故障输入 | 代码锚词 | 代码行 |
|---:|---|---|---|---|
| N-1 | `ngap_flat_presence` | 顶层 `ngap` 子映射 presence（**空 map 也死**） | `no longer accepts a top-level ngap sub-config` | `strategy_convert.go:8954-8958` |
| N-2 | `ngap_flat_static_port` | ngap 层**静态标量端口** + `flows=2`（静态四元组复制） | `layers pin a static four-tuple but flows > 1` | `schema/semantic.go:285` |

**B 类：任务期校验器拒绝（task-time，产出 0 帧 pcap）**

| # | 负例 ID | 故障输入 | 代码锚词 | 代码行 |
|---:|---|---|---|---|
| N-3 | `ngap_neg_v6` | `ip.src`/`ip.dst` 为 IPv6 | `only IPv4 is supported` | `ngap.go:149`（SrcIP）/ `:154`（DstIP） |
| N-4 | `ngap_neg_sst` | `pdu_session_setup.sst=300`（上界+45） | `SST 300 out of range [0,255]` | `ngap.go:195` |
| N-5 | `ngap_neg_nas_len` | `initial_nas` 4097 字节（**上界+1**） | `InitialNAS too long` | `ngap.go:204` |

**负例原子性**：每例单一故障注入；单次执行不得混注。**实测三例 B 类 pcap 均 0 帧**（文件 24 字节 = 仅 pcap 头，`capinfos -c` = 0）。A 类两例由 Go 单测覆盖（`ngap_migrate_test.go:30-43`、`schema/ngap_static_port_test.go:12-32`），**不产 pcap**。

**B 类锚词口径**：`error_contains` 是**子串**判定；三例均命中代码文案（前缀 `ngap: `）。**N-3 实测命中 SrcIP 分支**（`ip.src` 先于 `ip.dst` 判定，`ngap.go:147` 早于 `:152`），故实际文案为 `ngap: SrcIP fd00::1 is IPv6; only IPv4 is supported`。

**Validate 全部 16 条拒绝分支（`ngap.go`，逐条列，未入例的标 A′ 立项）**：

| # | 锚词（代码字面值） | 行 | 入例 |
|---:|---|---:|---|
| 1 | `invalid SrcIP %q` | 138 | ✗ A′ |
| 2 | `invalid DstIP %q` | 143 | ✗ A′ |
| 3 | `SrcIP %s is IPv6; only IPv4 is supported` | 149 | ✓ N-3 |
| 4 | `DstIP %s is IPv6; only IPv4 is supported` | 154 | ✗ A′（SrcIP 先判，DstIP 分支不可达除非 Src 为 v4） |
| 5 | `SrcPort %d out of range`（`>=65535`） | 159 | ✗ A′ |
| 6 | `DstPort %d out of range`（`>=65535`） | 162 | ✗ A′ |
| 7 | `GlobalRANNodeID.PLMNMCC %d out of range [0,999]` | 173 | ✗ A′ |
| 8 | `GlobalRANNodeID.PLMNMNC %d out of range [0,999]` | 176 | ✗ A′ |
| 9 | `SupportedTAList[%d].PLMNMCC %d out of range [0,999]` | 182 | ✗ A′ |
| 10 | `SupportedTAList[%d].PLMNMNC %d out of range [0,999]` | 185 | ✗ A′ |
| 11 | `PDUSessionSetup.PDUSessionID %d out of range [0,255]` | 192 | ✗ A′ |
| 12 | `PDUSessionSetup.SST %d out of range [0,255]` | 195 | ✓ N-4 |
| 13 | `DefaultPagingDRX %d out of range [0,3]` | 200 | ✗ A′（**registry 已限 Max:3，层内不可达**，§12.1） |
| 14 | `InitialNAS too long (%d bytes, max 4096)` | 204 | ✓ N-5 |
| 15 | `UplinkNAS too long (%d bytes, max 4096)` | 207 | ✗ A′ |
| 16 | `DownlinkNAS too long (%d bytes, max 4096)` | 210 | ✗ A′ |

**16 条中 3 条入例，13 条 A′ 立项**（G-NGAP-1）。**注意分支 13 层内不可达**（`registry.go:1826` `default_paging_drx` 已声明 `Min:0,Max:3`，越界值在 `ValidateLayers` 阶段即被拦，走不到 planner 的 200 行）。

**不得误报的合法协议事件**：多过程串接（#9）；两 TA 的 TA 列表（#10）；自定义 AMF 名（#12）；NAS 空→自动注册请求（#4 未给 `initial_nas` 时？——**#4 给了 `hello`**，自动分支今日无用例，A′）；缺省端口（#14）；端口池动态（#15）；显式 UE ID（#11）。

## 8. 边界

- **帧长**：实测下界 **60**（以太网最小帧：COOKIE-ACK / SHUTDOWN-ACK / SHUTDOWN-COMPLETE 三帧裸 46 字节被抬高）；上界 **118**（`ngap_initial_ue` f7 NAS=`hello`、`ngap_ta_drx` f5 TA×2）；**全 15 个 pcap 的 min/max 逐文件实测**：`all_procedures 60/114`、`amf_name 60/106`、`default_port 60/106`、`dl_nas 60/106`、`initial_ue 60/118`、`pdu_session 60/106`、`port_dyn 60/106`、`sctp_setup_basic 60/106`、`ta_drx 60/118`、`ue_ids 60/114`、`ue_release 60/106`、`ul_nas 60/106`（3 个 neg pcap 0 帧）。
- **PDU 长**：实测 19–55（§3.3 全表）；PDU 长**不受** 4 字节对齐约束（chunk 层负责）。
- **SCTP 块**：`Length` 为 uint16（上界 65535）；**本实现无分片**，单块 B+E 承载整个 PDU；DATA 恒 `SID=1`、`SSN=0`、`PPID=60`。
- **IE value 长度**：`buildIE` 用**单字节** `byte(len(value))`（`ngap.go:565`）→ **value ≥ 128 字节时静默截断**（G-NGAP-2）。今日最大 IE value = 50 字节（`ngap_ta_drx` 的 SupportedTAList），**未触界**。
- **NAS-PDU 上界**：4096 字节（`Validate`）；实测用例最大 9 字节。
- **端口**：显式 12345/38412 全正例；缺省 dst 38412（#14 覆盖）；src 缺席 → worker `12345+i` 保底；`>=65535` 拒绝（A′）。
- **地址族**：**仅 IPv4**；IPv6 显式拒绝（#13）；**异族混写**（src v4 + dst v6）→ 走 SrcIP 分支先拒（与 N-3 同锚词，A′ 可补例）。
- **多流**：`flow_control.flows=N` → N 条独立流，逐流 IP/端口动态解析（#15 实测 2 流：流 1 帧 1–9 用 `10.0.1.1`/`20000`，流 2 帧 10–18 用 `10.0.1.2`/`20001`）；`group_id` 固定值 → 单 worker FIFO 保序。
- **多会话**：`sessions[]` **不适用**（registry 无该键）。
- **不得产生回绕长度或超量分配**：帧长由 `buildChunk` 一次算定；`configChan` 容量 256 有界。

## 9. 原子 ID 与完成定义（17 个唯一语义 ID = 12 正 + 5 负，顺序为权威）

| # | ID | 类型 | 覆盖 | 包数断言 | 实测帧数 |
|---:|---|---|---|---|---:|
| 1 | `ngap_sctp_setup_basic` | 正 | §3.6/§3.3：SCTP 4 步握手 + NGSetup 对 + 3 步拆链（最小 9 帧） | `min_packets: 9` | 9 ✓ |
| 2 | `ngap_flat_presence` | 负(A) | §7 N-1：顶层 ngap presence 判死 | — | 0（无 pcap） |
| 3 | `ngap_flat_static_port` | 负(A) | §7 N-2：静态端口 + flows=2 拒 | — | 0（无 pcap） |
| 4 | `ngap_initial_ue` | 正 | §3.5：InitialUEMessage（proc 15, up） | `min_packets: 10` | 10 ✓ |
| 5 | `ngap_dl_nas` | 正 | §3.5/§5：DownlinkNASTransport（proc 4, **down**） | `min_packets: 10` | 10 ✓ |
| 6 | `ngap_ul_nas` | 正 | §3.5：UplinkNASTransport（proc 46, up） | `min_packets: 10` | 10 ✓ |
| 7 | `ngap_pdu_session` | 正 | §3.5/§5：PDUSessionSetup 请求+响应（proc 29 对） | `min_packets: 11` | 11 ✓ |
| 8 | `ngap_ue_release` | 正 | §3.5/§5：UEContextRelease Command+Complete（proc 41 对） | `min_packets: 11` | 11 ✓ |
| 9 | `ngap_all_procedures` | 正 | §5：全可选过程串接（16 帧） | `min_packets: 16` | 16 ✓ |
| 10 | `ngap_ta_drx` | 正 | §3.5：SupportedTAList×2 + DRX=2 + GlobalRANNodeID 自定义 | `min_packets: 9` | 9 ✓ |
| 11 | `ngap_ue_ids` | 正 | §3.5/§5：显式 UE ID（RAN-UE=42）进 IUE PDU | `min_packets: 10` | 10 ✓ |
| 12 | `ngap_amf_name` | 正 | §3.5：自定义 AMF 名 `AMF-EDGE-07`（frames 钉 hex） | `min_packets: 9` | 9 ✓ |
| 13 | `ngap_neg_v6` | 负(B) | §7 N-3：IPv6 拒 | — | 0 ✓ |
| 14 | `ngap_default_port` | 正 | §2/§3.5：dst 缺省 38412 + src 保底 12345 | `min_packets: 9` | 9 ✓ |
| 15 | `ngap_port_dyn` | 正 | §12.12：ngap.src_port 动态 inc + flows=2（逐流端口池） | **`packet_count: 18`** | 18 ✓ |
| 16 | `ngap_neg_sst` | 负(B) | §7 N-4：SST 越界拒 | — | 0 ✓ |
| 17 | `ngap_neg_nas_len` | 负(B) | §7 N-5：NAS 超长拒 | — | 0 ✓ |

**包数公式（实测复算，12/12 正例逐例一致）**：

```
帧数 = 4（握手）+ 2（NGSetup 对）+ 3（拆链）
     + 1×[initial_ue_message] + 1×[len(downlink_nas)>0] + 1×[len(uplink_nas)>0]
     + 2×[pdu_session_setup != nil] + 2×[ue_context_release]
     = 9 + 可选帧数
```

**校验**：#1/#10/#12/#14 可选 0 → 9 ✓；#4/#5/#6/#11 可选 1 → 10 ✓；#7/#8 可选 2 → 11 ✓；#9 可选 1+1+1+2+2=7 → 16 ✓；#15 单流 9 × 2 流 = 18 ✓。**12/12 与实测 pcap 帧数逐例一致**。

**断言规模（机读实测，2026-09-29）**：**148 条 `fields` 断言 + 3 条 `frames` 断言 + 12 条包数断言**（11 条 `min_packets` + 1 条 `packet_count`）。**全部对磁盘 pcap 逐条复算，零不符**。

**断言字段分布**：`sctp.chunk_type`（握手/拆链/PPID 面）、`sctp.srcport`/`sctp.dstport`（端口面）、`sctp.data_payload_proto_id`（=60 面）、`ngap.procedureCode`（过程码面）。**零条**断言 `ngap.NGAP_PDU`、`ngap.criticality`、`sctp.verification_tag`、`sctp.data_tsn`、`sctp.data_sid`、`sctp.data_ssn`、`ip.id`（M-1 与不确定性面未被覆盖，§3.2/§3.6）。

### 9.1 frames 断言逐条（3 条，全 OK）

| 用例 | 帧 | offset | hex | 语义 |
|---|---:|---:|---|---|
| #1 `ngap_sctp_setup_basic` | 5 | 62 | `00 15 00 00 03 00 48 00 0b 00 08 08 60 f4 10 04 00 00` | NGSetupRequest：choice=0, proc=21, crit=0, IEcount=3, IE1 id=72 crit=0 len=11, value 头 `08 60 f4 10 04 00 00` |
| #1 `ngap_sctp_setup_basic` | 6 | 62 | `01 15 01 00 01 00 01 00 0b 41 4d 46 2d 54 45 53 54 2d 30 31` | NGSetupResponse：choice=1, proc=21, crit=1, IEcount=1, IE id=1 crit=0 len=11, `AMF-TEST-01` |
| #12 `ngap_amf_name` | 6 | 62 | `01 15 01 00 01 00 01 00 0b 41 4d 46 2d 45 44 47 45 2d 30 37` | 同上但 AMF 名 = `AMF-EDGE-07`（**同长 11 故形状同构**） |

### 9.2 实测 IE 逐例复算（§3.4/§3.5 的机器证据）

| 用例 | 帧 | PDU 长 | proc | crit | IE 序列（id,crit,len） |
|---|---:|---:|---:|---:|---|
| #1/#4/#5/#6/#7/#8/#11/#12/#14/#15 | 5 | 41 | 21 | 0 | (72,0,11) (83,0,12) (21,1,1) |
| #10 `ngap_ta_drx` | 5 | 55 | 21 | 0 | (72,0,11) (83,0,**26**) (21,1,1) |
| 全正例 | 6 | 20 | 21 | 1 | (1,0,11) |
| #4 `ngap_initial_ue` | 7 | 54 | 15 | 1 | (85,0,4) (38,0,7) (121,0,16) (90,1,1) (112,1,1) |
| #11 `ngap_ue_ids` | 7 | 52 | 15 | 1 | (85,0,4)=42 (38,0,5) (121,0,16) (90,1,1) (112,1,1) |
| #5 `ngap_dl_nas` | 7 | 34 | 4 | 1 | (10,0,2) (85,0,4) (38,0,11) |
| #6 `ngap_ul_nas` | 7 | 32 | 46 | 1 | (10,0,2) (85,0,4) (38,0,9) |
| #7 `ngap_pdu_session` | 7/8 | 38/38 | 29/29 | 0/1 | (10,0,2) (85,0,4) (**77**/**78**,0,15) |
| #8 `ngap_ue_release` | 7/8 | 19/19 | 41/41 | 0/1 | (10,0,2) (85,0,4) |
| #9 `ngap_all_procedures` | 7/8/9/10/11/12/13 | 51/27/27/38/38/19/19 | 15/4/46/29/29/41/41 | 1/1/1/0/1/0/1 | 见上各行 |

**criticality 列的"实现意图值"**（= 字节 2 的整字节值，非 tshark 读值）：NGSetupReq=0、NGSetupResp=1、IUE=1、DL=1、UL=1、PDUReq=0、PDURes=1、UERelCmd=0、UERelCpl=1。**M-1 使 tshark 把每个 1 读成 0（reject）**——故 §3.2 表中 tshark 侧的 `criticality` 恒为 0，与本列不同。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求（TS 38.413 / TS 38.412 / RFC 4960） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | SCTP 关联（TS 38.412）：gNB 主动向 AMF 38412 建关联；PPID=60 | ①③ | `DependsOn ["ip"]`（`registry.go:1823`）；SCTP 4 步握手落码（`ngap.go:320-341`）；PPID 常量 60（`ngap.go:64`） | 无 |
| 2 | 命令/消息表 | 六类过程：NGSetup(21)/InitialUEMessage(15)/DownlinkNASTransport(4)/UplinkNASTransport(46)/PDUSessionResourceSetup(29)/UEContextRelease(41) | ②–⑧ | 六类全部落码（`ngap.go:704-836`）；过程码常量表（`ngap.go:87-93`） | **过程码覆盖面窄**：TS 38.413 §9.2 定义 **60+ 过程码**，本实现只 6 个（G-NGAP-4） |
| 3 | 状态机 | 关联建立→NGSetup→（UE 过程）→关联释放 | 全场景 | **无状态机**——线性剧本（`ngap.go:320-420`），无状态迁移判定 | 显式"不适用"（本层无状态机，§5） |
| 4 | 字段表 | NGAP-PDU 头三字段 + ProtocolIE-Container + 各 IE | 数据场景层 | `buildNGAPInitiating`/`buildNGAPSuccess`/`buildIEContainer`/`buildIE` 逐字段（`ngap.go:525-568`） | **M-1（choice/criticality 位域）** + 容器非 PER（§3.2/§3.4） |
| 5 | 错误处理 | 配置非法须拒绝并传播 | 负例 N-1..N-5 | 16 条 `Validate` 分支（`ngap.go:138-210`）+ 2 条 schema 门 | **13 条未入例**（G-NGAP-1） |
| 6 | 超时与活性 | SCTP 有 HEARTBEAT（RFC 4960 §3.3.5）；NGAP 层有 NG Reset/OverloadStart | — | **无 HEARTBEAT**（未实现）；**无 NGReset/Overload**（未实现） | A′ 立项（G-NGAP-4）；**协议层无 keepalive 概念**（判"不适用"，见 §6.1③） |
| 7 | NAT/代理/被动 | 无被动模式概念（gNB 主动建关联） | — | 无 `sessions[].src_port`；多流走策略级 `flow_control` | **显式不适用**被动模式 |
| 8 | 版本/方言 | NGAP 唯一版本（Rel-15+）；SCTP 唯一承载 | 全正例 | 单 profile（§1）；缺省端口 38412（`chain_planner_translate.go:1567`） | IPv6 **已作负例**（#13，覆）；SCTP-over-DTLS 未实现（不解决） |

**逐项重数**：8 行——已覆 **2**（连接模型 / 版本方言：IPv6 负例已覆）/ 立项 **4**（命令消息表 G-NGAP-4 / 字段表 M-1 / 错误处理 G-NGAP-1 / 超时活性 G-NGAP-4）/ **不适用 2**（状态机——本层无状态机 / NAT 被动模式——协议无此概念）。2 + 4 + 2 = 8 ✓

### 10.2 子表①：过程 × 终态矩阵（逐格已覆/立项/不适用）

| 过程 | T1 正常终态 | T2 配置拒绝 | T3 RST/异常终态 |
|---|---|---|---|
| SCTP 4 步握手 | 已覆（#1） | 已覆（#2 代表例，拒绝与消息无关） | A′ 立项（G-NGAP-9） |
| NGSetup（req+resp） | 已覆（#1/#10/#12） | 同上代表已覆 | A′ 立项（G-NGAP-9） |
| InitialUEMessage | 已覆（#4/#11） | 同上代表已覆 | A′ 立项（G-NGAP-9） |
| DownlinkNASTransport | 已覆（#5） | 同上代表已覆 | A′ 立项（G-NGAP-9） |
| UplinkNASTransport | 已覆（#6） | 同上代表已覆 | A′ 立项（G-NGAP-9） |
| PDUSessionResourceSetup | 已覆（#7） | 已覆（#16 SST 专属拒绝） | A′ 立项（G-NGAP-9） |
| UEContextRelease | 已覆（#8） | 同上代表已覆 | A′ 立项（G-NGAP-9） |
| SCTP 3 步拆链 | 已覆（全正例） | 同上代表已覆 | A′ 立项（G-NGAP-9） |
| 全过程串接 | 已覆（#9） | 不适用（组合场景非单点） | A′ 立项（G-NGAP-9） |

**逐格重数**：9 行 × 3 列 = 27 格——已覆 **17**（T1 列 9 + T2 列 8）/ A′ 立项 **9**（T3 列 9）/ **不适用 1**（全过程串接 T2——组合场景非单点配置拒绝）。17 + 9 + 1 = 27 ✓

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **24 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | NGSetupRequest 缺省 PLMN（460/1）+ gNB-ID=1 + TA 缺省 | 覆（#1，f5） |
| 2 | GlobalRANNodeID 显式（460/1，gnb_id=4097） | 覆（#10，实测 gNB-ID `00 00 10 01`） |
| 3 | SupportedTAList 1 项 / 1 TAC | 覆（#1，`01 ... 00 00 01`） |
| 4 | SupportedTAList 2 项 / TAC 数 2+1 | 覆（#10，26 字节） |
| 5 | DefaultPagingDRX=0（缺省） | 覆（#1，`00`） |
| 6 | DefaultPagingDRX=2 | 覆（#10，`02`） |
| 7 | AMFName 缺省 `AMF-TEST-01` | 覆（#1 f6 frames） |
| 8 | AMFName 自定义**等长**（11B）`AMF-EDGE-07` | 覆（#12，frames 钉 hex） |
| 9 | AMFName 自定义**变长** | **A′ 立项**（今日两例均 11B，**等长**——变长分支无例） |
| 10 | AMFName 空（回退缺省） | **A′ 立项**（`ngap.go:248-250` 有分支） |
| 11 | RAN-UE-NGAP-ID 缺省 1 | 覆（#1/#4 等） |
| 12 | RAN-UE-NGAP-ID 显式 42（`00 00 00 2a`） | 覆（#11） |
| 13 | RAN-UE-NGAP-ID 上界 4294967295 | A′ 立项 |
| 14 | AMF-UE-NGAP-ID 缺省 1（2B `00 01`） | 覆（#5/#7/#8） |
| 15 | AMF-UE-NGAP-ID 显式 >65535（2B 截断行为） | **A′ 立项**（#11 给了 424242 但 IUE 不含该 IE，**截断未被任何断言观察到**，G-NGAP-2） |
| 16 | InitialNAS 缺省（自动注册请求 **40B**） | **A′ 立项**（`buildDefaultNASPDU` 有实现，无用例） |
| 17 | InitialNAS 自定义短（`hello`=5B / `rr`=2B / `nas`=3B） | 覆（#4/#9/#11） |
| 18 | InitialNAS 上界 4096 | A′ 立项（边界值本身） |
| 19 | InitialNAS 上界+1 = 4097 | 覆负例（#17） |
| 20 | DownlinkNAS 非空（`downbytes`=9B / `dl`=2B） | 覆（#5/#9） |
| 21 | UplinkNAS 非空（`upbytes`=7B / `ul`=2B） | 覆（#6/#9） |
| 22 | PDUSessionSetup 缺省（SST=1/SD=1/ID=1） | 覆（#7/#9） |
| 23 | SST=300（上界+45） | 覆负例（#16） |
| 24 | 端口：显式 / 缺省 dst / 动态 inc 池 / 静态+flows>1 | 覆（#1 显式 / #14 缺省 / #15 动态 / #3 静态拒） |

**16 覆 + 8 立项 = 24**。✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 基站开机建 SCTP 关联（TS 38.412） | #1 | 已覆 |
| 2 | NG Setup 交换（基站与核心网握手） | #1/#10/#12 | 已覆 |
| 3 | UE 初始注册（手机开机） | #4/#11 | 已覆 |
| 4 | 下行 NAS 透传（鉴权/配置下发） | #5 | 已覆 |
| 5 | 上行 NAS 透传（注册完成上报） | #6 | 已覆 |
| 6 | PDU 会话资源建立（用户面通道） | #7 | 已覆 |
| 7 | UE 上下文释放（去附着） | #8 | 已覆 |
| 8 | 完整 UE 生命周期 | #9 | 已覆 |
| 9 | 多基站/多 UE 产线压力 | #15 | 已覆 |
| 10 | 缺省配置（零端口） | #14 | 已覆 |
| 11 | InitialContextSetup（UE 上下文建立，TS 38.413 §9.2.2） | — | **明确不解决**（G-NGAP-4） |
| 12 | Paging（寻呼，§9.2.6） | — | **明确不解决**（G-NGAP-4） |
| 13 | Handover 家族（切换，§9.2.3.x） | — | **明确不解决**（G-NGAP-4） |
| 14 | NGReset / ErrorIndication / OverloadStart（§9.2.7） | — | **明确不解决**（G-NGAP-4） |
| 15 | unsuccessfulOutcome 过程（失败结果分支） | — | **明确不解决**（实现无任何 `buildNGAPUnsuccessful` 调用，`PDUUnsuccessfulOutcome=2` 常量**从未使用**） |
| 16 | SCTP 多流复用（TS 38.412 流标识） | — | **明确不解决**（恒 SID=1） |
| 17 | SCTP 分片/重组（大 PDU） | — | **明确不解决**（恒单块 B+E） |
| 18 | SCTP HEARTBEAT 保活（RFC 4960 §3.3.5） | — | **明确不解决**（未实现） |
| 19 | 真实 AMF 语义（鉴权/切片可用性） | — | **明确不解决**（生成器范围外） |

**10 覆 + 9 不适用 = 19**。✓ 无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：①**规范原文**（TS 38.413 / TS 38.412 / RFC 4960）——定"必须是什么"，本轮用 RFC 4960 逐条核对 SCTP 块布局/握手/vtag 流转/CRC32c（**全部正确**），用 tshark 3.6.14 的 PER 读法反证 PDU 头位域（**M-1**）；②**商业化软件实际行为**——**未取到**（真实 AMF/gNB 线字节未抓包，TS 38.413 条款号未逐条核对 → G-NGAP-4）；③**可靠开源实现思路**——未参考（本实现为自研简化形）。三路一致点：SCTP 承载全链（PPID=60、38412、块类型、握手序列）；不一致点：**PDU 头位域编码**（规范/aligned-PER vs 本实现的整字节形）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `ngap` **raw-IP 自驱终结层**（本版；h323/mpls/telnet 同构先例） | 层自产完整以太帧（含 SCTP），可声明过程与业务字段；代价 = 一套层（已落码 969 行） | **采用** |
| B | 复用已有 `sctp` 层 + ngap 作为上层事件层 | sctp 层已存在（`registry.go:2071`）但**只产 SCTP chunk 序列**，不产 NGAP PDU；且 ngap 需要"过程开关 → 帧序列"的剧本，sctp 层无此概念 | **否决**（本版独立成层；未来若复用须解决 chunk/PDU 双层编排） |
| C | 拆成"传输层 sctp + 信令层 ngap"两层 | 两层的边界（TSN/vtag 在 sctp 层、PDU 在 ngap 层）需跨层状态传递，框架层间无此通道 | **否决**（状态在 `Plan` 局部变量，单层内聚更简单；opcua 方案 C 同款裁定） |

## 11. P2 D-NGAP-1 代码设计（CORE_MEMORY §8 八要素；as-built 逆向定稿）

> 状态说明：实现已落码（`internal/protocol/ngap/` 三文件），本 P2 条目为文档轨对既有实现的**逆向定稿**（as-built），供后续改动的唯一入口；P4 在本协议内为"缺口收敛"（§14），不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:8745-8860` + `:1876` + `:3674-3676` + `:3708`） | `NGAPConfig` / `NGAPGlobalRANNodeID` / `NGAPSupportedTA` / `NGAPPDUSessionSetup` + `FlowSpec.NGAP` 槽位 + `LayerTransportDyn.NGAP` | —（共享文件） |
| `trafficgen/internal/protocol/ngap/ngap.go` | planner：`Validate`（16 分支）+ `Plan`（剧本）+ SCTP 块构造 8 个 + NGAP PDU/IE 构造 12 个 + 编码辅助 8 个 | 895 |
| `trafficgen/internal/protocol/ngap/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator` + `RegisterLayerValidator`，`init()`）；`GenEvents` 恒 nil（raw 自驱） | 74 |
| `trafficgen/internal/protocol/ngap/ngap_test.go` | 54 个 `Test*`（Validate 面 15 + Plan 面 33 + 编码面 6） | 974 |
| 接线 6 件 | registry（`registry.go:1823`）/ translate（`chain_planner_translate.go:1458`）/ convert（`strategy_convert.go:1226`）/ `CheckProtoFlat`（`strategy_convert.go:8954`）/ 动态 allowlist（`layer_dyn.go:57`）+ 逐流解析（`:834`）/ raw-IP 与端口豁免（`chain_planner_util.go:54/57`、`chain_planner.go:763/996`）+ `main.go:123/601` | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`ngap.go:135`）：IP 可解析 → IPv4-only → 端口 `<65535` → `NGAP==nil` 早返回（**translate 后不可达**）→ GlobalRANNodeID PLMN 范围 → SupportedTAList 各 PLMN 范围 → PDUSessionID/SST 范围 → DRX 范围 → 三个 NAS 长度 ≤4096。**16 条拒绝分支**（§7 表）。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`ngap.go:217`）：先 `Validate`，再起 goroutine 流式产出（`configChan` 容量 256）。
- 生成器：`Name() "ngap"`；`GenEvents() nil`（**必须 nil**——`chain_planner.go` 的事件分支检查把非 nil `GenEvents` 路由到传输路径，ngap 须走 raw 自驱）；`Generate` 把 legacy `Plan` 每帧强制 `Direction="up"` 后 `Emit`（`layer_gen.go:26-57`）。

### 11.3 数据结构

`NGAPConfig{GlobalRANNodeID *NGAPGlobalRANNodeID, SupportedTAList []NGAPSupportedTA, DefaultPagingDRX int, AMFName string, UplinkNAS []byte, DownlinkNAS []byte, PDUSessionSetup *NGAPPDUSessionSetup, UEContextRelease bool, RANUENGAPID uint32, AMFUENGAPID uint32, InitialUEMessage bool, InitialNAS []byte}`（`types.go:8767-8828`，**12 字段**）；`NGAPGlobalRANNodeID{PLMNMCC, PLMNMNC int, GNBID uint32}`（`:8833-8837`）；`NGAPSupportedTA{PLMNMCC, PLMNMNC int, TACs []uint32}`（`:8841-8845`）；`NGAPPDUSessionSetup{PDUSessionID int, SST int, SD uint32}`（`:8849-8857`）。

**registry Fields（14 键）与 struct 12 字段逐键对齐**（机读实测）：12 业务键**全部可达**（无 opcua 那种"未登记键"），加 `src_port`/`dst_port` 端口 2 键 = 14。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry Fields 14 键 allowlist）→ translate（层内 config → `spec.NGAP` 12 键逐键搬运 + 端口双态：标量层值赢 / dst 缺席补 38412 / src 缺席不动 / 对象放行）→ worker 逐流动态解析（`layer_dyn.go:834-846` 端口池落 spec）→ `isRawIPChain` 判定（`chain_planner_util.go:54`）→ `flowMetaFor` 带 `NGAP` → ngap `Generator.Generate`（`layer_gen.go:32`）→ legacy `Planner.Plan`（`ngap.go:217`：握手 4 → NGSetup 对 → 可选过程 → 拆链 3）→ 逐帧 `Emit` → builder（SCTP 头 + CRC32c）→ writer（PCAP/NIC）。

### 11.5 错误分支

16 种 planner 拒绝（`ngap.go:138-210`）+ 2 种 schema 门（`strategy_convert.go:8954` presence、`schema/semantic.go:285` 静态四元组）全部传 task error（零假成功——三例 B 类实测 0 帧）。**无静默降级路径**（对比 opcua 的 `ErrorInject.Op` 未知值静默 Good）。**唯一静默行为**：`buildIE` 的 `byte(len(value))` 在 value ≥128 字节时**静默截断长度**（G-NGAP-2）。

### 11.6 性能边界

见 §6（流式产出、per-flow 局部状态、无跨流共享、无锁；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- **`CheckProtoFlat` 有 ngap 分支**（`strategy_convert.go:8954`）→ 顶层 `ngap` presence **今日已判死**（含空 map），N-1 用例**今日真绿**（**非假通过**，与 opcua G-OPCUA-1 相反）。✓
- **`sctp` 层已存在**（`registry.go:2071`）但 ngap **不用它**——`DependsOn ["ip"]` 直接挂 ip（§10.5 方案 B 已否决）。两协议各自产 SCTP 帧，**互不引用**。
- **动态 allowlist**：`ngap` 命中 2 键（`src_port`/`dst_port`，`layer_dyn.go:57`）——端口对象可动态；**12 业务键全关**（对象即 `does not support dynamic`）。见 §12.12。
- **registry 与生成表同代**：`schemas/v1/generated/layers.generated.json` 的 ngap 条目 = `category: terminal` / `depends_on: ["ip"]` / **14 字段**，与 `registry.go:1823` 逐键一致（机读实测）。**P4 若改 registry Fields 必须重跑 schemagen**。
- **`PDUUnsuccessfulOutcome=2` 常量从未使用**（`grep` 实测仅定义处一行）→ 死常量（G-NGAP-4 附表）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 3 文件 + 接线 6 处（registry/protocols/translate/convert/CheckProtoFlat/layer_dyn/chain_planner_util/chain_planner/main）；不触及其他协议。cases 回滚 = 恢复 17 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：**15/17 例顶层 = `{layers}`**（唯一键，零游离键）+ **1 例顶层 `{layers, group_id}`**（白名单键，非游离）；**第 17 例 `ngap_flat_presence` 顶层含 `ngap:{}`**——那是**判死负例的故障注入本身**（presence 门今日真绿），**非残留**；目标形状见 §2 样例 | §12.1；`cases/ngap.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 ngap 流量模板；任务 = 多策略合跑 + 总量封顶；多流走 `flow_control`（#15 用 `strategy_fc`） | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（**无派生流 + 静态回显**诚实声明）/插入位置（raw-IP 终层）/时间线。有长连接，不豁免 | §12.3 + §5 |
| §4 查规范 | TS 38.413 + TS 38.412 + RFC 4960 + tshark 3.6.14 字段（1119 个）与 15 例 pcap 实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["ip"]` 单值（`registry.go:1823`）；16+2 种拒绝分支；失败传 task error（三例 0 帧实测） | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待 P4 基准，不写承诺；pcap/NIC 两路验收明写；**确定性边界写清**） | §6 |
| §7 三份文档 | `116-ngap-{design,testcase}.md`（本对）+ cases JSON 17 例 + D-NGAP-1（§11）；**无旧基线**（§0） | 修订记录 |
| §8 设计先行 | **例外**：本协议实现与用例先于文档存在（`D-NGAP-1` P-PIPE #17 已落码落库），本版为 as-built 逆向定稿；§14 缺口为后续入口 | §0 说明 |
| §9 测试三源 | 三源 = TS 38.413/38.412 + RFC 4960（§10）+ D-NGAP-1（§11）+ tshark 3.6.14 字段与 pcap 实测（**已到抓包级**：15 例 pcap 在案，148+3+12 条断言逐条复算 OK）；17 ID 逐项回指；存量 17 例审计去向 testcase §8 | `116-ngap-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 `/tmp/pipe/doc-lanes/ngap.md`）+ 收官隔离复审；红先绿后 | 自审日志 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组 2 键开（allowlist 实测）；业务 12 键逐个列关 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `ngap` 已在 `registry.go:1823` 注册（**不新增层**）；生成表 14 键与 registry 逐键一致（机读实测）；**P4 若改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `ngap.*` + `sctp.*` + frames 三通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/ngap/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 项 | 例数 | 详情 |
|---|---:|---|
| 总例数 | **17** | 12 正 + 5 负 |
| `spec_json` 顶层键 = `{layers}` | **15** | 唯一顶层键，**零游离键** |
| `spec_json` 顶层键 = `{layers, ngap}` | **1** | `ngap_flat_presence`——**判死负例的故障注入**（presence 门） |
| `spec_json` 顶层键 = `{layers, group_id}` | **1** | `ngap_port_dyn`（`group_id` 在白名单内，非违规） |
| 层链形 | **17/17** | 全部 `[ip, ngap]`（两层） |
| 用例外层键 = `{expect,id,proto,spec_json,summary}` | **15** | — |
| 用例外层键 += `strategy_fc` | **2** | `ngap_flat_static_port`（flows=2）/ `ngap_port_dyn`（flows=2） |
| 负例 `expect` 键 = `{expect_error, error_contains, notes}` | **5/5** | 含 `notes`（非严格两键，G-NGAP-10） |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 本协议**从未用过顶层地址**；17/17 已住 `layers[0].ip.{src,dst}` |
| `src_port` | **0** | 已住 `layers[1].ngap.src_port`（16/17 显式写 12345；`ngap_default_port` 故意缺席验缺省面） |
| `dst_port` | **0** | 已住 `layers[1].ngap.dst_port`（16/17 显式写 38412） |
| `count` | **0** | 走 `strategy_fc`（2 例用 `flows`） |
| 顶层 `ngap` 子映射 | **1** | `ngap_flat_presence`——**判死负例的注入键，非残留**（§12-P2 ①） |
| `strategy_fc` / `flow_control` | **2** | `ngap_flat_static_port`（拒）/ `ngap_port_dyn`（2 流） |
| `group_id` | **1** | `ngap_port_dyn`（单 worker FIFO 保序） |

**结论**：**本协议存量 17 例中，非负例顶层键 = 0**（15 例顶层仅 `{layers}`；1 例 `ngap_port_dyn` 顶层 `{layers, group_id}`，`group_id` 为框架白名单键；第 17 例的顶层 `ngap` 键是**判死负例的故障注入本身**，presence 门今日真绿）——收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测）。**本协议无 §1 迁移工作量**。

目标形状样例见 §2。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"ngap":{}}` **今日会被拒**（`CheckProtoFlat` 有 ngap 分支，`strategy_convert.go:8954`，空 map 也死）→ **#2 `ngap_flat_presence` 今日真绿**（**非假通过**）。✓
- ② 白名单外游离键判死：**通用门存在**（`CheckProtoFlat` 的 `src_ip/dst_ip/src_port/dst_port/count` 五键检查 + presence 分支）；但**任意未知键**（如 `{layers:[…], bogus:1}`）今日仍**不判死**（G-NGAP-11，框架级问题，非 ngap 特有）。
- ③ 5 负例每条带锚词（已齐，§7）。
- ④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

**会话表**：`s1` **单 SCTP 关联基线**（#1–#12 除 #15，各自四元组，握手 4 → NGSetup 对 → 可选过程 → 拆链 3）/ `s2` **多流**（#15，`flows=2`，两条**独立** SCTP 关联，各自完整 9 帧剧本；实测流 1 = 帧 1–9 / 流 2 = 帧 10–18，端口池 `20000`→`20001`、IP `10.0.1.1`→`10.0.1.2`）。**无 `sessions[]` 形态**（registry 无该键，§12.12）。

**事务序列**：`t1` SCTP 关联建立（INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK）/ `t2` NG Setup（请求/响应对，proc 21）/ `t3` UE 相关过程（IUE 单发 proc 15 up / DL NAS 单发 proc 4 down / UL NAS 单发 proc 46 up / PDU-Sess 对 proc 29 / UERelease 对 proc 41）/ `t4` 关联拆除（SHUTDOWN/SHUTDOWN-ACK/SHUTDOWN-COMPLETE）。每事务四件事（前置/触发/成功/失败）：**前置 = 前序阶段完成（引擎不校验，剧本硬序）**；**触发 = 配置开关**；**成功 = 对应帧产出**；**失败 = 配置校验拒绝（§7）或任务级失败——协议层无"过程失败"概念**（无 `unsuccessfulOutcome` 实现，§10.4）。

**关联关系**：**无派生流**（诚实声明：单条 SCTP 关联承载全部 NGAP 信令，无 `driven_by`，无副连接——与 FTP 控制+数据、SIP 信令+媒体不同）。**UE 上下文关联** = `RAN-UE-NGAP-ID` + `AMF-UE-NGAP-ID` 双标识**静态回显**（§5 诚实声明：形式正确、引擎不校验配对，G-NGAP-5）。

**插入位置**：**raw-IP 自驱终结层**（`[ip, ngap]`，链上无 tcp/udp 中间层；ngap 层自行组装完整以太帧，§2 方向纪律）。

**时间线**：帧内严格顺序（Eth→IP→SCTP→chunk→PDU→IE）；阶段顺序**硬编码**（握手 → NGSetup → IUE → DL → UL → PDU-Sess → UERelease → 拆链，与配置书写顺序**无关**，§5）；多流**整块回放**（流 1 全 9 帧后流 2，`group_id` 固定值保 FIFO 序）；无交错（`concurrent` 未启用）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组端口 2 键全开**（allowlist `layer_dyn.go:57` 实测：`"ngap": {"src_port": true, "dst_port": true}`；`ip` 层 `src`/`dst` 全开在 `:15`）。逐流解析落 spec 端口：`layer_dyn.go:834-846`（`ld.NGAP.SrcPort`/`DstPort` → `ResolvePortValue(…, i)` → `spec.SrcPort/DstPort`，值非 0 才覆盖）。**#15 实测**：流 1（i=0）`20000`、流 2（i=1）`20001` ✓。

**业务字段 12 项全关**（allowlist 无 `ngap` 业务键，`layer_dyn.go:54-57` 注释明写"业务 12 键全关（结构选择器/联结身份/载荷，逐流变破坏 gNB↔AMF 联结语义）"；对象即拒 `does not support dynamic`）：

| # | 业务键 | 开/关 | 理由 |
|---:|---|---|---|
| 1 | `global_ran_node_id` | **关** | 对象型；gNB 联结身份，逐流变等于换基站，破坏关联语义 |
| 2 | `supported_ta_list` | **关** | 列表型；基站覆盖范围身份 |
| 3 | `default_paging_drx` | **关** | 标量枚举；关联级参数（且 registry 已限 0–3） |
| 4 | `amf_name` | **关** | 字符串；AMF 身份 |
| 5 | `ran_ue_ngap_id` | **关** | uint32；UE 上下文标识（逐流变需配 `amf_ue_ngap_id` 同步，引擎无此联动） |
| 6 | `amf_ue_ngap_id` | **关** | 同上 |
| 7 | `initial_ue_message` | **关** | 布尔开关（结构选择器） |
| 8 | `initial_nas` | **关** | 字符串→字节；载荷内容（可动态但无轮转需求，A′ 候选） |
| 9 | `downlink_nas` | **关** | 同上 |
| 10 | `uplink_nas` | **关** | 同上 |
| 11 | `pdu_session_setup` | **关** | 对象型；会话参数 |
| 12 | `ue_context_release` | **关** | 布尔开关 |

**序号算法实读**：`parseLayerDyn`（`layer_dyn.go:78`）/ `ResolvePortValue`（端口池）/ 保底自增 `12345+i`（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go:14` 头部 `layerDynAllowlist`）——**`ngap` 只有端口 2 键**（`grep` 实测），层内任何**业务对象值** → `does not support dynamic`。

**动态用例覆盖**：`ngap_port_dyn`（#15）覆盖 **inc 逐流端口池 + 逐流 IP**（`ip.src` inc + `ngap.src_port` inc + `ngap.dst_port` fixed 对象）两类。**未覆盖**：`rand` 可复现 / `list` 轮转 / `pattern` 替换 / inc 回绕 / 静态复制被拒（后者由 #3 覆盖，但走的是 schema 门非动态面）→ G-NGAP-12。

## 13. P3 对接清单（T-NGAP 输入；正文落 testcase 文件）

17 ID（12 正 + 5 负）+ 包数/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。**A′ 候选 13 例**（按缺口）：`ngap_neg_bad_ip`（IP 不可解析）/ `ngap_neg_dst_v6`（仅 dst v6）/ `ngap_neg_port_range`（端口 65535）/ `ngap_neg_plmn_mcc`·`ngap_neg_plmn_mnc`（GlobalRANNodeID PLMN 越界）/ `ngap_neg_ta_plmn`（TA PLMN 越界）/ `ngap_neg_session_id`（PDUSessionID 256）/ `ngap_neg_ul_nas_len`·`ngap_neg_dl_nas_len`（另两条 NAS 超长）/ `ngap_default_nas`（`initial_ue_message` 无 `initial_nas` → 自动注册请求）/ `ngap_amf_name_long`（变长 AMF 名）/ `ngap_amf_name_empty`（空名回退）/ `ngap_abort_rst`（G-NGAP-9）/ `ngap_plmn_3digit_mnc`（3 位 MNC 分支）/ `ngap_ie_oversize`（IE value ≥128 触发截断，G-NGAP-2）。**M-1 修复后须重钉**：`ngap.procedureCode` 之外的 criticality 断言（若 A′ 收编 `ngap.criticality` 字段，须按修复后的 `0x40/0x80` 口径钉）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| **G-NGAP-1** | **13 条 `Validate` 拒绝分支未入例**（§7 表 1/2/4/5/6/7/8/9/10/11/13/15/16）——含 IP 不可解析、DstIP v6、端口上界、三类 PLMN 越界（GlobalRANNodeID + SupportedTAList）、PDUSessionID 上界、UplinkNAS/DownlinkNAS 超长。其中**分支 13（`DefaultPagingDRX`）层内不可达**（registry 已限 `Max:3`，越界在 `ValidateLayers` 即被拦） | A′ 补例（13 条）；**分支 13 判定为"层内不可达"**，补例只能走扁平路径或明确登记为死分支 |
| **G-NGAP-2** | **`buildIE` 单字节长度截断**：`byte(len(value))`（`ngap.go:565`）→ IE value ≥128 字节时**静默写出错误的长度**（截断为 `len & 0xFF`），无拒绝、无告警。今日最大 IE value = 50 字节（`ngap_ta_drx`）**未触界**。**另**：`encodeAMFUENGAPID`（`ngap.go:618-622`）用 `uint16(id)` **静默截断** AMF-UE-NGAP-ID（>65535 的值被截断）——**该截断今日无任何断言观察到**（#11 给了 424242 但 InitialUEMessage 不含该 IE） | A′ 补例 `ngap_ie_oversize`（大 TA 列表触发 value ≥128）+ 裁定 AMF-UE-NGAP-ID 应改 4B 还是显式拒绝 |
| **G-NGAP-3** | **GlobalRANNodeID PLMN 回退条件过窄**：`ngap.go:711` 判 `if g.PLMNMCC != 0 \|\| g.PLMNMNC != 0`——**只给 MCC 不给 MNC**（如 `{plmn_mcc:460}`）时**两者都被采用**（MNC 取 0 → PLMN 编成 MCC=460/MNC=000），**不触发缺省回退**，产生一个非法的 MNC=0 PLMN。而 `Validate` 允许 MNC=0（`[0,999]` 含 0） | A′ 补例 + 裁定：PLMN 的 0 是"未设置"还是"合法 0"（涉及 validate 范围与回退条件的一致性） |
| **G-NGAP-4** | **过程覆盖面窄**：实现仅 6 个过程码（4/15/21/29/41/46），TS 38.413 §9.2 定义 **60+ 过程**；**InitialContextSetup / Paging / Handover 家族 / PathSwitch / NGReset / ErrorIndication / OverloadStart 等全部未实现**（任务书点名要求写清的项）。**`PDUUnsuccessfulOutcome=2` 常量从未使用**（无 `unsuccessfulOutcome` 过程，无 `buildNGAPUnsuccessful` 函数）→ 死常量。**TS 38.413 条款号未逐条核对**（本车道无规范原文） | **明确不解决**（生成器范围）+ 文档阶段记为待实现边界；条款号核对方法：取 TS 38.413 §9.2 过程码表与本实现 6 常量逐条对照 |
| **G-NGAP-5** | **UE ID 配对为静态回显、引擎不校验**：`RANUENGAPID`/`AMFUENGAPID` 被原样写进所有相关消息，无配对检查代码。形式正确（ID 出现在该出现的消息里，§5 表实测），**但正确性完全由配置决定**。**#11 只断言"显式 UE ID 进 IUE PDU"，不断言跨消息配对一致性** | A′ 补例（多过程串接时断言同一 UE ID 在各消息中一致）+ 裁定是否需要引擎级配对校验 |
| **G-NGAP-6** | **非确定性字段无种子**：`randNonZeroTag()`（vtag）/ `rand.Uint32()`（TSN）/ `uint16(rand.Uint32())`（IP ID）**均无种子**（`ngap.go:270/278-279/512-519`），同一配置两次运行这三类字节不同。**存量断言零覆盖**（故不 flaky），但**任何未来新增断言不得钉这三者** | 登记为**纪律约束**（写入 §6 确定性边界）；若需可复现，A′ 立项加种子 |
| **G-NGAP-7** | **SHUTDOWN 的 Cumulative TSN Ack 取值语义可疑**：`ngap.go:406-409` 写 `serverTSN-1`；当**服务端一帧未发**时 `serverTSN` 仍是**随机初值**（非 0），减 1 后是随机数，语义无意义。RFC 4960 §9.2 要求报告"本端已收到的最高 TSN" | A′ 裁定 + 补例（`ngap_sctp_setup_basic` 无服务端 DATA 帧，正是该场景） |
| **G-NGAP-8** | **3 位 MNC 分支无用例**：`encodePLMN`（`ngap.go:590-597`）有 `mnc >= 100` 的 3 位 MNC 分支（`plmn[1] = (mnc3<<4) \| mcc3`），今日两例 MNC 均 <100（1 与 5）→ 该分支**从未执行** | A′ 补例（MNC=101 等 3 位数） |
| **G-NGAP-9** | **RST/异常终态零覆盖**：T3 列 9 格全为 A′（§10.2）——ngap 层是 raw-IP 自驱，**无 tcp 层的 RST 能力**，异常中断只能靠截断 pcap 或 SCTP ABORT 块（**ABORT chunk 未实现**，`ChunkABORT` 常量不存在） | A′ 裁定：补 ABORT 块实现 + 补例，或明确"异常终态不适用" |
| **G-NGAP-10** | **5 条负例的 `expect` 含 `notes` 键**（`{expect_error, error_contains, notes}`，非严格两键口径）——与 moxa 范式不同 | P4 收窄：删 `notes`（或统一范式） |
| **G-NGAP-11** | **顶层未知键无通用门**：`{layers:[…], bogus:1}` 今日**不判死**（`CheckProtoFlat` 只查五键 + 各协议 presence 白名单）→ 建了 presence 类负例会真绿 = 假通过，**不建** | **框架级**（等 unknown-key 白名单；与 moxa G-MOXA-2 / opcua G-OPCUA-1 同款，禁加单协议黑名单分支） |
| **G-NGAP-12** | **动态字段覆盖不全**：`ngap_port_dyn` 只覆盖 `inc`（端口池 + 逐流 IP）；`rand` 可复现 / `list` 轮转 / `pattern` 替换 / inc 回绕**四类无例**（CORE_MEMORY §12 要求五类齐） | A′ 补例 4 条 |
| **G-NGAP-13** | **`amf_name` 变长与空回退无例**：两例 AMF 名均 11 字节（**等长**，故 PDU 形状同构）；变长分支与 `amf_name:""` 回退缺省（`ngap.go:248-250`）**均无用例** | A′ 补例（§10.3 行 9/10） |
| **G-NGAP-14** | **`initial_nas` 缺省（自动注册请求）无例**：`buildDefaultNASPDU`（`ngap.go:868-895`，**40 字节** 5GS Registration Request）已实现，但 3 个 IUE 用例全部显式给 `initial_nas` → **自动生成分支从未执行** | A′ 补例（`initial_ue_message=true` 且不给 `initial_nas`） |

**M-1（confirmed finding，非"缺口"而是**实现缺陷**）**：NGAP-PDU 的 `choice` 与 `criticality` 按整字节写（`0/1/2`），而 tshark 3.6.14 按 **aligned PER** 读**字节高 2 位**（`0x00/0x20/0x40` 与 `0x00/0x40/0x80`）→ **每个 successfulOutcome 被读成 initiatingMessage，每个 ignore 被读成 reject**（§3.2 变异探针实证）。**存量 151 条断言零覆盖该面**，故 17 例全绿而不自知。**修复方向**（本车道不改代码）：`buildNGAPInitiating`/`buildNGAPSuccess` 的 choice 参数改为 `0x00/0x20`（或统一左移 6 位）、criticality 改为左移 6 位；**修复后帧长不变**（同字节数），§9 包数公式与全部 frames 断言不受影响。**归属：代码阶段（P4）**。

## 15. 修订记录

- v1.0.0（2026-09-29）：批次二文档轨 #116 **首次成文**（本协议此前无任何设计/用例文档，§0）。as-built 逆向定稿：存量 17 例（12 正 + 5 负）逐条机读对账；**148 条 field 断言 + 3 条 frame 断言 + 12 条包数断言全部对磁盘 pcap 复算，零不符**（§9）；帧长公式 `max(60, 46+4*ceil(chunk_len/4))` 对 15 个 pcap **全帧零例外**（§2）；SCTP CRC32c **34 帧独立复算全 OK**（§3.1）；PLMN nibble 布局逐位复算（§3.7）；**M-1 confirmed finding**（PDU choice/criticality 位域与 aligned-PER 不一致，变异探针 256 值扫描钉边界，§3.2）；八项矩阵 + 子表①②③（27 格 = 覆 17 + A′ 9 + 不适用 1；24 行 = 覆 16 + 立项 8；19 行 = 覆 10 + 不适用 9）；门1 十四行齐 + §12.1/12-P2/12.3/12.12 四展开；缺口 **G-NGAP-1…G-NGAP-14** + M-1；覆盖反查门建议断言行 10 条（testcase §9）。**未跑引擎**（取证边界见 §0）。自审见 `/tmp/pipe/doc-lanes/ngap.md`。

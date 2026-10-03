# #116 ngap（NGAP · 5G 核心网 N2 接口信令）测试用例契约

> 版本：v1.0.0（as-built 文档轨）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/116-ngap-design.md` v1.0.0（D-NGAP-1）
> 旧基线：**无**（本协议此前无任何用例文档，设计 §0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/ngap.json`（**17 例 = 12 正 + 5 负**；ID/顺序/包数/断言本版逐条机读对账，§8）
> 白话一句：**十七条检查：十二条看正常跑（握手、基站自报家门、手机注册、上下行透传、会话建立、上下文释放、全流程串接、多流），五条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **17 个唯一语义 ID：12 正 + 5 负**（负例 N-1…N-5，分 A 类建链期 2 条 + B 类任务期 3 条）。派生规则：设计 §3 每个线格式条款、§5 每个阶段/自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：

| 检查项 | 结果 |
|---|---|
| 例数 / ID 唯一 | **17 / ✓** |
| 层链形 | **17/17 = `[ip, ngap]`**（两层，raw-IP 自驱终层） |
| `spec_json` 顶层键 = `{layers}`（唯一键） | **15/17** |
| `spec_json` 顶层键 = `{layers, ngap}` | **1**（`ngap_flat_presence`——**判死负例的故障注入**，非残留） |
| `spec_json` 顶层键 = `{layers, group_id}` | **1**（`ngap_port_dyn`，`group_id` 在框架白名单内，非游离键） |
| **非负例顶层键 = 0** | **✓**（16 个非负例中：15 例顶层仅 `{layers}`，1 例顶层 `{layers, group_id}`（白名单键）；第 17 例是负例，其顶层 `ngap` 为故障注入本身） |
| 用例外层键 | `{expect,id,proto,spec_json,summary}` ×15 + 加 `strategy_fc` ×2 |
| 正例包数断言 | `min_packets` ×11 + `packet_count` ×1（`ngap_port_dyn`） |
| 负例 `expect` 键集合 | `{expect_error, error_contains, notes}` ×5（**含 `notes`**，非严格两键，G-NGAP-10） |
| 负例锚词命中代码字面值 | ✓ 5/5（§4 表） |

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`sctp.srcport/dstport`、`sctp.chunk_type`、`sctp.data_payload_proto_id`、`ngap.procedureCode`、frames offset 62）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**——本版 17 例全部只用两路径均可观察的字段。

**TSHARK 基线（实测，tshark 3.6.14）**：`tshark -G fields` 中 `ngap.*` **1119 字段**；15 个 pcap **全部被解码**（`_ws.col.Protocol = NGAP` 于 DATA 帧），**零 `_ws.malformed`**（15 个文件逐文件实测 malformed=0），**零 expert 告警**。

可用字段通道（实测）：① `ngap.procedureCode`（**十进制串**，实测可断言）；② `ngap.criticality`（十进制串，**但值受 M-1 影响，见下**）；③ `ngap.NGAP_PDU`（十进制串，**受 M-1 影响**）；④ `sctp.chunk_type` / `sctp.srcport` / `sctp.dstport` / `sctp.data_payload_proto_id` / `sctp.verification_tag` / `sctp.data_tsn` / `sctp.data_sid` / `sctp.data_ssn`；⑤ frames 原始 hex（offset 62）。

**M-1 对字段断言的影响（必读，设计 §3.2）**：实现把 PDU 的 `choice` 与 `criticality` 按**整字节**写（`0/1/2`），而 tshark 按 **aligned PER** 读**字节高 2 位**。后果：**`ngap.NGAP_PDU` 恒解成 0（initiatingMessage），`ngap.criticality` 恒解成 0（reject）**——即每个 successfulOutcome 被读成 initiatingMessage、每个 ignore 被读成 reject。**今日 17 例零条断言这两个字段**（机读实测），故套件全绿而不自知。**任何 A′ 新增例若断言这两字段，必须按修复后的 PER 口径（`0x20`/`0x40`/`0x80`）钉，不得按今日字节钉。**

**断言基线（机读实测）**：**148 条 `fields` 断言 + 3 条 `frames` 断言 + 12 条包数断言**，全部对磁盘 pcap（`/tmp/mcp-pcaps/ngap/`）逐条复算，**零不符**。字段分布：`sctp.chunk_type` **77** / `ngap.procedureCode` **37** / `sctp.data_payload_proto_id` **14** / `sctp.dstport` **11** / `sctp.srcport` **9**。

**不可断言字段（纪律，设计 §6/G-NGAP-6）**：`sctp.verification_tag`、`sctp.data_tsn`、`ip.id` **三者无种子随机**（`rand` 直调，`ngap.go:270/278-279/512-519`），同一配置两次运行不同。**今日零条断言**（机读实测），**未来新增断言亦不得钉这三者**。

**包数约定（实测公式，设计 §9）**：

```
帧数 = 4（SCTP 握手）+ 2（NGSetup 对）+ 3（SCTP 拆链）+ 可选帧数
可选帧数 = 1×[initial_ue_message] + 1×[len(downlink_nas)>0] + 1×[len(uplink_nas)>0]
         + 2×[pdu_session_setup != nil] + 2×[ue_context_release]
```

负例无包数断言（A 类不产 pcap；B 类 pcap 实测 **0 帧**）。

**保活/重试/RST 口径**：协议层**无 keepalive 概念**（NGAP 无心跳消息；SCTP HEARTBEAT **未实现**）→ 判"不适用"（§6.1③）；**无重试/重连**（无状态机）；**RST 不适用**——ngap 是 raw-IP 自驱层，**无 tcp 层的 RST 能力**，且 SCTP ABORT 块未实现 → 异常终态 A′ 立项（G-NGAP-9）。正例恒以 **SCTP 3 步优雅拆链**结束。

## 2. 原子用例索引（17 ID = 12 正 + 5 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | 包数断言（实测） | 断言数 |
|---:|---|---|---|---|---:|
| 1 | `ngap_sctp_setup_basic` | 正 | §3.6/§3.3：SCTP 4 步握手 + NGSetup 对 + 3 步拆链（最小 9 帧） | `min_packets: 9`（实测 9 ✓） | 13 f + 2 fr |
| 2 | `ngap_flat_presence` | 负 A | §7 N-1：顶层 `ngap` presence 判死（空 map 也死） | —（不产 pcap） | 0 |
| 3 | `ngap_flat_static_port` | 负 A | §7 N-2：ngap 层静态端口 + `flows=2` 拒 | —（不产 pcap） | 0 |
| 4 | `ngap_initial_ue` | 正 | §3.5：InitialUEMessage（proc 15, up） | `min_packets: 10`（实测 10 ✓） | 14 f |
| 5 | `ngap_dl_nas` | 正 | §3.5/§5：DownlinkNASTransport（proc 4, **down**） | `min_packets: 10`（实测 10 ✓） | 14 f |
| 6 | `ngap_ul_nas` | 正 | §3.5：UplinkNASTransport（proc 46, up） | `min_packets: 10`（实测 10 ✓） | 14 f |
| 7 | `ngap_pdu_session` | 正 | §3.5/§5：PDUSessionSetup 请求+响应（proc 29 对） | `min_packets: 11`（实测 11 ✓） | 15 f |
| 8 | `ngap_ue_release` | 正 | §3.5/§5：UEContextRelease Command+Complete（proc 41 对） | `min_packets: 11`（实测 11 ✓） | 15 f |
| 9 | `ngap_all_procedures` | 正 | §5：全可选过程串接（16 帧） | `min_packets: 16`（实测 16 ✓） | 20 f |
| 10 | `ngap_ta_drx` | 正 | §3.5：SupportedTAList×2 + DRX=2 + GlobalRANNodeID 自定义 | `min_packets: 9`（实测 9 ✓） | 9 f |
| 11 | `ngap_ue_ids` | 正 | §3.5/§5：显式 UE ID（RAN-UE=42）进 IUE PDU | `min_packets: 10`（实测 10 ✓） | 10 f |
| 12 | `ngap_amf_name` | 正 | §3.5：自定义 AMF 名 `AMF-EDGE-07`（frames 钉 hex） | `min_packets: 9`（实测 9 ✓） | 9 f + 1 fr |
| 13 | `ngap_neg_v6` | 负 B | §7 N-3：IPv6 拒 | —（实测 0 帧 ✓） | 0 |
| 14 | `ngap_default_port` | 正 | §2/§3.5：dst 缺省 38412 + src 保底 12345 | `min_packets: 9`（实测 9 ✓） | 11 f |
| 15 | `ngap_port_dyn` | 正 | §12.12：`ngap.src_port` 动态 inc + `flows=2`（逐流端口池） | **`packet_count: 18`**（实测 18 ✓） | 4 f |
| 16 | `ngap_neg_sst` | 负 B | §7 N-4：SST 越界（300）拒 | —（实测 0 帧 ✓） | 0 |
| 17 | `ngap_neg_nas_len` | 负 B | §7 N-5：NAS 超长（4097 = 上界+1）拒 | —（实测 0 帧 ✓） | 0 |

**包数公式校验（12/12 正例）**：#1/#10/#12/#14 可选 0 → 9 ✓；#4/#5/#6/#11 可选 1 → 10 ✓；#7/#8 可选 2 → 11 ✓；#9 可选 7 → 16 ✓；#15 单流 9 × 2 流 = 18 ✓。**与实测 pcap 帧数逐例一致**。

**T-编号对照**：`T-NGAP-2…T-NGAP-17` 见各例 `summary`（#1 无 T 号，为存量等价迁移的冒烟例）。**序号以 cases JSON 顺序为权威。**

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含包数断言 + `fields`（部分含 `frames`）；帧位由 §1 公式与实测 pcap 双向确认。**全部断言已逐条对磁盘 pcap 复算通过。**

**共性断言（12 正例中的 11 例，#15 除外）**：

- 帧 1：`sctp.srcport=12345`、`sctp.dstport=38412`、`sctp.chunk_type=1`（INIT，up）
- 帧 2：`sctp.chunk_type=2`（INIT-ACK，down）
- 帧 3：`sctp.chunk_type=10`（COOKIE-ECHO，up）
- 帧 4：`sctp.chunk_type=11`（COOKIE-ACK，down）
- 帧 5：`sctp.data_payload_proto_id=60` + `ngap.procedureCode=21`（NGSetupRequest）
- 帧 6：`ngap.procedureCode=21` + `sctp.data_payload_proto_id=60`（NGSetupResponse）
- 末 3 帧：`sctp.chunk_type=7` / `8` / `14`（SHUTDOWN / SHUTDOWN-ACK / SHUTDOWN-COMPLETE）

> **PPID=60 是 NGAP 的承载标识**（TS 38.412），帧 5/6 双断言（`data_payload_proto_id` + `procedureCode`）正是"同一帧既是 NGAP 又是 DATA 块"的证据。
> **帧 5/6 的断言顺序不同**（#1 为 `PPID→proc`，#6 为 `proc→PPID`）——JSON 数组顺序即执行顺序，`tshark -T fields` 按 `-e` 顺序输出，故两条断言分别对应两次独立取值，非笔误。

### 3.1 `ngap_sctp_setup_basic`（9 帧）

`layers=[{ip:{src:"10.0.0.1",dst:"20.0.0.1"}},{ngap:{src_port:12345,dst_port:38412}}]`（业务面全空，只验最小剧本）。

- 共性 13 条断言（§3 开头）。
- **frames（2 条，offset 62）**：
  - 帧 5 `00 15 00 00 03 00 48 00 0b 00 08 08 60 f4 10 04 00 00`——choice=0(init)、proc=21、crit=0(reject)、IEcount=3、IE1 `id=72 crit=0 len=11`、value 头 `08 60 f4 10 04 00 00`（GlobalRANNodeID 的 `choice=00` + 内层长度 `08` + PLMN `60 f4 10` + BIT STRING 长度 `04` + gNB-ID 前 2 字节）。
  - 帧 6 `01 15 01 00 01 00 01 00 0b 41 4d 46 2d 54 45 53 54 2d 30 31`——choice=1(success)、proc=21、crit=1(ignore)、IEcount=1、IE `id=1 crit=0 len=11`、value `AMF-TEST-01`。
- **该例是全部 IE 面的基线**：其余正例的帧 5/6 与该例**逐字节同构**（除 #10 帧 5 的 TA 列表、#12 帧 6 的 AMF 名）。

### 3.2 `ngap_initial_ue`（10 帧）

`ngap={src_port:12345,dst_port:38412,initial_ue_message:true,initial_nas:"hello"}`。

- 帧 7：`ngap.procedureCode=15`（InitialUEMessage，**up**）。
- **实测 PDU（54B）**：choice=0、proc=15、crit=1、IEcount=**5**：`(85,reject,4)=00000001` / `(38,reject,7)=0005 68656c6c6f` / `(121,reject,16)` / `(90,ignore,1)=04` / `(112,ignore,1)=00`。
- **NAS-PDU 证据**：IE id=38 的 value = `00 05 68 65 6c 6c 6f`——2 字节大端长度 `00 05` + `hello` 5 字节（设计 §3.5）。**今日无 field 断言钉该字节**（A′ 候选，G-NGAP-1 面）。

### 3.3 `ngap_dl_nas`（10 帧）

`ngap={...,downlink_nas:"downbytes"}`。

- 帧 7：`ngap.procedureCode=4`（DownlinkNASTransport，**down**——AMF 发起方向）。
- **实测 PDU（34B）**：choice=0、proc=4、crit=1、IEcount=3：`(10,reject,2)=0001` / `(85,reject,4)=00000001` / `(38,reject,11)=0009 646f776e6279746573`。
- **方向证据**：该帧的 src/dst IP 与端口已由 `emitSCTP` 自行换向（`20.0.0.1:38412 → 10.0.0.1:12345`，实测 `sctp.srcport=38412` 于该帧；JSON 未断言此帧端口，只断 `chunk_type` 序列——**A′ 可补端口方向断言**）。
- **UE ID 对证据**：`(10,2B)=1` + `(85,4B)=1`（AMF-UE-NGAP-ID + RAN-UE-NGAP-ID 配对出现，设计 §5 表）。

### 3.4 `ngap_ul_nas`（10 帧）

`ngap={...,uplink_nas:"upbytes"}`。

- 帧 7：`ngap.procedureCode=46`（UplinkNASTransport，**up**）。
- **实测 PDU（32B）**：IEcount=3：`(10,2)=0001` / `(85,4)=00000001` / `(38,9)=0007 75706279746573`。

### 3.5 `ngap_pdu_session`（11 帧）

`ngap={...,pdu_session_setup:{pdu_session_id:1,sst:1,sd:1}}`。

- 帧 7：`ngap.procedureCode=29`（**Request**，choice=0、crit=reject、**down**）；帧 8：`ngap.procedureCode=29`（**Response**，choice=1、crit=ignore、**up**）。
- **实测两帧 PDU 各 38B**，IE 序列：`(10,reject,2)=0001` / `(85,reject,4)=00000001` / `(77|78,reject,15)=01 01 000b 0004 01000001 01 00010203`。
- **请求/响应唯一差异 = IE id（77 vs 78）**，list 内容**逐字节相同**（设计 §3.5）——这是"一对过程"的直接证据。**今日无断言钉该差异**（A′ 候选）。

### 3.6 `ngap_ue_release`（11 帧）

`ngap={...,ue_context_release:true}`。

- 帧 7：`ngap.procedureCode=41`（**Command**，choice=0、crit=reject、**down**）；帧 8：`ngap.procedureCode=41`（**Complete**，choice=1、crit=ignore、**up**）。
- **实测两帧 PDU 各 19B**，IEcount=2：`(10,reject,2)=0001` / `(85,reject,4)=00000001`——**无 NAS-PDU**（释放命令不带载荷）。

### 3.7 `ngap_all_procedures`（16 帧）

`ngap={...,initial_ue_message:true,initial_nas:"rr",downlink_nas:"dl",uplink_nas:"ul",pdu_session_setup:{...},ue_context_release:true}`。

- 帧 7/8/9/10/11/12/13：`ngap.procedureCode` = **15 / 4 / 46 / 29 / 29 / 41 / 41**。
- **阶段顺序证据（设计 §5）**：IUE(15) → DL(4) → UL(46) → PDU-Sess 对(29/29) → UERel 对(41/41)，**与配置书写顺序无关**（JSON 中键序为 initial/dl/ul/pdu/ue，实测帧序一致；设计 §5 已声明剧本硬序）。
- **包数证据**：可选帧 1+1+1+2+2=7 → 9+7=16 ✓。
- **实测 PDU 长**：51 / 27 / 27 / 38 / 38 / 19 / 19（`rr`=2B、`dl`=2B、`ul`=2B）。

### 3.8 `ngap_ta_drx`（9 帧）

`ngap={...,supported_ta_list:[{plmn_mcc:460,plmn_mnc:1,tacs:[100,200]},{plmn_mcc:411,plmn_mnc:5,tacs:[300]}],default_paging_drx:2,global_ran_node_id:{plmn_mcc:460,plmn_mnc:1,gnb_id:4097}}`。

- 帧 5/6：`ngap.procedureCode=21`。
- **实测帧 5 PDU = 55B**（较基线 41B 多 14B，全在 SupportedTAList）：`(72,reject,11)=00 08 08 60 f4 10 04 00 00 10 01`（**gNB-ID = 4097 = `00 00 10 01`**，基线为 1）/ `(83,reject,26)=02 60f410 01 60f410 02 000064 0000c8 11f450 01 11f450 01 00012c`（2 TA；TA1 PLMN 460/1、TAC `100`=000064 与 `200`=0000c8；TA2 PLMN 411/5=`11f450`、TAC `300`=00012c）/ `(21,ignore,1)=02`（DRX=2）。
- **该例覆盖 TA 列表多值 + 自定义 PLMN + 自定义 gNB-ID + 非缺省 DRX 四面**（设计 §3.5/§3.7）。
- **诚实声明**：DRX=2 的**线值**（`02`）今日**无 field 断言**（A′ 候选）；`ngap.criticality` 若收编须按 M-1 修复口径。

### 3.9 `ngap_ue_ids`（10 帧）

`ngap={...,ran_ue_ngap_id:42,amf_ue_ngap_id:424242,initial_ue_message:true,initial_nas:"nas"}`。

- 帧 7：`ngap.procedureCode=15`。
- **实测帧 7 PDU = 52B**：`(85,reject,4)= 00 00 00 2a`（**RAN-UE-NGAP-ID = 42 = 0x2a** ✓）；**无 IE id=10**（InitialUEMessage 不含 AMF-UE-NGAP-ID，符合 spec，设计 §5 表）。
- **诚实声明（G-NGAP-2/G-NGAP-5）**：`amf_ue_ngap_id=424242` **在本例中不出现在任何帧**（IUE 不含该 IE）——故 `encodeAMFUENGAPID` 的 `uint16()` 截断行为（424242 → `0x7932`）**未被本例观察**。**本例只断言"显式 UE ID 进 IUE PDU"（通过 `ngap.procedureCode=15` 定位帧位），不断言 IE 字节、不断言跨消息配对一致性。**

### 3.10 `ngap_amf_name`（9 帧）

`ngap={...,amf_name:"AMF-EDGE-07"}`。

- 帧 5/6：`ngap.procedureCode=21`。
- **frames（1 条，offset 62）**：帧 6 `01 15 01 00 01 00 01 00 0b 41 4d 46 2d 45 44 47 45 2d 30 37`——与 `ngap_sctp_setup_basic` 帧 6 **逐字节同构**，唯一差异在末 11 字节（`AMF-TEST-01` → `AMF-EDGE-07`）。
- **等长声明**：两名均 **11 字节**（`0b`），故 IE 长度字段与 PDU 总长（20B）**不变**——本例正是"**仅字符串面变、形状不变**"的直接证据。**变长 AMF 名今日无例**（G-NGAP-13）。

### 3.11 `ngap_default_port`（9 帧）

`layers=[{ip:{src:"10.0.0.1",dst:"20.0.0.1"}},{ngap:{}}]`（**ngap 层空配置**）。

- **端口断言（11 条中 2 条钉端口面）**：帧 1 `sctp.dstport=38412`（**dst 缺省补齐**，`chain_planner_translate.go:1567`）；帧 2 `sctp.dstport=12345`（down 帧 dst = 对端 src，**src 保底 `12345+i`**，i=0）。
- 帧 5/6 `ngap.procedureCode=21`；末 3 帧 chunk 7/8/14。
- **空配置合法性证据**：`{ngap:{}}` 经 translate 后 `spec.NGAP` **非 nil 但全零值** → legacy `Plan` 走全缺省剧本（NGSetup 对 + 拆链，无可选过程）→ 9 帧。
- **与 #2 的对照**：同一"空 ngap 配置"形状，**住在层内合法**（本例），**住顶层判死**（#2）——这是 §1 门的正反两面证据。

### 3.12 `ngap_port_dyn`（18 帧，唯一 `packet_count` 精确例）

`layers=[{ip:{src:{strategy:"inc",range:["10.0.1.1","10.0.1.2"],step:1},dst:"20.0.0.1"}},{ngap:{src_port:{strategy:"inc",range:[20000,20001],step:1},dst_port:{strategy:"fixed",value:38412}}}], group_id:{strategy:"fixed",value:"ngap-port-dyn"}`，`strategy_fc={type:"flows",value:2}`。

- **断言（4 条，全钉逐流端口池）**：帧 1 `sctp.srcport=20000` + `sctp.dstport=38412`；帧 10 `sctp.srcport=20001` + `sctp.dstport=38412`。
- **精确包数证据**：`packet_count: 18` = 2 流 × 9 帧/流。
- **多流展开证据（实测）**：帧 1–9 = 流 1（`10.0.1.1` / `20000`），帧 10–18 = 流 2（`10.0.1.2` / `20001`）——**整块回放、非交错**（设计 §12.3）。`group_id` 固定值 → 单 worker FIFO 保序（h323/mpls 先例）。
- **对象面证据**：`dst_port` 用 `{strategy:"fixed",value:38412}` **对象形**（而非标量）——证明 allowlist 对 ngap 端口放行对象（`layer_dyn.go:57`），且 fixed 对象逐流取同值（设计 §12.12）。
- **诚实声明**：本例**只断言端口池两帧**，不断言两流的过程码/包数独立正确（A′ 可补流 2 的过程面断言，G-NGAP-12）。

## 4. 负例契约（5 条，A 类 2 + B 类 3）

负例必须在**建链期（schema 门）**或**任务期（planner 校验器）**失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或假成功。锚词与设计 §7 表一一对应、同序。

### 4.1 A 类：建链期拒绝（create-time，无 pcap）

| ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（逐字） | 代码行 |
|---|---|---|---|---|
| `ngap_flat_presence` | `spec_json` 顶层含 `"ngap": {}`（**空 map 也死**） | `top-level ngap sub-config` | `protocol ngap rejects a top-level ngap sub-config (move it into the ngap layer of an [ip,ngap] layers chain)` | `strategy_convert.go:8954-8958` |
| `ngap_flat_static_port` | `layers=[{ip:{}},{ngap:{src_port:12345,dst_port:38412}}]` + `strategy_fc={flows:2}` | `static four-tuple` | `layers pin a static four-tuple but flows > 1: every flow would emit identical addresses/ports (static copy). …` | `schema/semantic.go:285` |

- **#2 的对照价值**：注入形状 `{"layers":[…],"ngap":{}}` 是**判死负例的故障注入本身**（非残留）——presence 门今日**真绿**（`CheckProtoFlat` 有 ngap 分支，设计 §12-P2 ①）。
- **#3 的形状要点**：`ip` 层为**空 map `{}`**（对门无贡献），使"静态四元组"判定**只由 ngap 层端口触发**——最小证明形（h323/mpls 同构先例）。
- **两例均由 Go 单测覆盖**（`ngap_migrate_test.go:30-43`、`schema/ngap_static_port_test.go:12-32`），**不产 pcap**（`ngap/<id>.pcap` 不存在）。

### 4.2 B 类：任务期校验器拒绝（task-time，pcap 实测 0 帧）

| ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（逐字） | 代码行 |
|---|---|---|---|---|
| `ngap_neg_v6` | `layers[0].ip={src:"fd00::1",dst:"fd00::2"}` | `only IPv4 is supported` | `ngap: SrcIP fd00::1 is IPv6; only IPv4 is supported` | `ngap.go:149` |
| `ngap_neg_sst` | `pdu_session_setup={pdu_session_id:1,sst:300,sd:1}` | `SST 300 out of range [0,255]` | `ngap: PDUSessionSetup.SST 300 out of range [0,255]` | `ngap.go:195` |
| `ngap_neg_nas_len` | `initial_nas` = 4097 个 `x`（**上界 4096 + 1**） | `InitialNAS too long` | `ngap: InitialNAS too long (4097 bytes, max 4096)` | `ngap.go:204` |

- **实测三例 pcap 均 0 帧**：`ngap_neg_v6.neg.pcap` / `ngap_neg_sst.neg.pcap` / `ngap_neg_nas_len.neg.pcap` 三文件**各 24 字节**（仅 pcap 全局头），`capinfos -c` = **0** ✓。
- **锚词口径**：`error_contains` 是**子串**判定；三例均命中代码文案（前缀 `ngap: `）。
- **#13 命中 SrcIP 分支**（`ngap.go:147` 早于 `:152`），故实际文案为 `SrcIP fd00::1`；`DstIP` 分支今日**不可达**（除非 Src 为 v4）→ G-NGAP-1 附表。
- **#17 的边界语义**：4097 = `Validate` 上界 4096 **+1**（设计 §8 边界相邻值）。
- **#16 的越界幅度**：SST=300 远超 `[0,255]`（**非紧邻上界**，紧邻上界 256 今日无例 → A′ 候选）。

### 4.3 负例原子性与纯净性

- **单一故障注入**：5 例各只注入一处故障，单次执行不混注。
- **负例纯净性**：5 例 `expect` **只有** `{expect_error, error_contains, notes}`——**无任何 `fields`/`frames`/包数断言**（机读实测），符合"负例执行期 expect 只有 expect_error 与 error_contains"的精神（`notes` 为文档性键，G-NGAP-10）。
- **无假成功**：三例 B 类实测 0 帧，**不存在**"只剩外壳的假成功"。

### 4.4 未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）

`Validate` 共 **16 条**拒绝分支，**仅 3 条入例**（#13/#16/#17），余 **13 条**未覆盖（G-NGAP-1）：

| # | 锚词 | 行 | 备注 |
|---:|---|---:|---|
| 1 | `invalid SrcIP %q` | 138 | A′ |
| 2 | `invalid DstIP %q` | 143 | A′ |
| 4 | `DstIP %s is IPv6; only IPv4 is supported` | 154 | A′（SrcIP 先判，需 Src=v4 才可达） |
| 5 | `SrcPort %d out of range`（`>=65535`） | 159 | A′ |
| 6 | `DstPort %d out of range`（`>=65535`） | 162 | A′ |
| 7 | `GlobalRANNodeID.PLMNMCC %d out of range [0,999]` | 173 | A′ |
| 8 | `GlobalRANNodeID.PLMNMNC %d out of range [0,999]` | 176 | A′ |
| 9 | `SupportedTAList[%d].PLMNMCC %d out of range [0,999]` | 182 | A′ |
| 10 | `SupportedTAList[%d].PLMNMNC %d out of range [0,999]` | 185 | A′ |
| 11 | `PDUSessionSetup.PDUSessionID %d out of range [0,255]` | 192 | A′ |
| 13 | `DefaultPagingDRX %d out of range [0,3]` | 200 | **层内不可达**（registry 已限 `Max:3`，越界在 `ValidateLayers` 即拦） |
| 15 | `UplinkNAS too long (%d bytes, max 4096)` | 207 | A′ |
| 16 | `DownlinkNAS too long (%d bytes, max 4096)` | 210 | A′ |

**未入用例的静默路径（缺陷候选）**：`buildIE` 的 `byte(len(value))` 在 IE value ≥128 字节时**静默截断长度**（`ngap.go:565`）；`encodeAMFUENGAPID` 的 `uint16(id)` **静默截断** >65535 的 UE ID（`ngap.go:620`）→ 均入 G-NGAP-2。

## 5. 覆盖与对账

### 5.1 三源回指行

3GPP TS 38.413 / TS 38.412 + RFC 4960（设计 §10）+ D-NGAP-1（设计 §11）+ tshark 3.6.14 字段表（1119 个 `ngap.*`）与 **15 例实测 pcap**（`/tmp/mcp-pcaps/ngap/`）→ 17 ID（本契约 §2）。第三源"已确认现网行为"当前 = **抓包级已到**（本仓引擎产出的 15 例 pcap 逐帧复算：148 field + 3 frame + 12 包数断言零不符；SCTP CRC32c 34 帧独立复算全 OK），但**真实 AMF/gNB 的线字节未取到、TS 38.413 条款号未逐条核对** → G-NGAP-4（按 §5.5 不写死进实现）。

**17 ID 逐项回指（§9.5 要求）**：#1←设计 §3.6/§3.3；#2←§7 N-1；#3←§7 N-2；#4←§3.5；#5←§3.5/§5；#6←§3.5；#7←§3.5/§5；#8←§3.5/§5；#9←§5；#10←§3.5；#11←§3.5/§5；#12←§3.5；#13←§7 N-3；#14←§2/§3.5；#15←§12.12；#16←§7 N-4；#17←§7 N-5。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **3GPP TS 38.413/38.412 公开语义 + RFC 4960 原文 + 仓库落码反推 + tshark 3.6.14 字段与 pcap 实测**，**非纯规范反推**（TS 38.413 条款号未逐条核对 → G-NGAP-4）。
- **对账两行**：**要求逻辑点总数 = 78**（八项 8 行 + 矩阵 27 格 + 变体 24 行 + 商业映射 19 行 = 8+27+24+19）；**用例覆盖数 = 45**；**不适用 = 12**；**开放立项（A′）= 21**。**45 + 12 + 21 = 78** ✓
  **粒度声明（严格按行/格重数，每点 1 计，不折算）**：
  - §10.1 八项：8 = 覆 **2**（连接模型 / 版本方言）+ 立项 **4**（命令消息表 / 字段表 / 错误处理 / 超时活性）+ 不适用 **2**（状态机 / NAT 被动模式）✓
  - §10.2 矩阵 27 格：覆 **17** + A′ **9** + 不适用 **1** ✓
  - §10.3 变体 24 行：覆 **16** + 立项 **8** ✓
  - §10.4 商业 19 行：覆 **10** + 不适用 **9** ✓
  - **合计 = 45 覆 + 21 A′ + 12 不适用 = 78** ✓
  **G-NGAP-1…G-NGAP-14 与 M-1 不折进 78**（缺口表另计 14 条 + M-1）。**反查全绿 ≠ 覆盖全**（§9.52 原文）。
- **门3 抽查候选**：最复杂用例 = **#9 `ngap_all_procedures`**（16 帧：握手 4 + NGSetup 对 + **7 帧可选过程**（IUE/DL/UL/PDU-Setup 对/UERel 对）+ 拆链 3；交织维度 = 过程(6)×方向(2)×choice(2)×IE 组合(5 类)）；**建议门3 抽 #9 + #15**（`ngap_port_dyn` 补多流面）。

### 5.3 T-编号与 ID 对照

`T-NGAP-2` ≡ #2；`T-NGAP-3` ≡ #3；`T-NGAP-4` ≡ #4；`T-NGAP-5` ≡ #5；`T-NGAP-6` ≡ #6；`T-NGAP-7` ≡ #7；`T-NGAP-8` ≡ #8；`T-NGAP-9` ≡ #9；`T-NGAP-10` ≡ #10；`T-NGAP-11` ≡ #11；`T-NGAP-12` ≡ #12；`T-NGAP-13` ≡ #13；`T-NGAP-14` ≡ #14；`T-NGAP-15` ≡ #15；`T-NGAP-16` ≡ #16；`T-NGAP-17` ≡ #17。（#1 `ngap_sctp_setup_basic` 为**存量等价迁移的冒烟例**，`summary` 中无 T 号。）

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 SCTP 关联内多对过程消息（#9 六对；#7/#8 各一对；#10 单对） | 已覆 #9/#7/#8 |
| ② | 非正常结束 | 正常结束 = SCTP 3 步拆链（全 12 正例）；**异常结束不适用**——ngap 是 raw-IP 自驱层，**无 tcp 层 RST 能力**，SCTP ABORT 块**未实现** | 已覆（拆链全正例）；异常终态 **A′ 立项**（G-NGAP-9） |
| ③ | 长保活 | NGAP 协议层**无 keepalive 概念**；SCTP HEARTBEAT **未实现** | **不适用**（无保活消息可测；非"未覆盖"而是"不存在"） |

无空项：① 有已覆例；② 有已覆例 + 1 条 A′ 立项；③ 显式不适用 + 理由。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 拒绝分支面 | 13 条未入例 `Validate` 分支（IP 解析 2 / DstIP v6 / 端口上界 2 / PLMN 越界 4 / PDUSessionID / DRX（不可达）/ UL+DL NAS 超长 2） | G-NGAP-1 |
| IE 字段断言面 | 收编 `ngap.NGAP_PDU`（**M-1 修复后**）与 `ngap.criticality`（同上）；IE 字节断言（NAS-PDU 长度前缀、AMF 名、TA 列表、gNB-ID、UE ID） | M-1 + G-NGAP-1 |
| 自动派生面 | `initial_ue_message=true` 无 `initial_nas` → 自动 5GS Registration Request（**40B**） | G-NGAP-14 |
| AMF 名形态面 | 变长名（>11B）/ 空名回退缺省 | G-NGAP-13 |
| PLMN 形态面 | 3 位 MNC 分支（`mnc>=100`） | G-NGAP-8 |
| IE 长度面上界 | IE value ≥128 触发单字节长度截断 | G-NGAP-2 |
| UE ID 面 | 跨消息配对一致性断言；AMF-UE-NGAP-ID >65535 的 2B 截断 | G-NGAP-5 / G-NGAP-2 |
| 动态字段面 | `rand` 可复现 / `list` 轮转 / `pattern` 替换 / inc 回绕 | G-NGAP-12 |
| 多流面 | 流 2 的过程码/包数独立断言（今日只断端口池两帧） | G-NGAP-12 |
| 方向面 | down 帧的 src/dst 端口换向断言（#5/#7/#8 今日只断 chunk_type） | G-NGAP-5 |
| 异常终态面 | SCTP ABORT 块实现 + 补例，或明确"不适用" | G-NGAP-9 |
| PLMN 回退面 | 只给 MCC 不给 MNC 时的 PLMN 编码（当前产出 MNC=0 非法 PLMN） | G-NGAP-3 |
| SHUTDOWN TSN 面 | Cumulative TSN Ack 取值语义（无服务端 DATA 帧时为随机值） | G-NGAP-7 |

**B′（框架面）**：顶层未知键通用门（G-NGAP-11，等框架级 unknown-key 白名单，不单独立项）/ 负例 `notes` 键收窄（G-NGAP-10）。进设计 §14。

### 6.3 3.14 豁免边界审计

**有长连接载体（SCTP 关联）→ `sessions[]` 形态不豁免**——但**本协议 registry Fields 无 `sessions` 键**（机读实测 14 键，设计 §12.1），故**无法用 `sessions[]` 表达多会话**；多会话只能靠**策略级多流**（#15，`flows=2`）表达。**形态差异已声明**（设计 §12.3）。**多流并发**由 `flow_control {"flows": N}`（用例侧 `strategy_fc`）承载，实测 2 流（#15）。**单包多载荷** = **不适用**（一个 SCTP DATA 块承载一个 NGAP-PDU，无多 question/多 RR 类形态，如实声明）。**流关联（控制流派生数据流）** = **不适用**（单关联承载全部信令，无副连接，设计 §12.3）。

## 7. 实现后执行建议

1. **P4 顺序**：①**先修 M-1**（`buildNGAPInitiating`/`buildNGAPSuccess` 的 choice 改 `0x20`、criticality 改左移 6 位）——**帧长与包数不变**，故 §2 包数公式与全部 frames 断言**无需重钉**，仅 `ngap.NGAP_PDU`/`ngap.criticality` 字段断言（A′ 新增）须按修复后口径；②补 A′ 拒绝分支例（13 条）；③补 IE 字节断言（NAS/AMF/TA/UE ID）；④补自动派生面与动态面；⑤全量复跑。
2. **实测顺序**：先 #1（最小 9 帧基线，钉 frames offset 62 两帧），再 #4/#5/#6（三向 NAS，proc 15/4/46 与方向面），再 #7/#8（两对过程，proc 29/41 各两帧），再 #9（全过程 16 帧串接顺序），再 #10/#12（TA 列表与 AMF 名形状），再 #14（缺省端口），最后 #15（多流端口池 18 帧）。
3. 二进制与 HEAD 同代确认（门2③）；门2② 全量（`CASE_PROTO=ngap` 全量不是增量）；门2④ 反查绿后进 P6。
4. **本协议无 §1 迁移步骤**（非负例顶层键今日已为 0，设计 §12.1）。
5. 任何 TS 38.413 条款号的具体引用须有规范原文证据（G-NGAP-4 纪律）。

## 8. 存量审计（17 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/ngap.json` **17 例**：12 正带包数断言（`min_packets` 9/10/10/10/11/11/16/9/10/9/9 共 11 条 + `packet_count` 18 一条），**与实测 pcap 帧数 12/12 逐例一致**（`capinfos -c`）；5 负中 A 类 2 例无 pcap、B 类 3 例 pcap 均 **0 帧**；**非负例顶层键 = 0**（15 例顶层仅 `{layers}`；1 例 `ngap_port_dyn` 顶层 `{layers, group_id}`，`group_id` 为框架白名单键；第 17 例的顶层 `ngap` 为负例注入）；**148 条 field + 3 条 frame 断言逐条对实测 pcap 复算（全 OK）**；层内 `ngap` 已带 **14 键**（与 registry Fields 及生成表逐键一致，机读实测）；**SCTP CRC32c 34 帧独立复算全 OK**。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **M-1 confirmed 缺陷（PDU 位域）**：choice/criticality 按整字节写、tshark 按 aligned-PER 高 2 位读 → **每个 successfulOutcome 被读成 initiatingMessage、每个 ignore 被读成 reject**。**今日 17 例零条断言这两字段**（机读实测），故全绿而不自知。设计 §3.2 已立项（变异探针 256 值扫描钉边界）。
2. **`ngap.go` 头注"analyzers recognize"失准**：procedureCode 可识别，但 choice/criticality 系统性误读、IE 容器完全不解（§0 #1/#2）。
3. **IE 容器非 PER**：`count(2B 大端) + {id(2B),crit(1B),len(1B),value}` 为自定形；tshark 解完 PDU 头后静默停下，**无任何 IE 级字段产生、亦无 malformed 告警**（设计 §3.4）。
4. **`buildIE` 单字节长度截断**：IE value ≥128 字节时静默写出错误长度（`ngap.go:565`）。今日最大 value = 50B（#10）未触界（G-NGAP-2）。
5. **AMF-UE-NGAP-ID 2 字节截断**：`uint16(id)`（`ngap.go:620`），>65535 静默截断。**#11 给了 424242 但该 IE 不出现在 IUE 中**，故截断行为今日**未被任何断言观察**（G-NGAP-2）。
6. **UE ID 配对为静态回显**：无配对校验代码；#11 只断言"显式 UE ID 进 IUE PDU"，不断言跨消息一致性（G-NGAP-5）。
7. **SHUTDOWN 的 Cumulative TSN Ack 语义可疑**：无服务端 DATA 帧时 `serverTSN-1` 是随机值（G-NGAP-7）。
8. **13 条 `Validate` 分支未入例**（G-NGAP-1）；**1 条层内不可达**（DRX，registry 已限 `Max:3`）。
9. **非确定性字段无种子**：vtag/TSN/IP ID（G-NGAP-6）——登记为纪律约束，**不得新增断言**。
10. **动态字段覆盖不全**：只有 `inc`（#15），缺 `rand`/`list`/`pattern`/回绕四类（G-NGAP-12）。
11. **结果产物链接悬空（全仓共性，非 ngap 特有）**：`trafficgen/docs/protocol-pcap-test/ngap.md` 写 `Cases: 17 — pass 17` 且链接 `ngap/<id>.pcap`，但 `trafficgen/docs/protocol-pcap-test/` 下**没有任何协议子目录**（机读：`ls -d */ \| wc -l` = **0**）。**该产物末次提交 `45016f3`（2026-09-19）晚于判死提交 `0417be5`（2026-09-13），故按批次二任务书口径不属于"过期产物"**，不登记该类缺口；悬空链接登记为事实（设计 §0 #3/#4）。
12. **本车道未跑引擎**：§8.1 的"逐条一致"是**存量 JSON 断言 × 磁盘既有 pcap**（文件日期 2026-09-27）的机读对账，**不等于今日复跑套件绿**（设计 §0 取证边界）。

### 8.3 逐条去向表（17 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `ngap_sctp_setup_basic` | —（冒烟） | **保留** | 形状已合规（纯 layers）；M-1 修复后可补 `ngap.NGAP_PDU=0` 断言（值不变，init 帧两版一致） |
| `ngap_flat_presence` | T2 | **保留** | 形状合规（presence 门今日真绿）；可收窄 `notes`（G-NGAP-10） |
| `ngap_flat_static_port` | T3 | **保留** | 同上 |
| `ngap_initial_ue` | T4 | **保留** | 可补 IE 字节断言（NAS-PDU 长度前缀 `0005` + `hello`）与 `ngap.NGAP_PDU=0` |
| `ngap_dl_nas` | T5 | **保留** | 可补 down 帧端口换向断言 + `ngap.NGAP_PDU=0` |
| `ngap_ul_nas` | T6 | **保留** | 同上（up 方向） |
| `ngap_pdu_session` | T7 | **改写** | **补 response 帧的 choice 断言**（M-1 修复后 `ngap.NGAP_PDU=1`）——该例是 M-1 的最佳观察点（同 proc 两帧、choice 不同） |
| `ngap_ue_release` | T8 | **改写** | 同上（proc 41 两帧 choice 0/1） |
| `ngap_all_procedures` | T9 | **保留** | 可补 7 帧可选过程的 choice 矩阵断言（修复后 0,0,0,0,1,0,1） |
| `ngap_ta_drx` | T10 | **保留** | 可补 DRX 线值 `02` + TA 列表字节断言 + `ngap.NGAP_PDU=0` |
| `ngap_ue_ids` | T11 | **保留** | 可补 RAN-UE `0000002a` 字节断言（G-NGAP-5） |
| `ngap_amf_name` | T12 | **保留** | frames 已钉；可补变长名另立 A′（G-NGAP-13） |
| `ngap_neg_v6` | T13 | **保留** | 可收窄 `notes`；可补 DstIP 分支例（Src=v4） |
| `ngap_default_port` | T14 | **保留** | 已钉 dst 38412 / src 12345 两面；可补"缺省 + flows>1 不拒"对照 |
| `ngap_port_dyn` | T15 | **保留** | 可补流 2 的过程面断言（今日只断端口池两帧） |
| `ngap_neg_sst` | T16 | **保留** | 可补紧邻上界 256 例（A′） |
| `ngap_neg_nas_len` | T17 | **保留** | 可补 UL/DL NAS 超长两例（A′，G-NGAP-1） |

**无"作废不注原因"：0 作废，0 等价覆盖**（17 例全部保留/改写 + A′ 新增）。**本协议非负例顶层键今日已为 0**（§1）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

**现状**：`trafficgen/tools/coverage_gate.py` **已有 `check_ngap`**（`:658-702`，D-NGAP-1 P5 落地件，含 17 场景面 + 14 键覆盖 + 5 锚词面 = **36 项**）。下列为**增量建议**（在既有 36 项之外追加；每条均可从本契约与 cases JSON 直接机读，不需新造事实）：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases) == 17` 且 ID 集合/顺序 = §2 十七项 | 本契约 §2 |
| 2 | **非负例** `spec_json` 顶层键 ⊆ `{layers, group_id}`（**16 例**：15 例仅 `{layers}`，1 例含 `group_id`；第 17 例 `ngap_flat_presence` 的顶层 `ngap` 键为负例注入，**显式豁免**） | 本契约 §1；设计 §12.1 |
| 3 | 12 正例包数 == `9 + 可选帧数`（可选帧由 spec 推出） | 设计 §9 公式 |
| 4 | 5 负例 `expect` 键 == `{expect_error, error_contains}`（**P4 删 `notes` 后**；今日为三键，须容忍 `notes`） | 本契约 §4 |
| 5 | 负例 `error_contains` ∈ 代码锚词集 `{"top-level ngap sub-config","static four-tuple","only IPv4 is supported","SST","InitialNAS too long"}` | 设计 §7 |
| 6 | 每正例至少一条 `sctp.chunk_type` 断言覆盖 4 步握手（值 1/2/10/11）与 3 步拆链（7/8/14） | 本契约 §3 共性 |
| 7 | 每含 DATA 帧的正例至少一条 `sctp.data_payload_proto_id=60` 断言 | 设计 §3.6（PPID=60） |
| 8 | 断言字段集 ⊆ `{sctp.srcport, sctp.dstport, sctp.chunk_type, sctp.data_payload_proto_id, ngap.procedureCode}`（**禁** `sctp.verification_tag` / `sctp.data_tsn` / `ip.id`——非确定性） | 设计 §6/G-NGAP-6 |
| 9 | 帧 hex 断言 offset 恒 62（raw-IP 链，无 VLAN/options） | 本契约 §3.1 |
| 10 | M-1 修复后：`ngap_pdu_session` 帧 7/8 的 `ngap.NGAP_PDU` ∈ `{0, 1}`（帧 8 必须为 1） | 设计 §3.2 |

**另注意**：`trafficgen/docs/protocol-pcap-test/ngap.md`（tracked 产物）写 `Cases: 17 — pass 17, fail 0, error 0`，末次提交 `45016f3`（**2026-09-19**）**晚于**判死提交 `0417be5`（2026-09-13）→ **不属于"过期产物"**（与 opcua G-OPCUA-10 / thrift G-THRIFT-10 判据不同，差别在日期）；但其中 `ngap/<id>.pcap` 链接**全部悬空**（`docs/protocol-pcap-test/` 下无任何协议子目录，**全仓共性**）。**本车道未跑该套件**，故不以任何形式引用该产物作为"今日已复跑"依据。

## 10. 修订记录

- v1.0.0（2026-09-29）：批次二文档轨 #116 **首次成文**。**17 例逐条索引**（§2）+ 正例逐项断言契约（§3，12 例含实测 PDU 字节与 IE 序列）+ 负例契约（§4，A 类 2 + B 类 3，锚词逐条对码，3 例实测 0 帧）+ 覆盖对账（§5，78 点 = 覆 47 + A′ 20 + 不适用 11）+ P3 固定动作（§6）+ 执行建议（§7）+ 存量审计（§8，17/17 保留或改写，**零作废**）+ 覆盖反查门增量建议 10 条（§9，既有 `check_ngap` 36 项之上）。**148 field + 3 frame + 12 包数断言全部对磁盘 pcap 复算零不符**。**未跑引擎**（§8.2 第 12 条）。自审见 `/tmp/pipe/doc-lanes/ngap.md`。

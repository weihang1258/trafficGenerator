# #131 syslog（RFC 5424 / RFC 3164 系统日志，UDP 514 主载体）设计契约

> 版本：v1.0.0（P-PIPE 文档轨批次二，as-built 逆向定稿）
> 日期：2026-09-29
> 车道：文档轨（#131 syslog）
> 旧基线：**无**——`docs/protocol-designs/` 下无 syslog 旧编号文档；本版为首份设计契约（as-built）
> 存量用例：`trafficgen/test/protocol_pcap/cases/syslog.json`（**1 例** = `syslog_smoke_01`，2026-09-29 机读实测；非负例顶层键 **1 处**（顶层 `syslog` 空子映射），**不是零残留**，见 §12.1 与 G-SYSLOG-1）
> 规范基线：① **RFC 5424**（The Syslog Protocol：报文格式 §6、PRI §6.2.1、长度上界 §6.1、STRUCTURED-DATA §6.3、MSG/BOM §6.4，2026-09-29 原文核对）；② **RFC 3164**（BSD 格式：PRI §4.1.1、TIMESTAMP §4.1.2、TAG §5.3、总长 ≤1024 §4.1）；③ **RFC 5426**（UDP 载体：端口 514 §3.3、每数据报一消息 §3.1、尺寸 §3.2）；④ **RFC 6587**（TCP 载体分帧：octet-counting §3.4.1、non-transparent §3.4.2）；⑤ **RFC 5425**（TLS 载体：端口 6514 §4.1）；⑥ RFC 5848（syslog-sign，仅作对照，见 G-SYSLOG-6）；⑦ 本机 tshark 3.6.14 `syslog.*` 12 字段表 + `udp.port 514→syslog` 绑定（2026-09-29 `-G fields`/`-G decodes` 实测）；⑧ 本仓落码（`internal/protocol/syslog/` + 接线，§11）
> 白话一句：**设备把一行日志（优先级 + 一串字段 + 正文）装进一个 UDP 包扔给收集器（514 端口），发完就完，不等回应——这就是 syslog。**

## 0. 沿革与基线声明（门1 必答：基线继承关系）

本 #131 为**首份** syslog 设计契约（无旧编号稿）。三项既有事实须先钉死：

| # | 既有说法/产物 | HEAD 实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | `planner.go` 注释引用 `design_syslog.md`（§1.8.4/§6.1/§8）、`testcases_syslog.md`（§3.3.2/§3.4.2/§1.2.2）、`validate_conventions.md`（§7/§1.1/§1.3） | 三文件**仓内不存在、本机磁盘不存在**（`find / -name` 实测零命中） | **死引用**（与 opcua #17 同类）：注释中的章节号不可追溯，本版不复制任何来自死文档的规格，全部按落码 + RFC 原文重钉（G-SYSLOG-9） |
| 2 | 代码注释/错误文案引 "RFC 5424 §6.2.8"（SD-ELEMENT）、"§6.4.4"（BOM） | RFC 5424 原文目录：§6.2 到 **6.2.7 为止**（无 6.2.8）；§6.4 无子节；SD-ELEMENT 实为 **§6.3.1**、BOM 实为 **§6.4** | **章节引用漂移**（锚词字面不受影响，负例 `error_contains` 按代码文案原样匹配即可）；本版一律引正确章节（G-SYSLOG-10） |
| 3 | `trafficgen/docs/protocol-pcap-test/syslog.md`（tracked，仓根相对路径）写 "Cases: 1 — pass 1, fail 0, error 0" | 末次提交 `e7e7d1c`（**2026-08-27**），早于判死提交 `0417be5`（2026-09-13）；`trafficgen/docs/protocol-pcap-test/syslog/` 目录**不存在（0 个 pcap）** | **产物过期**（同 pcep G-PCEP-11 口径）：该 "1/1 pass" **未经今日复跑证实**。本车道对该例 pcap（`/tmp/mcp-pcaps/syslog/syslog_smoke_01.pcap`，2026-09-27，判死提交后）做了 tshark 字段与帧字节复核（§9 一致），但**套件复跑仍属代码阶段**，本文档不以任何形式引用该产物作为"今日已复跑"依据（G-SYSLOG-8） |

**依赖链判定纪律**：以上与全文各裁定均为可判题（代码/pcap/RFC 原文三级对照），直接判对错，不问偏好。

## 1. 范围、profile 与实现状态边界

本版定义 **syslog 消息生成**（RFC 5424 新格式为主、RFC 3164 BSD 旧格式为辅）承载于 **UDP 514**（RFC 5426）的流量生成；TCP/TLS 载体（RFC 6587/5425）为**待实现边界**（§1 边界①）。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `syslog_udp_rfc5424_v1`（主） | UDP 514，链 `[ip,udp,syslog]` | 一数据报一消息（§3.1 全字段），fire-and-forget | 真实收集器语义（是否入库、过滤） |
| `syslog_bsd_v1` | 同上 | RFC 3164 布局（`format:"bsd"`，§3.5） | 从 RFC 5424 字段推导 BSD 字段（两格式字段面独立声明） |
| `syslog_tcp/tls` | TCP 514 / TLS 6514 | **链级拒绝**（`layer_gen.go:133-135`）；legacy `emitTCP` 存在但生产未注册 | —（待实现边界，G-SYSLOG-3） |

显式边界（"不实现、不声称、不许静默转换"）：① **TCP/TLS 载体链级不可达**——层校验器直接拒绝 `transport tcp/tls`（锚词 `syslog: %s transport not supported by the layer chain yet (udp only; tcp/tls deferred)`，`layer_gen.go:133-135`）；legacy planner 的 `emitTCP`（握手→分帧→挥手，`planner.go:595-688`）**未注册生产路径**（`main.go:547` 只注册 `NewChainPlanner("syslog")`），仅 Go API 直调可达；② `sign_blocks` 是**通用 SD-ELEMENT**（`[sign@32473 signature="..."]`），**不声称 RFC 5848 合规**（RFC 5848 §4.2 的 SD-ID 恒为 `ssign`、参数为 VER/RSID/SG/SPRI/GBC/FMN/CNT/HB/SIGN，G-SYSLOG-6）；③ **无 480/2048 长度上界强制**——仅有 UDP 65507 近似守卫（RFC 5426 §3.2；本设计 §6，G-SYSLOG-4）；④ BOM 语义与 RFC 5424 §6.4 ABNF 有线形偏离（G-SYSLOG-5）；⑤ IPv6 双栈（`EtherTypeFor(srcIP)` 动态选 EtherType）已实现于 planner/生成器，pcap 契约面无用例（A′）。

**实现状态（2026-09-29 实测）**：`syslog` 层已注册（`registry.go:167-169`，`CategoryTerminal`，`DependsOn ["udp"]`，**Fields 空 map**）；生成器/校验器经 `layer_gen.go:124-138` init 反向注册；`protocols.go:57` 准入；缺省目的端口 514（`chain_planner.go:1046-1053`）；`main.go:162` 空白导入 + `main.go:547` ChainPlanner 注册；1 例冒烟已落 `cases/syslog.json` 且 pcap 复核在案。单测 222 个 `Test*`（syslog 包 188 + chain 6 + convert 28，`grep -c` 实测），`go test ./internal/protocol/syslog/ ./internal/core/layers/ -run Syslog` 全绿（2026-09-29 实跑）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`udp.dstport`、`syslog.*` 字段、offset 42 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

层链 `[ip,udp,syslog]`（引擎自动补 `ip`；存量冒烟写最小链 `[udp,syslog]`）。syslog 报文是 UDP payload，**一数据报恰一消息**（RFC 5426 §3.1），无分段概念（UDP 分片属 IP 层，本层不产）。

端口：**UDP 514**（RFC 5426 §3.3；链缺省 `chain_planner.go:1046-1053`，tls→6514 分支链级不可达仅留 legacy 对齐）。源端口沿用 spec 通用默认 **12345**（`strategy_convert.go:49` `DefaultSrcPort`；`chain_planner.go:924` 允许 0/12345 上包，不强制协议端口）。TLS 6514 = RFC 5425 §4.1（仅 legacy 语义，链不可达）。

固定偏移：无 VLAN/IP options 时 **每帧 syslog 报文起点 = 帧偏移 42**（14 Eth + 20 IPv4 + 8 UDP）。**帧尾注意**：引擎 `pad_min_frame` 默认开启，短帧补 0 至 **60 字节最小以太帧**（`mcp/padding_inspect_test.go`："absent -> default ON -> padded to 60"）——存量冒烟帧 59 字节实发 60 字节，**末位 0x00 是链路层填充，不是消息内容**（存量 notes 的"0x00 终止符"说法为误诊，G-SYSLOG-11）。实测 pcap 另见 DSCP=CS1(0x20)/TTL=64/DF（用例未断言，随帧断言锚点不受影响）。

**目标形状 spec_json 样例**（**今日唯一可执行形 = as-built 形**：层链 + 顶层 `syslog` 子映射承载协议配置——层内不可住键，G-SYSLOG-1）：

```json
{
  "layers": [
    {"udp": {}},
    {"syslog": {}}
  ],
  "syslog": {
    "facility": 1, "severity": 6, "version": 1,
    "timestamp": "2026-08-12T10:00:00Z",
    "hostname": "host1", "app_name": "app", "proc_id": "123", "msg_id": "ID47",
    "structured_data": ["origin ip=\"192.0.2.1\""],
    "msg": "hello syslog"
  }
}
```

多包样例（`messages` 每条目一数据报，`count` 被忽略；或无 `messages` 时 `count`=N 复制单消息）：

```json
{
  "layers": [{"udp": {}}, {"syslog": {}}],
  "syslog": {
    "messages": [
      {"msg_id": "ID1", "msg": "first"},
      {"msg_id": "ID2", "msg": "second"}
    ]
  }
}
```

**目标形（层内承载，待 G-SYSLOG-1 收敛后方可执行，今日不可建）**：`{"layers":[{"udp":{"dst_port":514}},{"syslog":{"facility":1,"severity":6,"msg":"hello"}}]}`——registry syslog 行 Fields 为空（`layers.generated.json:4178` `"fields":{}`），层内任意键即 400 `layers: layer "syslog": unknown field "…"`（`complete.go:293`）。

## 3. 线格式编码（as-built，逐字段；RFC 章节为 2026-09-29 原文核对）

### 3.1 RFC 5424 报文（`encodeRFC5424`，`planner.go:699-762`）

线形（RFC 5424 §6 ABNF `SYSLOG-MSG = HEADER SP STRUCTURED-DATA [SP MSG]`）：

```
<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA [SP MSG]
```

| 字段 | RFC 章节 | 实现 | 默认/NILVALUE | 校验（锚词行号） |
|---|---|---|---|---|
| PRI | §6.2.1 | `<%d>`，十进制**无前导零** | facility=1/severity=6 经扁平解析注入（§3.2 偏差见 G-SYSLOG-2） | Facility>23 / Severity>7 拒（`:119/:122`） |
| VERSION | §6.2.2 | `%d`（uint8） | 1（`strategy_convert.go:1503`；生成器兜底 1，`layer_gen.go:47-50`） | rfc5424 下 0/≠1 拒（`:140/:143`）；bsd 下无 VERSION |
| TIMESTAMP | §6.2.3 | 空或 `-`→NILVALUE，否则**原文照发** | `-` | rfc5424 下非空必须 RFC 3339（Nano）（`:204`）；bsd 下接受任意非空（§3.5） |
| HOSTNAME | §6.2.4 | 1-255 PRINTUSASCII，空→`-` | `-` | 含 SP / >255 拒（`:271/:274`） |
| APP-NAME | §6.2.5 | 1-48 | `-` | 含 SP / >48 拒 |
| PROCID | §6.2.6 | 1-128 | `-` | 含 SP / >128 拒 |
| MSGID | §6.2.7 | 1-32 | `-` | 含 SP / >32 拒 |
| STRUCTURED-DATA | §6.3 | SD-ELEMENT 串接**无 SP**；空表→`-` | `-` | §3.3 |
| MSG | §6.4 | UTF-8；空则**整段省略**（无尾 SP）；非空则 SP（或 BOM，§3.4）前置 | 无 MSG | non_transparent 分帧下含 LF 拒（`:171/:175`） |

**总长度公式**：`L = (2 + digits(PRI)) + digits(VERSION) + Σ_{f ∈ {TIMESTAMP,HOSTNAME,APP-NAME,PROCID,MSGID,STRUCTURED-DATA}} (1 + len(f)) + (MSG=="" ? 0 : (BOM?3:1) + len(MSG))`——每字段前恒一个 SP；NILVALUE 计 1。校验：全空配置 = 4（`<14>`）+ 1（VERSION）+ 6×2（六个 `-` 各带前导 SP）= **17 字节**（`<14>1 - - - - - -`，存量冒烟实测 payload 恰 17B）。

**空配置默认流（P0b-2）**：`spec.Syslog == nil` 时 Validate 放行（`planner.go:112-114`）、生成器默认化 `&core.SyslogConfig{}`（`layer_gen.go:30-32`），version/format/count 兜底，**facility/severity 无兜底 → PRI=0**（G-SYSLOG-2）。

### 3.2 PRI（RFC 5424 §6.2.1）

`PRIVAL = Facility × 8 + Severity`，范围 0-191（ABNF `1*3DIGIT`）；Facility 0-23（0=kern…16=local0…23=reserved）、Severity 0-7（0=emerg…6=info…7=debug），越界 MUST 拒（实现 `:119/:122` ✓）。**缺省值断层（G-SYSLOG-2）**：facility=1(user)/severity=6(info) 的 1/6 缺省**只住扁平解析**（`strategy_convert.go:1501-1502` `getIntDefault(sub,"facility",1)`/`6`）；`planner.go:74-75` 的 `DefaultFacility=1/DefaultSeverity=6` **声明未用**，`:368-374` 是空 if 体死分支——故空层链（无顶层 `syslog` 键）线字节为 `<0>1 - - - - - -`，与带顶层空子映射的存量冒烟（`<14>…`）**不同**。今日以"带顶层子映射"形为权威（存量 1/1 如此）。

### 3.3 STRUCTURED-DATA（RFC 5424 §6.3，代码注释误引 §6.2.8）

- SD-ELEMENT = `[SD-ID [SP PARAM]]`；SD-ID 1-32 PRINTUSASCII（不含 `=`/SP/`]`/`"`）（§6.3.2）；PARAM-NAME 1-32（§6.3.3）；PARAM-VALUE 内 `"` `\` `]` MUST 转义为 `\"` `\\` `\]`（§6.3.3 原文）。
- 配置面（`parseSyslogStructuredData`，`strategy_convert.go:6691-6747`）双形：**字符串形**（原样透传）与**结构形** `{id, parameters:{...}}`（拼为 `[id k1="v1" k2="v2"]`，**参数序 = 键名字典序**，保证确定性输出；支持 `id@PEN`）；两形可混用。
- 校验（`validateSDElement`，`planner.go:289-343`）：空元素/未闭合 `]`/空括号/SD-ID 含 SP/超 32/空 ID 拒（`:291/:297/:301/:315/:318/:321`）；参数面弱校验（SD-ID 后非空则须含 `=`，`:339`）——**转义由调用方负责**，planner 不转义 StructuredData。
- `frameSDElement`（`:860-865`）：bare 形编码期自动补 `[...]`。

### 3.4 MSG 与 BOM（RFC 5424 §6.4）——**线形偏离声明（G-SYSLOG-5）**

RFC 形状：`... STRUCTURED-DATA SP MSG`，且 UTF-8 编码的 MSG **MUST 以 BOM（EF BB BF）开头**——即线字节 `SD SP BOM MSG体`。**实现**（`planner.go:752-759`）：`MsgHasBOM=true` 时 **BOM 替换 SP**（线字节 `SD BOM MSG体`，少一个 SP；单测 `TestSyslogPlan_Msg_ASCII_WithBOM` 按此钉死）。本版按实现钉死为 as-built 口径；是否回正属代码阶段裁定（P4），负例/正例断言今日不得引用"RFC 合规 BOM 线形"。MSG 为空时 BOM 不出现（`:610` 单测钉死）。

### 3.5 RFC 3164（BSD）编码（`encodeBSD`，`planner.go:772-846`）

```
<PRI>Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MSG
```

- PRI 同 §3.2；无 VERSION（`version` 键在 bsd 下不进线）。
- TIMESTAMP（§4.1.2）：`Mmm dd hh:mm:ss`，日 <10 前补**空格**（"Aug  7"）。配置面：空/`-` → 编码期取 `time.Now().UTC()`（非确定，用例须显式钉时间）；RFC 3339 值 → 重排为 BSD 形；**预格式 BSD 串 → 原文照发**（`planner.go:789-824`）。
- HOSTNAME：`nilOrValue`（空→`-`）。
- TAG[PID]（§5.3）：TAG=APP-NAME、PID=PROCID；PROCID 空时无 `[PID]` 段（`TAG:`），非空时 `TAG[PID]:`。
- MSG：非空则 `SP MSG`，空则省略。
- 总长：RFC 3164 §4.1 "packet MUST be 1024 bytes or less"——**实现无 1024 守卫**（并入 G-SYSLOG-4）。

### 3.6 RFC 6587 TCP 分帧（`emitTCP`，`planner.go:595-688`；**链级不可达**，G-SYSLOG-3）

握手（SYN/SYN-ACK/ACK，synOptions MSS+WinScale+SACK，`:909-918`）→ 每消息一逻辑帧、按 MSS 分段（`segmentByMSS`，`:887-904`；PSH-ACK 0x18）→ 四包挥手（FIN-ACK/ACK/FIN-ACK/ACK）。分帧（§3.4.1/§3.4.2 原文）：`octet_counting` = `MSG-LEN SP MSG LF`（MSG-LEN 为消息自身八位数，不含长度域与分隔符；缺省）与 `non_transparent` = `MSG LF`（TRAILER=LF；**MSG 内禁 LF**，`:171/:175` 拒）。TCP 514 端口 RFC 6587 §3.3/§4 明言"实际分配给 Shell 协议"；**tshark 3.6.14 `tcp.port 514→rsh`（非 syslog）**——未来 TCP 用例若用 514 须 `decode_as`，或改用非 514 fixture 端口（G-SYSLOG-12）。

### 3.7 sign_blocks（`planner.go:736-740`）

每值编码为 `[sign@32473 signature="<escaped>"]` 追加到 STRUCTURED-DATA 串接尾部；值内 `"` `\` `]` 经 `escapeSDValue`（`:869-879`）转义——**这是全实现唯一自动转义点**。**非 RFC 5848**（该 RFC SD-ID=`ssign`、参数 VER/RSID/…/SIGN，§4.2；G-SYSLOG-6）：本版定性为"通用 SD-ELEMENT 便捷写法"，用例/文档不得称 syslog-sign 合规。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明消息面（字段/SD/MSG/messages/count），引擎按固定剧本逐包产出；UDP 载体无握手无回应，tcp 层不参与。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 主机/设备向收集器上送一行日志（UDP 514，最常见） | 单 datagram，fire-and-forget | #1（`syslog_smoke_01`，默认字段面） |
| ② 带结构化元数据（SD-ELEMENT）的上送 | 同上 | A′ 立项（单测已覆，pcap 契约面无用例） |
| ③ 旧设备 BSD 格式日志 | 同上 | A′ 立项 |
| ④ 一次连接发多条日志（messages 逐条覆盖 / count 复制） | N datagram 顺序发出 | A′ 立项 |
| ⑤ 多设备→同一收集器（多流并发） | 多流四元组相异 | A′ 立项（`flow_control` 承载，本版未用） |

**五层覆盖逐层结论**（覆盖分两层如实声明：**单测面** = 222 个 `Test*`；**pcap 契约面** = 1 例冒烟）：
- **功能层**：RFC 5424 默认流正例 1 例（#1）；显式字段集/SD/BOM/BSD/messages/count/IPv6 正例、22 类 validator 拒绝负例**今日 pcap 契约面全缺**（单测面已覆编码/校验行为）→ A′ 全量立项（G-SYSLOG-7）。
- **性能层**：最小报文 17B（最小帧 60B padding）；UDP 上界守卫是基于 `256 + len(cfg.Msg) +` 顶层 StructuredData 的**固定近似预检**（`:249-259`），不是编码后精确长度检查，且未覆盖 `messages[]` 各条目的最终编码长度；因此 oversized messages 可能绕过该预检，不能声称已覆盖通用 UDP 65507 上界拒绝；无 MSS/分段（UDP 一包一消息）；TCP MSS 分段存在但链不可达（§1 边界①）；480/2048（RFC 5424 §6.1）/1024（RFC 3164 §4.1）无强制 → G-SYSLOG-4。
- **数据场景层**：PRI 值域边界（min 0/max 191）、facility/severity 逐值、字段长度上界 255/48/128/32/32、SD 双形+转义+BOM+UTF-8——单测面已覆（`planner_testpoints_test.go` 99 个 TestPoint），pcap 契约面 A′。
- **地址与流层**：**IPv4/IPv6 双栈必须**——`EtherTypeFor(srcIP)` 动态选 EtherType（`planner.go:557/633`），v4/v6 单测已覆（`:828/:839`），pcap 契约面仅 IPv4；**单流基线**已覆（#1）；**流关联不适用**：UDP fire-and-forget 无控制流/数据流派生（显式声明，不硬凑）。
- **业务层**：多会话不适用（UDP 无连接概念，无 `sessions[]` 形态）；多事务不适用（单 datagram 即终）；"多条日志"以 `messages`/`count` 承载（④），A′ 立项。

## 5. 消息/事务模型与状态机

syslog 层**无自有状态机**：UDP 载体每消息独立数据报、无序号无确认；TCP 载体的握手/挥手/分段属 tcp 层（链不可达，§1 边界①）。生成器是"按配置序把消息翻译成事件"的纯函数驱动。

**事件序（`SyslogGenerator.Generate`，`layer_gen.go:29-112`；与 legacy `emitUDP` 逐字节同源）**：`messages` 非空 → 逐条 `buildPerMessageCfg`（`planner.go:483-527`，零值字段继承父级；`msg_has_bom` 仅当条目任一字段被显式设置时才覆盖，`hasAnyMessageField` `:533-537`）编码后**每条一事件**（`count` 忽略）；否则单消息 ×`count`（缺省 1）复制。方向恒 `up`；每事件 Metadata 携带 `syslog_priority = facility*8+severity`（int）与 `syslog_transport = "udp"`（`layer_gen.go:82-86`），udp 层合并进数据报 Metadata（`generator.go` Inner 模式）。

**确定性**：同一输入必同一输出——除两处显式非确定：① bsd 格式 timestamp 空时取 `time.Now().UTC()`（`:802-805`，用例必须显式钉 timestamp）；② IPv4 ID/校验和逐次随机（pcap 断言不触 18-19/24-25 字节）。`structured_data` 结构形参数按键名字典序输出（`strategy_convert.go:6713-6716` 注释钉死）。

**自动派生规则**：① `cfg==nil` → 默认化空配置（P0b-2，PRI=0 断层见 G-SYSLOG-2）；② version/format/count 生成器兜底 1/rfc5424/1（`layer_gen.go:47-62`）；③ 顶层 `syslog` 子映射存在时扁平解析注入 1/6/1 缺省（`strategy_convert.go:1501-1503`）；④ 空 SD/空字段 → NILVALUE；⑤ 空 MSG → 无尾 SP；⑥ bare SD → 自动补 `[]`。

## 6. 性能设计与验收

- **目标与边界**：UDP 单流 = `len(messages)>1 ? len(messages) : count` 个数据报（`count` 缺省 1；仅 `len(messages)>1` 时实现忽略 `count`；`len(messages)==1,count=100` 生成 100 个数据报）；单数据报报文长 = §3.1 公式，无帧长上限强制（§1 边界③）；每帧内存 = 该报文长度（最小 17B）。吞吐数字由生成器级速率配置承载，协议层不重复定义。
- **依据**：事件流式产出（生成器逐事件 `EmitMsg`，无全量聚合）；无跨流共享状态；无锁（编码为纯函数）。
- **验收两路**：pcap（`/tmp/mcp-pcaps/syslog/`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `syslog.*` 字段、帧原始 hex 与 `packet_count`，不只断言"任务没报错"。
- **六类场景落点**：基线（#1，1 帧）/ 目标规模（messages 多包，A′）/ 压力上限（UDP 顶层近似预检拒绝，A′ 负例）/ 长时间运行（count 复制承载语义）/ 并发交错（多流 `flow_control`，A′）/ 背压（`packet_count` 精确计数守卫）。

## 7. 错误处理（负例锚词表；**今日 0 负例**，全部 A′ 立项）

以下输入必须被拒并传播为 task error，不得产出成功 PCAP 或假成功。**22 个 planner/validator 拒绝分支**（锚词逐字 = 代码文案，负例 `error_contains` 取其中子串）：

| # | 锚词（`planner.go` 逐字） | 行 | 触发 |
|---:|---|---:|---|
| 1 | `SrcIP %q is not a valid IP address` | :93 | SrcIP 非法 |
| 2 | `DstIP %q is not a valid IP address` | :98 | DstIP 非法 |
| 3 | `Facility %d invalid (must be 0-23` | :119 | Facility>23 |
| 4 | `Severity %d invalid (must be 0-7` | :122 | Severity>7 |
| 5 | `Format %q not in supported list` | :131 | format ∉ {rfc5424,bsd} |
| 6 | `Version 0 unsupported` | :140 | rfc5424+version 0 |
| 7 | `Version %d unsupported` | :143 | rfc5424+version≠0,1 |
| 8 | `Transport %q not in supported list` | :153 | transport ∉ {udp,tcp,tls} |
| 9 | `TCPFraming %q not in supported list` | :163 | 分帧 ∉ {octet_counting,non_transparent} |
| 10 | `MSG cannot contain LF in non-transparent framing` | :171 | 顶层 Msg 含 LF（non_transparent） |
| 11 | `Messages[%d].Msg cannot contain LF` | :175 | 逐消息 Msg 含 LF（non_transparent） |
| 12 | `%s %q not a valid RFC 3339 timestamp` | :204 | 顶层/逐消息 Timestamp 非法 |
| 13 | `encoded message exceeds UDP payload limit %d` | :257 | UDP 近似长度 >65507。**覆盖边界（as-built）**：validator 只做 `approx := 256 + len(cfg.Msg)` 加顶层 StructuredData 的固定近似预检（`:249-258`），**不遍历 `messages[]`、不调用编码器**——超限 `messages` 条目可通过本检查并生成超大 UDP 数据报；且固定 `256` 近似可能**误拒合法输入**（如空 SD + 最小头 + `Msg` 长 65252 时 `65508>65507` 拒，实际线长约 65270 < 65507）。错误文案中 `(RFC 5426 §6)` 为代码历史字面（负例锚词按文案原样匹配），非本版规范引用；本版规范引用 = §3.2 |
| 14 | `%s %q must not contain SP` | :271 | HOSTNAME/APP-NAME/PROCID/MSGID 含 SP |
| 15 | `%s exceeds %d bytes` | :274 | 同上四字段超长（255/48/128/32） |
| 16 | `StructuredData[%d] empty` | :291 | 空 SD 元素 |
| 17 | `StructuredData[%d] unclosed SD-ELEMENT` | :297 | 缺 `]` |
| 18 | `StructuredData[%d] empty brackets` | :301 | `[]` |
| 19 | `StructuredData[%d] SD-ID must not contain SP` | :315 | SD-ID 含 SP |
| 20 | `StructuredData[%d] SD-ID exceeds 32 bytes` | :318 | SD-ID 超长 |
| 21 | `StructuredData[%d] SD-ID empty` | :321 | 空 SD-ID |
| 22 | `StructuredData[%d] parameter %q missing '='` | :339 | 参数缺 `=` |

**链级附加拒绝**：transport tcp/tls（`layer_gen.go:133-135` 锚词 `not supported by the layer chain yet`）；层内未知键 `layers: layer "syslog": unknown field %q`（`complete.go:293`）；顶层扁平五键 `protocol syslog no longer accepts flat config field %s`（`CheckProtoFlat` 通用段，`strategy_convert.go`）。**混写注意**：#8（transport=tcp 在 Validate 放行）与链级拒绝**双门**——链路径先触链级锚词，负例锚词须按层路径取 `not supported by the layer chain yet`。

**不得误报的合法协议事件**：MSG 含 LF（octet_counting/udp 下合法，`:264` 单测钉死）；facility=0/severity=0（kern/emerg 合法值，显式设置不拒）；空配置默认流。

## 8. 边界

- **帧长**：最小 RFC 5424 报文 17B（`<14>1 - - - - - -`）；无上界强制（RFC 5426 §3.2 的 UDP 尺寸依据；本设计 §6，G-SYSLOG-4）；最小以太帧 60B 填充（pad_min_frame 默认 ON）。
- **PRI**：0-191 全值域合法；>191 不可表达（Facility/Severity 分字段校验挡住）。
- **字段长度**：255/48/128/32/32（RFC 5424 §6.2.4-6.2.7/§6.3.2）。
- **载体**：UDP 514 唯一链级可达载体；tcp/tls 链级拒绝（G-SYSLOG-3）。
- **端口**：dst 缺省 514；src 通用默认 12345（可显式覆盖/0 上包，`chain_planner.go:924`）。
- **地址族**：v4/v6 双栈；异族混写由链基座拒绝（`SrcIP %s and DstIP %s must be same IP version`）。
- **确定性**：bsd 空 timestamp 与 IPv4 ID/校验和两处非确定（§5），断言面规避。

## 9. 原子 ID 与完成定义（1 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 | packet_count（实测 pcap 复核 2026-09-29） |
|---:|---|---|---|---:|
| 1 | `syslog_smoke_01` | 正 | §3.1：RFC 5424 空配置默认流（`<14>1 - - - - - -`） | 1 |

**包数公式**：`len(messages)>1` 时为 `len(messages)`（忽略 `count`）；否则为 `count`（缺省 1）。因此 `len(messages)==1,count=100` 生成 100 个数据报；仅多消息（`len(messages)>1`）形状忽略 `count`。校验：#1 无 messages/count 缺省 → 1 ✓。

**实测复核（2026-09-29，tshark 3.6.14 对 `/tmp/mcp-pcaps/syslog/syslog_smoke_01.pcap`）**：1 帧 60B（59 实发 +1 填充）；UDP 12345→514；payload 17B = `3c 31 34 3e 31 20 2d 20 2d 20 2d 20 2d 20 2d 20 2d`（`<14>1 - - - - - -`，offset 42 起，与用例 frames 断言逐字节一致）；`syslog.facility=1`、`syslog.level=6`、`syslog.version=1`、`syslog.msg="1 - - - - - -"`（tshark 3.6.14 的 `syslog.msg` 值域 = VERSION 起的剩余报文，非纯 MSG 部分——本例 MSG 为空，断言值与实测一致）；hostname/appname/procid 均为 `-`。4 条 fields 断言 + 1 条 frames 断言全命中。

## 10. P1 规范矩阵（八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | UDP 514 数据报上送（RFC 5426 §3.1/§3.3）；TCP/TLS 为另两载体 | 场景①⑤ | 链 `[ip,udp,syslog]` 单载体；tcp/tls 链级拒绝（`layer_gen.go:133-135`） | G-SYSLOG-3 |
| 2 | 报文格式 | RFC 5424 §6 全字段 + RFC 3164 §4 布局 | 场景①②③ | `encodeRFC5424`/`encodeBSD` 逐字段落码；BOM 线形偏离；sign 非 5848 | G-SYSLOG-5/6 |
| 3 | 状态机 | syslog 无状态机（无握手/序号/确认） | 全部 | 无状态纯函数生成 ✓ | 无 |
| 4 | 字段表 | PRI/VERSION/TIMESTAMP/HOSTNAME/APP-NAME/PROCID/MSGID/SD/MSG 逐字段（§3.1 表） | 数据场景层 | 全字段落码 + validator 上界 | 全字段面 pcap 例缺 → G-SYSLOG-7（citation drift 另记 G-SYSLOG-10） |
| 5 | 错误处理 | 越界/非法值拒绝 | 负例面 | 22 拒绝分支落码 | pcap 负例 0 条 → G-SYSLOG-7 |
| 6 | 超时与活性 | 无 keepalive/重试概念（fire-and-forget） | — | 无 ✓ | **显式不适用** |
| 7 | NAT/代理/被动 | 无此概念（客户端单向推） | — | 无 `sessions[]` 形态 | **显式不适用** |
| 8 | 版本/方言 | rfc5424（VERSION=1 强制）/ bsd 双格式 | 场景①③ | `format` 二值 + VERSION 门 | pcap 双格式例缺 → G-SYSLOG-7 |

八项重数：覆 **1**（行 3 无状态机，#1 已证）+ 立项 **5**（行 1/2/4/5/8）+ 不适用 **2**（行 6/7）= 8 ✓

### 10.2 子表①：消息形态 × 终态矩阵（逐格已覆/立项/不适用；"已覆"=pcap 契约面，单测面另注）

| 消息形态 | T1 正常产出 | T2 配置拒绝 | T3 传输异常终态 |
|---|---|---|---|
| RFC 5424 默认流 | 已覆（#1） | A′ 建负例（G-SYSLOG-7） | 不适用（UDP 无异常终态） |
| 显式字段集（TS/HOST/APP/PROCID/MSGID） | A′（单测已覆） | A′（锚词在案 :204/:271/:274） | 不适用 |
| SD-ELEMENT（双形+PEN） | A′（单测已覆） | A′（锚词在案 :291-:339 六分支） | 不适用 |
| BOM MSG | A′（单测钉现状线形） | 不适用（无 BOM 专属拒绝） | 不适用 |
| BSD 格式 | A′（单测已覆） | A′（锚词在案 :131/:140） | 不适用 |
| messages 多包 / count 复制 | A′（chain 单测已覆） | 不适用 | 不适用 |
| TCP/TLS 载体 | **待实现边界**（链拒绝，G-SYSLOG-3） | A′ 建负例（链级锚词在案，`layer_gen.go:133-135`） | **待实现边界** |

7 行 × 3 列 = 21 格：已覆 **1**（r1T1）/ A′ 立项 **10**（r1T2、r2T1/T2、r3T1/T2、r4T1、r5T1/T2、r6T1、r7T2）/ 待实现边界 **2**（r7T1/T3）/ 不适用 **8**（r1T3、r2T3、r3T3、r4T2/T3、r5T3、r6T2/T3）。1+10+2+8=21 ✓

### 10.3 子表②：数据形态变体表（协议相关全部形态；单测 = `internal/protocol/syslog` 188 Test 中可指名者）

| # | 变体 | 单测 | pcap 契约 |
|---:|---|---|---|
| 1 | 空配置默认流 `<14>1 - - - - - -` | ✓（MinimalMessage_NILVALUE） | **#1 已覆** |
| 2 | PRI 最小 `<0>`（facility0/sev0） | ✓（TestPoint_1_1_3_1_MinPRI） | A′ |
| 3 | PRI 最大 `<191>` | ✓（TestPoint_1_1_3_2_MaxPRI） | A′ |
| 4 | facility 逐值 0/1/15/16/22/23 | ✓（TestPoint_1_1_1_x ×6） | A′ |
| 5 | severity 逐值 0-7 | ✓（TestPoint_1_1_2_x ×8） | A′ |
| 6 | facility 24 / severity 8 拒绝 | ✓（TestPoint_1_1_4_x） | A′ 负例 |
| 7 | VERSION 缺省=1 / 显式 1 | ✓（TestPoint_1_2_1） | A′ |
| 8 | VERSION=0：rfc5424 拒 / bsd 放行 | ✓（VersionZeroRfc5424Fails/BsdOk） | A′（负例） |
| 9 | TIMESTAMP RFC3339/NILVALUE（空与 `-`） | ✓（TimestampEmpty/Dash/RFC3339） | A′ |
| 10 | TIMESTAMP 非法拒绝 | ✓（TimestampInvalid） | A′ 负例 |
| 11 | 四字段上界 255/48/128/32 | ✓（Hostname/AppName/ProcID/MsgID TooLong） | A′ |
| 12 | 四字段含 SP 拒绝 | ✓（HostnameContainsSP） | A′ 负例 |
| 13 | SD bare 形自动包装 / 预框形 / @PEN / 多元素 | ✓（SDElement_x ×5） | A′ |
| 14 | SD 转义（SignBlocks 值 `"` `\` `]`） | ✓（SignBlocks_EscapedQuote 等 ×4） | A′ |
| 15 | SD 非法拒绝六分支 | ✓（SDUnclosed/SDEmpty/SDIDTooLong） | A′ 负例 |
| 16 | MSG ASCII/UTF-8 + BOM 三态（有/无/空 MSG） | ✓（Msg_x ×4） | A′ |
| 17 | BSD 全形 / 无 PID / 日补空格 | ✓（BSD_x ×4） | A′ |
| 18 | messages 多包（Count 忽略）+ 逐消息覆盖 | ✓（MultiPayload ×8 + chain ×1） | A′ |
| 19 | count>1 复制 | ✓（CountZero/Count10 + chain ×1） | A′ |
| 20 | TCP octet_counting / non_transparent 分帧 | ✓（TCP_x ×3，legacy 面） | **待实现边界**（G-SYSLOG-3） |
| 21 | IPv4/IPv6 EtherType | ✓（IPv4/IPv6_EtherType） | A′ |
| 22 | Metadata syslog_priority/syslog_transport | ✓（Metadata_PriorityTransport + chain） | A′ |
| 23 | UDP 上界：顶层单消息近似预检 >65507 | 分支在案（`:249-259`），**仅估算 `cfg.Msg` 与顶层 StructuredData，未检查 `messages[]` 各条目或最终编码长度；单测亦无** | A′ 负例（需分别覆盖顶层近似拒绝与 `messages[]` 漏检边界；当前不得称为完整上界覆盖） |

23 行：pcap 已覆 **1**（行 1）/ 单测已覆待收编 pcap **20**（行 2-22，**行 23 除外——该分支单测亦无**）/ 待实现边界 **1**（行 20）/ 分支在案 **1**（行 23）。1+20+1+1=23 ✓

**计数口径**：行 20（TCP 分帧）单测已覆但链不可达 → 计入"待实现边界"不计"待收编"；行 23 分支落码但无任何测试 → 计入"分支在案"。两处均不在"已覆"列。

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 主机/设备上送日志到集中收集器（RFC 5426 §1 典型部署） | #1 | 已覆（默认字段面） |
| 2 | 带结构化元数据的审计日志（SD-ELEMENT） | — | A′ 立项 |
| 3 | 旧设备 BSD 格式兼容（RFC 3164 存量） | — | A′ 立项 |
| 4 | 批量连续上送（多消息/高频） | — | A′ 立项 |
| 5 | 多设备同收多流并发 | — | A′ 立项（`flow_control`） |
| 6 | 签名日志（RFC 5848 syslog-sign） | — | **明确不解决**（实现非 5848 口径，G-SYSLOG-6） |
| 7 | TLS 加密日志上送（RFC 5425） | — | **待实现边界**（G-SYSLOG-3） |
| 8 | 真实收集器入库/过滤语义 | — | **明确不解决**（生成器不模拟服务端） |

3 类已覆/A′ 之外的 5 项显式定性。1 已覆 + 4 A′ + 2 明确不解决 + 1 待实现边界 = 8 ✓

### 10.5 三路对照与候选方案对比

三路：①规范原文（RFC 5424/3164/5426/6587/5425，2026-09-29 原文核对——本轮以原文校正代码注释三处章节漂移与 sign 语义偏差）；②商业化软件实际行为（**未取到**：真实 syslog 服务器/rsyslog-syslogng 的线字节未抓包核对 → 与 G-SYSLOG-8 同批归代码阶段补证）；③可靠开源实现思路（仅借鉴"BSD 日补空格/SD 转义三字符"共识，无代码借鉴）。三路一致点：PRI 公式、字段序、NILVALUE、分帧两法；不一致点：BOM 是否替换 SP（G-SYSLOG-5）、sign SD-ID 取值（G-SYSLOG-6）。

| 方案 | 走法 | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `syslog` 终结层（本版现状；ntp/snmp 同构波 4 先例） | 消息面可声明可断言；代价 = 配置只能住顶层子映射（空壳层） | **采用**（as-built） |
| B | 直接 udp 层 + 顶层 payload | 无 syslog 字段断言（tshark `syslog.*` 不可用）、无 PRI 结构 | 否决 |
| C | 层内承载全部 17 配置键（registry Fields 全登记） | 需 translate 层内分支 + 17 键 schema；与波 4 "配置经 FlowMeta 直传" 框架约定冲突 | 否决（G-SYSLOG-1 收敛另议：登记字段或维持 FlowMeta 直传 + 顶层键白名单化） |

## 11. P2 D-SYSLOG-1 代码设计（as-built 逆向定稿）

> 状态说明：实现已落码，本 P2 条目为对既有实现的逆向定稿，供后续改动的唯一入口；本协议内 P4 为"缺口收敛"，不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `internal/core/types.go`（`:8030-8087` + `:8094-8115` + `:1871`） | `SyslogConfig`（17 键）/`SyslogMessage`（9 覆盖键）+ `FlowSpec.Syslog` 槽位 | —（共享文件） |
| `internal/protocol/syslog/planner.go` | Validate（22 分支）+ Plan/emitUDP/emitTCP + encodeRFC5424/encodeBSD | 918 |
| `internal/protocol/syslog/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator`+`RegisterLayerValidator`，init） | 138 |
| `internal/protocol/syslog/planner_test.go` | 编码/校验/emit 面 69 Test | 988 |
| `internal/protocol/syslog/planner_testpoints_test.go` | TestPoint 规格 derived 99 Test | 1324 |
| `internal/protocol/syslog/planner_multipayload_test.go` | 多包面 20 Test | 404 |
| 接线 6 件 | registry（`layers/registry.go:167-169`）/ translate Meta 直传（`chain_planner_translate.go:53-61`）/ convert 子配置解析（`strategy_convert.go:1499-1521`）+ SD/Messages/Sign 解析（`:6691-6797`）/ protocols 准入（`protocols.go:57`）/ 缺省端口（`chain_planner.go:1046-1053`）+ src 放行（`:924`）/ main 空导入+注册（`main.go:162/:547`） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`planner.go:90`）：IP 形 + `validateSyslogConfig`（`:109-262`，与链校验器共用同一实现，`layer_gen.go:129-137` 追加 tcp/tls 链级拒绝）。nil config 放行（P0b-2）。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`:346`）：默认化→编码（messages 分支/单消息分支）→ `emitUDP`（udp）/`emitTCP`（tcp/tls，链不可达）。
- `SyslogGenerator.Generate(ctx, req)`（`layer_gen.go:29`）：事件流同源编码；`GenEvents()` 标记；`EmitEvent` 未接线显式报错（`:120-122` 防误调）。

### 11.3 数据结构

`SyslogConfig{Facility, Severity uint8; Version uint8; Timestamp, Hostname, AppName, ProcID, MsgID string; StructuredData []string; Msg string; MsgHasBOM bool; Format, Transport, TCPFraming string; Count uint32; SignBlocks []string; Messages []SyslogMessage}`（17 键，json 标签见 `types.go:8030-8087`）；`SyslogMessage{Timestamp, Hostname, AppName, ProcID, MsgID, StructuredData, Msg, MsgHasBOM, SignBlocks}`（9 覆盖键，零值=继承父级）。

### 11.4 主流程

层链配置（顶层 `syslog` 子映射 → `strategy_convert.go:1499` 解析入 `spec.Syslog`；层内 `{"syslog":{}}` 仅占位）→ `ValidateLayers`（registry Fields 空 → 层内键即拒）→ 链校验器（`validateSyslogConfig` + tcp/tls 门）→ 生成器 `Generate`（默认化→编码→逐事件 `EmitMsg`）→ udp 层 Inner 模式（每事件一数据报，Metadata 合并）→ ip/eth 层 → writer（PCAP/NIC）。

### 11.5 错误分支

22 拒绝分支（§7 表）全部传 task error；链级 3 门（tcp/tls、unknown field、flat 五键）。零假成功（存量唯一正例 pcap 1 帧与配置吻合）。死代码两处（G-SYSLOG-2）：`DefaultFacility/DefaultSeverity` 常量声明未用（`planner.go:74-75`）；`:368-374` 空 if 体死分支。

### 11.6 性能边界

见 §6（事件线性产出、per-flow 局部状态、无跨流共享、无锁）。

### 11.7 与现有逻辑的冲突点

- `CheckProtoFlat` **无 syslog 分支**（`grep` 实测零命中）→ 顶层 `syslog` 子映射 presence **不判死**——与 dns/mqtt/cwmp 等已登记协议不同；存量 1/1 例正带顶层子映射在跑。禁加单协议黑名单分支（kingbase 裁定），等框架级 unknown-key 白名单（G-SYSLOG-1）。
- 动态 allowlist（`internal/core/layer_dyn.go` 头部）：`syslog` **零命中**实测 → 业务字段动态对象即拒；四元组 `ip`/`udp` 全开。见 §12.12。
- registry `syslog` **无 Fields**（空壳层）→ 层内任何键 400（`complete.go:293`）；生成 schema 表 127 层同代（`layers.generated.json:4178` `"fields":{}`，机读实测）。
- 空配置默认流 PRI=0 与扁平缺省 PRI=14 两副面孔（G-SYSLOG-2，§3.2）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 3 源/测文件 + 接线 6 处（registry/protocols/translate/convert/chain_planner/main）；不触及其他协议。cases 回滚 = 恢复 1 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 1/1 顶层 = `{layers, syslog}`——**非负例顶层键 = 1（红，未达标）**；as-built 目标形状 = 层链 + 顶层 `syslog` 子映射（配置唯一可达入口，G-SYSLOG-1）；旧键去向逐键列明 | §12.1；`cases/syslog.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 syslog 流量模板（§2 样例）；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：单 UDP 会话/单事务/无流关联（显式不适用）/终结层插入/单包时间线 | §12.3 + §5 |
| §4 查规范 | RFC 5424/3164/5426/6587/5425 原文（2026-09-29 核对，章节号已校正代码漂移）+ tshark 3.6.14 字段/绑定实测 + 落码反推；八项矩阵 + 三子表 | §10 |
| §5 依赖与错误 | `DependsOn ["udp"]` 单值（`registry.go:167-169`）；22+3 拒绝分支；失败传 task error | §7/§11.5 |
| §6 性能 | §6 六要素齐（pcap/NIC 两路明写；吞吐归生成器配置不重复定义） | §6 |
| §7 三份文档 | `131-syslog-{design,testcase}.md` v1.0.0（本版）+ `cases/syslog.json` 1 例（机器契约）；无旧稿层 | 修订记录 |
| §8 设计先行 | 本轨为 as-built 逆向定稿（代码已先行落地，文档补契约）；缺口收敛（P4）按本版执行 | §11 状态说明 |
| §9 测试三源 | 三源 = RFC 原文（§10）+ D-SYSLOG-1（§11）+ tshark 3.6.14 字段与 pcap 实测（**断言级复核**：#1 的 4 fields+1 frames 逐条对 2026-09-27 pcap 复核命中，§9）；存量 1 例审计去向 testcase §8 | testcase §2/§5/§8 |
| §10 评审闭环 | 本车道机读自审 5 轮（脚本复核计数/断言/行号，含 3 轮修复；末轮起连续 2 轮 31 项零失败）；主线程隔离复审按队列另排（本车道不冒充已过） | 自审脚本 `/tmp/pipe/doc-lanes/syslog-selfaudit.py` 输出 |
| §11 白话 | 白话一句先行（文首）+ 每章关键裁定白话化 | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组 ip/udp 全开；业务字段 17 项全关 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `syslog` 已在 registry 注册（**不新增层**）；生成表 127 层同代（`layers.generated.json:4178` fields 空 map 与 registry 逐键一致，机读实测）；G-SYSLOG-1 若改 Fields 必须重跑 schemagen | §11.1/§11.7 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `syslog.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/syslog/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 |
|---|---|---|---|---|
| `cases/syslog.json` | 1 | `{layers, syslog}` ×1（**非负例顶层键 1 处**） | `[udp,syslog]` ×1 | 0 |

**旧键去向表**：

| 键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 目标形 = `layers[i].ip.src/dst`（缺省 flow 默认 10.0.0.1/20.0.0.1，`strategy_convert.go:43-44`） |
| `src_port` | **0** | 目标形 = `layers[i].udp.src_port`；缺省 12345 上包（`chain_planner.go:924` 放行），存量不断言 |
| `dst_port` | **0** | 目标形 = `layers[i].udp.dst_port`；链缺省 514（`chain_planner.go:1046-1053`），存量不断言 |
| `count`（顶层） | **0** | 顶层已判死（CheckProtoFlat 五键）；流数走 `flow_control`，包内复制数走 `syslog.count` |
| **顶层 `syslog` 子映射** | **1/1** | **仍住顶层且是配置唯一可达入口**（registry 层 Fields 空 → 层内键 400；translate 无层内 case，配置经 FlowMeta 直传，`chain_planner_translate.go:53-61`）→ **G-SYSLOG-1**；空 map 也承载缺省 1/6/1（`strategy_convert.go:1501-1503`），删键即变 PRI=0（G-SYSLOG-2） |
| `strategy_fc` / `flow_control` | **0** | 本协议无用例；多流目标形按需加 |

**结论**：本协议存量**非负例顶层键 = 1 ≠ 0（红）**——§1 门动作 = ①顶层 `syslog` 键今日**不可删**（删则断言值变 `<0>`，G-SYSLOG-2 收敛前删除即破坏用例）；②G-SYSLOG-1 收敛（registry Fields 登记 + translate 层内 case + presence 门）后方可迁层内并重建零残留；③A′ 新增例在 G-SYSLOG-1 收敛前**沿用 as-built 形**（§2 样例一），不得虚构纯层链形。

> **注（2026-09-29 机读）**：同形"空壳层 + 顶层协议子映射"的波 4 兄弟层为 ntp/snmp（同批 FlowMeta 直传），非 syslog 独有；本协议特有事实是**存量仅 1 例且已依赖该形状的缺省值**。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"syslog":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 syslog 分支，grep 实测）→ **P4 不建该负例**（建了会真绿 = 假通过）→ G-SYSLOG-1 登记。② 白名单外游离键判死（`unknown field`）今日**亦无通用门** → 同 G-SYSLOG-1，P4 不建。③ 负例今日 **0 条**（22 分支锚词全部 A′，G-SYSLOG-7）。④ 收官自查「非负例顶层键 = 0」**今日不成立（1 处，红）**（§12.1）。

### 12.3 §3 强制展开：五件套

会话表：`s1` 单 UDP 会话基线（#1；UDP 无连接，"会话"= 单流四元组上的 datagram 序列，无握手挥手）。事务：`t1` 单事务 = 一数据报一消息（fire-and-forget，无响应无确认）；`messages`/`count` 是同流多事务的顺序展开（A′）。关联关系：**无派生流**（UDP 单向推，无控制流/数据流主从；显式不适用）。插入位置：终结层（`[ip,udp,syslog]`，无中间层）。时间线：datagram 按事件序线性展开，无交错（`concurrent` 例外路径不启用）；消息内严格按 §3.1 字段序。**长连接豁免不适用**——本协议无长连接载体（TCP 链不可达），`sessions[]` 数组形态不存在（无豁免声明需要）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst`、`udp.src_port/dst_port` 四策略全开（allowlist `internal/core/layer_dyn.go` 头部实测：`ip`/`tcp`/`udp`/`eth`；保底 `DefaultSrcPort=12345`（`strategy_convert.go:49`），多流 worker 保底自增）。

**业务字段 17 项全关**（allowlist 无 `syslog` 行，grep 零命中实测；对象即拒 `does not support dynamic`）：`facility`/`severity`/`version`（协议级标量，逐流变无意义）/ `timestamp`/`hostname`/`app_name`/`proc_id`/`msg_id`（消息面标量——**逐流变体有真实需求**（模拟多主机/多进程），列 A′ 候选 G-SYSLOG-7）/ `structured_data`/`messages`/`sign_blocks`（列表对象，无动态形状）/ `msg`（正文标量，同前候选）/ `msg_has_bom`（布尔开关）/ `format`/`transport`/`tcp_framing`（结构选择器）/ `count`（数量控制，与 `flow_control` 分工）。

序号算法实读：`parseLayerDyn`（`layer_dyn.go:78` 起）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go` 头部）——**`syslog` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。动态算出的值只落 `ip`/`udp` 层对应字段，不另起顶层字段。

## 13. P3 对接清单（T-SYSLOG 输入；正文落 testcase 文件）

1 ID（1 正 + 0 负）+ packet_count + 断言 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§8 全量）。A′ 候选（最小闭环集，全部链级可执行）：`syslog_neg_facility_overflow`（:119）/ `syslog_neg_severity_overflow`（:122）/ `syslog_neg_format_unknown`（:131）/ `syslog_neg_version0_rfc5424`（:140）/ `syslog_neg_transport_tcp`（链级 :133）/ `syslog_neg_timestamp_invalid`（:204）/ `syslog_neg_field_too_long`（:274）/ `syslog_neg_sd_unclosed`（:297）/ `syslog_full_fields`（显式全字段面）/ `syslog_bsd_format`（bsd 预格式时间钉死）/ `syslog_multi_message`（messages 双包）/ `syslog_count_copies`（count=3）/ `syslog_ipv6`（offset 62 = 14+40+8）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-SYSLOG-1 | **层空壳 + 顶层子映射承载配置**：registry syslog 无 Fields（`layers.generated.json:4178`）、translate 无层内 case（配置经 FlowMeta 直传）→ 层内任意键 400；配置唯一入口 = 顶层 `syslog` 子映射 = **非负例顶层键 1/1（红，违反 1.11-1.13 白名单验收口径）**；且 `CheckProtoFlat` 无 syslog 分支 → presence 不判死，presence 负例今日**不建**（假绿） | P4/B′ 框架面：等框架级 unknown-key 白名单 + registry Fields 裁定（登记 17 键或顶层键白名单化）；**禁加单协议黑名单分支**（kingbase 裁定）；收敛前 A′ 例沿用 as-built 形 |
| G-SYSLOG-2 | **facility/severity 缺省断层**：1/6 缺省只住扁平解析（`strategy_convert.go:1501-1502`）；空层链（`spec.Syslog=nil` 或无顶层键）→ 生成器无兜底 → **PRI=0**（`<0>1 - - - - - -`），与存量 `<14>` 两副面孔；`DefaultFacility/DefaultSeverity` 声明未用（`planner.go:74-75`）+ `:368-374` 空 if 死分支 | P4：生成器/链缺省补 1/6 或删死常量二选一（failing-test-first：先钉 `<0>` vs `<14>` 分歧例）；修后存量 #1 断言不受影响（仍带顶层键） |
| G-SYSLOG-3 | **TCP/TLS 载体链不可达**：层校验器拒 tcp/tls（`layer_gen.go:133-135`）；legacy `emitTCP`（RFC 6587 分帧 + MSS 分段 + 握手挥手）未注册生产路径；单测已覆分帧面（TCP_x ×3）但 pcap 契约零例 | 待实现边界：A′ 接线（链放行 + 分帧正负例）或**明确不解决**；接线时同步处理 tshark 514→rsh 绑定（G-SYSLOG-12） |
| G-SYSLOG-4 | **长度上界无完整强制**：RFC 5424 §6.1（480 最低支持/2048 SHOULD）、RFC 5426 §3.2（v4 480/v6 1180/2048）、RFC 3164 §4.1（≤1024）均无检查；仅有 UDP 65507 的**固定近似预检**（`planner.go:249-259`，只读 `cfg.Msg` 与顶层 `cfg.StructuredData`，未遍历/编码 `Messages`） | A′ 分别补顶层近似拒绝与 `messages[]` 超限/临界值边界；在精确编码检查落码前，不得声称已覆盖通用 UDP 上界；480/2048 属 SHOULD/接收方要求 → **明确不解决**（生成器不裁剪用户报文），文档钉死口径 |
| G-SYSLOG-5 | **BOM 线形偏离**：实现 BOM 替换 SP（`planner.go:752-759`，线形 `SD BOM MSG`）；RFC 5424 §6.4 ABNF 为 `[SP MSG]` 且 MSG-UTF8 以 BOM 开头（线形 `SD SP BOM MSG`）——实现少一个 SP；单测按现状钉死（Msg_ASCII_WithBOM） | P4 裁定：改线形补 SP（重钉单测+新 pcap 例）或**明确不解决**并钉现状；两路均须在文档/用例口径去"RFC 合规 BOM"表述 |
| G-SYSLOG-6 | **sign_blocks 非 RFC 5848**：实现 `[sign@32473 signature="…"]`（`:736-740`）；RFC 5848 §4.2 SD-ID 恒 `ssign`、参数 VER/RSID/SG/SPRI/GBC/FMN/CNT/HB/SIGN（无 `signature`） | **明确不解决**（定性 = 通用 SD-ELEMENT 便捷写法，不声称 syslog-sign 合规）；用例/文档不得引 5848 章节作为该键依据 |
| G-SYSLOG-7 | **pcap 契约覆盖 = 1/1 冒烟**：22 拒绝分支 0 负例；显式字段/SD/BOM/BSD/messages/count/IPv6/Metadata 断言全缺（单测 188 Test 已覆编码行为）；业务字段动态全关（allowlist 无 syslog 行） | A′ 全量立项（§13 最小闭环集 13 例起步）；动态字段逐流变体（hostname/msg 模拟多主机）列候选，不冒充已覆盖 |
| G-SYSLOG-8 | **结果文档过期**：`trafficgen/docs/protocol-pcap-test/syslog.md`（tracked，仓根相对路径）"Cases: 1 — pass 1" 末次提交 `e7e7d1c`（2026-08-27）早于判死提交 `0417be5`（2026-09-13）；`trafficgen/docs/protocol-pcap-test/syslog/` **0 个 pcap**。本车道对 `/tmp/mcp-pcaps/syslog/syslog_smoke_01.pcap`（2026-09-27）复核 4+1 断言全命中，但**不得冒充套件今日复跑** | 代码阶段（P5 重跑套件后重生成产物）；本版不删不改 tracked 产物，读者不得据此判断已复跑（口径 = pcep G-PCEP-11） |
| G-SYSLOG-9 | **死引用**：`planner.go` 注释引 `design_syslog.md`/`testcases_syslog.md`/`validate_conventions.md`——仓内与本机均不存在 | 文档面已按落码+RFC 重钉（本版）；注释清理归代码阶段顺手项，不独立立项 |
| G-SYSLOG-10 | **RFC 章节引用漂移**：代码注释/错误文案引 §6.2.8（实为 §6.3.x）、§6.4.4（不存在，BOM 实为 §6.4）、§6.2（字段上界实为 §6.2.4-6.2.7）；锚词字面不受影响（负例按文案子串匹配） | 代码阶段顺手修（错误文案含 § 号者改动即动锚词，须与负例同步）；本版文档一律引正确章节 |
| G-SYSLOG-11 | **存量 notes 文案错误**：①"msg 尾部含 0x00 终止符"——实为 `pad_min_frame` 默认 ON 的 60B 最小帧填充（帧 59→60，UDP payload 恰 17B 无 NUL；证据：pcap hexdump + `mcp/padding_inspect_test.go` "default ON -> padded to 60"）；②"仅做帧前缀断言"——实为**全 payload 断言**（17B 恰等）；③summary "facility=1(2)" 的 "(2)" 无对应语义（疑笔误） | P4 改写 `expect.notes`（同 opcua G-OPCUA-7 P4 动作；断言本体全对，仅文案修正） |
| G-SYSLOG-12 | **tshark TCP 514 绑定为 rsh**（`tshark -G decodes` 实测：`tcp.port 514 rsh`，无 syslog 绑定；UDP 514→syslog ✓ 12 字段可用）——G-SYSLOG-3 接线后 TCP 用例在 514 上默认不解码 | 随 G-SYSLOG-3：用例须 `decode_as` 或 fixture 改非 514 端口 |

## 15. 修订记录

- v1.0.0（2026-09-29）：P-PIPE 文档轨批次二 as-built 首版。存量 1 例机读审计（**非负例顶层键 1 处红**，as-built 形钉死）；RFC 5424/3164/5426/6587/5425 原文核对并校正代码三处章节漂移；线格式逐字段定稿（§3，含 BOM 偏离/sign 非 5848 两处诚实边界）；P1 矩阵 + 三子表（21 格/23 行/8 行全计满）；D-SYSLOG-1 as-built 定稿（§11）；门1 十四行 + §12.1/12-P2/12.3/12.12 强制展开；缺口 G-SYSLOG-1…G-SYSLOG-12。pcap 断言复核（#1 的 4 fields + 1 frames 对 2026-09-27 pcap 全命中）。自审 5 轮（脚本机读，含 3 轮修复），末轮干净（连续 2 轮 31 项零失败）（脚本 `/tmp/pipe/doc-lanes/syslog-selfaudit.py`）。

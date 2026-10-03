# probe_smb（SMB 轻量探测诊断族）设计契约

> 版本：v1.1.0（静态闭环）
> 日期：2026-10-01
> 状态：SMB 探测诊断族设计与 PCAP 用例契约；**`probe` 无独立层名、无独立协议名**，本族归并 `smb` 协议。未执行 suite/MCP/NIC，不宣称运行通过。
> 配套文件：`docs/protocols/probe_smb/testcase.md`、`trafficgen/test/protocol_pcap/cases/probe_smb.json`
> 规范基线：MS-SMB2（SMB2/SMB3 线格式与会话状态机；本仓库引用面见 `docs/protocol-designs/07-smb-design.md`）+ CORE_MEMORY §1/§3/§12。

## 1. 范围、归属裁定与证据等级

本族定义 **SMB 轻量探测**（下文简称 probe）：在同一 TCP 连接上跑通一次最小 SMB2 会话（默认保底阶段 + 0–1 个数据操作），用于层链接线回归与操作支路的定向诊断。probe **不是新协议**——它是对 `smb` 终结层已有能力的定向调用，因此本文不含任何新线格式定义，只定义"怎么配、断言什么、边界在哪"。

### 1.1 归属三问实读（逐项实测，不猜）

| 问 | 实读结果 | 证据（文件:行） |
|---|---|---|
| 有独立 `probe` 层名吗？ | **无** | `internal/core/layers/registry.go` 全文件 grep `probe` → 0 命中；`r.Register(LayerSchema{Name: "smb", ...})` 为唯一 smb 行（`registry.go:1477`） |
| 有独立 `probe` 协议名吗？ | **无** | `internal/core/protocols.go` 全文件无 `probe`；`"smb": true` 在 `protocols.go:55` |
| 用例文件怎么归属？ | **`proto=smb`**（文件名 ≠ proto 字段，框架已认账） | `cases/probe_smb.json` 12 例均 `"proto":"smb"`；`test/protocol_pcap/verify_all_test.go:62` 注释"文件名与 proto 字段可能不同（如 cases/probe_smb.json 声明 proto=smb）" |
| 诊断族怎么被外部工具识别？ | **按 ID 前缀 `probe_`**，且明确"不是 296 例套件的一部分" | `test/protocol_pcap/deep_audit.py:150-151`（`case_id.startswith("probe_")`）、`:192-198`（无 case 文件时按诊断族归入 expected） |
| 引擎侧接线现状 | `smb` 已翻到链规划器 | `cmd/server/main.go:618` `app.engine.RegisterPlanner(layers.NewChainPlanner("smb"))` |

**裁定 P1（归属）**：probe = **smb 的子例族**（诊断族），**不立项**独立层/独立协议名。理由：①无任何注册面证据支持独立层（上表两行零命中）；②probe 用例的线上字节完全由 `smb` 层生成器产出（`internal/protocol/smb/layer_gen.go`），自建独立层等于复制 smb 语义；③外部工具链已按"同 proto + `probe_` 前缀"识别本族（deep_audit.py 口径）。按 CORE_MEMORY 1.12，"换个名字登记保留"不是合法收口——本族不需要保留，它本来就住在 smb 里。

### 1.2 编号裁定

INDEX（`docs/protocol-designs/INDEX.md` §6.3）规定设计文档编号 `NN` 为 00–77，且"文档编号与 00-unimplemented-list.md 表格编号一致"。逐号实测：01–18 在册（§3.1–§3.9），19–77 在册（§3.10–§3.12，其中 03/04 由合并文档 `02-03-04-jt808-jt809-jtt905-design.md` 覆盖）→ **00–77 已占满**。本族取顺延号 **78**，并在主线程集成动作里登记 INDEX（§18 缺口 G-PROBE-SMB-3：INDEX §6.3 的 00–77 上限需随之修订或补"顺延号"条款）。备选"并入 07 家族子号（如 07b）"被否：INDEX 无子号规则，且 07 号已是 smb 设计+用例合一的历史体裁，双头维护违反 §7.4/§7.7。

### 1.3 今日可达边界（不许把目标形状写成现状）

`smb` 业务配置今日走严格层链：`layers[].smb` → `spec.SMB`。实读链路：

| 环节 | 现状 | 证据 |
|---|---|---|
| 配置 → FlowSpec | 层内 `smb` 业务键转为 `spec.SMB` | `chain_planner_translate.go:2942-2954`（`TranslateSMBConfigFromMap`） |
| 层内 smb 业务键 → FlowSpec | **已有翻译分支** | `internal/core/layers/chain_planner_translate.go:2942-2954`；空层也生成默认非 nil 配置 |
| FlowSpec → 生成器 | `Meta.SMB = spec.SMB`，nil 即硬错 | `chain_planner_translate.go:191`；`internal/protocol/smb/layer_gen.go:504` `smb generator: no config (spec.smb required)` |
| 层内业务键的 schema 面 | **已登记并消费**（38 字段） | `registry.go:1477-1518`；`chain_planner_translate.go:2942-2954` |

结论：**严格层链形状（业务键住 smb 层）已可跑通**；层链校验拒绝顶层 `smb` 子映射，旧过渡形已从本族 12 例清除。

## 2. 推荐配置与协议栈

严格层链形状（业务键住 smb 层，12 个 probe 用例均采用此形）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.100", "dst": "10.0.0.1"}},
    {"tcp": {"dst_port": 445}},
    {"smb": {"operations": [{"op_type": "close"}]}}
  ],
  "flow_control": {"type": "flows", "value": 1}
}
```

| 键 | 约束 | 证据 |
|---|---|---|
| `layers[].ip.src/dst` | 地址唯一住处（1.1） | `validate_layers.go` 层链校验；`layer_dyn.go:17-21` 允许动态的层字段表 |
| `layers[].tcp.dst_port` | 端口唯一住处（1.2）；probe 面 445（direct）或 139（netbios） | `chain_planner.go:1249-1258`（`case "smb"`：`transport=netbios → 139`，否则 445） |
| `layers[].smb` | 终结层条目；承载业务键，空对象触发默认会话 | `registry.go:1477` `Category: CategoryTerminal, DependsOn ["tcp"]` |
| `smb.operations` | 探测操作面；空 → 默认单 `read`（`validate.go:307-309`） | `internal/protocol/smb/validate.go:307-309` |
| `smb.error_on_command` | 错误注入支路（§12 负例与 §9 非正常结束用） | `registry.go:1477-1518`；`layer_gen.go:446` 抑制规则 |
| `strategy_fc` / `flow_control` | 12 例中多流例使用 `strategy_fc: {"type":"flows","value":2}`；数量不写入 `spec_json` | `probe_multi_flow_dynamic`；其余单流默认 1 |
| （禁止）顶层 `src_ip/dst_ip/src_port/dst_port/count` | 判死锚词见 §12 | `strategy_convert.go:8641-8644`、`schema/semantic.go:131` |

## 3. 外层传输与固定偏移

probe 走 TCP；无 Ethernet VLAN / IPv4 options / IPv6 扩展头时：

| 载体 | NBSS 起点 | SMB2 头起点 | CLOSE 请求体起点 |
|---|---:|---:|---:|
| Ethernet + IPv4 + TCP | 54（14+20+20） | 58（+4 NBSS） | 122（+64 SMB2 头） |
| Ethernet + IPv6 + TCP | 74（14+40+20） | 78（+4 NBSS） | 142（+64 SMB2 头） |

- NBSS 头 4 字节（type 0x00 session message + 3 字节长度），SMB2 头 64 字节（13 具名字段，MS-SMB2 §2.2.1.2，见 `07-smb-design.md:140`）。
- 偏移 122 有落盘实证口径：`cases/smb.json` 的 close 族 frames 断言即在 offset 122 读 CLOSE 请求体首字段（请求 `18 00 00 00 00 00 00 00` = StructureSize 24 + Flags + Reserved；响应 `3c 00 00 00` = StructureSize 60）。probe 家族沿用同一偏移，不手算新值（§13 断言以 P5 落盘 pcap 复算为准）。
- IPv6 三偏移（74/78/142）按 40B 扩展头推导，**非**帧钉值：编号 7 fixture 仅断言 `ipv6.src/dst` 与 `smb2.cmd`，未用 `frames` 钉 74/78/142；P5 若需钉，先跑后钉复算（9.31/14.20）。
- NBSS 长度字段覆盖面在 P5 以 `nbss.length` 断言（tshark 实测该字段存在，见 §7 子表②）。
- NBSS 长度只覆盖一条 PDU（本生成器一条 message 一 PDU，不做 compound 合并——B′ 注记，见 §18 B′-3）。

## 4. 会话状态机与探测操作面

**八阶段最小序**（`internal/protocol/smb/layer_gen.go` 的 emit 序；设计表见 `07-smb-design.md:751-757`）：

```
TCP 握手 3 包 → NEGOTIATE(0x0000) → SESSION_SETUP(0x0001)×AuthRounds
→ TREE_CONNECT(0x0003) → CREATE(0x0005) → Operations(0–N)
→ CLOSE(0x0006) → TREE_DISCONNECT(0x0004) → LOGOFF(0x0002)
→ TCP 拆解 4 包
```

**CLOSE 抑制规则**（probe 的核心诊断点）：Operations 后 CLOSE 是强制拆解，但已发过就不重发——`layer_gen.go:444-451`：

```go
closeAlreadyEmitted := (opsErrored && stopAfter == "close") || closeOpEmitted
if !closeAlreadyEmitted { /* 发隐式 CLOSE 对 */ }
```

`closeOpEmitted` 由显式 `op_type: "close"` 置位（`layer_gen.go:364-370`），legacy 同一规则（`smb.go:277-280`）。**probe 家族的诊断靶心就是这条规则**：显式 close 只能出现一对，不得「隐式 + 显式」双发。

**操作面**（`layer_gen.go:324-441` switch 全枚举 + `validate.go:105-106` 白名单）：

| op_type | 命令码 | probe 用途 |
|---|---|---|
| `read` | 0x0008 | 默认操作（operations 空时的保底，`validate.go:308`） |
| `write` | 0x0009 | 多轮操作组合 |
| `close` | 0x0006 | 显式拆解（本族主靶） |
| `query_directory` / `query_info` / `lock`（存量套件有例） | 0x000E / 0x0010 / 0x000A | **不编入 probe 家族**（覆盖面归 smb 套件；230 例<无显式 operations> + 18 write + 5 read + 4 read/write 等已覆盖） |
| `set_info` / `flush` / `ioctl` | 0x0011 / 0x0007 / 0x000B | **不编入 probe 家族**（`validate.go` 白名单合法；smb 套件覆盖） |
| `echo` | 0x000D | 同连接活性探测（§9 长保活项） |

命令码常量：`internal/protocol/smb/constants.go:35-53`。认证轮数默认：`AuthMechanism` 空 → `ntlm` → `AuthRounds=3`（`validate.go:226-231` + `constants.go:282-291`，ntlm=3 / kerberos=2 / anonymous·guest=1）。

## 5. 探测族语义与分工

**"轻量"的定义（可判定的三条）**：①单会话（一个四元组一次 `NEGOTIATE…LOGOFF`）；②操作面 ≤1 个数据操作（多轮例除外，见 §13 编号 3）；③单例包数下限族（约 25 包量级），不做大载荷、不做多会话编排。

**分工（不双头）**：

| 面 | 归谁 | 说明 |
|---|---|---|
| 命令×方言×错误码全矩阵、多会话、多流编排、NAT/代理 | **smb 套件**（`cases/smb.json` 296 例 = 279 正 + 17 负，实测） | probe 家族不重复建例 |
| 层链接线回归 + 操作支路定向诊断（close 抑制、默认保底、错误注入、活性、载体、地址族、多流保底、双输出） | **probe 家族**（`cases/probe_smb.json`，§13 12 例） | 每例只查一个诊断目标 |

**台账口径**：probe 家族不计入 smb 套件的覆盖反查分母；当前 `cases/smb.json` 为 296 例（279 正 + 17 负）。

## 6. 载体、地址族与多流

- **载体**：445（Direct TCP，默认）与 139（NetBIOS Session Service，`transport=netbios`）各一例；两载体是独立 fixture，不可互推（1.11 端口住 tcp 层，缺省化在 `chain_planner.go:1249-1258`）。
- **地址族**：IPv4 与 IPv6 各一例（9.24 对称覆盖：IPv4 由主例代表，IPv6 独立建例，不互推）。IPv6 下 NBSS/SMB2 偏移整体 +20（§3 表），字段断言面不变。
- **多流**：`flow_control.flows=2` 时必须显式动态四元组（9.39 互斥铁律：flows>1 的层链四元组字段留空或写动态对象）。probe 多流例用 `tcp.src_port` 动态对象 + `group_id` 固定，断言两条独立会话（`tcp.stream` distinct + 每流 `smb2.msg_id` 从头部起算）。

## 7. P1 规范矩阵（CORE_MEMORY §4 八项）

| # | 规范要求 | 业务场景 | 代码现状（实读） | 缺口 |
|---|---|---|---|---|
| 4.1 连接模型 | 会话型长连接：TCP 445 Direct TCP / 139 NetBIOS Session Service；客户端主动建连（`07-smb-design.md:36`、`07-smb-design.md:1035`） | 轻量探测＝一次连接跑完一次会话 | tcp 层生成器产握手 3 包（`tcp.go:177/203/229`）+ 拆解 4 包（`tcp.go:330-400`，注释"FIN, ACK, FIN, ACK"）；smb 终结层 `DependsOn ["tcp"]`（`registry.go:1477`） | 无 |
| 4.2 命令/消息表 | 命令码枚举（`07-smb-design.md:188-200`，MS-SMB2 §2.2.1.2）；probe 只用 0x0000/0x0001/0x0003/0x0005/0x0006/0x0004/0x0002 + 可选 0x0008/0x0009/0x000D | 探测单支路 | `constants.go:35-53` 19 码常量；`layer_gen.go:324-441` 9 个 op 分支 | 无 |
| 4.3 状态机 | 阶段序 + 错误短路 + CLOSE 强制拆解（`07-smb-design.md:744-757`） | close 抑制诊断 | `layer_gen.go:444-451` 抑制规则；错误短路 `layer_gen.go:319-322` + `smb.go:268-270` | 无 |
| 4.4 字段表 | SMB2 头 64B/13 字段（`07-smb-design.md:140`）；CLOSE 请求 StructureSize=24、响应=60（`07-smb-design.md:479-500`） | 逐字段断言 | 生成器 body 纯函数 `buildCloseRequestBody/buildCloseResponseBody`；tshark 断言面实测 `smb.` 652 字段 + `smb2.` 533 字段（合计 1185） | 无 |
| 4.5 错误处理表 | `ErrorOnCommand` + `ErrorResponseStatus`；错误后 break 且拆解继续（`07-smb-design.md:744`） | 非正常结束诊断 | `validate.go` 码表校验；`layer_gen.go:366-370`（`stopAfter=="close"` → 错误响应） | 无 |
| 4.6 超时与活性 | SMB2 ECHO（0x000D）为连接活性检查；本生成器不产 TCP keepalive 探测（`tcp.go` 只用 SYN/ACK/PSH\|ACK/RST/FIN\|ACK） | 同连接多轮活性 | `layer_gen.go:413` `case "echo"` | 无（TCP keepalive 不产生＝B′ 注记 B′-4） |
| 4.7 NAT/代理/被动模式 | SMB 无被动模式/数据面派生；445 直连或 139 | 端口探测 | `chain_planner.go:1119-1127` 缺省端口；`strategy_convert.go:1293-1302` 同款 | 无 |
| 4.8 版本/方言 | 5 方言 0x0202/0x0210/0x0300/0x0302/0x0311（`07-smb-design.md:1-10` §1） | 探测配置继承 smb 默认方言；完整方言矩阵由 smb 套件 296 例覆盖 | probe 族不重复建矩阵，归 smb 套件核验 |

### 7.1 子表① 命令×响应码矩阵（probe 面逐格）

| 命令 | STATUS_SUCCESS | 注入错误码（`error_response_status`） | 结论 |
|---|---|---|---|
| NEGOTIATE 0x0000 | 覆（全部正例第 1 对） | 未编排 | 缺格＝归 smb 套件（T-族错误例），probe 不编 |
| SESSION_SETUP 0x0001 | 覆（3 轮 nlmt） | 未编排 | 同上 |
| TREE_CONNECT 0x0003 | 覆 | 未编排 | 同上 |
| CREATE 0x0005 | 覆 | 未编排 | 同上 |
| READ 0x0008 | 覆（默认操作） | 未编排 | 同上 |
| WRITE 0x0009 | 覆（多轮例） | 未编排 | 同上 |
| **CLOSE 0x0006** | **覆（显式 / 隐式两格）** | **覆（错误注入例）** | **probe 靶心，两格全建** |
| TREE_DISCONNECT 0x0004 | 覆 | 未编排 | 归 smb 套件 |
| LOGOFF 0x0002 | 覆 | 未编排 | 归 smb 套件 |
| ECHO 0x000D | 覆（活性例） | 未编排 | probe 建 1 格 |

### 7.2 子表② 数据形态变体表

| 形态 | probe 是否建例 | 断言通道 |
|---|---|---|
| 单 PDU 单 TCP segment | 覆（全部例） | `smb2.cmd` + `nbss.length` |
| 同连接多操作序列（read→write→close） | 覆（编号 3） | `smb2.cmd` 序列 + `smb2.msg_id` 递增 |
| 错误注入后拆解继续 | 覆（编号 4） | `smb2.nt_status` 非零 + 后续 `smb2.cmd` 仍出现 0x0004/0x0002 |
| 隐式 CLOSE 保底（operations 空） | 覆（编号 2） | CLOSE 恰一对 |
| 同连接多轮 ECHO | 覆（编号 5） | `smb2.cmd=13` 计数 |
| 139 载体 | 覆（编号 6） | `tcp.dstport=139` |
| IPv6 载体 | 覆（编号 7） | `ipv6.src`/`ipv6.dst` + SMB2 字段；本 fixture 不钉偏移 frames |
| 多流独立会话 | 覆（编号 8） | `tcp.stream` distinct + 每流 msg_id 首值 |
| 双输出（pcap / NIC） | 覆（编号 12） | 两通道字段一致 |
| 多 PDU 并入一条 NBSS（compound / NextCommand） | **不建例** | B′ 注记 B′-3（生成器一 message 一 PDU） |
| SMB3 加密（TRANSFORM_HEADER 52B 包裹） | **不建例** | B′ 注记 B′-2（probe 不走 encryption_required） |

### 7.3 子表③ 商业行为→用例映射表

| 商业/工具行为 | 出处（实读） | 映射 |
|---|---|---|
| tshark 3.6.14 对 probe 族的解析伪影分类（GSS-SPNEGO/NTLMSSP 越界读） | `deep_audit.py:127-152`（`is_smb_gss_artifact`，明列 `probe_` 前缀与"帧合法、NTLMv2 协商为正常 auto-session 流"） | 编号 1/2（notes 声明伪影，不进负例） |
| 诊断族 pcap 的验收归位（`<proto>/<caseID>.pcap`） | `internal/pcaptest/types.go:93-97`（`CasePcapName`）+ `internal/mcp/tools_testdrive.go:814-816`（proto 过滤按 **case 字段** 而非文件名） | 编号 1–12（pcap 落 `/tmp/mcp-pcaps/smb/`） |
| 现网真客户端（Windows 资源管理器 / `net use` / Samba `smbclient -L`）的探测形态与首轮方言/认证选择 | **未核对**（仓库无该抓包证据） | **待确认**：抓一份现网 445 首会话 pcap 比对首 3 包（确认方式＝抓包，见 §18 G-PROBE-SMB-5） |

## 8. 三路对照与候选方案对比

**三路对照（4.12–4.15）**：

| 路 | 内容 | 结论 |
|---|---|---|
| ①规范（4.12） | MS-SMB2：会话状态机、SYNC 头 64B、CLOSE 请求/响应体（经 `07-smb-design.md` §3 逐字段表引用，本仓库已核原文） | 定"必须是什么"：八阶段序 + CLOSE 体结构 |
| ②商业化软件（4.13） | tshark 3.6.14 dissector 行为（本机实测：`smb.` 652 + `smb2.` 533 = 1185 字段；对 probe 帧的 NTLMSSP 越界伪影已定性） | 定"现网真跑成什么样"可断言面 |
| ③开源实现（4.14） | 本仓库既有 `internal/protocol/smb` 实现（legacy planner 与层生成器同源，`layer_gen.go` 注释逐处对照 `smb.go` 行号） | 定"别人已验证的走法"：CLOSE 抑制、错误短路、默认操作 |
| 不一致时（4.15） | 三路无冲突；规范与实现冲突时按 4.24 先改实现 | — |

**候选方案对比（4.17）**：

| 方案 | 走法 | 优势 | 代价 | 裁定 |
|---|---|---|---|---|
| A：新建独立 `probe` 层/协议 | 注册 `probe` 层 + 生成器 + 白名单 | 名字直白 | 复制 smb 全部语义；无注册面证据；违反 1.12（凭空造层）；工具链（deep_audit/proto 过滤）需同步改 | **否** |
| B（**选**）：归并 smb 子族 + **业务键住 smb 层**（目标形，现已落地） | 层内业务键经 `translateTerminalConfig` 的 `case "smb"` 转为 `spec.SMB` | 满足 1.8/1.11 严格层链形；与已迁移协议同构 | **选定并已落地** |
| C：顶层 `smb` 过渡形 | 已由 `strategy_convert.go:8831-8833` 判死 | 违反 1.4/1.11；不得进入现行用例 | **否** |

现已选定并落地方案 B；不再保留 C 过渡写法。

## 9. 五件套（§3 行，强制展开）

| 件 | probe 家族内容 |
|---|---|
| ①会话表 | s1（IPv4/direct/445，主探测会话）；s2（IPv6 独立会话，编号 7）；s3（139 netbios 会话，编号 6）；s4/s5（多流例的两条会话，编号 8）。每会话独立 ID、独立四元组、独立生命周期（3.2） |
| ②事务序列 | 单会话内固定序：`NEGOTIATE → SESSION_SETUP×3 → TREE_CONNECT → CREATE → [Operations 0–N] → CLOSE → TREE_DISCONNECT → LOGOFF`；每事务四件事：前置＝前序阶段成功（4.3 短路规则）；触发＝该阶段 PDU 对；成功＝推进下一阶段；失败＝按 `error_on_command` 注入错误码后 break，拆解仍走完（3.4–3.7、4.5） |
| ③关联关系 | **无派生副流**（SMB2 数据面与控制面同连接，无 FTP 式独立数据连接）。诚实声明：`driven_by` 不适用；若后续接 SMB3 多通道（Multichannel）需另立条目（B′ 注记 B′-5） |
| ④插入位置 | 终结层（链末），无链上中间层；`DependsOn ["tcp"]`（`registry.go:1477`） |
| ⑤时间线 | 会话内**严格有序**（msg_id 单调递增，一个方向一对）；跨会话（多流例）**并发**且不假设全局到达顺序，只断言每流内序（3.11/3.12） |

**3.14 豁免边界审计**：SMB 是长连接协议 → **不豁免** `sessions[]`（本族单会话正例即显式声明会话）；多流并发面由编号 8 建例；「单包多载荷」面（compound/多 PDU 并一条 NBSS）**不适用**于本生成器（一 message 一 PDU）→ B′ 注记 B′-3，不冒充覆盖。

**3.15 三项（每个事务级行为面各一例或一立项）**：

| 项 | 落地 |
|---|---|
| ①同连接/同流内多轮操作 | **编号 3**（read→write→close 三操作同连接） |
| ②非正常结束 | **编号 4**（`error_on_command=close` 错误注入；断言语义＝错误响应 + 拆解继续 + CLOSE 恰一对） |
| ③长保活 | **编号 5**（同连接多轮 ECHO 0x000D 活性探测）；诚实声明：本生成器不产 TCP 层 keepalive 探测包，SMB2 无心跳帧，活性由会话内 PDU 轮次体现（B′ 注记 B′-4） |

## 10. §1 行：旧键去向与 spec_json 样例（强制展开）

| 旧键（现存量例与过渡形） | 去向 | 证据 |
|---|---|---|
| 顶层 `src_ip` | → `layers[].ip.src` | `strategy_convert.go:8641-8644` 判死锚词；`layer_dyn.go:17` 层字段表 |
| 顶层 `dst_ip` | → `layers[].ip.dst` | 同上 |
| 顶层 `src_port` | → `layers[].tcp.src_port`（probe 例可省，多流例用动态对象） | 同上 + 9.39 |
| 顶层 `dst_port` | → `layers[].tcp.dst_port`（445 / 139） | `chain_planner.go:1249-1258` 缺省化 |
| 顶层 `count` | **删** → `flow_control.{type,value}` | CORE_MEMORY 1.3；`flow_control` 白名单键（1.11） |
| 顶层 `smb` 子映射 | **判死并迁入完成** → `layers[].smb` | `strategy_convert.go:8831-8833`；`chain_planner_translate.go:2942-2954` |
| 顶层其它协议子映射 / `src_mac`/`dst_mac`/`ttl` | **判死**（白名单外游离键） | `schema/semantic.go:186-190`（`config mixes layers with flat four-tuple field ...`）；1.11–1.13 |

**存量现例原文（迁移前审计快照，现 JSON 已含 12 例）**：

```json
{"id":"probe_explicit_close","proto":"smb","summary":"probe: explicit close single close",
 "spec_json":{"src_ip":"10.0.0.100","dst_ip":"10.0.0.1","smb":{"operations":[{"op_type":"close"}]}},
 "expect":{"packet_count":24}}
```

该形状**迁移前经 MCP 必被拒**：`src_ip` 命中扁平键判死（`strategy_convert.go:8643` 锚词 `protocol smb no longer accepts flat config field src_ip`），且无 `layers` → 亦不被链套件采纳。现已改写为严格层链形；12 例实际均无上述顶层旧键。

**现行形状**：业务键直接位于 `layers[].smb`，见 §2；顶层 `smb` 子映射由 `strategy_convert.go:8831-8833` 判死。

## 附 A. 层链迁移契约（D1-D8，静态审计）

| ID | 结论 | 证据/去向 |
|---|---|---|
| D1 | SMB 业务字段只住 `layers[].smb`；地址/端口只住 `layers[].ip`/`layers[].tcp` | 12 条 cases 机读审计；正例均为 `[ip,tcp,smb]` |
| D2 | 标准链固定为 `[ip,tcp,smb]`；139 仅由 SMB transport 选择载体端口 | registry / chain planner 现状；`probe_netbios_139` |
| D3 | 会话阶段、CLOSE 体和偏移按 SMB2/NBSS 既有实现，不新增线格式 | 本文 §3–§4；`internal/protocol/smb` |
| D4 | `operations`、错误注入和 transport 等业务键保留在 `layers[].smb` | registry 字段与 `TranslateSMBConfigFromMap` |
| D5 | 顶层旧扁平键不属于正例目标形；三条故意违规输入保留为负例 | `probe_neg_*`；§12 |
| D6 | 多流数量由 cases 兄弟键 `strategy_fc` 表达，动态端口在 tcp 层；不把静态复制当覆盖 | `probe_multi_flow_dynamic` / `probe_neg_static_copy` |
| D7 | 三个负例 `expect` 严格只有 `expect_error` 与 `error_contains` | JSON 键集合审计 |
| D8 | 本次只做文档与 cases 静态闭环；Go/schema/索引及真实 suite、MCP、NIC 均不改不宣称 | 本次变更边界 |

## 附 B. 六项覆盖清单（C1-C6）

| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | JSON 可解析、12 个 ID 唯一、顺序一致 | 已静态对账，12/12 |
| C2 | 严格层链与地址/端口/业务归属 | 9 正例均为 `[ip,tcp,smb]`；3 负例仅故意注入顶层违规或静态复制 |
| C3 | 八阶段、显式/隐式/error CLOSE、read/write/echo、139、IPv6、多流 | 9 正例逐项映射 §13 与 testcase §2/§3 |
| C4 | 负例错误传播契约 | 3/3 `expect` 严格双键，锚词与代码静态回指；未实际运行 |
| C5 | 旧 flat 审计和代码接线缺口 | 旧 `src_ip` 例已迁移；SMB registry/planner/translate 已接线，无 Go 缺口 |
| C6 | PCAP/NIC 双输出契约 | `probe_pcap_nic_consistency` 定义共用断言；本轮未跑 suite/MCP/NIC |

## 附 C. 三源与缺口边界

**四元组（12.2）**：全部经层链承载，且**已在代码支持面**：

| 字段 | 动态支持 | 证据 |
|---|---|---|
| `ip.src` / `ip.dst` | 支持（动态对象） | `internal/core/layer_dyn.go:17`（allowlist `"ip": {"src","dst","ttl"}`） |
| `tcp.src_port` / `tcp.dst_port` | 支持（动态对象） | `layer_dyn.go:19`（allowlist `"tcp": {"src_port","dst_port"}`） |

**序号算法（12.4/12.14）代码位置（实读，未编）**：动态对象解析入口 `parseLayerDyn`（`internal/core/layer_dyn.go:78`）；逐流序号解析 `resolveLayerTuple`（`internal/core/layer_dyn.go:770`）；层内动态对象形状执法 `checkLayerDynObjects`（`internal/core/layers/validate_layers.go:329`，非白名单字段报 `%s does not support dynamic`，:370）。probe 家族不自创序号算法，全部复用上述三者。

**业务字段清单（12.3 逐键列开/不开）**：

| 业务键 | 开/不开 | 理由 |
|---|---|---|
| `operations[]`（含 `op_type/offset/length/data`） | **不开** | 无 smb 行 in `layerDynAllowlist`（`layer_dyn.go:17-71` 全表实测无 `"smb"` 键）→ 对象即 `does not support dynamic`；且"逐流换操作序"会让诊断目标漂移 |
| `error_on_command` / `error_response_status` | **不开** | 诊断靶心须固定（错误注入例是行为断言，不是值轮转） |
| `dialects` / `selected_dialect` | **不开** | 方言矩阵归 smb 套件（§7 子表②末两行） |
| `tree_connect_share` / `file_path` | **不开** | 无逐流轮转需求；且属会话身份面（12.9 静态复制禁令由四元组动态兜住） |
| `auth_rounds` / `auth_mechanism` | **不开** | 轮数是机制属性而非逐流变量 |

**静态复制（12.9/9.39）**：probe 多流例（编号 8）以 `tcp.src_port` 动态对象满足执法；未写动态时的保底只有 2.8 的 `src_port` 自动递增（本族不依赖它兜底）。

## 12. 边界、异常与错误传播

负例必须在**建策略/建任务**处被拒并带锚词（14.11），不允许产出成功 PCAP 或 `completed/0 packet` 假成功：

| 编号 | 负例 ID | 故障输入 | 目标 `error_contains`（实读锚词） | 锚词出处 |
|---|---|---|---|---|
| 9 | `probe_neg_flat_keys` | 顶层 `src_ip`（存量例形状） | `no longer accepts flat config field src_ip` | `strategy_convert.go:8641-8644`（`CheckProtoFlat`，函数起点约 `:8634`；策略建改经 `api/rest/strategy_handler.go:30` → `schema.ValidateStrategy` → `schema/semantic.go:131` 进入） |
| 10 | `probe_neg_layers_flat_mix` | `layers` + 顶层 `src_port` 并存 | `config mixes layers with flat four-tuple field src_port` | `schema/semantic.go:186-190` |
| 11 | `probe_neg_static_copy` | `layers` 内静态标量四元组 + `flows=2` | `layers pin a static four-tuple but flows > 1` | `schema/semantic.go:138-145`（静态复制判据辅助 `:198`） |

**注记（不建例，归 smb 套件）**：`op_type` 非法（锚 `smb: OpType must be read/write/close/query_directory/query_info/set_info/flush/echo/lock/ioctl`，`validate.go:105-106`）与 `auth_rounds` 越界（锚 `smb: AuthRounds must be 1-3 (0 for default)`，`validate.go:61-63`）已由 smb 套件的 `smb_tneg_T233_optype_invalid` / `smb_tneg_T230_rounds_oob` 覆盖（两 ID 实测存在于 `cases/smb.json`），probe 家族不重复建例。

**缺口**：presence 判死已落码（`strategy_convert.go:8831-8833`）；本族现行 12 例无顶层 `smb` 子映射，因此不再登记 G-PROBE-SMB-2。

## 13. 语义场景索引与 packet_count 映射

共 **12 个唯一语义 ID**：9 正 + 3 负。顺序须与 `testcase.md` §2 及 `cases/probe_smb.json` 完全一致（下表顺序即当前 JSON 顺序）。

| # | ID | 类型 | 诊断目标 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `probe_explicit_close` | 正 | 显式单 close：CLOSE 恰一对，无隐式重复（存量例迁移） | 25 |
| 2 | `probe_default_session` | 正 | 零负载默认保底会话（默认单 read + 隐式 CLOSE） | 29 |
| 3 | `probe_ops_multi_round` | 正 | 同连接多轮操作 read→write→close | 31 |
| 4 | `probe_error_on_close` | 正 | 非正常结束：close 错误注入，拆解继续 | 25 |
| 5 | `probe_echo_liveness` | 正 | 同连接多轮 ECHO 活性探测 | 29 |
| 6 | `probe_netbios_139` | 正 | 139 NetBIOS Session Service 载体 | 29 |
| 7 | `probe_ipv6_session` | 正 | IPv6 载体独立 fixture（`ip` 层放 IPv6 字面量） | 29 |
| 8 | `probe_multi_flow_dynamic` | 正 | 多流（`strategy_fc.flows=2` + 端口动态对象） | 58 |
| 9 | `probe_neg_flat_keys` | 负 | 顶层扁平键判死 | — |
| 10 | `probe_neg_layers_flat_mix` | 负 | layers + 顶层四元组混用判死 | — |
| 11 | `probe_neg_static_copy` | 负 | 静态复制判死（flows=2） | — |
| 12 | `probe_pcap_nic_consistency` | 正 | pcap / NIC 双输出一致 | 25 |

**packet_count 推导口径（诚实标注，P5 前不是断言值）**：单流基线 `3（握手）+ 2×8（会话八阶段的 PDU 对，其中 SESSION_SETUP 按 ntlm 默认 3 轮 = 6 包）+ 4（拆解）= 29`；显式单 close 少一次操作对 → **25**（编号 1/4/12）；`read+write+close` 三操作多 2 对 → **31**（编号 3）；编号 5 双 ECHO 仍是 2×29 以内的两操作 → **29**；编号 8 = `flows=2` × 29 = **58**。交叉验证：同形 smb 存量例 `smb_tpos101_close`（单 close）pin **25**、`smb_terr132_close_error`（write+close）pin **27**。**存量 probe 例的 24 与此矛盾**（24 = 25−1，即 legacy 3 包挥手时代残值；换分支 commit `34a52d4` 曾把它改为 25 并写明"链上 TCPGenerator 标准 4 包，probe_smb 漏同步"，但**该 commit 不在当前 HEAD**——`git branch --contains 34a52d4` 仅 `feat/68-hl7`）。故 24 属**过期值**，P5 必须以落盘 pcap 先跑后钉复算（9.31/14.20），不得照抄。

## 14. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §10 强制展开：旧键五个去向逐项落定（`src_ip/dst_ip/src_port/dst_port` → ip/tcp 层，`count` → `flow_control`），顶层 `smb` 子映射已判死并迁入 `layers[].smb`；严格层链 spec_json 样例见 §2；存量现例原文+判死锚见 §10 | 本契约 §2/§10/§15；`cases/probe_smb.json` |
| §2 策略/任务 | 策略=单 SMB 探测模板（自带 `flow_control`）；任务=多策略合跑+总量封顶；框架语义未动 | 本契约 §2；CORE_MEMORY §2.1/2.2 |
| §3 五件套 | 见 §9 强制展开：会话表 s1–s5、事务序列八阶段+四件事、关联关系（无派生副流，诚实声明）、插入位置（终结层）、时间线（会话内有序/跨会话并发）；3.14 审计与 3.15 三项逐项落表 | 本契约 §9；用例 3/4/5 |
| §4 查规范 | MS-SMB2（会话状态机/头 64B/CLOSE 体，经 `07-smb-design.md` 逐字段表）+ tshark 3.6.14 实测（`smb.` 652/`smb2.` 533）+ 本仓库实现对照；三路对照与候选对比见 §8；八项矩阵见 §7 | 本契约 §7/§8 |
| §5 依赖与错误 | 依赖＝`tcp`（`DependsOn ["tcp"]`，`registry.go:1477`）；错误分支＝§12 三负例锚词逐字实读；presence 判死已落码（`strategy_convert.go:8831-8833`） | 本契约 §12/§15/§18 |
| §6 性能 | 流式：一 PDU 一事件，无全量聚合；每会话 O(1) 包数；pcap/NIC 双路验收；吞吐目标**待 P4 基准**（不写承诺数字，6.5） | 本契约 §16 |
| §7 三份文档 | 78-probe_smb-{design,testcase}.md（ID 权威＝testcase §2）+ D-PROBE-SMB-1（本文 §15，门1 获批＝定稿）；schema 面 smb 行已存在（无新增注册） | 本文 §15/§19；testcase §11 |
| §8 设计先行 | 本条 P1–P3 先于 P5；门1 获批＝D-条目定稿＝开工门 | 提交序 |
| §9 测试三源 | ①规范/官方文档＝MS-SMB2 会话状态机与 CLOSE 体 ②设计＝D-PROBE-SMB-1 ③现网/实测＝tshark 字段实测 + smb 存量 pin（25/27）+ deep_audit 伪影定性；三源回指行见 testcase §6 | testcase §6 |
| §10 评审闭环 | 各阶段对抗自重审结论见 `/tmp/pipe/49-probe_smb/p123-report.md` | 报告 |
| §11 白话 | 汇报先一句白话结论 | 报告 |
| §12 动态清单 | 见 §11 强制展开：四元组四键开（layer_dyn allowlist 实读），业务五类逐个列不开+理由；序号算法位置实读 `parseLayerDyn:78`/`resolveLayerTuple:770`/`checkLayerDynObjects:329` | 本契约 §11 |
| §13 schema 派生 | 无新增层/字段注册（裁定 P1 归并）→ 无 schemagen 变更、无 `protocols.go` 白名单变更（`smb` 已在 `protocols.go:55`）；用例文件形状变更不触发生成器 | §1.1 实读表 |
| §14 真实流程 | suite 经 MCP 建策略建任务→引擎生成→pcap 落 `/tmp/mcp-pcaps/smb/`→tshark `smb2.*`/`nbss.*` 逐字段核对；先跑后钉（§13 推导口径）；`CASE_PROTO=smb` 会连带加载本族（proto 过滤按 case 字段：`tools_testdrive.go:814-816`） | §13/§17；testcase §10 |

## 15. D-PROBE-SMB-1（代码设计条目，八要素）

**状态**：已落地。层内 SMB 翻译由 `chain_planner_translate.go:2942-2954` 承接；依据：本文 §1–§13 + MS-SMB2 会话状态机 + 实读接线表。

1. **改哪几个文件**：本条文档、testcase 与 `cases/probe_smb.json`；不改任何 `.go`。12 例均为严格层链形。
2. **接口签名**：**N/A**——本族无 Go 接口新增/变更（裁定 P1）。用例契约类型沿用 `internal/pcaptest` 的 `Case`（`internal/pcaptest/types.go`，pcap 命名 `CasePcapName:93-97`）。
3. **数据结构**：用例 `spec_json` 形状＝`{"layers":[{"ip":{...}},{"tcp":{...}},{"smb":{...}}],"flow_control":{...}}`；`expect` 正例＝`{packet_count, directional, fields[], frames[]?, notes[]?}`，负例＝`{expect_error, error_contains}`（严格两键）。
4. **主流程**：MCP `flowb_run_protocol_suite`（`case_dir`＝cases 目录，`proto=smb`）→ 逐例建策略（REST 校验入口：`schema/semantic.go:120-176`）→ 建任务 → 引擎链生成（`ChainPlanner("smb")`，`main.go:618`）→ pcap 落 `/tmp/mcp-pcaps/smb/<caseID>.pcap` → `VerifyPcap` 逐字段。
5. **错误分支**：§12 三负例（锚词逐字实读）；错误传播必须是任务终态 error，不得 `completed/0 packet`（14.12）。
6. **性能边界**：单例 ≤ ~58 包（多流例 2×29）；12 例全量约 300 包；无新增锁/队列/内存结构；单流内存增量＝一次 `SMBConfig`。
7. **与现有逻辑的冲突点**：严格层链与顶层协议子映射判死规则一致；probe 侧不再自插 translate/coverage 逻辑；旧审计快照的 `packet_count:24` 已由当前 JSON 重钉为 25。
8. **回滚方式**：本次为文档与 cases 变更；按文件粒度回滚即可，无代码回滚面。

## 16. 性能设计与验收（CORE_MEMORY §6）

| 要素（6.1–6.8） | 内容 |
|---|---|
| 性能目标与规模边界（6.1/6.2） | 单例包数 ≤58（多流例 2×29，实测口径，非承诺吞吐）；并发会话数＝`flow_control.flows`（probe 家族默认 1，多流例 2）；单流最大报文＝SMB2 PDU（CLOSE 请求 ~90B 级，不触发 MSS 分段）；内存上限＝每流一份 `SMBConfig`；队列/缓冲＝沿用引擎既有有界队列，本族不新增；CPU 并行度＝沿用 PacketWorkers 缺省 |
| 双路验收（6.3） | pcap 路＝`CASE_PROTO=smb` 落盘 + `VerifyPcap`；NIC 路＝编号 12（`output_type=port_group` + `nic_capture`，接口按 `testing-interface` 记忆口径） |
| 实现路径依据（6.4） | 流式：生成器逐 PDU 事件 yield（`layer_gen.go:89-133`），无全量收集；无共享状态新增；限速/背压沿用 `SharedTokenBucket` 与任务级封顶（`flow_control`） |
| 未支撑数字（6.5） | 吞吐/延迟数字**待 P4 基准**，不写承诺 |
| 六类场景（6.6） | 基线＝编号 1/2；目标规模＝编号 8（多流）；压力上限＝多流例的 flows 放大（P4 基准时给档）；长时间＝编号 5（多轮 ECHO 活性）；并发交错＝编号 8（两流交错）；背压/资源耗尽＝沿用引擎测试面（本族不新建） |
| 断言面（6.7） | 断言包数、方向、`smb2.cmd` 序、`smb2.nt_status`、`nbss.length`、`tcp.dstport`——不断言"任务没报错" |
| 超预算即不合格（6.8） | 若某例包数远超推导值（如双 CLOSE 回归），判不合格并按 §13 复算 |

## 17. PCAP/NIC 观察、完成定义与与 smb 联验清单

**字段通道（tshark 3.6.14，本机实测）**：`smb.` 前缀 652 字段、`smb2.` 前缀 533 字段（合计 1185；口径 `awk -F'\t' '$3 ~ /^smb2?\./'` 计 1185，其中 `^smb\.` 652 含不含寄生行——`smb_direct.` 30 / `smb_netlogon.` 50 / `smb_pipe.` 31 三个邻族前缀**不计入**）。本族断言只用实测存在的字段：`smb2.cmd`、`smb2.msg_id`、`smb2.flags.response`、`smb2.nt_status`、`smb2.tid`、`smb2.credit.charge`、`smb2.credits.granted`、`smb2.dialect`、`nbss.type`、`nbss.length`、`tcp.dstport`、`tcp.stream`。

**完成定义**：①`cases/probe_smb.json` 12 例全绿（**全量**，14.19）；②pcap 落盘 `/tmp/mcp-pcaps/smb/` 可人工复查（14.16）；③三负例经真实流程被拒且锚词命中（14.11）；④包数与 §13 复算一致；⑤`pipe_gate.sh probe_smb` 门 2-1/2-3/反查四项绿（门 2-2 由 12 例全量承担）；⑥**与 smb 联验**（下表）。

**与 smb 联验清单（P5 必做，缺一不算完成）**：

| # | 联验项 | 判据 |
|---|---|---|
| J1 | 同批跑：`CASE_PROTO=smb` 一次加载两文件（`smb.json` 296 + `probe_smb.json` 12 = 308 例） | `tools_testdrive.go:814-816` proto 过滤按 case 字段；结果 total 应含本族 12 例 |
| J2 | close 族包数对账：`probe_explicit_close` vs `smb_tpos101_close`（同 spec 形状） | 两者落盘 pcap 包数一致（同口径 25，或按 pcap 复算后的同值）；不一致即有一条错 |
| J3 | 错误注入对账：`probe_error_on_close` vs `smb_terr132_close_error` | CLOSE 对计数一致（各 1 对）+ 拆解阶段仍完整 |
| J4 | 偏移对账：CLOSE 体起点 offset | probe 与 smb close 族 frames 同偏移（IPv4 122，实测口径） |
| J5 | 反查归属：`coverage_gate.py` `check_smb` 块 | 归 #50 smb 车道编写；本族 12 例**不进**该块分母，出口仍须为 0（并发方案 §2 M1 条） |
| J6 | 伪影口径：probe 帧的 NTLMSSP 越界读 | `deep_audit.py:127-152` 既有定性对迁移后的帧仍成立（notes 声明，不进负例） |
| J7 | 迁移顺序：目标形（`layers[].smb` 业务键）落地 | 当前 JSON 已使用目标形；SMB registry/planner/translate 接线已有静态证据，运行复跑留待 P5 |

## 18. 缺口立项清单（**缺口数 = 5**）

| 立项号 | 缺口 | 去向 |
|---|---|---|
| G-PROBE-SMB-1 | 已关闭：层内 smb 业务键消费面存在，`chain_planner_translate.go:2942-2954` 已覆盖 | 现行 12 例均使用严格层链形 |
| G-PROBE-SMB-2 | 已关闭：顶层 smb presence 判死已落码，`strategy_convert.go:8831-8833` | 负例集合不新增 presence 例 |
| **G-PROBE-SMB-3** | INDEX 编号上限：`INDEX.md` §6.3 规定 NN 00–77 且已占满，本族取顺延号 78 | **主线程集成动作**：登记 INDEX（修订 §6.3 或补顺延号条款） |
| **G-PROBE-SMB-4** | 覆盖率台账口径：诊断族不进反查分母，需在 smb 反查块显式声明 | 当前台账已登记不计入；由 #50 车道维持声明 |
| **G-PROBE-SMB-5** | 现网核对缺证据：真客户端（Windows/`smbclient`）探测首会话形态未核对 | P4 前置确认项（确认方式＝抓一份现网 445 首会话 pcap，比首 3 包）；不挡开工 |

**已关闭项**：独立 probe 层/协议（归并 smb）；SMB3 加密下的 probe 诊断（由 smb 套件覆盖）；compound/多 PDU 并一条 NBSS（当前生成器一 message 一 PDU，需新增 smb 能力后补例）；TCP 层 keepalive 探测包（当前生成器不产，活性用 ECHO 例验证）。

## 19. 修订记录

- v1.1.0（2026-10-01）：按当前 HEAD 对齐层链实现与 12 例 JSON：更新注册/翻译/判死行号、删除过渡形示例、同步 SMB 套件 296 例与 308 总量、关闭 G-PROBE-SMB-1/2。

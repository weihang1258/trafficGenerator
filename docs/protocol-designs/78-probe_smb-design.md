# probe_smb（SMB 轻量探测诊断族）设计契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-09-26
> 状态：仅设计与 PCAP（抓包文件）用例契约；**`probe` 无独立层名、无独立协议名**（§1 实读证据），本族归并 `smb` 协议；不修改 Go（编程语言）实现。
> 配套文件：`docs/protocol-designs/78-probe_smb-testcase.md`、`trafficgen/test/protocol_pcap/cases/probe_smb.json`
> 规范基线：MS-SMB2（SMB2/SMB3 线格式与会话状态机；本仓库引用面见 `docs/protocol-designs/07-smb-design.md`）+ CORE_MEMORY §1/§3/§12。

## 1. 范围、归属裁定与证据等级

本族定义 **SMB 轻量探测**（下文简称 probe）：在同一 TCP 连接上跑通一次最小 SMB2 会话（默认保底阶段 + 0–1 个数据操作），用于层链接线回归与操作支路的定向诊断。probe **不是新协议**——它是对 `smb` 终结层已有能力的定向调用，因此本文不含任何新线格式定义，只定义"怎么配、断言什么、边界在哪"。

### 1.1 归属三问实读（逐项实测，不猜）

| 问 | 实读结果 | 证据（文件:行） |
|---|---|---|
| 有独立 `probe` 层名吗？ | **无** | `internal/core/layers/registry.go` 全文件 grep `probe` → 0 命中；`r.Register(LayerSchema{Name: "smb", ...})` 为唯一 smb 行（`registry.go:1028`） |
| 有独立 `probe` 协议名吗？ | **无** | `internal/core/protocols.go` 全文件无 `probe`；`"smb": true` 在 `protocols.go:45` |
| 用例文件怎么归属？ | **`proto=smb`**（文件名 ≠ proto 字段，框架已认账） | `cases/probe_smb.json` 唯一例 `{"id":"probe_explicit_close","proto":"smb",...}`；`test/protocol_pcap/verify_all_test.go:62` 注释"文件名与 proto 字段可能不同（如 cases/probe_smb.json 声明 proto=smb）" |
| 诊断族怎么被外部工具识别？ | **按 ID 前缀 `probe_`**，且明确"不是 279 例套件的一部分" | `test/protocol_pcap/deep_audit.py:138-145`（`probe_smb.json` cases 是 diagnostics, not suite cases）、`:150-151`（`case_id.startswith("probe_")`）、`:192-198`（无 case 文件时按诊断族归入 expected） |
| 引擎侧接线现状 | `smb` 已翻到链规划器 | `cmd/server/main.go:614` `app.engine.RegisterPlanner(layers.NewChainPlanner("smb"))` |

**裁定 P1（归属）**：probe = **smb 的子例族**（诊断族），**不立项**独立层/独立协议名。理由：①无任何注册面证据支持独立层（上表两行零命中）；②probe 用例的线上字节完全由 `smb` 层生成器产出（`internal/protocol/smb/layer_gen.go`），自建独立层等于复制 smb 语义；③外部工具链已按"同 proto + `probe_` 前缀"识别本族（deep_audit.py 口径）。按 CORE_MEMORY 1.12，"换个名字登记保留"不是合法收口——本族不需要保留，它本来就住在 smb 里。

### 1.2 编号裁定

INDEX（`docs/protocol-designs/INDEX.md` §6.3）规定设计文档编号 `NN` 为 00–77，且"文档编号与 00-unimplemented-list.md 表格编号一致"。逐号实测：01–18 在册（§3.1–§3.9），19–77 在册（§3.10–§3.12，其中 03/04 由合并文档 `02-03-04-jt808-jt809-jtt905-design.md` 覆盖）→ **00–77 已占满**。本族取顺延号 **78**，并在主线程集成动作里登记 INDEX（§18 缺口 G-PROBE-SMB-3：INDEX §6.3 的 00–77 上限需随之修订或补"顺延号"条款）。备选"并入 07 家族子号（如 07b）"被否：INDEX 无子号规则，且 07 号已是 smb 设计+用例合一的历史体裁，双头维护违反 §7.4/§7.7。

### 1.3 今日可达边界（不许把目标形状写成现状）

`smb` 业务配置今日**只有一条活路**：顶层 `"smb"` 子映射 → `spec.SMB`。实读链路：

| 环节 | 现状 | 证据 |
|---|---|---|
| 配置 → FlowSpec | 只认顶层 `cfg["smb"]` 子映射 | `internal/core/strategy_convert.go:1292-1293`（`case "smb": if sub, ok := cfg["smb"].(map[string]interface{}); ok { spec.SMB = parseSMBConfig(sub) }`） |
| 层内 smb 业务键 → FlowSpec | **无翻译分支** | `internal/core/layers/chain_planner_translate.go` 的 `translateTerminalConfig`（函数体 `679-2527`）内全部 `case` 逐行实测（747/847/935/963/1024/1083/1106/1224/1302/1415/1500/1570/1641/1687/1744/1801/1993/2021/2042/2064/2091/2116/2140/2165/2186/2208/2232/2252/2268/2285/2300/2327/2370/2382/2393/2401/2409/2416/2424/2432/2439/2463/2472/2480/2488/2506）**无 `case "smb"`**；全仓库 `case "smb"` 三处均在别处（`strategy_convert.go:1292` 扁平解析 / `chain_planner.go:849` 源端口 0 保持 / `chain_planner.go:1119` 目的端口缺省），无一处消费层内业务键 |
| FlowSpec → 生成器 | `Meta.SMB = spec.SMB`，nil 即硬错 | `chain_planner_translate.go:191`；`internal/protocol/smb/layer_gen.go:504` `"smb generator: no config (spec.smb required)"` |
| 层内业务键的 schema 面 | **登记可写**（34 键全注册）→ 写了不报错但不消费 | `registry.go:1028-1065`（`transport/dialects/operations/error_on_command/...` 全在 Fields）；消费面零 |

结论：**目标形状（业务键住 smb 层）今天跑不通**（按 1.9 明示）；**今日可跑形状是"层链 + 顶层 smb 过渡形"**（全仓库 262 例现用此形，`cases/smb.json` 实测 279 例中 262 例含 `layers` 且带顶层 `smb`）。过渡形按 1.4/1.11 属违规，必须在 D-条目登记迁入计划（本文 §15 已登记），否则 `tools/pipe_gate.sh` 门 2-1 的黄灯升级为红。

## 2. 推荐配置与协议栈

今日可跑（过渡形，probe 用例 P5 落地即用）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.100", "dst": "10.0.0.1"}},
    {"tcp": {"dst_port": 445}},
    {"smb": {}}
  ],
  "smb": {"operations": [{"op_type": "close"}]},
  "flow_control": {"type": "flows", "value": 1}
}
```

目标形状（业务键住 smb 层；**今天跑不通**，需先补 `translateTerminalConfig` 的 `case "smb"`——缺口 G-PROBE-SMB-1，归口 smb 迁移）：

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
| `layers[].tcp.dst_port` | 端口唯一住处（1.2）；probe 面 445（direct）或 139（netbios） | `chain_planner.go:1119-1127`（`case "smb"`：`transport=netbios → 139`，否则 445） |
| `layers[].smb` | 终结层条目；目标形状承载业务键，今日为空负载 `{}` | `registry.go:1028` `Category: CategoryTerminal, DependsOn ["tcp"]` |
| `smb.operations` | 探测操作面；空 → 默认单 `read`（`validate.go:307-309`） | `internal/protocol/smb/validate.go:307-309` |
| `smb.error_on_command` | 错误注入支路（§12 负例与 §9 非正常结束用） | `registry.go` 字段表；`layer_gen.go:446` 抑制规则 |
| `flow_control` | 数量唯一住处（1.3）；probe 家族默认 1，多流例显式 2 | CORE_MEMORY 1.3/12.11 |
| （禁止）顶层 `src_ip/dst_ip/src_port/dst_port/count` | 判死锚词见 §12 | `strategy_convert.go:8280-8285`、`schema/semantic.go:131` |

## 3. 外层传输与固定偏移

probe 走 TCP；无 Ethernet VLAN / IPv4 options / IPv6 扩展头时：

| 载体 | NBSS 起点 | SMB2 头起点 | CLOSE 请求体起点 |
|---|---:|---:|---:|
| Ethernet + IPv4 + TCP | 54（14+20+20） | 58（+4 NBSS） | 122（+64 SMB2 头） |
| Ethernet + IPv6 + TCP | 74（14+40+20） | 78（+4 NBSS） | 142（+64 SMB2 头） |

- NBSS 头 4 字节（type 0x00 session message + 3 字节长度），SMB2 头 64 字节（13 具名字段，MS-SMB2 §2.2.1.2，见 `07-smb-design.md:140`）。
- 偏移 122 有落盘实证口径：`cases/smb.json` 的 close 族 frames 断言即在 offset 122 读 CLOSE 请求体首字段（请求 `18 00 00 00 00 00 00 00` = StructureSize 24 + Flags + Reserved；响应 `3c 00 00 00` = StructureSize 60）。probe 家族沿用同一偏移，不手算新值（§13 断言以 P5 落盘 pcap 复算为准）。
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
| 命令×方言×错误码全矩阵、多会话、多流编排、NAT/代理 | **smb 套件**（`cases/smb.json` 279 例 = 262 正 + 17 负，实测） | probe 家族不重复建例 |
| 层链接线回归 + 操作支路定向诊断（close 抑制、默认保底、错误注入、活性、载体、地址族、多流保底、双输出） | **probe 家族**（`cases/probe_smb.json`，§13 12 例） | 每例只查一个诊断目标 |

**台账口径（诚实声明）**：probe 家族**不计入** smb 套件的覆盖反查口径（`deep_audit.py:138-145` 已按"diagnostics, not suite cases"处置）。`tools/coverage_gate.py` 的 `check_smb` 块归 smb 车道编写（并发方案 §2 认领规则），probe 家族不另起反查块（缺口 G-PROBE-SMB-4，归 #50 车道一并声明）。

## 6. 载体、地址族与多流

- **载体**：445（Direct TCP，默认）与 139（NetBIOS Session Service，`transport=netbios`）各一例；两载体是独立 fixture，不可互推（1.11 端口住 tcp 层，缺省化在 `chain_planner.go:1119-1127`）。
- **地址族**：IPv4 与 IPv6 各一例（9.24 对称覆盖：IPv4 由主例代表，IPv6 独立建例，不互推）。IPv6 下 NBSS/SMB2 偏移整体 +20（§3 表），字段断言面不变。
- **多流**：`flow_control.flows=2` 时必须显式动态四元组（9.39 互斥铁律：flows>1 的层链四元组字段留空或写动态对象）。probe 多流例用 `tcp.src_port` 动态对象 + `group_id` 固定，断言两条独立会话（`tcp.stream` distinct + 每流 `smb2.msg_id` 从头部起算）。

## 7. P1 规范矩阵（CORE_MEMORY §4 八项）

| # | 规范要求 | 业务场景 | 代码现状（实读） | 缺口 |
|---|---|---|---|---|
| 4.1 连接模型 | 会话型长连接：TCP 445 Direct TCP / 139 NetBIOS Session Service；客户端主动建连（`07-smb-design.md:36`、`07-smb-design.md:1035`） | 轻量探测＝一次连接跑完一次会话 | tcp 层生成器产握手 3 包（`tcp.go:177/203/229`）+ 拆解 4 包（`tcp.go:330-400`，注释"FIN, ACK, FIN, ACK"）；smb 终结层 `DependsOn ["tcp"]`（`registry.go:1028`） | 无 |
| 4.2 命令/消息表 | 命令码枚举（`07-smb-design.md:188-200`，MS-SMB2 §2.2.1.2）；probe 只用 0x0000/0x0001/0x0003/0x0005/0x0006/0x0004/0x0002 + 可选 0x0008/0x0009/0x000D | 探测单支路 | `constants.go:35-53` 19 码常量；`layer_gen.go:324-441` 9 个 op 分支 | 无 |
| 4.3 状态机 | 阶段序 + 错误短路 + CLOSE 强制拆解（`07-smb-design.md:744-757`） | close 抑制诊断 | `layer_gen.go:444-451` 抑制规则；错误短路 `layer_gen.go:319-322` + `smb.go:268-270` | 无 |
| 4.4 字段表 | SMB2 头 64B/13 字段（`07-smb-design.md:140`）；CLOSE 请求 StructureSize=24、响应=60（`07-smb-design.md:479-500`） | 逐字段断言 | 生成器 body 纯函数 `buildCloseRequestBody/buildCloseResponseBody`；tshark 断言面实测 `smb.` 652 字段 + `smb2.` 533 字段（合计 1185） | 无 |
| 4.5 错误处理表 | `ErrorOnCommand` + `ErrorResponseStatus`；错误后 break 且拆解继续（`07-smb-design.md:744`） | 非正常结束诊断 | `validate.go` 码表校验；`layer_gen.go:366-370`（`stopAfter=="close"` → 错误响应） | 无 |
| 4.6 超时与活性 | SMB2 ECHO（0x000D）为连接活性检查；本生成器不产 TCP keepalive 探测（`tcp.go` 只用 SYN/ACK/PSH\|ACK/RST/FIN\|ACK） | 同连接多轮活性 | `layer_gen.go:413` `case "echo"` | 无（TCP keepalive 不产生＝B′ 注记 B′-4） |
| 4.7 NAT/代理/被动模式 | SMB 无被动模式/数据面派生；445 直连或 139 | 端口探测 | `chain_planner.go:1119-1127` 缺省端口；`strategy_convert.go:1293-1302` 同款 | 无 |
| 4.8 版本/方言 | 5 方言 0x0202/0x0210/0x0300/0x0302/0x0311（`07-smb-design.md:1-10` §1） | 方言面诊断 | `dialects`/`selected_dialect` 键；probe 家族只取一档 | probe 家族不编方言矩阵（归 smb 套件）；B′ 注记 B′-2 |

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
| IPv6 载体 | 覆（编号 7） | `ipv6.nxt`/偏移 +20 |
| 多流独立会话 | 覆（编号 8） | `tcp.stream` distinct + 每流 msg_id 首值 |
| 双输出（pcap / NIC） | 覆（编号 9） | 两通道字段一致 |
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
| B（**选**）：归并 smb 子族 + **业务键住 smb 层**（目标形） | 补 `translateTerminalConfig` 的 `case "smb"`，层内业务键 → `spec.SMB` | 满足 1.8/1.11 严格层链形；与 hl7/megaco/kerberos 等已迁移协议同构（同文件同 switch） | 需动跨协议共享文件一个协议本地块；与 smb 车道同块冲突 | **选**（缺口 G-PROBE-SMB-1，归 #50 车道落地） |
| C（**过渡用**）：归并 smb 子族 + 顶层 `smb` 过渡形 | 保持今日形状（layers + 顶层 smb） | 今天就能跑，零代码改动 | 违反 1.4/1.11；门 2-1 黄灯须登记迁入计划 | **过渡**（D-条目登记迁入计划；B 落地即切） |

选 B 且以 C 过渡的判据：规范未要求"业务键住层"，但 CORE_MEMORY 1.8/1.11 要求目标形状纯层链，故目标只能是 B；而 8.9「设计未定稿不开工」与 1.9「明确标注目标形状今天跑不通」允许先以 C 打通诊断面，B 由 smb 车道一并补齐（同文件同 switch，两车道各写一版必然冲突）。

## 9. 五件套（§3 行，强制展开）

| 件 | probe 家族内容 |
|---|---|
| ①会话表 | s1（IPv4/direct/445，主探测会话）；s2（IPv6 独立会话，编号 7）；s3（139 netbios 会话，编号 6）；s4/s5（多流例的两条会话，编号 8）。每会话独立 ID、独立四元组、独立生命周期（3.2） |
| ②事务序列 | 单会话内固定序：`NEGOTIATE → SESSION_SETUP×3 → TREE_CONNECT → CREATE → [Operations 0–N] → CLOSE → TREE_DISCONNECT → LOGOFF`；每事务四件事：前置＝前序阶段成功（4.3 短路规则）；触发＝该阶段 PDU 对；成功＝推进下一阶段；失败＝按 `error_on_command` 注入错误码后 break，拆解仍走完（3.4–3.7、4.5） |
| ③关联关系 | **无派生副流**（SMB2 数据面与控制面同连接，无 FTP 式独立数据连接）。诚实声明：`driven_by` 不适用；若后续接 SMB3 多通道（Multichannel）需另立条目（B′ 注记 B′-5） |
| ④插入位置 | 终结层（链末），无链上中间层；`DependsOn ["tcp"]`（`registry.go:1028`） |
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
| 顶层 `src_ip` | → `layers[].ip.src` | `strategy_convert.go:8280-8285` 判死锚词；`layer_dyn.go:17` 层字段表 |
| 顶层 `dst_ip` | → `layers[].ip.dst` | 同上 |
| 顶层 `src_port` | → `layers[].tcp.src_port`（probe 例可省，多流例用动态对象） | 同上 + 9.39 |
| 顶层 `dst_port` | → `layers[].tcp.dst_port`（445 / 139） | `chain_planner.go:1119-1127` 缺省化 |
| 顶层 `count` | **删** → `flow_control.{type,value}` | CORE_MEMORY 1.3；`flow_control` 白名单键（1.11） |
| 顶层 `smb` 子映射 | **过渡期保留**（今日唯一消费面）→ 目标迁 `layers[].smb`（G-PROBE-SMB-1） | `strategy_convert.go:1292-1293`；`chain_planner_translate.go` 无 `case "smb"` |
| 顶层其它协议子映射 / `src_mac`/`dst_mac`/`ttl` | **判死**（白名单外游离键） | `schema/semantic.go:186-190`（`config mixes layers with flat four-tuple field ...`）；1.11–1.13 |

**存量现例原文（`cases/probe_smb.json` 唯一例，实测）**：

```json
{"id":"probe_explicit_close","proto":"smb","summary":"probe: explicit close single close",
 "spec_json":{"src_ip":"10.0.0.100","dst_ip":"10.0.0.1","smb":{"operations":[{"op_type":"close"}]}},
 "expect":{"packet_count":24}}
```

该形状**今日经 MCP 必被拒**：`src_ip` 命中扁平键判死（`strategy_convert.go:8280-8285` 锚词 `protocol smb rejects flat config field src_ip`），且无 `layers` → 亦不被链套件（`layer_chain_suite_test.go:92-96` 只收含 `layers` 的条目）采纳。P5 必须改写为过渡形后重跑（去向见 testcase §5 存量审计）。

**目标形状样例（业务键住层，今天跑不通，需先补 G-PROBE-SMB-1）**：见 §2 第二段。**今日可跑样例**：见 §2 第一段。两形**不得并用**（同例同时写顶层 `smb` 与 `layers[].smb` 业务键＝双头，判死）。

## 11. §12 行：动态字段清单与序号算法（强制展开）

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
| 10 | `probe_neg_flat_keys` | 顶层 `src_ip`（存量例形状） | `rejects flat config field src_ip` | `strategy_convert.go:8282-8283`（`CheckProtoFlat`，函数体 `8273-8483`；策略建改经 `api/rest/strategy_handler.go:30` → `schema.ValidateStrategy` → `schema/semantic.go:131` 进入） |
| 11 | `probe_neg_layers_flat_mix` | `layers` + 顶层 `src_port` 并存 | `config mixes layers with flat four-tuple field src_port` | `schema/semantic.go:186-190` |
| 12 | `probe_neg_static_copy` | `layers` 内静态标量四元组 + `flow_control.flows=2` | `layers pin a static four-tuple but flows > 1` | `schema/semantic.go:285` |

**注记（不建例，归 smb 套件）**：`op_type` 非法（锚 `smb: OpType must be read/write/close/query_directory/query_info/set_info/flush/echo/lock/ioctl`，`validate.go:105-106`）与 `auth_rounds` 越界（锚 `smb: AuthRounds must be 1-3 (0 for default)`，`validate.go:61-63`）已由 smb 套件的 `smb_tneg_T233_optype_invalid` / `smb_tneg_T230_rounds_oob` 覆盖（两 ID 实测存在于 `cases/smb.json`），probe 家族不重复建例。

**缺口**：**「层链 + 顶层空 `smb` 子映射并存」判死锚词今日不存在**——`CheckProtoFlat`（`strategy_convert.go:8273-8483`）与 `ValidateProtocolSubConfigs`（`internal/core/validate.go:63-236` 的 case 列表）都无 `smb` 分支，实读确认。故本族的 presence 负例只能**立项**（G-PROBE-SMB-2），不许伪造锚词。

## 13. 语义场景索引与 packet_count 映射

共 **12 个唯一语义 ID**：9 正 + 3 负。顺序须与 `78-probe_smb-testcase.md` §2 及未来 `cases/probe_smb.json` 完全一致。

| # | ID | 类型 | 诊断目标 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `probe_explicit_close` | 正 | 显式单 close：CLOSE 恰一对，无隐式重复（存量例迁移） | 25 |
| 2 | `probe_default_session` | 正 | 零负载默认保底会话（默认单 read + 隐式 CLOSE） | 25 |
| 3 | `probe_ops_multi_round` | 正 | 同连接多轮操作 read→write→close | 29 |
| 4 | `probe_error_on_close` | 正 | 非正常结束：close 错误注入，拆解继续 | 25 |
| 5 | `probe_echo_liveness` | 正 | 同连接多轮 ECHO 活性探测 | 27 |
| 6 | `probe_netbios_139` | 正 | 139 NetBIOS Session Service 载体 | 25 |
| 7 | `probe_ipv6_session` | 正 | IPv6 载体独立 fixture | 25 |
| 8 | `probe_multi_flow_dynamic` | 正 | 多流（flows=2 + 端口动态对象） | 50 |
| 9 | `probe_pcap_nic_consistency` | 正 | pcap / NIC 双输出一致 | 25 |
| 10 | `probe_neg_flat_keys` | 负 | 顶层扁平键判死 | — |
| 11 | `probe_neg_layers_flat_mix` | 负 | layers + 顶层四元组混用判死 | — |
| 12 | `probe_neg_static_copy` | 负 | 静态复制判死 | — |

**packet_count 推导口径（诚实标注，P5 前不是断言值）**：`3（握手）+ 2×8（会话八阶段的 PDU 对，其中 SESSION_SETUP 按 ntlm 默认 3 轮 = 6 包）+ 4（拆解）+ 2×(操作数−1)`。交叉验证：同形 smb 存量例 `smb_tpos101_close`（单 close）pin **25**、`smb_terr132_close_error`（write+close）pin **27**——与公式逐值一致（实测两 pin 存在且值为 25/27）。**存量 probe 例的 24 与此矛盾**（24 = 25−1，即 legacy 3 包挥手时代残值；换分支 commit `34a52d4` 曾把它改为 25 并写明"链上 TCPGenerator 标准 4 包，probe_smb 漏同步"，但**该 commit 不在当前 HEAD**——`git branch --contains 34a52d4` 仅 `feat/68-hl7`）。故 24 属**过期值**，P5 必须以落盘 pcap 先跑后钉复算（9.31/14.20），不得照抄。

## 14. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §10 强制展开：旧键五个去向逐项落定（`src_ip/dst_ip/src_port/dst_port` → ip/tcp 层，`count` → `flow_control`），顶层 `smb` 子映射=已登记过渡（D-PROBE-SMB-1 迁入计划）；目标形状 spec_json 样例见 §2；存量现例原文+判死锚见 §10 | 本契约 §2/§10/§15；`cases/probe_smb.json` |
| §2 策略/任务 | 策略=单 SMB 探测模板（自带 `flow_control`）；任务=多策略合跑+总量封顶；框架语义未动 | 本契约 §2；CORE_MEMORY §2.1/2.2 |
| §3 五件套 | 见 §9 强制展开：会话表 s1–s5、事务序列八阶段+四件事、关联关系（无派生副流，诚实声明）、插入位置（终结层）、时间线（会话内有序/跨会话并发）；3.14 审计与 3.15 三项逐项落表 | 本契约 §9；用例 3/4/5 |
| §4 查规范 | MS-SMB2（会话状态机/头 64B/CLOSE 体，经 `07-smb-design.md` 逐字段表）+ tshark 3.6.14 实测（`smb.` 652/`smb2.` 533）+ 本仓库实现对照；三路对照与候选对比见 §8；八项矩阵见 §7 | 本契约 §7/§8 |
| §5 依赖与错误 | 依赖＝`tcp`（单值 `DependsOn ["tcp"]`，`registry.go:1028`）；错误分支＝§12 三负例锚词逐字实读；无锚可用的 presence 面**立项不伪造**（G-PROBE-SMB-2） | 本契约 §12/§15/§18 |
| §6 性能 | 流式：一 PDU 一事件，无全量聚合；每会话 O(1) 包数；pcap/NIC 双路验收；吞吐目标**待 P4 基准**（不写承诺数字，6.5） | 本契约 §16 |
| §7 三份文档 | 78-probe_smb-{design,testcase}.md（ID 权威＝testcase §2）+ D-PROBE-SMB-1（本文 §15，门1 获批＝定稿）；schema 面 smb 行已存在（无新增注册） | 本文 §15/§19；testcase §11 |
| §8 设计先行 | 本条 P1–P3 先于 P5；门1 获批＝D-条目定稿＝开工门 | 提交序 |
| §9 测试三源 | ①规范/官方文档＝MS-SMB2 会话状态机与 CLOSE 体 ②设计＝D-PROBE-SMB-1 ③现网/实测＝tshark 字段实测 + smb 存量 pin（25/27）+ deep_audit 伪影定性；三源回指行见 testcase §6 | testcase §6 |
| §10 评审闭环 | 各阶段对抗自重审结论见 `/tmp/pipe/49-probe_smb/p123-report.md` | 报告 |
| §11 白话 | 汇报先一句白话结论 | 报告 |
| §12 动态清单 | 见 §11 强制展开：四元组四键开（layer_dyn allowlist 实读），业务五类逐个列不开+理由；序号算法位置实读 `parseLayerDyn:78`/`resolveLayerTuple:770`/`checkLayerDynObjects:329` | 本契约 §11 |
| §13 schema 派生 | 无新增层/字段注册（裁定 P1 归并）→ 无 schemagen 变更、无 `protocols.go` 白名单变更（`smb` 已在 `protocols.go:45`）；用例文件形状变更不触发生成器 | §1.1 实读表 |
| §14 真实流程 | suite 经 MCP 建策略建任务→引擎生成→pcap 落 `/tmp/mcp-pcaps/smb/`→tshark `smb2.*`/`nbss.*` 逐字段核对；先跑后钉（§13 推导口径）；`CASE_PROTO=smb` 会连带加载本族（proto 过滤按 case 字段：`tools_testdrive.go:814-816`） | §13/§17；testcase §10 |

## 15. D-PROBE-SMB-1（代码设计条目，八要素）

**状态**：P2 定稿待批（门1 获批＝定稿＝开工门）。**依据**：本文 §1–§13 + MS-SMB2 会话状态机 + 实读接线表。

1. **改哪几个文件**：①`trafficgen/test/protocol_pcap/cases/probe_smb.json`（12 例改写为过渡形；**唯一**必需文件改动）；②本文与 testcase 两份文档；③**不改任何 `.go`**。目标形落地属 smb 迁移（G-PROBE-SMB-1，归 #50 车道，文件＝`internal/core/layers/chain_planner_translate.go` 新增一个协议本地 `case "smb"` 块）。
2. **接口签名**：**N/A**——本族无 Go 接口新增/变更（裁定 P1）。用例契约类型沿用 `internal/pcaptest` 的 `Case`（`internal/pcaptest/types.go`，pcap 命名 `CasePcapName:93-97`）。
3. **数据结构**：用例 `spec_json` 形状＝`{"layers":[{"ip":{...}},{"tcp":{...}},{"smb":{}}],"smb":{...},"flow_control":{...}}`（过渡形）；`expect` 正例＝`{packet_count, directional, fields[], frames[]?, notes[]?}`，负例＝`{expect_error, error_contains}`（严格两键）。
4. **主流程**：MCP `flowb_run_protocol_suite`（`case_dir`＝cases 目录，`proto=smb`）→ 逐例建策略（REST 校验入口：`schema/semantic.go:120-176`）→ 建任务 → 引擎链生成（`ChainPlanner("smb")`，`main.go:614`）→ pcap 落 `/tmp/mcp-pcaps/smb/<caseID>.pcap` → `VerifyPcap` 逐字段。
5. **错误分支**：§12 三负例（锚词逐字实读）；错误传播必须是任务终态 error，不得 `completed/0 packet`（14.12）。
6. **性能边界**：单例 ≤ ~50 包（多流例 2×25）；12 例全量 < 400 包；无新增锁/队列/内存结构；单流内存增量＝一次 `SMBConfig`（`types.go:9944+`）。
7. **与现有逻辑的冲突点**：①与 #50 smb 车道同目录同级文件（`cases/` 下两文件，无同文件写冲突；但 `translateTerminalConfig` 的 `case "smb"` 与 `coverage_gate.check_smb` 均归 #50，probe 车道不得自插同块）；②顶层 `smb` 过渡形与 1.11 白名单的冲突＝**已登记过渡**（本条目 3 号要素即迁入计划），门 2-1 黄灯不升红；③存量例 `packet_count:24` 与 smb 族 pin 25 冲突＝P5 先跑后钉修正（§13）。
8. **回滚方式**：单文件 `git revert`（用例文件 + 两文档），无代码回滚面；若 smb 车道迁移先行完成（B 落地），probe 用例同步切目标形，回滚仍为单文件。

## 16. 性能设计与验收（CORE_MEMORY §6）

| 要素（6.1–6.8） | 内容 |
|---|---|
| 性能目标与规模边界（6.1/6.2） | 单例包数 ≤50（实测口径，非承诺吞吐）；并发会话数＝`flow_control.flows`（probe 家族默认 1，多流例 2）；单流最大报文＝SMB2 PDU（CLOSE 请求 ~90B 级，不触发 MSS 分段）；内存上限＝每流一份 `SMBConfig`；队列/缓冲＝沿用引擎既有有界队列，本族不新增；CPU 并行度＝沿用 PacketWorkers 缺省 |
| 双路验收（6.3） | pcap 路＝`CASE_PROTO=smb` 落盘 + `VerifyPcap`；NIC 路＝编号 9（`output_type=port_group` + `nic_capture`，接口按 `testing-interface` 记忆口径） |
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
| J1 | 同批跑：`CASE_PROTO=smb` 一次加载两文件（`smb.json` 279 + `probe_smb.json` 12 = 291 例） | `tools_testdrive.go:814-816` proto 过滤按 case 字段；结果 total 应含本族 12 例 |
| J2 | close 族包数对账：`probe_explicit_close` vs `smb_tpos101_close`（同 spec 形状） | 两者落盘 pcap 包数一致（同口径 25，或按 pcap 复算后的同值）；不一致即有一条错 |
| J3 | 错误注入对账：`probe_error_on_close` vs `smb_terr132_close_error` | CLOSE 对计数一致（各 1 对）+ 拆解阶段仍完整 |
| J4 | 偏移对账：CLOSE 体起点 offset | probe 与 smb close 族 frames 同偏移（IPv4 122，实测口径） |
| J5 | 反查归属：`coverage_gate.py` `check_smb` 块 | 归 #50 smb 车道编写；本族 12 例**不进**该块分母，出口仍须为 0（并发方案 §2 M1 条） |
| J6 | 伪影口径：probe 帧的 NTLMSSP 越界读 | `deep_audit.py:127-152` 既有定性对迁移后的帧仍成立（notes 声明，不进负例） |
| J7 | 迁移顺序：目标形（`layers[].smb` 业务键）落地 | 由 #50 车道补 `case "smb"` 后，本族 12 例切目标形并复跑全绿（切换前不得声称目标形可用） |

## 18. 缺口立项清单（**缺口数 = 5**）

| 立项号 | 缺口 | 去向 |
|---|---|---|
| **G-PROBE-SMB-1** | 层内 smb 业务键无消费面：`translateTerminalConfig` 无 `case "smb"`（实读全 case 列表），写了不报错但不生效——目标形不可达 | **归 #50 smb 车道**（同文件同 switch 的协议本地块，与 convert switch 同为预期合并冲突点）；probe 侧只做形状切换与复跑 |
| **G-PROBE-SMB-2** | presence 判死锚缺失：`CheckProtoFlat`（`strategy_convert.go:8273+`）与 `ValidateProtocolSubConfigs`（`validate.go:63+`）均无 `smb` 分支 → 「层链 + 顶层空 smb 子映射并存」无锚可断言 | 归 #50 车道补 presence 判死（文案同族：`protocol smb rejects a top-level smb sub-config (move it into the smb layer of a [ip,tcp,smb] layers chain)`）；补前本族不建该负例 |
| **G-PROBE-SMB-3** | INDEX 编号上限：`INDEX.md` §6.3 规定 NN 00–77 且已占满，本族取顺延号 78 | **主线程集成动作**：登记 INDEX（修订 §6.3 或补顺延号条款） |
| **G-PROBE-SMB-4** | 覆盖率台账口径：诊断族不进反查分母，需在 smb 反查块显式声明 | 归 #50 车道（`coverage_gate.py` `check_smb` 块内声明） |
| **G-PROBE-SMB-5** | 现网核对缺证据：真客户端（Windows/`smbclient`）探测首会话形态未核对 | P4 前置确认项（确认方式＝抓一份现网 445 首会话 pcap，比首 3 包）；不挡开工 |

**「明确不解决」项**：独立 probe 层/协议（裁定 P1，无注册面证据，重复 smb 语义）；SMB3 加密下的 probe 面（`encryption_required` 不编排）；compound/多 PDU 并一条 NBSS（生成器一 message 一 PDU）；TCP 层 keepalive 探测包（生成器不产）。

## 19. 修订记录

- v1.0.0（2026-09-26）：建立 probe_smb 设计与用例契约。裁定 P1（probe 非独立层/协议，归并 smb 子族）与编号 78；P1 八项矩阵 8 行 + 三子表；三路对照 + 三方案候选对比；五件套 + 3.14/3.15；§1/§3/§12 三行强制展开；12 例语义索引（9 正 + 3 负）+ packet_count 推导口径（含存量 24 过期值裁定）；D-PROBE-SMB-1 八要素；门1 十四行表；缺口 5 项。不修改 Go 实现。

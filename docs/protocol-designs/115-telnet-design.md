# #115 telnet（TELNET 网络虚拟终端，RFC 854 + 选项协商族）设计契约

> 版本：v1.0.0（批次二文档车道 P1–P3，as-built 型）
> 日期：2026-09-29
> 车道：文档轨（#115 telnet 续号）
> 旧基线：**本协议无旧编号设计文档**（`docs/protocol-designs/` 无 `NN-telnet-*`，`git ls-files` 实测零命中）。权威来源 = ①`docs/CODE_DESIGN.md` §D-TELNET-1 条目（层链化决策，**已验收 2026-09-19 P6**）；②`docs/TEST_CASES.md` §T-TELNET-1…17（存量审计 + 测试点清单）；③存量 1 例扁平用例（`git show d58bef9~1:…cases/telnet.json`）——本版承这三者，冲突处按代码/实测钉（§0）
> 存量用例：`trafficgen/test/protocol_pcap/cases/telnet.json`（**17 例**，ID/顺序/断言已机读实测；`spec_json` 顶层键 = `{layers}` ×15 + `{layers,telnet}` ×1（T-2 presence 负例）+ `{layers,group_id}` ×1（T-16））
> 规范基线：① **RFC 854**（Telnet 协议规范：NVT、IAC 命令族 §3、IAC 转义）；② **RFC 855**（选项规范：WILL/WONT/DO/DONT 语义与拒绝路径 §3）；③ RFC 857（ECHO）/ RFC 858（SGA）/ RFC 1073（NAWS）/ RFC 1091（TTYPE）/ RFC 856（BINARY）/ RFC 859（STATUS）/ RFC 860（TM）/ RFC 1079（TSPEED）/ RFC 1184（LINEMODE）/ RFC 1372（LFLOW）/ RFC 1572（NEW-ENVIRON）；④ **RFC 1143**（选项协商状态机 Q method——**规范要求面，本实现不落**，§3.5）；⑤ 本机 tshark 3.6.14 `telnet.*` 字段表（**58 字段**实测）+ 15 个实测 pcap（`/tmp/mcp-pcaps/telnet/`）；⑥ 本仓库落码（`internal/protocol/telnet/` 三文件 + 接线，§11）
> 白话一句：**Telnet 就是"两台机器隔着网线开一个字符终端"——数据就是普通 ASCII 字符流，唯一特殊的是一个 0xFF 字节：它一出现，后面跟的就是"命令"而不是字符；命令里最重要的一族是"我这个选项开不开"的互相商量（IAC WILL/WONT/DO/DONT + 选项号）。本生成器把这条字符流连同商量过程逐字节按剧本演一遍。**

## 0. 沿革与旧稿校正声明（门1 必答：基线继承关系）

本协议**没有旧编号设计文档**，也没有旧编号用例文档。本版是 **as-built 首次定稿**：把 D-TELNET-1 条目、T-TELNET-1…17 清单与存量 17 例 JSON 三方对齐，写成契约文档。逐条校正如下：

| # | 旧来源说法 | HEAD 实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | 无 `NN-telnet-design.md` / `NN-telnet-testcase.md` | `ls docs/protocol-designs/ \| grep telnet` = 0 行；`INDEX.md` 无 telnet 行 | **本协议文档首次成文**（编号 115，续 102-thrift 之后）；非续号重做 |
| 2 | D-TELNET-1 §1 文件清单："registry 新终层行（**14 键**：10 业务+2 端口+dialog{list}+file_source{object}）"；§3 主流程："ValidateLayers（V9 **14 键**）" | `registry.go:1841-1855` 机读实测 **12 键**：`banner/dialog/terminal_type/window_cols/window_rows/file_source/scenario/username/password/commands/src_port/dst_port` | **旧稿"14 键"是计数错误**（10 业务键里已含 dialog/file_source，再列一遍即重复计数）；本版 §11.1 按 12 键钉，差异列 G-TELNET-1 |
| 3 | D-TELNET-1 §4 红例③："链 [ip,telnet{ports}]→**13 包**+flags 序 0x02/0x12/0x10" | `telnet_migrate_test.go:91` `wantFlags` 13 项、`:119` 断言 `packets==13`；实测 pcap `telnet_basic_session.pcap` = **13 帧** | **一致** ✓（13 = 3 握手 + 6 默认 dialog 段 + 4 挥手） |
| 4 | D-TELNET-1 §6："包数=13 基线/33 场景缺省/**36-38** 长输出+synch（MSS 分段 **6/5** 段）" | 实测：`long_output` **36** 帧（大响应 8196B → 5×1460 + 896 = **6 段**）、`synch` **38** 帧（y 输出 `Repeat("y\r\n",2000)`=6000B → 4×1460 + 160 = **5 段**） | **一致** ✓（"6/5 段"= long_output 6 段 / synch 5 段，与实测逐段吻合；本车道跑码探针 + pcap 双向核对） |
| 5 | `docs/protocol-pcap-test/telnet.md` 写 "Cases: 17 — pass 17, fail 0, error 0"，逐例包数 13/13/0/0/8/27/33/36/33/0/28/26/8/38/16/13 | 17/17 包数**逐例与实测 pcap 一致**（本车道机读复核，§9 表）；但 `docs/protocol-pcap-test/telnet/` **目录不存在**（0 个 pcap），而该文档 15 处链接 `(telnet/<id>.pcap)` | **包数数字可信、链接全断**；末次提交 `d58bef9`（**2026-09-19**）**晚于**判死提交 `0417be5`（2026-09-13），故**不适用** opcua G-OPCUA-10 的"过期产物"口径——本缺口是"**pcap 未留档 + 15 条死链**"，列 G-TELNET-3 |
| 6 | D-TELNET-1 §3 主流程："validateLayer（legacy——v6 透明无冲突）"；§2："validator：legacy **5** 锚词" | `layer_gen.go:66-69` `validateLayer` 直调 `Planner.Validate`；`telnet.go:124-157` 实测 **5 个错误分支**：`not a valid IP address`×2、`too small (min`、`too large (max`、`unknown scenario` | **一致** ✓；其中 IP×2 与 MSS×2 在链路径**不可达**（schema 格式门先拦 + `spec.TCP` 恒 nil，§7） |
| 7 | `docs/TEST_CASES.md` §T-TELNET："C 类注记：③ MSS 链路径固定 1460（spec.TCP 不可达，1.12 口径）" | `layer_gen.go:36-45` 构造 `core.FlowSpec` 时**不含 `TCP` 字段** → `spec.TCP` 恒 nil → `telnet.go:178-181` `mss` 恒 `DefaultMSS=1460` | **一致** ✓（MSS 配置键在链路径无入口 = C 类，§8） |
| 8 | `docs/TEST_CASES.md` §T-TELNET："C 类注记：② RFC 1143 协商状态机不做（legacy 合同逐字发射，不冒充真协商）" | `telnet.go:18-21` 头注逐字："The planner does **NOT** implement Option negotiation state (RFC 1143 Q method); it emits the dialog verbatim"；`telnet.go:370-488` `renderTelnetEvent` 纯映射无状态 | **一致** ✓；**这是本协议最重要的诚实边界**——规范要求的四态机在 §3.5 写全，标待实现边界 |
| 9 | `docs/TEST_CASES.md` §T-TELNET："T-12 扩为 dialog 多事件例（nop/ayt/brk/ao/ec/el/ga 七单字节命令逐个入 dialog）" | `cases/telnet.json` T-12 dialog 9 事件：ttype_is/naws/nop/ayt/brk/ao/ec/el/ga；实测 pcap p6–p12 各 2B 帧 `ff f1/ff f6/ff f3/ff f5/ff f7/ff f8/ff f9` | **一致** ✓（§9 表 T-12 逐字节列全） |
| 10 | `docs/TEST_CASES.md` §T-TELNET："随机面 serverSeq/clientSeq/ip.id 断言避开" | `telnet.go:215-222` `clientSeq`（`spec.TCP` nil → 恒 `rand.Uint32()`）、`serverSeq=rand.Uint32()`、`ipID=rand.Uint32()` 基址 | **一致** ✓（链路径 `InitialSeq` 亦不可达——同 `spec.TCP` 恒 nil）；本版 §6 明确断言面只到 flags/端口/事件字节 |
| 11 | D-TELNET-1 §1："Modify: `internal/core/layers/generator.go`+`chain_planner_chain.go`——FlowMeta.Telnet+carry" | `chain_planner_chain.go:28` 实测有 `Telnet: spec.Telnet` carry | **一致** ✓（§11.1 接线表） |
| 12 | D-TELNET-1 §1："Modify: `cmd/server/main.go:178,545`" | 实测 `main.go:196`（空导入）+ `main.go:578`（`RegisterPlanner(layers.NewChainPlanner("telnet"))`）——行号已漂移 | **行号漂移**（后续提交增行所致），事实一致；本版 §11.1 按 HEAD 行号 |

**依赖链判定纪律**：以上均为可判题（旧文→代码/pcap 二级对照），直接判定，不问偏好。**不可判的**（tshark 对 Telnet 的 `telnet.data` 伪影是否属工具缺陷）标"待确认"并写清确认方式（G-TELNET-4）。

**产物过期登记（G-TELNET-3）**：`trafficgen/docs/protocol-pcap-test/telnet.md`（**tracked 产物**，`git ls-files` 可证）写 "Cases: 17 — pass 17, fail 0, error 0"，末次提交 `d58bef9`（**2026-09-19 20:27**）——**晚于**判死提交 `0417be5`（2026-09-13 00:25），故**不属** opcua G-OPCUA-10 的"末次提交早于判死提交"口径。该文档的 17 个包数**本车道已逐例对实测 pcap 复核，全对**（§9 表）；缺口是另一件事：`docs/protocol-pcap-test/telnet/` **目录根本不存在**（非"空目录"），而文档内 15 处 `(telnet/<id>.pcap)` 链接全部指向该目录。**本车道未跑该套件**（17 例 pcap 取自 `/tmp/mcp-pcaps/telnet/`，系 P5 落盘副本，非本车道产出），故本文档**不以任何形式**（含"今日已跑通"）引用该产物作为套件可跑证据。

## 1. 范围、profile 与实现状态边界

本版定义 **TELNET（RFC 854 NVT + IAC 命令流）承载于 TCP 23** 的流量生成：TCP 三向握手 → 可选服务器 banner → 可选 FileSource 载荷 → 事件编排会话（选项协商 IAC 序列 / NVT 数据 / 子协商 SB）→ TCP 四包挥手。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `telnet_tcp_v1`（主） | TCP，fixture 23 | 握手 → banner/file_source → dialog 事件序 → 挥手 | 真实服务器语义（登录是否成功、命令是否真执行） |
| `telnet_scenario_v1` | 同上，仅 `scenario` 非空 | 6 场景白名单自动生成 dialog（覆盖手动 Dialog） | 场景内凭据/命令的真实效果 |
| `telnet_ipv6_v1` | 同上，仅外层 IPv6 | 同上（字节面与 v4 完全同构，仅载荷起点 54→74） | 从 IPv4 fixture 推导 IPv6 地址 |

显式边界（"不实现、不声称、不许静默转换"）：① **不实现 RFC 1143 选项协商状态机**——`renderTelnetEvent`（`telnet.go:370-488`）是**无状态纯映射**，`dialog` 里写什么就发什么（§3.5 写全规范要求的四态机作为待实现边界，G-TELNET-5）；② 不实现 NVT 的 CR 规范化——`Data` 里 CR 是否跟 LF/NUL 由用户自负（`types.go:8258-8261` 自认）；③ 不实现真协商的子协商语义——`sb` 事件的 `SubData` 是用户给的原始字节，生成器只做 0xFF 转义；④ 不实现 telnet over TLS（RFC 2946 STARTTLS / `telnet.telnet.starttls` 字段存在但本层无入口）；⑤ 不实现 BINARY 模式下的 8 位透明语义保证——`data_b64` 可承载任意字节，但转义规则对 0xFF 一视同仁（§3.3）；⑥ 不实现 TN3270E / COMPORT / AUTH 等专用子协商（选项码常量表里只有 11 个常用选项，§3.2）；⑦ 不实现 synch 的 TCP URG 位——`core.L4Config` 无 `UrgentPointer` 字段（`telnet.go:478-481` 自认，G-TELNET-6）。

**实现状态（2026-09-29 实测）**：`telnet` 层已注册（`registry.go:1841`，`CategoryTerminal`，`DependsOn ["ip"]`，**Fields 12 键**）；planner/scenario/生成器已落码（`internal/protocol/telnet/` 三文件共 **966 行**：`telnet.go` 563 / `scenario.go` 329 / `layer_gen.go` 74，`wc -l` 实测）；`allowedProtocols["telnet"]=true`（`protocols.go:58`）；层内 translate 已接线（`chain_planner_translate.go:1571`）；扁平 parse 与 presence 判死均在案（`strategy_convert.go:1522`/`:8959`）；`isRawIPChain` 收录（`chain_planner_util.go:54`）；端口豁免两名单收录（`chain_planner.go:764` dst / `:996` src）；静态复制门扫描面收录（`semantic.go:214`）；端口动态四件套收录（`layer_dyn.go:62`/`:252`/`:846` + `types.go:3679`）；main 空导入 + 注册（`main.go:196`/`:578`）；17 语义用例已落 `cases/telnet.json`。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport/srcport`、`tcp.flags`、`tcp.len`、`eth.type`、`telnet.data`、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, telnet]`（引擎自动补 `ip`；**不允许 `[ip,tcp,telnet]`**——`isRawIPChain`（`chain_planner_util.go:40-58`）见到链内含 `tcp`/`udp` 即返回 false，telnet 终层自驱会失去驱动权）。telnet 层是**raw-IP 自驱终层**：它自产**完整以太帧**（含 TCP 头与生命周期），不由 tcp 层托管。

端口：Telnet 默认 **TCP 23**（RFC 854 / IANA）。fixture 统一 `dst_port=23`；用例一律显式写端口并纳入断言（T-15 例外，专测缺省补齐）。

固定偏移：无 VLAN/IP options/TCP options 时，**每帧 Telnet 载荷起点为 IPv4 offset 54**（14+20+20）、**IPv6 offset 74**（14+40+20）。载荷内字段偏移按 §3.1 递推；**数据段按 MSS 分段后，段内偏移各自从载荷首算**。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"telnet": {"src_port": 12345, "dst_port": 23, "scenario": "login_full", "username": "bob"}}
  ]
}
```

多流样例（数量只走 `strategy_fc`；端口必须写成动态对象，静态端口 + flows>1 会被 `static four-tuple` 门判死，§7）：

```json
{
  "layers": [
    {"ip": {"src": {"strategy": "inc", "range": ["10.0.1.1", "10.0.1.2"], "step": 1}, "dst": "20.0.0.1"}},
    {"telnet": {"src_port": {"strategy": "inc", "range": [20000, 20001], "step": 1}, "dst_port": {"strategy": "fixed", "value": 23}}}
  ],
  "strategy_fc": {"type": "flows", "value": 2}
}
```

## 3. 线格式编码（逐项标注 RFC 出处；偏移均相对载荷首字节）

### 3.1 IAC 命令族（RFC 854 §3，`telnet.go:72-89`）

流里任何 **0xFF** 字节都是"解释为命令"（Interpret As Command）的引子。紧随其后的一字节是命令码：

| 码 | 名称 | 含义 | 本层事件类型 | 线上字节数 |
|---:|---|---|---|---:|
| 240 | SE | Subnegotiation End（子协商结束） | 由 `sb` 自动补 | — |
| 241 | NOP | No Operation | `nop` | 2 |
| 242 | DM | Data Mark（与 IP 合成 Synch） | `dm` | 2 |
| 243 | BRK | Break | `brk` | 2 |
| 244 | IP | Interrupt Process | `ip` | 2 |
| 245 | AO | Abort Output | `ao` | 2 |
| 246 | AYT | Are You There | `ayt` | 2 |
| 247 | EC | Erase Character | `ec` | 2 |
| 248 | EL | Erase Line | `el` | 2 |
| 249 | GA | Go Ahead | `ga` | 2 |
| 250 | SB | Subnegotiation Begin | `sb` | 3 + 子数据 + 2 |
| 251 | WILL | 我打算开启某选项 | `will` | 3 |
| 252 | WONT | 我拒绝/关闭某选项 | `wont` | 3 |
| 253 | DO | 请你开启某选项 | `do` | 3 |
| 254 | DONT | 请你关闭某选项 | `dont` | 3 |
| 255 | IAC | 转义字节本身 | （见 §3.3） | 2（双写） |

**两族形状**：① **三字节协商命令** `IAC <cmd> <option>`（WILL/WONT/DO/DONT）；② **两字节单命令** `IAC <cmd>`（NOP/DM/BRK/IP/AO/AYT/EC/EL/GA）。`renderTelnetEvent` 逐类型硬编码返回（`telnet.go:383-390` 三字节族 / `:458-475` 两字节族），**不做任何长度推导**。

**`synch` 快捷形**（`telnet.go:477-481`）：`IAC IP` + `IAC DM` = 4 字节 `ff f4 ff f2`。RFC 854 §3 规定 Synch 由 IP 后跟 DM 组成，DM 段**应带 TCP URG**——本实现不设 URG（G-TELNET-6）。

### 3.2 选项码表（RFC 855 + 后续 RFC，`telnet.go:92-104`）

| 码 | 选项 | 出处 | 本层 |
|---:|---|---|---|
| 0 | BINARY | RFC 856 | 常量在案；`option` 可自由写 |
| 1 | ECHO | RFC 857 | 常量 `OptEcho`；login_full/login_fail 密码段用它 |
| 3 | SGA | RFC 858 | 常量 `OptSGA`；defaultDialog 与协商头用它 |
| 5 | STATUS | RFC 859 | 常量 `OptStatus` |
| 6 | TM | RFC 860 | 常量 `OptTM` |
| 24 | TTYPE | RFC 1091 | 常量 `OptTType`；有专用事件 `ttype_send`/`ttype_is` |
| 31 | NAWS | RFC 1073 | 常量 `OptNAWS`；有专用事件 `naws` |
| 32 | TSPEED | RFC 1079 | 常量 `OptTSpeed` |
| 33 | LFLOW | RFC 1372 | 常量 `OptLFLOW` |
| 34 | LINEMODE | RFC 1184 | 常量 `OptLinemode`；option_reject 场景用它 |
| 39 | NEW-ENVIRON | RFC 1572 | 常量 `OptNewEnviron`；option_reject 场景用它 |

**`option` 字段宽度 = 1 字节（uint8）**，取值 0–255 全开（`types.go:8243` `Option uint8`）；无值域校验——未知选项码照发（真实协商才需要白名单，本层不做协商）。

### 3.3 IAC 转义（RFC 854 §3；`escapeIAC`，`telnet.go:494-521`）

**规则**：数据流里出现的字面 0xFF 必须**双写**为 `ff ff`，否则接收方会把它当命令引子。本实现对**三处**施加转义：

| 位置 | 代码 | 说明 |
|---|---|---|
| `data` 事件（`Data` 或 `DataB64` 解码后） | `telnet.go:376-381` | 每个 0xFF → `ff ff` |
| `sb` 事件的子数据（`SubData` 或 `SubDataB64` 解码后） | `telnet.go:395-401` | 同上 |
| `banner` / `file_source` 字节 | `telnet.go:292` / `:300` | 同上 |
| `ttype_is` 的终端类型串 | `telnet.go:427` | 同上（正常终端名不含 0xFF，防御性保留） |

**不施加转义**：IAC 命令序列本身（WILL/WONT/DO/DONT/SB…SE/NOP/IP/DM/…）——它们**就是**引子，不是数据（`telnet.go:365-369` 注释口径）。

**实现细节**：`escapeIAC` 先数 0xFF 个数精确预分配；无 0xFF 时返回**副本**（不别名入参，`telnet.go:504-510`）；空输入返回空切片（`:495-497`）。

**长度公式**：`len(out) = len(in) + count(0xFF in in)`。

### 3.4 子协商 SB 编码（RFC 855 §5 + RFC 1091 + RFC 1073）

**通用形状**（`sb` 事件，`telnet.go:392-406`）：

```
IAC SB <option:1B> <sub_data 已转义> IAC SE
ff  fa  <opt>       <...>              ff  f0
```

长度公式：`5 + len(escaped_sub)` = 3（`IAC,IACSB,opt`）+ 子数据 + 2（`IAC,IACSE`）。代码按 `4+len(sub)+2` **预分配容量**（多算 1 字节，不影响实际写入长度，`telnet.go:402-406`）。

**TTYPE 专用两形**（RFC 1091）：

| 事件 | 线上字节 | 长度 | 出处 |
|---|---|---:|---|
| `ttype_send` | `ff fa 18 01 ff f0` | **6** | `telnet.go:408-410`（常量 `TTypeSEND=1`，`OptTType=24=0x18`） |
| `ttype_is` | `ff fa 18 00 <value 已转义> ff f0` | **7 + len(value)** | `telnet.go:412-429`（常量 `TTypeIS=0`） |

`ttype_is` 的 `value` 取值链（**三级兜底**，`telnet.go:415-421`）：事件 `Value` → `TelnetConfig.TerminalType` → 常量 `"xterm"`（`DefaultTerminalType`，`telnet.go:63`）。

**NAWS 专用形**（RFC 1073；`telnet.go:431-456`）：窗口尺寸 **4 字节大端**，`cols` 在前 `rows` 在后：

```
IAC SB NAWS <cols_hi> <cols_lo> <rows_hi> <rows_lo> IAC SE
ff  fa  1f   <...4 字节大端...>                     ff  f0
```

**恒 9 字节**。编码用 `binary.BigEndian.PutUint16`（`telnet.go:449-451`）。取值链同三级兜底（`:435-448`）：事件 `Cols`/`Rows` → `TelnetConfig.WindowCols/Rows` → 常量 80×24。

> **零值陷阱（诚实声明，G-TELNET-7）**：`cols==0` 是 `uint16` 的零值，**无法与"未设置"区分**——所以 `{"type":"naws"}` 且配置 `window_cols=0` 时**必然**落到 80 兜底，**无法发出真正的 0×0 NAWS**。`planner_testpoints_test.go:524` `TestSB_NAWS_0x0` 已实测记录该行为（该测试用 `t.Logf` 而非断言钉死，属**弱断言**）。本版按实测行为钉，差异列 G-TELNET-7。

### 3.5 选项协商状态机（RFC 855 §3 + RFC 1143 Q method）——**规范要求面，本实现不落**

> **本节写的是规范要求的完整语义，用于界定"本实现缺什么"。本层不实现它（`telnet.go:18-21` 头注逐字声明），`dialog` 里写什么就发什么。**

RFC 1143 为每个选项定义**四态**与**转移表**：

| 状态 | 含义 |
|---|---|
| `NO` | 选项未启用，双方无未决请求 |
| `YES` | 选项已启用 |
| `WANTYES` | 本端已发请求，等待对端应答 |
| `WANTNO` | 本端已发拒绝，等待对端应答 |

**收到对端请求时的转移**（RFC 1143 §2 表格语义）：

| 本端态 | 收到 WILL（对端想开） | 收到 DO（对端要我开） |
|---|---|---|
| `NO` | 若本端愿开 → 回 DO，进 `YES`；否则回 DONT，留 `NO` | 若本端愿开 → 回 WILL，进 `YES`；否则回 WONT，留 `NO` |
| `YES` | 回 DO（幂等确认） | 回 WILL（幂等确认） |
| `WANTNO` | 若对端也请求同一选项 → **冲突**，回 DONT（RFC 855 §3 的循环拒绝防护） | 同左 |
| `WANTYES` | 回 DO，进 `YES` | 回 WILL，进 `YES` |

**同类还有 `WONT`/`DONT` 侧的对称表**（收到 WONT/DONT 时的降级路径）。

**本实现的对应关系（诚实声明）**：生成器把"协商过程"当成**用户写好的字节剧本**——用户要演"服务器 WILL ECHO、客户端 DO ECHO"，就在 `dialog` 里写 `{"type":"will","direction":"down","option":1}` + `{"type":"do","direction":"up","option":1}`。**生成器不推导**"客户端该回什么"，也不维护任何选项态。因此：① 用户可写出**违反状态机的序列**（如对端没请求就回 DO），生成器照发；② 用例断言的是**字节序列**，不是"协商结果正确"。这条边界是 `docs/TEST_CASES.md` §T-TELNET C 类注记②的原文口径，列 **G-TELNET-5（待实现边界）**。

**拒绝路径（RFC 855 §3）是可演的**：`option_reject` 场景（`scenario.go:248-279`）演示了 WILL→DONT 与 WILL→DONT 两条拒绝路径，字节可断言（T-8）。

### 3.6 NVT 数据与分段

**数据事件**（`data`）承载 NVT ASCII 字节：`Data`（字符串，`types.go:8248`）或 `DataB64`（base64，优先，`types.go:8254`，供非 UTF-8 二进制流用）。两者都过 `escapeIAC`（§3.3）。

> **为什么需要 `DataB64`（实测教训，T-10 notes）**：JSON 字符串无法表达单字节 0xFF——写 `"ÿ"` 会被 UTF-8 重编码成 `c3 bf` 两个字节，转义后变成 `c3 bf c3 bf`，与意图不符。故二进制/含 0xFF 的载荷必须走 `data_b64`。

**MSS 分段**（`segmentByMSS`，`telnet.go:530-547`）：每个数据事件先按 `mss` 切片，**每片独立成一个 PSH-ACK 段**，发件方 seq 逐段累加（`emitData`，`telnet.go:275-281`）：

| 输入 | 输出段 |
|---|---|
| `len==0` | 单个空片（调用方据 §4.1.1 跳过，不发 PSH-ACK） |
| `mss<=0` | 整块一片（不切） |
| 其余 | `ceil(len/mss)` 片，末片可短 |

**链路径 MSS 恒 1460**（`DefaultMSS`，`telnet.go:51`）——`spec.TCP` 恒 nil（§0 #7），配置无入口。分段数 = `ceil(len/1460)`。

**IAC 命令不分段**：`renderTelnetEvent` 的输出（2/3/6/9 字节）恒小于 MSS，天然单片。

### 3.7 固定头部与偏移速查

| 项 | IPv4 | IPv6 |
|---|---:|---:|
| 载荷起点 | **54** | **74** |
| 以太帧 EtherType | `0x0800` | `0x86dd`（`builder.go:125` `EtherTypeFor`） |
| 握手 SYN 选项 | MSS(1460) + WinScale(7) + SACK-Permitted（`synOptions`，`telnet.go:553-562`） | 同 |
| 默认 TTL | 64（`DefaultTTL`，`telnet.go:47`） | 同 |

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明事件序列（`dialog[]`）或场景名（`scenario`），引擎按固定剧本产出完整 TCP 包序列；telnet 层是 raw-IP 自驱终层，握手/挥手/分段全在本层内完成。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 最小会话（默认剧本） | 握手 → WILL SGA / DO SGA → `login: ` → `alice` → `$ ` → `exit` → 挥手 | #1（`telnet_basic_session`） |
| ② 完整交互式登录 | 协商 11 事件 → login/password（含 echo 关开）→ shell → 多命令 → logout | #4（`telnet_login_full`） |
| ③ 认证失败重提示 | 同上，密码错 → `Login incorrect` + 重新提示 | #5（`telnet_login_fail`） |
| ④ 多命令执行 | 协商 → 登录 → N 条命令各带回显 → logout | #6（`telnet_multi_command`） |
| ⑤ 大输出翻页/分页 | 命令响应超 MSS → 多段 PSH-ACK | #7（`telnet_long_output`） |
| ⑥ 选项协商被拒 | SGA 接受 + NEW-ENVIRON/LINEMODE 拒绝 + TTYPE 接受 | #8（`telnet_option_reject`） |
| ⑦ 中断长输出（Ctrl-C 语义） | 长输出流中插入 IAC IP + IAC DM → 服务器 `^C` 重提示 | #9（`telnet_synch`） |
| ⑧ 二进制流承载 | 含 0xFF 的数据经转义后原样过线 | #10（`telnet_iac_escape`） |
| ⑨ 子协商（环境/终端/窗口） | SB NEW-ENVIRON / SB TTYPE IS / SB NAWS | #11（`telnet_sb_subneg`）、#12（`telnet_ttype_naws_singles`） |
| ⑩ 服务器 banner 前置 | 握手后立即推欢迎语，再进 dialog | #13（`telnet_banner`） |
| ⑪ IPv6 产线 | 同上，仅外层 IPv6（offset 74） | #14（`telnet_v6`） |
| ⑫ 端口缺省/动态 | 无端口键 → 23；端口动态 × flows=2 | #15（`telnet_default_port`）、#16（`telnet_port_dyn`） |

**五层覆盖逐层结论**：

- **功能层**——IAC 命令族 16 类（WILL/WONT/DO/DONT/SB/SE + 9 单命令 + synch）正例；错误处理 3 类负例（presence 判死 / 静态端口拒 / scenario 白名单拒，§7）；场景 6/6 全覆。
- **性能层**——MSS 分段（#7 大响应 8196B → 5×1460+896 = 6 段；#9 y 输出 6000B → 4×1460+160 = 5 段）、最小帧（2 字节单命令，T-12 p6–p12）、最大帧（1514 以太 = 1460 段）、多流（#16 flows=2）；设计参数见 §6。
- **数据场景层**——空 dialog（走默认剧本）、`data_b64` 二进制、`sub_data_b64`、显式/缺省 ttype、显式/缺省 NAWS、0xFF 转义（data 与 sub 两处）、7 单命令枚举、19 事件类型中的 11 类有 JSON 用例。
- **地址与流层**——v4/v6 独立用例（#14 offset 74）；单流基线（#1）；端口缺省/显式/动态三态（#15/#1/#16）；**流关联（控制流派生数据流）显式不适用**：Telnet 是单 TCP 连接上的字符流，无副连接、无子流（RFC 854 无此概念）；**多会话（`sessions[]`）显式不适用**：telnet 层 registry 无 `sessions` 键（12 键实测），多流由策略级 `strategy_fc {"type":"flows"}` 承载（#16）。
- **业务层**——12 场景全部有落点；**多会话/多事务**：单连接内多事件（#4 26 段、#6 26 段）即"多事务"，但**无会话间状态隔离概念**（无 TID/Cookie 类关联标识，诚实声明）；**现网复合大场景**：#4（协商+登录+echo 关开+双命令+logout，交织 4 类）与 #9（协商+登录+大输出+中断+重提示，交织 4 类）满足 CORE_MEMORY §9.50 三类交织下限。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① RFC 1143 协商状态机（未实现，G-TELNET-5）；② 真实 TN3270E/COMPORT/AUTH 子协商（选项常量表外，§1 边界⑥）；③ telnet over TLS / STARTTLS（本层无入口）；④ NVT CR 规范化（用户自负，`types.go:8258-8261`）；⑤ `synch` 的 TCP URG 位（框架无字段，G-TELNET-6）；⑥ RST 异常中断（框架能力，本层零断言，G-TELNET-8）；⑦ 链路径 MSS 配置（`spec.TCP` 恒 nil，G-TELNET-9）。

## 5. 消息/事务模型与状态机

**事务定义**：一次**数据段发送**（一个 `data` 事件的 MSS 分段结果，或一条 IAC 命令）即一个最小驱动单位。**多事务** = 一个连接内多段按序回放（#4 的 26 段、#6 的 26 段、#7 的 29 段）。

telnet 层**无自有状态机**：TCP 握手/挥手/分段全在层内以固定脚本完成（`telnet.go:283-339`），事件回放是**无状态纯映射**（`renderTelnetEvent`）。规范要求的选项协商状态机见 §3.5（未实现）。

| 阶段 | 产出帧 | 代码 | 用例 |
|---|---|---|---|
| 握手 | SYN(up) → SYN-ACK(down) → ACK(up)，3 帧，SYN 带 MSS/WinScale/SACK | `telnet.go:284-288` | 全正例 |
| banner（可选） | 1+ 帧 down PSH-ACK（按 MSS 分段） | `:291-294` | #13 |
| FileSource（可选） | 1+ 帧 up PSH-ACK（按 MSS 分段，**在 dialog 前**） | `:297-304` | #13 |
| dialog 事件 | 每事件 1+ 帧（`data` 按 MSS 分段；IAC 命令恒 1 帧） | `:307-327` | #1/#4–#12 |
| 挥手 | FIN-ACK(up) → ACK(down) → FIN-ACK(down) → ACK(up)，4 帧 | `:331-339` | 全正例 |

**事件序（`Plan`，`telnet.go:167-340`）**：`握手 3` → `[banner]` → `[file_source]` → `dialog 事件序` → `挥手 4`。

**方向语义（本层最易踩的一处）**：`emit`/`emitData` **逐 emit 自管方向**——`direction:"down"` 的包由 `emit` 调用方**自行交换** 源/目的 IP、端口、MAC（`telnet.go:286` vs `:284` 的实参顺序）。因此 `layer_gen.go:50-53` 在 relay 时把**每个包的 `Direction` 强制改为 `"up"`**（h323/mpls/ngap 同款"防双换"）：raw-IP 驱动若对 `down` 包再做一次 L3 换向，会换回原方向导致错包。实测佐证：`telnet_migrate_test.go:95` `wantDst = [23,12345,23,12345,23,12345,23,12345,23,23,12345,12345,23]`——**up 包 dst=23、down 包 dst=12345**（客户端口），与 `emit` 实参逐包对应。

**自动派生规则**：① `Telnet` 配置 nil → 走 `defaultDialog()`（6 事件最小登录形，`telnet.go:348-357`）；② `Dialog` 空且 `Scenario` 空 → 同上；③ `Scenario` 非空 → **覆盖** 手动 `Dialog`（`telnet.go:198-202`，`scenario_test.go:443` `TestScenario_DialogIgnoredInScenarioMode` 实证）；④ `Direction` 非 `"up"`/`"down"` → 归 `"up"`（`:319-321`）；⑤ 未知 `Type` → 当作空 `data` → 不产帧（`:483-486`）；⑥ 空 `data` → 不产帧（`:314-317`，设计 §4.1.1 口径）；⑦ TCP 握手/挥手由本层脚本自动补（不依赖 tcp 层）；⑧ ISN/ipID 随机（§6 断言边界）。

**场景白名单（6 个，`scenario.go:52-61`）**：`login_full` / `login_fail` / `multi_command` / `long_output` / `option_reject` / `synch`。未知值 → `telnet: unknown scenario %q`（锚词 `unknown scenario`）。

**场景参数默认值**（`scenario.go:68-91`）：`username="alice"`、`password="secret123"`、`terminal_type="xterm"`、`window_cols=80`、`window_rows=24`、`commands=["ls -la","whoami"]`。

**命令回显表**（`commandResponse`，`scenario.go:314-329`）：`ls*` → 目录列表；`whoami` → `alice\r\n`；`date*` → 日期行；`uname*` → `Linux host 5.10.0 #1 SMP x86_64 GNU/Linux\r\n`；`pwd*` → `/home/alice\r\n`；其余 → `\r\n`（仅换行）。

**大输出常量**：`scenarioLongOutputBytes = 8192`（`scenario.go:46`），`long_output` 场景发 `Repeat("A",8192) + "\r\n$ "` = **8196 字节**（`scenario.go:238`；**JSON summary 写 8197 是 off-by-one**，G-TELNET-2）；`synch` 场景发 `Repeat("y\r\n",2000)` = **6000 字节**（3 字节/单元 × 2000，`scenario.go:299`）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流全链 ≤38 帧（`telnet_synch` 实测，含握手挥手）；最大单事件载荷 8196 字节（long_output）；最大分段数 = `ceil(8196/1460)` = 6 段；MSS 上界 65535（`telnet.go:140-142`，链路径不可达）；`validateScenario` 白名单 6 值。
- **依据**：事件序列**流式产出**——`Plan` 在 goroutine 内逐帧写 `chan core.PacketConfig`（容量 **256**，`telnet.go:165`），**无全量聚合**；每帧内存 = 该帧 payload 长度（最小 2 字节单命令；最大 1514 字节以太帧）；无跨流共享状态（全部局部变量）；无锁。
- **验收两路（§6.3 强制）**：pcap（`/tmp/mcp-pcaps/telnet/<id>.pcap`，负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `tcp.flags`/`tcp.dstport`/`tcp.len`/`eth.type`/frames 原始 hex 与包数，**不只断言"任务没报错"**。
- **六类场景落点（§6.6）**：基线（#1，13 帧）/ 目标规模（#4/#6，33 帧 26 事件段）/ 压力上限（#9，38 帧；#7 8196B 跨 6 段）/ 长时间运行（#4/#6 多命令展开承载语义）/ 并发交错（#16 flows=2 承载，两流各自完整剧本）/ 背压（帧数精确计数守卫漂移 + 分段数 = ceil(len/1460) 守卫）。
- **回归口径**：suite ±10%；D-TELNET-1 §6 记录 P5 时四协议回归（ngap 17 / h323 17 / mpls 14 / icmpv6 11）全绿。

**断言边界（CORE_MEMORY §9.27，必须写清）**：ISN 随机（`clientSeq`/`serverSeq`，`telnet.go:215-222`）、ipID 随机（`:206-211`）→ **seq/ack 的绝对值和 ip.id 不可断言**，只断 flags 面与端口面；`telnet.data` 对 IAC 帧输出空串、且会 trim 尾部空白、`\r\n` 显示为字面转义（实测伪影，G-TELNET-4）→ **字节面以 frames hex 断言为准**；包间隔无断言面。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须被拒并传播为 task error，不得产出成功 PCAP 或"只剩 TCP 外壳"的假成功（3 个负例实测 pcap **均 0 帧**）：

| # | 负例 ID | 故障输入 | 锚词（代码逐字） | 代码行 | 时机 |
|---:|---|---|---|---|---|
| N-1 | `telnet_flat_presence` | 顶层 `telnet:{}` 与 `layers` 并存（**空 map 也死**） | `top-level telnet sub-config` | `strategy_convert.go:8961-8963` | create-time（400） |
| N-2 | `telnet_flat_static_port` | `[ip{}, telnet{src_port,dst_port}]` 静态端口 + `flows=2` | `static four-tuple` | `schema/semantic.go:285` | create-time（400） |
| N-3 | `telnet_neg_scenario` | `scenario:"telnet999"`（白名单外） | `unknown scenario` | `scenario.go:58` | task-time（validator） |

**负例原子性**：每例单一故障注入；单次执行不得混注。三例 `expect` 键集合均为 `{expect_error, error_contains, notes}`（**含 `notes`，非严格两键**，G-TELNET-10）。

**presence 负例形状（CORE_MEMORY presence-negative-case-shape 口径）**：N-1 的形状是 **层链 + 顶层空子映射并存**（`{"layers":[…],"telnet":{}}`）——这是**判死执法对象**，不是旧键残留。收官自查口径"非负例顶层键 = 0"在 T-16 上成立（其 `group_id` 是**框架键**，与 `layers` 同级允许，见 §12.1）。

**未入用例的拒绝分支（不得冒充已覆盖）**：

| 分支 | 锚词 | 代码行 | 链路径可达？ | 归属 |
|---|---|---|---|---|
| SrcIP 非法 | `telnet: SrcIP %q is not a valid IP address` | `telnet.go:127` | **不可达**（schema 格式门先拦） | 零死锚词（C 类） |
| DstIP 非法 | `telnet: DstIP %q is not a valid IP address` | `telnet.go:132` | **不可达**（同上） | 零死锚词（C 类） |
| MSS 过小 | `telnet: TCP.MSS %d too small (min %d per RFC 879)` | `telnet.go:138` | **不可达**（`spec.TCP` 恒 nil，§0 #7） | C 类（G-TELNET-9） |
| MSS 过大 | `telnet: TCP.MSS %d too large (max 65535)` | `telnet.go:141` | **不可达**（同上） | C 类（G-TELNET-9） |
| 未知 scenario | `telnet: unknown scenario %q (want …)` | `scenario.go:58` | **可达** | **已覆 N-3** |

**不得误报的合法协议事件**：未知事件 `Type`（静默跳过，非错误，`telnet.go:483-486`）；空 `data`（静默跳过，`types.go` 设计口径 §4.1.1）；`Direction` 写 `"left"`（归 `"up"`，非错误）；`option` 写未知选项码（照发，本层不协商）；非 23 端口（**非默认端口合法**，`telnet.go:144-146` 注释明写不硬校验）；IPv6 外层（**正例格**，非负例）；`flows>1` + 动态端口（合法，#16）；`flows>1` + 静态端口（**非法**，N-2）。

## 8. 边界

- **帧长**：最小应用帧 = 2 字节（单命令 `ff f1` 等，T-12 p6–p12）；最小以太帧 = 握手 54 字节；**最大以太帧 = 1514**（MSS 1460 满段，T-7 p25–p29）；banner/file_source 同样按 MSS 分段。
- **分段数**：`ceil(payload_len / 1460)`。实测：8196 → 6 段（T-7）；`Repeat("y\r\n",2000)` = 6000 → 5 段（T-9）；`secret123\r\n` 11 字节 → 1 段。
- **MSS**：链路径**恒 1460**（`spec.TCP` 恒 nil，无配置入口，G-TELNET-9）；`DefaultMSS=1460` 与 `MinMSS=536` 常量在案但链路径不可达。
- **选项码**：`uint8` 0–255 全开，无白名单校验（本层不协商）。
- **NAWS 尺寸**：`uint16` 0–65535，**大端**；`0` 无法表达（零值陷阱，G-TELNET-7）。
- **TTYPE 值**：任意字符串，转义后直出；三级兜底（事件 → 配置 → `"xterm"`）。
- **端口**：显式 `12345`/`23` 共 **12/14** 正例（T-15 无端口键专测缺省、T-16 端口动态）；缺省 23（translate 镜像 `setDefaultDstPort`，`chain_planner_translate.go:1647-1651`）；`src_port` 缺席 → 链路径**保持 0**（`chain_planner.go:996` 豁免名单），单流 worker 按 `12345+i` 保底（`strategy_convert.go:49`）；非 23 端口合法（不硬校验）。
- **地址族**：v4/v6 独立用例（#14 为 IPv6，offset 74）；**IP 版本透明**——`Validate` 无族强制（`telnet.go:124-157` 实证），`EtherTypeFor` v6 → `0x86dd`（`builder.go:125`）。
- **事件类型**：19 类中 **11 类有 JSON 用例**（data/sb/ttype_is/naws/nop/ayt/brk/ao/ec/el/ga）；`will/wont/do/dont/ttype_send/ip/dm` 经**场景**覆盖（#4/#8/#9）；**`synch` 事件类型零用例**（#9 用的是分离的 `ip` + `dm`，G-TELNET-11）。
- **多流**：`strategy_fc {"type":"flows", N}` + 端口动态对象（#16 flows=2 → 26 帧 = 2×13）。
- 不得产生回绕长度或超量分配（`escapeIAC` 精确预分配；`segmentByMSS` 按 `ceil` 预分配）。

## 9. 原子 ID 与完成定义（17 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 | 包数（实测 pcap） | JSON 断言形状 |
|---:|---|---|---|---:|---|
| 1 | `telnet_basic_session` | 正 | §3.1/§5：默认剧本 6 事件基线 | **13**（JSON `min_packets:12`，未收窄） | 8 fields + 6 frames + 3 标量 |
| 2 | `telnet_flat_presence` | 负 | §7 N-1：顶层 `telnet:{}` presence 判死 | 0 | `expect_error` + 锚词 |
| 3 | `telnet_flat_static_port` | 负 | §7 N-2：静态端口 + flows=2 | 0 | `expect_error` + 锚词 |
| 4 | `telnet_login_full` | 正 | §5：`login_full` 场景（26 事件段） | **33** | `min_packets:33` + 4 fields + 4 frames |
| 5 | `telnet_login_fail` | 正 | §5：`login_fail` 失败路径（20 段） | **27** | `min_packets:27` + 3 fields + 1 frame |
| 6 | `telnet_multi_command` | 正 | §5：`multi_command` + 双命令（26 段） | **33** | `min_packets:33` + 3 fields + 1 frame |
| 7 | `telnet_long_output` | 正 | §3.6/§6：8196B 跨 MSS 6 段（29 段） | **36** | `min_packets:36` + 4 fields |
| 8 | `telnet_option_reject` | 正 | §3.5：DONT/WONT 拒绝路径（21 段） | **28** | `min_packets:28` + 3 fields + 2 frames |
| 9 | `telnet_synch` | 正 | §3.1：IAC IP + IAC DM 中断（31 段） | **38** | `min_packets:38` + 3 fields + 2 frames |
| 10 | `telnet_iac_escape` | 正 | §3.3：`data_b64` 0xFF 翻倍 | **8** | `min_packets:8` + 3 fields + 1 frame |
| 11 | `telnet_sb_subneg` | 正 | §3.4：`sb` 框架 + `sub_data_b64` 0xFF 翻倍 | **8** | `min_packets:8` + 3 fields + 1 frame |
| 12 | `telnet_ttype_naws_singles` | 正 | §3.4/§3.1：ttype/naws 缺省 + 7 单命令枚举 | **16** | `min_packets:16` + 3 fields + 2 frames |
| 13 | `telnet_banner` | 正 | §5：banner + file_source 前置 | **15** | `min_packets:15` + 3 fields + 2 frames |
| 14 | `telnet_v6` | 正 | §2/§8：IPv6 独立用例（offset 74） | **13**（JSON `min_packets:12`，未收窄） | 3 fields + 1 frame |
| 15 | `telnet_default_port` | 正 | §8：端口缺省 → 23 | **13**（JSON `min_packets:12`，未收窄） | 5 fields |
| 16 | `telnet_port_dyn` | 正 | §12.12：端口动态 inc × flows=2 | **26** | **`packet_count:26`（精确）** + 4 fields |
| 17 | `telnet_neg_scenario` | 负 | §7 N-3：未知 scenario 白名单拒 | 0 | `expect_error` + 锚词 |

**包数公式**：单流 = **3（握手）+ Σ 事件段数 + 4（挥手）**，其中 `Σ 事件段数 = Σ ceil(payload_i / 1460)` 对 banner/file_source/dialog 的每个数据事件求和，IAC 命令恒计 1 段。

**逐例校验（本车道机读复核，2026-09-29）**：

| # | 推导 | 实测 | ✓ |
|---:|---|---|---|
| 1 | 3 + 6（defaultDialog 6 事件）+ 4 | 13 | ✓ |
| 4 | 3 + 26（11 协商 + 8 登录 + 1 `$` + 2×2 命令 + 2 logout）+ 4 | 33 | ✓ |
| 5 | 3 + 20（11 + 8 + 1 重提示）+ 4 | 27 | ✓ |
| 6 | 3 + 26（11 + 8 + 1 + 2×2 + 2）+ 4 | 33 | ✓ |
| 7 | 3 + 29（11 + 8 + 1 + 1 命令 + **6 大响应段** + 2）+ 4 | 36 | ✓ |
| 8 | 3 + 21（10 协商 + 11 登录面）+ 4 | 28 | ✓ |
| 9 | 3 + 31（11 + 10 + **3 y 输出段** + ip + dm + ^C + exit + logout）+ 4 | 38 | ✓ |
| 10 | 3 + 1（1 data）+ 4 | 8 | ✓ |
| 11 | 3 + 1（1 sb）+ 4 | 8 | ✓ |
| 12 | 3 + 9（ttype_is + naws + 7 单命令）+ 4 | 16 | ✓ |
| 13 | 3 + 1 banner + 1 file + 6 defaultDialog + 4 | 15 | ✓ |
| 14 | 3 + 6 + 4 | 13 | ✓ |
| 15 | 3 + 6 + 4 | 13 | ✓ |
| 16 | 2 流 × 13 | 26 | ✓ |

**包数与实测 pcap 逐例一致**（`tshark -r … | wc -l` 实测，本车道执行）：**11 例精确等值**（33/27/33/36/28/38/8/8/16/15/26）+ **3 例 JSON 为下界**（T-1/T-14/T-15 `min_packets:12`，实测 13，未收窄，G-TELNET-16）。3 负例实测 0 帧。

### 9.1 tshark 字段通道（实测，2026-09-29）

本机 tshark **3.6.14** 有 telnet dissector：`tshark -G fields` 中 `telnet.*` 字段 **58 个**（唯一名，`awk` 实测；`grep telnet` 的 78 行含 `mactelnet` 等噪声，不采）；`tshark -G decodes` 有 `tcp.port 23 telnet`。

| 通道 | 字段 | 进制/形态 | 实测可用性 |
|---|---|---|---|
| ① | `telnet.data` | FT_STRING | **有伪影**：IAC 帧输出空串、trim 尾部空白（`login: `→`login:`）、`\r\n` 显示字面转义（G-TELNET-4） |
| ② | `telnet.cmd` | FT_UINT8 十进制 | **可用且未被用例使用**：多值逗号拼接（`250,240` = SB+SE）；单命令帧单值（`241`/`246`/…） |
| ③ | `telnet.subcmd` | FT_UINT8 十进制 | **可用且未被用例使用**：协商帧的选项码（`3`=SGA、`24`=TTYPE、`31`=NAWS、`39`=NEW-ENVIRON、`34`=LINEMODE）；多值逗号拼接 |
| ④ | `telnet.string_subopt.value` | FT_STRING | **可用且未被用例使用**：TTYPE IS 的终端名（实测 `xterm`/`vt100`） |
| ⑤ | `telnet.naws_subopt.width` / `.height` | FT_UINT16 十进制 | **可用且未被用例使用**：实测 `80`/`24`、`200`/`60` |
| ⑥ | frames `offset/hex` | 原始字节 | 17 例主断言通道（offset 54/74） |

**进制纪律（实测）**：`telnet.cmd`/`telnet.subcmd`/`naws_subopt.*` 用**十进制串**；多值字段是**逗号拼接串**（`"250,240"`），单值断言不可直接 `==`。

> **A′ 立项依据（G-TELNET-12）**：17 例今日**只用 `telnet.data` + frames**，通道 ②–⑤ 零使用。这不是"被迫"（dissector 存在且字段有效），是**未收编**。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | 客户端主动建 TCP 连接（RFC 854 §1） | 场景①–⑫ | `DependsOn ["ip"]` 单值（`registry.go:1841`）；**层内自产完整 TCP 包**（`telnet.go:283-339`） | 无 |
| 2 | 命令/消息表 | IAC 命令族 16 类（RFC 854 §3 表）+ 选项码表（RFC 855 + 后续 RFC） | 场景①–⑫ | 常量表 16 命令（`telnet.go:72-89`）+ 11 选项（`:92-104`）+ `renderTelnetEvent` 19 分支（`:370-488`） | `synch` 类型零用例（G-TELNET-11） |
| 3 | 状态机 | **RFC 1143 四态协商机**（NO/WANTYES/WANTNO/YES + 转移表） | 场景②⑥ | **未实现**——无状态纯映射（`telnet.go:18-21` 逐字声明） | **待实现边界**（G-TELNET-5） |
| 4 | 字段表 | IAC 三字节族 / 两字节族 / SB 框架 / TTYPE 两形 / NAWS 四字节大端 | 数据场景层 | `renderTelnetEvent` 逐类型硬编码（§3.1–§3.4） | NAWS 零值不可表达（G-TELNET-7） |
| 5 | 错误处理 | 3 类负例 + 2 类不可达分支（§7） | 负例 N-1/N-2/N-3 | presence 门（`strategy_convert.go:8961`）+ 静态门（`semantic.go:285`）+ scenario 白名单（`scenario.go:58`） | IP/MSS 4 分支零死锚词（C 类，§7） |
| 6 | 超时与活性 | **Telnet 无协议级保活**（无 PING/心跳；NOP 是"空操作"不是心跳） | — | 无 keepalive 代码 | **显式不适用**（如实声明） |
| 7 | NAT/代理/被动 | 无被动模式概念（客户端直连） | — | 无 `sessions[]`；多流走策略级 `strategy_fc` | **显式不适用**被动模式；NAT 穿透为框架面 |
| 8 | 版本/方言 | RFC 854 唯一 profile；6 场景方言；IPv6 已覆 | 正例 14 | `scenario` 白名单 6 值（`scenario.go:54-55`）；IP 透明（`telnet.go:124-157`）；缺省端口 23（`chain_planner_translate.go:1648`） | 真实服务器方言（TN3270E/AUTH）→ §1 边界⑥ |

**八项重数**：8 行逐行判定 = **已覆 5**（#1 连接模型 / #2 命令表 / #4 字段表 / #5 错误处理 / #8 版本方言）+ **立项 1**（#3 状态机——RFC 1143 未实现，G-TELNET-5）+ **不适用 2**（#6 保活——Telnet 无协议级心跳；#7 被动模式——无此概念）。5 + 1 + 2 = 8 ✓

### 10.2 子表①：事件类型 × 终态矩阵（逐格已覆/立项/不适用）

**19 个事件类型**（`renderTelnetEvent` 的 19 个分支标签，含空串别名 `""`）+ **1 个字段变体行**（`data_b64`，与 `data` 同分支不同字段）= **20 行** × 3 列：

| 事件类型 | T1 正常终态（有断言） | T2 配置拒绝 | T3 RST 异常终态 |
|---|---|---|---|
| `data` | 已覆（#1/#4/#5/#6/#7/#9/#13） | 不适用（数据无配置拒绝面） | A′ 立项（G-TELNET-8） |
| `data_b64`（字段变体，同 `data` 分支） | 已覆（#10） | 同上 | A′ 立项（G-TELNET-8） |
| `will` | 已覆（#1/#4/#8） | 同上 | A′ 立项（G-TELNET-8） |
| `wont` | 已覆（#4/#5） | 同上 | A′ 立项（G-TELNET-8） |
| `do` | 已覆（#1/#4/#8） | 同上 | A′ 立项（G-TELNET-8） |
| `dont` | 已覆（#4/#5/#8） | 同上 | A′ 立项（G-TELNET-8） |
| `sb` | 已覆（#11） | 同上 | A′ 立项（G-TELNET-8） |
| `ttype_send` | 已覆（#4/#8） | 同上 | A′ 立项（G-TELNET-8） |
| `ttype_is` | 已覆（#4/#8/#12） | 同上 | A′ 立项（G-TELNET-8） |
| `naws` | 已覆（#4/#12） | 同上 | A′ 立项（G-TELNET-8） |
| `ip` | 已覆（#9） | 同上 | A′ 立项（G-TELNET-8） |
| `dm` | 已覆（#9） | 同上 | A′ 立项（G-TELNET-8） |
| `nop` | 已覆（#12） | 同上 | A′ 立项（G-TELNET-8） |
| `ayt` | 已覆（#12） | 同上 | A′ 立项（G-TELNET-8） |
| `brk` | 已覆（#12） | 同上 | A′ 立项（G-TELNET-8） |
| `ao` | 已覆（#12） | 同上 | A′ 立项（G-TELNET-8） |
| `ec` | 已覆（#12） | 同上 | A′ 立项（G-TELNET-8） |
| `el` | 已覆（#12） | 同上 | A′ 立项（G-TELNET-8） |
| `ga` | 已覆（#12） | 同上 | A′ 立项（G-TELNET-8） |
| **`synch`** | **A′ 立项（零用例，G-TELNET-11）** | 同上 | A′ 立项（G-TELNET-8） |

**逐格重数**：20 行 × 3 列 = 60 格——已覆 **19**（T1 列 19）/ 立项 **21**（T1 列 1 + T3 列 20）/ 不适用 **20**（T2 列 20），零空格。19 + 21 + 20 = 60 ✓

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

| # | 变体 | 落点 |
|---:|---|---|
| 1 | 空 dialog → 默认剧本 6 事件 | 覆（#1/#14/#15） |
| 2 | 手动 dialog（单事件） | 覆（#10/#11） |
| 3 | 手动 dialog（9 事件多类型） | 覆（#12） |
| 4 | 场景 `login_full` | 覆（#4） |
| 5 | 场景 `login_fail`（失败路径） | 覆（#5） |
| 6 | 场景 `multi_command` + 显式 commands | 覆（#6） |
| 7 | 场景 `long_output`（8196B > MSS） | 覆（#7） |
| 8 | 场景 `option_reject`（DONT/WONT 拒绝） | 覆（#8） |
| 9 | 场景 `synch`（IP+DM 中断） | 覆（#9） |
| 10 | `data` 字段（字符串形态） | 覆（#1/#4–#9/#12/#13） |
| 11 | `data_b64` 字段（二进制形态） | 覆（#10） |
| 12 | `sub_data` 字段（非 b64） | **A′ 立项**（`telnet.go:400` 有分支，JSON 无用例） |
| 13 | `sub_data_b64` 字段 | 覆（#11） |
| 14 | `value` 字段（ttype_is 显式） | **A′ 立项**（`telnet.go:415-416` 有分支；#12 走缺省、#4/#8 走配置） |
| 15 | `cols`/`rows` 字段（naws 显式） | 覆（#4 走配置 200×60；`planner_testpoints_test.go:559` 单测有 132×60） |
| 16 | ttype 缺省 `"xterm"` | 覆（#12） |
| 17 | NAWS 缺省 80×24 | 覆（#12） |
| 18 | `option` 未知码 | **A′ 立项**（无校验，行为=照发，今日无例） |
| 19 | `direction` 缺省（空） | 覆（#12 全 `"up"` 显式；缺省分支由 `planner_test.go:320` 单测覆盖） |
| 20 | `direction` 非法值 | **A′ 立项**（`telnet.go:319-321` 有分支，`planner_test.go:338` 单测覆盖，JSON 无例） |
| 21 | 未知 `Type` | **A′ 立项**（`telnet.go:483-486` 有分支，`planner_test.go:371` 单测覆盖，JSON 无例） |
| 22 | 空 `data`（静默跳过） | **A′ 立项**（`telnet.go:314-317` 有分支，`planner_test.go:352` 单测覆盖，JSON 无例） |
| 23 | `banner` 非空 | 覆（#13） |
| 24 | `banner` 空（跳过） | 覆（全正例除 #13） |
| 25 | `file_source.literal` 形态 | 覆（#13） |
| 26 | `file_source.file` 形态 | **A′ 立项**（`telnet.go:297-304` 走 `PayloadCache.GetOrLoad`，JSON 无例） |
| 27 | IPv6 外层 | 覆（#14） |
| 28 | 缺省端口 23 | 覆（#15） |
| 29 | 显式端口 | 覆（#1 等 15 例） |
| 30 | 端口动态 + flows=2 | 覆（#16） |
| 31 | 静态端口 + flows=2（拒） | 覆（#3 负例） |
| 32 | 顶层 `telnet` presence（拒） | 覆（#2 负例） |
| 33 | 未知 scenario（拒） | 覆（#17 负例） |

**重数**：33 行逐行判定 = **已覆 26**（#1–#11、#13、#15–#17、#19、#23–#25、#27–#33）+ **A′ 立项 7**（#12 `sub_data` 原始形态 / #14 事件级 `value` / #18 未知 `option` 码 / #20 `direction` 非法值 / #21 未知 `Type` / #22 空 `data` / #26 `file_source.file` 形态）。26 + 7 = 33 ✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 交互式登录（RFC 854 §1 用例） | #4 | 已覆 |
| 2 | 认证失败重提示 | #5 | 已覆 |
| 3 | 远程命令执行 + 回显 | #6 | 已覆 |
| 4 | 大文件输出/分页（跨 MSS） | #7 | 已覆 |
| 5 | 选项协商（ECHO/SGA/TTYPE/NAWS） | #4/#8/#12 | 已覆 |
| 6 | 协商拒绝（能力不匹配） | #8 | 已覆 |
| 7 | 中断长输出（Ctrl-C） | #9 | 已覆 |
| 8 | 二进制数据流（BINARY 模式） | #10 | 已覆（转义面） |
| 9 | 子协商（环境变量/终端类型/窗口尺寸） | #11/#12 | 已覆 |
| 10 | 服务器 banner/欢迎语 | #13 | 已覆 |
| 11 | IPv6 产线 | #14 | 已覆 |
| 12 | 多客户端并发（flows） | #16 | 已覆 |
| 13 | 真实协商状态机（Q method 自动应答） | — | **明确不解决**（G-TELNET-5） |
| 14 | STARTTLS / telnet over TLS | — | **明确不解决**（§1 边界④） |
| 15 | TN3270E / AUTH / COMPORT 专用子协商 | — | **明确不解决**（§1 边界⑥） |
| 16 | 真实服务器方言差异（BSD/Linux/Solaris 提示语） | — | **明确不解决**（本层按剧本回放，不模拟真服务器） |

12 覆 + 4 不适用 = 16 ✓ 无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比

三路：① **规范原文**（RFC 854/855 + 选项族 RFC，定"必须是什么"——本轮已用它校正 D-TELNET-1 的"14 键"计数错误与"6/5 段"不准，§0 #2/#4）；② **商业化软件实际行为**（**部分取到**：本车道实测 tshark 3.6.14 对 15 个 pcap 的解码结果——`telnet.cmd`/`telnet.subcmd`/`string_subopt.value`/`naws_subopt.*` 四通道字段与原始字节一致，佐证 IAC 布局正确；**未取到**：真实 telnetd（BSD/Linux）的完整会话字节 → G-TELNET-13 待确认）；③ **可靠开源实现思路**（借鉴"0xFF 双写"与"NAWS 大端"两条——与 RFC 原文一致，无新信息）。

三路一致点：IAC 命令码表、选项码表、SB 框架、NAWS 大端 4 字节、0xFF 转义规则。**不一致点**：① **协商是否有状态**——规范要求四态机（RFC 1143），本实现是无状态回放（§3.5，G-TELNET-5）；② `synch` 的 URG 位——规范要求 DM 带 URG，本实现无（G-TELNET-6）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `telnet` 终层 raw-IP 自驱（本版；h323/mpls/ngap/sip/radius 同构先例） | 完整 TCP 包（含生命周期）自产，字节与 legacy 零漂移；代价 = 一套层（已落码 966 行） | **采用**（D-TELNET-1 A1 裁定） |
| B | `[ip,tcp,telnet]` 事件面 | 19 事件类型 + IAC 转义 + MSS 分段 + TCP 选项须全量重写为 MessageEvent 流 → **破坏字节等价**；且 tcp 层无静态端口抽取通道（`extractLayerSrcDst` 仅 ip，mpls B2 已证死路） | **否决**（D-TELNET-1 B2 否决理由） |
| C | 顶层扁平 `telnet` 子映射 + 独立 planner | 与 CORE_MEMORY §1"层链唯一真相"冲突；已被 `CheckProtoFlat` presence 门判死 | **否决**（#2 负例即该门的执法证据） |

## 11. P2 D-TELNET-1 代码设计（CORE_MEMORY §8 八要素；门1 已获批 = 定稿）

> 状态说明：实现已落码（`internal/protocol/telnet/` 三文件），本 P2 条目为文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/protocol/telnet/telnet.go` | 常量表（IAC/选项/TTYPE）+ `Planner.Validate` + `Planner.Plan` + `defaultDialog` + `renderTelnetEvent` + `escapeIAC` + `segmentByMSS` + `synOptions` | 563 |
| `trafficgen/internal/protocol/telnet/scenario.go` | 6 场景 dialog 合成（`validateScenario` + `buildScenarioDialog` + 6 个 `*Dialog` + `commandResponse`） | 329 |
| `trafficgen/internal/protocol/telnet/layer_gen.go` | 终结层生成器（`Generator` 包装 legacy `Plan`，force `Direction="up"`；`GenEvents` 恒 nil）+ `validateLayer` + `init()` 注册 | 74 |
| `trafficgen/internal/core/types.go`（`:8132-8200` `TelnetConfig` / `:8206-8280` `TelnetEvent` / `:1872` `FlowSpec.Telnet` / `:3679` `LayerDynValues.TELNET`） | 数据结构 | —（共享文件） |
| 接线 10 处 | registry（`layers/registry.go:1841`，12 键）/ translate（`chain_planner_translate.go:1571`）/ 扁平 parse（`strategy_convert.go:1522`）/ presence 门（`strategy_convert.go:8959`）/ protocols 准入（`protocols.go:58`）/ dst 端口豁免（`chain_planner.go:764`）/ src 端口豁免（`:996`）/ `isRawIPChain`（`chain_planner_util.go:54`）/ 静态门扫描面（`schema/semantic.go:214`）/ 端口动态五件（`layer_dyn.go:62/252/846`）/ main（`main.go:196`/`:578`） | — |
| 单测 3 文件 | `planner_test.go` 28 个 `Test*` / `planner_testpoints_test.go` 87 个 / `scenario_test.go` 15 个（共 **130** 个，`grep -c '^func Test'` 实测） | 2494 |
| 层链测试 3 文件 | `layers/telnet_migrate_test.go`（165 行，4 红例）/ `telnet_layer_dyn_test.go`（25 行）/ `schema/telnet_static_port_test.go`（29 行） | 219 |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`telnet.go:124`）：**只读不改 spec**（默认值在 `Plan` 里落，`telnet.go:121-123` 注释）；5 分支（§7 表）；`Telnet==nil` 通过（空配置合法 → 默认剧本）；**不硬校验端口 23**（`:144-146`）。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`telnet.go:160`）：先 `Validate`；起 goroutine 逐帧写 `chan`（容量 256）；`spec` 不被修改。
- `renderTelnetEvent(ev, cfg) ([]byte, bool)`（`telnet.go:370`）：19 分支纯映射；`(nil,false)` = 跳过。
- `escapeIAC(data []byte) []byte`（`:494`）；`segmentByMSS(payload, mss) [][]byte`（`:530`）；`synOptions(mss uint16) []core.TCPOption`（`:553`）。
- 生成器：`Name() "telnet"`（`layer_gen.go:20`）；`GenEvents()` **恒返回 nil**（`:26`，`chain_planner.go` 的事件分支检查据它路由）；`Generate(ctx, req)`（`:32`）relay 并 force `Direction="up"`。

### 11.3 数据结构

`TelnetConfig{Banner string, Dialog []TelnetEvent, TerminalType string, WindowCols/WindowRows uint16, FileSource *filesystem.FileSource, Scenario/Username/Password string, Commands []string}`（`types.go:8132-8200`，**10 键**）。

`TelnetEvent{Type, Direction string, Option uint8, Data, DataB64 string, SubData []byte, SubDataB64, Value string, Cols, Rows uint16}`（`types.go:8206-8280`，**10 键**）。

### 11.4 主流程

**create**：`ValidateStrategy` → `ValidateLayers`（V9，registry **12 键** allowlist）→ `CheckProtoFlat` presence 门（`strategy_convert.go:8959`）→ `checkLayerChainStaticCopy`（`semantic.go:214` 扫描面含 telnet）→ 400 或入库。

**任务**：`mapToFlowSpec` → `parseLayerDyn`（`layer_dyn.go:252` telnet 端口 int 面）→ worker `resolveLayerTuple`（`:846` 逐流端口落 spec）→ `ChainPlanner.ValidateSpec`：`validateSpecBase`（telnet 端口豁免）→ `translate` case `"telnet"`（`chain_planner_translate.go:1571`：`spec.Telnet==nil` 时逐键映射 10 业务键 + dialog/file_source JSON round-trip + 端口双态 + dst 缺席→23）→ `validateLayer`（= legacy `Validate`）→ `Plan`：`isRawIPChain`（`chain_planner_util.go:54`）→ raw-IP 驱动（meta 补齐 → `Generator.Generate` → legacy `Plan` 整包 relay → force up 防双换）→ builder（TCP L4 装配，`synOptions` 既有路径）→ writer（PCAP/NIC）。

### 11.5 错误分支

3 个**可达**拒绝分支全部传 task error（3 负例实测 0 帧，零假成功）：presence 门（create-time 400）、静态门（create-time 400）、scenario 白名单（task-time）。4 个**不可达**分支（IP parse ×2 / MSS ×2）为零死锚词（§7 表）。

### 11.6 性能边界

见 §6（channel 256 流式产出、per-flow 局部状态、无跨流共享、无锁；最大单帧 1514；最大事件载荷 8196）。

### 11.7 与现有逻辑的冲突点

- `CheckProtoFlat`（`strategy_convert.go:8625` 起）**有 telnet 分支**（`:8961-8963`，D-TELNET-1 决策）——与 opcua 的 G-OPCUA-1 不同，**本协议 presence 门已在案**（#2 负例即其执法证据）。
- **顶层未知游离键无通用门**：`{layers:[…], bogus: 1}` 今日**不判死**（`CheckProtoFlat` 只查五键 + 各协议子映射白名单）→ presence 负例若建该形状会**真绿 = 假通过**，**不建**（G-TELNET-14，与 opcua G-OPCUA-1 / moxa G-MOXA-2 同款）。
- 动态 allowlist（`layer_dyn.go:62`）：telnet **端口 2 键开**，业务 10 键全关（对象即 `does not support dynamic`）。见 §12.12。
- registry 12 键 vs D-TELNET-1 条目写"14 键" → **条目计数错误**（G-TELNET-1）。
- `telnet.go` 头注与 `types.go` 注释引用 `design_telnet.md`（**9 处**，`grep` 实测）——该文件**全仓不存在**（`find / -name design_telnet.md` = 0 命中）→ **死引用**（G-TELNET-15，与 opcua 死引用 `audit/25-opcua-adversarial-audit.md` 同款）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 3 文件 + 接线 10 处 + 3 个层链测试文件；不触及其他协议。cases 回滚 = 恢复 17 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：15/17 例顶层 = `{layers}` 唯一键；T-2 = `{layers,telnet}`（**presence 负例形状**，判死执法对象）；T-16 = `{layers,group_id}`（`group_id` 是**框架键**，与 layers 同级允许）。收官自查「非负例顶层键 = 0」**今日成立**（非负例 14 例顶层仅 `layers` + T-16 的框架键 `group_id`） | §12.1；`cases/telnet.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 telnet 流量模板（层链 + 端口/剧本）；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（raw-IP 自驱终层）/时间线 | §12.3 + §5 |
| §4 查规范 | RFC 854/855 + 857/858/1073/1091/856/859/860/1079/1184/1372/1572 + **RFC 1143（要求面，未实现）** + tshark 3.6.14 `telnet.*` 58 字段 + 15 例实测 pcap + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["ip"]` 单值（`registry.go:1841`）；3 可达 + 4 不可达拒绝分支；失败传 task error（3 负例 0 帧实测） | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；channel 256 流式；最大帧 1514；MSS 分段公式；pcap/NIC 两路验收明写） | §6 |
| §7 三份文档 | `115-telnet-{design,testcase}.md` v1.0.0（本版）+ D-TELNET-1（`CODE_DESIGN.md`，已验收）+ T-TELNET-1…17（`TEST_CASES.md`，已验收）+ 17 例 JSON | 修订记录 |
| §8 设计先行 | D-TELNET-1 P2 定稿（2026-09-19）先于 P4/P5 落码；门1 已交 + 对抗自重审 2 轮 | `CODE_DESIGN.md` 状态行 |
| §9 测试三源 | 三源 = RFC 854/855 族（§10）+ D-TELNET-1（§11）+ tshark 3.6.14 字段与 **15 例 pcap 实测**（本车道逐帧复核，§9 表）；17 ID 逐项回指；存量审计去向 testcase §8 | `115-telnet-testcase.md` §2/§5/§8 |
| §10 评审闭环 | D-TELNET-1 每阶段对抗自重审（`CODE_DESIGN.md` 状态行）+ 本车道 P1–P3 自审（testcase §10） | 自审日志 |
| §11 白话 | 本文首节白话一句 | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务 10 键逐个列关 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `telnet` 已在 `registry.go:1841` 注册（**不新增层**）；生成表同代；**若改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `telnet.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/telnet/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/telnet.json` | 17 | `{layers}` ×15 + `{layers,telnet}` ×1（T-2）+ `{layers,group_id}` ×1（T-16） | `[ip,telnet]` ×17 | 3/3 = `{expect_error, error_contains, notes}` |

**旧键去向表（§15.3 要求"每个键写去向"）**——旧形取自 `git show d58bef9~1:…cases/telnet.json`（P5 前的唯一存量例）：

| 旧键 | 旧值 | 去向 |
|---|---|---|
| `src_ip` | `"10.0.0.1"` | → `layers[0].ip.src`（T-1 改写） |
| `dst_ip` | `"20.0.0.1"` | → `layers[0].ip.dst` |
| `src_port` | `12345` | → `layers[1].telnet.src_port`（**端口住 telnet 层**，D-TELNET-1 决策 B1） |
| `dst_port` | `23` | → `layers[1].telnet.dst_port` |
| `count` | `1` | → **删**（数量走 `strategy_fc {"type":"flows"}`；T-16 用 `flows=2`） |
| 顶层 `telnet` 子映射 | `{}`（空 map） | → **删**；业务键迁 `layers[1].telnet.*`。**presence 门对空 map 也判死**（T-2 即该门证据） |

**目标形状**（§2 样例；存量 15/17 例已是此形）。

**结论**：① 旧键已全部退场（P5 `d58bef9` 完成）；② 收官自查行「非负例顶层键 = 0」**今日成立**——非负例 14 例顶层仅 `{layers}`（T-16 额外带框架键 `group_id`，与 layers 同级属允许面）；③ A′ 新增例全部沿用纯 layers 形（§13）。

> **注（2026-09-29 机读）**：全仓 `cases/*.json` 中另有多个协议已是纯 `{layers}` 形（opcua/moxa/... ），本协议**并非唯一**；本协议的**特有事实**是"17 例今日即零旧键残留"。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"telnet":{}}` **今日会被拒**（`CheckProtoFlat` telnet 分支，`:8961-8963` 实测）→ **T-2 已建且真红** ✓（与 opcua 的 G-OPCUA-1 相反——本协议该门在案）。
- ② 白名单外游离键判死（`unknown field`）今日**无通用门** → **不建**（建了会真绿 = 假通过），缺口 G-TELNET-14。
- ③ 3 负例每条带锚词（已齐，§7）。
- ④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

**会话表**：`s1` 单连接基线（#1/#4–#9/#13–#15，各自四元组，握手 → [banner] → [file_source] → dialog 事件序 → 挥手）/ `s2` 多流展开（#16，`strategy_fc flows=2`，**两流各自完整剧本、串行回放**，p1–p13 = 流 1、p14–p26 = 流 2）。

**事务序列**：`t1` 连接建立（握手 3 帧，SYN 带 MSS/WinScale/SACK）/ `t2` 服务器问候（banner，可选）/ `t3` 客户端载荷（file_source，可选，**在 dialog 前**）/ `t4` 事件回放（`dialog[]` 逐事件；`data` 按 MSS 分段，IAC 命令单片）/ `t5` 连接释放（挥手 4 帧）。每事务四件事（前置/触发/成功/失败）见 §5 阶段表 + §4 场景表。

**关联关系**：**无派生流**（诚实声明：Telnet 是单 TCP 连接上的字符流，RFC 854 无子流/副连接概念，无 `driven_by`；`file_source` 是同一连接内的前置载荷段，不是独立流）。

**插入位置**：**raw-IP 自驱终层**（`[ip, telnet]`，无中间层）；层内自产完整以太帧（含 TCP 头与生命周期），不由 tcp 层托管；`isRawIPChain` 见链内含 `tcp`/`udp` 即拒绝该路由（`chain_planner_util.go:48-52`）。

**时间线**：握手严格 3 帧序 → banner/file_source → dialog **严格按数组序** → 挥手 4 帧序；多流为**串行整块回放**（#16 实测 p1–p13 后 p14）；**无交错**（`concurrent` 为例外路径，本协议不启用）；段内 `tcp.len` 逐段 = 1460（末段可短）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组**：`ip.src`/`ip.dst`、`telnet.src_port`/`telnet.dst_port` **五策略全开**——allowlist `layer_dyn.go:62` 实测 `"telnet": {"src_port": true, "dst_port": true}`；`ip`/`eth`/`tcp`/`udp` 为框架级白名单（`layer_dyn.go` 头部）；保底 `DefaultSrcPort+i` = `12345+i`（`strategy_convert.go:49`）；dst 动态与 23 缺省和平共处（显式/动态值非零即不触发补齐）。

**业务字段 10 项全关**（allowlist 无 telnet 业务行，`grep` 实测零命中；对象即 `does not support dynamic`）：

| 业务键 | 关的理由（`layer_dyn.go:58-61` 原文口径） |
|---|---|
| `banner` | 会话身份（服务器问候语，逐流变破坏交互语义） |
| `dialog` | 会话结构（事件序列，列表无动态形状） |
| `scenario` | 结构选择器（6 值白名单，逐流变无意义） |
| `terminal_type` | 终端身份（TTYPE IS 的会话属性） |
| `window_cols` / `window_rows` | 终端身份（NAWS 会话属性） |
| `username` / `password` | 凭据面（逐流变 = 凭据喷洒语义） |
| `commands` | 会话结构（命令列表，列表无动态形状） |
| `file_source` | 载荷来源（对象，非动态形状） |

逐流变体需求列 A′ 候选（testcase §6.2）；今日按 §9.36 口径**不冒充覆盖**。

**序号算法实读**：`parseLayerDyn`（`layer_dyn.go:78`，telnet case 在 `:252`）/ `ResolvePortValue`（`layer_dyn.go:846-856` 逐流解析落 `spec.SrcPort`/`spec.DstPort`）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go:62`）——**telnet 无业务字段块**（grep 实测零命中）。

## 13. P3 对接清单（T-TELNET 草稿输入；正文落 testcase 文件）

17 ID（14 正 + 3 负）+ 包数/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。**A′ 候选 9 例**：

| # | 候选 ID | 覆盖 | 依据 |
|---:|---|---|---|
| 1 | `telnet_synch_event` | `synch` 事件类型（`ff f4 ff f2` 合并形） | G-TELNET-11 |
| 2 | `telnet_sub_data_raw` | `sub_data`（非 b64）形态 | §10.3 #12 |
| 3 | `telnet_ttype_value_explicit` | 事件级 `value` 字段 | §10.3 #14 |
| 4 | `telnet_file_source_file` | `file_source.file` 形态 | §10.3 #26 |
| 5 | `telnet_neg_option_unknown` | 未知 `option` 码照发 | §10.3 #18 |
| 6 | `telnet_direction_invalid` | `direction:"left"` → 归 up | §10.3 #20 |
| 7 | `telnet_unknown_type_skipped` | 未知 `Type` → 不产帧 | §10.3 #21 |
| 8 | `telnet_empty_data_skipped` | 空 `data` → 不产帧 | §10.3 #22 |
| 9 | `telnet_abort_rst` | RST 非正常终止 | G-TELNET-8 |

**另 3 类 B′（框架面，不单独立项）**：顶层游离键通用门（G-TELNET-14）/ 业务字段动态（G-TELNET-12 的业务面）/ 负例 `notes` 键收窄（G-TELNET-10）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-TELNET-1 | `CODE_DESIGN.md` §D-TELNET-1 两处写 registry **"14 键"**（§1 文件清单 + §3 主流程"V9 14 键"），机读实测 **12 键** | **文档修正**（D 条目属主线程/代码轨维护，本车道不碰 `CODE_DESIGN.md`）；12 键为准（§11.1） |
| G-TELNET-2 | `cases/telnet.json` T-7 summary 写 **"8197B 响应"**，实际 `Repeat("A",8192) + "\r\n$ "` = **8196 字节**（off-by-one）；同例 notes 首句"大响应首段 **p22**"与同 notes 末句"P5 校准：大响应首段=**p25**"**自相矛盾**（p25 为实测值）；D-TELNET-1 §6"36-38 长输出+synch（MSS 分段 **6/5** 段）"与实测（两例长输出族各 6 段）不符 | **P4 必做**：改写 T-7 summary 的 8197→8196、删 notes 首句的过时 p22 推算；D 条目段数口径修正归代码轨 |
| G-TELNET-3 | `trafficgen/docs/protocol-pcap-test/telnet.md`（**tracked 产物**）写 "Cases: 17 — pass 17"，17 个包数**本车道已逐例复核全对**；但 `docs/protocol-pcap-test/telnet/` **目录不存在**（0 个 pcap），文档内 **15 处** `(telnet/<id>.pcap)` 链接全断。末次提交 `d58bef9`（2026-09-19）**晚于**判死提交 `0417be5`（2026-09-13），故**不适用** opcua G-OPCUA-10 的"过期产物"口径 | **代码阶段**（P5 重跑套件后落盘 pcap 目录并重生成产物）；本版**不删不改**（tracked 产物）；在此之前读者不得据此判断 pcap 可查。口径差异与 G-OPCUA-10 明确区分：本缺口**不是**"数字未经复跑证实"，而是"**pcap 未留档 + 死链**" |
| G-TELNET-4 | tshark `telnet.data` 三则伪影：IAC 帧输出空串 / trim 尾部空白（`login: `→`login:`）/ `\r\n` 显示字面转义。**是否属工具缺陷待确认** | **待确认**：抓真实 telnetd 会话对照 Wireshark 上游 issue；确认前按"字节面以 frames 为准"钉（testcase §1 断言基线）；不声称 `telnet.data` 可作主断言 |
| G-TELNET-5 | **RFC 1143 选项协商状态机未实现**（四态 NO/WANTYES/WANTNO/YES + 转移表；`telnet.go:18-21` 逐字声明"emits the dialog verbatim"）。规范要求面见 §3.5 | **待实现边界**（C 类，不计入已覆盖统计）；A′ 候选：补状态机实现或明确"永久不解决"（本生成器合同=剧本回放，非真服务器）；用例今日不得声称"协商结果正确" |
| G-TELNET-6 | `synch` 的 DM 段**不带 TCP URG**（RFC 854 §3 要求 DM 段置 URG）；`core.L4Config` 无 `UrgentPointer` 字段（`telnet.go:478-481` 自认） | **待实现边界**（框架字段缺失）；A′ 候选：框架加 `UrgentPointer` 后补 `tcp.urgent_pointer` 断言 |
| G-TELNET-7 | **NAWS 零值不可表达**：`cols/rows` 是 `uint16`，`0` 无法与"未设置"区分 → `{"type":"naws"}` 必落 80×24 兜底，无法发真正的 `0×0`。`planner_testpoints_test.go:524` `TestSB_NAWS_0x0` 用 `t.Logf` 记录而非断言钉死（**弱断言**） | A′ 候选：改用 `*uint16` 或加 `naws_explicit` 标志；今日按实测行为钉，用例不得声称 0×0 可发 |
| G-TELNET-8 | **RST 非正常终止零用例**（框架 tcp 能力，本层零断言） | A′ 补例 `telnet_abort_rst`（CORE_MEMORY §3.15②后半） |
| G-TELNET-9 | **链路径 MSS 配置不可达**：`spec.TCP` 恒 nil（`layer_gen.go:36-45` 不传 TCP 字段）→ MSS 恒 1460，`MinMSS`/`MaxMSS` 两锚词零死锚词 | **待实现边界**（C 类）；A′ 候选：链路径接 MSS 键（须先改 `layer_gen.go` 传 TCP，属代码轨） |
| G-TELNET-10 | 3 负例 `expect` 键集合含 `notes`（`{expect_error, error_contains, notes}`），与严格两键口径不符 | **P4 收窄**：删 3 例的 `notes` 键 |
| G-TELNET-11 | **`synch` 事件类型零用例**：`renderTelnetEvent` 有 `case "synch"`（`telnet.go:477-481`），但 #9 场景用的是**分离的** `ip` + `dm` 两个事件（`scenario.go:301-302`），该合并形分支无任何 JSON 用例走过 | A′ 补例 `telnet_synch_event`（§13 #1） |
| G-TELNET-12 | **tshark 四通道零使用**：`telnet.cmd` / `telnet.subcmd` / `telnet.string_subopt.value` / `telnet.naws_subopt.*` 实测**可用**（§9.1），17 例今日零使用（只用 `telnet.data` + frames）。**不是被迫，是未收编** | A′ 收编：把 IAC 命令码/选项码/TTYPE 值/NAWS 尺寸补成 field 断言（可替代部分 frames 断言，提升可读性） |
| G-TELNET-13 | **真实 telnetd 线字节未取到**：第三源"商业化软件实际行为"仅到 tshark 解码级（15 例 pcap），真实 BSD/Linux telnetd 的完整会话字节未抓包对照；RFC 1143 条款号未逐条核对 | **待确认**：抓真实 telnetd 会话对照，或逐条核 RFC 1143 §2 表格；确认前按实现钉、不声称合规 |
| G-TELNET-14 | **顶层未知游离键无通用门**：`{layers:[…], bogus: 1}` 今日不判死（`CheckProtoFlat` 只查五键 + 各协议子映射白名单）→ presence 负例若建该形状会真绿 = 假通过 | **不建该负例**（等框架级 unknown-key 白名单）；与 opcua G-OPCUA-1 / moxa G-MOXA-2 同款；**禁加单协议黑名单分支** |
| G-TELNET-15 | **死引用**：全仓 **9 处** `.go` 注释引用 `design_telnet.md`（`telnet.go` ×3 / `types.go` ×2 / `scenario.go` ×1 / `scenario_test.go` ×1 / `planner_test.go` ×1 / `strategy_convert.go` ×1，机读实测），该文件**全仓不存在**（`find / -name design_telnet.md` = 0 命中） | **代码轨**（注释清理；本车道不碰 `.go`）；与 opcua 死引用 `audit/25-opcua-adversarial-audit.md` 同款 |
| G-TELNET-16 | **断言强度系统性偏弱**：14 正例中 **13 例用 `min_packets`（下界）**、仅 T-16 用 `packet_count`（精确）。其中 **T-1/T-14/T-15 三例的 `min_packets:12` 低于实测 13**（松弛度 1）——多发包不会红。对照 opcua 全正例 `packet_count` | **P4 收窄**：13 例改 `packet_count`（精确值见 §9 表）；本版按实测钉，不冒充精确 |
| G-TELNET-17 | **T-8 summary 与注释的角色描述与实测相反**：summary（及 `scenario.go:253-258` 注释）写"服务器 WILL NEW-ENVIRON → 客户端 DONT；客户端 WILL LINEMODE → 服务器 DONT"，实测 **p6（src=12345）WILL 39 → p7（src=23）DONT 39**（客户端提议、服务器拒绝）、**p8（src=23）WILL 34 → p9（src=12345）DONT 34**（服务器提议、客户端拒绝）——**两处角色互换**。字节与 pcap 不受影响 | **P4 必做**：按实测改写 T-8 summary；注释修正归代码轨 |

## 15. 修订记录

- v1.0.0（2026-09-29）：批次二文档车道 P1–P3，**as-built 首次成文**（本协议无旧编号设计文档，§0 逐条校正 12 项，含 **1 处旧文计数错误**（registry "14 键" 实为 12）、1 处 pcap 目录缺失、1 处行号漂移；10 项核对**一致**）。存量 17 例机读审计（顶层键分布、断言形状、包数公式 `3+Σ段+4` 逐例校验 14/14 与实测 pcap 一致）；15 个 pcap 逐帧复核（offset 54/74 hex 全对）；tshark 3.6.14 telnet dissector **58 字段**实测 + 四通道（`telnet.cmd`/`telnet.subcmd`/`string_subopt.value`/`naws_subopt.*`）可用性实测（A′ 立项依据 G-TELNET-12）；**RFC 1143 协商状态机**按规范写全（§3.5）并标待实现边界（G-TELNET-5）；§12.1/12.3/12.12 强制展开 + 12-P2；D-TELNET-1 as-built 定稿（§11）；缺口 G-TELNET-1…G-TELNET-17。自审见 `/tmp/pipe/doc-lanes/telnet.md`。

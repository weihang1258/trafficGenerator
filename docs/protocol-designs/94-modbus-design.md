# #94 modbus（Modbus TCP 工业控制协议）设计契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3）
> 日期：2026-09-28
> 车道：文档车道（modbus，#94）
> 旧基线：`docs/protocol-designs/13-modbus-design.md` v2.0.4（205 例 T-001~T-205；协议语义权威，**配置形状已过时**——扁平时代写法，§0 逐条校正）
> 存量用例：`trafficgen/test/protocol_pcap/cases/modbus.json`（213 例；**当前全部不可执行**，§0 表 #5 机读+实测双证）
> 规范基线：① **Modbus.org MB-ASYM-TCP**（MODBUS Application Protocol Specification V1.1b3，下称 **spec**）；② 历史参考 MODICON **PI-MBUS-300 Rev. J**（Modbus Protocol Reference Guide，串行链路帧格式）；③ 本仓库落码（`internal/protocol/modbus/` 七文件 + 接线，§11.1）；④ 本机 **tshark 3.6.14** 实测（`modbus.*`/`mbtcp.*` 字段通道，§2）；⑤ 旧基线设计文档（内部契约，非外部规范）。
> 白话一句：**Modbus 就是"一问一答"——主站发一条请求帧，从站回一条响应帧，帧头 7 字节自己带长度，所以 TCP 只管把字节按顺序送到；引擎里它是一层薄皮，握手分段挥手全交给 TCP 层。**

## 0. 13→94 沿革与旧稿过期声明校正（门1 必答：基线继承关系）

本 #94 与旧稿 `13-modbus-*` 是**同一协议的重做契约**，不是新协议。旧稿保留只读参考（协议语义/字节布局/异常码表全部继承），本契约逐条校正旧稿已过时的**状态声明与配置形状**：

| # | 旧稿说法（13-*，v2.0.4） | HEAD 实测（2026-09-28） | 校正结论 |
|---|---|---|---|
| 1 | "实现位置：planner/builder，规划中" | `trafficgen/internal/protocol/modbus/` **七文件已落码**：`builder.go` 432 行、`layer_gen.go` 186、`layer_gen_test.go` 615、`modbus.go` 1121、`modbus_test.go` 1909、`parser.go` 547、`types.go` 120（`wc -l` 实测）；**142 个 `Test*`**（`grep -c '^func Test'` = 129 + 13 实测） | "规划中"已过时；本契约 §11 为 as-built 逆向定稿 |
| 2 | 层注册未提及 | `registry.go:382` 已注册 `modbus`（`CategoryTerminal`，`DependsOn ["tcp"]`，`FieldContract {"tcp.dst_port":"502"}`，**Fields 仅 5 键**）；生成表 `layers.generated.json` 的 `modbus` 条目 `fields` 同 5 键（机读实测） | 已注册；但 Fields **缺 `transactions`**（G-MODBUS-1） |
| 3 | `MODBUSConfig` 定义"规划中" | `types.go:9471` 已定义 `MODBUSConfig`（6 字段）+ `:9499` `MODBUSOperation`（16 字段）；`FlowSpec.MODBUS` 槽位 `:1866` 已存在 | 已落码 |
| 4 | `modbus` 解析接线"规划中" | `strategy_convert.go:1579` 已有 `case "modbus"`（`parseMODBUSConfig` 搬运，`:7813`）；`chain_planner.go:938` 源端口 0 保持、`:1188` 目的端口默认 502；`chain_planner_translate.go:89` Meta 直传 `MODBUS: spec.MODBUS` | **Meta 直传已通**；缺的是**层内化**（G-MODBUS-2） |
| 5 | 旧稿 §7 用例"205 条"、§5 样例全为顶层扁平键 | 存量 `cases/modbus.json` **213 例**：顶层键分布 = `{layers, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, modbus}` ×130 + 同形带 `count` ×2 + **纯扁平（无 layers）** ×81；132 例的 `layers` 恒为 **空壳** `[{"tcp":{}},{"modbus":{}}]`（机读唯一值） | 旧样例形 = **过渡态违规形**（§1.4 混用）；**今日 MCP 实测三种形状全被拒**（§0.1） |
| 6 | 旧稿 §6 包数公式（无握手挥手时 N×2） | HEAD `layer_gen_test.go:269-290` 断言链上 `[ip→tcp→modbus]` 3 事务 = **13 包**（3 握手 + 6 数据 + 4 包挥手）；存量 JSON 正例 `packet_count` 众数 **9**（113 例）= 3 + 2 + 4（单事务 req+resp） | 链上公式 = **3 + 2N + 4**（N=事务数）；旧稿"仅 PDU 序列"口径作废。**挥手包数**：legacy `modbus.go:575-593` 已是 **4 包**（FIN\|ACK up → ACK down → FIN\|ACK down → ACK up），与链上 tcp 层一致——`layer_gen_test.go:272` 注释称"legacy 是 3 包挥手"系**过时注释**（同协议 `modbus.go:398` 自述"TCP 四次挥手"；`layer_gen_test.go` 全文无此字样），以代码为准 |
| 7 | 旧稿称多 master/多流"支持"（S11/S12，T-161~T-180） | 链上**显式拒绝**：`layer_gen.go:88-91` 生成器 + `layer_gen.go:158-166` validator 双拒 `master_count>1`/`flow_count>1`（enip/dnp3 同款纪律——链一次一个 flow） | 链形状下**多流不适用**；语义改由策略级 `flow_control flows=N` 承载（§5） |
| 8 | 旧稿未提 `CheckProtoFlat` | `strategy_convert.go:8625` `CheckProtoFlat` **无 modbus 分支**（`grep -c 'protocol == "modbus"'` = **0** 实测） | 顶层 `modbus` 子映射 presence **今日不判死**（G-MODBUS-3，moxa G-MOXA-2 同形） |

**依赖链判定纪律**：以上均为可判题（旧文→代码→用例三级对照），直接判定，不问偏好。不可判的（Modbus Security over TLS 802 是否入范围）标"明确不解决"并写清理由（§8）。

### 0.1 存量用例可执行性实测（2026-09-28，live MCP）

**结论：213 例今日无一可执行**——三种形状全被拒，逐字实测：

| 形状 | 例数 | MCP `flowb_generate_traffic` 实测返回 |
|---|---:|---|
| 纯扁平（无 `layers`） | 81 | `protocol modbus no longer accepts flat config field src_ip (use a layers chain: ip.src/ip.dst for addresses, tcp/udp src_port/dst_port for ports, flow_control for the flow count)` |
| 存量"层链"形（空壳 layers + 顶层扁平键） | 132 | 同上文案 **+** `config mixes layers with flat four-tuple field src_ip (use ip.src/ip.dst for addresses, tcp/udp src_port/dst_port for ports)` |
| 严格层链（配置搬进 `layers[modbus]`） | — | `layers: layer "modbus": unknown field "transactions"` |
| 空层探针（`layers:[{ip},{tcp},{modbus:{}}]`） | — | 任务 `status=failed`：`validation failed: modbus: MODBUS config is required` |

**根因 = 三个 Go 缺口**（本车道禁改代码 → 只能立项）：

| 缺口 | 内容 | 证据 |
|---|---|---|
| **G-MODBUS-1** | registry `modbus` Fields **缺 `transactions`**（业务键全缺，故层内配置无处可住） | `registry.go:385-391` 仅 5 键（unit_id/suppress_broadcast/master_count/flow_count/shared_tid_space）；`MODBUSConfig`（`types.go:9471`）含 `Transactions []MODBUSOperation` + 16 个 per-op 键 |
| **G-MODBUS-2** | `translateTerminalConfig` **无 `case "modbus"`** → 层 config 永不进 `spec.MODBUS` | `chain_planner_translate.go:855` switch 全文 73 个 case，`grep modbus` = **0 命中**（对照 moxa `:3304` 有分支） |
| **G-MODBUS-3** | `CheckProtoFlat` **无 modbus 分支** → 顶层 `modbus` 子映射 presence 今日不判死 | `strategy_convert.go:8625` 起逐协议 if 链无 modbus；§0.1 探针实测 `layers+modbus:{}` → `completed/100%` |

**机制补充（防误判"空壳即无需 translate"）**：`chain_planner_translate.go:852` 有前置守卫 `if len(s.Fields) == 0 { return }`——**modbus 有 5 个 Fields，守卫不触发**，控制流**进入** `switch term.Name`（`:855`）但因**无 `case "modbus"`** 而落空 → `spec.MODBUS` 保持 nil。故"层内配置不被解码"的**准确原因是缺 case，不是缺 Fields**（Fields 缺 `transactions` 是**第二道**拦截：即便补了 case，`transactions` 仍会被 `ValidateLayerConfig` 报 `unknown field`）。两道缺口须**同时**补齐。

**因 §1.9 纪律，本契约全部层链样例标注为「目标形状，今天跑不通，需先补代码」**；存量 213 例的改写去向见 testcase §8（**缺口登记表**，本车道不改 JSON）。

**顶层键残留总量（机读实测，非负例口径）= 1059 处**——构成：`src_ip` 151 + `dst_ip` 151 + `src_mac` 151 + `dst_mac` 151 + `src_port` 151 + `dst_port` 151 + `modbus` 151 + `count` 2 = 1059。**口径：非负例口径**（151 正例；62 负例不计——负例不产 PCAP，合规判据只看正例，与 ldp/rip/pcep/a2a/nvgre 车道一致）。全例口径（含 62 负例）为 **1493** 处。合规化的清理量按**非负例口径 1059** 计。

（**口径说明**：本表按**非负例口径**计，含 MAC 两键——`checkLayerFlatConflict`（`semantic.go:183-189`）明确把 `src_mac`/`dst_mac` 列为混用键，§1.11 白名单要求 MAC 真相住 `eth` 层。与主线程静态扫描基线 **1059 一致**；全例口径 1493（多出 62 负例 × 7 键 = 434）。两口径非矛盾，本契约统一采用**非负例口径 1059**。）

**presence 负例（G-MODBUS-3）不建，登记为待办**：§0.1 探针实测 `{"layers":[…],"modbus":{}}` → 任务 `completed/100%`（**未被拒**）。**建该负例 = 真绿假通过**（CORE_MEMORY §1.9；moxa §12-P2 同款先例）。登记为"**待 `CheckProtoFlat` 补 modbus 分支后方可建立**"的缺口；**禁止**以"给 modbus 单加黑名单分支"的方式闭合（kingbase 裁定：等框架级 unknown-key 白名单）。

**本车道交付边界（主线程裁定 2026-09-28）**：`cases/modbus.json` **保持原样、不提交**——合规层链形须先补 G-MODBUS-1/2（代码阶段，按"文档先行"顺序未到）；本车道只交两份文档 + 缺口登记。

**显式结论（文档阶段预期状态，非缺陷）**：**存量 213 例在当前 HEAD 上无一具备可执行断言**——三类形状（纯扁平 81 / 空壳层链 132 / 严格层链）经 live MCP 逐条探针全部被拒（§0.1 逐字错误锚词）。原因指向 **G-MODBUS-1（registry Fields 缺 `transactions`）+ G-MODBUS-2（translate 无 `case "modbus"`）**，二者属**代码阶段**；按用户"文档先行"口径，本阶段交付物即文档 + 缺口登记，故此为**预期状态**。本契约全部层链样例已按 §1.9 逐处标注「目标形状，今天跑不通，需先补代码」；可执行断言待代码阶段闭合 G-MODBUS-1/2 后按 testcase §8 逐条落地并全量复跑。

## 1. 范围、profile 与实现状态边界

本版定义主站（client/master，上位机/PLC/SCADA）与从站（server/slave，PLC/RTU 网关）之间的 **TCP 承载 Modbus TCP 报文序列**：TCP 三次握手完成后直接发第一个请求 PDU；每个事务 = 一个请求帧 + 一个（可选）响应帧，帧定界由 MBAP 头的 Length 字段承担；事务之间**无会话状态依赖**（唯一状态是 TCP 连接本身，spec §4.1；旧稿 §4.1）。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `modbus_tcp_v1`（主） | TCP 明文，IPv4 | 19 个功能码全形态（读/写/诊断/文件/FIFO/MEI）+ 10 个异常码 + 广播语义 + 多事务序列 + TID 回绕 | 真实从站处理时延、响应到达时刻、slave 内部寄存器状态 |
| `modbus_tcp_ipv6_v1` | 同上，仅外层 IPv6 | 同主 profile | 从 IPv4 fixture 推导 IPv6 地址 |

显式边界（"不实现、不声称、不许静默转换"）：

- **Modbus Security over TLS（端口 802）不在本版**（旧稿 §1.2 同结论）；UDP 承载（Modbus UDP）不在本版（spec 定义 TCP 承载为 MBAP；UDP 为厂商方言，无规范字节依据）。
- **多 master / 多流展开（`master_count>1` / `flow_count>1`）在链形状下不支持**——生成器 + validator 双拒（`layer_gen.go:81-86`/`:158-168`）；语义改由策略级 `flow_control {"flows": N}` 承载（§5）。
- 不声称任何事务与真实从站响应时序一致（生成器只保证帧序列与字节内容）。

**实现状态（2026-09-28 实测）**：`modbus` 层已注册（`registry.go:382`）、生成器已落码（`internal/protocol/modbus/` 七文件 4930 行）、`allowedProtocols["modbus"]=true`（`protocols.go:48`）、`migrationAllowlist["modbus"]=true`（`convert_proxy.go:61`）、Meta 直传已接（`chain_planner_translate.go:89`）。**但层链路径不通**：Fields 缺 `transactions`（G-MODBUS-1）+ translate 无分支（G-MODBUS-2），见 §0.1。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport/srcport`、`tcp.flags`、`modbus.*`/`mbtcp.*`、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, modbus]`（引擎自动补 `eth`；最小链 `[tcp, modbus]`）。modbus 报文是 TCP payload 的**完整 MBAP 帧**（7 字节头 + PDU）——**帧边界不是段边界**：一条 MBAP 帧可跨多段（>MSS，罕见——最大帧 260B < MSS 1460），多帧可合并进一段（TCP 层按 MSS 聚合，本仓库事件路径为**一帧一段**）。

端口：IANA 分配 **TCP 502**（spec 缺省；`FieldContract {"tcp.dst_port":"502"}`，`registry.go:384`；`chain_planner.go:1188` 缺省补齐）。fixture 统一 `dst_port=502`；用例一律显式写端口并纳入断言。非缺省端口（如 1502，存量有 1 例）同样合法——端口不参与协议语义。

固定偏移：无 VLAN/IP options/TCP options 时，**每帧首字节起点为 IPv4 offset 54（14+20+20）、IPv6 offset 74**（14+40+20）。存量 213 例全部断言 `offset 54`（**110 例有 frames 断言、共 169 条**，机读唯一偏移值 54）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**目标形状声明**：registry `modbus` Fields 今日缺 `transactions`，此形**今天跑不通，需先补代码** G-MODBUS-1+G-MODBUS-2，§1.9 口径）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 502}},
    {"modbus": {
      "unit_id": 1,
      "transactions": [{"function_code": 3, "starting_address": 0, "quantity": 1}]
    }}
  ]
}
```

多流样例（数量只走 `flow_control`；层内四元组留空走 worker 保底递增 §12.12）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"dst_port": 502}},
    {"modbus": {
      "unit_id": 1,
      "transactions": [{"function_code": 3, "starting_address": 0, "quantity": 1}]
    }}
  ],
  "flow_control": {"flows": 3}
}
```

## 3. 线格式编码（逐项标注出处）

### 3.1 MBAP 头（Modbus Application Protocol Header，7 字节）

| 偏移 | 长度 | 字段 | 值域/取值 | 端序 | 出处 |
|---:|---:|---|---|---|---|
| 0 | 2 | Transaction ID | 0-65535，master 分配，slave 原样回传 | big-endian | spec §4.1；旧稿 §3.1 |
| 2 | 2 | Protocol ID | **恒 0x0000** | big-endian | spec §4.1 |
| 4 | 2 | Length | **后续字节数 = 1(Unit ID) + PDU 长度**；最小 2，最大 254 | big-endian | spec §4.1；旧稿 §2.6 |
| 6 | 1 | Unit ID | 0-247（248-255 保留），**0 = 广播** | — | spec §4.1；旧稿 §2.1 |

**总长度公式**：`帧长 = 7 + PDU 长`；`MBAP Length = 1 + PDU 长`。PDU 最大 253 → Length 最大 254 → 帧最大 **260 字节**（单条 TCP 段可承载，MSS 1460）。

### 3.2 PDU 通用格式

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 1 | Function Code | 0x01-0x7F 正常；**0x80+ 为异常响应**（`原 FC \| 0x80`） |
| 1 | 变长 | Data | FC 特定（§3.3 逐 FC 表） |

### 3.3 各 Function Code 的 PDU 格式（19 个支持集 FC，逐 FC 请求/响应字段序）

支持集（`Validate` 合法集）：`{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0F, 0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x18, 0x2B}`，共 **19 个**。0x09/0x0A/0x0D/0x0E/0x12/0x13/0x19-0x2A 等保留码不在支持集。

| FC | 名称 | 请求 PDU（offset:字段:大小） | 响应 PDU |
|---|---|---|---|
| 0x01/0x02 | Read Coils / Discrete Inputs | 0:FC:1, 1:StartingAddress:2, 3:Quantity:2 | 0:FC:1, 1:ByteCount:1, 2:位数据:⌈qty/8⌉ |
| 0x03/0x04 | Read Holding / Input Registers | 0:FC:1, 1:StartingAddress:2, 3:Quantity:2 | 0:FC:1, 1:ByteCount:1, 2:寄存器值:qty×2 |
| 0x05 | Write Single Coil | 0:FC:1, 1:OutputAddress:2, 3:OutputValue:2 | echo（同请求） |
| 0x06 | Write Single Register | 0:FC:1, 1:RegisterAddress:2, 3:RegisterValue:2 | echo |
| 0x07 | Read Exception Status | 0:FC:1 | 0:FC:1, 1:ExceptionStatus:1 |
| 0x08 | Diagnostic | 0:FC:1, 1:SubFunction:2, 3:DataField:N | 子功能特定（0x0000 = echo） |
| 0x0B | Get Comm Event Counter | 0:FC:1 | 0:FC:1, 1:Status:2, 3:EventCount:2 |
| 0x0C | Get Comm Event Log | 0:FC:1 | 0:FC:1, 1:ByteCount:1, 2:Status:2, 4:EventCount:2, 6:MessageCount:2, 8:Events:N |
| 0x0F | Write Multiple Coils | 0:FC:1, 1:StartingAddress:2, 3:Quantity:2, 5:ByteCount:1, 6:OutputsValue:⌈qty/8⌉ | 0:FC:1, 1:StartingAddress:2, 3:Quantity:2 |
| 0x10 | Write Multiple Registers | 0:FC:1, 1:StartingAddress:2, 3:Quantity:2, 5:ByteCount:1, 6:RegistersValue:qty×2 | 0:FC:1, 1:StartingAddress:2, 3:Quantity:2 |
| 0x11 | Report Server ID | 0:FC:1 | 0:FC:1, 1:SlaveID:1, 2:RunIndicator:1, 3:Additional:N（**无 Byte Count 字段**） |
| 0x14 | Read File Records | 0:FC:1, 1:ByteCount:1, 2:items:7×M | 0:FC:1, 1:ByteCount:1, 2:items（每 item = FileResponseLength(1)=1+2×RL + RefType(1)=**0x06** + RecordData:2×RL） |
| 0x15 | Write File Records | 0:FC:1, 1:ByteCount:1, 2:items:Σ(7+2×RL)（每 item 首字节 = **Reference Type = 0x06**，item 内**无** Byte Count） | echo（含完整 Record Data） |
| 0x16 | Mask Write Register | 0:FC:1, 1:ReferenceAddress:2, 3:ANDMask:2, 5:ORMask:2 | echo |
| 0x17 | Read/Write Multiple Registers | 0:FC:1, 1:ReadAddr:2, 3:ReadQty:2, 5:WriteAddr:2, 7:WriteQty:2, 9:WriteBC:1, 10:WriteValues:WriteQty×2 | 0:FC:1, 1:ByteCount:1, 2:ReadValues:ReadQty×2 |
| 0x18 | Read FIFO Queue | 0:FC:1, 1:FIFOPointerAddress:2 | 0:FC:1, 1:ByteCount:**2**（与其余 FC 的 1 字节不同）, 3:FIFOCount:2, 5:Values:N×2 |
| 0x2B | Encapsulated Interface Transport（MEI） | 0:FC:1, 1:MEIType:1, 2:MEISpecificData:N | 0:FC:1, 1:MEIType:1, 2:ReadDeviceIDCode:1, 3:ConformityLevel:1, 4:MoreFollows:1, 5:NextObjectID:1, 6:NumberOfObjects:1, 7:Objects:Σ(2+ObjLen) |
| 0x80+ | Exception Response | 同对应 FC 请求 | 0:`FC\|0x80`:1, 1:ExceptionCode:1（**恒 2 字节 PDU**；MBAP Length = 3） |

出处：spec §6.1-§6.21 逐节；旧稿 §3.3.1-§3.3.17 已逐字节核算（R3/R4 复审修正 FC 0x14/0x15/0x18/0x11/0x2B 五处）。

**MEI Type 取值**（spec 表 42）：0x0D = CANopen（CiA 309）**不实现**；**0x0E = Read Device Identification**（请求与响应**同用** 0x0E）为本版唯一实现值。

### 3.4 位打包规则（FC 0x01/0x02/0x0F，spec §6.1）

- **字节传输顺序**：低地址字节先（low-address-first）。
- **字节内位序**：bit0（LSB）= `starting_address+0`，向字节高位递增。
- **末字节补零**：quantity 非 8 倍数时，末字节高位补 0（N = Quantity mod 8）。
- 例：quantity=10 → 第 1 字节承载 bit0-7，第 2 字节承载 bit8-9（bit10-15 补 0）。

注：本规范**避免用 little-endian/big-endian 描述位布局**，统一"低地址字节先 + 字节内 LSB 优先"，与寄存器值的 big-endian 明确区分。

### 3.5 数量上限汇总（spec §6 各 FC）

| FC | 字段 | 最小 | 最大 | 依据 |
|---|---|---|---|---|
| 0x01/0x02 | Quantity of Coils/Inputs | 1 | 2000 | spec §6.1/§6.2（0x07D0） |
| 0x03/0x04 | Quantity of Registers | 1 | 125 | spec §6.3/§6.4（0x7D） |
| 0x0F | Quantity of Outputs | 1 | 1968 | spec §6.11（0x7B0） |
| 0x10 | Quantity of Registers | 1 | 123 | spec §6.12（0x7B） |
| 0x17 | Read Quantity | 1 | 125 | spec §6.17 |
| 0x17 | Write Quantity | 1 | 121 | spec §6.17（写值 2×121 = 242B） |
| 0x18 | FIFO Count（响应） | 0 | 31 | spec §6.18（超出回异常码 0x04；值字节数必须 = 2×FIFO Count，自洽校验） |
| 0x0B/0x0C | Event Count / Message Count | 0 | 65535 | spec §6.5/§6.6（uint16 全域） |
| 0x08 | SubFunction | 0x0000 | 0x0015 | spec §6.8（0x0005-0x0009 reserved） |

### 3.6 异常码表（spec §7，10 个合法码）

| 码 | 名称 | 码 | 名称 |
|---|---|---|---|
| 0x01 | Illegal Function | 0x06 | Slave Device Busy |
| 0x02 | Illegal Data Address | 0x07 | Negative Acknowledge |
| 0x03 | Illegal Data Value | 0x08 | Memory Parity Error |
| 0x04 | Slave Device Failure | 0x0A | Gateway Path Unavailable |
| 0x05 | Acknowledge | 0x0B | Gateway Target Device Failed to Respond |

合法集（`Validate` 接受）：`{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x0A,0x0B}`。**0x00 = "未设置异常"（正常响应语义），不报错**；0x09、0x0C-0xFF 一律拒绝（0x09 在规范中 reserved）。

### 3.7 tcp 层联动语义

| tcp 字段 | 本协议语义 |
|---|---|
| `handshake` | **恒 true**：`layer_gen.go:181-183` 无条件写 `spec.TCP.Handshake = true`（legacy modbus 恒产握手，链上不可关；显式 false 被忽略） |
| `termination` | **恒 true**：同上（`spec.TCP.Termination = true`） |
| `mss` | 分段粒度：MBAP 帧最大 260B < MSS 1460，单帧单段；显式小 MSS 可强制分段（§8 边界） |
| `src_port` 缺席 + `flows>1` | worker 保底 `12345+i`（`worker.go:307-309`；`DefaultSrcPort=12345` 常量在 `strategy_convert.go:49`） |

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置是剧本（`transactions[]` 逐事务声明 FC 与参数），引擎按序产出事件，响应帧由 planner 自动构造（或 `response_values` 覆盖、或 `exception_code` 替换、或 `response_mode:no_response` 抑制）。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 轮询采集（SCADA 读寄存器） | 主站发 FC 0x03 请求 → 从站回寄存器值 | `modbus-fc03-read-holding`、`modbus-fc03-qty125-max` |
| ② 位状态读取（开关量） | FC 0x01/0x02 请求 → 位打包响应 | `modbus-fc01-read-coils`、`modbus-fc01-bit-order-lsb` |
| ③ 控制写入（开阀/置位） | FC 0x05/0x06/0x0F/0x10 请求 → echo/地址数量响应 | `modbus-fc05-write-coil`、`modbus-fc10-write-multi-registers` |
| ④ 诊断与自检 | FC 0x08 子功能（Return Query Data 等） | `modbus-fc08-diagnostic`、`modbus-fc08-sub-0000` |
| ⑤ 设备标识发现 | FC 0x2B MEI 0x0E（Read Device Identification） | `modbus-fc2b-mei-read-device-id`、`modbus-fc2b-conformity-01-basic` |
| ⑥ 文件记录读写（批量配方） | FC 0x14/0x15（Reference Type 0x06） | `modbus-fc14-read-file`、`modbus-fc15-write-file` |
| ⑦ FIFO 队列读取 | FC 0x18（FIFO Count 自洽） | `modbus-fc18-read-fifo`、`modbus-fc18-fifo31-max` |
| ⑧ 广播写入（多从站同时动作） | Unit ID=0 + 纯写 FC → 镜像响应（可抑制） | `modbus-broadcast-unit0-mirror`、`modbus-broadcast-unit0-suppress` |
| ⑨ 异常回执（slave 报错） | `exception_code != 0` → `FC\|0x80 + code` | `modbus-exception-fc03-02`、`modbus-exception-fc05-03-fc10-04` |
| ⑩ 多事务批量序列 | 单连接 N 事务，TID 递增 | `modbus-tid-sequence-3tx`、`modbus-wire-multi-tx-session` |

**五层覆盖逐层结论**：

- **功能层**——19 个 FC 每类正例（含 0x14/0x15/0x16/0x17/0x18/0x2B 六个冷门 FC）+ 10 个异常码 + 广播语义 + 豁免路径（FC 0x99）；错误处理每类至少一条负例（§7 表 20 行）。
- **性能层**——PDU 上界（FC 0x03 qty=125 → 帧 259B）、FC 0x10 qty=123（帧 259B）、FC 0x0F qty=1968（帧 253B）、TID 回绕（65536 事务）、多事务序列（3 事务 13 包）；MSS 分段（显式小 MSS）。
- **数据场景层**——每字段值域全扫（§3 表逐字段）：地址 0/0xFFFF、数量 0/1/最大/最大+1、Unit ID 0/1/127/128/247/248/255、异常码 0/全 10 码/0x09/0xFF、FC 0x05 写值 0/1/0xFF00/0x0000/非法、FC 0x08 子功能 0x0000/0x000A/0x000F/0x0013/0x0015/0x0016/保留、FC 0x2B MEI/Conformity 全枚举、FC 0x14/0x15 RefType、FC 0x18 FIFO Count 0/2/31/32。
- **地址与流层**——IPv4 全覆（213 例）；**IPv6 零覆盖**（机读地址恒 `10.0.0.1→20.0.0.1`，A′ 立项 `modbus_ipv6`；引擎已支持，MCP 实测 IPv6 链 `completed/9 包`）；单流基线；**流关联显式不适用**（无控制流派生数据流的协议语义，§5）；**多流（会话内并发流）显式不适用**（链形状拒绝，§5；语义走策略级 `flow_control`）。
- **业务层**——⑩ 多事务批量序列（3 事务，TID 递增）+ ⑧ 广播 + ⑨ 异常回执三条复合场景；SCADA 轮询链（读→写→读交替，`modbus-tx-order-sequential`）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：

1. **响应超时 / 重传**——spec 定义 client 侧超时重试，但生成器是"声明式回放"（不发真实网络、无真实从站），超时语义**无对应 wire 事件**；旧稿 §4.1 的 `RxTimeout` 状态**不实现**（`response_mode` 只表达"不发响应"，不表达超时）。
2. **TCP 层 RST 异常中断**——框架 tcp 层能力，本层零断言。
3. **slave 侧寄存器状态**——生成器只产帧，不维护寄存器模型（响应值由 `response_values` 或自动构造的全零决定）。
4. **Modbus Security over TLS（802）**——明确不解决（§8）。

## 5. 消息/事务模型与状态机

**事务定义**：同一 TCP 连接内一次完整的请求/响应交互（spec §4.1；旧稿 §4.1）。**多事务** = 一连接内 N 笔事务按序执行，TID 单调递增（`TID = (N-1) mod 65536`，第 1 个事务 TID=0，第 65537 个回绕至 0）。

modbus 层**无自有状态**（旧稿 §4.1 继承）：握手/seq-ack/挥手/分段全在 tcp 层；modbus 层是"按 `transactions[]` 顺序把事务翻译成帧事件"的纯函数驱动。

| 状态（tcp 层拥有） | modbus 层动作 | 用例 |
|---|---|---|
| `ESTABLISHED`（数据阶段） | 每事务：emit `(up, reqFrame)`；`shouldGenerateResponse` 为真时 emit `(down, respFrame)`（端口对换） | 全正例 |
| 终止（FIN 四包 / RST） | 事件流关闭 → tcp 层挥手；RST 为框架能力 | 全正例 FIN；RST 不适用（§4） |

**TID 策略**（`layer_gen.go:92-105`）：`shared_tid_space=true` → 全局原子计数器（`nextGlobalTID`）；`false`（默认）→ 流内独立 `localTID` 从 0 递增。**每事务只取一次，req/resp 共享**（spec §4.2 事务匹配语义）。

**响应抑制规则**（`shouldGenerateResponse`，`modbus.go:600`）：
1. `response_mode == "no_response"` → 抑制；
2. 广播（`unit_id == 0`）+ `suppress_broadcast == true` → 抑制（**含异常响应**，spec §4.4 细则 3）；
3. FC 0x08 子功能 0x0004（Force Listen Only）→ 抑制；
4. 其余 → 生成响应。

**广播语义三条细则**（spec §4.4；旧稿 §4.4）：
1. **广播 + 读功能码 → `Validate` 拒绝**：仅纯写 FC（0x05/0x06/0x0F/0x10/0x15/0x16）可广播；广播 + 读 FC（含 0x17 读写混合）拒绝，锚词 `broadcast`。
2. **默认仍发镜像响应包**（traffic-mirror 用途），`suppress_broadcast=true` 时省略。
3. `suppress_broadcast=true` 作用域**含异常响应**。

**自动派生规则**：
1. `transactions` 缺键（nil）→ planner 注入 **1 个默认事务**（FC=0x03, addr=0, qty=1，`modbus.go:120`；生成器 `layer_gen.go:78` 同款）；
2. `transactions` 显式空数组 `[]` → **仅 TCP 握手 + 挥手**（连接探测场景）；
3. TCP 握手/FIN 由 tcp 层自动补；
4. 响应 PDU 按 FC 自动构造（§4.5 规则表；`response_values` 覆盖 FC 之后的字节）。

**多会话展开**：`master_count>1` / `flow_count>1` 由 validator + 生成器**双拒绝**（`layer_gen.go:158-166` / `:88-91`，enip/dnp3 同款）；多流语义由策略级 `flow_control {"flows": N}` 表达（worker 递增 `src_port`）。**流关联（控制流派生数据流）显式不适用**——Modbus 无副连接概念（旧稿 §1.2 同结论）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流单事务 = 9 包（3 握手 + req + resp + 4 挥手）；单流 3 事务 = 13 包；MBAP 帧最大 260B（PDU 253）；单流最大帧 259B（FC 0x03 qty=125 / FC 0x10 qty=123）。多流由 `flow_control flows=N` 承载（N 流 × 9 包）。吞吐数字待代码补齐后基准，**本版不写承诺**（§6.5）。
- **依据**：事务序列流式展开（`Generate` 逐事务 emit，无全量收集）；每事务内存 = 帧长 + TCP 段开销（O(帧)）；无跨流共享状态；`shared_tid_space=true` 时用原子计数器（单点同步，无锁竞争面）。
- **验收两路**：pcap（`/tmp/mcp-pcaps/modbus/`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `modbus.*`/`mbtcp.*` 字段值与帧 hex，不只断言"任务没报错"。
- **六类场景落点**：基线（单事务 9 包）/ 目标规模（3 事务 13 包）/ 压力上限（qty=125 → 259B 帧；qty=1968 → 253B PDU）/ 长时间运行（TID 回绕 65536 事务）/ 并发交错（多流 `flow_control flows=N`，跨流不假设全局包序，只断言聚合）/ 背压（`packet_count` 精确计数守卫帧数漂移）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 validator/planner 拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。锚词取自 `modbus.go` 实测字面值（`grep 'fmt.Errorf("modbus:'`）：

| # | 负例类 | 故障输入 | `error_contains` 锚词（`modbus.go` 逐字实测） |
|---:|---|---|---|
| E-1 | 配置缺失 | `spec.MODBUS == nil` | `modbus: MODBUS config is required` |
| E-2 | 多主站越界 | `master_count < 0` 或 `> 1000` | `modbus: master_count must be 1-1000` |
| E-3 | 多流越界 | `flow_count < 0` 或 `> 100` | `modbus: flow_count must be 1-100` |
| E-4 | Unit ID 保留 | `unit_id > 247` | `modbus: unit_id %d is reserved (0-247)` |
| E-5 | 不支持 FC | FC ∉ 支持集且 `exception_code == 0`（且 bit7 未置） | `unsupported function code 0x` |
| E-6 | FC 高位 | FC bit7 置位且无异常码背书 | `function code high bit must not be set` |
| E-7 | 异常码非法 | `exception_code ∉ {0, 10 个合法码}` | `invalid exception code 0x` |
| E-8a | 读位数量越界 | FC 0x01/0x02 quantity ∉ [1,2000] | `quantity must be 1-2000` |
| E-8b | 读寄存器数量越界 | FC 0x03/0x04 quantity ∉ [1,125] | `quantity must be 1-125` |
| E-8c | 写多线圈数量越界 | FC 0x0F quantity ∉ [1,1968] | `quantity must be 1-1968` |
| E-8d | 写多寄存器数量越界 | FC 0x10 quantity ∉ [1,123] | `quantity must be 1-123` |
| E-9 | FC 0x17 缺数量 | `read_quantity` ∉ [1,125] / `write_quantity` ∉ [1,121] | `read_quantity must be explicit and 1-125` / `write_quantity must be explicit and 1-121` |
| E-10 | Values 长度不符 | FC 0x0F→⌈qty/8⌉ / FC 0x10→qty×2 / FC 0x17→write_qty×2 | `values length must be ceil(quantity/8)` / `values length must be quantity*2` / `values length must be write_quantity*2` |
| E-11 | FC 0x05 写值非法 | `write_value ∉ {0,1,0xFF00,0x0000}` 且无异常码 | `write_value must be 0/1/0xFF00/0x0000 or set exception_code` |
| E-12 | FC 0x18 FIFO 超限 | FIFO count > 31 | `FIFO count exceeds 31` |
| E-13 | FC 0x18 长度不自洽 | `response_values` 长 ≠ 2×FIFO count | `response_values length must match FIFO count` |
| E-14 | FC 0x08 子功能越界 | `sub_function > 0x0015` | `sub_function must be 0x0000-0x0015` |
| E-15 | FC 0x08 子功能保留 | `sub_function ∈ 0x0005-0x0009` | `sub_function 0x0005-0x0009 reserved` |
| E-16 | FC 0x2B MEI 非法 | `sub_function` 低字节 ≠ 0x0E | `FC 0x2B sub_function must be 0x000E` |
| E-17 | FC 0x2B 高字节 | `sub_function` 高字节 ≠ 0 | `FC 0x2B sub_function high byte must be 0` |
| E-18 | 互斥违反 | `exception_code != 0` 且 `response_values` 非空 | `exception_code and response_values are mutually exclusive` |
| E-19 | 广播 + 读 FC | `unit_id=0` + 读类 FC（含 0x17） | `broadcast (unit_id=0) is only valid for write function codes` |
| E-20a | FC 0x14 记录长度 | Record Length = 0 | `record length must be >= 1` |
| E-20b | FC 0x14/0x15 item 长度 | item 长度不符 | `item length mismatch` |
| E-20c | FC 0x15 RefType | item 首字节 ≠ 0x06 | `FC 0x15 item must start with Reference Type=0x06` |
| E-20d | FC 0x15 外层 Byte Count | 外层 Byte Count 与 items 不符 | `FC 0x15 outer byte count mismatch` |
| E-20e | FC 0x14 Values 倍数 | FC 0x14 values 长非 7 的倍数 | `values length for FC 0x14 must be a multiple of 7` |

**`response_values` 长度类锚词**（`modbus.go:631-680`，`validateResponseValues`）：逐 FC 有专属文案（如 `response_values length for FC 0x03 must be 1 + quantity*2`）——存量用例若涉及，锚词按实际 FC 取。**注意**：E-8 拆四行、E-20 拆五行，因文案逐 FC 不同（旧稿"quantity 类"合并写法会漏锚词匹配）。

**负例原子性**：每例单一故障注入；单次执行不得混注。

**不得误报的合法协议事件**：`exception_code == 0`（未设置异常）；Unit ID=0 + 纯写 FC（广播正例）；FC 0x99 + `exception_code != 0`（豁免路径正例）；FC 0x05 `write_value ∈ {0,1,0xFF00,0x0000}`；FC 0x18 FIFO count = 0/31（边界内）。

## 8. 边界

- **帧长**：PDU 253 为合法上界（FC 0x03 qty=125 → PDU 252；FC 0x10 qty=123 → PDU 252）；帧最大 260。不得产生超量分配或回绕长度。
- **数量边界**：每 FC 的最小 1 / 最大（§3.5）/ 最大+1（负例）三档全覆盖。
- **Unit ID**：0（广播）/ 1（缺省）/ 127 / 128 / 247（上界）/ 248（保留首值，负例）/ 255（负例）。
- **TID**：0（首事务）/ 递增 / 65535 / 65536（回绕）。
- **地址**：0x0000 / 0xFFFF / 回绕（FC 0x17 `write_address` 缺省 fallback = `starting_address + write_quantity`，uint16 回绕）。
- **异常码**：0（正常）/ 10 个合法码 / 0x09（reserved，负例）/ 0xFF（负例）。
- **FC 0x2B 枚举**：MEI Type 0x0E（唯一实现值）；Read Device ID Code 0x01/0x02/0x03/0x04；Conformity Level 0x01/0x02/0x03/0x81/0x82/0x83；More Follows 0x00/0xFF；Object ID 0x00-0xFF；Object Len 0。
- **MSS 分段**：MBAP 帧 ≤260B < MSS 1460，默认单帧单段；显式 `mss < 帧长` 时 tcp 层强制分段（今日无例 → A′ 补例）。
- **`direction` 字段**：**已废弃**（`types.go:9553` 注释 "DEPRECATED; planner ignores it"）；用例携带即被忽略（存量有 1 例 `modbus-direction-ignored` 钉该语义）。
- **Modbus Security over TLS（端口 802）**：**明确不解决**（无规范字节依据进入本版范围；迁入计划 = 若需求出现，另立 D- 条目按 TLS 层链 `[ip,tcp,tls,modbus]` 评估）。
- **UDP 承载**：**明确不解决**（spec 定义 TCP 承载为 MBAP；UDP 为厂商方言）。
- 不得产生回绕长度或超量分配（帧长显式声明，不隐式放大）。

## 9. 原子 ID 与完成定义

存量 213 例（180 个唯一 T 编号，25 个 T 号缺号：34/41/46/47/55/57/59/60/67/70/71/72/110/128/132/136/141/142/145/147/158/159/160/194/196）的逐条去向见 `94-modbus-testcase.md` §8。ID 顺序为权威（= JSON 顺序），改写时保持稳定。

**完成定义**：`tcp→modbus` 层链注册已落码；**G-MODBUS-1/2 补齐后**层链形状可跑通；19 个 FC 逐 FC 帧字节验证；异常/广播/豁免/多事务/TID 回绕/v4/v6 全部边界可观测；正负断言与错误传播完成；不声称从站时序与寄存器状态。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | 主站主动建连，单 TCP 连接承载 N 事务，无握手/认证阶段（spec §4.1） | 场景①–⑩ | `DependsOn ["tcp"]` 单值（`registry.go:382`）；TCP 握手/挥手由 tcp 层恒产（`layer_gen.go:180-185`） | 无 |
| 2 | 命令/消息表 | 19 个 FC + 异常响应（spec §6.1-§6.21/§7）；适配为 FC×响应形态矩阵（§10.2，**80 格**逐格结论） | 场景①–⑩ | `modbus.go` 19 个 `build*Request`/`build*Response` 分支 + `Validate` 全分支 | 无（§10.2 逐格） |
| 3 | 状态机 | 建连—数据—释放 3 态；事务无跨事务状态（spec §4.1） | 全正例 | tcp 层拥有状态；modbus 纯驱动 | 无 |
| 4 | 字段表 | MBAP 4 字段 + PDU per-FC 字段（§3.1/§3.3）；`MODBUSConfig` 6 + `MODBUSOperation` 16 字段 | 数据场景层 | `types.go:9471/9499` 已定义；builder 逐字段装配 | **层链承载**（G-MODBUS-1：Fields 缺 `transactions`） |
| 5 | 错误处理 | 20 类负例（§7 表） | 负例 E-1…E-20 | `modbus.go` Validate 全分支（142 个单测覆盖） | 无（锚词已钉） |
| 6 | 超时与活性 | client 侧超时重试（spec §4.1 `RxTimeout`） | — | **不实现**（声明式回放无真实网络） | **显式不适用**（§4 声明） |
| 7 | NAT/代理/被动 | 无被动模式概念（主站直连） | — | 无 | **显式不适用**；NAT 穿透为框架面 |
| 8 | 版本/方言 | Modbus TCP（MBAP）唯一 profile；Modbus Security over TLS 802 明确不解决；IPv6 扩展**引擎已支持但零用例**（A′ 立项） | 正例 | 缺省 502 已落码（`chain_planner.go:1188`）；IPv6 链 MCP 实测 `completed/9 包` | IPv6 用例缺口（A′，§10.3 #58） |

### 10.2 子表①：FC×响应形态矩阵（逐格已覆/立项/不适用）

响应形态四档：**R1 正常响应** / **R2 异常响应（`FC\|0x80`）** / **R3 抑制响应（no_response / suppress_broadcast / Force Listen Only）** / **R4 echo 响应**。

| FC | R1 正常 | R2 异常 | R3 抑制 | R4 echo |
|---|---|---|---|---|
| 0x01 | 已覆 `fc01-read-coils` | 已覆 `exception-fc01-01` | 已覆 `responsemode-no-response`（代表例） | 不适用（读类无 echo） |
| 0x02 | 已覆 `fc02-read-discrete` | 已覆（代表例同 R2 路径） | 已覆（代表例） | 不适用 |
| 0x03 | 已覆 `fc03-read-holding` | 已覆 `exception-fc03-02/05/06/07/08/0a/0b` | 已覆（代表例） | 不适用 |
| 0x04 | 已覆 `fc04-read-input` | 已覆（代表例） | 已覆（代表例） | 不适用 |
| 0x05 | 已覆 `fc05-write-coil` | 已覆 `exception-fc05-03-fc10-04` | 已覆（代表例） | 已覆 `fc05-echo` |
| 0x06 | 已覆 `fc06-write-register` | 已覆（代表例） | 已覆（代表例） | 已覆 `fc06-echo` |
| 0x07 | 已覆 `fc07-read-exc-status` | 已覆（代表例） | 已覆（代表例） | 不适用 |
| 0x08 | 已覆 `fc08-diagnostic` | 已覆（代表例） | 已覆 `fc08-sub-0001-restart`（Force Listen Only 路径） | 已覆 `fc08-sub-0000`（Return Query Data） |
| 0x0B | 已覆 `fc0b-multi-tx` | 已覆（代表例） | 已覆（代表例） | 不适用 |
| 0x0C | 已覆 `fc0c-events-3ev` | 已覆（代表例） | 已覆（代表例） | 不适用 |
| 0x0F | 已覆 `fc0f-write-multi-coils` | 已覆（代表例） | 已覆（代表例） | 不适用（写多类无 echo，响应为地址+数量） |
| 0x10 | 已覆 `fc10-write-multi-registers` | 已覆（代表例） | 已覆（代表例） | 不适用 |
| 0x11 | 已覆 `fc11-report-server-id` | 已覆（代表例） | 已覆（代表例） | 不适用 |
| 0x14 | 已覆 `fc14-read-file` | 已覆（代表例） | 已覆（代表例） | 不适用 |
| 0x15 | 已覆 `fc15-write-file` | 已覆（代表例） | 已覆（代表例） | 已覆 `wire-fc15-reftype6`（echo 含 Record Data） |
| 0x16 | 已覆 `fc16-mask-write` | 已覆（代表例） | 已覆（代表例） | 已覆 `wire-fc16-echo` |
| 0x17 | 已覆 `fc17-read-write` | 已覆（代表例） | 已覆（代表例） | 不适用 |
| 0x18 | 已覆 `fc18-read-fifo` | 已覆（代表例） | 已覆（代表例） | 不适用 |
| 0x2B | 已覆 `fc2b-mei-read-device-id` | 已覆（代表例） | 已覆（代表例） | 不适用 |
| 0x80+（豁免 FC） | 不适用（豁免路径恒异常响应） | 已覆 `fc99-exemption` | 不适用 | 不适用 |

**逐格重数**：20 行（19 个支持集 FC + 1 个豁免行）× 4 列 = **80 格**——已覆 63 / 不适用 17，零空格。

**R2/R3 代表例声明**（§9.21 同分支共享形状可代表）：异常响应（R2）与响应抑制（R3）**FC 无关**（`exception_code`/`response_mode`/`suppress_broadcast` 均为事务级字段，响应构造走同一分支）——故各 FC 行的 R2/R3 由代表例覆盖。**逐 FC 实测**：FC 0x06 与 FC 0x16 **无专属负例**（`grep` 实测 neg=0），其 R2 格由代表例（`exception-fc03-*` 等）覆盖；改写时若要求逐 FC 专属负例，补 2 例（A′）。其余 17 个 FC 均有专属负例（实测 neg ≥ 1）。

**适配声明**：Modbus 无"响应码"概念（响应即数据），"FC×响应形态"是"命令×响应码"矩阵的等价口径（moxa §10.2 同款适配）。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

| # | 变体 | 落点 |
|---:|---|---|
| 1 | 地址 = 0x0000 | 覆 `addr-0-min` |
| 2 | 地址 = 0xFFFF | 覆 `addr-ffff-max` |
| 3 | Unit ID = 0（广播 + 写） | 覆 `broadcast-unit0-mirror` |
| 4 | Unit ID = 0（广播 + 读） | 覆（负例）`r4-bcast-fc01` 等 11 例 |
| 5 | Unit ID = 1（缺省） | 覆 `unitid-default-1` |
| 6 | Unit ID = 127 / 128 | 覆 `unitid-128-mid` |
| 7 | Unit ID = 247（上界） | 覆 `unitid-247-max` |
| 8 | Unit ID = 248 / 255（保留） | 覆（负例）`validate-unitid-248`/`-255` |
| 9 | quantity = 0 | 覆（负例）`validate-qty-*` 系列 |
| 10 | quantity = 1（最小） | 覆 `fc01-qty1-min` 等 |
| 11 | quantity = 各 FC 最大 | 覆 `fc01-qty2000-max`/`fc03-qty125-max`/`fc0f-qty1968-max`/`fc10-qty123-max` |
| 12 | quantity = 最大+1 | 覆（负例）`validate-qty-fc01-2001`/`-fc03-126`/`-fc0f-1969`/`-fc10-124` |
| 13 | 位打包非 8 倍数（qty=10） | 覆 `fc01-read-coils`/`fc0f-qty123-unaligned` |
| 14 | 位序 LSB 优先 | 覆 `fc01-bit-order-lsb` |
| 15 | 异常码 0（未设置） | 覆 `validate-exc-00`（不报错，V-122） |
| 16 | 异常码 10 个合法值 | 覆 `exception-fc03-*` 7 例 + `fc01-01` + `fc05-03-fc10-04` 多码例 |
| 17 | 异常码 0x09（reserved） | 覆（负例）`validate-exc-09` |
| 18 | 异常码 0xFF | 覆（负例）`validate-exc-ff` |
| 19 | FC 0x05 写值 0 / 1 / 0xFF00 / 0x0000 | 覆 `fc05-writevalue-0`/`-1`/`-ffff`/`fc05-write-off-0000` |
| 20 | FC 0x05 写值非法（0x1234） | 覆（负例）`validate-fc05-illegal-value` |
| 21 | FC 0x08 子功能 0x0000/0x000A/0x000F/0x0013/0x0015 | 覆 `fc08-sub-0000`/`-000a`/`-000f`/`-0013-iop`/`-0015-max` |
| 22 | FC 0x08 子功能 0x0016（越界）/ 保留 | 覆（负例）`validate-fc08-subfn-0016`/`-reserved` |
| 23 | FC 0x2B MEI 0x0E | 覆 `fc2b-mei-base` |
| 24 | FC 0x2B MEI ≠ 0x0E（0x0F） | 覆（负例）`validate-fc2b-mei-000f` |
| 25 | FC 0x2B 高字节非 0 | 覆（负例）`validate-fc2b-highbyte-010e` |
| 26 | FC 0x2B Conformity Level 0x01/0x03/0x83 | 覆 `fc2b-conformity-01-basic`/`-03-extended`/`-83-extended-private` |
| 27 | FC 0x2B More Follows 0xFF + Next Object ID | 覆 `fc2b-more-follows-ff-next-05` |
| 28 | FC 0x2B Object Len 0 / 255 | 覆 `fc2b-object-len-0`/`-255` |
| 29 | FC 0x2B 多对象 | 覆 `fc2b-mei-multi-obj` |
| 30 | FC 0x14 RefType = 0x06 | 覆 `fc14-read-file`/`fc14-multi-record` |
| 31 | FC 0x14 Record Length = 0 | 覆（负例）`validate-fc14-reclen-0` |
| 32 | FC 0x14 响应 offset | 覆 `fc14-response-offsets` |
| 33 | FC 0x15 RefType = 0x06（item 首字节） | 覆 `wire-fc15-reftype6` |
| 34 | FC 0x15 RefType = 7（非法） | 覆（负例）`validate-fc15-reftype-7` |
| 35 | FC 0x15 Byte Count 不符 | 覆（负例）`validate-fc15-bc-mismatch` |
| 36 | FC 0x15 Record Length = 0 | 覆（负例）`validate-fc15-reclen-0` |
| 37 | FC 0x16 MaskAnd/MaskOr 0x0000/0xFFFF | 覆 `fc16-mask-and-0000`/`-ffff` |
| 38 | FC 0x16 掩码公式 | 覆 `fc16-mask-formula` |
| 39 | FC 0x17 read/write 独立字段 | 覆 `fc17-read-write` |
| 40 | FC 0x17 write_address 显式 / fallback | 覆 `fc17-writeaddr-explicit`/`-fallback` |
| 41 | FC 0x17 write_address 回绕 | 覆 `fc17-writeaddr-wrap` |
| 42 | FC 0x17 read_quantity 最大 125 / write_quantity 最大 121 | 覆 `fc17-readqty-125-max`/`writeqty-121-max` |
| 43 | FC 0x17 read_quantity 越界 126 | 覆（负例）`validate-fc17-readqty-126` |
| 44 | FC 0x17 quantity 被忽略 | 覆 `fc17-quantity-ignored` |
| 45 | FC 0x18 FIFO Count 0 / 2 / 31 | 覆 `fc18-fifo-count-0`/`fifo2-min`/`fifo31-max` |
| 46 | FC 0x18 FIFO Count 32（越界） | 覆（负例）`validate-fc18-fifo-32` |
| 47 | FC 0x18 长度不自洽 | 覆（负例）`r4-fc18-fifo-inconsistent` |
| 48 | FC 0x11 响应无 Byte Count | 覆 `wire-fc11-no-byte-count` |
| 49 | FC 0x11 Additional 空 | 覆 `fc11-additional-empty` |
| 50 | FC 0x0C Events 字段序 | 覆 `fc0c-events-3ev`/`fc0c-events-decoupled` |
| 51 | FC 0x0B Status/EventCount | 覆 `fc0b-multi-tx` |
| 52 | FC 0x07 Exception Status 0 | 覆 `fc07-exc-status-zero` |
| 53 | ResponseValues 覆盖响应 | 覆 `r2-resp-values-indep` |
| 54 | ResponseValues × ExceptionCode 互斥 | 覆（负例）`validate-mutex-exc-rv` |
| 55 | response_mode = no_response | 覆 `responsemode-no-response` |
| 56 | 豁免路径（FC ∉ 支持集 + 异常码） | 覆 `fc99-exemption`/`validate-fc99-exc0`（负例：豁免不生效） |
| 57 | direction 字段已废弃 | 覆 `direction-ignored` |
| 58 | IPv6 载体 | **零覆盖（A′ 立项）**——213 例地址恒 `10.0.0.1→20.0.0.1`（机读唯一值）；引擎已支持（MCP 实测 IPv6 链 `completed/9 包`，`ipv6.src/dst` 正确）→ 补例 `modbus_ipv6`（offset 74） |
| 59 | 非缺省端口（1502） | 覆 `dstport-1502` |
| 60 | 缺省端口（502 补齐） | **A′ 立项**——存量 `dstport-default-502` 名为"缺省"但**实际显式写了 `dst_port:502`**（机读实测），未验补齐；补例 `modbus_default_port_502`（**删键**） |

60 行全部有落点。✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | SCADA 轮询采集（spec §6.3 读保持寄存器） | `fc03-read-holding` + `tx-order-sequential` | 已覆 |
| 2 | 开关量状态读取（spec §6.1/§6.2） | `fc01-read-coils`/`fc02-read-discrete` | 已覆 |
| 3 | 控制写入（spec §6.5/§6.6/§6.11/§6.12） | `fc05-write-coil`/`fc06-write-register`/`fc0f-*`/`fc10-*` | 已覆 |
| 4 | 设备标识发现（spec §6.21 MEI 0x0E） | `fc2b-mei-read-device-id` + 5 个 Conformity 例 | 已覆 |
| 5 | 批量配方文件读写（spec §6.14/§6.15） | `fc14-read-file`/`fc15-write-file` | 已覆 |
| 6 | FIFO 队列（spec §6.18） | `fc18-read-fifo` | 已覆 |
| 7 | 广播多从站动作（spec §4.4） | `broadcast-unit0-mirror`/`-suppress` | 已覆 |
| 8 | 异常回执诊断（spec §7） | `exception-fc03-*` 7 例 | 已覆 |
| 9 | 网关部署（spec §7 异常码 0x0A/0x0B） | `exception-fc03-0a`/`-0b` | 已覆 |
| 10 | Modbus Security over TLS（802） | — | **明确不解决**（§8） |
| 11 | UDP 承载（厂商方言） | — | **明确不解决**（§8） |

9 覆 + 2 不适用 = 11。✓ 本表零缺口。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：① **规范原文**（MB-ASYM-TCP V1.1b3，定"必须是什么"：MBAP 7 字节头、19 个 FC、10 个异常码、广播语义）；② **商业化软件实际行为**（Modbus Poll / Simply Modbus / Kepware 等主站工具：单连接多事务、TID 从 0 递增、广播只写、异常回执 `FC|0x80`——旧稿 §6 S1-S15 场景即按此建立；本版不引入新断言）；③ **可靠开源实现思路**（本仓库同族先例：enip/dnp3/mqtt 的"TCP 终结层 + 事件流 + flat 键直传"，只借鉴接线思路不搬码）。三路一致点：单 TCP 连接 + 帧自带长度 + 事务独立；不一致点 = **响应是否总发**（现网 slave 对广播不回，本仓库为 traffic-mirror 用途默认发镜像，`suppress_broadcast` 可关——取舍：以配置字段为准，用例两侧都覆盖）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `modbus` 终结层（本版；enip/dnp3/mqtt 同构先例） | 帧序列/异常/广播/多事务/TID 五事可声明可断言；代价 = 一层薄皮（已落码 4930 行） | **采用** |
| B | 直接 tcp 层 + 顶层 payload 裸字节 | 无 FC 语义、无响应自动构造、无异常/广播表达 → §7 全部 20 类负例不可表达 | **否决** |
| C | 与 moxa 合并为"工业透传族" | Modbus 有应用层帧（MBAP+FC），moxa 无帧——文法不兼容，合并即错 | **否决** |

## 11. P2 D-MODBUS-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 状态说明：实现已落码（`internal/protocol/modbus/` 七文件），本 P2 条目为对既有实现的 **as-built 逆向定稿**，供门1 批准后作为后续改动的唯一入口；**层链内化（G-MODBUS-1/2）为本条目下的待实现边界**（§14）。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:9471`/`:9499` + `:1866`） | `MODBUSConfig`（6 字段）/ `MODBUSOperation`（16 字段）+ `FlowSpec.MODBUS` 槽位 | —（共享文件） |
| `trafficgen/internal/protocol/modbus/modbus.go` | `Planner.Validate`（20 类拒绝）+ `Plan`（握手→事务循环→挥手）+ `shouldGenerateResponse` + `build*PDU` | 1121 |
| `trafficgen/internal/protocol/modbus/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator("modbus")` + validator 注册，`init()`） | 186 |
| `trafficgen/internal/protocol/modbus/builder.go` | MBAP 帧装配 + 各 FC 请求/响应 PDU 字节产出 | 432 |
| `trafficgen/internal/protocol/modbus/parser.go` | 配置解析（`parseMODBUSConfig` 消费键同名） | 547 |
| `trafficgen/internal/protocol/modbus/types.go` | 类型别名 + 常量 | 120 |
| `trafficgen/internal/protocol/modbus/modbus_test.go` + `layer_gen_test.go` | 142 个 `Test*`（129 + 13，`grep -c` 实测） | 1909 + 615 |
| 接线 5 件 | registry 注册（`layers/registry.go:382`）/ Meta 直传（`chain_planner_translate.go:89`）/ convert 子配置搬运（`strategy_convert.go:1579`+`:7813`）/ protocols 准入（`protocols.go:48`）+ migrationAllowlist（`convert_proxy.go:61`）/ validateSpecBase 端口（`chain_planner.go:938`/`:1188`） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`modbus.go:62`）：`MODBUS==nil` → 拒绝（`modbus: MODBUS config is required`）；`master_count`/`flow_count`/`unit_id` 范围；逐事务 `validateOperation`（`:163`）——20 类拒绝归一分支，错误文案与 §7 锚词逐字一致。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`modbus.go:96`）：先 Validate；`cfg == nil` 补空配置；`transactions == nil` 补默认事务；逐事务 emit（SYN/SYN-ACK/ACK → 请求帧 → 可选响应帧 → FIN 四包）。
- 生成器：`Name() "modbus"`；`Generate(ctx, req)`（`layer_gen.go:57`）读 `req.Meta.MODBUS`；`GenEvents()` 事件生成器；`EmitEvent` 未接线显式错（防误调）；validator 注册（`layer_gen.go:155`）含多流双拒 + 握手/挥手强制 true。

### 11.3 数据结构

`MODBUSConfig{UnitID *uint8, SuppressBroadcast bool, Transactions []MODBUSOperation, MasterCount int, FlowCount int, SharedTIDSpace bool}`（`types.go:9471`，6 字段）；
`MODBUSOperation{FunctionCode uint8, ExceptionCode uint8, StartingAddress uint16, Quantity uint16, ReadAddress uint16, WriteAddress uint16, ReadQuantity uint16, WriteQuantity uint16, WriteValue uint16, Values []byte, ResponseValues []byte, SubFunction uint16, MaskAnd uint16, MaskOr uint16, ResponseMode string, Direction string}`（`:9499`，16 字段 + `Direction` 已废弃）。无新增字段。

### 11.4 主流程

配置 → validator（20 类拒绝 + 多流双拒 + 握手/挥手强制 true）→ planner（事务循环：`buildRequestPDU` → MBAP 装配 → emit；`shouldGenerateResponse` 为真则 `buildResponsePDU` → MBAP 装配 → emit）→ worker（TCP 握手/分段/挥手）→ writer（PCAP/NIC）。

### 11.5 错误分支

20 类 validator 拒绝各对应 planner/生成器双层守卫（§7 表）；全部传 task error（零假成功）。多流（`master_count>1`/`flow_count>1`）在生成器 + validator 双拒（`layer_gen.go:88-91`/`:158-166`）。

### 11.6 性能边界

见 §6（逐事务流式、per-flow 局部状态、`shared_tid_space` 原子计数器、无跨流共享；吞吐数字待代码补齐后基准）。

### 11.7 与现有逻辑的冲突点

- **`CheckProtoFlat`（`strategy_convert.go:8625`）无 modbus 分支**（`grep -c 'protocol == "modbus"'` = **0** 实测）：顶层 `modbus` 子映射 presence 不判死——属缺口 **G-MODBUS-3**（禁加单协议黑名单分支，等框架级 unknown-key 白名单；kingbase/moxa 记忆裁定）。
- **动态 allowlist**（`internal/core/layer_dyn.go` 头部）：`modbus` **零命中**实测 → 业务字段动态对象即拒；四元组 `ip`/`tcp`/`udp`/`eth` 全开。见 §12.12。
- **registry `modbus` Fields 仅 5 键**（`registry.go:382-394`）→ 层内 `transactions` 键无处可住，目标形状（§2）需补 Fields（G-MODBUS-1）。
- **`translateTerminalConfig` 无 `case "modbus"`**（`chain_planner_translate.go:855`）→ 层 config 不翻译进 `spec.MODBUS`，空层探针实测任务失败（G-MODBUS-2）。
- **`Direction` 字段已废弃**（`types.go:9553`）：planner 忽略；用例携带即被忽略（`modbus-direction-ignored` 钉该语义）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议七文件 + 接线 5 处（registry/protocols+convert_proxy/translate/strategy_convert/chain_planner）；不触及其他协议。cases 回滚 = 恢复 213 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 213/213 顶层含 `src_ip/dst_ip/src_mac/dst_mac/src_port/dst_port/modbus`（旧扁平残留）；132 例的 `layers` 是**空壳**；目标形状见 §2 样例（**今天跑不通**，G-MODBUS-1/2）；presence 判死形状缺口 G-MODBUS-3 | §12.1；`cases/modbus.json` 机读实测；§0.1 MCP 实测 |
| §2 策略/任务 | 策略 = 单 modbus 流量模板，自带 `flow_control`；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（终结层）/时间线。有长连接，不豁免 | §12.3 + §5 |
| §4 查规范 | spec MB-ASYM-TCP V1.1b3 + PI-MBUS-300 Rev. J + tshark 实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["tcp"]` 单值（`registry.go:382`）；20 类拒绝分支；失败传 task error | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待基准，不写承诺） | §6 |
| §7 三份文档 | `94-modbus-{design,testcase}.md` v1.0.0（草稿层）+ D-MODBUS-1（§11，门1 获批 = 定稿）+ T-MODBUS（testcase §2）+ 旧稿 13-* 为历史层 | 修订记录 |
| §8 设计先行 | P1–P3 先于 G-MODBUS-1/2 补齐；门1 获批 = D-MODBUS-1 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = spec（§10）+ D-MODBUS-1（§11）+ tshark 通道实测（`modbus.*`/`mbtcp.*`）；213 ID 逐项回指；存量缺口登记 testcase §8（本车道不改 JSON） | `94-modbus-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 `/tmp/pipe/doc-lanes/modbus.md`）+ 收官隔离复审；红先绿后 | 车道日志 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `modbus` 已在 `registry.go:382` 注册（**不新增层**）；`allowedProtocols["modbus"]=true`（`protocols.go:48`）；Meta 已直传（`translate.go:89`）；**补 Fields 必须重跑 schemagen**（G-MODBUS-1） | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `modbus.*`/`mbtcp.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/modbus/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-28）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 纯净 |
|---|---|---|---|---|
| `cases/modbus.json` | 213 | `{layers,src_ip,dst_ip,src_mac,dst_mac,src_port,dst_port,modbus}` ×130 + 同形带 `count` ×2 + 纯扁平 ×81 | 132 例的 `layers` 恒为 `[{"tcp":{}},{"modbus":{}}]`（**空壳**）；81 例无 `layers` | 否——62 负例中 **11 例无 `error_contains`**、**8 例 expect 仅 `{expect_error}`**、5 例混入 `has_handshake`/`terminates`/`directional`（违反负例纯净性，testcase §4 修） |

**旧键去向表（§15.3 要求"每个键写去向"）**：

> **口径**：出现例数按**全例口径**（213 例）列出，便于看"该键在存量里覆盖多广"；合规化清理量按**非负例口径 1059**（见 §0.1）。两列并列，避免口径混淆。

| 旧键 | 出现例数（全例 213） | 非负例（151） | 去向 |
|---|---:|---:|---|
| `src_ip` | **213** | 151 | 迁 `layers[i].ip.src` |
| `dst_ip` | **213** | 151 | 迁 `layers[i].ip.dst` |
| `src_mac` | **213** | 151 | 迁 `layers[i].eth.src_mac`（§1.11 白名单明确 MAC 真相住 eth 层） |
| `dst_mac` | **213** | 151 | 迁 `layers[i].eth.dst_mac` |
| `src_port` | **213**（211 例值 0） | 151 | 迁 `layers[i].tcp.src_port`；**值 0 = "不写"**（`chain_planner.go:938` 保持 0），改写时删除键（走保底递增） |
| `dst_port` | **213**（212 例 502 / 1 例 1502） | 151 | 迁 `layers[i].tcp.dst_port`；502 例**或删**（由 FieldContract 缺省补齐，A′ 验证） |
| `count` | **2** | 2 | 迁 `flow_control {"flows": N}`（§1.3） |
| 顶层 `modbus` 子映射 | **213** | 151 | **迁 `layers[i].modbus`**（须先补 registry `Fields`，G-MODBUS-1） |

**结论**：本协议有实质迁移工作量——§1 门的动作 = ①补 registry `Fields`（transactions + 16 个 per-op 键，G-MODBUS-1）；②加 translate 分支（层内 modbus → `spec.MODBUS`，G-MODBUS-2）；③213 例整体改写；④收官自查行「非负例顶层键 = 0」由 **8 键 → 0**（清理量 1059 处，非负例口径）。

目标形状样例见 §2（顶层仅 `layers` + `flow_control`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"modbus":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 modbus 分支，`grep -c` = 0 实测；§0.1 MCP 实测该形状 `status=completed`）→ **不建该负例**（建了会真绿 = 假通过）→ 缺口 G-MODBUS-3 登记。② 白名单外游离键判死（`unknown field`）可建一条（A′）。③ 62 负例锚词与负例纯净性须修齐（11 例缺锚词、8 例仅 `expect_error`、5 例混入成功断言）。④ 收官自查「非负例顶层键 = 0」（迁移后执行）。

### 12.3 §3 强制展开：五件套

- **会话表**：`s1` 单连接基线（全正例，各自四元组，SYN→事务循环→FIN 四包挥手）/ `s2` 多流会话（`flow_control flows=N`，worker 递增 `src_port`）。**无多会话数组**——Modbus 无 `sessions[]` 概念（连接即会话；多连接由策略级 `flows` 表达）。
- **事务序列**：`t1` 建连（握手，tcp 层）/ `t2` 发请求帧（每事务一个 MBAP 帧）/ `t3` 收响应帧（`shouldGenerateResponse` 为真时；端口对换）/ `t4` 终止（FIN；RST 为框架面不适用）；每事务四件事（前置/触发/成功/失败）见 §5 状态机 + §4 场景表。**事务间无依赖**（spec §4.1 无状态）——`t2→t3` 仅共享 TID。
- **关联关系**：**无派生流**（诚实声明：单 TCP 连接承载全部事务，无 `driven_by`；Modbus 无控制流/数据流分离概念——旧稿 §1.2 同结论）。
- **插入位置**：终结层（`[ip,tcp,modbus]`，无中间层）。
- **时间线**：事务内严格顺序（req → resp）/ 多流顺序展开（`flows=N` 整块 per-flow，跨流不假设全局包序，只断言聚合）/ 无交错（`concurrent` 不适用）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst`、`ip.ttl`、`tcp.src_port/dst_port`、`udp.src_port/dst_port`、`eth.src_mac/dst_mac` 五策略全开（allowlist `internal/core/layer_dyn.go` 头部实测四行：`ip`/`tcp`/`udp`/`eth`；保底 `DefaultSrcPort+i`（`worker.go:307-309`，常量 `strategy_convert.go:49`）；dst 动态与 502 缺省和平共处——显式/动态值非零即不触发补齐）。

**业务字段全关**（allowlist 无 `modbus` 行，`grep` 零命中实测；对象即拒）：`transactions[]`（事务剧本，16 个 per-op 键）/ `unit_id`（从站选择器）/ `suppress_broadcast`（广播策略）/ `shared_tid_space`（TID 空间选择器）——逐流变体需求列 A′ 候选（testcase §6.2）。

序号算法实读：`parseLayerDyn`（`internal/core/layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`worker.go:307-309` 注入 `DefaultSrcPort+i`）/ allowlist 白名单（`layer_dyn.go` 头部）——**`modbus` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。

## 13. P3 对接清单（T-MODBUS 草稿输入；正文落 testcase 文件）

存量 213 例（151 正 + 62 负，180 个唯一 T 编号）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 存量缺口登记（testcase §2–§5/§8 全量；本车道不改 JSON）。**A′ 可建 5 例**（与 testcase §6.2 对齐）：`modbus_ipv6`（**IPv6 零覆盖，offset 74**；引擎已支持，MCP 实测通过）/ `modbus_eth_mac_layer`（MAC 迁层验证）/ `modbus_default_port_502`（删 dst_port 验证 FieldContract 补齐）/ `modbus_mss_segment`（显式小 MSS 分段）/ `modbus_neg_unknown_field`（白名单外游离键）。**另有 1 例不建**：`modbus_neg_presence_shape`（G-MODBUS-3 未闭前建了假绿，不计入可建数）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| **G-MODBUS-1** | registry `modbus` Fields 仅 5 键，缺 `transactions` 及 16 个 per-op 键 → 层内配置无处可住 | 代码车道：补 Fields（moxa `registry.go:747-760` 范本）+ **重跑 schemagen**（`go run ./internal/core/layers/schemagen`） |
| **G-MODBUS-2** | `translateTerminalConfig` 无 `case "modbus"` → 层 config 永不进 `spec.MODBUS` | 代码车道：加分支（moxa `chain_planner_translate.go:3304` 范本——`completedConfig` + 严格 JSON 往返 + 空层二态）；对照 `spec.MODBUS` 已在 `drive` Meta 清单（`:89`） |
| **G-MODBUS-3** | `CheckProtoFlat` 无 modbus 分支 → 顶层 `modbus` 子映射 presence 今日不判死（§0.1 实测 `completed`） | 先实测再建例；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单；kingbase/moxa 裁定） |
| **G-MODBUS-4** | 业务字段动态全关（allowlist 无 `modbus` 行） | A′ 候选，不冒充已覆盖（§9.36 口径） |
| **G-MODBUS-5** | 存量 213 例三种形状全不可执行（§0.1） | 本车道只登记；**JSON 改写待 G-MODBUS-1/2 闭合**（testcase §8 逐条去向） |
| **G-MODBUS-6** | 62 负例中 11 例缺 `error_contains`、8 例 expect 仅 `{expect_error}`、5 例混入成功断言 | testcase §4 修（负例纯净性 §7 需求）；锚词按 §7 表补齐 |
| **G-MODBUS-7** | 多流展开（`master_count>1`/`flow_count>1`）在链形状拒绝 | **明确不解决**（enip/dnp3 同款：链一次一个 flow）；迁入计划 = 语义走策略级 `flow_control flows=N`，用例改写时 `master_count`/`flow_count` 用例转 `flow_control` 或标不适用 |
| **G-MODBUS-8** | 响应超时/重传（spec §4.1 `RxTimeout`）未实现 | **明确不解决**（声明式回放无真实网络）；用例不得携带该语义 |
| **G-MODBUS-9** | IPv6 零用例覆盖（213 例地址恒 IPv4；引擎已支持）——**存量、非本次引入** | A′ 补例 `modbus_ipv6`（offset 74，断言 `ipv6.src/dst`） |
| **G-MODBUS-10** | MSS 分段零用例（213 例无 `mss` 键；MBAP 帧 ≤260B < MSS 1460，默认单帧单段）——**存量、非本次引入** | A′ 补例 `modbus_mss_segment`（显式 `mss < 帧长`，先跑后钉段数） |
| **G-MODBUS-11** | `modbus-dstport-default-502` **名实不符**：名为"缺省"但显式写了 `dst_port:502`（机读实测），未验 FieldContract 补齐——**存量、非本次引入** | A′ 补 `modbus_default_port_502`（**删键**不断言值）；存量例改名或改载荷 |
| **G-MODBUS-12** | `validate-mastercount-0` 与 `validate-mastercount-1001` **载荷重复**（均 `master_count:1001`），且两例注记均写"=0 rejected"与载荷不符——**存量、非本次引入** | 改写时：一例保留为 `>max` 负例、另一例改载荷为 `0`（并修注记），或删除并注记原因；`flowcount-0` 同款（载荷 101、注记写 0） |
| **G-MODBUS-13** | `layer_gen_test.go:272` 注释称"legacy modbus.go 是 3 包挥手"**与代码不符**——实读 `modbus.go:575-593` 为 **4 包**（同文件 `:398` 自述"TCP 四次挥手"）——**存量、非本次引入** | 代码车道改注释（本车道禁改代码）；**不影响包数断言**（存量 213 例已按 4 包校准，9 = 3+2+4） |

## 15. 修订记录

- v1.0.0（2026-09-28）：P-PIPE #94 文档轨 P1–P3。13→94 沿革与 8 项过期校正（§0）；**存量 213 例可执行性 MCP 实测（§0.1）——三种形状全被拒，根因 G-MODBUS-1/2**；§12.1/12.3/12.12 强制展开 + 12-P2；D-MODBUS-1 as-built 定稿（§11）；缺口 G-MODBUS-1…G-MODBUS-13（含 G-MODBUS-11/12/13 三项存量问题登记）。**显式结论**：213 例当前无可执行断言属文档阶段预期状态（§0.1）。主线程裁定 2026-09-28：走 (b)，本车道不改 `cases/modbus.json`。自审轮次见 `/tmp/pipe/doc-lanes/modbus.md`。

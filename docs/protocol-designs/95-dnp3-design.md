# #95 dnp3（IEEE 1815-2012 DNP3 主站/外设）设计契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3）
> 日期：2026-09-28
> 车道：A 文档轨（Lane A，#95 dnp3）
> 旧基线：`docs/protocol-designs/11-dnp3-design.md` v1.1.4（2026-08-04，70 例语义来源；本 #95 为 P-PIPE 重做，思路继承、不搬码——旧稿"实现状态：未实现"已过时，见 §0）
> 存量用例：`trafficgen/test/protocol_pcap/cases/dnp3.json`（**70 例，本版保持原样未改**；改写留待代码阶段，理由见 §0.1 与 testcase §8）
> 规范基线：① IEEE 1815-2012（DNP3 官方标准，下称 **spec**）；② 旧基线设计文档（内部契约，非外部规范）；③ 本仓库落码（planner/builder/parser/scenario/生成器/接线，§11.1）；④ 本机 tshark 实测（tshark 3.6.14 有 `dnp3.*` dissector 共 166 字段；存量断言实际走 `tcp.*` + frames 通道，`dnp3.*` 为 A′ 可选增强）；⑤ 公开资料 + 假设（逐处标注，未达验证级 → G-DNP3-4）
> 白话一句：**DNP3 是电网/水厂那类"主站挨个问、外设老实答"的问答协议；一问一答都是带 CRC 的小帧，引擎里它是一层终结层——只管把问答帧按剧本排好，握手分段挥手全交给 TCP 层。**

## 0. 11→95 沿革与旧稿过期声明校正（门1 必答：基线继承关系）

本 #95 与旧稿 `11-dnp3-*` 是**同一协议的重做契约**，不是新协议。旧稿保留在磁盘只读参考，本契约逐条校正旧稿已过时的状态声明：

| # | 旧稿说法（11-*） | HEAD 实测（2026-09-28） | 校正结论 |
|---|---|---|---|
| 1 | "**实现状态：未实现**（见 00-unimplemented-list.md 工控类第 11 项）"（旧稿头注） | `trafficgen/internal/protocol/dnp3/` 八文件已落码共 **1468 行**：`builder.go` 163 / `dnp3.go` 143 / `dnp3_test.go` 314 / `layer_gen.go` 120 / `layer_gen_test.go` 438 / `parser.go` 75 / `scenario.go` 111 / `types.go` 104（`wc -l` 实测）；34 个 `Test*` 函数（`dnp3_test.go` 20 + `layer_gen_test.go` 14，`grep -c` 实测） | "未实现"已过时；本契约 §11 为 as-built 逆向定稿 |
| 2 | 旧稿通篇只有扁平 `Plan` 路径（§5.1：`Plan` 产 TCP 握手 3 包 + 数据 + 挥手 4 包） | 双路径并存：legacy `Planner.Plan`（`dnp3.go:67`，flat 入口，自产握手挥手）**+** 层链事件生成器 `DNP3Generator`（`layer_gen.go:43`，`GenEvents` 事件面，握手挥手交 tcp 层） | 层链路径为 P4a 新增；旧稿只描述 legacy |
| 3 | 旧稿未提层注册 | `registry.go:253` 已注册 `dnp3`（`CategoryTerminal`，`DependsOn ["tcp"]`，**无 Fields**）；生成表 `dnp3` 条目 `fields: {}`（机读实测） | 已注册；但**层是空壳**——层内配置今日无处可住（G-DNP3-1，§0.1） |
| 4 | 旧稿未提 `DNP3Config` 落码 | `internal/core/types.go:3458` 已定义 `DNP3Config`（39 键）；`:3501` `DNP3Object`、`:3512` `DNP3Point`、`:3521` `DNP3MultiOutstation`；`FlowSpec.DNP3` 槽位 `:1887` | 已落码 |
| 5 | 旧稿 §3 配置样例全部顶层扁平键（`src_ip`/`dst_ip` + 顶层 `dnp3` 子映射） | 存量 70/70 例含 `src_ip`/`dst_ip` + 顶层 `dnp3` 子映射（机读实测）；其中 41 例另带 `layers` 空壳 `[{tcp:{}},{dnp3:{}}]`，13 例另带顶层 `src_port` | 旧样例形 = **过渡态违规形**（§1.4/§1.11），**待代码阶段收敛**（§12.1）；§2 只给目标形状样例并标注今日不可跑 |
| 6 | 旧稿包数公式按 `Plan` 逐帧手算（§5.4 表：13 包 = 3 握手 + 6 数据 + 4 挥手） | 存量 JSON `packet_count` 机读实测：T21=9 / T22=13 / T23=15 / T24=11 / T25=9 / T26=11 / T28=6 / T29=5（legacy `Plan` 值）；层链事件面 = 3 握手 + N 帧 + 4 挥手（`layer_gen.go:43-67` 逐帧 emit） | legacy 公式继承有效（存量断言按实测钉）；层链值须代码阶段先跑后钉复核（§9.31） |
| 7 | 旧稿 §2.9 称"UDP 传输用 2 字节传输头（LTH+SEQ）"，无拒绝语义 | 层链生成器**显式拒绝** UDP：`dnp3 generator: transport=udp is not supported on the layer chain (tcp only)`（`layer_gen.go:52`）。**legacy `Plan`（`dnp3.go:138-139`）代码仍在，但其扁平入口今日已被 `CheckProtoFlat` 判死（§0.1 判据 B，实测 70/70 400）** | 层链不支持 UDP（诚实边界，§1）；存量 T27（UDP 2 包）为**历史实测值**，两条路径今日均不可执行，代码阶段收敛时须按新能力重判（G-DNP3-11） |
| 8 | 旧稿 §5.5 称"MultiOutstation Count=M → M 个独立 PacketConfig 流" | 层链生成器**显式拒绝** multi_outstation：`dnp3 generator: multi_outstation is not supported on the layer chain (one flow per outstation)`（`layer_gen.go:55`）。**legacy `Plan`（`dnp3.go:74-79`）代码仍在，但其扁平入口今日已被 `CheckProtoFlat` 判死（§0.1 判据 B）** | 层链不支持多外设展开（诚实边界，§1）；存量 13 例 multi 为**历史实测值**，两条路径今日均不可执行，代码阶段收敛时须按新能力重判（G-DNP3-11） |

### 0.1 层为空壳 + 扁平路径已判死——本版不改 cases JSON 的判据（2026-09-28 主线程裁定）

**判据 A：层为空壳**（两条同时成立）：

| # | 判据 | 实测 |
|---|---|---|
| 1 | `registry.go` 该协议 Register **无 `Fields`** | `registry.go:253` dnp3 Register 只有 `Name`/`Category`/`DependsOn`，**无 Fields**；生成表 `layers.generated.json` dnp3 = `{"category":"terminal","depends_on":["tcp"],"fields":{}}` |
| 2 | `translateTerminalConfig` 的 switch **无该协议 `case`** | `grep 'case "dnp3"' chain_planner_translate.go` = **0**（对比 `case "enip"` :2573 / `case "doip"` :2955 / `case "moxa"` :3304 均在） |

**后果链**：`chain_planner_translate.go:852` 的 `if len(s.Fields) == 0 { return }` 使层内配置**根本不被解码**；层内业务键被 `ValidateLayerConfig` 拒（`layers: layer "dnp3": unknown field "..."`，`complete.go:293`）。

**判据 B：扁平路径今日已判死（本版关键，2026-09-28 实测）**：

| 路径 | 实测 | 证据 |
|---|---|---|
| MCP / 建策略 | **存量 70/70 全部 400** | `schema/semantic.go:130` 调 `core.CheckProtoFlat`——该调用位于 layers 分支（`:109-120`）**之后且无条件**；`CheckProtoFlat`（`strategy_convert.go:8625+`）对 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count` 任一出现即返 400。存量 70/70 带 `src_ip`+`dst_ip` → 全红，文案 `protocol dnp3 no longer accepts flat config field src_ip`。**本车道实测复现：70 rejected / 0 accepted** |
| 离线 suite | **根本不跑 dnp3** | `layer_chain_suite_test.go:70` 的 `chainSuiteProtos` 白名单**不含 dnp3**；且 29 例无 `layers` 键被 `:138` 跳过（41 例有 layers 但同带顶层四元组，剥离 layers 后直传 `MapToFlowSpec`，**绕过 `CheckProtoFlat`**，属套件内部旁路、非生产路径） |

**结论**："legacy flat 路径"**今日已不存在**（Step 1 全协议扁平判死关闭）。**存量 70 例今日既非绿也非红——它们不可执行**；其 `packet_count`/frames 断言仅为**历史实测值**（旧版本遗留），待代码阶段层链内化后**重新校准**（§9.31 先跑后钉）。

**为什么今日改不动 cases JSON**：存量"层链例"实为 `layers:[{tcp:{}},{dnp3:{}}]`（**空壳层**）+ 顶层 `dnp3` 子映射 + 顶层四元组并存——**判死形状**（§1.4/§1.11/§1.13）。改成目标形状后层内键无处可住（判据 A，被 V9 拒）；保持原样则扁平键 400（判据 B）。**两条路都走不通**，故 `cases/dnp3.json` **保持原样**，合规化留代码阶段。

**故本版交付 = 设计 + 测试用例文档 + 缺口登记表**，`cases/dnp3.json` **保持原样**（70 例）。这与 rip/ldp/a2a/nvgre/pcep/someip 同批空壳协议一致；已补 Fields 的 moxa/iec104/tns/mongodb/stratum/coap 走正常改写路径。

**存量残留实测（机读，2026-09-28）**：**非负例口径 = 163 处**（主口径；`src_ip` 50 / `dst_ip` 50 / 顶层 `dnp3` 子映射 50 / `src_port` 13）——即 50 个非负例中**每个**都带 `src_ip`+`dst_ip`+`dnp3`，其中 13 例另带 `src_port`。**全例口径 = 223 处**（含 20 个负例的 60 处：`src_ip` 20 / `dst_ip` 20 / `dnp3` 20）。41 例带空壳 `layers`，29 例无 `layers`。

**依赖链判定纪律**：以上均为可判题（旧文→代码→用例三级对照），直接判定，不问偏好。不可判的（现网 DNP3 设备默认口/变体方言）标"待确认"并写清确认方式（G-DNP3-4）。

## 1. 范围、profile 与实现状态边界

本版定义主站（master）与外设（outstation）之间的 **DNP3 over TCP 问答帧序列**：链路层帧（`0x0564` 起，10B 帧头 + 每 16B 数据块附 2B CRC）作为 TCP 段载荷按 scenario 顺序回放。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `dnp3_tcp_master_v1`（主） | TCP 明文（fixture 20000，可配置覆盖） | scenario 全表（**16 个 distinct 名**；`scenario.go` 主 switch 15 个 case 行 = 17 个标签〔含多标签行 `multi_object_response`+`respond`、`read_class0`+`read_class123`〕+ 空串缺省臂；三口径关系见 §5「scenario 计数三口径」）+ objects 全形态 + IIN 全位 | 真实 RTU 响应时序、设备轮询周期 |
| `dnp3_tcp_outstation_v1` | 同上，`link_type=outstation` | respond/unsolicited 方向 | 从 master fixture 推导外设行为 |

显式边界（"不实现、不声称、不许静默转换"）：**UDP 传输不在本版**（层链生成器显式拒绝，`layer_gen.go:52`；legacy `Plan` 代码在但扁平入口已判死，§0 表 #7/§0.1 判据 B）；**multi_outstation 多流展开不在本版**（显式拒绝，`layer_gen.go:55`；同上，§0 表 #8）；串行链路（DNP3 serial）不在本版；不声称任何帧与真实 RTU 字节到达时序一致。

**实现状态（2026-09-28 实测）**：`dnp3` 层已注册（`registry.go:253`）、planner/builder/parser/scenario/生成器已落码（`internal/protocol/dnp3/` 八文件共 1468 行）、`allowedProtocols["dnp3"]=true`（`protocols.go:38`）、Meta 直传已接线（`chain_planner_translate.go:77` `DNP3: spec.DNP3`）。**核心缺口：层是空壳**——registry `Fields` 为空（`translate.go:852` 早返使层内配置根本不被解码）+ translate 无 `case "dnp3"`（G-DNP3-1，§0.1）。配置今日只能住**顶层 `dnp3` 子映射**（`strategy_convert.go:1589-1593` `parseDNP3Config` + `setDefaultDstPort 20000`），该形状经 MCP 建策略 **400**（`schema/semantic.go:130` `CheckProtoFlat`；dnp3 无自键分支但通用五键门已拦 `src_ip/dst_ip/src_port`）。**待代码阶段收敛。**

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport/srcport`、`tcp.flags`、offset 54/74 frames；`dnp3.*` 字段今日零断言，tshark 已支持可作 A′ 增强）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, dnp3]`（引擎自动补 `ip`；最小链 `[tcp, dnp3]`）。dnp3 报文是 TCP payload 的**完整链路层帧**——**段边界 = 帧边界**（每帧一段，事件模式）。

端口：DNP3 标准监听口 **TCP 20000**（spec；`strategy_convert.go:1592` `setDefaultDstPort(&spec, cfg, 20000)`；`types.go:5` `DefaultPort = 20000`）。fixture 统一 `dst_port=20000`；用例一律显式写端口并纳入断言（旧 §1.4 纪律继承）。

固定偏移：无 VLAN/IP options/TCP options 时，**每帧首字节起点为 IPv4 offset 54（14+20+20）、IPv6 offset 74**（14+40+20）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers` + `flow_control`；**目标形状声明**：registry `dnp3` Fields 今日为空，层内 `dnp3` 键今日无处可住（V9 报 `unknown field`），故此形**今天跑不通，需先补代码** G-DNP3-1，§1.9 口径）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 20000}},
    {"dnp3": {"link_type": "master", "transport": "tcp",
              "src_addr": 1, "dst_addr": 1024, "scenario": "reset_link"}}
  ],
  "flow_control": {"flows": 1}
}
```

多流样例（数量只走 `flow_control`，四元组留空走 worker 保底递增 §12.12）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"dst_port": 20000}},
    {"dnp3": {"link_type": "master", "scenario": "read_class0"}}
  ],
  "flow_control": {"flows": 3}
}
```

## 3. 线格式编码（逐项标注出处）

### 3.1 链路层帧（spec §2.1；`builder.go:47-66`）

帧 = 10B 帧头 + 数据块（每 16B 附 2B CRC）：

| 偏移 | 字段 | 长度 | 说明 |
|---|---|---|---|
| 0 | Start1 | 1 | 固定 `0x05`（`types.go:9`） |
| 1 | Start2 | 1 | 固定 `0x64`（`types.go:10`） |
| 2 | Length | 1 | 数据块总长（含每块 2B CRC），范围 0~255；帧长 = 10 + Length |
| 3 | Control | 1 | DIR/PRM/FCB/FCV/FC（§3.2） |
| 4-5 | DstAddr | 2（小端） | 目的链路地址；`0xFFFF` = 广播 |
| 6-7 | SrcAddr | 2（小端） | 源链路地址 |
| 8-9 | Header CRC | 2（小端） | 帧头前 8 字节的 CRC16/DNP |
| 10+ | Data Blocks | Length | 每 16B 一块 + 2B CRC16/DNP（块 CRC 独立计算，`builder.go:57-64`） |

**总长度公式**：`帧长 = 10 + (data_len + 2*ceil(data_len/16))`（`builder.go:48` `blocksLen := len(data)+2*((len(data)+15)/16)`）；`blocksLen > 255` 拒绝（`builder.go:49-51`，`MaxLinkLength=255`）。

**CRC16/DNP**（spec §2.8；`builder.go:12-25`）：poly `0x3D65`（reflected `0xA6BC`）、init `0x0000`、refin/refout true、xorout `0xFFFF`；查表法等价实现为逐位反射。

**帧最小长度**：真实 User Data 帧数据区 ≥ 5B（`tr(1)+app_ctl(1)+func(1)+≥1B`），否则 tshark 报 `Malformed Packet: DNP 3.0`；实现补 0 至 4B（`scenario.go:21-26` `padApp`），reset 帧携带 3 字节全零用户数据（`scenario.go:41` `resetPad`）。

### 3.2 控制字节（spec §2.2；`builder.go:28-35`）

```
  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
|DIR|PRM|FCB|FCV|  FunctionCode |
+---+---+---+---+---+---+---+---+
```

| 位 | 字段 | 说明 |
|---|---|---|
| 7 | DIR | 1 = 主站→外设；0 = 外设→主站 |
| 6 | PRM | 1 = 主站消息（发起方）；0 = 外设消息（响应方） |
| 5 | FCB | 帧计数位，每次新帧翻转（仅 FCV=1 时有效） |
| 4 | FCV | 1 = FCB 有效；0 = 忽略 FCB |
| 3-0 | FunctionCode | 链路层功能码（4 位） |

### 3.3 链路层功能码（spec §2.3；`types.go:17-25`）

**主站→外设（PRM=1）**：0 Reset Link State / 1 Reset User Process / 2 Test Link State / 3 User Data Confirm / 4 User Data No Confirm / 9 Request Link Status。
**外设→主站（PRM=0）**：0 ACK / 1 NACK / 2 Link Status / 3 User Data Confirm / 4 User Data No Confirm / 5-10 Reserved / 11 Not Supported。

Validate 拒绝 `link_fc > 11`（`dnp3.go:27`，`dnp3: link_fc out of range [0..11]`）。

### 3.4 应用层帧（spec §2.4；`builder.go:69-79`）

```
+------+------+-----------------------------+
| AC   | FC   | Object Headers + Data       |
+------+------+-----------------------------+
  1B     1B     variable
```

**响应类功能码（`0x81` Respond / `0x82` Unsolicited Respond）在 FC 后紧跟 2B IIN**（大端，`builder.go:71-72`）。

**应用控制字节 AC**（spec §2.4.2；`builder.go:38-44`）：`FIR(7) FIN(6) CON(5) AppSeq(4-0)`。

**IIN 位定义**（spec §2.4.3；`scenario.go:109-111` `effectiveIIN`）：字节 1（高）BROADCAST 0x8000 / Class1 0x4000 / Class2 0x2000 / Class3 0x1000 / NeedTime 0x0800 / LocalControl 0x0400 / DeviceTrouble 0x0200 / DeviceRestart 0x0100；字节 2（低）ConfigCorrupt 0x80 / FuncNotSupported 0x40 / ObjectUnknown 0x20 / ParameterError 0x10 / EventBufferOverflow 0x08 / AlreadyExecuting 0x04。shorthand 布尔位与 `iin` 原始值按位或（`scenario.go:110`）。

### 3.5 应用层功能码（spec §2.5；`types.go:28-66`）

请求：1 Read / 2 Write / 3 Select / 4 Operate / 5 Direct Operate / 6 Direct Operate No Ack / 7 Freeze / 8 Freeze No Ack / 9 Freeze Clear / 10 Freeze Clear No Ack / 20 Enable Unsolicited / 21 Disable Unsolicited / 22 Assign Class / 23 Delay Measurement / 24 Record Current Time / 13 Cold Restart / 14 Warm Restart / 131 Initialize Data / 132 Initialize Application。
响应：`0x81` Respond / `0x82` Unsolicited Respond / `0x00` Confirm。

Validate：`app_func` 字符串必须在 `appFunctions` 表内（`types.go:53-66`，22 项）；`app_func_code == 31` 或 `215` 拒绝（Reserved，`dnp3.go:31-32`）。

### 3.6 对象头（spec §2.6；`builder.go:81-106`）

```
+--------+--------+--------+--------+
| ObjType| Var    |Qualifier| Range  |
+--------+--------+--------+--------+
  1B       1B       1B      0/1/2/4/5B
```

| Qualifier | 含义 | Range 长度 |
|---|---|---|
| 0x00 | 8-bit start/stop index | 2B（各 1B；越 255 拒，`builder.go:87`） |
| 0x01 | 16-bit start/stop index | 4B（小端） |
| 0x06 | all objects（仅 read） | 0B |
| 0x07 | 8-bit count | 1B（>255 拒，`builder.go:96`） |
| 0x08 | 16-bit count | 2B（小端） |
| 0x17 | 8-bit count + 1B index/obj | 1B count + N×1B |
| 0x28 | 16-bit count + 2B index/obj | 2B count + N×2B |

Validate 白名单：仅 `0/1/6/7/8/0x17/0x28` 合法（`dnp3.go:34`）；`qualifier 0x00` 索引 > 255 拒（`dnp3.go:36`）；`qualifier 0x17` 点索引 > 255 拒（`dnp3.go:37`）。

**Variation=0 语义**（spec §2.7）：请求帧可填 0 = "任意变体"；**响应帧必须填具体值**（`dnp3.go:39` `response frame must use concrete Variation, not 0`）。Object 20 仅 Variation 1/2（`dnp3.go:38`）。

### 3.7 对象编码宽度（spec §2.7；`builder.go:137-162`）

| Object | Variation | 编码 |
|---|---|---|
| 1/2 | 1 | 8 点打包 1 字节（`builder.go:118-124`） |
| 12 | 1 | CROB 6B（code/count/ontime/offtime）+ 响应回显 1B Status（`builder.go:140-145`） |
| 10 | any | flag(1B) + value(1B) |
| 20/21/30/40 | 1 / 2 / 3,5 / 6 | flag + uint32 / uint16 / float32 / float64（小端） |
| 50 | any | 6B 48 位毫秒时间 |
| 其他 | any | 单字节 value |

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置是剧本（`scenario` 选一套问答模板 + `objects` 声明读/写哪些点），引擎按序产出帧事件，tcp 层按帧分段并补握手挥手。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 建链复位 | Reset Link → ACK | T21（`dnp3_t21_reset_link`） |
| ② Class 0 全量轮询 | Reset → Read 60.1 → ACK → Respond → ACK | T22（`dnp3_t22_read_class0`） |
| ③ Class 1/2/3 事件轮询 | Read 60.2/60.3/60.4 | T17（`dnp3_t17_read_class123`） |
| ④ SBO 控制（选前操作） | Select 12.1 → ACK → Respond → Operate 12.1（同 FCB） | T23（`dnp3_t23_select_operate`） |
| ⑤ 直接控制 | Direct Operate 12.1 | T24（`dnp3_t24_direct_operate`） |
| ⑥ 事件主动上报 | Unsolicited Respond 0x82 → Confirm 0x00 | T25（`dnp3_t25_unsolicited`） |
| ⑦ 计数器冻结 | Freeze / Freeze Clear 20.1 | T72/T64（`dnp3_t72_freeze_clear_var1` / `dnp3_t64_freeze_clear_con0`） |
| ⑧ 设备重启 | Cold/Warm Restart → Respond 51.1 | T26（`dnp3_t26_cold_restart`） |
| ⑨ 单点写入 | Write 80.1（Internal Indications） | `dnp3_write_single_80_1` |

**五层覆盖逐层结论（存量 70 例两条路径今日均不可执行——层链空壳 + 扁平已判死，§0.1；下列覆盖指"目标契约中已具断言"，非今日可跑）**：功能层——16 scenario 全表每类正例（T21-T26/T17/T72/T64/T35/T45/T71/T78/T68 等）+ 拒绝分支（存量 20 负例 + 目标 4 类）；性能层——多块帧跨 16B 块边界（T14/T15 块 16/17 字节 CRC 独立）、最小帧（T80 空数据 10B）、长度字节覆盖（T43/T44/T47 malformed_length）；数据场景层——IIN 14 位中 13 位有例（T48/T49/T50/T51/T52/T53/T54/T37；**`iin_device_restart` 零用例**，G-DNP3-13）、qualifier 全 7 值（T69 系列）、variation 边界（T70/T71/T73）、CRC 篡改（T36）、FC 保留值（T74/T75）；地址与流层——v4 全正例、**v6 今日零用例（G-DNP3-3）**、单流基线、多流走 `flow_control`（G-DNP3-1）；**流关联（控制流派生数据流）显式不适用**：单 TCP 连接承载全部问答帧，无副连接；**多流（会话内并发流）显式不适用**：单连接串行问答，多会话语义由 `flow_control flows` 承载。业务层——轮询问答链（reset→read→respond 多事务，T22 六帧）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① `think_time` 帧间停顿（字段存在，legacy `Plan` 生效，事件面由 ChainPlanner 逐包回填 Timestamp，`layer_gen.go:20-22` 已记 divergence）；② `is_event`/`app_con` 未在 scenario 表驱动的独立分支（字段在册，今日无独立用例，G-DNP3-5）；③ RST 异常中断（框架 tcp 层能力，本层零断言，A′ 补例 G-DNP3-6）。

## 5. 消息/事务模型与状态机

**事务定义**：同一 TCP 连接内一次链路帧交换（request/respond 对）。**多事务** = 一连接内多组交换按序执行：T22（reset 2 帧 + read 4 帧）。

dnp3 层无自有状态（`layer_gen.go:43-67` 纯函数驱动）：握手/seq-ack/挥手/分段全在 tcp 层；dnp3 层是"按 scenario 把帧翻译成事件"的纯函数。**legacy `Plan` 有独立状态机**（`dnp3.go:92-143`，自产握手挥手），层链路径不使用。

| 状态（tcp 层拥有） | dnp3 层动作 | 用例 |
|---|---|---|
| `ESTABLISHED`（数据阶段） | 每个 plannedFrame → `MessageEvent{Up, Bytes}`（`layer_gen.go:61-65`） | 全正例 |
| 终止（FIN 四包 / RST） | 事件流关闭 → tcp 层挥手；RST 为框架能力 | 全正例 FIN；RST → G-DNP3-6 |

**多会话展开**：多会话语义由策略级 `flow_control {"flows": N}` 表达（worker 递增 `src_port`）；`multi_outstation` 层链显式拒绝（`layer_gen.go:55`）→ 转负例。

**scenario 计数三口径（避免混用）**：① **16 个 distinct 名**（`grep -oE 'case [^:]*:' scenario.go | grep -oE '"[^"]*"' | grep -v '^""$' | sort -u | wc -l` = 16；**全文件范围**，排除空串缺省臂；与主 switch 口径同值）；② **主 switch 15 个 case 行**（`scenario.go:60-91`，多标签行按行计）；③ **主 switch 17 个标签**（多标签行拆分后；含空串缺省臂 1 个）。全文"16 项"一律指口径 ①。

**自动派生规则**：① `scenario` 缺省 → `exchange(AppRead, ...)`（`scenario.go:87-89`，等价 read）；② `objects` 缺省 → `defaultObjects(scenario)`（`scenario.go:94-102`）；③ TCP 握手/FIN 由 tcp 层自动补；④ 广播（`dst_addr=0xFFFF`）与 No-Ack 类 FC 不产 ACK/Respond（`scenario.go:52`）；⑤ `isResponse` 判定的响应类 scenario 走 `respond()`（`scenario.go:62-64`）。

**SBO FCB 不变量**：Select 与 Operate 必须用相同 FCB 位——`scenario.go:65-69` 保存 `savedFCB` 并在两次 exchange 间复位（`dnp3_test.go:124` `TestSelectOperatePreservesFCBBit` 守卫）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流全链 ≤ 3 握手 + N 帧 + 4 挥手；scenario 帧数上界受对象数约束（单帧数据区 ≤ 255B，`MaxLinkLength=255`）；多流 N 流顺序展开。吞吐数字待 P4 基准，**本版不写承诺**（§6.5）。
- **依据**：帧序列一次性展开（`scenarioFrames` 返回 `[]plannedFrame`，逐帧 emit，`layer_gen.go:57-66`）；每帧内存 = 帧长（≤265B）+ TCP 段开销（O(帧)）；无跨流共享状态；无锁（常量只读）。**诚实声明**：`drive()` 全量收集包序列于内存（`chain_planner_translate.go:37-40` 注释），帧级内存仍为 O(帧×流)。
- **验收两路**：pcap（`/tmp/mcp-pcaps/dnp3/`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `tcp.*` 字段与帧 hex（offset 54 的 `05 64` 起始 + 长度/控制/地址字节），不只断言"任务没报错"。
- **六类场景落点（目标契约；存量两条路径今日均不可执行，§0.1）**：基线（T21，9 包）/ 目标规模（T22，13 包）/ 压力上限（T14/T15 跨块 CRC）/ 长时间运行（多流展开）/ 并发交错（顺序多流承载语义，并发路径为例外不启用）/ 背压（`packet_count` 精确计数守卫帧数漂移）。**层链侧六类场景待代码阶段重测**（G-DNP3-1）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 planner/validator/生成器拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功：

| # | 负例 ID | 故障输入 | `error_contains` 锚词 |
|---:|---|---|---|
| N-1 | `dnp3_t4_invalid_link_type` | `link_type="slave"` | `link_type` |
| N-2 | `dnp3_t5_invalid_transport` | `transport="sctp"` | `transport` |
| N-3 | `dnp3_t6_invalid_app_func` | `app_func="foobar"` | `invalid app_func` |
| N-4 | `dnp3_t7_appseq_overflow` | `app_seq=16` | `app_seq` |
| N-5 | `dnp3_t8_broadcast_confirm` | `dst_addr=0xFFFF` + `confirm_required=true` | `broadcast cannot require confirm` |
| N-6 | `dnp3_t40_link_fc_overflow` | `link_fc=12` | `link_fc` |
| N-7 | `dnp3_t9_multi_zero_count` | `outstation_count=0` | `outstation_count` |
| N-8 | `dnp3_t10_multi_iplist_mismatch` | `ip_list` 长度 ≠ count | `outstation_ip_list` |
| N-9 | `dnp3_t57_multi_no_ip` | `count>1` 且无 IP | `outstation_ip` |
| N-10 | `dnp3_t58_multi_port_zero` | `src_port_start=0` | `src_port_start` |
| N-11 | `dnp3_t59_multi_port_overflow` | `src_port_start+count-1 > 65535` | `exceeds 65535` |
| N-12 | `dnp3_t55_iin_out_of_range` | `iin > 65535` | `iin` |
| N-13 | `dnp3_t66_crob_request_status_rejected` | CROB 请求带 `status` | `Status` |
| N-14 | `dnp3_t69_qualifier9_rejected` | `qualifier=9` | `qualifier` |
| N-15 | `dnp3_t69b_qualifier0_index_overflow` | `qualifier=0` 索引 > 255 | `index` |
| N-16 | `dnp3_t69c_qualifier17_point_index_overflow` | `qualifier=0x17` 点索引 > 255 | `index` |
| N-17 | `dnp3_t70_response_var0_rejected` | 响应帧 `variation=0` | `Variation` |
| N-18 | `dnp3_t73_counter_var3_rejected` | Object 20 `variation=3` | `variation` |
| N-19 | `dnp3_t74_fc31_reserved_rejected` | `app_func_code=31` | `FC=31` |
| N-20 | `dnp3_t75_fc215_reserved_rejected` | `app_func_code=215` | `FC=215` |
| N-21 | `dnp3_t27_udp_transport` | `transport="udp"`（层链） | `transport=udp is not supported on the layer chain` |
| N-22 | `dnp3_t31_multi_outstation_3` 等 8 例 | `multi_outstation`（层链） | `multi_outstation is not supported on the layer chain` |
| N-23 | `dnp3_neg_presence`（**待代码阶段建例**） | 层链 + 顶层空 `dnp3` 子映射并存 | `no longer accepts a top-level dnp3 sub-config` |
| N-24 | `dnp3_neg_stray_src_ip`（**待代码阶段建例**） | 层链 + 顶层 `src_ip` | `no longer accepts flat config field src_ip` |

**负例原子性**：每例单一故障注入；单次执行不得混注。**N-1…N-20 为存量已落地负例**（`cases/dnp3.json` 20 例，其中 T6/T8 锚词为空须补正，G-DNP3-9）；**N-21/N-22 为层链能力边界**（诚实边界传导，§1；存量 T27 与 8 例 multi 今日**两条路径均不可执行**——扁平入口已判死、层链生成器显式拒绝，故今日既非正例也非红例，G-DNP3-11）；**N-23/N-24 待代码阶段建例**（G-DNP3-2）。

**不得误报的合法协议事件**：`dst_addr=0xFFFF` 广播（T34 正例，仅 reject confirm 组合）；`link_fc` 0-11 全值（T39 正例）；`variation=0` 请求帧（T71 正例）；IIN 全位组合（T53 正例）。

## 8. 边界

- **帧长与块**：数据区 16B 整块边界（T14）、17B 跨块（T15）；`Length` 字节篡改（T43=0 / T47=200）；帧上界 265B（`MaxLinkLength=255`）。
- **CRC**：帧头 CRC 独立于块 CRC；`malformed_crc` 翻转末字节（T36）。
- **方向**：`link_type` 决定默认帧方向；`unsolicited` 要求 outstation（`dnp3.go:29`）。
- **地址族**：v4 全正例；**v6 今日零用例 → A′ 补例（G-DNP3-3）**。
- **端口**：显式 20000 全正例；缺省 20000（`strategy_convert.go:1592` 补齐）。
- **多外设**：层链拒绝（`layer_gen.go:55`）；legacy `Plan` 代码在但扁平入口已判死（§0.1 判据 B）——存量 8 例今日不可执行（G-DNP3-11）。
- **UDP**：层链拒绝（`layer_gen.go:52`）；legacy `Plan` 代码在但扁平入口已判死（§0.1 判据 B）——存量 T27 今日不可执行（G-DNP3-11）。
- **`is_event`/`app_con`/`think_time`**：字段在册但无独立 scenario 分支 → **明确不解决**（G-DNP3-5；用例不得携带）。
- 不得产生回绕长度或超量分配（帧长显式声明，不隐式放大）。

## 9. 原子 ID 与完成定义（存量 70 个唯一语义 ID；目标契约见 testcase §2）

**存量（`cases/dnp3.json`，本版未改）**：70 ID = 50 正 + 20 负，顺序为权威；`packet_count`/`min_packets` 与锚词为**历史实测值**（旧版本遗留；两条路径今日均不可执行，§0.1）。**存量形态 = 扁平过渡态**（顶层四元组 + 顶层 dnp3 子映射 + 空壳 layers 并存，判死形状，**cases 本版未改**）。**目标契约（合规化属代码阶段）**：testcase §2 给出 72 ID 目标集（41 正 + 31 负），其中 9 例 legacy 正例在层链路径为能力边界（须重判）、2 例判死负例新增。

完成定义（**代码阶段**）：`tcp→dnp3` 层链内化（registry Fields + translate 分支）；16 scenario 逐项生成验证；IIN/qualifier/variation 边界全可观测；**目标契约** 72 ID 正负断言与错误传播完成；不声称 RTU 时序。**本版为文档阶段，完成定义不适用**（§8.2 文档阶段定位）。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | 主站主动建连（TCP Server），单连接承载问答帧（spec §4） | 场景①–⑨ | `DependsOn ["tcp"]` 单值（`registry.go:253`） | 无 |
| 2 | 命令/消息表 | 16 scenario × 应用 FC 22 项（§3.5） | 场景①–⑨ | `scenarioFrames` 全分支（`scenario.go:60-91`）+ `appFunctions` 表（`types.go:53`） | 无（`is_event`/`app_con` 见 G-DNP3-5） |
| 3 | 状态机 | 建链—数据—释放 3 态（§5 表） | T22 多事务 | tcp 层拥有状态；dnp3 纯驱动 | 无 |
| 4 | 字段表 | `DNP3Config` 39 键（§3；`types.go:3458`） | 数据场景层 | builder 直传 + 长度/qualifier/变体校验 | 无 |
| 5 | 错误处理 | 24 类负例（§7 表） | 存量 20 负例 + 目标 4 类 | planner 23 种拒绝分支 + 生成器 2 种 + 门 2 种 | 存量 20 已落地（T6/T8 锚词空，G-DNP3-9）；N-23/N-24 待建（G-DNP3-2） |
| 6 | 超时与活性 | DNP3 有链路层重传/Test Link（spec §2.3） | — | 协议层无（重传为框架能力，本层零断言） | **显式不适用**（§4 声明），无缺口 |
| 7 | NAT/代理/被动 | 无被动模式概念（主站直连外设） | 多流走 `flow_control` | `multi_outstation` 层链拒绝（`layer_gen.go:55`） | **显式不适用**被动模式；多外设见 G-DNP3-1 |
| 8 | 版本/方言 | IEEE 1815-2012 唯一 profile；UDP/serial/multi 明确不解决 | 正例 41 | 缺省 20000 已落码（`:1592`） | 现网设备方言实证 → G-DNP3-4 |

### 10.2 子表①：scenario × 终态矩阵（逐格已覆/立项/不适用）

> **口径声明（本版关键）**：本表"已覆"= **目标契约中已具断言**，**不是今日可跑**。存量 70 例两条路径今日**均不可执行**——层链空壳（§0.1 判据 A）+ 扁平入口已判死（§0.1 判据 B，实测 70/70 400）；离线 suite 亦不收 dnp3（`chainSuiteProtos` 白名单无 dnp3）。**不得将本表"已覆"读作"今日已过"或"层链已过"**（ldp 先例）。

| scenario | T1 正常 FIN 终态 | T2 配置拒绝 | T3 层链能力边界 |
|---|---|---|---|
| reset_link | 已覆（T21） | 已覆（N-1/N-2/N-4 代表） | 待代码阶段（N-22 若带 multi，G-DNP3-11） |
| read_class0 | 已覆（T22） | 已覆（N-6/N-13/N-14/N-15） | 待代码阶段（G-DNP3-11） |
| read_class123 | 已覆（T17） | 已覆（N-16） | 待代码阶段（G-DNP3-11） |
| select_operate | 已覆（T23/T67） | 已覆（N-13） | 待代码阶段（G-DNP3-11） |
| direct_operate | 已覆（T24） | 已覆（N-14/N-15） | 待代码阶段（G-DNP3-11） |
| write_single | 已覆（`dnp3_write_single_80_1`） | 已覆（代表） | 待代码阶段（G-DNP3-11） |
| unsolicited | 已覆（T25） | 已覆（N-5） | 待代码阶段（G-DNP3-11） |
| cold/warm_restart | 已覆（T26） | 已覆（代表） | 待代码阶段（G-DNP3-11） |
| freeze/freeze_clear | 已覆（T72/T64） | 已覆（N-18） | 待代码阶段（G-DNP3-11） |
| enable/disable_unsolicited | **待建**（补例 `dnp3_enable_unsolicited`） | 已覆（代表） | 待代码阶段（G-DNP3-11） |
| assign_class | **待建**（补例 `dnp3_assign_class`） | 已覆（代表） | 待代码阶段（G-DNP3-11） |
| delay_measurement | **待建**（补例 `dnp3_delay_measurement`） | 已覆（代表） | 待代码阶段（G-DNP3-11） |
| respond / multi_object_response | 已覆（T3/T68/T78） | 已覆（N-17） | 待代码阶段（G-DNP3-11） |
| UDP 传输 | 已覆（T27；**层链显式拒绝**） | 已覆（N-2） | **层链不支持**（`layer_gen.go:52`，G-DNP3-11） |
| 多外设展开 | 已覆（8 例；**层链显式拒绝**） | 已覆（N-7…N-11） | **层链不支持**（`layer_gen.go:55`，G-DNP3-11） |

**逐格重数（可复算）**：15 行 × 3 列 = 45 格——**已具断言 27**（T1 列 12 + T2 列 15）+ **待建 3**（T1 列 enable_unsolicited/assign_class/delay_measurement）+ **层链不支持 2**（T3 列 UDP/多外设）+ **待代码阶段 13**（T3 列其余 13 行）= 45。零空格。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **24 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | 帧数据区 16B 整块 | 覆（T14） |
| 2 | 帧数据区 17B 跨块 | 覆（T15） |
| 3 | 帧空数据区（10B 帧） | 覆（T80） |
| 4 | `malformed_length=0` | 覆（T44） |
| 5 | `malformed_length=200` | 覆（T47） |
| 6 | `malformed_crc` 翻转 | 覆（T36） |
| 7 | IIN 单位 shorthand（14 位中 13 位有例；`device_restart` 零用例，G-DNP3-13） | 覆（T48/T49/T50/T51/T52/T37 等） |
| 8 | IIN 全位组合 | 覆（T53） |
| 9 | IIN 原始值 + shorthand 或 | 覆（T54） |
| 10 | IIN 越界（>65535） | 覆（N-12） |
| 11 | qualifier 0x00/0x01/0x06/0x07/0x08/0x17/0x28 全 7 值 | 覆（T22/T17/T69 系列） |
| 12 | qualifier 非法（0x09） | 覆（N-14） |
| 13 | qualifier 0x00 索引越 255 | 覆（N-15） |
| 14 | qualifier 0x17 点索引越 255 | 覆（N-16） |
| 15 | variation=0 请求（合法） | 覆（T71） |
| 16 | variation=0 响应（非法） | 覆（N-17） |
| 17 | Object 20 variation 3（非法） | 覆（N-18） |
| 18 | CROB 请求带 status（非法） | 覆（N-13） |
| 19 | CROB 响应回显 status | 覆（T68） |
| 20 | `link_fc` 0-11 全值 | 覆（T39，`link_fc=2`） |
| 21 | `link_fc=12` 越界 | 覆（N-6） |
| 22 | `link_fcb` 0/1 + 翻转 | 覆（T41/T42） |
| 23 | `app_seq` 0-15 回绕 | 覆（T30） |
| 24 | `app_func_code` 保留值 31/215 | 覆（N-19/N-20） |

**重数**：24 覆 + 0 立项 + 0 不适用 = 24。✓（`is_event`/`app_con`/`think_time` 无独立 wire 形态，见 §8 明确不解决）

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 主站周期轮询（Class 0/1/2/3）（spec §1.4） | T22/T17 | 已具断言（目标契约） |
| 2 | SBO 安全控制（spec §1.4） | T23/T67 | 已具断言（目标契约） |
| 3 | 直接控制（spec §1.4） | T24 | 已具断言（目标契约） |
| 4 | 事件主动上报（spec §1.4） | T25 | 已具断言（目标契约） |
| 5 | 计数器冻结（spec §1.4） | T72/T64 | 已具断言（目标契约） |
| 6 | 设备重启（spec §1.4） | T26 | 已具断言（目标契约） |
| 7 | 多外设轮询（RTU 农场） | 存量 8 例（历史实测值） | **两条路径均不可执行**（层链 `layer_gen.go:55` 拒绝 + 扁平已判死，G-DNP3-11） |
| 8 | UDP 传输 | 存量 T27（历史实测值） | **两条路径均不可执行**（层链 `layer_gen.go:52` 拒绝 + 扁平已判死，G-DNP3-11） |
| 9 | 串行链路 | — | **明确不解决**（v1 范围外） |

6 已具断言（目标契约）+ 2 两条路径均不可执行 + 1 明确不解决 = 9。✓无映射无确认即缺口——本表零缺口（全部待代码阶段重判）。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：①规范原文（IEEE 1815-2012，定"必须是什么"：三层架构、`0x0564` 帧头、每 16B 块 CRC、FC 表、IIN 位）；②商业化软件实际行为（DNP3 主站软件/RTU：轮询周期、SBO 默认、Class 轮询顺序——旧 §1.4 记载；出厂默认口/方言待确认 G-DNP3-4）；③可靠开源实现思路（opendnp3：reset 帧携带 3 字节全零用户数据惯例，`scenario.go:38-41` 注释引用；只借鉴思路）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `dnp3` 终结层（本版；enip/doip 同构先例） | scenario/objects/IIN/qualifier 四事可声明可断言；代价 = 一套终结层（已落码 1468 行） | **采用** |
| B | 直接 tcp 层 + 顶层 payload（旧稿无此方案，反例参照） | 无帧级校验、无 scenario 语义 → 24 负例不可表达 | **否决** |
| C | 与 modbus 合并为"工控族"（同为 SCADA 问答） | modbus 无 CRC 块结构/无链路层/IIN——文法不兼容，合并即错 | **否决** |

## 11. P2 D-DNP3-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 状态说明：实现已落码（`internal/protocol/dnp3/` 八文件），本 P2 条目为 P-PIPE 文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口；P4 在本协议内为"缺口收敛"（§14），不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（§3458-3530 + `:1887`） | `DNP3Config`/`DNP3Object`/`DNP3Point`/`DNP3MultiOutstation` 配置类型 + `FlowSpec.DNP3` 槽位 | —（共享文件） |
| `trafficgen/internal/protocol/dnp3/dnp3.go` | `Planner.Validate`（23 种拒绝）+ legacy `Plan`（握手→scenarioFrames→挥手）+ `isResponse` | 143 |
| `trafficgen/internal/protocol/dnp3/scenario.go` | `scenarioFrames` 纯函数（16 scenario 展开为帧序列）+ `effectiveIIN` | 111 |
| `trafficgen/internal/protocol/dnp3/builder.go` | `CRC16`/`BuildControl`/`BuildAppControl`/`BuildLinkFrame`/`BuildAppFrame`/`encodeObject`/`encodePoint` 纯函数 | 163 |
| `trafficgen/internal/protocol/dnp3/parser.go` | `ParseLinkFrame`/`ParseAppFrame`/`parseObject`（帧边界 + CRC 校验） | 75 |
| `trafficgen/internal/protocol/dnp3/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator("dnp3")` + `RegisterLayerValidator("dnp3")`，`init()`） | 120 |
| `trafficgen/internal/protocol/dnp3/types.go` | 常量 + 链路/应用 FC 表 + `appFunctions` + `CROB`/`LinkFrame`/`AppFrame` | 104 |
| `trafficgen/internal/protocol/dnp3/dnp3_test.go` + `layer_gen_test.go` | 34 个 `Test*`（CRC/builder/Validate/Plan/生成器面） | 314 + 438 |
| 接线 5 件 | registry 注册（`layers/registry.go:253`）/ translate Meta 直传（`chain_planner_translate.go:77`）/ convert 子配置搬运（`strategy_convert.go:1589-1593`）/ protocols 准入（`protocols.go:38`）/ validate 范围门（`validate.go:136`） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`dnp3.go:20`）：`DNP3==nil` 拒绝（`dnp3: config is required`）；link_type/transport/app_seq/link_fcb/link_fc/broadcast-confirm/unsolicited-role/app_func/FC 保留/objects 全字段/qualifier/index/multi_outstation 各归一分支，错误文案与 §7 锚词逐字一致。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`dnp3.go:67`）：先 Validate；`DstPort==0` 补 20000；multi_outstation 展开 M 个独立流；握手 → `scenarioFrames` 逐帧 → 挥手。
- 生成器：`Name() "dnp3"`；`GenEvents()` 事件生成器；`EmitEvent` 未接线显式错（防误调）；`Generate` 逐帧校验 + emit（`layer_gen.go:43-67`）。**生成器拒绝** UDP（`:52`）与 multi_outstation（`:55`）。

### 11.3 数据结构

`DNP3Config{LinkType, Transport, SrcAddr, DstAddr, LinkFCB, LinkFC, AppSeq, AppFunc, AppFuncCode, AppCON, Objects[], Scenario, IsEvent, IsUnsolicited, ConfirmRequired, IIN + 14 IIN 布尔位, MultiOutstation, Handshake, Termination, MSS, ThinkTime, MalformedCRC, MalformedLength, UnknownObject, UnknownFunc}`（`types.go:3458-3499` 全量 39 键，无新增）；`DNP3Object{ObjectType, Variation, Qualifier, IndexRange[2], Count, Points[], Flags[], Times[]}`；`DNP3Point{Value, Index, Status}`；`DNP3MultiOutstation{OutstationCount, OutstationAddrStart, OutstationIPStart, OutstationIPList[], SrcPortStart}`。

### 11.4 主流程

配置 → validator（字段域 20 分支 + 载体 2 分支）→ 生成器（`scenarioFrames` 展开为帧序列，逐帧 emit 事件）→ tcp 层生成器（握手/FIN/MSS 分段）→ worker（多流按 `flows` 复制四元组递增）→ writer（PCAP/NIC）。

### 11.5 错误分支

23 种 validator 拒绝 + 2 种生成器拒绝（UDP/multi_outstation）（§7 表）；全部传 task error（零假成功——N 系列守卫）。`is_event`/`app_con`/`think_time` 今日**不拒绝亦无独立生效面**（G-DNP3-5：用例不得携带）。

### 11.6 性能边界

见 §6（逐帧流式、per-flow 局部状态、无跨流共享、无锁；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- **层内配置今日无处可住**：registry `dnp3` Fields 为空（生成表 `fields: {}` 实测）+ translate **无 `case "dnp3"`**（`grep` 零命中）→ 层内写 `dnp3` 键由 V9 报 `unknown field`（`complete.go:293`）；目标形状（§2）需 P4 补 Fields + translate 分支（G-DNP3-1）。
- `CheckProtoFlat`（`strategy_convert.go:8625` 起，60 分支）**无 dnp3 分支**（`grep -c 'protocol == "dnp3"'` = 0 实测）：顶层 `dnp3` 子映射 presence 不判死——缺口 G-DNP3-2（禁加单协议黑名单分支，等框架级 unknown-key 白名单；kingbase/moxa 记忆裁定）。
- 动态 allowlist（`internal/core/layer_dyn.go:18-21`）：`dnp3` 零命中实测 → 业务字段动态对象即拒；四元组 `ip`/`tcp` 全开。见 §12.12。
- `pipe_gate.sh` 的 presence 红线 `case` 名单（`_pres_key`）今日不含 dnp3 → 门2-1 对 `dnp3_neg_presence` 判**黄**（非红）；P4 须把 dnp3 加入名单（B 车道动作，G-DNP3-2）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 8 文件 + 接线 5 处（registry/protocols/translate/convert/validate）；不触及其他协议。cases 回滚 = 恢复 70 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 70/70 顶层 = `src_ip/dst_ip + dnp3`（41 例另带空壳 layers，13 例另带 `src_port`）；**顶层旧键残留 163 处（非负例口径；全例 223 处）**，本版**未改 JSON**（§0.1 层空壳判据），待代码阶段收敛；presence 判死形状缺口 G-DNP3-2 | §12.1/§0.1；`cases/dnp3.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 dnp3 流量模板，自带 `flow_control`；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（终结层）/时间线。有长连接，不豁免 | §12.3 + §5 |
| §4 查规范 | IEEE 1815-2012 + 旧基线 + tshark `dnp3.*` 实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["tcp"]` 单值（`registry.go:253`）；24 类拒绝分支；失败传 task error | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待 P4 基准，不写承诺） | §6 |
| §7 三份文档 | `95-dnp3-{design,testcase}.md` v1.0.0（草稿层）+ D-DNP3-1（§11，门1 获批 = 定稿）+ T-DNP3（testcase §2：**存量 70 ID 为当前 JSON 集合**，目标契约 72 ID 待代码阶段落地）+ 旧稿 11-* 为历史层 | 修订记录 |
| §8 设计先行 | P1–P3 先于 P4 缺口收敛；门1 获批 = D-DNP3-1 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = IEEE 1815-2012（§10）+ D-DNP3-1（§11）+ tshark `dnp3.*` 实测（替代"已确认现网行为"档，未到抓包级 → G-DNP3-4，不冒充第三源）；存量 70 ID 逐项回指（目标契约 72 ID 待代码阶段落地）；存量 70 例审计去向 testcase §8 | `95-dnp3-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123 报告 §2）+ 收官隔离复审；红先绿后 | p123 报告 §2 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `dnp3` 已在 `registry.go:253` 注册（**不新增层**）；`allowedProtocols["dnp3"]=true`（`protocols.go:38`）；Meta 已直传（`translate.go:77`）；**P4 补 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `tcp.*` + frames 双通道（`dnp3.*` 可选）→ 先跑后钉；pcap 落 `/tmp/mcp-pcaps/dnp3/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-28）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 纯净 |
|---|---|---|---|---|
| `cases/dnp3.json`（**本版未改**） | 70 | `{src_ip,dst_ip,dnp3}` ×57 + 同形+`src_port` ×13 | 41 例带**空壳** `[{tcp:{}},{dnp3:{}}]`；29 例无 layers | 20/20 = `{error_contains,expect_error,notes}`（含 notes，非严格两键） |

**顶层旧键残留实测（非负例口径 = 主口径）= 163 处**（`src_ip` 50 / `dst_ip` 50 / 顶层 `dnp3` 子映射 50 / `src_port` 13）；全例口径 223 处（另含 20 负例的 60 处）。

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` | **70** | 待代码阶段收敛 → `layers[i].ip.src` |
| `dst_ip` | **70** | 待代码阶段收敛 → `layers[i].ip.dst` |
| `src_port` | **13** | 待代码阶段收敛 → `layers[i].tcp.src_port`（或删，走保底递增） |
| `dst_port` | **0** | 本已 absent；代码阶段补显式 20000（缺省由 `strategy_convert.go:1592` 补齐） |
| `count` | **0** | 无 count；数量走 `flow_control` |
| 顶层 `dnp3` 子映射 | **70** | **待代码阶段收敛 → `layers[i].dnp3`**（须先补 registry `Fields` + translate 分支，G-DNP3-1） |
| 空壳 `layers` | **41** | 待代码阶段改写为实层 `[{ip},{tcp},{dnp3}]`（今日改写会撞 V9 `unknown field`） |

**结论**：本协议 §1 门的动作（**全部待代码阶段**）= ①补 registry `Fields`（39 键）+ translate 分支（层内 dnp3→`spec.DNP3`）；②70 例整体改写 + 9 例能力边界重判 + 2 例判死负例新增；③收官自查行「非负例顶层键 = 0」由 **163 → 0**。

**为什么本版不动 JSON**：见 §0.1（层为空壳，照改 = 把绿例改红且新 JSON 仍不可调用）。目标形状样例见 §2（顶层仅 `layers`+`flow_control`，**今日跑不通**）。

### 12-P2 判死负例形状（链级红例必含清单①③④；本版**只登记、不改 JSON**）

- ① presence 形状 `{"layers":[…],"dnp3":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 dnp3 分支，`grep -c` = 0 实测）→ **待代码阶段建例** `dnp3_neg_presence`（补分支后真红）；缺口 G-DNP3-2 登记。② 白名单外游离键判死（`CheckProtoFlat` 通用五键门）→ **待代码阶段建例** `dnp3_neg_stray_src_ip`（该形**今日真红**）。③ 存量 20 负例每条带锚词，**但 2 例锚词为空**（T6/T8，须代码阶段补正，G-DNP3-9）。④ 收官自查「非负例顶层键 = 0」：**今日红**——非负例口径残留 **163 处**，待代码阶段收敛（G-DNP3-10）。

**本版不改 JSON 的理由**见 §0.1（层空壳；照改 = 绿例变红且新 JSON 不可调用）。

### 12.3 §3 强制展开：五件套

会话表：`s1` 单连接基线（T21/T22/T17/T35 等，各自四元组，SYN→帧序列→FIN 四包挥手）/ `s2` 控制会话（T23/T67，Select→Operate 两事务共享 FCB）/ `s3` 多流会话（`flow_control flows=N`，`src_port` 保底递增）。事务：`t1` 建连（握手，tcp 层）/ `t2` 发请求帧（up 事件）/ `t3` 收响应帧（down 事件）/ `t4` 终止（FIN；RST 为 A′）；每事务四件事（前置/触发/成功/失败）见 §5 状态机 + §4 场景表。关联关系：**无派生流**（诚实声明：单 TCP 连接承载全部问答帧，无 `driven_by`；multi_outstation 的 M 流为**并列独立流**非主从派生，且层链拒绝）。插入位置：终结层（`[ip,tcp,dnp3]`，无中间层）。时间线：帧内严格顺序 / 多流顺序展开（整块 per-flow，跨流不假设全局包序，只断言聚合）/ 无交错（`concurrent` 为例外路径不启用）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst`、`tcp.src_port/dst_port` 五策略全开（allowlist `internal/core/layer_dyn.go:18-21` 实测：`ip`/`tcp`/`udp`/`eth`；保底 `DefaultSrcPort+i`）。

**业务字段全关**（allowlist 无 `dnp3` 行，`grep` 零命中实测；对象即拒）：`scenario`（剧本选择器）/ `objects[]`（点表）/ `link_type`/`transport`（角色与载体）/ `src_addr`/`dst_addr`（链路地址）/ IIN 各位（响应状态）/ `multi_outstation`（多外设展开）——逐流变体需求列 A′ 候选（testcase §6.2；今日按 §9.36 口径不冒充覆盖）。

序号算法实读：`parseLayerDyn`（`layer_dyn.go`）/ `TupleGenerator.Next` / 保底自增（`strategy_convert.go` + worker 注入）/ allowlist 白名单（`layer_dyn.go:18-21`）——**`dnp3` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。

## 13. P3 对接清单（T-DNP3 草稿输入；正文落 testcase 文件）

**存量 70 ID**（50 正 + 20 负）逐条去向 + 锚词 + fixture 常量 + 双通道断言基线（testcase §2–§5/§8 全量）；**目标契约 72 ID** 作为代码阶段落地清单（testcase §2）。A′ 候选 5 例：`dnp3_enable_unsolicited`（§10.2）/ `dnp3_assign_class`（§10.2）/ `dnp3_delay_measurement`（§10.2）/ `dnp3_ipv6`（G-DNP3-3）/ `dnp3_abort_rst`（G-DNP3-6）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

> 每条三要素：**现象 / 证据行号 / 归属阶段**。本车道为文档轨，全部缺口归**代码阶段**处置。

| 缺口 | 现象 | 证据 | 归属阶段 / 去向 |
|---|---|---|---|
| **G-DNP3-1** | **层为空壳**：registry 无 Fields + translate 无 case → 层内配置根本不被解码，层内业务键被 V9 拒 `unknown field` | `registry.go:253`（无 Fields）；生成表 `dnp3.fields={}`；`grep 'case "dnp3"'` = 0；`translate.go:852` `if len(s.Fields)==0 { return }`；`complete.go:293` unknown field | **代码阶段首动作**：补 registry Fields（39 键）+ translate `case "dnp3"` + schemagen 重跑 |
| **G-DNP3-2** | `CheckProtoFlat` 无 dnp3 分支 → presence 形（层链 + 顶层空 dnp3）今日不判死；`pipe_gate.sh` `_pres_key` 名单亦无 dnp3 | `grep -c 'protocol == "dnp3"'` = 0（全 60 分支）；`pipe_gate.sh` case 名单逐项核对 | 代码阶段：先实测再建例；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单；kingbase/moxa 裁定） |
| **G-DNP3-3** | IPv6 载体零用例 | 存量 70 例无 IPv6（机读） | A′ 补例 `dnp3_ipv6`（offset 74，先跑后钉） |
| **G-DNP3-4** | 现网 DNP3 设备默认口/变体方言说法未达验证级 | 旧稿 §1.1 记载，无抓包/手册级证据 | 待确认：查 IEEE 1815-2012 附录或抓现网 RTU 包（三选一已写清）；确认前不写死进实现 |
| **G-DNP3-5** | `is_event`/`app_con`/`think_time` 字段存在但无独立 scenario 分支 | `scenario.go` 16 case 无对应分支；`types.go:3471`（`is_event`）/`:3468`（`app_con`）/`:3493`（`think_time`）字段在册 | **明确不解决** + 迁入计划（用例今日不得携带；实现则补驱动/用例） |
| **G-DNP3-6** | RST 非正常结束补例（§3.15②后半） | 存量 70 例零 RST | A′ 补例 `dnp3_abort_rst`（`tcp.rst` 框架能力，本层零断言） |
| **G-DNP3-7** | 业务字段动态全关（allowlist 无 `dnp3` 行） | `layer_dyn.go:18-21` 四行（ip/tcp/udp/eth）；`grep -c dnp3` = 0 | A′ 候选，不冒充已覆盖（§9.36 口径） |
| **G-DNP3-8** | `dnp3.*` tshark 字段（166 个可用）今日零断言——存量断言仅 `tcp.*` + frames | `tshark -G fields` 166 行；存量断言字段机读仅 `tcp.dstport/srcport/flags` | A′ 断言增强（可选，非阻塞）；增强须先跑后钉（§9.31） |
| **G-DNP3-9** | 存量 2 例负例锚词为空（`error_contains=""`）——任何错误均可通过，失去断言力 | `cases/dnp3.json` T6/T8 机读 `error_contains == ""` | 代码阶段：补正为 `invalid app_func` / `broadcast cannot require confirm`（逐字对 `dnp3.go:30`/`:28`） |
| **G-DNP3-10** | 存量顶层旧键残留 **163 处（非负例口径，主口径）**／全例 223 处——判死形状（§1.4/§1.11/§1.13） | 机读：非负例 `src_ip` 50 / `dst_ip` 50 / 顶层 `dnp3` 50 / `src_port` 13 | 待代码阶段收敛（随 G-DNP3-1）；收官自查「非负例顶层键 = 0」**今日红 → 163 → 0** |
| **G-DNP3-11** | 存量 9 例（1 UDP + 8 multi_outstation）**两条路径今日均不可执行**——层链生成器显式拒绝（`layer_gen.go:52`/`:55`），扁平入口已被 `CheckProtoFlat` 判死（§0.1 判据 B）。**注意**：其"层链必红"不再需要论证——它们今日**根本跑不到生成器**（建策略即 400） | `layer_gen.go:52`/`:55`；`semantic.go:130`；存量 T27/T31/T56/T60/T84/T32/T33/T81/T85 机读 | 代码阶段：随 G-DNP3-1 层链内化后按新能力重判（转负例或定形） |
| **G-DNP3-12** | 设计侧锚点缺口：50 个非负例中仅 12 例在 design 文档有落点，38 例只住 testcase §2——"每正例可回指设计"不成立 | 机读：50 非负例 ID 在 `95-dnp3-design.md` 出现 12 个 | 代码阶段随层链内化补设计侧锚点（§8.4 行 12 今日 ✗ 38/50） |
| **G-DNP3-13** | IIN 14 位中 `iin_device_restart` **零用例**（其余 13 位有例或入 T53 全位组合） | 机读：14 位 shorthand 中 13 位在用例出现，`iin_device_restart` 零 | A′ 补例 `dnp3_iin_device_restart`（或并入 T53 全位组合并计）；今日如实标零覆盖 |

## 15. 修订记录

- v1.0.0（2026-09-28）：P-PIPE #95 文档轨 P1–P3。11→95 沿革与 8 项过期校正（§0）；**§0.1 层空壳判据 + 本版不改 cases JSON 的理由**（2026-09-28 主线程裁定）；存量 70 例机读审计（顶层残留 163 处〔非负例口径〕/ 223 处〔全例〕）；§12.1/12.3/12.12 强制展开 + 12-P2（**只登记、不改 JSON**）；D-DNP3-1 as-built 定稿（§11）；缺口 G-DNP3-1…G-DNP3-13（每条三要素：现象/证据/归属阶段）。自审 5 轮，末轮干净（结论见 /tmp/pipe/doc-lanes/dnp3.md）。

# #117 h323（H.323 · ITU-T H.225.0/H.245 多媒体会议信令）设计契约

> 版本：v1.0.0（P-PIPE 文档轨 批次二 · as-built 型）
> 日期：2026-09-29
> 车道：文档轨 #117 h323（分支 `pipe/h323-doc`，基 `300dfc4`）
> 存量用例：`trafficgen/test/protocol_pcap/cases/h323.json`（**17 例 = 11 正 + 6 负**，ID/顺序/包数/断言与本版逐条一致，已机读实测）
> 规范基线：① ITU-T **H.225.0**（RAS 与呼叫信令；Q.931 消息集与 IE 链，下称 **H.225**）；② ITU-T **Q.931**（ISDN 三层呼叫控制：协议鉴别符 / 呼叫参考 / 消息类型 / 信息元素编码）；③ ITU-T **H.245**（媒体控制：终端能力集 TCS / 主从确定 MSD / 逻辑通道 OLC）；④ **RFC 1006**（TPKT：ISO-on-TCP 4 字节包头）；⑤ **RFC 3550**（RTP v2 头）；⑥ 本仓库落码（`internal/protocol/h323/` 三文件 + 接线，§11）；⑦ tshark 3.6.14 `q931.*` 字段表（156 字段）与参考 pcap 实测
> 白话一句：**打视频电话的"接线员"——先按 1720 拨号（TCP 握手），说一句"我要打给你"（SETUP），对方回"知道了、在响铃"（CALL PROCEEDING / ALERTING），中间夹几张"咱们用什么画质"的纸条（FACILITY），接通（CONNECT）后开始传画面（RTP），最后双方互道"挂了啊"（RELEASE COMPLETE）再拆线。另外还有一套"找总机登记"的广播（RAS，UDP 1719）。**

---

## 0. 首次成文声明与"代码注释声称 vs 实测"校正表

**沿革**：`find . -iname "*h323*" -not -path "./.git/*"` 实测——本仓库**没有任何 h323 旧设计稿或旧用例文档**（`docs/protocol-designs/` 下 `ls | grep -i h323` 零命中）。本 #117 是 h323 的**首次成文契约**，不存在"承旧稿/校正旧稿"关系。

**唯一在案的历史层**：
- 实现决策记录 **D-H323-1** 以代码注释形态散落在 `h323.go` / `layer_gen.go` / `registry.go:1335-1340` / `layer_dyn.go:46-49` / `chain_planner_translate.go:1262-1268` / `strategy_convert.go:8938-8943`，本版 §11 将其收敛为 as-built 代码设计条目。
- 结果产物 `trafficgen/docs/protocol-pcap-test/h323.md`（tracked）记 17/17 pass，末次提交 `62376e3`（**2026-09-19**）。**该提交晚于扁平判死提交 `0417be5`（2026-09-13）**，故按批次二任务书口径**不构成"产物过期"缺口**（与 pcep G-PCEP-11 的判定条件相反，结论为"不成立"）；但该文件内 12 条 pcap 相对链接指向的 `trafficgen/docs/protocol-pcap-test/h323/` 目录**不存在（0 个 pcap）**，链接全部失效 → G-H323-12。本车道**未跑**该套件，故不以任何形式引用该产物的 17/17 作为"今日已复跑"依据。

**代码注释声称 vs 实测（逐条机读校正，本版按实测钉）**：

| # | 注释声称（位置） | HEAD 实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | `types.go:5570-5581`：PER 载荷是"从参考 pcap 提取的字节模板"，"FACILITY 携带 [TCS req + TCS Ack + MSD Ack] 于一条消息"，"缺 MSD request"，"1440 字节 SETUP 带 18 个 fastStart OpenLogicalChannel" | `buildQ931Message`（`h323.go:359-388`）构造的 SETUP 为 **29 字节**（TPKT 4 + Q.931 头 5 + Bearer Capability IE 5 + Display IE 15）；`buildBearerCapabilityIE` 恒返回**固定 5 字节** `04 03 90 90 A3`（`h323.go:392-395`）。**无任何 PER 编码、无 h245Control、无 H323-UserInformation、无 fastStart** | **注释是设计意图，代码未落**；本版 §3.2 按代码钉 → **G-H323-1** |
| 2 | `types.go:5593-5595`：RAS "no reference pcap and is **PER-encoded** per H.225.0 §7" | `emitRASSignaling`（`h323.go:514-521`）写死 **8 字节**：`00 <msgType> 00 01 <4B gkIP>`——手写占位，非 ASN.1 PER | **注释与代码相反**；本版 §3.5 按代码钉 → **G-H323-4** |
| 3 | `types.go:5608-5610`：Display IE "a **NUL terminator is appended automatically** (reference \"Administrator\")" | `buildDisplayIE`（`h323.go:402-411`）返回 `{0x28, byte(len(data))} + data`，**不追加 NUL**；用例帧 4 实测尾字节 `…74 6f 72`（`r`），而参考 pcap 帧 4 为 `…74 6f 72 00`（`r\0`） | **注释与代码相反**；本版 §3.2 按代码钉（无 NUL）→ **G-H323-1** |
| 4 | `layer_gen.go:1-6`：legacy planner "**reproducing the reference pcap byte-for-byte**" | 参考 pcap 帧 4 的 SETUP 载荷 = **1440 字节**（TPKT `03 00 05 a0`），实现 = **29 字节**。仅 TPKT/Q.931 包头形状与 10 条消息的**顺序**一致，字节面完全不同 | **"byte-for-byte" 仅指"链驱动对 legacy 输出零改动"，不指复刻参考 pcap**；本版 §3 按实测钉 → **G-H323-1** |
| 5 | `types.go:5611`：`Crv` 注释 "0 = 0x2584 (the reference pcap value). **Multi-call sessions increment it per call**" | `h323.go:286` `callCRV := crv + uint16(callNum)`；用例 `h323_calls_multi` 实测呼叫 1 CRV=0x1000（帧 4）、呼叫 2 CRV=0x1001（帧 20） | **注释正确**（保留） |
| 6 | `types.go:5605-5606`：`RewriteAddr` "rewrites the PER templates' embedded IP/port bytes … to the flow's src/dst addresses" | `grep -n "RewriteAddr" internal/protocol/h323/h323.go` **零命中**——该字段被 translate 写入 `spec.H323`（`chain_planner_translate.go:1300-1301`）后**无任何消费者** | **死配置**；本版 §3.6 诚实声明 → **G-H323-2** |
| 7 | `types.go:5654-5658`：`EndpointType` 是 GRQ/RRQ 的端点类型（terminal/gateway） | `grep -n "EndpointType" internal/protocol/h323/h323.go` **零命中**——parse/validate/translate 三处接线齐全，`emitRASSignaling` 零读取 | **死配置**；本版 §3.5 诚实声明 → **G-H323-3** |

**依赖链判定纪律**：以上均为可判题（注释原文 → 代码行 → 用例帧字节三级对照），直接判定，不问偏好。不可判的（参考 pcap 的 PER 模板逐字段语义、H.245 TCS/MSD 真实编码）标"待确认"并写清确认方式（G-H323-1）。

---

## 1. 范围、profile 与实现状态边界

本版定义 **H.323 呼叫信令三面**的流量生成：呼叫信令面（TPKT + Q.931 over TCP 1720）、RAS 面（H.225.0 §7 over UDP 1719）、媒体面（RTP v2 over UDP）。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `h323_call_v1`（主，`scenario=full`） | TCP 1720（链 `[ip,h323]`，raw-IP 自驱） | TCP 握手 → Q.931 十条（SETUP/CP/FACILITY/ALERTING/FACILITY×3/CONNECT/RELCOMP×2）→ TCP 挥手 | 真实 H.245 能力协商语义 |
| `h323_tunnel_v1`（`scenario=tunnel_only`） | 同上 | TCP 握手 → Q.931 六条（SETUP/CP/ALERTING/CONNECT/RELCOMP×2）→ TCP 挥手 | FACILITY 隧道面（本场景**不发射**任何 FACILITY） |
| `h323_ras_v1`（`scenario=ras_only`） | UDP 1719，**无 TCP** | 4 对 RAS 消息（GRQ→GCF/RRQ→RCF/ARQ→ACF/DRQ→DCF），共 8 包 | 真实网守注册/准入语义 |
| `h323_media_v1`（`scenario=data_only`） | UDP 动态口（fixture 5062→5063），**无 TCP** | `frames` 个 RTP 帧，全 `up` 向 | 真实编解码/时间戳/SSRC 语义 |
| `h323_ipv6_v1` | 同上，仅外层 IPv6（EtherType 0x86DD） | 同 `h323_call_v1` | 从 IPv4 fixture 推导 IPv6 地址 |

**显式边界（"不实现、不声称、不许静默转换"）**：
1. **不实现 H.245 媒体控制**——FACILITY（0x62）消息只带 TPKT + Q.931 头 + Bearer Capability IE + Display IE，**不携带任何 H.245 PER 载荷**（`h245Control` / `H323-UserInformation` / TCS / MSD / OLC 全部未落码，§3.2、G-H323-1）；
2. **不实现真实 RAS PER 编码**——8 字节手写占位（§3.5、G-H323-4）；
3. **不实现 `rewrite_addr`**——键存在、被解析、被写入 spec，但无消费者（G-H323-2）；
4. **不实现 `ras.endpoint_type`**——同上（G-H323-3）；
5. **不实现 `full`/`tunnel_only` 场景下的 RAS 发射**——`ras.enabled=true` 在非 `ras_only` 场景被静默忽略（G-H323-5）；
6. **不实现真实 TCP 选项协商**——SYN 恒带 MSS/WinScale/SACK-Permit 三选项（`synOptions`，`h323.go:563-572`），WinScale 恒 0x07，WindowSize 恒 65535；
7. **不实现 RTP 时间戳/SSRC**——恒 0；序列号恒等于帧序号 `i`（`h323.go:438-446`）；
8. **不声称**多呼叫（`calls>1`）是并发——实现为**整块顺序回放**（§5.3）。

**实现状态（2026-09-29 实测）**：
- `h323` 层已注册：`registry.go:1341`，`CategoryTerminal`，`DependsOn ["ip"]`，**Fields 10 键**（`role`/`scenario`/`crv`/`display_name`/`calls`/`rewrite_addr`/`src_port`/`dst_port`/`media`/`ras`），**无 `Default`**（决策 F：缺省语义在 translate 镜像 parse，§3.7）；
- planner / 层生成器已落码：`internal/protocol/h323/h323.go` **598 行** + `layer_gen.go` **77 行** + `h323_test.go` **826 行 / 30 个 `Test*`**（`grep -c ''` / `grep -c "^func Test"` 实测）；
- 协议白名单：`protocols.go:41` `"h323": true`；
- 平面接线：`strategy_convert.go:1363` `case "h323"`（顶层子映射 → `spec.H323`）+ `setDefaultDstPort(…, 1720)`（`:1371`）；`strategy_convert.go:8940` 顶层 `h323` 子映射 presence 判死；
- 层内接线：`chain_planner_translate.go:1262` `case "h323"`（层 config 逐键 → `spec.H323`）；
- raw-IP 路由：`chain_planner_util.go:40` `isRawIPChain`，`:54` switch 含 `"h323"`；
- 端口语义：`chain_planner.go:758` 端口白名单含 `h323`；`:996` 源端口 0 保持 0（不在 base 检查期默认化）；
- 层动态：`layer_dyn.go:48` `"h323": {"src_port": true, "dst_port": true}`；`layer_dyn.go:806-815` H323 端口逐流落 spec；
- 17 例已落 `cases/h323.json`。

**输出契约（pcap / NIC 双输出）**：两路径共用同一 cases JSON 与同一断言集（`tcp.flags` / `tcp.dstport` / `tcp.srcport` / `ip.src` / `ip.dst` / `ipv6.src` / `ipv6.dst` / `q931.message_type` / `udp.srcport` / `udp.dstport` / `frame.len` 字段 + offset 54 的 frames 原始字节）；NIC 经 tcpdump 捕获（用例级 `nic_capture` 开关）；**不设仅单路径可用的断言**。

---

## 2. 协议栈、端口和固定偏移

**推荐层链 `[ip, h323]`**（引擎自动补 `ip`；最小链 `[ip, h323]` 即全部）。h323 是 **raw-IP 自驱终结层**：链内**没有** `tcp`/`udp` 层，TCP/UDP 头与握手挥手全部由 h323 生成器自己产出（`isRawIPChain`，`chain_planner_util.go:40-60`）。这与 `[ip,tcp,opcua]`（事件面、传输层托管握手）是**两类不同的链形态**。

**端口**：

| 面 | 端口 | 来源 |
|---|---|---|
| 呼叫信令 | TCP **1720**（`DefaultPort`，`h323.go:50`） | `dst_port` 缺席 → 1720（`chain_planner_translate.go` 镜像 `setDefaultDstPort`，`strategy_convert_helpers.go:41`） |
| RAS | UDP **1719**（`emitRASSignaling` 缺省，`h323.go:479-481`） | `ras.port` 0 → 1719；`ras.gatekeeper_ip` 空 → `spec.DstIP` |
| RTP 媒体 | UDP **5062 → 5063**（fixture，`h323.go:423-430`） | `media.src_port`/`media.dst_port` 0 → 5062/5063 |

**固定偏移（无 VLAN / 无 IP options / 无 TCP options 时）**：

- 呼叫信令帧：**TPKT 起点 = IPv4 offset 54**（14 以太 + 20 IP + 20 TCP）、**IPv6 offset 74**（14 + 40 + 20）；
- RAS / RTP 帧（UDP，8 字节头）：**载荷起点 = IPv4 offset 42**（14 + 20 + 8）、**IPv6 offset 62**（14 + 40 + 8）。

**目标形状 spec_json 样例（严格层链形，顶层仅 `layers`）**：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"h323": {"src_port": 12345, "dst_port": 1720}}
  ]
}
```

**多流样例（数量只走 `flow_control`；端口用层内动态对象）**：

```json
{
  "layers": [
    {"ip": {"src": {"strategy": "inc", "range": ["10.0.1.1", "10.0.1.2"], "step": 1}, "dst": "20.0.0.1"}},
    {"h323": {"src_port": {"strategy": "inc", "range": [30000, 30001], "step": 1}, "dst_port": 1720}}
  ],
  "flow_control": {"flows": 2}
}
```

---

## 3. 线格式编码（逐字节，按代码钉）

### 3.1 TPKT 头（4 字节，RFC 1006 §6；`buildQ931Message`，`h323.go:378-387`）

| 偏移 | 字段 | 尺寸 | 端序 | 本实现取值 |
|---|---|---|---|---|
| 0 | Version | 1 | — | `0x03`（`TPKTVersion`，`h323.go:62`） |
| 1 | Reserved | 1 | — | `0x00` |
| 2 | Length 高字节 | 1 | **大端** | `byte(tpktLen >> 8)` |
| 3 | Length 低字节 | 1 | **大端** | `byte(tpktLen & 0xFF)` |

**长度公式**：`tpktLen = 4 + len(q931)`（`h323.go:379`），即 TPKT 长度**含自身 4 字节头**（RFC 1006 语义）。**上界**：`q931` 最长 = 5 + 5 + 2 + 253 = 265，故 `tpktLen ≤ 269`，远低于 2 字节上限 65535，**无溢出分支**。

### 3.2 Q.931 消息（`buildQ931Message`，`h323.go:359-388`）

| 偏移（相对 TPKT 头之后） | 字段 | 尺寸 | 取值 |
|---|---|---|---|
| 0 | Protocol Discriminator | 1 | `0x08`（`Q931PD`，`h323.go:65`） |
| 1 | Call Reference Length | 1 | `0x02`（`CRVLength`，`h323.go:68`） |
| 2-3 | Call Reference Value | 2 **大端** | `crvVal`（bit15 = 方向标志，§3.3） |
| 4 | Message Type | 1 | 见下表 |
| 5… | Information Elements | 变长 | Bearer Capability IE（仅 SETUP/CONNECT）+ Display IE |

**消息类型表**（`h323.go:76-81`；`h323.go:317-343` 的发射顺序）：

| 消息 | 值 | 方向（role=caller） | full | tunnel_only | 带 Bearer Capability IE |
|---|---|:---:|:---:|:---:|:---:|
| ALERTING | `0x01` | down | ✓（第 4 条） | ✓（第 3 条） | ✗ |
| CALL PROCEEDING | `0x02` | down | ✓（第 2 条） | ✓（第 2 条） | ✗ |
| SETUP | `0x05` | up | ✓（第 1 条） | ✓（第 1 条） | **✓** |
| CONNECT | `0x07` | down | ✓（第 8 条） | ✓（第 4 条） | **✓** |
| RELEASE COMPLETE | `0x5A` | 双向各一 | ✓（第 9/10 条） | ✓（第 5/6 条） | ✗ |
| FACILITY | `0x62` | 交替 | ✓（第 3/5/6/7 条，**共 4 条**） | **✗ 不发射** | ✗ |

**信息元素 ①：Bearer Capability IE**（`buildBearerCapabilityIE`，`h323.go:392-395`）

恒返回**固定 5 字节** `04 03 90 90 A3`：

| 偏移 | 字段 | 值 | 语义 |
|---|---|---|---|
| 0 | IEI | `0x04` | Bearer Capability |
| 1 | Length | `0x03` | 后续 3 字节 |
| 2 | Coding standard / Info transfer capability | `0x90` | CCITT，3.1 kHz audio |
| 3 | Transfer mode / Info transfer rate | `0x90` | 电路模式，64 kbit/s |
| 4 | Layer 1 protocol / User info | `0xA3` | G.711 A-law |

**仅 SETUP 与 CONNECT 携带**（`h323.go:369-371`，条件 `msgType == MsgTypeSetup || msgType == MsgTypeConnect`）。

**信息元素 ②：Display IE**（`buildDisplayIE`，`h323.go:402-411`）

| 偏移 | 字段 | 尺寸 | 取值 |
|---|---|---|---|
| 0 | IEI | 1 | `0x28`（Display） |
| 1 | Length | 1 | `len(data)`（IA5 字节数） |
| 2… | Content | `len(data)` | IA5（ASCII）原始字节，**无 NUL 终止符** |

- **编码 = IA5/ASCII**（`h323.go:404` 注释：早期用 UTF-16BE 导致 Wireshark 报 "Trailing stray characters"，因 Q.931 dissector 把首个 `0x00` 当字符串终止符）；
- **截断**：`len(data) > 253` 时截为 253（`h323.go:405-407`）——因长度字段 1 字节、IEI+长度占 2 字节，255 − 2 = 253；
- **仅当 `displayName != ""` 时携带**（`h323.go:374-376`）；
- **校正**：`types.go:5608` 注释称"自动追加 NUL 终止符"，**与代码相反**（实测帧 4 尾字节 `…74 6f 72`，无 `00`）→ §0 表 #3。

**逐消息总长度公式**（`L = TPKT 长度`，`D = min(len(display_name), 253)`）：

```
L(SETUP)   = L(CONNECT) = 4 + 5 + 5 + [2 + D if D>0 else 0]
L(其余消息)              = 4 + 5     + [2 + D if D>0 else 0]
```

**以太帧长度**（呼叫信令，PSH-ACK 无 TCP 选项）：

```
frame.len = 14 + 20 + 20 + L   (IPv4)  = 54 + L
frame.len = 14 + 40 + 20 + L   (IPv6)  = 74 + L
```

**实测复核（用例帧断言 + 算术双证）**：

| 用例 | 帧 | display_name | D | L | frame.len | 实测断言 |
|---|---:|---|---:|---:|---:|---|
| `h323_smoke_01` | 4（SETUP） | `Administrator` | 13 | 4+5+5+15 = **29** | **83** | `frame.len` 断言集无，但帧 hex 前缀 `03 00 00 1d …`（0x1d=29）✓ |
| `h323_smoke_01` | 11（CONNECT） | `Administrator` | 13 | **29** | **83** | 帧 hex `03 00 00 1d 08 02 a5 84 07`（9B 前缀）✓ |
| `h323_smoke_01` | 12（RELCOMP） | `Administrator` | 13 | 4+5+15 = **24** | **78** | 帧 hex `03 00 00 18 …`（0x18=24）✓ |
| `h323_calls_multi` | 4（SETUP） | `t-h323-11` | 9 | 4+5+5+11 = **25** | **79** | `frame.len=79` + hex `03 00 00 19 …`（0x19=25）✓ |
| `h323_calls_multi` | 20（SETUP，呼叫 2） | `t-h323-11` | 9 | **25** | **79** | `frame.len=79` ✓ |
| `h323_role_callee` | 4（SETUP，方向翻转） | `Administrator` | 13 | **29** | **83** | `frame.len=83` ✓ |
| `h323_rewrite_addr` | 4 / 11 | `Administrator` | 13 | **29** | **83/83** | `frame.len=83` ×2 ✓ |

### 3.3 呼叫参考值 CRV 与方向标志（`h323.go:70-73, 286, 302-314`）

| 位 | 语义 |
|---|---|
| bit15 | 方向标志：`0` = 主叫方发起（`CRVFlagOriginating = 0x0000`），`1` = 被叫方发起（`CRVFlagTerminating = 0x8000`） |
| bit14-0 | 呼叫参考数值 |

- **默认 CRV** = `0x2584`（`DefaultCRV`，`h323.go:84`；参考 pcap 实测值）。缺省来源两级：translate 层给 0x2584（`chain_planner_translate.go:1274`），`Plan` 内再做 `crv == 0 → DefaultCRV` 二次兜底（`h323.go:183-185`）；
- **多呼叫递增**：`callCRV := crv + uint16(callNum)`（`h323.go:286`）——呼叫 1 = crv+0，呼叫 2 = crv+1，**低 15 位递增，不碰 bit15**；溢出到 bit15 时方向标志被污染（**未设守卫**，§8）；
- **标志按角色分配**（`h323.go:302-314`）：`role=caller` → 本侧 0x0000 / 对侧 0x8000；`role=callee` → 本侧 0x8000 / 对侧 0x0000；
- **实测**：`h323_smoke_01` 帧 4（SETUP）CRV 字节 `25 84`（= 0x2584，标志 0）；帧 11（CONNECT）`a5 84`（= 0x2584|0x8000，标志 1）；`h323_calls_multi` 帧 4 `10 00`、帧 20 `10 01`。

### 3.4 TCP 层（由 h323 生成器自产，链内无 `tcp` 层）

**握手（恒 spec `SrcIP:SrcPort → DstIP:DstPort`，与 role 无关，`h323.go:289-293`）**：

| 序 | 方向 | flags | seq | ack | 载荷 |
|---:|---|---|---|---|---|
| 1 | up | `0x02` SYN | `clientSeq` | 0 | — |
| 2 | down | `0x12` SYN-ACK | `serverSeq` | `clientSeq` | — |
| 3 | up | `0x10` ACK | `clientSeq` | `serverSeq` | — |

**序号初值**：`clientSeq = spec.TCP.InitialSeq`，0 → `1000`（`h323.go:226-232`）；`serverSeq = clientSeq + 5000`（`:233`）。**链路径不传 `spec.TCP`**（`layer_gen.go:38-47` 只填 8 个字段），故链路径 `clientSeq` 恒 1000、`serverSeq` 恒 6000。

**SYN 选项**（`synOptions`，`h323.go:563-572`；仅 flags `0x02`/`0x12` 携带，`:263-265`）：MSS（`spec.TCP.MSS` 或 1460）、WindowScale `0x07`、SACK-Permit。**WindowSize 恒 65535**（`h323.go:235`）。

**信令段**：flags 恒 `0x18`（PSH-ACK）；`seq += len(payload)`，`ack` 恒为对端当前 seq（`emitQ931`，`h323.go:276-280`）。

**挥手（`h323.go:346-350`，恒 spec src→dst，与 role 无关）**：

| 序 | 方向 | flags |
|---:|---|---|
| 1 | up | `0x11` FIN-ACK |
| 2 | down | `0x11` FIN-ACK |
| 3 | up | `0x10` ACK |

**注意**：实现是 **FIN / FIN / ACK 三次**（非 RFC 9293 的四次 FIN/ACK/FIN/ACK），且**第三包后无对端 ACK**——故 TCP 状态机并未真正闭合。用例 `h323_scenario_tunnel` 断言帧 10 = `tcp.flags 0x010` 即此第三包。

### 3.5 RAS 面（UDP 1719；`emitRASSignaling`，`h323.go:477-560`）

**载荷（恒 8 字节，手写占位，非 PER）**：

| 偏移 | 字段（代码注释口径） | 尺寸 | 取值 |
|---|---|---|---|
| 0-1 | Request Sequence Number | 2 | `00 00` |
| 2 | Message Type | 1 | 见下表 |
| 3 | Protocol Identifier | 1 | `0x01` |
| 4-7 | Gatekeeper IP | 4 | `net.ParseIP(gkIP).To4()`（`:519-521`）；`gkIP` 解析失败则**整段省略**，载荷退化为 4 字节 |

**消息序列（4 对 8 包，固定，`h323.go:497-509`）**：

| # | 方向 | msgType | 名称 |
|---:|---|---:|---|
| 1 | up | `0x01` | GRQ Gatekeeper Request |
| 2 | down | `0x02` | GCF Gatekeeper Confirm |
| 3 | up | `0x03` | RRQ Registration Request |
| 4 | down | `0x04` | RCF Registration Confirm |
| 5 | up | `0x05` | ARQ Admission Request |
| 6 | down | `0x06` | ACF Admission Confirm |
| 7 | up | `0x07` | DRQ Disengage Request |
| 8 | down | `0x08` | DCF Disengage Confirm |

**地址/端口**（`h323.go:523-535`）：`up` 帧 = `spec.SrcIP:spec.SrcPort → gkIP:ras.port`；`down` 帧 = `gkIP:ras.port → spec.SrcIP:spec.SrcPort`。**MAC 同向对称交换**。

**诚实声明**：这 8 字节**不是** H.225.0 §7 的 ASN.1 PER 编码（无 `RasMessage` CHOICE 标签、无 `requestSeqNum`、无 `endpointIdentifier`）→ G-H323-4。`ras.endpoint_type`（terminal/gateway）被解析与校验但**零消费** → G-H323-3。

### 3.6 RTP 媒体面（UDP；`emitRTPMedia`，`h323.go:414-474`）

**RTP v2 头（12 字节，RFC 3550 §5.1）**：

| 偏移 | 字段 | 尺寸 | 取值 |
|---|---|---|---|
| 0 | V/P/X/CC | 1 | `0x80`（V=2，其余 0） |
| 1 | M/PT | 1 | `media.PayloadType & 0x7F`（缺省 0 = G.711 µ-law） |
| 2-3 | Sequence Number | 2 **大端** | `i`（0 … frames−1） |
| 4-7 | Timestamp | 4 **大端** | **恒 0** |
| 8-11 | SSRC | 4 **大端** | **恒 0** |
| 12… | Payload | `frameSize` | **全零填充**（`make([]byte, frameSize)`，`:448`） |

**缺省**：`frames` 0 → 10；`frameSize` 0 → 160（20 ms G.711）；`srcPort` 0 → 5062；`dstPort` 0 → 5063（`:415-430`）。**全部 `up` 向**（`:454`），无反向媒体。

**诚实声明**：时间戳与 SSRC 恒 0，载荷全零——不承载真实媒体语义（§1 边界 7）。

### 3.7 缺省与二态语义（translate 镜像 parse；`chain_planner_translate.go:1269-1360`）

`h323` 层 registry **无 `Default`**（决策 F）——缺省全部在 translate 期补齐，镜像 flat parse（`strategy_convert.go:4080-4087`）：

| 键 | 缺省 | 语义 |
|---|---|---|
| `role` | `"caller"` | 缺省补 caller；`Plan` 内再做 `"" → caller` 二次兜底（`h323.go:174-177`） |
| `scenario` | `"full"` | 同上（`h323.go:178-181`） |
| `crv` | `0x2584` | **`getIntPresence` 语义**：显式 `0` 保留 0（translate `:1279-1283`），再由 `Plan` 的 `crv==0 → DefaultCRV` 兜底 → **显式 0 实际仍得 0x2584** |
| `display_name` | `"Administrator"` | 空串 → `Plan` 兜底 `"Administrator"`（`h323.go:186-189`） |
| `calls` | `1` | `0` → `Plan` 兜底 1（`h323.go:190-193`） |
| `rewrite_addr` | `false` | **死配置**（G-H323-2） |
| `src_port` | **不动**（0） | 单流 0 上包；多流 worker `12345+i` 保底 |
| `dst_port` | **1720** | translate 镜像 `setDefaultDstPort` |
| `media` 子映射 | 指针 nil = 关闭 | 存在即建 `H323MediaConfig`，各子键各自缺省 |
| `ras` 子映射 | 指针 nil = 关闭 | 同上 |

**端口"同键二态"**（`chain_planner_translate.go:1264-1268`）：标量 → 写 `spec.SrcPort/DstPort`（**层值赢**）；对象 → 放行，由 worker `resolveLayerTuple` 逐流解析后写 spec（`layer_dyn.go:806-815`，`non-zero wins`）。

---

## 4. 业务场景分析（现网典型场景与五层覆盖）

**现网典型**：H.323 是**视频会议/软终端（Polycom、华为 TE、Asterisk/FreeSWITCH 的 chan_h323、Cisco CUCM）**的呼叫控制栈。现网两种部署：

1. **直连呼叫（无网守）**——本实现参考 pcap 即此形态（`20.4.2.46:30000 → 30.4.2.46:1720`，直接 SETUP，无 RAS）；
2. **网守注册（Gatekeeper-routed）**——终端先向网守 RAS 注册（RRQ/RCF），每次呼叫前 ARQ 申请准入（ARQ/ACF），结束后 DRQ 脱离。

**生成器按什么顺序驱动**：`scenario` 决定驱动分支（`h323.go:196-209`）：

```
scenario == "data_only" → 仅 RTP（需 media.enabled），return
scenario == "ras_only"  → 仅 RAS（需 ras.enabled），return
scenario == "full"      → 握手 → Q.931 九条（含 FACILITY×3）→ [RTP] → 挥手
scenario == "tunnel_only" → 握手 → Q.931 六条（无 FACILITY）→ 挥手
```

**五层覆盖**：

| 层 | 本协议对照 | 展开点 |
|---|---|---|
| **功能** | 6 种 Q.931 消息类型 + 8 种 RAS 消息 + RTP 帧；4 种 scenario 分支；6 类错误（presence / 静态复制 / role / scenario / calls / display）| 消息类型逐值（§3.2 表）；scenario 逐分支；错误逐锚词（§7） |
| **性能** | 帧上界由 Display IE 253 字节封顶（L ≤ 269）；无 MSS 分段（信令恒单段，远小于 1460）；多呼叫/多流见 §6 | §6 全节 |
| **数据场景** | `role` 2 值 / `scenario` 4 值 / `crv` 16 位值域 / `display_name` 0–254 边界 / `calls` 0–65535 / `media` 6 子键 / `ras` 4 子键 | §9 表 + testcase §2 逐 ID |
| **地址与流** | IPv4 基线 + **IPv6 对照**（`h323_v6`，offset 74）；**流关联**：控制 TCP 1720 → 媒体 RTP（`flowID:rtp`）/ RAS（`flowID:ras`） | §5.3 五件套 |
| **业务** | **多呼叫**（`calls=N` 整块顺序回放，CRV 递增）| `h323_calls_multi` |

---

## 5. 消息/事务模型与状态机

### 5.1 状态机（声明式脚本回放，非反应式）

实现是**固定事件序列的线性回放**（§5 术语表"配置是剧本、引擎是回放者"），不存在运行时状态分支。状态推进如下（`role=caller`、`scenario=full`）：

```
IDLE
 └─(TCP SYN)──────────────► TCP_SYN_SENT
     └─(SYN-ACK/ACK)──────► ESTABLISHED
         └─(SETUP)────────► CALL_INITIATED
             └─(CALL PROCEEDING)─► CALL_PROCEEDING
                 └─(FACILITY)────► H245_TUNNELING
                     └─(ALERTING)► ALERTING
                         └─(FACILITY×2)─► H245_TUNNELING
                             └─(CONNECT)─► CONNECTED
                                 └─([RTP])─► MEDIA_ACTIVE
                                     └─(RELEASE COMPLETE ×2)─► RELEASED
                                         └─(FIN/FIN/ACK)────► CLOSED
```

**确定性**：同一 spec 必然产出同一字节序列——**唯一随机源不存在**（无 rand；`clientSeq` 恒 1000、`serverSeq` 恒 6000、CRV 由配置决定、RTP seq = 帧序号）。

**非法转移（validator 逐条拒绝，锚词逐字，`h323.go:102-156`）**：

| 非法输入 | 锚词（代码逐字） | 代码行 | 阶段 |
|---|---|---|---|
| `role` 非 caller/callee | `h323: invalid role %q (must be caller or callee)` | `:125` | task-time |
| `scenario` 非四值 | `h323: invalid scenario %q (must be full, tunnel_only, ras_only, or data_only)` | `:135` | task-time |
| `calls < 0` | `h323: calls must be >= 0, got %d` | `:140` | **链路径不可达**（§7 表注） |
| `len(display_name) > 254` | `h323: display_name must be <= %d bytes …` | `:145` | task-time |
| `TCP.MSS` 非 0 且 `< 536` | `h323: TCP.MSS %d too small (min %d)` | `:151` | 链路径不可达（链不传 `spec.TCP`） |
| `H323Config == nil` | `h323: H323Config is required` | `:116` / `layer_gen.go:68` | **链路径不可达**（translate 必建） |
| `SrcIP`/`DstIP` 非 IP | `h323: invalid SrcIP %q` / `invalid DstIP %q` | `:105` / `:110` | 由 ip 层先行拦截 |

**未设守卫的边界（§8）**：`callCRV = crv + callNum` 溢出 bit15 污染方向标志（`h323.go:286`，无检查）；`media.frames < 0` 时 `frames <= 0 → 10` 兜底（`:416-418`），但 `frameSize < 0` **无兜底**（`make([]byte, 负数)` 会 panic，`:448`）——链路径被 registry `uint16` Min=0 拦截，flat 路径由 parse 的 `h323.media.frame_size must be >= 0` 拦截。

### 5.2 事务序列（单呼叫内的四件事）

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| **t1 TCP 建连** | 无 | SYN → SYN-ACK → ACK | 进入 t2 | **无失败分支**（脚本回放，不重传、不超时） |
| **t2 Q.931 呼叫建立** | t1 完成 | SETUP（+BC IE+Display IE） | CP → [FACILITY] → ALERTING → [FACILITY×2] → CONNECT | **无失败分支**（不实现 RELEASE COMPLETE 的 cause IE、不实现错误响应） |
| **t3 媒体**（可选） | t2 的 CONNECT 已发 | `media.enabled` 时发 `frames` 个 RTP | 继续 t4 | 无 |
| **t4 释放** | t2 完成 | RELEASE COMPLETE（本侧） | 对侧 RELEASE COMPLETE | 无 |
| **t5 TCP 拆线** | t4 完成 | FIN-ACK → FIN-ACK → ACK | 呼叫结束 | 无 |

**RAS 事务**（`ras_only`）：t1' GRQ→GCF、t2' RRQ→RCF、t3' ARQ→ACF、t4' DRQ→DCF——四对固定，**无前置依赖、无失败分支**。

**诚实声明**：**全协议无重试、无超时、无保活、无异常中断分支**。失败分支面为零 → 按 §4 最小清单"保活/重试/重连/FIN/RST/异常中断"逐项：FIN 有（§3.4）、RST **无**（A′ 立项）、保活 **无**（H.323 呼叫信令层本无心跳，RAS 的 RRQ 周期性注册是唯一保活形态，本实现只发一轮 → A′ 立项）、重试/重连 **无**。

### 5.3 五件套（CORE_MEMORY §3.17；本协议**有长连接（TCP 1720），不豁免**）

**① 会话表**

| 会话 | 载体 | 四元组 | 生命周期 | 用例 |
|---|---|---|---|---|
| `s1` 呼叫 1 | TCP | `ip.src:ip.dst:h323.src_port:h323.dst_port` | 握手 → 10/6 条 Q.931 → [RTP] → 挥手（16/12 包） | 全部 `full`/`tunnel_only` 正例 |
| `s2` 呼叫 2..N | TCP（**同四元组复用**） | 同上 | 同上（**整块顺序**，第 2 会话包号起点 = 第 1 会话总包数 + 1） | `h323_calls_multi`（N=2，包 17 起） |
| `sR` RAS 面 | UDP | `spec.SrcIP:gkIP:spec.SrcPort:ras.port` | 8 包，**无握手/无挥手** | `h323_scenario_ras` |
| `sM` 媒体面 | UDP | `spec.SrcIP:spec.DstIP:media.src_port:media.dst_port` | `frames` 包，**无握手/无挥手** | `h323_scenario_data`、`h323_media_full` |

**② 事务序列**：见 §5.2（t1–t5 + t1'–t4'）。

**③ 关联关系（控制 → 派生流）**——**本协议最薄弱处，诚实登记**：

- 控制流 = TCP 1720 呼叫信令；派生流 = RTP 媒体 + RAS 注册；
- **关联手段 = `flowID` 后缀**：主控流 `flowID = "{srcIP}-{dstIP}-{srcPort}-{dstPort}"`（`h323.go:211`），RTP 为 `flowID + ":rtp"`（`:452`），RAS 为 `flowID + ":ras"`（`:539`）；
- **缺口**：**无显式关联字段**（CORE_MEMORY §3.8 要求 `driven_by{session,transaction,field}`）——派生流的端口**不随控制流推导**（RTP 端口来自 `media.src_port/dst_port` 独立配置，非 OLC 通告端口；RAS 端口来自 `ras.port`）；
- **子流独立四元组**：✓（各自独立 src/dst IP+port）；**独立握手/挥手**：✓（UDP 面无握手）；
- **顺序/交错**：`full` 场景下 RTP **插在 CONNECT 之后、RELCOMP 之前**（`h323.go:328-334`，实测 `h323_media_full`：帧 10=CONNECT、11–12=RTP、13–14=RELCOMP）；`data_only`/`ras_only` 是**独立单面**，与控制流不同时存在。

**④ 插入位置**：**终结层**（`[ip, h323]`，raw-IP 自驱）。链内**无中间层**，故无"插入到哪一层之间"的问题；h323 自己产出 L4（TCP/UDP）头。

**⑤ 时间线**：单呼叫内**严格顺序**（无并发、无交错调度）；多呼叫 = **整块顺序回放**（§5 术语表"多会话展开"）；**不启用 `concurrent`**；RTP 与 Q.931 在同一 TCP 流的包号序列内交错（媒体面用独立 UDP 四元组，但包号与主控流共用 `packetIndex` 计数器，`:282`）。

**注意（包号与 flowID 的错配）**：RTP/RAS 用**独立 flowID**（`:rtp`/`:ras`）但 `PacketIndex` 用**自己的局部计数器**（RTP `uint64(i)` `:453`；RAS `uint64(i)` `:538`），而主控流用共享的 `packetIndex`（`:282`）。多面同时存在时（`full`+media），resequencer 按 flowID 分别排序，**互不干扰**——这是设计正确点，非缺陷。

### 5.4 多会话/多流边界（CORE_MEMORY §3.14/§3.15）

| 项 | 本协议对照 |
|---|---|
| `sessions[]` | **不适用**——h323 的"多会话"是 `calls=N`（层内标量），非 `sessions[]` 数组。形态差异已声明（§12.3） |
| 多流并发 | 由策略级 `flow_control {"flows": N}` 承载（`h323_port_dyn` 实证，N=2） |
| 单包多载荷 | **不适用**——每条 Q.931/RAS/RTP 消息独立成帧，无多 question/多 RR 类形态 |
| 同连接多轮操作（§3.15①） | ✓ `calls>1`（`h323_calls_multi`，同连接两轮完整呼叫） |
| 非正常结束（§3.15②） | **部分**——正常 FIN 全正例；**RST 无用例** → A′ 立项（G-H323-14） |
| 长保活（§3.15③） | **无**——H.323 呼叫信令层无心跳；RAS 周期注册是唯一保活形态，本实现只发一轮 → A′ 立项 |

---

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

### 6.1 帧/报文长度上界与开销公式

| 面 | 公式 | 上界 | 依据 |
|---|---|---|---|
| 呼叫信令 | `L = 4 + 5 + [5] + [2 + min(len(display),253)]`（TPKT 长度）；`frame.len = 54 + L`（IPv4）/ `74 + L`（IPv6） | `L` ≤ **269 B** → `frame.len` ≤ **IPv4 323 B / IPv6 343 B** | §3.2 |
| RAS | `frame.len = 42 + 8`（IPv4；gkIP 解析失败退化为 46） | **50 B** | §3.5 |
| RTP | `frame.len = 42 + 12 + frameSize` | `frameSize` 由 `configUint16` 封顶 65535 → **65589 B** | §3.6 |

**跨 MSS 分段规则**：**不适用**——信令帧最大 343 B 远小于最小 MSS 536 B（`MinMSS`，`h323.go:59`），**恒单段**；RTP 帧虽可达 64 KB，但走 UDP，由 IP 层分片（生成器不分段，`L3Base` 的 `IPID = packetIndex` 逐包递增，`h323.go:251`）。

**单包多载荷**：不适用（§5.4）。

### 6.2 并发流下的行为

- **多流**：`flow_control {"flows": N}` → worker 逐流解析动态端口（`resolveLayerTuple`，`layer_dyn.go:770`），每流独立四元组、独立握手/挥手；
- **包数线性**：`N` 流 × 15 包/呼叫 × `calls` 次 = 总包数（`h323_port_dyn` 实测 2 流 × 15 = 30 ✓）；
- **调度**：单 worker FIFO → 逐流成对序（流 1 = 包 1–15，流 2 = 包 16–30，用例实测断言）。

### 6.3 流式与内存

- **流式**：`Plan` 用 `chan core.PacketConfig`（`maxsize` 256，`h323.go:164`）逐包 `select` 发送，**从不聚合**（符合 CLAUDE.md "Streaming only"）；
- **单包新增内存**：Q.931 最大 269 B 载荷；RTP `frameSize` 字节（缺省 160）；**无跨包状态**（除 `clientSeq`/`serverSeq`/`packetIndex` 三个标量）；
- **共享状态/锁**：**无**——纯局部变量，无 mutex、无跨进程共享；
- **限速**：由框架 `SharedTokenBucket` 按 `flow_control.bps` 承载，**本层不重复定义**（CORE_MEMORY §6 口径 1）。

### 6.4 验收两路（CORE_MEMORY §6.3）

| 路 | 验收方式 |
|---|---|
| **pcap** | MCP 建策略建任务 → 引擎写 pcap → tshark 逐字段核对（`q931.message_type` / `tcp.flags` / `frame.len` + offset 54 frames 原始字节） |
| **NIC** | 同 spec 经真实网口（`enp135s0f0np0`）发包 → tcpdump 捕获 → 同字段核对；`nic_capture` 用例级开关 |

**吞吐数字**：本版**不写承诺**（无基准数据）——按 CORE_MEMORY §6.5 标"待确认"，归属代码阶段（P4/P5 基准）。

---

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

**链路径负例（cases JSON 在案，6 条）**：

| # | 用例 ID | 故障输入 | `error_contains`（子串判定） | 代码文案（逐字） | 代码行 | 阶段 |
|---:|---|---|---|---|---|---|
| 1 | `h323_vn_presence` | 顶层 `h323: {}` + 层内 `h323: {}` | `top-level h323 sub-config` | `protocol h323 rejects a top-level h323 sub-config (move it into the h323 layer of an [ip,h323] layers chain)` | `strategy_convert.go:8942` | **create-time**（无落盘） |
| 2 | `h323_vn_static_port` | 层内静态端口 + `flows=2` | `static four-tuple` | 静态复制拒绝（`checkLayerChainStaticCopy` 扫描列表已扩含 h323） | `schema/semantic.go` | **create-time** |
| 3 | `h323_neg_role` | `role: "gatekeeper"` | `invalid role` | `h323: invalid role %q (must be caller or callee)` | `h323.go:125` | **task-time**（`.neg.pcap`） |
| 4 | `h323_neg_scenario` | `scenario: "bogus"` | `invalid scenario` | `h323: invalid scenario %q (must be full, tunnel_only, ras_only, or data_only)` | `h323.go:135` | task-time |
| 5 | `h323_neg_calls` | `calls: -1` | `not a numeric value` | `layers: layer "h323" field "calls" = -1 invalid: not a numeric value in [0,65535]` | `complete.go:315` | **create-time（V9 先拦）** |
| 6 | `h323_neg_display` | `display_name` 255 字节 | `display_name must be <=` | `h323: display_name must be <= 254 bytes (Display IE length is 1 byte), got 255` | `h323.go:145` | task-time |

**锚词口径说明**：
- `error_contains` 是**子串**判定，6 条均命中代码文案（前缀 `h323: ` 或 `layers: `）；
- **#5 的锚词切换（重要）**：registry 的 `calls` 是 `uint16 Min=0`（`registry.go:1347`），`-1` 在 `configUint64` 阶段即失败（`complete.go:315`），故 legacy 的 `h323: calls must be >= 0`（`h323.go:140`）在**链路径不可达**——用例按 V9 先拦口径钉 `not a numeric value`；
- **#1 的形状特殊性（批次二任务书要求点名）**：`h323_vn_presence` 是全仓**唯一**顶层非 `layers` 键例（`spec_json` = `{"layers":[…],"h323":{}}`），这是**判死负例的必需形状**（presence 门要求顶层出现 `h323` 键），**不是残留**。其余 16 例顶层零游离键（§12.1）。

**flat 路径（非链路径）的额外锚词**（`strategy_convert.go:4088-4127`，今日无用例 → A′ 立项 G-H323-14）：
`h323.role must be "caller" or "callee"` / `h323.scenario must be full|tunnel_only|ras_only|data_only` / `h323.calls must be >= 1` / `h323.display_name must be <= 254 bytes (Display IE length is 1 byte)` / `h323.media.frames must be >= 0` / `h323.media.frame_size must be >= 0` / `h323.ras.endpoint_type must be terminal|gateway`。

**未入用例的 legacy Validate 分支**（链路径不可达，G-H323-14）：`h323: invalid SrcIP %q`（`:105`）、`h323: invalid DstIP %q`（`:110`）、`h323: H323Config is required`（`:116`）、`h323: TCP.MSS %d too small`（`:151`）。

---

## 8. 边界

| 边界 | 内容 | 归属 |
|---|---|---|
| **Display IE 上界** | `Validate` 允许 ≤254（`MaxDisplayNameLen`，`h323.go:89`），`buildDisplayIE` 却截断 253（`:405-407`）——**254 字节输入通过校验后被静默截掉 1 字节** | 缺口 G-H323-6 |
| **CRV 溢出** | `callCRV = crv + uint16(callNum)`（`:286`）无守卫——`crv=0x8000` 起递增会污染 bit15 方向标志，使主叫方消息带被叫方标志 | 缺口 G-H323-9 |
| **`frameSize < 0`** | `make([]byte, frameSize)`（`:448`）无兜底（`frames` 有 `<=0 → 10`，`frameSize` 无）；链路径由 registry `uint16` 拦截，flat 路径由 parse 拦截 | 已由上游拦截，**不立项**（防御纵深足够） |
| **`gkIP` 解析失败** | `net.ParseIP(gkIP)` 为 nil 时 RAS 载荷**静默退化为 4 字节**（`:519-521`），不报错 | 缺口 G-H323-4（同族：非 PER 占位） |
| **`ras.enabled` 在 full/tunnel_only 被忽略** | `full` 分支（`:317-334`）只检查 `h.Media`，**从不检查 `h.Ras`**——`ras.enabled=true` + `scenario=full` 静默无 RAS | 缺口 G-H323-5 |
| **`data_only`/`ras_only` 忽略其余全部键** | 提前 return（`:196-209`），`role`/`calls`/`crv`/`display_name`/`rewrite_addr` 全部无效 | 缺口 G-H323-10 |
| **链路径强制 Direction="up"** | `layer_gen.go:53` 把每个包的方向覆写为 `"up"`（防 raw-IP 驱动二次换向）——故 `role=callee` 时 down 侧发起的 Q.931 在 tshark 侧不出 `message_type`（用例自述伪影），字节结构由 `frame.len` 承担 | 缺口 G-H323-13 |
| **TCP 拆线未闭合** | FIN/FIN/ACK 三次，末包后无对端 ACK（§3.4） | 缺口 G-H323-13（同族） |

---

## 9. 原子 ID 与完成定义（17 个唯一语义 ID，顺序为权威）

**正例 11 条**（`cases/h323.json` 顺序）：

| # | ID | scenario / 关键配置 | 包数 | 覆盖 |
|---:|---|---|---:|---|
| 1 | `h323_smoke_01` | full（显式 `src_port=12345`） | **15** | §3.2 九条 Q.931 + §3.4 握手/挥手 |
| 8 | `h323_scenario_tunnel` | `tunnel_only` | **12** | §3.2 六条（无 FACILITY） |
| 9 | `h323_scenario_ras` | `ras_only` + `ras.enabled` | **8** | §3.5 四对 RAS |
| 10 | `h323_scenario_data` | `data_only` + `media.enabled` | **10** | §3.6 RTP 缺省 10 帧 |
| 11 | `h323_calls_multi` | `calls=2` + `crv=4096` + `display_name="t-h323-11"` | **32** | §3.3 CRV 递增 + §5.3 多会话整块 |
| 12 | `h323_media_full` | full + `media.enabled` + `frames=2` | **18** | §5.3③ RTP 插 CONNECT 后 |
| 13 | `h323_dst_default` | 空 h323 层 | **16** | §3.7 `dst_port` 缺省 1720 |
| 14 | `h323_port_dyn` | `src_port` inc 动态 + `flows=2` + `group_id` | **32** | §12 动态端口逐流 |
| 15 | `h323_role_callee` | `role=callee` | **16** | §3.3 方向标志翻转 |
| 16 | `h323_rewrite_addr` | `rewrite_addr=true` | **16** | §3.6（**实为死配置**，G-H323-2） |
| 17 | `h323_v6` | IPv6 地址 | **16** | §2 offset 74 对照 |

**负例 6 条**：见 §7 表（#2–#7 用例位次）。

**包数公式（实测钉死，机读复核）**：

```
full         = 3 + 9 + 3 = 15  (+ frames if media.enabled)
tunnel_only  = 3 +  6 + 3 = 12
ras_only     = 8                (无 TCP)
data_only    = frames (缺省 10)  (无 TCP)
calls=N      = N × 15           (full 默认)
flows=M      = M × (每流包数)
```

**完成定义**：ID 集合与顺序 = `cases/h323.json` 实测（17 条，机读）；包数与断言逐条一致（testcase §2/§3）；6 条负例锚词与 §7 表逐字对应。

---

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵（§4.1–4.8）

| # | 规范项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---:|---|---|---|---|---|
| 4.1 | 连接模型 | 呼叫信令 = TCP 长连接（1720）；RAS = UDP（1719）；媒体 = UDP 动态 | 直连呼叫 + 网守注册 | ✓ TCP 1720 长连接（一次呼叫一连接，`calls>1` 复用四元组）；✓ UDP 1719；✓ UDP 5062/5063 | — |
| 4.2 | 命令/消息表 | Q.931 消息集（SETUP/CP/ALERTING/CONNECT/RELCOMP/FACILITY）+ RAS 消息集（GRQ/GCF/RRQ/RCF/ARQ/ACF/DRQ/DCF） | 呼叫建立/释放 | **6 种 Q.931 ✓**（缺 STATUS/INFO/PROGRESS/NOTIFY 等）；**8 种 RAS ✓**（缺 LRQ/LCF/IRQ/IRR/BRQ/BCF/RIP 等） | G-H323-15（未实现消息类型） |
| 4.3 | 状态机 | 呼叫状态（Null→Call Initiated→Overlap/Outgoing→Active→Released） | 单呼叫线性 | ✓ 线性回放（§5.1）；**无分支**（不实现拒绝/忙/重定向） | G-H323-16（无失败分支） |
| 4.4 | 字段表 | TPKT 4B / Q.931 头 5B / CRV 2B 大端 / IE 链 | — | ✓ 逐字节落码（§3.1–3.2）；**IE 链只实现 Bearer Capability + Display 两种**（缺 Called/Calling Party Number、User-User、Cause 等） | G-H323-17（IE 面窄） |
| 4.5 | 错误处理表 | Q.931 拒绝消息带 Cause IE；RAS 拒绝带 reason | — | **零实现**——无 Cause IE、无拒绝消息、无 RAS 拒绝 | G-H323-16 |
| 4.6 | 超时与活性 | RAS 周期注册（RRQ，默认 30 s）；TCP 保活 | 网守注册 | **零实现**——单轮 RAS、无周期、无保活 | G-H323-14（A′） |
| 4.7 | NAT/代理/被动模式 | H.323 有 H.460 NAT 穿越、fastStart 端口协商 | 现网穿越 | **零实现**——RTP 端口硬编码 5062/5063，不随 OLC 推导 | G-H323-7 |
| 4.8 | 版本/方言 | H.225v7 / Q.931 各国方言；IPv6 承载 | — | ✓ IPv6 承载（`h323_v6`）；**无版本协商**（无 protocolIdentifier/version 字段） | G-H323-15 |

### 10.2 子表①：消息 × 终态矩阵（逐格已覆/立项/不适用）

| 消息 | 值 | 正例 | 负例 | 结论 |
|---|---:|---|---|---|
| SETUP | 0x05 | ✓ `h323_smoke_01`/`tunnel`/`calls_multi` | — | **已覆** |
| CALL PROCEEDING | 0x02 | ✓ 同上 | — | **已覆** |
| ALERTING | 0x01 | ✓ 同上 | — | **已覆** |
| CONNECT | 0x07 | ✓ 同上 | — | **已覆** |
| FACILITY | 0x62 | ✓ `h323_smoke_01`/`media_full` | — | **已覆**（**载荷非 H.245**，G-H323-1） |
| RELEASE COMPLETE | 0x5A | ✓ 同上 | — | **已覆** |
| STATUS / STATUS ENQUIRY / INFO / PROGRESS / NOTIFY / SETUP ACK / USER INFO / SEGMENT / CONGESTION CONTROL | — | — | — | **A′ 立项**（G-H323-15） |
| RAS GRQ/GCF/RRQ/RCF/ARQ/ACF/DRQ/DCF | 0x01–0x08 | ✓ `h323_scenario_ras`（仅 srcport/dstport 断言） | — | **已覆（弱）**——**载荷非 PER，无 msgType 字段断言**（G-H323-4） |
| RAS LRQ/LCF/IRQ/IRR/BRQ/BCF/RIP/RAC | — | — | — | **A′ 立项**（G-H323-15） |
| RTP 帧 | — | ✓ `h323_scenario_data`/`media_full` | — | **已覆**（时间戳/SSRC 恒 0，§3.6） |

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

| 形态 | 变体 | 用例 | 结论 |
|---|---|---|---|
| `role` | `caller`（缺省）/ `callee` | `h323_smoke_01` / `h323_role_callee` | **已覆 2/2** |
| `scenario` | `full` / `tunnel_only` / `ras_only` / `data_only` | 四条 | **已覆 4/4** |
| `crv` | 缺省 0x2584 / 显式 4096 / 显式 0 | `h323_smoke_01` / `h323_calls_multi` / — | **已覆 2/3**（显式 0 → 被 Plan 兜底为 0x2584，**无独立例** → A′） |
| `display_name` | 缺省 `Administrator` / 自定义 / 空串 / 254 边界 / 255 超界 | `h323_smoke_01` / `h323_calls_multi` / — / — / `h323_neg_display` | **已覆 3/5**（空串 → 兜底 `Administrator`、254 边界 → A′） |
| `calls` | 缺省 1 / 2 / 0 / 65535 / 负数 | `h323_smoke_01` / `h323_calls_multi` / — / — / `h323_neg_calls` | **已覆 3/5**（0 → 兜底 1、65535 上界 → A′） |
| `src_port` | 显式 / 缺省（单流 0）/ 动态 inc / 静态+flows>1 | `h323_smoke_01` / `h323_dst_default` / `h323_port_dyn` / `h323_vn_static_port` | **已覆 4/4** |
| `dst_port` | 显式 1720 / 缺省 1720 / 动态 | 多条 / `h323_dst_default` / — | **已覆 2/3**（dst 动态 → A′） |
| `media` | 关闭 / enabled 缺省 frames / frames=2 / src_port / dst_port / payload_type / frame_size | 多条 / `h323_scenario_data` / `h323_media_full` / — / — / — / — | **已覆 3/7**（端口/payload_type/frame_size → A′） |
| `ras` | 关闭 / enabled / gatekeeper_ip / port / endpoint_type | 多条 / `h323_scenario_ras` / — / — / — | **已覆 2/5**（三项 → A′；`endpoint_type` 是死配置 G-H323-3） |
| `rewrite_addr` | false（缺省）/ true | 多条 / `h323_rewrite_addr` | **已覆 2/2**——但**两侧字节全等**（死配置 G-H323-2） |
| 地址族 | IPv4 / IPv6 | 16 例 / `h323_v6` | **已覆 2/2** |
| 编码形态 | IA5（Display IE）/ 二进制（Q.931 头）/ PER（**未实现**） | 多条 / 多条 / — | **2/3**（PER → G-H323-1/G-H323-4） |

### 10.4 子表③：商业行为→用例映射表

| # | 现网行为（商业产品） | 出处 | 映射用例 | 结论 |
|---:|---|---|---|---|
| 1 | Polycom/华为 TE 直连呼叫：SETUP 携带 Display IE（终端名）+ Bearer Capability（3.1 kHz audio） | 参考 pcap（`/home/pcap_auto/llcj_pcap/IP-TCP-20.4.2.46-30.4.2.46-30000-1720-10-10-2271-1779.pcap`，帧 4/5/8/15/16） | `h323_smoke_01`（帧 4/11/12 原始字节） | **已覆** |
| 2 | 被叫方先回 CALL PROCEEDING 再 ALERTING（振铃与接通分离） | 同上（帧 5/8） | `h323_smoke_01` 帧 5/7 | **已覆** |
| 3 | H.245 能力协商隧道在 Q.931 FACILITY 内（多轮 FACILITY 往返） | 同上（帧 6/9/10/11，**共 4 条 FACILITY**） | `h323_smoke_01` 帧 6（断言 0x62） | **结构已覆，载荷未覆**（G-H323-1） |
| 4 | 网守路由部署：呼叫前 RAS 注册 + 准入 | H.225.0 §7（**无参考 pcap**） | `h323_scenario_ras`（仅端口断言） | **弱覆**（G-H323-4） |
| 5 | 媒体面 RTP 在 CONNECT 后开始 | 同上（参考 pcap **无 RTP**——媒体在另一 pcap） | `h323_media_full` 帧 10–14 | **已覆** |
| 6 | 多呼叫复用同一 TCP 连接（CRV 递增区分） | 参考 pcap 单呼叫；多呼叫语义由 Q.931 §4.3 推导 | `h323_calls_multi`（帧 4/20） | **已覆** |
| 7 | 媒体端口由 OLC 通告（fastStart / H.245 OLC）而非硬编码 | H.245 §7.3 | — | **A′ 立项**（G-H323-7） |
| 8 | NAT 穿越（H.460） | ITU-T H.460.x | — | **不适用**（真实 NAT 穿越非本生成器范围） |

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

**三路对照**：
- **4.12 规范原文**（ITU-T Q.931 / H.225.0 / H.245 / RFC 1006 / RFC 3550）：定 TPKT 4 字节头、Q.931 头 5 字节（PD/CRV len/CRV/msgType）、CRV bit15 方向标志、Display IE 的 IA5 编码、RTP v2 12 字节头；
- **4.13 商业行为**：参考 pcap（Polycom 类终端直连呼叫，20 帧，SETUP 1440 字节含 18 个 fastStart OLC）——**实现只复刻了头形状与消息顺序，未复刻 PER 载荷**；
- **4.14 开源实现思路**：`chan_h323`（Asterisk）/ `openh323`（H323Plus）用 ASN.1 编译器生成 PER 编解码器——**本生成器不引入 ASN.1 编译器**（体积/复杂度不划算）；
- **4.15 取舍**：**以规范为底线、以现网行为为准绳**——线格式头（TPKT/Q.931/CRV/IE 链）严格按规范；PER 载荷**诚实声明未实现**（G-H323-1/G-H323-4），不用"看起来像"的假字节冒充。

**候选方案对比（PER 载荷的三种走法）**：

| 方案 | 来源 | 优势 | 劣势 | 选择 |
|---|---|---|---|---|
| **A. 引入 ASN.1 PER 编译器**（H.225/H.245 ASN.1 模块 → Go 编解码） | openh323 / H323Plus 做法 | 真实可互操作 | 引入大型代码生成链（数千行）、ASN.1 模块许可证、超出生成器范围 | **不选** |
| **B. 从参考 pcap 提取字节模板**（`types.go:5570` 注释的意图） | 注释声称 | 字节级复刻、零 ASN.1 依赖 | 模板只对一组地址有效，与"逐流可变"矛盾；需 `rewrite_addr` 补洞（而该键是死的） | **未落码**（G-H323-1） |
| **C. 最小合法头 + 占位 IE**（**当前实现**） | `h323.go:359-411` | 结构合法、tshark 可解码（`q931.message_type` 156 字段可用）、零依赖、逐流可变 | **载荷无 H.245 语义**，FACILITY 是空壳 | **已选**（诚实声明为边界） |

---

## 11. P2 D-H323-1 代码设计（CORE_MEMORY §8 八要素；as-built 逆向定稿）

### 11.1 文件清单（实测，非计划）

| 文件 | 行数 | 职责 |
|---|---:|---|
| `trafficgen/internal/protocol/h323/h323.go` | 598 | legacy `Planner`：`Validate` / `Plan` / `buildQ931Message` / `buildBearerCapabilityIE` / `buildDisplayIE` / `emitRTPMedia` / `emitRASSignaling` / `synOptions` |
| `trafficgen/internal/protocol/h323/layer_gen.go` | 77 | 层生成器适配：`Generator.Generate` 中继 legacy 输出 + 强制 `Direction="up"`；`validateLayer`；`init()` 注册 |
| `trafficgen/internal/protocol/h323/h323_test.go` | 826 | 30 个 `Test*`（`grep -c "^func Test"` 实测） |

**接线文件**（本协议不新增层，只接线）：`registry.go:1341`（注册）/ `chain_planner_translate.go:1262`（层内 translate）/ `strategy_convert.go:1363` + `:4075` + `:8940`（flat parse + presence 判死）/ `layer_dyn.go:48` + `:806`（动态端口）/ `chain_planner.go:758` + `:996`（端口语义）/ `chain_planner_util.go:40` + `:54`（raw-IP 路由）/ `protocols.go:41`（白名单）。

### 11.2 接口签名（as-built）

```go
// h323.go
const DefaultPort = 1720; DefaultTTL = 64; DefaultMSS = 1460; MinMSS = 536
const TPKTVersion = 0x03; Q931PD = 0x08; CRVLength = 0x02
const CRVFlagOriginating = 0x0000; CRVFlagTerminating = 0x8000
const MsgTypeAlerting = 0x01; MsgTypeCallProceeding = 0x02; MsgTypeSetup = 0x05
const MsgTypeConnect = 0x07; MsgTypeReleaseComplete = 0x5A; MsgTypeFacility = 0x62
const DefaultCRV = 0x2584; MaxDisplayNameLen = 254

type Planner struct{}
func NewPlanner() *Planner
func (p *Planner) Name() string                                   // "h323"
func (p *Planner) Validate(spec core.FlowSpec) error
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error)

func buildQ931Message(msgType byte, crvVal uint16, displayName string) []byte
func buildBearerCapabilityIE() []byte
func buildDisplayIE(displayName string) []byte
func emitRTPMedia(ctx context.Context, media *core.H323MediaConfig, spec core.FlowSpec, configChan chan<- core.PacketConfig)
func emitRASSignaling(ctx context.Context, ras *core.H323RasConfig, spec core.FlowSpec, configChan chan<- core.PacketConfig)
func synOptions(mss uint16) []core.TCPOption
func normalizeRole(r string) string
func normalizeScenario(s string) string

// layer_gen.go
type Generator struct{ legacy *Planner }
func (*Generator) Name() string                        // "h323"
func (*Generator) GenEvents() layers.EventGenerator     // 恒 nil（raw 自驱终层）
func (g *Generator) Generate(ctx context.Context, req *layers.GenRequest) error
func validateLayer(s core.FlowSpec) error
func init()  // RegisterLayerGenerator + RegisterLayerValidator
```

**`GenEvents` 恒 nil 的强制性**（`layer_gen.go:24-28`）：`chain_planner.go` 的事件分支检查把 `GenEvents != nil` 的生成器路由到传输路径——h323 是 raw 自驱终层，**必须**返 nil 才走 raw-IP 路径。

### 11.3 数据结构（as-built）

```go
// core/types.go:5583
type H323Config struct {
    Role        string            // "caller"(默认) | "callee"
    Scenario    string            // "full"(默认) | "tunnel_only" | "ras_only" | "data_only"
    Crv         uint16            // 0 = 0x2584；多呼叫 callCRV = Crv + callNum
    DisplayName string            // Display IE，IA5；缺省 "Administrator"
    Calls       int               // 0 = 1；顺序呼叫次数
    RewriteAddr bool              // ★ 死配置（G-H323-2）
    Media       *H323MediaConfig  // nil = 关闭
    Ras         *H323RasConfig    // nil = 关闭
}
type H323MediaConfig struct {
    Enabled bool; SrcPort uint16 /*0=5062*/; DstPort uint16 /*0=5063*/
    Frames int /*0=10*/; PayloadType uint8 /*0=µ-law*/; FrameSize int /*0=160*/
}
type H323RasConfig struct {
    Enabled bool
    GatekeeperIP string   // "" = spec.DstIP
    Port uint16           // 0 = 1719
    EndpointType string   // ★ 死配置（G-H323-3）
}
```

**注意**：`types.go:5564-5581` 的 struct doc comment 描述的是**未实现的设计意图**（PER 模板 / 1440 字节 SETUP / 18 fastStart OLC / NUL 终止符）——见 §0 校正表。

### 11.4 主流程

```
Generate(req)                                  // layer_gen.go:34
 └─ 构造 spec（8 字段：SrcIP/DstIP/TTL/SrcMAC/DstMAC/SrcPort/DstPort/H323）
     └─ legacy.Plan(ctx, spec)                  // h323.go:159
         ├─ Validate（失败 → return err）        // :160
         ├─ go func():
         │   ├─ 缺省解析（role/scenario/crv/display/calls） // :174-193
         │   ├─ scenario == "data_only" → emitRTPMedia, return   // :196-202
         │   ├─ scenario == "ras_only"  → emitRASSignaling, return // :203-209
         │   ├─ flowID / TTL / MSS / synOpts / seq 初始化          // :211-236
         │   ├─ for callNum in 0..calls-1:                          // :285
         │   │   ├─ callCRV = crv + callNum                        // :286
         │   │   ├─ TCP 握手 3 包                                   // :289-293
         │   │   ├─ role 决定 upDir/downDir/MAC/IP/Port/CRV 标志    // :302-314
         │   │   ├─ scenario=="full" → 10 条 Q.931 + [RTP]         // :317-334
         │   │   └─ else → 6 条 Q.931（tunnel_only）               // :335-343
         │   │   └─ TCP 挥手 3 包                                   // :346-350
         └─ close(configChan)
     └─ for pkt := range ch: pkt.Direction = "up"; req.Emit(pkt)   // layer_gen.go:52-57
```

**自动派生规则**（生成器自动补出的帧，逐个列出）：
1. TCP 握手 3 包（SYN/SYN-ACK/ACK）——**触发条件**：scenario ∈ {full, tunnel_only}；
2. TCP 挥手 3 包（FIN-ACK/FIN-ACK/ACK）——同上；
3. CALL PROCEEDING / ALERTING / CONNECT——**恒补**（脚本固定，不依赖对端响应）；
4. FACILITY ×4——**触发条件**：scenario == "full"；
5. RELEASE COMPLETE ×2——恒补（双向各一）；
6. RTP `frames` 帧——触发条件：`media != nil && media.Enabled`；**插入位置**：full 在 CONNECT 后 RELCOMP 前（`:328-331`）；data_only 独占；
7. RAS 8 包——触发条件：`scenario == "ras_only" && ras != nil && ras.Enabled`；**注意 full 场景不触发**（G-H323-5）。

### 11.5 错误分支

见 §5.1 非法转移表 + §7 锚词表。**链路径可达的 4 条**：`invalid role`、`invalid scenario`、`display_name must be <=`、`H323Config is required`（后者 translate 必建，实际不可达，防御性保留）。**链路径不可达的 3 条**：`calls must be >= 0`、`TCP.MSS too small`、`invalid SrcIP/DstIP`（上游拦截）。

### 11.6 性能边界

见 §6。要点：**单段信令**（≤269 B < MinMSS 536）、**流式 channel**（maxsize 256）、**零共享状态**、**零锁**、**RTP 载荷 `frameSize` 由 `uint16` 封顶**。

### 11.7 与现有逻辑的冲突点

| # | 冲突 | 处置 |
|---:|---|---|
| 1 | `types.go` struct doc comment 声称 PER 模板/NUL 终止符，与代码相反 | **保留注释**（不在文档车道改代码），登记 G-H323-1；归属代码阶段修正 |
| 2 | `RewriteAddr` / `EndpointType` 被 parse+validate+translate 三处接线却零消费 | 登记 G-H323-2 / G-H323-3；归属代码阶段（补实现或删键，CORE_MEMORY §1.12 口径） |
| 3 | `full` 场景忽略 `ras.enabled` | 登记 G-H323-5；归属代码阶段 |
| 4 | `Validate` 允许 display 254 而 `buildDisplayIE` 截断 253 | 登记 G-H323-6；归属代码阶段（对齐上界） |
| 5 | flat parse 的 `h323.calls must be >= 1`（`strategy_convert.go:4096`）与 legacy Plan 的 `0 → 1` 缺省语义冲突 | 登记 G-H323-11；归属代码阶段（统一口径） |

### 11.8 回滚方式

文档车道**零代码改动**——回滚 = 删除 `docs/protocol-designs/117-h323-{design,testcase}.md` 两个文件 + revert 本车道提交。不触碰任何 `.go` / `cases/*.json` / `trafficgen/tools/**`。

---

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 **15/17 例顶层 = `{layers}`**；**2 例例外**——`h323_port_dyn` 顶层含 `group_id`（**CORE_MEMORY §1.11 白名单结构键**，跨流绑定，合规）与 `h323_vn_presence` 顶层含 `h323:{}`（**判死负例的必需形状**）；**违规游离键 = 0**；无旧键可删（本协议**从未用过顶层地址/端口/count**） | §12.1；`cases/h323.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 h323 流量模板（层链 + `h323` 层 10 键）；任务 = 多策略合跑 + 总量封顶；框架语义未动 | §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表（s1/s2/sR/sM）/ 事务序列（t1–t5 + t1'–t4'）/ 关联关系（**无 driven_by，诚实登记 G-H323-7**）/ 插入位置（终结层）/ 时间线（严格顺序 + 多呼叫整块）。**有长连接（TCP 1720），不豁免** | §12.3 + §5 |
| §4 查规范 | ITU-T H.225.0 / Q.931 / H.245 + RFC 1006 / RFC 3550 + tshark 3.6.14 `q931.*`（156 字段）+ 参考 pcap 20 帧实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["ip"]` 单值（`registry.go:1341`）；6 条链路径负例（3 create-time + 3 task-time）+ 7 条 flat 锚词未入例；失败传 task error（负例 0 帧） | §5.1/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待确认，不写承诺；pcap/NIC 两路验收明写） | §6 |
| §7 三份文档 | `117-h323-{design,testcase}.md` v1.0.0（本版，首次成文）+ D-H323-1（§11，as-built）+ T-H323 草稿（testcase §2，17 ID） | 修订记录 |
| §8 设计先行 | **例外**：本协议为批次二 **as-built 型**——实现与 cases 已在案（P5 于 2026-09-19 收官），本版把既有实现如实写成契约；非"设计先行"路径 | 任务书 |
| §9 测试三源 | 三源 = 规范（H.225/Q.931/H.245/RFC 1006/3550）+ D-H323-1（§11）+ tshark 3.6.14 字段与参考 pcap 实测（**抓包级**：参考 pcap 20 帧 + 用例 5 条 frames 断言 + 48 条 fields 断言）；17 ID 逐项回指；存量审计去向 testcase §8 | `117-h323-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 本版自审（机读复核计数与断言）+ 收官隔离复审（subagent）；红先绿后 | 自审日志 |
| §11 白话 | 本文首节白话一句 | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组（ip.src/dst + h323.src_port/dst_port）全开（allowlist 实测）；业务 8 键全关 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `h323` 已在 `registry.go:1341` 注册（**不新增层**）；Fields 10 键；**本车道不改 registry，无需重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `q931.*`/`tcp.*`/`udp.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/h323/`。**本车道未跑**（as-built 文档车道，不跑套件） | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/h323.json` | **17** | **`{layers}` ×16** + **`{layers, h323}` ×1**（`h323_vn_presence`，**判死负例必需形状**） | **`[ip, h323]` ×17** | 6/6 = `{expect_error, error_contains, notes}` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 本协议**从未用过顶层地址**；17/17 地址已住 `layers[0].ip.{src,dst}` |
| `src_port` | **0** | 已住 `layers[1].h323.src_port`（11/11 正例显式或动态） |
| `dst_port` | **0** | 已住 `layers[1].h323.dst_port`（缺省走 translate 镜像 1720） |
| `count` | **0** | 走 `flow_control`（2 例用 `strategy_fc`） |
| 顶层 `h323` 子映射 | **1**（`h323_vn_presence`） | **唯一残留，且是判死负例的必需形状**（presence 门要求顶层出现 `h323` 键才判死）；**不是待迁移的旧格式** |
| `strategy_fc` / `flow_control` | **2**（`h323_vn_static_port`、`h323_port_dyn`） | 结构键，白名单内（CORE_MEMORY §1.11） |
| `group_id` | **1**（`h323_port_dyn`） | 结构键，白名单内（跨流绑定） |

**结论**：本协议存量**违规游离顶层键 = 0**——§1 门的动作 = ①**无旧键可删**（顶层地址/端口/count 从未出现）；②收官自查行「**非负例**顶层键（去白名单后）= 0」**今日即成立**（机读实测：16/16 非负例顶层键 ⊆ `{layers, group_id}`，其中 15 例仅 `layers`、1 例 `h323_port_dyn` 含白名单结构键 `group_id`）；③A′ 新增例全部沿用纯 layers 形。

> **`h323_vn_presence` 形状点名（批次二任务书强制）**：该例 `spec_json` = `{"layers":[{"ip":{...}},{"h323":{}}],"h323":{}}`——**层链 + 顶层空子映射并存**。这是**判死负例的标准形状**（presence 门扫的就是顶层 `h323` 键，空 map 也死），**与"旧格式残留"是两回事**。验收口径按批次二任务书：**非负例顶层键为 0** 即通过。

目标形状样例见 §2（顶层仅 `layers`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"h323":{}}` **今日会被拒**（`CheckProtoFlat` 有 h323 分支，`strategy_convert.go:8940-8943`）→ **P4/P5 已建该负例**（`h323_vn_presence`，与 opcua 的 G-OPCUA-1 情形相反）；
- ② 白名单外游离键判死（`unknown field`）**无通用门**（框架级 unknown-key 白名单未落）→ A′ 候选；
- ③ 6 条负例**每条带锚词**（已齐，§7）；
- ④ 收官自查「**非负例**顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

**会话表**：`s1` 呼叫 1（TCP 1720，15 包 = 3+9+3；`tunnel_only` 12 包 = 3+6+3）/ `s2` 呼叫 2..N（`calls=N`，**同四元组复用**，整块顺序，第 2 会话包号起点 = 前会话总包数+1；`h323_calls_multi` N=2 实测包 16 起）/ `sR` RAS 面（UDP 1719，8 包，无握手挥手；`h323_scenario_ras`）/ `sM` 媒体面（UDP 5062→5063，`frames` 包，无握手挥手；`h323_scenario_data`/`h323_media_full`）。

**事务序列**：`t1` TCP 建连（SYN/SYN-ACK/ACK）/ `t2` Q.931 呼叫建立（SETUP→CP→[FACILITY]→ALERTING→[FACILITY×2]→CONNECT）/ `t3` 媒体（可选 RTP）/ `t4` 释放（RELCOMP×2）/ `t5` TCP 拆线（FIN/FIN/ACK）；RAS 面另有 `t1'`–`t4'`（GRQ/RRQ/ARQ/DRQ 四对）。**每事务四件事**（前置/触发/成功/失败）见 §5.2 表——**失败分支全为空**（G-H323-16）。

**关联关系**：控制流（TCP 1720）→ 派生流（RTP `flowID:rtp`、RAS `flowID:ras`）。**诚实声明：无 `driven_by` 显式关联字段**（CORE_MEMORY §3.8），派生流端口**不随控制流推导**（RTP 端口独立配置、非 OLC 通告）→ **G-H323-7**。子流独立四元组 ✓；独立握手/挥手 ✓（UDP 面无握手）。

**插入位置**：**终结层**（`[ip, h323]`，raw-IP 自驱；`isRawIPChain`，`chain_planner_util.go:40-60`）。链内无中间层，h323 自产 L4 头。

**时间线**：单呼叫内**严格顺序**（无并发、无交错）；多呼叫 = **整块顺序回放**；**不启用 `concurrent`**；`full` 场景 RTP 插在 CONNECT 后 RELCOMP 前（实测帧 10=CONNECT、11–12=RTP、13–14=RELCOMP）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组 4 项**：`ip.src` / `ip.dst` / `h323.src_port` / `h323.dst_port`——**全开**（allowlist 实测 `layer_dyn.go:48`：`"h323": {"src_port": true, "dst_port": true}`；`ip` 行 `{"src","dst","ttl"}`）。**注意**：链内**无 `tcp`/`udp` 层**，故端口动态**必须**写 `h323` 层（不能写 `tcp.src_port`）。

**业务字段 8 项**：`role` / `scenario` / `crv` / `display_name` / `calls` / `rewrite_addr` / `media` / `ras`——**全关**（allowlist 无这些键，`grep` 零命中实测；对象即 `does not support dynamic`）。**理由**：`role`/`scenario` = 结构选择器（逐流变会使同一策略产出不同线形，破坏策略语义）；`crv`/`display_name` = 呼叫身份（逐流变无意义，呼叫间递增已由 `calls` 承担）；`calls` = 数量语义（属 `flow_control` 维度，非值算法）；`rewrite_addr` = 布尔开关；`media`/`ras` = 嵌套对象（无动态形状）。**与 icmpv6/mpls/ngap/telnet/sip/radius 同判**（`layer_dyn.go:46-49` 注释链）。

**序号算法实读**：

| 环节 | 代码位置 |
|---|---|
| allowlist 白名单 | `layer_dyn.go:48`（`"h323"` 行） |
| 层动态对象解析 | `parseLayerDyn`（`layer_dyn.go:78`）→ h323 分支 `layer_dyn.go:806-815`（`src_port` → `out.H323.SrcPort`，else → `out.H323.DstPort`） |
| 逐流解析落 spec | `resolveLayerTuple`（`layer_dyn.go:770`）→ H323 块（`layer_dyn.go:806-815`，`non-zero wins`） |
| 值算法 | `ResolvePortValue`（int 面，五种策略 fixed/inc/rand/list/pattern） |
| 保底自增 | worker 注入 `12345 + i`（`DefaultSrcPort`，`strategy_convert.go:49`） |
| 静态复制门 | `checkLayerChainStaticCopy` 扫描列表已扩含 `h323`（`schema/h323_static_port_test.go` 红例实证） |

**逐流成对序实证**：`h323_port_dyn`（`src_port` inc 30000–30001，`flows=2`，`group_id` 固定单 worker FIFO）——流 1 = 包 1–16 源口 30000、流 2 = 包 17–32 源口 30001；`ip.src` 同步 10.0.1.1 → 10.0.1.2（用例 6 条断言逐条钉）。

**未覆盖的动态格（A′ 立项，不得冒充已覆盖）**：`h323.dst_port` 动态对象、`ip.ttl` 动态、`rand`/`list`/`pattern` 三种策略、`inc` 回绕（range 用尽）——G-H323-18。

---

## 13. P3 对接清单（T-H323 草稿输入；正文落 testcase 文件）

**17 ID（11 正 + 6 负）** + `packet_count`/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。

**A′ 候选（P4 接线，本版不建例）**：
- 载荷面：`h323_facility_h245`（FACILITY 载荷字节断言——**需先实现 H.245 PER**，G-H323-1）；
- RAS 面：`h323_ras_payload`（RAS 载荷字节断言——**需先实现 PER**，G-H323-4）；`h323_ras_in_full`（full + `ras.enabled`，G-H323-5）；
- 死配置面：`h323_rewrite_addr_effective`（重写生效的字节断言，G-H323-2）；`h323_ras_endpoint_gateway`（G-H323-3）；
- 边界面：`h323_display_254`（254 边界，G-H323-6）；`h323_crv_explicit_zero`（显式 0）；`h323_calls_upper`（65535 上界）；`h323_crv_overflow`（CRV 溢出 bit15，G-H323-9）；
- 拒绝分支面：`h323_neg_srcip` / `h323_neg_mss`（G-H323-14）；
- 动态面：`h323_dst_port_dyn` / `h323_ttl_dyn` / `h323_dyn_rand` / `h323_dyn_list` / `h323_dyn_pattern` / `h323_dyn_wrap`（G-H323-18）；
- 非正常结束：`h323_abort_rst`（G-H323-14）；
- 保活面：`h323_ras_keepalive`（周期 RRQ，G-H323-14）。

---

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 归属阶段 |
|---|---|---|
| **G-H323-1** | **H.245 隧道未实现**：FACILITY（0x62）载荷 = TPKT+Q.931 头+（无 IE，因 FACILITY 不带 BC IE）+Display IE，**无 `h245Control` / `H323-UserInformation` PER**；TCS/MSD/OLC/fastStart 全部未落码。`types.go:5570-5581` 注释声称"PER 字节模板/1440 字节 SETUP/18 fastStart OLC/NUL 终止符"与代码相反（§0 表 #1/#3/#4）。证据：`h323.go:359-411`、用例帧 4 = 29 字节 vs 参考 pcap 帧 4 = 1440 字节 | **代码阶段**（实现 PER 或改写注释为诚实边界；本版按实现钉） |
| **G-H323-2** | **`rewrite_addr` 死配置**：`chain_planner_translate.go:1300-1301` 写入 `spec.H323.RewriteAddr`，`grep -n "RewriteAddr" internal/protocol/h323/h323.go` **零命中**。用例 `h323_rewrite_addr` 只断 `frame.len` 83/83，**与 `h323_smoke_01` 全等**——证明不了任何重写行为。证据：`types.go:5605-5606` 注释声称"重写 PER 模板内嵌 IP/端口字节" | **代码阶段**（补实现或按 CORE_MEMORY §1.12 删键；用例须收窄口径） |
| **G-H323-3** | **`ras.endpoint_type` 死配置**：parse（`strategy_convert.go:4123`）+ validate（`:4125-4126`）+ translate（`chain_planner_translate.go:1357-1358`）三处接线，`grep -n "EndpointType" internal/protocol/h323/h323.go` **零命中** | **代码阶段**（补实现——GRQ/RRQ 的 endpointType 字段，或删键） |
| **G-H323-4** | **RAS 非 PER 编码**：载荷恒 8 字节手写 `00 <msgType> 00 01 <4B gkIP>`，非 H.225.0 §7 ASN.1 PER。`types.go:5593-5595` 注释声称"PER-encoded"与代码相反。附带：`gkIP` 解析失败时载荷**静默退化为 4 字节**（`h323.go:519-521`）。用例 `h323_scenario_ras` 只断 `udp.srcport/dstport`，**无 msgType 字段断言** | **代码阶段**（实现 PER 或改写注释；用例补载荷断言） |
| **G-H323-5** | **`full`/`tunnel_only` 场景忽略 `ras.enabled`**：`full` 分支（`h323.go:317-334`）只检查 `h.Media`，**从不检查 `h.Ras`**——`ras.enabled=true` + `scenario=full` 静默无 RAS。RAS 仅在 `ras_only` 分支发射（`:203-209`） | **代码阶段**（补 full 场景的 RAS 发射路径，或明确文档化"RAS 仅 ras_only"） |
| **G-H323-6** | **Display IE 边界不一致**：`Validate` 允许 `len ≤ 254`（`MaxDisplayNameLen`，`h323.go:89/144`），`buildDisplayIE` 却截断 253（`h323.go:405-407`）——254 字节输入**通过校验后被静默截掉 1 字节**（无告警）。无 254 边界用例 | **代码阶段**（对齐上界：Validate 改 253，或 buildDisplayIE 改 254 并扩长度字段语义） |
| **G-H323-7** | **派生流无显式关联字段**（CORE_MEMORY §3.8）：RTP/RAS 用 `flowID` 后缀（`:rtp`/`:ras`）作唯一关联手段，**无 `driven_by{session,transaction,field}`**；RTP 端口独立配置（5062/5063），**不随控制流/OLC 通告推导**（H.245 §7.3 的 OLC 端口协商未实现） | **代码阶段**（补关联字段或明确声明"派生流端口独立配置"为设计选择） |
| **G-H323-8** | **`h323_smoke_01` expect 形状与其余 10 正例不一致**：该例用 legacy 8 键集（`has_handshake`/`negotiated`/`terminates`/`has_payload`/`min_packets`/`fields`/`frames`/`notes`），其余正例用 `{packet_count, fields[, frames], notes}`；且 `min_packets=15` **低于实际 16**（弱断言，差 1 包不会红）。证据：机读实测（pos expect keysets 计数 1/1/9） | **代码阶段**（统一为 `packet_count`；删 legacy 布尔键） |
| **G-H323-9** | **CRV 溢出无守卫**：`callCRV = crv + uint16(callNum)`（`h323.go:286`）——`crv ≥ 0x8000` 起递增会污染 bit15 方向标志，使主叫方消息带被叫方标志。无用例 | **代码阶段**（加 `& 0x7FFF` 掩码或显式拒绝；补用例） |
| **G-H323-10** | **`data_only`/`ras_only` 忽略其余全部键**：提前 return（`h323.go:196-209`），`role`/`calls`/`crv`/`display_name`/`rewrite_addr` 全部无效（如 `calls=3` + `ras_only` 仍只发 8 包）。无文档化、无用例 | **代码阶段**（文档化该语义，或补用例钉住） |
| **G-H323-11** | **`calls` 口径三处冲突**：① legacy Validate `h323: calls must be >= 0`（`h323.go:140`）链路径**不可达**（registry `uint16 Min=0` → `-1` 在 `complete.go:315` 先拦，锚词 `not a numeric value`）；② flat parse `h323.calls must be >= 1`（`strategy_convert.go:4096`）**拒绝 `calls=0`**；③ legacy Plan `calls == 0 → 1`（`h323.go:190-193`）**接受 0**。②与③语义冲突。用例 `h323_neg_calls` 按 ① 口径钉 | **代码阶段**（统一三处口径；① 的死锚词删除或补可达路径） |
| **G-H323-12** | **结果产物链接失效**：`trafficgen/docs/protocol-pcap-test/h323.md`（tracked）内 12 条 pcap 相对链接指向 `trafficgen/docs/protocol-pcap-test/h323/`，该目录**不存在（0 个 pcap）**。**注意口径**：该 .md 末次提交 `62376e3`（**2026-09-19**）**晚于**判死提交 `0417be5`（2026-09-13），故**不构成"产物过期"缺口**（与 pcep G-PCEP-11 判定条件相反，结论为"不成立"）；本项**仅登记链接失效**，且**不得**作为"今日已复跑"依据（本车道未跑套件） | **代码阶段**（P5 重跑套件后重生成产物与 pcap 留档） |
| **G-H323-13** | **链路径强制 `Direction="up"` 的副作用**：`layer_gen.go:53` 覆写每包方向（防 raw-IP 驱动二次换向）——故 `role=callee` 时 down 侧发起的 Q.931 在 tshark 侧**不出 `q931.message_type`**（用例 `h323_role_callee` 自述"tshark 方向性伪影"），字节结构只能由 `frame.len` 承担。**附带**：TCP 拆线为 FIN/FIN/ACK 三次（非 RFC 9293 四次），末包后无对端 ACK，TCP 状态机未闭合（`h323.go:346-350`） | **代码阶段**（文档化伪影；补 `role=callee` 的字节级断言替代路径；拆线序列按规范或明确声明简化） |
| **G-H323-14** | **未入例的拒绝分支与场景**（A′）：legacy 锚词 `invalid SrcIP`/`invalid DstIP`（`h323.go:105/110`）、`TCP.MSS %d too small`（`:151`）、`H323Config is required`（`:116`）；flat 锚词 7 条（§7 末）；**RST 非正常结束无用例**（§3.15②）；**RAS 周期保活未实现**（§3.15③，H.225.0 默认 30 s RRQ） | **代码阶段**（A′ 补例；保活需先补实现） |
| **G-H323-15** | **消息类型面窄**：Q.931 只实现 6 种（缺 STATUS/STATUS ENQUIRY/INFO/PROGRESS/NOTIFY/SETUP ACK/USER INFO/SEGMENT/CONGESTION CONTROL）；RAS 只实现 8 种（缺 LRQ/LCF/IRQ/IRR/BRQ/BCF/RIP/RAC）；**无版本协商字段**（H.225 的 protocolIdentifier/version） | **代码阶段**（A′ 补例；或明确声明"最小可识别集"边界） |
| **G-H323-16** | **失败分支面为零**：无 Q.931 拒绝消息（无 Cause IE）、无 RAS 拒绝（reason）、无重试/超时/重连。§5.2 四件事的"失败分支"全为空（§4 最小清单"请求/响应、重试、重连、异常中断"中三项无例） | **代码阶段**（补拒绝路径实现 + 负例） |
| **G-H323-17** | **IE 链面窄**：只实现 Bearer Capability（固定 5 字节）+ Display（IA5）两种 IE；缺 Called/Calling Party Number、User-User（H.245 隧道的载体）、Cause、Channel Identification 等 | **代码阶段**（A′ 补例；User-User 与 G-H323-1 同源） |
| **G-H323-18** | **动态整格未覆盖**：`h323.dst_port` 动态对象、`ip.ttl` 动态、`rand`/`list`/`pattern` 三种策略、`inc` 回绕（range 用尽）——**今日零用例**（§12.12 末段）。仅 `h323.src_port` + `inc` 一格已覆（`h323_port_dyn`） | **代码阶段**（A′ 补例；CORE_MEMORY §9.32/§12.15 要求五类全覆） |
| **G-H323-19** | **负例 expect 含 `notes` 键**（6/6）：`{expect_error, error_contains, notes}`，非严格两键口径（§7 负例纪律） | **代码阶段**（收窄为两键） |
| **G-H323-20** | **`q931.*` 字段面未收编**：tshark 3.6.14 有 `q931.*` **156 字段**，用例只用了 `q931.message_type` 1 个；可用未用：`q931.disc`（恒 0x08）、`q931.call_ref_len`（恒 2）、`q931.call_ref`（CRV 数值）、`q931.call_ref_flag`（方向标志，可直接替代 `role_callee` 的 `frame.len` 伪影路径，G-H323-13）、`q931.information_transfer_capability`（BC IE）、`q931.cause_value`。**附带**：`h323_v6` 无 frames 断言（offset 74 未覆盖） | **代码阶段**（A′ 补字段断言；`call_ref_flag` 可解 G-H323-13 的断言空位） |

---

## 15. 修订记录

- v1.0.0（2026-09-29）：批次二文档车道 #117 h323 **首次成文**（本仓库无 h323 旧设计稿，`find` 零命中实证）。as-built 型：把既有实现（`h323.go` 598 行 + `layer_gen.go` 77 行 + `h323_test.go` 826 行 / 30 个 `Test*`）与既有 17 例（`cases/h323.json`）如实写成契约。§0 首次成文声明 + **7 条"代码注释声称 vs 实测"校正表**（PER 载荷未实现 / RAS 非 PER / 无 NUL 终止符 / "byte-for-byte" 语义澄清 / CRV 递增正确 / rewrite_addr 死配置 / endpoint_type 死配置）；§3 逐字节线格式（TPKT 4B / Q.931 头 5B / CRV bit15 / BC IE 5B / Display IE / TCP / RAS 8B / RTP 12B）含**逐消息长度公式**与 7 条实测帧算术复核；§4 五层覆盖；§5 状态机 + 事务四件事 + **五件套**（§3.8 关联字段缺位诚实登记）；§6 性能（信令 TPKT 上界 269 B → frame.len ≤ 323/343 B、单段、流式、零锁）；§7 负例锚词表 6 条（含 `h323_vn_presence` 形状点名）；§9 17 ID 表 + 包数公式；§10 P1 八项矩阵 + 子表①②③ + 三路对照 + PER 三方案对比；§11 D-H323-1 as-built 八要素；§12 门1 十四行 + §12.1/§12-P2/§12.3/§12.12 强制展开；§13 P3 对接清单（A′ 候选 16 条）；**§14 缺口 G-H323-1…G-H323-20（20 条，三要素齐）**。机读自审（脚本复核计数与断言，不手算）。仅文档，未动任何 `.go` / `cases/*.json` / `trafficgen/tools/**`。

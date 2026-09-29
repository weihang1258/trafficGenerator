# #121 mpls（MPLS · 多协议标签交换 L2.5 标签栈，RFC 3031/3032/5462）设计契约

> 版本：v1.0.0（P-PIPE 文档轨 批次二 · as-built 型）
> 日期：2026-09-29
> 车道：文档轨 #121 mpls（分支 `pipe/mpls-doc`，基 `300dfc4`）
> 存量用例：`trafficgen/test/protocol_pcap/cases/mpls.json`（**14 例 = 7 正 + 7 负**，ID/顺序/包数/断言与本版逐条一致，已机读实测 + **今日实跑复核**，见 §0.2）
> 规范基线：① **RFC 3032**《MPLS Label Stack Encoding》（标签栈项位域 §2.1 / 内层协议判定 §2.2 / TTL §2.4 / 分片 §3 / LAN 承载与 EtherType §5 / IANA 保留值 §6，下称 **R3032**）；② **RFC 3031**《Multiprotocol Label Switching Architecture》（标签语义 §3.1 / 标签栈 §3.9 / NHLFE 与 push-swap-pop §3.10 / 标签交换 §3.13 / LSP §3.15 / PHP §3.16 / TTL §3.23 / shim 位置 §3.25.1，下称 **R3031**）；③ **RFC 5462**《MPLS EXP Field Renamed to TC Field》（EXP→TC 改名与 §2.1 图重写，下称 **R5462**）；④ 本仓库落码（`internal/protocol/mpls/` 三文件 + `internal/core/builder.go` 栈写入 + 接线，§11）；⑤ 本机 tshark 3.6.14 `mpls.*` 字段表（**5 字段**，实测）与今日实跑 12 份 pcap（`/tmp/mpls-doc-verify/mpls/`）
> 白话一句：**给 IP 包套上一层"邮局分拣码"——每个码 4 字节（20 位标签号 + 3 位优先级 + 1 位"这是最后一层"标志 + 8 位寿命），可以套好几层；以太网头里写 0x8847 告诉对方"后面跟的是分拣码不是 IP"。本引擎只发"贴着码的 IP 包"（数据面），不发"商量贴什么码"的协商报文（LDP/RSVP 控制面）。**

---

## 0. 首次成文声明与"代码注释声称 vs 规范原文"校正表

**沿革**：`find . -iname "*mpls*" -not -path "./.git/*"` 实测——本仓库**没有 mpls 旧设计稿或旧用例文档**（`docs/protocol-designs/` 下 `ls | grep -i mpls` 零命中）。本 #121 是 mpls 的**首次成文契约**，不存在"承旧稿/校正旧稿"关系。

**唯一在案的历史层**：
- 实现决策记录 **D-MPLS-1** 见 `docs/CODE_DESIGN.md:2390-2470`（P-PIPE #16 门1，状态"已验收 2026-09-19"）与 `docs/TEST_CASES.md:3372-3400`（T-MPLS-1…14，P3 定稿）。本版 §11 将其收敛为 as-built 代码设计条目，**不搬其过时状态声明**。
- 结果产物 `trafficgen/docs/protocol-pcap-test/mpls.md`（**tracked**，`git ls-files` 可证）记 `Cases: 14 — pass 14, fail 0, error 0`，末次提交 `d62db10`（**2026-09-19**）。**该提交晚于扁平判死提交 `0417be5`（2026-09-13）**，故按批次二任务书口径**不构成"产物过期"缺口**（与 pcep G-PCEP-11 的判定条件相反，结论为"不成立"）；但该文件内 12 条 pcap 相对链接指向的 `trafficgen/docs/protocol-pcap-test/mpls/` 目录**不存在（0 个 pcap）**，链接全部失效 → G-MPLS-8。

### 0.1 代码注释声称 vs 规范原文（逐条机读校正，本版按规范原文钉）

**方法**：本版对落码（含 `builder.go` / `types.go` / `planner.go`，excl `_test`）里出现的每一个 `RFC 3031/3032 §` 引用做**行级归属清单**（2026-09-29；注意 grep 陷阱：`grep §3.1` 会连带命中 5 处 `§3.10`，须按行归属），再逐条回查 RFC 原文（rfc-editor.org / datatracker.ietf.org 实测拉取）。行级清单：`§3.1`=14 / `§3.10`=5 / `§3.9`=2 / `RFC 3031 §3.12`=1 / `§2.1`=9（正确）/ `RFC 5462`=2（正确）。结论：**错误 22 处，正确 11 处**。这是本版最重要的校正面——错误的条款号会误导后续实现者去查错章节。

| # | 机读清单（行号逐字，可复核） | RFC 原文实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | `§3.1`（位域/栈编码，**14 处**）：`builder.go:93/99/966/1062/1068/1097/1122`（7）+ `types.go:3309/3354/3363/3374/3379`（5）+ `planner.go:11/66`（2）【注：`builder.go:85/1018` 与 `types.go:3014/3365` 在 grep 里同时命中 `§3.1` 与 `§3.10` 子串，归入 #2，不重计】 | **R3032 §3.1 不存在**——§3 是 "Fragmentation and Path MTU Discovery"（§3.1 Terminology / §3.2 Maximum Initially Labeled IP Datagram Size / …）。位域与图（Figure 1）在 **§2.1 "Encoding the Label Stack"** | **条款号错（§3.1 → §2.1，14 处）**；位域内容本身**正确** |
| 2 | `§3.10`（EtherType 与标签值，**5 处**）：`builder.go:85/1018`（EtherType 0x8847/0x8848，2）+ `types.go:3014/3330`（EtherType，2）+ `types.go:3365`（标签值，1） | **R3032 §3.10 不存在**（§3 只到 §3.6）。EtherType 在 **§5 "Transporting Labeled Packets over LAN Media"**；保留标签语义（0/1/2/3/4-15）在 **§2.1**（字段说明）与 **§6 "IANA Considerations"** | **条款号错（§3.10 → §5 或 §2.1+§6，5 处）**；取值内容**正确** |
| 3 | `§3.9`（内层是 IP，**2 处**）：`planner.go:48`（"MPLS labels any IP packet"）+ `builder.go:1113`（"inner L3 is the flow's own IPv4/IPv6 packet"） | **R3032 §3.9 不存在**（§3 只到 §3.6）。内层协议判定在 **§2.2 "Determining the Network Layer Protocol"**；"protocol-dependent procedures for IPv4 and IPv6" 在 **§1** | **条款号错（§3.9 → §2.2+§1，2 处）**；语义方向**正确** |
| 4 | `RFC 3031 §3.12`（in place，**1 处**）：`planner.go:99` | **R3031 §3.12 = "FEC-to-NHLFE Map (FTN)"**——与"in place"无关。"shim 在数据链路层头与网络层头之间"在 **§3.25.1** 与 **§3.23** | **条款号错（§3.12 → §3.25.1，1 处）**；语义方向**正确** |
| 5 | `§2.1`（**9 处**，正确）：`builder.go:1079/1096/1099/1118/1128`（5）+ `types.go:3311/3322`（2）+ `planner.go:62/72`（2） | **R3032 §2.1 正确**（原文："This bit is set to one for the last entry in the label stack" / "The label stack entries appear AFTER the data link layer headers, but BEFORE any network layer headers"） | **条款号正确**（保留，本协议正确的 RFC 3032 引用面） |
| 6 | `RFC 5462`（TC 3 位，**2 处**，正确）：`planner.go:69` + `types.go:3370` | **R5462 §1/§2.1 正确**（原文："This document changes the name of the field to the 'Traffic Class field' ('TC field')"） | **条款号正确**（保留） |
| 7 | 无条款号的正确声明（**2 条**）：`planner.go:11` 的"LDP/RSVP out of scope"（R3031 §3.6 属控制面 ✓）；`types.go:3303-3306` + `builder.go:1100` 的"内层 L3/L4 零 MPLS 感知"（R3032 §2.2 ✓） | — | **声明正确**（保留，本实现的关键正确性事实） |

**校正总账**：错误 **22 处** = `RFC 3032 §3.1`（14）→ **§2.1**；`RFC 3032 §3.10`（5）→ **§5**（EtherType 4 处）/**§2.1+§6**（标签值 1 处）；`RFC 3032 §3.9`（2）→ **§2.2 + §1**；`RFC 3031 §3.12`（1）→ **§3.25.1**。**保留正确**：`RFC 3032 §2.1`（9 处）、`RFC 5462`（2 处）、2 条无条款号的正确声明。**全部 22 处均为"指向不存在的章节或指向另一主题的章节"**（RFC 3032 §3 只到 §3.6，故 §3.9/§3.10 均不存在；RFC 3031 §3.12 存在但主题是 FTN）——本版全文按校正后的条款号书写，**缺口登记 G-MPLS-1**（代码注释待修，属代码阶段动作，本车道不改代码）。

**依赖链判定纪律**：以上均为可判题（落码注释原文 → RFC 原文逐章对照），直接判定，不问偏好。不可判的（RFC 3031 是否另有"in place"表述的旁证章节）标"待确认"并写清确认方式（G-MPLS-1 附注）。

### 0.2 今日实跑复核（2026-09-29，本车道亲跑）

本车道**实跑了** mpls 套件（与 §0 中 h323/opcua 车道的"未跑"声明不同——本协议可跑且已跑）：

```
PCAP_ROOT=/tmp/mpls-doc-verify MCP_API_KEY=dev-mcp-key CASE_PROTO=mpls \
  go test ./test/protocol_pcap/ -run TestProtocolPcapDrive -count=1
→ RESULT: 14 pass, 0 fail, 0 error (of 14)
```

| 复核项 | 方法 | 结果 |
|---|---|---|
| 套件结论 | 上命令（`-v`） | **14 pass / 0 fail / 0 error**（与 tracked 产物 `mpls.md` 的 14/14 **一致**） |
| 12 份 pcap 落盘 | `PCAP_ROOT` 指向**本车道私有目录** `/tmp/mpls-doc-verify/`（**未覆盖共享 `/tmp/mcp-pcaps/mpls/`**） | 12 个文件（7 正 `.pcap` + 5 负 `.neg.pcap`，两例 create-time 负例无落盘） |
| 28 条 field 断言 | 脚本逐条对 `tshark -T fields` 实读值比对（非手算） | **28/28 命中，0 处不符** |
| 1 条 frame 断言 | 脚本按 `frame.len` 切帧后取 `offset 14` 前缀匹配 | **命中**（`00 06 41 40`） |
| 包数 | `packet_count`/`min_packets` 对实读帧数 | **7/7 正例一致**（1/3/1/1/1/1/2） |
| 负例 | `.neg.pcap` 帧数 | **5/5 task-time 负例 = 0 帧**；2 例 create-time 负例**无落盘**（create 期即拒，见 §7） |
| 与 2026-09-27 存盘产物对账 | 同用例双跑，逐字段 `md5sum` 比对 | **7/7 解码字段完全一致**（文件字节含时间戳故 `cmp` 有差，字段面无差——**先跑后钉复核通过**） |

**结论**：本协议存量 14 例**今日在案且全绿**，断言逐条可执行且命中。这与 h323 车道的"未跑"、opcua 车道的"过期产物未证实"均不同——**本协议的 14/14 有今日实证**。tracked 产物 `mpls.md` 的 12 条相对链接失效（目录不存在）仍作缺口登记（G-MPLS-8），但**其 14/14 数字本身今日已被独立复核证实**。

---

## 1. 范围、profile 与实现状态边界

本版定义 **MPLS 数据面**的流量生成：以太网承载的带标签 IP 包（MPLS over Ethernet，EtherType 0x8847/0x8848），标签栈 1..N 层，内层 IPv4/IPv6 + TCP/UDP。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `mpls_eth_unicast_v1`（主） | 以太网，EtherType **0x8847** | 1..N 层标签栈 + 内层 IPv4/IPv6 TCP/UDP；单帧/多帧；up/down | 真实 LSR 转发表、真实 LSP 建立过程 |
| `mpls_eth_multicast_v1` | 同上，仅 EtherType **0x8848**（`multicast:true`） | 同主 profile | 真实组播树/组播标签分配 |
| `mpls_ipv6_inner_v1` | 同上，仅**内层** IPv6（外层 EtherType 仍是 0x8847） | 同主 profile | 从 IPv4 fixture 推导 IPv6 地址 |

显式边界（"不实现、不声称、不许静默转换"）：

1. **不实现控制面**——LDP（RFC 5036）/ RSVP-TE（RFC 3209）标签分发、LSP 建立、FTN/ILM 表、PHP 触发，全部 out of scope（R3031 §3.4/§3.6/§3.16）。本引擎只发"已贴好标签的包"，**不声称**该包能被真实 LSR 正确转发。
2. **不实现 push/swap/pop 操作本身**——本引擎**恒为 ingress 语义**：把配置里的标签栈**原样写进帧**（R3031 §3.10 的 "push" 面）。"swap"（替换栈顶）与 "pop"（弹栈）是 LSR 的转发行为，本引擎**不模拟**（§3.5 展开）。
3. **不实现 TTL 递减**——R3032 §2.4.1 的 outgoing TTL = max(incoming−1, 0) 是**转发**规则；本引擎是源端，只**写** TTL，不**算** TTL（§3.5）。
4. **不实现分片/PMTU**（R3032 §3）——超长内层包不做 MPLS 分片，不做 Path MTU Discovery 交互。
5. **不实现 MPLS over PPP/ATM/帧中继**——只做以太网承载（R3032 §4.3 的 PPP 0x0281/0x0283 不在本版；§5 的 802.3 LLC/SNAP 亦不在本版）。
6. **不实现保留标签的特殊语义**——0/1/2/3 与 4-15 作为**普通 20 位数值**写入，不触发 Explicit-Null 弹栈、不触发 Router Alert 处理（§3.1 取值表 + G-MPLS-4）。
7. **不实现标签栈与 GRE/PPPoE 的组合**——builder 显式拒绝（§3.6），三者都是"以太网头与 IP 头之间"的封装层，长度会歧义交织（`builder.go:1106/1109`）。

**实现状态（2026-09-29 实测）**：`mpls` 层已注册（`registry.go:1811`，`CategoryTerminal`，`DependsOn ["ip"]`，**Fields 8 键无 Default**）；planner 已落码（`internal/protocol/mpls/planner.go` 224 行 + `layer_gen.go` 78 行 + `planner_test.go` 464 行，`wc -l` 实测；**12 个 `Test*`**，`grep -c` 实测）；builder 侧标签栈写入已落码（`builder.go:1075 writeMPLSLabels` + `:1104 validateMPLSConfig`）；`allowedProtocols["mpls"]=true`（`protocols.go:48`）；层内 translate 已接线（`chain_planner_translate.go:1380`）；presence 判死已接线（`strategy_convert.go:8947`）；静态复制门已扩扫（`schema/semantic.go:214`）；端口动态已开（`layer_dyn.go:53`）；raw-IP 自驱已接线（`chain_planner_util.go:49`）；14 语义用例已落 `cases/mpls.json` 且**今日实跑全绿**（§0.2）。

**输出契约（pcap/NIC 双输出）**：两路径共用**同一 cases JSON 与同一断言集**（`eth.type` / `mpls.label` / `mpls.exp` / `mpls.bottom` / `mpls.ttl` / `ip.src` / `ip.dst` / `ip.id` / `ipv6.src` / `ipv6.hlim` / `udp.srcport` / `udp.dstport` / `tcp.srcport` / `tcp.dstport` / `data.data` 字段 + `offset 14` frames 原始字节）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。**注**：本车道实跑的是 pcap 路径（§0.2），NIC 路径今日**未跑**（框架能力，本层零专属断言 → G-MPLS-9）。

---

## 2. 协议栈、端口和固定偏移

推荐层链为 **`[ip, mpls]`**（raw-IP 自驱终层，链内**无 tcp/udp 层**——mpls 生成器自产完整包）。这是本协议与其他绝大多数协议的**结构性差异**：标签栈是 L2.5 层，位于以太网头与 IP 头之间，**不是任何传输层的载荷**。

```
+------------------+--------------------------------+---------------------------+
| Ethernet (14B)   | MPLS label stack (4B × N)      | inner IPv4/IPv6 + TCP/UDP |
| type = 0x8847/48 | Label(20)|TC(3)|S(1)|TTL(8)      | (流自己的那个 IP 包)       |
+------------------+--------------------------------+---------------------------+
 offset 0            offset 14                        offset 14 + 4N
```

**固定偏移**（无 VLAN 时）：

| 层 | 偏移 | 长度 |
|---|---|---|
| 以太网头 | 0 | 14 |
| **标签栈第 1 层（栈顶）** | **14** | **4** |
| 标签栈第 N 层（栈底） | 14 + 4(N−1) | 4 |
| **内层 L3 头起点** | **14 + 4N** | 20（IPv4）/ 40（IPv6） |

**总长度公式**：

```
以太帧长 = 14（Eth） + 4×N（标签栈） + 内层L3长 + 内层L4长 + payload
         = 14 + 4N + (20 或 40) + (8 UDP 或 20 TCP) + len(payload)
```

**标签栈总长 = 4 × N 字节**（N = 栈层数，`len(labels)`）。**无 VLAN 时栈起点恒 offset 14**；有 VLAN 时栈起点 = 18（`builder.go:1024-1027`：`mplsOff = 14`，`if VLAN != nil { mplsOff = 18 }`），本协议存量 14 例**均无 VLAN**。

**关键正确性事实（R3032 §2.1 的"栈在网络层头之前"）**：标签栈**不计入** IP 头的 Total Length 字段——`builder.go:319` 把栈长计入 `l2Len` 而非 `l3Len`，故内层 IP 的 Total Length 与**未打标签时完全相同**。这是本实现"内层 IP 头零 MPLS 感知"（§0.1 #10）的直接体现，今日实跑实证：`mpls_single_label_ipv4` 帧 @offset 16-17 = `00 21` = 33 = 20（IP 头）+ 8（UDP）+ 5（payload `probe`）——**不含 4 字节标签栈**。

**端口**：MPLS **没有端口概念**（L2.5 层，无传输层头）。链内无 tcp/udp 层，故 `validateBaseDstPortHandled` 把 mpls 列入豁免名单（`chain_planner.go:758`），**源/目的端口 0 合法**（`chain_planner.go:996` 注释：raw-IP 路由终结层无端口概念）。但**内层** L4 端口是真实存在的——它住 `mpls` 层的 `src_port`/`dst_port` 两键（1.2 已批偏离，h323 同款），translate 期落 `spec.SrcPort`/`spec.DstPort`（`chain_planner_translate.go:1447-1457`）。fixture 统一 `src_port=12345`、`dst_port=80`；用例一律显式写端口并纳入断言。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**本协议存量 14 例已是此形，无迁移工作量**，见 §12.1）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"mpls": {"src_port": 12345, "dst_port": 80, "labels": [{"label": 100}], "inner_payload": "probe"}}
  ]
}
```

多流样例（数量只走 `flow_control`；动态端口住 `mpls` 层，**不能**写 `tcp.src_port`——链内无 tcp 层）：

```json
{
  "layers": [
    {"ip": {"src": {"strategy": "inc", "range": ["10.0.1.1", "10.0.1.2"], "step": 1}, "dst": "20.0.0.1"}},
    {"mpls": {"src_port": {"strategy": "inc", "range": [30000, 30001], "step": 1}, "dst_port": 80, "labels": [{"label": 100}]}}
  ],
  "group_id": {"strategy": "fixed", "value": "mpls-port-dyn"}
}
```

（存量 `mpls_port_dyn` 用 `strategy_fc: {"type":"flows","value":2}` 而非 `flow_control`；两者都是框架结构键，§12.1 表内说明。）

---

## 3. 线格式编码（逐字节，按代码钉）

### 3.1 标签栈项（4 字节/层，位域非字节对齐；R3032 §2.1）

**这是本协议的核心位域结构**——**20 位字段不落在字节边界上**，必须按位移拼装，不能按字节读写。

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Label                  | TC  |S|       TTL      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|<------- 20 bits ------>|<-- 3 -->|<-1->|<----- 8 bits ------->|
```

| 位域 | 位宽 | 位偏移（自 32 位字最高位起） | 值域 | 默认 | 编码 |
|---|---:|---:|---|---|---|
| **Label** | **20** | 31..12 | 0 – 0xFFFFF（1048575） | **无缺省**（必填；空栈拒） | 20 位无符号，网络序字的高 20 位 |
| **TC** | **3** | 11..9 | 0 – 7 | 0（`omitempty`，缺省不写即 0） | 3 位无符号；R5462 前称 EXP |
| **S** | **1** | 8 | 0 / 1 | **栈底自动置 1**（用户可省） | 1 位布尔 |
| **TTL** | **8** | 7..0 | 0 – 255 | 0 → **64**（`DefaultMPLSTTL`） | 8 位无符号 |

**拼装公式**（`writeMPLSLabels`，`builder.go:1075-1093`，逐字）：

```go
entry := (l.Label & 0xFFFFF) << 12   // Label: 20 bits → 字的高 20 位
entry |= uint32(l.TC&0x07) << 9      // TC:    3 bits → 位 11..9
if s { entry |= 1 << 8 }             // S:     1 bit  → 位 8
entry |= uint32(ttl)                 // TTL:   8 bits → 位 7..0
binary.BigEndian.PutUint32(dst[i*4:], entry)   // 网络序（大端）32 位字
```

**端序**：**大端（网络序）**——整项作为一个 32 位字用 `BigEndian.PutUint32` 写入（`builder.go:1091`）。**这与"逐字段独立端序"无关**：位域拼装后整体大端输出，无字段级端序差异。

**逐层顺序**：`dst[i*4]`，i = 0 为**栈顶**（transmission order，最先被 LSR 处理的层），i = N−1 为**栈底**（R3032 §2.1：栈顶最早出现）。

**TTL 缺省**：`ttl == 0` → 写 **64**（`builder.go:1081-1084`；`DefaultMPLSTTL = 64`，`builder.go:101`）。**这与内层 IP TTL 的缺省值同源**（`builder.go:1165-1168` IPv4 与 `:1260` IPv6 同样 0→64），语义是"MPLS TTL 镜像 IP TTL"（R3032 §2.4.3：首次打标签时标签 TTL **MUST** 取 IP TTL 值——本实现取同一缺省常量 64 以符合该 MUST 的精神）。

**S 位自动纠正**（`builder.go:1077-1080`，逐字）：

```go
s := l.S
if i == len(mpls.Labels)-1 {
    s = true   // bottom of stack (RFC 3032 §2.1) — auto-correct
}
```

即：**最后一层恒写 S=1，无论用户写没写**；**非栈底写 S=true 是明确矛盾，由 `validateMPLSConfig` 拒绝**（`builder.go:1123`，锚词 `not the bottom of stack`）。这条"自动纠正 + 显式矛盾拒绝"的双面设计使"用户漏写 S"与"用户写错 S"分别得到正确与报错两种结果，无静默错帧。

**长度上限**：`Label > 0xFFFFF` 拒（`builder.go:1119` / `planner.go:66`）；`TC > 7` 拒（`builder.go:1122` / `planner.go:69`）。**两层门**（planner 的 Validate 与 builder 的 validateMPLSConfig）**文案逐字相同**（§7 锚词表）。

### 3.2 EtherType 强制（0x8847 / 0x8848；R3032 §5）

`writeL2`（`builder.go:1017-1033`，逐字）：

```go
if config.L2.MPLS != nil {
    mplsOff = 14
    if config.L2.VLAN != nil { mplsOff = 18 }
    if config.L2.MPLS.Multicast { etherType = EtherTypeMPLSMulticast }  // 0x8848
    else                        { etherType = EtherTypeMPLSUnicast   }  // 0x8847
}
```

| 值 | 常量 | 触发 |
|---|---|---|
| **0x8847** | `EtherTypeMPLSUnicast`（`builder.go:89`） | `multicast` 缺省/false（**unicast**） |
| **0x8848** | `EtherTypeMPLSMulticast`（`builder.go:90`） | `multicast: true` |

**强制语义**：MPLS 存在时 EtherType **恒取上表二值**，**无视** `L2Config.EtherType`（`builder.go:1019-1021` 注释："regardless of L2Config.EtherType, which still selects the INNER L3 layout"）。这是"双面职责分离"：EtherType 字段在线上表达"后面是标签栈"，而 `L2Config.EtherType` 转而表达"**栈底之后**是 IPv4 还是 IPv6"。

**与 VLAN 共存**：有 VLAN 时标签栈起点 = 18，EtherType 写在 offset 16-17（`builder.go:1036-1040`：TPID `0x8100` @12-13、VLAN tag @14-15、etherType @16-17）。本协议存量 14 例**无 VLAN 例**（G-MPLS-5）。

### 3.3 内层 L3 解析（栈底之后的协议判定；R3032 §2.2）

R3032 §2.2 明确：**标签栈内不含显式网络层协议字段**，内层协议靠栈底标签值 + 头部检查推断。本实现按**配置**而非按栈底标签值推断（因为本引擎是 ingress，标签值是用户给的、不承担"告知内层协议"的职责）：

`Build`（`builder.go:189-198`，逐字）：

```go
if config.L2.MPLS != nil &&
    (effectiveEtherType == EtherTypeMPLSUnicast || effectiveEtherType == EtherTypeMPLSMulticast) {
    effectiveEtherType = EtherTypeIPv4    // 默认内层 IPv4
}
```

| `L2.EtherType`（配置侧） | 内层 L3 | 线上 EtherType | 依据 |
|---|---|---|---|
| `0`（缺省） | **IPv4** | 0x8847/0x8848 | `builder.go:189-198` 默认分支 |
| `0x0800` | IPv4 | 0x8847/0x8848 | `EtherTypeFor` 对 v4 地址返回 0x0800 |
| `0x86DD` | IPv6 | 0x8847/0x8848 | `EtherTypeFor` 对 v6 地址返回 0x86DD |
| `0x8847`/`0x8848` | **IPv4**（兜底） | 0x8847/0x8848 | 同默认分支（`:196`） |
| 其他（如 0x0806 ARP） | — | — | **拒**（`validateMPLSConfig:1115`，锚词 `inner layer must be IP`） |

**内层族选择路径**：planner 的 `L2.EtherType = core.EtherTypeFor(srcIP)`（`planner.go:208`），即**按流地址族自动选内层 IPv4/IPv6**（`EtherTypeFor`，`builder.go:125-134`：`net.ParseIP` 后 `To4() != nil` → 0x0800，否则 0x86DD）。今日实跑实证：v6 例 `mpls_v6` 帧 @12-13 = `88 47`（外层仍是 MPLS unicast），内层 @18 = `62`（IPv6 版本号 6 + TrafficClass 高位）。

**非 IP 内层拒**（`builder.go:1111-1116`）：`validateMPLSConfig` 的 `switch effectiveEtherType` 只放行 `EtherTypeIPv4`/`EtherTypeIPv6`，其余（含 ARP 0x0806）拒——锚词 `mpls: inner layer must be IP (EtherType 0x0800/0x86DD), got 0x%04x`。

### 3.4 内层 L3/L4 头（零 MPLS 感知）

**本实现最关键的正确性事实**：内层 IP 头与 TCP/UDP 头**按未打标签时的同一代码路径装配**，无任何 MPLS 分支：

- **IPv4**（`writeL3v4`，`builder.go:1150+`）：Version/IHL `0x45`、TOS = `(DSCP<<2)|ECN`、Total Length = `20 + payloadLen`（**不含标签栈**）、IP ID、Flags/FragOffset、TTL、Protocol、Header Checksum（标准 RFC 791 反码和）、SrcIP、DstIP。
- **IPv6**（`writeL3v6`，`builder.go:1220+`）：Version 6、TrafficClass、FlowLabel=0、PayloadLength = `payloadLen`、NextHeader、HopLimit、SrcIP、DstIP。
- **L4**：TCP/UDP 头与校验和由 `buildL4` 常规路径写；**伪头部校验和**按内层 IP 族算（IPv4 用 4 字节地址、IPv6 用 16 字节地址）。

**实证（今日实跑）**：

| 用例 | 帧 | 内层 @offset | 证据 |
|---|---|---|---|
| `mpls_single_label_ipv4` | 1 | 18 | `45 20 00 21 00 01 40 00 40 11 1c aa 0a 00 00 01 14 00 00 01` = IPv4 v4/IHL5、TOS 0x20（DSCP 8 = CS1，框架缺省）、TotalLen **0x21=33**（= 20+8+5，**不含 4B 栈**）、ID 1、DF、TTL 64、proto 17 UDP、checksum 0x1caa、10.0.0.1→20.0.0.1 |
| `mpls_inner_tcp` | 1 | 18 | 同前缀但 `40 06`（TTL 64 / proto **6** TCP）、TotalLen `0x28`=40（= 20+20+0） |
| `mpls_v6` | 1 | 18 | `62 00 00 00 00 08 11 40 20 01 0d b8 ...` = IPv6 ver6、TC 0x20、FlowLabel 0、PayloadLen **8**、NextHeader 17（UDP）、HopLimit **64**、2001:db8::1 |
| `mpls_frames_multi` | 1/2/3 | 22 | IP ID `0x0001`/`0x0002`/`0x0003`（逐帧 +1，§5 自动派生） |

**注意 DSCP 缺省 0x20 的来源**：帧 @offset 17 = `20` 不是 mpls 层的行为，是**框架级** `DefaultDSCP = 0x08`（CS1，`strategy_convert.go:64`）经 `mapToFlowSpec`（`:346`）填 `spec.DSCP`，再经 `finalEmit`（`chain_planner.go:1564`）写 `pkt.L3.DSCP`。**存量 14 例无一条断言 DSCP**（G-MPLS-6：A′ 候选，收编 `ip.dsfield`）。

### 3.5 标签栈操作与 TTL 处理（**如实声明：本引擎只做 push，不做 swap/pop，不减 TTL**）

R3031 定义 LSR 的三种标签操作（**§3.10 "The Next Hop Label Forwarding Entry (NHLFE)"**，逐字）：① "replace the label at the top of the label stack with a specified new label"（**swap**）；② "pop the label stack"（**pop**）；③ "push one or more specified new labels onto the label stack"（**push**）。

**本引擎的对应关系（诚实声明，不夸大）**：

| 操作 | 规范出处 | 本引擎行为 | 用例覆盖 |
|---|---|---|---|
| **push** | R3031 §3.10（③） | **等价**——planner 按配置把 N 层标签**原样**写进帧（`planner.go:179-180`：`mplsCfg := *cfg; mplsCfg.Labels = labels`，逐帧复用同一栈）。**无真实 push 的"新标签由下游分配"语义**（标签值来自配置） | `mpls_single_label_ipv4`（N=1）、**`mpls_multi_label`（N=2）——今日无例，A′ 立项 G-MPLS-2** |
| **swap** | R3031 §3.10（①） | **不实现**——本引擎是 ingress，不模拟中间 LSR 替换栈顶 | **不适用**（无 LSR 中间态） |
| **pop** | R3031 §3.10（②） | **不实现**——不模拟 PHP（R3031 §3.16 Penultimate Hop Popping）弹栈 | **不适用**（同上） |

**TTL 处理（R3032 §2.4 逐条对照）**：

| 规范条款 | 原文要点 | 本引擎行为 |
|---|---|---|
| §2.4.1 Definitions | incoming TTL = 收到时栈顶 TTL；outgoing TTL = max(incoming−1, 0) | **不适用**——本引擎无"收到"环节（源端生成） |
| §2.4.2 Protocol-independent rules | outgoing TTL = 0 → 不转发且不得弹栈；转发时**必须**把栈顶 TTL 置为 outgoing 值 | **不适用**（同上） |
| §2.4.3 IP-dependent rules | **"When an IP packet is first labeled, the TTL field of the label stack entry MUST BE set to the value of the IP TTL field."** | **符合**——planner 把标签 TTL 0 解析为 `DefaultMPLSTTL = 64`（`planner.go:133-139`），内层 IP TTL 缺省同为 64（`builder.go:1165-1168`），二者**同源常量**，故"首次打标签时标签 TTL = IP TTL"在本实现的缺省路径上成立。**显式分歧路径**：用户可显式写 `labels[].ttl` ≠ `ip.ttl`，本引擎**不校验二者一致**（G-MPLS-3：A′ 候选——拒或告警） |
| §2.4.4 Translating Between Different Encapsulations | LC-ATM 互操作 | **不适用**（ATM 不在本版） |

**结论（写入契约，防止后续误读）**：本引擎的标签栈是**静态声明的栈**，`labels[]` 的每一层原样上线；`TTL` 只写不算；`S` 位自动纠正；**无 push/swap/pop 的动态语义，无 TTL 递减，无 PHP**。任何"MPLS 转发行为"的断言（如"经过 3 跳后 TTL 减 3"）在本引擎**不可表达**，不得写入用例。

### 3.6 与 GRE / PPPoE 的互斥（`validateMPLSConfig`，`builder.go:1104-1128`）

三条拒绝（逐字）：

| 条件 | 锚词 |
|---|---|
| `L2.GRE != nil` | `mpls: cannot combine MPLS with GRE (both are encapsulations between the Ethernet and IP layers)` |
| `L2.PPPoE != nil` | `mpls: cannot combine MPLS with PPPoE (both are encapsulations between the Ethernet and IP layers)` |
| 内层非 IP | `mpls: inner layer must be IP (EtherType 0x0800/0x86DD), got 0x%04x` |

**理由**（`builder.go:1100-1103` 注释）：三者都是"以太网头与 IP 头之间"的封装层，长度会歧义交织。**注**：这三条**今日零用例**（G-MPLS-7，A′ 候选）。

### 3.7 缺省与二态语义（translate 镜像 parse；`chain_planner_translate.go:1380-1460`）

**parse 零缺省 → translate 零缺省**（`strategy_convert.go:4333 parseMPLSConfig` 与 `chain_planner_translate.go:1388-1444` 逐键镜像）：**所有缺省都在 legacy `Plan` 内填**，这是本协议比 h323 更简的一处（D-MPLS-1 决策 C1）。

| 键 | 缺省行为 | 落点 |
|---|---|---|
| `labels` | **无缺省**——空/缺席 → `spec.MPLS.Labels = nil` → Validate 拒（锚词 `label stack must contain at least one entry`） | `planner.go:61-63` |
| `multicast` | false（unicast 0x8847） | `builder.go:1028-1032` |
| `inner_proto` | **0 = auto**：`spec.TCP != nil` → 6，否则 → 17（**链路径恒 17**，见下） | `planner.go:110-117` |
| `src_port` / `dst_port` | 链路径无缺省（层值直落 spec；worker 多流保底 `12345+i`） | `chain_planner_translate.go:1447-1457` |
| `frames` | 0 → **1** | `planner.go:118-121` |
| `direction` | `""` → **`"up"`** | `planner.go:122-125` |
| `inner_payload` | nil → **`spec.Payload`**（`planner.go:126-129`）；两者皆空 → 空载荷（帧被以太网 padding 补到 60） | 同左 |
| `labels[].ttl` | 0 → **64**（`DefaultMPLSTTL`） | `planner.go:133-139` + `builder.go:1081-1084` |
| `labels[].tc` | 0 | `omitempty` |
| `labels[].s` | 栈底**自动置 1**（§3.1） | `builder.go:1077-1080` |

**链路径 `inner_proto=0` 恒解析为 UDP（诚实声明）**：`inner_proto` 0 的 auto 分支判 `spec.TCP != nil`（`planner.go:111-116`），而 **`spec.TCP` 在链路径下恒为 nil**——`spec.TCP` 的唯一来源是扁平顶层 `tcp` 子映射（`strategy_convert.go:446`），链配置下不可达。故 **`inner_proto: 0` 与 `inner_proto: 17` 在链上等价**；内层 TCP 只能靠**显式** `inner_proto: 6` 表达，且此时 TCP 头是**裸头**（`l4.Seq/Ack/Flags/WindowSize` 全 0，因为 `spec.TCP == nil` 使 `planner.go:189-194` 的赋值分支不可达）——见 `mpls_inner_tcp` 用例的 notes 与 G-MPLS-10。

---

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明标签栈（每层的 label/TC/TTL）、内层协议与端口、帧数、方向，引擎按固定剧本产出带标签的 IP 帧（无握手、无挥手、无状态机——因为无传输层）。

**MPLS 的现网位置（业务背景）**：MPLS 是运营商骨干网的核心转发机制——入口 LSR（ingress）给 IP 包**压入**标签栈（push），中间 LSR 按栈顶标签**换标签**（swap），倒数第二跳**弹栈**（PHP），出口 LSR 交付裸 IP 包。**本引擎只覆盖 ingress 的那一刻**：一个 IP 包被贴上标签后刚上线的形态。这对**测试网络设备/DPI/流量分析系统**是有效输入（"给我一批带标签的包，我要验证我的解析器/分流器/负载均衡器能不能正确解封装"）。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 单层标签基线（最常见的 LSP 数据面） | 1 层标签 + 内层 IPv4/UDP 单帧 | #1（`mpls_single_label_ipv4`） |
| ② 单层标签内层 TCP | 同 ①，内层 TCP 裸头 | #12（`mpls_inner_tcp`） |
| ③ 多层标签栈（标签栈嵌套 / VPN 双层标签） | 2 层标签 + 内层 IPv4 | **今日无例 → A′ 立项（G-MPLS-2）** |
| ④ 逐帧发送（同一 LSP 上的连续包） | `frames=N`，每帧独立 IP ID | #9（`mpls_frames_multi`） |
| ⑤ 反向方向（回程流量） | `direction: down`，地址+MAC 交换 | #10（`mpls_direction_down`） |
| ⑥ 组播 MPLS（0x8848） | `multicast: true` | #11（`mpls_multicast`） |
| ⑦ 双栈内层（IPv6 骨干） | 内层 IPv6 | #13（`mpls_v6`） |
| ⑧ 多流（多条 LSP 并发） | `flows=2` + 动态端口 | #14（`mpls_port_dyn`） |
| ⑨ 配置错误拒绝（运维配错） | 7 条负例 | #2–#8 |

**五层覆盖逐层结论**：

- **功能层**——数据面 push 正例（#1/#9/#10/#11/#12/#13/#14 七例）+ 拒绝分支 7 类负例（#2–#8，覆盖 presence/静态复制/标签上界/TC 上界/S 位/InnerProto/Direction）。**控制面（LDP/RSVP）显式不适用**（§1 边界①）。
- **性能层**——最小帧（单标签 + 空载荷 → 以太网 padding 到 60，实跑实证）；多帧（`frames=3`，IP ID 递增）；**跨 MSS 分段显式不适用**（本层无分段概念，raw-IP 自驱不发 TCP 段）；标签栈深度上界**无代码上限**（`labels` 为 list，仅受每层 20 位值域约束；今日用例 N=1，N=2 立项 G-MPLS-2）。
- **数据场景层**——值域：`label` 100（正常）/ 1048576（上界+1 拒）；`tc` 0（缺省）/ 8（上界+1 拒）；`s` 缺省（自动纠正）/ 非栈底 true（拒）；`ttl` 0（→64 缺省）/ **显式值今日无例（G-MPLS-11）**；`multicast` off/on；`inner_proto` 0/17/6/1（拒）；`direction` 缺省/up/down/sideways（拒）；`frames` 缺省 1 / 3；`inner_payload` "probe"（实跑 `data.data = 70726f6265`）/ **缺席今日无独立例（G-MPLS-11）**。
- **地址与流层**——**IPv4 与 IPv6 均覆盖**（#1–#12/#14 为 IPv4，**#13 为内层 IPv6**）；**注意本协议的"地址族"指内层 L3 族**（外层恒为 MPLS EtherType，无 IP 外层），这是与所有其他协议的又一处结构差异。单流基线 = #1；**多流** = #14（`flows=2`，端口动态）；**流关联（控制流派生数据流）显式不适用**——MPLS 数据面无控制流，LSP 是**预先存在**的转发状态（§1 边界①）。
- **业务层**——现网典型（单层 LSP 数据面、组播、IPv6 骨干、多 LSP 并发）落点见上表 ①–⑧；**多会话显式不适用**（无会话概念，§5）；**多事务显式不适用**（无请求/响应，§5）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① LDP/RSVP 控制面（§1 边界①）；② swap/pop/PHP（§3.5）；③ TTL 递减（§3.5）；④ 分片/PMTU（§1 边界④）；⑤ PPP/ATM 承载（§1 边界⑤）；⑥ 保留标签 0-15 的特殊语义（§1 边界⑥）；⑦ VLAN 承载（代码支持但今日无例，G-MPLS-5）。

---

## 5. 消息/事务模型与状态机

**MPLS 数据面无事务、无会话、无状态机**——这是本协议与其他所有协议的**根本差异**，必须显式声明（CORE_MEMORY §3.14 豁免口径）。

| 概念 | 本协议状态 | 理由 |
|---|---|---|
| **会话** | **不适用** | 无连接建立/拆除；标签栈是**每个包独立携带**的转发指令，包与包之间无协议状态（R3031 §3.1："a label is a short, fixed length, locally significant identifier"——局部有效，非连接标识） |
| **事务** | **不适用** | 无请求/响应；MPLS 数据面是**单向**的（ingress → egress），无回程确认 |
| **状态机** | **不适用** | planner 是"配置 → 帧"的纯函数（`planner.go:104-223` 一次 for 循环，无状态转移） |
| **握手/挥手** | **不适用** | 链内无 tcp/udp 层，无 SYN/FIN（§2 结构） |
| **保活/重试/重连** | **不适用** | 无连接可保活/重试 |
| **多会话展开** | **不适用** | 无 `sessions[]` 键 |

**唯一的"序列"语义 = `frames`**：`mpls` 层 `frames` 键声明**每流发多少帧**（缺省 1），逐帧差异**只有内层 IP ID**（`planner.go:160-164`：`ipidCounter++; return uint16(ipidCounter)`，从 1 起逐帧 +1），**标签栈逐帧完全相同**（`planner.go:179-180` 每帧 `mplsCfg.Labels = labels` 复用同一解析后的栈）。

**今日实跑实证**（`mpls_frames_multi`，`frames=3`）：帧 1/2/3 的 `mpls.label` 均 100、`ip.id` 分别 `0x0001`/`0x0002`/`0x0003`。

**自动派生规则（逐条列出，不依赖隐含知识）**：

| # | 派生 | 触发 | 内容 | 代码位置 |
|---|---|---|---|---|
| 1 | 标签 TTL 缺省 | `labels[i].ttl == 0` | 写 **64**（`DefaultMPLSTTL`） | `planner.go:133-139`（解析）+ `builder.go:1081-1084`（兜底） |
| 2 | **S 位自动纠正** | **恒**（最后一层） | 栈底 S **恒写 1**（用户写 false 也被纠正） | `builder.go:1077-1080` |
| 3 | EtherType 强制 | `L2.MPLS != nil` | 0x8847（缺省）/ 0x8848（`multicast:true`） | `builder.go:1022-1033` |
| 4 | 内层 L3 族选择 | 恒 | 按 `srcIP` 地址族：v4 → 0x0800、v6 → 0x86DD | `planner.go:208`（`EtherTypeFor`）+ `builder.go:189-198` |
| 5 | `frames` 缺省 | `frames == 0` | **1** | `planner.go:118-121` |
| 6 | `direction` 缺省 | `direction == ""` | **`"up"`** | `planner.go:122-125` |
| 7 | `inner_proto` auto | `inner_proto == 0` | `spec.TCP != nil` → 6，否则 **17**（链路径恒 17） | `planner.go:110-117` |
| 8 | `inner_payload` 回退 | `InnerPayload == nil` | 取 `spec.Payload` | `planner.go:126-129` |
| 9 | 逐帧 IP ID | 恒 | 从 **1** 起逐帧 +1（`uint16` 溢出回绕） | `planner.go:160-164` |
| 10 | 内层 IP TTL 缺省 | `L3.TTL == 0` | **64**（框架级，非 mpls 专属） | `builder.go:1165-1168`（v4）/ `:1260`（v6） |
| 11 | 以太网 padding | 帧长 < 60 | 补零到 60（本协议单标签空载荷包恒命中） | `builder.go:325-330`（`MinEthernetFrame = 60`） |
| 12 | `direction=down` 交换 | `direction == "down"` | **planner 层**交换 src/dst 的 IP **与** MAC（`planner.go:171-176`） | 同左 |

**规则 12 的双换防护（重要，链路径合同）**：planner 在 down 时**自行**交换地址+MAC（`planner.go:171-176`），而 raw-IP 驱动对 `Direction=="down"` 的包**也会**交换 L3 地址（`chain_planner.go:1546-1548`）——若二者叠加会**双换回原值**。因此 `layer_gen.go:51-52` **强制把每个包的方向置为 `"up"`**：

```go
for pkt := range ch {
    pkt.Direction = "up"     // h323/icmpv6 同款防双换
    if err := req.Emit(pkt); err != nil { return err }
}
```

**效果**：驱动层看到 `Direction=="up"` 故**不再交换**，帧上保留的正是 planner 已交换后的地址——**`direction=down` 的最终帧面 = 交换后的地址**（今日实跑实证：`mpls_direction_down` 帧 `ip.src=20.0.0.1`、`ip.dst=10.0.0.1`，正是 `spec` 的 dst/src）。

---

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

### 6.1 帧/报文长度上界与开销公式

```
以太帧长 = 14 + 4×N + L3 + L4 + len(payload)     （无 VLAN；N = 栈层数）
```

| 项 | 值 | 来源 |
|---|---|---|
| 最小自然帧 | **14 + 4 + 20 + 8 + 0 = 46**（N=1、IPv4/UDP、空载荷）→ **padding 到 60** | `builder.go:325-330` |
| 今日实测帧长 | **60**（全部 IPv4 正例）；**66**（`mpls_v6` = 14+4+40+8+0） | 今日实跑 `frame.len` |
| 标签栈上界 | **无代码上限**（`labels` 为 list）；每层 Label ≤ 0xFFFFF | `builder.go:1119` |
| 栈层数上界（协议面） | R3032 §2.1 未设层数上限；实际受帧长与 MTU 约束 | — |
| 内层 L3 | IPv4 20 / IPv6 40 | `builder.go:203-208` |
| 内层 L4 | UDP 8 / TCP 20（无 options） | `l4Length` |

**分片/PMTU 显式不适用**（§1 边界④）：本层无分段概念；内层超 MTU 由框架/IP 层能力承载，mpls 层零断言。

### 6.2 并发流下的行为

多流由**策略级** `flow_control`（或 `strategy_fc`）承载，`flows=N` 时每流独立四元组 + 独立标签栈（同配置）；worker 逐流注入 `spec.SrcPort = 12345 + i`（保底自增）或层内动态解析值。**无跨流共享状态**——`Plan` 的每个 goroutine 持有自己的 `packetIndex`/`ipidCounter` 局部变量（`planner.go:146/160`），标签栈切片**只读复用**（`planner.go:179-180` 拷贝 `*cfg` 但 `Labels` 指向同一底层数组——**只读故无竞态**）。今日实测 `mpls_port_dyn`（`flows=2`）两流端口 30000/30001 逐流正确。

### 6.3 流式与内存

`Plan` 返回**带缓冲 channel（256）**，逐帧 `emit`（`planner.go:147-158`），**无全量收集**；每帧内存 = 该帧字节数（今日最大 66 B）。raw-IP 驱动路径（`chain_planner.go:1497-1580`）同样是 channel 流式（缓冲 256）。`Validate` 与 `Plan` 的缺省解析在**启动 goroutine 之前**完成（`planner.go:107-139`，注释明写"deterministic, same values every frame"），保证同输入同输出（§5 确定性）。

### 6.4 验收两路（CORE_MEMORY §6.3）

- **pcap 路**：今日**已跑**（§0.2），`RESULT: 14 pass, 0 fail, 0 error`；pcap 落本车道私有目录 `/tmp/mpls-doc-verify/mpls/`（12 文件）。断言实际 `eth.type`/`mpls.*`/`ip.*`/`udp.*`/`tcp.*`/`data.data` 字段值与 `offset 14` 原始 hex，**不只断言"任务没报错"**（28 条 field + 1 条 frame 逐条复核命中）。
- **NIC 路**：**今日未跑**（框架能力，`nic_capture` 用例级开关）；本层**零专属断言**（全部断言都是协议字段，与输出路径无关）→ G-MPLS-9。

### 6.5 六类场景落点（§6.6）

| 场景 | 落点 |
|---|---|
| 基线 | #1（单标签单帧，60 B） |
| 目标规模 | #9（`frames=3`）/ #14（`flows=2`） |
| 压力上限 | 标签栈深度（**今日无 N>1 例 → G-MPLS-2**）；帧长上界（今日最大 66 B，远未触界） |
| 长时间运行 | `frames` 大值承载（今日 N=3） |
| 并发交错 | 多流（#14）；`concurrent` 例外路径**不启用** |
| 背压 | `packet_count` 精确计数守卫帧数漂移；channel 缓冲 256 |

**吞吐数字待确认，本版不写承诺**（§6.5）。

---

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 **planner/validator**（task-time）或 **create-time 门**拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或假成功（今日实跑：5 例 task-time 负例 `.neg.pcap` 均 **0 帧**；2 例 create-time 负例**无落盘**）。

### 7.1 create-time 门（2 条，创建策略即拒，无 pcap）

| # | 负例 ID | 故障输入 | 门 | 锚词 | 代码位置 |
|---:|---|---|---|---|---|
| N-1 | `mpls_vn_presence` | `spec_json` 顶层出现 `"mpls": {}`（**空 map 也死**） | `CheckProtoFlat` presence | `top-level mpls sub-config` | `strategy_convert.go:8947-8951`（逐字：`protocol mpls no longer accepts a top-level mpls sub-config (move it into the mpls layer of an [ip,mpls] layers chain)`） |
| N-2 | `mpls_vn_static_port` | `mpls` 层**静态**端口 + `flows=2`（层链 `[ip{}, mpls{ports}]`） | `checkLayerChainStaticCopy` | `static four-tuple` | `schema/semantic.go:285`（mpls 已入扫描名单，`:214`） |

**N-2 的形状说明**：`ip` 层写成**空 map**（`{}`）——空 ip 层对静态复制门**无贡献**（无 `src`/`dst` 标量），使唯一触发源锁定为 `mpls` 层的静态端口，这是"最小证明形"（h323 T-3 同构）。

### 7.2 task-time validator 门（5 条，`.neg.pcap` 0 帧）

| # | 负例 ID | 故障输入 | 锚词（`error_contains`） | 代码文案（逐字） | 代码行 |
|---:|---|---|---|---|---|
| N-3 | `mpls_neg_label` | `label: 1048576`（= 2²⁰ = 0x100000） | `exceeds 20 bits` | `mpls: label %d (entry %d) exceeds 20 bits (max 0xFFFFF, RFC 3032 §3.1)` | `planner.go:66` |
| N-4 | `mpls_neg_tc` | `tc: 8` | `exceeds 3 bits` | `mpls: TC %d (entry %d) exceeds 3 bits (max 7, RFC 5462)` | `planner.go:69` |
| N-5 | `mpls_neg_sbit` | `labels: [{label:1, s:true}, {label:2}]`（非栈底置 S） | `not the bottom of stack` | `mpls: S=true on entry %d but it is not the bottom of stack (only the last entry may set S, RFC 3032 §2.1)` | `planner.go:72` |
| N-6 | `mpls_neg_innerproto` | `inner_proto: 1` | `InnerProto 1 not in supported list` | `mpls: InnerProto %d not in supported list (allowed: 6=TCP, 17=UDP)` | `planner.go:80` |
| N-7 | `mpls_neg_direction` | `direction: "sideways"` | `Direction "sideways" not in supported list` | `mpls: Direction %q not in supported list (allowed: up, down)` | `planner.go:91` |

**锚词口径**：`error_contains` 是**子串**判定；5 例均命中代码文案（前缀 `mpls: `）。**注意 N-3/N-5 的代码文案里含错误的 RFC 条款号**（`RFC 3032 §3.1` / 应为 `§2.1`；N-5 的 `§2.1` 正确）——**锚词只取不含条款号的子串**（`exceeds 20 bits` / `not the bottom of stack`），故条款号错误**不影响用例**（G-MPLS-1 仅为文档/注释层缺口）。

### 7.3 未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）

| # | 分支 | 锚词（代码逐字） | 代码行 | 归属 |
|---:|---|---|---|---|
| R-1 | `spec.MPLS == nil` | `mpls: MPLS config is required` | `planner.go:42` / `layer_gen.go:68` | 链路径不可达（translate 后恒非 nil）＝C 类保底 |
| R-2 | IP 不可解析（src/dst 各一） | `mpls: %s %q is not a valid IP address` | `planner.go:57` | A′ 候选 |
| R-3 | 空标签栈 | `mpls: label stack must contain at least one entry (RFC 3032 §2.1)` | `planner.go:62` / `builder.go:1118` | A′ 候选（**层内不可达**——`labels` 缺席即 nil，但 registry `labels` 类型 `list` 无 Default，缺键不填 → 可达；今日无例） |
| R-4 | `frames < 0` | `mpls: Frames %d must be >= 0` | `planner.go:84` | **V9 先拦**（registry `frames` Min 0 → 负数在 create-time 被 schema 拒，锚词为 V9 文案）→ A′ 候选 |
| R-5 | MPLS + GRE | `mpls: cannot combine MPLS with GRE …` | `builder.go:1106` | A′ 候选（§3.6） |
| R-6 | MPLS + PPPoE | `mpls: cannot combine MPLS with PPPoE …` | `builder.go:1109` | A′ 候选（§3.6） |
| R-7 | 内层非 IP（EtherType 既非 0x0800 亦非 0x86DD） | `mpls: inner layer must be IP …` | `builder.go:1115` | A′ 候选（§3.3） |

**不得误报的合法协议事件**：多层标签栈（N≥2）；内层 TCP 裸头（#12）；`direction=down`（#10）；`multicast: true`（#11）；内层 IPv6（#13）；`frames>1`（#9）；`flows>1` + 动态端口（#14）；保留标签值 0-15（**合法输入**，本引擎不拒——G-MPLS-4）。

---

## 8. 边界

- **帧长**：最小自然帧 46 B（N=1/IPv4/UDP/空载荷）→ **padding 到 60**；今日实测 60 B（IPv4）/ 66 B（IPv6）。
- **标签栈**：**层数无代码上限**；每层 `Label ≤ 0xFFFFF`、`TC ≤ 7`、`TTL ≤ 255`。今日用例 **N=1**（N=2 立项 G-MPLS-2）。
- **S 位**：栈底**恒 1**（自动纠正）；非栈底写 true **拒**。
- **TTL**：标签 TTL 0 → 64；内层 IP TTL 0 → 64（框架）；**二者不校验一致**（G-MPLS-3）。
- **EtherType**：**恒 0x8847/0x8848**（MPLS 存在时无视配置）；内层族由 `L2.EtherType`（即地址族）决定。
- **保留标签 0-15**：**作为普通数值接受**，不触发 Explicit-Null/Router Alert 特殊语义（G-MPLS-4）。
- **端口**：链内无 tcp/udp 层，**无端口概念**（0 合法）；内层 L4 端口住 `mpls` 层 `src_port`/`dst_port`。
- **地址族**：指**内层** L3 族；外层恒 MPLS EtherType。v4/v6 独立用例（#1–#12/#14 v4、#13 v6）。**异族混写（`ip.src` v4 + `ip.dst` v6）今日无例** → A′ 候选（框架级 `EtherTypeFor(srcIP)` 只看 src，行为待确认）。
- **VLAN**：代码支持（栈起点 18），**今日无例**（G-MPLS-5）。
- 不得产生回绕长度或超量分配（帧长由 `Build` 一次算定，`total := l2Len + l3Len + l4Len + len(payloadBytes)`，`builder.go:322`）。

---

## 9. 原子 ID 与完成定义（14 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 | 包数（**今日实跑实测**） | 断言数 |
|---:|---|---|---|---:|---:|
| 1 | `mpls_single_label_ipv4` | 正 | §3.1/§3.2/§3.3/§3.4：单标签栈（label 100/TTL 64）内层 IPv4/UDP 单帧基线 | **1**（`min_packets: 1`） | 7 fields + 1 frame |
| 2 | `mpls_vn_presence` | 负 | §7 N-1：顶层 `mpls` presence 判死 | **0**（create-time，无落盘） | 0 |
| 3 | `mpls_vn_static_port` | 负 | §7 N-2：层内静态端口 + `flows=2` 静态复制 | **0**（create-time，无落盘） | 0 |
| 4 | `mpls_neg_label` | 负 | §7 N-3：`label` 超 20 bit | **0**（`.neg.pcap`） | 0 |
| 5 | `mpls_neg_tc` | 负 | §7 N-4：`tc` 超 3 bit | **0**（`.neg.pcap`） | 0 |
| 6 | `mpls_neg_sbit` | 负 | §7 N-5：`s` 位非栈底 | **0**（`.neg.pcap`） | 0 |
| 7 | `mpls_neg_innerproto` | 负 | §7 N-6：`inner_proto` 非法 | **0**（`.neg.pcap`） | 0 |
| 8 | `mpls_neg_direction` | 负 | §7 N-7：`direction` 非法 | **0**（`.neg.pcap`） | 0 |
| 9 | `mpls_frames_multi` | 正 | §5：`frames=3` 多帧（IP ID 逐帧 +1） | **3** | 6 fields |
| 10 | `mpls_direction_down` | 正 | §5 规则 12：`direction=down`（地址+MAC 全交换） | **1** | 3 fields |
| 11 | `mpls_multicast` | 正 | §3.2：`multicast` → EtherType 0x8848 | **1** | 2 fields |
| 12 | `mpls_inner_tcp` | 正 | §3.4/§3.7：内层 TCP 裸头（`inner_proto: 6`） | **1** | 3 fields |
| 13 | `mpls_v6` | 正 | §3.3：内层 IPv6 对照 | **1** | 3 fields |
| 14 | `mpls_port_dyn` | 正 | §12.12：`src_port` inc 动态 + `flows=2` | **2** | 4 fields |

**包数公式**：

```
单流 = frames（缺省 1；模板面每流帧数）
多流 = flows × frames
```

校验：#1/#10/#11/#12/#13 `frames` 缺省 1 → **1** ✓；#9 `frames=3` → **3** ✓；#14 `flows=2` × 每流 1 帧 → **2** ✓；负例 → **0**。**7/7 正例与今日实跑帧数逐例一致**（§0.2）。

**T-编号对照（`docs/TEST_CASES.md:3372-3400` 的 T-MPLS-1…14 摘要）**：`mpls_single_label_ipv4` ≡ T-MPLS-1；`mpls_vn_presence` ≡ T-MPLS-2；`mpls_vn_static_port` ≡ T-MPLS-3；`mpls_neg_label` ≡ T-MPLS-4；`mpls_neg_tc` ≡ T-MPLS-5；`mpls_neg_sbit` ≡ T-MPLS-6；`mpls_neg_innerproto` ≡ T-MPLS-7；`mpls_neg_direction` ≡ T-MPLS-8；`mpls_frames_multi` ≡ T-MPLS-9；`mpls_direction_down` ≡ T-MPLS-10；`mpls_multicast` ≡ T-MPLS-11；`mpls_inner_tcp` ≡ T-MPLS-12；`mpls_v6` ≡ T-MPLS-13；`mpls_port_dyn` ≡ T-MPLS-14。**序号以 cases JSON 顺序为权威**（JSON 中 7 条负例集中在 #2–#8，正例 #9–#14 随后）。

---

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

**归类规则（八项行的三分法，机读可复核）**：末列写「无」= **已覆**；写「**不适用**」（含"明确不解决"）= **不适用**；写「A′/立项」= **立项**。据此 8 行 = **覆 2**（行 1 连接模型、行 4 字段表）/ **不适用 4**（行 2 命令消息表〔无消息概念〕、行 3 状态机、行 6 超时活性、行 7 NAT 被动）/ **立项 2**（行 5 错误处理〔7 条未入例分支〕、行 8 版本方言〔PPP/ATM 承载 + 保留标签语义〕）。

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | MPLS **无连接**——标签是"局部有效的短定长标识符"（R3031 §3.1），逐包携带转发指令；LSP 是预先配置的转发状态（R3031 §3.15） | 场景①–⑧ | `DependsOn ["ip"]` 单值（`registry.go:1811`）；raw-IP 自驱（`chain_planner_util.go:49`）；无会话/无握手 | 无（无连接是规范语义，非缺失） |
| 2 | 命令/消息表 | **无消息类型**——数据面只有"带标签的包"一种产物；控制面消息（LDP Label Mapping / RSVP Path 等）**不在本版** | 场景①–⑧ | planner 单循环产帧（`planner.go:166-219`），无消息分派 | **不适用**（本协议无消息表概念；控制面另行**明确不解决**，§1 边界①） |
| 3 | 状态机 | 无（本引擎为 ingress 源端，非 LSR） | — | 无状态（§5） | **不适用**（显式声明） |
| 4 | 字段表 | 标签栈项 4 键：Label 20 / TC 3 / S 1 / TTL 8（R3032 §2.1 + R5462 §2.1）；EtherType 2 值（R3032 §5）；内层协议判定（R3032 §2.2） | 数据场景层 | `writeMPLSLabels` 位域拼装（`builder.go:1075-1093`）；`writeL2` 强制 EtherType（`:1022-1033`）；内层族选择（`:189-198`） | 无 |
| 5 | 错误处理 | 规范**未定义**"非法标签栈"的线格式错误（LSR 收到无效标签按 R3031 §3.18 "Invalid Incoming Labels" 丢弃）——本实现的 7 条拒绝是**配置面**门 | 负例 N-1…N-7 | planner `Validate` 10 分支（`planner.go:40-95`）+ builder `validateMPLSConfig` 6 分支（`builder.go:1104-1128`）+ create-time 2 门 | A′ 7 条（§7.3） |
| 6 | 超时与活性 | 无——MPLS 数据面无保活/超时机制（LDP 有 KeepAlive，但属控制面） | — | 无 | **不适用** |
| 7 | NAT/代理/被动 | 无被动模式概念（本引擎恒为 ingress 主动发送） | — | 无 `sessions[]`；多流走策略级 `flow_control` | **显式不适用** |
| 8 | 版本/方言 | 本协议无版本字段（MPLS 无版本号；标签栈格式由 RFC 3032/5462 单一固定） | 正例 7 | 无版本键；EtherType 二值覆盖（#1/#11）；内层双族覆盖（#13） | **立项**（G-MPLS-4 保留标签语义；PPP/ATM 承载另行**明确不解决**，§1 边界⑤） |

### 10.2 子表①：线格式要素 × 终态矩阵（逐格已覆/立项/不适用）

| 要素 | T1 正常产帧 | T2 配置拒绝 | T3 传输异常终态 |
|---|---|---|---|
| 标签栈项 Label | 已覆（#1 label 100） | 已覆（#4 超 20 bit） | 不适用（无传输层，无 RST/异常中断概念） |
| 标签栈项 TC | 已覆（#1 tc 0） | 已覆（#5 超 3 bit） | 不适用 |
| 标签栈项 S | 已覆（#1 自动栈底 1） | 已覆（#6 非栈底 true） | 不适用 |
| 标签栈项 TTL | 已覆（#1 缺省 → 64） | A′ 立项（**TTL 无值域外可能**——uint8 天然 ≤255，V9 先拦；无拒绝分支） | 不适用 |
| 标签栈深度 N | 已覆（#1 N=1） | A′ 立项（**N=0 空栈拒**——§7.3 R-3） | 不适用 |
| EtherType unicast | 已覆（#1/#9/#10/#12/#13/#14） | 不适用（无配置面开关，缺省即 unicast） | 不适用 |
| EtherType multicast | 已覆（#11） | 不适用（同左） | 不适用 |
| 内层 L3 IPv4 | 已覆（#1/#9/#10/#11/#12/#14） | A′ 立项（非 IP 内层拒，§7.3 R-7） | 不适用 |
| 内层 L3 IPv6 | 已覆（#13） | A′ 立项（同 R-7；异族混写行为待确认 §8） | 不适用 |
| 内层 L4 UDP | 已覆（#1/#9/#10/#11/#13/#14） | 不适用（`inner_proto` 非 6/17 拒已覆 #7） | 不适用 |
| 内层 L4 TCP | 已覆（#12） | 已覆（#7 `inner_proto: 1`） | 不适用 |
| 帧数 `frames` | 已覆（#9 N=3；缺省 1 见 #1） | A′ 立项（负数由 V9 先拦，§7.3 R-4） | 不适用 |
| 方向 `direction` | 已覆（#10 down；缺省 up 见 #1） | 已覆（#8 sideways） | 不适用 |
| VLAN 承载 | A′ 立项（G-MPLS-5，代码支持今日无例） | 不适用 | 不适用 |

**逐格重数（机读逐格计数，2026-09-29）**：14 行 × 3 列 = 42 格——已覆 **18**（T1 列 13 + T2 列 5）/ A′ 立项 **6**（T1 列 1〔VLAN〕+ T2 列 5〔TTL/N/内层 IPv4/内层 IPv6/frames〕）/ **不适用 18**（T2 列 4〔ET-u/ET-m/内层 UDP/VLAN〕+ T3 列 14——无传输层故 T3 列**整列不适用**）。18 + 6 + 18 = 42 ✓

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **37 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | `labels` 单层 | 覆（#1，label 100） |
| 2 | `labels` 多层（N≥2） | **A′ 立项**（G-MPLS-2——**代码支持**（`writeMPLSLabels` 循环 + `planner_test.go:161-192` 单测 N=2），**用例零覆盖**；notes 里"pcap 7 mpls_http.pcap"是外部参考 pcap，非本仓用例） |
| 3 | `labels` 空数组 / 缺席 | A′ 立项（§7.3 R-3，planner `:62` + builder `:1118` 双门） |
| 4 | `label` = 0（IPv4 Explicit-Null） | **A′ 立项**（G-MPLS-4；本引擎**不特殊处理**，作普通值写 0——语义差异须显式声明） |
| 5 | `label` = 16（最小可用标签，RFC 3032 §2.1） | A′ 立项（同 G-MPLS-4 行；单测 `planner_test.go:71` 用过 16，用例零覆盖） |
| 6 | `label` = 100（正常值） | 覆（#1/#9/#10/#11/#12/#13/#14 全部） |
| 7 | `label` = 1048575（0xFFFFF 上界**等值**） | **A′ 立项**（G-MPLS-12——边界等值格；今日只测上界+1 拒 #4，**等值过**无例） |
| 8 | `label` = 1048576（上界 +1） | 覆（#4 拒） |
| 9 | `tc` = 0（缺省） | 覆（#1 `mpls.exp=0`） |
| 10 | `tc` = 7（上界**等值**） | **A′ 立项**（G-MPLS-12，同 #7 口径） |
| 11 | `tc` = 8（上界 +1） | 覆（#5 拒） |
| 12 | `s` 缺省（栈底自动 1） | 覆（#1 `mpls.bottom=1`） |
| 13 | `s` = true 于栈底（显式） | **A′ 立项**（等价于自动纠正，无独立可观察差异——**接受为单分支代表，注记**） |
| 14 | `s` = true 于非栈底 | 覆（#6 拒） |
| 15 | `ttl` = 0（缺省 → 64） | 覆（#1 `mpls.ttl=64`） |
| 16 | `ttl` 显式值（如 255） | **A′ 立项**（G-MPLS-11——**缺独立格**；单测 `planner_test.go:71/87` 用过 255，用例零覆盖） |
| 17 | `ttl` = 255（上界等值） | A′ 立项（同 #16） |
| 18 | `multicast` = false（缺省） | 覆（#1 `eth.type=0x8847`） |
| 19 | `multicast` = true | 覆（#11 `eth.type=0x8848`） |
| 20 | `inner_proto` = 0（auto） | 覆（#1/#9/#10/#11/#13/#14——链路径解析为 UDP，§3.7） |
| 21 | `inner_proto` = 17（显式 UDP） | **A′ 立项**（**与 0 等价**，链路径不可区分——接受为单分支代表，注记；设计 §3.7 已诚实声明） |
| 22 | `inner_proto` = 6（显式 TCP） | 覆（#12） |
| 23 | `inner_proto` = 1（非法） | 覆（#7 拒） |
| 24 | `direction` = up（缺省）/ 显式 up | 覆（#1 等全正例） |
| 25 | `direction` = down | 覆（#10） |
| 26 | `direction` 非法 | 覆（#8 拒） |
| 27 | `frames` = 1（缺省） | 覆（#1 等） |
| 28 | `frames` = 3 | 覆（#9） |
| 29 | `inner_payload` 显式 "probe" | 覆（#1 `data.data=70726f6265`） |
| 30 | `inner_payload` 缺席（回退 `spec.Payload`，两者皆空 → 空载荷） | **A′ 立项**（G-MPLS-11） |
| 31 | 内层 IPv4 | 覆（#1 等 6 例） |
| 32 | 内层 IPv6 | 覆（#13） |
| 33 | 端口显式 | 覆（全正例 12345/80） |
| 34 | 端口动态（inc） | 覆（#14） |
| 35 | 端口 rand/list/pattern 三策略 | A′ 立项（G-MPLS-13） |
| 36 | VLAN 承载 | A′ 立项（G-MPLS-5） |
| 37 | 保留标签 1/2/3（Router Alert / IPv6 Explicit-Null / Implicit-Null） | A′ 立项（G-MPLS-4） |

**逐行重数（机读逐行计数，2026-09-29）**：**覆 23 + A′ 立项 14 = 37** ✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 单层 LSP 数据面（运营商骨干最常见形态） | #1 | 已覆 |
| 2 | 同一 LSP 连续包（`frames`） | #9 | 已覆 |
| 3 | 回程方向流量（`down`） | #10 | 已覆 |
| 4 | 组播 MPLS（0x8848，MVPN 类） | #11 | 已覆 |
| 5 | 内层 TCP 业务流 | #12 | 已覆 |
| 6 | IPv6 骨干 | #13 | 已覆 |
| 7 | 多 LSP 并发（多流） | #14 | 已覆 |
| 8 | 标签栈嵌套（VPN 双层标签 / 标签栈） | — | **A′ 立项**（G-MPLS-2，代码支持用例缺） |
| 9 | LDP 标签分发协商 | — | **明确不解决**（§1 边界①，控制面） |
| 10 | RSVP-TE 显式路径建立 | — | **明确不解决**（同上） |
| 11 | 中间 LSR 换标签（swap） | — | **明确不解决**（§3.5，非本引擎位置） |
| 12 | PHP 倒数第二跳弹栈（pop） | — | **明确不解决**（§3.5） |
| 13 | TTL 递减与环路检测 | — | **明确不解决**（§3.5，R3031 §3.24 环路控制属转发面） |
| 14 | 分片 / PMTU 发现 | — | **明确不解决**（§1 边界④） |
| 15 | Explicit-Null 弹栈交付 | — | **明确不解决**（G-MPLS-4） |
| 16 | MPLS over PPP / ATM | — | **明确不解决**（§1 边界⑤） |
| 17 | 运维配错拦截（presence/静态复制/值域） | #2–#8 | 已覆 |

**8 覆 + 9 不适用/立项 = 17**。✓ 无映射无确认即缺口——本表零缺口（未覆项均有"明确不解决"或 A′ 立项落点）。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

**三路**：①**规范原文**（RFC 3031/3032/5462 全文实测拉取，2026-09-29）——定"必须是什么"；②**商业化软件实际行为**（**未取到**：真实 LSR/路由器（Cisco/Juniper/FRR）的线字节未抓包核对 → G-MPLS-14 待确认；本机 `/tmp/probe-iana/mpls.pcap` **已不存在**（`ls` 实测 No such file），D-MPLS-1 记载的"探针 pcap 验证记录"**今日不可复现**，故本版**不以该 pcap 为字节依据**，字节依据改为**今日实跑自产 pcap**（§0.2）；③**可靠开源实现思路**（Linux 内核 `net/mpls`、FRR `zebra` 的标签栈压栈实现——只借鉴"位域拼装后整体大端输出"这一条思路，未逐字节对照）。**三路一致点**：4 字节/层、位域 20/3/1/8、栈在网络层头之前、S 位只在栈底、EtherType 0x8847/0x8848。**不一致点/未取到点**：真实设备对保留标签与 TTL 的处理（②未取到 → G-MPLS-14）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | **`[ip, mpls]` 终层自驱整包 relay**（本版；h323/ngap 同构先例） | legacy planner 自产完整包（Eth + 栈 + 内层 IP/TCP/UDP），builder 原生写栈（强制 0x8847/0x8848 + offset 14）；代价 = 一套 raw-IP 终层（已落码） | **采用**（D-MPLS-1 决策 A1，本版 as-built 确认） |
| B | 中链 shim `[eth, mpls, ip, tcp]`（registry 占位行原设想，`CategoryL2`） | 需框架级新机制（数组=线序 + transport 终结面未定义） | **否决**（D-MPLS-1 决策 A 否决记录①） |
| C | `[ip, tcp, mpls]` 端口住 tcp 层 | **中链 tcp 静态端口无进 spec 通道**（`extractLayer*` 仅 ip 地址/eth MAC/ip TTL 三函数），且"动态通静态不通"形状不一致 | **否决**（D-MPLS-1 决策 A 否决记录②） |
| D | 独立标签栈构造器（不借 legacy planner） | 与 builder 的 L2/L3 装配重复实现，双份字节事实 | **否决**（"零字节分歧"是本实现的核心理由，`layer_gen.go:1-6`） |

---

## 11. P2 D-MPLS-1 代码设计（CORE_MEMORY §8 八要素；as-built 逆向定稿）

> 状态说明：实现已落码（`internal/protocol/mpls/` 三文件 + `internal/core/builder.go` 栈写入 + 接线），本条为 P-PIPE 文档轨对既有实现的**逆向定稿**（as-built），供门1 批准后作为后续改动的唯一入口；本协议**不新开层**，P4 在本协议内为"缺口收敛"（§14）。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数（`wc -l` 实测） |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:3321-3390` + `:3022`） | `MPLSConfig` / `MPLSLabel` + `L2Config.MPLS` 槽位 | —（共享文件） |
| `trafficgen/internal/core/builder.go`（`:85-101` 常量 + `:189-198` 内层族 + `:304-320` 长度 + `:1017-1033` EtherType + `:1061-1093` 写栈 + `:1104-1128` 校验） | 标签栈线编码 + EtherType 强制 + 内层 L3 解析 | —（共享文件） |
| `trafficgen/internal/protocol/mpls/planner.go` | `Planner.Validate`（10 分支）+ `Plan`（帧循环） | 224 |
| `trafficgen/internal/protocol/mpls/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator` + `RegisterLayerValidator`，`init()`）+ `validateLayer` | 78 |
| `trafficgen/internal/protocol/mpls/planner_test.go` | **12 个 `Test*`**（编码面 + 生成器面 + Validate 面 + 注册面 + 默认流面） | 464 |
| 接线 8 件 | registry 终层行（`layers/registry.go:1811`）/ translate 层内分支（`chain_planner_translate.go:1380`）/ convert 子配置搬运（`strategy_convert.go:1209` + `:4333`）/ presence 判死（`strategy_convert.go:8947`）/ protocols 准入（`protocols.go:48`）/ raw-IP 驱动（`chain_planner_util.go:49` + `chain_planner.go:1497`）/ 端口豁免名单（`chain_planner.go:758` + `:996`）/ 静态复制门扩扫（`schema/semantic.go:214`）+ 端口动态（`layer_dyn.go:53` + `:238` + `:823`） | — |

**测试面实测**：`internal/protocol/mpls/planner_test.go` **8 个 `Test*`** + `internal/core/builder_mpls_test.go` **10 个** + `internal/core/layers/mpls_migrate_test.go` **4 个** + `internal/core/schema/mpls_static_port_test.go` **1 个** = **23 个 `Test*`**（`grep -c '^func Test'` 实测）。

### 11.2 接口签名（as-built）

- `Validate(spec core.FlowSpec) error`（`planner.go:40`）：**只读**（`validate_conventions.md §1.1`：不改 spec、不填缺省）——10 个拒绝分支（nil / IP 解析 ×2 / 空栈 / label 上界 / TC 上界 / S 位置 / InnerProto / Frames / Direction）。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`planner.go:104`）：**缺省解析在启动 goroutine 前完成**（`:107-139`），随后 goroutine 逐帧 `emit`（缓冲 256）。
- `Generator.Name() "mpls"`；`GenEvents()` **返回 nil**（`layer_gen.go:27`，raw 自驱终层：整包经 `Emit` 而非消息事件——**必须保持 nil**，否则 `chain_planner.go` 的事件分支检查会把非 nil `GenEvents` 路由到 transport 路径）。
- `Generate(ctx, req)`（`layer_gen.go:33`）：`Meta.MPLS == nil` → 显式错（防误调）；否则组装等价 `FlowSpec`（`SrcIP/DstIP/TTL/SrcMAC/DstMAC/SrcPort/DstPort/MPLS` 直传）→ `legacy.Plan` → **逐包强制 `Direction = "up"`**（防双换，§5 规则 12）→ `req.Emit`。
- `validateLayer(s core.FlowSpec) error`（`layer_gen.go:66`）：`MPLS == nil` → `mpls: MPLS config is required`（链特定保底，translate 后不可达＝C 类）；否则复用 `Planner.Validate`（**零新文案**）。

### 11.3 数据结构

```go
type MPLSConfig struct {
    Labels       []MPLSLabel `json:"labels"`          // 传输序：entry 0 = 栈顶，末项 = 栈底（S 自动 1）
    Multicast    bool        `json:"multicast,omitempty"`   // true → 0x8848
    InnerProto   uint8       `json:"inner_proto,omitempty"` // 6=TCP / 17=UDP / 0=auto
    InnerPayload []byte      `json:"inner_payload,omitempty"`
    Frames       int         `json:"frames,omitempty"`      // 0 → 1
    Direction    string      `json:"direction,omitempty"`   // "up"(缺省) / "down"
}
type MPLSLabel struct {
    Label uint32 `json:"label"`            // 20 bits（>0xFFFFF 拒）
    TC    uint8  `json:"tc,omitempty"`     // 3 bits（>7 拒）；R5462 前称 EXP
    S     bool   `json:"s,omitempty"`      // 栈底恒 1（自动纠正）
    TTL   uint8  `json:"ttl,omitempty"`    // 0 → 64
}
```

**wire 级 vs 隧道级字段分离**（`types.go:3325-3328` 注释）：`Labels`/`Multicast` 由 **builder** 读（写线字节）；`InnerProto`/`InnerPayload`/`Frames`/`Direction` 由 **planner** 读（组装内层包与帧序列）——**builder 对后者零感知**。

### 11.4 主流程

**create**：`ValidateStrategy` → `ValidateLayers`（registry `mpls` Fields 8 键 allowlist）→ `CheckProtoFlat` presence 判死（`strategy_convert.go:8947`）→ `checkLayerChainStaticCopy`（含 mpls 端口，`semantic.go:214`）→ 400。

**task**：`mapToFlowSpec` → `parseLayerDyn`（mpls 端口对象）→ worker `resolveLayerTuple`（逐流端口落 spec，`layer_dyn.go:823-833`）→ `ChainPlanner.ValidateSpec`：`validateSpecBase`（mpls 端口豁免，`chain_planner.go:758`/`:996`）→ translate `case "mpls"`（`chain_planner_translate.go:1380-1460`）→ `validateLayer`（required 保底 + legacy `Validate` 10 分支）→ `Plan`：`isRawIPChain`（`chain_planner_util.go:49`）→ raw-IP 驱动（`chain_planner.go:1497-1580`，`meta` 补齐 SrcIP/DstIP/TTL/SrcMAC/DstMAC/SrcPort/DstPort/MPLS）→ `Generator.Generate` → legacy `Plan` 整包 → **force-up 防双换** → `Emit` → builder：`writeL2` 强制 0x8847/0x8848 + 栈写入（offset 14，VLAN 18）→ 内层 L3/L4 正常装配 → writer（PCAP/NIC）。

### 11.5 错误分支

**create-time 2 门**（`CheckProtoFlat` presence / `checkLayerChainStaticCopy`）+ **task-time planner 10 分支**（`planner.go:40-95`）+ **builder 6 分支**（`builder.go:1104-1128`）全部传 task error（今日实跑：5 例 task-time 负例 0 帧，2 例 create-time 负例无落盘——**零假成功**）。

**双门文案一致性（实测）**：planner 与 builder 对 label 上界 / TC 上界 / S 位置 / 空栈四条的文案**逐字相同**（`planner.go:62/66/69/72` vs `builder.go:1118/1119/1122/1123`）——两层门互为冗余（planner 在链路径先执行，builder 在直挂 legacy 路径兜底）。

### 11.6 性能边界

见 §6（channel 流式、per-flow 局部状态、标签栈只读复用、无跨流共享、无锁；吞吐数字待确认）。

### 11.7 与现有逻辑的冲突点

- **静态复制门已扩扫 mpls**（`schema/semantic.go:214` 名单含 `"mpls"`）→ **与 opcua 的 G-OPCUA-1 情形相反**：`mpls_vn_static_port` 负例**真能判死**（今日实跑 create-time 拒，无落盘）。
- **presence 门已有 mpls 分支**（`strategy_convert.go:8947`）→ 同 h323/ngap/telnet/sip/radius，**与 opcua 相反**：`mpls_vn_presence` 负例**真能判死**。
- **顶层未知键通用门仍缺**：白名单外游离顶层键（如 `{layers:[…], bogus: 1}`）今日**不判死**（`CheckProtoFlat` 只查各协议子映射白名单）→ 同 G-OPCUA-1 / G-MOXA-2 口径，**不建该负例**（建了会真绿 = 假通过）→ G-MPLS-15。
- **端口豁免双名单**：`chain_planner.go:758`（`validateBaseDstPortHandled`）与 `:996`（源端口 switch）两处均含 `"mpls"`——**任一处漏改都会使 mpls 链在 base 校验期报 `source port is required` / `destination port is required`**。今日两处均在（机读实测）。
- **`isL2OnlyProtocol` 不含 mpls**（`strategy_convert.go:231` 名单）→ `mapToFlowSpec` 会为 mpls 填默认 IP（10.0.0.1/20.0.0.1）与默认端口（12345/80）——**这是本协议"扁平缺省"的来源**，链路径下地址由 `ip` 层显式值覆盖（`chain_planner_chain.go:380-410`），端口由 `mpls` 层显式值覆盖。**行为正确**（mpls 有内层 IP，不是 L2-only），但需注意与 goose/sv 的差异。
- **DSCP 缺省 0x20 进帧**（§3.4 注）：框架级 `DefaultDSCP = 0x08` 使**所有** mpls 帧的 TOS = 0x20，而**存量 14 例零断言**（G-MPLS-6）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 3 文件 + builder 栈写入段 + 接线 8 处（registry/protocols/translate/convert×2/chain_planner_util/chain_planner×2/semantic/layer_dyn）；**不触及其他协议**（`writeMPLSLabels`/`validateMPLSConfig` 仅由 `L2.MPLS != nil` 触发，其他协议零影响）。cases 回滚 = 恢复 14 例 JSON（产物文件，非文档）。

---

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 **12/14 例顶层 = `{layers}`**；**2 例例外**——`mpls_port_dyn` 顶层含 `group_id`（**CORE_MEMORY §1.11 白名单结构键**，跨流绑定，合规）与 `mpls_vn_presence` 顶层含 `mpls:{}`（**判死负例的必需形状**）；**违规游离键 = 0**；无旧键可删（本协议**从未用过顶层地址/端口/count**） | §12.1；`cases/mpls.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 mpls 流量模板（层链 + `mpls` 层 8 键）；任务 = 多策略合跑 + 总量封顶；框架语义未动 | §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：**数据面豁免**（无控制面/无事务/无会话/无跨流——R3031 §3.1 标签是局部标识符非连接标识）；插入位置（终结层）；时间线（`frames` 顺序 + IP ID 逐帧 +1） | §12.3 + §5 |
| §4 查规范 | RFC 3031/3032/5462 全文实测拉取 + **22 处落码条款号校正**（§0.1）+ tshark 3.6.14 `mpls.*`（**5 字段**）+ 今日实跑 12 份 pcap 实测 + 落码反推；八项矩阵 + 子表①②③ | §10 + §0.1/§0.2 |
| §5 依赖与错误 | `DependsOn ["ip"]` 单值（`registry.go:1811`）；**2 create-time + 5 task-time 负例** + 7 条未入例拒绝分支；失败传 task error（今日实跑：5 例 0 帧 + 2 例无落盘） | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待确认，不写承诺；pcap 路今日已跑/NIC 路未跑明写） | §6 |
| §7 三份文档 | `121-mpls-{design,testcase}.md` v1.0.0（本版，首次成文）+ D-MPLS-1（§11，as-built）+ T-MPLS-1…14（`docs/TEST_CASES.md:3372` 草稿层）+ 14 ID（testcase §2） | 修订记录 |
| §8 设计先行 | **例外**：本协议为批次二 **as-built 型**——实现与 cases 已在案（P5 于 2026-09-19 收官，今日复跑全绿），本版把既有实现如实写成契约；非"设计先行"路径 | 任务书 |
| §9 测试三源 | 三源 = RFC 3031/3032/5462（§10）+ D-MPLS-1（§11）+ tshark 3.6.14 `mpls.*` 5 字段与**今日实跑 12 份 pcap**（**抓包级**：28 条 field + 1 条 frame 断言逐条复核命中）；14 ID 逐项回指；存量审计去向 testcase §8 | `121-mpls-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 本版自审（机读复核计数与断言）+ 收官隔离复审（subagent）；红先绿后 | 自审日志 |
| §11 白话 | 本文首节白话一句 | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组（`ip.src/dst` + `mpls.src_port/dst_port`）全开（allowlist 实测）；业务 5 键全关 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `mpls` 已在 `registry.go:1811` 注册（**不新增层**）；生成表 127 层中 `mpls` 条目 **8 字段与 registry 逐键一致**（机读实测 `schemas/v1/generated/layers.generated.json`）；**本车道不改 registry，无需重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `mpls.*`/`ip.*`/`udp.*`/`tcp.*` + frames 双通道 → **先跑后钉**；pcap 落本车道私有目录 `/tmp/mpls-doc-verify/mpls/`（**未覆盖共享 `/tmp/mcp-pcaps/mpls/`**）。**本车道已跑**：14 pass / 0 fail / 0 error | testcase §7 + §0.2 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/mpls.json` | **14** | **`{layers}` ×12** + **`{layers, group_id}` ×1**（`mpls_port_dyn`，白名单结构键）+ **`{layers, mpls}` ×1**（`mpls_vn_presence`，**判死负例必需形状**） | **`[ip, mpls]` ×14**（全例同形） | 7/7 = `{expect_error, error_contains, notes}` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 本协议**从未用过顶层地址**；14/14 地址已住 `layers[0].ip.{src,dst}` |
| `src_port` / `dst_port` | **0** | 已住 `layers[1].mpls.{src_port,dst_port}`（13/14 显式或动态；`mpls_v6` 亦显式） |
| `count` | **0** | 走 `strategy_fc`（2 例）/ `flow_control`（本版未用） |
| 顶层 `mpls` 子映射 | **1**（`mpls_vn_presence`） | **唯一残留，且是判死负例的必需形状**（presence 门要求顶层出现 `mpls` 键才判死）；**不是待迁移的旧格式** |
| `strategy_fc` | **2**（`mpls_vn_static_port`、`mpls_port_dyn`） | 结构键，白名单内（CORE_MEMORY §1.11） |
| `group_id` | **1**（`mpls_port_dyn`） | 结构键，白名单内（跨流绑定） |

**结论**：本协议存量**违规游离顶层键 = 0**——§1 门的动作 = ①**无旧键可删**（顶层地址/端口/count 从未出现）；②收官自查行「**非负例**顶层键（去白名单后）= 0」**今日即成立**（机读实测：13/13 非负例顶层键 ⊆ `{layers, group_id}`，其中 12 例仅 `layers`、1 例 `mpls_port_dyn` 含白名单结构键 `group_id`）；③A′ 新增例全部沿用纯 layers 形。

> **`mpls_vn_presence` 形状点名（批次二任务书强制）**：该例 `spec_json` = `{"layers":[{"ip":{...}},{"mpls":{...}}],"mpls":{}}`——**层链 + 顶层空子映射并存**。这是**判死负例的标准形状**（presence 门扫的就是顶层 `mpls` 键，空 map 也死），**与"旧格式残留"是两回事**。验收口径按批次二任务书：**非负例顶层键为 0** 即通过。

目标形状样例见 §2（顶层仅 `layers`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"mpls":{}}` **今日会被拒**（`CheckProtoFlat` 有 mpls 分支，`strategy_convert.go:8947-8951`）→ **已建该负例**（`mpls_vn_presence`，**与 opcua 的 G-OPCUA-1 情形相反**；今日实跑 create-time 拒，无落盘）；
- ② 白名单外游离键判死（`unknown field`）**无通用门**（框架级 unknown-key 白名单未落）→ A′ 候选（G-MPLS-15，**不建**——建了会真绿）；
- ③ **7 条负例每条带锚词**（已齐，§7）；
- ④ 收官自查「**非负例**顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

**会话表**：**不适用**（豁免）。理由：MPLS **无连接**——标签是"短定长、局部有效"的标识符（R3031 §3.1 逐字："a label is a short, fixed length, locally significant identifier"），**不是连接标识**；LSP（R3031 §3.15）是**预先配置的转发状态**，不是运行时建立的会话。链内**无 tcp/udp 层**，故**连"连接"这个承载概念都不存在**。**豁免依据**：CORE_MEMORY §3.14 的"无长连接载体 → 豁免"口径；本协议比 icmpv6 更彻底（icmpv6 尚有 IP 承载语义，mpls 连传输层都没有）。

**事务序列**：**不适用**（豁免）。理由：MPLS 数据面是**单向**的（ingress → egress），**无请求/响应**，无事务边界。唯一的"序列"是 `frames` 的 N 帧顺序（§5），它是**同一动作的重复**（每帧仅 IP ID 不同），不是事务。

**关联关系**：**不适用**（豁免）。理由：无控制流 → **无派生流**（LSP 不由本引擎的某个流"派生"，它是网络预先存在的转发状态）；无 `driven_by` 锚定；无父子流。**这是本协议与 h323（有 RTP/RAS 派生流）的关键差异**。

**插入位置**：**终结层**（`[ip, mpls]`，raw-IP 自驱；`isRawIPChain` 名单含 mpls，`chain_planner_util.go:49`）。链内**无中间层**；mpls 生成器自产完整包（Eth + 栈 + 内层 IP/L4），builder 只负责写 L2（含强制 EtherType）与装配内层 L3/L4。

**时间线**：`frames` 顺序发射（帧 1..N，IP ID 1..N）；**无并发、无交错**；`concurrent` 例外路径**不启用**；多流（#14）= 各流独立四元组、独立帧序列（`group_id` 固定单 worker FIFO 保证顺序）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组 4 项**：`ip.src` / `ip.dst` / `mpls.src_port` / `mpls.dst_port`——**全开**（allowlist 实测 `layer_dyn.go:53`：`"mpls": {"src_port": true, "dst_port": true}`；`ip` 行 `{"src","dst","ttl"}`）。**注意**：链内**无 `tcp`/`udp` 层**，故端口动态**必须**写 `mpls` 层（不能写 `tcp.src_port`）——写 `tcp` 层会因链内无该层而被拒或静默无效。

**业务字段 5 项**：`labels` / `multicast` / `inner_proto` / `direction` / `inner_payload`——**全关**（allowlist 无这些键，`grep` 零命中实测；对象即 `does not support dynamic`）。**理由**（`layer_dyn.go:49-52` 注释逐字）：`labels` = 路径身份（逐流变会使同一策略产出不同 LSP，破坏策略语义）；`multicast` = EtherType 选择器；`inner_proto` = 内层选择器；`direction` = 方向选择器；`inner_payload` = 载荷（逐流变体需求列 A′ 候选，G-MPLS-13）。**与 h323/ngap/telnet/sip/radius 同判**（`layer_dyn.go:46-53` 注释链）。

**序号算法实读**：

| 环节 | 代码位置 |
|---|---|
| allowlist 白名单 | `layer_dyn.go:53`（`"mpls"` 行） |
| 层动态对象解析 | `parseLayerDyn`（`layer_dyn.go:78`）→ mpls 分支 `layer_dyn.go:238-246`（`src_port` → `out.MPLS.SrcPort`，else → `out.MPLS.DstPort`） |
| 逐流解析落 spec | `resolveLayerTuple`（`layer_dyn.go:770`）→ MPLS 块 `layer_dyn.go:822-833`（`ResolvePortValue`，`non-zero wins`） |
| 值算法 | `ResolvePortValue`（int 面，五种策略 fixed/inc/rand/list/pattern） |
| 保底自增 | worker 注入 `12345 + i`（`DefaultSrcPort`，`strategy_convert.go:49`） |
| 静态复制门 | `checkLayerChainStaticCopy` 扫描列表已含 `mpls`（`schema/semantic.go:214`） |

**逐流成对序实证（今日实跑）**：`mpls_port_dyn`（`src_port` inc 30000–30001，`flows=2`，`group_id` 固定单 worker FIFO）——流 1 = 帧 1 源口 **30000** + `ip.src` **10.0.1.1**、流 2 = 帧 2 源口 **30001** + `ip.src` **10.0.1.2**（4 条断言逐条实跑命中）。

**未覆盖的动态格（A′ 立项，不得冒充已覆盖）**：`mpls.dst_port` 动态对象、`ip.ttl` 动态、`rand`/`list`/`pattern` 三种策略、`inc` 回绕（range 用尽）——G-MPLS-13。

---

## 13. P3 对接清单（T-MPLS 草稿输入；正文落 testcase 文件）

14 ID（7 正 + 7 负）+ 包数/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。**A′ 候选 16 例**：`mpls_multi_label`（N=2 栈，G-MPLS-2）/ `mpls_neg_empty_stack`（空栈，§7.3 R-3）/ `mpls_neg_bad_ip`（IP 不可解析，R-2）/ `mpls_neg_negative_frames`（R-4）/ `mpls_neg_mpls_gre`（R-5）/ `mpls_neg_mpls_pppoe`（R-6）/ `mpls_neg_inner_nonip`（R-7）/ `mpls_ttl_explicit`（显式 TTL，G-MPLS-11）/ `mpls_payload_default`（`inner_payload` 缺席，G-MPLS-11）/ `mpls_label_max`（0xFFFFF 等值，G-MPLS-12）/ `mpls_tc_max`（7 等值，G-MPLS-12）/ `mpls_vlan`（VLAN 承载，G-MPLS-5）/ `mpls_reserved_label`（保留值 0-15，G-MPLS-4）/ `mpls_dst_port_dyn`（G-MPLS-13）/ `mpls_port_rand`（G-MPLS-13）/ `mpls_neg_mixed_family`（异族混写，§8）。

---

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| **G-MPLS-1** | **落码 RFC 条款号错误 22 处**（§0.1 逐条列出，grep 机读行号）：`RFC 3032 §3.1`→**§2.1**（**14 处**：`builder.go:93/99/966/1062/1068/1097/1122`、`types.go:3309/3354/3363/3374/3379`、`planner.go:11/66`）；`RFC 3032 §3.10`→**§5**（EtherType **4 处**：`builder.go:85/1018`、`types.go:3014/3330`）/**§2.1+§6**（标签值 **1 处**：`types.go:3365`）；`RFC 3032 §3.9`→**§2.2+§1**（**2 处**：`planner.go:48`、`builder.go:1113`）；`RFC 3031 §3.12`→**§3.25.1**（**1 处**：`planner.go:99`）。**保留正确**：`RFC 3032 §2.1`（9 处）、`RFC 5462`（2 处）。**注**：`grep §3.1` 会被 `§3.10` 连带命中 5 处（前缀陷阱），本节数字一律按**行级归属**（§3.1 = 14 / §3.10 = 5） | **代码阶段**（注释与错误文案修正；**不影响用例**——锚词均不含条款号，§7.2 注）。**本车道不改代码**。附注：RFC 3031 是否另有"in place"表述的旁证章节未逐节穷举，若需绝对确认须通读全文 → 待确认 |
| **G-MPLS-2** | **多层标签栈（N≥2）用例零覆盖**——代码支持（`writeMPLSLabels` 循环，`builder.go:1075-1093`；单测 `planner_test.go:161-192` 验证 N=2 的 S 位 0/1 分布），但 `cases/mpls.json` **无 N≥2 例**；`planner_test.go:160` 注释引用的"pcap 7、mpls_http.pcap"是**外部参考 pcap**（不在本仓、今日不可复现），**不是本仓用例** | A′ 补例 `mpls_multi_label`（N=2，断言栈顶 S=0/栈底 S=1 + 内层起点 offset 22） |
| **G-MPLS-3** | **标签 TTL 与内层 IP TTL 不校验一致**——R3032 §2.4.3 规定首次打标签时标签 TTL **MUST** 取 IP TTL 值；本实现二者**各自独立缺省 64**（同源常量故缺省路径一致），但用户显式写 `labels[].ttl ≠ ip.ttl` 时**无任何校验**（可产不一致帧） | A′ 候选：拒或告警（**需先裁定**——R3032 §2.4.3 的 MUST 是否约束 ingress 生成器；本引擎非 LSR，可能属"明确不解决"）。今日不得声称该一致性受保障 |
| **G-MPLS-4** | **保留标签 0-15 无特殊语义**——R3032 §2.1/§6 定义 0=IPv4 Explicit-Null、1=Router Alert、2=IPv6 Explicit-Null、3=Implicit-Null、4-15 reserved；本实现**作普通 20 位数值写入**，不触发弹栈/告警/拒收。D-MPLS-1 已诚实注记"保留标签 0-15 未校验"（C 类） | **明确不解决**（本引擎非 LSR，无弹栈行为）+ A′ 补例 `mpls_reserved_label`（钉"接受为普通值"这一事实）。用例**必须避开**把保留值当作"特殊语义"断言 |
| **G-MPLS-5** | **VLAN 承载无例**——代码支持（`builder.go:1024-1027`：栈起点 `mplsOff = 18`；`:1036-1040` EtherType 写 offset 16-17），今日 14 例**均无 VLAN** | A′ 补例 `mpls_vlan`（断言栈起点 18 + EtherType 位置） |
| **G-MPLS-6** | **DSCP 缺省 0x20 进帧但零断言**——框架级 `DefaultDSCP = 0x08`（CS1，`strategy_convert.go:64`）经 `mapToFlowSpec`（`:346`）与 `finalEmit`（`chain_planner.go:1564`）写入内层 IP TOS，**全部 14 例的内层 TOS 都是 0x20**（今日实跑实证），但**无一条断言**。这是"字段被填充但无断言"的典型形态（CORE_MEMORY 测试政策 §5 反面案例） | A′ 候选：收编 `ip.dsfield` 断言（**或**裁定 DSCP 属框架面不属本协议断言面——两者皆可，须显式选一） |
| **G-MPLS-7** | **builder 侧 6 条拒绝分支零用例**：MPLS+GRE / MPLS+PPPoE / 内层非 IP / 空栈（builder 面）/ label 上界（builder 面）/ TC 上界（builder 面）——链路径下 planner 先拦，builder 面**不可达**；仅 legacy 直挂路径可达（`main.go` 的 legacy planner 直挂，链路径已迁移） | A′ 候选（若 legacy 直挂路径仍受支持则补单测；若已废弃则登记为死代码候选 → 需裁定）。今日不得声称 builder 侧门已被端到端覆盖 |
| **G-MPLS-8** | **结果产物相对链接全失效**——`trafficgen/docs/protocol-pcap-test/mpls.md`（**tracked**）含 **12 条** `[pcap](mpls/xxx.pcap)` 相对链接，但 `trafficgen/docs/protocol-pcap-test/mpls/` 目录**不存在（0 个 pcap，`ls` 实测 No such file or directory）**。**注**：该文件末次提交 `d62db10`（2026-09-19）**晚于**扁平判死提交 `0417be5`（2026-09-13），故**不构成"产物过期"缺口**（与 pcep G-PCEP-11 判定条件相反）；且其 14/14 数字**今日已被本车道独立复跑证实**（§0.2）。真实缺口**仅限**"链接悬空 + pcap 无留档" | **代码阶段**（重跑后重生成产物并落 pcap 到 `docs/protocol-pcap-test/mpls/`）；本版**不删不改**（tracked 产物）。**不得**把本缺口读成"套件不可跑"或"数字未经证实" |
| **G-MPLS-9** | **NIC 输出路径今日未跑**——本车道只跑了 pcap 路（§0.2）；NIC 经 tcpdump 捕获（`nic_capture` 开关）今日未执行。本层零专属断言（全部断言都是协议字段，与输出路径无关），但"两路径共用同一契约"这一条**今日只有 pcap 侧实证** | **代码阶段**（NIC 路回归；属批次级"双输出全量回归"范畴，非本协议文档阶段缺陷） |
| **G-MPLS-10** | **内层 TCP 恒为裸头**——链路径下 `spec.TCP` 恒 nil（`strategy_convert.go:446` 是唯一来源，链配置不可达），故 `inner_proto: 6` 时 `l4.Seq/Ack/Flags/WindowSize` 全 0（`planner.go:189-194` 的赋值分支不可达）。**这不是缺陷**（D-MPLS-1 已按"④ C 类：内层 TCP 无握手/序号语义"裁定），但须显式声明：**本引擎不生成 TCP 握手/序号/窗口**，内层 TCP 是"带正确端口与校验和的裸头" | **明确不解决**（legacy 单帧数据面合同）+ 用例 #12 的 notes 已声明。**不得**新增"TCP 握手/seq/窗口"类断言 |
| **G-MPLS-11** | **显式 TTL 与缺省 payload 两格零覆盖**——`labels[].ttl` 显式值（如 255，单测 `planner_test.go:71/87` 用过）与 `inner_payload` 缺席（回退 `spec.Payload`，两者皆空 → 空载荷）**今日无用例** | A′ 补例 `mpls_ttl_explicit` / `mpls_payload_default` |
| **G-MPLS-12** | **边界等值格缺失**（CORE_MEMORY §4 最小清单"边界相邻值"要求）：`label = 0xFFFFF`（上界**等值**，应过）与 `tc = 7`（上界**等值**，应过）今日无例——今日只有"上界 +1 拒"（#4/#5），**缺"上界等值过"的对偶格** | A′ 补例 `mpls_label_max` / `mpls_tc_max` |
| **G-MPLS-13** | **动态面覆盖不全**——今日只覆盖 `mpls.src_port` 的 `inc` 策略（#14）；`mpls.dst_port` 动态、`ip.ttl` 动态、`rand`/`list`/`pattern` 三策略、`inc` 回绕**均无例** | A′ 补例（§12.12 末段） |
| **G-MPLS-14** | **第三源（真实设备/开源实现线字节）未取到**——真实 LSR/路由器（Cisco/Juniper/FRR）的标签栈线字节未抓包核对；D-MPLS-1 记载的探针 pcap `/tmp/probe-iana/mpls.pcap` **今日不存在**（`ls` 实测），"探针验证"**不可复现** | 待确认：抓真实设备或 FRR/Linux 内核 MPLS 栈的包对照；确认前按 RFC 原文 + 本仓实跑钉，**不声称与真实设备字节一致**。**风险（须写清）**：若真实设备对保留标签/TTL 的处理与本实现不同，**不影响**今日 14 例（断言只覆盖 label 100/tc 0/ttl 64 等非保留值），但 G-MPLS-4/G-MPLS-3 的裁定需据此调整 |
| **G-MPLS-15** | **顶层未知键无通用门**——白名单外游离顶层键（如 `{layers:[…], bogus: 1}`）今日不判死（`CheckProtoFlat` 只查各协议子映射白名单） | **框架面**（等框架级 unknown-key 白名单；与 G-OPCUA-1/G-MOXA-2 同款）。**本协议不建该负例**（建了会真绿 = 假通过） |
| **G-MPLS-16** | **7 条负例 `expect` 含 `notes` 键**——与严格两键口径（`{expect_error, error_contains}`）不符；`notes` 是文档性字段，**不影响断言判定**，但违反 §7「负例纯净性」的形状要求 | **代码阶段**（P4 删 7 处 `notes`）；**本车道不改 cases JSON**（任务书边界）。**注**：同一批的 `mpls_single_label_ipv4` 等正例的 `notes` **保留**（正例无此限制） |
| **G-MPLS-17** | **`mpls_single_label_ipv4` 用 `min_packets: 1` 而非 `packet_count: 1`**——14 例中唯一一例；宽松断言（"≥1 帧"）**无法捕获帧数漂移**（若实现误发 2 帧，本用例仍绿）。这是 CORE_MEMORY 测试政策 §5「断言可观察结果而非结构」的边界形态 | A′ 收窄为 `packet_count: 1`（**必须跑后重钉**：先确认实跑恒 1 帧，再改断言——本车道今日实跑已确认帧数 = 1，证据在设计 §0.2） |
| **G-MPLS-18** | **`direction=down` 的 MAC 交换面零断言**——用例 `mpls_direction_down` 的 summary 与 notes 声称"地址+**MAC** 全交换"，实测 `expect.fields` **只有 3 条**（`ip.src`/`ip.dst`/`mpls.label`），**无 `eth.src`/`eth.dst` 断言**；`planner.go:173-176` 的 MAC 交换代码路径**今日无断言证据**（与真实 L2 多播 MAC 推导同属"代码有分支、用例无断言"形态） | A′ 补 `eth.src`/`eth.dst` 断言（**须先跑后钉**确认 MAC 实际值）；今日**不得声称** MAC 交换面已覆盖 |

---

## 15. 修订记录

- v1.0.0（2026-09-29，批次二文档轨 as-built 首版）：首次成文（本仓库无 mpls 旧稿，§0）。**核心产出**：①§0.1 **落码 RFC 条款号校正表**——22 处错误引用逐条回查 RFC 原文（`§3.1`→`§2.1` 等），保留 11 处正确项（`§2.1` 9 + `RFC 5462` 2，G-MPLS-1）；②§0.2 **今日实跑复核**（14 pass / 0 fail / 0 error，12 份 pcap 落私有目录，28 条 field + 1 条 frame 断言逐条命中，与 2026-09-27 存盘产物字段面 7/7 一致）；③§3.1 **位域布局逐位钉死**（20/3/1/8 非字节对齐 + 拼装公式 + 大端）；④§3.5 **标签栈操作与 TTL 逐条对照 R3031 §3.10 / R3032 §2.4**，诚实声明"只做 push、不做 swap/pop、不减 TTL"；⑤§12.1/§12.3/§12.12 强制展开（**数据面五件套豁免**）+ 12-P2；⑥§11 D-MPLS-1 as-built 定稿；⑦缺口 **G-MPLS-1…G-MPLS-18**（18 条，含 22 处条款号错误、多层栈零覆盖、NIC 未跑、结果产物链接失效等）。自审 3 轮，末轮干净（机读复核：缺口 18 条编号连续 / 门1 十四行 / 14 ID 三处一致 / 28 field + 1 frame / 四表计数机读复算 / 22 处条款号按行级归属复核）。

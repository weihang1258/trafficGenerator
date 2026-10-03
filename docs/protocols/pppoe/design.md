# #110 pppoe（PPPoE · 以太网承载点对点协议，RFC 2516）设计契约

> 版本：v1.0.0（批次二 as-built 文档轨；修订记录见 §15）
> 日期：2026-09-29
> 车道：文档轨（#110 pppoe）
> 旧基线：**无外部旧稿**——旧目录 `docs/protocol-designs/` 无 pppoe 设计/用例文档（`git log --all --name-only | grep -i pppoe` 仅命中本设计契约与实现文件，机读实测）。本协议**继承来源是两份内部契约**：`docs/CODE_DESIGN.md:2882` **D-PPPOE-1**（六裁定，2026-09-20 已验收）+ `docs/TEST_CASES.md:3744` **T-PPPOE-1…24**（24 例清单，P5 已执行 24/24×2 全绿）。本版把二者 + 实现 + cases 写成 as-built 契约，冲突处按 cases/实现钉，§0 逐条列出。
> 存量用例：`trafficgen/test/protocol_pcap/cases/pppoe.json`（**24 例 = 18 正 + 6 负**，已机读实测；顶层键已是纯层链形，零残留，见 §12.1）
> 规范基线：① **RFC 2516**（A Method for Transmitting PPP Over Ethernet，1999-02；§4 Payloads / §5 Discovery 四步 / §5.5 PADT / §6 PPP Session Stage / §7 LCP Considerations / Appendix A 标签表，下称 **RFC2516**，原文已拉取核对）；② **RFC 1661**（PPP，STD 51；§2 封装 / §3.2 阶段图 / §4 选项协商自动机 / §5 LCP 报文格式 / §6 LCP 配置选项，下称 **RFC1661**）；③ **RFC 1334**（PAP；§2.2 报文格式）；④ **RFC 1994**（CHAP；§3 配置选项 / §4.1 Challenge 与 Response 报文格式）；⑤ 本机 tshark 3.6.14 `pppoe.*`/`ppp.*` 字段表（§1）；⑥ 本仓库落码（`internal/protocol/pppoe/` + core 侧 9 处接线，§11）；⑦ 内部契约 D-PPPOE-1 / T-PPPOE-1…24（非外部规范）
> 白话一句：**以太网上的"拨号"——先喊一嗓子找服务器（PADI 广播→PADO 应答→PADR 选定→PADS 发号），拿到会话号后开始 PPP 协商（LCP 谈 MRU 和魔数，可选 PAP/CHAP 认证），然后在这条会话上跑 IPv4 数据，最后 PADT 拆线。所有字段都是网络序（大端）。**

## 0. 沿革与内部契约校正声明（门1 必答：基线继承关系）

本版是 pppoe 在当前权威目录下的**首份**协议契约（此前无任何 pppoe 设计/用例文档落盘）。继承来源为两份内部契约，本版逐条给出校正结论（区分"承契约"与"契约过时/引错"）：

| # | 内部契约说法 | HEAD 实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | 本协议无 `docs/protocol-designs/` 旧稿（§0 头注） | `git log --all --pretty=format: --name-only \| grep -i pppoe` 只命中 `trafficgen/docs/protocol-pcap-test/pppoe.md` + 实现/测试/cases 文件，**无 design/testcase md** | **首份文档**；本版不搬任何旧稿结构，直接按 v1.3 需求文档撰写 |
| 2 | D-PPPOE-1 裁定3：PADT 依据标"RFC 2516 **§5.6**"（`CODE_DESIGN.md:2888/2894`）；cases 全部 summary 同标 §5.6 | RFC2516 原文：**§5.5 = The PPPoE Active Discovery Terminate (PADT)**；**§5.6 不存在**（§5 只到 §5.5，其后即 §6 PPP Session Stage） | **引错章节号**（应为 **§5.5**）；实现行为正确、断言正确，仅引注错 → G-PPPOE-1 |
| 3 | D-PPPOE-1 裁定6：code 表 / PPP 协议字段表依据标"RFC 1661 **§5**"（`CODE_DESIGN.md:2895`）；cases `pppoe_lifecycle_full` summary 标"RFC 2516 §5+§5.6" | RFC1661 原文：**§5 = LCP Packet Formats**；**§2 = PPP Encapsulation**（含 Protocol 字段与 code 表）；RFC2516 **§5 = Discovery Stage**（code 表在 §5.1–§5.5 各节） | **引错章节号**（PPP Protocol/code 表应引 **RFC1661 §2** 或 **RFC2516 §5.1–§5.5**）→ G-PPPOE-1 |
| 4 | 实现注释：MRU 依据标"RFC 1661 §6.1"（`planner.go:65/353`） | RFC1661 **§6.1 = Maximum-Receive-Unit (MRU)** ✓ 正确 | 承（正确） |
| 5 | 实现注释：Magic-Number 依据标"RFC 1661 §6.13"（`planner.go:67/356/206`）；"MUST be chosen randomly" | RFC1661 **§6.13 不存在**（§6 只到 **§6.6 ACFC**）；**§6.4 = Magic-Number**。原文措辞："The Magic-Number **MUST** be chosen ... random"（§6.4） | **引错章节号**（应为 **§6.4**）；随机性要求属实 → G-PPPOE-1 |
| 6 | 实现注释：Auth-Protocol 选项依据标"RFC 1661 **§8**"（`planner.go:124`）与"RFC 1334 §2.2 / RFC 1994 §3"（`planner.go:351`） | RFC1661 **§8 不存在**（只到 §6）；Auth-Protocol 选项 = **§6.2**；认证阶段 = **§3.5 Authentication Phase**。RFC1334 **§2.2 = Packet Format**（Authenticate-Request 是 **§2.2.1**）；RFC1994 **§3 = Configuration Option Format**，**Challenge/Response 报文格式 = §4.1** | **引错章节号**（RFC1661 §8→§6.2；RFC1334 §2.2→§2.2.1 正确面；RFC1994 §3→§4.1）→ G-PPPOE-1 |
| 7 | 实现注释：PAP 依据标"RFC 1334 §2.1"（`planner.go:70/543/559`） | RFC1334 **§2.1 = Configuration Option Format**；**报文格式 = §2.2**（Authenticate-Request §2.2.1 / Ack §2.2.2） | **引错章节号**（应为 **§2.2.1 / §2.2.2**）→ G-PPPOE-1 |
| 8 | 实现注释：CHAP 依据标"RFC 1994 §3"（`planner.go:76/572/586/600`） | RFC1994 **§3 = Configuration Option Format**；Challenge/Response = **§4.1**，Success/Failure = **§4.2** | **引错章节号**（应为 **§4.1 / §4.2**）→ G-PPPOE-1 |
| 9 | D-PPPOE-1 裁定4：`sessions[]` 与顶层行为键互斥；"模板键共享" | 实现：互斥键集合 = **行为 6 键** `{session_id, skip_discovery, data_frames, data_payload, inner_proto, data_direction}`（`schema/semantic.go:331` + `planner.go:162-171` 同集合同序）；模板键 9 个可共存 | 承（正确）；本版 §11.3 把两集合逐键列开 |
| 10 | D-PPPOE-1 裁定2 注记③："链路径 eth MAC 注入点未证，v1 口径=MAC 走 spec 缺省" | `chain_planner.go:1352/1407/1469/1549` + `chain_planner_translate.go:337` 有 `pkt.L2.SrcMAC == ""` 回填；但 `planner.go:249-254` **非空 MAC 恒由 planner 写入**（`aa:bb:cc:dd:ee:01/02`），回填分支对 pppoe 恒不触发 | **链路径 eth 层 MAC 覆写今日不可达**（planner 抢先写死）→ G-PPPOE-2；本版 §3.1 按实现钉 |
| 11 | D-PPPOE-1 P4 注记（B′ 账本）："链路径内层 L4 端口恒 0" | cases 24/24 无端口键；`chain_planner.go:774-776`（src 0-keep）+`:996-997`（dst 0-keep）双名单含 pppoe；`planner.go:457-461` 把 `spec.SrcPort/DstPort` 直写内层 L4 | 承（正确）；本版 §3.7 明写"内层端口恒 0"为**已声明合成面** |
| 12 | T-PPPOE-1…24 §9.52 对账两行：逻辑点总数 **45** → 建例代表 39 + 注记 6 = 45/45 | `coverage_gate.py:3681 check_pppoe` 登记 45 检查（场景 24 + 键 15 + 锚词 6），**今日跑出 45/45 全绿**（`python3 tools/coverage_gate.py pppoe`，出口 0，实测） | 承（正确，今日复跑证实）；本版 §10 按规范要求面重列（不复用 45 口径） |
| 13 | T-PPPOE 表：TLV 标签表列"0104 发射+0110 builder 支持未编排+0103/0105/0201/0202/0203 未实现" | `builder.go:472-480 serializePPPoETags` 是**通用 TLV 序列化器**，任意 `PPPoETag{Type,Value}` 均可序列化；`planner.go:310-343` 只编排 **0x0101/0x0102/0x0104** 三种 | 承（正确）；"builder 支持未编排"= 未编排面，本版 §10.3 按立项登记 |
| 14 | D-PPPOE-1 裁定3：PADT 键 `padt` bool **缺省 true** | `planner.go:480` `if sessCfg.PADT == nil \|\| *sessCfg.PADT` ✓；`parsePPPoEConfig` 用 `getBoolPtr`（`strategy_convert.go:4208`，P5 抓出的漏接 bug 修复点） | 承（正确）；指针三态在 §5 明写 |
| 15 | D-PPPOE-1 裁定5：多流身份锚=Session ID，MAC 恒 spec 值不递增 | `planner.go:521` `sessFlowID = fmt.Sprintf("%s-pppoe-sess%d", flowID, sessCfg.SessionID)`；`planner.go:248-254` MAC 恒写 | 承（正确）；§5 会话表逐项列开 |

**依赖链判定纪律**：以上 15 项中 #2–#8 为**可判题**（RFC 原文逐节标题对照，直接判定"引错"），不问偏好；#10 为**代码可判题**（planner 恒写非空 MAC ⇒ 回填分支不可达）。不可判的（现网 BRAS 具体实现行为、Relay-Session-Id 编排需求）标"待确认"并写清确认方式（G-PPPOE-5）。

**产物过期登记（不构成缺口）**：`trafficgen/docs/protocol-pcap-test/pppoe.md`（**tracked 结果产物**，`git ls-files` 可证）写 `Cases: 24 — pass 24, fail 0, error 0`，末次提交 `bdd6275`（**2026-09-20**）——**晚于**判死提交 `0417be5`（2026-09-13，扁平判死泛化全协议 `CheckProtoFlat`）。故该产物**不属过期**（与 opcua G-OPCUA-10 相反）。**但**其链接的 `trafficgen/docs/protocol-pcap-test/pppoe/` 目录**不存在**（`.gitignore:88` `*.pcap` 使 pcap 从不入库），24 条 `[pcap](pppoe/<id>.pcap)` 链接**全部断链**——属"结果数字已随 P5 提交、pcap 留档不入库"的既知形态，本版**不以任何形式**（含"今日已复跑"）引用该产物作为套件可跑证据；本车道**未跑**该套件。

**pppoe 特殊性（须写清，不得含糊）**：pppoe 是本批**唯一 L2 承载（无外层 IP 传输层）的 raw 自驱协议**——帧结构为 `Eth + PPPoE + PPP + 内嵌 IPv4`，**外层没有 IP 头、没有 TCP/UDP 头**，因此①"端口"概念只存在于**内嵌** IPv4 的 L4 层且链路径恒 0（§3.7）；②`ip` 层在链上承载的是**内嵌** IPv4 语义而非外层地址（§2）；③地址族只支持 IPv4，IPv6 即负例（§7 N-4）。

## 1. 范围、profile 与实现状态边界

本版定义 **PPPoE（RFC 2516）承载于以太网** 的流量生成：发现阶段四步（PADI/PADO/PADR/PADS）、PPP 会话阶段（LCP 协商 + 可选 PAP/CHAP 认证 + IPv4 数据面）、拆线（PADT）。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `pppoe_eth_v1`（主） | 以太网直载（无 VLAN/MPLS/GRE），fixture `[ip,pppoe]` | Discovery 四步 → LCP 对 → 可选认证 → 1..N 内嵌 IPv4 数据帧 → PADT | 真实 BRAS 的会话资源分配、真实认证结果 |
| `pppoe_multi_session_v1` | 同上，`sessions[]` 多生命周期 | 每项一条独立生命周期（各自 Session ID、各自 Discovery） | 会话间并发交错（实现为**整块顺序**，§5） |
| `pppoe_skip_discovery_v1` | 同上，`skip_discovery=true` | 直接进入会话阶段（首帧即 0x8864） | 从 PADI/PADR 推导 Session ID |

显式边界（"不实现、不声称、不许静默转换"）：① **不实现 IPCP**（RFC 1332 网络层地址协商）——数据面地址来自配置而非协商（D-PPPOE-1 缺口 F，§14 G-PPPOE-3）；② **不实现 LCP 重传/超时**（RFC2516 §8 的 PADI 重发与等待加倍）——planner 零重发逻辑（`grep` 实测空），失败分支只由配置拒绝表达；③ **不实现真实 CHAP 摘要**——Response 的 16 字节 Value **直接回显 Challenge 值**，不算 MD5（`planner.go:393-411` 注释明写）；④ **不实现真实 PAP 校验**——Ack 的 Message 恒 `"welcome"`；⑤ 不实现 VLAN/MPLS/GRE 组合（`builder.go:493` 显式拒 GRE+PPPoE）；⑥ 不实现 0xffff Session ID（RFC2516 §4 保留值，实现只接受 uint16 且 0 走缺省 1）；⑦ **不声称**产出的流可被真实 BRAS 建立会话。

**实现状态（2026-09-29 实测）**：`pppoe` 层已注册（`registry.go:2191`，`CategoryTerminal`，`DependsOn ["ip"]`，**Fields 16 键**）；planner 已落码（`internal/protocol/pppoe/` 三文件共 **1490 行**：`planner.go` 608 / `layer_gen.go` 77 / `planner_test.go` 805）；`allowedProtocols["pppoe"]=true`（`protocols.go:51`）；raw-IP 自驱双名单已接线（`chain_planner_util.go:54/57`）；层内 translate 已接线（`chain_planner_translate.go:2764`）；FlowMeta carry 已接线（`chain_planner.go:1514-1516`）；24 语义用例已落 `cases/pppoe.json`。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`eth.type`、`pppoe.code`、`pppoe.session_id`、`ppp.protocol`、`ip.proto`、`ip.src/dst`、`eth.src` 字段 + offset 14/20/26/30/32/50 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。

## 2. 协议栈、端口与固定偏移

推荐层链为 **`[ip, pppoe]`**（存量 24/24 例均为此形，机读实测）。**注意与常规协议的方向相反**：pppoe 是 `CategoryTerminal` + `DependsOn ["ip"]` 的 **raw 自驱终结层**——帧由生成器一次产全（`Eth + PPPoE + PPP + 内嵌 IPv4`），**链上不存在外层 IP 头**；`ip` 层在链上承载的是 **PPP 内嵌 IPv4 的地址语义**（`planner.go:111-122` 的 IP 校验即内嵌 IP 校验），不是外层地址。因此**没有 `tcp`/`udp` 层**，也没有外层端口。

端口：**无外层端口概念**。内嵌 IPv4 的 L4 端口来自 `spec.SrcPort/DstPort`，而链路径无端口位可写 → **恒 0**（`chain_planner.go:774-776` src 0-keep 名单 + `:996-997` dst 0-keep 名单双含 pppoe；`planner.go:457-461` 直写）。这是**已声明的合成面**，不是缺陷（D-PPPOE-1 P4 B′ 注记，G-PPPOE-4 登记需求面）。

固定偏移（无 VLAN 时，**以太帧起点为 offset 0**）：

| 偏移 | 内容 | 长度 |
|---:|---|---|
| 0 | 目的 MAC | 6 |
| 6 | 源 MAC | 6 |
| 12 | EtherType（`0x8863` Discovery / `0x8864` Session） | 2 |
| **14** | **PPPoE 头**（ver/type + code + session_id + payload_length） | **6** |
| 20 | Discovery：首个 TLV 标签；Session Data：PPP Protocol 字段 | 4 / 2 |
| 22 | Session Data：PPP 载荷（LCP/PAP/CHAP 报文 或 内嵌 IPv4 头） | 变长 |
| 26 | Session Data 且 PPP=0x0021：内嵌 IPv4 头 | 20 |
| 46 | 内嵌 IPv4 且 UDP：UDP 头 | 8 |
| 50 | 内嵌 IPv4/UDP 的载荷 | 变长 |

**有 VLAN 时全部 +4**（`builder.go:213` `l2Len = 18`）；本版 24 例均无 VLAN。**有 MPLS 时被拒**（`builder.go:311` 显式拒 MPLS+PPPoE 组合）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**本协议存量 24 例已是此形，无迁移工作量**）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"pppoe": {"auth": "chap", "username": "bob", "data_frames": 2}}
  ]
}
```

多会话样例（数量只走 `sessions[]`，本协议**已用**）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"pppoe": {"auth": "chap", "sessions": [{"session_id": 21}, {"session_id": 22, "skip_discovery": true, "data_direction": "down", "data_frames": 2}]}}
  ]
}
```

## 3. 线格式编码（逐字段，可生成级）

### 3.1 以太封装与 EtherType

以太头 14 字节（dst 6 + src 6 + EtherType 2）。**EtherType 由 builder 强制**（`builder.go:25-31`）：`L2Config.PPPoE != nil` 时**无视 `L2Config.EtherType`**，按 `Code` 取值——`Code == 0x00`（Session Data）→ **0x8864**，其余 → **0x8863**（`builder.go:225-231` 的 `effectiveEtherType` 覆写 + `validatePPPoEConfig` 校验）。planner 侧 `emitFrame`（`planner.go:280-283`）也按同一规则写一遍 = **双保险**。

**MAC 取值（按实现钉，G-PPPOE-2）**：planner **恒写非空 MAC**（`planner.go:248-254`）——`spec.SrcMAC`/`spec.DstMAC` 非空则用，空则缺省 `aa:bb:cc:dd:ee:01`（client/up）/`aa:bb:cc:dd:ee:02`（server/down）。链路径 `spec.SrcMAC` 来自 `FlowMeta`（ip 层无 MAC 位），故**实际恒为缺省对**。用例 T-7 断言的 `eth.src = 02:00:00:00:00:02` 是 **builder/worker 侧的 spec 缺省**（`strategy_convert.go:31-32` `DefaultSrcMAC`/`DefaultDstMAC`），**与 planner 的 `aa:bb:...` 缺省是两套值**——down 帧由 planner 写 `downMAC`，其值来自 `spec.DstMAC`（链上 = `02:00:00:00:00:02`），故实测为后者。**本版按实测钉 T-7**（§8 边界明写该双套值）。

**PADI 目的 MAC 恒广播**（`planner.go:311`，`broadcastMAC = "ff:ff:ff:ff:ff:ff"`，RFC2516 §5.1）；PADO/PADR/PADS/PADT 为单播。

**填充**：`shouldPad(config.L2.Pad)` 为真（`nil` 或 `*true`）且总长 < `MinEthernetFrame = 60`（`builder.go:113`）时零填充至 60。**填充字节不计入 PPPoE Payload_Length**（`builder.go:328-336` 注释，RFC2516 §4 定义为 PPP 帧尺寸）。24 例中 PADI/PADO/PADR/PADS/LCP/PAP/CHAP 等短帧均被填充至 60。

### 3.2 PPPoE 头（6 字节，`builder.go:217-250` + `writeL2`）

| 偏移（相对 PPPoE 头） | 字段 | 类型/端序 | 本实现取值 |
|---:|---|---|---|
| 0 | VER/TYPE | 各 4 bit，**同一字节** | 恒 `0x11`（VER=1、TYPE=1，RFC2516 §4 "MUST be set to 0x1"） |
| 1 | CODE | uint8 | 见 §3.4/§3.5；由 `PPPoEConfig.Code` 直写 |
| 2 | SESSION_ID | uint16 **BE** | Discovery 段 `0x0000`；PADS 起为分配值（§3.4） |
| 4 | PAYLOAD_LENGTH | uint16 **BE** | 见 §3.9 |

**SESSION_ID 语义**（RFC2516 §4）："fixed for a given PPP session ... defines a PPP session along with the Ethernet SOURCE_ADDR and DESTINATION_ADDR"；`0xffff` 保留。实现缺省 `DefaultSessionID = 1`（`planner.go:38`）。

### 3.3 Discovery TLV 标签（`serializePPPoETags`，`builder.go:469-480`）

```
TAG_TYPE(2 BE) + TAG_LENGTH(2 BE) + TAG_VALUE(TAG_LENGTH 字节)
```

**TAG_LENGTH 只计 VALUE 字节，不含 4 字节 TLV 头**（RFC2516 §5 原文："indicating the length in octets of the TAG_VALUE"）。planner 编排的标签（`planner.go:310-343`）：

| 标签 | 值 | 出现帧 | 编排条件 |
|---|---|---|---|
| `0x0101` Service-Name | `ServiceName` 字节（**可为空** = 任意服务，RFC2516 Appendix A） | PADI/PADO/PADR/PADS | 恒发（四帧各一个） |
| `0x0102` AC-Name | `ACName`（缺省 `"trafficgen"`，`planner.go:46`） | **仅 PADO** | 恒发 |
| `0x0104` AC-Cookie | `Cookie` 字节数组 | PADO/PADR/PADS | `len(Cookie) > 0` 时 |

**未被编排的标签**（builder 通用序列化器支持任意 `Type`，但 planner 不产）：`0x0000` End-Of-List、`0x0103` Host-Uniq、`0x0105` Vendor-Specific、`0x0110` Relay-Session-Id、`0x0201` Service-Name-Error、`0x0202` AC-System-Error、`0x0203` Generic-Error → G-PPPOE-5。

**PADT 零标签**：`emitFrame(..., nil, nil, ...)` → `DiscoveryTags` 为 nil → `pppoeTagBytes` 为 nil → `Payload` 也为 nil → **Payload_Length = 0x0000**（RFC2516 §5.5 "No TAGs are required"）。

### 3.4 Discovery 四步逐帧（RFC2516 §5.1–§5.5）

| # | 帧 | 方向 | Code | 目的 MAC | SESSION_ID | 标签 | RFC2516 |
|---:|---|---|---|---|---|---|---|
| 1 | PADI | **up** | `0x09` | **广播** `ff:ff:ff:ff:ff:ff` | `0x0000` | Service-Name | §5.1 |
| 2 | PADO | **down** | `0x07` | 单播（client） | `0x0000` | Service-Name + **AC-Name** + [AC-Cookie] | §5.2 |
| 3 | PADR | **up** | `0x19` | 单播（server） | `0x0000` | Service-Name + [AC-Cookie **原样回显**] | §5.3 |
| 4 | PADS | **down** | `0x65` | 单播（client） | **分配的 Session ID** | Service-Name + [AC-Cookie] | §5.4 |
| 5 | PADT | **up** | `0xa7` | 单播（server） | **回显会话 ID** | **无** | **§5.5** |

`skip_discovery=true` 时**跳过 1–4 帧**（`planner.go:307`），**首帧即 LCP**（EtherType `0x8864`）——此时 Session ID **必须显式**（PADS 缺席，无分配来源；缺省仍落 `DefaultSessionID`）。

### 3.5 PPP 头与 LCP（RFC1661 §2/§4/§5/§6）

Session Data 帧在 PPPoE 头后**恒有 2 字节 PPP Protocol 字段**（RFC1661 §2，网络序）：

| PPP Protocol | 含义 | 载荷 |
|---|---|---|
| `0x0021` | IPv4（RFC1661 §2） | 内嵌 IPv4 头 + L4 + payload |
| `0xc021` | LCP（RFC1661 §2） | LCP 报文（`Payload` 承载） |
| `0xc023` | PAP（RFC1334） | PAP 报文 |
| `0xc223` | CHAP（RFC1994） | CHAP 报文 |
| `0x8021` | IPCP | **不实现**（G-PPPOE-3） |

**LCP 报文格式**（`buildLCPMessage`，`planner.go:534-541`，RFC1661 **§5**）：

```
Code(1) + Identifier(1) + Length(2 BE) + Options/Data
```

`Length` 计 **Code 起至末尾**（RFC1661 §5："Indicates the length of the packet including the Code, Identifier, Length and Data fields"）。实现只用 `Code=1` Configure-Request / `Code=2` Configure-Ack`（`planner.go:59-61`），`Identifier` 恒 1。

**LCP Configure-Request 选项序列**（`planner.go:353-368`，顺序固定）：

| 序 | 选项 | Type | Len | Value | RFC1661 |
|---:|---|---:|---:|---|---|
| 1 | Maximum-Receive-Unit | `1` | 4 | `MRU` uint16 **BE**（缺省 1492） | **§6.1** |
| 2 | Magic-Number | `5` | 6 | `MagicNumber` uint32 **BE** | **§6.4** |
| 3 | Authentication-Protocol | `3` | 4 | `0xc023`(PAP) / `0xc223`(CHAP) | **§6.2** |

第 3 项**仅当 `Auth ∈ {pap, chap}`** 时追加（`planner.go:365`）；`Auth ∈ {"", "none"}` 时**无**（T-4 钉）。

**长度公式**：LCP `Length = 4 + 10 + (4 if auth else 0)` = **14**（无认证）/ **18**（有认证）。
**Configure-Ack 复用同一选项字节**（`planner.go:375` `buildLCPMessage(lcpConfigureAck, 1, lcpOpts)`，RFC1661 §5.2 "MUST ... identical"）。

**Magic-Number 随机性**（RFC1661 §6.4 "MUST be chosen randomly"）：`resolveMagic`（`planner.go:206-215`）用 `crypto/rand` 取 4 字节，失败回退 `0x0900beef`；**显式 `MagicNumber != 0` 时直用**（测试确定性面）。**每个会话各自掷值**（P4 复审 R1 修复：原 goroutine 级一次 → 多会话共用，违"每链路独立"）。

### 3.6 PAP / CHAP

**PAP**（RFC1334 **§2.2.1 / §2.2.2**）：

| 报文 | 函数 | 布局 | 长度公式 |
|---|---|---|---|
| Authenticate-Request | `buildPAPRequest`（`planner.go:546-557`） | Code(1)=1 + ID(1) + Length(2 BE) + Peer-ID-Length(1) + Peer-ID + Password-Length(1) + Password | `6 + len(user) + len(pass)` |
| Authenticate-Ack | `buildPAPAck`（`:561-570`） | Code(1)=2 + ID(1) + Length(2 BE) + Message-Length(1) + Message | `5 + len(message)` |

ID 恒 1；Ack 的 Message 恒 `"welcome"`（`planner.go:389`）。**方向**：Request **up**（client→server）、Ack **down**。

**CHAP**（RFC1994 **§4.1 / §4.2**）：

| 报文 | 函数 | Code | 布局 | 长度公式 |
|---|---|---:|---|---|
| Challenge | `buildCHAPChallenge`（`:574-584`） | 1 | Code(1)+ID(1)+Length(2 BE)+Value-Size(1)+Value+Name | `5 + len(value) + len(name)` |
| Response | `buildCHAPResponse`（`:588-598`） | 2 | 同 Challenge | 同 |
| Success | `buildCHAPSuccess`（`:602-608`） | 3 | Code(1)+ID(1)+Length(2 BE)=**4** | 恒 4 |

`Value-Size` 恒 **16**（`chapValueLen`，`planner.go:86`），值由 `crypto/rand` 取（失败回退 `byte(i+1)` 序列，`:398-403`）。**Response 的 Value 直接回显 Challenge 的 Value**（同一次 `value[:]` 切片，`planner.go:404-409`）——**不计算 MD5**，RFC1994 §4.1 的摘要语义**不声称实现**（§1 边界③）。
**方向**：Challenge **down**、Response **up**、Success **down**（RFC1994 §2 步骤 1–3 的服务器发起序）。

### 3.7 数据面（PPP `0x0021` 内嵌 IPv4）

`planner.go:419-474`：每帧由 `core.L3Base(srcIP, dstIP, innerProto, spec.TTL, nextIPID(), spec)` 构造内嵌 IPv4，`core.L4Config{Protocol, SrcPort: spec.SrcPort, DstPort: spec.DstPort, ...}` 构造 L4。

| 键 | 取值 | 出处 |
|---|---|---|
| 内嵌 IPv4 地址 | `spec.SrcIP`/`spec.DstIP`（**链上来自 ip 层**） | `planner.go:451/454` |
| 方向 | `data_direction="up"`（缺省）→ src=client；`"down"` → **src/dst 与 MAC 全换向** | `planner.go:449-455` |
| `inner_proto` | `0` → `spec.TCP != nil ? 6 : 17`；显式 `6`/`17` | `planner.go:419-426` |
| `ip.id` | `nextIPID()` 逐帧 `+1`（会话内独立计数器，`planner.go:439-443`） | — |
| `TTL` | `spec.TTL` | `planner.go:456` |
| **L4 端口** | **恒 0**（链路径无端口位；§2 已声明合成面） | `planner.go:457-461` |
| L4 = TCP 时 | `spec.TCP` 非 nil 则带 Seq/Ack/Flags/WindowSize；nil 则**全零值** | `planner.go:462-469` |
| 载荷 | `DataPayload` 非 nil 则用；否则 `spec.Payload` | `planner.go:431-434` |

**帧数**：`DataFrames == 0` → **1**（`planner.go:435-438`；**不是"无数据帧"**，T-8 语义勘误点）。

### 3.8 PADT（RFC2516 **§5.5**）

`planner.go:480-484`：`sessCfg.PADT == nil || *sessCfg.PADT` 时发一帧——`code=0xa7`、**方向 up**、`Session ID = 已分配值`、**零 TLV**（`Payload_Length = 0x0000`）、EtherType `0x8863`（Discovery 家族）。`PADT` 是 `*bool` **指针三态**：`nil` → 发（缺省 true，完整 RFC 生命周期）；`*false` → **抑制**（T-2）；`*true` → 发。

### 3.9 长度公式与填充

```
以太帧总长 = 14 + [4 VLAN] + 6(PPPoE) + PPPoE_Payload_Length     -- 再按需填充至 ≥60
```

**PPPoE Payload_Length**（`builder.go:339-352`，RFC2516 §4："length of the PPPoE payload ... does not include the length of the Ethernet or PPPoE headers"）：

| 帧类 | Payload_Length | 说明 |
|---|---|---|
| Discovery | `len(标签 TLV 字节)` | 不含 PPP Protocol（Discovery 无该字段） |
| Session Data | `2 + l3Len + l4Len + len(payload)` | 含 PPP Protocol 2 字节 |

其中 `l3Len = 20`（PPP=0x0021 内嵌 IPv4）/ `0`（PPP=LCP/PAP/CHAP，`builder.go:236-241`）；`l4Len` = 内嵌 L4 头长。**`PayloadLength > 0` 时覆写计算值**（`builder.go:345-347`，用户可造故意错误长度测 DUT）→ 未被用例使用（G-PPPOE-6）。超 65535 即拒（`builder.go:350`，锚词 `pppoe: payload length %d exceeds 65535`）。

**已验证算例（逐项对 cases `frames` 断言机读复核，§13）**：

| 帧 | 标签/载荷 | Payload_Length | 对账 |
|---|---|---:|---|
| PADI（零长 Service-Name） | Service-Name TLV `4 + 0` | **4** | #1 帧 1 `...00 04` ✓ |
| PADO（缺省 AC-Name `"trafficgen"`） | Service-Name 4 + AC-Name `4 + 10` | **18** | 派生（无断言，notes 间接） |
| PADO（BRAS 三标签 #10） | Service-Name `4+8` + AC-Name `4+6` + Cookie `4+4` | **30** | 派生（#10 无 payload_length 断言） |
| LCP 无认证 | PPP Proto 2 + LCP 14 | **16** | #1/#4 帧 5 `...00 10` ✓ |
| LCP 带 Auth-Protocol | PPP Proto 2 + LCP 18 | **20** | #5 帧 5 `...00 14` ✓ |
| PAP Authenticate-Request（alice/s3cret） | PPP Proto 2 + PAP **17** | **19** | 派生（`0x0011` 是 **PAP Length 字段**，非 PPPoE payload_length） |
| CHAP Challenge（bob） | PPP Proto 2 + CHAP **24** | **26** | 派生（`0x0018` 是 CHAP Length 字段） |
| 数据帧（`tg-payload`） | PPP Proto 2 + IP 20 + UDP 8 + payload 10 | **40** | #16 帧 3 offset 50 载荷字节 ✓ |
| PADT（零标签） | 无 | **0** | #1 帧 8 `...00 00` ✓ |

> **口径提醒（防混淆）**：LCP 的 `Length`、PAP 的 `Length`、CHAP 的 `Length` 都是**各自协议报文内的长度字段**（计本协议报文），与 **PPPoE 的 `PAYLOAD_LENGTH`**（计 PPPoE 头之后的全部字节，含 2 字节 PPP Protocol）**不是同一个字段**。cases 的 `frames` 断言中，offset 14 处的 2 字节是 PPPoE `PAYLOAD_LENGTH`，offset 20 之后（LCP/PAP/CHAP 报文内）的才是各自协议的 `Length`。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明一次（或多次）完整 PPPoE 生命周期与业务键，引擎按固定剧本产出帧序列（Discovery 四步 → LCP 对 → 可选认证 → N 数据帧 → PADT），**无运行时刺激**。仅两处反应性成分：① CHAP Response 回显 Challenge 值（生成期合成，非运行时收到才发）；② 多会话由 `sessions[]` 数组驱动**整块顺序**回放。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 标准拨号全生命周期 | PADI→PADO→PADR→PADS→LCP→数据→PADT | #1（`pppoe_lifecycle_full`） |
| ② 客户端主动拆线 / 抑制拆线 | `padt` 指针三态 | #1（发）/ #2（`padt=false` 抑制） |
| ③ 半开重协商（跳过发现） | `skip_discovery=true` 直入会话阶段 | #3（`pppoe_skip_discovery`） |
| ④ 无认证拨号 | LCP 无 Auth-Protocol 选项 | #4（`pppoe_auth_none_lcp_len`） |
| ⑤ PAP 明文认证拨号 | LCP 带 c023 → PAP Req/Ack | #5（`pppoe_auth_pap`） |
| ⑥ CHAP 质询认证拨号 | LCP 带 c223 → Chal/Resp/Succ | #6（`pppoe_auth_chap`） |
| ⑦ 下行流量（服务器推流） | `data_direction=down` 内嵌 IP/MAC 全换向 | #7（`pppoe_data_direction_down`） |
| ⑧ 现网 BRAS 三标签形 | Service-Name + AC-Name + AC-Cookie 关联 | #10（`pppoe_bras_three_tags`） |
| ⑨ any-service 客户端 | 零长 Service-Name 标签 | #9（`pppoe_service_name_any`） |
| ⑩ 多会话并发拨号（同 BRAS 多用户） | `sessions[]` 各自独立生命周期 | #12/#13/#14 |
| ⑪ 内嵌业务协议区分 | `inner_proto` 6/17 | #15/#18 |

**五层覆盖逐层结论**：
- **功能层**——Discovery 五类帧（PADI/PADO/PADR/PADS/PADT）正例齐（#1/#9/#10/#12/#13）；PPP 会话阶段三类（LCP/PAP/CHAP）正例齐（#4/#5/#6）；数据面双方向（#1/#7）；拒绝分支 **6 类负例**（#19–#24，§7）。
- **性能层**——最小帧边界（PADI/PADO 等填充至 60）；多会话最大序列（#12 = **24 帧**，3×8）；多帧数据面（#17 `data_frames=2`）；**帧长上界**=以太 1500（RFC2516 §7：PPPoE MTU ≤ 1492 = 1500 − 6 − 2）；`Payload_Length` uint16 上限 65535（`builder.go:350` 守卫，今日无例 → G-PPPOE-6）。
- **数据场景层**——code 全表（6 值）、TLV 标签表（编排 3 种）、PPP Protocol 表（4 种编排）、LCP 选项表（3 种）、边界（空 Service-Name / cookie 有无 / MRU 缺省与显式 / Magic 显式与随机 / `data_frames` 0 与 2 / 超大 payload）——逐项落点见 §10.3。
- **地址与流层**——**只有 IPv4**（内嵌 IPv4 是 PPP `0x0021` 的唯一承载，RFC1661 §2）；**IPv6 显式不适用并建负例**（#22，锚词 `must be IPv4`）；单流基线（#1–#11/#15–#18）；**多会话**（`sessions[]`，§5 会话表）；**流关联（控制流派生数据流）显式不适用**——PPPoE 会话内的 PPP 链路是**单条点对点链路**，LCP/PAP/CHAP 与数据帧共用同一 Session ID、同一对 MAC，**无副连接、无 `driven_by` 锚定关系**（与 FTP/SIP 的主从流不同维度）；**多流（会话内并发流）显式不适用**——单链路串行收发，多流由策略级 `flow_control` 承载（本版 24 例未用）。
- **业务层**——十一场景全部有落点（上表）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① IPCP 地址协商（未实现，G-PPPOE-3）；② PADI/PADR 重传与超时加倍（RFC2516 §8 SHOULD，planner 零重发，G-PPPOE-5）；③ 真实 CHAP MD5 摘要（回显合成，§3.6）；④ VLAN/MPLS/GRE 组合承载（`builder.go` 显式拒）；⑤ Relay-Session-Id 中继（未编排，G-PPPOE-5）；⑥ PADS Service-Name-Error 拒绝路径（RFC2516 §5.4，未编排，G-PPPOE-5）。

## 5. 消息/事务模型与状态机

**事务定义**：一次请求 + 一次响应（Discovery 四步的**每一次往返**、LCP 对、PAP 对、CHAP 三帧序各算一个事务）。**多事务** = 一条生命周期内多个事务按序执行：#1 有 4（发现）+ 1（LCP）+ 0（无认证）= 5 个事务；#5 有 4+1+1 = 6 个；#6 有 4+1+3 = 8 个。

**状态机（RFC2516 §3 两阶段 + RFC1661 §3.2 阶段图）**：

| 阶段 | 状态 | 入口条件 | 产出帧 | 出口条件 | 用例 |
|---|---|---|---|---|---|
| **Discovery** | `DISCOVERY`（RFC2516 §5，无状态） | 流程启动，`skip_discovery=false` | PADI(up) → PADO(down) → PADR(up) → PADS(down) | PADS 分配 Session ID | #1/#5/#6/#8–#14 |
| **Session / Link Establishment** | `LCP`（RFC1661 §3.4） | Discovery 完成，或 `skip_discovery=true` | Configure-Request(up) → Configure-Ack(down) | Ack 回显同选项 | 全正例 |
| **Session / Authentication** | `AUTH`（RFC1661 §3.5） | `Auth ∈ {pap, chap}` | PAP：Req(up)/Ack(down)；CHAP：Chal(down)/Resp(up)/Succ(down) | Ack/Succ | #5/#6 |
| **Session / Network-Layer** | `DATA`（RFC1661 §3.6） | 认证完成或 `Auth ∈ {"", "none"}` | N×内嵌 IPv4 数据帧 | 计数到 `DataFrames` | 全正例 |
| **Termination** | `PADT`（RFC2516 §5.5） | `PADT != *false` | PADT(up)，零标签 | 帧发出 | 全正例除 #2 |

**非法转移**：本实现**无运行时状态机**——`runSession`（`planner.go:220-485`）是**顺序过程**：Discovery → LCP → Auth → Data → PADT，**不存在"在错误状态收到某帧"的路径**（无收包、无事件循环）。因此"状态机错"类负例**在本协议不适用**（§7 明写）。唯一的状态**前置约束**由 `Validate` 静态承担（`skip_discovery=true` 时 Session ID 必须显式——实现不强制，落缺省 1，§3.4）。

**会话表（五件套之一）**：

| 会话 | 形态 | 四元组 | 用例 |
|---|---|---|---|
| `s1` | 单会话基线 | 链上无端口（恒 0）；MAC = `aa:bb:cc:dd:ee:01`/`02`（planner 缺省）或 `02:00:00:00:00:01`/`02`（spec 缺省） | #1–#11/#15–#18 |
| `s2` | 多会话（`sessions[]`） | **每项一条完整生命周期**，各自 Session ID；`FlowID` 带 `-pppoe-sess<ID>` 后缀（`planner.go:521`） | #12（3 项派生 1/2/3）、#13（2 项显式 100/200）、#14（2 项 21/22 混合形态） |

**多会话展开 = 整块顺序，非交错**（§5 定性）：`sessions[]` 循环（`planner.go:491-525`）逐项调 `runSession`，**第 1 个会话跑完全流程（发现→LCP→认证→数据→PADT）才开始第 2 个**。实测锚点（T-12）：帧 1–8 = 会话 1（PADS 帧 4 `0x0001`、PADT 帧 8 `0x0001`）、帧 9–16 = 会话 2（`0x0002`）、帧 17–24 = 会话 3（`0x0003`）。

**包数公式（逐会话，机读复核 §13）**：

```
单会话帧数 = (0 if skip_discovery else 4) + 2(LCP 对) + (2 if pap | 3 if chap | 0) + DataFrames(0→1) + (0 if padt==false else 1)
流总帧数   = Σ 各会话帧数
```

**自动派生规则**（逐条列出触发条件与内容）：
1. `SessionID == 0` → `DefaultSessionID = 1`（`planner.go:226-229`）；`sessions[i].SessionID == 0` → `1 + i`（`:503-505`）。
2. `MRU == 0` → `1492`（`:230-233`）。
3. `ACName == ""` → `"trafficgen"`（`:234-237`）。
4. `Username`/`Password == ""` → `"trafficgen"`（`:238-245`）。
5. `SrcMAC`/`DstMAC == ""` → `aa:bb:cc:dd:ee:01`/`02`（`:248-254`）。
6. `MagicNumber == 0` → `crypto/rand` 4 字节（`:206-215`，失败回退 `0x0900beef`）。
7. `Auth ∈ {"", "none"}` → **不发**认证帧、LCP **无** Auth-Protocol 选项（`:359-368`）。
8. `InnerProto == 0` → `spec.TCP != nil ? 6 : 17`（`:419-426`）。
9. `DataDirection == ""` → `"up"`（`:427-430`）。
10. `DataPayload == nil` → `spec.Payload`（`:431-434`）。
11. `DataFrames == 0` → `1`（`:435-438`）。
12. `PADT == nil` → 发 PADT（`:480`）。
13. `sessions[i]` 的**行为 6 键**覆盖顶层；**模板 9 键**（`ac_name`/`service_name`/`auth`/`username`/`password`/`mru`/`magic_number`/`cookie`/`padt`）继承顶层（`:494` 深拷贝 `sessCfg := *cfg`）。
14. `sessions[i].SessionIDDyn != nil` → `ResolvePortValue(dyn, spec.FlowIndex)` 逐流解析（`:496-499`，非 0 才生效）。

**驱动与交互规格**：配置 → `ValidateLayers`（registry 16 键 allowlist + `checkPPPoESessionsMutex`）→ translate（`ParsePPPoEConfigFromMap` → `spec.PPPoE`）→ `FlowMeta.PPPoE` carry → `PPPoEGenerator.Generate`（`layer_gen.go:33-65`）→ `Planner.Plan` → `runSession` → `emitFrame` → `req.Emit`（raw-IP 驱动分支）→ worker → writer（PCAP/NIC）。

**防双换（srv6 同款，`layer_gen.go:58-63`）**：`Plan` 已在包内部完成 MAC/内层 IP 换向并置 `Direction="down"`；raw-IP 驱动的 `Emit` 包装对 `"down"` 包会**再换一次** L3 地址。本生成器**统一把每包 `Direction` 改写为 `"up"`** 后转 `Emit`——内层 L3 地址保持 Plan 换向结果，L2 MAC 保持 Plan 写入值（非空 → drive 的 `l2For` 回填跳过），语义与 legacy 扁平路径逐字节一致。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流全链 ≤**24 帧**（#12，3 会话 × 8 帧）；单会话最长 **11 帧**（#6 CHAP 全生命周期：4+2+3+1+1）；`Payload_Length` 上限 uint16 65535（`builder.go:350`）；以太帧上界 1500（PPPoE MTU ≤1492，RFC2516 §7）。吞吐数字待基准，**本版不写承诺**。
- **依据**：事件序列流式产出——`Plan` 返回 `chan PacketConfig`（**容量 256**，`planner.go:192`）逐帧发射，**无全量包聚合**；每帧内存 = 该帧总长（最小 = 填充后 60；最大今日 = #16 数据帧 50+10 = **60**，恰好等于填充阈值）；无跨流共享状态（`packetIndex`/`ipidCounter`/`magic` 均为 `runSession` 内局部变量）；**无锁**（`crypto/rand` 无共享状态）。
- **验收两路（§6.3 强制）**：pcap 与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `eth.type`/`pppoe.code`/`pppoe.session_id`/`ppp.protocol` 字段、帧原始 hex 与 `packet_count`，**不只断言"任务没报错"**。
- **六类场景落点（§6.6）**：基线（#1，8 帧）/ 目标规模（#6 CHAP 11 帧、#5 PAP 10 帧）/ 压力上限（#12 多会话 24 帧、#17 多帧数据面）/ 长时间运行（多会话整块展开承载语义）/ 并发交错（顺序整块承载语义，**并发路径不启用**）/ 背压（`packet_count` 精确计数守卫帧数漂移 + channel 256 有界缓冲）。
- **并发正确性（§6 规则 6）**：`sessions[]` 是**顺序**循环（`planner.go:491-525`），**非并发**——不存在共享速率或共享计数器的并发竞争面；`-race` 面由 planner 单测与链级测试覆盖（§11.6）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 registry/validator/planner 拒绝并传播为 task error，**不得产出成功 PCAP、`completed/0 packet` 或只剩外壳的假成功**：

| # | 负例 ID | 故障输入 | 真实拦截点 | 代码锚词（逐字） | 代码行 |
|---:|---|---|---|---|---|
| N-1 | `pppoe_neg_auth_invalid` | `auth="radius"` | planner `Validate` | `pppoe: Auth %q not in supported list (allowed: none, pap, chap)` | `planner.go:129` |
| N-2 | `pppoe_neg_inner_proto_invalid` | `inner_proto=5` | planner `Validate` | `pppoe: InnerProto %d not in supported list (allowed: 6=TCP, 17=UDP)` | `planner.go:137` |
| N-3 | `pppoe_neg_data_frames_negative` | `data_frames=-1` | **registry V9 范围门**（先于 planner） | `... field "data_frames" = -1 invalid: not a numeric value in [0,1000000]` | `complete.go:315`（registry 门）；planner 同分支 `planner.go:141` **链路径不可达** |
| N-4 | `pppoe_neg_ipv6_inner` | ip 层 `2001:db8::1/2` | planner `Validate`（**同族 IPv6**，混族被 ip 层先拦） | `pppoe: SrcIP %q must be IPv4 (PPPoE carries IPv4 over PPP Protocol 0x0021, RFC 1661 §6)` | `planner.go:120` |
| N-5 | `pppoe_neg_sessions_mutex` | `sessions[]` + 顶层 `data_frames` | **schema `checkPPPoESessionsMutex`**（create-time） | `pppoe: sessions and top-level session config are mutually exclusive ...` | `semantic.go:326`；planner 背 door `planner.go:160/169` |
| N-6 | `pppoe_neg_duplicate_session_id` | 两 `session_id=100` | **schema `checkPPPoESessionsMutex`**（create-time） | `pppoe: duplicate session_id 100 (each entry runs one lifecycle; derived IDs auto-increment)` | `semantic.go:355`；planner 背 door `planner.go:178` |

**锚词口径**：`error_contains` 是**子串**判定。N-1/N-2/N-4 命中 planner 文案；N-3 命中 registry 范围门文案（**planner 的 `DataFrames %d must be >= 0` 在链路径不可达**——V9 门先拦，P5 实测钉）；N-5/N-6 命中 schema 文案（**task-time 背 door 同锚词**，两路独立闭合）。

**负例原子性**：24 例中 6 负例**每例单一故障注入**，`expect` 严格只有 `{expect_error, error_contains}` **两键**（**无 `notes` 键**——与 opcua 存量不同，本协议已合规，机读实测）。

**未入用例的拒绝分支（不得冒充已覆盖）**：

| 分支 | 锚词 | 代码行 | 可达性 |
|---|---|---|---|
| `PPPoE == nil` | `pppoe: PPPoE config is required` | `planner.go:102` | **链路径不可达**（translate 空层 config 也翻译出非 nil，`chain_planner_translate.go:2775-2776`） |
| `SrcIP`/`DstIP` 非 IP 文本 | `pppoe: %s %q is not a valid IP address` | `planner.go:117` | 可达（今日无例） |
| `DataFrames < 0` | `pppoe: DataFrames %d must be >= 0` | `planner.go:141` | **链路径不可达**（registry V9 先拦） |
| `DataDirection` 非 `up`/`down` | `pppoe: DataDirection %q not in supported list (allowed: up, down)` | `planner.go:149` | 可达（今日无例） |
| `sessions[]` **空数组** | 同 N-5 锚词 | `planner.go:160` + `semantic.go:334` | 可达（今日无例） |
| builder 非法 `Code` | `pppoe: invalid code 0x%02x ...` | `builder.go:447` | **不可达**（planner 自管 code，恒取六值之一） |
| builder 非法 `PPPProtocol` + 非空 L3/L4 | `pppoe: PPPProtocol 0x%04x carries PPP control bytes in Payload ...` | `builder.go:452` | **不可达**（planner 对 LCP/PAP/CHAP 传空 L3/L4） |
| builder Discovery 带 L3/L4 | `pppoe: discovery code 0x%02x carries TLV tags only ...` | `builder.go:461` | **不可达**（planner Discovery 帧传 `withL3L4=false`） |
| builder Discovery 同时带 tags 与 Payload | `pppoe: discovery frame carries both DiscoveryTags and Payload ...` | `builder.go:464` | **不可达** |
| `PayloadLength` 覆写超 65535 | `pppoe: payload length %d exceeds 65535 ...` | `builder.go:350` | 可达（今日无例） |
| GRE + PPPoE 组合 | `gre: cannot combine GRE with PPPoE ...` | `builder.go:494` | **不可达**（pppoe 层无 GRE 键） |
| MPLS + PPPoE 组合 | MPLS 校验拒 | `builder.go:311` 注释 | **不可达**（pppoe 层无 MPLS 键） |
| 会话阶段 EtherType = IPv6 | `pppoe: session data carries an IPv4-only inner layer ...` | `builder.go:455` | 与 N-4 同面（planner 先拦） |

**不得误报的合法协议事件**：零长 Service-Name（#9，RFC2516 Appendix A "any service"）；`padt=false`（#2）；`skip_discovery=true`（#3/#7/#11/#15–#18）；`data_frames=0`（#8，语义=缺省 1）；多会话（#12–#14）；cookie 显式字节数组（#10）；Magic 随机（全正例）。

**"状态机错"类负例显式不适用**：本实现无运行时收包状态机（§5），**不存在"在错误状态收到某帧"的输入面**，故 §4 最小清单的"状态机错"一行在本协议**显式不适用**，理由如上（不硬凑用例）。

## 8. 边界

- **帧长与填充**：`MinEthernetFrame = 60`（`builder.go:113`）；PADI/PADO/PADR/PADS/LCP/PAP/CHAP 等短帧**恒被填充至 60**；`#16` 数据帧（50+10）**恰好 60**，不触发填充。填充字节**不计入 Payload_Length**。
- **Payload_Length 上界**：uint16 65535（`builder.go:350`）；今日无例 → G-PPPOE-6。
- **以太帧上界**：1500（PPPoE MTU ≤ 1492，RFC2516 §7）；PADI 另受 RFC2516 §5.1 约束（**含 PPPoE 头 ≤ 1484**，为 Relay-Session-Id 留位）——实现**不校验 1484**（G-PPPOE-6）。
- **Session ID**：uint16；`0` → 缺省 1；`0xffff` 是 RFC2516 §4 **预留值**，实现**不拒**（G-PPPOE-6）。
- **MAC 双套缺省值（须写清，不得含糊）**：planner 缺省 `aa:bb:cc:dd:ee:01`/`02`（`planner.go:250-253`）；spec/worker 缺省 `02:00:00:00:00:01`/`02`（`strategy_convert.go:31-32`）。链路径上 `spec.SrcMAC` 来自 `FlowMeta` → **实测为后者**（T-7 断言 `eth.src = 02:00:00:00:00:02`）。**eth 层 MAC 覆写今日不可达**（planner 恒写非空值，抢先于 `chain_planner.go:1352` 的回填）→ G-PPPOE-2。
- **内层端口**：**恒 0**（链路径无端口位，§2/§3.7）；这是已声明合成面，不是缺陷。
- **地址族**：**只 IPv4**（PPP `0x0021`）；IPv6 → N-4 负例；混族被 ip 层 same-IP-version 门先拦（P5 教训，故负例用**同族** IPv6）。
- **`data_frames`**：`0` 语义 = **缺省 1**（非"无数据帧"）；registry 上界 1000000（V9 门）。
- **`mru`**：uint16；`0` → 1492；实现**不校验 ≤1492**（RFC2516 §7 要求）→ G-PPPOE-6。
- **`magic_number`**：uint32；`0` → 随机。
- **`sessions[]`**：非 nil 空数组 → 拒（同 N-5 锚词）；显式重复 ID → 拒（N-6）；派生 ID 自动唯一。
- 不得产生回绕长度或超量分配（帧长由 `buildPacketFromConfig` 一次算定）。

## 9. 原子 ID 与完成定义（24 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 | packet_count（机读复核） |
|---:|---|---|---|---:|
| 1 | `pppoe_lifecycle_full` | 正 | §3.4/§3.5/§3.7/§3.8：全生命周期（缺省 ID 1 + PADT） | 8 |
| 2 | `pppoe_padt_suppressed` | 正 | §3.8：`padt=false` 指针三态抑制 | 7 |
| 3 | `pppoe_skip_discovery` | 正 | §3.4：`skip_discovery=true` + 显式 ID 9 | 4 |
| 4 | `pppoe_auth_none_lcp_len` | 正 | §3.5：无 Auth-Protocol 选项 → LCP len 14 | 8 |
| 5 | `pppoe_auth_pap` | 正 | §3.5/§3.6：LCP c023 + PAP Req/Ack | 10 |
| 6 | `pppoe_auth_chap` | 正 | §3.5/§3.6：LCP c223 + CHAP 三帧 | 11 |
| 7 | `pppoe_data_direction_down` | 正 | §3.7：下行换向（内嵌 IP + MAC） | 4 |
| 8 | `pppoe_data_frames_zero_default` | 正 | §3.7：`data_frames=0` → 缺省 1 | 8 |
| 9 | `pppoe_service_name_any` | 正 | §3.3：零长 Service-Name（any-service） | 8 |
| 10 | `pppoe_bras_three_tags` | 正 | §3.3：BRAS 三标签 + PADR 回显 Cookie | 8 |
| 11 | `pppoe_mru_magic_explicit` | 正 | §3.5：MRU 1480 + Magic 显式钉值 | 4 |
| 12 | `pppoe_sessions_derived_ids` | 正 | §5：`sessions[3]` 派生 ID 1/2/3 | 24 |
| 13 | `pppoe_sessions_explicit_ids` | 正 | §5：`sessions[2]` 显式 ID 100/200 | 16 |
| 14 | `pppoe_composite_multi_session` | 正 | §5/§10.4：复合大场景（模板 chap + 2 会话混合形态） | 19 |
| 15 | `pppoe_inner_tcp_explicit` | 正 | §3.7：`inner_proto=6` 内嵌 TCP | 4 |
| 16 | `pppoe_data_payload_bytes` | 正 | §3.7：`data_payload` 原文字节钉 | 4 |
| 17 | `pppoe_data_frames_two` | 正 | §3.7：`data_frames=2` 多帧 + IPID 递增 | 5 |
| 18 | `pppoe_inner_udp_explicit` | 正 | §3.7：`inner_proto=17` 显式 UDP | 4 |
| 19 | `pppoe_neg_auth_invalid` | 负 | §7 N-1 | —（0 帧） |
| 20 | `pppoe_neg_inner_proto_invalid` | 负 | §7 N-2 | —（0 帧） |
| 21 | `pppoe_neg_data_frames_negative` | 负 | §7 N-3 | —（0 帧） |
| 22 | `pppoe_neg_ipv6_inner` | 负 | §7 N-4 | —（0 帧） |
| 23 | `pppoe_neg_sessions_mutex` | 负 | §7 N-5 | —（0 帧） |
| 24 | `pppoe_neg_duplicate_session_id` | 负 | §7 N-6 | —（0 帧） |

**包数公式复核（机读脚本，§13）**：18 正例全部命中 §5 公式，**0 例不符**。校验：#1 4+2+0+1+1 = 8 ✓；#2 4+2+0+1+0 = 7 ✓；#3 0+2+0+1+1 = 4 ✓；#5 4+2+2+1+1 = 10 ✓；#6 4+2+3+1+1 = 11 ✓；#8 4+2+0+1+1 = 8 ✓；#12 3×8 = 24 ✓；#13 2×8 = 16 ✓；#14 (4+2+3+1+1) + (0+2+3+2+1) = 11+8 = 19 ✓；#17 0+2+0+2+1 = 5 ✓。

## 10. P1 规范矩阵（规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | 以太网直载，两阶段（Discovery 客户端-服务器 + Session 点对点，RFC2516 §3） | 场景①–⑪ | `DependsOn ["ip"]` 单值（`registry.go:2192`）；raw 自驱终结层（`chain_planner_util.go:54/57`） | 无 |
| 2 | 命令/消息表 | Discovery 5 类 code（§5.1–§5.5）+ Session code 0x00（§6）+ PPP Protocol 4 类（RFC1661 §2） | 场景①–⑦⑪ | `emitFrame` 按 code 写 EtherType（`planner.go:280-283`）；`builder.go:42-48` 六 code 常量 | 无（code 全表覆盖） |
| 3 | 状态机 | 两阶段五状态（§5 表） | #1/#5/#6/#12 | `runSession` 顺序过程（`planner.go:220-485`） | 无运行时状态机（§5 明写；状态机错负例不适用） |
| 4 | 字段表 | PPPoE 头 4 字段 + TLV 3 字段 + PPP Protocol 2B + LCP 4 字段 + 选项 3 类 | 数据场景层 | `writeL2`/`serializePPPoETags`/`buildLCPMessage` 逐字段 | 无 |
| 5 | 错误处理 | 6 类负例（§7）+ 13 个未入例拒绝分支 | 负例 N-1…N-6 | `Validate` 6 分支（`planner.go:102-181`）+ builder 5 分支 + schema 2 检查 | G-PPPOE-6（可达未建例 4 条） |
| 6 | 超时与活性 | RFC2516 §8：PADI/PADR 重传与等待加倍（SHOULD）；RFC2516 §7：AC 周期性发 Echo-Request（RECOMMENDED） | — | **零重发逻辑**（`grep` 实测空）；**零 Echo-Request**（LCP code 8/9 未编排） | G-PPPOE-5（如实登记，不实现） |
| 7 | NAT/代理/被动 | Relay-Session-Id 中继（§5/Appendix A 0x0110）；无被动模式概念（客户端主动发起） | — | 无中继编排；无被动模式 | **显式不适用**被动模式；中继 → G-PPPOE-5 |
| 8 | 版本/方言 | VER/TYPE 恒 0x1（§4，唯一版本）；EtherType 0x8863/0x8864 唯一（§8） | 全正例 | 恒 `0x11`；EtherType 按 code 强制 | 无 |

### 10.2 子表①：阶段 × 终态矩阵（逐格已覆/立项/不适用）

| 阶段 | T1 正常终态 | T2 配置拒绝 | T3 RST 异常终态 |
|---|---|---|---|
| Discovery（PADI/PADO/PADR/PADS） | 已覆（#1/#9/#10/#12/#13/#14） | 已覆（#21 代表例，拒绝与阶段无关） | **不适用**（无外层 TCP，无 RST 概念） |
| LCP 协商 | 已覆（全正例） | 已覆（#19 代表例） | 不适用（同上） |
| PAP 认证 | 已覆（#5） | 已覆（#19 代表例） | 不适用 |
| CHAP 认证 | 已覆（#6/#14） | 已覆（#19 代表例） | 不适用 |
| 数据面（内嵌 IPv4） | 已覆（#1/#7/#15/#16/#17/#18） | 已覆（#20 代表例） | 不适用 |
| PADT 拆线 | 已覆（全正例除 #2） | 已覆（#23/#24 代表例） | 不适用 |
| 跳过发现（半开） | 已覆（#3/#7/#11/#15–#18） | 已覆（#22 代表例） | 不适用 |
| 多会话编排 | 已覆（#12/#13/#14） | 已覆（#23/#24） | 不适用 |

**逐格重数（机读）**：8 行 × 3 列 = 24 格——已覆 **16**（T1 列 8 + T2 列 8）/ A′ 立项 **0** / **不适用 8**（T3 列 8，**理由=pppoe 无外层传输层，RST 是 TCP 层概念，本协议链上无 TCP**）。16 + 0 + 8 = 24 ✓，零空格。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **58 行**：

| # | 变体 | 落点 |
|---:|---|---|
> **注（口径）**：本表"覆"= **有显式断言落点**（field/frames）；无断言的帧仍由 `packet_count` + 帧位间接钉（如全 18 正例均发射完整 Discovery 四步）。逐例断言落点已机读实测（§13）。

| 1 | code `0x09` PADI | 覆（断言 #1/#2；全 18 正例发射） |
| 2 | code `0x07` PADO | 覆（断言 #1；全 18 正例发射） |
| 3 | code `0x19` PADR | 覆（断言 #1；全 18 正例发射） |
| 4 | code `0x65` PADS | 覆（断言 #1/#2；除 skip 形外全部发射） |
| 5 | code `0x00` Session Data | 覆（断言 #1/#3；全 18 正例发射） |
| 6 | code `0xa7` PADT | 覆（断言 #1/#3/#5/#8/#14/#17；除 #2 外全部发射） |
| 7 | 非法 code（六值之外） | 立项（planner 自管 code，不透出 → **不可达**） |
| 8 | TLV `0x0000` End-Of-List | 立项（未编排，G-PPPOE-5） |
| 9 | TLV `0x0101` Service-Name 非空 | 覆（#10 `"internet"` = `01 01 00 08`） |
| 10 | TLV `0x0101` 零长（any-service） | 覆（#9 三帧 `01 01 00 00`；#1 亦为缺省零长） |
| 11 | TLV `0x0102` AC-Name | 覆（#10 `"BRAS-1"`；缺省 `"trafficgen"` 由 #1 隐式覆盖） |
| 12 | TLV `0x0103` Host-Uniq | 立项（未编排，G-PPPOE-5） |
| 13 | TLV `0x0104` AC-Cookie 显式 | 覆（#10 PADR offset 32 `01 04 00 04 de ad be ef`） |
| 14 | TLV `0x0104` 缺席 | 覆（#1/#9 等，无 cookie 标签） |
| 15 | TLV `0x0105` Vendor-Specific | 立项（未编排） |
| 16 | TLV `0x0110` Relay-Session-Id | 立项（builder 通用序列化器支持，planner 未编排） |
| 17 | TLV `0x0201` Service-Name-Error | 立项（PADS 拒绝路径未编排，G-PPPOE-5） |
| 18 | TLV `0x0202` AC-System-Error | 立项（未编排） |
| 19 | TLV `0x0203` Generic-Error | 立项（未编排） |
| 20 | PPP `0x0021` IPv4 | 覆（断言 #1/#3/#5/#7/#15/#17/#18；全 18 正例数据帧） |
| 21 | PPP `0xc021` LCP | 覆（断言 #1/#4/#5/#11；全 18 正例） |
| 22 | PPP `0xc023` PAP | 覆（#5 两帧，帧 7/8） |
| 23 | PPP `0xc223` CHAP | 覆（#6 三帧 7/8/9；#14 帧 7/14） |
| 24 | PPP `0x8021` IPCP | 立项（未编排，G-PPPOE-3） |
| 25 | LCP MRU 缺省 1492 | 覆（#1 隐式；`payload_length` 0x0010 间接钉） |
| 26 | LCP MRU 显式 1480 | 覆（#11 `01 04 05 c8`） |
| 27 | LCP Magic 随机 | 覆（全正例除 #11；字节随机**不断言**） |
| 28 | LCP Magic 显式 | 覆（#11 `05 06 01 02 03 04`） |
| 29 | LCP Auth-Protocol 缺席 | 覆（#4，LCP len 14） |
| 30 | LCP Auth-Protocol `0xc023` | 覆（#5，LCP len 18） |
| 31 | LCP Auth-Protocol `0xc223` | 覆（#6，LCP len 18） |
| 32 | LCP Configure-Ack 回显同选项 | 覆（全正例帧 6/8 等） |
| 33 | `skip_discovery=false`（缺省，完整发现） | 覆（#1/#4/#5/#6/#8/#9/#10） |
| 34 | `skip_discovery=true` | 覆（#3/#7/#11/#15/#16/#17/#18） |
| 35 | `padt` 缺省（nil → 发） | 覆（全正例除 #2） |
| 36 | `padt=false`（抑制） | 覆（#2） |
| 37 | `data_frames=0`（→ 缺省 1） | 覆（#8） |
| 38 | `data_frames=1`（缺省路径） | 覆（#1 等多数） |
| 39 | `data_frames=2` | 覆（#17、#14 会话 2） |
| 40 | `inner_proto=0`（缺省 → 17） | 覆（#1 等多数，`ip.proto=17`） |
| 41 | `inner_proto=6` 显式 TCP | 覆（#15） |
| 42 | `inner_proto=17` 显式 UDP | 覆（#18） |
| 43 | `data_direction` 缺省 up | 覆（多数正例） |
| 44 | `data_direction=down` | 覆（#7、#14 会话 2） |
| 45 | `data_payload` 缺省（→ `spec.Payload`） | 覆（多数正例） |
| 46 | `data_payload` 显式字节 | 覆（#16 `"tg-payload"`） |
| 47 | `sessions[]` 缺省（单会话速记） | 覆（#1–#11/#15–#18） |
| 48 | `sessions[3]` 全空项（派生 ID） | 覆（#12） |
| 49 | `sessions[2]` 显式 ID | 覆（#13） |
| 50 | `sessions[]` 与模板键共存（chap 模板共享） | 覆（#14） |
| 51 | `sessions[]` 与行为键共存 | 覆（#23 **负例**） |
| 52 | `sessions[]` 空数组 | 立项（`planner.go:160` + `semantic.go:334` 有分支，今日无例） |
| 53 | 重复显式 `session_id` | 覆（#24 **负例**） |
| 54 | `payload_length` 覆写 | 立项（builder 支持 `builder.go:345`，planner 不设，今日无例） |
| 55 | 内嵌 IPv4 地址（ip 层语义） | 覆（全 18 正例） |
| 56 | 内嵌 IPv6（同族） | 覆（#22 **负例**，锚词 `must be IPv4`） |
| 57 | eth 层 MAC 覆写 | 立项（**链路径不可达**——planner 恒写非空 MAC，G-PPPOE-2） |
| 58 | 短帧填充至 60 | 覆（PADI/PADO/PADR/PADS/LCP/PAP/CHAP 各帧） |

**重数**：**覆 46 + 立项 12 = 58** ✓（机读逐行统计）。12 条立项 = 第 7/8/12/15/16/17/18/19/24/52/54/57 行（TLV 未编排 6 条 + IPCP 1 + 非法 code 1 + `sessions[]` 空数组 1 + `payload_length` 覆写 1 + MAC 覆写 1 + 认证/地址未编排 1）；其中 4 条为**不可达面**（#7 非法 code / #52 部分 / #54 / #57）——按"未入例"登记，**不冒充覆盖**。

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 标准宽带拨号全生命周期（RFC2516 §5+§6） | #1 | 已覆 |
| 2 | 客户端主动拆线（§5.5 PADT） | #1/#2 | 已覆 |
| 3 | 半开/重协商（跳过发现直入会话） | #3 | 已覆 |
| 4 | 无认证 ISP 接入 | #4 | 已覆 |
| 5 | PAP 明文认证接入（RFC1334） | #5 | 已覆 |
| 6 | CHAP 质询认证接入（RFC1994） | #6 | 已覆 |
| 7 | 下行推流（服务器→客户端） | #7 | 已覆 |
| 8 | 现网 BRAS 三标签形（AC-Name + AC-Cookie 关联） | #10 | 已覆 |
| 9 | any-service 客户端（不挑服务） | #9 | 已覆 |
| 10 | 同 BRAS 多用户并发拨号 | #12/#13/#14 | 已覆（**整块顺序，非并发**，§5） |
| 11 | 内嵌业务协议区分（TCP/UDP） | #15/#18 | 已覆 |
| 12 | 配置错误拒绝（六类） | #19–#24 | 已覆 |
| 13 | IPCP 地址协商（现网拨号先协商地址） | — | **已登记缺口，迁入计划**（G-PPPOE-3） |
| 14 | 真实 CHAP MD5 摘要 | — | **已登记缺口，迁入计划**（§3.6 回显合成） |
| 15 | PADI/PADR 重传与超时加倍（§8） | — | **已登记缺口，迁入计划**（G-PPPOE-5） |
| 16 | LCP Echo-Request 保活（§7） | — | **已登记缺口，迁入计划**（G-PPPOE-5） |
| 17 | Relay-Session-Id 中继 | — | **已登记缺口，迁入计划**（G-PPPOE-5） |
| 18 | PADS Service-Name-Error 拒绝路径 | — | **已登记缺口，迁入计划**（G-PPPOE-5） |
| 19 | Host-Uniq 请求关联 | — | **已登记缺口，迁入计划**（G-PPPOE-5） |
| 20 | VLAN/MPLS/GRE 组合承载 | — | **已登记缺口，迁入计划**（builder 显式拒） |

**重数（机读）**：**覆 12 + 不适用 8 = 20** ✓（第 1–12 行"已覆"，第 13–20 行"已登记缺口，迁入计划"）。无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比

三路：①**规范原文**（RFC2516/RFC1661/RFC1334/RFC1994，本轮已拉取原文逐节核对——**校正内部契约 7 处章节号引错**，§0 #2–#8）；②**商业化软件行为**（现网 BRAS 形：AC-Name 标识局设备、AC-Cookie 关联发现与会话——出处=运营商接入网通用抓包形，**未取到本仓实测现网 pcap** → G-PPPOE-5 待确认）；③**可靠开源实现思路**（pppd/rp-pppoe 的 Discovery 四步序、LCP 选项序 MRU→Magic→Auth-Protocol——只借鉴"选项顺序与 TLV 长度语义"两条思路）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | **独立 `pppoe` 终结层 + raw 自驱**（本版；srv6/ldap/radius 同构先例） | Discovery 四步/LCP 选项/认证三态/多会话可声明可断言；代价 = 一套层（已落码 685 行生产代码 + 805 行单测） | **采用**（D-PPPOE-1 裁定1） |
| B | `[eth, pppoe]` 让 eth 层管 MAC | eth 层 `Fields` 有 `src_mac`/`dst_mac`，但 planner 恒写非空 MAC 抢先 → 覆写不可达（G-PPPOE-2） | **否决**（现状即如此；如需 MAC 覆写须改 planner 优先级） |
| C | `[ip, tcp, pppoe]` 走 tcp 事件面 | PPPoE 无外层 TCP——帧是 L2 直载，tcp 层无立足点 | **否决**（协议事实不允许） |

## 11. P2 D-PPPOE-1 代码设计（as-built；D-PPPOE-1 已验收 = 定稿）

> 状态说明：实现已落码并验收（`D-PPPOE-1`，2026-09-20，提交 `8b6c565` P4 + `bdd6275` P5/P6）。本 P2 条目为文档轨对既有实现的**逆向定稿**（as-built），供后续改动的唯一入口。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/protocol/pppoe/planner.go` | `Validate`（6 分支）+ `Plan`/`runSession`/`emitFrame` + LCP/PAP/CHAP 序列化器 | 608 |
| `trafficgen/internal/protocol/pppoe/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator` + `RegisterLayerValidator`，`init()`）+ 防双换 | 77 |
| `trafficgen/internal/protocol/pppoe/planner_test.go` | 13 个 `Test*` | 805 |
| `trafficgen/internal/core/builder.go`（PPPoE 段） | 线编码：`writeL2` PPPoE 头 + `serializePPPoETags` + `validatePPPoEConfig` + Payload_Length | `:25-56`/`:217-250`/`:334-352`/`:442-480` |
| `trafficgen/internal/core/types.go` | `PPPoEConfig`（`:3051-3180`）+ `PPPoESession`（`:10786-10794`）+ `FlowSpec.PPPoE`（`:1851`）+ `PacketConfig` 槽位（`:2996`） | —（共享文件） |
| `trafficgen/internal/core/strategy_convert.go` | `parsePPPoEConfig`（`:4182`）+ `ParsePPPoEConfigFromMap`（`:4216`）+ `ParsePPPoESessions`（`:4223`）+ `SessionIDDyn` 旁挂（`:4236`）+ `case "pppoe"`（`:1201`）+ `DefaultSrcMAC/DstMAC`（`:31-32`） | — |
| `trafficgen/internal/core/schema/semantic.go` | `checkPPPoESessionsMutex`（`:326-372`）+ `numField` 双形（`:376-386`）+ 调用点（`:165`） | — |
| `trafficgen/internal/core/layers/registry.go` | pppoe 行（`:2191-2211`，`CategoryTerminal` + `DependsOn ["ip"]` + **16 Fields**） | — |
| `trafficgen/internal/core/layers/chain_planner_util.go` | `isRawIPChain` 双名单（`:54`/`:57`） | — |
| `trafficgen/internal/core/layers/chain_planner.go` | src 0-keep 名单（`:774-776`）+ dst 0-keep 名单（`:996-997`）+ `FlowMeta.PPPoE` carry（`:1514-1516`） | — |
| `trafficgen/internal/core/layers/chain_planner_translate.go` | `case "pppoe"`（`:2764-2776`，复用 `ParsePPPoEConfigFromMap` 单真相） | — |
| `trafficgen/internal/core/layers/generator.go` | `FlowMeta.PPPoE`（`:512`） | — |
| `trafficgen/internal/core/protocols.go` | `allowedProtocols["pppoe"]=true`（`:51`） | — |
| 测试（core 侧） | `builder_pppoe_test.go` 14 个 `Test*`（648 行）/ `pppoe_chain_test.go` 2 个（129 行）/ `pppoe_sessions_parse_test.go` 3 个（89 行）/ `schema/pppoe_sessions_test.go` 4 个（101 行） | 967 |

**测试合计**：**36 个 `Test*` 函数**（13+14+2+3+4，`grep -c '^func Test'` 实测）。

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`planner.go:100`）：`PPPoE==nil` 拒；内嵌 `SrcIP`/`DstIP` 必须是 IPv4；`Auth` 枚举；`InnerProto` 枚举；`DataFrames >= 0`；`DataDirection` 枚举；`sessions[]` 互斥 + 空数组 + 重复显式 ID（三锚，与 schema 同锚词背 door）。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`planner.go:191`）：容量 256 的 channel；goroutine 内跑 `sessions[]` 循环或单会话。
- `runSession(sessCfg core.PPPoEConfig, sessFlowID string)`（`planner.go:220`）：一条完整生命周期。
- `emitFrame(direction, srcMAC, dstMAC string, code uint8, sessID uint16, pppProto uint16, tags []core.PPPoETag, payload []byte, l3 core.L3Config, l4 core.L4Config, withL3L4 bool) bool`（`planner.go:279`）：单帧发射；`FlowID` 由闭包注入。
- 序列化器：`buildLCPMessage`（`:534`）/ `buildPAPRequest`（`:546`）/ `buildPAPAck`（`:561`）/ `buildCHAPChallenge`（`:574`）/ `buildCHAPResponse`（`:588`）/ `buildCHAPSuccess`（`:602`）。
- 生成器：`Name() "pppoe"`；`GenEvents() layers.EventGenerator` 返回 **nil**（raw 自驱，无事件面）；`Generate(ctx, *layers.GenRequest)` 逐帧 `Emit`（`layer_gen.go:33-65`）。

### 11.3 数据结构

`PPPoEConfig`（`types.go:3054`）**27 个 JSON 字段**，分三层：

| 层 | 字段 | 说明 |
|---|---|---|
| **wire 层**（builder 直读） | `Code`、`SessionID`、`PPPProtocol`、`PayloadLength`、`DiscoveryTags[]`、`PADT *bool`、`Sessions[]` | planner 每包填充；**不登记** registry Fields（见下） |
| **会话级**（planner 读，builder 忽略） | `SkipDiscovery`、`ACName`、`ServiceName`、`Cookie`、`MRU`、`MagicNumber`、`Auth`、`Username`、`Password`、`DataFrames`、`DataPayload`、`InnerProto`、`DataDirection` | 14 键 |
| **多会话** | `Sessions []PPPoESession` | `PPPoESession{SessionID, SessionIDDyn *StrategyConfig(json:"-"), SkipDiscovery, DataFrames, DataPayload, InnerProto, DataDirection}` |

**registry Fields = 16 键**（`registry.go:2193-2210`）：`session_id`/`skip_discovery`/`ac_name`/`service_name`/`cookie`/`mru`/`magic_number`/`auth`/`username`/`password`/`data_frames`/`data_payload`/`inner_proto`/`data_direction`/`padt`/`sessions`。

**wire 键 `code`/`ppp_protocol`/`payload_length`/`discovery_tags` 不登记**（P3 复审裁定，`CODE_DESIGN.md:2906`）：它们是 builder 每包面字段、**不被流程消费**，登记后用户可在层内写死单帧 code 而破坏生命周期——`ValidateLayerConfig` 拒之 = **正确行为**（1.12 消费面裁定）。

**sessions 互斥键集合（精确）**：**行为 6 键** = `{session_id, skip_discovery, data_frames, data_payload, inner_proto, data_direction}`（`semantic.go:331` + `planner.go:162-171`，两处独立同集合同序）；**模板 9 键** = `{ac_name, service_name, auth, username, password, mru, magic_number, cookie, padt}` 允许共存共享。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry 16 键 allowlist + `checkPPPoESessionsMutex`）→ translate（`case "pppoe"` → `ParsePPPoEConfigFromMap(completedConfig(s, term.Config))` → `spec.PPPoE`）→ `FlowMeta.PPPoE` carry（`chain_planner.go:1516`）→ `PPPoEGenerator.Generate`（`layer_gen.go:33`，`Direction` 统一改 `"up"`）→ `Planner.Plan` → `runSession` → `emitFrame` → `req.Emit`（raw-IP 驱动分支）→ worker → writer（PCAP/NIC）。

**translate 单真相**（`chain_planner_translate.go:2764-2776`）：层 config 经 `core.ParsePPPoEConfigFromMap` 复用扁平解析单一真相（`data_payload` 字符串语义=**原文字节**，JSON 往返会 base64 误读——srv6 `inner_payload` 同陷阱）；空层 config 也翻译出非 nil（全默认冒烟形状合法：PADT 缺省 true、SessionID 缺省 1）。

### 11.5 错误分支

6 种 planner 拒绝（`planner.go:102-181`）+ 5 种 builder 拒绝（`:447/452/455/461/464/350`）+ 2 种 schema 检查（`semantic.go:334/355`）全部传 task error（零假成功——6 负例实测 0 帧）。**真实拦截面与锚词见 §7 表**（N-3 走 registry V9 门，非 planner）。

### 11.6 性能边界

见 §6（channel 256 流式产出、`runSession` 局部状态、无跨流共享、无锁；吞吐数字待基准）。

### 11.7 与现有逻辑的冲突点

- `CheckProtoFlat`（`strategy_convert.go:8625` 起）：pppoe 顶层子映射 presence **不判死**（与 dns/mqtt/http 族已登记协议不同，属框架级缺口 → G-PPPOE-7）。
- **顶层未知键通用门也缺**：游离顶层键（如 `{layers:[…], bogus: 1}`）今日**不判死** → presence 负例今日建了会真绿 = 假通过，**不建**（G-PPPOE-7，与 opcua G-OPCUA-1 同款）。
- 动态 allowlist（`internal/core/layer_dyn.go:17-26`）：`pppoe` **零命中**（`grep` 实测）→ 业务字段动态对象即 `does not support dynamic`（`validate_layers.go:961/989` 门）；四元组 `ip`/`tcp`/`udp`/`eth` 全开。见 §12.12。
- **MAC 覆写不可达**（G-PPPOE-2，§3.1/§8）。
- **内层端口恒 0**（已声明合成面，G-PPPOE-4）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert `internal/protocol/pppoe/` 三文件 + core 侧接线 9 处（registry/protocols/translate/convert/semantic/chain_planner×2/chain_planner_util/generator/main.go）；不触及其他协议。cases 回滚 = 恢复 24 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 24/24 顶层 = `{layers}` **仅此一键，零残留**；目标形状见 §2 样例且**存量已达标**（本协议无迁移工作量） | §12.1；`cases/pppoe.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 pppoe 生命周期模板（`sessions[]` 可承载多生命周期）；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例；D-PPPOE-1 裁定1 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/**关联关系（无派生流，诚实声明）**/插入位置（终结层）/时间线。有会话载体，不留未登记空白 | §12.3 + §5 |
| §4 查规范 | RFC2516/RFC1661/RFC1334/RFC1994 **原文逐节核对**（本轮拉取，校正内部契约 7 处引错）+ tshark 3.6.14 字段表 + 落码反推；八项矩阵 + 子表①②③ | §10；§0 #2–#8 |
| §5 依赖与错误 | `DependsOn ["ip"]` 单值（`registry.go:2192`）；6 负例 + 13 未入例分支；失败传 task error（6 负例 0 帧） | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待基准，不写承诺；pcap/NIC 两路验收明写） | §6 |
| §7 三份文档 | `docs/protocols/pppoe/{design,testcase}.md` v1.0.0（本批首份）+ D-PPPOE-1（§11，已验收=定稿）+ T-PPPOE-1…24（testcase §2）+ 内部契约 D-PPPOE-1/T-PPPOE 为继承层 | 修订记录 |
| §8 设计先行 | 内部契约 D-PPPOE-1（P1–P6）先于实现；本版为 as-built 追认 | 提交序（`8b6c565`/`bdd6275`） |
| §9 测试三源 | 三源 = RFC 原文（§10）+ D-PPPOE-1（§11）+ tshark 字段表与 24 例 cases（**pcap 未在案**：`.gitignore:88` 使 pcap 不入库）；24 ID 逐项回指；存量审计 testcase §8 | `docs/protocols/pppoe/testcase.md` §2/§5/§8 |
| §10 评审闭环 | D-PPPOE-1 每阶段对抗自重审（门1 4 项→P2 4 项→P3 2 项→P4 2 项→P5 抓 1 真 bug）；本版文档轨自审见 §15 | 自审日志 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `pppoe` 已在 `registry.go:2191` 注册（**不新增层**）；Fields 16 键与 P3 复审裁定一致；**P4 若改 registry Fields 必须重跑 schemagen** | §11.1/§11.3 |
| §14 真实流程 | D-PPPOE-1 P5 经 MCP 建策略建任务 → 引擎真实生成 → tshark `pppoe.*`/`ppp.*` + frames 双通道 → 先跑后钉（24/24×2 全绿）；pcap 落盘但**不入库** | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | `spec_json` 顶层键 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|---|
| `cases/pppoe.json` | 24 | `{expect,id,proto,spec_json,summary}` | **`{layers}` ×24**（唯一键，**零游离键**） | `[ip,pppoe]` ×24 | 6/6 = `{expect_error, error_contains}` **严格两键** |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 本协议**从未用过顶层地址**；内嵌 IPv4 已住 `layers[0].ip.{src,dst}`（24/24） |
| `src_port` | **0** | 本已 absent（链路径无端口位，恒 0，§2） |
| `dst_port` | **0** | 同上；pppoe 无外层端口概念 |
| `count` | **0** | 走 `flow_control`（本版未用；多会话走 `sessions[]`） |
| 顶层 `pppoe` 子映射 | **0** | 已住 `layers[1].pppoe`（24/24） |
| `strategy_fc` / `flow_control` | **0** | 本协议无多流用例；目标形按需加 |
| `code`/`ppp_protocol`/`payload_length`/`discovery_tags` | **0** | **不登记** registry Fields（wire 面键，planner 每包填充，§11.3） |

**结论**：**本协议存量 24/24 顶层零残留**——§1 门的动作 = ①**无旧键可删**；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测 24/24 顶层仅 `layers`）；③A′ 新增例全部沿用纯 layers 形（§13）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"pppoe":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 pppoe 分支，`grep -c 'protocol == "pppoe"'` = 0 实测）→ **不建该负例**（建了会真绿 = 假通过）→ 缺口 G-PPPOE-7 登记。
- ② 白名单外游离键判死（`unknown field`）今日**亦无通用门** → 同 G-PPPOE-7，不建。
- ③ 6 负例每条带锚词（已齐，§7），`expect` 严格两键（**无 `notes`**，机读实测）。
- ④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

- **会话表**：`s1` 单会话基线（#1–#11/#15–#18，各自内嵌 IPv4 四元组，Discovery→LCP→[Auth]→Data→PADT）/ `s2` 多会话（#12 三项派生 1/2/3；#13 两项显式 100/200；#14 两项 21/22 混合形态——**每项一条完整独立生命周期**）。
- **事务序列**：`t1` Discovery 四步（PADI/PADO/PADR/PADS，§5 状态表）/ `t2` LCP 协商（Configure-Request/Ack 对）/ `t3` 认证（PAP 对 或 CHAP 三帧，条件=`Auth ∈ {pap,chap}`）/ `t4` 数据面（N 帧内嵌 IPv4）/ `t5` 拆线（PADT 单帧）。每事务四件事（前置/触发/成功/失败）见 §5 状态机表 + §4 场景表。
- **关联关系**：**无派生流**（诚实声明：PPPoE 会话内的 PPP 链路是**单条点对点链路**，LCP/PAP/CHAP 与数据帧共用同一 Session ID 与同一对 MAC，**无副连接、无 `driven_by`**——与 FTP 控制/数据、SIP 信令/媒体的主从流不是同一维度）。唯一的"关联"是 **Session ID 绑定**（RFC2516 §4：Session ID + 两端 MAC 唯一确定一条 PPPoE 会话）——PADS 分配、后续全部 Session Data 帧与 PADT 回显同一值（#1 帧 4/5/6/7/8 均 `0x0001`）。
- **插入位置**：**终结层**（`[ip, pppoe]`，无中间层；pppoe 是 `CategoryTerminal`，帧由生成器一次产全）。
- **时间线**：会话内严格顺序（Discovery 四步 → LCP 对 → 认证 → 数据 N 帧 → PADT）；多会话**整块顺序**（#12 帧 1–8/9–16/17–24 三段不交错）；**无并发**（`concurrent` 为例外路径，本协议不启用）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组**：`ip.src`/`ip.dst`/`tcp.src_port`/`tcp.dst_port`/`udp.src_port`/`udp.dst_port`/`eth.src_mac`/`eth.dst_mac` 五策略全开（allowlist `internal/core/layer_dyn.go:17-26` 头部实测：`ip`/`tcp`/`udp`/`eth`；保底 `DefaultSrcPort+i`（`strategy_convert.go:49`））。**pppoe 链上无 tcp/udp 层** → 端口动态面实际不可用；`ip` 层动态**可用**（承载内嵌 IPv4 地址，逐流变有意义）；`eth` 层动态**注册但链路径不可达**（G-PPPOE-2）。

**业务字段 16 项全关**（allowlist **无 `pppoe` 行**，`grep` 零命中实测；对象即 `does not support dynamic`，`validate_layers.go:961/989`）：

| 字段 | 开关 | 理由 |
|---|---|---|
| `session_id` | **关**（层直键） | 逐流变需求已由 `sessions[].session_id` **动态对象**旁挂承接（`SessionIDDyn`，见下）——层直键不另开 |
| `skip_discovery` | 关 | 结构选择器（布尔），逐流变无意义 |
| `ac_name` / `service_name` | 关 | 字符串，列表无动态形状；逐流变需求 → A′ 候选 |
| `cookie` | 关 | 对象（字节双形），无动态形状 |
| `mru` / `magic_number` | 关 | 数值常量，逐流变无意义（Magic 随机已由 planner 承担） |
| `auth` | 关 | 枚举选择器 |
| `username` / `password` | 关 | 字符串；逐流变需求 → A′ 候选 |
| `data_frames` | 关 | 数值常量 |
| `data_payload` | 关 | 对象（字节双形），无动态形状 |
| `inner_proto` | 关 | 枚举选择器 |
| `data_direction` | 关 | 枚举选择器 |
| `padt` | 关 | 布尔开关 |
| `sessions` | 关 | 列表结构（**其内层 `session_id` 有独立动态通道**，见下） |

**唯一的业务动态通道（`sessions[].session_id`）**：`PPPoESession.SessionIDDyn *StrategyConfig`（`types.go:10793`，`json:"-"`）——扁平解析时由 `parseStrategyConfigDyn(m["session_id"])` 旁挂（`strategy_convert.go:4236`）；planner 逐会话按**流序号**解析：`core.ResolvePortValue(sess.SessionIDDyn, spec.FlowIndex)`，**非 0 才生效**（`planner.go:496-499`）；`FlowIndex` 由 `layer_gen.go:52` 从 `req.Meta.FlowIndex` 透传。

**序号算法实读（逐处行号）**：
- `parseLayerDyn`（`layer_dyn.go:78` 区段）/ `LayerDynAllowlisted`（`:1052`）/ allowlist 表（`:17-26`）——**`pppoe` 无块**，即层内任何对象值 → `does not support dynamic`。
- `parseStrategyConfigDyn`（`strategy_convert.go:4236` 调用点）——`sessions[].session_id` 动态对象旁挂。
- `ResolvePortValue`（`tuple_generator.go:300-305` → `genPort`）——逐流解析。
- 保底自增（`strategy_convert.go:49` + worker 注入）——四元组兜底。
- **派生 Session ID 算法**（`planner.go:503-505`）：`DefaultSessionID + i`（= `1 + i`，**会话序号 i**，非流序号）——与 sip 动态对象按 `FlowIndex` 解析语义**不同**（T-PPPOE §9.40 陷阱注记，#12 notes 明写"派生=会话序号 i（1+i），非动态对象 FlowIndex 语义"）。

## 13. P3 对接清单（T-PPPOE 输入；正文落 testcase 文件）

24 ID（18 正 + 6 负）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。

**A′ 候选（今日无用例，不得冒充已覆盖）**：`pppoe_sessions_empty_array`（`sessions: []` 同 N-5 锚词，`planner.go:160`+`semantic.go:334`）/ `pppoe_neg_data_direction_invalid`（`planner.go:149`）/ `pppoe_neg_srcip_invalid`（`:117`）/ `pppoe_payload_length_override`（builder `:345` 覆写面）/ `pppoe_session_id_max`（`0xffff` 预留值，RFC2516 §4）/ `pppoe_mru_over_1492`（RFC2516 §7 上界）/ `pppoe_default_acname`（AC-Name 缺省 `"trafficgen"` 显式断言）/ `pppoe_host_uniq`（TLV 0x0103）/ `pppoe_pads_service_name_error`（TLV 0x0201 拒绝路径）/ `pppoe_lcp_echo_keepalive`（RFC2516 §7 Echo-Request）/ `pppoe_session_id_dyn`（`SessionIDDyn` 逐流动态，`FlowIndex` 面）/ `pppoe_eth_mac_override`（需先修 G-PPPOE-2）/ `pppoe_ipcp_phase`（需先实现，G-PPPOE-3）。

**机读复核脚本（本轮，自审用）**：① 24 例 ID 集合与顺序；② `spec_json` 顶层键 ⊆ `{layers}`；③ 18 正例 `packet_count` 对 §5 公式；④ 6 负例 `expect` 键集合 == `{expect_error, error_contains}`；⑤ 全部 `frames` 断言对派生字节模型（PPPoE 头/EtherType/TLV/PPP 头/LCP 选项偏移）；⑥ `coverage_gate.py pppoe` 45/45 复跑。**结果见 §15 自审结论。**

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-PPPOE-1 | **内部契约与实现注释的 RFC 章节号引错 7 处**（§0 #2–#8）：PADT 标 §5.6（应 §5.5）/ PPP 协议表标 RFC1661 §5（应 §2 或 RFC2516 §5.1–5.5）/ Magic 标 §6.13（应 §6.4）/ Auth-Protocol 标 RFC1661 §8（应 §6.2）/ PAP 标 RFC1334 §2.1（应 §2.2.1/§2.2.2）/ CHAP 标 RFC1994 §3（应 §4.1/§4.2） | **代码阶段**：修正 `planner.go` 与 `cases/*.json` summary 的章节引注（**不改行为、不改包数、不改断言**，纯注释/文案）；本文档已按 RFC 原文钉正确章节号 |
| G-PPPOE-2 | **eth 层 MAC 覆写链路径不可达**：planner 恒写非空 MAC（`planner.go:248-254`，缺省 `aa:bb:cc:dd:ee:01/02`）**抢先于** `chain_planner.go:1352` 的 `pkt.L2.SrcMAC == ""` 回填；且 planner 缺省与 spec 缺省（`02:00:00:00:00:01/02`）是**两套值** | A′ 候选（`pppoe_eth_mac_override`）；**需先裁定**：planner 应否优先用 `spec.SrcMAC/DstMAC` 的非空值（改 planner 取值优先级）——今日如实登记不可达 |
| G-PPPOE-3 | **IPCP 阶段未实现**（RFC 1332 网络层地址协商）：现网拨号先协商地址再传数据，引擎数据面地址来自配置非协商（D-PPPOE-1 缺口 F） | **已登记缺口，迁入计划**（v1 合成面）+ A′ 候选 `pppoe_ipcp_phase`；用例今日不得声称覆盖 |
| G-PPPOE-4 | **链路径内层 L4 端口恒 0**：链上无 tcp/udp 层可承载内嵌 IPv4 端口，pppoe 层 16 键亦无端口位（D-PPPOE-1 P4 B′ 注记） | A′ 候选（现网形内层端口需求）；今日如实登记为**已声明合成面**，用例 T-1 notes 已注记 |
| G-PPPOE-5 | **未编排的合法协议面 6 项**：TLV `0x0103` Host-Uniq / `0x0110` Relay-Session-Id / `0x0201` Service-Name-Error / `0x0202` AC-System-Error / `0x0203` Generic-Error / `0x0000` End-Of-List；+ PADI/PADR 重传（RFC2516 §8 SHOULD）+ LCP Echo-Request 保活（§7 RECOMMENDED）+ PADS 拒绝路径（§5.4） | **已登记缺口，迁入计划**（回放引擎无重传/无运行时收包）+ A′ 候选（TLV 面可按 `DiscoveryTags` 直配，但 planner 不编排）；第三源"现网 BRAS 实测 pcap"未取到 → **待确认**（抓现网拨号包对照） |
| G-PPPOE-6 | **可达但未建例的拒绝/边界面 4 条**：`PayloadLength` 覆写 >65535（`builder.go:350`）/ `mru > 1492`（RFC2516 §7 上界，实现不校验）/ `session_id == 0xffff`（RFC2516 §4 保留值，实现不拒）/ PADI 总长 > 1484（RFC2516 §5.1 约束，实现不校验） | A′ 补例（含两条"**实现不校验规范上界**"的缺陷候选：`mru` 与 `session_id 0xffff`，代码阶段裁定拒绝或登记） |
| G-PPPOE-7 | `CheckProtoFlat` 无 pppoe 分支（顶层 `pppoe` 子映射 presence 不判死）+ 无游离顶层键通用门 | P4 先实测再建例；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单）；今日不建（建了会真绿） |
| G-PPPOE-8 | **业务字段动态全关**（allowlist 无 `pppoe` 行）：`ac_name`/`service_name`/`username`/`password` 等逐流变需求无通道；唯一通道是 `sessions[].session_id`（`SessionIDDyn`） | A′ 候选，不冒充已覆盖（§12.12） |
| G-PPPOE-9 | **pcap 留档不入库**：`trafficgen/docs/protocol-pcap-test/pppoe.md`（tracked）的 24 条 `[pcap](pppoe/<id>.pcap)` 链接**全部断链**（`docs/protocol-pcap-test/pppoe/` 目录不存在；`.gitignore:88` `*.pcap` 使 pcap 从不入库）。**注**：该 md 末次提交 `bdd6275`（2026-09-20）**晚于**判死提交 `0417be5`（2026-09-13），故**不属过期产物**（与 opcua G-OPCUA-10 相反）；本车道**未跑**该套件，故**不以任何形式**引用该产物作为套件可跑证据 | **登记事实**（不删不改 tracked 产物）；口径与"结果数字已随提交、pcap 不入库"的既知形态一致 |

## 15. 修订记录

- v1.0.0（2026-09-29）：批次二 as-built 文档轨首版。**本协议无外部旧稿**（§0 机读实测）——继承来源 = 内部契约 D-PPPOE-1（`CODE_DESIGN.md:2882`，六裁定，已验收）+ T-PPPOE-1…24（`TEST_CASES.md:3744`，24/24×2 已执行）。**15 项内部契约校正**（§0），其中 7 项为 **RFC 原文逐节核对**得出的章节号引错（G-PPPOE-1）、1 项为代码可判题的 MAC 覆写不可达（G-PPPOE-2）。RFC2516/RFC1661/RFC1334/RFC1994 原文本轮全部拉取核对。存量 24 例机读审计（**顶层零残留**，本协议无迁移工作量）；**18 正例包数逐例对 §5 公式机读复核，0 例不符**；全部 `frames` 断言对派生字节模型复核（PPPoE 头/EtherType/TLV/PPP 头/LCP 选项偏移，全 OK）；`coverage_gate.py pppoe` 复跑 **45/45 绿**；D-PPPOE-1 as-built 定稿（§11）；缺口 G-PPPOE-1…G-PPPOE-9。**自审 3 轮，末轮干净**（轮次结论见 testcase §10）。

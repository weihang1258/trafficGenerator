# #123 arp（ARP 地址解析协议，RFC 826）设计契约

> 版本：v1.0.0（批次二文档车道 P1–P3，as-built 型）
> 日期：2026-09-29
> 车道：文档轨（#123 arp 续号）
> 旧基线：`docs/protocol-designs/123-arp-design.md` 为迁移前编号设计文档；本版将其内容迁入协议目录，并以 `docs/CODE_DESIGN.md` §D-ARP-1、`docs/TEST_CASES.md` §T-ARP-1…12、当前 12 例 JSON 与代码/实测交叉校正。冲突处按代码/实测钉（§0）。
> 存量用例：`trafficgen/test/protocol_pcap/cases/arp.json`（**12 例**，ID/顺序/断言已机读实测；`spec_json` 顶层键 = `{layers}` ×11 + `{layers,arp}` ×1（T-8 presence 判死负例，故意形状））
> 规范基线：① **RFC 826**（An Ethernet Address Resolution Protocol，1982，报文格式图 + 字段表 + Packet Generation/Reception 两段状态描述，下称 **spec**）；② 本机 tshark 3.6.14 `arp.*` 字段表（**51 个唯一字段**实测）+ 4 份正例实测 pcap（`/tmp/mcp-pcaps/arp/`，字节与包数的唯一权威）；③ 本仓库落码（`internal/protocol/arp/` 两文件 + 接线，§11）；④ 旧基线 D-ARP-1/T-ARP（内部契约，非外部规范）
> 白话一句：**ARP 就是"在以太网上喊一嗓子问谁有这个 IP"——帧里没有 IP 头也没有 TCP/UDP 头，28 字节直接骑在以太头后面（EtherType 0x0806）；问的人广播一句"谁有 10.0.0.2"，持有者单播回一句"我，我的 MAC 是 xx"。本生成器把这一问一答（或单发一答）按 RFC 826 字段序逐字节演出来。**

## 0. 沿革与旧来源校正声明（门1 必答：基线继承关系）

本协议文档已从迁移前编号文档 `docs/protocol-designs/123-arp-design.md` 迁入本目录。本版是协议目录下的 as-built 定稿：把 D-ARP-1 条目、T-ARP-1…12 清单、迁移前文档与当前 12 例 JSON 四方对齐，冲突处按代码/实测钉。逐条校正如下：

| # | 旧来源说法 | HEAD 实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | 迁移前编号文档 `docs/protocol-designs/123-arp-design.md` | 已迁入本目录；其内容与 D-ARP-1、T-ARP-1…12、当前 JSON 交叉校正 | **迁移完成**（本版为协议目录权威副本） |
| 2 | D-ARP-1 文件清单："protocol/arp/{layer_gen.go 新,**arp.go Planner 保留**}"；"main.go 翻转（:538 legacy→NewChainPlanner，**非空导入→空白**）" | 实测：生产注册只有 `main.go:563 RegisterPlanner(layers.NewChainPlanner("arp"))` + `main.go:21` 空白导入；legacy `arp.NewPlanner()` 全仓唯一调用点 = `api/rest/flowcontrol_integration_test.go:51`（**测试**） | **一致 ✓**（生产路径 = ChainPlanner）；但 legacy `arp.go` 的 `Plan/buildARPPacket/buildARPReply` 因此成为**生产不可达代码**（40 个 testpoint 测试全部测的是 legacy 面，§11.7 / G-ARP-2） |
| 3 | D-ARP-1 门1 表 §5 行："ValidateARPSpec IP/MAC 格式锚" | `layer_gen.go:145-167` 实测 4 分支：`arp: invalid sender_ip %q` / `arp: invalid target_ip %q` / `arp: invalid sender_mac %q` / `arp: invalid target_mac %q` | **一致 ✓**（4 锚词全在 T-6/T-9/T-10/T-11 执法） |
| 4 | D-ARP-1 裁定 5："mapToFlowSpec 不填伪四元组（isL2OnlyProtocol+=arp）……spec 面诚实（空 IP/0 端口）" | `strategy_convert.go:336-343` 实测：`SrcIP/DstIP = defaultL2String(…def="")`、`SrcPort/DstPort = defaultL2Port(…def=0)`；但 `SrcMAC/DstMAC = defaultMAC(cfg, "src_mac", DefaultSrcMAC)` **不经 l2Only 门** → 无 eth 层显式 MAC 时 spec 仍带 `02:00:00:00:00:01/02` 框架默认 MAC | **MAC 行与"诚实空"声明有半面出入**：MAC 不是端口，框架默认 MAC 保留是 goose 同款既有口径（生成器 `firstNonEmpty` 链消费它），非缺陷；本版 §5 按代码如实钉（§8 注记） |
| 5 | D-ARP-1 裁定 3 勘误："legacy op=2 仍发'请求形广播帧'（buildARPPacket 硬编码广播）字节错位——重建修正" | `layer_gen.go:59-61` 实测：op=2 发**单播宣告**（ether dst=senderMAC）；legacy `arp.go:101-103` 仍硬编码 `DstMAC: "ff:ff:ff:ff:ff:ff"` 且 op 可变 | **一致 ✓**（勘误已落 layer_gen）；legacy 侧的错位帧保留在生产不可达代码里（G-ARP-2） |
| 6 | T-ARP 清单标题 "§T-ARP-1…12 arp 层链收敛……P5 8/8 ×2 + 修轮 +4 例后 12/12 ×2" | `cases/arp.json` 机读实测 **12 例**（T-1…T-12；ef3bfb5 建 T-1…8，c7f6dec 修轮补 T-9…12）；`trafficgen/docs/protocol-pcap-test/arp.md` 逐例表 12 行 | **一致 ✓**（12/12，本版 §2 逐条对齐） |
| 7 | `trafficgen/docs/protocol-pcap-test/arp.md`："Cases: 12 — pass 12, fail 0, error 0"；4 处链接 `(arp/<id>.pcap)`、8 处空链接 `[pcap]()` | `trafficgen/docs/protocol-pcap-test/arp/` **目录不存在**（0 个 pcap 文件，`*.pcap` gitignored `.gitignore:88`）；末次提交 `c7f6dec`（**2026-09-22**）**晚于**判死提交 `0417be5`（2026-09-13） | **pass 数字可查但 pcap 留档断链**——不属 opcua G-OPCUA-10 的"过期产物"口径（提交晚于判死），属 telnet G-TELNET-3 同款"**pcap 未留档 + 死链**"，列 G-ARP-1；本车道**未跑**该套件（4 份正例 pcap 取自 `/tmp/mcp-pcaps/arp/` 系 P5 落盘副本，2026-09-27 mtime），不以任何形式引用该产物作为"今日已跑" |
| 8 | D-ARP-1 修轮 L3："FlowID 不设（下游仅日志/透传面）……不补 FlowID（无消费面，YAGNI）" | `layer_gen.go:80-92` `emitARP` 只设 Direction/L2/L4/Payload；L2-only 发射分支（`chain_planner.go:1341-1375`）不回填 FlowID/PacketIndex/Timestamp（对照 LDP/openwire 自驱分支 `:1469-1488` 有回填）；`internal/output/` 零消费 `FlowID`（grep 实测）；pcap writer `ts.IsZero()` → `time.Now()` 兜底（`pcap.go:154-156`） | **一致 ✓**（YAGNI 裁定延续）；as-built 事实登记：arp 两帧 PacketIndex 恒 0、pcap 时间戳 = 落盘时刻（`internal/core/layer_dyn.go` 无关）——无断言面受影响，登记不立项（§14 注记行） |
| 9 | D-ARP-1 裁定 6 B′："gratuitous ARP 不单列（oper=2 形可承载同等语义）" | RFC 语义：gratuitous ARP（自宣告）正统形 = **oper=1** 且 spa==tpa（tshark `arp.isgratuitous`/`arp.isannouncement` 可判，实测 51 字段在册）；本实现 oper=2 是"对端宣告"，与 spa==tpa 自宣告**不是同一 wire 形状** | **表述收窄**：oper=2 形承载的是"对端宣告"语义，**不能**替代 spa==tpa 形；gratuitous 自宣告形今日不可表达（spa/tpa 均可配但无语义联动，配出即是一条普通 request）→ 缺口立项（§4 / G-ARP-6 口径修正） |
| 10 | D-ARP-1 §3 五件套行 "validateSpecBase :613 / :1056 发射分支" | HEAD 实测：L2-only 豁免在 `chain_planner.go:861-863`；L2-only 发射分支在 `chain_planner.go:1341-1375`；EtherTypeARP 固写在 `:1367` | **行号漂移**（后续提交增行所致），事实一致；本版 §11.1 按 HEAD 行号 |

**依赖链判定纪律**：以上均为可判题（旧文→代码/pcap 二级对照），直接判定，不问偏好。**不可判的**（tshark `arp.isgratuitous` 等派生位对 our pcap 的取值是否与 RFC 826 判定语义一致）标"待确认"并写清确认方式（G-ARP-7）。

## 1. 范围、profile 与实现状态边界

本版定义 **ARP（RFC 826）以太网二层直载**的流量生成：`[eth, arp]` 链，28 字节定长报文，op=1 请求/应答自动配对、op=2 单发宣告。

**L2-only 显式声明（§4 地址与流层的协议级前提）**：ARP **没有 L3/L4 载体**——报文直接骑在以太头后（EtherType 0x0806，RFC 826 spec 报文格式图），无 IPv4/IPv6 头、无 TCP/UDP 头、无端口。理由：①ARP 的功能本身是"解析 L3 地址→L2 地址"的邻接层协议，发生在 IP 装配之前；②wire 上不存在 L3 头可断言（实测 pcap `frame.protocols = eth:ethertype:arp`，无 `ip` 段）。因此：框架 `isL2OnlyProtocol`（`strategy_convert.go:231-237`）收录 arp（goose/sv/arp/isis 四协议），`mapToFlowSpec` 对 arp **不填**伪四元组（src_ip=""/dst_ip=""/src_port=0/dst_port=0，`:336-343`），`validateSpecBase` 对 arp **直接放行**（无 IP parse/端口必填检查，`chain_planner.go:861-863`）——**顶层的 src_ip/dst_ip/src_port/dst_port 键对本协议无语义**（写了即 CheckProtoFlat 五键判死，§7 N-系）。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `arp_pair_v1`（主） | Ethernet（EtherType 0x0806） | op=1 缺省或显式 → 广播请求 + 单播应答 2 帧 | 真实网关行为（是否真的有 10.0.0.2 这台机器） |
| `arp_announce_v1` | 同上 | op=2 → 单发单播宣告 1 帧（对端角色） | 真实 NIC 对宣告的处理 |

显式边界（"不实现、不声称、不许静默转换"）：① **不实现 gratuitous ARP 自宣告形**（oper=1 + spa==tpa）——字段虽可配出该字节面，但无语义联动、无用例、无断言（G-ARP-6）；② **不实现 RARP/InARP**（oper 3/4/8/9，属 RFC 903/RFC 2390 他协议，D-ARP-1 裁定 6）；③ **不实现代理 ARP**（跨网段代答是转发面行为，非报文变体）；④ **IPv6 不适用**——ARP 的 ptype 恒 0x0800（IPv4，`layer_gen.go:100` 固写），IPv6 走 NDP（RFC 4861）非本协议；层内写 IPv6 文本会被 `putIP` 的 `To4()` 拒（`arp: invalid sender_ip %q: want IPv4`，§7）；⑤ 不实现 VLAN tag 的 arp 层内声明——VLAN 走链上 `vlan` 层（框架通用路径），arp 层自身无 VLAN 键；⑥ 不实现ARP 缓存表/重传/超时语义（RFC 826 的 Packet Reception 状态描述是接收端行为，生成器只产帧）。

**实现状态（2026-09-29 实测）**：`arp` 层已注册（`registry.go:1295`，`CategoryTerminal`，`DependsOn ["eth"]`，**Fields 5 键**）；生成器/校验器已落码（`internal/protocol/arp/` 两文件 **438 行**：`layer_gen.go` 172 / `arp.go` 266 legacy）；`allowedProtocols["arp"]=true`（`protocols.go:22`）；层内 translate 已接线（`chain_planner_translate.go:1044`）；L2-only 五件套全接（§11.1）；12 语义用例已落 `cases/arp.json`；`coverage_gate.py check_arp` 已登记（22 项，**22/22 绿** 本车道实测）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`eth.dst/src/type`、`arp.opcode`、offset 14 frames）；NIC 经 `port_group` 输出（框架通用）；不设仅单路径可用的断言。**网卡实测未跑**（D-ARP-1 性能行如实登记"pcap 路验收，网卡未跑"，本版延续该口径）。

## 2. 协议栈、帧布局和固定偏移

层链：**`[eth, arp]`**（唯一合法链形）。`DependsOn ["eth"]`（`registry.go:1295`）——引擎自动补 eth；链含 `ip`/`tcp`/`udp` 即判死（V-carrier 通用门，§7 N-3）。ARP 报文是**以太帧载荷本体**，不是任何传输层的数据。

端口：**不适用**（L2-only 无端口概念；`validateBaseDstPortHandled` 名单含 arp，`chain_planner.go:758`——dst 端口 0 合法；src 端口 worker 递增被 `HasExplicitSrcPort` 恒真跳过，`strategy_convert.go:363-365`）。

固定偏移（**偏移基 = 帧首**——L2-only 族与 L3 族的核心差异：ARP 体紧跟 14B 以太头，无 +54 的 IP 头跨距）：

| 帧 | 长度 | 说明 |
|---|---:|---|
| 以太头 | 14 | dst 6 + src 6 + EtherType 2（恒 `08 06`） |
| **ARP 体** | **28** | 起点 **offset 14**（§3.1 逐字段） |
| 零填充 | 18 | **IEEE 802.3 最小帧 60B**（`MinEthernetFrame`，`builder.go:109-113`；42 < 60 → pad 到 60，`builder.go:330-332`） |
| **帧总长** | **60** | 实测 pcap `frame.len=60`（4/4 例一致，含填充） |

> 偏移基=帧首的实证锚：T-2 帧 1 断言 `offset 14 = 00 01 08 00 06 04 00 01`（htype 起）——若按 L3 族口径（+54）断言必然红；tshark 解析 `frame.protocols = eth:ethertype:arp`（无 `:ip:` 段）双向证明无 L3 头。历史教训（P5 首轮 3 例钉红）正是把 28B 体首误标 offset 54/32 所致。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`）：

```json
{
  "layers": [
    {"eth": {"src_mac": "aa:bb:cc:dd:ee:01", "dst_mac": "aa:bb:cc:dd:ee:02"}},
    {"arp": {"operation": 1, "sender_ip": "10.0.0.1", "target_ip": "10.0.0.2"}}
  ]
}
```

多流样例（数量只走 `strategy_fc`；四元组不存在，**动态逃生口 = eth 层 MAC 写动态对象**——`eth.src_mac/dst_mac` 在 allowlist（`layer_dyn.go:21`），静态 MAC + flows>1 会被静态复制门判死，§7 N-8）：

```json
{
  "layers": [
    {"eth": {"src_mac": {"strategy": "inc", "range": ["02:00:00:00:00:01", "02:00:00:00:00:02"], "step": 1}, "dst_mac": "ff:ff:ff:ff:ff:ff"}},
    {"arp": {}}
  ],
  "strategy_fc": {"type": "flows", "value": 2}
}
```

> 多流样例为**目标形状声明**（今日 12 例零正例多流，T-12 只执法静态拒），A′ 候选（§13）。

## 3. 线格式编码（逐字段标注 RFC 826 出处；偏移相对帧首）

### 3.1 ARP 报文（28 字节定长，RFC 826 报文格式图；`BuildARPBody`，`layer_gen.go:97-118`）

| 帧偏移 | 体偏移 | 字段 | 尺寸 | 值 | 端序 | 代码 |
|---:|---:|---|---:|---|---|---|
| 14–15 | 0–1 | htype（Hardware Type） | 2 | **0x0001**（Ethernet，固写） | **大端** | `layer_gen.go:99` |
| 16–17 | 2–3 | ptype（Protocol Type） | 2 | **0x0800**（IPv4，固写） | **大端** | `:100` |
| 18 | 4 | hlen（Hardware Address Length） | 1 | **0x06**（MAC，固写） | — | `:101` |
| 19 | 5 | plen（Protocol Address Length） | 1 | **0x04**（IPv4，固写） | — | `:102` |
| 20–21 | 6–7 | oper（Operation） | 2 | 1=request / 2=reply | **大端** | `:103-104` |
| 22–27 | 8–13 | sha（Sender Hardware Address） | 6 | 可配 MAC | 原始字节序 | `:105-107` |
| 28–31 | 14–17 | spa（Sender Protocol Address） | 4 | 可配 IPv4 | 原始字节序 | `:108-110` |
| 32–37 | 18–23 | tha（Target Hardware Address） | 6 | 可配 MAC | 原始字节序 | `:111-113` |
| 38–41 | 24–27 | tpa（Target Protocol Address） | 4 | 可配 IPv4 | 原始字节序 | `:114-116` |

**长度公式**：`帧长 = 14（以太头）+ 28（ARP 体）`，不足 60 补零至 **60**（§2）。ARP 体恒 **28 字节定长**（hlen/plen 固写 6/4，无变长段）。

**htype/ptype/hlen/plen 四字段固写不可配**（registry 无对应键）：协议本身钉死 Ethernet/IPv4/MAC/IPv4 四元形状（D-ARP-1 裁定 6 "IPv4 单一协议面"）。oper 取值域 [1,2]（V9，§7 N-1）；**显式 0 = "用缺省"放行**（`complete.go:318-323` 显式 0 ≠ 缺失口径），生成器 0→1（§5）。

### 3.2 地址编解码与拒绝（`putMAC`/`putIP`，`layer_gen.go:120-140`）

| 输入 | 解析 | 失败锚词 |
|---|---|---|
| MAC 文本 | `net.ParseMAC` + len==6 检查 | `arp: invalid sender_mac %q: want 6-byte MAC` / `arp: invalid target_mac …`（`:121-127`） |
| IPv4 文本 | `net.ParseIP` + `To4()` + len==4 | `arp: invalid sender_ip %q: want IPv4` / `arp: invalid target_ip …`（`:129-140`） |

**两级防线（诚实声明）**：① 层校验器 `ValidateARPSpec`（`layer_gen.go:145-167`）用 `net.ParseIP`/`net.ParseMAC` 做**格式**门（非空才查）——`net.ParseIP("2001:db8::1")` **成功**，故 IPv6 文本**通过**层校验器；② 构造期 `putIP` 的 `To4()` 失败 → `want IPv4` 错误（Generate 中止 → task error）。即：**IPv6 文本在 task-time 构造期被拒，锚词仍是 `invalid sender_ip`/`invalid target_ip`**（前缀同族，`error_contains` 子串判定两路都命中）。MAC 格式错（如 `zz:bb:…`/`nope`）在层校验器即拒（`ParseMAC` 同函数）。

### 3.3 以太帧头（`finalEmit` L2-only 分支，`chain_planner.go:1341-1375`）

| 帧偏移 | 字段 | 值 | 代码 |
|---:|---|---|---|
| 0–5 | dst | 逐帧生成器给定（§5）；arp 层无显式 ether 键时 l2For 补（`pkt.L2.SrcMAC==""` 分支，`:1346-1351`） | `layer_gen.go:51/56/60` 实参 |
| 6–11 | src | 同上 | 同上 |
| 12–13 | EtherType | **恒 0x0806**（分支固写 `:1366-1368`，覆盖生成器已设值） | `core.EtherTypeARP`（`builder.go:15`） |
| 14+ | payload | 28B ARP 体 + pad | builder 通用装配 |

L3 **清空**（`pkt.L3 = core.L3Config{}`，`:1371`）——builder 因此跳过 IP 头装配；L4.Protocol 恒 `"arp"`（`:1372`，仅元数据，不产字节）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明 operation 与可选地址覆盖，引擎按固定剧本产出 1–2 帧；无握手挥手无会话（L2-only），tcp/udp 层不存在。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 地址解析问询（最常见） | 广播"谁有 tpa" → 单播回"我是 tha" | #1（`arp_t1_baseline_pair`） |
| ② 线格式取证（28B 整格） | 同①，字节全钉 | #2（`arp_t2_bytes_full`） |
| ③ 显式地址覆盖（跨网段模拟） | 四地址全显式 → sha/spa/tha/tpa 双钉 | #3（`arp_t3_explicit_addrs`） |
| ④ 单发宣告（对端角色应答面） | op=2 单帧单播 | #4（`arp_t4_single_reply`） |

**五层覆盖逐层结论**：

- **功能层**——oper 两值正例齐（op=1 配对 #1、op=2 单发 #4）；错误处理 8 类负例各至少一条（值域/格式×4/载体/presence/静态复制，§7）；28B 字节面整格钉（#2）。
- **性能层**——**定长协议**：28B 体恒定、帧恒 60B（pad），无分段/重组/MSS 概念（无传输层，显式不适用）；帧数天花板 = 2 帧/流（op=1）；多流行为由 `strategy_fc` 承载（T-12 负例执法静态拒；正例多流 A′ 立项）。性能验收参数见 §6。
- **数据场景层**——四地址字段值域：显式 MAC/IPv4（#3）、缺省（#1）、非法格式拒（#6/#9/#10/#11）、IPv6 文本构造期拒（§3.2，A′ 补例）；oper：1/2/缺省/3 拒（#5）；V9 显式 0 放行面（§3.1 注）。
- **地址与流层**——**IPv4/IPv6 双覆盖要求显式不适用**：ARP 无 IP 载体层（本节开头声明）；协议自身的地址面是 ptype=0x0800 **IPv4-only**（IPv6 走 NDP，§1 边界④）。**流关联（控制流派生数据流）显式不适用**：ARP 是单帧对等问询，无子流/副连接概念；**多会话显式不适用**：无连接协议，arp 层无 `sessions` 键（registry 5 键实测）；多流由策略级 `strategy_fc` 承载（正例 A′）。
- **业务层**——四场景全部有落点；**多事务 = 不适用**（无连接无事务概念，一次问询即全部语义）；**现网复合场景**：真实网络中 ARP 与 IP 流量交织（先问后连），属编排面（链上再加 tcp 层即拒绝——载体混入判死），本协议层内无交织面，如实声明。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① gratuitous ARP 自宣告形（oper=1+spa==tpa，G-ARP-6）；② RARP/InARP（他协议，oper 3/4/8/9 在本层 = V9 区间拒）；③ 代理 ARP（转发面行为）；④ VLAN 标记帧（链上 vlan 层框架路径，arp 层零断言，A′ 候选）；⑤ ARP 缓存表/重传（接收端语义）。

## 5. 消息/事务模型与状态机

**事务定义**：op=1 → **一个配对事务**（request up + reply down，2 帧）；op=2 → **一个单发事务**（announce down，1 帧）。**多事务 = 不适用**（无连接，一次配置即一次问询）。

arp 层无自有状态机（RFC 826 的 Packet Generation/Reception 两段是**接收端**行为表，生成器只产帧不维护缓存表）：生成是**纯函数**（配置 → 1–2 帧，无跨包状态，`layer_gen.go:32-62` 无任何可变字段）。

| 阶段 | 产出帧 | 方向 | 代码 | 用例 |
|---|---|---|---|---|
| op=1 请求 | 帧 1：ether src=senderMAC → dst=**ff:ff:ff:ff:ff:ff**（广播）；oper=1，sha=senderMAC，spa=senderIP，**tha=00:00:00:00:00:00**（全零），tpa=targetIP | up | `layer_gen.go:49-54` | #1/#2/#3 |
| op=1 应答 | 帧 2：ether src=targetMAC → dst=senderMAC（单播）；oper=2，**角色互换**：sha=targetMAC，spa=targetIP，tha=senderMAC，tpa=senderIP | down | `layer_gen.go:55-58` | #1/#3 |
| op=2 宣告 | 单帧：ether src=targetMAC → dst=senderMAC（单播）；oper=2，对端角色（sha=targetMAC/spa=targetIP/tha=senderMAC/tpa=senderIP）——**裁定 3 勘误**：legacy 此形发广播错位帧，重建修正 | down | `layer_gen.go:59-61` | #4 |

**事件序（`Generate`）**：`op==1`：帧 1 → 帧 2 顺序 emit；`op!=1`（即 2 或缺省 0→1 前的显式 2）：单帧 emit。**无其它自动派生**（不补 gratuitous、不补重传）。

**service 选择**：无（单 oper 开关，无服务清单概念——对照 opcua 四分支）。

**自动派生规则（逐条，不依赖隐含知识）**：① `req.Meta.ARP == nil` → `&core.ARPConfig{}`（空层零值，`layer_gen.go:36-39`）；② `op == 0` → **OperationRequest(1)**（`:40-43`）——显式 0 与缺省同语义（V9 放行 0 的配套）；③ `senderMAC = firstNonEmpty(arp.sender_mac, spec.SrcMAC, "aa:bb:cc:dd:ee:01")`（`:44`）——spec.SrcMAC 来自 eth 层 `extractLayerMACs`（`strategy_convert.go:696-702`，**arp 层 sender_mac 优先于 eth 层推导**，#3 实证 ether src 与 sha 双钉）；④ `targetMAC = firstNonEmpty(arp.target_mac, spec.DstMAC, "aa:bb:cc:dd:ee:02")`（`:45`）；⑤ `senderIP = firstNonEmpty(arp.sender_ip, "10.0.0.1")`、`targetIP = firstNonEmpty(arp.target_ip, "10.0.0.2")`（`:46-47`，**IP 无 eth 层可推导，常量兜底**）；⑥ `tha` 请求帧恒全零（`:51-53` zeroMAC 传参）；⑦ EtherType 恒 0x0806 由发射分支固写（§3.3）。

**确定性**：同一配置必然同帧序同字节（无随机源、无时间戳入线、无 map 迭代序依赖——`emitARP` 参数全显式）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流 ≤2 帧（op=1；op=2 单帧）；帧恒 **60B**（14+28+18 pad，IEEE 802.3 最小帧）；无分段/重组概念（无传输层）；无并发流内共享状态（纯函数）。吞吐数字待 P4 基准，**本版不写承诺**。
- **依据**：帧序列直发（`Generate` 逐帧 `req.Emit`，无缓冲聚合）；每帧内存 = 60B 常量；无锁（常量+局部变量）；发射 channel 256（链框架通用）。
- **验收两路（§6.3 强制）**：pcap（`/tmp/mcp-pcaps/arp/`，正例 `<id>.pcap` / 负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，框架 `port_group`）共用同一断言集；断言实际 `eth.dst/src/type`、`arp.opcode`、frames 原始 hex 与包数，不只断言"任务没报错"。**网卡路今日未跑**（D-ARP-1 如实口径延续）。
- **六类场景落点（§6.6）**：基线（#1，2 帧）/ 目标规模（op=1 配对即最大）/ 压力上限（**无**——定长协议，帧数天花板 2，如实声明）/ 长时间运行（不适用，无周期语义）/ 并发交错（多流 A′ 立项）/ 背压（`packet_count` 精确计数守卫帧数漂移 + 60B 帧长守卫 pad 面漂移）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须被拒并传播为 task error（或 create-time 400），不得产出成功 PCAP 或假成功（8 负例实测 pcap 均 0 帧）：

| # | 负例 ID | 故障输入 | 锚词（代码逐字） | 代码锚点 | 时机 |
|---:|---|---|---|---|---|
| N-1 | `arp_t5_neg_operation` | `operation=3` | `out of range [1,2]` | `complete.go:325`（V9 registry Min1/Max2） | create-time（400） |
| N-2 | `arp_t6_neg_sender_ip` | `sender_ip="not-an-ip"` | `invalid sender_ip` | `layer_gen.go:151` | task-time（validator） |
| N-3 | `arp_t7_neg_ip_carrier` | 链 `[eth, ip, arp]` | `must not have an ip/transport carrier` | `complete.go:342-357`（V-carrier 通用门，DependsOn eth 自动获得） | create-time（400） |
| N-4 | `arp_t8_neg_presence` | `layers + 顶层 arp:{}`（**空 map 也死**） | `no longer accepts a top-level arp` | `strategy_convert.go:9096-9111`（rawWrapChains `"arp": "[eth,arp]"`） | create-time（400） |
| N-5 | `arp_t9_neg_sender_mac` | `sender_mac="zz:bb:cc:dd:ee:01"` | `invalid sender_mac` | `layer_gen.go:158` | task-time（validator） |
| N-6 | `arp_t10_neg_target_mac` | `target_mac="nope"` | `invalid target_mac` | `layer_gen.go:163` | task-time（validator） |
| N-7 | `arp_t11_neg_target_ip` | `target_ip="999.0.0.1"` | `invalid target_ip` | `layer_gen.go:154` | task-time（validator） |
| N-8 | `arp_t12_neg_static_copy` | eth 层静态标量 MAC + `strategy_fc flows=2` | `static four-tuple` | `schema/semantic.go:198/285`（checkLayerChainStaticCopy，**eth 在扫描面** `:214`） | create-time（400） |

**负例原子性**：每例单一故障注入；单次执行不得混注。8 例 `expect` 键集合 = **严格两键** `{expect_error, error_contains}`（机读实测 8/8，与 opcua 的含-notes 形不同——本协议存量即合规）。

**presence 负例形状（CORE_MEMORY presence-negative-case-shape 口径，必须点名）**：N-4 的形状是**层链 + 顶层空子映射并存**（`{"layers":[…],"arp":{}}`）——这是**判死执法对象**，不是旧键残留。收官自查口径"非负例顶层键 = 0"在 arp 上**今日成立**（11 非负例顶层仅 `{layers}`，§12.1）。

**可达但未入例的拒绝分支（A′ 立项，不得冒充已覆盖）**：

| 分支 | 锚词 | 代码行 | 说明 |
|---|---|---|---|
| IPv6 文本入 sender_ip/target_ip | `invalid sender_ip`（构造期 `want IPv4` 后缀） | `layer_gen.go:133-137` | 层校验器 `net.ParseIP` 放行 v6 → 构造期 `To4()` 拒；**两段式**，§3.2 |
| 顶层五键扁平（src_ip 等） | `no longer accepts flat config field src_ip` | `strategy_convert.go:8635-8637` | 全协议通用五键门；arp 无专用例 |
| htype/ptype 面不可配 | — | 固写 | 无配置入口 = 无拒绝分支（如实，非缺口） |

**不得误报的合法协议事件**：`operation` 缺省/显式 0（→1，§5）；`arp:{}` 空层（合法缺省，#1/#2 即证）；ether 层 MAC 与 arp 层 sender_mac 并存（层键优先，#3）；IPv4 广播地址 255.255.255.255 入 tpa（`ParseIP`+`To4` 合法，照发——语义由用户负责）；`flows>1` + eth MAC 动态对象（**合法逃生口**，§2 多流样例）。

## 8. 边界

- **帧长**：ARP 体恒 28B；以太帧恒 60B（42+18 pad）。**pad 字节零**（tshark `Padding: 0000…` 实测）。
- **oper**：V9 [1,2]；显式 0 放行→生成器 1；3+ 拒；`uint16` 类型负值/浮点/超界 → V9 "not a numeric value" 系拒（`complete.go:308-313`，今日无例 → A′）。
- **地址**：MAC 恒 6B（`ParseMAC` len 检查）；IP 恒 4B（`To4` 检查）；四地址全部可配、全部可缺省。
- **帧数公式**：`packet_count = 2 if oper∈{缺省,1} else 1`（无握手挥手；L2-only 无 FIN/RST 面）。
- **端口**：不适用（0 值，worker 递增被跳过）。
- **多流**：`strategy_fc {"type":"flows"}` 承载；静态 MAC + flows>1 判死（N-8）；动态 eth MAC 为唯一逃生口（allowlist `layer_dyn.go:21`）。
- **spec 面半面注记（D-ARP-1 校正 #4 延续）**：L2-only 门只护 IP/端口（空/0）；`spec.SrcMAC/DstMAC` 在无 eth 层显式值时保留框架默认 `02:00:00:00:00:01/02`（`strategy_convert.go:342-343` defaultMAC 不经 l2Only 门）——生成器经 `firstNonEmpty` 消费它，行为正确；仅"spec 面全空"的表述对该两键不成立，如实登记不立项。
- 不得产生回绕长度或超量分配（28B 定长 `make([]byte, 28)` 一次分配）。

## 9. 原子 ID 与完成定义（12 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 | packet_count（实测） |
|---:|---|---|---|---:|
| 1 | `arp_t1_baseline_pair` | 正 | §5：op=1 缺省配对（广播问+单播答） | 2 |
| 2 | `arp_t2_bytes_full` | 正 | §3.1：28B 五段整格字节钉 | 2 |
| 3 | `arp_t3_explicit_addrs` | 正 | §5：四地址显式覆盖（层键优先） | 2 |
| 4 | `arp_t4_single_reply` | 正 | §5：op=2 单发宣告（勘误形） | 1 |
| 5 | `arp_t5_neg_operation` | 负 | §7 N-1：oper=3 区间拒 | —（0 帧） |
| 6 | `arp_t6_neg_sender_ip` | 负 | §7 N-2：sender_ip 格式拒 | —（0 帧） |
| 7 | `arp_t7_neg_ip_carrier` | 负 | §7 N-3：IP 载体混入拒 | —（0 帧） |
| 8 | `arp_t8_neg_presence` | 负 | §7 N-4：顶层 presence 判死 | —（0 帧） |
| 9 | `arp_t9_neg_sender_mac` | 负 | §7 N-5：sender_mac 格式拒 | —（0 帧） |
| 10 | `arp_t10_neg_target_mac` | 负 | §7 N-6：target_mac 格式拒 | —（0 帧） |
| 11 | `arp_t11_neg_target_ip` | 负 | §7 N-7：target_ip 格式拒 | —（0 帧） |
| 12 | `arp_t12_neg_static_copy` | 负 | §7 N-8：静态复制拒 | —（0 帧） |

**包数公式**：`oper∈{缺省,1} → 2`；`oper=2 → 1`。校验：#1–#3 op=1 → 2 ✓；#4 op=2 → 1 ✓。**4/4 与实测 pcap 帧数逐例一致**（机读 + tshark 双向复核，本车道 audit_arp.py）。

**断言形状基线（机读实测）**：4 正例 `expect` 键 = `{packet_count, fields, frames}`（notes 已从 cases JSON 移入本文 §3，避免机器契约混入非断言键）；断言总量 = **20 frames + 8 fields**（6+5+6+3 / 4+1+1+2），逐条经 `audit_arp.py` 对生成器语义模型复算（20/20 + 8/8 全对）+ tshark 实测 pcap 复核。

### 9.1 tshark 字段通道（实测，2026-09-29）

本机 tshark **3.6.14** 有 arp dissector：`tshark -G fields` 中 `arp.*` 唯一字段 **51 个**（`awk` 实测）。实测可用性（对本车道 4 份 pcap 逐字段验证）：

| 通道 | 字段 | 形态 | 实测 |
|---|---|---|---|
| ① | `arp.opcode` | 十进制串（`1`/`2`） | **已用**（8 断言中 3 条） |
| ② | `arp.hw.type` / `arp.proto.type` | 十进制 / `0x0800` hex 串 | **可用未用**（实测 `1` / `0x0800`） |
| ③ | `arp.hw.size` / `arp.proto.size` | 十进制 | **可用未用**（实测 `6` / `4`） |
| ④ | `arp.src.hw_mac` / `arp.src.proto_ipv4` / `arp.dst.hw_mac` / `arp.dst.proto_ipv4` | 冒号小写 hex / 点分十进制 | **可用未用**（实测值与 sha/spa/tha/tpa 逐字节一致） |
| ⑤ | `eth.dst` / `eth.src` / `eth.type` | 冒号小写 hex / `0x0806` | **已用**（各 3/1/1 条 = 5 条） |
| ⑥ | `arp.isgratuitous` / `arp.isannouncement` / `arp.isprobe` | 布尔派生位 | **待确认**（dissector 派生语义 vs RFC 826 判定一致性未逐条核对，G-ARP-7） |
| ⑦ | frames `offset/hex` | 原始字节 | 12 例主断言通道（**offset 基 = 帧首 14**，§2） |

> **A′ 立项依据（G-ARP-4）**：12 例今日只用 `arp.opcode` + `eth.*` 4 个字段名；通道 ②–④ **9 个字段实测可用但零使用**。这不是"被迫"（dissector 在案且字段有效），是**未收编**。`arp.isgratuitous` 族须先过 G-ARP-7 确认再收编。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | 无连接：以太直载（EtherType 0x0806）；request=链路层广播，reply=单播（RFC 826 spec 首段） | 场景①–④ | `DependsOn ["eth"]` 单值（`registry.go:1295`）；op=1 自动配对 / op=2 单发（`layer_gen.go:49-61`） | 无 |
| 2 | 命令/消息表 | oper=1 request / 2 reply（spec 报文格式图）；RARP/InARP（3/4/8/9）属他协议（RFC 903/2390） | 场景①④ | `ARPConfig.Operation` 单键 + V9 [1,2] | RARP/InARP 缺口立项（裁定 6） |
| 3 | 状态机 | 无状态；request/reply 靠 spa/tpa、sha/tha 角色互换绑定（无显式关联 ID） | 场景① | op=1 配对帧 2 角色互换（§5）；生成纯函数 | 无 |
| 4 | 字段表 | 28B = htype2+ptype2+hlen1+plen1+oper2+sha6+spa4+tha6+tpa4（spec 报文格式图逐字段） | 数据场景层 | `BuildARPBody` 逐字段（§3.1）；htype/ptype/hlen/plen 固写 | 固写四面无配置入口（如实，非缺口） |
| 5 | 错误处理 | oper 非法拒；地址格式非法拒 | 负例 N-1…N-8 | V9 区间 + validator 4 锚 + V-carrier + presence + 静态复制（§7） | IPv6 文本构造期拒未入例（A′） |
| 6 | 超时与活性 | 不适用（无重传/保活语义——RFC 826 无计时器字段） | — | 无保活代码 | **显式不适用**（如实） |
| 7 | NAT/代理/被动 | 不适用（无端口无连接） | — | 无端口面 | **显式不适用**；代理 ARP 缺口立项 G-ARP-6（转发面） |
| 8 | 版本/方言 | RFC 826（1982）单一标准；gratuitous/probe 是**行为模式**非报文变体（spa==tpa / spa==0 字节面） | — | 单版；自宣告形不可表达（§0 #9 校正） | gratuitous/probe 形不可表达 → G-ARP-6（缺口立项 G-ARP-6） |

**八项重数**：8 行逐行判定 = **已覆 5**（#1/#2/#3/#4/#5）+ **不适用 3**（#6 超时活性 / #7 NAT 被动 / #8 版本方言——单标准无方言面，gratuitous 缺口归 G-ARP-6 不折进本行）。5 + 3 = 8 ✓

### 10.2 子表①：消息 × 终态矩阵（oper 两形 × 3 列）

| 消息形 | T1 正常终态 | T2 配置拒绝 | T3 传输异常终态（RST 类） |
|---|---|---|---|
| op=1 配对（request+reply） | 已覆（#1/#2/#3） | 已覆（N-1 代表，oper 值域拒；N-2…N-8 为地址/链面拒） | **不适用**（L2-only 无 RST 概念——以太帧无传输层异常终态，如实） |
| op=2 单发宣告 | 已覆（#4） | 同上（oper 值域拒共享 N-1；地址拒 N-5…N-7 与消息形无关——两形同一构造路径） | 不适用（同上） |

**逐格重数**：2 行 × 3 列 = 6 格——已覆 **4**（T1 列 2 + T2 列 2）/ **不适用 2**（T3 列 2），零空格。4 + 2 = 6 ✓
（T2 列按"代表已覆"计：8 负例覆盖配置面全域，与消息形正交，不逐格重复计。）

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

| # | 变体 | 落点 |
|---:|---|---|
| 1 | op 缺省（→1） | 覆（#1/#2/#3） |
| 2 | op=1 显式 | A′ 立项（`{"operation":1}` 显式形今日无用例——#1 用 `{}`，值等价但**键路径未走**） |
| 3 | op=2 | 覆（#4） |
| 4 | op=0 显式（V9 放行→1） | A′ 立项（`complete.go:318-323` 有分支，今日无用例） |
| 5 | op=3（拒） | 覆（#5） |
| 6 | op 非数值（浮点/负值，V9 not-numeric 拒） | A′ 立项（`complete.go:308-313` 有分支，今日无用例） |
| 7 | 全缺省地址（{}） | 覆（#1/#2） |
| 8 | 四地址全显式 | 覆（#3） |
| 9 | sender_ip 非法 | 覆（#6） |
| 10 | target_ip 非法 | 覆（#11） |
| 11 | sender_mac 非法 | 覆（#9） |
| 12 | target_mac 非法 | 覆（#10） |
| 13 | IPv6 文本入 sender_ip（构造期拒） | A′ 立项（§3.2 两段式，今日无用例） |
| 14 | arp 层 sender_mac 覆盖 eth 层 | 覆（#3，ether src + sha 双钉） |
| 15 | eth 层缺席（单层 `[arp]`，eth 自动补） | A′ 立项（`completeDeps` 有路径，今日 12/12 显式写 eth） |
| 16 | eth 层 MAC 框架默认（`02:00:00:00:00:01`） | A′ 立项（`defaultMAC` 缺省链今日无用例，§8 半面注记） |
| 17 | `[eth, ip, arp]` 载体混入（拒） | 覆（#7） |
| 18 | 顶层 arp presence（拒） | 覆（#8） |
| 19 | 静态 MAC + flows=2（拒） | 覆（#12） |
| 20 | 动态 eth MAC + flows=2（合法多流） | A′ 立项（§2 多流样例目标形，今日零正例） |
| 21 | 顶层五键扁平（src_ip 等，拒） | A′ 立项（五键通用门今日 arp 无专用例） |
| 22 | VLAN 层 + arp（`[eth, vlan, arp]`） | A′ 立项（框架通用路径，arp 层零断言面，先探针后立项） |
| 23 | gratuitous 自宣告形（oper=1+spa==tpa） | **缺口立项 G-ARP-6**（G-ARP-6，§0 #9） |

**重数**：23 行逐行判定 = **已覆 13**（#1、#3、#5、#7–#12、#14、#17–#19）+ **A′ 立项 9**（#2、#4、#6、#13、#15、#16、#20–#22）+ **缺口立项 G-ARP-6 1**（#23）。13 + 9 + 1 = 23 ✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 局域网地址解析问询（RFC 826 §Packet Generation 用例） | #1 | 已覆 |
| 2 | 网关应答（对端角色） | #1 帧 2 / #4 | 已覆 |
| 3 | 网络取证/教学（28B 帧格式演示） | #2 | 已覆 |
| 4 | 跨网段/定制地址模拟 | #3 | 已覆 |
| 5 | 自由宣告（gratuitous ARP，RFC 5227 语义前身） | — | **缺口立项 G-ARP-6**（G-ARP-6：自宣告形 oper=1+spa==tpa 无语义联动；oper=2 是对端宣告非自宣告） |
| 6 | 地址冲突探测（probe，spa=0 形） | — | **缺口立项 G-ARP-6**（同上，spa=0 可配但无探测语义断言面） |
| 7 | 反向解析（RARP，RFC 903） | — | **缺口立项 G-ARP-6**（他协议） |
| 8 | 逆向解析（InARP，RFC 2390） | — | **缺口立项 G-ARP-6**（他协议） |
| 9 | 代理 ARP（跨网段代答） | — | **缺口立项 G-ARP-6**（转发面行为非报文变体） |
| 10 | IPv6 邻居解析（NDP，RFC 4861） | — | **缺口立项 G-ARP-6**（他协议，ptype 0x86DD 面） |

**重数**：10 行 = **已覆 4** + **缺口立项 G-ARP-6 6** = 10 ✓ 无映射无确认即缺口——本表零未决。

### 10.5 三路对照与候选方案对比

三路：① **规范原文**（RFC 826，定"必须是什么"——报文格式图 28B 字段序与 Packet Generation/Reception 两段；本轮已用它校正 D-ARP-1 的 gratuitous 语义表述，§0 #9）；② **商业化软件实际行为**（**抓包级已到**：tshark 3.6.14 对 4 份 pcap 的解码结果与 §3.1 字段表逐字段一致；**未取到**：真实网关/主机的 ARP 应答字节样本 → G-ARP-7 待确认）；③ **可靠开源实现思路**（Linux `arping` 的配对语义——request 广播 tha 全零 + reply 单播，与本实现 §5 一致，无新信息）。

三路一致点：28B 字段序、大端 oper、request 广播+tha 全零、reply 单播+角色互换。**不一致点**：① tshark `arp.isgratuitous` 派生位与 RFC 826 无该字段（dissector 增强语义）——收编前须确认（G-ARP-7）；② legacy op=2 广播形已被勘误（§0 #5，历史分歧已闭）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | L2-only 终结层 `[eth, arp]`（本版；goose/sv/isis 同构先例） | 28B 字节面复用 legacy 构造（裁定 1），编排/校验重建；代价 = 一套层（已落码 172 行） | **采用**（D-ARP-1 裁定 1–5） |
| B | legacy `arp.Planner` 直发 | op=2 广播错位（勘误对象）、零校验、无层链 → 已被 `main.go:563` 翻转弃用 | **否决**（生产不可达，§11.7） |
| C | raw-IP `[ip, arp]` 链 | 违反 RFC 826 无 IP 头语义；V-carrier 门判死（N-3 即执法证据） | **否决**（D-ARP-1 裁定 5） |

## 11. P2 D-ARP-1 代码设计（CORE_MEMORY §8 八要素；已验收 = as-built 定稿）

> 状态说明：实现已落码（`internal/protocol/arp/` 两文件），本 P2 条目为文档轨对既有实现的**逆向定稿**（as-built），作为后续改动的唯一入口；行号为 HEAD 实测（2026-09-29）。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/protocol/arp/layer_gen.go` | **生产路径**：`Generator`（L2-only 终结层，Generate+req.Emit，GenEvents=nil）+ `BuildARPBody`/`putMAC`/`putIP` + `ValidateARPSpec` + `init()` 注册（生成器+校验器） | 172 |
| `trafficgen/internal/protocol/arp/arp.go` | **legacy 生产不可达**：`Planner.Validate/Plan` + `buildARPPacket/buildARPReply`（op=2 广播错位历史面）+ `DefaultTTL` 死常量 | 266 |
| `trafficgen/internal/protocol/arp/arp_test.go` | legacy 面单测 5 个 `Test*` | 172 |
| `trafficgen/internal/protocol/arp/arp_testpoints_test.go` | legacy 面测试点 40 个 `Test*`（枚举面 `dns_icmp_arp.md` 反推） | 544 |
| `trafficgen/internal/core/layers/arp_chain_test.go` | 链级红例 4 个 `Test*`（配对/单发/显式地址/validator 锚——**生产路径测试**） | 169 |
| `trafficgen/internal/core/types.go`（`:2396-2406`） | `ARPConfig{Operation, SenderMAC, SenderIP, TargetMAC, TargetIP}` + `FlowSpec.ARP` 槽位（`:1695`） | —（共享文件） |
| 接线 8 处 | registry（`layers/registry.go:1295`，5 键）/ translate（`chain_planner_translate.go:1044`）/ 扁平 parse（`strategy_convert.go:926`）/ isL2Only（`:231`）+ rawWrapChains（`:9100`）/ protocols 准入（`protocols.go:22`）/ dst 端口豁免（`chain_planner.go:758`）/ L2-only validateSpecBase 豁免（`:861`）+ 发射分支（`:1341`）/ main（`main.go:21` 空白导入 + `:563` 注册） | — |

### 11.2 接口签名

- `ValidateARPSpec(s core.FlowSpec) error`（`layer_gen.go:145`）：`c==nil` 通过（空层缺省合法）；4 分支 §7 N-2/N-5/N-6/N-7；**不查 oper 值域**（V9 管辖，注释 `:143-144` 明写）。
- `(*Generator).Generate(ctx, req) error`（`layer_gen.go:32`）：`req==nil || req.Emit==nil` → `arp generator: invalid request`（防御分支，链路径不可达——Emit 恒非 nil）；op 语义 §5。
- `BuildARPBody(oper uint16, sha, spa, tha, tpa string) ([]byte, error)`（`:97`）：28B 一次分配；4 put 拒绝锚 §3.2。
- `(*Planner).Validate/Plan`（`arp.go:35/57`）：legacy 面，生产不可达（§11.7）。
- 生成器：`Name() "arp"`（`:29`）；`GenEvents()` 恒 nil（`:30`，L2-only 路由依据）。

### 11.3 数据结构

`ARPConfig{Operation uint16, SenderMAC, SenderIP, TargetMAC, TargetIP string}`（`types.go:2398-2405`，5 键；JSON tag `operation/sender_mac/sender_ip/target_mac/target_ip`）。

### 11.4 主流程

**create**：schema `ValidateStrategy` → `CheckProtoFlat`（五键 + rawWrapChains presence，`semantic.go:128-133`）→ `ValidateLayers`（V1/V4/V7/V7b/V9：V-carrier 拒 `[eth,ip,arp]`、V9 拒 oper 出 [1,2]、动态 allowlist 关业务键）→ `checkLayerChainStaticCopy`（`semantic.go:142`，flows>1 + 静态 eth MAC 拒）→ 400 或入库。

**任务**：`mapToFlowSpec`（`strategy_convert.go:330`：isL2Only → IP/端口空/0；`extractLayerMACs` 层 MAC 回填 spec）→ worker（`HasExplicitSrcPort` 恒真跳过端口递增）→ `ChainPlanner.ValidateSpec`：`validateSpecBase`（arp 豁免）→ `translateTerminalConfig` case `"arp"`（`chain_planner_translate.go:1044-1071`：`spec.ARP==nil` 时 5 键手工映射，空层→零值配置非 nil）→ `protocolValidator`（=`ValidateARPSpec`）→ `Plan` → L2-only 发射分支（`chain_planner.go:1341`：EtherTypeARP 固写 + L3 清空 + L4.Protocol）→ builder（L2 + 28B payload + pad 60）→ writer（PCAP/NIC）。

### 11.5 错误分支

create-time 3 门（V-carrier/V9/presence + 静态复制 = 4 门）+ task-time validator 4 分支，全部传播为 400/task error（8 负例实测 0 帧，零假成功）。构造期 `putMAC/putIP` 4 分支为 validator 同族背门（层校验器先火，构造期锚带 `: want IPv4`/`: want 6-byte MAC` 后缀——**子串锚仍命中**，§3.2）。

### 11.6 性能边界

见 §6（纯函数直发、60B 定长、无共享状态；吞吐待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- **legacy 双轨残留**：`arp.go` `Planner` 与 `layer_gen.go` `Generator` 同包并存，**op=2 语义相反**（legacy 广播错位 vs layer 单播宣告）、`Validate` 锚不同（`ARP config is required` vs 层校验 4 锚）。生产注册只有 ChainPlanner（`main.go:563`）；`arp.NewPlanner()` 唯一调用点 = REST 集成测试（`flowcontrol_integration_test.go:51`）。45 个 legacy `Test*` 测的是生产不可达面 → **G-ARP-2**（测试力气错配 + 同包双语义误用风险；处置=代码轨裁定删除或标注，本车道不碰 .go）。
- `DefaultTTL = 64`（`arp.go:14`）**零使用**（grep 全仓仅定义行）→ 死常量，归 G-ARP-2。
- `CheckProtoFlat` **有 arp 分支**（rawWrapChains，`strategy_convert.go:9100`）——与 opcua G-OPCUA-1 不同，presence 门在案（N-4 即执法证据）。
- **顶层未知游离键无通用门**：`{layers:[…], bogus: 1}` 今日不判死（`CheckProtoFlat` 只查五键 + 各协议子映射白名单）→ 该形状负例若建会真绿 = 假通过，**不建**（G-ARP-9，与 opcua/telnet 同款框架面）。
- 动态 allowlist（`layer_dyn.go`）：`eth` 2 键开（src_mac/dst_mac）；`arp` **零业务行**（grep 实测零命中）→ 5 业务键对象即 `does not support dynamic`。见 §12.12。
- registry 5 键无 Default、无 FieldContract（L2-only 无端口契约可声明）——与生成表 `schemas/v1/generated/layers.generated.json` 逐键一致（机读实测，127 层同代）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert `layer_gen.go` + 接线 8 处（registry/protocols/translate/convert×3/chain_planner×2/main）；`arp.go` legacy 面独立存在无接线。cases 回滚 = 恢复 12 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：11/12 例顶层 = `{layers}` 唯一键（零残留）；T-8 = `{layers,arp}` presence 判死负例（故意形状）；目标形见 §2 样例且**存量已达标**（本协议无迁移工作量） | §12.1；`cases/arp.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 arp 流量模板（层链 + oper/地址）；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：**L2-only 单流协议豁免声明**（无会话/端口/子流）+ 事务序/关联/插入位置/时间线四要素 | §12.3 + §5 |
| §4 查规范 | RFC 826 报文格式图 + Packet Generation/Reception 两段 + tshark 3.6.14 `arp.*` 51 字段 + 4 例实测 pcap + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["eth"]` 单值（`registry.go:1295`）；create-time 4 门 + task-time 4 锚；失败传 task error（8 负例 0 帧实测） | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；60B 定长；帧数公式；pcap/NIC 两路验收明写，网卡路未跑如实） | §6 |
| §7 三份文档 | `docs/protocols/arp/{design,testcase}.md` v1.0.0（本版）+ D-ARP-1（`CODE_DESIGN.md`，已验收）+ T-ARP-1…12（`TEST_CASES.md`，已验收）+ 12 例 JSON | 修订记录 |
| §8 设计先行 | D-ARP-1 P1/P2 定稿（2026-09-22，1f61887 随批）先于 P5 用例（ef3bfb5）与修轮（c7f6dec） | `CODE_DESIGN.md` 状态行 + git 历史 |
| §9 测试三源 | 三源 = RFC 826（§10）+ D-ARP-1（§11）+ tshark 3.6.14 字段与 **4 份正例 pcap 实测**（本车道逐帧复核，§9 表）；12 ID 逐项回指；存量审计去向 testcase §8 | `docs/protocols/arp/testcase.md` §2/§5/§8 |
| §10 评审闭环 | D-ARP-1 每阶段对抗自重审 + 收官隔离复审（PASS-WITH-FINDINGS 5 findings 全处置，`CODE_DESIGN.md` 修轮块）+ 本车道 P1–P3 自审（testcase §10） | 自审日志 |
| §11 白话 | 本文首节白话一句 | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：**L2-only 四元组=不适用**，MAC 面经 eth 层全开；业务 5 键逐个列关 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `arp` 已在 `registry.go:1295` 注册（**不新增层**）；生成表同代（5 键逐键一致机读实测）；**若改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `arp.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/arp/`；**网卡路未跑**（如实） | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/arp.json` | 12 | **`{layers}` ×11** + `{layers,arp}` ×1（T-8 presence 判死负例） | `[eth,arp]` ×11 + `[eth,ip,arp]` ×1（T-7 拒例） | **8/8 = 严格两键** `{expect_error, error_contains}` |

**旧键去向表（§15.3 要求"每个键写去向"）**——本协议 P4/P5 直接以层链形落例（无扁平存量例，`git log --follow cases/arp.json` = ef3bfb5 首建即层链形）：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 本协议**从未用过顶层地址**（L2-only 无 IP 面；写了即五键门判死） |
| `src_port` / `dst_port` | **0** | 不适用（L2-only 端口面不存在） |
| `src_mac` / `dst_mac` | **0** | MAC 真相住 eth 层（`extractLayerMACs` 唯一消费路径，CORE_MEMORY 1.11） |
| `count` | **0** | 数量走 `strategy_fc`（T-12 用 `flows=2`） |
| 顶层 `arp` 子映射 | **1**（T-8 负例） | **判死执法对象**（rawWrapChains `"arp": "[eth,arp]"`；**presence 形状须点名**：非残留，是故意坏配置） |
| `flow_control` / `strategy_fc` | **1**（T-12，case 顶层） | 合法数量键（`strategy_fc {"type":"flows","value":2}`；**必须放 case 顶层**，放 spec_json 内不触发静态门——T-12 首跑红例实录，`semantic.go:142` 只看 config 顶层） |

**结论**：**本协议存量 11 非负例顶层零残留**——§1 门的动作 = ①无旧键可删；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测 11/11 仅 `{layers}`）；③A′ 新增例全部沿用纯 layers 形（§13）。目标形状样例见 §2。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"arp":{}}` **今日会被拒**（rawWrapChains arp 行，`strategy_convert.go:9100`）→ **T-8 已建且真红** ✓（与 opcua 的 G-OPCUA-1 相反——本协议该门在案）。
- ② 白名单外游离键判死（`unknown field`）今日**无通用门** → **不建**（建了会真绿 = 假通过），缺口 G-ARP-9。
- ③ 8 负例每条带锚词（已齐，§7）。
- ④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套（L2-only 单流协议豁免声明 + 四要素）

**豁免声明**：arp 是**无连接 L2 单流协议**——无 TCP/UDP 会话概念、无端口、无子流派生、无 `sessions[]`（registry 5 键实测无该键）、无多事务。CORE_MEMORY §3"会话表"对本协议**降维**为"流表"，豁免理由：RFC 826 无会话语义可挂（问-答即全部生命周期）。**以下四要素照写不空**：

- **流表**：`f1` 单流基线（#1/#2/#3/#4，各自 eth MAC 对，1–2 帧即完整流）/ `f2` 多流展开（**今日零正例**；目标形 = `strategy_fc flows=N` + 动态 eth MAC，§2 样例；静态 MAC + flows>1 判死 = T-12）。
- **事务序列**：op=1 → `t1` 请求（up 广播，tha 全零）→ `t2` 应答（down 单播，角色互换）；op=2 → `t1` 宣告（down 单播）。每事务四件事（前置=层校验过、触发=Generate、成功=帧落 pcap、失败=4 锚任一）见 §5/§7。
- **关联关系**：request↔reply 靠**字段角色互换**绑定（spa/tpa、sha/tha 互换，无显式关联 ID——RFC 826 spec 原文如此）；**无派生流**（诚实声明：无控制流/数据流之分，`driven_by` 不适用）。
- **插入位置**：终结层（`[eth, arp]`，L2-only 族第 4 协议）；发射分支固写 EtherTypeARP + 清 L3（`chain_planner.go:1366-1372`）；**链内含 ip/tcp/udp 即判死**（V-carrier，N-3）。
- **时间线**：帧 1 → 帧 2 严格序（`Generate` 顺序 emit）；**无交错**（无 `concurrent` 概念）；多流为串行整块回放（框架 worker 语义）；帧间无时间间隔语义（pcap 时间戳 = 落盘时刻，`pcap.go:154-156` 兜底，§0 #8）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组=不适用**（L2-only 无 ip/tcp/udp 层）；**MAC 面等价物 = `eth.src_mac`/`eth.dst_mac` 两键全开**（allowlist `layer_dyn.go:21` 实测 `"eth": {"src_mac": true, "dst_mac": true}`）——逐流 MAC 变体经 `parseLayerDyn`（`layer_dyn.go:161-165` eth 分支）→ `resolveLayerTuple`（`:879-888` genMAC 逐流落 spec.SrcMAC/DstMAC）→ 生成器 `firstNonEmpty`（`layer_gen.go:44-45`）消费。**arp 业务 5 键全关**（allowlist 无 `arp` 行，grep 实测零命中；对象即 `does not support dynamic`）：

| 业务键 | 关的理由（family 口径：逐流变破坏协议语义） |
|---|---|
| `operation` | 消息形选择器（1/2 二值，逐流变无意义） |
| `sender_mac` / `target_mac` | 主机身份（arp 层键与 eth 层重复承载，动态面已由 eth 层提供——双门并存会歧义） |
| `sender_ip` / `target_ip` | 协议解析目标（问询对象身份，逐流变 = 扫描语义；若需多目标应走多流多策略） |

**序号算法实读**：`parseLayerDyn`（`layer_dyn.go:78`，eth 分支 `:161`）/ `resolveLayerTuple`（`:770`，eth 段 `:879-888`）/ 保底自增（`strategy_convert.go:49` DefaultSrcPort——**arp 被 `HasExplicitSrcPort` 恒真跳过** `:363-365`，端口递增不适用于本协议）/ allowlist 白名单（`layer_dyn.go:14-23`）——**`arp` 无业务块**（grep 实测零命中）。

## 13. P3 对接清单（T-ARP 草稿输入；正文落 testcase 文件）

12 ID（4 正 + 8 负）+ 包数/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。**A′ 候选 9 例**：

| # | 候选 ID | 覆盖 | 依据 |
|---:|---|---|---|
| 1 | `arp_t1b_op_explicit` | `{"operation":1}` 显式形（键路径区分） | §10.3 #2 |
| 2 | `arp_t4b_op_zero` | 显式 `operation:0`（V9 放行→1） | §10.3 #4 |
| 3 | `arp_t5b_op_nonnum` | op 浮点/负值（V9 not-numeric 锚） | §10.3 #6 |
| 4 | `arp_t6b_ipv6_text` | IPv6 文本入 sender_ip（构造期 `want IPv4`） | §10.3 #13 |
| 5 | `arp_t13_min_chain` | 单层 `[arp]`（eth 自动补全） | §10.3 #15 |
| 6 | `arp_t14_default_mac` | eth 层无 MAC（框架默认 `02:00:…` 面） | §10.3 #16 |
| 7 | `arp_t15_flows_dyn` | 动态 eth MAC + flows=2（正例多流） | §10.3 #20 |
| 8 | `arp_t16_flat_fivekey` | 顶层 `src_ip` 五键门（arp 专用例） | §10.3 #21 |
| 9 | `arp_t17_vlan_chain` | `[eth, vlan, arp]` 探针例（先探针定断言面） | §10.3 #22 |

**另 2 类 B′（框架面，不单独立项）**：顶层游离键通用门（G-ARP-9，等框架级 unknown-key 白名单，禁加单协议黑名单分支）/ `arp.isgratuitous` 族字段收编（G-ARP-7 确认后归 G-ARP-4 的 A′）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-ARP-1 | **结果产物 pcap 留档断链 + 陈旧负例遗留**：`trafficgen/docs/protocol-pcap-test/arp.md`（tracked）写 "Cases: 12 — pass 12, fail 0, error 0"，末次提交 `c7f6dec`（2026-09-22）**晚于**判死提交 `0417be5`（2026-09-13）——**不属** opcua G-OPCUA-10"过期产物"口径；但 `docs/protocol-pcap-test/arp/` **目录不存在**（0 个 pcap，`*.pcap` gitignored），文档 4 处 `(arp/<id>.pcap)` 链接全断（8 处负例空链接）。本车道未跑该套件，4 份正例 pcap 系 P5 落盘副本（`/tmp/mcp-pcaps/arp/`，2026-09-27 mtime）逐帧复核一致。**附注**：同目录 `arp_t12_neg_static_copy.neg.pcap`（176B/2 帧，mtime 2026-09-22 12:53，早于修轮提交 12:57）系首跑红例时代（strategy_fc 放置修正前）的**陈旧遗留**，与今日 create-time 拒语义矛盾——**不得作为证据引用**，重跑时清理 | **代码阶段**（P5 重跑套件后落盘 pcap 目录、重生成产物、清理陈旧负例文件）；本版**不删不改**（tracked 产物 + /tmp 探针面）；在此之前读者不得据此判断 pcap 可查（口径同 telnet G-TELNET-3，与 G-OPCUA-10 **明确区分**） |
| G-ARP-2 | **legacy 双轨残留**：`arp.go` 266 行（Planner/Plan/buildARPPacket/buildARPReply + 死常量 `DefaultTTL`）生产不可达（唯一注册点=REST 测试 `flowcontrol_integration_test.go:51`）；op=2 与生产语义**相反**（广播 vs 单播宣告）；45 个 legacy `Test*`（716 行）测的是死面——生产路径仅 `arp_chain_test.go` 4 测试覆盖 | **代码轨**（裁定删除 legacy 文件或显式标注 deprecated；本车道不碰 .go）。在此之前读者不得把 `arp.go` 注释当生产语义（裁定 3 勘误以 layer_gen 为准） |
| G-ARP-3 | **正例覆盖面窄**（4/12）：oper 显式 1 形、oper=0 形、op 非数值拒、IPv6 文本拒、单层 `[arp]` 自动补全、框架默认 MAC、动态 MAC 多流正例、五键门 arp 例、VLAN 链——**今日零用例**（§10.3 立项 9 行 + §13 A′ 9 例） | A′ 补例（§13 清单） |
| G-ARP-4 | **tshark 通道未收编**：`arp.hw.type/proto.type/hw.size/proto.size/src.hw_mac/src.proto_ipv4/dst.hw_mac/dst.proto_ipv4` 8 字段实测可用（§9.1），12 例今日只用 `arp.opcode`+`eth.*` 4 字段名（8 断言）。不是被迫，是未收编 | A′ 收编：#2 五段断言可全部转 field 通道（帧长断言留 frames）；`isgratuitous` 族先过 G-ARP-7 |
| G-ARP-5 | **静态复制门指引文案不含 eth**：`semantic.go:285` 锚词后缀 "Write the varying field as a dynamic object inside its layer (**ip.src/ip.dst, tcp/udp src_port/dst_port**)"——对 L2-only 用户（唯一合法动态面是 eth MAC）是**错误指引**（照写 ip/tcp/udp 层会被 V-carrier 拒） | **框架面**（B′）：文案补 eth.src_mac/dst_dst_mac；本车道不碰 semantic.go；T-12 断言不受影响（锚词 `static four-tuple` 前缀不变） |
| G-ARP-6 | **gratuitous/probe 自宣告形不可表达**：oper=1+spa==tpa（gratuitous）/spa=0（probe）无语义联动无断言面；D-ARP-1 裁定 6 "oper=2 形可承载同等语义"经 RFC 对照**不成立**（§0 #9 校正：oper=2 是对端宣告，wire 形状不同） | **缺口立项 G-ARP-6**（单帧自宣告非本生成器场景）；若未来实现须新增 `announce_mode` 类键 + `arp.isgratuitous` 断言（先过 G-ARP-7） |
| G-ARP-7 | **tshark 派生位语义未核对**：`arp.isgratuitous/isannouncement/isprobe/duplicate-address-*` 是 dissector 增强字段（RFC 826 无此字段），对本实现产物的取值语义是否与 RFC 5227 判定一致未逐条核对；真实网关 ARP 应答字节样本未取到 | **待确认**：抓真实网关 ARP 交互对照 tshark 派生位，或逐条读 Wireshark packet-arp.c 判定式；确认前不收编该族、不声称 `arp.isgratuitous` 断言可用 |
| G-ARP-8 | **正例 `notes` 键**：4 正例 expect 曾含 `notes`；已从 cases JSON 删除，说明已移入 testcase §3 | **已关闭**：4 正例键集合现为 `{packet_count, fields, frames}` |
| G-ARP-9 | **顶层未知游离键无通用门**：`{layers:[…], bogus: 1}` 今日不判死 → 该形状负例建了会真绿 = 假通过 | **不建该负例**（等框架级 unknown-key 白名单）；与 opcua G-OPCUA-1 / telnet G-TELNET-14 同款；**禁加单协议黑名单分支** |
| 注记（不立项） | FlowID/PacketIndex/Timestamp 不回填（L2-only 分支 + 生成器均不设；下游零消费，`pcap.go:154` 时间戳兜底 time.Now）——D-ARP-1 修轮 L3 YAGNI 裁定延续 | 如实登记；无断言面受影响 |

## 15. 修订记录

- v1.0.0（2026-09-29）：批次二文档车道 P1–P3，**as-built 定稿**（由迁移前编号文档迁入协议目录）。§0 逐条校正 **10 项**（含 D-ARP-1 gratuitous 语义表述收窄、legacy 双轨生产不可达实证、pcap 留档断链登记、行号漂移 2 处；7 项核对一致）。存量 12 例机读审计（顶层键分布 11+1、严格两键负例 8/8、断言总量 20 frames+8 fields）；**20+8 断言逐条经 audit_arp.py 对生成器语义模型复算全对** + 4 份正例 pcap tshark 逐帧复核（60B pad 面实证）；包数公式 oper 二值与实测 4/4 一致；tshark 3.6.14 `arp.*` **51 字段**实测 + 通道可用性分级（§9.1，A′ 立项 G-ARP-4）；偏移基=帧首专节钉死（§2，L2-only 族核心差异）；五层覆盖逐层展开 + 不适用显式声明（§4）；门1 十四行 + §12.1/§12.3/§12.12 强制展开 + 12-P2；D-ARP-1 as-built 定稿（§11）；缺口 G-ARP-1…G-ARP-9 + 注记行。自审 3 轮（audit_arp.py 机读复核含脚本自身 2 处 bug 修正），末轮干净。

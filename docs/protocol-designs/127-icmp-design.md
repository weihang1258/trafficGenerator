# #127 icmp（ICMP · RFC 792，IPv4 承载 Protocol 1）设计契约

> 版本：v1.0.0（批次二文档车道，as-built 型）
> 日期：2026-09-29
> 车道：批次二文档轨（协议编号 #127）
> 旧基线：**无独立设计稿**——`docs/protocol-designs/` 下无 `NN-icmp-*` 稿（`ls | grep -i icmp` 零命中实测）。文档基线 = ①**内部契约 D-ICMP-1**（`docs/CODE_DESIGN.md:3681`，#33 P-PIPE 2026-09-22 已验收：af02651 P4 / 1b4e440 P5 / c79aae5 P6 / 8621e64 修轮，含修轮块六发现与处置）；②结果产物 `trafficgen/docs/protocol-pcap-test/icmp.md`（tracked，**末次提交 `1b4e440` 2026-09-22 晚于判死提交 `0417be5` 2026-09-13 → 非过期产物**，但其指向的 pcap 目录缺失，G-ICMP-8）；③T-ICMP-1…8（`docs/TEST_CASES.md`）。本 #127 为 **as-built 逆向定稿**（§0 逐条校正）。
> 存量用例：`trafficgen/test/protocol_pcap/cases/icmp.json`（**8 例 = 4 正 + 4 负**，已机读实测；spec_json 顶层键 7/8 纯 `{layers}`，t7 为 presence 负例形状（含顶层 `icmp` 键=判死语义必含）；链形 `[ip,icmp]` ×8）
> 规范基线：① **RFC 792**（INTERNET CONTROL MESSAGE PROTOCOL，1981-09；报文格式/Type-Code 表/Echo 语义，下称 **spec**；本车道 2026-09-29 拉取原文核对 Type/Code/checksum 措辞）；② **RFC 1071**（校验和算法：逐 16 位反码和 + 折返 + 取反）；③ **RFC 1122** §3.2.2 / RFC 1812 §4.3.3.1（扩展 Code——**本车道未拉原文逐条核对，标待确认 G-ICMP-13**）；④ **RFC 4443** §2.3 + RFC 8200 §8.1（ICMPv6 伪首部校验和，姊妹协议对照面）；⑤ IANA Protocol Numbers（**ICMP = 1**）；⑥ 本机 tshark 3.6.14 `icmp.*` 字段表（`-G fields` 实测：`icmp.type/code/checksum/checksum.status/ident/ident_le/seq/seq_le` 等）；⑦ 本仓库落码（`internal/protocol/icmp/` 两文件 + 接线五件，§11）；⑧ 内部契约 D-ICMP-1（历史层）
> 白话一句：**"网络世界的嘀一声"——发一问（Echo Request，type 8），对端原样回一声（Echo Reply，type 0）；问与答靠两个 16 位数配对：Identifier 是"哪一轮对话"，Sequence 是"第几下"。报文 = IPv4（协议号 1）头后直接跟 8 字节 ICMP 头（type/code/校验和/标识/序号）+ 一段数据；校验和罩住**整个报文**（IPv4 无伪首部）。引擎里它是 raw-IP 终结层：没有端口、没有握手，一个 ping 就两帧。**

## 0. 基线校正与实测声明（门1 必答：基线继承关系）

本 #127 无前序独立设计稿，校正对象为"内部契约 + 结果产物 + 代码事实"三级，全部可判题（文档/代码/探针实测对照），直接判定，不问偏好。

| # | 旧基线说法 | HEAD/探针实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | `docs/protocol-designs/` 有 icmp 设计稿 | `ls docs/protocol-designs/ \| grep -i icmp` **零命中** | **不存在**；本 #127 为 icmp **首份独立设计契约**；唯一前序文档 = CODE_DESIGN.md 内部契约 D-ICMP-1（P-PIPE 交付，非独立稿） |
| 2 | D-ICMP-1 七裁定（线面复用/层形状/编排/validator/五件套/B′ 账本/回滚） | 七裁定逐条对 HEAD 复核：layer_gen.go 包装直传（:30-53）/6 键 [ip,icmp]（registry.go:1324）/两路编排（icmp.go:137/209）/三锚 validator（layer_gen.go:64-73）/五件套接线（§11.7）/B′ 账本（§3.4）/独立包回滚 | **全部仍成立**；本版 §11 为 as-built 逆向定稿，裁定文本升级为逐字段契约 |
| 3 | T-ICMP-1…8（TEST_CASES.md）与 cases 的 ID 对应 | `cases/icmp.json` 8 例 id = `icmp_t1_smoke…icmp_t8_neg_static_copy`，与 T-ICMP-1…8 **一一对应、顺序一致**（机读实测） | 一致；本版 §9 以 cases JSON ID 为权威 |
| 4 | 结果产物 `protocol-pcap-test/icmp.md` "Cases: 8 — pass 8"（**8/8 全绿**） | 该文件 tracked、末次提交 `1b4e440`（**2026-09-22，晚于**判死提交 `0417be5` 2026-09-13）→ **不落入过期产物口径**；但其正例 4 条 pcap 链接指向 `icmp/icmp_*.pcap`，而 `docs/protocol-pcap-test/icmp/` **目录不存在**（`git ls-files` 计 0 行） | **8/8 未经今日复跑证实 + pcap 产物缺失**（rtsp G-RTSP-6 口径，**非** pcep G-PCEP-11 过期口径）→ G-ICMP-8 |
| 5 | D-ICMP-1 P5 验收"suite 8/8 ×2 全绿、反查 18/18" | 反查 18/18 **今日复跑仍绿**（`python3 tools/coverage_gate.py icmp` 实测 18 项全 PASS）；8/8 为 **MCP 路径**验收（strategy create 过 schema 门）；**离线链执行器直调引擎路径实测 6/8**——t7/t8 两负例在引擎直调路径失守（`expected generation error, got success`，layer_chain_suite_test.go:331），因为两门只挂在 schema create-time | **两门的真实拦截面 = create-time（schema 400）**；本协议权威执行器 = MCP suite；引擎直调缝 → G-ICMP-4 |
| 6 | D-ICMP-1 修轮块 M1/M2/L2 处置 | M1 live 库清账（对账 0/0）与 M2 红例⑤⑥（icmp_chain_test.go:124/151）在案；L2 天花板声明（无连接 2 帧面 9.50/9.53 N/A）在 CODE_DESIGN | 处置均落地；三教训（live 库对账/防双换过滤面/分支专属红例）承入 §5.3/§11.4/§13 |
| 7 | "icmp 不映射 file_source（③ C 类）"（registry 注释） | registry Fields 6 键无 `file_source`；translate 不映射（chain_planner_translate.go:1141）；flat parse 仍读 `file_source`（strategy_convert.go:1562，判死后 MCP 不可达）；单测面 6 例保留（icmp_filesource_test.go） | 事实成立；**该单测面在链路径不可达**，今日不得声称"层链可配文件载荷" → G-ICMP-5 |
| 8 | （本车道探针新发现）| ①`[ip,icmp]`+IPv6 地址 → 静默产 2 帧 EtherType 0x86dd + NextHeader=1（族混不拒）；②`[ip,{tcp\|udp},icmp]` 夹层链 → **静默 0 包无错**（isRawIPChain 返回 false → 事件分支 → `GenEvents()`=nil）；③pattern step `code≠0` → **validator 放行并上包**（仅步 type 受检）；④type=0 显式单发 1 帧/pattern 混型步/空 pattern 回退——三条合法路径均无套件用例 | ①②③ 为**新发现缺口**（G-ICMP-1/2/3）；④ 合法路径零套件覆盖（G-ICMP-9）；全部今日探针实证 |

**依赖链判定纪律**：以上均为可判题（内部契约→代码行/探针三级对照），直接判定。RFC 1122 §3.2.2 扩展 Code 的逐条出处未拉原文核对，标待确认（G-ICMP-13）。

**D-ICMP-1 三教训承入本契约（隔离复审实录，写作纪律）**：
1. **P6 清库对账必须打 live 库**（服务端 cwd 相对路径 DB；repo 根库是冻结旧谱系）——本车道不碰库，该纪律约束的是代码阶段 P5/P6。
2. **Generator 防双换强制全包 Direction="up" 后，任何断言/测试不得按 Direction 过滤方向**（Direction 恒 "up" 无判别力）——本契约 §7 断言面与覆盖反查门建议行均不含 direction 断言；方向语义改由业务字节（payload[0]=type）与 L3 地址互换承载。
3. **新增分支必须有本协议专属红例**，不能靠同族协议测试顺带覆盖——本契约把"今日链级红例（单测面）在案、套件面零覆盖"的分支逐条列入 G-ICMP-9/10。

## 1. 范围、profile 与实现状态边界

本版定义 **ICMP Echo 探测面（RFC 792 type 8/0）承载于 IPv4（Protocol=1）** 的流量生成：单 ping（req+auto-reply）与 Pattern 多轮 ping。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `icmp_echo_v1`（主） | IPv4 直载（ip.proto=1，raw-IP 链） | 单 ping：Echo Request + 自动 Echo Reply（2 帧）；type=0 单发（1 帧） | 真实内核回包语义（回包是引擎自产） |
| `icmp_pattern_v1` | 同上 | 多轮：`pattern[]` 步序贯发射，type=8 步自动配对 reply；步级 type/code/sequence/data | 交错/并发调度（步序恒串行） |

显式边界（"不实现、不声称、不许静默转换"）：① **非 Echo 型 ICMP 不编排**（type 3/4/5/11/12/13/14/15/16 及扩展码——层 validator 直接拒，§3.4 规范面列出仅供参照，G-ICMP-6）；② **IPv6 载体不实现**（v6 域 = icmpv6 层 D-ICMPV6-1；但**族混今日不拒**，探针实证静默产无效帧，G-ICMP-2）；③ **无 TCP/UDP 语义**（无端口、无握手挥手、无 FIN/RST——validateSpecBase 端口豁免，`[ip,{tcp,udp},icmp]` 夹层今日静默 0 包，G-ICMP-3）；④ `file_source` 层链不可达（registry 无该键，translate ③ C 类不映射，G-ICMP-5）；⑤ ICMP 差错报文的"引用原始数据报"体（IP header + 64 bits）不实现。

**实现状态（2026-09-29 实测）**：`icmp` 层已注册（`registry.go:1324`，`CategoryTerminal`，`DependsOn ["ip"]`，FieldContract `ip.protocol=1`，Fields 6 键）；planner/generator 已落码（`icmp.go` 338 行 + `layer_gen.go` 85 行，`wc -l` 实测）；`allowedProtocols["icmp"]=true`（`protocols.go:43`）；层内 translate 已接线（`chain_planner_translate.go:1133`）；main.go 翻转注册（`main.go:562`）+ 空导入（`:75`）；生成表 **127 层**中 `icmp` 条目与 registry 逐键一致（`schemas/v1/generated/layers.generated.json` 机读实测）；8 例落 `cases/icmp.json`，反查 18/18 今日仍绿。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`icmp.type/ident/seq`、`ip.proto/src`、offset 34/42 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。raw-IP 无连接：`has_handshake`/`terminates` 断言对 icmp **不适用**（存量 8 例实测均未使用）。

## 2. 协议栈、端口和固定偏移

层链为 `[ip, icmp]`（引擎自动补 `ip`；最小链即 `[ip,icmp]`，icmp 层 `DependsOn ["ip"]` 强制）。ICMP 报文是 IPv4 payload 的一部分，**没有独立 L4 头**：`L4.Protocol="icmp"` 在 builder 里 `l4Length` 返回 0、`writeL4` 无分支（`builder.go:946-961/1285-1299`）——整个 ICMP 报文（8B 头+data）作为 Payload 直接跟在 IPv4 头后。**"无端口"≠"无承载"：ip.protocol=1 由两处钉死**——registry FieldContract `{"ip.protocol": "1"}`（IPPROTO_ICMP）与生成侧 `core.L3Base(…, 1, …)`（icmp.go:166/230 第三参）。

**端口：结构上不适用**。`mapToFlowSpec case "icmp"` 显式清 `spec.SrcPort/DstPort = 0`（strategy_convert.go:920-925，防 stale 值干扰）；`validateSpecBase` raw-IP 端口豁免（chain_planner.go:996）+ `validateBaseDstPortHandled` 含 icmp（:758）。框架多流注入的 `12345+i`（worker.go:308）对 icmp **线上不可见**（无 L4 头可写）——多流可区分性只能来自 ip.src 动态（§12.12）。

**固定偏移**（IPv4 无 options、无 VLAN 时）：**每帧 ICMP 头起点 = 帧偏移 34**（eth 14 + ip 20）；头内字段按 §3.1 递推；**Echo data 起点 = 42**（8 字节头后）。若误配 IPv6 地址（族混，G-ICMP-2）则 v6 头 40B → 载荷起点 54，且 NextHeader=1（无效组合）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**存量 7/8 例已是此形**，t7 为 presence 负例特形）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"icmp": {}}
  ]
}
```

多轮样例（identifier 显式、步 seq 显式）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"icmp": {"identifier": 5, "pattern": [
      {"type": 8, "sequence": 1, "data": "aa"},
      {"type": 8, "sequence": 2, "data": "bb"}
    ]}}
  ]
}
```

多流样例（数量只走 `flow_control`/`strategy_fc`；存量未用于正例，t8 用它触发框架静态复制门）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"icmp": {}}
  ],
  "flow_control": {"type": "flows", "value": 3}
}
```

## 3. 线格式编码（RFC 792 全文核对，逐字段按代码钉）

### 3.1 Echo 报文头（8 字节，RFC 792 "Echo or Echo Reply Message"）

| 帧偏移 | 头内偏移 | 字段 | 尺寸 | 端序 | 说明 |
|---|---|---|---|---|---|
| 34 | 0 | Type | 1B | — | 8=Echo Request，0=Echo Reply（RFC 792；本仓常量 `icmp.go:17-18`） |
| 35 | 1 | Code | 1B | — | Echo 恒 0（validator 强制） |
| 36–37 | 2–3 | Checksum | 2B | **大端** | RFC 1071 反码和，覆盖整个报文（§3.2） |
| 38–39 | 4–5 | Identifier | 2B | **大端** | 会话标识；**=0 时回退写 Sequence**（icmp.go:298-301） |
| 40–41 | 6–7 | Sequence | 2B | **大端** | 会话内序号；pattern 步缺省=步序（1 起） |
| 42 | 8 | Data | 0–n B | — | 配置 `data` 字符串按**原始字节**直转（非 base64，t4 帧 `61 61`="aa" 实证）；缺省 "ping" |

**总长度公式**：ICMP 报文长 = `8 + len(data)`；IPv4 total length = `28 + len(data)`；以太帧长 = `54 + len(data)`（IPv4 无 options、无 VLAN）。**上界无守卫**：`len(data) > 65507` 时 IPv4 total length 的 uint16 写入静默截断（`builder.go:1154`），产畸形帧 → G-ICMP-12。

**大端纪律**：头内全部多字节字段大端（`buildICMPPayload`，icmp.go:288-320 逐字节手写）；与 payload（data 原始字节）无端序混合面。

### 3.2 Checksum（覆盖整个 ICMP 报文；**IPv4 无伪首部**——与 ICMPv6 逐条对照）

RFC 792 原文（Echo 节）："The checksum is the 16-bit ones's complement of the one's complement sum of the ICMP message starting with the ICMP Type. For computing the checksum, the checksum field should be zero. If the total length is odd, the received data is padded with one octet of zeros for computing the checksum."

实现（`calculateChecksum`，icmp.go:323-338）：①校验和字段先置 0（`buildICMPPayload` 头零值再算）；②逐 16 位大端累加（含 Type/Code 字）；③奇数总长时**尾字节左移 8 位**补一个零八位组（icmp.go:330-332）；④高 16 位折返两次（end-around carry）后取反。**覆盖面 = 从 Type 起到 data 末的全部字节，不含 IP 头任何字段、不含伪首部**。

**与 ICMPv6（姊妹协议 D-ICMPV6-1）的差异逐条**：

| 维度 | ICMP（本协议，RFC 792） | ICMPv6（RFC 4443 §2.3 + RFC 8200 §8.1） |
|---|---|---|
| 校验和覆盖面 | **仅 ICMP 报文本体**（Type→data） | **IPv6 伪首部 + ICMPv6 报文**（src 16B + dst 16B + 上层长度 4B + 零 3B + NextHeader 1B=58） |
| 是否依赖地址 | **否**——校验和与 src/dst 无关，req 与 reply 的差异只来自 Type 字（0x0800 的有无） | **是**——`calculateICMPv6Checksum(srcIP, dstIP, msg)` 显式吃地址（icmpv6.go:309-311）；换向必须重算 |
| 函数签名（本仓） | `buildICMPPayload(config)` 不吃 IP（icmp.go:288） | `buildICMPv6Payload(srcIP, dstIP, config)`（icmpv6.go:281） |
| 承载字段 | IPv4 Header `Protocol=1` | IPv6 NextHeader=**58** |
| IP 头校验和 | IPv4 头自带头校验和（builder `calculateIPChecksum` 重算，与 ICMP 校验和独立） | IPv6 无头校验和，完整性全靠 L4 校验和 |
| 地址族守卫 | **今日缺失**（G-ICMP-2：v6 地址静默产 NextHeader=1 帧） | 有（icmpv6.go:57-78 拒 v4 地址，红例 icmpv6_neg_v4） |

**存量帧校验和逐条复算对拍（本车道脚本实测，6/6 全 OK——t2×2/t3×2/t4×2；t3 p2 的 data 断言缺失，data="abc" 由 spec 推出参与复算）**——反码和算式（cs 字段置零后逐 16 位累加）：

| 帧 | 报文字节（cs 置零） | 16 位累加和 | 折返后 | 取反 = 线上值 | 与 frames 断言 |
|---|---|---|---|---|---|
| t2 p1（req 缺省） | `0800 0000 0001 0001` + `7069 6e67` | 0x0800+0x0001+0x0001+0x7069+0x6e67 = **0xE6D2** | 0xE6D2 | **0x192D** | `19 2d` ✓ |
| t2 p2（reply） | `0000 0000 0001 0001` + ping | 0x0001+0x0001+0x7069+0x6e67 = **0xDED2** | 0xDED2 | **0x212D** | `21 2d` ✓ |
| t3 p1（id7 seq9 "abc"，**奇长补零**） | `0800 0000 0007 0009` + `6162 63`→尾补 `6300` | 0x0800+0x0007+0x0009+0x6162+0x6300 = **0xCC72** | 0xCC72 | **0x338D** | `33 8d` ✓ |
| t3 p2（reply 同 id/seq/data） | 同上去掉 0x0800 字 | **0xC472** | 0xC472 | **0x3B8D** | `3b 8d` ✓ |
| t4 p1（req1 id5 seq1 "aa"） | `0800 0000 0005 0001` + `6161` | 0x0800+0x0005+0x0001+0x6161 = **0x6967** | 0x6967 | **0x9698** | `96 98` ✓ |
| t4 p4（reply2 id5 seq2 "bb"） | `0000 0000 0005 0002` + `6262` | 0x0005+0x0002+0x6262 = **0x6269** | 0x6269 | **0x9D96** | `9d 96` ✓ |

> req→reply 的校验和关系：去掉 Type 字的 0x0800 后反码和减 0x0800，取反值加 0x0800（0x192D+0x0800=0x212D）——t2 notes[1] 的"首算 0x192f 误 → pcap 实测 212d"即此面（notes[0] 残留错误值，G-ICMP-11）。

### 3.3 Identifier / Sequence 语义（RFC 792 "Echo" 节）

RFC 792："an identifier to aid in matching echos and replies, **may be zero**" / "a sequence number to aid in matching echos and replies, may be zero"；"The identifier and sequence number may be used by the echo sender to aid in matching the replies with the echo requests"。

本仓语义（icmp.go:277-287 注释 + 代码）：① **Identifier 分组会话、Sequence 会话内递增**——两字段独立；② **回退规则：Identifier=0 时写 Sequence 值**（icmp.go:298-301，兼容 Identifier 字段引入前的旧行为：单 ping 内 req/reply 共用同一值）；③ pattern 路径 Identifier 从顶层共享（icmp.go:151），步缺省 seq=index+1（:141-143），故"顶层 id=0 + 步 seq 缺省"时每步 id=seq=步序（探针实证：混型步 step2 id=0002 seq=0002）；④ req 与 reply **恒同 id 同 seq 同 data**（icmp.go:178-184/243-249），配对可观察。

### 3.4 Type/Code 值域与消息体布局（RFC 792 规范面全表；as-built 只产 0/8）

RFC 792 定义的 Type 全表（本车道 2026-09-29 拉原文核对；布局列含各 Type 的"剩余头 + 数据体"）：

| Type | 消息 | Code 值域（RFC 792） | 消息体布局（8B 头之外） | as-built |
|---|---|---|---|---|
| 0 | Echo Reply | 0 | Identifier(2)+Sequence(2)+Data | **已产**（#1 p2 auto-reply；type=0 显式单发合法但零套件例，G-ICMP-9） |
| 3 | Destination Unreachable | 0 net / 1 host / 2 protocol / 3 port / 4 fragmentation needed & DF set / 5 source route failed | Unused(4B；RFC 1191 起其中 2B 承载 next-hop MTU) + 原始数据报（IP 头 + 64 bits） | 不编排（validator type 锚拒） |
| 4 | Source Quench | 0 | Unused(4B) + 原始数据报 | 不编排（RFC 6633 已弃用，规范面存档） |
| 5 | Redirect | 0 net / 1 host / 2 TOS&net / 3 TOS&host | Gateway Internet Address(4B) + 原始数据报 | 不编排 |
| 8 | Echo Request | 0 | Identifier(2)+Sequence(2)+Data | **已产**（#1–#4） |
| 11 | Time Exceeded | 0 ttl exceeded in transit / 1 fragment reassembly time exceeded | Unused(4B) + 原始数据报 | 不编排 |
| 12 | Parameter Problem | 0 pointer indicates the error | Pointer(1)+Unused(3) + 原始数据报 | 不编排 |
| 13 | Timestamp | 0 | Identifier(2)+Sequence(2)+Originate(4)+Receive(4)+Transmit(4)，时间戳=UT 午夜起毫秒 | 不编排 |
| 14 | Timestamp Reply | 0 | 同 13 | 不编排 |
| 15 | Information Request | 0 | Identifier(2)+Sequence(2) | 不编排 |
| 16 | Information Reply | 0 | Identifier(2)+Sequence(2) | 不编排 |

扩展 Code（type 3 code 6–15 等）出自 RFC 1122 §3.2.2 / RFC 1812 §4.3.3.1——**本车道未逐条核对原文，标待确认（G-ICMP-13）**；对 as-built 无影响（validator 在 type 锚即拒，code 域不可达）。

**as-built 收窄（D-ICMP-1 裁定 6 B′ 账本）**：层 validator 只放行 `type∈{8,0}` 且 `code=0`（layer_gen.go:64-69）；非 Echo 型**无 builder 路径**（buildICMPPayload 恒写 8B Echo 形头）。上表 3/4/5/11/12/13/14/15/16 为规范参照面，**不得声称可生成**（G-ICMP-6）。

### 3.5 Pattern 多轮（多会话 ping，D-ICMP-1 裁定 3）

`pattern[]` 非空时逐步发射（icmp.go:137-207）：①每步 1 帧，方向 up；②**步 type=8 自动补 1 帧 Echo Reply**（type=0、code=0、同 id 同 seq 同 data，方向 down→Generator 改 up）；③步字段缺省镜像 flat parse（决策 D1）：type 8/code 0/**sequence=0（含显式 0）自动补步序 index+1**（translate :1176 与 planner :141-143 双处同语义，防混搭缝）/data "ping"；④Identifier 顶层共享；⑤**空数组 `[]` 回退单 ping 路径**（parseICMPPattern 空返回 nil，:2125；探针实证 n=2）；⑥混型步（8+0）合法：type=0 步不触发 auto-reply（探针实证 n=3：req/rep(seq1)/step2-rep(seq2)）。**注意：步 `code` 不受 validator 检查**（仅步 type 受检）——code≠0 步可上包（探针实证），缺陷候选 G-ICMP-1。

### 3.6 承载与头生成（raw-IP 链）

`L3Base(spec.SrcIP, spec.DstIP, 1, effectiveTTL, ipID, spec)`（icmp.go:166/230）：Protocol=1、TTL=spec.TTL（缺省 64，icmp.go:14/78-80）、DSCP/ECN/Flags 透传 spec；**IPID 流内随机起点、逐包自增**（icmp.go:85-86 `ipID := uint16(rand.Uint32())`）——`ip.id` **不可复现，断言禁钉**（禁钉令入覆盖反查门 §9）。EtherType 由 `EtherTypeFor(spec.SrcIP)` 定（0x0800）；L2 MAC 由链驱动 `l2For` 补缺省（chain_planner_gen.go:230），存量不断言。**Direction 防双换**：legacy Plan 已完成 reply 的 L3 换向并置 Direction=down；raw-IP 驱动对 down 包再换 L3 即双换错——Generator 强制全包 `Direction="up"`（layer_gen.go:46-51）。后果：**线上方向不可从 Direction 判**，断言方向语义用 payload[0]（type 字节）与 L3 地址互换承载（#1 p2 `ip.src=20.0.0.1`）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明单 ping 或 pattern 步序，引擎按序产出 req/reply 帧；无连接、无会话推进，回包是引擎按 RFC 792 配对规则自产（非真实内核栈）。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 连通性探测（ping 单发） | 1 req + 1 auto-reply | #1/#2/#3 |
| ② 多轮探测会话（id 固定、seq 递增） | pattern 步序贯，逐步配对 | #4 |
| ③ 头字节取证（校验和/id/seq 逐格钉） | 同①，断言面加深 | #2/#3 |
| ④ 非法配置拦截（值域/形状） | validator/create 门拒绝 | #5–#8 |

**五层覆盖逐层结论**：
- **功能层**：Echo req/reply 配对正例（#1/#3）+ pattern 多轮（#4）+ 头字节整钉（#2）+ 4 类负例（type/code/presence/static-copy）。缺口面（步 code 不查/族混/夹层 0 包）见 G-ICMP-1/2/3。
- **性能层**：最小帧边界（data 空 → ICMP 8B、帧 54B——**今日无用例**，A′）；最大帧（data≤65507，**上界无守卫** G-ICMP-12）；多流并发（仅策略级 flow_control，存量 0 例）；**分段/重组不适用**（无 TCP；IPv4 分片不在本层语义内，FragOffset 透传 spec）。
- **数据场景层**：type 0/8 合法值、type 3/256/-1/非数值 拒（#5 + V9 实测锚）；code 0/1；identifier 0 回退/显式 7/边界 65535（合法，V9 界内；**65536 拒**，V9 实测）；sequence 1 缺省/显式 9/步 0 自动补（translate 分支，套件零例 G-ICMP-10）；data "ping"/"abc"（**奇长补零校验和路径**，#3 钉）/""（空串=无 data，**今日无用例** A′）/二进制（不支持，层链 data 只有字符串面）。
- **地址与流层**：**IPv4 已覆（8/8）**；**IPv6 显式不适用**（v6 域=icmpv6 层）——但族混今日**静默产无效帧**（G-ICMP-2，不适用≠已守卫）；单流基线（全部正例）；流关联（控制流派生数据流）**显式不适用**：raw-IP 单流、无子流机制；多流=策略级 `flow_control.flows`（t8 为其**拒绝面**，正例面 A′）。
- **业务层**：现网 ping 探测/多轮探测两场景全落点（§4 场景表）；差错观测（Unreachable/TimeExceeded/Redirect）与时延测量（Timestamp）**明确不解决**（G-ICMP-6）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① 真实差错报文语义（B′）；② IPv6 载体（icmpv6 层域；族守卫缺失另立 G-ICMP-2）；③ TTL/IPID 线上断言（IPID 随机不可钉；TTL 可断今日无用例）；④ `nic_capture` 双路径（框架能力，协议层零特有断言）。

## 5. 消息/事务模型与状态机

**事务定义**：一次 Echo 交互 = req（+auto-reply if type=8）。**多事务** = pattern 步序贯（#4 两步四帧）。

icmp 层无自有状态机：无连接、无握手挥手、无重传——"状态"仅存在于 per-flow 局部量（IPID 计数器、pattern 步游标），配置→帧是纯函数展开（确定性：同配置同帧序同字节，**除 ip.id 外**）。

| 阶段 | 产出帧 | 用例 |
|---|---|---|
| 单 ping（type=8） | req（up）+ reply（down→up，L3 已换向） | #1/#2/#3 |
| 单发（type=0 显式） | 仅 1 帧（无 auto-reply） | 探针实证 n=1；套件零例（G-ICMP-9） |
| Pattern（echo 步） | 每步 req+reply，序贯 | #4 |
| Pattern（混型/空） | 混型=3 帧 / 空=回退单 ping 2 帧 | 探针实证；套件零例（G-ICMP-9） |

**事件序（pattern 路径，icmp.go:137-207）**：`step1(req up)` → `step1(reply)` → `step2(req up)` → `step2(reply)`…——**帧位实测（#4）：p1=req1(seq1)/p2=rep1/p3=req2(seq2)/p4=rep2**（t4 notes 自述"帧序 req1/rep1/req2/rep2 首标 req2 误 → pcap 实测"，与代码一致）。

**自动派生规则（逐条）**：① type=8 的 req 自动补 reply（legacy :242 / pattern :177 双分支）；② reply 恒 type=0/code=0/同 id/同 seq/同 data（:243-249）；③ id=0 回退 seq（:298-301）；④ pattern 步 seq=0 自动补 index+1（:141-143 + translate :1176）；⑤ 空 ICMPConfig 缺省 type=8/code=0/seq=1/data="ping"（:91-97 + translate :1144）；⑥ 空层 `{}` → 全缺省合法 ping（translate 空层注释）；⑦ 空数组 pattern 回退单 ping（:2125 + :137 判空）；⑧ TTL=0 → 64；⑨ FileSource→Data 优先级（legacy 面，链路径不可达 G-ICMP-5）。

**配置→帧完整路径**：`cases spec_json` → `schema.ValidateStrategy`（create 门：CheckProtoFlat presence 判死 + checkLayerChainStaticCopy，semantic.go:130/142）→ `ValidateLayers`（V9 数值界 + unknown field + dynamic 对象门）→ `translateTerminalConfig case "icmp"`（层 config→`spec.ICMP`，chain_planner_translate.go:1133-1190）→ `validateLayer`（三锚 + HasLayerDynIP 豁免 + legacy IP 格式，layer_gen.go:59-80）→ `Generator.Generate` → legacy `Planner.Plan`（req/reply/pattern 展开 + buildICMPPayload 逐字节 + 校验和）→ 链驱动 Emit（Direction 强制 up / l2For 补 MAC / TOS 透传，chain_planner.go:1542-1585）→ worker → writer（PCAP/NIC）。

### 5.3 防双换与方向语义（修轮教训落地面）

legacy Plan 产 reply 时已完成 L3 地址换向并置 `Direction="down"`（icmp.go:185-204/251-270）；链驱动 Emit 对 down 包**再换一次 L3**（chain_planner.go:1546-1548）。若不防，reply 地址被换回 → 双换错。Generator 强制全包 `Direction="up"`（layer_gen.go:46-51）后：①L3 换向只发生一次（legacy 那次）；②l2For 沿 up 侧补 MAC；③**Direction 字段失去判别力**——红⑥首跑按 Direction 过滤方向即由此翻红（icmp_chain_test.go:163-166 注释实录）。本契约全部断言面不使用 Direction。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流全链 ≤ 2×pattern 步数帧（无握手挥手开销）；帧长 = `54+len(data)`（§3.1）；**data 上界无守卫**（>65507 截断，G-ICMP-12）；吞吐数字待 P4 基准，**本版不写承诺**。
- **依据**：`Plan` 走 `chan core.PacketConfig`（缓冲 256，icmp.go:68）流式产出，pattern 步逐帧发射（无全量聚合）；每帧内存 = 该帧长；per-flow 局部状态（IPID/步游标），无跨流共享、无锁。
- **验收两路（§6.3 强制）**：pcap（`<id>.pcap`/负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，`nic_capture`）共用同一断言集；断言实际 `icmp.*` 字段、帧原始 hex 与 `packet_count`，不只断言"任务没报错"。
- **六类场景落点（§6.6）**：基线（#1，2 帧）/ 目标规模（#4，4 帧，pattern 2 步）/ 压力上限（**pattern 步数上限无配置界**——步数即帧数，大 pattern 面为 A′ 候选）/ 长时间运行（不适用——无连接短序列，如实声明）/ 并发交错（不适用——单流串行）/ 背压（packet_count 精确计数守卫帧数漂移 + V9 界守卫值域）。
- **复现性边界**：`ip.id` 随机起点（icmp.go:85）→ **ip.id 断言禁钉**；其余字节全部确定性。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须被拒绝并传播为 task error，不得产出成功 PCAP 或 `completed/0 packet` 假成功：

| # | 负例 ID | 故障输入 | 拦截面（真实产地） | 锚词（代码逐字） |
|---:|---|---|---|---|
| N-1 | `icmp_t5_neg_type` | `icmp.type=3` | 层 validator（layer_gen.go:64-66，translate 后判） | `icmp type must be 8 (Echo Request) or 0 (Echo Reply), got 3` |
| N-2 | `icmp_t6_neg_code` | `icmp.code=1` | 层 validator（:67-69） | `icmp code must be 0 for Echo, got 1` |
| N-3 | `icmp_t7_neg_presence` | 层链 + 顶层 `icmp:{}` 并存 | **create-time**：schema.ValidateStrategy → `CheckProtoFlat` rawWrapChains（semantic.go:130 → strategy_convert.go:9100/9107-9111；batch 路径 convert.go:166 同门） | `no longer accepts a top-level icmp` |
| N-4 | `icmp_t8_neg_static_copy` | ip 层显式标量 + `strategy_fc flows=2` | **create-time**：schema.ValidateStrategy → `checkLayerChainStaticCopy`（semantic.go:142→:285；仅 fc.Type=flows 且 >1 触发） | `static four-tuple` |

**N-3/N-4 的引擎直调缝（今日探针实证，G-ICMP-4）**：`MapToFlowSpec` 对 icmp **无** ValidationErrors 分支（顶层 `icmp` 子映射在 universal 段 :455 先于 translate 填 `spec.ICMP`，层配置被静默顶掉——F1 混搭缝同构），`ChainPlanner` 无 static-copy 背 door；故离线链执行器（直调 `Engine.SubmitTask`）实测 t7/t8 失守。生产 MCP 路径（strategy create 过 schema 门）两门均在，存量 0 行（D-ICMP-1 P6 清库对账平）风险低——**登记不修，等框架级引擎侧门**。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：
- `icmp pattern step %d type must be 8 or 0, got %d`（layer_gen.go:71-73；红④单测面在案 icmp_chain_test.go:99-122，套件 0 例）；
- `invalid source IP: %s` / `invalid destination IP: %s`（legacy Planner.Validate，icmp.go:37-44；HasLayerDynIP 时豁免，红⑤单测面）；
- V9 数值界（框架，registry Fields Min/Max，本车道探针实测锚词）：`layers: layer "icmp" field "type" = 256 invalid: out of range [0,255]`、`field "sequence" = 65536 invalid: out of range [0,65535]`、`field "type" = eight invalid: not a numeric value in [0,255]`；
- 未知键：`layers: layer "icmp": unknown field "bogus"`（探针实测）；
- 动态对象门：`layers[1](icmp).data does not support dynamic`（探针实测；allowlist 无 icmp 行）。

**缺陷候选（validator 分支缺失，非"待补用例"）**：pattern 步 `code` 不受检（探针：`{"pattern":[{"type":8,"code":1,…}]}` 放行且上包 code=1）→ G-ICMP-1，代码阶段补步 code 分支（锚词建议镜像顶层：`icmp pattern step %d code must be 0 for Echo, got %d`）+ 失败用例先行。

**不得误报的合法协议事件**：id=0 回退（#1/#2 钉）；pattern 步 seq 显式/缺省并存（红⑥面）；type=0 单发；混型 pattern；空 pattern 回退——后三者套件零例但**探针实证合法**（G-ICMP-9，A′ 补正例，**不得建负例**）。

## 8. 边界

- **帧长**：最小 ICMP 报文 8B（data 空）→ 帧 54B（**无用例**，A′）；最大合法 = data 65507B（total length 65535）；**无上界守卫**（G-ICMP-12）。
- **Type 域**：只产 0/8；3/4/5/11/12/13/14/15/16 拒（§3.4）；256/-1/非数值 V9 拒（探针实测锚词）。
- **Code 域**：顶层恒 0；**pattern 步不查**（G-ICMP-1）。
- **id/seq 域**：uint16 全域合法（V9 界 [0,65535]）；id=0 语义=回退 seq，不是"无效值"。
- **pattern**：空数组=回退单 ping（合法）；步数无配置上限；步 type=0 不触发 auto-reply。
- **地址族**：v4 全覆盖；**v6 不拒（缺口）**——族守卫补齐前 `[ip(v6),icmp]` 产无效帧。
- **载体**：`[ip,icmp]` 唯一合法链形；`[ip,{tcp,udp},icmp]` **静默 0 包**（G-ICMP-3）；`[icmp]` 裸链经链补全自动加 ip 层。
- **端口**：协议无端口；spec 端口清 0；框架多流 srcport 注入线上不可见。
- **复现性**：除 ip.id 外全确定性；ip.id 禁钉。
- 不得产生回绕长度或超量分配（帧长由 buildICMPPayload 一次算定；上界守卫缺失见 G-ICMP-12）。

## 9. 原子 ID 与完成定义（8 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 | packet_count |
|---:|---|---|---|---:|
| 1 | `icmp_t1_smoke` | 正 | §3.1/§5：缺省 ping 配对（ip.proto=1/type 换向/角色互换） | 2 |
| 2 | `icmp_t2_header_bytes` | 正 | §3.1/§3.2：8B 头整钉 + 校验和 0x192D/0x212D | 2 |
| 3 | `icmp_t3_explicit` | 正 | §3.3：显式 id=7/seq=9/data=abc（**奇长补零校验和路径** 0x338D/0x3B8D） | 2 |
| 4 | `icmp_t4_pattern` | 正 | §3.5：pattern 2×echo 步（帧序 req1/rep1/req2/rep2；0x9698/0x9D96） | 4 |
| 5 | `icmp_t5_neg_type` | 负 | §7 N-1：type=3 拒 | —（0 帧） |
| 6 | `icmp_t6_neg_code` | 负 | §7 N-2：code=1 拒 | —（0 帧） |
| 7 | `icmp_t7_neg_presence` | 负 | §7 N-3：顶层 presence 判死（**create-time 门**） | —（0 帧） |
| 8 | `icmp_t8_neg_static_copy` | 负 | §7 N-4：静态复制拒（**create-time 门**，`strategy_fc flows=2`） | —（0 帧） |

**包数公式**：单 ping type=8 = **2**；type≠8 显式单发 = **1**；pattern = `2×(#type8步) + 1×(#type0步)`。校验：#1–#3 单 ping → 2 ✓；#4 两 echo 步 → 4 ✓。负例全部 validator/create 门拒绝 → 0 帧（t1–t6 今日离线实测 PASS 与 pcap 计数一致；t7/t8 见 G-ICMP-4）。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | 无连接：IPv4 直载（Protocol=1），Echo 请求/应答对（RFC 792 Echo 节） | 场景①–④ | `[ip,icmp]` raw-IP 终结层（registry.go:1324）+ Plan 双路（icmp.go:63） | 无 |
| 2 | 命令/消息表 | RFC 792 十一型 Type 表（§3.4） | 仅 Echo 面 | type∈{8,0} validator 收窄 + buildICMPPayload 恒 8B Echo 形 | 非 Echo 型不编排 → G-ICMP-6 |
| 3 | 状态机 | 无状态；Echo 对靠 id/seq 配对（RFC 792 "aid in matching"） | 探测会话 | 配对规则已实现（id 共享 + seq 同值） | 无 |
| 4 | 字段表 | 8B 头五字段 + data（§3.1） | 全字段可配 | buildICMPPayload 逐字节 | 步 code 不查 → G-ICMP-1 |
| 5 | 错误处理 | type/code 语义域校验 | 4 负例 | 三锚 validator + 框架门（§7） | 步 code 缺分支；引擎直调缝 → G-ICMP-1/4 |
| 6 | 超时与活性 | 不适用（无重传语义） | — | 不适用 | 不适用（如实） |
| 7 | NAT/被动 | 不适用 | — | 不适用 | 不适用（如实） |
| 8 | 版本方言 | RFC 792 单一；RFC 1122 注记；ICMPv6 = 姊妹协议（NextHeader 58，D-ICMPV6-1） | — | 单版 | v6 族守卫缺失 → G-ICMP-2；扩展 Code 出处待核 → G-ICMP-13 |

### 10.2 子表①：消息 × 终态矩阵（逐格已覆/立项/不适用）

| 消息 | T1 正常终态 | T2 配置拒绝 |
|---|---|---|
| Echo Request（type=8） | 已覆（#1–#4） | 已覆（#5 代表） |
| Echo Reply 显式单发（type=0） | **立项**（探针 n=1 实证合法，套件零例，G-ICMP-9） | 已覆（#5 代表） |
| Pattern 步（含缺省/显式） | 已覆（#4；混型/空数组立项 G-ICMP-9） | 已覆（#5/#6） |
| 非 Echo 9 型（3/4/5/11/12/13/14/15/16） | **不适用**（B′ 不编排，§3.4） | 已覆（#5 type=3 代表，同分支同锚） |

**逐格重数**：4 行 × 2 列 = **8 格 = 已覆 6 + 立项 1 + 不适用 1** ✓。**T3 传输异常终态整列不适用**（无连接、无传输层终结语义——无 FIN/RST 概念；D-ICMP-1 修轮 L2 天花板声明承 CODE_DESIGN，9.50/9.53 显式 N/A）。

### 10.3 子表②：数据形态变体表（27 行）

| # | 变体 | 落点 |
|---:|---|---|
| 1 | type 缺省（=8） | 覆（#1/#2） |
| 2 | type 显式 8 | 覆（#1–#4） |
| 3 | type 显式 0（单发） | 立项（探针 n=1，G-ICMP-9） |
| 4 | type 非法（3） | 覆（#5） |
| 5 | type V9 越界（256/-1/非数值） | 立项（V9 锚词探针实测，套件 0 例） |
| 6 | code 缺省（=0） | 覆（#1/#2） |
| 7 | code 非法（1，顶层） | 覆（#6） |
| 8 | pattern 步 code≠0 | **立项=缺陷候选**（validator 不查，G-ICMP-1） |
| 9 | identifier 缺省（=0 回退 seq） | 覆（#1/#2） |
| 10 | identifier 显式 | 覆（#3/#4） |
| 11 | sequence 缺省（=1） | 覆（#1/#2） |
| 12 | sequence 显式 | 覆（#3） |
| 13 | pattern 步 seq 缺省（index+1 自动补） | 立项（translate 分支，红⑥单测面，套件 0 例，G-ICMP-10） |
| 14 | pattern 步 seq 显式 | 覆（#4） |
| 15 | pattern 步 type=0（不 auto-reply） | 立项（探针 n=3，G-ICMP-9） |
| 16 | pattern 空数组（回退单 ping） | 立项（探针 n=2，G-ICMP-9） |
| 17 | data 缺省（"ping"） | 覆（#1/#2） |
| 18 | data 奇数长（"abc" 3B，补零校验和） | 覆（#3，0x338D/0x3B8D 钉） |
| 19 | data 偶数长（"aa"/"bb"） | 覆（#4） |
| 20 | data 空串（8B 裸头帧） | 立项（合法，套件 0 例） |
| 21 | data 二进制/base64 | 立项（层链 data 仅字符串面，不支持） |
| 22 | file_source | **不适用**（层链不可达，③ C 类，G-ICMP-5） |
| 23 | IPv4 载体 | 覆（8/8） |
| 24 | IPv6 载体 | **不适用**（icmpv6 层域）+ 族混缺陷（G-ICMP-2） |
| 25 | ttl 显式/动态 + ip.id 面 | 立项（今日无用例；ip.id 随机**禁钉**） |
| 26 | 多流 flows=2 静态拒 | 覆（#8） |
| 27 | 多流动态 ip 正例（flows=N） | 立项（红⑤单测面，套件 0 例，G-ICMP-7） |

重数：**27 行 = 覆 15 + 立项 10 + 不适用 2** ✓。

**八项 8 = 覆 2 + 开放 4 + 不适用 2（§10.1 缺口列反推）**：覆 2（连接模型/状态机）+ 开放 4（命令表 G-ICMP-6 / 字段表 G-ICMP-1 / 错误处理 G-ICMP-1·4 / 版本方言 G-ICMP-2·13）+ 不适用 2（超时活性/NAT）。

**对账两行（设计侧口径，与用例契约 §5.2 逐字一致）**：**要求逻辑点总数 = 50**（八项 8 行 + 矩阵① 8 格 + 变体② 27 行 + 商业③ 7 行）；**用例覆盖数 = 25**（八项 2 + ① 6 + ② 15 + ③ 2）；**不适用 = 9**（八项 2 + ① 1 + ② 2 + ③ 4）；**开放立项 = 16**（八项 4 + ① 1 + ② 10 + ③ 1）。25 + 9 + 16 = 50 ✓

### 10.4 子表③：商业行为→用例映射表（7 行）

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 连通性探测（现网 ping） | #1/#2/#3 | 已覆 |
| 2 | 多轮探测会话（id 固定 seq 递增） | #4 | 已覆 |
| 3 | 地址扫描探测（动态 ip 多流） | — | 立项（G-ICMP-7） |
| 4 | 差错报文观测（Unreachable/TimeExceeded/Redirect） | — | **明确不解决**（B′，G-ICMP-6） |
| 5 | 时延测量（Timestamp 13/14） | — | **明确不解决**（B′，G-ICMP-6） |
| 6 | MTU/PMTU 探测（frag needed code 4） | — | **明确不解决**（B′，G-ICMP-6） |
| 7 | IPv6 邻居发现/诊断 | — | **不适用**（icmpv6 层域，D-ICMPV6-1） |

重数：**7 行 = 覆 2 + 立项 1 + 不适用 4**（其中"明确不解决"3 + 域外 1）✓。

### 10.5 三路对照与候选方案对比（§4.12–4.15/§4.17）

三路：①规范原文（RFC 792 本车道拉取核对 + RFC 1071 算法原文，定"必须是什么"——已用它复算 5 条存量帧校验和全 OK，§3.2）；②商业化软件实际行为（**未取到**：真实 ping 内核栈线字节未抓包核对 → G-ICMP-13 待确认）；③可靠开源实现思路（Go 标准库 `net`/gopacket 的 ICMP 校验和同构——只借鉴"全报文反码和"这一条）。三路一致点：8B 头布局、大端、全报文校验和无伪首部；不一致点：无（Echo 面规范钉死）。

| 方案 | 走法 | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `icmp` raw-IP 终结层（本版；icmpv6 对称第 12 连） | 层内 6 键可声明可断言；已落码（423 行） | **采用** |
| B | 直接 ip 层 + payload 塞字节 | 无 type/code/id/seq 断言面、无 validator 收窄 → 8 例中 6 例不可表达 | **否决** |
| C | 拆"echo 层 + timestamp 层" | 非 Echo 型本就不编排，拆层无受益 | **否决**（B′ 账本已收窄） |

## 11. P2 D-ICMP-1 代码设计（CORE_MEMORY §8 八要素；as-built 定稿）

> 状态说明：实现已落码（2026-09-22 D-ICMP-1 P4/P5/P6 + 修轮），本条目为 P-PIPE 文档轨对既有实现的 **as-built 逆向定稿**，供后续改动作为唯一入口。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/protocol/icmp/icmp.go` | `Planner{Validate, Plan}` + `buildICMPPayload` + `calculateChecksum`（legacy 线面权威） | 338 |
| `trafficgen/internal/protocol/icmp/layer_gen.go` | `Generator`（包装 legacy，防双换）+ `validateLayer`（链路径三锚）+ `init()` 注册 | 85 |
| `trafficgen/internal/core/types.go`（:2373-2400） | `ICMPConfig{Type,Code,Identifier,Sequence,Data,Pattern,FileSource}` + `ICMPStep{Type,Code,Sequence,Data}` | —（共享文件） |
| `trafficgen/internal/core/layers/registry.go`（:1320-1333） | icmp 层 6 键 + FieldContract `ip.protocol=1` | — |
| `trafficgen/internal/core/layers/chain_planner_translate.go`（:1133-1190） | `case "icmp"` 层 config 手工逐键映射（缺省镜像决策 D1） | — |
| `trafficgen/internal/core/strategy_convert.go` | `:455` flat parse / `:920` case "icmp" 清端口 / `:2123` parseICMPPattern / `:9100` rawWrapChains presence 判死 | — |
| `trafficgen/internal/core/layers/icmp_chain_test.go` | 链级红例 6 例（红①–⑥） | 178 |
| 单测面 | `icmp_test.go` 6 + `icmp_testpoints_test.go` 35 + `icmp_filesource_test.go` 6 + `icmp_f7_autoreply_test.go` 3（`grep -c "^func Test"` 实测） | — |
| 接线 5 件 | registry（:1324）/ translate（:1133）/ convert（:920/:9100）/ protocols（:43）/ main.go（:75 空导入 + :562 RegisterPlanner） | — |

**注意**：本协议**无 planner.go/builder.go**（派发口径提及的三件中两件不存在）——线面权威在 `icmp.go`，层壳在 `layer_gen.go`。

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（icmp.go:35）：仅 IP 格式（`net.ParseIP`，锚 `invalid source/destination IP`）；**无地址族守卫**（v6 通过，G-ICMP-2）。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（:63）：双路（pattern :137 / 单 ping :209），chan 256 流式。
- `buildICMPPayload(config *core.ICMPConfig) []byte`（:288）：8B 头 + data + 校验和一次算定。
- `calculateChecksum(data []byte) uint16`（:323）：RFC 1071 全报文反码和。
- `Generator{Name/GenEvents/Generate}`（layer_gen.go:16-53）：`GenEvents()` 返回 nil（raw-IP 面不发事件）；`Generate` 包装 legacy 并强制全包 Direction="up"。
- `validateLayer(s core.FlowSpec) error`（:59-80）：`icmp config is required` / type 锚 / code 锚 / pattern 步 type 锚 / HasLayerDynIP 豁免 / legacy IP 复验。

### 11.3 数据结构

`ICMPConfig{Type uint8, Code uint8, Identifier uint16, Sequence uint16, Data []byte, Pattern []ICMPStep, FileSource *filesystem.FileSource}`（types.go:2373-2387）；`ICMPStep{Type, Code, Sequence uint16, Data []byte}`（:2389-2396）。registry Fields 6 键 `{type,code,identifier,sequence,data,pattern}`（file_source 不映射，③ C 类）；V9 界 type/code [0,255]、identifier/sequence [0,65535]。

### 11.4 主流程

见 §5 配置→帧完整路径。raw-IP 驱动（chain_planner.go:1497-1585）：`flowMetaFor(spec)` 携带 `spec.ICMP`（chain_planner_chain.go:28）→ `GenRequest.Meta.ICMP` → Generator 直传 legacy Plan → Emit 钩子（Direction 强制 up 由 Generator 先行完成 / l2For 补 MAC / multicastDstMAC / EtherTypeFor / TOS 透传 / FlowID 兜底 `flowID(spec)`）。

### 11.5 错误分支

三锚 validator + `icmp config is required` + legacy IP 两锚（§7 表）+ 框架四门（V9 界/unknown field/dynamic 门/create 双门）。全部传 task error（零假成功——t5/t6 离线实测 0 帧通过）。**分支缺口**：pattern 步 code（G-ICMP-1）、v6 族（G-ICMP-2）、夹层静默 0 包（G-ICMP-3）、引擎直调双门缝（G-ICMP-4）。

### 11.6 性能边界

见 §6（chan 256 流式、per-flow 局部状态、无锁；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- `CheckProtoFlat` rawWrapChains 含 icmp（:9100）→ 顶层 `icmp` 子映射 **create/batch 两路已判死**；`MapToFlowSpec` **无** icmp ValidationErrors 分支（引擎直调缝，G-ICMP-4）。
- `isRawIPChain`（chain_planner_util.go:40-58，icmp 在 :54 双名单第 7 位，名单共 24 协议）：链含 tcp/udp 即返回 false → 事件分支 → `GenEvents()`=nil → **静默 0 包**（G-ICMP-3）。
- 动态 allowlist（`internal/core/layer_dyn.go`）：**无 `icmp` 行**（grep 零命中实测）→ 6 业务键对象即 `does not support dynamic`（探针实测）；`ip` 层 src/dst/ttl 全开。
- rawWrapChains 与 universal flat parse（:455）的优先级：层链形状下若引擎直调（绕过 schema），顶层子映射静默赢层配置——create 门拦死后生产不可达（G-ICMP-4 缝）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert `internal/protocol/icmp/` 两文件 + 接线 5 处（registry/translate/convert/protocols/main）+ cases 8 例；不触及其他协议（icmpv6 独立包，对称但零共享）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 spec_json 顶层 7/8 = `{layers}` 唯一键；t7 为 presence 负例形状（判死语义必含，非遗留）；顶层 `icmp` 子映射 create/batch 两路已判死（rawWrapChains）；目标形状见 §2 样例且存量已达标（无迁移工作量） | §12.1；`cases/icmp.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 icmp 流量模板（单 ping/pattern）；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联关系（无派生流，raw-IP 单流豁免声明）/插入位置（终结层）/时间线 | §12.3 + §5 |
| §4 查规范 | RFC 792 原文本车道拉取核对（Type/Code 全表 + checksum 措辞 §3.2/§3.4）+ RFC 1071 + RFC 4443 §2.3 对照 + tshark 3.6.14 字段表 + 探针实测；八项矩阵 + 子表①②③（8 格/27 行/7 行逐格重数闭合） | §10；§3.2 对拍表 |
| §5 依赖与错误 | `DependsOn ["ip"]` 单值（registry.go:1324）；三锚 validator + 框架四门（§7）；失败传 task error（t5/t6 离线 0 帧实测） | §7/§11.5 |
| §6 性能 | 见 §6（包数公式/帧长公式/流式产出/复现性边界 ip.id 禁钉；吞吐待 P4 基准不写承诺；pcap/NIC 两路验收明写） | §6 |
| §7 三份文档 | `127-icmp-{design,testcase}.md` v1.0.0（本对）+ `cases/icmp.json`（8 ID）+ 内部契约 D-ICMP-1（历史层）+ 结果产物（缺失登记 G-ICMP-8） | 修订记录 |
| §8 设计先行 | 内部契约 P1–P3 先于 P4 落码（git 历史 0b084f2 同族→af02651）；本对文档先于任何后续改动；**本车道未动代码/cases** | `git status` 零改动；提交序 |
| §9 测试三源 | 三源 = RFC 792/1071/4443（§10）+ D-ICMP-1 as-built（§11）+ tshark 3.6.14 与存量 pcap 断言（**校验和 6/6 反码复算对拍**，§3.2；6/8 离线实测 + t7/t8 门面声明）；8 ID 逐项回指；存量 8 例审计去向 testcase §8 | `127-icmp-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 本车道自审（机读复核计数与断言）+ 收官隔离复审；红先绿后 | 修订记录；自审日志 |
| §11 白话 | 本文首节白话一句 | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组=ip 层 src/dst/ttl 开（allowlist 实测）；**端口=协议无端口（不适用）**；业务 6 键全关（探针实测锚词）；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `icmp` 已在 registry.go:1324 注册（不新增层）；生成表 127 层同代（`schemas/v1/generated/layers.generated.json` icmp 条目与 registry 逐键一致，机读实测）；**改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | MCP 建策略建任务 → 引擎真实生成 → tshark `icmp.*` + frames 双通道 → 先跑后钉（D-ICMP-1 验收实录）；本车道增量实测 = 反查 18/18 + 离线 6/8 + 探针 9 项（§0 #8） | testcase §1/§7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | spec_json 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/icmp.json` | 8 | **`{layers}` ×7** + `{layers, icmp}` ×1（t7 presence 负例特形，**判死语义必含**） | `[ip,icmp]` ×8（无例外） | 4/4 = `{expect_error, error_contains}` **严格两键**（无 notes，比 opcua/rtsp 干净） |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 已住 `layers[0].ip.{src,dst}`（8/8） |
| `src_port` / `dst_port` | **0** | **协议无端口**——mapToFlowSpec 清 0（strategy_convert.go:920）；validateSpecBase 端口豁免；框架多流注入线上不可见（§2） |
| `count` | **0** | 走 `flow_control`（本版未用）；**注意 cases 顶层 `count` 不是 flow_control——t7 特形除外，存量无此键** |
| 顶层 `icmp` 子映射 | **1**（t7，负例） | 正确形状 = `layers[i].icmp`（7/7 正例）；create/batch 判死在案（rawWrapChains），引擎直调缝 G-ICMP-4 |
| `strategy_fc`（case 级，非 spec_json 键） | **1**（t8） | 框架流控键，供 create 门触发 static-copy；正例多流目标形见 §2 样例 |

**结论**：**非负例 spec_json 顶层键 = 0 今日即成立**（机读实测 7/7 仅 `layers`）；§1 门的动作 = ①无旧键可删；②t7 保留（负例形状是判死门的可执行证据）；③A′ 新增例全部沿用纯 layers 形（§13）。
> **注**：全仓纯 `{layers}` 形协议已有多个（批次一 27 协议 + 本批同批若干），本协议**不构成全仓唯一性**；特有事实仅是"8 例链形恒 `[ip,icmp]` + 负例严格两键"。

目标形状样例见 §2。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① **presence 形状 `{"layers":[…],"icmp":{}}` 今日已被拒**（rawWrapChains 覆盖 icmp，红① `TestICMPChain_FlatPresenceRejected` + 套件 t7 双证）→ **P4 已建该负例且真红**（MCP 路径）✓。② 白名单外游离键判死（`unknown field`）**层内**有门（V9，探针实测 `layers: layer "icmp": unknown field "bogus"`）；**顶层游离键通用门今日无**——`CheckProtoFlat("icmp", {"layers":[…],"bogus":1})` 返回空串（函数体只查五键+子映射白名单），引擎直调面不判死 → **不建顶层 bogus 负例**（建了在 MCP create 路径会否真红取决于 ValidateStrategy 的其他检查，未探针验证，**不申报**）。③ 4 负例每条带锚词（已齐，§7）。④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

**会话表**：`s1` 单流基线（#1–#8 全部）——一条 raw-IP 流（`10.0.0.1 → 20.0.0.1`，无端口），req→reply 两帧或 pattern 步序贯。**本协议无 `sessions[]` 多会话形态**（raw 链单流、无连接）→ 多会话层**显式不适用**（不是遗漏，是链形态决定；D-ICMP-1 §3 豁免声明承接）。

**事务序列**：`t1` 单 ping 交互（req up → auto-reply；前置=配置就绪/触发=pattern 或单发展开/成功=2 帧按序落盘/失败=validator 拒 → task error）→ `t2` 多轮交互（pattern 逐步，步间无依赖但 seq 递增体现会话语义）。每事务四件事见 §5 事件序 + §4 场景表。

**关联关系（raw-IP 族豁免声明，非含糊）**：**无派生流**——ICMP 是探测协议，控制流即全部流量，无控制流派生数据/媒体流的主从关系（FTP/SIP 类 `driven_by` 锚定在本协议结构性不存在）。协议自身的 req/reply 配对（id/seq 同值回显，§3.3）是**报文内关联规则**，不是流关联维度——已在 #1/#3 断言面承载。

**插入位置**：**raw-IP 终结层**（`[ip, icmp]`）——链上**不得**出现 tcp/udp（夹层静默 0 包，G-ICMP-3）；链补全自动加 ip 层。

**时间线**：帧序 = 展开序（req 先 reply 后、步序贯）；**无交错**（单流串行，无并发路径）；全帧同 `Timestamp`（`now := time.Now()` 一次，icmp.go:82）——tshark `frame.time` 恒同值，**时间差断言不适用**（如实声明）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组**：

| 字段 | 动态可达性 | 说明 |
|---|---|---|
| `ip.src` / `ip.dst` | **开**（allowlist `layer_dyn.go:18-20` `"ip": {"src","dst","ttl"}`，五策略全支持） | 探针实测：range 形状 ACCEPTED n=2（红⑤同构） |
| `ip.ttl` | **开**（同上） | 今日无用例（G-ICMP-7 附带） |
| `icmp.src_port` / `icmp.dst_port` | **不存在** | icmp registry Fields **无端口键**（§2）——不是"关"，是协议无此维度 |
| 多流（flows=N） | 仅策略级 `flow_control.flows` | 静态标量 + flows>1 被 create 门拒（#8）；动态 ip 正例 A′（G-ICMP-7） |

**业务字段 6 项全关**（allowlist 无 `icmp` 行，grep 零命中实测；对象即拒，探针实测锚词）：

| 字段 | 开/关 | 理由 |
|---|---|---|
| `type` | 关 | 值域收窄 {8,0}，逐流变无意义 |
| `code` | 关 | Echo 恒 0 |
| `identifier` | 关 | 会话标识逐流变破坏 req/reply 配对语义 |
| `sequence` | 关 | 会话内序号，由 pattern 步序承载 |
| `data` | 关 | 载荷逐流变需求列 A′ 候选（探针实测锚词 `layers[1](icmp).data does not support dynamic`） |
| `pattern` | 关 | 列表无动态形状 |

→ **icmp 无任何业务字段支持动态**（A′ 候选，今日不冒充已覆盖）。

**序号算法实读**：①pattern 步 seq 自动补 `index+1`——translate `chain_planner_translate.go:1176`（`st.Sequence = uint16(len(ic.Pattern)+1)`）与 planner `icmp.go:141-143`（`seq = uint16(stepIdx+1)`）**双处同语义**（translate 先落值，planner 分支在链路径恒不触发，防混搭缝镜像）；②Identifier 回退 `icmp.go:298-301`；③IPID 随机起点+逐包自增 `icmp.go:85-86`（`ipID := uint16(rand.Uint32())` / `nextIPID`）；④保底端口自增（worker.go:308 `12345+i`）对 icmp 线上不可见（无 L4 头）；⑤`parseLayerDyn`（layer_dyn.go:78）读 allowlist，icmp 无块 → 层内对象即 `does not support dynamic`。**本协议存量 8 例无任何动态字段**（机读实测：8/8 的 ip 层 src/dst 均为字面字符串，icmp 层全标量）。

## 13. P3 对接清单（T-ICMP 输入；正文落 testcase 文件）

8 ID（4 正 + 4 负）+ packet_count/锚词 + 校验和对拍基线 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。

**A′ 候选（按缺口分组）**：
- **合法路径面**（G-ICMP-9）：`icmp_type0_single`（type=0 显式单发 1 帧）/ `icmp_pattern_mixed`（8+0 混型 3 帧）/ `icmp_pattern_empty`（空数组回退 2 帧）/ `icmp_data_empty`（8B 裸头帧 54B）。
- **拒绝分支面**（G-ICMP-1/10）：`icmp_neg_pattern_step_type`（步 type=3 → 步锚）/ `icmp_neg_pattern_step_code`（步 code=1，**需先修 G-ICMP-1**，失败用例先行）/ `icmp_neg_v9_bounds`（type=256 / sequence=65536 / 非数值，三锚探针已实测）。
- **族面**（G-ICMP-2）：`icmp_neg_v6_family`（[ip(v6),icmp] 拒——**需先修族守卫**）。
- **多流面**（G-ICMP-7）：`icmp_multi_flow_dynip`（ip.src range + flows=3，断言 `ip.src` 三值出现）。
- **断言面**（G-ICMP-12）：`icmp_ttl_assert`（ip.ttl=64 缺省 + 显式覆盖）；`icmp_data_boundary`（data 空/1B/最大界——最大界需先修上界守卫）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| **G-ICMP-1** | **pattern 步 code 无 validator 分支**：validateLayer 只查步 type（layer_gen.go:70-74）；探针实证 `{"pattern":[{"type":8,"code":1,…}]}` 放行且上包 code=1（顶层 code=1 却拒，#6）——与 RFC 792 Echo code 恒 0 相悖的不一致面 | **代码阶段**：validateLayer 补步 code 分支（锚词建议 `icmp pattern step %d code must be 0 for Echo, got %d`）+ 失败用例先行；**P4 必做** |
| **G-ICMP-2** | **IPv6 族混不拒**：legacy Validate 只查 `net.ParseIP`（icmp.go:37-44）；探针实证 `[ip(v6),icmp]` 静默产 2 帧 EtherType 0x86dd + NextHeader=1 + **v4 式校验和**（线上无效帧；icmpv6 有对称 v4 拒，族守卫不对称） | **代码阶段**：validateLayer 补 v4 族守卫（锚词建议镜像 icmpv6）+ 负例 `icmp_neg_v6_family`；**P4 必做** |
| **G-ICMP-3** | **`[ip,{tcp,udp},icmp]` 夹层链静默 0 包**：isRawIPChain 遇 tcp/udp 返回 false（chain_planner_util.go:44-51）→ 事件分支 → `GenEvents()`=nil（layer_gen.go:24）→ 0 包无错（探针 tcp/udp 双实证）；rtsp G-RTSP-2 同款 | **代码阶段**：isRawIPChain 的 icmp 分支加"链含 tcp/udp 也走 raw"或 GenEvents 返回显式错；**P4 不得只补用例不改代码** |
| **G-ICMP-4** | **引擎直调路径不判死 t7/t8 两门**：CheckProtoFlat 仅 schema create（semantic.go:130）+ batch（convert.go:166）调用，`MapToFlowSpec` 无 icmp ValidationErrors 分支（顶层子映射 universal 段 :455 先于 translate 填 spec 静默赢层配置）；checkLayerChainStaticCopy 仅 schema——离线链执行器（直调 SubmitTask）实测 t7/t8 失守（`expected generation error, got success`，layer_chain_suite_test.go:331）。生产 MCP 路径两门均在，存量 0 行 | B′ 登记（引擎直调/嵌入面）：等框架级引擎侧 presence/static 门；**不建离线负例**（会假绿）；icmp 不补入离线套件 chainSuiteProtos（同 rtsp 口径） |
| **G-ICMP-5** | **file_source 层链不可达**：registry 6 键无该键 + translate ③ C 类不映射；flat 判死后 MCP 不可达；单测面 6 例保留（icmp_filesource_test.go） | **明确不解决**（层链文件载荷面）；单测面保留不冒充链覆盖 |
| **G-ICMP-6** | **非 Echo 型不编排**（type 3/4/5/11/12/13/14/15/16 + 扩展码）：D-ICMP-1 裁定 6 B′ 账本；validator type 锚拒；§3.4 规范面列出仅供参照，**不得声称可生成** | **明确不解决**（生成器范围=Echo 探测面）；若未来实现须新增独立 builder 分支 + 重算全部面 |
| **G-ICMP-7** | **动态/多流正例零覆盖**：ip 层 src/dst/ttl 动态开（红⑤单测面）+ flows=N 正例今日 0 例（t8 只覆盖拒绝面） | A′ 补例 `icmp_multi_flow_dynip`（§13） |
| **G-ICMP-8** | **结果产物 pcap 缺失**：`protocol-pcap-test/icmp.md`（tracked，末次提交 `1b4e440` 2026-09-22）正例 4 链接指向 `icmp/*.pcap`，目录不存在（git ls-files 0 行）；**非过期产物**（晚于判死提交 `0417be5`，G-PCEP-11 口径不适用），属**缺失类**（G-RTSP-6 口径）；本车道未跑 MCP 套件，不以任何形式引用该 8/8 作为"今日已复跑" | **代码阶段**（P5 重跑套件后补 pcap 留档）；本版不删不改 tracked 产物 |
| **G-ICMP-9** | **三条合法路径零套件用例**：type=0 显式单发（探针 n=1）/ pattern 混型步 8+0（探针 n=3）/ pattern 空数组回退（探针 n=2）；单测面在案（TestF7_NonEchoType…/TestICMPPlan_PatternMixedTypes/TestICMPPlan_PatternEmptyFallsBackToLegacy） | A′ 补正例（§13）；**不得建负例**（探针实证合法） |
| **G-ICMP-10** | **两个 validator 分支套件零覆盖**：pattern 步 type 锚（红④单测面）/ HasLayerDynIP 豁免（红⑤单测面）——分支专属红例教训（D-ICMP-1 修轮 M2）的套件面欠账 | A′ 补例（§13） |
| **G-ICMP-11** | **t2 notes[0] 陈旧值**：首行 "reply(0000) → 0x192f" 与帧钉 `21 2d`（0x212D）矛盾——notes[1] 已自纠（"首算 192f 误 → pcap 实测 212d"）但首行残留误导（本车道反码复算证实 0x212D 正确，§3.2） | **P4 必做**：改写 t2 `expect.notes`（删 192f 陈旧值，保留对拍算式） |
| **G-ICMP-12** | **断言/边界面欠账**：①data>65507 时 IPv4 total length uint16 截断无守无例；②`icmp.checksum.status`/`ip.ttl` 今日零断言；③最小帧（data 空）零例 | A′ 补（上界守卫需先修代码，失败用例先行） |
| **G-ICMP-13** | **第三源未取到**：真实内核 ping 线字节未抓包对照；RFC 1122 §3.2.2 / RFC 1812 §4.3.3.1 扩展 Code 出处未逐条核对 | 待确认：抓 Linux ping 包对照 / 拉两 RFC 原文；确认前按实现钉、不声称合规（§3.4 扩展行已标待核） |

## 15. 修订记录

- v1.0.0（2026-09-29，批次二文档车道）：**icmp 首份独立设计契约**（无前序稿；§0 校正对象为内部契约 D-ICMP-1 + 结果产物 + 代码事实三源，8 项校正含 4 项**本车道探针新发现**——步 code 不查、v6 族混不拒、夹层静默 0 包、三合法路径零套件例）。as-built 逆向定稿：线格式逐字段到帧偏移（§3，含 RFC 792 Type/Code 全表与 as-built 收窄声明）；**校验和覆盖面与 ICMPv6 伪首部差异逐条对照（§3.2）+ 存量 6 帧反码复算对拍全 OK**；五件套含 raw-IP 族豁免声明与防双换方向语义（§5.3/§12.3）；门1 十四行 + §12.1/§12-P2/§12.3/§12.12 强制展开；规范矩阵八项 + 子表①②③（8 格/27 行/7 行逐格重数闭合，总 50 点 = 覆 25 + 不适用 9 + 开放 16）；缺口 **G-ICMP-1…G-ICMP-13**（含 2 项 P4 必做、3 项"明确不解决"）；覆盖反查门建议 10 条（9 绿 1 红，如实标红）。**本车道今日实跑**：离线链套件 6/8（临时空导入已回滚，零 `.go`/cases 改动；t7/t8 create-time 门面如实声明）+ coverage_gate 18/18 + 探针 9 项。自审 3 轮，末轮干净。

# #114 pptp（PPTP 点对点隧道协议，RFC 2637）设计契约

> 版本：v1.0.0（P-PIPE 文档轨批次二 as-built 定稿）
> 日期：2026-09-29
> 车道：文档轨（#114 pptp 续号；本批 10 协议 as-built 文档之一）
> 存量用例：`trafficgen/test/protocol_pcap/cases/pptp.json`（**20 例 = 13 正 + 7 负**，ID/顺序/包数/断言逐条机读实测；**顶层键已是纯层链形，零残留**——本协议无 §1 迁移工作量，见 §12.1）
> 规范基线：① **RFC 2637**（Point-to-Point Tunneling Protocol，1999-07，全文 3195 行本地实读，逐节标注）；② RFC 1661 §6（PPP 帧封装，数据面内层）；③ RFC 791/792/793/768（内嵌 IPv4/ICMP/TCP/UDP 头与校验和）；④ **参考 pcap 实证**：`/home/pcap_auto/llcj_mirror/IP-TCP-10.6.2.41-20.6.2.41-49194-1723-12-10-1260-980.pcap`（22 帧，本机 tshark 3.6.14 逐帧复核，§3 全部默认值的唯一权威）；⑤ 本仓库落码（`internal/protocol/pptp/` 三文件 2167 行 + `internal/core/builder.go` GRE-PPTP 分支 + 接线，§11）；⑥ 本机 tshark 3.6.14 `pptp.*` 字段表（58 字段实测）。
> 白话一句：**PPTP 是"打电话建立一条隧道，然后在隧道里跑 PPP 包"——先用 TCP 1723 这条"控制线"互相打招呼、点名要一路电话（SCCRQ→SCCRP→OCRQ→OCRP），再用 IP 协议号 47 的增强 GRE 把 PPP 帧（FF 03 + 0x0021 + 内嵌 IPv4）一节一节送过去，最后逐路挂断（CCRQ/CCDN）、整条线收线（StopRQ/StopRP）。**

## 0. 沿革与旧稿校正声明（门1 必答：基线继承关系）

本 #114 是 **pptp 的续号契约**，不是新协议。pptp 此前**没有** `NN-pptp-*.md` 设计/用例文档——其既有契约形态是 `docs/CODE_DESIGN.md` 的 **D-PPTP-1**（`CODE_DESIGN.md:3040` 起，P1+P2 定稿 2026-09-20 + P4/P5/P6 执行记录）。本版**承 D-PPTP-1 的全部裁定与实测结论**（裁定 1–4、51 Fields、T-PPTP-1…20 清单、P6 复审记录），并按 `protocol-doc-requirements.md` v1.3 补齐两份独立文档的结构要求。校正与继承逐条如下：

| # | D-PPTP-1 说法 | HEAD 实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | 契约形态 = `CODE_DESIGN.md` 单节（P1 矩阵 + 裁定 + T 清单 + 执行记录）；无独立 design/testcase 文档、无门1 十四行表、无五层覆盖展开、无缺口登记表、无覆盖反查门建议行 | — | **结构缺口**，本版按 §12/§4/§14/testcase §9 补齐 |
| 2 | P1 矩阵「控制连接：TCP 1723（§1.2）；控制消息头 8B（Length+Type+Magic+ControlType）」 | **头是 12B 不是 8B**：RFC 2637 §2 原文明确"8 octet fixed header"含 Length(2)+MsgType(2)+Magic(4)=8，**其后另接** Control Message Type(2)+Reserved0(2) 共 12B；实测参考 pcap 帧 4 TCP 载荷首 12B = `00 9c 00 01 1a 2b 3c 4d 00 01 00 00` | **P1 矩阵"8B"是 RFC 原文的"固定头"口径，不是本实现的控制头总长**；本版 §3.1 按 12B 钉（`controlHeader`，`planner.go:167`） |
| 3 | 裁定 1：「raw 自驱 wrap legacy（自建 TCP+GRE 数据面原样保留），layer_gen 防双换 Direction=up」 | `layer_gen.go:52` 逐包 `pkt.Direction = "up"`；`Generate` 调 `NewPlanner().Plan` 后经 `req.Emit` 重发 | 一致 ✓（本版 §11.4 逆向定稿） |
| 4 | 裁定 2：「registry 行 **51 Fields**（parsePPTPConfig 顶层键全集逐键登记）」 | 机读实测 registry pptp 行 **51 个 Fields 键**；`parsePPTPConfig`（`strategy_convert.go:3989`）顶层键 **50 个**（`inner_ip` 经嵌套 `parsePPTPInnerIP(m["inner_ip"])` 在 `:4044` 单独处理，非 `getX(m,"key")` 形）= 50 + `inner_ip` = **51 消费面，零差** | 一致 ✓（本版 §12.13 逐键对账） |
| 5 | P5 执行记录：「26 帧全序（3 握手 + SCCRQ 156/SCCRP 156/OCRQ 168/OCRP 32 + SLI×5 + GRE×5 + CCRQ/CCDN 合并 164/CCDN 148/StopRQ/RP + 挥手 4）」 | 参考 pcap 实测 22 帧（本仓多补 TCP ACK/FIN 序）；`cases/pptp.json` `pptp_full_session_ref` = **26**（§9 公式复算一致） | 一致 ✓（本版 §9 给可复算公式） |
| 6 | P2 errata：「tunnel_only = 隧道建立+**拆除**（无数据面——emitDataPlane 仅 full/data_only 触发 planner.go :665/:605）」 | `planner.go:665` `if scenario == "full"` 包住 `emitDataPlane`；`:644` `if scenario == "full" \|\| "control_only"` 包住 SLI；`:673-676` 拆除段**无场景门**恒执行 | 一致 ✓；**`tunnel_only` 语义 = "无 SLI + 无数据面 + 有拆除"**，比其字面名更窄（本版 §5 诚实声明） |
| 7 | 裁定 3：「场景强度全额：15 消息面……负例 **7 锚**（role/scenario/calls/sli_count/data_frames/down_data_frames/sub_address hex/64B 超长/inner IP）」 | 负例实为 **7 例**；`data_frames`/`down_data_frames` 两锚**无独立用例**（`planner.go:132-137` 两分支存在）；`incoming_call`/`wen` 两键**零用例**（`planner.go:639/661` 两分支存在） | **裁定 3 的"7 锚"枚举本身列了 9 项（含 data_frames/down_data_frames）**——存量实为 7 例，两者不等；未入例的 4 分支入 G-PPTP-2 |
| 8 | P6 复审：「负例 7 锚真实拦截面逐个核可达（role/scenario/sub_address/64B/inner IP = planner 锚；calls/sli_count = registry V9 先拦）」 | 机读复核：`calls=-1`/`sli_count=-1` 在**链路径**被 `complete.go:325` 范围门拒（`layer "pptp" field "calls" = -1 invalid: not a numeric value in [0,65535]`），**`planner.go:127`（条件在 `:126`）的 `invalid pptp calls %d` 分支在链路径不可达**（parse 期 `getIntPresence` 已把 -1 收下，但 registry 范围门先行） | 一致 ✓；**`error_contains` 因此写 `calls`/`sli_count`（字段名子串）而非 planner 文案**——本版 §7 按真实拦截面钉死 |
| 9 | 存量 `pptp_scenario_tunnel_only` 的 `expect.notes`：「tunnel_only=隧道建立+**数据面**（无控制拆除）」 | 同 #6：实测 tunnel_only **无数据面、有拆除** | **存量 notes 文案与实现相反**（`planner.go:644/665`）；P2 errata 已改 JSON summary，但 **`expect.notes` 未同步**（G-PPTP-1，P4 改写文案；**本版不改 JSON**） |
| 10 | 存量 `pptp_full_session_ref` 的 `expect.notes`：「包 13-17 = GRE 数据面（IP proto 47 无 TCP 端口，**data_frames 缺省 5**）」 | 缺省 `data_frames=3` + `down_data_frames=2` = **5 帧 GRE**（3 up + 2 down）；`parsePPTPConfig` 实测 `getIntPresence(m,"data_frames",3)` / `(m,"down_data_frames",2)` | **"缺省 5"把两个字段之和当成了 `data_frames` 单值**——结论（5 帧 GRE）正确，表述误导；本版 §9 拆写为 3+2（G-PPTP-1 附注） |
| 11 | 存量 `pptp_sli_count_three` 用 `min_packets: 20`，notes 写「SLI×3 → 总包数 22-2=20」 | 公式复算 = **24**（§9）；结果产物 `docs/protocol-pcap-test/pptp.md` 记 `sli_count_three` **Packets 24** | **存量断言是下限而非等值**：`20` 为真但**比实测 24 松 4**，且 notes 的"22-2"算式错（把 full 基准 26 当成 22）→ G-PPTP-1（P4 收窄为 `packet_count: 24`） |
| 12 | 存量 `pptp_inner_ip_explicit` **无 `packet_count`**，仅 `has_handshake/terminates/notes` | 该例 `scenario=tunnel_only` + `data_frames=1`；实测结果产物记 **Packets 16**；公式复算 16 ✓ | **断言缺失**（唯一一个既无 `packet_count` 也无 `min_packets` 的正例）→ G-PPTP-1（P4 补 `packet_count: 16`） |
| 13 | 存量 `pptp_control_header_magic` frames 断言「offset 54 = eth14+IP20+TCP20」 | 实测 pcap **无 VLAN/IP options/TCP options**，以太帧 14+20+20 = **54** ✓；帧 4/5 hex 与参考 pcap 逐字节一致 | 一致 ✓（本版 §2/§3.1 钉偏移） |
| 14 | 存量 `pptp_data_both_directions` frames 断言「packet 13 offset **34** hex `30 81 88 0b`」 | 实测：GRE 帧 offset **34 = 14（以太）+ 20（外层 IPv4）**，即 GRE 头起点 ✓（GRE 帧无 TCP 层） | 一致 ✓（**两个不同偏移基**：TCP 控制帧 54、GRE 数据帧 34，本版 §2 显式并列） |
| 15 | 存量 `pptp_full_session_ref` `fields` 11 条（`tcp.dstport` ×1 + `tcp.len` ×10） | 机读实测 11 条；`tcp.dstport=1723`（包 1）；`tcp.len` = 156/156/168/32/24/16/164/148/16/16（包 4/5/6/7/8/18/19/20/21/22） | 一致 ✓；**`pptp.*` tshark 字段今日零使用**（58 字段可用）→ G-PPTP-3 |
| 16 | D-PPTP-1 称「GRE 增强头：16B、flags 0x3081、proto 0x880B、Key=Len+peer Call ID、32bit Seq/Ack」 | `builder.go:827-840`：flags = `0x2000\|0x1000\|0x0001`（K\|S\|Ver=1）+ A 位 `0x0080`（AckPresent）→ **0x3081**；`fillPPTPGRE`（`:925`）回填 Payload Length 到 Key 高 16 位 | 一致 ✓；**A 位 = bit 8（0x0080）不是 RFC 1701 的 bit 5**（`planner.go:55-59` 注释 + RFC 2637 §4.1 原文 "A (Bit 8)" 双向确认，本版 §3.7 钉） |
| 17 | D-PPTP-1 裁定 4（B′ 账本）：「MS 客户端缺省 Host/Vendor 待确认、interleaved GRE over TCP、ICRQ 族 PAC 侧现网形、动态字段旁挂」 | `resolveDefaults` 实测 `hostName` 缺省 **空串**、`vendorName` 缺省 **"Microsoft"**（`planner.go:801-805`），**不是** B′ 注记里设想的 "machine"/"Microsoft Windows NT" | **B′ 注记的 MS 缺省未落码**；缺省值是"Host 空 + Vendor Microsoft"（参考 pcap 帧 4/5 实测 host_name 空、vendor "Microsoft"）→ G-PPTP-4 |
| 18 | D-PPTP-1 裁定 3：「15 消息面（full 场景逐消息 + scenario 四枚举）」 | 机读实测：**15 个消息类型常量**（`planner.go:39-53`，`msgSCCRQ…msgSLI`）+ **15 个消息构建函数**（`buildSCCRQ`/`buildSCCRP`/`buildOCRQ`/`buildOCRP`/`buildSLI`/`buildCCRQ`/`buildCCDN`/`buildStopRQ`/`buildStopRP`/`buildECRQ`/`buildECRP`/`buildICRQ`/`buildICRP`/`buildICCN`/`buildWEN`；另有 `buildInnerIPv4Packet` 非消息函数）；**`buildCCRQ` 同时服务 msg 12 与合并段** | 一致 ✓（15 消息类型常量齐，15 个消息 `build*` 齐） |
| 19 | 结果产物 `trafficgen/docs/protocol-pcap-test/pptp.md` 写「Cases: 20 — pass 20, fail 0, error 0」 | 末次提交 `08b8738b`（**2026-09-20 20:34**），**晚于**判死提交 `0417be5`（2026-09-13）✓；但 `docs/protocol-pcap-test/pptp/` **目录不存在（0 个 pcap 文件）**，表内 13 个正例的 `[pcap](pptp/*.pcap)` 链接**全部悬空** | **产物未过期（晚于判死提交），但 pcap 留档缺失**：20/20 数字**未经今日复跑证实**、且**无任何 pcap 文件可查** → G-PPTP-5（归属代码阶段 P5 重跑后重生成；本车道未跑该套件，不以任何形式引用该数字作为"今日已跑通"证据） |

**依赖链判定纪律**：以上均为可判题（RFC 原文 / 参考 pcap 实测 / 落码三级对照），直接判定，不问偏好。#2/#9/#10/#11/#12/#17 为**确认的存量缺陷候选**（文档侧记录、代码阶段修），本版**不改任何 JSON 与代码**（任务书边界）。

## 1. 范围、profile 与实现状态边界

本版定义 **PPTP 隧道会话（TCP 1723 控制面 + 增强 GRE 数据面）在单一 flow 内的完整生成**：控制连接建立（SCCRQ/SCCRP）、呼叫建立（OCRQ/OCRP；可选 ICRQ/ICRP/ICCN）、PPP 会话控制（SLI×N；可选 WEN）、数据面（GRE + PPP + 内嵌 IPv4）、呼叫拆除（CCRQ/CCDN）、控制连接拆除（StopRQ/StopRP）。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `pptp_pns_v1`（主，`role=pns` 缺省） | TCP 1723 控制面 + 外层 IPv4 proto 47 数据面 | 全生命周期（§5 状态机） | 真实 PAC 应答、真实拨号/电话网 |
| `pptp_pac_v1`（`role=pac`） | 同上，方向与 Call ID 归属反转 | 同上 | 真实 PNS 应答 |
| `pptp_ipv6_hosts_v1` | 同上，外层 IPv6 | 同上（控制面帧 offset 74） | 从 IPv4 fixture 推导 IPv6 地址 |

显式边界（"不实现、不声称、不许静默转换"）：

1. **不实现真实对端语义**——生成器按模板回灌控制消息，不解析对端 SCCRP 的版本协商（RFC 2637 §3.1.1 "Version OK / Not OK" 两分支**不建模**），不做 TCP 碰撞处理（§3.1.3 不实现）。
2. **不实现真实密码学/认证**——PPTP 的 PPP 层认证（MS-CHAP/MPPE，RFC 2637 §5）**完全不在本版**：数据面只承载明文 PPP 帧，不产 MPPE 加密载荷。
3. **不实现控制连接保活定时器**——RFC 2637 §3.1.4 的 60 秒 Echo 定时器不建模；`echo=true` 是**配置驱动的固定插入**（ECRQ/ECRP 各一帧），不是定时器触发。
4. **不实现 GRE 的 C/R/s/Recur 位**——PPTP 模式下恒为 `K=1 S=1 A=(AckPresent) Ver=1`；`builder.go:525-537` 显式**拒绝**组合标准模式的 Checksum/RoutingPresent/KeyPresent/SequencePresent（矛盾而非省略）。
5. **不实现内嵌 IPv6**——PPP 内层只支持 IPv4（`pppProtoIPv4=0x0021`；`PPTPInnerIP` 注释明写 "Only IPv4 inner packets are supported"）；`proto` 只接受 1/6/17（`planner.go:154`）。
6. **不实现 TCP 分片/重组**——控制面消息恒单段（MSS 1460 远大于最大 168B 控制消息；唯一可能跨段的是 `inner_ip.payload` 撑大的 GRE 帧，但 GRE 帧不经 TCP）。
7. **不声称 GRE 数据面参与 TCP 序列空间**——GRE 帧与 TCP 控制流**无序号关系**（独立 IP proto 47），`PacketIndex` 全局连续仅用于 resequencer 排序。

**实现状态（2026-09-29 实测）**：`pptp` 层已注册（`layers/registry.go:1945`，`CategoryTerminal`，`DependsOn ["ip"]`，**Fields 51 键**）；生成器/校验器已落码（`internal/protocol/pptp/` 三文件：`planner.go` 1075 行 / `layer_gen.go` 67 行 / `planner_test.go` 1004 行，27 个 `Test*`）；GRE-PPTP 线字节住在 `internal/core/builder.go:827-841` + `fillPPTPGRE:925`；`allowedProtocols["pptp"]=true`（`protocols.go:51`）；层内 translate 已接线（`chain_planner_translate.go:2798`，经 `core.ParsePPTPConfigFromMap` 单一真相）；`FlowMeta.PPTP` 注入（`chain_planner.go:1524`）；raw 链双名单（`chain_planner_util.go:54/57` + `chain_planner.go:996`）；控制通道 1723 由生成器 `Plan` 缺省（`planner.go:404`，0-keep 豁免）；链级测试 2 例（`pptp_chain_test.go:17/60`）；20 语义用例已落 `cases/pptp.json`。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`/`tcp.len`、frames 原始 hex @offset 54（控制）/34（GRE）、`packet_count`）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）。**不设仅单路径可用的断言**。**存量 20 例 NIC 路未跑**（结果产物无 NIC 记录，D-PPTP-1 性能段注明"网卡路未跑"）→ G-PPTP-5 附注。

## 2. 协议栈、端口与固定偏移

**双通道结构（本协议的核心特殊性）**：

```
TCP 1723 控制通道（应用层字节流，由 pptp 层自建 TCP 握手/挥手）
    ↓ 控制消息（12B 头 + 消息体）
─────────────────────────────────────────────────────────────
GRE 数据通道（外层 IPv4，Protocol=47，无 TCP/UDP 端口）
    ↓ 16B 增强 GRE 头（flags 0x3081 / proto 0x880B / Key / Seq / Ack）
    ↓ PPP 帧（FF 03 + Protocol 0x0021）
    ↓ 内嵌 IPv4 包（完整 IP 头 + L4 + payload）
```

**关键结论：PPTP 的两条通道在生成器里是同一个 flow 的两类帧，但线格式完全异构**——控制面帧有 TCP 头（可断言 `tcp.dstport=1723`、`tcp.len`），数据面帧**没有传输层端口**（IP proto 47，只能断言 `ip.proto` 与 GRE 头字节）。任何"每帧都有 1723"的断言都是错的（D-PPTP-1 P4 复审抓到的真实口径错，`pptp_chain_test.go:45-49` 已修正为控制面帧限定）。

推荐层链为 `[ip, pptp]`（**唯一形状**；pptp 是 raw-IP 终结层，`DependsOn ["ip"]`，自带 TCP 载体，**不写 `tcp` 层**）。存量 20/20 例层链均为 `[ip, pptp]`（机读实测）。

**端口**：控制连接 TCP **1723**（RFC 2637 §1.2）。链路径层 config **无端口位**（pptp 层 Fields 无 `src_port`/`dst_port`），`spec.DstPort==0` 合法（`chain_planner.go:789` 0-keep 名单），由生成器 `Plan` 在 `spec.DstPort==0` 时补 1723（`planner.go:404-406`）。源端口由 worker 按 `DefaultSrcPort(12345) + i` 注入（多流递增）；单流时 `spec.SrcPort` 原值（可能为 0，legacy 同口径直传）。

**固定偏移**（无 VLAN/IP options/TCP options）：

| 帧类 | 载荷起点 | 算式 |
|---|---:|---|
| TCP 控制帧（IPv4） | **54** | 14（以太）+ 20（IPv4）+ 20（TCP） |
| GRE 数据帧（IPv4） | **34**（GRE 头起点） | 14（以太）+ 20（外层 IPv4）；**无 TCP 层** |
| TCP 控制帧（IPv6） | **74** | 14 + 40 + 20 |
| GRE 数据帧（IPv6） | **54**（GRE 头起点） | 14 + 40 |

**内嵌（PPP 内层）IPv4 包的偏移不固定**——它跟在 16B GRE 头 + 4B PPP 头之后，起点 = 34 + 16 + 4 = **54**（IPv4 外层）；其内部字段偏移按 §3.7 递推，**且内层 payload 变长则后续偏移不稳**。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**本协议存量 20 例已是此形，无需迁移**）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"pptp": {}}
  ]
}
```

空 `pptp` 层 config = 全默认 = 参考 pcap full 形（26 帧）。带参样例：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"pptp": {
      "role": "pns", "scenario": "full", "calls": 2, "echo": true,
      "sli_count": 3, "data_frames": 2, "down_data_frames": 1,
      "inner_ip": {"src_ip": "192.168.1.10", "dst_ip": "10.10.0.5", "payload": "inner-pkt"}
    }}
  ]
}
```

多流样例（数量只走 `flow_control`；本协议存量未用，四元组留空走 worker 保底递增 §12.12）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"pptp": {"scenario": "full"}}
  ],
  "flow_control": {"flows": 3}
}
```

## 3. 线格式编码（逐字段、字节偏移、总长公式；全部对参考 pcap 实测）

### 3.1 控制消息固定头（12 字节，`controlHeader`，`planner.go:167-174`）

| 偏移 | 字段 | 类型/尺寸 | 端序 | 值 |
|---:|---|---|---|---|
| 0 | Length | uint16 | 大端 | **= 12 + len(body)**（含整个 PPTP 头，RFC 2637 §2） |
| 2 | PPTP Message Type | uint16 | 大端 | **恒 1**（Control Message；RFC 2637 §2 表） |
| 4 | Magic Cookie | uint32 | 大端 | **恒 0x1A2B3C4D**（RFC 2637 §2） |
| 8 | Control Message Type | uint16 | 大端 | 1…15（§3.2 表） |
| 10 | Reserved0 | uint16 | — | **恒 0**（RFC 2637 §2.1 "MUST be 0"） |

**总长公式**：`帧长 = 12 + len(body)`；**Length 字段 = 帧长**（不含以太/IP/TCP 头）。实测钉：SCCRQ/SCCRP 帧 4/5 首 12B = `00 9c 00 01 1a 2b 3c 4d 00 01 00 00` / `…00 02 00 00`（`00 9c` = 156 = 12+144，msgType 1/2）✓。

> **RFC 原文口径 vs 实现口径（重要，防误读）**：RFC 2637 §2 说"each PPTP Control Connection message begins with an **8 octet fixed header**"，指的是 **Length+MsgType+Magic 这 8 字节在 15 条消息模板里位置恒定**；紧接其后的 Control Message Type(2)+Reserved0(2) 也是固定位置，故**实现统一按 12B 头 + body 建模**（`controlHeader` 写满 12B，body 从偏移 12 起）。两者不矛盾，但引用时须写清（D-PPTP-1 P1 矩阵的"8B"是前者）。

### 3.2 控制消息类型表（RFC 2637 §2 原文，`planner.go:39-53` 常量逐条）

| Code | 名称 | 方向（本实现） | 构建函数 | 帧长 |
|---:|---|---|---|---:|
| 1 | Start-Control-Connection-Request | PNS→PAC | `buildSCCRQ` | 156 |
| 2 | Start-Control-Connection-Reply | PAC→PNS | `buildSCCRP` | 156 |
| 3 | Stop-Control-Connection-Request | PNS→PAC | `buildStopRQ` | 16 |
| 4 | Stop-Control-Connection-Reply | PAC→PNS | `buildStopRP` | 16 |
| 5 | Echo-Request | PAC→PNS | `buildECRQ` | 16 |
| 6 | Echo-Reply | PNS→PAC | `buildECRP` | 20 |
| 7 | Outgoing-Call-Request | PNS→PAC | `buildOCRQ` | 168 |
| 8 | Outgoing-Call-Reply | PAC→PNS | `buildOCRP` | 32 |
| 9 | Incoming-Call-Request | PAC→PNS | `buildICRQ` | 220 |
| 10 | Incoming-Call-Reply | PNS→PAC | `buildICRP` | 24 |
| 11 | Incoming-Call-Connected | PAC→PNS | `buildICCN` | 28 |
| 12 | Call-Clear-Request | 双向（见 §5） | `buildCCRQ` | 16 |
| 13 | Call-Disconnect-Notify | 双向（见 §5） | `buildCCDN` | 148 |
| 14 | WAN-Error-Notify | PAC→PNS | `buildWEN` | 40 |
| 15 | Set-Link-Info | 交替（见 §5） | `buildSLI` | 24 |

**消息长度公式汇总**（body = 帧长 − 12）：

| 消息 | body 公式 | 数值 |
|---|---|---:|
| SCCRQ | `2+2+4+4+2+2+64+64` = 144 | 156 |
| SCCRP | `2+1+1+4+4+2+2+64+64` = 144 | 156 |
| StopRQ | `1+1+2` = 4 | 16 |
| StopRP | `1+1+2` = 4 | 16 |
| ECRQ | `4` | 16 |
| ECRP | `4+1+1+2` = 8 | 20 |
| OCRQ | `2+2+4+4+4+4+2+2+2+2+64+64` = 156 | 168 |
| OCRP | `2+2+1+1+2+4+2+2+4` = 20 | 32 |
| ICRQ | `2+2+4+4+2+2+64+64+64` = 208 | 220 |
| ICRP | `2+2+1+1+2+2+2` = 12 | 24 |
| ICCN | `2+2+4+2+2+4` = 16 | 28 |
| CCRQ | `2+2` = 4 | 16 |
| CCDN | `2+1+1+2+2+128` = 136 | 148 |
| WEN | `2+2+4×6` = 28 | 40 |
| SLI | `2+2+4+4` = 12 | 24 |

### 3.3 SCCRQ / SCCRP（RFC 2637 §2.1 / §2.2）

**SCCRQ**（`buildSCCRQ`，`planner.go:188-198`），body 144B：

| body 偏移 | 字段 | 尺寸 | 端序 | 缺省值（= 参考 pcap 实测） |
|---:|---|---:|---|---|
| 0 | Protocol Version | 2 | 大端 | `0x0100`（1.0，RFC 2637 §2 "current value 0x0100"） |
| 2 | Reserved1 | 2 | — | 0（**未显式写，`make` 零值**） |
| 4 | Framing Capabilities | 4 | 大端 | `1`（bit0 = async，RFC 2637 §2.1） |
| 8 | Bearer Capabilities | 4 | 大端 | `1`（bit0 = analog） |
| 12 | Maximum Channels | 2 | 大端 | `0` |
| 14 | Firmware Revision | 2 | 大端 | `0` |
| 16 | Host Name | 64 | ASCII，NUL 补齐 | 空串（全 0） |
| 80 | Vendor String | 64 | ASCII，NUL 补齐 | `"Microsoft"` |

**SCCRP**（`buildSCCRP`，`planner.go:203-215`），body 144B——**与 SCCRQ 的唯一结构差异是偏移 2/3 拆成两个 1 字节字段**：

| body 偏移 | 字段 | 尺寸 | 缺省值 |
|---:|---|---:|---|
| 0 | Protocol Version | 2 | `0x0100` |
| 2 | Result Code | **1** | `1`（Successful channel establishment，RFC 2637 §2.2） |
| 3 | Error Code | **1** | `0`（None，RFC 2637 §2.16） |
| 4 | Framing Capability | 4 | `2`（bit1 = sync） |
| 8 | Bearer Capability | 4 | `3`（bit0\|bit1 = analog\|digital） |
| 12 | Maximum Channels | 2 | `0` |
| 14 | Firmware Revision | 2 | `0x0ece`（3790，**参考 pcap 实测值**） |
| 16 | Host Name | 64 | 空串 |
| 80 | Vendor String | 64 | `"Microsoft"` |

**实测钉（参考 pcap 帧 4/5 原始字节）**：帧 4 body @54 `00 00 01 00 00 00 00 00 00 01 00 00 00 01 00 00`（version `0100`、framing `1`、bearer `1`）；帧 5 body @54 `00 00 01 00 01 00 00 00 00 02 00 00 00 03 00 00 0e ce`（version `0100`、result `01` error `00`、framing `2`、bearer `3`、firmware `0ece`）。tshark 解出：帧 4 framing_capabilities=1/bearer=1/max_channels=0/firmware=0/vendor="Microsoft"；帧 5 result=1/error=0/framing=2/bearer=3/firmware=3790 ✓。

**Error Code 表（RFC 2637 §2.16，供 `scrp_error`/`ccdn_error`/`ocrp_error`/`stop_error` 取值）**：0 None / 1 Not-Connected / 2 Bad-Format / 3 Bad-Value / 4 No-Resource / 5 Bad-Call ID / 6 PAC-Error。

### 3.4 OCRQ / OCRP（RFC 2637 §2.7 / §2.8）

**OCRQ**（`buildOCRQ`，`planner.go:220-234`），body 156B：

| body 偏移 | 字段 | 尺寸 | 缺省值 |
|---:|---|---:|---|
| 0 | Call ID | 2 | `0xa9c0`（43456，**PNS 自己的 id**） |
| 2 | Call Serial Number | 2 | `3` |
| 4 | Minimum BPS | 4 | `300` |
| 8 | Maximum BPS | 4 | `100000000` |
| 12 | Bearer Type | 4 | `3` |
| 16 | Framing Type | 4 | `3` |
| 20 | Packet Recv. Window Size | 2 | `64` |
| 22 | Packet Processing Delay | 2 | `0` |
| 24 | Phone Number Length | 2 | **自动 = `len(phone_number)`**（**不 clamp**，见 §8） |
| 26 | Reserved1 | 2 | 0 |
| 28 | Phone Number | 64 | 空串 |
| 92 | Subaddress | 64 | **参考 pcap 的 16 字节二进制垃圾 + 48 零**（§3.4.1） |

**OCRP**（`buildOCRP`，`planner.go:254-266`），body 20B：

| body 偏移 | 字段 | 尺寸 | 缺省值 |
|---:|---|---:|---|
| 0 | Call ID | 2 | `0x35c9`（13769，**PAC 自己的 id**） |
| 2 | Peer's Call ID | 2 | **实参传入的 PNS id**（`0xa9c0`） |
| 4 | Result Code | 1 | `1`（Connected，RFC 2637 §2.8） |
| 5 | Error Code | 1 | `0` |
| 6 | Cause Code | 2 | `0` |
| 8 | Connect Speed | 4 | `14808325` |
| 12 | Packet Recv. Window Size | 2 | `16384` |
| 14 | Packet Processing Delay | 2 | `0` |
| 16 | Physical Channel ID | 4 | `0` |

**实测钉**：参考 pcap 帧 6 `pptp.call_id=43456`、`phone_number_length=0`、`subaddress` = 二进制垃圾 ✓；帧 7 `call_id=13769 / peer_call_id=43456 / result=1 / error=0 / cause=0 / connect_speed=14808325 / window=16384 / delay=0 / physical_channel_id=0` ✓。

#### 3.4.1 Sub-Address 的三种取值形态（`subAddressBytes`，`planner.go:240-250`）

| `sub_address` 配置 | 线字节 |
|---|---|
| **缺席**（空串） | 参考 pcap 的 `01 1f 42 3a 64 84 e9 4c af 72 89 2a 29 b1 d3 ab` + 48×`00`（`referenceSubAddress`，`planner.go:86`）——**参考实现伪影，逐字节复刻** |
| **十六进制串**（如 `"aabb"`） | hex 解码后**左对齐**写入，其余补 0；超 64B 截断（`copy` 语义） |
| 非法 hex（如 `"zz"`） | `Validate` 拒（锚词 `must be hex`，`planner.go:140`） |

> **注意**：`sub_address="00"` 解出 1 个零字节 + 63 零 = 全零，与"缺席"**不等价**（缺席 = 参考垃圾）。这是有意的：缺省复刻参考 pcap，显式配置则听配置。

### 3.5 SLI / CCRQ / CCDN / StopRQ / StopRP（RFC 2637 §2.15 / §2.12 / §2.13 / §2.3 / §2.4）

**SLI**（`buildSLI`，`planner.go:272-278`），body 12B：`Peer's Call ID(2) + Reserved1(2) + Send ACCM(4) + Receive ACCM(4)`。缺省 `send_accm = receive_accm = 0xffffffff`。

> **SLI 的 Peer Call ID 是本实现最反直觉的一处（参考实现伪影）**：RFC 2637 §2.15 要求 `Peer's Call ID` = 对端的 Call ID。本实现按 **PNS/PAC 交替**发 SLI，并区分 peer id：
> - **PNS 侧发的 SLI**（`i` 为偶数）：peer = **PAC 的 Call ID**（`r.peerCallID + callIdx`）——**符合 RFC**。
> - **PAC 侧发的 SLI**（`i` 为奇数）：peer = **PNS 侧的 TCP 源端口**（`pnsPort`，参考 pcap = 49194 = `0xc02a`）——**违反 RFC，是参考 pcap 的伪影**（`planner.go:645-659`）。
>
> 实测确认：参考 pcap 帧 8 `Peer Call ID: 13769`（= PAC id，RFC 合规）、帧 9 `Peer Call ID: 49194`（= PNS TCP 源端口，伪影）✓。可用 `sli_peer_call_id` 键覆盖 PAC 侧取值（`planner.go:653-657`，覆盖后 + callIdx）。

**CCRQ**（`buildCCRQ`，`planner.go:282-286`），body 4B：`Call ID(2) + Reserved1(2)`。

**CCDN**（`buildCCDN`，`planner.go:292-299`），body 136B：`Call ID(2) + Result Code(1) + Error Code(1) + Cause Code(2) + Reserved1(2) + Call Statistics(128, 全 0)`。

**StopRQ**（`buildStopRQ`，`planner.go:303-307`），body 4B：`Reason(1) + Reserved1(1) + Reserved2(2)`；`stop_reason` 缺省 `1`。

**StopRP**（`buildStopRP`，`planner.go:311-316`），body 4B：`Result(1) + Error(1) + Reserved(2)`；`stop_result` 缺省 `1`、`stop_error` 缺省 `0`。

### 3.6 ECRQ / ECRP（RFC 2637 §2.5 / §2.6）

**ECRQ**（`buildECRQ`，`planner.go:321-325`），body 4B：`Identifier(4)` = **恒 1**（`echoIdentifier`，`planner.go:64`）。

**ECRP**（`buildECRP`，`planner.go:329-335`），body 8B：`Identifier(4)=1 + Result Code(1) + Error Code(1) + Reserved1(2)`；**result/error 复用 `ocrp_result`/`ocrp_error`**（`planner.go:332-333`）。

> **无参考 pcap**：参考 pcap 不含 Echo 段（RFC 2637 §3.1.4 的 60 秒保活定时器在该 pcap 时间窗内未触发）。故 ECRQ/ECRP 的字节面**来自 RFC 模板 + 实现选择**，非实测钉（本版如实声明；`echo=true` 用例只断包数/方向，不断字节）。

### 3.7 ICRQ / ICRP / ICCN / WEN（RFC 2637 §2.9 / §2.10 / §2.11 / §2.14；PAC 侧，`incoming_call`/`wen` 键）

**ICRQ**（`buildICRQ`，`planner.go:344-356`），body 208B：`Call ID(2) + Call Serial Number(2) + Call Bearer Type(4) + Physical Channel ID(4) + Dialed Number Length(2) + Dialing Number Length(2) + Dialed Number(64) + Dialing Number(64) + Subaddress(64)`。复用 `bearer_type`/`physical_channel_id`/`sub_address`；两个长度字段自动 = `len(dialed_number)`/`len(dialing_number)`。

**ICRP**（`buildICRP`，`planner.go:361-370`），body 12B：`Call ID(2, PNS 分配) + Peer's Call ID(2, PAC 的) + Result Code(1) + Error Code(1) + Packet Recv. Window Size(2) + Packet Transmit Delay(2) + Reserved1(2)`。

**ICCN**（`buildICCN`，`planner.go:375-383`），body 16B：`Peer's Call ID(2) + Reserved1(2) + Connect Speed(4) + Packet Recv. Window Size(2) + Packet Transmit Delay(2) + Framing Type(4)`。

**WEN**（`buildWEN`，`planner.go:388-392`），body 28B：`Peer's Call ID(2) + Reserved1(2) + CRC Errors(4) + Framing Errors(4) + Hardware Overruns(4) + Buffer Overruns(4) + Time-out Errors(4) + Alignment Errors(4)`——六个计数器**恒 0**（RFC 2637 §2.14：仅在错误条件发生时发送）。

> **ICRQ 族与 WEN 今日零用例**（`incoming_call`/`wen` 两键在 20 例中零出现，机读实测）→ G-PPTP-2。ICRQ 的 `Subaddress` 复用同一个 `sub_address` 键（即 ICRQ 与 OCRQ 共享该配置），是实现的耦合点。

### 3.8 GRE 数据面（RFC 2637 §4.1；`builder.go:827-841` + `fillPPTPGRE:925`）

**增强 GRE 头（16B，`AckPresent=true` 缺省）**：

| 偏移 | 字段 | 尺寸 | 值（本实现） | RFC 2637 §4.1 |
|---:|---|---:|---|---|
| 0 | Flags | 2 | **`0x3081`** = C0 R0 **K1** **S1** s0 Recur000 **A1** Flags0000 Ver001 | K=1、S=1、A=1、Ver=1 |
| 2 | Protocol Type | 2 | **`0x880B`**（PPP） | "Set to hex 880B" |
| 4 | Key (HW) Payload Length | 2 | **回填 = 载荷字节数**（不含 GRE 头） | "Size of the payload, not including the GRE header" |
| 6 | Key (LW) Call ID | 2 | **对端的 Call ID**（PNS 侧帧带 PAC id / PAC 侧帧带 PNS id） | "Contains the Peer's Call ID" |
| 8 | Sequence Number | 4 | `0..N-1`（逐方向独立） | "sequence number of the payload" |
| 12 | Acknowledgment Number | 4 | 上行帧 `0`；下行帧 `= N-1`（已收的最高序号） | RFC 2637 §4.2 |

**与基础 GRE（RFC 2784/2890）的差异逐条**（`GREConfig.PPTP=true` 分支，`types.go:3232-3249` + `builder.go:525-537`）：

| # | 维度 | 基础 GRE | PPTP 增强 GRE |
|---:|---|---|---|
| 1 | Flags 位序 | C(0) R(1) K(2) S(3) s(4) Recur(5-7) Flags(8-12) Ver(13-15) | 同字段名，但 **A 位占 bit 8**（基础 GRE 的 bit 8 属 Flags） |
| 2 | A 位语义 | 无 | **Acknowledgment Number 存在位**（`0x0080`） |
| 3 | Protocol Type | 调用方指定（0x0800/0x0806/0x86DD/0x6558） | **强制 0x880B（PPP）**；传其它值即拒（`builder.go:535`） |
| 4 | Key 字段 | 调用方指定的不透明 32 位键 | **高 16 位 = Payload Length（回填）+ 低 16 位 = Call ID** |
| 5 | Checksum(C) | 可选 | **禁用**（传 `Checksum=true` 即拒，`builder.go:526`） |
| 6 | Routing(R) | 可选 | **禁用**（传 `RoutingPresent=true` 即拒，`builder.go:529`） |
| 7 | K/S 位 | 由 `KeyPresent`/`SequencePresent` 控制 | **由模式自管**（传任一即拒，`builder.go:532`） |
| 8 | 头长 | 4 + 各可选字段 | **12（无 Ack）或 16（有 Ack）**（`greHeaderLen`，`builder.go:553-558`） |

> **A 位 = bit 8 的实证链**：RFC 2637 §4.1 原文 "A (Bit 8) Acknowledgment sequence number present"；Linux 内核定义 `GRE_ACK = 0x0080`；Wireshark 仅在 PPP 路径该位为 1 时解出 Acknowledgment Number（`planner.go:55-59` 注释记载）。三源一致，**不是 RFC 1701 的 bit 5**。

**Payload Length 回填机制**（`fillPPTPGRE`，`builder.go:925-932`）：帧组装完成后按 `end − greStart − headerLen` 回填 Key 高 16 位；`headerLen` 由 flags 的 A 位动态判定（12 或 16）——**两遍编码**（先置 0 占位，后回填），与 opcua 的 MessageSize 一次写定不同。

**PPP 帧载荷**（`pppFrame`，`planner.go:893-920`）：

```
FF 03                      ← HDLC Address+Control（RFC 1661 §6，恒 FF 03）
00 21                      ← PPP Protocol = IPv4（RFC 1661 §6）
<内嵌 IPv4 包>              ← 完整 IP 头（含校验和）+ L4 + payload
```

**内嵌 IPv4 包**（`buildInnerIPv4Packet`，`planner.go:926-974`）：

| 字段 | 缺省 | 可配（`inner_ip.*`） |
|---|---|---|
| Version/IHL | `0x45`（v4，5×4B） | 不可配 |
| Total Length | `20 + len(l4)` | 由 payload 推出 |
| Identification | **`ipid+1`**（逐帧递增，`planner.go:914`） | 不可配 |
| Flags | `0x4000`（**DF**） | 不可配 |
| TTL | **64** | `ttl` |
| Protocol | **17（UDP）** | `proto`（只接受 1/6/17） |
| Header Checksum | RFC 791 §3.1 计算 | 自动 |
| Src/Dst IP | `10.10.10.1` / `10.10.10.2` | `src_ip`/`dst_ip` |
| L4 | UDP 8B（**checksum 恒 0**，RFC 768 允许）/ TCP 20B（checksum 计算）/ ICMP 8B（echo request，checksum 计算） | `src_port`/`dst_port`/`payload` |

**逐帧 IPID 唯一性**：`emitDataPlane` 用 `ipidBase + i` 保证同一 call 的 N+M 帧内层 IPID 互异（`planner.go:569-592`）；多 call 时 `ipidBase += dataFrames + downFrames`（`planner.go:667`）。

### 3.9 TCP 载体帧（控制面；`emit` 闭包，`planner.go:462-495`）

控制面帧是**本层自建的 TCP**（不走 tcp 层）：

| 项 | 值 |
|---|---|
| 握手 | SYN → SYN-ACK → ACK（3 帧；`planner.go:610-622`） |
| SYN options | MSS(1460，可用 `spec.TCP.MSS` 覆盖) + Window Scale(7) + SACK-Permitted（`synOptions`，`planner.go:1030-1039`） |
| Window Size | 恒 `65535`（`planner.go:471`） |
| 载荷帧 flags | `0x18`（PSH+ACK） |
| 挥手 | FIN-ACK → ACK → FIN-ACK → ACK（4 帧；`planner.go:683-697`） |
| 分段 | `segmentByMSS`（`planner.go:1009-1026`）：`payload` 按 MSS 切片，空载荷产 1 个空段 |
| 方向换向 | `up`/`down` 闭包对调 MAC/IP/端口（`planner.go:505-510`） |

> **`role=pac` 的换向**：`role` 决定哪一侧是 PNS；`send(side, payload)` 按 `role` 决定该消息是 `up` 还是 `down`（`planner.go:516-530`）。握手/挥手段也整体反转（`planner.go:616-622`/`:690-697`）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明角色、场景模板、呼叫数、SLI 条数、数据帧数，引擎按固定剧本产出帧序列（TCP 握手 → 控制消息按场景模板 → GRE 数据帧 → 拆除 → TCP 挥手）。无运行时刺激响应（除 TCP 握手挥手是自建固定序列外，全为配置驱动）。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 客户端拨号建立隧道（主路径） | SCCRQ→SCCRP→OCRQ→OCRP→SLI×5→数据→CCRQ/CCDN→Stop | #1（`pptp_full_session_ref`） |
| ② 控制连接建立与保活探测 | SCCRQ/SCCRP + ECRQ/ECRP | #9（`pptp_echo_keepalive`） |
| ③ 只建控制通道不跑数据 | `scenario=control_only` | #3（`pptp_scenario_control_only`） |
| ④ 只建隧道不跑数据 | `scenario=tunnel_only` | #4（`pptp_scenario_tunnel_only`） |
| ⑤ 纯数据面（隧道已存在） | `scenario=data_only` | #5（`pptp_scenario_data_only`） |
| ⑥ 服务器侧视角（PAC） | `role=pac` 全序反向 | #6（`pptp_role_pac`） |
| ⑦ 多路并发呼叫（一个隧道多 call） | `calls=N`：OCRQ/OCRP×N + SLI 逐 call | #7（`pptp_calls_two`）、#13（`pptp_composite_full_multi`） |
| ⑧ PPP 会话参数协商 | SLI 条数（ACCM 掩码） | #8（`pptp_sli_count_three`） |
| ⑨ 双向数据流 | `data_frames`/`down_data_frames` | #10（`pptp_data_both_directions`） |
| ⑩ 内网穿透（PPP 内层业务包） | `inner_ip` 显式指定内层 IPv4 | #11（`pptp_inner_ip_explicit`） |
| ⑪ 协商失败/错误码回传 | `scrp_result`/`ocrp_result` 非 0 | #12（`pptp_result_error_fields`） |
| ⑫ 控制头完整性校验 | Magic Cookie / Length / Control Type | #2（`pptp_control_header_magic`） |
| ⑬ 非法配置拒绝 | 7 类负例 | #14–#20 |

**五层覆盖逐层结论**：

- **功能层**——15 消息类型正例落点：#1 承接 9 条（SCCRQ/SCCRP/OCRQ/OCRP/SLI/CCRQ/CCDN/StopRQ/StopRP）、#9 承接 2 条（ECRQ/ECRP）、#6/#7 承接角色与多 call；**ICRQ/ICRP/ICCN/WEN 4 条今日零正例**（`incoming_call`/`wen` 键存在、`build*` 存在）→ G-PPTP-2。错误处理 7 类负例（配置错 ×5 + 长度错 ×1 + 值域错 ×1），**无线格式错/状态机错/关联错/载体错负例** → G-PPTP-2。
- **性能层**——帧长上界：控制面最大 = **ICRQ 220B**（今日无用例）→ 存量最大 = OCRQ 168B；数据面最大由 `inner_ip.payload` 决定（无上限守卫）→ G-PPTP-6。跨 MSS 分段：控制面恒单段（最大 220 ≪ 1460）；`data_frames`/`down_data_frames` 上界 1000000（registry `Max`）→ 线性帧数增长。多 call 并发：`calls` 上界 65535（registry），#7 覆 2。
- **数据场景层**——值域：`role` 2 值（覆 pns/pac）、`scenario` 4 值（覆全 4）、`calls`（覆 1/2）、`sli_count`（覆 5/3）、`data_frames`/`down_data_frames`（覆 3+2/2+1/1+2/1+1）、`sub_address`（覆 缺席/非法，**hex 合法值零用例**）、`scrp_result`/`ocrp_result`（覆非 0）、`host_name`（覆超长，**合法值零用例**）、`inner_ip`（覆 src/dst/payload，**proto=1/6 两分支零用例**）；编码变体：定长 64B NUL 补齐、hex 解码、二进制伪影；非法值拒绝：7 类。
- **地址与流层**——IPv4 全覆盖（20/20）；**IPv6 零用例**（`planner_test.go:966` 有 `TestPlanner_IPv6Hosts` 单测，**无用例**）→ G-PPTP-7。单流基线：#1–#13。**流关联（控制→数据主从关系）= 本协议的核心特征**：#1/#10 覆（同一 flow 内 TCP 控制 + GRE 数据，数据帧的 Call ID 由控制面 OCRQ/OCRP 决定，`planner.go:570-571`）；见 §12.3 五件套强制展开。**多流**：由策略级 `flow_control` 承载（存量未用）。
- **业务层**——13 个场景（上表）全部有落点；多会话：`calls=N` 是**同一隧道内多路呼叫**（RFC 2637 §3.2.2 "A session is defined by the triple (PAC, PNS, Call ID)"），#7/#13 覆 2 路；多事务：控制连接内的消息对序列（SCCRQ/RP → OCRQ/RP → … → StopRQ/RP），#1/#13 覆全序。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① TCP 碰撞处理（RFC 2637 §3.1.3，未实现）；② 版本协商降级（§3.1.1，未实现）；③ PPP 层认证与 MPPE 加密（§5，未实现）；④ 60 秒保活定时器（§3.1.4，未实现——`echo` 是配置驱动）；⑤ 内嵌 IPv6（未实现）；⑥ 真实电话网拨号语义（未实现）。

## 5. 事务模型与状态机

**事务定义**：一次请求 + 一次应答（SCCRQ/RP、OCRQ/RP、CCRQ/CCDN、StopRQ/RP 等成对消息）。**多事务** = 一个控制连接内多对按序执行（#1 全序、#13 复合）。

### 5.1 正常流程（`Plan`，`planner.go:400-701`）

```
[TCP 握手]  SYN(up) → SYN-ACK(down) → ACK(up)               3 帧
[控制建立]  SCCRQ(pns) → SCCRP(pac)                          2 帧
[保活可选]  ECRQ(pac) → ECRP(pns)                 ← echo=true 时 +2 帧
── 每 call i = 0..calls-1 ────────────────────────────────────
[呼叫建立]  OCRQ(pns, pnsID) → OCRP(pac, pacID, pnsID)        2 帧
[来话可选]  ICRQ(pac) → ICRP(pns) → ICCN(pac)     ← incoming_call 时 +3 帧
[链路参数]  SLI × sli_count（PNS/PAC 交替）      ← full/control_only 时 +N 帧
[WAN 错误]  WEN(pac)                              ← wen 时 +1 帧
[数据面]    GRE up × data_frames → GRE down × down_data_frames  ← 仅 full
[呼叫拆除]  CCRQ(pac) → [CCRQ(pns)‖CCDN(pns) 合并段] → CCDN(pac)  3 帧
──────────────────────────────────────────────────────────────
[控制拆除]  StopRQ(pns) → StopRP(pac)                        2 帧
[TCP 挥手]  FIN-ACK(up) → ACK(down) → FIN-ACK(down) → ACK(up)  4 帧
```

**三个必须写清的非直觉点**：

1. **`tunnel_only` 的语义比字面窄**（§0 #6）：`sliCount` 段被 `scenario == "full" || "control_only"` 门住（`planner.go:644`），`emitDataPlane` 被 `scenario == "full"` 门住（`planner.go:665`），**但拆除段（CCRQ/合并/CCDN）与 StopRQ/RP 无场景门**（`planner.go:673-680`）。故 `tunnel_only` = "SCCRQ/RP + OCRQ/RP + 拆除 + 挥手"，**无 SLI、无数据、有拆除**。
2. **`data_only` 直接 return**（`planner.go:602-607`）：无 TCP 握手、无控制面、无挥手，只发 `emitDataPlane(0, 0)`（用配置的 call id，**无 per-call 偏移**）。
3. **合并段（参考 pcap 伪影）**：拆除段中 PNS 侧把 `CCRQ(pnsID)` 与 `CCDN(pnsID)` **拼进同一个 TCP 段**（`planner.go:674-675`），总长 16+148 = **164B**（实测钉：参考 pcap 帧 15 `tcp.len=164`，tshark 解出内嵌两条 PPTP 消息 Length=16 与 Length=148 ✓）。
4. **CCDN 双向都带 PNS 的 call id**（参考 pcap 伪影）：`send("pac", buildCCDN(&r, pnsID))`（`planner.go:676`）——按 RFC 2637 §2.13，PAC 发的 CCDN 应带 PAC 的 Call ID，实现带了 PNS 的。实测确认：参考 pcap 帧 16 `pptp.call_id=43456`（= PNS id，不是 PAC 的 13769）✓。

### 5.2 状态机（RFC 2637 §3.1/§3.2）

**控制连接（§3.1.1 发起方 / §3.1.2 接收方）**：`idle → wait_ctl_reply → established → wait_stop_reply → idle`。

| 状态 | 本实现产出 | 触发 |
|---|---|---|
| `idle` | TCP SYN | 会话开始 |
| `wait_ctl_reply` | SCCRQ（发起方）；SCCRP（接收方） | TCP 建连后 |
| `established` | OCRQ/OCRP、SLI、数据、CCRQ/CCDN | 收到 SCCRP |
| `wait_stop_reply` | StopRQ | 本地终止 |
| （终态） | StopRP + FIN 挥手 | 收到 StopRP |

**呼叫状态（§3.2.4.2 PNS 侧）**：`idle → wait_reply → established → wait_disconnect → idle`。

| 状态 | 本实现产出 |
|---|---|
| `idle` | 发 OCRQ |
| `wait_reply` | 收 OCRP（result≠1 → 回 idle，本实现不建模分支） |
| `established` | 数据帧（GRE）；SLI 更新链路参数 |
| `wait_disconnect` | 发 CCRQ |
| （终态） | 收 CCDN |

### 5.3 非法转移（RFC 2637 §3 未定义的转移，本实现逐条列出）

**关键结论：本实现是"剧本回放"，不是"状态机应答"——它不检查收到的对端消息，因此不存在"非法转移被拒绝"的运行时行为。** 所有非法转移都只能通过**配置**表达，且**配置层无状态机校验**。逐条列出：

| # | 非法转移（RFC 视角） | 本实现行为 | 是否可配置触发 |
|---:|---|---|---|
| 1 | 未建控制连接（无 SCCRQ/RP）就发 OCRQ | 只能靠 `scenario` 选择；`data_only` 完全跳过控制面（发 GRE 而不发 SCCRQ） | **可**（`scenario=data_only`，**这是"非法但被允许"的形态**——语义上等于隧道已存在） |
| 2 | 未建呼叫（无 OCRQ/OCRP）就发 SLI | `control_only` 场景**只发 SLI 不发数据**；`tunnel_only` **不发 SLI** | 部分（`scenario` 四枚举是**模板选择**，非状态转移校验） |
| 3 | 已 `established` 再收 SCCRQ | 不建模（无对端解析） | **否** |
| 4 | 发 CCRQ 后再发数据帧 | `full` 场景数据帧在拆除段**之前**（`planner.go:665` 早于 `:673`），顺序恒正确 | **否**（无法配置出该形态） |
| 5 | StopRQ 后再发任意控制消息 | StopRQ/RP 恒在最后（`planner.go:679-680`），之后只有 TCP 挥手 | **否** |
| 6 | 版本不兼容（SCCRP version < SCCRQ） | `version` 是单一配置值，**SCCRQ 与 SCCRP 共用**（`resolved.version`）——**无法表达版本不一致** | **否**（G-PPTP-8） |
| 7 | Call ID 冲突（同隧道内重复） | `calls=N` 时 call id 按 `+callIdx` 递增，**不检测溢出回绕**（`callID + uint16(callIdx)`，`planner.go:634`） | **否**（G-PPTP-8） |
| 8 | 收到不存在的 Call ID 的 GRE 帧 | 不建模（无对端解析） | **否** |

**生成器在某状态下遇到合法/非法事件的确定性**：`Plan` 对同一 `FlowSpec` 产出**完全确定**的帧序列（唯一非确定源是 `randomUint32` 生成的 ISN 与 `randomIPID` 生成的 IPID 种子，二者不影响帧数与结构）。**无随机分支、无未定义行为**。

### 5.4 自动派生规则（逐条列出，不依赖隐含知识）

| # | 自动补出的内容 | 触发条件 | 内容 | 代码位置 |
|---:|---|---|---|---|
| 1 | TCP 握手 3 帧 | 除 `data_only` 外恒发 | SYN/SYN-ACK/ACK + SYN options | `planner.go:610-622` |
| 2 | TCP 挥手 4 帧 | 除 `data_only` 外恒发 | FIN-ACK/ACK/FIN-ACK/ACK | `planner.go:683-697` |
| 3 | 目的端口 1723 | `spec.DstPort == 0` | `DefaultPort` | `planner.go:404-406` |
| 4 | `calls = 1` | `cfg.Calls == 0` | 1 | `planner.go:416-419` |
| 5 | `role = "pns"` | `cfg.Role == ""` | pns | `planner.go:408-411` |
| 6 | `scenario = "full"` | `cfg.Scenario == ""` | full | `planner.go:412-415` |
| 7 | TTL = 64 | `spec.TTL == 0` | 64（外层）；内层 `inner_ip.ttl==0` 亦 64 | `planner.go:441-444` / `:960-962` |
| 8 | MSS = 1460 | `spec.TCP == nil \|\| MSS == 0` | 1460 | `planner.go:445-449` |
| 9 | 内层 IPID = `ipid+1` | 每 GRE 帧 | 逐帧递增 | `planner.go:914` |
| 10 | GRE Payload Length | 每 GRE 帧组装后 | `end − greStart − headerLen` | `builder.go:925-932` |
| 11 | OCRQ/ICRQ 的 Phone/Dialed/Dialing Number Length | 每消息 | `len(对应字符串)`（**不 clamp**） | `planner.go:230` / `:350-351` |
| 12 | **零值即默认（0 语义）** | 见 §5.5 | 大部分字段 | `resolveDefaults` |
| 13 | **`0` 是显式值（不是默认）** | 仅 `data_frames`/`down_data_frames` | 显式 0 = 零帧 | `planner.go:879-883` |

### 5.5 默认值双层结构（`0 = 用默认` vs `0 = 显式零`）

**这是本协议最容易踩的坑，必须写清**。配置值有**两个来源**，且语义不同：

| 来源 | 函数 | 语义 |
|---|---|---|
| **链/扁平解析层** | `parsePPTPConfig`（`strategy_convert.go:3989`） | 用 `getIntPresence(m, key, default)`：**键缺席 → 填默认值**；键存在（哪怕值 0）→ **保留该值** |
| **planner 默认层** | `resolveDefaults`（`planner.go:761-888`） | 用 `if cfg.X != 0 { r.X = cfg.X }`：**值 0 → 用参考默认**；值非 0 → 用配置值 |

**两层叠加的后果**：

1. 键**缺席** → parse 填默认（如 `calls=1`、`sli_count=5`、`data_frames=3`）→ planner 看到非 0 → 用该值。**结果 = 参考默认** ✓
2. 键**显式写 0** → parse **保留 0** → planner 看到 0 → **用参考默认**。**结果 = 参考默认**（用户想表达"零条"却得到默认！）
3. **例外**：`data_frames`/`down_data_frames` 在 planner 侧是**直赋**（`r.dataFrames = cfg.DataFrames`，`planner.go:882-883`）→ 键缺席时 parse 已填默认 3/2，显式 0 则**真的是 0 帧**（`planner.go:879-881` 注释明写这是有意的）。

**结论**：`calls=0`/`sli_count=0`/`echo=false`/`wen=false` 等**都无法通过显式 0 表达"零"**——`calls=0` 与缺席等价（都得 1），`sli_count=0` 与缺席等价（都得 5）。**唯一的"零"通道是 `data_frames`/`down_data_frames`**。用例 `pptp_sli_count_three`（sli_count=3）是唯一非默认 SLI 用例；**"SLI 零条"今日不可表达** → G-PPTP-8。

## 6. 性能设计与验收

- **目标与边界**：单流 `full` 场景缺省 = **26 帧**（§9 公式）；控制面单消息最大 **ICRQ 220B**（今日无用例）、存量最大 **OCRQ 168B**；GRE 数据帧数 = `calls × (data_frames + down_data_frames)`（线性）；`calls` 上界 65535（registry `Max`）、`data_frames`/`down_data_frames` 上界 **1000000**（registry `Max`）。吞吐数字待 P5 基准，**本版不写承诺**。
- **依据**：帧序列由 `Plan` 的 goroutine **流式产出**（`configChan` 缓冲 256，`planner.go:422`），**无全量包聚合**；每帧内存 = 该帧字节数（最小 16B 控制消息 / 60B 以太帧；最大由 `inner_ip.payload` 决定）；`resolved` 结构按流局部构造，**无跨流共享状态、无锁**。
- **并发**：单 `Plan` 一个 goroutine；多流由框架 worker 并发调用 `Plan`（各自独立 `resolved`/`pnsSeq`/`ipid`）。
- **验收两路（强制）**：pcap（`CASE_PROTO=pptp` 全量）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `tcp.len`/frames hex/`packet_count`，不只断言"任务没报错"。**存量 NIC 路未跑**（G-PPTP-5 附注）。
- **六类场景落点**：基线（#1，26 帧）/ 目标规模（#13 复合 33 帧）/ 压力上限（`calls`/`data_frames` 线性外推，**无大报文用例** → G-PPTP-6）/ 长时间运行（**不适用**：无定时器/保活周期，`echo` 是单次插入）/ 并发交错（**不适用**：单流内严格顺序，无交错路径）/ 背压（`packet_count` 精确计数守卫帧数漂移 + `configChan` 缓冲 256 有界）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须被拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功：

| # | 负例 ID | 故障输入 | 真实拦截面 | 代码锚词（逐字） | 代码行 |
|---:|---|---|---|---|---|
| N-1 | `pptp_neg_role_invalid` | `role="switch"` | planner `Validate` | `invalid pptp role "switch" (allowed: pns, pac)` | `planner.go:118` |
| N-2 | `pptp_neg_scenario_invalid` | `scenario="half"` | planner `Validate` | `invalid pptp scenario "half" (allowed: full, control_only, tunnel_only, data_only)` | `planner.go:124` |
| N-3 | `pptp_neg_calls_negative` | `calls=-1` | **registry 范围门**（`complete.go:325`） | `layers: layer "pptp" field "calls" = -1 invalid: not a numeric value in [0,65535]` | `complete.go:325`（**planner 的 `invalid pptp calls %d`（`planner.go:127`）链路径不可达**） |
| N-4 | `pptp_neg_sli_count_negative` | `sli_count=-1` | **registry 范围门** | `layers: layer "pptp" field "sli_count" = -1 invalid: not a numeric value in [0,65535]` | 同上（planner `planner.go:130` 不可达） |
| N-5 | `pptp_neg_sub_address_hex` | `sub_address="zz"` | planner `Validate` | `invalid pptp sub_address "zz" (must be hex)` | `planner.go:140` |
| N-6 | `pptp_neg_host_name_long` | `host_name` = 65 字节 | planner `Validate` | `pptp host_name/vendor_name/phone_number/dialed_number/dialing_number exceed 64 bytes (fixed-size fields, RFC 2637 §2)` | `planner.go:145` |
| N-7 | `pptp_neg_inner_ip_invalid` | `inner_ip.src_ip="300.1.2.3"` | planner `Validate` | `invalid pptp inner src_ip: 300.1.2.3` | `planner.go:149` |

**锚词口径**：`error_contains` 是**子串**判定。N-1/N-2/N-5/N-6/N-7 命中 planner 文案；**N-3/N-4 的锚词写字段名 `calls`/`sli_count`**（不是 planner 文案 `invalid pptp calls`）——因为真实拦截面是 registry 范围门，其错误串为 `layer "pptp" field "calls" = -1 invalid: …`，**含 `calls` 但不含 `invalid pptp calls`**。存量 JSON 已按此写（`"error_contains": "calls"` / `"sli_count"`），**与真实拦截面一致** ✓。**若 P4 想改回 planner 文案，必须先在链路径让范围门放行负数——不建议**（本版按 as-built 钉）。

**负例原子性**：每例单一故障注入；7 例均单键（机读实测）。**负例 `expect` 键 = `{expect_error, error_contains, notes}`（含 `notes`，与 92-moxa 严格两键口径不同）** → G-PPTP-1（P4 收窄）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：

| 锚词 | 代码行 | 链路径可达性 |
|---|---|---|
| `invalid source IP: %s` | `planner.go:105` | 可达（层链 `ip.src` 非法） |
| `invalid destination IP: %s` | `planner.go:110` | 可达 |
| `pptp config is required` | `planner.go:114` | **链路径不可达**（translate 恒产非 nil） |
| `invalid pptp calls %d` | `planner.go:127` | **不可达**（范围门先拦） |
| `invalid pptp sli_count %d` | `planner.go:130` | **不可达** |
| `invalid pptp data_frames %d` | `planner.go:133` | **不可达**（范围门 Min:0 先拦负数） |
| `invalid pptp down_data_frames %d` | `planner.go:136` | **不可达** |
| `invalid pptp inner dst_ip: %s` | `planner.go:152` | 可达 |
| `invalid pptp inner proto %d (allowed: 1 ICMP, 6 TCP, 17 UDP)` | `planner.go:155` | 可达（`proto=99`） |

## 8. 边界

- **帧长**：控制面最小 **16B**（StopRQ/StopRP/ECRQ/CCRQ）/ 最大 **220B**（ICRQ）；GRE 数据帧长 = 16（GRE）+ 4（PPP）+ 20（内层 IP）+ L4 + payload。**内层 payload 无上限守卫** → G-PPTP-6。
- **定长字段 64B**：`host_name`/`vendor_name`/`phone_number`/`dialed_number`/`dialing_number` 长度 > 64 即拒（`planner.go:143-146`）；**长度字段（Phone/Dialed/Dialing Number Length）不 clamp**——若字符串恰 64B 则长度字段写 64，**无溢出**；若 >64 已在 Validate 拒绝，故 builder 侧不可达。**Sub-Address 是 hex 字段，不走 64B 字符串检查**（>64B 的 hex 串被 `copy` 静默截断，`planner.go:247-249`）→ G-PPTP-6 附注。
- **端口**：层 config 无端口位；`dst_port` 缺省 1723（生成器内部）；`src_port` 缺省 0（单流）/ `12345+i`（多流 worker）。
- **地址族**：外层 v4/v6 由 `ip` 层决定；**内层（PPP 内嵌）只支持 IPv4**（`pppProtoIPv4`）；外层 IPv6 今日零用例 → G-PPTP-7。
- **Call ID 回绕**：`calls` 大时 `callID + uint16(callIdx)` 可回绕（`uint16` 加法），**无检测** → G-PPTP-8。
- **`0` 语义**：见 §5.5（`calls=0`/`sli_count=0` 不可表达"零"）。
- **GRE Payload Length**：uint16，最大 65535；内层 payload 超此值则 `uint16(payloadLen)` 静默截断 → G-PPTP-6。
- **不得产生回绕长度或超量分配**：控制消息长度由 `controlHeader` 一次算定（`12+bodyLen`，bodyLen 恒 ≤ 208）；GRE 头长度由 `greHeaderLen` 按 A 位算定。

## 9. 原子 ID 与完成定义（20 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 | packet_count |
|---:|---|---|---|---:|
| 1 | `pptp_full_session_ref` | 正 | §5.1：full 全生命周期（参考 pcap 逐字节） | 26 |
| 2 | `pptp_control_header_magic` | 正 | §3.1：控制头 12B 逐字节（Length/Type/Magic/ControlType） | 26 |
| 3 | `pptp_scenario_control_only` | 正 | §5.1：`scenario=control_only` | 21 |
| 4 | `pptp_scenario_tunnel_only` | 正 | §5.1：`scenario=tunnel_only`（**无 SLI、无数据、有拆除**） | 16 |
| 5 | `pptp_scenario_data_only` | 正 | §5.1：`scenario=data_only`（纯 GRE，无 TCP） | 4 |
| 6 | `pptp_role_pac` | 正 | §3.9：`role=pac` 换向 | 21 |
| 7 | `pptp_calls_two` | 正 | §5.1：`calls=2` 多路呼叫 | 31 |
| 8 | `pptp_sli_count_three` | 正 | §3.5：`sli_count=3` | 24（**存量写 `min_packets:20`**，G-PPTP-1） |
| 9 | `pptp_echo_keepalive` | 正 | §3.6：`echo=true` ECRQ/ECRP | 23 |
| 10 | `pptp_data_both_directions` | 正 | §3.8：双数据方向 + GRE 头字节 | 24 |
| 11 | `pptp_inner_ip_explicit` | 正 | §3.8：`inner_ip` 显式 | 16（**存量无 `packet_count`**，G-PPTP-1） |
| 12 | `pptp_result_error_fields` | 正 | §3.3/§3.4：`scrp_result`/`ocrp_result` 非 0 | 21 |
| 13 | `pptp_composite_full_multi` | 正 | §5.1：复合（calls 2 + echo + 双数据 + SLI 3） | 33 |
| 14 | `pptp_neg_role_invalid` | 负 | §7 N-1 | —（0 帧） |
| 15 | `pptp_neg_scenario_invalid` | 负 | §7 N-2 | — |
| 16 | `pptp_neg_calls_negative` | 负 | §7 N-3（registry 范围门） | — |
| 17 | `pptp_neg_sli_count_negative` | 负 | §7 N-4（registry 范围门） | — |
| 18 | `pptp_neg_sub_address_hex` | 负 | §7 N-5 | — |
| 19 | `pptp_neg_host_name_long` | 负 | §7 N-6 | — |
| 20 | `pptp_neg_inner_ip_invalid` | 负 | §7 N-7 | — |

### 9.1 包数公式（可复算，机读对账 13/13 正例一致）

```
非 data_only：
  N = 3                                    # TCP 握手
    + 2                                    # SCCRQ + SCCRP
    + (echo ? 2 : 0)                       # ECRQ + ECRP
    + Σ_{i=0}^{calls-1} [
        2                                  # OCRQ + OCRP
      + (incoming_call ? 3 : 0)            # ICRQ + ICRP + ICCN
      + (scenario ∈ {full, control_only} ? sli_count : 0)
      + (scenario ∈ {full, control_only} && wen ? 1 : 0)
      + (scenario == full ? data_frames + down_data_frames : 0)
      + 3                                  # CCRQ + 合并段(CCRQ+CCDN) + CCDN
      ]
    + 2                                    # StopRQ + StopRP
    + 4                                    # TCP 挥手

data_only：
  N = data_frames + down_data_frames
```

**逐例复算（脚本生成，非手算）**：#1/#2 = 3+2+0+1×(2+5+5+3)+2+4 = **26** ✓；#3（control_only）= 3+2+0+1×(2+5+3)+2+4 = **21** ✓；#4（tunnel_only）= 3+2+0+1×(2+0+0+3)+2+4 = **16** ✓；#5（data_only, df=2）= 2+2 = **4** ✓；#6 = **21** ✓；#7（calls 2）= 3+2+2×(2+5+3)+2+4 = **31** ✓；#8（sli 3）= 3+2+1×(2+3+3)+2+4 = **24** ✓；#9（echo）= 3+2+2+1×(2+5+3)+2+4 = **23** ✓；#10（full, df 2/down 1）= 3+2+1×(2+5+3+3)+2+4 = **24** ✓；#11（tunnel_only, df 1）= **16** ✓；#12 = **21** ✓；#13（calls 2 + echo + sli 3 + df 1/down 1）= 3+2+2+2×(2+3+3+2)+2+4 = **33** ✓。

**对账结论**：13 个正例中 **11 例的 JSON `packet_count` 与公式逐例一致**；#8 用 `min_packets:20`（公式值 24，**松 4**）；#11 **无计数断言**（公式值 16）。**机读脚本对账 13/13 无矛盾**（`min_packets` 20 ≤ 24 ✓；缺失断言不算矛盾）。

## 10. P1 规范矩阵（八项：规范要求→业务场景→代码现状→缺口）

| # | 八项 | 规范要求（RFC 2637） | 业务场景 | 代码现状 | 缺口 |
|---:|---|---|---|---|---|
| 1 | 连接模型 | 控制连接 = TCP 1723（§1.2），PNS/PAC 任一可发起（§3.1）；数据面 = 外层 IP proto 47（§4） | 场景①–⑬ | `DependsOn ["ip"]` + 生成器自建 TCP（`planner.go:610/683`）+ GRE 帧（`:536`） | 无 |
| 2 | 命令/消息表 | 15 条控制消息（§2.1–2.15）+ GRE 增强头（§4.1） | 场景①–⑫ | 15 常量 + 15 `build*` + GRE 分支（`builder.go:827`） | ICRQ/ICRP/ICCN/WEN 零用例（G-PPTP-2） |
| 3 | 状态机 | 控制连接 4 状态（§3.1.1/3.1.2）+ 呼叫 4 状态（§3.2.4） | #1/#13 | **无状态机实现**（剧本回放，§5.3）；非法转移不可配置触发 | 版本协商/碰撞处理不建模（G-PPTP-8） |
| 4 | 字段表 | 15 消息逐字段（§2.1–2.15）+ GRE 头 6 字段（§4.1） | 数据场景层 | 逐字段 builder（§3）+ `fillPPTPGRE` | 无 |
| 5 | 错误处理 | §2.16 七个 General Error Code；Result Code 语义（§2.2/§2.8） | 场景⑪ | 7 负例 + `scrp_result`/`ocrp_result` 可配；**Error Code 全枚举零用例** | G-PPTP-2 |
| 6 | 超时与活性 | §3.1.4：60 秒无消息 → ECRQ；再 60 秒无 ECRP → 关闭 | 场景② | **定时器不实现**；`echo` 是配置驱动单次插入 | G-PPTP-4（B′） |
| 7 | NAT/代理/被动 | 无被动模式概念（PNS/PAC 对称，`role` 键表达两侧） | 场景⑥ | `role` 二值（`planner.go:117`） | 无 |
| 8 | 版本/方言 | §2.1：version 高字节版本、低字节修订，当前 `0x0100`；版本协商降级（§3.1.1） | — | `version` 单键（`planner.go:790`），**SCCRQ/SCCRP 共用** | 版本不一致不可表达（G-PPTP-8） |

### 10.1 子表①：消息 × 终态矩阵（逐格已覆/立项/不适用）

| 消息 | T1 正常终态 | T2 配置拒绝 | T3 数据面伴随 |
|---|---|---|---|
| SCCRQ/SCCRP | 已覆（#1/#2） | 已覆（#14 代表例） | 不适用（控制连接阶段无数据） |
| StopRQ/StopRP | 已覆（#1） | 同上代表已覆 | 不适用 |
| ECRQ/ECRP | 已覆（#9） | 同上代表已覆 | 不适用 |
| OCRQ/OCRP | 已覆（#1/#7/#13） | 同上代表已覆 | 已覆（#10 数据紧随呼叫建立） |
| ICRQ/ICRP/ICCN | **A′ 立项**（G-PPTP-2） | 同上代表已覆 | A′ 立项 |
| CCRQ/CCDN | 已覆（#1/#13） | 同上代表已覆 | 已覆（数据在拆除之前） |
| WEN | **A′ 立项**（G-PPTP-2） | 同上代表已覆 | A′ 立项 |
| SLI | 已覆（#1/#8/#13） | 同上代表已覆 | 已覆（#10 SLI 后接数据） |

**逐格重数（机读脚本）**：8 行 × 3 列 = 24 格——已覆 **17**（T1 列 6：SCCRQ/Stop/ECRQ/OCRQ/CCRQ/SLI + T2 列 8 全覆 + T3 列 3：OCRQ/CCRQ/SLI）/ A′ 立项 **4**（ICRQ 行 T1+T3、WEN 行 T1+T3）/ **不适用 3**（T3 列：SCCRQ/Stop/ECRQ——控制连接阶段无数据面）。17 + 4 + 3 = 24 ✓

### 10.2 子表②：数据形态变体表（协议相关全部形态逐项）

| # | 变体 | 落点 |
|---:|---|---|
| 1 | `role="pns"` | 覆（#1–#5/#7–#13） |
| 2 | `role="pac"` | 覆（#6） |
| 3 | `role` 非法 | 覆（#14） |
| 4 | `scenario="full"` | 覆（#1/#2/#10/#13） |
| 5 | `scenario="control_only"` | 覆（#3/#6/#9/#12） |
| 6 | `scenario="tunnel_only"` | 覆（#4/#11） |
| 7 | `scenario="data_only"` | 覆（#5） |
| 8 | `scenario` 非法 | 覆（#15） |
| 9 | `scenario` 缺省（= full） | 覆（#1/#2/#7/#8/#10/#11/#13 未写 scenario 的例） |
| 10 | `calls=1`（缺省） | 覆（#1–#6/#8–#12） |
| 11 | `calls=2` | 覆（#7/#13） |
| 12 | `calls` 负值 | 覆（#16） |
| 13 | `calls` 上界（65535） | A′ 立项（G-PPTP-6） |
| 14 | `echo=true` | 覆（#9/#13） |
| 15 | `echo=false`（缺省） | 覆（其余正例） |
| 16 | `sli_count=5`（缺省） | 覆（#1/#2/#7/#9/#10/#12） |
| 17 | `sli_count=3` | 覆（#8/#13） |
| 18 | `sli_count` 负值 | 覆（#17） |
| 19 | `sli_count` 显式 0（不可表达零，§5.5） | A′ 立项（G-PPTP-8） |
| 20 | `data_frames=3`（缺省） | 覆（#1/#2/#3/#6/#7/#9/#12） |
| 21 | `data_frames=2` | 覆（#10） |
| 22 | `data_frames=1` | 覆（#11/#13） |
| 23 | `data_frames=0`（显式零，唯一可表达零的键） | A′ 立项（`planner_test.go:688` 有单测，**无用例**） |
| 24 | `down_data_frames=2`（缺省） | 覆（#1/#2/#3/#6/#7/#9/#12） |
| 25 | `down_data_frames=1` | 覆（#10/#13） |
| 26 | `down_data_frames` 负值 | A′ 立项（`planner.go:136` 分支，范围门先拦） |
| 27 | `sub_address` 缺席（参考伪影） | 覆（全正例） |
| 28 | `sub_address` 合法 hex | A′ 立项（G-PPTP-2） |
| 29 | `sub_address` 非法 hex | 覆（#18） |
| 30 | `host_name` 合法值 | A′ 立项（G-PPTP-2） |
| 31 | `host_name` 超 64B | 覆（#19） |
| 32 | `vendor_name`/`phone_number`/`dialed_number`/`dialing_number` 超 64B | A′ 立项（同一 `planner.go:145` 分支，4 键零用例） |
| 33 | `scrp_result` 非 0 | 覆（#12） |
| 34 | `ocrp_result` 非 0 | 覆（#12） |
| 35 | `scrp_error`/`ocrp_error`/`cause_code` 非 0 | A′ 立项（G-PPTP-2） |
| 36 | `stop_reason`/`stop_result`/`stop_error` 非 0 | A′ 立项（G-PPTP-2） |
| 37 | `ccdn_result`/`ccdn_error`/`ccdn_cause` 非 0 | A′ 立项（G-PPTP-2） |
| 38 | `inner_ip` 缺席（合成默认 10.10.10.1→10.10.10.2 UDP） | 覆（#1/#2/#10/#13） |
| 39 | `inner_ip.src_ip`/`dst_ip` 显式 | 覆（#11） |
| 40 | `inner_ip.payload` 显式 | 覆（#11） |
| 41 | `inner_ip.proto=17`（UDP，缺省） | 覆（全数据面例） |
| 42 | `inner_ip.proto=6`（TCP） | A′ 立项（`planner.go:932` 分支） |
| 43 | `inner_ip.proto=1`（ICMP） | A′ 立项（`planner.go:946` 分支） |
| 44 | `inner_ip.proto` 非法 | A′ 立项（`planner.go:155` 分支） |
| 45 | `inner_ip.src_ip` 非法 | 覆（#20） |
| 46 | `inner_ip.ttl` 显式 | A′ 立项（`planner.go:911`） |
| 47 | `inner_ip.src_port`/`dst_port` 显式 | A′ 立项（`planner.go:909-910`） |
| 48 | 外层 IPv6 | A′ 立项（G-PPTP-7） |
| 49 | `incoming_call=true`（ICRQ 族） | A′ 立项（G-PPTP-2） |
| 50 | `wen=true` | A′ 立项（G-PPTP-2） |
| 51 | `sli_peer_call_id` 覆盖 | A′ 立项（`planner.go:653` 分支） |
| 52 | `call_id`/`peer_call_id`/`call_serial` 显式 | A′ 立项（G-PPTP-2） |
| 53 | `version` 显式（含非 `0x0100`） | A′ 立项（G-PPTP-2） |
| 54 | `framing_caps`/`bearer_caps`/`max_channels`/`firmware_revision` 显式 | A′ 立项（G-PPTP-2） |
| 55 | `scrp_framing_caps`/`scrp_bearer_caps`/`scrp_firmware_rev` 显式 | A′ 立项（G-PPTP-2） |
| 56 | `min_bps`/`max_bps`/`bearer_type`/`framing_type`/`window_size`/`packet_delay` 显式 | A′ 立项（G-PPTP-2） |
| 57 | `ocrp_window_size`/`ocrp_delay`/`connect_speed`/`physical_channel_id` 显式 | A′ 立项（G-PPTP-2） |
| 58 | `send_accm`/`receive_accm` 显式 | A′ 立项（G-PPTP-2） |
| 59 | `phone_number`/`dialed_number`/`dialing_number` 合法值 | A′ 立项（G-PPTP-2） |

**32 覆 + 27 立项 = 59。** ✓（机读脚本重数）

### 10.3 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 客户端拨号建立 VPN 隧道（RFC 2637 §3.2.4 出站呼叫） | #1 | 已覆 |
| 2 | 控制连接建立（§3.1） | #1/#2 | 已覆 |
| 3 | 保活探测（§3.1.4） | #9（结构路径，非定时器） | 已覆（**结构路径**，定时器不实现） |
| 4 | 服务器侧（PAC）接受呼叫 | #6 | 已覆 |
| 5 | 一个隧道多路并发呼叫（§3.2.2 三元组） | #7/#13 | 已覆 |
| 6 | PPP 链路参数协商（SLI ACCM） | #8 | 已覆 |
| 7 | 双向数据承载（GRE + PPP + 内网包） | #10/#11 | 已覆 |
| 8 | 呼叫协商失败/错误码回传 | #12 | 已覆（结构路径） |
| 9 | 隧道拆除 | #1 | 已覆 |
| 10 | 控制头完整性校验（Magic Cookie 同步，§2） | #2 | 已覆 |
| 11 | 只建隧道不跑数据（探测/探测后放弃） | #3/#4 | 已覆 |
| 12 | 纯数据面（隧道已由他方建立） | #5 | 已覆 |
| 13 | 来话呼叫（PAC 侧拨入，§3.2.3） | — | **明确不解决**（G-PPTP-2：`incoming_call` 键存在、无用例） |
| 14 | WAN 错误上报（§2.14） | — | **明确不解决**（G-PPTP-2） |
| 15 | PPP 层认证与 MPPE 加密（§5） | — | **明确不解决**（§1 边界②） |
| 16 | TCP 碰撞处理（§3.1.3） | — | **明确不解决**（§1 边界①） |
| 17 | 版本协商降级（§3.1.1） | — | **明确不解决**（G-PPTP-8） |
| 18 | 真实电话网拨号语义 | — | **明确不解决**（§1 边界⑥） |

**12 覆 + 6 不适用 = 18。** ✓ 无映射无确认即缺口——本表零缺口。

### 10.4 三路对照

三路：①**规范原文**（RFC 2637 全文本地实读，15 条消息模板 + GRE 头 + 状态机逐节标注，§3 全部字段布局对 RFC 图逐行核对）；②**现网实测**（参考 pcap `/home/pcap_auto/llcj_mirror/IP-TCP-10.6.2.41-…-49194-1723-…pcap` 22 帧逐帧 tshark 解出，本版 §3 全部缺省值的唯一权威；镜像目录另有 23 个同构 pcap 可选，未逐一核对）；③**开源实现思路**（Linux pptp client / pptpd 的"控制面 + GRE 面单流编排"——只借鉴该结构决策，未取线字节）。

**一致点**：控制头布局（Length/MsgType/Magic/ControlType）、Magic Cookie 常量、GRE 增强头 A 位 = bit 8、Protocol Type 0x880B、Key = Payload Length + Call ID。

**不一致点（须写清）**：
- **SLI 的 Peer Call ID**（§3.5）：RFC 要求对端 Call ID，参考 pcap 的 PAC 侧 SLI 写的是 PNS 的 **TCP 源端口 49194**——**实现选择复刻参考 pcap 伪影**（`planner.go:645-659`），非 RFC 合规。
- **CCDN 的 Call ID**（§5.1 点 4）：RFC 要求发送方自己的 Call ID，参考 pcap 的 PAC 侧 CCDN 写的是 **PNS 的 Call ID**——同样复刻伪影。
- **CCRQ+CCDN 合并段**（§5.1 点 3）：RFC 未规定，参考 pcap 中 PNS 侧把两条消息拼进一个 TCP 段——实现复刻。
- **Host/Vendor 缺省**（§0 #17）：参考 pcap 为 Host 空 + Vendor "Microsoft"；D-PPTP-1 B′ 注记设想的 MS 客户端形（"machine"/"Microsoft Windows NT"）**未落码**。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `pptp` 终结层，raw 自驱 wrap legacy Plan（本版；pppoe/ldap/rtmp/rtsp 同构先例） | 控制面 + GRE 数据面在**同一 flow** 内可声明可断言；代价 = 自建 TCP 载体（已落码 1075 行） | **采用**（D-PPTP-1 裁定 1） |
| B | `[ip, tcp, pptp]` + `[ip, gre]` 双链事件面 | GRE 数据面**无独立生成器**（gre 层是底座，PPTP 增强头需新建），且两条链无法共享 Call ID 状态 → 大改 | **否决**（D-PPTP-1 裁定 1） |
| C | 只用 `[ip, gre]` + 顶层 payload 手工拼控制消息 | 15 消息族的字段序/长度公式/状态编排全部丢失 → 20 例中 15 例不可表达 | **否决** |

## 11. P2 D-PPTP-2 代码设计（as-built 逆向定稿；八要素）

> 状态说明：实现已落码（`internal/protocol/pptp/` 三文件 + `builder.go` GRE 分支），本 P2 条目是 P-PIPE 文档轨对既有实现的**逆向定稿**（as-built），供后续改动的唯一入口。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:5319-5549` + `:1852` + `:3232-3249`） | `PPTPConfig` / `PPTPInnerIP` + `FlowSpec.PPTP` 槽位 + `GREConfig.PPTP/CallID/AckPresent/Ack` | —（共享文件） |
| `trafficgen/internal/protocol/pptp/planner.go` | `Validate`（9 分支）+ `Plan`（场景编排 + 自建 TCP）+ 15 个消息 `build*` + `resolveDefaults` + PPP/内嵌 IP 构建 + 校验和 | 1074 |
| `trafficgen/internal/protocol/pptp/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator` + `RegisterLayerValidator`，`init()`）+ 防双换 Direction 改写 | 67 |
| `trafficgen/internal/protocol/pptp/planner_test.go` | 27 个 `Test*`（编码面 + 生成器面 + Validate 面 + 场景面 + 角色面 + 默认端口面 + IPv6 面） | 1026 |
| `trafficgen/internal/core/builder.go`（`:415-420` / `:519-538` / `:553-558` / `:827-841` / `:925-932`） | GRE-PPTP 模式：flags 组装、协议类型强制、Key 拆分、Payload Length 回填、模式互斥校验 | — |
| 接线 7 件 | registry 注册（`layers/registry.go:1945`，51 Fields）/ translate 层内分支（`chain_planner_translate.go:2798`）/ 扁平 parse（`strategy_convert.go:3989` + `ParsePPTPConfigFromMap:3697` + `case "pptp":1356`）/ protocols 准入（`protocols.go:51`）/ `FlowMeta.PPTP`（`chain_planner.go:1524`）/ raw 链双名单（`chain_planner_util.go:54,57` + `chain_planner.go:996`）/ 0-keep 名单（`chain_planner.go:789`） | — |
| 链级测试 | `trafficgen/internal/core/layers/pptp_chain_test.go`（2 例：raw 链 + 7 锚背 door） | 70 |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`planner.go:102`）：9 个拒绝分支（§7 表 + §7 未入例表）。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`planner.go:400`）：Validate 后启动 goroutine，向 `configChan`（缓冲 256）流式产出 `PacketConfig`。
- 生成器：`Name() "pptp"`；`GenEvents() nil`（**无事件面**——raw 自驱）；`Generate` 构造 `core.FlowSpec` 后调 `NewPlanner().Plan`，逐包改写 `Direction="up"` 再 `req.Emit`（`layer_gen.go:27-58`）。
- 校验器注册：`layers.RegisterLayerValidator("pptp", …)` → `(&Planner{}).Validate(*spec)`（`layer_gen.go:64-66`）。

### 11.3 数据结构

`PPTPConfig`（`types.go:5331-5538`，**51 键**，§12.13 逐键）；`PPTPInnerIP{SrcIP, DstIP, Proto, SrcPort, DstPort, TTL, Payload}`（7 子键，`types.go:5545-5560`）；`resolved`（planner 内部，`planner.go:713-758`，**44 字段** = 配置 + 已解析默认）；`GREConfig{PPTP, CallID, AckPresent, Ack, …}`（`types.go:3196-3260`）。

### 11.4 主流程

```
层链配置 → ValidateLayers（registry Fields 51 键 allowlist + V9 范围门）
  → translate（层内 config → spec.PPTP，经 core.ParsePPTPConfigFromMap 单一真相）
  → validateSpecBase（src 端口 0-keep / dst 端口 0-keep，1723 由 Plan 缺省）
  → FlowMeta.PPTP = spec.PPTP
  → 生成器 Generate → Planner.Plan
      → Validate → 默认化（role/scenario/calls/port）→ resolveDefaults
      → goroutine：TCP 握手 → 控制面（按 scenario 模板）→ GRE 数据面 → 拆除 → TCP 挥手
      → 逐帧 PacketConfig（Direction 已按角色换向）→ configChan
  → layer_gen 逐包 Direction="up" 改写 → req.Emit（raw-IP drive 分支）
  → core/builder：控制帧走 TCP 构建；GRE 帧走 PPTP 模式 GRE 构建（flags/proto/Key 回填）
  → writer（PCAP/NIC）
```

### 11.5 错误分支

planner `Validate` 9 分支 + registry 范围门（负数在 `calls`/`sli_count`/`data_frames`/`down_data_frames` 四键上先行拦截）+ builder GRE-PPTP 互斥 4 分支（`builder.go:526/529/532/535`）+ `layer_gen` 的 `Emit is nil`（`layer_gen.go:29`）。**全部传 task error，零假成功**（7 负例实测 0 帧）。

### 11.6 性能边界

见 §6（流式 channel 缓冲 256、per-flow 局部状态、无跨流共享、无锁；帧数与 calls/SLI/data_frames 线性；吞吐数字待 P5 基准）。

### 11.7 与现有逻辑的冲突点

- **`CheckProtoFlat` 无 pptp 分支**（`strategy_convert.go:8625` 起，`switch protocol` 无 `case "pptp"`，机读实测）：顶层 `pptp` 子映射 presence **不判死**——与 dns/mqtt/cwmp 等已登记协议不同，属缺口 G-PPTP-9（**禁加单协议黑名单分支**，等框架级 unknown-key 白名单；kingbase 记忆裁定）。
- **顶层未知键通用门也缺**：游离顶层键（如 `{layers:[…], bogus: 1}`）今日**不判死**（`CheckProtoFlat` 只查五键 + 各协议子映射白名单）→ presence 负例今日建了会真绿 = 假通过，**不建**（G-PPTP-9，与 moxa G-MOXA-2 / opcua G-OPCUA-1 同款）。
- **动态 allowlist**（`internal/core/layer_dyn.go:17-21`）：`pptp` **零命中**实测（allowlist 仅 `ip`/`tcp`/`udp`/`eth` + 少数协议块）→ 业务字段动态对象即拒；四元组 `ip`/`tcp` 全开。见 §12.12。
- **`validateBaseDstPortHandled` 豁免**：`pptp` 在 0-keep 名单（`chain_planner.go:789`），故 `dst_port=0` 不被 base 检查拒绝，由 `Plan :404` 补 1723。**副作用**：层链里**无法显式写 `dst_port`**（Fields 无该键）——若用户要非默认端口，今日**无通道** → G-PPTP-7。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 3 文件 + 接线 7 处 + `builder.go` GRE-PPTP 分支（`:415-420/:519-538/:553-558/:827-841/:925-932`）；不触及其他协议。cases 回滚 = 恢复 20 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 20/20 顶层 = `{layers}` **仅此一键，零残留**；目标形状见 §2 样例且**存量已达标**（本协议无迁移工作量） | §12.1；`cases/pptp.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 pptp 流量模板（层链 + 可选 `flow_control`）；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/**关联关系（控制→数据主从，本协议核心）**/插入位置（终结层）/时间线。有长连接，不豁免 | §12.3 + §5 |
| §4 查规范 | RFC 2637 全文实读（15 消息 + GRE 头 + 状态机）+ 参考 pcap 22 帧 tshark 实测 + tshark 3.6.14 `pptp.*` 58 字段 + 落码反推；八项矩阵 + 三子表 | §10 |
| §5 依赖与错误 | `DependsOn ["ip"]` 单值（`registry.go:1945`）；9+4 种拒绝分支；失败传 task error（7 负例 0 帧） | §5/§7/§11.5 |
| §6 性能 | 见 §6（六类场景要素齐；吞吐数字标待 P5 基准，不写承诺；pcap/NIC 两路验收明写，NIC 未跑已注明） | §6 |
| §7 三份文档 | `114-pptp-{design,testcase}.md` v1.0.0（本版）+ D-PPTP-1（`CODE_DESIGN.md:3040`，历史层，本版承其裁定）+ T-PPTP-1…20（testcase §2，20 ID） | 修订记录 |
| §8 设计先行 | D-PPTP-1 P1+P2 定稿（2026-09-20）先于 P4/P5 落码；本版为 as-built 逆向定稿 | `CODE_DESIGN.md` 提交序 |
| §9 测试三源 | 三源 = RFC 2637 + 参考 pcap 实测（§10.4）+ D-PPTP-1 + tshark 3.6.14 字段与 20 例；20 ID 逐项回指；存量 20 例审计去向 testcase §8 | `114-pptp-testcase.md` §2/§5/§8 |
| §10 评审闭环 | D-PPTP-1 P3/P4/P6 三轮对抗复审（P6 抓 2 实缺口 + 1 笔误，全修）+ 本版自审（§15） | `CODE_DESIGN.md` P6 段；本版 §15 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `pptp` 已在 `registry.go:1945` 注册（**不新增层**）；生成表同代（Fields 51 键与 `parsePPTPConfig` 消费面逐键一致，机读实测 §12.13）；**P4 若改 registry Fields 必须重跑 schemagen** | §11.1/§12.13 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `tcp.len`/frames 双通道 → 先跑后钉；pcap 落 `docs/protocol-pcap-test/pptp/`（**目录今日不存在**，G-PPTP-5） | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 项 | 实测 |
|---|---|
| 例数 | **20**（13 正 + 7 负） |
| `spec_json` 顶层键分布 | **`{layers}` ×20（唯一顶层键，零游离键）** |
| 层链形状 | **`[ip, pptp]` ×20**（唯一形状，无 `tcp` 层） |
| 正例 `expect` 键 | `{has_handshake, terminates, packet_count, fields/frames/notes}` 等 |
| 负例 `expect` 键 | **`{expect_error, error_contains, notes}` ×7**（含 `notes`，非严格两键） |
| 层内 `pptp` 键使用 | 12 键：`scenario`×10 / `data_frames`×4 / `calls`×3 / `sli_count`×3 / `role`×2 / `echo`×2 / `down_data_frames`×2 / `inner_ip`×2 / `scrp_result`×1 / `ocrp_result`×1 / `sub_address`×1 / `host_name`×1（**51 键中仅 12 键有用例**，39 键零用例） |

**旧键去向表（"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 本协议**从未用过顶层地址**；全部住 `layers[0].ip.{src,dst}`（20/20） |
| `src_port` | **0** | 层 config 无端口位；单流 0 / 多流 worker `12345+i` |
| `dst_port` | **0** | 层 config 无端口位；1723 由生成器 `Plan` 缺省（`planner.go:404`） |
| `count` | **0** | 走 `flow_control`（本版未用） |
| 顶层 `pptp` 子映射 | **0** | 已住 `layers[1].pptp`（20/20） |
| `strategy_fc` / `flow_control` | **0** | 本协议无多流用例；目标形按需加 |

**结论**：**本协议存量 20/20 顶层零残留**——§1 门的动作 = ①**无旧键可删**；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测 20/20 顶层仅 `layers`）；③A′ 新增例全部沿用纯 layers 形。

### 12.2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"pptp":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 pptp 分支，`grep -c` = 0 实测）→ **P4 不建该负例**（建了会真绿 = 假通过）→ 缺口 G-PPTP-9。
- ② 白名单外游离键判死（`unknown field`）今日**亦无通用门** → 同 G-PPTP-9，P4 不建。
- ③ **7 负例每条带锚词**（已齐，§7 表 + testcase §4）✓。
- ④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）✓。

### 12.3 §3 强制展开：五件套

**会话表**：

| 会话 | 构成 | 用例 | 四元组 |
|---|---|---|---|
| `s1` 单隧道单呼叫基线 | 3 握手 + SCCRQ/RP + OCRQ/RP + SLI×5 + GRE×5 + 拆除 + Stop + 4 挥手 = 26 帧 | #1/#2 | `10.0.0.1:src→20.0.0.1:1723` |
| `s2` 纯控制 | 同上无 GRE（21 帧） | #3/#6/#9/#12 | 同 `s1` |
| `s3` 纯隧道（无 SLI/数据） | 16 帧 | #4/#11 | 同 `s1` |
| `s4` 纯数据（无 TCP） | `data_frames + down_data_frames` 帧 | #5 | 同 `s1` |
| `s5` 多路呼叫（同隧道多 call） | `calls=2`：OCRQ/RP×2 + SLI 逐 call（31 帧） | #7/#13 | 同 `s1`（**同一四元组内多 call，不是多会话**） |

**事务序列**（每事务四件事）：

| 事务 | 前置 | 触发 | 成功 | 失败 |
|---|---|---|---|---|
| `t1` TCP 建连 | 会话开始 | `Plan` 入口 | 3 帧握手 | —（不建模） |
| `t2` 控制连接建立 | `t1` 完成 | `scenario ≠ data_only` | SCCRQ→SCCRP（result=1） | `scrp_result≠1` 可配（#12，**结构路径，不产失败流**） |
| `t3` 呼叫建立 | `t2` 完成 | 每 call | OCRQ→OCRP（result=1） | `ocrp_result≠1` 可配（#12） |
| `t4` 链路参数协商 | `t3` 完成 | `scenario ∈ {full, control_only}` | SLI×N | — |
| `t5` 数据承载 | `t3` 完成 | `scenario == full` | GRE 帧 × (data+down) | — |
| `t6` 呼叫拆除 | `t5` 完成 | 每 call 恒发 | CCRQ→[CCRQ‖CCDN]→CCDN | `ccdn_result`/`ccdn_error` 可配 |
| `t7` 控制连接拆除 | `t6` 完成 | 恒发 | StopRQ→StopRP | `stop_result` 可配 |

**关联关系（本协议的核心特征，必须写清）**：

- **控制 → 数据的主从关系**：GRE 数据帧的 **Key 低 16 位 = 对端 Call ID**，该 Call ID 由**控制面**决定——PNS 侧帧带 PAC 的 id（= OCRP 里的 `CallID`，缺省 `0x35c9`），PAC 侧帧带 PNS 的 id（= OCRQ 里的 `CallID`，缺省 `0xa9c0`）。代码：`emitDataPlane` 的 `pnsID := r.peerCallID + uint16(callIdx)` / `pacID := r.callID + uint16(callIdx)`（`planner.go:570-571`）。
- **`calls=N` 的逐 call 递增**：call i 用 `callID+i` / `peerCallID+i`（`planner.go:634-635`），故多 call 的数据帧 Call ID 与控制面一致地逐 call 偏移。
- **数据帧不派生新连接**：GRE 帧与 TCP 控制流**共享同一个 flow 四元组**（同一 `SrcIP/DstIP`，但**无端口**——IP proto 47）。**没有 `driven_by` 形态**（不是 FTP/SIP 式的副连接）。
- **方向换向**：`role=pns` 时控制面 PNS 侧 = `up`、PAC 侧 = `down`；`role=pac` 时整体反转（`planner.go:516-530`）。

**插入位置**：**终结层**（`[ip, pptp]`，无中间层，无 `tcp` 层——TCP 由本层自建）。`DependsOn ["ip"]` 单值。

**时间线**：控制消息内严格顺序（`plan` 顺序 = 帧序）；`calls` 逐 call **顺序整块**（call 0 全部完成再 call 1）；**无交错**（`concurrent` 为例外路径，本协议不启用）；GRE 数据面在呼叫建立之后、拆除之前。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组**：

| 字段 | 动态支持 | 机制 | 证据 |
|---|---|---|---|
| `ip.src` / `ip.dst` | **五策略全开** | allowlist `layer_dyn.go:18` `"ip": {"src": true, "dst": true, "ttl": true}` | 机读实测 |
| `tcp.src_port` / `tcp.dst_port` | **全开** | allowlist `:19` | 但 **pptp 链无 `tcp` 层** → 本协议层链不可达 |
| `eth.src_mac` / `eth.dst_mac` | 全开 | allowlist `:21` | 本协议层链无 `eth` 层 → 不可达 |
| **pptp 层源/目的端口** | **不适用** | pptp 层 Fields **无端口键**（§12.13）；目的端口 1723 由生成器缺省，源端口由 worker 按 `DefaultSrcPort(12345) + i` 注入（`chain_planner.go:889-1000` 的 raw 链分支，pptp 落 `:996` 名单，**0 保持 0**，多流才递增） | `chain_planner.go:996` |

**业务字段（51 键逐个列开/不开 + 理由）**：allowlist `layer_dyn.go` **无 `pptp` 行**（`grep -n pptp internal/core/layer_dyn.go` = 零命中实测）→ **全部 51 键今日动态对象即拒**（`does not support dynamic`）。逐类理由：

| 类 | 键 | 开/不开 | 理由 |
|---|---|---|---|
| 角色/场景选择器 | `role` / `scenario` | **不开** | 结构选择器，逐流变会产出异构流，无测试意义 |
| 计数 | `calls` / `sli_count` / `data_frames` / `down_data_frames` | **不开** | 帧数参数，逐流变会导致帧数不定，破坏 `packet_count` 断言 |
| 布尔开关 | `echo` / `wen` / `incoming_call` | **不开** | 分支开关 |
| Call ID 族 | `call_id` / `peer_call_id` / `call_serial` / `sli_peer_call_id` | **不开**（**A′ 候选**） | **理论上最该动态化**——多路呼叫需要互异的 Call ID；今日由 `calls=N` 的 `+callIdx` 机制承担 |
| SCCRQ 标量 | `version` / `framing_caps` / `bearer_caps` / `max_channels` / `firmware_revision` | **不开** | 能力协商常量 |
| SCCRP 标量 | `scrp_result` / `scrp_error` / `scrp_framing_caps` / `scrp_bearer_caps` / `scrp_firmware_rev` | **不开** | 同上 |
| 定长字符串 | `host_name` / `vendor_name` / `phone_number` / `dialed_number` / `dialing_number` / `sub_address` | **不开**（**A′ 候选**） | 逐流变有现网意义（不同客户端名），但需 hex 面特殊处理（`sub_address`） |
| OCRQ/OCRP 标量 | `min_bps` / `max_bps` / `bearer_type` / `framing_type` / `window_size` / `packet_delay` / `ocrp_result` / `ocrp_error` / `cause_code` / `connect_speed` / `ocrp_window_size` / `ocrp_delay` / `physical_channel_id` | **不开** | 协商常量 |
| SLI | `send_accm` / `receive_accm` | **不开** | 链路参数常量 |
| Stop/CCDN | `stop_reason` / `stop_result` / `stop_error` / `ccdn_result` / `ccdn_error` / `ccdn_cause` | **不开** | 结果码 |
| 嵌套对象 | `inner_ip`（7 子键） | **不开**（**A′ 候选**） | 对象型；内层地址逐流变有现网意义（不同内网网段） |

**序号算法实读**：

- 四元组动态解析：`parseLayerDyn`（`internal/core/layer_dyn.go:78`）+ `TupleGenerator.Next`（`tuple_generator.go`）。
- 保底自增：`DefaultSrcPort = 12345`（`strategy_convert.go:49`）+ worker 注入（`12345+i`）。
- allowlist 白名单：`layer_dyn.go:17-21`（**`pptp` 零命中**）。
- **Call ID 的"序号"**：`callID + uint16(callIdx)` / `peerCallID + uint16(callIdx)`（`planner.go:634-635`）——这是**帧内序号**（多 call 展开），**不是**逐流动态。
- **GRE Sequence Number**：逐方向独立 `0..N-1`（`planner.go:572-591`）。
- **内层 IPID**：`ipidBase + i`（`planner.go:573/585`），`ipidBase` 逐 call 累加（`:667`）。
- **IPID 种子**：`randomIPID()`（`planner.go:1050-1056`，crypto/rand，失败回退 `0x1234`）。
- **ISN**：`randomUint32()`（`planner.go:1060-1066`，可用 `spec.TCP.InitialSeq` 覆盖；PNS 侧），PAC 侧恒随机（`planner.go:458`）。

### 12.13 §13 registry Fields ↔ parse 消费面逐键对账（51 ↔ 51）

registry `pptp` 行 **51 个 Fields 键**（机读实测）；`parsePPTPConfig`（`strategy_convert.go:3989`）顶层消费键 **50 个**（`getX(m, "key")` 形）+ `inner_ip`（经嵌套 `parsePPTPInnerIP(m["inner_ip"])` 在 `:4044` 处理，7 子键不单独登记）= **51**。逐键一致，**零差**（D-PPTP-1 P6 横扫项复现 ✓）。`inner_ip` 登记为 `{Type: "object"}`（srv6 `inner_payload` 先例）。

**39 键零用例**（§12.1）：除 §12.1 列出的 12 个有用例的键外，其余 39 键**今日无用例** → G-PPTP-2（不冒充已覆盖）。

## 13. P3 对接清单（T-PPTP 草稿输入；正文落 testcase 文件）

20 ID（13 正 + 7 负）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。**A′ 候选 27 例**（§10.2 立项行）：`incoming_call` 族 1 例 / `wen` 1 例 / hex 合法 `sub_address` 1 例 / 合法 `host_name` 1 例 / 四个长度字段超限 1 例 / Error Code 枚举 1 例 / `inner_ip.proto` 三值 3 例 / `inner_ip.proto` 非法 1 例 / `inner_ip` 其余子键 3 例 / IPv6 外层 1 例 / `sli_peer_call_id` 覆盖 1 例 / `call_id` 族显式 1 例 / SCCRQ 标量族 1 例 / SCCRQ 结果族 1 例 / OCRQ 标量族 1 例 / SLI ACCM 1 例 / Stop/CCDN 结果码 1 例 / `data_frames=0` 显式零 1 例 / `calls` 上界 1 例 / 内层 payload 上限 1 例 / 动态字段（`call_id`/`inner_ip`/`host_name`）3 例 / 顶层 presence 判死 1 例（**须等框架门，今日建了会假绿**）/ 非默认 `dst_port` 1 例（**今日无通道**）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-PPTP-1 | **存量断言/文案缺陷 4 处**（文档侧记录，**本版不改 JSON**）：① `pptp_scenario_tunnel_only` 的 `expect.notes` 写"隧道建立+**数据面**（无控制拆除）"——实测**无数据面、有拆除**（`planner.go:644/665`）；② `pptp_sli_count_three` 用 `min_packets:20`（公式值 **24**，松 4）且 notes 算式"22-2=20"错（把 full 基准 26 当成 22）；③ `pptp_inner_ip_explicit` **无 `packet_count`**（唯一既无 `packet_count` 也无 `min_packets` 的正例，公式值 16）；④ `pptp_full_session_ref` 的 `expect.notes` 写"data_frames 缺省 5"——实为 `data_frames=3` + `down_data_frames=2` 之和（结论对、表述误导） | **代码阶段**（P4 改写 notes / 收窄为 `packet_count` / 补断言）；本版**不改任何 JSON**（任务书边界） |
| G-PPTP-2 | **零用例分支 4 类**：① ICRQ/ICRP/ICCN（`incoming_call` 键存在，`planner.go:639-643`）；② WEN（`wen` 键存在，`:661-663`）；③ **39 个 registry 键零用例**（§12.1，含 `call_id`/`version`/`inner_ip.proto=1/6`/合法 hex `sub_address`/合法 `host_name` 等）；④ Error Code 全枚举（RFC 2637 §2.16 七值） | A′ 补例（§13 候选清单）；**不得冒充已覆盖** |
| G-PPTP-3 | `pptp.*` tshark 字段**今日零使用**（本机 tshark 3.6.14 有 **58 个** `pptp.*` 字段，含 `pptp.control_message_type`/`pptp.call_id`/`pptp.magic_cookie`/`pptp.length` 等）——存量 20 例只断 `tcp.len` + frames hex | A′ 收编（可把 §3 的逐字段默认值改成字段断言；本版 §3 的实测值即候选期望） |
| G-PPTP-4 | **保活定时器不实现**：RFC 2637 §3.1.4 的 60 秒 Echo 定时器不建模，`echo=true` 是配置驱动单次插入；且 `resolveDefaults` 的 Host/Vendor 缺省（Host 空 + Vendor "Microsoft"）**不是** D-PPTP-1 B′ 注记设想的 MS 客户端形（"machine"/"Microsoft Windows NT"） | **明确不解决**（定时器非本生成器范围）；B′ 注记的 MS 缺省须**实测现网拨号包**后确认或删除该注记 |
| G-PPTP-5 | **结果产物 pcap 留档缺失**：`trafficgen/docs/protocol-pcap-test/pptp.md`（**tracked 产物**）写 `Cases: 20 — pass 20, fail 0, error 0`，末次提交 `08b8738b`（**2026-09-20**）**晚于**判死提交 `0417be5`（2026-09-13）✓ **未过期**；但 `docs/protocol-pcap-test/pptp/` **目录不存在（0 个 pcap）**，表内 13 个正例的 `[pcap](pptp/*.pcap)` 链接**全部悬空** → 该 20/20 **未经今日复跑证实、无任何 pcap 可查**；另 **NIC 路未跑**（D-PPTP-1 性能段自注"网卡路未跑"）。**本车道未跑该套件，故不以任何形式**（含"今日已跑通"）引用该数字 | **代码阶段**（P5 重跑套件后重生成产物 + 落 pcap 留档 + 补 NIC 路）；本版**不删不改**该产物（tracked，删除属 P5 动作），仅登记事实 |
| G-PPTP-6 | **长度/上界守卫缺失 3 处**：① 内层 `inner_ip.payload` 无上限（可产出超 MTU 的内嵌 IP 包，RFC 2637 §2 规定 GRE 内 MTU 1532，**无守卫**）；② GRE Key 高 16 位 Payload Length 是 uint16，payload 超 65535 静默截断（`fillPPTPGRE`，`builder.go:931`）；③ hex `sub_address` 超 64B 被 `copy` 静默截断（`planner.go:247-249`，不走 64B 字符串检查） | A′ 补例 + P4 裁定（拒绝 or 登记上限） |
| G-PPTP-7 | **IPv6 外层零用例**（`planner_test.go:966` 有 `TestPlanner_IPv6Hosts` 单测，**无用例**）；且 **`dst_port` 今日无配置通道**（层 Fields 无端口键 + 0-keep 豁免）→ 非默认端口不可表达 | A′ 补 IPv6 例；`dst_port` 通道需求 P4 裁定（登记 `dst_port` 键 or 明确不支持） |
| G-PPTP-8 | **状态机与配置表达能力缺口 4 处**：① 版本协商不建模（SCCRQ/SCCRP 共用 `version`，**版本不一致不可表达**）；② TCP 碰撞处理（§3.1.3）不实现；③ Call ID 回绕无检测（`callID + uint16(callIdx)`，`calls` 大时静默回绕）；④ **`calls=0`/`sli_count=0` 不可表达"零"**（§5.5 双层默认：显式 0 被 planner 当"用默认"）——唯一可表达零的键是 `data_frames`/`down_data_frames` | ①②**明确不解决**（剧本回放非状态机应答）；③④ A′ 裁定（加守卫 or 明确文档化） |
| G-PPTP-9 | `CheckProtoFlat` **无 pptp 分支**（顶层 `pptp` 子映射 presence 不判死）+ **无游离顶层键通用门** | P4 先实测再建例；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单）；与 G-OPCUA-1 / G-MOXA-2 同款 |
| G-PPTP-10 | **动态字段全关**（allowlist 无 `pptp` 行，51 键零动态）——其中 `call_id`/`peer_call_id`/`host_name`/`vendor_name`/`inner_ip` 5 项有真实逐流变需求 | A′ 候选（§12.12 表）；今日**不冒充已覆盖**（§9.36 口径） |

## 15. 修订记录

- v1.0.0（2026-09-29）：P-PIPE 文档轨批次二 as-built 定稿。承 D-PPTP-1（`CODE_DESIGN.md:3040`）全部裁定与实测结论；**19 项旧稿/存量校正**（§0，含 3 处存量断言缺陷、1 处 notes 与实现相反、1 处"缺省 5"表述误导、1 处 B′ 注记未落码）；§3 逐字段线格式（15 消息 + GRE 增强头 + PPP + 内嵌 IP，全部对参考 pcap 实测或 RFC 原文标注）；§3.8 GRE 与基础 GRE 八项差异逐条；§5.1 四个非直觉点（tunnel_only 语义/合并段/CCDN 双向 PNS id/data_only 直返）；§5.3 非法转移八条；§5.5 默认值双层结构（0 语义陷阱）；§9.1 包数公式（机读复算 13/13）；§10 八项矩阵 + 三子表（24 格 / 59 行 / 18 行）；§12.1/12.3/12.12/12.13 强制展开；缺口 G-PPTP-1…G-PPTP-10。**未动任何 `.go` 与 `cases/*.json`**。
- 自审记录：见 testcase §10（两份文档同批自审 4 轮，末轮干净）。

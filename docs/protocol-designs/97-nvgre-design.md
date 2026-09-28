# #97 nvgre（网络虚拟化 GRE，Network Virtualization using Generic Routing Encapsulation）设计契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3）
> 日期：2026-09-28
> 车道：文档轨（Lane，nvgre RESUME，#97）
> 旧基线：`docs/protocol-designs/55-nvgre-design.md` v1.0.0 + `55-nvgre-testcase.md` v1.0.0（20 例 = 14 正 + 6 负；本 #97 为 P-PIPE 重做，思路继承、不搬码——旧稿"层尚未注册/代码未写"状态已过时，见 §0）
> 存量用例：`trafficgen/test/protocol_pcap/cases/nvgre.json`（20/20 ID 与旧稿一致，顺序一致，已机读实测；**20/20 存量今日全量失效（0 pass）**——扁平形被 `CheckProtoFlat` 拒（`strategy_convert.go:8625-8637`）、层链形被 `unknown field` 拒（`complete.go:293`），两路皆红；顶层旧键 **56 处**残留（**非负例口径**：14 正例 × 4 键 src_ip/dst_ip/count/nvgre，各 14；全例口径 80）。迁移待**代码阶段**，G-NVGRE-1；本版**不动 cases**，见 §12.1）
> 规范基线：① RFC 7637（NVGRE）+ RFC 2784/2890（GRE 基础头与扩展）；② 旧基线设计文档（内部契约，非外部规范）；③ 本仓库落码（registry/generator/validator/convert/chain_planner，§11.1）；④ 本机 tshark 实测（有 `gre.*`/`eth.*`/`ip.*`/`vlan.*` 通道，**无 `nvgre.*` dissector**）；⑤ 公开资料 + 假设（逐处标注）
> 白话一句：**NVGRE 就是把一整个以太网帧（带着它自己的 MAC 和 IP）塞进一个 GRE 信封里寄出去，信封上盖的编号（VSID）决定这帧属于哪个虚拟子网；引擎里它是一层"自己造整封信"的终结层，不走 TCP/UDP，没有端口。**

## 0. 55→97 沿革与旧稿过期声明校正（门1 必答：基线继承关系）

本 #97 与旧稿 `55-nvgre-*` 是**同一协议的重做契约**，不是新协议。旧稿保留在磁盘只读参考，本契约逐条校正旧稿已过时的状态声明：

| # | 旧稿说法（55-*） | HEAD 实测（2026-09-28） | 校正结论 |
|---|---|---|---|
| 1 | "`nvgre` 层尚未注册，不修改 Go 实现，不宣称当前 suite 可运行"（design 头注） | `registry.go:1695` 已注册 `nvgre`（`CategoryTerminal`，`DependsOn ["ip"]`，**无 Fields、无 FieldContract**）；生成表 `layers.generated.json` nvgre = `{"category":"terminal","depends_on":["ip"],"fields":{}}`（机读实测） | "未注册"已过时；本契约 §11 为 as-built 逆向定稿 |
| 2 | 推荐层链 `[ip, gre, nvgre]`（design §2） | 实现为 **`[ip, nvgre]` 直连**——registry 注记明写分歧：gre 隧道层生成器要求内层包链（`req.Inner` 产 L3/L4 包）且 ProtocolType 限 0x0800/0x0806/0x86DD，而 NVGRE 内层是**裸 Ethernet 帧**，无法复用；故由 nvgre 生成器自写外层 IP + `L2.GRE`（`registry.go:1688-1694`） | 层链形状以 `[ip,nvgre]` 为唯一真相；旧稿 `[ip,gre,nvgre]` 作废（§2） |
| 3 | "NVGRE 使用 IP protocol 47 的 GRE，**不使用 UDP**"（design §2） | 生成器 `L3.Protocol = core.ProtocolGRE`（`layer_gen.go:90`），包内无 UDP/TCP 头；`isRawIPChain` 收录 nvgre（`chain_planner_util.go:54`） | 旧稿此条**正确**；本版重申：**无 UDP 4789 载体、无端口概念**（与同族 vxlan/geneve 的 UDP 载体形状不同，§2/§12.1） |
| 4 | "当前仓库没有注册 `nvgre` layer、planner、validator 或生成器"（design §1） | `internal/protocol/nvgre/layer_gen.go` 397 行已落码（生成器 + validator + `init()` 注册）；13 个 `Test*` 函数（`grep -c` 实测） | 已落码；本契约 §11 为 as-built 定稿 |
| 5 | `NVGREConfig{Profile, Outer, VSIDs[], WireFault}`（design §5 typedef，"设计契约，不是当前存在的 Go struct"） | `internal/core/encapsulation.go:298` 实际定义为 `NVGREConfig{VSID, FlowID, TTL*, Inner*, Datagrams[], WireFault*}`（**无 Profile/Outer/VSIDs**）；`NVGREOuter`/`NVGREVSID`/`NVGREInner` 三个旧 typedef **不存在** | 旧 typedef 作废；as-built 结构体见 §11.3（§3.1/§3.2 逐字段） |
| 6 | 旧稿 spec_json 样例全部顶层扁平键（design §5 + 存量 20 例） | 存量 20/20 例含顶层 `src_ip`/`dst_ip`/`count` + 顶层 `nvgre` 子映射（机读 **56 处**残留，**非负例口径**：14 正例 × 4 键，各 14）；20/20 均无 `layers` 键 | 旧样例形**今日全量失效**（0 pass——扁平路径已被 `CheckProtoFlat` 关闭，非「仍可跑的过渡态」）；迁移需**先补代码**（G-NVGRE-1），故 cases 本版**保持原样**（改了硬红、不改也全红，两条理由见 §12.1）；本契约 §2 样例只给纯层链形（目标形，今天跑不通） |
| 7 | 旧稿断言 `gre.key` 值为 `0x0003e801` 等 hex，并注"tshark 渲染格式待校准" | 生成器 `GREKey()` 用 `(vsid & 0xffffff) << 8 \| flowID`（`layer_gen.go:181-183`），builder 经 `binary.BigEndian.PutUint32` 落线；单测 `TestGREKeyBytes`（`layer_gen_test.go:35`）钉 raw bytes | 断言以 **raw frames hex** 为准（`frames[].hex`），不依赖 `gre.key` 的渲染格式；旧稿"待校准"注记由 §3.1 raw 字节面收口 |
| 8 | 旧稿 §9 #12 要求"IP 分片/重组" | 生成器每 datagram 发**完整单帧**，不做底层 IP 分片；`maxInnerPayload = 0xffff - 42 - 20` 兜住外层 IPv4 total length 回绕（`layer_gen.go:53`），超限由 validator 拒（`layer_gen.go:384`） | 分片面按"完整大 payload 单帧 + 长度上界拒绝"表达（§8）；旧稿"分片重组"降级为长度边界例 |

**依赖链判定纪律**：以上均为可判题（旧文→代码→用例三级对照），直接判定，不问偏好。不可判的标"待确认"并写清确认方式。

## 1. 范围、profile 与实现状态边界

本版定义 NVGRE **数据面封装**：外层 IPv4/IPv6 承载 IP protocol 47 的 GRE，GRE 内层是**裸 Ethernet 帧**（`ProtocolType = 0x6558` Transparent Ethernet Bridging）。覆盖单 VSID、多 VSID、多 Flow ID、内层 IPv4/IPv6、内层 VLAN、长度边界与错误传播。控制面、NHRP、ARP/ND 代理、隧道端点发现、策略路由、加密和云厂商私有扩展不由本 profile 推导。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `nvgre_v1`（主） | 外层 IPv4/IPv6 + GRE proto 47 | GRE Key、VSID/Flow ID、inner Ethernet、inner IPv4/IPv6、可选内层 VLAN | 隧道建立、端点发现、MAC 学习或业务可达性 |
| `nvgre_multi_vsid` | 同上 | 同一 fixture 中显式多个 VSID 与 Flow ID（`datagrams[]`） | 未声明的跨 VSID 转发或广播复制 |
| `nvgre_boundary` | 同上 | 24-bit VSID、8-bit Flow ID、内层帧长度边界 | 超范围值的截断、回绕或隐式修正 |

显式边界（"不实现、不声称、不许静默转换"）：不生成 TCP/UDP 握手（NVGRE 无连接）；不自动生成 ARP/ND/MAC 学习/无限广播；不把底层 IP 分片当 Ethernet frame 边界；**不使用 UDP 4789 或任何传输层载体**（IP proto 47 是唯一载体）。

**实现状态（2026-09-28 实测）**：`nvgre` 层已注册（`registry.go:1695`）；生成器 + validator 已落码（`internal/protocol/nvgre/layer_gen.go` 397 行）；`allowedProtocols["nvgre"]=true`（`protocols.go:63`）；`RegisterPlanner(NewChainPlanner("nvgre"))`（`main.go:504`）；`isRawIPChain` 收录（`chain_planner_util.go:54`）；20 语义用例已落 `cases/nvgre.json`。旧稿"代码未写"描述已过时（§0 表）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`ip.proto`、`gre.proto`、`gre.flags_and_version`、`eth.*`、`vlan.*`、`frames[].hex` raw 字节）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。NIC 侧允许 checksum offload 差异，但 GRE flags/protocol/Key/inner Ethernet 字节不得放宽。

## 2. 协议栈、端口和固定偏移

推荐层链为 **`[ip, nvgre]`**（引擎自动补 `ip`；nvgre 是 raw-IP 终结层，`DependsOn ["ip"]`）。**无传输层、无端口概念**——这是本协议与同族 vxlan/geneve 的**关键形状差异**：

| 协议 | 层链 | 载体 | 端口 | registry FieldContract |
|---|---|---|---|---|
| vxlan | `[ip, udp, vxlan]` | UDP 4789 | 有（`udp.src_port/dst_port`） | `{"udp.dst_port": "4789"}` |
| geneve | `[ip, udp, geneve]` | UDP 6081 | 有 | `{"udp.dst_port": "6081"}` |
| **nvgre** | **`[ip, nvgre]`** | **IP proto 47 GRE** | **无** | **无**（`DependsOn ["ip"]`） |

**端口**：无。`validateSpecBase` 把 nvgre 列入"无端口概念"豁免名单（`chain_planner.go:770`），目的/源端口 0 合法。用例**不得**写 `layers[udp]`、不得写 `udp.dst_port`。

### 2.1 同族 vxlan/geneve 层 Fields 实况对比（2026-09-28 机读，防"照抄范本"）

任务前提「三兄弟层形状应当一致」经核**不成立**，且「照抄 vxlan/geneve 用例作范本」亦**不成立**——但**三者存量形状并不同形**（机读：vxlan/geneve 20/20 **带 `layers`**，是「layers + 顶层残留**并存**」形；nvgre **0/20 带 `layers`**，是**纯扁平**形）：

| 协议 | registry Fields（`registry.go`） | FieldContract | DependsOn | cases 形状（机读） |
|---|---|---|---|---|
| vxlan | **`{}` 空** | `{"udp.dst_port":"4789"}` | `["udp"]` | **layers + 顶层残留并存形**（`layers` 20/20 = `[ip,udp,vxlan]`）：**70 处顶层旧键**（非负例口径）= 扁平标量 56（`src_ip`/`dst_ip`/`src_port`/`dst_port` 各 14）+ 顶层 `vxlan` 子映射 14 |
| geneve | **`{}` 空** | `{"udp.dst_port":"6081"}` | `["udp"]` | **layers + 顶层残留并存形**（`layers` 20/20 = `[ip,udp,geneve]`）：**70 处顶层旧键**（非负例口径）= 扁平标量 56（`src_ip`/`dst_ip`/`src_port`/`dst_port` 各 14）+ 顶层 `geneve` 子映射 14 |
| **nvgre** | **`{}` 空** | **无** | **`["ip"]`** | **纯扁平形**（`layers` **0/20**）：**56 处顶层旧键**（非负例口径）= 扁平标量 42（`src_ip`/`dst_ip`/`count` 各 14）+ 顶层 `nvgre` 子映射 14 |
| icmp（真范本） | `{code,data,identifier,pattern,sequence,type}` | `{"ip.protocol":"1"}` | `["ip"]` | **纯层链**：`[ip,icmp]` ×8，顶层仅 `layers`（1 例 presence 负例除外） |
| moxa（P4 后范本） | `{sessions,stream}` | 无 | `["tcp"]` | **纯层链**：23 例（含 20 处 A′ 新增） |

**结论**：① nvgre/vxlan/geneve 三层 Fields **同为空壳**——三者的层内配置今日**都不被解码**（`chain_planner_translate.go:852` 对空 Fields 提前返回）；② 三者的 cases **形状并不同形**——vxlan/geneve 是「layers + 顶层残留并存」（`layers` 20/20），nvgre 是纯扁平（`layers` 0/20）；**两者皆不可作「已全层链」范本**（残留未清）；③ 可作范本的是 **icmp**（`[ip,icmp]` raw-IP 同构，8 例全层链）与 **moxa**（P4 完成后 23 例）。④ nvgre 与 vxlan/geneve 的**形状差异**（`DependsOn ["ip"]` vs `["udp"]`、无 FieldContract vs 有）来自协议本身——**不因同族而趋同**。

固定偏移（无 VLAN/IP options/外层扩展头时，`frames[].hex` 逐字节锚点）：

| 观察点 | 外层 IPv4 | 外层 IPv6 |
|---|---:|---:|
| 外层 Ethernet | 0（14B） | 0（14B） |
| 外层 IP 头 | 14（20B） | 14（40B） |
| GRE FlagsAndVersion | **34** | **54** |
| GRE ProtocolType | 36 | 56 |
| GRE Key | **38** | **58** |
| inner Ethernet DstMAC | **42** | **62** |
| inner Ethernet SrcMAC | 48 | 68 |
| inner EtherType（无 VLAN） | **54** | **74** |
| inner VLAN TPID（`vlan_*` 时） | 54 | 74 |
| inner EtherType（有 VLAN） | 58 | 78 |

GRE 基础头 4 字节；NVGRE 必须置 Key Present（K）位，Key 字段紧随其后占 4 字节，故 inner Ethernet 起点 = 外层 IP 头尾 + 8。IPv4 外层 42、IPv6 外层 62。若外层 IP options、IPv6 扩展头、外层 VLAN 或显式内层 VLAN 存在，断言必须按实际头长定位，**不能继续套用上述常量**。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**目标形状声明**：registry `nvgre` Fields 今日为空 + `translateTerminalConfig` 对空 Fields 层提前返回（`chain_planner_translate.go:852`），层内任何键今日被 `ValidateLayerConfig` 以 `unknown field` 拒（函数起 `complete.go:279`，拒绝返回在 `:293`）→ 此形**今天跑不通，需先补代码** G-NVGRE-1，CORE_MEMORY §1.9 口径）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "198.51.100.10"}},
    {"nvgre": {
      "vsid": 1000,
      "flow_id": 1,
      "inner": {
        "src_mac": "02:aa:00:00:00:01",
        "dst_mac": "02:bb:00:00:00:01",
        "ether_type": "ipv4",
        "src_ip": "172.16.1.1",
        "dst_ip": "172.16.1.2",
        "payload_b64": "bnZncmUtaW5uZXItMDE="
      }
    }}
  ]
}
```

多 datagram 样例（`datagrams[]` 逐条独立 VSID/FlowID/inner，entry `inner` 缺席回退顶层 `inner`）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.70", "dst": "198.51.100.70"}},
    {"nvgre": {
      "vsid": 1000,
      "flow_id": 1,
      "inner": {"src_mac": "02:aa:00:00:00:07", "dst_mac": "02:bb:00:00:00:07",
                "ether_type": "ipv4", "src_ip": "172.16.7.1", "dst_ip": "172.16.7.2",
                "payload_b64": "bnZncmUtdnNpZGEtcGF5bG9hZA=="},
      "datagrams": [
        {"vsid": 1000, "flow_id": 1},
        {"vsid": 300000, "flow_id": 1,
         "inner": {"src_mac": "02:aa:00:00:00:08", "dst_mac": "02:bb:00:00:00:08",
                   "ether_type": "ipv4", "src_ip": "172.16.8.1", "dst_ip": "172.16.8.2",
                   "payload_b64": "bnZncmUtdnNpZGEtcGF5bG9hZA=="}},
        {"vsid": 16777215, "flow_id": 1,
         "inner": {"src_mac": "02:aa:00:00:00:09", "dst_mac": "02:bb:00:00:00:09",
                   "ether_type": "ipv4", "src_ip": "172.16.9.1", "dst_ip": "172.16.9.2",
                   "payload_b64": "bnZncmUtdnNpZGEtcGF5bG9hZA=="}}
      ]
    }}
  ]
}
```

外层 IPv6 样例（地址族由 `ip` 层地址字面量决定，不改写内层族）：

```json
{
  "layers": [
    {"ip": {"src": "2001:db8::10", "dst": "2001:db8::20"}},
    {"nvgre": {"vsid": 2000, "flow_id": 2,
               "inner": {"src_mac": "02:aa:00:00:00:02", "dst_mac": "02:bb:00:00:00:02",
                         "ether_type": "ipv4", "src_ip": "172.16.2.1", "dst_ip": "172.16.2.2",
                         "payload_b64": "bnZncmUtaW5uZXItMDE="}}}
  ]
}
```

## 3. 线格式编码（逐项标注出处）

### 3.1 GRE 头与 Key

NVGRE GRE 头遵循 RFC 2784/7637：

```text
FlagsAndVersion(2) | ProtocolType(2) | Key(4) | InnerEthernetFrame(N)
```

- `FlagsAndVersion` 确定值 **`0x2000`**（K=1；C、R、S、s、Recursion、Version 全 0，`layer_gen.go:27`）。
- `ProtocolType` 必须 **`0x6558`**（TEB，`layer_gen.go:30`）。
- Key 按**网络字节序**：`Key(32) = VSID(24) << 8 | FlowID(8)`（`layer_gen.go:181-183`）；builder 用 `binary.BigEndian.PutUint32` 落线，故 raw bytes = `VSID[23:16] | VSID[15:8] | VSID[7:0] | FlowID`。
- 例：VSID=`0x123456`、FlowID=`0x7a` → raw bytes `12 34 56 7a`。
- VSID 合法范围 `0x000000`–`0xffffff`（24-bit）；Flow ID `0x00`–`0xff`（8-bit）。VSID 不得截断为 16 位，Flow ID 不得混入 VSID。
- 单测锚点：`TestGREKeyBytes`（`layer_gen_test.go:35`）。

### 3.2 内层 Ethernet 帧

`buildInnerFrame`（`layer_gen.go:189-239`）产出：

```text
DstMAC(6) | SrcMAC(6) | [802.1Q(4)] | EtherType(2) | inner L3 | payload
```

- **MAC 原样保留**，不换外层 MAC（内层 fixture 的 MAC 就是内层 MAC）。
- `ether_type` 取值 `ipv4` | `ipv6` | `vlan_ipv4` | `vlan_ipv6`（`layer_gen.go:342-350`）；`vlan_*` 先插 802.1Q tag：TPID `0x8100` + TCI = `PCP(3)<<13 | DEI(0) | VID(12)`（`layer_gen.go:224-229`）。
- 内层 EtherType：`ipv4`→`08 00`，`ipv6`→`86 dd`（`layer_gen.go:230-234`）。
- **内层 IP 头**：内层 IPv4 用 `protocol=253`（RFC 3692 未指派，`layer_gen.go:41`）、TTL 64、checksum 由生成器计算（`ipv4Checksum`，`:243`）；内层 IPv6 用 `Next Header=59`（No Next Header，`:42`）、Hop Limit 64。**这是刻意选择**：让 tshark 不把内层载荷误解析成畸形伪影（`:37-40`）。
- 内层 IP 地址族必须与 `ether_type` 一致（`validator` 拒混族，`:358-377`）。
- 内层 VLAN：VID 0–4095（12-bit）、PCP 0–7（3-bit）（`:352-357`）。

### 3.3 长度与上界

- 内层 IPv4 payload 上界 `maxInnerPayload = 0xffff - 42 - 20`（`:53`），保证外层 IPv4 total length 不回绕。
- 内层 IPv6 payload 上界 `0xffff - 20 - 8 - 14 - 40`（`:379`）。
- 超限由 validator 拒（`layer_gen.go:384` / `:380`），不静默截断。

### 3.4 外层 IP 头

外层 IPv4：protocol 47、TTL 由 `nvgre.ttl` 解析（nil→64，`layer_gen.go:169-174`）、total length/checksum 由 builder 计算。外层 IPv6：Next Header 47、Hop Limit 同 TTL 语义。外层地址族由 `ip` 层地址字面量决定，**不改写内层 EtherType**（`layer_gen.go:230-234` 按 `fix.EtherType` 独立选族）。

### 3.5 tshark 通道

本机 tshark 3.6.14 **有** `gre.*`（`gre.proto`/`gre.flags_and_version`/`gre.key`）、`eth.*`、`ip.*`/`ipv6.*`、`vlan.*` 通道；**无 `nvgre.*` dissector**。断言以 `frames[].hex` raw 字节为主锚（偏移见 §2），tshark 字段为辅证。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置是剧本（`datagrams[]` 逐条声明 VSID/FlowID/inner 帧），引擎按序产出事件，nvgre 生成器逐条 emit 完整包。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 单租户隧道 | 一条 flow 封装一个 VSID 的以太网帧 | #1（`nvgre_basic_ipv4_inner_ipv4`） |
| ② 多租户共存 | 一条 flow 承载多 VSID，Key 高 24-bit 隔离 | #7（`nvgre_multi_vsid`） |
| ③ 同租户多流 | 同 VSID 多 Flow ID，Key 低 8-bit 隔离 | #8（`nvgre_multi_flow_same_vsid`） |
| ④ 跨代网段 | 外层 v6 承载 / 内层 v6 载荷（族独立组合） | #2/#3/#4/#11 |
| ⑤ 内层带 VLAN | 内层 802.1Q tag 透传 | #9（`nvgre_inner_vlan`） |
| ⑥ 大帧隧道 | 大内层帧完整单帧发出 | #12（`nvgre_mtu_reassembly`） |

**五层覆盖逐层结论**：功能层——GRE 头/Key/inner 帧每类正例 + 拒绝分支 6 类负例；性能层——大内层帧（§8 上界）、最小/空 payload 边界（#10）、多 datagram 展开（#7/#8 各 3 包）；数据场景层——VSID/FlowID 边界（0/1/0xffffff/0xff，`#5`/`#6`）、Key 字节序（`#12`/`#14`）、MAC 边界（广播 `#10`）、VLAN 边界（`#9`）、族组合（`#11`）；地址与流层——v4/v6 独立用例（`#1`–`#4`、`#11`）、单流基线、多 VSID/多 Flow；**流关联（控制流派生数据流）显式不适用**——NVGRE 是无连接封装，无主从流；**多流（会话内并发流）由 `datagrams[]` 表达**（同 flow 多包），跨 flow 数量走 `flow_control`。业务层——多租户/多流/跨代/带 VLAN 四场景。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① TCP/UDP 握手与挥手（无连接封装，无握手可测）；② 保活/重试/重连（NVGRE 无 keepalive 语义）；③ IP 分片/重组（生成器发完整单帧，分片面按长度上界表达，§8）；④ ARP/ND 代理与 MAC 学习（控制面，不在 profile）。

## 5. 消息/事务模型与状态机

**事务定义**：一条 flow 内一个 NVGRE datagram 的发送。**多事务** = 一 flow 内多 datagram 按序 emit（`datagrams[]`，#7/#8 各 3 个）。

nvgre 层**无自有状态**：无连接、无握手、无序号、无挥手；生成器是"按配置顺序把 datagram 翻译成完整包"的纯函数驱动（`foldDatagrams`，`layer_gen.go:125-142`）。

| 状态 | nvgre 层动作 | 用例 |
|---|---|---|
| 无状态（每条 datagram 独立） | 逐条 emit 完整包：外层 IP + GRE + Key + inner 帧 | #1–#14 |
| 结束 | 事件流结束（无挥手报文） | 全正例 |

**多 datagram 展开**：`foldDatagrams`（`layer_gen.go:125`）——`Datagrams` 空 → 用顶层 `VSID/FlowID/Inner` 发**单包**；非空 → 逐 entry 发一包，entry `inner` 缺席回退顶层 `inner`（`layer_gen.go:136-139`）。方向：`Up` 指针 `nil`/`true` = up，`false` = down（`layer_gen.go:81-84` 仅置 direction 字符串；**L3 地址交换在 raw-IP 分支的 Emit 闭包 `chain_planner.go:1546-1547`**）。

**自动派生规则**：① 空层 config（`{}`）→ 生成器用 `defaultFixture()`（`layer_gen.go:156-165`：MAC `02:00:00:00:00:01/02`、EtherType ipv4、IP `172.16.1.1/2`、payload `nvgre-default-inner`），vsid/flow 均 0——P0b 空配置默认流；② 外层 Ethernet 头由引擎补；③ 外层 IP 头/GRE 头由生成器自产（raw-IP 链）；④ TTL 缺省 64。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单 flow 每 datagram 一包（无握手挥手开销，与 moxa 的 `3+N+4` 公式不同）；多 datagram 顺序展开（#7/#8 各 3 包）；大内层帧受 `maxInnerPayload` 上界约束（§3.3）。吞吐数字待 P4 基准，**本版不写承诺**（§6.5）。
- **依据**：`foldDatagrams` 流式展开（切片遍历 + 逐条 `req.Emit`，无全量收集，`layer_gen.go:76-110`）；每包内存 = 内层帧长 + 外层头开销（O(帧)）；无跨流共享状态；无锁（常量只读）。ctx 取消逐条检查（`layer_gen.go:102-105`）。
- **验收两路**：pcap（`/tmp/mcp-pcaps/nvgre/`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `gre.flags_and_version`/`gre.proto`/Key raw 字节/inner MAC 与 payload hex，不只断言"任务没报错"。
- **六类场景落点**：基线（#1，1 包）/ 目标规模（#7/#8，3 包多 datagram）/ 压力上限（#12 大内层帧 + 长度上界拒绝）/ 长时间运行（多 datagram 顺序展开承载语义）/ 并发交错（单 flow 内顺序，跨 flow 由 worker 调度，不假设全局包序）/ 背压（`packet_count` 精确计数守卫 datagram 数漂移）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 validator 拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩外层 IP/GRE 的假成功。锚词取自 `layer_gen.go` 错误字面值（`:274-388`）：

| # | 负例 ID | 故障输入 | `error_contains` | 代码出处 |
|---:|---|---|---|---|
| N-1 | `nvgre_neg_gre_flags_protocol` | `wire_fault.kind="flags_reserved"`（C/R/S/s/reserved/version 非法） | `flags` | `:307` |
| N-2 | `nvgre_neg_key_vsid_flow` | `vsid=16777216`（> 24-bit） | `vsid` | `:279` |
| N-3 | `nvgre_neg_inner_ethernet_vlan` | `inner.src_mac="not-a-mac"` | `inner` | `:335` |
| N-4 | `nvgre_neg_address_family` | `inner.ether_type="ipv6"` + `inner.src_ip` 为 IPv4 | `family` | `:368` |
| N-5 | `nvgre_neg_carrier_length` | `wire_fault.kind="length_wrap"` | `length` | `:319` |
| N-6 | `nvgre_neg_vsid_flow_isolation` | `wire_fault.kind="vsid_flow_isolation"` | `isolation` | `:315` |
| N-7 | `nvgre_neg_presence_top_level_nvgre` | `layers` 链 + 顶层 `nvgre:{}` 并存 | `top-level` | 目标：`CheckProtoFlat`（**今日无 nvgre 分支**，G-NVGRE-2） |

**wire_fault 完整 kind 表**（`layer_gen.go:259-268`，7 种，全库已落码）：`flags_reserved`、`protocol_not_teb`、`key_missing`、`key_endian`、`vsid_flow_isolation`、`carrier_protocol`、`length_wrap`；未知 kind 亦拒（`:321`）。**存量仅用 3 种**（`flags_reserved`/`length_wrap`/`vsid_flow_isolation`），余 4 种 A′ 立项（testcase §6.2）。

**负例原子性**：每例单一故障注入；单次执行不得混注。

**不得误报的合法协议事件**：VSID=0 / FlowID=0（#5）、VSID=0xffffff / FlowID=0xff（#6）、空 payload（#10）、显式广播 MAC（#10）、`vlan_id=0`、TTL=255（#14）。

## 8. 边界

- **VSID/FlowID**：0、1、0xffffff、0xff 均已覆（#5/#6）；越界拒（N-2）。
- **Key 字节序**：raw `12 34 56 7a` 已覆（#12/#14）；主机序/截断由 `key_endian`/`key_missing` fault 表达（A′）。
- **内层 payload**：空 payload 合法（#10，帧 = 14B eth + 20B ip = 34B）；最大 payload 受 `maxInnerPayload` 约束（§3.3），精确上界例 A′ 立项。
- **MAC**：显式广播 `ff:ff:ff:ff:ff:ff` 原样落（#10）；非法 MAC 拒（N-3）。
- **VLAN**：VID=100/PCP=3 已覆（#9）；VID 上界 4095 / PCP 上界 7 A′ 立项；`vlan_id=0` 合法。
- **地址族**：v4/v6 外层 × v4/v6 内层四组合（#1–#4、#11）；异族混写拒（N-4）。
- **TTL/Hop Limit**：缺省 64 / 显式 255 已覆（#14）；显式 0 与 1 A′ 立项（builder 对 0 的默认化行为待跑后钉）。
- **多 datagram**：多 VSID（#7）/多 Flow 同 VSID（#8）已覆；`datagrams[]` 内 entry `inner` 缺席回退顶层 A′ 立项。
- 不得产生回绕长度或超量分配（大帧显式声明，超限拒绝，不隐式放大）。

## 9. 原子 ID 与完成定义（20 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count |
|---:|---|---|---|---:|
| 1 | `nvgre_basic_ipv4_inner_ipv4` | 正 | §3.1/§3.2/§3.4：outer v4 + GRE + inner Ethernet/IPv4 | 1 |
| 2 | `nvgre_outer_ipv6_inner_ipv4` | 正 | §3.4：outer v6（NH=47）+ inner IPv4 | 1 |
| 3 | `nvgre_outer_ipv4_inner_ipv6` | 正 | §3.2：outer v4 + inner IPv6（EtherType 0x86dd） | 1 |
| 4 | `nvgre_basic_ipv6_inner_ipv6` | 正 | §3.4：outer/inner IPv6 独立 fixture | 1 |
| 5 | `nvgre_vsid_zero_flow_zero` | 正 | §3.1：VSID=0/FlowID=0 显式保留 | 1 |
| 6 | `nvgre_vsid_max_flow_max` | 正 | §3.1：VSID=0xffffff/FlowID=0xff 不截断 | 1 |
| 7 | `nvgre_multi_vsid` | 正 | §5：多 VSID，Key 高 24-bit 隔离 | 3 |
| 8 | `nvgre_multi_flow_same_vsid` | 正 | §5：同 VSID 多 Flow ID，低 8-bit 隔离 | 3 |
| 9 | `nvgre_inner_vlan` | 正 | §3.2：内层 802.1Q（TPID/TCI/VID） | 1 |
| 10 | `nvgre_inner_ethernet_boundary` | 正 | §3.2/§8：广播 MAC、空 payload、Ethernet 边界 | 1 |
| 11 | `nvgre_outer_inner_family_matrix` | 正 | §4：族矩阵（内层二分 + 外层由 #2/#4 覆盖） | 2 |
| 12 | `nvgre_mtu_reassembly` | 正 | §3.3/§8：大内层帧完整单帧 + Key raw 字节 | 1 |
| 13 | `nvgre_pcap_nic_consistency` | 正 | §1：pcap/NIC 同一断言集 | 1 |
| 14 | `nvgre_key_endian_and_ttl` | 正 | §3.1/§8：Key 网络字节序 + TTL=255 边界 | 1 |
| 15 | `nvgre_neg_gre_flags_protocol` | 负 | §7 N-1 | — |
| 16 | `nvgre_neg_key_vsid_flow` | 负 | §7 N-2 | — |
| 17 | `nvgre_neg_inner_ethernet_vlan` | 负 | §7 N-3 | — |
| 18 | `nvgre_neg_address_family` | 负 | §7 N-4 | — |
| 19 | `nvgre_neg_carrier_length` | 负 | §7 N-5 | — |
| 20 | `nvgre_neg_vsid_flow_isolation` | 负 | §7 N-6 | — |

完成定义：`[ip,nvgre]` 层链注册已落码；GRE 头/Key/inner Ethernet/VLAN 逐字节可生成验证；outer/inner 族组合、VSID/FlowID 边界、多 VSID/多 Flow、长度边界与错误传播可观测；20 ID 正负断言完成；不声称控制面行为。

**T-编号对照**：T-NVGRE-S1…S14 ≡ #1…#14；T-NVGRE-N1…N6 ≡ #15…#20；N-7 为 P4 新增 presence 负例（不计入 20 语义 ID，见 G-NVGRE-2）。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | 无连接封装；每条 GRE 包独立，无握手（RFC 7637） | 场景①–⑥ | `DependsOn ["ip"]` 单值（`registry.go:1695`）；生成器逐 datagram emit（`layer_gen.go:76`） | 无 |
| 2 | 命令/消息表 | 无应用层命令——适配为"datagram 形态 × 终态"矩阵（§10.2，12 格逐格结论，moxa 适配先例） | 场景①–⑥ | `foldDatagrams` 全分支（`:125`）+ `ValidateConfig` 全分支（`:274`） | 立项 5 格（A′，§13） |
| 3 | 状态机 | 无状态（每条 datagram 独立，§5） | 全正例 | nvgre 层无自有状态；纯函数驱动 | **显式不适用**（无连接），无缺口 |
| 4 | 字段表 | `NVGREConfig` 6 键 + `EncapEthernetFixture` 8 键 + `NVGREDatagram` 4 键（§11.3） | 数据场景层 | builder 直传 + 长度/族/b64/范围校验（`:274-388`） | **层内化缺口 G-NVGRE-1** |
| 5 | 错误处理 | 6 类负例（§7 表）+ 7 种 wire_fault kind | 负例 N-1…N-6 | validator 分支齐（`:299-388`） | 4 种 fault 无用例（A′）；presence 缺分支 G-NVGRE-2 |
| 6 | 超时与活性 | 无保活/重试语义（无连接封装） | — | 协议层无（框架面） | **显式不适用**（§4 声明），无缺口 |
| 7 | NAT/代理/被动 | 无被动模式概念（封装协议） | 场景①–⑥ | 无 | **显式不适用**；NAT 穿透为框架面 |
| 8 | 版本/方言 | RFC 7637 唯一 profile；无版本协商 | 正例 14 | 无版本字段（`FlagsAndVersion` 的 Version 位恒 0，非零即拒） | 无 |

### 10.2 子表①：datagram 形态×终态矩阵（逐格已覆/立项/不适用；适配声明：NVGRE 无命令—响应码，datagram 形态×传输终态为等价口径）

| datagram 形态 | T1 正常 emit 终态 | T2 配置/线格式拒绝 | T3 方向变体（down） |
|---|---|---|---|
| B1 单 VSID 单包 | 已覆（#1–#6、#9、#10、#12–#14） | 已覆（N-1…N-6 代表例，拒绝与形态无关） | A′ 立项（`datagrams[].up=false`，今日无例） |
| B2 多 VSID | 已覆（#7） | 同上代表已覆 | A′ 立项 |
| B3 同 VSID 多 Flow | 已覆（#8） | 同上代表已覆 | A′ 立项 |
| B4 entry inner 缺席回退顶层 | A′ 立项（`datagrams[].inner` nil 回退，代码有分支 `:136-139`，今日无例） | 同上代表已覆 | A′ 立项 |

**逐格重数**：4 行 × 3 列 = 12 格——已覆 7（B1 T1/T2、B2 T1/T2、B3 T1/T2、B4 T2）/ A′ 立项 5（B1 T3、B2 T3、B3 T3、B4 T1、B4 T3），零空格。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **22 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | VSID=0 | 覆（#5） |
| 2 | VSID=1 | 覆（#11） |
| 3 | VSID=0xffffff | 覆（#6） |
| 4 | VSID 越界（0x1000000） | 覆（N-2） |
| 5 | FlowID=0 | 覆（#5、#10） |
| 6 | FlowID=0xff | 覆（#6） |
| 7 | FlowID 越界 | A′ 立项（uint8 类型层天然不可表达 >255，见 §13 注） |
| 8 | Key 网络字节序 | 覆（#12、#14 raw `12 34 56 7a`） |
| 9 | Key 主机序/截断 | A′ 立项（`key_endian`/`key_missing` fault，今日无例） |
| 10 | inner EtherType ipv4 | 覆（#1 等） |
| 11 | inner EtherType ipv6 | 覆（#3、#4） |
| 12 | inner vlan_ipv4 | 覆（#9） |
| 13 | inner vlan_ipv6 | A′ 立项（代码有分支 `:224`，今日无例） |
| 14 | inner 空 payload | 覆（#10） |
| 15 | inner 大 payload | 覆（#12） |
| 16 | inner payload 超上界 | A′ 立项（validator 有分支 `:384`，今日无例） |
| 17 | inner 广播 MAC | 覆（#10） |
| 18 | inner 非法 MAC | 覆（N-3） |
| 19 | inner 族混写 | 覆（N-4） |
| 20 | VLAN VID=0 | A′ 立项（合法边界，代码不拒 `:352`，今日无例） |
| 21 | VLAN VID 上界 4095 / 越界 | A′ 立项（validator 有分支 `:353`，今日无例） |
| 22 | VLAN PCP 上界 7 / 越界 | A′ 立项（validator 有分支 `:356`，今日无例） |

**逐行重数**：15 覆（行 1/2/3/4/5/6/8/10/11/12/14/15/17/18/19）+ 7 立项（行 7/9/13/16/20/21/22）+ 0 不适用 = 22。✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 单租户隧道（RFC 7637 §1 用例） | #1 `nvgre_basic_ipv4_inner_ipv4` | 已覆 |
| 2 | 多租户共存（VSID 隔离语义） | #7 `nvgre_multi_vsid` | 已覆 |
| 3 | 同租户多流（Flow ID 语义） | #8 `nvgre_multi_flow_same_vsid` | 已覆 |
| 4 | 跨代网段（v4 外层 + v6 内层） | #3/#11 | 已覆 |
| 5 | 内层 VLAN 透传（数据中心多租户 VLAN） | #9 `nvgre_inner_vlan` | 已覆 |
| 6 | 大帧隧道（jumbo 内层帧） | #12 `nvgre_mtu_reassembly` | 已覆 |
| 7 | 控制面（NHRP/端点发现） | — | **明确不解决**（v1 范围外，§1） |
| 8 | 加密/云厂商私有扩展 | — | **明确不解决**（v1 范围外，§1） |

6 覆 + 2 不适用 = 8。✓无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：①规范原文（RFC 7637/2784/2890，定"必须是什么"：proto 47、TEB 0x6558、K 位 + Key、24-bit VSID）；②商业化软件实际行为（Hyper-V Network Virtualization 等实现的 VSID/FlowID 语义——旧 §3.1 记载继承；无本机抓包，标"未达验证级"）；③可靠开源实现思路（本仓库同族先例：vxlan/geneve 的"封装终结层 + 内层 Ethernet fixture 共用构造器 + 逐 datagram emit"，只借鉴思路）。三路一致点：GRE + TEB + Key 编码；不一致点 = **载体层**（vxlan/geneve 走 UDP，nvgre 走裸 IP proto 47——取舍：以 registry/落码为准，nvgre 无 UDP 层、无端口）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `nvgre` raw-IP 终结层（本版；已落码） | 自产完整包（外层 IP + GRE + inner 帧），不依赖传输层；代价 = 不能复用 gre 隧道层生成器（内层是裸 Ethernet，非 L3/L4 包） | **采用**（registry `:1688-1694` 已文档化分歧） |
| B | `[ip, gre, nvgre]` 三层（旧稿 §2） | 复用 gre 隧道层——但该生成器要求内层包链且 ProtocolType 限 0x0800/0x0806/0x86DD，**无法承载裸 Ethernet 帧** | **否决**（registry 注记实证） |
| C | `[ip, udp, nvgre]` 走 UDP 4789（与 vxlan 同族形状） | NVGRE 的载体是 IP proto 47，**不是 UDP**（RFC 7637）；套 UDP 即伪造载体 | **否决**（规范明文） |

## 11. P2 D-NVGRE-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 状态说明：实现已落码（`internal/protocol/nvgre/layer_gen.go` 397 行），本 P2 条目为 P-PIPE 文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口；P4 在本协议内为"缺口收敛"（§14），不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/encapsulation.go`（§172/§197/§287/§298） | `EncapEthernetFixture`/`EncapWireFault`/`NVGREDatagram`/`NVGREConfig` 配置类型（三封装协议共用前两者） | —（共享文件） |
| `trafficgen/internal/protocol/nvgre/layer_gen.go` | 终结层生成器 + `ValidateConfig`/`validateWireFault`/`validateFixture` + `init()` 注册 | 397 |
| `trafficgen/internal/protocol/nvgre/layer_gen_test.go` | 13 个 `Test*`（Key 字节/GRE wire/IPv4/IPv6 外层/TTL/datagram 折叠/空配置/边界/拒绝面/接口） | — |
| 接线 7 件 | registry 注册（`layers/registry.go:1695`）/ translate Meta 直传（`chain_planner_translate.go:268`）/ raw-IP Meta 补传（`chain_planner.go:1512`）/ convert flat case（`strategy_convert.go:1461`）/ protocols 准入（`protocols.go:63`）/ raw-IP 名单（`chain_planner_util.go:54`）+ 端口豁免（`chain_planner.go:770`） | — |

### 11.2 接口签名

- `ValidateConfig(cfg *core.NVGREConfig) error`（`layer_gen.go:274`）：`nil` 通过（空配置默认流）；VSID > 24-bit（含 `datagrams[]` 逐条）、inner fixture 非法、wire_fault 非法各归一分支，错误文案与 §7 锚词逐字一致。
- `Generate(ctx, req *layers.GenRequest) error`（`layer_gen.go:67`）：先 `ValidateConfig`；逐 datagram 构造 `core.PacketConfig{Direction, L3{SrcIP,DstIP,Protocol:ProtocolGRE,TTL}, L2{GRE{KeyPresent:true,Key,ProtocolType:EtherTypeTEB}}, Payload:inner}`；逐条 `req.Emit`，ctx 取消即返（`:102-105`）。
- 注册（`init()`，`:390-397`）：`RegisterLayerGenerator("nvgre", ...)` + `RegisterLayerValidator("nvgre", ...)`。
- 导出：`GREKey(vsid, flowID) uint32`（`:181`，单测锚点）。

### 11.3 数据结构

`NVGREConfig{VSID uint32, FlowID uint8, TTL *uint8, Inner *EncapEthernetFixture, Datagrams []NVGREDatagram, WireFault *EncapWireFault}`（`encapsulation.go:298-312`，全量，无新增）。
`NVGREDatagram{VSID uint32, FlowID uint8, Up *bool, Inner *EncapEthernetFixture}`（`:287-292`）。
`EncapEthernetFixture{SrcMAC, DstMAC, EtherType, VLANID uint16, VLANPriority uint8, SrcIP, DstIP, Payload []byte}`（`:172-191`，三封装共用）。
`EncapWireFault{Kind string, Value int}`（`:197-200`）。

### 11.4 主流程

配置 → validator（VSID 范围 + fixture 6 分支 + wire_fault 8 分支）→ 生成器（`foldDatagrams` 展开 → `buildInnerFrame` 组装内层帧 → `PacketConfig` 经 `req.Emit`）→ builder（外层 IP 头 + `writeGRE` 序列化 GRE）→ writer（PCAP/NIC）。

### 11.5 错误分支

`ValidateConfig` 8 类拒绝（§7 表 N-1…N-6 + 未知 fault kind + fixture 6 子分支）各传 task error（零假成功）。**`translateTerminalConfig` 层内配置翻译缺口**（G-NVGRE-1）：空 Fields 层提前返回，层内键既不被翻译也不被消费。

### 11.6 性能边界

见 §6（逐 datagram 流式 emit、per-flow 局部状态、无跨流共享、无锁；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- **`translateTerminalConfig` 无 nvgre 分支 + registry Fields 为空**（`chain_planner_translate.go:852` 的 `if len(s.Fields) == 0 { return }` 对 nvgre 直接返回）→ 层内 `nvgre` 配置**不被翻译**进 `spec.NVGRE`，生成器读 `req.Meta.NVGRE`（`layer_gen.go:71`）为 nil → 走 `defaultFixture()` 发**默认包**。属缺口 G-NVGRE-1（moxa G-MOXA-1 / someip G-SOMEIP-1 同构）。
- **`ValidateLayerConfig` 未知字段即拒**（函数起 `complete.go:279`，`unknown field` 返回在 `:293`）：nvgre Fields 为空 ⇒ 层内**任何键**今日被 `layers: layer "nvgre": unknown field "vsid"` 拒。故目标形状（§2）今日**不是静默走错，而是硬拒**（P4 前建例即红）。
- **`CheckProtoFlat` 无 nvgre 分支**（`strategy_convert.go:8625` 起 60 个 `protocol ==` 分支无 nvgre（机读 `awk NR>=8625 && NR<=9114 | grep -c` = 60）；`rawWrapChains`（`:9095`）不含 nvgre）→ 顶层 `nvgre` 子映射 presence **不判死**，属缺口 G-NVGRE-2（禁加单协议黑名单分支，等框架级 unknown-key 白名单；moxa G-MOXA-2 / kingbase 裁定）。
- 动态 allowlist（`layer_dyn.go:17-21`）：`nvgre` 零命中实测 → 业务字段动态对象即拒；四元组 `ip` 全开（`src`/`dst`/`ttl`）；`nvgre` 无传输层故无 `tcp`/`udp` 端口动态面。见 §12.12。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert `internal/protocol/nvgre/` 2 文件 + 接线 6 处（registry/translate/chain_planner/convert/protocols/util）；不触及其他协议。cases 回滚 = 恢复 20 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 20/20 顶层 = `src_ip/dst_ip/count` + 顶层 `nvgre`（**56 处残留**，机读实测，**非负例口径**）；**本版 cases 保持原样**——层为空壳（`registry.go:1695` 无 Fields + `translate :852` 提前返回 + 无 `case "nvgre"`），迁移**全部落在代码阶段**（G-NVGRE-1）；presence 判死缺口 G-NVGRE-2 | §12.1；`cases/nvgre.json` 机读实测（56 处残留，非负例口径） |
| §2 策略/任务 | 策略 = 单 nvgre 流量模板，自带 `flow_control`；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表（无连接，单 flow 承载全部 datagram）/事务序列/关联（无派生流诚实声明）/插入位置（终结层）/时间线 | §12.3 + §5 |
| §4 查规范 | RFC 7637/2784/2890 + 旧基线 + tshark `gre.*` 通道实测（`nvgre.*` 零 dissector）+ 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["ip"]` 单值（`registry.go:1695`）；8 类拒绝分支；失败传 task error | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待 P4 基准，不写承诺） | §6 |
| §7 三份文档 | `97-nvgre-{design,testcase}.md` v1.0.0（草稿层）+ D-NVGRE-1（§11，门1 获批 = 定稿）+ T-NVGRE（testcase §2，20 ID）+ 旧稿 55-* 为历史层 | 修订记录 |
| §8 设计先行 | P1–P3 先于 P4 缺口收敛；门1 获批 = D-NVGRE-1 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = RFC 7637/2784/2890（§10）+ D-NVGRE-1（§11）+ tshark `gre.*`/frames 通道实测（替代"已确认现网行为"档，未到抓包级，不冒充第三源）；20 ID 逐项回指；存量 20 例审计去向 testcase §8 | `97-nvgre-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审 + 收官隔离复审；红先绿后 | 车道报告 §2 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：`ip.src/dst/ttl` 开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `nvgre` 已在 `registry.go:1695` 注册（**不新增层**）；`allowedProtocols["nvgre"]=true`（`protocols.go:63`）；Meta 已直传；**P4 补 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `gre.*`/`eth.*`/`ip.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/nvgre/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-28；本版 cases 保持原样未改）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 纯净 |
|---|---|---|---|---|
| `cases/nvgre.json` | 20（14 正 + 6 负） | 非负例 14 例 × `{src_ip, dst_ip, count, nvgre}`（**56 处顶层旧键残留**：四键各 14）；负例 6 例同形（另 24 处） | **无 `layers` 键 ×20**（纯扁平；链来自已注册 `ChainPlanner` 的 `completedChainUncached`/`completeSynthesized`，`chain_planner_chain.go:59-107`——**非** `BuildLayersPlanner`，后者要求 `layers` 键 `validate_layers.go:23`） | ✅ 6/6 只有 `{expect_error,error_contains}` |

**残留计数口径对账（2026-09-28 机读复算，2026-09-28 定案）**：

本协议统一采用**非负例口径**（= 合规判据口径，与 ldp/rip/pcep/a2a 各车道一致）：**56 处** = 14 个非负例 × 4 键（`src_ip`/`dst_ip`/`count`/`nvgre`，各 14）。另两种口径对照：

| 口径 | 算法 | nvgre | vxlan | geneve |
|---|---|---:|---:|---:|
| **非负例口径（采用）** | 14 正例 × 本协议顶层业务键（nvgre 4 键 `src_ip`/`dst_ip`/`count`/`nvgre`；vxlan·geneve 5 键 `src_ip`/`dst_ip`/`src_port`/`dst_port`/<proto>） | **56** | 70 | 70 |
| 全例口径 | 20 例 × 同上业务键（含负例） | 80 | 100 | 100 |
| 门脚本口径 | 全例 × 8 键表（`src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/`src_mac`/`dst_mac`/`ttl`，**不含协议子映射**） | 60 | 80 | 80 |

**键数差异的根因**：nvgre 是 raw-IP 无端口 → 业务键 4 个（`src_ip`/`dst_ip`/`count`/`nvgre`）；vxlan/geneve 是 UDP 载体、端口住顶层 → 业务键 5 个（`src_ip`/`dst_ip`/`src_port`/`dst_port`/`<proto>`，无 `count`）。故非负例口径 nvgre = 14×4 = **56**，vxlan/geneve = 14×5 = **70**。

**本文档一律写 56（非负例口径，仅指 nvgre 自身）**。三种口径**指向同一事实**：nvgre 20/20 为**纯扁平形**（`layers` 键 0）、**今日全量失效（0 pass）**、cases 本版未改、合规化属代码阶段。门脚本口径（nvgre 60）可复现：`bash trafficgen/tools/pipe_gate.sh nvgre` 逐条列出。

**全部数字由脚本生成**（非手算）：`git show cf6e2f0:<proto>.json` → 非负例集合 × 业务键（排除白名单）逐键计数。

**存量今日实跑状态（本车道自跑，2026-09-28）**：
```
CASE_PROTO=nvgre go test ./test/protocol_pcap/ -run TestProtocolPcapDrive -count=1
RESULT: 0 pass, 6 fail, 14 error (of 20)
  nvgre    0/20
```
- 14 正例 = `error`：submit 被 `CheckProtoFlat` 拒（`protocol nvgre no longer accepts flat config field src_ip`，`strategy_convert.go:8625-8637`）。
- 6 负例 = `fail`：被拒但错误文本**不含** `flags`/`vsid`/`inner`/`family`/`length`/`isolation`——**锚词全部失守**（harness 报 `rejected but error "..." does not contain "flags"` 等 6 条）。
⇒ 存量**不是「仍可跑的过渡态」，而是全量失效（0 pass）**；「本版不动 cases」有两条理由——**改了硬红**（层链形被 `unknown field` 拒）+ **不改也全红**（扁平形被 `CheckProtoFlat` 拒）。

目标形状样例见 §2（**今天跑不通**，CORE_MEMORY §1.9 口径）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"nvgre":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 nvgre 分支，`grep` 零命中实测）→ **P4 先补分支再建例**（不补就建会真绿 = 假通过）→ 缺口 G-NVGRE-2 登记。② 白名单外游离键判死（`unknown field`）P4 建一条（A′）。③ 6 负例每条带锚词（已齐，§7）——**但今日锚词全部失守**（见 §12.1 实跑 RESULT：6 负例 `fail`，非正确红）。④ 收官自查「非负例顶层键 = 0」——**待代码阶段**（存量 20/20 顶层有旧键，迁移与改写同步落地后执行）。⑤ **存量 20/20 今日全红**（0 pass），非「仍可跑的过渡态」。

### 12.3 §3 强制展开：五件套

会话表：`s1` 单 flow 基线（#1–#6、#9、#10、#12–#14，各一 datagram；无连接故无"会话"语义，单 flow 即全部）。事务：`t1` 发 datagram（`req.Emit` 一条完整包）；`t2` 结束（事件流关闭，**无挥手报文**）；每事务四件事（前置/触发/成功/失败）见 §5 + §4 场景表。关联关系：**无派生流**（诚实声明：NVGRE 是无连接封装，无控制流/数据流主从关系，无 `driven_by`；CancelRequest 类关联不适用）。插入位置：终结层（`[ip,nvgre]`，无中间层）。时间线：datagram 内严格顺序（`datagrams[]` 顺序即 emit 顺序）/ 单 flow 内顺序 / 跨 flow 由 worker 调度不假设全局包序（用例用 distinct 聚合断言，不用逐包定位）。方向：`up`/`down` 由 `layer_gen.go:81-84` 置 direction 字符串，**L3 地址交换在 raw-IP 分支 Emit 闭包 `chain_planner.go:1546-1547`**。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src`/`ip.dst`/`ip.ttl` 三键开（allowlist `layer_dyn.go:18` 实测 `"ip": {"src":true,"dst":true,"ttl":true}`）；**`nvgre` 无传输层故无端口动态面**（`tcp`/`udp` 端口键在本协议链上不存在）。

**业务字段 6 项全关**（allowlist 无 `nvgre` 行，`grep` 零命中实测；对象即拒）：`vsid`（租户身份）/ `flow_id`（流身份）/ `inner`（帧 fixture）/ `datagrams[]`（结构选择器）/ `ttl`（外层 TTL，**住 nvgre 层**——生成器读 `cfg.TTL` 而非 `spec.TTL`，见 §11.2 `outerTTL`）/ `wire_fault`（负例注入口）——逐流变体需求列 A′ 候选（testcase §6.2）。

**TTL 归属裁定**：`NVGREConfig.TTL *uint8`（`encapsulation.go:305`）是 nvgre 层键；raw-IP 分支虽补传 `meta.TTL = spec.TTL`（`chain_planner.go:1510`），但生成器 `outerTTL(cfg)`（`layer_gen.go:169`）**只读 cfg.TTL**——故 `layers[ip].ttl` 对本协议外层 TTL 是**死配置**，外层 TTL 唯一住处 = `layers[nvgre].ttl`（P4 补 Fields 必须含 `ttl`）。

序号算法实读：`parseLayerDyn`（`layer_dyn.go:78`）/ `TupleGenerator.Next` / 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go:17`）——**`nvgre` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。

## 13. P3 对接清单（T-NVGRE 草稿输入；正文落 testcase 文件）

20 ID（14 正 + 6 负）+ packet_count（1/1/1/1/1/1/3/3/1/1/2/1/1/1）+ 锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。A′ 候选 **10 例**：`nvgre_down_direction`（B1 T3）/ `nvgre_datagram_inner_fallback`（B4 T1）/ `nvgre_neg_key_missing`（fault）/ `nvgre_neg_key_endian`（fault）/ `nvgre_neg_protocol_not_teb`（fault）/ `nvgre_neg_carrier_protocol`（fault）/ `nvgre_vlan_v6`（变体 13）/ `nvgre_neg_payload_overflow`（变体 16）/ `nvgre_vlan_boundaries`（变体 20–22）/ `nvgre_neg_stray_top_key`（白名单游离键）。

**注（变体 7，FlowID 越界）**：`FlowID` 是 `uint8`（`encapsulation.go:302`），JSON 侧 >255 由解码层拒绝，非 nvgre validator 分支；登记为类型层天然边界，不单独立例（避免与解码错误混淆锚词）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-NVGRE-1（**阻塞级**） | registry `nvgre` Fields 为空（`registry.go:1695`）+ `translateTerminalConfig` 无 nvgre 分支（空 Fields 提前返回 `:852`）→ 层内配置**根本不被解码**；且 `ValidateLayerConfig` 未知字段即拒（函数起 `complete.go:279`，返回在 `:293`）→ 目标形状今日硬红 | **代码阶段首动作**：补 registry Fields（vsid/flow_id/ttl/inner/datagrams/wire_fault）+ translate `case "nvgre"`（`completedConfig` + `DisallowUnknownFields`，moxa `:3304` 范式）+ schemagen 重跑 → 20 例改写（顶层旧键 56→0，非负例口径）+ 先跑后钉；**本版不动 cases** |
| G-NVGRE-2 | `CheckProtoFlat` 无 nvgre 分支（`:8625-9114` 内 60 个 `protocol ==` 无 nvgre，机读实测；`rawWrapChains`（`:9095`）不含 nvgre）→ presence 形今日不判死 | P4 先补分支再建例；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单；kingbase 记忆裁定） |
| G-NVGRE-3 | 业务字段动态全关（allowlist 无 `nvgre` 行，`layer_dyn.go:17`） | A′ 候选，不冒充已覆盖（§9.36 口径） |
| G-NVGRE-4 | 4 种 wire_fault kind 无用例（`protocol_not_teb`/`key_missing`/`key_endian`/`carrier_protocol`） | A′ 补例（validator 分支已落码，逐 kind 一例） |
| G-NVGRE-5 | 方向变体（`datagrams[].up=false`）与 entry inner 回退无例（direction 分支 `layer_gen.go:81-84`；地址交换 `chain_planner.go:1546-1547`；inner 回退 `layer_gen.go:136-139`） | A′ 补例 |
| G-NVGRE-6 | 外层 IPv6 + 内层 `vlan_ipv6` 组合、VLAN 边界（VID 4095/PCP 7/VID=0）、payload 上界拒绝无例 | A′ 补例（validator 分支已落码） |
| G-NVGRE-7 | 旧稿 §9 #12"IP 分片/重组"未实现（生成器发完整单帧） | **明确不解决** + 迁入计划：分片面按长度上界拒绝表达（§8）；若实现则补驱动/用例 |
| G-NVGRE-8 | 出厂/现网 VSID-FlowID 分配实践无抓包实证（③ 源未达验证级） | 待确认：抓现网 NVGRE 包或查 Hyper-V NVGRE 文档；确认前不写死进实现 |

## 15. 修订记录

- v1.0.0（2026-09-28）：P-PIPE #97 文档轨 P1–P3。RESUME 续写：55→97 沿革与 8 项过期校正（§0，含层链形状 `[ip,gre,nvgre]`→`[ip,nvgre]` 与 typedef 作废两项硬校正）；存量 20 例机读审计（顶层残留 56 处，非负例口径、无 `layers` 键、expect 形状、ID 顺序一致）；§12.1/12.3/12.12 强制展开 + 12-P2；D-NVGRE-1 as-built 定稿（§11）；缺口 G-NVGRE-1…G-NVGRE-8。P1 自审 2 轮 / P2 自审 2 轮 / P3 自审 2 轮，末轮干净（结论见 `/tmp/pipe/doc-lanes/nvgre.md` §2）。
- v1.0.1（2026-09-28，隔离审查修轮）：审查报告 `/tmp/pipe/doc-reviews/nvgre.md`（有条件通过，2×P0 + 2×P1 + 5×P2）。修：**P0-1** 改口「假绿风险已排除」为「负例锚词全部失守」（实跑 `RESULT: 0 pass, 6 fail, 14 error`，拒因 `CheckProtoFlat`）；**P0-2**「扁平过渡态」→「存量今日全量失效（0 pass）」，补「不改也全红」第二条理由；**P1-①** vxlan/geneve 形状标签改「layers + 顶层残留并存形」（`layers` 20/20）vs nvgre「纯扁平形」（0/20）；**P1-②** 27B（原 28B）、1×11（原 1×12）；**P2-1** `complete.go` 引用补 `:293` 返回行；**P2-2** 扁平链来源改 `ChainPlanner.completedChainUncached`/`completeSynthesized`（非 `BuildLayersPlanner`）；**P2-3** 接线 7 件（原 6）；**P2-4** down 地址交换改指 `chain_planner.go:1546-1547`；**P2-5** `notes` 住 `expect` 内。自审 1 轮，末轮干净。

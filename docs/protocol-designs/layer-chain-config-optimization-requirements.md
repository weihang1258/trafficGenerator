# 配置层级链架构优化调整 · 需求文档（v1）

> 版本：**v1.1**（2026-08-27，P3 开工前修订）：按全量套件实证校准失败清单与根因（§2.3 D / §4）、新增机制决策点 F5–F8（§7，待确认）、验收标准增补第 9 条（§6）。
> 版本历史：v1.0（2026-08-25，基于多轮沟通确认）
> 承接：`18-layer-config-design.md`（方案 C 分层配置架构，v1.5.0）
> 目标：把当前"层链骨架 + 顶层平铺地址/端口 + 协议 flat 键直传"的**混合态**，收敛为"**每协议层自带默认配置模板**"的严格分层模型，并消除重复造轮子、统一非独立协议的层规划。
> 范围：**所有协议遵循的统一整体调整**（协议全集见 §2.3，不分批）。本次只收敛**已实现**部分；试点批次只是执行顺序。可并行则并行。

---

## 1. 核心模型（确认版）

### 1.1 层默认配置模板（每层 = 一张 schema）

每协议层的 template 含**三块**：

| 块 | 含义 | 例子 |
|---|---|---|
| **① 字段与默认值**（Fields） | 该层字段的类型 + 默认值 + [范围] | `flags: uint8, default 5` |
| **② 依赖声明**（deps） | `depends_on`（缺了自动补，硬依赖）+ `transport_on`（可替换传输层，第一个=默认）+ `optional_on`（选了才生效）+ `inner_required`（隧道内层起点） | `http: fields{method=GET...}, depends_on=[tcp], optional_on=[tls]` |
| **③ 默认行为模板**（default behavior） | 写空层 `{proto:{}}` 时，该层要产出**可用的默认流量**（默认连接 + 默认事件/会话序列），不是"不报错"，而是**有意义**的默认帧 | `{http_flv:{}}` → flags=5, tags=[onMetaData+AAC+AVC], rounds=1 的默认 FLV 体 |

### 1.2 依赖两维（关键修正）

依赖分**两维**，缺一不可：

| 维 | 表达 | 解决什么 |
|---|---|---|
| **维度一：层存在依赖**（`depends_on`） | "该层需要某层在它外层存在" | 只解决"层在不在" → **链补全** |
| **维度二：层字段值依赖**（`FieldContract`） | "该层的引入决定某层里**某个字段**的值" | 解决"字段值从哪来" → **跨层字段传播** |

> 现状缺维度二：tcp 的 `dst_port` 默认 0 = "由上层决定"，但**上层是谁、填 80 还是 443**，tcp 模板自身无法知道 —— 这必须由骑在它上面的终结/隧道层（通过 FieldContract）声明。

### 1.3 FieldContract（跨层字段契约）

```
FieldContract: { "<直接承载我的层>.<字段>": <常量值> }
```

- **目标层 = 紧邻外层的邻居层**（即"直接承载我"的那层），**不是最外层**。
- **值 = 常量**（含按 profile / 传输层取不同常量），**本期不做动态字段引用**（指向其他层字段、解析顺序、循环依赖复杂度高收益低）。

**例子（FieldContract）**：
```
http   模板 → 其直接承载层 tcp 写 dst_port=80
tls    模板 → 其直接承载层 tcp 写 dst_port=443
dns    模板 → 其直接承载层 udp/tcp 写 dst_port=53
modbus 模板 → 其直接承载层 tcp 写 dst_port=502
amqp   模板 → 其直接承载层 tcp 写 dst_port=5672
stun   模板 → 其直接承载层 udp 写 dst_port=3478（transport_on=tcp/tls 时 → 5349）
gre    模板 → 其直接承载层 ip 写 protocol=GRE(0x2F)
mcp    模板 → 按 profile 选**直接承载层**：stdio→tcp（逐行 JSON），http/streamable→http 层（http 再 FieldContract 给 tcp 8081）。a2a 纯 HTTP→http 层。
```

> ✅ **变体改父层契约值 · 已定案 (a)**：变体**不当独立层**，作载体层的 **dialect/profile**（kingbase = postgresql 层的 dialect 变体，据 dialect 选端口 54321），**不覆盖父层契约值**。见 §7 F4。

### 1.4 "骑"的关系（方向约定）

- 数组 `[ip, tcp, tls, http]` = **从最外层到最内层**（首层最外层、末层最内层/应用层）。
- 一层**"骑在"直接承载它的那层**上 = 它的**紧邻外层**。
- 生成字节从最内层往外；线上顺序 = `[IP头][TCP头][TLS头][HTTP体]`。

**例：https**
```
[ ip ← tcp ← tls ← http ]
   (内-内→最外)    http 骑 tls → 写 tls 字段（SNI/ALPN）
                    tls  骑 tcp → 写 tcp.dst_port=443
```
- **http 骑在 tls 上**；**tls 骑在 tcp 上**。
- **误区（§12.2）**：`[http, tls]`（http 在外）是错的 —— http 包 tls，末层 tls 是隧道层不能当末层 → 校验拒。正确 `[ip, tcp, tls, http]`。
- **一层双重身份**：某层**独立时是终结层**（如 `[ip,tcp,http]` 末层 http）；**被别的层骑时是中间载体层**（如 `[ip,tcp,http,http_flv]` 的 http 是中间层）。骑它的层会写入/替换该层字段，该层再往下 FieldContract 传播。http / tls 是典型"可终可载"层。**变体**（如 kingbase）**不当层**，而是载体层的 dialect/profile（§7 F4）。

### 1.5 解析流水线（四步）

```
① 链补全（维度一 DependsOn）  ：按 depends_on 插入缺失层，迭代到稳定
② 字段契约传播（维度二）      ：链定后，按 FieldContract 把常量写进"直接承载层"
③ 自身字段默认               ：每层字段，用户显式 > 模板默认
④ validate                   ：终结层唯一、传输层不在末层、隧道层不当末层、字段范围、protocol 与最外层一致
```

### 1.6 字段解析优先级（三级）

```
字段 f 的值 =
  ① 用户显式写 f               → 用户值（含显式 0；"显式 0 ≠ 缺失"）
  ② 直接承载层的 FieldContract → 契约常量值（如 http→80）
  ③ 该层模板自身 fields 默认   → 模板默认（如 tcp 模板 dst_port 默认 0）
```

> ② 依赖①：用户显式写 `tcp.dst_port` 时，②不覆盖①；①没写时才由②决定（http 骑上来填 80）。

> **优先级 vs 领域校验（维度不同，别混）**：上面三级决定的是**合法值域内的默认值**（dialect 决定取 5432 还是 54321）。用户显式覆盖默认只限合法值域内；**超出合法值域仍由 validator 拒绝**——如 `dialect=kingbase` 时端口必须 54321，用户显式写 `tcp.dst_port=54322` → 校验拒绝（报错含 "54321"），而非按"用户显式"生效。即：字段优先级定"默认填啥"，领域校验定"能不能是这个值"。

---

## 2. 协议分类（归属原则）

### 2.1 独立协议（有 RFC/标准，各管各的 wire 帧）

路由/网络（RIP/OSPF/ISIS/BGP/LDP/PCEP/IGMP/PIM/cflow/IP/TCP/UDP/SCTP/VXLAN/GENEVE/…）、安全（TLS/DTLS/Kerberos/NTLM/SPNEGO/OCSP/IKE）、文件（TFTP/SMB/NFS/FTP）、数据库（TDS/PostgreSQL/MySQL/DRDA/MongoDB/CQL）、工控（DNP3/ENIP/Modbus/CoAP/S7/IEC104/GOOSE/SV/MMS/OPC UA/BACnet）、消息（MQTT/AMQP）、音视频（RTMP/RTSP/SIP/H.323/STUN）、车联网（GBT32960/JT808/JT809/JTT905）、其他（SNMP/NTP/syslog/DHCP/DNS/SSH/LDAP/Radius/…）、健康（HL7/NMEA）。

### 2.2 非独立协议（无 RFC，是某协议的业务使用方式）→ 复用父层

统一原则：**这些"协议" = 某个父协议层 + 一个内容/profile 变体**，应复用父层，不各自造轮子。

| 族 | 协议 | 本质 | 复用父层 |
|---|---|---|---|
| **HTTP 内容载体** | http_flv、hls、hds、doh、onvif、cwmp、mmse、mcp、a2a | HTTP + 内容格式 | `http` 层（TransformEvents） |
| **数据库兼容** | kingbase（→PostgreSQL wire）、dameng（→Oracle/DB2 类） | 兼容某父库 wire | postgresql **已存在**（legacy flat，1/1，默认端口 5432 / RFC 765）且 kingbase 的 builder 就是完整 PG v3 wire（端口 54321）→ **提为共享 wire 层**，kingbase 作其 **dialect 变体**（见 §7 F4）。⚠️ dameng 非 PG 系（Oracle/DB2 类），暂无父库可复，**保持独立层**。**【已确认选①】** |
| **挖矿/区块链** | stratum、getwork、gbt、ethmining、xmrmining | JSON-RPC over HTTP/TCP | JSON-RPC 件 + http/tcp |
| **RTMP 变体** | rtmfp | RTMP over UDP | RTMP 层 + udp 载体 |
| **厂商隧道** | moxa | 串口服务器透传（TCP 封装） | tcp 载体 + 内容变体 |

> 注：hls 有 RFC 8216 但其本质仍是 HTTP 承载媒体容器；doh 有 RFC 8484 但其本质是 HTTP 承载 DNS。两者按"HTTP 内容载体"归位（复用 http 层），但保留各自字段模板。

### 2.3 协议全集清单（本次为**统一整体调整**，所有协议遵循；三类改动：设计文档 / 代码 / 用例）

> 本清单是**全集**，不分批次。**试点批次只是执行顺序**，全集始终可见、不遗漏。每个协议都要三改：**① 设计文档**（定义该层模板/归类/复用关系）、**② 代码**（registry/schema/planner/generator 实现模板与 FieldContract）、**③ 用例**（改写成严格分层写法）。

**图例**：现状列 `层链/遗留/未注册` + `模板Y/N/无层` + `跑通 x/y`；改动列 `设计/代码/用例`。

**共用零件（shared components / 复用目标）**：凡是"无 RFC、是某协议业务使用方式"的协议，都**骑**在下面这批共用件上，不各自造轮子：
1. **PostgreSQL v3 wire 层**（`postgresql`，现 legacy flat，待提为共享层，端口 5432）— kingbase 作 **dialect 变体**（dialect=kingbase，端口 54321）复用。
2. **http 层**（TransformEvents）— http_flv/hls/hds/a2a/mcp 复用。
3. **JSON-RPC 2.0 公共件** — mcp/a2a（内容）、挖矿族（stratum/getwork/gbt/ethmining/xmrmining）共用。
4. **RTMP/udp 载体** — rtmfp 复用。
5. **tcp 载体 + 内容变体** — moxa 复用。

#### A. 载体/骨架层（套娃外壳，需补 FieldContract + 模板）

| 层 | 类 | 现状 | 需改（设计/代码/用例） |
|---|---|---|---|
| ip | 网络层 | 层链, 模板Y | 设计/代码：补 FieldContract（gre→ip.protocol=GRE） |
| eth | 二层层 | 层链, 模板Y | 设计/代码：跨层 MAC 契约 |
| vlan | 二层层 | 层链, 模板Y | 设计/代码：QinQ 双层契约 |
| tcp | 传输层 | 层链, 模板Y | 设计/代码：**接收上层 FieldContract 写 dst_port** |
| udp | 传输层 | 层链, 模板Y | 设计/代码：同上 |
| mpls | 二层层 | 层链, 模板N | 设计/代码/用例：补模板 |
| pppoe | 二层层 | 层链, 模板N | 设计/代码/用例：补模板 |
| tls | 隧道层 | 层链, 模板Y | 设计/代码：FieldContract→tcp.dst_port=443 |
| gre | 隧道层 | 层链, 模板Y | 设计/代码：FieldContract→外层ip.protocol |

#### B. 独立应用协议（各管各 wire，复用传输层）

| 协议 | 现状 | 需改 |
|---|---|---|
| amqp | 层链,模板N,20/20 | 设计/代码：Fields+默认行为+FieldContract(→tcp 5672)；用例：分层 |
| modbus | 层链,模板N,213/213 | 同（→tcp 502） |
| mqtt | 层链,模板N,168/168 | 同（→tcp 1883） |
| stun | 层链,模板N,24/24 | 同（→udp 3478/tls 5349） |
| dns | 层链,模板Y,1/1 | 同（→udp/tcp 53，already） |
| dnp3 | 层链,模板N,70/70 | 设计/代码/用例：补模板 |
| doip | 层链,模板N,115/115 | 同 |
| enip | 层链,模板N,135/135 | 同 |
| gbt32960 | 层链,模板N,105/105 | 同 |
| nfs | 层链,模板N,201/201 | 同 |
| smb | 层链,模板N,280/280 | 同 |
| tds | 层链,模板N,131/131 | 同 |
| tftp | 层链,模板N,226/226 | 同（→udp 69） |
| rip | 层链,模板N,71/71 | 同（→udp 520） |
| srv6 | 层链,模板N,68/68 | 同 |
| moxa | 层链,模板N,13/13 | 厂商隧道，复用 tcp 载体 + 内容变体 |
| many 遗留 flat… | 遗留,无层 | 设计/代码/用例：迁为层 + 补模板（长尾） |

#### C. 非独立协议（复用父层，本次重点）

| 协议 | 类 | 复用 | 现状 | 需改 |
|---|---|---|---|---|
| http_flv | HTTP 载体 | http 层 | 层链,模板Y,15/15 | 设计/用例：规整入模板 + FieldContract(→http→80) |
| hls | HTTP 载体 | http 层 | 层链,模板Y,24/24 | 同 |
| hds | HTTP 载体 | http 层 | 层链,模板Y,17/17 | 同 |
| a2a | HTTP 载体 | http 层 | 层链,模板N,185/185 | **代码：改骑 [tcp,http,a2a] 删自造 HTTP/JSON-RPC**；设计/用例 |
| mcp | HTTP 载体 | http 层(按 profile) | 层链,模板N,79/79 | **代码：stdio→tcp / http→http 层，删 http_builder** |
| kingbase | DB 兼容变体 | **(a) 变体=profile**：kingbase 不当独立层，作 postgresql 层的 **dialect 变体**（dialect=kingbase） | 层链,模板N,11/15 | 设计/代码/用例：提 postgresql 为共享层 + 加 `dialect` 字段（据 dialect 选端口 54321）；kingbase 用例改 `[ip,tcp,postgresql]` + dialect=kingbase |
| dameng | DB 兼容 | 非 PG 系，暂独立层 | 层链,模板N,5/14 | 保持独立层（无 oracle/db2 父库待建） |
| rtmfp | RTMP 变体 | RTMP+udp | 层链,模板N,24/24 | 设计/代码：RTMP=内容 + udp=载体 |
| mining(stratum/getwork/gbt/ethmining/xmrmining) | 挖矿族 | JSON-RPC+http/tcp | 未注册(unimplemented) | 设计/代码/用例：共用 JSON-RPC 件 |

#### D. 待归位 / 未注册（本次**不含**，单列 P3）

> **v1.1 校准（2026-08-27）**：失败签名与根因按全量套件实证修正（基线快照：116 协议 / 2666 用例 / 2340 绿，24 协议未绿共 **326 例** = fail 116 + error 210）。
> 另记备查：v1.0 之后**计划外**补注册了约 20 个"已实现但未注册"的尾部协议（l2tp/wireguard/gtp/mysql/imap/pop3/smtp/redis/ike/ike_nat_t/grpc/ssh/rdp/openvpn/vmess/shadowsocks 等），现已全绿、不在本表。

| 协议 | 用例 | 现状 | 失败签名 | 实测根因 |
|---|---|---|---|---|
| igmp/ospf/isis/pim | 25/20/25/24 | **零 Go 实现**（仅设计文档+用例 JSON） | `unknown layer "X"` | `internal/protocol/{igmp,ospf,isis,pim}` 包不存在；registry 无 schema |
| dhcpv6 | 1 | 层已注册但 planner 未接线 | `unknown protocol: dhcpv6` | main.go 注释声明切链式（波5e），但 `RegisterPlanner(NewChainPlanner("dhcpv6"))` 注册行缺失 |
| ldp/pcep | 25+24 | ChainPlanner 已注册(main.go)，准入缺 | `invalid or missing protocol` | REST 白名单缺 + convert.go 双白名单缺 |
| goose/sv | 12+12 | legacy planner 已注册(main.go:454/455) | `invalid or missing protocol` | 仅 REST 白名单缺（convert.go 已有 goose/sv） |
| fins | 14 | legacy planner 已注册(main.go:504) | `invalid or missing protocol` | REST 与 convert.go 双缺 |

> **D 类 = 真正未归位**（层未注册 / planner 未接入），本次**不含**（单列 P3）。凡已注册 planner 的协议（哪怕半集成报错 / 半通）= **已实现、纳入本次**，见下。

**已实现但半集成 / 半通（纳入本次，但要修）**：

| 协议 | 用例 → 通过 | 失败签名 | 实测根因 |
|---|---|---|---|
| s7/bgp/coap/iec104 | 14→5 ·19→2 ·16→0 ·16→0 | task 层 `invalid protocol` | **convert.go worker 白名单缺**（REST/main.go 均已有）；接线后剩余错误再按实现 bug 排 |
| opcua/mms | 12→0 ·11→0 | `config required` 族 | **用例形状笔误为主嫌**：case `spec_json` 为数组而非对象，MCP `mapString` 对非 map 返回 nil → Config required 拒绝 |
| drda/thrift | 10→1 ·13→1 | `config required` 族 | 真实配置翻译缺陷（Go 包完整存在），逐字段核对翻译路径 |
| mongodb/someip/tns/cql | 13→12 ·16→7 ·12→5 ·17→1 | src_port 去重/包数/字段名 bug | 实现 bug，逐例排错（mongodb 仅差 1 例） |
| dameng | 14→6 | 半通（§2.3 C 试点遗留） | 保持独立层策略不变（F4），仅修生成/校验差异；kingbase 已随 postgresql dialect 全绿(16/16)，不再列 |
| tls | 1→0 | 握手基本用例失败 | 回归单例，先复跑定位再修 |

> **失败性质分布（P3 执行依据）**：326 个未通过中，**集成一致性类 ≈71%**（232 例：白名单漂移/planner 接线/配置翻译/用例形状——同一准入事实在 REST×2、worker×2、main.go、registry 多处各存一份导致漂移）、**协议从零实现类 ≈29%**（94 例：igmp/ospf/isis/pim）。故 P3 执行次序 = **先接线**（成本最低，立即转绿 5~6 协议并让真 bug 显形）→ 修翻译/形状 → 逐例排错 → 按宿主模式样板从零实现四路由协议（§7 F6）。

---

## 3. 当前实现缺口（要修的）

> **v1.1 状态注（2026-08-27）**：本节为 v1.0 时点的缺口快照。其中 §3.2 的"15 层有 Fields"统计与 §3.4 的"无 FieldContract 字段"已被 P0b/P1a **部分闭环**（FieldContract/dialect 已落地、大量壳层已有默认流）；§3.4 所述 `translateTerminalConfig` 手写逐例的尾巴仍在。以下保留原文备查，**勿当作现状断言**。

### 3.1 混合态：地址/端口仍顶层平铺

- 用例中 `src_ip`/`dst_ip` 各用 **999** 次、`dst_port` **534** 次，全在**顶层平铺**，不在层内。
- `layers` 数组各协议层是**空壳**（`{modbus:{}}`），配置经同名顶层 flat 键（`"modbus":{...}`）直传生成器。
- `applySpecToChain`（chain_planner.go:1542/1547）读 `spec.SrcIP/DstIP`（顶层）注入 ip 层 —— **层内 `ip.src/dst` 不权威**。
- 违背设计 G1"不再有独立顶层字段，src_ip/dst_port 必须写进层里"。

### 3.2 大多数层无字段默认模板（45/60 空壳）

| 统计 | 层 |
|---|---|
| 有 Fields（15） | ip、eth、vlan、tcp、udp、http、dns、http_flv、hls、hds、opcua、ftp、smtp、tls、gre |
| **空壳无 Fields（45）** | s7、ntp、snmp、syslog、mdns、dhcp、dhcpv6、ssdp、rip、tftp、enip、a2a、dnp3、doip、gbt32960、mcp、modbus、mqtt、coap、stun、rtmfp、amqp、mms、moxa、someip、drda、thrift、tns、mongodb、dameng、kingbase、cql、iec104、goose、sv、bgp、ldp、pcep、cflow、fins、nfs、smb、tds、mpls、pppoe |

### 3.3 大多数层无默认行为模板（空配置报错而非产出默认流）

- 例：`{amqp:{}}` 报 "connections is required"；`{modbus:{}}` 报 "transactions required"。
- 只有 http_flv / hls / hds 有默认体（FLV/m3u8 默认内容）。

### 3.4 无 FieldContract 表达（跨层字段值依赖缺失）

- `LayerSchema` 现只有 `Category / DependsOn / TransportOn / OptionalOn / InnerRequired / Fields / Constraints`，**无 FieldContract 字段**。
- 默认端口等跨层字段值靠 `chain_planner.go` 的 `translateTerminalConfig` **逐个 case 手写**（stun→3478、rtmfp→1935、ldp→646、pcep→4189、cflow→2055/4739、mcp→22/8081…），无统一机制。

### 3.5 重复造轮子

| 项 | 现状 | 目标 |
|---|---|---|
| **HTTP 族不一致** | http_flv/hls/hds 骑 http ✅；**a2a/mcp 骑 tcp 自造 HTTP**（`http_builder.go`）❌ | a2a/mcp 改骑 http，删 `http_builder.go` |
| **JSON-RPC 帧重复** | mcp/a2a 各自造 JSON-RPC 2.0 帧 | 抽公共 JSON-RPC 件 |
| **兼容 DB 独立层** | kingbase/dameng 独立层 | kingbase 作 postgresql 的 dialect 变体（§7 F4）；dameng 暂独立 |
| **挖矿族未来重复** | stratum/getwork/gbt/ethmining/xmrmining 将各自造 JSON-RPC/HTTP | 实现时共用 JSON-RPC 件 |

---

## 4. 尚未归位/层链未跑通的协议（定论见 §2.3 D）

> §2.3 D v1.1 已给出定论与实测根因；本表为速查版。

**全量套件基线（2026-08-26 快照）**：116 协议 / 2666 用例 / **2340 绿（87.8%）** / **24 协议未绿，失败 326 例**。

| 桶 | 协议 | 失败签名 → 实测根因 |
|---|---|---|
| 🅐 从零实现（94 例） | igmp、ospf、isis、pim | `unknown layer "X"` —— 无 Go 包 / 无 registry schema |
| 🅑 接线缺失（88 例，接线即通） | dhcpv6、ldp、pcep、goose、sv、fins | `unknown protocol` / `invalid or missing protocol` —— 注册行缺失或白名单缺项 |
| 🅒 翻译/形状（44 例） | opcua、mms、drda、thrift | `config required` 族 —— opcua/mms 为 spec_json 形状笔误主嫌；drda/thrift 为真实翻译缺陷 |
| 🅓 半集成实现 bug（99 例） | coap、iec104、bgp、s7、cql、tns、someip、dameng、mongodb | convert 白名单缺（前四者）/ 包数·字段·去重实现 bug |
| 🅔 回归单例（1 例） | tls | 握手基本用例失败，复跑定位 |

> 桶和：94 + 88 + 44 + 99 + 1 = 326。
> v1.0 曾判断"补齐模板通常会顺带让半集成报错类跑通"。**实证修正**：模板缺失不是半集成类的主因；约 71% 失败源自"同一准入事实在 REST×2 / worker×2 / main.go / registry 多处各存一份"的漂移与实现细节 bug。因此 P3 第一刀是**准入一致性接线 + 哨兵锁定**（§7 F5），其次翻译/形状（§7 F7），再逐例排错；四路由协议按宿主模式样板实现（§7 F6）。

---

## 5. 范围与优先级

### 5.1 范围
- **本次收敛的边界 = §2.3 协议全集**（权威完整清单，不分批）。试点批次只决定**先做哪几条线**，全集始终可见、不遗漏。
- 每个协议/层的改动**恒为三类**：**① 设计文档**（定义该层模板/归类/复用关系 + 更新 `18-layer-config-design.md`）、**② 代码**（registry/schema/planner/generator 实现模板与 FieldContract）、**③ 用例**（改写成严格分层写法）。缺一不可。
- 本次只收敛**已实现**代码/设计/用例（§2.3 A/B/C），**不新造协议**；D 类（未归位）单列 P3。
- 可并行则并行（模板补齐 / shared 件抽取 / HTTP 族改造 / 用例重写 4 条线并行）。

### 5.2 建议优先级

| 序 | 线 | 内容 | 收益 |
|---|---|---|---|
| **P0（试点第一条）** | shared 件 + 模型落地 | ① 提 `postgresql` 为共享 wire 层（kingbase 作其 dialect 变体，§7 F4）→ 打通"父层复用于变体"范式；② `LayerSchema` 增 `FieldContract`；解析流水线 ①→④ | 补"维度二"空缺 + 首条复用样例 |
| **P0b** | 模板补齐 | 45 个空壳层补 Fields + 默认行为模板（每协议能空配置出默认流） | 最大的架构收敛 |
| **P1a** | HTTP 族改造 | a2a/mcp 改骑 http 层 + 删 `http_builder.go`；抽 JSON-RPC 件 | 消除重复造轮子 |
| **P1b** | 兼容 DB 收尾 | dameng 暂独立层（Oracle/DB2 类，后续如需再抽 oracle 父层）；kingbase 复用已在 P0 闭环，不重复 | 消除重复实现 |
| **P2** | 用例重写 | 999 src_ip / 534 dst_port / 各协议 flat 键 → 迁进层 / FieldContract 表达 | 让"混合态"变"严格分层" |
| **P3** | 未归位协议 | 补齐层注册 / planner 白名单 / 配置翻译，让 §2.3 D 类协议跑通 | 全量套件变绿 |

> P0+P0b 是根基（每层有模板、依赖两维闭合 + 首条复用样例），P1 是复用收敛，P2 是写法收敛，P3 是补齐。P0 与 P1/P2/P3 可并行推进。

---

## 6. 验收标准

1. **每协议层有完整模板**：Fields（字段+默认+范围）+ 依赖声明（DependsOn/TransportOn/OptionalOn/InnerRequired）+ FieldContract + 默认行为模板。60 层无空壳。
2. **空配置产出默认流**：任意 `{proto:{}}` 都能补全成完整链并产生有意义的默认帧（不再报 "connections/transactions required"）。
3. **依赖两维闭合**：层存在依赖（补全）+ 层字段契约（传播）都生效；`tcp.dst_port` 能由骑在其上的终结/隧道层正确填入。
4. **优先级正确**：用户显式 > FieldContract 值 > 模板默认；显式 0 ≠ 缺失。
5. **重复造轮子消除**：HTTP 族统一骑 http 层（无各自 http_builder）；JSON-RPC 抽公共件；兼容 DB 复用父库。
6. **非独立协议统一层规划**：HTTP 内容载体 / DB 兼容 / 挖矿族 / RTMP 变体 / 厂商隧道 各归位到父层 + 内容变体。
7. **解析从模板来**：不再靠顶层平铺 `spec.X` 直传注入；层内字段权威。
8. **全量套件不回归**：收敛后已跑通协议不回归；§2.3 D 未归位 / 半集成协议优先转绿（P3）。
9. **准入一致性与用例质量门禁**（依赖 §7 F5/F7 确认后生效）：同一协议在 REST 白名单、worker convert 白名单、planner 注册、registry 四处的准入结论一致并由哨兵测试锁定；`cases/*.json` 通过 schema lint 后方可入库跑批。

---

## 7. 待确认/后续细化

- FieldContract 目标层"紧邻外层邻居层"、值"常量（含按 profile/传输层取不同常量）"已确认，**动态字段引用单列**。
- 默认行为模板为每协议补全（空配置出默认流）确认纳入本次。
- **【决策点 F2 · 已确认选①】**kingbase/dameng "复用父库"：确认**先造一个 PostgreSQL 共用零件**——把已有 `postgresql`（legacy flat，PG v3 wire，端口 5432）**提为共享 wire 层**，kingbase（同 PG v3 wire，端口 54321）作其 **dialect 变体**（不当独立层，见 §7 F4）。dameng 非 PG 系（Oracle/DB2 类）、暂无父库可复，**保持独立层**（后续如需再抽 oracle 父层）。
- **【决策点 F3 · 按 profile 选载体】**mcp/a2a "骑 http"：a2a 纯 HTTP 可整体改骑 http；**mcp 需按 profile 选载体**（stdio→tcp 逐行 JSON，http/streamable→http 层），非一刀切。
- **三类改动默认成立**：本次所有协议/层改动 = 设计文档 + 代码 + 用例，缺一不可（用户已确认，§5.1 固化）。
- **【决策点 F4 · 已确认选 (a) 变体=profile】**kingbase 骑 postgresql 时端口 54321 传不下去（postgresql FieldContract 写死 5432）。**确认**：kingbase **不当独立层**，作 postgresql 层的 **dialect 变体** → 配置 `[ip,tcp,postgresql]` + `postgresql.dialect=kingbase`，postgresql 模板据 dialect 默认端口 54321。**不打破"值=常量"**。已按此改写 §2.3 C kingbase 行 / §2.2 DB 行 / §2.3 共用零件第1点。

以下为 P3 开工前新增的机制决策点（2026-08-27 提案，**待确认**）：

- **【决策点 F5 · 提案待确认】白名单单源化 + 一致性哨兵测试**：同一协议的准入结论分散在 REST 两处表、worker convert.go 两处表、main.go 注册、registry 六道门，已实际发生漂移（commit 81cefc7 注册了 ldp/pcep planner 却因 REST 缺表被拒；dhcpv6 注释声明切链式但注册行丢失；s7/bgp/coap/iec104/opcua/mms REST 有而 worker 无）。最低限度做法：抽单一导出定义并在 CI 加哨兵断言四方集合相等；理想态做法：`RegisterPlanner` 注册即准入，删手抄表。
- **【决策点 F6 · 提案待确认】宿主模式（carrier mode）样板化**：把"终结层直发"沉淀为两种标准样板——**ip 直发**（ip.proto=2/89/103，用于 igmp/ospf/pim）、**L2 直发**（goose/sv 为已验证先例；isis 走 eth 终结、LLC 封装细节在其各自阶段1 定稿）。样板一节补进 `18-layer-config-design.md` §5 后，四路由协议照样板实现，避免再造混合态旁路。
- **【决策点 F7 · 提案待确认】用例资产 lint 进门**：`cases/*.json` 跑前 schema 校验（proto 必须已知、spec_json 必须是对象且键 ∈ registry、expect 字段名可被 tshark 解析）。原则：**修数据优于工具容错**——MCP `mapString` 对数组返回 nil 引爆 opcua/mms 属测例形状笔误，不靠工具兼容数组掩盖。
- **【决策点 F8 · 提案待确认】失败工单与结果文档卫生**：pcap 驱动对 fail/error 用例自动落盘"期望断言 vs tshark 实测值"对照文件；SUMMARY 改合并写（单协议跑批不得覆盖全量汇总）。

---

## 8. 实施编排（分阶段推进 + 流水线子代理）【用户确认版】

> 本节为**需求一部分**：不只是"做什么"，还规定"**怎么做**"。

### 8.1 分三阶段推进（串行阶段，阶段内流水线并行）

| 阶段 | 内容 | 出口条件 |
|---|---|---|
| **阶段1：文本类** | 先调整**设计文档 + 用例**，然后走 **review-fix-review** | 设计文档与用例 review 通过、自洽 |
| **阶段2：代码** | 再设计**代码调整** | 「设计文档 + 用例」为锚，代码按文档落地 |
| **阶段3：整体测试** | 再进行**整体测试 - 修复 - 测试** | 全量套件按目标变绿、无回归 |

> 阶段间**串行**（1 → 2 → 3 顺序），避免"做前面完了后面"：先用文本类把设计/用例定死，代码才有唯一锚点，测试才知道对错。阶段内**并行流水线**。

### 8.2 编排原则（阶段内流水线子代理）

1. **每阶段可使用子代理并发处理**，**不限并发数量**。
2. **并发子代理之间不能相互影响**（隔离：各自改独立协议/独立文件，不共享可变状态；同一协议的设计/用例/代码按协议边界切分，单子代理内聚）。
3. **流水线补充**：子代理处理完成一个，**立即补充一个新的**接上，**不要整批次全部子代理都完成才推进下一批次**（那样效率低）。
4. **阶段间严格串行**（1 → 2 → 3）：上一阶段**全部协议**完成并通过 review，才整阶段进入下一阶段。**不按协议跨阶段串骑**——否则"做前面完了后面"（前面某个协议半成品进代码，后面才发现设计没定死）。阶段**内**才是流水线（完成一个补一个）。
5. 每个子代理完成必须**自审**（本库 CLAUDE.md 强制），主代理再 review 实际改动。

### 8.3 为何阶段内流水线而非阶段内批次栅栏

阶段**内**整批等齐再推进 = 慢协议拖慢全队 + 闲时死等。阶段内流水线"完成一个补一个"让最慢的单个协议决定该阶段耗时，而不是最慢一批；且隔离保证阶段内各协议互不干扰、可随时平行补子代理。**阶段间仍严格串行**（§8.2 第4点）。

> 落地：主代理作为调度器，维护**当前阶段**的协议级队列；阶段内每完成一个 → 立即补对应子代理；该阶段**全部**协议通过 review 后，整阶段进入下一阶段（§8.1）。

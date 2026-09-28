# #100 someip（SOME/IP · AUTOSAR 面向服务中间件）设计契约

> 版本：v1.0.2（P-PIPE 文档轨 P1–P3 + 隔离审查修轮 + 小补登记；修订记录见 §15）
> 日期：2026-09-28
> 车道：文档轨（#100 someip 续号）
> 旧基线：`docs/protocol-designs/28-someip-design.md` v1.1.0 + `28-someip-testcase.md` v1.1.0（16 例 = 12 正 + 4 负；本 #100 为 P-PIPE 续号重做，**承 28 稿的场景划分与用例 ID 集合**；线格式以代码 + tshark 探针为唯一权威，28 稿线格式表经审计确认有 7 处错误并已逐条改正，见 §0 第 6–13 行）
> 存量用例：`trafficgen/test/protocol_pcap/cases/someip.json`（16/16 ID 与旧稿一致，顺序一致，已机读实测；顶层旧键残留待 P4 迁移，G-SOMEIP-1；**存量 16 例今日 create 400 全红**——五键在即被 `CheckProtoFlat` 拒，详见 §0 产物过期登记 G-SOMEIP-12）
> 规范基线：① AUTOSAR SOME/IP 协议规范（PRS SOME/IP Protocol Specification：16B 消息头字段域、Message Type/Return Code 编码、SD entry/option 结构、TP 分段，下称 **spec**）；② 本机 tshark 3.6.14 `someip.*`/`someipsd.*`/`someip.tp.*` 字段表实测（字段名与进制显示的唯一权威）；③ 本仓库落码（`internal/protocol/someip/` planner/builder/生成器 + 接线，§11）；④ 旧基线设计文档（内部契约，非外部规范）
> 白话一句：**车里的"服务电话系统"——一条消息 16 字节头（谁打给谁、哪个方法、第几通电话），头后面跟业务数据；还有两个附件：SD 是"黄页"（服务在哪儿），TP 是"把超长内容切段寄"。**

## 0. 28→100 沿革与旧稿校正声明（门1 必答：基线继承关系）

本 #100 与旧稿 `28-someip-*` 是**同一协议的续号契约**，不是新协议。旧稿保留在磁盘只读参考。审计逐条给出校正结论（区分"承旧稿"与"旧稿过时"），共 **13 项**：

| # | 旧稿说法（28-*） | HEAD 实测（2026-09-28） | 校正结论 |
|---|---|---|---|
| 1 | 设计文档 11 章、用例文档 9 章；无沿革章、无门1 十四行表、无动态清单、无性能验收两路 | — | **结构缺口**，本版按 §12/§6/§12.12 补齐 |
| 2 | "实现位置：`trafficgen/internal/protocol/someip/`"（design 头注） | 四文件已落码共 **1509 行**：`builder.go` 317 / `layer_gen.go` 295 / `planner.go` 344 / `someip_test.go` 553（`wc -l` 实测） | 承旧稿；本版 §11 为 as-built 定稿 |
| 3 | "层注册 category=Terminal、DependsOn=[udp]、TransportOn=[udp,tcp]"（§5.1） | `registry.go:763` 同值实测 | **承旧稿，审计通过** |
| 4 | "全部字段走 `spec.SOMEIP` 扁平键直传"（§5.2） | `types.go:759-775 SOMEIPConfig` 已定义；`chain_planner_translate.go:120 SOMEIP: spec.SOMEIP` 已直传 | 承旧稿；但 registry `Fields` 为**空**（生成表 `fields: {}` 实测）→ 层内无处可住，见 G-SOMEIP-1 |
| 5 | 存量 16 例 spec_json 为层链形（design §6 未给完整 spec_json 样例） | 机读：16/16 顶层 = `{layers, src_ip, dst_ip, src_port, dst_port, someip}`——**顶层四元组 + 顶层 `someip` 子映射与 `layers` 并存** | **过渡态违规形**（§1.4/§1.11），P4 按 §12.1 迁移；本版 §2 样例只给纯层链形 |
| 6 | §6 S8 / testcase §4.9：TP 载荷 **2500B**、`segment_size=1400`、`payload_length=2516`、重组长 2516 | JSON 实测：`len(payload)==2560`、`segment_size=1408`、`payload_length=2560`；expect `someip.tp.reassembled.length=2560`、包2 `someip.tp.offset=1408` | **旧稿数字错**（与执行事实源不符）；本版 §6 S8 按 JSON 钉死（2560/1408/2560） |
| 7 | §2.5/§3.4.2/S5：IPv4 Endpoint Option `type=0x01`，tshark 显示十进制 1 | 代码：`builder.go:36` 逻辑枚举 0x01 → `builder.go:43 sdWireOptionIPv4Endpoint=0x04` → wire 写 0x04；JSON expect `someipsd.option.type=4` | **旧稿把逻辑枚举当 wire 值**；本版 §3.4.2 区分逻辑枚举与 wire 字节 |
| 8 | §6 S5 hexdump Option 段 `01 00 09 00 14 00 00 c8 00 11 77 1a`（Type 在前） | 代码 `builder.go:273-276`：**Length(2B) 先写**，`b[2]=type`，即 `00 09 04 00 ...` | **旧稿 hexdump 过时**；本版 §6 S5 重算 |
| 9 | testcase §4.10：IPv6 用例断言 "`ip.proto=17`" | JSON 实测断言 `ipv6.nxt=17` | 表述与断言名不符，本版 §6 S9 改正 |
| 10 | §9.1 V5 锚词 "`someip: tp segment N out of range`" | 代码 `planner.go:50/:53`：`tp segment_size must be > 0` / `tp segment_size %d too small` | **旧稿锚词臆造**；本版 §7 按代码逐字 |
| 11 | testcase §5 负例 `error_contains` 用 `service_id must be nonzero` 等 | 代码 `planner.go:26/:35/:40/:45` 逐字一致（前缀 `someip: `） | 承旧稿，锚词命中；但**存量 JSON 未写全前缀**（见 §7 注） |
| 12 | 28 稿 §2.5 Entry 偏移表（100 稿 §3.4.1 照抄）：`Index1/NumOpts1@1`、`Index2/NumOpts2@2`、ServiceID@3-4、InstanceID@5-6、Major@7、TTL@8-10、Minor@11-14 | 代码 `builder.go:213-220`：`entry[0]=type`、`entry[4:6]=serviceID`、`entry[6:8]=instanceID`、`entry[8]=major`、`entry[9:12]=ttl`、`entry[12:16]=minor`；`setOpts`（`builder.go:251`）只写 `entry[3]` 高 4bit | **旧稿偏移整体错位 1 字节**（Index1/Index2 实为独立字节 @1/@2，NumOpts 合并于 @3）；本版 §3.4.1 按代码重写（探针实证见 §3.4.1 注） |
| 13 | 28 稿 §2.6 TP 表（100 稿 §3.5 照抄）：8B TP 头（Offered Length 4B + Segment ID 1B + more 1B + 保留 2B）；**后续段不重复消息头** | 代码 `buildTPHeader`（`builder.go:310-317`）返回 **4B**：低 28bit = offset（`&0xfffffff0` 16 对齐）、bit0 = more；`planner.go:247` 后续段**每段调用 `buildHeader` 重复完整 16B 头** | **旧稿头长与后续段结构全错**；本版 §3.5 按代码重写（tshark 对比探针见 §3.5 注） |

**依赖链判定纪律**：以上均为可判题（旧文→代码→用例三级对照），直接判定，不问偏好。不可判的（AUTOSAR 规范原文条款号）标"待确认"并写清确认方式（G-SOMEIP-8）。

> **第 12/13 行属"旧稿继承错误"而非"新错"**：本版 §3.4.1/§3.5 初稿照抄了 28 稿表，经隔离审查 B-1/B-2 打回后按代码 + tshark 探针重写（§3.4.1/§3.5 各附复算命令与原始输出）。教训：**字段/偏移表必须实调 tshark 探针产出，禁由旧稿搬运**。

**产物过期登记（重要，G-SOMEIP-12）**：`trafficgen/docs/protocol-pcap-test/someip.md` 写 "Cases: 16 — pass 16, fail 0, error 0"，但该文件末次提交 `3c5991a`（2026-08-28），**早于**判死提交 `0417be5`（2026-09-13）**16 天**；`cases/someip.json` 末改同为 `3c5991a`（2026-08-28）；`docs/protocol-pcap-test/someip/` 目录 **0 个 pcap 文件**（目录本身不存在）。更关键：**存量 16 例今日经 MCP 建策略 400 全红**——顶层旧键残留 **60 处**（非负例 12/12 全违规形，每例 `src_ip`/`dst_ip`/`src_port`/`dst_port` + 顶层 `someip` 子映射 5 键），首条即被 `CheckProtoFlat`（`strategy_convert.go:8632`）拒：`protocol someip no longer accepts flat config field src_ip`。**该结果文档是过期产物，16/16 pass 不代表今日可跑**——读者不得据此判断套件可用。

复算命令与原始输出（`trafficgen/` 下执行）：

```bash
git log -1 --format='%h %ad %s' --date=short -- docs/protocol-pcap-test/someip.md
# → 3c5991a 2026-08-28 fix(someip): SOME/IP-SD wire layout + TP segmentation (someip 4/16→16/16)
git log -1 --format='%h %ad %s' --date=short 0417be5
# → 0417be5 2026-09-13 feat(core): 扁平判死泛化全协议（CheckProtoFlat）
ls docs/protocol-pcap-test/someip/ | wc -l
# → 0（ls: No such file or directory）
git log -1 --format='%h %ad %s' --date=short -- test/protocol_pcap/cases/someip.json
# → 3c5991a 2026-08-28（与结果文档同提交）
python3 -c "
import json
cs=json.load(open('test/protocol_pcap/cases/someip.json'))
cs=cs if isinstance(cs,list) else cs['cases']
fk={'src_ip','dst_ip','src_port','dst_port','someip'}
print('non-neg residue', sum(len(set(c['spec_json'])&fk) for c in cs if 'expect_error' not in c['expect']),
      '| violating non-neg', sum(1 for c in cs if 'expect_error' not in c['expect'] and set(c['spec_json'])&fk), '/12')"
# → non-neg residue 60 | violating non-neg 12 /12
# MCP 建策略 16/16 → 400（`protocol someip no longer accepts flat config field src_ip …`）
```

## 1. 范围、profile 与实现状态边界

本版定义**车载 SOA 通信流量生成**：SOME/IP 本体（方法调用/事件/错误）+ SOME/IP-SD（服务发现）+ SOME/IP-TP（UDP 大载荷分段）。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `someip_udp_v1`（主） | UDP，fixture 30490 | 方法调用往返 / 无返回 / 事件 / 错误 / SD 四 entry / TP 分段 | 真实 ECU 的服务实例存在性、TTL 计时 |
| `someip_tcp_v1` | TCP，fixture 30490 | 同上（TCP 天然不分段，不取 TP 变体） | 从 UDP 例推导 TCP 例的包位 |
| `someip_ipv6_v1` | 同上，仅外层 IPv6 | 同上 | 从 IPv4 fixture 推导 IPv6 地址 |

显式边界（"不实现、不声称、不许静默转换"）：① 不实现 CommonAPI/WTLV/Type 1/2/3 载荷序列化（载荷按不透明字节直传）；② 不实现动态发现的"多播监听/应答调度"（SD 报文按配置显式发送）；③ 不实现运行期负载均衡/重传/心跳；④ SD Option 只实现 IPv4 Endpoint / IPv4 Multicast / IPv6 Endpoint 三类（`builder.go:264-292` 三分支），SD Endpoint(0x04)/Configuration(0x0C) 未实现（G-SOMEIP-4）；⑤ TP 只实现 REQUEST 变体首段（0x20），其余 TP 变体未覆（G-SOMEIP-5）。

**实现状态（2026-09-28 实测）**：`someip` 层已注册（`registry.go:763`）、planner/builder/生成器已落码（`internal/protocol/someip/` 四文件 1509 行）、`allowedProtocols["someip"]=true`（`protocols.go:56`）、Meta 已直传（`chain_planner_translate.go:120`）、缺省目的端口 30490（`chain_planner.go:1287`）、16 语义用例已落 `cases/someip.json`。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`someip.*`/`someipsd.*`/`someip.tp.*` 字段 + offset 42/54 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, udp, someip]`（引擎自动补 `ip`；最小链 `[udp, someip]`）；TCP 载体为 `[ip, tcp, someip]`。

端口：AUTOSAR SOME/IP 默认 **UDP/TCP 30490**（planner 缺省已落码 `chain_planner.go:1287`）。fixture 统一 `dst_port=30490`；用例一律显式写端口并纳入断言。

固定偏移：无 VLAN/IP options/UDP options 时，**SOME/IP 头起点为 IPv4+UDP offset 42**（14+20+8）、**IPv4+TCP offset 54**（14+20+20）；IPv6 载体相应为 62（14+40+8，UDP）。本版用例 frame 断言只落在 IPv4+UDP offset 42（S1/S3/S5/S8）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers` + `flow_control`；**目标形状声明**：registry `someip` Fields 今日为空，层内 `service_id` 等业务键今日无处可住，故此形**今天跑不通，需先补代码** G-SOMEIP-1，§1.9 口径）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"udp": {"src_port": 12345, "dst_port": 30490}},
    {"someip": {"service_id": 4660, "method_id": 1, "client_id": 1,
                "message_type": "request", "payload": [222, 173, 190, 239]}}
  ],
  "flow_control": {"flows": 1}
}
```

多流样例（数量只走 `flow_control`，四元组留空走 worker 保底递增 §12.12）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"udp": {"dst_port": 30490}},
    {"someip": {"service_id": 4660, "method_id": 1}}
  ],
  "flow_control": {"flows": 3}
}
```

## 3. 线格式编码（**以代码 + tshark 探针为唯一权威**；28 稿线格式表已逐条复核改正，见 §0）

### 3.1 消息头 16 字节（大端）

| 字节 | 字段 | 取值/语义 | tshark 字段 |
|---|---|---|---|
| 0-1 | Service ID | 16bit 大端；0 非法（V1） | `someip.serviceid` |
| 2-3 | Method ID | 16bit 大端；bit15=1 为事件，bit15=0 为方法；SD 固定 0x8100 | `someip.methodid` |
| 0-3 | Message ID | = Service ID + Method ID，32bit 大端 | `someip.messageid` |
| 4-7 | Length | **自 Request ID 起至消息末尾** = 8 + len(Payload) | `someip.length` |
| 8-9 | Client ID | 16bit 大端 | `someip.clientid` |
| 10-11 | Session ID | 16bit 大端；多会话递增 | `someip.sessionid` |
| 8-11 | Request ID | = Client ID + Session ID | — |
| 12 | Protocol Version | 固定 0x01（V4） | `someip.protoversion` |
| 13 | Interface Version | 默认 1，可配 | `someip.interfaceversion` |
| 14 | Message Type | 见 §3.2 | `someip.messagetype` |
| 15 | Return Code | 见 §3.3 | `someip.returncode` |

**Length 口径**：`Length = 4(RequestID) + 1(Proto) + 1(If) + 1(Type) + 1(RC) + len(Payload) = 8 + len(Payload)`。空载荷 Length=8（`someip_req_empty` 断言）。SD 报文的 Payload 含 SD 头+Entry+Option，Length 仍自 Request ID 起。

### 3.2 Message Type 取值表（逐值覆盖去向）

| 值 | 常量 | 方向 | 覆盖去向 |
|----|------|------|---------|
| 0x00 | REQUEST | C→S | 覆 `someip_req_resp` |
| 0x01 | REQUEST_NO_RETURN | C→S | 覆 `someip_no_return` |
| 0x02 | NOTIFICATION | S→C | 覆 `someip_multi_method_event`（0x8001 事件） |
| 0x80 | RESPONSE | S→C | 覆 `someip_req_resp` 包2（auto_response） |
| 0x81 | ERROR | S→C | 覆 `someip_error`（RC=0x01） |
| 0x20 | TP_REQUEST | C→S | 覆 `someip_tp_segments` 首段 |
| 0x21 | TP_REQUEST_NO_RETURN | C→S | **A′ 立项**（G-SOMEIP-5） |
| 0x22 | TP_NOTIFICATION | S→C | **A′ 立项**（G-SOMEIP-5） |
| 0xA0 | TP_RESPONSE | S→C | **A′ 立项**（G-SOMEIP-5） |
| 0xA1 | TP_ERROR | S→C | **A′ 立项**（G-SOMEIP-5） |

> TP 变体编码：Message Type 高 bit 为标志——bit6=0x40 Ack、bit5=0x20 TP（tshark `someip.messagetype.tp`）；0x20/0x21/0x22 低 5 位复用 0x00/0x01/0x02 语义，0xA0/0xA1 = RESPONSE/ERROR 叠 TP 标志。

### 3.3 Return Code 取值表（逐值覆盖去向）

| 值 | 常量 | 覆盖去向 |
|----|------|---------|
| 0x00 | E_OK | 覆（`someip_req_resp` 包2、`someip_no_return`） |
| 0x01 | E_NOT_OK | 覆（`someip_error`） |
| 0x02-0x0A | E_UNKNOWN_SERVICE … E_WRONG_MESSAGE_TYPE（9 值） | **A′ 立项**（G-SOMEIP-6；代码接受任意 uint8，`planner.go` 仅拒 >0xFF 面） |
| 0x20-0xFF | 应用自定义返回码 | **A′ 立项**（G-SOMEIP-6；同分支代表例，§9.21 口径） |

### 3.4 SOME/IP-SD 子结构

SD 报文本身是一条 Message ID = `Service ID(0xFFFF) + Method ID(0x8100)`、Message Type = NOTIFICATION(0x02)、Return Code = E_OK(0x00) 的 SOME/IP 消息。

#### 3.4.1 SD 头（8 字节）+ Entry（16 字节/条）+ Options Length（4 字节）

| SD 头偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 1 | Flags（bit7 Reboot / bit6 Unicast / bit5 ExpInitEvents） |
| 1-3 | 3 | Reserved |
| 4-7 | 4 | Length of Entries Array |

**Options Length（4 字节，大端）**：紧跟在 Entry 数组之后、Option 数组之前（`builder.go:194-199`，`PutUint32(optLenField, len(optBytes))`）。**无 Option 时也必须写这 4 字节 0**——tshark 缺此字段会把 Option 头 4 字节误读为长度并报 truncated/malformed（代码注释原文："missing before this fix"）。故 SD 报文总布局 = `16B SOME/IP 头 + 8B SD 头 + N×16B Entry + 4B Options Length + Options`。

| Entry 偏移 | 长度 | 字段 | 代码写入点 |
|---|---|---|---|
| 0 | 1 | Type（0x00 Find / 0x01 Offer / 0x06 Subscribe / 0x07 SubscribeAck） | `entry[0]`（`builder.go:214`） |
| 1 | 1 | **Index 1**（独立字节；tshark `someipsd.entry.index1`） | 代码不写（恒 0） |
| 2 | 1 | **Index 2**（独立字节；tshark `someipsd.entry.index2`） | 代码不写（恒 0） |
| 3 | 1 | **Num of Opts 1（高 4bit）+ Num of Opts 2（低 4bit）** | `setOpts`（`builder.go:246`，写入 `:251`）：`entry[3] = (numOpts&0x0F)<<4` |
| 4-5 | 2 | Service ID（大端） | `PutUint16(entry[4:6])`（`:216`） |
| 6-7 | 2 | Instance ID（大端） | `PutUint16(entry[6:8])`（`:217`） |
| 8 | 1 | Major Version | `entry[8]`（`:218`） |
| 9-11 | 3 | TTL（24bit 大端） | `putU24(entry[9:12])`（`:219`） |
| 12-15 | 4 | Minor Version（32bit 大端） | `PutUint32(entry[12:16])`（`:220`） |

**Entry 偏移实证（2026-09-28 自建探针，命令与原始输出）**：构造 Entry 使三个索引字节取不同值（`[1]=0x0A`、`[2]=0x0B`、`[3]=0x21`），喂 tshark：

```
$ tshark -r entry_probe.pcap -d udp.port==30490,someip -T fields \
    -e someipsd.entry.numopt1 -e someipsd.entry.numopt2 \
    -e someipsd.entry.serviceid -e someipsd.entry.instanceid \
    -e someipsd.entry.majorver -e someipsd.entry.ttl
0x02    0x01    0x1234  0x0001  1   3
```

即 `numopt1` = `[3]` 高 4bit（`0x21>>4` = 2）、`numopt2` = `[3]` 低 4bit（`0x21&0x0F` = 1）；`[1]`/`[2]` **不参与 numopt**（改 `[1]=0xF0,[2]=0xF0,[3]=0x00` → `numopt1=0x00 numopt2=0x00` 实测），它们是 tshark 的 `index1`/`index2` 字段。ServiceID 在 **4-5**（`0x1234`）、InstanceID 在 **6-7**、Major 在 **8**、TTL 在 **9-11**。

> **与 28 稿对照**：28-design §3.4.1 把 Entry 内偏移整体前移 1 字节（ServiceID@3-4、InstanceID@5-6、Major@7、TTL@8-10、Minor@11-14），且把 Index1/NumOpts1 与 Index2/NumOpts2 写成两个合并字段。实测 28 稿布局喂 tshark 得 `serviceid=0x3400 instanceid=0x0101 ttl=768`（全错）——**旧稿错、本版按代码重写**（§0 第 12 行）。
>
> **Index1/Index2 代码不实现**：`buildServiceEntry`/`buildEventgroupEntry` 均不写 `entry[1]`/`entry[2]`（恒 0）。§12.3 的"报文内引用"表述已相应修正——本实现**不做** entry→option 的 index 引用，仅写 NumOpts 计数。

**Eventgroup Entry（Type 0x06/0x07）变体**（`builder.go:229-241`）：前 12 字节同 Service Entry 布局（Type/Index1/Index2/NumOpts/ServiceID/InstanceID/Major/TTL），**12-15 字节改为** `entry[12]=reserved`、`entry[13]=init_event(bit7) | counter(低 4bit)`、`entry[14:16]=eventgroupID`（大端）。tshark 读 `someipsd.entry.counter`（`[13]` 低 4bit）与 `someipsd.entry.eventgroupid`（`[14:16]`）。**实证**：`someip_sd_subscribe` 断言 `eventgroupid=0x0001` 与 `counter=0x00` 经探针复现成立（28 稿 §2.5 Sub 变体行的"偏移 15 为 Eventgroup ID"亦错，实为 14-15）。

Entry 四条类型全部覆盖：0x00/0x01（`someip_sd_find_offer`）、0x06/0x07（`someip_sd_subscribe`）。

#### 3.4.2 Option：逻辑枚举 vs wire 字节（旧稿此处错，本版改正）

**关键区分**：`sd.options[].type` 是**配置侧逻辑枚举**（`builder.go:34-41`），写入帧的是 **wire 字节**（`builder.go:43-45`，经 `configToWireOptionType` 换算，因 tshark 的 `sd_option_type` 枚举重编号）：

| 配置逻辑枚举 | wire 字节 | 数据长度字段 | Option 总长 | 覆盖去向 |
|---|---|---|---|---|
| 0x01 IPv4 Endpoint | **0x04** | 9 | 12B | 覆 `someip_sd_find_offer`（tshark 显示 `someipsd.option.type=4`） |
| 0x02 IPv4 Multicast | **0x14** | 9 | 12B | **A′ 立项**（G-SOMEIP-4） |
| 0x06 IPv6 Endpoint | **0x06** | 21 | 24B | 覆 `someip_sd_ipv6`（tshark 显示 6） |
| 0x04 SD Endpoint | — | — | — | **明确不解决**（代码 `default: unsupported sd option type`，G-SOMEIP-4） |
| 0x0C Configuration | — | — | — | **明确不解决**（同上） |

**Option wire 布局（代码实测，非旧稿 hexdump）**：`Length(2B 大端) + Type(1B) + Reserved(1B) + 数据`。IPv4 数据段 = `addr(4B) + Reserved(1B) + proto(1B) + port(2B)`（`builder.go:273-276`）；IPv6 数据段 = `addr(16B) + Reserved(1B) + proto(1B) + port(2B)`（`builder.go:287-290`）。Length 字段值 9/21 = 数据段字节数（不含 Type/Length 自身；tshark 读 `real_length = ntohs(length)+3`）。

### 3.5 SOME/IP-TP 分段（承 28 稿的场景，线格式按代码/tshark 重写）

**每一段都是完整 SOME/IP 消息**（16B 消息头 + 4B TP 头 + 本段载荷），TP 头在消息头之后。首段 offset=0，后续段 offset = 已发数据字节累计。

**TP 头（4 字节，`buildTPHeader`，`builder.go:310-317`）**：

| 位域 | 内容 |
|---|---|
| 低 28bit（`v & 0xfffffff0`） | **offset**：本段在重组消息中的字节偏移，**16 对齐**（非 16 对齐值被 tshark 静默掩码截断） |
| bit0（`v \|= 0x01`） | **more_segments**（tshark `someip.tp.flags.more_segments`） |

> **与 28 稿对照（§0 第 13 行）**：28-design §2.6/§3.5 写"8B TP 头（Offered Length 32bit + Segment ID 8bit + more 低 1 位 + 保留）"且"后续段不重复消息头"——**两处均与代码相反**。代码 TP 头恒 4B，且 `planner.go:247` 对**每一段**调用 `buildHeader(...)` 产出完整 16B 头（后续段不是裸 TP 头）。

**TP 头实证（2026-09-28 自建两种布局对比，命令与原始输出）**：

```
代码布局（4B TP 头 + 每段 16B 头），同载荷 2560B / segment_size 1408：
$ tshark -r tp_code.pcap -d udp.port==30490,someip -T fields \
    -e someip.messagetype -e someip.tp.offset -e someip.tp.flags.more_segments \
    -e someip.tp.reassembled.length
0x20    0       1
0x20    1408    0       2560

文档 §3.5 旧布局（8B TP 头 + 后续段无消息头）：
0x20    2576    0                 ← OfferedLength 被读成 offset
0x86                              ← 后续段乱码（无消息头）
```

代码布局与 `cases/someip.json` 的 `someip_tp_segments` 断言**逐项一致**；旧布局喂 tshark 无法重组（无 `reassembled.length`）。

**实测口径（`someip_tp_segments`，JSON 为执行事实源）**：payload = **2560** 显式字节（0..255 循环，`len(payload)==2560` 机读可核）、`segment_size=1408`（16 对齐）、`tp.payload_length=2560`（**声明值，代码不消费**——见 G-SOMEIP-9）；两段 = 1408 + 1152；首段 `someip.tp.offset=0`、`more_segments=1`、`messagetype=0x20`、`messagetype.tp=1`；末段 `someip.tp.offset=1408`、`more_segments=0`；重组断言 `someip.tp.reassembled.length=2560`（**在末段**收敛，探针实测末段才有值）。TCP 载体天然不分段（S10），MessageType 不取 TP 变体。

**触发条件**（`planner.go:221`）：仅当 `tp.enabled=true` **且** `len(payload) > tp.segment_size` 才分段；否则整条单包发出（`segment_size=1408` 恰好等于载荷长时不分段）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明消息序列（`events[]` 或单条头字段），引擎按序产出事件；SD/TP 是同一序列上的子结构变体。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① ECU 方法调用（RPC） | Client REQUEST → Server RESPONSE（SessionID 配对） | S1（`someip_req_resp` / `someip_req_empty`） |
| ② 事件订阅后收通知 | SubscribeEventgroup → Ack → NOTIFICATION | S6 + S7（`someip_sd_subscribe` / `someip_multi_method_event`） |
| ③ 服务上下线发现 | FindService → OfferService（ID/版本/TTL） | S5（`someip_sd_find_offer`） |
| ④ 大载荷方法调用 | 超 MTU 载荷按 TP 切段发送 | S8（`someip_tp_segments`） |
| ⑤ 多会话并发调用 | 同 Client 多 SessionID 递增 | S2（`someip_multi_session`） |
| ⑥ 业务错误返回 | REQUEST → ERROR（RC≠0） | S4（`someip_error`） |
| ⑦ IPv6 车载网段 | 同 ①③，仅外层 IPv6 | S9/S9b（`someip_ipv6` / `someip_sd_ipv6`） |
| ⑧ TCP 可靠大调用 | TCP 载体双向交换 | S10（`someip_tcp_swap`） |

**五层覆盖逐层结论**：功能层——Message Type 10 值中 6 值有正例、4 个 TP 变体立项（G-SOMEIP-5）；Return Code 2 值有例、其余立项（G-SOMEIP-6）；SD entry 4 类型全覆；负例 4 条。性能层——大载荷跨段（2560B/2 段）、最小边界（空载荷 Length=8）、多会话 4 包、多方法多事件 5 包。数据场景层——空/非空/二进制 payload、SD 四类型、TTL 极值（0xFFFFFF 与 3）、IPv4/IPv6 双族、非法 message_type/service_id/session。地址与流层——v4/v6 独立用例、单流基线、多会话（SessionID 递增）；**流关联（控制流派生数据流）显式不适用**：SOME/IP 无控制/数据分离的副连接（SD 与业务同载体，各自独立消息）；**多流（会话内并发流）显式不适用**：单载体串行消息序列，多会话语义由 `flow_control flows` 承载。业务层——RPC 往返 + 事件订阅链 + 发现链（§4 表①–⑧）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① `interface_version` 非 1 值（字段可配、语义由应用层定，tshark 不校验，本层不断言）；② SD Flags 三标志位（`reboot_flag`/`unicast_flag`/`exp_init_events` 住 `sd` 子配置，28 稿 §5.3 列出但 JSON 无例 → A′ 候选）；③ 载荷超 MTU 未启 TP（不自动分段，由配置者决定）；④ TCP 载体下的 TP 变体（TCP 天然不分段）。

## 5. 消息/事务模型与状态机

**事务定义**：一条 SOME/IP 消息的发送（up）或接收（down）。**多事务** = 同一载体上多条消息按序执行：S2（两轮调用四包）、S7（两方法+一事件五包）。

someip 层无自有连接状态（承 28 稿 §4）：UDP 无连接，TCP 握手/挥手在 tcp 层；someip 层是"按配置把消息翻译成事件"的纯函数驱动，`auto_response` 是唯一的反应性成分（收到 REQUEST 自动补 RESPONSE）。

| 状态（载体层拥有） | someip 层动作 | 用例 |
|---|---|---|
| UDP 就绪（无状态） | 按 `message_type`/`events[]` 逐条 emit | S1–S9b |
| TCP `ESTABLISHED` | 同上；握手/FIN 由 tcp 层补 | S10 |
| TCP 终止 | 事件流关闭 → tcp 层挥手 | S10 |

**自动派生规则**：① `message_type=request` + `auto_response=true`（默认）→ 自动补一条 down RESPONSE（`planner.go:200` 起）；② `request_no_return` 强制无响应；③ `events[]` 逐条展开、SessionID 递增；④ SD 报文头由实现固定 ServiceID=0xFFFF / MethodID=0x8100 / Type=0x02 / RC=0x00（配置只写 `sd` 子块）。

**多会话展开**：多会话语义由策略级 `flow_control {"flows": N}` 表达（worker 保底递增 `src_port` 12345+i）；单 flow 内 `events[]` 是消息序列不是会话数组。`sessions[]` 结构本协议**不适用**（无独立连接生命周期概念）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流最大 5 包（S7 多方法多事件）；最大单包载荷 2560B 跨 2 段（S8）；SD 最大 2 包（S5 含 Option）；多流按 `flows` 复制四元组。吞吐数字待 P4 基准，**本版不写承诺**（§6.5）。
- **依据**：消息序列流式展开（planner 逐条 emit，无全量收集）；每段内存 = 消息头 16B + TP 头 4B + 段载荷（O(段长)）；无跨流共享状态；无锁（常量枚举只读）。
- **验收两路**：pcap（`/tmp/mcp-pcaps/someip/`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `someip.*`/`someipsd.*` 字段值与 frames hex，不只断言"任务没报错"。
- **六类场景落点**：基线（S1，2 包）/ 目标规模（S7，5 包多方法多事件）/ 压力上限（S8，2560B 跨段）/ 长时间运行（S2 多会话序列）/ 并发交错（多流顺序展开承载语义，并发路径为例外不启用）/ 背压（TP 分段 + `packet_count` 精确计数守卫段数漂移）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 planner/validator 拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 UDP 外壳的假成功。锚词逐字取自代码（`planner.go` 实测行号）：

| # | 负例 ID | 故障输入 | 代码文案（`planner.go` 逐字，含 `someip: ` 前缀） | JSON `error_contains`（实际子串） | 代码行 |
|---:|---|---|---|---|---|
| N-1 | `someip_neg_service_id` | `service_id=0` | `someip: service_id must be nonzero` | `service_id must be nonzero` | `planner.go:26` |
| N-2 | `someip_neg_session` | `session_start=1, session_inc=0` | `someip: invalid session_id` | `session_id` | `planner.go:35` |
| N-3 | `someip_neg_type` | `message_type=5`（非枚举） | `someip: invalid message_type 5` | `message_type` | `planner.go:40` |
| N-4 | `someip_neg_tp` | `tp.segment_size=0` | `someip: tp segment_size must be > 0` | `tp` | `planner.go:50` |

**未入用例的校验分支（A′ 立项，不得冒充已覆盖）**——planner 实测共 **10 个 `return fmt.Errorf`**（`planner.go:16-77` 全量枚举，§10.1 #5 计数同源）：

| 代码行 | 锚词 | 入例情况 |
|---|---|---|
| `:26` | `someip: service_id must be nonzero` | 入例 N-1 |
| `:35` | `someip: invalid session_id` | 入例 N-2 |
| `:40` | `someip: invalid message_type %v` | 入例 N-3 |
| `:45` | `someip: protocol_version must be 1, got %d` | **A′ 立项** |
| `:50` | `someip: tp segment_size must be > 0` | 入例 N-4 |
| `:53` | `someip: tp segment_size %d too small`（`< 8`） | **A′ 立项** |
| `:59` | `someip: invalid sd.type %q (want find\|offer\|subscribe\|subscribe_ack)` | **A′ 立项**（SD 唯一入口校验） |
| `:66` | `someip: events[%d] invalid message_type %v` | **A′ 立项** |
| `:71` | `someip: invalid source IP` | **A′ 立项** |
| `:74` | `someip: invalid destination IP` | **A′ 立项** |

入例 4 + 立项 6 = **10**。✓（builder 层另有 3 条：`invalid IPv4 option address` `:267`、`invalid IPv6 option address` `:282`、`unsupported sd option type %d` `:294`——同属 A′ 立项。）

**SD 入口校验与配置写法**：`sd.type` 是 SD 用例的唯一入口校验，合法值 4 个——`find`(0x00)/`offer`(0x01)/`subscribe`(0x06)/`subscribe_ack`(0x07)（`sdTypeFromString`，`builder.go:113-123`）。**`subscribe_ack` 可直接配置为独立一条 Ack 报文**（不必依赖 Subscribe 自动派生）；存量 `someip_sd_subscribe` 走的是 `type="subscribe"` + 自动补 Ack 的路径，**独立 `subscribe_ack` 配置今日无例 → A′ 立项**（G-SOMEIP-10）。

> **锚词前缀注**：代码文案带 `someip: ` 前缀，`error_contains` 是**子串**判定（命中即通过）。存量 4 例用的是短子串（`session_id`/`message_type`/`tp`），N-1 用较长子串——两者都能命中代码文案。P4 迁移时按本表"JSON `error_contains`"列保持现值（收窄到全文亦可，但须先跑后钉确认命中）。

**负例原子性**：每例单一故障注入；单次执行不得混注。

**不得误报的合法协议事件**：空载荷请求（S1 变体正例）；`request_no_return` 单包（S3 正例）；down 方向事件（S7 正例）；2560B 跨段（S8 正例）。

## 8. 边界

- **载荷长**：空载荷 Length=8（覆）；2560B 跨 2 段（覆）；`segment_size` 精确边界（=16 的倍数）今日无例 → A′（G-SOMEIP-5）。
- **`segment_size` 校验面**：代码只拒 `<=0`（`planner.go:50`）与 `<8`（`:53`），**不强制 16 对齐**；tshark 用 `&0xfffffff0` 掩码读 offset，**非 16 对齐的 segment_size 会被静默截断**（offset 值偏小、重组错位）→ 今日无例 → A′（G-SOMEIP-5）。
- **方向**：`direction` 缺省 = up；`down` 用于显式下发（S4/S7 事件）。纯 down 单条今日无独立例 → A′。
- **会话**：`session_start`/`session_inc` 递增覆（S2）；`session_inc=0` 拒绝覆（N-2）；`session_start=0` 分支今日无例 → A′。
- **地址族**：v4/v6 独立用例；异族混写今日无例 → A′。
- **端口**：显式 30490 全正例；缺省 30490（`chain_planner.go:1287` 补齐）今日无例 → A′。
- **SD Option**：IPv4/IPv6 覆；IPv4 Multicast（wire 0x14）无例 → A′；SD Endpoint/Configuration 未实现 → 明确不解决。
- **Message Type / Return Code 枚举**：见 §3.2/§3.3 逐值去向，未覆值已立项。
- 不得产生回绕长度或超量分配（TP 载荷显式声明 2560B，不隐式放大）。

## 9. 原子 ID 与完成定义（16 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count |
|---:|---|---|---|---:|
| 1 | `someip_req_resp` | 正 | §5：REQUEST→RESPONSE 往返 + SessionID 配对 | 2 |
| 2 | `someip_req_empty` | 正 | §3.1：空载荷 Length=8 | 2 |
| 3 | `someip_multi_session` | 正 | §5：两轮调用 SessionID=1,2 | 4 |
| 4 | `someip_no_return` | 正 | §5：REQUEST_NO_RETURN 单包 | 1 |
| 5 | `someip_error` | 正 | §3.3：ERROR 0x81 + RC=0x01 | 2 |
| 6 | `someip_sd_find_offer` | 正 | §3.4：entry 0x00→0x01 + IPv4 Option | 2 |
| 7 | `someip_sd_subscribe` | 正 | §3.4：entry 0x06→0x07 + eventgroup/counter | 2 |
| 8 | `someip_multi_method_event` | 正 | §3.2：两方法 + 事件 0x8001 | 5 |
| 9 | `someip_tp_segments` | 正 | §3.5：2560B / segment_size 1408 跨 2 段 | 2 |
| 10 | `someip_ipv6` | 正 | §2：IPv6 载体方法调用 | 2 |
| 11 | `someip_sd_ipv6` | 正 | §3.4.2：IPv6 Endpoint Option | 1 |
| 12 | `someip_tcp_swap` | 正 | §2：TCP 载体双向（`has_handshake` + `min_packets`） | —（min_packets 6） |
| 13 | `someip_neg_service_id` | 负 | §7：N-1 | — |
| 14 | `someip_neg_session` | 负 | §7：N-2 | — |
| 15 | `someip_neg_type` | 负 | §7：N-3 | — |
| 16 | `someip_neg_tp` | 负 | §7：N-4 | — |

完成定义：`udp→someip` 层链注册已落码；16 ID 正负断言与错误传播完成；`someip_sd_find_offer` 的 Option wire 字节与 `someip_tp_segments` 的段长/重组长按 JSON 事实钉死；不声称载荷序列化与运行期发现调度。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | UDP 无连接（事件/SD）；TCP 可靠（大调用） | 场景①–⑧ | `TransportOn ["udp","tcp"]`（`registry.go:763`）；`DependsOn ["udp"]` | 无 |
| 2 | 命令/消息表 | Message Type 10 值 + Return Code 值域 | §3.2/§3.3 表 | builder 全枚举常量（`builder.go:10-30`） | 4 个 TP 变体 + 9 个错误码立项（G-SOMEIP-5/6） |
| 3 | 状态机 | 无连接态（UDP）；ESTABLISHED（TCP）；auto_response 反应性 | S1/S4/S10 | `planner.go` 逐条 emit + auto_response 分支 | 无 |
| 4 | 字段表 | 16B 头 10 字段 + SD 头/Entry/Options Length + TP 4B 头（§3） | 数据场景层 | `types.go:759-775` + `1349-1383`；SD Entry 偏移按 §3.4.1 代码重写 | `tp.payload_length` 死配置 → G-SOMEIP-9（动态见 G-SOMEIP-3） |
| 5 | 错误处理 | 4 类负例（§7 表）+ 6 个未覆分支 | 负例 N-1…N-4 | planner **10 个**拒绝分支（`planner.go:16-77`） | 6 分支立项（§7 表） |
| 6 | 超时与活性 | SOME/IP 无保活/重试语义（应用层职责）；SD TTL 是宣告期非计时 | — | 协议层无 | **显式不适用**（§4 声明） |
| 7 | NAT/代理/被动 | 无被动模式概念；SD 有 unicast/multicast 标志 | — | `sd` 子配置无 flags 键（28 稿 §5.3 列出但未落码） | flags 键未落码 → A′（G-SOMEIP-7） |
| 8 | 版本/方言 | Protocol Version 固定 1；Interface Version 可配；IPv6 扩展已覆 | 正例 12 | `protocol_version` V4 校验（`planner.go:45`） | Interface Version 语义无例（显式不适用） |

**逐行重数**：8 行——**已覆 3**（#1 连接模型 / #3 状态机 / #4 字段表）/ **立项 3**（#2 命令表 / #5 错误处理 / #7 NAT 被动）/ **不适用 2**（#6 超时活性 / #8 版本方言）。3 + 3 + 2 = 8。✓

### 10.2 子表①：Message Type × 覆盖终态矩阵（逐格已覆/立项/不适用）

| Message Type | T1 正例覆盖 | T2 拒绝面 | T3 立项 |
|---|---|---|---|
| 0x00 REQUEST | 已覆（S1/S2/S4/S7） | 已覆（N-1/N-2/N-3 代表例） | — |
| 0x01 REQUEST_NO_RETURN | 已覆（S3） | 同上代表已覆 | — |
| 0x02 NOTIFICATION | 已覆（S7 事件 0x8001） | 同上代表已覆 | — |
| 0x80 RESPONSE | 已覆（S1/S2/S7 auto_response） | — | — |
| 0x81 ERROR | 已覆（S4） | — | — |
| 0x20 TP_REQUEST | 已覆（S8 首段） | 已覆（N-4 segment_size=0） | — |
| 0x21 TP_REQUEST_NO_RETURN | — | — | A′ 立项 |
| 0x22 TP_NOTIFICATION | — | — | A′ 立项 |
| 0xA0 TP_RESPONSE | — | — | A′ 立项 |
| 0xA1 TP_ERROR | — | — | A′ 立项 |

**逐格重数**：10 行 × 3 列 = 30 格——**已覆 10 / 立项 4 / 不适用 16**（不适用 = 该组合无独立证据需求：拒绝面按代表例共享分支，§9.21 口径；无 TP 变体的行无 T3 立项）。零遗漏：每个 Message Type 均有覆盖去向或立项结论。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **22 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | 空载荷（Length=8） | 覆（`someip_req_empty`） |
| 2 | 非空载荷 4B | 覆（`someip_req_resp`） |
| 3 | 二进制载荷（含 0x00/0xFF 面） | 覆（`someip_multi_session` payload [1..8]） |
| 4 | 大载荷 2560B（跨 TP 段） | 覆（`someip_tp_segments`） |
| 5 | `service_id=0` | 覆（N-1） |
| 6 | `service_id` 正常 0x1234 | 覆（全正例） |
| 7 | `method_id` 方法（bit15=0） | 覆（S1/S7 0x0001/0x0002） |
| 8 | `method_id` 事件（bit15=1） | 覆（S7 0x8001） |
| 9 | `session_start/inc` 递增 | 覆（`someip_multi_session`） |
| 10 | `session_inc=0` | 覆（N-2） |
| 11 | `session_start=0` | A′ 立项 |
| 12 | `message_type` 字符串枚举 | 覆（request/request_no_return/event/error） |
| 13 | `message_type` 非法 int | 覆（N-3） |
| 14 | `return_code` 0x00/0x01 | 覆（S1/S4） |
| 15 | `return_code` 0x02-0x0A 与 0x20-0xFF | A′ 立项（G-SOMEIP-6） |
| 16 | `direction` 缺省（=up） | 覆（全正例） |
| 17 | `direction=down` | 覆（S4/S7 事件） |
| 18 | `auto_response` 缺省 true | 覆（S1） |
| 19 | SD entry 0x00/0x01/0x06/0x07 | 覆（S5/S6） |
| 20 | SD Option IPv4 / IPv6 / Multicast | 覆 2 / A′ 1（Multicast，G-SOMEIP-4） |
| 21 | IPv4 / IPv6 载体 | 覆（S1 / S9） |
| 22 | UDP / TCP 载体 | 覆（S1 / S10） |

**重数**：覆 19 + 立项 3 = 22 行，零不适用。✓（#20 一行含两覆一立项，#15 一行含两覆多立项——行粒度计 1，内部值去向已在落点列逐值写明）

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | ECU 方法调用（RPC） | S1 `someip_req_resp` | 已覆 |
| 2 | 事件订阅后收通知 | S6 + S7 | 已覆 |
| 3 | 服务上下线发现 | S5 `someip_sd_find_offer` | 已覆 |
| 4 | 大载荷方法调用（TP） | S8 `someip_tp_segments` | 已覆 |
| 5 | 多会话并发调用 | S2 `someip_multi_session` | 已覆 |
| 6 | 业务错误返回 | S4 `someip_error` | 已覆 |
| 7 | IPv6 车载网段 | S9/S9b | 已覆 |
| 8 | TCP 可靠大调用 | S10 `someip_tcp_swap` | 已覆 |
| 9 | 服务优雅下线（StopOffer，TTL=0） | — | **A′ 立项**（SD entry TTL=0 变体，G-SOMEIP-7） |
| 10 | 事件组退订（StopSubscribeEventgroup） | — | **A′ 立项**（G-SOMEIP-7） |

8 覆 + 2 立项 = 10。✓无映射无确认即缺口——本表零缺口（立项已登记去向）。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：①规范原文（AUTOSAR SOME/IP PRS，定"必须是什么"：16B 头字段域、Message Type/Return Code 编码、SD entry/option、TP 分段）；②商业化软件实际行为（Vector CANoe / vSomeIP 等实现：SD 报文按显式单播发送、Option type wire 值与 tshark 枚举一致——本仓库以 tshark 3.6.14 实测为准）；③可靠开源实现思路（本仓库同族先例：radius 的 request/response 双向交换、enip/doip 的"终结层 + flat 键直传 + Validate 负向"，只借鉴思路）。三路一致点：16B 大端头 + Length 自 Request ID 起 + SD 固定 0xFFFF/0x8100；不一致点 = Option type 的"逻辑枚举 vs wire 值"（取舍：以 tshark 解析器实测 wire 值为准，代码 `configToWireOptionType` 换算，本版 §3.4.2 明记）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `someip` 终结层（本版；radius/enip 同构先例） | 消息类型/会话/SD/TP 四事可声明可断言；代价 = 一套层（已落码 1509 行） | **采用** |
| B | 直接 udp 层 + 顶层 payload（旧稿 §1.5 反对意见） | 无头字段/无 SessionID 配对/无 SD/TP → 12 正例中 10 例不可表达 | **否决** |
| C | 与 doip 合并为"车载族" | doip 是 TCP 诊断协议（0x02 头 + 诊断载荷），SOME/IP 是 UDP 优先 SOA 中间件——文法不兼容，合并即错 | **否决** |

## 11. P2 D-SOMEIP-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 状态说明：实现已落码（`internal/protocol/someip/` 四文件），本 P2 条目为 P-PIPE 文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口；P4 在本协议内为"缺口收敛"（§14），不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（§759-775 + §1349-1383） | `SOMEIPConfig` + `SOMEIPSDConfig`/`SOMEIPOption`/`SOMEIPTPConfig`/`SOMEIPEvent` + `FlowSpec.SOMEIP` 槽位 | —（共享文件） |
| `trafficgen/internal/protocol/someip/planner.go` | `Planner.Validate`（**10 种**拒绝，§7 表）+ `Plan`（逐条 emit + auto_response 补包 + TP 分段） | 344 |
| `trafficgen/internal/protocol/someip/builder.go` | 16B 头 + SD Entry/Option + TP 头逐字节拼接（大端）；逻辑枚举→wire 换算 | 317 |
| `trafficgen/internal/protocol/someip/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator("someip")` + validator 注册，`init()`） | 295 |
| `trafficgen/internal/protocol/someip/someip_test.go` | 单测（头字段 / Length 口径 / SD entry+option 布局 / TP 分段） | 553 |
| 接线 5 件 | registry 注册（`layers/registry.go:763`）/ translate Meta 直传（`layers/chain_planner_translate.go:120`）/ convert 子配置搬运（`strategy_convert.go:1700`）/ protocols 准入（`protocols.go:56`）/ 缺省端口（`layers/chain_planner.go:1287`） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`planner.go:16`）：`SOMEIP==nil` 通过（空配置默认流）；ServiceID=0 / session 非法 / message_type 非枚举 / protocol_version≠1 / TP segment_size 边界 / events 内 message_type 各归一分支，错误文案与 §7 表逐字一致。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`planner.go:79`）：先 Validate；`DstPort==0` 补 30490；按 `message_type`/`events[]` 逐条 emit；`auto_response` 时补 down RESPONSE（`planner.go:200`）。
- 生成器：`Name() "someip"`（`layer_gen.go:13`）；`GenEvents()` 事件生成器；`Generate` 逐消息校验 + emit；注册在 `layer_gen.go:294`（`RegisterLayerGenerator("someip", ...)`）。
- builder：`configToWireOptionType`（逻辑枚举→wire，`builder.go:51`）、`buildOptionBytes`（IPv4/IPv6 两分支 + default 拒绝，`builder.go:262`）、TP 头拼接。

### 11.3 数据结构

`SOMEIPConfig{ServiceID, MethodID, ClientID, SessionStart, SessionInc, ProtocolVersion, InterfaceVersion, MessageType, ReturnCode, AutoResponse *bool, Direction, Payload, SD, TP, Events}`（`types.go:759-775`）；`SOMEIPSDConfig{Type, ServiceID, InstanceID, MajorVersion, MinorVersion, TTL, EventgroupID, Counter, Options}`；`SOMEIPOption{Type, IP, Port, Proto}`；`SOMEIPTPConfig{Enabled, SegmentSize, PayloadLength}`；`SOMEIPEvent{MethodID, MessageType, ReturnCode, Direction, Payload}`。

### 11.4 主流程

配置 → validator（头字段 6 分支 + TP 2 分支）→ planner（消息逐条展开，auto_response 补响应，SD/TP 子结构组装）→ worker（UDP 单包 / TCP 段）→ writer（PCAP/NIC）。

### 11.5 错误分支

10 种 validator 拒绝（§7 表全量枚举：入例 4 + 立项 6）；全部传 task error（零假成功——N 系列守卫）。builder 层另有 3 条拒绝（`invalid IPv4/IPv6 option address` `:267/:282`、`unsupported sd option type` `:294`）。

### 11.6 性能边界

见 §6（逐消息流式、per-flow 局部状态、无跨流共享、无锁；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- `CheckProtoFlat`（`strategy_convert.go:8625` 起）**无 someip 分支**（`grep -c` = 0 实测）：顶层 `someip` 子映射 presence 不判死——与 moxa/ntlm 同款缺口 G-SOMEIP-2（禁加单协议黑名单分支，等框架级 unknown-key 白名单）。
- registry `someip` Fields 为空（生成表 `fields: {}` 实测）→ 层内业务键无处可住，目标形状（§2）需 P4 补 Fields + translate 分支（G-SOMEIP-1）。
- 动态 allowlist（`internal/core/layer_dyn.go` 头部）：`someip` 零命中实测 → 业务字段动态对象即拒；四元组 `ip`/`udp`/`tcp` 全开。见 §12.12。
- `strategy_convert.go:1700` 的 flat 分支是 out-of-band 兜底（注释「配置住层内」），但层内 Fields 空——今日两条路径互相不接，P4 由 G-SOMEIP-1 收口。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 4 文件 + 接线 5 处（registry/protocols/translate/convert/chain_planner）；不触及其他协议。cases 回滚 = 恢复 16 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 16/16 顶层 = `layers + src_ip/dst_ip/src_port/dst_port + someip`（旧扁平残留，P4 迁移 G-SOMEIP-1）；目标形状见 §2 样例；presence 判死形状缺口 G-SOMEIP-2 | §12.1；`cases/someip.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 someip 流量模板，自带 `flow_control`；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（终结层）/时间线。UDP 无长连接，TCP 载体有握手 | §12.3 + §5 |
| §4 查规范 | AUTOSAR PRS + 旧基线 + tshark 3.6.14 字段实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["udp"]` + `TransportOn ["udp","tcp"]`（`registry.go:763`）；**10 种**拒绝分支（§7 表）；失败传 task error | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待 P4 基准，不写承诺） | §6 |
| §7 三份文档 | `100-someip-{design,testcase}.md` v1.0.0（草稿层）+ D-SOMEIP-1（§11，门1 获批 = 定稿）+ T-SOMEIP（testcase §2，16 ID）+ 旧稿 28-* 为历史层 | 修订记录 |
| §8 设计先行 | P1–P3 先于 P4 缺口收敛；门1 获批 = D-SOMEIP-1 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = AUTOSAR PRS（§10）+ D-SOMEIP-1（§11）+ tshark 字段实测（替代"已确认现网行为"档，未到抓包级 → G-SOMEIP-8，不冒充第三源）；16 ID 逐项回指；存量 16 例审计去向 testcase §8 | `100-someip-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审 + 收官隔离复审；红先绿后 | 审计日志 §E |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `someip` 已在 `registry.go:763` 注册（**不新增层**）；`allowedProtocols["someip"]=true`（`protocols.go:56`）；Meta 已直传（`chain_planner_translate.go:120`）；**P4 补 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `someip.*`/`someipsd.*` 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/someip/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-28）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 纯净 |
|---|---|---|---|---|
| `cases/someip.json` | 16 | `{layers, src_ip, dst_ip, src_port, dst_port, someip}` ×16（无 `count`、无 `strategy_fc`/`flow_control`） | `[udp,someip]` ×15 + `[tcp,someip]` ×1（S10） | 4/4 = `{expect_error, error_contains, notes}`（含 notes，见 G-SOMEIP-7） |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` | **16** | 迁 `layers[i].ip.src`（G-SOMEIP-1） |
| `dst_ip` | **16** | 迁 `layers[i].ip.dst` |
| `src_port` | **16** | 迁 `layers[i].udp.src_port`（S10 迁 `tcp.src_port`） |
| `dst_port` | **16** | 迁 `layers[i].udp.dst_port`；**或删**（由 30490 缺省补齐，A′ 验证） |
| `count` | **0** | 本已 absent（数量走 `flow_control`，存量未用） |
| 顶层 `someip` 子映射 | **16** | **迁 `layers[i].someip`**（须先补 registry `Fields`，G-SOMEIP-1） |
| `layers[i].someip` 空壳 | **16** | 今日恒 `{}`（Fields 空，既不校验也不消费）——迁移后承载真实业务键 |

**结论**：本协议有实质迁移工作量——§1 门的动作 = ①补 registry `Fields`（service_id/method_id/client_id/session_start/session_inc/protocol_version/interface_version/message_type/return_code/auto_response/direction/payload/sd/tp/events）；②加 translate 分支（层内 someip→`spec.SOMEIP`）；③16 例整体改写；④新增 A′ 例全部纯 layers 形；⑤收官自查行「非负例顶层键 = 0」由 **6 键 → 0**。

目标形状样例见 §2（顶层仅 `layers`+`flow_control`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"someip":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 someip 分支，`grep -c` = 0 实测）→ **P4 不建该负例**（建了会真绿 = 假通过）→ 缺口 G-SOMEIP-2 登记。② 白名单外游离键判死（`unknown field`）P4 建一条（A′）。③ 4 负例每条带锚词（已齐，§7）。④ 收官自查「非负例顶层键 = 0」（P4 迁移后执行）。

### 12.3 §3 强制展开：五件套

**会话表**：本协议 UDP 侧**无会话结构**（无连接、无 `sessions[]`）；TCP 侧（S10）单连接，握手/FIN 由 tcp 层补。多"会话"语义 = 策略级 `flow_control {"flows": N}`（worker 保底递增 `src_port` 12345+i）。存量 16 例全为单 flow。

**事务序列**：`t1` 方法调用（REQUEST → auto_response RESPONSE）/ `t2` 无返回调用（REQUEST_NO_RETURN，单事务）/ `t3` 事件（NOTIFICATION，单向）/ `t4` 错误返回（REQUEST → ERROR）/ `t5` SD 发现（FindService → OfferService）/ `t6` SD 订阅（SubscribeEventgroup → Ack）/ `t7` TP 分段（首段 + 续段，同一消息）。每事务四件事（前置/触发/成功/失败）：前置 = 载体就绪（UDP 无状态 / TCP ESTABLISHED）；触发 = 配置一条消息或 `events[]` 元素；成功 = 下一事务（或会话结束）；失败 = 校验期拒绝（§7）或运行期任务失败。

**关联关系**：**无派生流**（诚实声明）——SOME/IP 无"控制连接派生数据连接"结构；SD 与业务消息各自独立、无 `driven_by`。**本实现不做 entry→option 的 index 引用**：`entry[1]`(Index1)/`entry[2]`(Index2) 代码恒 0，仅 `entry[3]` 高 4bit 写 NumOpts 计数（`setOpts`，`builder.go:251`）；Option 按配置顺序紧跟在 4B Options Length 之后。故 entry↔option 是**位置相邻**关系而非报文内索引引用。

**插入位置**：终结层（`[ip,udp,someip]` / `[ip,tcp,someip]`，无中间层）。

**时间线**：消息内严格顺序（`events[]` 按序回放）；多方法多事件按配置顺序（S7 五包定序）；TP 分段严格递增（S8 段 0→段 1）；多流顺序展开（跨流不假设全局包序，只断言聚合）；无交错（`concurrent` 为例外路径不启用）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst`、`udp.src_port/dst_port`、`tcp.src_port/dst_port` 五策略全开（allowlist `internal/core/layer_dyn.go` 头部四行实测：`ip`/`tcp`/`udp`/`eth`；保底 `DefaultSrcPort+i`（`strategy_convert.go:49`）；dst 动态与 30490 缺省和平共处——显式/动态值非零即不触发补齐）。

**业务字段全关**（allowlist 无 `someip` 行，`grep` 零命中实测；对象即拒）：`service_id`（服务身份）/ `method_id`（方法身份）/ `client_id`（客户端身份）/ `session_start`·`session_inc`（会话号算法）/ `message_type`·`return_code`（消息语义）/ `payload`（载荷，数组非标量）/ `sd`·`tp`（结构化子配置）/ `events[]`（消息序列）——逐流变体需求列 A′ 候选（testcase §6.2；今日按 §9.36 口径不冒充覆盖）。**理由**：SOME/IP 业务字段是"服务身份 + 会话配对"语义，逐流变会破坏 REQUEST/RESPONSE 配对与 SD 发现语义；逐流变化需求集中在四元组（已全开）。

序号算法实读：`parseLayerDyn`（`layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go` 头部）——**`someip` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。

## 13. P3 对接清单（T-SOMEIP 草稿输入；正文落 testcase 文件）

16 ID（12 正 + 4 负）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。A′ 候选（**均为未来 ID，不在当前 JSON ID 集合内**，§7 JSON ID 集合纪律）：`someip_tp_noret`（TP 0x21）/ `someip_tp_event`（TP 0x22）/ `someip_tp_response`（TP 0xA0）/ `someip_rc_unknown_service`（RC 0x02 代表例）/ `someip_sd_multicast`（Option wire 0x14）/ `someip_session_start_zero` / `someip_default_port`（删键断言补齐）/ `someip_neg_version`（V4 锚词）/ `someip_sd_stop_offer`（TTL=0）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-SOMEIP-1 | registry `someip` Fields 为空 + 无 translate 层内分支 → 顶层 `someip` 子映射迁层内 + 16 例改写 + schemagen 重跑 | P4 首动作；收官「非负例顶层键=0」 |
| G-SOMEIP-2 | `CheckProtoFlat` 无 someip 分支 → presence 形今日不判死 | P4 先实测再建例；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单） |
| G-SOMEIP-3 | 业务字段动态全关（allowlist 无 `someip` 行） | A′ 候选，不冒充已覆盖（§9.36 口径） |
| G-SOMEIP-4 | SD Option 仅 IPv4/IPv6 Endpoint 实现；IPv4 Multicast（wire 0x14）无例，SD Endpoint(0x04)/Configuration(0x0C) 未实现 | Multicast A′ 补例；后两者**明确不解决**（builder default 拒绝） |
| G-SOMEIP-5 | TP 变体 0x21/0x22/0xA0/0xA1 无例；`segment_size` 精确边界无例 | A′ 补例（先跑后钉段数） |
| G-SOMEIP-6 | Return Code 0x02-0x0A（9 值）与 0x20-0xFF 无例 | A′ 按分支代表例补（§9.21） |
| G-SOMEIP-7 | 负例 expect 含 `notes` 键（非严格两键）；SD Flags 三标志键（reboot/unicast/exp_init_events）28 稿列出但未落码；StopOffer/StopSubscribe 无例 | P4 收窄 expect 键；flags 键补代码或删声明；停止类 A′ 补例 |
| G-SOMEIP-8 | AUTOSAR PRS 规范条款号未逐条核对（本版以 tshark 字段实测 + 代码为权威）；"已确认现网行为"档未达抓包级 | 待确认：查 AUTOSAR PRS 对应章节，或抓现网 ECU 包（三选一已写清）；确认前不写死条款号 |
| G-SOMEIP-9 | `tp.payload_length` 是**死配置**（`grep -rc PayloadLength` 在 planner/builder/layer_gen = 0/0/0；代码只用 `len(cfg.Payload)` + `SegmentSize`） | P4 裁定：补消费或删键；**断言 `reassembled.length=2560` 实际来自 `len(payload)`，非该字段**（§3.5 已注明） |
| G-SOMEIP-10 | `sd.type="subscribe_ack"` 独立配置无例（`sdTypeFromString` 支持，存量只走 subscribe 自动派生） | A′ 补例（独立 Ack 报文） |
| G-SOMEIP-11 | 6 条未入例的 planner 拒绝分支（`protocol_version`/`segment_size<8`/`sd.type`/`events[i].message_type`/`src IP`/`dst IP`，§7 表）+ builder 3 条 | A′ 逐分支补负例（§9.47 错误码全表枚举） |
| G-SOMEIP-12 | **结果文档过期**：`trafficgen/docs/protocol-pcap-test/someip.md` 写 "Cases: 16 — pass 16, fail 0, error 0"，末次提交 `3c5991a`（2026-08-28）**早于判死提交 `0417be5`（2026-09-13）**；`cases/someip.json` 末改同为 `3c5991a`；`docs/protocol-pcap-test/someip/` **0 个 pcap**；**今日 16/16 例经 MCP 建策略 400 全红**（顶层旧键 60 处残留、非负例 12/12 全违规形） | **代码阶段（P5）**：套件重跑后**重生成**结果文档；在此之前读者不得据此判断套件可跑（§0 产物过期登记） |

## 15. 修订记录

- v1.0.2（2026-09-28，小补登记）：新增 **G-SOMEIP-12 结果文档过期**（§0 产物过期登记 + §14 缺口行）——`docs/protocol-pcap-test/someip.md` 写 16/16 pass，末次提交 `3c5991a`（2026-08-28）早于判死提交 `0417be5`（2026-09-13）；`docs/protocol-pcap-test/someip/` **0 个 pcap**；今日 16/16 例经 MCP 建策略 **400 全红**（顶层旧键 60 处残留、非负例 12/12 全违规形）。归属**代码阶段（P5 重跑套件后重生成该产物）**。口径与 pcep 车道 G-PCEP-11 一致。附复算命令与原始输出。
- v1.0.1（2026-09-28，隔离审查 B-1/B-2/B-3 + D 类修轮）：**B-1** §3.4.1 SD Entry 偏移表按代码/探针重写（ServiceID@4-5、InstanceID@6-7、Major@8、TTL@9-11、Minor@12-15；`entry[1]`/`entry[2]` 是 tshark `index1`/`index2` 独立字节，NumOpts 合并于 `entry[3]` 高/低 4bit）——初稿照抄 28 稿、偏移整体错位 1 字节（§0 第 12 行登记）；补 4B Options Length 字段与 Eventgroup 变体布局（counter@[13] 低 4bit、eventgroupID@[14:16]）；§12.3 关联表述改为"位置相邻、不做 index 引用"。**B-2** §3.5 TP 头由 8B 改 **4B**（低 28bit=offset 16 对齐、bit0=more），并声明**后续段重复完整 16B 头**（`planner.go:247`）——初稿照抄 28 稿、头长与后续段结构全错（§0 第 13 行登记）；§6 性能节 TP 头同步改 4B。**B-3** §7 补 planner 拒绝分支**全表 10 条**（入例 4 + A′ 立项 6，原写"7 种"漏 3 条：`sd.type`/`src IP`/`dst IP`）；§10.1 #5、§11.1、§11.5、§12 计数同步 10；补 `subscribe_ack` 独立配置写法。**D 类**：§10.1 #4 补 `tp.payload_length` 死配置缺口；§8 补"引擎不强制 16 对齐"事实；新增 G-SOMEIP-9/10/11。**每条附复算命令与原始输出**（§3.4.1/§3.5 探针段）。自审见审计日志 §E。
- v1.0.0（2026-09-28）：P-PIPE #100 文档轨 P1–P3。28→100 沿革与 11 项校正（§0）；存量 16 例机读审计（顶层残留形状、expect 形状、ID 顺序一致）；§12.1/12.3/12.12 强制展开 + 12-P2；D-SOMEIP-1 as-built 定稿（§11）；缺口 G-SOMEIP-1…G-SOMEIP-8；**承 28-someip-design 审计通过的线格式与场景结论**，冲突处按代码/JSON 事实改正（TP 2560/1408、Option wire 0x04、S5 hexdump、V5 锚词、ipv6.nxt）。自审见审计日志 §E。

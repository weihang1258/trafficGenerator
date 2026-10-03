# #98 pcep（路径计算元素通信协议，Path Computation Element communication Protocol）设计契约

> 版本：v1.0.1（P-PIPE 文档轨 P1–P3 + 隔离审查修轮；修订记录见 §16）
> 日期：2026-09-28
> 车道：文档轨（#98 pcep 续号审计）
> 旧基线：`docs/protocol-designs/42-pcep-design.md` v1.0.0 + `42-pcep-testcase.md` v1.0.0（24 例 = 17 正 + 7 负；本 #98 为按当前层链架构标准的审计续号，思路继承、不搬码——旧稿"层尚未实现/未注册"状态已过时，见 §0）
> 存量用例：`trafficgen/test/protocol_pcap/cases/pcep.json`（24/24 ID 与旧稿一致、顺序一致，已机读实测；**合规判定 = 非负例顶层键 84 处残留 / 17 例全违规**；**存量 24 例今日 create 400 全红**（五键在），去五键即可用；结果文档 `docs/protocol-pcap-test/pcep.md` 为过期产物——详见 §0）
> 规范基线：① RFC 5440（PCEP，TCP 4189）；② RFC 8231（stateful PCE，有状态 PCE）；③ RFC 8281（PCE-initiated LSP/delegation，PCE 发起 LSP/委托）；④ 本仓库落码（`internal/protocol/pcep/` 三文件，§11.1，as-built 逆向定稿）；⑤ 本机 tshark 3.6.14 实测（`pcep.*` 已注册 379 字段）
> 白话一句：**PCEP 是路由器之间"问路"的对话协议——一台机器问"到某目的地怎么走"，另一台算完把路径写回来；引擎里它是一层薄皮，只把配置好的每条消息按序翻译成 TCP 载荷，握手分段挥手全交给 TCP 层。**

## 0. 42→98 沿革与旧稿过期声明校正（门1 必答：基线继承关系）

本 #98 与旧稿 `42-pcep-*` 是**同一协议的续号契约**，不是新协议。旧稿保留在磁盘只读参考，本契约逐条校正旧稿已过时的状态声明、与实现的矛盾处，以及**违规过渡形**（下表行 2 为审计主结论的实证面）（全部为可判题：旧文→代码→用例三级对照，直接判定不问偏好）：

| # | 旧稿说法（42-*） | HEAD 实测（2026-09-28） | 校正结论 |
|---|---|---|---|
| 1 | "`pcep` 层尚未实现""不宣称 `pcep` 层已注册"（design 头注 / testcase 头注） | `registry.go:1391` 已注册 `LayerSchema{Name:"pcep", Category:CategoryTerminal, DependsOn:["tcp"]}`；`internal/protocol/pcep/` 三文件 2077 行（`builder.go` 792 / `planner.go` 151 / `pcep_test.go` 1134，`wc -l` 实测），50 个 `Test*` 函数（`grep -c` 实测）；`allowedProtocols["pcep"]=true`（`protocols.go:50`） | "尚未实现/未注册"已过时；本契约 §11 为 as-built 逆向定稿 |
| 2 | 旧稿 design §2 推荐层链样例 = **顶层扁平形**（`layers` + 顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port` + 顶层 `pcep` 子映射） | 存量 24/24 例 `spec_json` 顶层键 = `{layers, src_ip, dst_ip, src_port, dst_port, pcep}`（机读实测：`src_ip`×24 / `dst_ip`×24 / `dst_port`×24 / `src_port`×23 / `pcep`×24）；`layers` 内 `[{tcp:{}},{pcep:{}}]` 两键**恒空壳**（机读：非空层配置 0/24） | 旧样例形 = **过渡态违规形**（CORE_MEMORY §1.4/§1.11），代码阶段按 §12.1 收敛；本契约 §2 样例只给纯层链形 |
| 3 | 旧稿 design §7 负例表把 7 类故障描述为"错误注入"，锚词 `length`/`type`/`object`/`keepalive`/`session`/`address`/`stateful` | 机读实测：7 例中 **6 例不含 `wire_fault`**，走自然非法配置（`kind:"unknown"` / `objects:[{class:"rp",object_length:3}]` / keepalive 带 objects / `sid:0` / IPv4 profile 携 IPv6 / base profile 携 lsp+srp）；仅 `pcep_neg_malformed_length` 用 `wire_fault:{kind:"length"}` | 锚词作为**子串** 7/7 命中真实文案（见 §7 表）；但"错误注入"定性只对 1/7 成立，其余 6 例是配置拒绝面——§7 表逐行改写 |
| 4 | 旧稿 design §1 不变式 5："`session_id`… 若显式写在线上，必须在同一会话内一致" | `builder.go:691-693` 注释与代码明写 **SID 漂移不是错误**（"Both sides need not match (positive case uses 7/8), so drift alone is not an error — a zero SID is"）；RFC 5440 §7.3：SID 由发送方各自分配 | **旧稿不变式与实现/RFC 矛盾**，以 RFC + 实现为准（§4.1/§7）；旧稿 `pcep_neg_session_id` 描述"两个 Open SID 不一致"在实现下**不会红**，实际注入的是 `sid:0` |
| 5 | 旧稿 design §3.1 / testcase §1 钉 Open 固定样本 `20 01 00 10` | `builder.go:150-193` 无 capability 时 body 4B → object 8B → message length **12**；存量 JSON `frames` 实测 `20 01 00 0c`，`fields` 实测 `pcep.msg_length=12` | 旧稿常量 **0x10=16 错**（无 capability 的 Open 为 12）；本契约 §3.1 校正 |
| 6 | 旧稿 design §8 表行 15 `pcep_delegation_rfc8281_profile` = 3 events / 10 packets | 存量 JSON 实测 = **5 events / 12 packets**（2 Open + delegate/remove/create 三条 pcreq）；旧稿 testcase §3.3（`:76` bullet）与 design §8 表行 15 均写"三种 flags 事件"，实现单测 `pcep_test.go:199` 同款 delegate/create/administrative | 旧稿表行 **漏计两条 Open**（"3"= 三个 flags 事件）；JSON 5/12 正确，本契约 §9 校正 |
| 7 | 旧稿 testcase §3.2 `pcep_rro_ipv4_ipv6`："分别在 IPv4 与 IPv6 profile 的显式路径对象中使用对应 RRO subobject" | 存量 JSON 实测：单例、单 profile（`pcep_rfc5440_ipv4`），断言 `pcep.subobj.ipv4.ipv4`/`.l`/`pcep.obj.rro.type`/`pcep.subobj.flags.lpu`，**无 IPv6 半边** | 旧稿描述与用例不符；IPv6 RRO 属地址族对称缺口 G-PCEP-7 |
| 8 | 旧稿 design §8 行 1 覆盖列写"Open、Keepalive、SID、common length"、testcase §3.1 写"双向 Open" | JSON 实测 #1 = open c2s(sid7) + open s2c(sid8) + keepalive c2s，3 events / 10 packets | 两处口径一致，**无需校正**（指旧稿两处描述互不矛盾，**非合规声明**——该例顶层键仍违规） |
| 9 | 旧稿 testcase §3.3（`:78` bullet）`pcep_common_header_length` 写"Open、Keepalive、PCReq、PCRep 四个消息"（§2 索引行 16 同） | JSON 实测事件序列 = open c2s / open s2c / pcreq c2s / pcrep s2c（**无 keepalive 事件**），4 events / 11 packets | 旧稿覆盖列 **多列 Keepalive**；本契约 §9/§3.16 按实际事件序列校正（Keepalive 头部面由 #1/#3 覆盖） |
| 10 | 旧稿 testcase §3.1（`:59` bullet）`pcep_tcp_direction` 写"c2s PCReq/PCNtf 与 s2c PCRep/PCErr"（§2 索引行 12 同） | JSON 实测事件序列 = open c2s / open s2c / pcreq c2s / pcrep s2c / pcntf c2s（**无 PCErr**），5 events / 12 packets | 旧稿覆盖列 **PCErr 方向写错**（PCErr 是 s2c 且由 #6 承载）；本契约 §3.12 校正 |

**审计主结论（合规判据 = 非负例顶层键必须为 0）**：按白名单（`layers`/`strategy_fc`/`ttl`/`flow_control`/`output`/`output_config`/`group_id`）机读，**pcep 现状 = 违规过渡形，无一条合规**：

| 口径 | 实测 |
|---|---|
| 非负例（17 例）顶层越白名单键 | `src_ip`×17、`dst_ip`×17、`dst_port`×17、`src_port`×16、顶层 `pcep` 子映射×17 = **84 处残留，17/17 例全违规** |
| 全 24 例同口径 | **119 处残留，24/24 例全违规**（含 7 负例同样残留） |
| `layers` 内配置 | **恒空壳 0/24**（`[{tcp:{}},{pcep:{}}]` 两键皆 `{}`） |
| 层内配置是否被解码 | **否**——`registry.go:1391` 无 `Fields`；`translateTerminalConfig`（`chain_planner_translate.go:695`）**无 `case "pcep"`**，`:753-755` 只做 `spec.PCEP = &core.PCEPConfig{}` 空结构体赋值 |

**定性（现状可用性，实调）**：顶层 `pcep` 子映射 + 顶层四元组与 `layers` 并存 = **判死形状**（CORE_MEMORY §1.4/§1.11/§1.13），且**存量 24 例今日全部不可创建**——`core.CheckProtoFlat`（`strategy_convert.go:8632` 五键循环）在 create 门（`schema/semantic.go:130`）无条件执行，pcep **无**顶层子映射分支，故五键在即 400。**"合规层链形今日跑不通"成立**（`registry.go:1391` 无 `Fields`），但**"顶层五键形是唯一可用"不成立**：去掉五键即可用（四形实测见下）。

**四形实测表（本车道实调 `schema.ValidateStrategy`，命令见 §15 复算证据；禁止照抄）**：

| 形状 | create | 说明 |
|---|---|---|
| 存量：`layers` 空壳 + 五键 + 顶层 `pcep` | ❌ **400 ×24/24** | `protocol pcep rejects flat config field src_ip …`（`:8632`） |
| `layers` 空壳 + 顶层 `pcep`（**去五键**） | ✅ 24/24 可用 | `spec.PCEP` 已填、可出包（引擎路径 `MapToFlowSpec` `ValidationErrors` 空） |
| 仅顶层 `pcep`（无 `layers`） | ✅ 24/24 可用 | 同上 |
| 纯层链 `[ip,tcp,pcep]` 带 `events` | ❌ 0/24 | `layers: layer "pcep": unknown field "events"`（`complete.go:291-293`） |

**收敛路径（两条，取舍并列）**：①**低成本先解封**——存量 24 例**只删五键**（保留 `layers` 空壳 + 顶层 `pcep`），当日即可创建并跑出包；代价是仍非合规形（顶层 `pcep` 子映射残留），门1 §1 栏仍红。②**合规收敛**——代码阶段补三件事：`registry.go` 补 `pcep` 的 `Fields`（`profile`/`events`/`sessions`）；`translateTerminalConfig`（`chain_planner_translate.go:695`）补 `case "pcep"` 层内严格解码；`mapToFlowSpec`（`strategy_convert.go:331`，pcep 分支 `:1738-1740`）从子配置搬运收敛为层链驱动。**两条不互斥**：①可先恢复套件可跑性，②是门1 转绿的唯一路径。**文档阶段两件都改不动**（不动代码、不动 JSON），故 98 稿只如实登记。

**产物过期登记（重要）**：`trafficgen/docs/protocol-pcap-test/pcep.md` 写 "Cases: 24 — pass 24"，但该文件末次提交 `e60f8de`（2026-08-30），**早于**判死提交 `0417be5`（2026-09-13）两周；`cases/pcep.json` 末改 `07a5472`（2026-08-30）同日；`docs/protocol-pcap-test/pcep/` 目录 **0 个 pcap 文件**。**该结果文档是过期产物，24/24 pass 不代表今日可跑**——读者不得据此判断套件可用。

**依赖链判定纪律**：以上均为可判题，直接判定；不可判的（现网 PCE 实现的私有扩展行为）标"待确认"并写清确认方式（§14 G-PCEP-6）。

## 1. 范围、profile 边界与证据等级

本版定义 RFC 5440 的 PCEP 基础会话：TCP destination port（目的端口）4189、Open、Keepalive、PCReq、PCRep、PCNtf 和 PCErr；覆盖 IPv4 与 IPv6 endpoint（端点）地址族、PCEP common header（公共头）、message length（消息长度）、object header（对象头）、request/session 关联、LSP/ERO/RRO/Metric 和对象 flags（标志）。每个显式 PCEP event（事件）对应一个 TCP application payload（应用载荷）；planner（规划器）不自动补 Open、Keepalive、响应、重试或 teardown（拆除）之外的消息。

| profile | 规范范围 | 允许内容 | 明确不从本版推导 |
|---|---|---|---|
| `pcep_rfc5440_ipv4` | RFC 5440 IPv4 RSVP-TE endpoint | Open、Keepalive、PCReq、PCRep、PCNtf、PCErr；IPv4 END-POINT、ERO/RRO、Metric | 真实 CSPF、RSVP 状态、路由计算结果 |
| `pcep_rfc5440_ipv6` | RFC 5440 IPv6 endpoint | 同上；IPv6 END-POINT、IPv6 ERO/RRO subobject | 把 IPv6 地址压缩/改写成 IPv4，或混用地址族 |
| `pcep_rfc8231_stateful` | RFC 8231 stateful extension（有状态扩展） | 仅显式声明的 LSP/SRP/同步语义；必须同时标注 RFC 5440 base session | 自动维护 LSP 数据库、自动同步、隐式 PCUpd/PCInitiate |
| `pcep_rfc8281_delegation` | RFC 8281 delegation/profile（委托档案） | 显式 LSP delegate/remove/create flags 与 SRP；必须在 stateful profile 上声明 | 把 delegate flag 当作 RFC 5440 基础能力，或自动发起 LSP |
| `pcep_unknown_extension` | 未注册扩展 | 不生成 | 未知消息/对象/扩展 TLV 的成功 PCAP |
| `""`（缺省） | 实现接受空 profile（`builder.go:682` `validProfiles` 含 `""`） | 同 RFC 5440 base（无 profile 约束分支） | 把空 profile 当作扩展授权 |

RFC 8231/RFC 8281 只作为显式 profile 边界；基础 `pcep_rfc5440_*` 不接受 LSP/SRP 的 stateful-only 字段。RFC 8281 的 delegation 是 LSP object/SRP flags 的语义，不新增一个虚构的 message type。**PCUpd(10)/PCInitiate(12) 常量已定义但无事件分支（G-PCEP-6），本版不生成、不建正例。**

不变式：

1. PCEP 只能位于 `tcp` 后，TCP destination port 必须为 4189；正例无 UDP/裸 IP 载体。
2. TCP stream（字节流）中的每条 PCEP message 从 common header 开始：Version/Flags、Message-Type、Message Length；Version=1 的 version bit 为 `0x20`，Flags 保留位为零。
3. Message Length 是从 common header 起始到该 PCEP message 末尾的总长度，最小为 4；长度必须与 TCP stream 中实际消息边界一致，不以 Ethernet padding（填充）或 TCP segment length 冒充。
4. 每个 object 的四字节 object header 含 Object-Class、Object-Type/flags 和 Object-Length；Object-Length 至少为 4、必须按 4 字节对齐，并且不得越过 message length。
5. `sid`（Open Session-ID，uint8）由发送方各自分配，**同一会话两个方向的 SID 允许不同**（正例 7/8）；`sid:0` 保留且非法（RFC 5440 §7.3）。旧稿"必须一致"的说法作废（§0 行 4）。
6. request ID、LSP PLSP-ID、SRP-ID 和 endpoint 地址均按事件显式配置；不从前一条请求静默继承。
7. planner/validator（校验器）错误必须传播为 task error（任务错误）终态，不能 completed（完成）但 0 包。

**实现状态（2026-09-28 实测）**：`pcep` 层已注册（`registry.go:1391`，`CategoryTerminal`，`DependsOn ["tcp"]`，**无 `Fields` 表**）；planner/validator/builder 已落码（`internal/protocol/pcep/` 三文件 2077 行）；`allowedProtocols["pcep"]=true`（`protocols.go:50`）；生成器经 `layers.RegisterLayerGenerator("pcep", …)` 注册（`planner.go:149`）；端口缺省 4189（`chain_planner.go:1128`，且列入 `validateBaseDstPortHandled` 白名单 `:751`）；24 语义用例已落 `cases/pcep.json`。旧稿"代码未写"描述已过时（§0 表行 1）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport/srcport`、`pcep.*` 字段、offset 54 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

## 2. 协议栈、端口与固定偏移

推荐层链为 `[ip, tcp, pcep]`（引擎自动补 `ip`；最小链 `[tcp, pcep]`）。pcep 报文是 TCP payload 的**完整应用消息**——消息边界由 PCEP common header 的 Message Length 决定，不由 TCP 段边界决定；超 MSS 消息可跨段，接收端按 TCP 序号重组。

端口：PCEP 监听口 **TCP 4189**（RFC 5440 §5.1；planner 缺省 4189 已落码 `planner.go:28-30`，层链缺省补齐 `chain_planner.go:1128`）。用例一律显式写端口并纳入断言（§1.4 纪律）。

固定偏移：无 VLAN/IP options/TCP options 时，**每条消息首字节起点为 IPv4 offset 54（14+20+20）**。存量 24/24 例 `frames` 实测 offset 全为 **54**（含 `pcep_ipv6_address_family`——该例外层仍是 IPv4 载体，IPv6 只体现在 PCEP endpoint/subobject 语义，见 §4.4）。外层 IPv6 载体的 offset 74 今日零用例（§8 边界）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers` + `flow_control`；**目标形状声明**：registry `pcep` 无 `Fields` 表，层内 `events`/`profile`/`sessions` 键今日无处可住，故此形**今天跑不通，需先补代码** G-PCEP-1，§1.9 口径）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "192.0.2.20"}},
    {"tcp": {"src_port": 40000, "dst_port": 4189}},
    {"pcep": {
      "profile": "pcep_rfc5440_ipv4",
      "events": [
        {"kind": "open", "direction": "c2s", "keepalive": 30, "deadtime": 120, "sid": 7},
        {"kind": "open", "direction": "s2c", "keepalive": 30, "deadtime": 120, "sid": 8},
        {"kind": "keepalive", "direction": "c2s"}
      ]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

多会话样例（目标形，数量只走 `flow_control`，四元组留空走 worker 保底递增 `worker.go:308`）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "192.0.2.20"}},
    {"tcp": {"dst_port": 4189}},
    {"pcep": {
      "profile": "pcep_rfc5440_ipv4",
      "sessions": [
        {"src_port": 40001, "events": [{"kind": "open", "direction": "c2s", "sid": 7}]},
        {"src_port": 40002, "events": [{"kind": "open", "direction": "c2s", "sid": 22}]}
      ]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

## 3. 线格式编码（逐项标注出处）

### 3.1 Common header 与消息类型

PCEP message 的四字节 common header（`builder.go:85-91`）：

```text
byte 0: Version（高 3 bit，mask 0xE0）| Flags（低 5 bit，mask 0x1F）；Version=1 => 0x20
byte 1: Message-Type
byte 2..3: Message Length（network byte order / 大端，含 common header）
```

常量：`pcepVersion=0x20`、`hdrLen=4`、`objHdrLen=4`、`tlvHdrLen=4`、`defaultKA=30`、`defaultDT=120`（`builder.go:16-21`）。

| Type | 名称 | 事件 kind | 本版状态 |
|---:|---|---|---|
| 1 | Open | `open` | 已实现 |
| 2 | Keepalive | `keepalive` | 已实现 |
| 3 | PCErr | `pcerr` | 已实现 |
| 4 | PCNtf | `pcntf` | 已实现 |
| 6 | PCReq | `pcreq` | 已实现 |
| 7 | PCRep | `pcrep` | 已实现 |
| 10 | PCUpd | —（无 kind 分支） | **未实现**（G-PCEP-6） |
| 12 | PCInitiate | —（无 kind 分支） | **未实现**（G-PCEP-6） |

**消息总长度公式**（`builder.go` 实读，可复算）：
- Keepalive：`4`（`BuildKeepAliveMsg` = `buildCommonHeader(2, hdrLen)`）。
- Open（无 capability）：`4 + 4 + 4 = 12`；带 capability TLV：`12 + Σ(4 + len(TLV value))`（每个 stateful/sync TLV value 恒 4B → 每个 +8）。
- 多对象消息（PCReq/PCRep）：`4 + Σ(objHdrLen + pad4(bodyLen))`。
- PCNtf / PCErr：`4 + 4 + 4 = 12`（单对象，body 4B）。

正例无 IPv4 option、无 VLAN，TCP payload 起点固定为 offset 54。`frames` 锚定 common-header 前缀：Open `20 01 00 0c`、Keepalive `20 02 00 04`、PCReq `20 06`、PCRep `20 07`、PCNtf `20 04`、PCErr `20 03`（存量 24 例实测口径；长对象不固化未经 fixture 复核的完整 hex）。

### 3.2 Object header 与长度

Object header 四字节（`buildObjectHeader`，`builder.go:108-130`）：

```text
byte 0: Object-Class
byte 1: Object-Type（高 4 bit，mask 0xF0）| P flag（bit 1，0x02）| I flag（bit 0，0x01）
byte 2..3: Object-Length（大端，含 object header；body 按 4 字节对齐后重算）
```

Object 类（`builder.go:38-48`）：`open=1`、`rp=2`、`endpoint=4`、`metric=6`、`ero=7`、`rro=8`、`lspa=9`、`notif=12`、`error=13`、`lsp=32`、`srp=33`。TLV 类型：`stateful_pce=16`、`sync=17`。

**`objects[].object_length` 语义（实读，重要）**：该键**只参与校验，不落线**。`builder.go:773` 对声明值做 `>= 4 且 4 字节对齐` 校验，随后 `buildObjectHeader` 一律按实际 body 长度重算 Object-Length 写入线上。故它是**负例注入面**而非线格式控制面（G-PCEP-5）。

以下错误必须拒绝：message length 小于 4、声明长度大于 TCP stream 剩余字节、object length 小于 4、object length 非 4 字节对齐、object length 越过 message boundary、未知 class/type 或 object 与 message kind 不匹配。

### 3.3 Checksum/length 证据

PCEP 不在 RFC 5440 common header 中使用独立 checksum；TCP checksum 由 TCP 层负责。不要虚构 `pcep.checksum` 字段或把 TCP checksum 当 PCEP 字段。正例 fields 只使用 `tshark -G fields` 已注册字段（本机 3.6.14 实测 `pcep.*` 共 **379** 个），长度使用 `pcep.msg_length`/`pcep.object_length`；负例只检查错误传播。

### 3.4 业务场景分析（现网典型场景与五层覆盖；需求 §4 要求节，置于 §3 内以保持本文 §4–§15 编号稳定）

**定性**：**声明式剧本回放**——配置是剧本（`events[]` 逐条声明方向与消息内容），引擎按序产出 PCEP 消息，tcp 层按 MSS 分段、补握手/挥手。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① PCC 上线建会话 | 双向 Open 交换（SID 各自分配）+ Keepalive | #1/#2/#3 |
| ② 路径计算请求-响应 | PCReq（RP+END-POINT+ERO+Metric）→ PCRep（RRO+Metric，request_id 关联） | #4/#5 |
| ③ 失败与通知上报 | PCReq → PCErr（error type/value）或 PCNtf | #6 |
| ④ 批量计算 | 同连接多轮 PCReq/PCRep，request_id 隔离 | #7 |
| ⑤ IPv6 域内计算 | IPv6 END-POINT/ERO/RRO 对象 | #8 |
| ⑥ 有状态 PCE 同步 | Open capability TLV 16/17 + LSP/SRP 上报 | #9/#14 |
| ⑦ LSP 委托 | delegate/remove/create 三条独立事件 | #15 |
| ⑧ 多 PCC 并发 | 两条独立 TCP 会话，SID/request_id 隔离 | #13 |

**五层覆盖逐层结论**：
- **功能层**——6 类已实现消息（1/2/3/4/6/7）各有正例（#1–#7），每类至少一条负例面（§7 N-1…N-7）；未实现的 10/12 显式标不适用（G-PCEP-6）。
- **性能层**——最小消息 = Keepalive 4B（#1/#3）；长对象消息 = PCReq/PCRep 多对象（#4/#5/#7）；多会话展开 2×11=22 包（#13）；**跨 MSS 消息分段零用例**（PCEP 消息无长度上界声明，属缺口，§8）。
- **数据场景层**——对象类 11 种、metric type/flags/value、address family、长度边界，逐项见 §10.3（36 行，覆 30 + 缺口 6）。
- **地址与流层**——IPv4 已覆（#4/#5/#10）；IPv6 endpoint 语义已覆（#8）；外层 IPv6 载体缺口（§8）；**流关联（控制流派生数据流）显式不适用**：PCEP 无控制/数据分离，PCReq→PCRep 是同连接内事务关联（`request_id`）不是流关联；**多流（会话内并发流）显式不适用**：多会话语义由 `sessions[]` 承载（#13）。
- **业务层**——场景①–⑧ 全部有落点（上表零空缺）；多会话（#13）、多事务（#3/#7/#15 同连接多轮）各至少一例。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① PCUpd(10)/PCInitiate(12)（常量已定义、无事件分支，G-PCEP-6）；② PCNtf/PCErr 的 type/value **只能**经 `objects[]` 的 `class:"notification"`/`"error"` 提供（唯一输入路径，§4.3）——不得建"该 class 无效"类负例；③ PCEP 层保活定时器（Keepalive 是显式事件，引擎不自动补发，§10.1 第 6 项）；④ PCEP over TLS / 认证（明文协议，TLS 属框架 tls 层能力，本层零断言）。

## 4. RFC 5440 消息与对象语义

### 4.1 Open/Keepalive/session

OPEN object 使用注册字段 `pcep.obj.open.pcep_version`、`pcep.obj.open.flags`、`pcep.obj.open.keepalive`、`pcep.obj.open.deadtime`、`pcep.obj.open.sid`。body 4 字节：`[0]=0x20`（Ver=1<<5 | Flags=0）、`[1]=keepalive`、`[2]=deadtime`、`[3]=sid`（`builder.go:150-156`）。`keepalive`/`deadtime` 为 0 时取缺省 30/120（`builder.go:452-459`）。Open 的 Keepalive/DeadTimer 是会话参数，不代表 planner 自动插入周期性 Keepalive。Keepalive message 不带 object，且必须是 common header 长度 4。

**SID 语义（校正旧稿）**：SID 为 uint8，由发送方各自分配，两方向允许不同（RFC 5440 §7.3；实现 `builder.go:691-693`）；`sid:0` 保留且非法，validator 拒绝（`builder.go:695-698`）。SID 不是从 TCP 端口推导的随机值。

### 4.2 PCReq/PCRep

PCReq 至少含 RP（Request Parameters）、END-POINT、可选 BANDWIDTH、ERO、RRO、Metric、LSPA 等对象；PCRep 以 request ID 关联响应，可含 NO-PATH 或路径对象。字段断言使用已注册的 `pcep.obj.rp.*`、`pcep.request_id`、`pcep.obj.end_point.*`、`pcep.obj.bandwidth`、`pcep.obj.metric.*` 和 `pcep.obj.ero/rro.*`。请求与响应必须按 `request_id` 关联，但未提供成功路径计算器时不宣称 cost/path correctness（路径正确性）。

**自动派生规则（实读 `parseObjects`，`builder.go:505-528`）**：事件级 `endpoint` 非空且 `request_id>0` 且 `objects` 中无 `class:"rp"` 时，生成器**自动补一条 RP 对象**在最前（`BuildRPObject(requestID,false,false)`）；`rp` 对象内 `requested_id_number` 为 0 时回填事件级 `request_id`（`builder.go:536-540`）；`endpoint` 对象 body 为空时回填事件级 `endpoint`（`builder.go:544-562`）。这些补帧规则必须逐条列入用例依据。

ERO/RRO 的 IPv4/IPv6 subobject 必须保留 L（loose，松散）/X/flags/attribute、prefix length 和地址族；IPv4 profile 不得出现 IPv6 subobject，反之亦然。Metric 的 type、flags（Cost/Bound）和 IEEE float metric value 必须独立编码，不把 metric 当作 bandwidth。

### 4.3 PCNtf/PCErr

PCNtf 用 Notification object，使用已注册的 `pcep.obj.notification.type` 和 `.value`；通知不是 PCRep 的隐式响应。PCErr 使用 PCEP-ERROR object，`pcep.error.type`/`pcep.error.value` 表示错误码，`pcep.obj.error.type` 是对象类型字段；两者不应混淆。**输入路径（实读，易错点）**：PCNtf/PCErr 的 type/value **必须**经 `objects:[{class:"notification",type,value}]` / `objects:[{class:"error",type,value}]` 提供——这是唯一路径。`parseNotification`/`parseError`（`builder.go:623-655`）从 `objects[]` 里按 class 取出 type/value 供消息级 `BuildPCNtfMsg`/`BuildPCErrMsg` 使用；`parseObjects`（`:576-581`）随后跳过这两类，是因为值已被消息级消费，**不是"写了不生效"**。错误事件仍是一个正常方向的 PCEP message，只有非法配置才要求 task error。

### 4.4 IPv4/IPv6、multi-request 与 multi-session

IPv4 profile 使用 `pcep.obj.end_point.source_ipv4_address`/`destination_ipv4_address` 及 `pcep.subobj.ipv4.ipv4`；IPv6 profile 使用对应 IPv6 字段和 `pcep.subobj.ipv6.ipv6`。endpoint、ERO、RRO 的地址族必须一致；混用、缺失或将 IPv6 压入 IPv4 object 都是 address-family 错误（`builder.go:779-786` 双向分支）。

**地址族的两层区分（易错点，实读）**：PCEP 的 IPv4/IPv6 是**应用层 endpoint/subobject 语义**，与外层 IP 载体族**独立**。存量 `pcep_ipv6_address_family`（#8）外层仍为 IPv4（`src_ip=192.0.2.10`），IPv6 只体现在 END-POINT/ERO 对象里，`frames` offset 仍是 54。**外层 IPv6 载体（offset 74）今日零用例**（§8 边界）。

`multi_request` 在同一 TCP session 中按显式事件发送多个 PCReq，再发送 request_id 对应的多个 PCRep；每一请求独立携带 endpoint/metric/ERO，不能复用前一个请求对象。`sessions` 是多个独立 TCP 4189 flows，每个 flow 有自己的 `src_port`、SID、Open 和 teardown；会话之间的 SID/request ID 不得串联（`planner.go:109-126` 多会话展开；`src_port` 缺省由 `builder.go:701` 拒绝）。每个 flow 的 packet count（包数）包括 3-way handshake、显式 application messages 和四包 TCP teardown。

**包数公式（实读 `planner.go:66-83`，单流）**：`packet_count = 3（SYN/SYN-ACK/ACK） + N（显式事件数） + 4（FIN 四包）`。多会话（`sessions[]`）= 各会话包数之和（每会话独立 3+N_i+4）。存量 17 正例机读校验 17/17 符合（含 #13 = 2×11 = 22）。

## 5. RFC 8231 stateful 与 RFC 8281 delegation profile

`pcep_rfc8231_stateful` 是显式扩展 profile，基础 Open/Keepalive/PCReq/PCRep/PCErr 仍采用 RFC 5440 common header；LSP object 使用 `pcep.obj.lsp.plsp-id`、`pcep.obj.lsp.flags.*`，SRP object 使用 `pcep.obj.srp.id-number`、`.flags.*`。扩展能力 TLV 的注册字段（`pcep.stateful-pce-capability.*`、`pcep.sync-capability.*`）只有在配置声明 capability 时才出现；`include_db_version=true` 时**同时**发 TLV 16 与 TLV 17（`builder.go:173-180`）。此 profile 不自动维护数据库、同步所有 LSP 或生成 PCUpd/PCInitiate。

`pcep_rfc8281_delegation` 必须声明 stateful capability；delegate/remove/create/administrative/operational flags 只表达显式 LSP/SRP 事件。RFC 8281 不改变 RFC 5440 的 Open/Keepalive 基本格式，也不允许在 base profile 中静默接受 delegate flag——实现对此有专属拒绝分支（`builder.go:757-759`：`lsp`/`srp` 对象在非 stateful profile 下报 `%s object requires stateful profile`）。任何未注册扩展对象仍走负例。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

### 6.1 目标与规模边界

| 项（§6.2） | 本协议值 | 依据 |
|---|---|---|
| 目标吞吐 | **待 P4 基准**（不写承诺，§6.5） | 生成器级速率由框架 `flow_control.bps` 承载（需求 §10 口径一），本层不重复定义 |
| 并发会话/流数 | 单策略 `sessions[]` 条数不限（每会话一条独立 TCP 连接）；`flows=N` 由框架复制 | `planner.go:112-126` 逐会话展开；多流由 `flow_control` 承载 |
| 单流最大报文 | Open 无 capability = **12B**；带 capability = 12 + 8×TLV 数（每 TLV value 恒 4B）；Keepalive = 4B；多对象消息 = 4 + Σ(4 + pad4(body)) | §3.1 总长度公式（`builder.go` 实读） |
| 内存上限 | O(单消息 PDU 长度)，无跨消息累积；`Plan` chan 缓冲 **32**（`planner.go:37`） | 逐事件流式 emit，无全量收集 |
| 队列/缓冲上限 | 上条 chan 32；框架侧 bounded queue 由引擎统一（本层不新增队列） | `planner.go:37` |
| CPU 并行度 | 无本层并发；多 worker 由框架 `PacketWorkers` 决定（本层无锁、builder 全纯函数） | §11.6 |

### 6.2 性能依据（§6.4）

- **流式处理**：`Plan` 在 goroutine 内逐事件 `emit` 到 chan（`planner.go:38-64`），`parsePCEPEvents` 逐事件产出 `([]byte, bool)`，**不聚合**；多会话路径逐会话 `emitSel`（`planner.go:112-126`）。
- **每条流新增内存**：会话级仅 `payloads [][]byte` + `ups []bool`，大小 = 事件数 × 单消息长度（O(消息)）。
- **共享状态/锁**：无跨流共享状态；`builder.go` 全为纯函数（无全局可变状态）；`PCEPGenerator` 无字段。
- **限速与多 worker**：速率由框架 `SharedTokenBucket` 在 worker 层统一施加，本层不参与——故多 worker 不改变配置速率（§6.6 背压场景的验证依赖框架侧口径）。

### 6.3 验收两路（§6.3）

| 路径 | 断言集 | 落盘 |
|---|---|---|
| pcap | 与 NIC **共用同一 cases JSON 与断言集**（`pcep.*` 字段 + `tcp.dstport/srcport` + offset 54 frames + `packet_count`） | `/tmp/mcp-pcaps/pcep/` |
| NIC | 同上，经 tcpdump 捕获（`nic_capture` 用例级开关） | 同上 |

不设仅单路径可用的断言；断言实际字段值与 `frames` hex，**不只断言"任务没报错"**（§6.7）。

### 6.4 六类场景落点（§6.6）

| 场景 | 落点 | 现状 |
|---|---|---|
| 基线 | #1（3 事件 / 10 包） | 已覆 |
| 目标规模 | #13（2 会话 / 22 包整块展开） | 已覆 |
| 压力上限 | **跨 MSS 消息分段**（PCEP 消息无长度上界声明） | **缺口**（§8 边界；A′ 候选） |
| 长时间运行 | #3（6 事件）/ #7（7 事件）同连接多轮 | 已覆（短序列，非长稳） |
| 并发交错 | 多会话语义由 `sessions[]` 顺序整块展开承载；`concurrent` 为框架例外路径，本协议不启用 | 显式不适用 |
| 资源耗尽/背压 | `packet_count` 精确计数守卫段数漂移；chan 32 缓冲 | 部分（无显式背压例） |

### 6.5 不写承诺项（§6.5）

目标吞吐（pkt/s、bit/s）**无代码路径或基准数据支撑**，一律标"待 P4 基准"，不写成承诺。

## 7. 负例与错误传播

7 条负例逐行给出**实际注入形状**与**实际 validator 文案**（校正旧稿"错误注入"定性；锚词与真实文案的子串关系逐条实测）：

| # | ID | 实际注入形状（机读） | 实际拒绝分支（`builder.go` 行） | `error_contains` |
|---:|---|---|---|---|
| N-1 | `pcep_neg_malformed_length` | `wire_fault:{kind:"length",declared:2}`（7 例中唯一真走 `wire_fault` 的） | `CheckFault` `:661-670` → `pcep: fault injection "length"` | `length` |
| N-2 | `pcep_neg_unknown_type` | `{kind:"unknown",message_type:99}` | `:723` → `unknown message type 99 is not supported` | `type` |
| N-3 | `pcep_neg_object_length` | `objects:[{class:"rp",object_length:3}]` | `:773` → `object_length 3 is invalid (must be >= 4 and 4-byte aligned)` | `object` |
| N-4 | `pcep_neg_keepalive` | `{kind:"keepalive",objects:[{class:"rp"}]}` | `:732` → `keepalive must not have objects` | `keepalive` |
| N-5 | `pcep_neg_session_id` | `{kind:"open",sid:0}` | `:696-698` → `session id 0 is invalid (RFC 5440 §7.3, sender-assigned non-zero)` | `session` |
| N-6 | `pcep_neg_address_family` | IPv4 profile + IPv6 endpoint/ERO | `:781` → `IPv6 endpoint in IPv4 address family profile` | `address` |
| N-7 | `pcep_neg_stateful_without_profile` | base profile + `class:"lsp"`+`class:"srp"` | `:758` → `lsp object requires stateful profile` | `stateful` |

所有负例 JSON 的 `expect` 严格只有 `expect_error` 与 `error_contains`（存量机读 7/7 干净）；不得以成功但 0 packet、忽略损坏字段或一条 TCP ACK 满足断言。

**不得误报的合法协议事件**：两个方向 Open 的 SID 不同（#1 正例，7/8）；`pcep_rfc5440_ipv4` profile 下 IPv6 地址**不出现在**对象里即为合法；Keepalive 无对象（#1/#3 正例）；`sid` 非 0 的任意值（含 255）。

## 8. 边界

- **消息长度**：Keepalive 恒 4；Open 无 capability 恒 12；对象 body 按 4 字节对齐。`object_length` 越界值（0/5/65535）与 `msg_length` 下界 4 的相邻值今日无例 → A′ 补例（G-PCEP-5）。
- **SID 值域**：`sid:0` 已覆（N-5）；`sid:255` 上界今日无例 → A′ 补例。
- **地址族**：PCEP 语义层 v4/v6 各自已覆（#4/#8）；**外层 IPv6 载体（offset 74）零用例** → A′ 补例；**RRO-in-IPv6 零用例**（G-PCEP-7，§9.24 对称缺口）。
- **端口**：显式 4189 全正例；缺省 4189（`chain_planner.go:1128` 补齐）今日无例 → A′ 补例（G-PCEP-8）。
- **多会话**：`sessions[]` 已覆（#13，2 会话）；`sessions[i].src_port` 缺失被拒（`builder.go:701`）今日无例 → A′ 候选。
- **动态字段**：四元组五策略全开；pcep 业务字段全关（G-PCEP-3）。
- **未实现面**：PCUpd(10)/PCInitiate(12) 无事件分支（G-PCEP-6）→ 明确不解决 + 迁入计划，今日不得建正例。
- **死键**：`PCEPConfig.Transport`（`types.go:603`）全仓零读取（G-PCEP-4）→ 代码阶段删键裁定。
- 不得产生回绕长度或超量分配（消息长度显式声明，不隐式放大）。

## 9. 原子 ID 与完成定义（24 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 | application events | packet_count |
|---:|---|---|---|---:|---:|
| 1 | `pcep_open_keepalive` | 正 | §4.1：双向 Open（SID 7/8）、Keepalive、common length | 3 | 10 |
| 2 | `pcep_open_bidirectional` | 正 | §4.1/§4.4：双向 Open/Keepalive 与 TCP direction | 4 | 11 |
| 3 | `pcep_keepalive_direction` | 正 | §4.1：两方向 Keepalive 不自动补发 | 6 | 13 |
| 4 | `pcep_pcreq_ipv4_ero_metric` | 正 | §4.2：IPv4 PCReq、RP/endpoint/ERO/metric + PCErr 关联 | 4 | 11 |
| 5 | `pcep_pcrep_ipv4_ero_rro` | 正 | §4.2：IPv4 PCRep、RRO/metric/request ID | 4 | 11 |
| 6 | `pcep_pcntf_and_pcerr` | 正 | §4.3：PCNtf、PCErr、notification/error | 6 | 13 |
| 7 | `pcep_multi_request` | 正 | §4.4：多 request/response、request ID 隔离 | 7 | 14 |
| 8 | `pcep_ipv6_address_family` | 正 | §4.4：IPv6 endpoint/ERO（外层仍 IPv4） | 4 | 11 |
| 9 | `pcep_lsp_object_flags` | 正 | §5：RFC 8231 LSP/SRP、PLSP-ID | 4 | 11 |
| 10 | `pcep_rro_ipv4_ipv6` | 正 | §4.2：IPv4 RRO subobject flags/L bit | 4 | 11 |
| 11 | `pcep_metric_flags` | 正 | §4.2：Cost/Bound 与 metric value | 4 | 11 |
| 12 | `pcep_tcp_direction` | 正 | §4.4：c2s PCReq/PCNtf、s2c PCRep、4189 端口方向 | 5 | 12 |
| 13 | `pcep_multi_session` | 正 | §4.4：两个独立 TCP sessions/SID（7/8 与 22/23） | 8 | 22 |
| 14 | `pcep_stateful_rfc8231_profile` | 正 | §5：stateful capability TLV 16/17 profile 边界 | 3 | 10 |
| 15 | `pcep_delegation_rfc8281_profile` | 正 | §5：delegation flags（delegate/remove/create 三条 pcreq） | **5** | **12** |
| 16 | `pcep_common_header_length` | 正 | §3.1：version/type/message length（Open×2/PCReq/PCRep） | 4 | 11 |
| 17 | `pcep_object_flags` | 正 | §3.2/§4.2：P/I object flags、LSPA flags | 3 | 10 |
| 18 | `pcep_neg_malformed_length` | 负 | §7：N-1 wire_fault length | — | — |
| 19 | `pcep_neg_unknown_type` | 负 | §7：N-2 未知 message type | — | — |
| 20 | `pcep_neg_object_length` | 负 | §7：N-3 object length 越界 | — | — |
| 21 | `pcep_neg_keepalive` | 负 | §7：N-4 Keepalive 带 object | — | — |
| 22 | `pcep_neg_session_id` | 负 | §7：N-5 SID=0（旧稿"漂移"描述作废） | — | — |
| 23 | `pcep_neg_address_family` | 负 | §7：N-6 IPv4 profile 携 IPv6 | — | — |
| 24 | `pcep_neg_stateful_without_profile` | 负 | §7：N-7 base profile 携 LSP/SRP | — | — |

**存量机读对账（2026-09-28）**：24/24 ID 与上表一致、顺序一致；17 正例 `packet_count` 与上表逐行一致（含 #15 的 12，旧稿 10 为漏计 Open 的笔误，§0 行 6）；7 负例 `expect` 键集合严格 `{expect_error,error_contains}`。

完成定义：`tcp→pcep` 层链注册已落码；common header、消息/对象长度边界与 TCP reassembly（重组）可观测；六类 RFC 5440 message 及 IPv4/IPv6 endpoint/ERO/RRO/metric 逐项生成验证；17 正例逐项覆盖上表 fields/frames；7 负例从 planner→engine→task error 传播；stateful/delegation 只有显式 profile 才开放；未注册扩展与 PCUpd/PCInitiate 不被伪装成成功基础 PCEP。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | TCP 4189 长连接，PCC 主动建连；PCEP 无独立数据连接（RFC 5440 §5.1） | 场景①–⑧（§3.4） | `DependsOn ["tcp"]` 单值（`registry.go:1391`）；`sessions[]` 多连接整块展开（#13） | 无 |
| 2 | 命令/消息表 | 8 类 message（1/2/3/4/6/7/10/12） | 场景①–⑧ | 6 类有事件分支（`builder.go:449-495`）；10/12 常量已定义无分支 | **G-PCEP-6**（10/12 未实现） |
| 3 | 状态机 | 会话建立（Open 双向）—业务—释放 3 态；无 PCEP 层自有状态 | #1–#3 | tcp 层拥有握手/挥手；pcep 层纯事件驱动（`planner.go:66-83`） | 无 |
| 4 | 字段表 | common header 3 字段 + object header 3 字段 + 11 对象类字段 | 数据场景层 | `PCEPConfig`/`PCEPEvent`/`pcepObject` 全量（`types.go:601-652`、`builder.go:59+`） | `Transport` 死键 **G-PCEP-4**；`object_length` 不落线 **G-PCEP-5** |
| 5 | 错误处理 | 7 类负例（§7 表） | 负例 N-1…N-7 | `builder.go` 共 18 个 `fmt.Errorf`：validator 16（`ValidateConfig` `:673` + `validatePCEPEvents` `:716`，其中后者 10）+ `CheckFault` 2（`:666/668`） | 锚词已钉死 7/7；未覆盖分支见 §10.2 |
| 6 | 超时与活性 | Keepalive/DeadTimer 为会话参数（RFC 5440 §7.3），**不由 planner 自动插入周期消息** | #1/#3 显式 Keepalive | 无定时器；`keepalive`/`deadtime` 仅作 Open body 字段（`builder.go:452-459`） | **显式不适用**（生成器不回话），无缺口 |
| 7 | NAT/代理/被动 | PCEP 无被动模式概念；PCC/PCE 角色由事件 `direction` 表达 | #12 方向面 | 无被动分支 | **显式不适用**；NAT 穿透为框架面 |
| 8 | 版本/方言 | Version=1（`0x20`）；IPv4/IPv6 endpoint 方言；RFC 8231/8281 扩展 profile | #8/#14/#15 | 5 个 profile 白名单 + 空 profile（`builder.go:684`） | 外层 IPv6 载体零用例（§8） |

### 10.2 子表①：message type × 终态矩阵（逐格已覆/立项/不适用）

| message type | T1 正常 FIN 终态 | T2 配置拒绝 | T3 异常终止（RST） |
|---|---|---|---|
| 1 Open | 已覆（#1/#2） | 已覆（N-5，SID=0） | A′ 立项 |
| 2 Keepalive | 已覆（#1/#3） | 已覆（N-4） | A′ 立项 |
| 3 PCErr | 已覆（#4/#6） | 缺口（无专属拒绝分支） | A′ 立项 |
| 4 PCNtf | 已覆（#6） | 缺口（无专属拒绝分支） | A′ 立项 |
| 6 PCReq | 已覆（#4/#7） | 已覆（N-1/N-2/N-3/N-6/N-7） | A′ 立项 |
| 7 PCRep | 已覆（#5） | 缺口（无专属拒绝分支） | A′ 立项 |
| 10 PCUpd | **不适用**（未实现，G-PCEP-6） | **不适用** | **不适用** |
| 12 PCInitiate | **不适用**（未实现，G-PCEP-6） | **不适用** | **不适用** |

**逐格重数**：8 行 × 3 列 = 24 格——已覆 9（6 个 T1 + 3 个 T2）/ A′ 立项 6（6 类已实现消息的 T3）/ 缺口 3（PCErr/PCNtf/PCRep 的 T2）/ 不适用 6（10/12 两行全列）= 24，零空格。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **36 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | 单 Open（c2s） | 覆（#1） |
| 2 | 双向 Open（SID 不同，7/8） | 覆（#1/#2/#13） |
| 3 | 单 Keepalive | 覆（#1） |
| 4 | 多 Keepalive（双向各 2） | 覆（#3） |
| 5 | PCReq→PCRep 配对 | 覆（#5） |
| 6 | PCReq→PCErr 配对 | 覆（#4） |
| 7 | PCNtf | 覆（#6） |
| 8 | PCErr | 覆（#6） |
| 9 | 多 request 隔离 | 覆（#7） |
| 10 | IPv4 END-POINT | 覆（#4/#5） |
| 11 | IPv6 END-POINT | 覆（#8） |
| 12 | ERO IPv4 subobject | 覆（#4） |
| 13 | ERO IPv6 subobject | 覆（#8） |
| 14 | RRO IPv4 subobject | 覆（#5/#10） |
| 15 | RRO IPv6 subobject | **缺口 G-PCEP-7**（地址族对称） |
| 16 | Metric Cost（C flag） | 覆（#11） |
| 17 | Metric Bound（B flag） | 覆（#11） |
| 18 | Metric float value | 覆（#11，12.5） |
| 19 | LSP object（PLSP-ID） | 覆（#9/#14） |
| 20 | SRP object（ID-Number） | 覆（#9/#14/#15） |
| 21 | LSPA object | 覆（#17） |
| 22 | RP P/I flags | 覆（#17） |
| 23 | object_length 越界（3） | 覆（N-3） |
| 24 | object_length 边界相邻值（0/4/5/65535） | **缺口 G-PCEP-5** |
| 25 | message_length 越界 | 覆（N-1） |
| 26 | message_length 下界相邻值（3/4） | 缺口（并入 G-PCEP-5） |
| 27 | 未知 message type | 覆（N-2） |
| 28 | 未知 object class | 缺口（`unknown object class %q` 分支 `builder.go:615` 无例） |
| 29 | Keepalive 带 object | 覆（N-4） |
| 30 | SID=0 | 覆（N-5） |
| 31 | SID=255 上界 | 缺口（A′） |
| 32 | profile 混族 END-POINT | 覆（N-6） |
| 33 | profile 混族 ERO subobject | 覆（N-6） |
| 34 | base profile 携 LSP/SRP | 覆（N-7） |
| 35 | stateful/sync capability TLV | 覆（#14） |
| 36 | 外层 IPv6 载体（offset 74） | 缺口（A′） |

**逐格重数**：36 行 = 覆 30 + 缺口 6（#15 RRO-in-IPv6 / #24 object_length 边界相邻值 / #26 msg_length 下界 / #28 未知 object class / #31 SID 上界 / #36 外层 IPv6 载体）= 36，零空格。另附三项**显式不适用**（不占行）：PCUpd/PCInitiate 消息形态（G-PCEP-6 未实现）；"`class:"notification"`/`"error"` 写在 `objects[]` 无效"这一假设（**不成立**——它们是 pcntf/pcerr 的唯一输入路径，§4.3/§11.7，不得建该形状的负例）；PCEP 层保活定时器（§10.1 第 6 项）。

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | PCC 上线建会话（Open/Keepalive，RFC 5440 §6.1/§6.2） | #1/#2/#3 | 已覆 |
| 2 | 路径计算请求-响应（PCReq/PCRep，§6.4/§6.5） | #4/#5 | 已覆 |
| 3 | 错误与通知上报（PCErr/PCNtf，§6.6/§6.7） | #6 | 已覆 |
| 4 | 批量路径计算（多 request，§6.4） | #7 | 已覆 |
| 5 | IPv6 域内计算（RFC 5440 §7.1.3） | #8 | 已覆 |
| 6 | 有状态 PCE LSP 上报（RFC 8231 §5.1） | #9/#14 | 已覆 |
| 7 | LSP 委托（RFC 8281 §4.1） | #15 | 已覆 |
| 8 | 多 PCC 并发会话（部署常态） | #13 | 已覆 |
| 9 | PCE 主动下发/更新 LSP（PCInitiate/PCUpd，RFC 8281 §5.1/RFC 8231 §6.1） | — | **明确不解决**（G-PCEP-6：未实现，今日不得建正例） |
| 10 | 未知扩展协商（`pcep_unknown_extension` profile） | N-2（身份区分侧） | 待确认（profile 字符串被接受但无 TLV 面；未知 type 拒绝已覆） |
| 11 | PCEP over TLS / 认证 | — | **明确不解决**（RFC 5440 为明文；TLS 属框架 tls 层能力，本层零断言） |

8 覆 + 2 明确不解决 + 1 待确认 = 11。✓无映射无确认即缺口——本表零缺口（待确认项已写清确认方式：抓 FRR pathd 包）。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：①规范原文（RFC 5440/8231/8281，定"必须是什么"：TCP 4189 明文、common header + object header、profile 化扩展）；②商业化软件实际行为（FRR `pathd`、Cisco/Juniper PCEP 实现：均以 RFC 5440 为底线，扩展走 capability TLV 协商，不隐式发 PCUpd——**未做现网抓包实证，标待确认**）；③可靠开源实现思路（本仓库同族先例：ldp/cflow/pim 的"TCP/UDP 终结层 + 事件流 + builder 纯函数"，只借鉴思路）。三路一致点：事件显式化、无隐式补消息、扩展走 profile 白名单；不一致点：扩展能力协商的细节（取舍：以 RFC + 本仓库 profile 白名单为准，不实现协商状态机）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `pcep` 终结层（本版；ldp/cflow/pim 同构先例） | 事件/对象/长度/flags 四事可声明可断言；代价 = 一套薄层（已落码 2077 行） | **采用** |
| B | 直接 tcp 层 + 顶层 payload（旧扁平形） | 单段单向、无对象级校验 → 17 正例的 message type/对象/flags 全不可表达 | **否决**（CORE_MEMORY §1.4/§1.11） |
| C | 与 ldp 合并为"MPLS 信令族" | ldp 是 UDP/TCP 双载体 TLV 报文（默认 646），pcep 是 TCP 4189 的 object 结构报文——文法不兼容，合并即错 | **否决** |

## 11. P2 D-PCEP-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 状态说明：实现已落码（`internal/protocol/pcep/` 三文件），本 P2 条目为 P-PIPE 文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口；代码阶段（P4）在本协议内为"缺口收敛"（§14），不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:601-652` + `:1726`） | `PCEPConfig`/`PCEPSession`/`PCEPEvent`/`PCEPEndpoint`/`PCEPCapability`/`PCEPFault` 配置类型 + `FlowSpec.PCEP` 槽位 | —（共享文件） |
| `trafficgen/internal/protocol/pcep/planner.go` | `Planner.Validate`/`Plan`（握手→事件→挥手）+ `PCEPGenerator`（`Generate` 多会话展开）+ `init()` 注册生成器/校验器 | 151 |
| `trafficgen/internal/protocol/pcep/builder.go` | 线格式纯函数（common/object header、11 类对象、TLV）+ `parsePCEPConfig`/`parsePCEPEvents`/`parseObjects` + `ValidateConfig`/`validatePCEPEvents`/`CheckFault` | 792 |
| `trafficgen/internal/protocol/pcep/pcep_test.go` | 50 个 `Test*`（builder 线格式面 + validator 拒绝面 + planner 包数面） | 1134 |
| 接线 5 处 | registry 注册（`layers/registry.go:1391`）/ translate Meta 直传（`chain_planner_translate.go:166`）/ convert 子配置搬运（`strategy_convert.go:1738-1740`）/ protocols 准入（`protocols.go:50`）+ 端口缺省（`chain_planner.go:1128`、白名单 `:751`） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`planner.go:17`）：`PCEP==nil` 拒 `pcep: config is required`；否则转 `ValidateConfig(spec.PCEP)`。
- `ValidateConfig(cfg *core.PCEPConfig) error`（`builder.go:673`）：空 events+空 sessions 拒；profile 白名单（含 `""`）拒未知；逐事件走 `validatePCEPEvents`；Open SID=0 拒；`sessions[i].src_port==0` 拒。
- `validatePCEPEvents(events, cfg, prefix) error`（`builder.go:716`）：kind 空/`unknown`/未知、direction 非 c2s|s2c、keepalive 带 objects、`wire_fault.kind` 未知、非 stateful profile 携 lsp/srp、`object_length` 越界、地址族混写——共 **10** 个 `return fmt.Errorf`（行号 `:720/723/726/729/732/745/758/773/781/786`，`awk` 实测），错误文案与 §7 锚词逐字一致。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`planner.go:24`）：先 Validate；`DstPort==0` 补 4189；`parsePCEPConfig` 出 `(payloads, ups)`；单会话 emit（SYN/SYN-ACK/ACK → 事件 → FIN 四包）。
- 生成器：`Name() "pcep"`；`GenEvents()` 自返；`EmitEvent` 未接线显式错（防误调，`planner.go:97-99`）；`Generate` 按 `sessions[]` 或多事件逐条 `emitSel`（`planner.go:101-137`）。

### 11.3 数据结构

`PCEPConfig{Transport(死键，G-PCEP-4), Profile, Events[], Sessions[]}`；`PCEPSession{SrcPort, Events[]}`；`PCEPEvent{Kind, Direction, Keepalive, Deadtime, SID, RequestID, MessageType, Endpoint, Objects[](json.RawMessage), Capabilities[], WireFault}`；`PCEPEndpoint{SourceIPv4/DestinationIPv4/SourceIPv6/DestinationIPv6}`；`PCEPCapability{Kind, LSPUpdate, IncludeDBVersion}`；`PCEPFault{Kind, Declared}`（`types.go:601-652` 全量）。

### 11.4 主流程

配置 → validator（profile 白名单 + 逐事件 10 类分支）→ planner/builder（事件展开为 PDU 字节，`parsePCEPEvents` switch 6 类 kind）→ worker（TCP 层按 MSS 分段、补握手/挥手）→ writer（PCAP/NIC）。多会话路径：`sessions[]` 每条 `MessageEvent.SrcPort` 驱动 TCP 生成器的连接边界（拆旧连 + 建新连，`planner.go:109-126`）。

### 11.5 错误分支

`builder.go` 共 18 个 `return fmt.Errorf`（`grep -c` 实测）——其中 **16 个属 validator**（`ValidateConfig` `:673` + `validatePCEPEvents` `:716`），**2 个属 `CheckFault`**（`:666/668`，拒绝面非 validator）；全部传 task error（零假成功——N 系列守卫）；`CheckFault` 是**拒绝面**（`builder.go:661-670`：kind 合法也返回 error，即"注入了故障就拒"），不产出畸形线包——故 N-1 是"注入被拒"而非"发出畸形包"（§0 行 3）。

### 11.6 性能边界

见 §6（性能设计与验收）：逐事件流式展开（`Plan` goroutine + chan 32 缓冲，`planner.go:37`）；每事件内存 = PDU 长度 + TCP 段开销（O(消息)）；无跨流共享状态、无锁（builder 全为纯函数）。吞吐数字待 P4 基准，**本版不写承诺**（§6.5）。

### 11.7 与现有逻辑的冲突点

- registry `pcep` **无 `Fields` 表**（`registry.go:1391` 只给 Name/Category/DependsOn）→ 层内 `events`/`profile`/`sessions` 键无处可住；`complete.go:291-293` 对未注册键报 `layers: layer "pcep": unknown field %q`。目标形状（§2）需 P4 补 Fields + translate 分支（G-PCEP-1）。
- `chain_planner_translate.go:753-755` 今日只做 `if term.Name == "pcep" && spec.PCEP == nil { spec.PCEP = &core.PCEPConfig{} }`——**不做层内严格解码**（对比同文件 `pim`/`bgp` 的 `completedConfig` + `DisallowUnknownFields` 往返），故层内配置今日既进不去也不校验（G-PCEP-1）。
- `CheckProtoFlat`（`strategy_convert.go:8625` 起）**无 pcep 分支**（分支清单实读至 `:9085`（末分支 `postgresql`）无 pcep）：顶层 `pcep` 子映射 presence 不判死（G-PCEP-2，**禁加单协议黑名单分支**，等框架级 unknown-key 白名单）；但通用五键（`src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`）判死**今日已生效**（`strategy_convert.go:8632-8637`）。
- `parseObjects` 对 `class:"notification"`/`class:"error"` 跳过（`builder.go:576-581`），但这两类**必须**写在 `objects[]` 里——值由更早的 `parseNotification`/`parseError`（`:623-655`）取出后交给消息级 builder；`parseObjects` 的跳过是"值已消费"而非"输入无效"（§4.3）。
- 动态 allowlist（`internal/core/layer_dyn.go:17-21`）：`pcep` 零命中 → 业务字段动态对象即拒（G-PCEP-3）。
- `PCEPConfig.Transport`（`types.go:603`）全仓零读取（`grep` 实测）→ 死键（G-PCEP-4）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 3 文件 + 接线 5 处（registry/protocols/translate/convert/chain_planner）；不触及其他协议。cases 回滚 = 恢复 24 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | **不合规，待代码阶段收敛**（非负例顶层键 = 84 处残留，17/17 例违规；判据=顶层键必须为 0）。见 §12.1 强制展开：顶层 `pcep` 子映射 + 顶层四元组与 `layers` 并存 = 判死形状（§1.4/§1.11/§1.13）；层内空壳 0/24 且 `translateTerminalConfig` 无 `case "pcep"` → 合规层链形**今日跑不通**，须代码阶段先补 registry `Fields` + translate case + `mapToFlowSpec` 收敛（G-PCEP-1）；目标形状见 §2 样例；presence 判死形状缺口 G-PCEP-2 | §0 审计主结论；§12.1；`cases/pcep.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 pcep 流量模板，自带 `flow_control`；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（终结层）/时间线。有长连接，不豁免 | §12.3 + §4.4 |
| §4 查规范 | RFC 5440/8231/8281 + 落码反推 + tshark 379 字段实测；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["tcp"]` 单值（`registry.go:1391`）；18 个 `return fmt.Errorf`（validator 16 + `CheckFault` 2）；失败传 task error | §5/§7/§11.5 |
| §6 性能 | 见 §6「性能设计与验收（CORE_MEMORY §6.1–6.8）」：6.2 六项逐项给值或给基准方法、6.3 验收两路（pcap/NIC 共用断言集）、6.4 六类场景落点、6.5 不写承诺项 | §6 |
| §7 三份文档 | `98-pcep-{design,testcase}.md` v1.0.1（草稿层）+ D-PCEP-1（§11，门1 获批 = 定稿）+ T-PCEP（testcase §2，24 ID）+ 旧稿 42-* 为历史层 | 修订记录 |
| §8 设计先行 | P1–P3 先于 P4 缺口收敛；门1 获批 = D-PCEP-1 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = RFC 5440/8231/8281（§10）+ D-PCEP-1（§11）+ tshark 通道实测（`pcep.*` 379 字段 + 真实 pcap，替代"已确认现网行为"档，未做现网 PCE 抓包 → G-PCEP-6 待确认，不冒充第三源）；24 ID 逐项回指；存量 24 例审计去向 testcase §8 | `98-pcep-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见自审报告）+ 收官隔离复审；红先绿后 | 自审报告 §2 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `pcep` 已在 `registry.go:1391` 注册（**不新增层**）；`allowedProtocols["pcep"]=true`（`protocols.go:50`）；Meta 已直传（`chain_planner_translate.go:166`）；**代码阶段补 registry `Fields` 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `pcep.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/pcep/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-28；合规判据 = 非负例顶层键必须为 0）**：

| 文件 | 例数 | 顶层键分布 | 合规判定 | 链形 | 层内非空 | 负例 expect 纯净 |
|---|---|---|---|---|---|---|
| `cases/pcep.json` | 24 | `{layers, src_ip, dst_ip, src_port, dst_port, pcep}` ×23 + 同形无 `src_port` ×1（#13 多会话，`src_port` 住 `sessions[]`） | **❌ 非负例 84 处残留 / 17 例全违规**（全 24 例 119 处） | `[tcp,pcep]` ×24（层内恒 `{}`，**空壳**） | **0/24** | ✅ 7/7 只有 `{expect_error,error_contains}` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` | **24** | 迁 `layers[i].ip.src`（G-PCEP-1） |
| `dst_ip` | **24** | 迁 `layers[i].ip.dst` |
| `src_port` | **23** | 迁 `layers[i].tcp.src_port`；#13 住 `sessions[].src_port`（层内保留该键语义） |
| `dst_port` | **24** | 迁 `layers[i].tcp.dst_port`；**或删**（由 4189 缺省补齐，A′ `pcep_default_port` 验证） |
| `count` | **0** | 走 `flow_control`（本协议无存量 `strategy_fc`，P4 按需引入） |
| 顶层 `pcep` 子映射 | **24** | **迁 `layers[i].pcep`**（须先补 registry `Fields`，G-PCEP-1） |
| 顶层 `tcp` 子映射 | **0** | 无残留（`moxa` 的 N-4 型双写在本协议不存在） |

**结论（§1 栏去向 = 待代码阶段收敛，文档阶段改不动）**：本协议有实质迁移工作量——**须代码阶段**先做 ①补 registry `Fields`（`profile`/`events`/`sessions`）；②`translateTerminalConfig` 加 `case "pcep"` 层内严格解码分支（对齐 pim/bgp 的 `completedConfig` + `DisallowUnknownFields`）；③`mapToFlowSpec`（`strategy_convert.go:331`，pcep 分支 `:1738-1740`）从子配置搬运收敛为层链驱动；**然后**才可 ④24 例整体改写为纯层链形；⑤新增 A′ 例全部纯 layers 形；⑥收官自查行「非负例顶层键 = 0」由 **84 处 → 0**。

目标形状样例见 §2（顶层仅 `layers`+`flow_control`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"pcep":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 pcep 分支，实读零命中）→ **代码阶段（P4）不建该负例**（建了会真绿 = 假通过）→ 缺口 G-PCEP-2 登记。② 通用五键游离判死今日已生效（`strategy_convert.go:8632-8637`）→ 代码阶段（P4）可建一条（A′）。③ 7 负例每条带锚词（已齐，§7）。④ 收官自查「非负例顶层键 = 0」（代码阶段收敛后执行）。

### 12.3 §3 强制展开：五件套

会话表：`s1` 单连接基线（#1/#2/#3/#4/#5/#6/#7/#8/#9/#10/#11/#12/#14/#15/#16/#17，各自四元组，SYN→事件→FIN 四包挥手）/ `s2` 多会话（#13，`sessions[]` 两条，`src_port` 40001/40002，SID 7/8 与 22/23）。事务：`t1` 建连（握手，tcp 层）/ `t2` 发消息（事件，`direction` 定方向）/ `t3` 收消息（对向事件）/ `t4` 终止（FIN；RST 为 A′）；每事务四件事（前置/触发/成功/失败）见 §5 状态机 + §4 场景表。关联关系：**无派生流**（诚实声明：PCEP 无控制流派生数据流的语义，无 `driven_by`；PCReq→PCRep 的关联是**同连接内事务关联**，由 `request_id` 表达，不是流关联）。插入位置：终结层（`[ip,tcp,pcep]`，无中间层）。时间线：会话内严格顺序（事件数组序 = 线上序）/ 多会话整块展开（#13 先跑完 s1 再跑 s2，第二会话包号起点 = 第一会话总包数 + 1，实测 #13 第 15 包为 s2 的 Open）/ 无交错（`concurrent` 为例外路径不启用）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst`、`tcp.src_port/dst_port` 五策略全开（allowlist `internal/core/layer_dyn.go:17-21` 实测：`ip`{src,dst,ttl} / `tcp`{src_port,dst_port} / `udp`{src_port,dst_port} / `eth`{src_mac,dst_mac}；保底 `DefaultSrcPort+i`（`strategy_convert.go:49` 常量、`worker.go:308` 注入）；dst 动态与 4189 缺省和平共处——显式/动态值非零即不触发补齐）。

**业务字段 5 项全关**（allowlist 无 `pcep` 行，`grep` 零命中实测；对象即 `does not support dynamic`）：`profile`（会话档案）/ `events[]`（事件剧本）/ `sessions[]`（结构选择器）/ `objects[]`（对象载荷）/ `capabilities[]`（扩展能力）——逐流变体需求列 A′ 候选（testcase §6.2；今日按 §9.36 口径不冒充覆盖）。

序号算法实读：`parseLayerDyn`（`layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`strategy_convert.go:49` + `worker.go:308` 注入）/ allowlist 白名单（`layer_dyn.go:17-21`）——**`pcep` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。

## 13. P3 对接清单（T-PCEP 草稿输入；正文落 testcase 文件）

24 ID（17 正 + 7 负）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。A′ 候选 6 例：`pcep_default_port`（G-PCEP-8）/ `pcep_neg_free_key`（G-PCEP-2 通用五键）/ `pcep_rro_ipv6`（G-PCEP-7）/ `pcep_neg_object_length_boundary`（G-PCEP-5）/ `pcep_outer_ipv6`（§8 外层载体）/ `pcep_sid_max`（§8 SID 上界）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-PCEP-1 | registry `pcep` 无 `Fields` 表 + `translateTerminalConfig` 只赋空 `&core.PCEPConfig{}`（不做层内严格解码）→ 顶层 `pcep`/四元组迁层内 + 24 例改写 + schemagen 重跑 | **代码阶段（P4）首动作**；收官「非负例顶层键=0」由 **84 处 → 0** |
| G-PCEP-1a | **低成本先解封路径**：存量 24 例**只删五键**（保留 `layers` 空壳 + 顶层 `pcep`）→ create 即 200、`spec.PCEP` 已填可出包（四形实测表 §0 第 2/3 行） | 与 G-PCEP-1 并列：可先恢复套件可跑性，但**非合规形**（顶层 `pcep` 子映射残留），门1 §1 栏仍红；两路不互斥，G-PCEP-1 才是转绿唯一路径 |
| G-PCEP-11 | **结果文档过期**：`trafficgen/docs/protocol-pcap-test/pcep.md` 写 24/24 pass，末次提交 `e60f8de`（2026-08-30）早于判死提交 `0417be5`（2026-09-13）两周；`cases/pcep.json` 末改 `07a5472` 同日；`docs/protocol-pcap-test/pcep/` **0 个 pcap** | 代码阶段（P4）解封后**重生成**结果文档；在此之前读者不得据此判断套件可跑（§0 产物过期登记） |
| G-PCEP-2 | `CheckProtoFlat` 无 pcep 分支 → presence 形今日不判死 | 代码阶段先实测再建例；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单）；通用五键游离判死已生效可建例 |
| G-PCEP-3 | 业务字段动态全关（allowlist 无 `pcep` 行） | A′ 候选，不冒充已覆盖（§9.36 口径） |
| G-PCEP-4 | `PCEPConfig.Transport`（`types.go:603`）全仓零读取 = 死键 | 代码阶段删键裁定（删后层内再写即 `unknown field`） |
| G-PCEP-5 | `objects[].object_length` 只校验不落线（`builder.go:773` 校验 → `buildObjectHeader` 重算）；越界值/边界相邻值用例缺失 | 代码阶段写明语义（§3.2 已写）+ A′ 补边界例 |
| G-PCEP-6 | PCUpd(10)/PCInitiate(12) 常量已定义（`builder.go:32-33`）但无 kind 分支 → RFC 8231/8281 的 PCE 主动面未实现 | **明确不解决** + 迁入计划（实现则补 `parsePCEPEvents` case + 用例；今日不得建正例）；现网 PCE 行为实证待确认（抓 FRR pathd 包） |
| G-PCEP-7 | RRO-in-IPv6 零用例（§9.24 地址族对称缺口；#10 名 `pcep_rro_ipv4_ipv6` 与实际单 IPv4 不符） | A′ 补例 `pcep_rro_ipv6`；#10 改名或补 IPv6 半边 |
| G-PCEP-8 | 默认端口 4189 补齐（`chain_planner.go:1128`）今日无例 | A′ 补例 `pcep_default_port`（删键不断言值，只断言补齐行为） |
| G-PCEP-9 | `pcep_neg_session_id` 名不副实（实际注入 `sid:0`，非 SID 漂移；旧稿描述在实现下不会红） | P4 改名 `pcep_neg_open_sid_zero`（ID 改名需同步 design/testcase/cases 三处） |
| G-PCEP-10 | `parseObjects` 对 `class:"notification"`/`class:"error"` 静默跳过（`builder.go:576-581`） | 文档已写明（§4.3/§11.7）；用例不得依赖；如未来需支持对象级写法则立项 |

## 15. 复算证据（每个数字脚本生成或实调，禁手算）

本节命令均可在 worktree 根 `trafficgen/` 下复跑；输出即文中数字来源。

**① 顶层残留计数（84 / 119）**

```bash
python3 -c "
import json
d=json.load(open('test/protocol_pcap/cases/pcep.json'))
WL={'layers','strategy_fc','ttl','flow_control','output','output_config','group_id'}
pos=[c for c in d if 'expect_error' not in c['expect']]
print('非负例残留', sum(len(set(c['spec_json'])-WL) for c in pos), '/ 例数', len(pos))
print('全24例残留', sum(len(set(c['spec_json'])-WL) for c in d))
"
# → 非负例残留 84 / 例数 17 ; 全24例残留 119
```

**② 四形 create 实调（§0 表）**：临时探针（`internal/probe_pcep_tmp/main_test.go`，用后即删，`git status --porcelain` 归零）调 `schema.ValidateStrategy("synth","pcep",<spec>,nil)` 与 `core.CheckProtoFlat`：

```go
// A 存量 = layers空壳 + 五键 + 顶层 pcep
schema.ValidateStrategy("synth","pcep",spec,nil)   // → reject 24/24
core.CheckProtoFlat("pcep", spec)                  // → "protocol pcep rejects flat config field src_ip (…)"
// B layers空壳 + 顶层 pcep（去五键）  → accept 24/24
// C 仅顶层 pcep（无 layers）          → accept 24/24
// D 纯层链 [ip,tcp,pcep] 带 events    → reject 0/24 ; firstErr "layers: layer "pcep": unknown field "events""
// 引擎路径 core.MapToFlowSpec(stock,"pcep").ValidationErrors → []（空），PCEP != nil = true
```

**③ G8 字段计数（39 / 379）**

```bash
tshark -G fields | awk -F'\t' '$3 ~ /^pcep\./ {print $3}' | sort -u | wc -l   # → 379
python3 -c "
import json
d=json.load(open('test/protocol_pcap/cases/pcep.json'))
s=set()
for c in d:
  for f in c['expect'].get('fields',[]): s.add(f['field'])
print(len({f for f in s if f.startswith('pcep.')}), sorted(f for f in s if f.startswith('tcp.')))
"
# → 39 ['tcp.dstport', 'tcp.srcport']
```

**④ 行号引用核对（C4 四处）**

```bash
sed -n '691,693p' internal/protocol/pcep/builder.go   # SID 漂移注释
sed -n '452,459p' internal/protocol/pcep/builder.go   # KA/DT 缺省 30/120
sed -n '38,48p'   internal/protocol/pcep/builder.go   # object 类常量
sed -n '173,180p' internal/protocol/pcep/builder.go   # TLV 16/17 同发
```

**⑤ 分支计数（10 / 16 / 2）**

```bash
awk 'NR>=716 && NR<=790 && /return fmt.Errorf/ {print NR}' internal/protocol/pcep/builder.go  # → 720 723 726 729 732 745 758 773 781 786 (10)
awk 'NR>=661 && NR<=672 && /return fmt.Errorf/ {print NR}' internal/protocol/pcep/builder.go  # → 666 668 (CheckFault, 2)
grep -c 'return fmt.Errorf' internal/protocol/pcep/builder.go                                  # → 18
```

**⑥ 产物过期（G-PCEP-11）**

```bash
git log -1 --format='%h %ad %s' --date=short -- docs/protocol-pcap-test/pcep.md  # → e60f8de 2026-08-30
git log -1 --format='%h %ad %s' --date=short 0417be5                            # → 2026-09-13
ls docs/protocol-pcap-test/pcep/ 2>/dev/null | wc -l                             # → 0（目录不存在）
```

## 16. 修订记录

- v1.0.1（2026-09-28，隔离审查打回后修轮）：C1 现状可用性定性纠错（存量 24 例今日 create 400 全红；去五键即可用；补四形实测表与产物过期登记）；C2/G8 计数 36→39；C3 补真 §6 性能节（原 §6 降 §4.4，§11.6 与门1 §6 行指向修正）；C4 行号 4 处 + 分支计数口径（10/16/2）；新增 §15 复算证据节、G-PCEP-1a/G-PCEP-11。
- v1.0.0（2026-09-28）：P-PIPE #98 文档轨 P1–P3。续号审计：42→98 沿革与 8 项校正（§0，含 2 处与实现/RFC 矛盾：SID 一致性不变式、Open 长度常量 `0x10`→`0x0c`；1 处 doc/JSON 数值分歧 #15 3/10→5/12）；存量 24 例机读审计（顶层残留形状 5 键 24/24、层内空壳 0/24、expect 形状、ID 顺序一致、17 正例包数逐行对账）；§12.1/12.3/12.12 强制展开 + 12-P2；D-PCEP-1 as-built 定稿（§11）；缺口 G-PCEP-1…G-PCEP-10。P1 自审 2 轮 / P2 自审 2 轮 / P3 自审 2 轮，末轮干净（结论见 `/tmp/pipe/doc-lanes/pcep.md` §2）。

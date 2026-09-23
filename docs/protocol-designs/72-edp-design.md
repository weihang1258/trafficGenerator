# EDP（增强设备协议，Enhanced Device Protocol / 中国移动 OneNET 设备接入协议）设计契约

> 版本：v2.1.0（设计阶段）
> 日期：2026-09-02
> 状态：**已按 v1.3 重审清单修复（v2.1.0），待审查方复验关闭**（本文不自行宣称已通过对抗审查，以审查方对问题清单逐条确认关闭为完成标准）。
> 配套文件：`docs/protocol-designs/72-edp-testcase.md`、`trafficgen/test/protocol_pcap/cases/edp.json`（当前 JSON 仅含注册前置占位，本版不写文件、不改代码；占位端口已对齐 fixture）
> 规范基线：EDP 为**平台私有协议，无 RFC/国际标准**，权威依据取以下四层（逐项标注出处）：
> ① **OneNET 官方 EdpKit SDK**（设备终端接入协议参考实现，公开镜像两份独立副本交叉一致）：EdpKit **v1.1.4**（2015，官方 Windows DLL 版，wululu/wusongwei，见 keep1234quiet/OneNET_Demo_ESP8266_EDP_Led/EDP/EdpKit.c|.h）与 EdpKit **v1.0**（2017，官方嵌入式精简版，张继瑞，见 sanjaywu/IoT_Board_OneNET_Demo/OneNET/edpkit.c|.h）——本文 §3 全部字节布局逐行对照 SDK 组包/解包函数给出（出处写"SDK 函数名"；v1.3 重审两镜像实拉回对 0 缺陷，镜像留存 /tmp/edp_kit1.c|.h、/tmp/edp_kit2.c）；
> ② **OneNET 官方文档站 EDP 页**（open.iot.10086.cn，web.archive.org 2019-08 存档）：EDP 定性（Enhanced Device Protocol、基于 TCP 长连接、数据点上报/透传/转发/存储、平台消息下发、加密传输）、接入流程、FAQ（type=1/type=3 数据点 JSON 形态、cmd_id 语义与命令应答状态）——出处写"官方文档站《EDP 简介/接入说明》"；
> ③ **公开资料 + 假设，实现阶段实证校准**：端口 4472（公开接入资料 jjfaedp.h3.chinam2m.com:4472，平台控制台可配）、CONNRESP 标志字节语义、SAVEACK 应答 JSON 内容、DISCONNECT 报文体——公开 SDK 未钉死，逐处标注；
> ④ **本机实测**：tshark 3.6.14 `-G fields`/`-G protocols` + 按 SDK 逻辑构造 pcap 实证（`tcp.payload` 精确提取 EDP 报文字节、offset 54/74，见用例文档 §1）。
> 修订记录：v2.1.1（2026-09-23，修轮 F8 校准）：§6 示例与实现对齐——`json_str` 键更正为 `json`（实现 EDPEvent tag）、`devid_flag/msg_id_flag` 布尔更正为 0/1 整型（与 cases/edp.json 工作形状一致）；v2.1.0（2026-09-02）：按《需求文档 v1.3》rr-edp 重审（8C+5N）修复：**C-1** §1 补 pcap/NIC 双输出契约；**C-2** §5/§6 并发会话翻案纳入（+`edp_concurrent_sessions`）；**C-3** §5 补 RST/异常中断声明（FIN 统一挥手，cwmp R-6 同形）；**C-4** §2 补端口变体声明（+`edp_port_nondefault`）；**C-5** §7 负例 12 → 28 行原子拆分（一行一注入）、wire_fault 枚举 28 值 1:1 同序（§6）、锚词改"主锚词钉死（备选括注）"；**C-6** §8 边界相邻值族双侧补齐（127/16,383/2,097,151/65,534/devid u16 上界各 +1 例）；**C-7** 占位 JSON 三处对齐；**C-8** 用例文档 §1 edp.* 字段表述更正；**N1** §3.5 补 desc/bin 上界 SDK 严格 > 与 wire ≥ 口径差异声明；**N2** §3.5 补 kit2 msg_id 固定常量出处注；**N3** §3.10 补 kit2 type2+devid 公式漏 devid_len（SDK bug）注；**N4** §3.5 补标志×格式两维独立声明 + 矩阵 4×5 全 20 格正例；**N5** rtn=1 正例。配套用例文档 v2.1.0：39 → **89 条（61 正 + 28 负）**，ID 权威改用例文档 §2（§9 改簇级）。
> 修订记录：v2.0.1（2026-09-01）：按独立隔离审查 9 项清单修复（E01–E09，详见 git 历史）；v2.0.0（2026-09-01）：按需求文档 v1.1 重写取代 2026-08-21 臆造旧稿。

## 1. 范围、profile 和未注册边界

本版定义 OneNET EDP（Enhanced Device Protocol）的**明文 TCP 长连接**设备接入链路：通用报文格式（消息类型 + 剩余长度变长编码）、连接建立（CONNREQ 两种鉴权方式 / CONNRESP 返回码 0–9）、心跳（PINGREQ/PINGRESP）、数据点存储上报（SAVEDATA 五种数据格式：FullJson / Bin / SimpleJsonWithoutTime / SimpleJsonWithTime / String）、存储确认（SAVEACK）、端到端透传（PUSHDATA 双向，无应答）、平台命令下发与应答（CMDREQ/CMDRESP，cmdid 关联）、连接关闭（DISCONNECT）、IPv4/IPv6、多会话与并发会话、多事务。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `edp_tcp_plain_v1`（主 profile） | TCP 明文（fixture 端口 4472，可配置覆盖） | CONNREQ/CONNRESP、PINGREQ/PINGRESP、SAVEDATA 五格式、SAVEACK、PUSHDATA、CMDREQ/CMDRESP、DISCONNECT | 真实平台鉴权结果、数据点真实入库、触发器/规则引擎行为 |
| `edp_ipv6_v1` | 同上，仅外层 IPv6 | 同 `edp_tcp_plain_v1` | 从 IPv4 fixture 推导 IPv6 地址 |
| `edp_encrypt_boundary` | TCP + ENCRYPTREQ(0xE0)/ENCRYPTRESP(0xF0) | **仅边界声明，不设语义用例**：公开 SDK 两副本均只有类型值定义、无组包/解包函数（加密布局未公开）；注入该类型值由负例 `edp_neg_type_unimplemented` 拒绝 | 臆造加密协商布局；无密钥时声称加密内容可见 |

**输出契约（pcap/NIC 双输出）**：本协议全部用例同时兼容两种输出路径——`pcap` 文件输出（断言以 tshark 读 pcap 为准）与 `port_group`/NIC 网口输出（同一份用例契约驱动真实发包，断言由抓包侧使用相同 tshark 字段/原始字节校验）；两路径共用同一 cases JSON，不设仅单路径可用的断言（需求文档 v1.3 §8.2-7）。

显式边界（"不实现、不声称、不许静默转换"）：EDP **不保证消息顺序**——官方文档站《EDP 简介》原文"若客户端同时发起两次请求，服务器返回时，不保障返回报文的顺序，事务机制需要在上层实现"（本版事件序列按序回放，不模拟乱序返回）；ENCRYPTREQ/ENCRYPTRESP（0xE0/0xF0）布局未公开，本版不实现（注入走负例）；PUSHDATA 为**单向无应答**（SDK 无 pushdata 应答函数），不臆造确认帧。

当前仓库没有注册 `edp` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/edp.json` 只保留一个不计入语义 ID 的注册前置占位 `edp_neg_unregistered`（`expect_error=true`、`error_contains="unknown layer"`；v2.1 已对齐 fixture 端口 src 41072/dst 4472）。占位的拒绝、0 包或空 PCAP 不得报告为 EDP 行为通过；注册后按用例文档 §2 的同一顺序替换为 **89 个语义用例（61 正 + 28 负；语义 ID 清单以用例文档 §2 为唯一权威，本节与 §9 不再逐条维护）**。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[tcp, edp]`（引擎自动补 `ip`；需要显式地址族时写 `[ip, tcp, edp]` 或 IPv6 等价链）。EDP 报文是 TCP payload 的**字节流内容**，与 mqtt/gnutella 同款"TCP 之上直接组帧"的终结层形态。

端口：公开接入资料为 **4472**（jjfaedp.h3.chinam2m.com:4472，"公开资料 + 假设，实现阶段实证校准"）；实际部署按平台控制台/接入文档配置，planner 不得静默改写，同一条 fixture 内端口必须一致。本版 fixture 统一 `dst_port=4472`。**端口变体覆盖声明（v2.1）**：非默认端口（如 12472）为显式正例落点（`edp_port_nondefault`）——端口由配置覆盖，EDP 报文字节与端口无关（§3.1 帧自定界），非默认端口下全栈语义与默认端口基线一致。

固定偏移：无 VLAN（虚拟局域网）、IP options 与 TCP options 时，**EDP 报文首字节（消息类型）起点为 IPv4 offset（偏移）54（Ethernet 14 + IPv4 20 + TCP 20）、IPv6 offset 74**（14 + IPv6 40 + TCP 20；构造 pcap 实测印证，`tcp.payload` 即完整 EDP 报文）。**TCP 分段边界不是 EDP 帧边界**：EDP 是流式协议，接收端按"消息类型 1B + 变长剩余长度 + remainlen 字节体"循环取帧（SDK `GetEdpPacket`/`IsPkgComplete` 流式重组证据）；一个 TCP 段可含半帧、整帧或多帧粘连（多帧粘连由 §3.1 变长长度自然定界，不需分隔符）。

**断言通道与 DecodeAs（v2.1）**：本机 tshark 无 OneNET EDP dissector（"EDP"=Extreme Discovery Protocol），断言走 `tcp.payload` 全帧 hex 与 raw frames offset 54/74 双通道——**与端口无关、无 DecodeAs 依赖**；实现与抓包侧均不得依赖端口→dissector 绑定，也不得使用属 Extreme 的 `edp.*` tshark 字段（用例文档 §1 实测口径）。

## 3. 线格式编码（逐项标注出处）

### 3.1 通用报文格式与剩余长度变长编码（SDK `WriteRemainlen`/`ReadRemainlen`）

每条 EDP 报文 = **消息类型（1 字节）+ 剩余长度（变长 1–4 字节）+ 消息体（remainlen 字节）**。剩余长度表示消息体字节数，**不含消息类型与剩余长度字段本身**。

变长编码（MQTT varint 同构，SDK 逐行）：每字节低 7 位有效，最高位（bit7）为延续标志——1 表示后续还有编码字节，0 表示结束；各字节的权值为 1, 128, 16384, 2097152（multiplier 每次 ×0x80）。**解码最多 4 字节，超过 4 字节为协议错误**（`ReadRemainlen` `len_len > 4` 返回 -1）；4 字节可表达上限 268,435,455（0x0FFFFFFF）。

| remainlen 值域 | 编码字节数 | 示例 |
|---|---:|---|
| 0–127 | 1 | 100 → `64`；127 → `7f`（129 超出本档，需 2 字节） |
| 128–16,383 | 2 | 129 → `81 01`；300 → `AC 02` |
| 16,384–2,097,151 | 3 | 16,406 → `96 80 01` |
| 2,097,152–268,435,455 | 4 | 2,097,152 → `80 80 80 01` |

**总帧长公式：`L = 1 + len_varint(remainlen) + remainlen`**。最小帧 2 字节（PINGREQ/PINGRESP：type + `00`）。

字节序（SDK `WriteUint16`/`WriteUint32`/`ReadUint16`/`ReadUint32` 逐行）：**全部多字节整数网络字节序（大端），无混写**。**字符串字段一律 u16 长度前缀 + 原始字节**（`WriteStr`：u16 BE 长度 + 字节内容，无 NUL 终止）——u16 前缀决定单字符串上界 65,535 字节。

### 3.2 消息类型总表（SDK 头文件 `edpkit.h` 消息类型定义，两副本一致）

| 消息类型 | 值 | 方向 | 语义 | 应答 |
|---|---:|---|---|---|
| CONNREQ（连接请求） | 0x10 | 设备→平台 | 连接与鉴权（两种方式） | CONNRESP |
| CONNRESP（连接应答） | 0x20 | 平台→设备 | 返回码 0–9 | — |
| PUSHDATA（转发/透传数据） | 0x30 | 双向 | 端到端透传，无应答 | **无** |
| DISCONNECT（连接关闭） | 0x40 | 设备→平台 | 主动断开（体未公开，见 §3.9） | — |
| SAVEDATA（存储数据） | 0x80 | 设备→平台（平台→设备同构） | 数据点存储上报（五种格式） | SAVEACK |
| SAVEACK（存储确认） | 0x90 | 平台→设备 | 存储结果（JSON） | — |
| CMDREQ（命令请求） | 0xA0 | 平台→设备 | 命令下发（cmdid 关联） | CMDRESP |
| CMDRESP（命令应答） | 0xB0 | 设备→平台 | 命令执行结果（cmdid 回带） | — |
| PINGREQ（心跳请求） | 0xC0 | 设备→平台 | 保活探测 | PINGRESP |
| PINGRESP（心跳应答） | 0xD0 | 平台→设备 | 保活响应 | — |
| ENCRYPTREQ（加密请求） | 0xE0 | 设备→平台 | **本版边界，不实现**（§1） | ENCRYPTRESP |
| ENCRYPTRESP（加密应答） | 0xF0 | 平台→设备 | **本版边界，不实现**（§1） | — |

### 3.3 CONNREQ / CONNRESP（SDK `PacketConnect1`/`PacketConnect2`/`UnpackConnectResp`）

**CONNREQ 方式 1（设备 ID 鉴权，连接标志 0x40）**——TCP 连接建立后设备发送的首条报文：

| 偏移 | 字段 | 宽度 | 值域/值 | 端序 | 必选 | 出处 |
|---:|---|---:|---|---|---|---|
| 0 | 消息类型 | 1B | `0x10` | — | 是 | SDK CONNREQ |
| 1 | 剩余长度 | 变长（1–4B） | `13 + len(devid) + len(apikey)` | varint | 是 | `PacketConnect1` remainlen 表达式 |
| 2 | 协议名长度 | 2B | `0x0003` | 大端 | 是 | 同上 |
| 4 | 协议名 | 3B | ASCII `"EDP"`（45 44 50） | — | 是 | 同上 |
| 7 | 协议版本 | 1B | `0x01`（SDK `PROTOCOL_VERSION`） | — | 是 | 同上 |
| 8 | 连接标志 | 1B | `0x40`（方式 1） | — | 是 | 同上 |
| 9 | 保活时间 | 2B | 秒；官方 DLL 版固定 `0x0080`（128s），2017 版参数化 | 大端 | 是 | 同上 |
| 11 | 设备编号长度 | 2B | `len(devid)`（n） | 大端 | 是 | 同上 |
| 13 | 设备编号 devid | n B | ASCII 字节 | — | 是 | 同上 |
| 13+n | 鉴权信息长度 | 2B | `len(apikey)`（m） | 大端 | 是 | 同上 |
| 15+n | 鉴权信息 apikey | m B | ASCII 字节 | — | 是 | 同上 |

（偏移按剩余长度 1 字节编码计；varint 多字节时后续字段顺延。帧内 pcap 绝对偏移 = 54/74 + 表内偏移，如 keep_time 在 IPv4 帧偏移 63。）

**CONNREQ 方式 2（用户 ID 鉴权，连接标志 0xC0）**：与方式 1 同构，差异三处——连接标志 `0xC0`；保活时间后多一组**空设备编号**（`00 00`，长度 0）；随后是 userid（u16 前缀）+ authinfo（u16 前缀）而非 devid+apikey：空设备编号长度在偏移 11–12、userid 长度 13–14、userid 15 起、authinfo 长度 15+u、authinfo 17+u（u=len(userid)）。剩余长度 `15 + len(userid) + len(authinfo)`（SDK `PacketConnect2`）。连接标志合法值仅 `0x40`/`0xC0` 两态（公开 SDK 写死；其余值按未定义处理，进负例）。

**CONNRESP（平台→设备，SDK `UnpackConnectResp`）**：`0x20` + 剩余长度 `0x02` + 标志字节 1B + 返回码 1B，总长 4 字节。返回码在偏移 3（2017 版 `EDP_UnPacketConnectRsp` 返回 `rev_data[3]`，两副本一致）：

| rtn | 含义（SDK 返回码注释原文） |
|---:|---|
| 0 | 连接成功 |
| 1 | 验证失败：协议错误 |
| 2 | 验证失败：设备 ID 鉴权失败 |
| 3 | 验证失败：服务器失败 |
| 4 | 验证失败：用户 ID 鉴权失败 |
| 5 | 验证失败：未授权 |
| 6 | 验证失败：授权码无效 |
| 7 | 验证失败：激活码未分配 |
| 8 | 验证失败：该设备已被激活 |
| 9 | 验证失败：重复发送连接请求包 |

标志字节（偏移 2）：SDK 读出后未解释、公开资料未定义语义——**按"固定 `0x00` + 假设，实现阶段实证校准"处理**。rtn≠0 时连接失败，随后按 TCP 语义关闭，不得继续发送业务报文。

### 3.4 PINGREQ / PINGRESP（SDK `PacketPing`/`UnpackPingResp`）

PINGREQ：`C0 00`（类型 + 剩余长度 0），**2 字节最小帧**。PINGRESP：`D0 00`，同为 2 字节，无消息体。设备须在保活时间（§3.3）内发出 PINGREQ，否则平台断开（保活机制由平台执行；生成器按事件序列显式编排心跳，多轮重复心跳事务合法——`edp_heartbeat_multi`）。

### 3.5 SAVEDATA（SDK `PacketSavedataJson`/`PacketSavedataBin`/`PacketSaveData`/`UnpackSavedata`）

SAVEDATA 承载数据点存储上报，消息体结构：

```text
[0]            0x80
[1..]          剩余长度（变长）
消息标志        1B：bit7(0x80)=含设备编号，bit6(0x40)=含消息编号
[若 bit7=1]    设备编号长度 u16 + devid（转发目标设备；本设备连接上报时可不带）
[若 bit6=1]    消息编号 msg_id u16 BE（关联 SAVEACK）
数据格式标志    1B：0x01–0x05（SaveDataType 枚举）
[格式≠0x02]    内容 u16 长度前缀 + JSON/字符串字节
[格式=0x02]    desc u16 长度前缀 + JSON + bin_len u32 BE + 二进制数据
```

消息标志四种组合均合法（SDK：`PacketSaveData` 有 devid 时写 0xC0（devid+msg_id）、无 devid 时写 0x40（仅 msg_id）；`PacketSavedataJson` 有 devid 时写 0x80（仅 devid）、无 devid 时写 0x00）。**标志×格式两维独立（v2.1）**：消息标志（4 组合）与数据格式（5 种）无耦合约束——任一标志组合可携带任一数据格式；交叉矩阵 4×5=20 格**全部有正例**（用例文档 §2 #8–#30），两维独立性由矩阵全覆盖承载，不设"合并杂例"。**msg_id 出处注（N2）**：kit2 `EDP_PacketSaveData` 的 msg_id 为固定常量（`MSG_ID_HIGH`/`MSG_ID_LOW`），本设计将其参数化为自由 u16 值（关联 SAVEACK）——参数化是生成器泛化而非 SDK 原生形态，实现期不得按 SDK 常量硬编码（u16 值域满值由 `edp_msgid_max` 断言）。

**方向**：SAVEDATA 设备→平台为主方向；平台→设备**同构**（§3.2；SDK `UnpackSavedata` 按同一帧结构解包——设备侧须能收下行 SAVEDATA）。fixture 以 savedata 事件 `direction` 字段生成下行同构帧（§6：`up` 默认 / `down`）：下行帧字节结构与上行全同，仅 TCP 端口互换（srcport=4472）；**下行 SAVEDATA 无应答**——SAVEACK 仅平台对上行 SAVEDATA 回带（§3.6），不臆造设备侧确认帧。

数据格式（SDK `SaveDataType` 枚举，官方 FAQ 印证 type=1/type=3 形态）：

| 值 | 类型 | 内容编码 | 内容形态 |
|---:|---|---|---|
| 0x01 | kTypeFullJson | u16 + JSON | `{"datastreams":[{"id":"<ds_id>","datapoints":[{"at":"<时间>","value":<值>}]}]}`（可含顶层 `"token"`——JSON 内容自由度，正例 `edp_savedata_type1_token`） |
| 0x02 | kTypeBin | u16 + desc JSON + u32 + bin | desc 必须含 `"ds_id"` 字段；desc/bin 上界见下方口径注 |
| 0x03 | kTypeSimpleJsonWithoutTime | u16 + JSON | `{"<ds_id>":<值>}`（平台按当前时间入库） |
| 0x04 | kTypeSimpleJsonWithTime | u16 + JSON | `{"<ds_id>":{"<时间>":<值>}}` |
| 0x05 | kTypeString | u16 + 字符串 | 裸字符串（非 JSON） |

**desc/bin 上界口径注（N1）**：SDK `PacketSavedataBin` 的检查为**严格大于**比较（`desc_len > 0x01<<16`、`bin_len > 3*(0x01<<20)`、desc 无 ds_id 三条件组包失败）——desc=65,536B、bin=3MB **恰值可通过 SDK 检查**，但恰值必然因 `WriteStr` 的 uint16 截断产生坏帧；本设计 validator 按 **wire 口径 ≥ 拒绝**（恰值即非法），恰值处与 SDK 检查的差异特此声明（负例 `edp_neg_bin_desc_over`/`edp_neg_bin_over_3mb` 按 wire 口径断言）。

数据点值域（官方 FAQ）：浮点（float）、整型（int）、字符串（string）、JSON 对象（如位置 `{"loc":{"lon":117.48,"lat":39.96}}`）。时间格式 `YYYY-MM-DD HH:MM:SS`（SDK `FormatAt` 用 strftime `"%F %T"`）。**JSON 内容长度受 u16 前缀限制，上界 65,535 字节**（`WriteStr` 的 uint16 截断语义；精确上界 65,535 与邻位 65,534 均为合法正例 `edp_json_u16_max`/`edp_json_u16_adjacent`，>65,535 进负例）。

剩余长度公式（按标志组合）：flag `0x00` JSON：`4 + len(json)`；flag `0x40`：`6 + len(json)`；flag `0x80`：`6 + len(devid) + len(json)`；flag `0xC0`：`8 + len(devid) + len(json)`；Bin 把 `(2+len(json))` 换成 `(2+len(desc)) + 4 + bin_len`（如 flag `0x00` Bin：`8 + len(desc) + bin_len`）。

### 3.6 SAVEACK（SDK `UnpackSavedataAck`）

平台对 SAVEDATA 的确认：`0x90` + 剩余长度 + 标志字节 1B + 应答 JSON 长度 u16 BE + JSON 字节。SDK 只解帧不解析 JSON 内容；应答 JSON 含回带的 `msg_id` 与结果码（公开资料形态 `{"msg_id":<原消息编号>,"err_code":0}`；err_code=0 成功 / ≠0 失败两形态均为本版 fixture 值域，`edp_saveack_err_code`）——**内容结构属"公开资料 + 假设，实现阶段实证校准"**；本版 fixture 按该形态生成并断言 msg_id 关联。

### 3.7 PUSHDATA（SDK `PacketPushdata`/`UnpackPushdata`）

端到端透传，双向同构：`0x30` + 剩余长度 `2 + len(devid) + len(data)` + 设备编号（u16 前缀；设备→平台方向为目标设备 dst_devid，平台→设备方向为来源设备 src_devid）+ **不透明原始字节 data**（SDK 原样 `WriteBytes`，无格式约束——文本与二进制载荷均合法，`edp_pushdata_binary`）。**无应答帧**（SDK 无对应函数，不臆造）。

### 3.8 CMDREQ / CMDRESP（SDK `UnpackCmdReq`/`PacketCmdResp`）

**CMDREQ（平台→设备）**：`0xA0` + 剩余长度 `2 + len(cmdid) + 4 + len(req)` + cmdid 长度 u16 BE + cmdid + req 长度 **u32 BE** + 命令内容字节。cmdid 由平台随机产生、每条命令唯一（官方 FAQ Q3：可通过 cmd_id 查询命令回复与执行状态）；req 为不透明命令字节（文本 JSON 与二进制均合法，`edp_cmdreq_binary`）；cmdid 长度受 u16 前缀上界（`edp_cmdid_long` 用 64B）。

**CMDRESP（设备→平台）**：`0xB0` + 剩余长度 + cmdid 长度 u16 BE + cmdid（**必须回带 CMDREQ 的 cmdid，关联标识**）+ [**仅当 resp_len > 0**：resp 长度 u32 BE + resp 字节]。**条件字段**：resp 为空时无 resp_len/resp，剩余长度 = `cmdid_len + 2`；非空时 = `cmdid_len + resp_len + 6`（SDK `PacketCmdResp` 三元表达式原文）。设备应答后平台侧命令状态置"执行成功"，不应答置"执行超时"（官方 FAQ Q4，不影响下发过程）。

### 3.9 DISCONNECT 与加密消息边界

DISCONNECT：2017 版 SDK 头文件定义类型值 `0x40`（连接关闭），**两副本均无组包函数**；按"公开资料 + 假设，实现阶段实证校准"取最小形态 `40 00`（类型 + 剩余长度 0，2 字节）。ENCRYPTREQ(0xE0)/ENCRYPTRESP(0xF0)：仅类型值定义，布局未公开，§1 边界声明，本版不实现、不臆造（注入该类型值走负例 `edp_neg_type_unimplemented`）。

### 3.10 每消息长度公式汇总

| 消息 | remainlen 公式 | 总长 L |
|---|---|---|
| CONNREQ 方式 1 | `13 + len(devid) + len(apikey)` | `2 + remainlen`（varint 1B 时） |
| CONNREQ 方式 2 | `15 + len(userid) + len(authinfo)` | `2 + remainlen` |
| CONNRESP | `2`（恒定） | `4` |
| PINGREQ / PINGRESP | `0` | `2` |
| DISCONNECT（假设） | `0` | `2` |
| PUSHDATA | `2 + len(devid) + len(data)` | `2 + remainlen` |
| SAVEDATA flag0x00 JSON / 0x40 / 0x80 / 0xC0 | `4+J` / `6+J` / `6+D+J` / `8+D+J` | `1 + len_varint + remainlen` |
| SAVEDATA Bin（flag0x00 / 0x40 / 0x80 / 0xC0） | `8+C+B` / `10+C+B` / `10+D+C+B` / `12+D+C+B` | 同上 |
| SAVEACK | `1 + 2 + len(ack_json)` | `2 + remainlen` |
| CMDREQ | `2 + len(cmdid) + 4 + len(req)` | `2 + remainlen` |
| CMDRESP（空 resp / 非空） | `cmdid_len + 2` / `cmdid_len + resp_len + 6` | `2 + remainlen` |

（J=len(json)，D=len(devid)，C=len(desc)，B=bin_len。帧长上界：单帧受 varint 4 字节 = 268,435,455B 理论上界；实际约束 json ≤ 65,535（u16 前缀）、desc/bin 上界见 §3.5 口径注。**kit2 公式 bug 注（N3）**：kit2 的 type2+devid 组包公式漏 devid_len（写 `12+C+B`，该分支实际写入字节含 devid）——SDK 自带 bug；本表 flag0xC0 Bin = `12+D+C+B` 为 **wire 字节核算正确值**（按 kit1 组合推导），实现期不得照抄 kit2 公式。）

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性声明**：本引擎对 EDP 采用**声明式脚本化回放**——配置是剧本（sessions[]/events[] 逐条声明），引擎是回放者，按序产出帧；"事件驱动"一词不用于定性整体行为，仅用于两处反应性成分：①**自动应答**（收到 CONNREQ/PINGREQ/SAVEDATA/CMDREQ 帧后自动补 CONNRESP/PINGRESP/SAVEACK/CMDRESP 响应帧）；②**连接边界**（事件序列中源端口切换触发新 TCP 连接，即多会话展开）。

| 现网场景 | 事务交互 | 驱动顺序 | 对应用例 |
|---|---|---|---|
| ① 设备接入（最常见：设备上电连平台） | TCP→CONNREQ(方式1)→CONNRESP rtn=0 | 设备驱动全程 | `edp_connreq_devid_ipv4`、`edp_connreq_userid` |
| ② 周期心跳（保活时间窗内） | PINGREQ→PINGRESP，2 字节最小帧 | 设备驱动，保活间隔编排（单轮/多轮） | `edp_pingreq_pingresp`、`edp_heartbeat_multi` |
| ③ 周期数据点上报（官方 FAQ：数值/位置上报） | SAVEDATA(type1–5)→SAVEACK | 设备驱动 | `edp_savedata_type*` 全格式族（§9 簇）、`edp_saveack_msgid`、`edp_saveack_err_code`、`edp_savedata_deliver`（平台→设备同构下行） |
| ④ 二进制/固件块上报 | SAVEDATA(type2：desc+u32+bin) | 设备驱动 | `edp_savedata_type2_*`、`edp_savedata_bin_empty`、`edp_mss_large_bin`、`edp_remainlen_3byte_max`/`_4byte_band` |
| ⑤ 平台命令下发（点对点控制，官方文档站典型场景） | CMDREQ→CMDRESP（cmdid 关联） | 平台发起，设备应答（自动应答成分） | `edp_cmdreq_cmdresp`、`edp_cmdresp_empty`、`edp_cmdreq_binary`、`edp_cmdid_long` |
| ⑥ 端到端透传/转发（多设备拓扑） | 设备 A→平台→设备 B，双向 PUSHDATA，无应答 | 双方各自驱动 | `edp_pushdata_upload`、`edp_pushdata_deliver`、`edp_pushdata_binary` |
| ⑦ 接入失败与重连 | CONNREQ→CONNRESP rtn≠0→连接关闭 | 设备驱动，合法错误路径 | `edp_connack_refused`（rtn=2）、`edp_connack_rtn1`（rtn=1） |
| ⑧ 完整生命周期 | 接入→上报→心跳→命令→断开，单连接多事务 | 事件编排会话 | `edp_multi_transaction_keepalive`、`edp_disconnect` |
| ⑨ 多设备并发接入 | 各设备独立事务并发交错 | `concurrent: true` 交错回放（v2.1 翻案纳入，§5） | `edp_concurrent_sessions` |

**五层覆盖逐层结论**：功能层——12 类消息中本版实现范围（10 类，ENCRYPT×2 为边界、注入走负例 63）每类正例、CONNRESP rtn 0/1/2 正例（3–9 为值域声明）、心跳单轮/多轮、SAVEACK err_code 两形态、透传/命令二进制载荷、长 cmdid、多帧粘连；每类错误分支（配置/线格式/状态机/关联/长度/载体）负例一行一注入（§7 28 行）。性能层——大 Bin 载荷跨 MSS 分段重组（`edp_mss_large_bin` 16,350B、`edp_remainlen_4byte_band` 2,097,118B、`edp_remainlen_3byte_max` 2,097,117B）、**变长长度四档双侧边界全覆盖**（127/128、16,383/16,384、2,097,151/2,097,152 六个边界值各有正例）、json 65,535/65,534 上界邻位对 + 超界负例、最小 2 字节帧、多帧粘连。数据场景层——**标志×格式 4×5 全 20 格**（两维独立声明 §3.5）、五格式值域（int/float/string/对象）、时间格式、remainlen 变长四档、bin_len=0、json 上界邻位、keep_time 满值/最小非零（默认值断言由 `edp_connreq_devid_ipv4` 的 CONNREQ hex 承载）、msg_id 满值、devid 64B 长值与 u16 上界、长 cmdid。地址与流层——IPv4/IPv6 独立 fixture（connect 与全事务）、非默认端口、单流基线、多会话双四元组、**并发会话（v2.1 翻案纳入覆盖，§5）**；**流关联（控制流派生数据流）显式不适用**：EDP 端到端转发（PUSHDATA）走同一 TCP 连接由平台中转，协议无控制流派生数据流/媒体流概念（公开 SDK 全文无副连接）；**多流（一个会话内部并发流）显式不适用**：EDP 单 TCP 连接串行收发，无连接内多流概念。**RST/异常中断显式不适用**：见 §5 异常中断声明。业务层——接入/心跳/上报/命令/透传/拒绝/生命周期/多设备并发均为现网日常（OneNET EDP 典型部署形态），优先于教科书全消息遍历；多会话与多事务（连接内先后依赖：必须先 CONNECT 成功才能上报）均覆盖。

## 5. 消息/事务模型与状态机

**事务定义**：EDP 事务 = 同一 TCP 连接内一次完整的请求/响应交互。**关联标识分两档**：①无显式 ID 的问答对——连接事务（CONNREQ→CONNRESP，TCP 连接内首对）与心跳事务（PINGREQ→PINGRESP），靠连接内一问一答配对；②显式 ID——命令事务（CMDREQ→CMDRESP，cmdid 取材与配对）、存储事务（SAVEDATA(带 bit6 消息编号)→SAVEACK，msg_id 配对）。**多事务** = 一个连接内多笔事务按序执行且有先后依赖：**CONNREQ 必须是首条业务报文且 CONNRESP rtn=0 后才允许 SAVEDATA/PUSHDATA/PINGREQ/CMDRESP**（状态机约束）；后续事务按事件序列推进。**事务交互**示例：接入→上报→命令下发应答→断开（§4⑧ 全链）；SAVEACK 的 msg_id 回指触发它的 SAVEDATA。

设备侧会话状态机（确定性：同一事件序列必然产出同一帧序列，无随机/未定义行为；生成器在某状态下遇到非法事件——如未连接先上报——必须拒绝并报状态机错误，不得静默产出）：

| 状态 | 允许事件（→目标状态） | 必须保持 |
|---|---|---|
| `Disconnected` | TCP 三次握手（→`TransportReady`） | 握手后首条业务报文必须是 CONNREQ |
| `TransportReady` | 发送 CONNREQ（→`Connecting`） | 方式 1/方式 2 二选一；连接标志与字段形状匹配 |
| `Connecting` | 收到 CONNRESP rtn=0（→`Connected`）；rtn 1–9（→`Closed`） | rtn≠0 后不得再发任何业务报文，按 TCP 关闭 |
| `Connected` | SAVEDATA（保持）、PUSHDATA（保持）、PINGREQ（保持）、收 CMDREQ→发 CMDRESP（保持）、DISCONNECT（→`Disconnecting`）、TCP FIN（→`Closed`） | cmdid/msg_id 关联正确；保活时间窗内有心跳 |
| `Disconnecting` | DISCONNECT 后 TCP FIN（→`Closed`） | DISCONNECT 后不得再发业务报文 |
| `Closed` | — | 关闭后不得产生新业务帧 |

**自动派生规则**（引擎自动补出的帧，逐条列出触发条件与内容）：①CONNRESP——connect 事件后自动补 `20 02 00 <rtn>`（rtn 默认 0，可配置）；②PINGRESP——ping 事件后自动补 `D0 00`；③SAVEACK——savedata 事件带 msg_id 且配置 ack 时自动补 `90` 帧（ack_json 回带 msg_id 与 err_code，§3.6 假设形态）；④CMDRESP——cmdreq 事件后按配置自动补 cmdid 回带的 CMDRESP（resp 空时走条件缺省形态）；⑤TCP 三次握手与 FIN 挥手由 tcp 层自动补（连接边界：源端口切换触发新连接）。每条自动帧均可被事件显式覆盖（如 rtn≠0 拒绝路径）。

**异常中断声明（v2.1）**：本协议会话终止统一走 **FIN 四帧正常挥手**（`Closed` 转移），`edp` 层**不产生 RST**——传输层异常注入面非本协议语义（与 64-cwmp R-6 同形）；生成器不在会话中途注入 RST，异常中断场景不设用例、由传输层语义承载。

**多会话展开与并发会话**：`sessions[]` 多会话展开按序整块回放——先跑完第 1 个会话全流程（握手→事件→挥手），再跑第 2 个，不交错；**第二会话包号起点 = 前一会话总包数 + 1**；各会话四元组独立、设备身份/状态互不串用。**并发会话（`concurrent: true`）纳入覆盖（v2.1 翻案，判例 cwmp⑦/doh#24/onvif#56/hl7#26/megaco#45/bacnet#47 一致口径）**：生成器级多设备并发回放**不违反**"单会话内单连接串行"的协议约束——每个会话仍是独立 TCP 连接内严格串行，并发只是多会话的回放调度方式（包总数不变、仅交错）；正例 `edp_concurrent_sessions`（双设备 concurrent:true 交错，断言 devid/msg_id/SAVEACK 上下文跨流互不串用）。

## 6. 配置 typedef（JSON 形状示例，非 Go 代码）

```json
{
  "layers": [{"tcp": {}}, {"edp": {}}],
  "src_ip": "192.0.2.72", "dst_ip": "198.51.100.72",
  "src_port": 41072, "dst_port": 4472,
  "edp": {
    "sessions": [
      {
        "src_port": 41072, "dst_port": 4472,
        "events": [
          {"kind": "connect", "auth": "devid", "devid": "123456789",
           "apikey": "kJ8mQ2xV", "keep_time": 128, "connack_rtn": 0},
          {"kind": "savedata", "direction": "up", "devid_flag": 1, "msg_id_flag": 1,
           "devid": "123456789", "msg_id": 21930, "format": 1,
           "json": "{\"datastreams\":[{\"id\":\"temp\",\"datapoints\":[{\"at\":\"2026-08-31 12:00:00\",\"value\":22}]}]}",
           "ack": true},
          {"kind": "ping"},
          {"kind": "cmdreq", "cmdid": "12345678", "req_b64": "eyJsZWQiOiJvbiJ9",
           "resp_b64": "eyJzdGF0dXMiOiJvayJ9"},
          {"kind": "disconnect"}
        ]
      },
      {"src_port": 41073, "dst_port": 4472, "concurrent": false,
       "events": [
         {"kind": "connect", "auth": "userid", "userid": "284276",
          "authinfo": "secret-auth-info", "keep_time": 128},
         {"kind": "pushdata", "direction": "up", "devid": "987654321",
          "data_b64": "R0FURVdBWTpIRUxMTw=="}
       ]}
    ],
    "wire_fault": ""
  }
}
```

形状要点：`sessions[]` = 统一术语的**事件编排会话**（每个自带四元组与事件序列；多会话展开按序整块回放，第二会话包号起点 = 前会话总包数 + 1；会话级 `concurrent: true` 改为交错回放——v2.1 翻案纳入，§5）；`events[]` = 会话的**事件序列**，kind 覆盖 `connect`（auth=devid/userid 两方式）/`savedata`（direction=up 默认/down 为平台→设备同构下行帧，§3.5；devid_flag/msg_id_flag 对应 §3.5 标志位组合，format=1–5，json 或 desc+bin_b64，ack 可配 err_code）/`pushdata`（direction=up/down，双向同构）/`cmdreq`（含 cmdid 与 req/resp，二进制载荷用 *_b64）/`ping`/`disconnect`；会话级 `coalesce: true` 时 writer 把同方向相邻小帧合并进同一 TCP 段（多帧粘连，§2 流式定界合法形态，`edp_multi_frame_segment`）；`connack_rtn`/`ack`/`resp_b64` 控制 §5 自动派生帧；`wire_fault` 仅负例注入口（**28 值枚举，与 §7 表行 1:1 同序**：`type_unknown`/`type_unimplemented`/`remainlen_mismatch`/`remainlen_truncated`/`remainlen_5byte`/`protocol_name`/`version`/`conn_flag`/`format_flag`/`bin_desc_no_dsid`/`bin_desc_invalid`/`bin_desc_over`/`bin_over_3mb`/`state_no_connect`/`state_after_reject`/`state_after_disconnect`/`cmdid`/`msg_id`/`json_invalid`/`json_over_u16`/`layer_chain`/`carrier_udp`/`port_conflict`/`auth_devid_empty`/`auth_apikey_empty`/`auth_userid_empty`/`auth_authinfo_empty`/`connack_rtn`），不得成为线上字段。**配置到帧的完整路径**：配置 → validator（层链/端口/事件序状态机/字段值域/关联完整性校验）→ planner（事件序列展开为帧序列，逐帧按 §3 公式计算 remainlen 与总长）→ worker（组包：类型 + varint + 体；自动派生帧按 §5 插入；coalesce 合并同向相邻帧）→ writer（TCP 分段承载，跨 MSS 自动分段）→ PCAP/NIC（双输出契约，§1）。

## 7. 错误处理（负例锚词表，一行一注入）

以下输入必须由 planner/validator 拒绝并传播为 task error（任务错误），不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。**28 行 = 28 个单一故障注入**（一行一注入，v1.3 原子拆分；`wire_fault` 枚举 28 值与本表 1:1 同序，§6）；**锚词为主锚词单一钉死**（注册实现时每行 `error_contains` 恰取主锚词；备选词仅作实现自由度备注，不入断言），与用例文档 §5 一一对应、同序：

| # | 负例 ID | `wire_fault` 注入口 | 故障输入 | 主锚词（备选） |
|---:|---|---|---|---|
| 62 | `edp_neg_type_unknown` | `type_unknown` | 未知消息类型值（如 `0x00`/`0x50`/`0xFF`，不在 §3.2 表内） | `type`（备选 message/unknown） |
| 63 | `edp_neg_type_unimplemented` | `type_unimplemented` | 类型在 §3.2 表内但属 §1 边界不实现（`0xE0`/`0xF0`，ENCRYPT） | `type`（备选 unimplemented/encrypt） |
| 64 | `edp_neg_remainlen_mismatch` | `remainlen_mismatch` | 剩余长度 ≠ 消息体实际字节数 | `remainlen`（备选 length/mismatch） |
| 65 | `edp_neg_remainlen_truncated` | `remainlen_truncated` | 报文截断（体短于 remainlen 声明） | `truncat`（备选 remainlen/length） |
| 66 | `edp_neg_remainlen_5byte` | `remainlen_5byte` | 变长编码第 5 字节仍置延续位（`ReadRemainlen` len_len>4） | `remainlen`（备选 varint/byte） |
| 67 | `edp_neg_conn_protocol_name` | `protocol_name` | 协议名 ≠ "EDP"（如 "EDQ"） | `protocol`（备选 name） |
| 68 | `edp_neg_conn_version` | `version` | 协议版本 ≠ 1（如 0/2） | `version`（备选 protocol） |
| 69 | `edp_neg_conn_flag` | `conn_flag` | 连接标志非 0x40/0xC0（如 0x00/0x80/0xFF） | `flag`（备选 connect） |
| 70 | `edp_neg_savedata_format` | `format_flag` | 数据格式标志不在 0x01–0x05 值域（0x00/0x06/0xFF） | `format`（备选 type） |
| 71 | `edp_neg_bin_desc_no_dsid` | `bin_desc_no_dsid` | type2 desc 无 `ds_id` 字段 | `ds_id`（备选 desc） |
| 72 | `edp_neg_bin_desc_invalid` | `bin_desc_invalid` | type2 desc 非法 JSON（截断/非对象） | `desc`（备选 json/invalid） |
| 73 | `edp_neg_bin_desc_over` | `bin_desc_over` | desc ≥65,536B（wire 口径恰值即拒；SDK 严格 > 差异见 §3.5 口径注） | `desc`（备选 length/over） |
| 74 | `edp_neg_bin_over_3mb` | `bin_over_3mb` | bin_len ≥3MB（wire 口径恰值即拒） | `length`（备选 bin/size） |
| 75 | `edp_neg_state_no_connect` | `state_no_connect` | 事件序列不以 connect 开头（首事件 savedata/ping/pushdata/cmdresp） | `connect`（备选 state/sequence） |
| 76 | `edp_neg_state_after_reject` | `state_after_reject` | CONNRESP rtn≠0 后继续排业务事件 | `state`（备选 connect/sequence） |
| 77 | `edp_neg_state_after_disconnect` | `state_after_disconnect` | DISCONNECT 后继续排业务事件（§5 Disconnecting 约束） | `state`（备选 connect/sequence） |
| 78 | `edp_neg_cmdid_correlation` | `cmdid` | cmdreq 配置的应答 cmdid 与请求 cmdid 不同值 | `cmdid`（备选 correlation/cmd） |
| 79 | `edp_neg_msgid_correlation` | `msg_id` | saveack 配置的回带 msg_id ≠ 触发 savedata 的消息编号 | `msg_id`（备选 correlation） |
| 80 | `edp_neg_json_invalid` | `json_invalid` | JSON 载荷（0x01/0x03/0x04）非法 JSON（截断/非对象） | `json`（备选 invalid/parse） |
| 81 | `edp_neg_json_over_u16` | `json_over_u16` | json >65,535 字节（u16 溢出；65,534/65,535 邻位对为正例） | `json`（备选 length/u16） |
| 82 | `edp_neg_layer_chain` | `layer_chain` | 层链缺 tcp（`[{"edp":{}}]` 直连） | `layer`（备选 carrier/tcp） |
| 83 | `edp_neg_carrier_udp` | `carrier_udp` | UDP 载体（`[{"udp":{}},{"edp":{}}]`） | `carrier`（备选 udp/layer） |
| 84 | `edp_neg_port_conflict` | `port_conflict` | 端口/载体声明矛盾（如 dst_port 与载体约束冲突、同 fixture 内端口不一致） | `port`（备选 conflict/carrier） |
| 85 | `edp_neg_auth_devid_empty` | `auth_devid_empty` | 方式 1 devid 空串 | `devid`（备选 auth/config） |
| 86 | `edp_neg_auth_apikey_empty` | `auth_apikey_empty` | 方式 1 apikey 空串 | `apikey`（备选 auth/config） |
| 87 | `edp_neg_auth_userid_empty` | `auth_userid_empty` | 方式 2 userid 空串 | `userid`（备选 auth/config） |
| 88 | `edp_neg_auth_authinfo_empty` | `auth_authinfo_empty` | 方式 2 authinfo 空串 | `authinfo`（备选 auth/config） |
| 89 | `edp_neg_connack_rtn_range` | `connack_rtn` | `connack_rtn` 取 0–9 值域外值（如 10/0xFF） | `rtn`（备选 value/range） |

**不得误报为 planner error 的合法协议事件**：CONNRESP rtn=1–9 拒绝路径（正例 rtn 0/1/2）、CMDRESP 空 resp（条件缺省合法）、PUSHDATA 无应答、bin_len=0（空二进制合法）、json 值为 0 或空字符串（业务值域内合法）、DISCONNECT 后正常挥手、非默认端口、顶层 token 字段、type5 非 JSON 裸串、下行 SAVEDATA 无应答、keep_time 满值/最小非零。只有配置、线格式、长度、状态机或关联错误进入负例。

## 8. 边界

- **变长长度四档（双侧边界）**：remainlen 0（PINGREQ 最小 2 字节帧）/ 127↔128（1↔2 字节编码边界）/ 16,383↔16,384（2↔3 字节）/ 2,097,151↔2,097,152（3↔4 字节）；解码第 5 字节即错误（§3.1）。**六个档间边界值均有正例**：`edp_remainlen_1byte_max`（127 → `7f`）、`edp_remainlen_multibyte`（128 → `80 01`）、`edp_remainlen_2byte_max`（16,383 → `ff 7f`）、`edp_mss_large_bin`（16,384 → `80 80 01`）、`edp_remainlen_3byte_max`（2,097,151 → `ff ff 7f`）、`edp_remainlen_4byte_band`（2,097,152 → `80 80 80 01`）。
- **载荷上界（含邻位对）**：JSON 内容 ≤65,535B（u16 前缀；精确上界正例 `edp_json_u16_max`、邻位 65,534 正例 `edp_json_u16_adjacent`、>65,535 负例）；type2 desc 必含 `ds_id`，上界口径见 §3.5 口径注（wire ≥ 拒绝，恰值负例）；bin_len 上界同（**bin_len=0 合法**，空二进制边界正例）。
- **大载荷跨 MSS**：bin ≥MSS 的 SAVEDATA 跨多个 TCP 段（段数 = 帧长对 MSS 上取整），接收端按 §3.1 流式定界重组，**分段边界不是 EDP 帧边界**；`edp_mss_large_bin` 用 16,350B bin（remainlen 恰 16,384）、`edp_remainlen_3byte_max` 用 2,097,117B bin（remainlen 恰 2,097,151）、`edp_remainlen_4byte_band` 用 2,097,118B bin（remainlen 恰 2,097,152，bin <3MB 内）。
- **标识符（u16 前缀族）**：devid/apikey/userid/authinfo/cmdid/ds_id 均为 u16 前缀字符串，上界 65,535B；上界与长值正例：`edp_devid_u16_max`（devid 65,535B 满值）、`edp_long_devid`（64B 长值，remainlen 141 → 2 字节 varint `8d 01`）、`edp_cmdid_long`（64B cmdid）；方式 2 的空 devid（`00 00`）为协议固定形态非缺省（空串注入走负例 85–88）。
- **CONNRESP rtn 值域**：0–9；rtn 0/1/2 有正例，rtn=3–9 为**合法值域声明**——实现期按 `connack_rtn` 配置透传（同一编码行为，负例只测值域外拒绝），不逐项设例；rtn≠0 后连接进入 Closed，不得再发业务帧。
- **keep_time**：u16 全域合法；本版默认 128（0x0080，官方 DLL 版固定值，默认值断言由 `edp_connreq_devid_ipv4` 的 CONNREQ hex 承载）、满值 0xFFFF（`edp_keep_time_boundary`）、最小非零 1（`edp_keep_time_min`）；keep_time=0 的平台侧语义未公开，本版 fixture 不使用 0。
- **标志×格式矩阵**：4×5=20 格全正例（两维独立声明 §3.5，用例文档 §2 #8–#30）。
- **v4/v6**：IPv4/IPv6 独立 fixture（connect 与全事务各一），同一逻辑 EDP 报文字节必须一致，仅外层 IP 头与偏移（54/74）不同；不得从 IPv4 默认值推导 IPv6 地址。
- **端口**：默认 4472；非默认端口为正例（§2 端口变体声明，`edp_port_nondefault`），planner 不得静默改写。
- **多会话/并发**：多会话展开（≥2 个独立四元组，devid/状态/序号互不串用；第二会话起点 = 前会话总包数 + 1）与并发会话（`concurrent: true` 交错，§5 翻案纳入）均覆盖。
- **RST/异常中断**：显式不适用（§5 异常中断声明：FIN 统一挥手、不产生 RST）。
- 不得产生回绕长度或超量分配（varint 4 字节上界 268,435,455；受 json/bin 实际约束远低于此）。

## 9. 原子 ID 与完成定义（簇级）

**ID 权威（v1.3 行为面全枚举）**：语义用例 ID 清单以**用例文档 §2 为唯一权威**（v2.1 起按可测试行为面全枚举扩量：**89 条 = 61 正例 + 28 负例**，对应 rr-edp 行为面枚举 ~125 点、0.7+ 例/点——doh 111/onvif 95 同档）；本节不再维护 ID 逐条表（v2.0.x 的 39 ID 表见 git 历史）。设计、用例文档与未来 `edp.json` 使用同一组唯一 ID 与顺序；当前 JSON 另有不计入的 `edp_neg_unregistered` 占位。**正例簇**：①接入族——方式 1/方式 2/rtn 0/1/2/非默认端口/keep_time 满值/最小非零/devid 64B 与 u16 满值；②心跳族——单轮/多轮；③存储族——标志×格式 4×5 全 20 格、五格式值域（int/float/string/对象/时间键）、type1 token 变体、bin_len=0、下行同构方向、SAVEACK 关联与 err_code≠0、msg_id 满值、json 65,535/65,534 邻位对；④透传族——上行/下行/二进制载荷；⑤命令族——resp 非空文本/空 resp/二进制/长 cmdid；⑥编码边界族——remainlen 四档双侧六个边界值、MSS 分段（12 段/1,437 段）；⑦结构族——DISCONNECT、多帧粘连；⑧场景族——多事务全链、IPv4/IPv6（connect 与全事务）、多会话展开、并发会话。**负例簇**：§7 表 28 行逐单一故障注入（类型 2/remainlen 3/连接协议 3/格式 1/desc-bin 4/状态机 3/关联 2/json 2/载体 3/鉴权 4/rtn 1）。

完成定义：注册 `tcp→edp` 层链；逐字段生成并验证 §3 全部 10 类消息（含剩余长度变长编码、五数据格式 × 四标志组合全 20 格）；CONNECT 两方式、CONNRESP rtn=0 与代表性 rtn≠0 路径（正例 rtn 0/1/2；rtn=3–9 为值域声明，实现期按 `connack_rtn` 透传、值域外由负例 89 拒绝）、心跳（单轮/多轮）、存储+确认（msg_id 关联、err_code 两形态）、透传双向（含二进制载荷）、命令（cmdid 关联、条件缺省、长 cmdid、二进制载荷）、DISCONNECT、多事务、多会话展开与并发会话、多帧粘连、IPv4/IPv6、非默认端口、MSS 分段与全部边界（含四档双侧边界值与 json 邻位对）均可观测；用例文档 §2 全量语义用例（现 89 条 = 61 正 + 28 负）正负断言与错误传播完成；未注册阶段只接受 `unknown layer` 占位。

## 10. 修订记录

- v2.1.0（2026-09-02）：按《需求文档 v1.3》rr-edp 重审（8C+5N，报告 /tmp/edp_v13/report.md）修复：C-1 §1 双输出契约；C-2 §5/§6 并发会话翻案纳入（判例 cwmp⑦/doh#24/onvif#56/hl7#26/megaco#45/bacnet#47）+ `edp_concurrent_sessions`；C-3 §5 RST/异常中断声明（FIN 统一、不产生 RST，cwmp R-6 同形）；C-4 §2 端口变体声明 + `edp_port_nondefault`（12472）+ 无 DecodeAs 依赖声明；C-5 §7 负例 12 → 28 行原子拆分（一行一注入；原族式合并 3–4 故障/行拆净）、§6 wire_fault 枚举 28 值 1:1 同序、锚词改"主锚词钉死（备选括注）"；C-6 §8/用例补边界相邻值族（127/16,383/2,097,151 各档上界、json 65,534、devid u16 上界 65,535——四档双侧边界值齐全）；C-7 占位 JSON 三处对齐（dst 4472/src 41072/notes 计数）；N1 §3.5 desc/bin 上界 SDK 严格 > 与 wire ≥ 口径差异声明；N2 §3.5 kit2 msg_id 固定常量出处注（本版参数化为泛化）；N3 §3.10 kit2 type2+devid 公式漏 devid_len（SDK bug）注——本表 12+D+C+B 为 wire 正确值；N4 §3.5 标志×格式两维独立声明 + 4×5 全 20 格正例；N5 rtn=1 正例（rtn 3–9 维持值域声明）。配套用例文档 v2.1.0：39 → 89（61 正 + 28 负），ID 权威改用例文档 §2、本文 §9 改簇级。状态：已按清单修复，待审查方复验关闭。
- v2.0.1（2026-09-01）：按独立隔离审查 9 项问题清单（4 MAJOR + 5 MINOR）修复：E01 用例 `edp_datapoint_value_types` `tcp.len` 344→345；E02 +`edp_remainlen_4byte_band`、multibyte 改 128、mss_large_bin 改 16,384 档下界、§4/§8 四档对齐；E03 rtn 值域声明；E05 负例补 DISCONNECT 后注入；E06 keep_time 默认值断言由用例 1 承载；E07 +`edp_json_u16_max`；E08 token 范围外声明（v2.1 由正例取代）；E09 +`edp_savedata_deliver`（§3.5 方向段、§6 direction 字段）。ID 36→39。
- v2.0.0（2026-09-01）：按需求文档 v1.1 独立隔离审查流程重写，取代 2026-08-21 臆造旧稿（40B 帧头/magic EDP1/CRC32/REGISTER-HEARTBEAT-TELEMETRY、端口 9847 全部废弃）；以 EdpKit SDK 两副本 + 官方文档站为基线重新提炼线格式（v1.3 重审 SDK 回对 0 缺陷）。
- v1.0.0（2026-08-21）：旧稿首版（臆造线格式，全部废弃）。

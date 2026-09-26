# Stratum（比特币 Stratum v1，矿机-矿池工作分配）设计契约

> 版本：v1.0.0（P1–P3 文档轨产物；#89 stratum）
> 日期：2026-09-27
> 车道：并发管线车道 A（文档轨）｜协议号：**89**（ledger 队列位；文件按管线序 `89-stratum-*.md`）
> 配套文件：`docs/protocol-designs/89-stratum-testcase.md`、`trafficgen/test/protocol_pcap/cases/stratum.json`（现存 40 例：29 正 + 11 负）
> 旧基线：`75-stratum-design/testcase.md` v2.1.1（2026-09-01，40 例 29+11，行为面全枚举重审修复轮产物）——本契约逐节比对保留全部条目（§10.2），未删任何原有条目；改动仅四类：①文件号 75→89；②目标形状纯 layers 化 + 去向表；③新增 §10–§14；④packet_count 双勘误（§9）。
> 规范基线：Bitcoin Wiki《Stratum mining protocol》（方法签名/params 位置语义/notify 九参/submit 五参/set_extranonce 双参/extranonce1-2 语义/clean_jobs 语义，唯一成文方法学规范）+ BIP310《Stratum Protocol Extensions》（`mining.configure`/TMask/version-rolling 交集/`mining.set_version_mask`/submit 第 6 参）+ slush0/stratum-mining 参考实现（订阅构成/submit 签名/notify 发射序/prevhash 反转/extranonce1 大端计数/coinbase 占位 8B）+ zone117x/node-stratum-pool 参考实现（错误三元组 20–25 字面值与检查序）+ 公开资料假设（端口/文案大小写/extranonce1 长度/内部小端序/首 job 时序，实现阶段实证校准，G-ST-5）+ 本机 tshark 3.6.14 实测（§1 基线表）。
> **层链唯一真相**：本契约全文示例只有纯 `layers` 形——地址只住 `ip` 层（`src`/`dst`；IPv6 同住 `ip` 层，仓库无 `ipv6` 层）、端口只住 `tcp` 层（`src_port`/`dst_port`）、数量只走 `flow_control`；顶层只允许 `layers`/`flow_control` 家族/`output`（CORE_MEMORY §1.11–1.13）。任何顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/`stratum` 子映射都判违规（存量 40/40 混用形见 §12.1，P4 整形 G-ST-1）。
> **注册现状**：`stratum` 层**已注册**（`layers/registry.go:530-533`，`CategoryTerminal` + `DependsOn ["tcp"]` + `FieldContract {"tcp.dst_port":"3333"}`），且 `allowedProtocols["stratum"]=true`（`core/protocols.go:77`）、`NewChainPlanner("stratum")` 已在 `cmd/server/main.go:534` 注册（空导入 `:179`）、`spec.Stratum`（`types.go:1709`）+ Meta 直传（`chain_planner_translate.go:193`）+ FlowMeta（`generator.go:543`）已接线。本文**不宣称本次跑过 suite、不启动服务器**；所有"已落码/未落码"结论均标实测出处。
> **与 73-ethmining / 76-getwork 的关系（裁定 ST-A，§10.6）**：stratum = 主协议；ethmining = **同族异协议**（非 dialect 变体）；getwork = 另一载体协议（HTTP JSON-RPC）。互为对方的方言负例，见 §3.12。

---

## 1. 范围、profile 和未注册边界

本版定义矿机（miner）与矿池（pool）之间的 **比特币 Stratum v1 明文 TCP 长连接**：行分隔 JSON（每行一个 JSON 对象，行尾单个 LF `0x0a`）消息封装、订阅（`mining.subscribe`）、extranonce 订阅（`mining.extranonce.subscribe`）、授权（`mining.authorize`）、难度通知（`mining.set_difficulty`）、任务通知（`mining.notify` 九参）、extranonce 轮换（`mining.set_extranonce` 双参）、share 提交（`mining.submit` 五参）与提交响应三态、矿池侧反向消息（`client.get_version` 请求/响应、`client.show_message` 通知）、BIP310 扩展（`mining.configure`/`mining.set_version_mask`/version-rolling 第 6 参提交）、错误三元组、JSON-RPC `id` 关联、IPv4/IPv6、多会话与多事务。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `stratum_v1`（主 profile） | TCP 明文行式 JSON（fixture 端口 3333，可配置覆盖） | 7 类 `mining.*` 消息 + `client.get_version`/`client.show_message`、行重组、id 关联、share 三态、错误三元组 | 真实 share 密码学有效性、区块产生、真实矿池鉴权、难度与真实网络 target 的对应关系 |
| `stratum_ipv6_v1` | 同上，仅外层 IPv6 | 同主 profile | 从 IPv4 fixture 推导 IPv6 地址（fixture 显式给出 `2001:db8::75 → 2001:db8::100:75`） |
| `stratum_bip310_ext` | 主 profile + BIP310 扩展（由配置 `extensions` 声明，非独立层链） | `mining.configure`/`mining.set_version_mask`/version-rolling submit 第 6 参 `version_bits` | 未声明的其他扩展（`minimum-difficulty`/`subscribe-extranonce`/`info`，编码同 configure 结果映射，不逐个设例） |

显式边界（"不实现、不声称、不许静默转换"）：**Stratum V2**（二进制分帧、`mining.set` 族）不在本版，混入进负例；**`client.reconnect`**（传输层重定向语义，超出脚本化回放单会话边界）不实现；**`mining.suggest_difficulty`/`mining.suggest_target`**（矿池可不响应的自由裁量请求）不实现；**`mining.get_transactions`**（已被主流矿池移除的 legacy 方法）不实现，混入按未知 method 拒绝（负例锚 `unknown`）；**`mining.capabilities`/`mining.set_goal`**（wiki 标注 DRAFT）不实现；不声称任何 share 满足真实比特币 target 或产生区块（生成器不执行 PoW，share 内容为 fixture 声明值）。

**输出契约（pcap/NIC 双输出）**：本契约的用例同时服务于 pcap 与 port_group/NIC 两种输出路径——两路径共用同一份 cases JSON、同一 tshark 字段/帧字节断言，不设仅单路径可用的断言。逐项：① pcap = 离线文件，断言走 `tcp.payload` 全行 hex + offset 54/74 frames + `tcp.len`/`tcp.stream`；② NIC = port_group 网卡输出（实测口 enp135s0f0np0），经 tcpdump 捕获后以同一断言集核验——**NIC checksum offload 可能使 IP/TCP 校验和不同，本协议断言不含校验和字段，不受影响**；③ 大 coinb1 跨 MSS 行两路径均按 `tcp.stream` 重组后断言完整行；④ 多会话/并发在 NIC 路径以 `tcp.stream` distinct 区分；⑤ IPv6 NIC 抓包不引入 VLAN 偏移（fixture 无 VLAN，offset 74 两路径一致）；⑥ 粘行段两路径同为单段两行、段内 LF 计数一致。

**TSHARK 实测基线（本机 3.6.14，`-G fields` 核验）**：含 "stratum" 的字段 17 行**全部无关**（`ntp.stratum` NTP 层级、`ptp.*stratum` 时钟层级、`lte-rrc.accessStratumRelease*`、`nas-5gs/nas-eps Non-Access-Stratum`、`s1ap/hnbap/rrc/nr-rrc` 层级——实证输出在案），**不得使用任何 `stratum.*` 字段**。通用 JSON dissector 在裸 TCP 上不自动解析且不可 decode-as，`json.*` 字段不可用。可用断言通道（实测存在 11 字段）：`tcp.payload`（FT_BYTES，单段不跨段时即完整行含行尾 `0a`）、`tcp.len`、`tcp.srcport`、`tcp.dstport`、`tcp.stream`、`tcp.flags.reset`、`tcp.flags.fin`、`ip.version`、`ipv6.nxt`、`frame.number`、`frame.len` + `frames` 数组 `offset/hex` 断言（行首 `{`=`7b` 起点 IPv4 offset 54 / IPv6 offset 74）。

---

## 2. 推荐配置、层链与事件形状

唯一合法链形：**`[ip, tcp, stratum]`**（IPv6 地址族同住 `ip` 层，不新增层）。`stratum` 是**终结层**（`CategoryTerminal`），`Fields` 为空（生成表 `/layers => {"category":"terminal","depends_on":["tcp"],"field_contract":{"tcp.dst_port":"3333"},"fields":{}}` 实测）——协议配置今日经 `spec.Stratum`（顶层 `"stratum"` 子映射，`strategy_convert.go:625-627`）注入 + drive 经 Meta 直传（`chain_planner_translate.go:193`，外层函数 `drive` :44 起），层 config 恒空；3333 端口经 FieldContract 供通用应用补齐。

> **目标形状缺口（1.9 标注）**：上例纯 layers 形**今天跑不通，需先补代码**——层内 stratum 条目无翻译路径（`translateTerminalConfig` 无 `case "stratum"`，且 Fields 空在 `:756` 早返）→ 层内配置到不了 `spec.Stratum`（P0b 缺省流兜底，只出基线订阅会话）。P4 必办见 G-ST-1（加 `case "stratum"` + 严格解码 + flat/层并存优先级裁定）。

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.75", "dst": "198.51.100.75"}},
    {"tcp": {"src_port": 4075, "dst_port": 3333}},
    {"stratum": {"sessions": [
      {"src_port": 4075, "events": [
        {"kind": "subscribe", "id": 1, "user_agent": "MinerName/1.0.0",
         "extranonce1": "ea02567c", "extranonce2_size": 4},
        {"kind": "authorize", "id": 2, "username": "alice.rig1", "password": "x", "result": true},
        {"kind": "set_difficulty", "difficulty": 16384},
        {"kind": "notify", "job_id": "3",
         "prevhash": "b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5c43402000000000000000000",
         "coinb1": "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1603aa1a0b2f706f6f6c2e746573742f",
         "coinb2": "1603018e0c2f706f6f6c2e746573742f00000000",
         "merkle_branch": ["aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233"],
         "version": "20000000", "nbits": "a13c2c17", "ntime": "64f50123", "clean_jobs": false},
        {"kind": "submit", "id": 3, "username": "alice.rig1", "job_id": "3",
         "extranonce2": "1a2b3c4d", "ntime": "64f50123", "nonce": "9c5a2b1d"}
      ]}
    ]}}
  ],
  "flow_control": {"flows": 1}
}
```

> **`tcp.dst_port` 不写时**：由 `stratum` 层 `FieldContract {"tcp.dst_port":"3333"}`（`registry.go:532`）经通用 FieldContract 应用补齐；用户显式写端口时以显式值为准（非默认 4444 见 G-ST-3，P4 实测链内显式值是否被契约拒）。

### 2.1 层内配置键（**唯一权威 = registry `Fields`，实测 0 键**）

stratum 层 `Fields` 为空——层 config 恒 `{}`，全部协议配置走 `spec.Stratum`（`StratumConfig`，`core/stratum.go:13-30`）：`concurrent`（交错回放开关）/`profile`（信息性，生成器零读取）/`extensions`（BIP310 声明）/`sessions[]`/`wire_fault`（11 值，负例唯一注入口，非线上字段）。

### 2.2 事件形状与「静默丢弃键」清单（P4 必办，实测）

`StratumEvent` 是 Go struct（`core/stratum.go:46-93`，36 键）；`buildEventLines`（`layer_gen.go:170-339`）实际消费除 3 键外的全部事件键：

| 事件键 | 被消费？ | 消费点 / 备注 |
|---|---|---|
| `kind`/`id`/`pack_next` | ✅ | `layer_gen.go:171/107` switch 与粘连 |
| `user_agent`/`extranonce1`/`extranonce2_size`/`subscriptions` | ✅ | `:172-190`（缺省 → `FixtureSubsS1`/`FixtureExtranonce1`/size 4） |
| `username`/`password`/`result` | ✅ | `:198-218`（`result:false` → 错误 24 响应） |
| `difficulty` | ✅ | `:220-221` |
| `job_id`/`prevhash`/`coinb1`/`coinb2`/`merkle_branch`/`version`/`nbits`/`ntime`/`clean_jobs` | ✅ | `:223-254`（缺省 → 全套 fixture；`merkle_branch` nil → 单步） |
| `extranonce1`+`extranonce2_size`（set_extranonce） | ✅ | `:256-266`（缺省 → `b3f10a44`/8） |
| `extranonce2`/`nonce`/`version_bits` | ✅ | `:268-309`（缺省 → 按当前尺寸 fixture；vr 激活缺省 `18000000`） |
| `params`/`cfg_result`（configure） | ✅ | `:325-330`（缺省 → `FixtureCfgParams`/`FixtureCfgResult`） |
| `mask`/`message` | ✅ | `:331-336` |
| **`version_rolling_mask` / `min_bit_count`**（configure 事件） | ❌ **静默丢弃** | struct 无此键；`parseSubconfigJSON` 用 `json.Unmarshal` **无 `DisallowUnknownFields`**（`strategy_convert_helpers.go:21` 实测）→ 存量 `stratum_configure_version_rolling` 携带，双线字节仍由缺省 `FixtureCfgParams` 产出 → G-ST-2 |
| **`termination`**（stratum 级） | ❌ **静默丢弃** | struct 无此键；存量 `stratum_rst_pool_kick` 用 `stratum.termination:"rst"` + tcp 层 `rst:true` 双键 → 定归属（tcp 层 `rst` 已有登记，stratum 级疑冗余）→ G-ST-2 |
| **`profile`**（stratum 级） | ❌ 配上不生效 | struct 有键但生成器零读取（`layer_gen.go` 无 `.Profile`）；存量 40 例**零携带** → 不删 struct，但契约点名 |

> 声明：`profile`/`subscriptions` 缺省走 fixture 同源默认（"缺省=合法形态的协议"）→ 相关故障只能走注入通道，不进自然守卫。

### 2.3 并发与终止键（tcp 层，registry 有登记）

`concurrent`（`registry.go:75`，事件按 SrcPort 维护并发连接）/`rst`（`:72`，RST 短路）/`termination`（`:71`）均为 tcp 层合法键——存量 `concurrent_sessions`（tcp `concurrent:true` + stratum `concurrent:true` 双键）与 `rst_pool_kick`（tcp `rst:true` + stratum `termination:"rst"` 双键）**不是**游离键。P4 整形时 stratum 级 `concurrent` 保留（`StratumConfig.Concurrent` 有 struct 键，生成器 round-robin 消费 `layer_gen.go:116-137`），stratum 级 `termination` 按 G-ST-2 裁定去留。

---

## 3. 线格式权威（逐字段，P4 builder 硬对照表）

### 3.1 行式组帧与 JSON 序列化规则

- **消息边界**：每行 = 一个完整 JSON 对象 + 行尾单个 LF（`0x0a`）。行内不得出现未转义控制字符；CR（`0x0d`）不属于本协议（CRLF 进负例）。
- **JSON 形态**：线上字节钉死为**紧凑形态**（成员间无空格）；成员顺序钉死——请求/通知 `id,method,params`，响应 `id,result,error`。
- **`id` 取材与配对**：请求 `id` 为 JSON number，**由矿机迭代、会话内唯一、起点任意**；矿池响应必须按 `id` 值配对，不得按 TCP 位置配对。通知与 `client.show_message` 的 `id` 恒为 `null`，不得写成伪值（伪 id 进负例）。矿池侧反向请求（`client.get_version`）的 `id` 由矿池侧自选，矿机响应同值回带。
- **响应形状**：`{"id":<同值>,"result":<成功载荷或 false>,"error":<null 或错误三元组>}`。错误三元组 = `[<code 数值>, <message 字符串>, <traceback|null>]`（fixture 恒 `null`）。
- **hex 字段编码**：全部 hex 数据字段为 ASCII 十六进制字符串，**小写、无 `0x` 前缀、偶数长度**（比特币 stratum **不存在** `0x` 方言，带前缀即非法，进负例）。校验见 `planner.go:242-262`（`checkHexField`：前缀/奇偶/字符集/定宽四检）。
- **字节序声明（逐字段）**：`prevhash` 为 32 字节区块哈希的**内部字节序（展示序逐字节反转）**——参考实现 `block_template.py` `util.reverse_hash` 显式反转；fixture 对 `0000000000000000000234c4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4` ↔ `b4a3f2e1…00000000` 实证 `db[::-1]==wb` True。`version`/`nbits`/`ntime`/`nonce` 为 4 字节值内部（小端）hex 形态（⑤公开资料口径，实现阶段实证校准 G-ST-5）；其余 hex 字段为原始字节序，无反转。
- **difficulty 序列化**：JSON number，**钉死十进制定点表示**（`16384`/`32768`），**禁止科学计数法**。
- **行长公式**：`L(line) = <固定常量> + Σ len(可变字段)`（含行尾 LF），逐消息固定常量见 §3.13（19 值逐字节复算全中，脚本见报告 §3 R2）；无协议级行长上界，实际受 TCP 流与生成器缓冲约束。

### 3.2 消息总表（方法 / 方向 / params / 应答）

| 消息 | 方向 | id | params（位置语义） | 应答 |
|---|---|---|---|---|
| `mining.subscribe` | 矿机→矿池 | number | 1 元素：[0] 矿机名/版本（wiki 另载可选 [1] 会话恢复 extranonce1，fixture 不用） | 订阅响应（§3.3） |
| `mining.extranonce.subscribe` | 矿机→矿池 | number | 0 元素 `[]` | `result=true` |
| `mining.authorize` | 矿机→矿池 | number | 2 元素：[0] 用户名（账号.矿机名），[1] 密码 | `result=true` 或 `false + error[24]` |
| `mining.set_difficulty` | 矿池→矿机 | `null` | 1 元素：[0] difficulty（number；作用于**后续到达的 job**） | 无 |
| `mining.notify` | 矿池→矿机 | `null` | **9 元素**：job_id/prevhash/coinb1/coinb2/merkle_branch/version/nbits/ntime/clean_jobs | 无 |
| `mining.set_extranonce` | 矿池→矿机 | `null` | **2 元素**：[新 extranonce1, 新 extranonce2_size]；对**后续 job** 生效；**1 元素形态为 ethash 方言，混入进负例** | 无 |
| `mining.submit` | 矿机→矿池 | number | **5 元素**：用户名/job_id/extranonce2/ntime/nonce；version-rolling 激活时追加第 6 参 version_bits | 提交响应三态（§3.9） |
| `client.get_version` | **矿池→矿机** | number | 0 元素 `[]`；**方向反转**，矿池为请求方 | 矿机响应 `result=<版本串>` |
| `client.show_message` | 矿池→矿机 | `null` | 1 元素：人读消息字符串 | 无 |
| `mining.configure` | 矿机→矿池 | number | 2 元素：[扩展名数组，扩展参数映射]（BIP310） | 结果映射（§3.11） |
| `mining.set_version_mask` | 矿池→矿机 | `null` | 1 元素：[新 TMask]；**立即生效** | 无 |

**方向违例**：矿机侧发通知（notify/set_difficulty/set_extranonce/set_version_mask/show_message）、矿池侧发请求（subscribe/authorize/submit/configure）均为线格式/方向错，进负例（锚 `unknown`）。`client.get_version` 是唯一矿池→矿机的请求方向。

### 3.3 `mining.subscribe` 请求/响应

请求：`{"id":1,"method":"mining.subscribe","params":["MinerName/1.0.0"]}\n`（66B 实测）。
响应：`{"id":1,"result":[[["mining.set_difficulty","7f1a2b3c"],["mining.notify","9d8e7f6a"]],"ea02567c",4],"error":null}\n`（114B 实测）——**双订阅对**（set_difficulty 在前 notify 在后；ethash 仅单 notify 对）；extranonce1（fixture 4B/8hex，公开矿池 2–8B 均有⑤）；extranonce2_size（参考实现 8−4=**4**；fixture 基线 4、边界 8）。

### 3.4 `mining.extranonce.subscribe`

请求 `{"id":2,"method":"mining.extranonce.subscribe","params":[]}\n`（60B）；响应 `{"id":2,"result":true,"error":null}\n`（36B）。该请求为 `mining.set_extranonce` 的触发前提；不支持路径为矿池自由裁量，fixture 不产生。

### 3.5 `mining.authorize` 请求/响应

请求 `{"id":2,"method":"mining.authorize","params":["alice.rig1","x"]}\n`（65B）。成功 `{"id":2,"result":true,"error":null}\n`（36B）；拒绝 `{"id":2,"result":false,"error":[24,"Unauthorized worker",null]}\n`（64B；文案 fixture 钉 wiki 标题形态，node 实现小写并存⑤，G-ST-5）。**authorize 必须发生在 submit 之前**（检查序：未订阅 25 → 未授权 24）。

### 3.6 `mining.set_difficulty` 通知

`{"id":null,"method":"mining.set_difficulty","params":[16384]}\n`（62B）。规则：①变更**作用于后续到达的 job**；②矿池可随变更立即推 clean=true 新 job（fixture 不产生）；③difficulty 为 number（16384/32768，整数定点）。**未发 set_difficulty 直接 notify**：wiki 无 MUST 条款，公开矿池现实存在——**未约束自由度**，validator 不设约束、不设例。

### 3.7 `mining.notify` 通知

九元素语义（wiki 九字段原文 + 参考实现 `subscription.py` 发射序）：job_id（关联键，现网数字串 `"3"`/`"4"`）/ prevhash（64hex，**内部字节序**）/ coinb1（世代交易前段，extranonce 插其后）/ coinb2（后段）/ merkle_branch（hex 数组，**可为空**）/ version（8hex）/ nbits（8hex）/ ntime（8hex，滚动合法但 fixture 恒回带）/ clean_jobs（boolean：true 立即切 / false 尽快切）。订阅后首 job 时序（参考实现立即推 clean=true）为⑤标注时序，fixture 取"授权后推任务"标准线序，不设例。

### 3.8 `mining.set_extranonce` 通知

`{"id":null,"method":"mining.set_extranonce","params":["b3f10a44",4]}\n`（69B）。规则：①2 元素，对后续 job 生效（正例 9：轮换 4→8 + 后续 submit 16hex）；②触发前提 = 已发 extranonce.subscribe（fixture 恒先发，validator 不强制）；③**1 元素形态为 ethash 方言，混入进负例**。

### 3.9 `mining.submit` 请求与响应三态

请求 95B（五参）。**extranonce2 长度硬校验**：hex 字符数 = 2 × 当前 extranonce2_size（`planner.go:142-150`，`currentEn2Size:205-222` 与生成器同源缺省 subscribe→4/set_extranonce→8）。响应三态：接受（36B `result:true`）/ 拒绝（58B `result:false + error[21,"Job not found",null]`，**会话继续**）/ 其他错误（三元组结构完整，会话继续；fixture 不产生非 21 码）。

**错误码表**：20 `Other/Unknown` / 21 `Job not found`（stale）/ 22 `Duplicate share` / 23 `Low difficulty share` / 24 `Unauthorized worker`（先订阅后授权检查序）/ 25 `Not subscribed`。文案 fixture 钉 wiki 标题形态（⑤）。

### 3.10 `client.*` 反向消息

- **`client.get_version`**：矿池请求 51B（id=8）→ 矿机响应 49B（`result:"MinerName/1.0.0"`，同 id 回带）——**自动应答成分**（`layer_gen.go:311-320`）。
- **`client.show_message`**：矿池通知 82B（id=null，无应答）。
- **`client.reconnect`**：不实现。

### 3.11 BIP310 扩展

- **`mining.configure`**：请求 139B（`[["version-rolling"],{"version-rolling.mask":"ffffffff","version-rolling.min-bit-count":16}]`）→ 响应 90B（`{"version-rolling":true,"version-rolling.mask":"1fffe000"}`，交集 = server & miner）。未知扩展返回 `false`（fixture 恒支持路径）。
- **TMask**：**8 字符大小写不敏感 hex**；≠8 进负例。
- **`mining.set_version_mask`**：69B（`["00003000"]` verbatim），**立即生效**（与 set_difficulty/set_extranonce 的"后续 job 生效"不同）。
- **submit 第 6 参**：激活后必须追加 `version_bits`（106B 行，`18000000` ⊆ `1fffe000` ⊆ `ffffffff`）；约束 `version_bits & ~last_mask == 0`；**未激活时第 6 参非法**（`planner.go:157-164`，负例锚 `params`）。

### 3.12 与 73-ethmining / 76-getwork 的区分（不混装）

| 维度 | 本协议 | 73-ethmining | 76-getwork |
|---|---|---|---|
| notify 参数 | **9 元素** | 4 元素 | 无通知（轮询） |
| submit 参数 | **5 元素**（rolling 时 6） | 3 元素 | `eth_submitWork` 三参 |
| 工作构造 | coinbase 两段 + merkle 树 | 无 coinbase/merkle | 服务端全量工作对象 |
| extranonce | 双段（[1] 段 + [2] 尺寸） | 单段 ≤3B + minernonce 互补 | 无 |
| prevhash/seedhash | 32B **字节反转** | 32B 无反转 | — |
| set_extranonce | **2 元素** | **1 元素** | — |
| 扩展 | BIP310 configure/version-rolling | NiceHash extranonce 扩展 | — |
| 难度先行 | 无 MUST | 难度 1 兜底 MUST | — |
| 载体 | TCP 明文行式（3333） | TCP 明文行式（4444） | HTTP JSON-RPC（8545） |

跨协议方法混入（ethash 1 参 set_extranonce、GetWork `eth_getWork`）按未知方法/方言参数拒绝（负例锚 `unknown`/`params`）。

### 3.13 每消息行长公式汇总（固定常量逐字节复算全中）

| 消息 | 行长公式（B，含 LF） | fixture 样例长 |
|---|---|---:|
| subscribe 请求 | `50 + len(id) + len(user_agent)` | 66 |
| subscribe 响应 | `88 + len(id) + len(对1) + len(对2) + len(en1) + len(size 串)` | 114 |
| extranonce.subscribe 请求 | `59 + len(id)` | 60 |
| 响应 true（通用） | `35 + len(id)` | 36 |
| authorize 请求 | `53 + len(id) + len(user) + len(pass)` | 65 |
| authorize 响应 false | `42 + len(id) + len(code) + len(msg)` | 64 |
| set_difficulty | `57 + len(difficulty 串)` | 62 |
| notify | `75 + len(job_id) + 64 + len(coinb1) + len(coinb2) + Σmerkle + 8+8+8 + len(clean 串)` | 387 |
| notify（空 merkle，clean=true） | `73 + len(job_id) + 64 + len(coinb1) + len(coinb2) + 8+8+8 + 4` | 320 |
| set_extranonce | `60 + len(en1) + len(size 串)` | 69 |
| submit 请求 | `59 + len(id) + len(user) + len(job) + len(en2) + len(ntime) + len(nonce)` | 95 |
| submit 响应 false | `42 + len(id) + len(code) + len(msg)` | 58 |
| submit（6 参） | `62 + len(id) + len(user) + len(job) + len(en2) + len(ntime) + len(nonce) + len(vbits)` | 106 |
| client.get_version 请求 | `50 + len(id)` | 51 |
| client.get_version 响应 | `33 + len(id) + len(version 串)` | 49 |
| client.show_message | `57 + len(msg)` | 82 |
| mining.configure 请求 | `43 + Σ(len(扩展名)+4) + Σ(len(键)+9+len(值))` | 139 |
| mining.configure 响应 | `31 + len(id) + len(映射文本)` | 90 |
| mining.set_version_mask | `61 + len(mask)` | 69 |

## 4. 业务场景分析

**定性声明**：**声明式脚本化回放**——配置是剧本（sessions[]/events[] 逐条声明），引擎是回放者；"事件驱动"仅用于两处反应性成分：①**自动应答**（subscribe/authorize/extranonce.subscribe/submit 后自动补同 id 响应；`client.get_version` 到达后自动补矿机响应）；②**连接边界**（源端口切换触发新 TCP 连接，即多会话展开）。

| 现网场景 | 事务交互 | 驱动顺序 | 对应用例 |
|---|---|---|---|
| ① 矿机接入 | TCP→subscribe→订阅响应→authorize→授权响应 | 矿机驱动，矿池自动应答 | #1/#3/#2 |
| ② 鉴权拒绝 | authorize→`false + error[24]`（合法路径） | 矿机驱动，矿池拒绝 | #4 |
| ③ 收任务 | set_difficulty→notify（clean=false 增量 / true 清队列） | 矿池事件编排 | #5/#6/#7/#8 |
| ④ share 提交 | submit→响应 true/false（会话均继续） | 矿机驱动 | #10/#11 |
| ⑤ extranonce 轮换 | extranonce.subscribe→set_extranonce→后续 job/submit 用新尺寸 | 双侧编排 | #9 |
| ⑥ 矿池探测公告 | get_version 请求/响应、show_message | 矿池驱动反向 | #14/#15 |
| ⑦ version-rolling（现代 ASIC 标配） | configure→交集掩码→set_version_mask→submit 6 参 | 双侧编排 | #16/#17/#18 |
| ⑧ 多矿机并发 | 多会话按序展开 或 `concurrent:true` 交错 | 各自驱动 | #24/#26 |
| ⑨ 完整生命周期 | 接入→收任务→提交→clean=true 新任务→再提交 | 事件编排 | #25 |
| ⑩ 异常断开与重连 | submit 后 RST 短路；或 FIN 后重连 = 重 subscribe + re-authorize（新 extranonce1） | 矿池 RST / 矿机重连 | #27/#28 |

**五层覆盖逐层结论**：功能层——11 类消息每类正例 + 拒绝路径正例 + 11 类负例；性能层——大 coinb1 跨 MSS（#22：1444hex→1717B→2 段 1460+257）、粘连（#21：449B 一段两行）、最小行 36B（#3/#10）、行长公式上界（无协议上界，受公式约束）；数据场景层——difficulty 16384/32768、en2_size 4/8、prevhash 反转、clean 二值、merkle 空/单步、job 数字串、id 任意起点、错误码 20–25、TMask 恒 8、version_bits 子集；地址与流层——v4/v6、多会话、**并发交错**、RST、重连、非默认端口 4444；**流关联显式不适用**（单 TCP 长连接无副连接）；**多流（会话内部并发流）显式不适用**（单连接串行收发——否定多流≠否定连接间并发）。业务层——接入-收任务-提交日常链 + 多会话/多事务（authorize 先于 submit、set_difficulty 先于首 job、submit job ∈ 已收 notify）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① subscribe 第二可选参；② extranonce.subscribe 不支持路径；③ 难度变更随 clean=true 新 job 立即生效；④ 订阅后立即推首 job（clean=true）时序；⑤ ntime 滚动；⑥ 未发 set_difficulty 直接 notify（未约束自由度）；⑦ set_extranonce 触发前提不强制校验；⑧ 非 21 的其他提交错误码；⑨ suggest_difficulty/suggest_target/get_transactions/capabilities/set_goal/client.reconnect 不实现；BIP310 其余扩展不逐个设例；⑩ **保活口径**：无应用层 keepalive 帧，TCP keepalive 探测不产生——活性由 notify 周期体现（#25），不设 keepalive 例亦不进负例；**RST/重连已覆盖**：#27（RST）+ #28（重连），FIN 由全部其余正例 `terminates` 承载。

## 5. 消息/事务模型与状态机

**事务定义**：同一 TCP 连接内一次完整的请求/响应交互，关联标识为 JSON `id`。**多事务** = 一连接内多笔事务按序执行且有先后依赖：**subscribe 必须是首条 `mining.*` 请求**（`mining.configure` 为唯一允许的前置例外——BIP310 "should be the first message"；validator 对 configure 位置不设约束，`planner.go:48-57`）；**authorize 先于 submit**；**submit job_id ∈ 本会话已收 notify**；**set_difficulty 先于首条 notify**（现网标准线序）。

矿机侧会话状态机（确定性；非法事件必须拒绝并报状态机错误，不得静默产出；实现见 `planner.go:38-187`）：

| 状态 | 允许事件（→目标状态） | 必须保持 |
|---|---|---|
| `Disconnected` | TCP 握手（→`TransportReady`） | 首条应用消息为 subscribe（或 configure） |
| `TransportReady` | [可选] configure（保持）；subscribe（→`Subscribing`） | configure 掩码记为当前 rolling 状态 |
| `Subscribing` | 订阅响应（→`Subscribed`）；可选 extranonce.subscribe（保持） | 响应 id 同值；en1/en2_size 记为当前状态 |
| `Subscribed` | authorize（→`Authorizing`） | 用户名非空 |
| `Authorizing` | 响应 true（→`Authorized`）；false（→`AuthorizedRejected`） | 响应 id 同值 |
| `AuthorizedRejected` | TCP FIN（→`Closed`） | 拒绝后不得 submit（24 语义） |
| `Authorized` | set_difficulty/notify/set_extranonce/set_version_mask/show_message/get_version 应答/submit（均保持）；FIN（→`Closed`） | submit 用户名 = 已授权；job ∈ 已收集合；en2 长 = 2×当前尺寸；rolling 激活时必带第 6 参且满足掩码约束，未激活不得带 |
| `Closed` | — | 关闭后不得产生新行 |

**自动派生规则**：①订阅响应（同 id，按 subscriptions/en1/size 展开）；②extranonce.subscribe 响应（同 id `true`）；③授权响应（按 `result` 补 `true` 或 `false+error[24]`）；④提交响应（按 `result` 补 `true` 或 `false+error[21]`）；⑤版本响应（get_version 后自动补 `result=<版本串>`）；⑥TCP 握手与 FIN 由 tcp 层自动补。**多会话展开**：按序整块回放，第二会话包号起点 = 前一会话总包数 + 1；各会话四元组/id/extranonce/难度/job/用户名/rolling 状态互不串用。**并发**（`concurrent:true`）：round-robin 按事件下标交错（`layer_gen.go:116-137`），单会话内事件序仍受状态机约束。**关闭与重连**：关闭即状态失效；重连 = 新连接 + 重 subscribe（新 extranonce1）+ re-authorize（#28 新 en1 `ea02567f` distinct 断言）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- 6.1/6.2 目标：逐事件流式（`Generate` 逐会话逐事件 emit，无全量聚合）；单 flow 常驻内存 O(行长)；无锁无共享（会话状态为 per-run 局部）；唯一跨事件可变状态 = `sessionRun{subscribed, authorized, en2Size, jobs, vrActive}`（per-generator 从零起）。吞吐/并发/内存**目标数字待 P4 基准后定**（§6.5 诚实待确认，不写承诺）。
- 6.3 两路验收：pcap 路 = suite 落盘 `/tmp/mcp-pcaps/stratum/` + `tcp.payload`/frames hex；NIC 路 = tcpdump 抓包（`nic_capture` 用例级开关，实测口 enp135s0f0np0）+ 同一断言集。
- 6.4 依据：代码路径已落（builder/planner/layer_gen 行号见 §11）；pack 粘连为同方向字节拼接（`layer_gen.go:83-114`，异向自动 flush）；跨 MSS 分段由 tcp 层负责（段数 = 行长对 MSS 上取整）。
- 6.6/6.7 六类场景：基线（#1 9 包）/ 目标规模（#26 45 包三矿机）/ 压力上限（#22 1717B 跨段）/ 长运行时（#25 多轮）/ 并发交错（#26）/ 背压（buffer 溢出即 fatal，框架既有语义）。断言须含实际包数、行字节值、重组长度，**不许只断言"任务没报错"**。
- 6.8 失败边界：功能正确但超资源预算视为不合格（P4 基准后回填数字）。

## 7. 错误处理与错误传播

以下输入必须由 planner/validator 拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。**单一注入纪律：每行恰注入一个故障；主锚词为钉死的单一字面值**：

| # | 负例 ID | 类别 | 故障输入（单一注入） | 主锚词 |
|---:|---|---|---|---|
| 30 | `stratum_neg_json` | 线格式错 | 非法 JSON/截断/非对象行 | `json` |
| 31 | `stratum_neg_framing` | 线格式错 | 无 LF / CRLF / 长度前缀 | `framing` |
| 32 | `stratum_neg_method` | 线格式错 | 未知 method（含 `mining.get_transactions`/`eth_getWork`）/ 方向违例 | `unknown` |
| 33 | `stratum_neg_params` | 线格式错 | 数量/类型/位置错（含 ethash 1 参 set_extranonce、未激活 6 参 submit） | `params` |
| 34 | `stratum_neg_hex` | 值域错 | 宽度/字符集/奇偶/`0x` 前缀/TMask 宽度 | `hex` |
| 35 | `stratum_neg_state` | 状态机错 | 首消息非 subscribe-config / 未授权提交 / 关闭后续排 | `state` |
| 36 | `stratum_neg_id_correlation` | 关联错 | id 错配 / 伪 id / 未完成事务复用 | `id` |
| 37 | `stratum_neg_job_correlation` | 关联错 | job 非本会话 / 用户名不一致 | `job` |
| 38 | `stratum_neg_carrier` | 配置/载体错 | 层链缺 tcp（`[stratum]` 直连）/ UDP / 端口矛盾 | `carrier` |
| 39 | `stratum_neg_address_family` | 配置/载体错 | IPv6 地址配 IPv4 层链或反向 | `ip` |
| 40 | `stratum_neg_error_propagation` | 错误传播错 | 错误被吞 / 假成功 / 0 包 | `propagat` |

实现分层（实测）：`wire_fault` 11 值由 `planner.go:280-307`（`validateWireFault`）直接拒（锚词 = `wire fault <kind>` 文案内含）；自然守卫面 = 状态机（`state`：`:54/:79/:131/:134`）/ 关联（`job`：`:137/:140`；`id`：`:64/:75/:96/:168/:172/:177`）/ 值域（`hex`：`checkHexField :242-262`；`params`：`:67/:82/:92/:124/:159`）/ 未知 kind（`unknown`：`:183`）。**链级 carrier/address-family 自然守卫今日缺失**（`validate_layers.go` 无 stratum 分支）→ G-ST-6。

**不得误报的合法协议事件**：submit 拒绝（#11）、authorize 拒绝（#4）、难度变更（#8）、轮换（#9）、空 merkle（#19）、size=8（#20）、大 coinb1（#22）、反向消息（#14/#15）、configure 先行（#16）、激活态 6 参（#18）。

## 8. 存量审计口径

`cases/stratum.json` 40 例（29 正 + 11 负，无占位）逐条去向见 testcase §8：**40/40 合入、作废 0、等价覆盖 0**。现状同一混用形（顶层 6 键 + 空层条目 `{"ip":{}}`/`{"stratum":{}}` + 40/40 无 `flow_control`）。P4 动作 = 层链整形（G-ST-1）+ 事件 3 键修复（G-ST-2）+ 会话区分度（G-ST-7），整形后 ID/顺序/语义不变。

## 9. 用例集合摘要（ID 权威在 testcase §2）

40 个唯一语义 ID（29 正 + 11 负），顺序即 `stratum.json` 顺序：#1 subscribe 基线 / #2 extranonce 订阅 / #3 授权 / #4 授权拒绝 / #5 notify / #6 clean=true / #7 难度 / #8 难度变更 / #9 轮换 / #10 提交接受 / #11 提交拒绝 / #12 id 关联 / #13 prevhash 反转 / #14 get_version 反向 / #15 show_message / #16 configure / #17 set_version_mask / #18 version_bits 提交 / #19 空 merkle / #20 size=8 / #21 粘连 / #22 跨 MSS / #23 IPv6 / #24 多会话 / #25 生命周期 / #26 并发 / #27 RST / #28 重连 / #29 非默认端口 / #30–#40 十一负例。packet_count 见 testcase §2（**#9=17、#18=17**，旧稿 15 系笔误已勘误）。

完成定义：注册 `tcp→stratum` 层链；§3 全部 11 类消息逐字段生成并验证；订阅/授权/难度（含变更时序）/任务（clean 二值、空 merkle）/轮换/提交三态、反向应答、BIP310 三消息与 version_bits 约束、id 关联、多事务、多会话展开、IPv4/IPv6、MSS 分段与粘连重组、全部边界可观测；40 ID 正负断言与错误传播完成（含并发/RST/重连/非默认端口/混合地址族）；pcap/NIC 双输出共用本契约。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | TCP 明文长连接，单连接行式流（Wiki 全文唯一连接） | 矿机接入/断线重连（#1/#27/#28） | `DependsOn ["tcp"]`（`registry.go:531`）；握手/挥手 tcp 层 | 无 |
| 2 | 命令/消息表 | 11 类消息 + params 位置语义（Wiki 各方法节 + BIP310） | 场景①–⑦（§4 表） | builder 16 构造器（`builder.go:145-310`：11 消息类 + 5 辅助 `intStr/quoteJSON/isASCIIPlain/hexStringArray/LineLongCoinb1Pad`）；`buildEventLines` 11 分支（`layer_gen.go:172-331`） | `version_rolling_mask`/`min_bit_count` 事件键未接线 → G-ST-2 |
| 3 | 状态机 | 订阅首条/授权序/job 关联/version_bits 约束（参考实现检查序） | 多事务先后依赖（#25） | `validateSession`（`planner.go:38-187`）全转移 | 无（豁免面见 §10.2 不适用格） |
| 4 | 字段表 | hex 规则/反转/定点/TMask/行长公式（Wiki + 参考实现 + §3.13） | 数据场景面（§4） | `checkHexField`（`:242-262`）；单测钉行字节（`stratum_test.go:13-153`） | nbits/version 小端序待实证 → G-ST-5 |
| 5 | 错误处理表 | 错误码 20–25 + 拒绝会话继续语义（Wiki + 错误表） | 场景②④（#4/#11）+ 11 负例 | `validateWireFault` 11 值（`:280-307`）+ 自然守卫 | 链级 carrier/地址族自然守卫缺 → G-ST-6 |
| 6 | 超时与活性 | **协议层无 keepalive**（无 PING 类消息）；活性由 notify 周期体现 | 长保活（§4 声明⑩，#25） | 生成器不发 keepalive 包（无相关代码） | 无（显式不适用） |
| 7 | NAT/代理/被动模式 | 无（单直连 TCP，无被动端口通告） | — | — | **显式不适用** |
| 8 | 版本/方言差异 | BIP310 三件 + ethash 区分（§3.12）+ ⑤假设四点 | 场景⑦（#16/#17/#18） | `versionRollingActive`（`:226-238`）；区分表文档面 | ⑤假设待实证 → G-ST-5 |

### 10.2 子表①：消息×会话状态矩阵（逐格已覆/缺失/不适用；22+22+11=55）

列 = 建连前 / 已订阅 / 已授权 / 已收 job / 已关闭。行 = 11 类消息。

| 消息 | 建连前 | 已订阅 | 已授权 | 已收 job | 已关闭 |
|---|---|---|---|---|---|
| subscribe | 已覆 #1 | 已覆 #24（重订阅语义#28） | 不适用（同左） | 不适用 | 已覆 #28（重连即新连接重订阅）+ 负例#35（同连接关闭后续排） |
| extranonce.subscribe | 缺口→负例#35（首条非 subscribe-config 拒） | 已覆 #2 | 已覆 #9（前置行在场） | 不适用 | 不适用 |
| authorize | 缺口→负例#35（首条 authorize 拒） | 已覆 #3/#4 | 已覆 #25（re-authorize 语义#28） | 不适用 | 不适用 |
| set_difficulty | 缺口→负例#35 | 不适用（难度先行标准序） | 已覆 #7/#8 | 已覆 #8（变更作用后续 job） | 不适用 |
| notify | 缺口→负例#35 | 已覆 #5（标准序经授权） | 已覆 #5/#6/#19 | 已覆 #25（job 轮换） | 不适用 |
| set_extranonce | 缺口→负例#35 | 缺口→A′（未发 extranonce.subscribe 先轮换，validator 今日不拒 §4⑦） | 已覆 #9 | 已覆 #9（后续生效） | 不适用 |
| submit | 缺口→负例#35（未订阅）/ 自然守卫（未授权 `state`） | 自然守卫（`submit before authorize`） | 缺口→负例#37（job 非本会话；用户名错配） | 已覆 #10/#11/#18 | 不适用 |
| get_version | 不适用（反向请求无状态前置） | 已覆 #14 | 已覆 #14 | 不适用 | 不适用 |
| show_message | 不适用 | 已覆 #15 | 已覆 #15 | 不适用 | 不适用 |
| configure | 已覆 #16（首条例外） | 已覆 #18（后置线序） | 不适用 | 不适用 | 不适用 |
| set_version_mask | 缺口→负例#35（首条） | 缺口→A′（未 configure 先推送，validator 今日不拒） | 已覆 #17 | 不适用 | 不适用 |

缺口 11 = 负例通道 9（首条违例×7 →#35；未授权提交→自然守卫/`state`；job/用户名错配→#37，已建）+ A′ 2（未订阅先轮换 / 未 configure 先推送，validator 今日不拒）。

### 10.3 子表②：数据形态变体表（24 行，逐行有结论）

行式组帧/LF 边界/CRLF 拒绝/长度前缀拒绝/紧凑 JSON/成员序/id number 与 null 双态/hex 小写/hex 无前缀/hex 偶数长/字节序（prevhash 反转 + 内部小端⑤）/difficulty 定点/行长 19 公式/订阅对双态/en1 长度未钉死/en2_size 4 与 8/job 数字串/merkle 空与单步/version-nbits-ntime 8hex/clean 二值/TMask 恒 8/version_bits 子集/错误三元组/方向 11 类——**24/24 有结论**（正例 #1–#23 或负例 #30–#34 承载；en1 2–8B 变长与 ntime 滚动标 A′）。

### 10.4 关联关系专节（§3.8–3.10）：「无派生流」的边界

**主连接内无派生流**（诚实声明）：矿机-矿池是单 TCP 长连接行式协议，无控制/数据分离、无副连接概念（Wiki 全文仅此一条连接）。因此 `driven_by{session,transaction,field}` 三件套**不适用**，且**不许**用"同一模板连续重复发射"冒充编排（§3.13）。唯一跨连接关系 = 断线重连（#28，会话状态失效语义，非关联）。

### 10.5 候选方案对比（§4.17）与三路对照（§4.12–4.15）

| 方案 | 走法（借鉴来源） | 优劣 | 结论 |
|---|---|---|---|
| A 事件面声明式回放 + 自动应答 | 本仓库已落码（`layer_gen.go` + `builder.go`，xmrmining/ethmining 同构） | 优点：与家族一致，validator/生成器同源缺省；缺点：无 | **采用** |
| B 生 hex 透传 | cflow 负例逃生口先例 | 优点：零建模；缺点：丢失状态机/关联校验，11 负例无自然守卫 | 不选（仅负例注入通道保留 `wire_fault`） |
| C 通用 JSON-RPC 模板编译器 | 无（假想） | 优点：复用 getwork/gbt 面；缺点：stratum 行语义（订阅对/en 双段/反转/掩码约束）无法通用表达 | 不选 |

三路对照：①规范原文（Wiki + BIP310，逐表列出处）；②现网行为（Wiki 即 Slush 口径现网真相；错误文案大小写等 ⑤ 四点待抓包升级 G-ST-5）；③开源实现（slush0 + node-stratum-pool，逐文件）。三路在八点一致（§4 表），不一致 1 点（文案大小写）取舍已记。

### 10.6 裁定 ST-A：主协议 / 同族异协议关系

**stratum = 主协议；ethmining = 同族异协议（非 dialect 变体）；getwork = 另一载体协议**。五条实证：①registry 独立注册（stratum `:530` / ethmining `:534`，端口契约 3333 vs 4444）；②notify 九参 vs 四参；③submit 五参 vs 三参；④set_extranonce 双参 vs 单参（互为方言负例）；⑤测试面独立文件（40 vs 32 vs 62 例）。判定依据链：`registry.go:525-541` + `builder.go` 两族构造器 + §3.12 区分表。

## 11. P2 D-STRATUM-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 体裁：文件清单 / 接口签名 / 数据结构 / 主流程 / 错误分支 / 性能边界 / 冲突点 / 回滚。**依赖建模沿 §10.6 裁定 ST-A**。

### 11.1 文件清单（P4 动作，**本轨道不执行**）

| 文件 | 动作 | 职责 |
|---|---|---|
| `internal/core/layers/chain_planner_translate.go`（`translateTerminalConfig`） | **新建 `case "stratum"`**（G-ST-1 首要） | 层 config 经 JSON 往返 + `DisallowUnknownFields` 解码为 `core.StratumConfig`（xmrmining `:2129` / bacnet 范本）；flat/层并存优先级裁定；Fields 空早返（`:756`）在前——本 case 必须落在早返**之前**的分支区（goose 手工映射区同款位置），否则层内配置永不到达 |
| `internal/core/stratum.go:46-93`（`StratumEvent`） | **扩展** | 新增 `version_rolling_mask`/`min_bit_count` 事件键；定 `termination` 去留（删则 P4 同批改写存量 2 例） |
| `internal/protocol/stratum/layer_gen.go:170-339` | **扩展** | configure 分支消费新键（缺省保持 `FixtureCfgParams`）；`termination` 若保留则消费 |
| `internal/protocol/stratum/planner.go:38-187` | **扩展** | ①set_extranonce/set_version_mask 前置守卫（A′，今日不拒）；②链级 carrier/地址族自然守卫或书面豁免（G-ST-6） |
| `internal/core/layers/registry.go:530-533` | **不变**（已注册；`Fields` 空保持） | 若增键则重跑 schemagen（§13.18/13.19） |
| `internal/core/strategy_convert.go:625-627` | **不变**（JSON 往返自动搬运新键） | — |
| `tools/coverage_gate.py` | **扩展** | `check_stratum`（今日无，`:3083` 起 xmrmining 为范本）——40 ID 反查块；分发表登记 |
| `trafficgen/test/protocol_pcap/cases/stratum.json` | **改写** | 40 例层链整形（G-ST-1）+ 事件 3 键修复（G-ST-2）+ 会话区分度（G-ST-7）；ID/顺序/语义不变 |

### 11.2 接口签名（示意，P4 落码钉死）

```go
// builder（纯字节层，已有；新增无）
func BuildSubscribeReq(id json.RawMessage, ua string) []byte        // 已有
func BuildConfigureReq(id, exts, params json.RawMessage) []byte     // 已有（新键缺省 FixtureCfgParams）
// planner（校验层，扩展）
func Validate(spec core.FlowSpec) error                             // 已有
func validateSession(sess core.StratumSession, si int, extensions []string) error // 已有（补前置守卫）
// generator（事件层，已有）
func (g *StratumGenerator) Generate(ctx context.Context, req *layers.GenRequest) error // 已有
```

### 11.3 数据结构（现状 + 扩展）

现状（`types.go:1709`）：`FlowSpec.Stratum *StratumConfig`；`StratumConfig{Concurrent, Profile†, Extensions, Sessions, WireFault}`（†配上不生效，存量零携带故不删）；`StratumSession{SrcPort, DstPort, Events}`；`StratumEvent` 36 键（§2.2）。

**扩展方向（P4 定稿）**：新增事件字段全部**可选且 omitempty**，保证存量 40 例 JSON 不变即可继续工作；`version_rolling_mask`/`min_bit_count` 新增后 **JSON 解码无 `DisallowUnknownFields`**（`strategy_convert_helpers.go:21`）故存量 2 例（configure 相关）**无需**同批改写即可工作，但 P4 必须改写以行使新键（先跑后钉）。

### 11.4 主流程

```text
strategy config(layers)
  → ValidateLayers（未知层/未知字段 V9/层链完整性；stratum 层 Fields 空恒过）
  → ChainPlanner.ValidateSpec（FieldContract 端口补齐 + translateTerminalConfig 早返 + stratum validator 状态机/kind/hex/wire_fault）
  → translateTerminalConfig（Meta.Stratum 直传，chain_planner_translate.go:193）
  → worker 逐流：resolveLayerTuple（动态）→ ChainPlanner.Generate
  → StratumGenerator.Generate（逐 session → 逐 event → buildEventLines → EmitMsg{Up, Bytes, SrcPort}；concurrent 时 round-robin）
  → tcp 层（握手/分段/seq/挥手 + 多连接 + rst/concurrent）→ ip 层 → 输出（pcap / port_group）
```

### 11.5 错误分支（§5.2）

三档：①**链级**（`ValidateLayers`/`ChainPlanner.ValidateSpec`）——未知层、`unknown field`、presence 混用（`schema/semantic.go:183-186`；stratum 分支缺失 → G-ST-4）；②**配置级**（`Validate`）——wire_fault 11 值/状态机/kind/hex/id/job/version_bits；③**生成期**（`buildEventLines` 的 `unknown event kind`——**理论不可达**，kind 已由 ② 白名单化；若到达即实现 bug）。全部传播为 **task error**，**零假成功**。

### 11.6 性能边界（§6.1–6.8 摘要，详见本契约 §6）

单 flow 常驻内存 O(行长)；无锁无共享；逐事件流式；速率归框架 pacer。**不新增任何按流缓存**。

### 11.7 与现有逻辑的冲突点（§8.7）

1. **`CheckProtoFlat` 无 stratum 分支**：顶层 `stratum` 子映射不判死（28 分支机读在案）→ G-ST-4 框架级缺口，**禁加单协议分支**，上报主线程。
2. **事件 3 键静默丢弃**：`version_rolling_mask`/`min_bit_count`/`termination`（§2.2）→ G-ST-2，P4 修 struct + 改写存量 2 例。
3. **会话区分度**：`multi_session` 会话 2 值重复（§2.2 实测）→ G-ST-7。
4. **端口域**：链内显式 4444 vs FieldContract 3333 → G-ST-3，P4 实测为准。
5. **`coverage_gate.py` 无 `check_stratum`**：P4 新增 40 ID 反查块（xmrmining `:3083` 为范本）。

### 11.8 回滚方式（§8.8）

按提交序 `git revert`：struct 扩展 / validator 守卫 / 用例改写提交可逐提交回退；**存量 40 例改写提交是唯一的"数据面"提交**——回退它必须与 struct 扩展提交**同批回退**（否则新键用例与旧 struct 失配，但因无严格解码只表现为静默丢弃而非硬失败，风险低于 postgresql 的 `DisallowUnknownFields` 面）。registry/schemagen 生成文件随提交对齐（本设计**不新增层**；若 `Fields` 增键则重跑，`TestLayersGeneratedMatchesRegistry` 会红）。

---

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

> 证据三选一（§15.2）：文档章节 / 代码行 / 用例号。写不出 = 缺口立项，不许空着。§1/§3/§12 三行按 §15.3 强制展开（§12.1/§12.3/§12.12）。

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 40/40 混用形（机读），旧键去向逐键落实；目标形状见 §2；非负例顶层键 = 4（P4 整形后 = 0，G-ST-1）；presence 判死形状不适用但点名（G-ST-4） | 本契约 §2 + §12.1；`cases/stratum.json` 40 例机读 |
| §2 策略/任务 | 策略 = 单 stratum 模板（自带 `flow_control`）；任务 = 多策略合跑 + 封顶；框架语义未动 | `internal/core/worker.go:307-316`；本契约 §2 |
| §3 五件套 | 见 §12.3 强制展开：会话表 / 事务序列 / 关联关系（无派生流诚实声明）/ 插入位置 / 时间线；**有长连接载体，不豁免** | 本契约 §12.3 + §10.4；用例 #24/#25/#26/#28 |
| §4 查规范 | Wiki + BIP310 + slush0/node-stratum-pool + tshark 11 字段实测 + 旧稿实测沿用；P1 矩阵 8 行 + 三子表（§10.1–§10.3）+ 候选方案对比（§10.5） | 本契约 §3/§10 |
| §5 依赖与错误 | `DependsOn ["tcp"]`（`registry.go:531`）；`FieldContract 3333`（`:532`）；`wire_fault` 11 值（`planner.go:280-307`）；零假成功 | 本契约 §5/§7 + §11.5 |
| §6 性能 | 见本契约 §6（6.1–6.8 要素）；吞吐数字待 P4 基准 | 本契约 §6 |
| §7 三份文档 | `89-stratum-design/testcase.md`（草稿层，§7.4；append 进 CODE_DESIGN.md/TEST_CASES.md 的条目为唯一权威文本）+ D-STRATUM-1（本契约 §11，门1 获批 = 定稿）+ T-STRATUM（testcase §2）+ generated schema（不新增层） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 层链整形开工；门1 获批 = 定稿 = 开工门（§8.9） | 提交序 |
| §9 测试三源 | 三源 = 规范条款 + D-STRATUM-1 + Wiki 即现网口径（⑤假设 → G-ST-5）；40 ID 逐项回指；存量审计 §8 + testcase §8 | `89-stratum-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 `/tmp/pipe/89-stratum/p123-report.md` §3）+ 收官隔离复审 + 修轮；红先绿后 | 报告 §3 |
| §11 白话 | 汇报首句先行白话结论 | 报告首节 |
| §12 动态清单 | 见 §12.12 强制展开：四元组五策略全开（allowlist `:18-19`；`stratum` 不在 allowlist → 业务对象必拒）；业务 9 项逐个理由；序号算法实读行号 | 本契约 §12.12 |
| §13 schema 派生 | 已注册（`registry.go:530-533`，不新增层）；`protocols.go:77`；`main.go:534`；struct 标签锁定（§13.13） | 本契约 §11.1 |
| §14 真实流程 | suite 建策略建任务 → 真实生成 → tshark 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/stratum/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-27）**：

| 面 | 例数 | 形状 |
|---|---:|---|
| 顶层键 | 40/40 | `{src_ip,dst_ip,src_port,dst_port,layers,stratum}` |
| 链形 `[ip,tcp,stratum]` | 38 | 34 空 `ip{}` + 1 显式 v6 + 1 tcp 4444 + 1 tcp concurrent + 1 tcp rst |
| 链形 `[ip,stratum]`（刻意坏） | 1 | `stratum_neg_carrier` |
| tcp 特殊键 | 2 | `concurrent` ×1 / `rst` ×1 |
| `flow_control` | 40/40 缺 | P4 逐例补（正例） |
| 负例 expect 纯净 | 11/11 | 只有 `{expect_error,error_contains}` |

**旧键去向表**：见报告 §1.1（`src_ip`→`ip.src` / `dst_ip`→`ip.dst` / `src_port`→`tcp.src_port` / `dst_port`→`tcp.dst_port` / `count`→`flow_control`（存量 0）/ 顶层 `stratum`→`layers[]` stratum 条目 / 缺 `flow_control`→逐例补）。

**目标形状 spec_json 样例**：见 §2（纯 layers，顶层仅 `layers` + `flow_control`）。

**presence 判死形状说明（必须点名）**：`{"layers":[…],"stratum":{}}` 今日**不会被拒**（G-ST-4）→ **不建**该负例 → 登记缺口；白名单外游离键判死负例建 #41 面（`src_mac`，P4 实测是否真被拒）；载体负例 = 存量 #38（`carrier` 锚词，今日靠注入文案，G-ST-6）。

### 12.3 §3 强制展开：五件套

**会话表**：

| 会话 | 四元组 | 生命周期 | 用例 |
|---|---|---|---|
| `s1`（单会话基线） | `ip` + `tcp.4075→3333` | SYN→subscribe→authorize→set_difficulty→notify→submit→FIN 四way | #1–#23 |
| `s2`（多会话展开） | 第二 `sessions[].src_port=4076` | 与 s1 完全独立的握手→订阅→授权→任务→提交→挥手；**整块回放不交错** | #24 |
| `s3`（并发交错） | `concurrent:true` + 4075/4076/4077 | round-robin 按事件下标交错；断言 `tcp.stream` 三值 distinct | #26 |
| `s4`（断线重连，B′ 无） | 新连接 + 新 extranonce1 `ea02567f` | 建连→重 subscribe→re-authorize→新任务；旧状态失效 | #28 |

**事务序列（单事务四件事 §3.4–3.7）**：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| `t1` 订阅 | TCP 握手完成 | c2s subscribe | s2c 订阅响应（双对+en1+size） | 首条非 subscribe-config → 拒 `state` |
| `t2` 授权 | `t1` 完成（已订阅） | c2s authorize | s2c `true` → 可收任务 | `false+error[24]` → 关闭（#4；其后 submit 拒 24） |
| `t3` 收任务 | `t2` 成功 | s2c set_difficulty → notify | job 登记，clean 决定切换语义 | notify 参数错 → 拒 `params`/`hex` |
| `t4` 提交 | `t3` 已收 job | c2s submit | s2c `true`（入账）或 `false+error[21]`（stale，会话继续） | job 非本会话 → 拒 `job`；en2 尺寸错 → 拒；未授权 → 拒 `state` |
| `t5` 反向与扩展 | `t1` 完成 | s2c get_version/show_message/set_version_mask；c2s configure | 自动应答 / 掩码立即生效 / 交集掩码 | 未激活 6 参 → 拒 `params` |
| `t6` 终止与重连 | 任意 Authorized 态 | FIN 挥手 / RST 短路 / 重连重订阅 | 正常关闭；RST 后无业务行；重连新 en1 | 关闭后续排 → 拒 `state` |

**关联关系（§3.8–3.10）**：见 §10.4——**主连接内无派生流**，`driven_by` 不适用。

**插入位置**：终结层（`CategoryTerminal`，`DependsOn ["tcp"]`）——stratum 行直接落 TCP payload；链上**无中间层**。

**时间线**：**单会话严格顺序**（t1→t2→t3→t4/t5→t6，每步依赖前一步结果，`planner.go:38-187` 已对 submit/job/version_bits 强制）；**多会话整块顺序**（s1 跑完再跑 s2）；**并发交错**（`concurrent:true`，跨会话不假设全局包序，只断言会话内序与各会话独立）；**RST 短路**（`tcp.rst:true`，RST 后无业务行、无挥手）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组（`ip`/`tcp` 层，五策略全开）**：

| 字段 | 住处 | 开策略 | 依据 |
|---|---|---|---|
| `src`（src_ip） | `ip` 层 | fixed/inc/rand/list/pattern 全开 | allowlist `layer_dyn.go:18` |
| `dst`（dst_ip） | `ip` 层 | 同上 | 同上 |
| `src_port` | `tcp` 层 | 同上 + 未写动态保底 `12345+i`（`worker.go:307-308`，`DefaultSrcPort = 12345`，`strategy_convert.go:49`） | allowlist `layer_dyn.go:19` |
| `dst_port` | `tcp` 层 | 同上，**但与 3333 契约冲突面已声明**（动态 dst_port 非 3333 且无显式声明语义 → P4 实测，G-ST-3） | 同上 + 契约 `registry.go:532` |

**业务字段（`stratum` 层，逐个列开/不开 + 理由）**：

| 字段 | 开 | 理由 |
|---|---|---|
| `concurrent` | ✅ 开 | 交错开关，会话级声明（`layer_gen.go:116` 消费） |
| `extensions` | ✅ 开（链级声明） | BIP310 声明，非逐流值；`versionRollingActive` 消费（`:226-238`） |
| `profile` | ❌ 关 | 信息性字段，生成器零读取；逐流变无字节意义 |
| `user_agent` | ❌ 关（今天） | 固定矿机标识；多标识逐流变列 A′ 候选（需先登记 allowlist；`stratum` **不在** `layerDynAllowlist`，对象必拒） |
| `username` | ❌ 关（今天） | 多矿机逐流变可想象（多用户压测）→ A′ 候选，同上 |
| `job_id`/`extranonce1`/`extranonce2` | ❌ 关 | 会话内关联键 / 矿池指派值，逐流伪造破坏会话自洽 |
| `difficulty`/`mask`/`message` | ❌ 关 | 矿池指令/公告，逐流变无业务意义 |
| `coinb1`/`coinb2`/`merkle_branch`/`prevhash` | ❌ 关 | fixture 行字节，逐流变等价于"多套剧本"，应由多策略表达（§2.2） |
| `wire_fault` | ❌ 关 | 负例唯一注入口，非业务字段 |

**序号算法代码位置（实读，不编行号——§5.7）**：

- 层内字段动态解析入口：`internal/core/layer_dyn.go:78` `parseLayerDyn` → `:369` `checkDynShape` → `:770` `resolveLayerTuple(spec, i)`（`worker.go:316` 调用）。
- 值算法：`internal/core/tuple_generator.go:26` `TupleGenerator.Next(index)`（inc/rand/端口分发）。
- 保底自增：`internal/core/worker.go:307-308`（`flowCount > 1 && !spec.HasExplicitSrcPort` → `DefaultSrcPort + i`）。
- allowlist：`internal/core/layer_dyn.go:18-19`——**`stratum` 无块**，层内任何对象值 → `does not support dynamic`。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- **①层链+顶层空子映射并存**：本协议**不建**（G-ST-4，建了会真绿）→ 缺口登记，不冒充覆盖。
- **②白名单外游离键判死（1.11–1.13）**：`{"layers":[…],"src_mac":"02:00:00:00:00:01"}` → 必须拒（P4 实测今日是否真被拒；若不拒并入 G-ST-4）。
- **③一切负例 `expect_error` 带错误锚词**：11 负例逐条锚词见 §7。
- **④收官自查行**：「非负例顶层键 = 0」——P4 整形后预期 0（今日 4）。
- **载体负例**：`[ip,stratum]` 缺 tcp（存量 #38，锚词 `carrier`，今日靠注入文案，G-ST-6 补自然守卫或书面豁免）。

---

## 13. P3 对接清单（T-STRATUM 草稿输入；正文落 testcase 文件）

- §3.15 三项：见 testcase §6.1（①同连接多轮操作→#25 + A′ 补例；②非正常结束→#4/#11/#27 + 负例面 + A′ 2 条；③长保活→#25 + #8 + A′（协议层无 keepalive 显式不适用））。
- A′/B′ 两分类表：见 testcase §6.2（A′ = 引擎可构建需接线，七类要求面逐项列落点；B′ = 引擎结构缺口 G-ST-3/4，进设计 §14）。
- 9.52 对账两行：见 testcase §5.2（**规范逻辑点总数 = 87** = 八项 8 + 矩阵 55 + 变体 24；**用例覆盖数 = 63** = 8 + 矩阵已覆 22 + 矩阵负例通道 9 + 变体 24；**不适用 = 22**；63 + 22 + 2 = 87 ✓；清单出处 = 规范反推）。
- 3.14 豁免边界审计：见 testcase §6.3（**有长连接载体 → `sessions[]` 不豁免**；多流并发 #26 + 单包多载荷 #21/#22 各至少一例；流关联显式不适用）。
- 三源回指行：见 testcase §5.1（第三源 Wiki 即现网口径级，⑤假设挂 G-ST-5）。

---

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 立项号 | 缺口 | 确认方式（三选一：查文档 / 抓包 / 问人） | 去向 |
|---|---|---|---|
| **G-ST-1** | 层链整形：40 例顶层旧键搬入层链 + 顶层 `stratum` 搬入 `layers[]` 条目 + 29 正例补 `flow_control.flows=1` + **新建 `case "stratum"` 翻译**（`translateTerminalConfig` 无此 case 且 Fields 空 `:756` 早返——层内配置今日到不了 `spec.Stratum`，§2 已标 1.9） | 读 `schema/semantic.go:183-186` + 存量机读（§12.1） + `chain_planner_translate.go:692/756` | **A′**（P4 车道 B）；收官自查「非负例顶层键 = 0」 |
| **G-ST-2** | 事件形状 3 键：`version_rolling_mask`/`min_bit_count` + `termination:"rst"` → 修 struct + 改写存量 2 例，定 `termination` 归属 | 读 `stratum.go:46-93` + `strategy_convert_helpers.go:21` + 存量机读 | **A′** P4 必办；修后全量复跑 |
| **G-ST-3** | 端口域：链内显式 4444 是否被 FieldContract 3333 拒 → P4 实测为准 | 实测提交链内 4444 形 + 读 `registry.go:530-533` | P4 必办；B′ 候选 |
| **G-ST-4** | 顶层白名单洞：`CheckProtoFlat` 无 stratum 分支 → 层链+顶层空子映射不判死；游离键兜底 P4 实测 | 读 `strategy_convert.go:8322`（28 分支机读）+ 实测 | **框架级缺口**（禁单协议分支）；**上报主线程**；用例侧不建该负例 |
| **G-ST-5** | 现网 ⑤ 假设四点：文案大小写 / en1 长度 / 内部小端序 / 首 job 时序 → 实证校准 | **抓包**：公开矿池 3333 回环/现网包核对 + 查参考实现原文 | P4 前置确认项，不挡开工；确认前标"待确认" |
| **G-ST-6** | 链级守卫缺失：`validate_layers.go` 无 stratum 分支 → 缺 tcp/混合地址族无链面拒绝 | 读 `validate_layers.go`（机读零命中）+ 实测自然形 | P4 必办；补守卫或书面豁免 + coverage 登记 |
| **G-ST-7** | 会话区分度：`multi_session` 会话 2 en1/订阅标识与会话 1 重复 → P4 改 `ea02567d` + 显式订阅对 | 存量机读 + 旧稿 fixture 常量 | P4 必办（先跑后钉） |

---

## 15. 修订记录

- v1.0.0（2026-09-27）：P1–P3 文档轨产物（车道 A）。旧基线 75稿 v2.1.1 逐节比对（§10.2：未删条目，改动四类）；建立 P1 八项矩阵（§10.1）+ 三子表（§10.2 11×5=55 格，22+22+11 / §10.3 24 行 / §10.5 对比三行）+ §3.12 九行区分表 + ST-A 裁定 + 三路对照；门1 十四行表（§12，§1/§3/§12 强制展开）；D-STRATUM-1（§11，八要素）；性能设计与验收（§6）；缺口 7 项（§14）。实测：tshark 11 字段 + 17 无关行；行长 19 值复算全中（脚本见报告 §3 R2）；CheckProtoFlat 28 分支机读；存量 40 例机读。packet_count 双勘误（#9/#18 15→17）。**未修改任何 `.go`、未跑 suite、未启动服务器、未写共享文档/账本**。单元测试现状：`internal/protocol/stratum` pass；`internal/core/layers` 有 1 项 SSTP 失败（`TestSSTPChain_WireFaults/group_merges_same_direction`，非本协议，P4 集成点复核）。

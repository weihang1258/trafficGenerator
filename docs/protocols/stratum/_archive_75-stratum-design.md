# Stratum（比特币矿池 stratum 协议，Stratum v1 矿机-矿池工作分配）设计契约

> 版本：v2.1.1（设计阶段）
> 日期：2026-09-01
> 状态：**尚未实现**；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）双输出断言，不宣称当前测试套件可运行，不修改 Go（编程语言）/MCP（模型上下文协议）实现。按《协议设计文档与用例文档需求文档 v1.3》完成行为面全枚举重审修复轮（审查员 docs-bacnet：20 findings = 5C + 9D + 6N + 结构三项，逐项修复），本版 v2.1.0 为修复轮产物：35 → **40 例（29 正 + 11 负）**，待复验关闭；v1.1 流程既有重写（v2.0.0）记录见 §10。
> 配套文件：`docs/protocol-designs/75-stratum-testcase.md`、`trafficgen/test/protocol_pcap/cases/stratum.json`（当前 JSON 仅含注册前置占位，本版不写文件、不改代码）
> 规范基线：比特币 **Stratum v1**（矿机↔矿池 TCP 长连接、行分隔 JSON-RPC 类消息，slush/Braiins 口径），权威依据取以下六层（逐项标注出处）：
> ① **Bitcoin Wiki《Stratum mining protocol》**（en.bitcoin.it/wiki/Stratum_mining_protocol，下称 **wiki**）——本协议**唯一成文方法学规范**，本文全部方法签名、params 位置语义、notify 九参顺序、submit 五参、set_extranonce 双参、extranonce1/extranonce2 语义、clean_jobs 语义逐条出自 wiki（出处写"wiki §<方法名>"）；wiki 自身声明"无正式 BIP 的官方标准"，故②④参考实现为其行为学补强；
> ② **slush0/stratum-mining 参考实现**（原作者 Slush 官方 Python 矿池，`mining/service.py`、`mining/subscription.py`、`lib/block_template.py`、`lib/extranonce_counter.py`、`lib/coinbasetx.py`，出处写"参考实现 <文件>"）——subscribe 返回构成（订阅对数组 + extranonce1_hex + extranonce2_size）、submit 五参签名、notify 九参发射顺序、**prevhash 字节反转**（`util.reverse_hash`）、extranonce1 4 字节大端计数、coinbase extranonce 占位 8 字节（`'>Q'` ⇒ extranonce2_size 4）逐行对照；
> ③ **BIP310《Stratum Protocol Extensions》**（github.com/slushpool/stratumprotocol `stratum-extensions.mediawiki`，Pavel Moravec/Jan Capek 2018，下称 **BIP310**）——`mining.configure` 扩展协商、TMask 类型（8 字符 hex）、version-rolling 交集规则、`mining.set_version_mask` 立即生效、submit 第 6 参 `version_bits` 及 `version_bits & ~last_mask == 0` 约束逐条出自 BIP310（出处写"BIP310 §…"）；
> ④ **zone117x/node-stratum-pool 参考实现**（`lib/stratum.js`、`lib/jobManager.js`）——**错误三元组 20–25 字面值**（`[20,'other/unknown']`/`[21,'job not found']`/`[22,'duplicate share']`/`[23,'low difficulty share']`/`[24,'unauthorized worker']`/`[25,'not subscribed']`）与拒绝检查顺序（未订阅→未授权）出处（出处写"错误表"）；
> ⑤ **公开资料 + 假设，实现阶段实证校准**：端口 3333（slushpool/Braiins 传统默认，公开矿池 3333/4444/25 等并存，矿池可配）、错误文案大小写（wiki 表为大写标题、node 实现为小写——二者并存，fixture 钉死 wiki 标题形态）、extranonce1 长度（规范未钉死，参考实现 4 字节，公开矿池 2–8 字节均有）、subscribe 第二可选参（会话恢复 extranonce1）、nbits/version/ntime/nonce 的内部小端线序（参考实现仅显式反转 prevhash，其余按区块头内部序直传为公开资料口径）、参考实现"订阅后立即推送首 job（clean=true）"时序——逐处标注；
> ⑥ **本机实测**：tshark 3.6.14 `-G fields`/`-G protocols` + 按协议逻辑构造 pcap 实证（`tcp.payload` 精确提取完整行字节、offset 54/74、行尾 `0a`，见用例文档 §1）。
> 修订记录：v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》重写，取代 2026-08-20 旧稿（旧稿见 git 历史）。旧稿全部废弃：**submit 参数命名混入 ethash 方言**（旧稿 §4.3 写 `extra_nonce`，比特币口径为 extranonce2，与 extranonce1/extranonce2 双段语义混淆）；subscribe 响应钉成单订阅对形态（比特币现网为 set_difficulty+notify 双订阅对）；**缺 mining.set_extranonce**（本版按 wiki 补齐，2 元素形态）；负例锚词多选无候选集确定性；无业务场景分析/状态机/行长公式/五层覆盖。本版从 wiki + BIP310 + 两个参考实现逐条重新提炼。

## 1. 范围、profile 和未注册边界

本版定义矿机（miner）与矿池（pool）之间的 **比特币 Stratum v1 明文 TCP 长连接**：行分隔 JSON（newline-delimited JSON，每行一个 JSON 对象，行尾单个 LF `0x0a`）消息封装、订阅（`mining.subscribe`）、extranonce 订阅（`mining.extranonce.subscribe`）、授权（`mining.authorize`）、难度通知（`mining.set_difficulty`）、任务通知（`mining.notify` 九参）、extranonce 轮换（`mining.set_extranonce` 双参）、share 提交（`mining.submit` 五参）与提交响应三态、矿池侧反向消息（`client.get_version` 请求/响应、`client.show_message` 通知）、BIP310 扩展（`mining.configure`/`mining.set_version_mask`/version-rolling 第 6 参提交）、错误三元组、JSON-RPC `id` 关联、IPv4/IPv6、多会话与多事务。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `stratum_v1`（主 profile） | TCP 明文行式 JSON（fixture 端口 3333，可配置覆盖） | 7 类 `mining.*` 消息 + `client.get_version`/`client.show_message`、行重组、id 关联、share 三态、错误三元组 | 真实 share 密码学有效性、区块产生、真实矿池鉴权、难度与真实网络 target 的对应关系 |
| `stratum_ipv6_v1` | 同上，仅外层 IPv6 | 同主 profile | 从 IPv4 fixture（固定样本）推导 IPv6 地址 |
| `stratum_bip310_ext` | 主 profile + BIP310 扩展（由配置 `extensions` 声明，非独立层链） | `mining.configure`/`mining.set_version_mask`/version-rolling submit 第 6 参 `version_bits` | 未声明的其他扩展（`minimum-difficulty`/`subscribe-extranonce`/`info` 的编码同 configure 结果映射，本版不逐个设例，§4 声明） |

显式边界（"不实现、不声称、不许静默转换"）：**Stratum V2**（BIP 便道草案、二进制分帧、`mining.set` 族）不在本版，混入进负例；**`client.reconnect`**（要求矿机断开并重连到他机，传输层重定向语义超出脚本化回放单会话边界）不实现；**`mining.suggest_difficulty`/`mining.suggest_target`**（矿池可不响应的自由裁量请求）不实现；**`mining.get_transactions`**（已被主流矿池移除的 legacy 方法）不实现，混入按未知 method 拒绝（负例锚 `method`）；**`mining.capabilities`/`mining.set_goal`**（wiki 标注 DRAFT）不实现；不声称任何 share 满足真实比特币 target 或产生区块（生成器不执行 PoW 计算，share 内容为 fixture 声明值）。

当前仓库没有注册 `stratum` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/stratum.json` 只保留一个不计入语义 ID 的注册前置占位 `stratum_neg_unregistered`（`expect_error=true`、`error_contains="unknown layer"`；占位端口 3333 与本版 fixture 一致，**无需修正**——与 73-ethmining 占位端口错位不同；notes 已于 v2.1.0 修正为 40/29+11，注册时仅需按 §2 替换用例）。占位的拒绝、0 包或空 PCAP 不得报告为 Stratum 行为通过；注册后按本文 §9 与用例文档 §2 的同一顺序替换为 40 个语义用例（29 正 + 11 负，v2.1.0 新增正例 26-29 `stratum_concurrent_sessions`/`stratum_rst_pool_kick`/`stratum_reconnect_resubscribe`/`stratum_port_nondefault`、负例 39 `stratum_neg_address_family`）。

**输出契约（pcap/NIC 双输出，v2.1.0 C-1）**：本契约的用例同时服务于 pcap（抓包文件）与 port_group/NIC（网卡）两种输出路径——两路径共用同一份 cases JSON、同一 tshark 字段/帧字节断言，不设仅单路径可用的断言。逐项：① pcap = 离线文件，断言走 `tcp.payload` 全行 hex + offset 54/74 frames + `tcp.len`/`tcp.stream`；② NIC = port_group 网卡输出（实测口 enp135s0f0np0），经 tcpdump 捕获（`nic_capture` 用例级开关）后以同一 tshark 断言集核验——**NIC 网卡 checksum offload 可能使 IP/TCP 校验和字段与 pcap 路径不同，本协议断言不含校验和字段，不受影响**；③ 大 coinb1 跨 MSS 行（正例 22）在两路径均按 `tcp.stream` 重组后断言完整行（NIC 抓包 MTU 分段与 pcap 一致）；④ 多会话/并发（24/26）在 NIC 路径以 `tcp.stream` distinct 区分各连接，与 pcap 同；⑤ IPv6（23）NIC 抓包不引入 VLAN 偏移（fixture 无 VLAN，offset 74 两路径一致）；⑥ 粘行段（21）两路径同为单段两行、段内 LF 计数断言一致（与 64-cwmp/66-doh/67-onvif/68-hl7/70-megaco/65-bacnet/73-ethmining/74-xmrmining 同形）。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[tcp, stratum]`（引擎自动补 `ip`；需要显式地址族时写 `[ip, tcp, stratum]` 或 IPv6 等价链）。比特币 stratum 报文是 TCP payload 的**行式字节流内容**，与 73-ethmining/72-edp 同款"TCP 之上直接组行"的终结层形态——**无消息长度前缀、无记录头，消息边界只由 JSON 文本后的单个 LF（`0x0a`）决定**（wiki 全部示例行式形态；私有长度前缀进负例）。

端口：**3333**（slushpool/Braiins 传统默认端口，⑤"公开资料 + 假设，实现阶段实证校准"——NiceHash 等矿池另挂 4444/25 等，端口不是协议识别证据，可配置覆盖，planner 不得静默改写）。本版 fixture 统一 `dst_port=3333`；**非默认端口显式声明即合法通道（v2.1.0 C-2）**——正例 29 `stratum_port_nondefault` 行使 4444（公开矿池常用端口，端口不进 stratum 行内容，行字节与用例 1 一致）；未显式声明的非 3333 端口拒绝（负例 38 校验）。**无 DecodeAs 依赖声明**：本机无 stratum 专用 dissector（用例 §1 实测——`-G fields` 无 `stratum.*`，JSON dissector 裸 TCP 不解析且不可 decode-as），全部断言走 `tcp.payload`/frames，与端口无关——"非默认端口需 DecodeAs"判例（hl7#27/bacnet#46）在本协议不适用（彼处有 dissector 依赖端口自动解码，此处无 dissector 可言）。

固定偏移：无 VLAN（虚拟局域网）、IP options（IP 选项）与 TCP options 时，**每条 stratum 行的首字节（`{`，`0x7b`）起点为 IPv4 offset（偏移）54（Ethernet 14 + IPv4 20 + TCP 20）、IPv6 offset 74**（14 + IPv6 40 + TCP 20；构造 pcap 实测印证，`tcp.payload` 即完整行含行尾 `0a`）。**TCP 分段边界不是 stratum 行边界**：一个 TCP 段可含半行（跨 MSS 大行）、整行或多行粘连（行边界由 `0a` 自然定界），接收端按 LF 循环取行重组（§3.1）。

## 3. 线格式编码（逐项标注出处）

### 3.1 行式组帧与 JSON 序列化规则

- **消息边界**：每行 = 一个完整 JSON 对象 + 行尾单个 LF（`0x0a`）。行内不得出现未转义控制字符；CR（`0x0d`）不属于本协议（CRLF 进负例）。
- **JSON 形态**：wiki/参考实现示例为带空格的排版形态，线上字节由生成器钉死为**紧凑形态**（成员间无空格，`{"id":1,"method":…}`，现网客户端实际行为）；成员顺序钉死——请求/通知 `id,method,params`，响应 `id,result,error`。
- **`id` 取材与配对**：请求 `id` 为 JSON number，**由矿机迭代、会话内唯一、起点任意**（wiki 各方法示例；矿池响应必须按 `id` 值配对，不得按 TCP 位置配对）。通知与 `client.show_message` 的 `id` 恒为 `null`，不得写成伪值（伪 id 进负例）。矿池侧反向请求（`client.get_version`）的 `id` 由矿池侧自选，矿机响应同值回带。
- **响应形状**：`{"id":<同值>,"result":<成功载荷或 false>,"error":<null 或错误三元组>}`。错误三元组 = `[<code 数值>, <message 字符串>, <traceback|null>]`（wiki/错误表；第三元素 fixture 恒 `null`）。
- **hex 字段编码**：全部 hex 数据字段（prevhash/coinb1/coinb2/merkle 步/version/nbits/ntime/extranonce1/extranonce2/nonce/version_bits/订阅标识）为 ASCII 十六进制字符串，**小写、无 `0x` 前缀、偶数长度**（wiki/参考实现全部示例形态；比特币 stratum **不存在** `0x` 方言——与 ethash 的 `0x` 变体不同，带前缀即非法，进负例）。
- **字节序声明（逐字段）**：`prevhash` 为 32 字节区块哈希的**内部字节序（与区块浏览器展示序逐字节相反）**——参考实现 `block_template.py`：`binascii.unhexlify(util.reverse_hash(data['previousblockhash']))` 显式反转；`version`/`nbits`/`ntime`/`nonce` 为 4 字节值的**内部（小端）hex 形态**（⑤：参考实现仅显式反转 prevhash，其余按区块头内部序直传为公开资料口径，实现阶段实证校准）；其余 hex 字段（coinbase/merkle/extranonce）为原始字节序的 ASCII hex，无反转。
- **difficulty 序列化**：JSON number，**钉死十进制定点表示**（整数形态 `16384`，⑤：现网典型值；小数合法但本版 fixture 取整数），**禁止科学计数法**（生成器须定点格式化，不得依赖运行时 float 默认序列化）。
- **行长公式**：`L(line) = <固定常量> + Σ len(可变字段)`（含行尾 LF），逐消息固定常量见 §3.13（全部经脚本对 fixture 常量核验）；无协议级行长上界（coinb1/coinb2 与 merkle 步数随区块模板变化），实际受 TCP 流与生成器缓冲约束。

### 3.2 消息总表（方法 / 方向 / params / 应答，出处逐条）

| 消息 | 方向 | id | params（位置语义，出处 wiki/参考实现/BIP310） | 应答 |
|---|---|---|---|---|
| `mining.subscribe` | 矿机→矿池 | number | 1 元素（本版 fixture）：[0] 矿机名/版本（user agent）；wiki 另载可选 [1] 会话恢复 extranonce1（⑤：fixture 不使用，§4 声明） | 订阅响应（§3.3） |
| `mining.extranonce.subscribe` | 矿机→矿池 | number | 0 元素 `[]`（wiki §mining.extranonce.subscribe） | `result=true`（支持）；不支持路径 fixture 不产生（§4 声明②） |
| `mining.authorize` | 矿机→矿池 | number | 2 元素：[0] 用户名（账号.矿机名），[1] 密码（可省略场景本版不使用，fixture 恒两元素） | `result=true` 或 `result=false + error`（鉴权拒绝，§3.5） |
| `mining.set_difficulty` | 矿池→矿机 | `null` | 1 元素：[0] difficulty（number；作用于**后续到达的 job**，wiki §mining.set_difficulty："begin enforcing the new difficulty on the next job received"） | 无 |
| `mining.notify` | 矿池→矿机 | `null` | **9 元素**：[0] job_id、[1] prevhash（32B 反转 hex）、[2] coinb1、[3] coinb2、[4] merkle_branch 数组、[5] version、[6] nbits、[7] ntime、[8] clean_jobs（boolean）——顺序逐条 wiki §mining.notify（九字段）+ 参考实现 `subscription.py` 发射序 | 无 |
| `mining.set_extranonce` | 矿池→矿机 | `null` | **2 元素**：[0] 新 extranonce1（hex）、[1] 新 extranonce2_size（number）；对**后续 job** 生效（wiki §mining.set_extranonce："beginning with the next mining.notify job"）；**1 元素形态为 ethash 方言（73-ethmining），混入进负例锚 `params`** | 无 |
| `mining.submit` | 矿机→矿池 | number | **5 元素**：[0] 用户名、[1] job_id、[2] extranonce2（hex，长度 = 2×extranonce2_size）、[3] ntime、[4] nonce——wiki §mining.submit（五项）+ 参考实现 `service.py` `submit(worker_name, job_id, extranonce2, ntime, nonce)`；version-rolling 激活时追加第 6 参 version_bits（BIP310，§3.11） | 提交响应三态（§3.9） |
| `client.get_version` | **矿池→矿机** | number | 0 元素 `[]`（wiki §client.get_version）；**方向反转**：矿池为请求方，矿机响应 | 矿机响应 `result=<版本字符串>` |
| `client.show_message` | 矿池→矿机 | `null` | 1 元素：[0] 人读消息字符串（wiki §client.show_message） | 无（纯通知） |
| `mining.configure` | 矿机→矿池 | number | 2 元素：[0] 扩展名数组、[1] 扩展参数映射（BIP310 §mining.configure verbatim） | 结果映射（§3.11） |
| `mining.set_version_mask` | 矿池→矿机 | `null` | 1 元素：[0] 新 TMask（8 字符 hex）；**立即生效**（BIP310 verbatim 示例 `["00003000"]`） | 无 |

**方向违例**：矿机侧发通知（notify/set_difficulty/set_extranonce/set_version_mask/show_message）、矿池侧发请求（subscribe/authorize/submit/configure）均为线格式/方向错，进负例（§7 行 32，锚 `unknown`）。`client.get_version` 是唯一矿池→矿机的请求方向。

### 3.3 `mining.subscribe` 请求/响应

请求（本版 fixture 单元素形态，紧凑化）：

```text
{"id":1,"method":"mining.subscribe","params":["MinerName/1.0.0"]}\n
```

响应（wiki §mining.subscribe 结果三段式：订阅对数组 + extranonce1 + extranonce2_size；参考实现 `service.py`：`Pubsub.subscribe(...) + (extranonce1_hex, extranonce2_size)`）：

```text
{"id":1,"result":[[["mining.set_difficulty","7f1a2b3c"],["mining.notify","9d8e7f6a"]],"ea02567c",4],"error":null}\n
```

| 字段 | 位置 | 类型/宽度 | 值域与约束 | 出处 |
|---|---|---|---|---|
| `id` | 成员 | number | 与请求同值回带 | wiki |
| `result[0]` | 数组 | 订阅对数组 | `[["mining.set_difficulty",<id1>],["mining.notify",<id2>]]`——**比特币现网为双订阅对**（wiki 示例 set_difficulty 在前 notify 在后；ethash 仅单 notify 对，73 口径）；订阅标识为 hex 字符串，长度未钉死（fixture 取 8 hex） | wiki（示例数组）+⑤ |
| `result[1]` | 数组 | hex 字符串 | **extranonce1**，"Hex-encoded, per-connection unique string"（wiki 原文）；长度未钉死，参考实现 4 字节（`extranonce_counter.py` `struct.calcsize('>L')` 大端计数）——fixture 取 4B/8 hex，公开矿池 2–8B 均有（⑤） | wiki + 参考实现 +⑤ |
| `result[2]` | 数组 | number | **extranonce2_size**："The number of bytes that the miner uses for its ExtraNonce2 counter"（wiki 原文）；参考实现 = coinbase 占位 8 字节（`coinbasetx.py` `'>Q'`）− extranonce1 4 字节 = **4**；fixture 基线 4、边界 8 | wiki + 参考实现 |
| `error` | 成员 | `null` | 成功恒 `null` | wiki |

### 3.4 `mining.extranonce.subscribe`

请求 `{"id":2,"method":"mining.extranonce.subscribe","params":[]}\n`（wiki：单方法 0 参，"Indicates to the server that the client supports the mining.set_extranonce method"）。响应 `{"id":2,"result":true,"error":null}\n`。该请求为 `mining.set_extranonce` 的触发前提（wiki）；不支持时矿池行为（忽略/拒绝）为矿池自由裁量（⑤），本版 fixture 不产生，声明见 §4。

### 3.5 `mining.authorize` 请求/响应

请求 `{"id":2,"method":"mining.authorize","params":["alice.rig1","x"]}\n`（用户名 = 账号.矿机名现网惯例，⑤）。响应成功 `{"id":2,"result":true,"error":null}\n`；拒绝路径 `{"id":2,"result":false,"error":[24,"Unauthorized worker",null]}\n`（wiki §mining.authorize："result … usually true (successful), or false"；错误码 24 与文案出自错误表，**文案大小写公开实现存在大小写差异（node 实现小写），fixture 钉死 wiki 标题形态，实现阶段实证校准**，⑤）。**authorize 必须发生在 submit 之前**（参考实现 `service.py`：未授权提交抛 "Worker is not authorized" → 错误 24；未订阅提交 → 错误 25，检查顺序先订阅后授权，错误表）。用户名/密码为 ASCII 字符串，无规范长度上界，受行长公式约束。

### 3.6 `mining.set_difficulty` 通知

`{"id":null,"method":"mining.set_difficulty","params":[16384]}\n`。规则（均 wiki §mining.set_difficulty）：① 难度变更**作用于后续到达的 job**（"begin enforcing the new difficulty on the next job received"；正例 8 承载时序）；② "Some pools force a new job via clean_jobs so the change applies immediately"——矿池可随难度变更立即推 clean=true 新 job（wiki 原文），本版 fixture 不产生（次要合法行为声明，§4）；③ difficulty 为 number（fixture 整数 16384/32768）。**未发 set_difficulty 直接 notify 的线序**：wiki 无 MUST 条款（与 ethash 的难度 1 兜底 MUST 不同），公开矿池现实存在——声明为**未约束自由度**，validator 不设约束、不设例（§4）。

### 3.7 `mining.notify` 通知

`{"id":null,"method":"mining.notify","params":["3","<prevhash 64hex>","<coinb1>","<coinb2>",["<merkle 步 64hex>"],"20000000","a13c2c17","64f50123",false]}\n`。九元素语义（wiki §mining.notify 九字段原文 + 参考实现 `subscription.py` 发射序 `(job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs)`）：

| # | 字段 | 类型/宽度 | 语义与约束 |
|---:|---|---|---|
| 1 | job_id | 字符串 | "used to match submissions to work"——**submit 的关联键**（现网为数字串，fixture 钉死 `"3"`/`"4"`，⑤） |
| 2 | prevhash | 64 hex（32B） | "Hash of previous block"，**内部字节序（展示序逐字节反转）**——参考实现 `block_template.py` `util.reverse_hash` 显式反转；fixture 钉死展示序/线序一对值（§8，正例 13 断言） |
| 3 | coinb1 | hex（偶数长） | 世代交易前段——"The miner inserts ExtraNonce1 and ExtraNonce2 after this section"（wiki 原文）；参考实现 `block_template.py` `hexlify(self.vtx[0]._serialized[0])` |
| 4 | coinb2 | hex（偶数长） | 世代交易后段——"appended after the two extranonce values"；extranonce1‖extranonce2 拼接插在 coinb1/coinb2 之间（wiki §Extranonce semantics + 参考实现 `serialize_coinbase`：`part1 + extranonce1 + extranonce2 + part2`） |
| 5 | merkle_branch | hex 字符串数组 | "List of merkle branches"——逐个与 coinbase 哈希折叠得 merkle root（wiki 原文）；**可为空数组**（仅 coinbase 交易时零步，参考实现 `merkletree._steps` 空表形态，正例 19 承载） |
| 6 | version | 8 hex（4B） | "Bitcoin block version"，内部（小端）hex 形态（⑤） |
| 7 | nbits | 8 hex（4B） | "The encoded network difficulty"，内部（小端）hex 形态（⑤） |
| 8 | ntime | 8 hex（4B） | "nTime rolling should be supported, but should not increase faster than actual time"（wiki 原文；submit 的 ntime 可与 notify 不同——滚动合法，本版 fixture 不产生滚动变体，§4 声明） |
| 9 | clean_jobs | boolean | true："abort work and use the new job immediately"；false："continue current work, switch ASAP"（wiki 原文） |

**订阅后首 job 时序**：参考实现 `subscription.py` 在订阅完成后立即推送首个 job 且 `clean_jobs=True`（`emit_single(..., True)`）——⑤标注的参考实现时序；本版 fixture 统一取"授权后推任务"标准线序，该时序声明不设例（§4 声明④）。

### 3.8 `mining.set_extranonce` 通知

`{"id":null,"method":"mining.set_extranonce","params":["b3f10a44",4]}\n`。规则（均 wiki §mining.set_extranonce）：① 2 元素 `[extranonce1, extranonce2_size]`——replacement values，"beginning with the next mining.notify job" 生效（正例 9 承载：轮换后 submit 使用新尺寸 extranonce2）；② **触发前提** = 矿机已发 `mining.extranonce.subscribe`（wiki）——本版 fixture 的 set_extranonce 会话恒先发 extranonce.subscribe（正例 9 断言前提行在场）；③ **1 元素形态为 ethash 方言（73-ethmining 钉死），混入进负例锚 `params`**——两协议在此字段上互为对方的方言负例，家族口径一致。

### 3.9 `mining.submit` 请求与响应三态

请求 `{"id":3,"method":"mining.submit","params":["alice.rig1","3","1a2b3c4d","64f50123","9c5a2b1d"]}\n`（五参：worker_name/job_id/extranonce2/ntime/nonce，wiki §mining.submit + 参考实现签名 verbatim）。**extranonce2 长度硬校验**：hex 字符数 = 2 × 当前 extranonce2_size（subscribe 响应或最近 set_extranonce 声明；错误表 `[20,'incorrect size of extranonce2']` 佐证尺寸受检）。响应三态：

| 形态 | 线上形态（fixture） | 语义 |
|---|---|---|
| 接受 | `{"id":3,"result":true,"error":null}\n` | share 入账（正例 10） |
| 拒绝 | `{"id":3,"result":false,"error":[21,"Job not found",null]}\n` | 拒绝原因在错误三元组（21 = stale/旧 job）；**拒绝是合法协议路径，会话继续**（正例 11）；文案为 fixture 钉死 wiki 标题形态（⑤） |
| 其他错误 | `result=false + error[<code>,<msg>,null]` | 三元组结构完整；会话继续（本版 fixture 不产生非 21 的提交错误码，声明） |

**错误码表**（wiki 错误码条目 + 错误表/参考实现字面值；⑤文案形态）：

| code | message（fixture 形态） | 语义 |
|---:|---|---|
| 20 | `Other/Unknown` | 其他/未知（尺寸错、ntime 越界等内部检查） |
| 21 | `Job not found` | 旧 job（stale）——提交引用的 job 已被矿池淘汰 |
| 22 | `Duplicate share` | 重复提交同一 share |
| 23 | `Low difficulty share` | share 未达当前难度 |
| 24 | `Unauthorized worker` | worker 未通过授权（参考实现检查序：未订阅 25 → 未授权 24） |
| 25 | `Not subscribed` | 未订阅即提交 |

### 3.10 `client.*` 反向消息（矿池→矿机）

- **`client.get_version`**（wiki §client.get_version）：矿池请求 `{"id":8,"method":"client.get_version","params":[]}\n`，矿机响应 `{"id":8,"result":"MinerName/1.0.0","error":null}\n`（"client returns a result string with name and version"）。**方向反转**：本协议唯一矿池发起的请求-响应对（自动应答成分：收到该行自动补同 id 响应行）。
- **`client.show_message`**（wiki §client.show_message）：矿池通知 `{"id":null,"method":"client.show_message","params":["Maintenance in 10 minutes"]}\n`，无应答。
- **`client.reconnect`**：§1 声明不实现（传输层重定向语义）。

### 3.11 BIP310 扩展（`stratum_bip310_ext`）

- **`mining.configure`**（BIP310 verbatim 示例，fixture 取 version-rolling 单扩展）：请求 `{"id":5,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"ffffffff","version-rolling.min-bit-count":16}]}\n`——[0] 扩展名数组（REQUIRED）、[1] 扩展参数映射（REQUIRED）；响应 `{"id":5,"result":{"version-rolling":true,"version-rolling.mask":"1fffe000"},"error":null}\n`——结果映射每扩展一个 TExtensionResult（`true`/`false`/错误字符串），version-rolling 支持时附带交集掩码：**response mask = server_mask & miner_mask**（BIP310："the largest mask possible"）。未知扩展返回 `"version-rolling": false`（BIP310 示例），本版 fixture 恒支持路径。
- **TMask**：**8 字符大小写不敏感 hex 字符串**（BIP310 类型定义，编码 32 bit 无符号整数）——长度恒 8，进 §8 边界。
- **`mining.set_version_mask`**：矿池随时推送 `{"id":null,"method":"mining.set_version_mask","params":["00003000"]}\n`（BIP310 verbatim 示例），**立即生效**（BIP310 原文 "it is valid immediately"——与 set_difficulty/set_extranonce 的"后续 job 生效"不同，正例 17 断言）。
- **submit 第 6 参**：version-rolling 激活后 submit 必须追加 `version_bits`（TMask）——BIP310："the client must send one additional 6th parameter — version_bits — after worker_name, job_id, extranonce2, ntime, and nonce"；约束 `version_bits & ~last_mask == 0`，矿池计算 `nVersion = (job_version & ~last_mask) | (version_bits & last_mask)`（BIP310 原式）。**未激活时第 6 参非法**（validator 硬校验，负例 33 锚 `params`）；fixture 激活值 `18000000` ⊆ `1fffe000` ⊆ `ffffffff` 满足约束。

### 3.12 与 73-ethmining（ethash）/76-getwork 的区分（不混装）

| 维度 | 本协议（比特币 stratum） | 73-ethmining（ethash） | 76-getwork（节点 RPC） |
|---|---|---|---|
| notify 参数 | **9 元素**（job_id/prevhash/coinb1/coinb2/merkle 分支/version/nbits/ntime/clean_jobs） | 4 元素（job_id/seedhash/headerhash/clean_jobs） | 无通知（轮询） |
| submit 参数 | **5 元素**（extranonce2/ntime/nonce…；version-rolling 时 6 参） | 3 元素（worker/job_id/minernonce） | `eth_submitWork` 三参 |
| 工作构造 | coinbase 两段 + merkle 树（矿机拼装） | 无 coinbase/merkle（DAG 体系） | 服务端全量工作对象 |
| extranonce | extranonce1 + extranonce2 双段（subscribe 返回 [1] 段 + [2] 尺寸） | 单段 ≤3 字节 + minernonce 8−len 互补 | 无 |
| prevhash/seedhash | prevhash 32B **字节反转** | seedhash/headerhash 32B 无反转 | — |
| set_extranonce | **2 元素** [extranonce1, extranonce2_size] | **1 元素** [extranonce] | — |
| 扩展 | BIP310 mining.configure/version-rolling/set_version_mask | NiceHash extranonce subscribe 扩展 | — |
| 难度先行 | 无 MUST（未约束自由度） | spec §III MUST（难度 1 兜底） | — |
| 载体 | TCP 明文行式（3333） | TCP 明文行式（4444） | HTTP JSON-RPC（8545） |

planner 对跨协议方法混入（ethash 的 1 参 set_extranonce、GetWork 的 `eth_getWork`）按未知方法/方言参数拒绝（负例 28/29）。

### 3.13 每消息行长公式汇总（固定常量经脚本对 fixture 核验）

| 消息 | 行长公式（B，含行尾 LF） | fixture 样例长 |
|---|---|---:|
| subscribe 请求 | `50 + len(id) + len(user_agent)` | 66 |
| subscribe 响应 | `88 + len(id) + len(订阅对1 id) + len(订阅对2 id) + len(extranonce1) + len(extranonce2_size 串)` | 114 |
| extranonce.subscribe 请求 | `59 + len(id)` | 60 |
| 响应 true（通用形态） | `35 + len(id)` | 36 |
| authorize 请求 | `53 + len(id) + len(user) + len(pass)` | 65 |
| authorize 响应 false | `42 + len(id) + len(code) + len(msg)`（v2.1.1 R-1 勘误：拒绝响应与 submit 拒绝同骨架同常量——`{"id":`(6)+`,"result":false,"error":[`(25)+`,"`(2)+`",null]}`(8)+LF(1) = 42；64 = 42+1+2+19 实测核验，v2.1.0 误采 round-1 D-5 的 43） | 64 |
| set_difficulty | `57 + len(difficulty 串)` | 62 |
| notify | `75 + len(job_id) + 64 + len(coinb1) + len(coinb2) + Σ len(merkle 步) + 8 + 8 + 8 + len(clean 串)` | 387 |
| notify（空 merkle，clean=true） | `73 + len(job_id) + 64 + len(coinb1) + len(coinb2) + 8 + 8 + 8 + 4` | 320 |
| set_extranonce | `60 + len(extranonce1) + len(extranonce2_size 串)` | 69 |
| submit 请求 | `59 + len(id) + len(user) + len(job_id) + len(extranonce2) + len(ntime) + len(nonce)` | 95 |
| submit 响应 false | `42 + len(id) + len(code) + len(msg)` | 58 |
| submit 请求（6 参 version_bits） | `62 + len(id) + len(user) + len(job_id) + len(extranonce2) + len(ntime) + len(nonce) + len(version_bits)` | 106 |
| client.get_version 请求 | `50 + len(id)` | 51 |
| client.get_version 响应 | `33 + len(id) + len(version 串)` | 49 |
| client.show_message | `57 + len(msg)`（v2.1.0 D-4 修正，实测最小值核验） | 82 |
| mining.configure 请求 | `43 + Σ(len(扩展名)+4) + Σ(len(键)+9+len(值))` | 139 |
| mining.configure 响应 | `31 + len(id) + len(result 映射文本)`（v2.1.0 D-6 修正，钉死 fixture 字面值 `{"version-rolling":true,"version-rolling.mask":"1fffe000"}` 实测核验） | 90 |
| mining.set_version_mask | `61 + len(mask)` | 69 |

（`clean 串` = `true`/`false` 字面 4/5 字节；difficulty 串 = 十进制定点文本；所有公式 = 紧凑 JSON 字节数 + 1（LF）。notify 公式对 9 元素逐项：常量 75 含方法名/成员名/数组标点/引号与 LF。）

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性声明**：本引擎对比特币 Stratum 采用**声明式脚本化回放**——配置是剧本（sessions[]/events[] 逐条声明），引擎是回放者，按序产出行帧；"事件驱动"一词不用于定性整体行为，仅用于两处反应性成分：①**自动应答**（subscribe/authorize/extranonce.subscribe/submit 事件后自动补同 `id` 响应行；`client.get_version` 反向请求到达后自动补矿机响应行——响应形态按事件配置的 result/error 展开）；②**连接边界**（事件序列中源端口切换触发新 TCP 连接，即多会话展开）。

| 现网场景 | 事务交互 | 驱动顺序 | 对应用例 |
|---|---|---|---|
| ① 矿机接入（最常见：矿机上电连矿池） | TCP→subscribe→订阅响应→authorize→授权响应 | 矿机驱动请求，矿池侧自动应答 | `stratum_subscribe_ipv4`、`stratum_authorize`、`stratum_extranonce_subscribe` |
| ② 鉴权拒绝 | authorize→`result=false + error[24]`（合法错误路径） | 矿机驱动，矿池拒绝 | `stratum_authorize_reject` |
| ③ 收任务（矿池每新区块/周期一推） | set_difficulty→notify(clean=false 增量 / clean=true 清队列) | 矿池侧事件编排 | `stratum_notify_job`、`stratum_notify_clean_jobs`、`stratum_set_difficulty`、`stratum_set_difficulty_update` |
| ④ share 提交（矿机每找到低于 target 的哈希即提交） | submit→响应 true/false（接受/stale 拒绝，会话均继续） | 矿机驱动 | `stratum_submit_accept`、`stratum_submit_reject` |
| ⑤ extranonce 轮换（矿池负载调度/算力路由） | extranonce.subscribe→set_extranonce→后续 job/submit 用新 extranonce2 尺寸 | 双侧编排 | `stratum_set_extranonce` |
| ⑥ 矿池版本探测与公告 | client.get_version 请求/响应、client.show_message 公告 | 矿池驱动（反向），矿机自动应答/被动接收 | `stratum_client_get_version`、`stratum_client_show_message` |
| ⑦ version-rolling 协商（现代 ASIC 现网标配，BIP310） | configure→响应交集掩码→set_version_mask 推送→submit 6 参 | 双侧编排 | `stratum_configure_version_rolling`、`stratum_set_version_mask`、`stratum_submit_version_bits` |
| ⑧ 多矿机并发（矿场多台矿机同池接入，状态互不串） | 多会话按序展开 或 `concurrent: true` 交错回放 | 各自驱动 | `stratum_multi_session`、`stratum_concurrent_sessions` |
| ⑨ 完整挖矿生命周期 | 接入→收任务→提交→clean=true 新任务→再提交（单连接多事务） | 事件编排会话 | `stratum_mining_lifecycle` |
| ⑩ 异常断开与重连（矿池踢线 RST / 矿机断线重连） | submit 后 RST 短路终止；或 FIN 关闭后重连 = 重新 subscribe + re-authorize（新 extranonce1） | 矿池侧 RST / 矿机侧重连 | `stratum_rst_pool_kick`、`stratum_reconnect_resubscribe` |

**五层覆盖逐层结论**：功能层——11 类消息每类正例（§3.2 表全覆盖：subscribe/extranonce.subscribe/authorize×2 响应态/set_difficulty×2 时序/notify×2 clean 态 + 空 merkle 变体/set_extranonce/submit×2 响应态/client.get_version/client.show_message/configure/set_version_mask），响应错误路径（authorize 拒绝、submit stale 拒绝）以正例承载；每类错误分支（配置/线格式/状态机/关联/长度）负例（§7）。性能层——大 coinb1 notify 行跨 MSS 分段重组（`stratum_mss_large_coinb1`：coinb1 1444 hex、行 1717B、默认 MSS 1460、2 段）、多行粘连单段（`stratum_line_packing`：449B 一段两行）、最小行边界（响应 true 形态 `35+len(id)+1` = 36B 全族最小，由授权/提交/扩展响应行承载）、行长公式上界（无协议上界，受 §3.13 公式约束）。数据场景层——difficulty 值域（16384 基线/32768 变更，整数定点禁科学计数法）、extranonce2_size（4 基线/8 边界，extranonce2 长度 2×尺寸硬校验）、prevhash 字节反转（展示序/线序一对值逐字节断言）、clean_jobs 二值、merkle 空数组/单步两态、job_id 数字串、id 任意起点/递增、错误码 20–25 值域、TMask 恒 8 hex、version_bits 子集约束。地址与流层——IPv4/IPv6 独立 fixture、单流基线、多会话双四元组、**并发会话（`concurrent: true` 交错，正例 26，v2.1.0 C-3 翻案纳入）**、**异常中断 RST（正例 27）与断线重连（正例 28）**、非默认端口 4444（正例 29）；**流关联（控制流派生数据流）显式不适用**：矿机-矿池是单 TCP 长连接行式协议，无控制/数据分离、无副连接概念（wiki 全文仅此一条连接）；**多流（一个会话内部并发流）显式不适用**：单连接串行收发——"单 TCP 流串行"是否定多流的理由、不是否定连接间并发的理由（旧句类别混淆，v2.1.0 C-3 已改）。业务层——接入-收任务-提交链是现网挖矿日常（wiki 各方法即此链路），多会话与多事务（会话内 subscribe→authorize→notify→submit→notify→submit 先后依赖：authorize 先于 submit、set_difficulty 先于首 job——均为参考实现强制的时序）均覆盖。

**次要合法行为显式不适用声明（不设正例、亦不得进负例，§7 防误报同步）**：① subscribe 第二可选参（会话恢复 extranonce1，wiki）——fixture 恒单元素；② extranonce.subscribe 不支持路径（矿池忽略或拒绝，矿池自由裁量，⑤）——本版 fixture 恒回 `result=true`；③ 难度变更随 clean=true 新 job 立即生效（wiki §mining.set_difficulty 尾句的矿池路径）——本版难度变更不伴随新 job；④ 订阅后立即推送首 job（clean=true）的参考实现时序（⑤）——本版 fixture 统一"授权后推任务"标准线序；⑤ ntime 滚动（submit 的 ntime ≠ notify 的 ntime，wiki §mining.notify 尾句）——本版 submit 恒回带 notify 的 ntime；⑥ 未发 set_difficulty 直接 notify（未约束自由度，§3.6③）——validator 不设约束；⑦ extranonce.subscribe 触发前提的执行强制（wiki 未规定矿池必须校验）——validator 不设"未发 extranonce.subscribe 则 set_extranonce 非法"约束（正例 9 恒先发，声明为 fixture 行为而非协议强制）；⑧ 非 21 的其他提交错误码（20/22/23 等编码同拒绝正例三元组结构，不逐码设例）；⑨ `mining.suggest_difficulty`/`mining.suggest_target`/`mining.get_transactions`/`mining.capabilities`/`mining.set_goal`/`client.reconnect`——§1 声明不实现；BIP310 其余扩展（minimum-difficulty/subscribe-extranonce/info）——编码同 configure 结果映射，不逐个设例；⑩ **保活口径（v2.1.0 D-7）**：无应用层 keepalive 帧（stratum 无 PING 类消息），TCP 层 keepalive 探测本版不产生（生成器不发 keepalive 包）——长连接活性由 notify 周期下发体现（正例 25 两次 notify 间隔即默认活性），不设 keepalive 正例亦不进负例；**RST/异常中断与重连已覆盖（v2.1.0 C-5）**：正例 27（RST 短路，`tcp.flags.reset` 断言）+ 正例 28（重连重订阅），FIN 优雅终止由全部正例 `terminates=true` 承载——v1.3 §4 清单"FIN/RST 或异常中断"项双形态闭合。

## 5. 消息/事务模型与状态机

**事务定义**：Stratum 事务 = 同一 TCP 连接内一次完整的请求/响应交互，关联标识为 JSON `id`（响应同值回带）。**多事务** = 一个连接内多笔事务按序执行且有先后依赖：**subscribe 必须是首条 `mining.*` 请求**（`mining.configure` 为唯一允许的前置例外——BIP310："should be the first message sent after connecting"，⑤：现实中部分矿机在 subscribe 之后发送 configure，两种线序均合法，validator 对 configure 位置不设约束）；**authorize 先于 submit**（错误表检查序：未订阅 25 → 未授权 24；submit 的用户名必须等于已授权用户名）；**submit 的 job_id 必须来自本会话已收到的 notify**（job 关联键）；**set_difficulty 先于首条 notify**（现网标准线序，§3.6②——未约束自由度声明见 §4⑥）。通知无应答，不构成事务；事务交互示例：notify（job 3）→submit(3)→notify（job 4, clean=true）→submit(4)——第二笔 submit 依赖第一轮的 job 上下文轮换。

矿机侧会话状态机（确定性：同一事件序列必然产出同一行序列，无随机/未定义行为；生成器在某状态下遇到非法事件——如未订阅先提交——必须拒绝并报状态机错误，不得静默产出）：

| 状态 | 允许事件（→目标状态） | 必须保持 |
|---|---|---|
| `Disconnected` | TCP 三次握手（→`TransportReady`） | 握手后首条应用消息为 subscribe（或 BIP310 configure） |
| `TransportReady` | [可选] 发 configure+收响应（保持）；发 subscribe（→`Subscribing`） | configure 响应掩码记为当前 version-rolling 状态（未配置则未激活） |
| `Subscribing` | 收订阅响应（→`Subscribed`）；可选发 extranonce.subscribe+响应（保持） | 响应 id 同值；result[1] extranonce1 与 result[2] extranonce2_size 记为当前 extranonce 状态 |
| `Subscribed` | 发 authorize（→`Authorizing`） | 用户名/密码非空 |
| `Authorizing` | 授权响应 true（→`Authorized`）；false（→`AuthorizedRejected`） | 响应 id 同值 |
| `AuthorizedRejected` | TCP FIN（→`Closed`；本版 fixture 行为） | 拒绝后不得发 submit（错误表 24 语义） |
| `Authorized` | 收 set_difficulty（记当前难度，作用于后续 job，保持）；收 notify（job 集合追加，保持）；收 set_extranonce（更新当前 extranonce1/尺寸，作用于后续 job，保持）；收 set_version_mask（更新掩码，**立即生效**，保持）；收 show_message（保持）；答 client.get_version（保持）；发 submit→收响应 true/false（保持）；TCP FIN（→`Closed`） | submit 用户名 = 已授权用户名；submit job_id ∈ 已收 notify 集合；extranonce2 hex 长度 = 2 × 当前 extranonce2_size；version-rolling 激活时 submit 必带第 6 参且 `version_bits & ~last_mask == 0`，未激活时不得带 |
| `Closed` | — | 关闭后不得产生新行 |

**自动派生规则**（引擎自动补出的行，逐条列出触发条件与内容）：①订阅响应——subscribe 事件后自动补同 `id` 响应行（result 按事件配置的订阅对/extranonce1/extranonce2_size 展开）；②extranonce.subscribe 响应——同 `id` `result=true`；③授权响应——authorize 事件后按 `result` 配置补 `true` 或 `false+error[24]`；④提交响应——submit 事件后按 `result` 配置补 `true` 或 `false+error[21]`；⑤版本响应——`client.get_version` 反向请求事件后自动补同 `id` `result=<配置版本串>`（矿机侧自动应答成分）；⑥TCP 三次握手与 FIN 挥手由 tcp 层自动补（连接边界：源端口切换触发新连接）。每条自动行均可被事件显式覆盖（如拒绝路径）。

**多会话展开**：`sessions[]` 按序整块回放——先跑完第 1 个会话全流程（握手→事件→挥手），再跑第 2 个，不交错；**第二会话包号起点 = 前一会话总包数 + 1**。各会话四元组、id 序列、当前 extranonce、当前难度、job 集合、已授权用户名、version-rolling 状态互不串用（id 同值在不同会话可独立存在，但跨会话响应不得互相消费——负例锚 `id`）。**并发会话（`concurrent: true`）v2.1.0 C-3 翻案纳入**：矿池现网即 N 台矿机并发连接、每连接独立订阅/授权/收 job/提交（§4 场景⑧），由正例 26 `stratum_concurrent_sessions` 承载——三矿机交错回放，各会话四元组/extranonce/难度/job 集合/id 序列互不串用，单会话内事件序仍受本状态机约束（判例 cwmp⑦/doh#24/onvif#56/hl7#26/megaco#45/bacnet#47）；**多流（一个会话内部并发流）仍显式不适用**：单连接串行收发。

**连接关闭与重连语义（v2.1.0 C-5）**：连接关闭（FIN 四步挥手——全部正例默认；或 RST——正例 27，tcp 层 `termination:"rst"` 配置）即会话状态失效（extranonce/job/难度/授权不跨连接存活）；**重连 = 新 TCP 连接 + 重新 subscribe（矿池分配新 extranonce1）+ re-authorize**（正例 28 断言新连接首条应用行为 subscribe、新 extranonce1 distinct）——wiki 无会话恢复语义（subscribe 第二可选参为 §4 声明①不实现），跨连接状态继承不产生。

## 6. 配置 typedef（JSON 形状示例，非 Go 代码）

```json
{
  "layers": [{"tcp": {}}, {"stratum": {}}],
  "src_ip": "192.0.2.75", "dst_ip": "198.51.100.75",
  "src_port": 4075, "dst_port": 3333,
  "stratum": {
    "profile": "stratum_v1",
    "extensions": [],
    "sessions": [
      {
        "src_port": 4075, "dst_port": 3333,
        "events": [
          {"kind": "subscribe", "id": 1, "user_agent": "MinerName/1.0.0",
           "subscriptions": [["mining.set_difficulty", "7f1a2b3c"], ["mining.notify", "9d8e7f6a"]],
           "extranonce1": "ea02567c", "extranonce2_size": 4},
          {"kind": "extranonce_subscribe", "id": 2, "result": true},
          {"kind": "authorize", "id": 2, "username": "alice.rig1", "password": "x", "result": true},
          {"kind": "set_difficulty", "difficulty": 16384},
          {"kind": "notify", "job_id": "3",
           "prevhash": "b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5c43402000000000000000000",
           "coinb1": "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1603aa1a0b2f706f6f6c2e746573742f",
           "coinb2": "1603018e0c2f706f6f6c2e746573742f00000000",
           "merkle_branch": ["aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233"],
           "version": "20000000", "nbits": "a13c2c17", "ntime": "64f50123", "clean_jobs": false},
          {"kind": "submit", "id": 3, "username": "alice.rig1", "job_id": "3",
           "extranonce2": "1a2b3c4d", "ntime": "64f50123", "nonce": "9c5a2b1d", "result": true}
        ]
      }
    ],
    "wire_fault": ""
  }
}
```

形状要点：`sessions[]` = 统一术语的**事件编排会话**（每个自带四元组与事件序列，多会话展开按序整块回放，第二会话包号起点 = 前一会话总包数 + 1；`concurrent: true` 并发交错回放——v2.1.0 C-3，正例 26）；`events[]` = 会话的**事件序列**，kind 覆盖 `subscribe`（id/user_agent + 自动响应的 subscriptions/extranonce1/extranonce2_size）/`extranonce_subscribe`/`authorize`（result 控制响应三态）/`set_difficulty`（difficulty 十进制定点）/`notify`（九字段，merkle_branch 为数组）/`set_extranonce`（新 extranonce1 + extranonce2_size，更新会话当前 extranonce 状态）/`submit`（id/username/job_id/extranonce2/ntime/nonce + result 控制响应三态）/`get_version`（**矿池→矿机反向请求**，矿机自动应答 `result=version`）/`show_message`（矿池通知，无应答）/`configure`（extensions 数组 + params 映射 + 响应映射，BIP310）/`set_version_mask`（新掩码，立即生效）；`extensions` = `[]`（主 profile）或 `["version-rolling"]`（BIP310 变体，非独立层链）；`wire_fault` 仅负例注入口（取值 `json`/`framing`/`method`/`params`/`hex`/`state`/`id`/`job`/`carrier`/`address_family`/`propagation` 共 **11 值**，与 §7 表 11 行、用例文档 §5 表三方一一对应——v2.1.0 D-3 显式映射；每行恰注入一个故障，注入形状示例：`{"wire_fault":"framing"}` 注入末行无 LF、`{"wire_fault":"hex"}` 注入 prevhash 62 hex、`{"wire_fault":"address_family"}` 注入 IPv6 地址配 IPv4 层链——F-003 补），不得成为线上字段。**配置到帧的完整路径**：配置 → validator（层链/端口/事件序状态机/id 会话内唯一/hex 值域与偶数长/extranonce2 尺寸匹配/job 关联/version_bits 约束校验）→ planner（事件序列展开为行序列，紧凑 JSON 序列化 + LF，按 §3.13 公式计算行长）→ worker（TCP 分段：默认每行一段，>MSS 自动分段，段数 = 行长对 MSS 上取整；`pack` 相邻同方向行合并为一段）→ writer（PCAP/NIC）。

## 7. 错误处理（负例锚词表）

以下输入必须由 planner/validator 拒绝并传播为 task error（任务错误），不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。**单一注入纪律（v2.1.0 C-4/N-4）：每行恰注入一个故障；主锚词为钉死的单一字面值**（不再是候选列表），与用例文档 §5 表一一对应（11 行同序，`wire_fault` 11 值三方映射见 §6）：

| # | 负例 ID | 类别 | 故障输入（单一注入） | 主锚词 `error_contains` |
|---:|---|---|---|---|
| 30 | `stratum_neg_json` | 线格式错 | 行内容非法 JSON：截断对象、未闭合字符串、非对象行 | `json` |
| 31 | `stratum_neg_framing` | 线格式错 | 行组帧错：行尾无 LF（裸结束）、CRLF 混入、私有长度前缀取代换行 | `framing` |
| 32 | `stratum_neg_method` | 线格式错 | 方法错：未知 method（含声明不实现的 `mining.get_transactions`/`eth_getWork` 混入）、方法方向违例（矿机发 notify、矿池发 submit/configure） | `unknown` |
| 33 | `stratum_neg_params` | 线格式错 | params 元素数量/类型/位置错：subscribe 空数组、authorize 单参、notify 8 元素、submit 缺 nonce、set_extranonce 1 元素（ethash 方言）、clean_jobs 非布尔、merkle_branch 非数组、extranonce2_size 非数值、未激活 version-rolling 时 submit 6 参 | `params` |
| 34 | `stratum_neg_hex` | 值域错 | hex 字段违例：prevhash/merkle 步 ≠64 hex、version/nbits/ntime/nonce/version_bits ≠8 hex、非 hex 字符、奇数长度、`0x` 前缀（比特币 stratum 无 0x 方言） | `hex` |
| 35 | `stratum_neg_state` | 状态机错 | 首条应用消息既非 subscribe 也非 configure、未 authorize 先 submit、会话关闭后继续排事件 | `state` |
| 36 | `stratum_neg_id_correlation` | 关联错 | 响应 id 与请求不匹配、通知携带非 null 伪 id、**subscribe(id=1) 未收响应时 authorize 复用 id=1（会话内未完成事务 id 重复——单一变异仅 id 复用，method 不同非变异点，v2.1.0 C-4 钉死）** | `id` |
| 37 | `stratum_neg_job_correlation` | 关联错 | submit 的 job_id 不来自本会话已收 notify、submit 用户名与已授权用户名不一致 | `job` |
| 38 | `stratum_neg_carrier` | 配置/载体错 | 层链缺 tcp（`[stratum]` 直连）、UDP 载体、端口/载体声明矛盾 | `carrier` |
| 39 | `stratum_neg_address_family` | 配置/载体错 | IPv6 地址配 IPv4 层链（`[ip, tcp, stratum]` 形态 + v6 地址）或反向——混合地址族拒绝（v2.1.0 D-8 补） | `ip` |
| 40 | `stratum_neg_error_propagation` | 错误传播错 | validator/planner 已知错误被吞、任务假成功、0 包或错误响应丢失 | `propagat` |

**不得误报为 planner error 的合法协议事件**：submit 拒绝（`result=false + error[21]`，正例 11）、authorize 拒绝（正例 4）、难度变更（正例 8）、set_extranonce 轮换（正例 9）、空 merkle 数组（正例 19）、extranonce2_size=8（正例 20）、大 coinb1 行（正例 22）、client.get_version/show_message 反向消息（正例 14/15）、configure 先于 subscribe（正例 16——负例 31 的"首条"约束恒排除 configure）、version_bits 第 6 参在 version-rolling 激活时（正例 18）。只有配置、线格式、状态、关联、长度错误进入负例。

## 8. 边界

- **行长与分段**：notify 行 = `75 + len(job_id) + 64 + len(coinb1) + len(coinb2) + Σ len(merkle 步) + 8+8+8 + len(clean 串)`；`stratum_mss_large_coinb1` 用 coinb1 1444 hex 字符 ⇒ 行 1717B，默认 MSS 1460 不压，跨 2 段（1460+257），接收端按 LF 重组后断言完整行——**分段边界不切坏行内容，也不产生伪行界**（行内无 0x0a 字节是 JSON 文本保证：ASCII hex/方法名无 LF）。
- **多行粘连**：`stratum_line_packing` 将 set_difficulty（62B）+ notify（387B）合并为一段 449B 载荷，段内恰 2 个 `0a`；接收端按行拆分，段边界 ≠ 行边界两个方向都断言。
- **extranonce 双段**：extranonce1 长度未钉死（fixture 4B/8 hex，⑤）；extranonce2_size 基线 4（参考实现 8−4 推导）、边界 8（正例 20，extranonce2 16 hex）；submit extranonce2 长度 = 2×当前尺寸硬校验（违例进负例 33/34）。
- **prevhash 字节反转**：fixture 钉死展示序/线序一对值——展示序 `0000000000000000000234c4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4`，线序（逐字节反转）`b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5c43402000000000000000000`；正例 13 断言线上携带线序值（参考实现 `util.reverse_hash` 行为）。
- **difficulty 值域**：number >0；16384（基线）、32768（变更）；整数定点序列化、禁止科学计数法（§3.1）。
- **id 域**：JSON number，起点任意（正例 12 用 100/101/102）、会话内唯一、递增非协议强制但 fixture 钉死递增；响应同值回带；通知与 show_message 恒 `null`。
- **clean_jobs 二值**：true/false 各一正例（6/5）；非布尔进负例 33。
- **merkle_branch**：空数组（正例 19）与单步（基线）两态；非数组/步长非 64 hex 进负例 33/34。
- **TMask**：恒 8 hex（BIP310 类型定义）；≠8 进负例 34；`version_bits & ~mask != 0` 进负例 33（约束违例按 params 锚）。
- **v4/v6**：IPv4/IPv6 独立 fixture，同一逻辑行字节必须一致，仅外层 IP 头与偏移（54/74）不同；不得从 IPv4 默认值推导 IPv6 地址（fixture 显式给出 `2001:db8::75 → 2001:db8::100:75`）。
- **多会话**：≥2 个独立四元组，id 序列/extranonce/难度/job 集合/用户名/订阅标识互不串用；会话间包序按多会话展开（第二会话起点 = 前会话总包数 + 1）。
- **端口（v2.1.0 C-2）**：默认 fixture 3333；非默认端口 4444 **显式声明即合法通道**（正例 29——端口不进 stratum 行内容，行字节与基线一致），未显式声明的非 3333 端口拒绝（负例 38）；无 dissector 无 DecodeAs 依赖（§2 声明）。
- **并发/异常中断/重连（v2.1.0 C-3/C-5）**：并发交错正例 26（与 24 按序展开分立）；RST 异常中断正例 27（`tcp.flags.reset==1`、RST 后无业务行、无挥手）；重连重订阅正例 28（新 extranonce1 distinct、会话状态失效语义）。
- 不得产生回绕长度或超量分配（行长无协议上界，受生成器缓冲与 TCP 约束；大 coinb1 压力值 1444 hex 在配置显式声明，不隐式放大）。

## 9. 原子 ID 与完成定义

设计、testcase 与未来 `stratum.json` 必须使用同一组 **40 个唯一语义 ID（29 正 + 11 负）**、同一顺序（原子用例：一个用例只验证一个协议行为；每消息类型/每响应态/每时序变体/每长度边界/每关联规则/每错误分支各一——数量由协议结构决定，超过 20 条符合 v1.3 §7）；当前 JSON 另有不计入的 `stratum_neg_unregistered` 占位。

| # | ID | 类型 | 覆盖（设计 §） |
|---:|---|---|---|
| 1 | `stratum_subscribe_ipv4` | 正 | §3.3：订阅请求/响应全字段（双订阅对 + extranonce1 + extranonce2_size），IPv4 单流基线 |
| 2 | `stratum_extranonce_subscribe` | 正 | §3.4：extranonce 订阅请求 + `result=true` |
| 3 | `stratum_authorize` | 正 | §3.5：授权请求/成功响应（user/pass 两元素） |
| 4 | `stratum_authorize_reject` | 正 | §3.5：`result=false + error[24,"Unauthorized worker",null]` 拒绝路径（合法错误路径） |
| 5 | `stratum_notify_job` | 正 | §3.7：notify 九元素完整行（clean=false），难度先行时序 |
| 6 | `stratum_notify_clean_jobs` | 正 | §3.7：clean_jobs=true 变体（布尔二值边界） |
| 7 | `stratum_set_difficulty` | 正 | §3.6：难度通知（16384，通知行边界；全族最小行 36B 响应由用例 3/10 承载） |
| 8 | `stratum_set_difficulty_update` | 正 | §3.6：会话中难度变更（16384→32768），作用于后续 job |
| 9 | `stratum_set_extranonce` | 正 | §3.8：set_extranonce 轮换（尺寸 4→8）+ 后续 submit extranonce2 16 hex（后续 job 生效） |
| 10 | `stratum_submit_accept` | 正 | §3.9：submit 五元素 + `result=true` 接受 |
| 11 | `stratum_submit_reject` | 正 | §3.9：submit + `result=false + error[21,"Job not found",null]` 拒绝（会话继续） |
| 12 | `stratum_id_correlation` | 正 | §3.1/§5：id 任意起点（100/101/102）、按值配对（非 TCP 位置配对） |
| 13 | `stratum_prevhash_byteorder` | 正 | §3.1/§8：prevhash 字节反转（线上携带线序值，与展示序逐字节相反） |
| 14 | `stratum_client_get_version` | 正 | §3.10：矿池→矿机反向请求 + 矿机自动响应（方向反转成分） |
| 15 | `stratum_client_show_message` | 正 | §3.10：矿池通知（id=null，无应答） |
| 16 | `stratum_configure_version_rolling` | 正 | §3.11：mining.configure 请求/响应（BIP310 首条线序 + 交集掩码 `1fffe000`） |
| 17 | `stratum_set_version_mask` | 正 | §3.11：掩码推送通知（BIP310 verbatim `["00003000"]`，立即生效） |
| 18 | `stratum_submit_version_bits` | 正 | §3.11：version-rolling 激活下 submit 第 6 参 `version_bits`（`18000000` ⊆ `1fffe000` 约束满足） |
| 19 | `stratum_notify_empty_merkle` | 正 | §3.7/§8：merkle_branch 空数组边界（clean=true 变体） |
| 20 | `stratum_extranonce2_size8` | 正 | §3.3/§8：订阅即 extranonce2_size=8 + submit extranonce2 16 hex（长度 2×尺寸） |
| 21 | `stratum_line_packing` | 正 | §2/§8：多行粘连单段（set_difficulty+notify 449B 一段、段内 2 个 LF） |
| 22 | `stratum_mss_large_coinb1` | 正 | §3.13/§8：coinb1 1444 hex ⇒ 行 1717B 跨 MSS 2 段重组 |
| 23 | `stratum_ipv6` | 正 | §2/§8：IPv6 独立 fixture（offset 74） |
| 24 | `stratum_multi_session` | 正 | §5/§8：双矿机双四元组多会话展开（独立 extranonce/难度/job/用户名/订阅标识） |
| 25 | `stratum_mining_lifecycle` | 正 | §4⑨/§5：单会话多事务全链（接入→收任务→提交→clean=true 新任务→再提交） |
| 26 | `stratum_concurrent_sessions` | 正 | §4⑧/§5：三矿机 concurrent 交错回放（extranonce/订阅标识/id 互不串用，与 24 按序展开分立） |
| 27 | `stratum_rst_pool_kick` | 正 | §5：RST 异常中断（tcp.flags.reset，RST 后无业务行、无挥手；FIN/RST 清单项双形态闭合） |
| 28 | `stratum_reconnect_resubscribe` | 正 | §5：断线重连重订阅（新连接首条 = subscribe，新 extranonce1 distinct，会话状态失效语义） |
| 29 | `stratum_port_nondefault` | 正 | §2/§8：非默认端口 4444 显式声明合法通道（端口不进 stratum 行内容，行字节与用例 1 一致） |
| 30 | `stratum_neg_json` | 负 | §7：非法 JSON/截断/非对象行 |
| 31 | `stratum_neg_framing` | 负 | §7：无 LF/CRLF/长度前缀 |
| 32 | `stratum_neg_method` | 负 | §7：未知 method/方言混入/方向违例 |
| 33 | `stratum_neg_params` | 负 | §7：params 数量/类型/位置错（含 ethash 1 参 set_extranonce、未激活 6 参 submit） |
| 34 | `stratum_neg_hex` | 负 | §7：hex 值域/长度/奇偶/0x 前缀/TMask 宽度 |
| 35 | `stratum_neg_state` | 负 | §7：状态机错（首消息/未授权提交/关闭后续排） |
| 36 | `stratum_neg_id_correlation` | 负 | §7：id 错配/伪 id/未完成事务复用（单一变异钉死） |
| 37 | `stratum_neg_job_correlation` | 负 | §7：job 来源/用户名不一致 |
| 38 | `stratum_neg_carrier` | 负 | §7：载体/端口/层链错 |
| 39 | `stratum_neg_address_family` | 负 | §7：IPv6/v4 混合地址族 |
| 40 | `stratum_neg_error_propagation` | 负 | §7：错误未传播/假成功 |

完成定义：注册 `tcp→stratum` 层链；逐字段生成并验证 §3 全部 11 类消息（行式组帧、紧凑 JSON、LF 边界、行长公式、hex 小写无前缀、extranonce2 尺寸匹配、prevhash 字节反转）；订阅/授权/难度（含变更时序）/任务（clean 二值、空 merkle）/extranonce 轮换/提交三态、client.get_version 反向应答、BIP310 三消息与 version_bits 约束、id 关联、多事务、多会话展开、IPv4/IPv6、MSS 分段与粘连重组、全部边界均可观测；40 个语义 ID 正负断言与错误传播完成（含并发/RST/重连/非默认端口/混合地址族）；未注册阶段只接受 `unknown layer` 占位；pcap/NIC 双输出共用本契约（§1 输出契约段）；占位 JSON notes 已于 v2.1.0 同步修正（40/29+11）。

**完成验收对照（v1.3 §8.2，v2.1.0 补）**：① 三方一致（§9/用例 §2/用例 §8 + JSON 占位纪律）——脚本核验通过；② 两条主线（代码设计逻辑 + 用例覆盖）——v2.1.0 重审修复轮执行（审查员 docs-bacnet 20 findings 逐项修复）；③ 原子覆盖——一行一例（§7 单一注入纪律）；④ 失败用例先行——负例锚词钉死单一字面值；⑤ 锚词一致——§7 与用例 §5 逐行同序同词；⑥ pcap+NIC 双输出契约——§1 输出契约段六项；⑦ 待实现标记——§1 边界 + §4 声明⑨⑩ 逐项；⑧ 审查轮次入修订记录——§10 v2.1.0。不声称真实 PoW、share 密码学有效或区块产生。

## 10. 修订记录

- v2.1.1（2026-09-01，复验残留修复轮）：docs-bacnet 复验 20 findings 中 18 项关闭（N-2 反驳成立），本轮清零复验新报 11 处（2D+9N，脚本批改后正文未全落的同型残留）：**R-1**（D）§3.13 authorize 拒绝常量 43 → **42**（与 submit 拒绝同骨架同常量，64 = 42+1+2+19 逐字节复算；round-1 D-5 的 43 有误、v2.1.0 误采）；**R-2**（D）§1 占位段 notes 指令改"已于 v2.1.0 修正为 40/29+11"（旧指令描述不存在的 35/25+10 状态）；R-3 删 §7 旧引言段（双引言并存）；R-4 §3.2 方向违例锚词引用改钉死值 `unknown`；R-5 用例 §6 负例 10 类→11 类；R-6 用例 §7 条目重排 1..9；R-7 §4 场景表 ⑨⑩ 序对调；R-8 用例 §4 总则补"除用例 27 外"；R-9 用例 28 会话 2 extranonce1 段 hex 多余空格；R-10 fixture 补矿机 C 订阅标识对 `3e4f5a6b`/`7c8d9e0f`（并发三矿机订阅标识全钉死）；R-11 §9 行 29"端口不进行内容"补字。

- v2.1.0（2026-09-01，v1.3 行为面全枚举重审修复轮）：docs-bacnet 重审 20 findings（5C + 9D + 6N + 结构三项）逐项修复，35 → **40 例（29 正 + 11 负）**。**C-1** pcap/NIC 双输出契约补入（§1 六项逐条：离线/网卡 offload 不影响断言/跨 MSS 重组/多流 distinct/IPv6 偏移/粘行一致）；**C-2** 新增正例 29 `stratum_port_nondefault`（4444）+ §2 无 DecodeAs 依赖声明（本协议无 dissector，与 hl7#27/bacnet#46 判例形不同因）；**C-3**（MAJOR）并发会话翻案纳入——删"不适用"类别混淆声明（§5 改判：单 TCP 流串行仅能否定多流），新增正例 26 `stratum_concurrent_sessions`（三矿机交错）；**C-4** 负例 36 id 复用描述钉死单一变异 + §7 单一注入纪律声明；**C-5**（MAJOR）RST/重连覆盖——新增正例 27 `stratum_rst_pool_kick`（tcp.flags.reset 断言、无挥手）与 28 `stratum_reconnect_resubscribe`（重连重订阅、新 extranonce1），§5 补连接关闭→状态失效→重连语义，FIN 由全部正例 terminates 承载（清单项双形态闭合）；**D-1/D-2/D-3** 用例 §2 补并发行、§8 显式登记占位 ID、§6 wire_fault 11 值与两表三方显式映射 + §5 表补 wire_fault 注入口列；**D-4/D-5/D-6** 公式常量修正（show_message 55→57、authz_rej 42→43、cfg_resp 30→31，均按 fixture 字面值实测核验）；**D-7/D-8** §4 声明⑩保活口径（无 keepalive 帧、TCP 探测不产生）+ 负例 39 `stratum_neg_address_family`（混合地址族拒绝）；**N-1/N-4** §7/§5 两表同序 + 主锚词钉死单一字面值；**N-5/N-6** 用例 22 断言落点 = 重组后行完整（不要求段界对齐）、用例 21 形态声明 = 单段内两完整行；**N-7** 用例 §7 补计数/notes/单一注入三条静态检查；**D-9** stratum.json 占位 notes 本轮同步修正（40/29+11）；**N-8/F-001** 版本 v2.1.0 + v1.3 修订来源登记；**F-002** §9 补 v1.3 §8.2 八条验收对照；**F-003** §6 补 wire_fault 注入形状示例。负例编号 26–35 → 30–40。审查由 docs-bacnet agent 独立执行，待复验关闭。

- v1.0.0（2026-08-20）：旧稿首版（14 正 + 6 负）——submit 参数命名混入 ethash 方言（`extra_nonce`）、subscribe 响应钉成单订阅对、缺 mining.set_extranonce、无业务场景分析/状态机/行长公式。
- v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-20 旧稿（旧稿见 git 历史）。以 Bitcoin Wiki《Stratum mining protocol》+ BIP310 + slush0/stratum-mining 与 node-stratum-pool 两个参考实现为规范基线逐条提炼：行式 JSON（LF 边界、紧凑形态钉死）、11 类消息（7 类 mining.* + client.get_version/show_message + BIP310 configure/set_version_mask）、params 位置语义、**双订阅对** subscribe 响应、extranonce1/extranonce2 双段语义与 extranonce2 尺寸匹配、**prevhash 字节反转**（参考实现 `util.reverse_hash`）、notify 九参/submit 五参/set_extranonce 双参、错误三元组 20–25、version-rolling 第 6 参约束；与 73-ethmining（ethash）/76-getwork 的三方区分表钉死不混装（set_extranonce 元数互为方言负例）。fixture 全部常量脚本核验（订阅标识/extranonce1 `ea02567c`/job `3`/`4`/prevhash 展示序-线序对/coinb1/coinb2/merkle/difficulty 16384→32768/掩码 `1fffe000`→`00003000`/version_bits `18000000`/错误 `[24,"Unauthorized worker",null]`/`[21,"Job not found",null]`）。用例按 v1.1 原子原则从 20 条重排为 **35 条（25 正 + 10 负）**——每消息类型、每响应态、每时序变体、每长度边界、每关联规则、每错误分支各一例；新增 §4 业务场景分析（五层逐层、流关联与多流显式不适用、九项次要合法行为声明）、§5 状态机与事务模型（自动派生规则含 client.get_version 反向应答）、§6 JSON 配置 typedef 与配置到帧路径、§3.13 行长公式表（脚本核验）；端口 3333、错误文案形态、extranonce1 长度、ntime/version 内部小端序、订阅后首 job 时序按"公开资料 + 假设，实现阶段实证校准"标注；以本机 tshark 3.6.14 构造 pcap 实证（tcp.payload 全行 hex/offset 54/74/行尾 0a）固化断言基线。状态：**待独立隔离审查**。

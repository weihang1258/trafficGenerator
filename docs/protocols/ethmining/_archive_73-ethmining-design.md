# ETHMining（以太坊挖矿 stratum 协议，EthereumStratum/1.0.0 ethash 矿池通信）设计契约

> 版本：v2.0.2（设计阶段）
> 日期：2026-09-01
> 状态：**尚未实现**；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）双输出断言，不宣称当前测试套件可运行，不修改 Go（编程语言）/MCP（模型上下文协议）实现。按《协议设计文档与用例文档需求文档 v1.3》完成行为面全枚举重审修复轮（审查员 review-ethmining：6 confirmed（4 MAJOR + 2 MINOR）+ 6 自洽 + 3 待实现边界），本版 v2.0.2 为修复轮产物：31 → **32 例（22 正 + 10 负）**，待复验关闭；v1.1 流程既有审查修复（v2.0.1）记录见 §10。
> 配套文件：`docs/protocol-designs/73-ethmining-testcase.md`、`trafficgen/test/protocol_pcap/cases/ethmining.json`（当前 JSON 仅含注册前置占位，本版不写文件、不改代码）
> 规范基线：ETHMining = **ethash 挖矿 stratum**（矿机↔矿池 TCP 长连接、行分隔 JSON-RPC 类 2.0 消息），权威依据取以下四层（逐项标注出处）：
> ① **NiceHash《Ethereum stratum mining protocol v1.0.0》R2**（github.com/nicehash/Specifications `EthereumStratum_NiceHash_v1.0.0.txt`，下称 **spec**，按 §I–§V 引用）——本协议**唯一成文规范**，本文 §3 全部消息形态、参数位置、 extranonce ≤3 字节、minernonce 长度互补（8 字节全 nonce）、难度先行 MUST 与难度 1 兜底、clean_jobs 语义、错误三元组 `[-1,"Job not found",null]` 逐条出自 spec（出处写"spec §…"）；
> ② **NiceHash《extranonce subscribe extension》**（同仓 `NiceHash_extranonce_subscribe_extension.txt`，下称 **ext**）——`mining.extranonce.subscribe` 请求/响应与 `mining.set_extranonce` 触发前提的出处（出处写"ext §…"）；
> ③ **以太坊 ethash 算法公开资料**（Ethereum Wiki/Mining 页与 spec §II 转述）：seedhash（32 字节，每 30,000 块 = 1 epoch 变更，用于识别 DAG）、headerhash（32 字节）、nonce 全宽 64 bit（8 字节）、difficulty→target 换算同比特币（difficulty 1 ⇔ target `00000000ffff0000…00`，spec §III 钉死）；
> ④ **公开资料 + 假设，实现阶段实证校准**：端口 4444（ethermine 等主流 ethash 矿池公开接入页 stratum 端口，矿池控制台可配）、0x 前缀方言（ethminer/部分矿池现网携带 `0x`，spec §I.4 明确去除 `0x`，二者并存）、`"jsonrpc":"2.0"` 成员方言（部分矿池消息携带，spec 形态无此成员）、authorize 失败错误码 `[24,"Unauthorized user",null]`（标准 stratum 惯例值，spec 未钉死）——逐处标注；
> ⑤ **本机实测**：tshark 3.6.14 `-G fields`/`-G protocols` + 按 spec 逻辑构造 pcap 实证（`tcp.payload` 精确提取完整行字节、offset 54/74、末字节 `0a`，见用例文档 §1）。
> 修订记录：v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》重写，取代 2026-08-21 旧稿（旧稿见 git 历史）。**旧稿协议定位错误**——旧稿按"节点侧 legacy JSON-RPC（`eth_getWork`/`eth_submitWork`/`eth_getHashrate`/`eth_submitHashrate`，HTTP 端口 8545）"定义，与本协议**ethash stratum（矿机-矿池、TCP 行式、`mining.*` 方法族）**完全不符，全部废弃；本版从 spec + ext 逐条重新提炼（GetWork 轮询协议由 `76-getwork` 单列，两者互不混装）。

## 1. 范围、profile 和未注册边界

本版定义矿机（miner）与矿池（pool）之间的 **ethash stratum 明文 TCP 长连接**：行分隔 JSON（newline-delimited JSON，每行一个 JSON 对象，行尾单个 LF `0x0a`）消息封装、订阅（`mining.subscribe`）、extranonce 订阅扩展（`mining.extranonce.subscribe`）、授权（`mining.authorize`）、难度通知（`mining.set_difficulty`）、任务通知（`mining.notify`）、extranonce 轮换（`mining.set_extranonce`）、share 提交（`mining.submit`）与提交响应三态、JSON-RPC `id` 关联、IPv4/IPv6、多会话与多事务。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `ethmining_stratum_v1`（主 profile） | TCP 明文行式 JSON（fixture 端口 4444，可配置覆盖） | spec 全部 7 类消息 + ext 扩展、行重组、id 关联、share 三态 | 真实 share 密码学有效性、区块产生、真实矿池鉴权、难度与真实网络 target 的对应关系 |
| `ethmining_ipv6_v1` | 同上，仅外层 IPv6 | 同主 profile | 从 IPv4 fixture（固定样本）推导 IPv6 地址 |
| `ethmining_hex_prefix_v1` | 同主 profile，hex 数据字段带 `0x` 前缀 | 会话内前缀统一的方言变体（④ 标注；由主 profile + `hex_prefix:"0x"` 配置选择，非独立层链） | 混合前缀（同一会话 `0x` 与无前缀并存）——进负例 |

显式边界（"不实现、不声称、不许静默转换"）：**EthereumStratum/2.0.0 草案**（`mining.hello`/`mining.set`/`mining.noop`/会话恢复 token，AndreaLanfranchi 草案稿）不在本版；**比特币 stratum 专用消息**（`client.get_version`、`mining.configure`、9 参数 notify、5 参数 submit）不在本版——属 `75-stratum` 契约；**GetWork 轮询**（`eth_getWork` 等 4 个 legacy 方法）不在本版——属 `76-getwork` 契约，planner 对混入方法按未知 method 拒绝（负例）；不声称任何 share 满足真实 ethash target 或产生区块（生成器不执行 PoW 计算，share 内容为 fixture 声明值）。

当前仓库没有注册 `ethmining` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/ethmining.json` 只保留一个不计入语义 ID 的注册前置占位 `ethmining_neg_unregistered`（`expect_error=true`、`error_contains="unknown layer"`；占位为旧稿遗留，`dst_port` 8545 与 notes 旧计数在注册时一并修正为 4444/32 条，本版不改 JSON 文件）。占位的拒绝、0 包或空 PCAP 不得报告为 ETHMining 行为通过；注册后按本文 §9 与用例文档 §2 的同一顺序替换为 32 个语义用例（22 正 + 10 负，v2.0.2 新增正例 22 `ethmining_custom_port`）。

**输出契约（pcap/NIC 双输出，v2.0.2 C1）**：本契约的用例同时服务于 pcap（抓包文件）与 port_group/NIC（网卡）两种输出路径——两路径共用同一份 cases JSON、同一 tshark 字段/帧字节断言（`tcp.payload` 全行 hex、`tcp.len`、`tcp.stream`、offset 54/74 frames），NIC 路径仅经 tcpdump 捕获（`nic_capture` 为用例级开关），L2 无 VLAN 前提下偏移与载荷提取稳定，不改变断言语义（与 64-cwmp/66-doh/67-onvif/68-hl7/70-megaco/65-bacnet 同形）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[tcp, ethmining]`（引擎自动补 `ip`；需要显式地址族时写 `[ip, tcp, ethmining]` 或 IPv6 等价链）。ethash stratum 报文是 TCP payload 的**行式字节流内容**，与 75-stratum/edp 同款"TCP 之上直接组行"的终结层形态——**无消息长度前缀、无记录头，消息边界只由 JSON 文本后的单个 LF（`0x0a`）决定**（spec §III 全部示例行尾 `\n`；私有长度前缀进负例）。

端口：主流 ethash 矿池 stratum 接入端口 **4444**（ethermine 公开接入页 eu1.ethermine.org:4444 一类，"公开资料 + 假设，实现阶段实证校准"；NiceHash Ethash 挂 3353、部分矿池挂 14444——端口不是协议识别证据，可配置覆盖，planner 不得静默改写）。本版 fixture 统一 `dst_port=4444`；**非默认端口显式声明即合法通道（v2.0.2 C2）**——正例 22 `ethmining_custom_port` 行使 3353（端口不进 stratum 行内容，行字节与用例 1 一致）；未显式声明的非 4444 端口拒绝（负例 31）。

固定偏移：无 VLAN（虚拟局域网）、IP options（IP 选项）与 TCP options 时，**每条 stratum 行的首字节（`{`，`0x7b`）起点为 IPv4 offset（偏移）54（Ethernet 14 + IPv4 20 + TCP 20）、IPv6 offset 74**（14 + IPv6 40 + TCP 20；构造 pcap 实测印证，`tcp.payload` 即完整行含行尾 `0a`）。**TCP 分段边界不是 stratum 行边界**：一个 TCP 段可含半行（跨 MSS 大行）、整行或多行粘连（行边界由 `0a` 自然定界），接收端按 LF 循环取行重组（§3.1）。

## 3. 线格式编码（逐项标注出处）

### 3.1 行式组帧与 JSON 序列化规则

- **消息边界**：每行 = 一个完整 JSON 对象 + 行尾单个 LF（`0x0a`）。行内不得出现未转义控制字符；CR（`0x0d`）不属于本协议（CRLF 进负例，spec 示例统一裸 LF）。
- **JSON 形态**：spec 示例为带空格的排版形态，线上字节由生成器钉死为**紧凑形态**（成员间无空格，`{"id":1,"method":…}`，现网客户端实际行为）；成员顺序钉死——请求/通知 `id,method,params`，响应 `id,result,error`（spec 全部示例的成员顺序）。
- **`id` 取材与配对**：请求 `id` 为 JSON number，**由矿机迭代、会话内唯一、起点任意**（spec §III："miner iterates ids and can start with any number"；矿池可能不按 FIFO 处理，响应必须按 `id` 值配对，不得按 TCP 位置配对）。通知的 `id` 恒为 `null`（spec 全部通知示例 `"id": null`），不得写成伪值（伪 id 进负例）。
- **响应形状**：`{"id":<同值>,"result":<成功载荷或 false>,"error":<null 或错误三元组>}`。错误三元组 = `[<code 数值>, <message 字符串>, <data|null>]`（spec §III submit 拒绝示例 `[-1,"Job not found",null]`；ext 不支持路径 `[20,"Not supported.",null]`）。
- **hex 字段编码**：全部 hex 数据字段为 ASCII 十六进制字符串，**默认无 `0x` 前缀**（spec §I.4 明确去除 `0x` 冗余）；字符集 `0-9a-f`（spec 示例全小写），偶数长度。`hex_prefix` 配置项声明方言变体 `"0x"`（④ 标注），**同一会话内前缀必须统一**，混用进负例。
- **difficulty 序列化**：JSON number，**钉死十进制定点表示**（`0.5`/`1.0`/`5000012.0` 形态，同 spec 示例），**禁止科学计数法**（生成器须定点格式化，不得依赖运行时 float 默认序列化）。
- **行长公式**：`L(line) = <固定常量> + Σ len(可变字段)`，逐消息固定常量见 §3.11（全部经脚本对 fixture 常量核验）；无协议级行长上界（job_id "HEX number of any size"，spec §III notify 段），实际受 TCP 流约束。
- **行-段映射（pack 条款）**：默认**每行一段**（§6 配置到帧路径与用例文档 §1 包数约定的基线）；配置 `pack` 开启后，**相邻同方向行默认合并为单一 TCP 段**（仅同方向相邻行粘连，如矿池连续两条通知合为一段），**方向交替处（请求/响应边界）不合并**——请求与其响应恒各占一段；`pack:false` 显式关闭（等价默认，恢复每行一段）。正例 `ethmining_line_packing`（用例 17）为 pack 开启形态，其余正例默认每行一段。

### 3.2 消息总表（方法 / 方向 / params / 应答，出处逐条）

| 消息 | 方向 | id | params（位置语义，出处 spec §III/§IV） | 应答 |
|---|---|---|---|---|
| `mining.subscribe` | 矿机→矿池 | number | 2 元素：[0] 矿机名/版本（user agent），[1] 协议串 `"EthereumStratum/1.0.0"`（矿池不支持该版本时**可回错误或直接断开**——矿池自由裁量路径，本版 fixture 不产生，声明见 §4①） | 订阅响应（§3.3） |
| `mining.extranonce.subscribe` | 矿机→矿池 | number | 0 元素 `[]`（ext §全文） | `result=true`（支持）或 `result=false + error[20,"Not supported.",null]`（不支持，合法值域声明，本版 fixture 取支持路径） |
| `mining.authorize` | 矿机→矿池 | number | 2 元素：[0] 用户名（账号[.矿机名]），[1] 密码（"同标准 stratum"语义，spec §III） | `result=true` 或 `result=false + error`（鉴权拒绝路径，§3.5） |
| `mining.set_difficulty` | 矿池→矿机 | `null` | 1 元素：[0] difficulty（double；difficulty 1 ⇔ target `00000000ffff0000000000000000000000000000000000000000000000000000`，换算同比特币，spec §III） | 无 |
| `mining.notify` | 矿池→矿机 | `null` | 4 元素：[0] job_id（hex，任意长度），[1] seedhash（32 字节 hex），[2] headerhash（32 字节 hex），[3] clean_jobs（boolean；true ⇒ 清空作业队列、旧 job 的后续提交按 stale 处理，spec §III） | 无 |
| `mining.set_extranonce` | 矿池→矿机 | `null` | 1 元素：[0] 新 extranonce（hex，≤3 字节）；**仅在矿机已发 extranonce.subscribe 后由矿池发送**（ext §全文）；对**后续** job 生效（spec §III） | 无 |
| `mining.submit` | 矿机→矿池 | number | 3 元素：[0] 用户名，[1] job_id，[2] minernonce（hex，**字节数 = 8 − extranonce 字节数**，spec §III："provided extranonce was 2 bytes… minernonce is 6 bytes"） | 提交响应三态（§3.9） |

**方向违例**：矿机侧发通知（notify/set_difficulty/set_extranonce）、矿池侧发请求（subscribe/authorize/submit）均为线格式/方向错，进负例（§7，锚 `method`/`direction`）。

### 3.3 `mining.subscribe` 请求/响应

请求（spec §III 握手段与 §IV 场景，紧凑化；fixture 常量值）：

```text
{"id":1,"method":"mining.subscribe","params":["MinerName/1.0.0","EthereumStratum/1.0.0"]}\n
```

响应（spec §III 原文形态，紧凑化）：

```text
{"id":1,"result":[["mining.notify","ae6812eb4cd7735a302a8a9dd95cf71f","EthereumStratum/1.0.0"],"080c"],"error":null}\n
```

| 字段 | 位置 | 类型/宽度 | 值域与约束 | 出处 |
|---|---|---|---|---|
| `id` | 成员 | number | 与请求同值回带 | spec §III |
| `result[0]` | 数组 | 数组（订阅三元组） | `[["mining.notify", <订阅标识>, "EthereumStratum/1.0.0"]]`；第三元素协议串与请求一致，**不一致时矿机应终止连接**（spec §III；本版 fixture 恒一致） | spec §III |
| `result[0][0][1]` | 嵌套 | hex 字符串 | 订阅标识（不透明；spec 示例 32 hex 字符，长度未钉死——fixture 钉死该值） | spec §III |
| `result[1]` | 数组 | hex 字符串 | **初始 extranonce，≤3 字节**（spec §III："Extranonce may be max 3 bytes in size"；长度未钉下界——0 长度无规范示例）。**1 字节为合法值**（validator 按 §3.9 互补公式支持 1B ⇒ minernonce 7B），本版 fixture 取 2B/3B 两态，不另设 1B 例（§8） | spec §III |
| `error` | 成员 | `null` | 成功恒 `null` | spec §III |

### 3.4 `mining.extranonce.subscribe`（ext 扩展）

请求 `{"id":2,"method":"mining.extranonce.subscribe","params":[]}\n`；支持时响应 `{"id":2,"result":true,"error":null}\n`，不支持时 `{"id":2,"result":false,"error":[20,"Not supported.",null]}\n`（ext §全文 verbatim）。矿池也可能忽略请求不回包或直接断开（ext 明示的现实行为，本版 fixture 不产生，声明）。该请求为 `mining.set_extranonce` 的触发前提（ext）。

### 3.5 `mining.authorize` 请求/响应

请求 `{"id":2,"method":"mining.authorize","params":["test","password"]}\n`（spec §IV verbatim 用户名/密码）。响应成功 `{"id":2,"result":true,"error":null}\n`；拒绝路径 `{"id":2,"result":false,"error":[24,"Unauthorized user",null]}\n`（错误码/文案为标准 stratum 惯例 fixture 值，④ 标注；spec 未钉死鉴权错误码）。**authorize 必须发生在初始握手期内、submit 之前**（spec §III："Miner shall authorize during initial handshake"）；拒绝后会话可关闭（本版 fixture 行为，正例 `ethmining_authorize_reject`）。用户名/密码为 ASCII 字符串，无规范长度上界（现网形态为 ETH 地址 + `.矿机名`，④ 标注），受行长公式约束。

### 3.6 `mining.set_difficulty` 通知

`{"id":null,"method":"mining.set_difficulty","params":[0.5]}\n`（spec §III verbatim）。规则（均 spec §III）：① **首条 job 之前矿池 MUST 发送**本通知；② 未发时矿机**按难度 1 兜底**（两种线序均合法——正例 `ethmining_set_difficulty_default` 承载兜底线序）；③ 难度变更只对**后续到达**的 job 生效（正例 `ethmining_set_difficulty_update` 承载时序）；④ difficulty 为 double（0.5 为 spec 最小示例值；大值变体 5000012.0）。

### 3.7 `mining.notify` 通知

`{"id":null,"method":"mining.notify","params":["bf0488aa","<seedhash 64hex>","<headerhash 64hex>",false]}\n`（spec §III verbatim 值域）。四元素语义：job_id——hex 数字任意长度（spec §III）；seedhash——32 字节，识别 DAG epoch（spec §II/§III：每 30,000 块变更，逐 job 重发以支持多币切换）；headerhash——32 字节，当前区块头哈希；clean_jobs——true 时清空队列、旧 job 后续提交按 stale 处理（spec §III）。job_id 是 submit 的关联键（§5 事务模型）。

### 3.8 `mining.set_extranonce` 通知

`{"id":null,"method":"mining.set_extranonce","params":["af4c"]}\n`（spec §III verbatim，1 元素形态）。**对后续 job 生效**（spec §III）；新 extranonce 同样 ≤3 字节（§3.3 值域）。注意与 ext 通用扩展的 2 元素形态（`[extranonce1, extranonce2_size]`）区分——**本版钉死 ethash 1 元素形态**（spec 为准），2 元素形态为比特币 stratum 方言（进负例锚 `params`）。

### 3.9 `mining.submit` 请求与响应三态

请求 `{"id":3,"method":"mining.submit","params":["test","bf0488aa","6a909d9bbc0f"]}\n`（spec §III verbatim）。**全 nonce 拼接**：`extranonce ‖ minernonce` 总宽 8 字节（spec §II/§III：extranonce 2 字节 ⇒ minernonce 6 字节；3 字节 ⇒ 5 字节）——长度互补是 validator 硬校验。响应三态（spec §III）：

| 形态 | 线上形态（spec verbatim） | 语义 |
|---|---|---|
| 接受 | `{"id":3,"result":true,"error":null}\n` | share 入账（正例 `ethmining_submit_accept`） |
| 拒绝 | `{"id":3,"result":false,"error":[-1,"Job not found",null]}\n` | 拒绝原因在错误三元组（如旧 job/stale）；**拒绝是合法协议路径，会话继续**（正例 `ethmining_submit_reject`） |
| 其他错误 | `result=false + error[<code>,<msg>,<data|null>]` | 三元组结构完整；会话继续（本版 fixture 不产生非"Job not found"错误码，声明） |

### 3.10 与 75-stratum（比特币）/76-getwork 的区分（不混装）

| 维度 | 本协议（ethash stratum） | 75-stratum（比特币） | 76-getwork（节点 RPC） |
|---|---|---|---|
| notify 参数 | 4 元素（job_id/seedhash/headerhash/clean_jobs） | 9 元素（prevhash/coinb1/coinb2/merkle 分支/version/nbits/ntime…） | 无通知（轮询） |
| submit 参数 | 3 元素（worker/job_id/minernonce） | 5 元素（extranonce2/ntime/nonce） | `eth_submitWork` 三参（nonce/header/mixDigest） |
| 工作构造 | 无 coinbase/merkle（DAG 体系） | coinbase + merkle 树 | 服务端全量工作对象 |
| extranonce | 1 段 ≤3 字节 + minernonce 互补 | extranonce1 + extranonce2 双段 | 无 |
| 载体 | TCP 明文行式 | TCP 明文行式 | HTTP JSON-RPC（8545） |

注：表中"工作构造"行（coinbase/merkle 树 vs DAG 体系）为**语义区分声明，不在用例断言范围**——DAG 生成是密码学层构造，pcap 中不可观测；用例对本协议的可观测断言仅覆盖线格式维度（参数个数、hex 形态与长度、extranonce 单段形态、长度互补）。

### 3.11 每消息行长公式汇总（固定常量经脚本对 fixture 核验）

| 消息 | 行长公式（B） | fixture 样例长 |
|---|---|---:|
| subscribe 请求 | `53 + len(id) + len(ua) + len(proto)` | 90 |
| subscribe 响应 | `59 + len(id) + len(订阅标识) + len(proto) + len(extranonce)` | 117 |
| extranonce.subscribe 请求 | `59 + len(id)` | 60 |
| extranonce.subscribe 响应 true | `35 + len(id)` | 36 |
| authorize 请求 | `53 + len(id) + len(user) + len(pass)` | 66 |
| authorize 响应 true | `35 + len(id)` | 36 |
| authorize 响应 false | `42 + len(id) + len(code) + len(msg)` | 62 |
| set_difficulty | `57 + len(difficulty 串)` | 60 |
| notify | `58 + len(job_id) + len(seedhash) + len(headerhash) + len(clean_jobs 串)` | 199 |
| set_extranonce | `59 + len(extranonce)` | 65 |
| submit 请求 | `53 + len(id) + len(user) + len(job_id) + len(minernonce)` | 78 |
| submit 响应 true | `35 + len(id)` | 36 |
| submit 响应 false | `42 + len(id) + len(code) + len(msg)` | 58 |

（`clean_jobs 串` = `true`/`false` 字面 4/5 字节；difficulty 串 = 十进制定点文本。所有公式 = 紧凑 JSON 字节数 + 1（LF）。）

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性声明**：本引擎对 ETHMining 采用**声明式脚本化回放**——配置是剧本（sessions[]/events[] 逐条声明），引擎是回放者，按序产出行帧；"事件驱动"一词不用于定性整体行为，仅用于两处反应性成分：①**自动应答**（subscribe/authorize/extranonce.subscribe/submit 事件后自动补同 `id` 响应行，响应形态按事件配置的 result/error 展开）；②**连接边界**（事件序列中源端口切换触发新 TCP 连接，即多会话展开）。

| 现网场景 | 事务交互 | 驱动顺序 | 对应用例 |
|---|---|---|---|
| ① 矿机接入（最常见：矿机上线连矿池） | TCP→subscribe→订阅响应→authorize→授权响应 | 矿机驱动请求，矿池侧自动应答 | `ethmining_subscribe_ipv4`、`ethmining_authorize`、`ethmining_extranonce_subscribe` |
| ② 鉴权拒绝 | authorize→`result=false + error`（合法错误路径） | 矿机驱动，矿池拒绝 | `ethmining_authorize_reject` |
| ③ 收任务（矿池持续推任务，每新区块/周期一推） | set_difficulty→notify(clean=false 增量 / clean=true 清队列) | 矿池侧事件编排 | `ethmining_notify_job`、`ethmining_notify_clean_jobs`、`ethmining_set_difficulty`、`ethmining_set_difficulty_default`、`ethmining_set_difficulty_update` |
| ④ share 提交（矿机每找到低于 target 的哈希即提交） | submit→响应 true/false（接受/拒绝，会话均继续） | 矿机驱动 | `ethmining_submit_accept`、`ethmining_submit_reject` |
| ⑤ extranonce 轮换（矿池负载调度，ext 扩展链路） | extranonce.subscribe→set_extranonce→后续 job/submit 用新 extranonce | 双侧编排 | `ethmining_set_extranonce` |
| ⑥ 多矿机并发（矿场多台矿机同池接入，状态互不串） | 多会话展开，各会话独立 extranonce/难度/job/id | 各自驱动 | `ethmining_multi_session` |
| ⑦ 完整挖矿生命周期 | 接入→收任务→提交→新任务→再提交（单连接多事务） | 事件编排会话 | `ethmining_mining_lifecycle` |

**五层覆盖逐层结论**：功能层——7 类消息 + 1 扩展每类正例（§3.2 表全覆盖：subscribe/authorize/extranonce.subscribe/set_difficulty×3 变体/notify×2 变体/set_extranonce/submit×2 响应态），响应错误路径（authorize 拒绝、submit 拒绝）以正例承载；每类错误分支（配置/线格式/状态机/关联/长度）负例（§7）。性能层——大 job_id notify 行跨 MSS 分段重组（`ethmining_mss_large_jobid`：job_id 1500 hex、行 1691B、默认 MSS 1460、2 段）、多行粘连单段（`ethmining_line_packing`：259B 一段含两行）、最小行边界（响应 true 形态 `35+len(id)+1` = 36B 全族最小，由订阅/授权/提交响应行承载；最小通知行 set_difficulty 60B，tcp.len 断言）、行长公式上界（无协议上界声明，受 §3.11 公式约束）。数据场景层——difficulty 值域（0.5 小数/5000012.0 大值/缺省 1 兜底）、extranonce 长度（2B 基线/3B 满值，≤3B 上界）、minernonce 与 extranonce 长度互补（6B/5B 两态，全 nonce 恒 8B）、job_id 任意长度（8 hex 常见/1500 hex 压力）、clean_jobs 二值、id 任意起点/递增、0x 前缀方言、hex 字符集全小写、长用户名（40 hex ETH 地址 + `.矿机名` 共 68 字符）。地址与流层——IPv4/IPv6 独立 fixture、单流基线、多会话双四元组；**流关联（控制流派生数据流）显式不适用**：矿机-矿池是单 TCP 长连接行式协议，无控制/数据分离、无副连接概念（spec 全文仅此一条连接）；**多流（一个会话内部并发流）显式不适用**：单连接串行收发。业务层——接入-收任务-提交链是现网挖矿日常（spec §IV 场景即此链路），多会话与多事务（会话内 subscribe→authorize→notify→submit→notify→submit 先后依赖：authorize 先于 submit、set_difficulty 先于首 job）均覆盖。

**次要合法行为显式不适用声明（不设正例、亦不得进负例，§7 防误报同步）**：① 矿池对不支持协议版本的 subscribe **回错误或直接断开**（spec §III 矿池自由裁量路径）——本版 fixture 恒协商一致（`EthereumStratum/1.0.0`），错误回包形态由 submit/authorize 拒绝正例承载同一编码行为；② extranonce.subscribe 不支持路径（ext）——ext 错误字面值 `[20,"Not supported.",null]` **不设断言**（本版 fixture 恒走支持路径），validator 仅校验错误三元组形态（`[number, string, null]`），编码行为同 submit 拒绝正例，不重复设例；③ 矿池忽略 extranonce.subscribe 不回包（ext 明示现实行为）——本版 fixture 恒回包；④ 非"Job not found"的其他 submit 错误码——编码同拒绝正例（三元组结构），不逐码设例；⑤ notify 先于 authorize 的线序——spec 未禁止但现网时序均为授权后推任务，本版 fixture 不产生、validator 不设约束（声明为未约束自由度）；⑥ **已关闭连接上重发 subscribe / 矿机断线重连后的会话重置语义**（重连新连接是否继承 extranonce/job/难度状态——spec 未钉死）——本版 fixture 不产生跨连接重连序列（多会话展开中各会话恒从全新握手开始），validator 不约束；同一会话内 close 事件后继续排事件仍为负例 28 状态机错，两者不冲突；⑦ **clean_jobs=true 后旧 job 后续 submit 的 stale 拒绝路径**（spec 未钉死错误码字面值）——本版 fixture 不产生该线序（clean=true 正例 6 不含旧 job 提交），validator 不设约束，submit 拒绝的编码行为由正例 12 承载；⑧ 缺省难度（兜底 1.0）线序下的 submit 提交——正例 8 承载缺省线序、正例 11/12 承载 submit 编码与响应三态，组合不产生新行为分支，不设组合例（避免 ID 膨胀）；⑨ **无保活/重试消息（显式不适用，v2.0.2 C3）**：spec/ext 无 PING/保活/重试类消息，长连接由矿池周期 notify 维持——本版不设 keepalive/retry 正例，亦不得进负例；⑩ **RST 异常中断为待实现边界（v2.0.2 C3）**：异常断开（矿池中途 RST 等）属 tcp 层框架能力，本协议层不新增 RST 断言——正例全部 FIN 优雅终止已覆盖 v1.3 §4 清单"FIN/RST 或异常中断"项；RST 注入在框架 tcp 层实现验证，不计入本协议 ID 覆盖统计。

## 5. 消息/事务模型与状态机

**事务定义**：ETHMining 事务 = 同一 TCP 连接内一次完整的请求/响应交互，关联标识为 JSON `id`（响应同值回带）。**多事务** = 一个连接内多笔事务按序执行且有先后依赖：**subscribe 必须是首条应用消息**（spec §III："Miner sends data first"）；**authorize 先于 submit**（spec §III 握手段；submit 的用户名必须等于已授权用户名）；**submit 的 job_id 必须来自本会话已收到的 notify**（job 关联键）；**set_difficulty 先于首条 notify**（spec §III MUST，缺省难度 1 兜底线序为唯一例外——正例 8 承载）。通知无应答，不构成事务；事务交互示例：notify（job A）→submit(A)→notify（job B）→submit(B)——第二笔 submit 依赖第一轮的 job 上下文轮换。

矿机侧会话状态机（确定性：同一事件序列必然产出同一行序列，无随机/未定义行为；生成器在某状态下遇到非法事件——如未订阅先提交——必须拒绝并报状态机错误，不得静默产出）：

| 状态 | 允许事件（→目标状态） | 必须保持 |
|---|---|---|
| `Disconnected` | TCP 三次握手（→`TransportReady`） | 握手后首条应用消息必须是 subscribe |
| `TransportReady` | 发 subscribe（→`Subscribing`） | params[1] 协议串 `EthereumStratum/1.0.0` |
| `Subscribing` | 收订阅响应（→`Subscribed`） | 响应 id 同值；result[1] extranonce ≤3 字节并记为当前 extranonce |
| `Subscribed` | 发 authorize（→`Authorizing`）；可选事件：发 extranonce.subscribe+收响应（保持）——**须在首条 set_extranonce 之前任意时点**（ext 触发前提），本版 fixture 取 authorize 之前 | 用户名/密码非空 |
| `Authorizing` | 授权响应 true（→`Authorized`）；false（→`AuthorizedRejected`） | 响应 id 同值 |
| `AuthorizedRejected` | TCP FIN（→`Closed`；本版 fixture 行为） | 拒绝后不得发 submit（标准 stratum 语义） |
| `Authorized` | 收 set_difficulty/notify/set_extranonce（保持）；发 submit→收响应 true/false（保持）；TCP FIN（→`Closed`） | submit 用户名 = 已授权用户名；submit job_id ∈ 已收 notify 集合；minernonce 字节数 = 8 − 当前 extranonce 字节数；set_extranonce 后当前 extranonce 更新（作用域 = 后续 job） |
| `Closed` | — | 关闭后不得产生新行 |

**自动派生规则**（引擎自动补出的行，逐条列出触发条件与内容）：①订阅响应——subscribe 事件后自动补同 `id` 响应行（result 按事件配置的订阅标识/extranonce 展开）；②extranonce.subscribe 响应——同 `id` `result=true`；③授权响应——authorize 事件后按 `result` 配置补 `true` 或 `false+error 三元组`；④提交响应——submit 事件后按 `result` 配置补 `true` 或 `false+[-1,"Job not found",null]`；⑤TCP 三次握手与 FIN 挥手由 tcp 层自动补（连接边界：源端口切换触发新连接）。每条自动行均可被事件显式覆盖（如拒绝路径）。

**多会话展开**：`sessions[]` 按序整块回放——先跑完第 1 个会话全流程（握手→事件→挥手），再跑第 2 个，不交错；**第二会话包号起点 = 前一会话总包数 + 1**。各会话四元组、id 序列、当前 extranonce、当前难度、job 集合、已授权用户名互不串用（id 同值在不同会话可独立存在，但跨会话响应不得互相消费——负例锚 `id`）。并发回放模式（`concurrent: true`）为生成器例外路径，本版不启用——多矿机并发连接的**协议语义**由顺序多会话展开（用例 20）承载：各会话四元组与状态互不串用、按序整块回放，等价表达矿场多台矿机同池接入的现网场景（§4 场景⑥）；"单 TCP 流串行"是生成器回放方式而非协议属性，并发交错只引入时序差异、不改变本协议层断言语义，故不作为本版必要路径。

## 6. 配置 typedef（JSON 形状示例，非 Go 代码）

```json
{
  "layers": [{"tcp": {}}, {"ethmining": {}}],
  "src_ip": "192.0.2.73", "dst_ip": "198.51.100.73",
  "src_port": 4073, "dst_port": 4444,
  "ethmining": {
    "profile": "ethmining_stratum_v1",
    "hex_prefix": "",
    "sessions": [
      {
        "src_port": 4073, "dst_port": 4444,
        "events": [
          {"kind": "subscribe", "id": 1, "user_agent": "MinerName/1.0.0",
           "protocol": "EthereumStratum/1.0.0",
           "subscription_id": "ae6812eb4cd7735a302a8a9dd95cf71f", "extranonce": "080c"},
          {"kind": "authorize", "id": 2, "username": "test", "password": "password",
           "result": true},
          {"kind": "set_difficulty", "difficulty": 0.5},
          {"kind": "notify", "job_id": "bf0488aa",
           "seed_hash": "abad8f99f3918bf903c6a909d9bbc0fdfa5a2f4b9cb1196175ec825c6610126c",
           "header_hash": "645cf20198c2f3861e947d4f67e3ab63b7b2e24dcc9095bd9123e7b33371f6cc",
           "clean_jobs": false},
          {"kind": "submit", "id": 3, "username": "test", "job_id": "bf0488aa",
           "miner_nonce": "6a909d9bbc0f", "result": true}
        ]
      }
    ],
    "wire_fault": ""
  }
}
```

形状要点：`sessions[]` = 统一术语的**事件编排会话**（每个自带四元组与事件序列，多会话展开按序整块回放，第二会话包号起点 = 前会话总包数 + 1）；`events[]` = 会话的**事件序列**，kind 覆盖 `subscribe`（id/user_agent/protocol + 自动响应的 subscription_id/extranonce）/`extranonce_subscribe`/`authorize`（result 控制响应三态）/`set_difficulty`（difficulty 十进制定点）/`notify`（job_id/seed_hash/header_hash/clean_jobs）/`set_extranonce`（新 extranonce，更新会话当前 extranonce）/`submit`（id/username/job_id/miner_nonce + result 控制响应三态）；`hex_prefix` = `""`（spec 默认，无前缀）或 `"0x"`（方言变体，§1），作用域 = 全部 hex 数据字段（extranonce/job_id/seed_hash/header_hash/miner_nonce/订阅标识），会话内必须统一；`wire_fault` 仅负例注入口（取值 `json`/`framing`/`method`/`params`/`hex`/`state`/`id`/`job`/`carrier`/`propagation`，§7），不得成为线上字段。**配置到帧的完整路径**：配置 → validator（层链/端口/事件序状态机/id 会话内唯一/hex 值域与前缀统一/长度互补/关联完整性校验）→ planner（事件序列展开为行序列，紧凑 JSON 序列化 + LF，按 §3.11 公式计算行长）→ worker（TCP 分段：默认每行一段，>MSS 自动分段，段数 = 行长对 MSS 上取整；`pack` 开启时相邻同方向行合并为单一 TCP 段、方向交替处不合并，`pack:false` 恢复每行一段——§3.1 pack 条款）→ writer（PCAP/NIC）。

## 7. 错误处理（负例锚词表）

以下输入必须由 planner/validator 拒绝并传播为 task error（任务错误），不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。锚词（anchor word）为 `error_contains` 断言字面值，与用例文档 §5 一一对应、同序：

| # | 负例 ID | 故障输入（`wire_fault`/配置注入口） | `error_contains` 候选锚词 |
|---:|---|---|---|
| 23 | `ethmining_neg_json` | 行内容非法 JSON：截断对象、未闭合字符串、非对象行 | `json`、`decode`、`line` |
| 24 | `ethmining_neg_framing` | 行组帧错：行尾无 LF（裸结束）、CRLF 混入、私有长度前缀取代换行 | `newline`、`framing`、`line` |
| 25 | `ethmining_neg_method` | 方法错：未知 method（含 GetWork 的 `eth_getWork` 混入）、方法方向违例（矿机发 notify、矿池发 submit） | `method`、`unknown`、`direction` |
| 26 | `ethmining_neg_params` | params 元素数量/类型/位置错：subscribe 缺协议串、authorize 单参、notify 3 元素、submit 缺 minernonce、set_difficulty 参数非数值、clean_jobs 非布尔、set_extranonce 2 元素方言混入 | `params`、`field`、`type` |
| 27 | `ethmining_neg_hex` | hex 字段违例：seed_hash/header_hash 非 64 hex、job_id 非 hex 字符、extranonce >6 hex（>3B 上界）、minernonce 字节数 ≠ 8 − extranonce、奇数长度、同会话 `0x` 前缀混用 | `hex`、`length`、`extranonce`、`prefix` |
| 28 | `ethmining_neg_state` | 状态机错（四分支）：首条应用消息为 authorize、首条应用消息为 mining.notify（首条混入 GetWork `eth_getWork` 同时命中负例 25 的 unknown method 锚）、未 authorize 先 submit、会话关闭后继续排事件 | `state`、`sequence`、`subscribe` |
| 29 | `ethmining_neg_id_correlation` | id 关联错：响应 id 与请求不匹配、通知携带非 null 伪 id、同会话 id 重复 | `id`、`match`、`correlation` |
| 30 | `ethmining_neg_job_correlation` | job 关联错：submit 的 job_id 不来自本会话已收 notify、submit 用户名与已授权用户名不一致 | `job`、`worker`、`correlation` |
| 31 | `ethmining_neg_carrier` | 载体错：层链缺 tcp（`[ethmining]` 直连）、UDP 载体、端口/载体声明矛盾、IPv6 层链配 IPv4 地址（混合地址族——框架 IP 层校验承载，v2.0.2 C2） | `carrier`、`tcp`、`port`、`ip`、`version` |
| 32 | `ethmining_neg_error_propagation` | validator/planner 已知错误被吞、任务假成功、0 包或错误响应丢失 | `error`、`propagat`、`task` |

锚词候选集说明：负例 32 的三个锚词（`error`/`propagat`/`task`）为**三选一候选集**，非并列断言——实现期按实际错误信息钉死其一后，同步更新本文表与用例文档 §5 表两处。

**负例原子性（v2.0.2 C4，全表适用）**：上表各行故障输入为**互斥候选集**——每个负例 ID 实现期选定其一钉死注入并同步本文表/用例文档 §5 表两处；**单次执行不得混注两个及以上故障**（锚词命中不可归因）；如需全量覆盖按 v1.3 §7 原子原则拆子 ID（如 `ethmining_neg_hex` 可拆 `_seedlen`/`_nonhex`/`_exceed3b`/`_complement`/`_odd`/`_prefix`）。

**不得误报为 planner error 的合法协议事件**：submit 拒绝（`result=false + error`，正例 12）、authorize 拒绝（正例 4）、难度缺省线序（正例 8）、难度变更（正例 9）、extranonce 轮换（正例 10）、extranonce.subscribe 不支持响应（§4 声明②）、minernonce=0 长度（extranonce 3B 上界下的理论形态——本版 extranonce ≤3B ⇒ minernonce ≥5B，0 长度不可达，不设例）。只有配置、线格式、状态、关联、长度错误进入负例。

## 8. 边界

- **行长与分段**：notify 行 = `58 + len(job_id) + 64 + 64 + len(clean_jobs 串)`；`ethmining_mss_large_jobid` 用 job_id 1500 hex 字符 ⇒ 行 1691B，默认 MSS 1460 不压，跨 2 段（1460+231），接收端按 LF 重组后断言完整行——**分段边界不切坏行内容，也不产生伪行界**（行内无 0x0a 字节是 JSON 文本保证：ASCII hex/方法名无 LF）。
- **多行粘连**：`ethmining_line_packing` 将 set_difficulty（60B）+ notify（199B）合并为一段 259B 载荷，段内恰 2 个 `0a`；接收端按行拆分，段边界 ≠ 行边界两个方向都断言。
- **extranonce 宽度带**：≤3 字节（spec 钉死上界）；基线 2B（`080c`）⇒ minernonce 6B，满值 3B（`a2eea0`）⇒ minernonce 5B；**1B 为合法值**（validator 按 §3.9 互补公式支持 1B ⇒ minernonce 7B），本版 fixture 取 2B/3B 两态，不另设 1B 例；>3B 进负例 27；0 长度无规范示例不使用（§3.3）。
- **全 nonce 恒 8B**：`extranonce ‖ minernonce` 拼接宽度硬校验（正例 10/14 断言两段长度互补；负例 27 拒绝互补违例）。
- **difficulty 值域**：double >0；0.5（spec 最小示例）、5000012.0（大值变体）、缺省 1.0（兜底线序）；序列化禁止科学计数法（§3.1）。**兜底难度 1.0 不上线路径**（缺省线序中矿池不发 set_difficulty 行，1.0 是矿机侧缺省推断值），无法从 pcap 断言其字面值——正例 8 断言的是 set_difficulty 行的缺席，非 1.0 字面值。
- **id 域**：JSON number，起点任意（正例 13 用 100/101/102）、会话内唯一、递增非协议强制但 fixture 钉死递增；响应同值回带。
- **clean_jobs 二值**：true/false 各一正例（6/5）；非布尔进负例 26。
- **0x 前缀**：会话内统一（默认无前缀正例为主 profile，`0x` 变体正例 15）；混用进负例 27。
- **v4/v6**：IPv4/IPv6 独立 fixture，同一逻辑行字节必须一致，仅外层 IP 头与偏移（54/74）不同；不得从 IPv4 默认值推导 IPv6 地址（fixture 显式给出 `2001:db8::73 → 2001:db8::100:73`）。
- **多会话**：≥2 个独立四元组，id 序列/extranonce/难度/job 集合/用户名互不串用；会话间包序按多会话展开（第二会话起点 = 前会话总包数 + 1）。
- **端口（v2.0.2 C2）**：默认 fixture 4444；非默认端口 3353 **显式声明即合法通道**（正例 22——端口不进 stratum 行内容，行字节与基线一致），未显式声明的非 4444 端口拒绝（负例 31）；本协议无 dissector、断言全走 `tcp.payload`/frames，无 DecodeAs 依赖。
- **无保活/重试消息（v2.0.2 C3）**：spec/ext 无 PING 类保活或重试机制，长连接由矿池周期 notify 维持——显式不适用（§4⑨），不设正例亦不得进负例；**RST 异常中断（v2.0.2 C3）**：属框架 tcp 层能力，本协议层零断言零 ID（§4⑩），正例全部 FIN 优雅终止。
- 不得产生回绕长度或超量分配（行长无协议上界，受生成器缓冲与 TCP 约束；大 job_id 压力值 1500 hex 在配置显式声明，不隐式放大）。

## 9. 原子 ID 与完成定义

设计、testcase 与未来 `ethmining.json` 必须使用同一组 **32 个唯一语义 ID（22 正 + 10 负）**、同一顺序（原子用例：一个用例只验证一个协议行为；每消息类型/每响应态/每时序变体/每长度边界/每关联规则/每错误分支各一——数量由协议结构决定，超过 20 条符合 v1.3 §7）；当前 JSON 另有不计入的 `ethmining_neg_unregistered` 占位。

| # | ID | 类型 | 覆盖（设计 §） |
|---:|---|---|---|
| 1 | `ethmining_subscribe_ipv4` | 正 | §3.3：订阅请求/响应全字段（订阅三元组 + extranonce），IPv4 单流基线 |
| 2 | `ethmining_extranonce_subscribe` | 正 | §3.4：ext 扩展请求 + `result=true`（支持路径） |
| 3 | `ethmining_authorize` | 正 | §3.5：授权请求/成功响应（user/pass 两元素） |
| 4 | `ethmining_authorize_reject` | 正 | §3.5：`result=false + error[24,"Unauthorized user",null]` 拒绝路径（合法错误路径） |
| 5 | `ethmining_notify_job` | 正 | §3.7：notify 四元素完整行（clean=false），难度先行时序 |
| 6 | `ethmining_notify_clean_jobs` | 正 | §3.7：clean_jobs=true 变体（布尔二值边界） |
| 7 | `ethmining_set_difficulty` | 正 | §3.6：难度通知（0.5，最小通知行 60B，tcp.len 边界；全族最小行 36B 响应由用例 3/11 承载） |
| 8 | `ethmining_set_difficulty_default` | 正 | §3.6：缺省难度兜底线序（未发 set_difficulty 直接 notify，合法） |
| 9 | `ethmining_set_difficulty_update` | 正 | §3.6：会话中难度变更（5000012.0），作用于后续 job |
| 10 | `ethmining_set_extranonce` | 正 | §3.8/§3.9：set_extranonce 轮换（2B→3B）+ 后续 submit minernonce 5B 互补 |
| 11 | `ethmining_submit_accept` | 正 | §3.9：submit 三元素 + `result=true` 接受 |
| 12 | `ethmining_submit_reject` | 正 | §3.9：submit + `result=false + [-1,"Job not found",null]` 拒绝（会话继续） |
| 13 | `ethmining_id_correlation` | 正 | §3.1/§5：id 任意起点（100/101/102）、按值配对（非 TCP 位置配对） |
| 14 | `ethmining_extranonce_max3` | 正 | §3.3/§8：extranonce 3B 满值（`a2eea0`）+ minernonce 5B（全 nonce 8B，spec §IV 组合） |
| 15 | `ethmining_hex_prefix` | 正 | §1/§3.1：`0x` 前缀方言变体（订阅响应/notify/submit 全链统一前缀） |
| 16 | `ethmining_long_username` | 正 | §3.5/§8：长用户名（40 hex 地址 + 矿机名 68 字符）authorize/submit 同值 |
| 17 | `ethmining_line_packing` | 正 | §2/§8：多行粘连单段（set_difficulty+notify 259B 一段、段内 2 个 LF） |
| 18 | `ethmining_mss_large_jobid` | 正 | §3.11/§8：job_id 1500 hex ⇒ 行 1691B 跨 MSS 2 段重组 |
| 19 | `ethmining_ipv6` | 正 | §2/§8：IPv6 独立 fixture（offset 74） |
| 20 | `ethmining_multi_session` | 正 | §5/§8：双矿机双四元组多会话展开（独立 extranonce/难度/job/用户名） |
| 21 | `ethmining_mining_lifecycle` | 正 | §4⑦/§5：单会话多事务全链（接入→收任务→提交→新任务→再提交） |
| 22 | `ethmining_custom_port` | 正 | §2/§3：非默认端口 3353 显式声明合法通道（端口不进 stratum 行内容，行字节与用例 1 一致） |
| 23 | `ethmining_neg_json` | 负 | §7：非法 JSON/截断/非对象行 |
| 24 | `ethmining_neg_framing` | 负 | §7：无 LF/CRLF/长度前缀 |
| 25 | `ethmining_neg_method` | 负 | §7：未知 method/GetWork 混入/方向违例 |
| 26 | `ethmining_neg_params` | 负 | §7：params 数量/类型/位置错 |
| 27 | `ethmining_neg_hex` | 负 | §7：hex 值域/长度/互补/前缀混用 |
| 28 | `ethmining_neg_state` | 负 | §7：状态机错（首消息/未授权提交/关闭后续排） |
| 29 | `ethmining_neg_id_correlation` | 负 | §7：id 错配/伪 id/重复 |
| 30 | `ethmining_neg_job_correlation` | 负 | §7：job 来源/用户名不一致 |
| 31 | `ethmining_neg_carrier` | 负 | §7：载体/端口/层链错 |
| 32 | `ethmining_neg_error_propagation` | 负 | §7：错误未传播/假成功 |

完成定义：注册 `tcp→ethmining` 层链；逐字段生成并验证 §3 全部 7 类消息 + ext 扩展（行式组帧、紧凑 JSON、LF 边界、行长公式、hex 前缀统一、长度互补）；订阅/授权/难度（含缺省与变更时序）/任务（clean 二值）/extranonce 轮换/提交三态、id 关联、多事务、多会话展开、IPv4/IPv6、MSS 分段与粘连重组、全部边界均可观测；32 个语义 ID 正负断言与错误传播完成；未注册阶段只接受 `unknown layer` 占位。注册时同步修正占位 JSON 的 `dst_port` 8545→4444 与 notes 计数 32/22+10（§1）；pcap/NIC 双输出共用本契约（§1 输出契约段）。不声称真实 PoW、share 密码学有效或区块产生。

## 10. 修订记录

- v1.0.0（2026-08-21）：旧稿首版（14 正 + 6 负）——**协议定位错误**：按节点侧 legacy JSON-RPC（`eth_getWork`/`eth_submitWork`/`eth_getHashrate`/`eth_submitHashrate`、HTTP 8545、Stratum-like 混合 profile）定义，与 ethash stratum 矿池协议不符。
- v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-21 旧稿（旧稿见 git 历史）。协议定位纠正为 **ethash stratum（EthereumStratum/1.0.0）**：以 NiceHash 官方 spec R2 + extranonce subscribe extension 全文为规范基线逐条提炼——行式 JSON（LF 边界、紧凑形态钉死）、7 类消息 + 1 扩展（subscribe/extranonce.subscribe/authorize/set_difficulty/notify/set_extranonce/submit）、params 位置语义、extranonce ≤3 字节与 minernonce 8−len 互补、难度先行 MUST 与难度 1 兜底、clean_jobs 语义、错误三元组；与 75-stratum（比特币）/76-getwork 的三方区分表钉死不混装。fixture 全部常量取 spec verbatim（订阅标识 `ae6812…`、extranonce `080c`/`a2eea0`、job `bf0488aa`、seedhash/headerhash、minernonce `6a909d9bbc0f`/`cfae7df760`、difficulty 0.5、错误 `[-1,"Job not found",null]`）。用例按 v1.1 原子原则从 20 条重排为 **31 条（21 正 + 10 负）**——每消息类型、每响应态、每时序变体、每长度边界、每关联规则、每错误分支各一例；新增 §4 业务场景分析（五层逐层、流关联与多流显式不适用声明）、§5 状态机与事务模型（自动派生规则）、§6 JSON 配置 typedef 与配置到帧路径、§3.11 行长公式表（脚本核验）；0x 前缀方言、端口 4444、鉴权错误码按"公开资料 + 假设，实现阶段实证校准"标注；以本机 tshark 3.6.14 构造 pcap 实证（tcp.payload 全行 hex/offset 54/74/行尾 0a）固化断言基线。状态：**待独立隔离审查**。
- v2.0.1（2026-09-01）：按独立隔离审查 23 项问题清单修复（9 MAJOR + 14 MINOR，T16 审查判定无缺陷不修），31 ID 与顺序不变。关键项：§3.1 新增行-段映射 **pack 条款**（相邻同方向行合并为单一 TCP 段、方向交替处不合并、`pack:false` 可关，正例 17 引用）；§4 声明②明写 ext 错误字面值 `[20,"Not supported.",null]` 不设断言、validator 仅校验三元组形态，并增补 ⑥ 重连重置语义、⑦ clean_jobs 后 stale 拒绝路径、⑧ 缺省难度下 submit 不设组合例（T02/T12/T13/T15 走声明不新增 ID）；§5 状态机 extranonce.subscribe 可选事件自 `Subscribing` 移至 `Subscribed` 行并钉死时点约束（首条 set_extranonce 之前，fixture 取 authorize 之前）；§7 负例 26 锚词补 `prefix`、负例 27 对齐四分支（首条 authorize/首条 notify/未授权 submit/关闭后事件）、负例 31 锚词注明三选一候选集；§3.10 getwork submit 列补参数名（nonce/header/mixDigest）、"工作构造"行注明不在用例断言范围（DAG 为密码学层，pcap 不可观测）；§3.3/§8 补 extranonce 1B 合法值声明（validator 支持互补、fixture 取 2B/3B 两态）；§8 补兜底难度 1.0 不上线路径不可断言说明；§9 完成定义补注册时占位 JSON 修正项。

- v2.0.2（2026-09-01，v1.3 行为面全枚举重审修复轮）：review-ethmining 重审 6 confirmed（4 MAJOR + 2 MINOR）+ 6 自洽确认 + 3 待实现边界，逐项修复：**C1**（MAJOR）pcap/NIC 双输出契约补入（§1 输出契约段——两路径共用同一 cases JSON 与断言集，`nic_capture` 用例级开关；状态行"PCAP 断言"改"PCAP/NIC 双输出断言"）；**C2**（MAJOR）新增正例 22 `ethmining_custom_port`（非默认端口 3353，端口不进 stratum 行内容、行字节与用例 1 一致、无 DecodeAs 依赖——本协议无 dissector），31 → **32 例（22 正 + 10 负）**、负例编号 22–31 → 23–32（ID 与故障语义不变）；neg_carrier 补 IPv6/v4 混合地址族分支（锚 `ip`/`version`，框架 IP 层校验承载），§2/§8 端口口径同步；**C3**（MAJOR）§4 声明补 ⑨ 无保活/重试消息显式不适用（spec/ext 无 PING 类机制，周期 notify 维持）与 ⑩ RST 异常中断记为待实现边界（框架 tcp 层能力、本协议层零断言零 ID，FIN 优雅终止已覆盖清单项），§8 补口径 bullet；**C4**（MAJOR）§7 表尾补负例原子性注（故障输入互斥候选集、单次执行单一注入、全量覆盖拆子 ID 示例）；**C5**（MINOR）§5 并发措辞修正（`concurrent: true` 为生成器例外路径本版不启用；"单 TCP 流串行"系回放方式非协议属性；多矿机并发语义由顺序多会话展开用例 20 承载），§6 形状注同步；**C6**（MINOR）现行规范引用 v1.1 → v1.3（状态行/§9 原子原则引用；历史修订条目保留 v1.1 原口径）。

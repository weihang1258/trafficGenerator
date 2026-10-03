# XMRMining（门罗币挖矿 stratum 协议，Monero / RandomX 矿池通信）设计契约

> 版本：v2.0.3（设计阶段）
> 日期：2026-10-01
> 状态：**已登记层链能力，静态契约待运行验收**；仓库已注册 `xmrmining` layer 并具备 LayerChain terminal translation，本版只冻结 64 个静态用例，不宣称正例已运行通过。负例必须严格使用 `expect_error` + `error_contains` 两键；不通过改写文档冒充运行证据。按《协议设计文档与用例文档需求文档 v1.3》完成行为面全枚举重审修复轮；本版 v2.0.3 固定 **64 例（25 正 + 39 负）**。
> 配套文件：`docs/protocols/xmrmining/testcase.md`、`trafficgen/test/protocol_pcap/cases/xmrmining.json`（JSON 已登记 64 例：25 正例、39 负例）
> 规范基线：XMRMining = **Monero（门罗币）挖矿 stratum 协议**，RandomX（随机 X）算法的矿机↔矿池 TCP 长连接、行分隔 JSON（newline-delimited JSON，每行一个 JSON 对象，行尾单个 LF `0x0a`）消息封装。权威依据取以下四层（逐项标注出处）：
> ① **xmrig/xmrig-proxy《Stratum mining protocol》**（github.com/xmrig/xmrig-proxy `doc/STRATUM.md`，下称 **spec**）——本协议**唯一成文官方规范**，本文 §3 全部消息形态、字段名、verbatim 示例、错误文案（"Invalid payment address provided"/"Low difficulty share"）、session id 回带、keepalived 扩展逐条出自 spec（出处写"spec §login/job/submit/keepalived"）；
> ② **XMRig 客户端源码**（github.com/xmrig/xmrig `src/base/net/stratum/Client.cpp`、`Job.cpp`、`Job.h`、`src/base/io/json/JsonRequest.cpp`，下称 **xmrig-impl**）——compact JSON 序列化（JsonRequest 成员顺序 `id,jsonrpc,method`）、login 带 `rigid` 可选字段（Client.cpp `m_rigId`）、**blob 的 nonce 偏移 39 与 4 字节小端**（Job.h `nonceOffset()` 默认 39、`nonceSize()` RandomX=4、`kMaxBlobSize=408`）、**target 4/8 字节两态**（Job.cpp `setTarget` switch 4/8）、**seed_hash 恰 64 hex**（Job.cpp `setSeedHash` 校验）、extensions 解析（`algo`/`keepalive`/`connect`/`tls`）——出处写"xmrig-impl …"；
> ③ **MoneroOcean nodejs-pool**（github.com/MoneroOcean/nodejs-pool `lib/pool/protocol.js`、`lib/coins/core/factories.js`，下称 **mo-pool**）——**现代 job 对象形态**（`blob/algo/height/seed_hash/job_id/target/id`，`buildStandardJobPayload`）、job 通知**省略 id 成员**（`pushMessage({method:"job",params})`）、`keepalive` 与 `keepalived` 双别名（`RATE_LIMIT_METHODS`）、`getjob` 客户端主动拉取（`handleGetJobRequest`）、错误响应 `{code:-1,message}` 与 `result:{status:"OK"}` 形状（`sendReply`）——出处写"mo-pool …"；
> ④ **公开资料 + 假设，实现阶段实证校准**：矿池接入端口（旧稿沿用 18081——该端口为 **monerod daemon RPC** 常见端口而非 stratum 矿池标准端口，主流 XMR 矿池多挂 3333/5555，如 supportxmr；端口不是协议识别证据，可配置覆盖，逐处标注）、`result.id` 的 UUID 形态（spec 示例 `1be0b7b6-…`，长度未钉死）、keepalived 请求带 `jsonrpc` 成员（spec 示例省略、xmrig-impl `ping()` 携带——两形态均合法，本版钉死带 jsonrpc）、`getjob` 响应 result 直接为 job 对象（mo-pool `getBestCoinJob` 形态推断，标注假设）；
> ⑤ **本机实测**：tshark 3.6.14 `-G fields`/`-G protocols` + 按 spec 逻辑构造 pcap 实证（`tcp.payload` 精确提取完整行含行尾 `0a`、offset 54/74、`json.*` 辅助字段，见用例文档 §1）。
> 修订记录：v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》重写，取代 2026-08-21 旧稿（旧稿见 git 历史）。**旧稿协议定位模糊**——旧稿按"CryptoNote/Monero 矿池 Stratum-like/JSON-RPC 混合"定义，未钉死权威规范（login/getjob/submit/keepalived 方法与服务端 job 通知方向描述无规范出处）、未区分通知省略 id 与 id:null、未钉死 blob nonce 偏移/上界/字节序、无 fixture 常量与行长公式；本版从 spec + xmrig-impl + mo-pool 逐条重新提炼，用例按 v1.1 原子原则从 20 条重排为 **33 条（23 正 + 10 负）**。

## 1. 范围、profile 和层链边界

本版定义矿机（miner）与矿池（pool）之间的 **Monero/RandomX stratum 明文 TCP 长连接**：行分隔 JSON（每行一个 JSON 对象，行尾单个 LF `0x0a`）消息封装、登录（`login`，订阅+授权合一，对象 params）、任务通知（`job`，无 id 成员）、share 提交（`submit`）与提交响应两态、保活（`keepalived`/`keepalive` 别名）、客户端主动拉任务（`getjob`）、`id` 关联、动态字段（session id/job_id/blob/target/seed_hash/height/algo/nonce/result）、IPv4/IPv6、多会话与多事务。**不执行真实 RandomX 工作量证明，不验证 share/区块密码学有效性**——`nonce`/`result` 为 fixture 声明值，只断言格式、值域与关联。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `xmrmining_stratum_v1`（主 profile） | TCP 明文行式 JSON（fixture 端口 18081，可配置覆盖） | spec 全部 5 类方法（login/job/submit/keepalived/getjob）+ 字段变体、行重组、id 关联、响应两态 | 真实 share/区块密码学有效性、真实矿池鉴权、RandomX 计算 |
| `xmrmining_ipv6_v1` | 同上，仅外层 IPv6 | 同主 profile | 从 IPv4 fixture（固定样本）推导 IPv6 地址 |
| `xmrmining_job_legacy_v1` | 同主 profile，job 对象仅 `blob/job_id/target` 三字段 | spec 原文最小 job 形态（正例 6 承载） | 现代矿池附加字段（algo/height/seed_hash/id）可缺省 |

显式边界（"不实现、不声称、不许静默转换"）：**`block_template` 方法**（矿工自选区块模板模式，jtgrassie/monero-pool `sss.md`）不在本版——属自选模板扩展，planner 对混入方法按未知 method 拒绝（负例）；**HTTP JSON-RPC 承载**（monerod daemon RPC，端口 18081 的 HTTP 形态）不在本版——本版 18081 仅为 TCP 行式 stratum fixture 端口，不承载 `get_block_template` 等 daemon HTTP 方法；**比特币 stratum**（`mining.subscribe`/`mining.authorize`/9 参数 notify/5 参数 submit、数组 params）不在本版——属 `75-stratum` 契约，mo-pool 虽为兼容性接受 `mining.authorize`/`mining.subscribe`，本版 XMR 语义钉死为对象 params 的 `login` 主形态（规范依据 spec §login），数组 params 混入进负例锚 `params`；不声称任何 share 满足真实 target 或产生区块。

仓库已注册 `xmrmining` layer，且 planner 已具备 LayerChain terminal translation；`cases/xmrmining.json` 当前登记 64 个语义用例（25 正 + 39 负），无额外占位例。正例已采用严格层链形状，但本轮未运行 suite/server/MCP/NIC，因此只能作为静态契约，不能报告为行为通过。负例均为单一故障输入，`expect` 严格限制为 `expect_error` 与 `error_contains` 两键。运行验收仍需由后续阶段完成；不得通过文档或 cases 伪造运行证据。

**输出契约（pcap/NIC 双输出，v2.0.1 C-06）**：本契约的用例同时服务于 pcap（抓包文件）与 port_group/NIC（网卡）两种输出路径——两路径共用同一份 cases JSON、同一 tshark 字段/帧字节断言（`tcp.payload` 全行 hex、`tcp.len`、`tcp.stream`、offset 54/74 frames），NIC 路径仅经 tcpdump 捕获（`nic_capture` 为用例级开关），L2 无 VLAN 前提下偏移与载荷提取稳定，不改变断言语义（与 64-cwmp/66-doh/67-onvif/68-hl7/70-megaco/65-bacnet/73-ethmining 同形）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[tcp, xmrmining]`（引擎自动补 `ip`；需要显式地址族时写 `[ip, tcp, xmrmining]` 或 IPv6 等价链）。XMR stratum 报文是 TCP payload 的**行式字节流内容**，与 75-stratum/73-ethmining/72-edp 同款"TCP 之上直接组行"的终结层形态——**无消息长度前缀、无记录头，消息边界只由 JSON 文本后的单个 LF（`0x0a`）决定**（spec 全部示例行尾 `\n`；私有长度前缀进负例）。

端口：旧稿 fixture 端口 **18081**（该端口为 monerod daemon RPC 常见端口；主流 XMR stratum 矿池接入端口多挂 3333/5555，如 pool.supportxmr.com:3333，"公开资料 + 假设，实现阶段实证校准"；端口不是协议识别证据，可配置覆盖，planner 不得静默改写）。本版 fixture 统一 `dst_port=18081`（旧稿 JSON 占位同值，注册时保持一致）；**非默认端口显式声明即合法通道（v2.0.1 C-05）**——正例 24 `xmrmining_port_nondefault` 行使 3333（主流 XMR stratum 接入端口，端口不进 stratum 行内容，行字节与用例 1 一致），未显式声明的非 18081 端口拒绝（负例 62）。

固定偏移：无 VLAN（虚拟局域网）、IP options（IP 选项）与 TCP options 时，**每条 stratum 行的首字节（`{`，`0x7b`）起点为 IPv4 offset（偏移）54（Ethernet 14 + IPv4 20 + TCP 20）、IPv6 offset 74**（14 + IPv6 40 + TCP 20；构造 pcap 实测印证，`tcp.payload` 即完整行含行尾 `0a`）。**TCP 分段边界不是 stratum 行边界**：一个 TCP 段可含半行（跨 MSS 大行）、整行或多行粘连（行边界由 `0a` 自然定界），接收端按 LF 循环取行重组（§3.1）。

## 3. 线格式编码（逐项标注出处）

### 3.1 行式组帧与 JSON 序列化规则

- **消息边界**：每行 = 一个完整 JSON 对象 + 行尾单个 LF（`0x0a`）。行内不得出现未转义控制字符；CR（`0x0d`）不属于本协议（CRLF 进负例，spec 示例统一裸 LF）。
- **JSON 形态**：spec 示例为带空格的排版形态，线上字节由生成器钉死为**紧凑形态**（成员间无空格，`{"id":1,"jsonrpc":"2.0","method":"login",…}`，xmrig-impl `JsonRequest::create` 行为）；成员顺序钉死——请求 `id,jsonrpc,method,params`，响应 `id,jsonrpc,error,result`，通知 `jsonrpc,method,params`（spec 与 mo-pool `pushMessage` 全部示例的成员顺序）。
- **`id` 取材与配对**：请求 `id` 为 JSON number，**由矿机迭代、会话内唯一、login 恒为 1**（spec §login 示例 `"id":1`；xmrig-impl `JsonRequest::create` login 显式 `id=1`，后续 submit/keepalived/getjob 递增）；响应 `id` **同值回带**（spec 全部响应示例）。**通知省略顶层 `id` 成员**（spec §job 示例无 `id` 成员、mo-pool `pushMessage({method:"job",params})` 不设 id）——这与标准 JSON-RPC 通知 `"id":null` 不同，本协议生态省略 id 成员；**`params.id` 为 job 对象成员不受限**（现代 job 会话 id 回带，整行可含 `"id"` 键，v2.0.1 C-02 澄清：断言口径 = 顶层无 `"id":` 成员，非"整行不含"）；通知顶层携带伪 `id` 进负例（锚 `id`）。响应必须按 `id` 值配对，不得按 TCP 位置配对（§5 事务模型）。
- **`jsonrpc` 成员**：请求/响应**恒为 `"2.0"`**（spec 全部示例携带）；**keepalived 请求本版钉死携带** `"jsonrpc":"2.0"`（xmrig-impl `Client::ping()` 生成 `{"id":…,"jsonrpc":"2.0","method":"keepalived",…}`；spec 示例省略该成员——两形态均合法，mo-pool 请求端不校验，本版钉死带 jsonrpc 主形态，省略形态声明为合法方言不设例）。
- **响应形状**：`{"id":<同值>,"jsonrpc":"2.0","error":<null 或错误对象>,"result":<成功载荷或 null>}`。错误对象 = `{"code": <number>, "message": <string>}`（spec §login 错误示例、mo-pool `sendReply` 构造；data 成员非本协议规范形态，不设例）。
- **hex 字段编码**：全部 hex 数据字段为 ASCII 十六进制字符串，**无 `0x` 前缀**（spec 全部示例无前缀；0x 前缀进负例锚 `hex`），字符集 `0-9a-f`（spec 示例全小写），偶数长度。涉及字段：`blob`/`target`/`seed_hash`/`nonce`/`result`（submit）/`extra_nonce`（self-select 边界，不设例）。
- **数值序列化**：`height` 为 JSON number（十进制定点，spec 语义区块高度）；`id` 为 JSON number；`code` 为 JSON number。禁止科学计数法。
- **行长公式**：`L(line) = <固定常量> + Σ len(可变字段)`，逐消息固定常量见 §3.8（全部经脚本对 fixture 常量核验）；无协议级行长上界（job_id 为任意长度字符串，spec §job 示例 28 字符），实际受 blob 上界（§3.9）与 TCP 流约束。

### 3.2 消息总表（方法 / 方向 / id / params / 应答，出处逐条）

| 消息 | 方向 | id | params（spec §/xmrig-impl/mo-pool 出处） | 应答 |
|---|---|---|---|---|
| `login` | 矿机→矿池 | number（恒 1） | **对象** `{login, pass, agent[, rigid]}`；login=钱包地址或 `wallet.worker`，pass=密码（未设默认 `"x"`，mo-pool `validateLoginParams`），agent=矿机 UA 保留字段，rigid=可选矿机标识（xmrig-impl `m_rigId`） | 登录响应（§3.3） |
| `job` | 矿池→矿机 | **省略**（通知） | **对象**（job 对象：`blob/job_id/target` spec 原文三字段；现代矿池附加 `algo/height/seed_hash/id`，mo-pool `buildStandardJobPayload`） | 无 |
| `submit` | 矿机→矿池 | number | **对象** `{id, job_id, nonce, result[, algo, sig, commitment]}`；id=会话 id（回带 login 响应的 `result.id`），job_id=关联 job，nonce=4B hex，result=32B hash hex；可选 algo（xmrig-impl `EXT_ALGO`）、sig（64B 签名 hex）、commitment（32B hex，xmrig-impl 条件成员） | 提交响应两态（§3.5） |
| `keepalived` | 矿机→矿池 | number | **对象** `{id}`（会话 id；spec §keepalived verbatim；`keepalive` 为 mo-pool 接受别名，§3.6） | 保活响应（status `KEEPALIVED`） |
| `getjob` | 矿机→矿池 | number | **对象** `{id}`（会话 id；mo-pool `handleGetJobRequest`） | 结果 job 对象（§3.7） |

**方向违例**：矿机侧发 `job` 通知、矿池侧发 `login`/`submit`/`getjob`/`keepalived` 请求均为线格式/方向错，进负例（§7，锚 `method`/`direction`）。

### 3.3 `login` 请求/响应（spec §login + xmrig-impl）

请求（spec verbatim 紧凑化；fixture 常量值）：

```text
{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"<wallet 95>","pass":"x","agent":"XMRig/6.21.0 (Linux x86_64) libuv/1.44.0 gcc/11.3.0"}}\n
```

| 字段 | 位置 | 类型/宽度 | 值域与约束 | 出处 |
|---|---|---|---|---|
| `id` | 成员 | number | 恒 1（首条应用消息） | xmrig-impl `create(doc,1,"login",…)` |
| `method` | 成员 | 字符串 | 恒 `"login"` | spec §login |
| `params.login` | 对象 | 字符串 | 钱包地址（spec 示例 95 字符）或 `wallet.worker`（`.` 后缀矿机名，§4④ 标注；xmrig-impl 支持 worker 后缀） | spec §login |
| `params.pass` | 对象 | 字符串 | 密码；未设时矿池默认 `"x"` | spec §login、mo-pool `validateLoginParams` |
| `params.agent` | 对象 | 字符串 | 矿机 UA（保留字段，仅透传） | spec §login |
| `params.rigid` | 对象 | 字符串 | **可选**矿机标识（`rig-01` 一类；spec 未列，xmrig-impl 条件成员） | xmrig-impl `m_rigId` |

响应成功（spec verbatim 紧凑化）：

```text
{"id":1,"jsonrpc":"2.0","error":null,"result":{"id":"1be0b7b6-b15a-47be-a17d-46b2911cf7d0","job":{<job 对象>},"status":"OK"}}\n
```

| 字段 | 类型/宽度 | 值域与约束 | 出处 |
|---|---|---|---|
| `result.id` | 字符串 | **会话 id**——后续 submit/keepalived/getjob 的 `params.id` 必须回带（关联键）；spec 示例 UUID 形态 36 字符，长度未钉死（本版 fixture 钉死该值） | spec §login、xmrig-impl `parseLogin` 失败即关闭 |
| `result.job` | 对象 | 初始 job（与 `job` 通知的 job 对象同构，§3.4） | spec §login |
| `result.status` | 字符串 | 恒 `"OK"` | spec §login |
| `result.extensions` | 数组 | **可选**：`["algo","keepalive"]` 一类（xmrig-impl `parseExtensions`：algo/nicehash/connect/keepalive/tls） | xmrig-impl |

响应错误（spec verbatim）：

```text
{"id":1,"jsonrpc":"2.0","error":{"code":-1,"message":"Invalid payment address provided"}}\n
```

`error` = 对象 `{code:<number>, message:<string>}`（spec §login 错误示例）。**login 失败 → 会话关闭**（xmrig-impl `parseLogin` 失败或 `isCriticalError` 即 `close()`；spec 语义：登录不成功不产任务）。登录响应 `result.id` 缺失 → 矿机关闭（xmrig-impl `parseLogin` code=1；该分支由负例 55 `xmrmining_neg_result_id_missing` 钉死）。

### 3.4 `job` 通知（spec §job + mo-pool）

spec verbatim（最小形态）：

```text
{"jsonrpc":"2.0","method":"job","params":{"blob":"070780e6…","job_id":"4BiGm3/RgGQzgkTI/xV0smdA+EGZ","target":"b88d0600"}}\n
```

现代矿池形态（mo-pool `buildStandardJobPayload` 成员顺序 `blob,algo,height,seed_hash,job_id,target,id`）：

```text
{"jsonrpc":"2.0","method":"job","params":{"blob":"<152 hex>","algo":"rx/0","height":2652853,"seed_hash":"<64 hex>","job_id":"<28>","target":"b88d0600","id":"<session 36>"}}\n
```

| 字段 | 类型/宽度 | 值域与约束 | 出处 |
|---|---|---|---|
| `params.blob` | hex 字符串 | RandomX block template；**nonce 位于 offset 39（默认）4 字节小端**，解码字节数 ≥ 43（39+4），**上界 407B**（xmrig-impl `Job.h kMaxBlobSize`=408 且 `setBlob` 对 size≥408 拒绝——合法域 [43,407]，v2.0.1 C-01 修正）；spec 示例 76B | spec §job、xmrig-impl `nonceOffset`/`nonceSize`/`setBlob` |
| `params.job_id` | 字符串 | job 标识——submit 的关联键；任意长度（spec 示例 28 字符，含 `+/` base64 类字符） | spec §job |
| `params.target` | hex 字符串 | 紧凑难度表示（前导零字节 = 前导零位）；**4 字节常见形态 `b88d0600`，XMRig 支持 8 字节**（§3.9） | spec §job、xmrig-impl `setTarget` |
| `params.seed_hash` | hex 字符串 | RandomX DAG seed，**恰 64 hex（32B）**；变更触发数据集重建（~2.5 小时级），矿池提前发送 | spec 转述、xmrig-impl `setSeedHash`（strlen 恒 64 校验） |
| `params.height` | number | 区块高度（fixture 2652853/2652854；决定 seed 变更间随机程序数） | mo-pool `buildStandardJobPayload` |
| `params.algo` | 字符串 | RandomX 算法串 `"rx/0"` | mo-pool、xmrig-impl `setAlgorithm` |
| `params.id` | 字符串 | **可选**会话 id 回带（现代矿池形态） | mo-pool |

**通知省略 `id` 成员**（spec §job verbatim 无 `id`、mo-pool `pushMessage` 不设）——不得写成 `"id":null` 或伪值。工作轮换由新 `job_id`/`blob`/`seed_hash`/`height` 触发；轮换后旧 job 的提交按 stale 处理（矿池侧判定，本版只断言合法拒绝路径）。每个会话的最近 job 独立维护，多会话间 job 状态互不串用。

### 3.5 `submit` 请求与响应两态（spec §submit）

请求（spec verbatim 紧凑化）：

```text
{"id":2,"jsonrpc":"2.0","method":"submit","params":{"id":"1be0b7b6-…","job_id":"4BiGm3/RgGQzgkTI/xV0smdA+EGZ","nonce":"d0030040","result":"e1364b8782…"}}\n
```

| 字段 | 类型/宽度 | 值域与约束 | 出处 |
|---|---|---|---|
| `params.id` | 字符串 | 会话 id——**必须回带 login 响应的 `result.id`**（关联校验） | spec §submit、xmrig-impl `m_rpcId` |
| `params.job_id` | 字符串 | **必须来自本会话已收 job 的 `job_id`**（关联校验） | spec §submit |
| `params.nonce` | hex 字符串 | 4 字节（8 hex）u32 全域；矿机在 blob nonce 字段的尝试值（不与 blob 初始 nonce 字段强制相等——矿机本地写回尝试值后提交，测试只断言 8 hex 与 job 关联） | spec §submit、xmrig-impl `toHex(nonce,4B)` |
| `params.result` | hex 字符串 | 32 字节（64 hex）PoW 哈希（fixture 声明值，不做密码学断言） | spec §submit |
| `params.algo` | 字符串 | **可选**（`"rx/0"`；xmrig-impl `EXT_ALGO` 条件成员） | xmrig-impl |
| `params.sig` | hex 字符串 | **可选** 64 字节签名（128 hex；xmrig-impl 条件成员） | xmrig-impl |
| `params.commitment` | hex 字符串 | **可选** 32 字节（64 hex；xmrig-impl 条件成员） | xmrig-impl |

响应两态（spec §submit verbatim）：

| 形态 | 线上形态（spec verbatim 紧凑化） | 语义 |
|---|---|---|
| 接受 | `{"id":2,"jsonrpc":"2.0","error":null,"result":{"status":"OK"}}\n` | share 入账（正例 `xmrmining_submit_accept`） |
| 拒绝 | `{"id":2,"jsonrpc":"2.0","error":{"code":-1,"message":"Low difficulty share"}}\n` | 拒绝原因在错误对象（旧 job/stale/低难度）；**拒绝是合法协议路径，会话继续**（xmrig-impl `handleSubmitResponse`：非 critical 错误不关闭） |

### 3.6 `keepalived` 请求/响应（spec §keepalived + mo-pool）

请求（本版钉死带 jsonrpc 的 xmrig-impl 形态）：

```text
{"id":3,"jsonrpc":"2.0","method":"keepalived","params":{"id":"1be0b7b6-…"}}\n
```

- `params.id` = 会话 id（同 §3.5 关联规则）；`keepalive`（无 d）为 mo-pool 接受的**别名 method**（`RATE_LIMIT_METHODS` 双映射），本版作为 method 名方言变体正例（`xmrmining_keepalive_alias`）。
- spec 示例省略 `jsonrpc` 成员——声明为合法方言形态（mo-pool 请求端不校验），本版主形态带 jsonrpc，省略形态不设例、不进负例。

响应（spec verbatim）：`{"id":3,"jsonrpc":"2.0","error":null,"result":{"status":"KEEPALIVED"}}`——**status 值恒 `"KEEPALIVED"`**（区别于 login/submit 的 `"OK"`，spec §keepalived verbatim）。保活用于防止连接空闲超时（spec："Miner send keepalived to prevent connection timeout"），不是 job/share/登录成功的替代品。

### 3.7 `getjob` 请求/响应（mo-pool `handleGetJobRequest`）

```text
{"id":4,"jsonrpc":"2.0","method":"getjob","params":{"id":"<session 36>"}}\n
{"id":4,"jsonrpc":"2.0","error":null,"result":{<job 对象>}}\n
```

- 客户端主动拉取模式（矿机在无 job 或轮换时拉取）；`params.id` = 会话 id。
- 响应 `result` 直接为 job 对象（与 §3.4 现代形态同构）——"公开资料 + 假设，实现阶段实证校准"（mo-pool `handleGetJobRequest` 返回 `miner.getBestCoinJob()`，其对象形状经 `buildStandardJobPayload` 推断；本版 fixture 钉死为现代 job 对象）。
- `getjob` 未登录时调用 → mo-pool 返回 `"Unauthenticated"` 并关闭（合法错误路径声明，本版 fixture 不产生——正例仅已登录拉取）。

### 3.8 每消息行长公式汇总（固定常量经脚本对 fixture 核验）

固定常量 = 紧凑 JSON 骨架字节数 + 1（LF）。可变字段以占位长度计算，逐消息公式：

| 消息 | 行长公式（B） | fixture 样例长 |
|---|---|---|
| login 请求 | `84 + len(id串) + len(login) + len(pass) + len(agent) [+ 11 + len(rigid)]` | 232（无 rigid）；249（rigid `rig-01`）；239（`wallet.worker` 形态） |
| login 响应 OK | `77 + len(id串) + len(result.id) + len(job对象)` | 491 |
| login 响应 error | `55 + len(id串) + len(code串) + len(message)` | 90 |
| job 通知（现代） | `43 + len(job对象)`；job 对象 = `78 + len(blob) + len(algo) + len(height串) + len(seed_hash) + len(job_id) + len(target) + len(session id)` | 420 |
| job 通知（legacy 三字段） | `43 + len({blob,job_id,target} 对象)` | 266 |
| submit 请求 | `96 + len(id串) + len(session) + len(job_id) + len(nonce) + len(result) [+ 10 + len(algo)] [+ 9 + len(sig)] [+ 16 + len(commitment)]` | 233（无可选）；247（+algo）；450（+sig+commitment） |
| submit 响应 OK | `62 + len(id串)` | 63 |
| submit 响应 error | `55 + len(id串) + len(code串) + len(message)` | 78 |
| keepalived 请求 | `65 + len(id串) + len(session)` | 102 |
| keepalived 响应 | `70 + len(id串)` | 71 |
| getjob 请求 | `61 + len(id串) + len(session)` | 98 |
| getjob 响应 | `47 + len(id串) + len(job对象)` | 425 |
| login 响应 extensions | `77 + len(id串) + len(result.id) + 14 + len(extensions数组) + len(job对象)` | 525 |

（所有公式 = 紧凑 JSON 字节数 + 1（LF）。`len(id串)` = JSON number 文本长度（fixture id 均 1 位）。）

### 3.9 blob / target / seed_hash / nonce 字段规格（代码可生成级）

| 字段 | 类型 | 长度/字节序 | 值域与约束 | 出处 |
|---|---|---|---|---|
| `blob` | hex 字符串 | 偶数 hex；解码后字节数 ∈ **[43, 407]** | 解码字节数 < 43（39+4，nonceOffset+nonceSize）或 ≥ 408 拒绝（xmrig-impl `setBlob` 硬校验）；**nonce 字段位于 offset 39（默认），4 字节小端整数**（xmrig-impl `nonceOffset()` 默认 39、`nonce()` 返回 `uint32_t*` 直接解引用即小端读）；offset 39 起 8 hex 字符为 nonce 字段 | xmrig-impl `Job.h`/`Job.cpp` |
| `target` | hex 字符串 | 4 字节（8 hex）或 8 字节（16 hex） | 4 字节紧凑难度（`b88d0600`，前导零字节=前导零位）为 spec 示例形态；8 字节为 xmrig-impl `setTarget` 支持的第二形态；**长度非 4/8 字节拒绝** | spec §job、xmrig-impl `setTarget` |
| `seed_hash` | hex 字符串 | **恰 64 hex（32B）** | 非 64 hex 拒绝（xmrig-impl `setSeedHash` `strlen != 64` 返回 false） | xmrig-impl `setSeedHash` |
| `nonce`（submit） | hex 字符串 | 恰 8 hex（4B） | u32 全域（`00000000`–`ffffffff`）；非 8 hex 拒绝 | spec §submit、xmrig-impl |
| `result`（submit） | hex 字符串 | 恰 64 hex（32B） | PoW 哈希；本版 fixture 声明值，不做密码学断言 | spec §submit |
| `session id`（result.id/params.id） | 字符串 | 不透明（spec 示例 36 字符 UUID 形态） | 长度未钉死（spec）；本版 fixture 钉死 36 字符；login 响应缺 result.id 拒绝（xmrig-impl code=1，负例 55） | spec §login、xmrig-impl |
| `job_id` | 字符串 | 任意长度 | 无协议上界；spec 示例 28 字符（含 `+/` 字符，非 hex 值域——job_id 是 opaque 标识，不套 hex 校验） | spec §job |
| `height` | JSON number | — | 正整数（区块高度） | mo-pool |
| `algo` | 字符串 | — | `"rx/0"` 一类 RandomX 算法串 | mo-pool、xmrig-impl |

**hex 校验规则**（validator 逐条）：blob/target/seed_hash/nonce/result 必须为偶数长度 ASCII hex（`0-9a-f`），带 `0x` 前缀、奇数长度、非法字符、超长（blob≥408B、target 非 4/8B、seed_hash≠64、nonce≠8、result≠64）全部拒绝（负例锚 `hex`/`length`/`value`）。`job_id`/`session id` 为 opaque 字符串，不套 hex 校验。

## 4. 业务场景分析（现网典型场景与五层覆盖）**定性声明**：本引擎对 XMRMining 采用**声明式脚本化回放**——配置是剧本（sessions[]/events[] 逐条声明），引擎是回放者，按序产出行帧；"事件驱动"一词不用于定性整体行为，仅用于两处反应性成分：①**自动应答**（login/submit/keepalived/getjob 事件后自动补同 `id` 响应行，响应形态按事件配置的 status/error 展开）；②**连接边界**（事件序列中源端口切换触发新 TCP 连接，即多会话展开）。

| 现网场景 | 事务交互 | 驱动顺序 | 对应用例 |
|---|---|---|---|
| ① 矿机接入（最常见：矿机上线连矿池） | TCP→login→登录响应（会话 id + 初始 job + status OK） | 矿机驱动请求，矿池侧自动应答 | `xmrmining_login_job_ipv4`、`xmrmining_login_extensions`、`xmrmining_login_rigid` |
| ② 登录拒绝（无效钱包/凭证） | login→错误响应→连接关闭（合法错误路径） | 矿机驱动，矿池拒绝 | `xmrmining_login_reject` |
| ③ 收任务（矿池每新区块/周期推 job，区块高度递增） | login（含初始 job）→job 通知（现代/legacy 形态）→再 job 轮换 | 矿池侧事件编排 | `xmrmining_job_notify`、`xmrmining_job_notify_legacy` |
| ④ share 提交（矿机每找到低于 target 的哈希即提交） | submit→响应 OK / error（接受/拒绝，拒绝会话继续） | 矿机驱动 | `xmrmining_submit_accept`、`xmrmining_submit_reject`、`xmrmining_submit_algo`、`xmrmining_submit_sig` |
| ⑤ 保活（空闲防断线） | keepalived→status KEEPALIVED（`keepalive` 别名同效） | 矿机驱动 | `xmrmining_keepalived`、`xmrmining_keepalive_alias` |
| ⑥ 主动拉任务（矿机无 job/轮换时） | getjob→响应 job 对象 | 矿机驱动 | `xmrmining_getjob` |
| ⑦ 多矿机并发（矿场多台矿机同池接入，状态互不串） | 多会话按序展开 或 `concurrent: true` 交错回放，各会话独立 session id/job/难度/id | 各自驱动 | `xmrmining_multi_session`、`xmrmining_concurrent_sessions` |
| ⑧ 完整挖矿生命周期 | 接入→收任务→提交→新任务→再提交→保活→断开（单连接多事务） | 事件编排会话 | `xmrmining_lifecycle` |

**五层覆盖逐层结论**：功能层——5 类方法 + 变体每类正例（§3.2 表全覆盖：login×3 变体/响应两态、job 现代+legacy 两形态、submit×4 变体/响应两态、keepalived+别名、getjob），错误路径（login 拒绝、submit 拒绝）以正例承载；每类错误分支（配置/线格式/状态机/关联/长度）负例（§7）。性能层——大 job_id notify 行跨 MSS 分段重组（`xmrmining_mss_large_jobid`：job_id 1500 字符、行 1892B、默认 MSS 1460、2 段）、blob 407B 满值上界行（`xmrmining_blob_max`：行 1082B 一段，v2.0.1 C-01）、多行粘连单段（`xmrmining_line_packing`：653B 一段含 job+submit 两行）。数据场景层——blob 值域（nonce 偏移 39/4B 小端/上界 408B）、target 4/8B 两态、seed_hash 恰 64 hex、nonce 0/满值边界、result 64 hex、job_id 任意长度（28 字符基线/1500 字符压力）、session id 36 字符 opaque、height 递增、algo 变体。地址与流层——IPv4/IPv6 独立 fixture、单流基线、多会话双四元组；本协议不存在控制/数据分离或副连接，故不定义派生数据流；单连接内部为串行收发，并发仅发生在独立会话之间；**并发会话（`concurrent: true` 交错回放）v2.0.1 C-07 纳入**：正例 25 双矿机并发接入（与 22 按序展开分立）。业务层——接入-收任务-提交-保活链是现网挖矿日常（spec 全部场景即此链路），多会话与多事务（会话内 login→job→submit→job→submit→keepalived 先后依赖：login 先于一切、submit 依赖已收 job 与已得 session id）均覆盖。

以下边界项不设用例，均属合法方言或框架能力，不得进负例（§7 防误报同步）：① `keepalived` 请求省略 `jsonrpc` 成员（spec 示例形态，§3.6）——合法方言，本版主形态带 jsonrpc，省略形态不设例；② 矿池忽略 `getjob` 或返回拒绝（mo-pool 对未登录返回 `"Unauthenticated"`）——本版 fixture 恒成功路径，拒绝编码同 login 拒绝正例；③ `submit` 其他错误文案（非 "Low difficulty share"）——错误对象结构同拒绝正例，不逐文案设例；④ `block_template` 自选模板模式（jtgrassie sss.md）——边界声明不实现，planner 对混入方法按未知 method 拒绝（负例锚 `method`）；⑤ **无应用层保活/重试消息（v2.0.1 N-02）**——keepalived 是业务方法非 TCP 保活，长连接活性由 job 周期/keepalived 方法承载，不设 TCP keepalive 探测例亦不进负例；⑥ **RST/异常中断不适用（v2.0.1 N-02）**——所有会话以 FIN 挥手统一终止，生成器不构造 RST 异常断开（框架 tcp 层能力，本协议层零断言零 ID）。

## 5. 消息/事务模型与状态机

**事务定义**：XMR 事务 = 同一 TCP 连接内一次完整的请求/响应交互，关联标识为 JSON `id`（响应同值回带）。**通知（job）无 id、无应答，不构成事务**。**多事务** = 一个连接内多笔事务按序执行且有先后依赖：**login 必须是首条应用消息**（spec §login："Miner send login request after connection successfully established"）；**login 成功（得 session id 与初始 job）后才允许 submit/getjob/keepalived**（状态机约束）；**submit 的 `params.id` 必须等于 login 响应的 `result.id`**（会话关联键）；**submit 的 `job_id` 必须来自本会话已收 job**（job 关联键）；**响应按 `id` 值配对，不按 TCP 位置配对**（矿池可能不按 FIFO 处理）。事务交互示例：login（id=1）→submit（id=2，依赖会话 id 与 job A）→job B→submit（id=3，依赖 job B）——第二笔 submit 依赖第一轮的 job 上下文轮换。

矿机侧会话状态机（确定性：同一事件序列必然产出同一行序列，无随机/未定义行为；生成器在某状态下遇到非法事件——如未登录先提交——必须拒绝并报状态机错误，不得静默产出）：

| 状态 | 允许事件（→目标状态） | 必须保持 |
|---|---|---|
| `Disconnected` | TCP 三次握手（→`TransportReady`） | 握手后首条应用消息必须是 login |
| `TransportReady` | 发 login（→`LoggingIn`） | params.login 非空；id=1 |
| `LoggingIn` | 收登录响应 OK（→`LoggedIn`）；收错误响应（→`Closed`） | 响应 id 同值；成功时记录 result.id 为会话 id、result.job 为最近 job；**login 失败后不得再发任何应用消息**（xmrig-impl `close()` 语义） |
| `LoggedIn` | 收 job 通知（保持，更新最近 job）；发 submit→收响应 OK/error（保持）；发 getjob→收响应（保持）；发 keepalived→收响应（保持）；TCP FIN（→`Closed`） | submit/getjob/keepalived 的 params.id = 会话 id；submit 的 job_id ∈ 已收 job 集合；响应 id 同值；submit 拒绝后会话继续（非 critical） |
| `Closed` | — | 关闭后不得产生新行 |

**自动派生规则**（引擎自动补出的行，逐条列出触发条件与内容）：①登录响应——login 事件后自动补同 `id` 响应行（成功：result 含 session id + job（按事件配置现代/legacy 形态）+ status "OK"，可选 extensions；错误：error 对象按事件配置 code/message）；②提交响应——submit 事件后按 `result` 配置补 `{"status":"OK"}` 或 error 对象；③保活响应——keepalived/keepalive_alias 事件后补同 `id` `{"status":"KEEPALIVED"}`；④getjob 响应——getjob 事件后补同 `id` result=job 对象（§3.7 假设形态）；⑤TCP 三次握手与 FIN 挥手由 tcp 层自动补（连接边界：源端口切换触发新连接）。每条自动行均可被事件显式覆盖（如拒绝路径）。

**多会话展开**：`sessions[]` 按序整块回放——先跑完第 1 个会话全流程（握手→事件→挥手），再跑第 2 个，不交错；**第二会话包号起点 = 前一会话总包数 + 1**。各会话四元组、id 序列、会话 id、最近 job 互不串用（同值 session id 在不同会话可独立存在，但跨会话响应不得互相消费——负例锚 `id`）。**并发会话（`concurrent: true`）v2.0.1 C-07 翻案纳入**：矿场多矿机并发接入是现网常态（§4 场景⑦），由正例 25 `xmrmining_concurrent_sessions` 承载——双矿机交错回放，各会话四元组/session id/job_id/id 序列互不串用，单会话内事件序仍受本状态机约束（判例 cwmp⑦/doh#24/onvif#56/hl7#26/megaco#45/bacnet#47）。**多流（一个会话内部并发流）仍显式不适用**：单连接串行收发——"单 TCP 流串行"是否定多流的理由、不是否定连接间并发的理由（旧句类别混淆，v2.0.1 已改）。

## 6. 配置 typedef（JSON 形状示例，非 Go 代码）

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.74", "dst": "198.51.100.74"}},
    {"tcp": {"src_port": 4074, "dst_port": 18081}},
    {"xmrmining": {
    "profile": "xmrmining_stratum_v1",
    "sessions": [
      {
        "events": [
          {"kind": "login", "id": 1,
           "login": "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD",
           "pass": "x", "agent": "XMRig/6.21.0 (Linux x86_64) libuv/1.44.0 gcc/11.3.0",
           "session_id": "1be0b7b6-b15a-47be-a17d-46b2911cf7d0",
           "job": {"blob": "070780e6…", "job_id": "q7PLUPL25UV0z5Ij14IyMk8htXbj",
                   "target": "b88d0600", "algo": "rx/0", "height": 2652853,
                   "seed_hash": "c9aa8bd6…", "id": "1be0b7b6-…"},
           "status": "OK", "extensions": ["algo", "keepalive"]},
          {"kind": "job", "job_id": "4BiGm3/RgGQzgkTI/xV0smdA+EGZ",
           "blob": "0707d5ef…", "target": "b88d0600",
           "algo": "rx/0", "height": 2652854, "seed_hash": "c9aa8bd6…"},
          {"kind": "submit", "id": 2, "session_id": "1be0b7b6-…",
           "job_id": "4BiGm3/RgGQzgkTI/xV0smdA+EGZ",
           "nonce": "d0030040", "result": "e1364b8782…", "status": "OK"},
          {"kind": "keepalived", "id": 3, "session_id": "1be0b7b6-…"}
        ]
      }
    ]
    }}
  ]
}
```

形状要点：`sessions[]` = 统一术语的**事件编排会话**（每个自带四元组与事件序列，多会话展开按序整块回放，第二会话包号起点 = 前会话总包数 + 1；`concurrent: true` 并发交错回放——v2.0.1 C-07，正例 25）；`events[]` = 会话的**事件序列**，kind 覆盖 `login`（id=1、login/pass/agent + 自动响应的 session_id/job/status/extensions）/`job`（矿池侧通知：job_id/blob/target 必填，algo/height/seed_hash/id 可选）/`submit`（id/session_id/job_id/nonce/result + status 控制响应两态）/`keepalived`（含 `method` 别名开关 `keepalive_alias: true`）/`getjob`（id/session_id）；`wire_fault` 仅负例注入口，**39 值枚举与 §7 表/用例文档 §5 表三方同序**（v2.0.1 C-04 原子拆分；v2.0.2 复验 V-1 补 `result_id_missing`）：`json_truncated、json_unclosed、json_notobject、framing_no_lf、framing_crlf、framing_length_prefix、method_unknown、method_direction、method_btc_array、params_login_missing、params_login_type、params_submit_missing、params_submit_type、params_getjob_missing、params_keepalived_missing、hex_blob_odd、hex_blob_nonhex、hex_blob_short、hex_blob_overflow、hex_seed_hash、hex_target、hex_nonce、hex_result、hex_prefix、state_first_login、state_submit_before_login、state_after_login_reject、state_after_close、id_resp_mismatch、result_id_missing、id_notify_fake、id_reuse、job_unknown、job_session_mismatch、carrier_missing_tcp、carrier_udp、carrier_port_conflict、prop_swallowed、prop_fake_success`（§7），不得成为线上字段。**配置到帧的完整路径**：配置 → validator（层链/端口/事件序状态机/id 会话内唯一/hex 值域与长度/job 关联/会话关联校验）→ planner（事件序列展开为行序列，紧凑 JSON 序列化 + LF，按 §3.8 公式计算行长）→ worker（TCP 分段：默认每行一段，>MSS 自动分段，段数 = 行长对 MSS 上取整；`pack` 相邻同方向行合并为一段）→ writer（PCAP/NIC）。

## 7. 错误处理（负例锚词表）

以下输入必须由 planner/validator 拒绝并传播为 task error（任务错误），不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。锚词（anchor word）为 `error_contains` 断言字面值，与用例文档 §5 一一对应、同序：

以下输入必须由 planner/validator 拒绝并传播为 task error（任务错误），不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。**逐故障输入原子拆分（v2.0.1 C-04）：一行一例，每行恰注入一个故障；主锚词为钉死的单一字面值**，与用例文档 §5 表一一对应（39 行同序）：

| # | 负例 ID | 类别 | 故障输入（单一注入） | 主锚词 `error_contains` |
|---:|---|---|---|---|
| 26 | `xmrmining_neg_json_truncated` | 线格式错 | 行内容截断（`{"id":1,"jsonrpc":"2.0","method":"login` 无闭合，缺对象尾部） | `json` |
| 27 | `xmrmining_neg_json_unclosed` | 线格式错 | 字符串未闭合（login 行 params 字符串缺引号） | `json` |
| 28 | `xmrmining_neg_json_notobject` | 线格式错 | 某行为 JSON 数组/标量（非对象顶层） | `json` |
| 29 | `xmrmining_neg_framing_no_lf` | 线格式错 | 末行无 LF 裸结束 | `newline` |
| 30 | `xmrmining_neg_framing_crlf` | 线格式错 | 行尾 `0d0a`（CRLF，spec 统一裸 LF） | `crlf` |
| 31 | `xmrmining_neg_framing_length_prefix` | 线格式错 | 行前置 4 字节长度前缀取代换行定界 | `framing` |
| 32 | `xmrmining_neg_method_unknown` | 线格式错 | 未知 method（含 `block_template` 混入，§1 边界） | `method` |
| 33 | `xmrmining_neg_method_direction` | 线格式错 | 矿机事件发 `job` 通知（方向违例） | `direction` |
| 34 | `xmrmining_neg_method_btc_array` | 线格式错 | `mining.subscribe` 数组 params 混入（比特币 stratum 形态，§1 边界） | `params` |
| 35 | `xmrmining_neg_params_login_missing` | 值域错 | login 缺 `login` 字段 | `login` |
| 36 | `xmrmining_neg_params_login_type` | 值域错 | login `login` 非字符串（如数字） | `params` |
| 37 | `xmrmining_neg_params_submit_missing` | 值域错 | submit 缺 `nonce` 字段 | `submit` |
| 38 | `xmrmining_neg_params_submit_type` | 值域错 | submit `job_id` 非字符串 | `params` |
| 39 | `xmrmining_neg_params_getjob_missing` | 值域错 | getjob 缺 `id` 字段 | `getjob` |
| 40 | `xmrmining_neg_params_keepalived_missing` | 值域错 | keepalived 缺 `id` 字段 | `keepalived` |
| 41 | `xmrmining_neg_hex_blob_odd` | 值域错 | blob 奇数长度 hex | `blob` |
| 42 | `xmrmining_neg_hex_blob_nonhex` | 值域错 | blob 含非法 hex 字符（如 `g`） | `blob` |
| 43 | `xmrmining_neg_hex_blob_short` | 值域错 | blob 解码 <43B（39+4 nonceOffset+nonceSize 下界） | `blob` |
| 44 | `xmrmining_neg_hex_blob_overflow` | 值域错 | blob 解码 ≥408B（超上界 407B） | `blob` |
| 45 | `xmrmining_neg_hex_seed_hash` | 值域错 | seed_hash 非 64 hex | `seed_hash` |
| 46 | `xmrmining_neg_hex_target` | 值域错 | target 非 4/8 字节 | `target` |
| 47 | `xmrmining_neg_hex_nonce` | 值域错 | nonce 非 8 hex | `nonce` |
| 48 | `xmrmining_neg_hex_result` | 值域错 | submit result 非 64 hex | `result` |
| 49 | `xmrmining_neg_hex_prefix` | 值域错 | hex 字段带 `0x` 前缀（本协议无前缀，spec 全部无前缀） | `hex` |
| 50 | `xmrmining_neg_state_first_login` | 状态机错 | 首条应用消息非 login（如直接 job 通知） | `login` |
| 51 | `xmrmining_neg_state_submit_before_login` | 状态机错 | 未 login 成功先 submit | `submit` |
| 52 | `xmrmining_neg_state_after_login_reject` | 状态机错 | login 失败后继续排业务事件 | `login` |
| 53 | `xmrmining_neg_state_after_close` | 状态机错 | 会话关闭后继续排事件 | `state` |
| 54 | `xmrmining_neg_id_resp_mismatch` | 关联错 | 响应 id ≠ 请求 id（按值配对，不得按 TCP 位置） | `id` |
| 55 | `xmrmining_neg_result_id_missing` | 关联错 | login 响应 `result` 对象缺 `id` 成员（xmrig-impl `parseLogin` code=1） | `result` |
| 56 | `xmrmining_neg_id_notify_fake` | 关联错 | job 通知携带伪 `id`（本协议省略 id 成员，伪 id 非法） | `id` |
| 57 | `xmrmining_neg_id_reuse` | 关联错 | 同会话未完成事务复用同一 id | `id` |
| 58 | `xmrmining_neg_job_unknown` | 关联错 | submit 的 job_id 不来自本会话已收 job | `job` |
| 59 | `xmrmining_neg_job_session_mismatch` | 关联错 | submit/getjob/keepalived 的 params.id ≠ 本会话 session id | `session` |
| 60 | `xmrmining_neg_carrier_missing_tcp` | 配置/载体错 | 载体故障注入（`carrier_missing_tcp` wire_fault） | `carrier` |
| 61 | `xmrmining_neg_carrier_udp` | 配置/载体错 | UDP 载体声明 | `carrier` |
| 62 | `xmrmining_neg_carrier_port_conflict` | 配置/载体错 | 端口与载体声明矛盾 | `port` |
| 63 | `xmrmining_neg_prop_swallowed` | 错误传播错 | validator 已知 hex/状态错误被吞 | `propagat` |
| 64 | `xmrmining_neg_prop_fake_success` | 错误传播错 | 任务报 completed/0 packet 假成功 | `task` |

**不得误报为 planner error 的合法协议事件**：submit 拒绝（error 对象，正例 8）、login 拒绝（正例 2）、job 通知省略 id（正例 5/6）、keepalive 别名（正例 12）、keepalived 请求省略 jsonrpc 方言（§4 声明②）、submit 可选字段（algo/sig/commitment，正例 9/10）、target 8 字节（正例 16）、nonce 0/满值（正例 17）。只有配置、线格式、状态、关联、长度错误进入负例。

## 8. 边界

- **行长与分段**：job 通知行 = `43 + 78 + len(blob) + len(algo) + len(height串) + len(seed_hash) + len(job_id) + len(target) + len(session)`；`xmrmining_mss_large_jobid` 用 job_id 1500 字符 ⇒ 行 1892B，默认 MSS 1460 不压，跨 2 段（1460+432），接收端按 LF 重组后断言完整行——**分段边界不切坏行内容，也不产生伪行界**（行内无 0x0a 字节是 JSON 文本保证：hex/ASCII 字段无 LF）。
- **多行粘连**：`xmrmining_line_packing` 将 job 通知（419B）+ submit（232B）合并为一段 653B 载荷，段内恰 2 个 `0a`；接收端按行拆分，段边界 ≠ 行边界两个方向都断言。
- **blob 宽度带**：解码字节数 ∈ [43, 407]（xmrig-impl `setBlob` 对 size≥408 拒绝、kMaxBlobSize=408——合法上界 407B，v2.0.1 C-01）；nonce 字段位于 offset 39、4 字节小端；`xmrmining_blob_max` 用 407B 满值 blob（行 1082B 一段）；解码 <43B 进负例 43、≥408B 进负例 44（407 满值正例 + 408 超界负例边界对闭合）。
- **target 两态**：4 字节（`b88d0600`，spec 示例）与 8 字节（`b88d060000000000`，xmrig-impl `setTarget` 第二形态）各一正例（16）；非 4/8B 进负例 46。
- **seed_hash 恒 64 hex**：非 64 进负例 45；变更触发数据集重建（本版 fixture 会话内恒定，跨会话可不同）。
- **nonce 全域**：u32 0x00000000–0xffffffff（正例 17 两态）；非 8 hex 进负例 47。
- **id 域**：login 恒 1，后续递增（spec/xmrig-impl）；会话内唯一；响应同值回带；跨会话可复用但不得互相消费。
- **job_id 值域**：opaque 字符串（可含 `+/`，非 hex）；基线 28 字符，压力 1500 字符（正例 19）；不套 hex 校验。
- **session id**：opaque；login 响应缺 `result.id` 拒绝（xmrig-impl code=1，负例 55）；submit/getjob/keepalived 必须回带。
- **v4/v6**：IPv4/IPv6 独立 fixture，同一逻辑行字节必须一致，仅外层 IP 头与偏移（54/74）不同；不得从 IPv4 默认值推导 IPv6 地址（fixture 显式给出 `2001:db8::74 → 2001:db8::100:74`）。
- **多会话**：≥2 个独立四元组，id 序列/会话 id/job 集合互不串用；会话间包序按多会话展开（第二会话起点 = 前会话总包数 + 1）。
- **端口（v2.0.1 C-05）**：默认 fixture 18081；非默认端口 3333 **显式声明即合法通道**（正例 24——端口不进 stratum 行内容，行字节与基线一致），未显式声明的非 18081 端口拒绝（负例 62）；本协议无专用 dissector、断言全走 `tcp.payload`/frames，无 DecodeAs 依赖。
- **并发会话（v2.0.1 C-07）**：`concurrent: true` 双矿机交错回放（正例 25，session id/job_id/id 互不串用）；多流（单连接内部并发流）仍显式不适用（单连接串行收发）。
- **无保活/RST（v2.0.1 N-02）**：无应用层 PING/重试消息（keepalived 是业务方法，长连接活性由 job 周期承载），不设 keepalive 探测例亦不进负例；RST/异常中断不适用——所有会话以 FIN 挥手统一终止，生成器不构造 RST（框架 tcp 层能力，本协议层零断言零 ID）。
- 不得产生回绕长度或超量分配（行长无协议上界，受 blob 407B 合法上界与生成器缓冲约束；大 job_id 压力值 1500 字符在配置显式声明，不隐式放大）。

## 9. 原子 ID 与完成定义

设计、testcase 与机器契约 `xmrmining.json` 当前使用同一组 **64 个唯一语义 ID（25 正 + 39 负）**、同一顺序；正例是待实现静态契约，负例按单故障输入严格双键。

| # | ID | 类型 | 覆盖（设计 §） |
|---:|---|---|---|
| 1 | `xmrmining_login_job_ipv4` | 正 | §3.3：login 请求/响应全字段（会话 id + 现代 job + status OK），IPv4 单流基线 |
| 2 | `xmrmining_login_reject` | 正 | §3.3：login 错误响应（`code:-1` + "Invalid payment address provided"）+ 连接关闭（合法错误路径） |
| 3 | `xmrmining_login_extensions` | 正 | §3.3：login 响应带 `extensions`（algo/keepalive） |
| 4 | `xmrmining_login_rigid` | 正 | §3.3：login 带可选 `rigid` 字段（xmrig-impl） |
| 5 | `xmrmining_job_notify` | 正 | §3.4：job 通知（省略 id）+ 现代 job 对象全字段（blob/algo/height/seed_hash/job_id/target/id） |
| 6 | `xmrmining_job_notify_legacy` | 正 | §3.4：legacy 三字段 job 形态（仅 blob/job_id/target，spec 原文） |
| 7 | `xmrmining_submit_accept` | 正 | §3.5：submit 请求/响应 OK（会话+job 关联） |
| 8 | `xmrmining_submit_reject` | 正 | §3.5：submit + error 对象（"Low difficulty share"），会话继续（合法错误路径） |
| 9 | `xmrmining_submit_algo` | 正 | §3.5：submit 带可选 `algo` 字段 |
| 10 | `xmrmining_submit_sig` | 正 | §3.5：submit 带可选 `sig`/`commitment` 字段（长行 450B） |
| 11 | `xmrmining_keepalived` | 正 | §3.6：keepalived 请求/响应 status KEEPALIVED |
| 12 | `xmrmining_keepalive_alias` | 正 | §3.6：`keepalive` 别名 method（mo-pool 双映射） |
| 13 | `xmrmining_getjob` | 正 | §3.7：getjob 请求/响应 result=job 对象（主动拉取模式） |
| 14 | `xmrmining_id_correlation` | 正 | §3.1/§5：多事务 id 按值配对（login id=1/submit id=2/keepalived id=3），非 TCP 位置配对 |
| 15 | `xmrmining_blob_nonce_offset` | 正 | §3.9：blob nonce 字段位于 offset 39、4 字节（8 hex），submit nonce 为 8 hex 且 job 关联 |
| 16 | `xmrmining_target_length` | 正 | §3.9：target 4 字节与 8 字节两态 |
| 17 | `xmrmining_nonce_boundary` | 正 | §3.9：nonce 0x00000000 与 0xffffffff 边界（u32 全域） |
| 18 | `xmrmining_line_packing` | 正 | §2/§8：job+submit 多行粘连单段（653B、段内 2 个 LF） |
| 19 | `xmrmining_mss_large_jobid` | 正 | §3.8/§8：job_id 1500 字符 ⇒ 行 1892B 跨 MSS 2 段重组 |
| 20 | `xmrmining_blob_max` | 正 | §3.9/§8：blob 407B 合法上界（行 1082B，v2.0.1 C-01） |
| 21 | `xmrmining_ipv6` | 正 | §2/§8：IPv6 独立 fixture（offset 74） |
| 22 | `xmrmining_multi_session` | 正 | §5/§8：双矿机双四元组多会话展开（独立 session id/job/id） |
| 23 | `xmrmining_lifecycle` | 正 | §4⑧/§5：单会话多事务全链（接入→收任务→提交→新任务→再提交→保活） |
| 24 | `xmrmining_port_nondefault` | 正 | §2/§8：非默认端口 3333 显式声明合法通道（端口不进 stratum 行内容，行字节与用例 1 一致） |
| 25 | `xmrmining_concurrent_sessions` | 正 | §4⑦/§5：双矿机 concurrent 交错回放（session id/job_id/id 互不串用，与 22 按序展开分立） |
| 26 | `xmrmining_neg_json_truncated` | 负 | §7：行内容截断 |
| 27 | `xmrmining_neg_json_unclosed` | 负 | §7：字符串未闭合 |
| 28 | `xmrmining_neg_json_notobject` | 负 | §7：某行为 JSON 数组/标量 |
| 29 | `xmrmining_neg_framing_no_lf` | 负 | §7：末行无 LF 裸结束 |
| 30 | `xmrmining_neg_framing_crlf` | 负 | §7：行尾 `0d0a` |
| 31 | `xmrmining_neg_framing_length_prefix` | 负 | §7：行前置 4 字节长度前缀取代换行定界 |
| 32 | `xmrmining_neg_method_unknown` | 负 | §7：未知 method |
| 33 | `xmrmining_neg_method_direction` | 负 | §7：矿机事件发 `job` 通知 |
| 34 | `xmrmining_neg_method_btc_array` | 负 | §7：`mining.subscribe` 数组 params 混入 |
| 35 | `xmrmining_neg_params_login_missing` | 负 | §7：login 缺 `login` 字段 |
| 36 | `xmrmining_neg_params_login_type` | 负 | §7：login `login` 非字符串 |
| 37 | `xmrmining_neg_params_submit_missing` | 负 | §7：submit 缺 `nonce` 字段 |
| 38 | `xmrmining_neg_params_submit_type` | 负 | §7：submit `job_id` 非字符串 |
| 39 | `xmrmining_neg_params_getjob_missing` | 负 | §7：getjob 缺 `id` 字段 |
| 40 | `xmrmining_neg_params_keepalived_missing` | 负 | §7：keepalived 缺 `id` 字段 |
| 41 | `xmrmining_neg_hex_blob_odd` | 负 | §7：blob 奇数长度 hex |
| 42 | `xmrmining_neg_hex_blob_nonhex` | 负 | §7：blob 含非法 hex 字符 |
| 43 | `xmrmining_neg_hex_blob_short` | 负 | §7：blob 解码 <43B |
| 44 | `xmrmining_neg_hex_blob_overflow` | 负 | §7：blob 解码 ≥408B |
| 45 | `xmrmining_neg_hex_seed_hash` | 负 | §7：seed_hash 非 64 hex |
| 46 | `xmrmining_neg_hex_target` | 负 | §7：target 非 4/8 字节 |
| 47 | `xmrmining_neg_hex_nonce` | 负 | §7：nonce 非 8 hex |
| 48 | `xmrmining_neg_hex_result` | 负 | §7：submit result 非 64 hex |
| 49 | `xmrmining_neg_hex_prefix` | 负 | §7：hex 字段带 `0x` 前缀 |
| 50 | `xmrmining_neg_state_first_login` | 负 | §7：首条应用消息非 login |
| 51 | `xmrmining_neg_state_submit_before_login` | 负 | §7：未 login 成功先 submit |
| 52 | `xmrmining_neg_state_after_login_reject` | 负 | §7：login 失败后继续排业务事件 |
| 53 | `xmrmining_neg_state_after_close` | 负 | §7：会话关闭后继续排事件 |
| 54 | `xmrmining_neg_id_resp_mismatch` | 负 | §7：响应 id ≠ 请求 id |
| 55 | `xmrmining_neg_result_id_missing` | 负 | §7：login 响应缺 result.id |
| 56 | `xmrmining_neg_id_notify_fake` | 负 | §7：job 通知携带伪 `id` |
| 57 | `xmrmining_neg_id_reuse` | 负 | §7：同会话未完成事务复用同一 id |
| 58 | `xmrmining_neg_job_unknown` | 负 | §7：submit 的 job_id 不来自本会话已收 job |
| 59 | `xmrmining_neg_job_session_mismatch` | 负 | §7：submit/getjob/keepalived 的 params.id ≠ 本会话 session id |
| 60 | `xmrmining_neg_carrier_missing_tcp` | 负 | §7：层链缺 tcp |
| 61 | `xmrmining_neg_carrier_udp` | 负 | §7：UDP 载体声明 |
| 62 | `xmrmining_neg_carrier_port_conflict` | 负 | §7：端口与载体声明矛盾 |
| 63 | `xmrmining_neg_prop_swallowed` | 负 | §7：validator 已知 hex/状态错误被吞 |
| 64 | `xmrmining_neg_prop_fake_success` | 负 | §7：任务报 completed/0 packet 假成功 |

完成定义：注册 `tcp→xmrmining` 层链；逐字段生成并验证 §3 全部 5 类方法 + 变体（行式组帧、紧凑 JSON、LF 边界、行长公式、hex 值域、blob nonce 偏移/上界、target 两态、seed_hash 恒 64、会话/作业关联）；登录（含 extensions/rigid/拒绝路径）、job 通知（现代/legacy）、submit 两态、保活双别名、getjob、id 关联、多事务、多会话展开、IPv4/IPv6、MSS 分段与粘连重组、全部边界均可观测；64 个语义 ID 正负断言与错误传播完成；当前已具备 registry 与 terminal translation，运行验收仍待后续阶段，不以静态契约冒充行为通过；pcap/NIC 双输出共用本契约（§1 输出契约段）。不声称真实 RandomX PoW、share/区块密码学有效、矿池凭证有效或区块产生。

## 10. P1规范矩阵与三路对照

| 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|
| 长 TCP、LF 行界 | 登录/任务/提交 | `xmrmining` registry 字段与 terminal translation 已登记；运行未验收 | G-XMR-2：待 suite/server 验证端到端行组帧与重组 |
| login 请求与响应 | 矿机接入 | 层链终结配置可翻译；行为未运行确认 | G-XMR-2：待正例 1–4 运行验收 |
| job 通知无顶层 id | 下发任务 | 层链终结配置可翻译；行为未运行确认 | G-XMR-2：待正例 5–6 运行验收 |
| submit 双响应态 | share 接受/拒绝 | 层链终结配置可翻译；行为未运行确认 | G-XMR-2：待正例 7–10 运行验收 |
| keepalived/getjob | 保活/主动拉取 | 层链终结配置可翻译；行为未运行确认 | G-XMR-2：待正例 11–13 运行验收 |
| blob nonce 39/4B | 工作量提交 | 字段约束已登记；未运行确认字节偏移与边界 | G-XMR-2：待正例 15/17/20 运行验收 |
| target 4/8B、seed 64 hex | 难度/RandomX | 字段约束已登记；未运行确认拒绝路径 | G-XMR-2：待正例 16、负例 45–49 运行验收 |
| IPv4/IPv6 与多会话 | 矿场接入 | 层链可承载；多会话行为未运行确认 | G-XMR-2：待正例 21–25 运行验收 |

| 命令×响应码 | 已覆盖 |
|---|---|
| login: OK/-1 | 正例 1/2 |
| submit: OK/-1 | 正例 7/8 |
| keepalived: KEEPALIVED | 正例 11/12 |
| getjob: result job | 正例 13 |

| 数据形态变体 | 用例 |
|---|---|
| modern/legacy job | 5/6 |
| target 4/8B | 5/16 |
| blob 43–407B、nonce 边界 | 15/17/20 |
| IPv4/IPv6、按序/交错会话 | 1/21/22/25 |

| 商业行为 | 用例映射 |
|---|---|
| XMRig login/rigid/extensions | 1/3/4 |
| MoneroOcean job/getjob/keepalive | 5/13/11/12 |
| 现网多矿机交错 | 22/25 |

三路对照：官方 xmrig-proxy `STRATUM.md` 定消息底线；XMRig `Client.cpp`/`Job.cpp` 定字段校验与 nonce；MoneroOcean `protocol.js` 定现代 job、别名和应答。三者冲突时规范为底线、实现行为为兼容依据，未知形态以待抓包确认，不写入正例。

| 方案 | 优点 | 代价 | 结论 |
|---|---|---|---|
| 逐事件生成 LF 行 | 流式、低内存、易校验 | 需维护会话状态 | 采用 |
| 预拼接整连接字节 | 实现短 | 大 job_id 内存峰值、难分段 | 不采用 |

## 11. 性能设计与验收

目标与边界：默认单行单段；job_id 1500 字符跨 MSS；blob 最大 407B；多会话按序或交错。规划器逐事件流式产出，不收集全连接；队列与缓冲沿用引擎有界配置，CPU 并行度由 worker 数决定。pcap 验收检查行尾 LF、重组内容、段数和 packet_count；NIC 验收用 tcpdump 对同一 fields/frames 断言。六类场景为基线、目标规模、压力上限、长时间、并发交错、资源耗尽/背压，分别对应 1、19、20、23、25 和 19/22；实际吞吐、延迟、内存、CPU、队列积压、丢包须记录，未基准化数字不作承诺。

## 12. 八要素、动态字段与门1

| 八要素 | 定稿 |
|---|---|
| 文件 | layer 注册、planner、validator、cases 三文件 |
| 接口 | 输入 `layers` + `sessions/events`，输出流式 packet config |
| 结构 | ip/tcp/xmrmining 层，session→event→line |
| 流程 | validator→planner→worker→PCAP/NIC writer |
| 错误 | 39 个 `wire_fault` 均 task error，禁止假成功 |
| 性能边界 | MSS 分段、407B blob、1500 字符 job_id、有界队列 |
| 冲突点 | 顶层旧字段与 TCP/UDP 载体均拒绝 |
| 回滚 | 回滚本轮 G-XMR-2 文档/验收登记变更；registry 与 terminal translation 现状不回退；cases 与文档保持契约 |

动态清单：四元组 `ip.src/dst`、`tcp.src_port/dst_port` 使用 fixed 或按会话显式值；`id` 使用会话序号递增；`session_id`、`job_id`、`blob`、`target`、`seed_hash`、`height`、`nonce`、`result`、`algo` 均使用 fixed/事件值，不隐式变化。序号算法在 planner 的 sessions/events 遍历中实现；动态策略未实现前不得声称支持 rand/inc/pattern。

门1对照：旧键 `src_ip/dst_ip`→`ip` 层，`src_port/dst_port`→`tcp` 层，`count`→`flow_control`，业务映射→`xmrmining` 层；完整 spec 示例见 §6；五件套为 sessions、events、关联键、时间线、错误分支，见 §5；动态三行清单见本节。

- v2.0.3（2026-10-01）：层链能力状态修订轮。机器契约已实际包含 64 个语义 ID（25 正 + 39 负），文档与 cases 对账；确认 registry 与 terminal translation 已存在，保留“尚未运行 suite/server/MCP/NIC”的静态边界。

- v2.0.1（2026-09-01，v1.3 行为面全枚举重审修复轮）：docs-xmrmining 重审 7 confirmed + 2 note 逐项修复，33 → **63 例（25 正 + 38 负）**。**C-01** blob 合法域 [43,408]→[43,407]（xmrig `setBlob` 对 size≥408 拒绝），正例 20 改 407B/行 1082B/814 hex；**C-02** 通知断言改"顶层无 id 成员"（`params.id` 为 job 对象成员不受限，废除"整行不含 22696422"自相矛盾断言）；**C-03** 用例 18 packet_count 正文 10→11（3+4+4）；**C-04**（MAJOR）负例逐故障输入原子拆分 10 → 38 行（一行一例单一注入、主锚词钉死单一字面值、`wire_fault` 38 值三方同序），补 login 缺字段族全分支；**C-05** 新增正例 24 `xmrmining_port_nondefault`（3333，端口不进行内容、行字节与用例 1 一致，无 dissector 无 DecodeAs 依赖）；**C-06** pcap/NIC 双输出契约声明补入（§1）；**C-07** 并发会话翻案纳入（§5 措辞修正 + 正例 25，"单 TCP 流串行"仅能否定多流）；**N-01** 用例 4 公式 +8→+11；**N-02** RST/保活显式不适用声明（§4⑤⑥/§8）。负例编号 24–33 → 26–63。审查由撰写者执行，待独立复验关闭。

- v1.0.0（2026-08-21）：旧稿首版（14 正 + 6 负）——**协议定位模糊**：按"CryptoNote/Monero 矿池 Stratum-like/JSON-RPC 混合"定义，login/getjob/submit/keepalived 方法与服务端 job 通知方向无权威规范出处；未钉死通知省略 id 与 id:null 的差异、blob nonce 偏移/上界/字节序、target 两态、seed_hash 恒 64 hex；无 fixture 常量与行长公式；错误分支锚词与用例集含臆造值。
- v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-21 旧稿（旧稿见 git 历史）。以 **xmrig/xmrig-proxy STRATUM.md（官方规范）** 为唯一成文基线，XMRig 源码与 MoneroOcean 现网形态佐证，逐条重新提炼：行式 JSON（LF 边界、紧凑形态、成员顺序钉死）、5 类方法（login/job/submit/keepalived/getjob）、对象 params、通知省略 id、会话 id 回带关联、blob nonce 偏移 39/4B 小端/上界 408B、target 4/8B、seed_hash 恰 64、keepalived 别名与 KEEPALIVED 状态、getjob 主动拉取；与 75-stratum（比特币）/76-getwork（daemon HTTP RPC）/block_template（自选模板）区分钉死不混装。fixture 全部常量取 spec verbatim（钱包 95 字符/会话 id `1be0b7b6-…`/blob 两例/`job_id` 两例/target `b88d0600`/nonce `d0030040`/result 32B/错误文案），现代 job 对象取 mo-pool `buildStandardJobPayload` 形态。用例按 v1.1 原子原则从 20 条重排为 **33 条（23 正 + 10 负）**——每消息类型、每响应态、每形态变体、每长度边界、每关联规则、每错误分支各一例；新增 §4 业务场景分析（五层逐层、流关联与多流显式不适用声明）、§5 状态机与事务模型（自动派生规则）、§6 JSON 配置 typedef 与配置到帧路径、§3.8 行长公式表（脚本核验）；端口 18081、keepalived jsonrpc 形态、getjob result 形态按"公开资料 + 假设，实现阶段实证校准"标注；以本机 tshark 3.6.14 构造 pcap 实证（无 XMR 专用 dissector、`tcp.payload` 全行 hex/offset 54/74/行尾 0a、`json.*` 辅助字段）固化断言基线。状态：**待独立隔离审查**。

# #91 ethmining（EthereumStratum/1.0.0 ethash 矿池 stratum）设计契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3）
> 日期：2026-09-27
> 车道：A 文档轨（并发管线 lane A，#91 ethmining RESUME）
> 旧基线：`docs/protocol-designs/73-ethmining-design.md` v2.0.2 + `73-ethmining-testcase.md` v2.0.2（32 例 = 22 正 + 10 负；本 #91 为 P-PIPE 重做思路参考、不搬码——旧稿"尚未实现"状态已过时，见 §14 G-EM-1）
> 存量用例：`trafficgen/test/protocol_pcap/cases/ethmining.json`（32/32 ID 与旧稿 §8 一致，顺序一致，已实测）
> 规范基线：① NiceHash《Ethereum stratum mining protocol v1.0.0》R2（github.com/nicehash/Specifications `EthereumStratum_NiceHash_v1.0.0.txt`，下称 **spec**，§I–§V）；② NiceHash《extranonce subscribe extension》（同仓，下称 **ext**）；③ 以太坊 ethash 公开资料（seedhash/headerhash 32 字节、nonce 全宽 8 字节、difficulty→target 换算同比特币）；④ 公开资料 + 假设（端口 4444、`0x` 前缀方言、`"jsonrpc":"2.0"` 方言、授权拒绝 `[24,"Unauthorized user",null]`，逐处标注，实现阶段实证校准）；⑤ 本机 tshark 实测基线（旧稿 §1：无 dissector，断言走 `tcp.payload`/frames，offset 54/74）。
> 白话一句：**这是以太坊矿机连矿池要活干的那套行式对话，和比特币矿池那套同姓不同命——参数个数、长度规则全不一样，所以引擎里是两套独立接线，不是同一个东西加个开关。**

## 0. 主/dialect 判定（门1 必答：独立接线 vs stratum dialect 变体）

**裁定：ethmining = 独立接线（independent terminal layer），不是 stratum 的 dialect 变体。** kingbase #35 先例的"退役收敛"五条实测依据在此全部反向不成立，逐条如下（证据均为仓库实测行号，2026-09-27 HEAD）：

| # | kingbase 退役依据 | ethmining 对照实测 | 结论 |
|---|---|---|---|
| 1 | registry 唯一注册（postgresql 一层，kingbase 无独立层） | `registry.go:530-533` 注册 `stratum`（FieldContract `tcp.dst_port:3333`）**与** `registry.go:540-543` 注册 `ethmining`（FieldContract `tcp.dst_port:4444`）——**两个独立 LayerSchema**，各有独立注释块与端口契约 | 独立层 |
| 2 | cases 全 `proto:"postgresql"`（CASE_PROTO=kingbase 装载 0 例） | `cases/ethmining.json` 32 例全 `proto:"ethmining"`；`cases/stratum.json` 40 例全 `proto:"stratum"`——各自装载，无交叉 | 独立身份 |
| 3 | `dialectFieldContract` 改契约值常量（变体只改常量） | `grep dialect internal/protocol/ethmining/*.go internal/protocol/stratum/*.go`（除注释行"dialect"字样互斥说明外）**无 dialect 字段、无 dialect 分支**；registry 的 `dialectFieldContract`（`registry.go:1852`）只服务 postgresql/kingbase，无 ethmining/stratum 条目 | 无 dialect 机制 |
| 4 | kingbase 包不存在（零残留） | `internal/protocol/ethmining/{builder.go(213行),planner.go(334行),layer_gen.go(309行)}` 与 `internal/protocol/stratum/{builder.go(319行),planner.go(307行),layer_gen.go(370行)}` **两套完整文件**；双向 `grep protocol/stratum internal/protocol/ethmining/` 与反向**零命中**（零共享代码、零交叉导入） | 独立实现 |
| 5 | 测试面认同一层双 dialect | `generator.go:543 Stratum *core.StratumConfig` 与 `:547 ETHMining *core.ETHMiningConfig` 两个独立 FlowSpec 槽位；`chain_planner_translate.go:193` 与 `:197` 两条独立直传分支；`protocols.go:77 "stratum"` 与 `:80 "ethmining"` 两个独立准入；`main.go:179` 与 `:182` 两个独立空导入；`RegisterLayerGenerator("stratum")` 与 `("ethmining")` 两个独立生成器注册 | 独立接线九件齐 |

**线语法互斥证据（决定性）**：两 planner 互相拒绝对方形态——`internal/protocol/ethmining/planner.go:161-164` 拒绝比特币 2 元素 `set_extranonce [en,size]`（"2-element form is the bitcoin stratum dialect"）；`internal/protocol/stratum/planner.go:124` 拒绝 ethash 1 元素形态（"1-element form is the ethash dialect"）。共享 dialect 层不可能出现双向拒绝；这是两套文法的铁证。

**三方区分表**（旧稿设计 §3.10，本版继承）：notify 参数 4 元素（job_id/seedhash/headerhash/clean_jobs）vs 比特币 9 元素（含 coinb1/coinb2/merkle）；submit 3 元素（worker/job_id/minernonce）vs 5 元素；extranonce 单段 ≤3 字节 + minernonce 互补恒 8B vs 双段 extranonce1+extranonce2；载体同为 TCP 行式但端口 4444 vs 3333；GetWork（76）更是 `[ip,tcp,http,getwork]` 链（HTTP 8332），连载体都不同。

**依赖链判定纪律**：以上均为可判题（标准→设计→代码三级一致），直接判定，不问偏好。不可判的（G-EM-2 现网矿池方言实证）标"待确认"并写清确认方式。

## 1. 范围、profile 与实现状态边界

本版定义矿机（miner）与矿池（pool）之间的 **ethash stratum 明文 TCP 长连接**：行分隔 JSON（每行一个 JSON 对象，行尾单个 LF `0x0a`）消息封装、订阅（`mining.subscribe`）、extranonce 订阅扩展（`mining.extranonce.subscribe`）、授权（`mining.authorize`）、难度通知（`mining.set_difficulty`）、任务通知（`mining.notify`）、extranonce 轮换（`mining.set_extranonce`）、share 提交（`mining.submit`）与提交响应三态、JSON-RPC `id` 关联、IPv4/IPv6、多会话与多事务。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `ethmining_stratum_v1`（主） | TCP 明文行式 JSON（fixture 4444，可配置覆盖） | spec 全部 7 类消息 + ext 扩展、行重组、id 关联、share 三态 | 真实 share 有效性、区块产生、真实鉴权、难度与 target 对应关系 |
| `ethmining_ipv6_v1` | 同上，仅外层 IPv6 | 同主 profile | 从 IPv4 fixture 推导 IPv6 地址 |
| `ethmining_hex_prefix_v1` | 同主 profile，hex 字段带 `0x` | 会话内前缀统一的方言变体（由 `hex_prefix:"0x"` 选择，非独立层链） | 混合前缀（进负例） |

显式边界（"不实现、不声称、不许静默转换"）：EthereumStratum/2.0.0 草案不在本版；比特币 stratum 专用消息（`client.get_version`、`mining.configure`、9 参数 notify、5 参数 submit）不在本版——属 75-stratum；GetWork 轮询（`eth_getWork` 等 4 方法）不在本版——属 76-getwork，planner 对混入按未知 method 拒绝；不声称任何 share 满足真实 ethash target（生成器不执行 PoW，share 为 fixture 声明值）。

**实现状态（2026-09-27 实测，与旧稿"尚未实现"已不同）**：`ethmining` 层已注册（registry.go:540-543）、planner/validator/生成器已落码（`internal/protocol/ethmining/` 三文件 + `internal/core/ethmining.go` 配置类型）、`allowedProtocols["ethmining"]=true`（protocols.go:78-80）、32 语义用例已落 `cases/ethmining.json`（占位已替换，无 `unregistered` 残留）。旧稿"当前 JSON 仅含占位"描述已过时（G-EM-1 注记）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.payload` 全行 hex、`tcp.len`、`tcp.stream`、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, ethmining]`（引擎自动补 `ip`；最小链 `[tcp, ethmining]`）。ethash stratum 报文是 TCP payload 的**行式字节流内容**——**无消息长度前缀、无记录头，消息边界只由 JSON 文本后的单个 LF（`0x0a`）决定**（spec §III 全部示例行尾 `\n`；私有长度前缀进负例）。

端口：主流 ethash 矿池 stratum 接入端口 **4444**（④ 标注；NiceHash Ethash 挂 3353、部分矿池挂 14444——端口不是协议识别证据，可配置覆盖，planner 不得静默改写）。fixture 统一 `dst_port=4444`；**非默认端口显式声明即合法通道**——正例 `ethmining_custom_port` 行使 3353（端口不进 stratum 行内容，行字节与基线一致）；未显式声明的非 4444 端口拒绝（负例 `ethmining_neg_carrier`）。

固定偏移：无 VLAN/IP options/TCP options 时，**每条 stratum 行首字节（`{`=`0x7b`）起点为 IPv4 offset 54（14+20+20）、IPv6 offset 74**（14+40+20）。**TCP 分段边界不是 stratum 行边界**：一段可含半行（跨 MSS）、整行或多行粘连（行界由 `0a` 定界），接收端按 LF 循环取行重组。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers` + `flow_control`）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.73", "dst": "198.51.100.73"}},
    {"tcp": {"src_port": 4073, "dst_port": 4444}},
    {"ethmining": {"sessions": [
      {"src_port": 4073, "dst_port": 4444, "events": [
        {"kind": "subscribe", "id": 1, "user_agent": "MinerName/1.0.0",
         "protocol": "EthereumStratum/1.0.0",
         "subscription_id": "ae6812eb4cd7735a302a8a9dd95cf71f", "extranonce": "080c"},
        {"kind": "authorize", "id": 2, "username": "test", "password": "password", "result": true},
        {"kind": "set_difficulty", "difficulty": 0.5},
        {"kind": "notify", "job_id": "bf0488aa",
         "seed_hash": "abad8f99f3918bf903c6a909d9bbc0fdfa5a2f4b9cb1196175ec825c6610126c",
         "header_hash": "645cf20198c2f3861e947d4f67e3ab63b7b2e24dcc9095bd9123e7b33371f6cc",
         "clean_jobs": false},
        {"kind": "submit", "id": 3, "username": "test", "job_id": "bf0488aa",
         "miner_nonce": "6a909d9bbc0f", "result": true}
      ]}
    ]}}
  ],
  "flow_control": {"flows": 1}
}
```

## 3. 线格式编码（逐项标注出处）

### 3.1 行式组帧与 JSON 序列化规则

- **消息边界**：每行 = 一个完整 JSON 对象 + 行尾单个 LF。行内不得出现未转义控制字符；CR 不属于本协议（CRLF 进负例，spec 示例统一裸 LF）。
- **JSON 形态**：线上字节钉死为**紧凑形态**（成员间无空格）；成员顺序钉死——请求/通知 `id,method,params`，响应 `id,result,error`（spec 全部示例顺序）。
- **`id` 取材与配对**：请求 `id` 为 JSON number，**由矿机迭代、会话内唯一、起点任意**（spec §III）；矿池响应必须按 `id` 值配对，不得按 TCP 位置配对。通知 `id` 恒 `null`，伪 id 进负例。
- **响应形状**：`{"id":<同值>,"result":<载荷或 false>,"error":<null 或三元组>}`。错误三元组 = `[code 数值, message 字符串, data|null]`（spec §III `[-1,"Job not found",null]`；ext 不支持路径 `[20,"Not supported.",null]`）。
- **hex 字段编码**：全部 hex 数据字段为 ASCII 十六进制字符串，**默认无 `0x` 前缀**（spec §I.4）；字符集 `0-9a-f`，偶数长度。`hex_prefix:"0x"` 声明方言变体（④ 标注），**同一会话内前缀必须统一**，混用进负例。
- **difficulty 序列化**：JSON number，**钉死十进制定点**（`0.5`/`5000012.0`），**禁止科学计数法**。
- **行长公式**：`L(line) = <固定常量> + Σ len(可变字段)`（+1 LF），逐消息常量见 §3.11；无协议级行长上界（job_id "HEX number of any size"，spec §III）。
- **行-段映射（pack 条款）**：默认**每行一段**；`pack` 开启后**相邻同方向行合并为单一 TCP 段**，方向交替处不合并；`pack:false` 恢复每行一段。

### 3.2 消息总表（方法 / 方向 / params / 应答，出处 spec §III/§IV，ext 全文）

| 消息 | 方向 | id | params（位置语义） | 应答 |
|---|---|---|---|---|
| `mining.subscribe` | 矿机→矿池 | number | 2 元素：[0] user agent，[1] `"EthereumStratum/1.0.0"`（矿池不支持可回错误或断开——自由裁量，本版 fixture 不产生） | 订阅响应（§3.3） |
| `mining.extranonce.subscribe` | 矿机→矿池 | number | 0 元素 `[]`（ext） | `result=true`（支持）或 `false+[20,"Not supported.",null]`（不支持，合法值域声明，fixture 取支持路径） |
| `mining.authorize` | 矿机→矿池 | number | 2 元素：[0] 用户名（账号[.矿机名]），[1] 密码 | `result=true` 或 `false+error`（§3.5） |
| `mining.set_difficulty` | 矿池→矿机 | `null` | 1 元素：[0] difficulty（double；1 ⇔ target `00000000ffff0000…00`，换算同比特币，spec §III） | 无 |
| `mining.notify` | 矿池→矿机 | `null` | 4 元素：[0] job_id（hex 任意长度），[1] seedhash（32B hex），[2] headerhash（32B hex），[3] clean_jobs（boolean；true ⇒ 清空队列、旧 job 后续提交按 stale 处理） | 无 |
| `mining.set_extranonce` | 矿池→矿机 | `null` | 1 元素：[0] 新 extranonce（hex ≤3B）；**仅在矿机已发 extranonce.subscribe 后发送**（ext）；对**后续** job 生效 | 无 |
| `mining.submit` | 矿机→矿池 | number | 3 元素：[0] 用户名，[1] job_id，[2] minernonce（hex，**字节数 = 8 − extranonce 字节数**） | 提交响应三态（§3.9） |

**方向违例**：矿机发通知、矿池发请求均为错，进负例（锚 `method`/`direction`）。

### 3.3–3.9 消息细则（承旧稿 §3.3–§3.9，全量有效；fixture 常量见 testcase §3）

- **subscribe 响应**：`result=[[["mining.notify",<订阅标识>,"EthereumStratum/1.0.0"]],<extranonce>]`；`result[1]` **extranonce ≤3 字节**（spec §III 上界；1B 合法，本版 fixture 取 2B/3B 两态）；协议串不一致时矿机应终止连接（fixture 恒一致）。
- **extranonce.subscribe**：请求 `params:[]`；矿池也可能忽略不回包或断开（ext 明示现实行为，fixture 恒回包）。
- **authorize**：`authorize 必须发生在初始握手期内、submit 之前`（spec §III）；拒绝码 `[24,"Unauthorized user",null]` 为标准 stratum 惯例 fixture 值（④ 标注）；用户名/密码 ASCII，无规范长度上界（现网 ETH 地址 + `.矿机名`，68 字符长用户名正例承载）。
- **set_difficulty**：① 首条 job 前 MUST 发送；② 未发时按难度 1 兜底（两种线序均合法——缺省线序正例承载）；③ 变更只对后续 job 生效；④ double（0.5 spec 最小示例 / 5000012.0 大值）。**兜底 1.0 不上线**（矿机侧推断值，pcap 不断言字面值，只断言 set_difficulty 行缺席）。
- **notify**：seedhash 32B（每 30,000 块一 epoch，多币切换逐 job 重发）；job_id 为 submit 关联键。
- **set_extranonce**：钉死 ethash **1 元素形态**；比特币 2 元素形态为方言（进负例锚 `params`；planner.go:161-164）。
- **submit 响应三态**：接受 `result=true`；拒绝 `result=false+[-1,"Job not found",null]`（会话继续）；其他错误三元组结构完整、会话继续（fixture 不产生非"Job not found"码，声明）。

### 3.11 每消息行长公式汇总（固定常量经脚本对 fixture 核验，旧稿 §3.11 全量继承）

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

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式脚本化回放**——配置是剧本（sessions[]/events[] 逐条声明），引擎按序产出行帧；"事件驱动"仅用于 ① 自动应答（subscribe/authorize/extranonce.subscribe/submit 后自动补同 `id` 响应行）② 连接边界（源端口切换触发新 TCP 连接）。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 矿机接入 | TCP→subscribe→订阅响应→authorize→授权响应 | 1、2、3 |
| ② 鉴权拒绝 | authorize→`result=false+error`（合法路径） | 4 |
| ③ 收任务 | set_difficulty→notify（clean=false 增量 / true 清队列） | 5、6、7、8、9 |
| ④ share 提交 | submit→响应 true/false（会话均继续） | 11、12 |
| ⑤ extranonce 轮换 | extranonce.subscribe→set_extranonce→后续 job/submit 用新值 | 10 |
| ⑥ 多矿机并发 | 多会话展开，各会话独立 extranonce/难度/job/id | 20 |
| ⑦ 完整生命周期 | 接入→收任务→提交→新任务→再提交（单连接多事务） | 21 |

**五层覆盖逐层结论**：功能层——7 类消息 + 1 扩展每类正例，拒绝路径以正例承载，错误分支 10 类负例；性能层——大 job_id 跨 MSS（1691B/2段）、粘连单段（259B 两行）、最小行边界（响应 36B / 通知 60B）；数据场景层——difficulty 三态、extranonce 2B/3B、minernonce 互补、job_id 任意长度、clean 二值、id 任意起点、0x 方言、hex 字符集、长用户名；地址与流层——v4/v6 独立 fixture、单流基线、多会话双四元组、非默认端口 3353；**流关联（控制流派生数据流）显式不适用**：单 TCP 长连接，无副连接（spec 全文仅此一条连接）；**多流（会话内并发流）显式不适用**：单连接串行收发。业务层——接入-收任务-提交链（spec §IV 即此链路）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① 矿池对不支持协议版本的回错误/断开（fixture 恒一致）；② extranonce.subscribe 不支持路径（validator 仅校验三元组形态）；③ 矿池忽略 extranonce.subscribe 不回包；④ 非"Job not found"的 submit 错误码；⑤ notify 先于 authorize 的线序（validator 不约束）；⑥ 重连会话重置语义（各会话恒全新握手；会话内 close 后排事件仍为负例）；⑦ clean=true 后旧 job 的 stale 拒绝路径；⑧ 缺省难度线序下的 submit 组合（不设组合例）；⑨ **无保活/重试消息**（spec/ext 无 PING 类机制）；⑩ **RST 异常中断为框架 tcp 层能力**（本协议层零断言零 ID，正例恒 FIN）。

## 5. 消息/事务模型与状态机

**事务定义**：同一 TCP 连接内一次完整的请求/响应交互，关联标识为 `id`（响应同值回带）。**多事务** = 一连接内多笔事务按序执行且有先后依赖：**subscribe 首条**；**authorize 先于 submit**（submit 用户名 = 已授权用户名）；**submit job_id ∈ 本会话已收 notify**；**set_difficulty 先于首条 notify**（缺省兜底为例外）。

矿机侧会话状态机（确定性；非法事件必须拒绝报状态机错误，不得静默产出）：

| 状态 | 允许事件（→目标） | 必须保持 |
|---|---|---|
| `Disconnected` | TCP 握手（→`TransportReady`） | 首条应用消息必须是 subscribe |
| `TransportReady` | 发 subscribe（→`Subscribing`） | params[1] = `EthereumStratum/1.0.0` |
| `Subscribing` | 收订阅响应（→`Subscribed`） | 响应 id 同值；extranonce ≤3B 并记为当前值 |
| `Subscribed` | 发 authorize（→`Authorizing`）；可选 extranonce.subscribe+响应（保持，须在首条 set_extranonce 之前，fixture 取 authorize 之前） | 用户名/密码非空 |
| `Authorizing` | 响应 true（→`Authorized`）；false（→`AuthorizedRejected`） | 响应 id 同值 |
| `AuthorizedRejected` | TCP FIN（→`Closed`） | 拒绝后不得发 submit |
| `Authorized` | 收 set_difficulty/notify/set_extranonce（保持）；发 submit→收响应（保持）；FIN（→`Closed`） | 用户名一致；job_id ∈ 已收集合；minernonce = 8 − 当前 extranonce；set_extranonce 更新当前值（作用域后续 job） |
| `Closed` | — | 关闭后不得产生新行 |

**自动派生规则**：① subscribe 后自动补同 `id` 响应行；② extranonce.subscribe 后补 `result=true`；③ authorize 后按 `result` 补 true/false+三元组；④ submit 后按 `result` 补 true/false+三元组；⑤ TCP 握手/FIN 由 tcp 层自动补（源端口切换触发新连接）。

**多会话展开**：`sessions[]` 按序整块回放（先跑完会话 1 全流程再跑会话 2，不交错）；**第二会话包号起点 = 前一会话总包数 + 1**。各会话四元组/id/extranonce/难度/job/用户名互不串用。`concurrent:true` 为生成器例外路径本版不启用——多矿机并发语义由顺序多会话展开承载。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单会话全链 ≤18 包（含握手挥手）；大 job_id 行 1691B 跨 2 段为最大单行压力；多会话 2 会话 30 包整块展开。吞吐数字待 P4 基准，**本版不写承诺**（§6.5）。
- **依据**：事件序列流式展开为行（planner 行序列，无全量收集）；每行内存 = 行长 + TCP 段开销（O(行)）；跨会话状态（当前 extranonce/难度/job 集合/用户名）为 per-session 局部，无跨会话共享；pack 合并仅同方向相邻行（§3.1），不改变总字节。
- **验收两路**：pcap（`/tmp/mcp-pcaps/ethmining/`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `tcp.len` 序列与行 hex，不只断言"任务没报错"。
- **六类场景落点**：基线（用例 1，9 包）/ 目标规模（用例 21，18 包全链）/ 压力上限（用例 18，1691B 跨段）/ 长时间运行（多会话展开，用例 20）/ 并发交错（顺序展开承载语义，并发路径为例外不启用）/ 背压（259B 粘连段 + MSS 分段，接收端按 LF 重组）。

## 7. 错误处理（负例锚词表，与 testcase §5 一一对应、同序）

以下输入必须由 planner/validator 拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功：

| # | 负例 ID | 故障输入 | `error_contains` 候选锚词 |
|---:|---|---|---|
| 23 | `ethmining_neg_json` | 截断对象、未闭合字符串、非对象行 | `json`、`decode`、`line` |
| 24 | `ethmining_neg_framing` | 无 LF 裸结束、CRLF、私有长度前缀 | `newline`、`framing`、`line` |
| 25 | `ethmining_neg_method` | 未知 method（含 `eth_getWork` 混入）、方向违例 | `method`、`unknown`、`direction` |
| 26 | `ethmining_neg_params` | 元素数量/类型/位置错、set_extranonce 2 元素方言混入 | `params`、`field`、`type` |
| 27 | `ethmining_neg_hex` | 非 64 hex、非 hex 字符、>3B 上界、互补违例、奇数长度、前缀混用 | `hex`、`length`、`extranonce`、`prefix` |
| 28 | `ethmining_neg_state` | 首条非 subscribe、未授权先 submit、关闭后续排 | `state`、`sequence`、`subscribe` |
| 29 | `ethmining_neg_id_correlation` | 响应 id 不匹配、通知伪 id、同会话 id 重复 | `id`、`match`、`correlation` |
| 30 | `ethmining_neg_job_correlation` | job_id 非本会话 notify、用户名与授权不一致 | `job`、`worker`、`correlation` |
| 31 | `ethmining_neg_carrier` | 层链缺 tcp、UDP 载体、端口矛盾、混合地址族 | `carrier`、`tcp`、`port`、`ip`、`version` |
| 32 | `ethmining_neg_error_propagation` | 已知错误被吞、假成功、0 包 | `error`、`propagat`、`task`（三选一候选集，实现期钉死其一） |

**负例原子性**：各行故障输入为互斥候选集——每个负例 ID 实现期选定其一钉死注入并同步两文档；单次执行不得混注；全量覆盖按 §7 原子原则拆子 ID。

**不得误报的合法协议事件**：submit/authorize 拒绝、难度缺省/变更、extranonce 轮换、不支持响应、`0x` 统一变体、大 job_id 均为正例形态。

## 8. 边界

- **行长与分段**：notify = `58 + len(job_id) + 64 + 64 + len(clean 串)`；大 job_id（1500 hex ⇒ 1691B）跨 2 段（1460+231），重组后断言完整行；行内无 `0x0a` 是 JSON 文本保证。
- **多行粘连**：set_difficulty(60B)+notify(199B)=259B 一段，段内恰 2 个 `0a`；段边界 ≠ 行边界双向断言。
- **extranonce 宽度带**：≤3B；基线 2B ⇒ minernonce 6B，满值 3B ⇒ 5B；1B 合法（validator 按互补公式支持，fixture 取 2B/3B 两态）；>3B 进负例；0 长度无规范示例不使用。**全 nonce 恒 8B**硬校验。
- **difficulty**：double >0；0.5 / 5000012.0 / 缺省 1.0（不线上不断言字面）；禁科学计数法。
- **id 域**：number，起点任意，会话内唯一；响应同值回带。
- **clean_jobs 二值**：各一正例；非布尔进负例。
- **0x 前缀**：会话内统一；混用进负例。
- **v4/v6**：独立 fixture，同一逻辑行字节一致，仅外层头与偏移（54/74）不同；IPv6 地址显式给出，不得推导。
- **多会话**：≥2 独立四元组，状态互不串用；第二会话起点 = 前会话总包数 + 1。
- **端口**：默认 4444；3353 显式声明合法；未声明的非 4444 拒绝；无 DecodeAs 依赖。
- **无保活/重试**（显式不适用）；**RST 为框架 tcp 层能力**（本层零断言）。
- 不得产生回绕长度或超量分配（大 job_id 显式声明，不隐式放大）。

## 9. 原子 ID 与完成定义（32 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 |
|---:|---|---|---|
| 1 | `ethmining_subscribe_ipv4` | 正 | §3.3：订阅全字段，IPv4 单流基线 |
| 2 | `ethmining_extranonce_subscribe` | 正 | §3.4：ext 请求 + `result=true` |
| 3 | `ethmining_authorize` | 正 | §3.5：授权请求/成功响应 |
| 4 | `ethmining_authorize_reject` | 正 | §3.5：`result=false+error[24]` 拒绝路径 |
| 5 | `ethmining_notify_job` | 正 | §3.7：notify 四元素（clean=false） |
| 6 | `ethmining_notify_clean_jobs` | 正 | §3.7：clean=true 变体 |
| 7 | `ethmining_set_difficulty` | 正 | §3.6：难度通知（最小通知行 60B） |
| 8 | `ethmining_set_difficulty_default` | 正 | §3.6：缺省兜底线序 |
| 9 | `ethmining_set_difficulty_update` | 正 | §3.6：会话中难度变更 |
| 10 | `ethmining_set_extranonce` | 正 | §3.8/§3.9：轮换 2B→3B + 互补 |
| 11 | `ethmining_submit_accept` | 正 | §3.9：submit + `result=true` |
| 12 | `ethmining_submit_reject` | 正 | §3.9：submit + `result=false+[-1]`（会话继续） |
| 13 | `ethmining_id_correlation` | 正 | §3.1/§5：id 任意起点、按值配对 |
| 14 | `ethmining_extranonce_max3` | 正 | §3.3/§8：3B 满值 + 5B 互补 |
| 15 | `ethmining_hex_prefix` | 正 | §1/§3.1：`0x` 方言变体 |
| 16 | `ethmining_long_username` | 正 | §3.5/§8：68 字符长用户名同值 |
| 17 | `ethmining_line_packing` | 正 | §2/§8：粘连单段 259B |
| 18 | `ethmining_mss_large_jobid` | 正 | §3.11/§8：1691B 跨段重组 |
| 19 | `ethmining_ipv6` | 正 | §2/§8：IPv6 独立 fixture |
| 20 | `ethmining_multi_session` | 正 | §5/§8：双会话展开 |
| 21 | `ethmining_mining_lifecycle` | 正 | §4⑦/§5：单会话多事务全链 |
| 22 | `ethmining_custom_port` | 正 | §2：3353 显式合法通道 |
| 23 | `ethmining_neg_json` | 负 | §7：非法 JSON |
| 24 | `ethmining_neg_framing` | 负 | §7：组帧错 |
| 25 | `ethmining_neg_method` | 负 | §7：未知 method/方向违例 |
| 26 | `ethmining_neg_params` | 负 | §7：params 错 |
| 27 | `ethmining_neg_hex` | 负 | §7：hex 违例 |
| 28 | `ethmining_neg_state` | 负 | §7：状态机错 |
| 29 | `ethmining_neg_id_correlation` | 负 | §7：id 关联错 |
| 30 | `ethmining_neg_job_correlation` | 负 | §7：job 关联错 |
| 31 | `ethmining_neg_carrier` | 负 | §7：载体错 |
| 32 | `ethmining_neg_error_propagation` | 负 | §7：错误未传播 |

完成定义：`tcp→ethmining` 层链注册已落码；§3 全部 7 类消息 + ext 扩展逐字段生成验证；订阅/授权/难度（含缺省与变更）/任务（clean 二值）/轮换/提交三态、id 关联、多事务、多会话、v4/v6、MSS 分段与粘连重组、全部边界可观测；32 ID 正负断言与错误传播完成；不声称真实 PoW。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | TCP 明文长连接，矿机主动建连，单连接无副流（spec §III） | 场景①–⑦ | `DependsOn ["tcp"]` 单值（registry.go:541-542）；多会话整块展开（planner） | 无 |
| 2 | 命令/消息表 | 7 类 + ext（§3.2 表全覆盖，spec §III/§IV + ext 全文） | 场景①–⑤ | builder/planner 已落码（三文件 856 行） | 无（fixture 不产生的自由裁量路径走 §4 声明） |
| 3 | 状态机 | 建连—业务—释放 8 状态（§5 表） | 全链用例 21 | planner 状态机已落码（含 set_extranonce 前提校验） | 无 |
| 4 | 字段表 | 每字段取值/长度/字节序/缺省（§3.3–§3.9 + §3.11 公式） | 数据场景层 | builder 紧凑序列化 + 定点 difficulty + 互补校验 | 无 |
| 5 | 错误处理 | 三元组形态 + 10 类负例（§7 表） | 负例 23–32 | planner 10 种 wire_fault 拒绝分支 | 锚词钉死 1 处（负例 32 三选一候选集）→ G-EM-3 |
| 6 | 超时与活性 | spec/ext 无保活/重试语义（长连接由周期 notify 维持） | — | 协议层无（框架 tcp 层能力） | **显式不适用**（§4⑨⑩），无缺口 |
| 7 | NAT/代理/被动 | 无被动模式概念（单连接直连） | 多会话双四元组 | sessions[].src_port 独立四元组 | **显式不适用**被动模式；NAT 穿透为框架面 |
| 8 | 版本/方言 | EthereumStratum/1.0.0 唯一版本；`0x` 方言；比特币/GetWork 互斥 | 正例 15 / 负例 25 | hex_prefix 配置 + 双向方言拒绝（两 planner） | 现网矿池方言实证 → G-EM-2 |

### 10.2 子表①：消息×响应态矩阵（逐格已覆/缺失/不适用）

| 消息 | 成功态 | 拒绝/变体态 | 时序变体 | 覆盖结论 |
|---|---|---|---|---|
| subscribe | 响应 extranonce（用例 1） | —（协议串不一致→断开，自由裁量声明） | 首条强制（负例 28） | 已覆 |
| extranonce.subscribe | `result=true`（用例 2） | `false+[20]` 不支持路径（声明，不设例） | 须先于 set_extranonce（用例 10） | 已覆 + 1 声明 |
| authorize | `result=true`（用例 3） | `false+[24]`（用例 4） | 先于 submit（负例 28） | 已覆 |
| set_difficulty | 0.5（用例 7） | 缺省兜底（用例 8）/ 变更（用例 9）/ 大值（用例 9） | 先于首 notify（MUST，缺省为例外） | 已覆 |
| notify | clean=false（用例 5） | clean=true（用例 6） | 难度先行 / 缺省线序 | 已覆 |
| set_extranonce | 轮换（用例 10） | 2 元素方言混入（负例 26） | 对后续 job 生效 | 已覆 |
| submit | `true`（用例 11） | `false+[-1]`（用例 12，会话继续） | job/用户名关联（负例 30） | 已覆 |

**逐格重数**：7 行 × 3 列 = 21 格——已覆 18 / 声明（自由裁量不设例）3，零空格。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **19 行**：行边界（LF/CRLF/长度前缀/无 LF）/ JSON 形态（紧凑/截断/非对象）/ id（任意起点/伪 id/重复/错配）/ extranonce（2B/3B/1B 合法/>3B/0 长度不用）/ minernonce（6B/5B/互补违例/奇数）/ hex 前缀（无/统一 `0x`/混用）/ difficulty（0.5/大值/缺省/科学计数法禁）/ job_id（8 hex/1500 hex/非 hex）/ seedhash-headerhash（64 hex/62 hex）/ clean（二值/非布尔）/ 用户名（短/68 字符/不一致）/ 密码（两元素/单参）/ 方向（7 种违例）/ 方法（未知/GetWork 混入/比特币方言）/ 地址族（v4/v6/混合）/ 端口（4444/3353/未声明非默认）/ 分段（单段/粘连/跨 MSS）/ 会话（单/双/同值 id 跨会话）/ 载体（缺 tcp/UDP/直连）——每行均有正例或负例落点（§9/§7）。

### 10.4 候选方案对比（三路对照 §4.12–4.15 内含）

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `ethmining` 终结层（本版；stratum B6 同构先例 `internal/protocol/stratum/`） | 线文法独立、端口独立、事件字段独立；代价 = 一套新 builder/planner（856 行，已落码） | **采用** |
| B | stratum 层加 `dialect:"ethmining"`（kingbase/postgresql 先例 registry.go:645-660） | 要求线文法可由常量切换；但 notify 4 vs 9 参、submit 3 vs 5 参、set_extranonce 1 vs 2 元素是**结构差异**，常量切换不可表达；双向拒绝证明语义不兼容 | **否决**（§0 实测五条） |
| C | 与 getwork 合并为"以太坊族"（旧稿 v1.0 定位：HTTP 8545） | 载体都不同（TCP 行式 vs HTTP）；旧稿已废弃，git 历史可查 | **否决** |

三路一致点：行式组帧、无 dissector、`tcp.payload` 断言通道（ethmining/stratum/xmrmining 三 stratum 系一致）；不一致点 = 文法结构（上表），取舍：线字节以 NiceHash spec 为准，断言通道以 tshark 实测为准。

### 10.5 裁定 EM-A：独立接线（主层关系）

**ethmining 与 stratum 为两个独立主协议层**（§0 五条实测依据）。`dialect` 一词在本协议仅出现在"比特币方言混入拒绝"文案中（planner.go:161-164），不是配置机制。

## 11. P2 D-ETHMINING-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 状态说明：实现已落码（b7ab0ce），本 P2 条目为 P-PIPE 文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口；P4 在本协议内为"缺口收敛"（§14），不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/ethmining.go` | `ETHMiningConfig/Session/Event` 配置类型 | 92 |
| `trafficgen/internal/protocol/ethmining/builder.go` | 行序列化 + fixture 常量 + 紧凑 JSON | 213 |
| `trafficgen/internal/protocol/ethmining/planner.go` | 10 种 wire_fault 校验 + 状态机 + 关联检查 | 334 |
| `trafficgen/internal/protocol/ethmining/layer_gen.go` | 终结层生成器注册（`RegisterLayerGenerator("ethmining")`）+ validator 注册 | 309 |
| `trafficgen/internal/protocol/ethmining/ethmining_test.go` | 行 hex 基线单测 | 144 |
| 接线 6 件 | registry 注册 / FlowSpec 槽位（generator.go:547）/ translate 直传（:197）/ convert 子配置搬运（strategy_convert.go:631-635）/ protocols 准入（protocols.go:80）/ main 空导入（main.go:182） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（planner.go:18）：cfg==nil（空层）通过（默认基线会话）；否则 hex_prefix 白名单 → wire_fault 分派 → 事件序列状态机 + 关联完整性。
- 生成器：`Name() "ethmining"`；`EmitEvent` 经 `GenRequest.EmitMsg`（stratum 同构）。
- `spec.ETHMining` 经 `chain_planner_translate.go:197 ETHMining: spec.ETHMining` Meta 直传（事件字段自动搬运，无须逐字段取码）。

### 11.3 数据结构

`ETHMiningConfig{Profile, HexPrefix, Sessions[], WireFault}`；`ETHMiningSession{SrcPort, DstPort, Events[]}`；`ETHMiningEvent{Kind, PackNext, ID(json.RawMessage), UserAgent/Protocol/SubscriptionID/Extranonce, Username/Password/JobID/MinerNonce, Result/ErrorCode/ErrorMsg, Difficulty, SeedHash/HeaderHash/CleanJobs, NewExtranonce}`（core/ethmining.go 全量）。

### 11.4 主流程

配置 → validator（层链/端口/事件序/id 唯一/hex 值域与前缀统一/长度互补/关联完整性）→ planner（事件展开为行序列，紧凑 JSON + LF，§3.11 行长）→ worker（TCP 分段：默认每行一段，>MSS 自动分段；pack 合并同方向相邻行）→ writer（PCAP/NIC）。

### 11.5 错误分支

10 种 wire_fault 注入各对应 planner 拒绝分支（§7 表）；全部Loader为 task error（零假成功——负例 32 守卫）。互补公式 `len(minernonce) == 8 − len(extranonce)` 硬校验；`hex_prefix` 非 `""`/`"0x"` 拒绝；2 元素 set_extranonce 拒绝（方言门）。

### 11.6 性能边界

见 §6（逐事件流式、per-session 局部状态、无跨会话共享、无锁；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- stratum 共存：两层独立注册、独立端口契约（3333 vs 4444），无冲突；跨方言混入由双方 planner 双向拒绝（§0）。
- `CheckProtoFlat`（strategy_convert.go:8322 起）**无 ethmining/stratum/getwork 分支**（实测 grep 零命中）：顶层 `ethmining` 子映射 presence 不判死——与 D-NTLM-1 等已登记协议不同，属缺口 G-EM-4（禁加单协议黑名单分支，等框架级 unknown-key 白名单；kingbase 记忆裁定）。
- 动态 allowlist（layer_dyn.go:17 起）：`ethmining`/`stratum` 业务键均未登记（grep 零命中）→ 业务字段动态对象即拒；四元组 `ip`/`tcp` 全开。见 §12.12。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 4 文件 + 接线 6 处（registry/protocols/main/generator/translate/convert）；不触及其他协议。cases 回滚 = 恢复 32 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 32/32 顶层 = `layers + src_ip/dst_ip/src_port/dst_port + ethmining`（旧扁平残留，P4 迁移）；目标形状见 §2 样例；presence 判死形状缺口 G-EM-4 | §12.1；`cases/ethmining.json` 实测 |
| §2 策略/任务 | 策略 = 单 ethmining 流量模板，自带 `flow_control`；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（终结层）/时间线。有长连接，不豁免 | §12.3 + §5 |
| §4 查规范 | NiceHash spec R2 + ext + ethash 公开资料 + tshark 实测；八项矩阵 + 子表①② | §10 |
| §5 依赖与错误 | `DependsOn ["tcp"]` 单值（registry.go:542）；FieldContract 4444；wire_fault 10 kind；失败传 task error | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待 P4 基准，不写承诺） | §6 |
| §7 三份文档 | `91-ethmining-{design,testcase}.md` v1.0.0（草稿层）+ D-ETHMINING-1（§11，门1 获批 = 定稿）+ T-ETHMINING（testcase §2，32 ID）+ 旧稿 73-* 为历史层 | 修订记录 |
| §8 设计先行 | P1–P3 先于 P4 缺口收敛；门1 获批 = D-ETHMINING-1 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = NiceHash spec/ext（§3 逐表注出处）+ D-ETHMINING-1（§11）+ 已确认现网行为（G-EM-2 未到抓包级，不冒充）；32 ID 逐项回指；存量 32 例审计去向 testcase §8 | `91-ethmining-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123 报告 §3）+ 收官隔离复审；红先绿后 | p123 报告 §3 |
| §11 白话 | 每阶段先行一句白话结论（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `ethmining` 已在 registry.go:540-543 注册（**不新增层**）；`allowedProtocols["ethmining"]=true`（protocols.go:80）；ChainPlanner 已接线；**若 P4 改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `tcp.payload` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/ethmining/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

- **存量实测**（2026-09-27 机读）：32/32 例顶层键 = `{layers, src_ip, dst_ip, src_port, dst_port, ethmining}`；层形 `[tcp,ethmining]` ×30（4444）+ ×1（3353）+ `[{ethmining}]` ×1（`ethmining_neg_carrier` 刻意坏配置）；22 正例 `expect` 只有 `{packet_count}`；10 负例 `expect` 只有 `{expect_error,error_contains}`（形状干净）。
- **旧键去向**：`src_ip`/`dst_ip` → `ip.src`/`ip.dst`；`src_port`/`dst_port` → `tcp.src_port`/`tcp.dst_port`（`sessions[]` 内 per-session 覆盖保留为层内事件面字段，非顶层）；顶层 `ethmining` 子映射 → `layers[]` 内 `{"ethmining":{...}}` 层配置；数量 → `flow_control`。样例见 §2（顶层仅 `layers`+`flow_control`）。
- **事件内字段**：`profile`（信息性，三值）/`result` 等事件面键住层内，不动。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"ethmining":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 ethmining 分支，实测）→ **P4 不建该负例**（建了会真绿 = 假通过）→ 缺口 G-EM-4 登记。② 白名单外游离键判死（`unknown field`，`layers/complete.go:293`）P4 建一条。③ 10 负例每条带锚词（已齐）。④ 收官自查「非负例顶层键 = 0」（P4 迁移后执行）。

### 12.3 §3 强制展开：五件套

会话表：`s1` 单会话全序（用例 21）/ `s2` 双会话整块展开（用例 20，各自 `sessions[].src_port`，起点规则 §5）；事务：`t1` 接入（subscribe→authorize）/ `t2` 收任务（set_difficulty→notify）/ `t3` 提交（submit→响应）/ `t4` 轮换（extranonce.subscribe→set_extranonce→后续 job）；每事务四件事（前置/触发/成功/失败）见 §5 状态机 + §4 场景表。关联关系：**无派生流**（诚实声明：单 TCP 长连接，无 `driven_by`；CancelRequest 类关联不适用）。插入位置：终结层（`[ip,tcp,ethmining]`，无中间层）。时间线：会内严格顺序 / 多会话整块（第二会话起点 = 前会话总包数 + 1）/ 无交错（`concurrent:true` 为例外路径不启用，语义由顺序展开承载）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst`、`tcp.src_port/dst_port` 五策略全开（allowlist `layer_dyn.go:17-21` 实测；保底 `DefaultSrcPort+i`（`strategy_convert.go:49`）；dst 动态与端口契约冲突面已在框架声明）。**业务字段 15 项全关**（allowlist 无 `ethmining` 行，实测 grep 零命中；对象即拒）：`hex_prefix`（会话级选择器）/ `sessions[]`（剧本结构）/ `events[]`（剧本结构）/ `user_agent`/`protocol`（协商常量）/ `subscription_id`/`extranonce`（服务端指派）/ `username`/`password`（剧本身份）/ `job_id`/`seed_hash`/`header_hash`（服务端指派）/ `miner_nonce`（剧本值）/ `difficulty`（服务端指派）/ `wire_fault`（故障注入）——逐流变体需求列 A′ 候选（testcase §6.2）。序号算法实读：`parseLayerDyn`（`layer_dyn.go:78`）/ `checkDynShape`（`:369`）/ `resolveLayerTuple`（`:770`）/ `TupleGenerator.Next`（`tuple_generator.go:26`）/ `ResolveIP/Port/StringValue`（`:290/300/310`）/ 多流保底（`worker.go:300-308`，`DefaultSrcPort+i`）。

## 13. P3 对接清单（T-ETHMINING 草稿输入；正文落 testcase 文件）

32 ID（22 正 + 10 负）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。A′ 候选：业务字段动态（`username`/`job_id` 逐流变）/ 1B extranonce 例 / 并发交错例（`concurrent:true` 启用时）/ 现网方言实证例（G-EM-2 关闭时）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-EM-1 | 旧稿 73-* "尚未实现/仅占位"描述已过时（实现 b7ab0ce 已落，32 语义用例已落盘） | 本版如实注记；73-* 为历史层不改 |
| G-EM-2 | 现网矿池方言实证（`"jsonrpc":"2.0"` 成员、非 4444/3353 端口约定、鉴权错误码字面）未到抓包级 | A′ 候选；确认方式：抓现网矿池包或查矿池官方接入文档（三选一已写清） |
| G-EM-3 | 负例 32 锚词三选一候选集未钉死 | P4 按实际错误信息钉死其一，同步两文档 |
| G-EM-4 | `CheckProtoFlat` 无 ethmining 分支 → 顶层 `ethmining` 子映射 presence 不判死；存量 32/32 顶层旧键残留待 P4 迁层链 | P4 迁 32 例为严格层链形 + 收官自查「非负例顶层键=0」；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单；kingbase 记忆裁定） |
| G-EM-5 | 业务字段动态全关（allowlist 无 `ethmining` 行） | A′ 候选，不冒充已覆盖（§9.36 口径） |

## 15. 修订记录

- v1.0.0（2026-09-27）：P-PIPE #91 文档轨 P1–P3。RESUME 续写：主/dialect 判定（§0/§10.5，独立接线五条实测 + 双向拒绝铁证 + 方案 A/B/C 对比）；旧稿 73-* v2.0.2 线格式/状态机/行公式/32 ID 全量继承（思路参考不搬码）；存量 32 例机读审计（顶层残留形状、expect 形状、ID 顺序一致）；§12.1/12.3/12.12 强制展开 + 12-P2；D-ETHMINING-1 as-built 定稿（§11）；缺口 G-EM-1…G-EM-5。P1 自审 3 轮 / P2 自审 2 轮 / P3 自审 2 轮，末轮干净（结论见 p123 报告 §3）。

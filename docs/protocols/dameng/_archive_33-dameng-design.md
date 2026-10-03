# Dameng（达梦数据库）数据库协议设计

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：仅设计与用例契约；`dameng` 层尚未实现，本稿不宣称 MCP（Model Context Protocol，模型上下文协议）套件可以运行。
> 配套文件：`docs/protocol-designs/33-dameng-testcase.md`、`trafficgen/test/protocol_pcap/cases/dameng.json`、`docs/protocol-designs/audit/33-dameng-adversarial-audit.md`

## 1. 范围、证据等级和不变式

Dameng（达梦）客户端通常经 TCP 连接数据库服务，常见默认监听端口为 **5236**。公开资料能够稳定支持的是 TCP 载体、默认端口以及客户端/服务端双向会话；DM8（达梦数据库 8）不同补丁、兼容模式、认证方式和加密配置可能选择不同的私有应用消息布局。

本版因此明确区分三类内容：

| 级别 | 本版处理 | 是否写入固定 frame（帧）十六进制 |
|---|---|---|
| TCP/IP 事实 | TCP 载体、默认端口 5236、四元组、IPv4/IPv6、流内方向和握手/终止 | 只用 tshark（抓包解析器）传输字段；不把 TCP 选项当成 Dameng 头 |
| 会话/语义契约 | CONNECT、AUTH、SQL 请求、SQL 成功/错误、会话结束的事件顺序 | 用 profile（档案）名表达；不把 profile 名当作线上字节 |
| 版本化私有 wire（线格式） | 应用消息头、长度字段的宽度/字节序、认证摘要、SQL 编码、响应状态和分片 | 当前不固定；实现前必须补充对应 DM 版本的可复现 PCAP（抓包文件）或官方字节证据 |

以下内容**不属于本版已确定事实**：任何“DM 包头固定为 N 字节”、magic（魔数）、长度字段的偏移/字节序、用户名密码字段位置、密码摘要算法、SQL opcode（操作码）、错误码、结果列元数据和服务端自动响应。没有可靠的版本化 fixture（固定样本）时，填入这些字节会制造伪精确断言。

不变式：

1. `dameng` 终结层只能承载在 TCP 上；UDP、裸 IP 和缺少 TCP 的层链必须拒绝。
2. 默认目的端口为 5236；本版不把非标准端口静默当成达梦流量。未来若开放覆盖，必须在配置和用例中显式声明。
3. 每个 session（会话）由独立四元组标识；不同 session 的认证状态、请求序列和响应关联不得混用。
4. 语义事件按配置顺序进入同一 TCP stream（TCP 流）；一个事件的实际应用 payload（载荷）由所选 profile 决定，不由本设计猜测。
5. 连接、认证、SQL 请求和 SQL 响应之间的状态迁移由 planner（规划器）校验；失败必须传播到 task（任务）错误终态，不能“完成但 0 包”。
6. TCP 三次握手、应用数据段和正常 FIN 终止由公共 TCP 层负责；Dameng 应用事件不隐式增加未配置的 ACK 或服务端消息。
7. 应用 payload 超过 MSS（最大报文段长度）时可能被 TCP 分段；任何固定 frame offset（帧偏移）都只能针对实际 segment，不能当作 TCP 流偏移。

## 2. 载体和会话模型

### 2.1 层链

```json
{"layers":[{"tcp":{}},{"dameng":{}}]}
```

`dameng` 是终结层，硬依赖 TCP。默认配置如下：

```json
{
  "layers": [{"tcp": {}}, {"dameng": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "src_port": 12345,
  "dst_port": 5236,
  "dameng": {"profile": "dm8_profile_pending", "events": []}
}
```

`dm8_profile_pending` 是本仓库的**实现契约名**，不是 Dameng 线上字段或服务器协商字符串。实现阶段必须将它绑定到有来源的版本模板；在未绑定前不得生成“看起来像 DM8”的随机二进制。

### 2.2 TCP/IP 绝对偏移

无 VLAN、无 IP option、无 TCP option 时，IPv4 TCP payload 起点为 Ethernet 14 + IPv4 20 + TCP 20 = **frame offset 54**；IPv6 起点为 14 + 40 + 20 = **74**。这两个数字只描述 TCP 载荷起点，不表示 Dameng 应用头起点，也不能推出应用字段偏移。启用 option、扩展头或 MSS 分段后，应使用解码字段或 TCP stream 重组结果。

### 2.3 事件和方向

事件拥有以下公共属性：

| 字段 | 类型 | 约束 |
|---|---|---|
| `kind` | enum | `connect`、`auth_request`、`auth_response`、`sql_request`、`sql_response`、`close` |
| `direction` | enum | `c2s` 或 `s2c`；connect/auth request/sql request 为 c2s，响应为 s2c |
| `profile` | string | 已登记的版本化模板名；不直接写入 wire |
| `sql` | string（仅 SQL 请求） | 语义 SQL 文本；编码和线上位置由 profile 决定 |
| `result` | enum（仅 SQL 响应） | `success` 或 `error`；错误码/文本布局由 profile 决定 |

最小成功状态序列是：

```text
connect(c2s) → auth_request(c2s) → auth_response(s2c) →
sql_request(c2s) → sql_response(s2c)
```

如果某个 profile 的认证协商包含额外 challenge（挑战）/response（响应）轮次，必须显式展开为独立事件，不能由 planner 暗中增加。`connect → sql_request`、缺少认证响应、响应方向错误、认证失败后继续 SQL 都必须拒绝。

## 3. 版本化 profile 边界

### 3.1 连接 profile

`connect_default` 仅表示“客户端发起一次 DM 会话连接事件”。本版不固定其应用头、客户端版本、能力位、字符集、服务名或连接描述。将来需要：

- 指定 DM8 具体版本/补丁和兼容模式；
- 给出 TCP stream fixture，并标注应用消息边界；
- 证明长度、字节序、字段偏移和方向；
- 将 profile 版本写入 design/testcase/JSON 三方。

### 3.2 认证 profile

`auth_default`、`auth_password`、`auth_secure` 均只是预留的模板类别；本版不声称任一密码摘要或 challenge 算法。测试配置中的 `username` 可以用于语义输入，但密码不得写入真实 PCAP 或日志；实现阶段应使用固定测试凭据占位并说明脱敏规则。任何认证结果必须由显式 `auth_response` 表达，不能根据“连接成功”推断认证成功。

### 3.3 SQL profile

`sql_select_default` 和 `sql_error_default` 表示 SQL 请求/响应语义，不固定 SQL 文本的字符编码、命令码、参数绑定、结果集元数据、错误码或错误文本的 wire 位置。`sql` 文本可以在 testcase 中作为输入契约，但当前不使用其 ASCII/UTF-8 字节作为 frame 断言。

成功响应和错误响应必须分成两个 profile/事件，不允许通过某个未定义状态位猜测结果。错误响应的可观察性在本版限于 TCP 方向、非空 payload 和事件数；待得到版本 fixture 后再增加 DM 专用字段断言。

### 3.4 不支持的能力

以下能力在本版是待实现边界：DMHS/分布式事务、TLS/通信加密、压缩、批量协议、LOB（大对象）分片、服务端推送、预处理语句二进制绑定、结果集分页、代理协议、Oracle/兼容模式下的替代 wire 语义。不得把它们的字节复用到默认 profile。

## 4. 配置契约

```json
{
  "layers": [{"tcp": {}}, {"dameng": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "src_port": 12345,
  "dst_port": 5236,
  "dameng": {
    "wire_profile": "dm8_profile_pending",
    "events": [
      {"kind":"connect", "direction":"c2s", "profile":"connect_default"},
      {"kind":"auth_request", "direction":"c2s", "profile":"auth_default", "username":"SYSDBA"},
      {"kind":"auth_response", "direction":"s2c", "profile":"auth_default", "result":"success"},
      {"kind":"sql_request", "direction":"c2s", "profile":"sql_select_default", "sql":"SELECT 1"},
      {"kind":"sql_response", "direction":"s2c", "profile":"sql_select_default", "result":"success"}
    ]
  }
}
```

字段约束：

| 字段 | 默认/限制 | 说明 |
|---|---|---|
| `wire_profile` | 必填；当前仅接受已登记 profile | 版本化模板选择器，不是线上字节 |
| `events` | 非空；按顺序校验 | 语义事件序列 |
| `sessions` | 可选；与单 session 二选一 | 每项覆盖端口并拥有独立状态 |
| `dst_port` | 默认 5236；本版要求 5236 | 非标准端口拒绝并包含 `5236`/`port` |
| `max_message_bytes` | 实现声明后才能使用 | 当前不伪造数值；超过实现上限必须报 `limit` |
| `wire_fault` | 仅负例 | 在 planner 边界模拟 header/length/truncation，不生成损坏合法流 |

校验错误锚点：

| 错误 | 条件 | 稳定锚点 |
|---|---|---|
| 载体 | UDP、缺少 TCP 或多余终结层 | `tcp` |
| 端口 | `dst_port != 5236` | `5236` 或 `port` |
| profile | 未登记或混用不兼容版本 profile | `profile` |
| 状态 | connect 缺失、顺序错误、方向错误 | `state` |
| 认证 | 未成功认证即发 SQL，或认证失败后继续 | `auth` |
| 关联 | s2c 响应无对应请求/请求顺序错 | `response` 或 `correlation` |
| 长度 | profile 编码后截断、长度溢出或超过实现上限 | `length`、`truncated` 或 `limit` |
| SQL | 缺少 SQL、空 SQL 不被 profile 支持 | `sql` |

## 5. 包数和场景映射

在公共 TCP planner 的小 payload、每个语义事件恰好一个 TCP 数据段、无额外 ACK 事件的前提下：

```text
packet_count = 3（握手） + 应用事件数 + 4（FIN 终止）
```

MSS 分段或具体 profile 产生多段时必须同步修订三方包数；下面的数字是当前设计契约，不是对私有 wire 分片行为的承诺。

| 场景 | JSON id | 事件数 | packet_count | 观察重点 |
|---|---|---:|---:|---|
| 基础连接 | `dameng_connect` | 1 | 8 | TCP 5236、connect payload |
| 认证成功 | `dameng_auth_success` | 3 | 10 | c2s/s2c 认证方向、非空 payload |
| SQL 成功 | `dameng_sql_success` | 5 | 12 | SQL 请求/成功响应的双向事件 |
| SQL 错误 | `dameng_sql_error` | 5 | 12 | 错误响应方向与独立 profile |
| 长度边界 | `dameng_length_boundary` | 5 | 12 | profile 边界输入、非空 payload |
| IPv4 | `dameng_ipv4` | 5 | 12 | IPv4 TCP 5236 |
| IPv6 | `dameng_ipv6` | 5 | 12 | IPv6 TCP 5236 |
| 多会话 | `dameng_multi_session` | 2×3 | 20 | 两条四元组、认证状态隔离 |
| UDP 载体负例 | `dameng_neg_udp` | — | — | 仅错误传播 |
| 端口负例 | `dameng_neg_port` | — | — | 仅错误传播 |
| profile 负例 | `dameng_neg_profile` | — | — | 仅错误传播 |
| 状态负例 | `dameng_neg_state` | — | — | 仅错误传播 |
| 截断负例 | `dameng_neg_truncated` | — | — | 仅错误传播 |
| 上限负例 | `dameng_neg_oversize` | — | — | 仅错误传播 |

这里的 `dameng_connect` 只验证连接事件可规划；它不声称服务端已 ACCEPT 或会自动认证。`dameng_auth_success` 的三个事件是 connect、auth_request、auth_response；其后才允许 SQL。

## 6. 实现完成定义

实现前必须先补充以下证据和失败优先测试：

1. 为至少一个明确 DM8 版本记录真实客户端/服务端 PCAP，标出应用消息边界和 TCP stream 重组方式。
2. 从 fixture 推导应用头长度、length 字段宽度/字节序、认证字段和 SQL 请求/响应稳定字节；若不同版本不一致，拆分 profile，不能取“最常见值”。
3. 为 connect、认证成功/失败、SQL 成功/错误、截断、长度溢出、MSS 分段分别写失败优先测试。
4. 将 planner 错误传播到 API→engine→task 终态，禁止 0 包成功。
5. 在 profile fixture 稳定后，为每个正例增加 DM 专用 `fields` 或 `frames`，并把 offset 改成动态解码/重组断言；当前仅传输层断言不构成 wire 实现完成。
6. 运行 `go test -race -count=1`、JSON 静态检查和真实 PCAP/NIC（网卡）验证；当前文档阶段不执行这些实现测试。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立达梦 TCP 5236 设计契约，覆盖连接、认证、SQL 成功/错误、长度边界、IPv4/IPv6、多会话和负例；明确私有应用头、认证和 SQL 字节必须由版本化 fixture 定稿，未定稿字段不写入固定 frame 断言。

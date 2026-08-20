# Dameng（达梦数据库）三件套双视角对抗审查

> 审查对象：`docs/protocol-designs/33-dameng-design.md`、`docs/protocol-designs/33-dameng-testcase.md`、`trafficgen/test/protocol_pcap/cases/dameng.json`
> 审查日期：2026-08-20
> 审查口径：**文档阶段审查**；不检查也不假定 Go planner（规划器）、builder（构造器）、validator（校验器）或 `dameng` layer（层）已实现。

## 1. 审查方法

本轮分别执行：

1. **设计逻辑视角**：从 TCP 载体、5236 端口、事件状态、方向、会话隔离、包数公式、版本化 profile（档案）边界和错误传播逐项反推；特别尝试找出把未确认的 DM8（达梦数据库 8）私有 header（头）、长度字段、认证摘要、SQL opcode/错误码写成事实的地方。
2. **用例覆盖视角**：从 design（设计）§1–§5 的每个固定事实、状态分支、成功/错误语义、边界、IPv4/IPv6、多 session（会话）和负例反查 testcase（用例文档）/JSON，检查原子性、可观察性和正负结构。
3. **机器检查**：JSON 语法、ID 唯一性与顺序、包数推导、正负 `expect` 形状、所有正例 TCP/5236。

## 2. 设计逻辑视角

### D-01：确定事实与私有 wire 分离（通过）

设计只固定 TCP 载体、常见默认端口 5236、四元组、IPv4/IPv6 和事件方向；明确没有可靠版本 fixture（固定样本）时，不固定 Dameng 应用头的字节数、magic、length 字段、用户名/密码位置、摘要算法、SQL 命令码或错误码。`wire_profile`/`payload_profile` 是实现契约名，明确不是线上字符串。

### D-02：会话状态和方向约束可实现（通过）

`connect → auth_request → auth_response(success) → sql_request → sql_response` 的最小成功序列与事件表一致；设计拒绝缺 connect、认证未完成、响应方向错误以及认证失败后继续 SQL。SQL 成功与错误是不同结果分支，没有通过未定义状态位推断服务器行为。

### D-03：TCP/IP 偏移未冒充 Dameng 头偏移（通过）

设计给出 IPv4 TCP payload 起点 54、IPv6 起点 74，同时明确它们不是 Dameng 应用头起点。JSON 不含 Dameng 应用 `frames`，只使用 `ip.version`、`tcp.srcport`、`tcp.dstport`、`tcp.len` 字段，避免伪造固定私有 offset，也覆盖 TCP option/MSS/流重组边界。

### D-04：包数公式和多会话隔离一致（通过）

小 payload、每事件一段的公式为 `3 + events + 4`。正例 1/3/5 事件分别是 8/10/12 包；两条 3 事件流是 20 包。设计明确具体 profile 发生分段或合并时必须同步修订三方，不把当前数字当成私有协议永恒事实。

### D-05：错误传播和版本边界完整（通过）

设计覆盖 UDP/缺 TCP、非 5236 端口、未知 profile、状态/认证/响应关联、截断/长度/上限和 SQL 缺失；要求 planner 错误到 task 终态传播，禁止“0 包成功”。TLS/加密、压缩、LOB、批量、DMHS、兼容模式替代 wire 和结果集私有布局均被列为待实现边界。

## 3. 用例覆盖视角

### C-01：连接/认证/SQL 成功与错误原子覆盖（通过）

`dameng_connect` 单独证明连接事件；`dameng_auth_success` 只证明认证成功方向；`dameng_sql_success` 和 `dameng_sql_error` 分别证明 SQL 正常/错误响应。每条正例都有握手、终止、非空负载和传输层字段断言，没有把 SQL 文本直接当作线上字节。

### C-02：长度边界、IPv4/IPv6、多会话覆盖（通过）

`dameng_length_boundary` 使用版本化 `length_boundary`/最小非空 profile 语义，但不伪造长度值；IPv4、IPv6 分离为独立 cases；多会话用 12345/12346 与服务端 5236 的 `distinct_values + distinct_exclude` 做调度无关的四元组断言，避免握手双向端口污染客户端集合。

### C-03：负例覆盖和结构（通过）

六个负例分别覆盖 UDP、端口、未知 profile、未认证 SQL、截断和实现上限。每条 `expect` 仅有 `expect_error` 与 `error_contains`，没有 `packet_count`、`fields` 或 `frames`，不会把失败任务的空 PCAP 当作成功。

### C-04：私有 wire 可观察性边界（通过）

当前没有任何固定 Dameng frame hex 或应用 offset；这是符合需求的待实现边界而非覆盖缺陷，因为版本/补丁/认证模式会影响私有 payload。设计和 testcase 均要求取得明确 DM8 fixture 后再补应用头长度、字节序、认证和 SQL 断言，并同步三方。

## 4. 自审与修订记录

### Round 1：结构和语义审查

发现多会话聚合断言若将服务端 5236 混入 `distinct_values` 会无法证明客户端端口集合，已改为 `distinct_exclude: ["5236"]`；目的端口反向断言排除 12345/12346。复核事件数与包数后未发现其他问题。

### Round 2：对抗审查

尝试以以下输入反驳：UDP 载体、5237 端口、未知 profile、直接 SQL、截断、超上限、认证失败后 SQL、IPv6 常量应用 offset、TCP 分段、多会话交织和伪造 DM8 header。每项都有稳定错误锚点、动态字段断言或明确待实现边界；未发现新增 confirmed finding（确认问题）。

### Round 3：最终一致性审查

执行 JSON 解析、三方 ID/顺序/包数静态比较、正例/负例 expect 形状检查和 TCP/5236 检查；确认 14 个 ID 一一对应，8 条正例包数为 `8/10/12/12/12/12/12/20`，6 条负例没有结构断言。Round 3 clean（通过）。

## 5. 结论

- 设计逻辑视角：D-01..D-05，0 个未修复 finding。
- 用例覆盖视角：C-01..C-04，0 个未修复 finding。
- 自审：**3 轮，最后一轮 clean**。
- Go build、unit test、MCP suite、真实 NIC/PCAP 未执行，因为本任务明确为文档阶段且 `dameng` 尚未实现；这属于记录的待实现边界，不是本轮文档缺陷。

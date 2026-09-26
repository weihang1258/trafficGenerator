# Dameng（达梦数据库 DM8）测试用例契约

> 版本：v1.0.0（P1–P3 文档轨产物；#81 dameng）
> 日期：2026-09-26
> 配套设计：`docs/protocol-designs/81-dameng-design.md`（v1.0.0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/dameng.json`（现存 **14** 例，旧扁平形，P4 全量改写）
> 旧基线：`docs/protocol-designs/33-dameng-testcase.md`（v1.0.0，14 例：8 正 + 6 负，包数 `[8,10,12,12,12,12,12,20]`——本契约存量改写面全部延续该包数）
> 状态：**设计阶段**。本文**不跑 suite、不启动服务器**，不宣称任何绿的结论；ID 权威 = 本文 §2。存量 14 例的逐条审计去向见 §8。

## 1. 测试原则与形状基线

- **形状基线（CORE_MEMORY §1）**：`spec_json` 必须是**纯 layers** 形——地址只住 `ip` 层（`src`/`dst`）、端口只住 `tcp` 层、数量只走 `flow_control`；顶层只允许 `layers`/`flow_control` 家族/`output`（§1.11）。**正例顶层键 = 0**（白名单外即红）。
  **本协议存量实况（实测）**：14/14 例**是旧扁平形**（顶层键含 `src_ip/dst_ip/src_port/dst_port` + `dameng` 子映射，层 config 全空）——P4 有 14 例改写工作量（设计 §12.1），与 postgresql"存量已 0"形态相反。
- **载体**：`dameng` 为 TCP-only 终结层，链形 `[ip, tcp, dameng]`（IPv6 同形，只换 `ip` 层地址）。链夹 `udp`（`[ip,udp,dameng]`）判死（通用 tcp-only 逻辑 `complete.go:448-466`，锚词 `tcp`）。**UDP 面不存在**（设计 §5）。
- **端口**：`tcp.dst_port` **不写**，由 `dameng` 层 `FieldContract` 补齐 5236（`registry.go:643`）。显式写非契约端口 → 拒（`planner.go:56-58`，锚词 `5236`）。
- **方向**：6 kind 各有自然方向（connect/auth_request/sql_request/close = c2s；auth_response/sql_response = s2c，`planner.go:33-41`）。**所有正例必须显式写 `direction`**；显式值与 kind 自然方向不一致今日不拦 → 缺口 G-DM-5，不建该负例（建了会真绿 = 假通过）。
- **断言通道（实测）**：Dameng 私有协议**无 tshark dissector**（`tshark -G fields` 零 `dameng.*` 命中；`dm8.*` 11 命中全是航空 ATN-CPDLC 字段，无关）。主通道 = 载体字段 `ip.version`/`ipv6.version`/`tcp.srcport`/`tcp.dstport`/`tcp.flags`/`tcp.len`；占位字节只断言**非空**（`tcp.len` nonzero），**不断言其值为 DM8 正确性证据**（设计 §3.2 铁律）。**不自创字段名**。
- **包数公式（存量 8 正例逐例复算通过）**：单会话 `packet_count = 3（SYN/SYN-ACK/ACK）+ N（事件数）+ 4（FIN-ACK 四way）= N + 7`；多会话 = 各会话独立经此公式后求和（`dameng_multi_session` 2 会话 × 3 事件 → 2×10 = **20** ✓）。所有约定值按 §9.31/§14.20 **先跑后钉**。
- **「事件数」口径**：`events[]` 数组长度（`sessions[]` 形则为各 session 的 `events` 之和）；**握手/挥手不计入事件数**。
- **负例纪律（§14.11/§14.12）**：`expect` 键集合严格为 `{"expect_error","error_contains"}`；锚词与 validator 字面值一一对应（设计 §4.2）。
- **目标形状示例**（`dameng_sql_success` 改写形，纯 layers）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345}},
    {"dameng": {
      "wire_profile": "dm8_profile_pending",
      "events": [
        {"kind": "connect", "direction": "c2s", "profile": "connect_default"},
        {"kind": "auth_request", "direction": "c2s", "profile": "auth_default"},
        {"kind": "auth_response", "direction": "s2c", "profile": "auth_default", "result": "success"},
        {"kind": "sql_request", "direction": "c2s", "profile": "sql_select_default", "sql": "SELECT 1"},
        {"kind": "sql_response", "direction": "s2c", "profile": "sql_select_default", "result": "success"}
      ]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

（注：改写时事件内 `username` 键按 G-DM-3 同批删/接线；示例已删。）

## 2. 原子用例索引（32 ID = 13 正 + 19 负，顺序为权威）

「今日」列：✅ = 存量改写后现存能力即可跑（**26 例**：8 正改写 + 18 负）；A′ = 需 P4 接线或新能力（**6 例**：5 正 + 1 负 #32，含 P4-V9 层内未知字段例；用例已定义，落盘在 P4）。

> 计数说明：32 行 = 13 正（#1–#13）+ 19 负（#14–#32）。「今日」机读复核口径待 P4 改写后执行；**A′ 用例的 ID 与断言在本文即定稿**，P4 落盘时按 §9.14 全量重跑（§14.19 全量非增量）。

| # | ID | 类型 | 覆盖 | 今日 | 约定 packet_count |
|---:|---|---|---|---|---:|
| 1 | `dameng_connect` | 正 | 单 connect 事件、TCP 5236 | ✅（改写） | 8 |
| 2 | `dameng_auth_success` | 正 | connect→auth_request→auth_response(success) 方向序 | ✅（改写） | 10 |
| 3 | `dameng_auth_error_then_close` | 正 | auth_response(error) → authOK=false → close 收尾 | A′（新） | 11 |
| 4 | `dameng_sql_success` | 正 | 完整 5 事件成功序 | ✅（改写） | 12 |
| 5 | `dameng_sql_error` | 正 | SQL 错误响应独立 profile | ✅（改写） | 12 |
| 6 | `dameng_close_clean` | 正 | 5 事件 + close 末位正常结束 | A′（新） | 13 |
| 7 | `dameng_length_boundary` | 正 | `length_boundary` + `payload_size` 最小非空 | ✅（改写） | 12 |
| 8 | `dameng_ipv4` | 正 | IPv4 载体（`ip.version=4`） | ✅（改写） | 12 |
| 9 | `dameng_ipv6` | 正 | IPv6 载体（`ipv6.version=6`，起点 74） | ✅（改写） | 12 |
| 10 | `dameng_multi_session` | 正 | `sessions[]` 两会话整块展开 | ✅（改写） | 20 |
| 11 | `dameng_multi_flow_dynamic` | 正 | `flows=N` 多流 + 四元组动态五策略 | A′（新） | 8×N |
| 12 | `dameng_long_sql_mss` | 正 | 长 SQL 跨 MSS 分段 | A′（新） | 实测钉 |
| 13 | `dameng_pcap_nic_consistency` | 正 | 同 fixture 双路（pcap + NIC）字段一致 | A′（新） | 12 |
| 14 | `dameng_neg_udp` | 负 | 链夹 `udp` | ✅（改写） | — |
| 15 | `dameng_neg_port` | 负 | 显式 `dst_port=5237` | ✅（改写） | — |
| 16 | `dameng_neg_profile` | 负 | `wire_profile` 未登记 | ✅（改写） | — |
| 17 | `dameng_neg_state` | 负 | 首事件即 `sql_request` | ✅（改写） | — |
| 18 | `dameng_neg_truncated` | 负 | `wire_fault` truncate | ✅（改写） | — |
| 19 | `dameng_neg_oversize` | 负 | `wire_fault` over_limit | ✅（改写） | — |
| 20 | `dameng_neg_unknown_kind` | 负 | `kind` 未登记值 | ✅（新） | — |
| 21 | `dameng_neg_empty_sql` | 负 | `sql_request` 空 SQL | ✅（新） | — |
| 22 | `dameng_neg_sql_before_auth` | 负 | 未认证即 SQL | ✅（新） | — |
| 23 | `dameng_neg_sql_after_auth_error` | 负 | 认证 error 后继续 SQL | ✅（新） | — |
| 24 | `dameng_neg_close_not_last` | 负 | close 非末位 | ✅（新） | — |
| 25 | `dameng_neg_auth_response_without_request` | 负 | 无前置 auth_request 的 auth_response | ✅（新） | — |
| 26 | `dameng_neg_connect_not_first` | 负 | 首事件为 auth_request（非 connect） | ✅（新） | — |
| 27 | `dameng_neg_events_sessions_exclusive` | 负 | `events` 与 `sessions` 并存 | ✅（新） | — |
| 28 | `dameng_neg_session_empty_events` | 负 | session 空事件表 | ✅（新） | — |
| 29 | `dameng_neg_wire_fault_unknown_kind` | 负 | `wire_fault.kind` 未登记值 | ✅（新） | — |
| 30 | `dameng_neg_wire_fault_wrong_shape` | 负 | `wire_fault` 为非对象形 | ✅（新） | — |
| 31 | `dameng_neg_payload_size` | 负 | `payload_size` 非法值 | ✅（新） | — |
| 32 | `dameng_neg_unknown_layer_field` | 负 | dameng 层内第 6 个键（5 键白名单外） | A′（P4 V9 后生效） | — |

## 3. 正例逐项断言契约

> 通则：①每条正例 `expect` 至少含 `packet_count`（或 `min_packets`）、`has_payload`；②字段断言只用载体字段（`ip.*`/`ipv6.*`/`tcp.*`）；③占位字节只断非空；④所有 `direction` 显式；⑤负例零混入。

1. **`dameng_connect`**：链 `[ip,tcp,dameng]`，`ip.src=10.0.0.1`/`ip.dst=20.0.0.1`，`tcp.src_port=12345`（**不写 dst_port**）。事件 1 条（connect/c2s）。断言：`tcp.dstport=5236`（包 4）、`tcp.len` nonzero（包 4）、`has_handshake`、`terminates`、`has_payload`。`packet_count = 1 + 7 = 8`。
2. **`dameng_auth_success`**：事件 3 条（connect、auth_request、auth_response success）。断言：包 4/5 `tcp.dstport=5236`、包 6 `tcp.srcport=5236`（s2c 响应）、各应用事件包 `tcp.len` nonzero。`packet_count = 3 + 7 = 10`。
3. **`dameng_auth_error_then_close`**：事件 4 条（connect、auth_request、auth_response `result=error`、close）。断言：前 3 包方向序 c2s/c2s/s2c、包 7（close）`tcp.dstport=5236`、`terminates`。`packet_count = 4 + 7 = 11`。A′（新例，P4 落盘）。
4. **`dameng_sql_success`**：事件 5 条完整成功序（`sql=SELECT 1`）。断言：包 4/5/7 `tcp.dstport=5236`（c2s）、包 6/8 `tcp.srcport=5236`（s2c）、包 8 `tcp.len` nonzero。`packet_count = 5 + 7 = 12`。SQL 文本仅作输入契约，**不断言其 ASCII 在 wire 连续出现**（占位字节 = profile 名）。
5. **`dameng_sql_error`**：事件序同 #4，SQL 为明确失败语义、响应 `result=error`。断言请求/响应方向、TCP 5236、非空 payload；不编造错误码/错误文本。`packet_count = 12`。
6. **`dameng_close_clean`**：事件 6 条（#4 序 + close 末位）。断言：close 包方向 c2s + `tcp.dstport=5236`、`terminates`。`packet_count = 6 + 7 = 13`。A′（新例；存量零 `close` 用例，P4 落盘）。
7. **`dameng_length_boundary`**：`wire_profile=length_boundary` + `payload_size=profile_minimum_nonempty`，事件为完整 5 事件成功序。断言包 4 `tcp.dstport=5236` + `tcp.len` nonzero。这里的"边界"是 profile 声明的最小合法非空编码，不写未经证实的 Dameng 长度字段数值。`packet_count = 12`。
8. **`dameng_ipv4`**：完整 5 事件成功序。断言包 4 `ip.version=4`、包 4/5 `tcp.dstport=5236`。`packet_count = 12`。
9. **`dameng_ipv6`**：同 #8 事件序，`ip` 层填 IPv6 地址（`2001:db8::1` → `2001:db8::2`）；断言 `ipv6.version=6`、frames 起点 **74**（§9.24 对称，地址不复用 #8 的 IPv4 fixture）。`packet_count = 12`。
10. **`dameng_multi_session`**：`sessions[{src_port:12345,events:[3]},{src_port:12346,events:[3]}]`。断言：`tcp.srcport` 的 `distinct_values = ["12345","12346"]` 且 `distinct_exclude` 含 `5236`（§9.38 聚合排除服务端固定口）；`tcp.dstport` 的 `distinct_values = ["5236"]` 且 `distinct_exclude` 含两个 client 口；两会话**整块展开不交错**（术语表口径，第二会话 SYN 包号 = 11）。`packet_count = (3+7) × 2 = 20`。
11. **`dameng_multi_flow_dynamic`**：`flow_control.flows=3` + `ip.src` 动态 inc（回绕）/`ip.dst` rand（seed 可复现）/`tcp.src_port` list 轮转。断言：`ip.src` 的 `distinct_values` 三值、`tcp.srcport` 轮转序、rand 同 seed 跨两次运行 same（可复现）；**静态复制被拒另行**（P4 补 `dameng_neg_static_duplicate`，§12 动态面）。A′。`packet_count = 8 × 3 = 24`（connect 单事件基线，实测钉）。
12. **`dameng_long_sql_mss`**：长 SQL（如 3000 字节）跨 MSS。断言 `tcp.len` 分段（`distinct_values` 含两个不同值）；占位字节的 SQL 文本不进字节，故本例验证的是"长配置输入不断裂会话"，不断言 SQL 重组。A′。`packet_count` 实测钉。
13. **`dameng_pcap_nic_consistency`**：同 fixture 先 pcap 后 `output_type=port_group` + NIC。断言两路 `tcp.dstport`/`tcp.srcport` 序列/`tcp.len` 一致；NIC 抓包注意 checksum offload 边界。A′（NIC 例 P5 落）。`packet_count = 5 + 7 = 12`（#4 序）。

## 4. 负例契约

每个负例必须在 planner/validator 边界失败并传播为 **task error**；不能产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error","error_contains"}`：

| # | ID | 故障输入 | 目标 `error_contains` | 锚词出处（实测） |
|---:|---|---|---|---|
| 14 | `dameng_neg_udp` | 链 `[ip,udp,dameng]` | `tcp` | 通用 tcp-only 逻辑 `complete.go:448-466`（`rides tcp only (carrier)`；dameng 无专用链消息） |
| 15 | `dameng_neg_port` | 显式 `tcp.dst_port=5237`（改写形；存量为顶层 `dst_port=5237`） | `5236` | `planner.go:56-58` `is not the default %d` |
| 16 | `dameng_neg_profile` | `wire_profile="unknown_profile"` | `profile` | `planner.go:53-55` `unknown wire profile %q` |
| 17 | `dameng_neg_state` | 首事件即 `{kind:"sql_request"}` | `state` | `planner.go:102-104` `first event must be connect` |
| 18 | `dameng_neg_truncated` | `wire_fault={"kind":"truncate_message","value":1}` | `truncated` | `builder.go:52` `truncated message length` |
| 19 | `dameng_neg_oversize` | `wire_fault={"kind":"message_limit","value":"over_limit"}` | `limit` | `builder.go:54` `over implementation limit` |
| 20 | `dameng_neg_unknown_kind` | `{kind:"bind"}`（未登记） | `unknown kind` | `planner.go:99-101` |
| 21 | `dameng_neg_empty_sql` | `{kind:"sql_request"}` 无 `sql` | `sql` | `planner.go:133-135` `empty SQL text` |
| 22 | `dameng_neg_sql_before_auth` | connect 后直接 `sql_request`（无认证） | `auth` | `planner.go:129-132` `before successful authentication` |
| 23 | `dameng_neg_sql_after_auth_error` | `auth_response(result=error)` 后 `sql_request` | `auth` | 同上（`authOK=false` 分支 `:124-128`） |
| 24 | `dameng_neg_close_not_last` | `close` 后追加事件 | `state` | `planner.go:105-107` `close must be the last event` |
| 25 | `dameng_neg_auth_response_without_request` | 无前置 `auth_request` 的 `auth_response` | `state` | `planner.go:108-110` `without auth_request` |
| 26 | `dameng_neg_connect_not_first` | 首事件为 `auth_request` | `state` | `planner.go:102-104`（与 #17 同分支不同首 kind，按 §9.21 不同上下文算不同测试点） |
| 27 | `dameng_neg_events_sessions_exclusive` | `events` 与 `sessions` 并存 | `mutually exclusive` | `planner.go:62-64` |
| 28 | `dameng_neg_session_empty_events` | `sessions=[{src_port,events:[]}]` | `empty events` | `planner.go:72-75` |
| 29 | `dameng_neg_wire_fault_unknown_kind` | `wire_fault={"kind":"bogus"}` | `unknown kind` | `builder.go:56` |
| 30 | `dameng_neg_wire_fault_wrong_shape` | `wire_fault="truncate"`（字符串形） | `invalid wire_fault` | `builder.go:47-48` |
| 31 | `dameng_neg_payload_size` | `payload_size="huge"` | `payload_size` | `planner.go:65-67` `unsupported payload_size` |
| 32 | `dameng_neg_unknown_layer_field` | dameng 层内增第 6 键 | `unknown field` | `complete.go:293`（**P4 V9 后生效**；今日落盘会真绿 = 假通过，P4 随 `Fields` 同批落盘） |

**合法但易误判为负例的形态（必须在正例覆盖，不许误报）**：空 `profile` 事件（回退 `dm8` 字节，G-DM-7 注记）、`wire_fault` 空/nil（**no-op**，`builder.go:43-45` 显式放行）、认证 `result` 缺省（视为 success，`planner.go:124-128`）。

**今日不可建的负例（缺口，不建）**：显式 direction 与 kind 自然方向不一致（G-DM-5，无守卫）；层链+顶层空 `dameng` 子映射并存（G-DM-6，`CheckProtoFlat` 无 dameng 分支）。

## 5. 三源回指行与 9.52 对账

### 5.1 三源回指（§9.2–9.4）

**①公开资料**：DM8 默认端口 5236（dameng 官方社区 + 多源一致）+ SYSDBA 默认用户 + TCP 建连语义——本文 §3/§4 的端口/方向/顺序断言回指该档；私有 wire **无出处**，不断言（设计 §10 铁律）。
**②D-DAMENG-1**（设计 §11）：文件清单/接口签名/数据结构/主流程/错误分支/性能边界/冲突点/回滚。
**③已确认的现网行为**：**当前为未确认级**——只有公开资料描述的默认建连行为，**无本机抓包证据** → 挂 **G-DM-4**，按 §5.5 不写死进实现。
→ 落盘：`trafficgen/test/protocol_pcap/cases/dameng.json`（目标 13 正例 + 19 负例；ID 权威 = 本文 §2）。

### 5.2 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **公开资料 + 旧基线语义契约反推**（DM8 默认端口/用户 + 33-design 的事件/状态语义），**非**引擎能力面反推。引擎侧只作现状取证：`registry.go:642-643`（无 `Fields` + FieldContract）/`planner.go:43-146`（validator）/`builder.go:17-58`（占位字节 + wire_fault）/`layer_gen.go:20-66`（生成器）/tshark 零 dissector 实测。
- **对账两行**：
  - **规范逻辑点总数 = 46** = 设计 §10.1 八项矩阵 **8** 行 + §10.2 事件×状态矩阵 **20** 格（4 行 × 5 列）+ §10.3 数据形态变体表 **18** 行。
  - **用例覆盖数 = 38** = 八项 **8** 行（每行均有落点：#1–#13 覆盖全部 8 行，行 6/7 以"显式不适用"收口）+ 矩阵**已覆 15 格**（✅6 + Ⓡ9）+ 矩阵**缺口→用例通道 3 格**（#22–#24 新负例；#25/#26 为已覆格内深度负例）+ 变体 **12** 行（直接落点；其余 6 行 = A′/注记通道）。
  - **不适用/注记 = 3** = 矩阵 N-A 1 + 现状允许注记 1 + 变体无形态注记 1（§10.3 无单包多载荷面）。
  - **缺口 = 5**（G-DM-1/2/3/5/6 为 B′/A′/框架级；G-DM-4 现网确认、G-DM-7 空 profile、G-DM-8 分段面为 A′ 补例通道，不折进 5）。
  - 校验：**38 + 3 + 5 = 46** ✓ 无遗漏。
- **粒度声明（防误读）**：按设计 §10 的行/格粒度计数，每行/格只计 1 点；跨切面缺口 **G-DM-1…G-DM-8** 另登设计 §14，**不折进 46 点、也不冒充覆盖**。

## 6. P3 固定动作

### 6.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接：connect→认证→SQL→（SQL→响应）*→close | 已覆：#4（单轮全序）、#10（两连接各三事件）；多轮 SQL = A′ 补例（P4 落 `dameng_multi_query_rounds`） |
| ② | 非正常结束 | 正常 = close + FIN-ACK 四way（#6）；**非正常** = ①认证失败（#3）②SQL 错误（#5）③校验期拒绝（19 负例）④**服务端主动断连 / RST**（`tcp.rst=true`） | ①–③ 已覆；④ → **A′ 补例**（P4 落 `dameng_server_abort_rst`）；无 B′ |
| ③ | 长保活 | 协议层**无 keepalive 语义**（设计 §10.1 行 6 显式"不适用"）——活性由 TCP 承担；长会话 = 同连接多轮 SQL | 已覆：#10（多会话）+ #4（含终止）；**同连接多轮 SQL**（>2 轮）随 ① 的 A′ 补例同批 |

无空项：①③ 各有已覆例 + 各 1 条 A′ 补例；② 有已覆例 + 1 条 A′ 补例。

### 6.2 A′/B′ 两分类表（要求面反推：数据 / 业务 / 现网 / 多流 / 地址族 / 断言通道 六类）

**A′（引擎可构建，需 P4 接线 → 落 32 ID 内或补例）**：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | 认证结果 success/error；SQL 结果 success/error；空 SQL；wire_profile 2 值；payload_size 单值；长 SQL 分段 | #2/#3/#4/#5/#21/#7/#31 + #12 A′ |
| 业务 | 单轮全序；多轮 SQL；close 正常结束；认证失败后 close | #4/#6/#3 + 多轮 A′ 补例 |
| 现网 | 默认 Oracle 兼容模式建连面 | #2/#4；**抓包级确认 → G-DM-4** |
| 多流 | `flows=N` 多流并发 + `sessions[]` 多会话展开 + PCAP/NIC 双路一致 | #10/#11/#13 |
| 地址族 | IPv4 / IPv6 两格（`§9.24` 对称，不许一族代表另一族） | #8 / #9 两格满格（起点 54/74 两档） |
| 断言通道 | 载体字段通道（`tcp.*`/`ip.*`）× 占位非空通道；**无 DM8 dissector 通道**（实测零命中） | #1–#10 走载体字段；§1 通道表已写死 |
| 动态 | 四元组 × 五策略（inc 回绕 / rand 可复现 / list 轮转 / pattern 替换 / 静态复制被拒） | #11（四策略）+ 负例（静态复制拒绝面，P4 补 `dameng_neg_static_duplicate`） |

**B′（引擎结构缺口 → D-DAMENG-1「明确不解决 + 迁入计划」，见设计 §14）**：

- **G-DM-1**（私有 wire 版本化 fixture 面）——覆盖设计 §10.1 行 2/8。
- 另 5 项（G-DM-2/3/5/7/8）为 **A′ 缺口**，G-DM-6 为**框架级缺口**，G-DM-4 为现网确认项，已在设计 §14 逐项写明去向。

### 6.3 §3.14 豁免边界审计

- **本协议有长连接载体**（单 TCP 连接承载全部会话事件）→ **`sessions[]` 不豁免**：设计 §12.3 会话表 s1–s3 显式声明；#10 覆盖多会话展开。
- **多流并发**：已覆 #11（`flows=N`，A′）+ #10（`sessions[]` 两连接）+ #13（双输出路，A′）。
- **单包多载荷**：本协议**无此形态**（每事件一 TCP 数据段，无多子结构报文）→ **显式不适用**，不硬凑用例。
- 结论：多流、多会话两项各有结论，单包多载荷显式不适用，**无豁免逃逸**。

### 6.4 断言契约核对结论（与设计 §3/§4/§11 一致）

1. **ID 契约核对**：本文 §2 的 **32** 个 ID = **13 正 + 19 负**（#1–#13 / #14–#32），与设计 §9 的分布摘要**逐值一致**。
2. **packet_count 契约**：公式 `N + 7`（单会话）已对存量 8 正例逐例复算通过（8/10/12/12/12/12/12/20 全中）；多会话按会话求和。**所有约定值 P5 先跑后钉**（§9.31/§14.6/§14.20），不照抄。
3. **通道核对**：Dameng dissector **零命中**已实证（`tshark -G fields` 全表 grep）；占位字节只断非空；**不自创字段名**。
4. **负例纯净性**：19 条负例 `expect` 键集合均为 `{"expect_error","error_contains"}`；**唯一例外 #32 标 A′**（今日落盘会真绿 = 假通过，P4 随 `Fields` 同批落）。
5. **未注册期纪律**：本协议**已注册**，故不存在"占位例"形态；不得把本文 A′ 用例的"未落盘"报告为"suite 通过"。

## 7. 实现后执行建议（P4/P5）

1. **先决**：完成设计 §11.1 的文件清单动作（尤其 §11.3 的**时序约束**——registry 补 `Fields` + translate 补分支 + 存量 14 例改写 + `username` 删/接线必须**同批**，否则 `DisallowUnknownFields`/静默空流造成新假象）。
2. **落盘顺序（§9.26 补齐顺序）**：①改写 14 例跑绿 → ②状态机新负例（#20–#28）→ ③新正例（#3/#6）→ ④全量（动态/分段/双路 A′）。
3. **跑法**：`CASE_PROTO=dameng`（装载 `dameng.json` 全量跑，§14.19 全量非增量）。
4. **断言纪律**：tshark 字段名一律取自 `tshark -G fields` 实测；占位字节只断 `tcp.len` nonzero。
5. **负例锚词**：与 `planner.go` / `builder.go` / 通用链逻辑的错误字面值逐条对齐（§4 表右列已给行号）；锚词漂移必须同步改用例，**不许放宽阈值**。
6. **pcap 落盘**：默认 `/tmp/mcp-pcaps/dameng/`；NIC 例走 `port_group` + `enp135s0f0np0`。

## 8. 存量用例逐条审计去向（§9.14 / §14.4）

**存量基线与实测（2026-09-26 机读）**：

| 文件 | 例数 | 顶层键 | 链形 | `decode_as` | 负例 expect |
|---|---:|---|---|---|---|
| `cases/dameng.json` | 14 | 14/14 含 `src_ip/dst_ip/src_port/dst_port` + `dameng` 子映射 | `[tcp,dameng]`×13 + `[udp,dameng]`×1 | 无 | ✅ 6/6 仅 `{expect_error,error_contains}` |

**§8.1 逐条去向表（14/14 全覆盖，不留未处置项）**：

| 存量 ID | 类型 | 关键形状 | 去向 |
|---|---|---|---|
| `dameng_connect` | 正 | 1 事件 connect、`pk=8` | **改写** #1：纯层链形（地址→`ip` 层、端口→`tcp` 层、`dameng` 子映射→层 config）；包数/断言保留 |
| `dameng_auth_success` | 正 | 3 事件、`pk=10` | **改写** #2；同上改写 + `username` 按 G-DM-3 同批处置 |
| `dameng_sql_success` | 正 | 5 事件、`pk=12` | **改写** #4；同上 |
| `dameng_sql_error` | 正 | 5 事件 error、`pk=12` | **改写** #5；同上 |
| `dameng_length_boundary` | 正 | `length_boundary` + `payload_size`、`pk=12` | **改写** #7；`payload_size` 进层 config |
| `dameng_ipv4` | 正 | 4 事件 IPv4、`pk=12` | **改写** #8 |
| `dameng_ipv6` | 正 | IPv6、`pk=12` | **改写** #9；保留其 IPv6 fixture 地址面 |
| `dameng_multi_session` | 正 | `sessions[]` 2 会话 × 3 事件、`pk=20` | **改写** #10；`distinct_values`/`distinct_exclude` 断言**原样保留**（含 §9.38 排除服务端口口径） |
| `dameng_neg_udp` | 负 | `[udp,dameng]`，锚 `tcp` | **改写** #14（链形保留，顶层旧键清零，锚词逐字保留） |
| `dameng_neg_port` | 负 | 顶层 `dst_port=5237`，锚 `5236` | **改写** #15（坏端口改写为层内 `tcp.dst_port=5237` 显式形，锚词逐字） |
| `dameng_neg_profile` | 负 | `wire_profile="unknown_profile"`，锚 `profile` | **改写** #16（锚词逐字） |
| `dameng_neg_state` | 负 | 首条 `sql_request`，锚 `state` | **改写** #17（锚词逐字） |
| `dameng_neg_truncated` | 负 | `wire_fault truncate_message`，锚 `truncated` | **改写** #18（锚词逐字） |
| `dameng_neg_oversize` | 负 | `wire_fault message_limit`，锚 `limit` | **改写** #19（锚词逐字） |

**结论**：14/14 全部有明确去向（14 改写，**无一条"作废不注原因"**）。改写在 P4 按设计 §12.1 执行；**改写后 `proto` 仍为 `dameng`**（独立层裁定 DM-A，见设计 §10.6）。

**改写时必须同批处理的死字段**：9 例 10 处 `events[].username`（auth_request；`dameng_multi_session` 含 2 处）→ **删键或接线**（设计 §2.3/G-DM-3）；否则"配上不生效"延续。

## 9. 修订记录

- v1.0.0（2026-09-26）：P1–P3 文档轨产物（车道 A）。建立 32 ID 契约（13 正 + 19 负）、正负例逐项断言契约、三源回指行、9.52 对账两行（46 = 38 + 3 + 5）、§3.15 三项、A′/B′ 两分类表、§3.14 豁免边界审计、存量 14 例逐条审计去向、实现后执行建议。**不跑 suite、不启动服务器**；ID 权威 = 本文 §2。旧基线对照：包数公式与 6 负例锚词延续 33-testcase；形状面（旧扁平→纯层链）与 18 新 ID 为新增。

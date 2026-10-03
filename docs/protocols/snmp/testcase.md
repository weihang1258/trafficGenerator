# SNMP 测试用例契约

> 版本：v1.2.0（2026-10-01，文档轨）
> 范围：T1–T6；机器契约：`trafficgen/test/protocol_pcap/cases/snmp.json`。
> 规范依据：RFC 1157、RFC 3416/3417、RFC 3414、X.690。
> 当前状态：本轮把唯一用例迁为严格层链目标形；SNMP Fields/converter 尚未接通，故不宣称 suite 通过。

## T1 形状与执行边界

目标配置只允许顶层 `layers`、框架流控和 `output`；地址位于 `ip` 层，端口位于 `udp` 层，SNMP 业务字段位于 `snmp` 层。当前唯一 case 使用最小链 `[udp,snmp]`，因此 `ip` 由框架补齐。顶层 `snmp` 子映射已删除；现有代码尚未消费层内复杂字段，迁移缺口为 G-SNMP-10。

PCAP/NIC 应共用该 JSON 和同一 fields/raw 断言。当前未运行本轮 suite，不把历史结果表述为今日通过。

## T2 原子 ID 与当前机器契约

当前只有一个正例，JSON 顺序即权威：

| # | ID | 类型 | 包数 | 当前结论 |
|---:|---|---|---:|---|
| 1 | `snmp_smoke_01` | 正 | 1 | 严格层链目标形；待层字段接线后运行 |

输入目标形：

```json
{"layers":[{"udp":{}},{"snmp":{"var_binds":[{"name":"1.3.6.1.2.1.1.1.0"}]}}]}
```

它只验证一次 SNMPv2c（wire-version=1）风格 Get：默认目的端口 161、community `public`、一个 OID 和 error-status 0。`src_port=12345` 是框架惯例，不作为本例断言。

## T3 正例断言

| packet | 字段 | 期望 | 依据 |
|---:|---|---|---|
| 1 | `udp.dstport` | `161` | RFC 3417；planner 默认端口 |
| 1 | `snmp.version` | `1`（v2c） | RFC 3416 version INTEGER；converter 默认 v2c |
| 1 | `snmp.community` | `public` | v1/v2c 默认 community |
| 1 | `snmp.get_request_element` | `1` | RFC 3416 §4.2.1 |
| 1 | `snmp.name` | `1.3.6.1.2.1.1.1.0` | VarBind OID |
| 1 | `snmp.error_status` | `0` | GetRequest field1 |

无 `frames`，所以当前 case 不直接证明 BER 外层 tag、长度字节、PDU tag、OID base-128 或 checksum 原始字节；这些必须在后续用例补齐，不得从任务不报错推导覆盖。

## T4 负例与错误传播

当前 JSON 无负例。实现阶段必须新增并逐条拆分：非法 version、空 community、v3 auth 缺密码、priv 无 auth、非法 auth/priv、engine ID、PDU 越界、Get 类空 VarBind、非法 OID、端口/地址族、截断 BER、长度不匹配、UDP payload 超限。负例 `expect` 严格只允许 `expect_error` 与 `error_contains`；错误必须传播到任务终态，不得生成成功 PCAP、completed/0 packet 或只输出 UDP。

## T5 覆盖审计

| 面 | 已覆 | 待补 |
|---|---|---|
| 功能 | 单 Get | GetNext/Set/GetBulk/Response/Trap/Inform/v3/Report |
| 性能 | 单小包 | BER 长形、UDP 上界、repeat/背压 |
| 数据 | version/community/OID/error-status | value tags、OID 边界、空/最大/非法 |
| 地址与流 | IPv4 默认 161 | IPv6、非默认端口、混合拒绝 |
| 业务 | 单 datagram | repeat/响应、Trap/Inform、USM；无连接多会话不适用 |

固定动作：同流多轮操作待 RepeatCount/PollInterval 例；非正常结束在 UDP 协议层不适用，但 BER 截断须负例；SNMP 无 keepalive，轮询间隔不是 keepalive。

## T6 缺口与执行计划

先补 G-SNMP-10 的层字段契约和 converter 接线，再运行本正例；随后按规范枚举正负行为面，校准 tshark fields/raw offsets；最后用同一 JSON 做 PCAP 与授权 NIC tcpdump 验收，并补基线、目标规模、压力、长跑、交错、背压六类性能测试。未实现内容不写入当前 ID 集合。

## C1–C6 测试验收

- **C1**：PCAP/NIC 使用同一 JSON 和断言，当前仅登记契约，不宣称已验证。
- **C2**：UDP 无握手、保活、FIN/RST；Repeat 是 datagram 序列，不冒充连接状态。
- **C3**：一个事务一个 datagram；无多会话/多流关联，明确不适用。
- **C4**：负例单故障、纯 `expect_error/error_contains`，覆盖 validator/planner 错误传播。
- **C5**：严格层链；不恢复顶层 `snmp` 或四元组旧键。
- **C6**：实现后全量跑 suite，再做 PCAP/NIC 双路径和六类性能验收。

## T1–T6 测试点清单与三源回指

测试点先行，来源按 RFC/设计/现网三列登记；未有现网证据的行为明确标待确认，不把代码存在当作通过。

| T | 规范条文→业务场景 | 设计/代码分支 | cases 去向 |
|---|---|---|---|
| T-SNMP-1 | RFC 3416 §4.2.1 Get + 单 OID | D1#2；`planner.go:722` | `snmp_smoke_01` |
| T-SNMP-2 | RFC 3416 GetNext/Set/GetBulk/Response | D1#2；PDU 分支 | G-SNMP-2，新增原子例 |
| T-SNMP-3 | RFC 1157 Trap、RFC 3416 Trap/Inform | D1#2；Trap 编码 | G-SNMP-2，需 Net-SNMP/Wireshark pcap |
| T-SNMP-4 | X.690 BER 短/长形、OID base-128、父子长度 | D1#4；`planner.go:660-770` | G-SNMP-3/8 |
| T-SNMP-5 | VarBind value tags 全枚举及 exception | D1#4；`encodeVarBind` | G-SNMP-4 |
| T-SNMP-6 | RFC 3414 v3 USM auth/priv/engine | D1#8；`validateSNMPConfig` | G-SNMP-6 |
| T-SNMP-7 | 默认 161/162、IPv4/IPv6、定制端口 | D1#7；chain defaults | G-SNMP-2 |
| T-SNMP-8 | 错误 version/PDU/OID/USM/截断/越界 | D1#5；validator/planner error | G-SNMP-7/8，负例待补 |
| T-SNMP-9 | repeat、同 request-id 响应、poll interval | D1#3/#6；`layer_gen.go:44-87` | G-SNMP-2 |
| T-SNMP-10 | 现网 Net-SNMP/Wireshark 默认 Get/Trap/v3 | D2；需授权抓包确认 | Get=当前例，Trap/v3 待确认 |

## T3 颗粒度与 T4 §3.15 适用性

每个规范字段、PDU、value tag、错误和边界独立为一例；枚举逐值，BER/OID 按正交矩阵（版本×地址族×PDU×端口），动态字段按 fixed/inc/rand/list/pattern 整格。当前仅 `snmp_smoke_01` 进入机器契约，不能把已有内部单测代替端到端 cases。

SNMP 是无连接 UDP 协议：同“连接”多轮不适用；以同一策略的 repeat 多 datagram 立项（G-SNMP-2）。非正常结束以 BER 截断/长度错误负例表达（G-SNMP-8）。长保活没有 SNMP 自有语义；以长时间 poll/repeat 与队列背压性能项立项（G-SNMP-9），不伪造 keepalive 用例。

## T5 存量逐条去向与 T6 失败路径

存量唯一 `snmp_smoke_01`：合入本契约，层内 `var_binds` 已迁移；其历史字段断言保留为待 P5 校准，未复跑不宣称通过。没有其他存量 ID。

负例必须经 MCP/真实任务提交，`expect` 只含 `expect_error` 与 `error_contains`，锚词须逐字取自 validator/planner 文案（如 `Version`、`VarBinds empty`、`invalid`、`length`）；不得混有 `packet_count`/`fields`，不得以 completed/0 packet 作为失败证明。当前无机器负例，故 T6 为待补缺口而非已覆盖。

## C1–C6 对账

- C1：JSON 唯一正例顶层仅 `layers`；`snmp` 业务字段在 `layers[1].snmp`。
- C2：UDP 无握手、FIN/RST、keepalive；一个事务一个 datagram，repeat 另立行为例。
- C3：无会话/多流关联；多 OID VarBind 与 repeat 仍分别覆盖，不以单请求冒充。
- C4：负例契约尚为空，新增时严格双键并锚真实错误。
- C5：唯一 ID `snmp_smoke_01` 在本文 T-SNMP-1 登记。
- C6：未发现 `snmp-spec-mapping.md`；记录为无 mapping 备注，非缺口。

## 修订与自审

v1.2.0（2026-10-01）：补 T1 三源回指、T2 测试点清单、T3 不可再分/三类场景/正交与动态整格、T4 §3.15 三项适用性、T5 存量去向、T6 真实失败路径及 C1–C6；与 JSON 一例 ID/正负数对账一致。补明唯一 smoke 为 SNMPv2c（wire-version=1），并统一文档版本标记。
自审 2 轮，末轮干净：逐项复查 ID、顶层键、层内字段、包数/字段历史口径、负例纯净性和所有 G-SNMP 缺口。

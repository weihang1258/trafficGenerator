# #126 ICMPv6（RFC 4443 Echo）设计契约

> 版本：v1.0.0（P-PIPE 文档轨，as-built）  
> 日期：2026-09-29  
> 旧稿：无独立 ICMPv6 设计稿；历史实现/迁移依据为 `internal/protocol/icmpv6/` 与 `icmpv6_migrate_test.go`。  
> 配套用例：`docs/protocols/icmpv6/testcase.md`；机器契约：`trafficgen/test/protocol_pcap/cases/icmpv6.json`（11 例，顺序与 testcase §2 一致）。

## 0. 范围、权威性与现状

本契约描述 IPv6 上的 ICMP Echo Request/Reply（RFC 4443 §2、§4.1、§4.2），仅覆盖 type 128/129、code 0。推荐且实际链形为 `[ip,icmpv6]`；ICMPv6 是 L3 raw-IP 终结层，不使用 TCP/UDP 端口。代码已落地：`internal/protocol/icmpv6/icmpv6.go`（planner、校验和、自动回复）、`layer_gen.go`（层生成器/validator）、`internal/core/layers/chain_planner_translate.go:1072`（层内翻译）、`internal/core/layers/registry.go:1304`（注册）、`strategy_convert.go:1141`（legacy flat 搬运）。

本版 as-built 事实优先于旧注释；pcap/NIC 使用同一 cases 契约。RFC 4443 是 ICMPv6 语义依据，RFC 8200 §8.1 是 IPv6 伪首部校验和依据。

## 1. 配置形状与顶层迁移

### 1.1 目标形状

```json
{
  "layers": [
    {"ip": {"src": "2001:db8::1", "dst": "2001:db8::2"}},
    {"icmpv6": {}}
  ]
}
```

`icmpv6` 必须位于层链内；层内 6 个业务键为 `type`、`code`、`identifier`、`sequence`、`data`、`pattern`，注册于 `registry.go:1309-1319`。空 map 是合法缺省 Echo Request。顶层仅允许通用控制键与 `layers`；即使顶层 `icmpv6:{}` 为空也拒绝，错误锚词为 `top-level icmpv6 sub-config`（`strategy_convert.go:8931-8936`）。

### 1.2 旧键去向（门1 §1）

| 旧/扁平键 | 目标去向 | 当前证据 |
|---|---|---|
| `src_ip` / `dst_ip` | `layers[ip].src` / `layers[ip].dst` | `chain_planner_translate.go` 的 ip 层翻译；目标例见 §1.1 |
| `icmpv6.type` | `layers[icmpv6].type` | `chain_planner_translate.go:1085-1087` |
| `icmpv6.code` | `layers[icmpv6].code` | `:1088-1090` |
| `icmpv6.identifier` | `layers[icmpv6].identifier` | `:1091-1093` |
| `icmpv6.sequence` | `layers[icmpv6].sequence` | `:1094-1096` |
| `icmpv6.data` | `layers[icmpv6].data`（字符串转字节） | `:1097-1101` |
| `icmpv6.pattern[]` | `layers[icmpv6].pattern[]` | `:1102-1129` |
| 顶层 `icmpv6` 子映射 | 无去向，presence 判死 | `strategy_convert.go:8931-8936` |
| `src_port` / `dst_port` | 清零；线上无 L4 端口 | `strategy_convert.go:1153-1158` |

完整目标 spec_json 例：

```json
{"layers":[{"ip":{"src":"2001:db8::1","dst":"2001:db8::2"}},{"icmpv6":{"type":129,"identifier":7,"sequence":9,"data":"probe"}}]}
```

## 2. 协议栈与线格式

Ethernet IPv6 EtherType 为 `0x86dd`；IPv6 Next Header 为 `58`；默认 Hop Limit 为 64（`icmpv6.go:32-40,101-104`）。IPv6 固定头 40B，故无扩展头时 ICMPv6 头起点 = Ethernet 14 + IPv6 40 = offset 54；Echo data（tshark `data.data`）起点 = 54 + 8 = 62。

ICMPv6 消息布局（网络字节序）：

| 偏移 | 宽度 | 字段 | 值/默认 |
|---:|---:|---|---|
| 0 | 1 | Type | 128 Request 或 129 Reply；空层默认 128 |
| 1 | 1 | Code | 必须 0；默认 0 |
| 2 | 2 | Checksum | IPv6 伪首部 + 消息的一补和，网络序 |
| 4 | 2 | Identifier | 网络序；配置 0 时生成器回退为 Sequence |
| 6 | 2 | Sequence | 网络序；空层默认 1，pattern 缺省按 1-based step 序号 |
| 8.. | 可变 | Data | 字节；空层/step 缺省 `ping` |

总长度为 `8 + len(Data)`。`buildICMPv6Payload`（`icmpv6.go:281-302`）先填字段、再以 checksum 字段为零计算伪首部校验和。无效 IPv6 地址时 checksum 返回 0，但 validator 在静态链路径拒绝该地址。

## 3. 五件套、交互和状态机（门1 §3）

### 3.1 会话表

| 会话 | 载体 | 标识 | 状态 |
|---|---|---|---|
| Echo exchange | 单个声明式 flow | `flowID = src-dst-icmpv6`；Echo identifier/sequence | request → optional reply |

ICMPv6 无连接建立、保活、重连或端口会话；“会话表”仅为生成器 flow 与 Echo 标识，不引入 TCP 状态。

### 3.2 事务序列与关联

单 ping：`type=128 request(up)` 自动派生 `type=129 reply(down)`；Reply 交换 src/dst 与 MAC，并复制 identifier、sequence、data。`type=129` 是单发，不再自动回包。pattern 按声明顺序逐步发包，每步 type=128 追加同字段 reply，type=129 仅一包。raw-IP 驱动再把每包 Direction 强制为 `up`（`layer_gen.go:26-52`，srv6 同款防双换：legacy 已完成 L3 换向，再换即双换错；ICMPv6 无业务 MAC，force-up 后由 up 侧补缺省 MAC）。

### 3.3 插入位置与时间线

`layers[icmpv6]` 是 IPv6 层的终结层；链翻译 → `FlowSpec.ICMPv6` → layer validator → `Generator.Generate` → legacy `Planner.Plan` → `PacketConfig` → builder。planner 在单 goroutine 中按 pattern 顺序写 channel；同一 `now` 时间戳用于该 flow 的包。动态 IP 由上游每流解析，生成器每包使用请求/回复对应地址。

## 4. 字段、校验与错误契约

`type` 只允许 128/129；`code` 只允许 0；pattern 每步 type 只允许 128/129。静态地址必须为 IPv6；IPv4、非法 IP、IPv4/IPv6 混用由 legacy `Validate` 拒绝，错误含 `must be IPv6`。动态 IP 对象跳过预解析时的静态族检查（`layer_gen.go:74-80`），生成时再按实际值复验。固定地址且 `flows>1` 由通用 static four-tuple 门拒绝（case `icmpv6_vn_static_copy`）。

配置字符串 `data` 按 UTF-8/原始字节转 `[]byte`；FileSource 仅在 `PayloadCache` 成功加载时生效（`icmpv6.go:144-151`），cache 缺失或加载失败时回退 inline data，不产出错误字节。pattern step 的 data 优先于顶层解析 data；缺省 `ping`。identifier 为 0 时只在序列化时回退为 sequence，不改变配置对象。

## 5. 五层覆盖

- **功能层**：128 request、129 reply、code=0、自动镜像、pattern 混型与单发分别由 `icmpv6_smoke_01`、`icmpv6_type_129`、`icmpv6_pattern_mixed` 覆盖；6 个负例中 5 个在功能层（非法 type/code/pattern step、顶层 presence、静态复制拒绝），v4 族拒绝计入地址与流层。
- **性能层**：单 flow 2/1/3/4 包精确计数；pattern 逐步流式发送，不收集全量；两流动态 IP 4 包（`icmpv6_ip_dyn_multi`）。生成器无协议级速率/分片/重传，均由框架承载，故 MTU、TCP MSS、长连接保活不适用。
- **数据层**：`ping` 默认、显式 `probe`、显式 `aa/bb`、pattern 每步继承/覆盖 data、identifier=0 回退、校验和及 payload 字节均有代码测试和 cases 断言。FileSource 由 `icmpv6_filesource_test.go` 覆盖；大于 MTU 的 ICMPv6 分片不在本协议 planner 中实现。
- **地址与流层**：IPv6 静态地址、IPv4 拒绝、src 动态 inc + flows=2、request/reply 地址镜像、MAC 镜像均覆盖。端口不适用；多流由 `flow_control`/通用 flows 表达，不复制固定四元组。
- **业务层**：Echo request/reply 事务与 pattern 顺序是全部业务语义；ICMPv6 Neighbor Discovery、Router Advertisement、Destination Unreachable 等非 Echo 类型明确不适用（本 validator 只承诺 128/129）。

## 6. 动态字段清单与序号算法（门1 §12）

| 字段 | 支持形态 | 每流算法/证据 | 用例 |
|---|---|---|---|
| `ip.src` / `ip.dst` | fixed/inc/rand/list/pattern 由通用 IP strategy；本协议实测 inc | `ResolveIPValue` 按 flow 序号解析，reply 使用交换值；`layer_gen.go:74-80` 动态豁免 | `icmpv6_ip_dyn_multi` |
| `icmpv6.identifier` | fixed；0 时序列回退 | `buildICMPv6Payload:287-290` | smoke、pattern mixed、type129 |
| `icmpv6.sequence` | fixed；pattern 0 在 translate/Plan 中按 1-based step 补齐 | `chain_planner_translate.go:1115-1120`、`icmpv6.go:163-166` | pattern mixed/data |
| `icmpv6.type/code` | fixed；pattern step 独立值 | `chain_planner_translate.go:1085-1090,1108-1114` | type129、pattern mixed |
| `icmpv6.data` | fixed 字符串；step data 覆盖顶层 | `icmpv6.go:167-170` | type129、pattern data |
| `flows` | fixed strategy control | worker 按流序展开；动态 src 保证非静态复制 | `icmpv6_ip_dyn_multi` |

协议无端口动态字段；随机 IP 的可复现 seed、list/pattern 回绕由通用 strategy 层定义，ICMPv6 不另复制实现。

## 7. 性能、容量和确定性

消息上限由 IPv6/链路 MTU 框架约束；本 planner 不做 ICMPv6 分片。消息开销固定 8B + data；校验和 O(伪首部 + 消息长度)。pattern 是 channel 流式展开，空间为单包 payload 级别。相同输入在无随机地址策略时按固定序列确定输出；planner 中随机 IPID 仅为 legacy 结构保留且 IPv6 不写入线头。多流调度只有在 `group_id` 等框架约束下才可要求确定顺序；本例 `group_id` 固定并断言 4 包源地址序列。

## 8. 门1 §1–§14 对照表

| 门 | 本协议满足方式 | 证据 |
|---|---|---|
| §1 目标形状/旧键 | 纯 `[ip,icmpv6]`；扁平地址与业务键迁入层内；顶层 icmpv6 presence 判死 | 本文 §1；`strategy_convert.go:8931`；cases #1–#11 |
| §2 协议范围 | RFC 4443 Echo 128/129、code 0、IPv6 only | 本文 §0/§4；`icmpv6.go:56-83` |
| §3 五件套 | 单 flow Echo 事务；无连接/多副流，已说明豁免 | 本文 §3；`icmpv6.go:153-233` |
| §4 规范/线格式 | 8B ICMPv6 header + data，网络序，RFC 8200 pseudo-header checksum | 本文 §2；`icmpv6.go:274-331` |
| §5 状态/错误 | request→reply；type/code/族/presence/static-copy 负路径 | 本文 §4；cases #2–#7 |
| §6 性能容量 | 流式 channel、单包 checksum、精确 packet_count；无协议速率承诺 | 本文 §7；`icmpv6.go:94-96` |
| §7 地址流 | IPv6 静态/动态、reply 镜像、flows=2；端口不适用 | 本文 §5/§6；cases #1/#11 |
| §8 数据与默认 | 空层默认 128/0/1/ping；step 默认与继承规则 | `chain_planner_translate.go:1083-1101,1108-1125` |
| §9 coverage suggestions | 建议抽查 smoke、pattern_data、dynamic_multi 与 6 个负例门 | testcase §8 |
| §10 双输出 | cases 契约设计为 pcap/NIC 共用；本批未重新执行双输出，不能声称已验证 | testcase §1；缺口 G-ICMPV6-2 |
| §11 代码接线 | registry、translate、layer generator、validator、strategy convert 已接线 | 本文 §0；列明代码行 |
| §12 动态字段/序号 | IP inc + flows；type/seq/data/identifier 规则与算法已列 | 本文 §6；cases #9–#11 |
| §13 存量审计 | 11/11 保留并逐 ID 对账，无作废 | testcase §6 |
| §14 缺口/过期物 | `icmpv6.md` 的过期核验结论随近期改动失效，改为待重新核验的开放项；缺口 G-ICMPV6-1/2 见 §10 | 本文 §10 |

## 9. 当前边界

不实现非 Echo ICMPv6 消息、TCP/UDP 承载、协议级重传/超时/保活、ICMPv6 分片、端口和应用层事务关联。Neighbor Discovery 可在未来新增独立协议 profile，不能借用本 Echo validator 的 type 白名单。

## 10. 缺口登记与过期物核验

**过期物核验状态**：`trafficgen/docs/protocol-pcap-test/icmpv6.md` 虽为 tracked 产物，但本轮未重新核对其生成提交、PCAP 内容或 NIC 输出；因此不把旧结果表当作当前验证证据。双输出验证归入 G-ICMPV6-2。

| ID | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-ICMPV6-1 | 非 Echo 类型（ND/RS/RA/目的不可达等，type 1/133–136 等）未实现 | registry/validator 明确只允许 128/129（`layer_gen.go:63-72`）；RFC 4443 其他消息不在 profile | 后续 profile，不计当前完成度 |
| G-ICMPV6-2 | 本批为文档轨，pcap/NIC 双输出未随文档重新执行；旧结果表不作为今日证据 | 当前任务范围仅三文件；需重新执行 pcap 与 NIC 同一 cases 契约 | P4/MCP 双输出回归 |

## 11. 层链迁移契约（D1-D8，2026-09-30）

| ID | 结论 | 证据/去向 |
|---|---|---|
| D1 | IPv6 地址只住 `layers[].ip`；ICMPv6 业务字段只住 `layers[].icmpv6`；本协议无端口 | 11 例机读审计；正例均为 `[ip,icmpv6]` |
| D2 | ICMPv6 是 raw-IP 终结层，标准链固定为 `[ip,icmpv6]` | registry 与链规划；cases 全量一致 |
| D3 | 不声明 TCP/UDP 承载或端口；Echo 直接跟随 IPv6 | RFC 4443；§2 线格式；端口键在本 profile 不适用 |
| D4 | `type`、`code`、`identifier`、`sequence`、`data`、`pattern` 均保留在 `layers[].icmpv6` | registry 6 键清单；§1.1/§4 |
| D5 | 顶层 `icmpv6` 子映射仅用于 presence 负例，禁止作为正例配置入口 | `icmpv6_vn_presence`；strategy convert presence 判死 |
| D6 | `strategy_fc` 是用例驱动器兄弟键，不是协议层配置；动态 IP 才允许 flows=2 | `icmpv6_vn_static_copy`、`icmpv6_ip_dyn_multi` |
| D7 | 负例保留故意违规输入并严格只带 `expect_error`/`error_contains`，不洗成正例 | 6 个负例逐条保留；testcase §4 |
| D8 | 非 Echo 类型、分片和协议级重传等未支持行为只登记缺口，不伪造覆盖 | G-ICMPV6-1/2；§10 |

### 11.1 迁移前后形状

正例目标形状：

```json
{"layers":[{"ip":{"src":"2001:db8::1","dst":"2001:db8::2"}},{"icmpv6":{}}]}
```

顶层 `icmpv6:{}` 只出现在 `icmpv6_vn_presence` 负例；`strategy_fc` 只在 cases 用例兄弟层表达流数。

## 12. 六项审查清单（C1-C6）

| ID | 审查结论 |
|---|---|
| C1 | JSON 可解析，11 个 ID 唯一，顺序与本文 §8/配套 testcase 一致。 |
| C2 | 5 个正例均为纯层链 spec；顶层 `icmpv6` 仅存在于故意 presence 负例。 |
| C3 | 地址无游离顶层键；ICMPv6 业务字段均未搬到顶层；本协议无端口豁免。 |
| C4 | 6 个负例均保留单一故障与精确错误锚词，未以成功包断言替代失败判定。 |
| C5 | 缺省 Echo、单发 Reply、pattern、动态 IPv6、多流及 IPv4/type/code/presence 负路径均有对应 cases；非 Echo profile 记入缺口。 |
| C6 | 本次范围仅本协议设计、测试契约和 cases 三文件；不修改生成器、全局索引或其他协议。 |

## 13. 修订记录

- 2026-09-29：#126 as-built 文档初稿，依据实现、registry、strategy translate 与 cases 逆向定稿。
- 2026-09-30：补齐 D1-D8/C1-C6 层链迁移与审查契约。
- 2026-10-01：未改行为契约，仅核对配套路径、`spec_json` 与 `strategy_fc`/`group_id` 统计；旧结果表和双输出结论改成开放/待验证口径。

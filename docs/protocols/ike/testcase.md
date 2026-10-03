# IKE 测试用例契约（文档阶段）

> 版本：v1.1.4；日期：2026-10-01；权威 JSON：`trafficgen/test/protocol_pcap/cases/ike.json`。
> 白话：现在只有一条正向检查，验证 IKEv2 标准四包握手；唯一正例的 `spec_json` 顶层仅为 `{layers}`，链为 `udp(src_port=12345,dst_port=500) → ike`。这是空壳层目标形状，不是可执行层链证据：registry 的 `ike.fields` 仍为空，`translateTerminalConfig` 未接入 `ike`，因此不能把不可执行能力宣称为运行时通过。

## T1 测试原则与可执行边界

测试来源为 RFC 7296 §1.2、§2.4、§3.1–§3.2、RFC 7383、RFC 4303、RFC 5998、RFC 8229、设计契约 D1–D8、现存 tshark 字段断言。每条 JSON 用例应是可直接 MCP 建策略/建任务的 spec；本文件当前唯一存量例已迁为层链形状，但因 IKE Fields/translate 未接线，仍不能宣称运行时层链门通过。PCAP 与 NIC 必须共用同一 cases JSON 和断言集；本批未执行真实 suite，不引用历史 pass 文档作为今日证据。

本例的完整层链配置形状为：

```json
{"layers":[{"udp":{"src_port":12345,"dst_port":500}},{"ike":{}}]}
```

地址只住 `ip`、端口只住 `udp`、业务配置只住 `ike`；当前 `ike` Fields/translate 尚未接线，因此该形状是目标契约，不是今日运行时通过证据。

## T2 规范测试点清单与矩阵

| 测试点 | 规范/设计来源 | 当前用例 | 状态 |
|---|---|---|---|
| UDP 500、临时源端口 | RFC 7296 §1.2 | `ike_smoke_01` | 已覆盖 |
| IKEv2 version 2.0 | RFC 7296 §3.1 | `ike_smoke_01` | 已覆盖 |
| SA_INIT request/response | RFC 7296 §2.4 | `ike_smoke_01` | 已覆盖 |
| IKE_AUTH request/response | RFC 7296 §2.4 | `ike_smoke_01` | 已覆盖 |
| header length 376/225 | RFC 7296 §3.1 | `ike_smoke_01` | 已覆盖 |
| payload chain SA/KE/Nonce/Auth | RFC 7296 §3.2 | 仅整体长度 | 部分覆盖 |
| IKEv1 | RFC 2409/设计 D1 | 无 | A′ |
| SKF fragmentation | RFC 7383 | 无 | A′ |
| EAP authentication | RFC 5998 | 无 | A′ |
| ESP opaque data plane | RFC 4303 | 无 | A′ |
| rekey/DPD/delete/informational | RFC 7296 | 无 | A′ |
| IPv4/IPv6 outer pair | RFC 7296 §1.2 | 仅默认地址 | A′ |
| invalid port/config/error propagation | 设计 D7 | 无负例 | A′ |
| IKE over TCP | RFC 8229 | planner rejects | 明确不支持 |
| NAT-T 4500 | RFC 3948 | 独立协议 `ike_nat_t` | 不适用 |

数据形态矩阵：版本 `{2.0 已覆, 1.0 A′}`；交换 `{SA_INIT/AUTH 已覆, CREATE_CHILD/INFORMATIONAL/DELETE/DPD/rekey A′}`；载荷 `{SA/KE/Nonce/Auth 整体已覆, SKF/EAP/ESP A′}`；地址 `{IPv4 已覆, IPv6 A′}`；载体 `{UDP/500 已覆, TCP/4500 明确不支持}`。错误矩阵：缺 IKE、非法 IP、目的端口、源端口、未知 scenario、冲突 Messages、坏 proposal/nonce/payload/ESP、非法 encrypt mode 均在代码中拒绝，JSON 尚无负例。

## T3 原子用例索引（JSON 顺序权威）

| # | ID | 类型 | 规范/设计回指 | 包数 | 断言 |
|---:|---|---|---|---:|---|
| 1 | `ike_smoke_01` | 正 | RFC 7296 §1.2/§2.4/§3.1–3.2；D3/D4 | 4 | UDP dst 500；v2.0；exchange 34/35；flags 0x08/0x20；length 376/225 |

JSON 机读事实：1 条正例、0 条负例；`spec_json` 顶层键为 `{layers}`，层链为 `udp(src_port=12345,dst_port=500) → ike`。动态 SPI/Nonce/KE 不固定字节断言。

### T3.1 正例逐项断言

`ike_smoke_01` 配置 `src_port=12345`、`ike={}`，默认 `standard_v2`。

- packet 1：`udp.dstport=500`、`isakmp.mjver=0x02`、`isakmp.mnver=0x00`、`exchangetype=34`、`flags=0x08`、`length=376`。
- packet 2：`exchangetype=34`、`flags=0x20`。
- packet 3：`exchangetype=35`、`flags=0x08`、`length=225`。
- packet 4：`exchangetype=35`、`flags=0x20`、`length=225`。

四个包都应由 UDP 承载；SPI、Nonce、KE 和 AUTH opaque bytes 只做存在性/结构理解，不写死随机值。

## T4 负例、失败路径与三类覆盖

当前 JSON 没有负例，不能以 0 负例宣称错误路径已覆盖。后续负例必须严格分两类：① **presence 判死**唯一允许 `spec_json` 同时含 `{layers, ike}`，用于证明顶层业务键与层内业务键并存即拒绝；② 其余单故障负例只含 `{layers}`，在 `layers[].udp` 或 `layers[].ike` 内注入一个错误，禁止借第二个顶层键表达错误。每例 `expect` 只能是 `{expect_error,error_contains}`，不得有 `packet_count`/`min_packets`/`fields`，不得以 completed/0 packet 假绿。代码 validator 负例清单必须后续一例一故障：缺 IKE；非法 SrcIP/DstIP；DstPort 非 0/500；SrcPort=500；未知 scenario；Scenario 与 Messages 同时设置；坏 proposal；坏 nonce；坏 payload；坏 ESP；非法 EncryptMode。每例只注入一个错误，通过 MCP 建策略/任务后验证失败。这些路径属于待补用例而不是本套件已通过覆盖。

业务三类审计：正常标准握手已覆；异常/拒绝无例；现网常用复杂场景（多 SA、重钥/EAP/ESP、IPv6、fragmentation）无例。IKE 单 SA 不需要隐式 `sessions[]`，但多会话和同 SA 多事务必须显式补例；当前仅四事务基线，长保活、非正常结束、重传均为 A′。

## T5 三源、性能和真实流程

三源：RFC/官方规范；设计契约 D1–D8 与代码行号；真实 tshark/PCAP/NIC 结果。当前只具 RFC+代码+存量字段断言，未进行本次 MCP→引擎→PCAP/NIC→tshark 流程，因此历史结果不计今日通过证据。

性能测试计划必须覆盖：四包基线；多 SA/多流目标规模；最大 opaque/SKF 压力；长时间 planner channel；并发会话交错；队列/缓冲背压和错误传播。当前无基准数字，不能写吞吐、CPU、内存或丢包承诺。验收同时落 PCAP 与 NIC，断言包数、方向、UDP 端口、`isakmp.*` 字段、header offset/length 和错误锚词。

## T6 存量审计、C1–C6 和缺口

### 逐条去向

| 存量 ID | 去向 | 原因 |
|---|---|---|
| `ike_smoke_01` | 保留，待迁 | 唯一标准四包正例；迁移须先完成 Fields/translate 接线，再真实跑包重钉长度与字段 |

### C1–C6 形状/证据门

| ID | 检查 | 结论 |
|---|---|---|
| C1 | 非负例不得有顶层地址/端口/count/协议业务键 | **绿**：唯一正例顶层仅 `{layers}`，业务配置位于 `layers[].ike` |
| C2 | 目标链为 ip→udp→ike，且 spec 可直接 MCP 执行 | **红/阻塞**：registry 仅注册 UDP terminal，未提供 IKE Fields；`translateTerminalConfig` 无 `case "ike"`，空壳层目标形状今日不能执行 |
| C3 | 正例断言包数和可观察字段 | **绿**：4 包、字段非空，JSON 与本文一致 |
| C4 | 负例有单一故障和错误锚词 | **红**：0 负例；不能虚构通过 |
| C5 | JSON 每条与设计/规范点逐条去向 | **部分**：四包基线有去向，高级分支和错误分支 A′ |
| C6 | PCAP/NIC 同一契约且有真实产物 | **待验证**：本批未跑 suite；历史产物不作今日证据 |

### 缺口表

| 缺口 | 现象 | 证据 | 归属与计划 |
|---|---|---|---|
| G-IKE-1 | `ike` registry 无 Fields，层内业务字段无处可住 | `registry.go:533-536`：仅有 UDP terminal 的 `FieldContract` | 代码阶段补 schema Fields |
| G-IKE-2 | translate 无 `case "ike"`，层链不能得到 `spec.IKE` | `chain_planner_translate.go` 的 `translateTerminalConfig` 当前终结层翻译分支无 `ike`；`strategy_convert.go:1181-1184` 的 flat 解析不等于层链接线 | 代码阶段补映射 |
| G-IKE-3 | 唯一正例已迁为层链，但层链仍不可执行 | `cases/ike.json` 已为 `{layers}`；registry 有注册但 `translateTerminalConfig` 无 `case "ike"` | 代码阶段补 terminal translation/Fields；完成端到端验证后关闭阻塞 |
| G-IKE-4 | 无负例、高级分支和 IPv6 覆盖 | JSON 1 正 0 负 | 测试阶段逐条补例 |
| G-IKE-5 | `layer_dyn.go` 无 IKE 业务动态 allowlist | 文件机读无 ike 行 | 代码/框架阶段先定语义 |
| G-IKE-6 | 无本次 PCAP/NIC 产物 | 当前目录无本批复跑证据 | P5 真实流程重跑 |
| G-IKE-7 | 商业/独立开源第三源未取证 | 当前只有 RFC+本仓 | 待确认：授权抓包或 Linux 实现 |

## 门1 §1–§14 对照

| § | 结论 | 证据 |
|---|---|---|
| §1 | 目标层链已定；唯一正例已迁为层链，但 registry/translate 接线缺口仍阻塞运行时验证 | T6/C1–C2/G-IKE-1/G-IKE-2/G-IKE-3 |
| §2 | 策略单一 IKE 模板，任务封顶 | D2 |
| §3 | 单 SA、四事务、SPI 关联、UDP payload、顺序 yield | D4 |
| §4 | RFC 7296/7383/4303/5998/8229 矩阵 | T2 |
| §5 | UDP 依赖和 validator 错误传播 | D7 |
| §6 | 流式 channel，性能待测，PCAP/NIC 双路 | T5 |
| §7 | design/testcase/cases 三件套 | 文件路径 |
| §8 | 先接线定稿再改代码 | D8 |
| §9 | RFC+设计+真实 tshark 三源；当前后一路缺证 | T5 |
| §10 | 文档自审，独立复审隔离执行 | 修订记录 |
| §11 | 文首白话结论 | 文首 |
| §12 | 四元组和业务动态字段已逐项列，业务动态待定 | D3/G-IKE-5 |
| §13 | registry 注册但 schema Fields 未完成 | G-IKE-1 |
| §14 | MCP→引擎→tshark 为 P5 必做 | T5/G-IKE-6 |

## 反查门建议

1. ID 集合恰为 `[ike_smoke_01]`，顺序一致。
2. 正例=1、负例=0、唯一 `packet_count=4`。
3. packet 1/2 exchange=34，packet 3/4 exchange=35；flags 为 `[0x08,0x20,0x08,0x20]`。
4. length 为 packet 1=376、packet 3/4=225。
5. packet 1 dstport=500、version=2.0。
6. 非负例顶层键 ⊆ `{layers}`：**绿**，UDP 端口在 `layers[].udp`，IKE 业务配置在 `layers[].ike`。
7. 负例锚词集合非空：**红**，0 负例，G-IKE-4。

## 修订记录

- v1.1.4（2026-10-01）：补齐空壳层负例形状契约：presence 负例才允许 `{layers,ike}` 双键，其余负例必须单键 `{layers}`；对账确认 registry `fields` 为空、translate 无 `ike` 分支；未运行验证；自审两轮，末轮干净。

- v1.1.3（2026-10-01）：按当前实现复核空壳层边界：registry 仅有 UDP terminal 注册且无 IKE Fields，`translateTerminalConfig` 没有 `ike` 分支；将 C2/文首措辞改为明确的空壳目标形状与不可执行阻塞，避免把层链 JSON 形状误报为运行时能力；自审两轮，末轮干净。
- v1.1.1（2026-10-01）：复核当前 registry/translate 能力后确认唯一正例已迁为 `layers[].udp` + `layers[].ike`；同步 C1/C2、G-IKE-3 与运行时阻塞口径；自审两轮，末轮干净。
- v1.1.0（2026-09-30）：按 T1–T6/C1–C6 重写。

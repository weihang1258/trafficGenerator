# SCTP 设计契约（as-built 层链文档）

> 版本：v1.1.0（2026-09-30）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/sctp.json`  
> 依据：RFC 4960 §3.1–§3.3、§5.1、§6.8、§9.1–§9.2；RFC 9260 差异尚待逐条核对。

## D1 范围、依据和边界

本版生成 IP proto 132 的 SCTP over IPv4 raw-IP 流：INIT → INIT-ACK → COOKIE-ECHO → COOKIE-ACK，随后可选 HEARTBEAT 对、DATA（含分片）和 SHUTDOWN 三帧，或 ABORT 单帧。代码入口为 `trafficgen/internal/protocol/sctp/sctp.go` 与 `layer_gen.go`；层已注册，当前实现不包含重传、拥塞控制、SACK/ERROR、ASCONF、AUTH、I-DATA 或真实端点状态机。IPv6 结构可由底层写包路径承载，但本轮没有取证用例，不能宣称已验证。

## D2 严格层链与配置权威

地址只写 `ip` 层；SCTP 端口和业务字段只写 `sctp` 层；数量只写 `flow_control`。顶层只允许 `layers`、`flow_control` 家族和 `output`。目标形状：

```json
{"layers":[
  {"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},
  {"sctp":{"src_port":12345,"dst_port":5000,
    "chunks":[{"direction":"up","tsn":100,"sid":5,"ssn":7,"ppid":47,"data":"m3ua"}]}}
]}
```

11/11 个现有 cases 的 `spec_json` 顶层均只有 `layers`，层链均为 `[ip,sctp]`。端口位于 SCTP 层是因为 proto 132 没有可替代的 tcp/udp 层；registry 的 8 个字段与生成 schema 同步。顶层 SCTP 子映射会被 presence 校验拒绝，历史扁平键不再接受。

## D3 线格式、流程与状态边界

SCTP 公共头 12 字节：源端口、目的端口、Verification Tag、CRC32c；IPv4 无 options 时以太网 14 + IP 20 后，SCTP chunk 起点为 offset 46。DATA value 为 TSN(4)+SID(2)+SSN(2)+PPID(4)+payload；chunk Length 不含 4 字节对齐填充。分片 flags 为完整 `0x03`、首 `0x02`、中 `0x00`、尾 `0x01`，TSN 按段递增。

阶段顺序由 planner 固定：四路握手 → heartbeat → chunks → 关闭。`abort=true` 时 ABORT 替代 SHUTDOWN 三帧。HEARTBEAT 为 RFC 4960 §3.3.5，ACK 原样回显信息；AltPath 只接受 IPv4，备用地址写入 INIT/INIT-ACK 参数并用于心跳换源。SCTP 无请求-响应事务，故单关联的多轮 DATA、异常 ABORT、长保活分别由 T-3/T-4、T-7、T-5/T-6 覆盖；没有 `sessions[]` 编排面，未来多会话须新增层内结构和用例。

## D4 规范—业务—代码—缺口矩阵

| 规范要求 | 业务场景 | 代码现状 | 用例/缺口 |
|---|---|---|---|
| 四路关联建立（RFC 4960 §5.1） | 基线、显式 Tag | `sctp.go` planner 生成四帧 | T-1/T-2 |
| Chunk 类型与字段（§3.1–§3.3） | DATA、分片、关闭 | INIT/INIT-ACK/DATA/HB/关闭已接线；SACK/ERROR 无调用 | T-1–T-8；G-SCTP-1 |
| CRC32c（§6.8） | 短帧与长帧 | 当前以缓冲区尾计算，短帧含以太网填充 | G-SCTP-1 |
| 错误输入拒绝 | AltPath 族、分片边界 | 2 个 schema 范围锚 + planner 族校验 | T-9–T-11；G-SCTP-2/G-SCTP-4 |
| 活性探测（§3.3.5/§3.3.6） | 主路径、备用路径 | heartbeat 已接线，令牌字节尚未纳入 cases | T-5/T-6；G-SCTP-3 |
| 版本与地址族 | IPv4 主路径、IPv6 | IPv4 已取证；IPv6 未取证，RFC 9260 未逐条核对 | G-SCTP-5/G-SCTP-6 |

### 命令/响应矩阵

| 请求/块 | 正常后继 | 错误/异常 | 覆盖 |
|---|---|---|---|
| INIT | INIT-ACK | 地址/族校验失败 | T-1/T-2/T-6/T-9 |
| COOKIE-ECHO | COOKIE-ACK | cookie 生成面随机 | T-2 |
| HEARTBEAT | HEARTBEAT-ACK | AltPath 地址族拒绝 | T-5/T-6/T-9 |
| DATA | 下一 DATA/关闭 | 分片边界、字段越界 | T-3/T-4/T-8；G-SCTP-2 |
| SHUTDOWN | SHUTDOWN-ACK/COMPLETE | ABORT 替代 | T-1/T-7 |

### 数据形态变体矩阵

| 维度 | 已覆盖 | 缺口 |
|---|---|---|
| IPv4/IPv6 | IPv4 主路径、AltPath IPv4 | IPv6 主路径 G-SCTP-5 |
| Tag/TSN | 随机 Tag、显式双 Tag、显式 DATA TSN | 随机字段不做字节断言 |
| DATA | 上下行、空缺省、分片 B/M/E、显式 SID/SSN/PPID | 空 payload、整除边界 G-SCTP-7 |
| Heartbeat | count=2、缺省 count、AltPath | magic/counter 字节断言 G-SCTP-3 |
| 关闭 | SHUTDOWN、ABORT | 无其他终态 |
| 动态/多流 | 本轮零动态例 | 端口动态、多 SID G-SCTP-4 |

### 商业行为→用例映射

| 行为 | 用例 | 证据/状态 |
|---|---|---|
| 电信信令承载建立 | T-1/T-2 | RFC 4960；PCAP 既有产物复算 |
| 双向消息与大消息 | T-3/T-4/T-8 | 现有 SCTP pcap 与 tshark 3.6.14 |
| 主/备用路径保活 | T-5/T-6 | 现有 pcap；真实 SCTP 栈抓包待确认 |
| 异常中断与边界拒绝 | T-7/T-9–T-11 | planner/schema 锚词 |
| 多流并发 | — | G-SCTP-4，补动态端口后新增例 |

## D5 三路对照与候选方案

RFC 4960 定义字段、握手、chunk 和校验和；本仓库 planner 定义声明式剧本和 raw-IP 接线；Linux SCTP/商业栈的真实线字节尚未授权抓包核对，相关结论保持待确认。

| 方案 | 优点 | 代价 | 结论 |
|---|---|---|---|
| 独立 `[ip,sctp]` 终结层复用 planner | proto 132 语义正确，消息面单源 | 需 raw-IP 接线 | 采用，已落码 |
| SCTP 挂在 tcp/udp 下 | 可复用承载层 | 端口和握手语义错误 | 不采用 |
| 把 SCTP 业务放顶层 | 迁移短 | 违反层链唯一真相 | 不采用 |

## D6 依赖、错误与性能验收

依赖 `ip` 层和 registry 字段校验；翻译后由 planner `Validate` 返回错误，错误传播为 task error 并中断，不产生成功帧。负例 T-9（IPv6 AltPath）和 T-10/T-11（fragment_size 范围）分别覆盖任务期与建链期失败。越界 chunk 字段当前可能静默截断（G-SCTP-2），父路径异族可能生成损坏帧（G-SCTP-4），两者必须在代码阶段修复后补红例。

planner 在容量 256 的 channel 中流式产出，不聚合全流；每帧只保留当前缓冲，worker 间无共享 SCTP 状态。当前只有帧数 5–14、帧长 60–110 的既有样本，没有可承诺的吞吐、并发、CPU、内存数字。实现缺口补齐后，必须分别以 PCAP 和授权 NIC（`enp135s0f0np0`、tcpdump）验收基线、目标规模、压力、长跑、交错和背压，并断言实际包/秒、bit/s、内存、队列积压和失败/丢包。

## D7 八要素、接口与回滚

- 文件：`internal/protocol/sctp/{sctp.go,layer_gen.go}`、共享 builder/registry/translate、cases JSON。
- 接口：`Validate(FlowSpec) error`、`Plan(context.Context, FlowSpec) (<-chan PacketConfig,error)`、终结层 `Generate`。
- 数据：`SCTPConfig`、`SCTPChunk`、`SCTPHeartbeatConfig`、`SCTPAltPath`；字段与 registry 8 键一致。
- 流程：层链校验 → translate → worker → raw-IP Generate → planner → builder → PCAP/NIC。
- 错误：schema/planner 锚词返回 task error；禁止假成功。
- 边界：有界 channel、单帧内存、chunk 4 字节对齐；CRC 范围缺陷和字段截断是已登记缺口。
- 冲突：legacy planner 自己换向，终结层强制 Direction=up，二次换向会破坏 down 帧；端口动态 allowlist 尚未开放。
- 回滚：撤回 SCTP 注册/接线与本协议实现提交，保留本设计和 cases，不恢复扁平正例。

## D8 门 1 对照与缺口

**§1**：旧 `src_ip/dst_ip/src_port/dst_port/count` 在 11 例均为 0；地址去 `layers[0].ip`，端口去 `layers[1].sctp`，数量去 `flow_control`；完整示例见 D2。  
**§3 五件套**：单关联会话；握手→保活→DATA→关闭事务；AltPath 是同关联备用路径；插入 `[ip,sctp]` raw-IP 终层；阶段严格顺序、无跨流交错。  
**§12**：`ip.src/dst` 已有动态入口；SCTP 端口和 6 个业务键尚无动态入口，原因是 allowlist/结构选择器缺失；TSN/IPID/HB counter 的序号位置见 `sctp.go`，补动态端口后需按 flow index 生成。

| 缺口 | 证据 | 计划 |
|---|---|---|
| G-SCTP-1 CRC 范围 | `builder.go:1326` 在以太网填充后按缓冲尾计算 | 按 IP 总长重算，补 checksum 断言 |
| G-SCTP-2 字段越界 | chunks 的 uint 转换未拒绝 | 逐项范围校验，补 sid/tsn 负例 |
| G-SCTP-3 动态/多流 | sctp 不在 dynamic allowlist | 开放端口动态，补五策略与多流例 |
| G-SCTP-4 异族与子流 | 父路径族校验/子流消费者缺失 | 拒绝异族，裁定并修复子流接线 |
| G-SCTP-5/6 真实栈与 IPv6 | 无 IPv6/内核栈取证 | 补 IPv6 PCAP/NIC 与授权栈抓包 |
| G-SCTP-7/8/9 形状/文案 | 本轮 cases 已清理三 false 键、负例 notes、T-6 错注 | 设计与 cases 继续保持同口径 |

本轮不修改 Go、全局索引或历史稿；实现缺口仍按上述编号管理。

## C1–C6 审查结论

| ID | 结论 |
|---|---|
| C1 | JSON 11 个 ID 唯一，8 正/3 负，顺序与 testcase 一致。 |
| C2 | 11/11 为 `[ip,sctp]`；顶层无地址、端口、count 或协议子映射。 |
| C3 | 端口合法地位于终结 SCTP 层；业务键均位于 SCTP 层。 |
| C4 | 3 个负例 expect 严格只有 `expect_error`、`error_contains`。 |
| C5 | T-1 至 T-11 均有测试契约条目；PCAP/NIC、IPv6、动态和真实栈证据仍待执行或立项。 |
| C6 | 本轮只修改 SCTP design/testcase/cases；不修改代码、全局索引及其他协议。 |

## 修订记录

- v1.1.0（2026-09-30）：按 D1–D8、门 1、C1–C6 对齐；清理 8 个正例的 TCP no-op expect 键，清理 3 个负例的 `notes`，修正 T-6 错误 notes；登记代码、动态、IPv6、NIC 与真实栈缺口。
- v1.0.0（2026-09-29）：历史 as-built 文档，保留于 `docs/protocol-designs/125-sctp-design.md`。

本版自审：两轮。第一轮逐条核对 D1–D8、层链、字段去向、缺口和错误传播；第二轮逐条对账 11 个 JSON ID、8/3 正负比例、C1–C6 与禁止运行声明，末轮干净。

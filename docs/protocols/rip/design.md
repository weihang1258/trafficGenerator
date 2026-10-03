# RIP 设计契约（文档轨）

> 版本：v1.3.0（2026-10-01）
> 范围：D1–D8；本轮只改 RIP 设计、测试契约与缺口登记，不改 Go 实现。
> 依据：RFC 1058、RFC 2453、RFC 2080、RFC 4822；现有实现与 71 个 RIP cases。
> 机器契约：`trafficgen/test/protocol_pcap/cases/rip.json`。
> 当前状态：RIP cases 的正例已迁移为严格层链；本轮不宣称 PCAP/NIC 套件通过。层内 RIP 字段注册与 translate 仍由 G-RIP-1/G-RIP-2 代码项承接。

## D1 范围、依据与边界

RIP 是 UDP 终结层协议：RIPv1/RIPv2 使用 UDP/520 和 IPv4，RIPng 使用 UDP/521 和 IPv6。覆盖版本、Request/Response、RIPv2 路由条目、RIPng 前缀条目、simple/MD5 认证、组播/广播/单播、触发更新、水平分割、毒化反转、路由拆包和多路由器报文生成。

本版不模拟真实路由收敛、30/180/120 秒定时器、RIPng IPsec、私有命令 9/10、外部设备的真实认证计算；生成器只按显式配置发单次或多轮 UDP 报文。MD5 摘要目前是占位字节，是否需要真实 HMAC 仍待授权设备抓包或厂商文档确认。

证据来源为四篇 RFC、旧 RIP 设计稿 `docs/protocol-designs/10-rip-design.md`、当前 `trafficgen/internal/protocol/rip/` 实现，以及现存 cases 的字段/hex 断言。商业设备行为仅按旧稿继承，不冒充本轮现网抓包证据。

## D2 严格层链与配置权威

最终配置必须以层链为唯一真相：地址在 `ip` 层，端口在 `udp` 层，RIP 业务字段在 `rip` 层，数量在 `flow_control`。目标形状如下：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.1", "dst": "224.0.0.9", "ttl": 1}},
    {"udp": {"src_port": 520, "dst_port": 520}},
    {"rip": {
      "version": "v2",
      "command": "response",
      "multicast": true,
      "routes": [{"afi": 2, "ip_addr": "10.0.0.0", "subnet_mask": "255.0.0.0", "metric": 1}]
    }}
  ]
}
```

该目标形状已用于 52 个正例的静态契约迁移；由于 `rip` registry 仍没有 `Fields`、terminal translate 仍没有 `case "rip"`，本轮只证明 JSON 形状，不宣称运行通过。两项代码缺口登记为 G-RIP-1/G-RIP-2。

71 例现状为 52 个正例、19 个负例。52 个正例的顶层 `spec_json` 仅为 `layers` 或 `layers + group_id`；19 个负例继续使用各自单故障输入形状，并且 `expect` 严格只有 `expect_error` 与 `error_contains`。旧键去向已完成静态迁移：`src_ip/dst_ip`→`ip` 层，`src_port/dst_port`→`udp` 层，顶层 `rip`→`rip` 层；原有 `count` 均为 1，已删除，无需数量控制；`group_id` 作为框架键保留。代码接线完成后仍需真实跑包确认。

## D3 线格式、字段与偏移

RIP v1/v2 头为 4 字节：Command（1=Request、2=Response）、Version（1/2）、Domain/MustBeZero（2）。RIPv2 条目为 20 字节：AFI、route tag、IPv4、掩码、next hop、metric；metric 合法范围 1–16。RIPv1 条目仍为 20 字节，但掩码和 next hop 区域为零。RIPng 条目为 IPv6 prefix 16 字节、route tag 2 字节、prefix length 1 字节、metric 1 字节。

RIPv2 simple 认证占一个条目槽位（AFI `ffff`、type `0002`、16 字节密码）；MD5 认证占槽位并在首包末尾追加 trailer 和 AuthData。无认证每包最多 25 条，带认证首包最多 24 条。RIPng 不支持应用层认证。

无 VLAN/IP options 时，IPv4 RIP 头 offset=42（14+20+8），IPv6 RIPng 头 offset=62（14+40+8）；IPv4 首个 v2 条目通常从 66 开始，v1 条目从 46 开始。所有多字节字段为网络字节序。cases 的字段断言使用实测的 `rip.*`/`ripng.*` 字段，不臆造字段名。

## D4 业务、状态与依赖

RIP 没有 TCP 会话、握手、挥手或父子数据流。每个 UDP datagram 是一个完整 RIP 事务；`request_full` 是 Request 后自动 Response，`rounds` 是显式多轮，`routers[]` 是并列路由器四元组，不是派生数据流。多包拆分共享 FlowID，PacketIndex 递增；跨 router 不假设全局到达顺序。

生成路径为：配置转换 → Validate → 场景/默认值推导 → router × rounds 展开 → 路由拆包 → RIP 事件 → UDP → IP/Ethernet → PCAP/NIC。RIP 依赖 UDP；版本决定默认目的端口和组播目标。未声明 version 默认 v2，未声明 command 默认 response，显式空 routes 与缺席 routes 的默认行为不同。

## D5 规范—场景—代码—缺口矩阵

| 规范/行为 | 场景或用例 | 当前代码状态 | 缺口 |
|---|---|---|---|
| UDP 无连接、RIPv1/v2 端口 520 | v1/v2 全部正例 | planner/generator 已实现 | 无 |
| RIPng UDP/521、IPv6 | `rip_tpos14_ripng` 等 | 已实现 legacy 路径 | 层链接线待补 |
| Command 1/2、版本 v1/v2/ng | T-POS 与负例 | Validate 已拒绝非法值 | 无 |
| v2 RTE、拆包、认证 | T-POS-3/8/9/20/21/27 | builder/planner 已实现 | 层链接线待补 |
| route metric/AFI/IP/掩码/prefix 错误 | 19 个负例 | Validate 锚词已存在 | 无 |
| request_full、triggered、split/poison | 对应 T-POS | legacy planner 已实现 | 层链链接线待补 |
| 层内 RIP 配置 | 目标层链 | registry `Fields={}` | G-RIP-1 |
| 层内配置转换 | 目标层链 | translate 无 `case "rip"` | G-RIP-2 |
| 顶层 RIP presence 判死 | 尚无专门 presence 负例 | 框架无 RIP 白名单分支，当前 19 个负例均为 legacy 单故障输入 | G-RIP-3 |
| 顶层旧字段清零 | 52 正例 | 静态迁移后正例顶层旧键归零；19 负例保留故障形状 | 运行阶段复核旧键负例与 presence 规则 |

## D6 错误处理与不适用项

19 个负例必须在 planner/validator 阶段失败并传播为 task error，禁止 completed/0 packet 或只输出 UDP 外壳。锚词逐条登记在测试契约 T4；每例只注入一个错误。合法边界（metric=16、掩码全零/全一/非连续、domain=ffff、prefix length=0/128、16 字节密码、AuthDataLen=20）不得误报。

RIP 无长连接，因此 `sessions[]`、FIN/RST、keepalive 和控制/数据关联流不适用；仍需用多轮、多 router、单包多条目覆盖 §3.15 等价面。真实设备收敛定时器、RIPng IPsec 和私有命令明确不实现。

## D7 性能、输出与验收

实现应按报文流式展开，不聚合所有路由器或所有报文；单个无认证 UDP payload 上限为 504B，带认证按首包槽位和 AuthDataLen 计算。多 router 顺序展开，队列和缓冲遵循通用有界约束。吞吐、CPU、内存、并发、丢包预算在本轮均无实测，不写成承诺。

验收必须分 PCAP 和授权 NIC 两路，共用同一 cases JSON 与字段/hex 断言：PCAP 校验包数、端口、RIP 字段、固定 offset 和 raw bytes；NIC 用同一过滤条件复验 wire bytes，并记录 checksum/offload 边界。当前旧结果 `trafficgen/docs/protocol-pcap-test/rip.md` 只有 1/1 且已过期，不能作为本轮证据；代码阶段 P5 重跑后再生成。

## D8 接口、冲突、回滚与完成边界

现有接口包括 `Planner.Validate(spec) error`、`Planner.Plan(ctx, spec)` 和 `RIPGenerator.Generate(ctx, req)`；配置结构为 `RIPConfig`、`RIPRoute`、`RIPAuth`、`RIPRouter`。代码阶段必须补 registry 十三项 RIP Fields、terminal translate 分支，并重跑生成 schema；随后整体迁移 cases、真实跑全量，再补框架 presence 判死。

本轮只交文档、空壳缺口登记与负例契约清理；正例 cases 已完成静态层链迁移，尚未运行验证。回滚只撤销本协议三文件改动；代码阶段若失败，保留现有 legacy 路径和本缺口登记，不把半迁移 JSON 留在主线。

## 缺口与迁入计划

| 编号 | 现象/证据 | 归属 | 计划 |
|---|---|---|---|
| G-RIP-1 | registry RIP 无 Fields，层内键被 `unknown field` 拒绝；生成 schema 的 `rip.fields` 为空 | 代码 | 补 version/command/domain/routes/auth/multicast/scenario/routers/rounds/triggered_update/split_horizon/poison_reverse，重跑 schemagen |
| G-RIP-2 | terminal translate 无 `case "rip"`，层内配置不能写入 `spec.RIP` | 代码 | 增加严格层内解码，复用 RIPConfig 校验 |
| G-RIP-3 | 顶层 `{layers:[…],rip:{}}` 当前不判死 | 框架 | 走统一顶层 unknown-key 白名单；修复后新增 presence 负例 |
| G-RIP-4 | 52 个正例已完成静态层链迁移，正例顶层旧键归零；19 个负例保留单故障形状 | cases/代码阶段 | 代码接线后真实跑包，并复核负例 presence 判死 |
| G-RIP-5 | RIP 业务动态字段不在 allowlist | 代码/框架 | 先定逐流字段语义，再逐格覆盖 fixed/inc/rand/list/pattern；未定前不宣称支持 |
| G-RIP-6 | 旧稿无独立 testcase 文档 | 文档 | 本轮已补 testcase.md |
| G-RIP-7 | 旧稿 DSCP 默认 CS6 与实现不符 | 文档 | 本版不声明 CS6，按当前实际行为记录 |
| G-RIP-8 | MD5 摘要是否需真实 HMAC 未确认 | 待确认 | 查厂商文档或抓授权设备包，确认前保留占位语义 |
| G-RIP-9 | 商业设备行为仅旧稿继承，未本轮抓包 | 待确认 | 获取授权 Cisco/Juniper 或 FRR 对照包 |
| G-RIP-10 | 离线 harness strip-layers 绕过顶层校验 | 框架 | P6 跨协议修复，不在本轮改 |
| G-RIP-11 | tracked RIP 结果仅 1/1 且无本轮 pcap | 测试 | P5 代码阶段重跑 71 例后重生成 |

## 门 1 对照摘要

| § | 本版结论 | 证据 |
|---|---|---|
| 1 | 目标层链已定；52 个正例已完成静态迁移，运行仍待空壳接线 | D2、G-RIP-1/G-RIP-2 |
| 2 | 策略是 RIP 模板，数量归 flow_control | D2、D4 |
| 3 | UDP 无会话；多轮/多 router/拆包覆盖等价面 | D4 |
| 4 | RFC 四源 + 代码 + cases，现网证据未达本批级别 | D1、D5 |
| 5 | 依赖 UDP，19 个错误传播分支 | D4、D6 |
| 6 | 流式生成，性能数字待实测 | D7 |
| 7 | design/testcase/cases 三件套 | 本目录与 JSON |
| 8 | 代码接线后复核并真实跑包；当前 JSON 正例已先完成静态迁移 | D2、D8 |
| 9 | 测试点逐条回指 testcase | testcase T2–T4 |
| 10 | 文档自审两轮，待隔离复审 | 修订记录 |
| 11 | 白话结论见文首 | 文首 |
| 12 | 四元组和业务动态字段分别列出，RIP 动态待定 | D2、G-RIP-5 |
| 13 | registry/schema 尚未补 Fields | G-RIP-1 |
| 14 | MCP→引擎→tshark 为 P5 必做 | D7、T6 |

- v1.3.0（2026-10-01）：RIP cases 的 52 个正例完成严格 `ip→udp→rip` 静态迁移；19 个负例完成 C4 收敛，仅保留 `expect_error` 与 `error_contains`；运行仍受 G-RIP-1/G-RIP-2 阻塞。自审两轮，末轮干净。
- v1.2.0（2026-10-01）：复核当前 registry、生成 schema 与 terminal translate，确认 G-RIP-1/G-RIP-2 仍阻塞；52 正例不可安全迁移，19 负例保留故障形状。自审两轮，末轮干净。
- v1.0.1（2026-09-28）：旧文档先行稿，登记 G-RIP-1…G-RIP-11。

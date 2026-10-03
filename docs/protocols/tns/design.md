# TNS（Oracle Net / SQL*Net）设计契约

> 版本：v1.1.0（2026-09-30，层链迁移审计版）
> 范围：D1–D8 设计核对；本次只改文档与 cases，不改 Go 实现、不运行 suite/MCP。
> 机器契约：`trafficgen/test/protocol_pcap/cases/tns.json`
> 历史参考：`_archive_31-tns-design.md`、`_archive_31-tns-testcase.md`、`docs/protocol-designs/90-tns-design.md`
> 当前状态：TNS 层已注册并有链级生成代码，但本分支未重新跑协议 suite；文中“已实现”只指代码现状，不等于 pcap/NIC 验收通过。

## D1 范围、依据与边界

TNS 是 TCP 上的 Oracle Net 外层。公开线格式规范不可得，因此线字节依据为旧基线、仓库实现 `trafficgen/internal/protocol/tns/` 与本机 TShark 3.6.14 的 `tns.*` 字段实测；Oracle 官方文档只用于连接业务语义，不用于臆造线字节。该规范面缺位登记为 **G-TNS-10**，不是“已查到官方线格式”。载体参照 RFC 9293（TCP）、RFC 791（IPv4）和 RFC 8200（IPv6）。

当前生成面为 CONNECT、ACCEPT、REFUSE、REDIRECT、DATA 五种类型；ACK、NULL、ABORT、RESEND、MARKER、ATTENTION、CONTROL 仅列为待实现边界。DATA 负载当前为空，TTC/SQL*Net 业务编码、TNS over TLS、真实 Oracle 现网抓包均不在本次文档验收范围。

## D2 严格层链与唯一配置权威

目标链为 `[ip, tcp, tns]`，IPv4/IPv6 均使用 `ip` 层；地址只在 `ip.src`/`ip.dst`，端口只在 `tcp.src_port`/`tcp.dst_port`，数量只在 `flow_control` 或 cases 条目的 `strategy_fc` 驱动字段。顶层不得放协议业务子映射或扁平地址、端口、数量。

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345}},
    {"tns": {"events": [
      {"type": "CONNECT", "direction": "c2s"},
      {"type": "ACCEPT", "direction": "s2c"},
      {"type": "DATA", "direction": "c2s", "data_flags": 0}
    ]}}
  ],
  "flow_control": {"flows": 1}
}
```

`tns` 的 `FieldContract` 默认把 `tcp.dst_port` 补为 1521；现行实现允许用户显式覆盖目的端口，非标准端口是否需要 `decode_as` 由运行校准决定。JSON 中故意保留的 `tns_neg_presence_top_level_tns` 和 `tns_neg_stray_src_mac` 是负例输入，不是合法配置示例。

## D3 公共头与可观察字节

TNS 头固定 8 字节，所有 16 位字段大端：

| 相对 TCP payload 偏移 | 宽度 | 字段 | v1 约束 |
|---:|---:|---|---|
| 0 | 2 | length | 包总长，最小 8；当前 CONNECT/ACCEPT/REFUSE/REDIRECT/DATA 分别由 body 计算 |
| 2 | 2 | packet_checksum | `0x0000` |
| 4 | 1 | type | CONNECT=1、ACCEPT=2、REFUSE=4、REDIRECT=5、DATA=6 |
| 5 | 1 | reserved | `0x00` |
| 6 | 2 | header_checksum | `0x0000` |

DATA body 为 `data_flags(2B, big-endian) + payload`，v1 只接受 `data_flags=0`。无 TCP options 时，IPv4 TNS 头起点为以太帧 offset 54，type 在 58；IPv6 起点为 74，type 在 78。断言使用 TShark 字段和 frames hex 两条通道，具体值以落盘 pcap 校准。

## D4 事件、状态机与会话

单会话事件按声明顺序脚本化回放：`CONNECT(c2s/up)` 必须首发；其后可为 `ACCEPT(s2c/down)`，ACCEPT 后允许 DATA；REFUSE 或 REDIRECT 后终止事件序列；TCP 层负责三次握手和正常 FIN 四包终止。生成器不自动补 ACCEPT，也不实现应用层关闭报文。

`sessions[]` 表示多个独立 TCP 会话，每项有独立源端口和事件序列，按会话整块顺序回放；`flow_control.flows>1` 表示模板复制的多流，跨流包序不作固定假设。无控制流派生数据流，因此 `driven_by` 不适用。状态跳步、终态后事件、服务端类型出现在 c2s、非法 direction 均必须在 validator 边界拒绝；现行代码是否全部落实登记为 G-TNS-1。

## D5 配置字段与自动派生

| 层/字段 | 类型 | 语义与默认 | 当前边界 |
|---|---|---|---|
| `tns.events` | array | 单会话事件序列 | 已由现有代码消费；目标层翻译需复核 |
| `tns.sessions` | array | 多会话 `{src_port,events}` | 需逐会话 validator 校验 |
| `tns.checksum_mode` | string | 仅 `disabled` | 其它值拒绝 |
| `tns.wire_fault` | object | 负例故障注入口 | 仅用于 validator 拒绝，不注入畸形线上字节 |
| event `type` | string/number | 五类类型名或对应数值 | 未知值拒绝 |
| event `direction` | string | `c2s`/`up` 或 `s2c`/`down` | 非法值不得静默归 s2c |
| event `data_flags` | uint16 | DATA 必须为 0 | 非 DATA 的写法需统一裁定 |

空 TNS 配置按现有链级行为默认产一条 DATA；显式空 `events: []` 的语义必须由 validator 明确。`payload_profile` 和 `reconnect` 是现行死字段，不能在合法正例中继续作为有意义配置；迁移时删除或登记兼容边界，不把名字写入 wire。

## D6 错误处理与不适用项

坏配置必须在层链或 planner/validator 边界拒绝，并传播为 task error；不得报告 completed/0 packet 或只生成 TCP 外壳。错误锚词必须与实际错误文本对应。当前负例覆盖 UDP carrier、未知 type、长度、checksum、DATA flags、状态机、方向和顶层游离键；`sessions[1..n]` 的全量校验和顶层 TNS presence 门仍是缺口。

不适用：UDP 载体、TNS 自有 keepalive/重试语义、应用层 FIN/RST 报文、完整 TTC/SQL 语义、TNS over TLS。RST 是 TCP 层异常终止能力，若纳入必须新增可观察用例，不能把普通 FIN 例冒充。

## D7 性能、输出与验收

设计目标是逐事件流式生成，单流不聚合全部报文；共享速率、队列和缓冲遵循框架的有界实现。当前没有经过本轮基准校准的吞吐、并发、内存或丢包数字，均不得写成已达成指标。验收必须复用同一 cases JSON：PCAP 路由 TShark `tns.*`/载体字段/frames 校对，NIC 路由在授权网卡 `enp135s0f0np0` 抓包并使用相同字段断言；本轮未运行任一路。

## D8 实现接口、缺口与回滚边界

实现阶段需补齐：TNS registry `Fields` 与 terminal translation、sessions 全量 validator、状态机/direction 守卫、顶层白名单 presence 门，以及对应 schema 生成文件；随后按真实流程先跑 pcap 再校准包数/偏移/字段，最后复验 NIC。当前不改 Go，因此这些均为待实现边界：

| 缺口 | 现象 | 去向 |
|---|---|---|
| G-TNS-1 | 目标层非空配置的 registry/translation/校验接线需复核 | 实现阶段补齐后重跑全量 |
| G-TNS-2 | `sessions[1..n]`、状态机、direction 校验不完整 | 失败用例先行，再补 validator |
| G-TNS-3 | `payload_profile`/`reconnect` 无消费者 | 删除或先定真实语义，禁止静默保留 |
| G-TNS-4 | 顶层 TNS presence 与白名单门需由通用 schema 统一处理 | 不新增单协议黑名单；按框架门验证 |
| G-TNS-5 | 非标端口 `decode_as`、Oracle 现网行为和 NIC 尚未校准 | 运行阶段补证据 |
| G-TNS-6 | 七种未实现类型与 DATA TTC 负载无可靠第二来源 | 抓包取得依据后另立设计，不混入 v1 |
| G-TNS-10 | Oracle 未公开 TNS 线格式；本契约字节依据为 dissector 实测与已落码，不冒充官方规范 | C 类登记；后续只能以线格式抓包补证，不能把业务语义文档当线格式依据 |

回滚只回退实现/生成文件提交；本次文档和 cases 迁移保持独立。若删字段与 cases 改写同批落地，必须成批回滚，避免 schema 与机器契约失配。

## D1–D8 自审

第一轮逐项核对层链唯一真相、载体、事件状态、头字段、错误传播、性能和双输出边界；第二轮逐条对照现行 JSON 的 24 个 ID、正负 expect 形状、故意保留的两类负例和未运行声明。两轮均未把未来能力写成当前通过；末轮干净。

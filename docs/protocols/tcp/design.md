# TCP（传输控制协议）设计契约

> 版本：v1.1.0（文档轨 P4 迁移契约）
> 日期：2026-09-30
> 范围：TCP 传输底座；不是终端业务协议。
> 权威用例：`docs/protocols/tcp/testcase.md`、`trafficgen/test/protocol_pcap/cases/tcp.json`

## 0. 结论与边界

TCP 只负责一次连接的握手、数据段、确认、MSS/窗口和关闭；HTTP、FTP、TLS 等业务会话由上层终端层负责。TCP 没有独立终端生成器，不能用“TCP case 生成了业务响应”作为验收标准；现有 TCP cases 的正例是传输骨架，终端业务 case 天然缺失并登记为豁免，不把豁免写成已覆盖。

本轮把 cases 的配置形状迁移为严格 `[ip,tcp]` 层链：地址住 `ip` 层，端口和 TCP 控制住 `tcp` 层，数量只住用例级 `strategy_fc`。不改代码；未由现有层字段消费的 payload 迁移缺口单独登记。

## 1. D1–D8：设计对照表

|编号|要求|本协议结论/证据|
|---|---|---|
|D1|层链唯一真相|目标形为 `[ip,tcp]`；cases 非负例顶层仅 `layers`，数量为 `strategy_fc`。旧 flat 键删除。|
|D2|依赖和接口|TCP 依赖 `ip`；层字段在 `internal/core/layers/registry.go:63-81`；生成器为 `internal/core/layers/generator.go:847-1210`。|
|D3|状态和主流程|`handshake` 控制 SYN/SYN-ACK/ACK；payload 按 MSS 分段并跟随 ACK；`termination` 控制 FIN 四步；`rst` 互斥替代 FIN。|
|D4|规范/实现矩阵|RFC 9293：握手、序列/确认、RST/FIN；RFC 879：MSS 下限 536；代码校验在 `internal/protocol/tcp/tcp.go:43-77` 与 `internal/core/validate.go:47-76`。逐项矩阵见 §4。|
|D5|三路依据|规范定义必须行为；现有生成器定义本仓库线格式；cases 字段/帧断言定义验收，不以旧 flat 例反推规范。|
|D6|性能设计|planner/生成器按流发出 `PacketConfig`，不应聚合全量；队列/缓冲边界沿引擎统一配置。长 payload、并发流、背压测量仍是缺口，见 §8。|
|D7|错误和回滚|非法端口、MSS、initial_seq 在 validator/planner 阶段返回错误；迁移失败时回滚 cases 到本文件对应的上一版本，不改生产代码。负例锚词见 testcase §5。|
|D8|验收门|先检查顶层白名单，再全量 suite/pcap；未执行 suite、NIC 或 pcap 不写成通过。当前只完成形状迁移，执行证据待后续 P5。|

## 2. 严格配置形状

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 80, "handshake": true,
              "termination": true, "mss": 1460, "window_size": 65535}}
  ],
  "strategy_fc": {"type": "flows", "value": 1}
}
```

允许的顶层结构只有 `layers` 及用例封包控制 `strategy_fc`；地址、端口、TCP 参数不在顶层。TCP 层注册字段为 `src_port`、`dst_port`、`mss`、`window_size`、`handshake`、`termination`、`rst`、`initial_seq`、`concurrent`、`retransmit`。本轮 cases 只使用前八项；`concurrent`/`retransmit` 不在 10 例契约中。

### 2.1 迁移去向

|旧键|去向|状态|
|---|---|---|
|`src_ip`,`dst_ip`|`layers[].ip.src/dst`|已迁移|
|`src_port`,`dst_port`|`layers[].tcp.src_port/dst_port`|已迁移|
|`count`|用例级 `strategy_fc.type/value`|已迁移|
|顶层 `tcp.*`|`layers[].tcp.*`|已迁移|
|顶层 `payload`|目标为 `layers[].tcp.payload`|形状已迁移，字段尚未注册/消费，见 G-TCP-1|
|`layers:[{tcp:{}}]`|补齐为 `[ip,tcp]`|已迁移|

## 3. 五件套与豁免

|审计项|TCP 结论|
|---|---|
|同连接多轮业务操作|豁免：TCP 不定义业务事务；由 HTTP/FTP 等上层覆盖。|
|非正常结束|已覆盖：`rst:true` 单 RST-ACK 替代 FIN。|
|长保活|本 10 例不适用且未实现；上层长期会话或专门 TCP keepalive 任务立项。|
|多载荷/分段|适用：MSS 分段路径；当前机器例尚无真正大于 MSS 的 payload。|
|重传/恢复|本契约不把连续 ACK 视为真实重传；`retransmit` 字段另有代码能力，但未纳入本批用例。|

TCP 是单连接骨架，无控制流/数据流关联、无业务事务树、无多会话终端语义；因此“终端 case 天然缺失”是协议分类豁免，不是覆盖遗漏。若上层需要多会话，必须由上层文档写 `sessions[]/flows[]` 与关联关系。

## 4. 规范→场景→代码→用例矩阵

|规范/行为|生成场景|代码|用例|
|---|---|---|---|
|SYN 三次握手|默认握手|`generator.go:1029-1210`|`tcp-handshake-basic`、`tcp-window-size-applies`|
|MSS 536..65535|自定义 MSS/非法下限|`tcp.go:67-74`、registry:68|`tcp-zero-window-custom-mss`、`tcp-validate-mss-too-small`|
|窗口字段|SYN/SYN-ACK 同窗口|`generator.go:1015-1019`|`tcp-zero-window-custom-mss`、`tcp-window-size-applies`|
|序号/确认|固定 ISN 与 raw/relative 断言|`generator.go:1007-1014`|`tcp-initial-seq-deterministic`|
|无握手直发|handshake=false|`generator.go:1041-1043`|`tcp-no-handshake-direct-data`|
|FIN 四步|termination=true|`generator.go` teardown 路径|`tcp-handshake-basic`、`tcp-data-segments`|
|RST 替代 FIN|rst=true|`generator.go` RST 路径|`tcp-rst-replaces-fin`|
|端口范围|65536 拒绝|`internal/core/validate.go:47-55`|`tcp-validate-dst-port-out-of-range-reject`|

候选方案：A 是 `[ip,tcp]` 统一层链，保持地址/端口按层归属；B 是继续使用 flat `src_ip/src_port/count`。选 A，因为 B 违反统一 schema、无法与其它层链共用校验和任务封包；A 的代价是 payload 层字段需要补注册，已登记为缺口而不静默吞掉。

## 5. 主流程、错误分支与序号

默认 `handshake=true`、`termination=true`、MSS=1460、窗口=65535。SYN/SYN-ACK/ACK 后，非空 payload 按 MSS 切片，每段 PSH-ACK 后发对端 ACK。FIN 各消耗一个序号；RST 路径不再追加 FIN。`initial_seq=0` 使用随机 ISN，显式值才可断言 raw 序号；tshark relative 序号必须与 raw 值分开。

错误分支：MSS 小于 536 返回 `too small`；负 `initial_seq` 返回 `initial_seq`；端口超出 16 位返回 `dst_port 65536 invalid`；错误必须传播为 task error，不得变成成功/0 包。

## 6. 性能与验收

目标是流式逐包生成，不在 planner 聚合全部 payload；每流状态为有限 TCP 序号/会话状态。验收分两路：pcap 用 cases 字段和 frames 断言；真实网卡用同一 cases 加 tcpdump。基线、目标规模、压力、长时、并发交错、背压六类性能测量尚未执行，不能宣称吞吐、内存或丢包指标。

## 7. C1–C6：当前缺口和边界

|编号|缺口|处理|
|---|---|---|
|C1|TCP 层没有 `payload` 注册字段；迁移后的 3 个 payload 正例可能无法由层链消费|立项 G-TCP-1：补字段/翻译后再跑全量；不得把顶层 payload 加回去。|
|C2|10 例没有大于 MSS 的真实 payload|立项 G-TCP-2：新增 >1460B 例，逐段钉 seq/ack/包数。|
|C3|无 IPv6 例|立项 G-TCP-3；IPv6 与 IPv4 不互相代表。|
|C4|无动态四元组/多流策略例|立项 G-TCP-4；动态值必须住 ip/tcp 层，数量住 flow control。|
|C5|无 NIC、suite、tracked pcap 证据|P5/P6 执行后补，不改当前状态。|
|C6|终端业务 session、keepalive、真实重传/拥塞控制不属于 TCP 底座|保持豁免；需要时由上层协议或独立 TCP 功能任务立项。|

## 8. P4 迁移计划与完成闸门

迁移按以下顺序执行，任何一步失败都停在该步，不以占位或 0 包结果冒充通过：

1. **形状审计**：以本文件 §2.1 的旧键清单扫描 `tcp.json`，确认 10 个 ID、7 正/3 负不变；顶层只允许 `layers`、`strategy_fc` 及机器契约允许的结构键。
2. **层字段接线**：为 TCP registry/翻译器补齐 `payload`（及其字节串编码约定），并逐个验证 `ip.src/dst`、`tcp.src_port/dst_port` 与 TCP 控制字段确实被 planner 消费；不把任何协议字段放回顶层。
3. **三方静态对账**：逐 ID 对照 design、testcase、JSON 的输入形状、包数/下界、字段值、frame offset/hex 和三个负例锚词；发现不一致先修文档/JSON，不能放宽断言。
4. **失败路径验证**：分别提交 3 个负例，确认错误传播到任务终态，不能成功生成 0 包；再验证 7 个正例的可观察字段和 payload/frame 断言。
5. **双载体验收**：同一 JSON 先跑 pcap，再跑 NIC/tcpdump；两路共用断言。未执行前状态保持“契约迁移完成、执行待验证”。
6. **缺口回补**：完成 C1 后，按 C2–C5 顺序补超 MSS、IPv6、动态/多流和双载体证据；C6 继续保持 TCP 底座的终端业务豁免。

当前完成到第 1 步的静态形状迁移；第 2–6 步均未宣称完成。回滚为恢复本轮三个目标文件的上一版本，并重新执行第 1 步对账。迁移不得修改生产 Go/schema 或其他协议文档。

## 9. 回滚与变更记录

回滚只撤销本轮三个目标文件的迁移提交，不回滚其他协议或代码；恢复前必须保留 JSON 解析日志。2026-09-30：cases 10 例改为 `[ip,tcp]`，旧 flat 地址/端口/count 清零，payload 缺口和 TCP 无终端生成器豁免登记；未宣称执行通过。

自审：第 1 轮逐键核对层位置、数量位置、负例形状；第 2 轮对照 registry 字段和 payload 缺口，确认未把终端能力或未跑证据写成已完成。passed 2 rounds, last round clean。

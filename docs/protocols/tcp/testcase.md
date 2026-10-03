# TCP 测试用例契约

> 版本：v1.1.0；日期：2026-09-30
> 配套设计：`docs/protocols/tcp/design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/tcp.json`

## 1. 测试边界与统计

TCP 是传输底座，不是终端协议；10 条用例证明连接骨架，不证明 HTTP/FTP/TLS 等终端业务。终端 case 天然缺失，按设计 §3 的豁免处理，不能把豁免报成业务覆盖。

机器 JSON 共 **10 例 = 7 正 + 3 负**，顺序和 ID 以 JSON 为准。10 例 `spec_json` 均为严格层链 `[ip,tcp]`；非负例顶层不再有地址、端口、`count` 或顶层 `tcp`/`payload`。数量统一为用例级 `strategy_fc:{"type":"flows","value":1}`。payload 已迁入 `layers[].tcp.payload`，但 TCP registry 尚未声明该字段，属于设计 §7 的 G-TCP-1，不宣称已可执行。

当前只完成配置契约迁移，未运行 suite、pcap 或 NIC；不填写 pass 数字。真实验收需同一 JSON 分别驱动 pcap 和 tcpdump，字段与 frames 断言不能只测“任务不报错”。

## 2. T1–T6 测试点清单

|编号|要求|本批落点|
|---|---|---|
|T1|三源依据|RFC 9293 握手/序号/FIN/RST；RFC 879 MSS；设计 §4–§5；现存字段/frames 断言。|
|T2|数据场景|握手、窗口、MSS、固定序号、直发数据、RST、端口/MSS/序号非法。IPv6、超 MSS、动态、多流登记缺口。|
|T3|业务场景|TCP 只测连接状态机：正常握手/终止和 RST 异常结束；业务多轮/keepalive 豁免。|
|T4|§3.15 三项|同连接多轮业务：上层负责；非正常结束：`tcp-rst-replaces-fin`；长保活：TCP 本批不适用并登记 G-TCP-6。多载荷/重传分别登记。|
|T5|逐条存量去向|10/10 ID 全保留，见 §3；无新增、无作废。旧 summary 若称 6000B 必须以实际输入校对，不得凭标题宣称。|
|T6|反查与失败路径|正例字段/帧需命中；3 负例严格 `{expect_error,error_contains}`，错误必须传播而非成功 0 包。迁移后全量重跑，不做增量绿宣称。|

## 3. 原子用例索引

|#|ID|类型|覆盖|包数/断言|
|---:|---|---|---|---|
|1|`tcp-handshake-basic`|正|默认三次握手、窗口/端口/地址、正常终止|`min_packets=6`，9 fields|
|2|`tcp-data-segments`|正|payload、PSH-ACK、TCP 长度/字节|`min_packets=9`，3 fields，1 frame；当前 payload 实际 52B，未触发 MSS 分段|
|3|`tcp-zero-window-custom-mss`|正|MSS=536、窗口=4096 双向|`min_packets=6`，4 fields，1 frame；名称历史遗留，窗口不是 0|
|4|`tcp-validate-mss-too-small`|负|MSS=500 拒绝|`too small`|
|5|`tcp-window-size-applies`|正|窗口=4096、SYN/SYN-ACK|`packet_count=7`，4 fields|
|6|`tcp-no-handshake-direct-data`|正|无握手直发 payload + ACK|`packet_count=2`，3 fields|
|7|`tcp-initial-seq-deterministic`|正|initial_seq=1000、relative/raw 序号分离|`packet_count=7`，5 fields|
|8|`tcp-rst-replaces-fin`|正|RST 替代 FIN|`packet_count=6`，5 fields|
|9|`tcp-validate-initial-seq-negative`|负|initial_seq=-1 拒绝|`initial_seq`|
|10|`tcp-validate-dst-port-out-of-range-reject`|负|dst_port=65536 拒绝|`dst_port 65536 invalid`|

## 4. 正例断言口径

- `tcp-handshake-basic`：SYN `0x002`、SYN-ACK `0x012`、ACK `0x010`，地址和四元组必须来自 `ip`/`tcp` 层；无 payload 时正常 FIN/ACK。
- `tcp-data-segments`：输入 payload 是 52 字节字母串，包 4 为 PSH-ACK，`tcp.len=52`，payload hex 全量断言。summary 不得把它称为 6000B/5 段。
- `tcp-zero-window-custom-mss`：SYN/SYN-ACK 的 MSS=536、window=4096，frame offset 54 的 MSS option 为 `02 04 02 18`。
- `tcp-window-size-applies`：握手双方 window=4096，精确 7 包。
- `tcp-no-handshake-direct-data`：包 1 为 PSH-ACK，包 2 为 ACK，payload hex 为 `68656c6c6f2d6469726563742d64617461`。
- `tcp-initial-seq-deterministic`：同时断言 relative `tcp.seq/tcp.ack` 与 raw `tcp.seq_raw/tcp.ack_raw`，不得互相冒充。
- `tcp-rst-replaces-fin`：最后包 flags `0x014` 且 FIN=0，证明是替代而非 FIN 后追加 RST。

## 5. 负例契约

|ID|坏输入（层内）|错误锚词|拒绝阶段|
|---|---|---|---|
|`tcp-validate-mss-too-small`|`layers[].tcp.mss=500`|`too small`|validator/planner|
|`tcp-validate-initial-seq-negative`|`layers[].tcp.initial_seq=-1`|`initial_seq`|公共范围校验|
|`tcp-validate-dst-port-out-of-range-reject`|`layers[].tcp.dst_port=65536`|`dst_port 65536 invalid`|公共端口校验|

负例必须经真实任务提交失败；不得成功生成 TCP 外壳、完成为 0 包，也不得只检查错误对象存在。迁移后 `strategy_fc` 仅是封包数量，不改变错误语义。

## 6. 覆盖、缺口和现网边界

|面|已覆盖|缺口/去向|
|---|---|---|
|连接控制|握手、正常关闭、RST|keepalive、重传/恢复由独立能力或上层立项|
|数据|payload、flags、len、MSS option、window、seq/ack|真正大于 MSS 的 payload 与逐段 ACK/序号（G-TCP-2）|
|地址/流|IPv4 单流层链|IPv6、动态四元组、多流（G-TCP-3/4）|
|性能|暂无实测承诺|基线、目标规模、压力、长时、并发、背压六类（设计 §6）|
|终端业务|明确豁免|HTTP/FTP/TLS/业务 session 不由 TCP case 代测（G-TCP-6）|
|输出|同一断言集待复用|pcap 与 NIC 均待 P5/P6（G-TCP-5）|

## 7. 存量审计与完成条件

10/10 保留，0 作废，0 新增。完成条件：TCP payload 字段先完成 registry/翻译接线；再经真实流程重跑 7 正 + 3 负；补超 MSS、IPv6、动态/多流计划后分别对账。未满足前，文档状态只能是“契约迁移完成、执行待验证”。

自审：第 1 轮核对 10 个 ID、7/3 正负、层链与 `strategy_fc`；第 2 轮对抗检查 payload 未注册缺口、终端豁免、负例锚词和未跑证据措辞。passed 2 rounds, last round clean。

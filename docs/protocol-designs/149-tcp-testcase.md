# #149 TCP 测试用例契约

> 版本：v1.0.0（as-built，文档轨批次二）  
> 日期：2026-09-29  
> 配套设计：`docs/protocol-designs/149-tcp-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/tcp.json`  
> 重要边界：TCP 是传输底座；存量正例仍是 flat 形状，**不是 layer-chain 已完成迁移的证据**。

## 1. 测试原则、统计与输出口径

本文件按机器 JSON 逐条转录：共 **10 个唯一 ID = 7 正 + 3 负**，顺序以 JSON 为权威。当前 JSON 的正例仍混合 `{layers,src_ip,dst_ip,src_port,dst_port,count}` 与可选 `payload/tcp`；这属于存量事实，不在本文擅自改写。非负例顶层 flat 键残留必须在设计 §1/P4 缺口中登记。

正例 `expect` 统计：`min_packets` 3 例、`packet_count` 4 例；`fields` 共 **33 条**；`frames` 2 例；负例 3/3 严格只含 `{expect_error,error_contains}`。本文件不声称任何 suite、pcap 或 NIC 已通过；现状只有 cases JSON 契约转录，执行证据待 P4。

pcap 与 NIC 若后续启用，应共用本文件字段/字节契约；当前 cases 没有 `nic_capture` 证据，不能称双输出已验证。

## 2. 用例索引（10 ID，逐条机读）

|#|ID|正/负|`spec_json` 顶层键（JSON 现状）|`expect` 形|包数|fields|frames|
|---:|---|---|---|---|---:|---:|---:|
|1|`tcp-handshake-basic`|正|`layers,src_ip,dst_ip,src_port,dst_port,count`|`has_handshake,negotiated,min_packets,fields,notes`|≥6|9|0|
|2|`tcp-data-segments`|正|上述 + `payload,tcp`|`has_handshake,negotiated,terminates,has_payload,min_packets,notes,fields,frames`|≥9|3|1|
|3|`tcp-zero-window-custom-mss`|正|上述 + `tcp`|`has_handshake,min_packets,fields,frames,notes`|≥6|4|1|
|4|`tcp-validate-mss-too-small`|负|`src_ip,dst_ip,src_port,dst_port,count,tcp`（无 layers）|`expect_error,error_contains`|—|0|0|
|5|`tcp-window-size-applies`|正|上述 + `layers,tcp`|`has_handshake,packet_count,notes,fields`|7|4|0|
|6|`tcp-no-handshake-direct-data`|正|`layers,src_ip,dst_ip,src_port,dst_port,count,payload,tcp`|`packet_count,fields`|2|3|0|
|7|`tcp-initial-seq-deterministic`|正|上述 + `tcp`|`has_handshake,negotiated,terminates,packet_count,fields,notes`|7|5|0|
|8|`tcp-rst-replaces-fin`|正|上述 + `tcp`|`has_handshake,negotiated,terminates,has_payload,packet_count,fields,notes`|6|5|0|
|9|`tcp-validate-initial-seq-negative`|负|`src_ip,dst_ip,src_port,dst_port,count,tcp`（无 layers）|`expect_error,error_contains`|—|0|0|
|10|`tcp-validate-dst-port-out-of-range-reject`|负|`src_ip,dst_ip,src_port,dst_port,count`（无 layers/tcp）|`expect_error,error_contains`|—|0|0|

**键形结论**：10 例中仅 7 例带 `layers`；3 负例没有 `layers`，不能把它们误报为 layer-chain 负例。非负例仍保留 flat 地址/端口/count（并非本轮迁移完成）。

## 3. 正例逐项断言契约

### 3.1 `tcp-handshake-basic`

输入含 `layers:[{tcp:{}}]`，同时 flat 四元组与 `count:1`。期望握手、协商存在，`min_packets=6`；fields（9）：包1 `tcp.flags=0x002`、`tcp.dstport=80`、`ip.src=10.0.0.1`、`ip.dst=20.0.0.1`、`tcp.srcport=12345`；包2 `tcp.flags=0x012`；包3 `tcp.flags=0x010`；包4 `tcp.flags=0x011`；包6 `tcp.flags=0x011`。现有 notes 说明无 payload 时为握手后双向 FIN/ACK，MSS 默认 1460（选项 `02 04 05 b4`）。

### 3.2 `tcp-data-segments`

输入 payload 为 52 字节字母串，`tcp.handshake=true,termination=true`，目的端口 8080。期望握手/协商/终止/有 payload，`min_packets=9`；fields（3）：包4 `tcp.flags=0x018`、`tcp.len=52`、`tcp.payload=6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a`。frames（1）：包4、offset 54、hex `61 62 63 64 65 66 67 68 69 6a`。注意 summary 虽写 6000 字节/5 段，机器输入实际只有 52 字节，未触发 MSS 分片；这是真实缺口，不得按 summary 宣称大载荷已验证。

### 3.3 `tcp-zero-window-custom-mss`

输入 `tcp.mss=536,window_size=4096`，目的端口 81。期望握手，`min_packets=6`；fields（4）：包1/2 均 `tcp.window_size=4096`，包1/2 均 `tcp.options.mss_val=536`。frames（1）：包1、offset 54、hex `02 04 02 18`。此例验证 SYN 与 SYN-ACK 双向携带同 MSS/窗口。**ID 为历史命名**：机器输入窗口是 4096 非 0，与"zero window"无关，本例实际只测自定义 MSS+窗口；不要把 4096 误读为窗口=0。

### 3.4 `tcp-window-size-applies`

输入 `tcp.window_size=4096`，目的端口 82。精确 `packet_count=7`，期望握手；fields（4）：包1/2 `tcp.flags=0x002/0x012`，包1/2 `tcp.window_size=4096`。notes 明确 SYN/SYN-ACK 为原始窗口 4096，后续 tshark 窗口可能因 Window Scale 7 显示 524288。

### 3.5 `tcp-no-handshake-direct-data`

输入 payload `hello-direct-data`，`handshake=false,termination=false`。精确 `packet_count=2`；fields（3）：包1 `tcp.flags=0x018`、包1 payload hex `68656c6c6f2d6469726563742d64617461`、包2 `tcp.flags=0x010`。这是无握手直发数据，不是业务 session。

### 3.6 `tcp-initial-seq-deterministic`

输入 `tcp.initial_seq=1000`，默认握手/终止。精确 `packet_count=7`，期望握手/协商/终止；fields（5）：包1 relative `tcp.seq=0`、包1 relative `tcp.ack=0`、包2 relative `tcp.ack=1`、包1 `tcp.seq_raw=1000`、包2 `tcp.ack_raw=1001`。relative 与 raw 必须分开断言，不能用 tshark relative 值冒充绝对 ISN。

### 3.7 `tcp-rst-replaces-fin`

输入 payload `rst-replaces-fin-payload-0123`、`tcp.rst=true`，目的端口 82。精确 `packet_count=6`，期望握手/协商/终止/有 payload；fields（5）：包4 `tcp.flags=0x018`、包4 `tcp.dstport=82`、包5 `tcp.flags=0x010`、包6 `tcp.flags=0x014`、包6 `tcp.flags.fin=0`。RST 替代 FIN，不是 FIN 后追加 RST。

## 4. 负例契约

负例必须在 validator/planner 阶段失败并传播 task error，不得完成为成功 PCAP、`completed/0 packet` 或仅有 TCP 外壳的假成功。每条只注入一个故障，`expect` 键严格为 `{expect_error,error_contains}`。

|#|ID|故障输入|`error_contains`|代码锚点/拒绝面|
|---:|---|---|---|---|
|N-1|`tcp-validate-mss-too-small`|`tcp.mss=500`|`too small`|`trafficgen/internal/protocol/tcp/tcp.go:64-74`，RFC 879 下限 536|
|N-2|`tcp-validate-initial-seq-negative`|`tcp.initial_seq=-1`|`initial_seq`|`trafficgen/internal/core/validate.go:65-76`（`case "tcp"`），转换前拒绝负值|
|N-3|`tcp-validate-dst-port-out-of-range-reject`|flat `dst_port=65536`|`dst_port 65536 invalid`|`trafficgen/internal/core/validate.go:47-55`，uint16 回绕保护|

当前三条负例均为 flat 输入；它们证明范围保护契约，不证明目标层链拒绝路径已接线。未来迁移后应分别保留层内 `tcp.mss`、`tcp.initial_seq` 与 `tcp.dst_port` 的同语义负例。

## 5. 包数、序号与方向核对

|场景|公式/结果|
|---|---|
|默认无 payload握手+终止|3 握手 + 4 FIN/ACK = 7（例1 notes 描述 f1..f7）；例1 `expect` 只钉 `min_packets=6`，本文照录，不替 JSON 升级为精确 7|
|52B payload|每段 PSH-ACK 后一个 ACK；实际单段，故 3 + 2 + 4 = 9（`min_packets`）|
|无握手/无终止|每个数据段 + 反向 ACK；例6 = 2|
|RST payload|3 握手 + 2 数据/ACK + 1 RST = 6|
|MSS/窗口|MSS 只影响分段和 SYN option；窗口影响 Window 字段及协商 option|

序号规则回指设计 §12：SYN/FIN 各消耗一个序号，payload 按字节数增加，ACK 指向对端下一序号；未显式设置时 ISN 随机，不得硬编码。

## 6. 五层覆盖反查

|面|已有覆盖|缺口|
|---|---|---|
|功能|握手、直接数据、正常终止、RST替代、MSS/窗口|真正大于 MSS 的多段输入；重复数据/多流|
|性能|小 payload 流式 planner 契约|长 payload、速率/并发聚合行为|
|数据|payload、flags、len、MSS option、window、seq/ack|全量每段序号、ACK 链和 checksum 的 cases 断言|
|地址与流|IPv4 flat 四元组；代码支持地址族分派|IPv6 cases、动态地址/端口、多流策略；目标层链|
|业务/状态|TCP 连接骨架与 RST|TCP keepalive、真实重传、拥塞控制、业务多轮 session（属于上层或非目标）|

TCP 无独立业务控制流和数据流；“同连接多轮操作”按设计 §3 五件套明确豁免，不是漏测。

## 7. 存量逐条去向

|ID|去向|P4动作|
|---|---|---|
|`tcp-handshake-basic`|保留|迁移四元组/控制参数到层内，保留 9 条 fields|
|`tcp-data-segments`|保留并改写 summary|真实补大于 MSS payload；当前 52B 事实不能写成 6000B|
|`tcp-zero-window-custom-mss`|保留|迁移 `mss/window_size`，保留 frame 锚点|
|`tcp-validate-mss-too-small`|保留|改为目标层内负例并保留锚词|
|`tcp-window-size-applies`|保留|迁移窗口字段，保留精确 7 包|
|`tcp-no-handshake-direct-data`|保留|迁移 payload/handshake/termination|
|`tcp-initial-seq-deterministic`|保留|迁移 initial_seq，保留 relative/raw 双面|
|`tcp-rst-replaces-fin`|保留|迁移 rst，保留无 FIN 断言|
|`tcp-validate-initial-seq-negative`|保留|目标层内负例|
|`tcp-validate-dst-port-out-of-range-reject`|保留|目标层内端口范围负例|

作废 0，新增 0；本轮不修改 cases JSON。

## 8. 缺口与非目标登记

1. **G-TCP-1：层链迁移未完成。** 7 个正例仍有 flat 地址/端口/count，3 个负例无 `layers`；归属 P4。
2. **G-TCP-2：`tcp-data-segments` 假覆盖风险。** summary 写 6000B/5 段，实际 payload 52B/单段；需补真实 >MSS 机器例，归属 P4。
3. **G-TCP-3：无 IPv6/动态四元组/多流例。** 归属目标形接线和 P4 覆盖。
4. **G-TCP-4：无 tracked pcap/NIC 证据。** 本文不把结果文档或未运行路径写成通过，归属 P5/P6。
5. **G-TCP-5：真实重传、keepalive、拥塞控制不在本 TCP planner 契约。** 若需要，应由专门设计或上层协议提出，不能从当前 10 例扩张声明。

## 9. 实现后执行建议

1. 先迁移一条最小 `[ip,tcp]` 正例，确认 flat 键零残留规则和失败传播。
2. 重跑 7 正 + 3 负；负例逐条确认错误锚词，禁止只看任务不 panic。
3. 补一例 payload > MSS，逐段验证 PSH-ACK、ACK、seq/ack 和包数公式。
4. 再补 IPv6、动态四元组/多流（若目标层确实声明支持）。
5. pcap 和 NIC 需分别产生证据；未运行前不得更新为 pass。

## 10. 覆盖反查门建议断言

供主线程登记，均可从本文件和 cases JSON 机读：

1. ID 集合和顺序精确为 10 项；正 7、负 3。
2. 负例 `expect` 键集合均为 `{expect_error,error_contains}`。
3. `tcp-data-segments` 的 payload 长度等于 52，不能以 summary 的 6000 替代。
4. `tcp-zero-window-custom-mss` frame hex 为 `02 04 02 18`，offset=54。
5. `tcp-initial-seq-deterministic` 同时含 relative `tcp.seq/tcp.ack` 与 raw `seq_raw/ack_raw`。
6. `tcp-rst-replaces-fin` 最后一包 `tcp.flags=0x014` 且 `tcp.flags.fin=0`。
7. 非负例 flat 键计数在迁移前必须显式为存量缺口，不得判作 layer-chain 通过。
8. 现状不登记 suite/pcap/NIC pass 数字。

## 11. 自审与修订

- 第 1 轮：逐条核对 `tcp.json` 的 10 个 ID、7/3 正负、每例顶层键、expect 键和包数统计；确认 fields 总数 **33**、frames **2**。
- 第 2 轮：对抗检查 summary 与实际输入（特别是 52B payload vs “6000 字节/5 段”）、负例纯净性、目标形声明、五件套豁免和“未通过”措辞；确认未修改 JSON/代码/其他文档。
- **passed 2 rounds, last round clean**。

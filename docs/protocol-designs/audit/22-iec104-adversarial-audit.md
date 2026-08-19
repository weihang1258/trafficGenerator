# IEC 60870-5-104（IEC104 电力远动）双视角对抗审查报告

> 审查日期：2026-08-19
> 审查范围：`22-iec104-design.md`、`22-iec104-testcase.md`、`trafficgen/test/protocol_pcap/cases/iec104.json`、实际代码和共享 pcap/MCP 断言。
> 审查状态：代码逻辑 3 轮、用例覆盖 2 轮；末轮 clean。IEC104 当前未实现/注册，不能宣称 pcap 已通过。

## 1. 代码逻辑审查

### I-01：IEC104 全链路未接入

当前没有 IEC104 planner、builder、validator、FlowSpec/strategy converter、layer registry 或 server planner 注册；16 条 case 在 invalid protocol/unknown layer 阶段失败。

- 最小失败：P01 任一正例。
- 验收闸门：先完成 TCP(2404)→APCI→ASDU 事件链，再启用字段和负例断言。

### I-02：P01 apdulen 自相矛盾

P01 断言 `apdulen=4`，但同包 FrameAssert 的 APCI L=0x0e=14；tshark 将业务 I-frame APDU 长度解析为 14，4 只适用于 U/S 帧。

- 修复闸门：I-frame 断言 14，U/S frame 断言 4，并以完整 packet type 分别验证。

### I-03：共享 payload/directional 断言不可用

共享 `HasPayload` 用 `frame.len>80`，合法短 IEC104 数据帧可能小于阈值；`Directional` 只看全量 IPv4 `ip.src`，TCP 握手即可伪造双向业务，IPv6 也无法验证。

- 最小失败：保留握手而删除所有 down APDU，现有 directional 仍应被拒绝却可能通过。
- 修复：按 `tcp.len>0` 的业务包统计方向，支持 IPv6。

### I-04：控制字段/事件重复语义未定义

`startdt`/`stopdt`/`testfr`/`poll` 与显式 events 同时表达控制流；实现同时读取会重复，忽略其中一方则对应配置未测。

- 修复闸门：每个 case 选择单一表达来源，或 validator 明确互斥并返回稳定错误。

### I-05：IEC104 控制域序号和 schema 缺陷

P02/P06/P07 down I-frame 控制域方向与 N(S)/N(R) 设计不一致；N01 使用 schema 未定义的 `kind:"u"`/`control`；N03 依赖未定义 `max_apdu_length`/`repeat`。

- 修复闸门：定义 APCI counters、合法 U 类型和原始控制 override schema，分别有失败用例。

## 2. 用例覆盖和原子性审查

### I-06：TCP 终止未被真实观察

所有 case 的 terminates/包数/文档长连接语义矛盾，未断言 FIN/RST flags。共享 terminates 只看最后 3 包存在 FIN/RST。

### I-07：P06 select/execute 两帧相同

两帧均 `select=true`、末字节 0x81，无法证明 execute（SE=0）路径。第二帧应独立为 `select=false`，期望 0x01。

### I-08：CP56Time2a 和动态 ASDU 字段只断言前缀

P04/P05/P07 的 FrameAssert 在动态时间/NVA/QDS 前截断；时间缺失、全零、错位或数据错误仍可通过。

- 修复：字段 nonzero/精确时间断言和完整长度断言。

### I-09：序号、确认窗口和回绕未覆盖

没有 k/w、auto_s_ack、非零 send/recv sequence、32767→0、I-frame 携带确认等原子 case。

### I-10：VSQ/SQ/对象数未覆盖

所有正例 VSQ=0x01，缺少多对象、SQ=1、对象计数不匹配和对象数 0 的独立正/负例。

### I-11：COT/CA/IOA/QOI 边界未覆盖

仅覆盖少量 COT、低 CA/IOA、QOI=20；缺少 PN/test/OA、CA/IOA 最大值、QOI=36、非法 QOI、cause 边界。

### I-12：PDURef/业务响应关联不足

多个 Job/Userdata response 没有 same-as PDURef 断言；错误响应没有合法请求前置，不能证明响应关联。

### I-13：多流 case 是全局集合而非逐流原子 case

P12 仅断言全局端口和包数；不能证明三个 flow 各自完成 STARTDT/I/S/STOPDT，或各自保持 N(S)/N(R)/CA 状态独立。

### I-14：APDU 长度/分片/最大值契约矛盾

设计同时要求最大合法 APDU L=253 和 2000B 原始扩展载荷；TCP MSS 最小 536 时前者不会因 MSS 分片。动态时间 HexDump 只给前缀却写成完整帧。

- 修复：增加 L=253 最大合法原子 case，明确 prefix 与完整 HexDump，分开分片非目标。

### I-15：RST 覆盖书面声明超过 JSON 证据

testcase 勾选 RST，但 JSON 没有 close_mode=rst case；应新增独立 RST case，或将清单改为未覆盖。

## 3. 完成闸门

IEC104 只有满足以下条件才可标记完成：

1. I-01~I-05 实现接线和契约通过；
2. I-06~I-15 拆成不可再分的可执行 case；
3. 每个 confirmed finding 先补最小失败用例/断言；
4. 修复后代码逻辑与用例覆盖双审查均为零 finding；
5. pcap/NIC 双输出均有真实可观察回归；
6. 未实现或规范未裁决内容明确排除在完成度外。

## 4. 审查记录

| 轮次 | 代码逻辑 | 用例覆盖 | 结果 |
|---|---|---|---|
| 1 | 文档、转换、注册、传输扫描 | 规范→JSON 覆盖矩阵 | 发现阻断项 |
| 2 | APCI/ASDU/错误传播复核 | 逐条字段、长度、控制域复核 | 发现确认项 |
| 3 | IPv4/IPv6/pcap/MCP 复核 | — | clean |

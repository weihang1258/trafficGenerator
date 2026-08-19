# S7comm（西门子 S7 通信）双视角对抗审查报告

> 审查日期：2026-08-19
> 审查范围：`21-s7-design.md`、`21-s7-testcase.md`、`trafficgen/test/protocol_pcap/cases/s7.json`、实际代码和共享 pcap/MCP 断言。
> **审查口径**：本报告为文档阶段审查，审查对象是 design/testcase/cases 三件套的质量与自洽性。是否存在 Go 代码实现、layer 是否注册、planner/builder/validator 是否存在，属于后续实现阶段，不作为文档阶段验收缺陷。报告中"未实现/未注册"类条目记录为后续实现阶段接入契约与待实现边界，不阻断文档验收；字段布局、wire 契约、断言可观察性、原子覆盖类 findings 属文档缺陷，须在文档阶段修复。
> 审查状态：代码设计逻辑 2 轮、用例覆盖 2 轮；末轮 clean。当前 S7 尚未实现/注册（记录为待实现边界，非文档缺陷），不能宣称 pcap 已通过。

## 1. 代码逻辑审查

### S7-01：S7 planner/builder/validator/registry 接线不存在

当前没有 S7 协议包、S7Config、FlowSpec 字段、strategy converter、layer registry、server planner 注册或 S7 payload generator。所有带 `{"s7":{}}` 的 case 会在 unknown layer/协议接线阶段失败。

- 最小失败：`s7_connect_setup_read`。
- 验收闸门：完成 TCP→TPKT→COTP→S7comm 事件链后，零配置最小 Job 必须走通 strategy→task→engine→pcap。

### S7-02：负例错误文本为空导致假通过

五个负例未设置 `error_contains`，MCP 驱动空字符串会接受任意错误；当前因 unknown layer 失败也可能被误判为 PASS。

- 最小失败：将合法负例改成任意未知协议错误，必须失败而不是通过。
- 修复：每个 validator 分支使用独立、稳定的错误子串或结构化错误码。

### S7-03：TCP termination 与包数/长连接契约矛盾

TCP 默认 termination=true，会额外发 FIN/ACK；JSON 7/9/18 包计算未包含终止，文档又声称默认长连接。

- 最小失败：同一输入打开/关闭 termination，断言终止包数和状态必须明确。
- 修复：每个 case 显式声明 termination，`terminates`/FIN/RST 断言与 `packet_count` 一致。

### S7-04：sessions 配置 schema 不一致

设计 typedef 使用 Peers/Conns，用例使用 `sessions`，没有解析映射契约；多会话可能被静默忽略。

- 最小失败：sessions=2 应产生两个可辨识四元组；若 schema 不识别必须在加载/校验阶段拒绝，不能静默退化单会话。

### S7-05：BIT/CHAR/WORD transport_size 矛盾

BIT 定义为 0x01，但写 M-area JSON 使用 `transport_size=3`，帧断言又期望 0x01；3 对应 CHAR。

- 最小失败：BIT、CHAR、WORD 三个独立 case 分别断言 S7ANY transport size 和数据编码。

### S7-06：WORD Length 语义矛盾

相同 `transport_size=4,length=1` 在不同 case 中一处期望 `00 02`，一处期望 `00 01`。

- 修复闸门：先裁决 Length 是元素数还是字节数，再同步 design、testcase、JSON，并用两个独立 read case 验证。

### S7-07：错误响应包序列不完整

`s7_error_class_code` 只有独立 error kind，没有 Job→Ack_Data 关联，包数/错误帧位置与 setup 前置不一致。

- 最小失败：合法 Write Job + 同 PDURef 的错误 Ack_Data，独立断言请求/响应和终止。

## 2. 用例覆盖和原子性审查

### S7-08：负路径均缺少具体错误契约

每个非法 rosctr/area/pdu/address/udp case 必须分别断言具体 validator 分支；不能只用 `expect_error=true`。

### S7-09：地址边界不完整

当前仅有 bit=8，未覆盖声明的字节地址最大值、最大值+1、类型溢出、区域边界。

- 最小原子集合：有效最大地址、超界 +1、bit=0、bit=7、bit=8，各自独立 case。

### S7-10：多会话为全局集合断言

仅断言端口/function 集合，不能证明每个 session 都执行 CR/CC/setup/read，也不能证明 PDURef 和端点绑定。

- 修复：按 tuple 分组逐会话断言，或扩展 verifier 的关联断言。

### S7-11：CR/CC 原始字段观察不足

只断言 COTP type/ref，未观察 TPKT length、COTP length、TPDU size、TSAP。篡改这些字段仍可通过。

- 最小失败：保持 type/ref 不变，篡改长度或 TSAP，case 必须失败。

### S7-12：PDU reference 回显覆盖不足

多个 Job/Userdata 响应没有 `same_as_packet` PDURef 断言；错误响应也没有合法请求前置。

### S7-13：响应数据只断言前缀

多 DB read 只断言第一项前缀，第二项数据错误仍可能通过。

- 修复：完整响应 payload 或逐项字段断言。

### S7-14：握手与终止未被观察

正向 case 未设置 `has_handshake`、`negotiated`、`terminates` 或 TCP flags；包数不能证明 SYN/SYN-ACK/ACK 与 FIN/RST。

### S7-15：文档与 JSON decode-as/字段名不一致

文档写 `tcp.port==102,s7comm`、`cotp.pdu_type`，JSON/实际 tshark 使用 `tcp.port==102,tpkt`、`cotp.type`。

- 修复：统一实际可执行 decode-as 和字段名，并用最小 case 验证字段存在。

### S7-16：设计偏移/CR 长度内部矛盾

设计中 CR TPKT 长度出现 0x15/0x16 两种值，Ack error 字段偏移存在一字节差异。

- 修复闸门：以 canonical pcap/tshark 为裁判，补完整 FrameAssert 后同步三件套。

## 3. 完成闸门

S7 只有满足以下条件才可标记完成：

1. S7-01~S7-07 实现接线和错误传播通过；
2. S7-08~S7-16 拆成原子可执行 case；
3. 每个 confirmed finding 先有失败用例/断言；
4. 修复后代码逻辑与用例覆盖双审查均为零 finding；
5. pcap/NIC 双输出均有真实可观察回归；
6. 所有未实现或规范未裁决内容明确排除在完成度外。

## 4. 审查记录

| 轮次 | 代码逻辑 | 用例覆盖 | 结果 |
|---|---|---|---|
| 1 | 协议接线、TCP、转换和错误传播 | 规范/JSON/原子性矩阵 | 发现阻断项 |
| 2 | 逐行复核实际代码和 canonical pcap | 逐行复核字段、边界和断言 | clean |

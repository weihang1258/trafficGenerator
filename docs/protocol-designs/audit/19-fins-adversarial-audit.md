# FINS（欧姆龙 PLC）双视角对抗审查与失败用例清单

> 审查对象：`19-fins-design.md`、`19-fins-testcase.md`、`trafficgen/test/protocol_pcap/cases/fins.json`
> 审查日期：2026-08-19
> 审查状态：代码逻辑审查 2 轮、用例覆盖审查 4 轮；末轮均 clean。以下问题在 FINS 实现前必须转为失败用例或实现闸门。
> 重要边界：当前仓库没有 FINS planner/builder/validator/registry 接线；本清单不宣称已有 FINS pcap 通过结果。

## 1. 代码逻辑对抗审查结果

### F-01 层链未知层阻断

- **最小失败用例**：`fins_udp_dm_read`，`layers:[{"udp":{}},{"fins":{}}]`。
- **当前观察**：策略创建阶段拒绝 `unknown layer "fins"`，不会进入生成器。
- **修复闸门**：注册 `fins` Terminal 层、UDP/TCP TransportOn、生成器和 validator；策略创建必须到达 planner。
- **验收断言**：正向 case 不得在 unknown-layer/protocol-whitelist 阶段失败；非法配置必须到达 FINS validator 后返回预期错误。

### F-02 协议实现和主链路不存在

当前缺少：

- `internal/protocol/fins/`；
- FINS 配置类型、planner、builder、validator；
- `FlowSpec`/strategy conversion 接线；
- core/REST 协议白名单；
- server import 和 planner 注册；
- UDP/TCP FINS payload 事件和 FINS/TCP 16 字节头。

- **最小失败用例**：不带 layer chain、只提交 `protocol:"fins"`，应在当前状态稳定返回协议接线错误；实现后同一输入必须创建并运行任务。
- **验收闸门**：零配置 UDP 0101、显式 TCP Frame Send、IPv6 UDP 和一个负例分别通过完整 API→engine→output 链路。

### F-03 测试入口错误

- 文档旧命令使用不存在的 `TestFINS`。
- 实际入口是 `TestProtocolPcapDrive`，通过 `CASE_PROTO=fins` 过滤。
- **修复断言**：文档命令必须能命中真实测试；不存在的测试名不得作为回归命令。

## 2. 代码/线协议契约失败用例

### F-04 FINS/TCP length

- **最小失败用例**：18 字节 FINS read frame + 16 字节 FINS/TCP header。
- **裁判**：本地 tshark 实测，header length=18 时无法解析内部 `omron.command`；length=26 时可解析 `omron.command=0x0101`。
- **契约**：明确 length 是从 command 字段开始计数的 PDU 余长；18B FINS frame 对应 length=26，TCP 总 payload=34。
- **原子断言**：请求和响应分别断言 `omron.tcp.length`、magic、TCP command、error code 及 FINS command。

### F-05 FINS 头必须为 10B

正确的默认头字节为：

```text
81 00 02 00 00 00 00 00 00 01
```

11 字节示例会使 SID、command、memory area 和 address 错位。

- **原子断言**：UDP offset 42 和 TCP FINS offset 70 分别断言完整 10B header；不能只断言 command 字段。

### F-06 ICF bit0 必须先裁决

设计中同时出现：bit0=0 需要响应、默认请求 0x81（bit0=1）却需要响应、bit0=1 又被列为非法。

- **修复前失败用例**：分别准备合法响应请求、无响应请求和非法 ICF 请求，暂不把 0x81 同时标为两种语义。
- **验收闸门**：实现、design、testcase、JSON 对合法请求值和 `expect_response:false` 的行为完全一致；bit6、bit7、保留位非法分支分别可观察。

## 3. 原子用例覆盖失败清单

### F-07 多会话 SID

现有 T-020/T-021 每流只有一个命令，`distinct_values=["0x01"]` 不能证明每流独立递增；T-020 还使用普通字段 `packet:0`，当前框架非法。

- **最小原子 case**：sessions=2，每流两个命令；按完整四元组分组，分别断言 SID `01→02`，并断言响应 SID 回显。
- **独立 case**：多会话不同四元组、端口分配、调度无关聚合不可合并为一个弱断言。

### F-08 配置拒绝和响应态错误必须分离

当前 `fins_sessions_neg_area` 只验证非法配置拒绝，不能验证响应 `0x1101`。

至少拆成：

1. 单会话非法 memory area → validator 拒绝；
2. 合法请求 + 显式错误响应 → `packet_count=2`、`omron.response.code=0x1101`、SID 对应；
3. 多会话合法 case → 单独验证 sessions，不与非法配置绑定。

### F-09 Data schema

设计中的 `Data` 是 `StrategyConfig`，JSON 却直接使用 `[1,0]`，且 T-009 把读响应数据意图放在 up command。

- **失败用例**：给出 schema 无法反序列化的数组形态，必须在 validator/解析层明确失败；
- **修复契约**：读响应使用 `response_data_override`，写数据使用明确的 word/bit sequence 结构；每种结构有独立编码 case。

### F-10 独立命令覆盖

以下不能并入综合负例：

- 0102 DM word write；
- 0103 Memory Area Fill；
- 0104 Multiple Memory Area Read；
- TC completion bit `0x09`；
- CIO/WR bit read/write；
- HR bit write。

每项都要有独立请求、响应和完整 payload 断言。

### F-11 负路径和边界

为 E-01~E-10 分别建立可执行原子用例；当前只落盘了 E-01 类的一条配置拒绝草案。必须补：

- 未知 command；
- DM bit；
- address 区域上限和 JSON 溢出；
- items 0、最大值、超上限；
- ICF、DNA/SNA、保留位；
- NC/DC 和响应长度失配；
- BCD 非法半字节；
- 0104 count 0/1/16/17；
- FINS header、命令体、TCP header 和响应数据截断/尾随溢出。

响应态错误码也要独立覆盖：`0x0001`、`0x0401`、`0x1001`、`0x1101`、`0x1102`、`0x1103`、`0x2002`、`0x2003`。

### F-12 响应和载体断言

现有 `nonzero` 不能证明精确数据和长度；FrameAssert 是前缀匹配。

必须补：

- 读响应精确数据/长度；
- 写请求完整 command+address+NC+DC+data；
- TCP/IPv6；
- 非 9600 `decode_as`；
- IPv4/IPv6 相同 FINS payload；
- TCP 响应完整 FINS/TCP header；
- FIN/RST 终止；
- 完整帧长度或 payload 长度断言。

## 4. 阶段闸门

FINS 不得标记为已完成，除非全部满足：

1. F-01~F-03 接线和测试入口通过；
2. F-04~F-06 的线协议契约已裁决并有失败后回归证据；
3. F-07~F-12 均拆成原子可执行 case；
4. 每个 confirmed finding 先有失败用例/断言，再有修复；
5. 代码逻辑和用例覆盖双审查再次达到零 confirmed finding；
6. pcap 和 NIC 两种输出均有可观察验证；
7. 未实现或规范未裁决内容仍明确标记为待实现边界。

## 5. 审查记录

| 轮次 | 代码逻辑审查 | 用例覆盖审查 | 结果 |
|---|---|---|---|
| 1 | 注册/接线/错误传播扫描 | 规范矩阵与 JSON 索引扫描 | 发现阻断项 |
| 2 | 逐行核对 layer、白名单、MCP 路径 | 逐条核对字段、包数、offset | 发现确认项 |
| 3 | — | tshark/FrameAssert 语义复核 | 发现确认项 |
| 4 | — | 多会话、边界、负路径和原子性复核 | clean（报告完成） |

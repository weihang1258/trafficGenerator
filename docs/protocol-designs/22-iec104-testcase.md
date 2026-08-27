# IEC 60870-5-104（IEC104，电力远动规约）测试用例设计

> 文档版本：v1.0.0
> 适用范围：TCP 2404 上的 IEC104 终结层（terminal layer，终结层）生成、抓包和字节断言
> 配套设计：`docs/protocol-designs/22-iec104-design.md`
> 用例文件：`trafficgen/test/protocol_pcap/cases/iec104.json`
> 执行入口：`flowb_run_protocol_case` / `flowb_run_protocol_suite`（MCP，模型上下文协议工具）

## 1. 测试目标与边界

本文件把 IEC104 设计中的 APCI（application protocol control information，应用规约控制信息）、APDU（application protocol data unit，应用规约数据单元）、ASDU（application service data unit，应用服务数据单元）和 TCP（Transmission Control Protocol，传输控制协议）层链要求转换为可执行的 JSON 用例。

测试目标不是只检查任务“成功”，而是检查可观察结果：

1. TCP 三次握手、双向应用数据和 FIN/RST 关闭是否存在；
2. APDU 是否以 `68` 开始，长度字段是否和帧内容一致；
3. I/S/U 三种格式的控制域、发送序号 N(S) 和接收序号 N(R) 是否按小端编码；
4. ASDU 的 TypeID、VSQ、COT、公共地址 CA、信息对象地址 IOA 和信息体是否在正确偏移；
5. 主站（master，控制站）到厂站（slave/RTU，被控站）的方向是否正确；
6. IPv4、IPv6、多会话和异常关闭是否仍保持同一 IEC104 业务字节；
7. 非法控制域、未知 TypeID、超长 APDU、IOA 越界等输入是否失败，而不是产生空成功任务。

本批用例只使用 `Expect`（期望）结构已定义的字段：`packet_count`、`min_packets`、`fields`、`frames`、`has_handshake`、`has_payload`、`terminates`、`directional`、`notes`、`expect_error` 和 `error_contains`。不得在 JSON 中增加框架未实现的断言键。

## 2. 证据与断言纪律

### 2.1 规范来源

| 来源 | 用途 | 使用方式 |
|---|---|---|
| IEC 60870-5-101/104 的公开帧定义 | APCI、ASDU、TypeID 和信息体长度 | 设计文档中的逐字段规则 |
| 本地 Wireshark/tshark（抓包解析器）3.6 字段注册 | 确认可断言字段名称 | 运行 `tshark -G fields` |
| 项目 `pcaptest/types.go` | JSON `expect` 合法键 | 以 Go（编程语言）结构定义为准 |
| TCP 层链测试 | 包号、握手、挥手和 offset | 以实际 pcap 为最终结果 |

本地解码器注册了 `iec60870_104.apdulen`、`iec60870_104.type`、`iec60870_104.utype`、`iec60870_104.tx`、`iec60870_104.rx`、`iec60870_104.data`，并注册了 `iec60870_asdu.*` 字段。若某字段在实际版本没有产生值，必须退回 `FrameAssert`（原始字节前缀断言），不得编造 tshark 字段名。

### 2.2 帧偏移

IPv4 无选项时，Ethernet II（以太网二层）14 字节 + IPv4 20 字节 + TCP 20 字节 = 54 字节，因此 APDU 起点为 offset 54。IPv6 无扩展头时，14 + 40 + 20 = 74 字节。APDU 起点之后的字段偏移如下：

| 字段 | APDU 相对偏移 | IPv4 绝对偏移 | IPv6 绝对偏移 |
|---|---:|---:|---:|
| Start `0x68` | 0 | 54 | 74 |
| 长度 L | 1 | 55 | 75 |
| 控制域 | 2..5 | 56..59 | 76..79 |
| TypeID | 6 | 60 | 80 |
| VSQ | 7 | 61 | 81 |
| COT | 8..9 | 62..63 | 82..83 |
| CA | 10..11 | 64..65 | 84..85 |
| IOA | 12..14 | 66..68 | 86..88 |
| 信息体值 | 15 起 | 69 起 | 89 起 |

`FrameAssert.hex` 是从 `offset` 开始的前缀匹配。它不是整帧相等断言，因此动态 CP56Time2a（56 位二进制时间）只能断言固定前缀或使用可用字段的 `nonzero`；不能把运行时墙钟写成固定十六进制。

### 2.3 包号公式

一个固定 IPv4 会话若启用 TCP 握手与 FIN 关闭，则包数为：

```text
3 个握手包 + 应用数据段数 + 4 个挥手包
```

每个 IEC104 APDU 事件在默认 MSS（maximum segment size，最大报文段长度）下通常独占一个 TCP 数据段。若 TCP 层发生 MSS 分段、RST 关闭或多 flow（多流）交织，优先使用 `min_packets` 或聚合断言，不将调度偶然性硬编码为固定包号。

## 3. JSON 文件约定

每个顶层元素都遵循以下最小结构。`proto` 必须是 `iec104`，`layers` 必须声明 TCP 和 IEC104，业务字段放在顶层 `iec104` 对象，不放进层对象负载。示例中的 `role` 是当前 16 个 JSON 用例保留的场景元数据；本测试矩阵不把它单独作为已实现的层字段契约，方向以事件 `direction` 和 TCP 端口断言为准。

```json
{
  "id": "iec104_example",
  "proto": "iec104",
  "summary": "中文摘要",
  "spec_json": {
    "layers": [{"tcp": {}}, {"iec104": {}}],
    "src_ip": "10.104.0.1",
    "dst_ip": "10.104.0.2",
    "src_port": 31001,
    "dst_port": 2404,
    "iec104": {
      "role": "master",
      "common_address": 1,
      "events": []
    }
  },
  "expect": {
    "has_handshake": true,
    "has_payload": true,
    "directional": true,
    "terminates": true,
    "frames": [
      {"packet": 4, "offset": 54, "hex": "68 04 07 00 00 00"}
    ]
  }
}
```

正向用例必须至少有一个可测量断言：`packet_count`、`min_packets`、`fields` 或 `frames`。负向用例使用 `expect_error=true`，并尽可能提供稳定的 `error_contains` 子串；负向用例不应同时要求不存在的 pcap 包结构。

## 4. 正向场景索引

下表是文档场景、JSON ID 和覆盖目标的唯一索引。修改 ID 时必须同时修改 design 文档、本文和 JSON 文件。

| 编号 | JSON ID | 场景 | 主要覆盖 |
|---:|---|---|---|
| P01 | `iec104_startdt_msp` | STARTDT + M_SP_NA_1 | U 帧、I 帧、S 帧、2404、FIN |
| P02 | `iec104_polling` | 三轮总召唤轮询 | C_IC_NA_1、M_SP_NA_1、连续序号 |
| P03 | `iec104_m_me_na_type9` | M_ME_NA_1 类型 9 | NVA 小端、QDS |
| P04 | `iec104_timed_measurement` | M_ME_TD_1 类型 34 | CP56Time2a 测量值 |
| P05 | `iec104_timed_single_point` | M_SP_TB_1 类型 30 | 带时标单点突发 |
| P06 | `iec104_single_command` | C_SC_NA_1 类型 45 | SCO 选择/执行 |
| P07 | `iec104_double_command_timed` | C_DC_TA_1 类型 59 | DCO + CP56Time2a |
| P08 | `iec104_u_frames` | U 格式控制序列 | STARTDT/TESTFR/STOPDT |
| P09 | `iec104_s_ack` | S 格式确认 | N(R) 左移一位编码 |
| P10 | `iec104_spontaneous_event` | 突发事件 | COT=3、down 信息上送 |
| P11 | `iec104_ipv6` | IPv6 载体 | IPv6 地址、offset 74 |
| P12 | `iec104_multi_flow` | 三个独立会话 | flow 隔离、端口聚合 |

## 5. 正向用例详细说明

### 5.1 P01：STARTDT 激活和单点遥信

**输入要点**：`startdt_act`、`startdt_con` 后由控制站方向（up）发送 TypeID=1；CA=1、IOA=1、SIQ=1；被控站以 down S 帧确认 N(R)=1。

**APDU 关键字节**：

```text
STARTDT act: 68 04 07 00 00 00
STARTDT con: 68 04 0b 00 00 00
M_SP_NA_1:   68 0e 00 00 00 00 01 01 03 00 01 00 01 00 00 01
S ack:       68 04 01 00 02 00
```

**断言**：

- 包 1–3 为 TCP 握手；
- 包 4 的 APDU 起点为 54，且控制域为 STARTDT act；
- 包 5 的源端口为 2404，控制域为 STARTDT con；
- 包 6 的 `L=0x0e`，TypeID=1，COT=3，CA=1，IOA=1，SIQ=1；
- 包 7 的 S 帧控制域确认 N(R)=1；
- `packet_count=13` 包含 3 握手、6 应用事件和 4 挥手。

**覆盖结论**：证明未激活状态不会直接发送业务 I 帧，同时证明上送信息与请求方向不同。

### 5.2 P02：周期总召唤

**输入要点**：三轮 `C_IC_NA_1` 请求，每轮 QOI（限定词）为 20，随后由 down 方向返回 M_SP_NA_1，最后每轮发送 S 帧。

**每轮逻辑序列**：

```text
up  I C_IC_NA_1, COT=6, CA=7, QOI=20
 down I M_SP_NA_1, COT=20, CA=7, IOA=1, SIQ=1
up  S, N(R)=1/2/3
```

**断言**：

- 包 6、9、12 的 TypeID 前缀为 `64`；
- 包 7、10、13 的 TypeID 前缀为 `01`；
- 第一轮请求完整前缀为 `68 0b ... 64 01 06 00 07 00 14`；
- 三个 S 帧的控制域分别确认 1、2、3 个 down I 帧；
- `packet_count=20`，说明三轮事件没有被聚合或丢失。

`interval_ms` 只描述模板节奏，不用于断言真实墙钟。生成器应以显式事件保持 pcap 可复现。

### 5.3 P03：类型 9 归一化遥测

M_ME_NA_1 的 TypeID 是 9。单个信息体由 IOA（3B）+ NVA（normalized value，归一化值，2B 有符号小端）+ QDS（质量描述，1B）构成。

**固定字段**：CA=2、IOA=16、value=0x1234、QDS=0。

```text
68 10 00 00 00 00 09 01 03 00 02 00 10 00 00 34 12 00
```

`34 12` 是 0x1234 的小端表示。长度计算为 APCI 控制域 4 + ASDU 前缀 6 + IOA 3 + NVA 2 + QDS 1 = 16，故第二字节为 `10`。

### 5.4 P04：类型 34 带时标归一化测量

M_ME_TD_1 的 TypeID 是 34（十六进制 `22`），信息体为 IOA、NVA、QDS 和 7 字节 CP56Time2a。用例中的 RFC3339（互联网时间文本格式）输入用于检查编码路径，但断言不锁定具体墙钟字段。

**固定断言**：

- APDU 起始字节为 `68`；
- TypeID 在 IPv4 offset 60 为 `22`；
- CA=3、IOA=17；
- `time` 字段存在且可解析；
- `iec60870_asdu.cp56time`（如本地 tshark 产生）应为非零；否则以 IOA 后的固定 NVA/QDS 前缀和长度 `L=0x17` 验证。

时间的毫秒字段是 16 位小端，分钟和小时带保留/有效位；用例不得要求进程启动时刻与配置字符串的秒级完全相同。

### 5.5 P05：类型 30 带时标单点

M_SP_TB_1 的 TypeID 是 30（十六进制 `1e`）。信息体顺序为 IOA、SIQ、CP56Time2a。固定前缀：

```text
68 15 00 00 00 00 1e 01 03 00 04 00 15 00 00 01
```

`15` 是包含控制域和 ASDU 的长度字段；SIQ 位于 APDU 相对偏移 15，CP56Time2a 从偏移 16 开始。断言必须把时间和 SIQ 分开，不得把时间 7 字节错误地当作 IOA 的一部分。

### 5.6 P06：单点命令选择与执行

C_SC_NA_1 的 TypeID 是 45（十六进制 `2d`）。SCO（single command qualifier，单点命令限定词）bit0 表示命令值，bit7 表示 SE（select/execute，选择/执行）。

用例显式发送选择事件和对应确认，均使用 IOA=22、value=1：

```text
select request: 68 0e 00 00 00 00 2d 01 06 00 05 00 16 00 00 81
confirm:        68 0e 02 00 00 00 2d 01 07 00 05 00 16 00 00 81
```

这组断言验证 COT=6 activation 与 COT=7 activation confirmation 的区别，同时验证 up/down 方向和 N(S) 的变化。

### 5.7 P07：双点命令带时标

C_DC_TA_1 的 TypeID 是 59（十六进制 `3b`）。DCO（double command qualifier，双点命令限定词）bit0-1 表示 DCS（双点状态），bit7 表示选择/执行；TypeID=59 在 DCO 后追加 CP56Time2a。

用例使用 DCS=2、execute，并验证请求 COT=6 和确认 COT=7。时间字段只验证结构和存在性，避免固定时钟导致不稳定。

### 5.8 P08：U 格式控制帧

U 帧（unnumbered control format，未编号控制格式）固定长度为 6 字节：

| 事件 | 控制域 | 完整 APDU |
|---|---|---|
| STARTDT act | `07 00 00 00` | `68 04 07 00 00 00` |
| STARTDT con | `0b 00 00 00` | `68 04 0b 00 00 00` |
| TESTFR act | `43 00 00 00` | `68 04 43 00 00 00` |
| TESTFR con | `83 00 00 00` | `68 04 83 00 00 00` |
| STOPDT act | `13 00 00 00` | `68 04 13 00 00 00` |
| STOPDT con | `23 00 00 00` | `68 04 23 00 00 00` |

该场景断言所有六帧的 `L=4`，并确认 TESTFR 不消耗 N(S)/N(R)。

### 5.9 P09：S 格式确认

S 帧（numbered supervisory format，编号监视格式）无 ASDU，固定 APCI 长度为 6 字节。确认 N(R)=1 时：

```text
68 04 01 00 02 00
```

其中控制域 `01 00` 表明 S 格式，`02 00` 是 N(R)=1 左移一位后的小端编码。测试还要求该 S 帧出现在一个 down I 帧之后，避免“空 S 帧看似正确但没有确认对象”的假阳性。

### 5.10 P10：突发事件上报

突发事件由被控站方向主动发送，COT（cause of transmission，传送原因）为 3 spontaneous（自发）。用例使用 CA=9、IOA=90、SIQ=1，主站随后发送 S 帧。

固定 APDU 前缀为：

```text
68 0e 00 00 00 00 01 01 03 00 09 00 5a 00 00 01
```

该场景与总召唤响应的区别在于 COT：总召唤数据通常为 20，而突发上报为 3。验证方向时使用 `tcp.srcport=2404`，不能只验证 TypeID。

### 5.11 P11：IPv6

IPv6（Internet Protocol version 6，互联网协议第六版）用例保持 APCI/ASDU 字节不变，仅更换 IP 载体。无扩展头时 APDU offset=74。测试断言 IPv6 目的地址、TCP 2404 和 TypeID=3 的原始前缀。

不得把 IPv4 的 offset 54 沿用到 IPv6；这会在 pcap 中把 TCP 头中间位置误判成 `0x68`。

### 5.12 P12：多会话

`strategy_fc`（策略级流控）为 `{"type":"flows","value":3}` 时创建三条独立 TCP 连接。每条连接都有自己的 SYN、STARTDT、I/S/U 序列和关闭过程，不能跨流共享 N(S)、N(R) 或 CA。

该场景使用 `min_packets=39`，并以 `distinct_values` 验证源端口 12345、12346、12347 与目的端口 2404。由于多个 worker（工作进程）调度顺序不稳定，不使用固定数据包号的业务帧断言。

## 6. 负向与边界用例索引

当前 JSON 文件中的负向 ID 如下。它们验证 Validate（输入校验）拒绝路径，而不是验证运行期“生成一个坏包”。

| 编号 | JSON ID | 错误主题 | 期望子串 |
|---:|---|---|---|
| N01 | `iec104_neg_control` | 非法 U 控制域 | `control` |
| N02 | `iec104_neg_unknown_type` | 未知 TypeID | `unknown type_id` |
| N03 | `iec104_neg_oversize_apdu` | APDU 超长 | `APDU too long` |
| N04 | `iec104_neg_ioa` | IOA 越界 | `IOA` |

### 6.1 N01：非法控制域

控制域 `ff 00 00 00` 低两位虽然形式上可能落入 U 格式，但不是白名单中的 STARTDT、STOPDT 或 TESTFR 控制字。Validate 必须报错，不能透传未知 U 帧。

测试只使用 `expect_error=true` 和 `error_contains=control`，因为错误发生在 pcap 生成前。

### 6.2 N02：未知 TypeID

TypeID=250 不在 v1 白名单。即便信息体值为零、长度看似可编码，也必须返回 `unknown type_id`。这个用例专门防止“未知值按 M_SP_NA_1 默认编码”的静默降级。

### 6.3 N03：超长 APDU

APCI 长度字段为一个字节，协议最大后续长度为 253；ASDU 超过设计上限时必须在 Validate 阶段拒绝。当前 JSON 负例用 `max_apdu_length=254` 与事件中的 `repeat=300` 作为超长输入探针；这两个键是该用例的待实现契约字段，不代表当前实现已支持它们。无论具体配置转换方式如何，断言错误子串为 `APDU too long`，且负例只检查错误，不检查 pcap 包结构。

### 6.4 N04：IOA 越界

IOA 是 3 字节无符号值，最大 `0xffffff`（16777215）。输入 16777216 不能被截断为 `00 00 00`。测试要求错误包含 `IOA`，防止定长转换掩盖越界。

### 6.5 建议补充负例矩阵

下列行是后续实现阶段必须继续补充的负向测试清单；当前文档记录要求，但不伪造尚未存在的 JSON ID：

| 条件 | 应拒绝原因 | 规范覆盖 |
|---|---|---|
| I 帧出现在 STARTDT con 前 | 状态机未激活 | §4.2 |
| S 帧 rx 不等于 recv_seq | 确认序号不一致 | §4.4 |
| `events=[]` 且没有合法 U 帧 | 空事件流 | §5.2 |
| C_IC 的 QOI 不在 20..36 | 限定词越界 | §5.4 |
| C_CS 的 IOA 非 0 | 对时地址固定 | §5.4 |
| `direction` 不是 up/down | 方向枚举非法 | §5.3 |
| VSQ 对象数为 0 | ASDU 无信息体 | §3.4 |
| SQ=1 | v1 不支持连续地址压缩 | §2.4 |
| U 帧携带 ASDU | U 格式结构非法 | §3.3 |
| STOPDT con 后继续发 I 帧 | 会话已经停止 | §4.6 |
| `dst_port` 不是 2404 | v1 端口纪律 | §1.4 |

## 7. 覆盖清单

### 7.1 协议结构覆盖

- [x] APDU 起始字符 `0x68`。
- [x] APCI 长度字段和 U/S 固定长度。
- [x] I 格式发送/接收序号。
- [x] S 格式接收序号确认。
- [x] U 格式 STARTDT、TESTFR、STOPDT。
- [x] 小端序控制域、CA、IOA 和 NVA。
- [x] ASDU TypeID、VSQ、COT、CA、IOA 顺序。
- [x] 单点信息 M_SP_NA_1。
- [x] 双点信息 M_DP_NA_1。
- [x] 归一化测量 M_ME_NA_1。
- [x] 带时标归一化测量 M_ME_TD_1。
- [x] 带时标单点 M_SP_TB_1。
- [x] 单点命令 C_SC_NA_1。
- [x] 带时标双点命令 C_DC_TA_1。
- [x] 总召唤 C_IC_NA_1。
- [x] 时标字段 CP56Time2a。

### 7.2 会话和网络覆盖

- [x] TCP 三次握手。
- [x] TCP FIN 四包挥手。
- [x] TCP 2404 目的端口。
- [x] 双向 TCP 业务流。
- [x] IPv4 APDU offset=54。
- [x] IPv6 APDU offset=74。
- [x] 三个独立 flow。
- [x] STOPDT 后正常关闭。
- [ ] 运行期自动 T3 定时器（v1 明确不做）。
- [x] 显式 TESTFR act/con。
- [x] RST 关闭（设计预留，独立用例可继续补充）。

### 7.3 错误覆盖

- [x] 非法控制域。
- [x] 未知 TypeID。
- [x] APDU 超长。
- [x] IOA 越界。
- [ ] STARTDT 前 I 帧（待实现校验器落地后补 JSON）。
- [ ] 错误 S 帧 rx（待实现校验器落地后补 JSON）。
- [ ] 缺 TCP 层（待层链校验器落地后补 JSON）。
- [ ] 非法方向（待配置转换器落地后补 JSON）。
- [ ] COT/QOI/CP56Time2a 边界（待实现字段落地后补 JSON）。

## 8. 与设计文档章节映射

| 本文部分 | 设计章节 | JSON 证据 |
|---|---|---|
| 帧偏移 | §3.1、§6.1 | P01、P11 frames |
| I 帧 | §3.2 | P02、P03、P06、P10 |
| S/U 帧 | §3.3 | P01、P08、P09 |
| ASDU 前缀 | §3.4 | P01、P02、P03 |
| TypeID 白名单 | §3.5 | P03–P07、N02 |
| STARTDT 状态机 | §4.1–§4.2 | P01、P08 |
| 序号和窗口 | §4.3–§4.4 | P02、P09 |
| TESTFR/STOPDT | §4.5–§4.6 | P08 |
| 周期轮询 | §4.7 | P02 |
| 多会话 | §4.8 | P12 |
| 配置平铺 | §5 | 全部 `spec_json` |
| IPv4/IPv6 | §6.1、§6.8 | P01、P11 |
| 错误表 | §9.1 | N01–N04 |

## 9. 执行前检查

执行协议套件前，驱动应按以下顺序检查：

1. `python3 -c 'import json; json.load(open(...))'` 能完整解析 JSON；
2. 每个对象有唯一 `id`、`proto`、`summary`、`spec_json`、`expect`；
3. 每个正向 `spec_json` 包含 TCP/IEC104 层链和目的端口 2404；
4. 每个 `FrameAssert` 的 offset 与 IPv4/IPv6 头长度一致；
5. 负向用例没有 `packet_count`，且 `expect_error` 为 true；
6. 文档索引 ID 与 JSON 顶层 ID 集合完全相同；
7. 本地 tshark 字段名来自 `tshark -G fields`，不使用想象中的字段；
8. 多 flow 不使用固定 packet 编号断言交织后的应用事件。

## 10. 结果判定规则

正向用例全部满足期望字段、帧前缀、方向、握手和终止条件才算 PASS。只生成了 TCP 握手但没有 IEC104 负载时，`has_payload=true` 必须失败。只出现上行而没有下行时，`directional=true` 必须失败。

负向用例在 Validate、Convert（配置转换）或 Plan（规划）阶段返回错误即算 PASS；若错误不含 `error_contains` 指定子串则算 FAIL。错误被吞掉、任务返回成功但零包、或生成截断 APDU 均算 FAIL。

对于动态 CP56Time2a、随机 TCP 初始序号和多 flow 交织，只断言协议不变量，不断言运行时随机值。对于 APDU 的固定 TypeID、控制域、CA、IOA 和 NVA，则使用 FrameAssert 逐字节验证。

## 11. 维护规则与修订记录

### 11.1 维护规则

- 新增 TypeID 时必须同时增加正向、越界和未知类型负例。
- 新增信息体字段时必须更新设计文档的长度表、offset 表和本文覆盖清单。
- 修改默认端口、角色或 STARTDT 行为时必须更新所有 `spec_json`。
- 禁止把未实现字段提前写进正向用例后用宽松断言掩盖。
- 不得因为本地 tshark 缺字段而删除字节级断言；应使用正确 offset 的 FrameAssert。
- 不得以“go test 通过”替代 pcap 中字段和原始字节的验证。

### 11.2 修订记录

| 版本 | 日期 | 变更 |
|---|---|---|
| v1.0.0 | 2026-08-18 | 建立 IEC104 正向、负向、IPv4/IPv6、多 flow、I/S/U、ASDU 和字节断言测试矩阵。 |

## 附录 A：用例 ID 完整列表

```text
iec104_startdt_msp
iec104_polling
iec104_m_me_na_type9
iec104_timed_measurement
iec104_timed_single_point
iec104_single_command
iec104_double_command_timed
iec104_u_frames
iec104_s_ack
iec104_spontaneous_event
iec104_ipv6
iec104_multi_flow
iec104_neg_control
iec104_neg_unknown_type
iec104_neg_oversize_apdu
iec104_neg_ioa
```

## 附录 B：最小 HexDump 参考

```text
68 04 07 00 00 00  # STARTDT act
68 04 0b 00 00 00  # STARTDT con
68 04 43 00 00 00  # TESTFR act
68 04 83 00 00 00  # TESTFR con
68 04 13 00 00 00  # STOPDT act
68 04 23 00 00 00  # STOPDT con
68 04 01 00 02 00  # S, N(R)=1
```

这些参考只说明应用层字节，不替代 TCP 头、校验和、序号和 pcap 的完整验证。

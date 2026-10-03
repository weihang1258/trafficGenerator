# Moxa NPort（串口服务器透传）协议测试用例

> 版本：v1.0.0
> 日期：2026-08-18
> 配套：`27-moxa-design.md`（协议设计，§7 索引）、`trafficgen/test/protocol_pcap/cases/moxa.json`（用例文件，本文件 §5 的机器可读版本）
> 说明：本文档将设计文档 §7 的每个场景/每条负路径展开为可直接执行的测试用例（case），与 `cases/moxa.json` **一一对应、id 相同**。断言语法遵循 `pcaptest` 框架（`Case/Expect/FieldAssert/FrameAssert/StrategyFC`），见 `trafficgen/internal/pcaptest/types.go`。

## 1. 概述

### 1.1 测试目标（从设计文档与测试策略双重派生）

用例家族由两条源头派生，缺一不可：

1. **设计源头**（`27-moxa-design.md`）：§6 的 6 个正向场景（S1-S6）+ §9 的错误表（对应 7 条负向用例 N-1..N-7）。每个场景/每行错误一条用例（Testing Policy §1：spec 驱动、一行一测）。
2. **用户强制覆盖清单**（本次任务的验收项）：
   - 单向 byte 流（固定 / pattern payload 多段）→ S1、S3，用例 `moxa_single_up`、`moxa_bidirectional`；
   - 双向流（payload + response，方向 up/down）→ S3 的 WR/RT 块，`moxa_bidirectional`；
   - 多串口会话（sessions>1 的多流展开）→ S4，`moxa_sessions_multi`；
   - IPv4 + IPv6 载体 → S1（IPv4）+ S6（IPv6），`moxa_single_up`、`moxa_ipv6`；
   - 负路径 expect_error（空 payload、payload 超长 >MSS、非法串口参数）→ N-1/N-6/N-5，`moxa_neg_empty_payload`、`moxa_neg_oversize`、`moxa_neg_bad_b64`。

> 强制覆盖清单中的"payload 超长 >MSS"是**正负两条**用例的交点：单块 2000B（>MSS1460 且 ≤MaxBlockBytes 2048）走**正向** `moxa_multi_segment`（MSS 分段）；单块 3000B（>MaxBlockBytes）走**负向** `moxa_neg_oversize`（E-B1 拒绝）。"超过 MSS"本身不是错误（MSS 分段是 tcp 层职责），"超过 MaxBlockBytes"才是错误——边界在 `_maxblockbytes_`，详见设计 §2.3/§5.6 冲突修正与 §6.3 分段矩阵。

### 1.2 用例全集速查

| # | 用例 id | 方向 | 关键断言 | 对应设计 |
|---|---------|------|---------|---------|
| 1 | `moxa_single_up` | 正 | packet_count=8、hex、dstport、握手/挥手 | S1 |
| 2 | `moxa_multi_segment` | 正 | packet_count=9、hex 首字节 A、段1=包4/段2=包5 | S2 |
| 3 | `moxa_bidirectional` | 正 | directional、down 段 srcport=4800、up/down hex | S3 |
| 4 | `moxa_sessions_multi` | 正 | distinct srcport [12345,12346,12347]、dstport 恒 4800 | S4 |
| 5 | `moxa_binary_payload` | 正 | hex = b64 解码 | S5 |
| 6 | `moxa_ipv6` | 正 | ipv6.src/dst、hex 偏移 74、dstport 4800 | S6 |
| 7 | `moxa_neg_empty_payload` | 负 | expect_error + error_contains | N-1 / E-T1 |
| 8 | `moxa_neg_config_packet` | 负 | expect_error（配置字节不进数据面） | N-2 / 设计 §3.2/§9.2 |
| 9 | `moxa_neg_sessions_multi` | 负 | expect_error（v1 拒绝 sessions>1） | N-3 / E-S3 |
| 10 | `moxa_neg_no_handshake` | 负 | expect_error（tcp.handshake=false） | N-4 / E-T5 |
| 11 | `moxa_neg_bad_b64` | 负 | expect_error（非法 base64） | N-5 / E-T3 |
| 12 | `moxa_neg_oversize` | 负 | expect_error（>2048 = E-B1） | N-6 / E-B1 |
| 13 | `moxa_neg_bad_direction` | 负 | expect_error（direction:"sideways" 非法） | N-7 / E-T2 |

> 13 例 = 6 正 + 7 负。与 `27-moxa-design.md` §7 映射表、`cases/moxa.json` id 完全一致（此清单即一致性校验锚点）。

### 1.3 运行方式

```bash
# 校验 cases JSON 语法（写完后立即跑）
python3 -c 'import json; json.load(open("trafficgen/test/protocol_pcap/cases/moxa.json"))'

# 全量驱动（真实 NIC + tshark 校验，经 MCP suite 工具）
CASE_PROTO=moxa go test ./test/protocol_pcap/ -run TestProtocolPcapDrive -v -timeout 600s

# 冒烟（前 N 个用例）
CASE_PROTO=moxa CASE_MAX=4 go test ./test/protocol_pcap/ -run TestProtocolPcapDrive -v -timeout 600s
```

> CLAUDE.md 背书：所有测试经 MCP 执行（`flowb_run_protocol_suite`），`go test` 与任何 MCP 客户端跑同一套校验；`-count=1` 防 go test 缓存吞运行期 env 差异（NIC_PROTO/CASE_PROTO 不在缓存 key 内）。

---

## 2. 配置块（spec_json 样例）

> 所有 `spec_json` 采用 **generate_traffic config 对象形态**（非数组；数组已废弃），与 enip/modbus 用例一致：`layers` 数组声明层链、`src_ip/dst_ip/src_port/dst_port` 在顶层、协议数据在 flat 键（`moxa`）。`dst_port=4800` 显式（设计 §1.4 纪律），src_port 只在不需多流时省略（默认 0 → worker 分配）。

### 2.1 基础骨架（S1/S5/S6 共用）

```json
{
  "layers": [
    {"tcp": {}},
    {"moxa": {}}
  ],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "dst_port": 4800,
  "moxa": {
    "stream": [{"payload": "hello"}]
  }
}
```

### 2.2 强制覆盖项 → 配置要点速查

| 强制项 | 在哪个用例 / 配置差异 |
|--------|----------------------|
| 单向 byte 流（固定 payload） | `moxa_single_up` —— 上述骨架本体 |
| 单向 byte 流（pattern payload 多段） | `moxa_bidirectional`/`moxa_multi_segment` —— 多块 stream 或长 payload |
| 双向流（payload+response） | `moxa_bidirectional` —— stream 含 `direction:"down"` 块 |
| 多串口会话 | `moxa_sessions_multi` —— `strategy_fc:{"type":"flows","value":3}` |
| IPv4 / IPv6 载体 | `moxa_single_up`（IPv4）/ `moxa_ipv6`（IPv6，src_ip/dst_ip 改 v6 地址） |
| 负路径 | 7 条 expect_error 用例（§5） |

### 2.3 逐用例 spec_json

#### 2.3.1 `moxa_single_up`（S1）

```json
{
  "layers": [{"tcp": {}}, {"moxa": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "dst_port": 4800,
  "moxa": {"stream": [{"payload": "hello"}]}
}
```

#### 2.3.2 `moxa_multi_segment`（S2，2000B 单块，MSS 分段）

```json
{
  "layers": [{"tcp": {"mss": 1460}}, {"moxa": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "dst_port": 4800,
  "moxa": {"stream": [{"payload": "AAAAAAAAAA"}]}
}
```

> 注释（JSON 无法内联，见 §3.4）：payload 实为 **2000 个 `A`**（0x41×2000）——>MSS1460 → 2 段（1460+540）；≤MaxBlockBytes2048 → 不撞 E-B1。上例的 `"AAAAAAAAAA"` 是占位符，用例文件里写 2000 字字符穿；`json.load` 校验前用生成工具展开（见 §3.4）。

#### 2.3.3 `moxa_bidirectional`（S3，双向 + pattern 多段）

```json
{
  "layers": [{"tcp": {"mss": 536}}, {"moxa": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "dst_port": 4800,
  "moxa": {
    "stream": [
      {"direction": "up",   "payload": "WR"},
      {"direction": "down", "payload": "RT"},
      {"direction": "up",   "payload": "WR"},
      {"direction": "down", "payload": "RT"}
    ]
  }
}
```

> "pattern 多段"在本项目配置里就是**多个块**（配置层无 pattern 语法；payload 是字面量）。48 字节的 WR/RT 块演示多段但不触发 MSS 分段（536 MSS 下 48B 单段）。

#### 2.3.4 `moxa_sessions_multi`（S4，策略级多 flow）

```json
{
  "layers": [{"tcp": {}}, {"moxa": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "dst_port": 4800,
  "moxa": {"stream": [{"payload": "hello"}]}
}
```

> 顶层**不写 src_port**：`strategy_fc`（Case.StrategyFC）= `{"type":"flows","value":3}`，worker 自动递增 src_port 12345/12346/12347（设计 §4.3）。src_ip/dst_ip 三者会共享（3 路 4-tuple 仅 src_port 区分）。

#### 2.3.5 `moxa_binary_payload`（S5）

```json
{
  "layers": [{"tcp": {}}, {"moxa": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "dst_port": 4800,
  "moxa": {"stream": [{"payload_b64": "aGFoYQ=="}]}
}
```

> `aGFoYQ==` 解码 = "haha" = 字节 `68 61 68 61`。`payload_b64` 优先于 `payload`（互斥，设计 §5.1）。

#### 2.3.6 `moxa_ipv6`（S6）

```json
{
  "layers": [{"tcp": {}}, {"moxa": {}}],
  "src_ip": "2001:db8::1",
  "dst_ip": "2001:db8::2",
  "dst_port": 4800,
  "moxa": {"stream": [{"payload": "hello"}]}
}
```

#### 2.3.7 负向配置（§5 详述，各 1 行预告）

| 用例 | spec_json 差异 |
|------|----------------|
| `moxa_neg_empty_payload` | `moxa.stream` 缺省（或空数组 / 空 payload） |
| `moxa_neg_config_packet` | `moxa.stream[0].payload` 前 3 字节 = `5a 5a 5a`（受控探针） |
| `moxa_neg_sessions_multi` | `moxa.sessions=2` |
| `moxa_neg_no_handshake` | `tcp.handshake=false` |
| `moxa_neg_bad_b64` | `moxa.stream[0].payload_b64="%%%"`（非法） |
| `moxa_neg_oversize` | `moxa.stream[0].payload` = 3000B（>2048） |
| `moxa_neg_bad_direction` | `moxa.stream[0].direction="sideways"`（非法方向，E-T2） |

---

## 3. 断言目录（expect 写法全解）

> 每类断言一行一义，全部经 `VerifyPcap`（`trafficgen/internal/pcaptest/verify.go`）执行。负向用例（`expect_error`）由 `tools_testdrive.go` `runOneCasePcap` 语义判定：createAndRunStrategy 被校验拒绝 → PASS；成功但空流/任务失败 → 按 expect_error 判定（成败翻转）。

### 3.1 包结构断言

| 字段 | 含义（verify.go） |
|------|------------------|
| `packet_count` | 精确包数（本设计所有正向用例精度确定：事件模式无独立 ACK，S1=8/S2=9/S3=11/S4=24 等，见 §3.6） |
| `min_packets` | 下界包数（预留；当前用例均用精确 packet_count，不再用下界） |
| `has_handshake` | 首包 TCP SYN |
| `negotiated` | 至少一个 SYN+ACK |
| `terminates` | 末 3 包内有 FIN(0x001)/RST(0x004) |
| `has_payload` | 至少一包 frame.len>80（moxa 除 S2 大段外帧长均 ≤80，正向用例默认不设；仅 S2 设 true） |
| `directional` | 至少 2 个不同 ip.src |

### 3.2 字段断言（FieldAssert）

| 形式 | 语义 |
|------|------|
| `{packet:4, field:"tcp.dstport", value:"4800"}` | 第 4 包该字段恰为 4800 |
| `{packet:4, field:"tcp.dstport"}`（value 空串） | 字段存在即可 |
| `{field:"tcp.srcport", distinct_values:["12345","12346","12347"]}` | 多流聚合：恰为这些值、各至少一次、无他值（跳过 Packet；S4 用） |
| `{field:"tcp.dstport", distinct_values:["4800"], distinct_exclude:[]}` | 全包皆 4800 |
| `{packet:4, field:"tcp.flags", value:"0x018"}` | flag 位比较（期望位必须都置位；PSH\|ACK） |
| `{packet:6, field:"tcp.seq", nonzero:true}` | 非零存在 |
| `same_as_packet` | 跨包相等（本设计不依赖，留作二进制/会话 id 扩展） |

### 3.3 帧字节断言（FrameAssert）

`{packet:4, offset:54, hex:"68 65 6c 6c 6f"}` —— 在帧偏移 offset 处**十六进制前缀匹配**（不要求覆盖整包）。偏移按载体锚定（设计 §6.1 帧解剖）：

| 载体 | offset |
|------|--------|
| IPv4 数据段（14+20+20） | 54 |
| IPv6 数据段（14+40+20） | 74 |
| SYN 带选项包 | 60 |

### 3.4 长 payload 的写法约定（2000 个 A 怎么进 JSON）

- `cases/moxa.json` 是纯 JSON，无法写注释；2000 个 `A` 直接内联在 `payload` 字符串里（单行、无换行，合法 JSON）。
- 生成方式：实现阶段用脚本 `printf 'A%.0s' {1..2000}` 拼入；testcase 文档与 JSON **统一约定 2000**（"M-Size 冲突修正"，设计 §5.6/§6.3）。
- 校验：`python3 -c 'import json; d=json.load(open(...)); assert len(d["spec_json"]["moxa"]["stream"][0]["payload"])==2000'`（见 §7 校验清单）。

### 3.5 负向断言（expect_error）

`{expect_error:true, error_contains:"moxa: empty stream block or payload required"}` —— 期望错误字符串包含子串（空 = 任意错误均可）。`error_contains` 源 = 设计 §9.1 错误表"错误消息要点"列，逐项对应。

### 3.6 设计 §5.7 期望帧摘要 ↔ expect 字段对照

| 设计 §5.7 行 | expect 写法 |
|--------------|-------------|
| S1 packet_count=8 | `expect.packet_count: 8` |
| S1 has_handshake/negotiated/terminates | 三者 true |
| S1 dstport 全 4800 | `fields:[{packet:4,field:"tcp.dstport",value:"4800"}]`（+S4 用 distinct） |
| S1 hex "hello" @54 | `frames:[{packet:4,offset:54,hex:"68 65 6c 6c 6f"}]` |
| S2 packet_count=9 | `expect.packet_count: 9`（2 段→段1=包4/段2=包5）+ has_payload=true（1514>80） |
| S3 directional / down srcport | `directional:true` + `{packet:5,field:"tcp.srcport",value:"4800"}`（5=首个 down 数据包） |
| S5 hex "haha" @54 | `frames:[{packet:4,offset:54,hex:"68 61 68 61"}]` |
| S6 v6 src/dst + hex @74 | fields ipv6.src/ipv6.dst + `frames:[{packet:4,offset:74,hex:"68 65 6c 6c 6f"}]` |

---

## 4. 逐用例走查（per-case walkthrough）

> 每条 = 配置 → 期望包序列推演 → 断言清单（写成 JSON 时即 `expect`）。**包序推演是"当前生成器语义下"的确定性**（设计 §3.4 帧界限不确定性）；S2/S4 因段间 ACK 布局或流交织不给出精确 packet 号（用聚合/下界断言）。

### 4.1 `moxa_single_up`（正向，S1）

- **配置**（§2.3.1）：单块 `{"payload":"hello"}`，dst_port 4800，tcp 默认握手/挥手。
- **包序推演**（packet_count=8）：1 SYN → 2 SYN+ACK → 3 ACK → 4 数据(PSH|ACK, "hello") → 5 FIN|ACK → 6 ACK → 7 FIN|ACK → 8 ACK。事件模式下数据段后无独立对端 ACK（piggyback，设计 §3.1/§8.2）。
- **断言清单**：

```json
"expect": {
  "packet_count": 8,
  "has_handshake": true,
  "negotiated": true,
  "terminates": true,
  "fields": [
    {"packet": 4, "field": "tcp.dstport", "value": "4800"},
    {"packet": 4, "field": "tcp.flags", "value": "0x018"}
  ],
  "frames": [
    {"packet": 4, "offset": 54, "hex": "68 65 6c 6c 6f"}
  ],
  "notes": [
    "S1: 单向上行固定 payload；8 包 = 3 握手 + 1 数据 + 4 挥手（事件模式无独立 ACK，设计 §3.1/§8.2）",
    "dst_port 显式 4800 纳入断言（设计 §1.4 纪律）"
  ]
}
```

- **关键校验点**：数据包在正确偏移 54 携带"hello"；flags=0x018（PSH|ACK）；`dstport==4800`。`terminates` 由末 3 包内的 FIN（flags=0x011）满足。不设 `has_payload`：帧长 59→补零 60 ≤ 80 阈值。

### 4.2 `moxa_multi_segment`（正向，S2）

- **配置**（§2.3.2）：单块 `{"payload":"A"×2000}`，mss 1460 → 2 段（1460+540），≤MaxBlockBytes2048 不撞 E-B1。
- **包序推演**（packet_count=9）：3 握手 + 数据阶段 `段1(PSH|ACK,1460A)→段2(PSH|ACK,540A)`（事件模式段间不插 ACK）+ 挥手 4 = 3+2+4 = 9。段1=包4、段2=包5。
- **断言清单**：

```json
"expect": {
  "packet_count": 9,
  "has_handshake": true,
  "has_payload": true,
  "terminates": true,
  "fields": [
    {"packet": 4, "field": "tcp.dstport", "value": "4800"},
    {"packet": 4, "field": "tcp.len", "nonzero": true}
  ],
  "frames": [
    {"packet": 4, "offset": 54, "hex": "41"},
    {"packet": 5, "offset": 54, "hex": "41"}
  ],
  "notes": [
    "S2: 2000B 单块 > MSS1460 → 2 段（1460+540）；≤MaxBlockBytes2048 不撞 E-B1",
    "hex 断言用前缀匹配（首字节 41），不整段穷举；段1=包4 段2=包5（事件模式无独立 ACK）",
    "has_payload=true 仅此例成立（段帧 1514>80 阈值）；其余正向用例帧长均 ≤80 故不设"
  ]
}
```

> 若 tcp 层实际布局与事件模式推演偏差（如走 legacy 独立 ACK），`frames` 的 packet 号需校准；实施时以实际 tshark 输出核对一次再锁定（见 §7 校验清单"校准一步"）。

### 4.3 `moxa_bidirectional`（正向，S3）

- **配置**（§2.3.3）：mss 536，**双向流** WR/RT×2（up → down → up → down）。
- **包序推演**（packet_count=11）：3 握手 + 数据阶段 4 块各 1 包（up WR / down RT / up WR / down RT，事件模式每块 1 包无独立 ACK）+ 挥手 4 = 3+4+4 = 11。
- **断言清单**：

```json
"expect": {
  "packet_count": 11,
  "has_handshake": true,
  "negotiated": true,
  "terminates": true,
  "directional": true,
  "fields": [
    {"packet": 4, "field": "tcp.dstport", "value": "4800"},
    {"packet": 5, "field": "tcp.srcport", "value": "4800"},
    {"field": "tcp.dstport", "distinct_values": ["4800"], "distinct_exclude": ["12345"]}
  ],
  "frames": [
    {"packet": 4, "offset": 54, "hex": "57 52"},
    {"packet": 5, "offset": 54, "hex": "52 54"}
  ],
  "notes": [
    "down 段 srcport=4800（服务器回包端口对换），断言 packet5 tcp.srcport==4800",
    "distinct_exclude 滤掉下行握手/挥手包 dst=客户端源端口（12345）的污染（设计 §9.1/E? 见 verify DistinctExclude 语义）"
  ]
}
```

- **关键校验点**：`directional`（≥2 个不同 ip.src）；up 段 hex "WR"（包4）、down 段 hex "RT"（包5）且 down 段 `tcp.srcport==4800`（服务器方向端口对换的直接证据）；`tcp.dstport` 聚合恒 4800（用 distinct_exclude 滤掉握手/挥手下行包 dst=12345 的对端端口）。

### 4.4 `moxa_sessions_multi`（正向，S4）

- **配置**（§2.3.4）：`strategy_fc:{"type":"flows","value":3}`，3 路独立 TCP 连接，src_port 自动递增 12345/12346/12347。
- **包序推演**（packet_count=24）：每流 3+1+4 = 8 包（事件模式无独立 ACK），3 流 = 24。
- **断言清单**：

```json
"expect": {
  "packet_count": 24,
  "has_handshake": true,
  "fields": [
    {"field": "tcp.srcport", "distinct_values": ["12345", "12346", "12347"], "distinct_exclude": ["4800"]},
    {"field": "tcp.dstport", "distinct_values": ["4800"], "distinct_exclude": ["12345", "12346", "12347"]}
  ],
  "notes": [
    "3 流 × 8 包 = 24；流交织非确定 → distinct_values 聚合断言",
    "distinct_exclude 滤对端端口（下行包 src=4800 / dst=12345-47 不入聚合）",
    "不逐包定位（多流调度无固定包位）"
  ]
}
```

- **关键校验点**：`distinct_values` 精确锁定 3 个 srcport 且无其他值（多流展开生效）；dstport 聚合恒 4800；两者均靠 distinct_exclude 滤对端端口。

### 4.5 `moxa_binary_payload`（正向，S5）

- **配置**（§2.3.5）：`payload_b64:"aGFoYQ=="` → "haha" = `68 61 68 61`。
- **断言清单**：

```json
"expect": {
  "packet_count": 8,
  "has_handshake": true,
  "terminates": true,
  "fields": [
    {"packet": 4, "field": "tcp.dstport", "value": "4800"}
  ],
  "frames": [
    {"packet": 4, "offset": 54, "hex": "68 61 68 61"}
  ],
  "notes": ["S5: base64 解码正确 + 二进制原样透传；8 包 = 3 握手 + 1 数据 + 4 挥手（不设 has_payload，帧长 60≤80）"]
}
```

### 4.6 `moxa_ipv6`（正向，S6）

- **配置**（§2.3.6）：IPv6 地址 + "hello"，payload 偏移 74。
- **断言清单**：

```json
"expect": {
  "packet_count": 8,
  "has_handshake": true,
  "terminates": true,
  "fields": [
    {"packet": 4, "field": "ipv6.src", "value": "2001:db8::1"},
    {"packet": 4, "field": "ipv6.dst", "value": "2001:db8::2"},
    {"packet": 4, "field": "tcp.dstport", "value": "4800"}
  ],
  "frames": [
    {"packet": 4, "offset": 74, "hex": "68 65 6c 6c 6f"}
  ],
  "notes": [
    "IPv6 载体：payload 偏移 74（设计 §6.1）；tcp 校验和覆盖 IPv6 伪头，专家信息自动校验；8 包不设 has_payload（帧长 79<80）"
  ]
}
```

### 4.7 负向用例（expect_error，无包）

负向用例**不断言包结构**（任务被拒绝，无 pcap 产出）。`expect_error:true` + `error_contains`（设计 §9.1 错误消息要点）。

| 用例 id | 触发配置 | error_contains |
|---------|---------|----------------|
| `moxa_neg_empty_payload` | `moxa.stream` 缺省 / 空 / `payload` 空串 | `moxa: empty stream block or payload required` |
| `moxa_neg_sessions_multi` | `moxa.sessions=3` | `moxa: sessions=3>1 not supported` |
| `moxa_neg_no_handshake` | `{"tcp":{"handshake":false}}` | `moxa: tcp.handshake must be true` |
| `moxa_neg_bad_b64` | `payload_b64:"%%%"` | `moxa: invalid payload_b64` |
| `moxa_neg_bad_direction` | `stream` 块 `direction:"sideways"` | `moxa: invalid direction` |
| `moxa_neg_oversize` | `payload` 3000B（>MaxBlockBytes 2048） | `moxa: block 0 payload 3000 exceeds max 2048` |
| `moxa_neg_config_packet` | `payload` 前 3 字节 `5a 5a 5a`（受控探针） | `moxa: config-packet bytes in stream are not supported` |

> 语义：期望**任务/调用失败**，失败即 PASS（工具语义）。"payload 超长 >MSS（=4000，但仍 >2048）"已经并入 `moxa_neg_oversize`（E-B1 在 2048 处设界，>2048 就被拒——"超长+超 MSS"单一根因）。真正"超 MSS 但合法"的方向在 `moxa_multi_segment` 覆盖。这就是任务要求里"payload 超长"的正负两条覆盖的交点（§1.1）。

---

## 5. 与 case 文件索引表（一致性锚点）

> 此表 = `cases/moxa.json` 的目录。**任意一处改动三处同步**：本表 ↔ `27-moxa-design.md` §7 ↔ JSON id。

| # | id | proto | 正/负 | 强制覆盖项 | specs（设计） | 断言要点 |
|---|----|-------|------|-----------|--------------|---------|
| 1 | `moxa_single_up` | moxa | 正 | 单向 byte 流（固定 payload）/ IPv4 | S1 | packet_count=8、hex "hello"@54、dstport 4800、握手/挥手 |
| 2 | `moxa_multi_segment` | moxa | 正 | 单向 byte 流（多段） | S2 | packet_count=9、hex 首字节 A@54、2000B 分 2 段（段1=包4/段2=包5）、has_payload |
| 3 | `moxa_bidirectional` | moxa | 正 | 双向流（payload+response） | S3 | packet_count=11、directional、down 段 srcport=4800、WR/RT hex |
| 4 | `moxa_sessions_multi` | moxa | 正 | 多串口会话（多 flow） | S4 | packet_count=24、distinct srcport [12345..12347]（distinct_exclude 滤 4800） |
| 5 | `moxa_binary_payload` | moxa | 正 | 二进制（payload_b64） | S5 | packet_count=8、hex = b64 解码（68 61 68 61）@54 |
| 6 | `moxa_ipv6` | moxa | 正 | IPv6 载体 | S6 | packet_count=8、ipv6.src/dst、hex@74、dstport 4800 |
| 7 | `moxa_neg_empty_payload` | moxa | 负 | 负路径：空 payload | N-1/E-T1 | expect_error+error_contains |
| 8 | `moxa_neg_config_packet` | moxa | 负 | 负路径：配置字节混入数据面 | N-2 | expect_error（诚实边界，设计 §9.2） |
| 9 | `moxa_neg_sessions_multi` | moxa | 负 | 负路径：非法串口参数（多会话） | N-3/E-S3 | expect_error |
| 10 | `moxa_neg_no_handshake` | moxa | 负 | 负路径：handshake=false | N-4/E-T5 | expect_error |
| 11 | `moxa_neg_bad_b64` | moxa | 负 | 负路径：非法 base64 | N-5/E-T3 | expect_error |
| 12 | `moxa_neg_oversize` | moxa | 负 | 负路径：payload 超长（>MSS 且 >2048） | N-6/E-B1 | expect_error |
| 13 | `moxa_neg_bad_direction` | moxa | 负 | 负路径：非法方向 | N-7/E-T2 | expect_error（direction:"sideways"） |

---

## 6. 覆盖清单（coverage checklist）

> 任务强制覆盖项 → 用例 → 状态；以及设计 §9 错误表 → 用例全映射（Testing Policy §1：一行一测）。

### 6.1 任务强制覆盖清单

| 强制项 | 用例 | 状态 |
|--------|------|------|
| 单向 byte 流（固定 payload） | `moxa_single_up` | 覆盖 |
| 单向 byte 流（pattern payload 多段） | `moxa_multi_segment`（长块分段）+ `moxa_bidirectional`（多块） | 覆盖 |
| 双向流（payload + response） | `moxa_bidirectional`（WR/RT，up/down 方向对换） | 覆盖 |
| 多串口会话（sessions>1 的多 flow 展开） | `moxa_sessions_multi`（strategy_fc flows=3） | 覆盖 |
| IPv4 + IPv6 载体 | `moxa_single_up`（v4）+ `moxa_ipv6`（v6） | 覆盖 |
| 负路径：空 payload | `moxa_neg_empty_payload` | 覆盖 |
| 负路径：payload 超长（>MSS） | `moxa_neg_oversize`（3000>2048 拒绝）+ 正向对照 `moxa_multi_segment`（2000 分段） | 覆盖（正负成对） |
| 负路径：非法串口参数/方向 | `moxa_neg_sessions_multi`（sessions>1）、`moxa_neg_no_handshake`（handshake=false）、`moxa_neg_bad_b64`（非法 b64）、`moxa_neg_bad_direction`（非法方向） | 覆盖 |

### 6.2 设计 §9 错误表 → 用例映射

| 错误 ID（设计 §9.1） | 用例 | 状态 |
|----------------------|------|------|
| E-T1（空流/空块） | `moxa_neg_empty_payload` | 覆盖 |
| E-T2（非法方向） | `moxa_neg_bad_direction`（`direction:"sideways"` → 拒绝，专列方向负例） | 覆盖 |
| E-T3（非法 base64） | `moxa_neg_bad_b64` | 覆盖 |
| E-B1（单块>2048） | `moxa_neg_oversize` | 覆盖 |
| E-B2（>MSS 但合法） | `moxa_multi_segment`（正向） | 覆盖 |
| E-S3（sessions>1） | `moxa_neg_sessions_multi` | 覆盖 |
| E-T4（dst_port 越域） | 复用 tcp 既有负例（不单列，设计 §9.1 注） | 承继 |
| E-T5（handshake=false） | `moxa_neg_no_handshake` | 覆盖 |
| N-2（配置字节混入数据面） | `moxa_neg_config_packet` | 覆盖 |

---

## 7. 校验清单（bash，写完即跑）

```bash
# 1) JSON 语法 + 结构
python3 - <<'PY'
import json
d = json.load(open("trafficgen/test/protocol_pcap/cases/moxa.json"))
assert isinstance(d, list) and len(d) == 13, f"13 cases expected, got {len(d)}"
ids = [c["id"] for c in d]
assert ids == ["moxa_single_up","moxa_multi_segment","moxa_bidirectional",
               "moxa_sessions_multi","moxa_binary_payload","moxa_ipv6",
               "moxa_neg_empty_payload","moxa_neg_config_packet",
               "moxa_neg_sessions_multi","moxa_neg_no_handshake",
               "moxa_neg_bad_b64","moxa_neg_oversize","moxa_neg_bad_direction"], ids
neg = [c for c in d if c["expect"].get("expect_error")]
assert len(neg) == 7, "7 negative cases expected"
seg = [c for c in d if c["id"]=="moxa_multi_segment"][0]
payload = seg["spec_json"]["moxa"]["stream"][0]["payload"]
assert len(payload) == 2000 and payload[0] == "A", "S2 payload must be 2000xA"
print("moxa.json OK:", len(d), "cases")
PY

# 2) 三件套行数
wc -l docs/protocol-designs/27-moxa-design.md \
      docs/protocol-designs/27-moxa-testcase.md \
      trafficgen/test/protocol_pcap/cases/moxa.json
```

> 一致性自检项（与 §5 锚点）：testcase §4.7 error_contains ↔ 设计 §9.1 错误消息要点 ↔ JSON expect.error_contains，三处逐字一致。

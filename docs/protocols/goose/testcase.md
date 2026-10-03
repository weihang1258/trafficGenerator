# IEC 61850-8-1 GOOSE 协议测试用例契约

> 版本：v2.0.0（P-PIPE 文档轨，as-built 对账版）
> 范围：GOOSE L2 直承帧；当前 cases JSON 共 33 例（18 正 + 15 负）。
> 配套：`trafficgen/test/protocol_pcap/cases/goose.json`；设计：`docs/protocols/goose/design.md`。
> 形状硬约束：正例顶层仅 `layers`；层链为 `[eth,goose]`；负例的顶层 `goose` 或 `[ip,goose]` 仅用于证明判死规则，不是合法配置。

---

## 目录

1. [测试环境与校验手段](#1-测试环境与校验手段)
2. [框架断言工具](#2-框架断言工具)
3. [用例编号规则](#3-用例编号规则)
4. [正向用例（T-GSE-S1..S7）](#4-正向用例t-gse-s1s7)
5. [负路径用例（T-GSE-NEG）](#5-负路径用例t-gse-neg)
6. [字段断言速查表](#6-字段断言速查表)
7. [覆盖勾选清单](#7-覆盖勾选清单)
8. [与 JSON 用例的一致性](#8-与-json-用例的一致性)
9. [测试执行与回归](#9-测试执行与回归)

---

## 1. 测试环境与校验手段

### 1.1 运行环境

- pcap 框架（`trafficgen/test/protocol_pcap/`）生成抓包，`tshark` 解析验证。GOOSE 帧**不经过 IP**，EtherType 0x88B8。
- **tshark goose 解析器可用性（关键前提）**：Wireshark 较新版本（3.x 中近期版本与 master）带 `goose` 解析器，EtherType 0x88B8 自动以 `goose` 解析（字段名 `goose.*`）；但**不少发行版 tshark 不含 goose 解析器**（goose 解析器在 2022 年后才入主线，且默认未必编译）。因此本设计断言策略为**双层**：
  1. 若 tshark 有 goose 解析器：用 `goose.*` 字段断言（§6 速查表）；
  2. **否则（保证性兜底）：一律用 FrameAssert 原始字节断言 APDU BER 标签字节**（`0x61`/`0x80`…`0x8A`/`0xAB`、MMS Data 内部 tag `0x83`-`0x91`/`0xA1`/`0xA2`）——这是本协议所有用例的共同底线，**不依赖 tshark 是否认识 goose**。
- 全部用例以 FrameAssert 为主断言手段；tshark `goose.*` 字段断言作为"可用则启用、不可用则跳过"的增强项（notes 记录）。

### 1.2 权威字节事实来源

- design.md §2.5 的 BER Tag 表（goosePdu=0x61、gocbRef=0x80、timeAllowedToLive=0x81、datSet=0x82、goID=0x83、t=0x84、stNum=0x85、sqNum=0x86、test=0x87、confRev=0x88、ndsCom=0x89、numDatSetEntries=0x8A、allData=0xAB）——口径与 libiec61850/Wireshark 一致，非任务初稿的旧标签编号。
- MMS Data 内部 tag（§3.6）：Boolean=0x83、BitString=0x84、Integer=0x85、Unsigned=0x86、FloatingPoint=0x87、OctetString=0x89、VisibleString=0x8A、BinaryTime=0x8C、UtcTime=0x91、Array=0xA1、Structure=0xA2。
- 帧头（§2.4）：APPID 默认 0x1000（GOOSE 段 0x0000-0x3FFF）、Length=8+APDU、Reserve1/2=0。
- 组播 MAC：01:0C:CD:01:xx:xx，默认 dst 01:0C:CD:01:02:03。
- 状态机（§4）：变化 stNum+1、sqNum 重置 0；重发/心跳 sqNum 递增、stNum 不变。

### 1.3 字节序与计数规则（断言前提）

- 所有数值字段大端；stNum/sqNum 从 1 起。
- 事件变化首帧 sqNum=**0**（非 1）；其后每次重发 +1。
- t 字段（CP 8B）为运行期墙钟，**测试不定值断言**（仅断言其存在/恒定字节段结构 0x84 08）。

### 1.4 运行约束（测试依赖）

| 约束 | 值 | 说明 |
|------|----|------|
| tshark 版本 | 任意（goose.* 可用则启用，否则 FrameAssert 兜底） | §1.1 |
| 帧序 | 按 `count` 与 `event_seq.retransmits` 生成 | 仅断言有限帧序，不断言墙钟间隔 |
| 帧数上限 | 每用例 ≤20 | 快速重发序列小窗口即可 |
| 并发用例 | 每用例独立引擎实例 | GOOSE 计数彼此隔离（§4.1） |

**测试前置校验命令**：
```bash
tshark -v | head -2
tshark -G fields | grep -c '\bgoose\.'   # >0 则启用 goose.* 断言；=0 则纯 FrameAssert
```

---

## 2. 框架断言工具

### 2.1 Case 结构（pcaptest/types.go）

```json
{
  "id": "goose_heartbeat",
  "proto": "goose",
  "spec_json": {
    "layers": [
      {"eth": {"src_mac": "aa:bb:cc:dd:ee:01", "dst_mac": "01:0c:cd:01:02:03"}},
      {"goose": {"gocb_ref": "...", "conf_rev": 1, "dat_set": "...", "data": [{"type": "int32", "value": 1234}], "count": 3}}
    ],
    "flow_control": {"flows": 1}
  },
  "expect": {"packet_count": 3, "fields": [], "frames": []}
}
```

### 2.2 断言语义

| 断言类型 | 字段 | 语义 |
|----------|------|------|
| 等值 | `field` + `value` | tshark 输出该字段等于给定值（数值以 `0x` 十六进制或十进制给） |
| 存在性 | `field` + `nonzero: true` | 字段存在且非零 |
| 跨包相等 | `field` + `same_as_packet: 1` | 与第 1 包同值（如 confRev 同流恒定） |
| FrameAssert | `offset` + `hex` | 按包内偏移精确比对原始字节——**本协议主断言**（无 IP 证明、BER tag 校验、无 goose 解析器兜底） |

注意：GOOSE 的 `t` 字段是运行期墙钟，**不可**用固定 `value` 断言；用 FrameAssert offset 断言 `84 08` 标签 + 存在性（0x84 08 后 8 字节可省略不核对内容）。

### 2.3 负路径断言

`expect_error: true` 时框架断言任务**失败**且错误文本含 `error_contains`（如 `"appid"`）。框架保证"任务失败"被观测（Testing Policy 第 4 条：不能只是"不失败"）。

---

## 3. 用例编号规则

- 正向：`T-GSE-S<n>-<m>`，S1..S7 对应 design.md §6 场景 S1..S7（S1 静默心跳、S2 快速重发+数据集变化、S3 test/ndsCom、S4 VLAN、S5 多类型数据、S6 无 IP、S7 多数据集）。
- 负向：`T-GSE-NEG-*`，对应当前 JSON 的 15 条错误路径。
- JSON 用例 id 采用 `goose_<key>` 小写（如 `goose_heartbeat`、`goose_retransmit`、`goose_dataset_change`、`goose_test_flag`、`goose_ndscom_flag`、`goose_vlan`、`goose_multitype`、`goose_no_ip`、`goose_multidataset`、`goose_neg_appid`、`goose_neg_sqnum`、`goose_neg_stnum`）。

### 3.1 历史核心用例子集（13 项；当前可执行清单见 §10.2）

| 编号 | 名称 | 场景/依据 | 类型 | JSON |
|------|------|-----------|------|------|
| T-GSE-S1-01 | 静默心跳 3 帧（stNum 恒同 sqNum 递增） | S1（§6.1） | 正 | `goose_heartbeat` |
| T-GSE-S1-02 | 帧头字段 | §2.4 | 正 | 并入 `goose_heartbeat` |
| T-GSE-S2-01 | 有限重发序列 | S2（§6.2） | 正 | `goose_retransmit` |
| T-GSE-S2-02 | 数据集变化 stNum+1 sqNum 重置 | §4.4 | 正 | `goose_dataset_change` |
| T-GSE-S3-01 | test 置位 | §4.5/§6.3 | 正 | `goose_test_flag` |
| T-GSE-S3-02 | ndsCom 置位 | §4.5/§6.3 | 正 | `goose_ndscom_flag` |
| T-GSE-S4-01 | VLAN 场景 | S4（§6.4） | 正 | `goose_vlan` |
| T-GSE-S5-01 | 多类型数据值 | S5（§6.5） | 正 | `goose_multitype` |
| T-GSE-S6-01 | 无 IP 层证明 | S6（§6.6） | 正 | `goose_no_ip` |
| T-GSE-S7-01 | 多数据集（6 成员） | S7（§6.7） | 正 | `goose_multidataset` |
| T-GSE-NEG-01 | AppID 越界（实现拒绝所有大于 0x3FFF 的值） | §9.2 | 负 | `goose_neg_appid`；锚词 `outside GOOSE range 0x0000-0x3fff` |
| T-GSE-NEG-02 | sqNum 不连续 | §9.1 | 负 | `goose_neg_sqnum` |
| T-GSE-NEG-03 | stNum 回绕 | §9.1 | 负 | `goose_neg_stnum` |

---

## 4. 正向用例（T-GSE-S1..S7）

### 4.1 T-GSE-S1-01：静默心跳 3 帧（stNum 恒同、sqNum 递增）

- **依据**：design.md §6.1（S1）
- **配置**：GOOSE 层显式配置，`gocb_ref`/`dat_set`/`tal_ms:500`/`appid:0x1000`，数据集 `[{int32 pos=1234},{binary_time tm},{int32 rate=5678}]`、`count:3`
- **期望**：
  - `packet_count == 3`
  - fields（tshark goose.* 可用时）：
    - packet 1 `goose.appid` == 0x1000、`goose.length` == 184
    - packet 1 `goose.stNum` == 1；packet 2/3 `goose.stNum` `same_as_packet=1`（stNum 恒同）
    - packet 1 `goose.sqNum` == 1、packet 2 == 2、packet 3 == 3（递增）
    - packet 1 `goose.confRev` == 1；packet 2/3 `same_as_packet=1`
    - packet 1 `goose.numDatSetEntries` == 3
    - packet 1 `goose.timeAllowedtoLive` == 500
  - frames（**无 goose 解析器时的兜底主断言**）：
    - packet 1 offset 12 hex `88 b8`（EtherType）
    - packet 1 offset 14 hex `10 00`（APPID）
    - packet 1 offset 16 hex `00 b8`（Length=184）
    - packet 1 offset 22 hex `61 81 ad`（APDU 长形式，content=173）
    - packet 1 offset 25 hex `80 29`（gocbRef 起点）、offset 68 `81 02 01 f4`（TAL）、offset 162 `85 01 01`（stNum）、offset 177 `8a 01 03 ab 10`（num/allData）
- **关键断言**：三帧 stNum 恒 1、sqNum 1/2/3 逐一观测；Length=184 精确；BER 长形式和逐字段偏移必须与 JSON 一致。

### 4.2 T-GSE-S1-02：帧头字段（APPID/Reserve1/Reserve2）

- **依据**：§2.4
- **配置**：同 S1-01
- **期望**：
  - frames：packet 1 offset 14 hex `10 00 00 b8 00 00 00 00`（APPID + Length=184 + Reserve1/2；GOOSE 头完整 8 字节）
  - tshark goose.*：`goose.reserve1 == 0`、`goose.reserve2 == 0`
- **关键断言**：GOOSE 头 8 字节逐一对上（FrameAssert 兜底，防"字段解析但字节错"）。

### 4.3 T-GSE-S2-01：有限重发序列（同内容 sqNum 递增、stNum 恒同）

- **依据**：§4.2/§6.2（S2）
- **配置**：`event_seq` 含一次变化（`data_idx:0`、`retransmits:5`），`count:8`，生成 8 帧（1 心跳 + 6 事件帧 + 1 收尾帧）；不对墙钟间隔作断言
- **期望**：
  - fields：packet 2..7 `goose.stNum` `same_as_packet=2`（恒 2）；packet 2..7 `goose.sqNum` == 0,1,2,3,4,5（递增）；packet 1 `goose.stNum`==1、`goose.sqNum`==1
  - frames：packet 2 与 packet 3 的 allData 段 hex 相同（内容变化帧与重发帧内容一致）
- **关键断言**：`sqNum` 递增 `stNum` 恒同 = 快速重发核心语义（强制覆盖项）。

### 4.4 T-GSE-S2-02：数据集变化（stNum+1、sqNum 重置 0）

- **依据**：§4.4/§6.2（S2）
- **配置**：同 S2-01
- **期望**：
  - fields：packet 1 `goose.stNum`==1、`goose.sqNum`==1；packet 2 `goose.stNum`==2、**`goose.sqNum`==0**（重置！）
  - frames：packet 2 offset 165 hex `86 01 00`（sqNum=0 的最小 BER 编码）
- **关键断言**：变化瞬间 stNum+1、sqNum 由 1 重置为 **0**（不是 1）——强制覆盖项，防止实现把 sqNum 顺序递增而漏重置。

### 4.5 T-GSE-S3-01：test 置位

- **依据**：§4.5/§6.3（S3）
- **配置**：`test:true`，心跳 2 帧
- **期望**：
  - fields（若可用）：`goose.simulation == true`（Wireshark 把 test 显示为 simulation）
  - frames：每帧 offset 对应段 hex `... 87 01 01 ...`（test=true 字节；若无 goose.*，该 FrameAssert 是唯一证明）
- **关键断言**：test 标志置 1 编码为 `87 01 01`（强制覆盖项）。

### 4.6 T-GSE-S3-02：ndsCom 置位

- **依据**：§4.5/§6.3（S3）
- **配置**：`nds_com:true`，心跳 2 帧
- **期望**：
  - fields（若可用）：`goose.ndsCom == true`
  - frames：每帧对应段 hex `... 89 01 01 ...`（ndsCom=true 字节）
- **关键断言**：ndsCom 置 1 编码为 `89 01 01`（强制覆盖项）。

### 4.7 T-GSE-S4-01：VLAN 场景

- **依据**：§2.2/§6.4（S4）
- **配置**：`vlan_enabled:true`, `vlan_id:100`, `vlan_priority:4`
- **期望**：
  - fields（若可用）：`vlan.id` == 100；`vlan.priority` == 4
  - frames：packet 1 offset 12 hex `81 00 80 64 88 b8`（TPID + TCI 0x8064 + EtherType；§6.4 TCI 计算）；offset 20 hex `00 ab`（GOOSE Length=171）
- **关键断言**：VLAN 头插在 EtherType 前且 TPID/TCI 精确；APDU 偏移整体 +4（FrameAssert offset 26 起 `61`）。长形式 `61 81 a0` 的内容长度为 160，APDU total=163，Length=8+163=171。

### 4.8 T-GSE-S5-01：多类型数据值（Boolean/Integer/Real/FloatingPoint/BitString 各 >1）

- **依据**：§3.6/§3.7/§6.5（S5）
- **配置**：数据集含 boolean（2 个）、int32（2 个）、uint32、float32、bit_string（2 个）、visible_string（2 个）——保证强制覆盖项"各类型 >1"
- **期望**：
  - fields（若可用）：`goose.boolean` true/false、`goose.integer` 值、`goose.unsigned` 值、`goose.real` 值、`goose.floating_point` 字节、`goose.bit_string` 字节
  - frames（**主断言**）：从 allData 段（`ab <L>`）起逐成员 FrameAssert hex：
    - `83 01 01`（boolean true）、`83 01 00`（boolean false）
    - `85 02 00 96`（int32=150）、`85 02 16 2e`（int32=5678）
    - `86 02 27 10`（uint32=10000）
    - `87 05 08 3f c0 00 00`（float32=1.5，§3.7 IEC 61850 二进制浮点长 5，**非 IEEE 裸 4 字节**；JSON 用例实际值 2.5）
    - `84 02 00 fe`（bit_string 8 位 padding=0 = (8−8)）
    - `84 02 04 0f`（bit_string 4 位 padding=4 = (8−4)）
    - `8a 05 48 65 6c 6c 6f`（visible_string "Hello"）
- **关键断言**：Boolean/Integer/Real(FloatingPoint)/BitString 各 >1 且字节编码逐一对上（强制覆盖项）；float 是 IEC 61850 语义不是 IEEE 754。

### 4.9 T-GSE-S6-01：无 IP 层证明（帧不含 IP 头）

- **依据**：§3.1/§6.6（S6）
- **配置**：复用 T-GSE-S1-01 的帧
- **期望**：
  - fields：`frame.protocols` 不含 `ip`（有解析器时可能为 `eth:goose`，无解析器时可能为 `eth:data`；不使用固定字符串相等断言）
  - frames：packet 1 offset 12 hex `88 b8`（EtherType 是 GOOSE 不是 0x0800/0x86dd）；offset 22 hex `61`（APDU 首字节非 0x45）
- **关键断言**：EtherType 层独立证明无 IP；字段断言 `frame.protocols` 传达"无 ip 层"。

### 4.10 T-GSE-S7-01：多数据集（numDatSetEntries > 1，6 成员）

- **依据**：§3.8/§6.7（S7）
- **配置**：数据集 6 成员（boolean + int32 + uint32 + float32 + bit_string + visible_string）
- **期望**：
  - fields（若可用）：`goose.numDatSetEntries` == 6；`goose.allData` 存在
  - frames：packet 1 allData 段首 hex `... 8a 01 06 ab ...`（num=6 + allData 标签）；随帧 FrameAssert 逐成员 hex
- **关键断言**：numDatSetEntries>1 且与 allData 成员数一致（强制覆盖项）。

---

## 5. 负路径用例（T-GSE-NEG）

### 5.1 T-GSE-NEG-01：APPID 越界（实现范围外）

- **依据**：design.md §9.2
- **配置（非法）**：`appid: 0x4000`；实现接受范围仅为 `0x0000-0x3FFF`
- **期望**：`expect_error: true`、`error_contains: "outside GOOSE range 0x0000-0x3fff"`
- **关键**：所有大于 `0x3FFF` 的值均走同一拒绝路径；默认 `0x1000` 合法。

### 5.2 T-GSE-NEG-02：sqNum 不连续（负路径）

- **依据**：design.md §9.1
- **配置（非法）**：`event_seq[].sqnum_step:2` 使重发序列跳号。
- **期望**：`expect_error: true`、`error_contains: "sqNum"`（发送前校验或任务失败被观测）
- **关键**：护住"变化后首帧 sqNum=0、其后单调 +1"的硬规则（§4.4）。

### 5.3 T-GSE-NEG-03：stNum 回绕（负路径）

- **依据**：design.md §9.1
- **配置（非法）**：`start_stnum:4294967295`，首帧后将溢出。
- **期望**：`expect_error: true`、`error_contains: "stNum"`
- **关键**：护住"stNum 不回绕"（§4.4），防事件版本号回归导致订阅方误判。

### 5.4 负例预期 vs 规格行对照

| 负例 | 触发字段 | 期望错误文本（error_contains） | 规格行 | JSON |
|------|----------|-------------------------------|--------|------|
| APPID 越界 | `appid` | `"outside GOOSE range 0x0000-0x3fff"` | §9.2 | `goose_neg_appid` |
| sqNum 不连续 | `event_seq[].sqnum_step` | `"sqNum"` | §9.1 | `goose_neg_sqnum` |
| stNum 回绕 | `start_stnum: 0xffffffff` | `"stNum"` | §9.1 | `goose_neg_stnum` |

每条负例除了 `expect_error:true`，还必须断言 `error_contains` 命中**对应字段名**——只 fail 不定位等于没锁住具体规则（Testing Policy 第 2 条：失败路径要测"错在哪里"，不是"反正失败了"）。

---

## 6. 字段断言速查表

### 6.1 tshark goose.* 字段（goose 解析器可用时）

| tshark 字段 | 类型 | 用例用途 | 对应字节 |
|------------|------|----------|----------|
| `goose.appid` | uint16 | APPID | GOOSE 头 0 |
| `goose.length` | uint16 | Length 精确 | GOOSE 头 2 |
| `goose.reserve1` / `goose.reserve1.s_bit` | uint16/bool | Reserve1 / 仿真位 | GOOSE 头 4 |
| `goose.reserve2` | uint16 | Reserve2=0 | GOOSE 头 6 |
| `goose.gocbRef` | string | 控制块引用 | APDU 0x80 |
| `goose.timeAllowedtoLive` | int32 | TAL==500 | APDU 0x81 |
| `goose.datSet` | string | 数据集引用 | APDU 0x82 |
| `goose.goID` | string | GOOSE 标识 | APDU 0x83 |
| `goose.t` | string | 时间戳存在（不定值） | APDU 0x84 |
| `goose.stNum` | uint32 | 变化计数 | APDU 0x85 |
| `goose.sqNum` | uint32 | 重发计数 | APDU 0x86 |
| `goose.simulation`（test） | bool | test 置位 | APDU 0x87 |
| `goose.confRev` | int32 | 配置版本 | APDU 0x88 |
| `goose.ndsCom` | bool | 送修标志 | APDU 0x89 |
| `goose.numDatSetEntries` | int32 | 条目数 | APDU 0x8A |
| `goose.allData` | uint32(seq) | 成员序列 | APDU 0xAB |
| `goose.boolean` / `goose.bit_string` / `goose.integer` / `goose.unsigned` / `goose.floating_point` / `goose.real` / `goose.visible_string` / `goose.octet_string` / `goose.binary_time` / `goose.utc_time` / `goose.array` / `goose.structure` | 各异 | 数据成员值 | allData 成员 |
| `vlan.id` / `vlan.priority` | uint16 | VLAN 场景 | VLAN TCI |
| `frame.protocols` | string | 无 IP 证明 | — |

### 6.2 逐字段断言编写指南

| 断言意图 | 推荐写法 | 反例（不可用） |
|----------|----------|----------------|
| sqNum 递增 | 多包 `value`（1/2/3）或 `distinct_values` | 只断言第 1 包（后包没验） |
| stNum 恒同 | `{"field":"goose.stNum","same_as_packet":1}` | 每包 `value:1`（实现死写也算过） |
| 字段**不存在**/标签验证 | FrameAssert 证明无该 tag | `{"field":"goose.x","zero":true}`——字段不存在时 tshark 输出也是空 |
| t 时间戳 | FrameAssert offset hex `84 08`（只对标签+长度，不对 8 字节内容） | value 定值断言（墙钟变化，必挂） |
| 无 goose 解析器兜底 | 一律 FrameAssert 逐字段 hex（§2.2） | 依赖 goose.* 存在性 |
| 字节流成员 | frames 的 offset+hex 前/尾片段 | value 整串比较（跨 tshark 版本空白差异） |
| 组播/无 IP | `field":"frame.protocols"` + `eth.type` value | 只隔看 `eth.type`（忽略协议链） |

**数值进制注意**：`goose.appid` tshark 默认 `BASE_HEX` 输出 `0x1000`；`goose.stNum/sqNum` 是 `BASE_DEC` 输出 `1`/`2`。断言 value 字符串应与 tshark 输出格式一致（框架语义数值归一见 §2.2）。

### 6.3 用 tshark 命令行核对（调试期）

```bash
# 有 goose 解析器时
tshark -r out.pcap -Y goose -T fields -e goose.appid -e goose.stNum \
  -e goose.sqNum -e goose.confRev -e goose.numDatSetEntries \
  -e goose.test -e goose.simulation -e goose.ndsCom -e goose.allData

# 无 goose 解析器时（验证原始字节兜底）
tshark -r out.pcap -x | head -60   # 逐字节看 APDU BER 标签

# 无 IP 证明
tshark -r out.pcap -Y 'ip' | wc -l    # 期望 0

# 快速重发 sqNum 序列
tshark -r out.pcap -Y goose -T fields -e goose.sqNum
```

---

## 7. 覆盖勾选清单

针对任务强制性覆盖项逐条核对（存放测试用例是否实现）：

- [x] **静默心跳**：多帧 stNum 恒同、sqNum 递增（T-GSE-S1-01）
- [x] **快速重发序列**：同内容 sqNum 递增、stNum 恒同（T-GSE-S2-01）
- [x] **数据集变化**：stNum+1、sqNum 重置 0（T-GSE-S2-02）
- [x] **test 置位**（T-GSE-S3-01）、**ndsCom 置位**（T-GSE-S3-02）
- [x] **confRev**：初值 1 + 同流恒定（T-GSE-S1-01 same_as）
- [x] **数据值类型**：Boolean/Integer/Real(FloatingPoint)/BitString 各 >1（T-GSE-S5-01）
- [x] **多数据集**：numDatSetEntries>1（T-GSE-S7-01，6 成员）
- [x] **无 IP 层证明**：帧不含 IP 头（T-GSE-S6-01，frame.protocols + EtherType 双重证据）
- [x] **负路径 expect_error**（15 例）：
  - AppID 越界 >0x3FFF（T-GSE-NEG-01，0x4000 落 SV 段）
  - sqNum 不连续（T-GSE-NEG-02）与 sqNum 上限（T-GOOSE-32，start 0xFFFFFFFE）
  - stNum 回绕（T-GSE-NEG-03）
- [x] **tshark goose.\* 字段使用**：§6.1 速查表；**无可用的解析器时以 FrameAssert 原始字节兜底**（§1.1/§2.2）——本协议断言不依赖解析器

**IPv4/IPv6 标注**：GOOSE 为 L2 直承协议，IPv4/IPv6 承载均标注 **N/A**（不支持 R-GOOSE over IP，design.md §1.5）；以"帧不含 IP 头"证据用例（T-GSE-S6-01）替代。

---

## 8. 与 JSON 用例的一致性

`cases/goose.json` 与本文档一一对应；§3.1 是历史核心子集，当前完整清单以 §10.2/T2 的 33 个 JSON ID 为准。

| JSON id | 对应用例 | spec_json.goose 要点 | expect 结构 |
|---------|----------|----------------------|-------------|
| `goose_heartbeat` | T-GSE-S1-01/02 | `count:3` 心跳；`tal_ms:500`、`appid:4096`(0x1000)；data=[int32 1234, binary_time, int32 5678] | `packet_count:3`；stNum/sqNum 序列、confRev/TAL、frames 标签 |
| `goose_retransmit` | T-GSE-S2-01 | `event_seq` 单次变化；`retransmits:5`、`count:8` | fields stNum==2 sqNum 0..5；pk2/pk3 allData 段 hex 相同 |
| `goose_dataset_change` | T-GSE-S2-02 | 同上事件变化；`retransmits:2`、`count:5` | pk1 sqNum==1、pk2 **sqNum==0**、stNum 1→2；frames `86 01 00`（最小 BER） |
| `goose_test_flag` | T-GSE-S3-01 | `test:true` 心跳 2 帧 | frames `87 01 01`；goose.simulation 真 |
| `goose_ndscom_flag` | T-GSE-S3-02 | `nds_com:true` 心跳 2 帧 | frames `89 01 01`；goose.ndsCom 真 |
| `goose_vlan` | T-GSE-S4-01 | `vlan_enabled:true`、`vlan_id:100`、`vlan_priority:4` | frames offset 12 `81 00 80 64 88 b8`；offset 26 `61`（APDU 右移 4） |
| `goose_multitype` | T-GSE-S5-01 | data 10 成员：bool×2/int32×2/uint32/float32/bit_string×2/visible_string×2 | frames allData 段逐成员 hex（`83 01 01`、`85 ...`、`87 05 ...`、`84 ...`、`8a ...`）；numDatSetEntries==10 |
| `goose_no_ip` | T-GSE-S6-01 | 复用心跳帧 | fields `frame.protocols` 不含 ip；frames offset 12 `88 b8`、offset 22 `61` |
| `goose_multidataset` | T-GSE-S7-01 | data 6 成员（bool/int32/uint32/float32/bit_string/visible_string） | frames `8a 01 06 ab ...`；numDatSetEntries==6 |
| `goose_neg_appid` | T-GSE-NEG-01 | **`appid:16384`**(0x4000) 非法 | `expect_error:true`、`error_contains:"outside GOOSE range 0x0000-0x3fff"` |
| `goose_neg_sqnum` | T-GSE-NEG-02 | 注入不连续 sqNum（跳号/变化首帧非 0） | `expect_error:true`、`error_contains:"sqNum"` |
| `goose_neg_stnum` | T-GSE-NEG-03 | `start_stnum:4294967295` | `expect_error:true`、`error_contains:"stNum"` |

**一致性规则**：
1. `proto` 一律 `"goose"`；`layers` 一律 `[{"eth":{}},{"goose":{}}]`（L2 终结，无 ip/tcp/udp 层键）。
2. 正向用例 `expect_error:false`；负向 `expect_error:true` 且必须带 `error_contains`（不许裸 fail）。
3. 全部正向用例至少 1 条 FrameAssert（兜底无 goose 解析器）；tshark goose.* 字段断言全部标注"可用则启用"。
4. JSON 中十六进制一律小写（`0x88b8`、`0x1000`）、frame offset 相对以太头起点。

---

## 9. 测试执行与回归

### 9.1 用例→运行映射

```bash
# 全量 GOOSE 用例
cd trafficgen && go test ./test/protocol_pcap/ -run TestGoose/ -v -count=1

# 单例（拿到 pcap 后可 tshark 手查）
go test ./test/protocol_pcap/ -run 'TestGoose/goose_no_ip' -v -count=1

# 无 IP 证明复核
tshark -r /tmp/goose_no_ip.pcap -Y 'ip' | wc -l        # 期望 0
tshark -r /tmp/goose_no_ip.pcap -x | head -30          # 0x88B8 后直接 BER
```

### 9.2 回归棋盘（spec 字段 ↔ 用例 ↔ pcap 断言）

| spec 元素（design.md） | 用例 | pcap 断言点 |
|---------------------------------|------|-------------|
| §2.4 APPID/Length/Reserve | S1-01/02 | 头 8 字节 FrameAssert |
| §3.3-3.8 APDU BER 标签 | S1-01 | `0x61`/`0x80..0x8A`/`0xAB` 逐字节 |
| §3.6 MMS Data 内部 tag | S5-01/S7-01 | allData 成员 hex |
| §4.1/§4.2 有限帧序列 | S2-01 | sqNum 0..5 递增 |
| §4.2 变化 stNum+1/sqNum 重置 | S2-02 | `86 01 00` |
| §4.3 test/ndsCom | S3-01/02 | `87 01 01`/`89 01 01` |
| §4.1/§4.2 有限心跳 | S1-01 | stNum 恒同 + sqNum 递增 |
| §2.1/§3.1 组播/无 IP | S6-01 | EtherType+frame.protocols |
| §6.4 VLAN | S4-01 | TCI 0x8064 |
| §3.8 多数据集 | S7-01 | num==6==成员数 |
| §9 错误表 | 15 负例 | expect_error + error_contains |

### 9.3 已知运行时变数（回归口径）

- `t` 为墙钟：只断言 `84 08` 标签长度段，**不断言 8 字节内容**。
- 实现按有限 `count` 生成帧；不承诺运行时 TMax/t0 退避调度或 clamp。

---

## 10. P-PIPE 测试契约（T1–T6）

### 10.1 T1：三源与原子测试点

三源为 IEC 61850-8-1 规范（EtherType、APPID、BER/APDU、状态机）、设计文档 D1–D8、以及现有 33 例 pcap/FrameAssert 实测。每个设计行为均拆成原子点：L2 EtherType/无 IP、APPID/Length/Reserve、VLAN、APDU 标签顺序、最小 BER 整数、各数据类型、stNum/sqNum、test/ndsCom/confRev、成员计数、错误传播。

### 10.2 T2：原子用例索引与存量对账

JSON 33 个唯一 ID 均纳入本契约：9 个核心正例（heartbeat/retransmit/dataset/test/nds/VLAN/multitype/multidataset/no-IP）+ 9 个扩展正例（goID、起始序号、整数/字符串/时间类型、组合事件/标志）+ 15 个负例（presence、静态复制、APPID、sqNum、stNum、confRev、空 data、非法类型、空引用/超长/TAL/IP/VLAN/上限）。以 JSON ID 为权威，不把旧文档的 13 例声明当作现状。

### 10.3 T3：三类覆盖与 §3.15

数据覆盖正常、边界、非法和运行期时间；行为覆盖心跳、事件重发、数据集变化、标志/VLAN/多类型；环境覆盖有/无 tshark goose 解析器。GOOSE 无长连接会话、无控制/数据分离事务，因此 §3.15 的长保活、同连接多轮事务、异常结束均标记 N/A；事件序列仍以多帧状态机用例覆盖，不用重复模板冒充事件编排。

### 10.4 T4：字段/形状/断言清单

正例必须有 `layers`，`layers` 必须以 `eth` 开始并以 `goose` 终结；地址/MAC/业务键只能住对应层；数量使用 `flow_control`，单流帧预算 `goose.count` 仅保留现有引擎语义。正例至少一条 FrameAssert；动态 `t` 只断言 `84 08`；负例必须 `expect_error:true` 且 `error_contains` 指向具体规则。

### 10.5 T5：A′/B′ 与缺口

A′（实现已覆盖但缺独立断言）：Reserve 位非零、最大合法引用/数值、多个事件连续交错、NIC 抓包、性能六场景。B′（代码能力或协议扩展缺口）：厂商 IED 三路行为对照 G-GOOSE-1；吞吐/CPU/内存/队列/NIC 基准 G-GOOSE-2；动态业务字段与帧预算最终分工 G-GOOSE-3；array/structure 编码扩展另立项。不能确认的项目不标完成。

### 10.6 T6：反查门

反查脚本/人工检查应验证：33 JSON ID 与本文索引无差集；正例顶层非白名单键为 0；正例均 `[eth,goose]`；负例锚词非空且与 validator 分支对应；每个正例至少一条 frame/field 可观测断言；文档的数量、链形、字段名与 JSON 实际一致。

## 11. P-PIPE 补齐附录（T1–T6，2026-10-01）

### 11.1 T1 三源回指

规范源为 IEC 61850-8-1（L2 映射、APPID/Length、BER 字段、状态序号、VLAN）；设计源为 `design.md` §2–§6、§9、§13；现网/实现源为 `trafficgen/internal/protocol/goose/goose.go`、`ber.go`、schema/layers 校验及 pcap FrameAssert。每一原子点均有 JSON ID：EtherType/无 IP→`goose_no_ip`；头字段→`goose_heartbeat`；VLAN→`goose_vlan`；BER 类型→`goose_multitype`/`goose_int64`/`goose_uint64`/`goose_octet_string`/`goose_utc_time`；序列→`goose_retransmit`/`goose_dataset_change`；错误→15 条负例。厂商 IED 差异没有本树样本，确认方式为取得厂商 pcap 后逐字段重跑，编号 G-GOOSE-1。

### 11.2 T2 测试点清单先行

| 规范条文 | 业务场景 | 代码分支 | 覆盖/缺口 |
|---|---|---|---|
| L2 0x88B8、组播 | 无 IP 单帧 | goose layer + eth builder | `goose_no_ip` |
| APPID/Length/Reserve | 标准头 | frame builder | `goose_heartbeat` |
| BER tag/最小整数 | 标量、时间、字符串 | `ber.go` | `goose_multitype`及扩展正例 |
| stNum/sqNum | 心跳、变化、重发 | `emitGooseFrames` | heartbeat/retransmit/dataset/combo |
| VLAN 802.1Q | PCP/VID | eth layer | `goose_vlan`, `goose_neg_vlan` |
| 失败边界 | 空、超长、越界、承载 | schema/validator | 15 负例 |
| 静态复制 | flows>1 | layer static-copy validator | `goose_vn_static_copy` |

### 11.3 T3 颗粒度、三类场景与强度

每例只钉一个主行为，复合行为拆为独立 ID。数据场景覆盖空/最大引用、TAL、APPID/VLAN 边界、BER 类型与长度；业务场景覆盖心跳、事件首帧、重发、连续事件和标志组合；现网场景覆盖标准组播、VLAN 过程总线及无/有 goose tshark 解析器。枚举逐值落在 `goose_multitype`、类型扩展和负例；正交矩阵为 VLAN×标志×事件×数据类型；动态整格对 `t` 只做运行期存在性，不虚构业务动态；断言边界由 FrameAssert 钉 tag/offset，无法固定墙钟内容则明确不定值。

### 11.4 T4 §3.15 三项

GOOSE 无长连接会话，三项均为协议不适用但已给替代证据：同连接多轮操作=N/A（无连接；事件多帧序列由 `goose_combo_event` 覆盖）；非正常结束=N/A（无会话释放；validator 失败由全部负例覆盖）；长保活=N/A（无定时器；有限心跳 `goose_heartbeat`/`goose_combo_event` 覆盖可观察连续帧）。不是空缺，也不把重复静态帧冒充事务。

### 11.5 T5 存量逐条去向

旧稿 S1–S7 与 NEG-01..03 均保留并映射到对应 JSON；扩展存量 `goose_goid`、`goose_start_sqnum`、`goose_start_stnum`、`goose_int64`、`goose_uint64`、`goose_octet_string`、`goose_utc_time`、`goose_combo_flags`、`goose_combo_event` 合入现行清单；`goose_vn_empty_layer`、`goose_vn_presence`、`goose_vn_static_copy`、`goose_neg_confrev`、`goose_neg_no_data`、`goose_neg_type`、`goose_neg_gocbref`、`goose_neg_str255`、`goose_neg_tal`、`goose_neg_sqnum_max`、`goose_neg_ip_carrier`、`goose_neg_vlan` 为新增边界/迁移守卫。无 JSON ID 作废；历史“13 项”仅核心子集，不代表总量。

### 11.6 T6 失败路径与可观测输出

15 条负例的 `expect` 严格只含 `expect_error`、`error_contains`，分别命中 validator 的真实锚词：`outside GOOSE range 0x0000-0x3fff`、`sqNum step`、`stNum must not overflow`、`top-level goose sub-config`、`static four-tuple`、`conf_rev must be non-zero`、`at least one`、`unsupported data type`、`gocb_ref and dat_set are required`、`exceed 255 bytes`、`tal_ms must be in`、`must not have an ip/transport carrier`、`goose VLAN is out of range`。提交坏配置必须真实失败；正例以 packet_count、fields 或 frames 观测输出，不以“不报错”冒充通过。

### 11.7 完整 ID 对账

顺序固定为：`goose_heartbeat`, `goose_retransmit`, `goose_dataset_change`, `goose_test_flag`, `goose_ndscom_flag`, `goose_vlan`, `goose_multitype`, `goose_multidataset`, `goose_no_ip`, `goose_neg_appid`, `goose_neg_sqnum`, `goose_neg_stnum`, `goose_vn_presence`, `goose_vn_static_copy`, `goose_neg_confrev`, `goose_neg_no_data`, `goose_neg_type`, `goose_neg_gocbref`, `goose_neg_str255`, `goose_neg_tal`, `goose_goid`, `goose_start_sqnum`, `goose_start_stnum`, `goose_int64`, `goose_uint64`, `goose_octet_string`, `goose_utc_time`, `goose_combo_flags`, `goose_combo_event`, `goose_vn_empty_layer`, `goose_neg_sqnum_max`, `goose_neg_ip_carrier`, `goose_neg_vlan`。总计 33：正例 18，负例 15。32 例层链是 `[eth,goose]`；唯一差异是故意的 `goose_neg_ip_carrier` 使用 `[ip,goose]` 判死形，另有 `goose_vn_presence` 保留顶层 `goose` presence 负例。正例顶层仅 `layers`；负例错误断言键形均严格两键。



- **C1 层链唯一真相**：33/33 `spec_json` 含 `layers`；32/33 为合法或专门判死的 `[eth,goose]`，唯一 `goose_neg_ip_carrier` 为故意 `[ip,goose]` 负例。
- **C2 顶层白名单**：18 个正例顶层仅 `layers`；`goose_vn_presence` 的顶层 `goose` 是故意 presence 判死对象，不计残留；无顶层地址、端口、MAC、业务子映射或 `count`。
- **C3 L2/MAC 约束**：正例源 MAC 与目标 MAC 均住 `layers[].eth`（`src_mac`/`dst_mac`）；GOOSE 层只承载业务字段；EtherType 固定 0x88b8；不得出现 IP/传输层。
- **C4 失败锚点**：15 个负例均 `expect_error:true` 且 `expect` **严格只有** `expect_error`、`error_contains` 两键；`error_contains` 指向 appid、sqNum、stNum、confRev、data/type/ref/tal/VLAN、presence 或 carrier 规则。
- **C5 文档/JSON 对账**：JSON 33 ID 是当前存量权威；旧 §3.1 的 13 项仅历史核心集合，扩展 ID 逐条纳入 T2，不得再宣称 13 例总量。
- **C6 可观测性**：正例均有 fields 或 frames 断言；tshark 解析器缺失时 FrameAssert 仍可验证；时间戳不写死墙钟内容。


| 版本 | 日期 | 变更 |
|------|------|------|
| v1.0.0 | 2026-08-18 | 初稿：S1..S7 正向 + NEG-01..15，双层断言（FrameAssert 兜底 + tshark goose.* 可选增强），覆盖清单 §7，JSON 一致性表（历史 12 项核心用例） |

> 联合核对源：/tmp/libiec61850（goose_publisher.c、mms_access_result.c）、/tmp/ws2/packet-goose.c（Wireshark 解析器）——与 design.md §11 一致。
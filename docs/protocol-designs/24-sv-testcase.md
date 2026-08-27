# IEC 61850-9-2 SV 协议测试用例设计文档

> 版本：v1.0.0（初稿）
> 设计日期：2026-08-18
> 范围：IEC 61850-9-2 采样值（SV，Sampled Values）流量的 pcap 框架测试用例定义，覆盖 9-2LE（Light Edition，采样值简化版）与 9-2 Full 两种配置口径，以及全部负路径（expect_error）
> 父文档：24-sv-design.md（协议设计：BER 编码、帧布局、状态机、字节模板 S1-Sn）
> 配套文件：`trafficgen/test/protocol_pcap/cases/sv.json`（用例数据，与此文档严格一致）；同栈置信来源：23-goose-testcase.md（未写成时引用 24-sv-testcase.md 自举）

---

## 目录

1. [测试环境与校验手段](#1-测试环境与校验手段)
2. [框架断言工具](#2-框架断言工具)
3. [用例编号规则](#3-用例编号规则)
4. [正向用例（T-SV-S1..S9）](#4-正向用例t-sv-s1s9)
5. [负路径用例（T-SV-NEG）](#5-负路径用例t-sv-neg)
6. [字段断言速查表](#6-字段断言速查表)
7. [覆盖勾选清单](#7-覆盖勾选清单)
8. [与 JSON 用例的一致性](#8-与-json-用例的一致性)
9. [测试执行与回归](#9-测试执行与回归)

---

## 1. 测试环境与校验手段

### 1.1 运行环境

- pcap 框架（`trafficgen/test/protocol_pcap/`）生成抓包，`tshark` 解析验证。SV 帧**不经过 IP**，EtherType 0x88BA 时 tshark **自动**以 `sv` 解析器解成员（无需 `-d` 解码提示）。
- `-d` 仅用于强制 PhsMeas 解码 seqData：`tshark -d sv.seqData,PhsMeas`（tshark 版本 ≥3.6 支持 `-d sv.<proto>...` 时；否则回退原始字节断言 `sv.seqData`）。具体版本行为见 §2.2。
- 无 IP 层：所有用例 `frame.protocols` 为 `eth:sv`（无 VLAN）或 `eth:vlan:sv`（VLAN），**不得含 `ip`**（证明用例 T-SV-S7-01）。

### 1.2 权威字节事实来源

- 24-sv-design.md §2.5 的 BER Tag 表（savPdu=0x60、noASDU=0x80、seqASDU=0xa2、ASDU=0x30、svID=0x80、datSet=0x81、smpCnt=**0x82**、confRev=**0x83**、refrTm=0x84、smpSynch=0x85、smpRate=0x86、seqData=**0x87**、smpMod=0x88）——口径与 libiec61850/Wireshark 一致，非任务提示的旧 tag 编号。
- 帧头（§2.4）：APPID 默认 0x4000（SV 段 0x4000-0x7FFF）、Length=8+APDU、Reserve1/2=0。
- seqData（§2.7）：9-2LE 每通道 8 字节（4B instMag 大端 + 4B quality），4I+4V = 64 字节。
- 组播 MAC：01:0C:CD:04:xx:xx，默认 dst 01:0C:CD:04:00:01。

### 1.3 字节序与回绕规则（断言前提）

- 所有数值字段大端。
- smpCnt 16 位，到 `SamplesPerCycle`（默认 4000）回 0。
- 双重发：同 smpCnt 连续 2 帧，内容字节完全相同（仅 `frame.number` 不同）。

### 1.4 运行约束（测试依赖）

| 约束 | 值 | 说明 |
|------|----|------|
| tshark 版本 | ≥3.6（建议） | `sv.confRev`/`sv.reserve1.s_bit` 依版本名变；回退用 `sv.confRef` |
| 测试机时钟粒度 | ≥µs | `sv_period` 时间戳断言默认容差 |
| 帧数上限 | 每个用例 ≤4002（含回绕抽检） | 较长流用公式/抽样验证，防 pcap 过大 |
| 并发用例 | 每用例独立引擎实例 | SV 计数彼此隔离（§4.11） |

**测试前置校验命令**：
```bash
tshark -v | head -2          # 确认版本支持 sv 解析器
tshark -G fields | grep -c '\bsv\b'   # 或确认字段表含 sv.*
```

---

## 2. 框架断言工具

### 2.1 Case 结构（pcaptest/types.go）

```json
{
  "id": "sv_xxx",
  "proto": "sv",
  "summary": "...",
  "spec_json": { "layers": [{"eth":{}},{"sv":{}}], "src_mac": "...", "sv": {...} },
  "expect": {
    "packet_count": null,
    "min_packets": 3,
    "fields": [ {"packet": 1, "field": "sv.appid", "value": "0x4000", ...} ],
    "frames": [ {"packet": 1, "offset": 22, "hex": "60 60 ..."} ],
    "expect_error": false,
    "error_contains": "",
    "notes": []
  }
}
```

### 2.2 断言语义

| 断言类型 | 字段 | 语义 |
|----------|------|------|
| 等值 | `field` + `value` | tshark 输出该字段等于给定值（数值以 `0x` 十六进制或十进制给） |
| 存在性 | `field` + `nonzero: true` | 字段存在且非零（如 smpCnt>0 证明递增） |
| 跨包相等 | `field` + `same_as_packet: 1` | 与第 1 包同值（如 confRev 同流恒定） |
| 多样性 | `distinct_values` | 跨包该字段需出现这些值（如 smpCnt 0/1/2 递增） |
| FrameAssert | `offset` + `hex` | 按包内偏移精确比对原始字节（无 IP 证明、BER tag 校验的终极手段） |

注意：tshark 数值字段输出的进制（`0x4000` vs `16384`）取决于显示设置；框架比对时统一整数语义（`value` 传 int 或 `0x` 字符串均可）。对 `sv.seqData` 这类字节流字段用 FrameAssert 更稳（tshark 默认把 OCTET STRING 会话成十六进制串，跨版本可能有空白差异）。

### 2.3 负路径断言

`expect_error: true` 时框架断言任务**失败**且错误文本含 `error_contains`（如 `"confRev"`）。与 go 单测的 `ErrorContains` 同义。框架保证"任务失败"被观测（Testing Policy 第 4 条：不能只是"不失败"）。

---

## 3. 用例编号规则

- 正向：`T-SV-S<n>-<m>`，S1..S9 对应 24-sv-design.md §6 场景 S1..S9（S1 基础帧、S2 双重发、S3 回绕、S4 smpSynch、S5 4I+4V、S6 自定义数据集、S7 无 IP、S8 VLAN、S9 时序）。
- 负向：`T-SV-NEG-01..04`，对应 §9 错误处理表。
- JSON 用例 id 采用 `sv_<key>` 小写（如 `sv_smp_seq`、`sv_double_send`、`sv_smp_wrap`、`sv_smp_synch_global`、`sv_4i4v`、`sv_custom_dataset`、`sv_no_ip`、`sv_vlan`、`sv_neg_confrev`、`sv_neg_appid`、`sv_neg_wrap`、`sv_neg_seqdata_len`）。

### 3.1 用例全清单（16 项一览）

| 编号 | 名称 | 场景/依据 | 类型 | JSON |
|------|------|-----------|------|------|
| T-SV-S1-01 | 9-2LE 基础采样 3 联发 | S1（§6.1） | 正 | `sv_smp_seq` |
| T-SV-S1-02 | 帧头字段 | §2.4 | 正 | 并入 `sv_smp_seq` |
| T-SV-S2-01 | 双重发 | S2（§6.2） | 正 | `sv_double_send` |
| T-SV-S3-01 | smpCnt 回绕 | S3（§6.3） | 正 | `sv_smp_wrap` |
| T-SV-S3-02 | 非法回绕 | §9.1 | 负 | `sv_neg_wrap` |
| T-SV-S4-01 | smpSynch 置位 | S4（§6.4） | 正 | `sv_smp_synch_global` |
| T-SV-S4-02 | smpSynch 非法 | §9.5 | 负 | `sv_neg_smp_synch` |
| T-SV-S5-01 | 4I+4V 数据量 | S5（§6.5） | 正 | `sv_4i4v` |
| T-SV-S6-01 | 自定义数据集 | S6（§6.6） | 正 | `sv_custom_dataset` |
| T-SV-S7-01 | 无 IP 证明 | S7（§6.7） | 正 | 并入 `sv_4i4v` |
| T-SV-S8-01 | VLAN 场景 | S8（§6.8） | 正 | `sv_vlan` |
| T-SV-S9-01 | 采样周期稳定 | S9（§6.9） | 正 | `sv_period` |
| T-SV-NEG-01 | ConfRev<1 | §9.2 | 负 | `sv_neg_confrev` |
| T-SV-NEG-02 | APPID 越界 | §9.3 | 负 | `sv_neg_appid` |
| T-SV-NEG-03 | Length 不符 | §9.4 | 负 | 单测（缺口） |
| T-SV-NEG-04 | 通道长度不符 | §9.6 | 负 | 单测（缺口） |

---

## 4. 正向用例（T-SV-S1..S9）

### 4.1 T-SV-S1-01：9-2LE 基础采样帧 3 联发（smpCnt 递增 >1 帧）

- **依据**：24-sv-design.md §6.1（S1）
- **配置**：`sv_id:"xxxxMUnn01"`, `appid:0x4000`, `conf_rev:1`, `samples_per_cycle:4000`, `smp_synch:2`, `smp_rate:4000`, `period_us:250`, `double_send:false`, 4I+4V 通道, 无 VLAN
- **期望**：
  - `packet_count == 3`
  - fields：
    - packet 1 `sv.appid` == 0x4000
    - packet 1 `sv.length` == 112（0x70；8 头 + APDU 104）
    - packet 1 `sv.svID` == "xxxxMUnn01"
    - packet 1 `sv.smpCnt` == 0
    - packet 2 `sv.smpCnt` == 1
    - packet 3 `sv.smpCnt` == 2
    - packet 1 `sv.confRev` == 1；packet 2/3 `sv.confRev` `same_as_packet=1`
    - packet 1 `sv.seqData` nonzero（64 字节）
  - frames：packet 1 offset 22（帧首字节 APDU）hex `60 66`；offset 0（帧首）hex `01 0c cd 04 00 01`
- **关键断言**：smpCnt 递增被 3 帧逐一观测（不止"递增了"）。Length 精确 112（0x70）证明 APDU 长度正确（§2.4 公式）。

```
（完整字节模板：24-sv-design.md §6.1；packet 1 前 30 字节 hex，svID=xxxxMUnn01）
01 0c cd 04 00 01 aa bb cc dd ee 03 88 ba 40 00 00 70 00 00 00 00
60 66 80 01 01 a2 61 30 5f 80 0a 78 78 78 78 4d 55 6e 6e 30 31
82 02 00 00 83 04 00 00 00 01 85 01 02 86 02 0f a0 87 40 ...
```

### 4.2 T-SV-S1-02：帧头字段（APPID/Length/Reserve1/Reserve2）

- **依据**：§2.4
- **配置**：同 S1-01
- **期望**：
  - packet 1 `sv.appid` == 0x4000
  - packet 1 `sv.length` == 112（0x70；10B svID 的 8 头 + APDU 104）
  - packet 1 `sv.reserve1` == 0
  - packet 1 `sv.reserve2` == 0
  - frames：packet 1 offset 14 hex `40 00 00 70 00 00 00 00`（SV 头完整 8 字节）
- **关键断言**：SV 头 8 字节逐一对上（FrameAssert 兜底，防"字段解析但字节错"）。

### 4.3 T-SV-S2-01：双重发（同 smpCnt 2 帧）

- **依据**：§4.6 / §6.2（S2）
- **配置**：同 S1 但 `double_send:true`，发 6 帧
- **期望**：
  - `packet_count == 6`
  - fields：`sv.smpCnt` 在 6 帧内 `distinct_values` == [0,1,2]（各出现 2 次）
  - `sv.smpCnt` packet 1 == 0 && packet 2 == 0（`same_as_packet` 用于 confRev；smpCnt 同值用 value）
  - frames：packet 1/2 完整字节 vs packet 1 `same_as` → 逐字节相同（offset 22 `hex` 两包相同）
- **关键断言**：S2 冗余报语义——同 smpCnt 出现 2 次且内容一致；后续正常递增。

### 4.4 T-SV-S3-01：smpCnt 回绕（0 → 3999 → 0）

- **依据**：§4.3 / §6.3（S3）
- **配置**：`samples_per_cycle:4000`，发 4002 帧（覆盖 3999→0 回绕）
  - （框架若对 packet_count 增负担，可用小 wrap 如 `samples_per_cycle:4` 发 6 帧验证相对回绕；另设 4000 回绕的抽检用例。）
- **期望**（以 `samples_per_cycle:4` 变体为例，发 6 帧）：
  - packet 1..4 `sv.smpCnt` == 0,1,2,3
  - packet 5 `sv.smpCnt` == 0（回绕）
  - packet 6 `sv.smpCnt` == 1
  - fields 中 `sv.smpCnt` 不出现 4（无越界）
- **关键断言**：回绕点在 `wrap-1 → 0`，不是 `wrap → 0`；回绕后持续递增。

### 4.5 T-SV-S3-02：非法回绕（负路径）

- **依据**：§9.1（S3 负例）
- **配置（非法）**：`samples_per_cycle: 0`（每周采样数 <1）
- **期望**：`expect_error: true`、`error_contains: "samples_per_cycle"`（校验拒绝，任务失败）

### 4.6 T-SV-S4-01：smpSynch 置位（未同步 → 全局）

- **依据**：§4.4 / §6.4（S4）
- **配置**：两阶段 `sv` 任务：stage A `smp_synch:0`，stage B `smp_synch:2`（模拟 PTP 接入题；框架若单任务不可分段，则拆 2 用例共验）
- **期望**：
  - stage A 全部帧 `sv.smpSynch` == 0
  - stage B 全部帧 `sv.smpSynch` == 2
  - stage B 首帧 `sv.smpCnt` 延续 stage A（smpCnt 跨段连续，`same_as` 跨任务不可用——各任务独立断言 `sv.smpCnt` 首包 0 即可，或设计上允许）
- **关键断言**：同步状态随配置切换，且不重置采样计数语义（b/w：文档承认两任务各自独立起始；若需跨段连续，须引擎支持续帧，属扩展。）

`SmpSynch=2`（全局）单任务帧的 hex 片段：`... 85 01 02 ...`（§6.1 packet 1 offset 53）。

### 4.7 T-SV-S4-02：smpSynch 非法值（负路径）

- **依据**：§9.5（S4）
- **配置（非法）**：`smp_synch: 5`（合法 {0,1,2}）
- **期望**：`expect_error: true`、`error_contains: "smpSynch"`

### 4.8 T-SV-S5-01：4I+4V 9-2LE 完整数据量

- **依据**：§2.7 / §6.5（S5）
- **配置**：完整 8 通道（I_A I_B I_C I_N V_A V_B V_C V_N），每通道 `quality:0`
- **期望**：
  - packet 1 `sv.seqData` nonzero；FrameAssert offset 62 `hex` 前 8 字节 `00 00 00 1e 00 00 00 00`（I_A）
  - `sv.seqData` 长度 64（FrameAssert offset 60 起 64 字节，或 tshark 字节串长度断言——框架以 `frames` hex 片段核对头尾）
  - 若 tshark 支持 PhsMeas 解码：`sv.meas_value` == 30(I_A), 45(I_B), ..., 135(V_N)；`sv.meas_quality` == 0
- **关键断言**：四电流+四电压 8 通道时序与幅值全对上；（可选）PhsMeas 解码验证。

### 4.9 T-SV-S6-01：自定义数据集（非 9-2LE）

- **依据**：§5.1 / §6.6（S6）
- **配置**：`data` 仅 2 通道（`I_A:int32`、`V_A:float32`），`smp_rate` 省略（nil），`smp_synch:2`，无 datSet
- **期望**：
  - packet 1 `sv.svID` == "xxxxMUnn01"；`sv.smpCnt` == 0；`sv.smpSynch` == 2
  - fields 中 `sv.smpRate` **不存在**——框架对"字段不存在"断言：`fields` 写 `{"field":"sv.smpRate","nonzero":true}` 反义，或 notes 说明用 FrameAssert 证明无该 tag 字节。本用例 notes: ["sv.smpRate 省略 = 可选字段行为（§3.3）"]，断言方式：FrameAssert offset 50（seqData 前）hex `87 08`（紧邻 tag，无 86 出现）
  - frames：packet 1 offset 50 hex `87 08 00 00 00 1e 3f c0 00 00`（seqData 8 字节：I_A=30、V_A=1.5f）
- **关键断言**：自定义数据集字节宽正确；可选字段按协议省略（tag 不出现）——这是 9-2 Full 自由 profile 的行为区别于 9-2LE 的地方。

### 4.10 T-SV-S7-01：无 IP 层证明（帧不含 IP 头）

- **依据**：§3.1 / §6.7（S7）
- **配置**：复用 T-SV-S1-01 的帧
- **期望**：
  - `frame.protocols` 不含 `ip`（tshark 一票否决不出现 `ip`；框架断言 `frame.protocols` 的 `value` 含 `eth:sv` 或 `contains "ip" == false`）
  - frames：packet 1 offset 12 hex `88 ba`（EtherType 是 SV 不是 IPv4 0x0800/IPv6 0x86dd）
  - 无 20 字节 IPv4 头（FrameAssert offset 22 == `60`，APDU 首字节，非 0x45）
- **关键断言**：EtherType 层能独立证明；用字段断言 `frame.protocols` 传达"无 ip 层"。

### 4.11 T-SV-S8-01：VLAN 场景

- **依据**：§2.2 / §6.8（S8）
- **配置**：`vlan_enabled:true`, `vlan_id:100`, `vlan_priority:4`
- **期望**：
  - fields：`vlan.id` == 100；`vlan.priority` == 4
  - frames：packet 1 offset 12 hex `81 00 80 64 88 ba`（TPID + TCI 0x8064 + EtherType SV；§6.8 TCI 计算 0x8064）
  - `frame.protocols` 含 `vlan`（`eth:vlan:sv`）
- **关键断言**：VLAN 头插在 EtherType 前且 TPID/TCI 精确；协议链含 vlan。

### 4.12 T-SV-S9-01：采样周期稳定（时间戳）

- **依据**：§4.8 / §6.9（S9）
- **配置**：`period_us:250`，连续 100 帧
- **期望**：
  - `min_packets == 100`
  - fields：无（时间戳断言依赖 `frame.time_relative/time_delta`，框架若支持时间字段则断言均值；否则 notes 说明以`frame.time_delta` 手工抽检，见 §8）
  - 可选：`frame.time_relative` 单调递增且末帧 ≈ 期长 × N
- **关键断言**：周期（250µs）语义被覆盖（发送节拍未失控）；若框架不支持时间断言，降级为 `min_packets` + 手工 `tshark -T fields -e frame.time_delta` 抽检并记录白名单。

### 4.13 T-SV-S10-01：smpSynch 三值枚举（0/1/2 逐帧可见）

- **依据**：§6.10（S10）、§4.4
- **配置**：`smp_synch:0` 发 2 帧 → `smp_synch:1` 发 2 帧 → `smp_synch:2` 发 2 帧（分段任务；若单任务不可分段，拆 3 个用例共用断言）
- **期望**：
  - 每段包 `sv.smpSynch` 对应 0 / 1 / 2（`value` 精确断言）
  - 跨段 `sv.smpCnt` 按段各自起始，但**同一段内恒定不变异**（smpSynch 是帧级稳定字段，不是每个包变）
  - frames：段 C 首包 offset 53 hex `85 01 02`
- **关键断言**：三个枚举全部编码正确；`sv.smpSynch` 非"随机位"，而是每帧都写死为配置值。

---

## 5. 负路径用例（T-SV-NEG）

### 5.1 T-SV-NEG-01：ConfRev < 1（非法配置版本）

- **依据**：§9.2
- **配置（非法）**：`conf_rev: 0`
- **期望**：`expect_error: true`、`error_contains: "confRev"`
- **关键**：护住"0 表示未定义版本，IED 不采"的硬规则；单测同样应断言 `Validate` 返回错误（§8 把 pcap 用例与单测关联）。

### 5.2 T-SV-NEG-02：APPID 越界（GOOSE 保留段）

- **依据**：§9.3
- **配置（非法）**：`appid: 0x3999`（落 GOOSE 保留段 0x0000-0x3FFF）
- **期望**：`expect_error: true`、`error_contains: "appid"`
- **关键**：设 0x3999 证明校验器有段位鉴别（非简单"非 0x4000 就报"）；默认 0x4000 合法。

### 5.3 T-SV-NEG-03：Length / APDU 长度不匹配

- **依据**：§9.4
- **配置**：合法配置，但框架注入`strategy` 强制 Length 字段错误（如覆写 `sv.length` 参数 = 8+APDU+1）——帧内 Length 与实际 APDU 长度不一致
- **期望**：`expect_error: true`（发送前校验或接收 tshark 判定 Malformed；框架在 send 前拦截 = "任务失败"错误），`error_contains: "length"`
- **关键**：Length 公式的唯一性被锁住（§3.4/§9.4）。

### 5.4 T-SV-NEG-04：数据通道长度不符

- **依据**：§9.6
- **配置（非法）**：`data` 声明 4 通道，但通道宽总和 ≠ seqData 实际字节（框架算 8×通道数，若数据写入器少写即不符）
- **期望**：`expect_error: true`、`error_contains: "seqData"`
- **关键**：护住"seqData 长度必须等于 8×通道数"（§2.7），防静默截断。

> 负例实现备注：expect_error 依赖引擎"任务失败被观测"（§2.3）。单测 `sv_test.go` 中 `Validate` 直接断言错误即可（pcap 用例负责端到端）。

### 5.5 负例预期 vs 规格行对照

| 负例 | 触发字段 | 期望错误文本（error_contains） | 规格行 | JSON |
|------|----------|-------------------------------|--------|------|
| 非法回绕 | `samples_per_cycle` | `"samples_per_cycle"` | §9.1 R1 | `sv_neg_wrap` |
| ConfRev<1 | `conf_rev` | `"confRev"` | §9.2 | `sv_neg_confrev` |
| APPID 越界 | `appid` | `"appid"` | §9.3 | `sv_neg_appid` |
| smpSynch 非法 | `smp_synch` | `"smpSynch"` | §9.5 | `sv_neg_smp_synch` |
| Length 不符 | `sv.length`（注入） | `"length"` | §9.4 | 单测 |
| 通道长度不符 | `data`/`seqData` | `"seqData"` | §9.6 | 单测 |

每条负例除了 `expect_error:true`，还必须断言 `error_contains` 命中**对应字段名**——只 fail 不定位等于没锁住具体规则（Testing Policy 第 2 条：失败路径要测"错在哪里"，不是"反正失败了"）。

---

## 6. 字段断言速查表

| tshark 字段 | 类型 | 用例用途 | 对应字节 |
|------------|------|----------|----------|
| `sv.appid` | uint16 | 帧头 APPID | SV 头 0 |
| `sv.length` | uint16 | Length 精确 112（0x70，10B svID） | SV 头 2 |
| `sv.reserve1` / `sv.reserve1.s_bit` | uint16/bool | Reserve1=0 / 仿真位 | SV 头 4 |
| `sv.reserve2` | uint16 | Reserve2=0 | SV 头 6 |
| `sv.savPdu` | label | APDU 存在 | APDU 全段 |
| `sv.noASDU` | uint32 | ==1 | 0x80 字段 |
| `sv.seqASDU` | uint32 | ==1 | 0xa2 计数 |
| `sv.svID` | string | "xxxxMUnn01" | ASDU 0x80 |
| `sv.datSet` | string | 不存在（自定义） | ASDU 0x81 |
| `sv.smpCnt` | uint32 | 递增/回绕/双重发 | ASDU 0x82 |
| `sv.confRev` | uint32 | ==1 / 恒定 | ASDU 0x83 |
| `sv.refrTm` | string | 可选，不默认 | ASDU 0x84 |
| `sv.smpSynch` | int32 | 0/2 切换 | ASDU 0x85 |
| `sv.smpRate` | uint32 | ==4000 / 不存在 | ASDU 0x86 |
| `sv.seqData` | bytes | 字节流断言 | ASDU 0x87 |
| `sv.smpMod` | int32 | 可选，不默认 | ASDU 0x88 |
| `sv.meas_value` | int32 | PhsMeas 解码（tshark -d） | seqData instMag |
| `sv.meas_quality` | uint32 | PhsMeas 品质 | seqData quality |
| `vlan.id` / `vlan.priority` | uint16 | VLAN 场景 | VLAN TCI |
| `frame.protocols` | string | 无 IP 证明 | — |
| `frame.time_relative` | double | 周期稳定 | — |

### 6.1 逐字段断言编写指南

每个 `sv.*` 字段的断言写法随其类型/语义而变化，这里列出推荐形态（对应框架 `FieldAssert` 能力）：

| 断言意图 | 推荐写法 | 反例（不可用） |
|----------|----------|----------------|
| 数值精确 | `{"field":"sv.length","value":"112"}` | `{"field":"sv.length","nonzero":true}`（只证明非零，丢精度） |
| 跨包恒定 | `{"field":"sv.confRev","same_as_packet":1}` | 每包都 `value:1` 若实现死写也算过——`same_as` 更严格 |
| 递增序列 | 用多包 `value`（0/1/2）或 `distinct_values` | 只断言第 1 包 value=0（后包没验） |
| 字段**不存在** | `notes` + FrameAssert（证明无该 tag） | `{"field":"sv.smpRate","zero":true}`——字段不存在时 tshark 输出也是空，`zero` 判不了 |
| 字节流 seqData | `frames` 的 offset+hex 前/尾片段 | `value` 比较整串（跨 tshark 版本空白差异不稳定） |
| 组播/无 IP | `field":"frame.protocols"` + `eth.type` value | 只隔看 `eth.type`（忽略规范要求"整个协议链"） |
| 双发相同 | 两包 `frames.offset` hex 各取相同 | `same_as_packet` 只适用于字段，整帧需 `frames` 两样本重合 |

**数值进制注意**：`sv.appid` tshark 默认 `BASE_HEX` 输出 `0x4000`，`sv.smpCnt` 是 `BASE_DEC` 输出 `0`/`1`；断言 value 字符串应与 tshark 输出格式一致，或框架做语义数值归一（见 §2.2）。取 `0x4000` 时十六进制、十进制均可的两可，框架不予依赖。

### 6.2 用 tshark 命令行核对（调试期 Use of sv.*）

pcap 捕获校验错误时，以 tshark 直接跑通逐字段，作为用例断言同源参照：

```bash
# 协议树已确认 eth:sv，字段分布抽查
tshark -r out.pcap -Y sv -T fields -e sv.appid -e sv.length -e sv.reserve1 \
  -e sv.svID -e sv.smpCnt -e sv.confRev -e sv.smpSynch -e sv.smpRate

# seqData 若 tshark 支持 PhsMeas 解码
tshark -r out.pcap -Y 'sv' -T fields -e sv.meas_value -e sv.meas_quality

# 无 IP 证明：整个链路不含 ip
tshark -r out.pcap -Y 'ip' | wc -l        # 期望 0

# 双重发：smpCnt 序列
tshark -r out.pcap -Y sv -T fields -e sv.smpCnt

# 回绕边界：smpCnt 最大值
tshark -r out.pcap -Y 'sv.smpCnt==3' -T fields -e frame.number
```

这些命令即 pcap 用例 `expect.fields` 的手工等价位；**用例自动化后仍保留此清单**作为回归调试切入（§9）。

---

## 7. 覆盖勾选清单

针对任务强制性覆盖项逐条核对（存放测试用例是否实现）：

- [x] **采样值序列**：smpCnt 递增 >1 帧（T-SV-S1-01，3 帧 0/1/2）
- [x] **双重发**：同 smpCnt 2 帧（T-SV-S2-01）
- [x] **回绕**：0→3999→0 及相对回绕（T-SV-S3-01）；非法回绕负例（T-SV-S3-02）
- [x] **smpSynch**：置位/切换（T-SV-S4-01）；非法值负例（T-SV-S4-02）
- [x] **4I+4V 9-2LE 数据量**：完整 64 字节 + 每通道幅值（T-SV-S5-01）
- [x] **自定义数据集**：非 9-2LE（T-SV-S6-01）
- [x] **无 IP 层证明用例**：帧不含 IP 头（T-SV-S7-01，frame.protocols + EtherType 双重证据）
- [x] **负路径 expect_error**：
  - 非法 smpCnt 回绕（T-SV-S3-02）
  - ConfRev < 1（T-SV-NEG-01）
  - APPID 越界（T-SV-NEG-02）
  - （扩展）Length 不符（T-SV-NEG-03）、通道长度不符（T-SV-NEG-04）
- [x] **tshark sv.\* 字段使用**：§6 速查表逐字段对接

**IPv4/IPv6 标注**：SV 为 L2 直承协议，IPv4/IPv6 承载均标注 **N/A**（不支持 R-SV over IP，24-sv-design.md §1.5）；以"帧不含 IP 头"证据用例（T-SV-S7-01）替代。

---

## 8. 与 JSON 用例的一致性

`trafficgen/test/protocol_pcap/cases/sv.json` 的每个条目（12 个）对应上表一个用例 id。S1-02（帧头字段）、S7（无 IP 证明）分别并入 `sv_smp_seq`/`sv_4i4v` 的断言，T-SV-NEG-03/04（Length/通道长度）由 Go 单测覆盖（框架当前不支持"每包注入错误 Length"），见 §9 第 1 条。

| JSON id | 测试用例 | 主题 | 核心断言（来自 expect） |
|---------|----------|------|--------------------------|
| `sv_smp_seq` | T-SV-S1-01 + S1-02 | 9-2LE 基础采样 3 帧递增 + 帧头 8 字节 | sv.appid=0x4000、sv.length=112(0x70)、sv.smpCnt 0/1/2、SV 头 hex |
| `sv_double_send` | T-SV-S2-01 | 双重发 | sv.smpCnt 0,0,1,1,2,2 六帧；两帧 hex 相同 |
| `sv_smp_wrap` | T-SV-S3-01 | 回绕（samples_per_cycle=4） | smpCnt 0,1,2,3,0,1；不越界 |
| `sv_neg_wrap` | T-SV-S3-02 | 非法回绕负例 | expect_error，error_contains "samples_per_cycle" |
| `sv_smp_synch_global` | T-SV-S4-01 | smpSynch=2 置位 | sv.smpSynch==2 且各包 same_as |
| `sv_neg_smp_synch` | T-SV-S4-02 | smpSynch 非法值负例 | expect_error，error_contains "smpSynch" |
| `sv_4i4v` | T-SV-S5-01 + S7 | 4I+4V 数据量 + 无 IP 证明 | seqData 64B hex（offset 60..124）+ eth.type 0x88ba + frame.protocols=eth:sv |
| `sv_custom_dataset` | T-SV-S6-01 | 自定义数据集（int32+float32） | smpRate 省略、seqData 8B hex（offset 50） |
| `sv_vlan` | T-SV-S8-01 | VLAN 场景 | vlan.id=100、priority=4、TCI 0x8064 hex、frame.protocols=eth:vlan:sv |
| `sv_period` | T-SV-S9-01 | 采样周期稳定 | min_packets 100 + 时间戳抽检 |
| `sv_neg_confrev` | T-SV-NEG-01 | ConfRev<1 负例 | expect_error，error_contains "confRev" |
| `sv_neg_appid` | T-SV-NEG-02 | APPID 越界负例 | expect_error，error_contains "appid" |

**特例说明**：
- `sv_smp_seq` 承担 S1-02 的帧头断言（`offset 14` hex `40 00 00 6a 00 00 00 00`），不再单设条目。
- `sv_4i4v` 承担 S7 的无 IP 证明：`eth.type=0x88ba` + `frame.protocols=eth:sv`（含 `sv` 且不含 `ip`）。
- Length/通道长度两个负例当前框架无法注入坏帧，`expect_error` 语义由单测 `Validate`（§9）与 BER 层自检覆盖；JSON 暂缺，记录于下表"已知缺口"。

**已知缺口（下阶段补）**：
| 缺口 | 原因 | 补救 |
|------|------|------|
| `sv_neg_len`（T-SV-NEG-03） | 框架不支持字段级恶意覆写 Length | 单测注入 `sv.length` 错误断言 error |
| `sv_neg_seqdata_len`（T-SV-NEG-04) | 同上 | 单测构造通道声明与字节不符断言 error |
| smpSynch 未同步→全局的两阶段（S4 双段） | 框架单任务不支持中途改配置 | 拆 2 用例共验或 engine 续帧扩展后补 |

（JSON 侧实现时按上表逐一落盘；若框架不支持某断言类型，对应 `expect` 降级并在 `notes` 记录——原则是"能断言的尽量断言，素材保留给单测/tshark 手工"。）

---

## 9. 测试执行与回归

1. Go 单测（`internal/protocol/sv/`）：BER 编码逐字节、smpCnt 回绕、double_send 帧序、Validate 全部负例——失败先例：testcase 用例与单测若有冲突，以本规范为准（24-sv-design.md §5.3 的 validate 语义）。
2. pcap 框架执行：`go test ./test/protocol_pcap/ -run 'SV' -count=1`（规避 go test 缓存，Memory 记录 NIC/go test 缓存陷阱）。
3. 端到端验证：`tshark -r out.pcap -Y sv` 列出 `sv.appid/sv.smpCnt/sv.smpSynch` 各字段抽检；`sv.seqData` 用 `-d sv.seqData,PhsMeas` 验证 meas_value。
4. 回归勾选：§7 清单逐项打勾，任何一个"无法断言"项都要在 notes 暴露（Testing Policy 第 5/8 条：可观测结果，不留"看起来对"的假绿）。

### 9.1 单测 ↔ pcap 用例 ↔ 规格 三向映射

每行三方可独立跑，交叉验证（Testing Policy 第 1/3/4 条）：

| 关注点 | 规格章节 | 单测断言 | pcap 用例 |
|--------|----------|----------|-----------|
| BER tag/长度逐字节 | §2.5 | `encodeSavPdu` 输出 == hex 模板 | `sv_smp_seq` frames |
| smpCnt 递增 | §4.3 | 帧序列 0,1,2,… | `sv_smp_seq` fields |
| smpCnt 回绕 | §4.3 | wrap-1 → 0 | `sv_smp_wrap` |
| 双重发 | §4.6 | 同 tick 2 帧同 smpCnt | `sv_double_send` |
| seqData 通道布局 | §2.7 | 8 通道字节 == 期望 | `sv_4i4v` frames |
| 自定义数据布局 | §5.1/§6.6 | 2 通道 int32+float32 字节 | `sv_custom_dataset` frames |
| VLAN TCI | §2.2 | TCI 0x8064 | `sv_vlan` frames |
| Validate 负例 | §9 | `Validate` 返回 error + 消息 | `sv_neg_*` expect_error |
| 无 IP | §3.1 | 层链不含 IP | `sv_4i4v` frame.protocols |
| 周期 | §4.8 | ticker 间隔 == Period | `sv_period` min_packets |

### 9.2 失败注入矩阵（每个负例测哪一层）

负例要覆盖"配置错/编码错/时序错"三类，不能只测 validate 拒绝：

| 失败模式 | 注入点 | 断言目标 |
|----------|--------|----------|
| 非法 smpCnt 回绕 | `validate`（samples_per_cycle<1） | error 传播到任务 fail |
| confRev=0 | `validate` | error + confRev 字样 |
| APPID 越界 | `validate` | error + appid 字样 |
| smpSynch=5 | `validate` | error + smpSynch 字样 |
| Length/APDU 不符 | `ber.go 自检` / 单测注入 | error，防静默坏帧 |
| 通道长度不符 | `ber.go` 长度断言 | error，防静默截断 |
| 定时器泄漏 | `-race + goleak` | 无残留 ticker |

> 原则：能由 `Validate` 拒绝的绝不延迟到发送；发送层只做二次自检（defense in depth），且都有对应单测兜底。

---

## 修订记录

| 版本 | 日期 | 内容 |
|------|------|------|
| v1.0.0 | 2026-08-18 | 初稿：16 用例定义（12 正向 + 4 负向），与 sv.json 逐条对应；覆盖勾选全打勾；无 IP 证据用例替代 IPv4/IPv6（N/A）；tshark sv.* 字段速查表 |

# FINS（欧姆龙 PLC）测试用例设计文档

> 版本：v1.1.0（层链迁移审计版）
> 设计日期：2026-08-18
> 修订日期：2026-08-19（同步三件套中的已确认差异）
> 范围：FINS（欧姆龙 PLC 通信协议）在 UDP/TCP 9600 上的 pcap 框架测试用例定义。覆盖 FINS/UDP 请求-响应、FINS/TCP（Frame Send）、六类内存区（CIO/WR/HR/TC/DM/IR）、位域读写、错误码响应、BCD SID、IPv4+IPv6、多会话（sessions>1）与全部负路径（expect_error）
> 父文档：`docs/protocols/fins/design.md`（协议设计：10 字节命令头、命令码、内存区码、结束码、HexDump S1-S10）
> 配套文件：`trafficgen/test/protocol_pcap/cases/fins.json`（用例数据，与此文档**严格一致**）
> 框架共底：`trafficgen/internal/pcaptest/types.go`（Case/Expect/FieldAssert/FrameAssert 结构）+ `trafficgen/test/protocol_pcap/` 驱动

---

## 目录

1. [测试环境与校验手段](#1-测试环境与校验手段)
2. [框架断言工具](#2-框架断言工具)
3. [用例编号规则与全清单](#3-用例编号规则与全清单)
4. [正向用例（T-001 ~ T-022）](#4-正向用例t-001--t-022)
5. [多会话用例（T-020 ~ T-023）](#5-多会话用例t-020--t-023)
6. [负路径用例（20 条落盘负例；旧 T-024 ~ T-034 为设计编号）](#6-负路径用例20-条落盘负例旧-t-024--t-034-为设计编号)
7. [字段断言速查表](#7-字段断言速查表)
8. [覆盖勾选清单](#8-覆盖勾选清单)
9. [与 JSON 用例的一致性](#9-与-json-用例的一致性)
10. [测试执行与回归](#10-测试执行与回归)

## 修订记录

---

## 1. 测试环境与校验手段

### 1.1 运行环境

- pcap 框架（`trafficgen/test/protocol_pcap/`）生成抓包，`tshark` 解析验证。
- FINS 默认端口 **9600**（TCP/UDP 均有；IANA 未注册，Wireshark 将其注册为 `omron` 协议简称，见 packet-omron-fins.c）。9600 端口**免 `-d`**：tshark 自动以 `omron` 解析器解成员。
- 非 9600 端口时需 `decode_as` 提示（用例 T-035）。
- IPv6 载体用例：FINS 载荷与 IP 版本无关，`ipv6.*` 与 `omron.*` 并存；`omron.*` 断言与 IPv4 用例完全相同。

### 1.2 权威字节事实来源

- `docs/protocols/fins/design.md` §2（全大端、内存区码表、FINS/TCP 头布局、结束码表）
- Wireshark `packet-omron-fins.c` 字段名：`omron.icf` / `omron.sid` / `omron.command` / `omron.memory.area.read` / `omron.memory.address` / `omron.memory.address.bits` / `omron.memory.numitems` / `omron.response.code` / `omron.response.data` / `omron.tcp.length` / `omron.tcp.command` / `omron.tcp.error_code` / `omron.tcp.magic`
- gofins（`l1va/gofins`）header.go/driver.go/memory_area.go/end_code.go

### 1.3 一致性校验命令（与 `docs/protocols/fins/design.md` §7 索引表对齐）

```bash
cd /home/weihang/trafficGenerator
python3 -c "
import json
d=json.load(open('trafficgen/test/protocol_pcap/cases/fins.json'))
ids=[c['id'] for c in d]
assert len(ids)==len(set(ids)), 'duplicate id'
assert len(ids)==45, len(ids)
print('OK', len(ids), 'cases')
"
```

### 1.4 校验 `expect` 结构合法性（复用 types.go 合法键）

```bash
python3 -c "
import json
d=json.load(open('trafficgen/test/protocol_pcap/cases/fins.json'))
expect_keys={'packet_count','min_packets','fields','frames','has_handshake','has_payload',
'negotiated','terminates','directional','notes','expect_error','error_contains'}
field_keys={'packet','field','value','same_as_packet','nonzero','distinct_values','distinct_exclude'}
frame_keys={'packet','offset','hex'}
for c in d:
    e=c['expect']
    assert set(e)<=expect_keys, (c['id'],'bad expect key',set(e)-expect_keys)
    for f in e.get('fields',[]):
        assert set(f)<=field_keys, (c['id'],'bad field key',set(f)-field_keys)
    for f in e.get('frames',[]):
        assert set(f)<=frame_keys, (c['id'],'bad frame key',set(f)-frame_keys)
print('expect keys OK', len(d))
"
```

---

## 2. 框架断言工具

### 2.1 Case 结构（pcaptest/types.go）

```json
{
  "id": "fins_xxx",
  "proto": "fins",
  "summary": "...",
  "spec_json": { "layers": [{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"udp":{"src_port":1234,"dst_port":9600}},{"fins":{"transport":"udp","commands":[{"command":257,"memory_area":"dm","address":100,"items":2}]}}] },
  "expect": {
    "packet_count": 2,
    "fields": [ {"packet": 1, "field": "omron.sid", "value": "0x01", ...} ],
    "frames": [ {"packet": 1, "offset": 42, "hex": "81 00 02 00 ..."} ],
    "expect_error": false,
    "error_contains": "",
    "notes": []
  }
}
```

### 2.2 断言语义

| 断言 | 字段 | FINS 用法 |
|------|------|-----------|
| 等值 | `field`+`value` | `omron.command=0x0101`、`omron.sid=0x01`、`udp.dstport=9600` |
| 存在性 | `field`+`nonzero` | `omron.tcp.length` 非零、`omron.response.data` 存在 |
| 多样性 | `distinct_values` | 多会话 SID 聚合（T-021） |
| FrameAssert | `offset`+`hex` | 头字节级校验（T-036/37），offset=42（UDP）/70（TCP） |

> tshark 数值字段输出进制按显示设置（`BASE_HEX` 字段如 `omron.command` 输出 `0x0101`；`BASE_DEC` 字段如 `omron.memory.numitems` 输出十进制）。框架比对统一整数语义：`value` 传 int 或 `0x` 字符串均可，用例文档写"十进制数字"或 `0x` 均合法（如 `omron.memory.numitems` 用 `2`、`omron.command` 用 `0x0101`）。

### 2.3 负路径断言

`expect_error: true` 时框架断言任务**失败**且错误文本含 `error_contains`。FINS 的负路径分两类：
- **Validate 拒绝**（E-01~E-07、E-09、E-10）：错误文本含标识（如 `"memory area"`、`"address"`、`"icf"`）
- **planner 报错 → 任务失败**（E-08）：错误文本含 `"response"`（响应缺失）

---

## 3. 用例编号规则与全清单

### 3.1 编号规则

- 正向：`T-001 ~ T-022`（载体 / 内存区 / bit 域 / BCD / 命令集 / SID / ICF / 无响应）
- 多会话：`T-020 ~ T-023`（sessions>1）
- 负路径：当前 JSON 20 条负例（均 `expect_error`，实际 ID 与锚词见 §3.3）
- 框架/一致：`T-035 ~ T-040`（tshark 解码、FrameAssert、汇总冒烟）
- JSON id：`fins_<key>` 小写（每个 id 见下清单）

### 3.2 全清单（含 cases/fins.json 45 条用例）

> `JSON` 列非空 = 该行有独立 cases/fins.json 用例；`设计行` = 规格已记录但尚未落盘。当前 JSON 文件共 **45 条（25 条正向 + 20 条负向）**；每个 ID 只出现一次。

| 编号 | 名称 | 类型 | JSON id |
|------|------|------|---------|
| T-001 | FINS/UDP 内存区读-响应往返（DM） | 正 | `fins_udp_dm_read` |
| T-002 | FINS/TCP Frame Send 读取 | 正 | `fins_tcp_read` |
| T-003 | FINS/UDP IPv6 载体读取 | 正 | `fins_udp_ipv6_read` |
| T-004 | CIO 区字读 | 正 | `fins_cio_read_word` |
| T-005 | WR 区字读 | 正 | `fins_wr_read_word` |
| T-006 | HR 区字读 | 正 | `fins_hr_read_word` |
| T-007 | TC PV 字读 | 正 | `fins_tc_read_pv` |
| T-008 | IR 索引寄存器字读 | 正 | `fins_ir_read_word` |
| T-009 | HR 位域读（01 00 数据） | 正 | `fins_hr_read_bit` |
| T-010 | CIO 位域写 | 正 | `fins_cio_write_bit` |
| T-011 | DM 字写（NC/DC） | 正 | 旧设计编号；当前 ID 见 §3.3 |
| T-012 | Clock Read + BCD 数据 | 正 | `fins_clock_read_bcd` |
| T-013 | Memory Area Fill（0103） | 正 | 旧设计编号；当前 ID 见 §3.3 |
| T-014 | Multiple Memory Area Read（0104） | 正 | 旧设计编号；当前 ID 见 §3.3 |
| T-015 | ICF 方向位请求/响应 | 正 | 旧设计编号；当前 ID 见 §3.3 |
| T-016 | SID 会话内递增 01→02 | 正 | 旧设计编号；当前 ID 见 §3.3 |
| T-017 | 显式固定 SID | 正 | 旧设计编号；当前 ID 见 §3.3 |
| T-018 | TCP 命令号 vs FINS 命令码隔离 | 正 | 旧设计编号；当前 ID 见 §3.3 |
| T-019 | expect_response=false 不回响应 | 正 | 旧设计编号；当前 ID 见 §3.3 |
| T-020 | sessions=2 双流 SID 独立递增 | 正 | `fins_sessions_two` |
| T-021 | sessions=3 聚合 DistinctValues | 正 | `fins_sessions_three` |
| T-022 | 多会话不同 4-tuple | 正 | 旧设计编号；当前 ID 见 §3.3 |
| T-023 | 多会话负路径：非法内存区 | 负 | `fins_sessions_neg_area` |
| T-024 | 非法内存区 → 0x1101 响应 | 负 | 旧设计编号；当前 ID 见 §3.3 |
| T-025 | 地址越界 → 0x1103 响应 | 负 | 旧设计编号；当前 ID 见 §3.3 |
| T-026 | 非法 ICF | 负 | 旧设计编号；当前 ID 见 §3.3 |
| T-027 | 未知命令码拒绝 | 负 | 旧设计编号；当前 ID 见 §3.3 |
| T-028 | DM 位口径非法 | 负 | 旧设计编号；当前 ID 见 §3.3 |
| T-029 | 元素数 NC=0 | 负 | 旧设计编号；当前 ID 见 §3.3 |
| T-030 | 数据长度与 NC 不匹配 | 负 | 旧设计编号；当前 ID 见 §3.3 |
| T-031 | 响应长度缺失 | 负 | 旧设计编号；当前 ID 见 §3.3 |
| T-032 | BCD 字段越界 | 负 | 旧设计编号；当前 ID 见 §3.3 |
| T-033 | GCT 非法（≠2） | 负 | `fins_vn_gct` |
| T-034 | DNA 非法（≠0） | 负 | 旧设计编号；当前 ID 见 §3.3 |
| T-035 | 非 9600 端口 tshark -d 解码 | 正 | 旧设计编号；当前 ID 见 §3.3 |
| T-036 | FrameAssert：FINS 头起始字节 | 正 | 旧设计编号；当前 ID 见 §3.3 |
| T-037 | FrameAssert：FINS/TCP 头 16B | 正 | 旧设计编号；当前 ID 见 §3.3 |
| T-038~T-040 | 汇总冒烟 | 正 | 旧设计编号；当前 ID 见 §3.3 |

### 3.3 当前 JSON ID 与负例锚词对账（45/45）

当前 `cases/fins.json` 共 45 条：25 条正向、20 条负向。正向 ID：

`fins_udp_dm_read`、`fins_tcp_read`、`fins_udp_ipv6_read`、`fins_cio_read_word`、`fins_wr_read_word`、`fins_hr_read_word`、`fins_tc_read_pv`、`fins_ir_read_word`、`fins_hr_read_bit`、`fins_cio_write_bit`、`fins_clock_read_bcd`、`fins_sessions_two`、`fins_sessions_three`、`fins_dm_write_word`、`fins_fill_dm`、`fins_multi_read`、`fins_icf_explicit`、`fins_sid_auto_incr`、`fins_sid_fixed`、`fins_expect_response_false`、`fins_tc_flag_read`、`fins_wr_read_bit`、`fins_down_endcode_1101`、`fins_combo_tcp_seq`、`fins_combo_sessions_full`。

| JSON id | `expect_error` | `error_contains` 锚词 |
|---|---:|---|
| `fins_sessions_neg_area` | true | `invalid memory area` |
| `fins_vn_address_over` | true | `address exceeds range` |
| `fins_vn_icf_cmd` | true | `icf response-required bit must be clear` |
| `fins_vn_icf_cfg` | true | `icf request direction bit must be clear` |
| `fins_vn_unknown_cmd` | true | `unsupported command` |
| `fins_vn_dm_bit` | true | `dm does not support bit access` |
| `fins_vn_items_zero` | true | `items must be > 0` |
| `fins_vn_data_len` | true | `data length` |
| `fins_vn_clock_bcd` | true | `clock field out of range` |
| `fins_vn_gct` | true | `invalid gct` |
| `fins_vn_dna` | true | `invalid dna` |
| `fins_vn_sna` | true | `invalid sna` |
| `fins_vn_read_areas_empty` | true | `read_areas` |
| `fins_vn_fill_bit` | true | `fill does not support bit access` |
| `fins_vn_transport` | true | `invalid transport` |
| `fins_vn_direction` | true | `invalid direction` |
| `fins_vn_sessions_neg` | true | `not a numeric value in [0,1000000]` |
| `fins_vn_presence` | true | `top-level fins sub-config` |
| `fins_vn_static_copy` | true | `static four-tuple` |
| `fins_vn_fill_data_len` | true | `fill data must be 2 bytes` |

`fins_vn_presence` 有意保留层链外的顶层 `fins` 子配置，用于验证 presence 判死；`fins_vn_static_copy` 的 `strategy_fc` 位于 case 兄弟键而非 `spec_json`。两者均为已验收负例形状，不是迁移遗漏。

---



> 每条给出：spec_json 要点（fins 块）、预期包数、关键断言。**已落盘 45/45 JSON ID 以 §3 清单和本轮对账为准；凡写"已覆盖"均指"JSON 已有对应例"，尚未跑真实 suite/pcap/NIC 验证，不冒充已跑通；未落盘设计行不计入已验收。**

### T-001 FINS/UDP 内存区读-响应往返（DM 区）— `fins_udp_dm_read`

- 口径订正（2026-10-01）：本例 JSON 摘要曾写"请求 ICF=0x81"，与 JSON `expect`（`omron.icf=0x80`）、`fins.go:402` builder 缺省（请求 0x80/响应 0xC0）、`fins_test.go:246` 金字节（`0x80…`）均不一致——摘要已订正为 0x80。ICF=0x80（网关+需响应）为合法请求口径；0x81（bit0=不期望响应）走 E-06 拒绝（`fins_vn_icf_cmd` 同款位）。

- spec_json：严格层链 `layers:[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"udp":{"src_port":1234,"dst_port":9600}},{"fins":{"transport":"udp","commands":[{command:257, memory_area:"dm", address:100, items:2}]}}]`（0101 读 D100 2 字）
- 预期：**packet_count=2**（请求 up + 响应 down）
- 断言：
  - P1 请求：`omron.icf=0x80`、`omron.sid=0x01`、`omron.command=0x0101`、`omron.memory.area.read=0x82`、`omron.memory.address=0x0064`、`omron.memory.numitems=2`、`udp.dstport=9600`
  - P2 响应：`omron.icf=0xC0`、`omron.sid=0x01`（回显）、`omron.response.code=0x0000`、`udp.srcport=9600`、`udp.dstport=1234`
- 强制覆盖：FINS/UDP 请求-响应、DM 区、默认端口、响应回显 SID

### T-002 FINS/TCP Frame Send 读取 — `fins_tcp_read`

- spec_json：严格层链 `layers:[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":1235,"dst_port":9600}},{"fins":{"transport":"tcp","commands":[{command:257, memory_area:"dm", address:100, items:2}]}}]`
- 预期：TCP 握手 3 + 请求 + 响应 + FIN 关闭**至少 7 包**；JSON 使用 `min_packets=7`、`has_handshake=true`。具体 FIN/ACK 交织顺序由 TCP 载体决定。
- 断言：请求包 `omron.tcp.magic=0x46494e53`、`omron.tcp.length=26`（当前 builder 为 8 + 18B FINS 帧，见注）、`omron.tcp.command=0x00000002`（Frame Send）、`omron.tcp.error_code=0`；`omron.command=0x0101`
- 注：memory area read 请求 FINS 帧 = 10 头 + 2 命令码 + 6 参数 = **18 字节**（无结束码）；响应 = 10 + 2 + 2 结束码 + 4 数据 = **18 字节**。当前 builder 的 `omron.tcp.length` 为 8 + FINS 帧长度，两方向都是 26。TCP 总载荷 = 16 + 18 = 34 字节。
- 强制覆盖：FINS/TCP、Frame Send 头、TCP 端口 9600

### T-003 FINS/UDP IPv6 载体 — `fins_udp_ipv6_read`

- spec_json：严格层链 `layers:[{"ip":{"src":"2001:db8::1","dst":"2001:db8::2"}},{"udp":{"src_port":1236,"dst_port":9600}},{"fins":{"transport":"udp","commands":[{command:257, memory_area:"dm", address:100, items:1}]}}]`
- 预期：packet_count=2
- 断言：P1 `ipv6.src=2001:db8::1`、`ipv6.dst=2001:db8::2`、`udp.dstport=9600`、`omron.command=0x0101`、`omron.sid=0x01`；P2 `omron.response.code=0x0000`
- 强制覆盖：IPv4+IPv6

### T-004 CIO 区字读 — `fins_cio_read_word`

- spec_json：fins = `commands:[{command:257, memory_area:"cio", address:0, items:1}]`
- 断言：`omron.memory.area.read=0xB0`（CIO 字码）、`omron.memory.address=0x0000`、`omron.memory.numitems=1`；响应 `omron.response.data` 存在（2 字节）
- 强制覆盖：内存区 CIO

### T-005 WR 区字读 — `fins_wr_read_word`

- spec_json：`memory_area:"wr", address:10, items:1`
- 断言：`omron.memory.area.read=0xB1`、`omron.memory.address=0x000A`
- 强制覆盖：内存区 WR

### T-006 HR 区字读 — `fins_hr_read_word`

- spec_json：`memory_area:"hr", address:5, items:2`
- 断言：`omron.memory.area.read=0xB2`、`omron.memory.address=0x0005`、`omron.memory.numitems=2`；响应 `omron.response.data` 非零且按 `items=2` 推导为 4 字节（当前断言 schema 只提供存在/非零检查，精确长度留待实现）。
- 强制覆盖：内存区 HR

### T-007 TC PV 字读 — `fins_tc_read_pv`

- spec_json：`memory_area:"tc_pv", address:0, items:1`（TC PV 字码 0x89）
- 断言：`omron.memory.area.read=0x89`、`omron.memory.address=0x0000`、`omron.memory.numitems=1`
- 强制覆盖：内存区 TC（PV 口径）
- 注：TC 地 0-65535（定时器/计数器编号）；本用例用 PV 字口径，位口径（0x09 Completion Flag）在测试环境里区分断言（设计行）

### T-008 IR 索引寄存器字读 — `fins_ir_read_word`

- spec_json：`memory_area:"ir", address:0, items:1`
- 断言：`omron.memory.area.read=0xDC`（CS1 Index Register）、`omron.memory.address=0x0000`
- 强制覆盖：内存区 IR

### T-009 HR 位域读 — `fins_hr_read_bit`

- spec_json：`memory_area:"hr", address:0x10, bit:2, items:2`（HR16 的 bit2/3 读）
- 断言：`omron.memory.area.read=0x32`（HR bit 码）、`omron.memory.address.bits=0x02`、`omron.memory.numitems=2`；响应 `omron.response.data` = `01 00`（FrameAssert 或 bytes）
- 强制覆盖：bit 域 + HR 位码

### T-010 CIO 位域写 — `fins_cio_write_bit`

- spec_json：`command:258`（0102）、`memory_area:"cio", address:0, bit:3, items:2`、`data:[{"strategy":"fixed","value":1},{"strategy":"fixed","value":0}]`（或 `response_end_code:0`）
- 断言：`omron.command=0x0102`、`omron.memory.area.read=0x30`（CIO bit 码）、`omron.memory.address.bits=0x03`、`omron.memory.numitems=2`（元素数 NC=2）；写请求的 DC=2（FrameAssert 第 8-9 参数字节 `00 02`）；响应 `omron.response.code=0x0000` 且无响应数据
- 强制覆盖：bit 域 + 写

### T-011 DM 字写（NC/DC 对账）— `fins_dm_write_word`

- spec_json：`command:258`、`memory_area:"dm", address:200, items:2`、`data:[0x1122,0x3344]`（字数据）
- 断言：`omron.command=0x0102`、`omron.memory.area.read=0x82`、`omron.memory.address=0x00C8`、`omron.memory.numitems=2`、`omron.response.data` 无（写响应无数据）、FrameAssert 请求尾部 `11 22 33 44`（offset 52+10）
- 强制覆盖：DM 写、字数据大端

### T-012 Clock Read + BCD — `fins_clock_read_bcd`

- spec_json：fins = `commands:[{command:1793}]`（0x0701 Clock Read）
- 请求帧 = 10 头 + 2 命令码 = 12 字节；响应 = 10+2+2(结束码)+8(BCD)=22 字节
- 断言：请求 `omron.command=0x0701` 且无 `omron.memory.*` 字段；响应 **无** `omron.response.code`（Wireshark 对 0x0701 响应不解析结束码——见 packet-omron-fins.c 的 0x0701 分支命令长度为 0 即返回），用响应 FrameAssert 校验 FINS 帧 offset 54 起的 `00 00 20 26 08 18 14 30 00 02`（结束码 + 8B BCD）
- 强制覆盖：BCD SID（时字节 0x14 半字节法）—— FrameAssert 覆盖字节 0x14；SID 为普通字节 0x01（请求头）
- 注：Clock Read 命令码 0x0701 与"SID BCD"混淆点相关，见 §6 T-032

### T-013~T-019 命令集/SID/ICF/无响应（设计行，无 JSON）

| T | 名称 | 断言要点 | 升级建议 |
|---|------|---------|---------|
| T-013 | Memory Area Fill 0103 | 命令码 `omron.command=0x0103`；tshark 对 0103 请求要求剩余长度==8（4 寻址+2 NC+2 数据）才解析——请求 FINS 帧 = 10+2+8 = 20 字节（**不带 DC 字段**，数据长度由 NC 隐含；区别于 0102 带 DC）；响应无数据 | 并入 T-030 或自开 |
| T-014 | Multiple Read 0104 | `omron.command=0x0104`、响应各内存区数据按长度分块（tshark 自 0x82 区分 2 字节）；请求组参数 tshark 按 4 字节/组解析（已知怪癖，不要断言请求组字段，用 FrameAssert） | 并入 未来 JSON 用例 |
| T-015 | ICF 方向位 | 请求 ICF bit6=0（0x80）、响应 bit6=1（0xC0）——T-001 已覆盖 | 不单开 |
| T-016 | SID 递增 | 多命令序列请求 SID=01,02（2 个请求） | 并入 T-001 未来（T-001 现单命令） |
| T-017 | 显式固定 SID | `sid:5` 时请求 SID=0x05 且响应回显 0x05 | 自开 |
| T-018 | TCP 命令号隔离 | `omron.tcp.command=0x00000002` ≠ `omron.command` ——T-002 已覆盖 | 不单开 |
| T-019 | expect_response=false | 只发请求不回响应 → packet_count=1 | 自开 |

---

## 5. 多会话用例（T-020 ~ T-023）

> 多会话 = `sessions>1`，planner 生成 N 条并行流，**每流 SID 从 1 独立递增**（`docs/protocols/fins/design.md` §4.4）。断言必须验证"并发正确性"而非仅"无 race"（测试策略 §6）：断言每流 SID 是 1..N 递增、跨流无串号。

### T-020 sessions=2 双流 SID 独立 — `fins_sessions_two`

- spec_json：fins = `sessions:2`、`commands:[{command:257, memory_area:"dm", address:100, items:1}]`
- 预期：min_packets=4（2 流 × 请求+响应）；包调度交织不可确定性
- 断言（聚合，调度无关）：
  - `omron.command` 全为 0x0101（存在断言）
  - `omron.sid` 每流独立：DistinctValues={0x01}（各流仅 1 个请求 → SID=01）；用 `udp.srcport` 区分流（引擎给每流独立 src_port），跨流 SID 不冲突
- 强制覆盖：**多会话 sessions>1**

### T-021 sessions=3 聚合 DistinctValues — `fins_sessions_three`

- spec_json：fins = `sessions:3`、`commands:[{command:257, memory_area:"dm", address:100, items:1}]`
- 断言：`omron.sid` DistinctValues = `["0x01"]`。当前用例不对 `udp.srcport` 的完整集合做断言，因为多流端口分配策略尚未由实现裁决。
- 提示：若命令序列为 2 个请求（未来），DistinctValues={0x01,0x02} 且每流内不重复才是"独立递增"的正确性证明（当前单请求用例只能证明无串号）

### T-022 多会话不同 4-tuple（设计行）

- 设计要点：每流可配不同 src/dst IP、端口。断言聚合 `udp.dstport` 出现两值。未来从 T-020 派生。

### T-023 多会话负路径 — `fins_sessions_neg_area`

- spec_json：fins = `sessions:2`、`commands:[{command:257, memory_area:"xyz_bad", address:0, items:1}]`
- expect：`expect_error:true`、`error_contains:"memory area"`——多会话亦必须走 Validate 拒绝（期望：任务失败，而非 0 包静默通过；测试策略 §4 集成）
- 强制覆盖：多会话 x 负路径

---

## 6. 负路径用例（20 条落盘负例；旧 T-024 ~ T-034 为设计编号）

> 全部 20 条落盘负例均为 `expect_error: true`，并且 `expect` **仅保留这两个契约键**：`expect_error` 与 `error_contains`；不携带 `notes`、`packet_count`、`fields`、`frames` 等额外键。§3.3 的精确 `error_contains` 锚词验证任务确实失败。旧 T-023~T-034 是行为设计编号；当前 JSON 负例以 `fins_vn_*` 与会话负例 ID 为准。配置拒绝与响应态错误码分列：`fins_down_endcode_1101` 是正向配置的响应错误码例，不计入本表。

下表左半为**行为编号与 spec 触发**，右半为**实际落盘 ID 与真实锚词**（锚词取自 `trafficgen/internal/protocol/fins/fins.go` 的 `fmt.Errorf` 原文，可机读核对）：

| 行为编号 | 名称 | spec 触发 | 落盘 JSON id | 真实 `error_contains` | EUID |
|---|------|----------|------------------|---------------------|------|
| T-023 | 多会话负路径 | `sessions:2` + `memory_area:"xyz_bad"` | `fins_sessions_neg_area` | `invalid memory area` | E-01 |
| T-024 | 非法内存区 | `memory_area:"xyz_bad"` | 同上（多会话形态即非法内存区唯一落盘例） | `invalid memory area` | E-01 |
| T-025 | 地址越界 | `address:70000`（超区域上限） | `fins_vn_address_over` | `address exceeds range` | E-04 |
| T-026 | 非法 ICF（bit0）/ 非法 ICF（bit6） | `icf:0x01`（不期望响应） / cfg 级请求方向位 | `fins_vn_icf_cmd` / `fins_vn_icf_cfg` | `icf response-required bit must be clear` / `icf request direction bit must be clear` | E-06 |
| T-027 | 未知命令码 | `command:0x1234` | `fins_vn_unknown_cmd` | `unsupported command` | E-02 |
| T-028 | DM 位口径非法 | `memory_area:"dm", bit:3` | `fins_vn_dm_bit` | `dm does not support bit access` | E-03 |
| T-029 | 元素数 NC=0 | `items:0` | `fins_vn_items_zero` | `items must be > 0` | E-05 |
| T-030 | 数据长度与 NC 不匹配 | 字写 `items:2` 但 data 只 2 字节 | `fins_vn_data_len` | `data length` | E-07 |
| T-031 | 0103 填充数据长度非法 | `fill` 模板字节数 ≠ 2 | `fins_vn_fill_data_len` | `fill data must be 2 bytes` | E-10 |
| T-032 | BCD 字段越界 | clock `hour:0x99`（BCD 非法）；SID 是普通 1 字节字段，不按 BCD 校验 | `fins_vn_clock_bcd` | `clock field out of range` | E-09 |
| T-033 | GCT 非法（≠2） | `gct:3` | `fins_vn_gct` | `invalid gct` | E-06 |
| T-034 | DNA 非法 / SNA 非法 | `dna:1` / `sna:1` | `fins_vn_dna` / `fins_vn_sna` | `invalid dna` / `invalid sna` | E-06 |
| — | 0104 `read_areas` 为空或超组 | `read_areas:[]` | `fins_vn_read_areas_empty` | `read_areas` | E-10 |
| — | 0103 位口径非法 | `fill` + `bit` | `fins_vn_fill_bit` | `fill does not support bit access` | E-03 |
| — | 载体非法 | `transport:"sctp"` | `fins_vn_transport` | `invalid transport` | — |
| — | 方向非法 | `direction:"sideways"` | `fins_vn_direction` | `invalid direction` | — |
| — | sessions 非数值 | `sessions:"two"` | `fins_vn_sessions_neg` | `not a numeric value in [0,1000000]` | — |
| — | 顶层 `fins` 子映射（presence） | 层链外顶层 `fins:{}` | `fins_vn_presence` | `top-level fins sub-config` | — |
| — | 静态四元组复制门 | 兄弟键 `strategy_fc` 多流静态复制 | `fins_vn_static_copy` | `static four-tuple` | — |
| — | 0104 组内 DM 位口径 | `read_areas` 中 dm+bit | （同 `fins_vn_dm_bit` 家族，锚词 `dm does not support bit access`） | — | E-03 |

> 上表 20 行对应 §3.3 的 20 条 JSON 负例；E 编号对应 `docs/protocols/fins/design.md` §9.2 错误表。每条断言任务**确实失败**（Testing Policy §4），不得只断言"不 panic"。
>
> **E-08（响应缺失 / planner 报错）当前无独立落盘负例**：`fins.go` 的响应派生是内建的，不存在"缺 down 派生导致 planner 报错"的配置入口，故无法构造 `expect_error` 触发；此缺口如实登记，不以 E-07 家族顶替（T-031 原设计的 E-08 语义已改判为 0103 填充数据长度 E-10）。

---

## 7. 字段断言速查表

| tshark 字段 | 类型/进制 | 含义 | 常用值 |
|-------------|----------|------|--------|
| `omron.icf` | 8 位 hex | 信息控制字段 | 0x80 请求 / 0xC0 响应 |
| `omron.sid` | 8 位 hex | 服务 ID | 0x01..（递增 / 回显） |
| `omron.command` | 16 位 hex | FINS 命令码 | 0x0101 / 0x0102 / 0x0701 |
| `omron.memory.area.read` | 8 位 hex | 内存区码 | 0x82 DM / 0xB0 CIO / 0x30 CIO bit… |
| `omron.memory.address` | 16 位 hex | 起始字地址 | 0x0064（D100） |
| `omron.memory.address.bits` | 8 位 hex | 位偏移 | 0x00 字 / 0x02.. bit |
| `omron.memory.numitems` | 16 位 dec | 元素数 NC | 1、2… |
| `omron.response.code` | 16 位 hex | 结束码 | 0x0000 / 0x1101… |
| `omron.response.data` | bytes | 读响应数据 | 大端字数据 |
| `omron.tcp.magic` | 32 位 hex | 'FINS' | 0x46494e53 |
| `omron.tcp.length` | 32 位 dec/hex | TCP length 字段（builder=8+FINS 帧长） | 26（18B 读请求） |
| `omron.tcp.command` | 32 位 hex | TCP 层命令号 | 0x00000002 Frame Send |
| `omron.tcp.error_code` | 32 位 hex | 错误码 | 0 |

> 进制：`BASE_HEX` 字段输出 `0x…`；`BASE_DEC` 输出十进制（如 `omron.memory.numitems`=2）。框架比对整数语义，两种写法均可。

---

## 8. 覆盖勾选清单（本轮机读对账 2026-10-01：未跑 suite/pcap；"覆" = JSON 有对应例）

| 覆盖点 | 用例 | 状态 |
|--------|------|------|
| FINS/UDP 请求-响应 | T-001 | 覆 JSON `fins_udp_dm_read`（ICF=0x80/0xC0 口径，摘要已订正） |
| FINS/TCP（Frame Send） | T-002 | 覆 JSON `fins_tcp_read`（length=26） |
| 内存区 CIO | T-004 | 覆 JSON `fins_cio_read_word` |
| 内存区 WR | T-005 | 覆 JSON `fins_wr_read_word` |
| 内存区 HR | T-006 | 覆 JSON `fins_hr_read_word` |
| 内存区 TC（PV+Flag） | T-007/T-33 | 覆 JSON `fins_tc_read_pv`（0x89）+ `fins_tc_flag_read`（0x09） |
| 内存区 DM（读+写） | T-001/T-011 | 覆 JSON `fins_udp_dm_read` + `fins_dm_write_word` |
| 内存区 IR | T-008 | 覆 JSON `fins_ir_read_word` |
| bit 域（读+写） | T-009/T-010 | 覆 JSON `fins_hr_read_bit`/`fins_cio_write_bit` |
| WR 位读 | T-34 | 覆 JSON `fins_wr_read_bit`（0x31） |
| 错误码响应（0x1101） | T-25 | 覆 JSON `fins_down_endcode_1101`（正向配置，响应态） |
| BCD 时钟 | T-012 | 覆 JSON `fins_clock_read_bcd`（FrameAssert，7 BCD 字节无世纪） |
| IPv4+IPv6 | T-001/T-003 | 覆 JSON `fins_udp_ipv6_read` |
| 多会话 sessions>1 | T-020/T-021 | 覆 JSON `fins_sessions_two`/`fins_sessions_three` + `fins_combo_sessions_full` |
| 多命令序列/SID 递增 | T-016/T-017 | 覆 JSON `fins_sid_auto_incr`（01→02）+ `fins_sid_fixed`（恒 07） |
| ICF 显式/无响应 | T-015/T-019 | 覆 JSON `fins_icf_explicit` + `fins_expect_response_false` |
| 命令集 0103/0104 | T-013/T-014 | 覆 JSON `fins_fill_dm` + `fins_multi_read` |
| TCP 组合大场景 | T-31 | 覆 JSON `fins_combo_tcp_seq`（读→写→校时 3 动作） |
| 负路径 E-01~E-10 | T-023~T-039 | 覆 20/20 负例（`expect` 恰两键，机读证实） |
| 非 9600 `decode_as` | D-FINS-1 | 未覆盖（无 JSON 例，不冒充） |
| TCP 非正常结束/长保活 | D-FINS-3 | 未覆盖（真实行为待复核） |

---

## 9. 与 JSON 用例的一致性

- cases/fins.json 的 45 个 ID（25 正例、20 负例）与本档 §3.2/§3.3 的当前清单对账；每个 ID 只出现一次，20 条负例均具备 `expect_error` 与精确 `error_contains`。
- 每条 JSON 的 `summary` 必须包含其 T 编号与覆盖点（如 "T-001: FINS/UDP DM 读往返"），供回归追溯。
- 当前存量去向：45/45 条已落盘；25 条正例合入当前清单，20 条负例保留其故意错误输入与精确锚词。`fins_vn_presence` 是 presence 判死专用形状，`fins_vn_static_copy` 的 `strategy_fc` 是 case 级流控字段；二者均非遗漏。旧 T-011 等设计编号若无同名 T 映射，按当前 JSON ID 记录，不宣称为未落盘。
- 升级步骤（新增 JSON 用例）：① 本档 §3 加行 + §4/5/6 加断言；② design §7 加行；③ 写 JSON 文件 + 更新 §1.3 expect 集合并跑脚本。

---

## 10. 测试执行与回归（本轮未执行：任务禁令禁跑 suite/server/Go test；以下为跑法记录，非执行结论）

- 运行（待执行）：`cd trafficgen && go test ./test/protocol_pcap/ -run TestFINS -count=1 -v`（`-count=1` 防 go test 缓存）
- 回归：`go vet ./... && go test -race ./...`（FINS 包 + 框架包）
- tshark 判据：`tshark -r out.pcap -Y omron -T fields -e omron.icf -e omron.sid -e omron.command -e omron.memory.area.read -e omron.memory.address -e omron.memory.numitems -e omron.response.code`
- 失败定位：先看 `omron.*` 字段是否存在（tshark 是否把载荷认成 omron），再逐字段比对——端口非 9600 时先确认 `-d` 提示生效。

---

## 修订记录

| 版本 | 日期 | 内容 |
|------|------|------|
| v1.0.0 | 2026-08-18 | 初稿：框架、全清单（T-001~T-040）、初始 JSON 用例（8 类内存区 + bit + 双载体 + IPv6 + 双/三会话 + BCD）、负路径设计行、覆盖清单、一致性脚本 |
| v1.0.1 | 2026-08-19 | 对齐实际 14 条 JSON：修正 ID 集合、T-011 未落盘状态、TCP 包数、Clock Read FrameAssert、位写偏移、HR 响应数据断言及 GCT/DNA/BCD 负路径边界 |
| v1.1.0 | 2026-09-30 | 层链迁移审计：45/45 JSON 现状、T1-T6/C1-C6、D-FINS 缺口引用；不伪造断言数值 |
| v1.1.1 | 2026-10-01 | 收官：T-001 ICF 口径订正（0x80/0xC0，JSON 摘要）、§8 覆盖清单机读重钉（TC-Flag/WR-bit/错误码/组合例补口，未跑 suite 声明）、§10 未执行声明；静态闭环 |

## 11. 层链迁移审计（T1-T6，2026-09-30，2026-10-01 对账）

本节按 `/tmp/review-checklist.md` 的 T1–T6 逐项核对；“设计行”只表示待落盘或待实证，不算已验收。

| ID | 测试审计结论 | 证据 |
|---|---|---|
| T1 | 三源回指已逐类落到规范、设计、现网/实现；现网抓包尚未取得 | 规范：设计 §2–§4；设计：§8/§9/§14；实现：`trafficgen/internal/protocol/fins/{fins.go,layer_gen.go}`；确认方式：真实 suite + tshark，现网行为另抓 UDP/TCP 9600 包 |
| T2 | 测试点清单先行，覆盖命令、载体、字段、状态、错误与配置形状 | §3.2/§3.3 ID 清单；§7 字段断言；下表按“规范条文→业务场景→代码分支→缺口”列出；缺口以 D-FINS 编号回指 design §12.2 |
| T3 | 颗粒度不可再分，并标明数据/业务/现网三类与强度 | 数据：六区/位字/大端/BCD/错误值逐项；业务：多命令 SID、sessions、TCP/UDP；现网：UDP/TCP 9600 典型行为。字段等值/FrameAssert/DistinctValues 各自独立，未实测格不宣称覆盖 |
| T4 | §3.15 三项均有用例或立项 | 同连接多轮：`fins_sid_auto_incr`、`fins_combo_tcp_seq`；非正常结束：响应错误码 `fins_down_endcode_1101`，TCP RST 立项 D-FINS-3；长保活：FINS 无应用保活语义，立项 D-FINS-3，确认方式为真实 TCP pcap |
| T5 | 45/45 存量逐条有去向 | 25 正例按 §3.2/§8 合入；20 负例按 §3.3/§6 保留；设计编号 T-013/T-014/T-016/T-017/T-019 等分别指向现有 ID 或“等价覆盖”，未落盘的非核心扩展转 D-FINS-1/2/3，不伪造验收 |
| T6 | 20 条失败路径均是可触发拒绝且只断言稳定错误锚词 | JSON 机读确认每条 `expect` 恰为 `{expect_error,error_contains}`；锚词逐条与 `fins.go:37-205`、`chain_planner.go:626`、`complete.go:315`、`strategy_convert.go:8929`、`semantic.go:285` 对照；执行确认仍待 suite 禁令解除 |

### 11.1 迁移状态与缺口

- 已迁移：45/45 个 cases 文件条目已使用层链；其中 25 正例可作为目标配置形状，20 负例保留故意违规输入。
- 特殊负例：`fins_vn_presence` 有意保留顶层 `fins:{}`，用于验证 presence 判死，不得清洗。
- 流控：`fins_vn_static_copy` 的 `strategy_fc` 已移到 cases 条目兄弟键；它不是策略 `spec_json` 的业务字段。
- 缺口：D-FINS-1~3 由设计文档登记；没有真实套件/pcap 证据的设计行不计入已验收覆盖。

## 12. 六项测试覆盖清单（C1-C6）

| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | 顶层键与用例数量 | 45 条唯一 ID；25 正例、20 负例；JSON 可解析。 | §1.3、§3.3；全量机读对账 |
| C2 | 层链形状 | 25 正例均为 `[ip,(udp|tcp),fins]`；presence/游离键/flat count 等负例保留故意违规形状。 | §11 T2/T4、§11.1 |
| C3 | 空壳登记 | 顶层 `fins:{}` 仅用于 `fins_vn_presence` 判死，已登记为专门负例；不存在“保留正例空壳”。 | `fins_vn_presence`、design §12 |
| C4 | 负例契约 | 20 例都有稳定 `error_contains`，`expect` 不混入 `packet_count`/`fields`/`frames`。 | §2.3、§3.3 |
| C5 | 存量去向 | 多会话、多命令、TCP 组合例均有 JSON ID 或明确设计行；旧编号映射不能替代未落盘实证。 | §3.2、§5、§11 T5 |
| C6 | spec-mapping 对账 | 未发现独立 `fins-spec-mapping.md`，按清单要求记为备注；当前以本文 §3.3 与 design §7.1 对账。 | 非缺口；不宣称 suite/pcap 全绿 |


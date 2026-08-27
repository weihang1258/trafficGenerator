# FINS（欧姆龙 PLC）测试用例设计文档

> 版本：v1.0.1
> 设计日期：2026-08-18
> 修订日期：2026-08-19（同步三件套中的已确认差异）
> 范围：FINS（欧姆龙 PLC 通信协议）在 UDP/TCP 9600 上的 pcap 框架测试用例定义。覆盖 FINS/UDP 请求-响应、FINS/TCP（Frame Send）、六类内存区（CIO/WR/HR/TC/DM/IR）、位域读写、错误码响应、BCD SID、IPv4+IPv6、多会话（sessions>1）与全部负路径（expect_error）
> 父文档：`docs/protocol-designs/19-fins-design.md`（协议设计：10 字节命令头、命令码、内存区码、结束码、HexDump S1-S10）
> 配套文件：`trafficgen/test/protocol_pcap/cases/fins.json`（用例数据，与此文档**严格一致**）
> 框架共底：`trafficgen/internal/pcaptest/types.go`（Case/Expect/FieldAssert/FrameAssert 结构）+ `trafficgen/test/protocol_pcap/` 驱动

---

## 目录

1. [测试环境与校验手段](#1-测试环境与校验手段)
2. [框架断言工具](#2-框架断言工具)
3. [用例编号规则与全清单](#3-用例编号规则与全清单)
4. [正向用例（T-001 ~ T-022）](#4-正向用例t-001--t-022)
5. [多会话用例（T-020 ~ T-023）](#5-多会话用例t-020--t-023)
6. [负路径用例（T-024 ~ T-034）](#6-负路径用例t-024--t-034)
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

- 19-fins-design.md §2（全大端、内存区码表、FINS/TCP 头布局、结束码表）
- Wireshark `packet-omron-fins.c` 字段名：`omron.icf` / `omron.sid` / `omron.command` / `omron.memory.area.read` / `omron.memory.address` / `omron.memory.address.bits` / `omron.memory.numitems` / `omron.response.code` / `omron.response.data` / `omron.tcp.length` / `omron.tcp.command` / `omron.tcp.error_code` / `omron.tcp.magic`
- gofins（`l1va/gofins`）header.go/driver.go/memory_area.go/end_code.go

### 1.3 一致性校验命令（与 19-fins-design.md §7 索引表对齐）

```bash
cd /home/weihang/trafficGenerator
python3 -c "
import json
d=json.load(open('trafficgen/test/protocol_pcap/cases/fins.json'))
ids=[c['id'] for c in d]
assert len(ids)==len(set(ids)), 'duplicate id'
expect={'fins_udp_dm_read','fins_tcp_read','fins_udp_ipv6_read','fins_cio_read_word',
'fins_wr_read_word','fins_hr_read_word','fins_tc_read_pv','fins_ir_read_word',
'fins_hr_read_bit','fins_cio_write_bit','fins_clock_read_bcd','fins_sessions_two',
'fins_sessions_three','fins_sessions_neg_area'}
got=set(ids)
assert got==expect, ('id mismatch', sorted(got-expect), sorted(expect-got))
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
  "spec_json": { "layers": [{"udp":{}},{"fins":{}}], "src_ip": "...", "dst_ip": "...", "fins": {...} },
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
- 负路径：`T-024 ~ T-034`（expect_error）
- 框架/一致：`T-035 ~ T-040`（tshark 解码、FrameAssert、汇总冒烟）
- JSON id：`fins_<key>` 小写（每个 id 见下清单）

### 3.2 全清单（含 cases/fins.json 14 条用例）

> `JSON` 列非空 = 该行有独立 cases/fins.json 用例；`设计行` = 规格已记录但尚未落盘。当前 JSON 文件共 **14 条（13 条正向 + 1 条负向）**；每个 ID 只出现一次。

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
| T-011 | DM 字写（NC/DC） | 正 | 设计行（JSON 未落盘） |
| T-012 | Clock Read + BCD 数据 | 正 | `fins_clock_read_bcd` |
| T-013 | Memory Area Fill（0103） | 正 | 设计行（JSON 未落盘） |
| T-014 | Multiple Memory Area Read（0104） | 正 | 设计行（JSON 未落盘） |
| T-015 | ICF 方向位请求/响应 | 正 | 设计行（JSON 未落盘） |
| T-016 | SID 会话内递增 01→02 | 正 | 设计行（JSON 未落盘） |
| T-017 | 显式固定 SID | 正 | 设计行（JSON 未落盘） |
| T-018 | TCP 命令号 vs FINS 命令码隔离 | 正 | 设计行（JSON 未落盘） |
| T-019 | expect_response=false 不回响应 | 正 | 设计行（JSON 未落盘） |
| T-020 | sessions=2 双流 SID 独立递增 | 正 | `fins_sessions_two` |
| T-021 | sessions=3 聚合 DistinctValues | 正 | `fins_sessions_three` |
| T-022 | 多会话不同 4-tuple | 正 | 设计行（JSON 未落盘） |
| T-023 | 多会话负路径：非法内存区 | 负 | `fins_sessions_neg_area` |
| T-024 | 非法内存区 → 0x1101 响应 | 负 | 设计行（JSON 未落盘） |
| T-025 | 地址越界 → 0x1103 响应 | 负 | 设计行（JSON 未落盘） |
| T-026 | 非法 ICF | 负 | 设计行（JSON 未落盘） |
| T-027 | 未知命令码拒绝 | 负 | 设计行（JSON 未落盘） |
| T-028 | DM 位口径非法 | 负 | 设计行（JSON 未落盘） |
| T-029 | 元素数 NC=0 | 负 | 设计行（JSON 未落盘） |
| T-030 | 数据长度与 NC 不匹配 | 负 | 设计行（JSON 未落盘） |
| T-031 | 响应长度缺失 | 负 | 设计行（JSON 未落盘） |
| T-032 | BCD 字段越界 | 负 | 设计行（JSON 未落盘） |
| T-033 | GCT 非法（≠2） | 负 | 设计行（错误编号待实现） |
| T-034 | DNA 非法（≠0） | 负 | 设计行（JSON 未落盘） |
| T-035 | 非 9600 端口 tshark -d 解码 | 正 | 设计行（JSON 未落盘） |
| T-036 | FrameAssert：FINS 头起始字节 | 正 | 设计行（JSON 未落盘） |
| T-037 | FrameAssert：FINS/TCP 头 16B | 正 | 设计行（JSON 未落盘） |
| T-038~T-040 | 汇总冒烟 | 正 | 设计行（JSON 未落盘） |

---

## 4. 正向用例（T-001 ~ T-022）

> 每条给出：spec_json 要点（fins 块）、预期包数、关键断言。当前 JSON 文件含 13 条正向和 1 条负向；其余为设计级（无文件）场景。

### T-001 FINS/UDP 内存区读-响应往返（DM 区）— `fins_udp_dm_read`

- spec_json：`layers:[{"udp":{}},{"fins":{}}]`、`src_ip:10.0.0.1`、`dst_ip:20.0.0.1`、`src_port:1234`、`dst_port:9600`；fins = `transport:udp`、`commands:[{command:257, memory_area:"dm", address:100, items:2}]`（0101 读 D100 2 字）
- 预期：**packet_count=2**（请求 up + 响应 down）
- 断言：
  - P1 请求：`omron.icf=0x81`、`omron.sid=0x01`、`omron.command=0x0101`、`omron.memory.area.read=0x82`、`omron.memory.address=0x0064`、`omron.memory.numitems=2`、`udp.dstport=9600`
  - P2 响应：`omron.icf=0xC1`、`omron.sid=0x01`（回显）、`omron.response.code=0x0000`、`udp.srcport=9600`、`udp.dstport=1234`
- 强制覆盖：FINS/UDP 请求-响应、DM 区、默认端口、响应回显 SID

### T-002 FINS/TCP Frame Send 读取 — `fins_tcp_read`

- spec_json：`layers:[{"tcp":{}},{"fins":{}}]`、`dst_port:9600`；fins = `transport:"tcp"`、`commands:[{command:257, memory_area:"dm", address:100, items:2}]`
- 预期：TCP 握手 3 + 请求 + 响应 + FIN 关闭**至少 7 包**；JSON 使用 `min_packets=7`、`has_handshake=true`。具体 FIN/ACK 交织顺序由 TCP 载体决定。
- 断言：请求包 `omron.tcp.magic=0x46494e53`、`omron.tcp.length=18`（= FINS 帧长，见注）、`omron.tcp.command=0x00000002`（Frame Send）、`omron.tcp.error_code=0`；`omron.command=0x0101`
- 注：memory area read 请求 FINS 帧 = 10 头 + 2 命令码 + 6 参数 = **18 字节**（无结束码）；响应 = 10 + 2 + 2 结束码 + 4 数据 = **18 字节**。`omron.tcp.length` 两方向都是 18（`0x00000012`）。TCP 总载荷 = 8 + 18 = 26 字节。
- 强制覆盖：FINS/TCP、Frame Send 头、TCP 端口 9600

### T-003 FINS/UDP IPv6 载体 — `fins_udp_ipv6_read`

- spec_json：`layers:[{"udp":{}},{"fins":{}}]`、`src_ip:2001:db8::1`、`dst_ip:2001:db8::2`、`dst_port:9600`；fins 同 T-001（DM 读）
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
| T-015 | ICF 方向位 | 请求 ICF bit6=0（0x81）、响应 bit6=1（0xC1）——T-001 已覆盖 | 不单开 |
| T-016 | SID 递增 | 多命令序列请求 SID=01,02（2 个请求） | 并入 T-001 未来（T-001 现单命令） |
| T-017 | 显式固定 SID | `sid:5` 时请求 SID=0x05 且响应回显 0x05 | 自开 |
| T-018 | TCP 命令号隔离 | `omron.tcp.command=0x00000002` ≠ `omron.command` ——T-002 已覆盖 | 不单开 |
| T-019 | expect_response=false | 只发请求不回响应 → packet_count=1 | 自开 |

---

## 5. 多会话用例（T-020 ~ T-023）

> 多会话 = `sessions>1`，planner 生成 N 条并行流，**每流 SID 从 1 独立递增**（19-fins-design.md §4.4）。断言必须验证"并发正确性"而非仅"无 race"（测试策略 §6）：断言每流 SID 是 1..N 递增、跨流无串号。

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

## 6. 负路径用例（T-024 ~ T-034）

> 全部 `expect_error: true`。负路径分级：**Validate 拒绝**（配置期即报错）与 **响应态错误码**（配置合法、`response_end_code` 令模拟 PLC 回错误帧）。两类都要可测试。

| T | 名称 | spec 触发 | error_contains | EUID |
|---|------|----------|----------------|------|
| T-023 | 多会话负路径 | 非法内存区 "xyz_bad" | "memory area" | E-01 |
| T-024 | 非法内存区 | `memory_area:"xyz_bad"` | "memory area" | E-01 |
| T-025 | 地址越界 | `address:70000`（超 0xFFFF 区域上限） | "address" | E-04 |
| T-026 | 非法 ICF | `icf:0xC0`（请求含 bit6=响应）或 `icf:0x01`（bit0=不响应） | "icf" | E-06 |
| T-027 | 未知命令码 | `command:0x1234` | "command" | E-02 |
| T-028 | DM 位口径 | `memory_area:"dm", bit:3` | "memory area"/"bit" | E-03 |
| T-029 | 元素数 0 | `items:0` | "items" | E-05 |
| T-030 | 数据长度失配 | 字写 `items:2` 但 data 只 2 字节 | "data"/"len" | E-07 |
| T-031 | 响应长度缺失 | `expect_response:true` 且命令字段缺响应派生物（或 planner 断言响应长度） | "response" | E-08 |
| T-032 | BCD 字段越界 | clock 响应 `hour:0x99`（BCD 非法）；SID 是普通 1 字节字段，不在此例中按 BCD 校验 | "bcd" | E-09 |
| T-033 | GCT 非法 | `gct:3`；错误编号与统一错误子串尚未由当前实现裁决 | 待实现 | — |
| T-034 | DNA 非法 | `dna:1`；按 design §9.2 的 DNA/SNA 校验归入 E-06 | "dna" | E-06 |

> E 编号对应 19-fins-design.md §9.2 错误表。每条断言任务**确实失败**（Testing Policy §4），不得只断言"不 panic"。

---

## 7. 字段断言速查表

| tshark 字段 | 类型/进制 | 含义 | 常用值 |
|-------------|----------|------|--------|
| `omron.icf` | 8 位 hex | 信息控制字段 | 0x81 请求 / 0xC1 响应 |
| `omron.sid` | 8 位 hex | 服务 ID | 0x01..（递增 / 回显） |
| `omron.command` | 16 位 hex | FINS 命令码 | 0x0101 / 0x0102 / 0x0701 |
| `omron.memory.area.read` | 8 位 hex | 内存区码 | 0x82 DM / 0xB0 CIO / 0x30 CIO bit… |
| `omron.memory.address` | 16 位 hex | 起始字地址 | 0x0064（D100） |
| `omron.memory.address.bits` | 8 位 hex | 位偏移 | 0x00 字 / 0x02.. bit |
| `omron.memory.numitems` | 16 位 dec | 元素数 NC | 1、2… |
| `omron.response.code` | 16 位 hex | 结束码 | 0x0000 / 0x1101… |
| `omron.response.data` | bytes | 读响应数据 | 大端字数据 |
| `omron.tcp.magic` | 32 位 hex | 'FINS' | 0x46494e53 |
| `omron.tcp.length` | 32 位 dec/hex | FINS 帧长 | 18（读请求） |
| `omron.tcp.command` | 32 位 hex | TCP 层命令号 | 0x00000002 Frame Send |
| `omron.tcp.error_code` | 32 位 hex | 错误码 | 0 |

> 进制：`BASE_HEX` 字段输出 `0x…`；`BASE_DEC` 输出十进制（如 `omron.memory.numitems`=2）。框架比对整数语义，两种写法均可。

---

## 8. 覆盖勾选清单

| 覆盖点 | 用例 | 状态 |
|--------|------|------|
| FINS/UDP 请求-响应 | T-001 | JSON `fins_udp_dm_read` |
| FINS/TCP（Frame Send） | T-002 | JSON `fins_tcp_read` |
| 内存区 CIO | T-004 | JSON `fins_cio_read_word` |
| 内存区 WR | T-005 | JSON `fins_wr_read_word` |
| 内存区 HR | T-006 | JSON `fins_hr_read_word` |
| 内存区 TC | T-007 | JSON `fins_tc_read_pv` |
| 内存区 DM | T-001/T-011 | T-001 JSON `fins_udp_dm_read`；T-011 仍为设计行 |
| 内存区 IR | T-008 | JSON `fins_ir_read_word` |
| bit 域 | T-009/T-010 | JSON `fins_hr_read_bit`/`fins_cio_write_bit` |
| 错误码响应（0x1101） | T-024 | 设计行（JSON 未含，规划升级） |
| BCD SID | T-012 | JSON `fins_clock_read_bcd` |
| IPv4+IPv6 | T-001/T-003 | JSON `fins_udp_ipv6_read` |
| 多会话 sessions>1 | T-020~T-023 | JSON `fins_sessions_two`/`fins_sessions_three` |
| 负路径：非法内存区 | T-024 | 设计行 |
| 负路径：越界 | T-025 | 设计行 |
| 负路径：非法 ICF | T-026 | 设计行 |

---

## 9. 与 JSON 用例的一致性

- cases/fins.json 的 14 个 ID 与 19-fins-design.md §7 索引表 JSON 列 + 本档 §3 全清单 JSON 列**三方一致**（§1.3 脚本校验）；T-011 等未落盘设计行不计入 JSON ID 集合。
- 每条 JSON 的 `summary` 必须包含其 T 编号与覆盖点（如 "T-001: FINS/UDP DM 读往返"），供回归追溯。
- 设计行（无 JSON）不代表不测：记录在 §4/§5/§6 的断言要点，升级时同步三处（this 档、design §7、JSON + §1.3 expect 集合）。
- 升级步骤（新增 JSON 用例）：① 本档 §3 加行 + §4/5/6 加断言；② design §7 加行；③ 写 JSON 文件 + 更新 §1.3 expect 集合并跑脚本。

---

## 10. 测试执行与回归

- 运行：`cd trafficgen && go test ./test/protocol_pcap/ -run TestFINS -count=1 -v`（`-count=1` 防 go test 缓存，见记忆"go test 缓存陷阱"）
- 回归：`go vet ./... && go test -race ./...`（FINS 包 + 框架包）
- tshark 判据：`tshark -r out.pcap -Y omron -T fields -e omron.icf -e omron.sid -e omron.command -e omron.memory.area.read -e omron.memory.address -e omron.memory.numitems -e omron.response.code`
- 失败定位：先看 `omron.*` 字段是否存在（tshark 是否把载荷认成 omron），再逐字段比对——端口非 9600 时先确认 `-d` 提示生效。

---

## 修订记录

| 版本 | 日期 | 内容 |
|------|------|------|
| v1.0.0 | 2026-08-18 | 初稿：框架、全清单（T-001~T-040）、初始 JSON 用例（8 类内存区 + bit + 双载体 + IPv6 + 双/三会话 + BCD）、负路径设计行、覆盖清单、一致性脚本 |
| v1.0.1 | 2026-08-19 | 对齐实际 14 条 JSON：修正 ID 集合、T-011 未落盘状态、TCP 包数、Clock Read FrameAssert、位写偏移、HR 响应数据断言及 GCT/DNA/BCD 负路径边界 |

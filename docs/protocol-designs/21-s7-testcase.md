# 西门子 S7comm（S7 Communication，S7 通信协议）协议测试用例设计文档

> 版本：v1.0.0（初稿）
> 设计日期：2026-08-18
> 范围：S7comm 流量的 pcap 框架测试用例定义：连接建立（CR→CC→Setup F0）、读/写变量、多 DB 读、setup 参数、keep-alive 0xFA、错误响应（error class/code）、Read SZL、IPv4/IPv6、多会话独立源端口，以及全部 expect_error 负路径（非法 ROSCTR / 非法 area / PDU 长度不一致 / 地址越界 / udp 传输拒绝）
> 父文档：21-s7-design.md（协议设计：字节布局、状态机、HexDump 模板 S1-S12）
> 配套文件：`trafficgen/test/protocol_pcap/cases/s7.json`（用例数据，与此文档严格一致）
> 环境：tshark 的 s7comm 解析器；帧 IPv4 偏移 54 / IPv6 偏移 74；TCP 目标端口固定 102

---

## 目录

1. 概述
2. JSON 块结构
3. 索引表
4. 覆盖清单

---

# 1. 概述

## 1.1 测试目标

本套用例的目标是**验证 21-s7-design.md 第 6 章的每个 HexDump 模板能以逐字节一致的方式生成**，且生成流在任何环节不吞错（尤其负向用例：校验器必须拒绝，任务真实失败，不能静默产出 0 包）。

三重验证构造（对应 pcap 框架的三种断言原语，见父文档 18-layer-config-design.md）：

1. **连接期逐包断言**：CR/CC 无 S7 头——对帧 4/5 断言 COTP 字段（`cotp.pdu_type` 0x0E/0x0D）或 FrameAssert 字节；对帧 6/7（setup）断言 `s7comm.*`。
2. **业务期按函数断言**：read/write/SZL 的 `s7comm.param.func`、`s7comm.data.returncode`、`s7comm.header.pduref` 回显（`same_as_packet`）。
3. **负向 expect_error**：非法配置经 Validate 拒绝，任务按预期失败（无 pcap，仅 `expect_error:true`）。

## 1.2 与 design 章节的对应

| testcase 摘要 | design | HexDump |
| --- | --- | --- |
| 连接建立（CR/CC/setup） | 1.2, 4.1 | S1-S4 |
| 读 DB | 3.6 | S5-S6 |
| 写 M 区 | 3.7 | S7-S8 |
| 多 DB 读 | 3.6, 3.10 | S5（2 项） |
| setup 参数 | 3.5 | S3-S4 |
| keep-alive | 3.8 | S9 |
| 错误响应 | 9.1-9.3 | S12 |
| Read SZL | 3.9 | S10-S11 |
| IPv6 | 1.4, 8.4 | S3 (IPv6) |
| 多会话 | 4.1, 8.5 | S3-S8 双流 |
| 负向 | 9.3 | — |

## 1.3 用例生成环境约定

- 所有用例 `dst_port: 102`；帧 4/5 为 COTP CR/CC（无 `s7comm` 字段）。
- 该帧偏移由 `EtherTypeFor(src_ip)` 动态决定：IPv4 54，IPv6 74。
- 每个用例在 `expect.fields` 上断言 s7comm 字段时，必须给 case 配 `decode_as: ["tcp.port==102,s7comm"]`（确保 tshark 对该 TCP 流按 s7comm 解码，避免启发式 dissector 认领）。

# 2. JSON 块结构

## 2.1 用例对象外壳

```jsonc
{
  "id": "s7_xxx",
  "proto": "s7",
  "summary": "一句话：测什么、断言什么",
  "spec_json": {
    "layers": [ {"tcp": {}}, {"s7": {}} ],
    "src_ip": "10.0.0.1",
    "dst_ip": "20.0.0.1",
    "src_port": 12345,
    "dst_port": 102,
    "s7": {
      "transport": "tcp",
      "sessions": 1,
      "commands": [ ... ]
    }
  },
  "expect": {
    "packet_count": 12,
    "fields": [ ... ],
    "frames": [ ... ]
  }
}
```

- `sessions`：会话数；>1 时各会话独立 srcPort（s7_multi_session_ports 覆盖）。
- `commands[]`：读/写/keepalive/readsZL/error，顺序即执行顺序。

## 2.2 字段断言对象（expect.fields[]）

| 键 | 类型 | 语义 |
| --- | --- | --- |
| `packet` | int | 1 基包序（第 N 帧） |
| `field` | string | tshark 字段名（s7comm.* 等） |
| `value` | string | 期望值（tshark 输出格式，如数值/0x…） |
| `same_as_packet` | int | 等于另一帧同字段值（PduRef 回显用） |
| `nonzero` | bool | 非零/非空 |
| `distinct_values` | [string] | 多流聚合断言（多会话 srcPort） |

## 2.3 帧字节断言对象（expect.frames[]）

| 键 | 类型 | 语义 |
| --- | --- | --- |
| `packet` | int | 帧号 |
| `offset` | int | 帧内偏移（IPv4 54 / IPv6 74） |
| `hex` | string | 期望字节（空格分隔） |

## 2.4 负向用例外壳

```jsonc
{
  "id": "s7_negative_bad_rosctr",
  "proto": "s7",
  "summary": "…",
  "spec_json": { "layers": [...], "dst_port": 102, "s7": { "commands": [{"kind":"read","force_rosctr":9,"items":[...]}] } },
  "expect": { "expect_error": true,
    "notes": ["s7: invalid rosctr 9 → Validate 拒绝，任务失败无 pcap"] }
}
```

负向 case **无** `fields`/`frames`/`packet_count`（没有产出包），只有 `expect_error:true`。这条路径是"plan 错误被吞 → 任务 completed 0 包"反例的守卫（00-unimplemented-list 记录）。

---

# 3. 索引表

以下为 `trafficgen/test/protocol_pcap/cases/s7.json` 的完整用例清单（id 顺序 = 文件中出现顺序）。每行标注：期望包数、断言类型（fields / frames / expect_error）、对应 design 模板。

| # | id | 摘要 | 包数 | 断言类型 |
| --- | --- | --- | --- | --- |
| 1 | `s7_connect_setup_read` | 完整会话：TCP 握手→CR→CC→Setup(F0)→Read(DB1)，逐包断言 | 9 | fields+frames |
| 2 | `s7_write_m_area` | 写 M 区（area 0x83，M100.0 位 BIT）→ Ack_Data OK | 9 | fields+frames |
| 3 | `s7_multi_db_read` | 一次 read 双 DB 项（itemcount=2），响应 2 项 | 9 | fields+frames |
| 4 | `s7_setup_pdu_length` | Setup 请求 pdu_length=480，响应 240；MaxAmQ 协商 | 7 | fields+frames |
| 5 | `s7_keepalive` | keep-alive 0xFA：Job、parlg=1、datlg=0，无响应 | 7 | fields+frames |
| 6 | `s7_read_szl` | Read SZL 0x0132/0x0004 经 Userdata(0x07) 请求/响应 | 9 | fields+frames |
| 7 | `s7_error_class_code` | 错误响应：Ack_Data errcls/errcod 非零（0x04/0x01） | 9 | fields+frames |
| 8 | `s7_ipv6_session` | IPv6 全会话（dst_ip 为 IPv6，偏移 74） | 9 | fields+frames |
| 9 | `s7_multi_session_ports` | sessions=2 独立 srcPort，各走完整会话 | 18 | fields |
| 10 | `s7_negative_bad_rosctr` | 非法 ROSCTR（9）→ Validate 拒绝 | 0 | expect_error |
| 11 | `s7_negative_bad_area` | 非法 area（0x00）→ Validate 拒绝 | 0 | expect_error |
| 12 | `s7_negative_pdu_mismatch` | TPKT 长度与 COTP+S7 不一致 → Validate 拒绝 | 0 | expect_error |
| 13 | `s7_negative_addr_range` | 字节地址越界（>0xFFFFF 或 bit>7）→ Validate 拒绝 | 0 | expect_error |
| 14 | `s7_udp_rejected` | transport=udp → 生成器显式拒绝 | 0 | expect_error |

## 3.1 用例 #1 逐包断言明细（s7_connect_setup_read，含包号与帧断言）

包序（TCP 握手 1-3 → CR 4 → CC 5 → setup 6/7 → read 8/9 → 收尾）：

| 帧 | 方向 | 内容 | fields 断言 | frames 断言 |
| --- | --- | --- | --- | --- |
| 1 | up | SYN | tcp.flags SYN | — |
| 2 | down | SYN/ACK | tcp.flags SYN+ACK | — |
| 3 | up | ACK | — | — |
| 4 | up | COTP CR（无 S7） | cotp.pdu_type=0x0e | //zigzag 54：TPKT+COTP |
| 5 | down | COTP CC | cotp.pdu_type=0x0d | //zigzag 54 |
| 6 | up | Setup Job | s7comm.header.rosctr=1, .param.func=0xf0 | //zigzag 54: S3 模板 |
| 7 | down | Setup Ack_Data | rosctr=3, errcls=0x00, func=0xf0 | S4 模板 |
| 8 | up | Read Job（DB1.DBW0） | func=0x04, itemcount=1 | S5 模板 |
| 9 | down | Read Ack_Data（0x1234） | func=0x04, data.returncode=0xff | S6 模板 |
| 10 | up | Keep-alive（独立用例 #5 覆盖；本用例收尾） | — | — |
| 11-13 | — | TCP FIN 序列（#1 已含） | tcp.flags FIN | — |

> 上表为设计意图；实际包数/包序以 s7.json 为准。s7.json 中 #1 为 9 帧（含 FIN 序列）且不含 keep-alive（keep-alive 由 #5 独占）。s7.json 与本节必须一致（§4 核对）。

## 3.2 用例 #3：多 DB 读（s7_multi_db_read）参数项分解

请求参数区（Job，帧 8，已实测 tshark：func=0x04 itemcount=2 db=1,2）：

```
04 02                          Read Var，count=2
12 0a 10 04 00 01 00 01 84 00 00 00   item0: DB1 字 0 WORD，元素 1（读 1 个字）
12 0a 10 04 00 01 00 02 84 00 00 02   item1: DB2 字 2 WORD，元素 1
```

响应数据区（Ack_Data，**单个响应帧**返回两项，帧 9；请求/响应均带 itemcount）：

```
ff 04 00 02 12 34    item0: rc=ff, transp=04, len=2, value=1234
ff 04 00 02 56 78    item1: value=5678
```

**关键实测结论**：
1. 双 DB 读的响应是**一个 Ack_Data 帧**带两个数据项（itemcount=2），不是两帧。
2. tshark 对双 item 帧的 `s7comm.param.item.db`/`item.area`/`data.returncode` 输出为**逗号分隔多值**（`1,2` / `0x84,0x84` / `0xff,0xff`）——框架 FieldAssert 只支持单值字段，故这些字段不被断言。
3. 断言改为：精确字段（func/itemcount/rosctr/pduref 回显）+ FrameAssert 双 S7ANY 参数区（帧 8 offset 73，含 DB1 字 0 = `00 00`、DB2 字 2 = `00 02`）+ 数据区共享结构头（帧 9 offset 75 `ff 04 00 02`）。offset 由 payload 相对偏移 19/21 加 54 得出（见 s7.json notes）。

## 3.3 用例 #9：多会话（s7_multi_session_ports）srcPort 分布

sessions=2，src_port=12345 基础：会话 0 用 12345，会话 1 用 12346。各会话独立执行 CR/CC/setup/read。

断言：`tcp.srcport` 的 `distinct_values`: ["12345","12346"]；两个会话各自的第一业务帧 `s7comm.param.func=0x04` 都出现（各至少一次）。

---

# 4. 覆盖清单

本节是从 design 各章抽取的**必须覆盖**清单（CLAUDE.md 测试策略第一条：从 spec 逐条派生用例）。每条标注：关联 design 章节、覆盖用例 id、判定方式。

## 4.1 连接建立（CR→CC→Setup F0）

**来自 design 1.2、3.3、4.1、3.5、4.4.1。**

| 需求 | 断言 | 用例 |
| --- | --- | --- |
| TCP 握手先行（SYN→SYN/ACK→ACK） | tcp.flags 逐步 | #1, #8 |
| CR 无 S7 头（帧 4 只有 TPKT+COTP） | cotp.pdu_type=0x0e + FrameAssert 无 0x32 | #1, #8 |
| CC 回显 CR src-ref（dst-ref 对调） | cotp pdu_type=0x0d | #1, #8 |
| Setup Job func=0xf0 先于业务 | 帧 6 rosctr=1 func=0xf0 | #1 |
| Setup Ack_Data rosctr=3 errcls=0 | 帧 7 | #1, #4 |
| PDU 长度协商 480/240 | s7comm.param.pdu_length | #4 |
| MaxAmQ calling/called=1 | s7comm.param.maxamq_calling/called | #4 |
| **首个 S7 PDU 从 setup 起（CR/CC 无 pduref）** | 帧 4/5 无 s7comm.header | #1 |

## 4.2 读变量（Read Var 0x04）

**来自 design 3.6。**

| 需求 | 断言 | 用例 |
| --- | --- | --- |
| Read Job func=0x04 | s7comm.param.func | #1 |
| S7ANY 项（spec/addrlen/syntax/transp/len/db/area/addr） | FrameAssert S5 模板 | #1, #6 |
| 响应 Ack_Data 回显 pduref | s7comm.header.pduref same_as_packet | #1, #3 |
| 响应 returncode=0xff（Success） | s7comm.data.returncode | #1, #3 |
| 读 4 字节 WORD 值 0x1234 | FrameAssert S6 | #1 |
| 多 DB 读（itemcount=2、双项） | itemcount + 响应双项 | #3 |
| DB2 偏移地址（0x0002 字） | FrameAssert 地址域 | #3 |

## 4.3 写变量（Write Var 0x05）

**来自 design 3.7。**

| 需求 | 断言 | 用例 |
| --- | --- | --- |
| Write Job func=0x05 + S7ANY | s7comm.param.func=0x05 | #2 |
| 写 M 区（area 0x83）BIT 位 | FrameAssert 参数区 area=0x83 | #2 |
| 写数据项（rc=0x00, transp, len, value） | FrameAssert S7 模板 | #2 |
| 响应 rc 位图 0x0000（OK） | FrameAssert S8 | #2 |

## 4.4 Setup 参数与 Keep-alive

**来自 design 3.5、3.8。**

| 需求 | 断言 | 用例 |
| --- | --- | --- |
| setup pdu_length 客户端 480 | s7comm.param.pdu_length=480 | #4 |
| setup 响应 pdu_length 240 | =240 | #4 |
| keep-alive func=0xfa parlg=1 datlg=0 | param.func=0xfa + FrameAssert S9 | #5 |
| keep-alive 无响应（不等待） | 包序（其后无 down） | #5 |

## 4.5 错误响应（error class / error code）

**来自 design 9.1-9.3。**

| 需求 | 断言 | 用例 |
| --- | --- | --- |
| Ack_Data 头带错误类/错误码 | s7comm.header.errcls/errcod 非零 | #7 |
| errcls=0x04 errcod=0x01 精确值 | value 断言 | #7 |
| 错误响应 alt 数据（写请求数据项 rc=0x00/reserved） | FrameAssert S12/Wr 模板 | #7 |

## 4.6 Read SZL（Userdata 0x07）

**来自 design 3.9。**

| 需求 | 断言 | 用例 |
| --- | --- | --- |
| ROSCTR=0x07（Userdata，不是 Job） | s7comm.header.rosctr=7 | #6 |
| 参数头 0x000112 + 方法 0x11/0x12 | FrameAssert S10 头 | #6 |
| SZL-ID/Index 0x0132/0x0004 | s7comm.data.userdata.szl_id=0x0132 | #6 |
| 响应 returncode=0xff transp=0x09 | s7comm.data.returncode / transportsize | #6 |

## 4.7 IPv6 全会话

**来自 design 1.4、8.4。**

| 需求 | 断言 | 用例 |
| --- | --- | --- |
| dst_ip 为 IPv6 时 EtherType=0x86DD | ipv6.src/dst、frame.len | #8 |
| 帧载荷偏移 74（FrameAssert 用 74） | frames offset=74 | #8 |
| 会话建立/读写与 IPv4 语义一致 | s7 字段断言同 #1 | #8 |

## 4.8 多会话独立源端口（sessions>1）

**来自 design 4.1、8.5。**

| 需求 | 断言 | 用例 |
| --- | --- | --- |
| 每会话独立 srcPort（12345、12346） | tcp.srcport distinct_values | #9 |
| 各会话独立完整会话（CR/CC/setup/read 各出现） | func 存在断言 | #9 |

## 4.9 负向路径（expect_error）

**来自 design 9.3、10.3、8.9。**

| 需求 | 拒绝位置 | 用例 |
| --- | --- | --- |
| 非法 ROSCTR（9） | Validate | #10 |
| 非法 area（0x00） | Validate | #11 |
| TPKT 长度与 COTP+S7 不一致 | Validate（不产畸形包） | #12 |
| 字节地址越界（>0xFFFFF 或 bit>7） | Validate | #13 |
| transport=udp | 生成器显式拒绝 | #14 |

## 4.10 断言-字段-框架一致（derived from §1.3 + 8.12）

- 所有 `expect.fields` 值用 tshark 实际输出格式（如 `0x04`、`1`），核对方法：连跑 `tshark -r gen.pcap -T fields -e s7comm.param.func`。
- 所有 `decode_as` 为 `["tcp.port==102,s7comm"]`。
- packet_count 与 §3 索引表匹配；若 FIN 序列被省略，调整 §3.1 表中包数（保持 s7.json 与文档一致）。

## 4.11 覆盖声明（对照 CLAUDE.md 测试策略）

- **Spec-driven**：本清单每一行都从 design 表/字段矩阵派生，非"顺手测测"。
- **负路径**：§4.9 五行负向完整覆盖（#10-#14），并断言**真实失败**而非 0 包静默完成。
- **集成**：全会话用例（#1/#8）驱动 tcp→s7 全链（握手→建立→业务→（FIN）），不只是单包。
- **可观察输出**：frames+fields 断言实际字节/字段值，非"不 panic"。
- **唯一已知不可断言项**：多会话 FrameAssert（交织非确定），改由 distinct_values 断言（#9）——文档化取舍。

## 4.12 逐用例期望明细（与 s7.json 严格一致）

> 本节给每个正项用例的**精确字段/帧断言**。s7.json 落盘后与本节逐条核对；不一致以 s7.json（框架执行的真实断言）为准并回改本节，保持"文档=数据"单一事实源。

### s7_connect_setup_read（#1）

帧布局：1 SYN / 2 SYN-ACK / 3 ACK / 4 CR / 5 CC / 6 Setup Job / 7 Setup Ack / 8 Read Job / 9 Read Ack。

fields（packet:field=value）：

| 帧 | field | value |
| --- | --- | --- |
| 4 | cotp.pdu_type | 0x0e |
| 5 | cotp.pdu_type | 0x0d |
| 6 | s7comm.header.rosctr | 1 |
| 6 | s7comm.param.func | 0xf0 |
| 7 | s7comm.header.rosctr | 3 |
| 7 | s7comm.header.errcls | 0x00 |
| 8 | s7comm.param.func | 0x04 |
| 8 | s7comm.param.itemcount | 1 |
| 9 | s7comm.data.returncode | 0xff |
| 9 | s7comm.header.pduref | same_as_packet=8 |

frames（示例，非穷举）：

| 帧 | offset | hex 前缀 |
| --- | --- | --- |
| 6 | 54 | `03 00 00 19 02 f0 80 32 01 00 00`（S3） |
| 9 | 54 | `03 00 00 1b 02 f0 80 32 03 00 00 03 00 00 02 00 06 00 00 04 01 ff 04 00 02 12 34`（S6） |

### s7_write_m_area（#2）

帧布局：…8 Write Job / 9 Write Ack。

| 帧 | field | value |
| --- | --- | --- |
| 8 | s7comm.param.func | 0x05 |
| 8 | s7comm.param.itemcount | 1 |
| 9 | s7comm.header.rosctr | 3 |
| 9 | s7comm.param.func | 0x05 |

frames：

| 帧 | offset | hex |
| --- | --- | --- |
| 8 | 54 | S7 模板：参数区写 M 区 `12 0a 10 01 00 01 00 00 83 00 03 20 00 03 00 01 01`（S7ANY BIT transp=1，线性位索引 addr24=100*8+0=0x320，tshark 实测 Byte=100 Bit=0） |
| 9 | 54 | S8 模板：Write Ack_Data `03 00 00 16 02 f0 80 32 03 00 00 04 00 00 01 00 02 00 00 05 00 00`（rosctr=3，返回码 `05 00 00`=0x0000 OK） |

### s7_multi_db_read（#3）

| 帧 | field | value |
| --- | --- | --- |
| 8 | s7comm.param.itemcount | 2 |
| 8 | s7comm.header.pduref | （回显基准） |
| 9 | s7comm.header.rosctr | 3 |
| 9 | s7comm.param.itemcount | 2 |
| 9 | s7comm.header.pduref | same_as_packet=8 |

frames：请求参数区双项（见 §3.2；帧 8 offset 73 双 S7ANY，帧 9 offset 75 数据头 `ff 04 00 02`）。itemcount 在请求与响应均为 2。

### s7_setup_pdu_length（#4）

| 帧 | field | value |
| --- | --- | --- |
| 6 | s7comm.param.pdu_length | 480 |
| 6 | s7comm.param.maxamq_calling | 1 |
| 6 | s7comm.param.maxamq_called | 1 |
| 7 | s7comm.param.pdu_length | 240 |

frames：S3 帧 6 / S4 帧 7 模板（与 s7.json 一致）。

### s7_keepalive（#5）

| 帧 | field | value |
| --- | --- | --- |
| 6 | s7comm.header.rosctr | 1 |
| 6 | s7comm.param.func | 0xfa |
| 6 | s7comm.header.parlg | 1 |
| 6 | s7comm.header.datlg | 0 |

frames：S9 `03 00 00 12 02 f0 80 32 01 00 00 00 01 00 01 00 00 fa`（帧 6）。

### s7_read_szl（#6）

| 帧 | field | value |
| --- | --- | --- |
| 8 | s7comm.header.rosctr | 7 |
| 8 | s7comm.header.parlg | 8 |
| 8 | s7comm.header.datlg | 8 |
| 9 | s7comm.header.rosctr | 7 |
| 9 | s7comm.data.userdata.szl_id | 0x0132 |
| 9 | s7comm.data.returncode | 0xff |
| 9 | s7comm.data.transportsize | 0x09 |

frames：S10 帧 8 / S11 帧 9 模板（Direct 短头，offset 54）。

### s7_error_class_code（#7）

| 帧 | field | value |
| --- | --- | --- |
| 8 | s7comm.header.errcls | 0x04 |
| 8 | s7comm.header.errcod | 0x01 |

frames：S12 `… 00 00 04 01 05`。

### s7_ipv6_session（#8）

| 帧 | field | value |
| --- | --- | --- |
| 6 | s7comm.param.func | 0xf0 |
| 8 | s7comm.param.func | 0x04 |
| — | ipv6.src/dst | 存在（nonzero fields） |

frames：offset=74 的 S3 模板。

### s7_multi_session_ports（#9）

| field | distinct_values |
| --- | --- |
| tcp.srcport | ["12345","12346"] |
| s7comm.param.func | ["0xf0","0x04"] |

## 4.13 tshark 字段值核对命令（维护者用）

对任一 `expect.fields` 断言，可独立复核：

```bash
tshark -r gen.pcap -d tcp.port==102,s7comm -T fields -e s7comm.param.func \
       -e s7comm.header.rosctr -e s7comm.data.returncode -e s7comm.param.itemcount
```

预期输出对应 indices 应与文档一致。若 tshark 版本变化导致字段名/值格式变（如 `0x0004` vs `4`），以本命令实测为准并回改 s7.json（而非反向）。帧 4/5（CR/CC）无 s7comm 字段，读取时为空（符合预期，1.3 已述）。

## 4.14 覆盖率说明与已知取舍

- **已覆盖（spec 驱动逐条）**：连接建 3 阶段、setup、keepalive、read（含 multi-DB）、write、SZL、错误头、双 IPv4/IPv6、多会话独立端口、5 类负向。
- **未单测通过多帧写**：多 DB 写多项（合并进 #3 读双项检验同构逻辑）。
- **未覆盖（文档化）**：COTP 分片（PDU<480 不分片）、S7 认证、block 传输 0x1C-0x1E、冗余——见 design 11.1。这些不列为缺陷，列为已知限制。

## 4.15 验收标准（doc 各节 ↔ s7.json 一致性）

1. §3 索引表 14 个 id 与 s7.json 完全一致（无缺/无多）。
2. §4.12 每行 fields/frames 在 s7.json 中存在且值一致；FrameAssert offset 对 IPv4=54、对 IPv6=74。
3. 负向 5 例均 `expect_error:true` 且无 fields/frames/packet_count。
4. `python3 -m json.tool s7.json` 通过。
5. （实现后）`go test ./test/protocol_pcap/... -run S7 -count=1` 全绿；tshark 为最终裁判。

# SOME-IP（Scalable service-Oriented MiddlewarE over IP）协议测试用例设计文档

> 版本：v1.0.0（初稿）
> 设计日期：2026-08-18
> 范围：SOME/IP（汽车开放系统架构 AUTOSAR 的"基于 IP 的可扩展面向服务中间件"）与 SOME/IP-SD（Service Discovery，服务发现）、SOME/IP-TP（Transport Protocol，传输分段）流量的 pcap 框架测试用例定义；覆盖方法调用 REQUEST→RESPONSE、REQUEST_NO_RETURN、NOTIFICATION 事件、ERROR 返回码、SD FindService/OfferService、SubscribeEventgroup/Ack、多方法多事件、TP 分段、IPv4+IPv6、多会话、独立 IPv6 SD Endpoint Option 以及全部负路径（expect_error）
> 父文档：28-someip-design.md（协议设计：16B 大端头、SD/TP 子结构、状态机、HexDump 场景 S1-S10 + S9b）
> 配套文件：`trafficgen/test/protocol_pcap/cases/someip.json`（用例数据，与此文档严格一致）
> 权威字段源：tshark 3.6.14 本机 `someip.*`/`someipsd.*`/`someip.tp.*` 字段表（确认真实性），UDP 载荷偏移 42、TCP 偏移 54

---

## 目录

1. [测试环境与校验手段](#1-测试环境与校验手段)
2. [框架断言工具](#2-框架断言工具)
3. [用例编号规则](#3-用例编号规则)
4. [正向用例](#4-正向用例T-someip-s1s10)
5. [负路径用例](#5-负路径用例t-someip-neg)
6. [字段断言速查表](#6-字段断言速查表)
7. [覆盖勾选清单](#7-覆盖勾选清单)
8. [与 JSON 用例的一致性](#8-与-json-用例的一致性)
9. [测试执行与回归](#9-测试执行与回归)

---

## 1. 测试环境与校验手段

### 1.1 运行环境

- pcap 框架（`trafficgen/test/protocol_pcap/`）生成抓包，`tshark` 解析验证。
- SOME/IP 消息承载于 UDP/TCP 上（本套用例以 **UDP 30490** 为主，另有 TCP 载体例）；tshark **自动**识别：`someip` 解析器按端口/UDP 载荷启发式启用（`-d` 可用 `udp.port==30490,someip` 强制，通常无需）。
- SD 报文（Message ID `0xFFFF8100` + Message Type=0x02）由 tshark 自动按 `someipsd` 解析，无额外 `-d`。

### 1.2 权威字节事实来源

- 消息头 16 字节大端布局：Message ID(Service ID 16bit + Method ID 16bit)、Length(=8+Payload，自 Request ID 起)、Request ID(Client ID 16bit + Session ID 16bit)、Protocol Version(0x01)、Interface Version、Message Type、Return Code——与 tshark 字段集一致（`someip.messageid`/`someip.length`/`someip.sessionid`/`someip.protoversion`/`someip.messagetype`/`someip.returncode`）。
- SD：Flags(1B)+Reserved(3B)+Entry 数组长度(4B)+Entry(16B/条)+Option。Entry type：FindService=0x00/OfferService=0x01/SubscribeEventgroup=0x06/SubscribeEventgroupAck=0x07。Option type：IPv4 Endpoint=0x01/IPv4 Multicast=0x02/IPv6 Endpoint=0x06——与 tshark `someipsd.entry.*`/`someipsd.option.*` 一致。
- TP：Offered Length(4B)+Segment ID(1B)+more_segments 低 1 位(1B)+保留；Message Type TP 变体（REQUEST→0x20、NOTIFICATION→0x22、RESPONSE→0xA0）——与 tshark `someip.messagetype.tp`/`someip.tp.offset`/`someip.tp.flags.more_segments` 一致。

### 1.3 字节序与回绕规则（断言前提）

- 所有数值字段大端。
- Session ID 多会话递增（session_inc），不要求回绕。
- TP 段序号 0 起递增；末段 more_segments=0。

### 1.4 运行约束（测试依赖）

| 约束 | 值 | 说明 |
|------|----|------|
| tshark 版本 | ≥3.6 | 建议；字段名基于 3.6.14 核实 |
| 双向包索引 | 精确 | 请求先发、响应后发，packet 索引按抓包顺序（§4 表逐条给） |
| 每包载荷 | ≤1400（非 TP）| UDP 不分段 |
| 并发用例 | 每用例独立引擎实例 | 计数/会话互不干扰 |

**测试前置校验命令**：
```bash
tshark -v | head -2          # 确认 3.6+
tshark -G fields | grep -c 'someip'   # 确认 someip/someipsd 字段表（≥107）
```

---

## 2. 框架断言工具

### 2.1 Case 结构（pcaptest/types.go）

```json
{
  "id": "someip_xxx",
  "proto": "someip",
  "summary": "...",
  "spec_json": { "layers": [{"udp":{}},{"someip":{}}], "src_ip": "10.0.0.1",
                 "dst_ip": "20.0.0.1", "src_port": 12345, "dst_port": 30490,
                 "someip": { ... } },
  "expect": {
    "packet_count": 2,
    "fields": [ {"packet": 1, "field": "someip.messagetype", "value": "0x00", ...} ],
    "frames": [ {"packet": 1, "offset": 42, "hex": "12 34 00 01 ..."} ],
    "expect_error": false,
    "error_contains": "",
    "notes": []
  }
}
```

### 2.2 断言语义

| 断言类型 | 字段 | 语义 |
|----------|------|------|
| 等值 | `field` + `value` | tshark 输出该字段等于给定值 |
| 存在性 | `field` + `nonzero: true` | 字段存在且非零 |
| 跨包相等 | `field` + `same_as_packet: 1` | 与第 1 包同值（REQUEST/RESPONSE 的 SessionID 配对） |
| FrameAssert | `offset` + `hex` | 按包内偏移精确比对原始字节（大端头/SD/TP 的终极手段） |
| 负路径 | `expect_error` + `error_contains` | 任务必须失败且错误文本含子串 |

注意：tshark 数值进制——`someip.*`/`someipsd.entry.*` 十六进制字段输出 `0x` 前缀（如 `someip.messagetype`=0x00、`someipsd.entry.serviceid`=0x1234），`someipsd.option.type`/`port` 为十进制（0x01 显示 1、30490 显示 30490）；`value` 按对应进制给。

### 2.3 负路径断言

`expect_error: true` 时框架断言任务**失败**且错误文本含 `error_contains`（如 `"service_id"`）。"任务失败被观测"是硬性要求（Testing Policy 第 4 条），不得只断言"不失败"。

---

## 3. 用例编号规则

- 正向：`T-SOMEIP-<分组>-<序号>`，对应 28-someip-design.md §6 场景 S1..S10；S9b 为独立 IPv6 SD Option 原子场景。
- 负向：`T-SOMEIP-NEG-01..04`，对应 design §9 错误处理表 V1/V2/V3/V5。
- JSON 用例 id 采用 `someip_<key>` 小写（下划线连接）。

### 3.1 用例全清单（16 项一览）

| 编号 | 名称 | 场景/依据 | 类型 | JSON id |
|------|------|-----------|------|---------|
| T-SOMEIP-REQ-01 | 方法调用 REQUEST→RESPONSE | S1（§6.1） | 正 | `someip_req_resp` |
| T-SOMEIP-REQ-02 | 空载荷方法调用 | S1 变体 | 正 | `someip_req_empty` |
| T-SOMEIP-SESS-01 | 多会话 Session ID 匹配 | S2（§6.2） | 正 | `someip_multi_session` |
| T-SOMEIP-NORET-01 | REQUEST_NO_RETURN | S3（§6.3） | 正 | `someip_no_return` |
| T-SOMEIP-ERR-01 | ERROR 返回码 | S4（§6.4） | 正 | `someip_error` |
| T-SOMEIP-SD-01 | SD FindService→OfferService | S5（§6.5） | 正 | `someip_sd_find_offer` |
| T-SOMEIP-SD-02 | SD SubscribeEventgroup→Ack | S6（§6.6） | 正 | `someip_sd_subscribe` |
| T-SOMEIP-EVT-01 | 多方法多事件 NOTIFICATION | S7（§6.7） | 正 | `someip_multi_method_event` |
| T-SOMEIP-TP-01 | TP 分段重组 | S8（§6.8） | 正 | `someip_tp_segments` |
| T-SOMEIP-IPV6-01 | IPv6 载体方法调用 | S9（§6.9） | 正 | `someip_ipv6` |
| T-SOMEIP-IPV6-SD-01 | IPv6 SD Endpoint Option | S9b（§6.9b） | 正 | `someip_sd_ipv6` |
| T-SOMEIP-TCP-01 | TCP 载体双向 | S10（§6.10） | 正 | `someip_tcp_swap` |
| T-SOMEIP-NEG-01..04 | 负路径（4 例） | §9.1 V1/V2/V3/V5 | 负 | `someip_neg_*`×4 |

## 4. 正向用例（T-SOMEIP-S1..S10 + S9b）

> 公共默认：UDP 载体（`[{"udp":{}},{"someip":{}}]`）、src_ip=10.0.0.1、dst_ip=20.0.0.1、src_port=12345、dst_port=30490、service_id=0x1234、method_id=0x0001、client_id=0x0001。双向包索引在 UDP 下单流内按抓包顺序：请求包 1、响应包 2。

### 4.1 T-SOMEIP-REQ-01 方法调用 REQUEST→RESPONSE（S1）

**依据**：design §4.2 方法调用状态机 + §6 S1。**目标**：REQUEST(0x00)→RESPONSE(0x80) 双向交换，Session ID 配对。

`someip_req_resp`：

```json
{
  "id": "someip_req_resp",
  "proto": "someip",
  "summary": "T-SOMEIP-REQ-01/S1: 方法调用 REQUEST(0x00) → autoResponse RESPONSE(0x80)，payload de ad be ef，同 SessionID 配对，UDP 30490",
  "spec_json": {
    "layers": [ {"udp": {}}, {"someip": {}} ],
    "src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
    "src_port": 12345, "dst_port": 30490,
    "someip": {
      "service_id": 4660, "method_id": 1, "client_id": 1,
      "protocol_version": 1, "interface_version": 1,
      "message_type": "request", "auto_response": true,
      "payload": [222, 173, 190, 239]
    }
  },
  "expect": {
    "packet_count": 2,
    "fields": [
      {"packet": 1, "field": "someip.messageid", "value": "0x12340001"},
      {"packet": 1, "field": "someip.length", "value": "12"},
      {"packet": 1, "field": "someip.sessionid", "value": "0x0001"},
      {"packet": 1, "field": "someip.messagetype", "value": "0x00"},
      {"packet": 1, "field": "someip.returncode", "value": "0x00"},
      {"packet": 1, "field": "udp.dstport", "value": "30490"},
      {"packet": 2, "field": "someip.messagetype", "value": "0x80"},
      {"packet": 2, "field": "someip.returncode", "value": "0x00"},
      {"packet": 2, "field": "someip.sessionid", "same_as_packet": 1},
      {"packet": 2, "field": "someip.messageid", "same_as_packet": 1},
      {"packet": 2, "field": "udp.srcport", "value": "30490"}
    ],
    "frames": [
      {"packet": 1, "offset": 42, "hex": "12 34 00 01 00 00 00 0c 00 01 00 01 01 01 00 00 de ad be ef"},
      {"packet": 2, "offset": 42, "hex": "12 34 00 01 00 00 00 0c 00 01 00 01 01 01 80 00 de ad be ef"}
    ],
    "notes": [
      "包1 REQUEST Type=0x00，包2 RESPONSE Type=0x80；header offset 42 = Eth14+IP20+UDP8",
      "Length=0x0c=12 = 8(RequestID..RC) + 4(payload)；same_as_packet 断言响应回用请求 SessionID/MessageID"
    ]
  }
}
```

### 4.2 T-SOMEIP-REQ-02 空载荷方法调用（S1 变体）

`someip_req_empty`：同配置但无 payload → Length=8、单包请求 + 响应（空载荷 RESPONSE）。断言 `someip.length=8`、`someip.messagetype: 包1=0x00 / 包2=0x80`、包2 `same_as_packet` sessionid。对应 design §6 S1 空载荷注释。

### 4.3 T-SOMEIP-SESS-01 多会话 Session ID 匹配（S2）

**目标**：多会话递增 + 每对请求/响应配对（`session_start=1, session_inc=1`，两次方法调用）。

`someip_multi_session`：

```json
{
  "id": "someip_multi_session",
  "proto": "someip",
  "summary": "T-SOMEIP-SESS-01/S2: 两次方法调用 SessionID=1,2，各自 RESPONSE 回用本会话号（same_as_packet）",
  "spec_json": {
    "layers": [ {"udp": {}}, {"someip": {}} ],
    "src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
    "src_port": 12345, "dst_port": 30490,
    "someip": {
      "service_id": 4660, "method_id": 1, "client_id": 1,
      "session_start": 1, "session_inc": 1, "auto_response": true,
      "events": [
        {"payload": [1, 2, 3, 4]},
        {"payload": [5, 6, 7, 8]}
      ]
    }
  },
  "expect": {
    "packet_count": 4,
    "fields": [
      {"packet": 1, "field": "someip.sessionid", "value": "0x0001"},
      {"packet": 1, "field": "someip.messagetype", "value": "0x00"},
      {"packet": 2, "field": "someip.sessionid", "same_as_packet": 1},
      {"packet": 2, "field": "someip.messagetype", "value": "0x80"},
      {"packet": 3, "field": "someip.sessionid", "value": "0x0002"},
      {"packet": 3, "field": "someip.messagetype", "value": "0x00"},
      {"packet": 4, "field": "someip.sessionid", "same_as_packet": 3},
      {"packet": 4, "field": "someip.messagetype", "value": "0x80"}
    ],
    "notes": [
      "包1/2 会话1 配对、包3/4 会话2 配对；包3 SessionID=0x0002 证明递增",
      "events 列表逐条展开，SessionID 递增分配；响应序列与请求交错"
    ]
  }
}
```

### 4.4 T-SOMEIP-NORET-01 REQUEST_NO_RETURN（S3）

**依据**：design §6 S3。**目标**：Type=0x01 单包、autoResponse 强制关闭（无响应包）。

`someip_no_return`：`"message_type":"request_no_return"`，其余同 4.1。断言 `packet_count=1`、包1 `someip.messagetype=0x01`、`someip.returncode=0x00`；FrameAssert `12 34 00 01 00 00 00 0c 00 01 00 01 01 01 01 00 de ad be ef`（offset 42）。notes 标注"REQUEST_NO_RETURN 无响应，packet_count=1 证明 autoResponse 被强制关闭"。

### 4.5 T-SOMEIP-ERR-01 ERROR 返回码（S4）

**依据**：design §6 S4。**目标**：Type=0x80→0x81、ReturnCode=E_NOT_OK(0x01)、session 配对。

`someip_error`：`"message_type":"request"` + 显式 `"direction":"down"` RESPONSE 配置 ERROR（用 `events` 显式下发 down ERROR，或 auto_response 后配置 error）：

```json
{
  "id": "someip_error",
  "proto": "someip",
  "summary": "T-SOMEIP-ERR-01/S4: REQUEST → ERROR(0x81) RC=0x01(E_NOT_OK)，同 SessionID",
  "spec_json": {
    "layers": [ {"udp": {}}, {"someip": {}} ],
    "src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
    "src_port": 12345, "dst_port": 30490,
    "someip": {
      "service_id": 4660, "method_id": 1, "client_id": 1,
      "message_type": "request",
      "events": [
        {"direction": "down", "message_type": "error", "return_code": 1, "payload": [0]}
      ]
    }
  },
  "expect": {
    "packet_count": 2,
    "fields": [
      {"packet": 1, "field": "someip.messagetype", "value": "0x00"},
      {"packet": 2, "field": "someip.messagetype", "value": "0x81"},
      {"packet": 2, "field": "someip.returncode", "value": "0x01"},
      {"packet": 2, "field": "someip.sessionid", "same_as_packet": 1}
    ],
    "notes": [
      "ERROR 响应 RC=0x01(E_NOT_OK)；Type=0x81 必须配非 0 RC（design §9 V6）",
      "down 方向源端口变 30490（udp.srcport 可选断言）"
    ]
  }
}
```

### 4.6 T-SOMEIP-SD-01 SD FindService→OfferService（S5）

**依据**：design §6 S5 + §3.4。**目标**：Entry type 0x00/0x01、ServiceID/InstanceID/版本/TTL、IPv4 Endpoint Option；S5 的 FrameAssert 与设计稿逐字节一致。

`someip_sd_find_offer` 的可观察字段：两包 `someip.serviceid=0xffff`、`someip.methodid=0x8100`、`someip.messagetype=0x02`；包1 Entry `type=0x00/serviceid=0x1234/instanceid=0x0001/majorver=1/minorver=0/ttl=16777215`；包2 Entry `type=0x01/majorver=1/minorver=0/ttl=3`，并断言 Option `type=1/ipv4address=20.0.0.200/port=30490`。`ttl` 与 `someip.length` 按 tshark 十进制输出。

FrameAssert（SOME/IP 头起点 offset 42）：

```text
包1：ff ff 81 00 00 00 00 20 00 01 00 01 01 01 02 00 00 00 00 00 00 00 00 10 00 00 00 12 34 00 01 01 ff ff ff 00 00 00 00 00
包2：ff ff 81 00 00 00 00 2c 00 01 00 02 01 01 02 00 00 00 00 00 00 00 00 10 01 01 00 12 34 00 01 01 00 00 03 00 00 00 00 00 01 00 09 00 14 00 00 c8 00 11 77 1a
```

逐字节核算：包1 wire 40B，`Length=0x20=32=8+(SD头8+Entry16)`；包2 wire 52B，`Length=0x2c=44=8+(SD头8+Entry16+Option12)`；两包 Entries Length 均 `0x10=16`。Option 12B 为 `01 00 09 00 14 00 00 c8 00 11 77 1a`，其中 `Length=00 09`（大端），Option 总长=3B 头+9B 数据。JSON 中 Offer 的 Option 配置为 `{"type":1,"ip":"20.0.0.200","port":30490,"proto":"udp"}`。

> `cases/someip.json` 是执行事实源；上述 frame、字段与 notes 必须与 JSON `someip_sd_find_offer` 同步。SD 报头 Service ID 固定 0xffff，不能把 Entry Service ID 0x1234 与外层头混淆。

### 4.7 T-SOMEIP-SD-02 SD SubscribeEventgroup→Ack（S6）

`someip_sd_subscribe`：type `subscribe`(0x06)→`subscribe_ack`(0x07)，Subscribe Entry 带 InstanceID/EventgroupID；Ack 使用规范允许的最小结构，不引用 Endpoint Option。

- 包1断言：`someip.serviceid=0xffff`、`someipsd.entry.type=0x06`、`serviceid=0x1234`、`instanceid=0x0001`、`eventgroupid=0x0001`。
- 包2断言：`someip.serviceid=0xffff`、`someipsd.entry.type=0x07`、`counter=0x0`。
- **结构边界**：SubscribeEventgroupAck 可以不带 Option；此原子用例验证无 Option 的合法 Ack，不声称覆盖带 Endpoint Option 的 Ack 变体。若未来实现该变体，新增独立 case 并重算 Entries/Options Length，不能复用本 case 的断言。

### 4.8 T-SOMEIP-EVT-01 多方法多事件 NOTIFICATION（S7）

`someip_multi_method_event`：REQUEST×2 + 事件 NOTIFICATION(0x02, method_id=0x8001)：

```json
{
  "id": "someip_multi_method_event",
  "proto": "someip",
  "summary": "T-SOMEIP-EVT-01/S7: 多方法 A/B(REQUEST→RESPONSE) + 事件 NOTIFICATION(0x02) method 0x8001 同流",
  "spec_json": {
    "layers": [ {"udp": {}}, {"someip": {}} ],
    "src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
    "src_port": 12345, "dst_port": 30490,
    "someip": {
      "service_id": 4660, "client_id": 1, "auto_response": true,
      "events": [
        {"method_id": 1, "message_type": "request", "payload": [1]},
        {"method_id": 2, "message_type": "request", "payload": [2]},
        {"method_id": 32769, "message_type": "event", "direction": "down", "payload": [9, 9]}
      ]
    }
  },
  "expect": {
    "packet_count": 5,
    "fields": [
      {"packet": 1, "field": "someip.methodid", "value": "0x0001"},
      {"packet": 1, "field": "someip.messagetype", "value": "0x00"},
      {"packet": 2, "field": "someip.methodid", "same_as_packet": 1},
      {"packet": 2, "field": "someip.messagetype", "value": "0x80"},
      {"packet": 3, "field": "someip.methodid", "value": "0x0002"},
      {"packet": 3, "field": "someip.messagetype", "value": "0x00"},
      {"packet": 4, "field": "someip.methodid", "same_as_packet": 3},
      {"packet": 4, "field": "someip.messagetype", "value": "0x80"},
      {"packet": 5, "field": "someip.methodid", "value": "0x8001"},
      {"packet": 5, "field": "someip.messagetype", "value": "0x02"}
    ],
    "notes": [
      "方法 A/B MethodID=0x0001/0x0002 各自 REQUEST→RESPONSE；事件 MethodID=0x8001 bit15=1=event, Type=0x02",
      "事件 NOTIFICATION 无响应、方向 down（源端口 30490）",
      "SessionID 在请求序列 1,2 分配、事件用独立会话（实现按 events 逐条递增）"
    ]
  }
}
```

### 4.9 T-SOMEIP-TP-01 TP 分段重组（S8）

**依据**：design §6 S8 + §3.5。**目标**：真实 2500B 载荷按 `segment_size=1400` 分为 1400B+1100B 两段，首段 TP 变体 0x20、more_segments=1，末段 more=0，重组长度 2516。

`someip_tp_segments` 的 JSON `spec_json.someip.payload` 是 2500 个显式字节（0..255 循环），并同时设置 `tp.payload_length=2500`；不存在 4B 骨架加 2500B 声明的假 payload。断言 `packet_count=2`、首段 `messagetype=0x20/tp=1/offset=2516/more_segments=1`、末段 `more_segments=0/reassembled.length=2516`。实现尚未注册的边界见 design §8；这里的可执行表达明确以数组长度为事实。

> 大数组故不在本文复制 2500 个元素；JSON 的 `len(spec_json.someip.payload)==2500` 是审查脚本的机器可核对条件，本文的分段与长度数字必须保持同步。

### 4.10 T-SOMEIP-IPV6-01 IPv6 载体方法调用（S9）

`someip_ipv6` 是 IPv6 UDP 载体下的普通 REQUEST→RESPONSE，断言 IPv6 地址、`ip.proto=17`、消息头 MessageID 与响应 SessionID；它不宣称覆盖 IPv6 SD Option。

### 4.10b T-SOMEIP-IPV6-SD-01 IPv6 SD Endpoint Option（S9b）

`someip_sd_ipv6` 是独立原子 case：IPv6 UDP 载体上的单个 SD OfferService，Option type=0x06、IPv6 地址 `2001:db8::1`、端口 30490。断言 `ipv6.src/dst`、`someip.serviceid=0xffff`、`someipsd.entry.type=0x01`、`someipsd.option.type=6`（tshark 十进制）、`someipsd.option.ipv6address`、`someipsd.option.port`。IPv6 Option wire 为 `06 00 15 00` + 16B 地址 + `00 11 77 1a`，总长24B、Length=0x0015。

### 4.11 T-SOMEIP-TCP-01 TCP 载体双向（S10）

`someip_tcp_swap` 只使用可靠的 observable assertions：`has_handshake=true`、`min_packets=6`、首包 `tcp.flags=0x002` 且 `tcp.dstport=30490`。框架不能按 SOME/IP 字段内容选择 TCP 数据包，因而不硬编码“包4/包5”；REQUEST/RESPONSE 的字段存在性需由 tshark 或实现级检查补充。该限制不是协议语义缺失，也不代表 packet 1 是数据包。

---

## 5. 负路径用例（T-SOMEIP-NEG）

> 对应 design §9.1 校验规则 V1/V2/V3/V5。每条 `expect_error: true`，任务**必须失败**且错误含 `error_contains`；若非失败（哪怕发了一包）判 FAIL。

| JSON id | 依据 | spec 关键配置 | error_contains |
|---------|------|--------------|----------------|
| `someip_neg_service_id` | V1 | `"service_id": 0` | `service_id must be nonzero` |
| `someip_neg_session` | V2 | `"session_start": 0, "session_inc": 0`（明确非递增） | `invalid session_id` |
| `someip_neg_type` | V3 | `"message_type": 5`（非枚举） | `invalid message_type` |
| `someip_neg_tp` | V5 | `tp.segment_size: 0`（或段数超限 / OfferedLength 不符） | `tp segment` |

以 **T-SOMEIP-NEG-01** 为样板（其余结构相同，改 key + 断言）：

```json
{
  "id": "someip_neg_service_id",
  "proto": "someip",
  "summary": "T-SOMEIP-NEG-01/V1: service_id=0 非法 -> Validate 拒绝",
  "spec_json": {
    "layers": [ {"udp": {}}, {"someip": {}} ],
    "src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
    "src_port": 12345, "dst_port": 30490,
    "someip": { "service_id": 0, "method_id": 1, "message_type": "request" }
  },
  "expect": {
    "expect_error": true,
    "error_contains": "service_id must be nonzero",
    "notes": [
      "Validate negative：任务必须在创建/启动失败，错误含 'service_id must be nonzero'（design §9.1 V1）"
    ]
  }
}
```

> 负路径在层链写法下仍传 `layers`（无 SOME/IP 包发出），与 enip 负路径用例（`enip_t081_unknown_command` 等）同构。

---

## 6. 字段断言速查表

| tshark 字段 | 进制显示 | 用途 |
|-------------|---------|------|
| `someip.serviceid` / `someip.methodid` | 0x hex | 头 Service/Method ID（method 0x0001、event 0x8001、SD 0x8100） |
| `someip.messageid` | 0x hex 32bit | 头 Message ID（如 0x12340001） |
| `someip.length` | 十进制 | =8+len(payload)；空载荷 8 |
| `someip.sessionid` | 0x hex | Session ID；same_as_packet 配对 |
| `someip.protoversion` / `someip.interfaceversion` | 0x hex | 1/1 |
| `someip.messagetype` | 0x hex | 0x00 REQUEST / 0x01 NORET / 0x02 EVENT / 0x80 RESPONSE / 0x81 ERROR / 0x20..0xA0 TP |
| `someip.returncode` | 0x hex | 0x00 E_OK / 0x01 E_NOT_OK |
| `someip.messagetype.tp` / `.ack` | 1/0 | TP / Ack 标志位（布尔） |
| `someip.tp.offset` | 十进制 | Offered Length（TP 首段 32bit 低 24bit 在此呈现） |
| `someip.tp.flags.more_segments` | 1/0 | 还有后续段 |
| `someip.tp.reassembled.length` | 十进制 | TP 重组总字节数（=16+payload） |
| `someipsd.entry.type` | 0x hex | 0x00 Find / 0x01 Offer / 0x06 Subscribe / 0x07 Ack |
| `someipsd.entry.serviceid` / `instanceid` | 0x hex | entry 服务/实例 ID |
| `someipsd.entry.majorver` | 十进制 | 主版本 |
| `someipsd.entry.minorver` | 十进制 | Minor Version（32bit BE）；S5 断言 0 |
| `someipsd.entry.ttl` | 十进制 | TTL 秒（24bit）；0xFFFFFF 在 tshark/JSON 中写 16777215 |
| `someipsd.entry.eventgroupid` | 0x hex | 订阅事件组 ID |
| `someipsd.entry.counter` | 0x hex | Ack 计数器（低 4bit） |
| `someipsd.option.type` | **十进制** | 0x01 IPv4 Endpoint / 0x02 Multicast / 0x06 IPv6 Endpoint → '1'/'2'/'6' |
| `someipsd.option.ipv4address` / `ipv6address` | 点分/冒号 | 端点地址 |
| `someipsd.option.port` | 十进制 | 端点端口（30490） |
| `udp.dstport` / `udp.srcport` | 十进制 | 载体方向证明（up=12345→30490、down=30490→12345） |

**进制注意**（§2.2 细则落实）：`someip.*`、`someipsd.entry.*` 用 `0x` 串；`someipsd.option.type/port`、`someip.length/ttl` 用十进制串。

## 7. 覆盖勾选清单

> 每项对应任务强制覆盖要求与 design 场景，实现/用例提交时逐条勾选：

| 覆盖项 | 用例 | ✓ |
|--------|------|---|
| 方法调用 REQUEST→RESPONSE（Session ID 匹配） | `someip_req_resp` / `someip_req_empty` | ☐ |
| REQUEST_NO_RETURN | `someip_no_return` | ☐ |
| NOTIFICATION 事件 | `someip_multi_method_event` | ☐ |
| ERROR 返回码（0x81+RC≠0） | `someip_error` | ☐ |
| SD FindService/OfferService（ID/版本/Minor/TTL/Option 长度） | `someip_sd_find_offer` | ☐ |
| SD SubscribeEventgroup/Ack（Instance/EventgroupID/Counter/最小无 Option） | `someip_sd_subscribe` | ☐ |
| 多方法多事件 | `someip_multi_method_event` | ☐ |
| TP 分段（OfferedLength/SegmentID/more） | `someip_tp_segments` | ☐ |
| IPv4 + IPv6 双载体 | `someip_req_resp`(v4) + `someip_ipv6`(v6) | ☐ |
| IPv6 SD Endpoint Option | `someip_sd_ipv6` | ☐ |
| 多会话 | `someip_multi_session` | ☐ |
| TCP 载体双向 | `someip_tcp_swap` | ☐ |
| 负路径 expect_error（ServiceID=0 / 非法 SessionID / TP 越界 / 非法类型） | `someip_neg_service_id` / `someip_neg_session` / `someip_neg_tp` / `someip_neg_type` | ☐ |
| 双向交换响应包索引精确 | 各正向用例 packet 位逐条 | ☐ |

> 勾选结论提交时随 MCP `flowb_run_protocol_suite` 结果一起回填（每种状态 pass/fail 统计），并比对 design §7 索引表无遗漏。

---

## 8. 与 JSON 用例的一致性

### 8.1 一致性规则

1. `cases/someip.json` 是**单一事实源**，本文档 §4/§5 的 JSON 块与其逐字节一致（同 id、同 spec_json、同 expect）；本文档是描述与原理解释，JSON 是执行数据。
2. `proto` 恒 `"someip"`（驱动按文件名 `someip.json` + 此字段分派）。
3. 层链写法：`spec_json.layers = [{"udp":{}},{"someip":{}}]`（默认 UDP）或 `[{"tcp":{}},{"someip":{}}]`（S10）；`src_ip/dst_ip/src_port/dst_port` 定量明确（dst_port 30490）。
4. SD 例：报头 ServiceID/MethodID 由实现固定 0xFFFF/0x8100（design §3.4），配置只写 `sd` 子块 + `method_id: 0x8100`、`message_type: "event"`，**不写**顶层 `someip.service_id`（避免与 entry 的 ServiceID 混淆）；S5 的 `sd.options` 供生成的 OfferService 引用，FindService 仍为无 Option；FrameAssert 逐字节校验 SD 布局。
5. ExpectError 例不设 packet_count/fields（任务失败无包）。

### 8.2 与 design §7 索引对照

design §7 表"JSON id"列与本文档 §3.1 清单列的 16 个 id 完全一致；design §6 场景 ↔ testcase §4 编号 ↔ JSON id 三向可追。任何新增用例须同步三处（design 场景表 + testcase §4/§5 + JSON），并回填 §7 勾选清单。

---

## 9. 测试执行与回归

### 9.1 执行命令

```bash
# 单协议全用例（MCP 驱动套件）
CASE_PROTO=someip go test -run TestProtocolPcapDrive ./test/protocol_pcap/ -v -count=1

# 全量（防止回归）
go test -run TestProtocolPcapDrive ./test/protocol_pcap/ -v -timeout 3600s
```

### 9.2 回归策略（遵循 CLAUDE.md Testing Policy）

1. **Spec 驱动**：每条用例对应 design §6 场景/§9 规则（§7 勾选清单为证）。
2. **覆盖失败路径**：4 例负路径必须"真失败"且错误文本命中 `error_contains`；不得只断言不失败。
3. **断言可观察输出**：字段断言 + FrameAssert 双通道；`same_as_packet` 证明 SessionID/MessageID 配对。
4. **包位可观测**：UDP 单流包位确定（请求 1/响应 2）；TCP 用例包位依赖握手探测，实测偏差须按 §4.11 备注校准后回写本文档与 JSON。
5. **tshark 版本回归**：升级 tshark 后重跑 `tshark -G fields` 对照 §6 速查表字段名无变更。

### 9.3 已知断言依赖（提交前确认）

| 项 | 说明 |
|----|------|
| `someip.messageid` | 0x str；v6 下相同 |
| `someipsd.option.type` | 十进制；不随版本变 |
| `someip.tp` 重组 | 3.6 上 `reassembled.length` 在 TP 首段收敛——若 tshark 升级后字段缺席，回退断 `someip.tp.reassembled.data`/`nonzero` |
| TCP 包位 | 见 §4.11 |

> 三件套（design §7 索引 / testcase 文档 / cases JSON）互为倒影，交付时以 MCP 套件实际 pass 数回填 §7。S9b 的 IPv6 SD Option 与 S5 的 IPv4 Option 是两个独立原子行为。修订记录见下表。

---

## 10. 修订记录

| 版本 | 日期 | 内容 |
|------|------|------|
| v1.1.0 | 2026-08-20 | 修正 S5 FrameAssert/Length/Entry/Option 字节核算；S8 改为 JSON 显式 2500B payload；明确 S6 Ack 无 Option 的规范边界；新增独立 S9b IPv6 SD Option；补齐 SD outer serviceid、minorver、instanceid、TTL 进制及 TCP 包位限制 |
| v1.0.0 | 2026-08-18 | 初稿：完整 9 章；12 用例（8 正 + 4 负）；tshark 3.6.14 字段集核实（someip.* / someipsd.* / someip.tp.*）；SD/TP 布局依据 28-someip-design.md §3.4/§3.5；负路径 enumerate（V1/V2/V3/V5）；覆盖勾选清单 §7；JSON 一致性规则 §8 |
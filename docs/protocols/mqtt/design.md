# MQTT 协议设计与测试用例

**版本**：v2.0.2
**生成时间**：2026-08-05
**规范来源**：MQTT 3.1.1（OASIS Standard 2014，等价 ISO/IEC 20922:2016）；MQTT 5.0（OASIS Standard 2018，RFC 9560 信息参考）
**传输层**：TCP（默认端口 1883 明文，8883 TLS）
**扩展表节点**：`mqttProtRpt`（见 `docs/protocol-designs/00-unimplemented-list.md` 第 14 项）
**优先级**：P0（IoT 最常见，未实现清单首要推荐）

本文档遵循 `CLAUDE.md` 第 8 条测试策略，所有测试用例均从规范章节 + Config 字段表派生，覆盖正向 / 负向 / 边界三类，每条用例独立且失败优先。

---

## §1. 协议概述

### 1.1 规范来源与版本

| 版本 | 规范 | 关键差异 |
|------|------|----------|
| 3.1.1 | OASIS Standard 2014 / ISO 20922:2016 | 当前最广泛部署版本，无 Properties（属性）/Reason Code（原因码）字段，CONNECTION 返回码仅 0-5 |
| 5.0 | OASIS Standard 2018 / RFC 9560 信息参考 | 新增 Reason Code（原因码，扩展到 0x80-0xA2）、Properties（属性，28 个 Property Identifier）、Topic Alias（主题别名）、Shared Subscriptions（共享订阅）、Will Delay（遗嘱延迟）、AUTH 包（增强认证）、NoLocal/RetainAsPublished/RetainHandling 订阅选项 |

trafficgen 同时支持 3.1.1 与 5.0，由 `MQTTConfig.Version` 选择，默认 4（=3.1.1，CONNECT 协议名 `MQTT`、级别 4）；5 使用 CONNECT 级别 5 并启用 Properties 编码。

### 1.2 业务场景

MQTT（Message Queuing Telemetry Transport，消息队列遥测传输）是发布/订阅模式的轻量级消息协议，主要用于 IoT（物联网）设备到云端、云端到设备的双向消息通道：

- **传感数据上报**：设备作为 publisher（发布者）周期性 PUBLISH（发布）传感器读数到主题 `sensor/temp`、`sensor/humid`。
- **下行控制**：云端作为 publisher 向 `device/cmd` 发布控制指令，设备订阅该主题接收。
- **遗嘱消息**（LWT，Last Will and Testament）：设备 CONNECT 时携带 Will Message（遗嘱消息），异常断线时由 broker（代理服务器）代为发布到 will topic，使其他订阅者感知设备离线。
- **保留消息**（Retained Message）：PUBLISH 置 Retain=1（保留标志），broker 缓存最近一条，新订阅者订阅该主题时立即收到。
- **多客户端并发**：N 个设备同时建立独立 TCP 连接，每个连接独立 4-tuple、独立 client_id（客户端标识）。
- **keepalive（保活）**：连接空闲超过 keepalive（保活间隔）时，客户端发 PINGREQ（心跳请求），broker 回 PINGRESP（心跳响应）维持连接。

### 1.3 与本项目已实现协议的关系

| 已实现协议 | 共性 | 差异 |
|------------|------|------|
| SOCKS5 | TCP 流、固定信令阶段、TCP 握手+挥手框架 | SOCKS 是代理协议，MQTT 是发布订阅；MQTT 有 QoS 0/1/2 三档可靠级别 |
| RADIUS | 请求/响应同 4-tuple 多轮 | RADIUS 走 UDP，MQTT 走 TCP 长连接 |
| LDAP | 多轮 bind/search/unbind | LDAP 是查询协议，MQTT 是消息推送 |
| SIP/RTSP | TCP 对话+独立 RTP/UDP 数据面 | MQTT 数据面（PUBLISH）就在同一 TCP 流内，无独立子流 |

### 1.4 不实现的范围

- **WebSocket 传输**（MQTT over WS，端口 9001）：本项目暂不混入 WebSocket 层。
- **TLS 8883**：由 `internal/protocol/tls` 独立处理，MQTT planner 仅生成明文 1883 流。
- **MQTT-SN（传感器网络版）**：基于 UDP 的精简变体，不在本次范围。
- **真实 broker 行为模拟**：trafficgen 是流量生成器，不发真正的 broker 转发逻辑；will/retain 场景由 planner 直接编排为"客户端断线 → broker 发 will PUBLISH"的字节序列。
- **AUTH 包（5.0 Enhanced Authentication）**：MQTTConfig 无对应字段产生 AUTH 包，本期不实现。§2.2/§10.1 列出 AUTH 仅作规范完整性参考，planner 不产出。
- **UNSUBSCRIBE/UNSUBACK**：本期不强制实现，§5.3 不列 `buildUnsubscribe` 函数。§8.1 清单不要求 UNSUBSCRIBE flags 校验。

---

## §2. 数据类型与编码

### 2.1 固定头部（Fixed Header）

```
  7 6 5 4 3 2 1 0
 +-+-+-+-+-+-+-+-+
 | Type  | Flags |
 +-+-+-+-+-+-+-+-+
 | Remaining Len |  (1-4 字节, Variable Byte Integer)
 |     ...       |
 +-+-+-+-+-+-+-+-+
```

- **Byte 1 高 4 位 Type**：包类型码（见 §2.2）。
- **Byte 1 低 4 位 Flags**：每类型固定值（见 §2.2），3.1.1 中部分位必须为 0，5.0 中保留位必须为 0。
- **Byte 2-5 Remaining Length**：Variable Byte Integer（可变字节整数，见 §2.3），编码剩余字节数（不含固定头本身）。

固定头第一字节 = `(Type << 4) | Flags`。例如：
- CONNECT = `0x10`
- CONNACK = `0x20`
- PUBLISH QoS1 Retain = `0x33`（Type=3, DUP=0, QoS=01, Retain=1）
- PUBREL = `0x62`（Type=6, flags=0010）
- DISCONNECT = `0xE0`
- AUTH (5.0) = `0xF0`（本期不实现）

### 2.2 包类型码表

| 类型 | Code | Flags（低 4 位） | 方向 | 说明 |
|------|------|------------------|------|------|
| Reserved | 0 | 0 | — | 禁用 |
| CONNECT | 1 | 0 | C→S | 客户端连接请求 |
| CONNACK | 2 | 0 | S→C | 连接确认 |
| PUBLISH | 3 | DUP1 QoS1 QoS0 Retain | 双向 | 发布消息，flags 由用户控制 |
| PUBACK | 4 | 0 | 双向 | QoS 1 收到确认 |
| PUBREC | 5 | 0 | 双向 | QoS 2 收到确认（第一轮） |
| PUBREL | 6 | 0 0 1 0 | 双向 | QoS 2 释放（第二轮，flags 固定 0x02） |
| PUBCOMP | 7 | 0 | 双向 | QoS 2 完成（第三轮） |
| SUBSCRIBE | 8 | 0 0 1 0 | C→S | 订阅请求，flags 固定 0x02 |
| SUBACK | 9 | 0 | S→C | 订阅确认 |
| UNSUBSCRIBE | 10 | 0 0 1 0 | C→S | 取消订阅，flags 固定 0x02 |
| UNSUBACK | 11 | 0 | S→C | 取消订阅确认 |
| PINGREQ | 12 | 0 | C→S | 心跳请求 |
| PINGRESP | 13 | 0 | S→C | 心跳响应 |
| DISCONNECT | 14 | 0 | 3.1.1: C→S; 5.0: 双向 | 主动断开（3.1.1 §3.14.1：仅客户端→服务端；5.0 §3.14.1：双向） |
| AUTH | 15 | 0 | 双向 | MQTT 5.0 认证交换（本期不实现，仅作规范参考）；3.1.1 禁用 |

### 2.3 Variable Byte Integer（剩余长度编码 / VBI）

每字节低 7 位为有效位，最高位为 continuation bit（续位标记）。1-4 字节可表示 0 至 268,435,455（约 256MB）：

| 字节数 | 编码范围 | 示例 |
|--------|----------|------|
| 1 | 0 - 127 | `0x00`、`0x7F` |
| 2 | 128 - 16,383 | `0x80 0x01` = 128 |
| 3 | 16,384 - 2,097,151 | `0x80 0x80 0x01` = 16,384 |
| 4 | 2,097,152 - 268,435,455 | `0x80 0x80 0x80 0x01` = 2,097,152 |

**编码算法**（MQTT 3.1.1 §2.2.3 / MQTT 5.0 §1.5.5）：
```
do {
  encodedByte = X MOD 128
  X = X DIV 128
  if X > 0: encodedByte = encodedByte OR 128
  output(encodedByte)
} while X > 0
```

**解码算法**：
```
multiplier = 1
value = 0
do {
  encodedByte = next byte
  value += (encodedByte AND 127) * multiplier
  if multiplier > 128*128*128:
    throw Error(Malformed Variable Byte Integer)
  multiplier *= 128
} while (encodedByte AND 128) != 0
```

**最小编码原则**（5.0 §1.5.5）：编码值必须使用最小字节数。如 128 必须编码为 `0x80 0x01`，不能为 `0x80 0x00`（值 0 用 2 字节）或 `0x80 0x80 0x01`（值 128 用 3 字节）。违反 = Malformed Packet。

**边界用例必覆盖**（见 §6 场景 / §7.10）：剩余长度 0、127、128、16383、16384、2097151、2097152。

### 2.4 数据类型汇总

MQTT 规范定义的六种数据类型（5.0 §1.5）：

| 类型 | 长度 | 编码 | 用途示例 |
|------|------|------|---------|
| Binary Data | 2 字节长度前缀 + N 字节 | 大端长度 | Will Payload、Password、Correlation Data |
| Bit | 1 位 | 单独位 | Connect Flags 各位 |
| Two Byte Integer | 2 字节 | 大端 | Keep Alive、Packet ID、Topic Alias、Server Keep Alive |
| Four Byte Integer | 4 字节 | 大端 | Session Expiry Interval、Message Expiry Interval、Will Delay Interval |
| UTF-8 Encoded String | 2 字节长度前缀 + UTF-8 字节 | 大端长度 | Protocol Name、ClientID、Topic Name、Username、Content Type |
| UTF-8 String Pair | 2 字节长度前缀键 + 2 字节长度前缀值 | 双字符串 | User Property |

**UTF-8 字符串禁止**（3.1.1 §1.5.3 / 5.0 §1.5.4.1）：
- 不得包含 U+0000（空字符）。
- 不得包含 UTF-16 代理区字符（U+D800-U+DFFF）。
- 长度字段为 2 字节大端无符号整数，**合法范围 0-65535（0xFFFF）全范围，无保留值**；字符串最大 65,535 字节（5.0 §1.5.4："the maximum size of a UTF-8 Encoded String is 65,535 bytes"，3.1.1 §1.5.3 同）。超过 65535 字节 → 无法编码，Validate 报错。

**Binary Data 长度**：2 字节长度前缀，最大 65535 字节。

### 2.5 CONNECT 报文（Variable Header + Payload）

```
Variable Header (3.1.1: 10 字节; 5.0: 10 字节 + Properties):
  Protocol Name Length (2) | "MQTT" (4) | Protocol Level (1) | Connect Flags (1) | Keep Alive (2)
  [5.0: Properties Length (VBI) + Properties]
Connect Flags 位:
  bit7 Username | bit6 Password | bit5 Will Retain | bit4-3 Will QoS | bit2 Will Flag | bit1 Clean Session/Clean Start | bit0 Reserved(0)
Payload (按顺序，存在性由 Connect Flags 决定):
  Client Identifier (2-len + bytes)
  [Will Properties Length (VBI, 5.0, if Will Flag=1, 必填——即使无属性也写 0x00)]
  Will Topic (2-len + bytes, if Will Flag)
  Will Payload (2-len + bytes, if Will Flag)
  Username (2-len + bytes, if bit7)
  Password (2-len + bytes, if bit6)
```

**3.1.1 与 5.0 字段差异**：
- Protocol Level：3.1.1 = 4（`0x04`），5.0 = 5（`0x05`）。
- 5.0 在 Keep Alive 后多一段 Properties（属性，见 §2.14），包含 Session Expiry Interval、Will Delay Interval、Topic Alias Maximum 等新字段。
- 3.1.1 的 Connect Flags bit1 叫 Clean Session；5.0 叫 Clean Start（语义类似但配合 Session Expiry Interval 更灵活）。
- 5.0 允许 Password Flag=1 而 Username Flag=0（无 Username 仅 Password），3.1.1 要求 Username Flag=0 时 Password Flag 必须 0。

**Connect Flags 位布局**（bit7 在最高位）：

| Bit | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
|-----|---|---|---|---|---|---|---|---|
| 字段 | User Name Flag | Password Flag | Will Retain | Will QoS (MSB) | Will QoS (LSB) | Will Flag | Clean Session/Clean Start | Reserved |

Will QoS 取值：00=QoS0、01=QoS1、10=QoS2、11=Malformed（5.0 §3.1.2.3：值为 3 是 Protocol Error）。

### 2.6 CONNACK 报文

```
3.1.1 Variable Header (2 字节):
  Session Present (1, bit0=SP, bit1-7=0) | Return Code (1)
5.0 Variable Header (3+ 字节):
  Connect Acknowledge Flags (1, bit0=Session Present, bit1-7=0) | Reason Code (1) | Properties Length (VBI) + Properties
```

无 Payload。

**3.1.1 Return Code 表**（仅 0-5 有效，6-255 保留）：

| Code | 含义 |
|------|------|
| 0x00 | Connection Accepted（接受） |
| 0x01 | Refused: unacceptable protocol version（不可接受的协议版本） |
| 0x02 | Refused: identifier rejected（标识符被拒绝） |
| 0x03 | Refused: server unavailable（服务端不可用） |
| 0x04 | Refused: bad user name or password（用户名/密码错误） |
| 0x05 | Refused: not authorized（未授权） |

**5.0 CONNACK Reason Code 表**（5.0 §2.4 Table 2-6 中适用 CONNACK 的代码；3.1.1 的 1-5 在 5.0 中**不**是有效 CONNACK 代码）：

| Code | Hex | 含义 |
|------|-----|------|
| 0 | 0x00 | Success（成功） |
| 128 | 0x80 | Unspecified error（未指定错误） |
| 129 | 0x81 | Malformed Packet（畸形包） |
| 130 | 0x82 | Protocol Error（协议错误） |
| 131 | 0x83 | Implementation specific error（实现特定错误） |
| 132 | 0x84 | Unsupported Protocol Version（不支持的协议版本） |
| 133 | 0x85 | Client Identifier not valid（客户端标识符无效） |
| 134 | 0x86 | Bad User Name or Password（用户名或密码错误） |
| 135 | 0x87 | Not authorized（未授权） |
| 136 | 0x88 | Server unavailable（服务端不可用） |
| 137 | 0x89 | Server busy（服务端繁忙） |
| 138 | 0x8A | Banned（被禁） |
| 140 | 0x8C | Bad authentication method（认证方法错误） |
| 144 | 0x90 | Topic Name invalid（主题名无效） |
| 149 | 0x95 | Packet too large（包过大） |
| 151 | 0x97 | Quota exceeded（超出配额） |
| 153 | 0x99 | Payload format invalid（负载格式无效） |
| 154 | 0x9A | Retain not supported（不支持保留） |
| 155 | 0x9B | QoS not supported（不支持 QoS） |
| 156 | 0x9C | Use another server（使用其他服务器） |
| 157 | 0x9D | Server moved（服务器迁移） |
| 159 | 0x9F | Connection rate exceeded（连接速率超限） |

**重要**：148（0x94, Topic Alias invalid）**仅适用于 DISCONNECT**，**不适用于 CONNACK**。141（0x8D, Keep Alive timeout）也仅适用于 DISCONNECT。本表已严格按 5.0 §2.4 过滤。

**Session Present 互斥**（3.1.1 §3.2.2.1 / 5.0 §3.2.2.2）：
- CleanSession=1 / CleanStart=1 → Session Present 必须 0。
- Return/Reason Code ≠ 0 → Session Present 必须 0。
- 违反 → 客户端必须断连。

### 2.7 PUBLISH 报文

```
Variable Header:
  Topic Name (2-len + bytes)
  [Packet Identifier (2), only if QoS > 0]
  [5.0: Properties Length (VBI) + Properties]
Payload:
  Application message bytes (0 to N)
```

固定头 flags：
- **DUP（bit3）**：1 = 重发。仅 QoS>0 有效，QoS0 必须 0。
- **QoS（bit2-1）**：00=QoS0，01=QoS1，10=QoS2，11=Malformed（接受方必须断连）。
- **Retain（bit0）**：1 = broker 缓存此消息。

**PUBLISH Topic Name 禁通配符**（3.1.1 §4.7.1 / 5.0 §3.3.2.1）：不得包含 `#` 或 `+`（仅 SUBSCRIBE filter 允许）。违反 = Protocol Error。

**Topic Name 长度字段**：2 字节大端，合法范围 0-65535（0xFFFF）全范围（与 §2.4 UTF-8 字符串上限一致），无保留值。

**Payload 长度** = Remaining Length - Variable Header 长度。Payload 可为 0 字节（合法）。

### 2.8 QoS 1 流程

```
上行（client→server, client publishes）:
Client                  Server
  |--- PUBLISH (QoS1, PacketID=X) --->|
  |<-------- PUBACK (PacketID=X) ------|

下行（server→client, server publishes to subscriber）:
Server                  Client
  |--- PUBLISH (QoS1, PacketID=X) --->|
  |<-------- PUBACK (PacketID=X) ------|
```

一个 PUBLISH + 一个 PUBACK，2 字节 Packet ID 在两包中一致。PUBACK 固定头 = `0x40`，Remaining Length = 2（3.1.1）/ 2 + Properties（5.0）。

**方向矩阵**：上行 PUBLISH=up/PUBACK=down；下行 PUBLISH=down/PUBACK=up（ack 方向翻转）。

### 2.9 QoS 2 流程

```
上行（client→server, client publishes）:
Client                  Server
  |--- PUBLISH (QoS2, PacketID=X) --->|
  |<-------- PUBREC (PacketID=X) ------|
  |--- PUBREL (PacketID=X, 0x62) ---->|
  |<-------- PUBCOMP (PacketID=X) -----|

下行（server→client, server publishes to subscriber）:
Server                  Client
  |--- PUBLISH (QoS2, PacketID=X) --->|
  |<-------- PUBREC (PacketID=X) ------|
  |--- PUBREL (PacketID=X, 0x62) ---->|
  |<-------- PUBCOMP (PacketID=X) -----|
```

四包交换，每个都携带相同 Packet ID。PUBREL 固定头 flags=0x02（其他类型必须为 0）。**方向矩阵**：

| 步骤 | 上行方向 | 下行方向 |
|------|---------|---------|
| PUBLISH | up | down |
| PUBREC | down | up |
| PUBREL | up | down |
| PUBCOMP | down | up |

下行的 ack 链方向与上行的差异：PUBREC/PUBCOMP 由 server 发（down→up），PUBREL 由 client 发（up→down）——中段方向翻转。planner 按此矩阵生成每包方向。

**PUBREC/PUBREL/PUBCOMP 字节**（3.1.1，无 Properties）：
- PUBREC = `0x50 0x02 <PacketID 高> <PacketID 低>`
- PUBREL = `0x62 0x02 <PacketID 高> <PacketID 低>`（flags=0x02 强制）
- PUBCOMP = `0x70 0x02 <PacketID 高> <PacketID 低>`

### 2.10 SUBSCRIBE / SUBACK

```
SUBSCRIBE Variable Header:
  Packet Identifier (2)
  [5.0: Properties Length (VBI) + Properties]
SUBSCRIBE Payload (按订阅项重复):
  Topic Filter (2-len + bytes) | Subscription Options (1)
    Options bits (5.0):
      bit0-1 QoS | bit2 NoLocal | bit3 RetainAsPublished | bit4-5 RetainHandling | bit6-7 Reserved(0)
    (3.1.1: 仅 bit0-1 QoS 有效，bit2-7 必须 0)
SUBACK Variable Header:
  Packet Identifier (2)
  [5.0: Properties Length (VBI) + Properties]
SUBACK Payload:
  Reason Code per filter (1 byte each)
    3.1.1: 0x00=QoS0 granted | 0x01=QoS1 | 0x02=QoS2 | 0x80=Failure
    5.0:   同 3.1.1 + 0x83=Implementation error | 0x87=Not authorized | 0x8F=Topic Filter invalid |
           0x91=Packet Identifier in use | 0x97=Quota exceeded | 0x9E=Shared Sub not supported |
           0xA1=Sub ID not supported | 0xA2=Wildcard Sub not supported
           （完整 11 项：0x00/0x01/0x02/0x80/0x83/0x87/0x8F/0x91/0x97/0x9E/0xA1/0xA2，5.0 §3.9.3 Table 3-8）
```

SUBSCRIBE 固定头 = `0x82`（flags=0x02 强制）。SUBACK 固定头 = `0x90`。

**通配符（Topic Filter）**：
- `+`：单层通配符，匹配一层。
- `#`：多层通配符，必须在末尾，匹配任意层。
- `sport/+/score` 匹配 `sport/tennis/score`、`sport/cricket/score`，不匹配 `sport/score`。
- `#` 单独匹配除 `$` 开头外的所有主题（3.1.1 §4.7.2：通配符 filter 不匹配 `$` 开头 topic，如 `$SYS/...`）；`sport/#` 匹配 `sport/`、`sport/x`、`sport/x/y`。
- **Shared Subscriptions（5.0 §4.8.2）**：`$share/{group}/{filter}` 形式，`{group}` 不能含 `/`、`+`、`#`；`{filter}` 必须至少一层（即 `$share/g` 非法——缺少 filter 部分）。3.1.1 不支持。

**Subscription Options（5.0）**：
- **NoLocal（bit2）**：1 = 不回送给发布者自己（防回声）。仅 5.0；3.1.1 必须 0。
- **RetainAsPublished（bit3）**：1 = 转发时保留 RETAIN 位原值；0 = 转发时清零 RETAIN。
- **RetainHandling（bit4-5）**：00=每次订阅都发 retained；01=仅新订阅发；10=从不发；11=Reserved（Protocol Error）。

### 2.11 UNSUBSCRIBE / UNSUBACK

结构与 SUBSCRIBE/SUBACK 类似，payload 是 Topic Filter 列表（无 Options 字节），UNSUBACK payload（5.0）是每个 filter 一个 Reason Code。

固定头：UNSUBSCRIBE = `0xA2`（flags=0x02），UNSUBACK = `0xB0`。本期不实现（见 §1.4）。

### 2.12 PINGREQ / PINGRESP / DISCONNECT

| 类型 | Variable Header | Payload | 字节 |
|------|-----------------|---------|------|
| PINGREQ | 无 | 无 | `0xC0 0x00` |
| PINGRESP | 无 | 无 | `0xD0 0x00` |
| DISCONNECT 3.1.1 | 无 | 无 | `0xE0 0x00` |
| DISCONNECT 5.0 | Reason Code (1) + Properties | 无 | `0xE0 0x02 <Reason> <PropertiesLen>` 或更长 |

**DISCONNECT 5.0 字节**（无属性时）：`0xE0 0x02 0x00 0x00`（Reason Code=0=Normal disconnection，Properties Length=0）。**Properties Length 是必填字段**（5.0 §3.14.2.2），可为 0，不可省略。

**DISCONNECT 5.0 Reason Code 表**（5.0 §2.4 适用 DISCONNECT 的代码）：

| Code | Hex | 含义 |
|------|-----|------|
| 0 | 0x00 | Normal disconnection（正常断开） |
| 4 | 0x04 | Disconnect with Will Message（带遗嘱断开） |
| 128 | 0x80 | Unspecified error |
| 129 | 0x81 | Malformed Packet |
| 130 | 0x82 | Protocol Error |
| 131 | 0x83 | Implementation specific error |
| 135 | 0x87 | Not authorized |
| 137 | 0x89 | Server busy |
| 139 | 0x8B | Server shutting down |
| 140 | 0x8C | Bad authentication method |
| 141 | 0x8D | Keep Alive timeout |
| 142 | 0x8E | Session taken over |
| 143 | 0x8F | Topic Filter invalid |
| 144 | 0x90 | Topic Name invalid |
| 147 | 0x93 | Receive Maximum exceeded |
| 148 | 0x94 | Topic Alias invalid（仅 DISCONNECT） |
| 149 | 0x95 | Packet too large |
| 150 | 0x96 | Message rate too high |
| 151 | 0x97 | Quota exceeded |
| 152 | 0x98 | Administrative action |
| 153 | 0x99 | Payload format invalid |
| 154 | 0x9A | Retain not supported |
| 155 | 0x9B | QoS not supported |
| 156 | 0x9C | Use another server |
| 157 | 0x9D | Server moved |
| 158 | 0x9E | Shared Subscriptions not supported |
| 159 | 0x9F | Connection rate exceeded |
| 160 | 0xA0 | Maximum connect time |
| 161 | 0xA1 | Subscription Identifiers not supported |
| 162 | 0xA2 | Wildcard Subscriptions not supported |

### 2.13 AUTH 包（5.0，本期不实现）

固定头 = `0xF0`（type=15, flags=0）。Variable Header = Reason Code (1) + Properties。Reason Codes: 0x00=Success、0x18=Continue authentication、0x19=Re-authenticate、0x80=Unspecified error、0x97=Quota exceeded。仅 5.0 支持，3.1.1 禁用。planner 不产出 AUTH 包。

### 2.14 MQTT 5.0 Properties（属性）格式

每包的 Properties 段以 VBI 长度前缀开始，后接 0 至 N 个 Property 条目：

```
Properties 段: Properties Length (VBI) + Property entries
Property entry: Identifier (VBI) + Value (type-dependent)
```

**Properties Length VBI 不含自身**：编码的是后续 Property entries 字节数，不含 VBI 自身字节数。

**Properties Length 必填**：5.0 中即使无属性也必须写 `0x00` 长度字节，不可省略该段（5.0 §2.2.2.1）。

**完整 Property Identifier 表**（5.0 §2.2.2.2 Table 2-4）：

| Dec | Hex | 名称 | 类型 | 适用包 |
|-----|-----|------|------|--------|
| 1 | 0x01 | Payload Format Indicator | Byte | PUBLISH, Will Properties |
| 2 | 0x02 | Message Expiry Interval | Four Byte Integer | PUBLISH, Will Properties |
| 3 | 0x03 | Content Type | UTF-8 Encoded String | PUBLISH, Will Properties |
| 8 | 0x08 | Response Topic | UTF-8 Encoded String | PUBLISH, Will Properties |
| 9 | 0x09 | Correlation Data | Binary Data | PUBLISH, Will Properties |
| 11 | 0x0B | Subscription Identifier | Variable Byte Integer | SUBSCRIBE；down PUBLISH（broker→client 转发时，可重复，多订阅匹配 §3.3.2.3.8）；**禁止 up PUBLISH**（[MQTT-3.3.4-6]） |
| 17 | 0x11 | Session Expiry Interval | Four Byte Integer | CONNECT, CONNACK, DISCONNECT |
| 18 | 0x12 | Assigned Client Identifier | UTF-8 Encoded String | CONNACK |
| 19 | 0x13 | Server Keep Alive | Two Byte Integer | CONNACK |
| 21 | 0x15 | Authentication Method | UTF-8 Encoded String | CONNECT, CONNACK, AUTH |
| 22 | 0x16 | Authentication Data | Binary Data | CONNECT, CONNACK, AUTH |
| 23 | 0x17 | Request Problem Information | Byte | CONNECT |
| 24 | 0x18 | Will Delay Interval | Four Byte Integer | Will Properties（**不是 0x1A**） |
| 25 | 0x19 | Request Response Information | Byte | CONNECT |
| 26 | 0x1A | Response Information | UTF-8 Encoded String | CONNACK |
| 28 | 0x1C | Server Reference | UTF-8 Encoded String | CONNACK, DISCONNECT |
| 31 | 0x1F | Reason String | UTF-8 Encoded String | CONNACK, PUBACK, PUBREC, PUBREL, PUBCOMP, SUBACK, UNSUBACK, DISCONNECT, AUTH |
| 33 | 0x21 | Receive Maximum | Two Byte Integer | CONNECT, CONNACK |
| 34 | 0x22 | Topic Alias Maximum | Two Byte Integer | CONNECT, CONNACK |
| 35 | 0x23 | Topic Alias | Two Byte Integer | PUBLISH |
| 36 | 0x24 | Maximum QoS | Byte | CONNACK |
| 37 | 0x25 | Retain Available | Byte | CONNACK |
| 38 | 0x26 | User Property | UTF-8 String Pair | 所有包（可重复） |
| 39 | 0x27 | Maximum Packet Size | Four Byte Integer | CONNECT, CONNACK |
| 40 | 0x28 | Wildcard Subscription Available | Byte | CONNACK |
| 41 | 0x29 | Subscription Identifier Available | Byte | CONNACK |
| 42 | 0x2A | Shared Subscription Available | Byte | CONNACK |

**重要修正**（v2.0.0）：
- 0x18（24）= **Will Delay Interval**（Four Byte Integer，Will Properties），**不是 0x1A**。
- 0x1A（26）= Response Information（UTF-8 String，CONNACK）。
- 0x15（21）= **Authentication Method**（不是 Topic Alias Maximum）。
- 0x19（25）= **Request Response Information**（不是 Server Keep Alive）。
- 0x13（19）= Server Keep Alive。
- 0x21（33）= **Receive Maximum**（不是 Reason String）。
- 0x1F（31）= Reason String。
- 0x22（34）= Topic Alias Maximum。

**Property 重复规则**：除 User Property（0x26，可重复）外，同包内同 ID 不得重复 → Malformed Packet。**例外**：Subscription Identifier（0x0B）仅在下行 PUBLISH（broker→client 转发）中可重复——当一条 PUBLISH 命中多个订阅时，broker 会携带多个 Sub ID 转发（5.0 §3.3.2.3.8）；SUBSCRIBE 中的 0x0B **不得重复**（5.0 §3.8.2.1.2："It is a Protocol Error to include the Subscription Identifier more than once"）。

**Property × 包类型白名单**：每个 ID 只能在"适用包"列的包型中出现。不匹配 = Malformed Packet。例如：
- Session Expiry 0x11 仅 CONNECT/CONNACK/DISCONNECT。
- Topic Alias 0x23 仅 PUBLISH。
- Will Delay Interval 0x18 仅 Will Properties（CONNECT payload 内）。

---

## §3. 消息结构（各 Packet Type 逐包字节构造）

### 3.1 CONNECT 字节构造

**3.1.1 CONNECT 字节布局**（无 Properties）：
```
固定头: 0x10 <Remaining Length VBI>
Variable Header (10 字节):
  00 04 4d 51 54 54        Protocol Name "MQTT"
  04                        Protocol Level 4
  <Connect Flags 1 字节>    见 §2.5 位布局
  <Keep Alive 2 字节 大端>
Payload:
  <ClientID 2-len + bytes>
  [Will Topic 2-len + bytes, if Will Flag]
  [Will Payload 2-len + bytes, if Will Flag]
  [Username 2-len + bytes, if Username Flag]
  [Password 2-len + bytes, if Password Flag]
```

**5.0 CONNECT 字节布局**（含 Properties）：
```
固定头: 0x10 <Remaining Length VBI>
Variable Header (10 字节 + Properties):
  00 04 4d 51 54 54        Protocol Name "MQTT"
  05                        Protocol Level 5
  <Connect Flags 1 字节>
  <Keep Alive 2 字节 大端>
  <Properties Length VBI>
  <Property entries>
Payload:
  <ClientID 2-len + bytes>
  [Will Properties Length VBI, if Will Flag]    ← 必填，无属性也写 0x00
  [Will Property entries, if Will Flag]
  [Will Topic 2-len + bytes, if Will Flag]
  [Will Payload 2-len + bytes, if Will Flag]
  [Username 2-len + bytes, if Username Flag]
  [Password 2-len + bytes, if Password Flag]
```

**Remaining Length 计算**：= Variable Header 字节数 + Properties 段字节数（含 VBI）+ Payload 字节数。

**Connect Flags 计算**：
```
ConnectFlags = 0
if Username != "": ConnectFlags |= 0x80
if Password != "": ConnectFlags |= 0x40
if Will != nil:
    ConnectFlags |= 0x04                          // Will Flag
    ConnectFlags |= (Will.QoS & 0x03) << 3        // Will QoS bits 4-3
    if Will.Retain: ConnectFlags |= 0x20           // Will Retain bit 5
if CleanSession (or CleanStart): ConnectFlags |= 0x02
// bit0 Reserved 永远 0
```

### 3.2 CONNACK 字节构造

**3.1.1 CONNACK**（4 字节）：
```
20 <Remaining Length=0x02> <Session Present 1 字节> <Return Code 1 字节>
```
- Session Present 字节：bit0=SP，bit1-7=0（即 0x00 或 0x01）。
- 示例：成功 + 无 session = `20 02 00 00`；成功 + session 存在 = `20 02 01 00`；拒绝 code=5 = `20 02 00 05`。

**5.0 CONNACK**（无属性时 4 字节）：
```
20 03 <Session Present 1 字节> <Reason Code 1 字节> <Properties Length=0x00>
```
- 示例：成功 + 无 session + 无属性 = `20 03 00 00 00`。
- 有属性时：`20 <Remaining Length> <SP> <Reason> <Properties Length VBI> <Properties...>`。

### 3.3 PUBLISH 字节构造

**3.1.1 PUBLISH**：
```
固定头: <0x30 | DUP<<3 | QoS<<1 | Retain> <Remaining Length VBI>
Variable Header:
  <Topic Name 2-len + bytes>
  [Packet ID 2 字节 大端, if QoS > 0]
Payload:
  <Application Message bytes>
```

**5.0 PUBLISH**（含 Properties）：
```
固定头: <0x30 | DUP<<3 | QoS<<1 | Retain> <Remaining Length VBI>
Variable Header:
  <Topic Name 2-len + bytes>
  [Packet ID 2 字节 大端, if QoS > 0]
  <Properties Length VBI>
  <Property entries>
Payload:
  <Application Message bytes>
```

**第一字节计算**：
```
firstByte = 0x30
if DUP: firstByte |= 0x08
firstByte |= (QoS & 0x03) << 1
if Retain: firstByte |= 0x01
```

**示例**：
- QoS0, DUP=0, Retain=0 → `0x30`
- QoS1, DUP=0, Retain=0 → `0x32`
- QoS1, DUP=0, Retain=1 → `0x33`
- QoS2, DUP=1, Retain=1 → `0x3D`（0011 1101）
- QoS0, DUP=1, Retain=0 → 非法（QoS0 + DUP=1）

### 3.4 PUBACK / PUBREC / PUBREL / PUBCOMP 字节构造

**3.1.1**（每包 4 字节）：
```
PUBACK:  40 02 <PacketID 高> <PacketID 低>
PUBREC:  50 02 <PacketID 高> <PacketID 低>
PUBREL:  62 02 <PacketID 高> <PacketID 低>    ← flags=0x02 强制
PUBCOMP: 70 02 <PacketID 高> <PacketID 低>
```

**5.0**（无属性时 5 字节，含 Reason Code + Properties Length=0）：
```
PUBACK:  40 03 <PacketID 高> <PacketID 低> <Reason Code> <Properties Length=0x00>
PUBREC:  50 03 <PacketID 高> <PacketID 低> <Reason Code> <Properties Length=0x00>
PUBREL:  62 03 <PacketID 高> <PacketID 低> <Reason Code> <Properties Length=0x00>
PUBCOMP: 70 03 <PacketID 高> <PacketID 低> <Reason Code> <Properties Length=0x00>
```

Reason Code 默认 0x00（Success）。PUBREL flags=0x02 强制（5.0 亦然）。

### 3.5 SUBSCRIBE / SUBACK 字节构造

**3.1.1 SUBSCRIBE**：
```
固定头: 82 <Remaining Length VBI>
Variable Header:
  <Packet ID 2 字节 大端>
Payload (按 filter 重复):
  <Topic Filter 2-len + bytes>
  <Requested QoS 1 字节>          ← 3.1.1 仅 bit0-1 有效，bit2-7=0
```

**5.0 SUBSCRIBE**（含 Properties）：
```
固定头: 82 <Remaining Length VBI>
Variable Header:
  <Packet ID 2 字节 大端>
  <Properties Length VBI>
  <Property entries>
Payload (按 filter 重复):
  <Topic Filter 2-len + bytes>
  <Subscription Options 1 字节>   ← bit0-1 QoS | bit2 NoLocal | bit3 RAP | bit4-5 RH | bit6-7=0
```

**SUBACK**：
```
固定头: 90 <Remaining Length VBI>
Variable Header:
  <Packet ID 2 字节 大端>
  [5.0: Properties Length VBI + Properties]
Payload:
  <Reason Code 1 字节> × N        ← 每个 filter 一个
```

### 3.6 PINGREQ / PINGRESP / DISCONNECT 字节构造

```
PINGREQ:        C0 00
PINGRESP:       D0 00
DISCONNECT 3.1.1: E0 00
DISCONNECT 5.0 (无属性): E0 02 00 00      ← Reason=0, PropertiesLen=0
DISCONNECT 5.0 (带 Reason=0x04 Will): E0 02 04 00
```

### 3.7 Property 编码字节示例

**Property Identifier 编码**：VBI（通常 1 字节，ID ≤ 127）。

**Value 编码按类型**：
- **Byte**（如 0x01 Payload Format Indicator）：1 字节。例：`01 01` = ID 0x01 + value 1（UTF-8）。
- **Two Byte Integer**（如 0x23 Topic Alias）：2 字节大端。例：`23 00 01` = ID 0x23 + value 1。
- **Four Byte Integer**（如 0x11 Session Expiry Interval）：4 字节大端。例：`11 00 00 0E 10` = ID 0x11 + value 3600。
- **UTF-8 Encoded String**（如 0x03 Content Type）：2 字节长度 + UTF-8。例：`03 00 10 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6A 73 6F 6E` = ID 0x03 + "application/json"（16 字节）。
- **Binary Data**（如 0x09 Correlation Data）：2 字节长度 + 原始字节。例：`09 00 04 01 02 03 04` = ID 0x09 + 4 字节。
- **UTF-8 String Pair**（如 0x26 User Property）：2 字节长度键 + 2 字节长度值。例：`26 00 01 6B 00 01 76` = ID 0x26 + key="k" + value="v"。
- **Variable Byte Integer**（如 0x0B Subscription Identifier，**仅 SUBSCRIBE / down PUBLISH 合法，禁止 up PUBLISH**，见 §2.14）：VBI。例：`0B C8 01` = ID 0x0B + value 200（VBI 编码 `0xC8 0x01`）。

**Will Delay Interval 编码示例**（5.0，ID=0x18）：
- value=5 秒：`18 00 00 00 05`（ID 0x18 + 4 字节大端 5）。
- Will Properties 段（仅含 Will Delay=5）：`05 18 00 00 00 05`（Properties Length=5 + 5 字节属性）。

---

## §4. 状态机

### 4.1 单会话主状态机

```
TCP SYN/SYN-ACK/ACK
        │
        ▼
   CONNECT (up)  ─────►  [broker 处理]
        │
        ▼
   CONNACK (down)
        │
        │  ConnectAckCode != 0  ──► TCP FIN/FIN-ACK/ACK (无后续)
        │
        ▼
   [SUBSCRIBE (up) ► SUBACK (down)] × N  (可选, 每条订阅一次)
        │
        ▼
   [PUBLISH (up/down) ► {PUBACK | PUBREC►PUBREL►PUBCOMP}] × M  (可选)
        │
        ▼
   [PINGREQ (up) ► PINGRESP (down)]  (可选, PingAfterMessages=true)
        │
        ▼
   DISCONNECT (up, 可选) ──► TCP FIN/FIN-ACK/ACK
```

### 4.2 QoS 子状态机

> **注**：本节描述规范的真实 MQTT 重传语义。trafficgen planner **不实现任何 timer/重传**——§4.3 明确"总是成对生成"。本节仅作为协议语义参考，便于理解 QoS1/2 的四包交换结构。planner 输出的固定序列等价于"无丢包、无重传"的理想路径。

**QoS 0（至多一次）**：`PUBLISH` 即结束，无 ACK。

**QoS 1（至少一次）**：
```
PUBLISH (sender→receiver, PacketID=X, DUP=0)
  ├── timer: 未收到 PUBACK → 重发 PUBLISH (DUP=1, 同 PacketID)
  └── PUBACK (receiver→sender, PacketID=X) → 完成
```

**QoS 2（恰好一次）**：
```
PUBLISH (sender→receiver, PacketID=X, QoS=2)
  ├── timer: 未收到 PUBREC → 重发 PUBLISH (DUP=1)
  └── PUBREC (receiver→sender, PacketID=X)
        ├── timer: 未收到 PUBREL → 重发 PUBREC
        └── PUBREL (sender→receiver, PacketID=X, flags=0x02)
              ├── timer: 未收到 PUBCOMP → 重发 PUBREL
              └── PUBCOMP (receiver→sender, PacketID=X) → 完成
```

### 4.3 死锁/缺响应防护

- **CONNACK 拒绝后不发后续包**：ConnectAckCode≠0 时，planner 跳过 Subscriptions/Messages/Ping，直接进入 TCP 挥手（与 broker 行为一致）。
- **PUBLISH/PUBACK 等待缺口**：planner 总是成对生成（PUBLISH 后必跟对应 ACK），用户无法单独发 PUBLISH 而漏掉 ACK —— 由 planner 自动补全。
- **DISCONNECT 后无更多 MQTT 包**：DISCONNECT 必须是最后一个 MQTT 包，后续只允许 TCP 挥手。
- **QoS=3 非法**：Validate 拒绝 QoS 字段值为 3。
- **PUBREL flags 必须 0x02**：planner 写死，不接受用户覆盖；其他类型的 flags 强制为表 §2.2 中的固定值。
- **多会话独立 FlowID**：每个 session 的 4-tuple 不同 → FlowID 不同 → resequencer（重排序器）独立排序，不会跨会话串包。

### 4.4 遗嘱消息（Will Message）状态机

```
CONNECT (Will Flag=1, Will Topic, Will Payload, Will QoS)
        │
        ├── 正常 DISCONNECT ──► Will 被 broker 丢弃，不发布
        │
        └── 异常断开（无 DISCONNECT）
                │
                ▼
        [3.1.1] broker 立即发布 Will PUBLISH
        [5.0]  broker 延迟 Will Delay Interval 秒后发布
                │
                ▼
        Will PUBLISH (down, Will Topic, Will Payload, Will QoS, Will Retain)
```

planner 简化：在 `Disconnect: *false` + `Will != nil` 时，于 TCP 挥手前插入 will PUBLISH 下行段（+QoS1/2 时附 ACK 链）。

> **模型偏差说明（will 时序）**：真实规范语义（3.1.1 §3.1.2.5 / 5.0 §3.1.3.2）中，Will 由 **broker 在检测到连接异常断开之后**替客户端发布——即 will PUBLISH 出现在客户端发出的 FIN/RST **之后**；而正常 DISCONNECT（或等价于主动断开的 FIN 挥手）时 broker **不发布** will。trafficgen 是单连接字节序列生成器，无法在断开后跨越已终止的 TCP 连接建模 broker 的独立发布。因此本节与 §6.9（S9）/T-169 的编排属于**broker 视角的单向字节序列建模**：will PUBLISH（down）在客户端断开动作（FIN/RST）**之前**插入同一 4-tuple，模拟"broker 已收到断开事件并代发 will"的字节效果。这是**已知模型偏差**（真实 pcap 中 will PUBLISH 由对端在 FIN/RST 后发出），实现时按本说明执行，测试断言（T-169/T-170）以"will PUBLISH 在断开包之前"为基准，不再声称与 TCP 语义一致。

### 4.5 Keep Alive 超时状态机

```
空闲超过 KeepAlive 秒
        │
        ▼
   PINGREQ (up)
        │
        ▼
   PINGRESP (down)        ← 正常响应
        │
        └── 超过 1.5× KeepAlive 无响应 ──► broker 判定客户端离线，关闭连接
```

planner 不模拟真实 timer，由 `PingAfterMessages=true` 触发单次 PINGREQ/PINGRESP。

---

## §5. 配置类型定义（Go struct）

参考 `SocksConfig`（types.go:6258）风格：JSON tag、omitempty、默认值注释、空值行为。新增 `MQTTConfig` 与配套 `MQTTSession`、`MQTTMessage`、`MQTTSubscribe`、`MQTTProperty` 类型。

### 5.1 MQTTConfig（顶层）

```go
// MQTTConfig configures the MQTT protocol planner (3.1.1 / 5.0). Each
// config drives ONE TCP session (one 4-tuple, one client_id). For multiple
// concurrent clients use Sessions[] — each becomes an independent flow with
// its own 4-tuple and FlowID.
type MQTTConfig struct {
    // Version (版本): 4 = MQTT 3.1.1 (default), 5 = MQTT 5.0.
    Version int `json:"version,omitempty"`

    // ClientID (客户端标识): CONNECT payload Client Identifier. Empty =
    // "trafficgen-<counter6hex>" (deterministic auto-generated per flow via
    // atomic counter, e.g. "trafficgen-000001" — NOT random, ensures
    // reproducibility and uniqueness across concurrent tasks). MQTT allows
    // empty client_id only when Clean Session=true, planner forces Clean
    // when empty — see §6 S10 boundary. Validate：Sessions 内显式重复
    // client_id → 报错；跨 task 自动生成保证唯一（counter 单调递增）。
    ClientID string `json:"client_id,omitempty"`

    // KeepAlive (保活间隔, seconds): CONNECT Keep Alive field. nil = default
    // 60 (when both KeepAlive and Sessions are empty). *0 = disable
    // keepalive (server treats as infinite, planner outputs 0x00 0x00).
    // *N (N>0) = N seconds. Pointer type distinguishes "omitted → 60"
    // from "explicit 0 → disabled".
    KeepAlive *int `json:"keep_alive,omitempty"`

    // CleanSession (3.1.1) / CleanStart (5.0): nil = true (default).
    // When false, broker should persist session across reconnects.
    CleanSession *bool `json:"clean_session,omitempty"`

    // Username/Password (认证): CONNECT payload. Empty + non-empty password
    // rejected at Validate. When both empty, Connect Flags bit7/bit6 = 0.
    // 5.0 allows Password without Username; 3.1.1 requires Username Flag=0
    // → Password Flag=0.
    Username string `json:"username,omitempty"`
    Password string `json:"password,omitempty"`

    // Will (遗嘱消息): CONNECT will fields. nil = no will.
    Will *MQTTWill `json:"will,omitempty"`

    // ConnectAckCode (CONNACK Return/Reason Code): 0 = success (default).
    // Non-zero suppresses all downstream publish/subscribe messages (RFC:
    // connection rejected → TCP teardown follows). Validate 检查取值域：
    // 3.1.1 合法值 0-5（6-255 报错）；5.0 精确枚举白名单（见 §8.2）。
    ConnectAckCode int `json:"connect_ack_code,omitempty"`

    // ConnectAckSessionPresent (CONNACK Session Present bit): false (default).
    // Validate 强制：CleanSession=true 时此字段必须 false（3.1.1 §3.2.2.1）；
    // ConnectAckCode≠0 时此字段必须 false（5.0 §3.2.2.2）。违反 → Validate 报错。
    ConnectAckSessionPresent bool `json:"connect_ack_session_present,omitempty"`

    // Subscriptions (订阅列表): emitted as one SUBSCRIBE/SUBACK exchange
    // immediately after CONNACK. Empty = skip subscribe phase.
    Subscriptions []MQTTSubscribe `json:"subscriptions,omitempty"`

    // Messages (消息列表): publish/ack exchanges emitted after the subscribe
    // phase (or directly after CONNACK when no subscriptions). Each entry
    // drives QoS 0/1/2 packet exchange per its QoS field. Empty = no publish
    // phase (just CONNECT/CONNACK/PINGREQ/PINGRESP/DISCONNECT).
    Messages []MQTTMessage `json:"messages,omitempty"`

    // PingAfterMessages (心跳触发): when true, emit PINGREQ/PINGRESP after
    // the message phase and before DISCONNECT. false (default) = skip. Use
    // this to model keepalive behavior; the planner does NOT simulate real
    // keepalive timers — it emits a single PINGREQ/PINGRESP pair on demand.
    PingAfterMessages bool `json:"ping_after_messages,omitempty"`

    // Disconnect (主动断开): nil = true (default, send DISCONNECT before TCP
    // teardown); *false = TCP RST/FIN without MQTT DISCONNECT (models
    // abnormal disconnect — required for will-message scenarios).
    Disconnect *bool `json:"disconnect,omitempty"`

    // Sessions (多会话列表): when non-empty, the planner emits one flow per
    // entry (each gets a distinct 4-tuple and FlowID via the SubFlow
    // mechanism, mirroring SIP/RTSP multi-stream handling). Inheritance
    // semantics: scalar fields (KeepAlive/CleanSession/Username/Password/
    // Disconnect) inherit top-level value when session field is zero/nil;
    // slice fields (Messages/Subscriptions/Properties/Will) REPLACE (not
    // append) top-level when session field is non-nil, and inherit top-level
    // when nil. Each session emits its own Messages (no cross-session
    // duplication). Empty = single-session mode using the top-level fields
    // directly.
    Sessions []MQTTSession `json:"sessions,omitempty"`

    // Properties (5.0 only): CONNECT-level properties. Ignored when
    // Version=4. nil = no properties entries. IMPORTANT: in 5.0 the
    // Properties Length (VBI) is MANDATORY even when there are no
    // properties — the planner always writes the 0x00 length byte for a
    // nil slice (5.0 §2.2.2.1, "Properties Length" is required,
    // value may be 0). The segment is never omitted entirely.
    Properties []MQTTProperty `json:"properties,omitempty"`
}
```

### 5.2 MQTTWill（遗嘱消息）

```go
// MQTTWill is the CONNECT Will Message configuration.
type MQTTWill struct {
    // Topic (遗嘱主题): Will Topic. Empty = error at Validate (will flag
    // requires non-empty topic).
    Topic string `json:"topic,omitempty"`

    // Payload (遗嘱负载): Will Payload bytes. Empty = zero-length payload
    // (valid per RFC).
    Payload string `json:"payload,omitempty"`

    // QoS (遗嘱QoS): 0 (default), 1, or 2. Validated against the QoS table.
    QoS int `json:"qos,omitempty"`

    // Retain (遗嘱保留): true = broker caches will as retained message.
    Retain bool `json:"retain,omitempty"`

    // DelayInterval (5.0 only): Will Delay Interval seconds. 0 = publish
    // immediately on disconnect. Validate：Version=4 + DelayInterval≠0 →
    // 报错（v5-only 字段在 v4 一律报错，与 Properties 政策一致）。
    // 编码为 Will Properties 段中的 ID 0x18 (Four Byte Integer)。
    DelayInterval int `json:"delay_interval,omitempty"`
}
```

### 5.3 MQTTMessage（一条发布消息）

```go
// MQTTMessage is one PUBLISH exchange. QoS determines the downstream
// ack chain: QoS0 → PUBLISH only; QoS1 → PUBLISH+PUBACK; QoS2 →
// PUBLISH+PUBREC+PUBREL+PUBCOMP. Direction "up" (default) = client→server
// (client publishes), "down" = server→client (server publishes down to the
// subscribing client — models broker forwarding a retained/matched message).
type MQTTMessage struct {
    Topic     string `json:"topic,omitempty"`     // PUBLISH topic; empty = error (除非 Topic Alias 已建映射)
    Payload   string `json:"payload,omitempty"`   // application message bytes
    QoS       int    `json:"qos,omitempty"`       // 0 (default), 1, 2
    Retain    bool   `json:"retain,omitempty"`    // PUBLISH retain flag
    DUP       bool   `json:"dup,omitempty"`       // PUBLISH dup flag (QoS>0 only)
    PacketID  uint16 `json:"packet_id,omitempty"` // 0 = auto-increment from 1 (省略等价于 0)
    Direction string `json:"direction,omitempty"` // "up" (default) or "down"

    // Properties (5.0 only): PUBLISH-level properties. Ignored when
    // MQTTConfig.Version=4.
    Properties []MQTTProperty `json:"properties,omitempty"`
}
```

### 5.4 MQTTSubscribe（一次订阅）

```go
// MQTTSubscribe is one SUBSCRIBE/SUBACK exchange.
type MQTTSubscribe struct {
    // PacketID: SUBSCRIBE packet identifier. 0 = auto-increment (continuing
    // the same counter as MQTTMessage.PacketID).
    PacketID uint16 `json:"packet_id,omitempty"`

    // Filters (订阅过滤器): topic filter list. Each gets one Reason Code in
    // SUBACK payload. Empty = error at Validate.
    Filters []MQTTTopicFilter `json:"filters,omitempty"`

    // AckReasonCodes (SUBACK Reason Codes): one per filter. Empty = all 0x00
    // (QoS0 granted). Length must match Filters; mismatch = error.
    AckReasonCodes []int `json:"ack_reason_codes,omitempty"`
}

// MQTTTopicFilter is one topic filter in a SUBSCRIBE.
type MQTTTopicFilter struct {
    Filter string `json:"filter,omitempty"` // e.g. "sensor/+", "sport/#", "a/b/c"
    QoS    int    `json:"qos,omitempty"`    // 0 (default), 1, 2

    // 5.0 订阅选项（3.1.1 必须为 0/默认）
    NoLocal           bool `json:"no_local,omitempty"`            // bit2, 5.0 only
    RetainAsPublished bool `json:"retain_as_published,omitempty"` // bit3, 5.0 only
    RetainHandling    int  `json:"retain_handling,omitempty"`     // bit4-5, 5.0 only, 0/1/2
}
```

### 5.5 MQTTProperty（5.0 属性）

```go
// MQTTProperty is one MQTT 5.0 property. Identifier is the 5.0 §2.2.2.2
// Property Identifier. Value is encoded by Format:
//   "byte"      → 1-byte unsigned (Payload Format Indicator, etc.)
//   "uint16"    → 2-byte big-endian (Topic Alias, Server Keep Alive, etc.)
//   "uint32"    → 4-byte big-endian (Session Expiry, Message Expiry, etc.)
//   "string"    → 2-byte length + UTF-8 bytes (Content Type, Response Topic,
//                 Reason String)
//   "binary"    → 2-byte length + raw bytes (Correlation Data)
//   "stringpair"→ 2-byte len key + 2-byte len value (User Property, repeated)
//   "vbi"       → Variable Byte Integer (Subscription Identifier)
// Format "" defaults to "string" (most common).
type MQTTProperty struct {
    Identifier int    `json:"identifier"`
    Format     string `json:"format,omitempty"`
    Value      string `json:"value,omitempty"` // numeric for byte/uint16/uint32/vbi; text for string; hex for binary; "k\x00v" for stringpair
}

// Validate 规则（5.0 §2.2.2.2）：
// 1. Property Identifier × 包类型白名单：每类包只接受特定 ID（见 §2.14"适用包"列）。
//    如 Session Expiry 0x11 仅 CONNECT/CONNACK/DISCONNECT；Topic Alias 0x23 仅 PUBLISH。
//    不匹配 → Validate 报错。
// 2. 重复检查：除 User Property（0x26）外，同包内同 ID 不得重复 → 报错。
//    例外：Subscription Identifier（0x0B）仅在下行 PUBLISH（direction="down"，
//    broker→client 转发，多订阅匹配，5.0 §3.3.2.3.8）中允许重复；
//    SUBSCRIBE 中的 0x0B 不得重复（5.0 §3.8.2.1.2）。
// 3. 方向检查：0x0B 禁止出现在 up 方向（client→server）PUBLISH 中 →
//    报错（5.0 §3.3.4 [MQTT-3.3.4-6]："A PUBLISH packet sent from a Client to a
//    Server MUST NOT contain a Subscription Identifier"）。
```

### 5.6 MQTTSession（多会话条目）

```go
// MQTTSession overrides the top-level MQTTConfig fields for one client
// session. Only non-zero/non-empty fields override; absent fields inherit
// from the parent. Each session becomes an independent TCP 4-tuple (SrcPort
// auto-increments when HasExplicitSrcPort=false).
type MQTTSession struct {
    ClientID    string         `json:"client_id,omitempty"`
    KeepAlive   *int           `json:"keep_alive,omitempty"`
    CleanSession *bool         `json:"clean_session,omitempty"`
    Username    string         `json:"username,omitempty"`
    Password    string         `json:"password,omitempty"`
    Will        *MQTTWill      `json:"will,omitempty"`
    Subscriptions []MQTTSubscribe `json:"subscriptions,omitempty"`
    Messages    []MQTTMessage  `json:"messages,omitempty"`
    PingAfterMessages bool     `json:"ping_after_messages,omitempty"`
    Disconnect  *bool          `json:"disconnect,omitempty"`
    Properties  []MQTTProperty `json:"properties,omitempty"`

    // SrcPort/DstPort override: 0 = inherit from FlowSpec / auto-assign.
    SrcPort uint16 `json:"src_port,omitempty"`
    DstPort uint16 `json:"dst_port,omitempty"`
}
```

### 5.7 字段默认值汇总表

| 字段 | 默认值 | 空值行为 |
|------|--------|----------|
| Version | 4 (3.1.1) | 0 → 4 |
| ClientID | `trafficgen-<counter6hex>` | 空字符串 → 确定性自动生成（atomic counter 单调递增）+ 强制 CleanSession=true；Sessions 内显式重复 → Validate 报错 |
| KeepAlive | 60 | nil → 60（单会话模式）；*0 → 禁用保活，planner 输出 `0x00 0x00`；*N (N>0) → N 秒 |
| CleanSession | true | nil → true |
| Username/Password | 空 | 两者皆空 = 匿名（无认证） |
| Will | nil | nil = 无遗嘱 |
| ConnectAckCode | 0 (success) | 0 = 接受 |
| ConnectAckSessionPresent | false | false = 无 session |
| Subscriptions | 空 | 空 = 跳过订阅阶段 |
| Messages | 空 | 空 = 跳过发布阶段 |
| PingAfterMessages | false | false = 不发心跳 |
| Disconnect | true | nil = true |
| Sessions | 空 | 空 = 单会话模式 |
| Properties | 空 | 空 = Properties Length = 0 |
| MQTTMessage.QoS | 0 | 0 = QoS0 |
| MQTTMessage.DUP | false | QoS0 + DUP=true → 报错 |
| MQTTMessage.Direction | "up" | "" → "up" |
| MQTTMessage.PacketID | 1 起步自增 | 0 = 自动分配（等同于省略）；自增到 65535 后 **wrap 到 1**（不溢出到 0，T-119） |
| MQTTMessage.Retain | false | false = 不缓存 |
| MQTTWill.QoS | 0 | 0 = QoS0 |
| MQTTWill.Retain | false | false = 不缓存 |
| MQTTWill.DelayInterval | 0 | 0 = 立即发布；v4 + ≠0 → 报错 |
| MQTTSubscribe.Filters | 空 | 空 = Validate 报错 |
| MQTTSubscribe.AckReasonCodes | 全 0x00 | 空 = 全授予 QoS0 |
| MQTTSubscribe.PacketID | 1 起步自增 | 0 = 自动分配 |
| MQTTTopicFilter.QoS | 0 | 0 = QoS0 |
| MQTTProperty.Format | "string" | "" → "string" |
| Default port | 1883 | DstPort 0 → 1883 |

---

## §6. 包序列场景（HexDump S1-S15）

本章给出 15 个完整 HexDump 场景，覆盖所有 MQTT 包型与业务路径。每个场景包含：输入 spec、完整 PacketConfig 序列表、关键 MQTT 字节 HexDump、逐字节核算。

### S1. CONNECT/CONNACK 基础连接（3.1.1）

**输入**：
```json
{"mqtt": {"client_id": "c1", "keep_alive": 60, "clean_session": true}}
```

**PacketConfig 序列**（10 包）：

| Index | Direction | TCP Flags | MQTT Type | MQTT 字节 (hex) |
|-------|-----------|-----------|-----------|-----------------|
| 0 | up | SYN (0x02) | — | — |
| 1 | down | SYN-ACK (0x12) | — | — |
| 2 | up | ACK (0x10) | — | — |
| 3 | up | PSH-ACK (0x18) | CONNECT | `10 0e 00 04 4d 51 54 54 04 02 00 3c 00 02 63 31` |
| 4 | down | PSH-ACK (0x18) | CONNACK | `20 02 00 00` |
| 5 | up | PSH-ACK (0x18) | DISCONNECT | `e0 00` |
| 6 | up | FIN-ACK (0x11) | — | — |
| 7 | down | FIN-ACK (0x11) | — | — |
| 8 | up | ACK (0x10) | — | — |

**CONNECT 逐字节核算**（Index 3）：
```
10          固定头第一字节 = Type=1 (CONNECT) << 4 | Flags=0 → 0x10
0e          Remaining Length = 14 (0x0e)
              = 2 (Protocol Name Len) + 4 ("MQTT") + 1 (Level) + 1 (Flags)
              + 2 (KeepAlive) + 2 (ClientID Len) + 2 ("c1") = 14
00 04       Protocol Name Length = 4
4d 51 54 54 "MQTT"
04          Protocol Level = 4 (3.1.1)
02          Connect Flags = 0000 0010 (bit1 CleanSession=1, 其余 0)
00 3c       Keep Alive = 60 (0x3c)
00 02       ClientID Length = 2
63 31       "c1"
```

**CONNACK 逐字节核算**（Index 4）：
```
20          Type=2 (CONNACK) << 4 | 0 = 0x20
02          Remaining Length = 2
00          Session Present = 0 (bit0=0, bit1-7=0)
00          Return Code = 0 (Success)
```

### S2. PUBLISH QoS 0（无 ACK）

**输入**：
```json
{"mqtt": {"client_id": "temp-sensor-01", "messages": [{"topic": "sensor/temp", "payload": "23.5", "qos": 0}]}}
```

**PacketConfig 序列**（10 包，仅展示 MQTT 段）：

| Index | Direction | MQTT Type | MQTT 字节 (hex) |
|-------|-----------|-----------|-----------------|
| 3 | up | CONNECT | `10 1a 00 04 4d 51 54 54 04 02 00 3c 00 0e 74 65 6d 70 2d 73 65 6e 73 6f 72 2d 30 31` |
| 4 | down | CONNACK | `20 02 00 00` |
| 5 | up | PUBLISH q0 | `30 11 00 0b 73 65 6e 73 6f 72 2f 74 65 6d 70 32 33 2e 35` |
| 6 | up | DISCONNECT | `e0 00` |

**CONNECT 逐字节核算**（Index 3）：
```
10          CONNECT
1a          Remaining Length = 26 (0x1a)
              = 10 (Variable Header) + 2 (ClientID Len) + 14 ("temp-sensor-01") = 26
              （VH = 协议名长度 2 + "MQTT" 4 + Level 1 + Flags 1 + KeepAlive 2 = 10 字节，
               不含 ClientID 长度前缀字段；Remaining Length = 固定头之后的所有字节数）
00 04 4d 51 54 54  "MQTT"
04          Level 4
02          CleanSession=1
00 3c       KeepAlive=60
00 0e       ClientID Length = 14
74 65 6d 70 2d 73 65 6e 73 6f 72 2d 30 31  "temp-sensor-01"
```

**PUBLISH 逐字节核算**（Index 5）—— **关键修正点**：
```
30          Type=3 (PUBLISH) << 4 | DUP=0|QoS=00|Retain=0 = 0x30
11          Remaining Length = 17 (0x11)
              = 2 (Topic Len) + 11 (topic) + 4 (payload) = 17
00 0b       Topic Name Length = 11 (0x0b)    ← "sensor/temp" 是 11 字节，不是 10
73 65 6e 73 6f 72 2f 74 65 6d 70  "sensor/temp" (11 字节)
32 33 2e 35  "23.5" (4 字节 payload)
```

**核算**：`sensor/temp` = s(1) e(2) n(3) s(4) o(5) r(6) /(7) t(8) e(9) m(10) p(11) = 11 字节。长度字段 = `0x0b`（11），**不是 `0x0a`**。Remaining Length = 2 + 11 + 4 = 17 = `0x11`，**不是 `0x0c`**。

**关键断言**：
- PUBLISH 固定头 `0x30`（DUP=0, QoS=00, Retain=0）。
- PUBLISH 无 Packet Identifier 字段（QoS0 必须省略）。
- 无 PUBACK（QoS0 不需要确认）。
- DISCONNECT 在 CONNACK/PUBLISH 之后。

### S3. PUBLISH QoS 1（含 PUBACK）

**输入**：
```json
{"mqtt": {"client_id": "alert-01", "messages": [{"topic": "alert/fire", "payload": "WARNING", "qos": 1, "packet_id": 100}]}}
```

**MQTT 段**：

| Index | Direction | MQTT Type | MQTT 字节 (hex) |
|-------|-----------|-----------|-----------------|
| 3 | up | CONNECT | (略) |
| 4 | down | CONNACK | `20 02 00 00` |
| 5 | up | PUBLISH q1 | `32 15 00 0a 61 6c 65 72 74 2f 66 69 72 65 00 64 57 41 52 4e 49 4e 47` |
| 6 | down | PUBACK | `40 02 00 64` |
| 7 | up | DISCONNECT | `e0 00` |

**PUBLISH 逐字节核算**（Index 5）：
```
32          Type=3 | DUP=0 | QoS=01 | Retain=0 = 0011 0010 = 0x32
15          Remaining Length = 21 (0x15)
              = 2 (Topic Len 长度前缀) + 10 (topic) + 2 (PacketID) + 7 (payload) = 21
              （Remaining Length = 固定头之后的所有字节数，长度前缀字段计入其所在字段）
00 0a       Topic Name Length = 10 (0x0a)   "alert/fire" = 10 字节
61 6c 65 72 74 2f 66 69 72 65  "alert/fire"
00 64       Packet ID = 100 (0x64)
57 41 52 4e 49 4e 47  "WARNING" (7 字节)
```

**PUBACK 逐字节核算**（Index 6）：
```
40          Type=4 (PUBACK) << 4 | 0 = 0x40
02          Remaining Length = 2
00 64       Packet ID = 100 (与 PUBLISH 一致)
```

**关键断言**：
- PUBLISH 固定头 `0x32`（QoS=01）。
- PUBLISH 含 PacketID `0x00 0x64`（=100）。
- PUBACK 固定头 `0x40`，payload 为 `0x00 0x64`。
- PacketID 在 PUBLISH 与 PUBACK 中一致。

### S4. PUBLISH QoS 2 全流程（4 包交换）

**输入**：
```json
{"mqtt": {"client_id": "billing-01", "messages": [{"topic": "billing/tx", "payload": "TX12345", "qos": 2, "packet_id": 7}]}}
```

**MQTT 段**：

| Index | Direction | MQTT Type | MQTT 字节 (hex) |
|-------|-----------|-----------|-----------------|
| 3 | up | CONNECT | (略) |
| 4 | down | CONNACK | `20 02 00 00` |
| 5 | up | PUBLISH q2 | `34 15 00 0a 62 69 6c 6c 69 6e 67 2f 74 78 00 07 54 58 31 32 33 34 35` |
| 6 | down | PUBREC | `50 02 00 07` |
| 7 | up | PUBREL | `62 02 00 07` |
| 8 | down | PUBCOMP | `70 02 00 07` |
| 9 | up | DISCONNECT | `e0 00` |

**PUBLISH 逐字节核算**（Index 5）：
```
34          Type=3 | DUP=0 | QoS=10 | Retain=0 = 0011 0100 = 0x34
15          Remaining Length = 21 (0x15)
              = 2 (Topic Len 长度前缀) + 10 (topic) + 2 (PacketID) + 7 (payload) = 21
00 0a       Topic Name Length = 10   "billing/tx" = 10 字节
62 69 6c 6c 69 6e 67 2f 74 78  "billing/tx"
00 07       Packet ID = 7
54 58 31 32 33 34 35  "TX12345"
```

**PUBREC/PUBREL/PUBCOMP 逐字节核算**（Index 6-8）：
```
PUBREC:  50 02 00 07    Type=5, RemainingLen=2, PacketID=7
PUBREL:  62 02 00 07    Type=6, flags=0x02 强制, PacketID=7
PUBCOMP: 70 02 00 07    Type=7, PacketID=7
```

**关键断言**：
- PUBLISH `0x34`（QoS=10）。
- PUBREL `0x62 0x02 0x00 0x07`（flags=0x02 强制）。
- 4 包共享同一 PacketID=7。

### S5. SUBSCRIBE/SUBACK

**输入**：
```json
{"mqtt": {"client_id": "sub-01", "subscriptions": [{"filters": [{"filter": "sensor/+", "qos": 0}]}]}}
```

**MQTT 段**：

| Index | Direction | MQTT Type | MQTT 字节 (hex) |
|-------|-----------|-----------|-----------------|
| 3 | up | CONNECT | (略) |
| 4 | down | CONNACK | `20 02 00 00` |
| 5 | up | SUBSCRIBE | `82 0d 00 01 00 08 73 65 6e 73 6f 72 2f 2b 00` |
| 6 | down | SUBACK | `90 03 00 01 00` |
| 7 | up | DISCONNECT | `e0 00` |

**SUBSCRIBE 逐字节核算**（Index 5）：
```
82          Type=8 (SUBSCRIBE) << 4 | flags=0x02 = 1000 0010 = 0x82
0d          Remaining Length = 13 (0x0d)
              = 2 (PacketID) + 2 (Filter Len) + 8 (filter) + 1 (QoS) = 13
00 01       Packet ID = 1
00 08       Topic Filter Length = 8   "sensor/+" = 8 字节
73 65 6e 73 6f 72 2f 2b  "sensor/+"
00          Requested QoS = 0
```

**SUBACK 逐字节核算**（Index 6）：
```
90          Type=9 (SUBACK) << 4 | 0 = 0x90
03          Remaining Length = 3
              = 2 (PacketID) + 1 (Reason Code) = 3
00 01       Packet ID = 1 (与 SUBSCRIBE 一致)
00          Reason Code = 0x00 (QoS0 granted)
```

### S6. UNSUBSCRIBE（本期不实现，仅字节参考）

**字节参考**（3.1.1，filter=`sensor/+`）：
```
UNSUBSCRIBE: a2 0c 00 02 00 08 73 65 6e 73 6f 72 2f 2b
              ↑  ↑   ↑    ↑
              │  │   │    └─ "sensor/+" (8 字节)
              │  │   └─ Filter Length = 8
              │  └─ Packet ID = 2
              └─ Type=10 | flags=0x02

UNSUBACK:    b0 02 00 02
              ↑  ↑   ↑
              │  │   └─ Packet ID = 2
              │  └─ Remaining Length = 2
              └─ Type=11 | flags=0
```

### S7. PINGREQ/PINGRESP（Keep Alive）

**输入**：
```json
{"mqtt": {"client_id": "ping-01", "keep_alive": 30, "ping_after_messages": true}}
```

**MQTT 段**：

| Index | Direction | MQTT Type | MQTT 字节 (hex) |
|-------|-----------|-----------|-----------------|
| 3 | up | CONNECT | `10 13 00 04 4d 51 54 54 04 02 00 1e 00 07 70 69 6e 67 2d 30 31` |
| 4 | down | CONNACK | `20 02 00 00` |
| 5 | up | PINGREQ | `c0 00` |
| 6 | down | PINGRESP | `d0 00` |
| 7 | up | DISCONNECT | `e0 00` |

**PINGREQ/PINGRESP 字节**：
```
PINGREQ:  c0 00    Type=12, RemainingLen=0
PINGRESP: d0 00    Type=13, RemainingLen=0
```

**CONNECT 逐字节核算**（Index 3）：
```
10          CONNECT
13          Remaining Length = 19 (0x13)
              = 10 (VH) + 2 (ClientID Len 长度前缀) + 7 ("ping-01") = 19
              （VH = 协议名长度 2 + "MQTT" 4 + Level 1 + Flags 1 + KeepAlive 2 = 10 字节，
               不含 ClientID 长度前缀字段；Remaining Length = 固定头之后的所有字节数）
00 04 4d 51 54 54  "MQTT"
04          Level 4
02          CleanSession=1
00 1e       Keep Alive = 30 (0x1e)
00 07       ClientID Length = 7
70 69 6e 67 2d 30 31  "ping-01"
```

### S8. DISCONNECT（3.1.1 与 5.0）

**3.1.1 DISCONNECT**：
```
e0 00    Type=14, RemainingLen=0
```

**5.0 DISCONNECT**（无属性，Reason Code=0=正常断开）：
```
e0 02 00 00
↑  ↑  ↑  ↑
│  │  │  └─ Properties Length = 0 (必填)
│  │  └─ Reason Code = 0 (Normal disconnection)
│  └─ Remaining Length = 2
└─ Type=14 | flags=0
```

**5.0 DISCONNECT 带 Will Message**（Reason Code=4）：
```
e0 02 04 00    Reason=0x04 (Disconnect with Will Message), PropertiesLen=0
```

### S9. 遗嘱消息（Will Message）

**输入**：
```json
{
  "mqtt": {
    "client_id": "device-01",
    "will": {"topic": "client/status", "payload": "offline", "qos": 1, "retain": false},
    "disconnect": false,
    "messages": []
  }
}
```

**期望包序列**（FIN-based 异常断开变体，10 包）：

| Index | Direction | TCP Flags | MQTT Type | MQTT 字节 (hex) |
|-------|-----------|-----------|-----------|-----------------|
| 0 | up | SYN (0x02) | — | — |
| 1 | down | SYN-ACK (0x12) | — | — |
| 2 | up | ACK (0x10) | — | — |
| 3 | up | PSH-ACK (0x18) | CONNECT | `10 2d 00 04 4d 51 54 54 04 0e 00 3c 00 09 64 65 76 69 63 65 2d 30 31 00 0d 63 6c 69 65 6e 74 2f 73 74 61 74 75 73 00 07 6f 66 66 6c 69 6e 65` |
| 4 | down | PSH-ACK (0x18) | CONNACK | `20 02 00 00` |
| 5 | down | PSH-ACK (0x18) | PUBLISH q1 (will) | `32 18 00 0d 63 6c 69 65 6e 74 2f 73 74 61 74 75 73 00 01 6f 66 66 6c 69 6e 65` |
| 6 | up | PSH-ACK (0x18) | PUBACK | `40 02 00 01` |
| 7 | up | FIN-ACK (0x11) | — | — |
| 8 | down | FIN-ACK (0x11) | — | — |
| 9 | up | ACK (0x10) | — | — |

**CONNECT 逐字节核算**（Index 3）—— Will 字段：
```
10          CONNECT
2d          Remaining Length = 45 (0x2d)
              = 10 (VH) + (2+9) (ClientID 含长度前缀)
              + (2+13) (Will Topic 含长度前缀)
              + (2+7) (Will Payload 含长度前缀) = 45
              （VH = 协议名长度 2 + "MQTT" 4 + Level 1 + Flags 1 + KeepAlive 2 = 10 字节，
               不含任何长度前缀字段；Remaining Length = 固定头之后的所有字节数）
00 04 4d 51 54 54  "MQTT"
04          Level 4
0e          Connect Flags = 0000 1110
              bit1 CleanSession=1 (0x02)
              bit2 Will Flag=1 (0x04)
              bit4-3 Will QoS=01 (0x08)    ← QoS1 → 0x08
              合计 0x02 | 0x04 | 0x08 = 0x0e
00 3c       KeepAlive=60
00 09       ClientID Length = 9
64 65 76 69 63 65 2d 30 31  "device-01"
00 0d       Will Topic Length = 13   "client/status" = 13 字节
63 6c 69 65 6e 74 2f 73 74 61 74 75 73  "client/status"
00 07       Will Payload Length = 7
6f 66 66 6c 69 6e 65  "offline"
```

**Will PUBLISH 逐字节核算**（Index 5）：
```
32          Type=3 | QoS=01 | Retain=0 = 0x32
18          Remaining Length = 24 (0x18)
              = 2 (Topic Len 长度前缀) + 13 (topic) + 2 (PacketID) + 7 (payload) = 24
00 0d       Topic Length = 13
63 6c 69 65 6e 74 2f 73 74 61 74 75 73  "client/status"
00 01       Packet ID = 1 (自动分配)
6f 66 66 6c 69 6e 65  "offline"
```

**关键断言**：
- CONNECT Connect Flags bit2=1（Will Flag），bit4-3=01（Will QoS1）。
- CONNECT payload 顺序：ClientID → Will Topic → Will Payload → （无 Username/Password）。
- 无 DISCONNECT 包（`Disconnect: *false`）。
- will PUBLISH 方向为 `down`。
- will PUBLISH 编排在 TCP FIN 之前（broker 视角建模：模拟 broker 已收到断开事件后代发 will；真实规范中 will 在断开之后由 broker 发布，见 §4.4 模型偏差说明）。

### S10. 多会话（3 个客户端并发）

**输入**：
```json
{
  "mqtt": {
    "sessions": [
      {"client_id": "s1", "messages": [{"topic": "t/1", "payload": "a", "qos": 0}]},
      {"client_id": "s2", "messages": [{"topic": "t/2", "payload": "b", "qos": 0}]},
      {"client_id": "s3", "messages": [{"topic": "t/3", "payload": "c", "qos": 0}]}
    ]
  }
}
```

**期望**：3 个独立 flow，每个 10 包，SrcPort 自增（36164/36165/36166），DstPort 同 1883。

**Flow 1 (s1)** MQTT 段：
```
CONNECT: 10 0e 00 04 4d 51 54 54 04 02 00 3c 00 02 73 31
         ClientID="s1", PUBLISH topic="t/1" payload="a"
         Remaining Length = 10 (VH) + 2 (ClientID Len 长度前缀) + 2 ("s1") = 14 = 0x0e
         （VH 不含 ClientID 长度前缀字段；Remaining Length = 固定头之后的所有字节数）
PUBLISH: 30 07 00 03 74 2f 31 61    topic="t/1" (3 字节), payload="a" (1 字节)
         RemainingLen = 2 + 3 + 1 = 6 = 0x06   ← 修正：应为 0x06 不是 0x07
```

**修正核算**：`t/1` = t(1) /(2) 1(3) = 3 字节。Topic Length = 3 = `0x03`。Remaining Length = 2 + 3 + 1 = 6 = `0x06`。**正确字节**：`30 06 00 03 74 2f 31 61`。

**Flow 2 (s2)** PUBLISH：`30 06 00 03 74 2f 32 62`（topic="t/2", payload="b"）
**Flow 3 (s3)** PUBLISH：`30 06 00 03 74 2f 33 63`（topic="t/3", payload="c"）

**关键断言**：
- 3 个 FlowID 互不相同。
- 每个 flow 的 PUBLISH payload 分别为 `a`/`b`/`c`。
- 每个 flow 的 CONNECT payload 含不同 ClientID。
- TCP seq 在各 flow 内独立（不跨 flow 累加）。

### S11. 多流关联（SubFlow 机制 + GroupID）

**输入**：同 S10，额外设 `spec.GroupID = "mqtt-batch"`。

**期望**：3 个 flow 的 PacketConfig.Metadata 含 `group_id="mqtt-batch"`，路由到同一 PacketWorker，resequencer 按各 flow 内 PacketIndex 独立排序。

**关键断言**：
- 3 flow 的 GroupID 相同（共享父 FlowSpec）。
- 3 flow 的 FlowID 含 `:mqtt-0`/`:mqtt-1`/`:mqtt-2` 后缀。
- 3 flow 的 4-tuple 互不相同（SrcPort 36164/36165/36166）。

### S12. MQTT 5.0 Properties（Session Expiry + Topic Alias）

**输入**：
```json
{
  "mqtt": {
    "version": 5,
    "client_id": "v5-client",
    "properties": [
      {"identifier": 17, "format": "uint32", "value": "3600"},
      {"identifier": 34, "format": "uint16", "value": "1"},
      {"identifier": 38, "format": "stringpair", "value": "k\x00v"}
    ],
    "messages": [
      {
        "topic": "sensor/temp", "payload": "{\"t\":1}", "qos": 0,
        "properties": [
          {"identifier": 3, "format": "string", "value": "application/json"},
          {"identifier": 35, "format": "uint16", "value": "1"}
        ]
      },
      {
        "topic": "", "payload": "{\"t\":2}", "qos": 0,
        "properties": [
          {"identifier": 35, "format": "uint16", "value": "1"}
        ]
      }
    ]
  }
}
```

**CONNECT 字节**（5.0 含 Properties）：
```
10 27                 Remaining Length = 39 (0x27)
00 04 4d 51 54 54    "MQTT"
05                    Level 5
02                    CleanStart=1
00 3c                 KeepAlive=60
11                    Properties Length VBI = 17 (0x11)
<Properties entries>:
  11 00 00 0e 10      Session Expiry Interval = 3600 (0x0E10)
                      (ID 0x11 + 4 字节大端 3600)
  22 00 01            Topic Alias Maximum = 1
                      (ID 0x22 + uint16=1；声明后 client 才可发送 Topic Alias，
                       5.0 §3.1.2.11.5 / §3.3.2.3.4)
  26 00 01 6b 00 01 76  User Property k=v
                      (ID 0x26 + key Len=1 + "k" + value Len=1 + "v")
00 09                 ClientID Length = 9
76 35 2d 63 6c 69 65 6e 74  "v5-client"
```

**Remaining Length 核算**（CONNECT）：= 10 (VH) + 1 (Properties Length) + 17 (Properties) + 2 (ClientID Len) + 9 (ClientID) = 39 = `0x27`。

**Properties Length 核算**：
- ID 0x11 (1 字节) + uint32 (4 字节) = 5 字节
- ID 0x22 (1 字节) + uint16 (2 字节) = 3 字节
- ID 0x26 (1 字节) + key Len (2 字节) + "k" (1 字节) + value Len (2 字节) + "v" (1 字节) = 7 字节
- 合计 17 字节 → Properties Length VBI = `0x11`

**第一条 PUBLISH**（建立 Topic Alias=1 映射）：
```
30 2b                 Remaining Length = 43 (0x2b)
00 0b                 Topic Name Length = 11   "sensor/temp"
73 65 6e 73 6f 72 2f 74 65 6d 70  "sensor/temp"
16                    Properties Length VBI = 22 (0x16)
<Properties entries>:
  03 00 10 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6a 73 6f 6e
    Content Type = "application/json" (16 字节)
    (ID 0x03 + Len=16 + 16 字节)
  23 00 01             Topic Alias = 1
    (ID 0x23 + uint16=1)
7b 22 74 22 3a 31 7d   Payload = "{\"t\":1}" (7 字节)
```

**Remaining Length 核算**（第一条 PUBLISH）：= 2 (Topic Len) + 11 (topic) + 1 (Properties Length) + 22 (Properties) + 7 (payload) = 43 = `0x2b`。

**Properties Length 核算**（第一条 PUBLISH）：
- ID 0x03 (1) + Len (2) + 16 = 19 字节
- ID 0x23 (1) + uint16 (2) = 3 字节
- 合计 22 字节 → Properties Length VBI = `0x16`

**第二条 PUBLISH**（复用 Topic Alias=1，Topic Name 为空）：
```
30 0d                 Remaining Length = 13 (0x0d)
00 00                 Topic Name Length = 0 (空，复用 alias)
03                    Properties Length VBI = 3
<Properties entries>:
  23 00 01             Topic Alias = 1 (复用)
7b 22 74 22 3a 32 7d   Payload = "{\"t\":2}" (7 字节)
```

**Remaining Length 核算**（第二条 PUBLISH）：= 2 (Topic Len) + 0 (空 topic) + 1 (Properties Length) + 3 (Properties) + 7 (payload) = 13 = `0x0d`。

**关键断言**：
- CONNECT Protocol Level = `0x05`。
- Properties Length VBI 正确（`0x11`，含 Topic Alias Maximum）。
- ID 0x11 编码为 `0x11 0x00 0x00 0x0E 0x10`（3600）。
- ID 0x22 编码为 `0x22 0x00 0x01`（Topic Alias Maximum=1）。
- ID 0x26 编码为 `0x26 0x00 0x01 6b 0x00 0x01 76`。
- 第一条 PUBLISH Topic Name 长度字段=11（`sensor/temp` 字节数）。
- 第二条 PUBLISH Topic Name 长度字段=0；Properties 段含 `0x23 0x00 0x01`。

### S13. 认证（Username/Password）

**输入**：
```json
{"mqtt": {"client_id": "auth-client", "username": "admin", "password": "secret"}}
```

**CONNECT 字节**：
```
10 26                 Remaining Length = 38 (0x26)
00 04 4d 51 54 54     "MQTT"
04                    Level 4
c2                    Connect Flags = 1100 0010
                        bit7 Username=1 (0x80)
                        bit6 Password=1 (0x40)
                        bit1 CleanSession=1 (0x02)
                        合计 0x80 | 0x40 | 0x02 = 0xc2
00 3c                 KeepAlive=60
00 0b                 ClientID Length = 11
61 75 74 68 2d 63 6c 69 65 6e 74  "auth-client" (11 字节)
00 05                 Username Length = 5
61 64 6d 69 6e        "admin" (5 字节)
00 06                 Password Length = 6
73 65 63 72 65 74     "secret" (6 字节)
```

**Remaining Length 核算**：
```
= 10 (VH) + 2 (ClientID Len) + 11 (ClientID)
+ 2 (Username Len) + 5 (Username)
+ 2 (Password Len) + 6 (Password)
= 10 + 13 + 7 + 8 = 38 = 0x26 ✓
```

### S14. 错误处理（CONNACK 拒绝码，8 包）

**输入**：
```json
{"mqtt": {"client_id": "bad-client", "connect_ack_code": 5, "messages": [{"topic": "t", "payload": "p", "qos": 0}]}}
```

**期望包序列**（拒绝后跳过后续，8 包：3 握手 + CONNECT + CONNACK + 3 挥手）：

| Index | Direction | MQTT Type | MQTT 字节 (hex) |
|-------|-----------|-----------|-----------------|
| 3 | up | CONNECT | (略) |
| 4 | down | CONNACK | `20 02 00 05` |
| 5 | up | FIN-ACK | — (无 PUBLISH/DISCONNECT) |

**CONNACK 字节**：
```
20 02 00 05
↑  ↑  ↑  ↑
│  │  │  └─ Return Code = 5 (not authorized)
│  │  └─ Session Present = 0
│  └─ Remaining Length = 2
└─ Type=2 (CONNACK)
```

**关键断言**：
- CONNACK byte[1]=5。
- 后续无 SUBSCRIBE/PUBLISH/PINGREQ/DISCONNECT（共 8 包：3 握手 + CONNECT + CONNACK + 3 挥手）。
- planner 实现：CONNECT 拒绝后直接 TCP FIN/FIN-ACK/ACK 三步挥手。

### S15. Keep Alive 超时（5.0 DISCONNECT Reason=0x8D）

**输入**：
```json
{"mqtt": {"version": 5, "client_id": "timeout-01", "keep_alive": 30, "connect_ack_code": 0}}
```

**期望**（模拟 broker 检测 keep alive 超时，发 DISCONNECT down）：

| Index | Direction | MQTT Type | MQTT 字节 (hex) |
|-------|-----------|-----------|-----------------|
| 3 | up | CONNECT | `10 17 00 04 4d 51 54 54 05 02 00 1e 00 00 0a 74 69 6d 65 6f 75 74 2d 30 31` |
| 4 | down | CONNACK | `20 03 00 00 00` |
| 5 | down | DISCONNECT | `e0 02 8d 00` |

**CONNECT 5.0 逐字节核算**（Index 3）：
```
10          CONNECT
17          Remaining Length = 23 (0x17)
              = 10 (VH) + 1 (Properties Length = 0x00) + 2 (ClientID Len 长度前缀) + 10 ("timeout-01") = 23
              （VH = 协议名长度 2 + "MQTT" 4 + Level 1 + Flags 1 + KeepAlive 2 = 10 字节，
               5.0 在 VH 后、ClientID 前写 Properties Length 字节，Remaining Length = 固定头之后的所有字节数）
00 04 4d 51 54 54    "MQTT"
05          Level 5
02          CleanStart=1
00 1e       KeepAlive=30 (0x1e)
00          Properties Length = 0 (5.0 必填，无属性也写 0x00)
00 0a       ClientID Length = 10
74 69 6d 65 6f 75 74 2d 30 31  "timeout-01"
```

**CONNACK 5.0 逐字节核算**（Index 4）：
```
20          CONNACK
03          Remaining Length = 3 (5.0 多一个 Properties Length 字节)
00          Session Present = 0
00          Reason Code = 0 (Success)
00          Properties Length = 0
```

**DISCONNECT 5.0 逐字节核算**（Index 5，Keep Alive timeout）：
```
e0          DISCONNECT
02          Remaining Length = 2
8d          Reason Code = 0x8D (141) = Keep Alive timeout
00          Properties Length = 0
```

**关键断言**：
- CONNECT KeepAlive 字段 `0x00 0x1E`（30）。
- 5.0 CONNACK 含 Properties Length=0x00 必填字节。
- 5.0 DISCONNECT 含 Reason Code=0x8D（Keep Alive timeout，仅 DISCONNECT 适用）。

---

## §7. 测试用例（T-001 ~ T-215）

每条用例独立，遵循 `CLAUDE.md` §7 失败测试先行：先写 reproducing failing test，再修代码使其通过。所有用例在 `internal/protocol/mqtt/mqtt_test.go` 中实现。

### 7.1 RFC 字段构造测试（§2-§3）

#### T-001 CONNECT 3.1.1 字节构造

- **场景**：默认 CONNECT（Version=4, ClientID=`c1`, CleanSession=true, KeepAlive=60, 无 will/认证）。
- **输入**：`MQTTConfig{Version:4, ClientID:"c1", KeepAlive:60}`。
- **期望 Payload**（CONNECT 包 PSH-ACK 段）：`10 0e 00 04 4d 51 54 54 04 02 00 3c 00 02 63 31`
  - `10` = CONNECT type + flags 0
  - `0e` = Remaining Length 14（= 2+4+1+1+2+2+2 = 14，固定头之后所有字节数）
  - `00 04 4d 51 54 54` = Protocol Name "MQTT"
  - `04` = Protocol Level 4
  - `02` = Connect Flags（bit1 CleanSession=1）
  - `00 3c` = Keep Alive 60
  - `00 02 63 31` = ClientID "c1"
- **断言**：`bytes.Equal(payload, wantBytes)`；自洽断言 `int(payload[1]) == len(payload)-2`。

#### T-002 CONNECT 5.0 含 Properties

- **场景**：Version=5，Session Expiry Interval=3600，Topic Alias Maximum=1，User Property `k`=`v`。
- **输入**：见 §6 S12 输入。
- **期望**：Protocol Level=`0x05`；Properties Length VBI=`0x11`；ID 17=`0x11 0x00 0x00 0x0E 0x10`；ID 34=`0x22 0x00 0x01`；ID 38=`0x26 0x00 0x01 6b 0x00 0x01 76`。
- **断言**：字节级匹配。

#### T-003 CONNACK 3.1.1 各 Return Code

- **场景**：ConnectAckCode 分别为 0/1/2/3/4/5。
- **输入**：6 个 spec，仅 ConnectAckCode 不同。
- **期望**：CONNACK payload byte[1] 对应 0/1/2/3/4/5；Code≠0 时后续无 SUBSCRIBE/PUBLISH/PING/DISCONNECT。
- **断言**：表驱动测试，`if got[1] != wantCode`。

#### T-004 CONNACK 5.0 Reason Code 域

- **场景**：Version=5，ConnectAckCode ∈ {0, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 140, 144, 149, 151, 153, 154, 155, 156, 157, 159}（22 个有效 CONNACK 代码）。
- **期望**：Validate 通过；CONNACK byte[2] 对应 hex 值；Code≠0 → 后续无 SUBSCRIBE/PUBLISH/PING/DISCONNECT。
- **断言**：表驱动 22 行，逐行验证 Validate 通过 + 字节正确。

#### T-005 PUBLISH QoS0/1/2 固定头

- **场景**：三条 message，QoS 分别 0/1/2，Retain=0, DUP=0。
- **期望固定头第一字节**：`0x30` / `0x32` / `0x34`。
- **断言**：`payload[0] == wantFirstByte`。

#### T-006 PUBLISH Retain 与 DUP 标志位（负向流量建模）

- **场景**：QoS1 + Retain=1 + DUP=1。**注意：此为负向/畸形流量建模用例**——规范 §3.3.1.1 规定首次发送的 PUBLISH 必须 DUP=0，DUP=1 仅用于重传；本用例的 PUBLISH 是 flow 内首条且唯一一条 QoS1 消息，无前置重传语义，DUP=1 在真实 broker 看来是协议违规。作为流量生成器，planner 允许用户构造此类负向流量用于测试 broker 的容错性。
- **期望**：第一字节 `0x3B`（0011 1011：DUP=1, QoS=01, Retain=1）。
- **断言**：`payload[0] == 0x3B`。

#### T-007 PUBREL flags 强制 0x02

- **场景**：QoS2 publish 流程。
- **期望**：PUBREL 第一字节 `0x62`（type=6, flags=0010）。
- **断言**：QoS2 流程中第 3 个 MQTT 包（PUBREL）`payload[0] == 0x62`。

#### T-008 Variable Byte Integer 编码边界

- **场景**：encodeVBI(0) / (127) / (128) / (16383) / (16384) / (2097151) / (2097152) / (268435455)。
- **期望**：
  - 0 → `00`
  - 127 → `7F`
  - 128 → `80 01`
  - 16383 → `FF 7F`
  - 16384 → `80 80 01`
  - 2097151 → `FF FF 7F`
  - 2097152 → `80 80 80 01`
  - 268435455 → `FF FF FF 7F`
- **断言**：`bytes.Equal(encodeVBI(x), want)`。

#### T-009 Variable Byte Integer 解码

- **场景**：decodeVBI 反向上述 8 个用例。
- **断言**：返回值 + 字节数正确。

#### T-010 encodeVBI 超长报错

- **场景**：encodeVBI(268435456)（超出 4 字节范围）。
- **期望**：返回 error。
- **断言**：`err != nil`。

#### T-011 CONNECT 含 username/password 字节顺序

- **场景**：见 §6.13（S13）。
- **期望 payload**：`10 26 00 04 4d 51 54 54 04 c2 00 3c 00 0b 61 75 74 68 2d 63 6c 69 65 6e 74 00 05 61 64 6d 69 6e 00 06 73 65 63 72 65 74`
  - Remaining Length 38（0x26）
  - Connect Flags `0xC2`（Username+Password+CleanSession）
  - ClientID `auth-client`(11) → Username `admin`(5) → Password `secret`(6)
- **断言**：字节级匹配；自洽断言 `int(payload[1]) == len(payload)-2`。

#### T-012 CONNECT 含 will 字节顺序（Will QoS1）

- **场景**：见 §6.9（S9）。Will Topic=`client/status`, Will Payload=`offline`, Will QoS=1, Retain=false, CleanSession=true。
- **期望**：Connect Flags = `0x0E`（0000 1110：bit1 CleanSession + bit2 Will Flag + bit4-3 Will QoS=01 = 0x02 | 0x04 | 0x08 = 0x0E）。
- **断言**：`ConnectFlags == 0x0E`；payload 顺序 ClientID → Will Topic → Will Payload。

#### T-013 Will Retain=1 → Connect Flags=0x2E

- **场景**：`will: {topic: t, payload: p, qos: 1, retain: true}`（CleanSession 默认 true）。
- **期望**：Connect Flags = `0x2E`（0010 1110：bit5 Will Retain=1、bit4-3 Will QoS=01、bit2 Will Flag=1、bit1 CleanSession=1）。
- **断言**：CONNECT 字节 flags 位置 == 0x2E。

#### T-014 Will QoS=2 → Connect Flags=0x16

- **场景**：`will: {topic: t, payload: p, qos: 2}`（CleanSession 默认 true，retain=false）。
- **期望**：Connect Flags = `0x16`（0001 0110：bit4 Will QoS=10 高位、bit2 Will Flag=1、bit1 CleanSession=1；bit3=0）。
- **断言**：CONNECT 字节 flags 位置 == 0x16。

#### T-015 Will QoS=3 → Validate 报错

- **场景**：`will: {topic: t, payload: p, qos: 3}`。
- **断言**：Validate 报错（Will QoS=3 是 Protocol Error）。

#### T-016 SUBSCRIBE 字节构造

- **场景**：单个 filter `sensor/+`，QoS0。
- **期望 payload**：`82 0d 00 01 00 08 73 65 6e 73 6f 72 2f 2b 00`
  - `82` = type 8 + flags 0x02
  - `0d` = Remaining Length 13（= 2 PacketID + 2 长度字段 + 8 filter + 1 Options = 13）
  - `00 01` = PacketID 1
  - `00 08 sensor/+` = filter（`sensor/+` 共 8 字符，长度字段=0x08）
  - `00` = QoS0
- **断言**：字节级匹配；自洽断言 `int(payload[1]) == len(payload)-2`。

#### T-017 SUBACK 多 filter Reason Codes

- **场景**：3 个 filter，AckReasonCodes=[0x00, 0x01, 0x80]。
- **期望**：SUBACK payload 最后 3 字节为 `00 01 80`。
- **断言**：`bytes.HasSuffix(payload, []byte{0x00, 0x01, 0x80})`。

#### T-018 PINGREQ/PINGRESP/DISCONNECT 3.1.1 字节

- **场景**：PingAfterMessages=true, Disconnect=true, Version=4。
- **期望**：PINGREQ=`C0 00`，PINGRESP=`D0 00`，DISCONNECT(3.1.1)=`E0 00`。
- **断言**：3 个独立 PSH-ACK 段的字节匹配。

#### T-019 DISCONNECT 5.0 含 Reason Code

- **场景**：Version=5, Disconnect=true，默认 Reason Code=0（Normal disconnection）。
- **期望**：`E0 02 00 00`（type=14, RemainingLen=2, ReasonCode=0, PropertiesLen=0）。5.0 §3.14.2：DISCONNECT 的 Variable Header = Reason Code + Properties，**Properties Length 是必填字段**（可为 0），故 v5 DISCONNECT 无属性时也必须写 `0x00` 长度字节，固定头 Remaining Length=2。
- **断言**：`bytes.Equal(payload, []byte{0xE0, 0x02, 0x00, 0x00})`。

#### T-020 5.0 CONNACK Properties Length=0x00 必填

- **场景**：Version=5, 无 Properties。
- **期望**：CONNACK = `20 03 00 00 00`（5 字节，最后 1 字节是 Properties Length=0）。
- **断言**：`bytes.Equal(payload, []byte{0x20, 0x03, 0x00, 0x00, 0x00})`。

#### T-021 5.0 PUBLISH 无属性 Properties Length=0x00 必填

- **场景**：Version=5, PUBLISH QoS0, 无 Properties, topic="t", payload="p"。
- **期望**：`30 05 00 01 74 00 70`（type=0x30, RemainingLen=5, TopicLen=1, "t", PropertiesLen=0, "p"）。核算：Remaining Length = 2 (Topic Len 长度前缀) + 1 ("t") + 1 (Properties Length) + 1 ("p") = 5 = `0x05`。
- **断言**：字节级匹配。

#### T-022 5.0 SUBACK 无属性 Properties Length=0x00 必填

- **场景**：Version=5, SUBSCRIBE 1 filter。
- **期望**：SUBACK = `90 04 00 01 00 00`（RemainingLen=4, PacketID=1, ReasonCode=0, PropertiesLen=0）。
- **断言**：字节级匹配。

#### T-023 Will Delay Interval 5.0 字节编码（ID=0x18）

- **场景**：Version=5 + `will: {topic: "client/status", payload: "offline", qos: 1, delay_interval: 5}`。
- **期望**：CONNECT Connect Flags bit2=1；payload 顺序 ClientID → Will Properties → Will Topic → Will Payload；Will Properties 段 = `05 18 00 00 00 05`（Length=5，ID 0x18 + uint32 大端 5）。
- **断言**：字节级匹配；Will Properties Length 字段值 == 其后属性字节数（自洽）。

#### T-024 v5 will 无属性 → Will Properties Length=0x00

- **场景**：Version=5 + `will: {topic: t, payload: p, qos: 0}`（无 DelayInterval 等属性）。
- **期望**：Will Flag=1 时 Will Properties 段**必填**（5.0 §3.1.3.2.3），无属性时编码长度字节 `0x00`，不可省略。
- **断言**：CONNECT payload 中 Will Properties Length 字节 == 0x00（位于 ClientID 之后、Will Topic 长度字段之前）。

#### T-025 Property Format=byte 正测

- **场景**：Version=5 + PUBLISH `properties: [{identifier: 1, format: "byte", value: "1"}]`（Payload Format Indicator=1）。
- **期望**：PUBLISH Properties 段含 `0x01 0x01`（ID 0x01 + 1 字节值 0x01）。
- **断言**：字节级匹配。

#### T-026 Property Format=vbi 负向（up PUBLISH 含 Subscription Identifier 报错）

- **场景**：Version=5 + up PUBLISH `properties: [{identifier: 11, format: "vbi", value: "200"}]`（Subscription Identifier=200，方向默认 up）。
- **期望**：Validate **报错**（client→server PUBLISH 不得携带 Subscription Identifier，5.0 §3.3.4 [MQTT-3.3.4-6]；v2.0.2 起 T-026 由正测改为负向用例——原正测场景违反规范，若需验证 0x0B 的 VBI 编码正确性，改用 SUBSCRIBE 或 down PUBLISH）。
- **断言**：`err != nil && strings.Contains(err.Error(), "subscription")`。
- **对照**：SUBSCRIBE 携带 0x0B 合法（见 T-141b）；down PUBLISH 携带 0x0B 合法且可重复（见 T-141c）；SUBSCRIBE 两个 0x0B 报错（见 T-141d）。

#### T-027 Property Format=uint32 正测

- **场景**：Version=5 + CONNECT `properties: [{identifier: 17, format: "uint32", value: "3600"}]`。
- **期望**：Properties 段含 `0x11 0x00 0x00 0x0E 0x10`（ID 0x11 + 4 字节大端 3600）。
- **断言**：字节级匹配。

#### T-028 Property Format=binary 正测

- **场景**：Version=5 + PUBLISH `properties: [{identifier: 9, format: "binary", value: "01020304"}]`（Correlation Data=4 字节）。
- **期望**：Properties 段含 `0x09 0x00 0x04 0x01 0x02 0x03 0x04`。
- **断言**：字节级匹配。

#### T-029 Property Format=stringpair 正测

- **场景**：Version=5 + CONNECT `properties: [{identifier: 38, format: "stringpair", value: "k\x00v"}]`。
- **期望**：Properties 段含 `0x26 0x00 0x01 6b 0x00 0x01 76`。
- **断言**：字节级匹配。

#### T-030 Property Format=uint16 正测

- **场景**：Version=5 + PUBLISH `properties: [{identifier: 35, format: "uint16", value: "1"}]`（Topic Alias=1）。
- **期望**：Properties 段含 `0x23 0x00 0x01`。
- **断言**：字节级匹配。

### 7.2 状态机测试（§4）

#### T-031 单会话默认流程包顺序

- **场景**：默认 spec（一条 QoS0 publish, PingAfterMessages=false, Disconnect=true）。
- **期望 TCP flags 序列**：`02 12 10 18 18 18 18 11 11 10`。
- **期望 MQTT type 序列**（仅 PSH-ACK 段）：`CONNECT CONNACK PUBLISH DISCONNECT`。
- **断言**：flags + type 双重匹配。

#### T-032 CONNACK 拒绝后跳过后续

- **场景**：ConnectAckCode=5。
- **期望**：CONNECT → CONNACK → TCP 挥手，无 SUBSCRIBE/PUBLISH/DISCONNECT。
- **断言**：PSH-ACK 段数=2（CONNECT + CONNACK）。

#### T-033 QoS1 两包交换顺序

- **场景**：单条 QoS1 message。
- **期望 MQTT type 序列**：`PUBLISH PUBACK`。
- **断言**：2 包 type 顺序 + 共享 PacketID。

#### T-034 QoS2 四包交换顺序

- **场景**：单条 QoS2 message。
- **期望 MQTT type 序列**：`PUBLISH PUBREC PUBREL PUBCOMP`。
- **断言**：4 包 type 顺序 + 共享 PacketID。

#### T-035 PINGREQ 在 PUBLISH 之后

- **场景**：PingAfterMessages=true，一条 QoS0 publish。
- **期望 MQTT type 序列**：`CONNECT CONNACK PUBLISH PINGREQ PINGRESP DISCONNECT`。
- **断言**：PINGREQ 在 PUBLISH 之后、DISCONNECT 之前。

#### T-036 DISCONNECT 是最后一个 MQTT 包

- **场景**：默认 spec。
- **期望**：所有 MQTT PSH-ACK 段中，DISCONNECT 是最后一个 MQTT 包；其后仅 TCP 挥手。
- **断言**：最后一个 PSH-ACK 段的 payload[0]=`0xE0`。

#### T-037 QoS=3 被拒绝

- **场景**：`messages: [{topic: t, payload: p, qos: 3}]`。
- **期望**：Validate 返回 error，包含 "qos"。
- **断言**：`err != nil && strings.Contains(err.Error(), "qos")`。

#### T-038 QoS2 下行方向矩阵

- **场景**：`messages: [{topic: "device/cmd", payload: "on", qos: 2, direction: "down", packet_id: 4}]`。
- **期望方向序列**：PUBLISH=down → PUBREC=up → PUBREL=down → PUBCOMP=up。
- **断言**：4 包方向逐一匹配矩阵；四包共享 PacketID=4。

#### T-039 QoS1 下行方向矩阵

- **场景**：`messages: [{topic: "device/cmd", payload: "on", qos: 1, direction: "down", packet_id: 3}]`。
- **期望 MQTT 序列**：PUBLISH(down, PacketID=3) → PUBACK(up, PacketID=3)。
- **断言**：PUBLISH 的 Direction=="down"，PUBACK 的 Direction=="up"。

#### T-040 CleanSession=true + SessionPresent=false 默认

- **场景**：默认 CleanSession=true。
- **断言**：CONNACK byte[0] bit0=0（Session Present=0）。

#### T-041 ConnectAckSessionPresent=true → CONNACK byte[0]=0x01

- **场景**：`clean_session: false, connect_ack_session_present: true`（3.1.1 §3.2.2.1 合法组合）。
- **期望**：CONNACK 完整字节 = `20 02 01 00`（固定头 + Session Present=1 + Return Code=0）；其中 Session Present 字节 = `0x01`（bit0=1，bit1-7=0）。
- **断言**：`bytes.Equal(payload, []byte{0x20, 0x02, 0x01, 0x00})`（完整包字节，风格与 T-181~T-187 一致）。

### 7.3 Plan 输出测试（§5）

#### T-042 默认 spec 包总数 = 10

- **场景**：默认 spec（一条 QoS0 publish）。
- **期望**：`len(cfgs) == 10`。
- **断言**：总数匹配。

#### T-043 MSS 分段超长 PUBLISH（整包 TCP 层切段）

- **场景**：PUBLISH payload 4000 字节，MSS=1460。
- **期望**：**PUBLISH 是单一完整的 MQTT 报文，不得拆成多个独立 MQTT 包**（MQTT 5.0 §2.1.4："Control Packets MUST be sent in their entirety"）——MSS 分段是 TCP 传输层行为：单个 PUBLISH 报文（固定头 + VH + 4000 字节 payload）按 MSS 切为 3 个 TCP 段（1460+1460+1080），**仅第一个段含 MQTT 固定头**，各段 TCP payload 拼接 = 完整 PUBLISH 字节；接收端按 Remaining Length 重组。方向 up，seq 累加。
- **断言**：TCP 层切段数为 3，`pshPayloads` 总段数 = 3 + (CONNECT+CONNACK+DISCONNECT) = 6；3 个 TCP 段 payload 拼接 = 原 PUBLISH 报文（固定头 `0x30 <RL>` + Topic/VH + 4000 字节 payload）；MQTT 层仍只解析出 1 个 PUBLISH 包（非 3 个）。
- **实现注**：§10.3.4"emit 辅助函数参考 socks5 segmentByMSS"处加注——**MQTT PUBLISH 整包不拆，仅 TCP 层分段**；不要把 payload 切成 3 段各写一个完整 MQTT 固定头（会产出 3 个畸形 PUBLISH）。

#### T-044 MSS=MinMSS 边界接受

- **场景**：`TCP.MSS=536`（恰好等于 MinMSS=536）。
- **期望**：planner 接受；单个 PUBLISH 报文按 536 切为 8 个 TCP 段（536×7+248），仅首段含 MQTT 固定头（整包不拆语义同 T-043）。
- **断言**：TCP 段数=8。

#### T-045 MSS=MinMSS-1 边界拒绝

- **场景**：`TCP.MSS=535`（< MinMSS=536）。
- **期望**：Validate 报错。
- **断言**：`err` 包含 "MSS"。

#### T-046 MSS 过小报错

- **场景**：`TCP.MSS=100`（< MinMSS=536）。
- **期望**：Validate 报错。
- **断言**：`err` 包含 "MSS"。

#### T-047 TCP 握手含 MSS/WinScale/SACK 选项

- **场景**：默认 spec。
- **期望**：SYN 与 SYN-ACK 的 L4.TCPOptions 含 Kind=2(MSS)、Kind=3(WinScale)、Kind=4(SACK)。
- **断言**：遍历 TCPOptions，3 个 Kind 都存在。

#### T-048 TCP 挥手四步

- **场景**：默认 spec, Disconnect=true。
- **期望**：最后 3 个 TCP 包 flags 为 `0x11 0x11 0x10`（FIN-ACK, FIN-ACK, ACK）。
- **断言**：flags 序列匹配。

#### T-049 seq/ack 连续性

- **场景**：默认 spec。
- **期望**：每个 TCP 包的 seq + payload_len = 下一个同方向包的 seq；ack 反映对端 seq 累加。
- **断言**：自实现 seq/ack 连续性检查。

#### T-050 Disconnect=false 模型异常断开

- **场景**：`Disconnect: *false`。
- **期望**：无 DISCONNECT PSH-ACK 段；TCP 挥手仍发（模拟 FIN-based 断开）。
- **断言**：MQTT type 序列无 DISCONNECT；TCP 挥手存在。

#### T-051 RST=true 模型硬断开

- **场景**：`spec.TCP.RST = true` + `Disconnect: *false`。
- **期望**：TCP 挥手替换为 RST 段。
- **断言**：最后一个 TCP 包 flags 含 RST 位 (0x04)。

#### T-052 InitialSeq 固定 ISN

- **场景**：`spec.TCP.InitialSeq = 1000`。
- **期望**：SYN 包 seq=1000。
- **断言**：`cfgs[0].L4.Seq == 1000`。

#### T-053 keep_alive=0 → CONNECT `00 00`

- **场景**：`keep_alive: 0`（显式 0 = 禁用保活，与缺省 60 区分，`*int` 表达）。
- **期望**：CONNECT Keep Alive 字段 = `0x00 0x00`（服务端视为无限保活）。
- **断言**：字节级匹配；与 T-001（`0x00 0x3C`）对照。

### 7.4 业务场景测试（§6）

#### T-054 QoS0 publish 完整流程

- **场景**：见 S2。
- **断言**：见 S2 关键断言。

#### T-055 QoS1 publish 完整流程

- **场景**：见 S3。
- **断言**：PacketID 一致性；PUBLISH `0x32`，PUBACK `0x40`。

#### T-056 QoS2 publish 完整流程

- **场景**：见 S4。
- **断言**：4 包共享 PacketID；PUBREL `0x62`。

#### T-057 subscribe + 下行 publish

- **场景**：见 §6 S5（client 订阅 sensor/+，broker 推送下行 PUBLISH）。
- **断言**：SUBSCRIBE flags=0x02，下行 PUBLISH 方向=down。

#### T-058 will message 流程

- **场景**：见 S9。
- **断言**：Will Flag=1, 无 DISCONNECT, will PUBLISH 下行。

#### T-059 retain message 多 session

- **场景**：自建输入（两 session：pub-retain 发布 Retain=1，sub-retain 订阅后收到 retain 副本；无独立 S 场景，多 session 独立 4-tuple 结构见 S10）。
- **断言**：两 session 独立, Retain=1。

#### T-060 username/password 认证

- **场景**：见 S13。
- **断言**：Connect Flags=0xC2, 字段顺序 ClientID→Username→Password。

#### T-061 MQTT 5.0 Properties

- **场景**：见 S12。
- **断言**：Protocol Level=5, Property 编码正确，ID 0x11/0x22/0x26/0x23 字节匹配。

#### T-062 keepalive PINGREQ/PINGRESP

- **场景**：见 S7。
- **断言**：KeepAlive=30 字段, PINGREQ=`C0 00`, PINGRESP=`D0 00`。

#### T-063 多会话 3 个客户端

- **场景**：见 S10。
- **断言**：3 FlowID 独立, SrcPort 自增, payload 分别 a/b/c。

#### T-064 多会话 SrcPort 显式不自动递增

- **场景**：Sessions 中每个显式设 SrcPort=50000/50001/50002。
- **断言**：3 flow 的 SrcPort 分别为 50000/50001/50002（用户值优先）。

#### T-065 会话级字段覆盖与继承

- **场景**：顶层 `username: "top"`、`will: {...}`、`properties: [...]`、`ping_after_messages: true`；session1 显式覆盖 `username: "s1"`、`will: {...}`、`properties: [...]`、`ping_after_messages: false`；session2 全部缺省。
- **期望**：session1 用覆盖值（Username="s1"）；session2 继承顶层值（Username="top"、PingAfterMessages=true）；slice 字段（Will/Properties）非 nil 时整体替换、nil 时继承。
- **断言**：两 session 的 CONNECT 字节分别含各自 Username；session2 flow 含 PINGREQ/PINGRESP，session1 flow 不含。

#### T-066 顶层 messages + 3 sessions 继承/替换语义

- **场景**：顶层 `messages: [{topic: "t/0", payload: "x", qos: 0}]` + 3 个 session（session1 有自己 messages，session2/3 无 messages）。
- **期望**：session1 的 Messages 非空 → 整体替换（不追加父级 `t/0`）；session2/3 的 Messages 为 nil → 继承顶层并各自发送一条 `t/0`（每 session 恰好 1 条，无跨 session 重复）。
- **断言**：session1 flow 无 `t/0`；session2/3 flow 各含 1 条 `t/0`；总 PUBLISH 数 = 1 + 1 + 1 = 3。

### 7.5 异常与边界测试（§6 边界场景）

#### T-067 CONNACK 拒绝码 1 跳过后续

- **场景**：ConnectAckCode=1。
- **断言**：CONNACK byte[1]=1；后续 MQTT 包数=0。

#### T-068 CONNACK 拒绝码 5 跳过后续

- **场景**：ConnectAckCode=5。
- **断言**：CONNACK byte[1]=5；后续 MQTT 包数=0。

#### T-069 PUBLISH DUP=1 + QoS0 报错

- **场景**：`messages: [{topic: t, payload: p, qos: 0, dup: true}]`。
- **期望**：Validate 报错。
- **断言**：`err` 包含 "DUP" 或 "QoS"。

#### T-070 订阅通配符 `+` 接受

- **场景**：filter=`sport/+/score`。
- **断言**：Validate 通过；SUBSCRIBE payload 含 filter 字面量。

#### T-071 订阅 `#` 不在末尾报错

- **场景**：filter=`sport/#/score`。
- **期望**：Validate 报错。
- **断言**：`err` 包含 "wildcard" 或 "#"。

#### T-072 空 topic PUBLISH 报错（无 Topic Alias）

- **场景**：`messages: [{topic: "", payload: p, qos: 0}]`（无 Properties，Version=4）。
- **断言**：Validate 报错（3.1.1 不支持 Topic Alias，空 topic 一律报错）。

#### T-073 空 topic + Topic Alias=1 首包报错（映射未建立）

- **场景**：Version=5, CONNECT 声明 Topic Alias Maximum=1（规则 §8.1 10b），`messages: [{topic: "", payload: p, qos: 0, properties: [{identifier: 35, format: "uint16", value: "1"}]}]`（alias=1 但本 flow 内无前置非空 topic PUBLISH 建立映射）。
- **断言**：Validate 报错（首个携带某 Topic Alias 的 PUBLISH 必须有非空 Topic Name）。

#### T-074 空 topic + Topic Alias=1 复用合法（映射已建立）

- **场景**：Version=5, CONNECT 声明 Topic Alias Maximum=1，`messages: [{topic: "sensor/temp", ...properties: [TopicAlias=1]}, {topic: "", ...properties: [TopicAlias=1]}]`。
- **断言**：Validate 通过；第二条 PUBLISH Topic Name 长度字段=0；Properties 段含 `0x23 0x00 0x01`。

#### T-074b PUBLISH 用 Topic Alias 但 CONNECT 未声明 Topic Alias Maximum 报错

- **场景**：Version=5, CONNECT properties 不含 0x22，`messages: [{topic: "sensor/temp", payload: p, qos: 0, properties: [{identifier: 35, format: "uint16", value: "1"}]}]`。
- **断言**：Validate 报错（CONNECT 未声明 Topic Alias Maximum（缺省 0）即使用 Topic Alias，5.0 §3.1.2.11.5；规则 §8.1 10b）。

#### T-075 超长 topic 报错

- **场景**：topic 长度 65536。
- **断言**：Validate 报错（2 字节长度字段溢出）。

#### T-076 client_id 空字符串自动生成

- **场景**：`ClientID: ""`。
- **期望**：CONNECT payload ClientID 非空，前缀 `trafficgen-`；Connect Flags bit1 CleanSession=1 强制。
- **断言**：ClientID 长度 > 0 且前缀匹配；CleanSession=true。

#### T-077 剩余长度 127 边界

- **场景**：PUBLISH payload 长度使 RemainingLen=127。Remaining Length = 2 (Topic Len) + 1 (topic="t") + N (payload) = 3+N = 127，故 N=124。
- **断言**：VBI 字节为 `0x7F`（单字节）。

#### T-078 剩余长度 128 边界

- **场景**：PUBLISH payload 长度使 RemainingLen=128。
- **断言**：VBI 字节为 `0x80 0x01`（两字节）。

#### T-079 剩余长度 16383 边界

- **场景**：PUBLISH payload 使 RemainingLen=16383。
- **断言**：VBI 字节为 `0xFF 0x7F`。

#### T-080 剩余长度 16384 边界

- **场景**：PUBLISH payload 使 RemainingLen=16384。
- **断言**：VBI 字节为 `0x80 0x80 0x01`。

#### T-081 剩余长度 2097152 边界

- **场景**：PUBLISH payload 使 RemainingLen=2097152。
- **断言**：VBI 字节为 `0x80 0x80 0x80 0x01`。

#### T-082 payload 0 字节 PUBLISH

- **场景**：`messages: [{topic: t, payload: "", qos: 0}]`。
- **期望**：PUBLISH payload 段长度 0；RemainingLen 仅含 Topic Name 长度字段(2) + Topic(1) = 3。
- **断言**：`len(publishPayload) == 0`；RemainingLen byte=3。

#### T-083 topic 65535 字节

- **场景**：topic 长度 65535（需多 TCP 段）。
- **期望**：Topic Name 长度字段 `0xFF 0xFF`（65535，UTF-8 字符串合法上限，见 §2.4）；PUBLISH 跨多段。
- **断言**：Validate 通过；长度字段 + 段拼接 = 原 topic。Remaining Length = 2 (Topic Len 长度前缀) + 65535 + 0/2 (PacketID，QoS0 无) + payload 长度，VBI 需 4 字节编码（> 16383）。

#### T-084 PacketID 省略/显式 0 自动分配

- **场景**：`messages: [{topic: t, payload: p, qos: 1}]`（不显式设 packet_id，等同于 packet_id=0）。
- **断言**：Validate 通过；PUBLISH 与 PUBACK 共享同一自动分配 PacketID（planner 从 1 起自增），PUBLISH 含 `0x00 0x01`，PUBACK 含 `0x00 0x01`。

#### T-085 Will QoS=3 报错

- **场景**：`will: {topic: t, payload: p, qos: 3}`。
- **断言**：Validate 报错。

#### T-086 Will 无 topic 报错

- **场景**：`will: {payload: p}`。
- **断言**：Validate 报错。

#### T-087 Username 空 + Password 非空 报错（3.1.1）

- **场景**：Version=4, `Password: "x"`（Username 空）。
- **断言**：Validate 报错（3.1.1：Username Flag=0 时 Password Flag 必须 0）。

#### T-088 Username 空 + Password 非空 接受（5.0）

- **场景**：Version=5, `Password: "x"`（Username 空）。
- **断言**：Validate 通过（5.0 允许 Password 无 Username）；Connect Flags bit6=1, bit7=0。

#### T-089 Version=3 报错

- **场景**：`Version: 3`。
- **断言**：Validate 报错（仅支持 4 和 5）。

#### T-090 Version=6 报错

- **场景**：`Version: 6`。
- **断言**：Validate 报错。

#### T-091 SUBACK Reason Codes 长度不匹配报错

- **场景**：filters 3 个，AckReasonCodes=[0,1]（2 个）。
- **断言**：Validate 报错。

#### T-092 Subscriptions Filters 空报错

- **场景**：`subscriptions: [{packet_id: 1}]`（无 filters）。
- **断言**：Validate 报错。

#### T-093 Property Format=binary 非法 hex

- **场景**：`Properties: [{Identifier: 9, Format: "binary", Value: "xyz"}]`。
- **断言**：Validate 报错。

#### T-094 Property Format=uint32 非数字

- **场景**：`Properties: [{Identifier: 17, Format: "uint32", Value: "abc"}]`。
- **断言**：Validate 报错。

#### T-095 Version=4 时设置 Properties 报错

- **场景**：`Version: 4, Properties: [{Identifier: 17, Format: "uint32", Value: "3600"}]`。
- **断言**：Validate 报错（3.1.1 无 Properties）。

#### T-096 DstPort 默认 1883

- **场景**：spec 不设 DstPort。
- **断言**：planner 输出的 L4.DstPort=1883。

#### T-097 默认 spec 全空字段

- **场景**：`MQTTConfig{}`（全空）。
- **期望**：Version=4, ClientID 自动生成, CleanSession=true, KeepAlive=60, 单条 CONNECT/CONNACK/DISCONNECT（无 message）。
- **断言**：包总数 = 3 握手 + 3 MQTT + 3 挥手 = 9。

#### T-098 GroupID 元数据传递

- **场景**：spec.GroupID 非空。
- **断言**：每个 PacketConfig.Metadata 含 group_id 字段。

#### T-099 ConnectAckCode=6 (3.1.1) 报错

- **场景**：`version: 4, connect_ack_code: 6`。
- **断言**：Validate 报错（3.1.1 合法值仅 0-5）。

#### T-100 ConnectAckCode=130/135/144 (5.0) 接受

- **场景**：表驱动：`version: 5` + connect_ack_code ∈ {130（协议错误）、135（未授权）、144（主题名无效）}。
- **期望**：Validate 通过；CONNACK byte[2] 分别 = `0x82`/`0x87`/`0x90`；Code≠0 → 后续无 SUBSCRIBE/PUBLISH/PING/DISCONNECT。
- **断言**：表驱动字节断言 + 后续 MQTT 包数=0。

#### T-101 ConnectAckCode=137 (5.0) 接受

- **场景**：`version: 5, connect_ack_code: 137`（Server busy）。
- **期望**：Validate 通过；CONNACK byte[2]=`0x89`。
- **断言**：字节级匹配。

#### T-102 ConnectAckCode=148 (5.0) 报错

- **场景**：`version: 5, connect_ack_code: 148`。
- **断言**：Validate 报错（148=Topic Alias invalid 仅适用于 DISCONNECT，不适用于 CONNACK）。

#### T-103 ConnectAckCode=141 (5.0) 报错

- **场景**：`version: 5, connect_ack_code: 141`。
- **断言**：Validate 报错（141=Keep Alive timeout 仅适用于 DISCONNECT）。

#### T-104 ConnectAckCode=200 (5.0) 报错

- **场景**：`version: 5, connect_ack_code: 200`。
- **断言**：Validate 报错（5.0 CONNACK 合法集不含 200，最大 0x9F=159）。

#### T-105 CleanSession=true + SessionPresent=true 报错

- **场景**：`clean_session: true, connect_ack_session_present: true`。
- **断言**：Validate 报错（3.1.1 §3.2.2.1）。

#### T-106 ConnectAckCode≠0 + SessionPresent=true 报错

- **场景**：`connect_ack_code: 5, connect_ack_session_present: true`。
- **断言**：Validate 报错（5.0 §3.2.2.2）。

#### T-107 PUBLISH topic 含通配符报错

- **场景**：表驱动：`messages: [{topic: "a/#", ...}]`、`messages: [{topic: "a/+/b", ...}]`。
- **断言**：Validate 报错（PUBLISH Topic Name 禁通配符）。

#### T-108 PUBLISH properties 含 0x11 报错

- **场景**：`messages: [{topic: t, payload: p, qos: 0, properties: [{identifier: 17, format: "uint32", value: "3600"}]}]`（Session Expiry 仅 CONNECT/CONNACK/DISCONNECT）。
- **断言**：Validate 报错（Property Identifier × 包类型白名单不匹配）。

#### T-109 重复 Content Type 报错

- **场景**：`properties: [{identifier: 3, format: "string", value: "a"}, {identifier: 3, format: "string", value: "b"}]`（同包同 ID 重复，非 User Property）。
- **断言**：Validate 报错；对照：User Property（0x26）重复合法。

#### T-110 v4 + Will DelayInterval≠0 报错

- **场景**：`version: 4, will: {topic: t, payload: p, delay_interval: 5}`。
- **断言**：Validate 报错（v5-only 字段在 v4 一律报错）。

#### T-111 $share 共享订阅合法

- **场景**：Version=5 + filter=`$share/g/sensor/+`。
- **断言**：Validate 通过；SUBSCRIBE payload 含 filter 字面量。

#### T-112 $share 缺 filter 非法

- **场景**：表驱动：Version=5 + filter=`$share/g`（缺少 filter 部分）；Version=4 + filter=`$share/g/sensor/+`（5.0 特性）。
- **断言**：两条均 Validate 报错。

#### T-113 空 ClientID + 显式 CleanSession=false

- **场景**：`client_id: "", clean_session: false`。
- **期望**：planner 强制 CleanSession=true（3.1.1 §3.1.3.1），Validate 通过，不报错。
- **断言**：CONNECT Connect Flags bit1=1（CleanSession 被强制置 1）。

#### T-114 topic 含 U+0000 报错

- **场景**：`messages: [{topic: "a b", payload: p, qos: 0}]`。
- **断言**：Validate 报错（UTF-8 字符串禁止 U+0000）。

#### T-115 v5 CONNECT 无属性 Properties Length=0x00

- **场景**：Version=5，CONNECT 无 properties（仅此行为此场景独有；CONNACK/PUBLISH/SUBACK 的无属性版已分别由 T-020/T-021/T-022 覆盖）。
- **断言**：CONNECT 在 Keep Alive 后输出 Properties Length 字节 `0x00`（5.0 §2.2.2.1 必填）；固定头 Remaining Length 与字节序列自洽。

#### T-116 decodeVBI 负向路径

- **场景**：三条 malformed VBI（5.0 §1.5.5）：
  1. `decodeVBI([]byte{0x80, 0x80, 0x80, 0x80, 0x01})`（5 字节超上限）；
  2. `decodeVBI([]byte{0x80, 0x00})`（非最小编码：值 0 用 2 字节）；
  3. `decodeVBI([]byte{0x80, 0x80, 0x80, 0x80})`（第 4 字节仍带续位）。
- **期望**：全部返回 error，且错误类别可区分。
- **断言**：`err != nil` 且错误信息匹配各自类别。

#### T-117 report 层字段聚合

- **场景**：default spec（一条 QoS0 publish）经全链路（task handler → engine → Plan → report）后，`internal/core/report.go` 聚合 mqttProtRpt 28 字段。
- **期望**：`version=4`、`type` 分布 `{connect:1, connack:1, publish:1, disconnect:1}`、`qos_level=0`、`retain=0`、`dup=0`、`reason_codes=[0]`、`connack_session_present=0`、`client_id="c1"`、`keep_alive=60`、`clean_session=1`、`will_flag=0`、`disconnect_flag=1`、`topic="sensor/temp"`、`payload_len=4`、`messages_count=1`、`sessions_count=1` 等 28 字段。
- **断言**：report JSON 中 28 字段逐一匹配。

#### T-118 topic 含 UTF-8 多字节字符

- **场景**：topic=`传感器/温度`。
- **断言**：Topic Name 长度字段=字节数（非字符数）；planner 不破坏 UTF-8。

#### T-119 PacketID 接近 65535 溢出

- **场景**：`packet_id: 65535`，QoS1。
- **断言**：PUBLISH + PUBACK PacketID=`0xFF 0xFF`；planner 内部自增从 65535 → 1（wrap，不溢出到 0）。

#### T-120 字段冲突：Will 与无 ClientID

- **场景**：`ClientID: ""` + `will: {topic: t, payload: p, qos: 1}`。
- **期望**：空 ClientID 强制 CleanSession=true，但 Will 仍允许。
- **断言**：Validate 通过；Connect Flags bit1=1 + bit2=1。

### 7.6 集成测试（CLAUDE.md §4 必须覆盖跨层）

#### T-121 strategy_convert case "mqtt" 解析

- **场景**：用户 JSON `{"protocol": "mqtt", "mqtt": {"client_id": "x"}}` 经 mapToFlowSpec。
- **断言**：`spec.MQTT != nil && spec.MQTT.ClientID == "x"`。

#### T-122 strategy_convert 默认端口 1883

- **场景**：JSON 不设 dst_port。
- **断言**：`spec.DstPort == 1883`。

#### T-123 main.go RegisterPlanner

- **场景**：启动 server，调用 `engine.Planner("mqtt")`。
- **断言**：返回非 nil 且类型为 `*mqtt.Planner`。

#### T-124 task handler → engine → Plan 全链路

- **场景**：通过 MCP/HTTP 提交一个 mqtt task，验证 configChan 输出。
- **断言**：task 状态 completed；生成的 pcap 文件含 MQTT 字节。

#### T-125 ValidationErrors 透传到 task 失败

- **场景**：用户 spec 含 `qos: 3`（非法）。
- **断言**：task 状态 failed；error message 含 "qos"。

#### T-126 多会话 SubFlow 机制独立 4-tuple

- **场景**：3 个 session，未显式 SrcPort。
- **断言**：3 flow 的 (SrcIP, DstIP, SrcPort, DstPort) 4-tuple 互不相同；SrcPort 自增。

#### T-127 PacketWorkers=8 不乱序

- **场景**：默认 spec, `PacketWorkers: 8`。
- **断言**：生成的 pcap 中包序与 PacketIndex 一致（验证 resequencer）。

### 7.7 对抗性测试（CLAUDE.md §6 §8）

#### T-128 并发多 task 不串包

- **场景**：同时提交 5 个 mqtt task（不同 client_id），并发跑 Plan。
- **断言**：每个 task 的 cfgs 中 ClientID 字节序列不含其他 task 的 ClientID。

#### T-129 -race 干净

- **场景**：所有测试 `go test -race`。
- **断言**：无 data race 报告。

#### T-130 ctx 取消中途返回

- **场景**：Plan 协程启动后立即 `ctx.Cancel()`。
- **断言**：configChan 关闭且已发出的 cfgs 数 < 完整数。

#### T-131 0 字节 payload + 0 字节 will 边界

- **场景**：`will: {topic: t, payload: "", qos: 0}` + `messages: [{topic: t2, payload: "", qos: 0}]`。
- **断言**：不 panic；CONNECT 含 Will Payload 长度字段=0；PUBLISH payload 段长度=0。

### 7.8 5.0 Reason Code 域完整测试

#### T-132 CONNACK 5.0 全部 22 个有效代码（逐条独立断言）

- **场景**：覆盖 §2.6 表中全部 22 个 CONNACK 代码，每条代码**独立测试函数/独立子测试**（非表驱动合并，避免行内断言失败掩盖其他行）。
- **断言**：每行 Validate 通过；CONNACK byte[2] 匹配；Code≠0 → 后续无 MQTT 包。
- **与 T-004 的关系**：T-004 在 §7.1 表驱动覆盖同一集合；T-132 逐条独立断言，确保某一行失败时测试用例定位到具体代码（CLAUDE.md §8：表驱动测试不掩盖字段缺漏）。

#### T-133 DISCONNECT 5.0 全部 31 个有效代码

- **场景**：表驱动 31 行，覆盖 §2.12 表中所有 DISCONNECT 代码。
- **断言**：每行 Validate 通过；DISCONNECT 字节含对应 Reason Code。

#### T-134 SUBACK 5.0 扩展 Reason Code

- **场景**：Version=5, AckReasonCodes ∈ {0x80, 0x83, 0x87, 0x8F, 0x91, 0x97, 0x9E, 0xA1, 0xA2}（5.0 扩展 9 项）。
- **断言**：Validate 通过；SUBACK payload 含对应字节。
- **补充**：0x00/0x01/0x02（3.1.1 granted 三档）由 T-017/T-192 覆盖；0x80（Failure）与 5.0 扩展 9 项合并后共 11 项 = 规范 Table 3-8 完整集（v2.0.2 补 0x91/0x97）。

#### T-135 5.0 CONNACK 拒绝 1-5 报错

- **场景**：Version=5, ConnectAckCode ∈ {1, 2, 3, 4, 5}。
- **断言**：Validate 报错（1-5 在 5.0 中不是有效 CONNACK 代码）。

### 7.9 Property × 包类型白名单完整测试

#### T-136 CONNECT 允许的 Property ID

- **场景**：表驱动，Version=5，CONNECT Properties 分别设 ID ∈ {0x11, 0x15, 0x16, 0x17, 0x19, 0x21, 0x22, 0x26, 0x27}。
- **断言**：每个 ID Validate 通过。

#### T-137 CONNECT 禁止的 Property ID

- **场景**：表驱动，Version=5，CONNECT Properties 分别设 ID ∈ {0x01, 0x02, 0x03, 0x08, 0x09, 0x0B, 0x12, 0x13, 0x18, 0x1A, 0x1C, 0x1F, 0x23, 0x24, 0x25, 0x28, 0x29, 0x2A}。
- **断言**：每个 ID Validate 报错（不在 CONNECT 白名单）。

#### T-138 PUBLISH 允许的 Property ID

- **场景**：表驱动，Version=5，PUBLISH Properties 分别设 ID ∈ {0x01, 0x02, 0x03, 0x08, 0x09, 0x0B, 0x23, 0x26}。
- **断言**：每个 ID Validate 通过。

#### T-139 PUBLISH 禁止的 Property ID

- **场景**：表驱动，Version=5，PUBLISH Properties 分别设 ID ∈ {0x11, 0x12, 0x13, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1C, 0x1F, 0x21, 0x22, 0x24, 0x25, 0x27, 0x28, 0x29, 0x2A}。
- **断言**：每个 ID Validate 报错。

#### T-140 Will Properties 允许的 Property ID

- **场景**：表驱动，Version=5，Will（通过 CONNECT）Properties 分别设 ID ∈ {0x01, 0x02, 0x03, 0x08, 0x09, 0x18, 0x26}。
- **断言**：每个 ID Validate 通过；Will Properties 段含对应字节。

#### T-141 Will Properties 禁止的 Property ID

- **场景**：表驱动，Version=5，Will Properties 设 ID ∈ {0x11, 0x23, 0x26}（除 User Property 0x26 外 Will 段不允许的 ID）。
- **断言**：除 0x26 外 Validate 报错。

#### T-141b SUBSCRIBE 携带 Subscription Identifier（0x0B）合法

- **场景**：Version=5 + SUBSCRIBE `properties: [{identifier: 11, format: "vbi", value: "200"}]`（Subscription Identifier=200，SUBSCRIBE 白名单含 0x0B，5.0 §3.8.2.1.2）。
- **期望**：Validate 通过；SUBSCRIBE Properties 段含 `0x0B 0xC8 0x01`（ID 0x0B + VBI 编码 200 = `0xC8 0x01`）——0x0B 的 VBI 编码正测在此覆盖（v2.0.2 起自 T-026 移入）。
- **断言**：字节级匹配。

#### T-141c down PUBLISH 携带 Subscription Identifier 合法（可重复）

- **场景**：Version=5 + down PUBLISH（`direction: "down"`，模拟 broker 向订阅者转发）`properties: [{identifier: 11, format: "vbi", value: "200"}, {identifier: 11, format: "vbi", value: "201"}]`（两个 0x0B，多订阅匹配转发）。
- **期望**：Validate 通过；Properties 段含 `0x0B 0xC8 0x01 0x0B 0xC9 0x01`。
- **断言**：字节级匹配（0x0B 的重复例外仅限 down PUBLISH，5.0 §3.3.2.3.8）。

#### T-141d SUBSCRIBE 两个 Subscription Identifier 报错

- **场景**：Version=5 + SUBSCRIBE `properties: [{identifier: 11, format: "vbi", value: "200"}, {identifier: 11, format: "vbi", value: "201"}]`。
- **断言**：Validate 报错（SUBSCRIBE 中 0x0B 不得重复，5.0 §3.8.2.1.2）。

### 7.10 VBI 边界完整测试

#### T-142 encodeVBI 全部边界值

- **场景**：表驱动 encodeVBI(0/127/128/16383/16384/2097151/2097152/268435455)。
- **断言**：8 个边界值编码字节正确。

#### T-143 decodeVBI 全部边界值

- **场景**：反向解码 8 个边界值。
- **断言**：返回值 + 字节数正确。

#### T-144 encodeVBI 负数报错

- **场景**：encodeVBI(-1)。
- **断言**：返回 error。

#### T-145 encodeVBI 超大值报错

- **场景**：encodeVBI(268435456)（超出 4 字节范围）。
- **断言**：返回 error。

### 7.11 多会话与继承测试

#### T-146 多会话 FlowID 含 :mqtt-i 后缀

- **场景**：3 个 session。
- **断言**：3 flow 的 FlowID 分别含 `:mqtt-0`/`:mqtt-1`/`:mqtt-2`。

#### T-147 多会话 TCP seq 独立

- **场景**：2 个 session，每个发 1 条 QoS0 publish。
- **断言**：flow1 的 TCP seq 不影响 flow2；各 flow 内 seq 连续。

#### T-148 多会话 PacketIndex 独立

- **场景**：3 个 session。
- **断言**：每个 flow 的 PacketIndex 从 0 起，不跨 flow 累加。

#### T-149 多会话 GroupID 共享

- **场景**：spec.GroupID="g1" + 3 个 session。
- **断言**：3 flow 的 Metadata group_id 均为 "g1"。

#### T-150 Session 显式 SrcPort 优先

- **场景**：Sessions[0].SrcPort=50000, HasExplicitSrcPort=true。
- **断言**：flow0 的 SrcPort=50000（不自动递增）。

### 7.12 订阅选项测试（5.0）

#### T-151 NoLocal=1 接受（5.0）

- **场景**：Version=5, filter with NoLocal=true。
- **断言**：Validate 通过；SUBSCRIBE payload Options byte bit2=1。

#### T-152 NoLocal=1 报错（3.1.1）

- **场景**：Version=4, filter with NoLocal=true。
- **断言**：Validate 报错（3.1.1 不支持 NoLocal）。

#### T-153 RetainAsPublished=1 接受（5.0）

- **场景**：Version=5, filter with RetainAsPublished=true。
- **断言**：Validate 通过；Options byte bit3=1。

#### T-154 RetainHandling=2 接受（5.0）

- **场景**：Version=5, filter with RetainHandling=2。
- **断言**：Validate 通过；Options byte bit4-5=10。

#### T-155 RetainHandling=3 报错（5.0）

- **场景**：Version=5, filter with RetainHandling=3。
- **断言**：Validate 报错（RetainHandling=11 是 Protocol Error）。

### 7.13 字段计数与扩展表测试

#### T-156 扩展表 28 字段完整聚合

- **场景**：复杂 spec（含 will/subscribe/publish/properties，Version=5）。
- **断言**：report JSON 含 28 个 mqttProtRpt 字段（tx_id/version/type/dup/qos_level/retain/reason_codes/connack_session_present/client_id/keep_alive/clean_session/will_flag/will_topic/will_qos/will_retain/username/password_set/direction/topic/payload_len/subscriptions_count/filters_count/messages_count/ping_count/disconnect_flag/sessions_count/properties_count/topic_alias_used）。

#### T-157 topic_alias_used 字段

- **场景**：Version=5, PUBLISH 含 Topic Alias Property。
- **断言**：report topic_alias_used=1。

#### T-158 will_topic 字段

- **场景**：spec 含 will。
- **断言**：report will_topic 等于 will.Topic 值。

### 7.14 规范一致性补充测试

#### T-159 CONNECT 第二个报错

- **场景**：planner 在 CONNECT 后又发 CONNECT。
- **断言**：planner 不产出第二个 CONNECT（规范禁止）。

#### T-160 PUBLISH QoS0 + PacketID 报错

- **场景**：`messages: [{topic: t, payload: p, qos: 0, packet_id: 1}]`（QoS0 不应有 PacketID）。
- **期望**：Validate 报错（QoS0 PUBLISH 必须无 Packet Identifier，5.0 §3.3.2.2/3.1.1 §3.3.2.2）。
- **断言**：`err != nil && strings.Contains(err.Error(), "packet_id")`。

#### T-161 PUBLISH QoS=3 报错

- **场景**：`qos: 3`。
- **断言**：Validate 报错。

#### T-162 SUBSCRIBE PacketID=0 自动分配

- **场景**：`subscriptions: [{filters: [...]}]`（不设 PacketID）。
- **断言**：SUBSCRIBE 含自动分配的 PacketID（从 1 起自增，与 MQTTMessage 共享计数器）。

#### T-163 DISCONNECT 后无 MQTT 包

- **场景**：默认 spec。
- **断言**：DISCONNECT 是最后一个 MQTT PSH-ACK 段。

#### T-164 CONNACK 3.1.1 byte[0] bit1-7=0

- **场景**：3.1.1 CONNACK。
- **断言**：byte[0] ∈ {0x00, 0x01}（仅 bit0 有效）。

#### T-165 CONNACK 5.0 byte[0] bit1-7=0

- **场景**：5.0 CONNACK。
- **断言**：byte[0] ∈ {0x00, 0x01}。

#### T-166 SUBSCRIBE 至少 1 个 filter

- **场景**：`subscriptions: [{packet_id: 1, filters: []}]`。
- **断言**：Validate 报错。

#### T-167 UTF-8 字符串长度字段边界（0xFFFF = 65535 合法）

- **场景**：表驱动两行——topic 长度 65535；topic 长度 65536。
- **断言**：
  1. topic 长度 65535 → Validate 通过（UTF-8 字符串长度字段合法范围 0-65535 全范围，无保留值，见 §2.4）；
  2. topic 长度 65536 → Validate 报错（超出 2 字节长度字段可编码上限 65535）。

### 7.15 异常断开与 RST 测试

#### T-168 RST=true 无 MQTT DISCONNECT

- **场景**：`TCP.RST=true, Disconnect: *false`。
- **断言**：无 DISCONNECT 字节；最后 TCP 包 flags 含 RST。

#### T-169 RST=true + will message

- **场景**：`TCP.RST=true, Disconnect: *false, will: {...}`。
- **断言**：will PUBLISH + PUBACK 编排在 RST 之前（broker 视角建模：模拟 broker 已收到断开事件后代发 will；真实规范中 will 在异常断开之后由 broker 发布，见 §4.4 模型偏差说明——RST 后 TCP 连接已终止，同一 4-tuple 上不能再传 MQTT 包）；包总数 = 8（3 握手 + CONNECT + CONNACK + will PUBLISH + PUBACK + RST）。

#### T-170 FIN 挥手 + will message

- **场景**：`Disconnect: *false, will: {...}`（RST=false）。
- **断言**：will PUBLISH + PUBACK + FIN 挥手；包总数=10（will PUBLISH 编排在 FIN 之前，broker 视角建模，见 §4.4 模型偏差说明）。

### 7.16 Property 编码负向测试

#### T-171 Property Identifier 超范围报错

- **场景**：`Properties: [{Identifier: 100, Format: "byte", Value: "1"}]`（100 未分配）。
- **断言**：Validate 报错。

#### T-172 Property Value 溢出 uint16

- **场景**：`Properties: [{Identifier: 35, Format: "uint16", Value: "70000"}]`（70000 > 65535）。
- **断言**：Validate 报错。

#### T-173 Property Value 溢出 uint32

- **场景**：`Properties: [{Identifier: 17, Format: "uint32", Value: "5000000000"}]`（> 4294967295）。
- **断言**：Validate 报错。

#### T-174 Property Value 溢出 byte

- **场景**：`Properties: [{Identifier: 1, Format: "byte", Value: "256"}]`。
- **断言**：Validate 报错。

#### T-175 Property binary 长度超 65535

- **场景**：`Properties: [{Identifier: 9, Format: "binary", Value: <65536 字节 hex>}]`。
- **断言**：Validate 报错。

### 7.17 Session 字段继承完整测试

#### T-176 Session CleanSession 继承

- **场景**：顶层 CleanSession=false, session 不设。
- **断言**：session flow 继承 CleanSession=false。

#### T-177 Session KeepAlive 继承

- **场景**：顶层 KeepAlive=120, session 不设。
- **断言**：session flow CONNECT KeepAlive 字段=120。

#### T-177b Session KeepAlive 显式 0 覆盖

- **场景**：顶层 KeepAlive=60, session `keep_alive: 0`。
- **断言**：session flow CONNECT KeepAlive 字段=`0x00 0x00`（`*int` 显式 0 覆盖，非继承顶层 60；见 §8.6）。

#### T-178 Session Disconnect 继承

- **场景**：顶层 Disconnect=*false, session 不设。
- **断言**：session flow 无 DISCONNECT 包。

#### T-179 Session Will 整体替换

- **场景**：顶层 will={topic:a}, session will={topic:b}。
- **断言**：session flow CONNECT 含 will topic="b"（替换非追加）。

#### T-180 Session Will nil 继承

- **场景**：顶层 will={topic:a}, session will=nil。
- **断言**：session flow CONNECT 含 will topic="a"（继承）。

### 7.18 字节级完整场景测试

#### T-181 S1 完整字节序列

- **场景**：S1 输入。
- **断言**：10 包 PacketConfig 的 MQTT 字节与 §6.1 表完全匹配。

#### T-182 S2 完整字节序列

- **场景**：S2 输入。
- **断言**：10 包 PacketConfig 的 MQTT 字节与 §6.2 表匹配，特别是 CONNECT `10 1a 00 04 4d 51 54 54 04 02 00 3c 00 0e 74 65 6d 70 2d 73 65 6e 73 6f 72 2d 30 31`（RemainingLen=26）与 PUBLISH `30 11 00 0b ...`（修正后的字节）。

#### T-183 S4 完整字节序列

- **场景**：S4 输入。
- **断言**：13 包 PacketConfig 的 MQTT 字节匹配，4 包 QoS2 交换字节正确。

#### T-184 S9 完整字节序列

- **场景**：S9 输入。
- **断言**：10 包 PacketConfig 的 MQTT 字节匹配：CONNECT `10 2d 00 04 4d 51 54 54 04 0e 00 3c 00 09 64 65 76 69 63 65 2d 30 31 00 0d 63 6c 69 65 6e 74 2f 73 74 61 74 75 73 00 07 6f 66 66 6c 69 6e 65`（RemainingLen=45，Connect Flags=0x0E）；will PUBLISH `32 18 00 0d 63 6c 69 65 6e 74 2f 73 74 61 74 75 73 00 01 6f 66 66 6c 69 6e 65`（RemainingLen=24）。

#### T-185 S12 完整字节序列

- **场景**：S12 输入（5.0 + Properties）。
- **断言**：MQTT 字节匹配——CONNECT `10 27 ...`（RemainingLen=39，Properties Length=0x11，含 Topic Alias Maximum `0x22 0x00 0x01`）；第一条 PUBLISH `30 2b ...`（RemainingLen=43）；第二条 PUBLISH `30 0d ...`（RemainingLen=13）；两条 PUBLISH 的 Topic Alias 编码正确。

#### T-186 S13 完整字节序列

- **场景**：S13 输入。
- **断言**：CONNECT 字节 = `10 26 00 04 4d 51 54 54 04 c2 00 3c 00 0b 61 75 74 68 2d 63 6c 69 65 6e 74 00 05 61 64 6d 69 6e 00 06 73 65 63 72 65 74`。

#### T-187 S15 完整字节序列

- **场景**：S15 输入（5.0 Keep Alive timeout）。
- **断言**：CONNECT 字节 = `10 17 00 04 4d 51 54 54 05 02 00 1e 00 00 0a 74 69 6d 65 6f 75 74 2d 30 31`（RemainingLen=23）；DISCONNECT 字节 = `e0 02 8d 00`。

### 7.19 边界场景补充

#### T-188 剩余长度 268435455 边界

- **场景**：PUBLISH payload 使 RemainingLen=268435455（VBI 4 字节最大值）。
- **断言**：VBI 字节为 `0xFF 0xFF 0xFF 0x7F`。

#### T-189 剩余长度 268435456 报错

- **场景**：PUBLISH payload 使 RemainingLen=268435456（超出 4 字节范围）。
- **断言**：planner 报错（VBI 编码失败）。

#### T-190 topic 0 字节 + 无 Topic Alias 报错

- **场景**：`messages: [{topic: "", payload: p, qos: 0}]`（无 Properties）。
- **断言**：Validate 报错。

#### T-191 PacketID 65535 + QoS2

- **场景**：`messages: [{topic: t, payload: p, qos: 2, packet_id: 65535}]`。
- **断言**：4 包 QoS2 交换均含 PacketID=`0xFF 0xFF`。

#### T-192 多 filter SUBSCRIBE 字节

- **场景**：3 个 filter：`a`、`b/+`、`c/#`，QoS 分别 0/1/2。
- **断言**：SUBSCRIBE payload 含 3 个 filter + 3 个 Options 字节；SUBACK 含 3 个 Reason Code。

### 7.20 规范禁止行为测试

#### T-193 PUBREL flags≠0x02 报错（planner 内部）

- **场景**：planner 内部测试，验证 buildPubrel 强制 flags=0x02。
- **断言**：单元测试 mock 用户传入任意 flags，buildPubrel 输出第一字节始终=0x62。

#### T-194 SUBSCRIBE flags≠0x02 报错（planner 内部）

- **场景**：planner 内部测试 buildSubscribe。
- **断言**：输出第一字节始终=0x82。

#### T-195 CONNECT Protocol Name 错误

- **场景**：planner 内部测试 buildConnect。
- **断言**：输出始终含 `00 04 4d 51 54 54`（"MQTT"），不接受用户修改。

#### T-196 CONNECT bit0 Reserved 永远 0

- **场景**：planner 内部测试。
- **断言**：Connect Flags bit0 始终=0。

#### T-197 PUBLISH QoS=3 报错

- **场景**：`qos: 3`（二进制 11）。
- **断言**：Validate 报错。

#### T-198 5.0 Maximum QoS Property

- **场景**：Version=5, CONNACK Properties 含 Maximum QoS=1（ID 0x24）。
- **断言**：planner 在 CONNACK 中输出 `24 01` 字节（ID 0x24 + byte 1）。

#### T-199 5.0 Retain Available Property

- **场景**：Version=5, CONNACK Properties 含 Retain Available=0（ID 0x25）。
- **断言**：planner 在 CONNACK 中输出 `25 00` 字节。

#### T-200 5.0 Shared Subscription Available Property

- **场景**：Version=5, CONNACK Properties 含 Shared Subscription Available=1（ID 0x2A）。
- **断言**：planner 在 CONNACK 中输出 `2A 01` 字节。

### 7.21 用例计数

| 类别 | 数量 | 编号范围 |
|------|------|---------|
| RFC 字段构造（§7.1） | 30 | T-001~T-030 |
| 状态机（§7.2） | 11 | T-031~T-041 |
| Plan 输出（§7.3） | 12 | T-042~T-053 |
| 业务场景（§7.4） | 13 | T-054~T-066 |
| 异常与边界（§7.5） | 55 | T-067~T-120 + T-074b |
| 集成（§7.6） | 7 | T-121~T-127 |
| 对抗性（§7.7） | 4 | T-128~T-131 |
| 5.0 Reason Code 域（§7.8） | 4 | T-132~T-135 || Property × 包类型白名单（§7.9） | 10 | T-136~T-141 + T-141b/T-141c/T-141d |
| VBI 边界（§7.10） | 4 | T-142~T-145 |
| 多会话与继承（§7.11） | 5 | T-146~T-150 |
| 订阅选项（§7.12） | 5 | T-151~T-155 |
| 字段计数与扩展表（§7.13） | 3 | T-156~T-158 |
| 规范一致性补充（§7.14） | 9 | T-159~T-167 |
| 异常断开与 RST（§7.15） | 3 | T-168~T-170 |
| Property 编码负向（§7.16） | 5 | T-171~T-175 |
| Session 字段继承完整（§7.17） | 6 | T-176~T-180 + T-177b |
| 字节级完整场景（§7.18） | 7 | T-181~T-187 |
| 边界场景补充（§7.19） | 5 | T-188~T-192 |
| 规范禁止行为（§7.20） | 8 | T-193~T-200 |
| **合计** | **205 条** | T-001~T-200 + T-177b + T-074b + T-141b/T-141c/T-141d |

实际实现时可能微调（拆分/合并），但总数不少于 200 条，且每条对应一个规范章节 / Config 字段 / 边界。

---

## §8. Validate 规则

### 8.1 Validate 总体规则（优先序）

Validate 在 `Planner.Validate(spec core.FlowSpec) error` 中执行，按以下顺序检查（先报第一个错误）：

1. **Version 域**：仅 4 和 5 合法；3/6/其他 → 报错。
2. **ClientID**：Sessions 内显式重复 → 报错；空字符串 → 自动生成（不报错）。
3. **KeepAlive**：`*int` 取值 -1 及以下 → 报错（Keep Alive 必须 ≥ 0）。
4. **Username/Password**：Version=4 + Username 空 + Password 非空 → 报错。
5. **Will**：非 nil 时 Topic 非空；Will QoS ∈ {0,1,2}；Version=4 + DelayInterval≠0 → 报错。
6. **ConnectAckCode 域**：Version=4 仅 0-5；Version=5 精确枚举白名单（§8.2）。
7. **ConnectAckSessionPresent 互斥**：CleanSession=true + SessionPresent=true → 报错；ConnectAckCode≠0 + SessionPresent=true → 报错。
8. **Subscriptions**：Filters 非空；每个 filter 语法合法（§8.3）；AckReasonCodes 长度 == Filters 长度。
9. **Messages**：QoS ∈ {0,1,2}；DUP + QoS0 → 报错；Topic 含通配符 → 报错；Topic 长度 ≤ 65535；空 Topic 须有已建 Topic Alias 映射。
10. **Properties**：Version=4 + Properties 非空 → 报错；ID × 包类型白名单（§8.4）；同包同 ID 重复（除 0x26；0x0B 仅 down PUBLISH 例外）→ 报错；**0x0B 出现在 up 方向 PUBLISH → 报错**（5.0 §3.3.4 [MQTT-3.3.4-6]：client→server PUBLISH 不得含 Subscription Identifier）；**SUBSCRIBE 中 0x0B 重复 → 报错**（5.0 §3.8.2.1.2）；Value 按 Format 校验（§8.5）。
10b. **Topic Alias Maximum 声明**：Version=5 时，若任一 PUBLISH 携带 Topic Alias（0x23），CONNECT 必须声明 Topic Alias Maximum（0x22 ≥ 使用到的 alias 最大值）→ 否则 Validate 报错（5.0 §3.1.2.11.5：CONNECT 未声明 0x22 时缺省 0，表示客户端不接受任何 Topic Alias；客户端发送 Topic Alias 受服务端 CONNACK 声明上限约束，本节为生成合法流量要求 CONNECT 侧先声明自身能力）。
11. **MSS**：`spec.TCP.MSS` < MinMSS(536) → 报错（继承公共规则）。
12. **UTF-8**：Topic/Filter/ClientID/Username 含 U+0000 或代理区字符 → 报错。

### 8.2 ConnectAckCode 精确枚举

**3.1.1**：合法值 = {0, 1, 2, 3, 4, 5}（§2.6 表）。其他 → 报错。

**5.0**：合法值 = {0, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 140, 144, 149, 151, 153, 154, 155, 156, 157, 159}（22 个，§2.6 表）。

**不在集合内的值**（如 141/148/200）→ 报错。141（Keep Alive timeout）与 148（Topic Alias invalid）**仅适用于 DISCONNECT**，不适用于 CONNACK。

### 8.3 Topic Filter 语法校验

| Filter | 合法性 | 说明 |
|--------|--------|------|
| `sport/tennis/score` | 合法 | 字面量 |
| `sport/+/score` | 合法 | `+` 单层 |
| `sport/#` | 合法 | `#` 多层必须在末尾 |
| `sport/#/score` | 非法 | `#` 不在末尾，报错 |
| `+/+` | 合法 | 多个 `+` |
| `#` | 合法 | 单 `#` |
| `sport+` | 合法 | `+` 在中间不分割层，按字面量匹配 |
| `$share/g/sensor/+` | 合法（5.0） | Shared Subscription，group=`g`，filter=`sensor/+` |
| `$share/g` | 非法（5.0） | 缺少 filter 部分 |
| `$share/a/b/c` | 合法（5.0） | group=`a`，filter=`b/c` |
| `$SYS/+/x` | 合法（语法层） | `$` 开头 filter 语法合法；通配符不匹配 `$` 开头 topic 是 broker 端语义，planner 只校验语法 |
| `$share/` 空 group | 非法 | group 为空 |

planner 规则：
- `#` 必须在末尾 → 否则报错。
- `$share/` 前缀仅 Version=5 合法；Version=4 → 报错。
- `$share/{group}/{filter}` 中 `{group}` 非空、不含 `/`/`+`/`#`；`{filter}` 非空 → 否则报错。
- 其他均接受（planner 只做语法校验，不做语义校验）。

**PUBLISH Topic Name 禁通配符**（§4.7.1）：PUBLISH 的 Topic Name 不得包含 `#` 或 `+`。Validate 检查 `MQTTMessage.Topic`，含 `#`/`+` → 报错。

### 8.4 Property Identifier × 包类型白名单

| 包型 | 允许的 Property ID 集合 |
|------|------------------------|
| CONNECT | {0x11, 0x15, 0x16, 0x17, 0x19, 0x21, 0x22, 0x26, 0x27} |
| CONNACK | {0x11, 0x12, 0x13, 0x15, 0x16, 0x1A, 0x1C, 0x1F, 0x21, 0x22, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A} |
| PUBLISH | {0x01, 0x02, 0x03, 0x08, 0x09, 0x0B, 0x23, 0x26} |
| Will Properties | {0x01, 0x02, 0x03, 0x08, 0x09, 0x18, 0x26} |
| SUBSCRIBE | {0x0B, 0x26} |
| SUBACK | {0x1F, 0x26} |
| PUBACK/PUBREC/PUBREL/PUBCOMP | {0x1F, 0x26} |
| UNSUBSCRIBE | {0x26} |
| UNSUBACK | {0x1F, 0x26} |
| DISCONNECT | {0x11, 0x1C, 0x1F, 0x26} |
| AUTH | {0x15, 0x16, 0x1F, 0x26} |

planner 仅对 CONNECT/CONNACK/PUBLISH/SUBSCRIBE/SUBACK/DISCONNECT 校验（本期实现的包型）；UNSUBSCRIBE/UNSUBACK/AUTH 不实现（见 §1.4）。

### 8.5 Property Value 按 Format 校验

| Format | 合法 Value | 非法 Value |
|--------|-----------|-----------|
| "byte" | 0-255 十进制数字 | 负数/256+/非数字 → 报错 |
| "uint16" | 0-65535 十进制数字 | 65536+/非数字 → 报错 |
| "uint32" | 0-4294967295 十进制数字 | 溢出/非数字 → 报错 |
| "string" | 任意 UTF-8（不含 U+0000） | 含 U+0000 → 报错 |
| "binary" | 合法 hex 字符串（偶数长度） | 非 hex/奇数长度 → 报错 |
| "stringpair" | "key\x00value" 形式 | 无 \x00 分隔符 → 报错 |
| "vbi" | 0-268435455 十进制数字 | 溢出/非数字 → 报错 |

### 8.6 Session 字段继承/替换规则

| 字段类型 | 规则 |
|---------|------|
| 标量（KeepAlive/CleanSession/Username/Password/Disconnect/PingAfterMessages） | session 字段为零值/nil → 继承顶层；非零 → 覆盖 |
| 指针标量（KeepAlive `*int` / CleanSession `*bool` / Disconnect `*bool`） | session 字段 **nil → 继承顶层；非 nil（含显式 0）→ 覆盖**。特别地，KeepAlive 三态语义（§5.1：nil→默认 60、*0→禁用保活、*N→N 秒）在 session 层同样成立：session `keep_alive: 0` 是"显式 0 覆盖"，**不继承顶层**，该 session 的 CONNECT KeepAlive 字段输出 `00 00`（禁用保活） |
| 切片（Messages/Subscriptions/Properties/Will） | session 字段为 nil → 继承顶层；非 nil → **整体替换**（不追加） |
| ClientID | session 为空 → 自动生成（顶层为空时）；Sessions 内显式重复 → 报错 |

### 8.7 交叉对抗审计检查清单

实现完成后，由独立 reviewer 按本清单逐项审计：

#### 8.7.1 RFC 字段一致性

- [ ] CONNECT Protocol Name 字节 `00 04 4d 51 54 54`（"MQTT"）— 3.1.1 与 5.0 一致。
- [ ] CONNECT Protocol Level：3.1.1=`0x04`，5.0=`0x05`。
- [ ] Connect Flags bit0 Reserved 永远 0（任何版本）。
- [ ] CONNACK 3.1.1 byte[0] bit0=Session Present，bit1-7 必须为 0；byte[1]=Return Code。
- [ ] CONNACK 5.0 byte[0] bit0=Session Present，bit1-7 保留（必须 0）；byte[1]=Reason Code；其后 Properties。
- [ ] PUBLISH QoS0 必须无 Packet Identifier；QoS1/2 必须有。
- [ ] PUBREL/PUBREC/PUBCOMP 固定头 flags 必须按表 §2.2（PUBREL=0x02，其余=0x00）。
- [ ] SUBSCRIBE 固定头 flags 必须 0x02（bit1=1）。[UNSUBSCRIBE 本期不实现，清单项不可达]
- [ ] SUBSCRIBE payload 每条 = Topic Filter(2-len + bytes) + Options(1 byte)。
- [ ] Variable Byte Integer 编码遵循 §2.3 算法，最大 4 字节、最大值 268,435,455，最小编码原则。
- [ ] UTF-8 编码字符串字段 = 2 字节大端长度 + 字节序列。
- [ ] 5.0 Properties Length 是 VBI，编码 Properties 段本身字节数（不含 VBI 自身）。
- [ ] 5.0 Properties Length 必填（即使为 0）。
- [ ] 148（Topic Alias invalid）仅 DISCONNECT，不用于 CONNACK。
- [ ] Will Delay Interval = 0x18（Will Properties），不是 0x1A。

#### 8.7.2 状态机死锁/缺响应

- [ ] 每个 PUBLISH(QoS1) 后必有对应 PUBACK（同 PacketID）。
- [ ] 每个 PUBLISH(QoS2) 后必有 PUBREC→PUBREL→PUBCOMP 三件套（同 PacketID）。
- [ ] CONNACK Code≠0 后无任何 SUBSCRIBE/PUBLISH/PINGREQ/DISCONNECT。
- [ ] DISCONNECT 必是最后一个 MQTT 包；其后仅 TCP 挥手。
- [ ] PingAfterMessages=true 时 PINGREQ 后必跟 PINGRESP。
- [ ] Will message 场景：Disconnect=false + Will Flag=1，planner 输出 broker 发 will PUBLISH 的下行段。
- [ ] ctx 取消时不阻塞 emit 协程（select 含 `<-ctx.Done()`）。
- [ ] configChan 关闭前所有 emit 已完成（defer close 模式）。

#### 8.7.3 多会话独立 4-tuple

- [ ] 每个 session 的 (SrcIP, DstIP, SrcPort, DstPort) 4-tuple 互不相同。
- [ ] SrcPort 自增仅在 `HasExplicitSrcPort=false` 时；显式值优先。
- [ ] 每个 session 的 FlowID 独立（含 `:mqtt-<i>` 后缀）。
- [ ] TCP seq/ack 在每个 session 内独立，不跨 session 累加。
- [ ] PacketIndex 在每个 session 内独立从 0 起。
- [ ] GroupID 共享父 FlowSpec（保证同 PacketWorker 排序）。

#### 8.7.4 Config 字段覆盖

- [ ] MQTTConfig 全部 15 字段（Version/ClientID/KeepAlive/CleanSession/Username/Password/Will/ConnectAckCode/ConnectAckSessionPresent/Subscriptions/Messages/PingAfterMessages/Disconnect/Sessions/Properties）有至少 1 条测试。
- [ ] MQTTWill 全部 5 字段（Topic/Payload/QoS/Retain/DelayInterval）覆盖。
- [ ] MQTTMessage 全部 8 字段（Topic/Payload/QoS/Retain/DUP/PacketID/Direction/Properties）覆盖。
- [ ] MQTTSubscribe 全部 3 字段（PacketID/Filters/AckReasonCodes）覆盖。
- [ ] MQTTTopicFilter 全部 5 字段（Filter/QoS/NoLocal/RetainAsPublished/RetainHandling）覆盖。
- [ ] MQTTProperty 全部 3 字段（Identifier/Format/Value）覆盖；7 种 Format 各至少 1 条正测。
- [ ] MQTTSession 全部 13 字段（ClientID/KeepAlive/CleanSession/Username/Password/Will/Subscriptions/Messages/PingAfterMessages/Disconnect/Properties/SrcPort/DstPort）覆盖或继承测试。

#### 8.7.5 边界覆盖

- [ ] Variable Byte Integer 8 个边界值（0/127/128/16383/16384/2097151/2097152/268435455）全测。
- [ ] client_id 空字符串边界。
- [ ] payload 0 字节边界。
- [ ] topic 65535 / 65536 字节边界。
- [ ] PacketID 0 / 65535 边界。
- [ ] QoS 0/1/2/3 边界（3=非法）。
- [ ] Version 3/4/5/6 边界。
- [ ] MSS MinMSS/默认/超大 边界。

#### 8.7.6 集成点覆盖

- [ ] strategy_convert case "mqtt" 解析（T-121）。
- [ ] 默认端口 1883 填充（T-122）。
- [ ] main.go RegisterPlanner（T-123）。
- [ ] task handler → engine → Plan 全链路（T-124）。
- [ ] ValidationErrors 透传 task 失败（T-125）。
- [ ] PacketWorkers=8 不乱序（T-127）。

#### 8.7.7 测试质量（CLAUDE.md §8 对抗性审查）

- [ ] 每条测试断言**可观见结果**（字节数值 / 包数 / 方向），而非仅"不 panic"。
- [ ] 每条测试覆盖**正确的代码路径**（如 CONNACK 拒绝路径独立测试）。
- [ ] **失败测试先行**：每个 bug fix 必先写 reproducing failing test。
- [ ] 表驱动测试不掩盖字段缺漏（CONNACK 22 个 5.0 代码各自独立行）。
- [ ] 并发测试不仅测 `-race` 干净，还测**可观见行为**。
- [ ] 集成测试驱动**全路径**（task handler → engine → Plan → pcap）。

#### 8.7.8 已知陷阱

- [ ] **PUBREL flags=0x02**：参考 SOCKS5 `S 位自动修正` 教训，必须强制 flags，不接受用户覆盖。
- [ ] **VBI 编码边界**：参考 DHCPv6 lifetime 字段教训，128/16384/2097152 三个跃迁点必须独立测试。
- [ ] **多会话 FlowID 独立**：参考 SIP/RTSP RTP 子流教训，每个 session 必须独立 FlowID。
- [ ] **Properties Length VBI 不含自身**：参考 LDAP BER 长形式教训。
- [ ] **5.0 与 3.1.1 字段差异**：参考 OpenVPN opcode 表教训，Protocol Level 4 vs 5 必须显式测试。
- [ ] **空 ClientID 强制 CleanSession**：参考 MySQL opcode 表教训，边界行为必须显式测试。
- [ ] **Topic Alias 与空 Topic Name 的关系**：5.0 中 PUBLISH 携带 Topic Alias 时 Topic Name 可为空，但仅当之前 PUBLISH 已建立 alias 映射。
- [ ] **Topic Alias Maximum 必须先声明**：5.0 中任何 PUBLISH 使用 Topic Alias（0x23）前，CONNECT 必须声明 Topic Alias Maximum（0x22）≥ alias 值，否则协议违规（5.0 §3.1.2.11.5）。
- [ ] **Subscription Identifier（0x0B）方向规则**：禁止 up PUBLISH 携带（5.0 §3.3.4 [MQTT-3.3.4-6]）；SUBSCRIBE 不得重复（§3.8.2.1.2）；down PUBLISH 多订阅匹配可重复（§3.3.2.3.8）。
- [ ] **PUBLISH 整包不拆**：MSS 分段仅作用于 TCP 层，单个 PUBLISH 报文（含固定头）是 §2.1.4 不可分割应用层消息，不得拆成多个独立 MQTT 包（见 T-043/T-044）。
- [ ] **Will Delay Interval 仅 5.0 且 ID=0x18**：3.1.1 中 Will 立即发布；ID 0x18 编码于 Will Properties 段。
- [ ] **148 仅 DISCONNECT**：Topic Alias invalid 不可用于 CONNACK Reason Code。
- [ ] **§5.1 表 PUBLISH 字节**：`sensor/temp` 长度字段是 0x0b（11 字节），Remaining Length 是 0x11（17）。

---

## §9. 错误处理

### 9.1 Validate 错误类别

| 错误类别 | 示例 | 严重度 |
|---------|------|--------|
| 版本错误 | Version=3/6 | fatal（Validate 报错） |
| QoS 错误 | QoS=3 | fatal |
| 通配符错误 | `#` 不在末尾 | fatal |
| 空值错误 | Will 无 Topic | fatal |
| 长度错误 | Topic 65536 字节 | fatal |
| Property 错误 | ID×包型不匹配 | fatal |
| 互斥错误 | CleanSession=true + SessionPresent=true | fatal |
| 域错误 | ConnectAckCode=6 (3.1.1) | fatal |
| DUP 错误 | QoS0 + DUP=true | fatal |
| UTF-8 错误 | Topic 含 U+0000 | fatal |

所有 Validate 错误 → task 状态 failed，error message 透传（T-125 验证）。

### 9.2 Planner 运行时错误

| 场景 | 行为 |
|------|------|
| VBI 编码溢出（RemainingLen > 268435455） | Plan 返回 error |
| ctx 取消 | emit 协程 select ctx.Done()，干净退出 |
| configChan 关闭 | defer close 模式 |
| MSS 分段 | 无错误（自动分段） |

### 9.3 客户端侧错误处理（生成器视角）

trafficgen 是流量生成器，模拟客户端行为。对 broker 的异常响应（如 CONNACK 拒绝码）：
- **CONNACK Code≠0**：planner 跳过后续包，直接 TCP 挥手（模拟客户端收到拒绝后断开）。
- **其他响应异常**（如收到畸形 CONNACK）：不在 planner 范围（planner 只生成预设序列）。

### 9.4 负向流量建模

trafficgen 允许用户构造协议违规流量以测试 broker 容错性（见 T-006 DUP=1 注释）：
- DUP=1 首次发送（QoS1+）——协议违规但 planner 允许。
- CONNACK 拒绝码组合——正常场景。
- 其他违规（如 flags 错误）——planner 强制固定值，不允许用户覆盖。

---

## §10. 扩展字段映射

### 10.1 包类型速查表

```
CONNECT=0x10  CONNACK=0x20  PUBLISH=0x30|32|34(+DUP/Retain 位)
PUBACK=0x40   PUBREC=0x50   PUBREL=0x62   PUBCOMP=0x70
SUBSCRIBE=0x82  SUBACK=0x90  UNSUBSCRIBE=0xA2  UNSUBACK=0xB0
PINGREQ=0xC0   PINGRESP=0xD0  DISCONNECT=0xE0  AUTH=0xF0 (5.0, 本期不实现)
```

**PUBLISH 第一字节完整表**：

| QoS | DUP | Retain | 第一字节 |
|-----|-----|--------|---------|
| 0 | 0 | 0 | 0x30 |
| 0 | 0 | 1 | 0x31 |
| 1 | 0 | 0 | 0x32 |
| 1 | 0 | 1 | 0x33 |
| 1 | 1 | 0 | 0x3A |
| 1 | 1 | 1 | 0x3B |
| 2 | 0 | 0 | 0x34 |
| 2 | 0 | 1 | 0x35 |
| 2 | 1 | 0 | 0x3C |
| 2 | 1 | 1 | 0x3D |
| 0 | 1 | * | 非法（QoS0 + DUP=1） |
| 3 | * | * | 非法（QoS=3） |

**验算**：0x3D = 0011 1101 → Type=3(0011), DUP=1(bit3), QoS=2(bit2=1,bit1=0), Retain=1(bit0) ✓

### 10.2 扩展表对照（mqttProtRpt，28 字段）

扩展表节点 `mqttProtRpt` 对应 MQTT 上报字段，由 `internal/core/report.go` 聚合每个 MQTT flow 的 PacketConfig.Metadata 后输出：

| 扩展表字段 | 来源（Config / 生成流量） | 聚合方式 |
|-----------|---------------------------|---------|
| tx_id | MQTTMessage.PacketID / MQTTSubscribe.PacketID（自动分配时取 planner 自增计数器值） | 每 flow 取最大 PacketID 作为该 flow 的事务号；多 flow 取 max |
| version | MQTTConfig.Version（4 或 5） | 直接取值，单 flow 单一值 |
| type | 固定头 Type 位（CONNECT=1...AUTH=15） | 按 flow 内各包类型计数：`{connect:1, connack:1, publish:N, ...}` |
| dup | MQTTMessage.DUP（bit3） | 统计 flow 内 DUP=1 的 PUBLISH 数 |
| qos_level | MQTTMessage.QoS / MQTTWill.QoS / MQTTTopicFilter.QoS | 取 flow 内最大 QoS 值（0/1/2） |
| retain | MQTTMessage.Retain / MQTTWill.Retain | 统计 flow 内 Retain=1 的 PUBLISH 数（含 will） |
| reason_codes | ConnectAckCode（CONNACK）+ AckReasonCodes（SUBACK） | 合并为 `[connack_code, suback_code1, ...]` 数组 |
| connack_session_present | ConnectAckSessionPresent（CONNACK byte[0] bit0） | 直接取 bool → 0/1 |
| client_id | MQTTConfig.ClientID / MQTTSession.ClientID | 直接取字符串 |
| keep_alive | MQTTConfig.KeepAlive（*int 解析后） | 直接取值（0=禁用） |
| clean_session | MQTTConfig.CleanSession（*bool 解析后） | 直接取 bool → 0/1 |
| will_flag | MQTTConfig.Will != nil | 直接取 bool → 0/1 |
| will_topic | MQTTConfig.Will.Topic | 直接取字符串，无 will 时为空 |
| will_qos | MQTTConfig.Will.QoS | 直接取值，无 will 时为 0 |
| will_retain | MQTTConfig.Will.Retain | 直接取 bool → 0/1 |
| username | MQTTConfig.Username / MQTTSession.Username | 直接取字符串（不脱敏，与 pcap 一致） |
| password_set | MQTTConfig.Password != "" | 直接取 bool → 0/1（不输出明文密码） |
| direction | MQTTMessage.Direction（"up"/"down"） | 统计 flow 内 up/down PUBLISH 数 |
| topic | MQTTMessage.Topic | 取 flow 内最后一条 PUBLISH 的 Topic |
| payload_len | len(MQTTMessage.Payload) | 取 flow 内最后一条 PUBLISH 的 Payload 长度 |
| subscriptions_count | len(Subscriptions) | 直接取值（多 session 求和） |
| filters_count | sum(len(Filters)) | 所有订阅的 filter 总数 |
| messages_count | len(Messages) | 直接取值（多 session 求和） |
| ping_count | PingAfterMessages（true→1） | 直接取值 |
| disconnect_flag | Disconnect（*bool 解析后） | 直接取 bool → 0/1 |
| sessions_count | len(Sessions) | 直接取值（单会话=1） |
| properties_count | sum(len(Properties)) | 所有包属性的总数 |
| topic_alias_used | 是否使用 Topic Alias（ID 0x23） | 直接取 bool → 0/1 |

**共 28 字段**（v2.0.0 修正：v1.1 误写 27 字段）。

### 10.3 集成点

#### 10.3.1 `internal/core/types.go` 新增 MQTTConfig

在文件末尾 `XmppConfig` 后追加：

```go
MQTT *MQTTConfig `json:"mqtt,omitempty"`
```

并定义 `MQTTConfig` / `MQTTWill` / `MQTTMessage` / `MQTTSubscribe` / `MQTTTopicFilter` / `MQTTProperty` / `MQTTSession` 类型（字段定义见 §5）。

#### 10.3.2 `internal/core/strategy_convert.go` 新增 case "mqtt"

```go
case "mqtt":
    if sub, ok := cfg["mqtt"].(map[string]interface{}); ok {
        spec.MQTT = parseMQTTConfig(sub)
    }
    // MQTT defaults to port 1883 (RFC 9.1.1 §4.1, plaintext)
    if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
        spec.DstPort = 1883
    }
```

#### 10.3.3 `cmd/server/main.go` 注册 NewPlanner

```go
app.engine.RegisterPlanner(mqtt.NewPlanner())
```

#### 10.3.4 `internal/protocol/mqtt/mqtt.go` 实现骨架

```go
package mqtt

const (
    DefaultPort      = 1883
    DefaultTTL       = 64
    DefaultMSS       = 1460
    MinMSS           = 536
    DefaultKeepAlive = 60

    TypeCONNECT     = 1
    TypeCONNACK     = 2
    TypePUBLISH     = 3
    TypePUBACK      = 4
    TypePUBREC      = 5
    TypePUBREL      = 6
    TypePUBCOMP     = 7
    TypeSUBSCRIBE   = 8
    TypeSUBACK      = 9
    TypeUNSUBSCRIBE = 10
    TypeUNSUBACK    = 11
    TypePINGREQ     = 12
    TypePINGRESP    = 13
    TypeDISCONNECT  = 14
    TypeAUTH        = 15
)

type Planner struct{}
func NewPlanner() *Planner { return &Planner{} }
func (p *Planner) Name() string { return "mqtt" }
func (p *Planner) Validate(spec core.FlowSpec) error { /* §8 规则 */ }
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) { /* ... */ }
```

实现遵循 socks5 模板：
1. Validate → 字段语法检查（Version/ClientID/QoS/通配符/Properties 等，见 §8）。
2. Plan → 启 goroutine，emit TCP 握手 → MQTT 包序列 → TCP 挥手。
3. emit 辅助函数：参考 socks5 `emit` / `emitData` / `segmentByMSS`。**MQTT 例外**：`segmentByMSS` 仅作用于 TCP 层分段——单个 MQTT PUBLISH 报文（含固定头+VH+payload）是 §2.1.4 定义的不可分割应用层消息，**不得拆成多个独立 MQTT 包**；MSS 分段时仅首段携带 MQTT 固定头，后续段为同一 MQTT 报文的字节延续（见 T-043/T-044）。
4. 多会话：循环 sessions，每 session 独立 emit 一组 TCP 握手+MQTT+挥手，FlowID 加 `:mqtt-<i>` 后缀。

#### 10.3.5 测试 pcap 参考

实现时建议用 `mosquitto` 或 `emqx` 抓真实 pcap 作为字节对照。pcap 存放路径建议：`/home/pcap_auto/mqtt_311_basic.pcap`、`/home/pcap_auto/mqtt_5_props.pcap`。

---

## §11. 层链迁移契约（D1–D8，2026-09-30）

| ID | 结论 | 证据/去向 |
|---|---|---|
| D1 | 地址只住 `layers[].ip` 的 `src`/`dst`；端口只住 `layers[].tcp` 的 `src_port`/`dst_port` | `mqtt.json` 全量 206 条机读审计 |
| D2 | 明文 MQTT 的标准链固定为 `[ip,tcp,mqtt]`；TLS 承载唯一允许 `[ip,tcp,tls,mqtt]` | `mqtt_over_tls` 与其余正例的 `layers` 顺序 |
| D3 | MQTT 业务字段只住 `layers[].mqtt`；TLS 字段只住 `layers[].tls`，不得在顶层配置 | §5 字段定义与 cases 全量审计 |
| D4 | 流数量由 `flow_control`/策略驱动；`sessions` 是 MQTT 层内会话编排，不替代流控字段；3 个动态例各用 `strategy_fc.type=flows,value=2` | CORE_MEMORY §1–§3；`mqtt_dyn_client_id_list`、`mqtt_dyn_topic_pattern`、`mqtt_dyn_payload_list` 的 JSON 审计 |
| D5 | `group_id` 仅为顶层跨流绑定结构键；不能与顶层 `mqtt` 业务子配置并列 | `mqtt_t149_group_id_shared` 是故意判死 presence 负例 |
| D6 | 正例不得混用旧 flat 地址/端口/count；本批正例 139 条标准链 + 1 条 TLS 链，顶层仅 `{layers}` | JSON 顶层键统计 |
| D7 | 负例保留故意违规输入和精确 `error_contains`，不洗成成功层链；负例不得带包数断言 | 66 条负例 expect 形状审计 |
| D8 | WebSocket、MQTT-SN、AUTH 生成、UNSUBSCRIBE/UNSUBACK、真实 broker 转发与今日双输出未实现/未复跑的面只登记缺口，不伪造覆盖 | §1.4、§8 缺口表与 P5 计划 |

### 12.1 规范—业务—代码—缺口矩阵

| 面 | 规范/设计要求 | 当前代码与 cases | 结论 |
|---|---|---|---|
| 连接/承载 | MQTT 3.1.1/5.0 over TCP；可叠 TLS | `mqtt` planner、`[ip,tcp,mqtt]` 与唯一 TLS 链 | 已覆盖 |
| 控制包与 QoS | CONNECT/CONNACK、PUBLISH QoS0/1/2、订阅、保活、断开 | §2–§4、S/T cases | 已覆盖于当前 profile |
| 属性与边界 | v5 properties、VBI、UTF-8、alias、reason code | §2.3/§2.14、正负 cases | 已覆盖的列入 cases；未列项见 G-MQTT |
| broker 语义 | retain、will、session 的实际跨连接状态 | planner 为单连接字节序列模型 | 简化模型，非真实 broker |
| 非实现扩展 | WS、MQTT-SN、AUTH、UNSUBSCRIBE/UNSUBACK | §1.4 明确不实现 | 不适用/缺口，不计当前覆盖 |

### 12.2 代码设计八要素与门 1

- **文件/接口**：实现入口为 `internal/protocol/mqtt` 的 planner/validator；本轮只修订本设计、testcase 与 cases，不改 Go。
- **数据结构/主流程**：层链解析 IP→TCP→（TLS）→MQTT；校验后流式生成握手、MQTT 控制包/分段、终止。
- **错误分支**：validator 错误必须传播为 task error；负例只断言错误锚词，不得以 0 包完成假绿。
- **性能边界**：保持流式生成；TCP MSS 只切分单个 MQTT 报文的承载字节，不把它伪造为多个 MQTT 包；已登记正例字段断言 52 条、帧断言 215 条，队列/缓冲预算由通用引擎负责。
- **冲突与回滚**：若实现不接受严格层链，登记 G-MQTT-1 后补 parser/translate；回滚仅撤销本轮三文件文档变更，不回退既有协议实现。

门 1 结论：层链字段归属与顺序已由 206 条 JSON 机读审计确认；正例为 139 条 `[ip,tcp,mqtt]` 与 1 条 `[ip,tcp,tls,mqtt]`；`mqtt_t149_group_id_shared` 是唯一故意判死的旧 presence 形，不是正例残留。今日未执行 suite/PCAP/NIC，不能把门 1 与运行通过混写。

### 12.3 缺口登记

| ID | 缺口 | 计划 |
|---|---|---|
| G-MQTT-1 | 本轮未重新执行 MCP→task→PCAP/NIC→tshark 双输出链路 | P5 用同一 `mqtt.json` 全量重跑，记录 suite、pcap、NIC、tshark 版本与命中数 |
| G-MQTT-2 | TLS 例的 record `content_type` 语义需以实际抓包复核 | P5 对照 TLS record 原始字节与断言，修正文档或 cases |
| G-MQTT-3 | 真实 broker 的跨连接 retain/will/session 状态未模拟 | 后续 broker-integration profile；当前仅保留单流字节序列模型 |

## §13. C1–C6 审查结论

| ID | 结论 |
|---|---|
| C1 | JSON 可解析，206 个 ID 唯一，顺序与 testcase 契约一致。 |
| C2 | 140 条正例均为严格层链；唯一非层链形为故意 presence 负例。 |
| C3 | 地址、端口、承载和 MQTT 业务字段均按层归属；未新增顶层业务豁免。 |
| C4 | 66 条负例的 `expect` 严格为 `{expect_error,error_contains}`，无 notes、包数或成功包断言。 |
| C5 | 同连接多轮、非正常结束、保活、QoS/属性/动态/IPv6/多会话均有 cases；真实 broker 语义及双输出列入 G-MQTT。 |
| C6 | 本轮范围严格限定为 MQTT 三文件，不修改 Go、全局索引、旧稿或其他协议。 |

---

## §14. 修订记录

| 版本 | 日期 | 修订内容 |
|------|------|---------|
| v1.0 | 2026-08-03 | 初版：16 条场景 + 116 条用例 |
| v1.1 | 2026-08-04 | 修复 v1.0 审计 32 问题（Remaining Length 字节、KeepAlive *int、Will 确定性序列、下行方向矩阵等） |
| **v2.0.0** | **2026-08-05** | **基于 MQTT 官方规范全文重写（MQTT 3.1.1 OASIS + MQTT 5.0 OASIS + RFC 9560），修复 deep-r2 审计 17 问题** |
| **v2.0.1** | **2026-08-05** | **修复 R1-v2 复审审计 12 问题（§6 HexDump Remaining Length 系统性错误 6 处、T-021 期望字节、UTF-8 长度上限表述、T-160/T-161 重复、S15 占位符、will 时序模型偏差说明、T-004/T-132 重复、KeepAlive *int 显式 0 继承语义、T-115 重复、§8.7.4 字段计数）** |
| **v2.0.2** | **2026-08-05** | **修复 R2-v2 复审审计 6 问题（H-1 Subscription Identifier 方向/重复规则、M-1 S12 补 Topic Alias Maximum、M-2 SUBACK Reason Code 补 0x91/0x97、L-1 S14 包数统一+旧章节号清理、L-2 T-041 CONNACK 固定头前缀、L-3 T-043 PUBLISH 整包不拆 TCP 层分段）** |
| **v2.0.3** | **2026-10-01** | **负例契约收紧：66 条 `expect` 统一为严格 `{expect_error,error_contains}`，移除 `notes` 等非契约键。** |

### 11.1 v2.0.0 关键修复清单（对照 deep-r2 审计）

| 审计编号 | 问题 | v2.0.0 修复 |
|---------|------|------------|
| C-D1 | Will Delay Interval ID 错标 0x1A | §2.14/§10.2 修正为 **0x18**（Will Properties）；T-023 期望字节改 `05 18 00 00 00 05` |
| C-D2 | §5.1 PUBLISH 字节双错 | §6.2（S2）修正为 `30 11 00 0b ...`（Topic Len=11, RemainingLen=17）；T-182 断言修正 |
| H-D1 | 0x15 错标 Topic Alias Maximum | §2.14 修正为 **Authentication Method**；新增 0x22=Topic Alias Maximum |
| H-D2 | 0x19 错标 Server Keep Alive | §2.14 修正为 **Request Response Information**；新增 0x13=Server Keep Alive |
| H-D3 | 0x21 错标 Reason String | §2.14 修正为 **Receive Maximum**；新增 0x1F=Reason String |
| H-D4 | 148 错归 CONNACK | §2.6 明确 148 仅 DISCONNECT；T-102 断言报错 |
| H-D5 | §2.5 表格列结构误导 | §2.6 拆分为 3.1.1 Return Code 表 + 5.0 Reason Code 表；5.0 表严格按规范 22 个 CONNACK 代码 |
| M-D1 | 5.0 CONNACK 域过宽 | §8.2 精确枚举 22 个有效值 |
| M-D2 | 扩展表字段计数 27→28 | §10.2 修正为 28 字段 |
| M-D3 | §8.1 UNSUBSCRIBE 清单不可达 | §8.7.1 标注 [UNSUBSCRIBE 本期不实现，清单项不可达] |
| M-D4 | PacketID=0 表述矛盾 | §6.12/T-084 统一为"0 = 自动分配（等同于省略）" |
| M-D5 | AUTH 标注不明确 | §2.2/§2.13 标注"本期不实现，仅作规范参考" |
| M-D6 | §2.12 适用包列不完整 | §2.14 逐行补全适用包列 |
| L-D1 | will PUBACK 语义不自洽 | §6.9（S9）注明"此 PUBACK 为字节序列完整性添加" |
| L-D2 | 0x3D 无验算 | §10.1 补充逐位验算 |
| L-D4 | JSON \x00 非法 | §6.12 输入 value 改为 `"k\x00v"` 说明 + §5.5 注释 |
| L-D5 | buildUnsubscribe 残留 | §5.3 删除该函数 |

### 11.2 v2.0.0 新增内容

- §3 消息结构逐包字节构造（新增，含 CONNECT/CONNACK/PUBLISH/ACK/SUBSCRIBE 字节布局与验算）。
- §6 HexDump 场景 S1-S15（15 个完整场景，含逐字节核算；v1.1 的 6.x 章节重组为 S1-S15 编号）。
- §7 测试用例 T-001~T-200（200 条；v1.1 的 TC-MQTT-001~113 重编号为 T-001~T-200，并新增 84 条）。
- §8 Validate 规则（新增，8 个子节：总体规则/精确枚举/Filter 语法/Property 白名单/Value 校验/继承规则/审计清单）。
- §9 错误处理（新增，4 个子节）。
- §10 扩展字段映射（28 字段完整表 + PUBLISH 第一字节完整表 + 集成点）。
- §11 修订记录（新增）。

### 11.3 v2.0.1 关键修复清单（对照 R1-v2 复审审计）

| 审计编号 | 问题 | v2.0.1 修复 |
|---------|------|------------|
| C-R1 | S2 CONNECT Remaining Length 错（`0x12`→`0x1a`，重复计入长度前缀） | §6.2 字节与核算修正为 26；T-182 基准同步 |
| C-R2 | S3/S4 PUBLISH Remaining Length 错（`0x0f`/`0x10`→`0x15`） | §6.3/§6.4 字节与核算修正为 21；T-055/T-056 基准不变 |
| C-R3 | S7 CONNECT Remaining Length 错（`0x0c`→`0x13`） | §6.7 字节修正为 19，补逐字节核算 |
| C-R4 | S9 CONNECT `0x1d`→`0x2d`、Will PUBLISH `0x14`→`0x18` | §6.9 两处字节与核算修正为 45/24；T-184 基准同步 |
| C-R5 | S10 CONNECT Remaining Length 错（`0x0b`→`0x0e`） | §6.10 字节修正为 14，补核算 |
| C-R6 | T-021 期望字节错（`30 06`→`30 05`） | §7.1 修正并补核算 |
| H-R1 | UTF-8 字符串上限表述错误（0xFFFF 保留的说法错误） | §2.4/§2.7 改为合法范围 0-65535 全范围；T-167 重写为 65535 通过/65536 报错；T-083 补 RL 核算 |
| H-R2 | T-160/T-161 重复定义 | T-160 明确断言 Validate 报错；T-197 编号名修正为 "PUBLISH QoS=3 报错" |
| H-R3 | S15 CONNECT 缺 Remaining Length 实际字节 | §6.15 补全 `10 17 ...` 与核算（RL=23） |
| H-R4 | Will 时序语义矛盾 | §4.4 补充"broker 视角单向字节序列建模"模型偏差说明；S9 断言与 T-169 措辞修正 |
| M-R1 | T-004/T-132 重复 | T-132 改为逐条独立断言，并注明与 T-004 的分工 |
| M-R2 | KeepAlive `*int` 显式 0 继承语义未定义 | §8.6 明确"nil 继承、非 nil（含 0）覆盖"；新增 T-177b |
| M-R3 | T-115 与 T-020/021/022 重复 | T-115 精简为 CONNECT 无属性一行，注明其余由 T-020/021/022 覆盖 |
| L-R1 | §8.7.4 字段计数错误 | MQTTTopicFilter 改 5 字段；MQTTSession 核对为 13 字段 |

### 11.4 v2.0.2 关键修复清单（对照 R2-v2 复审审计）

| 审计编号 | 问题 | v2.0.2 修复 |
|---------|------|------------|
| H-1 | §2.14/§5.5 把 Subscription Identifier（0x0B）标为"适用 PUBLISH 且可重复"，违反 5.0 §3.3.4 [MQTT-3.3.4-6]（client→server PUBLISH 不得含 Sub ID）与 §3.8.2.1.2（SUBSCRIBE 中 0x0B 不得重复） | §2.14 表行 0x0B 适用包改为"SUBSCRIBE；down PUBLISH（broker→client 转发可重复）；禁止 up PUBLISH"；§2.14 重复规则改述方向条件例外；§3.7 0x0B 示例加方向注；§5.5 Validate 规则 2 拆为三子规则（重复/方向/SUBSCRIBE 单实例）；§8.1 规则 10 同步；T-026 由正测改为负向用例（up PUBLISH 含 0x0B → 报错）；新增 T-141b（SUBSCRIBE 携带 0x0B 合法，VBI 编码正测移入）、T-141c（down PUBLISH 多 0x0B 合法可重复）、T-141d（SUBSCRIBE 两个 0x0B 报错） |
| M-1 | S12 CONNECT 未声明 Topic Alias Maximum 即在 PUBLISH 用 Topic Alias=1，违反 5.0 §3.1.2.11.5/§3.3.2.3.4 | S12 输入 properties 增加 `{identifier: 34, format: "uint16", value: "1"}`；CONNECT 字节由 `10 22 ...`（RL=34, PL=0x0c）改为 `10 27 ...`（RL=39, PL=0x11，含 `0x22 0x00 0x01`）；T-002/T-061/T-185 断言基准同步；§8.1 新增规则 10b"PUBLISH 用 Topic Alias 前 CONNECT 必须声明 Topic Alias Maximum"；新增 T-074b（未声明 + 用 alias → 报错）；T-073/T-074 输入补 CONNECT 声明 |
| M-2 | §2.10 SUBACK 5.0 Reason Code 列表漏 0x91/0x97（规范 Table 3-8 完整 11 项，文档仅列 9 项） | §2.10 列表补 0x91（Packet Identifier in use）+ 0x97（Quota exceeded），并标注完整 11 项集；T-134 集合由 7 项扩为 9 项（与 3.1.1 granted 三档合并覆盖规范 11 项） |
| L-1 | S14 标题"6 包"与正文"8 包"并存 + 旧章节号引用残留（§6.4/§6.6/§6.11/§6.12/§6.13 在 v2.0.0 重编号后无锚点） | S14 标题改为"8 包"；正文断言统一为 8 包（3 握手 + 2 MQTT + 3 挥手）；§5.1 注释 `see §6.12 boundary` 改 `see §6 S10 boundary`；T-002 `§6.12 输入` 改 `§6 S12 输入`；T-057 `§6.4` 改 `§6 S5`；T-059 `§6.6` 改自建输入并参考 S10；§7.5 标题 `§6.11/§6.12` 改 `§6 边界场景`；§2.3 `§6.12` 改 `§6 场景` |
| L-2 | T-041 断言"CONNACK payload = `0x01 0x00`"漏固定头 `20 02` 前缀，与 §7.18 字节级断言风格不一致 | T-041 期望改为完整包字节 `20 02 01 00`（固定头 + SP=1 + Code=0），断言改为 `bytes.Equal(payload, []byte{0x20, 0x02, 0x01, 0x00})`，风格与 T-181~T-187 一致 |
| L-3 | T-043 MSS 分段断言未区分"TCP 层切段"与"应用层拆包"，按字面实现会产出 3 个畸形 PUBLISH（每段各带固定头） | T-043/T-044 改为断言"单个 PUBLISH 报文（含固定头）在 TCP 层被切为 N 段，仅首段含 MQTT 固定头；各段 TCP payload 拼接 = 完整 PUBLISH 字节；接收端按 Remaining Length 重组"；引用 5.0 §2.1.4"Control Packets MUST be sent in their entirety"；§10.3.4 emit 辅助函数加注"MQTT PUBLISH 整包不拆，仅 TCP 层分段"；§8.7.8 已知陷阱新增"PUBLISH 整包不拆"条目 |

### 11.5 文档统计

| 指标 | v1.1 | v2.0.0 | v2.0.1 | v2.0.2 |
|------|------|--------|--------|--------|
| 总行数 | 2101 | **~3300+** | **~3265** | **~3320** |
| HexDump 场景 | 12（6.x 编号） | **15（S1-S15）** | **15（S1-S15，RL 全部重新逐字节核算）** | **15（S1-S15，S12 补 Topic Alias Maximum）** |
| 测试用例 | 116（TC-MQTT-001~113） | **200（T-001~T-200）** | **201（T-001~T-200 + T-177b）** | **205（+T-074b/T-141b/T-141c/T-141d）** |
| 规范章节引用 | 部分 | 全量（3.1.1 + 5.0 + RFC 9560） | 全量 | 全量 |
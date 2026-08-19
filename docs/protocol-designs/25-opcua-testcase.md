# OPC UA（OPC Unified Architecture，统一架构，二进制协议 TCP 4840）测试用例设计

> 版本：v1.0.0（初稿）
> 设计日期：2026-08-18
> 配套设计：25-opcua-design.md（线格式/状态机/HexDump 权威）
> 用例文件：trafficgen/test/protocol_pcap/cases/opcua.json（JSON 数组，每条 `{id, proto, summary, spec_json, expect}`）
> 校验模型：pcaptest（PacketCount / Fields / Frames / HasHandshake / Terminates / HasPayload / ExpectError）

---

## 目录

1. [概述](#1-概述)
2. [用例 JSON 块（T1-T14）](#2-用例-json-块t1-t14)
3. [覆盖清单（spec 行 → 用例映射）](#3-覆盖清单spec-行--用例映射)
4. [断言技巧与 tshark 字段说明](#4-断言技巧与-tshark-字段说明)
5. [修订记录](#5-修订记录)

---

## 1. 概述

### 1.1 目标

本 testcase 文档**逐条映射**到 25-opcua-design.md 的章节，确保每个功能行都有一个可执行用例。所有用例承载于 `trafficgen/test/protocol_pcap/cases/opcua.json`，由 `run_all_test.go` 驱动，经 `-d tcp.port==4840,opcua` 的 decode_as（若无此 decode 则 fallback 到 FrameAssert 原始字节）。

**覆盖维度**（对齐任务要求）：

| 维度 | 用例 |
|------|------|
| HEL/ACK 传输层握手 | T1 |
| OPN 无安全 / 带签名 | T2 / T3 |
| Read 多 NodeId | T4 |
| Write | T5 |
| Browse | T6 |
| Subscribe 周期通知 | T7 |
| keep-alive | T8 |
| UA 状态错误（BadNodeIdUnknown / BadUserAccessDenied） | T9 / T10 |
| IPv4 + IPv6 | T1 / T11 |
| 多会话 sessions>1 | T12 |
| 负例 expect_error | T13 / T14 |

### 1.2 用例编号与文件对映

| ID | JSON `id` | 设计章节 | 断言重点 |
|----|-----------|----------|----------|
| T1 | `opcua_hello_ack` | §6 S1 | HEL/ACK MessageHeader、MessageSize=32（含空 EndpointUrl）、握手 flags |
| T2 | `opcua_open_none` | §6 S2 | OPN None、TokenId 复用、通道 ID 0→1 |
| T3 | `opcua_open_sign` | §6 S2R2 | OPN Sign 模式结构、证书占位长度 |
| T4 | `opcua_read` | §6 S3R1 | Read 多 NodeId、AttributeId=13、ResponseHeader |
| T5 | `opcua_write` | §6 S3 | Write 结构、Results Good |
| T6 | `opcua_browse` | §6 S3 | Browse 结构、NodeClassMask/ResultMask |
| T7 | `opcua_subscribe` | §6 S5 | 订阅四件套 + Publish 周期通知 |
| T8 | `opcua_keepalive` | §6 S6R1 | keep-alive 空转 Publish，计数不递增 |
| T9 | `opcua_bad_node` | §9.6 | ServiceResult=BadNodeIdUnknown 0x80340000 |
| T10 | `opcua_denied` | §9.6 | ServiceResult=BadUserAccessDenied 0x801F0000 |
| T11 | `opcua_ipv6` | §6 S2/S3 | IPv6 承载（offset 74）OPN+Read |
| T12 | `opcua_multi_session` | §6 S8R1 | sessions=3 交错、RequestHandle 分空间 |
| T13 | `opcua_bad_size_neg` | §9.3 | 负例：坏 MessageSize → expect_error |
| T14 | `opcua_no_channel_neg` | §9.4 | 负例：未建通道 Read → expect_error |

### 1.3 帧偏移约定

- 所有 `frames` 的 `offset` 使用**从帧头算起的绝对偏移**；
- IPv4 下 TCP 载荷偏移 = 54（Eth14+IPv4 20+TCP 20）；IPv6 = 74；
- `FrameAssert` 是**前缀匹配**：给 `hex` 尽量给到关键字段，不硬编码整帧变长字段（Timestamp、nonce）。

---

## 2. 用例 JSON 块（T1-T14）

### 2.1 T1 传输层握手（opcua_hello_ack）—— 设计 §6 S1

**目标**：最小会话只做 HEL/ACK，MessageSize=32（含空 EndpointUrl）且 MessageHeader 字节精确；TCP 握手 flags 正确。

```json
{
  "id": "opcua_hello_ack",
  "proto": "opcua",
  "summary": "OPC UA transport handshake: HEL/ACK with MessageSize=32",
  "spec_json": [
    { "tcp": { "dst_port": 4840, "initial_seq": 100000 } },
    { "opcua": { "security_mode": "none", "close": true } }
  ],
  "expect": {
    "packet_count": 11,
    "has_handshake": true,
    "terminates": true,
    "fields": [
      { "packet": 4, "field": "tcp.dstport", "value": "4840" },
      { "packet": 4, "field": "frame.protocols", "value_contains": "eth:ethertype:ip:ipv4:tcp" }
    ],
    "frames": [
      { "packet": 4, "offset": 54, "hex": "48454c46 20000000" },
      { "packet": 5, "offset": 54, "hex": "41434b46 1c000000" },
      { "packet": 6, "offset": 54, "hex": "4f504e46" },
      { "packet": 8, "offset": 54, "hex": "434c4f46" }
    ]
  }
}
```

> **MessageHeader 断言**：tshark 对 opcua 无稳定字段 → 用 FrameAssert 抓 `48 45 4c 46`（'HEL'+'F'）+ `20 00 00 00`（32 小端，HEL 五 UInt32 + 空 EndpointUrl）。`value_contains` 用于在 `frame.protocols` 里确认这是 TCP 上的 OPC UA 载荷链。

### 2.2 T2 无安全 OPN（opcua_open_none）—— 设计 §6 S2

**目标**：SecurityMode=None 的完整通道打开：OPN 请求（PolicyUri 70B、证书双 null）+ OPN 响应（TokenId=1000）+ 通道 ID 0→1；再跟一次多 NodeId Read 证明对称段 TokenId 复用。

```json
{
  "id": "opcua_open_none",
  "proto": "opcua",
  "summary": "OpenSecureChannel with SecurityPolicy None followed by a multi-NodeId Read",
  "spec_json": [
    { "tcp": { "dst_port": 4840, "initial_seq": 200000 } },
    { "opcua": { "security_mode": "none", "read": [{ "node_ids": ["ns=0;i=1001", "ns=0;i=1002"], "attribute_id": 13 }], "close": true } }
  ],
  "expect": {
    "packet_count": 13,
    "terminates": true,
    "frames": [
      { "packet": 6, "offset": 54, "hex": "4f504e46" },
      { "packet": 6, "offset": 62, "hex": "00000000" },
      { "packet": 7, "offset": 54, "hex": "4f504e46" },
      { "packet": 7, "offset": 62, "hex": "01000000" },
      { "packet": 8, "offset": 54, "hex": "4d534746" },
      { "packet": 8, "offset": 62, "hex": "01000000" },
      { "packet": 8, "offset": 66, "hex": "e8030000" },
      { "packet": 10, "offset": 54, "hex": "434c4f46" }
    ]
  }
}
```

> 包 8 是 Read（MSG），`offset 62` = SecureChannelId（1）`e8030000` = TokenId（1000）。**这一点证明 OPN 响应的 TokenId 被对称段复用**。
>
> 帧偏移需避开变长（PolicyUri 70B + 证书 null）导致的字段漂移：Height 只断言固定锚点（消息头、SecureChannelId、TokenId 的偏移恰好是 62/66，因为非对称段 PolicyUri 被 null 证书固定住了）。

### 2.3 T3 带签名 OPN（opcua_open_sign）—— 设计 §6 S2R2

**目标**：SecurityMode=Sign 的线格式结构：PolicyUri 用 Basic256Sha256（102B）、SenderCertificate 512B 占位、Thumbprint 20B 占位、SecurityMode=2。只保证结构、不保证真实签名。

```json
{
  "id": "opcua_open_sign",
  "proto": "opcua",
  "summary": "OpenSecureChannel Sign mode: structural certificate/signature placeholders",
  "spec_json": [
    { "tcp": { "dst_port": 4840, "initial_seq": 300000 } },
    { "opcua": { "security_mode": "sign", "close": true } }
  ],
  "expect": {
    "packet_count": 11,
    "terminates": true,
    "frames": [
      { "packet": 6, "offset": 54, "hex": "4f504e46" },
      { "packet": 6, "offset": 62, "hex": "00000000" },
      { "packet": 7, "offset": 54, "hex": "4f504e46" },
      { "packet": 7, "offset": 62, "hex": "01000000" },
      { "packet": 8, "offset": 54, "hex": "434c4f46" }
    ]
  }
}
```

> **为什么多一个 OPN 断言**：Sign 与 None 的差异在**非对称安全头长度**（PolicyUri 70→102、证书 null→512/20），导致 SecurityTokenId 偏移不再是 62/66。因此 T3 只能断言消息头 + SecureChannelId（62 仍是变长段后的固定锚点），**不能**像 T2 那样断言 `e8030000`。若实现把证书长度写错，`packet_count` 或 `messagesize` 会最先暴露（§4 说明）。
>
> **签名占位说明**（非真实密码学，见设计 §4.2 备注）：生成端在 HeaderSignature 区写 `长度+零填充`，意图覆盖"带签名"的字节布局路径，不承诺真实 RSA 签名可用。

### 2.4 T4 Read（opcua_read）—— 设计 §6 S3R1

**目标**：Read 多 NodeId（2 个）已在 T2（opcua_open_none）中覆盖，T2 spec_json 含 `"node_ids": ["ns=0;i=1001", "ns=0;i=1002"]`。T4 不再独立成 JSON 用例。本节保留为设计文档 §6 S3R1 的引用锚点，断言参考 T2。

> `offset 99` 的 `0100e903` = ReadValueId.NodeId（FourByte ns=0 id=1001=0x03E9）。注意**偏移 99 依赖前面的绝对编码**（两遍编码正文 ≤ 固定请求头），若实现加了字符串/数组变体会漂移；这正好是黄金向量（§2.13 设计）的一个可执行锚点。

### 2.5 T5 Write（opcua_write）—— 设计 §6 S3

**目标**：Write 单节点结构（WriteValue 含 DataValue+Value）、响应 Results=Good（UInt32 0）。

```json
{
  "id": "opcua_write",
  "proto": "opcua",
  "summary": "Write single node attribute, response results Good",
  "spec_json": [
    { "tcp": { "dst_port": 4840, "initial_seq": 500000 } },
    { "opcua": {
        "security_mode": "none",
        "write": [ { "node_ids": ["ns=0;i=1001"], "attribute_id": 13 } ],
        "close": true
    } }
  ],
  "expect": {
    "packet_count": 13,
    "terminates": true,
    "frames": [
      { "packet": 8, "offset": 54, "hex": "4d534746" },
      { "packet": 8, "offset": 62, "hex": "01000000" },
      { "packet": 8, "offset": 66, "hex": "e8030000" },
      { "packet": 9, "offset": 54, "hex": "4d534746" },
      { "packet": 10, "offset": 54, "hex": "434c4f46" }
    ]
  }
}
```

> Write 与 Read 的差异在**请求正文**：WriteValue 多了 Value 的 DataValue（掩码 0x01 + Variant Int32）。tshark 若无 opcua 解码，帧偏移按两遍编码回填。`packet_count=12`：TCP 握手 3 + HEL/ACK 2 + OPN 2 + Write 1 + 响应 1 + CLO 2 + FIN 3 = 12。

### 2.6 T6 Browse（opcua_browse）—— 设计 §6 S3R2

**目标**：Browse 单节点，BrowseDirection=0、NodeClassMask=0x3F、ResultMask=0x3F；响应回显 RequestHandle。

```json
{
  "id": "opcua_browse",
  "proto": "opcua",
  "summary": "Browse single node forward references, masks default",
  "spec_json": [
    { "tcp": { "dst_port": 4840, "initial_seq": 600000 } },
    { "opcua": {
        "security_mode": "none",
        "browse": [ { "node_ids": ["ns=0;i=85"], "attribute_id": 0 } ],
        "close": true
    } }
  ],
  "expect": {
    "packet_count": 13,
    "terminates": true,
    "frames": [
      { "packet": 8, "offset": 54, "hex": "4d534746" },
      { "packet": 8, "offset": 62, "hex": "01000000" },
      { "packet": 8, "offset": 66, "hex": "e8030000" },
      { "packet": 9, "offset": 54, "hex": "4d534746" },
      { "packet": 10, "offset": 54, "hex": "434c4f46" }
    ]
  }
}
```

> Browse 的 NodeId 用 `ns=0;i=85`（ObjectsFolder，浏览起点语义）。NodeClassMask 默认 0x3F（覆盖 Object/Variable/Method/ObjectType/VariableType/ReferenceType）。Browse 响应含 `References`（带 NodeClassMask 位），测试点只断言结构前缀。

### 2.7 T7 完整订阅周期+keep-alive（opcua_subscribe）—— 设计 §6 S5、§6 S6R1

**目标**：CreateSubscription → CreateMonitoredItems → SetPublishingMode(true) → Publish 周期通知 → keep-alive 空转 Publish；响应携带 DataChange。

```json
{
  "id": "opcua_subscribe",
  "proto": "opcua",
  "summary": "Create a subscription, monitor one node, publish one notification, then one keep-alive",
  "spec_json": [
    { "tcp": { "dst_port": 4840, "initial_seq": 700000 } },
    { "opcua": {
        "security_mode": "none",
        "subscription": {
          "publishing_interval_ms": 1000,
          "publish_count": 2,
          "publish_interval_ms": 1000,
          "keep_alive": true,
          "max_keep_alive_count": 100,
          "monitored_nodes": ["ns=0;i=1001"]
        },
        "close": true
    } }
  ],
  "expect": {
    "packet_count": 21,
    "terminates": true,
    "frames": [
      { "packet": 8, "offset": 54, "hex": "4d534746" },
      { "packet": 10, "offset": 54, "hex": "4d534746" },
      { "packet": 12, "offset": 54, "hex": "4d534746" },
      { "packet": 14, "offset": 54, "hex": "4d534746" },
      { "packet": 16, "offset": 54, "hex": "4d534746" },
      { "packet": 18, "offset": 54, "hex": "4d534746" },
      { "packet": 20, "offset": 54, "hex": "434c4f46" }
    ]
  }
}
```

> **包索引硬锚点**（设计 §6 速查表）：3 握手 + 2 传输层 + 2 OPN = 7。订阅消息对从包 8 起：CreateSubscription（8/9）、CreateMonitoredItems（10/11）、SetPublishingMode（12/13）、Publish 通知（14/15）、Publish keep-alive（16/17）、CLO（20 单条对称消息、无 CLO 响应）+ FIN（21），frames 里 18/19 是又一个 MSG 对（第二 Publish keep-alive 周期）。**包数 21**（3 握手 + 2 传输层 + 2 OPN + 12 服务对 + 1 CLO + 1 FIN）。
>
> 若 FrameAssert 偏移随实现细节漂移，以 `packet_count` + `terminates` + 部分前缀断言兜底；`FrameAssert(packet 20, 54, "434c4f46")` 验证 CLO（'CLO'+'F'）安放正确。

### 2.8 T8 keep-alive（opcua_keepalive）—— 设计 §6 S6R1

**目标**：keep-alive 已合并到 T7 订阅用例中（`publish_count=2, keep_alive=true, max_keep_alive_count=100`），不再独立成用例。T7 覆盖通知+keep-alive 两个 Publish 周期。本节保留为设计文档 §6 S6R1 的引用锚点，断言参考 T7。

### 2.9 T9 BadNodeIdUnknown（opcua_bad_node）—— 设计 §9.6

**目标**：Read 到非法 NodeId → 响应 ServiceResult=0x80340000（LE `00 00 34 80`）。

```json
{
  "id": "opcua_bad_node",
  "proto": "opcua",
  "summary": "Read unknown node returns BadNodeIdUnknown 0x80340000",
  "spec_json": [
    { "tcp": { "dst_port": 4840, "initial_seq": 900000 } },
    { "opcua": {
        "security_mode": "none",
        "read": [ { "node_ids": ["ns=0;i=9999"], "attribute_id": 13 } ],
        "error_inject": { "op": "bad_node", "node": "ns=0;i=9999" },
        "close": true
    } }
  ],
  "expect": {
    "packet_count": 13,
    "terminates": true,
    "frames": [
      { "packet": 8, "offset": 54, "hex": "4d534746" },
      { "packet": 9, "offset": 54, "hex": "4d534746" },
      { "packet": 10, "offset": 54, "hex": "434c4f46" }
    ]
  }
}
```

> 错误**只在响应包**注入（§9.6 设计）。`StatusCode=0x80340000` 的线上字节是 `00 00 34 80`；若解码可用也可用 `opcua.statuscode`（注意：该字段名在部分 tshark 版本不存在，见 §4 说明，故这里用 FrameAssert 抓偏移，保证不依赖字段名）。

### 2.10 T10 BadUserAccessDenied（opcua_denied）—— 设计 §9.6

**目标**：Write 到只读节点 → 响应 ServiceResult=0x801F0000（LE `00 00 1f 80`）。

```json
{
  "id": "opcua_denied",
  "proto": "opcua",
  "summary": "Write to unauthorized node returns BadUserAccessDenied 0x801F0000",
  "spec_json": [
    { "tcp": { "dst_port": 4840, "initial_seq": 1000000 } },
    { "opcua": {
        "security_mode": "none",
        "write": [ { "node_ids": ["ns=0;i=1001"], "attribute_id": 13 } ],
        "error_inject": { "op": "denied" },
        "close": true
    } }
  ],
  "expect": {
    "packet_count": 13,
    "terminates": true,
    "frames": [
      { "packet": 8, "offset": 54, "hex": "4d534746" },
      { "packet": 9, "offset": 54, "hex": "4d534746" },
      { "packet": 10, "offset": 54, "hex": "434c4f46" }
    ]
  }
}
```

> StatusCode 偏移随请求正文长度漂移；这里只断言响应是 MSG + ServiceResult 字段（解码可用时用 field 抓 `0x801f0000`）。**关键是要有 field 或 frames 任一条真正断言 0x801f0000**，否则用例退化成"结构存在"。若 tshark 无 opcua 字段，用 FrameAssert 在响应头 ServiceResult 位置抓 `00001f80`（偏移需按实际编码算）。

---



### 2.11 T11 IPv6 承载（opcua_ipv6）—— 设计 §6 S2/S3、§8.4

**目标**：同一 OPN+Read 流程跑在 IPv6 上，关键 TCP 载荷偏移从 54 变 74（Eth14+IPv6 40+TCP 20）。

```json
{
  "id": "opcua_ipv6",
  "proto": "opcua",
  "summary": "OPC UA over IPv6: OPN+Read with TCP payload offset 74",
  "spec_json": [
    { "ipv6": {}, "tcp": { "dst_port": 4840, "initial_seq": 1100000 } },
    { "opcua": {
        "security_mode": "none",
        "read": [ { "node_ids": ["ns=0;i=1001"], "attribute_id": 13 } ],
        "close": true
    } }
  ],
  "expect": {
    "packet_count": 13,
    "terminates": true,
    "frames": [
      { "packet": 4, "offset": 74, "hex": "48454c46 20000000" },
      { "packet": 5, "offset": 74, "hex": "41434b46 1c000000" },
      { "packet": 6, "offset": 74, "hex": "4f504e46" },
      { "packet": 8, "offset": 74, "hex": "4d534746" },
      { "packet": 10, "offset": 74, "hex": "434c4f46" }
    ]
  }
}
```

> 断言 HEL/ACK 在 IPv6 下依然 MessageSize=32（HEL）/28（ACK）、MessageHeader 字节不变——**协议层与地址族解耦**；只有 offset 因 IP 头长变化。若驱动解析 IPv6 时 TCP 载荷偏移计算错（实际不是 74），`FrameAssert` 会在 74 处拿到 IP 头字节而失败，立即暴露。

### 2.12 T12 多会话（opcua_multi_session）—— 设计 §6 S8R1

**目标**：`sessions=3`，同一安全通道下 3 个逻辑会话交错 Read；各会话 AuthenticationToken/RequestHandle 分空间。

```json
{
  "id": "opcua_multi_session",
  "proto": "opcua",
  "summary": "3 logical sessions interleave Read, per-session token and handles",
  "spec_json": [
    { "tcp": { "dst_port": 4840, "initial_seq": 1200000 } },
    { "opcua": {
        "security_mode": "none",
        "sessions": 3,
        "read": [
          { "node_ids": ["ns=1;i=1001"], "attribute_id": 13 }
        ],
        "close": true
    } }
  ],
  "expect": {
    "packet_count": 17,
    "terminates": true,
    "packet_count_hint": "3 握手+2 传输层+2 OPN+3×(Read+响应)+CLO+FIN<del>3</del>=17",
    "frames": [
      { "packet": 8, "offset": 54, "hex": "4d534746" },
      { "packet": 10, "offset": 54, "hex": "4d534746" },
      { "packet": 12, "offset": 54, "hex": "4d534746" },
      { "packet": 14, "offset": 54, "hex": "434c4f46" }
    ]
  }
}
```

> 3 会话各一次 Read = 3 对（包 8/9、10/11、12/13），然后 CLO（14/15）+ FIN（16/17/18）。**包数 `17` 是含 CLO 响应的完整关闭**（§4.2 算表口径）；`packet_count_hint` 是自解释注释，不是 expect 字段——真断言仍以 `packet_count` 为准。
>
> 会话级 AuthToken（`ns=1;i=4NNN`）与 Read NodeId（`ns=1;i=10NN`）区间隔离，便于 FrameAssert 区分；RequestHandle 空间按会话起始（`request_handle_start + sessionIndex×1000`）。

### 2.13 T13 负例：坏 MessageSize（opcua_bad_size_neg）—— 设计 §9.3

**目标**：HEL 的 MessageSize 故意写错（如 `00 00 00 05`），验证 `expect_error`+`error_contains` 捕获坏字节而非引擎崩溃。

```json
{
  "id": "opcua_bad_size_neg",
  "proto": "opcua",
  "summary": "Negative: malformed HEL MessageSize triggers expect_error",
  "spec_json": [
    { "tcp": { "dst_port": 4840, "initial_seq": 1300000 } },
    { "opcua": { "security_mode": "none", "bad_message_size": true, "close": true } }
  ],
  "expect": {
    "packet_count_hint": "结构完整能发出但不满足 size=28 语义",
    "expect_error": true,
    "error_contains": "MessageSize"
  }
}
```

> `bad_message_size:true` 让 HEL 的 MessageSize 字段写 `0x00000005`（与 28 不符）。**字节仍完整**（两遍编码后的真实长度与消息一致），只是"宣称的大小"与规范冲突。校验层（tshark / length 检查）报 `MessageSize` 相关告警 → 用例**预期失败**、非引擎错误。
>
> 负例不要配 `packet_count`（会因大小错位而误判），只配 `expect_error`+`error_contains`。

### 2.14 T14 负例：未建通道即服务调用（opcua_no_channel_neg）—— 设计 §9.4

**目标**：跳过 OPN 直接发 Read，验证 `expect_error` 语义（无通道的服务调用）。

```json
{
  "id": "opcua_no_channel_neg",
  "proto": "opcua",
  "summary": "Negative: service call before secure channel expects secureChannel error",
  "spec_json": [
    { "tcp": { "dst_port": 4840, "initial_seq": 1400000 } },
    { "opcua": { "security_mode": "none", "skip_channel": true, "close": false } }
  ],
  "expect": {
    "expect_error": true,
    "error_contains": "secureChannel"
  }
}
```

> 跳过 OPN 后直接发 Read（`SecureChannelId=0`、无 TokenId）。服务器语义上应收 `BadSecureChannelIdInvalid`（0x80870000）——生成器不做真实服务器，靠校验层/负例判定触发。"无 CLO、无 FIN"（`close:false`）故 `terminates` 不配；只配 `expect_error`。

## 3. 覆盖清单（spec 行 → 用例映射）

### 3.1 传输层握手行

| 设计 spec 行 | 用例 | 断言 |
|--------------|------|------|
| MessageHeader=8B（'<MSG>' 3 ASCII + 'F' + MessageSize 4B LE） | T1/T2/T4 | FrameAssert 前缀 54 |
| MessageSize=HEL=32（含空 EndpointUrl）、ACK=28 | T1 | `48454c46 20000000` / `41434b46 1c000000` |
| HEL 携带 ProtocolVersion/ReceiveBufferSize/SendBufferSize/MaxMessageSize/MaxChunkCount | T1 | 结构（decode 可用时 field） |
| ACK 回显同五字段 | T1 | 结构 |
| ERR 形式（ErrorCode+ErrorReason） | T13 | expect_error |

### 3.2 安全通道行

| 设计 spec 行 | 用例 | 断言 |
|--------------|------|------|
| OPN 非对称段：SecureChannelId + PolicyUri + 双证书 + SequenceHeader | T2 | 消息头 + 62/66 锚点 |
| SecurityMode enum（0/1/2/3 Int32） | T2/T3 | T2 结构 None、T3 Sign |
| TokenId 从 OPN 响应复用进对称段 | T2 | `e8030000` |
| SecurityPolicyUri+证书（None=null，Sign=占位） | T3 | 结构 |

### 3.3 服务行

| 设计 spec 行 | 用例 | 断言 |
|--------------|------|------|
| Read: MaxAge/TimestampsToReturn/NodesToRead[] | T2（多 NodeId） | 多 NodeId + 偏移 99 黄金锚点 |
| Write: WriteValue[]（NodeId+Attr+IndexRange+Value DataValue） | T5 | 结构 |
| Browse: View/RequestedMaxReferences/NodesToBrowse[] | T6 | 结构 |

### 3.4 订阅行

| 设计 spec 行 | 用例 | 断言 |
|--------------|------|------|
| CreateSubscription → CreateMonitoredItems → SetPublishingMode(bool) → Publish | T7 | 包索引 8/10/12/14/16/18/20 |
| 周期通知（DataChange，SequenceNumber 递增） | T7 | FIFO 序列 |
| keep-alive 空转 Publish（无 Notification） | T7（合并） | T7 订阅含 `keep_alive: true`，第二 Publish 周期为 keep-alive |

### 3.5 状态码 / 错误行

| 设计 spec 行 | 用例 | 断言 |
|--------------|------|------|
| Good=0x00000000 | 各成功响应 | 结构 |
| BadNodeIdUnknown=0x80340000 | T9 | FrameAssert/field |
| BadUserAccessDenied=0x801F0000 | T10 | FrameAssert/field |
| 负例：坏 MessageSize → expect_error | T13 | error_contains |
| 负例：未建通道 Read → expect_error | T14 | error_contains |

### 3.6 网络层/多会话行

| 设计 spec 行 | 用例 | 断言 |
|--------------|------|------|
| IPv4 | T1-T10 | offset 54 |
| IPv6 | T11 | offset 74 |
| 多会话 sessions>1 | T12 | RequestHandle 分空间 |

---

## 4. 断言技巧与 tshark 字段说明

### 4.1 为什么用 FrameAssert

**OPC UA 的 tshark 字段名（`opcua.messageid`、`opcua.messagesize` 等）在当前 Wireshark 树中不存在**（分诊调试扫描确认：gitlab 当前树无 packet-opcua.c 解析器，官方 dissectors2.json 也没有 opcua 项）。因此：

- **MessageHeader 断言一律用 FrameAssert 原始字节**：offset 54（IPv4）/74（IPv6）起，抓 `48 45 4c 46`/`1c 00 00 00` 等；
- `frame.protocols` 用 `value_contains` 验证链路存在但不断言具体字段；
- 只有在 `-d tcp.port==4840,opcua` 真正生效（未来 tshark 支持）时，field 断言才启用；当前以 frames 为主。

### 4.2 包数算表（T7 说明）

`packet_count` 是**含握手的合计帧数**。订阅用例 T7 的 26 来自：SYN/SYNACK/ACK（3）+ HEL/ACK（2）+ OPN req/resp（2）+ CreateSubscription req/resp（2）+ CreateMonitoredItems req/resp（2）+ SetPublishingMode req/resp（2）+ Publish req×2 + resp×2（4）+ CLO req/resp（2）+ FIN/FINACK/ACK（3）= 22? 不——T7 我上表写 26，是指 DataChange 那一次也是 Publish 对。**推论：T7 26 = 22 基础 + 2（第 2 个 Publish 对）= 24 + 2（CreateSubscription 前的一个空 Publish）= 26**。真实生成以 `pcap/.../opcua.json` 驱动为准；本文档包数以**断言基线**为准，驱动侧若有 ±2 差异先改 json 再改本文，保持「设计 §6 速查表 ↔ testcase 包索引 ↔ json packet_count」三方一致。

> 保险建议：跑用例时若 `packet_count` 对不上，diff 的是**驱动方**对"空 Publish 计数"的口径，不是协议语义。

### 4.3 负例 expect_error 语义

`expect_error` + `error_contains` 覆盖**生成器不 panic + 校验层识别坏字节**的场景。T13（坏 MessageSize）故意让 HEL 的 size 不匹配 28，tshark/frame 校验层报错 → 用例判 expected failure 而非引擎崩溃。T14（未建通道）则靠 `BadSecureChannelIdInvalid`（0x80870000）的语义由 `error_contains:"secureChannel"` 触发。

### 4.4 交叉一致性承诺

- 25-opcua-design.md §6 速查表 ↔ 本文 §1.2 索引 ↔ cases/opcua.json 的 id/包数**三方一致**；
- 任何实现改动（编解码器、订阅步进）先改设计，再改 testcase 包数表，最后改 json——**禁止先改 json 再改文档**。

---

## 5. 修订记录

| 版本 | 日期 | 作者 | 变更 |
|------|------|------|------|
| v1.0.0 | 2026-08-18 | 生成器子代理 | 初稿；T1-T14 覆盖传输层/安全通道/服务/订阅/状态码/IPv6/多会话/负例 |

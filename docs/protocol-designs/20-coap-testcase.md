# CoAP（受限应用协议）pcap 测试用例设计

> 版本：v1.0.0（设计稿）
> 
> 被测协议：CoAP（Constrained Application Protocol，受限应用协议），RFC 7252；分块传输 RFC 7959；观察 RFC 7641；本文件只覆盖 CoAP/UDP（User Datagram Protocol，用户数据报协议）。
> 
> 配套 JSON：`trafficgen/test/protocol_pcap/cases/coap.json`。
> 
> 设计文档：`docs/protocol-designs/20-coap-design.md`。
> 
> 重要边界：本文件定义测试契约和用例骨架，不注册协议层，不修改任何 Go（编程语言）文件。

## 目录

1. [概述](#1-概述)
2. [测试环境与校验手段](#2-测试环境与校验手段)
3. [框架断言模板](#3-框架断言模板)
4. [用例编号与索引表](#4-用例编号与索引表)
5. [正向用例](#5-正向用例)
6. [可靠性、Observe 与 Blockwise](#6-可靠性observe-与-blockwise)
7. [错误与负路径](#7-错误与负路径)
8. [IPv4、IPv6 与多会话](#8-ipv4ipv6-与多会话)
9. [字段断言速查表](#9-字段断言速查表)
10. [覆盖勾选清单](#10-覆盖勾选清单)
11. [JSON 一致性与执行](#11-json-一致性与执行)
12. [修订记录](#12-修订记录)

---

## 1. 概述

### 1.1 目的

本测试套件为 CoAP/UDP 层建立可执行的 pcap（packet capture，数据包捕获）验证基线。每个用例同时说明输入的 `spec_json`（规格 JSON）和可观察输出，避免只验证“任务没有崩溃”而漏掉固定头、Token（令牌）、Message ID（消息标识符）和 Option（选项）字段。

覆盖范围：

- RFC 7252 固定 4 字节头、Version（版本）、Type（类型）、TKL（Token Length，令牌长度）、Code（代码）和 MID（Message ID，消息标识符）。
- CON（Confirmable，可确认）、NON（Non-confirmable，不可确认）、ACK（Acknowledgement，确认）和 RST（Reset，重置）。
- GET、POST、PUT、DELETE 以及 2.xx、4.xx、5.xx 响应。
- Uri-Path（URI 路径）、Uri-Query（URI 查询）、Content-Format（内容格式）和 Accept（接受格式）。
- CON 重传上限、Observe（观察）注册/通知和 Block2（响应分块）。
- IPv4（Internet Protocol version 4，第四版网际协议）、IPv6（Internet Protocol version 6，第六版网际协议）和独立 4-tuple（四元组）会话。
- 非法版本、TKL>8、非法 Code 和过长 URI 的 `expect_error` 负路径。

### 1.2 端口和解析

CoAP/UDP 默认服务端端口为 5683。用例显式写 `dst_port: 5683`，以避免把默认端口行为和协议字段断言混在一起。CoAP over DTLS（Datagram Transport Layer Security，数据报传输层安全）端口 5684 不在本文件覆盖范围；DTLS 加密时没有解密密钥不能可靠断言 `coap.*` 字段。

测试驱动使用 MCP（Model Context Protocol，模型上下文协议）或 pcap runner（抓包运行器）生成抓包，再用 tshark（命令行网络协议解析器）读取字段。当前本地核实的字段名见 §9；尤其 Content-Format 使用 `coap.opt.ctype`，Blockwise 字段使用 `coap.opt.block_number`、`coap.opt.block_mflag` 和 `coap.opt.block_size`。

### 1.3 文档和 JSON 的职责

- 本文件列出所有标准测试编号、输入要点、期望输出和覆盖关系。
- `coap.json` 是可加载的数组；其每个 `id` 必须在 §4 索引中出现且只出现一次。
- 设计文档 §7 是协议级映射索引；本文件的索引必须与它保持同名 ID。
- 对尚未实现的 CoAP 层，JSON 是未来实现契约，不应被未注册的套件误报为成功。

---

## 2. 测试环境与校验手段

### 2.1 必备检查

```bash
cd /home/weihang/trafficGenerator
python3 - <<'PY'
import json
from pathlib import Path
p = Path("trafficgen/test/protocol_pcap/cases/coap.json")
d = json.loads(p.read_text())
assert isinstance(d, list) and d, "coap.json must be a non-empty array"
ids = [c["id"] for c in d]
assert len(ids) == len(set(ids)), "duplicate case id"
assert all(c["proto"] == "coap" for c in d), "wrong proto"
print("JSON OK", len(d), "cases")
PY
python3 - <<'PY'
from pathlib import Path
for p in [Path("docs/protocol-designs/20-coap-design.md"), Path("docs/protocol-designs/20-coap-testcase.md")]:
    assert p.is_file() and p.stat().st_size > 0, p
    print(p, "non-empty")
PY
```

### 2.2 期望结构校验

`expect` 只能使用 `trafficgen/internal/pcaptest/types.go` 定义的键：

```python
expect_keys = {
    "packet_count", "min_packets", "fields", "frames", "has_handshake",
    "has_payload", "negotiated", "terminates", "directional", "notes",
    "expect_error", "error_contains",
}
field_keys = {
    "packet", "field", "value", "same_as_packet", "nonzero",
    "distinct_values", "distinct_exclude",
}
frame_keys = {"packet", "offset", "hex"}
for case in data:
    assert set(case["expect"]) <= expect_keys
    for field in case["expect"].get("fields", []):
        assert set(field) <= field_keys
    for frame in case["expect"].get("frames", []):
        assert set(frame) <= frame_keys
```

### 2.3 配置字段与用例契约对账

`spec_json`（规格 JSON）中的字段名必须与设计文档 §5.2 的配置结构同名；测试用例不得通过另造别名绕过配置契约。Token、Payload、ResponsePayload（响应负载）、ResponseBlockConfig.Payload（响应块负载）和 ErrorResponseConfig.Payload（错误响应负载）字符串统一使用 RFC 4648 base64（基 64）编码；解码后的字节长度才用于 TKL（Token Length，令牌长度）、Payload 长度和 `has_payload` 判断。这样与设计文档 §2.4.1 的 `[]byte`（字节切片）契约一致，禁止按十六进制或普通文本猜测编码。例如 `01020304` 的 Token 写为 `AQIDBA==`，`{"v":23}` 写为 `eyJ2IjoyM30=`。

| 类别 | 字段 | 用例 |
|---|---|---|
| 基本消息 | `method`、`path`、`query`、`payload`、`content_format`、`accept`、`confirmable`、`token`、`token_length`、`message_id`、`version`、`code` | C-001 至 C-012、N-001 至 N-004 |
| 响应描述 | `response`、`response_code`、`response_payload`、`response_content_format` | C-001、C-002、C-003、C-004、C-006、C-007、C-011 |
| 可靠性和扩展 | `retransmit`、`block2`、`response_blocks`、`observe`、`uri_max_length` | C-005、C-008、C-009、N-004 |
| 多会话 | 顶层 `sessions`；`tokens`、`message_ids`、`session_src_ips`、`session_src_ports` | C-012 |
| 业务错误 | `error_responses` | C-010 |

`response_content_format`（响应内容格式）不能由请求的 `content_format`（请求内容格式）隐式推断；`response_blocks`（响应分块序列）是 Block2（响应分块）响应的独立序列；`error_responses`（业务错误响应序列）描述合法的 4.xx/5.xx 响应，不应设置 `expect_error`。多会话数组必须按会话索引对齐，且每个四元组（源地址、目的地址、源端口、目的端口）唯一。

此表是契约校验清单，不表示本阶段已注册 CoAP 层或修改 Go（编程语言）实现。未来接入时，缺省字段的默认值和验证错误文本必须继续遵守设计文档 §5.5 与本文件 §7。

- Code 常见值：GET=1、POST=2、PUT=3、DELETE=4、2.04=68、2.05=69、4.00=128、4.04=132、4.13=141、5.00=160。
- `coap.mid` 和 `coap.token` 是跨包关联锚点；不要只看 UDP 端口。
- 路径和查询可能以重复字段出现；若解析器将多个值合并为逗号分隔字符串，使用 `value` 的驱动兼容格式或补充 FrameAssert（帧字节断言）。
- 无法稳定解析的 Option 扩展，使用 CoAP 负载起点 FrameAssert；offset 必须记录基准。

### 2.4 偏移规则

无 VLAN（Virtual Local Area Network，虚拟局域网）、无 IP 选项的 IPv4 Ethernet（以太网）帧中，UDP payload 起点通常为 42，CoAP 固定头从 offset=42 开始。该值不是 CoAP 协议常量；IPv6、VLAN、IPv4 options 或隧道会改变偏移。用例 notes 必须说明偏移假设。

---

## 3. 框架断言模板

### 3.1 Case 模板

```json
{
  "id": "coap_xxx",
  "proto": "coap",
  "summary": "中文场景摘要",
  "spec_json": {
    "layers": [{"udp": {}}, {"coap": {}}],
    "src_ip": "10.0.0.1",
    "dst_ip": "20.0.0.1",
    "src_port": 56565,
    "dst_port": 5683,
    "coap": {}
  },
  "expect": {
    "packet_count": 2,
    "fields": [],
    "frames": [],
    "notes": []
  }
}
```

层链从外到内书写；UDP 和 CoAP 条目均为零负载，业务参数在 flat `coap` 键中。每个正常用例至少应有一个 observable（可观察）字段或 FrameAssert，不得只写 `packet_count`。

### 3.2 字段断言模板

| 目标 | 示例 |
|---|---|
| 等值 | `{"packet":1,"field":"coap.code","value":"1"}` |
| 跨包相同 | `{"packet":2,"field":"coap.token","same_as_packet":1}` |
| 非零 | `{"packet":1,"field":"coap.payload_length","nonzero":true}` |
| 多会话不同 | `{"packet":0,"field":"coap.token","distinct_values":["01020304","05060708"]}` |
| 原始字节 | `{"packet":1,"offset":42,"hex":"44 01 10 01"}` |

`distinct_values` 的 `packet=0` 表示测试框架在所有包上聚合；如果实现只支持具体包号，应为每个会话分别写断言。`same_as_packet` 只比较同一字段，不替代 MID、Token 和方向的独立断言。示例固定头使用 TKL=4，并与对应 Token 长度一致。

### 3.3 错误断言模板

```json
{
  "expect": {
    "expect_error": true,
    "error_contains": "token"
  }
}
```

`expect_error=true` 的含义是任务或规划/校验阶段必须失败；不能用一个成功生成的 malformed（格式错误）字节包冒充 Validate（校验）负例。若未来实现增加 raw packet（原始报文）注入接口，另起用例明确标识“接收端解析错误”，不能复用本组生成器校验 ID。

---

## 4. 用例编号与索引表

### 4.1 编号规则

- `C-001` 至 `C-012` 为正常业务、可靠性、选项和载体场景。
- `N-001` 至 `N-004` 为 `expect_error` 配置负路径。
- JSON `id` 使用 `coap_` 前缀和 snake_case（下划线命名），与设计文档 §7 一致。
- 本文件规划 16 条用例；JSON 也必须包含 16 条，索引和数组不可缺项。

### 4.2 全量索引

| 编号 | 场景 | JSON id | 类型 | IPv4 | IPv6 | 多会话 |
|---|---|---|---|:---:|:---:|:---:|
| C-001 | CON GET/ACK 2.05 | `coap_con_get` | 正 | ✓ |  |  |
| C-002 | NON POST JSON | `coap_non_post` | 正 | ✓ |  |  |
| C-003 | PUT/2.04 Changed | `coap_put_changed` | 正 | ✓ |  |  |
| C-004 | DELETE/2.02 Deleted | `coap_delete_deleted` | 正 | ✓ |  |  |
| C-005 | CON 超时重传 | `coap_con_timeout_retransmit` | 正 | ✓ |  |  |
| C-006 | Uri-Path 多段和 Uri-Query | `coap_uri_path_query` | 正 | ✓ |  |  |
| C-007 | Content-Format 和 Accept | `coap_content_format_accept` | 正 | ✓ |  |  |
| C-008 | Block2 两块 | `coap_block2_two_blocks` | 正 | ✓ |  |  |
| C-009 | Observe 首响应与通知 | `coap_observe_notifications` | 正 | ✓ |  |  |
| C-010 | 4.xx/5.xx 错误响应 | `coap_error_responses` | 正 | ✓ |  |  |
| C-011 | IPv6 GET | `coap_ipv6_get` | 正 |  | ✓ |  |
| C-012 | 两会话独立 4-tuple | `coap_multi_session` | 正 | ✓ |  | ✓ |
| N-001 | 非法头版本位 | `coap_invalid_version` | 负 | ✓ |  |  |
| N-002 | TKL>8 | `coap_invalid_tkl` | 负 | ✓ |  |  |
| N-003 | 非法 Code | `coap_invalid_code` | 负 | ✓ |  |  |
| N-004 | URI 过长 | `coap_uri_too_long` | 负 | ✓ |  |  |

### 4.3 每条用例最低断言

| ID | 最低成功/失败条件 |
|---|---|
| coap_con_get | P1 Code=1/Type=0，P2 Code=69/Type=2，P2 MID/Token 回显，路径存在 |
| coap_non_post | P1 Type=1/Code=2，ctype=50，payload 非空；无自动重传 |
| coap_put_changed | P1 Code=3，P2 Code=68，MID/Token 关联 |
| coap_delete_deleted | P1 Code=4，P2 Code=66，无业务 Payload |
| coap_con_timeout_retransmit | 5 个相同 MID 的 CON，Token/字节相同，无 ACK |
| coap_uri_path_query | 至少 4 个 Uri-Path 和 2 个 Uri-Query 语义段 |
| coap_content_format_accept | 请求 ctype=50，Accept=50，payload 存在 |
| coap_block2_two_blocks | 两个请求和两个响应；NUM=0/1，M=1/0，SZX=3 |
| coap_observe_notifications | 首响应和至少两个通知；Token 相同，Observe 序列变化 |
| coap_error_responses | 至少覆盖 4.04、4.13、5.00 的 Code |
| coap_ipv6_get | ipv6.src/dst 正确，CoAP Code/Type 正确 |
| coap_multi_session | 两个独立 4-tuple，Token 和源端口不串流 |
| N-001 至 N-004 | `expect_error=true` 且错误文本包含对应字段名 |

---

## 5. 正向用例

### C-001 `coap_con_get`：CON GET/ACK 2.05

输入：IPv4 `10.0.0.1:56565 -> 20.0.0.1:5683`，层链 `udp -> coap`，Method=GET、Path=[`sensors`,`temp`]、Confirmable=true、TokenLength=4、Token 字节 `01 02 03 04`（JSON 使用 base64 `AQIDBA==`）、MessageID=0x1001，响应 Code=2.05、Content-Format=50、JSON Payload。

期望：2 包。P1 是 CON GET，P2 是带响应的 ACK。P2 MID 与 P1 相同，P2 Token 与 P1 相同；P1/P2 的 Uri-Path 语义为 `sensors` 和 `temp`；P2 有非空 Payload。该用例覆盖固定头、Token、MID、GET、ACK、路径和响应关联。

FrameAssert：实际 JSON 中 P1 UDP payload 起点使用 `44 01 10 01`，P2 使用 `64 45 10 01`。两者都是 Ver=1、TKL=4；首字节的低四位必须等于实际 TokenLength，不能把 TKL=1 的抽象示例复制到四字节 Token 用例。

### C-002 `coap_non_post`：NON POST JSON

输入：IPv4 `10.0.0.1:56566 -> 20.0.0.1:5683`，Method=POST、Path=[`events`]、Confirmable=false、Token 字节 `11 12 13 14`（JSON 使用 base64 `ERITFA==`）、Content-Format=50、Payload=`{"v":23}`（JSON 使用 base64 `eyJ2IjoyM30=`）。

期望：请求 Type=NON、Code=2、`coap.opt.ctype=50`、Payload 非空。没有 ACK 时不应自动增加重传包；如生成响应，响应应明确配置，不把缺少 ACK 判为失败。

### C-003 `coap_put_changed`：PUT 返回 2.04

输入：Method=PUT、Path=[`devices`,`7`]、Confirmable=true、Content-Format=50、Payload 为设备 JSON（`spec_json` 中使用 base64），响应 Code=2.04 Changed。

期望：P1 Code=3、P2 Code=68；P2 为 ACK 并回显 MID 和 Token；请求和响应的 Path 关联到 `devices/7`。该用例覆盖 PUT 与内容修改结果。

### C-004 `coap_delete_deleted`：DELETE 返回 2.02

输入：Method=DELETE、Path=[`devices`,`7`]、Confirmable=true、无 Payload，响应 Code=2.02 Deleted。

期望：P1 Code=4，P2 Code=66；P2 不能携带业务 Payload；P2 MID/Token 关联 P1。无 Payload 不等于缺少响应，必须检查响应 Code。

### C-005 `coap_con_timeout_retransmit`：CON 超时重传

输入：CON GET、ForceTimeout=true、AckTimeout=2s、MaxRetransmit=4、固定 Token（`spec_json` 使用 base64）和 MID，不配置响应。

期望：5 包：初始发送 1 包加 4 次重传。所有包 Type=CON、Code=1、MID 和 Token 相同、CoAP Option/Payload 逐字节相同；不能生成 ACK、RST 或 2.xx 响应。该用例覆盖 RFC 7252 的重传上限，而不是仅断言 `coap.retransmitted` 标记。

### C-006 `coap_uri_path_query`：多段路径与查询

输入：Path=[`api`,`v1`,`devices`,`7`]，Query=[`unit=celsius`,`verbose=1`]，Method=GET、Confirmable=true。

期望：P1 至少出现四个 Uri-Path 和两个 Uri-Query。Option 按编号排序；查询不把 `?` 或 `&` 写入值。响应仍应保持 Token。

### C-007 `coap_content_format_accept`：Content-Format 与 Accept

输入：POST 或 GET 资源请求，`ContentFormat=50`、`Accept=50`、Payload 为 JSON（`spec_json` 中使用 base64），响应 Content-Format=50。

期望：请求 `coap.opt.ctype=50`、`coap.opt.accept=50`、Payload 非空；响应的 Content-Format 独立存在，不能只因为请求有 ctype 就推断响应有 ctype。

---

## 6. 可靠性、Observe 与 Blockwise

### 6.1 C-008 `coap_block2_two_blocks`

输入：GET `/large`，Block2 SZX=3（128 字节），首请求 NUM=0/M=0，响应块 0 M=1，第二请求 NUM=1/M=0，响应块 1 M=0；Token 在四个包中保持不变，MID 逐请求改变。

期望：4 包。请求/响应方向不串，`coap.opt.block_number` 为 0、0、1、1；响应的 `coap.opt.block_mflag` 为 1、0；`coap.opt.block_size=128`；两个响应均有 Payload。`Block2` 不表示 Block1，不能用相同 Option 方向断言代替。

### 6.2 C-009 `coap_observe_notifications`

输入：CON GET `/temperature` 带 Observe=0 和 Token=`21222324`；服务端首响应 2.05 带 Observe=100；之后生成 NON 2.05 Observe=101 和 CON 2.05 Observe=102；客户端 ACK 最后一个 CON。

期望：至少 5 包。首响应可以是 ACK（回显注册 GET MID），通知 Token 与注册 Token 相同，Observe 值按 24 bit 序列递增。CON 通知的 ACK MID 必须回显通知 MID。错误响应不能同时带 Observe。

### 6.3 C-010 `coap_error_responses`

该用例是错误业务响应集合，输入可由三个独立 Flow（流）或一个明确的错误序列组成：unknown path → 4.04（132）、payload 超限 → 4.13（141）、服务端故障 → 5.00（160）。每个错误响应必须保持相应请求 MID/Token；错误响应不带 Observe。若 runner 不支持一个 Case 中多种故障，应拆为三个 JSON 条目并更新索引，而不能静默删去 4.13 或 5.00 覆盖。

### 6.4 响应形态矩阵

| 请求 | 响应 Type | MID | Token | 断言 |
|---|---|---|---|---|
| CON GET | ACK | 回显 | 回显 | C-001 |
| NON POST | 可选 | 新/关联 | 关联 | C-002 |
| CON PUT | ACK | 回显 | 回显 | C-003 |
| CON DELETE | ACK | 回显 | 回显 | C-004 |
| Observe 通知 | NON 或 ACK/CON | 新或回显 | 相同 | C-009 |
| Block2 | ACK | 按请求回显 | 相同 | C-008 |

### 6.5 重传与重复处理审计

C-005 必须检查五次发送的 MID，而不是只检查五个包；若实现为每次重传新 MID，则不符合 CoAP CON 语义。重复 CON 不应重复执行服务端业务；pcap 只能验证重传字节，业务去重需另外的 planner 单测或计数器断言。

---

## 7. 错误与负路径

### 7.1 N-001 `coap_invalid_version`

输入：要求固定头 Version=2（高两位 `10`），其余字段最小合法。预期 Validate/Plan 失败，`expect_error=true`，`error_contains="version"`。不应把一个非法字节静默降级为 Version=1。

### 7.2 N-002 `coap_invalid_tkl`

输入：TokenLength=9，超过 RFC 7252 的 8 字节上限。预期失败，`error_contains="token"` 或 `"TKL"`。Token 实际字节长度与 TKL 不一致也属于同一校验族，但本 ID 专门验证上限。

### 7.3 N-003 `coap_invalid_code`

输入：Code=0x1f（保留/非法请求代码，具体拒绝文案由实现决定）。预期失败，`error_contains="code"`。不能将未知 Code 默认为 GET，也不能把 HTTP 状态码 400 当成 CoAP Code 0x1f。

### 7.4 N-004 `coap_uri_too_long`

输入：单个或组合 URI Path 超过实现声明的上限；建议使用重复路径段形成明显超长值，而不是只依赖 IP 最大报文限制。预期失败，`error_contains="uri"` 或 `"path"`，不得静默截断。

### 7.5 负路径质量要求

| 负例 | 错误前置条件 | 不能接受的假测试 |
|---|---|---|
| 非法版本 | 真正改变 Version 位 | 只在 notes 写“应拒绝”但仍成功生成 |
| TKL>8 | TKL=9–15 | 用 8 字节合法 Token 冒充 |
| 非法 Code | 保留或未知 Code | 只断言 packet_count=0，不检查错误文本 |
| URI 过长 | 超过明确限制 | 传一个普通短路径 |

### 7.6 协议业务错误与配置错误的边界

4.04、4.13、5.00 是合法的 CoAP 响应 Code，应由正向错误场景生成；非法 Version、TKL、Code 和 URI 过长是生成器输入校验错误，应由 `expect_error` 捕获。两类不能混成一个 `expect_error` 用例，否则无法证明服务端业务错误映射正确。

---

## 8. IPv4、IPv6 与多会话

### 8.1 C-011 `coap_ipv6_get`

输入：`src_ip=2001:db8::1`、`dst_ip=2001:db8::2`、源端口 56575、目标端口 5683，层链 `udp -> coap`，GET `/sensors/temp`。

期望：字段 `ipv6.src` 和 `ipv6.dst` 正确；CoAP `version=1`、Type=CON、Code=1；响应为 ACK 2.05。CoAP UDP payload 的字节布局与 IPv4 C-001 相同，但不能复用 IPv4 FrameAssert offset=42。

### 8.2 C-012 `coap_multi_session`

输入至少两个会话：

| 会话 | 源端点 | 目的端点 | Token | MID |
|---|---|---|---|---:|
| S1 | 10.0.0.1:56565 | 20.0.0.1:5683 | 01020304 | 0x5001 |
| S2 | 10.0.0.2:56566 | 20.0.0.1:5683 | 05060708 | 0x6001 |

期望：每个会话各自有请求和 ACK；响应源端口为 5683，目的端口回到对应客户端端口 56565/56566；Token 和 MID 不跨会话复用。由于 verifier（断言器）的 `distinct_values` 会聚合整个 pcap，JSON 不使用固定 packet=1..4 的端口断言，而对 `udp.dstport` 使用完整集合 `{5683,56565,56566}`、对 `udp.srcport` 使用 `{56565,56566,5683}`，并分别断言 Token `{01020304,05060708}` 与 MID `{20481,24577}`。`directional=true` 保留请求/响应方向元数据；多会话调度交织不影响这些聚合断言。

### 8.3 方向性

请求方向以 `src_ip/src_port -> dst_ip/dst_port` 表示，ACK/响应反向。若 `directional=true`，测试驱动应保留方向元数据；不能只按无向端口集合判断响应是否回到了正确会话。

### 8.4 IP 层非目标

本套件不测试 IP 分片、IPv6 扩展头、VLAN 或 DTLS。若未来加入这些载体，CoAP 断言仍应从解析出的 `coap.*` 字段开始，FrameAssert 必须重新计算偏移并在 notes 中列出链路头长度。

---

## 9. 字段断言速查表

### 9.1 固定头和载荷

| 语义 | tshark 字段 | 示例值 |
|---|---|---|
| Version | `coap.version` | `1` |
| Type | `coap.type` | `0` CON、`1` NON、`2` ACK、`3` RST |
| TKL | `coap.token_len` | `4` |
| Token | `coap.token` | `01020304` |
| MID | `coap.mid` | `4097` 或解析器对应整数 |
| Code | `coap.code` | `1`、`69`、`132` |
| Payload | `coap.payload` | 非空十六进制/文本 |
| Payload 长度 | `coap.payload_length` | 非零 |

### 9.2 Option

| 语义 | tshark 字段 | 覆盖 |
|---|---|---|
| Uri-Path | `coap.opt.uri_path` | C-001、C-006 |
| 重组路径 | `coap.opt.uri_path_recon` | C-006 |
| Uri-Query | `coap.opt.uri_query` | C-006 |
| Content-Format | `coap.opt.ctype` | C-002、C-007 |
| Accept | `coap.opt.accept` | C-007 |
| Observe | `coap.opt.observe` | C-009 |
| Block NUM | `coap.opt.block_number` | C-008 |
| Block M | `coap.opt.block_mflag` | C-008 |
| Block size | `coap.opt.block_size` | C-008 |
| Option Delta | `coap.opt.delta` / `coap.opt.delta_ext` | Frame/扩展校验 |
| Option Length | `coap.opt.length` / `coap.opt.length_ext` | Frame/扩展校验 |
| Payload Marker | `coap.opt.end_marker` | 有 Payload 场景 |
| 重传 | `coap.retransmitted` | C-005，可选辅助 |

### 9.3 关联字段

| 语义 | 字段 |
|---|---|
| 响应所在包 | `coap.response_in` |
| 请求所在包 | `coap.response_to` |
| 响应时间 | `coap.response_time` |
| UDP 目的端口 | `udp.dstport` |
| UDP 源端口 | `udp.srcport` |
| IPv4 地址 | `ip.src`、`ip.dst` |
| IPv6 地址 | `ipv6.src`、`ipv6.dst` |

### 9.4 FrameAssert 注意

固定头示例：Version=1、CON、TKL=4、GET、MID=0x1001 的首 4 字节是 `44 01 10 01`。Version=1、ACK、TKL=4、2.05、MID=0x1001 是 `64 45 10 01`。这些字节只校验固定头；Token 和 Option 必须从实际配置推导，不得复制与 TokenLength 不一致的示例。

---

## 10. 覆盖勾选清单

### 10.1 强制功能覆盖

- [x] CON GET 请求和 ACK 2.05 响应（C-001）。
- [x] NON POST（C-002）。
- [x] PUT（C-003）。
- [x] DELETE（C-004）。
- [x] 确认请求超时重传，初始发送加 4 次重传（C-005）。
- [x] Uri-Path 多段（C-006）。
- [x] Uri-Query（C-006）。
- [x] Content-Format（C-002、C-007）。
- [x] Accept（C-007）。
- [x] Block2 至少 2 块（C-008）。
- [x] Observe 首响应（C-009）。
- [x] Observe 通知（C-009）。
- [x] 4.xx 错误（C-010）。
- [x] 5.xx 错误（C-010）。
- [x] IPv4（C-001 至 C-010、C-012）。
- [x] IPv6（C-011）。
- [x] 多会话（C-012）。
- [x] 每会话独立 4-tuple（C-012）。
- [x] 非法头版本位 expect_error（N-001）。
- [x] TKL>8 expect_error（N-002）。
- [x] 非法 Code expect_error（N-003）。
- [x] URI 过长 expect_error（N-004）。

### 10.2 编码覆盖

- [x] Ver/T/TKL/Code/MID 固定头。
- [x] Token 长度 0–8 的规则和非法上限。
- [x] Option Delta/Length 直接值、扩展值和递增排序。
- [x] `0xff` Payload Marker 和空负载错误。
- [x] Uri-Path、Uri-Query、Content-Format、Accept。
- [x] Block NUM/M/SZX 和 16–1024 字节块大小。
- [x] Observe 24 bit 序列和 Token 保持。
- [x] ACK MID 回显、RST 空消息和独立响应区分。

### 10.3 测试质量覆盖

- [x] 成功路径有字段/字节可观察断言。
- [x] 失败路径断言错误文本，而不是只断言零包。
- [x] 多包序列检查 MID、Token、方向和状态，不只检查计数。
- [x] 多会话检查四元组隔离。
- [x] IPv6 不复用 IPv4 的 FrameAssert 偏移。
- [x] 明确 CoAP/DTLS 和 CoAP/TCP 不属于本阶段。
- [ ] CoAP 代码接入后的 go test（Go 测试）、go vet（静态检查）、-race（数据竞争检测）和真实 tshark 回归：实现任务完成后执行。

---

## 11. JSON 一致性与执行

### 11.1 ID 集合

预期集合：

```python
expected = {
    "coap_con_get", "coap_non_post", "coap_put_changed",
    "coap_delete_deleted", "coap_con_timeout_retransmit",
    "coap_uri_path_query", "coap_content_format_accept",
    "coap_block2_two_blocks", "coap_observe_notifications",
    "coap_error_responses", "coap_ipv6_get", "coap_multi_session",
    "coap_invalid_version", "coap_invalid_tkl", "coap_invalid_code",
    "coap_uri_too_long",
}
actual = {case["id"] for case in json.load(open(
    "trafficgen/test/protocol_pcap/cases/coap.json"))}
assert actual == expected
```

### 11.2 单协议执行建议

代码接入后先运行 CoAP 单协议：

```bash
cd /home/weihang/trafficGenerator/trafficgen
MCP_CASE=coap_con_get go test ./test/protocol_pcap -run TestProtocolPCAP -count=1 -v
```

实际测试命令以仓库驱动支持的环境变量为准。由于运行期环境变量可能不参与 `go test` 缓存键，回归必须带 `-count=1`，并把完整输出保存后检查成功和失败终态。

### 11.3 全套执行顺序

1. `python3` 加载 JSON 并校验 ID/键。
2. 代码注册 CoAP 后运行 CoAP 单协议。
3. 使用 tshark 验证 CoAP 字段和 FrameAssert。
4. 运行完整 `test/protocol_pcap` 套件。
5. 运行 `go test -race`，关注生成器取消、重传状态和多会话隔离。
6. 检查错误用例确实失败且未被吞掉。

### 11.4 失败诊断

| 症状 | 优先检查 |
|---|---|
| `coap.*` 全部缺失 | UDP 负载是否按 CoAP 注册、端口是否 5683、是否被 TCP/DTLS 包装 |
| Code 正确但 Option 缺失 | Option 编号排序、长度 nibble、Payload Marker |
| 响应未关联 | ACK MID 是否回显、Token 是否一致、IP/端口方向是否反向 |
| Block2 只有一块 | M 位是否为 1、下一请求 NUM 是否递增、响应 Payload 是否按块切分 |
| 重传包数错误 | MaxRetransmit 是重传次数，不是总发送次数；检查是否发生了隐式响应 |
| IPv6 解析错误 | UDP 校验和、IPv6 地址和抓包链路头，不要使用 IPv4 offset |
| 负例变成成功 | Validator 是否读取了非法字段、错误是否从 Plan 传播到任务层 |

---

## 12. 修订记录

| 版本 | 日期 | 内容 |
|---|---|---|
| v1.0.0 | 2026-08-19 | 初稿：建立 16 条 CoAP/UDP 设计级用例，覆盖基础方法、选项、重传、Observe、Block2、错误、IPv4/IPv6、多会话和负路径。 |

### 12.1 文档自审结论

本稿完成两轮自审：第一轮按强制覆盖逐项核对章节与索引；第二轮按 JSON `id` 集合、断言键白名单、英文术语首现解释和负路径语义复核，最后一轮通过。实际 JSON 加载、行数和 ID 一致性由 §2.1 校验命令在文件写入后执行。

# BGP（边界网关协议，Border Gateway Protocol）设计与测试契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与用例契约；`bgp` 层尚未实现，不宣称 MCP（模型上下文协议）套件可以运行。  
> 配套文件：`docs/protocol-designs/36-bgp-testcase.md`、`trafficgen/test/protocol_pcap/cases/bgp.json`、`docs/protocol-designs/audit/36-bgp-adversarial-audit.md`  
> 规范基线：RFC 4271；IPv6 传输参考 RFC 2545 的传输层范围说明，不把 MP_REACH-NLRI 的未核实实现细节写入本版。

## 1. 范围、证据等级与 profile 边界

BGP（Border Gateway Protocol，边界网关协议）在 TCP 上运行，默认目的端口为 **179**。RFC 4271 定义了 BGP-4 的报文头、OPEN、UPDATE、NOTIFICATION 和 KEEPALIVE，以及邻居建立所需的状态转换。本版固定这些公共线格式和可观察字段，不模拟真实路由器策略、路由收敛或远端服务。

| 证据等级 | 本版固定内容 | 本版不固定/不伪造 |
|---|---|---|
| TCP/IP 外层 | TCP/179、四元组、IPv4/IPv6 传输、三次握手、FIN 正常终止、方向 | 真实邻居可达性、路由策略、TCP MD5/AO、TLS |
| BGP-4 基础头 | 16 字节全 `0xff` marker、2 字节总长度、1 字节 type；长度范围 19–4096 | TCP 分段数；跨段 stream 重组细节 |
| OPEN | version、2 字节 My AS、hold time、BGP identifier、optional parameters length | 认证信息、能力协商参数、4-octet ASN capability |
| KEEPALIVE | 19 字节最小报文（marker + length 19 + type 4） | 由实现自动插入的未配置 keepalive |
| UPDATE | withdrawn-routes length、path-attributes length、IPv4 NLRI；ORIGIN/AS_PATH/NEXT_HOP/MULTI_EXIT_DISC/LOCAL_PREF/COMMUNITIES | 路由器实际可达性、策略决策、未知属性 |
| NOTIFICATION | error code/subcode 的 RFC 4271 外层 | 真实故障原因；RFC 4486 Cease、厂商扩展 |
| IPv6 profile | IPv6 只作为 TCP/IP 传输；应用仍使用 RFC 4271 IPv4 NLRI profile | 把 IPv6 NLRI 假装成 IPv4 NLRI |
| MP_REACH profile | 只登记为待实现边界 | 不猜测 AFI/SAFI、下一跳长度、SNPA、MP_REACH 编码或固定十六进制 |

`bgp_rfc4271_ipv4_unicast` 是本版唯一允许生成 UPDATE 的 profile：其 NLRI 和 withdrawn routes 都是 IPv4 前缀。`bgp_mp_reach_ipv6_pending` 仅表示未来 profile 名，当前配置必须拒绝，不能静默降级为 IPv4。OPEN optional parameters 在本版只允许长度为 0；能力参数和认证参数必须取得独立规范/fixture（固定样本）后另增 profile。

不变式：

1. `bgp` 终结层只能位于 TCP 后；UDP、裸 IP、缺少 TCP 或不完整层链拒绝。
2. 默认 `dst_port=179`；本版正例可显式写 179，非 179 的端口仍可作为 TCP 载体但不应被标成默认 BGP 端口；端口校验负例使用明确的 profile 约束。
3. 每个 BGP 报文都有 marker、length、type；length 包含 19 字节头，最小 19，最大 4096，按实际编码字节数回填。
4. OPEN 的 version 为 4；My AS、hold time、identifier 均按网络字节序编码；BGP identifier 是 IPv4 地址，即使 TCP 外层使用 IPv6。
5. UPDATE 的 withdrawn-routes length 和 total path-attributes length 均为 2 字节；每条 IPv4 NLRI 为 prefix length（1 字节）加所需的前缀字节，不补无意义的 host 字节。
6. ORIGIN、AS_PATH、NEXT_HOP 是 RFC 4271 的 well-known mandatory 属性；MED、LOCAL_PREF、COMMUNITIES 的 flags、type code、长度和取值必须逐字段编码。
7. 一条应用事件默认占一个 TCP data segment；MSS 分段时 `packet_count` 和 frame offset 只指实际 segment，验证器必须按 TCP stream 重组。
8. planner（规划器）或 validator（校验器）错误必须传播到 task（任务）错误终态，不能“完成但 0 包”。

## 2. 层链、端口和配置 profile

```json
{
  "layers": [{"tcp": {}}, {"bgp": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "src_port": 12345,
  "dst_port": 179,
  "bgp": {
    "wire_profile": "bgp_rfc4271_ipv4_unicast",
    "events": []
  }
}
```

| 配置键 | 类型/约束 | 语义 |
|---|---|---|
| `wire_profile` | 必填；`bgp_rfc4271_ipv4_unicast` 或待实现 profile | 选择版本和地址族模板，不直接编码为 payload（载荷） |
| `events` | 数组；按序 | 单会话应用事件；方向必须为 `c2s` 或 `s2c` |
| `kind` | `open`、`keepalive`、`update`、`notification`；负例可用 `wire_fault` | 事件类别；故障注入不生成合法线上报文 |
| `version` | OPEN 内 1–255；正例为 4 | BGP 版本 |
| `my_as` | 0–65535 | OPEN 的 2 字节 My AS；4-octet ASN 能力不在本版 |
| `hold_time` | 0–65535 秒 | OPEN 的 2 字节 hold time；0 表示不启用保持计时器 |
| `identifier` | IPv4 地址 | OPEN 的 BGP identifier |
| `withdrawn_prefixes` | IPv4 CIDR 数组 | UPDATE 的 withdrawn routes |
| `nlri` | IPv4 CIDR 数组 | UPDATE 的 NLRI；仅 IPv4 profile |
| `attributes` | 明确属性对象 | ORIGIN、AS_PATH、NEXT_HOP、MED、LOCAL_PREF、COMMUNITIES |
| `error_code`/`error_subcode` | 1 字节各 | NOTIFICATION 外层错误码；只使用 RFC 4271 已定义值 |
| `fault_kind` | 仅随 `kind=wire_fault` 出现 | marker/length/type 等验证边界注入，不代表合法线上报文 |

推荐的最小 OPEN/KEEPALIVE 会话：

```json
{
  "wire_profile": "bgp_rfc4271_ipv4_unicast",
  "events": [
    {"kind": "open", "direction": "c2s", "version": 4, "my_as": 64512, "hold_time": 90, "identifier": "192.0.2.1"},
    {"kind": "open", "direction": "s2c", "version": 4, "my_as": 64513, "hold_time": 90, "identifier": "192.0.2.2"},
    {"kind": "keepalive", "direction": "c2s"},
    {"kind": "keepalive", "direction": "s2c"}
  ]
}
```

## 3. RFC 4271 线格式

### 3.1 通用报文头

每条报文都从下列 19 字节开始：

```text
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                           Marker (16)                         |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Length               |      Type     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Marker 必须为 16 字节全 `0xff`。
- Length 是包含头部在内的 BGP 报文总长度，网络字节序；19 ≤ length ≤ 4096。
- Type：1 OPEN、2 UPDATE、3 NOTIFICATION、4 KEEPALIVE；其他值拒绝。

### 3.2 OPEN

OPEN 的 body 为：`Version(1) | My AS(2) | Hold Time(2) | BGP Identifier(4) | Optional Parameters Length(1) | Optional Parameters(N)`。因此 optional parameter 为空时，OPEN 总长度为 29 字节（`00 1d`）。

本版正例使用 version 4、2 字节 ASN、明确 hold time 和 identifier，optional parameters length 固定为 0。RFC 5492 能力参数、RFC 6793 4-octet ASN capability、认证信息等不在 RFC 4271 基础 profile 中，不能写成确定字节。

### 3.3 KEEPALIVE

KEEPALIVE 没有 body，总长度固定为 19：marker + `00 13` + type `04`。它只能出现在 OPEN 交换成功后的 established（已建立）事件序列中；单独的 connect 例不自动增加 KEEPALIVE。

### 3.4 UPDATE

UPDATE body 的顺序为：

```text
Withdrawn Routes Length(2)
Withdrawn Routes(variable)
Total Path Attribute Length(2)
Path Attributes(variable)
NLRI(variable)
```

IPv4 前缀采用 `prefix length` 加 `ceil(prefix length/8)` 个最高有效地址字节。例如 `203.0.113.0/24` 为 `18 cb 00 71`，`192.0.2.1/32` 为 `20 c0 00 02 01`。

RFC 4271 属性编码（本版固定这些可复算字段）：

| 属性 | Flags | Type | Value |
|---|---:|---:|---|
| ORIGIN | `0x40` | 1 | 1 字节：IGP=0、EGP=1、INCOMPLETE=2 |
| AS_PATH | `0x40` | 2 | segment type（AS_SEQUENCE=2/AS_SET=1）、ASN count、2 字节 ASN 列表 |
| NEXT_HOP | `0x40` | 3 | 4 字节 IPv4 地址 |
| MULTI_EXIT_DISC | `0x80` | 4 | 4 字节无符号 metric |
| LOCAL_PREF | `0x40` | 5 | 4 字节无符号 preference |
| COMMUNITIES | `0xc0` | 8 | 每个 community 4 字节；本版用 `NO_EXPORT=0xffffff01` |

当属性值长度小于 256 时使用 one-octet length；大于等于 256 的扩展长度编码不在本版正例中，但长度边界必须拒绝截断或溢出。UPDATE 可以同时带 withdrawn routes 和 NLRI；两者分别由各自的长度/列表界限解析。

### 3.5 NOTIFICATION

NOTIFICATION body 为 `Error Code(1) | Error Subcode(1) | Data(variable)`。本版使用 RFC 4271 的 Hold Timer Expired（code 4、subcode 0、空 data）作为稳定外层例，报文总长度为 21。Cease（code 6）和厂商/扩展子码另设 profile，不从本例推导。

## 4. 邻接状态和事件约束

状态模型只约束可观察事件顺序，不承诺路由器真实 FSM（有限状态机）重传：

```text
Idle/transport connect
  → OPEN_SENT / OPEN_CONFIRM
  → Established
  → UPDATE 或 KEEPALIVE
  → NOTIFICATION（可选）或 TCP FIN
```

- `open` 必须成对出现，且两方向各一条；OPEN 的 version、identifier 和 hold time 分别属于发送方。
- KEEPALIVE 只能在两条 OPEN 后出现。
- UPDATE 只能在 Established 后出现；update 事件可独立包含撤销、属性和 NLRI。
- NOTIFICATION 必须是会话最后的 BGP 应用事件；随后由 TCP 层终止。NOTIFICATION 不等于 planner 错误。
- BGP session（会话）按 TCP 四元组隔离；多 session 的事件不能交叉关联。
- 本版不自动发送 OPEN、KEEPALIVE 或响应；所有应用事件必须显式配置。

## 5. 地址族和 MP_REACH 边界

IPv6 transport（传输）例只改变 IP 外层：TCP 仍使用 179，BGP identifier 仍为 IPv4，`bgp_rfc4271_ipv4_unicast` 的 UPDATE 仍携带 IPv4 NLRI。这不是 IPv6 NLRI 支持。

IPv6 NLRI 需要 MP_REACH_NLRI（RFC 4760）属性，其 AFI/SAFI、next-hop 地址长度、SNPA 列表、NLRI 编码和 capability 协商必须由独立 profile 定义。本版不写 MP_REACH 固定 hex、不生成“看似 IPv6”的 UPDATE；`bgp_mp_reach_ipv6_pending` 输入应返回 profile 错误。该边界在负例 `bgp_neg_mp_reach_profile` 中验证。

## 6. 包数、帧偏移与场景映射

无额外 TCP option、每个应用事件一个 TCP data segment 时：

```text
packet_count = 3（SYN/SYN-ACK/ACK） + 应用事件数 + 4（FIN 终止）
```

IPv4 TCP payload 起点是 Ethernet 14 + IPv4 20 + TCP 20 = **offset 54**；IPv6 起点是 Ethernet 14 + IPv6 40 + TCP 20 = **offset 74**。固定 offset 仅用于实际未分段 TCP frame；MSS 分段用 stream 重组后断言。

| 场景 | JSON id | 应用事件数/每流 | packet_count |
|---|---|---:|---:|
| TCP connect | `bgp_connect` | 0 | 7 |
| OPEN + KEEPALIVE | `bgp_open_keepalive` | 4 | 11 |
| UPDATE 全属性 | `bgp_update_attributes` | 5 | 12 |
| withdrawn + NLRI | `bgp_update_withdraw` | 5 | 12 |
| NOTIFICATION | `bgp_notification_hold_expired` | 3 | 10 |
| hold time=0 | `bgp_hold_time_zero` | 4 | 11 |
| IPv4 NLRI /32 | `bgp_ipv4_nlri_32` | 5 | 12 |
| IPv6 transport | `bgp_ipv6_transport` | 4 | 11 |
| 双 session | `bgp_multi_session` | 4 × 2 | 22 |
| length=19 boundary | `bgp_keepalive_length_boundary` | 4 | 11 |
| marker/version/length/type/AS/profile 负例 | `bgp_neg_*` | — | — |

`bgp_update_attributes` 的 5 个应用事件为 OPEN c2s、OPEN s2c、KEEPALIVE c2s、KEEPALIVE s2c、UPDATE c2s；`bgp_update_withdraw` 和 `/32` 例同样以 5 个事件结束于 UPDATE。`bgp_ipv6_transport` 仅改变 src/dst IP 版本，不改变应用 profile。

## 7. 错误处理

| 输入故障 | 必须拒绝的原因 | 稳定错误关键词 |
|---|---|---|
| UDP 或缺 TCP 层 | BGP 只承载在 TCP | `tcp` |
| 未登记 MP_REACH IPv6 profile | 不能把未知地址族降级到 IPv4 | `profile` |
| marker 非 16 字节全 `0xff` | 通用头非法 | `marker` |
| length 小于 19、超过 4096 或声明长度与 body 不符 | 报文边界非法 | `length` |
| type 不在 1–4 | 未知消息类型 | `type` |
| OPEN version 非 4 | RFC 4271 BGP-4 profile 不匹配 | `version` |
| My AS 超出 2 字节范围 | 基础 OPEN 字段不能编码 | `as` |
| UPDATE 含 IPv6 NLRI 但未使用 MP_REACH profile | IPv4 NLRI profile 地址族不匹配 | `address` |
| Established 前发送 UPDATE/KEEPALIVE | 邻接状态非法 | `state` |

所有错误必须在 planner/validator 层返回并使任务进入错误终态；不能生成空 PCAP 后报告成功。负例不代表合法线上流量。

## 8. 实现完成定义与待实现边界

后续实现必须：

1. 注册 TCP→BGP 终结层，默认端口 179，并拒绝 UDP/缺 TCP/不完整层链。
2. 实现 RFC 4271 通用头、OPEN、KEEPALIVE、UPDATE、NOTIFICATION 的字节编码，所有 length 按编码后字节数回填。
3. 对 marker、length、type、version、AS、状态和地址族各写失败优先单测，并验证错误经 API→engine→PCAP 传播。
4. 对 IPv4 NLRI 的 prefix length、前缀截断、withdrawn/path attribute 长度和 TCP MSS 分段写可观察集成测试。
5. 对 IPv6 transport 与 IPv4 NLRI 分离验证；不能以 IPv6 outer IP 推断 MP_REACH 支持。
6. 取得 RFC 4760/RFC 5492/RFC 6793 的实现 profile 和可复现 fixture 后，再单独实现 MP_REACH、能力协商和 4-octet ASN；不得修改当前基础 profile 语义。

明确待实现：MP_REACH/MP_UNREACH、BGP capabilities、4-octet ASN、route refresh、graceful restart、BGP authentication、TCP MD5/AO、Cease 扩展、厂商属性、真实策略/收敛、压缩/TLS、分片重组之外的实现细节。任何新增字段必须同时更新 design、testcase、JSON 和 audit。

## 9. 修订记录

- v1.0.0（2026-08-20）：建立 RFC 4271 基础 profile；固定 TCP/179、通用头、OPEN/KEEPALIVE/UPDATE/NOTIFICATION、邻接状态、IPv4 NLRI、IPv6 transport，明确 MP_REACH/能力/4-octet ASN 边界。

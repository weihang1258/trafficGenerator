# #146 snmp（SNMPv1/v2c/v3）测试用例契约

> 版本：v1.0.0（P-PIPE 批次二，as-built）
> 日期：2026-09-29；配套设计：`docs/protocol-designs/146-snmp-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/snmp.json`（**1/1 ID，顺序与本版一致**）
> 白话一句：**现有唯一检查验证最小 SNMPv1 GET：默认 161、public、一个 OID、无错误。**

## 1. 测试原则、形状与输出

本文严格记录存量，不把设计中未执行的 v2c/v3、Trap、长形 BER 或负例伪装成现有用例。JSON 顶层 case 键为 `id/proto/summary/spec_json/expect`；`spec_json` 顶层仅 `{layers,snmp}`，层链 `[udp,snmp]`。该形状是当前实现的配置入口：registry 的 `snmp` Fields 为空，协议字段由顶层 `snmp` 子映射进入 `strategy_convert.go`；因此不能删掉顶层映射来宣称扁平合规（设计 G-SNMP-1）。

pcap 与 NIC 使用同一 cases JSON。UDP 无握手、FIN/RST、keepalive、重试和连接终止断言；如无 VLAN/IP options，IPv4 UDP payload 起点是偏移 42，IPv6 为 62。本 case 未含 frames 原始字节断言，不能声称已验证 BER 原始偏移；其 fields 断言由 tshark 实际解码结果承担。

## 2. 原子用例索引（权威顺序）

|#|ID|类型|场景/依据链|包数|断言|
|---:|---|---|---|---:|---|
|1|`snmp_smoke_01`|正|RFC 3416 §4.2.1 GetRequest + RFC 3417 UDP agent 端口 + 设计 §3.1/§3.2|1|`udp.dstport=161`；`snmp.version=1`（SNMPv2c wire version integer）；`snmp.community=public`；`snmp.get_request_element=1`；OID `1.3.6.1.2.1.1.1.0`；`snmp.error_status=0`|

**包数来源**：`SNMPGenerator.Generate` 默认 `repeat=1`，一次 up request；`IsResponse` 缺省 false，故无 down response。`dst_port` 缺省由 chain planner 对 Get 选 161。JSON 的 `expect.packet_count=1` 与这一路径一致。

## 3. `snmp_smoke_01` 断言契约

输入（与 JSON 完全一致）：

```json
{
  "layers":[{"udp":{}},{"snmp":{}}],
  "snmp":{"var_binds":[{"name":"1.3.6.1.2.1.1.1.0"}]}
}
```

### 3.1 可执行断言逐条

|packet|字段|期望|可观察依据|
|---:|---|---|---|
|1|`udp.dstport`|`161`|RFC 3417 agent/query port；`chain_planner.go:1054-1067`|
|1|`snmp.version`|`1`|RFC 3416 version INTEGER 的 v2c wire 值；converter 缺省 `Version=1`|
|1|`snmp.community`|`public`|v1/v2c community；`strategy_convert.go:1407` 缺省 public|
|1|`snmp.get_request_element`|`1`|GetRequest PDU 的一个 VarBind；RFC 3416 §4.2.1|
|1|`snmp.name`|`1.3.6.1.2.1.1.1.0`|VarBind OID；RFC 3416 §4.2.1|
|1|`snmp.error_status`|`0`|GetRequest 中 error-status 为 INTEGER 0；`encodePDUWithTag` field1=0|

JSON `notes` 进一步固定：community 默认 public；src 端口沿 flow 默认 12345 且不作为断言；tshark 实测上述字段；层链为 `[udp,snmp]`。这些 notes 是上下文，不替代 6 条 fields 机器断言。

### 3.2 未断言项

本例没有 `frames`，因此不直接证明外层 `30`、version INTEGER、community TLV、PDU tag `a0`、OID 首弧 `2b`、VarBind 长度或 checksum 的原始字节。也没有证明方向响应、IPv6、非默认端口、重复请求、Trap/Inform、USM 或 BER 长形。它们只能在后续原子用例中补，不得从“任务成功”推导覆盖。

## 4. 负例契约

现有 JSON **0 个负例**。因此没有可执行的 `expect_error/error_contains` 断言。应补但不得冒充已覆盖的 validator/planner 面包括：Version=2/非法版本、v1/v2c 空 community、v3 auth 缺 password、priv 无 auth、非法 auth/priv 名、engine ID 非 hex/越界、PDUType>6、Get/Set 类空 VarBinds、空/非法 OID、混合 IPv4/IPv6、端口越界，以及截断 BER/长度不匹配/UDP payload 超限。

## 5. 覆盖与审计

### 5.1 存量去向

|ID|去向|原因/后续|
|---|---|---|
|`snmp_smoke_01`|保留|唯一已执行 SNMPv1/v2c-style Get 冒烟；断言值与实现及 JSON 一致|

无作废、无改写、无等价覆盖。存量数量严格为 1，不套用共享模板中的其他协议数量。

### 5.2 五层反查

|层|现状|证据/缺口|
|---|---|---|
|功能|仅 Get 单 OID；GetNext/Set/GetBulk/Response/Trap/Inform/v3/Report 未覆盖|#1；G-SNMP-2|
|性能|仅单最小报文；VarBind 扩展、0x81/0x82 长形、UDP 上界未覆盖|设计 §4；G-SNMP-3/G-SNMP-8|
|数据|只观察 version/community/PDU/OID/error-status；NULL 为实现默认但未断原始 tag；其它值类型未覆盖|#1；G-SNMP-4|
|地址与流|仅 IPv4 默认 UDP 161；IPv6、非默认端口、跨族拒绝未覆盖；流关联不适用|#1；设计 §1|
|业务|单次 Manager Get；重复轮询、请求响应、Trap/Inform、USM discovery/auth/priv 未覆盖；UDP 单报模型无连接多会话|#1；G-SNMP-2|

### 5.3 §3.15 固定动作

1. 同流多轮操作：未覆盖，待补 `RepeatCount`/PollInterval 用例（G-SNMP-2）。
2. 非正常结束：UDP 无连接，协议层不适用；BER 截断属于负例待补（G-SNMP-8）。
3. 长保活：SNMP 本协议无 keepalive，显式不适用；轮询间隔不是保活确认。

### 5.4 覆盖反查门建议断言行

1. `len(cases.snmp)==1`，ID 顺序唯一为 `snmp_smoke_01`。
2. 正例 `packet_count==1`，且无负例。
3. `snmp_smoke_01` fields 恰包含 6 条表 3.1 断言（字段和值逐一比对）。
4. `spec_json.layers` 顺序严格为 `udp,snmp`，顶层协议配置存在且含一个 `var_binds`。
5. 非负例不含 `expect_error`；本协议当前无 `frames`，不得将 frames 覆盖报告为已完成。
6. `snmp_smoke_01` 的 `udp.dstport` 必须为 `161`，而非默认源端口 `12345`。

## 6. A′/B′ 后续清单

**A′ 协议面**：补 GetNext/Set/GetBulk；v1 Trap、v2 Trap、Inform；Response/error-status；VarBind 全部 BER 值类型与 exception tags；v3 noAuth/noPriv、auth、priv、engine 参数；长 community/VarBind 触发 0x81/0x82；OID base-128 边界；RepeatCount/response 方向；IPv6/非默认端口；原始 frames 偏移断言。

**B′ 框架面**：层链与顶层 `snmp` 子映射共存的 presence 白名单/游离键判死需由通用框架统一收敛；业务字段 dynamic allowlist 目前没有 snmp 条目，不在本 JSON 伪建动态用例。

## 7. 修订记录与自审

- v1.0.0（2026-09-29）：按唯一权威 `cases/snmp.json` 写入 1 个 ID、1 包、6 条 fields 断言；明确未覆盖 BER 原始字节与协议行为面；补五层、存量去向、负例空集、覆盖反查门、A′/B′。
- 自审 **2 轮，末轮干净**：机读对照 JSON ID/顺序、packet_count、6 条 field 字段和值、层链顺序与顶层配置；复核未虚增存量数量。未运行 pcap 套件，不宣称今日套件通过。

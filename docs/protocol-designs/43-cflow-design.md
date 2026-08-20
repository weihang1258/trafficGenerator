# cflow（Cisco NetFlow/IPFIX 流记录导出）设计契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：仅设计与 PCAP（抓包文件）用例契约；不修改 Go（编程语言）实现，不宣称 `cflow` 层已注册。
> 配套文件：`docs/protocol-designs/43-cflow-testcase.md`、`docs/protocol-designs/audit/43-cflow-adversarial-audit.md`、`trafficgen/test/protocol_pcap/cases/cflow.json`
>
> 规范基线：RFC 3954（NetFlow Version 9）与 RFC 7011（IPFIX）。

## 1. 范围与 profile（协议档案）边界

本阶段将 cflow 严格限定为**两个可验证 profile**，不把任意 UDP 流量标成 cflow：

| profile | 规范 | 版本/载体 | 本阶段允许的内容 |
|---|---|---|---|
| `netflow_v9_rfc3954` | RFC 3954 | UDP，默认目的端口 2055 | NetFlow v9 Export Packet（导出包）、Template FlowSet（模板流集）、Data FlowSet（数据流集）、IPv4/IPv6 flow record（流记录）、header sequence/source ID、sampling/timeout 元数据 |
| `ipfix_rfc7011` | RFC 7011 | UDP，默认目的端口 4739 | IPFIX Message（消息）、Template Set（模板集）、Options Template Set（选项模板集）、Data Set（数据集）、IPv4/IPv6 flow record、Observation Domain、标准 Information Element（信息元素）与 enterprise-specific IE（企业私有信息元素） |

两种 profile 均实现，因为 RFC 3954 与 RFC 7011 的 header、template 标识和长度语义不同；不能用一个“通用 v9/IPFIX” profile 静默切换版本。每个正例必须显式给出 `profile`。未登记版本、sFlow、NetFlow v5/v8、IPFIX over TCP/SCTP/TLS、采集器重传、模板跨 exporter（导出器）共享均属于本阶段之外。

cflow 应用层**没有独立 checksum（校验和）字段**。UDP checksum 是传输层字段：可由 UDP/IP builder（构造器）按普通 UDP 规则计算，但不得在 cflow header、FlowSet 或 IE 中伪造“cflow checksum”。`wire_fault.kind=checksum` 仅用于验证请求非法的 cflow checksum 不会被接受；它不是合法 cflow 线上报文。

不变式：

1. cflow 终结层只能位于 UDP 后，UDP/IPv4 默认目的端口为 2055（NetFlow v9）或 4739（IPFIX）；缺 UDP、错误 carrier（承载）或 profile/端口不匹配必须错误。
2. NetFlow v9 header 为 20 字节：`version(2)=9`、`count(2)`、`sys_uptime(4)`、`unix_secs(4)`、`sequence(4)`、`source_id(4)`。`count` 是本 Export Packet 中记录数量语义，不把 FlowSet 数量误当 count。 同一 packet 同时含一个 Template Record 和一个 Data Record 时 count=2；含一个模板和两条数据记录时 count=3。
3. IPFIX header 为 16 字节：`version(2)=10`、`length(2)`（整个 Message 字节数）、`export_time(4)`、`sequence_number(4)`、`observation_domain_id(4)`。`length` 必须等于编码后的完整 Message 长度，不能等于单个 Set 长度。
4. 每个 FlowSet/Set 都有 `id(2)+length(2)`；length 包括 Set header，且不能越过 Message/Export Packet 边界。Template/Data Set 的 ID、字段顺序、字段长度必须互相匹配。
5. v9 Template FlowSet ID 为 0；IPFIX Template Set ID 为 2，Options Template Set ID 为 3；Data Set ID 必须等于已登记 Template ID（本套件默认 256）。padding（填充）只能出现在规范允许的位置，不计为记录字段。
6. 标准 IE 的 type/length 按对应 RFC 编码；IPFIX enterprise bit（企业位）置位时，IE type 的高位与 PEN（Private Enterprise Number，私有企业号）必须同时出现。PEN 缺失、enterprise bit 与 PEN 不一致、field count（字段数）和实际 descriptors（描述项）不一致均错误。
7. IPv4 地址元素使用 4 字节、IPv6 地址元素使用 16 字节；一个 template 不得把 IPv6 field length 写成 4，也不得把 IPv4 record 填入 IPv6 template。地址族错误必须在 planner/validator（规划器/校验器）层失败。
8. active/inactive timeout（活动/非活动超时）与 sampling（采样）是记录或 Options Template 中显式的语义值；不会由 exporter 时间戳静默推导，也不会自动生成 refresh（刷新）消息。
9. multi-exporter（多导出器）以不同 source ID（v9）或 Observation Domain ID（IPFIX）隔离；multi-session（多会话）以不同 UDP 四元组隔离。不同 exporter/session 的 template 不能互相解码。
10. 错误必须传播到 task error（任务错误）终态，不能完成但生成 0 包；负例不输出“损坏但成功”的 PCAP。

## 2. UDP 载体与配置契约

推荐配置形状如下（payload（载荷）语义放在 `cflow` 对象内）：

```json
{
  "layers": [{"udp": {}}, {"cflow": {}}],
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.10",
  "src_port": 40000,
  "dst_port": 2055,
  "cflow": {
    "profile": "netflow_v9_rfc3954",
    "source_id": 7,
    "observation_domain_id": 7,
    "sequence": 100,
    "templates": [],
    "records": []
  }
}
```

| 键 | 约束 | 语义 |
|---|---|---|
| `profile` | 必填，取表中两个值 | 选择线上版本；不作为自定义 payload 字段 |
| `src_port`/`dst_port` | v9 默认 2055，IPFIX 默认 4739 | 只改变 UDP 载体；正例显式写默认端口 |
| `source_id` | v9 4 字节 | Exporter/source identity；不同值隔离 v9 template 状态 |
| `sequence` | v9 4 字节 | header FlowSequence；单调性按同一 source ID/session 检查 |
| `observation_domain_id` | IPFIX 4 字节 | IPFIX header OD ID；不同值不能共享模板缓存 |
| `export_time`/`unix_secs` | 4 字节 | 由配置给出或采用可观察的固定 fixture（固定样本）；不得在断言中硬编码运行时墙钟 |
| `templates` | 有序数组 | Template/Options Template 描述；每项含 template id 与 field descriptors |
| `records` | 有序数组 | Data Set 记录；必须引用同一 exporter/session 已登记的 template |
| `fields` | `element_id`、`length`、可选 `pen` | 标准 IE 或 enterprise IE；字段顺序决定 record 布局 |
| `record` | 与 template 同序的值数组/对象 | IPv4/IPv6 地址、端口、协议、计数、时间、timeout 等实际字节 |
| `options` | IPFIX Options Template 专用 | scope field count、option field count、scope/data 值 |
| `wire_fault` | 仅负例 | version/template/length/field_count/address_family/checksum 等拒绝注入；不是合法字段 |

本阶段不指定 Go API 名称；上述对象是设计阶段的可观察输入契约。实现必须拒绝未知 profile、未知 IE 编码、缺 template、重复 template ID、Data Set 无匹配 template、记录短于/长于模板和跨 session template 借用。

## 3. 线格式与可验证字段

### 3.1 NetFlow v9（RFC 3954）

无 IPv4 option 时 UDP payload 起点为 offset（偏移）42（Ethernet 14 + IPv4 20 + UDP 8）；IPv6 时为 offset 62（14 + 40 + 8）。v9 header：

```text
Version(2) | Count(2) | SysUptime(4) | UnixSecs(4)
Sequence(4) | SourceId(4)
```

每个 FlowSet：

```text
FlowSetId(2) | FlowSetLength(2) | body...
```

Template FlowSet（ID 0）的 body 是一组 `TemplateId(2) | FieldCount(2) | [FieldType(2) | FieldLength(2)]*`。Data FlowSet 的 ID 必须等于 Template ID；record 字节严格按 descriptors 顺序拼接。v9 enterprise-specific IE 的编码细节不在本阶段宣称支持；需要私有 field 时使用 IPFIX enterprise profile 并显式 PEN。

本阶段采用可复算且已注册的 v9 IE：`IN_BYTES=1`、`IN_PKTS=2`、`PROTOCOL=4`、`IPV4_SRC_ADDR=8`、`L4_SRC_PORT=7`、`IPV4_DST_ADDR=12`、`L4_DST_PORT=11`、`IPV6_SRC_ADDR=27`、`IPV6_DST_ADDR=28`、`LAST_SWITCHED=21`、`FIRST_SWITCHED=22`、`SRC_MASK=9`、`DST_MASK=13`。字段 type/length 在 frame（帧）中可由 template 直接复算，tshark（网络分析器）字段使用注册名 `cflow.template_field_type`、`cflow.template_field_length` 和对应 record 字段。

### 3.2 IPFIX（RFC 7011）

IPFIX Message header：

```text
Version(2)=10 | Length(2) | ExportTime(4)
SequenceNumber(4) | ObservationDomainId(4)
```

Set ID：Template Set=2，Options Template Set=3，Data Set=template ID（本套件默认 256）。Template Record 为 `TemplateId(2) | FieldCount(2) | [InformationElementId(2) | FieldLength(2)]*`；enterprise bit 置于 IE ID 高位时，descriptor 后紧跟 PEN(4)。Options Template 使用 `ScopeFieldCount(2)` 与 `OptionFieldCount(2)`，随后 scope descriptors 和 option descriptors。

IPFIX 标准 IE 采用 RFC 7011/7012 注册编号：`octetDeltaCount=1`、`packetDeltaCount=2`、`protocolIdentifier=4`、`sourceIPv4Address=8`、`sourceTransportPort=7`、`destinationIPv4Address=12`、`destinationTransportPort=11`、`sourceIPv6Address=27`、`destinationIPv6Address=28`、`flowStartMilliseconds=152`、`flowEndMilliseconds=153`、`samplingInterval=34`、`observationPointId=138`。企业 IE 只使用显式 `enterprise_number`/PEN，并在 wire 上保留 enterprise bit；不声称具体厂商 IE 名称。

可验证 cflow fields（均先用 `tshark -G fields` 检查过）至少包括：

- header：`cflow.version`、`cflow.len`、`cflow.count`、`cflow.sequence`、`cflow.source_id`、`cflow.od_id`、`cflow.exporttime`；
- set/template：`cflow.flowset_id`、`cflow.flowset_length`、`cflow.template_id`、`cflow.template_field_count`、`cflow.template_field_type`、`cflow.template_field_length`；
- address/record：`cflow.srcaddr`、`cflow.dstaddr`、`cflow.srcaddrv6`、`cflow.dstaddrv6`、`cflow.srcport`、`cflow.dstport`、`cflow.protocol`、`cflow.packets`、`cflow.octets`、`cflow.timestart`、`cflow.timeend`；
- enterprise/options：`cflow.template_ipfix_pen_provided`、`cflow.template_ipfix_field_type_enterprise`、`cflow.template_ipfix_field_pen`、`cflow.template_ipfix_scope_field_count`、`cflow.template_ipfix_total_field_count`、`cflow.enterprise_private_entry`、`cflow.flow_active_timeout`、`cflow.flow_inactive_timeout`。

字段验证只使用上述已注册字段或 UDP/IP 基础字段；不使用猜测的 `cflow.checksum`、不存在的 `cflow.length` 或厂商私有字段名。

## 4. 场景与 ID 闭环

设计、测试契约、审计和 JSON 必须按以下**同一顺序**使用 22 个唯一 ID。正例 15 个，负例 7 个。

| # | ID | 类型 | 关键覆盖 | packet_count |
|---:|---|---|---|---:|
| 1 | `cflow_v9_template_data_ipv4` | 正 | v9 header、Template/Data Set、IPv4 record | 1 |
| 2 | `cflow_v9_ipv6_record` | 正 | v9 IPv6 source/destination record | 1 |
| 3 | `cflow_v9_header_sequence_source` | 正 | v9 sequence/source ID/时间 | 1 |
| 4 | `cflow_v9_timeout_sampling` | 正 | active/inactive timeout、sampling fields | 1 |
| 5 | `cflow_v9_multi_record` | 正 | 一个 Data Set 两条 IPv4 records、count/length | 1 |
| 6 | `cflow_v9_multi_exporter` | 正 | 两个 source ID 的独立 v9 export packets | 2 |
| 7 | `cflow_v9_multi_session` | 正 | 两个 UDP 四元组、template 不串会话 | 2 |
| 8 | `cflow_ipfix_template_data_ipv4` | 正 | IPFIX header length、Template/Data Set、IPv4 record | 1 |
| 9 | `cflow_ipfix_ipv6_record` | 正 | IPFIX IPv6 record、16 字节地址字段 | 1 |
| 10 | `cflow_ipfix_enterprise_ie` | 正 | enterprise bit、PEN、private IE boundary | 1 |
| 11 | `cflow_ipfix_variable_length_ie` | 正 | variable-length IE length=65535 编码边界 | 1 |
| 12 | `cflow_ipfix_observation_domain_sequence` | 正 | OD ID 与 sequence 隔离 | 1 |
| 13 | `cflow_ipfix_timeout_options_template` | 正 | Options Template scope/option、timeout | 1 |
| 14 | `cflow_ipfix_multi_exporter` | 正 | 两个 OD ID 的独立 IPFIX messages | 2 |
| 15 | `cflow_boundary_lengths` | 正 | 最小合法 header/set length 与无 checksum 语义 | 1 |
| 16 | `cflow_neg_version` | 负 | v9/IPFIX version 不匹配或未知 | — |
| 17 | `cflow_neg_template` | 负 | Data Set 无匹配 template | — |
| 18 | `cflow_neg_length` | 负 | header/Set length 越界或不一致 | — |
| 19 | `cflow_neg_field_count` | 负 | field count 与 descriptors/record 不一致 | — |
| 20 | `cflow_neg_address_family` | 负 | IPv4 template 填 IPv6 或反之 | — |
| 21 | `cflow_neg_udp_port` | 负 | 非 profile 规定 UDP carrier/端口 | — |
| 22 | `cflow_neg_checksum` | 负 | 请求不存在的 cflow checksum | — |

### 4.1 包数、偏移和失败语义

每个 UDP export packet 为一个 PCAP frame；多 exporter/session 例的 `packet_count` 是显式 export packet 数，不自动补响应。v9/IPFIX 的 cflow payload 起点分别为 IPv4 offset 42、IPv6 offset 62。每条正例必须有 `packet_count`、非空 `fields` 与非空 `frames`；frames 只固定公共 header/set 的可复算前缀，不硬编码运行时 timestamp。负例 `expect` 严格只允许 `expect_error` 与 `error_contains`。

## 5. 错误处理与完成定义

| 故障 | 必须拒绝的原因 | 稳定错误关键词 |
|---|---|---|
| version | profile 与线上 version 不同、未知 version | `version` |
| template | Data Set 找不到同 session/template ID | `template` |
| length | Message/Export/Set 声明长度不等于实际编码或越界 | `length` |
| field count | count 与 descriptors、record 字节长度不一致 | `field` |
| address family | IPv4/IPv6 template 与 record 长度/值不匹配 | `address` |
| carrier/port | 缺 UDP、非 2055/4739、错误 profile 端口 | `udp` |
| checksum | cflow 不定义 checksum，不能请求/伪造该字段 | `checksum` |

实现完成定义：逐字段回填 header/Set length；v9/IPFIX 的 count/sequence/OD/source ID 可观察；模板和数据按 session 隔离；IPv4/IPv6 与 enterprise/variable-length 边界有失败优先测试；所有负例错误经 API→engine→task 传播。UDP checksum 仅由通用 UDP builder 负责，不能被 cflow profile 解释成应用 checksum。

## 6. 规范边界

本套件不覆盖 NetFlow v5/v8、IPFIX Options 的复杂 subTemplateList、reduced-size encoding 的全部组合、八字节/厂商专有 PEN 的语义名称、TCP/SCTP/TLS transport、模板撤销/重传策略、采集器缓存持久化、真实 exporter 时钟同步、采样统计推断。新增内容必须同时更新设计、testcase、audit 和 JSON 的 ID 顺序。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 RFC 3954 NetFlow v9 与 RFC 7011 IPFIX 双 profile，固定 UDP 2055/4739、header/sequence/source/OD、Template/Data/Options Set、IPv4/IPv6、enterprise/variable-length、timeout、multi-exporter/session 和负例边界；明确 cflow 无应用 checksum。

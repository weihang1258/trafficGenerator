# cflow（Cisco NetFlow/IPFIX 流记录导出）设计契约

> 版本：v1.1.3（收敛版；as-built 静态契约 + 执行缺口登记）
> 日期：2026-10-01
> 状态：层链设计与 cases JSON 静态契约已对账（27 例：正 15、负 12）；Go 路径已接线（registry `cflow` 15 字段、translate 严格解码分支、`ValidateConfig`/`BuildV9/IPFIX` + `Planner`），但本轮不宣称任何 suite/PCAP/NIC 执行。`trafficgen/docs/protocol-pcap-test/cflow.md` 仅是 2026-08-27 的 22 例历史产物，不是当前 27 例证据。实现缺口按 D-CFLOW 编号登记。
> 配套文件：`docs/protocols/cflow/testcase.md`、`trafficgen/test/protocol_pcap/cases/cflow.json`
> 本轮只改 cflow 三件套，不改 Go；不跑 suite、PCAP、NIC；不写 Git。
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
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "198.51.100.10"}},
    {"udp": {"src_port": 40000, "dst_port": 2055}},
    {"cflow": {
    "profile": "netflow_v9_rfc3954",
    "source_id": 7,
    "sequence": 100,
    "templates": [],
    "records": []
    }}
  ]
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

设计、测试契约、审计和 JSON 必须按同一顺序使用 27 个唯一 ID。正例 15 个，负例 12 个。

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
| 23 | `cflow_neg_presence_top_level_cflow` | 负 | 层链与顶层 cflow 混用 | — |
| 24 | `cflow_neg_carrier_tcp` | 负 | TCP carrier | — |
| 25 | `cflow_neg_carrier_no_udp` | 负 | 缺 UDP carrier | — |
| 26 | `cflow_neg_flat_count` | 负 | 顶层 count | — |
| 27 | `cflow_neg_unknown_layer_field` | 负 | 未知 cflow 层字段 | — |

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

## 7. P1 规范矩阵与三路对照

| 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|
| RFC 3954 §5 header/template/data | v9 模板后数据记录 | registry/planner/builder/generator 与单元测试已存在 | D-CFLOW-1：层链→端到端 PCAP/NIC 验证待确认 |
| RFC 7011 §3/§7 message/set | IPFIX template、options、data | IPFIX builder/planner 与单元测试已存在 | D-CFLOW-2：端到端 PCAP/NIC 验证待确认 |
| RFC 3954 §5.3 / RFC 7011 §3.2 | IPv4/IPv6 字段长度 | builder 有地址族校验，cases 覆盖 4/16 字节 | D-CFLOW-3：planner→task→输出链路待确认 |
| RFC 7011 §3.2 | enterprise IE/PEN | builder 有 enterprise bit/PEN 编码路径，cases 覆盖边界 | D-CFLOW-4：端到端 PEN 解码待确认 |
| RFC 7011 §7.1 | variable-length IE | builder/cases 声明 65535 边界 | D-CFLOW-5：端到端变量长度编码待确认 |
| RFC 3954 §5.3 / RFC 7011 §3.1 | sequence/source/OD 隔离 | planner 有 exporter/session 分支，专门测试已存在 | D-CFLOW-6：多流实际输出隔离待确认 |
| RFC 3954 §5.3 / RFC 7011 §8 | timeout/sampling/options | config/builder 路径与 cases 已定义 | D-CFLOW-7：采样语义与抓包解码待确认 |
| RFC 3954 §5 / RFC 7011 §3 | 长度、carrier、错误传播 | registry/planner/builder 有校验分支，27 cases 含负例 | D-CFLOW-8：API→task 错误传播及负例真红待确认 |

### 子表

| 命令/消息 | 响应/结果 | 覆盖 |
|---|---|---|
| Template/Data | 匹配模板后编码记录 | 正例 1、8；负例 17 验证缺模板拒绝 |
| Options Template | scope + option fields | 正例 13 |
| 非法 version/length/field | task error | 负例 16、18、19 |
| 错误 carrier/address/checksum | task error | 负例 20–22、24–27 |

| 数据形态变体 | 用例 |
|---|---|
| v9/IPFIX × IPv4/IPv6 | 1、2、8、9 |
| 单/多 record、multi-exporter、multi-session | 5–7、14 |
| enterprise、variable-length、options | 10、11、13 |
| 最小长度、非法长度、地址族错 | 15、18、20 |

| 商业行为 | 用例映射 | 证据/确认 |
|---|---|---|
| 多 exporter 按 source/OD 隔离 | 6、14 | RFC 字段语义；商业设备抓包待确认 |
| 同一 exporter 模板复用 | 1、8 | RFC 模板引用；商业设备抓包待确认 |
| 超时/采样显式导出 | 4、13 | RFC 字段语义；商业设备抓包待确认 |

| 规范原文 | 商业软件行为 | 开源实现思路 | 取舍 |
|---|---|---|---|
| RFC 3954 §5 | Cisco IOS NetFlow v9 以 UDP/2055 导出 | nfdump 1.7.x 按 template cache 解码 | 先固定 RFC 形状，商业差异列待确认 |
| RFC 7011 §3、§7 | IPFIX exporter 按 OD 隔离 | libfixbuf 2.x 按 template/OD 管理状态 | 采用显式 profile，拒绝静默 v9/IPFIX 混用 |

| 候选方案 | 优点 | 代价 | 决策 |
|---|---|---|---|
| 每个 profile 独立编码器 | 版本语义清晰、错误可定位 | 两套 header/set 逻辑 | 采用 |
| 一个通用 payload 编码器 | 代码少 | 长度、template、enterprise 语义混淆 | 不采用 |

## 8. 依赖、接口、结构、流程与回滚

- 依赖：`ip → udp → cflow`；cflow 依赖 profile、模板先于数据、同 session 的 exporter/source/OD 状态。
- 接口：输入为 `spec_json.layers[]` 的 cflow 对象，输出为 UDP payload/PCAP frame；负例返回带 `version/template/length/field/address/udp/checksum` 锚词的 task error。
- 结构：profile、header、templates/options、records、wire_fault；地址只在 ip 层，端口只在 udp 层，数量只在 flow_control。
- 流程：校验 carrier/profile → 建立 session template 状态 → 编码 header/set/record → 回填长度 → 输出 PCAP/NIC。
- 错误：任一校验失败中断任务，不输出成功 PCAP，不把 0 包报告为成功；重试不由 cflow 自动执行，超时由 task 层决定。
- 性能边界：按 §9 验收；实现未提供基准前所有数字是待确认，不作承诺。
- 冲突点：旧扁平地址/端口/协议子映射与层链冲突；顶层负例 23、26 用于拒绝，不能成为正例形状。
- 回滚：删除 cflow 层注册/翻译变更并保留本三文件；cases 回退到本版本前的提交，不修改其他协议。

## 9. 性能设计与验收

目标待基准确认：包/秒、bit/s、并发 session、单包最大长度、内存、队列上限、CPU worker 数均不得在无代码/基准证据时写成承诺。实现应流式逐 frame 编码，不全量聚合 records；共享 template 状态需按 session 隔离，锁与队列积压需测量。验收分两路：PCAP 逐字段/长度/tshark 校对；真实网卡用 tcpdump 校对 UDP 端口、profile header、丢包与错误率。性能测试点为基线、目标规模、压力上限、长时间、并发交错、背压/资源耗尽六类。

## 10. 动态字段清单

| 字段 | fixed | inc | rand | list | pattern | 序号算法/状态 |
|---|---|---|---|---|---|---|
| ip.src/ip.dst | fixed 输入 | 未登记 | 未登记 | 未登记 | 未登记 | 当前 cases 无动态策略；由 D-CFLOW-9 跟踪 |
| udp.src_port/dst_port | fixed 输入 | 未登记 | 未登记 | 未登记 | 未登记 | 当前 cases 无动态策略；由 D-CFLOW-9 跟踪 |
| cflow.sequence | fixed 输入 | 未登记 | 未登记 | 未登记 | 未登记 | header 固定值；序号递增由 D-CFLOW-9 跟踪 |
| cflow.source_id/observation_domain_id | fixed 输入 | 未登记 | 未登记 | 未登记 | 未登记 | exporter/session 固定 ID；由 D-CFLOW-9 跟踪 |
| record 地址/端口/计数/时间 | fixed 输入 | 未登记 | 未登记 | 未登记 | 未登记 | 不写动态则 fixed；由 D-CFLOW-9 跟踪 |
| profile/template_id/IE/PEN | fixed 输入 | 不适用 | 不适用 | 不适用 | 不适用 | 结构字段，避免运行中漂移 |

未确认策略在 D-CFLOW-9 立项；在代码补齐前不得声称动态五策略已支持。flows=N 且无动态字段必须拒绝或告警，防止静态复制。

## 11. 门1 对照表

| CORE 行 | cflow 对照与证据 |
|---|---|
| §1 | 旧 `src_ip/dst_ip/src_port/dst_port/count` 与顶层 `cflow` 均不得出现在正例；完整层链例见 §2，地址进 ip、端口进 udp、数量进 flow_control。负例 23、26 固定拒绝。 |
| §3 | cflow 为无长连接的 UDP 导出：sessions/多 exporter 用例显式登记；同连接多轮、非正常结束、长保活豁免（无连接导出不适用），D-CFLOW-10 记录为待确认扩展，不用空白冒充覆盖。 |
| §12 | 四元组动态与 record 业务字段逐项见 §10；当前仅 fixed 有实现依据，其余列待确认并立项 D-CFLOW-9。 |

## 12. P2 D-CFLOW-1 代码设计（CORE_MEMORY §8 八要素；门1 = 定稿）

> 当前状态：`cflow` 已有 registry、planner、builder、generator 和单元测试路径；本节记录这些代码与 cases 的契约关系，但本轮未运行端到端 PCAP/NIC 验证，因此不把静态代码证据误报为运行验收。

### 12.1 文件、接口与数据结构

- 文件：`trafficgen/internal/core/types.go`（FlowSpec cflow 槽位）、`trafficgen/internal/core/layers/registry.go`（层字段与 `DependsOn: ["udp"]`）、`trafficgen/internal/core/layers/chain_planner_translate.go`（层配置往返）、`trafficgen/internal/protocol/cflow/`（planner、编码器、生成器）、`trafficgen/test/protocol_pcap/cases/cflow.json`（机器契约）。
- 接口：`Validate(*CFlowConfig) error`；`Plan(context.Context, FlowSpec) (<-chan PacketConfig, error)`；`Generate(...) error`。具体 Go 签名以现有协议接口为准，不能新增顶层 flat 入口。
- 数据：`profile`、header 元数据、templates/options、records、wire_fault；模板状态按 `{profile, exporter/session, template_id}` 隔离。地址只在 `ip`，端口只在 `udp`，数量只在 `flow_control`。

### 12.2 主流程、错误与回滚

`ValidateSpec` 检查 `[ip,udp,cflow]`、profile/端口和字段形状 → 建立 session 模板状态 → 编码 header/set/record 并回填长度 → 输出 PCAP/NIC。version、template、length、field、address、udp、checksum 任一失败都返回 task error；不输出损坏 PCAP，不报告 completed/0 packet。回滚为移除 cflow registry/translate/generator 接线并保留本三文件，恢复 cases 到上一契约版本。

### 12.3 性能边界

编码必须逐 packet/record 流式处理，不聚合全部 records；模板状态按 session 局部保存，不跨 exporter 共享。吞吐、并发 session、最大 Message、内存、队列上限和 worker 数均待 P4 基准；验收同时走 PCAP（tshark/长度/frame）与 NIC（tcpdump/端口/丢包），覆盖基线、目标规模、压力、长时、并发交错、背压六类。

## 13. 门1 §1–§14 对照与 D/T/C 追踪

| CORE | cflow 结论 | 证据/去向 |
|---|---|---|
| §1 层链唯一真相 | 正例 15/15 只用 `[ip,udp,cflow]`；顶层 cflow/count 仅负例守门 | testcase §2；`cflow_neg_presence_top_level_cflow`、`cflow_neg_flat_count` |
| §2 策略/任务 | 数量归 `flow_control`，协议对象只描述一个 export 模板 | §2、D-CFLOW-1 |
| §3 五件套 | 无连接 UDP；exporter/session 以显式 packet、OD/source/四元组隔离；不虚构长保活 | §4、§6；D-CFLOW-10 |
| §4 规范 | RFC 3954 §5 与 RFC 7011 §3/§7；字段/长度/错误逐项列出 | §3、§5、T-CFLOW |
| §5 依赖与错误 | cflow 只依赖 UDP；所有七类错误传播 task error | §5、§12.2；负例 16–27 |
| §6 性能 | 流式编码与六类验收，数字待基准 | §12.3 |
| §7 三份文档 | design/testcase/cases 三者 ID 顺序一致 | testcase §6 |
| §8 设计先行 | D-CFLOW-1 设计契约已定稿；运行验收仍按缺口逐项闭环 | 本节 |
| §9 三源测试 | RFC + D-CFLOW-1 + Cisco/libfixbuf 行为待抓包确认 | §7、testcase §5 |
| §10 评审闭环 | 文档与 JSON 静态对账后再进入 P4 | testcase §6 |
| §11 白话 | cflow 是 UDP 上严格 profile 化的流记录导出，不是任意 UDP payload | §1 |
| §12 动态 | 当前仅 fixed 有依据；其余策略列 D-CFLOW-9，不在 cases 冒充支持 | §10 |
| §13 schema | 层字段由 registry 派生，改动后必须重跑 schema | D-CFLOW-1 文件清单 |
| §14 真实流程 | 实现后按 PCAP/NIC 双通道验证，当前不宣称可运行 | §12.3、testcase §7 |

**D-CFLOW-1…10**：D1 层链/字段接线；D2 v9 编码；D3 IPFIX 编码；D4 地址族；D5 enterprise/PEN；D6 variable-length；D7 exporter/session 状态；D8 timeout/sampling/options；D9 动态字段；D10 长连接/重传扩展（不适用本阶段，需新 profile）。未实现项保持缺口，不写成完成。

### 13.1 T-CFLOW 原子追踪

T-CFLOW-01…15 对应正例 1–15，逐项覆盖 v9/IPFIX header、template/data、IPv4/IPv6、sequence/source/OD、timeout/sampling/options、enterprise、variable-length、multi-exporter/session 与长度边界；T-CFLOW-N01…N12 对应负例 16–27，逐项覆盖 version、template、length、field count、address family、UDP port、checksum、顶层 presence、错误 carrier、flat count、未知字段。每个 ID 只有一个主要行为断言，负例 expect 只保留 `expect_error` 与 `error_contains`。

### 13.2 C-CFLOW 商业/开源行为对照

| 行为 | 来源 | 用例/状态 |
|---|---|---|
| Cisco NetFlow v9 默认 UDP/2055、source/template cache | Cisco IOS NetFlow 文档；抓包待补 | 1–7；现网证据缺口 G-CFLOW-1 |
| IPFIX 默认 UDP/4739、OD/template cache | RFC 7011 与 libfixbuf 思路；抓包待补 | 8–14；G-CFLOW-2 |
| UDP-only exporter，不跨 transport 迁移 | RFC 3954/7011；商业实现版本差异待确认 | 15、21、24、25 |

三路不一致时以 RFC 为底线；未取得真实 exporter 抓包前只标待确认，不把文档描述当现网证据。候选方案为 profile 独立编码器（采用，语义清晰）或通用 payload 编码器（否决，易混淆 v9/IPFIX 长度与模板规则）。

## 14. 修订记录

- v1.0.0（2026-08-20）：建立 RFC 3954 NetFlow v9 与 RFC 7011 IPFIX 双 profile，固定 UDP 2055/4739、header/sequence/source/OD、Template/Data/Options Set、IPv4/IPv6、enterprise/variable-length、timeout、multi-exporter/session 和负例边界；明确 cflow 无应用 checksum。
- v1.1.3（2026-10-01）：静态复审修正版本与三件套对账口径；确认 27 个 ID、15/12 正负分类、负例双键断言及唯一层链形状；不宣称 suite/PCAP/NIC 执行。

## 15. D1–D8 完整性补录（静态审查结论）

### 15.1 D1/D2：八项规范矩阵、子表和三路依据

| 八项（规范来源） | 业务场景 | 代码现状 | 缺口/结论 |
|---|---|---|---|
| 连接模型：RFC 3954 §5、RFC 7011 §3 的 UDP datagram | 单 export、multi-exporter、multi-session | `trafficgen/internal/protocol/cflow/planner.go:13-58` 逐 packet 规划 | D-CFLOW-1：端到端输出待跑 |
| 消息/记录表：RFC 3954 §5、RFC 7011 §7 | template→data、options | `builder.go:213-270, 470-560` 编码 | D-CFLOW-2/3：PCAP 解码待跑 |
| 状态机：template 必须先于 data | 跨 exporter/session 不共享 template | `builder.go:758-847` 校验引用 | D-CFLOW-7：真实隔离待跑 |
| 字段表：header、set、IE 长度/大端 | IPv4/IPv6、enterprise、variable-length | `builder.go:1-120, 560-670` | D-CFLOW-4/5：输出校准待跑 |
| 错误表：version/template/length/field/address/checksum | 12 个坏配置 | `builder.go:758-859` 有锚词 | D-CFLOW-8：task error 传播待确认 |
| 超时/活性：RFC 7011 §8 | options timeout、sampling | options 编码路径与例 4/13 | D-CFLOW-8：抓包字段待确认 |
| NAT/代理/会话隔离 | UDP 四元组、source/OD 隔离 | `planner.go:99-145` 派生 exporter/session | D-CFLOW-6：交错输出待确认 |
| 版本/方言：RFC 3954 vs RFC 7011 | v9/2055 与 IPFIX/4739 分开 | `planner.go:20-31` 端口守卫 | 已实现静态约束；端到端待跑 |

| 命令/消息 | 结果/错误 | 用例 |
|---|---|---|
| Template/Data | template 匹配后编码 record；缺 template 报 `template` | 1、8、17 |
| Options Template | scope/option 与 timeout 编码 | 4、13 |
| version/length/field | task error，分别含稳定锚词 | 16、18、19 |
| carrier/address/checksum | task error，含 `carrier`/`address`/`checksum` | 20–25、22、27 |

| 数据形态变体 | 结果 | 用例 |
|---|---|---|
| v9/IPFIX × IPv4/IPv6 | 4/16 字节地址与不同 header | 1、2、8、9 |
| 单/多 record、exporter、session | count、source/OD、四元组隔离 | 5–7、14 |
| enterprise/variable/options | PEN、65535、scope/option | 10、11、13 |
| 最小合法/非法长度、错误 carrier | 边界或拒绝 | 15、18、21、24、25 |

| 规范原文 | 商业行为 | 开源实现思路 | 用例/结论 |
|---|---|---|---|
| RFC 3954 §5 | Cisco IOS NetFlow v9 默认 UDP/2055、source/template cache | nfdump 1.7.x template cache | 1–7；真实设备抓包为 G-CFLOW-1 |
| RFC 7011 §3/§7 | IPFIX 默认 UDP/4739、OD/template cache | libfixbuf 2.x OD/template 管理 | 8–14；真实 exporter 抓包为 G-CFLOW-2 |
| RFC 3954/7011 transport | UDP datagram，不跨 TCP/SCTP | planner 仅建 UDP `PacketConfig` | 21、24、25；以 RFC 为底线 |

| 候选走法 | 优点 | 代价 | 决策 |
|---|---|---|---|
| v9/IPFIX 独立编码器（`builder.go`） | 长度、template、enterprise 规则互不污染 | 两套 header/set 逻辑 | 采用，错误边界清晰 |
| 通用 payload 编码器 | 共享循环较少 | v9 count 与 IPFIX length/enterprise 容易混淆 | 不采用 |

### 15.2 D3–D5：依赖、性能和八要素闭环

- 依赖链是 `ip → udp → cflow`；先做 carrier/profile/template 检查，再编码。失败返回 builder/planner error，任务应中断且不得以 completed/0 packet 代替；cflow 不自动重试，超时由 task 层决定。当前 `planner.go:72-96` 对部分 Build error 直接结束 goroutine，D-CFLOW-8 立项补 task error 传播，不宣称负例可执行。
- 性能验收不写无依据数字。测量维度固定为包/秒、bit/s、并发 exporter/session、最大 message、进程内存、队列积压、CPU worker、丢包率；六组场景为基线、目标规模、压力上限、长时间、并发交错、背压/资源耗尽。PCAP 路：落盘后用 tshark 校对 version/length/set/IE/端口及错误终态；网卡路：tcpdump 在真实接口校对 UDP 2055/4739、profile、丢包和错误率，两路均断言字段，不以“任务未报错”替代。
- 八要素：文件=`registry.go:1394-1421`、`chain_planner_translate.go:3255-3287`、`internal/protocol/cflow/{planner,builder}.go`；接口=`Planner.Validate/Plan` 与 `BuildV9ExportPacket/BuildIPFIXMessage`；结构=`CFlowConfig` 及 templates/records/options；流程=校验→模板状态→编码→回填长度→输出；错误=七类锚词并中断；边界=流式 packet、session 局部状态、资源指标待基准；冲突=旧顶层 cflow/flat 五键与层链冲突；回滚=移除 cflow registry/translate/generator 接线并恢复三件套上一版本。

### 15.3 D6/D7：动态字段与门 1 三行展开

动态字段逐项结论：`ip.src`、`ip.dst`、`udp.src_port`、`udp.dst_port`、`cflow.sequence`、`source_id`、`observation_domain_id`、record 地址/端口/计数/时间目前只有 fixed 证据；inc/rand/list/pattern 没有 cflow 专属解析路径，立项 D-CFLOW-9，不把 `flows>1` 静态复制当动态。当前包序号算法位于 `planner.go:42-57` 的 `idx++`，并非按动态字段生成；因此五策略各自的序号算法位置为“未接线，补策略解析与按 FlowIndex 复现后再定”，不能虚构代码位置。`profile/template_id/IE/PEN` 是结构字段，固定且不开放动态。

| 门1行 | 去向与完整证据 |
|---|---|
| §1 | 旧 `src_ip/dst_ip/src_port/dst_port/count` 与顶层 `cflow` 正例零残留；完整例见 §2 的 `[ip,udp,cflow]`，地址住 ip、端口住 udp、数量住 `flow_control`；23/26 是故意 presence/游离键拒绝例。 |
| §3 | cflow 是无长连接 UDP 导出；会话表=exporter/session 四元组，事务序列=template→data，关联关系=source/OD→template，插入位置=每个 datagram 的 cflow payload，时间线=planner 按 packet 顺序发出。长连接三项对 cflow 不适用，明确登记为边界判定：若未来引入连接型 profile，必须新增 profile、五件套和用例，不得借本套件宣称覆盖。 |
| §12 | 四元组和业务动态字段逐项见本节；当前 fixed 仅由 `planner.go`/`builder.go` 支撑，动态五策略及跨策略动态待 D-CFLOW-9 代码立项，`idx++` 仅是 packet index，不是动态值算法。 |

D8 结论：本轮不存在正例游离键；无可住字段的动态能力已登记 D-CFLOW-9，task error 传播已登记 D-CFLOW-8，均有后续迁入/实现路径，不以开放留白冒充完成。

### 15.4 D1–D8 编号对账（本轮静态闭环）

| 编号 | 规范要求 → 业务形态 | registry/translate 现状 | 结论与后续缺口 |
|---|---|---|---|
| D1 | RFC 3954/7011 的 UDP datagram；`ip → udp → cflow` | `registry.go` 将 `cflow` 注册为依赖/承载 `udp` 的终结层；`chain_planner_translate.go` 严格解码层配置 | 27 例已统一层链形；真实 PCAP/NIC 仍属执行缺口 |
| D2 | v9 header、count、Template/Data FlowSet | `internal/protocol/cflow/builder.go` 的 v9 编码器消费 `CFlowConfig` | 正例 1–7、15 对账；D-CFLOW-2 仍待真实解码 |
| D3 | IPFIX length、Template/Options/Data Set、OD | 同一 builder 的 IPFIX 分支；层字段由 registry/translate 进入 `CFlowConfig` | 正例 8–14 对账；D-CFLOW-3 仍待真实解码 |
| D4 | IPv4/IPv6 IE 长度与地址族匹配 | `ValidateConfig` 检查 element 8/27 与 record 地址形态 | 正例 1/2/8/9、负例 20；端到端校准登记 D-CFLOW-4 |
| D5 | enterprise bit/PEN 与 variable-length marker | registry 允许 `templates` 结构字段，builder 编码 PEN/65535 | 正例 10/11；PEN/变量长度 PCAP 解码登记 D-CFLOW-5 |
| D6 | source/OD、sequence 与 exporter/session 隔离 | `planner.go` fan-out 使用 `Exporters`/`Sessions`，层配置不另造顶层字段 | 正例 3/6/7/12/14；交错输出登记 D-CFLOW-6 |
| D7 | timeout、sampling、Options Template | registry/translate 允许 `options` 与 options template；builder 有 v9/IPFIX options 分支 | 正例 4/13；字段解码登记 D-CFLOW-7 |
| D8 | 非法 version/template/length/field/address/carrier/checksum 必须拒绝 | `ValidateConfig`/层校验提供稳定锚词；负例 16–27 覆盖 wire fault 与 presence/载体/白名单 | 静态形状已闭环；API→task 错误终态仍是 D-CFLOW-8，未以“0 包完成”冒充通过 |

D1–D8 的“已覆盖”只表示配置落在现有 registry/translate 能力和 JSON 静态断言内；不把未运行的 suite、PCAP、NIC 或 task 终态写成证据。动态五策略及无可住字段登记 D-CFLOW-9，连接型扩展登记 D-CFLOW-10。

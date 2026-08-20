# cflow（NetFlow v9/IPFIX）设计与用例对抗审查

> 审查范围：`docs/protocol-designs/43-cflow-design.md`、`docs/protocol-designs/43-cflow-testcase.md`、`trafficgen/test/protocol_pcap/cases/cflow.json`
> 日期：2026-08-20
> 状态：设计阶段审查；不检查 Go 实现，不宣称 `cflow` 层已注册。

## 1. 审查口径

本审查把“代码逻辑视角”替换为**规格可实现性视角**：检查版本、UDP 载体、header/Set/template/data、字段长度、地址族、enterprise IE、timeout、exporter/session 隔离和错误传播是否足以指导后续实现；再独立检查用例是否真正覆盖这些契约。审查只接受已由 RFC 3954/RFC 7011 或 `tshark -G fields` 证明的字段，不用猜测的厂商名、checksum 或 timestamp 常量。

## 2. 字段探针与证据

已运行：

```sh
tshark -G fields | grep -E '^F\s+.*cflow\.'
```

探针确认本套件使用的字段已注册：

- header：`cflow.version`、`cflow.len`、`cflow.count`、`cflow.sequence`、`cflow.source_id`、`cflow.od_id`；
- set/template：`cflow.flowset_id`、`cflow.flowset_length`、`cflow.template_id`、`cflow.template_field_count`、`cflow.template_field_type`、`cflow.template_field_length`；
- record：`cflow.srcaddr`、`cflow.dstaddr`、`cflow.srcaddrv6`、`cflow.dstaddrv6`、`cflow.srcport`、`cflow.dstport`、`cflow.protocol`、`cflow.packets`、`cflow.octets`、`cflow.timestart`、`cflow.timeend`；
- IPFIX enterprise/options：`cflow.template_ipfix_pen_provided`、`cflow.template_ipfix_field_type_enterprise`、`cflow.template_ipfix_field_pen`、`cflow.enterprise_private_entry`、`cflow.template_ipfix_scope_field_count`、`cflow.template_ipfix_total_field_count`、`cflow.flow_active_timeout`、`cflow.flow_inactive_timeout`。

未发现并因此未使用 `cflow.checksum`；cflow 应用层没有 checksum。JSON 的 `udp.checksum` 仅在传输边界正例中使用，避免把 UDP checksum 冒充 cflow checksum。

## 3. 三方/四方闭环核对

### 3.1 ID 集合与顺序

设计 §4、testcase §2、本文表格和 JSON 逐项核对，22 个 ID 顺序一致：

| # | ID | 类型 | JSON packet_count |
|---:|---|---|---:|
| 1 | `cflow_v9_template_data_ipv4` | 正 | 1 |
| 2 | `cflow_v9_ipv6_record` | 正 | 1 |
| 3 | `cflow_v9_header_sequence_source` | 正 | 1 |
| 4 | `cflow_v9_timeout_sampling` | 正 | 1 |
| 5 | `cflow_v9_multi_record` | 正 | 1 |
| 6 | `cflow_v9_multi_exporter` | 正 | 2 |
| 7 | `cflow_v9_multi_session` | 正 | 2 |
| 8 | `cflow_ipfix_template_data_ipv4` | 正 | 1 |
| 9 | `cflow_ipfix_ipv6_record` | 正 | 1 |
| 10 | `cflow_ipfix_enterprise_ie` | 正 | 1 |
| 11 | `cflow_ipfix_variable_length_ie` | 正 | 1 |
| 12 | `cflow_ipfix_observation_domain_sequence` | 正 | 1 |
| 13 | `cflow_ipfix_timeout_options_template` | 正 | 1 |
| 14 | `cflow_ipfix_multi_exporter` | 正 | 2 |
| 15 | `cflow_boundary_lengths` | 正 | 1 |
| 16 | `cflow_neg_version` | 负 | — |
| 17 | `cflow_neg_template` | 负 | — |
| 18 | `cflow_neg_length` | 负 | — |
| 19 | `cflow_neg_field_count` | 负 | — |
| 20 | `cflow_neg_address_family` | 负 | — |
| 21 | `cflow_neg_udp_port` | 负 | — |
| 22 | `cflow_neg_checksum` | 负 | — |

### 3.2 正例覆盖

| 检查项 | 覆盖证据 | 结论 |
|---|---|---|
| v9/IPFIX profile | ID 1–7 为 v9、8–15 为 IPFIX；端口分别 2055/4739 | 通过；无单一 profile 偷换版本 |
| header/version/sequence | ID 1–4、8、12、15 的 fields/frames | 通过；v9 20B/IPFIX 16B 的长度语义写明 |
| template/data set | ID 1、2、5、8、9、10、11、13 | 通过；Data Set ID 与 template 绑定 |
| IPv4/IPv6 | ID 1、5、8、9；IPv6 field length=16 | 通过；不把 IPv6 缩成 IPv4 |
| enterprise/info elements | ID 10、11；enterprise bit/PEN/65535 | 通过；不写未注册厂商名称 |
| timeouts/sampling | ID 4、13 | 通过；active/inactive 和 sampling 均有非平凡断言 |
| multi-exporter | ID 6、14；source_id/OD ID distinct | 通过；状态隔离维度可观察 |
| multi-session | ID 7；UDP src port distinct | 通过；不依赖调度交错 |
| length/set count | ID 1、5、8、13、15 | 通过；count 与 FlowSet/Set 数的区别明确 |
| checksum | ID 15 只断言 UDP checksum，且明确无 cflow checksum | 通过；未伪造协议字段 |

### 3.3 负例覆盖与结构

| ID | 失败路径 | 锚点 | 结构结论 |
|---|---|---|---|
| `cflow_neg_version` | version/profile mismatch | `version` | 仅错误断言 |
| `cflow_neg_template` | Data Set 无模板 | `template` | 仅错误断言 |
| `cflow_neg_length` | Message/Set 边界错误 | `length` | 仅错误断言 |
| `cflow_neg_field_count` | descriptors/record count 不一致 | `field` | 仅错误断言 |
| `cflow_neg_address_family` | IPv4/IPv6 template 混用 | `address` | 仅错误断言 |
| `cflow_neg_udp_port` | carrier/端口错误 | `udp` | 仅错误断言 |
| `cflow_neg_checksum` | 伪造不存在的 cflow checksum | `checksum` | 仅错误断言 |

## 4. 对抗性发现与修复记录

### F-01（第 1 轮发现，已修复）：把 cflow 写成单一版本会掩盖 header 差异

若只写“cflow 支持 NetFlow/IPFIX”，实现可能用 version=9/10 自动推导，测试无法发现 IPFIX 16 字节 header、OD ID 和 Message length 的差异。本版改为两个显式 profile，且 testcase/JSON 按 v9 7 个正例、IPFIX 8 个正例分段；负例 `cflow_neg_version` 专门验证 profile/version 不匹配。

### F-02（第 1 轮发现，已修复）：正例字段曾可能使用未注册 enterprise 名称

Wireshark 的 cflow dissector（解析器）只稳定提供 enterprise bit/PEN/type/bytes 字段，不保证任意厂商 IE 的名称。已将 enterprise 正例改成 `cflow.template_ipfix_*` 与 `cflow.enterprise_private_entry`，并在字段探针节列出注册证据；不写 `cflow.enterprise_name` 等猜测字段。

### F-03（第 1 轮发现，已修复）：checksum 语义容易伪造

cflow 应用层没有 checksum，只有 UDP checksum。已删除所有 `cflow.checksum` 正例字段；`cflow_boundary_lengths` 只观察 `udp.checksum`，`cflow_neg_checksum` 要求拒绝应用 checksum 注入，并在设计/测试中说明不是合法线上报文。

### F-04（第 2 轮发现，已修复）：负例可能带成功 PCAP 断言

按测试驱动器的 negative 语义，负例不能含 packet_count/fields/frames，否则会把失败任务和 PCAP 验证混在一起。已在 testcase、audit 和 JSON 统一为严格两个 expect 键，并在本审计 §3.3 逐项复核。

### F-05（第 2 轮发现，已修复）：count 与 Set 数量的混淆

v9 `count` 是记录数量而非 FlowSet 数，IPFIX 没有 v9 count 字段；IPFIX `length` 是整个 Message 字节数。已在设计不变式、正例 ID 1/5/8/13/15 和 testcase 断言中分别表达，避免用 `cflow.count` 断言 IPFIX。

## 5. 最终结论

当前四件套满足：双 profile（RFC 3954 NetFlow v9、RFC 7011 IPFIX）、UDP/2055/4739、header/version/sequence/source/OD、Template/Data/Options Set、IPv4/IPv6、enterprise/info elements、timeout/sampling、多 exporter/session、length/count、无应用 checksum 语义，以及 version/template/length/field count/address-family/port/checksum 负例。未修改 Go。

自审记录：共完成两轮自审。第 1 轮修复 F-01/F-02/F-03 后，重新核对规范边界和字段注册；第 2 轮修复 F-04/F-05 后，重新核对四方 ID、packet_count、正负 expect 结构、offset 和 checksum 语义；**自审通过 2 轮，最后一轮 clean（通过）**。

## 6. 修订记录

- v1.0.0（2026-08-20）：完成设计阶段四件套对抗审查，确认 22 个 ID 的四方闭环和正负路径边界。

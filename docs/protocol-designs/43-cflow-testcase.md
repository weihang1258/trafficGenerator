# cflow（NetFlow v9/IPFIX 流记录导出）测试用例契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/43-cflow-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/cflow.json`
> 状态：`cflow` 层尚未实现；本文只定义实现后的 PCAP 断言，不宣称 MCP（模型上下文协议）套件可运行。

## 1. 测试原则

用例从设计 §1–§5 逐项派生。cflow 只接受 `netflow_v9_rfc3954`（RFC 3954）和 `ipfix_rfc7011`（RFC 7011）两个 profile（协议档案），分别使用 UDP/2055 和 UDP/4739；不把任意 UDP payload（载荷）标成 cflow。无 IPv4 option 时 cflow payload offset（偏移）为 42，IPv6 为 62。UDP checksum 是传输层字段，cflow 应用层没有 checksum；正例不伪造 `cflow.checksum`。

- 每个正例都有 `packet_count`、非空 `fields` 和非空 `frames`。
- 正例字段全部来自 `tshark -G fields` 已注册的 cflow/UDP/IP 字段；动态 export time 不写固定值。
- frames 只使用公共 header、Set header、template descriptor 的可复算前缀；offset 42/62 指向 UDP payload，不把 Ethernet/IP/UDP 头算进 cflow。
- 负例的 `expect` 严格只有 `expect_error` 与 `error_contains`，无 `packet_count`、`fields`、`frames`。
- 多 exporter/session 只用显式 packet 数和可观察 source/OD/端口隔离，不假设调度器交织顺序。

## 2. 用例索引（与设计、审计、JSON 同序）

| # | ID | 类型 | 覆盖 | packet_count |
|---:|---|---|---|---:|
| 1 | `cflow_v9_template_data_ipv4` | 正 | v9 header、Template/Data Set、IPv4 record | 1 |
| 2 | `cflow_v9_ipv6_record` | 正 | v9 IPv6 record | 1 |
| 3 | `cflow_v9_header_sequence_source` | 正 | sequence/source ID | 1 |
| 4 | `cflow_v9_timeout_sampling` | 正 | timeout/sampling | 1 |
| 5 | `cflow_v9_multi_record` | 正 | count 与两条 record | 1 |
| 6 | `cflow_v9_multi_exporter` | 正 | 两个 source ID | 2 |
| 7 | `cflow_v9_multi_session` | 正 | 两个 UDP session | 2 |
| 8 | `cflow_ipfix_template_data_ipv4` | 正 | IPFIX length、Template/Data Set | 1 |
| 9 | `cflow_ipfix_ipv6_record` | 正 | IPv6 record | 1 |
| 10 | `cflow_ipfix_enterprise_ie` | 正 | enterprise IE/PEN | 1 |
| 11 | `cflow_ipfix_variable_length_ie` | 正 | variable-length IE | 1 |
| 12 | `cflow_ipfix_observation_domain_sequence` | 正 | OD/sequence | 1 |
| 13 | `cflow_ipfix_timeout_options_template` | 正 | Options Template/timeout | 1 |
| 14 | `cflow_ipfix_multi_exporter` | 正 | 两个 OD ID | 2 |
| 15 | `cflow_boundary_lengths` | 正 | 最小合法 length、无 cflow checksum | 1 |
| 16 | `cflow_neg_version` | 负 | version 错误 | — |
| 17 | `cflow_neg_template` | 负 | 缺 template | — |
| 18 | `cflow_neg_length` | 负 | header/Set length 错误 | — |
| 19 | `cflow_neg_field_count` | 负 | field count 错误 | — |
| 20 | `cflow_neg_address_family` | 负 | 地址族错误 | — |
| 21 | `cflow_neg_udp_port` | 负 | UDP carrier/端口错误 | — |
| 22 | `cflow_neg_checksum` | 负 | 伪造 cflow checksum | — |

## 3. 正例断言契约

### 3.1 NetFlow v9

- **`cflow_v9_template_data_ipv4`**：UDP/2055，一个 v9 Export Packet，header version=9、count=2（一个 Template Record 加一个 Data Record），含 Template FlowSet ID=0、template 256（8/4、12/4）和 Data Set ID=256 的 IPv4 源/目的地址。断言 `cflow.version=9`、`cflow.count=2`、`cflow.flowset_id=0`、`cflow.template_id=256`、`cflow.srcaddr=10.43.1.1`；offset 42 固定 `00 09 00 02`。
- **`cflow_v9_ipv6_record`**：UDP/2055，template 使用 field type 27/28、length 16，Data Set 为 `2001:db8:43::1`→`2001:db8:43::2`。断言 `cflow.version=9`、`cflow.srcaddrv6`、`cflow.dstaddrv6`、`cflow.template_field_length=16`；offset 62 固定 `00 09 00 02`，证明 IPv6 记录不缩成 4 字节。
- **`cflow_v9_header_sequence_source`**：显式 sequence=0x01020304、source_id=0x0a0b0c0d、sys_uptime=600；断言 `cflow.sequence=0x01020304`、`cflow.source_id=0x0a0b0c0d`、`cflow.sysuptime=600` 和 UDP dstport=2055。frame 固定版本/count，不固定 unix time。
- **`cflow_v9_timeout_sampling`**：模板/记录含 `FIRST_SWITCHED`、`LAST_SWITCHED`，并含 Options/采样语义 `flow_active_timeout=60`、`flow_inactive_timeout=15`、sampling interval=1000；断言两个 timeout、`cflow.sampling_interval=1000`、`cflow.timestart`/`timeend` 非零。frame 固定 template descriptor 起点。
- **`cflow_v9_multi_record`**：一个 v9 packet 的 count=2，Data Set 有两个 IPv4 records，地址分别为 10.43.5.1→10.43.5.2 与 10.43.5.3→10.43.5.4；断言 `cflow.count=2`、两个 `cflow.srcaddr` 值、`cflow.flowset_length` 非零和 `cflow.packets` 非零，验证 count 不是 FlowSet 数。
- **`cflow_v9_multi_exporter`**：两个 UDP/2055 packet，source_id 分别 101、202，且各带自己的 template/data；断言 packet_count=2、`cflow.source_id` distinct values=101/202、两个 template ID 均为 256。不能用 source_id=0 默认化。
- **`cflow_v9_multi_session`**：两个 UDP 四元组（src port 41001/41002、dst 2055），source_id 同为 7 但 template 状态隔离；断言 packet_count=2、`udp.srcport` distinct values、每包 `cflow.version=9` 和 `cflow.template_id=256`。不假设 packet 交织顺序。

### 3.2 IPFIX

- **`cflow_ipfix_template_data_ipv4`**：UDP/4739，一个 IPFIX Message，header version=10、length=44、OD=43，含 Template Set ID=2、template 256（8/4、12/4）和 Data Set 256。断言 `cflow.version=10`、`cflow.len=44`、`cflow.flowset_id=2`、`cflow.template_id=256`、`cflow.srcaddr=10.43.8.1`；offset 42 固定 `00 0a 00 2c`。
- **`cflow_ipfix_ipv6_record`**：OD=44，template 27/28 长度 16，Data Set 含 `2001:db8:44::1`→`::2`；断言 version=10、OD=44、IPv6 地址字段和 length=16；offset 62 固定 `00 0a`。
- **`cflow_ipfix_enterprise_ie`**：template 含标准 `sourceIPv4Address` 与 enterprise IE ID=0x8001、PEN=424242；断言 `cflow.template_ipfix_pen_provided=1`、`cflow.template_ipfix_field_type_enterprise=1`、`cflow.template_ipfix_field_pen=424242`、`cflow.enterprise_private_entry` 非空。不得断言未注册的厂商 IE 名称。
- **`cflow_ipfix_variable_length_ie`**：template 的 enterprise IE length=65535（variable-length marker），Data Set 使用短字符串值；断言 template field length=65535、enterprise bit/PEN 和 `cflow.enterprise_private_entry` 非空；frame 固定 `00 0a` 与 Set ID，不把变量值当固定字段长度。
- **`cflow_ipfix_observation_domain_sequence`**：version=10、sequence=0x01020304、OD=0x11223344，Data Set 仍引用 template 256；断言 `cflow.sequence=0x01020304`、`cflow.od_id=0x11223344`、`cflow.template_id=256` 和 dstport=4739。
- **`cflow_ipfix_timeout_options_template`**：同一 Message 含 Options Template Set ID=3，scope field count=1、total field count=2，scope=observationPointId、option=active/inactive timeout；断言 `cflow.template_ipfix_scope_field_count=1`、`cflow.template_ipfix_total_field_count=2`、两个 timeout 字段。frame offset 42 固定 `00 0a`，不把 Options Set 数量当 header count。
- **`cflow_ipfix_multi_exporter`**：两个 UDP/4739 messages，OD ID 分别 501/502，sequence 各自从 0 开始并含独立 template/data；断言 packet_count=2、OD distinct values=501/502、version=10 和 dstport=4739。模板不得跨 OD 解码。

### 3.3 长度/无 checksum 边界

- **`cflow_boundary_lengths`**：最小一个 v9 Export Packet，header 和一个合法 Template/Data Set 按实际字节长度回填；断言 version=9、count=2、flowset length 非零、`udp.dstport=2055`、`udp.checksum` 非零（仅说明 UDP 传输校验和存在），并以 frame offset 42 固定 `00 09 00 02`。不出现也不断言 `cflow.checksum`；cflow 没有应用 checksum。

## 4. 负例契约

负例配置使用 `wire_fault` 或不合法 profile，且 `expect` 必须严格是以下两个键：

| ID | 故障输入 | error_contains |
|---|---|---|
| `cflow_neg_version` | v9 profile 声明 version=10，或 IPFIX profile 声明 version=9 | `version` |
| `cflow_neg_template` | Data Set ID=256 但 session 未出现 template 256 | `template` |
| `cflow_neg_length` | Message/Export/Set length 小于 header、超过 packet 或与实际 body 不符 | `length` |
| `cflow_neg_field_count` | template field_count=3 但只提供 2 个 descriptor，或 record 长度不匹配 | `field` |
| `cflow_neg_address_family` | IPv4 template 填 16-byte IPv6 record，或 IPv6 template 填 4-byte IPv4 record | `address` |
| `cflow_neg_udp_port` | v9 使用 4739、IPFIX 使用 2055，或 carrier 不是 UDP | `udp` |
| `cflow_neg_checksum` | cflow 对象请求 checksum/wire fault checksum；cflow 应用层无该字段 | `checksum` |

负例不得有 `packet_count`、`fields`、`frames` 或成功 PCAP 断言；错误必须最终体现为 task error。

## 5. 三方一致性检查

1. 设计 §4、本文 §2、审计 §3 与 JSON 的 22 个 ID 集合、拼写和顺序完全一致；正例 15、负例 7。
2. 正例 packet_count 按顺序为 `[1,1,1,1,1,2,2,1,1,1,1,1,1,2,1]`，每条均含 fields 与 frames。
3. 每个正例的 cflow fields 都在 `tshark -G fields` 探针清单中；未使用 `cflow.checksum`。
4. v9 正例只使用 UDP/2055、version=9；IPFIX 正例只使用 UDP/4739、version=10。
5. IPv4 frame offset=42，IPv6 frame offset=62；动态时间只用 nonzero 或不作值断言。
6. multi-exporter 用 v9 source_id 或 IPFIX OD ID，multi-session 用 UDP 端口；不以随机 packet 顺序表达关联。
7. 负例 `expect` 仅有 `expect_error`、`error_contains`。

## 6. 实现后执行建议

先运行 JSON 语法、ID 唯一性、正负 expect 结构、字段注册名、offset 和 packet_count 静态检查；然后按索引顺序验证 v9 header/template/data、IPv4/IPv6、timeout/sampling、exporter/session 隔离，再验证 IPFIX length/options/enterprise/variable-length，最后执行七个负例。应分别用 tshark 检查 cflow expert malformed 标记、UDP checksum 与真实 Set length；不能以“任务完成但 0 包”作为通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 15 个正例和 7 个负例，覆盖 RFC 3954/RFC 7011 双 profile、UDP 2055/4739、header/sequence/source/OD、template/data/options、IPv4/IPv6、enterprise/variable-length、timeout、multi-exporter/session、长度和无应用 checksum 边界。

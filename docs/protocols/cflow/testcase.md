# cflow（NetFlow v9/IPFIX 流记录导出）测试用例契约

> 版本：v1.1.3（静态闭环对账版）
> 日期：2026-10-01
> 配套设计：`docs/protocols/cflow/design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/cflow.json`
> 本轮只改 cflow design/testcase/cases 三件套，不改 Go；不跑 suite、PCAP、NIC；不写 Git。
> 状态：层链用例契约；总 27 例（正 15、负 12），以 JSON 实际 ID/断言为准。cflow engine/builder 已落地（registry `cflow` 分支、translate 严格解码分支、`ValidateConfig`/`BuildV9/IPFIX`），但本轮不宣称已执行 suite/PCAP/NIC。`trafficgen/docs/protocol-pcap-test/cflow.md` 仅是 2026-08-27 的 22 例历史产物，不是当前 27 例证据。

## 1. 测试原则

用例从设计 §1–§5 逐项派生。cflow 只接受 `netflow_v9_rfc3954`（RFC 3954）和 `ipfix_rfc7011`（RFC 7011）两个 profile（协议档案），分别使用 UDP/2055 和 UDP/4739；不把任意 UDP payload（载荷）标成 cflow。无 IPv4 option 时 cflow payload offset（偏移）为 42，IPv6 为 62。UDP checksum 是传输层字段，cflow 应用层没有 checksum；正例不伪造 `cflow.checksum`。

- 每个正例都有 `packet_count`、非空 `fields` 和非空 `frames`。
- 正例字段全部来自 `tshark -G fields` 已注册的 cflow/UDP/IP 字段；动态 export time 不写固定值。
- frames 只使用公共 header、Set header、template descriptor 的可复算前缀；offset 42/62 指向 UDP payload，不把 Ethernet/IP/UDP 头算进 cflow。
- 负例的 `expect` 严格只有 `expect_error` 与 `error_contains`，无 `packet_count`、`fields`、`frames`。
- 多 exporter/session 只用显式 packet 数和可观察 source/OD/端口隔离，不假设调度器交织顺序。

## 2. 用例索引（与设计、JSON 同序）

测试点清单（规范条文 → 业务场景 → 代码分支 → 缺口）：每个 profile 的 header/template/data、IPv4/IPv6、sequence/source/OD、timeout/sampling/options、enterprise/variable-length、边界长度/无 checksum、multi-exporter/session、7 类 wire_fault、carrier/顶层/count/未知字段拒绝；已覆点见 §2 表与 §3/§4 断言条目，缺口见设计 D-CFLOW-1…10。

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
| 23 | `cflow_neg_presence_top_level_cflow` | 负 | 层链与顶层 cflow 混用 | — |
| 24 | `cflow_neg_carrier_tcp` | 负 | TCP carrier | — |
| 25 | `cflow_neg_carrier_no_udp` | 负 | 缺 UDP carrier | — |
| 26 | `cflow_neg_flat_count` | 负 | 顶层 count 白名单违规 | — |
| 27 | `cflow_neg_unknown_layer_field` | 负 | 未知 cflow 层字段 | — |

## 3. 正例断言契约

### 3.1 NetFlow v9

- **`cflow_v9_template_data_ipv4`**：UDP/2055，一个 v9 Export Packet，header version=9、count=2（一个 Template Record 加一个 Data Record），含 Template FlowSet ID=0、template 256（8/4、12/4）和 Data Set ID=256 的 IPv4 源/目的地址。断言 `cflow.version=9`、`cflow.count=2`、`cflow.flowset_id=0`、`cflow.template_id=256`、`cflow.srcaddr=10.43.1.1`；offset 42 固定 `00 09 00 02`。
- **`cflow_v9_ipv6_record`**：UDP/2055，template 使用 field type 27/28、length 16，Data Set 为 `2001:db8:43::1`→`2001:db8:43::2`。断言 `cflow.version=9`、`cflow.srcaddrv6`、`cflow.dstaddrv6`、`cflow.template_field_length=16`；offset 62 固定 `00 09 00 02`，证明 IPv6 记录不缩成 4 字节。
- **`cflow_v9_header_sequence_source`**：显式 sequence=0x01020304、source_id=0x0a0b0c0d、sys_uptime=600；断言 `cflow.sequence=0x01020304`、`cflow.source_id=0x0a0b0c0d`、`cflow.sysuptime=600` 和 UDP dstport=2055。frame 固定版本/count，不固定 unix time。
- **`cflow_v9_timeout_sampling`**：模板/记录含 `FIRST_SWITCHED`、`LAST_SWITCHED`，并含 Options/采样语义 `flow_active_timeout=60`、`flow_inactive_timeout=15`、sampling interval=1000；断言两个 timeout、`cflow.sampling_interval=1000`、`cflow.timestart`/`timeend` 非零。frame 固定 template descriptor 起点。
- **`cflow_v9_multi_record`**：一个 v9 packet 的 count=3（一个 Template Record 加两条 Data Record），Data Set 有两个 IPv4 records，地址分别为 10.43.5.1→10.43.5.2 与 10.43.5.3→10.43.5.4；断言 `cflow.count=3`、两个 `cflow.srcaddr` 值、`cflow.flowset_length` 非零和 `cflow.packets` 非零，验证 count 不是 FlowSet 数。
- **`cflow_v9_multi_exporter`**：两个 UDP/2055 packet，source_id 分别 101、202，且各带自己的 template/data；断言 packet_count=2、`cflow.source_id` distinct values=101/202、两个 template ID 均为 256。不能用 source_id=0 默认化。
- **`cflow_v9_multi_session`**：两个 UDP 四元组（src port 41001/41002、dst 2055），source_id 同为 7 但 template 状态隔离；断言 packet_count=2、`udp.srcport` distinct values、每包 `cflow.version=9` 和 `cflow.template_id=256`。不假设 packet 交织顺序。

### 3.2 IPFIX

- **`cflow_ipfix_template_data_ipv4`**：UDP/4739，一个 IPFIX Message，header version=10、length=44、OD=43，含 Template Set ID=2、template 256（8/4、12/4）和 Data Set 256。断言 `cflow.version=10`、`cflow.len=44`、`cflow.flowset_id=2`、`cflow.template_id=256`、`cflow.srcaddr=10.43.8.1`；offset 42 固定 `00 0a 00 2c`。
- **`cflow_ipfix_ipv6_record`**：OD=44，template 27/28 长度 16，Data Set 含 `2001:db8:44::1`→`::2`；断言 version=10、OD=44、IPv6 地址字段和 length=16；offset 62 固定 `00 0a`。
- **`cflow_ipfix_enterprise_ie`**：template 含标准 `sourceIPv4Address` 与 enterprise IE ID=0x8001、PEN=424242；断言 `cflow.template_ipfix_pen_provided=1`、`cflow.template_ipfix_field_type_enterprise=1`、`cflow.template_ipfix_field_pen=424242`、`cflow.enterprise_private_entry` 非空。不得断言未注册的厂商 IE 名称。
- **`cflow_ipfix_variable_length_ie`**：template 的 enterprise IE length=65535（variable-length marker），Data Set 使用短字符串值；断言 template field length=65535、enterprise bit/PEN 和 `cflow.enterprise_private_entry` 非空；frame 固定 `00 0a` 与 Set ID，不把变量值当固定字段长度。
- **`cflow_ipfix_observation_domain_sequence`**：version=10、sequence=0x01020304、OD=0x11223344，Data Set 仍引用 template 256；断言 `cflow.sequence=0x01020304`、`cflow.od_id=0x11223344`、`cflow.template_id=256` 和 dstport=4739。
- **`cflow_ipfix_timeout_options_template`**：同一 Message 含 Options Template Set ID=3，scope field count=1（线上实测 total=3=Scope 1 + Data 2，P6 勘误：旧文 total=2 不相容，断言只钉 scope=1 + 两 timeout，见 P6 已知事项①）；scope=observationPointId、option=active/inactive timeout；断言 `cflow.template_ipfix_scope_field_count=1`、两个 timeout 字段。frame offset 42 固定 `00 0a`，不把 Options Set 数量当 header count。
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
| `cflow_neg_checksum` | cflow 对象请求 checksum/wire fault checksum | `checksum` |
| `cflow_neg_presence_top_level_cflow` | layers 与顶层 cflow 同时出现 | `no longer accepts a top-level cflow sub-config` |
| `cflow_neg_carrier_tcp` | cflow 置于 tcp carrier | `carrier` |
| `cflow_neg_carrier_no_udp` | 缺少 udp carrier | `carrier` |
| `cflow_neg_flat_count` | 顶层 count | `no longer accepts flat config field count` |
| `cflow_neg_unknown_layer_field` | cflow 层未知字段 | `layers: layer` |

负例不得有 `packet_count`、`fields`、`frames` 或成功 PCAP 断言；错误必须最终体现为 task error。

## 5. 三源回指、场景强度、存量去向与 C1–C6

| 来源 | 规范/实现面 | 用例去向 |
|---|---|---|
| RFC 3954 §5 | v9 header、Template/Data FlowSet、count、IPv4/IPv6、sequence/source | 1–7、15 |
| RFC 7011 §3、§7 | IPFIX length、Template/Options/Data Set、OD、enterprise/variable-length IE | 8–14 |
| `registry.go` cflow schema、`chain_planner_translate.go` cflow 分支、`internal/protocol/cflow/{planner,builder}.go` | `[ip,udp,cflow]` 依赖、profile/端口、模板引用、地址族、wire_fault 错误 | 1–27；代码事实，端到端待执行 |
| Cisco IOS NetFlow v9 / libfixbuf IPFIX 行为 | 默认端口、source/OD 与模板隔离 | 6、7、14；现网抓包待确认 |

每条 ID 是一个不可再分的主行为点；组合场景仍只钉可观察的 packet_count、字段值和 raw prefix，不把随机到达顺序当作关联证据。正常、边界、非法覆盖分别为 1–15、15、16–27；动态字段只在当前 fixed 输入与 nonzero/presence 断言中使用，inc/rand/list/pattern 仍是 D-CFLOW-9 缺口。

同连接多轮、非正常结束、长保活对无连接 cflow 导出不适用，按设计 §11 作为豁免登记，并由 D-CFLOW-10 跟踪潜在新 profile/扩展；不伪造覆盖。多 exporter/session 通过显式 source/OD/四元组关联；正例 5、6、7、14 是业务组合场景，当前未声称并发交错已实测。

### 5.1 存量逐条去向

| 存量 | 去向 |
|---|---|
| 原 22 个 v9/IPFIX 正常/验证例 | 保留并按当前 JSON ID 1–22 对账 |
| 新增层链白名单/carrier/未知字段负例 23–27 | 保留为故意拒绝契约，不迁成正例 |
| 无法在层链表达的旧正例 | 无；cflow registry 已有 15 个字段且 translate 有严格解码分支 |
| `trafficgen/docs/protocol-pcap-test/cflow.md` 的 22 例历史结果 | 仅历史产物；其缺少 23–27，不能作为当前 27 例 suite/NIC 证据 |

### 5.2 C1–C6 审查门（本轮静态契约）

| ID | 检查 | 结论 |
|---|---|---|
| C1 | JSON 可解析、27 个 ID 唯一且顺序与本文/设计一致 | 绿（27/27） |
| C2 | 15 个正例严格 `[ip,udp,cflow]`，正例顶层业务键零残留 | 绿（15/15） |
| C3 | 地址只在 `ip`、端口只在 `udp`；`cflow` 业务只在终结层 | 绿；10 个负例保留空顶层，另有 1 个故意顶层 `cflow`、1 个故意 `count` |
| C4 | 12 个负例 `expect` 严格只有 `expect_error`、`error_contains`，锚词非空 | 绿（12/12） |
| C5 | v9/IPFIX、IPv4/IPv6、模板/数据、options、enterprise、variable-length、multi-exporter/session、边界和 carrier/白名单负例均有原子点 | 绿；现网第三源、动态策略、性能与 NIC 仍待补 |
| C6 | 本轮只改 cflow design/testcase/cases 三件套 | 绿；本轮不改 Go、不跑 suite/NIC |

## 6. 对账检查与执行边界

1. 总数 27，正/负为 15/12，ID 唯一；layer shape 为 `[ip,udp,cflow]` 25 例、`[ip,tcp,cflow]` 1 个故意 carrier 负例、`[ip,cflow]` 1 个故意缺 carrier 负例。
2. 15 个正例 packet_count 为 `[1,1,1,1,1,2,2,1,1,1,1,1,1,2,1]`，每条均含非空 fields 与 frames。
3. 正例 spec 顶层键集合为 `{}`（15/15）；负例仅两例故意非空：顶层 `cflow` 与 `count` 各 1。
4. v9 正例只使用 UDP/2055、version=9；IPFIX 正例只使用 UDP/4739、version=10；IPv4/IPv6 frame offset 分别为 42/62。
5. 负例 expect 键集合恰为 `{'expect_error','error_contains'}`（12/12），没有 packet_count、fields、frames 或 notes。
6. multi-exporter/session 通过 source_id、OD 或 UDP 源端口关联，不依赖 packet 顺序。

当前仅完成 JSON/文档静态对账；未宣称当前 27 例已通过 suite、PCAP 或 NIC。后续执行顺序是静态脚本 → 15 个正例字段/长度 → 12 个 task error；失败必须以真实 task error 结束，不能用 completed/0 packet 代替。

## 7. T1–T6 审查补录

### T1 三源回指

| 测试面 | RFC/官方条文 | 设计条目 | 现网/确认方式 | 用例 |
|---|---|---|---|---|
| v9 header/template/data | RFC 3954 §5、§7 | design §1、§3.1、D-CFLOW-1/2 | Cisco IOS NetFlow v9 抓包；未取得前标待确认 | 1–7、15 |
| IPFIX message/template/options/data | RFC 7011 §3、§7、§8 | design §3.2、D-CFLOW-3/8 | libfixbuf exporter 抓包；未取得前标待确认 | 8–14 |
| 错误/载体/白名单 | RFC 3954 §5、RFC 7011 §3；CORE §1.11–1.13 | design §5、D-CFLOW-8 | MCP task error 实跑；当前仅有代码锚词证据 | 16–27 |

缺少真实 exporter/NIC 证据的行明确待确认；确认方式是指定版本软件导出固定 template/data 后走 PCAP 与 NIC 两路。

### T2 测试点清单先行与缺口矩阵

| 规范条文/要求 | 业务场景 | 代码分支 | 用例/缺口 |
|---|---|---|---|
| RFC 3954 header/count/template/data | v9 单/多 record、IPv4/IPv6 | `builder.go` v9 header/template/data | 1、2、5；D-CFLOW-2 |
| RFC 7011 length/Set/OD | IPFIX template/data、multi-OD | `builder.go` IPFIX message/set | 8、9、12、14；D-CFLOW-3/7 |
| RFC 7011 enterprise/variable/options | PEN、65535、timeout | IPFIX template/options branches | 10、11、13；D-CFLOW-4/5/8 |
| RFC 3954/7011 invalid inputs | version/template/length/field/address/checksum | `ValidateConfig`/`BuildExportPacket` | 16–22；D-CFLOW-8（任务错误传播待实跑） |
| CORE §1.11–1.13 | top-level presence/count、TCP/missing UDP/unknown field | `CheckProtoFlat`、layer validator/strict decode | 23–27；静态形状已覆盖 |
| CORE §12 | fixed/inc/rand/list/pattern × 四元组/业务字段 | 当前 cflow 没有动态解析分支 | D-CFLOW-9；不得伪造覆盖 |

清单来源是 RFC/CORE 要求反推，而非从既有 ID 倒推；每一行都有用例或缺口编号。

### T3 颗粒度、场景类别与强度

每条 ID 只有一个主行为断言；组合例只组合同一观察面。数据场景覆盖版本、地址族、长度、IE、PEN、空模板和错误 wire fault；业务场景覆盖多 record、multi-exporter、multi-session、template→data；现网场景覆盖默认 UDP 2055/4739、Cisco/libfixbuf 行为映射（待真实抓包确认）。强度按枚举逐值、正交矩阵（profile×地址族×单/多 exporter/session）、动态整格（五策略全部登记为 D-CFLOW-9 缺口）和断言边界（packet_count、distinct、nonzero、offset/frame prefix）执行。

### T4 §3.15 三项

cflow 是无连接 UDP datagram 协议，不存在同连接多轮、非正常连接结束、长保活；三项作为设计边界豁免登记，而不是伪造覆盖。可映射边界已覆盖：template→data（1、8、13）、多 exporter/session（6、7、14）、非法输入中断（16–27）。若未来新增 TCP/SCTP/TLS profile，必须新增五件套与对应三例。

### T5 存量逐条去向

原历史 22 个 v9/IPFIX 例逐条合入当前 1–22；新增 23–27 为严格层链守门负例，不是旧正例改名；历史 `trafficgen/docs/protocol-pcap-test/cflow.md` 的 22 例仅作为来源记录，未把历史执行结果冒充当前证据。无用例作废；原因、ID、去向均与 §2 和 JSON 顺序一致。

### T6 失败路径与可执行断言

16–22 每类 wire/profile 错误均要求 `expect_error` 加稳定锚词；23–27 分别验证 presence、carrier、count、unknown-field 拒绝。负例 `expect` 恰好只有 `expect_error`、`error_contains`，没有成功 PCAP 断言。代码静态证据显示 `planner.go:72-96` 某些 Build error 当前在 goroutine 内直接 return，尚不能证明 suite 会得到 task error；因此 D-CFLOW-8 是阻塞缺口，不能把 completed/0 packet 视为通过。执行时必须通过 MCP 建任务→生成 PCAP/网卡输出→tshark/终态核对，失败必须真红。

## 8. T1–T6 与 C1–C6 结论

| 编号 | 静态闭环结论 | 证据或缺口 |
|---|---|---|
| T1 | 规范、设计、实现、cases 四向回指；v9 1–7/15、IPFIX 8–14、错误 16–27 均有去向 | RFC 3954/RFC 7011；设计 D1–D8；registry/translate；现网 exporter 抓包待确认 |
| T2 | 测试点先行覆盖 header、set/template、record、地址族、OD/source、options、enterprise、变量长度、载体和失败分支 | JSON 1–27；动态五策略与 task error 为 D-CFLOW-9/D-CFLOW-8 缺口 |
| T3 | 每例主断言不可再分；正例含 packet_count+fields+frames，负例仅双键；复合面由多 record/exporter/session 表达 | JSON 实际结构；不宣称并发交错已运行 |
| T4 | 无连接 UDP 不适用同连接多轮、非正常结束、长保活；template→data、multi exporter/session、非法中断已登记 | 设计 §11、D-CFLOW-10；不以空白冒充覆盖 |
| T5 | 历史 22 例合入 1–22；23–27 是新增严格层链守门负例；历史文档结果不当作当前证据 | JSON ID 顺序与设计 §4 一致 |
| T6 | 12 个负例 expect 键集合严格为 `expect_error,error_contains`，锚词非空；7 类 wire/profile 错误及 5 类层链拒绝均覆盖 | 静态闭环；真实 task error 仍待 D-CFLOW-8 |
| C1 | JSON 语法、27 个 ID 唯一、顺序与两份文档一致 | 绿（已用 `json.tool` 与静态脚本复核） |
| C2 | 15 正例严格 `[ip,udp,cflow]`，无顶层业务键 | registry/translate 提供字段承载依据 |
| C3 | 地址住 ip、端口住 udp、业务住 cflow；presence 负例保留双键 | 25 标准形；`layers+cflow` 与 `layers+count` 仅故意负例 |
| C4 | 12 负例 expect 仅双键且锚词非空 | 静态结构满足，执行真红待 D-CFLOW-8 |
| C5 | v9/IPFIX、IPv4/IPv6、模板/数据、options、PEN、变量长度、多 exporter/session、边界、载体均有原子例 | 1–27 对账；性能/第三源/NIC 未宣称 |
| C6 | 修改面严格为 design/testcase/cflow.json | 不改 Go、其他文档、索引；不运行 suite/MCP/NIC |


总计 27 例，正 15、负 12；ID 顺序与 JSON 完全一致。spec_json 顶层形状为 `layers` 25 例、`layers+cflow` 1 个故意 presence 负例、`layers+count` 1 个故意游离键负例；层链形状为 `[ip,udp,cflow]` 25、`[ip,tcp,cflow]` 1、`[ip,cflow]` 1。15 个正例顶层白名单游离键为 0；12 个负例 expect 键集合全部恰为 `expect_error,error_contains`。registry 在 `registry.go:1402-1421` 有 cflow 15 字段，translate 在 `chain_planner_translate.go:3255-3287` 有严格解码 case；因此正例层链字段有住处，动态策略与 task error 传播仍按 D-CFLOW-8/9 立项。

## 9. 修订记录

- v1.1.0（2026-09-30）：按 CORE 对齐严格层链；对账 JSON 实测 27 例（15 正 + 12 负），补齐顶层白名单、carrier、未知字段与负例去向。
- v1.1.1（2026-10-01）：按实现证据区分代码路径与未运行的端到端验证；§3.15 三项按无连接协议豁免登记。
- v1.1.2（2026-10-01）：补三源回指、原子测试点、存量逐条去向、精确 layer/顶层/negative-expect 审计及 C1–C6；纠正 22 例历史产物不等于当前 27 例执行证据。
- v1.1.3（2026-10-01）：第二轮静态自审复核 27 个 ID 与 JSON 同序、15/12 分类、正例层链与负例 expect 形状；未新增实现或执行声明。

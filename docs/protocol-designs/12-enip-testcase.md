# ENIP（EtherNet/IP）测试用例契约

> 版本：v1.0.1（2026-09-27，P4–P6 交付回写；v1.0.0 = P3 产物）
> 日期：2026-09-26（v1.0.0）/ 2026-09-27（v1.0.1 回写）
> 配套设计：`docs/protocol-designs/12-enip-design.md` v2.1.1（§7 测试用例表为 T 号权威，§11.3/§11.4 为 P1–P3 与交付回写，§12–§17 为 P1–P3 产物 + P6 回填；A′/B′/9.52 两行互见设计 §16.3/§16.4）
> 机器契约：`trafficgen/test/protocol_pcap/cases/enip.json`（交付 **137** 例 = 82 正 + 55 负；P3 审计基线 135 见 §5；P1–P3 门1表与自重审结论见 `/tmp/pipe/56-enip/p123-report.md`）
> 状态：`enip` 层**已注册并入链**（六键 Fields，registry.go:229-240，P4）；链级生成器**已落地**（internal/protocol/enip/layer_gen.go，P4a）；legacy planner 保留。**去扁平改写已完成**（P5）——137 例 `layers` 必备（81 正例顶层键集唯一；复合用例另带框架键 `group_id`；唯一顶层协议子映射为 presence 判死负例 `enip_neg_presence`）。lane6 MCP suite **137/137**、离线链套件（CHAIN_PROTO=enip）**137/137**。

## 1. 测试原则、载体口径与现状边界

1. 用例从设计 §2–§4（规范面）、§8（Validate 规则）、§9（错误处理）、§12（动态字段）逐项派生，并回指 `12-enip-design.md` §7 的 T 号（三源：ODVA 规范 / D-ENIP-1 / 现网与解析器实测，见 §6.3）。
2. 载体固定 **TCP 44818**（`enip` 层 `DependsOn ["tcp"]`，registry.go:229-240；`FieldContract{"tcp.dst_port":"44818"}` 供缺省）；无 VLAN/IP options/TCP options 时 ENIP 起点 offset = `14+20+20 = 54`（现状 frames 全部按 54 钉）。
3. 字节序全 **little-endian**（ENIP 头/CPF/CIP）；Sockaddr Info 的 SinPort/SinAddr 按 OpENer 平台 LE 写入并标注可配置（设计 §2.4.2/R9）。
4. 断言通道：`enip.*` tshark 字段（口径 `tshark -G fields | awk -F'\t' '$3 ~ /^enip\./'` = **99 字段**，本机 TShark 3.6.14）+ CIP 内层与结构面走 `frames` hex（**交付 78 例**带 frames）+ 载体 `tcp.dstport`/`tcp.srcport`/`tcp.flags`。交付 137 例共用 **8 个**断言字段：`enip.command`42 / `enip.length`32 / `tcp.srcport`15 / `enip.session`12 / `enip.status`6 / `enip.cpf.itemcount`4 / `tcp.flags`4 / `tcp.dstport`2（脚本普查；legacy 期的 11 字段口径见 §5 历史审计）。
5. 动态面断言用 `presence` / `nonzero` / `distinct` / `same_as_packet`。**交付现状**：四元组动态对象 **1 例**（`enip_t180_multiflow_txn_error_branch` 的 `tcp.src_port` inc 对象 `{\"strategy\":\"inc\",\"range\":[12345,12346],\"step\":1}`，兼作 12.9 静态复制门逃生口（静态标量四元组 + flows>1 会被 `checkLayerChainStaticCopy`（schema/semantic.go:198）判死；worker 保底递增见 worker.go:307-309，层动态覆盖见 :311-316）；`distinct_values` 聚合端口断言 2 条（同例，聚端口断言按 14.13 分侧：`distinct_exclude` 排对侧端口）；业务字段（命令/会话/连接身份）动态**未开** → G-ENIP-4；`session_handle` 的 inc/rand 形为拒绝负例（T-090/T-091）。四元组动态住 `ip`/`tcp` 层（设计 §14.12）。
6. 负例执行期 `expect` 键集合严格为 `{expect_error, error_contains}`（另有 `notes` 为 runner 注释键，非断言键）；交付 **55 例锚词 40 种不同值**（§4 逐条）。
7. **拓扑缺口（诚实声明）**：地址族仅 IPv4（82/82 正例，`10.0.0.1`→`20.0.0.1`）；链上层内多单元展开（`session_count/flow_count>1`）与 UDP I/O 面仍判死（生成器 layer_gen.go:56-71 + 同步预检 validate_layers.go:550-587 双路闭合；G-ENIP-1/2）；**framework 多流面已补 1 例**（flows=2 复制流）；IPv6 零例（A′，§6.2）。


## 2. T-ENIP 目标清单（232 个 T 号 × 现状落地）

设计 §7 共列 **232 个 T 号**（T-001~T-220 + T-120a/b/c + T-133a~d + T-200a~e）。用例文件按 id 命中 **111 个**（v1.0.0 基线 110 → P6 复合用例 `enip_t180_multiflow_txn_error_branch` 落 T-180），另 **25 例**为非 T 命名（summary 引用 22 个 T 号，全部 ⊂ 未落地集合，属**部分语义覆盖**）。逐段对账（脚本实测）：

| 段 | 设计条目数 | 现状落地（按用例 id） | 缺口 | 缺口清单去向 |
|---|---:|---:|---:|---|
| §7.2 正向 | 80 | 15 | **65** | §6.2 A′（P5 casegen；其中 22 号有非 T 例部分覆盖） |
| §7.3 负向 | 43 | 42 | **1**（T-120c） | §4 末（负例补齐） |
| §7.4 边界 | 44 | 34 | **10**（含 T-122/T-123/T-126/T-128/T-159 等） | §6.2 A′ |
| §7.5 多会话/多流 | 20 | **16**（+T-180） | **4**（T-163/T-168/T-171/T-178） | §6.2 A′ + B′ G-ENIP-1 |
| §7.6 集成 | 25 | 1（T-199） | **24**（T-181~T-198 tshark 面 + T-200/T-200a~e 互操作） | §6.2 A′（互操作面含 G-ENIP-5 确认项） |
| §7.7 修订追加 | 20 | 3（T-217/218/219） | **17** | §6.2 A′ |
| **合计** | **232** | **111** | **121** | — |

**注 1**：T 号 `T-090/T-091`（`session_handle` inc/rand 策略拒绝）现状为**负例**，与设计 §7.3 归类不同——已按 `expect_error` 归入负例段（§4 已按现状登记）。
**注 2**：`T-074/T-128`（SequenceCounter 回绕）由 `enip_seq_wraparound_3_frames`（summary 引 T-074/128）承载，按 id 未命中，本文按「未落地」计（该例链上被 `io_data` 预检拒，属 G-ENIP-2 面）。
**注 3**：T-143（ItemCount=1 用户项）现状被**接受**并断言 totals=3，与设计 §8.2 V-105（≥2）字面冲突（用例 summary 已诚实声明 impl allows）——**仍未决**，三选一（改实现 / 改契约 / 立项）挂 A′（§6.2）。
**注 4**：T-180 的落地形式是 **framework 多流**（`strategy_fc flows=2` → 两条独立 TCP 会话各 4 包挥手；其余 136 例 = 122 例缺省单流 + 14 例显式 `strategy_fc flows=1`），非 `SessionCount=2` 的层内多单元展开（后者链上仍拒，G-ENIP-1）；同例同时承载 T-179（多流并发时序不交叉：每流 3 命令有序）与 T-217（Status=0x0064 的 `enip.status` 字段 + `64 00 00 00` frames 字节双钉；T-217 本体另有 `enip.status` 字段断言在案）语义。


## 3. 正例断言契约（按段，含未落地的断言要求）

1. **§7.2 正向（现状 15 例 + 25 非 T 例）**：断言 `enip.command`/`enip.length`/`enip.session` + frames 钉结构。已落地代表：`enip_nop_heartbeat`（0x0000 + Length=4 + payload `DE AD BE EF`）、`enip_forward_open_request`（0x006F + CIP 0x54 + `o2t_rpi=100000` + conn params=512）、`enip_multiple_service_packet`（MSP 0x0A，offsets 6/14，Length=44）、`enip_large_forward_open`（0x5B，Length=70）。未落地 65 号中最关键：CIP 服务码余值（0x02/08/09/0D/11/15/16/17/18-1D/56/57/5A）、PCCC 0x4B、Logix 0x4C/0x4D/0x52/0x55（断言 `enip.length` + CIP service 字节）、Identity 属性 8/9/10 读取面。
2. **§7.3 负向**：见 §4（55 例锚词表）；未落地的 T-120c（Forward_Open O2TConnID=0 → 允许但警告，非拒绝）须断言**不报错** + 响应回读分配值。
3. **§7.4 边界（现状 34 例）**：断言 `enip.length` 边界（T-121 已落地：0）、`SessionHandle` 0/0xFFFFFFFF（T-124/T-125 已落地）、EPATH 8/16-bit 与 Connection Point（T-132/T-133a~d 已落地）、路径补齐（T-155/T-156 已落地）、ProductName 空/255（T-157/T-158 已落地）。未落地：T-122（Length=65515，断言 `EB FF`）、T-123（65516 → 拒绝）、T-126（SenderContext 全 0）、T-128（0xFFFF 回绕）、T-159（ProductName 256B → 拒绝）。
4. **§7.5 多会话/多流（交付 16 例）**：B 类 12 例已改写为**单单元等价例**（`flows=1`；`+u`/`+2u` 派生在 u=0 恒等，字节与 legacy 对齐；notes 逐例披露 G-ENIP-1），断言独立 SessionHandle / ConnSerialNum / ConnectionID / SenderContext 起点；**新增复合用例 1 例**（`enip_t180_multiflow_txn_error_branch`）= framework `flows=2` 两条独立会话（src_port 12345/12346 动态对象 + 顶层框架键 `group_id` 固定同 shard 使包位确定，流 0 = 包 1-10，流 1 = 包 11-20）+ 会话内 3 命令多事务 + down 异常分支，断言 20 个字段点 + 4 段 frames（含每流独立 FIN 与 Status=0x0064 字节面）。未落地 4 号（T-163/T-168/T-171/T-178）属多单元/多设备迁移面（G-ENIP-1）。
5. **§7.6 集成（现状 1 例 T-199）**：tshark 解析面（T-181~T-198）与 OpENer 互操作（T-200a~e）未落地 → A′ 补；互操作的期望值须先过 G-ENIP-5（现网/EDS 核对）。
6. **§7.7 修订追加（现状 3 例：T-217/218/219）**：ENIP Status 0x0064/0x0065/0x0069 的 `enip.status` 断言已落地（复合用例另以 frames 钉 `64 00 00 00` 字节形）；未落地 17 号覆盖 CIP 服务码/EPATH 段面（T-201~T-216、T-220），断言 = CIP 首字节 + frames。


## 4. 负例契约（交付 55 例锚词原文）

每个负例必须在 planner/validator 失败并传播为 task error；不得输出成功 pcap、`completed/0 packet` 或只有 TCP 外壳的假成功。`expect` 键集合严格 `{expect_error, error_contains}`（+ `notes` 注释键）。**交付 55 例锚词原文如下（40 种不同值；按 cases 文件顺序）**：

> **重锚说明（P5–P6 实测，与 v1.0.0 原表差异）**：① `enip_t104_class_id_out_of_range`/`enip_t105_instance_id_out_of_range` 链上由**严格解码**先拒（`cannot unmarshal number 65536` / `4294967296`），原 `class_id out of range` 文案只在顶层旧形可达；② `enip_t108/t109/t110` 由**同步预检** `io_data` 先拒（三条 IOData 专属校验分支随 G-ENIP-2 落地后重校准）；③ `enip_t117/t118` 为 **worker 通用 0 包锚**（`planner produced 0 packet configs`）——根因 `validateFromResponseConfig` 只在 drive 期跑（G-ENIP-8），notes 已逐例披露；④ `enip_v006` 重锚为 `multi-unit expansion`（预检），`enip_v005` 保留 `session_count -1 out of range`（负值段不被预检拦）。
> **未决对账项（诚实登记）**：`enip_t086/t087` 的锚词为整句原文（`SendRRData requires at least 2 CPF items, a cip_service, or a payload`），与 14.11「短锚词」口径不符；锚词逐字来自真实终态（非假绿），收敛为短锚词属 A′ 对账（§6.2）。

| # | 用例 id | 交付 `error_contains` |
|---|---|---|
| 1 | `enip_io_connection_udp_full_chain` | `io_data` |
| 2 | `enip_seq_wraparound_3_frames` | `io_data` |
| 3 | `enip_t081_unknown_command` | `unknown command 0x1234` |
| 4 | `enip_t082_registersession_cpf` | `RegisterSession must not carry CPF` |
| 5 | `enip_t083_registersession_pv0` | `protocol_version must be 1, got 0` |
| 6 | `enip_t120b_registersession_pv2` | `protocol_version must be 1, got 2` |
| 7 | `enip_t084_registersession_optionflag` | `option_flag must be 0` |
| 8 | `enip_t086_sendrrdata_nocpf` | `SendRRData requires at least 2 CPF items, a cip_service, or a payload` |
| 9 | `enip_t087_sendrrdata_itemcount1_noservice` | `SendRRData requires at least 2 CPF items, a cip_service, or a payload` |
| 10 | `enip_t088_sendunitdata_noaddr` | `SendUnitData requires Connection Address item` |
| 11 | `enip_t089_sendunitdata_nodata` | `SendUnitData requires Connected Data item` |
| 12 | `enip_t093_forwardopen_noconnserial` | `connection_serial_number required for Forward_Open` |
| 13 | `enip_t094_forwardopen_novendor` | `originator_vendor_id required for Forward_Open` |
| 14 | `enip_t095_forwardopen_noorigserial` | `originator_serial_number required for Forward_Open` |
| 15 | `enip_t096_forwardopen_class5` | `invalid transport class 5 (must be 0-3)` |
| 16 | `enip_t112_forwardopen_class15` | `invalid transport class 15 (must be 0-3)` |
| 17 | `enip_t097_forwardopen_rpi0` | `RPI must be > 0` |
| 18 | `enip_t098_forwardopen_reservedbit` | `reserved bit (bit 12) in o2t_connection_parameters must be 0` |
| 19 | `enip_t099_forwardclose_notriad` | `Forward_Close requires connection_serial_number` |
| 20 | `enip_t100_listidentity_cpf` | `ListIdentity request must not carry CPF` |
| 21 | `enip_t101_listservices_cpf` | `ListServices request must not carry CPF` |
| 22 | `enip_t102_listinterfaces_cpf` | `ListInterfaces request must not carry CPF` |
| 23 | `enip_t103_unregistersession_payload` | `UnRegisterSession must not carry payload or CPF` |
| 24 | `enip_t106_msp_nosubrequests` | `Multiple_Service_Packet requires sub_requests` |
| 25 | `enip_t107_msp_65subs` | `sub_requests exceeds limit of 64` |
| 26 | `enip_t108_io_framesize_65466` | `io_data` |
| 27 | `enip_t109_io_framecount0` | `io_data` |
| 28 | `enip_t110_io_noconnid` | `io_data` |
| 29 | `enip_t111_timeoutmult8` | `timeout_multiplier must be 0-7, got 8` |
| 30 | `enip_t113_unknown_scenario` | `enip: unknown scenario "unknown"` |
| 31 | `enip_t114_unknown_transport` | `enip: transport must be tcp or udp, got "icmp"` |
| 32 | `enip_t115_dstport_502` | `enip: dst_port must be 44818` |
| 33 | `enip_t116_unknown_typeid` | `unknown type_id 0x9999` |
| 34 | `enip_t117_source_cmd_index_99` | `planner produced 0 packet configs` |
| 35 | `enip_t118_unknown_fromresp_field` | `planner produced 0 packet configs` |
| 36 | `enip_t119_sockaddr_len15` | `Sockaddr Info length must be 16` |
| 37 | `enip_t120a_forwardclose_path_mismatch` | `Forward_Close connection path` |
| 38 | `enip_t129_seq_start_7fff` | `io_data` |
| 39 | `enip_t130_seq_step2` | `io_data` |
| 40 | `enip_t141_io_framesize0` | `io_data` |
| 41 | `enip_t142_io_framesize_max` | `io_data` |
| 42 | `enip_t073_seq_10_frames` | `io_data` |
| 43 | `enip_t085_registersession_payload5` | `payload must be 4 bytes` |
| 44 | `enip_t090_sessionhandle_strategy_inc` | `session_handle strategy must be fixed or from_response` |
| 45 | `enip_t091_sessionhandle_strategy_rand` | `session_handle strategy must be fixed or from_response` |
| 46 | `enip_t092_sendrrdata_cipservice0` | `cip_service required for SendRRData with Unconnected Data` |
| 47 | `enip_t104_class_id_out_of_range` | `cannot unmarshal number 65536` |
| 48 | `enip_t105_instance_id_out_of_range` | `cannot unmarshal number 4294967296` |
| 49 | `enip_t120_connpathsize_mismatch` | `connection_path_size mismatch` |
| 50 | `enip_t166_2session2flow_io` | `io_data` |
| 51 | `enip_t167_multiflow_seq_from_1` | `io_data` |
| 52 | `enip_t170_multiflow_udp_shared_tuple` | `io_data` |
| 53 | `enip_v005_session_count_negative` | `session_count -1 out of range` |
| 54 | `enip_v006_flow_count_negative` | `multi-unit expansion` |
| 55 | `enip_neg_presence` | `rejects a top-level enip` |

## 5. 存量 135 例逐条审计去向（§9.14；P3 审计基线，下表 135 行止于 P3 基线）

**执行状态（v1.0.1）**：下表为 P3 对 legacy 135 例的逐条去向审计（135 行，与现文件前 135 行**同序**，逐行机核一致），**已由 P5 按表执行完毕**（提交 `adfeb76`），四类去向与实际改写一一对应；下表之后净增 2 行：`enip_neg_presence`（P4，presence 判死，文件第 136 行）+ `enip_t180_multiflow_txn_error_branch`（P6，复合用例，文件第 137 行）= 交付 **137 例**。下表保留 P3 原始审计口径（含 legacy 期 86 例 frames / 11 字段统计），交付实测统计见 §1.4。

口径：`spec_json.layers` 非空 → A 类；旧扁平正例按 `spec_json.enip.io_data` 是否非空二分（B 无 io_data 的多单元 TCP 面 12 例 / C 含 io_data 的 UDP I/O 面 10 例）；负例全归 D。四类互斥穷尽：**69 + 12 + 10 + 44 = 135**。

% A 69：删顶层 `src_ip/dst_ip/src_port/dst_port` + 顶层 `enip` 子映射（18 例另删顶层 `tcp` 子映射），命令数组迁 `layers[i].enip`（依赖 G-ENIP-3）。
% B 12：改写为 `flow_control.flows=1` 单单元等价例（`+u`/`+2u` 派生在 u=0 恒等，可与 legacy 字节对齐）。
% C 10：链上不可达（生成器 layer_gen.go:56-64 拒绝）→ 以现状钉 + G-ENIP-2 注记，不删用例（§9.36）。
% D 44：改层链形负例，锚词保留；`enip_v005`/`enip_v006` 两例随 `session_count`/`flow_count` 迁层重锚。


| # | 用例 id | 正/负 | T 段（设计 §7） | 现状形状 | 面标记 | 审计去向 |
|---|---|---|---|---|---|---|
| 1 | `enip_nop_heartbeat` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 2 | `enip_listidentity_session_lifecycle` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 3 | `enip_registersession_session_state` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 4 | `enip_sendrrdata_get_attribute_single` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 5 | `enip_forward_open_request` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 6 | `enip_get_attributes_all` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 7 | `enip_set_attribute_single` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 8 | `enip_get_attribute_list` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 9 | `enip_multiple_service_packet` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 10 | `enip_large_forward_open` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 11 | `enip_forward_close_triad` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 12 | `enip_io_connection_udp_full_chain` | 正 | S/T 场景（非 T 号） | 旧扁平 `layers=[]` | io_data | C 作废重做（UDP I/O 面 → G-ENIP-2） |
| 13 | `enip_error_response_status` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 14 | `enip_forward_open_response_full` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 15 | `enip_listidentity_response` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 16 | `enip_epath_16bit_class` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 17 | `enip_epath_16bit_instance` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 18 | `enip_epath_16bit_attribute` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 19 | `enip_seq_wraparound_3_frames` | 正 | S/T 场景（非 T 号） | 旧扁平 `layers=[]` | io_data/transport=udp | C 作废重做（UDP I/O 面 → G-ENIP-2） |
| 20 | `enip_forward_close_response` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 21 | `enip_reset_service` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 22 | `enip_start_service` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 23 | `enip_stop_service` | 正 | S/T 场景（非 T 号） | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 24 | `enip_t081_unknown_command` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 25 | `enip_t082_registersession_cpf` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 26 | `enip_t083_registersession_pv0` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 27 | `enip_t120b_registersession_pv2` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 28 | `enip_t084_registersession_optionflag` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 29 | `enip_t086_sendrrdata_nocpf` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 30 | `enip_t143_sendrrdata_itemcount1` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 31 | `enip_t087_sendrrdata_itemcount1_noservice` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 32 | `enip_t088_sendunitdata_noaddr` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 33 | `enip_t089_sendunitdata_nodata` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 34 | `enip_t093_forwardopen_noconnserial` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 35 | `enip_t094_forwardopen_novendor` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 36 | `enip_t095_forwardopen_noorigserial` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 37 | `enip_t096_forwardopen_class5` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 38 | `enip_t112_forwardopen_class15` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 39 | `enip_t097_forwardopen_rpi0` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 40 | `enip_t098_forwardopen_reservedbit` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 41 | `enip_t099_forwardclose_notriad` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 42 | `enip_t100_listidentity_cpf` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 43 | `enip_t101_listservices_cpf` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 44 | `enip_t102_listinterfaces_cpf` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 45 | `enip_t103_unregistersession_payload` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 46 | `enip_t106_msp_nosubrequests` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 47 | `enip_t107_msp_65subs` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 48 | `enip_t108_io_framesize_65466` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | io_data | D 负例改写（锚词保留） |
| 49 | `enip_t109_io_framecount0` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | io_data | D 负例改写（锚词保留） |
| 50 | `enip_t110_io_noconnid` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | io_data | D 负例改写（锚词保留） |
| 51 | `enip_t111_timeoutmult8` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 52 | `enip_t113_unknown_scenario` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 53 | `enip_t114_unknown_transport` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 54 | `enip_t115_dstport_502` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 55 | `enip_t116_unknown_typeid` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 56 | `enip_t117_source_cmd_index_99` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 57 | `enip_t118_unknown_fromresp_field` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 58 | `enip_t119_sockaddr_len15` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 59 | `enip_t120a_forwardclose_path_mismatch` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 60 | `enip_t121_nop_length0` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 61 | `enip_t124_sessionhandle_max` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 62 | `enip_t125_sessionhandle_zero` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 63 | `enip_t127_sendercontext_max` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 64 | `enip_t129_seq_start_7fff` | 正 | §7.4 边界 | 旧扁平 `layers=[]` | io_data/transport=udp | C 作废重做（UDP I/O 面 → G-ENIP-2） |
| 65 | `enip_t130_seq_step2` | 正 | §7.4 边界 | 旧扁平 `layers=[]` | io_data/transport=udp | C 作废重做（UDP I/O 面 → G-ENIP-2） |
| 66 | `enip_t131_epath_class8_max` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 67 | `enip_t132_epath_class16_min` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 68 | `enip_t133_epath_instance32` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 69 | `enip_t133a_epath_class32_raw` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 70 | `enip_t133b_epath_attr32_raw` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 71 | `enip_t133c_epath_connpoint8` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 72 | `enip_t133d_epath_connpoint16` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 73 | `enip_t134_rpi_min` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 74 | `enip_t135_rpi_max` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 75 | `enip_t136_connparams_6dff` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 76 | `enip_t137_large_connparams_max` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 77 | `enip_t139_pathsize255` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 78 | `enip_t140_msp_offset_boundary` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 79 | `enip_t141_io_framesize0` | 正 | §7.4 边界 | 旧扁平 `layers=[]` | io_data/transport=udp | C 作废重做（UDP I/O 面 → G-ENIP-2） |
| 80 | `enip_t142_io_framesize_max` | 正 | §7.4 边界 | 旧扁平 `layers=[]` | io_data/transport=udp | C 作废重做（UDP I/O 面 → G-ENIP-2） |
| 81 | `enip_t144_itemcount4_sockaddr` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 82 | `enip_t145_sockaddr_port_max` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 83 | `enip_t146_sockaddr_ip_max` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 84 | `enip_t147_timeout0` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 85 | `enip_t148_timeout_max` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 86 | `enip_t149_ifhandle_nonzero` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 87 | `enip_t151_addstatus_255words` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 88 | `enip_t155_epath_odd_pad` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 89 | `enip_t156_epath_even` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 90 | `enip_t160_vendorid_max` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 91 | `enip_t003_listservices` | 正 | §7.2 正向 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 92 | `enip_t010_listinterfaces` | 正 | §7.2 正向 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 93 | `enip_t014_registersession_nocpf` | 正 | §7.2 正向 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 94 | `enip_t027_set_attribute_list` | 正 | §7.2 正向 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 95 | `enip_t063_large_forward_open_response` | 正 | §7.2 正向 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 96 | `enip_t064_nop_no_response` | 正 | §7.2 正向 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 97 | `enip_t066_identity_attr1` | 正 | §7.2 正向 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 98 | `enip_t067_identity_attr6` | 正 | §7.2 正向 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 99 | `enip_t068_tcpip_attr1` | 正 | §7.2 正向 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 100 | `enip_t069_ethlink_attr3` | 正 | §7.2 正向 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 101 | `enip_t070_sendercontext_echo` | 正 | §7.2 正向 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 102 | `enip_t073_seq_10_frames` | 正 | §7.2 正向 | 旧扁平 `layers=[]` | io_data/transport=udp | C 作废重做（UDP I/O 面 → G-ENIP-2） |
| 103 | `enip_t075_epath_class8` | 正 | §7.2 正向 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 104 | `enip_t077_epath_instance8` | 正 | §7.2 正向 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 105 | `enip_t079_epath_attr8` | 正 | §7.2 正向 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 106 | `enip_t217_status_0064` | 正 | §7.7 修订追加 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 107 | `enip_t218_status_0065` | 正 | §7.7 修订追加 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 108 | `enip_t219_status_0069` | 正 | §7.7 修订追加 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 109 | `enip_t199_scenario_full` | 正 | §7.6 集成 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 110 | `enip_t157_productname_empty` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 111 | `enip_t158_productname_255` | 正 | §7.4 边界 | 层链 `[tcp,enip]` | 单单元 | A 合入（删顶层旧键+子映射，命令迁 enip 层） |
| 112 | `enip_t085_registersession_payload5` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 113 | `enip_t090_sessionhandle_strategy_inc` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 114 | `enip_t091_sessionhandle_strategy_rand` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 115 | `enip_t092_sendrrdata_cipservice0` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 116 | `enip_t104_class_id_out_of_range` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 117 | `enip_t105_instance_id_out_of_range` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 118 | `enip_t120_connpathsize_mismatch` | 负 | §7.3 负向 | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 119 | `enip_t161_sessioncount2_senderctx` | 正 | §7.5 多会话/多流 | 旧扁平 `layers=[]` | 多单元 2×1 | B 重构（单单元等价例 → flows=1） |
| 120 | `enip_t162_sessioncount8_handles` | 正 | §7.5 多会话/多流 | 旧扁平 `layers=[]` | 多单元 8×1 | B 重构（单单元等价例 → flows=1） |
| 121 | `enip_t164_flowcount2_forwardopen` | 正 | §7.5 多会话/多流 | 旧扁平 `layers=[]` | 多单元 1×2 | B 重构（单单元等价例 → flows=1） |
| 122 | `enip_t165_flowcount8_connids` | 正 | §7.5 多会话/多流 | 旧扁平 `layers=[]` | 多单元 1×8 | B 重构（单单元等价例 → flows=1） |
| 123 | `enip_t166_2session2flow_io` | 正 | §7.5 多会话/多流 | 旧扁平 `layers=[]` | io_data/多单元 2×2 | C 作废重做（UDP I/O 面 → G-ENIP-2） |
| 124 | `enip_t167_multiflow_seq_from_1` | 正 | §7.5 多会话/多流 | 旧扁平 `layers=[]` | io_data/多单元 1×2 | C 作废重做（UDP I/O 面 → G-ENIP-2） |
| 125 | `enip_t169_multisession_tcp_tuples` | 正 | §7.5 多会话/多流 | 旧扁平 `layers=[]` | 多单元 2×1 | B 重构（单单元等价例 → flows=1） |
| 126 | `enip_t170_multiflow_udp_shared_tuple` | 正 | §7.5 多会话/多流 | 旧扁平 `layers=[]` | io_data/多单元 1×2/transport=udp | C 作废重做（UDP I/O 面 → G-ENIP-2） |
| 127 | `enip_t172_fromresponse_session_isolated` | 正 | §7.5 多会话/多流 | 旧扁平 `layers=[]` | 多单元 2×1 | B 重构（单单元等价例 → flows=1） |
| 128 | `enip_t173_fromresponse_flow_isolated` | 正 | §7.5 多会话/多流 | 旧扁平 `layers=[]` | 多单元 1×2 | B 重构（单单元等价例 → flows=1） |
| 129 | `enip_t174_unregister_session_matched` | 正 | §7.5 多会话/多流 | 旧扁平 `layers=[]` | 多单元 2×1 | B 重构（单单元等价例 → flows=1） |
| 130 | `enip_t175_forward_close_serial_matched` | 正 | §7.5 多会话/多流 | 旧扁平 `layers=[]` | 多单元 1×2 | B 重构（单单元等价例 → flows=1） |
| 131 | `enip_t176_senderctx_global_inc` | 正 | §7.5 多会话/多流 | 旧扁平 `layers=[]` | 多单元 2×1 | B 重构（单单元等价例 → flows=1） |
| 132 | `enip_t177_senderctx_per_unit` | 正 | §7.5 多会话/多流 | 旧扁平 `layers=[]` | 多单元 1×2 | B 重构（单单元等价例 → flows=1） |
| 133 | `enip_t179_multiflow_order` | 正 | §7.5 多会话/多流 | 旧扁平 `layers=[]` | 多单元 1×2 | B 重构（单单元等价例 → flows=1） |
| 134 | `enip_v005_session_count_negative` | 负 | S/T 场景（非 T 号） | 旧扁平 `layers=[]` | 单单元 | D 负例改写（锚词保留） |
| 135 | `enip_v006_flow_count_negative` | 负 | S/T 场景（非 T 号） | 旧扁平 `layers=[]` | 多单元 1×101 | D 负例改写（锚词保留） |

## 6. 覆盖审计固定动作（§9.52 / §3.14 / §3.15）

### 6.1 §3.15 三项

| 项 | 现状 | 判定 |
|---|---|---|
| ① 同连接多轮操作 | `enip_listidentity_session_lifecycle`（发现→注册→注销）、`enip_registersession_session_state`、`enip_multiple_service_packet`（单 SendRRData 多子请求）、`enip_t180_multiflow_txn_error_branch`（同一流 3 命令有序 + 会话句柄回写） | 有例 ✅ |
| ② 非正常结束 | 错误响应（`enip_error_response_status` CIP 层；`enip_t180_...` ENIP Status=0x0064 down 错误响应 + `enip_t217/218/219`）、路径不一致判死（`enip_t120a_forwardclose_path_mismatch`）；**FIN/RST 中途断开 / 未 Close 即断 / 失效重连无例** | 半程 → G-ENIP-7 |
| ③ 长保活 | `enip_nop_heartbeat`（NOP，OpENer 不响应面与设计 §2.2 一致） | 有例 ✅ |

### 6.2 A′ / B′ 两分类

**A′（现有引擎可构建 → 补例）**：IPv6 面（`ip` 层 v6 字面量）1–2 例；CIP 服务码余 24 值逐值 ≥1 例；CM 扩展状态 20 值逐值 ≥1 例（现状 `additional_status` 键零出现）；CPF TypeID 0x000C/0x0100/0x8002 的 `type_id` 键面；未落地 T 号 **121** 个按段补齐；T-143（ItemCount=1）与设计 §8.2 V-105 的对账（改实现 / 改契约 / 立项三选一，**未决**）；`enip_t086/t087` 长锚词收敛为短锚词（14.11 口径）；非正常结束面（G-ENIP-7）。

**B′（引擎结构缺口 → D-ENIP-1「明确不解决 + 迁入计划」）**：G-ENIP-1 层内多单元展开（链一次一 flow；**framework 多流面已由 `enip_t180_...` 部分承接**）；G-ENIP-2 UDP I/O 面（链单载体）；G-ENIP-4 业务字段动态（enip 不在 `layerDynAllowlist`）；G-ENIP-8 `validateFromResponseConfig` 同步面并入（0 包锚的重校准前置）；超时/重传时间轴（无时钟语义，明确不解决）；NAT/代理中间盒（无面，明确不解决）；大端 Sockaddr（无第二形态证据，明确不解决）。（G-ENIP-3 已落地可核销。）

### 6.3 9.52 对账两行 + 清单出处 + 3.14 豁免审计 + 三源回指

- **行 1（规范逻辑点总数 vs 用例覆盖数）**：口径 = 设计 §2/§3/§4/§6/§8/§9 表格数据行（表头与 `---` 已剔除，脚本实测）——**规范逻辑点总数 = 317**（§2 163 + §3 52 + §4 14 + §6 15 + §8 55 + §9 18）；**用例覆盖数 = 137**（正 82 + 负 55；P3 基线 135）；**缺口** = 未落地 T 号 **121** 个 + §6.2 A′ 面。
- **行 2（清单出处声明）**：清单**不是**从现有用例或引擎能力反推（§9.48 禁止项），而是从 ODVA CIP Networks Library Vol.1/Vol.2（落点＝设计 §2–§4）+ Rockwell 官方出版物（ENET-AT002E-EN-P / ENET-UM006 / 技术支持文档 471230）+ 实现面（OpENer / libplctag）+ 解析器实测（tshark `enip.*` 99 字段）反推；逐条可与设计 §12 三子表、§13.2 映射表对应。
- **3.14 豁免边界审计（v1.0.1 修订）**：本协议**不豁免** sessions（同连接多轮有例）；**多流并发已有正例**（`enip_t180_multiflow_txn_error_branch`，framework flows=2 + 动态四元组；v1.0.0 原句「多流并发…各有例」当时仅指 legacy 多单元面，P5 改写后那批转为单单元等价例，该句已 stale——本版按交付实况修正）；单包多载荷有例（`enip_multiple_service_packet` MSP 2 子请求）——无豁免逃逸。
- **三源回指行**：每条用例的 `summary`/断言面须能回指 ①规范行（设计 §2–§4 或 §7 T 号）②D-ENIP-1 条目（设计 §15）③现网行为（设计 §13.2 映射表行）。

### 6.4 §9.49/§9.50/§9.53 复合大场景点数（v1.0.1 新增）

- **最复杂用例**：`enip_t180_multiflow_txn_error_branch` = 20 包 / **2 条 TCP 流** / 每流 **3 命令**有序序列 / 1 条 **down 异常分支**（ENIP Status=0x0064）/ 20 个字段断言 + 4 段 frames。
- **交织维度点数**：多流 ✓（flows=2，四元组独立 12345/12346）+ 多事务 ✓（会话内 3 命令）+ 异常分支 ✓（错误响应）⇒ **3 类**（≥ §9.50 下限）。
- **§9.49 真实编排项**：会话内多事务 ✓ + 并发/交错 ✓（两条流各自完整时序；`group_id` 固定使流序确定）= 2 项。
- 基线对照：v1.0.0 期最复杂例（`enip_listidentity_session_lifecycle`）仅 1 类交织，本用例为 P6 补齐项。


## 7. 三方一致性与静态检查（v1.0.1 交付实测）

1. 设计 §7（232 T 号）、本文 §2（逐段对账）、`cases/enip.json`（**137 例**）三方一致性：id 命中 **111** 号、缺口 **121** 号，差异已逐段登记（§2），孤儿引用 0（用例 id 内 T 号全 ⊂ 设计 §7）。
2. 静态检查：`python3 -m json.tool trafficgen/test/protocol_pcap/cases/enip.json` 通过；137 例 `proto` 全为 `enip`；55 负例 `expect` 键集合合规（`{expect_error, error_contains}` + `notes`）。
3. 去扁平门（pipe_gate 门2-1）：顶层旧键**绿**（无残留）；顶层协议子映射并存**黄 2 行**：`enip_neg_presence:顶层子映射+enip`（presence 判死执法对象，设计 §14-P2 在案）与 `enip_t180_...:顶层子映射+group_id`（框架键 `group_id` 非协议键，h323/smb 语料同形）；`_pres_key=enip` 红线**绿**（无顶层 enip presence 残留，presence 负例豁免）。
4. 二进制与 HEAD 同代、suite 全量全绿（14.18/14.19）：lane6 MCP `RESULT: 137 pass, 0 fail, 0 error (of 137)`；离线 `TestLayerChainSuite`（CHAIN_PROTO=enip）137/137；pcap 逐例落盘可复查（14.16）。


## 8. P5/P6 执行结果（v1.0.0 §8 动作清单的落地回写）

1. ✅ G-ENIP-3 已落（enip 层六键 Fields + 层翻译 + presence 判死），A 类 69 例完成去扁平。
2. ✅ 按 §5 表逐条改写：A 69 / B 12 / C 10 / D 44；改写全部**先跑后钉**重建 frames/包号（B 类包号 = legacy +3，握手 3 包；D 类按实测终态重锚）。
3. ⏳ §2 的 121 个 T 号未补齐（P3 计划的「优先补可构建部分」未执行，缺口按段保留在 §2/§6.2，属 A′ 后续）。
4. ⏳ IPv6、CM 扩展状态逐值、CIP 服务码余值、PCCC/Logix 方言面未补（§6.2 A′）；G-ENIP-5 现网核对未做。
5. ✅ `coverage_gate.py` 的 `check_enip` 块已落（P4；反查逐项绿）。
6. ✅ **P6 修轮新增**：复合大场景用例 `enip_t180_multiflow_txn_error_branch`（§6.4）——补 §9.49/§9.50 的多流与复合下限；5 例重锚用例 notes 与实钉锚对齐；G-ENIP-8 立项登记。


## 9. 修订记录

- v1.0.1（2026-09-27）：P4–P6 交付回写——用例 135 → **137**（82 正 + 55 负；+presence 判死负例 +复合大场景正例）；T 命中 110 → **111**（T-180 落地）/缺口 122 → **121**；§4 负例锚词表更新为交付实测 55 例 40 种锚词（含 5 例重锚说明与长锚词未决对账项）；§5 保留 P3 审计表并标注执行状态；§6.3 修正 v1.0.0「多流并发各有例」stale 表述（P5 后该批转单单元等价例，多流正例由复合用例承接）；新增 §6.4（§9.49/9.50/9.53 复合场景点数）与 §8 执行结果；§1/§7 统计按交付实测同步。**不改任何用例文件与 Go 代码**（本文为交付文本）。
- v1.0.0（2026-09-26）：P1–P3 产物。建立 T-ENIP 目标清单（232 T 号 × 现状 110 命中 / 122 缺口）、44 例负例锚词原文表、存量 135 例逐条审计去向（A69/B12/C10/D44）、A′/B′ 分类、9.52 对账两行（317 vs 135）、3.14 豁免审计与三源回指行；不改 `cases/enip.json`，不宣称 suite 可运行。


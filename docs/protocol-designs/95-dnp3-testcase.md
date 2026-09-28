# #95 dnp3（IEEE 1815-2012 DNP3 主站/外设）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3）
> 日期：2026-09-28
> 配套设计：`docs/protocol-designs/95-dnp3-design.md` v1.0.0（D-DNP3-1）
> 旧基线：`docs/protocol-designs/11-dnp3-design.md` v1.1.4（70 例语义来源）
> 机器契约：`trafficgen/test/protocol_pcap/cases/dnp3.json`（**70 例，本版保持原样未改**——层为空壳，见设计 §0.1 与本文件 §8）
> 白话一句：**这份文档分两层看：存量七十条检查今天跑在旧写法上（扁平过渡态，还没搬到新写法）；新写法要多少条、每条查什么，§2 列了目标清单，合规化属代码阶段。**
>
> **一句话口径（与 nvgre/rip/a2a 各车道一致）**：存量 70 例为**扁平过渡态**（顶层四元组 + 顶层 `dnp3` 子映射 + 空壳 `layers` 并存，判死形状）；**`cases/dnp3.json` 本版未改**（`git diff` vs 基线 = 0 行）；**合规化属代码阶段**（先补 registry `Fields` + translate `case "dnp3"`，G-DNP3-1）。
>
> **🔴 关键：存量 70 例今日既非绿也非红——它们不可执行**。层链路径层空壳（判据 A）；扁平路径已被 `CheckProtoFlat` 判死（判据 B，本车道实测 **70 rejected / 0 accepted**）；离线 suite 的 `chainSuiteProtos` 白名单不含 dnp3。其 `packet_count`/frames 均为**历史实测值**，待代码阶段层链内化后重校准。详见设计 §0.1。

## 1. 测试原则、形状基线与本版交付边界

用例从设计 §3–§9 逐项派生。**本版为文档阶段**（需求文档 v1.3 §3"文档阶段定位"）：交付物是本文件 + 设计文档 + 缺口登记表；`cases/dnp3.json` **保持原样**（理由见 §8.1）。

**形状基线（2026-09-28 机读实测，存量 70 例；⚠ 这些例今日不可执行，见设计 §0.1）**：70/70 例 `spec_json` 顶层含 `src_ip`/`dst_ip` + 顶层 `dnp3` 子映射（13 例另含 `src_port`）；41 例另带**空壳** `layers`（`[{tcp:{}},{dnp3:{}}]`，两层 config 恒 `{}`），29 例无 `layers`；50 正例 `expect` 含 `packet_count`（33 例）或 `min_packets`（17 例）；20 负例 `expect` 键集合 = `{error_contains,expect_error,notes}`（含 `notes`，**非**严格两键）。

**顶层旧键残留实测（非负例口径 = 主口径）= 163 处**——`src_ip` 50 / `dst_ip` 50 / 顶层 `dnp3` 子映射 50 / `src_port` 13（50 个非负例每例均带前三者，13 例另带 `src_port`）。**全例口径 = 223 处**（另含 20 个负例的 60 处）。**判死形状**（设计 §1.4/§1.11/§1.13）——收官自查「非负例顶层键 = 0」**今日红**（163 → 0 待代码阶段收敛，G-DNP3-10）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport/srcport`、`tcp.flags`、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线**：本机 tshark 3.6.14 有 `dnp3.*` dissector（**166 字段**，`tshark -G fields` 实测）——**但存量断言零使用 `dnp3.*`**（机读实测：断言字段仅 `tcp.dstport` 25 / `tcp.srcport` 23 / `udp.dstport` 1 / `ip.dst` 12 / `tcp.flags` 1 + frames 49 例）。可用通道：① `tcp.dstport/srcport`；② `tcp.flags`/`tcp.seq`；③ `ipv6.src/dst`；④ frames `offset/hex`（帧首字节，IPv4 offset 54 / IPv6 offset 74）。`dnp3.*` 为 A′ 可选增强（G-DNP3-8）。

**动态字段禁止硬编码**：生成期值用 `same_as_packet`/`distinct_values`/`nonzero` 断言（本协议今日零使用；多流用例走 `distinct_values`，G-DNP3-7）。

**包数约定**：层链 = 3（握手）+ N（scenario 帧数）+ 4（FIN 四包挥手）。存量包数为**历史实测值**（旧版本遗留）；两条路径今日均不可执行（设计 §0.1），层链值须代码阶段先跑后钉（§9.31）。

**保活/重试/RST 口径**：dnp3 层无 PING 类消息，不设正例亦不得进负例；RST 为框架 tcp 层能力，本协议层不新增断言（A′ 补例 G-DNP3-6 除外）；正例恒 FIN 优雅终止。

## 2. 目标用例契约（72 ID = 41 正 + 31 负，**待代码阶段落地**）

> **状态声明**：本节是**目标契约**，不是今日 JSON 的内容。今日 `cases/dnp3.json` 为存量 70 例（见 §8）。本节的 72 ID 中，**41 正例**由存量 41 例（去掉 9 例层链能力边界）改写而来 + **31 负例**由存量 20 负例改写 + 9 例能力边界转负 + 2 例新增判死负例。**层内配置今日无处可住**（设计 §0.1），故本表落地须先补 registry `Fields` + translate `case "dnp3"`（G-DNP3-1）。

### 2.1 目标正例（41）

| # | ID | 覆盖（设计 §） | packet_count / min_packets |
|---:|---|---|---|
| 1 | `dnp3_t21_reset_link` | §3.3/§4①：建链复位（Reset Link→ACK） | 9 |
| 2 | `dnp3_t22_read_class0` | §3.5/§4②：Class 0 全量轮询（六帧） | 13 |
| 3 | `dnp3_t23_select_operate` | §5：SBO 两事务共享 FCB | 15 |
| 4 | `dnp3_t24_direct_operate` | §3.5/§4⑤：直接控制 | 11 |
| 5 | `dnp3_t25_unsolicited` | §3.5/§4⑥：事件主动上报 + Confirm | 9 |
| 6 | `dnp3_t26_cold_restart` | §3.5/§4⑧：冷重启 | 11 |
| 7 | `dnp3_write_single_80_1` | §3.7/§4⑨：单点写入 80.1 | 11 |
| 8 | `dnp3_t28_no_handshake` | §3.3：`handshake=false` 无握手 | 6 |
| 9 | `dnp3_t34_broadcast_no_ack` | §8：广播不产 ACK | 8 |
| 10 | `dnp3_t29_no_termination` | §5：`termination=false` 不断开 | 5 |
| 11 | `dnp3_t30_appseq_wrap` | §3.4：AppSeq 回绕 | 13 |
| 12 | `dnp3_t36_malformed_crc` | §8：CRC 篡改位 | 13 |
| 13 | `dnp3_t48_iin_already_executing` | §3.4：IIN AlreadyExecuting | 13 |
| 14 | `dnp3_t49_iin_event_buffer_overflow` | §3.4：IIN EventBufferOverflow | 13 |
| 15 | `dnp3_t50_iin_local_control` | §3.4：IIN LocalControl | 13 |
| 16 | `dnp3_t52_iin_config_corrupt` | §3.4：IIN ConfigCorrupt | 13 |
| 17 | `dnp3_t46_unknown_func` | §3.5：未知功能码 200 | 11 |
| 18 | `dnp3_t37_iin_object_unknown` | §3.4：IIN ObjectUnknown | 13 |
| 19 | `dnp3_t43_malformed_length` | §3.1：Length 字节篡改 | 13 |
| 20 | `dnp3_t1_valid_minimal` | §3.1：最小合法帧 | min 4 |
| 21 | `dnp3_t3_valid_outstation` | §3.3：外设 respond 方向 | min 4 |
| 22 | `dnp3_t39_link_fc_status` | §3.3：链路 FC=2 Link Status | min 4 |
| 23 | `dnp3_t41_fcb_zero_only` | §3.2：FCB=1 FCV=0 | min 4 |
| 24 | `dnp3_t42_fcb_toggle` | §3.2：FCB 翻转 | min 5 |
| 25 | `dnp3_t44_malformed_length_zero` | §3.1：`malformed_length=0` | min 4 |
| 26 | `dnp3_t47_malformed_length_200` | §3.1：`malformed_length=200` | min 4 |
| 27 | `dnp3_t14_block16_crc` | §3.1：16B 整块 CRC | min 4 |
| 28 | `dnp3_t15_block17_crc` | §3.1：17B 跨块 CRC | min 4 |
| 29 | `dnp3_t51_iin_broadcast` | §3.4：IIN Broadcast | min 4 |
| 30 | `dnp3_t53_iin_all_bits` | §3.4：IIN 全位组合 | min 4 |
| 31 | `dnp3_t54_iin_raw_and_shorthand` | §3.4：原始值 + shorthand 或 | min 4 |
| 32 | `dnp3_t35_empty_objects_link_only` | §5：空 objects 仅链路帧 | 9 |
| 33 | `dnp3_t45_unknown_object_respond` | §3.6：未知对象响应 | 13 |
| 34 | `dnp3_t71_request_var0_accepted` | §3.6：请求 variation=0 合法 | min 4 |
| 35 | `dnp3_t72_freeze_clear_var1` | §3.5/§4⑦：Freeze Clear | min 4 |
| 36 | `dnp3_t78_link_ctrl03_outstation_data` | §3.3：链路 FC=3 外设主动上报 | min 4 |
| 37 | `dnp3_t80_empty_data_10bytes` | §3.1：空数据 10B 帧 | min 4 |
| 38 | `dnp3_t17_read_class123` | §3.5/§4③：Class 1/2/3 事件轮询 | 13 |
| 39 | `dnp3_t64_freeze_clear_con0` | §3.4：Freeze Clear CON=0 | min 4 |
| 40 | `dnp3_t67_operate_crob_shared_appseq` | §5：Operate CROB 共享 AppSeq | 15 |
| 41 | `dnp3_t68_respond_crob_status_echo` | §3.7：CROB 响应回显 Status | 8 |

**注**：上表 41 例中，`dnp3_t21`…`dnp3_t68` 均为**存量已有 ID**（§8.3 逐条去向），落地 = 层链改写（内容不变，形状改 `[{ip},{tcp},{dnp3}]`）；包数值为**历史实测值**，**层链路径须先跑后钉重校准**。

### 2.2 目标负例（31）

| # | ID | 覆盖（设计 §7） | 锚词 | 今日状态 |
|---:|---|---|---|---|
| 42 | `dnp3_t4_invalid_link_type` | N-1 角色非法 | `link_type` | 存量已有 |
| 43 | `dnp3_t5_invalid_transport` | N-2 载体非法 | `transport` | 存量已有 |
| 44 | `dnp3_t6_invalid_app_func` | N-3 功能码名非法 | `invalid app_func` | 存量已有（**锚词待补**，G-DNP3-9） |
| 45 | `dnp3_t7_appseq_overflow` | N-4 AppSeq 越界 | `app_seq` | 存量已有 |
| 46 | `dnp3_t8_broadcast_confirm` | N-5 广播+确认互斥 | `broadcast cannot require confirm` | 存量已有（**锚词待补**，G-DNP3-9） |
| 47 | `dnp3_t40_link_fc_overflow` | N-6 链路 FC 越界 | `link_fc` | 存量已有 |
| 48 | `dnp3_t9_multi_zero_count` | N-7 外设数 0 | `outstation_count` | 存量已有 |
| 49 | `dnp3_t10_multi_iplist_mismatch` | N-8 IP 列表长度不符 | `outstation_ip_list` | 存量已有 |
| 50 | `dnp3_t57_multi_no_ip` | N-9 多外设无 IP | `outstation_ip` | 存量已有 |
| 51 | `dnp3_t58_multi_port_zero` | N-10 源端口起点 0 | `src_port_start` | 存量已有 |
| 52 | `dnp3_t59_multi_port_overflow` | N-11 源端口越 65535 | `exceeds 65535` | 存量已有 |
| 53 | `dnp3_t55_iin_out_of_range` | N-12 IIN 越界 | `iin` | 存量已有 |
| 54 | `dnp3_t66_crob_request_status_rejected` | N-13 CROB 请求带 Status | `Status` | 存量已有 |
| 55 | `dnp3_t69_qualifier9_rejected` | N-14 qualifier 非法 | `qualifier` | 存量已有 |
| 56 | `dnp3_t69b_qualifier0_index_overflow` | N-15 qualifier 0 索引越界 | `index` | 存量已有 |
| 57 | `dnp3_t69c_qualifier17_point_index_overflow` | N-16 qualifier 0x17 点索引越界 | `index` | 存量已有 |
| 58 | `dnp3_t70_response_var0_rejected` | N-17 响应 variation=0 | `Variation` | 存量已有 |
| 59 | `dnp3_t73_counter_var3_rejected` | N-18 Object 20 variation 3 | `variation` | 存量已有 |
| 60 | `dnp3_t74_fc31_reserved_rejected` | N-19 FC=31 保留 | `FC=31` | 存量已有 |
| 61 | `dnp3_t75_fc215_reserved_rejected` | N-20 FC=215 保留 | `FC=215` | 存量已有 |
| 62 | `dnp3_t27_udp_transport` | N-21 层链拒 UDP | `transport=udp is not supported on the layer chain` | **存量为正例**，待转（G-DNP3-11） |
| 63 | `dnp3_t31_multi_outstation_3` | N-22 层链拒多外设 | `multi_outstation is not supported on the layer chain` | **存量为正例**，待转（G-DNP3-11） |
| 64 | `dnp3_t56_outstation_ip_start` | N-22 同上（IP 起点形） | 同上 | **存量为正例**，待转 |
| 65 | `dnp3_t60_iplist_overrides_start` | N-22 同上（列表覆盖形） | 同上 | **存量为正例**，待转 |
| 66 | `dnp3_t84_multi_outstation_10` | N-22 同上（10 外设） | 同上 | **存量为正例**，待转 |
| 67 | `dnp3_t32_multi_outstation_3_groupid` | N-22 同上（group_id 形） | 同上 | **存量为正例**，待转 |
| 68 | `dnp3_t33_multi_outstation_3_wire_order` | N-22 同上（线序形） | 同上 | **存量为正例**，待转 |
| 69 | `dnp3_t81_strategy_convert_full_path` | N-22 同上（全链路形） | 同上 | **存量为正例**，待转 |
| 70 | `dnp3_t85_multi_outstation_20_stress` | N-22 同上（20 外设压力） | 同上 | **存量为正例**，待转 |
| 71 | `dnp3_neg_presence` | N-23 层链 + 顶层空 dnp3 子映射并存 | `no longer accepts a top-level dnp3 sub-config` | **待新建**（G-DNP3-2） |
| 72 | `dnp3_neg_stray_src_ip` | N-24 层链 + 顶层 src_ip 游离键 | `no longer accepts flat config field src_ip` | **待新建**（G-DNP3-2） |

T-编号对照：T-DNP3-P1…P41 ≡ #1…#41；T-DNP3-N1…N31 ≡ #42…#72（与设计 §7 对应）。

**JSON ID 集合纪律声明**：本文档引用的 **A′ 补例 ID**（`dnp3_enable_unsolicited` / `dnp3_assign_class` / `dnp3_delay_measurement` / `dnp3_ipv6` / `dnp3_abort_rst`）与 **2 例判死负例 ID**（`dnp3_neg_presence` / `dnp3_neg_stray_src_ip`）**均为未来 ID，不在当前 `cases/dnp3.json` 的 70 个 ID 集合内**（§7 三件套纪律：设计行与待实现边界不得写入当前 JSON ID 集合，除非已有可执行实现和断言）。当前 JSON 集合 = §8 存量 70 例。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count` 或 `min_packets` + 载体断言 + 帧首 frames 断言。帧首 hex 均可由 fixture 精确预算（`05 64` 起始；reset 帧 `05 64 06 c0 00 04 01 00`；ACK 帧 `05 64 06 00 01 00 00 04`）。**下断言的包数值与 hex 取自存量 legacy flat 路径实测；层链路径须代码阶段先跑后钉复核。**

### 3.1 `dnp3_t21_reset_link`（9）

Reset Link（帧 4，offset 54，hex `05 64 06 c0 00 04 01 00`）+ ACK（帧 5，hex `05 64 06 00 01 00 00 04`）；`tcp.dstport=20000`（帧 4）+ `tcp.srcport=20000`（帧 5，端口对换）；`has_handshake`/`terminates` 全 true。

### 3.2 `dnp3_t22_read_class0`（13）

Reset Link（帧 4）+ Read 请求（帧 6，hex `05 64 07 d3 00 04 01 00`）+ Respond（帧 8，hex `05 64 06 03 01 00 00 04`）；三帧 frames 断言；`tcp.dstport=20000`。

### 3.3 `dnp3_t23_select_operate`（15）

Select（帧 4，hex `05 64 0f d3 00 04 01 00`）+ Respond（帧 6）+ Operate（帧 8，同 hex = FCB 共享直接证据）；`tcp.dstport=20000`；`has_handshake`/`terminates` true。

### 3.4 `dnp3_t24_direct_operate`（11）

Direct Operate（帧 4，hex `05 64 0f d3 00 04 01 00`）+ Respond（帧 6，hex `05 64 12 03 01 00 00 04`）；`tcp.dstport=20000`。

### 3.5 `dnp3_t25_unsolicited`（9）

Unsolicited Respond（up）+ Confirm（down）；`tcp.dstport=20000` + `tcp.srcport=20000`；`has_handshake`/`terminates` true。

### 3.6 `dnp3_t26_cold_restart`（11）

Cold Restart 请求 + Respond；`tcp.dstport=20000`；`has_handshake`/`terminates` true。

### 3.7 `dnp3_write_single_80_1`（11）

Write 80.1 请求 + Respond；`tcp.dstport=20000`；`has_handshake`/`terminates` true。

### 3.8 `dnp3_t28_no_handshake`（6）

`handshake=false` → 无 SYN/SYN-ACK/ACK 三包，仅 scenario 帧 + FIN；`has_handshake=false`/`terminates=false`。

### 3.9 `dnp3_t34_broadcast_no_ack`（8）

`dst_addr=0xFFFF` 广播 → 不产 ACK/Respond（`scenario.go:52`）；`has_handshake`/`terminates` true。

### 3.10 `dnp3_t29_no_termination`（5）

`termination=false` → 无 FIN 四包；`has_handshake=true`/`terminates=false`。

### 3.11 `dnp3_t30_appseq_wrap`（13）

`app_seq` 回绕；`tcp.dstport=20000`；`has_handshake`/`terminates` true。

### 3.12 `dnp3_t36_malformed_crc`（13）

`malformed_crc=true` 翻转末字节；帧 hex 断言反映篡改；`tcp.dstport=20000`。

### 3.13 IIN 系列（`t48`/`t49`/`t50`/`t52`/`t37`，各 13）

单个 IIN shorthand 位置位 → 响应帧 IIN 字节变化；三帧 frames 断言；`tcp.dstport=20000`。

### 3.14 `dnp3_t46_unknown_func`（11）

`unknown_func=true` → FC=200 + IIN FuncNotSupported；`tcp.dstport=20000`。

### 3.15 `dnp3_t43_malformed_length`（13）

`malformed_length` 篡改 Length 字节；帧 hex 断言反映；`tcp.dstport=20000`。

### 3.16 `min_packets` 族（17 例，`dnp3_t1`…`dnp3_t80`）

帧数随配置变化的例用 `min_packets`（4 或 5）+ frames 帧首字节断言；不断言精确包数以避帧数漂移（代码阶段先跑后钉，§9.31）。

**正例总则**：广播、`link_fc` 0-11 全值、`variation=0` 请求帧、IIN 全位组合均为正例形态，只有配置/线格式/状态/关联/长度错误进入负例。

## 4. 负例契约

负例必须在 planner/validator/生成器阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；**目标形状** `expect` 键集合严格为 `{expect_error,error_contains}`（存量 20 例含 `notes`，代码阶段归位到 case 级）。锚词与设计 §7 表一一对应、同序：

| ID | 故障输入 | `error_contains` | 拒绝层 | 存量实测 |
|---|---|---|---|---|
| `dnp3_t4_invalid_link_type` | `link_type="slave"` | `link_type` | Validate | ✓ 锚词命中 |
| `dnp3_t5_invalid_transport` | `transport="sctp"` | `transport` | Validate | ✓ |
| `dnp3_t6_invalid_app_func` | `app_func="foobar"` | `invalid app_func` | Validate | **✗ 锚词为空**（G-DNP3-9） |
| `dnp3_t7_appseq_overflow` | `app_seq=16` | `app_seq` | Validate | ✓ |
| `dnp3_t8_broadcast_confirm` | 广播 + `confirm_required` | `broadcast cannot require confirm` | Validate | **✗ 锚词为空**（G-DNP3-9） |
| `dnp3_t40_link_fc_overflow` | `link_fc=12` | `link_fc` | Validate | ✓ |
| `dnp3_t9_multi_zero_count` | `outstation_count=0` | `outstation_count` | Validate | ✓ |
| `dnp3_t10_multi_iplist_mismatch` | IP 列表长度 ≠ count | `outstation_ip_list` | Validate | ✓ |
| `dnp3_t57_multi_no_ip` | 多外设无 IP | `outstation_ip` | Validate | ✓ |
| `dnp3_t58_multi_port_zero` | `src_port_start=0` | `src_port_start` | Validate | ✓ |
| `dnp3_t59_multi_port_overflow` | 端口越 65535 | `exceeds 65535` | Validate | ✓ |
| `dnp3_t55_iin_out_of_range` | `iin` 越界 | `iin` | validate.go 范围门 | ✓ |
| `dnp3_t66_crob_request_status_rejected` | CROB 请求带 Status | `Status` | Validate | ✓ |
| `dnp3_t69_qualifier9_rejected` | `qualifier=9` | `qualifier` | Validate | ✓ |
| `dnp3_t69b_qualifier0_index_overflow` | qualifier 0 索引越界 | `index` | Validate | ✓ |
| `dnp3_t69c_qualifier17_point_index_overflow` | qualifier 0x17 点索引越界 | `index` | Validate | ✓ |
| `dnp3_t70_response_var0_rejected` | 响应 `variation=0` | `Variation` | Validate | ✓ |
| `dnp3_t73_counter_var3_rejected` | Object 20 `variation=3` | `variation` | Validate | ✓ |
| `dnp3_t74_fc31_reserved_rejected` | `app_func_code=31` | `FC=31` | Validate | ✓ |
| `dnp3_t75_fc215_reserved_rejected` | `app_func_code=215` | `FC=215` | Validate | ✓ |
| `dnp3_t27_udp_transport` | `transport="udp"`（层链） | `transport=udp is not supported on the layer chain` | 生成器 | **存量为正例**（G-DNP3-11） |
| `dnp3_t31_*` 等 8 例 | `multi_outstation`（层链） | `multi_outstation is not supported on the layer chain` | 生成器 | **存量为正例**（G-DNP3-11） |
| `dnp3_neg_presence` | 层链 + 顶层空 dnp3 子映射 | `no longer accepts a top-level dnp3 sub-config` | CheckProtoFlat（补分支后） | **待新建**（G-DNP3-2） |
| `dnp3_neg_stray_src_ip` | 层链 + 顶层 src_ip | `no longer accepts flat config field src_ip` | CheckProtoFlat 通用门 | **待新建**（G-DNP3-2） |

**负例原子性**：每例单一故障注入；单次执行不得混注。

## 5. 覆盖与对账

### 5.1 三源回指行

IEEE 1815-2012（DNP3 官方标准，帧格式/FC 表/IIN 位）+ D-DNP3-1（设计 §11）+ tshark 通道实测（`tcp.*`/frames，`dnp3.*` 166 字段今日零断言）→ 目标 72 ID（本契约 §2）。第三源"已确认现网行为"当前 = **未确认级**（G-DNP3-4，不写死进实现）。UDP/serial/多外设面**层链不支持**（生成器显式拒绝，G-DNP3-11）。

### 5.2 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **IEEE 1815-2012 规范反推 + 旧基线契约 + 仓库落码反推 + tshark 通道实测**。
- **对账两行**：**要求逻辑点总数 = 86**（八项 8 行 + 矩阵 45 格 + 变体 24 行 + 商业映射 9 行）；**用例覆盖数（目标契约已具断言）= 65**（八项 8 + 矩阵 T1/T2 两列 27 + 变体 24 + 商业 6）；**待建（立项）= 3**（矩阵 T1 列 enable_unsolicited/assign_class/delay_measurement）；**层链不支持（不适用）= 5**（矩阵 T3 列 UDP/多外设 2 + 商业多外设/UDP 2 + 商业串行链路 1）；**待代码阶段 = 13**（矩阵 T3 列其余 13 行的层链侧重判）。65 + 3 + 5 + 13 = 86 ✓（三表逐格重数见设计 §10.2/§10.3/§10.4）。
  **粒度声明**：行/格粒度每点 1 计；G-DNP3-1…G-DNP3-13 与次要合法行为（RST/think_time）不折进 86。**反查全绿 ≠ 覆盖全**（§9.52 原文）。**注意**：本对账的"已覆"= 目标契约已具断言，**不是今日可跑**——存量两条路径均不可执行（设计 §0.1），不得读作"今日已过"或"层链已过"。
- **门3 抽查候选**：最复杂用例 = **#3 `dnp3_t23_select_operate`**（Select→Operate 两事务 + FCB 共享不变量 + CROB 对象 + 三帧 hex 双通道）；交织维度 = 事务(2)×FCB 不变量×对象(12.1)×终态(FIN)。若按 9.49/9.50 下限偏弱在"多流/异常分支"面，**建议门3 抽 #3 + #40 `dnp3_t67_operate_crob_shared_appseq`**（补 AppSeq 共享面）。

### 5.3 T-编号与旧 id 对照（设计 §9 全表摘要）

`dnp3_t21_reset_link` ≡ T-DNP3-P1；`dnp3_t22_read_class0` ≡ T-DNP3-P2；…；`dnp3_t4_invalid_link_type` ≡ T-DNP3-N1；`dnp3_t5_invalid_transport` ≡ T-DNP3-N2；…（全 72 项见 §2 表，顺序一一对应）。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接多帧问答（#2 T22 六帧、#3 T23 两事务） | 已覆（flat）#2/#3 |
| ② | 非正常结束 | 正常 FIN 全正例；应用层正常终止报文 = **无**（DNP3 无终止类型）；网络层异常 = RST | A′ 补例 **`dnp3_abort_rst`**（`tcp.rst=true`，框架能力，本层零断言，G-DNP3-6）+ 负例面 |
| ③ | 长保活 | 协议层无 keepalive 语义（设计 §4 显式不适用）；长会话 = 同连接多帧 + 多流展开 | #2/#3 承载（>2 帧） |

无空项：① 有已覆例；② 有负例面 + 1 条 A′ 补例；③ 有 #2/#3。

### 6.2 A′/B′ 两分类表

**A′（代码阶段接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 层链化 | registry `Fields` 补 39 键 + translate `case "dnp3"` 层内分支 | G-DNP3-1，目标 72 例全依赖 |
| scenario 面 | enable/disable_unsolicited、assign_class、delay_measurement | 设计 §10.2 三待建（补例 `dnp3_enable_unsolicited` 等） |
| 地址族面 | IPv6 载体 | `dnp3_ipv6`（G-DNP3-3，offset 74，先跑后钉） |
| 非正常结束 | `tcp.rst` 补例 | `dnp3_abort_rst`（G-DNP3-6） |
| 断言增强 | `dnp3.*` tshark 字段（166 可用，今日零用） | G-DNP3-8 |
| 现网面 | 设备方言/默认口实证 | G-DNP3-4 |

**B′（框架面）**：`CheckProtoFlat` dnp3 presence 分支 + `pipe_gate.sh` `_pres_key` 名单（G-DNP3-2，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态（G-DNP3-7，allowlist 无 `dnp3` 行）/ `is_event`/`app_con`/`think_time`（G-DNP3-5，明确不解决）。进设计 §14，「明确不解决 + 迁入计划」。

### 6.3 3.14 豁免边界审计

**有长连接载体 → `sessions[]` 不豁免**（设计 §12.3 会话表 s1/s2/s3；多会话语义走 `flow_control flows`）；多流并发走 `flow_control`（G-DNP3-1）；单包多载荷 = **不适用**（dnp3 帧恒单 ASDU、无多 question/多 RR 类形态，如实声明；`objects[]` 多对象在**单帧内**是帧内结构非多载荷）。

## 7. 实现后执行建议（代码阶段）

1. **顺序**：G-DNP3-1（registry Fields + translate 分支 + schemagen 重跑）→ 存量 70 例层链改写（先跑后钉）→ 9 例能力边界重判（转负例或按新能力定形）→ 补 A′ 5 例 + 2 例判死负例 → 全量复跑。
2. **实测顺序**：先 T21/T22（reset/read 基线与 frames），再 T23/T67（SBO FCB 共享），再 T14/T15（跨块 CRC），最后 T80（空帧）、IIN 系列。
3. 二进制与 HEAD 同代确认（门2③）；门2② 全量（`CASE_PROTO=dnp3` 全量不是增量）；门2④ 反查绿后进 P6。
4. 任何 `dnp3.*` 断言增强须有独立 tshark 字段证据和失败优先测试（设计 §1.2 ⑤ 纪律）。

## 8. 存量审计与缺口登记（70 例；**本版不改 JSON**）

### 8.1 为什么本版不动 cases JSON（层空壳判据）

**两条判据同时成立即"空壳"**：① `registry.go:253` dnp3 Register **无 Fields**（生成表 `fields:{}`）；② `translateTerminalConfig` switch **无 `case "dnp3"`**（`grep` = 0）。

**后果**：`chain_planner_translate.go:852` `if len(s.Fields) == 0 { return }` 使层内配置**根本不被解码**；层内业务键被 `ValidateLayerConfig` 拒（`complete.go:293` `unknown field`）。

**为什么改不动**：存量"层链例"实为 `layers:[{tcp:{}},{dnp3:{}}]`（**空壳层**）+ 顶层 `dnp3` 子映射 + 顶层四元组并存——**判死形状**（设计 §1.4/§1.11/§1.13）。改成目标形状后 ①层内键无处可住（被 V9 拒）；②仍带顶层旧键则经 MCP 建策略 400（`schema/semantic.go:130`）。**照改 = 把绿例改红，且新 JSON 依旧不可调用**（违反 §14.1）。故 `cases/dnp3.json` **保持原样**，改写留代码阶段。

### 8.2 存量实测面（2026-09-28，机读）

**执行状态（实测）：两条路径今日均不可执行**——建策略 70/70 400（`CheckProtoFlat`，设计 §0.1 判据 B）；离线 suite 不收 dnp3（`chainSuiteProtos` 白名单）。故下列断言值均为**历史实测值**。

`cases/dnp3.json` **70 例** = 50 正（33 带 `packet_count`、17 带 `min_packets`）+ 20 负。顶层旧键残留 **163 处（非负例口径）**／223 处（全例）；41 例带空壳 `layers`，29 例无。20 负例 `expect` 键集合 = `{error_contains,expect_error,notes}`（含 notes）；**2 例锚词为空**（T6/T8）。断言字段仅 `tcp.dstport` 25 / `tcp.srcport` 23 / `udp.dstport` 1 / `ip.dst` 12 / `tcp.flags` 1 + frames 49 例。

### 8.3 缺口登记表（每条三要素：现象 / 证据行号 / 归属阶段）

> 本车道为文档轨，**全部缺口归代码阶段处置**（需求文档 v1.3 §3 文档阶段定位；`docs-first-workflow` 例外条）。

| 缺口 | 现象 | 证据 | 归属阶段 / 去向 |
|---|---|---|---|
| **G-DNP3-1** | **层为空壳**：registry 无 Fields + translate 无 case → 层内配置根本不被解码，层内业务键被 V9 拒 `unknown field` | `registry.go:253`（无 Fields）；生成表 `dnp3.fields={}`；`grep 'case "dnp3"'` = 0；`translate.go:852`；`complete.go:293` | **代码阶段首动作**：补 registry Fields（39 键）+ translate `case "dnp3"` + schemagen 重跑 |
| **G-DNP3-2** | `CheckProtoFlat` 无 dnp3 分支 → presence 形今日不判死；`pipe_gate.sh` `_pres_key` 名单亦无 dnp3 | `grep -c 'protocol == "dnp3"'` = 0（全 60 分支）；`pipe_gate.sh` case 名单逐项核对 | 代码阶段：先实测再建例；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单） |
| **G-DNP3-3** | IPv6 载体零用例 | 存量 70 例无 IPv6（机读） | A′ 补例 `dnp3_ipv6`（offset 74，先跑后钉） |
| **G-DNP3-4** | 现网 DNP3 设备默认口/变体方言说法未达验证级 | 旧稿 §1.1 记载，无抓包/手册级证据 | 待确认：查 IEEE 1815-2012 附录或抓现网 RTU 包 |
| **G-DNP3-5** | `is_event`/`app_con`/`think_time` 字段存在但无独立 scenario 分支 | `scenario.go` 16 case 无对应分支；`types.go:3471`（`is_event`）/`:3468`（`app_con`）/`:3493`（`think_time`）字段在册 | **明确不解决** + 迁入计划（用例今日不得携带） |
| **G-DNP3-6** | RST 非正常结束补例（§3.15②后半） | 存量 70 例零 RST | A′ 补例 `dnp3_abort_rst` |
| **G-DNP3-7** | 业务字段动态全关（allowlist 无 `dnp3` 行） | `layer_dyn.go:18-21` 四行（ip/tcp/udp/eth）；`grep -c dnp3` = 0 | A′ 候选，不冒充已覆盖（§9.36 口径） |
| **G-DNP3-8** | `dnp3.*` tshark 字段（166 可用）今日零断言 | `tshark -G fields` 166 行；存量断言字段机读仅 `tcp.*`/`udp.dstport`/`ip.dst` | A′ 断言增强（可选，非阻塞）；增强须先跑后钉 |
| **G-DNP3-9** | 存量 2 例负例锚词为空——任何错误均可通过，失去断言力 | `cases/dnp3.json` T6/T8 机读 `error_contains == ""` | 代码阶段补正为 `invalid app_func` / `broadcast cannot require confirm`（逐字对 `dnp3.go:30`/`:28`） |
| **G-DNP3-10** | 存量顶层旧键残留 **163 处（非负例口径，主口径）**／全例 223 处——判死形状 | 机读：非负例 `src_ip` 50 / `dst_ip` 50 / 顶层 `dnp3` 50 / `src_port` 13 | 待代码阶段收敛（随 G-DNP3-1）；收官自查「非负例顶层键 = 0」**今日红 → 163 → 0** |
| **G-DNP3-11** | 存量 9 例（1 UDP + 8 multi_outstation）**两条路径今日均不可执行**——层链生成器显式拒绝（`layer_gen.go:52`/`:55`），扁平入口已被 `CheckProtoFlat` 判死（设计 §0.1 判据 B，实测 70/70 400）。其"层链必红"无须论证——今日**根本跑不到生成器**（建策略即 400） | `layer_gen.go:52`/`:55`；`semantic.go:130`；存量 T27/T31/T56/T60/T84/T32/T33/T81/T85 | 代码阶段：随 G-DNP3-1 层链内化后按新能力重判（转负例或定形） |
| **G-DNP3-12** | 设计侧锚点缺口：50 个非负例中仅 12 例在 design 文档有落点，38 例只住 testcase §2——"每正例可回指设计"不成立 | 机读：50 非负例 ID 在 `95-dnp3-design.md` 出现 12 个 | 代码阶段随层链内化补设计侧锚点（§8.4 行 12 今日 ✗ 38/50） |
| **G-DNP3-13** | IIN 14 位中 `iin_device_restart` **零用例**（其余 13 位有例或入 T53 全位组合） | 机读：14 位 shorthand 中 13 位在用例出现，`iin_device_restart` 零 | A′ 补例 `dnp3_iin_device_restart`（或并入 T53 全位组合并计）；今日如实标零覆盖 |

### 8.4 覆盖反查门建议断言行（**红项如实标红**）

> 供代码阶段 `coverage_gate.py` 的 `check_dnp3` 块使用（登记归代码阶段，G-DNP3-2 同批）。**下列第 13/14 项今日为红，不得作为"今日已过"申报**（ldp 先例）。

| # | 断言行 | 今日判定 |
|---:|---|---|
| 1 | 用例数 == 目标契约数（代码阶段落地后） | 目标 72 |
| 2 | ID 全仓唯一 | 存量 ✓ |
| 3 | 负例 `expect` 键集合严格 == `{expect_error,error_contains}` | 存量 ✗（含 notes，20/20） |
| 4 | 负例 `error_contains` 非空 | 存量 ✗（T6/T8 为空） |
| 5 | 每负例锚词命中代码字面值 | **✗ 0/20 今日不可执行**（存量 20 例建策略即 400，跑不到锚词比对；18/20 仅为锚词与代码字面值的静态比对，非执行结果） |
| 6 | 正例顶层键 ⊆ 白名单（**非负例口径 50**；§8.2 的 41 指带空壳 layers 的例数，非同一分母） | 存量 ✗（50/50 违规） |
| 7 | 非负例顶层协议子映射 == 0 | 存量 ✗（50 处） |
| 8 | 正例 `packet_count`/`min_packets` 存在 | 存量 ✓（50/50） |
| 9 | 正例含 frames 或 fields 断言 | **✗ 49/50**（`dnp3_t71_request_var0_accepted` 两者皆无，仅 min_packets） |
| 10 | `dnp3_neg_presence` 存在且锚词含 `top-level dnp3` | 待建 ✗ |
| 11 | `dnp3_neg_stray_src_ip` 存在且锚词含 `flat config field src_ip` | 待建 ✗ |
| 12 | 每正例 ID 与设计 §9/scenario 表可回指 | **✗ 38/50**（非负例中仅 12 例在设计文档有落点；其余 38 例只住 testcase §2，设计侧待补锚点，G-DNP3-12） |
| 13 | **非负例顶层旧键 == 0**（收官自查行，非负例口径） | **今日红：163 处**（G-DNP3-10） |
| 14 | **层链路径可跑**（层内配置可住） | **今日红：层空壳**（G-DNP3-1） |

## 9. 修订记录

- v1.0.0（2026-09-28）：P-PIPE #95 文档轨 P1–P3。**本版为文档阶段**（层空壳，`cases/dnp3.json` 保持原样，理由见 §8.1）。存量 70 例机读审计（顶层残留 163 处〔非负例口径〕/ 223 处〔全例〕）；目标契约 72 ID（§2，待代码阶段落地）；§5.2 对账两行（要求 86 = 覆盖 65 + 待建 3 + 层链不支持 5 + 待代码阶段 13）；§6 P3 固定动作；§8.3 缺口登记表（G-DNP3-1…G-DNP3-13，每条三要素）；§8.4 覆盖反查门建议断言行（**红项如实标红**）。自审 5 轮，末轮干净（结论见 /tmp/pipe/doc-lanes/dnp3.md）。

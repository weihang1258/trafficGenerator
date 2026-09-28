# #96 rip（Routing Information Protocol）测试用例契约

> 版本：v1.0.1（文档先行批次一，车道 A；v1.0.1 = 补登记 G-RIP-11 结果产物过期）
> 日期：2026-09-28
> 配套设计：`docs/protocol-designs/96-rip-design.md` v1.0.1
> 旧基线：`docs/protocol-designs/10-rip-design.md` v1.0.0（仅设计稿，**无用例文档**——本版新建补缺 G-RIP-5）
> 机器契约：`trafficgen/test/protocol_pcap/cases/rip.json`（71 例 = 52 正 + 19 负；ID/包数/锚词已机读实测与本文一致；**顶层旧键残留 71/71（178 处，非负例口径），代码阶段迁移**，G-RIP-1/G-RIP-2/G-RIP-4）
> 白话一句：**七十一道检查：五十二道看正常喊话（各版本、各场景、各种边界值、多路由器），十九道看胡来能不能被拦下；每道只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **71 个唯一语义 ID：52 正 + 19 负**（存量继承，语义全部保留）。派生规则：设计 §3 每个字段/偏移条款、§4 每个业务场景、§5 每个自动派生规则、§7 每行错误处理、§8 每个边界在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**（§7 原子原则）。

**形状基线（2026-09-28 机读实测）**：

| 项 | 实测 | 判定 |
|---|---|---|
| 例数 / ID 唯一 | 71 / 71 唯一 | ✓ |
| 正/负 | 52 正 + 19 负 | ✓ |
| 例对象顶层键 | 5 键 `{expect,id,proto,spec_json,summary}`（71/71 同形） | ✓ |
| `spec_json` 顶层键（**括号内为该顶层键形状的例数，非扁平例数**） | `{layers,rip,src_port,count}` ×36 + `{rip,src_port,count}` ×17 + `{layers,rip,src_port,count,dst_ip}` ×7 + `{layers,rip,src_port,count,src_ip,dst_ip,dst_port}` ×5 + `{layers,rip,src_port,count,group_id}` ×4 + `{rip,src_port,count,src_ip,dst_ip,dst_port}` ×2 | **✗ 71/71 例均含旧键**；非负例口径残留 **178 处**（全 71 例口径 241 处），G-RIP-4 |
| 链/扁 × 正/负 | 52 链形**全为正例**；19 扁平形**全为负例**（机读实测，两者恰好同界） | 口径注 |
| 层链形 | `[udp,rip]` ×52，**层 config 恒 `{}`（空壳）** | ✗ 空壳层（G-RIP-1/G-RIP-2） |
| 扁平形 | ×19（无 `layers` 键） | ✗ 旧形（G-RIP-4） |
| 负例 `expect` 键集合 | `{error_contains,expect_error,notes}` ×19 | **✗ 含 `notes`**，非严格两键（差异登记，§4 末） |
| 正例 `expect` 键集合 | `{fields,frames,notes,packet_count}` ×39 + `{fields,notes,packet_count}` ×7 + `{frames,notes,packet_count}` ×5 + `{notes,packet_count}` ×1 | 正例不设严格键约束（`notes` 为设计回指，非断言） |

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（§3 通道表）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线（2026-09-28 实测，tshark 3.6.14）**：`rip.*` = **18 字段**、`ripng.*` = **8 字段**（全表见设计 §3.7）。**断言字段一律以该表为准**，不得臆造。RIPng 走独立字段族 `ripng.*`（tshark 按端口 521 + IPv6 分派），不得用 `rip.*` 断言 ng 报文。

**断言通道实测分布**（机读，71 例 `expect` 内字段计数）：`udp.srcport` 20 / `ip.dst` 16 / `udp.length` 16 / `rip.command` 12 / `rip.metric` 11 / `rip.family` 9 / `rip.version` 7 / `udp.dstport` 7 / `ip.ttl` 6 / `rip.auth.type` 5 / `ripng.rte.prefix_length` 5 / `ip.src` 5 / `ripng.rte.metric` 4 / `rip.netmask` 4 / `ripng.rte.ipv6_prefix` 3 / `rip.auth.passwd` 2 / `rip.key_id` 2 / `rip.auth_data_len` 2 / `rip.seq_num` 2 / `rip.digest_offset` 2 / `rip.ip` 2 / `ripng.cmd` 1 / `ripng.version` 1 / `ipv6.dst` 1。

**frames offset 实测**：42（IPv4 RIP 头起点，14+20+8）34 处 / 66（IPv4 首条目）16 / 46（v1 RTE 起点）16 / 62（IPv6 RIP 头起点，14+40+8）5 / 82（IPv6 首条目）4 / 86（MD5 trailer）4 / 58（v1 掩码位）1 / 90（MD5 摘要）1 / 106、126（多条目）各 1。**offset 口径**：42/62 = RIP 头；+24 = 首条目（v2/ng，头 4 + 条目起始 20 内偏移）；v1 条目内掩码位 = +16。

**动态字段禁止硬编码**：生成期值用 `same_as_packet`/`distinct_values`/`nonzero` 断言（`rip_tedge22_routers_100_inc`/`rip_tpos17_100_routers` 的 `group_id` 聚合已用）。

**包数约定**：UDP 单发无握手/挥手——`packet_count` = 报文数（拆包后），不适用 `3+N+4` 公式。多 router = routers × rounds × ceil(entries/25)（首包带认证时 24）。

**保活/重试/RST 口径**：RIP 层无 PING 类消息、无握手/挥手（UDP 无连接），不设正例亦不得进负例；RST 概念不适用（无 TCP 载体）。

**DSCP 口径（G-RIP-7）**：设计 §0 表 #6 校正——旧稿「DSCP 默认 CS6」是**死参数**（`rip.go:502` 算出但从不达线）。**用例不得断言 CS6**；线上 DSCP 恒 = `spec.DSCP`（0 时落 ip 层 schema 默认 0）。

## 2. 原子用例索引（71 ID = 52 正 + 19 负；顺序 = `cases/rip.json` 顺序，为权威）

| # | ID | 型 | 覆盖（设计 §） | packet_count |
|---:|---|---|---|---:|
| 1 | `rip_tpos1_request_full` | 正 | §5 派生③：request_full → Request + auto-Response | 2 |
| 2 | `rip_tpos1b_user_routes` | 正 | §5 派生④：request_full 带用户路由 | 2 |
| 3 | `rip_tpos4_v1_broadcast` | 正 | §3.3：v1 广播 255.255.255.255 | 1 |
| 4 | `rip_tpos6_multicast_ttl` | 正 | §3.8：v2 组播 224.0.0.9，TTL=1 | 1 |
| 5 | `rip_tpos7_rounds` | 正 | §5 派生⑥：rounds=3 三轮 | 3 |
| 6 | `rip_tpos8_simple_auth` | 正 | §3.4：simple 认证（16B 补零） | 1 |
| 7 | `rip_tpos9_md5_auth` | 正 | §3.4：MD5 认证（PacketLength 44 + trailer） | 1 |
| 8 | `rip_tpos27_auth_25_routes` | 正 | §3.6：认证 + 25 路由（首包 24 上限） | 2 |
| 9 | `rip_tpos27b_auth_26_routes` | 正 | §3.6：认证 + 26 路由拆包 | 2 |
| 10 | `rip_tpos14_ripng` | 正 | §3.5：RIPng FF02::9，端口 521 | 1 |
| 11 | `rip_tpos10_split_horizon` | 正 | §4⑦：单播水平分割过滤 | 1 |
| 12 | `rip_tpos12_poison_reverse` | 正 | §4⑦：毒化反转 | 1 |
| 13 | `rip_tedge6_zero_routes` | 正 | §5 派生④：显式空路由 → 裸 4B 头 | 1 |
| 14 | `rip_tedge11_default_route` | 正 | §8：缺省路由 0.0.0.0/0 | 1 |
| 15 | `rip_tpos33_domain` | 正 | §3.1：domain=1 | 1 |
| 16 | `rip_terr14_multicast_overrides` | 正 | §3.8：multicast 覆盖用户 DstIP | 1 |
| 17 | `rip_tpos5_unicast` | 正 | §3.8：v2 单播，TTL=64 | 1 |
| 18 | `rip_tpos10_route_poison` | 正 | §8：metric=16 毒化 | 1 |
| 19 | `rip_tpos13_triggered` | 正 | §5 派生：triggered_update 跳过 Request | 1 |
| 20 | `rip_tpos15_ripng_default` | 正 | §3.5：RIPng 缺省路由 ::/0 | 1 |
| 21 | `rip_tpos24_simple_auth_16b` | 正 | §8：密码恰 16B 不补零 | 1 |
| 22 | `rip_tpos29_version_default` | 正 | §5 派生①：version 缺席默认 v2 | 1 |
| 23 | `rip_tpos32_v1_multicast_broadcast` | 正 | §3.8：v1 multicast → 广播 | 1 |
| 24 | `rip_tedge7_25_entries` | 正 | §8：25 条目单包上限 | 1 |
| 25 | `rip_tedge19_domain_ffff` | 正 | §8：domain=0xFFFF 透传 | 1 |
| 26 | `rip_tedge10_51_entries` | 正 | §8：51 条目拆 25+25+1 | 3 |
| 27 | `rip_tedge12_ip_bcast_err` | 负 | §7 N-14：广播地址作路由 | — |
| 28 | `rip_tedge13_mask_zero` | 正 | §8：掩码 0.0.0.0 | 1 |
| 29 | `rip_tedge14_mask_ffff` | 正 | §8：掩码 255.255.255.255 | 1 |
| 30 | `rip_tedge15_mask_noncontig` | 正 | §8：非连续掩码透传 | 1 |
| 31 | `rip_tedge16_ripng_len0` | 正 | §8：PrefixLen=0 | 1 |
| 32 | `rip_tedge17_ripng_len128` | 正 | §8：PrefixLen=128 | 1 |
| 33 | `rip_tedge18_ripng_len129_err` | 负 | §7 N-19：PrefixLen=129 | — |
| 34 | `rip_tedge1_metric0_err` | 负 | §7 N-3：metric=0 | — |
| 35 | `rip_tedge20_default_routes` | 正 | §5 派生④：routes=nil → 5 条默认 | 1 |
| 36 | `rip_tedge21_routers_empty` | 正 | §5 派生⑤：routers=[] → 单 router | 1 |
| 37 | `rip_tedge22_routers_100_inc` | 正 | §10.3 #50：100 router + group_id inc | 100 |
| 38 | `rip_tedge2_metric1` | 正 | §8：metric=1 下限 | 1 |
| 39 | `rip_tedge3_metric16` | 正 | §8：metric=16 不可达 | 1 |
| 40 | `rip_tedge4_metric17_err` | 负 | §7 N-4：metric=17 | — |
| 41 | `rip_tedge5_metric255_err` | 负 | §7 N-5：metric=255 | — |
| 42 | `rip_tedge8_26_entries` | 正 | §8：26 条目拆 25+1 | 2 |
| 43 | `rip_tedge9_50_entries` | 正 | §8：50 条目拆 25+25 | 2 |
| 44 | `rip_terr10_password_17b` | 负 | §7 N-12：密码 17B | — |
| 45 | `rip_terr11_ip_invalid` | 负 | §7 N-15：路由 IP 非法字面 | — |
| 46 | `rip_terr12_mask_invalid` | 负 | §7 N-16：掩码非法字面 | — |
| 47 | `rip_terr13_nh_v6` | 负 | §7 N-17：v2 next_hop 异族 | — |
| 48 | `rip_terr15_split_poison` | 正 | §4⑦：split+poison 组合 | 1 |
| 49 | `rip_terr16_router_empty` | 负 | §7 N-18：routers=[{}] | — |
| 50 | `rip_terr17_authdatalen0` | 负 | §7 N-13：AuthDataLen=0 | — |
| 51 | `rip_terr18_multicast_split` | 正 | §4⑦：组播跳过过滤 | 1 |
| 52 | `rip_terr19_afi_ffff_explicit` | 负 | §7 N-8：AFI=0xFFFF 显式 | — |
| 53 | `rip_terr1_version_v3` | 负 | §7 N-1：version=v3 | — |
| 54 | `rip_terr3_command_update` | 负 | §7 N-2：command=update | — |
| 55 | `rip_terr5_afi3` | 负 | §7 N-6：AFI=3 | — |
| 56 | `rip_terr6_afi_ffff` | 负 | §7 N-7：AFI=0xFFFF | — |
| 57 | `rip_terr7_auth_sha256` | 负 | §7 N-9：auth type=sha256 | — |
| 58 | `rip_terr8_auth_v1` | 负 | §7 N-10：v1 + auth | — |
| 59 | `rip_terr9_auth_ng` | 负 | §7 N-11：ng + auth | — |
| 60 | `rip_tpos16_3_routers` | 正 | §4⑤：3 router 各独立四元组 | 3 |
| 61 | `rip_tpos17_100_routers` | 正 | §4⑤：100 router 压力 | 100 |
| 62 | `rip_tpos18_default_routes` | 正 | §5 派生④：response_default 5 路由 | 1 |
| 63 | `rip_tpos1b_request_full_4tuple` | 正 | §5 派生③：request_full 同四元组 | 2 |
| 64 | `rip_tpos20_50_entries` | 正 | §8：50 条目（512B×2） | 2 |
| 65 | `rip_tpos21_51_entries` | 正 | §8：51 条目拆包 | 3 |
| 66 | `rip_tpos22_host_mask` | 正 | §8：主机路由 /32 | 1 |
| 67 | `rip_tpos23_ripng_128` | 正 | §8：RIPng 主机路由 /128 | 1 |
| 68 | `rip_tpos25_md5_authdatalen20` | 正 | §8：AuthDataLen=20 透传 | 1 |
| 69 | `rip_tpos28_8_routers` | 正 | §4⑤：8 router 并发 | 8 |
| 70 | `rip_tpos30_command_default` | 正 | §5 派生②：command 缺席默认 response | 1 |
| 71 | `rip_tpos3_26_entries` | 正 | §8：26 条目（v2 无认证拆包） | 2 |

T-编号对照：ID 前缀即 T 编号（`rip_tposN_*` = T-POS-N，`rip_tedgeN_*` = T-EDGE-N，`rip_terrN_*` = T-ERR-N）。机读分组计数：T-POS 32（全正）/ T-EDGE 22（17 正 + 5 负）/ T-ERR 17（3 正 + 14 负）= 71（设计 §9 同表）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count` + RIP 头字段断言 + 报文 hex 断言。通道分布见 §1。

### 3.1 场景族（#1、#2、#5、#19、#22、#62、#63、#70）

- `rip_tpos1_request_full`（2）：帧 1 offset 42 hex `01 02 00 00`（Request）；帧 2 offset 42 hex `02 02 00 00`（auto-Response）；`rip.command`=1（帧 1）/=2（帧 2）；`rip.version`=2（帧 1）；`rip.family`=`2,2,2,2,2`（帧 2 五条默认路由）；`udp.dstport`=520（帧 1）；`udp.srcport`=52001（帧 2）。
- `rip_tpos1b_user_routes`（2）：同 #1 但 Response 携带用户 1 条路由（`rip.family` 单值 2）。
- `rip_tpos1b_request_full_4tuple`（2）：两帧四元组完全相同（`udp.srcport`/`udp.dstport`/`ip.src`/`ip.dst` 逐帧同值）——同 FlowID 直接证据。
- `rip_tpos13_triggered`（1）：仅 1 报文（无 Request 前导）；`rip.command`=2；metric 断言。
- `rip_tpos18_default_routes`（1）：`rip.family`=`2,2,2,2,2`（5 条默认路由）。
- `rip_tpos30_command_default`（1）：command 缺席 → 头字节 1 = `0x02`。
- `rip_tpos29_version_default`（1）：version 缺席 → 头字节 2 = `0x02`。
- `rip_tpos7_rounds`（3）：rounds=3 → 3 个 Response 报文，各自独立 RIP 消息。

### 3.2 版本族（#3、#10、#20、#23、#31、#32、#67）

- `rip_tpos4_v1_broadcast`（1）：v1 → 广播；`ip.dst`=255.255.255.255；`rip.version`=1；`udp.length`=32（8+4+20）。
- `rip_tpos14_ripng`（1）：`ipv6.dst`=ff02::9；`ripng.cmd`=2；`ripng.version`=1；`ripng.rte.ipv6_prefix`；`ripng.rte.prefix_length`；`ripng.rte.metric`；offset **62**。
- `rip_tpos15_ripng_default`（1）：RIPng ::/0（PrefixLen=0）；offset 62/66/82。
- `rip_tpos23_ripng_128`（1）：PrefixLen=128 主机路由；wire 字节 0x80。
- `rip_tpos32_v1_multicast_broadcast`（1）：v1 + multicast → 广播（忽略用户 DstIP）；`ip.ttl`=1。
- `rip_tedge16_ripng_len0`（1）/`rip_tedge17_ripng_len128`（1）：PrefixLen 边界 0 / 128。

### 3.3 认证族（#6、#7、#8、#9、#21、#68）

- `rip_tpos8_simple_auth`（1）：帧 1 offset 42 hex `02 02 00 00 ff ff 00 02 73 65 63 72 65 74 31 32 33 00 00 00 00 00 00 00`（头 + AFI FFFF + Type 0002 + 密码 `secret123` 补零到 16B）；offset 66 hex `00 02 00 00 0a 00 00 00 ff 00 00 00 00 00 00 00 00 00 00 01`（AFI 2 + RouteTag 0 + IP 10.0.0.0 + 掩码 255.0.0.0 + metric 1）；`rip.auth.type`=2；`rip.auth.passwd`=`secret123`。
- `rip_tpos9_md5_auth`（1）：帧 1 offset 42 hex `02 02 00 00 ff ff 00 03 00 2c 01 10 00 00 30 39 00 00 00 00 00 00 00 00`（AFI FFFF + Type 0003 + **PacketLength 0x002c=44** + KeyID 01 + AuthDataLen 0x10=16 + Seq 0x3039=12345）；offset 86 hex `ff ff 00 01`（trailer marker + Type 0001）；`rip.digest_offset`；`rip.key_id`；`rip.auth_data_len`；`rip.seq_num`。
- `rip_tpos27_auth_25_routes`（2）：认证 + 25 路由 → 首包 24 条 + 次包 1 条。
- `rip_tpos27b_auth_26_routes`（2）：认证 + 26 路由 → 拆包，认证仅首包。
- `rip_tpos24_simple_auth_16b`（1）：密码恰 16B（不补零）；`rip.auth.passwd`。
- `rip_tpos25_md5_authdatalen20`（1）：AuthDataLen=20；trailer 24B；摘要占位 20B；offset 86/90。

### 3.4 组播/单播/过滤族（#4、#11、#12、#16、#17、#18、#48、#51）

- `rip_tpos6_multicast_ttl`（1）：`ip.dst`=224.0.0.9；`ip.ttl`=1；`udp.srcport`=520；`rip.metric`=2。
- `rip_tpos5_unicast`（1）：`ip.dst`=192.168.1.2；`ip.ttl`=64；`udp.dstport`=520。
- `rip_terr14_multicast_overrides`（1）：multicast=true 时用户 DstIP 被覆盖（`ip.dst` 仍 224.0.0.9）。
- `rip_tpos10_split_horizon`（1）：`next_hop==dst_ip` 的路由被过滤（保留另一条）。
- `rip_tpos12_poison_reverse`（1）：两条都保留，`next_hop==dst_ip` 者 metric=16。
- `rip_tpos10_route_poison`（1）：metric=16 wire 字节 `00 00 00 10`。
- `rip_terr15_split_poison`（1）：split+poison 组合（单播保留两条）。
- `rip_terr18_multicast_split`（1）：组播跳过过滤（两条都保留）。

### 3.5 拆包/条目数族（#24、#26、#42、#43、#64、#65、#71）

- `rip_tedge7_25_entries`（1）：504B payload 单包；offset 42/66。
- `rip_tedge8_26_entries`（2）：25+1；offset 46/66。
- `rip_tedge9_50_entries`（2）/`rip_tpos20_50_entries`（2）：25+25；512B×2。
- `rip_tedge10_51_entries`（3）/`rip_tpos21_51_entries`（3）：25+25+1。
- `rip_tpos3_26_entries`（2）：v2 无认证 26 条拆包，同 FlowID。

### 3.6 边界值族（#13、#14、#15、#25、#28、#29、#30、#38、#39、#66）

- `rip_tedge6_zero_routes`（1）：显式空路由 → 裸 4B 头（`udp.length`=12）。
- `rip_tedge11_default_route`（1）：0.0.0.0/0 metric=1 透传。
- `rip_tpos33_domain`（1）：domain=1（头字节 2-3 = `00 01`）。
- `rip_tedge19_domain_ffff`（1）：domain=0xFFFF 透传（`ff ff`）。
- `rip_tedge13_mask_zero`（1）/`rip_tedge14_mask_ffff`（1）：掩码 `00 00 00 00` / `ff ff ff ff`。
- `rip_tedge15_mask_noncontig`（1）：非连续掩码 `ff 00 00 03` 透传（offset 42 含掩码起、58 掩码尾、62 metric）。
- `rip_tedge2_metric1`（1）/`rip_tedge3_metric16`（1）：wire metric `00 00 00 01` / `00 00 00 10`。
- `rip_tpos22_host_mask`（1）：/32 主机路由。
- `rip_tedge20_default_routes`（1）：routes=nil + scenario 缺席 → 5 条默认路由（帧级 offset 42/46/66/86/106/126）。

### 3.7 多路由器族（#36、#37、#60、#61、#69）

- `rip_tedge21_routers_empty`（1）：routers=[] → 单 router 用 FlowSpec 四元组；`udp.srcport`=520。
- `rip_tpos16_3_routers`（3）：3 router 各自 SrcIP；`udp.srcport` 聚合 = 52001/52002/52003。
- `rip_tpos28_8_routers`（8）：8 router 各 1 报文；`udp.srcport` 聚合 52001…52008。
- `rip_tpos17_100_routers`（100）：100 router 压力；`group_id` fixed（同 worker）。
- `rip_tedge22_routers_100_inc`（100）：100 router + `group_id` inc [1,100] → 100 个不同 group id。

**正例总则**：metric 1/16、掩码 0/全 1/非连续、PrefixLen 0/128、domain 0xFFFF、密码恰 16B、AuthDataLen=20 均为正例形态；只有配置/线格式/长度/值域错误进入负例。

## 4. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 UDP 外壳的假成功。锚词与设计 §7 表一一对应、同序（19/19 已机读实测逐字一致）：

| ID | 故障输入 | `error_contains` | 代码出处 |
|---|---|---|---|
| `rip_terr1_version_v3` | `version="v3"` | `invalid version` | `rip.go:118` |
| `rip_terr3_command_update` | `command="update"` | `invalid command` | `rip.go:102` |
| `rip_tedge1_metric0_err` | `metric=0` | `metric must be >= 1` | `rip.go:230` |
| `rip_tedge4_metric17_err` | `metric=17` | `metric must be <= 16` | `rip.go:233` |
| `rip_tedge5_metric255_err` | `metric=255` | `metric must be <= 16` | `rip.go:233` |
| `rip_terr5_afi3` | `afi=3` | `invalid AFI` | `rip.go:260` |
| `rip_terr6_afi_ffff` | 路由 `afi=0xFFFF` | `AFI=0xFFFF is reserved for authentication` | `rip.go:257` |
| `rip_terr19_afi_ffff_explicit` | 同上（显式形） | 同上 | 同上 |
| `rip_terr7_auth_sha256` | `auth.type="sha256"` | `invalid auth type` | `rip.go:160` |
| `rip_terr8_auth_v1` | `version="v1"` + auth | `RIP v1 does not support authentication` | `rip.go:153` |
| `rip_terr9_auth_ng` | `version="ng"` + auth | `RIPng does not support authentication` | `rip.go:156` |
| `rip_terr10_password_17b` | 密码 17B | `simple auth password must be <= 16 bytes` | `rip.go:165` |
| `rip_terr17_authdatalen0` | MD5 `auth_data_len=0` | `md5 auth_data_len must be > 0` | `rip.go:171` |
| `rip_tedge12_ip_bcast_err` | 路由 IP `255.255.255.255` | `broadcast address cannot be used as route` | `rip.go:299` |
| `rip_terr11_ip_invalid` | 路由 IP `999.1.1.1` | `invalid IP address` | `rip.go:242` |
| `rip_terr12_mask_invalid` | 掩码 `not-a-mask` | `invalid subnet mask` | `rip.go:268` |
| `rip_terr13_nh_v6` | v2 `next_hop` 为 IPv6 | `next_hop must be IPv4` | `rip.go:293` |
| `rip_terr16_router_empty` | `routers=[{}]` | `at least one field must be non-empty` | `rip.go:186` |
| `rip_tedge18_ripng_len129_err` | RIPng `prefix_len=129` | `prefix_len must be <= 128` | `rip.go:275` |

**负例原子性**：每例单一故障注入；单次执行不得混注。

**负例纯净性差异（诚实登记）**：存量 19/19 负例的 `expect` 键集合为 `{error_contains,expect_error,notes}`——**含 `notes`**（设计回指文本，非断言），与 moxa 范式的严格两键 `{expect_error,error_contains}` 不一致。`notes` 不参与判定（`VerifyPcap` 只读 `expect_error`/`error_contains`），但**代码阶段改写时统一删 `notes`**（可移入例对象顶层 `summary`/`notes` 或删）。属形状差异，非缺陷。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 1058/2453/2080/4822（§10 八项矩阵 + 三子表）+ 设计 §11 as-built 代码条目 + tshark 26 字段实测（`rip.*` 18 + `ripng.*` 8）→ 71 ID（本契约 §2）。第三源"已确认现网行为"当前 = **旧基线继承级**（Cisco/Juniper 默认行为，未达本批抓包级 → G-RIP-9，不冒充第三源）。

### 5.2 §9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 四篇规范反推 + 设计 §10 三子表 + 存量 71 例机读**（`rip.*`/`ripng.*` 字段实测在册），**非纯现有用例反推**。
- **对账两行**：**要求逻辑点总数 = 89**（八项矩阵 8 + 子表① 12 格 + 子表② 50 行 + 子表③ 10 行 + §3.15 三项 3 + 性能六类 6；逐表重数见设计 §10.1–10.4/§6）；**用例覆盖数 = 75**（八项已覆 5〔行 1/2/4/5/8〕+ 子表① 已覆 7 + 子表② 50 + 子表③ 已覆 8 + §3.15 等价面 0 + 性能已覆 5〔基线/目标规模/压力上限/长时间/背压〕）；**不适用 = 13**（八项 3〔行 3/6/7〕+ 子表① 4 + 子表③ 2 + §3.15 三项 3 + 性能 1〔并发交错〕）；**立项 = 1**（子表① 空格 A′ `rip_ripng_request`）。**75 + 13 + 1 = 89 ✓**。
  **粒度声明**：行/格粒度每点 1 计；G-RIP-1…G-RIP-11 不折进 89。**反查全绿 ≠ 覆盖全**（§9.52 原文）。
- **门3 抽查候选**：最复杂用例 = **`rip_tpos17_100_routers`**（100 router × 独立四元组 × FlowID × group_id 绑定）或 **`rip_tpos27_auth_25_routes`**（认证 + 满包拆包 + 双报文）。交织维度 = router 数 × 认证 × 拆包 × 版本。若按 9.49/9.50 下限偏弱在"并发交错"面（RIP 无并发路径，顺序展开承载），**建议门3 抽 `rip_tpos27_auth_25_routes` + `rip_tpos16_3_routers`**。

### 5.3 T-编号与 ID 对照

ID 前缀即 T 编号（§2 表末行）：`rip_tposN_*` ≡ T-POS-N；`rip_tedgeN_*` ≡ T-EDGE-N；`rip_terrN_*` ≡ T-ERR-N。

## 6. 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | **不适用**——RIP 是 UDP 无连接，无"连接内多轮"概念；等价面 = 多轮通告（`rounds`） | `rip_tpos7_rounds`（3 轮）承载；无立项 |
| ② | 非正常结束 | **不适用**——UDP 无 FIN/RST；等价面 = 报文被拒绝（19 负例） | 19 负例承载 |
| ③ | 长保活 | **不适用**——RIP 无 keepalive 消息；等价面 = 多 router/多轮长序列 | `rip_tpos17_100_routers`（100 报文）承载 |

无空项：三项各有等价面承载 + 显式不适用理由。

### 6.2 A′/B′ 两分类表

**A′（代码阶段）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 层链化 | registry `Fields` 补十三键 + translate `case "rip"` 层内分支 | G-RIP-1/G-RIP-2，用例 #1–#71 全依赖 |
| 空格补齐 | RIPng Request | `rip_ripng_request`（设计 §10.2 唯一空格） |
| 游离键负例 | 白名单外顶层键判死 | `rip_neg_stray_src_ip`（今日已生效，探针实证） |
| presence 负例 | 层链 + 顶层空 `rip` 子映射 | `rip_neg_top_rip_presence`——**待 G-RIP-3 修复后**才建（今日建会真绿 = 假通过） |
| 形状统一 | 19 负例删 `expect.notes` | §4 末（代码阶段改写时执行） |

**B′（框架面）**：`CheckProtoFlat` rip presence 分支（G-RIP-3，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态（G-RIP-5，allowlist 无 `rip` 行）/ 离线 harness strip-layers（G-RIP-10，框架级 P6 票）。进设计 §14，「明确不解决 + 迁入计划」。

### 6.3 3.14 豁免边界审计

**无长连接协议 → `sessions[]` 豁免**（RIP 是 UDP 无连接，显式不适用，理由见设计 §5）；**但多流覆盖不豁免**：多 router 并发（#41/#42/#50/#34，3/8/100/100）与单包多载荷（#24/#26 多条目）各有用例。豁免成立且未架空多流覆盖。

## 7. 实现后执行建议

1. **代码阶段顺序**：G-RIP-1 + G-RIP-2（registry Fields 十三键 + translate 分支 + schemagen 重跑）→ 71 例改写（删顶层旧键 `src_ip/dst_ip/src_port/dst_port/count` + 顶层 `rip` 子映射迁层内；`count>1` 的 2 例补 `strategy_fc flows=N`；19 负例删 `expect.notes`）→ 先跑后钉 71 例 → 补 A′（`rip_ripng_request` + `rip_neg_stray_src_ip`）→ G-RIP-3 修复后再建 `rip_neg_top_rip_presence` → 全量复跑。
2. **实测顺序**：先 #4/#17（单报文基线与端口），再 #6/#7（认证 hex），再 #1（request_full 双包），再 #24/#26（拆包），最后 #10（RIPng offset 62 与 `ripng.*` 字段）、#41/#42（多 router 聚合）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=rip` 全量不是增量）；门2④ 反查绿后进 P6。
4. **离线套件注意**：`layer_chain_suite_test.go` 的 `chainSuiteProtos` 今日**不含 rip**（实测映射 0 命中）——不带 `CHAIN_PROTO=rip` 时 71 例全被 `loadChainCases` 跳过（默认全仓跑法不红）。单跑须 `CHAIN_PROTO=rip`，且需在 import 块补 rip 空导入（今日缺，G-RIP-10 关联）。
5. 任何 MD5 摘要占位的具体断言须有独立证据和失败优先测试（设计 §1 G-RIP-8 纪律）。

## 8. 存量审计（71 例逐条去向）

### 8.1 存量实测面（2026-09-28）

`cases/rip.json` **71 例**：52 正带 `packet_count`（1×36 / 2×9 / 3×4 / 8×1 / 100×2，全部 = 报文数）；19 负 `expect` 键集合 `{error_contains,expect_error,notes}`（含 `notes`，非纯净两键）；层链形 52 例层 config 恒 `{}`（空壳）；扁平形 19 例；**链/扁与正/负恰好同界**（52 正 = 52 链形，19 负 = 19 扁平形，机读实测）。

**顶层旧键逐键计数（脚本复算，链/扁分列）**：

| 键 | 链形(52) | 扁平(19) | 合计 |
|---|---:|---:|---:|
| `src_ip` | 5 | 2 | 7 |
| `dst_ip` | 12 | 2 | 14 |
| `dst_port` | 5 | 2 | 7 |
| `count` | 52 | 19 | 71 |
| `rip` | 52 | 19 | 71 |
| `src_port` | 52 | 19 | 71 |
| **合计** | **178** | **63** | **241** |

**两套口径**：**241** = 全 71 例旧键出现总次数；**178** = 非负例口径（= 链形 52 正例合计；19 扁平例全为负例，不计入判死面）。两数不得互换。

### 8.2 现状矛盾点（代码阶段前诚实登记）

1. **存量跑的是过渡态混合形，不是纯层链**：52 例的 `layers=[{udp:{}},{rip:{}}]` 只是**空壳**（`rip` 层 config 恒 `{}`，既不校验也不消费——探针实证层内业务键被拒 `unknown field "command"`），真实配置住顶层 `rip` 子映射 + 顶层四元组。
2. **MCP 真实路径今日 400**：52 层链例带顶层 `src_port` → `CheckProtoFlat` 通用五键检查命中（探针 `ValidateStrategy` 实证）；19 扁平例同 400。**71 例既非绿也非红**。
3. **离线套件今日不覆盖 rip**：`chainSuiteProtos` 无 rip（实测）→ 默认跑法跳过；补空导入后 `CHAIN_PROTO=rip` 实测 **52/52 全绿 58.5s**——**只有 52 个链形例被执行，19 个扁平例被 `layer_chain_suite_test.go:138` 的 `if _, ok := specMap["layers"]; !ok { continue }` 过滤器跳过、从未执行**（scratch 副本探针）。故"绿"仅证明 52 个链形例的断言在引擎侧有效，不覆盖 19 扁平例、也不证明 MCP 可达。
4. **presence 形今日不判死**：`CheckProtoFlat` 无 rip 分支（`grep -c` = 0）；探针 `{layers:[...],rip:{}}` → schema errs=0。**建该负例会真绿 = 假通过** → G-RIP-3 修复后才建。
5. **19 负例 `expect` 含 `notes`**：非严格两键（不参与判定，代码阶段统一删）。
6. **结果文档过期且不完整（G-RIP-11）**：tracked 结果产物 `trafficgen/docs/protocol-pcap-test/rip.md` 写 `Cases: 1 — pass 1, fail 0, error 0`——**只有 1 例**，与存量 71 例不符（本身即不完整产物）；末次提交 `a674fe9`（2026-09-05）早于判死提交 `0417be5`（2026-09-13）；`docs/protocol-pcap-test/rip/` **0 个 pcap**（目录不存在）。该 `1/1 pass` **是过期且不完整的产物，不得作为"套件可跑"依据**。rip 双重缺口：不完整（1 vs 71；19 扁平例另被 `layer_chain_suite_test.go:138` 跳过、从未执行）+ 过期（今日经 MCP 建策略全部 400）。归属**代码阶段**（P5 重跑套件后重生成）。

### 8.3 逐条去向表（71 行摘要，按组）

| 存量组 | 例数 | 去向 | 改写动作（G-RIP-1/G-RIP-2 落地时） |
|---|---:|---|---|
| T-POS（#1–#52 中 27 例） | 27 | **改写** | 目标形状化（`ip` 层地址 + `udp` 层端口 + `rip` 层十三键）；`packet_count` 不变（报文数） |
| T-EDGE 正（22 例中 15） | 15 | **改写** | 同上；边界值内联保留 |
| T-ERR 正（22 例中 2） | 2 | **改写** | 同上（`rip_terr14_multicast_overrides`/`rip_terr15_split_poison`/`rip_terr18_multicast_split` 属组合告警正例） |
| 多 router（#34/#42/#50） | 3 | **改写** | 四元组留空走保底递增；`group_id` 保留（白名单）；`count>1` 补 `strategy_fc flows=N` |
| 负例 19 例 | 19 | **改写** | `rip` 子映射迁层内；锚词不变；**删 `expect.notes`** |
| 合计 | **71** | 全改写 | 0 作废，0 等价覆盖 |

无"作废不注原因"：0 作废，0 等价覆盖（全部改写 + 4 新增 A′）。

## 9. 覆盖反查门建议断言行（供主线程合后登记 coverage gate，本车道不碰 `coverage_gate.py`）

以下为 `check_rip(cases)` 的建议检查项，供主线程在代码阶段落码后登记。**红项如实标红，不得作为"今日已过"申报**（ldp 先例）。

| # | 检查项 | 判据 | 今日 |
|---:|---|---|---|
| 1 | 白名单收 rip | `protocols.go` 含 `"rip": true` | 绿 |
| 2 | registry rip 行 | `DependsOn: []string{"udp"}` / `CategoryTerminal` | 绿（`registry.go:184`） |
| 3 | registry rip Fields 补全（G-RIP-1 落码后） | `fields` 键数 = 13（version/command/domain/routes/auth/multicast/scenario/routers/rounds/triggered_update/split_horizon/poison_reverse） | **红**（今日 `fields = {}`） |
| 4 | translate rip 严格解码分支（G-RIP-2 落码后） | `chain_planner_translate.go` 含 `case "rip":` 且含 `"rip layer config decode"` | **红**（switch 73 case 无 rip） |
| 5 | FlowMeta.RIP 直传 | `chain_planner_translate.go:64` 含 `RIP:    spec.RIP` | 绿 |
| 6 | FlowMeta.RIP 字段 | `generator.go` 含 `RIP` 字段 | 绿 |
| 7 | FlowSpec.RIP 字段 | `types.go` 含 `RIP *RIPConfig` | 绿 |
| 8 | main.go 空导入 + ChainPlanner | `internal/protocol/rip` 在 `main.go` 且 `NewChainPlanner("rip")` 在册 | 绿 |
| 9 | 目的端口不静态默认化 | `chain_planner.go:1132` 含 `case "rip":` 且 `spec.DstPort = 0` | 绿 |
| 10 | SrcPort 不静态默认化 | `chain_planner.go:913` 含 `case "rip":`（保持 0） | 绿 |
| 11 | isRIPChain 豁免 | `chain_planner_util.go:161` 含 `isRIPChain` 且 `applySpecToChain` ip 分支引用 | 绿 |
| 12 | generated schema rip 条目同代 | `layers.generated.json` 的 `rip.depends_on == ["udp"]` | 绿 |
| 13 | CheckProtoFlat 顶层 rip presence 判死（G-RIP-3 落码后） | `strategy_convert.go` 含 `protocol rip no longer accepts a top-level rip sub-config` | **红**（`grep -c` = 0；探针 presence 形 errs=0） |
| 14 | 顶层 rip presence 零残留（非负例） | 无「有 `layers` + 顶层 `rip` dict + 非 `expect_error`」的例；存量 **52 例命中** | **红**（待代码阶段收敛） |
| 15 | 正例顶层键白名单（§1.11/§1.13 判据：非负例顶层键 = 0） | 非负例顶层键 ⊆ `{layers, strategy_fc, ttl, flow_control, output, output_config, group_id}`；存量 **178 处残留**（`count` 52 / `rip` 52 / `src_port` 52 / `dst_ip` 12 / `src_ip` 5 / `dst_port` 5） | **红**（待代码阶段收敛） |
| 16 | 命令 × 版本 × 认证矩阵 | cases 中命令/版本/认证取值组合 ⊇ 设计 §10.2 已覆 7 格 | 绿（除 `rip_ripng_request` 立项） |
| 17 | 负例锚词 19/19 | 19 负例 `error_contains` 集与 `rip.go` 字面值一一对应 | 绿 |
| 18 | 负例 expect 纯净 | 19/19 `expect` 键严格 `{expect_error,error_contains}` | **红**（今日含 `notes`，代码阶段删） |
| 19 | packet_count = 报文数 | 52 正例 = routers × rounds × ceil(entries/25) | 绿 |
| 20 | RIPng 字段族分离 | ng 例断言走 `ripng.*` 而非 `rip.*` | 绿 |

**注**：第 3/4/13/14/15/18 项今日为红（G-RIP-1/G-RIP-2/G-RIP-3/G-RIP-4 未落码 + 形状未统一），属**登记在案的缺口**，不得作为"今日已过"申报。**另注意**：`docs/protocol-pcap-test/rip.md` 的 `1/1 pass` 是过期且不完整的产物（G-RIP-11），不得作为"套件可跑"依据。

## 10. 修订记录

- v1.0.1（2026-09-28）：**补登记 G-RIP-11（结果产物过期且不完整）**——`docs/protocol-pcap-test/rip.md` 的 `1/1 pass` 系过期且不完整产物（末次提交 `a674fe9` 2026-09-05 早于判死提交 `0417be5` 2026-09-13；存量 71 例 vs 产物 1 例；`docs/protocol-pcap-test/rip/` 0 个 pcap），归属代码阶段（P5 重跑套件后重生成）。落点：§8.2 第 6 条（现状矛盾点）+ §9 覆盖反查门表末「注」段提醒句；缺口表/复算证据见设计 §14/§12-P4。口径对齐 pcep 先例 G-PCEP-11。仅文档，未动 JSON/代码。
- v1.0.0（2026-09-28）：文档先行批次一 #96。**新建**（旧基线只有 `10-rip-design.md`，无 testcase 文档，G-RIP-6）。
  **本版按主线程裁定交付：cases/rip.json 不改写**——层空壳实证（设计 §12-P3 三条探针证据原文）；改写会打断 52 例存量离线绿且新 JSON 仍不可经 MCP 调用（违反 §14.1）。
  缺口编号按主线程口径：G-RIP-1（层空壳）/ G-RIP-2（translate 缺 case）/ G-RIP-3（CheckProtoFlat 无 rip 分支）/ G-RIP-4（顶层旧键 178 处）/ G-RIP-5…G-RIP-10。
  内容：71 ID（52 正 + 19 负）全量继承并逐条回指设计；形状基线机读实测（§1，含断言通道 24 字段分布与 offset 10 档分布）；§2 索引顺序 = JSON 顺序；§3 正例 7 族断言契约；§4 负例 19 锚词逐条对码 + `notes` 差异登记；§5 对账两行（**89 = 75 + 13 + 1**）；§6 固定动作（3.15 三项 + A′/B′ + 3.14）；§7 执行建议（含离线套件 rip 缺席实证）；§8 存量 71 例去向；**§9 覆盖反查门建议断言行 20 项（6 项红如实标注，ldp 先例）**。
  自审 4 轮，末轮干净（结论见 /tmp/pipe/doc-lanes/rip.md）。

# PIM（协议无关组播，Protocol Independent Multicast）四件套对抗审查

> 审查对象：`docs/protocol-designs/40-pim-design.md`、`docs/protocol-designs/40-pim-testcase.md`、`trafficgen/test/protocol_pcap/cases/pim.json`
> 审查日期：2026-08-20
> 审查口径：设计文档阶段；不检查、不修改 Go（编程语言）实现，不把 `pim` 层未注册视为缺陷。
> 结论：本轮按设计逻辑和用例覆盖两个独立视角复核；最后一轮静态检查 clean（通过）。

## 1. 审查方法

### 1.1 设计逻辑视角

从 RFC 7761 PIM-SM（稀疏模式）和 RFC 4607 PIM-SSM（源特定组播）的范围、IPv4 Protocol 103 载体、PIMv2 4-byte common header（公共头）、Internet checksum、Hello options、Join/Prune source trees、Bootstrap/RP-set、Candidate-RP、Register/Register-Stop、Assert 和状态边界反向审查。特别检查：

- PIM 没有自身 length 字段；长度通过 IPv4 total length 和编码结果确定。
- PIM checksum 只覆盖 PIM packet，不把 IPv4 header checksum 或 Ethernet padding 混入。
- `(*,G)` wildcard（通配源）与具体 `(S,G)` 的状态和地址语义分离；SSM 不能降级为 RP/共享树。
- DR election（DR 选举）与 Bidirectional PIM DF Election（双向 PIM 指定转发器选举）分开；DF 只作为独立 profile 负例。
- IPv6 profile 不复制 IPv4 PIM 的地址编码/checksum；未验证的 encoded-address 保留字节不写成长固定 hex。
- 重传是显式完整事件，不能自动补发响应或虚构 sequence number。

### 1.2 用例覆盖视角

从设计 §8 的 24 个 ID 反查 testcase 和 JSON，确认每条正例均有：`packet_count`、`has_payload=true`、observable `fields`、offset 34 的 `frames`；每条负例的 `expect` 仅有 `expect_error` 与 `error_contains`。检查正例是否逐项触达 Hello/计时器、Join/Prune 两种树、多组、多邻居、显式重传、Bootstrap/RP hash/priority、Candidate-RP、Register、Register-Stop、Assert、SSM 和错误边界。

## 2. 设计逻辑审查结果

### D-01 载体和公共头（通过）

设计只允许 `ip→pim` 的 IPv4 profile，固定 Protocol 103；PIM 起点 offset 34。公共头明确为 Version/Type、Reserved、Checksum 四字节，Type 0/1/2/3/4/5/8 与事件表一致。未把 PIM 当 UDP/TCP payload，也没有凭空加入 PIM length。

### D-02 checksum 与长度（通过）

checksum 算法被限定为完整 PIM packet 的 Internet checksum，编码后回填；IPv4 header 和 Ethernet padding 被排除。正例只观察非零值，避免未经 fixture 验证的常量。length 负例用 IP total/body 边界注入，契约没有把最小以太网帧长度冒充 PIM 长度。

### D-03 RFC 7761 事件语义（通过）

Hello 的 Holdtime、Hello interval、LAN Prune Delay、DR Priority、Generation ID 分开配置；PCAP 字段使用 `pim.holdtime`、`pim.interval` 仅限 State Refresh、`pim.t`、`pim.propagation_delay`、`pim.override_interval`、`pim.dr_priority`、`pim.generation_id`；Hello interval 只作调度元数据；Join/Prune 有上游邻居、group、joined/pruned source，分别覆盖 wildcard 和具体 `(S,G)`。Bootstrap/C-RP 的 BSR、hash mask、RP priority/Holdtime/group prefix 均是显式字段；Register 的 inner IPv4、Register-Stop 的 group/source、Assert 的 RPT/metric 不互相继承。

### D-04 状态和选举边界（通过）

状态键按 interface+neighbor+group+source 分隔，正例包含 upstream/downstream 标签、多邻居、多组和重复事件。DR election 只把 priority/address winner 作为会话元数据；DF Election 不伪造成 RFC 7761 类型，使用独立 profile 负例。PIM-SM 与 PIM-SSM profile 互斥，SSM 只允许具体 `(S,G)`。

### D-05 IPv6 和未验证字节（通过）

IPv6 输入只走拒绝边界，不产生 IPv4 PIM 成功 PCAP；设计明确 IPv6 PIM 需要独立 profile。encoded-address 的保留字段、mask/计数没有编造固定值，frame 只锚定已确认的公共头前缀。

## 3. 用例覆盖对抗审查

| 覆盖项 | JSON ID | observable / 结果 |
|---|---|---|
| Hello Holdtime/checksum（interval 为调度元数据） | `pim_sm_hello_holdtime` | Protocol 103、type、Holdtime、checksum、frame；Hello interval 为调度元数据；通过 |
| Hello options/DR priority/Generation ID | `pim_sm_hello_options` | option 字段、priority、Generation ID、frame；通过 |
| Holdtime=0 | `pim_sm_hello_zero_holdtime` | 零值字段和 frame；通过 |
| `(*,G)` | `pim_sm_joinprune_wildcard` | wire-level 组/上游邻居、join/prune count；通过 |
| `(S,G)` | `pim_sm_joinprune_source` | wire-level source、组、两类 count；通过 |
| multi-group/multi-source | `pim_sm_joinprune_multi_group` | group/source 列表和 count；通过 |
| explicit retransmission | `pim_sm_joinprune_retransmit` | 两包、type、重传标记、树标识；通过 |
| Bootstrap/RP hash/priority | `pim_sm_bootstrap_rp_set` | BSR、hash mask、RP 地址/priority；通过 |
| Candidate-RP | `pim_sm_candidate_rp_adv` | type、RP、priority/Holdtime/prefix count；通过 |
| Register/Register-Stop | `pim_sm_register`, `pim_sm_register_stop` | flags/inner IPv4 与显式 group/source；通过 |
| Assert | `pim_sm_assert` | group/source、RPT、metric；通过 |
| DR election | `pim_sm_dr_election` | 三邻居 priority/address 和 winner metadata；通过 |
| multi-neighbor state | `pim_sm_multi_neighbor_state` | 六事件逐包 wire-level upstream/group/source；状态元数据另行记录；通过 |
| checksum/length boundary | `pim_sm_checksum_length` | `ip.len`、`pim.cksum`、公共头；无伪造 PIM length；通过 |
| SSM single/multi group | `pim_ssm_joinprune_sg`, `pim_ssm_multi_group` | 具体 source、无 RP、组隔离；通过 |
| `pim_neg_ipv6_profile` | IPv6 profile | 仅 `expect_error` + `profile`；通过 |
| `pim_neg_checksum` | checksum fault | 仅 `expect_error` + `checksum`；通过 |
| `pim_neg_length` | IP/PIM length fault | 仅 `expect_error` + `length`；通过 |
| `pim_neg_type` | unknown type | 仅 `expect_error` + `type`；通过 |
| `pim_neg_address_family` | IPv4/IPv6 mix | 仅 `expect_error` + `address`；通过 |
| `pim_neg_ssm_rp` | SSM/RP violation | 仅 `expect_error` + `ssm`；通过 |
| `pim_neg_df_profile` | DF profile boundary | 仅 `expect_error` + `df`；通过 |

## 4. 机器契约静态检查

执行并确认：

```text
python3 -m json.tool trafficgen/test/protocol_pcap/cases/pim.json
24 个 id 唯一；17 个正例均含 packet_count + fields + frames；7 个负例 expect 仅含 expect_error/error_contains
全部正例 frame offset=34；全部正例 frame hex 从 PIM Version/Type 公共头开始
```

本套件未运行协议 suite，因为 `pim` 实现和层注册明确不在本任务范围。后续实现时仍需补：RFC 7761 encoded-address 的逐字节 fixture、checksum 数值测试、IP total length 负例的真实 planner→engine→task error 集成测试，以及 RFC 7761/4607 profile 的真实 PCAP/NIC（网卡）证据。

## 5. 结论与剩余风险

本四件套在设计阶段闭环：ID、顺序、包数、公共头 offset、正负 expect 结构一致；没有将 IPv6、DF Election、未知 PIM 类型或未验证地址编码冒充已实现事实。剩余风险全部是实现阶段门槛，而非本次文档缺陷：PIM encoded-address 字段/计数的字节 fixture、RFC checksum 复算、真实长度错误传播和 PIM-SM 状态机集成。

- 审查结论：通过。
- 自审结论：自审通过 2 轮，最后一轮 clean。

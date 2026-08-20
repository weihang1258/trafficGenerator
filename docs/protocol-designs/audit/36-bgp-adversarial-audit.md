# BGP（边界网关协议，Border Gateway Protocol）三件套对抗审查

> 审查日期：2026-08-20  
> 对象：`36-bgp-design.md`、`36-bgp-testcase.md`、`trafficgen/test/protocol_pcap/cases/bgp.json`  
> 属性：设计文档阶段审查；无 Go（编程语言）实现，不执行协议正例 suite（测试套件）验收。  
> 结论：两轮自审后 clean（通过）；RFC 4271 基础 profile、IPv6 transport 边界、MP_REACH 待实现边界和负向错误契约闭环。

## 1. 审查口径

- **规格可实现性视角**：逐字段核对 TCP/179、BGP 通用头 19 字节、marker/length/type、OPEN、KEEPALIVE、UPDATE、NOTIFICATION、邻接状态和 IPv4/IPv6 transport；检查 profile 没有把 MP_REACH、capability、4-octet ASN 或认证细节伪造成 RFC 4271 基础线格式。
- **用例覆盖视角**：逐行反查设计错误表和场景表；每个正例检查 observable、包数、帧偏移和原始字节；每个负例检查仅有 `expect_error/error_contains`。
- **静态检查**：加载 JSON，检查唯一 ID、正负分类、十六进制可解析、marker/length 自洽、offset、TCP 事件包数和多 session 聚合断言。

## 2. 规格可实现性审查

### 2.1 已确认

1. **通用头完整**：每条固定 frame 都有 16 字节全 `ff` marker、2 字节总 length、1 字节 type；最小 KEEPALIVE 为 19 字节，OPEN 为 29 字节，NOTIFICATION 为 21 字节。
2. **OPEN 字段边界明确**：version=4、My AS/hold time 的 2 字节网络序、IPv4 BGP identifier、optional parameters length=0；没有伪造 capability 或认证参数。
3. **UPDATE 属性可复算**：ORIGIN、AS_PATH、NEXT_HOP、MED、LOCAL_PREF、COMMUNITIES 组合的 path attribute 总长为 39；/24 NLRI 为 `18 cb 00 71`，/32 NLRI 为 `20 c0 00 02 01`；withdrawn length 和 total attribute length 均显式断言。
4. **状态边界明确**：OPEN 交换后才能 KEEPALIVE/UPDATE；NOTIFICATION 是合法应用事件且随后终止，不被当成 planner error；connect 不隐式插入应用报文。
5. **地址族隔离**：IPv6 仅改变 IP/TCP 外层，BGP identifier 仍为 IPv4，基础 profile 的 NLRI 仍为 IPv4；MP_REACH IPv6 独立作为 pending profile，不写未核实字节。
6. **错误传播目标明确**：UDP carrier、marker、length、type、OPEN version、My AS、状态和地址族各有负例；任务必须进入错误终态，不能成功生成空 PCAP。

### 2.2 实现阶段守护项（不是当前文档 finding）

| 项目 | 已写契约 | 实现前必须补充 |
|---|---|---|
| UPDATE attribute flags | RFC 4271 基础五类属性和 community 已固定 | 每类属性编码器的字节级单测、重复属性策略 |
| 状态机 | OPEN→Established→UPDATE/KEEPALIVE；NOTIFICATION 末尾 | 双向 OPEN、重复 OPEN、缺失 OPEN、取消/终止分支的实现验证 |
| IPv6 transport | IPv6 TCP + IPv4 BGP identifier | IPv6 checksum/PCAP 解码、frame offset 74 与 stream 重组 |
| 多 session | sessions 独立四元组、聚合端口断言 | 每条流独立状态、TCP sequence、worker 交织下的集成测试 |
| MP_REACH/capability/ASN4 | 明确 pending，不静默降级 | RFC 4760/RFC 5492/RFC 6793 版本化 profile 和 fixture |
| MSS | 设计要求分段时 stream 验证 | 禁止用固定 frame offset 代替 TCP 重组断言 |

这些是实现前的守护项，不是对当前设计/用例的缺陷判定。

## 3. 用例覆盖对抗审查

### 3.1 正例逐条核对

| id | 设计覆盖 | JSON observable | 结果 |
|---|---|---|---|
| `bgp_connect` | TCP/179 connect、无隐式 BGP 事件 | packet_count=7、握手/终止、无 payload | 通过 |
| `bgp_open_keepalive` | 双向 OPEN、双向 KEEPALIVE | type/version、4 个固定 RFC frame | 通过 |
| `bgp_update_attributes` | IPv4 UPDATE + 六类属性 | type、withdrawn/path length、属性字段、/24、完整 frame | 通过 |
| `bgp_update_withdraw` | IPv4 /24 withdrawn route | type、withdrawn length=4、attribute length=0、/24 frame | 通过 |
| `bgp_notification_hold_expired` | NOTIFICATION code=4/subcode=0 | type、major/minor 字段、21 字节 frame | 通过 |
| `bgp_hold_time_zero` | OPEN hold time=0 合法边界 | 双 holdtime、KEEPALIVE、OPEN/KA frame | 通过 |
| `bgp_ipv4_nlri_32` | /32 前缀四字节边界 | type、prefix_length=32、/32 frame | 通过 |
| `bgp_ipv6_transport` | IPv6 TCP transport + IPv4 identifier | ipv6.version、端口、identifier、offset=74 frame | 通过 |
| `bgp_multi_session` | 两个独立四元组 | srcport distinct=12345/12346、dstport=179 | 通过 |
| `bgp_keepalive_length_boundary` | RFC 4271 合法最小 length=19 | length/type、完整 19 字节 frame | 通过 |

### 3.2 负例逐条核对

| id | 设计错误行 | JSON expect | 结果 |
|---|---|---|---|
| `bgp_neg_udp` | UDP/缺 TCP carrier | 仅 `expect_error` + `tcp` | 通过 |
| `bgp_neg_mp_reach_profile` | 未登记 MP_REACH IPv6 profile | 仅 `expect_error` + `profile` | 通过 |
| `bgp_neg_marker` | marker 非全 `ff` | 仅 `expect_error` + `marker` | 通过 |
| `bgp_neg_length` | length 小于 19 | 仅 `expect_error` + `length` | 通过 |
| `bgp_neg_type` | type=9 | 仅 `expect_error` + `type` | 通过 |
| `bgp_neg_version` | OPEN version=3 | 仅 `expect_error` + `version` | 通过 |
| `bgp_neg_as` | My AS=70000 超出 2 字节 | 仅 `expect_error` + `as` | 通过 |
| `bgp_neg_state` | OPEN 前 UPDATE | 仅 `expect_error` + `state` | 通过 |
| `bgp_neg_address` | IPv4 profile 使用 IPv6 NLRI | 仅 `expect_error` + `address` | 通过 |

## 4. 三方静态一致性结果

执行独立检查加载设计、testcase 和 JSON 后核对：

- ID 集合：19 个，设计 §6/§7、testcase §2/§4、JSON 一致且唯一；正例 10 个、负例 9 个。
- 正例包数严格为 `[7,11,12,12,10,11,12,11,22,11]`；多 session 按每条流 `3+4+4=11` 后求和为 22。
- 正例全部 `has_handshake=true`、`terminates=true`；除 `bgp_connect` 外全部 `has_payload=true` 且有 fields/frames observable。
- IPv4 frame offset 只为 54；IPv6 transport 例只为 74；多 session 不使用固定 packet 序号绑定交织事件。
- 所有固定 frame 的 marker 为 16 字节全 `ff`，header length 与 frame 实际字节数相等；UPDATE 属性长度=39、KEEPALIVE length=19、NOTIFICATION length=21 可独立复算。
- 负例 `expect` 严格只有 `expect_error` 和 `error_contains`，没有 packet_count、fields 或 frames。

## 5. Findings（发现项）

### F-01（已修复：多 session 包数公式表述）

初稿的通用公式未在测试文档索引附近明确“多 session 按每条 TCP 四元组独立计算后求和”，容易把 8 个事件错误套成 15 包。已同步补充公式说明，并以 JSON 的 `packet_count=22` 和两组各 4 事件复算；当前三方一致。

### F-02（保留为实现边界：MP_REACH/能力协商字节）

RFC 4271 基础 profile 不足以支持 IPv6 NLRI 的 MP_REACH、能力协商和 4-octet ASN。文档没有伪造这些 payload，而是将 `bgp_mp_reach_ipv6_pending` 明确设为拒绝 profile；待取得 RFC 4760/RFC 5492/RFC 6793 版本化实现依据后另增 profile/cases。

## 6. 结论与自审记录

BGP RFC 4271 基础 profile 的 design/testcase/JSON/audit 已形成闭环：TCP/179、通用头、OPEN、KEEPALIVE、UPDATE 属性、NOTIFICATION、邻接状态、IPv4/IPv6 transport、多 session、length/marker/type/version/AS/address 负例均有契约和 observable。由于 `bgp` 层尚未实现，未虚报运行时 suite 通过。

自审完成 **两轮**：第 1 轮独立逐字节复算 marker、length、OPEN/KEEPALIVE/UPDATE/NOTIFICATION、属性长度、prefix 边界和包数，发现并修复 F-01；第 2 轮反查设计→testcase→JSON 的 19 个 ID、正负 expect 结构、offset 和多 session 聚合断言，未发现新问题；**最后一轮 clean（通过）**。

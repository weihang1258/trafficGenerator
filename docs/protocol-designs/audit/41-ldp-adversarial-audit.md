# LDP（标签分发协议，Label Distribution Protocol）四件套对抗审查

> 审查对象：`41-ldp-design.md`、`41-ldp-testcase.md`、`trafficgen/test/protocol_pcap/cases/ldp.json`
> 基线：RFC 5036；本机 Wireshark/tshark（网络分析器）字段注册表
> 状态：设计阶段；未运行生成器，不把未注册 `ldp` 层描述成已实现。

## 1. 审查方法

本审查分为两条独立视角：

1. 设计逻辑：逐项检查 RFC 5036 范围、UDP/TCP 载体、方向/端口、公共头、message/TLV length、FEC/label 边界、控制模式、邻接/session 状态和 IPv6 profile 边界。
2. 用例覆盖：逐项检查 JSON ID、顺序、正负结构、packet_count、fields、frames、offset 与本机 `tshark -G fields` 结果；对可能的固定顺序假设进行反证。

## 2. 设计逻辑审查结果

### D-01 载体与方向/端口（通过）

设计明确 UDP/646 只承载 discovery Hello，TCP/646 承载 session。UDP 正例显式 646→646；TCP 正例显式 50000→646，方向通过事件字段表达。没有把 LDP 写成 IP protocol number，也没有把 TCP application event 放入 UDP 正例。

### D-02 Common header 与长度层级（通过）

公共头固定 Version/PDU Length/LSR ID/Label Space ID；message length 明确包含 Message ID 但不含 Type/Length；TLV length 明确只含 Value。S1、S2、S9 的 frame 可逐字节复算这些边界。错误表分别使用 `pdu`、`message`、`tlv` 关键词，避免不同层级混淆。

### D-03 RFC 5036 消息覆盖（通过）

正例覆盖 Hello、Initialization、KeepAlive、Address、Label Mapping、Label Request、Label Withdraw、Label Release、Notification；Request/Mapping 另有 ordered+DoD 场景。未把未配置的自动响应或真实路由收敛写成已完成行为。

### D-04 FEC 与 label 边界（通过）

/24 和 /32 均为 IPv4 Prefix FEC，FEC type=2、AF=1；/24 使用 3 个前缀字节，/32 使用 4 个。Generic Label 以 32-bit 字段承载但契约要求 20-bit 值；N8 使用 0x100000，正例使用 0x12345/0xABCDE。IPv6 FEC 没有被伪造为正例。

### D-05 DU/DoD、control 与邻接（通过）

设计同时登记 `downstream_unsolicited`/`downstream_on_demand` 与 `independent`/`ordered`；S12 将 ordered+DoD 与 Request→Mapping 顺序绑定。S9/S10/S14 区分 targeted/basic discovery；S13 定义独立四元组 session，不能共享 state。

### D-06 IPv6/profile 边界（通过）

IPv6 transport/profile 未定义；N3 必须以 `profile` 拒绝，不能从 IPv6 outer IP 推断 IPv6 FEC 能力。设计另列 VPN/VC/PW、capability、TCP MD5/AO 等待实现边界。

### D-07 checksum 语义（通过）

设计明确 LDP 不定义自身 checksum，外层 `ip.checksum`、`tcp.checksum`、`udp.checksum` 不能被称为 LDP checksum。避免了把传输层校验误写进 RFC 5036 公共头。

## 3. 用例覆盖对抗审查

### 3.1 正例逐条核对

| ID | 关键覆盖 | 观察检查 |
|---|---|---|
| S1 `ldp_tcp_initialization` | TCP/646、公共头、Initialization 参数 | packet 4 fields + offset 54 frame |
| S2 `ldp_tcp_keepalive` | 双向 KeepAlive、空参数 | message type/len/id/PDU len + frame |
| S3 `ldp_address_ipv4` | Address List IPv4 | Address TLV fields + frame |
| S4 `ldp_label_mapping_ipv4` | /24 Mapping + label | FEC fields + Generic Label + frame |
| S5 `ldp_label_request_ipv4` | /24 Request 无 label | Request/FEC fields + frame |
| S6 `ldp_label_withdraw_ipv4` | Mapping→Withdraw | packet 7 message/FEC/label + frame |
| S7 `ldp_label_release_ipv4` | Mapping→Release | packet 7 与 Withdraw 分离 + frame |
| S8 `ldp_label_mapping_host32` | /32 host route | prefix length 32 + 4-byte prefix + frame |
| S9 `ldp_udp_targeted_hello` | targeted UDP discovery | UDP ports、Hello、targeted、transport address |
| S10 `ldp_udp_parallel_hellos` | basic Hello 两方向 | 两个 packet 的方向端口与 frames |
| S11 `ldp_notification_shutdown` | Notification/Status | type/TLV/status + frame |
| S12 `ldp_ordered_dod_allocation` | ordered + DoD | Request/Mapping 次序与 label |
| S13 `ldp_tcp_multi_session` | parallel TCP sessions | distinct ports/LSR IDs，不假设交织 |
| S14 `ldp_dual_adjacency` | basic+targeted+TCP | 双 discovery 与 session 载体边界 |

所有正例均有 `packet_count`、`fields`、`frames`；TCP/UDP offset 分别为 54/42。S13 是唯一使用聚合 distinct 断言的多 session 例，避免 scheduler（调度器）顺序假设；S14 作为显式 aggregate（聚合）契约，同时保留每个载体的 frame 锚点。

### 3.2 负例逐条核对

| ID | 故障 | 断言 | 结构检查 |
|---|---|---|---|
| N1 `ldp_neg_carrier` | 缺 carrier | carrier | 仅两个 expect 键 |
| N2 `ldp_neg_port` | 非 646 | port | 仅两个 expect 键 |
| N3 `ldp_neg_ipv6_profile` | 未定义 IPv6 | profile | 仅两个 expect 键 |
| N4 `ldp_neg_pdu_length` | PDU 边界 | pdu | 仅两个 expect 键 |
| N5 `ldp_neg_message_length` | message 边界 | message | 仅两个 expect 键 |
| N6 `ldp_neg_tlv_length` | TLV 边界 | tlv | 仅两个 expect 键 |
| N7 `ldp_neg_unknown_message` | unknown type | unknown | 仅两个 expect 键 |
| N8 `ldp_neg_label_bounds` | label 越界 | label | 仅两个 expect 键 |
| N9 `ldp_neg_prefix_bounds` | prefix >32 | prefix | 仅两个 expect 键 |
| N10 `ldp_neg_state` | 状态顺序 | state | 仅两个 expect 键 |
| N11 `ldp_neg_checksum` | 传输校验和故障 | checksum | 仅两个 expect 键 |

N4–N6 分别守护三层长度，不能由一个“malformed”负例代替；N8/N9 不能由字段存在性断言代替。

## 4. 机器契约静态检查

本轮对文件执行：

- JSON 解析：通过。
- ID 唯一性与顺序：四件套均声明 25 个 ID（14 正、11 负）；JSON 顺序为 S1–S14、N1–N11。
- 正例结构：14/14 有 `packet_count`、`fields`、`frames`；负例 11/11 的 `expect` 键集合严格为 `expect_error,error_contains`。
- 字段注册：使用的 `ldp.*` 字段均来自本机 `tshark -G fields` 查询；未写 `ldp` 未注册的 nested 字段。
- 载体偏移：UDP frame offset=42；TCP frame offset=54；未对 TCP 分段宣称固定 offset。
- 文档/JSON 包数表：S1–S14 为 `[9,11,10,10,10,11,11,10,1,2,10,11,22,12]`。

## 5. Findings（发现项）

### F-01（已修复：S1 PDU length 算术）

初稿把 Initialization 的长度写错；按 RFC 5036 Common Session Parameters Value=14 字节，当前统一为 TLV length=14、Message length=22、PDU length=32，并重新复核初始化 frame。该 finding 不涉及 Go 实现。

### F-02（已修复：正例数量闭环）

初稿先写 12 正例/22 总 ID，后增加 multi-session 与 dual-adjacency；已同步 design/testcase/audit 为 14 正例、11 负例、25 总 ID，JSON 顺序已复核。

### F-03（已修复：Initialization Protocol Version）

第二轮复核发现 S1/S2 等初始化 frame 的 Common Session Parameters Protocol Version 初稿为 2，而 RFC 5036 基础 profile 与设计约束均为 1；已将 JSON fields 与所有初始化 frame 的对应字节统一为 1。

### F-04（保留：dual-adjacency 使用显式 aggregate 层链输入）

当前 `ldp` 层未注册，S14 的 `dual_adjacency` 配置名是未来实现契约，不能运行或宣称已支持。它保留在套件中是为了锁定 basic/targeted/TCP 三者边界；实现时需先定义 aggregate schema，再把 packet_count=12 作为可执行契约。

### F-05（保留：tshark 字段值格式）

`tshark -G fields` 已确认字段名称；不同 tshark 版本对十六进制字段的显示可能是 `0x0200` 或十进制。实现后以本机实际 `-T fields` 输出为准，必要时仅调整 JSON value 表示，不新增未注册字段或改变语义覆盖。

## 6. 自审记录与结论

### Round 1

发现 F-01（S1 PDU length）、F-02（ID 数量闭环）；修复后重新生成 JSON、同步三份文档，并检查 JSON 解析。

### Round 2

逐条复核 25 个 ID、正负 expect shape、TCP/UDP offset、字段注册和帧十六进制。发现 F-03（初始化 Protocol Version）并确认 F-04 是实现阶段边界；修复 F-03 后未再发现矛盾。

### Round 3

重新复核 Protocol Version=1 的初始化 frame、字段断言、25 ID 数量、负例键集合和注册字段；发现无新增问题。

### Round 4

对 label control/advertisement 显式配置、FEC prefix string 断言、所有正例 carrier/端口和最后的 JSON shape 做反证检查；发现无新增问题，最后一轮 clean。

结论：设计四件套自审通过 4 轮，最后一轮 clean。Go 实现未修改；当前未运行 MCP suite（因为 `ldp` 层尚未注册）。

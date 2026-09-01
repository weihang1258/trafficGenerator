# Megaco/H.248（媒体网关控制协议，文本编码）测试用例契约

> 版本：v1.2.0（测试用例）
> 日期：2026-09-01
> 配套设计：`docs/protocol-designs/70-megaco-design.md`（v1.2.0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/megaco.json`
> 状态：按《协议设计文档与用例文档需求文档 v1.3》完成独立对抗重审（审查员 rr-megaco：行为面 114 点，✓79/半8/✗27；confirmed findings 5 MAJOR C 项 + 2 MAJOR D 项 + 约 20 MINOR + 4 N 项），本版为修复轮产物：23 条 → **77 条（46 正 + 31 负）**，待 rr-megaco 复验。记录见 §9。
> 规范基线：RFC 3525 / ITU-T H.248.1 (03/2002)，文本编码（Annex B.2 ABNF）；TPKT 成帧 RFC 1006 / RFC 3525 Annex D.2（SHALL）；端口 IANA `megaco-h248 2944`、`h248-binary 2945`、`mgcp-gateway 2427`。

## 1. 测试原则和未注册边界

用例按《需求文档 v1.3》从规范（RFC 3525 文本编码）与设计 §2–§8 派生：**可测试行为面全枚举**（消息/事务/动作/命令四层 × 描述符值域 × 事务关联 × 边界 × 错误分支 × 载体 × 场景 × 交互），用例 = 不可再分的测试点（本版 77 条 = 46 正 + 31 负，对应 rr-megaco 枚举的 114 行为面点，比率约 1.5 点/例）。**ID 权威 = 本文 §2**；依据列标注出处，不要求与设计章节一对一映射。**pcap 与 port_group/NIC 两种输出路径使用同一份用例契约**（同一 ID、同一断言、同一包数，C-2，与 64-cwmp/66-doh/67-onvif/68-hl7 同形）。

当前 JSON 只保留 `megaco_neg_unregistered` 注册前置占位：`proto=megaco`、`expect_error=true`、`error_contains` 精确为 `unknown layer`；占位不计入 77 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 Megaco 行为通过。注册后移除占位，按本文 §2 顺序补入 46 个正例与 31 个负例。

**机器契约**：`trafficgen/test/protocol_pcap/cases/megaco.json`（第二阶段生成，本版不写文件）。`proto` 固定为 `megaco`，不得用 `h248`/`mgcp`；三入口别名由 planner 归一。

**TSHARK 实测基线（本机 3.6.14）**：megaco 文本 dissector 绑定 2944 端口、字段族 `megaco.*` 齐全（§3 清单与设计 §3.9 实测一致，含 `reservevalue/reservegroup/terminationstate`）；2427 端口绑定的是 `mgcp` dissector——`megaco_udp_2427_mgcp_alias` 用例证据在"decode_as 强制 megaco（`-d udp.port==2427,megaco`）"与"offset 42 起始行/命令 token 字节断言"二选一，case JSON 实现时定并同步四件套。**非 2944 端口实测不自动按 megaco 解码**：非默认端口用例（若有）的 fields 断言须带 `-d` DecodeAs 提示或全 frames hex 断言。

**动态值不硬编码**：transactionId、数值 ContextID、媒体 SDP 地址/端口、时间戳为运行期/策略值——用 `nonzero`、`same_as_packet`、`distinct_values`、包间关系与稳定 token 字节断言。**边界固化 carve-out**（§4 各边界例声明）：被测规格点即边界值本身的用例允许 fixture 显式固化（TerminationID 恰 64、transactionId 恰 4294967295、定时器恰 99、ContextID 4294967293、transid 0、StreamID 65535、Version 2 位形态）。不做"媒体已建立""编解码协商成功"等超出控制面的断言。

**包数约定**（设计 §9）：UDP 每消息一包；TCP = 3（握手）+ N（承载 TPKT PDU 字节的分段数）+ 4（双向 FIN/ACK 挥手）。约定数字是实现基线，若实现采用不同 ACK 合并或分段方式，须同步更新四件套，不得把约定数字当 RFC 消息数。

**TPKT 成帧**（设计 §2）：TCP 载体每条消息前置 RFC 1006 TPKT 头 4B（`版本=0x03`、`保留=0x00`、`总长度 2B 大端 = 4B 头 + Megaco 消息长度`），Megaco 文本起点 offset **58（IPv4）/78（IPv6）**；消息定界依据 TPKT 长度域，文本语法仅作内容验证。UDP 一数据报一消息（无 TPKT，offset 42/62）。

**多会话/并发包号规则**（设计 §8）：多会话展开按序整块回放，第二会话起点 = 前会话总包数 + 1（如 `megaco_udp_ipv4_multi_session`：第一会话 4 包共 2 消息，第二会话 6 包共 3 消息、起点 = 包 5）；`concurrent: true` 并发会话交错回放（C-3 翻案纳入，`megaco_udp_ipv4_concurrent_sessions`）——并发只作用于生成器级多连接交错，两会话各自事务配对与状态隔离断言不放宽。

## 2. 原子用例索引

| # | ID | 类型 | 载体 | 覆盖 | 依据 | 包数 |
|---:|---|---|---|---|---|---:|
| 1 | `megaco_udp_ipv4_registration` | 正 | UDP/IPv4 | MG 注册 SC(Restart,ROOT)+Services、Reply 事务关联、单流基线 | 设计§2/§3.2/§3.5/§3.6/§5.2 | 2 |
| 2 | `megaco_udp_ipv6_failover` | 正 | UDP/IPv6 | SC(Failover)+Reason 909、IPv6 offset 62 | 设计§3.6/§5.2/§8 | 2 |
| 3 | `megaco_tcp_ipv4_dual_transaction` | 正 | TCP/IPv4 | 同消息双事务、T2 首错停止（430 后第二命令不执行）、事务/动作级错误描述符 | 设计§2(TPKT)/§3.2/§3.4/§3.5/§5.1/§5.2/§7 | 9 |
| 4 | `megaco_tcp_ipv6_call_flow` | 正 | TCP/IPv6 | 编程→建连→回填→拆连多消息事务依赖 | 设计§3.3/§3.5/§4/§5.2/§8 | 15 |
| 5 | `megaco_udp_ipv4_notify_events` | 正 | UDP/IPv4 | Events(RequestID) 编程→Notify(ObservedEvents 同 RequestID)→Reply | 设计§3.5/§4/§5.1 | 4 |
| 6 | `megaco_udp_ipv4_audit_wildcard` | 正 | UDP/IPv4 | 同消息双事务 O-AV(ROOT)+W-AC(*)、O-/W- 前缀 | 设计§3.4/§3.5/§3.7 | 2 |
| 7 | `megaco_udp_ipv4_handoff` | 正 | UDP/IPv4 | 两会话 handoff：SC HandOff+Reason 903+MgcIdToTry / 纯 HandOff | 设计§3.6/§4/§5.2/§6/§8 | 4 |
| 8 | `megaco_udp_ipv4_abbrev_tokens` | 正 | UDP/IPv4 | 缩写 token：`!/1`、T/C/SC/SV/MF/E/P；大小写不敏感 | 设计§3.1/§3.4/§3.5 | 4 |
| 9 | `megaco_udp_ipv4_move_media` | 正 | UDP/IPv4 | Move 命令+完整 Media 描述符、前置 Add 建连对 | 设计§3.4/§3.5/§5.2 | 4 |
| 10 | `megaco_udp_ipv4_large_digitmap` | 正 | UDP/IPv4 | 大 DigitMap 长消息单数据报承载 | 设计§3.5/§8 | 2 |
| 11 | `megaco_tcp_ipv4_mss_reassembly` | 正 | TCP/IPv4 | 长 TPKT PDU 跨 TCP 分段、按 TPKT 长度域切分重组 | 设计§2/§3.10/§8 | 11 |
| 12 | `megaco_udp_ipv4_multi_session` | 正 | UDP/IPv4 | 多会话双四元组状态隔离（会话 2 Events 编程+Notify） | 设计§4/§5.2/§8 | 10 |
| 13 | `megaco_tcp_ipv4_pending_immack` | 正 | TCP/IPv4 | T→PN{}→Reply(IA)→K 单点三方握手 | 设计§3.2/§5.1/§5.2 | 11 |
| 14 | `megaco_udp_2427_mgcp_alias` | 正 | UDP/IPv4 | 入口名 mgcp+默认 2427+同一文本线格式（三名合一） | 设计§1/§2/§3.9 | 2 |
| 15 | `megaco_udp_ipv4_termid_max_length` | 正 | UDP/IPv4 | TerminationID 恰 64 字符（pathNAME 上界） | 设计§3.7/§8 | 2 |
| 16 | `megaco_udp_ipv4_transid_max` | 正 | UDP/IPv4 | transactionId 恰 4294967295（UINT32 上界，边界固化 carve-out） | 设计§3.2/§8 | 2 |
| 17 | `megaco_udp_ipv4_digitmap_timer_max` | 正 | UDP/IPv4 | DigitMap T 定时器恰 99（1-99 上界；D-4 口径：T:0 为禁用启动定时器的合法语义不归越界） | RFC 3525 §7.1.14+设计§3.5 v1.2 | 2 |
| 18 | `megaco_udp_ipv4_termination_state` | 正 | UDP/IPv4 | TerminationState 描述符：ServiceStates/EventBufferControl（C-5） | RFC 3525 §7.1.5+设计§3.5 | 2 |
| 19 | `megaco_udp_ipv4_version_negotiation` | 正 | UDP/IPv4 | 版本协商：MG Services 提议 Version=2、Reply 回 Version=1 低版胜出（C-6） | RFC 3525 §11.3+设计§4 场景 1 | 2 |
| 20 | `megaco_udp_ipv4_method_graceful` | 正 | UDP/IPv4 | SC Method=Graceful + Delay 参数（C-7） | RFC 3525 §7.2.8/§7.1.13 | 2 |
| 21 | `megaco_udp_ipv4_method_forced` | 正 | UDP/IPv4 | SC Method=Forced（C-7 方法值域第二补值） | RFC 3525 §7.2.8 | 2 |
| 22 | `megaco_udp_ipv4_method_disconnected` | 正 | UDP/IPv4 | SC Method=Disconnected（MG 重连原 MGC，C-7 第三补值） | RFC 3525 §7.2.8/§11.5 | 2 |
| 23 | `megaco_udp_ipv4_whitespace_comment_variants` | 正 | UDP/IPv4 | 空白/注释变体：`;` 注释、CR-only EOL、多 LWSP（C-9） | RFC 3525 Annex B（SEP/EOL/LWSP/COMMENT） | 2 |
| 24 | `megaco_udp_ipv4_mid_address_port` | 正 | UDP/IPv4 | mId 带端口形态 `[192.0.2.10]:2944`（C-10 第一补形） | RFC 3525 Annex B（mId 四形态） | 2 |
| 25 | `megaco_udp_ipv4_mid_devicename` | 正 | UDP/IPv4 | mId deviceName（pathNAME）形态（C-10 第二补形） | RFC 3525 Annex B | 2 |
| 26 | `megaco_tcp_ipv4_transaction_level_error` | 正 | TCP/IPv4 | 事务级 errorDescriptor：Reply=id{Error=411{...}} 整事务错（C-11） | RFC 3525 Annex B（transactionReply errorDescriptor 分支） | 9 |
| 27 | `megaco_tcp_ipv4_ack_range` | 正 | TCP/IPv4 | K 区间形态 `K{<a>-<b>}`（C-12） | RFC 3525 Annex B/D.1.2.2 | 12 |
| 28 | `megaco_udp_ipv4_transid_zero_error_reply` | 正 | UDP/IPv4 | transactionId 0：缺 ID 请求的错误 Reply（C-13） | RFC 3525 §8.1.1 | 1 |
| 29 | `megaco_udp_ipv4_reserved_value_group` | 正 | UDP/IPv4 | LocalControl ReservedValue/ReservedGroup=ON/OFF（C-14 第一项） | RFC 3525 §7.1.7 | 2 |
| 30 | `megaco_udp_ipv4_eventbuffer_descriptor` | 正 | UDP/IPv4 | EventBuffer 描述符（C-14 第二项） | RFC 3525 §7.1.10 | 2 |
| 31 | `megaco_udp_ipv4_mode_sendonly` | 正 | UDP/IPv4 | LocalControl Mode=SendOnly（值域 SO，C-15） | RFC 3525 §7.1.7 | 2 |
| 32 | `megaco_udp_ipv4_mode_inactive` | 正 | UDP/IPv4 | LocalControl Mode=Inactive（值域 IN，C-15） | RFC 3525 §7.1.7 | 2 |
| 33 | `megaco_udp_ipv4_mode_loopback` | 正 | UDP/IPv4 | LocalControl Mode=Loopback（值域 LB，C-15） | RFC 3525 §7.1.7 | 2 |
| 34 | `megaco_udp_ipv4_audit_item_domain` | 正 | UDP/IPv4 | Audit auditItem 值域扩展（Media/Signals/DigitMap/Statistics，C-15） | RFC 3525 §7.1.12 | 2 |
| 35 | `megaco_udp_ipv4_signals_types` | 正 | UDP/IPv4 | Signals 信号类型 OO/TO/BR + SignalList（C-15） | RFC 3525 §7.1.11 | 2 |
| 36 | `megaco_udp_ipv4_error_code_431` | 正 | UDP/IPv4 | 错误码 431：通配无匹配（C-16） | RFC 3525 §7.2.5/错误码注册 | 2 |
| 37 | `megaco_udp_ipv4_error_code_442` | 正 | UDP/IPv4 | 错误码 442：命令语法错（C-16） | RFC 3525 错误码注册 | 2 |
| 38 | `megaco_udp_ipv4_services_delay_timestamp` | 正 | UDP/IPv4 | Services Delay/TimeStamp 参数（C-17） | RFC 3525 §7.1.13 | 2 |
| 39 | `megaco_udp_ipv4_context_id_high_boundary` | 正 | UDP/IPv4 | ContextID 近似上界（0xFFFFFFFD 正例，C-18） | RFC 3525 §8.1.2（保留值注释） | 2 |
| 40 | `megaco_udp_ipv4_version_two_digits` | 正 | UDP/IPv4 | 起始行 Version 2 位数字形态（语法 1*2DIGIT 上界，C-18 carve-out） | RFC 3525 Annex B（Version=1*2DIGIT） | 2 |
| 41 | `megaco_udp_ipv4_streamid_max` | 正 | UDP/IPv4 | StreamID UINT16 上界 65535（C-18） | RFC 3525 §7.1.6 | 2 |
| 42 | `megaco_udp_ipv4_embed_events` | 正 | UDP/IPv4 | Events 嵌套描述符（Embed，C-19） | RFC 3525 §7.1.9（嵌套 eventsDescriptor） | 2 |
| 43 | `megaco_udp_ipv4_events_no_requestid` | 正 | UDP/IPv4 | Events 无 RequestID 形态（ABNF 可选，C-19） | RFC 3525 Annex B（EventsToken [EQUAL RequestID] 可选） | 2 |
| 44 | `megaco_udp_ipv4_registration_redirect` | 正 | UDP/IPv4 | 注册改派流：Reply 带 ServiceChangeMgcId → MG 转向新 MGC 重发注册（C-20） | RFC 3525 §11.2 | 4 |
| 45 | `megaco_udp_ipv4_concurrent_sessions` | 正 | UDP/IPv4 | 并发会话交错回放（C-3 翻案纳入） | 设计§4 v1.2（cwmp⑦/doh/onvif 同判例） | 4 |
| 46 | `megaco_udp_ipv4_digitmap_z_timer` | 正 | UDP/IPv4 | DigitMap Z 修饰符（digitMapLetter 长时长修饰符，Timer 口径 100ms-9.9s）（D-4） | RFC 3525 Annex B（digitMapLetter=Z） | 2 |
| 47 | `megaco_neg_encoding_text_as_ber` | 负 | — | `encoding=ber` 声明而载荷为文本字节 | 设计§1/§3.8 | — |
| 48 | `megaco_neg_encoding_port_mismatch` | 负 | — | text 编码声明配 2945（BER 默认端口） | 设计§2 | — |
| 49 | `megaco_neg_syntax_start_line` | 负 | — | 起始行 MegacopToken 缺失/拼错（非 `MEGACO`/`!`） | RFC 3525 Annex B | — |
| 50 | `megaco_neg_syntax_version_zero` | 负 | — | 起始行版本为 `0` | 设计§3.1 | — |
| 51 | `megaco_neg_syntax_version_three_digits` | 负 | — | 起始行版本 3 位数字（Version=1*2DIGIT 越界） | RFC 3525 Annex B | — |
| 52 | `megaco_neg_syntax_mid_missing` | 负 | — | mId 缺失（起始行后直接 messageBody） | 设计§3.1 | — |
| 53 | `megaco_neg_syntax_mid_invalid` | 负 | — | mId 非法形式（四形态之外） | 设计§3.1 | — |
| 54 | `megaco_neg_syntax_body_form` | 负 | — | messageBody 既非事务表也非 errorDescriptor | RFC 3525 Annex B | — |
| 55 | `megaco_neg_syntax_services_missing_params` | 负 | — | Services 缺必选 Method/Reason（描述符必选参数） | RFC 3525 §7.1.13 | — |
| 56 | `megaco_neg_command_pre_registration` | 负 | — | 注册前发非 SC 命令（505 语义，§9.1 规则 6） | RFC 3525 §9.1 | — |
| 57 | `megaco_neg_command_modify_nonexistent` | 负 | — | 未 Add 先 Modify/Subtract 不存在终结点 | 设计§5.2 | — |
| 58 | `megaco_neg_command_reply_choose_all` | 负 | — | reply 动作使用 `$`/`*` context（CHOOSE/ALL 仅请求侧） | 设计§3.3 | — |
| 59 | `megaco_neg_command_uncreated_context` | 负 | — | 引用未创建的数值 Context | 设计§5.2 | — |
| 60 | `megaco_neg_command_first_error_continues` | 负 | — | 同事务首命令失败后第二命令（无 O-）响应仍出现（首错后仍执行） | RFC 3525 §8 | — |
| 61 | `megaco_neg_pairing_reply_id_mismatch` | 负 | — | Reply transactionId 与请求不等 | 设计§5.1 | — |
| 62 | `megaco_neg_pairing_pending_id_mismatch` | 负 | — | Pending transactionId 与请求不等 | 设计§5.1 | — |
| 63 | `megaco_neg_pairing_duplicate_transid` | 负 | — | 同会话重复 transactionId（作用域唯一性） | 设计§5.1 | — |
| 64 | `megaco_neg_pairing_ack_unconfirmed` | 负 | — | `K` 确认未发生/未确认过的事务（覆盖集 ⊄ 已确认集合） | 设计§3.2 | — |
| 65 | `megaco_neg_pairing_ia_without_pending` | 负 | — | `ImmAckRequired` 出现在未回过 Pending 的事务 | 设计§5.2 | — |
| 66 | `megaco_neg_pairing_observed_requestid` | 负 | — | ObservedEvents RequestID 与生效 Events RequestID 不匹配 | RFC 3525 §7.1.9/§7.1.17 | — |
| 67 | `megaco_neg_length_message_truncated` | 负 | — | 消息截断（messageBody 未闭合/尾部缺失） | 设计§7 | — |
| 68 | `megaco_neg_length_termid_over_64` | 负 | — | TerminationID 超 64 字符（pathNAME 上界） | RFC 3525 §6.2.2 | — |
| 69 | `megaco_neg_length_transid_over_uint32` | 负 | — | transactionId >4294967295（UINT32 越界） | 设计§3.2 | — |
| 70 | `megaco_neg_length_digitmap_timer` | 负 | — | DigitMap 定时器越界：T>99 或 S/L 为 0（D-4 口径：T:0 为合法禁用语义不归越界） | RFC 3525 §7.1.14 | — |
| 71 | `megaco_neg_length_context_reserved` | 负 | — | ContextID 取保留值 0/0xFFFFFFFE/0xFFFFFFFF 作具体 Context | RFC 3525 §8.1.2 | — |
| 72 | `megaco_neg_carrier_layer_mismatch` | 负 | — | 层链 udp/tcp 与配置声明不符 | 设计§2 | — |
| 73 | `megaco_neg_carrier_entry_port_encoding` | 负 | — | 入口名-端口-编码组合非法（text 配 2945、mgcp 别名配非法载体） | 设计§2 | — |
| 74 | `megaco_neg_carrier_invalid_port` | 负 | — | 非法端口号（0/65536） | 设计§2 | — |
| 75 | `megaco_neg_carrier_return_address` | 负 | — | 会话四元组与请求源地址不符（响应回程校验失败，§9） | RFC 3525 §9 | — |
| 76 | `megaco_neg_carrier_udp_mtu_exceeded` | 负 | — | UDP 载体消息长 > MTU−头开销（validator 拒绝或要求改 TCP，不静默截断，C-8） | RFC 3525 Annex D.1+设计§8 | — |
| 77 | `megaco_neg_services_address_mgcidtotry_conflict` | 负 | — | Services 同时携带 ServiceChangeAddress 与 MgcIdToTry（ABNF at most one of either，C-17） | RFC 3525 §7.1.13 | — |
| 78 | `megaco_neg_unregistered` | 占位 | — | 层注册前置占位，不计语义覆盖 | §1 未注册边界 | — |

## 3. 线上编码与偏移断言

文本消息从应用起点开始。无 VLAN、无 IP options、无 TCP options 时：UDP/IPv4 offset 42（Eth 14 + IPv4 20 + UDP 8）、UDP/IPv6 offset 62；TCP 载荷起点 54（IPv4）/74（IPv6）前置 RFC 1006 TPKT 头 4B（`版本=0x03`、`保留=0x00`、`总长度 2B 大端 = 4 + 消息长度`），Megaco 文本起点 **58（IPv4）/78（IPv6）**。UDP 一数据报一消息（无 TPKT）；TCP 先按字节流重组，再按 **TPKT 长度域**切分消息（Annex D.2 SHALL），文本语法（起始行到 messageBody 闭合）仅用于内容验证，segment 边界不等于消息边界。

起始行稳定前缀两形：`MEGACO/1 `（长形）与 `!/1 `（缩写形）；其后是 `mId` 四形式：`domainAddress`（`[IPv4]`/`[IPv6]`，可带 `:端口`）、`domainName`（`<域名>` 尖括号）、`mtpAddress`（`MTP{...}` 花括号，本版不用）、`deviceName`（pathNAME 裸 token）。空白/注释高度自由（`SEP = (WSP / EOL / COMMENT) LWSP`、`COMMENT = ";" ... EOL`）：解析断言不得依赖固定行宽或空白形态（用例 23）。消息级示例（RFC 3525 Appendix I 风格）：

```text
MEGACO/1 [192.0.2.10] Transaction = 10003 {
    Context = $ {
        Add = A4444,
        Add = $ {
            Media { Stream = 1 {
                LocalControl { Mode = ReceiveOnly },
                Local { v=0 c=IN IP4 $ m=audio $ RTP/AVP 4 a=ptime:30 }
            } }
        }
    }
}
```

实现后证据以 tshark 实测字段为准（`tshark -G fields | grep megaco` 已核，与设计 §3.9 同一清单）：`megaco.start_token`、`megaco.version`、`megaco.mId`、`megaco.transaction`（方向）、`megaco.transid`、`megaco.context`/`megaco.ctx`/`megaco.ctx.term`、`megaco.command`、`megaco.command_optional`、`megaco.wildcard_response`、`megaco.termid`、`megaco.requestid`、`megaco.media`、`megaco.localcontroldescriptor`、`megaco.mode`、`megaco.streamid`、`megaco.servicestates`、`megaco.eventbuffercontrol`、`megaco.reservevalue`、`megaco.reservegroup`、`megaco.terminationstate`、`megaco.localdescriptor`/`megaco.remotedescriptor`、`megaco.events`、`megaco.observedevents`、`megaco.signal`、`megaco.digitmap`、`megaco.statistics`、`megaco.packagesdescriptor`、`megaco.pkgdname`、`megaco.audit`/`megaco.audititem`、`megaco.error`/`megaco.error_code`/`megaco.error_string`。**字段断言使用实测格式**（`megaco.transid` FT_UINT32 十进制、`megaco.version` FT_STRING）；不得臆造未实测字段名/格式。端口 2944 自动按 megaco 解码；2427 按 §1 规则处理。dissector 已知行为（断言校准）：`PN` 消息 `megaco.transaction` 也置 `Reply`、`K` 区间 transid 只取首个数——Pending 与 `K` 断言按帧字节前缀处理（用例 13/27）。

## 4. 正例逐项断言契约

约定 packet_count 见 §2 表；以下 fields/frames 为最低断言集，实现期可增不可减。默认 fixture 地址 `192.0.2.10 → 192.0.2.4`、UDP/TCP `2944`；各例标注的 fixture 定值以帧字节 ASCII/token 断言；TCP 例含握手/挥手包且握手包不承载 Megaco 字节。

1. **`megaco_udp_ipv4_registration`**（UDP/IPv4，packet_count=2）：请求起始行 `MEGACO/1 `、mId 恒定；`megaco.transid` nonzero、`megaco.command=ServiceChange`、`megaco.ctx.term=ROOT`、Services 含 `Method=Restart` 与 `Reason="901 Cold Boot"`、Profile/ServiceChangeAddress/Version 存在；Reply 事务 ID 与请求 same_as_packet，Reply 含 `ServiceChange=ROOT` 且带 Profile/Version。
2. **`megaco_udp_ipv6_failover`**（UDP/IPv6，packet_count=2）：`ip.version=6`、offset 62 起文本；SC `Method=Failover`、`Reason="909 MGC Impending Failure"`；Reply 关联同 #1；`megaco.transid` 两包同值。
3. **`megaco_tcp_ipv4_dual_transaction`**（TCP/IPv4，packet_count=9）：TCP 握手三包；TPKT 头 `[54..57] = 03 00 <len_hi> <len_lo>`、文本 offset 58；同消息双事务 `T1{}`/`T2{}`、`megaco.transid` distinct 恰两值；T1=AuditValue ROOT 成功；T2 首命令 `AuditValue = A9999 {Audit{Events}}`（不存在终结点）→ Reply 内 `Error = 430 {"Unknown TerminationID"}`（`megaco.error_code=430`）；第二命令 `AuditValue = ROOT` 因首错停止不执行——**断言按包级字节包含原语（D-6/N-4 修正）**：重组后 T2 回应全形文本（自 `P<id2>{` 至配对 `}`）内不含第二段 `AuditValue` 响应回文（字节串包含断言，不以「区间」表述）、`megaco.error_code=430` 在 Reply 消息中恰一次。事件级错误是合法协议行为非负例；两 Reply 聚合单消息。
4. **`megaco_tcp_ipv6_call_flow`**（TCP/IPv6，packet_count=15）：TPKT `[74..77]`、文本 offset 78；四顺序事务：①NULL context 编程 Modify（Events+Signals）；②`Context=${Add=A4444,Add=${Media{Stream=1{LocalControl{Mode=ReceiveOnly},Local{SDP(含 $)}}}}}` 建连、Reply 回具体 ContextID 与填充 Local；③两条 Modify Remote 回填（A4444、A4445 单命令单 TerminationID）；④Subtract×2 拆连（可回 Statistics）；`ipv6.nxt=6`、事务 ID 递增不重复、每 Reply same_as、`megaco.mode=ReceiveOnly`、`megaco.streamid=1`、CHOOSE `$` 仅请求侧；role=mgc 初始 Registered 等价态。
5. **`megaco_udp_ipv4_notify_events`**（UDP/IPv4，packet_count=4）：四消息：Modify 编程 Events=2222→Reply→Notify（ObservedEvents=2222 同 RequestID，`megaco.requestid` same_as）→Reply；`megaco.command` 序列 Modify/Notify、`megaco.events`/`megaco.observedevents`、`al/of` 与时间戳存在。
6. **`megaco_udp_ipv4_audit_wildcard`**（UDP/IPv4，packet_count=2）：`T1{Context=-{O-AuditValue=ROOT{Audit{Packages}}}}`、`T2{Context=*{W-AuditCapability=*{Audit{Events}}}}`；transid 恰两 distinct、AV/AC 并存、`megaco.ctx.term=ROOT` 与通配可解析、`megaco.command_optional`/`megaco.wildcard_response` 存在。
7. **`megaco_udp_ipv4_handoff`**（UDP/IPv4，packet_count=4）：会话 1（MG↔MGC1）：MGC1 SC HandOff+Reason 903+MgcIdToTry+Reply；会话 2（MG↔MGC2，起点=包 3）：MG SC HandOff+Reason 903+Reply；两会话事务 ID 空间独立、mId 按方向恒定（peer_mid 区分 MGC1/MGC2）、Reason 903 两会话存在。
8. **`megaco_udp_ipv4_abbrev_tokens`**（UDP/IPv4，packet_count=4）：注册对全缩写+混合大小写、`megaco.start_token=!/1`；编程对 `MF=A4444{E=2222{al/of}}`；命令缩写解析语义不变、`megaco.events` 存在、大小写变体不误判。
9. **`megaco_udp_ipv4_move_media`**（UDP/IPv4，packet_count=4）：Add 建连对（得具体 ContextID）+ Move 对（Media{Stream=1{LocalControl{Mode=SendReceive},Local/Remote SDP}}）；`megaco.command=Move`、`megaco.mode=SendReceive`、`megaco.streamid=1`、Reply 回具体 ContextID。
10. **`megaco_udp_ipv4_large_digitmap`**（UDP/IPv4，packet_count=2）：>1KB DigitMap 的 Modify 单数据报承载；`udp.length` 覆盖整条消息、`megaco.digitmap` 存在、无截断、UDP 一数据报一消息。
11. **`megaco_tcp_ipv4_mss_reassembly`**（TCP/IPv4，packet_count=11）：小 MSS 使长 Add（大 Media/SDP）TPKT PDU 跨多段；按 `tcp.stream` 重组后按 TPKT 长度域切分（`[54..57]=03 00 <len>`、TPKT 头只出现首段）；文本语法验证完整；`megaco.transid` 唯一、`megaco.command=Add`、Local SDP 完整。
12. **`megaco_udp_ipv4_multi_session`**（UDP/IPv4，packet_count=10）：会话 1：注册对+编程 Modify 对（4 包）；会话 2（起点=包 5）：注册对+Events 编程对+Notify 对（6 包）；四元组 distinct、transid 按会话隔离、终结点/RequestID 映射不串用。
13. **`megaco_tcp_ipv4_pending_immack`**（TCP/IPv4，packet_count=11）：四应用消息各一 TPKT PDU；PN/Reply/K 的 transid 与请求 same_as；K 覆盖集⊆已确认事务集合；帧字节形态前缀（`T`/`PN`/`P`+数字/`K{`）区分四形态（dissector Pending 也置 Reply——已知行为注记）；IA 仅在回过 PN 后。
14. **`megaco_udp_2427_mgcp_alias`**（UDP/IPv4，packet_count=2）：注册对同构；证据走 decode_as（`-d udp.port==2427,megaco`）或 offset 42 起始行/token 字节断言；不产生 MGCP 本体线格式。
15. **`megaco_udp_ipv4_termid_max_length`**（UDP/IPv4，packet_count=2）：`Modify = A+63 位数字（恰 64）{Events=2222{al/of}}`+Reply；帧字节中终结点串恰 64 字符、`megaco.termid` 存在、Reply same_as。
16. **`megaco_udp_ipv4_transid_max`**（UDP/IPv4，packet_count=2）：请求与 Reply 的 transactionId 恰 `4294967295`；`megaco.transid=4294967295` 两包同值。
17. **`megaco_udp_ipv4_digitmap_timer_max`**（UDP/IPv4，packet_count=2）：`Modify = A4444 {DigitMap = Dm99 {T:99, (0|00|1xxx)}}`+Reply；帧字节含 `T:99`、`megaco.digitmap` 存在；越界负例限定为 T>99 与 S/L 的 0。
18. **`megaco_udp_ipv4_termination_state`**（UDP/IPv4，packet_count=2）：`Modify = A4444 {Media{TerminationState{ServiceStates=Test, EventBufferControl=LockStep}}}`+Reply；断言 `megaco.servicestates=Test`（TE）、`megaco.eventbuffercontrol=LockStep`（SP）、`megaco.terminationstate` 存在——实测字段在正确嵌套下填充（rr-megaco pcap 实证）。
19. **`megaco_udp_ipv4_version_negotiation`**（UDP/IPv4，packet_count=2）：注册 SC Services 携带 `Version=2`（MG 提议其支持的最高版本）；Reply 回 `Version=1`（MGC 选择较低版本——低版胜出）；两包起始行均 `MEGACO/1`；断言帧字节请求侧含 `Version=2`、Reply 侧含 `Version=1`、`megaco.version` 起始行值=1。
20. **`megaco_udp_ipv4_method_graceful`**（UDP/IPv4，packet_count=2）：`SC = ROOT {Services{Method=Graceful, Reason="900 Service Restored", Delay=30}}`+Reply；`megaco.command=ServiceChange`、帧字节含 `Graceful` 与 `Delay=30`。
21. **`megaco_udp_ipv4_method_forced`**（UDP/IPv4，packet_count=2）：`SC = ROOT {Services{Method=Forced, Reason="908 MG Impending Failure"}}`+Reply；帧字节含 `Forced`。
22. **`megaco_udp_ipv4_method_disconnected`**（UDP/IPv4，packet_count=2）：`SC = ROOT {Services{Method=Disconnected, Reason="900 Service Restored"}}`+Reply；帧字节含 `Disconnected`。
23. **`megaco_udp_ipv4_whitespace_comment_variants`**（UDP/IPv4，packet_count=2）：注册请求内注入 `; comment` 注释行、CR-only 行尾与连续多空格；解析不因空白形态差异误判（起始行/命令/描述符字段断言与 #1 一致）。
24. **`megaco_udp_ipv4_mid_address_port`**（UDP/IPv4，packet_count=2）：注册对 mId 用 `[IP]:port` 形态；`megaco.mId` 存在且帧字节含 `]:2944`；同一会话内 mId 恒定。
25. **`megaco_udp_ipv4_mid_devicename`**（UDP/IPv4，packet_count=2）：注册对 mId 用 deviceName（如 `mgw-1.example.net` pathNAME 形态，非尖括号域名）；`megaco.mId` 存在、恒定。
26. **`megaco_tcp_ipv4_transaction_level_error`**（TCP/IPv4，packet_count=9）：packet_count=9=3+2+4（请求+Reply 两 TPKT PDU）；TPKT 头/offset 断言同 #3。请求引用不存在 Context → Reply 为 `Reply<id>{Error = 411 {"Unknown ContextID"}}`（事务级 errorDescriptor 分支，无 actionReply 体）；`megaco.error_code=411`——与 #3 动作级（Reply 事务体内 Error）分立。
27. **`megaco_tcp_ipv4_ack_range`**（TCP/IPv4，packet_count=12）：packet_count=12=3+5+4（T+Reply ×2 = 4 PDU + K 1 PDU）。会话内先发生两笔已确认事务（各自 T→Reply），第三消息 `K{<a>-<b>}` 覆盖两已确认事务（区间，帧字节以 `K{` 开头 + 区间 `-` 文本存在）；dissector 对区间 transid 只取首个数（已知行为注记）——断言以帧字节前缀与区间文本为准，不固化 transactionId 数值；K 覆盖集 ⊆ 已确认事务集合（§3.2 校验）。
28. **`megaco_udp_ipv4_transid_zero_error_reply`**（UDP/IPv4，packet_count=1）：MG 对无法解析 TransactionID 的请求回错误 Reply、其 transactionId 恰为 `0`（保留值）；帧字节含 `Reply 0 {`/等价缩写、`megaco.transid=0`——0 作错误 Reply 的合法保留用途（与 ContextID 保留值负例分立）。
29. **`megaco_udp_ipv4_reserved_value_group`**（UDP/IPv4，packet_count=2）：`Modify = A4444 {Media{Stream=1{LocalControl{Mode=SendReceive, RV=ON, RG=OFF}}}}`+Reply；`megaco.reservevalue`/`megaco.reservegroup`（实测字段）与 `ON`/`OFF` 文本存在。
30. **`megaco_udp_ipv4_eventbuffer_descriptor`**（UDP/IPv4，packet_count=2）：`Modify = A4444 {EventBuffer {al/of}}`+Reply；`megaco.eventbuffercontrol` 之外的事件缓冲描述符存在性断言（描述符 token 字节 `EventBuffer`/`EB`）。
31. **`megaco_udp_ipv4_mode_sendonly`**（UDP/IPv4，packet_count=2）：`LocalControl{Mode=SendOnly}`+Reply；`megaco.mode` 断言（缩写 SO 等价）。
32. **`megaco_udp_ipv4_mode_inactive`**（UDP/IPv4，packet_count=2）：`LocalControl{Mode=Inactive}`+Reply；`megaco.mode` 断言。
33. **`megaco_udp_ipv4_mode_loopback`**（UDP/IPv4，packet_count=2）：`LocalControl{Mode=Loopback}`+Reply；`megaco.mode` 断言。
34. **`megaco_udp_ipv4_audit_item_domain`**（UDP/IPv4，packet_count=2）：`AV = A4444 {Audit{Media, Signals, DigitMap, Statistics}}`+Reply；`megaco.audititem` 多值存在（值域扫描，与 #6 的 Packages/Events 分立补值）。
35. **`megaco_udp_ipv4_signals_types`**（UDP/IPv4，packet_count=2）：`Modify = A4444 {Signals{cg/bt(to=100), SignalList=1{al/ri(br)}}}` 类（OO/TO/BR 三类型+SignalList 分组）+Reply；`megaco.signal` 存在、SignalList 编号帧字节存在。
36. **`megaco_udp_ipv4_error_code_431`**（UDP/IPv4，packet_count=2）：`AV = R13/9/* {Audit{Events}}`（通配无匹配终结点）→ Reply `Error = 431 {"No TerminationID matched a wildcard"}`；`megaco.error_code=431`。
37. **`megaco_udp_ipv4_error_code_442`**（UDP/IPv4，packet_count=2）：Modify 携带非法命令参数（事件级合法错误形态）→ Reply `Error = 442 {"Syntax Error in Command"}`；`megaco.error_code=442`——与负例线格式校验（validator 拒绝）分立：本例为线格式合法、语义错的设备回包。
38. **`megaco_udp_ipv4_services_delay_timestamp`**（UDP/IPv4，packet_count=2）：SC Services 携带 `Delay=60` 与 `TimeStamp=20260901T12000000`（yyyymmddThhmmssss 形态）+Reply；帧字节含两参数文本。
39. **`megaco_udp_ipv4_context_id_high_boundary`**（UDP/IPv4，packet_count=2）：MG Reply 回具体 ContextID `4294967293`（0xFFFFFFFD，紧邻保留值 0xFFFFFFFE 的合法上界）；`megaco.ctx` 数值断言——保留值 0/4294967294/4294967295 作具体 Context 归负例。
40. **`megaco_udp_ipv4_version_two_digits`**（UDP/IPv4，packet_count=2）：fixture 起始行 `MEGACO/11`（2 位数字语法合法上界形态；语法层 carve-out 正例——语义层主口径仍 v1，本例只断言解析不因 2 位数字拒绝，不做 MGC 语义裁决断言）；`megaco.version` 断言、消息正常解析——与版本 `0`/3 位数字负例分立。
41. **`megaco_udp_ipv4_streamid_max`**（UDP/IPv4，packet_count=2）：`Media{Stream=65535{LocalControl{Mode=SendReceive}}}`+Reply；`megaco.streamid=65535`；>65535 归负例（UINT16 上界）。
42. **`megaco_udp_ipv4_embed_events`**（UDP/IPv4，packet_count=2）：`Modify = A4444 {Events=2222{dd/ce{dd(Dialplan0)}, Embed{Events=2223{al/of}}}}` 类嵌套+Reply；嵌套描述符帧字节存在、外内层 RequestID 各自可断言。
43. **`megaco_udp_ipv4_events_no_requestid`**（UDP/IPv4，packet_count=2）：`Modify = A4444 {Events{al/of}}`（无 `= RequestID`）+Reply——合法形态；与 #5 带 RequestID 形态分立。
44. **`megaco_udp_ipv4_registration_redirect`**（UDP/IPv4，packet_count=4）：会话 1（MG↔MGC1）：MG 注册 SC+Reply **携带 ServiceChangeMgcId**（拒绝/改派）；会话 2（MG↔MGC2，起点=包 3）：MG 向新 MGC 重发注册 SC+Reply（无 MgcIdToTry=接受）；与 #7 HandOff 语境分立（冷启动改派）；两会话 transid 独立。
45. **`megaco_udp_ipv4_concurrent_sessions`**（UDP/IPv4，packet_count=4）：`concurrent: true` 双四元组交错（两 MG-MGC 控制关联，H.248 多关联并发是现网常态）；断言两 `会话` 交错但各自事务配对完整、transid 空间/mId/Events RequestID 互不串用。
46. **`megaco_udp_ipv4_digitmap_z_timer`**（UDP/IPv4，packet_count=2）：`DigitMap = DmZ {(0|Z0|1x)}`（`Z` 为数字串内 digitMapLetter 长时长修饰符；Timer 注释：Z 单位 100ms、上界 9.9s）+Reply；帧字节含 `Z0` 分支、`megaco.digitmap` 存在。

**正例总则**：每条实现后至少含 `packet_count`/`min_packets`、载体与方向断言、`has_payload`、可观察 fields、稳定 frames（起始行与关键 token 字节前缀）；动态值只用关联断言。合法协议事件（事件级/事务级 errorDescriptor、`transid 0` 错误 Reply、边界固化 carve-out、空白/注释变体、`concurrent` 交错、`ack` 区间）均为正例形态；只有配置、线格式、状态机、关联、长度、描述符参数错误进入负例（§5）。消息级 errorDescriptor（messageBody=errorDescriptor）本版不设正例，设计 §7 有显式声明。

## 5. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩传输层外壳的假成功。执行期 `expect` 严格只有 `{"expect_error","error_contains"}` 两个键，不添加 `packet_count`、`notes`、`min_packets`、`fields` 或 `frames`。**逐故障输入原子拆分：一行一例，钉死该行注入的单一 `wire_fault`/配置变异**（C-1）；主锚词钉死（N-4），与设计 §7 表一一对应（31 行同序）：

| # | ID | `wire_fault` 注入口 | 故障输入（单一注入） | 主锚词（备选） |
|---:|---|---|---|---|
| 47 | `megaco_neg_encoding_text_as_ber` | `encoding_text_as_ber` | `encoding=ber` 声明而载荷为文本字节 | `encoding`（ber/text） |
| 48 | `megaco_neg_encoding_port_mismatch` | `encoding_port_mismatch` | text 编码声明配 2945（BER 默认端口） | `encoding`（port） |
| 49 | `megaco_neg_syntax_start_line` | `syntax_start_line` | 起始行 MegacopToken 缺失/拼错（非 `MEGACO`/`!`） | `message`（syntax） |
| 50 | `megaco_neg_syntax_version_zero` | `syntax_version_zero` | 起始行版本为 `0` | `version`（message） |
| 51 | `megaco_neg_syntax_version_three_digits` | `syntax_version_three_digits` | 起始行版本 3 位数字（Version=1*2DIGIT 越界） | `version`（message） |
| 52 | `megaco_neg_syntax_mid_missing` | `syntax_mid_missing` | mId 缺失（起始行后直接 messageBody） | `mid`（message） |
| 53 | `megaco_neg_syntax_mid_invalid` | `syntax_mid_invalid` | mId 非法形式（四形态之外） | `mid`（message） |
| 54 | `megaco_neg_syntax_body_form` | `syntax_body_form` | messageBody 既非事务表也非 errorDescriptor | `message`（syntax） |
| 55 | `megaco_neg_syntax_services_missing_params` | `syntax_services_missing_params` | Services 缺必选 Method/Reason（描述符必选参数） | `message`（services） |
| 56 | `megaco_neg_command_pre_registration` | `command_pre_registration` | 注册前发非 SC 命令（505 语义，§9.1 规则 6） | `command`（state） |
| 57 | `megaco_neg_command_modify_nonexistent` | `command_modify_nonexistent` | 未 Add 先 Modify/Subtract 不存在终结点 | `command`（termination） |
| 58 | `megaco_neg_command_reply_choose_all` | `command_reply_choose_all` | reply 动作使用 `$`/`*` context（CHOOSE/ALL 仅请求侧） | `command`（context） |
| 59 | `megaco_neg_command_uncreated_context` | `command_uncreated_context` | 引用未创建的数值 Context | `command`（context） |
| 60 | `megaco_neg_command_first_error_continues` | `command_first_error_continues` | 同事务首命令失败后第二命令（无 O-）响应仍出现（首错后仍执行） | `command`（state） |
| 61 | `megaco_neg_pairing_reply_id_mismatch` | `pairing_reply_id_mismatch` | Reply transactionId 与请求不等 | `transaction`（reply） |
| 62 | `megaco_neg_pairing_pending_id_mismatch` | `pairing_pending_id_mismatch` | Pending transactionId 与请求不等 | `transaction`（pending） |
| 63 | `megaco_neg_pairing_duplicate_transid` | `pairing_duplicate_transid` | 同会话重复 transactionId（作用域唯一性） | `transaction`（duplicate） |
| 64 | `megaco_neg_pairing_ack_unconfirmed` | `pairing_ack_unconfirmed` | `K` 确认未发生/未确认过的事务（覆盖集 ⊄ 已确认集合） | `transaction`（ack） |
| 65 | `megaco_neg_pairing_ia_without_pending` | `pairing_ia_without_pending` | `ImmAckRequired` 出现在未回过 Pending 的事务 | `transaction`（ack） |
| 66 | `megaco_neg_pairing_observed_requestid` | `pairing_observed_requestid` | ObservedEvents RequestID 与生效 Events RequestID 不匹配 | `transaction`（requestid） |
| 67 | `megaco_neg_length_message_truncated` | `length_message_truncated` | 消息截断（messageBody 未闭合/尾部缺失） | `length`（truncat） |
| 68 | `megaco_neg_length_termid_over_64` | `length_termid_over_64` | TerminationID 超 64 字符（pathNAME 上界） | `length`（limit） |
| 69 | `megaco_neg_length_transid_over_uint32` | `length_transid_over_uint32` | transactionId >4294967295（UINT32 越界） | `length`（limit） |
| 70 | `megaco_neg_length_digitmap_timer` | `length_digitmap_timer` | DigitMap 定时器越界：T>99 或 S/L 为 0（D-4 口径：T:0 为合法禁用语义不归越界） | `length`（timer） |
| 71 | `megaco_neg_length_context_reserved` | `length_context_reserved` | ContextID 取保留值 0/0xFFFFFFFE/0xFFFFFFFF 作具体 Context | `length`（context） |
| 72 | `megaco_neg_carrier_layer_mismatch` | `carrier_layer_mismatch` | 层链 udp/tcp 与配置声明不符 | `carrier`（layer） |
| 73 | `megaco_neg_carrier_entry_port_encoding` | `carrier_entry_port_encoding` | 入口名-端口-编码组合非法（text 配 2945、mgcp 别名配非法载体） | `carrier`（profile） |
| 74 | `megaco_neg_carrier_invalid_port` | `carrier_invalid_port` | 非法端口号（0/65536） | `port`（carrier） |
| 75 | `megaco_neg_carrier_return_address` | `carrier_return_address` | 会话四元组与请求源地址不符（响应回程校验失败，§9） | `carrier`（address） |
| 76 | `megaco_neg_carrier_udp_mtu_exceeded` | `carrier_udp_mtu_exceeded` | UDP 载体消息长 > MTU−头开销（validator 拒绝或要求改 TCP，不静默截断，C-8） | `length`（mtu） |
| 77 | `megaco_neg_services_address_mgcidtotry_conflict` | `services_address_mgcidtotry_conflict` | Services 同时携带 ServiceChangeAddress 与 MgcIdToTry（ABNF at most one of either，C-17） | `services`（exclusive） |

合法协议事件不进负例（防误报）：事件级/事务级 errorDescriptor（430/411/431/442）、`transid 0` 错误 Reply、边界固化值、空白/注释变体、`K` 区间、`concurrent` 交错、IPv4/IPv6、缩写 token。负例不得污染合法格式：每条故障只改变对应一项协议前提；错误保留最具体来源，不得自动补齐缺失 ID 或重排命令成合法顺序。事件级错误（用例 3）与设备回包语义错误（用例 36/37，线格式合法、语义错）是正例；负例注入全部发生在**生成器配置/validator 阶段**，不产生线字节。

## 6. 五层覆盖映射（v1.3 行为面对照，按 ID 引用防错位）

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 命令族（1-23/29-46 中各命令例）、事务形态（3/13/26/27/28）、描述符族（4/5/9/10/12/17/18/29/30/34/35/41/42/43/46）、负例 47-77 | 八命令全覆盖：SC（1/2/7/8/19/20/21/22/38/44）、Modify（4/5/12/15/17/18/23/29/31/32/33/41/42/43/46）、Add/Subtract（4/9）、Move（9）、Notify（5/12）、AV/AC（3/6/34/36/37）、O-/W- 前缀（6）；事务四形态：Request/Reply 全体、Pending+IA+K（13）与 K 区间（27）；错误描述符两级：动作级（3）+ 事务级（26）、`transid 0` 错误 Reply（28）；TerminationState（18）、RV/RG（29）、EventBuffer（30）、Embed/无 RequestID Events（42/43）补描述符盲区；负例 31 行逐故障输入（编码×2、线格式×7、状态机×5、关联×6、长度×6、载体×4、描述符参数×1） |
| 性能 | 10、11、13、27 + 负例 76 | 大 DigitMap 单数据报（10）；长 TPKT PDU 跨 MSS 分段重组（11）；长事务 PN/IA/K 往返（13）；K 区间（27）；UDP 超 MTU 拒绝（负例 76） |
| 数据场景 | 值域（20-22/29/31-35/37/38/46）、边界族（15/16/17/28/39/40/41）、编码变体（8/23/24/25） | Mode SO/IN/LB（31-33）+ RC/SR（4/9）；RV/RG（29）；auditItem 值域（34）；Signals OO/TO/BR+SignalList（35）；Method 值域 Graceful/Forced/Disconnected（20-22）；错误码 431/442（36/37）；Delay/TimeStamp（38）；Z 修饰符（46）；边界：TerminationID 恰 64（15）、transid 恰 UINT32 上界（16）、定时器恰 99（17）、transid 0（28）、ContextID 0xFFFFFFFD（39）、Version 2 位（40）、StreamID 65535（41）；缩写/大小写（8）、空白/注释（23）、mId 四形态之二（24/25） |
| 地址与流 | 1（单流基线）、2/4（v6）、45（并发）、7/12/44（多会话）；流关联显式不适用 | v4 全量 + v6（2/4）；UDP（1/2/5-10/12/14-46 中 UDP 例）与 TCP（3/4/11/13/26/27）；**并发会话翻案纳入**（45，`concurrent: true` 交错）；多会话（7/12/44）；**流关联不适用保留**：控制面不派生 RTP 媒体数据面（设计 §4.1） |
| 业务 | 注册（1/14/19/44）、呼叫（4/9）、上报（5/12）、巡检（6/34）、故障切换（2/7/21/22）、并发运营（45） | 冷启动注册+版本协商（1/19）、改名合一（14）、注册改派（44）、呼叫建立与媒体搬移（4/9）、事件上报（5/12）、Audit 巡检（6/34）、handoff/failover/disconnected（2/7/21/22）、多会话并行（7/12）、并发关联（45） |

## 7. 机器契约与静态检查

1. 运行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/megaco.json`，确认当前 JSON 恰有一个 `megaco_neg_unregistered`：`proto=megaco`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
2. **ID 权威 = 本文 §2**：设计 §7/§9、注册后的 `megaco.json`、audit 与本文 §2 保持同一 77 个语义 ID、同一顺序（46 正 + 31 负）；当前 JSON 另有不计语义覆盖的注册前置占位。
3. 46 个正例实现后均有 `packet_count`/`min_packets`、载体、方向、动态关联（nonzero/same_as_packet/distinct/包间关系）与可观察字段；31 个负例 `expect` 键集合恰为 `{expect_error,error_contains}`，packet_count 为 `—`；`wire_fault` 注入口与 §5 表逐行一致。
4. 线上断言以 tshark 实测为准（§3 清单，与设计 §3.9 一致）；2944 自动解码；2427 按 §1 规则（decode_as 或字节断言）。不得伪造未实测 `megaco.*` 字段名/格式。
5. 文本按 ABNF 语法边界校验：起始行、事务/动作/命令/描述符层级、LWSP/EOL/注释与大小写规则；SDP 内容大小写敏感且 `}` 转义（设计 §3）。
6. UDP 保留数据报边界（一数据报一消息，无 TPKT，超 MTU 拒绝——负例 76）；TCP 先按字节流重组、再按 TPKT 长度域切分消息（Annex D.2 SHALL）；MSS 分段不改变 TPKT PDU 边界。
7. 动态 transactionId/ContextID/媒体值只用 presence/nonzero/same_as_packet/distinct/类型长度，不枚举固定运行期 ID；边界固化 carve-out 用例（§1 清单）除外。
8. **pcap/NIC 双输出**：两输出路径共用本契约（同一 cases JSON、同一 tshark 字段/frames 断言），NIC 路径抓包口差异不改变断言语义（C-2）。
9. 负例覆盖 31 个可实现故障输入并逐行传播为 task error；`unknown layer` 占位不得冒充协议语义负例已执行。

## 8. 三方一致性表

设计 §7（负例表）/§9、本文 §2、实现后 `megaco.json` 保持同一 77 个语义 ID、同一顺序（当前 JSON 另有占位，不计入）：

```text
megaco_udp_ipv4_registration
megaco_udp_ipv6_failover
megaco_tcp_ipv4_dual_transaction
megaco_tcp_ipv6_call_flow
megaco_udp_ipv4_notify_events
megaco_udp_ipv4_audit_wildcard
megaco_udp_ipv4_handoff
megaco_udp_ipv4_abbrev_tokens
megaco_udp_ipv4_move_media
megaco_udp_ipv4_large_digitmap
megaco_tcp_ipv4_mss_reassembly
megaco_udp_ipv4_multi_session
megaco_tcp_ipv4_pending_immack
megaco_udp_2427_mgcp_alias
megaco_udp_ipv4_termid_max_length
megaco_udp_ipv4_transid_max
megaco_udp_ipv4_digitmap_timer_max
megaco_udp_ipv4_termination_state
megaco_udp_ipv4_version_negotiation
megaco_udp_ipv4_method_graceful
megaco_udp_ipv4_method_forced
megaco_udp_ipv4_method_disconnected
megaco_udp_ipv4_whitespace_comment_variants
megaco_udp_ipv4_mid_address_port
megaco_udp_ipv4_mid_devicename
megaco_tcp_ipv4_transaction_level_error
megaco_tcp_ipv4_ack_range
megaco_udp_ipv4_transid_zero_error_reply
megaco_udp_ipv4_reserved_value_group
megaco_udp_ipv4_eventbuffer_descriptor
megaco_udp_ipv4_mode_sendonly
megaco_udp_ipv4_mode_inactive
megaco_udp_ipv4_mode_loopback
megaco_udp_ipv4_audit_item_domain
megaco_udp_ipv4_signals_types
megaco_udp_ipv4_error_code_431
megaco_udp_ipv4_error_code_442
megaco_udp_ipv4_services_delay_timestamp
megaco_udp_ipv4_context_id_high_boundary
megaco_udp_ipv4_version_two_digits
megaco_udp_ipv4_streamid_max
megaco_udp_ipv4_embed_events
megaco_udp_ipv4_events_no_requestid
megaco_udp_ipv4_registration_redirect
megaco_udp_ipv4_concurrent_sessions
megaco_udp_ipv4_digitmap_z_timer
megaco_neg_encoding_text_as_ber
megaco_neg_encoding_port_mismatch
megaco_neg_syntax_start_line
megaco_neg_syntax_version_zero
megaco_neg_syntax_version_three_digits
megaco_neg_syntax_mid_missing
megaco_neg_syntax_mid_invalid
megaco_neg_syntax_body_form
megaco_neg_syntax_services_missing_params
megaco_neg_command_pre_registration
megaco_neg_command_modify_nonexistent
megaco_neg_command_reply_choose_all
megaco_neg_command_uncreated_context
megaco_neg_command_first_error_continues
megaco_neg_pairing_reply_id_mismatch
megaco_neg_pairing_pending_id_mismatch
megaco_neg_pairing_duplicate_transid
megaco_neg_pairing_ack_unconfirmed
megaco_neg_pairing_ia_without_pending
megaco_neg_pairing_observed_requestid
megaco_neg_length_message_truncated
megaco_neg_length_termid_over_64
megaco_neg_length_transid_over_uint32
megaco_neg_length_digitmap_timer
megaco_neg_length_context_reserved
megaco_neg_carrier_layer_mismatch
megaco_neg_carrier_entry_port_encoding
megaco_neg_carrier_invalid_port
megaco_neg_carrier_return_address
megaco_neg_carrier_udp_mtu_exceeded
megaco_neg_services_address_mgcidtotry_conflict
```

## 9. 修订记录

- v1.0.0（2026-08-31）：按 `protocol-doc-requirements.md` v1.0 强制契约重写，取代 2026-08-21 旧稿。两文档独立、统一术语（事件编排会话/多会话展开/事务/锚词）、14 正例 + 6 负例 + 1 占位、四层偏移（42/62/54/74）、UDP 每消息一包与 TCP 3+N+4 包数约定、多会话第二会话起点 = 前会话包数 + 1。正例 ID 统一 `megaco_` 前缀；BER 从正例移除、降为负例锚点；补充 tshark 实测证据与 2427 端口 mgcp dissector 绑定事实。
- 三向交叉审计（2026-08-31）2 轮：用例 3 T2 改 AuditValue 不存在终结点并覆盖 Error 描述符正例；用例 6 并入 AuditCapability；用例 9 并入 Move；用例 5 扩 4 消息使 RequestID 关联可断言；负例锚词表与设计 §7 对齐；规范回对补 505/406 语义与 `ImmAckRequired` 前提。
- 独立隔离审查修复：v1.1.0（2026-09-01）按独立审查员 22 项问题清单（F1–F22）逐项关闭：TCP 载体采用 TPKT 成帧（文本起点 58/78、帧字节 `[54..57]/[74..77]=03 00 <len>` 断言、定界改 TPKT 长度域）；用例 7 补必选 Reason；用例 4 回填改两条 Modify；O-/W- 并入用例 6；用例 8 补 Modify{Events} 对；§2 增"设计依据"列；新增正向边界用例 15-17（语义 ID 20→23）；用例 3 改"首错停止"两命令断言；负例 22 补 ContextID 保留值；用例 13 改单点 K、帧字节形态前缀断言、dissector 已知行为注记；删除用例 6 不可判定断言；§2 占位行与设计 §9 表同构；§6 覆盖映射重算。
- 复验修复 R1-R5（2026-09-01，独立审查复验轮）：R1 用例 12 会话 2 补 Events 编程对（Notify 前置编程），packet_count 8→10；R2 用例 13 帧字节断言裁为形态前缀、不固化 transactionId；R3 §6 数据场景落点补 7；R4 负例 19/21/23 各补故障输入使 §5.2 第 4 列锚词全部可触达；R5 用例 3 T2 第二命令改 `AuditValue = ROOT`。
- v1.2.0（2026-09-01，v1.3 重审修复轮）：rr-megaco 行为面 114 点全枚举重审（5 MAJOR C + 2 MAJOR D + 约 20 MINOR + 4 N）后重出：23 条 → **77 条（46 正 + 31 负）**。关键修复：**D-1**（CRITICAL）废除"23 个唯一语义 ID"固化契约——ID 权威改本文 §2，设计 §9 改为覆盖图景+权威指针；**C-2**（CRITICAL）负例逐故障输入原子拆分 6→31 行（一行一例单一注入、主锚词钉死、`wire_fault` 枚举扩 31 值三方同序）；**C-1/C-3** 并发会话翻案纳入（45，`concurrent: true` 交错回放；流关联/多流不适用声明合理保留）；**C-4** pcap/NIC 双输出声明（§1/§7.8）；**C-5/D-2** TerminationState 补例（18：ServiceStates/EventBufferControl 实测字段断言）；**C-6** 版本协商例（19：Services Version=2 提议、Reply Version=1 低版胜出）；**C-7** Method 值域补 Graceful/Forced/Disconnected（20-22）；**C-8** UDP 超 MTU 拒绝负例（76）；**C-9** 空白/注释变体例（23）；**C-10** mId 四形态补 `[IP]:port` 与 deviceName（24/25）；**C-11** 事务级 errorDescriptor 例（26，与 3 动作级分立）；**C-12** K 区间例（27，帧字节前缀断言绕开 dissector 区间首数行为）；**C-13** `transid 0` 错误 Reply 例（28）；**C-14** RV/RG（29）+EventBuffer（30）；**C-15** Mode 值域 SO/IN/LB（31-33）+auditItem 值域（34）+Signals OO/TO/BR+SignalList（35）；**C-16** 错误码 431/442（36/37）；**C-17** Services Delay/TimeStamp（38）+ServiceChangeAddress↔MgcIdToTry 互斥负例（77）；**C-18** 边界相邻值（39 ContextID 0xFFFFFFFD / 40 Version 2 位 / 41 StreamID 65535）；**C-19** Embed（42）+Events 无 RequestID（43）；**C-20** 注册改派流（44，Reply 携 ServiceChangeMgcId→转向新 MGC 重发）；**D-3/N-1** `mtpAddress` 形态改 `MTP{...}` 花括号（§3/设计 §3.1）；**D-4/N-3** DigitMap `T:0` 为禁用启动定时器的合法语义（设计 §3.5/§8 口径修正），越界负例限定 T>99 与 S/L 为 0（70），补 Z 修饰符例（46）；**D-5/N-2** 错误码出处改"部分正文引用、其余 H.248.8/IANA 注册"（设计 §3.5/§3.6）；**D-6/N-4** 用例 3 首错停止断言改包级字节包含原语（不以"区间"表述）；**N-5** tshark 字段清单补实测存在字段（`reservevalue/reservegroup/terminationstate`）。扩量正例：17 既有例全保留（3 断言修正、17 D-4 口径微调）+ 新增 29 例（18-46）。

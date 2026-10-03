# Kerberos V5 测试用例契约（层链 as-built）

> 版本：v1.1.0（2026-09-30）  
> 设计契约：`docs/protocols/kerberos/design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/kerberos.json`  
> 本轮只改文档和 cases 形状，不改 Go 或其他协议。

## T1 形状、来源和执行边界

20 个唯一 ID 按 JSON 顺序排列：14 个正例、6 个负例。每条 `spec_json` 都是目标任务配置：地址在 `layers[].ip`，端口在 `layers[].udp/tcp`，业务在 `layers[].kerberos`，无顶层 `src_ip`、`dst_ip`、`src_port`、`dst_port`、`count` 或协议子映射。`sessions[].src_ip/src_port` 是 kerberos 层内的会话覆盖，不是顶层旧键。

来源为 RFC 4120 §5–§7、RFC 6113、RFC 3961/4121、设计契约 D1–D8、实际生成器/链路代码和 JSON raw frame。历史 suite 产物记录 20/20 通过（`trafficgen/docs/protocol-pcap-test/kerberos.md`，2026-09-24）；本轮不重新执行，也不把该历史记录当作今日 NIC 证据。无密钥时仅断言外层、DER 顶层 tag/type、明文 realm/principal、错误码、padata 和 EncryptedData 外壳。

## T2 规范测试点与矩阵

| 测试点 | 规范/设计来源 | 用例 | 状态 |
|---|---|---|---|
| IPv4/UDP/88 AS 基线 | RFC 4120 §5.4.1 | #1 | 已覆盖 |
| IPv6/UDP/88 独立基线 | RFC 4120、CORE §9.24 | #2 | 已覆盖 |
| TCP/88 4-byte BE record | RFC 4120 §6 | #3 | 已覆盖，实测 11 帧 |
| AS/TGS/AP 请求—回复 | RFC 4120 §5.4 | #4–6、#9 | 已覆盖 |
| KRB-ERROR PREAUTH_REQUIRED | RFC 4120 §5.9、RFC 6113 | #7–8 | 已覆盖 |
| ticket/principal/realm | RFC 4120 §5.2/§5.3 | #5–6、#9 | 外壳已覆盖，内层 opaque |
| EncryptedData etype/kvno/cipher | RFC 3961/4121 | #6、#10 | 外壳已覆盖 |
| nonce/time/skew/replay/retry | RFC 4120 §3.2、§5.4 | #11–12、#19 | 正负均有 |
| 多 session、地址族、载体隔离 | CORE §3、§9 | #2、#13 | 已覆盖；IPv6/TCP 交叉为缺口 |
| 非法长度/tag/carrier | 设计 D5/D7 | #15–20 | 6 个负例 |

数据形态矩阵：地址 `{IPv4 #1, IPv6 #2}`；承载 `{UDP #1–2/4–14, TCP #3}`；消息 `{AS #1/4/7–8/11–13, TGS #5/8–9/13–14, AP #6/9–10/12–14, ERROR #1/7/11–12/14}`；DER `{短/长长度、顶层 tag、可见字段、opaque 密文}`；会话 `{单 #1–12/14，多 #13}`。IPv6/TCP、多会话 UDP↔TCP 交叉尚未有独立 fixture，见缺口 G-KERBEROS-2。

## T2 测试点清单先行与三源回指

清单先于逐例登记，来源不是现有 JSON 反推：RFC 4120 §5.1–§5.9、§6–§7，RFC 6113，RFC 3961/4121，CORE §3.8–§3.15、§9.20–§9.53 和设计 D9–D12。每行均给出规范条文、业务场景、代码分支和缺口结论。

| 规范条文 | 业务场景 | 代码分支 | 用例/缺口 |
|---|---|---|---|
| RFC 4120 §6 | UDP datagram、TCP 4B BE record、segment 切分 | `builder.go:390–415` | #1–3；IPv6/TCP G-KERBEROS-2 |
| RFC 4120 §5.2–§5.4.2 | AS/TGS/AP 请求响应及方向 | `builder.go:28–41,173–304` | #4–6、#9–10、#13–14 |
| RFC 4120 §5.9、RFC 6113 | PREAUTH_REQUIRED、METHOD-DATA、PA type/value 顺序 | `builder.go:118–159` | #7–8；商业 KDC 行为 G-KERBEROS-3 |
| RFC 4120 §3.2、§5.4 | nonce/time/skew/retransmission/replay | `planner.go:56–64` | #11–12、#19 |
| RFC 4120 §5.2/§5.3、RFC 3961/4121 | principal/realm、etype/kvno/cipher 外壳 | `builder.go:68–86,173–242` | #5–6、#9–10；无 key 内层不解密 |
| CORE §3.1–§3.13 | 独立 session、事务序列、端点隔离 | `builder.go:450–532` | #13；UDP↔TCP 交叉 G-KERBEROS-2 |
| CORE §9.46–§9.47 | 长/短 DER、空 padata、枚举 type、边界/非法值 | `der.go:19–50`、strict decode | #3、#6、#8、#10、#15–20 |
| CORE §9.49–§9.50 | 多事务、多 session、异常交织复杂场景 | sessions/events planner | #5、#12–14；现网复杂度补测 G-KERBEROS-4 |

### T1 三源回指

| 来源 | 条目 | 证据与用例 |
|---|---|---|
| 规范 | RFC 4120 §5–§7、§6；RFC 6113；RFC 3961/4121 | 设计 D9 矩阵；#1–12 |
| 设计 | D9 八项矩阵、D10 错误/性能、D11 动态字段、D12 门1 | 本文 T3–T6；#13–20 |
| 现网 | MIT/Heimdal/KDC 行为待授权抓包确认 | G-KERBEROS-3；确认后回填行为→用例映射，不把历史 PCAP 当 NIC 证据 |

### T3 颗粒度、三类场景与强度

- 数据场景：#1/#2 地址族，#3 TCP framing，#6/#10 etype/kvno/cipher 长度，#7/#8 padata type/value，#11 时间/nonce，#15–20 非法边界；枚举逐值或按分支代表，断言 tag、长度、字段值和错误锚词。
- 业务场景：#4–6、#9–10 的 AS→TGS→AP 序列；#7–8 预认证重试；#11 skew；#12 重传/replay；#13 三 session 交错；#14 复合载体核对。每例一个主行为点，组合序列只保留不可再分的状态链。
- 现网场景：#1、#3、#7、#12、#14 对应常见 UDP KDC、TCP fallback、预认证、重放和抓包一致性；商业软件版本与 NAT/代理行为未取证，按 G-KERBEROS-3 登记确认方式。
- 强度：tag/msg-type/error_code 逐分支；PA type 1/2/150 正交；IPv4/IPv6×UDP/TCP 交叉已标缺口；动态字段按整格审计（当前实现 fixed/list，见 D11），负例必须真拒。

### §3.15 三项与存量去向

| 必查项 | 用例/结论 |
|---|---|
| 同连接多轮操作 | #7–8、#12、#14；同一 session 内显式 events 序列 |
| 非正常结束 | #11 skew、#12 replay、#15–20 负例；错误传播必须 task error |
| 长保活 | Kerberos 生成器不维护协议计时器；作为 G-KERBEROS-4 性能/超时立项，不把 TCP 握手冒充保活 |

存量逐条审计：20 个 JSON ID 全部合入；14 个正例保留并以 JSON packet_count 为准；6 个负例保留并严格双键；历史 `kerberos_neg_unregistered` 占位作废，因协议已注册且不存在该当前故障面。无 mapping 文件；三源映射以本文件与设计 D9 为准。

## T3 原子用例索引（JSON 顺序权威）

| # | ID | 类型 | packet_count | 规范/设计回指 |
|---:|---|---|---:|---|
| 1 | `kerberos_ipv4_udp_as_basic` | 正 | 4 | D3/D4；IPv4/UDP/AS |
| 2 | `kerberos_ipv6_udp_as_basic` | 正 | 4 | D3；IPv6/UDP |
| 3 | `kerberos_tcp_record_framing` | 正 | 11 | D3；TCP 4B length、segment 切分 |
| 4 | `kerberos_as_req_as_rep` | 正 | 2 | D4；nonce/realm/principal |
| 5 | `kerberos_tgs_req_tgs_rep` | 正 | 6 | D4；krbtgt/service ticket |
| 6 | `kerberos_ap_req_ap_rep` | 正 | 6 | D4；ticket/authenticator opaque |
| 7 | `kerberos_krb_error_preauth_required` | 正 | 4 | D4；错误码 7、重试 |
| 8 | `kerberos_preauth_rfc6113` | 正 | 6 | D4；METHOD-DATA/padata 顺序 |
| 9 | `kerberos_ticket_principal_realm` | 正 | 6 | D4；组件和 realm |
| 10 | `kerberos_encrypteddata_opaque` | 正 | 6 | D4；etype/kvno/cipher 长度 |
| 11 | `kerberos_nonce_time_skew` | 正 | 6 | D4；nonce/time/skew |
| 12 | `kerberos_replay_retransmission` | 正 | 8 | D4；重传/replay 错误 |
| 13 | `kerberos_multi_session_flow` | 正 | 12 | D4；三 session/端点隔离 |
| 14 | `kerberos_pcap_nic_consistency` | 正 | 8 | D3/D7；双向外壳一致 |
| 15 | `kerberos_neg_truncated_record` | 负 | — | D7；record/truncated |
| 16 | `kerberos_neg_tcp_length` | 负 | — | D7；tcp length/framing |
| 17 | `kerberos_neg_message_tag` | 负 | — | D7；tag/version/message |
| 18 | `kerberos_neg_encrypted_boundary` | 负 | — | D7；encrypted/cipher boundary |
| 19 | `kerberos_neg_time_nonce_replay` | 负 | — | D7；time/nonce/replay |
| 20 | `kerberos_neg_udp_carrier` | 负 | — | D7；udp/transport/carrier |

正例的 `expect` 断言 packet_count、tshark/common carrier 字段和 raw frames；动态 nonce、ticket、时间、cipher 只用 presence/nonzero/same-as/distinct。TCP 实测 packet_count=11、AS 单对实测 2，均以 JSON 和真实生成器产物为准，不沿用旧设计约定 8/4。

## T4 正例断言和失败路径

- #1–2：目的端口 88、IPv4/IPv6 next protocol 17、起点 42/62、V5 AS 顶层 tag、双向四帧；IPv6 UDP checksum 非零。
- #3：TCP/88 handshake、起点 54、每条消息 4-byte BE length；record 可跨 segment，实测含 11 个线上帧。
- #4–6、#9–10：AS/TGS/AP 顶层 tag 与 pvno/msg-type 自洽；realm/principal 组件、ticket/EncryptedData 外壳可见，密文内层不作断言。
- #7–8：KRB-ERROR code 7、METHOD-DATA/padata type/顺序、PA-ENC-TIMESTAMP 外壳和后续请求；不把错误当 AS-REP。
- #11–12：nonce/request 关联、合法时间窗口、重传复用请求 bytes；重复 AP-REQ 产生 replay 错误而不推进状态两次。
- #13：独立 session 端点和状态，不串 nonce/ticket/replay/TCP buffer；不假设全局到达顺序。
- #14：PCAP/NIC 计划使用 `udp port 88 or tcp port 88`，核对方向、端口、tag 和 framing；本轮未重新执行 NIC。

## T5 负例契约、真实流程和性能

负例 `expect` 严格只有 `expect_error`、`error_contains`；不得有 fields、frames、packet_count 或 notes。六例分别覆盖：消息/DER 截断、TCP length、tag/msg-type、EncryptedData 边界、time/nonce/replay、载体/端口/双载体。错误必须经 planner/validator 传播为 task error，不能 completed/0 packet 或仅生成 UDP/TCP 外壳。

真实验收顺序：经 MCP 建策略/任务 → 引擎生成 PCAP 或授权 NIC 发包 → tshark/raw frame 逐字段校对；二进制须与当前代码同代。性能补测需覆盖基线、目标规模、压力上限、长时运行、并发交错、资源耗尽/背压，并分别记录包/秒、bit/s、并发 session/flow、最大记录、内存、队列积压及失败/丢包；当前无本轮数字。

### 多轮、异常终止、长保活

多轮编排由 `sessions[].events[]` 声明序列表达，一轮一消息，按声明顺序生成；重试/重传由 `#8/#12` 的显式事件重放表达，不是生成器内部隐式行为。异常终止由 `krb_error` 事件和六个负例表达：KRB-ERROR 只标记错误码并继续声明序列，负例在 planner/validator 层直接拒绝，不产生半成品产物。长保活和 timeout 语义由 Kerberos 标准单独定义，当前生成器不维持连接计时器，TCP 握手/挥手帧属于承载层，不计入事件包数。

### C1–C6 原子核验（每个可单独复验）

| 门项 | 断言 | JSON 证据 |
|---|---|---|
| C1 | top 为数组、20 ID 唯一且有序 | `#1–20` 顺序与 T3 表一致 |
| C2 | 正例 `spec_json` 顶层仅 `layers`；`[ip,udp\|tcp,kerberos]` | `#1–14` 顶层键束均为 `['layers']` |
| C3 | 端口只在 `udp/tcp`；`sessions[]` 覆盖在 kerberos 层 | 端口在承载层；`#13` 三 session 用 `src_ip/src_port` 覆盖 |
| C4 | 负例 expect 严格双键且两键非空 | `#15–20` 仅 `expect_error`、`error_contains` |
| C5 | 命令×码、正负错、边界、载体、会话隔离 | T2 表与 T3 回指列 |
| C6 | 本轮不改 Go/全局/其他协议 | `git status` 只含 Kerberos 三文件 |

## T6 存量审计、缺口和 C1–C6

### 存量逐条去向

| 存量 | 去向 | 说明 |
|---|---|---|
| 20 个 JSON ID | 全部保留 | 生成器提交已产出 20 例，顺序不变 |
| 14 个正例 | 保留 | 真实 packet_count 以 JSON 为准 |
| 6 个负例 | 保留 | 单一故障、严格双键 expect |
| 历史 `kerberos_neg_unregistered` 占位 | 作废 | 已注册且 cases 已完整 20 例；不再保留 unknown-layer 假边界 |

### C1–C6 审查门

| ID | 检查 | 结论 |
|---|---|---|
| C1 | JSON 可解析、20 ID 唯一、顺序与本文/设计一致 | 绿 |
| C2 | 正例严格层链；顶层旧键零残留 | 绿 |
| C3 | 地址在 ip，端口在 udp/tcp，Kerberos 业务在 kerberos 层 | 绿；session 覆盖为层内字段 |
| C4 | 6 负例仅 `expect_error`/`error_contains`，锚词非空 | 绿 |
| C5 | AS/TGS/AP、PREAUTH、opaque、replay、多 session 和载体边界均有例 | 绿；IPv6/TCP 交叉和性能待补 |
| C6 | 本轮范围仅三份 Kerberos 文件，未改 Go/全局/其他协议 | 绿 |

### 缺口登记

| ID | 缺口 | 处理 |
|---|---|---|
| G-KERBEROS-1 | 本轮未重跑 MCP→PCAP/NIC→tshark | 二进制同代后全量重跑 20 例 |
| G-KERBEROS-2 | IPv6/TCP 与多 session UDP↔TCP 交叉无独立 fixture | 新增层链例，先跑后钉包数/offset |
| G-KERBEROS-3 | 商业设备行为、keytab/key log 未取证 | 授权抓包/密钥证据后单独扩展 |
| G-KERBEROS-4 | 性能六档无当前基准 | 实现阶段补测并记录 PCAP/NIC 两路 |

## 修订记录

- v1.1.0（2026-09-30）：按 T1–T6、C1–C6 和层链唯一真相重写；对账 20 例、14/6、实际 packet_count；清除过期未注册占位口径，登记真实执行、交叉地址族、第三源和性能缺口；自审两轮，末轮干净。
- v1.0.0（2026-08-20）：历史设计阶段测试契约。

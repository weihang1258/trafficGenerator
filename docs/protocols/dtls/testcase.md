# DTLS（数据报传输层安全，Datagram Transport Layer Security）测试用例契约

> 版本：v1.3.0（2026-10-01；T1–T6 完成，运行期边界单列）
> 日期：2026-10-01
> 配套设计：`docs/protocols/dtls/design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/dtls.json`
> 状态：`dtls` 层已注册；本文与 JSON 对账为 20 ID（14 正例、6 负例）。本轮只改文档与层链契约，**未运行 suite、未跑 Go 测试、未起服务、未抓 NIC**；静态闭合不等于已验收。

## T1 形状、来源和执行边界

20 个唯一 ID 按 JSON 数组顺序排列：14 个正例、6 个负例。每条 `spec_json` 都是目标任务配置：地址只住 `layers[].ip`（`src`/`dst`），端口只住 `layers[].udp`（`src_port`/`dst_port`；负例 `dtls_neg_udp_carrier` 用 `layers[].tcp` 承载非法载体），DTLS 业务只住 `layers[].dtls`；无顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`，也无顶层 `dtls` 子映射。`sessions[].src_ip`/`src_port`/`dst_port`/`version` 是 `dtls` 层内的会话覆盖，不是顶层旧键。

来源三路：① 规范为 RFC 6347 §3.1/§4.1/§4.2（DTLS 1.2）、RFC 4347（DTLS 1.0 记录语义）、RFC 768（UDP 载体），RFC 8446 仅作边界参考；② 设计来源为设计 §2–§10、§13.1–§13.5；③ 现网来源为 OpenSSL/主流 DTLS 服务端 cookie challenge 与 flight 行为、tshark 只可靠显示外层字段（设计 §13.3/§14.3）。三路均以 PCAP/NIC 复核确认；无解密证据时只断言外层 record 字段与明文握手记录。

执行边界：DTLS 是 UDP/4433 数据报协议。无 VLAN、IPv4 options、IPv6 extension header 时，IPv4/UDP record 起点为 offset 42，IPv6/UDP 为 62；每条 DTLS record 固定 13-byte header。加密 epoch 后 PCAP/NIC 只可断言 content type、版本、epoch、48-bit sequence、Length 和密文长度，不可声称看见明文 handshake、cookie、alert 或 application data。

## T2 规范测试点与矩阵

### 测试点清单（规范条文 → 业务场景 → 代码分支 → 用例）

| 规范条文 | 业务场景 | 代码分支/契约 | 覆盖与缺口 |
|---|---|---|---|
| RFC 6347 §4.1 record/epoch/sequence | 版本、13-byte header、epoch 切换 | `putRecord`/`dtlsWalker.nextRecord` | 已覆盖：#1/#3/#7/#12；真实包数以落盘 PCAP 校准 |
| RFC 6347 §4.2 cookie/flight | cookie challenge、重传、超时关闭 | `handshakeBody`（type 3 组 cookie）/`nextMsgSeq` | 已覆盖：#4/#9/#10；真实计时边界待实现校准（G-DTLS-3） |
| RFC 6347 §4.2.2 分片 | 乱序 fragment 重组 | `handshakeBody` 24-bit 长度/偏移守卫 | 已覆盖：#5/#6；非法边界 #18 |
| RFC 768 + RFC 6347 §3.1 | IPv4/IPv6 UDP carrier、checksum | `ip→udp→dtls` 层链 + `validate_layers` 预检 | 已覆盖：#1/#2/#11/#13/#20 |
| RFC 6347 §4.1.2 加密边界 | CCS 后 opaque records | `cipherFill` 确定性填充 | 已覆盖：#8/#14；无 key log 不断言明文 |
| RFC 6347 §4.1 非法值 | 截断/非法版本/序号回绕/分片越界/cookie 状态/载体错 | 6 个 `wire_fault` 值 + 自然守卫 + 预检 | 已覆盖：#15–#20 |

### 数据形态变体表（协议相关全部形态逐项）

| 变体维度 | 取值 | 用例 | 缺口 |
|---|---|---|---|
| 地址族 | IPv4 / IPv6 | #1 / #2 | IPv6 与其他维度交叉格见 G-DTLS-4 |
| 记录版本 | `fe fd`(1.2) / `fe ff`(1.0) | #1,#2,#4–#14 / #3 | 1.0×IPv6 无例（G-DTLS-4） |
| content type | 20 CCS / 21 alert / 22 handshake / 23 appdata | #8/#9 / #8/#9/#14 / #1–#6/#13 / #8/#12/#14 | 未知 type 由 #16 负例覆盖 |
| 分片形态 | 单片 / 跨 record 分片 / 乱序重组 | #1 / #5 / #6 | — |
| epoch | 0（明文）/ 1（加密） | #1–#6 / #7–#14 | — |
| 方向 | up / down | 全部正例均含双向 | — |
| 载体 | UDP | #1–#19 | TCP 载体由 #20 负例拒 |
| 会话数 | 单会话 / 双会话 | #1–#9,#12–#14 / #10 | — |
| 流数 | 单流 / 多流（端点覆盖） | #1–#10,#12–#14 / #11 | — |
| 长度边界 | 1 / 62 / 1400 / 0（链级单测） | #12（1/62/1/2/1400/1） | Length=0 由 `TestDTLSChain_ZeroLengthRecord` 承接 |

### 正交组合矩阵（9.23；已覆/缺失逐格）

| 维度交叉 | IPv4 | IPv6 |
|---|---|---|
| 单会话 × 1.2 | #1 | #2 |
| 单会话 × 1.0 | #3 | **缺（G-DTLS-4）** |
| 多会话 | #10 | **缺（G-DTLS-4）** |
| 多流 | #11 | **缺（G-DTLS-4）** |
| 分片/乱序 | #5/#6 | **缺（G-DTLS-4）** |
| 加密 opaque | #8/#14 | **缺（G-DTLS-4）** |

动态策略×字段矩阵（9.32/9.33）：14 个正例的四元组与业务字段**全部为静态标量**，`fixed/inc/rand/list/pattern` 五策略×字段一格未落，登记为 G-DTLS-2（B 类缺口，不冒充已覆盖）。

### §3.15 三项场景

- 同连接多轮操作：#4 `dtls_v12_cookie_exchange` 的 ClientHello（无 cookie）→ HelloVerifyRequest → 带 cookie 的 ClientHello → 继续握手（T4）。
- 非正常结束：#9 `dtls_retransmission_timeout` 的 flight 重传→超时错误/alert close，#8 的 alert 关闭；失败传播由 #15–#20 负例验证。
- 长保活：DTLS 无应用层长保活语义；立项 `D-DTLS-KEEPALIVE-1`，确认方式为查 RFC 6347 profile 与主流实现的 heartbeat/empty-record PCAP，未确认前不增加业务断言（G-DTLS-7）。

## T3 原子用例索引（JSON 顺序权威）

| # | ID | 类型 | 覆盖 | 约定 packet_count | 三源回指 |
|---:|---|---|---|---:|---|
| 1 | `dtls_ipv4_v12_basic` | 正 | IPv4/UDP 4433、DTLS 1.2 基本握手记录 | 12 | RFC 6347 §4.1；设计 §3/§4 |
| 2 | `dtls_ipv6_v12_basic` | 正 | IPv6/UDP 4433、DTLS 1.2 独立 fixture | 12 | RFC 6347 §3.1；设计 §9 |
| 3 | `dtls_v10_legacy_record` | 正 | DTLS 1.0 `fe ff` record/version 边界 | 12（v1.0.1 实测重钉，原约定 8） | RFC 4347；设计 §4 |
| 4 | `dtls_v12_cookie_exchange` | 正 | ClientHello、HelloVerifyRequest、带 cookie 的 ClientHello | 16 | RFC 6347 §4.2.1；设计 §7 |
| 5 | `dtls_handshake_fragmentation` | 正 | 单握手消息跨 records 的 fragment header | 10 | RFC 6347 §4.2.2；设计 §6 |
| 6 | `dtls_handshake_reassembly` | 正 | 分片乱序重组、message_seq/offset 完整性 | 10 | RFC 6347 §4.2.2；设计 §6 |
| 7 | `dtls_epoch_sequence_transition` | 正 | epoch 0→1、每方向 48-bit sequence 独立递增 | 14 | RFC 6347 §4.1；设计 §5 |
| 8 | `dtls_ccs_alert_application` | 正 | CCS、alert、application data 外层类型与关闭 | 16 | RFC 6347 §4.1；设计 §5/§8 |
| 9 | `dtls_retransmission_timeout` | 正 | flight 重传、超时、异常关闭/最终错误 | 18 | RFC 6347 §4.2.4；设计 §7 |
| 10 | `dtls_multi_session_isolation` | 正 | 两个独立 session 的 cookie/epoch/sequence/关闭 | 24 | CORE §3；设计 §9 |
| 11 | `dtls_multi_flow` | 正 | 多四元组、多方向流和不串用状态 | 12 | CORE §3；设计 §9 |
| 12 | `dtls_record_boundary_lengths` | 正 | 空 record、最大附近 Length、UDP datagram 边界 | 6 | RFC 6347 §4.1；设计 §10 |
| 13 | `dtls_pcap_nic_consistency` | 正 | PCAP/NIC 方向、4433、record header 一致 | 16 | CORE §6/§14；设计 §12 |
| 14 | `dtls_encrypted_opaque_boundary` | 正 | 加密后的外层字段可见、内层明文不可声称可见 | 10 | RFC 6347 §4.1.2；设计 §8 |
| 15 | `dtls_neg_record_truncated` | 负 | record header/Length 截断 | — | 设计 §10 |
| 16 | `dtls_neg_version_epoch` | 负 | version/content type/epoch 非法 | — | 设计 §10 |
| 17 | `dtls_neg_sequence_overflow` | 负 | 48-bit sequence 溢出、回绕或重复 | — | 设计 §10 |
| 18 | `dtls_neg_fragment_bounds` | 负 | handshake 分片边界/重叠/拼接错误 | — | 设计 §6/§10 |
| 19 | `dtls_neg_cookie_state` | 负 | cookie 状态、重传状态或握手顺序错误 | — | 设计 §7/§10 |
| 20 | `dtls_neg_udp_carrier` | 负 | UDP/4433 载体、checksum 或 datagram 边界错误 | — | 设计 §3/§10 |

正例的 `expect` 断言 `packet_count`、tshark 字段与稳定 raw frames（5 例带 frames：#1/#2/#12/#13/#14；其余为 `[]`）；动态端口、cookie、sequence 或加密字节使用 `nonzero`、`distinct_values`、`same_as_packet`，不猜测运行期随机常量。负例执行期 `expect` 严格只有 `expect_error`、`error_contains`。

## T4 正例断言和失败路径

1. **`dtls_ipv4_v12_basic`**：一条 IPv4/UDP/4433 session，断言 `ip.proto=17`、record offset 42、版本 `fe fd`、type 22/20/23 的合法顺序、epoch 初始为 0，`packet_count=12`；raw frame 钉首包 13-byte 头与前 42 字节前缀；不得断言加密后的握手 body。
2. **`dtls_ipv6_v12_basic`**：outer `ipv6.nxt=17`、UDP/4433，record offset 62，版本 `fe fd`、IPv6 地址与 IPv4 fixture 独立，`packet_count=12`；IPv6 UDP checksum 非零且正确。
3. **`dtls_v10_legacy_record`**：会话 `version="1.0"`，record 版本 raw `fe ff`，type 22、13-byte header、epoch/sequence 合法，`packet_count=12`；不得套用 TLS `03 xx` 版本。
4. **`dtls_v12_cookie_exchange`**：至少观察 ClientHello（type 1）→ HelloVerifyRequest（type 3，`cookie_length=3`）→ 第二个 ClientHello（type 1）→ 继续握手，`packet_count=16`；cookie 用 presence/length 断言，不猜测值。
5. **`dtls_handshake_fragmentation`**：一个 handshake message 的 12-byte header 中完整 length、message_seq、fragment_offset/fragment_length；三条 type 22 records 携带 offset 0/8/16 的片段，`packet_count=10`，不把 fragment length 当完整 message length。
6. **`dtls_handshake_reassembly`**：乱序片段（offset 8 → 0 → 16）按 message_seq/offset 重组后只推进一次状态；raw header 的 24-bit length/offset/fragment length 网络序正确，`packet_count=10`；不假设 datagram 全局顺序。
7. **`dtls_epoch_sequence_transition`**：每方向至少有 epoch 0 sequence 0、epoch 1 sequence 0/1/2；断言 sequence 为 6-byte big-endian、epoch 不回退且双向独立；重传复用握手消息的 `message_seq` 但 record sequence 不复用，`packet_count=14`。
8. **`dtls_ccs_alert_application`**：明文 CCS type 20 与明文 alert type 21（`alert_message.level=2`/`desc=10`）后进入加密 epoch；外层随后出现 type 23 application data 和 type 21 alert/关闭，`packet_count=16`。加密 alert 只断言 type/epoch/Length，不断言 level/description。
9. **`dtls_retransmission_timeout`**：同一 ClientHello 以 `message_seq=0` 重发两次、HVR cookie 重发两次、带 cookie 的 ClientHello 以 `message_seq=1` 重发两次；重传复用 `message_seq` 但 record sequence 递增（#5→2、#6→3）；超过 retry limit 后以 alert 关闭（#15 type 21），`packet_count=18`；不得 completed/0 packet。
10. **`dtls_multi_session_isolation`**：两条独立 UDP session（src_port 5001/5002，第二条另有 `src_ip=192.0.2.64`）各自完成 cookie/epoch/sequence/关闭，`packet_count=24`；断言第二条会话 epoch/sequence 从 0 重新起算、cookie 长度各自独立（3 / 1），`udp.srcport` distinct 集为 {5001,5002}。
11. **`dtls_multi_flow`**：两条会话以 `src_ip`/`src_port` 覆盖区分（192.0.2.64:5001 与 192.0.2.63:5002），双向流不拼 handshake 片段，`packet_count=12`；断言 `ip.src` 与 `udp.srcport` 的端点归属一致，不假设全局顺序。
12. **`dtls_record_boundary_lengths`**：record 长度边界面（v1.0.1：Length=0 由实现侧链级单测 `TestDTLSChain_ZeroLengthRecord`（`trafficgen/internal/core/layers/dtls_chain_test.go:391`）承接——tshark 对 0 长 record 恒标 Malformed 不能作干净正例；本用例断言 1/62/1/2/1400/1 六档与 13-byte header/Length 边界一致，含 `dtls.handshake.length=50`，`packet_count=6`，显式值不可被默认值替换）。
13. **`dtls_pcap_nic_consistency`**：同一 fixture 输出 PCAP 并在指定 NIC capture；两条方向明确的 UDP/4433 records 的 version/type/epoch/Length 和稳定前缀一致（`udp.dstport=4433` 与应答侧 `udp.srcport=4433`），`packet_count=16`；过滤器为 `udp port 4433`，记录 checksum offload。本轮未执行 NIC。
14. **`dtls_encrypted_opaque_boundary`**：加密 epoch records 仅断言 type/version/epoch/6-byte sequence/Length 和密文长度（type 23 len 8、type 21 len 2），`packet_count=10`；不能写 `dtls.handshake.type` 或明文 alert/application payload 的断言，除非提供 key log 解密证据。

失败路径：正例异常 timeout 断言重传可观察且最终 error/alert close，不能以任务未报错替代输出校验；负例必须经真实 planner/validator 路径被拒（T5）。

## T5 负例契约、真实流程和性能

每个负例必须在 planner/validator 失败并传播为 task error；不能产生成功 PCAP、completed/0 packet 或只剩 UDP 外壳的假成功。`expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 拒绝通道 | 目标 `error_contains` |
|---|---|---|---|
| `dtls_neg_record_truncated` | `wire_fault="record_length"`：Length 与实际 datagram 字节不符 | `validateWireFault` 注入拒 | `record` |
| `dtls_neg_version_epoch` | `wire_fault="version_epoch"`：非法版本/epoch | `validateWireFault` 注入拒 | `version` |
| `dtls_neg_sequence_overflow` | `wire_fault="sequence_overflow"`：seq 超 48-bit | `validateWireFault` 注入拒 | `sequence` |
| `dtls_neg_fragment_bounds` | 自然非法配置：`fragment_offset+fragment_length > length` | `handshakeBody` 自然守卫拒 | `fragment` |
| `dtls_neg_cookie_state` | 自然非法配置：`cookie` 出现在 `type=1`（非 HVR） | `handshakeBody` 自然守卫拒 | `cookie` |
| `dtls_neg_udp_carrier` | `layers[].tcp` 承载 DTLS | `validate_layers` 预检拒 | `udp` |

合法的空 record、epoch=0/1、DTLS 1.0 `fe ff`、IPv4 zero checksum、IPv6 non-zero checksum、cookie 重传、乱序 fragment、加密 opaque payload 和异常 timeout 由正例覆盖，不能误报为负例。错误传播必须保留原始原因，不能用通用“0 packets”替代验证错误。

真实验收顺序（CORE §14）：经 MCP 建策略/任务 → 引擎生成 PCAP 或授权 NIC 发包 → tshark/raw frame 逐字段校对；服务器二进制须与代码 HEAD 同代。性能补测需覆盖基线、目标规模、压力上限、长时运行、并发交错、资源耗尽/背压六档，并分别记录包/秒、bit/s、并发 session/flow、最大记录、内存、队列积压及失败/丢包；**当前无本轮数字**（G-DTLS-6）。

## T6 存量审计、缺口和 C1–C6

### 存量逐条去向（9.14）

历史 20 个 DTLS 条目逐条合入当前 20 个 ID：14 个正例（`dtls_ipv4_v12_basic`、`dtls_ipv6_v12_basic`、`dtls_v10_legacy_record`、`dtls_v12_cookie_exchange`、`dtls_handshake_fragmentation`、`dtls_handshake_reassembly`、`dtls_epoch_sequence_transition`、`dtls_ccs_alert_application`、`dtls_retransmission_timeout`、`dtls_multi_session_isolation`、`dtls_multi_flow`、`dtls_record_boundary_lengths`、`dtls_pcap_nic_consistency`、`dtls_encrypted_opaque_boundary`）均合入并保留；6 个负例（`dtls_neg_record_truncated`、`dtls_neg_version_epoch`、`dtls_neg_sequence_overflow`、`dtls_neg_fragment_bounds`、`dtls_neg_cookie_state`、`dtls_neg_udp_carrier`）均合入并按真实拒绝入口归类。

作废一条：旧 Length=0 干净正例，原因是 tshark 将其标记 Malformed，零长语义迁入 `TestDTLSChain_ZeroLengthRecord`（见 T4 第 12 项与修订记录）；除此之外无作废条目。

### C1–C6 审查门

| ID | 检查 | 结论 |
|---|---|---|
| C1 | JSON 可解析、20 ID 唯一、顺序与本文 T3/设计 §11 一致 | 绿（`python3 -m json.tool` 通过；14 正 + 6 负） |
| C2 | 正例严格层链；顶层旧键零残留 | 绿（正例顶层仅 `layers`；无 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/顶层 `dtls`） |
| C3 | 地址在 `ip`，端口在 `udp`（负例 `tcp`），DTLS 业务在 `dtls` 层 | 绿；`sessions[].src_ip/src_port/dst_port/version` 为层内会话覆盖 |
| C4 | 6 负例仅 `expect_error`/`error_contains`，锚词非空 | 绿（键集合逐一核对为两键） |
| C5 | cookie/flight、分片/重组、epoch/sequence、CCS/alert/opaque、多会话/多流、长度边界、载体边界均有例 | 绿；动态字段、IPv6 交叉格、真实计时待补（G-DTLS-2/3/4） |
| C6 | 本轮范围仅本协议三份文件（`design.md`/`testcase.md`/`cases/dtls.json`），未改 Go/全局/其他协议 | 绿 |

### 缺口登记

| ID | 缺口 | 处理 |
|---|---|---|
| G-DTLS-1 | 本轮未重跑 MCP→PCAP/NIC→tshark；静态闭合不等于已验收 | 二进制同代后全量重跑 20 例（CORE §14.19 全量非增量） |
| G-DTLS-2 | 动态字段零覆盖：四元组与业务字段五策略×字段矩阵一格未落 | 按 CORE §12/§9.32 补 `fixed/inc/rand/list/pattern` 整格用例，先跑后钉 |
| G-DTLS-3 | 真实 flight 计时/重传上限/超时数值未校准；#9 为声明式事件序列，非真实计时器 | 实现侧计时器落地后以 PCAP 校准重钉 |
| G-DTLS-4 | IPv6×（多会话/多流/分片/1.0/加密）交叉格无独立 fixture | 新增层链例，先跑后钉包数/offset |
| G-DTLS-5 | 商业设备（OpenSSL 等）cookie challenge/flight 行为未取证 | 授权抓包或官方文档取证后单独扩展 |
| G-DTLS-6 | 性能六档无当前基准 | 实现阶段补测并记录 PCAP/NIC 两路 |
| G-DTLS-7 | 长保活（heartbeat/empty record）语义未确认 | `D-DTLS-KEEPALIVE-1` 立项，查 RFC 6347 profile 与主流实现 PCAP |

### 静态检查

1. 设计 §11、本文 T3、`cases/dtls.json` 保持同一 20 个语义 ID、同一顺序；14 正例 + 6 负例。
2. 固定 offsets 为 IPv4/UDP DTLS=42、IPv6/UDP=62；record header 永远 13 bytes；Length 只覆盖 fragment。
3. Record raw frame 只固定可复核的 content type、`fe ff`/`fe fd`、epoch/sequence 宽度和稳定长度；cookie、端口、密文和运行期序列使用动态断言。
4. Handshake 12-byte header 的 length/offset/fragment length 均为 24-bit 网络序；重组按 message_seq/offset，不按 TCP 字节流规则。
5. 加密 epoch 后不得声称看见明文握手、cookie、alert level/description 或 application payload；只有明文 fixture/key log 解密证据才可扩大断言。
6. DTLS 使用 UDP/4433，不测试 TCP handshake/MSS/FIN；IPv4 checksum 可零或正确非零，IPv6 checksum 必须非零且正确。
7. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/dtls.json` 应成功；数组含完整 20 个语义 ID，顺序与本文 T3 一致。
8. 若 tshark 无 `dtls.*` 字段，使用稳定 raw frames 与通用 `udp`/`ip`/`ipv6` 字段，不自创解析字段。

### T-DTLS 原子追踪与 C-DTLS 对照

T-DTLS-01…14 对应 T3 的 14 个正例，T-DTLS-N01…N06 对应六个负例；每个 ID 只有一个主要行为断言，负例 `expect` 严格保留两键。C-DTLS 对照：RFC 4347/6347 记录/握手边界落在 T4/T5/T6/T9，OpenSSL cookie/flight 形态落在 T4/T8/T9，tshark opaque 可见性落在 T8/T14（设计 §14.3）。

## T7 运行期未验证边界（不是通过声明）

本轮仅完成静态文档、JSON 机读审计和锚词源码核对，未运行真实 suite、未起服务、未生成/读取 PCAP、未做 NIC 抓包，也未运行 timeout 计时验证。因此：

- `dtls_retransmission_timeout` 的 timeout、retry limit、重传间隔仍是待钉参数，事件形状不等于真实计时器证据。
- 五种动态策略（`fixed/inc/rand/list/pattern`）在四元组和 DTLS 业务字段上均未验证；14 个正例全部是静态标量。
- PCAP/tshark 字段、raw frame 与 NIC 方向/校验和卸载均未验证；性能基线、目标规模、压力、长跑、交错、背压六档亦无数字。
- Length=0 虽是协议边界，tshark 会将零长 DTLS record 标为 `Malformed`，因此不能用它作干净正例；零长只由链级 `TestDTLSChain_ZeroLengthRecord` 承接。无 dissector/key log 时退回通用 UDP/IP 和 raw bytes，不虚构 `dtls.*` 明文断言。

## T8 C4 锚词核对与静态形状证据

六个负例 `expect` 键集合逐条为且仅为 `expect_error`、`error_contains`，无 `packet_count`/`frames`。`record`、`version`、`sequence` 三个注入锚词由 `trafficgen/internal/core/dtls.go:131-144` 的 `DescribeDTLSWireFault` 给出；`fragment`、`cookie` 由 `trafficgen/internal/protocol/dtls/builder.go` 分片和 cookie 守卫给出；`udp` 由层载体预检契约给出。若运行期文案不同，必须先以同代二进制实测再更新，不把猜测写成通过。

机读对账：总 20，正 14，负 6；ID 顺序与 T3 一致；`spec_json` 顶层形状 `{"layers"}:20`；层链 `ip→udp→dtls`:19、故意 presence 负例 `ip→tcp→dtls`:1。`strategy_fc`/`flow_control` 均未出现，因为所有正例都是单流；不能将缺席误写成迁移失败。

## T9 修订记录

- v1.2.0（2026-10-01）：按 T1–T6 + C1–C6 结构重写，补齐测试点清单、数据形态变体表、正交组合矩阵、§3.15 三项、存量逐条去向与编号缺口（G-DTLS-1…7）；修正配置示例为事件对象形状（`kind`/`up`）、字段名 `seq`、负例拒绝通道三分；明确本轮未跑 suite/NIC。
- v1.1.0（2026-09-30）：修正已注册/已落地状态、配套路径与 20 例 JSON 对账；补充层链形状、三源映射、规范矩阵和未实现能力缺口说明。
- v1.0.1（2026-09-24，P5 实测重钉 + P6 修轮对齐）：①③ `dtls_v10_legacy_record` packet_count 约定 8 → 实测 12（裁定4+§9.31，全事件面 12 record）；②⑫ `dtls_record_boundary_lengths` 的 Length=0 record 改 1B opaque（tshark 对 0 长 record 恒标 Malformed，无法作为干净正例断言），零长语义由实现侧链级单测 `TestDTLSChain_ZeroLengthRecord`（13B 头 Length=0 无 payload 逐字节钉）承接；③负例通道据实三分：`record_truncated`/`version_epoch`/`sequence_overflow` 走 wire_fault 注入拒，`fragment_bounds`/`cookie_state` 走自然非法配置守卫拒，`udp_carrier` 走 validate_layers 预检拒。

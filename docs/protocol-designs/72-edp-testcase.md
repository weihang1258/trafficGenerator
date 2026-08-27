# EDP（物联网边缘设备数据协议，IoT Edge Data Protocol）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-21  
> 配套设计：`docs/protocol-designs/72-edp-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/edp.json`  
> 状态：`edp` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `edp_neg_unregistered`，其 `expect` 必须 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

EDP v1 使用 TCP 字节流和 40 字节固定帧头；测试必须先重组 TCP，再按 `frame_length` 分离帧，不把 TCP segment（分段）边界当作 EDP 边界。动态 `device_id`、`message_id`、`sequence`、`timestamp`、JSON 数值、二进制样本、CRC 和 TLS 密文不能硬编码；使用 `presence`、`nonzero`、`same_as_packet`、`distinct`、长度/范围和跨帧关系断言。TLS 未解密只能断言 TLS carrier（载体）元数据，不断言 EDP magic、类型或 CRC。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `edp_tcp_ipv4_registration` | 正 | IPv4/TCP 注册、v1 帧头、动态设备/消息标识 | 8 |
| 2 | `edp_tcp_ipv6_heartbeat` | 正 | IPv6/TCP 心跳、序号/时间戳和 CRC | 8 |
| 3 | `edp_json_telemetry_v1` | 正 | v1 JSON 遥测字段类型和动态序列 | 8 |
| 4 | `edp_binary_telemetry_v1` | 正 | binary-v1 tag/length/value 负载 | 8 |
| 5 | `edp_command_response` | 正 | 命令、响应和动态 request_message_id 关联 | 10 |
| 6 | `edp_batch_data` | 正 | 批量数据顺序、计数和批量 ACK | 10 |
| 7 | `edp_ack_correlation` | 正 | ACK 与消息标识/序号的双向关联 | 8 |
| 8 | `edp_tcp_length_framing` | 正 | TCP 分段、粘连、多帧长度重组 | 10 |
| 9 | `edp_tls_opaque_carrier` | 正 | TLS opaque carrier、可见 TLS 记录而非明文 EDP | 10 |
| 10 | `edp_multi_session_multi_stream` | 正 | 多会话、多流、状态和缓存隔离 | 16 |
| 11 | `edp_reconnect_retry` | 正 | 断线重连、retry 标志和原消息关联 | 14 |
| 12 | `edp_pcap_nic_consistency` | 正 | PCAP/NIC 方向、端口、IP 族和帧边界一致 | 12 |
| 13 | `edp_versioned_frame_contract` | 正 | magic、v1 版本、type、保留位和 payload_format | 8 |
| 14 | `edp_device_sequence_progression` | 正 | 设备状态、单调序号、时间戳和跨帧一致性 | 12 |
| 15 | `edp_neg_frame_length` | 负 | 帧/子长度、截断和 CRC 边界错误 | — |
| 16 | `edp_neg_frame_header` | 负 | version/type/magic/保留位/CRC 错误 | — |
| 17 | `edp_neg_field_types_sequence` | 负 | 字段类型和 sequence/timestamp 规则错误 | — |
| 18 | `edp_neg_ack_correlation` | 负 | ACK、响应、批量和重试关联错误 | — |
| 19 | `edp_neg_carrier_profile` | 负 | carrier、TCP 端口和 IP 族错误 | — |
| 20 | `edp_neg_error_propagation` | 负 | planner/worker/writer 错误传播与假成功 | — |

## 3. 正例逐项断言契约

1. **`edp_tcp_ipv4_registration`**：IPv4/TCP 三次握手后发送 `REGISTER=0x01`；重组帧断言 magic `EDP1`、version 1、`header_length=40`、`frame_length` 与实际字节数一致、动态 device/message ID 存在、JSON payload 为对象、CRC 非零/长度正确；响应方向也有合法 EDP 帧，`packet_count=8`。
2. **`edp_tcp_ipv6_heartbeat`**：独立 IPv6/TCP fixture，断言 `ipv6.nxt=6`、地址族和 TCP 端口；`HEARTBEAT=0x02` 的 status/uptime 类型正确，sequence/timestamp 动态且不倒退，CRC 边界有效，不能从 IPv4 fixture 继承地址，`packet_count=8`。
3. **`edp_json_telemetry_v1`**：`TELEMETRY=0x03`、payload_format=JSON；断言 `measurements` 数组、name/unit 为 string、value 为 number、帧头 payload_length 等于 UTF-8 字节数；业务 value 可为 0，不把 0 误判为缺失，动态序号用存在/范围/递增断言，`packet_count=8`。
4. **`edp_binary_telemetry_v1`**：payload_format=binary，首字节明确为 `binary-v1=0x01`；逐项断言 tag/大端 u16 length/value 边界、measurement_name、f64 value、unit、quality 和样本时间戳；不得把 JSON 文本或 Unicode 字符数当作二进制长度，`packet_count=8`。
5. **`edp_command_response`**：发送 `COMMAND=0x04`，arguments 为 object；响应 `RESPONSE=0x05` 的 `request_message_id` 与请求动态 message_id `same_as_packet`，status/result 类型合法，设备上下文相同且方向相反，`packet_count=10`。
6. **`edp_batch_data`**：发送 `BATCH=0x06`，至少两个 items；断言 batch_count 等于 items 数量、线上顺序不重排、每项字段可回指；批量 ACK 明确状态和成功/失败项目，帧长度覆盖完整 payload，`packet_count=10`。
7. **`edp_ack_correlation`**：发送带 `ack_required` 的遥测/命令，`ACK=0x07` 断言 ack_message_id 与原消息动态 ID 相等、ack_sequence 与原序号相等、status 类型合法；TCP ACK 不替代 EDP ACK，`packet_count=8`。
8. **`edp_tcp_length_framing`**：一个 TCP segment 切开固定帧头/负载，另一个携带粘连的两帧；按重组后的 `frame_length` 恢复每帧，断言不跨帧拼接 device/message/payload/CRC，`packet_count=10`。
9. **`edp_tls_opaque_carrier`**：TLS 握手后出现双向 Application Data；断言 TLS record content type/长度、TCP 9847（或显式 TLS 端口）、方向和终止，不断言加密内容中的 `EDP1`、type、device_id、CRC，`packet_count=10`。
10. **`edp_multi_session_multi_stream`**：至少两个不同 TCP 四元组和同一连接多个事务并行；断言各会话 device/message ID、sequence、重组缓存、ACK 和状态隔离；不同设备/会话动态标识 `distinct`，不依赖全局交织包序，`packet_count=16`。
11. **`edp_reconnect_retry`**：首次连接注册后断开，第二四元组重连；retry 帧置 flags bit 0，原 message_id 和序号关系保持，REGISTER/重连状态合法，重试不计成新业务消息，`packet_count=14`。
12. **`edp_pcap_nic_consistency`**：同一明文 fixture 分别写 PCAP 并 NIC 捕获；断言 TCP carrier、方向、9847 端口、IPv4/IPv6、握手/终止、重组帧 header_length/frame_length/type 和 CRC 边界一致。过滤器推荐 `tcp port 9847`，`packet_count=12`。
13. **`edp_versioned_frame_contract`**：跨 REGISTER/HEARTBEAT/TELEMETRY 至少三种 type，断言 magic、version=1、合法 type、flags 保留位为 0、payload_format 与负载一致、header_length 固定 40，动态长度逐帧计算，`packet_count=8`。
14. **`edp_device_sequence_progression`**：同一设备多帧断言 session 状态从 registered 到 active、sequence 单调不倒退、timestamp presence/nonzero 且不倒退、message_id 存在；重试保留原业务关联，`packet_count=12`。

无 TLS 密钥时，不添加“EDP 明文正确”“CRC 验证成功”或动态值固定断言；无 EDP dissector（解析器）时使用 `tcp`/`tls` 和稳定 raw frames（原始帧）进行边界证据。

## 4. 负例契约

每个负例必须在 planner/validator 失败并传播为 task error；不能产生成功 PCAP、`completed/0 packet` 或只有 TCP 握手的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `edp_neg_frame_length` | frame_length/子长度/截断/CRC 边界不一致 | `length` |
| `edp_neg_frame_header` | magic/version/type/保留位/CRC 错误 | `version`、`type` 或 `crc` |
| `edp_neg_field_types_sequence` | JSON/binary 字段类型错误或 sequence/timestamp 违法 | `field`、`type` 或 `sequence` |
| `edp_neg_ack_correlation` | ACK、RESPONSE、BATCH 或 retry 关联错误 | `ack`、`correlation` 或 `message` |
| `edp_neg_carrier_profile` | 非 TCP、错误端口、TLS/明文或 IP 族混用 | `carrier`、`port`、`tcp` 或 `family` |
| `edp_neg_error_propagation` | planner/worker/writer 错误被吞掉或假成功 | `error`、`propagat` 或 `planner` |

## 5. 三方一致性和静态检查

1. 设计 §8 的 20 个 ID、本文 §2、注册后的 JSON 和审计必须保持同一组 ID、同一顺序：14 正例 + 6 负例；当前 JSON 另有一个不计数的注册占位。
2. 注册后正例均有 packet_count/min_packets、carrier、方向和稳定帧字段；负例 expect 只能有 expect_error/error_contains。当前未注册 JSON 只验证 placeholder（占位）结构。
3. 固定帧头按 40 字节、大端字段、`frame_length=40+device_id_len+message_id_len+payload_length+4` 验证；CRC 覆盖除 CRC 外全部字节，不能用 TCP segment 边界替代。
4. JSON payload 的长度按 UTF-8 字节计算；binary-v1 首字节和 tag/length/value 必须与 payload_format 一致；动态 ID、序号、时间戳、业务数值和 CRC 使用动态断言。
5. COMMAND/RESPONSE、ACK、BATCH 和 retry 关联必须按同一设备上下文验证；TCP ACK 不作为应用 ACK；不同会话不可跨流匹配。
6. IPv4/IPv6、多会话、多流和 keep-alive 以流内状态为准；TLS 未解密只断言 TLS record，不断言 EDP 明文。
7. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/edp.json` 应成功；当前数组只能含 `edp_neg_unregistered`，且 `proto=edp`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `edp` layer 后，先检查 JSON parser、ID 顺序、正负 expect 键集合、帧头 offset/长度、CRC、JSON/binary-v1 tag、ACK correlation、TLS opaque 和 TCP 重组，再运行 1–14 的 PCAP/NIC 正例和 15–20 的错误传播。若环境没有 EDP dissector，使用通用 TCP/TLS 字段与 raw frames；不能将唯一 placeholder 运行结果报告为 EDP suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-21）：建立 14 个正例和 6 个严格负例，覆盖 EDP v1 帧头/长度/CRC、注册/心跳/遥测/命令/响应/批量/ACK、JSON/binary-v1、TLS opaque、IPv4/IPv6、多会话/多流、重连重试、PCAP/NIC 和错误传播；不修改 Go/MCP 实现。

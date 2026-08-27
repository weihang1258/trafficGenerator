# EDP（物联网边缘设备数据协议，IoT Edge Data Protocol）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-21  
> 状态：仅设计与 PCAP（抓包文件）/NIC（网卡）用例契约；`edp` 层尚未注册，不修改 Go（编程语言）或 MCP（模型上下文协议）实现，不宣称当前测试套件可运行。  
> 配套文件：`docs/protocol-designs/72-edp-testcase.md`、`trafficgen/test/protocol_pcap/cases/edp.json`  
> 证据基线：本契约定义的 EDP v1（版本 1）线格式、TCP（传输控制协议）承载和 TLS（传输层安全）不透明承载。

## 1. 范围、证据等级和未注册边界

EDP 是面向 IoT（物联网，Internet of Things）边缘设备的双向设备注册、保活、遥测、命令和确认协议。本设计覆盖 TCP 长度分帧、设备/消息标识、序号、时间戳、CRC（循环冗余校验，Cyclic Redundancy Check）、JSON（对象表示法，JavaScript Object Notation）与二进制负载、IPv4/IPv6、TLS、重连重试、多会话多流以及 PCAP/NIC 证据。

当前仓库没有注册 `edp` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/edp.json` 只保留一个不计入语义覆盖的 `edp_neg_unregistered` 注册前置占位，必须 `expect_error=true` 且 `error_contains="unknown layer"`。注册前拒绝、0 包或空 PCAP 不是 EDP 行为通过。

没有设备证书私钥、动态 fixture（固定样本）或业务数据库时，测试只能断言可观察的帧头、长度、类型、字段存在性、方向、TCP/TLS 载体和 CRC 字节边界；不得把运行期 `device_id`、`message_id`、`sequence`、`timestamp` 编成固定值，也不得在无密钥时声称 TLS 内部 EDP 字段可见。动态值使用 `presence`（存在）、`nonzero`（非零）、`distinct`（互异）、`same_as_packet`（与指定包相同）或范围/长度断言。

## 2. 推荐层链、端口和配置

明文 EDP 推荐层链为 `[ip, tcp, edp]` 或 `[ipv6, tcp, edp]`；TLS 承载为 `[ip, tcp, tls, edp]`，其中 EDP 位于 TLS 加密内容内，抓包器只能观察 TLS。实现注册后，层链仅是集成契约，不表示当前已经注册。

```json
{
  "layers": [{"ip": {}}, {"tcp": {}}, {"edp": {}}],
  "src_ip": "192.0.2.72", "dst_ip": "198.51.100.72",
  "src_port": 49721, "dst_port": 9847,
  "edp": {
    "version": 1, "carrier": "tcp", "payload_format": "json",
    "device_id": {"strategy": "rand", "range": [8, 32]},
    "message_id": {"strategy": "rand", "range": [8, 32]},
    "sequence": {"strategy": "inc", "range": [1, 4294967295]},
    "timestamp": {"strategy": "runtime"}
  }
}
```

| 配置项 | 约束 |
|---|---|
| `carrier`（载体） | 明文 `tcp` 或 `tls`；EDP 不使用 UDP（用户数据报协议）作为本契约载体。TLS 未解密时为 opaque（不透明）载体。 |
| `dst_port` | 明文/TLS profile（档案）默认 TCP `9847`；实际部署可显式配置，但同一 fixture 必须保持端口一致。 |
| `ip_family` | `ipv4` 或 `ipv6`，一条流不能混用；两种地址族须由独立正例覆盖。 |
| `version` | 当前契约固定为 `1`；未知版本进入版本负例。 |
| `type` | `REGISTER=0x01`、`HEARTBEAT=0x02`、`TELEMETRY=0x03`、`COMMAND=0x04`、`RESPONSE=0x05`、`BATCH=0x06`、`ACK=0x07`。 |
| `device_id`/`message_id` | UTF-8（统一码转换格式）或约定二进制标识，长度由帧头给出；运行期生成，不能写死样本值。每个会话的设备标识一致，不同设备/会话按测试要求 distinct。 |
| `sequence` | 无符号 64 位大端（Big Endian）序号；同一设备的有效消息单调递增，重试保留原序号并由 `message_id`/重试标志区分。 |
| `timestamp` | 无符号 64 位大端运行期时间戳；只断言 presence/nonzero 和会话内非倒退，不硬编码墙上时钟。 |
| `payload_format` | `json` 或 `binary`；格式必须与 `flags`/类型声明一致，契约版本 1 的字段表见 §4。 |
| `batch`/`retry` | 批量负载保留项目顺序；重试不得跨设备复用 `message_id`，且响应/ACK（确认）必须关联原消息。 |
| `wire_fault` | 仅负例注入口：`frame_length`、`header`、`field_type`、`ack_correlation`、`carrier`、`propagation`。 |

## 3. TCP 帧格式和长度规则

TCP 是字节流，不保留发送端写边界。接收端必须先读取固定 40 字节帧头，再按 `frame_length` 读取剩余字节；一次 TCP 段可包含半帧、完整帧或多个粘连帧。禁止把 TCP segment（分段）边界当作 EDP 帧边界。

EDP v1 帧按大端编码，布局如下：

```text
固定帧头（40 bytes）
  magic[4]         = ASCII "EDP1"
  version          u8       = 0x01
  type             u8       = REGISTER..ACK
  flags            u16      bit 0=retry，bit 1=ack_required，其他保留为 0
  frame_length     u32      固定帧头 + device_id + message_id + payload + CRC32 总长度
  header_length    u16      = 40
  device_id_len    u16      device_id 字节数
  message_id_len   u16      message_id 字节数
  sequence         u64      运行期序号
  timestamp        u64      运行期时间戳
  payload_format   u8       1=JSON，2=binary
  reserved         u8       = 0
  payload_length   u32      payload 字节数
可变区域
  device_id        [device_id_len]
  message_id       [message_id_len]
  payload          [payload_length]
  crc32            u32      对固定帧头和可变区域（不含 CRC）计算
```

必须满足：`header_length=40`；`frame_length = 40 + device_id_len + message_id_len + payload_length + 4`；`frame_length`、各长度和实际 TCP 重组字节数相等；CRC 使用 v1 约定的 CRC-32/ISO-HDLC（多项式 0x04C11DB7，具体初值/异或值须由实现固定并在 fixture 中一致）。长度字段按字节计算，不按 Unicode 字符数、Base64（基 64 编码）字符数或 JSON 文本字符数计算。帧头、负载或 CRC 截断、超长、整数溢出、未知保留位或父帧长度越界都必须拒绝并向任务错误传播。

`REGISTER` 建立设备能力和契约版本；`HEARTBEAT` 可无业务字段但仍需合法帧头、动态序号/时间戳和 CRC；`TELEMETRY`、`COMMAND`、`RESPONSE`、`BATCH` 和 `ACK` 的 `message_id`/序号关系见 §5。ACK 不得只凭 TCP ACK 代替 EDP 应用确认。

## 4. v1 负载契约：JSON 与二进制

JSON 负载使用 UTF-8 且必须是对象；字段类型是协议契约的一部分，未知字段按版本策略保留但不得改变已知字段类型。推荐字段如下：

| 类型 | 必填字段与类型 | 约束 |
|---|---|---|
| `REGISTER` | `device_id` string、`capabilities` array、`contract_version` integer | 负载中的 `device_id` 必须与帧头对应；版本为 1。 |
| `HEARTBEAT` | `status` string、`uptime_ms` integer | 不得把运行期时间戳替换为固定文本；允许附加能力摘要。 |
| `TELEMETRY` | `measurements` array、每项 `name` string、`value` number、`unit` string | 每项顺序保留；业务数值可为 0，但帧序号/时间戳按动态规则断言。 |
| `COMMAND` | `command` string、`arguments` object、`request_message_id` string | `request_message_id` 与被执行消息关联。 |
| `RESPONSE` | `request_message_id` string、`status` string、`result` object/null | 必须回指对应 `COMMAND` 的动态标识。 |
| `BATCH` | `items` array、`batch_count` integer | `batch_count` 等于 items 数量，不能静默去重或重排。 |
| `ACK` | `ack_message_id` string、`ack_sequence` integer、`status` string | 两个 ACK 关联字段都必须匹配原始消息；重试仍回指同一原消息。 |

二进制负载采用本契约 v1 的显式 schema（模式）版本：首字节 `0x01` 表示 `binary-v1`，随后为无符号字段表和长度前缀；每个项目使用 `tag u8 + length u16 + value[length]`，整数均大端。实现必须声明 `payload_format=2`，不得把 JSON 文本当作二进制 v1。二进制字段 tag 至少定义 `0x01=measurement_name`、`0x02=measurement_value_f64`、`0x03=unit`、`0x04=quality_u8`、`0x05=sample_timestamp_u64`；重复 tag 的顺序按线上顺序解释，未知 tag 按版本策略跳过但仍计入长度。测试只对动态样本字段做存在性、长度、类型和关联断言，不固定具体设备值。

## 5. 设备状态、命令、ACK、批量和错误传播

单个设备会话状态为 `disconnected → connected → registered → active → reconnecting`；只有 `REGISTER` 成功后才能发送 `HEARTBEAT`、遥测或命令。`REGISTER`/心跳应支持正常关闭和网络中断后的重连。重连可以建立新 TCP 流，但必须保持设备身份策略，重试帧置 `retry` 标志、保留原 `message_id` 与序号语义，并使用新的 TCP 四元组；不得把重试当成新的业务消息。

`COMMAND` 请求与 `RESPONSE`、`ACK` 的关联必须在同一设备上下文中按动态 `message_id` 和 `sequence` 验证；错误设备、错误序号、错误消息标识、重复 ACK、提前 ACK、ACK 状态与响应不一致都失败。`BATCH` 的每个 item 具备稳定线上顺序和可回指标识，批量 ACK 必须说明成功/失败项目，不得只回复批量总数。

planner/validator/worker（工作进程）/writer（写出器）任一层拒绝后，任务必须进入 error（错误）状态并保留原始原因；禁止将规划失败吞掉后报告 `completed/0 packet`，也禁止输出只有 TCP 握手而没有 EDP 负载的假成功。正常正例必须有双向 TCP 数据和可重组 EDP 帧；TLS 正例只能在明文未解密范围内断言 TLS 载体。

## 6. TLS、IPv4/IPv6、多会话、多流与 PCAP/NIC

明文 profile 使用 TCP 9847；TLS profile 使用同一 EDP 语义的 TLS 记录承载，若部署约定 TLS 专用端口则必须在配置和测试中显式一致。无会话密钥时，PCAP/NIC 只断言 TCP 三次握手、TLS ClientHello/ServerHello（客户端/服务器问候）、TLS Application Data（应用数据）方向、长度和端口；不得断言加密后的 EDP magic、类型、动态字段或 CRC。NIC 捕获可能受 checksum offload（校验和卸载）影响，不能把未回填校验和误报为 EDP 错误。

IPv4 fixture（固定样本）必须断言 `ip.proto=6`；IPv6 fixture 必须断言 `ipv6.nxt=6`、地址族和独立地址，不能从 IPv4 样本复制字段。至少两个不同四元组的多会话和同一连接上的多流/keep-alive（保持连接）事务必须隔离设备状态、重组缓存、序号、消息关联和重试计数；全局交织包序不作为协议语义依据。

PCAP 输出和 NIC 实时捕获应对同一配置分别验证：方向、TCP 端口、IP 族、握手/终止、重组帧长度和稳定帧头字段一致；TLS 情况只比较可见 TLS 记录元数据。推荐过滤器为 `tcp port 9847`，使用专用 TLS 端口时同时记录实际端口。包数约定只用于实现后的 fixture，不把当前未注册占位的拒绝结果当作协议通过。

## 7. 错误处理和负例契约

6 个负例必须在 planner/validator 失败并传播为 task error；`expect` 执行期只能包含 `expect_error` 与 `error_contains`。错误文本应包含目标关键词，且保留原始层级原因。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `edp_neg_frame_length` | `frame_length`、子长度、TCP 截断或 CRC 前后边界不一致 | `length` |
| `edp_neg_frame_header` | 未知 version/type、magic/保留位或 CRC 算法/值错误 | `version`、`type` 或 `crc` |
| `edp_neg_field_types_sequence` | JSON/二进制字段类型错误、序号倒退/重复或时间戳非法 | `field`、`type` 或 `sequence` |
| `edp_neg_ack_correlation` | ACK/响应回指错误设备、message_id、sequence、批量项目或重试原消息 | `ack`、`correlation` 或 `message` |
| `edp_neg_carrier_profile` | 非 TCP、错误端口、TLS/明文混用或 IPv4/IPv6 族不匹配 | `carrier`、`port`、`tcp` 或 `family` |
| `edp_neg_error_propagation` | planner/worker/writer 注入错误后被吞掉、假成功或错误文本丢失 | `error`、`propagat` 或 `planner` |

## 8. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例和 6 个负例；顺序必须与 `72-edp-testcase.md` §2 及注册后的 `edp.json` 完全一致。当前 JSON 只有不计数的注册前置占位。

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

三方契约必须保持本文 §8、`72-edp-testcase.md` §2、注册后的 `edp.json` 同一组 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `edp_neg_unregistered`，且唯一预期为 `unknown layer`。

## 9. 实现完成定义

注册 `edp` layer 后，必须逐字段校验 v1 帧头和大端长度、CRC、JSON/binary-v1、设备状态、命令/响应/ACK、批量顺序、TCP 重组、TLS opaque、IPv4/IPv6、多会话、多流和重连重试；planner→worker→writer→PCAP/NIC 端到端传播成功与失败。测试需包含 `-race`（竞态检测）和集成路径，动态标识/序号/时间戳只使用运行期断言。无 TLS 密钥时不得声称 EDP 明文可见。

## 10. 修订记录

- v1.0.0（2026-08-21）：建立 14 个正例和 6 个负例，覆盖 EDP v1 TCP 帧头/长度/CRC、注册/心跳/遥测/命令/响应/批量/ACK、JSON/binary-v1、TLS opaque、IPv4/IPv6、多会话/多流、重连重试、PCAP/NIC 和错误传播；不修改 Go/MCP 实现。

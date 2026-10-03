# RTMP 设计契约（as-built，静态收官）

## 1. 范围与目标形状

本协议实现 Adobe RTMP 1.0 明文 TCP 流量，使用 raw 自驱终结层 `rtmp`，默认目标端口 1935。唯一配置真相是层链；canonical 形状如下：

```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"rtmp":{}}]}
```

推荐层链为 `[ip,rtmp]`（引擎可补 `ip`）；不放 `tcp` 层。RTMP 层自建 TCP SYN/SYN-ACK/ACK、RTMP C0/C1/S0/S1/S2/C2、命令与数据面、FIN/FIN-ACK/ACK。IPv4 RTMP 载荷固定起点为 offset 54，IPv6 为 74。

实现只承诺一个 profile：`rtmp_tcp_v1`。不声称支持 RTMPS/TLS、RTMPT/HTTP 隧道、RTMFP/UDP、服务器状态机、Ping/Pong 保活、重连、AMF3、未列出的 AMF0 类型或未列出的命令。

## 2. 线面与流程

固定流程为：TCP 三帧握手 → C0/C1（1537B，MSS 1460 下 2 段）→ S0/S1/S2（3073B，3 段）→ C2（1536B，2 段）→ connect → 服务端五连（Window Ack、Set Peer Bandwidth、Stream Begin、Set Chunk Size、`_result`）→客户端 Window Ack→createStream→Set Buffer Length→`_result`→play 或 publish→可选数据 chunk→三帧 TCP 挥手。

无数据时 20 帧；每个 `rtmp.data` 元素增加一帧：`packet_count = 20 + len(data)`。数据方向缺省为 down；消息类型缺省按方向选择 video(9)/audio(8)；chunk stream id 缺省按类型选择 6/4；缺省 payload 为 100 个零字节。

chunk 基本头恒 fmt=0、csid 低 6 位；消息头为 11 字节，timestamp/length 大端，message stream id 小端。AMF0 仅编码 Number、String、Object、Null（Boolean 常量未产出）。命令仅 connect、createStream、play、publish。

## 3. 依赖、错误和边界

`rtmp` 依赖 `ip`，是 raw 自驱层；生成器顺序流式产出，不聚合全量数据。validator 必须拒绝并传播 task error：非法地址、缺失 RTMP 配置、app 超过 255 字节、非法 command、MSS 小于 536、非法 data message type。链路径现有三条机器负例分别钉 app、command、message type。

当前明确未解决且不得伪装为覆盖：stream_name/tc_url/AMF0 字符串长度守卫、chunk message length 溢出、csid>63、非法 base64 的静默丢弃、真实服务器行为、RST/NIC/IPv6/多流等补充场景。`payload_b64` 与 `payload` 同时存在时 b64 优先；原始 `payload` 是原文字节而非 hex。

## 4. D/T/C 关闭审计

| 维度 | 结论 | 证据 |
|---|---|---|
| D1 范围/依赖 | 已闭合：明文 RTMP、raw `[ip,rtmp]`、默认 1935 | `trafficgen/internal/protocol/rtmp/` 与 registry |
| D2 线格式 | 已闭合：握手分段、fmt0 chunk、AMF0、控制/命令/数据序列 | `rtmp.go` 及现有 pcap 复核 |
| D3 错误契约 | 已闭合：三条 executable 负例各单一故障、严格 `expect_error`+`error_contains` | `cases/rtmp.json` |
| T1 原子用例 | 已闭合：16 个唯一 ID，13 正 + 3 负，顺序固定 | canonical testcase §2 / cases JSON |
| T2 覆盖边界 | 已登记：IPv6、多流、RST、NIC、长度守卫、保活和扩展命令不冒充已覆盖 | testcase §5 |
| C1 形状 | 已闭合：16/16 `spec_json` 顶层仅 `layers`，层形 `[ip,rtmp]` | cases JSON 机读审计 |
| C2 对账 | 已闭合：design/testcase/cases ID 集合与顺序一致 | 本文 §5 |
| C3 范围纪律 | 已闭合：本轮只改 canonical design/testcase 与 cases；不改 Go/schema/index/runtime | 工作树审计 |

## 5. canonical ID 清单

`rtmp_play_session_full`, `rtmp_handshake_segments`, `rtmp_chunk_header_amf0_connect`, `rtmp_protocol_control_messages`, `rtmp_publish_mode`, `rtmp_stream_name_custom`, `rtmp_app_tc_url_custom`, `rtmp_data_audio`, `rtmp_data_video`, `rtmp_data_bidirectional`, `rtmp_data_payload_b64`, `rtmp_composite_publish_multi_data`, `rtmp_neg_app_too_long`, `rtmp_neg_command_invalid`, `rtmp_neg_msg_type_invalid`, `rtmp_data_payload_raw`。

每个正例的 `expect.packet_count` 必须等于 `20 + len(rtmp.data)`；负例必须在 validator 阶段失败，不得产出成功 PCAP、`completed/0 packet` 或 TCP 外壳；每条负例只注入一个故障，`expect` 严格只能含 `expect_error` 与 `error_contains`。

## 6. 三路方案、依赖与验收

| 路径 | 规范要求 | 商业行为 | 开源实现现状 |
|---|---|---|---|
| 明文 RTMP/TCP | RTMP 1.0 握手、chunk、AMF0 命令 | 播放或推流会话可被 DPI/回放工具识别 | 已实现，raw `rtmp` 终结层自建 TCP |
| RTMPS/TLS | TLS 封装后承载 RTMP | 加密传输 | 未实现，不纳入本 profile |
| RTMPT/RTMFP | HTTP 隧道或 UDP 变体 | 代理穿透/低时延 | 未实现，不纳入本 profile |

候选方案取舍：保留 raw 自驱 `[ip,rtmp]`（实现现状与握手/挥手字节一致）；不叠加 `tcp` 层（会重复生成 L4）；不为未实现扩展增加配置键。依赖链为 `ip → rtmp`，translate 分支位于 `chain_planner_translate.go:2911-2918`，字段注册位于 `registry.go:1918-1928`。

错误处理在 trust boundary 由 validator 拒绝：`App exceeds`、`invalid Command`、`MsgType ... invalid` 三条负例分别覆盖单一错误；解析器对非法 `payload_b64` 当前静默回退为空载荷，属于已登记缺口而非成功语义。生成器按流 yield，故性能约束是 O(单帧) 内存；PCAP 与 NIC 必须复用同一 cases 和断言，不能以单一路径代替另一条。

## 7. 八要素与动态字段

八要素闭合为：目标（明文 RTMP 1.0）、参与方（client/server）、承载（IPv4/TCP）、会话（单 TCP 连接）、消息（握手/chunk/AMF0）、时序（握手→connect→控制→命令→数据→挥手）、状态（仅线序，不执法真实服务器状态机）、失败（validator 锚词）。动态字段为握手随机字节、TCP 初始序号、默认源端口注入值和可选 data payload；它们只能断言长度、类型、方向、跨包关系，不能断言随机字面值。序号由 planner 的 `clientSeq/serverSeq` 递增，数据按配置顺序发出，分段由 `segmentByMSS`（`rtmp.go:719-736`）执行。

## 8. Gate-1

- 顶层旧键清单：正例不得有 `src_ip`、`dst_ip`、端口、`count` 或顶层 `rtmp`；地址仅 `layers[0].ip`，业务仅 `layers[1].rtmp`，数量不写入 spec。
- 会话/事务/关联/时间线：单连接固定握手与控制序列；每个 data 元素对应一条后续 chunk；多流、重连和真实状态机不宣称覆盖。
- 动态字段清单：C0/C1、S0/S1/S2、C2 随机字节；TCP seq/ack；默认 payload；可选 base64 解码字节。上述字段均以结构/长度断言为准。
- 能力结论：有 registry Fields 且有 translate `case "rtmp"`，因此无 `G-RTMP-1` 能力阻断缺口；剩余缺口是功能边界（IPv6、多流、RST/NIC、保活、扩展命令、长度守卫等）。

# RTMP 测试用例契约（canonical）

## 1. 机器权威与形状

机器权威：`trafficgen/test/protocol_pcap/cases/rtmp.json`。共 16 个唯一 ID，13 个正例、3 个负例，顺序与本文一致。所有 `spec_json` 顶层只能有 `layers`，16/16 层形为 `[ip,rtmp]`；业务字段只能住 `layers[1].rtmp`，地址只能住 `layers[0].ip`。本协议是 raw 自驱层，不加 `tcp` 层。

正例每条 `expect.packet_count` 必须等于 `20 + len(rtmp.data)`；负例 `expect` 严格只含 `expect_error`、`error_contains`，必须在 validator 阶段失败且不生成成功 PCAP、零包假成功或 TCP 外壳。

## 2. ID 与断言索引

| # | ID | 类型 | 最小契约 |
|---:|---|---|---|
| 1 | `rtmp_play_session_full` | 正 | 20 包；默认 play；TCP flags、1935 端口、握手分段与 connect chunk |
| 2 | `rtmp_handshake_segments` | 正 | 20 包；`tcp.len` 1460/77、1460/1460/153、1460/76 |
| 3 | `rtmp_chunk_header_amf0_connect` | 正 | 20 包；offset 54 的 fmt0/csid3/length/type/streamID 与 AMF0 connect/Number(1.0) 字节 |
| 4 | `rtmp_protocol_control_messages` | 正 | 20 包；Window Ack、createStream、play 控制 chunk 字节 |
| 5 | `rtmp_publish_mode` | 正 | 20 包；publish 分支，禁止只以握手成功冒充 publish 覆盖 |
| 6 | `rtmp_stream_name_custom` | 正 | 20 包；play 参数包含 `movie1` |
| 7 | `rtmp_app_tc_url_custom` | 正 | 20 包；connect 对象包含显式 app/tc_url |
| 8 | `rtmp_data_audio` | 正 | 21 包；up、type 8、csid 4、100B 零 payload |
| 9 | `rtmp_data_video` | 正 | 21 包；down、type 9、csid 6 |
| 10 | `rtmp_data_bidirectional` | 正 | 22 包；up audio 后 down video，方向顺序可观察 |
| 11 | `rtmp_data_payload_b64` | 正 | 21 包；b64 `cnRtcC1kYXRh` 解码为 `rtmp-data` |
| 12 | `rtmp_composite_publish_multi_data` | 正 | 22 包；publish + app/stream 自定义 + audio/video 两 chunk |
| 13 | `rtmp_neg_app_too_long` | 负 | app 256 字节；锚词 `App exceeds` |
| 14 | `rtmp_neg_command_invalid` | 负 | command `pause`；锚词 `invalid Command` |
| 15 | `rtmp_neg_msg_type_invalid` | 负 | data[0] type 5；锚词 `MsgType` |
| 16 | `rtmp_data_payload_raw` | 正 | 21 包；`payload` `raw-frame` 按原文字节透传，不按 hex 解码 |

## 3. 三项行为审计

| 要求 | 结论 |
|---|---|
| 同连接多轮操作 | 已覆盖：握手、connect、控制五连、createStream、play/publish、数据面；#10/#12 含两条数据 chunk |
| 非正常结束 | 正例统一三帧 FIN 挥手；RST 属框架能力，未在本协议 cases 中伪造覆盖，登记缺口 |
| 长保活 | RTMP 层未实现 Ping/Pong 或周期保活，明确不适用并登记缺口；不以一次性控制消息冒充保活 |

## 4. 三源、断言与缺口

设计来源为 Adobe RTMP 1.0、仓库 `internal/protocol/rtmp` 落码和已有 pcap/tshark 复核。固定偏移为 IPv4 54、IPv6 74；动态握手随机字节不得硬编码。若收编 tshark 协议字段，必须使用 `rtmpt.*`，不得误用同名 AppleTalk `rtmp.*`。

已覆盖：RTMP 握手与 MSS 分段、fmt0 chunk、AMF0 connect、协议控制、play/publish、app/tc_url/stream_name、音视频与双向数据、b64 与原文字节载荷，以及三条严格负例。明确未覆盖：IPv6、多流、RST/NIC、非默认端口、缺省 data 字段逐项、超长字段、chunk 分块、fmt1/2/3、AMF3、扩展命令、真实服务器状态机和 Ping/Pong。

## 5. D/T/C 对账

| 维度 | design | testcase | cases |
|---|---|---|---|
| ID 集合/顺序 | §5，16 ID | §2，16 ID | 16 条，顺序一致 |
| 配置形状 | raw `[ip,rtmp]`，顶层仅 layers | §1 明确纯层链 | 16/16 仅 `layers` |
| 包数 | 20+N | 每个正例逐 ID 标出 | 正例断言按 N；负例无成功包 |
| 负例 | 三类 validator 拒绝 | §1/§2/§4 严格契约 | 三条单故障、两键 expect |
| 范围 | 不含代码/schema/index/runtime | 只描述 executable cases | 唯一机器来源 |

## 6. 关闭规则

文档只宣称 cases JSON 已存在且形状、ID、负例契约一致；未执行的 IPv6、多流、RST、NIC、性能和长度守卫不计入完成。任何新增覆盖必须先更新 design 的缺口与 testcase 的 ID/断言，再更新 cases JSON；不得把 notes 当作断言。

## 7. 原子测试点与失败路径审计

测试点先行且按不可再分行为拆解：TCP 三次握手、C0/C1 分段、S0/S1/S2 分段、C2 分段、connect AMF0、服务端控制五连、createStream、setBufferLen、play/publish、每个 data chunk 的方向/类型/csid/payload、三帧挥手；每项均由正例或 frame/field 断言承接。失败路径仅三条，每条只改变一个输入：`app` 超长、`command` 非法、`msg_type` 非法；三条 `expect` 均严格双键，锚词分别来自 `rtmp.go:143`、`:149`、`:163`。`payload_b64` 非法静默为空载荷、未知扩展命令和超长/多流等未形成负例，列为缺口而非假覆盖。

§3.15 固定动作：同连接多轮操作由 #1/#12 覆盖；非正常结束仅核验实现的三帧 FIN，RST 未实现不伪造；长保活明确不适用，RTMP 层未实现 Ping/Pong。三源回指为 RTMP 1.0/Adobe 线格式、`internal/protocol/rtmp/rtmp.go` 与现网 cases/pcap 断言；设计回指 design §2、§3、§7。

# #145 gRPC 测试用例契约

> 版本：v1.0.0（as-built 文档轨）
> 日期：2026-09-29
> 机器契约：`trafficgen/test/protocol_pcap/cases/grpc.json`
> 配套设计：`145-grpc-design.md`

## 1. 形状与执行原则

当前机器契约只有 **1 个正例、0 个负例**。JSON 的唯一 ID、顺序、`min_packets`、字段断言、frame offset 与 notes 是事实权威；设计中的未落入 JSON 行为不得计为已覆盖。正例是集成冒烟，不替代按字段/边界/错误分解的原子用例。pcap 与 NIC 输出应复用这份契约；本车道未执行套件，过期结果不作今日证据。

**严格层链基线**：当前 1/1 正例 `spec_json` 顶层键严格为 `{layers}`；`layers` 顺序为 `ip → tcp → grpc`，地址、端口、业务字段均住在对应层内。当前没有负例；因此不能把 presence 形状、游离顶层键或错误传播称为已覆盖。后续负例必须使用严格双键形状 `{expect_error,error_contains}`，不得混入 `layers`、成功包断言或 `notes`。

## 2. JSON 逐 ID 索引（权威）

| # | ID | 类型 | 场景/依据链 | JSON 包数门槛 | 断言摘要 |
|---:|---|---|---|---:|---|
| 1 | `grpc-basic-call` | 正 | h2c 单 unary：TCP 握手、HTTP/2 preface/SETTINGS、HEADERS/DATA/响应 HEADERS/GOAWAY、TCP 终止；RFC 7540/9113 §3.4/§4/§6，gRPC protocol §4 | 13 | handshake、negotiated、terminates、payload；TCP SYN/端口/ACK；HTTP/2 type/flags；`:method POST`、`:path /svc/m`、`:scheme http`、`:authority 20.0.0.1:80`；gRPC compressed=0、message_length=0；响应 200；GOAWAY；4 个原始 frame hex |

**三方对账警告（G-GRPC-1）**：JSON `min_packets=13`，notes 描述“15 帧 = 3 握手 + 8 数据 + 4 终止”，且实现 legacy `Plan` 明确产生 3+应用事件+4；设计文档不替换该机器事实。主线程应以真实 pcap/链上事件计数重钉 `packet_count`、帧编号与 offset 后再关闭缺口。

### 2.1 `grpc-basic-call` 原始断言逐条转录

- `has_handshake=true`、`negotiated=true`、`terminates=true`、`has_payload=true`、`min_packets=13`。
- packet 1: `tcp.flags=0x002`、`tcp.dstport=80`。
- packet 2: `tcp.flags=0x012`；packet 3: `tcp.flags=0x010`。
- packet 4: `http2.type=4`。
- packet 5: `http2.type=4,4`。
- packet 6: `http2.type=4`、`http2.flags=0x01`。
- packet 7: `http2.type=1`、method `POST`、path `/svc/m`、scheme `http`、authority `20.0.0.1:80`。
- packet 8: `http2.type=0`、`grpc.compressed_flag=0`、`grpc.message_length=0`。
- packet 9: `http2.type=1`、status `200`。
- packet 10: `http2.type=1`。
- packet 11: `http2.type=7`。
- frame packet 4 offset 54: `50 52 49 20 2a 20 48 54 54 50 2f 32 2e 30 0d 0a 0d 0a 53 4d 0d 0a 0d 0a`。
- frame packet 8 offset 54: `00 00 05 00 01 00 00 00 01 00 00 00 00`。
- frame packet 9 offset 54: `00 00 01 01 04 00 00 00 01 88`。
- frame packet 10 offset 54: `00 00 1e 01 05 00 00 00 01 40 0b 67 72 70 63 2d 73 74 61 74 75 73 01 30 40 0c 67 72 70 63 2d 6d 65 73 73 61 67 65 00`。
- frame packet 11 offset 54: `00 00 08 07 00 00 00 00 00 00 00 00 01 00 00 00 00`。

### 2.2 notes 中的实现事实

h2c 使用客户端 24-byte magic + SETTINGS；packet 5 合并 server SETTINGS 与 ACK，packet 6 是 client ACK；packet 7 headers 包含 content-type/te/user-agent/grpc-encoding/grpc-accept-encoding；packet 8 DATA 的 9-byte HTTP/2 header 后为 5-byte gRPC prefix 与空 body；packet 9 为 HPACK `:status=200`；packet 10 为 trailers `grpc-status: 0` 与空 `grpc-message`；packet 11 为 GOAWAY。tshark 在部分 headers 后可能追加 Decompressed Header 展示块，验证器需只取 offset 54 的原始 TCP payload。

## 3. 规范行为面到用例缺口反查

| 行为面 | 当前 JSON | 结论/未来原子例 |
|---|---|---|
| preface magic、SETTINGS、ACK | #1 | 已覆盖集成形；应拆 SETTINGS id/value 与 ACK |
| unary 请求/响应/trailers | #1 | 已覆盖空 message；应补非空 protobuf |
| server/client/bidi stream | 无 | G-GRPC-2：每种 call type、消息数/END_STREAM |
| 多 stream Calls、奇数 stream id、关联 | 无 | G-GRPC-2/G-GRPC-4 |
| HPACK authority/path/metadata、authorization never-indexed | 部分 #1 | metadata/敏感头缺口 |
| identity/gzip、base64/raw/FileSource | identity 空体部分 | gzip、base64/raw/FileSource 缺口；TLS/HTTPS 传输不在当前 h2c 契约内 |
| grpc status 0..16 与 URL 编码 message | status 0 部分 | 边界 0/16、负/17、消息编码 |
| timeout 单位 n/u/m/S/M/H | 无 | 合法与非法单位/数字负例 |
| PING 请求/ACK | 无 | Pings count 0/1/多、opaque |
| RST_STREAM CANCEL | 无 | CancelAfter 正例 |
| WINDOW_UPDATE | 无 | 31-bit 最大、0/高位非法 |
| GOAWAY | #1 | `GoAwayAfter` false 语义缺口 G-GRPC-6 |
| HTTP/2 MaxFrameSize/MSS 分片 | 无 | 16384、相邻值、跨 frame/MSS |
| IPv4/IPv6、默认/非默认端口 | 仅 IPv4、显式 80 | G-GRPC-4 |
| validator 错误传播 | 无 | G-GRPC-5；每锚词一条 expect_error，任务必须 error/0 frame |

## 4. 负例契约要求

当前 JSON 没有负例，故不能声称错误路径已通过。未来负例必须严格只含 `expect_error` 与 `error_contains`，且对应 validator 字面锚词，不混入成功包断言：缺 service/method、非法 call type、非法 encoding/accept encoding/timeout、status 越界、MaxFrameSize/InitialWindow 越界、base64/leading protobuf key 错、FileSource 冲突、Call 字段空、Pings/CancelAfter 负数、WINDOW_UPDATE 高位溢出、MSS<536。错误必须从 validator 传播到 task 终态，不得 completed/0 packets 假成功。

## 5. 存量用例审计

| ID | 去向 | 原因/动作 |
|---|---|---|
| `grpc-basic-call` | 保留但待改写 | 唯一现有冒烟覆盖 h2c 基线；保留 HTTP/2/gRPC 原始断言，按实测 pcap 重钉包数、packet 编号和 notes（G-GRPC-1） |

无作废 ID，无等价覆盖。新增原子用例不得修改该 ID 的语义以掩盖缺口。

## 6. 固定动作与覆盖门建议

### 6.1 §3.15 三项

1. 同连接同流多轮操作：未覆盖（Calls/streaming）；G-GRPC-2。
2. 非正常结束：RST_STREAM 未覆盖；G-GRPC-2。
3. 长保活：PING 未覆盖；G-GRPC-2。

### 6.2 五层覆盖结论

功能层仅有完整 unary 冒烟；性能层无跨 frame/MSS、边界；数据层仅空 protobuf/identity；地址与流层仅 IPv4 单 stream；业务层仅单 unary。其余行为都登记为缺口，不以设计说明替代测试证据。

### 6.3 覆盖反查门建议断言行

1. `len(cases["grpc"]) == 1` 且 ID 顺序为 `grpc-basic-call`。
2. `spec_json` 顶层键集合严格为 `{layers}`，不存在游离 `grpc`/flat 键。
3. 唯一正例 `expect` 含 `has_handshake/negotiated/terminates/has_payload/min_packets/fields/frames`。
4. 所有 `fields`/`frames` 断言 packet 与 offset 为整数，且 frame hex 可解析。
5. packet 4 magic 必须逐字节等于 HTTP/2 connection preface。
6. packet 8 gRPC compressed flag=0、message length=0；packet 9 status=200；packet 11 type=7。
7. 重钉后 `min_packets` 等于实际 pcap 帧数，不能继续以 13 与 notes 的 15 不一致。
8. 未来负例 expect 键只能是 `{expect_error,error_contains}`，error_contains 必须属于 validator 锚词集。
9. pcap 与 NIC 使用同一 ID/断言集合；不得以旧结果文档的 pass 数代替复跑。

## 7. 过期产物登记

`trafficgen/docs/protocol-pcap-test/grpc.md` tracked，末次提交日期为 2026-08-27，早于 2026-09-13 的扁平判死提交 `0417be5`；本车道没有今日复跑与 pcap 留档，故该产物数字不可作为当前通过证据。归属代码阶段 P5：重跑套件后重生成，不在本车道修改。

## 8. 修订记录

- v1.0.1（2026-10-01）：审计修订：补明 1/1 正例严格 `[ip,tcp,grpc]` 层链、业务字段层内化及负例严格双键契约；明确当前仅覆盖明文 h2c，TLS/HTTPS 传输未覆盖；未改 Go 或扩写不可执行用例。自审 2 轮，末轮干净。
- v1.0.0（2026-09-29）：#145 as-built 用例契约；逐字登记现有 grpc.json 唯一 ID、断言、frame hex，审计 JSON/实现包数矛盾，枚举行×字段×边界×错误缺口与覆盖门建议。自审 1 轮，末轮干净；待独立隔离复审。

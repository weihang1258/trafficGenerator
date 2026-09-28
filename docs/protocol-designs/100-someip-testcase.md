# #100 someip（SOME/IP）测试用例契约

> 版本：v1.0.2（P-PIPE 文档轨 P1–P3 + 隔离审查修轮 + 小补登记；修订记录见 §9）
> 日期：2026-09-28
> 配套设计：`docs/protocol-designs/100-someip-design.md` v1.0.2（D-SOMEIP-1）
> 旧基线：`docs/protocol-designs/28-someip-testcase.md` v1.1.0（16 例；**承其审计通过的场景与断言思路**，冲突处按 JSON 事实改正）
> 机器契约：`trafficgen/test/protocol_pcap/cases/someip.json`（16/16 ID 与本版 §2 一致，顺序一致，已机读实测；顶层旧键残留待 P4 迁移，G-SOMEIP-1；**存量 16 例今日 create 400 全红**，详见 §8.2 第 7 条 G-SOMEIP-12）
> 白话一句：**十六条检查：十二条看正常收发（调用、空包、多会话、无返回、错误、黄页发现、订阅、事件、切段、新网段、IPv6 黄页、TCP），四条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **16 个唯一语义 ID：12 正 + 4 负**。派生规则：设计 §3 每个头字段/子结构条款、§5 每个事务/自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-28 机读实测）**：case 级键 = `{expect,id,proto,spec_json,summary}` ×16 + **`decode_as` ×12**（12 正例有、4 负例无；`decode_as` 内容为 `udp.port==30490,someip`，因 tshark 默认按 DNS 解析 30490——探针实证必须显式 `-d` 才挂 someip dissector）；**case 级 `notes` = 0/16**（`notes` 住 `expect` 内，16/16 有）。与范本 92-moxa（case 级 `notes` 23/23、`decode_as` 0）形状不同。`spec_json` 顶层键 = `{layers,src_ip,dst_ip,src_port,dst_port,someip}` ×16（**过渡态违规形**：四元组与顶层 `someip` 子映射同 `layers` 并存；无 `count`、无 `strategy_fc`/`flow_control`）；层形 `[udp,someip]` ×15 + `[tcp,someip]` ×1（`someip_tcp_swap`）；层内 `someip` 恒 `{}` 空壳（registry Fields 空，既不校验也不消费，G-SOMEIP-1）；12 正例 `expect` 含 `packet_count`（`someip_tcp_swap` 例外，用 `has_handshake`+`min_packets`）；4 负例 `expect` 键集合 = `{expect_error,error_contains,notes}`（含 `notes`，非严格两键，G-SOMEIP-7）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`someip.*`/`someipsd.*`/`someip.tp.*` 字段 + offset 42/54 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线**：本机 tshark **3.6.14**，`someip`/`someipsd` dissector 存在（`tshark -G fields | grep -c someip` > 0）。**进制纪律**（tshark 实测）：`someip.serviceid/methodid/messageid/sessionid/protoversion/interfaceversion/messagetype/returncode`、`someipsd.entry.*` 用 `0x` 串；`someip.length`、`someipsd.entry.majorver/minorver/ttl`、`someipsd.option.type/port`、`someip.tp.offset/reassembled.length` 用十进制串。`someip.messagetype.tp` 与 `someip.tp.flags.more_segments` 是布尔，断言用 `"1"`/`"0"`。

**动态字段禁止硬编码**：生成期值用 `same_as_packet`（SessionID/MessageID 配对，S1/S2/S4/S7 已用）断言，不写死生成期派生值。

**包数约定**：UDP 单流包位确定（请求先、响应后，按抓包顺序）；TCP 用例包位依赖握手探测（`min_packets` 下限 + 稳定锚点，见 §3.12）；负例无 `packet_count`。

**保活/重试/RST 口径**：SOME/IP 无 PING 类保活消息（SD 的 TTL 是宣告期不是计时器），不设正例亦不得进负例；RST 为框架 tcp 层能力，本协议层不新增断言；UDP 正例无挥手（无连接），TCP 正例恒 FIN 优雅终止。

## 2. 原子用例索引（16 ID = 12 正 + 4 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count |
|---:|---|---|---|---:|
| 1 | `someip_req_resp` | 正 | §3.1/§5：REQUEST→RESPONSE 往返 + SessionID 配对 | 2 |
| 2 | `someip_req_empty` | 正 | §3.1：空载荷 Length=8 | 2 |
| 3 | `someip_multi_session` | 正 | §5：两轮调用 SessionID=1,2 | 4 |
| 4 | `someip_no_return` | 正 | §3.2：REQUEST_NO_RETURN 单包 | 1 |
| 5 | `someip_error` | 正 | §3.3：ERROR 0x81 + RC=0x01 | 2 |
| 6 | `someip_sd_find_offer` | 正 | §3.4：entry 0x00→0x01 + IPv4 Option | 2 |
| 7 | `someip_sd_subscribe` | 正 | §3.4：entry 0x06→0x07 + eventgroup/counter | 2 |
| 8 | `someip_multi_method_event` | 正 | §3.2：两方法 + 事件 0x8001 | 5 |
| 9 | `someip_tp_segments` | 正 | §3.5：2560B / segment_size 1408 跨 2 段 | 2 |
| 10 | `someip_ipv6` | 正 | §2：IPv6 载体方法调用 | 2 |
| 11 | `someip_sd_ipv6` | 正 | §3.4.2：IPv6 Endpoint Option | 1 |
| 12 | `someip_tcp_swap` | 正 | §2：TCP 载体双向 | —（`min_packets` 6） |
| 13 | `someip_neg_service_id` | 负 | §7：N-1 | — |
| 14 | `someip_neg_session` | 负 | §7：N-2 | — |
| 15 | `someip_neg_type` | 负 | §7：N-3 | — |
| 16 | `someip_neg_tp` | 负 | §7：N-4 | — |

T-编号对照：T-SOMEIP-REQ-01/02 ≡ #1/#2；T-SOMEIP-SESS-01 ≡ #3；T-SOMEIP-NORET-01 ≡ #4；T-SOMEIP-ERR-01 ≡ #5；T-SOMEIP-SD-01/02 ≡ #6/#7；T-SOMEIP-EVT-01 ≡ #8；T-SOMEIP-TP-01 ≡ #9；T-SOMEIP-IPV6-01 ≡ #10；T-SOMEIP-IPV6-SD-01 ≡ #11；T-SOMEIP-TCP-01 ≡ #12；T-SOMEIP-NEG-01…04 ≡ #13…#16。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

### 3.1 `someip_req_resp`（2）

`service_id=4660`、`method_id=1`、`client_id=1`、`message_type="request"`、`auto_response=true`、`payload=[222,173,190,239]`。

- 包1：`someip.messageid=0x12340001`、`someip.length=12`、`someip.sessionid=0x0001`、`someip.messagetype=0x00`、`someip.returncode=0x00`、`udp.dstport=30490`。
- **缺省化**（`layer_gen.go:40-57`）：`client_id`/`protocol_version`/`interface_version`/`session_start`/`session_inc` 为 0 时各缺省为 1；`auto_response` 缺省 true。本用例显式写 `protocol_version:1, interface_version:1`，其余例不写走缺省。
- 包2：`someip.messagetype=0x80`、`someip.returncode=0x00`、`someip.sessionid` **same_as_packet 1**、`someip.messageid` **same_as_packet 1**、`udp.srcport=30490`。
- frames（offset 42）：包1 `12 34 00 01 00 00 00 0c 00 01 00 01 01 01 00 00 de ad be ef`；包2 同首 12B + `80 00` + 同 payload。

### 3.2 `someip_req_empty`（2）

同 3.1 但无 `payload` 键。断言：包1 `someip.length=8`、`someip.messagetype=0x00`；包2 `someip.messagetype=0x80`、`someip.returncode=0x00`、`someip.sessionid` **same_as_packet 1**。Length=8 是"空载荷 = 8(RequestID..RC)"的直接证据。

### 3.3 `someip_multi_session`（4）

`session_start=1`、`session_inc=1`、`auto_response=true`、`events=[{payload:[1,2,3,4]},{payload:[5,6,7,8]}]`。

- 包1 `sessionid=0x0001`/`messagetype=0x00`；包2 `sessionid` **same_as 1**/`messagetype=0x80`；包3 `sessionid=0x0002`/`messagetype=0x00`；包4 `sessionid` **same_as 3**/`messagetype=0x80`。
- frames（offset 42）：包1 `... 00 01 01 01 00 00 01 02 03 04`（SessionID=0001）；包3 `... 00 02 01 01 00 00 05 06 07 08`（SessionID=0002）。
- **多事务证据**：包3 SessionID=0x0002 证明递增；每对请求/响应 same_as 证明配对而非串号。

### 3.4 `someip_no_return`（1）

`message_type="request_no_return"`、`payload=[222,173,190,239]`。断言 `packet_count=1`、包1 `someip.messagetype=0x01`、`someip.returncode=0x00`、`someip.length=12`；frame（offset 42）`12 34 00 01 00 00 00 0c 00 01 00 01 01 01 01 00 de ad be ef`。`packet_count=1` 是 auto_response 被强制关闭的直接证据。

### 3.5 `someip_error`（2）

`message_type="request"` + `events=[{direction:"down", message_type:"error", return_code:1, payload:[0]}]`。

- 包1 `messagetype=0x00`；包2 `messagetype=0x81`、`returncode=0x01`、`sessionid` **same_as 1**、`udp.srcport=30490`（down 方向端口对换证据）。

### 3.6 `someip_sd_find_offer`（2）

`method_id=33024`(0x8100)、`message_type="event"`、`sd={type:"find", service_id:4660, instance_id:1, major_version:1, ttl:16777215, options:[{type:1,ip:"20.0.0.200",port:30490,proto:"udp"}]}`。

- 包1（FindService）：`someip.methodid=0x8100`、`someip.serviceid=0xffff`、`someip.messagetype=0x02`、`someipsd.entry.type=0x00`、`someipsd.entry.serviceid=0x1234`、`someipsd.entry.instanceid=0x0001`、`someipsd.entry.ttl=16777215`（十进制）、`someipsd.entry.minorver=0`。
- 包2（OfferService）：`someip.serviceid=0xffff`、`someipsd.entry.type=0x01`、`someipsd.entry.majorver=1`、`someipsd.entry.ttl=3`、`someipsd.entry.minorver=0`、**`someipsd.option.type=4`**（十进制；配置逻辑枚举 1 → wire 0x04，设计 §3.4.2）、`someipsd.option.ipv4address=20.0.0.200`、`someipsd.option.port=30490`。
- **Option wire 字节**（`builder.go:273-276`，代码实测）：`Length(2B 大端)=00 09` + `Type=04` + `Reserved=00` + `addr=14 00 00 c8` + `Reserved=00` + `proto=11`(UDP) + `port=77 1a`，共 12B。**28-testcase §4.6 的 FrameAssert（Type 在首字节、type=01）过时**——本版按代码重写，G-SOMEIP-1 迁移时按实际 pcap 再钉一次 hex。
- **SD 报文完整布局**（含 4B Options Length，`builder.go:194-199`）：`16B SOME/IP 头 + 8B SD 头 + N×16B Entry + 4B Options Length + Options`（设计 §3.4.1）。

### 3.7 `someip_sd_subscribe`（2）

`method_id=33024`、`message_type="event"`、`sd={type:"subscribe", service_id:4660, instance_id:1, eventgroup_id:1}`。

- 包1（Subscribe 0x06）：`someip.serviceid=0xffff`、`someipsd.entry.type=0x06`、`someipsd.entry.serviceid=0x1234`、`someipsd.entry.instanceid=0x0001`、`someipsd.entry.eventgroupid=0x0001`。
- 包2（Ack 0x07）：`someipsd.entry.type=0x07`、`someipsd.entry.counter=0x00`、`someip.serviceid=0xffff`。
- **结构边界**：Ack 可不引用 Endpoint Option；本原子用例专门覆盖无 Option 的合法结构，不声称覆盖带 Option 的 Ack 变体。若未来实现该变体，新增独立 case 并重算 Entries/Options Length，不能复用本 case 断言。

### 3.8 `someip_multi_method_event`（5）

`service_id=4660`、`client_id=1`、`auto_response=true`、`events=[{method_id:1,message_type:"request",payload:[1]}, {method_id:2,message_type:"request",payload:[2]}, {method_id:32769,message_type:"event",direction:"down",payload:[9,9]}]`。

- 包1 `methodid=0x0001`/`messagetype=0x00`；包2 `methodid` **same_as 1**/`messagetype=0x80`；包3 `methodid=0x0002`/`messagetype=0x00`；包4 `methodid` **same_as 3**/`messagetype=0x80`；包5 `methodid=0x8001`/`messagetype=0x02`。
- **事件证据**：0x8001 的 bit15=1（事件语义）+ Type=0x02（NOTIFICATION）+ 方向 down。

### 3.9 `someip_tp_segments`（2）

`payload` = **2560** 显式字节（0..255 循环，`len(payload)==2560` 机读可核）、`tp={enabled:true, segment_size:1408, payload_length:2560}`。

> **`tp.payload_length` 是死配置**（G-SOMEIP-9）：`grep -rc PayloadLength` 在 planner/builder/layer_gen = **0/0/0**，代码只用 `len(cfg.Payload)` + `SegmentSize`；故 `reassembled.length=2560` 来自 **payload 数组长度**，不是 `payload_length` 声明值。

- 包1（首段）：`someip.messagetype=0x20`、`someip.messagetype.tp=1`、`someip.tp.offset=0`、`someip.tp.flags.more_segments=1`。
- 包2（末段）：`someip.tp.offset=1408`、`someip.tp.flags.more_segments=0`、`someip.tp.reassembled.length=2560`。
- 段切分 = 1408 + 1152（2560 − 1408）。**旧稿 28 写 2500B/1400/2516 与执行事实源不符**，本版按 JSON 钉死（设计 §0 #6）。

### 3.10 `someip_ipv6`（2）

`src_ip=2001:db8::1`、`dst_ip=2001:db8::2`、`message_type="request"`、`auto_response=true`、`payload=[16,32]`。

- 包1：`ipv6.src=2001:db8::1`、`ipv6.dst=2001:db8::2`、**`ipv6.nxt=17`**（UDP；旧稿写 `ip.proto=17`，断言名不符，本版改正）、`someip.messageid=0x12340001`。
- 包2：`someip.messagetype=0x80`、`someip.sessionid` **same_as 1**。
- 本用例**不宣称**覆盖 IPv6 SD Option（那是 #11）。

### 3.11 `someip_sd_ipv6`（1）

`src_ip=2001:db8::10`、`dst_ip=2001:db8::20`、`method_id=33024`、`message_type="event"`、`sd={type:"offer", service_id:4660, instance_id:1, major_version:1, minor_version:0, ttl:3, options:[{type:6,ip:"2001:db8::1",port:30490,proto:"udp"}]}`。

- 断言：`ipv6.src=2001:db8::20`、`ipv6.dst=2001:db8::10`（down 方向：server→client）、`someip.serviceid=0xffff`、`someipsd.entry.type=0x01`、`someipsd.option.type=6`（十进制；IPv6 逻辑枚举 0x06 与 wire 0x06 同值）、`someipsd.option.ipv6address=2001:db8::1`、`someipsd.option.port=30490`。
- Option wire（`builder.go:287-290`）：`Length=00 15` + `Type=06` + `Reserved=00` + 16B 地址 + `Reserved=00` + `proto=11` + `port=77 1a`，共 24B。

### 3.12 `someip_tcp_swap`（`min_packets` 6）

`layers=[{tcp:{}},{someip:{}}]`、`message_type="request"`、`auto_response=true`、`payload=[1,2,3,4]`。

- 断言：`has_handshake=true`、`min_packets=6`、包1 `tcp.flags=0x002`（SYN）、包1 `tcp.dstport=30490`。
- **断言边界（诚实声明）**：框架无"按 SOME/IP 字段筛选 TCP 数据包"的断言器，故不硬编码数据包号（不写"包4/包5"）；SOME/IP 的 REQUEST/RESPONSE 字段存在性需 tshark 或实现级检查补充。该限制是 harness 表达力边界（§9.27），不是协议语义缺失，也不代表包 1 是数据包。

## 4. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 UDP 外壳的假成功。锚词与设计 §7 表一一对应、同序（代码逐字，`planner.go` 实测行号）：

| ID | 故障输入（机读实测） | JSON `error_contains`（实际子串） | 代码文案（`planner.go` 逐字） | 代码行 |
|---|---|---|---|---|
| `someip_neg_service_id` | `service_id=0` | `service_id must be nonzero` | `someip: service_id must be nonzero` | `planner.go:26` |
| `someip_neg_session` | `session_start=1, session_inc=0` | `session_id` | `someip: invalid session_id` | `planner.go:35` |
| `someip_neg_type` | `message_type=5`（int 非枚举） | `message_type` | `someip: invalid message_type 5` | `planner.go:40` |
| `someip_neg_tp` | `tp={enabled:true, segment_size:0}` | `tp` | `someip: tp segment_size must be > 0` | `planner.go:50` |

**锚词口径**：`error_contains` 是**子串**判定；存量 4 例用短子串（N-2/N-3/N-4）与较长子串（N-1）混用，两者均命中代码文案。

**负例原子性**：每例单一故障注入；单次执行不得混注。

**expect 键形状注**：存量 4 负例 `expect` = `{expect_error, error_contains, notes}`（含 `notes`）。设计 §7 口径与 92-moxa 范式的严格两键不同——P4 收窄时删 `notes`（G-SOMEIP-7）。

**planner 拒绝分支全表（10 条，`planner.go:16-77` 实测；入例 4 + A′ 立项 6）**：

| 代码行 | 锚词 | 入例 |
|---|---|---|
| `:26` | `someip: service_id must be nonzero` | ✅ `someip_neg_service_id` |
| `:35` | `someip: invalid session_id` | ✅ `someip_neg_session` |
| `:40` | `someip: invalid message_type %v` | ✅ `someip_neg_type` |
| `:45` | `someip: protocol_version must be 1, got %d` | A′ |
| `:50` | `someip: tp segment_size must be > 0` | ✅ `someip_neg_tp` |
| `:53` | `someip: tp segment_size %d too small`（`< 8`） | A′ |
| `:59` | `someip: invalid sd.type %q (want find\|offer\|subscribe\|subscribe_ack)` | A′ |
| `:66` | `someip: events[%d] invalid message_type %v` | A′ |
| `:71` | `someip: invalid source IP` | A′ |
| `:74` | `someip: invalid destination IP` | A′ |

builder 层另有 3 条（`invalid IPv4 option address` `:267` / `invalid IPv6 option address` `:282` / `unsupported sd option type %d` `:294`），同属 A′ 立项（G-SOMEIP-11）。

**SD 入口配置写法**：`sd.type` 合法值 4 个——`find`/`offer`/`subscribe`/`subscribe_ack`（`sdTypeFromString`，`builder.go:113-123`）。**`subscribe_ack` 可独立配置**（不必依赖 subscribe 自动派生）；存量 `someip_sd_subscribe` 走 subscribe+自动 Ack 路径，独立 `subscribe_ack` 配置今日无例 → A′（G-SOMEIP-10）。

## 5. 覆盖与对账

### 5.1 三源回指行

AUTOSAR SOME/IP PRS（16B 头字段域 / Message Type / Return Code / SD entry-option / TP 分段）+ D-SOMEIP-1（设计 §11）+ tshark 3.6.14 字段实测（`someip.*`/`someipsd.*`/`someip.tp.*`）→ 16 ID（本契约 §2）。第三源"已确认现网行为"当前 = **未确认级**（G-SOMEIP-8，按 §5.5 不写死进实现；AUTOSAR PRS 条款号未逐条核对，以 tshark 实测 + 代码为权威）。

**16 ID 逐项回指（§9.5 要求）**：#1←设计 §3.1/§5；#2←§3.1；#3←§5；#4←§3.2；#5←§3.3；#6←§3.4；#7←§3.4；#8←§3.2；#9←§3.5；#10←§2；#11←§3.4.2；#12←§2；#13–#16←§7。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **AUTOSAR PRS 公开语义 + 旧基线契约 + 仓库落码反推 + tshark 3.6.14 字段实测**，**非纯规范反推**（未逐条核对 PRS 条款号 → G-SOMEIP-8）。
- **对账两行**：**要求逻辑点总数 = 70**（八项 8 行 + 矩阵 30 格 + 变体 22 行 + 商业映射 10 行）；**用例覆盖数 = 40**（八项 3 + 矩阵已覆 10 + 变体已覆 19 + 商业已覆 8）；**不适用 = 18**（八项 2 + 矩阵 16）；**开放立项 = 12**（八项 3 + 矩阵 4 + 变体 3 + 商业 2）。40 + 18 + 12 = 70。✓
  **粒度声明**：行/格粒度每点 1 计；G-SOMEIP-1…G-SOMEIP-12 不折进 70。**反查全绿 ≠ 覆盖全**（§9.52 原文）。逐表重数见设计 §10.1（八项）/§10.2（30 格）/§10.3（22 行）/§10.4（10 行）。
- **门3 抽查候选**：最复杂用例 = **#8 `someip_multi_method_event`**（5 包：两方法往返 + 事件，MethodID 0x0001/0x0002/0x8001 × Type 0x00/0x80/0x02 × 方向 up/down × SessionID 分配，交织维度 = 方法(3)×类型(3)×方向(2)）；**建议门3 抽 #8 + #9**（`someip_tp_segments` 补分段/重组面）。

### 5.3 T-编号与旧 id 对照（设计 §9 全表摘要）

`someip_req_resp` ≡ T-SOMEIP-REQ-01；`someip_req_empty` ≡ T-SOMEIP-REQ-02；`someip_multi_session` ≡ T-SOMEIP-SESS-01；`someip_no_return` ≡ T-SOMEIP-NORET-01；`someip_error` ≡ T-SOMEIP-ERR-01；`someip_sd_find_offer` ≡ T-SOMEIP-SD-01；`someip_sd_subscribe` ≡ T-SOMEIP-SD-02；`someip_multi_method_event` ≡ T-SOMEIP-EVT-01；`someip_tp_segments` ≡ T-SOMEIP-TP-01；`someip_ipv6` ≡ T-SOMEIP-IPV6-01；`someip_sd_ipv6` ≡ T-SOMEIP-IPV6-SD-01；`someip_tcp_swap` ≡ T-SOMEIP-TCP-01；`someip_neg_service_id`/`someip_neg_session`/`someip_neg_type`/`someip_neg_tp` ≡ T-SOMEIP-NEG-01…04。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | UDP 单流多消息序列（#3 两轮调用、#8 两方法一事件）；TCP 同连接多消息 | 已覆 #3/#8 |
| ② | 非正常结束 | UDP 无终止报文（无连接，正例即结束）；错误返回 = 应用层语义（#5 ERROR，非传输异常）；传输异常 = RST（框架 tcp 层能力） | 已覆 #5（应用层错误）；RST **A′ 立项**（框架能力，本层零断言） |
| ③ | 长保活 | 协议层无 keepalive 语义（设计 §4 显式不适用）；长序列 = 多消息展开 | #3/#8 承载（>2 条消息） |

无空项：① 有已覆例；② 有已覆例（#5）+ 1 条 A′ 立项；③ 有 #3/#8。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 层链化 | registry `Fields` 补 someip 业务键 + translate 层内分支 | G-SOMEIP-1，用例 #1–#16 全依赖 |
| TP 变体面 | 0x21/0x22/0xA0/0xA1 四个 TP 变体 | G-SOMEIP-5 |
| 错误码面 | Return Code 0x02-0x0A 代表例 + 应用码 | G-SOMEIP-6 |
| SD Option 面 | IPv4 Multicast（wire 0x14） | G-SOMEIP-4 |
| SD 停止面 | StopOffer（TTL=0）/ StopSubscribeEventgroup | G-SOMEIP-7 |
| 边界精化 | `segment_size` 精确边界（16 倍数） | G-SOMEIP-5 |
| 会话面 | `session_start=0` 分支 | 设计 §8 |
| 版本面 | V4 锚词负例（`protocol_version=2`） | 设计 §7 注 |
| 端口面 | dst_port 缺省补齐 30490 | 设计 §8 |
| 地址族面 | 异族混写拒绝 | 设计 §8 |
| 非正常结束 | `tcp.rst` 补例 | ② 的 A′ |

**B′（框架面）**：`CheckProtoFlat` someip presence 分支（G-SOMEIP-2，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态（G-SOMEIP-3，allowlist 无 `someip` 行）/ 负例 `notes` 键收窄（G-SOMEIP-7）。进设计 §14，「明确不解决 + 迁入计划」。

### 6.3 3.14 豁免边界审计

**无长连接协议（UDP 主路径）→ `sessions[]` 不适用**（UDP 无连接、无独立生命周期；设计 §5 已声明）；**多流并发**由策略级 `flow_control {"flows": N}` 承载（本版 16 例未用，存量单 flow）；**单包多载荷** = **不适用**（SOME/IP 每条消息一个载荷区，无多 question/多 RR 类形态，如实声明）。TCP 载体（#12）有长连接 → 握手/FIN 由 tcp 层补，本层不断言。

## 7. 实现后执行建议

1. **P4 顺序**：G-SOMEIP-1（registry Fields + translate 分支 + schemagen 重跑）→ 存量 16 例改写（删顶层旧键，`someip` 子映射迁层内）→ 先跑后钉 16 例（**特别重钉 #6 的 Option FrameAssert**，旧稿 hex 过时）→ 补 A′ 例 → 全量复跑。
2. **实测顺序**：先 #1/#2（头字段与 Length 基线），再 #6/#7（SD entry/Option 布局），再 #9（TP 分段与重组长度），再 #8（多方法多事件序列），最后 #11（IPv6 SD Option）、#12（TCP 载体）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=someip` 全量不是增量）；门2④ 反查绿后进 P6。**另注意**：`docs/protocol-pcap-test/someip.md` 的 16/16 pass 是过期产物（G-SOMEIP-12），不得作为"套件可跑"依据。
4. 任何 AUTOSAR PRS 条款号的具体引用须有规范原文证据（G-SOMEIP-8 纪律）。

## 8. 存量审计（16 例逐条去向）

### 8.1 存量实测面（2026-09-28）

`cases/someip.json` **16 例**：12 正（11 例带 `packet_count` = 2/2/4/1/2/2/2/5/2/2/1；`someip_tcp_swap` 用 `has_handshake`+`min_packets`）；4 负 `expect` 键集合 `{expect_error,error_contains,notes}`；16/16 顶层含 `src_ip`/`dst_ip`/`src_port`/`dst_port` + 顶层 `someip` 子映射；层内 `someip` 恒 `{}`；`someip_tp_segments` payload 机读 `len==2560`；`someip_sd_find_offer` expect `someipsd.option.type=4`（十进制）。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **存量跑的是过渡态混合形，不是纯层链，且今日 create 400 全红**：`spec_json` 的 `layers=[{udp:{}},{someip:{}}]` 只是**空壳**（`someip` 层 config 恒 `{}`，既不校验也不消费），真实配置住顶层 `someip` 子映射 + 顶层四元组。按"非负例顶层键必须为 0"判据，**非负例 12/12 全部违规**（60 处残留）；五键在即被 `CheckProtoFlat`（`strategy_convert.go:8632`）拒，**今日 16/16 例 MCP 建策略 400、无一条可创建**——旧 id 的 `packet_count` 断言只有**改写落地后**才有效（第 7 条 G-SOMEIP-12）。
2. **旧稿 TP 数字与执行事实源不符**：28-design §6 S8 / 28-testcase §4.9 写 2500B/1400/2516，JSON 实测 2560B/1408/2560。P4 不改包数（2 段不变），本版 §3.9 按 JSON 钉死。
3. **旧稿 S5 Option 断言过时**：28-testcase §4.6 的 FrameAssert 把 Type 写首字节且 type=01；代码 `builder.go:273-276` 是 Length 先写、wire type=0x04。本版 §3.6 改正，P4 先跑后钉重写 hex。
4. **旧稿 V5 锚词臆造**：28-design §9.1 写 `someip: tp segment N out of range`，代码实际 `tp segment_size must be > 0` / `tp segment_size %d too small`。本版 §4 按代码逐字。
5. **负例 `notes` 键**：4 负例 expect 含 `notes`，与严格两键口径不符（G-SOMEIP-7）。
6. **存量未覆盖**：TP 变体 0x21/0x22/0xA0/0xA1、Return Code 其余 9+ 值、IPv4 Multicast Option、StopOffer/StopSubscribe、`segment_size` 边界、`session_start=0`、缺省端口、异族混写**今日零用例**（A′ 补）。
7. **结果文档过期（G-SOMEIP-12）**：`trafficgen/docs/protocol-pcap-test/someip.md` 写 "Cases: 16 — pass 16, fail 0, error 0"，但末次提交 `3c5991a`（2026-08-28）**早于判死提交 `0417be5`（2026-09-13）**；`cases/someip.json` 末改同为 `3c5991a`；`docs/protocol-pcap-test/someip/` **0 个 pcap**；**今日 16/16 例经 MCP 建策略 400 全红**（顶层旧键 60 处残留、非负例 12/12 全违规形）。该 16/16 pass **是过期产物，不代表今日可跑**；归属**代码阶段（P5 重跑套件后重生成该产物）**。

### 8.3 逐条去向表（16 行）

| 存量 id | T-编号 | 去向 | 改写动作（G-SOMEIP-1 落地时） |
|---|---|---|---|
| `someip_req_resp` | T-SOMEIP-REQ-01 | **改写** | 目标形状化（`ip` 层地址 + `udp` 层端口 + `someip` 层业务键）；packet_count 2 不变 |
| `someip_req_empty` | T-SOMEIP-REQ-02 | **改写** | 同上；Length=8 断言不变 |
| `someip_multi_session` | T-SOMEIP-SESS-01 | **改写** | 同上；SessionID 递增/same_as 断言不变 |
| `someip_no_return` | T-SOMEIP-NORET-01 | **改写** | 同上；packet_count 1 不变 |
| `someip_error` | T-SOMEIP-ERR-01 | **改写** | 同上；RC=0x01 断言不变 |
| `someip_sd_find_offer` | T-SOMEIP-SD-01 | **改写** | 同上；**Option FrameAssert 按实际 pcap 重钉**（旧 hex 过时） |
| `someip_sd_subscribe` | T-SOMEIP-SD-02 | **改写** | 同上；entry 0x06→0x07 断言不变 |
| `someip_multi_method_event` | T-SOMEIP-EVT-01 | **改写** | 同上；packet_count 5 不变 |
| `someip_tp_segments` | T-SOMEIP-TP-01 | **改写** | 同上；2560B/1408/2560 内联保留 |
| `someip_ipv6` | T-SOMEIP-IPV6-01 | **改写** | 地址迁 `ip` 层；`ipv6.nxt=17` 断言不变 |
| `someip_sd_ipv6` | T-SOMEIP-IPV6-SD-01 | **改写** | 同上；Option type=6 断言不变 |
| `someip_tcp_swap` | T-SOMEIP-TCP-01 | **改写** | `tcp` 层保留；`has_handshake`+`min_packets` 不变 |
| `someip_neg_service_id` | T-SOMEIP-NEG-01 | **改写** | `someip` 子映射迁层内；锚词不变；删 `notes` |
| `someip_neg_session` | T-SOMEIP-NEG-02 | **改写** | 同上 |
| `someip_neg_type` | T-SOMEIP-NEG-03 | **改写** | 同上 |
| `someip_neg_tp` | T-SOMEIP-NEG-04 | **改写** | 同上 |

无"作废不注原因"：0 作废，0 等价覆盖（全部改写 + A′ 新增）。

## 9. 修订记录

- v1.0.2（2026-09-28，小补登记）：§8.2 新增第 7 条 **G-SOMEIP-12 结果文档过期**——`docs/protocol-pcap-test/someip.md` 的 16/16 pass 为过期产物（末次提交 `3c5991a` 2026-08-28 早于判死提交 `0417be5` 2026-09-13；`docs/protocol-pcap-test/someip/` 0 个 pcap；今日 16/16 例经 MCP 建策略 400 全红）。归属**代码阶段（P5 重跑套件后重生成）**。口径与 pcep 车道 G-PCEP-11 一致。设计侧同步 §0 产物过期登记 + §14 缺口行。
- v1.0.1（2026-09-28，隔离审查 B-1/B-2/B-3 + D 类修轮）：**B-1** §3.6 的 SD Entry 偏移表按代码/探针重写（ServiceID@4-5、InstanceID@6-7、Major@8、TTL@9-11、Minor@12-15；Index1@1/Index2@2 为独立字节，NumOpts 合并于 `entry[3]`）——旧稿偏移整体错位 1 字节；补 SD 报文完整布局（含 4B Options Length）。**B-2** §3.9 TP 头由 8B 改 **4B**（低 28bit=offset 16 对齐、bit0=more），并声明**后续段重复完整 16B 头**（`planner.go:247`）——旧稿头长与后续段结构全错。**B-3** §4 补 planner 拒绝分支**全表 10 条**（入例 4 + A′ 立项 6，原写"7 种"漏 3 条：`sd.type`/`src IP`/`dst IP`），补 `subscribe_ack` 独立配置写法。**D 类**：§1 形状基线补 `decode_as` 12/16 与 `notes` 位置；§3.1 补缺省化；§3.9 标注 `tp.payload_length` 死配置（G-SOMEIP-9）。每条附复算命令与原始输出。自审见审计日志 §E。
- v1.0.0（2026-09-28）：P-PIPE #100 文档轨 P1–P3。**承 28-someip-testcase 审计通过的 16 ID / 锚词 / fixture 思路**；形状基线机读实测（§1）；P3 固定动作（§6）；执行建议（§7）；存量审计（§8，16/16 改写）；冲突处按 JSON/代码事实改正（TP 2560/1408/2560、Option type=4 与 wire 布局、`ipv6.nxt=17`、V5 锚词）。自审见审计日志 §E。

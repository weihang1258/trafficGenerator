# #110 pppoe（PPPoE）测试用例契约

> 版本：v1.0.0（批次二 as-built 文档轨）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/110-pppoe-design.md` v1.0.0
> 旧基线：**无外部旧稿**（`docs/protocol-designs/` 无 pppoe 文档，机读实测）；继承来源 = 内部契约 `docs/TEST_CASES.md:3744` **T-PPPOE-1…24** + `docs/CODE_DESIGN.md:2882` **D-PPPOE-1**
> 机器契约：`trafficgen/test/protocol_pcap/cases/pppoe.json`（**24 例**，ID/顺序/包数/断言与本版逐条一致，已机读实测；顶层键已是纯层链形，零残留）
> 白话一句：**二十四条检查：十八条看正常拨号（发现四步、LCP 协商、两种认证、两种方向、多会话、多协议），六条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **24 个唯一语义 ID：18 正 + 6 负**（负例 N-1…N-6）。派生规则：设计 §3 每个消息/字段条款、§5 每个事务/自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：24/24 例顶层键 = `{expect,id,proto,spec_json,summary}`；`spec_json` 顶层键 = **`{layers}` ×24（唯一键，零游离键、零顶层 `pppoe` 子映射）**——本协议存量**顶层零残留**，无 §1 迁移工作量（设计 §12.1）；层形 **`[ip,pppoe]` ×24**（统一，无例外）；18 正例 `expect` 含 `packet_count` + `fields`（其中 8 例另含 `frames`）+ `notes`；6 负例 `expect` 键集合 = **`{expect_error, error_contains}`（严格两键，无 `notes`，机读实测）**。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`eth.type`/`pppoe.code`/`pppoe.session_id`/`ppp.protocol`/`ip.proto`/`ip.src`/`ip.dst`/`eth.src` 字段 + offset 14/20/26/30/32/50 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。

**TSHARK 基线（实测）**：本机 tshark 3.6.14 有 **pppoe + ppp 双 dissector**——`pppoe.*` 9 字段（`version`/`type`/`code`/`session_id`/`payload_length`/`payload_length.bad`）+ `ppp.*` 16 字段（`protocol`/`code`/`identifier`/`length`/`magic_number`/`data`/`direction`/`address`/`control`/`oui`/`kind`/`fcs_*`/`bad_checksum`）。**今日 24 例只使用 `eth.type`/`pppoe.code`/`pppoe.session_id`/`ppp.protocol`/`ip.proto`/`ip.src`/`ip.dst`/`eth.src` 八个字段 + frames**；`pppoe.payload_length`/`pppoe.version`/`pppoe.type`/`ppp.magic_number`/`ppp.length` 等**可用但零使用** → A′ 立项（G-PPPOE-6 附表）。

**断言基线**：`fields` 断言用**十六进制串**（`"0x8863"`/`"0x09"`/`"0x0001"`/`"0xc021"`/`"0x0021"`）与**十进制串**（`ip.proto` `"17"`/`"6"`）；`frames` 断言用空格分隔的十六进制字节串。

**动态字段禁止硬编码**：生成期随机值（LCP Magic-Number、CHAP Value）**一律不断言字节**——#1 notes 明写 "magic 字节随机不断言"；#6 notes 明写 "挑战值 crypto/rand 随机，回显关系由包 8 value==包 7 value 保证"。

**包数约定（机读复核公式，设计 §5）**：

```
单会话帧数 = (0 if skip_discovery else 4) + 2(LCP 对) + (2 if pap | 3 if chap | 0) + DataFrames(0→1) + (0 if padt==false else 1)
流总帧数   = Σ 各会话帧数
```

**18 正例逐例对公式复核，0 例不符**（§5.2）。负例无 `packet_count`（0 帧）。

**保活/重试/RST 口径**：**本协议无保活、无重试、无 RST**——① RFC2516 §7 的 LCP Echo-Request 保活（RECOMMENDED）**未编排**（G-PPPOE-5）；② RFC2516 §8 的 PADI/PADR 重传与等待加倍（SHOULD）**未实现**（planner 零重发，`grep` 实测空）；③ **无外层 TCP 传输层**，故 **RST 是 TCP 层概念，本协议链上不存在**——"非正常结束"在本协议只有 **PADT 拆线**（RFC2516 §5.5）一种表达，#2 是它的抑制反向面。正例恒以 PADT 优雅结束（除 #2）。

## 2. 原子用例索引（24 ID = 18 正 + 6 负，顺序为权威）

| # | ID | 类型 | 场景 | 依据链 | packet_count（机读复核） |
|---:|---|---|---|---|---:|
| 1 | `pppoe_lifecycle_full` | 正 | 全生命周期（缺省 ID 1 + PADT 缺省真） | RFC2516 §5.1–§5.5 + §6；RFC1661 §5/§6.1/§6.4 | 8 |
| 2 | `pppoe_padt_suppressed` | 正 | `padt=false` 抑制拆线帧 | RFC2516 §5.5（拆断语义反向面） | 7 |
| 3 | `pppoe_skip_discovery` | 正 | 跳过发现 + 显式 ID 9（首帧即 0x8864） | RFC2516 §5.1–§5.4（跳过面）+ §6 | 4 |
| 4 | `pppoe_auth_none_lcp_len` | 正 | 无 Auth-Protocol 选项 → LCP len 14 | RFC1661 §6.2（选项缺席）+ §5 | 8 |
| 5 | `pppoe_auth_pap` | 正 | PAP 认证（LCP c023 + Req/Ack） | RFC1661 §6.2；RFC1334 §2.2.1/§2.2.2 | 10 |
| 6 | `pppoe_auth_chap` | 正 | CHAP 认证（LCP c223 + 三帧） | RFC1661 §6.2；RFC1994 §4.1/§4.2 | 11 |
| 7 | `pppoe_data_direction_down` | 正 | 下行数据面（内嵌 IP + MAC 全换向） | RFC1661 §3.6/§2 | 4 |
| 8 | `pppoe_data_frames_zero_default` | 正 | `data_frames=0` → 缺省 1 帧（语义勘误面） | 设计 §5 自动派生规则 11 | 8 |
| 9 | `pppoe_service_name_any` | 正 | 零长 Service-Name = any-service | RFC2516 Appendix A（0x0101） | 8 |
| 10 | `pppoe_bras_three_tags` | 正 | 现网 BRAS 三标签 + PADR 回显 Cookie | RFC2516 Appendix A（0x0101/0x0102/0x0104）+ §5.3 | 8 |
| 11 | `pppoe_mru_magic_explicit` | 正 | MRU 1480 + Magic 显式钉值 | RFC1661 §6.1/§6.4 | 4 |
| 12 | `pppoe_sessions_derived_ids` | 正 | `sessions[3]` 全空项 → 派生 ID 1/2/3 | 设计 §5（多会话展开）+ D-PPPOE-1 裁定4 | 24 |
| 13 | `pppoe_sessions_explicit_ids` | 正 | `sessions[2]` 显式 ID 100/200 | 设计 §5 + D-PPPOE-1 裁定4 | 16 |
| 14 | `pppoe_composite_multi_session` | 正 | 复合大场景（模板 chap + 2 会话混合形态） | 设计 §5/§10.4（9.50 交织 ≥3 类） | 19 |
| 15 | `pppoe_inner_tcp_explicit` | 正 | `inner_proto=6` 内嵌 TCP | RFC1661 §2（0x0021 内嵌） | 4 |
| 16 | `pppoe_data_payload_bytes` | 正 | `data_payload` 原文字节钉 | 设计 §3.7（载荷） | 4 |
| 17 | `pppoe_data_frames_two` | 正 | `data_frames=2` 多帧 + IPID 递增 | 设计 §3.7（`ip.id` 逐帧 +1） | 5 |
| 18 | `pppoe_inner_udp_explicit` | 正 | `inner_proto=17` 显式 UDP | RFC1661 §2 | 4 |
| 19 | `pppoe_neg_auth_invalid` | 负 | `auth="radius"` 枚举拒 | 设计 §7 N-1 | —（0 帧） |
| 20 | `pppoe_neg_inner_proto_invalid` | 负 | `inner_proto=5` 枚举拒 | 设计 §7 N-2 | —（0 帧） |
| 21 | `pppoe_neg_data_frames_negative` | 负 | `data_frames=-1` registry V9 范围门拒 | 设计 §7 N-3 | —（0 帧） |
| 22 | `pppoe_neg_ipv6_inner` | 负 | 同族 IPv6 内嵌 → `must be IPv4` | RFC1661 §2 + 设计 §7 N-4 | —（0 帧） |
| 23 | `pppoe_neg_sessions_mutex` | 负 | `sessions[]` × 顶层行为键互斥 | D-PPPOE-1 裁定4；设计 §7 N-5 | —（0 帧） |
| 24 | `pppoe_neg_duplicate_session_id` | 负 | 重复显式 `session_id` 判死 | D-PPPOE-1 裁定5；设计 §7 N-6 | —（0 帧） |

**T-编号对照（与 `docs/TEST_CASES.md:3744` T-PPPOE 节一致，逐项相同）**：T-1≡#1 / T-2≡#2 / T-3≡#3 / T-4≡#4 / T-5≡#5 / T-6≡#6 / T-7≡#7 / T-8≡#8 / T-9≡#9 / T-10≡#10 / T-11≡#11 / T-12≡#12 / T-13≡#13 / T-14≡#14 / T-15≡#15 / T-16≡#16 / T-17≡#17 / T-18≡#18 / T-19≡#19 / T-20≡#20 / T-21≡#21 / T-22≡#22 / T-23≡#23 / T-24≡#24。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count` + `fields`；8 例另含 `frames`（#1/#4/#5/#6/#9/#10/#11/#16）。**帧位与偏移已机读对派生字节模型复核（全 OK）**。偏移口径：**以太帧起点 offset 0**，PPPoE 头 offset 14，首个 TLV / PPP Protocol offset 20。

### 3.1 `pppoe_lifecycle_full`（8 帧）

`layers = [{ip:{src:10.0.0.1,dst:20.0.0.1}}, {pppoe:{}}]`（全缺省）。

- `fields`（15 条）：帧 1 `eth.type=0x8863` + `pppoe.code=0x09`（PADI）；帧 2 `pppoe.code=0x07`（PADO）；帧 3 `pppoe.code=0x19`（PADR）；帧 4 `pppoe.code=0x65` + `pppoe.session_id=0x0001`（**PADS 分配缺省 ID 1**）；帧 5 `eth.type=0x8864` + `pppoe.code=0x00` + `pppoe.session_id=0x0001` + `ppp.protocol=0xc021`（LCP Configure-Request）；帧 6 `ppp.protocol=0xc021`（Configure-Ack）；帧 7 `ppp.protocol=0x0021` + `ip.proto=17`（内嵌 IPv4/UDP 数据帧）；帧 8 `eth.type=0x8863` + `pppoe.code=0xa7` + `pppoe.session_id=0x0001`（PADT）。
- `frames`：帧 1 offset 14 `11 09 00 00 00 04`（VER/TYPE `0x11` + CODE `0x09` + SESSION_ID `0x0000` + **LENGTH `0x0004`** = 零长 Service-Name 标签 4 字节）；帧 5 offset 14 `11 00 00 01 00 10`（Session Data：CODE `0x00` + ID `0x0001` + **LENGTH `0x0010`** = PPP Proto 2 + LCP 14）；帧 5 offset 20 `c0 21 01 01 00 0e`（**PPP Proto `0xc021` + LCP Code 1 + ID 1 + Length `0x000e`** = 4+MRU 4+Magic 6）；帧 8 offset 14 `11 a7 00 01 00 00`（PADT：CODE `0xa7` + ID `0x0001` + **LENGTH `0x0000` 零 TLV**）。
- **notes 要点**：PADT 缺省 true（原 7 帧 smoke 增第 8 帧）；Discovery 段 session_id=0，PADS 起回显缺省 1；LCP options=MRU(`01 04 05 d4`)+Magic(`05 06 随机`)→LCP len `0x000e`、payload_length `0x0010`；**magic 字节随机不断言**；数据帧 inner IPv4/UDP，**链路径无端口位→srcport/dstport=0（合成面，B′ 注记）**。

### 3.2 `pppoe_padt_suppressed`（7 帧）

`{pppoe:{padt:false}}`。

- `fields`：帧 1 `pppoe.code=0x09`；帧 4 `pppoe.code=0x65`；帧 7 `ppp.protocol=0x0021`。
- **断言要点**：**末帧 = 数据帧（帧 7）而非 PADT**——`padt` 是 `*bool` 指针三态，`false` 抑制拆线帧。帧序与 #1 前 7 帧一致。

### 3.3 `pppoe_skip_discovery`（4 帧）

`{pppoe:{skip_discovery:true, session_id:9}}`。

- `fields`：帧 1 `eth.type=0x8864` + `pppoe.code=0x00` + `pppoe.session_id=0x0009` + `ppp.protocol=0xc021`（**首帧即 Session Data，Discovery 四步全缺**）；帧 3 `ppp.protocol=0x0021`；帧 4 `pppoe.code=0xa7` + `pppoe.session_id=0x0009`（PADT 回显显式 ID）。
- **断言要点**：PADS 缺席 → Session ID **必须显式**（notes 明写）；全部帧回显 9。

### 3.4 `pppoe_auth_none_lcp_len`（8 帧）

`{pppoe:{auth:"none"}}`。

- `fields`：帧 5 `ppp.protocol=0xc021`。
- `frames`：帧 5 offset 14 `11 00 00 01 00 10`；帧 5 offset 20 `c0 21 01 01 00 0e`。
- **断言要点**：**无 Auth-Protocol 选项时 LCP Configure-Request 总长 14**（4 + MRU 4 + Magic 6，RFC1661 §6.1/§6.4）——与 #5 的 18 构成 `+4` 的直接证据（Auth-Protocol 选项恰 4 字节）。

### 3.5 `pppoe_auth_pap`（10 帧）

`{pppoe:{auth:"pap", username:"alice", password:"s3cret"}}`。

- `fields`：帧 5 `ppp.protocol=0xc021`；帧 7 `ppp.protocol=0xc023`（Authenticate-Request，up）；帧 8 `ppp.protocol=0xc023`（Authenticate-Ack，down）；帧 9 `ppp.protocol=0x0021`（数据帧）；帧 10 `pppoe.code=0xa7`。
- `frames`：帧 5 offset 14 `11 00 00 01 00 14`（**LENGTH `0x0014` = 2 + 18**）；帧 5 offset 20 `c0 21 01 01 00 12`（**LCP len `0x0012` = 4+4+6+4**）；帧 7 offset 20 `c0 23 01 01 00 11`（**PAP Request：Proto `0xc023` + Code 1 + ID 1 + Length `0x0011` = 6+5+6**）。
- **notes 要点**：Auth-Protocol 选项 4B（type 3 + len 4 + `c023`）；Ack：code 2 + msg `"welcome"`。

### 3.6 `pppoe_auth_chap`（11 帧）

`{pppoe:{auth:"chap", username:"bob"}}`。

- `fields`：帧 7/8/9 `ppp.protocol=0xc223`（Challenge down / Response up / Success down）；帧 10 `ppp.protocol=0x0021`。
- `frames`：帧 7 offset 20 `c2 23 01 01 00 18`（**CHAP Challenge：Proto `0xc223` + Code 1 + ID 1 + Length `0x0018` = 4+1+16+3**）。
- **notes 要点**：`Value-Size`=16、Name=`bob`(3) → len 24；**挑战值 crypto/rand 随机，回显关系由包 8 value == 包 7 value 保证**（planner 合成，**不算 MD5**，设计 §3.6 诚实边界）；Success len 4。

### 3.7 `pppoe_data_direction_down`（4 帧）

`{pppoe:{skip_discovery:true, session_id:3, data_direction:"down"}}`。

- `fields`：帧 3 `ip.src=20.0.0.1`、`ip.dst=10.0.0.1`、`eth.src=02:00:00:00:00:02`。
- **断言要点**：**down = 服务端下发面**——内嵌 IPv4 地址**全换向**（src=配置的 dst）+ `eth.src` 取 spec 缺省下行 MAC `02:00:00:00:00:02`；LCP（帧 1/2）与 PADT（帧 4）**方向不变**（仍 client 发起）。

### 3.8 `pppoe_data_frames_zero_default`（8 帧）

`{pppoe:{session_id:2, data_frames:0}}`。

- `fields`：帧 7 `ppp.protocol=0x0021`；帧 8 `pppoe.code=0xa7`。
- **断言要点（语义勘误）**：`data_frames=0` **不是"无数据帧"，而是缺省 1**（`planner.go:435-438` `frames == 0 → 1`）——包数 8 与 #1 同形，**仍有 1 个数据帧**。T-PPPOE P5 已把 TEST_CASES 边界行按实现语义勘误。

### 3.9 `pppoe_service_name_any`（8 帧）

`{pppoe:{}}`（Service-Name 缺省空串）。

- `frames`：帧 1/2/3 offset 20 均 `01 01 00 00`（**TLV Type `0x0101` + TAG_LENGTH `0x0000` 零长**）。
- **断言要点**：零长 Service-Name = **any-service**（RFC2516 Appendix A："When the TAG_LENGTH is zero this TAG is used to indicate that any service is acceptable"）；offset 20 = eth 14 + PPPoE 头 6。

### 3.10 `pppoe_bras_three_tags`（8 帧）

`{pppoe:{service_name:"internet", ac_name:"BRAS-1", cookie:[222,173,190,239]}}`。

- `fields`：帧 4 `pppoe.session_id=0x0001`。
- `frames`：帧 1 offset 20 `01 01 00 08`（Service-Name `"internet"` 8B）；帧 2 offset 20 `01 01 00 08`；帧 3 offset 32 `01 04 00 04 de ad be ef`（**AC-Cookie TLV：Type `0x0104` + LEN 4 + 值**；offset 32 = 20 + Service-Name TLV 12）。
- **断言要点（现网形）**：AC-Name 标识局端设备（`0x0102`）、AC-Cookie 关联发现与会话（`0x0104`，RFC2516 §5.3 要求 PADR 原样回显）；**cookie 用字节数组**（`getByteSlice` 字符串=**原文字节**，hex 串会被当 ASCII，故 hex 语义必须写字节数组）。

### 3.11 `pppoe_mru_magic_explicit`（4 帧）

`{pppoe:{skip_discovery:true, session_id:6, mru:1480, magic_number:16909060}}`（= `0x01020304`）。

- `fields`：帧 1 `ppp.protocol=0xc021`。
- `frames`：帧 1 offset 20 `c0 21 01 01 00 0e`（LCP len 14）；offset 26 `01 04 05 c8`（**MRU 选项：type 1 + len 4 + 值 `0x05c8`=1480**）；offset 30 `05 06 01 02 03 04`（**Magic 选项：type 5 + len 6 + 显式值**）。
- **断言要点**：MRU 1480（RFC1661 §6.1）；**Magic 显式钉值 = §6.4 随机性的测试确定性面**。

### 3.12 `pppoe_sessions_derived_ids`（24 帧）

`{pppoe:{sessions:[{},{},{}]}}`。

- `fields`：帧 4/8 `pppoe.session_id=0x0001`；帧 12/16 `=0x0002`；帧 20/24 `=0x0003`。
- **断言要点**：每会话 8 帧 × 3 = 24；**派生 ID = 会话序号 i（`1+i`）**——`DefaultSessionID + i`（`planner.go:503-505`），**非动态对象 FlowIndex 语义**（9.40 陷阱注记，notes 明写）；三个 PADT（帧 8/16/24）各回显本会话 ID。**多会话整块顺序**：帧 1–8 会话 1、帧 9–16 会话 2、帧 17–24 会话 3，**不交错**。

### 3.13 `pppoe_sessions_explicit_ids`（16 帧）

`{pppoe:{sessions:[{session_id:100},{session_id:200}]}}`。

- `fields`：帧 4/8 `pppoe.session_id=0x0064`（100）；帧 12/16 `=0x00c8`（200）。
- **断言要点**：PADS 回显**显式值**；每会话独立完成发现四步；**重复显式 ID 由 Validate/schema 判死**（#24 负例面）。

### 3.14 `pppoe_composite_multi_session`（19 帧，最复杂例）

`{pppoe:{auth:"chap", sessions:[{session_id:21},{session_id:22, skip_discovery:true, data_direction:"down", data_frames:2}]}}`。

- `fields`：帧 7 `ppp.protocol=0xc223`；帧 11 `pppoe.code=0xa7` + `pppoe.session_id=0x0015`（21）；帧 14 `ppp.protocol=0xc223`；帧 18 `ppp.protocol=0x0021`；帧 19 `pppoe.code=0xa7` + `pppoe.session_id=0x0016`（22）。
- **断言要点（9.50 交织维度 ≥3）**：`auth=chap` 是**模板键**（顶层共享，`sessions` 仅覆盖行为 6 键——D-PPPOE-1 裁定4 键集合）。会话 21（完整发现 + chap）= 4 Discovery + 2 LCP + 3 CHAP + 1 data + 1 PADT = **11 帧**（包 1–11）；会话 22（skip + chap + down 2 data）= 2 + 3 + 2 + 1 = **8 帧**（包 12–19）；合计 19。**交织维度** = 多会话(2) × 认证(chap 共享) × skip_discovery × 方向(down) × 多帧(2) = **5 类 ≥ 3** ✓。

### 3.15 `pppoe_inner_tcp_explicit`（4 帧）

`{pppoe:{skip_discovery:true, session_id:4, inner_proto:6}}`。

- `fields`：帧 3 `ip.proto=6`、`ppp.protocol=0x0021`。
- **断言要点**：`inner_proto=6` = 内嵌 TCP；**链路径 `spec.TCP` 缺席 → L4 Seq/Ack/Flags 全零值合成**（设计 §3.7）。

### 3.16 `pppoe_data_payload_bytes`（4 帧）

`{pppoe:{skip_discovery:true, session_id:5, data_payload:"tg-payload"}}`。

- `fields`：帧 3 `ppp.protocol=0x0021`。
- `frames`：帧 3 offset 50 `74 67 2d 70 61 79 6c 6f 61 64`（`"tg-payload"` 10 个 ASCII 字节）。
- **断言要点**：offset 50 = eth 14 + PPPoE 6 + PPP 2 + IP 20 + UDP 8；**`data_payload` 字符串 = 原文字节**（`getByteSlice` 语义，非 hex）；`payload_length = 2+20+8+10 = 0x0028`。

### 3.17 `pppoe_data_frames_two`（5 帧）

`{pppoe:{skip_discovery:true, session_id:7, data_frames:2}}`。

- `fields`：帧 3 `ppp.protocol=0x0021`；帧 4 `ppp.protocol=0x0021`；帧 5 `pppoe.code=0xa7`。
- **断言要点**：**两数据帧 `ip.id` 逐帧递增**（`planner.go:439-443` `ipidCounter` 每会话独立计数）；PADT 收尾。

### 3.18 `pppoe_inner_udp_explicit`（4 帧）

`{pppoe:{skip_discovery:true, session_id:8, inner_proto:17}}`。

- `fields`：帧 3 `ip.proto=17`。
- **断言要点**：显式声明 UDP 面；**缺省面（`inner_proto=0` + `spec.TCP == nil` → 17）由 #1 覆盖**——本例如实只钉"显式写 17 与缺省同结果"。

**正例总则**：多节点/多帧/多会话/双方向/双认证/双协议均为正例形态，只有配置/长度/地址族错误进入负例。

## 4. 负例契约

负例必须在 registry/schema/planner 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩外壳的假成功（**6 例实测 0 帧**）。锚词与设计 §7 表一一对应、同序（代码逐字）：

| ID | 故障输入（机读实测） | JSON `error_contains` | 真实拦截点 + 代码文案（逐字） | 代码行 |
|---|---|---|---|---|
| `pppoe_neg_auth_invalid` | `{auth:"radius"}` | `Auth` | planner `Validate`：`pppoe: Auth %q not in supported list (allowed: none, pap, chap)` | `planner.go:129` |
| `pppoe_neg_inner_proto_invalid` | `{inner_proto:5}` | `InnerProto` | planner `Validate`：`pppoe: InnerProto %d not in supported list (allowed: 6=TCP, 17=UDP)` | `planner.go:137` |
| `pppoe_neg_data_frames_negative` | `{data_frames:-1}` | `data_frames` | **registry V9 范围门**：`... field "data_frames" = -1 invalid: not a numeric value in [0,1000000]` | `complete.go:315`（planner 同分支 `planner.go:141` **链路径不可达**） |
| `pppoe_neg_ipv6_inner` | ip 层 `{src:"2001:db8::1", dst:"2001:db8::2"}` | `must be IPv4` | planner `Validate`：`pppoe: SrcIP %q must be IPv4 (PPPoE carries IPv4 over PPP Protocol 0x0021, RFC 1661 §6)` | `planner.go:120` |
| `pppoe_neg_sessions_mutex` | `{data_frames:3, sessions:[{session_id:100}]}` | `pppoe: sessions and top-level session config are mutually exclusive` | **schema `checkPPPoESessionsMutex`**（create-time 400）；planner 背 door 同锚词 | `semantic.go:326/334`；`planner.go:160/169` |
| `pppoe_neg_duplicate_session_id` | `sessions:[{session_id:100},{session_id:100}]` | `pppoe: duplicate session_id` | **schema `checkPPPoESessionsMutex`**（create-time 400）；planner 背 door 同锚词 | `semantic.go:355`；`planner.go:178` |

**锚词口径**：`error_contains` 是**子串**判定。N-1/N-2/N-4 命中 planner 文案；N-3 命中 registry 范围门文案（**锚词随真实拦截面**——P5 实测钉：registry V9 门先于 planner Validate，故 planner 的 `DataFrames %d must be >= 0` 在链路径**不可达**）；N-5/N-6 命中 schema 文案（**task-time 背 door 同锚词**，两路独立闭合，C 类）。

**负例原子性**：6 例**每例单一故障注入**，单次执行不得混注。`expect` 键集合 = **`{expect_error, error_contains}` 严格两键**（机读实测 6/6，**无 `notes` 键**——本协议已合规，与 opcua 存量不同）。

**地址族纪律（P5 教训）**：N-4 必须用**同族 IPv6**——混族（v4 源 + v6 目的）会被 **ip 层 same-IP-version 门先拦**，pppoe validator 的 `must be IPv4` 分支不可达。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：

| 分支 | 锚词 | 代码行 | 可达性 |
|---|---|---|---|
| `PPPoE == nil` | `pppoe: PPPoE config is required` | `planner.go:102` | **链路径不可达**（translate 空层也翻译出非 nil） |
| `SrcIP`/`DstIP` 非 IP 文本 | `pppoe: %s %q is not a valid IP address` | `planner.go:117` | 可达（今日无例） |
| `DataFrames < 0` | `pppoe: DataFrames %d must be >= 0` | `planner.go:141` | **链路径不可达**（registry V9 先拦） |
| `DataDirection` 非 `up`/`down` | `pppoe: DataDirection %q not in supported list (allowed: up, down)` | `planner.go:149` | 可达（今日无例） |
| `sessions[]` 空数组 | 同 N-5 锚词 | `planner.go:160` + `semantic.go:334` | 可达（今日无例） |
| builder 非法 `Code` | `pppoe: invalid code 0x%02x ...` | `builder.go:447` | **不可达**（planner 自管 code） |
| builder PPP 控制报文带 L3/L4 | `pppoe: PPPProtocol 0x%04x carries PPP control bytes in Payload ...` | `builder.go:452` | **不可达** |
| builder Discovery 带 L3/L4 | `pppoe: discovery code 0x%02x carries TLV tags only ...` | `builder.go:461` | **不可达** |
| builder Discovery 同时带 tags 与 Payload | `pppoe: discovery frame carries both DiscoveryTags and Payload ...` | `builder.go:464` | **不可达** |
| `PayloadLength` 覆写 >65535 | `pppoe: payload length %d exceeds 65535 ...` | `builder.go:350` | 可达（今日无例） |
| GRE + PPPoE 组合 | `gre: cannot combine GRE with PPPoE ...` | `builder.go:494` | **不可达**（pppoe 层无 GRE 键） |

**"状态机错"类负例显式不适用**：本实现**无运行时收包状态机**（`runSession` 是顺序过程，`planner.go:220-485`）——**不存在"在错误状态收到某帧"的输入面**，故 §4 最小清单的"状态机错"一行在本协议**显式不适用**，理由=无收包/无事件循环，不硬凑用例。**"载体错"类**同理由不适用（无外层传输层可错配）。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC2516 + RFC1661 + RFC1334 + RFC1994（**原文本轮拉取逐节核对**，设计 §10）+ D-PPPOE-1（设计 §11）+ tshark 3.6.14 字段表与 24 例 cases → 24 ID（本契约 §2）。

**24 ID 逐项回指**：#1←设计 §3.4/§3.5/§3.7/§3.8；#2←§3.8；#3←§3.4；#4←§3.5；#5←§3.5/§3.6；#6←§3.5/§3.6；#7←§3.7；#8←§3.7；#9←§3.3；#10←§3.3；#11←§3.5；#12←§5；#13←§5；#14←§5/§10.4；#15←§3.7；#16←§3.7；#17←§3.7；#18←§3.7；#19←§7 N-1；#20←§7 N-2；#21←§7 N-3；#22←§7 N-4；#23←§7 N-5；#24←§7 N-6。

**第三源诚实声明**：第三源"现网行为"今日 = **未取到**——本仓无现网 BRAS 抓包（`docs/protocol-pcap-test/pppoe/` 目录不存在；`.gitignore:88` `*.pcap` 使 pcap 从不入库）。BRAS 三标签形（#10）的出处是**运营商接入网通用抓包形**，**未经本仓实测对照** → G-PPPOE-5（待确认方式 = 抓现网拨号包对照）。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 2516/1661/1334/1994 原文逐节反推 + 内部契约 D-PPPOE-1/T-PPPOE + 仓库落码反推 + tshark 3.6.14 字段表**，**非纯规范反推**（第三源未取到 → G-PPPOE-5）。
- **对账两行**：**要求逻辑点总数 = 110**（八项 8 行 + 矩阵 24 格 + 变体 58 行 + 商业映射 20 行）；**覆盖数 = 79**（八项 5 + 矩阵 16 + 变体 46 + 商业 12）；**不适用 = 16**（矩阵 8 + 商业 8；八项第 7 行"被动模式显式不适用"同时该行另有立项，见下注）；**开放立项 = 15**（八项 3 + 变体 12）。79 + 16 + 15 = **110** ✓
  **重数（逐表，机读逐行统计）**：八项 8 = 覆 5（第 1/2/3/4/8 行缺口列"无"）+ 立项 3（第 5/6/7 行，第 7 行"中继 → G-PPPOE-5"）✓；矩阵 24 格 = 覆 16 + A′ 0 + 不适用 8 ✓；变体 58 = 覆 46 + 立项 12 ✓；商业 20 = 覆 12 + 不适用 8 ✓。**四表合计 = 110**（8+24+58+20）✓。
  **注（口径）**：① 覆盖数 79 > 用例数 24 属正常——**同一用例覆盖多个逻辑点**（如 #1 一个用例覆盖 code 六值、TLV、PPP 协议、LCP 选项、数据面等多行），这是 §7"设计一条规格可派生多条用例、反之一个用例可覆盖多条规范行"的正常形态，**不做一对一映射**；② 八项第 7 行同时含"被动模式显式不适用"与"中继立项"两面，按**主口径（缺口列有值）计为立项 1**，其"不适用"面在行内文字显式声明，不重复计数（故"不适用"合计 16 而非 17）。
  **粒度声明**：行/格粒度每点 1 计；G-PPPOE-1…G-PPPOE-9 不折进 110。**反查全绿 ≠ 覆盖全**。**行内复核已机读实测**：18 正例包数 0 例不符（§5.3）、6 负例 `expect` 严格两键、`spec_json` 顶层键 24/24 ⊆ `{layers}`。
- **门3 抽查候选**：最复杂用例 = **#14 `pppoe_composite_multi_session`**（19 帧：两会话混合形态，交织维度 = 多会话(2) × 认证(chap 模板共享) × skip_discovery × 方向(down) × 多帧(2) = **5 类**）；**建议门3 抽 #14 + #12**（`pppoe_sessions_derived_ids` 补派生 ID 与整块顺序面）。

### 5.3 机读复核结果（本轮，自审用）

| # | 复核项 | 方法 | 结果 |
|---:|---|---|---|
| 1 | 24 例 ID 集合与顺序 | `json.load` 逐例取 `id` | 与 §2 表**逐项一致** |
| 2 | `spec_json` 顶层键 | 逐例取 `spec_json.keys()` | **`{layers}` ×24**，零游离键 |
| 3 | 层形 | 逐例取 `layers[].keys()` | **`[ip,pppoe]` ×24**，统一 |
| 4 | 18 正例 `packet_count` | 对 §1 公式逐例重算 | **0 例不符**（8/7/4/8/10/11/4/8/8/8/4/24/16/19/4/4/5/4） |
| 5 | 6 负例 `expect` 键集合 | 逐例取 `expect.keys()` | **`{expect_error,error_contains}` ×6**，无 `notes` |
| 6 | 全部 `frames` 断言（8 例 **20 条**） | 对派生字节模型（PPPoE 头/EtherType/TLV/PPP 头/LCP 选项偏移） | **全 OK**（含 offset 14 处 `payload_length` 3 处算例） |
| 7 | `coverage_gate.py pppoe` | `python3 trafficgen/tools/coverage_gate.py pppoe` | **45/45 通过，出口 0（绿）** |

**7 项全绿。**

## 6. P3 固定动作（§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单会话内多事务（Discovery 4 + LCP 1 + 认证 0–3 + 数据 N + PADT 1）；多会话多轮完整生命周期 | 已覆 #1（5 事务）/ #5（6）/ #6（8）/ #12（3×5）/ #14 |
| ② | 非正常结束 | **无外层 TCP → RST 不适用**；应用层拆线 = PADT（RFC2516 §5.5），本协议唯一终止表达 | 已覆 #1/#3/#5/#8/#14/#17（PADT）；**抑制反向面 #2**；**RST 显式不适用**（无 TCP 层） |
| ③ | 长保活 | **协议层无 keepalive**：RFC2516 §7 的 LCP Echo-Request（RECOMMENDED）未编排；§8 的 PADI/PADR 重传未实现 | **立项**（G-PPPOE-5；不硬凑用例） |

无空项：① 有已覆例；② 有已覆例 + 1 条显式不适用（RST）；③ 如实立项（非静默留空）。

### 6.2 A′/B′ 两分类表

**A′（代码阶段接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 章节引注面 | 修正 7 处 RFC 章节号引错（`planner.go` 注释 + cases summary） | G-PPPOE-1 |
| 字段断言面 | 收编 tshark `pppoe.payload_length`/`pppoe.version`/`pppoe.type`/`ppp.magic_number`/`ppp.length`——今日零使用 | G-PPPOE-6 |
| 拒绝分支面 | `data_direction` 非法 / `SrcIP` 非 IP 文本 / `sessions[]` 空数组 | 设计 §7 表 |
| 上限边界面 | `payload_length` 覆写 / `mru > 1492` / `session_id == 0xffff` / PADI > 1484 | G-PPPOE-6（含 2 条"实现不校验规范上界"缺陷候选） |
| 缺省面 | `ac_name` 缺省 `"trafficgen"` 显式断言 | 设计 §5 规则 3 |
| TLV 面 | Host-Uniq `0x0103` / Relay-Session-Id `0x0110` / PADS Service-Name-Error `0x0201` / AC-System-Error `0x0202` / Generic-Error `0x0203` / End-Of-List `0x0000` | G-PPPOE-5 |
| MAC 面 | eth 层 MAC 覆写（**需先修 G-PPPOE-2**） | G-PPPOE-2 |
| 动态面 | `sessions[].session_id` 动态对象（`SessionIDDyn` 逐流 `FlowIndex` 解析） | G-PPPOE-8 |
| 地址协商面 | IPCP 阶段（**需先实现**） | G-PPPOE-3 |
| 端口面 | 内嵌 IPv4 L4 端口非 0（**需先实现端口位**） | G-PPPOE-4 |
| 保活面 | LCP Echo-Request / PADI 重传 | G-PPPOE-5 |

**B′（框架面）**：`CheckProtoFlat` pppoe presence 分支 + 游离顶层键通用门（G-PPPOE-7，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态 allowlist 无 `pppoe` 行（G-PPPOE-8）。进设计 §14，「明确不解决 + 迁入计划」。

### 6.3 3.14 豁免边界审计

**有会话载体（`sessions[]` 多生命周期）→ 不豁免**（设计 §12.3 会话表 s1/s2；`sessions[]` 是**每项一条完整独立生命周期**的编排数组，与 sip `sessions`/`medias` 同族形态——**形态差异已声明**：本协议 `sessions[]` 与顶层行为 6 键互斥，模板 9 键共享，D-PPPOE-1 裁定4）；**多流并发**由策略级 `flow_control {"flows": N}` 承载（本版 24 例未用，存量单 flow）；**单包多载荷** = **不适用**（PPPoE 每帧一个 PPP 协议报文，无多 question/多 RR 类形态，如实声明）。

## 7. 实现后执行建议

1. **代码阶段顺序**：①先修 G-PPPOE-1（纯注释/文案，**不改行为/包数/断言**）；②裁定 G-PPPOE-2（MAC 取值优先级）与 G-PPPOE-6 两条"实现不校验规范上界"（`mru`/`session_id 0xffff`）——拒绝或登记；③补 A′ 拒绝分支与上限边界面；④补 TLV 面（G-PPPOE-5）；⑤全量复跑。**本协议无 §1 迁移步骤**（顶层零残留）。
2. **实测顺序**：先 #1（8 帧 code 序 `09/07/19/65/00/00/00/a7` + PADT LENGTH 0），再 #4（LCP len 14 基线），再 #5/#6（认证面 LCP len 18 + PAP/CHAP 帧序），再 #11（MRU/Magic 钉值），再 #12（派生 ID 1/2/3 + 整块顺序），最后 #14（复合大场景 19 帧）。
3. **二进制与 HEAD 同代确认**（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=pppoe` 全量不是增量）；门2④ 反查绿后进 P6。
4. **服务端重启纪律**（P5 教训）：改 parse/planner 后必须重编重启服务端，否则 suite 用旧逻辑跑（padt 漏接 bug 的 got-8 根因）。
5. 任何 RFC 条款号引用须有原文证据（**本轮已逐节核对并校正 7 处引错**，G-PPPOE-1）。

## 8. 存量审计（24 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/pppoe.json` **24 例**：18 正带 `packet_count`（8/7/4/8/10/11/4/8/8/8/4/24/16/19/4/4/5/4），**逐例对 §1 公式机读复核 0 例不符**；6 负 `expect` 键集合 `{expect_error,error_contains}`（**严格两键**）；24/24 顶层键仅 `{layers}`（**零残留**）；层形 `[ip,pppoe]` ×24；8 例含 `frames`（**20 条**），逐条对派生字节模型复核**全 OK**；层内 `pppoe` 已带 16 键（与 registry Fields 逐键一致，机读实测）。

### 8.2 现状矛盾点（诚实登记）

1. **RFC 章节号引错 7 处（G-PPPOE-1）**：`planner.go` 注释与 cases summary 把 PADT 标 §5.6（应 §5.5）、PPP 协议表标 RFC1661 §5（应 §2）、Magic 标 §6.13（应 §6.4）、Auth-Protocol 标 RFC1661 §8（应 §6.2）、PAP 标 RFC1334 §2.1（应 §2.2.1）、CHAP 标 RFC1994 §3（应 §4.1）。**行为与断言全部正确，仅引注错**——本轮已用 RFC 原文逐节核对钉正确章节号。
2. **MAC 覆写不可达（G-PPPOE-2）**：planner 恒写非空 MAC（缺省 `aa:bb:cc:dd:ee:01/02`）抢先于 `chain_planner.go:1352` 的空值回填；且 planner 缺省与 spec 缺省（`02:00:00:00:00:01/02`）是**两套值**——#7 断言 `eth.src=02:00:00:00:00:02` 实测为后者（spec 缺省）。
3. **`data_frames=0` 语义勘误（已修）**：T-PPPOE 原写"无数据帧"与实现 `frames==0→1` 不符，P5 已按实现语义勘误并落 #8 notes（"0 非'无数据帧'而是缺省 1"）。
4. **负例锚词随真实拦截面（已钉）**：#21 `data_frames=-1` 被 **registry V9 范围门**拦（非 planner），锚词 `data_frames` 命中范围门文案；#22 必须**同族 IPv6**（混族被 ip 层 same-IP-version 先拦）。
5. **TLV 面未编排（G-PPPOE-5）**：builder 的 `serializePPPoETags` 是通用 TLV 序列化器（任意 `Type` 可序列化），但 planner 只编排 `0x0101`/`0x0102`/`0x0104` 三种；Host-Uniq/Relay-Session-Id/三个错误标签/End-Of-List 今日**无编排通道**。
6. **IPCP 未实现（G-PPPOE-3）**：现网拨号先协商地址再传数据，引擎数据面地址来自配置——v1 合成面，如实登记。
7. **内层端口恒 0（G-PPPOE-4）**：链上无 tcp/udp 层可承载内嵌 IPv4 端口，pppoe 层 16 键亦无端口位——#1 notes 已注记（"链路径无端口位→srcport/dstport=0（合成面，B′ 注记）"）。
8. **`expect.notes` 键（非缺陷）**：18 正例 `expect` 含 `notes`（说明性文案），6 负例**不含**——与 opcua 存量（负例也带 `notes`）不同，本协议负例已合规，**无收窄动作**。
9. **pcap 留档不入库（G-PPPOE-9）**：`trafficgen/docs/protocol-pcap-test/pppoe.md`（tracked）的 24 条 pcap 链接**全部断链**（目录不存在；`.gitignore:88`）。**该 md 末次提交 `bdd6275`（2026-09-20）晚于判死提交 `0417be5`（2026-09-13），不属过期产物**（与 opcua G-OPCUA-10 相反）；本车道未跑该套件，**不以任何形式**引用该产物作为套件可跑证据。
10. **存量未覆盖**：`data_direction` 非法 / `SrcIP` 非 IP / `sessions[]` 空数组 / `payload_length` 覆写 / `mru>1492` / `session_id 0xffff` / 6 个 TLV / IPCP / MAC 覆写 / 动态 `session_id` / LCP Echo **今日零用例**（A′ 补）。

### 8.3 逐条去向表（24 行）

| 存量 id | T-编号 | 去向 | 改写动作（代码阶段） |
|---|---|---|---|
| `pppoe_lifecycle_full` | T1 | **保留** | 形状已合规（纯 layers）；summary 章节号 §5.6 → §5.5（G-PPPOE-1）；可补 `pppoe.payload_length` field 断言 |
| `pppoe_padt_suppressed` | T2 | **保留** | 同上（章节号）；断言已足 |
| `pppoe_skip_discovery` | T3 | **保留** | 同上 |
| `pppoe_auth_none_lcp_len` | T4 | **保留** | 同上；可补 `ppp.length` field 断言 |
| `pppoe_auth_pap` | T5 | **保留** | 同上；RFC1334 引注 §2.1 → §2.2.1/§2.2.2 |
| `pppoe_auth_chap` | T6 | **保留** | 同上；RFC1994 引注 §3 → §4.1/§4.2 |
| `pppoe_data_direction_down` | T7 | **保留** | 同上；可补 MAC 双套值说明（G-PPPOE-2） |
| `pppoe_data_frames_zero_default` | T8 | **保留** | 语义勘误已在 notes 落定（P5） |
| `pppoe_service_name_any` | T9 | **保留** | 形状已合规 |
| `pppoe_bras_three_tags` | T10 | **保留** | 第三源未取到 → G-PPPOE-5 待确认 |
| `pppoe_mru_magic_explicit` | T11 | **保留** | Magic 引注 §6.13 → §6.4（G-PPPOE-1） |
| `pppoe_sessions_derived_ids` | T12 | **保留** | 可补"整块顺序"断言说明（今日靠帧位间接钉） |
| `pppoe_sessions_explicit_ids` | T13 | **保留** | 形状已合规 |
| `pppoe_composite_multi_session` | T14 | **保留** | 形状已合规（门3 抽查候选） |
| `pppoe_inner_tcp_explicit` | T15 | **保留** | 形状已合规 |
| `pppoe_data_payload_bytes` | T16 | **保留** | 形状已合规 |
| `pppoe_data_frames_two` | T17 | **保留** | 可补 `ip.id` 递增显式断言（今日 notes 描述，无 field 断言） |
| `pppoe_inner_udp_explicit` | T18 | **保留** | 形状已合规 |
| `pppoe_neg_auth_invalid` | T19 | **保留** | 已合规（严格两键） |
| `pppoe_neg_inner_proto_invalid` | T20 | **保留** | 同上 |
| `pppoe_neg_data_frames_negative` | T21 | **保留** | 同上（锚词随 registry V9 真实拦截面，P5 已钉） |
| `pppoe_neg_ipv6_inner` | T22 | **保留** | 同上（同族 IPv6 纪律，P5 已钉） |
| `pppoe_neg_sessions_mutex` | T23 | **保留** | 同上（锚词已是最长完整文案） |
| `pppoe_neg_duplicate_session_id` | T24 | **保留** | 同上 |

**无"作废不注原因"**：**0 作废，0 等价覆盖**——24 例全部保留（其中 8 例含可补强项，均属 A′ 增量而非改写）。**本协议存量 24/24 顶层零残留**。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

> **前置事实**：`coverage_gate.py:3681 check_pppoe` **已存在并已登记 45 条检查**（场景 24 + 键 15 + 锚词 6），**本轮复跑 45/45 全绿，出口 0**（机读实测）。故本节的建议是**增量补强**，不是从零登记——主线程合入时按需追加，**不删既有 45 条**。

建议追加下列断言（**每条均可从本契约与 cases JSON 直接机读，不需新造事实**）：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['pppoe']) == 24` 且 ID 集合 = §2 二十四项，**顺序一致** | 本契约 §2 |
| 2 | 24/24 例 `spec_json` 顶层键 ⊆ `{layers}`（**本协议零游离键**） | 本契约 §1；设计 §12.1 |
| 3 | 24/24 例层形 == `["ip","pppoe"]`（统一，无例外） | 本契约 §1 |
| 4 | 18 正例 `packet_count == (0 if skip_discovery else 4) + 2 + (2 if pap\|3 if chap\|0) + max(data_frames,1) + (0 if padt is False else 1)`（`sessions[]` 时逐会话求和） | 设计 §5 公式 |
| 5 | 6 负例 `expect` 键 == `{expect_error, error_contains}`（**严格两键，无 notes**） | 本契约 §4 |
| 6 | 负例 `error_contains` ∈ 代码锚词集 `{"Auth", "InnerProto", "data_frames", "must be IPv4", "pppoe: sessions and top-level session config are mutually exclusive", "pppoe: duplicate session_id"}` | 设计 §7 |
| 7 | 非负例顶层键计数 == 0（**今日已成立**） | 设计 §12.1 |
| 8 | 每例至少一条 `fields` 断言；含 `frames` 的 8 例每条 frames 落在 offset ∈ {14, 20, 26, 30, 32, 50} | 本契约 §3 |
| 9 | 全 24 例的 `pppoe` 层键 ⊆ registry 16 键集合（**wire 键 `code`/`ppp_protocol`/`payload_length`/`discovery_tags` 不得出现**） | 设计 §11.3 |
| 10 | `sessions[]` 与行为 6 键**不得同时出现**于同一 pppoe 层（#23 负例除外——该例是 `expect_error` 用例，断言其存在） | 设计 §11.3 / D-PPPOE-1 裁定4 |
| 11 | 显式 `session_id` 在 `sessions[]` 内**不得重复**（#24 负例除外） | 设计 §11.3 / 裁定5 |

**另注意**：`trafficgen/docs/protocol-pcap-test/pppoe.md` 的 24 条 pcap 链接**全部断链**（G-PPPOE-9，`.gitignore:88` 使 pcap 不入库），但该 md 末次提交 `bdd6275`（2026-09-20）**晚于**判死提交 `0417be5`（2026-09-13）——**不属过期产物**；本车道**未跑**该套件，故不以任何形式引用该产物作为"今日已复跑"依据。

## 10. 修订记录

- v1.0.0（2026-09-29）：批次二 as-built 文档轨首版。**本协议无外部旧稿**——继承来源 = 内部契约 T-PPPOE-1…24（`TEST_CASES.md:3744`，24/24×2 已执行）+ D-PPPOE-1（`CODE_DESIGN.md:2882`）。**24 ID 逐项索引**（§2，与 cases JSON 逐条一致）；18 正例逐项断言契约（§3）；6 负例锚词表含**真实拦截面**（§4：N-3 走 registry V9 门、N-5/N-6 走 schema create-time 门，planner 背 door 同锚词）；P3 固定动作（§6：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）；执行建议（§7）；存量审计 24/24 全部保留（§8）；覆盖反查门**增量**建议 11 条（§9，**既有 45 条已绿，不删**）。
  **本轮机读复核 7 项全绿**（§5.3）：ID 集合与顺序 / 顶层键 24/24 ⊆ `{layers}` / 层形 24/24 `[ip,pppoe]` / 18 正例包数对公式 **0 例不符** / 6 负例严格两键 / 20 条 frames 对派生字节模型全 OK / `coverage_gate.py pppoe` **45/45 出口 0**。
  **校正与缺口**：RFC 原文逐节核对钉出 **7 处章节号引错**（G-PPPOE-1，纯引注，不改行为）+ 1 处代码可判题的 MAC 覆写不可达（G-PPPOE-2）；缺口 G-PPPOE-1…G-PPPOE-9。**自审 3 轮，末轮干净**（第 1 轮抓 2 处覆盖表用例号错标——code/TLV 行的断言落点与机读实测不符，已改按实测钉；第 2 轮复核包数公式与 frames 模型，0 处不符；第 3 轮复核重数与对账两行，干净）。

# #94 modbus（Modbus TCP 工业控制协议）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3）
> 日期：2026-09-28
> 配套设计：`docs/protocol-designs/94-modbus-design.md` v1.0.0（D-MODBUS-1）
> 旧基线：`docs/protocol-designs/13-modbus-design.md` v2.0.4 §7（T-001~T-205；思路继承不搬码）
> 机器契约：`trafficgen/test/protocol_pcap/cases/modbus.json`（213 例；**当前全部不可执行**——三种形状全被拒，设计 §0.1 实测；改写待 G-MODBUS-1/2）
> 白话一句：**二百多条检查——大部分看"发出去的字节对不对"（功能码、地址、数量、掩码、异常码），一小部分看"胡来的配置能不能被拦下"；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生。存量 **213 例（151 正 + 62 负）**，180 个唯一 T 编号（25 个缺号：34/41/46/47/55/57/59/60/67/70/71/72/110/128/132/136/141/142/145/147/158/159/160/194/196）。派生规则：设计 §3 每个 FC 字段条款、§5 每个事务/抑制行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-28 机读实测）**：

| 项 | 实测值 |
|---|---|
| `spec_json` 顶层键 | `{layers, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, modbus}` ×130 + 同形带 `count` ×2 + **纯扁平（无 layers）** ×81 |
| `layers` 内容 | 132 例恒为 **空壳** `[{"tcp":{}},{"modbus":{}}]`（机读唯一值） |
| 地址/MAC | 恒 `10.0.0.1 → 20.0.0.1`、`02:00:00:00:00:01 → 02:00:00:00:00:02`（213/213，**零 IPv6**） |
| 端口 | `src_port` 0×211 / 20000×1 / 40000×1；`dst_port` 502×212 / 1502×1 |
| `strategy_fc` | **0 例** |
| 层内 `tcp` 键 | 恒 `{}`（无 mss/handshake/initial_seq，213/213） |
| 正例 `packet_count` | 145 例有（众数 **9** = 3 握手 + req + resp + 4 挥手，113 例）；6 例用 `min_packets` |
| 帧断言偏移 | **110 例 / 169 条**，**恒 offset 54**（IPv4） |
| 断言字段面 | `modbus.*` 30 种 + `mbtcp.*` 3 种 + `tcp.dstport/srcport` + `ip.src` |
| 负例 | 62；expect 键集：`{ec,ee,notes}`×33 / `{ec,ee}`×13 / `{expect_error}`×8 / 含成功断言×5 / `{ee,notes}`×3。**缺 `error_contains` 者 11 例**（8 例仅 `{expect_error}` + 3 例 `{expect_error,notes}`）；**混入成功断言者 5 例** |

**执行可行性（MCP 实测，设计 §0.1）**：三种形状**全部被拒**——纯扁平 → `no longer accepts flat config field src_ip`；空壳 layers + 顶层扁平键 → 同上 + `config mixes layers with flat four-tuple field src_ip`；严格层链 → `layers: layer "modbus": unknown field "transactions"`。**本文件全部断言在 G-MODBUS-1/2 闭合前无法执行**（不冒充已覆盖，CORE_MEMORY §1.9 / B6 §1 JSON ID 纪律）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport/srcport`、`tcp.flags`、`modbus.*`/`mbtcp.*`、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线**：本机 tshark 3.6.14 有 Modbus 解析器。可用通道：① `modbus.*`（func_code/reference_num/word_cnt/bit_cnt/byte_cnt/exception_code/diagnostic_code/and_mask/or_mask/mei/conformity_level/object_*/ev_count/…，**30 种**，机读实测）；② `mbtcp.*`（trans_id/unit_id/len，3 种）；③ `tcp.dstport/srcport`/`tcp.flags`/`tcp.seq`/`tcp.len`；④ `ip.src`/`ipv6.src/dst`；⑤ frames `offset/hex`（帧首字节，IPv4 offset 54 / IPv6 offset 74）。

**已知 tshark 限制（更正 2026-09-28）**：FC 0x08 子功能 0x0015 在 Wireshark 3.6 **值表未收录**（显示 `Diagnostic Code: Unknown (21)`）——**但字段本身可观察**：自建 pcap 实证 `tshark -T fields -e modbus.diagnostic_code` 输出 **`21`**，`tshark -G fields` 确认 `modbus.diagnostic_code` 在册（`FT_UINT16`），仅 `tshark -G values` 缺 `21` 条目。**故该例断言 `modbus.diagnostic_code=21` 与 frames hex 并存、均有效**（存量 `modbus-fc08-sub-0015-max` 正是双断言，机读实测）；**不得**因"值表未收录"删掉字段断言（先前"改断 frames hex"的说明系误判，已删）。

**动态字段禁止硬编码**：生成期值用 `same_as_packet`/`distinct_values`/`nonzero` 断言。

**包数约定**：单流 = 3（握手）+ 2N（N 事务 × req+resp）+ 4（FIN 四包挥手）。**空事务（`transactions: []`）= 3 + 0 + 4 = 7 包**（无 modbus 数据帧，`modbus-transactions-empty-array` 机读实测 `packet_count=7`；该例不设 `directional`——挥手 FIN 后 server ACK 仍在，但无响应方向数据）。响应被抑制时 `2N` 减为 N（如 `responsemode-no-response` 单事务 = 3 + 1 + 4 = 8 包，机读实测）。数据帧从帧 4 起；实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count。

**保活/重试/RST 口径**：modbus 层无 PING 类消息，不设正例亦不得进负例；RST 为框架 tcp 层能力，本协议层不新增断言；正例恒 FIN 优雅终止。**响应超时/重传显式不适用**（设计 §4 声明，用例不得携带）。

## 2. 原子用例索引（213 ID = 151 正 + 62 负，顺序为权威）

存量 ID 顺序即 JSON 顺序，改写时保持稳定。按功能域分组（**T 编号为权威 ID，`modbus-*` 为 JSON id**）：

| 域 | 用例数 | 代表 ID | 覆盖（设计 §） |
|---|---:|---|---|
| FC 0x01/0x02 读位 | 8 | `modbus-fc01-read-coils`、`modbus-fc02-qty2000-max` | §3.3/§3.4 位打包 |
| FC 0x03/0x04 读寄存器 | 8 | `modbus-fc03-read-holding`、`modbus-fc04-qty125-max` | §3.3 寄存器值 BE |
| FC 0x05/0x06 写单 | 11 | `modbus-fc05-write-coil`、`modbus-fc06-writevalue-ffff` | §3.3 echo 响应 |
| FC 0x07/0x08 状态/诊断 | 9 | `modbus-fc07-read-exc-status`、`modbus-fc08-sub-0015-max` | §3.3 子功能表 |
| FC 0x0B/0x0C 事件 | 4 | `modbus-fc0b-multi-tx`、`modbus-fc0c-events-3ev` | §3.3 字段序 |
| FC 0x0F/0x10 写多 | 7 | `modbus-fc0f-write-multi-coils`、`modbus-fc10-qty123-max` | §3.3/§3.5 上限 |
| FC 0x11 从站 ID | 2 | `modbus-fc11-report-server-id` | §3.3 无 Byte Count |
| FC 0x14/0x15 文件记录 | 6 | `modbus-fc14-multi-record`、`modbus-fc15-multi-item` | §3.3 RefType 0x06 |
| FC 0x16 掩码写 | 4 | `modbus-fc16-mask-formula` | §3.3 AND/OR |
| FC 0x17 读写多 | 9 | `modbus-fc17-writeaddr-fallback`、`modbus-fc17-writeaddr-wrap` | §3.3/§8 回绕 |
| FC 0x18 FIFO | 7 | `modbus-fc18-fifo31-max`、`modbus-fc18-fifo-count-0` | §3.3/§3.5 自洽 |
| FC 0x2B MEI | 11 | `modbus-fc2b-conformity-83-extended-private` | §3.3 MEI 枚举 |
| 异常响应 | 9 | `modbus-exception-fc03-0a`、`modbus-exception-fc05-03-fc10-04` | §3.6 异常码 |
| 广播语义 | 3 | `modbus-broadcast-unit0-mirror`/`-suppress`/`-exception` | §5 广播三细则 |
| TID 序列 | 8 | `modbus-tid-increment-256tx`、`modbus-tid-wrap-65536` | §5 TID 规则 |
| 多流/multi | 20 | `modbus-flow-count-4`、`modbus-master2-flow2-matrix` | §5（**链上拒绝**，见 §5.4） |
| wire 集成 | 9 | `modbus-wire-mbap-length`、`modbus-wire-fc11-no-byte-count` | §3 全帧字节 |
| 默认/事务形态 | 5 | `modbus-transactions-empty-array`、`modbus-responsemode-no-response` | §5 自动派生规则 |
| 地址/端口/UnitID | 7 | `modbus-addr-ffff-max`、`modbus-dstport-1502`、`modbus-unitid-128-mid` | §3.1/§8 |
| 顺序/方向 | 2 | `modbus-tx-order-sequential`、`modbus-req-resp-directions` | §5 时间线 |
| 豁免路径 | 1 | `modbus-fc99-exemption` | §3.3 豁免规则 |
| 独立性（响应/请求） | 1 | `modbus-r2-resp-values-indep` | §5 关键设计点 1 |
| 负例（Validate） | 62 | `modbus-validate-*`、`modbus-r4-*` | §7 全 20 类 |

**合计 213（151 正 + 62 负）** ✓

**T-编号对照**：T-001~T-205 域划分见旧稿 §7.1-§7.8；本版保留 T 编号作为依据链锚点，JSON id 为权威执行标识。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

### 3.1 单事务基线（9 包）

FC=0x03 addr=0 qty=1（`modbus-addr-0-min`）：帧 4（offset 54）hex `00 00 00 00 00 06 01 03 00 00 00 01`（MBAP: TID=0, PID=0, Len=6, Unit=1；PDU: 03 0000 0001）；帧 5（down）响应由 `response_values` 决定（如 `modbus-fc03-qty1-min` 帧 5 = `00 00 00 00 00 05 01 03 02 ab cd`，MBAP Len=5、Byte Count=2）。`tcp.dstport=502` + `mbtcp.trans_id=0` + `mbtcp.unit_id=1` + `modbus.func_code=3`（均帧 4）；`has_handshake`/`terminates`/`directional` 全 true。

### 3.2 三事务序列（13 包）

3 事务 → 3 + 6 + 4 = 13 包。TID 递增 0→1→2（`mbtcp.trans_id` 断言）；帧 4/6/8 为 up 请求，帧 5/7/9 为 down 响应。`modbus-tid-sequence-3tx`/`modbus-wire-multi-tx-session` 为代表。

### 3.3 位打包（FC 0x01/0x02/0x0F）

`modbus-fc01-read-coils`（qty=9）→ 帧 4 = `00 00 00 00 00 06 01 01 00 00 00 09`（bit_cnt=9）、帧 5 = `00 00 00 00 00 05 01 01 02 13 01`（Byte Count=2 = ⌈9/8⌉，末字节高 7 位补 0）；`modbus-fc01-bit-order-lsb` 钉 bit0 = starting_address+0。`modbus-fc0f-qty123-unaligned`（qty=123）→ 帧 4 = `00 00 00 00 00 17 01 0f 00 00 00 7b 10`（Byte Count=0x10=16=⌈123/8⌉）。

### 3.4 数量上限边界

`modbus-fc03-qty125-max`（FC 0x03 qty=125）→ 帧 5 `00 00 00 00 00 fd 01 03 fa`（`mbtcp.len=253`、`modbus.byte_cnt=250`），帧长 259B。`modbus-fc10-qty123-max` 同值；`modbus-fc0f-qty1968-max`（qty=1968）→ 帧 4 = `00 00 00 00 00 fd 01 0f 00 00 07 b0 f6`（`modbus.byte_cnt=246`，MBAP Len=253）。

### 3.5 异常响应

`exception_code != 0` → 响应 PDU 恒 2B（`FC|0x80 + code`），MBAP Length = 3（`mbtcp.len=3`）。`modbus-exception-fc03-02`：帧 4 = `00 00 00 00 00 06 01 03 00 00 00 01`（**请求 PDU 正常构造**）、帧 5 = `00 00 00 00 00 03 01 83 02`（`0x03|0x80=0x83`）。`-0a`（Gateway Path Unavailable）/`-0b`（Gateway Target Device Failed to Respond）同形；`modbus-exception-fc05-03-fc10-04` 两事务各带不同异常码（11 包）。

### 3.6 广播语义

`modbus-broadcast-unit0-mirror`（unit_id=0 + FC 0x05 write_value=1）→ **双向镜像**：帧 4 = 帧 5 = `00 00 00 00 00 06 00 05 00 64 ff 00`（`mbtcp.unit_id=0`）；`-suppress`（`suppress_broadcast=true`）→ **无响应帧**，8 包 = 3 + 1 + 4；`-exception`（广播 + 异常码 0x02 + suppress）→ 异常响应一并抑制，帧 4 = `00 00 00 00 00 06 00 06 00 64 00 01`（FC 0x06 写单寄存器），8 包。

### 3.7 豁免路径

`modbus-fc99-exemption`（FC=0x99 ∉ 支持集 + `exception_code=0x01`）→ 请求 PDU 仅 FC 一字节，帧 4 = `00 00 00 00 00 02 01 99`（MBAP Len=2）、帧 5 = `00 00 00 00 00 03 01 99 01`（`0x99|0x80 = 0x99`，9 包）。

### 3.8 wire 集成（MBAP 全帧）

`modbus-wire-mbap-length` 逐帧核 `mbtcp.len`；`modbus-wire-fc11-no-byte-count`：帧 5 = `00 00 00 00 00 04 01 11 01 ff`（FC 0x11 响应首字节即 Slave ID=0x01、Run Indicator=0xff，**无 Byte Count**）；`modbus-wire-fc15-reftype6` 钉 item 首字节 = Reference Type 0x06；`modbus-wire-fc16-echo`：帧 4 = 帧 5 = `00 00 00 00 00 08 01 16 00 32 aa aa 55 55`（AND/OR 掩码 echo）；`modbus-wire-pid-unreachable-skip` 钉 Protocol ID 恒 0（帧 4 offset 2-3 = `00 00`）。

**正例总则**：`exception_code == 0`、Unit ID=0 + 纯写 FC、FC 0x99 + 异常码、FC 0x05 写值 ∈ {0,1,0xFF00,0x0000}、FC 0x18 FIFO count ∈ {0..31} 均为正例形态，只有配置/线格式/状态/关联/长度错误进入负例。

## 4. 负例契约

负例必须在 validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；`expect` 键集合**严格为** `{expect_error, error_contains}`（B6 §7 负例纯净性）。锚词与设计 §7 表一一对应、同序（20 类）。

**存量负例缺陷（G-MODBUS-6，改写时必修）**：

| 缺陷 | 例数 | 例 ID | 修法 |
|---|---:|---|---|
| **缺 `error_contains`** | 11 | 8 例仅 `{expect_error}`：`r4-bcast-fc03`/`-fc0c`/`-fc11`、`r4-fc2b-sub-000f`、`validate-fc15-bc-mismatch`、`validate-fc18-fifo-32`、`validate-fc2b-mei-000f`、`validate-qty-fc03-126`；3 例带 notes：`validate-fc08-subfn-reserved`、`validate-qty-fc0f-0`、`validate-unsupported-fc13` | 按设计 §7 表补锚词（广播类→`broadcast (unit_id=0) is only valid for write function codes`；数量类→`quantity must be 1-125`/`1-1968`；MEI 类→`FC 0x2B sub_function must be 0x000E`；FIFO→`FIFO count exceeds 31`；FC 不支持→`unsupported function code 0x`；子功能保留→`sub_function 0x0005-0x0009 reserved`；FC 0x15 BC→`FC 0x15 outer byte count mismatch`） |
| **expect 仅 `{expect_error}`** | 8 | `r4-bcast-fc03`、`r4-bcast-fc0c`、`r4-bcast-fc11`、`r4-fc2b-sub-000f`、`validate-fc15-bc-mismatch`、`validate-fc18-fifo-32`、`validate-fc2b-mei-000f`、`validate-qty-fc03-126` | 补 `error_contains`（这 8 例同时属"缺锚词"类，**共 11 例缺锚词 = 8 例仅 expect_error + 3 例带 notes**） |
| **混入成功断言** | 5 | `validate-fc99-exc0`、`validate-fc17-readqty-126`、`validate-fc2b-highbyte-010e`、`validate-fc2b-sub-0000`、`validate-fc2b-sub-000d`（均含 `has_handshake`/`terminates`/`directional`） | 删除成功包结构断言（负例无 PCAP） |

**负例锚词表（设计 §7 同序；锚词为 `modbus.go` 逐字实测字面值）**：

| # | 负例类 | 故障输入 | `error_contains` |
|---:|---|---|---|
| E-1 | 配置缺失 | `spec.MODBUS == nil` | `modbus: MODBUS config is required` |
| E-2 | 多主站越界 | `master_count < 0` 或 `> 1000` | `modbus: master_count must be 1-1000` |
| E-3 | 多流越界 | `flow_count < 0` 或 `> 100` | `modbus: flow_count must be 1-100` |
| E-4 | Unit ID 保留 | `unit_id > 247` | `modbus: unit_id %d is reserved (0-247)` |
| E-5 | 不支持 FC | FC ∉ 支持集且无异常码背书 | `unsupported function code 0x` |
| E-6 | FC 高位 | bit7 置位且无异常码背书 | `function code high bit must not be set` |
| E-7 | 异常码非法 | `exception_code ∉ {0} ∪ 10 合法码` | `invalid exception code 0x` |
| E-8a–d | 数量越界（逐 FC 文案不同） | FC 0x01/02 → `quantity must be 1-2000`；0x03/04 → `1-125`；0x0F → `1-1968`；0x10 → `1-123` | 对应文案 |
| E-9 | FC 0x17 缺数量 | `read_quantity`/`write_quantity` 越界 | `read_quantity must be explicit and 1-125` / `write_quantity must be explicit and 1-121` |
| E-10 | Values 长度不符 | FC 0x0F/0x10/0x17 | `values length must be ceil(quantity/8)` / `values length must be quantity*2` / `values length must be write_quantity*2` |
| E-11 | FC 0x05 写值非法 | `write_value ∉ {0,1,0xFF00,0x0000}` | `write_value must be 0/1/0xFF00/0x0000 or set exception_code` |
| E-12 | FC 0x18 FIFO 超限 | FIFO count > 31 | `FIFO count exceeds 31` |
| E-13 | FC 0x18 长度不自洽 | `response_values` 长 ≠ 2×FIFO count | `response_values length must match FIFO count` |
| E-14 | FC 0x08 子功能越界 | `sub_function > 0x0015` | `sub_function must be 0x0000-0x0015` |
| E-15 | FC 0x08 子功能保留 | `sub_function ∈ 0x0005-0x0009` | `sub_function 0x0005-0x0009 reserved` |
| E-16 | FC 0x2B MEI 非法 | `sub_function` 低字节 ≠ 0x0E | `FC 0x2B sub_function must be 0x000E` |
| E-17 | FC 0x2B 高字节 | `sub_function` 高字节 ≠ 0 | `FC 0x2B sub_function high byte must be 0` |
| E-18 | 互斥违反 | `exception_code != 0` 且 `response_values` 非空 | `exception_code and response_values are mutually exclusive` |
| E-19 | 广播 + 读 FC | `unit_id=0` + 读类 FC | `broadcast (unit_id=0) is only valid for write function codes` |
| E-20a–e | 文件记录 | Record Length=0 / item 长度 / RefType≠0x06 / 外层 BC 不符 / values 非 7 倍数 | `record length must be >= 1` / `item length mismatch` / `FC 0x15 item must start with Reference Type=0x06` / `FC 0x15 outer byte count mismatch` / `values length for FC 0x14 must be a multiple of 7` |

**存量锚词有效性实测**：51 例带锚词的负例**全部是上述字面值的子串**（机读逐条比对，零失配）——即锚词无需改，只需给 11 例缺锚词者补上（§4 表）。

**负例原子性**：每例单一故障注入；单次执行不得混注。

## 5. 覆盖与对账

### 5.1 三源回指行

Modbus.org **MB-ASYM-TCP V1.1b3**（MBAP 帧 + 19 FC + 10 异常码 + 广播语义）+ **D-MODBUS-1**（设计 §11）+ **tshark 3.6.14 通道实测**（`modbus.*`/`mbtcp.*`/frames）→ 213 ID（本契约 §2）。第三源"已确认现网行为"当前 = **落码反推 + tshark 通道**（本协议无现网抓包证据档，按 §5.5 不写死进实现）。

### 5.2 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **spec MB-ASYM-TCP V1.1b3 + PI-MBUS-300 Rev. J + 仓库落码反推 + tshark 通道实测**，**非从现有用例反推**（旧稿 §7 的 T-001~T-205 是按规范章节逐条派生的）。
- **对账两行**：**要求逻辑点总数 = 167**（八项 8 行 + FC×响应形态矩阵 80 格 + 数据变体 60 行 + 商业映射 11 行 + 用例形状 8 点）；**用例覆盖数 = 141**（八项 6 + 矩阵已覆 63 + 变体已覆 58 + 商业已覆 9 + 形状已覆 5）；**不适用 = 21**（八项 2〔超时活性/NAT 被动〕+ 矩阵 17 + 商业 2〔TLS 802/UDP 承载〕）；**开放 = 5**（变体 2〔IPv6 零覆盖、缺省端口名实不符〕+ 形状 3〔顶层键残留 G-MODBUS-5 / 负例纯净性 G-MODBUS-6 / presence 判死不可建 G-MODBUS-3〕）。141 + 21 + 5 = 167。✓
  **形状 8 点**：① 顶层键白名单（§1.11）② presence 负例可建性 ③ 负例纯净性 ④ 包数公式 ⑤ 帧偏移 ⑥ pcap/NIC 双输出 ⑦ 断言字段面 ⑧ ID 顺序稳定。
  **粒度声明**：行/格粒度每点 1 计；G-MODBUS-1…G-MODBUS-10 不折进 167。**反查全绿 ≠ 覆盖全**（§9.52 原文）——且本协议今日**连反查都无法进行**（213 例全不可执行，§1）。
- **门3 抽查候选**：最复杂用例 = `modbus-fc17-read-write` 或 `modbus-wire-multi-tx-session`（3 事务 × 多 FC × TID 递增 × req/resp 配对 × 帧 hex 双通道）；交织维度 = 事务(3)×FC(3)×方向(2)×TID 序列。若按 9.49/9.50 下限偏弱在"并发交错"面，**建议门3 抽 `modbus-wire-multi-tx-session` + `modbus-tid-perflow-5tx`**。

### 5.3 三分类（A/B/C，B6 §9.15-9.18）

- **A 类（不动代码直接写）**：绝大多数正例（FC 帧字节、边界、wire 集成）。
- **B 类（需代码或解析器改动）**：**全部 213 例**——层链内化需 G-MODBUS-1（registry Fields）+ G-MODBUS-2（translate 分支）；A′ 中 IPv6/MAC 层/缺省端口例依赖 G-MODBUS-1/2 闭合。
- **C 类（harness/架构表达力边界）**：响应超时/重传（无 wire 事件，设计 §4 声明）；多流展开（链形状拒绝，G-MODBUS-7）——**不冒充覆盖**。

### 5.4 存量多流用例的链形状去向（G-MODBUS-7）

存量 **22 例**（`master_count>1` 13 例 ∪ `flow_count>1` 12 例；19 正 + 3 负）在链形状下**生成器 + validator 双拒**（设计 §7）。去向三选一（改写时逐例裁定并注记）：① 转策略级 `flow_control {"flows": N}`（保留多流语义，如 `modbus-flow-count-4`/`modbus-mastercount2-flows3`）；② 改判为负例（锚词 `master_count`/`flow_count` 不支持）；③ 标不适用并从 ID 集合移除（若语义无法表达）。**不得静默保留为"正例"**（会真红）。

**口径对齐（22 vs 表格行 20）**：22 = **真实多流判据**（`master_count>1 ∪ flow_count>1`，含 3 负例）；§2/§8.3 域表的「多流/multi」行 = **20**（= 22 − 3 负例〔归入负例行〕+ 1 `modbus-master1-flow1-baseline`〔`mc=fc=1` 未越界，按命名归本域〕）。两数口径不同、互不矛盾；**域表按"每例恰属一行"分区，求和 = 213**（机读复算）。

其中 3 例负例（`modbus-validate-mastercount-0`/`-1001`、`modbus-validate-flowcount-0`）**语义需校正**：实测 `Validate` 判的是 `>1000`/`>100`（`modbus.go:70-75`），而存量注记写"master_count=0 rejected"/"flow_count=0 rejected"但载荷实为 **`1001`**/**`101`**——**注记与载荷不符**；且 `mastercount-0` 与 `mastercount-1001` **载荷完全相同（均 1001），属重复例**（改写时：一个保留为 `>max` 负例，另一个改载荷为 `0` 或删除并注记原因）。另 3 例（`modbus-master1-flow1-baseline`（mc=1/fc=1）、`modbus-tid-perflow-5tx`（无 mc/fc 键）、`modbus-shared-tid-wrap-65538`（mc=1/fc=1））名含 multi 但 `master_count`/`flow_count` **未越界**（机读实测），**链上合法**，仅需常规层链化。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接多事务（3 事务 req/resp 交替）→ `modbus-tid-sequence-3tx`/`modbus-wire-multi-tx-session`；256 事务/65536 回绕 | 已覆 |
| ② | 非正常结束 | 正常 FIN 全正例；**应用层异常结束 = 异常响应**（`FC\|0x80 + code`，9 例） | 已覆（异常响应 9 例）；RST 为框架面（A′ 可选） |
| ③ | 长保活 | 协议层无 keepalive 语义（设计 §4 显式不适用）；长会话 = 同连接多事务（256tx/65536 回绕例） | `modbus-tid-increment-256tx`/`modbus-tid-wrap-65536` 承载 |

无空项：① 有 3 事务 + 256/65536 事务例；② 有 9 异常例；③ 有长序列例。

### 6.2 A′/B′ 两分类表

**A′（代码补齐 + 用例）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 层链化 | registry `Fields` 补 `transactions` + 16 个 per-op 键 + translate `case "modbus"` | G-MODBUS-1/2，213 例全依赖 |
| 地址族面 | IPv6 载体（**零覆盖**） | `modbus_ipv6`（G-MODBUS-9，offset 74） |
| MAC 层 | `src_mac`/`dst_mac` 迁 `layers[eth]` | `modbus_eth_mac_layer`（§1.11 白名单） |
| 端口面 | dst_port 缺省补齐 502 | `modbus_default_port_502`（**删键**不断言值——存量 `modbus-dstport-default-502` 名为"缺省"但**实际显式写了 `dst_port:502`**，机读实测，非真缺省例） |
| 分段面 | 显式小 MSS 强制分段 | `modbus_mss_segment`（G-MODBUS-10，先跑后钉段数） |
| 判死面 | 白名单外游离键 `unknown field` | `modbus_neg_unknown_field` |
| **不建** | presence 形状（`layers` + 顶层空 `modbus` 子映射） | `modbus_neg_presence_shape`——**G-MODBUS-3 未闭前建了会真绿假通过**（§1 实测 `completed/100%`），**不列入 A′ 可建清单** |
| 负例纯净性 | 11 例补锚词 + 8 例补 `error_contains` + 5 例删成功断言 | G-MODBUS-6（§4 表） |

**B′（框架面）**：`CheckProtoFlat` modbus presence 分支（G-MODBUS-3，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态（G-MODBUS-4，allowlist 无 `modbus` 行）/ 多流展开（G-MODBUS-7，明确不解决）/ 响应超时重传（G-MODBUS-8，明确不解决）。进设计 §14，「明确不解决 + 迁入计划」。

### 6.3 3.14 豁免边界审计

**有长连接载体 → `sessions[]` 不豁免**？——**本协议无 `sessions[]` 概念**：连接即会话，多连接由策略级 `flow_control flows=N` 表达（设计 §12.3 会话表 s1/s2）。多流并发：**链形状拒绝**（G-MODBUS-7），语义走 `flow_control`。**单包多载荷显式不适用**——Modbus 一帧一 PDU，无多 question/多 RR 类形态，如实声明。

## 7. 实现后执行建议

1. **P4 顺序**：G-MODBUS-1（registry Fields + schemagen 重跑）→ G-MODBUS-2（translate 分支）→ 213 例改写（删顶层扁平键，MAC 迁 eth 层，modbus 子映射迁层内）→ 先跑后钉 213 例 → 修 G-MODBUS-6（负例纯净性）→ 补 A′ 例（IPv6/MAC/缺省端口/MSS/游离键）→ 全量复跑。
2. **实测顺序**：先单事务基线（帧 hex 与 9 包），再异常/广播/豁免，再 3 事务 TID 序列，再边界（qty=125/1968、TID 回绕），最后 IPv6（offset 74）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=modbus` 全量不是增量）；门2④ 反查绿后进 P6。
4. 任何"tshark 字段不存在"的断言须先 `tshark -G fields | grep modbus` 实证（FC 0x08 子功能 0x0015 先例：**值表缺条目 ≠ 字段不可观察**——`modbus.diagnostic_code` 字段在册且输出 21，只是 `-G values` 无 21 标签；**不得据此删字段断言**）。

## 8. 存量用例缺口登记表（213 例现状 + 待代码阶段改写）

> **本表不是"改写记录"，是缺口登记**——主线程裁定（2026-09-28）：本车道**不改 `cases/modbus.json`**。合规层链形须先补代码（设计 §0.1 G-MODBUS-1/2），按"文档先行"顺序代码阶段未到。下表登记现状、缺口与**代码阶段**的改写动作。

### 8.1 存量实测面（2026-09-28，机读）

`cases/modbus.json` **213 例**：151 正 + 62 负；顶层键 8 种 + 2 例 `count` + 81 例纯扁平；132 例 `layers` 恒为空壳 `[{"tcp":{}},{"modbus":{}}]`；地址/MAC 213/213 恒同值（**零 IPv6**）；`src_port` 211 例为 0；`strategy_fc` 0 例；层内 `tcp` 恒 `{}`；正例 `packet_count` 众数 9（113 例）；帧断言偏移恒 54（**110 例 / 169 条**）；负例 62 例中 11 例缺锚词、5 例混入成功断言。

**顶层旧键残留总量 = 1059 处**（**非负例口径**：151 正例 × 7 键 = 1057 + `count` 2；62 负例不计——负例不产 PCAP，合规判据只看正例，与 ldp/rip/pcep/a2a/nvgre 车道一致）。全例口径 1493。即合规化的清理量。

### 8.2 现状缺口清单（**全部为阻断项**，代码阶段闭合）

| # | 缺口 | 现状（机读/实测） | 闭合条件 |
|---|---|---|---|
| 1 | **213 例全部不可执行** | 三种形状全被拒（设计 §0.1 MCP 逐条探针）：纯扁平 → `no longer accepts flat config field src_ip`；空壳 layers+顶层扁平键 → 同上 + `config mixes layers with flat four-tuple field src_ip`；严格层链 → `layers: layer "modbus": unknown field "transactions"` | 补 G-MODBUS-1（registry Fields 加 `transactions` + 16 per-op 键）+ G-MODBUS-2（translate 加 `case "modbus"`） |
| 2 | **132 例的"层链"是空壳** | `layers` 只声明 `tcp`/`modbus` 两个空对象，真配置住顶层扁平键——§1.4 混用违规形（moxa G-MOXA-1 同形先例） | 同上；改写时配置搬入 `layers[modbus]` |
| 3 | **零 IPv6 覆盖** | 213 例地址恒 `10.0.0.1→20.0.0.1`；**引擎已支持**（MCP 实测 IPv6 链 `completed/9 包`，`ipv6.src/dst` 正确） | A′ 补例 `modbus_ipv6`（offset 74） |
| 4 | **多流用例与链形状冲突** | 22 例（13 `master_count>1` ∪ 12 `flow_count>1`，19 正 + 3 负）链上被双拒 | §5.4 三选一裁定；另 `validate-mastercount-0` 与 `-1001` **载荷重复**（均 1001）且注记与载荷不符 |
| 5 | **负例不纯净** | 11 例缺 `error_contains`（8 例仅 `{expect_error}` + 3 例带 notes）+ 5 例混入 `has_handshake`/`terminates`/`directional` | G-MODBUS-6；锚词按 §4 表补 |
| 6 | **"缺省端口"例名实不符** | `modbus-dstport-default-502` 显式写了 `dst_port:502`（机读），非真缺省验证 | A′ 补 `modbus_default_port_502`（删键） |
| 7 | **presence 负例不可建** | `{"layers":[…],"modbus":{}}` 实测 `completed/100%`（未拒） | G-MODBUS-3：待 `CheckProtoFlat` 补 modbus 分支（**禁单协议黑名单**，走框架级白名单）后方可建立；**今日建 = 真绿假通过** |

### 8.3 逐条去向表（213 例按域汇总；逐 ID 明细见 JSON 顺序）

> 「去向」列 = **代码阶段**动作，本车道不执行。ID 顺序 = JSON 顺序，改写时保持稳定。

| 域 | 例数 | 去向（代码阶段） | 改写动作 |
|---|---:|---|---|
| FC 0x01/0x02 读位 | 8 | **改写** | 顶层键删；地址→`layers[ip]`；MAC→`layers[eth]`；`modbus` 子映射→`layers[modbus]`；packet_count 不变 |
| FC 0x03/0x04 读寄存器 | 8 | **改写** | 同上 |
| FC 0x05/0x06 写单 | 11 | **改写** | 同上 |
| FC 0x07/0x08 状态/诊断 | 9 | **改写** | 同上 |
| FC 0x0B/0x0C 事件 | 4 | **改写** | 同上 |
| FC 0x0F/0x10 写多 | 7 | **改写** | 同上 |
| FC 0x11 从站 ID | 2 | **改写** | 同上 |
| FC 0x14/0x15 文件记录 | 6 | **改写** | 同上 |
| FC 0x16 掩码写 | 4 | **改写** | 同上 |
| FC 0x17 读写多 | 9 | **改写** | 同上 |
| FC 0x18 FIFO | 7 | **改写** | 同上 |
| FC 0x2B MEI | 11 | **改写** | 同上 |
| 异常响应 | 9 | **改写** | 同上 |
| 广播语义 | 3 | **改写** | 同上 |
| TID 序列 | 8 | **改写** | 同上 |
| 多流/multi | 20 | **改写 + 裁定** | §5.4 三选一（转 `flow_control` / 改负例 / 移出） |
| wire 集成 | 9 | **改写** | 同基线动作；帧 hex 不变 |
| 默认/事务形态 | 5 | **改写** | 同上；`transactions-empty-array` 保留空数组语义 |
| 地址/端口/UnitID | 7 | **改写** | 同上；地址→`layers[ip]`、端口→`layers[tcp]` |
| 顺序/方向 | 2 | **改写** | 同上 |
| 豁免路径 | 1 | **改写** | 同上 |
| 独立性（响应/请求） | 1 | **改写** | 同上 |
| 负例（Validate） | 62 | **改写 + 修纯净性** | 顶层键删 + §8.2 #5 三类缺陷修齐 |

**合计 213** ✓（机读复算：23 行逐行求和 = 213；**分区口径**：每例恰属一行——负例 62 例整体归「负例」行，多流行按真实判据 `master_count>1 ∪ flow_count>1` 的 19 正例 + `modbus-master1-flow1-baseline`〔`mc=fc=1`，按命名归本域〕= 20，**非**按 id 子串 `multi` 机械计数〔该法只得 9，且多数是 FC 名如 `fc0b-multi-tx`〕）。逐条裁定：**0 作废，0 等价覆盖**（全部待改写 + **A′ 可建 5 例**〔`modbus_neg_presence_shape` 不计——G-MODBUS-3 未闭前建了假绿〕+ 20 例多流待裁定）。**无"作废不注原因"**。**本车道执行数 = 0**（缺口登记，非改写）。

## 9. 修订记录

- v1.0.0（2026-09-28）：P-PIPE #94 文档轨 P1–P3。旧稿 13-* 的 213 ID / T 编号 / 锚词 / fixture 全量继承（思路参考不搬码）；新增形状基线机读实测（§1）、**可执行性 MCP 实测（§1，三形状全拒）**、P3 固定动作（§6）、执行建议（§7）、存量缺口登记表（§8：7 项阻断缺口 + 213 例逐域去向，**本车道不改 JSON**）；主线程裁定 2026-09-28 走 (b)。自审轮次见 `/tmp/pipe/doc-lanes/modbus.md`。

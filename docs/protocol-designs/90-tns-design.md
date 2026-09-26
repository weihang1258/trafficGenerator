# TNS（Oracle Net / SQL*Net，透明网络底层）设计契约

> 版本：v1.0.0（P1–P3 文档轨产物；#90 tns）
> 日期：2026-09-27
> 车道：并发管线车道 A（文档轨）｜协议号：**90**（ledger 队列位；文件按既有命名序 `90-tns-*.md`，旧基线 `31-tns-design.md`/`31-tns-testcase.md` 保留为历史层 §7.4）
> 配套文件：`docs/protocol-designs/90-tns-testcase.md`、`trafficgen/test/protocol_pcap/cases/tns.json`（现存 **12 例**）、`trafficgen/internal/protocol/tns/`（builder/planner/layer_gen/tns_test）
> 规范基线：**无公开规范**（Oracle 未公开 TNS 线协议）→ 本契约以 ①旧基线设计文档（`31-tns-design.md` v1.0.0，2026-08-20）+ ②本仓库已落码字节（`internal/protocol/tns/builder.go`）+ ③本机 Wireshark/TShark 3.6.14 的 `tns.*` dissector 字段面（实测 **87** 字段）三源交叉为准。**TCP/IPv4/IPv6 载体**参照 RFC 9293 / RFC 8200；Oracle Net 官方文档（Database Net Services Reference / Administrator's Guide）作为业务语义出处，**线字节断言不以官方文档为准**（官方文档不公布线格式）。
> **层链唯一真相**：本契约全文示例只有纯 `layers` 形——地址只住 `ip` 层（`src`/`dst`；IPv6 地址族同住 `ip` 层，仓库无 `ipv6` 层，kerberos/ntlm/postgresql 先例）、端口只住 `tcp` 层（`src_port`/`dst_port`）、数量只走 `flow_control`；顶层只允许 `layers`/`flow_control` 家族/`output`（CORE_MEMORY §1.11–1.13）。任何顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/`tns` 子映射都判违规。**注**：本协议**存量配置今天正落在违规形上**（§12.1 实测），迁移计划见 §11 — 这是本契约与 postgresql #82（存量已是纯 layers 形）的**根本差异**。
> **注册现状（实测）**：`tns` 层**已注册**（`internal/core/layers/registry.go:632-633`，`CategoryTerminal` + `DependsOn ["tcp"]` + `FieldContract {"tcp.dst_port": "1521"}`，**无 `Fields` 块**）；`allowedProtocols["tns"]=true`（`internal/core/protocols.go:55`）；`cmd/server/main.go:163` 已空白导入 `internal/protocol/tns`（触发 `layer_gen.go:70-73` 的 generator/validator 注册）。本文**不宣称本次跑过 suite、不启动服务器**；所有"已落码/未落码"结论均标实测出处。

---

## 1. 范围、证据等级与已落码边界

### 1.1 范围

TNS（Transparent Network Substrate）是 Oracle Net / SQL*Net 的线协议外层。本契约定义其**在 TCP 载体上的生成契约**：

- **P-CONNECT**：`CONNECT → ACCEPT`（成功）／`CONNECT → REFUSE`（拒绝）／`CONNECT → REDIRECT`（重定向）三类连接控制事件。
- **P-DATA**：`DATA` 报文（TNS header + 2 字节 data flags + 不透明 TTC/SQL*Net 负载）。
- **P-MULTI**：多会话（`sessions[]`，每会话独立四元组）与多流（`flow_control.flows>1`）。

### 1.2 证据等级三档（本契约纪律）

| 档 | 可写内容 | 是否固定线字节 | 本协议实况 |
|---|---|---|---|
| ①规范原文级 | — | — | **不存在**（Oracle 未公开 TNS 线格式）。本契约不虚设此档。 |
| ②dissector 实测级 | TShark 3.6.14 `tns.*` 字段名与语义（实测 **87** 字段）、包类型字节、8 字节头布局、DATA flags 位面 | 是——可逐字节断言 | §3 全部字段表 |
| ③实现现状级 | 本仓库 `internal/protocol/tns/*` 与 `core.TNSConfig` 的已落码边界（哪些事件键被消费） | 是——作为"今日可达/不可达"判据 | §2.3 / §11 |

**档②的权威性声明（诚实边界，§4.11/§5.4 口径）**：TNS 包类型字节与头布局的唯一可复现依据是 Wireshark dissector 的枚举（`packet-tns.c` 的分类逻辑，字段名以 `tshark -G fields` 实测为准）。本契约**不声称**这些字节等于 Oracle 官方规范，只声称"TShark 3.6.14 按其解析且本仓库 builder 与之逐字节一致"。若未来获得 Oracle 官方线格式文档，须回填档①并复核档②。

### 1.3 已落码边界（实测，2026-09-27 HEAD）

- **字节原语**：`internal/protocol/tns/builder.go`（255 行）——`buildHeader`（8 字节头）/ `buildPacket` / `buildDataPacket` / `bodyForType` + 五类 body 构造函数（`connectBody` / `acceptBody` / `refuseBody` / `redirectBody`）+ `eventType` / `validNumericType` / `checkWireFault`。
- **事件面生成器**：`internal/protocol/tns/layer_gen.go`（73 行）——`TNSGenerator.Generate` 逐事件构造并 `EmitMsg`；**空配置默认化产一条 `DATA` 事件**（`layer_gen.go:26-29`，P0b-2）。
- **校验器**：`Planner.Validate`（`planner.go:17-65`），经 `layer_gen.go:72` 的 `RegisterLayerValidator("tns", ...)` 接入链路径。
- **legacy planner（关键现状）**：`Planner.Plan`（`planner.go:67-155`，含自产 SYN/SYN-ACK/ACK 握手与 FIN 四包包挥手）**没有任何非测试调用方**——全仓库 `grep -rn "protocol/tns"` 非测试命中**只有** `cmd/server/main.go:163` 的空白导入（`_`），链路径只走 `layer_gen.go` 的 `TNSGenerator`。`Plan()` 由 `tns_test.go` 的 7 个测试直调保留为回归面，**不构成线上能力**。本契约把它的能力逐项列为 A′/B′（§11.2 / testcase §8.2）。

**存量用例基线**：`cases/tns.json` **12 例**（7 正 + 5 负），逐例审计去向落 testcase §8.3。

---

## 2. 推荐配置、层链与事件形状

### 2.1 层链

唯一合法链形：**`[ip, tcp, tns]`**（IPv6 地址族同住 `ip` 层，不新增层）。`tns` 是**终结层**（`CategoryTerminal`，`registry.go:632`），`DependsOn ["tcp"]`，无 `TransformEvents`、无 `OptionalOn`、无 `TransportOn`、无 `InnerRequired`。

**目标形状 spec_json（纯 layers，顶层仅 `layers` + `flow_control`）**：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.90", "dst": "198.51.100.90"}},
    {"tcp": {"src_port": 41234}},
    {"tns": {
      "events": [
        {"type": "CONNECT", "direction": "c2s", "payload_profile": "connect_basic"},
        {"type": "ACCEPT",  "direction": "s2c", "payload_profile": "accept_basic"},
        {"type": "DATA",    "direction": "c2s", "payload_profile": "ttc_connect", "data_flags": 0},
        {"type": "DATA",    "direction": "s2c", "payload_profile": "ttc_accept",  "data_flags": 0}
      ]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

> **`tcp.dst_port` 不写**：由 `tns` 层 `FieldContract {"tcp.dst_port": "1521"}`（`registry.go:633`）经 `chain_planner.go:597-616` 的**通用 FieldContract 端口块**补齐（`tns` 不在 DstPort switch 的 case 名单里，也不在 `validateBaseDstPortHandled` 名单里 → 走通用块；`chain_planner.go:599`/`:1155` 的注释原文点名 `tns`）。
> **目标形状今日跑不通（CORE_MEMORY §1.9 强制标注）**：`tns` 层 schema **无 `Fields` 块**（`registry.go:632-633`；生成表 `schemas/v1/generated/layers.generated.json:3808-3815` 实测 `"fields": {}`），而 `translateTerminalConfig`（`chain_planner_translate.go:1076` `if len(s.Fields) == 0 { return }` + 无 `case "tns"`）不翻译 `tns` 层 config → **层内 `events` 今日既被 V9 拒（`complete.go:292-294` `unknown field`）也不会被消费**。迁移动作 = G-TNS-1（§14），今日可用形状 = §2.1a。

### 2.1a 今日可用形状（过渡态，**违规形，必须迁移**）

存量 12 例的实测形状：`{"layers":[{"tcp":{}},{"tns":{}}], "src_ip":…, "dst_ip":…, "src_port":…, "dst_port":1521, "tns":{…}}`。

| 层/键 | 位置 | 是否被消费 | 证据 |
|---|---|---|---|
| 协议配置（`events`/`sessions`/`checksum_mode`/`wire_fault`） | **顶层 `tns` 子映射** | ✅ 是 | `strategy_convert.go:1429-1431`（flat 路径 `parseSubconfigJSON[*TNSConfig]`） |
| `tns` 层 config | `layers[2].tns` | ❌ **空 map**（存量写 `{}`） | `TranslateTerminalConfig` 无 tns 分支 + `len(s.Fields)==0` 早退 |
| 地址/端口 | **顶层** `src_ip`/`dst_ip`/`src_port`/`dst_port` | ✅ 是（`mapToFlowSpec` 缺省读） | `strategy_convert.go:324-341` |

**判定**：该形同时违反 §1.4（`layers` 与顶层四元组混用）与 §1.11（顶层 `tns` 业务子映射）。**P4 必须整体迁到 §2.1 目标形**；迁移在库存量时须先确认 `checkLayerFlatConflict`（`schema/semantic.go:183-191`）与 `CheckProtoFlat`（`strategy_convert.go:8322+`，五键判死）对**这 12 条用例的当前提交结果**（G-TNS-5）。

### 2.2 层内配置键（目标形 5 键；**今日 = 0 键**）

| 键 | 类型 | 默认 | 语义 | 今日状态 |
|---|---|---|---|---|
| `events` | list | `[]` | 有序应用事件序列（单会话） | ❌ 未注册（须补 `registry.go` `Fields`） |
| `sessions` | list | `[]` | 多会话展开：每项 `{src_port, events[]}` | ❌ 未注册 |
| `checksum_mode` | string | `"disabled"` | v1 只允许 `disabled`（生成 checksum=0） | ❌ 未注册 |
| `reconnect` | bool | `false` | REDIRECT/失败后是否新建连接；v1 不自动重连 | ❌ **死字段**（全仓库零读取，`types.go:1226` 唯一命中为定义本身）→ **P4 删键** |
| `wire_fault` | object | nil | 负例故障注入口，**不是线上字段** | ❌ 未注册 |

**层字段范围校验（V9）**：白名单制——5 键之外的任何键 → `layers: layer "tns": unknown field %q`（`complete.go:292-294`）。**今日 `Fields` 为空 ⇒ 任何非空 `tns` 层 config 都被拒**（这是 §2.1 目标形状不通的第二处根因）。**事件内键（`type`/`direction`/`payload_profile`/`data_flags`）不受 registry 约束**（`events` 是 `list` 型无界字段，`complete.go:296-300` 对 `Min==0 && Max==0` 直接 skip）。

### 2.3 事件形状与「死字段」清单（P4 必办，实测）

`core.TNSEvent`（`types.go:1207-1213`）**仅 4 个 JSON 键**，全部被消费：

| 事件键 | 被消费？ | 消费点 |
|---|---|---|
| `type` | ✅ | `builder.go:172` `eventType`（string 5 值 / 数值 5 值） |
| `direction` | ✅ | `planner.go:159-166` `evUp`（`c2s`/`up` → up，`s2c`/`down`/其它 → down） |
| `payload_profile` | ❌ **死字段（wire 面）** | **零读取**：`builder.go` 全文无 `.PayloadProfile`；body 由 `type` 决定（`bodyForType:88-104`）。存量的 `connect_basic`/`ttc_connect` 等**全部不生效**——`TestBuildPacketConnect`（`tns_test.go:161-164`）正是断言"body 不含 profile 名字面"→ **G-TNS-4**。P4 处置二选一：**删除该键**（推荐，§1.12 口径）或给它真实语义（版本化 body 模板注册表）。 |
| `data_flags` | ✅ 仅 `DATA` | `builder.go:66-71`（非 0 → 拒）；**非 DATA 事件上写 `data_flags` = 静默无效**（`buildPacket` 只在 `pt == TypeData` 分支读它）→ G-TNS-7 |

`core.TNSConfig`（`types.go:1221-1227`）5 键：`events` / `sessions` / `checksum_mode` / `reconnect`（**死**）/ `wire_fault`。

---

## 3. 线格式权威（逐字段，P4 builder 硬对照表）

### 3.1 8 字节公共头（档②：dissector 实测字段名）

| 偏移 | 大小 | 字段 | 本仓库常量 | TShark 字段 | 断言通道 |
|---:|---:|---|---|---|---|
| 0 | 2 | `length` | 包总长（含头），`8..65535` 大端 | `tns.length` (FT_UINT16, BASE_DEC) | 字段 ✅ |
| 2 | 2 | `packet_checksum` | `0x0000`（v1 disabled） | `tns.packet_checksum` (FT_UINT16, BASE_HEX) | 字段 ✅ |
| 4 | 1 | `type` | 见 §3.2 | `tns.type` (FT_UINT8, BASE_DEC) | 字段 ✅ |
| 5 | 1 | `reserved` | `0x00` 恒 | `tns.reserved_byte` (FT_BYTES) | 字段 ✅（值形 `"00"`） |
| 6 | 2 | `header_checksum` | `0x0000`（v1 disabled） | `tns.header_checksum` (FT_UINT16, BASE_HEX) | 字段 ✅ |

实现：`builder.go:45-53`（`binary.BigEndian.PutUint16` 写 0/2、6/8；`b[4]=type`；`b[5]=0x00`）。**声明值形态**（tshark -G fields 实测）：`tns.type` = BASE_DEC（十进制字符串，"1"/"2"/"6"）、`tns.length` = BASE_DEC、两个 checksum = BASE_HEX（`"0x0000"`）、`tns.reserved_byte` = FT_BYTES（`"00"`）。**JSON 断言必须按此形态写**，不许混用（存量 12 例实测已按此形态，正确）。

**长度公式（可复算）**：

```text
非 DATA：length = 8 + len(body)
DATA   ：length = 8 + 2 + len(payload)          （builder.go:70）
TCP payload 字节数 ≡ length                     （两者必须相等；见 G-TNS-3）
```

**实测锚（本仓库 builder + 单测双列）**：CONNECT body = **98** 字节 → `length = 106`（`0x006a`）；ACCEPT body = 20 → `length = 28`（`0x001c`）；REFUSE body = 8 → `length = 16`；REDIRECT body = 4 → `length = 12`；空负载 DATA → `length = 10`（`0x000a`）。逐值出处：`tns_test.go:151/158`（106）、`:173`（28）、`:195`（16）、`:212`（12）、`:228`（10）。

### 3.2 包类型字节表（档②：dissector 枚举 + 本仓库只实现 5 个）

| 数值 | 名称 | 方向/用途 | 本仓库实现 | 用例 |
|---:|---|---|---|---|
| `0x01` | CONNECT | 客户端建立 TNS 连接并携带连接数据 | ✅ `builder.go:126-138` | #1/#5/#6/#7 |
| `0x02` | ACCEPT | 服务端接受连接并返回协商数据 | ✅ `builder.go:143-150` | #1/#5/#6/#7 |
| `0x03` | ACK | 确认/控制 | ❌ 未实现 | — |
| `0x04` | REFUSE | 服务端拒绝连接 | ✅ `builder.go:154-160` | #2 |
| `0x05` | REDIRECT | 服务端要求客户端改连另一地址 | ✅ `builder.go:164-166` | #3 |
| `0x06` | DATA | TTC/SQL*Net 数据 | ✅ `builder.go:57-79/205-214` | #1/#4/#7 |
| `0x07` | NULL | 空控制包 | ❌ 未实现 | — |
| `0x09` | ABORT | 异常中止 | ❌ 未实现 | — |
| `0x0b` | RESEND | 重发请求 | ❌ 未实现 | — |
| `0x0c` | MARKER | 标记包 | ❌ 未实现 | — |
| `0x0d` | ATTENTION | 注意事件 | ❌ 未实现 | — |
| `0x0e` | CONTROL | 控制包 | ❌ 未实现 | — |

**字节面的 dissector 佐证（实测字段存在性）**：`tns.marker.type` / `tns.marker.databyte`（MARKER）、`tns.control.data`（CONTROL）、`tns.abort_data`（ABORT）在 `tshark -G fields` 中**存在** → 这些类型是 dissector 认得的真实类型（非本仓库臆造），但本仓库生成器**不支持**（`builder.go:24-39` `typeCode` 只映射 5 个；`validNumericType:195-202` 同）。未实现类型 = **B′/A′ 缺口 G-TNS-2**，不作为今日用例。

> **`payload_profile` 不上 wire（§3.1 旧基线纪律延续）**：profile 名**绝不**写入线字节。`builder.go:126-138` 的 CONNECT body 是固定的 `connect_common` 结构 + TNSPING 风格描述串 `(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=test)))`，与 profile 值无关。

### 3.3 五类 body 的逐字节结构（P4 对照表，实测自 `builder.go`）

**CONNECT / ACCEPT 共享前缀 `connectCommonVOO()`（16 字节，`builder.go:110-121`）**：

| 偏移（body 内） | 值 | 字段 | TShark 字段 |
|---:|---|---|---|
| 0-1 | `0x0136` | version | `tns.version` |
| 2-3 | `0x0136` | compat_version | `tns.compat_version` |
| 4-5 | `0x0821` | service_options | `tns.service_options` + 10 个 `tns.so_flag.*` |
| 6-7 | `0x2000` | sdu_size | `tns.sdu_size` |
| 8-9 | `0x2000` | max_tdu_size | `tns.max_tdu_size` |
| 10-11 | `0x0300`（CONNECT）／`0x0736`（ACCEPT，`builder.go:145-146` 覆写） | nt_proto_characteristics | `tns.nt_proto_characteristics` + 16 个 `tns.ntp_flag.*` |
| 12-13 | `0x0000` | line_turnaround | `tns.line_turnaround` |
| 14-15 | `0x4001` | value_of_one | `tns.value_of_one` |

**CONNECT 续段（`:126-138`）**：`connect_data_length`(2) = 48 / `connect_data_offset`(2)=0 / `connect_data_max`(2)=48 / `flags0`(2)=0 / `flags1`(2)=0 / `trace_cf1`(8)=0 / `trace_cf2`(8)=0 / `trace_cid`(8)=0 / `connect_data`(48) = `(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=test)))`。body 总长 = 16+10+24+48 = **98**。对应字段：`tns.connect_data_length` / `tns.connect_data_offset` / `tns.connect_data_max` / `tns.connect_flags0` / `tns.connect_flags1` / `tns.connect_data`。

**ACCEPT 续段（`:143-150`）**：`accept_data_length`(2)=0 / `accept_data_offset`(2)=0。body 总长 = 16+4 = **20**。字段：`tns.accept_data_length` / `tns.accept_data_offset`。

**REFUSE（`:154-160`）**：`refuse_reason_user`(1)=0 / `refuse_reason_system`(1)=0 / `refuse_data_length`(2)=0 / pad(2)=0 / pad(2)=0。body = **8**。字段：`tns.refuse_data_length` / `tns.refuse_data`。

**REDIRECT（`:164-166`）**：`redirect_data_length`(2)=0 + pad(2)。body = **4**。字段：`tns.redirect_data_length` / `tns.redirect_data`。

**DATA（`:205-214`）**：`data_flags`(2) + 不透明负载（当前恒 0 字节）。

> **诚实边界（旧基线纪律延续）**：`connect_common` 的常量值（`0x0136`/`0x0821`/`0x2000`/`0x4001` 等）是**本仓库选定的固定测试值**，不是"Oracle 某版本的协商结果"。它们的唯一断言语义是"TShark 能解析且不报 `Malformed`"。**不许**在用例里把 version/service_options 的值断言成"Oracle 版本事实"。

### 3.4 DATA flags（`tns.data_flag`）

`DATA` 负载结构：`TNS header (8B) | data_flags (2B, 大端) | TTC/SQL*Net bytes (N)`。

**v1 唯一合法值 = `0x0000`**（`builder.go:66-71`；`planner.go:53-57` validator 同判）。TShark 暴露 11 个位面字段（`tns.data_flag.send` / `.rc` / `.c` / `.reserved` / `.more` / `.eof` / `.dic` / `.rts` / `.sntt` + `tns.data_id` / `tns.data_length`）——**位语义存在但本契约不启用**（无公开规范依据，§5.4）。非零 flags → 拒（锚词 `data_flags`，E-05）。

### 3.5 dissector 能力边界（实测，写死供 P4 参照）

| 项 | 实测结果 |
|---|---|
| `tns.*` 字段总数 | **87**（口径 `tshark -G fields \| awk -F'\t' '$3 ~ /^tns[.]/' \| wc -l`） |
| TShark 版本 | 3.6.14（Git commit 83f40263b97e） |
| 端口启发式 | 标准 1521 端口下 CONNECT 报文可被自动识别（存量 `tns_connect_accept` 等 pcap 已解析出 `tns.type`，见 §8.1）；**非标准端口**须 `decode_as`（G-TNS-6） |
| 存量用例 `decode_as` | **0/12 例**（全部走 1521 端口启发式） |

---

## 4. 会话状态机与自动派生（设计权威）

### 4.1 状态集合（本契约定义，依据 §3 报文面 + 旧基线 §3/§4）

```text
Init ──CONNECT──▶ ConnectSent ──ACCEPT──▶ Established ──DATA*──▶ Established
                       │                                              │
                       ├──REFUSE────▶ Refused（终态，禁 DATA）         │
                       └──REDIRECT──▶ Redirected（终态，禁 DATA）      │
                                                                      ▼
                                          （无应用层终止报文）──▶ TCP FIN 四包挥手
```

- `Init → ConnectSent`：**CONNECT 必须是首事件**（`planner.go:50-52` validator 强制方向 `c2s`/`up`）。
- `Established`：ACCEPT 后进入；此后允许 `DATA`。
- `Refused` / `Redirected`：**终态**——`REFUSE`/`REDIRECT` 后**不得再有任何事件**（旧基线 §3.3/§3.4 纪律）。
- **终止**：TNS v1 **无应用层关闭报文**（`0x07 NULL`/`0x09 ABORT` 未实现）→ 会话结束完全由 `tcp` 层挥手承担（`tcp.termination` 默认 `true`，`registry.go:71`）。

### 4.2 非法转移（当前守卫 vs 缺口）

| 非法转移 | 今日守卫？ | 触发点 / 缺口 |
|---|---|---|
| 首事件非 `c2s`/`up` | ✅ 拒 | `planner.go:50-52`（锚词 `first event must be`） |
| 未知 `type`（字符串或数值） | ✅ 拒 | `builder.go:172-202`（锚词 `unknown packet type`） |
| `data_flags != 0` | ✅ 拒 | `planner.go:53-57`（锚词 `data_flags must be 0`） |
| `checksum_mode` 非 `disabled` | ✅ 拒 | `planner.go:30-32`（锚词 `unsupported checksum mode`） |
| `events` 与 `sessions` 并存 | ✅ 拒 | `planner.go:27-29`（锚词 `mutually exclusive`） |
| `events` 空且 `sessions` 空 | ✅ 拒 | `planner.go:24-26`（锚词 `at least one event`） |
| `sessions[i].events` 空 | ✅ 拒 | `planner.go:39-41`（锚词 `empty events`） |
| **`ACCEPT` 前出现 `DATA`**（状态机跳步） | ❌ **无守卫** | → G-TNS-8 |
| **`REFUSE`/`REDIRECT` 后仍有事件** | ❌ **无守卫** | → G-TNS-8 |
| **`REFUSE`/`REDIRECT`/`ACCEPT` 出现在 `c2s` 方向** | ❌ **无守卫**（方向只被 `evUp` 二值化，不校验语义） | → G-TNS-8 |
| **`direction` 非 `c2s`/`s2c`/`up`/`down`（如 `bogus`）** | ❌ **不拒**（`evUp:159-166` 落 `default: false` = 静默当成 s2c） | → G-TNS-8（用例 #24） |
| **`sessions[1..n]` 内的事件** 未做任何校验 | ❌ **不校验**（`planner.go:37-44` 只对 `Sessions[0]` 跑事件循环） | → G-TNS-3（**后果严重**，见 §4.4） |
| 载体非 `tcp`（链夹 `udp`） | ✅ 拒 | `complete.go:446-468` 通用 carrier 门（`tns` 判 `tcpOnly`：`DependsOn` 含 `tcp` 且不含 `udp`），锚词 `carrier`（实测存量 `tns_neg_udp` 的 `error_contains: "tcp"` 亦落此文案，见 §8.2） |

### 4.3 自动派生帧（生成器自动补的内容，逐条列出）

| 派生内容 | 触发条件 | 内容 | 出处 |
|---|---|---|---|
| TCP 三次握手 | `tcp.handshake` 默认 `true` | SYN/SYN-ACK/ACK | `registry.go:70` + tcp 生成器 |
| TCP 四次挥手 | `tcp.termination` 默认 `true` | FIN-ACK/ACK/FIN-ACK/ACK | `registry.go:71` |
| 多会话新连接 | `sessions[i].src_port` 经 `MessageEvent.SrcPort` 上报，tcp 层见端口变化即挥旧握新 | 每会话独立握手/挥手/序号 | `layer_gen.go:49-57` |
| 空配置默认事件 | `spec.TNS == nil` 或 `events`/`sessions` 均空 | 一条 `DATA` 事件（`{Type:"DATA"}`） | `layer_gen.go:26-29`；`planner.go:75-77` |
| 默认目的端口 | 用户未写 `tcp.dst_port` | **1521** | `registry.go:633` FieldContract + `chain_planner.go:597-616` |

> **「自动应答」不存在**：本层是**声明式脚本化回放**，不因收到 `CONNECT` 自动补 `ACCEPT`。每个方向的报文都必须在 `events[]` 里显式声明（与 protocol-doc-requirements 术语表一致，postgresql #82 §4.3 同款）。

### 4.4 【CRITICAL 现状】生成器对 `sessions[1..n]` 的**静默截断**

`TNSGenerator.Generate`（`layer_gen.go:20-59`）：`if len(cfg.Events) > 0 { … return nil }`——当 `events` 非空时处理 events；否则遍历 sessions 全部。**但当 `events` 为空、`sessions` 非空时它对每个 session 都产出事件，这一点正确**；问题在 **`Planner.Validate` 侧**：`planner.go:36-44` 把校验目标设为 `Sessions[0].Events`（`evs = cfg.Sessions[0].Events`），**`Sessions[1..n]` 的事件从不校验**。

**后果（今日可达的静默失败）**：配置 `sessions=[{events:[CONNECT]}, {events:[{type:127}]}]` → validator 只查 `Sessions[0]`（合法）→ **通过** → 生成器处理 `Sessions[1]` 时 `buildPacket` 返回 `unknown packet type 127` 错误 → `Generate` 返回 error → 该 error 经 tcp/ip 级联（`chain_planner_translate.go:598-605` 的 `lastErr` 聚合）传播为 **task error**。

> **待 P4 实测定性（不许猜）**：错误**是否真到达 task 终态**取决于框架对生成器 error 的处理（`drive` 返回值 → `Plan` → worker 预检/终态）。本契约**不预先断言**，把它列为 **G-TNS-3**，P4 用真实流程（§14）钉死；若实测"任务报 completed + 部分包"则升级为 CRITICAL 修轮项（§14.12「任务失败却报成功是同一级别的 bug」）。

---

## 5. 依赖声明与端口契约

**依赖（§5.1）**：
- 依赖 `tcp` 层（唯一载体，`DependsOn ["tcp"]`，`registry.go:632`）；依赖 `ip` 层提供地址族与 TTL（经 tcp 的 `DependsOn ["ip"]` 间接补全，`complete.go:90-110`）；
- **无 `udp` 语义**（链夹 udp 判死，`complete.go:446-468`）；
- 无外部密钥/证书依赖；无第三方服务依赖（生成器不发真实连接）。

**端口契约（§1.2/§1.3）**：`FieldContract {"tcp.dst_port": "1521"}`（`registry.go:633`）→ 由 `chain_planner.go:597-616` 的**通用契约块**写入 `spec.DstPort`（`tns` 不在 DstPort switch case 里、也不在 `validateBaseDstPortHandled` 名单里 → 走通用块；注释 `chain_planner.go:599`/`:1155` 逐字点名 `tns`）。

> **与 postgresql 的关键差异（用户显式端口的处置）**：postgresql 有 `chain_planner.go:553-595` 的**专用契约块**，用户显式写非契约端口即拒（锚词 `is not the default %d`）。**`tns` 没有专用块** → 用户显式写 `tcp.dst_port` 时走 `chain_planner.go:603-611` 的"用户显式 > FieldContract"分支：**尊重用户值，不拒**。即 **`tns` 今日无端口域校验**（G-TNS-9）。这是设计选择差异而非缺陷：TNS 的服务端口在现网确实可配（Oracle 监听器可绑任意端口）。

---

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **6.1/6.2 目标与预算**：本层为**事件驱动流式渲染**——逐事件构造一个 TNS 报文并立即 `EmitMsg`，无全量聚合、无按包增长的结构（`layer_gen.go:33-44`）；**唯一可变状态**：无（`TNSGenerator` 是零字段 struct，`layer_gen.go:12`；对比 postgresql 有 per-generator `paramIdx` 计数器）。帧长上界：非 DATA ≤ `8 + 98`（CONNECT 固定 body），DATA ≤ `10 + len(payload)`（当前 payload 恒空 → 恒 10）。**并发面**：每个 flow 一个新 generator 实例（`layer_gen.go:71` 工厂 `func() (LayerGenerator, error) { return &TNSGenerator{}, nil }`），**无共享可变状态、无需锁**。速率与队列上限由框架（Pacer / 有界队列）承担，本层不重复定义。
- **6.3 双路验收**：**pcap 路** = suite 落盘 `/tmp/mcp-pcaps/tns/`，用 tshark `tns.*` 字段 + `frames` hex 校对；**NIC 路** = `output_type=port_group` + 网口 `enp135s0f0np0` 抓包，断言 TCP/应用字段一致（记忆 `testing-interface` 指定网口）。
- **6.4 依据**：流式路径如 6.1 所述；每条流新增内存 = 一个空 generator 实例 + 当前报文字节切片（≤108B）+ TCP 层会话状态；无共享状态、无锁；限速与多 worker 总速率正确性由框架 pacer（共享桶）保证，本层不引入第二套速率语义。
- **6.5 诚实待确认**：**吞吐（包/秒、bit/秒）、并发流数、内存上限的具体数字待 P4 基准实测后钉**，本文不写承诺数字（§6.5「没有代码路径或基准数据支撑的性能数字只能标为待确认」）。
- **6.6 六类场景**：基线（单会话 CONNECT→ACCEPT）/ 目标规模（多会话 `sessions[]` 2 条；多流 `flows>1`）/ 压力上限（长 `connect_data` / 大 DATA 负载，逼近 MSS 分段——**今日 DATA 负载恒 0**，压力面需 P4 先开负载配置）/ 长时间运行（同连接多轮 DATA 事件）/ 并发交错（多流 × 多会话）/ 背压（下游消费慢时队列积压行为）。前五类 P4/P5 落用例，背压类沿用框架既有测试面。
- **6.7 断言口径**：断言**实际输出值**（`tns.type` / `tns.length` / `tns.packet_checksum` / `tns.header_checksum` / `tns.reserved_byte` / `tns.data_flag` + `tcp.srcport`/`tcp.dstport`/`tcp.flags` + `frames` hex），**不许只断言"任务没失败"**；负例断言锚词。
- **6.8 失败边界**：功能正确但超预算视为设计不合格——本层的预算面即"单 flow 常驻内存 O(1)、零共享状态"，若 P4 引入按流缓存报文数组或 per-flow 计数器即违反本条。

---

## 7. 错误处理与错误传播

- 所有校验错误必须在 **planner/validator 边界**抛出并传播为 **task error**，**不许**产出成功 PCAP、`completed + 0 packet`、或只剩 TCP 外壳的假成功（CORE_MEMORY §14.11/§14.12）。
- 负例执行期 `expect` 键集合**严格**为 `{"expect_error", "error_contains"}`（protocol-doc-requirements §7「负例纯净性」；存量 5 负例实测**已纯净**）。
- **`wire_fault` 的当前实现边界（实测）**：`checkWireFault`（`builder.go:237-255`）只接受**对象**形 `{"kind": ..., "value": ...}`，三个 kind：
  - `length` → `tns: wire fault: packet length %v below minimum 8`（锚词 `length`）
  - `packet_checksum` → `tns: wire fault: packet_checksum %v conflicts with disabled checksum mode`（锚词 `checksum`）
  - `data_flags` → `tns: wire fault: nonzero data_flags %v rejected in v1`（锚词 `data_flags`）
  - 其它 kind → `unknown kind %q`；JSON 非法 → `invalid wire_fault: %v`。
  - **注意**：`wire_fault` 的**字节注入动作在生成器侧未接线**（`layer_gen.go` 不读 `wire_fault`；只有 `Planner.Validate:33-35` 读）——故障在 validator 期就被拒绝，因此负例走"配置被拒"通道而非"产出畸形包"通道。这是**正确也是唯一可行**的通道（§14.11 要求坏配置必须被拒）。
- 三档错误面：①**链级**（`ValidateLayers`/`ChainPlanner.ValidateSpec`）——未知层、`unknown field`（V9）、carrier 非 tcp；②**配置级**（`Planner.Validate`）——type/direction 首事件/data_flags/checksum_mode/events-sessions 互斥/IP 合法性/wire_fault；③**生成期**（`buildPacket` 的 `unknown packet type` / `data_flags must be 0`）——**理论不可达**（②已白名单化），**唯一可达路径是 `sessions[1..n]` 未校验**（§4.4 / G-TNS-3）。

---

## 8. 存量审计口径

`cases/tns.json` **12 例**（7 正 + 5 负），逐例审计去向落 testcase §8.3。三条实测事实先行：

1. **12/12 例是"层链 + 顶层扁平"混合形**：逐例顶层键 = `{layers, src_ip, dst_ip, src_port(11/12), dst_port, tns}`（`tns_multi_session`/`tns_neg_udp` 无 `src_port`）。链形 `[tcp, tns]` ×11 + `[udp, tns]` ×1（`tns_neg_udp`，刻意坏配置）。**非负例顶层键 ≠ 0** —— 这是本协议与 postgresql #82（存量已纯 layers 形、非负例顶层键 = 0）的**根本差异**，也是本契约最大的迁移面（G-TNS-1/G-TNS-5）。
2. **7/7 正例都有完整 `expect`**：`packet_count` + `has_handshake: true` + `terminates: true` + `fields`（1-22 条）+ `frames`（1-5 条）；5/5 负例 `expect` 键集严格 = `{expect_error, error_contains}`（纯净）。
3. **0/12 例有 `decode_as`**：全部依赖 1521 端口启发式（dissector 实测可用）。

---

## 9. 用例集合摘要（ID 权威在 testcase §2）

**合计 26 个语义 ID = 18 正 + 8 负**（其中存量 12 例改写后计入，14 例为新增或 A′ 待落）。分布：

- 正例 18：连接控制 4（#1–#4）/ 数据与 flags 4（#5–#8）/ 多会话与多流 4（#9–#12）/ 头部与地址族 4（#13–#16，含 IPv4/IPv6 对称）/ 动态与输出路 2（#17–#18）。
- 负例 8：载体 1（#21）/ 类型与形状 2（#22–#23）/ 方向与状态机 2（#24–#25，A′ 待落）/ 长度·校验和·flags 3（#26–#28）。

逐 ID、逐 `packet_count`、逐断言见 testcase §2–§4。

---

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> **口径调整声明（本协议特有）**：§4.12–4.15 要求"规范原文 / 现网行为 / 开源实现"三路对照。TNS **无公开规范** → 第一路**缺位**，由"dissector 实测 + 本仓库已落码字节"两路顶上，并**全程标注档②属性**（§1.2）。这不满足 §4.19 的"已实现 / 明确不支持 / 不适用"之外的第四态，本契约如实登记为 **G-TNS-10（规范面缺位）**，不冒充"已查规范"。
> 条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号，**不留白**。

### 10.1 八项规范矩阵

| # | 要求面（本契约节 + 档②出处） | 业务场景 | 代码现状（实测） | 缺口 |
|---|---|---|---|---|
| 1 | **连接模型**：单 TCP 连接承载 CONNECT→ACCEPT→DATA*；无控制/数据分离；客户端主动建连（旧基线 §3/§5.1；`DependsOn ["tcp"]`） | Oracle 客户端（sqlplus/JDBC/OCI）连监听器 | ✅ registry 已注册（`registry.go:632`）；✅ 生成器事件驱动（`layer_gen.go:20-59`）；✅ 多会话经 `sessions[].src_port` 复用同一 TCP 层多连接（`layer_gen.go:49-57` + tcp 层端口变化挥旧握新） | 无（A′ 已覆盖连通性） |
| 2 | **命令/消息表**：12 个类型字节（§3.2 全枚举） | 全报文族覆盖 | ⚠️ **已实现 5 个**（CONNECT/ACCEPT/REFUSE/REDIRECT/DATA，`builder.go:24-39`）；❌ **未实现 7 个**：ACK/NULL/ABORT/RESEND/MARKER/ATTENTION/CONTROL | 缺口 → **B′ G-TNS-2**（字节语义仅 dissector 单源，无二次依据；见 §10.5） |
| 3 | **状态机**：Init→ConnectSent→Established→(Refused/Redirected 终态)→TCP 挥手（§4.1） | 客户端乱序发包（DATA 先于 ACCEPT）、REFUSE 后继续发 | ⚠️ **仅 7 条守卫**（§4.2 上表）；❌ 跳步/终态后事件/方向语义/`direction` 枚举值 **无守卫** | 缺口 → **A′ G-TNS-8**（P4 补守卫 + 逐条负例 #24/#25） |
| 4 | **字段表**：8 字节头全部大端；`length` 含自身；DATA flags 2 字节大端（§3.1/§3.4） | 跨实现互操作（TShark / Oracle 客户端） | ✅ 大端（`builder.go:217-219` `appendU16` 用 `byte(v>>8), byte(v)`）；✅ `length = 8 + body` 可复算（§3.1 实测锚五值）；✅ DATA `length = 8+2+payload` | 无 |
| 5 | **错误处理**：配置级拒绝 + task error 传播（§7） | 坏配置提交、`sessions[1..n]` 坏事件 | ⚠️ 7 类守卫齐（§4.2）但 **`sessions[1..n]` 不校验**（`planner.go:37-44`）；⚠️ `wire_fault` 只在 validator 期拒（字节注入未接线） | 缺口 → **G-TNS-3（P4 实测定性，潜在 CRITICAL）** |
| 6 | **超时与活性**：TNS 协议层**无 keepalive/超时/重传语义**——由 TCP 承担；会话空闲不断连（Oracle 的 `SQLNET.EXPIRE_TIME`/`INBOUND_CONNECT_TIMEOUT` 是**监听器配置项**，非线协议特性） | 连接池长连接空闲复用 | ✅ 协议层无自有定时器（生成器不含 sleep/wait）；✅ TCP keepalive 由 `tcp` 层握手机制承担 | **不适用**（显式声明：协议无此语义，不硬凑用例；长保活用例由"同连接多轮 DATA"承载 #18） |
| 7 | **NAT/代理/重定向**：TNS **无应用层 NAT 遍历**（无 PORT/PASV 类衍生连接）；`REDIRECT`（0x05）是"服务端要求客户端改连另一地址"——**但 v1 不自动重连**（`reconnect` 是死字段） | Oracle Connection Manager (CMAN)、RAC SCAN 重定向 | ⚠️ `REDIRECT` 只产一个包、**不改连**（`builder.go:164-166` 只写 4 字节空 body，重定向地址编码未实现）；❌ 无第二连接 | **A′ G-TNS-11**（重定向地址编码 + `reconnect` 语义，需 `sessions[]` 关联建模）；**今日 `reconnect` 判死字段**（§2.2） |
| 8 | **版本/方言**：**无版本协商机制**（TNS 头的 `version`/`compat_version` 是 CONNECT body 内的固定测试值，非协商字段）；方言面 = 载体地址族（IPv4/IPv6） | Oracle 11g/19c/23c 并存 | ✅ 地址族双面已可生成（`L3Base`/`EtherTypeFor`，IPv4 offset 54 / IPv6 offset 74）；⚠️ body 常量恒 `0x0136`（**不断言为版本事实**，§3.3 诚实边界） | **不适用**（协议无版本协商面）；版本差异载体面 → 用例 #15/#16 |

### 10.2 子表①：操作序列矩阵（逐格已覆/缺失/不适用）

> **适配声明**：本协议无"响应码"概念（§4.22 原型是请求命令×响应码）。等价物 = **事件类型 × 会话位置**（§4.1 状态机），并叠加**方向**维度（`REFUSE`/`REDIRECT`/`ACCEPT` 语义上只可能由服务端发出，但生成器不校验方向——见 §4.2 缺口）。
> 行 = 12 个类型字节；列 = 5 个会话位置面。

| 类型 \ 位置 | Init→ConnectSent | ConnectSent→Established | Established（数据段） | Refused/Redirected（终态） | TCP 挥手后 |
|---|---|---|---|---|---|
| `0x01` CONNECT | 已覆 #1/#2/#3/#5 | 不适用（不可重发） | 不适用 | 不适用 | 缺口→负例 #25（A′） |
| `0x02` ACCEPT | 不适用 | 已覆 #1/#5/#6/#7 | 不适用 | 不适用 | 缺口→负例 #25（A′） |
| `0x03` ACK | 缺口→B′ G-TNS-2 | 缺口→B′ | 缺口→B′ | 缺口→B′ | 缺口→B′ |
| `0x04` REFUSE | 不适用 | 已覆 #2 | **缺口→负例 #25**（REFUSE 后禁 DATA） | 不适用 | 缺口→负例 #25 |
| `0x05` REDIRECT | 不适用 | 已覆 #3 | **缺口→负例 #25** | 不适用 | 缺口→负例 #25 |
| `0x06` DATA | **缺口→负例 #25**（跳步） | **缺口→负例 #25**（ACCEPT 前发 DATA） | 已覆 #1/#4/#5/#6/#7/#8 | 缺口→负例 #25 | 缺口→负例 #25 |
| `0x07` NULL | 缺口→B′ G-TNS-2 | 缺口→B′ | 缺口→B′ | 缺口→B′ | 缺口→B′ |
| `0x09` ABORT | 不适用 | 缺口→B′ G-TNS-2 | 缺口→B′ | 缺口→B′ | 不适用 |
| `0x0b` RESEND | 缺口→B′ G-TNS-2 | 缺口→B′ | 缺口→B′ | 缺口→B′ | 不适用 |
| `0x0c` MARKER | 不适用 | 缺口→B′ G-TNS-2 | 缺口→B′ | 缺口→B′ | 缺口→B′ |
| `0x0d` ATTENTION | 不适用 | 缺口→B′ G-TNS-2 | 缺口→B′ | 缺口→B′ | 缺口→B′ |
| `0x0e` CONTROL | 缺口→B′ G-TNS-2 | 缺口→B′ | 缺口→B′ | 缺口→B′ | 缺口→B′ |

**逐格机械重数（可复核）**：表体 **12 行 × 5 列 = 60 格**，三类：
- **已覆 8 格**（#1–#8 的落点，含"多例共享格"）；
- **不适用 22 格**（协议定义上不可能出现的组合——如 CONNECT 不出现在 Established 之后、ACCEPT 不出现在 Init）；
- **缺口 30 格**：**缺口→A′/负例通道 11 格**（#25 的 8 格 + #24 面），**缺口→B′ 通道 19 格**（7 个未实现类型 × 各自可达位置）。

8 + 22 + 30 = 60 ✓ 无空格。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

| # | 变体维度 | 形态 | 对应用例 | 备注（实测锚） |
|---:|---|---|---|---|
| 1 | 地址族 | IPv4 / IPv6（同住 `ip` 层） | #15 / #16 | IPv4 头起点 54 = 14+20+20；IPv6 起点 74 = 14+40+20；二者 TNS 字节**完全相同**（`L3Base` 只换 L3） |
| 2 | 事件类型 | CONNECT/ACCEPT/REFUSE/REDIRECT/DATA（5） | #1–#8 | `builder.go:24-39` |
| 3 | 事件类型承载形 | 字符串（`"CONNECT"`）×5 / 数值（1/2/4/5/6）×5 | #22 | `eventType` 双形（`builder.go:172-191`）；**大小写敏感**（`"connect"` 拒，`tns_test.go:41`） |
| 4 | 方向 | `c2s`/`up`（上）与 `s2c`/`down`（下）；空 → 上 | 全正例 | `evUp`（`planner.go:159-166`）；**非法值静默落 s2c**（G-TNS-8） |
| 5 | 会话结构 | `events[]`（单流）/ `sessions[]`（多连接，各带 `src_port`） | #1–#8 / #9 | 二选一互斥（`planner.go:27-29`） |
| 6 | 多流 | `flow_control.flows=N` | #10 | 逐流四元组动态（§12） |
| 7 | 端口 | 默认 1521（FieldContract）/ 显式非默认（**今日放行**） | #14 | `registry.go:633`；无域校验（G-TNS-9） |
| 8 | DATA flags | `0x0000`（唯一合法） | #4/#5/#8 | `builder.go:66-71`；非零拒 #28 |
| 9 | DATA 负载长度 | 0（今日唯一） | #5 | `builder.go:99` `bodyForType(TypeData) → nil, nil` |
| 10 | body 常量 | CONNECT/ACCEPT 的 `connect_common` 固定值；ACCEPT 与 CONNECT 差 1 字段（`nt_proto_characteristics` `0x0736` vs `0x0300`） | #1/#13 | `builder.go:145-146` |
| 11 | `length` 取值面 | 10 / 12 / 16 / 28 / 106（五类固定 body） | #13 | `tns_test.go` 逐值实测 |
| 12 | checksum 模式 | `disabled`（生成 0）/ 其它（拒） | #13 / 负例 #26 | `planner.go:30-32` |
| 13 | 校验和字段 | `packet_checksum`=0 + `header_checksum`=0 | #13 | `builder.go:45-53` |
| 14 | `reserved` 字节 | 恒 `0x00` | #13 | `builder.go:50` |
| 15 | `payload_profile` | 任意字符串（**不生效**） | 存量 12 例全带 | 死字段 G-TNS-4 |
| 16 | 空配置 | `tns: {}` / `tns` 缺席 / 层 config 空 | #12 | `layer_gen.go:26-29` 默认化产一条 DATA |
| 17 | 事件数 | 1 / 2 / 4 / 6 / 2×2（多会话） | #1/#2/#3/#4/#9 | `packet_count = 3 + N + 4` |
| 18 | MSS 分段 | 大 body 跨 segment | **不适用（今日）** | body 恒 ≤98B < MSS 1460；开启 DATA 负载后需补（G-TNS-12） |
| 19 | 输出路 | pcap / NIC（port_group） | #18 | 双路验收 §6.3 |
| 20 | `decode_as` | 标准 1521 免声明 | 全例 | 实测 0/12 例带；非标端口面 G-TNS-6 |
| 21 | `wire_fault` | `length` / `packet_checksum` / `data_flags` / 未知 kind / 非对象形 | 负例 #26–#28 | `builder.go:237-255` |
| 22 | 动态字段 | `ip`/`tcp` 四元组 × 五策略 | #17 | §12 |
| 23 | 死字段 | `reconnect`（配置级）/ `payload_profile`（事件级） | 负例 #23 + 存量删键 | §2.2/§2.3 |

### 10.4 关联关系专节（§3.8–3.10）：TNS 的「无派生流」边界

TNS **没有**控制流派生数据流的形态（对照 FTP 控制+数据、SIP 信令+媒体）：全部 TNS 报文复用**同一条 TCP 连接**。唯一的"跨连接"候选是 **REDIRECT**——服务端要求客户端**另建一条连接**到别的地址。但：

| 关联三件事（§3.9） | REDIRECT 的取值 |
|---|---|
| 归属哪个会话 | **不属于任何会话**——是服务端发起的"请改连"指令，v1 不产生第二连接 |
| 归属哪个事务 | 无（不携带事务标识） |
| 由哪个字段决定 | **无字段**——重定向地址的编码未实现（`builder.go:164-166` 只写 `redirect_data_length=0` + pad） |

**结论**：本协议 `driven_by` 语义**今日不适用**（无被关联流）。诚实声明：**REDIRECT 的第二连接不实现**（A′ G-TNS-11），其关联语义待 P4 与框架共同裁定（三选一：`driven_by` 扩展 / 独立 `redirect_to{host,port}` 字段 / 明确不支持）。**不许**用"同一模板连续重复发射"冒充该关联（§3.13）。

### 10.5 候选方案对比（§4.17）与三路对照（§4.12–4.15）

**三路对照（第一路缺位，如实标注）**：

① **规范原文**：**不存在**（Oracle 未公开 TNS 线格式）。替代依据 = ①旧基线设计文档 `31-tns-design.md`（本仓库内部契约，非外部规范）+ ②dissector 实测。**G-TNS-10 登记。**

② **现网行为**（产品+行为+出处）：
- **Oracle Database 客户端（sqlplus / OCI / JDBC thin）**：连监听器（默认 1521），首报文为 CONNECT（type 0x01），服务端回 ACCEPT（0x02）或 REFUSE（0x04）；认证与查询走 DATA（0x06）内的 TTC。出处：**Oracle Database Net Services Administrator's Guide**（连接概念与监听器行为章节）+ 本仓库旧基线 §3。
- **Oracle Connection Manager (CMAN)**：可下发 REDIRECT（0x05）要求客户端改连。
- **确认方式（G-TNS-13）**：本机起 Oracle XE / 连现网 Oracle 实例，用 `tshark` 抓 1521 核对 CONNECT/ACCEPT 的头字节与 TShark 解析——**当前未做**，故"现网行为"档仅到"官方文档描述的行为"级，**未到"本机抓包已确认"级**。

③ **开源实现思路**：
- **Wireshark `epan/dissectors/packet-tns.c`**（本机 TShark 3.6.14 实测 **87** 个 `tns.*` 字段，口径 `tshark -G fields | awk -F'\t' '$3 ~ /^tns[.]/' | wc -l`）：字段面覆盖头（`length`/`packet_checksum`/`header_checksum`/`type`/`reserved_byte`）+ `connect_common` 全字段（`version`/`compat_version`/`service_options` + 10 个 `so_flag.*`/`sdu_size`/`max_tdu_size`/`nt_proto_characteristics` + 16 个 `ntp_flag.*`/`line_turnaround`/`value_of_one）+ 各类型 body（`connect_data*`/`accept_data*`/`refuse_data*`/`redirect_data*`/`abort_data`/`marker.*`/`control.data`）+ DATA 面（`data_flag` + 11 位面/`data_id`/`data_length`/`data_oci.id`/`data_piggyback.id`/`data_setp_*`/`data_sns.*`/`data_opi.*`）。**只借鉴字段语义，不搬码**（§4.14）。
- **本仓库 `internal/protocol/tns/builder.go`**（255 行）：已落码的字节真相，**双列互证**（§3.3 表格右列）。

**三路一致性**：在「8 字节头布局」「全部 int 大端」「五类包类型字节」「`length` 含自身」「ACCEPT 与 CONNECT 共享 `connect_common` 前缀」五点，②③一致。**不一致点**：dissector 认 12 个类型字节 + DATA flags 11 位面，而本仓库只实现 5 个类型 + flags 恒 0 —— 取舍按 §4.15「以规范为底线、以现网行为为准绳」：**无规范时以"可复现实测 + 已有落码"为准，不扩未验证字节**（B′ G-TNS-2）。

**候选方案对比（§4.17）**：

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| **A 层链化 + 补 registry 五键 + translate 分支** | 保持现有事件驱动生成器（`layer_gen.go` 不动字节逻辑），补 `registry.go` `Fields` 五键 + 在 `chain_planner_translate.go` 加 `case "tns"`（JSON 往返解码，照 postgresql 分支 `:1315-1342` 范本），存量 12 例整体改写为纯 layers 形 | 与已收官族同构（postgresql 范本逐行可照）；零新框架机制；一次性消灭 §1.4/§1.11 双违规 | 需 1 次批量迁移 + 12 例改写 | O(n) 流式不变；兼容性最好（迁移后单一真相） | **采用** |
| B 保持顶层 `tns` 子映射现状 | 不动配置载体，只补用例 | 工作量最小 | **违反 §1.4/§1.11**（层链唯一真相被架空）；门2① 顶层检查必红 | 双真相长期存在 | **不选** |
| C 生 hex 回放 | 事件内 `body_hex` 逃生口，整帧 hex 覆盖 | 最简单 | 字段不可结构化断言、动态面全失、类型字节无法验证 | 动态零分 | 仅作负例/特殊形逃生口 |
| D 扩实现到 12 个类型字节 | 按 dissector 枚举把 ACK/NULL/ABORT/… 全实现 | 覆盖最全 | **无第二来源佐证**（仅 dissector 单源，§5.4 禁无依据定字段）；body 结构未验证 | 反工风险高 | **不选**（列 B′ G-TNS-2，等现网抓包证据） |

---

## 11. P2 D-TNS-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 体裁：文件清单 / 接口签名 / 数据结构 / 主流程 / 错误分支 / 性能边界 / 冲突点 / 回滚。

### 11.1 文件清单（P4 动作，**本轨道不执行**）

| 文件 | 动作 | 职责 |
|---|---|---|
| `internal/core/layers/registry.go:632-633` | **扩展** | `tns` 注册补 `Fields` 五键（`events`/`sessions`/`checksum_mode`/`wire_fault` + 无 `reconnect`），照 postgresql 块（`:644-660`）范本 |
| `internal/core/layers/chain_planner_translate.go` | **扩展** | 新增 `case "tns"`：`completedConfig` + JSON 往返 → `spec.TNS`（照 postgresql 分支 `:1315-1342`）；**注意 `:1076` 的 `if len(s.Fields) == 0 { return }` 早退——补 registry 后该早退不再拦 `tns`** |
| `internal/core/types.go:1207-1227` | **修改** | ① 删 `TNSConfig.Reconnect`（死字段）；② 事件 `PayloadProfile` 二选一（删键 or 接线，§2.3） |
| `internal/protocol/tns/planner.go:36-57` | **扩展** | validator 补：`sessions[1..n]` 事件校验（G-TNS-3）+ 状态机守卫（G-TNS-8）+ `direction` 枚举值白名单 |
| `internal/protocol/tns/planner.go:67-155` | **裁定去向** | legacy `Plan` 无调用方 → **删除**或转 `_test.go`-only 回归资产（§11.7 冲突点 1） |
| `trafficgen/test/protocol_pcap/cases/tns.json` | **改写** | 12 例全部迁纯 layers 形（§2.1）+ 补 14 例 |
| `trafficgen/tools/coverage_gate.py` | **扩展** | 新增 `check_tns` 块 + 分发表（`:3429`）登记 `"tns": check_tns` |
| `internal/core/strategy_convert.go:8322+` | **扩展（可选）** | `CheckProtoFlat` 加 `tns` presence 分支（照 ntlm/ocsp 先例 `:8400`）→ 支撑负例 #23 |

### 11.2 接口签名（示意，P4 落码钉死）

```go
// 现有（不改签名）
func buildHeader(length uint16, packetType byte, checksum uint16) []byte
func buildPacket(ev core.TNSEvent) ([]byte, error)
func buildDataPacket(length uint16, dataFlags uint16, payload []byte) []byte
func eventType(ev core.TNSEvent) (byte, error)

// P4 新增/修改（示意）
func (Planner) Validate(spec core.FlowSpec) error   // 扩：sessions 全量 + 状态机 + direction 白名单
func tnsStateMachine(events []core.TNSEvent) error  // 新增：CONNECT 首 / ACCEPT 后才 DATA / REFUSE|REDIRECT 后无事件
```

### 11.3 数据结构（现状 + 扩展）

现状（`types.go:1207-1227`）：

```go
type TNSEvent struct {
    Type           interface{} `json:"type,omitempty"`            // string | 数值（负例）
    Direction      string      `json:"direction,omitempty"`
    PayloadProfile string      `json:"payload_profile,omitempty"` // 死字段候选（§2.3）
    DataFlags      uint16      `json:"data_flags,omitempty"`
}
type TNSSession struct {
    SrcPort uint16     `json:"src_port,omitempty"`
    Events  []TNSEvent `json:"events,omitempty"`
}
type TNSConfig struct {
    Events       []TNSEvent      `json:"events,omitempty"`
    Sessions     []TNSSession    `json:"sessions,omitempty"`
    ChecksumMode string          `json:"checksum_mode,omitempty"`
    Reconnect    bool            `json:"reconnect,omitempty"`     // 死字段 → P4 删
    WireFault    json.RawMessage `json:"wire_fault,omitempty"`
}
```

**扩展方向（P4 定稿）**：不新增事件字段（字节面已够）；仅**删** `Reconnect` 与（待裁定）`PayloadProfile`。删 `Reconnect` 时 **JSON 解码用 `DisallowUnknownFields` 会在存量配置上硬失败** → P4 必须**同批改写存量 12 例**（删 `payload_profile` 键，若走删键路线）。**这是本契约最紧的时序约束**（P4 第 1 步）。

### 11.4 主流程

```text
strategy config(layers)
  → ValidateLayers（未知层 / 未知字段 V9 / 层链完整性 / 动态形状）
  → ChainPlanner.ValidateSpec
      → validateSpecBase（校验 DstPort 走通用 FieldContract 块 → 1521）
      → translateTerminalConfig  ← 【P4 新增 case "tns" 落点】
      → protocolValidator("tns") = Planner.Validate  ← 【P4 扩 sessions/状态机/direction】
  → worker 逐流：resolveLayerTuple（动态）→ ChainPlanner.Generate
  → TNSGenerator.Generate（逐 session → 逐 event → buildPacket → EmitMsg{Up, Bytes, SrcPort}）
  → tcp 层（握手/分段/seq/挥手 + 多连接）→ ip 层 → 输出（pcap / port_group）
```

### 11.5 错误分支（§5.2）

三档：①**链级**（`ValidateLayers`/`ChainPlanner.ValidateSpec`）——未知层、V9 `unknown field`、carrier 非 tcp；②**配置级**（`Planner.Validate` + P4 新增守卫）——type/direction/首事件/互斥/checksum_mode/data_flags/IP/wire_fault/sessions 全量/状态机；③**生成期**（`buildPacket` 的 `unknown packet type`/`data_flags must be 0`）——理论不可达（②白名单化），**P4 补 sessions 全量校验后彻底关闭**（G-TNS-3）。全部经 `spec.ValidationErrors` / `error` 传播为 **task error**，**零假成功**。

### 11.6 性能边界（§6.1–6.8 摘要，详见本契约 §6）

单 flow 常驻内存 O(1)（零可变状态）；无锁无共享；逐事件流式；速率归框架 pacer。**不新增任何按流缓存**。

### 11.7 与现有逻辑的冲突点（§8.7）

1. **legacy planner 的双头风险（最高优先）**：`internal/protocol/tns/planner.go` 的 `Plan`（`:67-155`）**未被任何非测试代码引用**（实测：全仓库非测试命中仅 `cmd/server/main.go:163` 空白导入）。它自产握手/挥手（`:116`/`:136`/`:149-152`）——与链路径的 `tcp` 层职责**重复**。**裁定**：不接线；`Plan` 删除或整包转 `_test.go` 回归资产。**不许两套真相并存**。
2. **`Reconnect` 静默无效**：`TNSConfig.Reconnect` 存在（`types.go:1226`），但全仓库零读取（`grep -rn "Reconnect" internal/` 非测试命中只在 `openwire/builder.go:226` 的一个**局部变量名**，与本字段无关）→ 配上不报错也不生效。P4 删或接线，二选一。
3. **`PayloadProfile` 静默无效**：同 §2.3，**零读取**（`grep -rn "PayloadProfile" internal/` 非测试命中仅 `types.go:1211` 定义本身）。存量 12 例**全部**携带该键。
4. **`sessions[1..n]` 不校验（潜在 CRITICAL）**：`planner.go:37-44` 的 `evs = cfg.Sessions[0].Events` 是本协议最危险的一行（§4.4）。P4 必须失败测试先行（G-TNS-3）。
5. **`tns` 层 `Fields` 为空导致 V9 拒绝任何层 config**：`registry.go:632-633` + `complete.go:292-294`。这是 §2.1 目标形状不通的直接原因。
6. **`CheckProtoFlat` 无 `tns` 分支**：顶层 `tns` 子映射**不被 presence 判死**（`strategy_convert.go:8322+` 各协议分支列表里无 `tns`）→ 负例 #23 今日**建了会真绿 = 假通过**，按 postgresql G-PG-6 同款口径：**立项 G-TNS-5，P4 先实测 `checkLayerFlatConflict`（五键）是否已拦**，白名单外走框架级门（§1.13）。
7. **`coverage_gate.py` 无 `check_tns`**：分发表 `:3429` 无 `"tns"` 键 → 门2④ 反查今日**无本协议块**。P4 新增。

### 11.8 回滚方式（§8.8）

按提交序 `git revert`：registry/translate/types/validator 扩展类提交可逐提交回退；**存量 12 例改写提交是唯一的"数据面"提交**——回退它必须与字段删除提交**同批回退**（否则 `DisallowUnknownFields` 与用例配置失配）。registry `Fields` 增键后**必须重跑 `schemagen`**（`go run ./internal/core/layers/schemagen`），否则 `TestLayersGeneratedMatchesRegistry` 变红（§13.18/13.19）；生成文件 `schemas/v1/generated/layers.generated.json:3808` 的 `tns.fields` 随提交对齐（**层数不变**，不新增层）。

---

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

> 证据三选一（§15.2）：文档章节 / 代码行 / 用例号。写不出 = 缺口立项，不许空着。§1/§3/§12 三行按 §15.3 强制展开（§12.1/§12.3/§12.12）。

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 12/12 是**"层链 + 顶层扁平 + 顶层 `tns` 子映射"三重违规形**（实测逐例），旧键残留 = 5 键 + 1 子映射；目标形状 spec_json 样例见 §2.1；**迁移计划 = G-TNS-1**（P4 一次性改写）；非负例顶层键收官目标 = 0 | 本契约 §2.1/§2.1a/§12.1；`cases/tns.json` 12 例机读实测 |
| §2 策略/任务 | 策略 = 单 tns 流量模板，自带 `flow_control`（flows/bps/time）；任务 = 多策略合跑 + 总量封顶；框架语义未动（`tns` 不在 worker/task 特判名单） | `internal/core/worker.go:300-316`；本契约 §2.1 |
| §3 五件套 | 见 §12.3 强制展开：会话表 / 事务序列 / 关联关系（含 REDIRECT 诚实边界）/ 插入位置 / 时间线；**有长连接载体（单 TCP 承载全部事件），不豁免** | 本契约 §12.3 + §10.4；用例 #9/#10/#11 |
| §4 查规范 | **第一路缺位（无公开规范）→ G-TNS-10 登记**；替代 = 旧基线 `31-tns-design.md` + 本仓库落码字节 + TShark 3.6.14 `tns.*` **87** 字段实测；三路对照与候选方案对比（§10.5）；P1 矩阵 8 行 + 三子表（§10.1–§10.3） | 本契约 §1.2/§3/§10 |
| §5 依赖与错误 | 依赖 = `DependsOn ["tcp"]` 单值（`registry.go:632`），无 `TransportOn`/`OptionalOn`/`InnerRequired`；端口契约 `FieldContract{"tcp.dst_port":"1521"}` 走**通用块**（`chain_planner.go:597-616`）；`wire_fault` 3 有效 kind + 2 类非法形（`builder.go:237-255`）；失败全部传 task error（零假成功） | 本契约 §5/§7 + §11.5 |
| §6 性能 | 见本契约 §6「性能设计与验收」（6.1–6.8 要素）：逐事件流式、单 flow O(1) 内存、**零可变状态**、无锁无共享；pcap/NIC 双路验收（NIC = `enp135s0f0np0`）；吞吐数字标「待 P4 基准」（§6.5 不写承诺） | 本契约 §6 |
| §7 三份文档 | `90-tns-design.md` v1.0.0 + `90-tns-testcase.md` v1.0.0（per-protocol 草稿层，§7.4）+ D-TNS-1（本契约 §11，门1 获批 = 定稿）+ T-TNS（testcase §2）+ generated schema（**层数不变**；若 registry `Fields` 增键则重跑 `schemagen`） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 实现；门1 获批 = D-TNS-1 定稿 = 开工门（§8.9） | 提交序 |
| §9 测试三源 | 三源 = ①旧基线设计文档（内部契约，非外部规范）②D-TNS-1（§11）③**dissector 实测**（替代"已确认现网行为"档，**未到抓包级 → G-TNS-13**，不冒充第三源）；26 ID（18 正 + 8 负）逐项回指；存量 12 例审计去向 testcase §8.3 | `90-tns-testcase.md` §2/§5/§6/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 `/tmp/pipe/90-tns/p123-report.md` §3）+ 收官隔离复审 + 修轮；红先绿后 | 报告 §3 |
| §11 白话 | 汇报首句先行白话结论 | 报告 §0 |
| §12 动态清单 | 见 §12.12 强制展开：四元组 = `ip`/`tcp` 层（五策略全支持，allowlist `layer_dyn.go:17-21`；`tns` **不在** allowlist → 业务字段对象必拒）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | 本契约 §12.12 |
| §13 schema 派生 | `tns` 已在 `registry.go:632-633` 注册（**已含在层数内**，**不新增层**）；`allowedProtocols["tns"]=true`（`protocols.go:55`）；`main.go:163` 已空白导入；生成表 `layers.generated.json:3808-3815` 实测 `fields: {}`；**P4 改 `Fields` 必须重跑 schemagen**（§13.18/13.19）；struct 标签字面量锁定（§13.13） | 本契约 §11.1/§11.8 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `tns.*`（87 字段）+ frames hex 双通道 → 先跑后钉（§9.31/§14.20）；pcap 落 `/tmp/mcp-pcaps/tns/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-27）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 纯净 |
|---|---:|---|---|---|
| `cases/tns.json` | 12 | `{layers, src_ip, dst_ip, src_port, dst_port, tns}` ×11 + `{layers, src_ip, dst_ip, dst_port, tns}` ×1（`tns_multi_session`，无 `src_port`；`tns_neg_udp` 同无） | `[tcp,tns]` ×11 + `[udp,tns]` ×1（`tns_neg_udp`，刻意坏配置） | ✅ 5/5 只有 `{expect_error,error_contains}` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` | **12** | 迁 `layers[i].ip.src`（G-TNS-1） |
| `dst_ip` | **12** | 迁 `layers[i].ip.dst` |
| `src_port` | **10** | 迁 `layers[i].tcp.src_port`（`tns_multi_session`/`tns_neg_udp` 用 `sessions[].src_port`/无） |
| `dst_port` | **12** | 迁 `layers[i].tcp.dst_port`；**或删**（由 FieldContract 补 1521，推荐） |
| `count` | **0** | 走 `flow_control`（存量均未写） |
| 顶层 `tns` 子映射 | **12** | **迁 `layers[i].tns`**（须先补 registry `Fields`，G-TNS-1） |
| 事件内 `payload_profile`（死字段） | **12/12 例** | **P4 删键**（§1.12；非顶层键，同属"配上不生效"） |
| 配置级 `reconnect`（死字段） | **0** | P4 删字段（§2.2） |

**结论**：本协议有**实质迁移工作量**（对照 postgresql #82 的"守住"工作量）——§1 门的动作 = ①补 registry `Fields`；②加 translate 分支；③12 例整体改写；④新增 14 例全部纯 layers 形；⑤收官自查行「非负例顶层键 = 0」由 **12 → 0**。

**目标形状 spec_json 样例（纯 layers，顶层仅 `layers` + `flow_control`）**：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.90", "dst": "198.51.100.90"}},
    {"tcp": {"src_port": 41234}},
    {"tns": {
      "events": [
        {"type": "CONNECT", "direction": "c2s"},
        {"type": "ACCEPT",  "direction": "s2c"},
        {"type": "DATA",    "direction": "c2s", "data_flags": 0},
        {"type": "DATA",    "direction": "s2c", "data_flags": 0}
      ]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

**presence 判死形状说明（本协议现状必须点名）**：`{"layers":[…],"tns":{}}`（层链 + 顶层空子映射并存）是 §15.3 M5 清单①的**判死负例形状**。本协议因 `CheckProtoFlat` **无 `tns` 分支**（§11.7 冲突点 6）今日**不会被拒** → 该负例**今日建成会真绿 = 假通过**；P4 先实测 `checkLayerFlatConflict`（`schema/semantic.go:183-191`，只查 6 个四元组/MAC 键，**不含 `tns`**）与 `CheckProtoFlat` 的实际行为，再决定建例或并 G-TNS-5。白名单外游离键判死负例（`src_mac`，走 1.11/1.13 通用门）今日即可建（#23）。

### 12.3 §3 强制展开：五件套

**会话表**：

| 会话 | 四元组 | 生命周期 | 用例 |
|---|---|---|---|
| `s1`（单会话基线） | `ip.src/dst` + `tcp.41234→1521` | SYN/SYN-ACK/ACK → CONNECT(c2s) → ACCEPT(s2c) → DATA* → FIN-ACK 四包 | #1 |
| `s2`（多会话展开） | 第二 `src_port`（`sessions[].src_port`） | 与 s1 完全独立的握手→事件→挥手；**整块回放不交错** | #9 |
| `s3`（并发多流） | `flows=3` 三条独立四元组 | 框架逐流并行；断言每流各自独立 | #10 |
| `s4`（拒绝/重定向终态） | 同 s1 四元组 | 建连 → CONNECT → REFUSE/REDIRECT → **无 DATA** → 挥手 | #2/#3 |
| `s5`（重定向第二连接，A′） | 独立四元组 → 重定向目标地址 | 建连 → CONNECT → REDIRECT → 客户端改连新地址 | G-TNS-11 |

**事务序列（单事务四件事 §3.4–3.7）**：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| `t1` 建连 | TCP 握手完成（`tcp.handshake` 默认 true） | c2s CONNECT（`0x01`） | s2c ACCEPT（`0x02`） | s2c REFUSE（`0x04`）→ 会话终态 → 挥手（#2）；s2c REDIRECT（`0x05`）→ 会话终态（#3） |
| `t2` 数据 | `t1` 收到 ACCEPT | c2s/s2c DATA（`0x06`，flags=0） | 继续 DATA 或结束 | 无协议层错误报文（TNS 无错误类型）→ **失败分支 = 无**（诚实声明） |
| `t3` 终止 | 任意已建立态 | **无应用层终止报文**（NULL/ABORT 未实现） | TCP FIN 四包 | 非正常结束 = RST（`tcp.rst=true`，A′ 补例 #19） |

**关联关系（§3.8–3.10）**：见 §10.4 专节——**主连接内无派生流**（诚实声明）；唯一"跨连接"候选 = REDIRECT（今日不实现，A′ G-TNS-11）。因此 `driven_by` 今日**不适用**，且**不许**用"同一模板连续重复发射"冒充编排（§3.13）。

**插入位置**：终结层（`CategoryTerminal`，`DependsOn ["tcp"]`）——TNS 报文直接落 TCP payload；链上**无中间层**（无 tls/http 包装面）。**注**：Oracle 有 TNS over TLS 形态，本契约 v1 不含（G-TNS-14）。

**时间线**：**单会话严格顺序**（t1→t2→t3，每步依赖前一步；`planner.go:50-52` 已对首事件方向强制）；**多会话整块顺序**（s1 全流程跑完再跑 s2——`layer_gen.go:45-57` 的 sessions 循环是顺序的，tcp 层按 `SrcPort` 变化挥旧握新）；**多流并发**（`flows=N`，跨流不假设全局包序，只断言流内序与各流独立）。无"长传输分片让位"面（无数据流）；控制可中插动作 = 无（TNS 无 ABOR/STAT 类）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组（`ip`/`tcp` 层，五策略全开）**：

| 字段 | 住处 | 开策略 | 依据 |
|---|---|---|---|
| `src`（src_ip） | `ip` 层 | fixed/inc/rand/list/pattern 全开 | allowlist `layer_dyn.go:18`（`"ip": {"src","dst","ttl"}`） |
| `dst`（dst_ip） | `ip` 层 | 同上 | 同上 |
| `src_port` | `tcp` 层 | 同上 + 未写动态保底 `12345+i`（`worker.go:307-308`，`DefaultSrcPort = 12345`，`strategy_convert.go:49`） | allowlist `layer_dyn.go:19` |
| `dst_port` | `tcp` 层 | 同上，**但 §5 端口契约面无域校验**（`tns` 无专用契约块）→ 显式/动态 `dst_port` **今日可用**（与 postgresql 相反，那里会被拒） | 同上 + `chain_planner.go:603-611` |

**业务字段（`tns` 层，逐个列开/不开 + 理由）**：

| 字段 | 开 | 理由 |
|---|---|---|
| `events[]` 整块 | ❌ 关 | 事件序列是会话剧本；逐流变等价于"多套剧本"，应由多策略表达（§2.2 策略=单一模板） |
| `sessions[]` 整块 | ❌ 关 | 同上；多会话的内部展开已由 `sessions[].src_port` 承担 |
| `checksum_mode` | ❌ 关 | v1 只有 `disabled` 一个合法值，逐流变无意义 |
| `wire_fault` | ❌ 关 | 负例唯一注入口，非业务字段 |
| 事件内 `direction` | ❌ 关 | 会话内结构性取值，逐流变破坏会话自洽 |
| 事件内 `payload_profile` | ❌ 关 | **死字段**（§2.3），P4 删键，不讨论动态 |

**序号算法代码位置（实读，不编行号——§5.7）**：

- 层内字段动态解析入口：`internal/core/layer_dyn.go` `parseLayerDyn`（从 layers 数组抽取对象值）→ `checkDynShape`（形状校验）→ `resolveLayerTuple(spec, i)`（**逐流解析并覆写**，`worker.go` 与 `layer_dyn.go` 两处调用）。
- 值算法：`internal/core/tuple_generator.go` `TupleGenerator.Next(index)`；inc 回绕 / rand 可复现（seed+index）/ 端口生成 / 单值解析（`ResolveIPValue`/`ResolvePortValue`/`ResolveStringValue`）。
- 保底自增：`internal/core/worker.go:307-308`（`flowCount > 1 && !spec.HasExplicitSrcPort` → `DefaultSrcPort + i`）。
- allowlist 白名单：`internal/core/layer_dyn.go:17-21`（`ip`/`tcp`/`udp`/`eth` + 各协议块）——**`tns` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- **①层链+顶层空子映射并存**：本协议**存量正是此形**（12/12 例顶层有 `tns` 子映射），但 `CheckProtoFlat` 无 `tns` 分支 → **今日不判死**。P4 动作：先实测（G-TNS-5），按结果建负例或并缺口；**不许**建了会真绿的例冒充覆盖。
- **②白名单外游离键判死（1.11–1.13）**：`{"layers":[…],"src_mac":"02:00:00:00:00:01"}` → 必须拒，锚词 `mixes layers with flat four-tuple field`（`schema/semantic.go:186`）；顶层 `ttl` 等其余游离键由 V9/白名单兜底——**P4 须实测该形今日是否真被拒**。
- **③一切负例 `expect_error` 带错误锚词**：5 个存量负例逐条锚词见 testcase §4；新增 3 条同规。
- **④收官自查行**：「非负例顶层键 = 0」——**今日 = 6 键（`layers`+5）**，P4 迁移后预期 **1（仅 `layers`）**。
- **载体负例**：链夹 `udp`（`[udp,tns]`）判死，锚词 `carrier`（`complete.go:465`，`tns` 判 `tcpOnly`）；存量 `tns_neg_udp` 的 `error_contains: "tcp"` 落同一文案（含 "tcp" 子串）——**P4 须实跑确认锚词匹配**（G-TNS-15）。

---

## 13. P3 对接清单（T-TNS 草稿输入；正文落 testcase 文件）

- §3.15 三项：见 testcase §6.1（①同连接多轮 DATA → #18 + A′ 补例；②非正常结束 → `tcp.rst` #19 + 负例面；③长保活 → 协议层无 keepalive 语义已显式声明不适用 + #18 承载）。
- A′/B′ 两分类表：见 testcase §6.2。
- 9.52 对账两行：见 testcase §5.3（规范逻辑点总数 vs 用例覆盖数 + 不适用面）+ 清单出处声明（**旧基线 + dissector 实测，非外部规范**）。
- 「性能设计与验收」：见本契约 §6（6.1–6.8 要素齐）。
- 3.14 豁免边界审计：见 testcase §6.3（**有长连接载体 → `sessions[]` 不豁免**）。
- 三源回指行：见 testcase §5.1（第三源"已确认现网行为"当前 = 未确认级，挂 G-TNS-13）。

---

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 立项号 | 缺口 | 确认方式（三选一：查文档 / 抓包 / 问人） | 去向 |
|---|---|---|---|
| **G-TNS-1** | **层链化未接线（最高优先）**：`tns` 层 registry **零 `Fields`**（`registry.go:632-633`）+ `translateTerminalConfig` **无 `case "tns"`**（且 `:1076` 因 `len(s.Fields)==0` 早退）→ 层内 `events` 今日既被 V9 拒也不被消费；唯一可用载体是**顶层 `tns` 子映射**（违反 §1.4/§1.11） | 读 `registry.go:632-633` + `chain_planner_translate.go` case 列表（grep `case "tns"` 零命中）+ 生成表 `layers.generated.json:3808-3815` | **P4 第 1 步必办**（照 postgresql `:1315-1342` 范本）；用例 #1–#18 全部依赖它 |
| **G-TNS-2** | 7 个类型字节未实现（ACK `0x03`/NULL `0x07`/ABORT `0x09`/RESEND `0x0b`/MARKER `0x0c`/ATTENTION `0x0d`/CONTROL `0x0e`）——dissector 认得（`tns.marker.*`/`tns.control.data`/`tns.abort_data` 字段实测存在），本仓库 `typeCode`/`validNumericType` 只白名单 5 个 | **抓包**：Oracle 客户端/服务端真实交互抓包确认各类型的 body 结构（无规范可查） | **B′**（无二次依据 → 不进 v1；`明确不解决` + 迁入计划待抓包） |
| **G-TNS-3** | **`sessions[1..n]` 事件完全不校验**：`planner.go:36-44` 只校验 `Sessions[0].Events`；坏 `type`/`data_flags` 会逃过 validator 到生成期（§4.4） | 读 `planner.go:37-44` + **P4 用真实流程实测**（submit `sessions=[合法,{type:127}]` → 看 task 终态） | **A′/潜在 CRITICAL**（P4 失败测试先行；若实测"报成功 + 部分包"升级 CRITICAL 修轮） |
| **G-TNS-4** | 事件级 `payload_profile` 死字段：**零读取**（`grep -rn "PayloadProfile" internal/` 非测试命中仅 `types.go:1211` 定义），存量 **12/12** 例全带；profile 名不上 wire 是设计纪律（`tns_test.go:161-164` 断言 body 不含 profile 名） | 读 `builder.go` 全文（无 `.PayloadProfile`）+ 存量机读 | **P4 删键**（§1.12 口径）；用例 #13 建"删键后正常"正向断言 |
| **G-TNS-5** | 顶层白名单洞：`CheckProtoFlat` 无 `tns` 分支（`strategy_convert.go:8322+`）→ 顶层 `tns` 子映射不判死；`checkLayerFlatConflict`（`semantic.go:183-191`）只查 6 键（不含 `tns`） | 读 `strategy_convert.go:8322-8430` 各协议分支 + `semantic.go:183-191` + **P4 实测提交该形** | **P4 实测后定**：能拦则建 presence 负例；不能拦则并框架级 unknown-key 白名单缺口（kingbase 记忆裁定：**禁加单协议黑名单分支**），**不建会真绿的例** |
| **G-TNS-6** | `decode_as` 面未验证：存量 0/12 例带；标准 1521 端口启发式可用，但**非标端口**（用户显式写 `dst_port` 时）dissector 是否仍识别 `tns.*` 未实测 | 读 `driver.go`（`decode_as` 消费路径）+ **P4 起非标端口用例实测** tshark | P4 补例 #14（非标端口 + `decode_as` 或无字段则降级 frames hex） |
| **G-TNS-7** | 事件级 `data_flags` 在**非 DATA 事件**上静默无效：`buildPacket` 只在 `pt == TypeData` 分支读它（`builder.go:66-71`），但 `Planner.Validate:53-57` 对**所有**事件查非零 → 语义不一致 | 读 `builder.go:57-79` + `planner.go:53-57` | **A′**：P4 统一为"仅 DATA 可写，其它类型写了即拒"或"静默忽略"二选一，写进 validator + 用例 |
| **G-TNS-8** | 状态机守卫缺失：跳步（ACCEPT 前 DATA）/ 终态后事件（REFUSE/REDIRECT 后）/ 方向语义（服务端专属类型出现在 c2s）/ `direction` 枚举值（非 `c2s`/`s2c`/`up`/`down` 静默落 s2c，`planner.go:159-166`）| 读 `planner.go:17-65` 全文 | **A′**（P4 补守卫 + 负例 #24/#25） |
| **G-TNS-9** | 端口无域校验：`tns` 走通用 FieldContract 块（`chain_planner.go:597-616`），用户显式/动态 `dst_port` 被尊重而非拒绝（对照 postgresql 的 `:585-591` 专用块） | 读 `chain_planner.go:597-616` + `validateBaseDstPortHandled` 名单（`tns` 不在） | **设计选择**（TNS 端口现网可配）——写进契约即可，不补校验；用例 #14 钉行为 |
| **G-TNS-10** | **规范面缺位**：Oracle 未公开 TNS 线格式 → §4.12–4.15 的第一路（规范原文）**不存在**，档①为空 | **查文档**：Oracle Database Net Services Reference / Administrator's Guide（**只管业务语义，不含线格式**）；如未来有公开线格式文档则回填 | **C 类登记**（§9.17）：声明本契约字节依据 = dissector 实测 + 已落码，不冒充"已查规范" |
| **G-TNS-11** | REDIRECT 语义不完整：①重定向地址编码未实现（`builder.go:164-166` 只写 4 字节空 body）；②无第二连接（`reconnect` 死字段）；③`driven_by` 三件套无法套用（§10.4） | 读 `builder.go:164-166` + `types.go:1226`；裁定方式 = P4 与框架共同定（扩展 driven_by / 独立 `redirect_to` 字段 / 明确不支持） | **A′**（三选一收口后写结论，不留白） |
| **G-TNS-12** | DATA 负载恒 0：`bodyForType(TypeData) → nil, nil`（`builder.go:98-99`），无负载配置面 → TTC/SQL*Net 字节、MSS 分段压力面今日均不可达 | 读 `builder.go:98-99` + `layer_gen.go`（无负载字段） | **B′**（无公开 TTC 编码依据；`明确不解决`，用例侧 #5 钉现状 `length=10`） |
| **G-TNS-13** | 现网行为未到抓包级：Oracle 客户端的真实 CONNECT/ACCEPT 字节只有官方文档描述，无本机抓包证据（§10.5 ②） | **抓包**：本机起 Oracle XE（或连现网实例）+ `tshark` 抓 1521 核对头字节 | P4 前置确认项，不挡开工；确认前相关条目按 §5.5 标"待确认" |
| **G-TNS-14** | TNS over TLS 不在 v1（Oracle 的 `PROTOCOL=tcps`）：无 `[tcp,tls,tns]` 链支持 | 查 Oracle 文档（tcps 协议配置）+ 抓包 | **明确不解决**（v1 范围外，§1.2 已声明） |
| **G-TNS-15** | 载体负例锚词未实跑验证：`tns_neg_udp` 断言 `error_contains: "tcp"`，而通用 carrier 门文案是 `… %s rides tcp only (carrier)`（`complete.go:465`）——含 "tcp" 子串，**逻辑上匹配**，但未实跑 | **P4 实跑**该负例确认锚词命中 | P4 门2② 必办（红了改锚词，不许放宽到"任务不失败"） |

---

## 15. 修订记录

- v1.0.0（2026-09-27）：P1–P3 文档轨产物（车道 A，协议 #90）。建立 P1 八项要求面矩阵（§10.1）+ 三子表（§10.2 操作序列矩阵 12×5=60 格 / §10.3 数据形态变体 23 行 / §10.5 三路对照与候选方案对比）+ 门槛裁定（§10.4 无派生流诚实边界）；门1 §1–§14 十四行表（§12，§1/§3/§12 强制展开）；D-TNS-1 代码设计（§11，八要素）；性能设计与验收（§6）；缺口 15 项（§14）。**核心发现**：①`tns` 层零 `Fields` + 无 translate 分支 → 层链化未接线（G-TNS-1，本协议最大迁移面）；②`sessions[1..n]` 事件完全不校验（G-TNS-3，潜在 CRITICAL）；③`payload_profile`/`reconnect` 两个死字段（G-TNS-4/G-TNS-11）。**未修改任何 `.go`、未跑 suite、未启动服务器、未写共享文档/账本**。

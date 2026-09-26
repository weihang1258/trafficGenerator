# MMS（IEC 61850 制造报文规范，ISO 9506 / TCP 102）测试用例契约

> 版本：v1.0.0（P1–P3 文档轨产物；#88 mms）
> 日期：2026-09-26
> 配对设计：`docs/protocol-designs/88-mms-design.md`（下称"设计"）
> pcap 用例文件：`trafficgen/test/protocol_pcap/cases/mms.json`（下称"cases"，现存 11 例）
> 旧基线：`26-mms-testcase.md` v1.0.1（其 §2 JSON 块已过期三处：Read 响应长度/`91 04`/Write `80 01 00`——以本文件 §2 + cases 现状为准，过期对照见设计 §8）
> 生效范围：MMS 终结层；层链 `["ip","tcp","mms"]`（存量 11/11 暂缺 `ip` 层，P4 补，G-MMS-8）
> 帧号约定：**1-based**，单流 TCP SYN = 帧 1
> 验证工具：TShark 3.6.14（`tpkt.*`/`cotp.*` 白名单字段；内层 MMS 拒解 → `frames[]` 原始字节断言）

## 1. 测试原则与形状基线

- **断言双通道**：`fields[]`（`{packet, field, value}`，仅 `ip.version`/`tcp.dstport`/`tpkt.*`/`cotp.*` 白名单）+ `frames[]`（`{packet, offset, hex}`，帧首 0-based 前缀匹配；IPv4 载荷起点 54，IPv6 74）。
- **目标形状**（P4 改写后全部用例必须符合；存量 T-9 例外，见 §8.1）：顶层仅 `layers`（+ 可选 `flow_control`）；`layers=[{"ip":{"src","dst"}},{"tcp":{"dst_port":102}},{"mms":{…}}]`。
- **包数契约**：关联 7 包（1 SYN+2 SYNACK+3 ACK+4 CR+5 CC+6 DT1+7 DT2）；每确认服务 +2 包；report +1 包（下行）；多会话 18 包。
- **负例纪律**：`expect_error=true` + `error_contains` 锚词（§4）；presence 判死负例待 G-MMS-1 落码后建（今日不建假绿例）。
- **先跑后钉**：一切 packet_count/帧号/hex 以 P5 实跑 pcap 校准（§9.31/§14.20），本文件 §2 表为存量现状值（P4 改写后重校准）。

## 2. 原子用例索引（11 ID = 9 正 + 2 负，顺序为权威）

| ID | 种类 | 包序 | 关键断言 |
|---|---|---|---|
| T-MMS-1 `mms_connect_establish` | 正（空层默认流） | 7 包：1-3 握手，4 CR，5 CC，6 DT1，7 DT2 | 帧4 `030000140fe00000000100c0010cc20101c10102`；帧6 DT1 全载荷（165B）；帧7 DT2 `030000a1…` + 偏移105 `30 0d … 61 4e … a9 …` |
| T-MMS-2 `mms_read_multi_type` | 正 | 关联后 8=ReadReq，9=ReadResp | 帧9 偏移61 `a1 1e 02 01 01 a4 19 a1 17`；偏移70 `83 01 ff 85 01 2a 86 01 07 89 02 01 02 91 08 65 bb 87 c0 00 00 00 00`（utcTime 8B） |
| T-MMS-3 `mms_write_success` | 正 | 8=WriteReq（`a5`），9=WriteResp | 帧9 偏移66 `a5 04 81 00 81 00`（成功项 `81 00`） |
| T-MMS-4 `mms_information_report` | 正 | 8=Report 下行单帧（无响应） | 偏移61 `a3`；**`injectOn: 1` 为无效键**（G-MMS-2，P4 改写处理） |
| T-MMS-5 `mms_getnamelist` | 正 | 8=Req（`a0…a1`），9=Resp（`a1…a1`） | 请求恒带 `a0{80 00}` extendedObjectClass（builder 行为） |
| T-MMS-6 `mms_identify` | 正 | 8=Req（`a0…a2`），9=Resp（`a1…a2`，`80 vendor/81 MMS/82 1.0`） | vendor 缺省 `FAKE8150` |
| T-MMS-7 `mms_service_error` | 正向业务负向（ErrorPDU 有意产出） | 8=ReadReq（`a4`），9=Err | 帧9 偏移61 `a2 0a 80 01 01 a2 05 a0 03 87 01 02`（access/object-non-existent） |
| T-MMS-8 `mms_no_associate` | 负向（运行时：跳关联） | 4 起直发（`min_packets: 5`） | 帧4 `cotp.type=0x0f` + 偏移61 `a0`（纯 DT 无 CR/CC） |
| T-MMS-9 `mms_ipv6` | 正（形状过期→改写） | 同 T-1，偏移 74 | 字节与 T-1 同；**顶层 `src_ip/dst_ip` flat 残留 → P4 改 `ip` 层** |
| T-MMS-10 `mms_multi_session` | 正（并发） | 18 包；CR_A=帧4，CR_B=帧8；服务 A=15，B=17 | 两路 CR 同字节；帧17 偏移78 `1a 04 49 45 44 32`（IED2）；invoke 各自从 1 |
| T-MMS-11 `mms_validate_reject` | 负例（配置拒） | 不产包 | `expect_error=true`，`error_contains="name"`（超 32B 名） |

> 帧 6 DT1 全载荷（165B）与帧 7 DT2 首段为 canonical 字节（设计 §3.3），P5 以 pcap 重校准为准，此处不复抄全串（存量 cases 行为准）。

## 3. 正例逐项断言契约

- T-1：`packet_count=7` + `negotiated` + `has_handshake`；fields 20 项（CR：type/li/srcref/destref/tpdu_size/src-tsap/dst-tsap + ip.version + tcp.dstport；CC：type/li/srcref/destref/tpdu_size；DT1：type/eot/li/tpkt.length=165；DT2：type/eot）；frames 5 项（帧4/5 CR/CC 全20B；帧6 DT1 全165B；帧7 DT2 首段 + 偏移105 CPA/AARE/Initiate-Resp 段）。
- T-2：fields 2（帧8/9 `cotp.type=0x0f`）；frames 4（帧8 `0300` 前缀；帧9 `03 00 00` + 偏移61 响应头 + 偏移70 五 Data）。
- T-3：fields 2；frames 6（帧8 `03 00` + 偏移66 `a5` + 偏移61 `a0`；帧9 `03 00 00` + 偏移66 `a5 04 81 00 81 00` + 偏移61 `a1`）。
- T-4：fields 1（帧8 type）；frames 2（`03 00 00` + 偏移61 `a3`）。
- T-5：fields 2；frames 6（请求/响应 `a0/a1` + 服务标签 `a1`，§2 表）。
- T-6：fields 2；frames 6（`a0/a2` 请求，`a1/a2` 响应）。
- T-9：fields 7（CR type/srcref + ip.version=6 + tcp.dstport + tpkt.length=20；DT1 type + tpkt.length=165）；frames 4（偏移 74，同 T-1 字节）。
- T-10：fields 2（帧4/8 CR）；frames 8（两路 CR + 帧15 `0300`/`a0`/`02 01 01` + 帧17 `a0`/`02 01 01`/`1a 04 49 45 44 32`）；`packet_count=18`。

## 4. 负例契约

| 用例 | 面 | 锚词/断言 |
|---|---|---|
| T-MMS-7 | 业务负向（ErrorPDU） | `87 01 02` 特征串（帧9 偏移61 段内）；请求 `a4` |
| T-MMS-8 | 运行时负向（未关联直发） | `min_packets: 5`；帧4 DT 非 CR |
| T-MMS-11 | 配置拒（超长名） | `expect_error=true` + `error_contains="name"`（`planner.go:32`） |
| 待建（G-MMS-1 落码后） | presence 判死 `{"layers":[…],"mms":{}}` | `expect_error` + `error_contains` 含 `top-level`（文案由 P4 落码钉死，megaco/hl7/mmse 同款） |
| 待建（V9 已生效） | 白名单外游离键判死 | `expect_error` + `layers: layer "mms": unknown field`（`complete.go:293`） |
| A′ T-MMS-15/16/17/18/20（§6.2） | validator 三值/值定制/域超长/非法位串 | 各锚词见 §6.2 |

## 5. 三源回指行与 9.52 对账

**三源回指**：旧基线 §2–§4（RFC 1006/ISO 8073/8650/8823/9506 + IEC 61850-8-1，章节级）+ D-MMS-2（设计 §11）→ 11 ID（本文件 §2）。第三源"已确认现网行为"当前 = **libiec61850 参考抓包 canonical + TShark dissector 面 + 三探针**（真实 IED 抓包未到 → G-MMS-8 观察项，不冒充）。

**9.52 对账两行 + 清单出处声明**：

- **清单出处声明**：本清单来源 = **规范/旧基线反推**（PDU×状态 33 格 + 变体 32 行 + 八项 8 行），**非**引擎能力面反推。引擎侧只作现状取证（builder 436 行 / layer_gen 267 行 / 单测 24 个 / 接线五件行号）。
- **对账两行**：**规范逻辑点总数 = 73**（八项 8 行 + 矩阵 33 格 + 变体 32 行）；**用例覆盖数 = 36**（八项 8 行各至少一例 + 矩阵已覆 16 + 变体已覆 12；行粒度，行内缺口见矩阵/变体）；**不适用 = 6**（矩阵 B 列 4 + C 列 2）；**缺口 = 31**（矩阵 11 + 变体 20）。36 + 6 + 31 = 73 ✓。其中 A′ 10 项覆盖缺口 10 格/行（§6.2），余下 B′ 声明不支持 + G-MMS-1/2/8 过程债。**粒度声明**：行/格粒度每点 1 计；G-MMS-1…8 不折进 73。**反查全绿 ≠ 覆盖全**（§9.52 原文）。
- ID 权威 = 本文件 §2（11 存量）+ §6.2（10 A′ 补例）。

## 6. P3 固定动作

### 6.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接：关联→读→写→名列表→标识→上送全序；多步 invoke 递增 | 已覆 T-1..7（各单轮）；多轮同连接 → A′ `mms_multi_step_invoke`（T-MMS-13，>2 步递增） |
| ② | 非正常结束 | ErrorPDU（T-7）；未关联直发（T-8）；配置拒（T-11）；超长 TPKT 拒（仅单测） | 前三已覆；AARE 拒绝/Conclude → B′ G-MMS-4（明确不支持） |
| ③ | 长保活 | 协议层无 keepalive（设计 §10.1 行 6 显式不适用）；长会话 = 同连接多轮事务 | 已覆 T-1（关联常驻）；>2 轮随 ① 的 T-MMS-13 同批 |

无空项：①③ 各有已覆例 + 1 条 A′ 补例；② 有已覆例 + B′ 声明。

### 6.2 A′/B′ 两分类表（要求面反推）

A′（P4 接线/补例，10 项；并入与否由主线程定）：

| ID | 补例 | 锚/断言 |
|---|---|---|
| T-MMS-12 | `mms_visible_string`（visibleString 读写一对） | `8a` 标签落线（builder 已支持，零 cases） |
| T-MMS-13 | `mms_multi_step_invoke`（单连接 read→write→identify 三步） | invoke `02 01 01/02/03` 逐帧落线 |
| T-MMS-14 | `mms_write_no_associate`（B 列：未关联直发 write） | 帧4 `a5`（矩阵 Write×B） |
| T-MMS-15 | `mms_error_definition`（definition 类拒） | `82` 类标签落线 |
| T-MMS-16 | `mms_error_service`（service 类拒） | `84` 类标签落线 |
| T-MMS-17 | `mms_error_value_custom`（errorValue 非零定制） | 定制值落线（缺省 2 对照） |
| T-MMS-18 | `mms_domain_overlong`（域名超 32B 拒） | `error_contains="domain"`（`planner.go:35`） |
| T-MMS-19 | `mms_assoc_params`（association 非缺省覆盖） | localDetail/调用数落线（有单测 `TestBuildAssociateAppliesNonDefaultParameters`，零 cases） |
| T-MMS-20 | `mms_services_supported_bad`（非法位串拒） | `error_contains="servicesSupported"`（`builder.go:364/368`，仅单测） |
| T-MMS-21 | `mms_report_multi`（上送多对象/多类型） | `a3` + 多 Data 落线 |

B′（G-MMS-3/4/5/6 结构缺口；文档声明不支持或立项实现，见设计 §14）。

### 6.3 §3.14 豁免边界审计

**有长连接载体 → `sessions[]` 不豁免**：单会话 T-1..8 / 并发双会话 T-10（`multiSession` + `concurrent=true` + `40000+i`）已覆；单包多载荷两形态（多对象一次读写 T-2/T-3 + 名列表多名 T-5）已覆。三项各有结论，**无豁免逃逸**。

### 6.4 断言契约核对结论（与设计 §3/§3.9/§11 一致）

- 白名单字段（`tpkt.version/length`、`cotp.type/li/srcref/destref/tpdu_size/src-tsap/dst-tsap/eot`、`ip.version`、`tcp.dstport`）TShark 3.6.14 实测可解（探针 pkt2/3 + S7 面 `s7comm.*` 反证内层拒解 MMS）。
- 内层一律 frames 前缀（偏移 54/74 + 内层 61/105/78）；T-7 `87 01 02` 在偏移 61 段内前缀命中。
- 旧基线过期三处已改按现状（设计 §8）：Write `81 00` / utcTime `91 08` / Read 响应 `a1 1e/a4 19/a1 17`。

## 7. 实现后执行建议（P4/P5）

- P4 按设计 §11 落码（G-MMS-1 presence 分支 + coverage `check_mms` 登记 + pipe_gate 键表 `mms`），链级红例清单设计 §12-P2（含②游离键判死即刻可建）。
- T-9 改写（`ip` 层 + 删 flat）+ 全文件补 `ip` 层示例 + `flow_control` 补例（G-MMS-8）；T-4 `injectOn` 改写同步（G-MMS-2）。
- G-MMS-3 失败测试先行（float/binaryTime/structure 复现例红→绿）。
- P5：`CASE_PROTO=mms` 全量 ×2 + 门 2 四项 + coverage 反查 + `-race` + pcap 落 `/tmp/mcp-pcaps/mms/`。

## 8. 存量用例逐条审计去向（§9.14 / §14.4）

| 存量 ID | 去向 | 改写点 |
|---|---|---|
| mms_connect_establish | 合入 T-MMS-1 | 补 `ip` 层（P4） |
| mms_read_multi_type | 合入 T-MMS-2 | 同上 |
| mms_write_success | 合入 T-MMS-3 | 同上 |
| mms_information_report | 合入 T-MMS-4 | 同上 + `injectOn` 处置 |
| mms_getnamelist | 合入 T-MMS-5 | 补 `ip` 层 |
| mms_identify | 合入 T-MMS-6 | 补 `ip` 层 |
| mms_service_error | 合入 T-MMS-7 | 补 `ip` 层 |
| mms_no_associate | 合入 T-MMS-8 | 补 `ip` 层 |
| mms_ipv6 | 改写 T-MMS-9 | flat→`ip` 层 + `flow_control` |
| mms_multi_session | 合入 T-MMS-10 | 补 `ip` 层 |
| mms_validate_reject | 合入 T-MMS-11 | 补 `ip` 层 |

去向合计：10 合入 + 1 改写 + 0 作废（作废 0，需注明原因的作废无）。

### 8.1 T-9 改写 spec（目标形状，P4 落码钉死）

```json
{
  "layers": [
    {"ip": {"src": "2001:db8::1", "dst": "2001:db8::2"}},
    {"tcp": {"dst_port": 102}},
    {"mms": {}}
  ]
}
```

（断言面不变：偏移 74 + fields 7 项；`src_ip/dst_ip` 顶层键删除。）

## 9. 修订记录

| 版本 | 日期 | 变更 |
|---|---|---|
| v1.0.0 | 2026-09-26 | P1–P3 文档轨初版：11 ID 索引 + 33/32 格对账 + A′ 10 项 + 存量审计 |

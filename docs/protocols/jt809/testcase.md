# JT809（JT/T 809-2019）测试用例契约

> 版本：v1.1.1（静态闭环修订，2026-10-01）  
> 配套设计：`docs/protocols/jt809/design.md`（当前可执行契约见该设计 §19；历史目标清单见 §8B，为 57 行历史依据）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/jt809.json`（15/15 ID 与本文 §2 同序，含保留的 presence 判死负例）  
> 实现：`trafficgen/internal/protocol/jt809/{types.go,builder.go,layer_gen.go,parser.go}`；链层入口为 `layer_gen.go` 的 `PlanWithConfig` 路径；端口缺省由 `mapToFlowSpec` case `jt809`（主链 8812）与 `PlanWithConfig` 内部缺省双保险供给

> 白话一句：**十五条检查覆盖主链登录/注销、2019 信封与登录体、保活、断开/关闭、从链路双流、转义和登录应答；四条检查越界或非法 presence 配置被拒绝。本文记录机器契约现状，不声称本轮 pcap/NIC 重跑通过。**
>
> 三源回指：规范依据为 JT/T 809-2019 §4.2、§4.3、§5.2；设计依据为 `docs/protocols/jt809/design.md` §3B–§8B 及其 §17 迁移契约；现网/实现依据为 `trafficgen/internal/protocol/jt809/` 当前 `5B/5D + CRC16` 线形与本文件 §2 的机器契约。规范旧信封与当前实现不一致之处，按 §5.2 的 G-JT809-N 缺口记录，不伪造为已覆盖。

## 1. 测试原则和形状基线

用例按机器契约逐条登记；一个用例只钉一个协议行为或一组不可拆的线格式事实。实现以 JT809 当前线层为准：`5B` 起始符、`5D` 结束符、未转义内容上的 CRC16、整体转义；2011/2013 头长 22B，2019 头长 30B（追加 8B `time_sec`）；`MsgLength` 是整帧长度 `1 + header + body + 2 + 1`。

**2026-09-29 机读形状核对：**

| 项 | 值 |
|---|---|
| 例数 | **15**（11 正 + 4 负） |
| ID 顺序 | `jt809_t1_baseline` … `jt809_t15_neg_presence_top_level_jt809`，以 JSON 顺序为权威 |
| 例顶层键 | 15 个例均为 `{expect,id,proto,spec_json,summary}` |
| `spec_json` 顶层键 | **14 个正例为 `{layers}`**；T-15 为**故意** `{layers,jt809}` presence 判死形；无 flat 四元组、无 `count` |
| 层形 | **`[ip,jt809]` ×15**；地址住 `layers[0].ip`，业务配置住 `layers[1].jt809`；T-15 的层内 `jt809:{}` 仅用于判死 |
| 正/负 | 11 正（均 `packet_count`）+ 4 负（`expect_error`） |
| 正例包数 | 7 帧 ×7、8 帧 ×2、13 帧 ×1、14 帧 ×1 |
| 正例字段断言 | **35 条**；`frames` 线字节断言共 **59 条**（逐例由 JSON 机读计数） |
| 负例 `expect` | 4/4 均为严格 `{expect_error,error_contains}` 两键；无成功断言或附加键；为严格仅两键的“干净负例”形状 |

**证据边界：**上述数字来自 JSON 机读。`expect.fields`、`expect.frames` 是机器契约要求，不等于本轮重新抓取；本文不声称 pcap 复跑、NIC 抓包或测试通过。实际执行应待 P5 重跑。

## 2. 原子用例索引（15 ID = 11 正 + 4 负）

> JSON 顺序是权威；T-15 是唯一保留顶层 `jt809` 的 presence 判死负例，形状为层链与顶层空子映射并存，不能清洗为正例或删除。

| # | ID | 类型 | 覆盖行为 | 包数 | 字段断言 | frames 断言 |
|---:|---|---|---|---:|---:|---:|
| 1 | `jt809_t1_baseline` | 正 | 主链 `0x1001` 登录 + `0x1003` 注销，3 握手 + 2 消息 + 3 挥手 | 8 | 7 | 2 |
| 2 | `jt809_t2_envelope_header` | 正 | 2019 30B 头、整帧长度、版本/时间/加密占位/CRC | 7 | 2 | 17 |
| 3 | `jt809_t3_login_body` | 正 | 2019 登录体 `UserId/Password/GNSS/DownLinkIP/Port` | 7 | 2 | 7 |
| 4 | `jt809_t4_keepalive_pair` | 正 | `0x1005` → `0x1006` 空体及双方向 SN | 8 | 3 | 6 |
| 5 | `jt809_t5_disconnect` | 正 | `0x1007`，ErrorCode=1 | 7 | 2 | 3 |
| 6 | `jt809_t6_close_notify` | 正 | `0x1008`，ReasonCode=2，EncryptFlag/Key | 7 | 2 | 4 |
| 7 | `jt809_t7_slave_dual_flow` | 正 | 主链 + 从链两条 TCP 4-tuple、`0x9001` VerifyCode、同 GroupID | 14 | 6 | 4 |
| 8 | `jt809_t8_slave_resp_negative` | 正 | `0x9002` Result=1 从链应答 | 13 | 4 | 3 |
| 9 | `jt809_t9_escape_bytes` | 正 | `0x5B/0x5D` 内容触发双 escape，帧长 74 | 7 | 2 | 5 |
| 10 | `jt809_t10_logout` | 正 | `0x1003` UserId + Password 12B 体 | 7 | 2 | 4 |
| 11 | `jt809_t11_neg_gnss_overflow` | 负 | `gnss_center_id=1000000000` 越界 | — | — | — |
| 12 | `jt809_t12_neg_version_flag` | 负 | `version_flag=3` 越界 | — | — | — |
| 13 | `jt809_t13_neg_error_code` | 负 | `main_disconnect.error_code=3` 越界 | — | — | — |
| 14 | `jt809_t14_login_resp_body` | 正 | `0x1002` Result(1B)+VerifyCode(4B) | 7 | 3 | 4 |
| 15 | `jt809_t15_neg_presence_top_level_jt809` | 负 | 层链 + 顶层空 `jt809` presence 判死 | — | — | — |

## 3. 正例逐项契约

### 3.1 `jt809_t1_baseline`（8 帧）

输入为 `10.0.0.1 → 20.0.0.1`、`gnss_center_id=291`、`initial_sn=100`，顺序为 `main_login`、`main_logout`。契约要求主链 TCP 8812，首三帧为 SYN/SYN-ACK/ACK，消息帧为第 4、5 帧，末三帧为挥手；字段断言共 7 条，frames 钉第 4 帧 `10 01`、第 5 帧 `10 03`（offset 63）。

### 3.2 `jt809_t2_envelope_header`（7 帧）

2019 形：`version_flag=2`、`version_bytes=010000`、`time_sec=1700000000`、`initial_sn=7`。第 4 帧 TCP payload 的整帧长度为 84：`1 + 30 + 50 + 2 + 1`；frames 逐字节钉 `5B`、MsgLength `00 00 00 54`、SN `7`、MsgId `10 01`、GNSS `0x123`、Version `010000`、Encrypt/Key、Time `1700000000`、CRC `22 6D`、尾 `5D`。这些是契约断言，待 P5 重跑复核。

### 3.3 `jt809_t3_login_body`（7 帧）

2019 登录体输入：GNSS=1001、UserId=2002、Password=`pw123456`、DownLinkIP=`192.168.1.100`、Port=8813、Time=1700000000。登录体为 50B，整帧长度为 84；frames 钉 MsgId `10 01`、UserId `00 00 07 D2`、password 原字节、GNSS `00 00 03 E9`、IP 原字节、端口 `D5 53`。

### 3.4 `jt809_t4_keepalive_pair`（8 帧）

输入 `initial_sn=50`、`platform_initial_sn=60`，流程为 `main_keepalive`、`main_keepalive_resp`。第 4 帧为 `0x1005`、SN=50，第 5 帧为 `0x1006`、SN=60；二者均空体（MsgLength=26，即 `1+22+0+2+1`）。

### 3.5 `jt809_t5_disconnect`（7 帧）

`main_disconnect`、`error_code=1`。第 4 帧 MsgId=`10 07`，体中 ErrorCode=`01`；主链端口为 8812，消息后进入 TCP 挥手。

### 3.6 `jt809_t6_close_notify`（7 帧）

`main_close`、`reason_code=2`，并设置 `encrypt_flag=1`、`encrypt_key=9999`。第 4 帧头中钉 EncryptFlag=`01`、Key=`00 00 27 0F`，体中 ReasonCode=`02`；该例登记的是加密占位字段，不代表真实加密。

### 3.7 `jt809_t7_slave_dual_flow`（14 帧）

主链为下级发起 `10.0.0.1:12345 → 20.0.0.1:8812`，从链为上级发起 `20.0.0.1:8812 → 10.0.0.1:8813`；主链消息后才打开从链 TCP，最终主链先挥手、从链后挥手。第 8 帧为从链 `0x9001`，SN=5、VerifyCode=`0x12345678`；两条流共享 GroupID。契约字段钉主链 8812、从链 SYN 8813、从链方向和端口，frames 钉 MsgLength=30、MsgId=`90 01`、SN=5、VerifyCode。

### 3.8 `jt809_t8_slave_resp_negative`（13 帧）

仅配置从链 `slave_connect_resp`、Result=1；主链无消息面但仍有主链握手与挥手。从链第 7 帧为 `0x9002`，TCP payload length=27，MsgId=`90 02`，体 Result=`01`，方向为从链 8813 → 上级。这里“negative”是业务 Result，不是 `expect_error` 负例。

### 3.9 `jt809_t9_escape_bytes`（7 帧）

2011/2013 形 `version_flag=1`，`down_link_port=0x5B5D`。原始内容中的 `5B`、`5D` 在线上分别变为 `5A 01`、`5E 01`；未转义整帧 72B，加两个扩位后为 74B。契约钉首尾 `5B/5D`、转义字节、CRC `49 D4`，待 P5 重跑核对。

### 3.10 `jt809_t10_logout`（7 帧）

`gnss_center_id=291`、UserId=777、Password=`logout88`、InitialSN=9，流程为 `main_logout`。第 4 帧 MsgId=`10 03`，体为 UserId `00 00 00 03` + password 字节；全流程仍含主链握手和挥手。

### 3.11 `jt809_t14_login_resp_body`（7 帧）

`main_login_resp`，Result=0、VerifyCode=`0x12345678`、InitialSN=3。第 4 帧为上级方向 `0x1002`，整帧 TCP length=31：`1 + 22 + 5 + 2 + 1`；体钉 Result=`00`、VerifyCode=`12 34 56 78`、CRC=`9A F1`。

## 4. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功（**本契约无在案 pcap 复跑实证，P5 重跑后补**）。锚词与 planner `ValidateConfig`（`trafficgen/internal/protocol/jt809/jt809.go`）逐字对应：

| # | ID | 故障输入（机读实测） | JSON `error_contains` | 代码锚（ValidateConfig） | 拒绝层 |
|---:|---|---|---|---|---|
| N-1 | `jt809_t11_neg_gnss_overflow` | `gnss_center_id:1000000000` | `out of range [0,999999999]` | GNSS 上界 999999999（`registry.go` V9 区间锚同义；`chain_planner_test` 锚词 `GNSSCenterId 1000000000 > 999999999`） | registry V9 + planner ValidateConfig |
| N-2 | `jt809_t12_neg_version_flag` | `version_flag:3` | `out of range [0,2]` | VersionFlag>2 拒（`registry.go` V9 上界 2 同义） | registry V9 + planner ValidateConfig |
| N-3 | `jt809_t13_neg_error_code` | `procedures:[main_disconnect{error_code:3}]` | `ErrorCode 3 > 2` | ErrorCode>2 拒（**嵌套 procedures 键，registry V9 区间门不下探 list**——锚落 planner 而非框架层） | planner ValidateConfig |

**锚词口径**：`error_contains` 是**子串**判定；N-1/N-2/N-3 使用 validator/registry 真实锚词，T-15 使用 presence 门真实锚词。

- **负例原子性**：每例单一故障注入；N-1/N-2/N-3/T-15 共 4/4 机读实测均单注入。

**负例纯净性**：4/4 `expect` 键集合 = `{expect_error, error_contains}`（**无 `packet_count`、无 `fields`、无 `frames`、无附加键**）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：EncryptFlag>1、Password>8（procedure 级同界）、DownLinkIP>32、version_bytes 非 6 hex、未知 procedure type、procedure 链路归属错配、Result>4、ReasonCode>2、procedure 级 Password/DownLinkIP 超界——以上 planner 锚今日零独立负例；层校验器双段校验的第一段（层内键形/枚举）亦无独立负例。

**T-15 presence 负例**：`spec_json` 保留 `{"layers":[{"ip":{...}},{"jt809":{}}],"jt809":{}}`，故意触发 `no longer accepts a top-level jt809 sub-config`。这是门禁所需的判死形状，不是旧格式正例；其 `expect` 仍严格只有 `expect_error` 与 `error_contains`。

## 5. 覆盖与对账

### 5.1 三源回指行

JT/T 809-2019（设计 §2B–§8B 引用面）+ D-JT809-1（合集设计 Part B）+ **14 个既有正例的在案 frames/包数**（机读实测形状，见 §1/§2）+ **T-15 presence 负例** → 15 ID（本契约 §2）。第三源"已确认现网行为"当前 = **形状级**（ID/顺序/顶层键形/expect 键形/包数/帧 hex 全部机读核对）；**pcap 复跑与 NIC 实证今日不声称**（P5 重跑后刷新，缺口 G-JT809-4）。

**15 个 ID 逐项回指（设计 §）**：T-1←§6B（基线关联）；T-2←当前线形 §19.1/§19.3（2019 头/CRC/长度口径）；T-3←§4B 登录体 as-built（UserId+Password+GNSS+IP+Port）；T-4←设计缺口外增量（0x1005/0x1006，G-JT809-N）；T-5←§4B.4/§7B.3（0x1007）；T-6←设计缺口外增量（0x1008 加密占位，G-JT809-N）；T-7/T-8←§3B.2/§6B（主从双流/GroupID/0x9001/0x9002）；T-9←§19.3 转义口径；T-10←§4B 注销 as-built；N-1…N-3←§5B.1/§19.2；T-14←设计缺口外增量（0x1002 当前体形，G-JT809-N）；T-15←§17 D5/§19.5（presence 判死）。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **合集设计 Part B 公开语义 + 仓库落码反推 + 14 个既有正例的存量机读审计 + T-15 presence 判死负例**，**非纯规范反推**（JT/T 809-2019 逐条条款号未全部标注到行）。
- **对账两行（逐表重数，机读复算，不做跨表二次加总）**：设计计划面要求逻辑点 = **§8B B-01…B-56 表面 57 条，实际 58 行**（B-24 与 B-24b 分占两行；设计文末自述“57 条”与表行数不符）；存量已落 = **15 例**（14 个既有 as-built 例 + T-15 presence 判死）；**未落 43 行**（A′ 立项，§6.2）。**15 ≠ 58，缺口如实登记**；粒度：表中每行计 1。**反查全绿 ≠ 覆盖全**。

### 5.3 T-编号与 id 对照

见 §2 表（15/15 一一对应，T-1…T-10 + T-14 + T-15 + N-1…N-3）。T 系与 B 系**不是一一映射**（例：T-2…T-6/T-9/T-10/T-14 是当前 5B/5D+CRC 线形的独立编排，非 B 系 32B 无 CRC 口径的机械投影；B-05 的 Result=5、§7B.3(d) ReasonCode=99 等边界在当前 15 例中零负例）；映射为语义近似。

### 5.4 设计未覆盖、实现已含（as-built 诚实登记）

| 项 | 现状 | 登记 |
|---|---|---|
| 0x1005/0x1006 保活对 | 设计 §8B **无当前线形用例行**；实现 `emitJT809Procedure` + T-4 已编排钉帧 | **G-JT809-N**（as-built 增量，不虚构设计依据） |
| 0x1008 关闭通知 + 加密占位 | 同上；实现 + T-6 已编排 | **G-JT809-N** |
| 2019 30B 头/`time_sec`/CRC16/MsgLength 整帧口径 | 历史设计 §3B–§4B 为 32B 无 CRC 口径；当前线形见 §19.1/§19.3，T-2/T-14 已钉 | **G-JT809-N** |
| 0x1002 体形 Result(1)+VerifyCode(4) | 历史设计 §4B.2 为 Result+GNSS 体形；当前 wire 为 5B 体（T-14 钉） | **G-JT809-N** |
| 0x9001 VerifyCode(4) 体 | 历史设计 §4B.8 为 0x1001 对称 25B 体；当前 wire 为 4B VerifyCode（T-7 钉） | **G-JT809-N** |
| `platform_initial_sn` 层键 | 设计 §6B.3 描述四 SN 计数器语义；层键显式配置面为落码增量（T-4 用例驱动） | **G-JT809-N**（本协议内编号，不占 C1-C6） |

> 配套设计 Part B 的主链登录、注销、断开通知、双 TCP 主/从链路、MsgSN、2019 登录体、加密占位与转义等要求，已由 15 例中的对应输入/frames 契约登记。当前 cases JSON **没有**设计文档旧清单中的车辆容器 `0x1200/0x1300/0x1400/0x1500/0x1600`、从链容器 `0x9100/0x9600` 例，因此不能宣称这些面已覆盖。

合集设计未覆盖当前实现和 cases 已出现的：

- `0x1005` 主链保活、`0x1006` 主链保活应答（T-4）；
- `0x1008` 主链关闭通知（T-6）；
- 2019 30B 头的固定 `time_sec`、CRC16 和整帧 MsgLength 口径（T-2）；
- `0x1002` Result+VerifyCode 登录应答体的当前线钉（T-14）；
- `0x9001/0x9002` 从链连接及其双流时序的当前线钉（T-7/T-8）；
- `0x5B/0x5D` 转义字节 `5A01/5E01` 的当前实现口径（T-9）。

上述设计未覆盖、实现已含的差异统一登记为缺口 **G-JT809-N**，不得虚构为合集设计已有依据。

### 5.5 包数公式（实测钉死，TCP 族口径）

单流 = **3（握手 SYN/SYN-ACK/ACK）+ 消息帧数 + 3（挥手 FIN/FIN/ACK）**；双流 = 主链 6 帧开销 + 从链 6 帧开销 + 全部消息帧。逐例复算：T-1=3+2+3=8；T-2/T-3/T-5/T-6/T-9/T-10/T-14=3+1+3=7；T-4=3+2+3=8；T-7=3+1+3（主链）+3+1+3（从链）=14；T-8=3+0+3（主链无消息面）+3+1+3（从链）=13。**负例无 `packet_count`**（planner 拒绝，不产帧）。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | **适用**——主链登录→保活→注销序贯（T-1 双消息、T-4 保活对）；主从双流序贯（T-7/T-8） | **已覆**（T-1/T-4/T-7/T-8；主从"先主后从"由实现 timeline 保证） |
| ② | 非正常结束 | **适用**——0x1007 ErrorCode、0x1008 ReasonCode | **已覆 wire 面**（T-5/T-6）；"拒绝后立即断开"的状态机行为无独立用例（A′） |
| ③ | 长保活 | **适用**——0x1005→0x1006 单对（T-4 已编排）；重复保活次数/长时序压力无用例 | **T-4 已覆单对**；重复保活/超时重发 A′（G-JT809-1） |

### 6.2 A′/B′ 两分类表

**A′（P4/P5 接线候选，设计 §8B 未落存量面）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 容器面 | 0x1200/0x1300/0x1400/0x1500/0x1600 与 0x9100/0x9600 容器；从链注销/保活/断开/关闭族（0x9003…0x9008） | 设计 §4B.5–§4B.13/§8B B-09…B-49、B-51（G-JT809-3） |
| 结果枚举面 | 0x1002/0x9002 Result 逐值（0–4）、DisconnectReason/ReasonCode 逐值 | 设计 §4B.2/§4B.4/§5B.1（本契约 §4 仅覆盖 ErrorCode=3 拒绝） |
| SN 回绕面 | InitialSN=0xFFFFFFFE 连续 4 条 SN=…FE/FF/0/1（设计 B-27） | 设计 §6B.3/§8B B-27 |
| 多平台面 | M 平台独立 4-tuple/独立 MsgSN/GNSS 互异（设计 §7B.10 B-25/B-26）；`slave_link_enabled` 多平台 GroupID 路由 | 设计 §7B.10 |
| 保活面 | 重复保活与 SN 递增、30s 超时重发（状态机声明） | 设计 §6B.1/§8B（G-JT809-1） |
| NIC/复跑面 | 15 例 pcap 复跑留档 + NIC 路径用例（今日零证据） | 本契约 §1（G-JT809-4） |

**B′（框架面）**：① 嵌套 procedures 键 V9 区间门不下探（N-3 口径，锚落 planner 是**准拦截点**但框架层存在盲扫面）；② 当前 cases 缺显式 tcp 层（G-JT809-LC-1）；③ `frames` hex 钉帧是主断言通道，`fields` 仅 TCP 面（`tcp.dstport`/`tcp.flags`/`tcp.len`/`tcp.srcport`），协议面全靠 offset 字节钉——无 dissector 字段依赖，但亦无字段级交叉验证；④ 正例 `expect.notes` 为帧内重钉提示（P5 前置说明），非负例形状问题——15 例 `expect` 键集合机读核对干净。

### 6.3 3.14 豁免边界审计

**多会话编排 → 豁免不适用但已覆盖等价面**：JT809 双链路 = 主从两条 TCP 流（T-7/T-8 已编排），等价于"sessions[]" 的多流语义；`slave_procedures` 非空即开从链（实现 `PlanWithConfig`），无隐式数量推导。**长连接保活 → 豁免不适用**：保活是显式 `main_keepalive`/`main_keepalive_resp` procedure（T-4），非传输层 keepalive；重复保活 A′（G-JT809-1）。**单包多载荷 = 不适用**（JT809 一帧一报文）。

## 7. 实现后执行建议（P5）

1. 先按 JSON 顺序重跑 15 例，负例必须观察 task error，不能只看"0 包完成"。
2. 正例逐帧核对 `packet_count`（§5.5 公式逐例复算）、TCP 方向/端口和 35 条字段断言，并按 `frames` offset 复核 59 条线字节断言。
3. T-2 固定 `time_sec=1700000000`，确认 2019 头不会因运行时钟漂移（实现 `buildFrameVer` 在 `TimeSec==0` 时取 `time.Now()`——T-2/T-3 显式钉值，不受漂移影响）；T-9 确认转义后 CRC 与尾界；T-7/T-8 确认主从 4-tuple、顺序和 GroupID。
4. 生成 pcap 后再做 tshark/NIC 对账；本文件不声称 NIC 证据或 pcap 重跑通过（G-JT809-4）。
5. 补写合集设计缺口 G-JT809-N 前，不得把旧 32B/无 CRC 口径继续当作实现契约。

## 8. 存量审计（15 例逐条去向）

### 8.1 存量实测面（2026-10-01 机读）

`cases/jt809.json` **15 例**：11 正（`packet_count` 11/11：8/7/7/8/7/7/14/13/7/7/7，公式 §5.5 逐例复算一致）+ 4 负；**14 个正例 `spec_json` 顶层键 = `{layers}`，T-15 是唯一故意 presence 判死形状 `{layers,jt809}`**；层形 `[ip,jt809]` ×15；正例 `frames` ×11（hex 钉帧，共 59 条）+ `fields` ×11（TCP 面，共 35 条）；负例 `expect` = `{expect_error, error_contains}` ×4，无 `packet_count`。

### 8.2 现状矛盾点（诚实登记）

1. **设计清单计数与当前存量分离**：§8B 页脚历史自述 57 条，表逐行机读为 58 行（B-24/B-24b 分占两行）；当前机器契约仅声明存量 15 例（11 正 + 4 负，其中 T-15 为 presence 判死），其余设计条目仍为 A′ 缺口。
2. **无 pcap/NIC 复跑实证可引用**：本文所有"钉/在案"字样均指**在案已钉值**（cases JSON 内 frames/notes 与既有审计），**非本轮复跑**——P5 重跑后刷新证据链（G-JT809-4）。
3. **`fields` 断言仅 TCP 面**：35 条全为 `tcp.dstport`/`tcp.flags`/`tcp.len`/`tcp.srcport`，协议面全靠 frames hex——无 dissector 字段名依赖，但亦无字段级交叉验证（B′③）。
4. **负例锚 N-1/N-2 双段、N-3 单段**：N-1/N-2 有 registry V9 同义锚 + planner 锚；N-3 仅 planner 锚（V9 不下探 list，框架盲扫面 B′①）。
5. **显式 tcp 层缺失**：14 个正例为 `[ip,jt809]` as-built 形，T-15 是故意 presence 负例；目标 `[ip,tcp,jt809]` 未迁移（G-JT809-LC-1）。

### 8.3 逐条去向表（14 行）

| ID | 去向 | 现状/后续 |
|---|---|---|
| `jt809_t1_baseline` | 保留 | 主链基线；P5 重跑 |
| `jt809_t2_envelope_header` | 保留 | 2019 头与 CRC 线钉；P5 重跑 |
| `jt809_t3_login_body` | 保留 | 登录体字段；P5 重跑 |
| `jt809_t4_keepalive_pair` | 保留 | 0x1005/0x1006 增量覆盖；补设计缺口 |
| `jt809_t5_disconnect` | 保留 | 0x1007；P5 重跑 |
| `jt809_t6_close_notify` | 保留 | 0x1008 增量覆盖；补设计缺口 |
| `jt809_t7_slave_dual_flow` | 保留 | 双流/GroupID/0x9001；P5 重跑 |
| `jt809_t8_slave_resp_negative` | 保留 | 0x9002 Result=1 业务负路径；P5 重跑 |
| `jt809_t9_escape_bytes` | 保留 | 双 escape；P5 重跑 |
| `jt809_t10_logout` | 保留 | 注销体；P5 重跑 |
| `jt809_t11_neg_gnss_overflow` | 保留 | registry/planner 锚；P5 错误传播 |
| `jt809_t12_neg_version_flag` | 保留 | registry/planner 锚；P5 错误传播 |
| `jt809_t13_neg_error_code` | 保留 | 嵌套 ValidateConfig 锚；P5 错误传播 |
| `jt809_t14_login_resp_body` | 保留 | 0x1002 wire 例；补设计缺口 |
| `jt809_t15_neg_presence_top_level_jt809` | 保留 | presence 判死形状；不得清洗为正例 |

统计：**保留 15，作废 0，等价覆盖 0；缺口 5 个主项**（G-JT809-N 设计覆盖差异、G-JT809-1 长保活、G-JT809-3 容器面、G-JT809-4 执行证据、G-JT809-LC-1 显式 tcp 层；G-JT809-2/G-JT809-5 为已关闭/分离口径项）。

## 9. 覆盖反查建议

## 9. 覆盖反查建议

1. `len(cases['jt809']) == 15`，ID 集合及顺序等于本文 §2。
2. 14 个正例 `spec_json` 顶层键严格为 `{layers}`；T-15 为故意 `{layers,jt809}` presence 判死形；正例层形严格为 `[ip,jt809]`。
3. 正例数 11，负例数 4；正例包数分布为 7×7、8×2、13×1、14×1。
4. 正例字段断言总数为 35；frames 断言总数为 59。
5. 负例锚词集合包含 `out of range [0,999999999]`、`out of range [0,2]`、`ErrorCode 3 > 2`、`no longer accepts a top-level jt809 sub-config`。
6. P5 后所有正例应满足 handshake/termination；双流例应满足主链 8812、从链 8813 与同 GroupID。
7. 不把 `0x1005/0x1006/0x1008`、CRC16、2019 30B 头等 as-built 增量倒写成合集设计已有条款。

## 10. 现状缺口清单

| 编号 | 缺口 | 影响 | 处理 |
|---|---|---|---|
| G-JT809-N | 合集设计未覆盖 0x1005/0x1006/0x1008、CRC16/22/30B 信封、0x9001/0x9002 当前线形、0x1002 当前体形、转义口径 | 设计→实现回指不完整 | P4 补 JT809 专属设计增量；本稿如实登记 |
| G-JT809-1 | 仅一对保活，无重复/长时序保活 | §3.15 长保活覆盖不足 | 增加重复保活与 SN 递增例 |
| G-JT809-2 | 已关闭：4 个负例 `expect` 均为严格 `{expect_error,error_contains}` 二键，机读核对 2026-10-01 | 旧 `notes` 键报告不适用于当前 JSON；T-15 presence 形状保留且无附加键 | 关闭；C1-C6 表登记为已关闭 |
| G-JT809-3 | 车辆容器/报警/定位/静态信息等设计面在当前 15 例中为零 | 不能宣称 JT809 业务全覆盖 | 按实现实际支持面补 cases；不以旧设计清单代替实测 |
| G-JT809-4 | 未有本轮 pcap/NIC 证据 | 线字节和包数尚待执行确认 | P5 重跑、tshark 与 NIC 分开留证 |
| G-JT809-5 | 历史设计与当前统计分离 | `design.md` 历史 §8B 为 57 条目标设计用例，不是当前已执行数量；当前机器契约仅为本文件 §2 的 15 例（11 正、4 负） | 以后补例时分别更新历史设计清单与当前 JSON 机读统计 |

## 11. C1–C6 门禁（当前静态核对，2026-10-01）

| ID | 判定 | 说明 |
|---|---|---|
| C1 | 通过 | JSON 可解析；15 ID 唯一且与 §2 同序；顶层键 `{expect,id,proto,spec_json,summary}` ×15 |
| C2 | 通过 | 14 个正例 `spec_json` 顶层仅 `{layers}`；T-15 仅为 presence 判死例；无顶层地址/端口/count |
| C3 | 通过 | 地址在 ip 层；默认端口由实现供给，JSON 未伪造游离协议字段 |
| C4 | 通过 | 4 个负例 `expect` 严格为 `{expect_error,error_contains}` 二键；T-15 的顶层 `jt809` 仅在此故意形状出现 |
| C5 | 条件通过 | 主从双流、保活、非正常结束与转义均有现状用例；车辆容器和长保活登记 G-JT809-N/G-JT809-1/G-JT809-3，不冒充覆盖 |
| C6 | 通过 | 本轮范围严格为 design.md、testcase.md、jt809.json；不改生成器与其他协议 |

静态核对不等于执行证据：`§9` 的每一条都是 P5 重跑的前置条件；本轮未运行 suite、pcap 或 NIC（缺口 G-JT809-4）。


## 12. 层链迁移审计（T1-T6，2026-09-30 历史快照）

> 本节 T1/T2 保留 2026-09-30 审计时的 14 例历史口径；当前机器契约已由 T-15 增补为 15 例（11 正 + 4 负），见 §1、§8、§11。历史数字不覆盖当前结论。

| ID | 检查 | 证据 |
|---|---|---|
| T1 | [历史快照] JSON 可解析，14 个 ID 唯一，且与本文 §2 同序 | 机读校验 |
| T2 | [历史快照] 14 个正例 `spec_json` 均为 `[ip,jt809]` 当前 as-built 形；T-15 后续新增为 presence 判死例；显式 `[ip,tcp,jt809]` 目标形仍登记缺口 G-JT809-LC-1 | 全量层审计 |
| T3 | 4 个负例保留故意错误输入和错误锚词（含 T-15 presence 锚） | `expect_error`/`error_contains` |
| T4 | 地址仅在 ip 层；无顶层地址/端口/count | 全量键审计 |
| T5 | `procedures`/主从开关仍在 jt809 层，未由顶层数量隐式推导 | T-1/T-4/T-7/T-10 |
| T6 | 迁移不改变协议字段、线字节断言或负例语义；as-built 与规范差异单列 G-JT809-N | 对照设计 §17 与 JSON |

## 13. 现状与门禁结论

- 门①（当前线形可执行）：15 例形状和错误锚词均可机读核对；不宣称本轮 pcap/NIC 已跑通。
- 门②（旧格式清除）：顶层 flat 地址/端口/count 已清除；显式 tcp 传输层尚未迁移，登记 G-JT809-LC-1，不以当前 `[ip,jt809]` 冒充目标形。


- v1.0.0（2026-09-29）：新建 JT809 as-built cases 契约。机读核对 14 例、11 正/3 负、ID 顺序、`{layers}` 顶层形、`[ip,jt809]` 层形、正例包数分布、35 条字段断言与 59 条 frames 断言；登记合集设计与当前实现的结构差异，特别标明设计未覆盖但实现已含的 0x1005/0x1006/0x1008 及当前 5B/5D+CRC16 信封；不宣称 pcap/NIC 重跑。自审 **2 轮，末轮干净**。
- v1.0.1（2026-09-29）：隔离复审修正 3 处：§1 与 §10 正例包数分布 7×8 → **7×7**（实际 T2/T3/T5/T6/T9/T10/T14）；§9 P5 复核步骤 frames 断言数 52 → **59**（与 §1/§10 对齐）。
- v1.1.1（2026-10-01，本轮）：新增 `jt809_t15_neg_presence_top_level_jt809`（层链 + 顶层空 `jt809` 并存的 presence 判死负例，锚词取自 `rawWrapChains` 真实文案）；存量 14 → **15 例**（11 正 + 4 负）；D1-D8/T1-T6/C1-C6 全部按 JSON 重数（正例顶层仅 `{layers}`，T-15 为唯一故意例外）。本轮仅静态核对（`json.tool` + 脚本重数 + diff），**未跑 suite/pcap/NIC**。自审 **2 轮，末轮干净**。

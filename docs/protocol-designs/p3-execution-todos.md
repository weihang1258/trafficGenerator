# P3 执行待办清单（全部）

> 来源：`layer-chain-config-optimization-requirements.md` **v1.1**（§2.3 D / §4 校准版）+ 2026-08-27 实证分析。
> 基线：116 协议 / 2666 用例 / 2340 绿 / **24 协议未绿共 326 例**。
> 使用规则：每个 todo 完成 → 勾选本文件 → 按 [[git-commit-strategy]] 提交 commit。修 bug 先写失败测试；每改必自审再测（CLAUDE.md 强制）。
> 本清单在INDEX 挂接动作见 T6.4。

---

## T0 · 决策门（用户输入，不阻塞 T1）

- [x] **T0.1** 确认 F5【白名单单源化 + 一致性哨兵测试】（已确认选(a) 单源+哨兵）——解锁 T2.5
- [ ] **T0.2** 确认 F6【宿主模式样板化】（待 T5 前再确认）——决定 T5 实现方式与设计文档增节
- [x] **T0.3** 确认 F7【用例资产 lint 进门】（已确认先修数据、lint 后置）——T3 按"修数据"主路线；lint 待 T4 前落
- [x] **T0.4** 确认 F8【失败工单 + SUMMARY 合并写】（已确认 T4 前落）——建议在 T4 开工前落
- [x] **T0.5** 网页"支持清单"页改为自动同步（用户确认顺手修，2026-08-27）
- [x] **T0.6** 修复顺序确认为【效率优先】：一处修复救活最多用例的先做（2026-08-27）

> **R1 纠偏入档**：此前把 `TestSystemProtocols_List` 期望值对齐 `system.go` 手抄表（commit 3877571 内）方向反了——手抄表本身才是病灶。按 T0.5 决议改为自动同步后，该测试随之改为断言与真实来源一致。

<!-- 评审注：F5 单源化涉及 extract 白名单导出定义，务必在 T2 统一评审时核查 REST/worker 引用位置不遗漏（共 4 处读取），以免"单一事实源"反而漏掉某处读取路径。 -->

## T1 · dhcpv6 接线（桶🅑，1 例）

- [x] **T1.1** `cmd/server/main.go` 波5e 注释块处补 `app.engine.RegisterPlanner(layers.NewChainPlanner("dhcpv6"))` + 自审（注释与代码一致化）【commit b43b253】
- [x] **T1.2** `CASE_PROTO=dhcpv6` 跑批验证 1/1 绿 → commit

> 运维提示：pcap 驱动连 `http://127.0.0.1:8081/mcp` 的 dev server（非刚编译的后端）。改 `cmd/server/*.go` 后必须先重建二进制并重启 server（停 pid→起 `nohup ./cmd/server/tg-server-new -config configs/config.dev.yaml`），否则用例仍跑旧进程。日志 `/tmp/tg-server-<user>.log`（注意原 `/tmp/tg-server-new.log` 为 root 属主不可写）。

## T2 · 准入白名单补齐（桶🅑，接线即通）

- [x] **T2.1** REST `strategy_handler.go` 两处白名单 → 改引用 `core.IsAllowedProtocol`【commit b43b253 之后另行 F5 提交】
- [x] **T2.2** worker `convert.go` ValidateTaskSpec → 改引用单一事实源
- [x] **T2.3** worker `convert.go` ValidateBatchSpec → 改引用单一事实源
- [x] **T2.4** 单协议跑批：单源化后 ldp 3/pcep 3/goose 1/sv 4/fins 5 突破准入（0→×），真实字段 bug 显形 → 移交 T4【见 T2.6】
- [x] **T2.5**（依赖 T0.1）哨兵测试：`TestAllowedProtocolsStable`（锁 95 集）+ `TestNegativeOnlyPlaceholdersRejected`（锁 32 纯负向占位须继续被拒）
- [ ] **T2.6** s7/bgp/coap/iec104/opcua/mms 白名单接通后重跑，残留真实实现 bug 移交 T4 对应条目

> **T2 成果**：F5 单源化将 4 处手抄白名单收敛为 `internal/core/protocols.go` 单一 `allowedProtocols`（95 名）+ `IsAllowedProtocol()`；哨兵测试锁定完整性。验证：原四表并集 92 全保留（0 遗漏）+ engine 注册集全覆盖（0 缺失）。ldp/pcep/goose/sv/fins 从"全被 invalid protocol 拒"到"部分通过 + 字段 bug 显形"。**既有回归**：`TestStart_*` ×3 为 pre-existing（task_stale_test.go，与白名单无关）；**R1 纠偏**：`TestSystemProtocols_List` 的 cflow 漂移不是"加 cflow 到期望集"能修的——手抄表 `system.go` 才是病灶，按 T0.5 决议改为自动同步引擎注册表（commit 7c307b5）。

## T3 · 配置翻译与用例形状（桶🅒，44 例）

- [ ] **T3.1** opcua：定夺并记录 spec_json 形状结论（修数据 vs 工具容错），修订用例使正路径全绿
- [ ] **T3.2** mms：同 T3.1
- [ ] **T3.3** drda：对照设计文档逐字段核对翻译路径，**先写失败用例**再修实现
- [ ] **T3.4** thrift：同 T3.3
- 出口：四协议全绿；负路径 expect_error 用例保持"应败仍败"，不得被误"修绿"

## 【08-27 聚类分析修正】（凭实测签名聚类，替代按协议逐个排错的旧假设）

对桶🅑五个"解锁后仍失败"协议（ldp/pcep/goose/sv/fins 共 71 例）做失败签名聚类，结论：**不是 71 个独立 bug，是 7 类根因**：

| 簇 | 内容 | 涉及 | 裁决 |
|---|---|---|---|
| ① 期望值书写格式错（字节本就对） | `0xC1`vs`0xc1`、宽度 `0`vs`0x00000000` 等 | fins 9 处（已修 ✅ 5→11/14，commit affa2b9）；ldp 若干字段同病 | 改 case JSON |
| ② 单点编码 bug 放大 | PCEP 公共头/OPEN 对象编码错误 → dissector 判全包 malformed | pcep ~17 例同一签名 | 产品修 ×1 处救一片 |
| ③ 校验器过严误杀 | goose 全被一句过窄规则拒；sv 全被 "L2 only" 规则拒（链式自动补层冲突，属框架级，**先修=为 T5 四路由探路**） | goose 9、sv 7 | 产品修规则/接线 |
| ④ 字段级编码差异 | ldp TLV 多段、FEC 前缀、若干字节位 | ldp 8-10 例 | 产品修（部分又混①） |
| ⑤ 事件词汇缺失 | 生成器不认 `wire_fault` 等标准事件种类；多会话正例产出 0 事件 | ldp 4 例 | 产品补 |
| ⑥ 校验缺失（该拒没拒） | `expected rejected but completed` | ldp 负例5、pcep 负例3 | 产品补校验+文案对齐设计文档 |
| ⑦ 默认流/翻译缺口 | `config is required`、sessions 上限拒绝 | pcep_multi_session、fins_sessions×2；与桶🅒(opcua/mms/drda/thrift) **同机制家族** | 归入 T3 一起做 |

> 推论：tshark 字段渲染约定（hex 大小写/宽度/前缀）缺统一规范会持续制造假失败——规范随 T4.0 工单工具一并沉淀。

## T4 · 半集成实现排错（效率优先队列，2026-08-27 用户确认）

> 新顺序原则：**一处修复能救活最多用例的先做**。每条纪律：设计/testcase 文档为仲裁 → 先写失败测试 → 修复 → 自审+review → 单独 commit。

- [ ] **T4.0** driver fail/error 自动落盘"期望 vs 实测"工单 + tshark 渲染书写规范沉淀 + SUMMARY 合并写【F8 已确认】
- [x] **T4.1** 🔥 pcep 编码器根治（簇②，3/24→22/24，远超 ~17 预期）【commit 0cc2ca5 + 3a69a0a】
  - 根因：对象头 Object-Type 位错位(bit6-7→高nibble 0xF0)+各对象 body 布局错误+LSP/SRP class 错(21/24→32/33)+stateful TLV flag 位错(0x80→0x01/0x02)，对照 packet-pcep.c 逐一修正
  - 校验补全：object_length 须>=4且4对齐 / 拒 unknown 事件 / address family 文案
  - **剩 2 例需设计确认**：①`pcep_neg_session_id`(open c2s SID7/s2c SID99)——设计与正例 open_keepalive(c2s7/s2c8 也是"不一致"却合法)冲突，按"不同 SID 即拒"会破坏正例，SID 语义需设计仲裁；②`pcep_multi_session`(spec_json 顶层 sessions[] 数组)——层链 `[tcp,pcep]` 读 spec.PCEP=nil→"config is required"，sessions 结构解析缺口(集群⑦)
- [x] **T4.2** goose 过严校验器（簇③）【commit 0eeee5e + 6ebf59a + 063c7d9 + 待提交】
  - 根因：mapToFlowSpec 给 L2-only 链（goose/sv）填默认 src_ip/dst_ip/
    src_port/dst_port（10.0.0.1/20.0.0.1/12345/80 假值），被 "L2 only" 校验
    拒收——框架级"链式补层冲突"。修复：L2-only 协议不填默认 + 顶层 count 回填。
  - chain_planner: goose/sv Emit 保留生成器 VLAN，不 l2For 覆盖。
  - 编码对齐 Wireshark packet-goose.c：多类型 allData（boolean/int/uint/
    float/bit_string/visible_string/binary_time/utc_time）、PDU tag 0x85-0x89
    修正、INTEG 最小编码、bit_string 左对齐（bit_length）、FLOAT32 IEC
    5 字节（0x08 前缀 + IEEE 754）、goID 缺省回填 gocbRef。
  - event_seq 重传状态机（stNum++/sqNum 复位 0/重传帧）+ sqNum 连续性
    校验（neg_sqnum 该拒已拒）+ stNum/sqNum 溢出文案。
  - **结果：1/12 → 12/12 全绿**；回归测试 L2 默认值/顶层 count/重传序列/
    bit_string 编码/neg_sqnum 拒收。
- [x] **T4.3** sv 链式 L2 冲突（簇③，兼为 T5 探路）【commit 8c7be03】
  - 框架 L2 修复复用 goose（T4.2 的 mapToFlowSpec 不填默认 IP + Emit 保留
    VLAN），sv 不再被 "L2 only" 拒。
  - sv 编码根治：ASDU 嵌套缺 0xa2 seqASDU/内层 0x30 导致 tshark 判全帧
    malformed；seqData 值4字节+可选quality4字节（带 quality=8/通道，无
    quality=4/通道，sv_custom_dataset 非 9-2LE）；float32 IEEE 754；double_send
    帧数=c.Count。
  - 用例校准（①）：reserve1/2→0x0000、frame.protocols 按 tshark 输出、
    sv_vlan eth.type→vlan.etype。
  - **结果：sv 0/12 → 12/12 全绿**。
- [x] **T4.4** fins 剩余：BCD 时钟编码 + 多会话上限（1 例产品修 + 2 例并入 T3）【commit 49d62bf】
  - BCD 时钟产品修：Wireshark omron-fins dissector（3.6.14/master）把 0x0701 时钟读**
    响应**解析为 2 结束码 + **7 字节时钟**（年/月/日/时/分/秒/星期），**无世纪字段**。
    旧编码器多写 1 字节世纪 → dissector offset 不推进 → 帧判 malformed。修：去掉世纪字节。
  - 用例校准：帧断言 offset 54 `00 00 20 26 08 18 14 30 00 02` → `00 00 26 08 18 14 30 00 02`。
  - **fins 11/14 → 12/14**；`fins_sessions_two/three`（sessions>1 链式多流展开）是框架级多流
    限制（mqtt/nfs/modbus 同款拒绝），**并入 T3** 框架多流课题。
- [x] **T4.5** ldp 分簇清扫：⑤事件词汇 → ④字段编码 → UDP hello 子路径 → ⑥补校验【commit 待补】
  - **3/25 → 23/25 全绿（除 2 例框架多流并入 T3）**。
  - ✅ ① 期望格式校准（tshark 渲染基准）：fec.pfval 不带 /len（tshark 只输出裸前缀，用
    fec.len 字段携带长度）；tlv.type 为消息内全部 TLV 类型逗号拼接（0x0100,0x0200）；
    generic.label 十进制（74565/703710，非 0x12345）；帧断言 PDU/Message Length 差 1
    （编码正确，期望值多写/少写 0x01）。
  - ✅ **tshark 3.6.14 LDP FEC-only dissector 伪影**：packet-ldp.c dissect_tlv_fec 在
    dispatch 前无条件读 op_length=tvb_get_bits16(offset+8)，对 IPv4 Prefix FEC（/24=7B）
    该读取点永远在 FEC 元素末端之外 2 字节。若 FEC TLV 是消息最后一个 TLV（Label
    Request 必须 FEC-only）→ offset+8 越 tvb 终点 → BoundsError → malformed；若后面有
    Label TLV（Mapping/Withdraw/Release）则读取点落在其后 TLV 头内 → 正常。编码正确
    （RFC 5036 §3.4.1.1/§3.5.1），非帧缺陷。已入 pcaptest whitelist（verify.go）。
  - ✅ **Status TLV 10 字节产品修**（notification）：RFC 5036 §3.5.3.1 Status TLV =
    Status Code(4)+Message ID(4)+Message Type(2)=10 字节；旧实现只发 4 字节状态码 →
    tshark "length is 4, should be 10" → status.data 空。修 BuildNotification 扩为全 10 字节。
    用例改为 status_code=10(Shutdown)，期望 status.data=0x0000000a。
  - ✅ ⑤ 事件词汇/形状：wire_fault 不是合法事件 kind——故障注入走 `ldp.fault_kind` 顶层键
    （CheckFault 识别 pdu_length/message_length/tlv_length/label_bounds/unknown_message/
    checksum）。用例由 wire_fault 事件改 shape 为顶层 fault_kind。
  - ✅ ⑥ 补校验：neg_port（udp_discovery 源端口必须 646）；neg_state（keepalive 前必须
    initialization）；neg_prefix_bounds（/33 前缀在 Validate 时以 "prefix" 错误拒绝，而非
    延迟到 planner 0 包）；neg_ipv6_profile（IPv6 传输 + IPv4 basic profile 拒绝混用）；
    neg_carrier/neg_checksum 走顶层 fault_kind/carrier 校验。
  - **ldp_dual_adjacency / ldp_tcp_multi_session**（adjacencies/sessions 多邻接多会话）是框架
    级多流展开限制（同 fins_sessions），**并入 T3**。
- [ ] **T4.6** mongodb（差 1 例）
- [ ] **T4.7** s7/bgp/coap/iec104（白名单已通，排真实错）
- [ ] **T4.8** tns/dameng/someip/cql
- [ ] **T4.9** tls 回归单例复跑定位

## T5 · 四路由协议从零实现（桶🅐，94 例）

> 按 §8 编排：每协议内部严格 阶段1 文本 → 阶段2 代码 → 阶段3 测试；四协议之间相互隔离可并行。

- [ ] **T5.0**（依赖 T0.2）`18-layer-config-design.md` §5 增"宿主模式"节：tcp-carrier / udp-carrier / ip-direct(ip.proto 直发) / l2-direct 四样板，引用 goose/sv 先例 —— 全部协议的阶段1 锚点
- [ ] **T5.1** igmp·阶段1：设计文档对齐样板（组播地址约束、query/report 分型）→ review
- [ ] **T5.2** igmp·阶段2：`internal/protocol/igmp` 包（planner/layer_gen）+ registry schema（DependsOn=[ip]，ip.proto=2）+ main.go + 三处白名单 + 冒烟链式测试 → 自审+review
- [ ] **T5.3** igmp·阶段3：CASE_PROTO=igmp 25/25 → commit
- [ ] **T5.4–56** ospf 三步同构（proto=89；Hello/LSA 模板）
- [ ] **T5.7–59** pim 三步同构（proto=103）
- [ ] **T5.10–512** isis 三步同构（**l2-direct 特例**：无 ip 层，LLC 封装细节在其阶段1 单独定稿）

## T6 · 收尾与验收

- [ ] **T6.1** 全量套件跑批一次，出最终 SUMMARY（工作区现存 4 个脏结果文档随本次自然再生）
- [ ] **T6.2** 各协议结果 md 与 SUMMARY 一致性核对并提交
- [ ] **T6.3** 若 T0 已确认：F5–F8 状态翻转为已确认；F5/F7 生效则宣布验收第 9 条门禁生效
- [ ] **T6.4** 本文档挂接 INDEX.md；更新记忆文件
- **终验**：§6 验收标准全部满足 + 2666 用例全绿 ⇒ P3 达成（"全量套件变绿"）

---

## 范围外备忘（不在本期验收，全集可见防遗漏）

1. mining 族 5 协议未实现（stratum/getwork/gbt/ethmining/xmrmining；方案=共用 JSON-RPC 件，已定待实施）
2. `translateTerminalConfig` 手写端口尾巴收敛到 FieldContract（§3.4 尾债）
3. 用例严格分层化残留盘点：spec_json 平铺键形态与 G1"层内权威"目标的差距审计（P2 遗留）
4. a2a/mcp "骑 http 层、删 http_builder.go" 完成度待核实（P1a 声称完成）
5. dameng 后续如需抽 oracle 父层（F4 既定后续）

## 粗略工期参考（不计并行）

| 批 | 内容 | 参考 |
|---|---|---|
| T1 | 1 行接线+验证 | 小时级 |
| T2 | 白名单×4 +（可选哨兵） | 0.5 天（含哨兵 ~1 天） |
| T3 | 形状×2 + 翻译×2 | 1–2 天 |
| T4 | 十条排错（有 T4.0 工单提速） | 2–4 天 |
| T5 | 设计文档一节 + 四协议×三阶段 | 4–6 天 |
| T6 | 收尾 | 0.5 天 |

> 并行机会：T2 六个协议互相独立；T4 十条互相独立；T5 四协议互相独立（§8.2 隔离规则）。批次间保持 T→T' 串行次序由决策/前置关系决定，非硬栅栏的以实际依赖为准。

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

> **T2 成果**：F5 单源化将 4 处手抄白名单收敛为 `internal/core/protocols.go` 单一 `allowedProtocols`（95 名）+ `IsAllowedProtocol()`；哨兵测试锁定完整性。验证：原四表并集 92 全保留（0 遗漏）+ engine 注册集全覆盖（0 缺失）。ldp/pcep/goose/sv/fins 从"全被 invalid protocol 拒"到"部分通过 + 字段 bug 显形"。**既有回归**：`TestStart_*` ×3 为 pre-existing（task_stale_test.go，与白名单无关）；`TestSystemProtocols_List` 是 system.go 与测试的 cflow 漂移（已顺手修复，加 cflow 到期望集）。

## T3 · 配置翻译与用例形状（桶🅒，44 例）

- [ ] **T3.1** opcua：定夺并记录 spec_json 形状结论（修数据 vs 工具容错），修订用例使正路径全绿
- [ ] **T3.2** mms：同 T3.1
- [ ] **T3.3** drda：对照设计文档逐字段核对翻译路径，**先写失败用例**再修实现
- [ ] **T3.4** thrift：同 T3.3
- 出口：四协议全绿；负路径 expect_error 用例保持"应败仍败"，不得被误"修绿"

## T4 · 半集成实现排错（桶🅓 99 例 + 🅔 1 例）

> 顺序按剩余失败数升序（先易后难）。每条纪律：tshark 对照定位差异 → 先写失败测试 → 修复 → 自审+review → 单独 commit。

- [ ] **T4.0**（依赖 T0.4，可选但强烈建议先做）driver fail/error 自动落盘"期望 vs 实测"对照工单；SUMMARY 改合并写
- [ ] **T4.1** mongodb（差 1 例）
- [ ] **T4.2** tns（7 败）
- [ ] **T4.3** dameng（8 败）
- [ ] **T4.4** someip（9 败）
- [ ] **T4.5** s7（T2 接线后剩余 9 错误）
- [ ] **T4.6** cql（16 败）
- [ ] **T4.7** coap（16 败）
- [ ] **T4.8** iec104（16 败）
- [ ] **T4.9** bgp（17 败）
- [ ] **T4.10** tls 回归单例：复跑→定位→修；若属实回归，补防回归断言

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

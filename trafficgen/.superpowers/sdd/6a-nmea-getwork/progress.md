# SDD ledger — plan: .superpowers/sdd/6a-nmea-getwork/plan.md

Ruling: Tasks 5–7 (getwork/stratum) verified ALREADY IMPLEMENTED in tree —
commit 349e57d (getwork 62 用例) + 718300b (stratum 40 用例) 及后续。计划
底稿（31 例、registry 草稿）被现行实现取代；引用路径 docs/protocol-designs/
75-*/76-* 与 internal/protocol/dns/layer_gen.go、gbt/chain_planner.go 在
仓库中不存在（计划路径陈旧）。未来 agent 勿按计划重实现。

- Task 5: complete — 349e57d/718300b（registry 8332/3333 + layer_gen + 单测）
- Task 6: complete — 349e57d/718300b（strategy_convert.go:480-490 parseSubconfigJSON）
- Task 7: complete — 349e57d/718300b（62 + 40 用例，超出计划 31 例；全量
  getwork 62/62 22.6s、stratum 40/40 12.7s 实测通过，getwork-task-report.md）
- Task 8: NMEA 子集 pending — 待 nmea-implementer 的 RST/双载体引擎接线后
  跑全量 nmea 套件（当前 76/80，余 4 例引擎级缺口）

# NMEA 收官追加（2026-09-06）
- Task 8 complete — 4743e00 layer-chain self-drive for NMEA 0183:
  nmea_tcp_rst/rst_multi/coexist: 3 PASS；nmea_tcp_udp_coexist_reversed:
  1 known gap（sessions 序 UDP-first 与 has_handshake 断言口径冲突）。
  CHAIN_PROTO=nmea 离线套件 80 例：79 PASS + 1 SKIP。-race 全绿。
- Task 6a NMEA self-drive 收尾：nmea/layer_gen.go emit branch + Plan
  分支（meta.NMEA 接线） + applySpecToChain rst 翻译 + NMEASession.
  Termination 字段 + chain_planner_nmea_test.go 4 例单测 + knownGaps
  注释保留 1 例。

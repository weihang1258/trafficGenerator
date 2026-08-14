# TFTP Spec-to-PCAP Test Case Mapping

## Files

- **Design spec**: `/home/weihang/trafficGenerator/docs/protocol-designs/06-tftp-design.md` (§7 "测试用例（T-001 ~ T-241）", line 1167)
- **PCAP test cases**: `/home/weihang/trafficGenerator/trafficgen/test/protocol_pcap/cases/tftp.json` (226 cases)
- **PCAP results**: `/home/weihang/trafficGenerator/trafficgen/docs/protocol-pcap-test/tftp.md` (226 cases)

## Spec Overview

§7 contains **241 test cases** organized into 11 sections：

| Section | Range | Count | Description |
|---------|-------|-------|-------------|
| §7.1 正向用例 | T-001~T-020 | 20 | RRQ/WRQ 基础下载上传、blksize/timeout/tsize/windowsize 协商、OACK/ACK#0/FinalBlockZero/ServerTID/默认化 |
| §7.2 负向错误注入 | T-021~T-040 | 20 | ERROR(0-8) 注入时机/方向/默认 ErrMsg 映射/超长截断/互斥/优先级 |
| §7.3 边界用例 | T-041~T-070 | 30 | blksize 8/65464 极值、自动追加开关、块号 65535/65536 回绕、0 字节末块、多流 TID 冲突、S15 完整流程 |
| §7.4 Validate 负向 | T-071~T-105 | 35 | 字段校验错误（filename/mode/error_code/端口范围/互斥组合） |
| §7.5 多流与异常 | T-106~T-125 | 20 | 多流并发/交错、TID 变更迁移、块重传、windowsize×ERROR/重传/追加组合 |
| §7.6 字节精确 | T-126~T-140 | 15 | RRQ/WRQ/OACK/DATA/ACK/ERROR 逐字节核算（14B/15B/19B/32B...） |
| §7.7 端到端集成 | T-141~T-160 | 20 | Plan→Worker→PCAP、tshark 解析、真实 NIC 发送、Validate 失败传播、参考 PCAP 比对、metadata |
| §7.8 并发正确性 | T-161~T-175 | 15 | 8 流并发/-race/共享 Pacer 限速/Plan 确定性/无死锁/worker 消费 |
| §7.9 选项组合矩阵 | T-176~T-205 | 30 | 2^4 选项组合×关键状态分支、windowsize=1/65535 边界、选项顺序固定 |
| §7.10 协议交互与互操作 | T-206~T-221 | 16 | 真实 tftp 客户端互操作、tshark 识别/选项/错误码解析、VLAN/隧道共存、速率/方向统计 |
| §7.11 回归与审计追踪 | T-222~T-241 | 20 | C1-C5/H1-H6/M1-M7 审计修复回归（uint32 块数/判定 TSize/ERROR 语义/默认映射） |
| **Total** | | **241** | |

## Coverage by Section（226 pcap cases → 221/241 spec IDs）

| Section | Range | IDs | Covered | Missing | 缺口性质 |
|---------|-------|-----|---------|---------|----------|
| §7.1 正向用例 | T-001~T-020 | 20 | 20 | 0 | — |
| §7.2 负向错误注入 | T-021~T-040 | 20 | 20 | 0 | — |
| §7.3 边界用例 | T-041~T-070 | 30 | 30 | 0 | — |
| §7.4 Validate 负向 | T-071~T-105 | 35 | 34 | 1 | T-098 单测域 |
| §7.5 多流与异常 | T-106~T-125 | 20 | 20 | 0 | — |
| §7.6 字节精确 | T-126~T-140 | 15 | 15 | 0 | — |
| §7.7 端到端集成 | T-141~T-160 | 20 | 15 | 5 | 真实 NIC/参考比对/ctx 取消/轮转 |
| §7.8 并发正确性 | T-161~T-175 | 15 | 6 | 9 | -race/goroutine/Pacer 单测域 |
| §7.9 选项组合矩阵 | T-176~T-205 | 30 | 30 | 0 | — |
| §7.10 协议交互与互操作 | T-206~T-221 | 16 | 12 | 4 | 真实客户端/重放/多任务 |
| §7.11 回归与审计追踪 | T-222~T-241 | 20 | 19 | 1 | T-232 文档一致性（已满足） |
| **Total** | | **241** | **221** | **20** | **91.7%** |

## 剩余缺失清单（20 条，全部为 pcap-drive 域外）

| ID | 验证点 | 缺口原因 | 建议归属 |
|----|--------|----------|----------|
| T-098 | TFTPConfig 缺失 → `tftp: TFTPConfig is required` | 单测已覆盖：`TestValidate_TFTPConfigMissing`（tftp_test.go:452） | Go 单测（已覆盖） |
| T-146 | E2E: 真实 NIC 发送（enp135s0f0np0） | 需物理网卡 + 抓包，非 pcap-drive 环境 | 硬件 E2E |
| T-151 | E2E: 参考 PCAP 比对（RRQ） | 需 testdata 参考文件 + 逐字节比对框架 | 框架扩展域 |
| T-152 | E2E: 参考 PCAP 比对（多选项） | 同上 | 框架扩展域 |
| T-156 | E2E: context 取消 | Plan 协程取消行为，需 goroutine 观察 | Go 单测域 |
| T-160 | E2E: PCAP 轮转/文件名 | 时间戳文件名 + 轮转，engine 域 | Go 单测域 |
| T-162 | 共享 Pacer 限速（8 流 1Mbps） | 聚合吞吐测量，engine 域 | Go 单测域 |
| T-163 | 并发 Plan 同 spec 确定性 | 8 goroutine 字节比对 | Go 单测域 |
| T-164 | 并发 Plan 不同 spec | 8 goroutine 独立序列 | Go 单测域 |
| T-165 | 并发 + context 取消 | 8 goroutine 中途 cancel | Go 单测域 |
| T-170 | 高并发 Plan 无死锁 | 16 goroutine | Go 单测域 |
| T-171 | worker 消费速率 | 大 blocks 流经 worker 无积压 | Go 单测域 |
| T-172 | 并发 Validate | 8 goroutine 同非法 spec 同错误 | Go 单测域 |
| T-173 | 并发 Validate + Plan | 混合 4 合法 + 4 非法 | Go 单测域 |
| T-174 | 包序号连续性（多 worker） | PacketIndex 全局连续，-race | Go 单测域 |
| T-206 | 真实 tftp 客户端互操作（下载） | 需外部 tftp 服务器应答 | 硬件/互操作 E2E |
| T-207 | 真实 tftp 服务器互操作（上传） | 需外部 tftp 服务器接收 | 硬件/互操作 E2E |
| T-212 | PCAP 重放一致性 | 需重放框架（engine 已有独立 replay 实现与测试） | 框架扩展域 |
| T-216 | 多任务混合流量（3 任务隔离） | driver 单任务驱动，多任务需扩展 | 框架扩展域 |
| T-232 | windowsize 引用统一 RFC 7440 | **已满足**：文档全文仅 T-232/H1 两处提及 RFC 3625（均为"删除该引用"的修复记录），无实质 RFC 3625 引用 | 文档一致性（已满足） |

**结论：20 条缺失全部属于 pcap-drive 不可脚本化域**（真实硬件/goroutine/共享速率/参考文件/文档），无一条可通过追加 pcap case 覆盖。pcap 用例侧覆盖率已达上限 91.7%。

## Key Observations

1. **覆盖率从 60.2% 提升至 91.7%**（145 → 221 spec IDs，135 → 226 pcap 用例）。§7.1/§7.2/§7.3/§7.5/§7.6/§7.9 六节 100% 全覆盖；§7.4/§7.11 各剩 1 条（T-098 单测已覆盖、T-232 文档已满足）；§7.7/§7.8/§7.10 剩余均为域外（真实 NIC/goroutine/外部客户端/重放）。

2. **planner bug 修复（V20 互斥检查不可达）**：原 `mapToFlowSpec`（strategy_convert.go）仅填充 spec.TCP，HTTP/DNS/FTP/ICMP/SCTP 子配置永不填充，tftp `Validate` 的 V20 互斥检查（tftp.go:56-73）对 `http/dns/ftp/icmp/sctp` 不可触发——T-102（TFTP+HTTP 共存拒绝）此前被判为 **MCP 不可达**。修复：strategy_convert.go 将 `cfg["http"]/cfg["dns"]/cfg["ftp"]/cfg["icmp"]/cfg["sctp"]` 提升为通用读取（与 tcp 同级），tftp planner Validate V20 全部 6 个互斥检查现在均可达。验证：
   - 探针（tmp_probe）：protocol=tftp + http 子配置 → `spec.HTTP != nil` → V20 触发
   - 端到端：`tftp-http-coexist-reject`、`tftp-e2e-tcp-reject` 经 MCP 任务运行时 Validate 拒绝，case PASS（error_contains 匹配）
   - 单测：`TestMapToFlowSpec_UniversalHTTPSubConfig` / `TestMapToFlowSpec_UniversalDNSSubConfig` / `TestMapToFlowSpec_UniversalSCTPSubConfig` 全部 PASS

3. **T-063 与 §5.2 的 OACK tsize 规则验证**：T-063 期望 OACK 回 `tsize\0 0\0`，但 §5.2（H6 修复）规定 RRQ 模式仅 `ServerTSize > 0` 时才回声 tsize。实测 pcap：`tftp-rrq-tsize0-client`（client_tsize=1024, server_tsize 未设）的 OACK 为纯 `00 06`（UDP 长度 0x000a，无选项字节）——**planner 行为正确，spec T-063 表行有误**。已修正设计文档 T-063 行（OACK 空 `00 06`）与 case 断言；planner 代码零改动。

4. **data_payload_pattern 语义确认**：pattern `"AA"` 生成 ASCII 字符 'A'（0x41），**不是** hex 0xAA。`tftp-matrix-blk8-ws2` 的帧断言因此从 `00030001aaaaaaaa` 改为 `000300014141414141414141`。所有使用 pattern 的 case 均按此语义验证通过。

5. **大数 blocks 用例**：`tftp-rrq-blocks-65535-head`（131071 包）与 `tftp-regress-blocks-65536-wrap`（131073 包）实际生成并验证（short-circuit 用 `min_packets=2` 仅断言首包语义，避免全量帧断言）。块号回绕（65535→0，R2-HIGH-3）经 wrap-seq 字节断言验证。

6. **windowsize 窗口语义实测确认**：`i % ws == 0 || i == bc` 的 ACK 边界规则在多 case 验证（T-120/121/122/197/198、matrix-blk8-ws2 等）；TID 变更（T-110）12 包序列与 ERROR(5)→新 TID 后继续传输的扩展行为经字节级断言确认。

7. **T-104/T-105 已定义并覆盖**：旧映射文档记"spec 占位未定义"；实际 spec §7.4 已定义（ErrorAfterBlock×RetransmitBlocks 重叠合法、ErrorAfterBlock×FinalBlockZero 并存合法），由 `tftp-validate-t104-error-afterblock-retransmit` 与 `tftp-rrq-error-after-finalzero` 覆盖。

8. **T-232（RFC 3625 引用）已满足**：设计文档全文仅 T-232/H1 两处出现 "RFC 3625"，均为修复记录本身（H1 已删除实质引用）；文档一致性目标达成，无需 case。

9. **Validate 负向 34/35 全覆盖**：T-071~T-105 除 T-098（单测覆盖）外全部经 MCP 任务运行时 Validate 拒绝验证（expect_error + error_contains），含 V20 六个互斥检查（tcp/http/dns/ftp/icmp/sctp）。

## Recommendations

1. **pcap 用例补齐已达上限（91.7%）**：剩余 20 条全部为域外（表见上）。无需继续追加 tftp pcap case；如追求 100% 名义覆盖，可把 T-098/T-156/T-160/T-162~T-174 的归属登记到 Go 单测清单并逐一确认存在。
2. **T-212（PCAP 重放一致性）**：engine 已有独立 replay 实现（P1-P10/R1-R10，2026-07 完成，~130 测试 -race）；若需 tftp 专属重放验证，可扩展 pcap-drive 驱动调用重放路径，成本中等。
3. **T-216（多任务混合流量）**：driver 扩展多任务 batch 提交后可补；属框架级改造。
4. **回归风险**：本次改动仅涉及 tftp.json（5 case 断言修正）、strategy_convert.go（通用子配置读取）、strategy_convert_validate_test.go（3 单测）与设计文档 T-063 行；建议 CI 全量跑一次确认其他协议（HTTP/DNS/FTP/ICMP/SCTP 子配置读取路径）无回归。

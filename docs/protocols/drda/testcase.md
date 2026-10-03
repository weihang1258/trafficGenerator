# DRDA T-DRDA 用例契约

> 版本：v1.2.1（D/T/C 文档审查版＋C5 13 例逐例对账，2026-10-01）
> 日期：2026-10-01
> 配套设计：`docs/protocols/drda/design.md` v1.2.1
> 机器契约：`test/protocol_pcap/cases/drda.json`（13 例已落地可解析；9 正 + 4 负；真实 suite/pcap/NIC 尚未运行）

## 1. 形状和断言纪律

所有正例 `spec_json` 都是严格层链形：地址在 `ip`，端口在 `tcp`，数量在 `flow_control`；顶层没有协议子映射、地址、端口或 `count`。合法链为 `[ip,tcp,drda]`，IPv6 仍使用 `ip`。负例可故意保留违规形状以验证拒绝。

正例必须断言包数、方向/握手/终止、字段或帧字节；负例 `expect` 只能含 `expect_error` 和 `error_contains`。帧偏移为 IPv4 54、IPv6 74；DDM 头固定 10 字节。包数以实际 pcap 校准，当前 JSON 中的数值是既有契约值，不声称本轮复跑。

## 2. 原子用例索引

| # | ID | 类型 | 行为点 | 包数 |
|---:|---|---|---|---:|
| 1 | `drda_excsat` | 正 | TCP 446、EXCSAT→EXCSATRD、DDM 头 | 9 |
| 2 | `drda_security_check` | 正 | EXCSAT→ACCSEC→SECCHK 及响应顺序 | 13 |
| 3 | `drda_database_connect` | 正 | ACCRDB/RM 与 SAMPLE | 15 |
| 4 | `drda_sql_success` | 正 | SQLDTA/SQLCARD，SQLCODE=0 | 17 |
| 5 | `drda_sql_error` | 正 | SQLDTA/SQLCARD，SQLCODE=-204、SQLSTATE=42704 | 17 |
| 6 | `drda_dss_min_length` | 正 | length=10、length2=4 边界 | 9 |
| 7 | `drda_ipv6_excsat` | 正 | IPv6 地址族对称、DRDA 字节不变 | 9 |
| 8 | `drda_multi_session` | 正 | 两独立 TCP session、correlator 各自从 1 起 | 18 |
| 9 | `drda_dss_length_mismatch` | 负 | 声明长度 11 与段长度 10 不一致 | — |
| 10 | `drda_udp_rejected` | 负 | UDP 载体违反 TCP 依赖 | — |
| 11 | `drda_chained_format` | 正 | chained 首 DDM format=0x41 | 9 |
| 12 | `drda_neg_presence_top_level_drda` | 负 | 顶层 drda 子映射与层链并存 | — |
| 13 | `drda_neg_dst_port_contract` | 负 | 显式目标端口非 446 | — |

## 3. 正例断言清单

- #1：packet 4/5 的 `tcp.dstport=446`、`drda.ddm.ddmid=0xd0`、format `0x01`、correlator 1、length 10、length2 4、代码点 `0x1041/0x1443`；frames offset 54 分别为 `00 0a d0 01 00 01 00 04 10 41` 和 `...14 43`。
- #2：代码点按 EXCSAT、ACCSEC、ACCSECRD、SECCHK、SECCHKRM 顺序出现；packet 8/9 correlator 为 3；frames offset 56 含 `d0 01 00 03`。
- #3：packet 10/11 代码点 `0x2001/0x2201`、correlator 4/配对；frames offset 62 为 `20 01`/`22 01`。
- #4：packet 12/13 代码点 `0x2412/0x2408`，响应 TCP payload 非空；offset 64 含 SQLCODE 0 与 SQLSTATE `00000` 的参数字节。
- #5：同 #4 的序列，offset 64 含 SQLCODE `-204`（U32 BE `ff ff ff 34`）与 SQLSTATE `42704`。
- #6：packet 4/5 均 length 10、length2 4，验证最小 DDM。
- #7：packet 4 断言 IPv6 version/source/destination、TCP 446、EXCSAT；offset 74 的 DDM 前缀与 #1 相同。
- #8：`tcp.srcport` distinct 为 12345/12346（排除 446），目标端口 distinct 为 446；两个 session 独立生成 9 包。
- #9：packet 4 `tcp.dstport=446`、format `0x41`、`fmt.bit1=1`、代码点 `0x1041`、correlator 1；packet 5 format `0x01`、代码点 `0x1443`；frames offset 54 请求 `00 0a d0 41 00 01 00 04 10 41`、响应 `00 0a d0 01 00 01 00 04 14 43`。

## 4. 负例契约

| ID | 违规输入 | 锚词 |
|---|---|---|
| #10 `drda_dss_length_mismatch` | `[ip,tcp,drda]` 中 `dss_length=11`、segment length=10 | `dss_length` |
| #11 `drda_udp_rejected` | `[ip,udp,drda]` | `tcp` |
| #12 `drda_neg_presence_top_level_drda` | 层链 `drda` 与顶层空 `drda` 子映射并存 | `top-level drda sub-config` |
| #13 `drda_neg_dst_port_contract` | 层内 `tcp.dst_port=5000` | `dst_port must be 446` |

错误必须在生成数据前返回，不产截断 pcap。

## 5. T1–T6 测试矩阵

| 编号 | 测试面 | 用例 |
|---|---|---|
| T1 | 建连、释放、TCP 长连接 | #1–#9 |
| T2 | 请求/响应代码点与顺序 | #1–#5、#9 |
| T3 | DDM 长度、BE 头、TLV/SQL 参数 | #1、#4–#6、#9 |
| T4 | IPv4/IPv6、双 session、chained | #7/#8/#9 |
| T5 | 非法长度、错误载体、presence、端口契约 | #10–#13 |
| T6 | 真实流程与性能六类场景 | C5/C6，待真实 suite/NIC 与基准执行 |

## 6. A′/B′ 对账

A′ 已覆盖：DSS 头、EXCSAT/ACCSEC/SECCHK/ACCRDB/SQLDTA/SQLCARD 主序列、成功/负 SQLCODE、最小长度、IPv4/IPv6、双 session、chained format、TCP 依赖负例。B′ 立项：SQLSTT 多语句、失败 RM 参数、完整 token/SECMEC、reconnect、全量 pcap/NIC 复跑、性能基准。对应设计 C1–C6，不把缺口写成已覆盖。

## 7. 业务流程和五件套

| 项 | DRDA 结论 |
|---|---|
| 会话表 | 每个 TCP 446 session 独立 ID、四元组、correlator；#8 |
| 事务序列 | EXCSAT→ACCSEC→SECCHK→ACCRDB→SQLDTA/SQLCARD；#1–#5 |
| 关联关系 | 请求/响应以 correlator 配对；双 session 不跨流复用 |
| 插入位置 | 同一 TCP 长连接内按阶段顺序插入；SQL 在 RDB 关联后 |
| 时间线 | 当前按 session 顺序串行生成；未来并发交错须另立用例 |

## 8. 存量和旧文档审计

旧 `_archive_29-*` 逐条核对：13 个当前 ID（原 10 个存量 ID 加 chained、presence、端口契约三项新增）均有对应覆盖；旧顶层扁平写法不再作为当前示例。缺少本轮实际 pcap 证据的断言维持“待复跑”状态。

### 8.1 C5 13 例逐例对账（静态契约验收；真实执行待复跑）

| ID | 类型 | 验收项 | 状态 |
|---|---|---|---|
| `drda_excsat` | 正 | 9 包；TCP 446、EXCSAT/EXCSATRD、长度/格式/correlator、offset 54 两帧 | 静态已核对；suite/pcap/NIC 未运行 |
| `drda_security_check` | 正 | 13 包；五代码点顺序、packet 8/9 correlator=3、offset 56 四帧 | 静态已核对；suite/pcap/NIC 未运行 |
| `drda_database_connect` | 正 | 15 包；ACCRDB/RM、correlator 配对、offset 62 两帧 | 静态已核对；suite/pcap/NIC 未运行 |
| `drda_sql_success` | 正 | 17 包；SQLDTA/SQLCARD、TCP payload 非空、offset 64 SQLCODE 0/SQLSTATE 00000 | 静态已核对；suite/pcap/NIC 未运行 |
| `drda_sql_error` | 正 | 17 包；SQLDTA/SQLCARD、SQLCODE -204（`ff ff ff 34`）、SQLSTATE 42704 | 静态已核对；suite/pcap/NIC 未运行 |
| `drda_dss_min_length` | 正 | 9 包；请求/响应 length=10/length2=4、最小帧 | 静态已核对；suite/pcap/NIC 未运行 |
| `drda_ipv6_excsat` | 正 | 9 包；IPv6 地址族、offset 74 DDM 前缀与 #1 相同 | 静态已核对；suite/pcap/NIC 未运行 |
| `drda_multi_session` | 正 | 18 包；两 session 源端口 12345/12346、目标 446、9 包对称 | 静态已核对；suite/pcap/NIC 未运行 |
| `drda_chained_format` | 正 | 9 包；请求 format=0x41+`fmt.bit1=1`、响应 0x01、offset 54 两帧 | 静态已核对；suite/pcap/NIC 未运行 |
| `drda_dss_length_mismatch` | 负 | `[ip,tcp,drda]`、声明长度 11/段长度 10、`dss_length` 锚词 | 静态已核对；suite/pcap/NIC 未运行 |
| `drda_udp_rejected` | 负 | `[ip,udp,drda]`、`tcp` 锚词 | 静态已核对；suite/pcap/NIC 未运行 |
| `drda_neg_presence_top_level_drda` | 负 | 层链 drda＋顶层空 drda 并存、`top-level drda sub-config` 锚词 | 静态已核对；suite/pcap/NIC 未运行 |
| `drda_neg_dst_port_contract` | 负 | 层内 `tcp.dst_port=5000`、`dst_port must be 446` 锚词 | 静态已核对；suite/pcap/NIC 未运行 |

C5 结论为 13/13 静态契约已对账、0/13 真实运行。不得将上述表格或 JSON 解析通过写成 pcap/NIC/suite 证据。

## 9. 修订记录

- v1.2.0（2026-09-30）：与 JSON 13 例对账；补 chained、顶层 presence、端口契约三例，更新 T1–T6、A′/B′ 和存量审计。

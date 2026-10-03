# DRDA（分布式关系数据库架构）测试用例设计

> 配对设计：`docs/protocol-designs/29-drda-design.md`
> 可执行契约：`trafficgen/test/protocol_pcap/cases/drda.json`
> 当前状态：文档设计阶段；`drda` 层尚未注册，因此本文件先定义实现完成后的 pcap 断言，不宣称当前回归已通过。

## 1. 测试目标与断言口径

术语沿用设计文档：TCP（Transmission Control Protocol，传输控制协议）、DSS（Data Stream Structure，数据流结构）、DDM（Distributed Data Management，分布式数据管理）。

本批用例以 TCP（Transmission Control Protocol，传输控制协议）446 为默认载体，覆盖 DDM（Distributed Data Management，分布式数据管理）/DSS（Data Stream Structure，数据流结构）关联建立、SQLAM（SQL Application Manager，SQL 应用管理器）结果、长度边界、IPv6、多会话和配置拒绝。所有正向 case 必须同时具备 `packet_count`、至少一个 `fields` 或 `frames`，并按 1 起始包号断言；负向 case 只有 `expect_error` 与 `error_contains`。

### 1.1 帧偏移

- IPv4 TCP payload 起点：54 = 以太网 14 + IPv4 20 + TCP 20。
- IPv6 TCP payload 起点：74 = 以太网 14 + IPv6 40 + TCP 20。
- `frames[].hex` 是从该偏移开始的原始字节前缀；不把 TCP 分段数量当作 DDM 数量。
- DDM 头固定 10 字节：`length(2) magic(1) format(1) correlator(2) length2(2) code_point(2)`，均为大端（BE，big-endian）。最小无参数对象为 `00 0a d0 01 00 01 00 04` 加 2 字节代码点。

### 1.2 包数

固定小载荷单 TCP 会话为：3 个握手包 + 每个应用请求/响应各 1 个数据包 + 4 个挥手包。因此：

| 应用往返数 | packet_count |
|---:|---:|
| 1（S1、S6、S7） | 9 |
| 3（S2） | 13 |
| 4（S3） | 15 |
| 5（S4、S5） | 17 |
| 两条独立 S1 会话 | 18 |

调度器若把纯 ACK 或多个应用事件重新分包，必须在实现阶段以实际 TCP planner 序列更新设计与 JSON；本批 JSON 只钉死当前公共 TCP 约定下的小载荷情形。

## 2. 用例清单与设计映射

| 测试编号 | JSON id | 类型 | 覆盖 |
|---|---|---|---|
| T-DRDA-001 | `drda_excsat` | 正 | TCP 446、EXCSAT→EXCSATRD、DSS/DDM 头 |
| T-DRDA-002 | `drda_security_check` | 正 | ACCSEC→ACCSECRD、SECCHK→SECCHKRM |
| T-DRDA-003 | `drda_database_connect` | 正 | ACCRDB→ACCRDBRM、RDB 关联 |
| T-DRDA-004 | `drda_sql_success` | 正 | SQLDTA→SQLCARD、SQLCODE=0 |
| T-DRDA-005 | `drda_sql_error` | 正 | SQLDTA→SQLCARD、负 SQLCODE/SQLSTATE |
| T-DRDA-006 | `drda_dss_min_length` | 正 | DDM length=10、length2=4 下界 |
| T-DRDA-007 | `drda_ipv6_excsat` | 正 | IPv6 payload offset=74 |
| T-DRDA-008 | `drda_multi_session` | 正 | sessions=2、各自关联和 correlator |
| T-DRDA-009 | `drda_dss_length_mismatch` | 负 | 显式 `dss_length` 与编码长度不一致 |
| T-DRDA-010 | `drda_udp_rejected` | 负 | UDP 不是 DRDA 允许载体 |

## 3. 正向用例规格

### 3.1 `drda_excsat`（T-DRDA-001/S1）

- 配置：`[tcp, drda]`，目的端口 446，`association=excsat`，请求代码点 `0x1041`，响应 `0x1443`，correlator=1。
- 预期：9 包；握手、协商和终止均为真；packet 4/5 的 `drda.ddm.ddmid=0xd0`、`drda.ddm.format=0x01`、`drda.ddm.rqscrr=1`、代码点分别为 `0x1041/0x1443`；TCP payload 起点分别是 `00 0a d0 01 00 01 00 04 10 41` 与 `00 0a d0 01 00 01 00 04 14 43`。

### 3.2 `drda_security_check`（T-DRDA-002/S2）

- 配置：完整 EXCSAT 后发送 ACCSEC（`0x106d`，SECMEC=USER_PASSWORD 的占位机制）和 SECCHK（`0x106e`），不放真实密码；响应为 ACCSECRD（`0x14ac`）和 SECCHKRM（`0x1219`）。
- 预期：13 包；应用顺序为 EXCSAT、EXCSATRD、ACCSEC、ACCSECRD、SECCHK、SECCHKRM；packet 8/9 分别断言代码点和 `drda.ddm.rqscrr=3`；FrameAssert 从 payload+2 的 magic 偏移开始，避免虚构含认证参数的总长度。用户名/令牌只使用配置的确定性占位字节。

### 3.3 `drda_database_connect`（T-DRDA-003/S3）

- 配置：`association=database`，依次包含 EXCSAT、ACCSEC、SECCHK、ACCRDB（`0x2001`，`rdb_name=SAMPLE`）；响应包含 EXCSATRD、ACCSECRD、SECCHKRM、ACCRDBRM（`0x2201`）。
- 预期：15 包；packet 10/11 为 ACCRDB 请求/响应方向，目的/源端口为 446；FrameAssert 在 DDM code point 偏移处分别断言 `20 01`、`22 01`，不虚构包含 RDBNAM 参数的总长度。ACCRDBRM 成功后才能进入 SQL 阶段。

### 3.4 `drda_sql_success`（T-DRDA-004/S4）

- 配置：完成数据库关联，`sql.data` 为 UTF-8 的确定性短数据，`sql.code=0`、`sql.state=00000`；请求 DDM 为 SQLDTA（`0x2412`），响应 DDM 为 SQLCARD（`0x2408`）。
- 预期：17 包；packet 16/17 代码点分别为 `0x2412/0x2408`，`tcp.len` 非零，FrameAssert 在 DDM code point 偏移处钉住 `24 12`、`24 08`；总长度由编码后 SQL 数据决定，不在设计阶段编造。SQLCARD 的 SQLCODE=0 必须作为实现层结构字段或重组后的字节断言；若本地 tshark 无 SQLCARD 子字段，不能以“存在 SQLCARD”代替 SQLCODE 断言。

### 3.5 `drda_sql_error`（T-DRDA-005/S5）

- 配置同成功例，但 `sql.code=-204`、`sql.state=42704`、`sql.diagnostic=missing object`。
- 预期：17 包；packet 16 SQLDTA、packet 17 SQLCARD，响应代码点为 `0x2408`，SQLCODE/SQLSTATE 必须可观察且为错误值；应用错误不应被当作 task/config error，连接仍按正常终止路径结束。

### 3.6 `drda_dss_min_length`（T-DRDA-006/S6）

- 配置：显式最小无参数 DDM，`dss_length=10`，`length2=4`，代码点使用 EXCSAT；响应同样是长度下界结构。
- 预期：9 包；packet 4/5 `drda.ddm.length=10`、`drda.ddm.length2=4`，FrameAssert 为 `00 0a d0 01 00 01 00 04 10 41` / `00 0a d0 01 00 01 00 04 14 43`。此例验证的是长度边界，不把空 DSS 误判为成功业务阶段。

### 3.7 `drda_ipv6_excsat`（T-DRDA-007/S7）

- 配置与 S1 相同，地址为 `2001:db8::1`→`2001:db8::2`。
- 预期：9 包；packet 4 `ipv6.version=6`、`ipv6.src/dst` 和 `tcp.dstport=446`；frame offset=74 的 DDM 前缀与 S1 完全相同，说明 IP 版本不改变 DRDA 字节。

### 3.8 `drda_multi_session`（T-DRDA-008/S8）

- 配置 `sessions=2`，第二 session 使用源端口 12346；两个 session 都执行最小 EXCSAT→EXCSATRD，correlator 各自从 1 开始，不跨流复用。
- 预期：18 包；`tcp.srcport` distinct values 为 12345/12346，`tcp.dstport` 为 446；每个流均有握手、DDM 请求/响应和终止。确定性输出按 session 顺序；未来并发实现应改成按流匹配，不用全局 packet 序号。

## 4. 负向用例

### 4.1 `drda_dss_length_mismatch`（T-DRDA-009）

`[tcp,drda]` 中声明 `dss_length=11`，但实际 DDM 为 10 字节；预期 `expect_error=true`、`error_contains="dss_length"`，不设置 `packet_count`、`fields` 或 `frames`。错误必须在 planner/builder 生成数据前返回，不能生成截断或长度不一致的 pcap。

### 4.2 `drda_udp_rejected`（T-DRDA-010）

使用 `[udp,drda]`；预期 `expect_error=true`、`error_contains="tcp"`，不设置任何 pcap 结构断言。该例验证层依赖/载体校验，而不是测试 UDP 上的“DRDA 变体”。

## 5. 覆盖与审查清单

- [x] TCP 446 默认端口和完整握手/终止。
- [x] EXCSAT、ACCSEC、SECCHK、ACCRDB 及各响应的方向与状态顺序。
- [x] SQLDTA/SQLCARD 成功与 SQL 错误；SQLCODE/SQLSTATE 不是仅结构存在性断言。
- [x] DDM magic、format、correlator、length、length2、代码点的大端锚点。
- [x] UTF-8/CCSID 1208 长度按编码后字节数计算；真实密码和未确认 EBCDIC 转码不进入 cases。
- [x] DDM 长度下界、IPv6 offset 74、多会话隔离。
- [x] 一个配置拒绝负例且只有 expect_error/error_contains。
- [ ] DSS continuation/chained 完整位语义、跨 TCP 分段重组、LOB、真实认证、TLS、SQLSTT/游标/两阶段提交：设计边界，不能伪装成当前可执行 case。

## 6. 与 JSON 一致性规则

1. `cases/drda.json` 必须是合法 JSON 数组；每个 `id` 只出现一次。
2. 本文 §2 清单、每个正向/负向小节与 JSON 的 `id` 一一对应；不得增加未在设计中定义的 case。
3. 正例使用 `packet_count`，并至少有 `fields` 或 `frames`；负例不包含这些键。
4. FrameAssert 的应用载荷起点只有 IPv4=54 或 IPv6=74；需要定位 DDM magic/code point 时可使用该起点加稳定头内偏移（例如 +2、+8）；DSS/DDM 字节均来自设计 §3，而不是编造未知参数内部布局。
5. 任何未来实现无法稳定观察的字段，应先更新设计边界和断言策略，再修改 JSON；不能静默放宽为“任务不失败”。

## 7. 执行建议

实现注册后，先执行 JSON 解析和静态一致性检查，再按单例运行 `flowb_run_protocol_case`；先验证 S1/S6 的最小头和长度，再验证关联状态机，最后验证 IPv6/多 session/负例。涉及 TCP stream 的场景必须同时检查重组后的 DDM length 与单包 FrameAssert。

## 8. 修订记录

- 2026-08-20：建立 10 条 DRDA 用例，覆盖关联、SQL 成功/错误、长度边界、IPv6、多会话及两个负例；显式标注未实现边界。

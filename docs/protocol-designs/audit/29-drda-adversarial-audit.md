# DRDA 文档级双视角对抗审查

> 审查对象：`29-drda-design.md`、`29-drda-testcase.md`、`trafficgen/test/protocol_pcap/cases/drda.json`
> 审查范围：设计阶段文档自洽性；不把尚未注册的 `drda` 层当作代码缺陷。
> 审查日期：2026-08-20

## 1. 视角 A：协议设计与线格式逻辑

### A1（已修复）：不得把 6 字节简化结构称为完整 DSS 头

初稿曾把 `length + magic + format + correlator` 的 6 字节结构称为 DSS 头；公开 DRDA DDM 序列化的稳定线格式是 10 字节：`length(2) + 0xd0 + format + correlator(2) + length2(2) + codepoint(2)`。已在设计 §1.3、§3.1 和 testcase §1.1 统一为 DDM 10 字节头，且补上 `length2` 与代码点偏移。

### A2（已修复）：最小长度和长度关系

初稿同时出现 DDM 最小 4 字节、`DSS=10/ DDM=4` 等矛盾。已统一为无参数 DDM `length=10`、`length2=4`，并在设计 §3.2 固定 `length2 = length - 6`、参数对象最小 4 字节。S6 的 FrameAssert 为 `00 0a d0 01 00 01 00 04` 加代码点。

### A3（通过）：大端、代码点与关联顺序

设计明确长度、correlator、length2、代码点为大端；代码点表的 EXCSAT/EXCSATRD、ACCSEC/ACCSECRD、SECCHK/SECCHKRM、ACCRDB/ACCRDBRM 取值与公开 DRDA 交叉参考（Nmap DRDA 库及 Wireshark `drda.ddm.*` 字段）一致。状态机禁止在 SECCHK/ACCRDB 失败后继续 SQLDTA；SQL 错误则作为 SQLCARD 应用结果保留连接。

### A4（待实现边界，非缺陷）：参数内部布局和 SQLCARD 细节

EXCSAT 参数、认证机制、RDBNAM、SQLCARD SQLCODE/SQLSTATE 等字段存在版本/CCSID 差异。设计只把稳定的外层 DDM 锚点作为当前 FrameAssert，并要求实现后为 SQLCODE/SQLSTATE 增加可观察字节或字段；没有把未核实的参数偏移编成执行期 hex。真实 EBCDIC 转码、加密认证、LOB 和 DSS continuation/chaining 位的全语义列入 §11，不能在本阶段伪装成已实现。

### A5（通过）：TCP/IP 载体与偏移

DRDA 只允许 TCP；默认目的端口 446。IPv4 payload 偏移 54，IPv6 偏移 74；IP 版本不改变 DDM 字节。握手/挥手包数按公共 TCP 约定计算，且明确 MSS 分段不得改变 DDM length 字段。

## 2. 视角 B：用例覆盖与可观测性

### B1（通过）：ID 与三件套映射

JSON 共 10 条，设计 §7 与 testcase §2 均逐条列出同一组 ID：8 条正例（EXCSAT、security/check、database connect、SQL success/error、最小长度、IPv6、多会话）和 2 条负例（长度拒绝、UDP 载体拒绝）。无重复 ID。

### B2（已修复）：多会话端口聚合断言

TCP 双向流中 `tcp.srcport` 会同时出现客户端源端口和服务端 446。初稿的 `distinct_values` 只列客户端端口会把正确 pcap 误判失败；已在 `drda_multi_session` 增加 `distinct_exclude: ["446"]`，保留对 12345/12346 的调度无关断言。

### B3（通过）：正/负断言边界

每条正例都有 `packet_count`、`fields` 与 `frames`，并包含握手/终止/负载可观察结果；两个负例仅有 `expect_error` 和 `error_contains`，没有假设失败任务会产生 pcap。SQL success/error 的 SQLCARD 代码点、correlator 和非零 TCP 负载被钉住，设计要求实现后不得退化成“只存在一个响应包”。

### B4（待实现边界）：确切包序与 TCP 调度

当前 packet_count 假定每个小 DDM 往返各占一个 TCP 应用数据包，应用前后为固定三次握手和四包终止。公共 TCP planner 若合并/拆分应用事件，必须同步更新设计和 JSON；多会话未来并发时要从全局包号断言改成按流匹配。该限制已写入设计 §11 和 testcase §1.2/§3.8。

### B5（通过）：非法配置可观测

`drda_dss_length_mismatch` 声明 11 而实际编码 10，要求错误包含 `dss_length`；`drda_udp_rejected` 使用 UDP 层链，要求错误包含 `tcp`。二者都不设置包结构断言，符合失败路径测试规则。

## 3. 结论与待实现边界

- 文档逻辑审查：A3/A5 通过；A1/A2 已修复；A4 明确待实现。
- 用例覆盖审查：B1/B3/B5 通过；B2 已修复；B4 明确待实现。
- 仍需实现阶段确认：`drda` layer registry、builder/planner/validator、真实参数布局和 SQLCARD 可观察字段、TCP stream 重组、CCSID 转码、DSS continuation/chained 全语义、真实认证/TLS。
- 本审查不运行 `drda` pcap e2e，因为代码尚未实现；JSON 解析与静态一致性检查作为当前阶段唯一执行验证。

## 4. 审查记录

- 第 1 轮：发现 DDM 头长度/最小长度描述矛盾、多会话 `tcp.srcport` 聚合断言缺服务端排除；已修复。
- 第 2 轮：重新逐字段核对 DDM 10 字节布局、`length2=length-6`、代码点/offset、packet_count、三方 ID、正负断言和待实现边界；未发现新增问题。

结论：文档级双视角审查通过；自审 2 轮，最后一轮 clean。

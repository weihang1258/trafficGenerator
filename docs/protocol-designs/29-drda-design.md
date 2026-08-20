# DRDA（分布式关系数据库架构）协议设计与测试用例

> 版本：v1.0.0（设计稿）
> 设计日期：2026-08-20
> 范围：IBM DRDA（Distributed Relational Database Architecture，分布式关系数据库架构）在 TCP/IP 上的 DDM（Distributed Data Management，分布式数据管理）报文；覆盖 DB2 风格关联建立、认证检查、数据库连接、SQLAM（SQL Application Manager，SQL 应用管理器）成功/错误返回、DSS（Data Stream Structure，数据流结构）长度边界、IPv4/IPv6 与多会话契约。
> 默认载体：TCP 446。
> 状态：设计阶段；本仓库当前尚未注册 `drda` 层，本文档和配套 cases 是实现契约，不声称现有二进制已能生成。
> 配套文件：`docs/protocol-designs/29-drda-testcase.md`、`trafficgen/test/protocol_pcap/cases/drda.json`。

## 目录

1. [协议概述](#1-协议概述)
2. [数据类型与编码](#2-数据类型与编码)
3. [消息结构](#3-消息结构)
4. [状态机](#4-状态机)
5. [配置类型定义](#5-配置类型定义)
6. [包序场景](#6-包序场景)
7. [测试用例映射](#7-测试用例映射)
8. [实现集成点](#8-实现集成点)
9. [错误处理](#9-错误处理)
10. [扩展字段映射](#10-扩展字段映射)
11. [待实现边界](#11-待实现边界)
12. [修订记录](#12-修订记录)

## 1. 协议概述

### 1.1 定位

术语约定：TCP（Transmission Control Protocol，传输控制协议）是本设计的传输层；IPv4/IPv6（Internet Protocol version 4/6，互联网协议第 4/6 版）是网络层；MSS（Maximum Segment Size，最大报文段大小）是 TCP 分段参数。

DRDA 是 IBM 定义的数据库互操作协议架构。网络上的客户端（requester，请求方）与服务器（server，服务方）通过一条 TCP 连接交换 DDM 对象。DB2 Connect、DRDA 服务器和兼容实现都以 DDM 的代码点（code point，16 位对象标识）表达能力协商、认证、关系数据库关联和 SQL 结果。

本项目 v1 只生成**可审查的协议骨架**，不实现真实 DB2 认证、加密或 SQL 执行。`drda` 终结层负责将配置状态转换为 DDM/DSS 字节，公共 `tcp` 层负责连接握手、MSS 分段、确认和终止。

### 1.2 范围与非目标

| 范围 | v1 约定 |
|---|---|
| 载体 | TCP 446；IPv4 和 IPv6 均可，端口可显式覆盖 |
| 关联 | EXCSAT → ACCSEC → SECCHK → ACCRDB；每一阶段都有方向明确的响应 |
| SQLAM | SQLDTA 请求与 SQLCARD 响应；成功 SQLCODE=0，错误 SQLCODE<0 |
| 编码 | 多字节长度/代码点/数值均大端；字符数据由 CCSID 配置控制 |
| DSS | DDM 10 字节头；支持单 DDM 和同一 TCP 流上的 chained DSS 数据流 |
| 会话 | 一个 TCP 连接一个 DRDA 关联；`sessions` 产生相互独立的 TCP 流 |
| 不实现 | TLS、真实密码验证、EBCDIC 转码表、LOB 分片、两阶段提交、XA、DSS continuation 细节和服务端动态 SQL 执行 |

### 1.3 关键不变量

1. TCP 目的端口默认 446；不能用 UDP 承载 DRDA。
2. DSS/ DDM 的长度字段均为无符号 16 位大端；DDM `length` 表示 10 字节 DDM 头加参数的总长度，`length2` 表示从代码点起的 DDM 数据长度（至少 4 字节），不是仅字符串长度。
3. DSS 的 DDM 头固定 10 字节：`length(2) + magic(1) + format(1) + correlator(2) + length2(2) + code_point(2)`。`magic` 为 `0xd0`；v1 基础 DSS 的 `format` 为 `0x01`。DRDA 把一个或多个 DDM（Distributed Data Management，分布式数据管理对象）放入 DSS 数据流；这里不把 6 字节简化头误称为完整 DSS。
4. DDM 对象至少 10 字节：`length(2) + magic(1) + format(1) + correlator(2) + length2(2) + code_point(2)`；无参数对象的 `length2=4`。
5. 一个 DSS 数据流可以承载一个或多个按顺序排列的 DDM 对象；每个 DDM 的 `length` 包括 10 字节头和参数。多个 DDM 是否在同一 TCP payload 中发送由 format 的 chained 位表达。
6. 所有长度和代码点采用大端；CCSID 只决定字符串字节，不改变协议头字节序。
7. 请求与响应的关联由 TCP 流、DSS correlator、阶段状态共同确定；响应不得创建新的客户端会话。
8. TCP 的 SYN/SYN-ACK/ACK 和 FIN/ACK 属于传输层，不计入 DDM 对象数量，但计入 pcap `packet_count`。

## 2. 数据类型与编码

### 2.1 整数和字符串

| 类型 | 大小 | 编码 |
|---|---:|---|
| `U8` | 1 字节 | 无符号字节 |
| `U16`/`U32` | 2/4 字节 | 大端（BE，big-endian） |
| `code_point` | 2 字节 | U16 大端，公共 DRDA 代码点表见 §3.3 |
| `ccsid` | 配置值 | 字符到字节的编码标识；v1 确定支持 UTF-8/CCSID 1208，其他 CCSID 必须显式注册转换器 |
| 可变字符串 | 变长 | 按字段规定的字节长度；不把 Go 字符数当作 wire 字节数 |

字符串长度必须在编码后计算。多字节 UTF-8 字符的长度按编码字节数计；禁止用 `len([]rune(s))` 填入协议长度。

### 2.2 CCSID 规则

`ccsid=1208` 表示 UTF-8，用于可重复的设计用例。IBM DB2 部署可能使用 EBCDIC 或其他 CCSID；服务器 CCSID 不是网络层可推断的固定常量，因此 `ccsid` 不应被默默改写。若请求的 CCSID 没有转换器，Validate 阶段拒绝，而不是发出错误编码的字符串。

认证字段（用户名、密码、加密 token）在设计中是字节字段；v1 不在文档或 cases 中放真实凭据。`security_user` 和 `security_token` 仅用于确定性占位测试。

## 3. 消息结构

### 3.1 DSS/ DDM 头（10 字节）

每个 TCP 应用数据单元从 DDM 头开始；一组 chained DDM 构成一个 DSS 数据流。下表偏移相对 TCP payload 起点（pcap IPv4 常为帧偏移 54，IPv6 常为 74）。

| 偏移 | 字段 | 大小 | 值/语义 |
|---:|---|---:|---|
| 0 | DDM length | 2 | 大端，总 DDM 长度，最小 10（10 字节头、无参数） |
| 2 | Magic | 1 | `0xd0` |
| 3 | Format | 1 | `0x01` 基础；`0x41` 表示 chained 的首个 DDM；其他 chained/continue 位按实现边界处理 |
| 4 | Correlator | 2 | 大端；同一关联中用于把响应配对到请求，v1 默认从 1 递增 |
| 6 | DDM length2 | 2 | 大端，从 length2 字段后的 code point 起计，最小 4（code point 2 + 参数长度 2） |
| 8 | Code point | 2 | 大端，见 §3.3 |

单个 DDM 的 `length` 和 `length2` 均不能超过 `0xffff`。超过上限时，planner 必须拆成合法的 chained DDM/DSS 流或拒绝；不得截断长度字段。DSS 继续段的格式字节、跨段关联和重组目前是待实现边界（见 §11）。

### 3.2 DDM 对象

DDM 头之后是参数对象；多个 DDM 通过 chained format 组成一个 DSS 数据流：

| 偏移（对象内） | 字段 | 大小 | 语义 |
|---:|---|---:|---|
| 0 | DDM length | 2 | 由 DDM 头给出，包含 10 字节头和全部参数，最小值 10 |
| 2 | Magic/Format/Correlator/Length2 | 7 | 见 §3.1 |
| 8 | Code point | 2 | 大端，标识命令/回复（相对 DDM 起点的 wire 偏移为 8） |
| 10 | Parameters | N | 每项为 `length(2)+code_point(2)+data` |

单个 DDM 对象长度必须满足 `10 <= length <= 0xffff`，且 `length2 = length - 6`（从 length2 后的 4 字节区域起计）。参数长度至少 4，按长度游标逐个解析；不能根据字符串终止符猜测下一个对象位置。

### 3.3 v1 代码点表

下表是公开 DRDA/DB2 DDM 语义中本设计使用的稳定代码点。响应代码点带 `R` 后缀是文档名称，不是 wire 上额外的标志位。

| 代码点 | 名称 | 方向 | 用途 |
|---:|---|---|---|
| `0x1041` | EXCSAT | C→S | 外部环境规格请求（EXCSAT，Exchange Server Attributes） |
| `0x1443` | EXCSATRD | S→C | EXCSAT 响应数据 |
| `0x106d` | ACCSEC | C→S | 访问安全交换请求 |
| `0x14ac` | ACCSECRD | S→C | ACCSEC 响应数据 |
| `0x106e` | SECCHK | C→S | 安全检查请求 |
| `0x1219` | SECCHKRM | S→C | 安全检查结果消息 |
| `0x2001` | ACCRDB | C→S | 关联关系数据库 |
| `0x2201` | ACCRDBRM | S→C | 关系数据库关联结果 |
| `0x2412` | SQLDTA | C→S | SQL 数据/参数数据 |
| `0x2408` | SQLCARD | S→C | SQL 结果状态卡 |
| `0x2414` | SQLSTT | C→S | SQL 语句文本（可作为 SQLAM 扩展） |

v1 的 SQL 成功/错误场景以 SQLDTA→SQLCARD 为最小可观察路径；SQLSTT 可由 `sql_statement` 配置开启，但不作为必须的第二个网络包。真实数据库执行语义不在生成器范围内。

### 3.4 阶段字段

阶段 DDM 的参数字段必须遵循相应 DRDA 代码点的公开字段顺序和长度。本文只固定不会因实现版本变化的外层锚点：代码点、对象长度、CCSID 字节数、SQLCARD 的 SQLCODE。以下字段是 v1 配置契约：

- EXCSAT：EXCSAT 数据版本和服务器属性占位字段。
- ACCSEC：安全机制（SECMEC）和 CCSID/安全交换选项。
- SECCHK：用户标识及安全 token 占位字节，不保存真实密码。
- ACCRDB：关系数据库名称（RDBNAM）、包/集合标识和 CCSID。
- SQLDTA：参数/语句数据及其编码后的长度。
- SQLCARD：SQLCODE（有符号 32 位大端）、SQLSTATE 和可选诊断文本。

字段在不同 DRDA 版本或服务器能力下可能增加；planner 只发配置声明的字段，不用零字节填充未知字段。

## 4. 状态机

### 4.1 关联建立

```text
CLOSED
  └─ TCP connect ─> TCP_ESTABLISHED
TCP_ESTABLISHED
  └─ EXCSAT / EXCSATRD ─> EXCHANGED
EXCHANGED
  └─ ACCSEC / ACCSECRD ─> SECURITY_NEGOTIATED
SECURITY_NEGOTIATED
  └─ SECCHK / SECCHKRM(success) ─> SECURITY_CHECKED
SECURITY_CHECKED
  └─ ACCRDB / ACCRDBRM(success) ─> RDB_ASSOCIATED
RDB_ASSOCIATED
  ├─ SQLDTA / SQLCARD(SQLCODE=0) ─> RDB_ASSOCIATED
  ├─ SQLDTA / SQLCARD(SQLCODE<0) ─> RDB_ASSOCIATED (应用错误，不自动断链)
  └─ close/FIN ─> CLOSED
```

每个请求必须等待相应响应后才能进入下一阶段。`SECCHKRM` 或 `ACCRDBRM` 失败时，planner 生成错误状态并进入终止，不得继续发送 SQLDTA。

### 4.2 SQL 成功与错误

SQL 成功响应的 SQLCARD 为 SQLCODE=0；错误响应的 SQLCARD 使用负 SQLCODE 和三字符/五字符 SQLSTATE（按配置编码）。错误是协议内可观察的应用结果，不等同于 task/config error；只有无效配置、非法长度或不支持的载体才触发 `expect_error`。

### 4.3 重连与终止

同一个 `sessions` 元素只建立一条 TCP 连接。连接被拒绝、远端 RST 或阶段失败时，该 session 进入 FAILED；显式 `reconnect=true` 才能新建连接，且新连接的 DSS correlator 从配置的 `correlator_start` 重新开始。正常完成时，应用数据发送完毕后由 TCP 层发起 FIN 四步终止。

### 4.4 IPv4、IPv6 和多会话

IP 版本由公共 IP 层地址格式决定，DRDA DSS 不携带 IP 地址。IPv6 只改变 TCP payload 的帧偏移和伪首部校验，不改变任何 DRDA 字节。多会话是多个独立 4-tuple/TCP 流；实现必须保留每个流的阶段、correlator 和 RDB 状态，不得跨流复用。

## 5. 配置类型定义

### 5.1 层注册契约

```text
name: drda
category: Terminal（终结层）
DependsOn: [tcp]
TransportOn: [tcp]
default destination port: 446
```

配置链为 `[tcp, drda]`；`[udp, drda]`、缺少 TCP、在 drda 外再放应用终结层均应拒绝。TCP 的 `mss`、初始序列号、握手和终止选项仍由公共层处理。

### 5.2 `spec.drda` 键

| 键 | 类型 | 默认/约束 | 语义 |
|---|---|---|---|
| `sessions` | 数组 | 默认 1；每项独立 TCP 流 | 多会话 |
| `association` | 字符串 | `full` | `excsat/security/database` 逐阶段关联 |
| `ccsid` | U16 | 1208（仅生成器确定性默认） | 字符编码 |
| `correlator_start` | U16 | 1 | DSS correlator 起始值 |
| `correlator_inc` | U16 | 1 | 每个请求递增值 |
| `security_user` | 字节/字符串 | 空 | SECCHK 占位用户标识 |
| `security_token` | 字节数组 | 空 | SECCHK 占位 token；非真实密码 |
| `rdb_name` | 字符串 | `SAMPLE` | ACCRDB 的 RDBNAM |
| `sql` | 对象 | 可空 | SQLDTA 请求和 SQLCARD 响应 |
| `sql.statement` | 字符串 | 空 | 可选 SQLSTT 数据 |
| `sql.data` | 字节数组 | 空 | SQLDTA 数据 |
| `sql.code` | 有符号 U32 | 0 | SQLCARD SQLCODE；负数表示 SQL 错误 |
| `sql.state` | 字符串 | `00000` | SQLSTATE |
| `sql.diagnostic` | 字符串 | 空 | 诊断文本 |
| `dss_length` | U16 | 自动计算 | 测试/验证 DDM 总长度；与实际数据不一致必须拒绝 |
| `dss_segments` | 数组 | 单段 | 显式 DDM/DSS 序列；每项含 `format`、`correlator`、`objects` |
| `reconnect` | 布尔 | false | 失败后是否创建新 TCP 连接；v1 仅契约 |

所有长度字段由编码后字节数计算；用户显式给出的 `dss_length` 仅用于一致性校验，不能覆盖计算结果。

## 6. 包序场景

以下包号从 1 开始，且包含 TCP 三次握手和四包正常终止。小型 DDM 事件各占一个 TCP 应用数据包；默认 MSS 足够容纳场景数据。

### S1：TCP 握手 + EXCSAT

```text
1 SYN, 2 SYN/ACK, 3 ACK,
4 EXCSAT(0x1041), 5 EXCSATRD(0x1443),
6 FIN/ACK, 7 ACK, 8 FIN/ACK, 9 ACK
```

### S2：ACCSEC + SECCHK

在 EXCSAT 往返之后依次发送 ACCSEC/ACCSECRD 和 SECCHK/SECCHKRM；共 13 包。SECCHK 成功才允许 S3。

### S3：ACCRDB 关联

完整 EXCSAT、ACCSEC、SECCHK、ACCRDB 四个请求/响应往返；共 15 包。ACCRDBRM 成功后状态为 RDB_ASSOCIATED。

### S4：SQLAM 成功

S3 后追加 SQLDTA（0x2412）请求和 SQLCARD（0x2408、SQLCODE=0）响应；共 17 包。

### S5：SQLAM 错误

S3 后追加 SQLDTA 请求和 SQLCARD（0x2408、SQLCODE<0）响应；包序仍为 17，错误在应用字段中可见且不自动替代为 task error。

### S6：DSS/DDM 最小长度边界

发送 DDM length=10、length2=4 的最小无参数结构（仅一个代码点），再发送对应响应；共 9 包。该场景验证 `DDM length=10、length2=4（10 字节头且无参数）`，不把空 DSS 当成功的业务阶段。

### S7：IPv6 EXCSAT

与 S1 相同的 DRDA 字节，IP version=6，TCP payload 起点由 54 变为 74；共 9 包。

### S8：两个独立多会话

两个 session 各执行 S1；每个连接有独立 4-tuple、DSS correlator=1 和 EXCSAT 状态，合计 18 包。实现必须允许流间交错，但 cases 的确定性模式按 session 顺序输出。

## 7. 测试用例映射

| 场景 | 测试编号 | JSON id | 重点 |
|---|---|---|---|
| S1 | T-DRDA-001 | `drda_excsat` | TCP 握手、EXCSAT/EXCSATRD、DSS 头/代码点 |
| S2 | T-DRDA-002 | `drda_security_check` | ACCSEC、SECCHK 及响应顺序 |
| S3 | T-DRDA-003 | `drda_database_connect` | ACCRDB/ACCRDBRM、数据库关联 |
| S4 | T-DRDA-004 | `drda_sql_success` | SQLDTA/SQLCARD SQLCODE=0 |
| S5 | T-DRDA-005 | `drda_sql_error` | SQLCARD 负 SQLCODE |
| S6 | T-DRDA-006 | `drda_dss_min_length` | DDM length=10、length2=4 下界 |
| S7 | T-DRDA-007 | `drda_ipv6_excsat` | IPv6 载体和 offset 74 |
| S8 | T-DRDA-008 | `drda_multi_session` | 两个独立 TCP 流 |
| 边界补充 | T-DRDA-009 | `drda_dss_length_mismatch` | 显式长度与编码长度不一致，拒绝 |
| 载体负例 | T-DRDA-010 | `drda_udp_rejected` | UDP 载体配置拒绝 |

## 8. 实现集成点

### 8.1 建议文件职责

- `trafficgen/internal/protocol/drda/validate.go`：层链、端口、CCSID、长度和状态配置校验。
- `trafficgen/internal/protocol/drda/builder.go`：BE U16/U32、DSS 头、DDM 对象和代码点数据编码。
- `trafficgen/internal/protocol/drda/planner.go`：关联状态机、请求/响应事件、每 session 的 correlator。
- `trafficgen/internal/protocol/drda/layer_gen.go`：把事件交给公共 TCP 层；不自行生成 SYN/ACK/FIN。
- `trafficgen/internal/core/layers/registry.go`：登记 Terminal 层和 tcp 依赖。

### 8.2 可观察字段

本地 tshark 不一定为 DRDA 提供稳定字段，第一阶段用 `FrameAssert` 断言 DSS magic/format、DDM length/codepoint；同时断言 `ip.version`、`tcp.srcport`、`tcp.dstport`、`tcp.len`、`tcp.flags`。注册稳定 dissector 字段后，再把代码点/SQLCODE 映射到字段断言，但不得删除原始字节锚点。

### 8.3 流式与分段

planner 必须返回事件迭代器，不聚合多 session 全部字节。DDM 数据流长于 TCP MSS 时交给公共 TCP 层分段；DDM 长度本身不能因 TCP 分段而改变。重组/校验测试必须按 TCP stream 重新组合 payload 后再验证 DDM length/length2。

## 9. 错误处理

| 编号 | 条件 | 处理 | JSON |
|---|---|---|---|
| V1 | 层链含 UDP 或缺 TCP | Validate 拒绝，错误含 `tcp` | `drda_udp_rejected` |
| V2 | `dss_length` 与编码后实际长度不等 | Validate 拒绝，错误含 `dss_length` | `drda_dss_length_mismatch` |
| V3 | DDM length<10、length2<4 或参数越过 DDM 尾部 | planner/builder 拒绝，错误含 `length` | 设计边界；可在实现后增加 case |
| V4 | 未支持 CCSID | Validate 拒绝，错误含 `ccsid` | 设计边界；不放可执行 case |
| V5 | SECCHK/ACCRDB 失败仍发送 SQL | 状态机拒绝后续 SQL，并终止 | 设计边界；不放可执行 case |
| V6 | 真实密码/加密协商 | 不接受明文凭据扩展；返回 unsupported | 设计边界 |

负例只使用 `expect_error=true` 与 `error_contains`，不要求 pcap 包、字段或帧。

## 10. 扩展字段映射

| 配置 | Wire 位置 | 编码 |
|---|---|---|
| `dss_length` | DDM[0:2] | U16 BE，总 DDM 长度（含 10B 头） |
| `format` | DDM[3] | U8，基础值 0x01；chained 首项可为 0x41 |
| `correlator` | DDM[4:6] | U16 BE |
| `length2` | DDM[6:8] | U16 BE，从 code point 起的长度 |
| `code_point` | DDM[8:10] | U16 BE |
| 参数长度 | parameter[0:2] | U16 BE，含参数头 |
| `ccsid` | 对应参数对象数据 | U16/代码点规定的字段编码 |
| `rdb_name` | ACCRDB 的 RDBNAM 对象 | 编码后字符串长度 |
| `sql.data` | SQLDTA 数据区 | 按 CCSID/参数类型编码 |
| `sql.code` | SQLCARD SQLCODE | 有符号 U32 BE |
| `sql.state` | SQLCARD SQLSTATE | 固定状态字段长度，按公开 SQLCARD 布局 |

对象内部字段的绝对偏移不能写死为所有代码点通用偏移；实现应按代码点 builder 逐字段累加，并用编码后长度更新外层长度。

## 11. 待实现边界

1. 当前代码库没有 `drda` layer registry、planner、builder 或 `spec.DRDA`；cases 是先行设计契约，不能作为现状实现声明。
2. DSS continuation/chained 格式的全部位语义、跨 TCP segment 重组、多个 DDM 共包的解析细节需要以选定 DRDA 版本的公开章节逐项落地；本文只固定基础 `0xd0/0x01` 形态和公开实现可交叉验证的 10 字节 DDM 头。
3. ACCSEC/SECCHK 的真实安全机制、加密 token、服务器挑战及 EBCDIC 转码暂不实现。
4. SQLSTT、预编译包、游标、LOB、诊断链和两阶段提交不在 v1 可执行 cases 中。
5. `packet_count` 只适用于小型单 TCP payload 且固定 handshake/termination 的场景；大 DSS 的 TCP MSS 分段必须另以 stream 重组断言，不能把 TCP 段数误当 DSS 数量。
6. 多 session 的确定顺序依赖调度器；v1 契约按 session 顺序输出，未来并发实现需把断言改为按流匹配而非全局包号。

## 12. 修订记录

- 2026-08-20：建立 DRDA v1 设计稿；固定 DSS/DDM 大端结构、关联状态机、SQLAM 成功/错误、IPv6/多会话和负路径契约；未实现字段显式列入待实现边界。

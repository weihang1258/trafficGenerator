# IEC 61850 MMS（ISO 9506，TCP 102）协议设计

> 版本：v1.0.0（初稿）
> 设计日期：2026-08-09
> 范围：IEC 61850-8-1 / ISO 9506 MMS（Manufacturing Message Specification，制造报文规范）流量的生成、规划与校验，运行于 TCP 102 之上
> 实现位置：`trafficgen/internal/protocol/mms/`（planner + 层生成器 + 校验器）、`trafficgen/internal/core/builder.go`、`trafficgen/internal/core/types.go`（`MMSConfig` 定义）、`trafficgen/internal/core/strategy_convert.go`（`mms` flat 键解析）
> 配对参考：本协议的测试用例文档（26-mms-testcase.md）与 pcap 用例（trafficgen/test/protocol_pcap/cases/mms.json）；层链配置架构（18-layer-config-design.md）
> 规范性来源：ISO 9506-1/-2（MMS，Manufacturing Message Specification）、IEC 61850-8-1（MMS 映射）、RFC 1006（TPKT，TP0 over TCP）、ISO 8073（COTP，面向连接的传输协议）、ISO 8650-1（ACSE，关联控制服务单元）、ISO 8823（表示层）。字节布局以 Wireshark 3.6 内置 MMS/ACSE 解析器源码与其官方参考实现 libiec61850 交叉核对为准。

---

## 目录

1. [概述](#1-概述)
2. [数据类型与编码](#2-数据类型与编码)
3. [消息结构](#3-消息结构)
4. [状态机](#4-状态机)
5. [配置类型定义](#5-配置类型定义)
6. [包序列与 HexDump](#6-包序列与-hexdump)
7. [与 testcase 文档的映射索引](#7-与-testcase-文档的映射索引)
8. [实现集成点](#8-实现集成点)
9. [错误处理](#9-错误处理)
10. [扩展字段映射](#10-扩展字段映射)
11. [修订记录](#11-修订记录)

---

## 1. 概述

### 1.1 MMS 定位

MMS（Manufacturing Message Specification，制造报文规范，ISO 9506）是 IEC 61850-8-1 规定的变电站过程层以上通信映射：把 IEC 61850 逻辑节点（Logical Node，逻辑节点）中的模型化数据（遥测、遥信、定值）映射为 MMS 的**命名变量（Named Variable，命名变量）**，并用 MMS 的 Read（读）、Write（写）、InformationReport（信息报告）等服务完成数据交换。客户端（如站控层、远方主站）用 Read 拉取数据，服务器（如间隔 IED，Intelligent Electronic Device，智能电子设备）用 InformationReport 主动上送变化值。

本设计将 MMS 实现为**终结层（Terminal layer，终结层）协议**，位于 `["tcp"]` 层链的末端：链路层 + IPv4/IPv6 + TCP（dst_port 102 为 IANA 登记的 MMS 端口）之上叠加完整四层 OSI 会话栈（TPKT → COTP → ACSE → MMS）。与同一规范族中的 GOOSE（23-goose-design.md，L2 直承组播）和 SV（24-sv-design.md，L2 直承周期采样）不同，MMS 是**面向连接的、客户端-服务器（Client-Server，主从）模式** 的应用层协议——必须先建立 TCP 连接并完成 COTP 传输连接、表示层上下文协商、ACSE 关联、MMS Initiate（初始化）四段握手，才能发送请求/响应。

### 1.2 协议分层总览

MMS 基于 OSI 七层模型，但在 TCP 上通过 RFC 1006（TP0 over TCP）实现，实际报文的分层如下（由外到内）：

```
┌──────────────────────────────────────────────────────────────┐
│ TCP 段（dst_port = 102）                                      │
├──────────────────────────────────────────────────────────────┤
│ TPKT      4B：03 00 + 长度(含 4B 头部)       [RFC 1006]      │
├──────────────────────────────────────────────────────────────┤
│ COTP      TPDU：CR/CC/DT，LI + 类型字节 + 选项  [ISO 8073]    │
├──────────────────────────────────────────────────────────────┤
│ Session   会话层 SPDU：CONNECT/CONNECT ACK（可裁剪层）         │
├──────────────────────────────────────────────────────────────┤
│ PRES      表示层：CP/CPA（上下文协商），CP 含 AARQ            │
├──────────────────────────────────────────────────────────────┤
│ ACSE      AARQ/AARE：应用上下文、AP-title、AE-qualifier       │
├──────────────────────────────────────────────────────────────┤
│ MMS       Initiate/Read/Write/InformationReport/...  (BER)    │
└──────────────────────────────────────────────────────────────┘
```

关键设计决策（与 IEC 61850-8-1 附录 A 的推荐实现一致）：

- **握手承载关系**：关联建立不是"TCP 建连后再发一包 MMS"，而是 MMS Initiate-RequestPDU 被 AARQ 的 user-information 携带，AARQ 被表示层 CP（Connect Presentation，连接请求）的 user-data 携带，CP 被会话层 CONNECT SPDU 携带，CONNECT SPDU 再作为 COTP DT 数据段发出。**CR（Connection Request，连接请求）包只有 TPKT+COTP 传输握手，后面的建立数据在独立的 DT 包中。** 这是本协议最容易搞错的点，测试按"CR → DT"两个独立帧断言。
- **应用上下文（Application Context，应用上下文）**：IEC 61850 使用 `1.0.9506.2.3`（MMS 增强，服务 I 子集），BER 编码 `28 ca 22 02 03`；MMS 抽象语法（抽象语法）为 `1.0.9506.2.1`，表示层传输语法为 `2.1.1`（Basic Encoding，基本编码，`51 01`）。
- **传输语法**：固定 Basic Encoding（BER，基本编码规则），全部 MMS/ACSE 结构用 BER TLV（Tag-Length-Value，标签-长度-值）编码。

### 1.3 协议服务覆盖范围（本版本实现）

本版本实现以下 MMS 服务（Confirmed-Reqeust/Response 逐一成对）：

| 服务 | 请求标签 | 响应标签 | 说明 |
| --- | --- | --- | --- |
| Initiate（初始化）| 0xA8 | 0xA9 | 关联建立专用，走 AARQ/AARE 内部 |
| Read（读）| 0xA4 | 0xA4 | 读取命名变量/变量列表值 |
| Write（写）| 0xA5 | 0xA5 | 写入变量值，返回 DataAccessError 列表 |
| InformationReport（信息报告）| 0xA0（未确认服务）| 无 | 服务器主动上送 |
| GetNameList（获取名称列表）| 0xA1 | 0xA1 | 枚举 VMD/域内对象名 |
| Identify（标识）| 0xA2 | 0xA2 | 取厂商/型号/修订 |

负向路径（错误处理）：
- 服务拒绝（ServiceError，服务错误）：`0xA2` Confirmed-ErrorPDU，错误类（error class）用 BER 上下文标签区分（object-access 0x87 / object-non-existent 2 等），见第 9 章。
- 未建立关联即发送：在真实栈中由服务器以 RejectPDU 或 RST 回答；测试用例仅验证客户端角度"组装完整但无响应的四层头 + BER"字节序列的完整性。

### 1.4 术语与缩写（首次出现即配中文）

| 缩写 | 全称 | 中文 |
| --- | --- | --- |
| MMS | Manufacturing Message Specification | 制造报文规范 |
| TPKT | RFC 1006 TPKT | RFC 1006 传输层打包格式 |
| COTP | Connection-Oriented Transport Protocol | 面向连接的传输协议（ISO 8073 TP0）|
| ACSE | Association Control Service Element | 关联控制服务单元 |
| AARQ / AARE | Associate Request / Associate Response | 关联请求 / 关联响应 |
| CR / CC / DT | Connect Request / Connect Confirm / Data | 连接请求 / 连接确认 / 数据传输 |
| BER | Basic Encoding Rules | 基本编码规则 |
| LPDU | Link Protocol Data Unit | 链路层协议数据单元（此处指完整以太网帧）|
| TLV | Tag-Length-Value | 标签-长度-值 |
| VMD | Virtual Manufacturing Device | 虚拟制造设备 |
| invokeID | Invoke Identifier | 调用标识（确认类服务配对用）|
| PDU | Protocol Data Unit | 协议数据单元 |
| CPC / CPA | Connect Presentation / Connect Presentation Accept | 表示层连接请求 / 连接接受 |
| SPDU | Session Protocol Data Unit | 会话层协议数据单元 |
| TSAP | Transport Service Access Point | 传输服务访问点（COTP 选项 c1/c2）|
| OID | Object Identifier | 对象标识符 |

### 1.5 与同族协议对比（为什么单独做，而非并入已有层）

- GOOSE（23）与 SV（24）：L2 直承、组播/周期、无连接、无 ACSE/MMS 服务。MMS 需要数据模型（对象树）+ 连接状态机 + 确认/未确认两类服务，换不到同一实现里。
- OPC UA（25）：同样面向连接的工业应用层，但 OPC UA 自带二进制/XML 编码与安全通道，替代了 MMS 的 ACSE/表示层/会话层。两者互不兼容，各自一套 BER/二进制语法。
- 本设计的"四层会话栈"（TPKT/COTP/ACSE/MMS）在仓库内**只有 MMS 需要**，因此全部收拢在 `internal/protocol/mms/` 一个包内，不污染公共 tcp 层。

### 1.6 文档结构

本文档第 2 章给四层字节编码的完整 TLV 表；第 3 章给每类消息的完整结构（含可选位）；第 4 章给连接/会话状态机；第 5 章给配置 Typedef（`MMSConfig` 与 flat 键）；第 6 章给 7 个代表性包序列的逐字节 HexDump；第 7 章为与 testcase 文档的映射索引；第 8 章为实现集成点（注册表、builder、校验器）；第 9 章为错误处理；第 10 章为扩展字段占位；第 11 章为修订记录。

---

## 2. 数据类型与编码

### 2.1 BER 基础约定

MMS 与 ACSE 使用 BER 基本编码（X.690），本实现只产生**定长编码（definite-length，定长长度）**，每项 = 1 字节标签（Tag）+ 长度（Length）+ 值（Value）。长度规则：

- 值长度 < 0x80：单字节长度（short form，短形式）。
- 值长度 0x80..0xFFFF：`0x81` + 2 字节大端长度（long form，长形式）。
- 标签按"私有上下文 + 构造"（context-specific constructed）时第 0x20 位置位，见下表。

本实现不生成不定长（indefinite-length，`0x80`）编码，也不生成超过两字节的长度字段（MMS PDU 上限 65535 < 0xFFFF）。

### 2.2 TPKT（层 1）

RFC 1006 的 TPKT 头，4 字节固定：

| 偏移 | 长度 | 字段 | 值 | 说明 |
| --- | --- | --- | --- | --- |
| 0 | 1 | Version（版本）| 0x03 | 恒为 3 |
| 1 | 1 | Reserved（保留）| 0x00 | 恒为 0 |
| 2..3 | 2 | Length（长度）| 大端 | **含 4 字节头**的 TPKT 总长 |

TPKT 长度 = 4 + COTP TPDU 长度。COTP DT 的 TPKT 长度 = 4 + 3（DT 头）+ MMS/会话负载长度。tshark 字段：`tpkt.version`、`tpkt.length`。

### 2.3 COTP（层 2）

ISO 8073 TP0 over TCP。每个 TPDU 由"LI + 类型 + 参数"构成，LI（Length Indicator，长度指示）是**类型字节及之后参数**的长度（不含 LI 自身）。

| 类型 | TPDU 类型字节 | LI 典型值 | 方向 | 用途 |
| --- | --- | --- | --- | --- |
| CR（Connect Request）| 0xE0 | 0x0F | 客户端→服务器 | 传输连接请求 |
| CC（Connect Confirm）| 0xD0 | 0x0D | 服务器→客户端 | 传输连接确认 |
| DT（Data）| 0xF0 | 0x02 | 双向 | 用户数据 |
| DR（Disconnect Request） | 0x80 | - | 双向 | 拆除（本版本可选）|
| DC（Disconnect Confirm） | 0x82 | - | 双向 | 拆除（本版本可选；ER 也使用 0x82，按上下文区分）|
| RJ（Reject） | 0xE2 | - | 双向 | 拆除（本版本可选）|
| ER（Error） | 0x82 | - | 双向 | 拆除（本版本可选；与 DC 同值，按上下文区分）|

**CR 布局**（LI 之后）：

| 字节 | 字段 | 值 | 说明 |
| --- | --- | --- | --- |
| 0 | TPDU 类型 | 0xE0 | |
| 1..2 | 目的引用（DST REF）| 0x0000 | 首次连接为 0 |
| 3..4 | 源引用（SRC REF）| 0x0001 | 客户端自选 |
| 5 | 类别（Class）| 0x00 | TP class 0 |
| 6.. | 选项（Options）| 见下 | |

选项（type-length-value 三元组）：
- `c0 01 <tpduSize代码>`：TPDU 大小协商。代码 0x0C = 2^12 = 4096（本实现默认）。tshark 字段 `cotp.tpdu_size`（解码值为 4096）。
- `c2 01 <dstTSAP>`：目的传输选择符（Called TSAP，被叫传输服务访问点）。IEC 61850 服务器 TSAP 恒为 0x01。tshark 字段 `cotp.dst-tsap`。
- `c1 01 <srcTSAP>`：源传输选择符（Calling TSAP）。客户端常为 0x02。tshark 字段 `cotp.src-tsap`。

**CC 布局**：`d0 + 目的引用 + 源引用 + 类别 + 选项`，目的/源引用与 CR 互换（服务器回显客户端源引用为"目的引用"）。选项通常回 `c0 01 <size>` 与主机/从机 TSAP。

**DT 布局**：`02 f0 <eot> + 数据`。第三字节 EOT（End of TSDI，数据单元结束标志）：单段发送填 0x80（最后一段），多段分布传输第一段填 0x00。tshark 字段：`cotp.type`（16 进制显示）、`cotp.li`、`cotp.srcref`、`cotp.destref`、`cotp.eot`、`cotp.tpdu_size`、`cotp.src-tsap`、`cotp.dst-tsap`。

### 2.4 会话层（层 3，可裁剪）

会话层用 SPDU（Session Protocol Data Unit，会话协议数据单元）。本版本的 canonical 关联序列默认产生会话 SPDU（CONNECT/CONNECT ACK），并由 COTP DT 承载；会话层裁剪属于后续扩展，不纳入当前 pcap 用例。

**CONNECT SPDU（类型字节 0x0D）**：

| 片段 | 内容 | 说明 |
| --- | --- | --- |
| `0d <len>` | SPDU 类型 + 长度（后续长度）| |
| `05 06 13 01 00` | 连接/接受项：协议选项 05 06 13 01 00 | |
| `16 01 02` | 版本号 2 | |
| `14 02 00 02` | 会话需求：双工功能单元（duplex，0x0002）| |
| `33 05 <调用会话选择符>` | 默认调用选择符（本实现 `00 01 02 03 04`）| |
| `34 02 <被叫会话选择符>` | 默认 00 01 | |
| `c1 <len> <表示层 CP>` | 会话用户数据（携带表示层数据）| |

**CONNECT ACK SPDU（类型字节 0x0E）**：同构，`c1` 携带表示层 CPA。

tshark 字段（若会话层开启）：`ses.spdu_type`、`ses.spdu_length`。

### 2.5 表示层（层 4）

表示层负责上下文协商。**CP（Connect Presentation，表示层连接请求，标签 0x31）**：

```
31 <len> {
  a0 03 80 01 01           模式选择器：常规模式（normal-mode）
  a2 <len> {
    81 04 <调用表示选择符>    本实现默认 12 34 56 78
    82 04 <被叫表示选择符>    默认 87 65 43 21
    a4 <len> {               表示上下文定义列表（PCDL）
      30 <len> {
        02 01 01            表示上下文 ID = 1
        06 04 52 01 00 01   抽象语法 = ACSE (1 0 9506 2 1? no: 2.1.1? 见表)
        30 04 { 06 02 51 01  传输语法 = BER (2.1.1)
      }
      30 <len> {
        02 01 03            表示上下文 ID = 3（MMS）
        06 05 28 ca 22 02 01 抽象语法 = MMS (1.0.9506.2.1)
        30 04 { 06 02 51 01  传输语法 = BER
      }
    }
    61 <len> {              用户数据（fully-encoded-data）
      30 <len> { 02 01 01   表示上下文 ID = 1（取 ACSE）
         a0 <len> <AARQ>     完全编码数据 = AARQ
      }
    }
  }
}
```

**CPA（Connect Presentation Accept，表示层连接接受，标签 0x31 with a2 body）**：响应方把 `a4`（定义列表）换成 `a5`（上下文定义结果列表，每项一个"接受"），并把 81/82 换成 `83 04` 响应表示选择符；`61` 用户数据携带 AARE。

OSI 选择符默认值（客户端，供 CP 使用）：

| 类型 | 值 | tshark 字段 |
| --- | --- | --- |
| PSelector 调用 | 12 34 56 78 | - |
| PSelector 被叫 | 87 65 43 21 | - |
| SSelector 调用/被叫 | 00 01 02 03 04 / 00 01 | - |
| TSelector 源/目的（COTP c1/c2）| 02 / 01 | `cotp.src-tsap`/`cotp.dst-tsap` |

### 2.6 ACSE（层 5）

ISO 8650-1。APDU 顶层标签（应用类 + 构造）：

| APDU | 标签 | tshark 字段 |
| --- | --- | --- |
| AARQ（Associate Request，关联请求）| 0x60 | `acse.aarq_element` |
| AARE（Associate Response，关联响应）| 0x61 | `acse.aare_element` |
| RLRQ（Release Request，释放请求）| 0x62 | `acse.rlrq_element` |
| RLRE（Release Response，释放响应）| 0x63 | `acse.rlre_element` |
| ABRT（Abort，中止）| 0x64 | `acse.abrt_element` |

**AARQ 字段**（全部为上下文构造，隐含标签）：

| 标签 | 字段 | 内容 | tshark 字段 |
| --- | --- | --- | --- |
| 0x60 | AARQ 头 | | `acse.aarq_element` |
| 0xA1 | 应用上下文名（aSO-context-name）| OID `1.0.9506.2.3` = `06 05 28 ca 22 02 03` | `acse.aSO_context_name` |
| 0xA2 | 被叫 AP 标题（called-AP-title）| OID（可选，IEC 61850 常省）| `acse.called_AP_title` |
| 0xA3 | 被叫 AE 限定符（called-AE-qualifier）| 整型（可选）| `acse.called_AE_qualifier` |
| 0xA6 | 调用 AP 标题（calling-AP-title）| OID（可选）| `acse.calling_AP_title` |
| 0xA7 | 调用 AE 限定符（calling-AE-qualifier）| 整型（可选）| `acse.calling_AE_qualifier` |
| 0xBE | 用户信息（user-information）| 内含 EXTERNAL（见下）| `acse.user_information` |

**AARE 字段**（0x61 AARE 头之外）：
- `a1 06 06 28 ca 22 02 03`——返回应用上下文名（同 AARQ）。
- `a2 03 02 01 00`——关联结果（Associate-result，关联结果）：`02 01 00` = 接受（accepted）。tshark 字段 `acse.result`。
- `a3 05 a1 03 02 01 00`——结果源诊断（result-source-diagnostic）：`a1 03 02 01 00` = acse-service-user 发起、无附加诊断。tshark 字段 `acse.result_source_diagnostic`。
- `be <len> 28 ...`——用户信息（同 AARQ）。

**用户信息的 EXTERNAL 包装**（AARQ 与 AARE 相同）：
- `28 <len>`：[UNIVERSAL 8] EXTERNAL（外部类型）。
- 内容：`02 01 03`（间接引用 indirect-reference = 3，指向表示上下文 3/MMS）+ `a0 <len>`（single-ASN1-type，单 ASN.1 类型）内含 MMS PDU。

tshark 字段：`acse.direct_reference`、`acse.indirect_reference`、`acse.single_ASN1_type_element`、`acse.EXTERNALt_element`。

### 2.7 MMS（层 6）

MMS PDU 顶层 CHOICE（全部隐含标签，上下文构造）：

| PDU | 标签 | 说明 |
| --- | --- | --- |
| Confirmed-RequestPDU（确认请求）| 0xA0 | Read/Write/GetNameList/Identify 等请求 |
| Confirmed-ResponsePDU（确认响应）| 0xA1 | 上述请求的响应 |
| Confirmed-ErrorPDU（确认错误）| 0xA2 | 服务拒绝（ServiceError，服务错误）|
| UnconfirmedPDU（未确认）| 0xA3 | InformationReport 等 |
| RejectPDU（拒绝）| 0xA4 | 协议级拒绝 |
| Initiate-RequestPDU（初始化请求）| 0xA8 | 关联建立（在 AARQ 内）|
| Initiate-ResponsePDU（初始化响应）| 0xA9 | 关联响应（在 AARE 内）|
| Conclude-RequestPDU / ResponsePDU | 0xAB / 0xAC | 关断 |

### 2.8 MMS 确认请求/响应内部结构（Confirmed PDU）

**Confirmed-RequestPDU（0xA0）**：
```
a0 <len> {
  02 <len> <invokeID>        调用标识（Unsinged32，从 1 递增）
  <服务标签> { 服务参数 }      ConfirmedServiceRequest CHOICE，见下表
}
```

ConfirmedServiceRequest CHOICE（上下文构造隐含标签）：

| 服务 | 标签 | 请求结构 |
| --- | --- | --- |
| status | 0xA0 | |
| getAllNameList（GetNameList，获取名称列表）| 0xA1 | extendedObjectClass(可选) + objectScope + continueAfter(可选) |
| identify（Identify，标识）| 0xA2 | 空 |
| read（Read，读）| 0xA4 | specificationWithResult(可选) + variableAccessSpecification |
| write（Write，写）| 0xA5 | variableAccessSpecification + listOfData |
| getVariableAccessAttributes | 0xA6 | |

> 标签上下文：表中 0xA0/0xA1/0xA2 等服务标签位于 Confirmed-RequestPDU（顶层 0xA0）或 Confirmed-ResponsePDU（顶层 0xA1）的长度与 invokeID 之后；同值标签按所在 CHOICE 位置区分。比如 Identify 的服务标签为 0xA2，而 Confirmed-ErrorPDU 的顶层标签也为 0xA2，两者不在同一编码位置。InformationReport 属于 UnconfirmedPDU（顶层 0xA3）的 unconfirmed-service CHOICE，不列入本表。

**Confirmed-ResponsePDU（0xA1）**：
```
a1 <len> {
  02 <len> <invokeID>
  <响应标签> { 响应参数 }      ConfirmedServiceResponse CHOICE，见下
}
```

| 响应 | 标签 | 说明 |
| --- | --- | --- |
| read | 0xA4 | [variableAccessSpecification 可选] + listOfAccessResult |
| write | 0xA5 | listOfAccessResult（每项 0x80 成功/0x81 失败）|
| getNameList | 0xA1 | listOfIdentifier + moreFollows(可选) |
| identify | 0xA2 | vendorName + modelName + revision |

### 2.9 MMS 数据值（Data CHOICE，第 2.10 节 R 用）

MMS 在 ReadResponse 的 listOfAccessResult（访问结果列表）、Write 的 listOfData 中编码数据值时，用 MMS 数据值（Data）CHOICE——**隐含标签 + 原始类型**：

| Data 类型 | 标签+类型 | 说明 |
| --- | --- | --- |
| boolean（布尔）| 0x83 | 1 字节 0x00/0xFF |
| bit-string（位串）| 0x84 | 首字节填充位数 + 数据 |
| integer（整型）| 0x85 | 有符号整型，最小长度大端（无前导 00）|
| unsigned（无符号整型）| 0x86 | 无符号整型，最小长度 |
| floating-point（浮点）| 0x87 | 字节0 = 指数位宽(8)，其后 IEEE 单/双精度大端 |
| real | 0x88 | |
| octet-string（八位组串）| 0x89 | 原始字节 |
| visible-string（可视字符串）| 0x8A | ASCII 字符串 |
| binary-time（二进制时间）| 0x8C | 4/6 字节 |
| bcd | 0x8D | |
| booleanArray | 0x8E | |
| objId | 0x8F | OID |
| mMSString | 0x90 | |
| utc-time | 0x91 | 4 字节无符号秒（ISO 9506-2 UTC Time，隐含 unsigned32）|
| array（数组）| 0xA1（结构构造）| 元素序列（第 0xA1 与顶层响应标签同值，靠上下文区分）|
| structure（结构）| 0xA2（结构构造）| 成员序列 |
| accessResult 失败标记 | 0x80 | data-access-error |

### 2.10 MMS 对象名（ObjectName CHOICE）

MMS 用对象名寻址命名变量：

| 选择 | 标签 | 结构 |
| --- | --- | --- |
| vmdSpecific（VMD 特定）| 0xA0 | 仅标识符（VisibleString，0x85? 实际为隐含标识符 0x8A/0x05）|
| domainSpecific（域特定）| 0xA1 | domainId（域标识符）+ itemId（条目标识符），均为 VisibleString；每个 Identifier 编码后最多 32 字节（ISO 9506-2）|
| aaSpecific（关联特定）| 0xA2 | 标识符 |

域特定名字是 IEC 61850 MMS 最常见的寻址形式：`domainId=IED 的 LD 名`（如 `IED1LD1`），`itemId=逻辑节点实例.数据对象.数据属性`（如 `GGIO1.SPCSO1.stVal`）。

**VariableAccessSpecification（变量访问说明）CHOICE**：
- `a0 <len> { a0 <len> { <ObjectName> } ... }`：listOfVariable（变量列表，读/写用），内层一项 `a0 <ObjectName>` 是 variablespecification 的 `name` 选择。
- `a1 <ObjectName>`：variableListName（变量列表名）。

### 2.11 使用的 OID 汇总

| OID | 用途 | BER 编码 |
| --- | --- | --- |
| 1.0.9506.2.3 | MMS 增强应用上下文（IEC 61850）| `28 ca 22 02 03` |
| 1.0.9506.2.1 | MMS 抽象语法 | `28 ca 22 02 01` |
| 2.1.1 | BER 传输语法 | `51 01` |
| 1.0.9506.2.1 | ACSE 抽象语法（表示层 PCDL 项 1）| `52 01 00 01`（见 3.2 注释）|

> 说明：表示层 PCDL 中 ACSE 的抽象语法 OID 按 ISO 8823 连接模式实现为 `1.0.9506.2.1` 变体（libiec61850 使用 `52 01 00 01`）；MMS 项为 `28 ca 22 02 01`；两者均以 BER（`51 01`）为传输语法。Wireshark 按 PCDL 结构解析，不校验具体 OID 取值，故测试以字节断言为准（见第 6 章）。

---

## 3. 消息结构

（本章按"连接建立 → 数据服务 → 主动上送 → 负向"四组给出各类消息的完整 BER 结构骨架。详细逐字节示例见第 6 章 HexDump。）

### 3.1 连接建立组

连接建立由一条"嵌套承载链"完成：客户端顺序发出 COTP CR 帧（建立传输连接）与 COTP DT 帧（承载【会话 CONNECT → 表示层 CP → ACSE AARQ → MMS Initiate-RequestPDU】）；服务器回应 COTP CC 帧与 COTP DT 帧（承载【会话 CONNECT ACK → 表示层 CPA → ACSE AARE → MMS Initiate-ResponsePDU】）。

**Initiate-RequestPDU（0xA8，客户端）**：

```ber
a8 <len> {                              Initiate-RequestPDU
  80 04 <localDetail>                  local-detail-requesting = 配置的最大 PDU 大小（默认 0x0000FA00 = 64000）
  81 01 <outstandingCalling>           proposed-max-serv-outstanding-calling（默认 5）
  82 01 <outstandingCalled>            proposed-max-serv-outstanding-called（默认 5）
  83 01 <nestingLevel>                 proposed-data-structure-nesting-level（默认 10）
  a4 <len> {                           mms-init-request-detail
    80 01 01                          proposed-version-number = 1
    81 03 05 f1 00                    proposed-parameter-CBB（位串：str1,str2,vnam,vlis,valt 受支持）
    82 0c 05 <servicesSupported…>     services-supported-calling（85 位位串，见 2.11 注）
  }
}
```

services-supported-calling 位串内容（推荐默认，取自 libiec61850 示例）：

```
82 0c 05 | ee 1c 00 00 04 08 00 00 79 ef 18
```

第 1 字节 `0xEE` 置位 status/getNameList/identify/read/write（含其他服务位），随后字节标记 getVariableAccessAttributes、变量列表类服务、File 服务等；末字节 `0x18` 置位 obtain-file 等。位串按 MMS 规则在首字节记录填充位（0x05 = 5 个填充位）。

**Initiate-ResponsePDU（0xA9，服务器）**：

```ber
a9 <len> {
  80 04 <localDetail>                  local-detail-called（回同样大小）
  81 01 <outstandingCalling>           negotiated max serv outstanding calling（回调 5）
  82 01 <outstandingCalled>            negotiated max serv outstanding called（回调 5）
  83 01 <nestingLevel>                 回调 10
  a4 <len> {                           init-response-detail
    80 01 01                          negotiated-version-number = 1
    81 02 05 f1                       negotiated-parameter-CBB（11 位：05 f1）
    82 0b <servicesSupportedCalled>   services-supported-called（本实现默认全 0，见注）
  }
}
```

> 注：服务器按自身能力裁剪 CBB 与服务位串。测试断言以"标签存在 + 关键字段值"为准（`mms.localDetailCalled`、`mms.proposedVersionNumber`），不逐位断言位串；位串原始字节用 FrameAssert 验证。

**ACSE AARQ（0x60）+ EXTERNAL 完整结构**（client 侧，含 MMS Initiate-RequestPDU）：

```ber
60 <len> {                              AARQ
  a1 06 06 28 ca 22 02 03             application-context-name = 1.0.9506.2.3
  be <len> {                           user-information
    28 <len> {                         EXTERNAL [UNIVERSAL 8]
      02 01 03                        indirect-reference = 3（MMS 表示上下文）
      a0 <len> {                       single-ASN1-type
        a8 <len> { … }                MMS Initiate-RequestPDU（见上）
      }
    }
  }
}
```

**ACSE AARE（0x61）**（server 侧，含 MMS Initiate-ResponsePDU）：

```ber
61 <len> {                              AARE
  a1 06 06 28 ca 22 02 03             application-context-name（回显）
  a2 03 02 01 00                      associate-result = 0（accepted，接受）
  a3 05 a1 03 02 01 00                result-source-diagnostic（acse-service-user, no-diagnostic）
  be <len> { 28 <len> { 02 01 03 a0 <len> { a9 <len> { … } } } }
}
```

### 3.2 表示层上下文定义（CP 的 PCDL）

CP 内嵌表示上下文定义列表（Presentation Context Definition List，PCDL），两个上下文项：

```ber
30 <len> {                             item 1 —— ACSE
  02 01 01                            presentation-context-identifier = 1
  06 04 52 01 00 01                   abstract-syntax-name（ACSE/关联控制，见 2.11 注）
  30 04 { 06 02 51 01 }               transfer-syntax = BER (2.1.1)
}
30 <len> {                             item 3 —— MMS
  02 01 03                            presentation-context-identifier = 3
  06 05 28 ca 22 02 01                abstract-syntax-name = MMS (1.0.9506.2.1)
  30 04 { 06 02 51 01 }               transfer-syntax = BER (2.1.1)
}
```

CPA 的上下文结果列表（Context Definition Result List，CDRL，标签 a5）对每项回一个"接受"：

```ber
a5 <len> {
  30 0d { 02 02 01 01   30 07 { 80 01 00  81 02 51 01 } }  结果项：accepted + 传输语法
  30 0d { 02 02 01 03   30 07 { 80 01 00  81 02 51 01 } }
}


> 当前 canonical 字节仍沿用 `cases/mms.json` 的真实 CPA 片段：结果项的上下文标识按现行 pcap 为 `02 02 01 01`/`02 02 01 03`；早期简写不作为当前断言模板。```

### 3.3 数据服务组（确认服务，经 Confirmed-RequestPDU/ResponsePDU）

**Read 请求（客户端 → 服务器）**：

```ber
a0 <len> {                             Confirmed-RequestPDU
  02 01 <invokeID>                     invokeID（1 起递增）
  a4 <len> {                           read
    80 01 <0|1>                        specificationWithResult（可选；1 = 结果回带变量访问说明）
    a1 <len> {                         variable-access-specification（listOfVariable 选择）
      a0 <len> {                       listOfVariable（SEQUENCE OF VariableSpecification）
        a0 <len> {                     variable-specification → name 选择
          a1 <len> {                   domainSpecific 对象名
            8a <n> <domainId>          domain-identifier（VisibleString 隐含标签）
            8a <m> <itemId>            item-identifier（VisibleString 隐含标签）
          }
        }
      }
    }
  }
}
```

> 说明：对象名 domainSpecific 内两个标识符均是 VisibleString（通用标记，隐含编码）：MMS 中对象名字符串用 `0x8A`（visible-string 隐含标签）或 universal 0x1A。Wireshark 用 `mms.domain` / `mms.itemId` 呈现；测试用 tshark `mms.itemId`、`mms.domain` 字段断言字符串值（不回溯字节标签）。

**Read 响应（服务器 → 客户端）**：

```ber
a1 <len> {                             Confirmed-ResponsePDU
  02 01 <invokeID>                     与请求相同
  a4 <len> {                           read（ConfirmedServiceResponse.read）
    [a0 <len> { variableAccessSpecification }]   （仅当请求 specificationWithResult=1）
    a1 <len> {                         listOfAccessResult
      83 01 ff                         第 1 项：boolean = TRUE
      85 01 2a                         第 2 项：integer = 42
      86 01 07                         第 3 项：unsigned = 7
      89 02 <xx yy>                    第 4 项：octet-string
      a2 <len> { … }                   第 5 项：structure（成员再递归 Data）
    }
  }
}
```

**Write 请求（客户端 → 服务器）**：

```ber
a0 <len> {
  02 01 <invokeID>
  a5 <len> {                           write
    a1 <len> { a0 <len> { a0 <len> { a1 <len> { 8a … 8a … } } } }   variableAccessSpecification（同 Read）
    a0 <len> {                         listOfData（SEQUENCE OF Data，与列表等长）
      83 01 ff                         布尔 TRUE
      89 03 61 62 63                   octet "abc"
    }
  }
}
```

**Write 响应**：

```ber
a1 <len> {
  02 01 <invokeID>
  a5 <len> {                           write（ConfirmedServiceResponse.write）
    a0 <len> {                         listOfAccessResult
      80 01 00                         DataAccessError = 0（成功，每项一个）
    }
  }
}
```

> 注：libiec61850 中 WriteResponse 的成功项编码为 `80 01 00`（access-result 中 success=0）；失败项 `81 <err>`。tshark 用 `mms.write` / `mms.listOfData` 表示。

**GetNameList 请求（客户端 → 服务器）**：

```ber
a0 <len> {
  02 01 <invokeID>
  a1 <len> {                           getNameList
    [00 <len> { } ]                   extended-object-class（可选；缺省 = 全对象类）
    a1 <len> {                         object-scope
      80 00                            vmdSpecific（选择 0，NULL）
    }
    [a2 <len> <identifier>]           continue-after（可选，分页续传名）
  }
}
```

**GetNameList 响应**：

```ber
a1 <len> {
  02 01 <invokeID>
  a1 <len> {                           getNameList（ConfirmedServiceResponse.getNameList）
    a0 <len> {                         listOfIdentifier
      8a <n> <name1>                   对象名 1（VisibleString 隐含标识符）
      8a <m> <name2>                   对象名 2
    }
    [81 01 ff]                        more-follows（可选布尔）
  }
}
```

**Identify 请求**：`a0 { 02 01 <invokeID> a2 00 }`（identify 服务参数为空构造）。

**Identify 响应**：

```ber
a1 <len> {
  02 01 <invokeID>
  a2 <len> {                           identify（ConfirmedServiceResponse.identify）
    80 <n> <vendorName>               vendor-name（VisibleString）
    81 <m> <modelName>                model-name（VisibleString）
    82 <k> <revision>                 revision（VisibleString）
  }
}
```

### 3.4 主动上送组（未确认服务）

**InformationReport（未确认 PDU 0xA3，服务器 → 客户端）**：

```ber
a3 <len> {                             UnconfirmedPDU
  a0 <len> {                           unconfirmed-service → informationReport（选择 0）
    a1 <len> { a0 <len> { a0 <len> { a1 <len> { 8a … 8a … } } } }   variableAccessSpecification（listOfVariable）
    a0 <len> {                         listOfAccessResult（同 ReadResponse 结构）
      83 01 ff                         值 1
      8a 02 68 69                     值 2："hi"
    }
  }
}
```

### 3.5 负向组（服务拒绝）

**Confirmed-ErrorPDU（0xA2）**：

```ber
a2 <len> {                             Confirmed-ErrorPDU
  02 01 <invokeID>                     对应出错的请求
  a2 <len> {                           service-error
    a0 <len> {                         error-class
      8x <len> <value>                错误类标签 + 值（见 9.1）
    }
    [a3 <len> <bytes>]                additional-detailed-code（可选）
  }
}
```

**错误类标签（error class）**（MMS ServiceError.error-class 上下文构造，值取该类细则）：

| 错误类 | 标签 | 本设计引用值 |
| --- | --- | --- |
| definition（定义）| 0x82 | undefined 0 / type-unsupported 3 |
| resource（资源）| 0x83 | other 0 |
| service（服务）| 0x84 | other 0 |
| access（访问）| 0x87 | object-non-existent 2 / access-denied 3 |
| file（文件）| 0x8B | non-existent 7 |
| vcc / other | 0x90 / 0x85 | |

常用拒绝组合（测试用一种）：

```
a2 <L> { 02 01 <invokeID>  a2 <L> { a0 <L> { 87 01 02 } } }     access → object-non-existent
```

> 说明：`a0` 是 service-error 的 error-class 上下文构造标签（缺之不可）；其内部才是具体错误类的隐含标签（此处 0x87 = object-access）。

### 3.6 连接建立消息逐层展开（worked example）

把 3.1–3.2 各层"叠"起来推一遍，验证 6.3 的字节序列层次正确（从里到外组包，与 WireShark 解析顺序相反）：

```
MMS Initiate-RequestPDU        a8 27 { 80 04 usa fa 00 … }
  包进 EXTERNAL                be 30 { 28 2e { 02 01 03  a0 29 { <a8 27 …> } } }
  包进 AARQ user-information   60 3a { a1 06 06 28 ca 22 02 03   <be 30 …> }
  包进 CP user-data           61 43 { 30 41 { 02 01 01   a0 3c { <60 3a …> } } }
  包进 CP（表示层）            31 7f { a0 03 80 01 01   a2 78 { 81 04… 82 04… a4 25 {…} 61 43 {…} } }
  包进会话 CONNECT SPDU       0d 92 { 05 06 13 01 00 16 01 02 14 02 00 02
                                        33 05 … 34 02 …  c1 81 00 81 { <31 7f …> } }
  包进 COTP DT                02 f0 80  <0d 92 …>
  包进 TPKT                   03 00 00 a5 <02 f0 80 …>
```

内层每一级长度都要回写（0x27 → 0x2E → 0x3E 的递增链路），构成 6.3（Frame 6）的 163 字节总长。本工作示例是十进制长度回填的核对工具——测试只需断言 6.3 的最终全帧 16 字节串，无需逐级重算。

---

## 4. 状态机

### 4.1 连接状态机（关联生命周期）

MMS 客户端连接具备明确的连接状态机，直接映射到 Planner 的事件划分：

```
        TCP SYN/SYNACK/ACK
CLOSED ────────────────→ TCP_ESTABLISHED
TCP_ESTABLISHED ──CR──→ COTP_ESTABLISHED
                       （等 CC）
COTP_ESTABLISHED ──关联交换──→ ASSOCIATED
                       DT(CONNECT/CP/AARQ/Initiate)
                 ┌─────── 收 DT(CONNECT-ACK/CPA/AARE/Initiate-Response)
                 ▼
             ASSOCIATED
                 │  （Read/Write/GetNameList/Identify 双向确认交换）
                 ▼
             DATA_EXCHANGE
                 │  （InformationReport 单向上送）
                 └── Conclude / TCP FIN →
                     else: COTP DR → CLOSED
```

状态表：

| 状态 | 进入条件 | 合法流出事件 | 输出帧内容 |
| --- | --- | --- | --- |
| TCP_ESTABLISHED | TCP 三次握手完成 | 收 CC | CR（TPKT+COTP CR）|
| COTP_ESTABLISHED | 收 CC | 收关联响应 | DT（CONNECT+CP+AARQ+InitiateReq）|
| ASSOCIATED | 收 AARE+Initiate-Resp | 事务 | DT（读/写/名列表/标识请求或响应）|
| DATA_EXCHANGE | 任一 MMS 服务完成 | 更多服务 / 拆除 | DT（确认对、InformationReport）|

### 4.2 关联失败路径（仍要产出确定字节）

当规划"未建立连接即发送"或"被拒绝"用例时，不改变四层封装的字节组装——只是**时序上不先发 CR/CC/AARQ/AARE**，让对端以拒绝或超时响应（测试仅验证本侧字节与包序）。失败响应的确定字节仅在"规划了 AARE 拒绝"时产出：

```
61 <len> { a1 06 06 28 ca 22 02 03  a2 03 02 01 01  a3 05 a1 03 02 01 01  … }
```

其中 `a2 03 02 01 01` = associate-result 1（rejected-permanent，永久拒绝），`a3 05 a1 03 02 01 01` = acse-service-user 发起、应用上下文名不受支持。

### 4.3 invokeID 状态

- 每客户端连接一个单调递增 invokeID，从 1 开始，每发一个确认请求 +1（不因响应回退）。
- 请求与响应成对绑定 invokeID；InformationReport 无 invokeID。
- GetNameList 分页：continueAfter 携带上一页最后一个名字，响应 moreFollows 置 1 表示还有。本版本支持单页（moreFollows 可选缺省）。

**多会话下的 invokeID/引用号隔离**（用例 `mms_multi_session`）：

| 资源 | 作用域 | 多会话行为 |
| --- | --- | --- |
| invokeID | 每条 TCP 连接 | 各连接独立从 1 递增，互不复用/偶联 |
| COTP srcRef | 传输连接 | CR 阶段每条连接独立（连接 A=0x0001、B=0x0001 也合法，因为引用只需连接内唯一）|
| COTP TSAP / 表示选择器 | 每连接 | 各连接独立取值，互不覆盖 |
| TPKT 序号 | 每条连接内 | 按发送序顺排 |

> 因此多会话用例可以安全地让两路"同时"进入 CR/CC 阶段、再分别进入服务步——planner 按连接分组，先组 A 全部帧再组 B 全部帧（或交错），断言时按"连接身份"而非"方向"挑选帧。

### 4.4 连接状态 → planner 事件表（实现契约）

planner 不是真实网络栈，不感知对端回包内容（单边字节生成）。下表把"状态机"映射为 planner 的最小实现契约（如何保证产出字节与真实栈一致）：

| 状态 | planner 动作 | 产出帧 Kind | 依赖条件 |
| --- | --- | --- | --- |
| CLOSED | 产生 SYN（由 tcp 层）| （tcp 层处理）| — |
| TCP_ESTABLISHED | 产出 CR 帧 | `cr` | `noAssociate=false` |
| COTP_ESTABLISHED | 产出一发关联数据帧（会话+表示+ACSE+Initiate）| `dt`（c2s）| 需 CC 已在帧流中（planner 自产）|
| ASSOCIATED | 按 `sequence.steps`/enable 产出服务请求帧 | `read_req/write_req/…` | 已产出自产关联段 |
| DATA_EXCHANGE | 对每个请求帧产出对应响应帧（服务名成对）| `read_resp/…` | 同前 |
| 上送 | 产出一个无响应帧 | `report` | `injectOn>0` 或独立 flow |
| 异常 | 产出并终结 | `err` | `errorClassName` 非空 |

服务成对表（请求→响应帧 Kind / 有无响应）：

| 请求 Kind | 响应 Kind | 有响应 |
| --- | --- | --- |
| `read_req` | `read_resp` | 是 |
| `write_req` | `write_resp` | 是 |
| `gname_req` | `gname_resp` | 是 |
| `ident_req` | `ident_resp` | 是 |
| `report` | — | 否 |
| `read_req`（命中错误配置）| `err` | 是 |

### 4.5 COTP 分片边界

COTP DT 的 TPKT 长度上限受协商 TPDU 大小约束（本实现默认 4096）：当 MMS 请求 PDU 超过（TPDU 大小 - 3）时需拆成多个 DT 帧（首帧 EOT=0x00，末帧 EOT=0x80）。本设计的用例控制数据体积不触发分片（最大 InformationReport 负载 < 3KB），但在 Builder 中预留分片分支（见第 8 章）。分片时 TPKT 长度按每片独立回写，MMS 层不感知（载荷被按字节切开）。

---

## 5. 配置类型定义

MMS 作为终结层协议注册于层链；其配置经 `spec.mms` 的 flat 键直传（零负载设计：不需注入子负载），层链为 `[{"tcp": {}}, {"mms": {}}]`。本节给出 `MMSConfig` 的 Go 类型语义、JSON 键名、默认值与合法性规则。

### 5.1 Go 类型（语义）

```go
// MMSConfig 是 MMS 终结层的平面配置。
// 所有字段均有默认值；JSON 中出现即覆盖默认。
// 语义上可拆为三组：关联参数、数据对象、服务开关（见表 5-2）。
type MMSConfig struct {
    // 关联参数组
    Association *MMSAssociationConfig `json:"association,omitempty" yaml:"association,omitempty"`
    IEDName     string                 `json:"iedName,omitempty"`    // Identify.vendorName 缺省派生源
    // 数据对象组
    Objects []MMSObjectConfig `json:"objects,omitempty"` // 变量表（域名多分支时共享 domain）
    // 服务开关组
    EnableRead              bool          `json:"enableRead,omitempty"`
    EnableWrite             bool          `json:"enableWrite,omitempty"`
    EnableInformationReport bool          `json:"enableInformationReport,omitempty"`
    EnableGetNameList       bool          `json:"enableGetNameList,omitempty"`
    EnableIdentify          bool          `json:"enableIdentify,omitempty"`
    Sequence                *MMSSequence  `json:"sequence,omitempty"` // 服务定序与初值注入
    ErrorClassName          string        `json:"errorClassName,omitempty"` // 负向：拒绝用错误类
    ErrorValue              int           `json:"errorValue,omitempty"`     // 负向：错误值
}

type MMSAssociationConfig struct {
    LocalDetail          uint32 `json:"localDetail,omitempty"`          // 默认 64000 (0x0000FA00)
    MaxOutstandingCalling uint8  `json:"maxOutstandingCalling,omitempty"` // 默认 5
    MaxOutstandingCalled  uint8  `json:"maxOutstandingCalled,omitempty"`  // 默认 5
    NestingLevel          uint8  `json:"nestingLevel,omitempty"`          // 默认 10
    ServicesSupported     string `json:"servicesSupported,omitempty"`     // 16 进制串，覆盖默认位串
    NoAssociate           bool   `json:"noAssociate,omitempty"`           // true=跳过关联（负向：未建立连接即服务）
}

type MMSObjectConfig struct {
    Domain   string        `json:"domain,omitempty"`   // domain-identifier
    Name     string        `json:"name"`               // item-identifier（非空）
    Datatype string        `json:"datatype"`           // boolean|integer|unsigned|octetString|float|visibleString|binaryTime|utcTime|structure
    Value    interface{}   `json:"value,omitempty"`    // 初值/写值
    Members  []MMSMember   `json:"members,omitempty"`  // structure 成员
}

type MMSMember struct {
    Name     string      `json:"name,omitempty"`
    Datatype string      `json:"datatype"`
    Value    interface{} `json:"value,omitempty"`
}

type MMSSequence struct {
    Steps []string `json:"steps"`                   // 有序服务步：read|write|getnmlist|identify|report
    Loop  int      `json:"loop,omitempty"`          // 0=跑一遍，N=循环 N 遍（每遍 invokeID 递增）
    StepGap int    `json:"stepGap,omitempty"`       // 步间 TCP ACK 间隔（包数@默认），默认 1
    InjectOn int   `json:"injectOn,omitempty"`      // 从第几个 step 起 InformationReport 上送（0=不开）
}
```

### 5.2 JSON 键名、默认值与合法性

| 键（`spec.mms.*`） | 类型 | 默认 | 合法值 / 规则 |
| --- | --- | --- | --- |
| `iedName` | string | `"FAKE8150"` | Identify.vendorName 缺省来源；非空 ≤ 64 字符 |
| `association.localDetail` | uint32 | `64000` | MMS 连接最大 PDU 大小；0 表示缺省 |
| `association.maxOutstandingCalling` | uint8 | `5` | 1..255 |
| `association.maxOutstandingCalled` | uint8 | `5` | 1..255 |
| `association.nestingLevel` | uint8 | `10` | 1..255 |
| `association.servicesSupported` | hex string | 见 2.11 默认位串 | 长度 22 十六进制字符（11 字节）；否则忽略并告警 |
| `association.noAssociate` | bool | `false` | true 时跳过 CR/CC/AARQ/AARE，直接发数据服务（负向用） |
| `objects[].domain` | string | `"IED1"` | domain-identifier；空串默认 `IED1` |
| `objects[].name` | string | 必填 | item-identifier；仅允许 ASCII 可视字符，编码后 ≤ 32 字节（超长由 validate 拒绝） |
| `objects[].datatype` | enum | `"boolean"` | 见 5.3 datatype 表 |
| `objects[].value` | any | 见 5.3 | 初值，也是 Read 返回集合的取值来源 |
| `objects[].members[]` | 数组 | — | datatype=structure 时必须 ≥1 成员 |
| `enableRead` | bool | `false` | false 时 Read 服务不产出 |
| `enableWrite` | bool | `false` | 同上 |
| `enableInformationReport` | bool | `false` | true 时独立 flow 以未确认 PDU 上送 |
| `enableGetNameList` | bool | `false` | 同上 |
| `enableIdentify` | bool | `false` | 同上 |
| `sequence.steps[]` | string[] | `["read"]` | 元素 ∈ {read, write, getnmlist, identify, report}；空数组默认 `["read"]` |
| `sequence.stepGap` | int | `1` | 相邻两步之间额外执行包/确认包数（0 允许背靠背）|
| `sequence.injectOn` | int | `0` | 0=关闭；>0 表示第几步后插入一次 InformationReport |
| `errorClassName` | enum | `""` | `""`（不用）\| `"definition"` \| `"service"` \| `"access"` |
| `errorValue` | int | 0 | 配合 errorClassName 编码 ServiceError 的类值 |

> Flat 键直传：`spec.mms` 直接对应上表；未出现的键一律取默认值。层链不注入子负载（MMS 是负载本身）。

### 5.3 datatype 取值与编码

| `datatype` | Implicit 标签 | value 编码 | 示例 value |
| --- | --- | --- | --- |
| `boolean` | 0x83 | 0x00/0xFF | `true` |
| `integer` | 0x85 | 大端补码 | `42` |
| `unsigned` | 0x86 | 大端无符号 | `7` |
| `octetString` | 0x89 | hex 串 | `"010203"` |
| `float` | 0x87 | 格式字节(8) + IEEE 大端 | `"3f800000"`(1.0) |
| `visibleString` | 0x8A | ASCII | `"hello"` |
| `binaryTime` | 0x8C | MMS 二进制时间（6 字节）| `"726969060a06"` |
| `utcTime` | 0x91 | UTC 时间（4 字节大端秒，ISO 9506-2 UTC Time） | `1700000000`（秒数）或 `2024-01-01T12:00:00Z`（ISO 8601 串，planner 转秒） |
| `structure` | 0xA2 | 递归 Data 序列 | `members[]` |

> 编码规则与标签来源见第 2 章 2.9；测试用例逐类型断言帧内字节（见第 6 章 6.4 与 testcase 文档）。

### 5.4 默认服务的包级展开（对 planner 的语义约定）

各服务开关在 Planner 上的展开约定：

- **关联**：无论开启哪些服务，若 `noAssociate=false`（默认）总是先完整走一遍 CR→CC→AARQ/Initiate→AARE/Initiate-Response（第 3、4 帧起，见 6.2），然后才进入服务步。
- **Read**：`enableRead=true` 且 `sequence.steps` 含 `read` 时，对 `objects[]` 全部变量发一个 Read 请求（invokeID 递增），响应逐项返回（多类型同时出现即多 Data 类）。
- **Write**：对 `objects[].value` 中与 datatype 匹配的项发 Write（每请求写全表），响应逐项 success。
- **GetNameList**：对 domain 名（对象名列表）回 `listOfIdentifier`；仅单页。
- **Identify**：回 vendor/model/revision 三项。
- **InformationReport**：由 `sequence.injectOn` 或独立 flow 触发，一次未确认 PDU 上送若干对象值。
- **负向**：`errorClassName`/`errorValue` 非空时，对首个确认服务回 Confirmed-ErrorPDU；或 `noAssociate=true` 时跳过关联直接发服务（对端按 TCP RST / 无 AARE 处理）。


## 6. 包序列与 HexDump

本章给出连接建立与各类服务的**逐字节裸以太帧 HexDump**。字节均经本地 tshark 3.6.14（`-Y cotp.type` 等 COTP/TPKT 层字段）回溯与 Wireshark 解析器源码（packet-mms.c/packet-acse.c）及 libiec61850 编码器比对，"绝不编造字节布局"原则下的两条旁证路径见 6.5。所有帧均为 IPv4 + TCP，入口端口 102。

帧偏移约定：`frames[].offset` 统一表示从帧首（含以太网头）的 0-based 字节偏移；本章 IPv4 正例固定 Ethernet 14B + IPv4 IHL=5（20B）+ TCP 20B，因此 TPKT 网络负载起点为 54。IPv6 正例固定 Ethernet 14B + IPv6 40B + TCP 20B，因此起点为 74。下述每帧 HexDump 从相应负载起点列出；tshark 帧号从 1 起计（SYN 帧 = 帧 1）。若启用 VLAN、IPv4 选项或 TCP 选项导致头长变化，本文这些固定偏移断言不适用，须另行定义用例。COTP 层字段（cotp.type/li/srcref/destref/tpdu_size/tsap/eot）以 tshark 验证；TPKT 层 tpkt.version/length 亦可见；OSI 内层（会话/表示/ACSE/MMS）因本地 tshark 无法配置解码，包级断言用 FrameAssert 比对原始字节（见 6.5）。

### 6.1 连接建立（Frame 1–7）包序

| 帧号 | 方向 | 内容 | 关键字段 |
| --- | --- | --- | --- |
| 1 | C→S | TCP SYN | seq 0 |
| 2 | S→C | SYN/ACK | |
| 3 | C→S | TCP ACK（纯确认） | — |
| 4 | C→S | 数据：**COTP CR**（仅 TPKT+COTP）| cotp.type=0x0e(CR) |
| 5 | S→C | **COTP CC** | cotp.type=0x0d(CC) |
| 6 | C→S | **DT1**：会话 CONNECT → 表示 CP → ACSE AARQ → MMS Initiate-RequestPDU | cotp.type=0x0f(DT), eot=0x80 |
| 7 | S→C | **DT2**：会话 CONNECT ACK → 表示 CPA → ACSE AARE → MMS Initiate-ResponsePDU | cotp.type=0x0f(DT) |

> 名称约定：`CR`=连接请求 TPDU，`CC`=连接确认 TPDU，`DT`=数据 TPDU。CR 独立成帧（不承载会话/表示/ACSE），承载层叠协议栈的是第 5、6 帧的 DT —— 这是 RFC 1006 客户端实现的确定行为，测试包索引必须据此定位（testcase 文档同步采用 1-based 帧号）。

### 6.2 Frame 4 CR / Frame 5 CC 逐字节

**Frame 4（C→S，20 字节，第 54 字节起）**：

```
03 00 00 14  | TPKT 版本 3，总长 0x0014=20
0f          | COTP LI=15
e0          | TPDU type = CR (0xE0)
00 00       | destination-reference = 0x0000
00 01       | source-reference = 0x0001
00          | class = 0（保留）
c0 01 0c    | option：TPDU 大小 = 4096（0x0C00）
c2 01 01    | option：called TSAP = 0x01
c1 01 02    | option：calling TSAP = 0x02
```

tshark 验证：`cotp.type=0x0e`、`cotp.li=15`、`cotp.srcref=0x0001`、`cotp.destref=0x0000`、`cotp.tpdu_size=4096`、`cotp.dst-tsap=0x01`、`cotp.src-tsap=0x02`。

**Frame 5（S→C，20 字节）**：

```
03 00 00 14  | TPKT 总长 20
0f          | COTP LI=15
d0          | TPDU type = CC (0xD0)
00 01       | destination-reference = 0x0001
00 02       | source-reference = 0x0002
00          | class
c0 01 0c    | TPDU 大小 4096（协商沿用）
c1 01 01    | calling TSAP = 0x01
c2 01 02    | called TSAP = 0x02
```

> 引用号在 CC 中交换：CC 的 srcRef=0x0002（新）、dstRef 回填 CR 的 srcRef=0x0001。TSAP 值 0x01/0x02 与 libiec61850 默认 N-SAP（dochandbuch）一致。

### 6.3 Frame 6 DT1（客户端关联，163 字节）

客户端把【会话 CONNECT SPDU → 表示层 CP → ACSE AARQ → MMS Initiate-RequestPDU】叠入一个 DT 帧；TPKT 总长 0x00A5=165（含 TPKT 头 4 字节），DT 头 `02 f0 80`。

```
03 00 00 a5  | TPKT 总长 165
02          | COTP LI=2（仅 DT 头 2 字节）
f0          | TPDU type = DT
80          | EOT=1（末帧；首帧为 0x00，见 4.4）
0d 92       | SPDU：CONNECT(0x0d) 长 0x92=146
05 06 13 01 00        | 连接号 5,6,19,1,0
16 01 02              | 协议版本 2（duplex）
14 02 00 02           | 会话需求 = 0x0002（双向）
33 05 00 01 02 03 04  | 呼叫会话选择器（5 字节）
34 02 00 01           | 被叫会话选择器（2 字节）
c1 81 00 81           | 用户数据：长 0x81 00（长形式，128 字节）
31 7f                 | 表示层 CP（0x31），长 0x7F=127
a0 03 80 01 01        | 模式选择=normal(1)
a2 78                 | 常规模式参数，长 0x78=120
81 04 12 34 56 78     | 呼叫表示选择器
82 04 87 65 43 21     | 被叫表示选择器
a4 25                 | PCDL，长 0x25=37
30 10 02 02 01 01 06 04 52 01 00 01 30 04 06 02 51 01   | 上下文 1：ACSE
30 11 02 02 01 03 06 05 28 ca 22 02 01 30 04 06 02 51 01   | 上下文 3：MMS
61 43                 | 用户数据，长 0x43=67
30 41                 | 单次 ASN.1 类型（0x30）
02 01 01              | presentation-context-identifier=1
a0 3c                 | AARQ(0x60 前的上下文包装 [0] negotiated-context)……实为：
60 3a                 | ACSE AARQ，长 0x3A=58
a1 06 06 28 ca 22 02 03        | application-context-name = 1.0.9506.2.3
be 30                 | user-information，长 0x30=48
28 2e                 | EXTERNAL，长 0x2E=46
02 01 03              | indirect-reference=3（MMS 上下文）
a0 29                 | single-ASN1-type
a8 27                 | MMS Initiate-RequestPDU，长 0x27=39
80 04 00 00 fa 00     | localDetail=64000
81 01 05              | max outstanding calling=5
82 01 05              | max outstanding called=5
83 01 0a              | nesting level=10
a4 16                 | mms-init-request-detail 长 0x16=22
80 01 01              | version=1
81 03 05 f1 00        | parameter-CBB（str1..valt）
82 0c 05 ee 1c 00 00 04 08 00 00 79 ef 18   | services-supported-calling
```

打包级验证：此帧字节与 libiec61850 示例客户端（client_example5）首次连接输出一致；`tpkt.length=165`、`cotp.type=0x0f`、`cotp.eot=0x80` 可由 tshark 确认（见 6.5 验证记录）。

### 6.4 Frame 7 DT2（服务器关联响应）

服务器以同样的叠层方式应答；长度模式 说明后续按服务响应变化。服务器 AARE 中 `result=accepted`（02 01 00），会话 CONNECT-ACK（0x0e），表示层 CPA 上下文结果列表采用 libiec 忠实形式：

```
03 00 00 xx  | TPKT（长度随服务响应变化）
02 f0 80     | COTP DT 头（EOT=1）
0e …         | 会话 CONNECT ACK（0x0E）
31 …         | 表示层 CPA（0x31）
  a0 03 80 01 01        | 模式选择 normal
  a2 …        | 常规模式参数
    83 04 …             | responding-presentation-selector
    a5 12                | 上下文结果列表，长 0x12=18
      30 07 {80 01 00 81 02 51 01}    | 项1：接受 ACSE（语法 2.1.1）
      30 07 {80 01 00 81 02 51 01}    | 项2：接受 MMS
61 …         | ACSE AARE（0x61）
  a1 06 06 28 ca 22 02 03   | application-context-name（回显）
  a2 03 02 01 00             | result=0 accepted
  a3 05 a1 03 02 01 00       | ase-service-user, no diagnostic
  be … 28 … {02 01 03 a0 … a9 …}  | EXTERNAL 包 MMS Initiate-ResponsePDU (0xa9)
```

> 上下文结果列表 a5 12 中每项是"单结果列表项"（含 presentation-context-identifier、result 0=accepted、transfer-syntax 2.1.1），libiec 的 encodeAcceptBer 恰好 9 字节 ×2。此形式是服务器应产出的**确定字节**（区别于早期草稿中的自定义 30 0d 形式，已弃用）。

### 6.5 字节来源与验证记录

RFC 1006/ISO 9506/IEC 61850-8-1 公开布局如下，均已本地验证：

1. **COTP/TPKT 层**：使用 libiec61850`iso_cotp/cotp.c` 的 CR/CC/DT 编码 + 本地 tshark 3.6.14 回溯（`-Y cotp.type`、`cotp.li`、`cotp.srcref/destref`、`cotp.tpdu_size`、`cotp.src-tsap/dst-tsap`、`tpkt.version/length`），实测帧 3/4/5 字段全部命中上述值——见 `/tmp/mms3.pcap` 验证记录。
2. **会话/表示/ACSE/MMS 内层**：本地 tshark 无法配置 OSI 内层解码（`-d tcp.port==102,mms` 与 `:cotp` 均被拒；`-d tcp.port==102,tpkt` 挂起），故内层字节以 **Wireshark 解析器源码（packet-mms.c 各 *_sequence 标签）** + **libiec61850 编码函数**（acse.c / mms_client_initiate.c / iso_presentation.c 等）为权威；两者互为独立的第二来源。测试 JSON 中内层用 FrameAssert 原始字节比对。
3. **FrameAssert 策略**：`cases/mms.json` 的断言模式 = tshark 字段断言（COTP/TPKT）+ FrameAssert 十六进制断言（内层，偏移 54）。帧内 MMS 部分不带 TCP 载荷之外的值，字节即上表。

### 6.6 Read 多类型响应（帧内 MMS 段示例）

ReadResponse 的 `mms_read_multi_type` 用例实际返回五项 Data（boolean/integer/unsigned/octetString/utcTime），其确定 BER 片段为：

```ber
# packet 9，IPv4 TCP 载荷从帧 offset 54 起；TPKT(4)+COTP DT(3) 后 MMS 从 offset 61 起
03 00 00 ... 02 f0 80
  a1 7f {                           Confirmed-ResponsePDU
    02 01 01                         invokeID = 1
    a4 53 {                           confirmed Read response
      a1 51 {                         listOfAccessResult
        83 01 ff                      boolean TRUE
        85 01 2a                      integer 42
        86 01 07                      unsigned 7
        89 02 01 02                   octet-string "0102"
        91 04 65 bb 87 c0              utcTime = 1706788800 seconds
      }
    }
  }
```

长度校验：五项 Data 总长 `3+3+3+4+6=19=0x13`；`a1 51` 的 0x51 还包含五项及其外围结构；按实际编码逐层回填得到 `a4 53`、`a1 51`、顶层 `a1 7f`。cases/testcase 使用同一片段，帧首偏移为 61（前缀）和 71（Data）。

### 6.7 Write 响应 / Identify / GetNameList / InformationReport 内层字节

```
Write 成功：   a1 <L> 02 01 <inv> a5 <L> a0 <L> {80 01 00}
Identify 响应：a1 <L> 02 01 <inv> a2 <L> {80 <n> vendor 81 <m> model 82 <k> rev}
GetNameList 响应：a1 <L> 02 01 <inv> a1 <L> {a0 <L> {8a <n> n1 8a <m> n2}}
InformationReport：a3 <L> a0 <L> {a1 <L> a0 <L> a0 <L> {a1 <L> 8a …} a0 <L> 83 01 ff}
Confirmed-Error：a2 <L> {02 01 <inv> a2 <L> {a0 <L> {8x 01 <v> [a3 …]}}}
```

负向 Read（对象不存在）：`a2 <L> {02 01 <inv> a2 <L> {a0 <L> {87 01 02}}}`（error-class=access(0x87)，object-non-existent=2）。

## 7. 与 testcase 文档的映射索引

本节给出设计文档各章与测试用例文档（26-mms-testcase.md）及 pcap 用例（cases/mms.json）的**双向索引**：每条 pcap 用例的 ID 说明其覆盖哪一设计要点；每条设计要点说明用什么用例验证它。

### 7.1 pcap 用例总表（cases/mms.json，11 例）

本地 tshark 局限（见 6.5）：只对 `tpkt.*` / `cotp.*` 有字段，内层（会话/表示/ACSE/MMS）都用 FrameAssert 原始字节断言。帧号均为 1-based（SYN = 帧 1）。

| 用例 ID | 覆盖服务/要点 | 设计文档章节 | 包序（帧号 1-based）|
| --- | --- | --- | --- |
| `mms_connect_establish` | 完整关联：TCP 三次握手 → CR → CC → DT1(会话/表示/ACSE/MMS Initiate) → 反向关联响应 | 2.2-2.11, 3.1, 6.1-6.3 | 1 SYN, 2 SYNACK, 3 ACK, 4 CR, 5 CC, 6 DT1, 7 DT2 |
| `mms_read_multi_type` | Read：5 个变量多类型（boolean/integer/unsigned/octetString/utcTime）| 2.9, 3.3, 5.3, 6.6 | 关联建立后 8 = ReadReq, 9 = ReadResp |
| `mms_write_success` | Write：写全表返 success（80 01 00）| 3.3, 6.7 | 8 = WriteReq, 9 = WriteResp |
| `mms_information_report` | InformationReport 未确认 PDU 上送 | 2.9, 3.4, 6.7 | 8 = Report（无响应）|
| `mms_getnamelist` | GetNameList：listOfIdentifier | 3.3, 6.7 | 8 = Req, 9 = Resp |
| `mms_identify` | Identify：vendor/model/revision | 3.3, 6.7 | 8 = Req, 9 = Resp |
| `mms_service_error` | 负向：读不存在的对象 → Confirmed-ErrorPDU（access/object-non-existent）| 3.5, 6.7, 9.1 | 8 = ReadReq, 9 = Err |
| `mms_no_associate` | 负向：跳过关联直接发数据服务（未建立连接）| 4.2, 5.2(noAssociate) | 1 起直接数据帧（无关联四段）|
| `mms_ipv6` | IPv6 版本完整关联序列 | 8.3 层链 IPv6 / 10.3 偏移表 | 1 SYN(IPv6), 2 SYNACK, 3 ACK, 4 CR, … |
| `mms_multi_session` | 多会话：两路独立 TCP 关联同时建立（独立 invokeID/引用号）| 4.1, 4.3, 8.1 | 两路 CR/CC 交错；服务请求各自 invokeID=1，且对象域 IED1/IED2 可区分 |
| `mms_validate_reject` | 负向：item-identifier 编码后超过 32 字节，validate 拒绝 | 5.2, 9.3 | 创建任务失败，不产包 |

> 双向索引使用示例：要查"Read 响应如何编码"，读设计 3.3 与 6.6，用 `mms_read_multi_type` 的 FrameAssert 字节回查；要查某 pcap 用例覆盖了什么，见本表第三列。

### 7.2 设计要点 → 用例 覆盖矩阵

| 设计要点 | 用例（可多条）|
| --- | --- |
| COTP CR 独立成帧（第 6.1 节关键决策）| `mms_connect_establish`（帧 4 纯 CR）|
| TPKT 长含头、COTP LI | `mms_connect_establish`（tpkt.length/cotp.li 断言）|
| Initiate-RequestPDU 内嵌 AARQ/EXTERNAL（indirect-ref 3）| `mms_connect_establish`（FrameAssert 6.3 字节）|
| 关联响应 Initiate-ResponsePDU（a9）| `mms_connect_establish`（帧 7）与 `mms_ipv6` |
| 数据服务直到关联后才发生（时序）| 各服务用例的包序（关联后编号）|
| Read 多类型一次返回 | `mms_read_multi_type` |
| Write 成功每项 80 01 00 | `mms_write_success` |
| InformationReport 无响应 | `mms_information_report`（帧后无第 2 包）|
| GetNameList listOfIdentifier | `mms_getnamelist` |
| Identify 三项字符串 | `mms_identify` |
| Confirmed-ErrorPDU 结构 | `mms_service_error` |
| noAssociate 跳过关联 | `mms_no_associate` |
| IPv6 层链完整（载荷偏移 74）| `mms_ipv6` |
| 多会话并发、状态互不干扰 | `mms_multi_session`（两路服务请求 invokeID=1，分别含 IED1/IED2）|
| COTP DT 分片（首帧 EOT=0）| 未单列（预留，见 10.2 `mms_fragmented_dt`）|

### 7.3 覆盖度自查

- 正向服务共 5 类，每类 ≥1 用例（read/write/report/getnamelist/identify）。
- 负向路径 ≥1 用例（service_error：object-non-existent）；另设 no_associate（未建立连接）负向。
- 关联建立被独立用例覆盖（最严格断言）；其余用例以"完整关联 + 服务"包序验证数据服务依赖关联存在（第 4 章状态机）。
- 序列化边界：TCP SYN/CR/DT 逐帧断言，保证"CR 与 DT 独立成帧"不回归。
- 多会话用例验证状态机互不干扰（独立 invokeID/引用号）。
- IPv6 用例验证层链在 40 字节 IPv6 头下偏移平移正确（54→74）。

## 8. 实现集成点

MMS 在代码库中的接线点如下（内部接口）：

### 8.1 注册与层链

- 协议类型注册：`internal/core/types.go`（或 registry）新增 `"mms"`，元数据 `Category: Terminal`、`DependsOn: ["tcp"]`、`DefaultPort: 102`。
- 层链校验：`internal/core/validate.go` 允许 `["tcp","mms"]`；`mms` 前无 `tcp` 报链序错误；`mms` 前再叠一层报"终结层之上不可再叠"。
- `spec.mms` flat 键 → `MMSConfig`（`internal/core/strategy_convert.go` 中 `parseMMSConfig`）；未出现在 5.2 表的未知键忽略并告警。

### 8.2 planner 接口

```go
// internal/protocol/mms/planner.go（示意）
func PlanMMSFrames(cfg *MMSConfig, ctx LayerCtx) ([]MMSFrame, error)
type MMSFrame struct {
    Dir     string // c2s / s2c
    Kind    string // cr|cc|dt|read_req|read_resp|write_req|write_resp|
                   // report|gname_req|gname_resp|ident_req|ident_resp|err|ack
    Invoke  int    // 非 0 = 该确认帧携带的 invokeID
    Payload []byte // 应用层字节（COTP DT 载荷 / CR/CC TPDU）
}
```

展开次序：`planAssociation()` 产出关联四段（CR/CC/DT1/DT2，第 6.1 节）；`planServices()` 依 `sequence.steps` 与 enable 开关产出服务帧；`invokeID` 单调递增（4.3）。`Payload` 是最终以太帧中的"应用载荷"字节——含 TPKT+COTP+（MMS/会话/表示/ACSE），由本层在 tcp 层提供的载荷窗口（64KB 上限内）内自组装。

### 8.3 层链装配（IPv4/IPv6 偏移）

- tcp 层提供 MSS 与载荷写入回调；mms 层把 `MMSFrame.Payload`（含 TPKT/COTP/内层 BER）写入 TCP 载荷区。
- 偏移：IPv4 = 14(eth)+20(ip)+20(tcp) = 54；IPv6 = 14+40+20 = 74。mms 层不感知偏移，只写应用载荷（见 10.3）。
- COTP DT 分片：`payloadLen > tpduSize-3` 时拆分（首片 EOT=0x00，末片 0x80，每片 ≤ tpduSize-3）。当前用例不触发但保留分支与测试。

### 8.4 校验器（tshark/FrameAssert 双通道）

- `internal/pcaptest/verify.go`：`RunTshark` 默认 decode 不含 mms（本地 3.6.14 拒绝 `-d tcp.port==102,mms`），故 COTP/TPKT 走 tshark 字段断言，内层走 FrameAssert（hex）。用例 JSON 的 `decodeAs` 留空、`fields` 限制在 `tpkt.*`/`cotp.*` 白名单，防止未知字段导致 tshark 非零退出。
- FrameAssert 断言格式：`{"offset": "network", "data": "<hex>"}` 或 `{偏移值, data}` 对；框架见 run_all_test.go 与 hex.go。
- 字节参照：内层 MMS/ACSE/表示/会话字节以 Wireshark 解析器源码 + libiec61850 编码器为权威（第 6.5 节）。

### 8.5 测试接入

- 单元测试：`mms_planner_test.go`（包序、invokeID 递增、noAssociate 跳过、IPv6 偏移）；`mms_builder_test.go`（DT 分片 EOT、TPKT 长度）；`validate` 负向（未知 datatype/错误类/超长）。
- pcap 集成：`cases/mms.json` 用例由 `run_all_test.go` 驱动，逐用例 Build→Plan→Write→tshark→FrameAssert。
- 用例进入 26-mms-testcase.md 索引（第 7 章 7.1）。

## 9. 错误处理

错误分四类：**配置错误（validate）、服务拒绝（Confirmed-ErrorPDU）、编码层错误、链路/时序错误**。

### 9.1 服务拒绝（Confirmed-ErrorPDU）

通用结构（3.5 节）：`a2 <L> { 02 01 <invokeID>  a2 <L> { a0 <L> { <errorClass> 01 <value> [a3 附加码] } } }`。

| error-class | 标签 | 值 | 含义 |
| --- | --- | --- | --- |
| definition | 0x82 | 3 | type-unsupported（类型不支持）|
| resource | 0x83 | 0 | other（其他）|
| service | 0x84 | 0 | other（其他，服务不可用）|
| access | 0x87 | 2 | object-non-existent（对象不存在）|
| access | 0x87 | 3 | access-denied（拒绝访问）|
| file | 0x8B | 7 | non-existent（文件不存在）|

常用拒绝字节（object-access, object-non-existent）：
`a2 <L> { 02 01 04  a2 <L> { a0 <L> { 87 01 02 } } }` —— 测试把 `87 01 02` 作为 FrameAssert 特征串。

**触发点**：`errorClassName="access"` + `errorValue=2`；或读一个 `objects[]` 中不存在的 `name`（校验器缺省转 object-non-existent）。已存在的 `name` 但类型不符 → definition/type-unsupported。

### 9.2 关联拒绝（AARE result ≠ 0）

`associate-result`：0=accepted，1=rejected-permanent，2=rejected-transient。负向预留：`a2 03 02 01 01 a3 05 a1 03 02 01 01`（associate-result=1，永久拒绝 + acse-service-user + 应用上下文名不受支持）。首版默认 accepted，负向用 `noAssociate` 表达"未建立关联"。

### 9.3 编码层错误（BER 非法 / 配置非法）

- 非法 datatype：`objects[].datatype` 无对应标签（5.3 表外）→ 校验错误，任务拒绝创建。
- 未知服务名：`sequence.steps` 元素不在 {read, write, getnmlist, identify, report} → 报错列出合法值。
- 未知错误类：`errorClassName` 不在五类 → 报错。
- 超长负载：octetString/visibleString 超 COTP 可载上限 → 提示调大 localDetail 或减负（或依赖分片，10.2）。
- 覆盖度：`mms_validate_reject` 在 pcap 驱动层验证超长 item-identifier 的任务创建拒绝；其他非法 datatype、未知服务名/错误类仍由 validate 单测覆盖（不产出坏字节）。

### 9.4 链路/时序错误

- 未建立关联即发数据服务：仅 `noAssociate=true` 时允许（显式负向用例）；否则 planner 先补关联（默认）。
- 对端不回 AARE / 无响应：planner 按"单边字节序列"照发全部本侧帧，不做无限等待（无重传）。
- 多会话：一路失败不影响另一路（独立状态，见用例 `mms_multi_session`）。

### 9.5 错误优先级与处理策略

| 错误 | 级别 | 处理 |
| --- | --- | --- |
| validate 配置非法 | error | 拒绝创建任务（不产包）|
| 未知 datatype/错误类/服务名 | error | 同上 |
| 服务错误（Confirmed-ErrorPDU）| warning | 正常业务负向（有意产出并断言）|
| tshark 字段缺失 | warning | 校验器跳过该字段（白名单）|
| 超长 PDU | info | 自动分片（EOT 标志）|

## 10. 扩展字段映射

本版本刻意留白；以下是后续迭代落点，测试编号预留（`cases/mms.json` 不包含，避免未实现断言误判）。

### 10.1 服务扩展

| 扩展点 | 说明 | 预留测试 ID |
| --- | --- | --- |
| GetVariableAccessAttributes | 读变量类型/属性（请求 0xA6）| `mms_get_var_attr` |
| 文件服务（FileOpen/Read/Close）| 用到 file 错误类 | `mms_file` |
| Journal 服务 | 事件日志读写 | `mms_journal` |
| 分页 GetNameList（moreFollows=true）| continueAfter 续传 | `mms_name_list_paging` |
| 关联拒绝（AARE result≠0）| 9.2 负向 | `mms_assoc_reject` |

### 10.2 编码/交互扩展

| 扩展点 | 说明 | 预留测试 ID |
| --- | --- | --- |
| COTP DT 分片 | 负载 > tpduSize-3，EOT 0x00…0x80 | `mms_fragmented_dt` |
| VLAN/MPLS 叠加 | 偏移继续平移（tcp 层扩展）| — |
| 会话层裁剪（省略 SPDU）| ISO 兼容最小栈 | — |
| 变量写失败单项（81）| Write 部分失败 | `mms_write_fail_item` |

### 10.3 层链装配偏移表

| 层 | IPv4 偏移 | IPv6 偏移 | 说明 |
| --- | --- | --- | --- |
| 以太头 | 0 | 0 | 14 字节 |
| IP 头 | 14（20B）| 14（40B）| |
| TCP 头 | 34（20B）| 54（20B）| |
| 应用载荷（TPKT 起）| 54 | 74 | mms 层写 MMSFrame.Payload |

### 10.4 已排除项

| 项 | 结论 | 原因 |
| --- | --- | --- |
| TLS（MMS over TLS）| 排除 | IEC 62351-3，后续 X-over-TLS 统一层接入 |
| 运行时服务协商 | 排除 | CBB/servicesSupported 固定位串，不交互协商 |
| GOOSE/SV 复用 | 排除 | 对象模型与编码完全不同（1.5）|
| 无栈式周期上报 | 排除 | 本版本仅请求-响应 + 显式 InformationReport |

## 11. 修订记录

| 版本 | 日期 | 变更 |
| --- | --- | --- |
| v1.0.0 | 2026-08-09 | 初稿：四层栈全字节布局、关联建立"CR 独立帧 + DT 承载栈"、5 服务 + 2 负向、10 pcap 用例设计 |
| v1.0.1 | 2026-08-09 | 表示层 CPA 上下文结果列表改为 libiec 忠实形式（a5 12 + 两条 30 07）；补充 OID 汇总与 invokeID 状态 |
| v1.1.0 | 2026-08-18 | 帧号统一 1-based；补第 5 章 MMSConfig/第 7 章双向索引/第 8 章集成点/第 10 章扩展占位；同步建立 26-mms-testcase.md 与 cases/mms.json |
| v1.1.1 | 2026-08-20 | 统一 frames 0-based 帧首偏移并补 IPv4/IPv6 锚点；utcTime 改 ISO 9506-2 4 字节秒；收紧 Identifier 32 字节限制并新增 validate 负例；补多会话可观察断言，修正关联结果与 COTP 类型上下文 |

> 后续修订：实现编码评审发现的新错误（响应字节与报价）；每轮 pcap 回归后在此追补版本与变更。

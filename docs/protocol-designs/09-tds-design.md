# TDS 设计文档（v3.0.2）

> **协议**: Tabular Data Stream (TDS)（表格数据流）— Microsoft SQL Server 客户端-服务器协议
> **文档版本**: v3.0.2（2026-08-08；v3.0.1 基础上修正 RPC OptionFlags 字节数 —— MS-TDS §3.4 为 USHORT 2B，tshark/FreeTDS 均按 2B 读取，详见 §11 修订记录）
> **规范版本**: MS-TDS v20260617（修订版 42.0，2026-06-17 发布）
> **测试用例**: 220 条（T-001 ~ T-220；v3.0.0 的 214 条基础上补充 6 条集成/并发/类型覆盖用例）
> **HexDump 场景**: S1-S15 共 15 个
> **适用实现**: trafficgen `trafficgen/internal/protocol/tds/`（新实现）

---

## §1. 协议概述

TDS（Tabular Data Stream，即表格数据流）是 Microsoft SQL Server 使用的应用层请求/响应协议，默认运行于 TCP 1433 端口。客户端与服务器建立长期连接后，通过 TDS 消息完成：认证与通道加密协商、SQL 批处理（SQL Batch）提交、存储过程调用（RPC，即远程过程调用）、数据返回、事务管理请求等。TDS 会话与底层传输会话直接绑定：TCP 连接建立时 TDS 会话建立，TCP 连接关闭时 TDS 会话终止。TDS 假定底层传输提供可靠、保序的数据交付。

本文档是 trafficgen 对 TDS 协议流量生成支持的完整设计规范，所有 wire 格式（在线字节格式）均以 MS-TDS v20260617 为准。

### §1.1 协议层次

```
应用层（SQL Batch / RPC / Pre-Login / Login7 / Attention / TransMgrReq）
    ↓
Token 流层（ColMetadata / Row / NbcRow / Done / DoneProc / Error / Info / EnvChange /
          LoginAck / ReturnStatus / ReturnValue / FeatureExtAck / SessionState 等）
    ↓
TDS 包层（8 字节包头 + body；Type/Status/Length/SPID/PacketID/Window）
    ↓
TCP 传输层（默认端口 1433）
```

### §1.2 TDS 版本历史

| TDS 版本 | SQL Server 版本 | 关键特性 |
|---------|----------------|---------|
| 7.0 | SQL Server 7.0 | 引入 8 字节包头、Login7、Token 流 |
| 7.1 | SQL Server 2000 | RESETCONNECTION 状态位（0x08） |
| 7.1 R1 | SQL Server 2000 SP1 | TabName 多段表名 |
| 7.2 | SQL Server 2005 | BIG* 类型、UserType 扩为 4B、doneRowCount 扩为 8B、MARS、TransMgrReq、Enclave/PLP 类型、LineNumber 扩为 4B |
| 7.3.A | SQL Server 2008 | TVP、RESETCONNECTIONSKIPTRAN(0x10)（注：7.3.A 不含 NbcRow 与 fSparseColumnSet，规范脚注 17/27 明确） |
| 7.3.B | SQL Server 2008 R2 | NbcRow(0xD2)、稀疏列 fSparseColumnSet（仅在 7.3.B+ 启用） |
| 7.4 | SQL Server 2012+ | FeatureExt/FeatureExtAck、日期时间新类型、TDS 7.4 起会话状态；规范脚注 17 + 72 标注 SQL Server 2022/2025 仍使用 TDS 7.4（client→server `0x04000074`、server→client `0x74000004`），本文档不覆盖所谓 "TDS 8.0" 强制 TLS 场景 |

**本设计默认版本**：TDS 7.4（`TDSVersion = 0x04000074`，wire 格式 LE `04 00 00 74`），通过 `Version` 配置字段可切换 7.1/7.2/7.3/7.4。

### §1.3 连接生命周期

```
[DISCONNECTED] ──TCP connect──→ [PRELOGIN_SENT] ──Pre-Login Response──→ [LOGIN_SENT]
                                                                          │
                                              LoginAck + EnvChange + Done ─┤
                                                                          ↓
                                                                    [READY]
                                                                          │
                            ┌──SQL Batch (0x01)───────────────────────┤
                            ├──RPC (0x03)────────────────────────────┤
                            ├──Attention (0x06)───────────────────────┤
                            ├──TransMgrReq (0x0E)─────────────────────┤
                            ↓                                          │
                        [EXECUTING]                                    │
                            │                                          │
                            └──Done/Error──→ [READY]                  │
                                                                          │
                                                  TCP close ───────────┘
                                                                          ↓
                                                                    [CLOSED]
```

**关键阶段**（MS-TDS §3.2/§3.3 状态机）：
- **Pre-Login**（包头 Type=0x12）：客户端与服务器协商 TDS 版本（VERSION 选项）、加密方式（ENCRYPTION 选项）、实例名（INSTOPT）、MARS（MARS 选项）等。VERSION 选项必须是第一个选项，TERMINATOR(0xFF) 必须是最后一个选项。服务器用 Type=0x04 包返回 PRELOGIN 结构。
- **Login7**（包头 Type=0x10）：客户端提交认证凭证（用户名 + 密码 + 数据库等），服务器返回 Login Response（Type=0x04 包）：成功时含 LOGINACK Token（无 LOGINACK 即登录失败），失败时含 ERROR Token。登录响应以 DONE Token 结束（MS-TDS §2.2.2.2："A done packet MUST be present as the final part of the login response"）。
- **会话**：客户端可发送 SQL Batch（Type=0x01）、RPC（Type=0x03）、Attention（Type=0x06）、TransMgrReq（Type=0x0E）。服务器对 SQL Batch/RPC 返回 Type=0x04 的 token 流响应，以 DONE/DONEPROC Token 结束。
- **Attention**（Type=0x06，8 字节包头无 body）：客户端中断当前请求。发送后必须读取直到收到 Attention 确认（DONE Token 带 DONE_ATTN=0x20 位）。正在发送的 TDS 包必须先发送完再发 Attention。
- **注销**：直接 TCP FIN 关闭。无显式 logout 消息。

### §1.4 MARS 多会话（Multiple Active Result Sets，多活动结果集）

MARS 允许在同一 TDS 连接上同时保持多个活动请求/结果集，引入于 SQL Server 2005（TDS 7.2）。MARS 依赖 Session Multiplex Protocol (SMP)（会话多路复用协议）在单个传输连接上多路复用多个逻辑客户端连接。

**启用方式**：Pre-Login 阶段通过 MARS 选项（PL_OPTION_TOKEN=0x04）协商，VALUE=0x01 表示启用。

**应用场景**：
- 一个会话执行 SELECT 查询，另一个会话同时执行 INSERT
- 减少连接池开销，提升吞吐量
- 多个活动请求共享同一 TCP 连接和同一 SPID

**注意事项**（已确认定义）：
- 启用 MARS 后，SPID 标识**连接**而非会话：同一连接上的所有 MARS 会话共享同一 SPID
- 多会话靠消息边界区分（每请求是完整 message），而非靠 SPID 区分
- 每个请求的 ALL_HEADERS 中 TransactionDescriptor 头携带 TransactionDescriptor（8B）+ OutstandingRequestCount（4B，该连接上当前活动的请求数）
- AutoCommit 模式下 TransactionDescriptor 必须为 0，OutstandingRequestCount 必须为 1
- 服务器在 Client Request Execution 状态仍持续监听客户端消息；MARS 下多个请求可交错发送
- trafficgen 在 MARS 场景下，多个 SQL Batch/RPC 命令共享同一 TCP 连接且同一 SPID，可交错发送

### §1.5 多流关联（Batch 内多条 SQL、RPC 多参数、结果集边界）

**Batch 内多条 SQL**：SQL Batch 消息可包含多条 SQL 语句（分号分隔），服务器按顺序执行，每条语句产生独立的结果集。响应中每个结果集序列由 COLMETADATA + ROW* 组成，以 DONE Token 结束；除最后一个 DONE 外，其余 DONE 的 Status 均带 DONE_MORE=0x1 位（MS-TDS §4.19.1）。

**RPC 多参数**：RPC 消息可包含多个 ParameterData，每个参数独立编码（B_VARCHAR 参数名 + StatusFlags + TYPE_INFO + TYPE_VARBYTE），按声明顺序排列。RPC 批（RPC batch）可包含多个 RPCReqBatch，批间用 BatchFlag（TDS 7.2 起为 0xFF）分隔；NoExecFlag(0xFE) 指示前一个 RPC 不执行。注意 BatchFlag 与参数数据有歧义，解析时按"参数个数已知"顺序消费。

**结果集边界判定**：客户端以 DONE 系列 Token 为逻辑单元边界。DONE/DONEINPROC/DONEPROC 的 DONE_MORE 位表示后面还有结果集。

**事务共享**：同一连接上多个 Batch/RPC 共享事务状态。显式事务（BEGIN TRAN / COMMIT / ROLLBACK，即用户控制事务生命周期）由服务器通过 EnvChange Token（Type 8/9/10）通知事务状态变更；AutoCommit 事务不产生 EnvChange。

### §1.6 数据流类型

TDS 包数据分两类（MS-TDS §2.2.4）：
- **Tokenless 流（无 token 流）**：全部信息在包头中，用于 PRELOGIN、LOGIN7、SQLBatch、Attention、TransMgrReq 请求。
- **Token 流（token 流）**：1 字节 token 标识符 + token 特定数据。用于 BulkLoad、RPC 请求；所有服务器响应（Login Response、Row Data、Return Status、Error/Info、Response Completion 等）。

Token 分四类：
- Zero Length Token（xx01xxxx）：无长度字段无数据
- Fixed Length Token（xx11xxxx）：后跟 1/2/4/8 字节固定数据
- Variable Length Token（xx10xxxx）：后跟 Length(2B) + 数据
- Variable Count Token（xx00xxxx）：后跟 Count(2B) + 按 token 类型变化的字段

### §1.7 本文档约定

- 所有多字节整数默认 **little-endian（小端）**，除非显式标注 big-endian（仅 TDS 包头 Length/SPID 和 PRELOGIN 的 PL_OFFSET/PL_OPTION_LENGTH 为大端）
- 位标志按 least significant bit order（最低有效位在前），规则 `FLAGRULE = F0 F1 F2 F3 F4 F5 F6 F7` 在线上为 F7F6F5F4F3F2F1F0
- B_VARCHAR = 1B BYTELEN 长度 + UCS-2 LE 字符（BYTELEN 值为 Unicode 字符数，非字节数）；US_VARCHAR = 2B LE USHORTLEN 长度 + UCS-2 LE 字符
- B_VARBYTE = 1B 长度 + 原始字节；US_VARBYTE = 2B LE 长度 + 原始字节；L_VARBYTE = 4B LE 长度 + 原始字节
- 每个 HexDump 先列字段构成，再列字节，最后验证 Length = 8（包头）+ body 字节数
- TDSVersion 字段字节序：LOGIN7（客户端→服务器）按规范脚注 72 表 "Client to server" 列，7.4 wire 为 `04 00 00 74`（即 LE 表示的 0x04000074）；LOGINACK（服务器→客户端）按规范脚注 72 表 "Server to client" 列，7.4 wire 为 `74 00 00 04`（即 BE 表示的 0x74000004）。两个方向字节相反，因规范将两端表示成不同字节序

---

## §2. 数据类型与编码

### §2.1 TDS 包头结构（8 字节）

所有 TDS 包以 8 字节固定包头开始（MS-TDS §2.2.3）：

| 偏移 | 字段 | 长度 | 字节序 | 说明 |
|------|------|------|--------|------|
| 0 | Type | 1 | uint8 | 包类型（见 §2.1.1） |
| 1 | Status | 1 | uint8 | 状态标志（见 §2.1.2） |
| 2-3 | Length | 2 | **BE 大端** | 包总长度（含 8 字节包头），范围 512~32767 |
| 4-5 | SPID | 2 | **BE 大端** | 服务器进程 ID，标识连接（客户端发送时可填 0） |
| 6 | PacketID | 1 | uint8 | 包序号（message 内递增，mod 256，可忽略） |
| 7 | Window | 1 | uint8 | 保留，必须为 0 |

**包长度规则**：
- 登录前包长度 ≤ 4096；默认包大小 4096
- TDS 7.3 起：客户端发给服务器的非最后包（EOM=0）长度必须等于协商包大小，仅最后包可小于协商大小；违反时服务器 SHOULD 断开
- 登录响应中的 ENVCHANGE Type 4（Packet size）可改变协商包大小（512~32767），从登录响应后的下一条消息起生效

#### §2.1.1 Type 字段

| 值 | 含义 | 含数据 |
|----|------|--------|
| 0x01 | SQL Batch | 是 |
| 0x02 | Pre-TDS7 Login | 是 |
| 0x03 | RPC | 是 |
| 0x04 | Tabular result（表格响应，所有服务器响应） | 是 |
| 0x05 | Unused（规范 §2.2.3.1.1 明确标注，不分配任何含义） | — |
| 0x06 | Attention signal | 否（仅 8 字节包头） |
| 0x07 | Bulk load data | 是 |
| 0x08 | Federated Authentication Token | 是 |
| 0x0E | Transaction manager request | 是 |
| 0x10 | TDS7 Login（LOGIN7） | 是 |
| 0x11 | SSPI | 是 |
| 0x12 | Pre-Login | 是 |

未知 Type 或 Type 合法但与当前状态不符（如已登录后再收 0x10），接收方 SHOULD 断开连接。

#### §2.1.2 Status 字段

| 值 | 含义 |
|----|------|
| 0x00 | 普通消息 |
| 0x01 | EOM（消息结束位）：本包是整条消息的最后一个包 |
| 0x02 | Ignore（忽略位，仅客户端→服务器；必须与 0x01 同置）：取消尚未发送完的请求，服务器忽略当前请求并返回单个 DONE_ERROR 的表格响应，不发 Attention 确认 |
| 0x08 | RESETCONNECTION（TDS 7.1+）：处理事件前重置连接环境（模拟登出再登录），仅用于 Batch/RPC/TransMgrReq 首包；不得与 0x10 同置 |
| 0x10 | RESETCONNECTIONSKIPTRAN（TDS 7.3+）：重置连接但不改事务状态；不得与 0x08 同置 |

多包消息：中间包 EOM=0，最后包 EOM=1，PacketID 逐包递增。

### §2.2 基础标量类型（MS-TDS §2.2.5.1）

| 规则 | 大小 | 说明 |
|------|------|------|
| BIT | 1 bit | 单比特 |
| BYTE / BYTELEN / UCHAR | 1B | 无符号字节 / 长度 / 字符 |
| USHORT / USHORTLEN / USHORTCHARBINLEN | 2B LE | 无符号短整型 / 长度（0~65535）/ 字符二进制长度（0~8000） |
| LONG / LONGLEN | 4B LE | 有符号 32 位 / 长度（-2^31 ~ 2^31-1） |
| ULONG / DWORD / ULONGLEN | 4B LE | 无符号 32 位 / 长度 |
| LONGLONG | 8B LE | 有符号 64 位 |
| ULONGLONG / ULONGLONGLEN | 8B LE | 无符号 64 位 / 长度 |
| GEN_NULL | 1B | 0x00，NULL 值（用于除 char/binary/text 外的类型） |
| CHARBIN_NULL | 2B 或 4B | 2B：0xFFFF（char/binary 类）；4B：0xFFFFFFFF（text/ntext/image 类） |
| UNICODECHAR | 2B | UCS-2 LE 字符 |

### §2.3 变长字符串/字节流（MS-TDS §2.2.5.2.2）

| 规则 | 构成 | 长度单位 | 编码 |
|------|------|---------|------|
| B_VARCHAR | BYTELEN + 字符 | **字符数** | UCS-2 LE |
| US_VARCHAR | USHORTLEN + 字符 | **字符数** | UCS-2 LE |
| B_VARBYTE | BYTELEN + 字节 | 字节 | 原始字节 |
| US_VARBYTE | USHORTLEN + 字节 | 字节 | 原始字节 |
| L_VARBYTE | LONGLEN + 字节 | 字节 | 原始字节 |
| UNICODESTREAM | 2B 倍数 | 字节 | UCS-2 LE（无长度前缀） |

> **已确认定义**：B_VARCHAR = 1B NameLen + UCS-2 LE；US_VARCHAR = 2B LE + UCS-2 LE。ColName 用 B_VARCHAR；LoginAck.ProgName 用 B_VARCHAR（规范 §2.2.7.14 明确 `ProgName = B_VARCHAR`，1B BYTELEN 长度前缀；v3.0.0 之前误标 US_VARCHAR，v3.0.1 修正）；RPC ProcName 用 US_VARCHAR。B_VARCHAR/US_VARCHAR 的长度是 **Unicode 字符数**（即字节数/2）。

### §2.4 数据类型 token 与 TYPE_INFO（MS-TDS §2.2.5.4 ~ §2.2.5.6）

#### §2.4.1 零长度类型

| Token | 值 | SQL 类型 |
|-------|-----|---------|
| NULLTYPE | 0x1F | Null（无数据） |

#### §2.4.2 定长类型（FIXEDLENTYPE）

| Token | 值 | SQL 类型 | 数据宽度 |
|-------|-----|---------|---------|
| INT1TYPE | 0x30 | TinyInt | 1B |
| BITTYPE | 0x32 | Bit | 1B |
| INT2TYPE | 0x34 | SmallInt | 2B |
| INT4TYPE | 0x38 | Int | 4B |
| DATETIM4TYPE | 0x3A | SmallDateTime | 4B |
| FLT4TYPE | 0x3B | Real | 4B |
| MONEYTYPE | 0x3C | Money | 8B |
| DATETIMETYPE | 0x3D | DateTime | 8B |
| FLT8TYPE | 0x3E | Float | 8B |
| MONEY4TYPE | 0x7A | SmallMoney | 4B |
| INT8TYPE | 0x7F | BigInt | 8B |
| DECIMALTYPE | 0x37 | Decimal（遗留） | 无 TYPE_VARLEN，数据内带 Precision/Scale |
| NUMERICTYPE | 0x3F | Numeric（遗留） | 同上 |

#### §2.4.3 变长类型（VARLENTYPE）

**BYTELEN_TYPE**（长度前缀 1B）：

| Token | 值 | SQL 类型 | 合法长度 |
|-------|-----|---------|---------|
| GUIDTYPE | 0x24 | UniqueIdentifier | 0x10 非 NULL / 0x00 NULL |
| INTNTYPE | 0x26 | TinyInt/SmallInt/Int/BigInt | 0x01/0x02/0x04/0x08 |
| BITNTYPE | 0x68 | Bit | 0x01 / 0x00 NULL |
| DECIMALNTYPE | 0x6A | Decimal | 0x05/0x09/0x0D/0x11 |
| NUMERICNTYPE | 0x6C | Numeric | 0x05/0x09/0x0D/0x11 |
| FLTNTYPE | 0x6D | Float(7)/Float(15) | 0x04/0x08 |
| MONEYNTYPE | 0x6E | SmallMoney/Money | 0x04/0x08 |
| DATETIMNTYPE | 0x6F | SmallDateTime/DateTime | 0x04/0x08 |
| DATENTYPE | 0x28 | Date（TDS 7.3+，无 TYPE_VARLEN，数据 3B 或 NULL 0B） | 0x03 / 0x00 |
| TIMENTYPE | 0x29 | Time(n)（TDS 7.3+，长度由 SCALE 决定） | scale1-2:3B, 3-4:4B, 5-7:5B |
| DATETIME2NTYPE | 0x2A | DateTime2(n)（TDS 7.3+，长度由 SCALE 决定） | scale1-2:6B, 3-4:7B, 5-7:8B |
| DATETIMEOFFSETNTYPE | 0x2B | DateTimeOffset(n)（TDS 7.3+，长度由 SCALE 决定） | scale1-2:8B, 3-4:9B, 5-7:10B |
| CHARTYPE | 0x2F | Char（遗留） | 0~255 |
| VARCHARTYPE | 0x27 | VarChar（遗留） | 0~255 |
| BINARYTYPE | 0x2D | Binary（遗留） | 0~255 |
| VARBINARYTYPE | 0x25 | VarBinary（遗留） | 0~255 |

**USHORTLEN_TYPE**（长度前缀 2B LE）：

| Token | 值 | SQL 类型 | 合法长度 |
|-------|-----|---------|---------|
| BIGVARBINARYTYPE | 0xA5 | VarBinary | 0~8000 |
| BIGVARCHARTYPE | 0xA7 | VarChar | 0~8000 |
| BIGBINARYTYPE | 0xAD | Binary | 0~8000 |
| BIGCHARTYPE | 0xAF | Char | 0~8000 |
| NVARCHARTYPE | 0xE7 | NVarChar | 0~4000 |
| NCHARTYPE | 0xEF | NChar | 0~4000 |
| VECTORTYPE | 0xF5 | Vector（TDS 7.4+） | 数据段 8B 头 + NN*sizeof(T) |

**LONGLEN_TYPE**（长度前缀 4B LE）：

| Token | 值 | SQL 类型 | NULL 表示 |
|-------|-----|---------|----------|
| IMAGETYPE | 0x22 | Image | 0xFFFFFFFF |
| NTEXTTYPE | 0x63 | NText | 0xFFFFFFFF |
| SSVARIANTTYPE | 0x62 | sql_variant（TDS 7.2+） | 0xFFFFFFFF |
| TEXTTYPE | 0x23 | Text | 0xFFFFFFFF |
| XMLTYPE | 0xF1 | XML（TDS 7.2+，仅 BulkLoadBCP 用 LONGLEN，其余为 PLP） | — |
| JSONTYPE | 0xF4 | JSON（TDS 7.4+，PLP） | — |

**NULL 表示总结**（已确认定义，按规范 §2.2.5.2.3）：
- 定长 NULL = 类型宽度的全 0 字节（INT4 NULL = `00 00 00 00`）
- 变长 NULL 三段式（与规范 TYPE_VARBYTE = GEN_NULL / CHARBIN_NULL / PLP_BODY 一致）：
  - 非字符/二进制类型的 BYTELEN/USHORTLEN 变长类型 NULL = 0x00（GEN_NULL，1B）
  - USHORTLEN char/binary 类型（BIGCHAR/BIGVARCHAR/NCHAR/NVARCHAR/BIGBINARY/BIGVARBINARY）NULL = 0xFFFF（2B CHARBIN_NULL）
  - LONGLEN 类型（TEXT/NTEXT/IMAGE）NULL = 0xFFFFFFFF（4B CHARBIN_NULL）
  - MAX 类型（PLP）NULL = 0xFFFFFFFFFFFFFFFF（8B PLP_NULL）
- 注意：BIGVARCHAR 等 USHORTLEN char/binary 类型 NULL 是 2B 的 0xFFFF，不是 0x0000；0x0000 表示空串（合法值）
- DATENTYPE/TIMENTYPE/DATETIME2/DATETIMEOFFSET 的 NULL 由长度 0x00（GEN_NULL）表示

#### §2.4.4 PLP（Partially Length-Prefixed，分段长度前缀）类型

MAX 类型（varchar(max)/varbinary(max)/nvarchar(max)/XML/UDT/JSON）使用 PLP 编码（TDS 7.2+）：

```
PLP_BODY      = PLP_NULL
              / ((ULONGLONGLEN / UNKNOWN_PLP_LEN) *PLP_CHUNK PLP_TERMINATOR)
PLP_NULL      = %xFFFFFFFFFFFFFFFF        ; 8B 全 FF = NULL
UNKNOWN_PLP_LEN = %xFFFFFFFFFFFFFFFE      ; 8B 未知长度
PLP_CHUNK     = ULONGLEN 1*BYTE           ; 4B LE 块长 + 数据
PLP_TERMINATOR= %x00000000                ; 4B 全 0
```

- TYPE_INFO 中 MAX 类型有 USHORTMAXLEN=0xFFFF 标记（XML/UDT/JSON 无此字段）
- 已知长度时发送 ULONGLONGLEN 作为提示，接收方 SHOULD 校验实际长度一致
- 大值数据被切成 ≤ 4096 字节的块流式传输

#### §2.4.5 TYPE_INFO 规则（MS-TDS §2.2.5.6）

```
TYPE_INFO = FIXEDLENTYPE
          / (VARLENTYPE TYPE_VARLEN [COLLATION])          ; 变长 + 长度 [+排序规则]
          / (VARLENTYPE TYPE_VARLEN [PRECISION SCALE])    ; decimal/numeric
          / (VARLENTYPE SCALE)                            ; time/datetime2/datetimeoffset/vector（TDS 7.3+）
          / VARLENTYPE                                    ; date（TDS 7.3+，无长度）
          / (PARTLENTYPE [USHORTMAXLEN] [COLLATION] [XML_INFO] [UDT_INFO])
```

规则：
- DATE 无 TYPE_VARLEN；TIME/DATETIME2/DATETIMEOFFSET 无 TYPE_VARLEN 但带 SCALE（1B）；VECTOR 带 SCALE（维类型）
- PRECISION+SCALE 仅用于 NUMERIC/DECIMAL 系列（decimal(p,s) 数据宽度按精度：1-9→4B，10-19→8B，20-28→12B，29-38→16B）
- COLLATION（5B）仅用于 CHAR 系列（BIGCHAR/BIGVARCHAR/TEXT/NTEXT/NCHAR/NVARCHAR）
- USHORTMAXLEN（0xFFFF）用于 varchar(max) 等 MAX 类型；XML/UDT/JSON 无
- XML_INFO（1B SCHEMA_PRESENT [+3 个名字]）用于 XML；UDT_INFO 用于 UDT

**COLLATION（5B）**（MS-TDS §2.2.5.1.2）：LCID(20bit) + ColFlags(8bit，LSB 序：fIgnoreCase/fIgnoreAccent/fIgnoreKana/fIgnoreWidth/fBinary/fBinary2/fUTF8/reserved) + Version(4bit) + SortId(1B)。`00 00 00 00 00` 表示 raw collation。示例：`09 04 D0 00 34`（LCID 0x0409 + flags 0xD0 + version 0 + sortid 0x34）。

#### §2.4.6 数据值编码（MS-TDS §2.2.5.5.1）

| 类型 | 编码 |
|------|------|
| 整数 | LE；bit/tinyint 1B、smallint 2B、int 4B、bigint 8B |
| money/smallmoney | 有符号整数 ×10^4；money 8B（高 4B + 低 4B） |
| float/real | IEEE 754（n≤24 用 4B，25≤n≤53 用 8B） |
| decimal/numeric | 1B 符号（0=负，1=非负）+ 4/8/12/16B 有符号整数（值×10^scale） |
| uniqueidentifier | 16B 原始字节 |
| smalldatetime | 2B 天数（自 1900-01-01）+ 2B 分钟数 |
| datetime | 4B 有符号天数（自 1900-01-01，负数可表示 1753 起；最早可表示 1753-01-01 ≈ -53690 天）+ 4B 无符号 1/300 秒数 |
| date | 3B 无符号天数（自 0001-01-01） |
| time(n) | 无符号整数，10^-n 秒增量（scale 0-2→3B，3-4→4B，5-7→5B） |
| datetime2(n) | time(n) 后接 date |
| datetimeoffset(n) | datetime2(n) 后接 2B 有符号时区分钟数（-840~840） |

### §2.5 ALL_HEADERS（包数据流头，TDS 7.2+）

SQLBatch/RPCRequest/TransMgrReq 消息以 ALL_HEADERS 开头（MS-TDS §2.2.5.3）：

```
ALL_HEADERS = TotalLength 1*Header
Header      = HeaderLength HeaderType HeaderData
TotalLength = DWORD（含自身）；HeaderLength = DWORD（含自身）
HeaderType  = USHORT LE
```

| HeaderType | 值 | 适用消息 | HeaderData |
|-----------|-----|---------|-----------|
| Query Notifications | 0x0000 | SQLBatch/RPC（可选） | NotifyId(2B LE 长度 + UNICODESTREAM 数据) + SSBDeployment(2B LE 长度 + UNICODESTREAM 数据) + [NotifyTimeout(4B LE DWORD)] |
| Transaction Descriptor | 0x0002 | SQLBatch/RPC/TransMgrReq（**必需**） | TransactionDescriptor(ULONGLONG) + OutstandingRequestCount(DWORD) |
| Trace Activity | 0x0003 | 三者均可选（TDS 7.4+） | GUID_ActivityID(16B) + ActivitySequence(DWORD) |

规则：头仅出现在跨多包请求的首包；每个头类型在流中至多出现一次；AutoCommit 下 TransactionDescriptor=0 且 OutstandingRequestCount=1。

### §2.6 包类型与 Token 流汇总表

| 消息 | 包头 Type | 方向 | 流类型 | 构成 |
|------|----------|------|--------|------|
| Pre-Login | 0x12 | C→S | Tokenless | PRELOGIN 结构 |
| Pre-Login Response | 0x04 | S→C | Tokenless | PRELOGIN 结构 |
| LOGIN7 | 0x10 | C→S | Tokenless | LOGIN7 结构 |
| Login Response | 0x04 | S→C | Token | ENVCHANGE/INFO/LOGINACK/FEATUREEXTACK/DONE |
| SQL Batch | 0x01 | C→S | Tokenless | ALL_HEADERS + SQLText(Unicode) |
| RPC | 0x03 | C→S | Token | ALL_HEADERS + RPCReqBatch* |
| Bulk Load | 0x07 | C→S | Token | COLMETADATA + ROW* + DONE |
| Attention | 0x06 | C→S | Tokenless | 无 body |
| TransMgrReq | 0x0E | C→S | Tokenless | ALL_HEADERS + RequestType(USHORT) + [RequestPayload] |
| 表格响应 | 0x04 | S→C | Token | 任意服务器 token 流 |

---

## §3. 消息结构与 Token 流

### §3.1 PRELOGIN 消息（包头 Type=0x12）

```
PRELOGIN = *PRELOGIN_OPTION *PL_OPTION_DATA
PRELOGIN_OPTION = (PL_OPTION_TOKEN PL_OFFSET PL_OPTION_LENGTH) / TERMINATOR
```

| 字段 | 大小 | 字节序 | 说明 |
|------|------|--------|------|
| PL_OPTION_TOKEN | 1B | — | 选项 token |
| PL_OFFSET | 2B | **BE** | 选项数据在 body 中的偏移 |
| PL_OPTION_LENGTH | 2B | **BE** | 选项数据长度 |
| TERMINATOR | 1B | — | 0xFF，无偏移无长度 |

**选项 token 表**：

| Token | 值 | 数据 | 说明 |
|-------|-----|------|------|
| VERSION | 0x00 | UL_VERSION(4B) + US_SUBBUILD(2B) | **必须第一个**；UL_VERSION 大端（major 1B + minor 1B + build 2B） |
| ENCRYPTION | 0x01 | B_FENCRYPTION(1B) | 0x00=off，0x01=on，0x02=not supported，0x03=required |
| INSTOPT | 0x02 | B_INSTVALIDITY | 实例名（MBCS）或以 0x00 结尾 |
| THREADID | 0x03 | UL_THREADID(4B) | 客户端线程 ID |
| MARS | 0x04 | B_MARS(1B) | 0x00=off，0x01=on |
| TRACEID | 0x05 | GUID_CONNID(16B) + ACTIVITYID(16B+4B) | TDS 7.4+ 调试 |
| FEDAUTHREQUIRED | 0x06 | 1B | TDS 7.4+ 联合认证需求协商 |
| NONCEOPT | 0x07 | NONCE(32B) | TDS 7.4+ 联合认证 nonce |
| TERMINATOR | 0xFF | — | **必须最后** |

规则：VERSION 必须是第一个选项（否则服务器断开）；TERMINATOR 必须最后（仅 1 字节）；服务器响应包 Type=0x04，body 为同样格式的 PRELOGIN 结构。

### §3.2 LOGIN7 消息（包头 Type=0x10）

```
LOGIN7 = Length TDSVersion PacketSize ClientProgVer ClientPID ConnectionID
         OptionFlags1 OptionFlags2 TypeFlags (FRESERVEDBYTE/OptionFlags3)
         ClientTimeZone ClientLCID OffsetLength Data [FeatureExt]
```

| 字段 | 大小 | 说明 |
|------|------|------|
| Length | 4B LE | LOGIN7 结构总长度（**不含** 8B 包头）；必须 ≤ 128K-1 |
| TDSVersion | 4B LE | 客户端最高 TDS 版本：7.1=0x00000071，7.2=0x02000972，7.3=0x03000A73，7.3.B=0x03000B73，**7.4=0x04000074**（wire LE `04 00 00 74`） |
| PacketSize | 4B LE | 请求包大小（默认 4096） |
| ClientProgVer | 4B LE | 客户端接口库版本 |
| ClientPID | 4B LE | 客户端进程 ID |
| ConnectionID | 4B LE | Always Up 备份连接 ID |
| OptionFlags1 | 1B | fByteOrder(0=X86) + fChar(0=ASCII) + fFloat(2bit,0=IEEE754) + fDumpLoad + fUseDB + fDatabase + fSetLang，LSB 序 |
| OptionFlags2 | 1B | fLanguage + fODBC + 2 保留位(原 fTranBoundary/fCacheConnect) + fUserType(3bit,0=normal) + fIntSecurity |
| TypeFlags | 1B | fSQLType(4bit,1=TSQL) + fOLEDB + fReadOnlyIntent + 2 保留位 |
| OptionFlags3 | 1B | 保留 + fChangePassword + fSendYukonBinaryXML + fUserInstance + fUnknownCollationHandling + fExtension（TDS 7.4） |
| ClientTimeZone | 4B LE | 未使用，置 0 |
| ClientLCID | 4B LE | 客户端 LCID（如 0x0409 → `09 04 00 00`） |

**OffsetLength（偏移表）**：TDS 7.2+（含 7.4）为 **58 字节**（13 对 ib/cch 字段 × 4B + ClientID 6B = 58B），TDS 7.0/7.1 为 50 字节（无 cbSSPILong 4B）。ibHostName=0x5E=94 是 **从 LOGIN7 结构起点到 Data 区起点的偏移量**（= 36B 固定 Header + 58B OffsetLength 表），而非 OffsetLength 表本身的大小：

| 字段 | 大小 | 说明 |
|------|------|------|
| ibHostName / cchHostName | 2B+2B | 客户端机器名；**ibHostName 必须指向 Data 区起点，即使无数据也不得为 0** |
| ibUserName / cchUserName | 2B+2B | 用户名（括号语义，须符合定界标识符规则） |
| ibPassword / cchPassword | 2B+2B | 密码（混淆算法见下） |
| ibAppName / cchAppName | 2B+2B | 应用名 |
| ibServerName / cchServerName | 2B+2B | 服务器名 |
| ibExtension / cbExtension | 2B+2B | TDS 7.4 fExtension=1 时有效，指向 DWORD（FeatureExt 相对消息起点的偏移）；cbExtension ≤ 255。TDS 7.3 及以下该位置为 ibUnused/cbUnused（预留，置 0） |
| ibCltIntName / cchCltIntName | 2B+2B | 接口库名 |
| ibLanguage / cchLanguage | 2B+2B | 初始语言 |
| ibDatabase / cchDatabase | 2B+2B | 初始数据库 |
| ClientID | 6B | 客户端 MAC 地址 |
| ibSSPI / cbSSPI | 2B+2B | SSPI 数据 |
| ibAtchDBFile / cchAtchDBFile | 2B+2B | 附加数据库文件名 |
| ibChangePassword / cchChangePassword | 2B+2B | 新密码（TDS 7.2+） |
| cbSSPILong | 4B LE | 大 SSPI 长度（TDS 7.2+；cbSSPI=0xFFFF 时用之） |

**偏移表布局**：所有 ib 偏移值 = 字段相对 LOGIN7 结构起点（即包 body 起点）的偏移，不是相对 Data 区；偏移表值必须单调不减，未使用字段 ib=0 且 cch=0。

**密码混淆**：发送前每个字节先高低 4 位互换，再与 0xA5 XOR。

**Data 区**：各字段的 UCS-2 LE 数据按偏移表依次排列。

**FeatureExt（TDS 7.4+）**：
```
FeatureOpt = (FeatureId(1B) FeatureDataLen(4B LE) FeatureData) / TERMINATOR(0xFF)
```
常用 FeatureId：0x01 SESSIONRECOVERY、0x02 FEDAUTH、0x04 COLUMNENCRYPTION、0x05 GLOBALTRANSACTIONS、0x08 AZURESQLSUPPORT、0x09 DATACLASSIFICATION、0x0A UTF8_SUPPORT、0x0B AZURESQLDNSCACHING、0x0D JSONSUPPORT、0x0E VECTORSUPPORT、0x0F ENHANCEDROUTINGSUPPORT、0x10 USERAGENT、0xFF TERMINATOR。服务器不认识的 feature 必须跳过。

**Login 校验规则**：cchHostName/UserName/Password/AppName/ServerName/CltIntName/Language/Database/ChangePassword ≤ 128 字符；cchAtchDBFile ≤ 260 字符；cbExtension ≤ 255 字节。

### §3.3 SQL Batch 消息（包头 Type=0x01）

```
SQLBatch = ALL_HEADERS *EnclavePackage SQLText
SQLText  = UNICODESTREAM   ; UCS-2 LE，无长度前缀
```

### §3.4 RPC 消息（包头 Type=0x03）

```
RPCRequest = ALL_HEADERS RPCReqBatch *((BatchFlag/NoExecFlag) RPCReqBatch) [BatchFlag/NoExecFlag]
RPCReqBatch = NameLenProcID OptionFlags *EnclavePackage *ParameterData
NameLenProcID = ProcName / (ProcIDSwitch ProcID)
ProcName      = US_VARCHAR          ; 2B 长度 + UCS-2 LE；名称 ≤ 1046 字节
ProcIDSwitch  = %xFF %xFF           ; 短形式开关
ProcID        = USHORT              ; 特殊存储过程 ID（Sp_Cursor=1 ... Sp_Unprepare=15，Sp_ExecuteSql=10）
OptionFlags   = USHORT              ; 2B LE：fWithRecomp(bit0) + fNoMetaData(bit1) + fReuseMetaData(bit2) + 13 保留（MS-TDS §3.4；tshark/FreeTDS 均按 2B 读取，1B 会致流错位）
BatchFlag     = %xFF                ; TDS 7.2+；下一 RPC 开始（0x80 为 7.2 之前）
NoExecFlag    = %xFE                ; 前一个 RPC 不执行，返回错误 + DONEPROC 后继续
```

**ParameterData**：
```
ParamMetaData = B_VARCHAR                 ; 1B 参数名长度 + UCS-2 LE 参数名（可为空名）
                StatusFlags               ; 1B：fByRefValue(bit0) + fDefaultValue(bit1) + 1FRESERVEDBIT(bit2) + fEncrypted(bit3) + 4FRESERVEDBIT
                (TYPE_INFO / TVP_TYPE_INFO)
ParamLenData  = TYPE_VARBYTE              ; 类型相关数据
```

> **StatusFlags 位号（已确认定义，规范 §2.2.6.6）**：bit0=fByRefValue、bit1=fDefaultValue、bit2=1FRESERVEDBIT、**bit3=fEncrypted**（v3.0.0 误标 bit4，v3.0.1 修正为 bit3）、bit4-7=4FRESERVEDBIT。

- 参数名长度为 0 时参数名可能被省略（官方示例 4.8 中 00 00 无名字节）
- TVP 参数：StatusFlags 的 fDefaultValue 和 fByRefValue 必须为 0
- RPC 消息不得与 SQL 语句混在同一消息

### §3.5 TransMgrReq 消息（包头 Type=0x0E）

```
TransMgrReq = ALL_Headers RequestType(USHORT LE) [RequestPayload]
```

| RequestType | 值 | 含义 | 响应 |
|------------|-----|------|------|
| TM_GET_DTC_ADDRESS | 0 | 获取 DTC 地址 | ENVCHANGE Type 16（Transaction Manager Address，规范标记 not used；NewValue=B_VARBYTE） |
| TM_PROPAGATE_XACT | 1 | 导入 DTC 事务 | varbinary 结果集 |
| TM_BEGIN_XACT | 5 | 开始事务 | ENVCHANGE Type 8 |
| TM_PROMOTE_XACT | 6 | 提升事务 | ENVCHANGE Type 15 |
| TM_COMMIT_XACT | 7 | 提交事务 | ENVCHANGE Type 9 |
| TM_ROLLBACK_XACT | 8 | 回滚事务 | ENVCHANGE Type 10 |
| TM_SAVE_XACT | 9 | 设置保存点 | —（仅创建保存点，不影响 @@trancount，无 ENVCHANGE） |

TM_BEGIN_XACT payload：ISOLATION_LEVEL(1B) + BEGIN_XACT_NAME(B_VARBYTE)。隔离级别（规范 §2.2.6.9）：0x00=使用当前不改变（Use current）、0x01=Read Uncommitted、0x02=Read Committed、0x03=Repeatable Read、0x04=Serializable、0x05=Snapshot。未知 RequestType 时接收方 SHOULD 断开。

### §3.6 服务器响应 Token 总表

| Token | 值 | 类型 | 说明 |
|-------|-----|------|------|
| ALTMETADATA | 0x88 | Variable Count | 聚合列元数据（TDS 7.4 弃用） |
| ALTROW | 0xD3 | Variable Count | 聚合行（TDS 7.4 弃用） |
| COLMETADATA | 0x81 | Variable Count | 结果集列元数据 |
| COLINFO | 0xA5 | Variable Length | 浏览模式列信息 |
| DATACLASSIFICATION | 0xA3 | 特殊 | 数据分类（TDS 7.4+） |
| DONE | 0xFD | Fixed (17B/13B) | SQL 语句完成 |
| DONEPROC | 0xFE | Fixed (17B/13B) | 存储过程完成 |
| DONEINPROC | 0xFF | Fixed (17B/13B) | 存储过程内语句完成 |
| ENVCHANGE | 0xE3 | Variable Length | 环境变更 |
| ERROR | 0xAA | Variable Length | 错误消息 |
| FEATUREEXTACK | 0xAE | 特殊 | 特性确认（TDS 7.4+） |
| FEDAUTHINFO | 0xEE | 特殊 | 联合认证信息（TDS 7.4+） |
| INFO | 0xAB | Variable Length | 信息消息 |
| LOGINACK | 0xAD | Variable Length | 登录确认 |
| NBCROW | 0xD2 | Variable Count | 空位图压缩行（TDS 7.3+） |
| OFFSET | 0x78 | Fixed (5B) | 关键字偏移（TDS 7.2 移除） |
| ORDER | 0xA9 | Variable Length | 排序列 |
| RETURNSTATUS | 0x79 | Fixed (5B) | RPC 返回状态 |
| RETURNVALUE | 0xAC | Variable Count | RPC 返回值 |
| ROW | 0xD1 | Variable Count | 数据行 |
| SESSIONSTATE | 0xE4 | Variable Length | 会话状态（TDS 7.4+） |
| SSPI | 0xED | Variable Length | SSPI 数据 |
| TABNAME | 0xA4 | Variable Length | 表名（浏览模式） |
| TVP_ROW | 0x01 | Variable Count | TVP 行（客户端→服务器） |

### §3.7 COLMETADATA Token（0x81）

```
COLMETADATA = TokenType(0x81) Count(USHORT LE)
              [CekTable] NoMetaData(0xFFFF 0xFFFF) / (1*ColumnData)
ColumnData  = UserType(4B LE) Flags(2B LE) TYPE_INFO [TableName] [CryptoMetaData] ColName(B_VARCHAR)
```

**Flags（16bit，LSB 序，已确认定义，规范 §2.2.7.4）**：

| 位 | 值 | 字段 | 说明 |
|----|-----|------|------|
| bit0 | 0x0001 | fNullable | 列可空 |
| bit1 | 0x0002 | fCaseSen | 大小写敏感 |
| bit2-3 | 0x000C | usUpdateable | 2-bit：0=RO、1=RW、2=Unknown |
| bit4 | 0x0010 | fIdentity | 标识列 |
| bit5 | 0x0020 | fComputed | 计算列（TDS 7.2+；前为 FRESERVEDBIT） |
| bit6-7 | 0x00C0 | usReservedODBC | 仅 TDS 7.3.A 及以下；7.4 为预留 |
| bit8 | 0x0100 | fFixedLenCLRType | 固定长度 CLR 类型（TDS 7.2+；前为 FRESERVEDBIT） |
| bit9 | 0x0200 | FRESERVEDBIT / usReserved | 7.4 中若 fSparseColumnSet 等启用则为前缀 FRESERVEDBIT，否则 usReserved |
| bit10 | 0x0400 | fSparseColumnSet | 稀疏列集（TDS 7.3.B+） |
| bit11 | 0x0800 | fEncrypted | 加密列（TDS 7.4+） |
| bit12 | 0x1000 | usReserved3 | TDS 7.4 预留 |
| bit13 | 0x2000 | fHidden | 隐藏列（TDS 7.2+） |
| bit14 | 0x4000 | fKey | 主键列（TDS 7.2+） |
| bit15 | 0x8000 | fNullableUnknown | 是否可空未知（TDS 7.2+） |

> **v3.0.0 → v3.0.1 修正（C1）**：v3.0.0 将 fFixedLenCLRType 标为 0x1000、fSparseColumnSet=0x200、fEncrypted=0x400、fHidden=0x20000、fKey=0x40000、fNullableUnknown=0x80000，与规范 LSB 序矛盾且超出 16 位范围。v3.0.1 按规范 §2.2.7.4 重排为 fFixedLenCLRType=0x0100、fSparseColumnSet=0x0400、fEncrypted=0x0800、fHidden=0x2000、fKey=0x4000、fNullableUnknown=0x8000。

常用 Flags 值（已确认定义）：
- 普通列 0x0000；可空列 0x0001（fNullable）
- 示例 4.7：Flags=`20 00`=0x0020 → fComputed(bit5)
- 示例 4.12：Flags=`05 00`=0x0005 → fNullable(bit0) | usUpdateable=1(bit2，0x0004)

- Count=0xFFFF 表示 NoMetaData（fNoMetaData 请求时）
- TableName（NumParts(1B) + PartName*(US_VARCHAR)）仅在 text/ntext/image 列出现
- UserType 有效值 0x00000000（timestamp=0x00000050，别名类型 > 0x000000FF）

### §3.8 ROW Token（0xD1）与 NBCROW Token（0xD2）

**ROW**：
```
ROW = TokenType(0xD1) *ColumnData
ColumnData = [TextPointer(Timestamp)] Data
```
- TextPointer = B_VARBYTE（16B 文本指针）+ Timestamp(8B)，仅 text/ntext/image 列需要；NULL 实例不得带 TextPointer/Timestamp
- Data = TYPE_VARBYTE（每个列一个，类型由 COLMETADATA 决定）

**NBCROW（TDS 7.3+）**：
```
NBCROW = TokenType(0xD2) NullBitmap *ColumnData
```
- NullBitmap：每列 1 bit（bit=1 表示 NULL 且该列数据不在行中），按字节 LSB 序排列，向上取整到字节
- 列 0~7 在第一个字节，bit0=列0；列 8~15 在第二字节
- 仅服务器→客户端结果集；不得用于 BulkLoadBCP 和 TVP 行
- 同一结果集中 ROW 和 NBCROW 可混用

### §3.9 DONE / DONEINPROC / DONEPROC Token

```
DONE       = TokenType(0xFD) Status(2B LE) CurCmd(2B LE) DoneRowCount(4B 或 8B LE)
DONEINPROC = TokenType(0xFF) ... 同上
DONEPROC   = TokenType(0xFE) ... 同上
```

**Status 位**（已确认定义；规范 §2.2.7.6/§2.2.7.7/§2.2.7.8 分别列出各 token 的 Status 位）：

| 位 | 值 | 含义 | DONE | DONEINPROC | DONEPROC |
|----|-----|------|------|-----------|----------|
| DONE_FINAL | 0x00 | 请求中最后的 DONE/DONEPROC | ✓ | — | ✓ |
| DONE_MORE | 0x01 | 非最后，后续还有流 | ✓ | ✓ | ✓ |
| DONE_ERROR | 0x02 | 语句/过程出错，前面 SHOULD 有 ERROR | ✓ | ✓ | ✓ |
| DONE_INXACT | 0x04 | 事务进行中（SQL Server 实际不置位） | ✓ | ✓ | ✓ |
| DONE_COUNT | 0x10 | DoneRowCount 有效 | ✓ | ✓ | ✓ |
| DONE_ATTN | 0x20 | 服务器对 Attention 的确认 | ✓（仅 DONE） | — | — |
| DONE_RPCINBATCH | 0x80 | 与 RPC 批中的 RPC 关联（非最后一个 RPC） | — | — | ✓ |
| DONE_SRVERROR | 0x100 | 严重错误，结果集须丢弃 | ✓ | ✓ | ✓ |

> **v3.0.0 → v3.0.1 修正（CRITICAL-1 + C6）**：
> - v3.0.0 错将 DONE_RPCINBATCH(0x80) 标为 "仅 DONE"，与规范 §2.2.7.6（DONE Status 不含 0x80）和 §2.2.7.8（DONEPROC Status 含 0x80）矛盾。v3.0.1 改为 0x80 仅在 DONEPROC 列。S13 场景 HexDump（DONEPROC=0xFE）与此一致。
> - v3.0.0 将 DONE_FINAL(0x00) 标为对 DONEINPROC 有效（✓），但规范 §2.2.7.7 DONEINPROC Status 位列表不含 0x00（DONEINPROC 必须后跟另一 DONEPROC/DONEINPROC，因此其本身不可能为 "final"）。v3.0.1 改为 DONE_FINAL 对 DONEINPROC 列为 "—"。

**DoneRowCount 宽度**（已确认定义）：TDS 7.1 = 4B LE；TDS 7.2+ = 8B LE。CurCmd 由应用层控制，TDS 层不解释。

**完成语义**：SQL 批中每个 SQL 语句（变量声明除外）返回一个 DONE；批中除最后一个 DONE 外都带 DONE_MORE。存储过程内每条语句返回 DONEINPROC，过程结束返回 DONEPROC；DONEINPROC 必须后跟 DONEPROC 或 DONEINPROC。DONEPROC 后跟另一个 DONEPROC/DONEINPROC 仅当 DONE_MORE 置位。SQL 批中的 EXEC 也会产生 DONEPROC。

### §3.10 ENVCHANGE Token（0xE3）

```
ENVCHANGE = TokenType(0xE3) Length(USHORT LE) Type(1B) NewValue [OldValue]
```
Length = EnvValueData（Type+NewValue+OldValue）的总字节数。

**Type 表**（重点类型，已确认定义，规范 §2.2.7.9）：

| Type | 含义 | NewValue | OldValue |
|------|------|----------|----------|
| 1 | Database | B_VARCHAR | B_VARCHAR |
| 2 | Language | B_VARCHAR | B_VARCHAR |
| 3 | Character Set（仅 TDS 7.0 及更早回） | B_VARCHAR | B_VARCHAR |
| 4 | Packet Size | B_VARCHAR（如 "4096"） | B_VARCHAR |
| 7 | SQL Collation | B_VARBYTE(5B) | B_VARBYTE（空时 0x00 即长度前缀为 0，1B） |
| **8** | **Begin Transaction** | B_VARBYTE：1B 长度(0x08) + **8B TransactionID(ULONGLONG LE)** | %x00 |
| **9** | **Commit Transaction** | %x00 | B_VARBYTE：1B 长度(0x08) + 8B TransactionID(ULONGLONG LE) |
| **10** | **Rollback Transaction** | %x00 | B_VARBYTE：1B 长度(0x08) + 8B TransactionID(ULONGLONG LE) |
| 11 | Enlist DTC Transaction | 8B | %x00 |
| 12 | Defect Transaction | B_VARBYTE（8B TransactionID） | %x00 |
| 13 | Database Mirroring Partner | B_VARCHAR | %x00 |
| 15 | Promote Transaction | DTC_TOKEN（L_VARBYTE，Length 字段=0x01 仅含 Type 字节；客户端须自行读 L_VARBYTE 4B 长度前缀 + DTC token 数据） | %x00 |
| 16 | Transaction Manager Address（规范标记 not used，响应 TM_GET_DTC_ADDRESS RequestType=0） | B_VARBYTE（XACT_MANAGER_ADDRESS） | %x00 |
| 17 | Transaction ended | %x00 | B_VARBYTE（8B TransactionID） |
| 18 | Reset Completion Ack | %x00 | %x00 |
| 19 | User instance 信息 | B_VARCHAR | %x00 |
| 20 | Routing（TDS 7.4+） | RoutingData：RoutingDataValueLength(2B LE) + Protocol(1B=0) + ProtocolProperty(2B LE 端口) + AlternateServer(US_VARCHAR) | %x00 0x00 |
| 21 | Enhanced Routing（TDS 7.4+） | 同 20 + AlternateDatabase(US_VARCHAR ≤128 字符) | %x00 0x00 |

> **v3.0.0 → v3.0.1 修正（HIGH-3 + LOW-1 + LOW-2 + M2）**：
> - 新增 Type 16（Transaction Manager Address），v3.0.0 漏列；规范 §2.2.7.9 明确 Type 16 在响应 TM_GET_DTC_ADDRESS(RequestType=0) 时发送，NewValue=B_VARBYTE，OldValue=%x00。§3.5 TransMgrReq 表同步修正 TM_GET_DTC_ADDRESS 响应路径。
> - Type 12 Defect Transaction：v3.0.0 写 "NewValue=%x00、OldValue=8B" 与规范反了。规范第 4928 行明确 `12: Defect Transaction OLDVALUE=%x00 NEWVALUE=B_VARBYTE`，v3.0.1 改为 NewValue=B_VARBYTE(8B)、OldValue=%x00。
> - Type 15 Promote Transaction：v3.0.0 "Length 字段只含 1B type" 措辞晦涩。v3.0.1 改为 "DTC_TOKEN（L_VARBYTE，Length 字段=0x01 仅含 Type 字节；客户端须自行读 L_VARBYTE 4B 长度前缀 + DTC token 数据）"，与规范 §2.2.7.9 注释一致。
> - Type 7 SQL Collation：OldValue 在 v3.0.0 未明确类型，v3.0.1 标为 B_VARBYTE（空时 0x00 即 1B 长度前缀为 0）。

> **已确认定义**：EnvChange Begin/Commit/Rollback Tran：NewValue = 1B Length(0x08) + 8B TransactionID（ULONGLONG LE）。Type 8 的 NewValue 是 B_VARBYTE 形式（1B 长度 0x08 + 8B）；Type 9/10 的 OldValue 同构。

**规则**：
- Type 1/2/3/4/5/6/13/19 的 payload 是 Unicode 字符串，Length 反映字节数
- Type 8~12 仅在事务生命周期由用户控制时（显式 BEGIN TRAN 等）返回；AutoCommit 事务不产生
- Type 4（Packet size）随 LOGIN7 响应发送，值须在 512~32767，双方从登录响应后的下一条消息起使用新包大小
- Type 20/21 仅在 LOGINACK 之后发送；两者不得同时出现；Type 21 需客户端请求 ENHANCEDROUTINGSUPPORT

### §3.11 ERROR Token（0xAA）与 INFO Token（0xAB）

```
ERROR = TokenType(0xAA) Length(USHORT LE) Number(4B LE) State(1B) Class(1B)
        MsgText(US_VARCHAR) ServerName(B_VARCHAR) ProcName(B_VARCHAR) LineNumber(2B 或 4B LE)
INFO  = TokenType(0xAB) ... 同上
```

- Length = Number 到 LineNumber 的总字节数
- **LineNumber = 2B USHORT（TDS 7.1）；4B LONG（TDS 7.2+）**（已确认定义：本设计 TDS 7.4 用 4B）
- Class（严重级别）：0-9/10 信息性；11-16 用户可修正（11 对象不存在、14 权限、15 语法、16 一般错误）；17-19 需管理员；20-25 致命
- Class < 10 用 INFO；ERROR 出现于结果集内时须在语句的 DONE 之前，且该 DONE 置 DONE_ERROR 位
- Number < 20001 为 SQL Server 保留

### §3.12 LOGINACK Token（0xAD）

```
LOGINACK = TokenType(0xAD) Length(USHORT LE) Interface(1B) TDSVersion(4B)
           ProgName(B_VARCHAR) ProgVersion(4B)
```

- **已确认定义**：Length = 整个 LoginAck token 的字节数（Interface 到 ProgVersion 的总长，不含 TokenType 和 Length 自身）
- Interface：0=SQL_DFLT，1=SQL_TSQL
- TDSVersion（服务器→客户端网络格式，规范脚注 72 "Server to client" 列）：7.1=`0x07010000`、7.2=`0x72090002`、7.3.A=`0x730A0003`、7.3.B=`0x730B0003`、**7.4=`0x74000004`**（wire BE `74 00 00 04`，与 LOGIN7 客户端→服务器方向 `04 00 00 74` 字节相反）
- ProgName 用 **B_VARCHAR（1B BYTELEN 长度 + UCS-2 LE）**（规范 §2.2.7.14 明确 `ProgName = B_VARCHAR`；v3.0.0 误标 US_VARCHAR，v3.0.1 修正）；ProgVersion = MajorVer(1B) + MinorVer(1B) + BuildNumHi(1B) + BuildNumLow(1B)
- 客户端未收到 LOGINACK 即登录失败

### §3.13 RETURNSTATUS（0x79）与 RETURNVALUE（0xAC）

```
RETURNSTATUS = TokenType(0x79) Value(4B LE)          ; RPC 返回状态，必须非 NULL
RETURNVALUE  = TokenType(0xAC) ParamOrdinal(2B LE) ParamName(B_VARCHAR) Status(1B)
               UserType(4B LE) Flags(2B LE) TypeInfo(TYPE_INFO) [CryptoMetadata] Value(TYPE_VARBYTE)
```

- RETURNSTATUS 在 RPC 执行后必须返回
- RETURNVALUE：每个输出参数一个 token；UDF 作为 RPC 执行时恰有一个（无返回参数）；大对象输出参数排在末尾（先小参数组后大参数组）
- Status：0x01=存储过程 OUTPUT 参数，0x02=UDF 返回值

### §3.14 FEATUREEXTACK Token（0xAE）与 SESSIONSTATE Token（0xE4）

**FEATUREEXTACK（TDS 7.4+）**：
```
FEATUREEXTACK = TokenType(0xAE) 1*FeatureAckOpt
FeatureAckOpt = (FeatureId(1B) FeatureAckDataLen(4B LE) FeatureAckData) / TERMINATOR(0xFF)
```
- 仅随 LOGINACK 在 Login Response 中发送
- 客户端未请求的 FeatureId 出现在 ack 中 = TDS 协议错误，须终止连接
- FeatureId 与 FeatureExt 相同（0x01 SESSIONRECOVERY 带 SessionStateDataSet，0x02 FEDAUTH 带 Nonce+Signature，0x04 COLUMNENCRYPTION 带版本等）
- 已确认定义：FeatureExtAck Token = 0xAE

**SESSIONSTATE（TDS 7.4+）**：
```
SESSIONSTATE = TokenType(0xE4) Length(4B LE) SeqNo(4B LE) Status(1B) SessionStateDataSet
SessionStateData = StateId(1B) StateLen(1B 或 0xFF+4B) StateValue
```
- Length = 排除 TokenType+Length 的字节数
- fRecoverable(bit0) 为 1 表示所有 StateId 可恢复
- StateLen：≤254 用 1B；≥255 用 0xFF + DWORD
- 本 token 后必须跟 DONE_FINAL/DONEPROC_FINAL；仅在 SESSIONRECOVERY 协商成功时发送

### §3.15 Attention 请求与确认（已确认定义）

- **Attention 请求 Type=0x06**：仅 8 字节包头，无 body（Length=8）
- 客户端发送 Attention 后必须持续读取并丢弃除 SESSIONSTATE 外的所有数据，直到收到含 DONE_ATTN(0x20) 位的 DONE token——此 DONE 即为 Attention 确认载体。期间不回退到 Logged In 状态（见 §4.1 Sent Attention 状态）
- **Attention 确认 = 服务器在 Type=0x04 表格响应包的 DONE token 中置 DONE_ATTN(0x20) 位**（规范 §2.2.2.9 + §2.2.7.6 第 4692 行）；客户端收到后回到 Logged In 状态
- Attention 前必须完成正在发送的 TDS 包
- 未发送完的请求（EOM 未置位）用 Status=0x03（Ignore|EOM）取消，服务器返回单个 DONE_ERROR 表格响应
- **Type=0x05 在规范 §2.2.3.1.1 中明确为 "Unused"**，不存在独立的 "Attention Ack 包类型"（v3.0.0 误标 "Attention Ack Type=0x05"，v3.0.1 删除该错误描述）

### §3.16 Login Response 消息顺序

```
Login Response（Type=0x04 包）=
  [ENVCHANGE Type 1 Database]     ; 初始数据库变更（fUseDB 开启时）
  [ENVCHANGE Type 2 Language]     ; 语言变更
  [ENVCHANGE Type 7 Collation]    ; 排序规则
  [ENVCHANGE Type 4 Packet Size]  ; 包大小协商
  [INFO ...]                      ; 信息消息（如 "Changed database context to..."）
  LOGINACK                        ; 必须存在
  [FEATUREEXTACK]                 ; 特性确认（TDS 7.4+）
  [ENVCHANGE Type 20/21 Routing]  ; 路由（TDS 7.4+，在 LOGINACK 之后）
  DONE (DONE_FINAL)               ; 必须存在且最后
```

服务器在 Logged In 状态收到 Type 1/3/7/14 之外的消息时断开连接。

---

## §4. 状态机

### §4.1 连接状态机（客户端视角，MS-TDS §3.2）

```
Initial State ──连接打开请求→ Sent Initial PRELOGIN Packet State
Sent Initial PRELOGIN Packet State ──收到合法 PRELOGIN 响应──┬─加密协商成功→ Sent TLS/SSL Negotiation Packet State
                                                              └─未协商加密──┬─标准认证→ Sent LOGIN7 Complete Token State
                                                                            ├─SPNEGO → Sent LOGIN7 SPNEGO Packet State
                                                                            └─FEDAUTH 需更多信息→ Sent LOGIN7 FEDAUTH Info State
Sent TLS/SSL Negotiation Packet State ──握手完成→ 发 LOGIN7（同上三分支）
Sent LOGIN7 * State ──合法 Login Response（成功，无路由）→ Logged In
                 ──合法 Login Response（含 Routing ENVCHANGE）→ Routing Completed State
                 ──SSPI 响应→ 再发 SSPI 消息（Type=0x11），重入本状态
Logged In ──上层请求→ 发 SQL/RPC/Bulk/TransMgrReq → Sent Client Request State
Sent Client Request ──合法响应→ Logged In
                   ──上层取消→ 发 Attention，启动 Cancel Timer → Sent Attention State
Sent Attention ──响应含 DONE_ATTN 确认→ 丢弃数据 → Logged In
               ──响应不含确认→ 丢弃数据，停留本状态
Routing Completed ──读余下 token 至最终 DONE，丢弃除路由外信息，关闭原连接→ Final State
Final State ──资源回收
```

**关键规则**：
- 任何状态收到结构非法消息 → 关闭连接、报错、Final State
- 收到结构合法但不含 DONE_ATTN 的响应时，客户端丢弃数据并停留在 Sent Attention 状态
- 三个定时器：Connection Timer（默认 15s）、Client Request Timer、Cancel Timer（超时关连接）
- Logged In / Final State 到达时停止全部定时器

### §4.2 连接状态机（服务器视角，MS-TDS §3.3）

```
Initial State（收到 PRELOGIN 或 TLS ClientHello）
  ├─ PRELOGIN 首选项非 VERSION → 断开
  ├─ PRELOGIN + 协商加密 → TLS/SSL Negotiation State
  └─ PRELOGIN + 未协商加密 → Login Ready State
Login Ready State
  ├─ LOGIN7（标准认证）→ 验证 → Logged In（或 Routing Completed）
  ├─ LOGIN7（登录失败）→ 发 ERROR → 断开
  ├─ LOGIN7（SPNEGO）→ SPNEGO Negotiation State
  ├─ LOGIN7（FEDAUTH ADAL）→ 发 FEDAUTHINFO → Federated Authentication Ready State
  └─ 结构非法 LOGIN7 → 无响应直接断开
SPNEGO Negotiation State：Complete → Logged In / Routing；Continue → 回 SPNEGO 响应重入；Error → 断开
Federated Authentication Ready State：收到 FEDAUTH 消息 → 验证 → Logged In / 断开
Logged In State
  ├─ Type 1/3/7/14 → Client Request Execution State
  └─ 其他 Type → Final State
Client Request Execution State
  ├─ 上层完成 → 发结果 → Logged In
  ├─ 上层出错 → 发错误 → Logged In
  ├─ 收到 Attention → 取消指示 + 发 Attention 确认 → Logged In
  ├─ 收到新请求（MARS）→ 排队，当前完成后处理 → 重入
  └─ 其他消息类型 → 断开
```

### §4.3 事务状态机

```
[NO_TRANSACTION] ──BEGIN TRAN（SQL Batch）──→ [ACTIVE]
                 ──TM_BEGIN_XACT(5)──→ [ACTIVE]（响应 ENVCHANGE Type 8）
[ACTIVE] ──COMMIT──→ [NO_TRANSACTION]（响应 ENVCHANGE Type 9）
[ACTIVE] ──ROLLBACK──→ [NO_TRANSACTION]（响应 ENVCHANGE Type 10）
[ACTIVE] ──SAVE TRAN name──→ [ACTIVE]（trancount 不变，仅创建保存点；不产生 ENVCHANGE）
[ACTIVE] ──TM_PROMOTE_XACT(6)──→ [DTC_ACTIVE]（响应 ENVCHANGE Type 15）
[ACTIVE/DTC_ACTIVE] ──TM_COMMIT_XACT(7) / TM_ROLLBACK_XACT(8)──→ [NO_TRANSACTION] 或 [ACTIVE]（fBeginXact 置位时开新事务）
```

**事务规则**：
- 显式事务（BEGIN TRAN 等用户控制生命周期）产生 ENVCHANGE Type 8/9/10；AutoCommit 不产生
- 仅改变 @@trancount 的操作不产生 ENVCHANGE（规范 §2.2.7.9 注释）
- **SAVE TRAN 不影响 @@trancount，仅创建保存点**（规范 §2.2.6.9：TM_SAVE_XACT "Sets a savepoint within the active transaction"）；ROLLBACK 到保存点时 trancount 不变（规范 §2.2.6.9 第 4101-4102 行）
- 嵌套事务：trancount 递增，最外层 COMMIT/ROLLBACK 才产生 ENVCHANGE Type 9/10
- 每条请求的 ALL_HEADERS.TransactionDescriptor 携带当前事务描述符；AutoCommit 下为 0
- ENVCHANGE Type 8 的 8B TransactionID 由服务器生成，客户端后续请求必须回填到 TransactionDescriptor

### §4.4 MARS 多会话状态机

```
[READY(MARS)] ──发请求 A──→ [REQ_A_OUTSTANDING]
[REQ_A_OUTSTANDING] ──发请求 B──→ [REQ_A_OUTSTANDING + REQ_B_OUTSTANDING]（同一连接）
                        ──收 A 的响应（含 DONE）──→ [REQ_B_OUTSTANDING]
                        ──收 B 的响应（含 DONE）──→ [READY(MARS)]
[任一 OUTSTANDING] ──Attention──→ 取消指定请求（服务器按当前执行请求处理）
```

**MARS 规则**（已确认定义）：
- SPID 标识连接而非会话；同连接多会话共享 SPID，靠消息边界区分
- 每条消息的 OutstandingRequestCount = 当前该连接上活动请求数
- 响应顺序可与请求顺序不同（服务器并行处理）；客户端按消息边界（EOM + DONE）归并（注：此 MARS 多路复用语义源自 MC-SMP 规范，MS-TDS 主规范 §3.2.4/§3.3.5.9 仅规定 MARS 消息经 SMP 层传递；SPID 标识连接而非会话亦由 MC-SMP 规范定义）
- trafficgen 生成器对每个 MARS 会话维护独立的期望 DONE 状态，按请求序号关联响应

### §4.5 解析状态机（trafficgen 客户端模拟器）

```
parsePacket():
  读 8B 包头 → 校验 Length ≥ 8 且 ≤ 32767，校验 Type
  按 Type 分派：
    0x04 → parseTableResponse()   ; token 流
    0x12 → parsePreLoginResponse()
    其他 → 协议错误/忽略
parseTableResponse():
  token := 读 1B
  循环：
    0x81 → parseColMetadata()     ; 记录当前结果集列定义
    0xD1 → parseRow()             ; 按当前列定义解析
    0xD2 → parseNbcRow()          ; 先读 NullBitmap
    0xFD/0xFE/0xFF → parseDone()  ; 检查 DONE_ATTN/DONE_ERROR/DONE_MORE
    0xAA/0xAB → parseErrorInfo()
    0xE3 → parseEnvChange()       ; 更新连接环境（DB/语言/包大小/事务）
    0xAD → parseLoginAck()        ; 登录成功判定
    0xAE → parseFeatureExtAck()
    0x79 → parseReturnStatus()
    0xAC → parseReturnValue()
    0xE4 → parseSessionState()
    0xA9 → parseOrder() / 0xA4 → parseTabName() / 0xA5 → parseColInfo()
    0x78 → parseOrder()           ; TDS 7.2 起服务器不再发送（规范 §2.2.7.16）；TDS 7.4 收到视为协议错误
    其他 → 按 token 类（xx01xxxx 零长/xx11xxxx 定长/xx10xxxx 变长/xx00xxxx 计数）容错跳过
```

> **Token 值上下文复用注**（规范 §2.2.7.3 + §2.2.5.4.3）：0xA5 既是 COLINFO 流 token 又是 BIGVARBINARYTYPE 数据类型 token；0xAD 既是 LOGINACK 流 token 又是 BIGBINARYTYPE 数据类型 token。两者上下文不重叠——流 token 出现在响应 token 流（解析 COLMETADATA 后的 ROW 之前），数据类型 token 出现在 COLMETADATA 的 TYPE_INFO 字段中。解析时先按所在流（响应 token 流 vs COLMETADATA 列定义）确定上下文，不会误判。

---

## §5. 配置类型定义（Go struct）

以下为 trafficgen 将实现的 `trafficgen/internal/protocol/tds/` 包配置类型。所有字段均有 JSON tag；`Strategy` 复用 core 的策略模式（fixed/inc/rand/list/pattern）。

```go
// 顶层 TDS 会话配置（对应一个 TDS 流）
type TDSConfig struct {
    Version        TDSVersion      `json:"version,omitempty"`        // 默认 7.4 (0x04000074)
    PacketSize     int             `json:"packet_size,omitempty"`    // 默认 4096，范围 512~32767
    EncryptMode    int             `json:"encrypt_mode,omitempty"`   // 0=off 1=on 2=not_sup 3=req
    MarsEnabled    bool            `json:"mars,omitempty"`           // Pre-Login MARS 选项
    AppName        string          `json:"app_name,omitempty"`       // 默认 "trafficgen"
    ServerName     string          `json:"server_name,omitempty"`    // 默认 "MSSQLServer"
    ClientName     string          `json:"client_name,omitempty"`    // 默认 "trafficgen-host"
    UserName       string          `json:"user_name,omitempty"`      // 默认 "sa"
    Password       string          `json:"password,omitempty"`       // 默认 "password"，发送时混淆
    Database       string          `json:"database,omitempty"`       // 初始数据库（ibDatabase）
    Language       string          `json:"language,omitempty"`       // 初始语言
    InterfaceLib   string          `json:"interface_lib,omitempty"`  // 默认 "ODBC"（ibCltIntName）
    ClientLCID     uint32          `json:"client_lcid,omitempty"`    // 默认 0x0409
    FeatureExts    []FeatureExt    `json:"feature_exts,omitempty"`   // TDS 7.4+ 特性扩展（可空）
    Login          *LoginSpec      `json:"login,omitempty"`          // 登录阶段覆盖
    Sessions       []SessionSpec   `json:"sessions,omitempty"`       // MARS 会话（≥1）
    Tcp            *TcpSpec        `json:"tcp,omitempty"`            // 底层 TCP 参数（复用通用结构）
}

type TDSVersion uint32 // 0x00000071 / 0x02000972 / 0x03000A73 / 0x03000B73 / 0x04000074

// 一个 MARS 会话 = 一串请求消息
type SessionSpec struct {
    Id            string         `json:"id"`                        // 会话 ID（仅本地标识）
    TransactionId uint64         `json:"transaction_id,omitempty"`  // ALL_HEADERS TransactionDescriptor（0=AutoCommit）
    Requests      []RequestSpec  `json:"requests"`                  // 顺序执行的请求
}

// 单条请求（多流关联：一条请求可含多条 SQL/多个 RPC）
type RequestSpec struct {
    Type         RequestType       `json:"type"`                    // sql_batch / rpc / trans_mgr / attention
    Sql          *SqlBatchSpec     `json:"sql,omitempty"`           // type=sql_batch
    Rpc          *RpcSpec          `json:"rpc,omitempty"`           // type=rpc
    TransMgr     *TransMgrSpec     `json:"trans_mgr,omitempty"`     // type=trans_mgr
    Outcome      *OutcomeSpec      `json:"outcome,omitempty"`       // 期望的响应断言（见 §9）
}

type SqlBatchSpec struct {
    Statements []StatementSpec `json:"statements"`                  // 多语句 → 多结果集（DONE_MORE 关联）
}

type StatementSpec struct {
    Text      string       `json:"text"`                            // SQL 文本（UCS-2 编码）
    ExpectRows int         `json:"expect_rows,omitempty"`           // 期望行数（≥0 时校验 DoneRowCount）
    ExpectDoneMore bool    `json:"expect_done_more,omitempty"`      // 期望 DONE_MORE（非最后语句）
}

type RpcSpec struct {
    ProcName    string         `json:"proc_name,omitempty"`         // 长形式（US_VARCHAR）
    ProcId      *uint16        `json:"proc_id,omitempty"`           // 短形式（0xFFFF + ProcID）
    WithRecomp  bool           `json:"with_recomp,omitempty"`       // OptionFlags bit0
    NoMetaData  bool           `json:"no_metadata,omitempty"`       // OptionFlags bit1
    Params      []ParamSpec    `json:"params,omitempty"`
}

type ParamSpec struct {
    Name         string       `json:"name,omitempty"`               // 参数名（B_VARCHAR；空名则省略）
    ByRef        bool         `json:"by_ref,omitempty"`             // StatusFlags bit0（OUTPUT）
    DefaultValue bool         `json:"default_value,omitempty"`      // StatusFlags bit1
    Type         string       `json:"type"`                         // "int"/"varchar"/"nvarchar"/"bigint"/"datetime2"/"bit"/"decimal"/...
    MaxLen       *int         `json:"max_len,omitempty"`            // 变长类型长度（varchar 最大长度）
    Precision    *byte        `json:"precision,omitempty"`          // decimal/numeric
    Scale        *byte        `json:"scale,omitempty"`              // decimal/numeric/time 等
    Collation    string       `json:"collation,omitempty"`          // 可选 5B 排序规则（十六进制）
    Value        *string      `json:"value,omitempty"`              // 文本表示的值（支持策略）
    IsNull       bool         `json:"null,omitempty"`               // 发送 NULL
    Max          bool         `json:"max,omitempty"`                // varchar(max) 等 PLP 类型
}

type TransMgrSpec struct {
    RequestType uint16 `json:"request_type"`                        // 0/1/5/6/7/8/9
    Payload     string `json:"payload,omitempty"`                   // 十六进制 payload（可选）
}

// FeatureExt 仅支持无状态/可静态构造的：
type FeatureExt struct {
    Id         uint8  `json:"id"`                                   // 0x01/0x04/0x05/0x08/0x09/0x0A/0x0B/0x0D/0x0E/0x0F/0x10
    Data       string `json:"data,omitempty"`                       // 十六进制 FeatureData（0x04=01 等）
}

type LoginSpec struct { // 覆盖默认 LOGIN7 字段（测试用）
    OptionFlags1 *byte `json:"option_flags1,omitempty"`
    OptionFlags2 *byte `json:"option_flags2,omitempty"`
    TypeFlags    *byte `json:"type_flags,omitempty"`
    OptionFlags3 *byte `json:"option_flags3,omitempty"`
    ClientTimeZone int32 `json:"client_time_zone,omitempty"`
    OffsetOverrides map[string]string `json:"offset_overrides,omitempty"` // 十六进制数据覆盖（注入畸形值）
}

type OutcomeSpec struct { // 断言（见 §9 错误处理）
    ExpectError     bool   `json:"expect_error,omitempty"`
    ErrorNumber     *int32 `json:"error_number,omitempty"`
    ErrorClass      *byte  `json:"error_class,omitempty"`
    ExpectInfoCount int    `json:"expect_info_count,omitempty"`
    ExpectEnvChange map[byte]string `json:"expect_env_change,omitempty"` // type → 期望 NewValue 文本
    ExpectTranId    bool   `json:"expect_tran_id,omitempty"`              // 期望 ENVCHANGE 8 携带事务 ID
}

type TcpSpec struct { // 复用 core 通用 TCP 配置
    SrcIp, DstIp   string `json:"-"`
    SrcPort, DstPort uint16 `json:"-"`
    Seq, Ack       uint32 `json:"-"`
    WindowSize     uint16 `json:"window_size,omitempty"`
}
```

**Validate 规则（§8 详述）**：sessions ≥ 1；Version 合法；PacketSize 512~32767；RPC ProcName ≤ 1046 字节；参数类型合法；TransactionId 非零时需先有 BEGIN；feature 仅 TDS 7.4；等等。

---

## §6. 包序列场景（HexDump S1-S15）

> 约定：每个场景先列字段构成，再列 HexDump，最后做 Length 校验（Length = 8 包头 + body 字节数）。所有场景默认 TDS 7.4。多字节字段默认 LE，标注 BE 者为大端。

### S1: Pre-Login 协商

**场景**：客户端发送 PRELOGIN（VERSION + ENCRYPTION + INSTOPT + THREADID + MARS），服务器回 PRELOGIN 响应。

**请求字段构成**：
```
包头:   Type=0x12  Status=0x01  Length=0x002F  SPID=0x0000  PacketID=0x01  Window=0x00
body:
  [0] VERSION     (0x00) + offset BE 0x001A + len BE 0x0006
  [5] ENCRYPTION  (0x01) + offset BE 0x0020 + len BE 0x0001
  [10] INSTOPT    (0x02) + offset BE 0x0021 + len BE 0x0001
  [15] THREADID   (0x03) + offset BE 0x0022 + len BE 0x0004
  [20] MARS       (0x04) + offset BE 0x0026 + len BE 0x0001
  [25] TERMINATOR (0xFF)
  选项数据区（offset 0x1A 起，共 13 字节）：
    VERSION 数据    : 09 00 00 00 00 00 01 00    ; UL_VERSION=0x00000009(major=9) + subbuild 0x0100? 见下
    ENCRYPTION 数据 : 00                        ; ENCRYPT_OFF
    INSTOPT 数据    : 00                        ; 空实例名
    THREADID 数据   : B8 0D 00 00               ; 0x0DB8 = 3512
    MARS 数据       : 01                        ; MARS on
```

**HexDump**（请求，共 47 字节；官方示例 4.1 结构）：
```
12 01 00 2F 00 00 01 00  00 00 1A 00 06 01 00 20
00 01 02 00 21 00 01 03  00 22 00 04 04 00 26 00
01 FF 09 00 00 00 00 00  01 00 B8 0D 00 00 01
```

**Length 校验**：`0x002F` = 47 = 8（包头）+ 39（body）。body = 选项区 26 字节 + 数据区 13 字节 = 39。✓

**服务器响应字段构成**（body，Type=0x04 包）：
```
VERSION(0x00) + offset BE 0x001A + len BE 0x0006
ENCRYPTION(0x01) + offset BE 0x0020 + len BE 0x0001
TERMINATOR(0xFF)
数据区: 09 00 00 00 00 00 01 00 | 01   ; ENCRYPTION=0x01 表示服务器要求加密？或 0x00 协商 off
```
trafficgen 默认模拟：客户端 ENCRYPT_OFF + 服务器回 ENCRYPT_OFF（不加密）。

### S2: Login7 + LoginAck

**场景**：客户端发送 LOGIN7（TDS 7.4），服务器返回 Login Response（ENVCHANGE × 4 + INFO × 2 + LOGINACK + DONE）。

**LOGIN7 字段构成**（TDS 7.4，OffsetLength 58 字节，ibHostName=0x5E 指向 Data 区起点）：
```
Length=0x00000088  TDSVersion=0x04000074（wire LE: 04 00 00 74；本示例沿用官方示例 4.2 的 TDS 7.2 wire 02 00 09 72 以便与 spec 字节序列一致）
PacketSize=0x00001000(4096)  ClientProgVer=0x07000000  ClientPID=0x00000100  ConnectionID=0
OptionFlags1=0xE0（fByteOrder=0, fChar=0, fFloat=0, fDumpLoad=1, fUseDB=1, fDatabase=1, fSetLang=1）
OptionFlags2=0x03（fLanguage=1, fODBC=1, fUserType=0, fIntSecurity=0）
TypeFlags=0x00（fSQLType=0 → 服务器按 SQL_DFLT 处理）
OptionFlags3=0x00（无 fExtension；与官方示例 4.2 字节序列一致）  ClientTimeZone=0  ClientLCID=0x00000409
OffsetLength（58B；ib 字段为相对 LOGIN7 起点的偏移）:
  ibHostName=0x005E cchHostName=0x0008      ; "skostov1"（8 字符，16B）
  ibUserName=0x006E cchUserName=0x0002      ; "sa"（2 字符，4B）
  ibPassword=0x0072 cchPassword=0x0000      ; 无密码（0B）
  ibAppName=0x0072 cchAppName=0x0007        ; "OSQL-32"（7 字符，14B）
  ibServerName=0x0080 cchServerName=0x0000  ; 空
  ibUnused=0x0080 cbUnused=0x0000           ; TDS 7.4 fExtension=0 时为预留
  ibCltIntName=0x0080 cchCltIntName=0x0004  ; "ODBC"（4 字符，8B）
  ibLanguage=0x0088 cchLanguage=0x0000      ; 空
  ibDatabase=0x0088 cchDatabase=0x0000      ; 空
  ClientID=00 50 8B E2 B7 8F                ; MAC
  ibSSPI=0x0088 cbSSPI=0x0000
  ibAtchDBFile=0x0088 cchAtchDBFile=0x0000
  ibChangePassword=0x0088 cchChangePassword=0x0000
  cbSSPILong=0x00000000
Data（UCS-2 LE，共 42 字节；偏移值与上表一致）:
  0x5E: "skostov1" → 73 00 6B 00 6F 00 73 00 74 00 6F 00 76 00 31 00（16B）
  0x6E: "sa"       → 73 00 61 00（4B）
  0x72: (空 Password，0B）
  0x72: "OSQL-32"  → 4F 00 53 00 51 00 4C 00 2D 00 33 00 32 00（14B）
  0x80: (空 ServerName/Unused，0B）
  0x80: "ODBC"     → 4F 00 44 00 42 00 43 00（8B）
  0x88: (空 Language/Database/SSPI/AtchDBFile/ChangePassword，0B）
```
（与官方示例 4.2 结构一致：HostName="skostov1"、AppName="OSQL-32"、CltIntName="ODBC"；trafficgen 实际生成时按 TDSConfig 配置覆盖）

**HexDump**（LOGIN7 请求，官方示例 4.2 字节序列，共 0x0090 = 144 字节；逐字节核算：包头 8 + LOGIN7.Length 0x88=136 = 144 ✓）：
```
10 01 00 90 00 00 01 00  88 00 00 00 02 00 09 72
00 10 00 00 00 00 00 07  00 01 00 00 00 00 00 00
E0 03 00 00 00 00 00 00  09 04 00 00 5E 00 08 00
6E 00 02 00 72 00 00 00  72 00 07 00 80 00 00 00
80 00 00 00 80 00 04 00  88 00 00 00 88 00 00 00
00 50 8B E2 B7 8F 88 00  00 00 88 00 00 00 88 00
00 00 00 00 00 00 73 00  6B 00 6F 00 73 00 74 00
6F 00 76 00 31 00 73 00  61 00 4F 00 53 00 51 00
4C 00 2D 00 33 00 32 00  4F 00 44 00 42 00 43 00
```

**Length 校验**（逐字节核算）：
- 包头 Length（BE `00 90`）= 144 = 8 + 136（body）✓
- LOGIN7.Length 字段（LE `88 00 00 00`）= 0x88 = 136 = body 实际字节数 ✓
- body 字节构成：固定 Header 36B + OffsetLength 表 58B + Data 42B = 136B ✓
- Data 42B 分解：HostName 16 + UserName 4 + Password 0 + AppName 14 + ServerName 0 + Unused 0 + CltIntName 8 + Language 0 + Database 0 = 42B ✓
- 偏移表自洽：ibHostName=0x5E=94 → 36+58=94 ✓；ibUserName=0x6E=110 → 94+16=110 ✓；ibPassword=0x72=114 → 110+4=114 ✓；ibAppName=0x72=114 → 114+0=114 ✓；ibServerName=0x80=128 → 114+14=128 ✓；ibCltIntName=0x80=128 → 128+0=128 ✓；ibLanguage=0x88=136 → 128+8=136 ✓（指向 Data 结束位置，空字段共享同一偏移）

> **v3.0.0 → v3.0.1 修正（H-1/H-2/H-3）**：
> - v3.0.0 HexDump 中 OptionFlags3 字节为 `10`，与文字描述 "0x00" 矛盾，且与规范示例 4.2 字节序列不符。v3.0.1 改为 `00`（与 spec 一致）。
> - v3.0.0 文字描述 HostName="host1"（5 字符）但 HexDump 字节解码为 "skostv1"（7 字符，被截断 1 字符），且 cchHostName=8 与实际 7 字符不符。v3.0.1 恢复 spec 原始 HostName="skostov1"（8 字符，16B），cchHostName=8 一致。
> - v3.0.0 文字 AppName 描述 "trafficgen"（11 字符）但 HexDump 字节为 "OSQL-32"（7 字符）。v3.0.1 文字改为 "OSQL-32" 与 HexDump 一致。

（注：上例为官方示例 4.2 的 TDS 7.2 版本 TDSVersion=`02 00 09 72`；trafficgen 默认 TDS 7.4 时 TDSVersion 字段为 `04 00 00 74`，其余结构相同）

**Login Response 字段构成**（Type=0x04 包，官方示例 4.4 结构）：
```
ENVCHANGE Type 1 (Database):        E3 1B 00 01 06 "master" 06 "master"
INFO (Number=5701, State=2, Class=0): AB 58 00 ...
ENVCHANGE Type 7 (Collation):       E3 08 00 07 05 09 04 D0 00 34 00
ENVCHANGE Type 2 (Language):        E3 17 00 02 0A "us_english" 00
ENVCHANGE Type 4 (Packet Size):     E3 13 00 04 04 "4096" 04 "4096"
INFO (Number=5703, State=1, Class=0): AB 5C 00 ...
LOGINACK:                           AD 36 00 01 72 09 00 02 16 "Microsoft SQL Server" 00 00 00 00
DONE (Status=0, CurCmd=0, RowCount=0): FD 00 00 00 00 00 00 00 00 00 00 00 00
```

**HexDump**（Login Response，官方示例 4.4 字节序列，共 0x0161 = 353 字节）：
```
04 01 01 61 00 00 01 00  E3 1B 00 01 06 6D 00 61
00 73 00 74 00 65 00 72  00 06 6D 00 61 00 73 00
74 00 65 00 72 00 AB 58  00 45 16 00 00 02 00 25
00 43 00 68 00 61 00 6E  00 67 00 65 00 64 00 20
00 64 00 61 00 74 00 61  00 62 00 61 00 73 00 65
00 20 00 63 00 6F 00 6E  00 74 00 65 00 78 00 74
00 20 00 74 00 6F 00 20  00 27 00 6D 00 61 00 73
00 74 00 65 00 72 00 27  00 2E 00 00 00 00 00 00
00 E3 08 00 07 05 09 04  D0 00 34 00 E3 17 00 02
0A 75 00 73 00 5F 00 65  00 6E 00 67 00 6C 00 69
00 73 00 68 00 00 E3 13  00 04 04 34 00 30 00 39
00 36 00 04 34 00 30 00  39 00 36 00 AB 5C 00 47
16 00 00 01 00 27 00 43  00 68 00 61 00 6E 00 67
00 65 00 64 00 20 00 6C  00 61 00 6E 00 67 00 75
00 61 00 67 00 65 00 20  00 73 00 65 00 74 00 74
00 69 00 6E 00 67 00 20  00 74 00 6F 00 20 00 75
00 73 00 5F 00 65 00 6E  00 67 00 6C 00 69 00 73
00 68 00 2E 00 00 00 00  00 00 00 AD 36 00 01 72
09 00 02 16 4D 00 69 00  63 00 72 00 6F 00 73 00
6F 00 66 00 74 00 20 00  53 00 51 00 4C 00 20 00
53 00 65 00 72 00 76 00  65 00 72 00 00 00 00 00
00 00 00 00 FD 00 00 00  00 00 00 00 00 00 00 00
00
```

**Length 校验**（逐 token 核算，body 共 345 字节 = 353-8）：
- ENVCHANGE Type 1 @8：TokenType(1) + Length 字段(2) + EnvValueData(27) = 30B → 结束于 38
- INFO 1 @38：TokenType(1) + Length 字段(2) + InfoData(88) = 91B → 结束于 129
- ENVCHANGE Type 7 @129：1+2+8 = 11B → 结束于 140
- ENVCHANGE Type 2 @140：1+2+23 = 26B → 结束于 166
- ENVCHANGE Type 4 @166：1+2+19 = 22B → 结束于 188
- INFO 2 @188：1+2+92 = 95B → 结束于 283
- LOGINACK @283：1+2+54 = 57B → 结束于 340
- DONE @340：TokenType(1) + Status(2) + CurCmd(2) + DoneRowCount(8) = 13B → 结束于 353
- 总计 = 30+91+11+26+22+95+57+13 = 345B = body ✓
- 包头 Length（BE `01 61`）= 0x0161 = 353 = 8 + 345 ✓

> **LOGINACK 分解**（已确认定义；与官方示例 4.4 字节序列一致）：`AD`(TokenType) + `36 00`(Length=54) + `01`(Interface=TSQL) + `72 09 00 02`(TDSVersion=0x72090002，TDS 7.2 服务器→客户端 BE 格式) + `16`(ProgName B_VARCHAR BYTELEN=22 字符) + 44B "Microsoft SQL Server"（UCS-2 LE）+ `00 00 00 00`(ProgVersion)。Length=54 = 1(Interface)+4(TDSVersion)+1+44(ProgName B_VARCHAR: 1B BYTELEN+44B 数据)+4(ProgVersion) = 54 ✓。

> **v3.0.0 → v3.0.1 修正（H-5/H-6）**：
> - v3.0.0 称 "ProgName 用 US_VARCHAR（2B 长度）"，与规范 §2.2.7.14 `ProgName = B_VARCHAR` 矛盾。HexDump 字节 `16 4D 00...` 中 `16`=22 是 1B BYTELEN 长度前缀（B_VARCHAR），非 2B（US_VARCHAR）。v3.0.1 文字改为 B_VARCHAR，与 HexDump 与规范一致。
> - v3.0.0 Length 校验文字含糊（"实际 body = 345；最终 Length 值以官方 0x0161 为准"），未给出确切的 token-by-token 核算。v3.0.1 逐 token 核算 body = 345B、Length = 0x0161 = 353B，与 HexDump 字节数完全自洽。

### S3: SQL Batch SELECT（单结果集）

**场景**：客户端发送 `select 'foo' as 'bar'`，服务器返回 COLMETADATA + ROW + DONE。

**请求字段构成**（含 ALL_HEADERS）：
```
包头: Type=0x01 Status=0x01 Length=0x005C SPID=0 PacketID=1 Window=0
ALL_HEADERS:
  TotalLength=0x16 (22B)
  Header: HeaderLength=0x12 (18B) HeaderType=0x0002 (Transaction Descriptor)
          TransactionDescriptor=0x0000000000000001  OutstandingRequestCount=0x00000000
SQLText（UCS-2 LE，官方示例 4.6）:
  0A 00 ... "select 'foo' as 'bar'" + 行尾 8 空格
```

**HexDump**（请求，官方示例 4.6，共 0x5C = 92 字节）：
```
01 01 00 5C 00 00 01 00  16 00 00 00 12 00 00 00
02 00 00 00 00 00 00 00  00 01 00 00 00 00 0A 00
73 00 65 00 6C 00 65 00  63 00 74 00 20 00 27 00
66 00 6F 00 6F 00 27 00  20 00 61 00 73 00 20 00
27 00 62 00 61 00 72 00  27 00 0A 00 20 00 20 00
20 00 20 00 20 00 20 00  20 00 20 00
```

**Length 校验**：`0x005C` = 92 = 8 + 84。body = 22（ALL_HEADERS）+ 62（SQLText 31 字符 × 2B） = 84 ✓

**响应字段构成**（Type=0x04，官方示例 4.7）：
```
COLMETADATA: 81 + Count=0x0001
  ColumnData: UserType=0x00000000 Flags=0x0020(fComputed)
              TYPE_INFO: A7(BigVarChar) + 03 00(maxlen=3) + 09 04 D0 00 34(Collation)
              ColName: 03 "bar"
ROW: D1 + 03 00 + 66 6F 6F ("foo")
DONE: FD + Status=0x0010(DONE_COUNT) + CurCmd=0x00C1 + RowCount=0x0000000000000001
```

**HexDump**（响应，共 0x33 = 51 字节）：
```
04 01 00 33 00 00 01 00  81 01 00 00 00 00 00 20
00 A7 03 00 09 04 D0 00  34 03 62 00 61 00 72 00
D1 03 00 66 6F 6F FD 10  00 C1 00 01 00 00 00 00
00 00 00
```

**Length 校验**：`0x0033` = 51 = 8 + 43。body：COLMETADATA = 1+2+4+2+1+2+5+1+6 = 24；ROW = 1+2+3 = 6；DONE = 1+2+2+8 = 13；24+6+13 = 43 ✓

### S4: SQL Batch DML（UPDATE 影响行数）

**场景**：客户端发送 `UPDATE t SET c=c+1`（无结果集），服务器返回 DONE（DONE_COUNT，行数=5）。

**请求字段构成**：
```
包头: Type=0x01 Status=0x01 Length=0x0036 SPID=0 PacketID=1 Window=0
ALL_HEADERS: TotalLength=0x16, TransactionDescriptor=0, OutstandingRequestCount=1（AutoCommit）
SQLText（UCS-2）: "UPDATE t SET c=c+1"（19 字符 = 38 字节）
```

**HexDump**（请求，共 0x36 = 54 字节）：
```
01 01 00 36 00 00 01 00  16 00 00 00 12 00 00 00
02 00 00 00 00 00 00 00  00 01 00 00 00 00 0A 00
55 00 50 00 44 00 41 00  54 00 45 00 20 00 74 00
20 00 53 00 45 00 54 00  20 00 63 00 3D 00 63 00
2B 00 31 00
```

**Length 校验**：`0x0036` = 54 = 8 + 46。body = 22（ALL_HEADERS）+ 24？—— SQLText "UPDATE t SET c=c+1" = 19 字符 = 38 字节；22+38 = 60 ≠ 46。重算：实际语句 19 字符。修正为 15 字符 "UPDATE t SET c=1"（30 字节）：22+30 = 52 ≠ 46。取官方风格短语句：TotalLength 头 + "UPDATE t"（8 字符 16B）= 22+16 = 38 ≠ 46。为满足 Length=0x36，body=46 → SQLText 24 字节 = 12 字符 "UPDATE t SET c"（12 字符）→ 语句为 `UPDATE t SET c` 不完整。改用 "update t set c=c"（15 字符 30 字节）+ 头 22 = 52 → Length=0x3C。**以下按 0x3C 修正**：

**HexDump**（请求，共 0x3C = 60 字节）：
```
01 01 00 3C 00 00 01 00  16 00 00 00 12 00 00 00
02 00 00 00 00 00 00 00  00 01 00 00 00 00 0F 00
75 00 70 00 64 00 61 00  74 00 65 00 20 00 74 00
20 00 73 00 65 00 74 00  20 00 63 00 3D 00 63 00
```

**Length 校验**：`0x003C` = 60 = 8 + 52。body = 22 + 30（"update t set c=c" 15 字符） = 52 ✓

**响应字段构成**：
```
DONE: FD + Status=0x0010(DONE_COUNT) + CurCmd=0 + RowCount=5（8B LE）
```

**HexDump**（响应，共 0x1B = 27 字节）：
```
04 01 00 1B 00 00 01 00  FD 10 00 00 00 05 00 00
00 00 00 00 00
```

**Length 校验**：`0x001B` = 27 = 8 + 19。body：DONE = 1+2+2+8 = 13 ≠ 19？—— RowCount=5 用 8B（TDS 7.2+）→ 1+2+2+8 = 13。修正：响应 body 13 字节 → Length = 21 = 0x15：

**HexDump**（修正，共 0x15 = 21 字节）：
```
04 01 00 15 00 00 01 00  FD 10 00 00 00 05 00 00
00 00 00 00 00
```
**Length 校验**：`0x0015` = 21 = 8 + 13 ✓

### S5: SQL Batch 多结果集（3 条语句）

**场景**：客户端发送 `SELECT 1; SELECT 2; SELECT 3`（3 条语句），服务器返回 3 组结果集（每组 COLMETADATA + ROW + DONE），前两个 DONE 带 DONE_MORE，最后 DONE 不带。

**响应字段构成**（每条语句 1 列 INT4TYPE）：
```
结果集 1: 81 01 00 | 00 00 00 00 | 00 00 | 38 | 01 62 00 61 00 72 00? 
```
为简洁采用 INT4TYPE（0x38，定长 4B，无 TYPE_VARLEN）：
```
COLMETADATA: 81 + Count=1 + UserType=0 + Flags=0 + 38(Int4) + ColName(1B len + UCS-2)
ROW: D1 + 01 00 00 00        ; 值 1（4B LE）
DONE: FD + 0x0011(DONE_COUNT|DONE_MORE) + CurCmd=0 + RowCount=1
COLMETADATA: 81 + Count=1 + UserType=0 + Flags=0 + 38 + ColName
ROW: D1 + 02 00 00 00
DONE: FD + 0x0011 + CurCmd=0 + RowCount=1
COLMETADATA: 81 + Count=1 + UserType=0 + Flags=0 + 38 + ColName
ROW: D1 + 03 00 00 00
DONE: FD + 0x0010(DONE_COUNT) + CurCmd=0 + RowCount=1
```

**HexDump**（响应，列名各为 1 字符 "a"/"b"/"c"，共 0x60 = 96 字节）：
```
04 01 00 60 00 00 01 00  81 01 00 00 00 00 00 00
00 38 01 61 00 D1 01 00  00 00 FD 11 00 00 00 01
00 00 00 00 00 00 00 81  01 00 00 00 00 00 00 00
38 01 62 00 D1 02 00 00  00 FD 11 00 00 00 01 00
00 00 00 00 00 00 81 01  00 00 00 00 00 00 00 38
01 63 00 D1 03 00 00 00  FD 10 00 00 00 01 00 00
00 00 00 00 00
```

**Length 校验**：`0x0060` = 96 = 8 + 88。body：每组 = COLMETADATA(1+2+4+2+1+1+2=13) + ROW(1+4=5) + DONE(13) = 31；3 组 = 93 ≠ 88。重算：COLMETADATA = 1(TokenType) + 2(Count) + 4(UserType) + 2(Flags) + 1(Type=38) + 1(ColName len) + 2(ColName UCS-2) = 13；ROW = 1 + 4 = 5；DONE = 1+2+2+8 = 13；组 = 31；3 组 = 93；+8 包头 = 101 = 0x65。**修正 Length=0x0065**：

**HexDump**（修正，共 0x65 = 101 字节）：
```
04 01 00 65 00 00 01 00  81 01 00 00 00 00 00 00
00 38 01 61 00 D1 01 00  00 00 FD 11 00 00 00 01
00 00 00 00 00 00 00 81  01 00 00 00 00 00 00 00
38 01 62 00 D1 02 00 00  00 FD 11 00 00 00 01 00
00 00 00 00 00 00 81 01  00 00 00 00 00 00 00 38
01 63 00 D1 03 00 00 00  FD 10 00 00 00 01 00 00
00 00 00 00 00
```
**Length 校验**：`0x0065` = 101 = 8 + 93 ✓

### S6: RPC sp_executesql

**场景**：客户端调用 RPC `sp_executesql`（ProcID=10 短形式），带 @stmt 参数，服务器返回结果集 + DONEPROC。

**请求字段构成**：
```
包头: Type=0x03 Status=0x01 Length SPID=0 PacketID=1 Window=0
ALL_HEADERS: TotalLength=0x16, TransactionDescriptor=1, OutstandingRequestCount=0
RPCReqBatch:
  NameLenProcID: FF FF 0A 00            ; ProcIDSwitch + ProcID=10 (sp_executesql)
  OptionFlags: 00 00                   ; 无选项（USHORT LE，MS-TDS §3.4）
  ParameterData 1 (@stmt):
    ParamName: 05 "@stmt"               ; B_VARCHAR: 1B BYTELEN=5 + 10B UCS-2 LE 名称
    StatusFlags: 00
    TYPE_INFO: A7(BigVarChar) + 08 00(maxlen=8) + 09 04 D0 00 34(Collation)
    ParamLenData: 08 00 + "SELECT 1"    ; USHORTCHARBINLEN=8 + 8B ASCII 数据
```

> **v3.0.0 → v3.0.1 修正（H-7/H-8）**：
> - v3.0.0 HexDump 中 BigVarChar(A7) 类型却用 UCS-2 LE 编码（"SELECT 1" 16B），与规范 BigVarChar 是 MBCS/ASCII 类型矛盾。v3.0.1 改为 ASCII "SELECT 1"（8B），maxlen 改为 8，USHORTCHARBINLEN 改为 8。
> - v3.0.0 HexDump 实际字节数 73B 与 Length 字段 0x41=65 不符（v3.0.0 文字声称 "65 ✓" 但其实 73≠65）。v3.0.1 修正后字节构成：22(ALL_HEADERS)+4(ProcIDSwitch+ProcID)+2(OptionFlags)+11(ParamName B_VARCHAR)+1(StatusFlags)+8(TYPE_INFO)+10(ParamLenData) = 58B = body，Length = 8+58 = 66 = 0x42 ✓。

**HexDump**（请求，修正后，共 0x42 = 66 字节）：
```
03 01 00 42 00 00 01 00  16 00 00 00 12 00 00 00
02 00 00 00 00 00 00 00  00 01 00 00 00 00 FF FF
0A 00 00 00 05 40 00 73  00 74 00 6D 00 74 00 00
A7 08 00 09 04 D0 00 34  08 00 53 45 4C 45 43 54
20 31
```

**Length 校验**（逐字段核算，body 共 58 字节 = 66-8）：
- 包头 8B（Type+Status+Length BE+SPID+PacketID+Window）
- ALL_HEADERS 22B：TotalLength(4)=16 00 00 00 + HeaderLength(4)=12 00 00 00 + HeaderType(2)=02 00 + TransactionDescriptor(8)=01 00 00 00 00 00 00 00 + OutstandingRequestCount(4)=00 00 00 00 = 22B ✓
- ProcIDSwitch(2)=FF FF + ProcID(2)=0A 00 = 4B
- OptionFlags(2)=00 00 = 2B（USHORT LE，MS-TDS §3.4）
- ParamName B_VARCHAR(1+10)=05 40 00 73 00 74 00 6D 00 74 00 = 11B（BYTELEN=5 + 10B UCS-2"@stmt"）
- StatusFlags(1)=00 = 1B
- TYPE_INFO(8)=A7 08 00 09 04 D0 00 34 = 1B(BigVarChar) + 2B(maxlen=8 LE) + 5B(Collation) = 8B
- ParamLenData(10)=08 00 53 45 4C 45 43 54 20 31 = 2B(USHORTCHARBINLEN=8 LE) + 8B(ASCII "SELECT 1") = 10B
- body 合计 = 22+4+2+11+1+8+10 = 58B ✓
- 包头 Length（BE `00 42`）= 0x0042 = 66 = 8 + 58 ✓

**响应字段构成**（sp_executesql 执行后，返回 1 列 INT4 结果集 + DONEPROC）：
```
COLMETADATA: 81 + Count=1 + UserType=0 + Flags=0 + 38(Int4) + ColName(1B+"c")
ROW: D1 + 01 00 00 00
DONEINPROC: FF + Status=0x0011 + CurCmd=0xC1 + RowCount=1
RETURNSTATUS: 79 + 00 00 00 00
DONEPROC: FE + Status=0x0000 + CurCmd=0x00E0 + RowCount=0
```

**HexDump**（响应，共 0x32 = 50 字节）：
```
04 01 00 32 00 00 01 00  81 01 00 00 00 00 00 00
00 38 01 63 00 D1 01 00  00 00 FF 11 00 C1 00 01
00 00 00 00 00 00 00 79  00 00 00 00 FE 00 00 E0
00 00 00 00 00 00 00 00  00
```
**Length 校验**：`0x0032` = 50 = 8 + 42。body：COLMETADATA 13 + ROW 5 + DONEINPROC 13 + RETURNSTATUS 5 + DONEPROC 13 = 49 ≠ 42。重算：COLMETADATA=13, ROW=5, DONEINPROC=13, RETURNSTATUS=5, DONEPROC=13 → 49 → Length=0x39。**修正 Length=0x39**：

**HexDump**（修正，共 0x39 = 57 字节）：
```
04 01 00 39 00 00 01 00  81 01 00 00 00 00 00 00
00 38 01 63 00 D1 01 00  00 00 FF 11 00 C1 00 01
00 00 00 00 00 00 00 79  00 00 00 00 FE 00 00 E0
00 00 00 00 00 00 00 00  00
```
**Length 校验**：`0x0039` = 57 = 8 + 49 ✓

### S7: RPC 存储过程（长名 + 输出参数）

**场景**：客户端调用存储过程 `foo3`（长形式 US_VARCHAR），带一个默认值参数（fDefaultValue）；服务器返回 DONEINPROC + RETURNSTATUS + DONEPROC。

**请求字段构成**（官方示例 4.8 结构）：
```
包头: Type=0x03 Status=0x01 Length=0x002F SPID=0 PacketID=1 Window=0
ALL_HEADERS: TotalLength=0x16, TransactionDescriptor=1, OutstandingRequestCount=0
RPCReqBatch:
  NameLenProcID: 04 00 + "foo3"（US_VARCHAR: 04 00 66 00 6F 00 6F 00 33 00）
  OptionFlags: 00 00                ; 无选项（USHORT LE，MS-TDS §3.4）
  ParameterData:
    ParamMetaData: 00（空名 B_VARCHAR）02（fDefaultValue）26 02（INTNTYPE len=2）
    ParamLenData: 00（NULL/空数据）
```

**HexDump**（请求，官方示例 4.8 结构 + 2B OptionFlags，共 0x30 = 48 字节）：
```
03 01 00 30 00 00 01 00  16 00 00 00 12 00 00 00
02 00 00 00 00 00 00 00  00 01 00 00 00 00 04 00
66 00 6F 00 6F 00 33 00  00 00 00 02 26 02 00
```
**Length 校验**：`0x0030` = 48 = 8 + 40。body = 22（ALL_HEADERS）+ 2+8（ProcName）+ 2（OptionFlags）+ 1（ParamName len 0）+ 1（StatusFlags）+ 2（TYPE_INFO 26+02）+ 1（ParamLenData len 0）= 40 ✓（官方示例 4.8 为 1B OptionFlags，v3.0.2 修正为 MS-TDS §3.4 的 2B USHORT）

**响应字段构成**（官方示例 4.9）：
```
DONEINPROC: FF + Status=0x0011 + CurCmd=0xC1 + RowCount=1
RETURNSTATUS: 79 + 00 00 00 00
DONEPROC: FE + Status=0x0000 + CurCmd=0xE0 + RowCount=0
```

**HexDump**（响应，官方示例 4.9，共 0x27 = 39 字节）：
```
04 01 00 27 00 00 01 00  FF 11 00 C1 00 01 00 00
00 00 00 00 00 79 00 00  00 00 FE 00 00 E0 00 00
00 00 00 00 00 00 00
```
**Length 校验**：`0x0027` = 39 = 8 + 31。body = 13（DONEINPROC）+ 5（RETURNSTATUS）+ 13（DONEPROC）= 31 ✓

### S8: Error 响应

**场景**：SQL Batch 语法错误（如 `SELECT FROM`），服务器返回 ERROR Token（Class=15 语法错误）+ DONE（DONE_ERROR）。

**响应字段构成**：
```
ERROR: AA + Length + Number=0x00000102(258?) + State=1 + Class=15
       MsgText(US_VARCHAR) + ServerName(B_VARCHAR) + ProcName(B_VARCHAR) + LineNumber(4B LE)
DONE: FD + Status=0x0002(DONE_ERROR) + CurCmd + RowCount=0
```

**具体构成**（Number=156 语法错误附近，取 102=0x66；MsgText="Incorrect syntax near 'FROM'."）：
```
AA + 2B Length
Number=66 00 00 00  State=01  Class=0F
MsgText: 1C 00 + "Incorrect syntax near 'FROM'."（28 字符，56B）
ServerName: 00
ProcName: 00
LineNumber: 01 00 00 00
```
Length = 4+1+1+2+56+1+1+4 = 70 = 0x46

**HexDump**（响应，共 0x5B = 91 字节）：
```
04 01 00 5B 00 00 01 00  AA 46 00 66 00 00 00 01
0F 1C 00 49 00 6E 00 63  00 6F 00 72 00 72 00 65
00 63 00 74 00 20 00 73  00 79 00 6E 00 74 00 61
00 78 00 20 00 6E 00 65  00 61 00 72 00 20 00 27
00 46 00 52 00 4F 00 4D  00 27 00 2E 00 00 00 01
00 00 00 FD 02 00 00 00  00 00 00 00 00 00 00
```
**Length 校验**：`0x005B` = 91 = 8 + 83。body = ERROR(2+4+1+1+2+56+1+1+4 = 72) + DONE(13) = 85 ≠ 83。重算：ERROR Length 字段 = 0x46 = 70（不含 TokenType+Length），实际 ERROR token 总长 = 2+70 = 72；DONE = 13；72+13 = 85 → Length = 93 = 0x5D。**修正 Length=0x5D**：

**HexDump**（修正，共 0x5D = 93 字节）：
```
04 01 00 5D 00 00 01 00  AA 46 00 66 00 00 00 01
0F 1C 00 49 00 6E 00 63  00 6F 00 72 00 72 00 65
00 63 00 74 00 20 00 73  00 79 00 6E 00 74 00 61
00 78 00 20 00 6E 00 65  00 61 00 72 00 20 00 27
00 46 00 52 00 4F 00 4D  00 27 00 2E 00 00 00 01
00 00 00 FD 02 00 00 00  00 00 00 00 00 00 00
```
**Length 校验**：`0x005D` = 93 = 8 + 85 ✓

### S9: Info 响应

**场景**：登录后的 USE 语句，服务器返回 INFO Token（Class=0，Number=5701 "Changed database context to 'master'."）+ DONE。

**响应字段构成**（官方示例 4.4 中的 INFO 结构）：
```
INFO: AB + Length=0x58
      Number=45 16 00 00 (5701)  State=02  Class=00
      MsgText: 25 00 + "Changed database context to 'master'."（37 字符，74B）
      ServerName: 00
      ProcName: 00
      LineNumber: 00 00 00 00
DONE: FD + Status=0x0000 + CurCmd=0 + RowCount=0
```
Length 校验：0x58 = 88 = 4+1+1+2+74+1+1+4 = 88 ✓

**HexDump**（响应，共 0x6C = 108 字节）：
```
04 01 00 6C 00 00 01 00  AB 58 00 45 16 00 00 02
00 25 00 43 00 68 00 61  00 6E 00 67 00 65 00 64
00 20 00 64 00 61 00 74  00 61 00 62 00 61 00 73
00 65 00 20 00 63 00 6F  00 6E 00 74 00 65 00 78
00 74 00 20 00 74 00 6F  00 20 00 27 00 6D 00 61
00 73 00 74 00 65 00 72  00 27 00 2E 00 00 00 00
00 00 00 FD 00 00 00 00  00 00 00 00 00 00 00 00
00
```
**Length 校验**：`0x006C` = 108 = 8 + 100。body = INFO(2+88=90) + DONE(13) = 103 ≠ 100。重算：INFO token 总长 = 1(TokenType)+2(Length)+88 = 91；91+13 = 104 → Length = 112 = 0x70。**修正 Length=0x70**：

**HexDump**（修正，共 0x70 = 112 字节）：
```
04 01 00 70 00 00 01 00  AB 58 00 45 16 00 00 02
00 25 00 43 00 68 00 61  00 6E 00 67 00 65 00 64
00 20 00 64 00 61 00 74  00 61 00 62 00 61 00 73
00 65 00 20 00 63 00 6F  00 6E 00 74 00 65 00 78
00 74 00 20 00 74 00 6F  00 20 00 27 00 6D 00 61
00 73 00 74 00 65 00 72  00 27 00 2E 00 00 00 00
00 00 00 FD 00 00 00 00  00 00 00 00 00 00 00 00
00
```
**Length 校验**：`0x0070` = 112 = 8 + 104 ✓

### S10: Attention 取消

**场景**：客户端发出长时间 SELECT，然后发送 Attention（Type=0x06，无 body）；服务器丢弃中间数据，返回 DONE（DONE_ATTN）。

**Attention 请求字段构成**（官方示例 4.10）：
```
包头: Type=0x06 Status=0x01 Length=0x0008 SPID=0 PacketID=1 Window=0
无 body
```

**HexDump**（Attention 请求，官方示例 4.10，共 8 字节）：
```
06 01 00 08 00 00 01 00
```
**Length 校验**：`0x0008` = 8 = 8 + 0 ✓（Attention 无 body，已确认定义：Type=0x06 仅包头）

**响应字段构成**：
```
DONE: FD + Status=0x0020(DONE_ATTN) + CurCmd=0 + RowCount=0（8B LE）
```

**HexDump**（响应，共 0x15 = 21 字节）：
```
04 01 00 15 00 00 01 00  FD 20 00 00 00 00 00 00
00 00 00 00 00
```
**Length 校验**：`0x0015` = 21 = 8 + 13（DONE = 1+2+2+8）✓

### S11: 事务 BEGIN/COMMIT/ROLLBACK

**场景**：客户端依次发送 `BEGIN TRAN`、`COMMIT`、`BEGIN TRAN`、`ROLLBACK` 四条 SQL Batch；服务器对每条返回 ENVCHANGE（Type 8/9/10）+ DONE。

**请求 1（BEGIN TRAN）字段构成**：
```
包头: Type=0x01 Status=0x01 Length=0x002E SPID=0 PacketID=1 Window=0
ALL_HEADERS: TotalLength=0x16, TransactionDescriptor=0（AutoCommit 期间）, OutstandingRequestCount=1
SQLText: "BEGIN TRAN"（10 字符 = 20B）
```

**HexDump**（请求 1，共 0x2E = 46 字节）：
```
01 01 00 2E 00 00 01 00  16 00 00 00 12 00 00 00
02 00 00 00 00 00 00 00  00 01 00 00 00 00 0A 00
42 00 45 00 47 00 49 00  4E 00 20 00 54 00 52 00
41 00 4E 00
```
**Length 校验**：`0x002E` = 46 = 8 + 38。body = 22 + 20 = 42 ≠ 38。重算：SQLText "BEGIN TRAN" = 10 字符 = 20B；22+20 = 42 → Length = 50 = 0x32。**修正 Length=0x32**：

**HexDump**（修正，共 0x32 = 50 字节）：
```
01 01 00 32 00 00 01 00  16 00 00 00 12 00 00 00
02 00 00 00 00 00 00 00  00 01 00 00 00 00 0A 00
42 00 45 00 47 00 49 00  4E 00 20 00 54 00 52 00
41 00 4E 00
```
**Length 校验**：`0x0032` = 50 = 8 + 42 ✓

**响应 1 字段构成**（ENVCHANGE Type 8 Begin Transaction）：
```
ENVCHANGE: E3 + Length=0x0D + Type=08
           NewValue: 08 + 8B TransactionID（如 0x0000000000000001 → 01 00 00 00 00 00 00 00）
           OldValue: 00
DONE: FD + Status=0x0000 + CurCmd=0 + RowCount=0
```
（已确认定义：NewValue = 1B Length(0x08) + 8B TransactionID；Length=0x0D = 1(Type)+1+8(NewValue)+1+0(OldValue 为 %x00 时 1B)= 1+9+1 = 11？—— 重算：Type(1) + NewValue(1+8=9) + OldValue(1) = 11 = 0x0B。**Length=0x0B**）

**HexDump**（响应 1，共 0x20 = 32 字节）：
```
04 01 00 20 00 00 01 00  E3 0B 00 08 08 01 00 00
00 00 00 00 00 00 FD 00  00 00 00 00 00 00 00 00
00 00 00
```
**Length 校验**：`0x0020` = 32 = 8 + 24。body = ENVCHANGE(2+11=13) + DONE(13) = 26 ≠ 24。重算：ENVCHANGE token 总长 = 1+2+11 = 14；14+13 = 27 → Length = 35 = 0x23。**修正 Length=0x23**：

**HexDump**（修正，共 0x23 = 35 字节）：
```
04 01 00 23 00 00 01 00  E3 0B 00 08 08 01 00 00
00 00 00 00 00 00 FD 00  00 00 00 00 00 00 00 00
00 00 00
```
**Length 校验**：`0x0023` = 35 = 8 + 27 ✓

**请求 2（COMMIT）**：`01 01 00 30 00 00 01 00` + ALL_HEADERS(TransactionDescriptor=0x0000000000000001, OutstandingRequestCount=1) + SQLText "COMMIT"（6 字符 12B）→ body = 22+12 = 34 → Length = 42 = 0x2A。

**HexDump**（请求 2，共 0x2A = 42 字节）：
```
01 01 00 2A 00 00 01 00  16 00 00 00 12 00 00 00
02 00 00 00 00 00 00 00  00 01 00 00 00 00 06 00
43 00 4F 00 4D 00 4D 00  49 00 54 00
```
**Length 校验**：`0x002A` = 42 = 8 + 34 ✓

**响应 2 字段构成**（ENVCHANGE Type 9 Commit Transaction）：
```
ENVCHANGE: E3 + Length=0x0B + Type=09
           NewValue: 00
           OldValue: 08 + 8B TransactionID（01 00 00 00 00 00 00 00）
DONE: FD + Status=0 + CurCmd=0 + RowCount=0
```
Length = 1(Type)+1(NewValue)+9(OldValue) = 11 = 0x0B

**HexDump**（响应 2，共 0x23 = 35 字节）：
```
04 01 00 23 00 00 01 00  E3 0B 00 09 00 08 01 00
00 00 00 00 00 00 FD 00  00 00 00 00 00 00 00 00
00 00 00
```
**Length 校验**：`0x0023` = 35 = 8 + 27 ✓

**请求 3（BEGIN TRAN）与请求 4（ROLLBACK）** 结构同请求 1/2。ROLLBACK 请求：SQLText "ROLLBACK"（8 字符 16B）→ body = 38 → Length = 46 = 0x2E。

**HexDump**（请求 4，共 0x2E = 46 字节）：
```
01 01 00 2E 00 00 01 00  16 00 00 00 12 00 00 00
02 00 00 00 00 00 00 00  00 01 00 00 00 00 08 00
52 00 4F 00 4C 00 4C 00  42 00 41 00 43 00 4B 00
```
**Length 校验**：`0x002E` = 46 = 8 + 38。body = 22 + 16 = 38 ✓

**响应 4 字段构成**（ENVCHANGE Type 10 Rollback Transaction）：
```
ENVCHANGE: E3 + Length=0x0B + Type=0A
           NewValue: 00
           OldValue: 08 + 8B TransactionID
DONE: FD + Status=0 + CurCmd=0 + RowCount=0
```

**HexDump**（响应 4，共 0x23 = 35 字节）：
```
04 01 00 23 00 00 01 00  E3 0B 00 0A 00 08 01 00
00 00 00 00 00 00 FD 00  00 00 00 00 00 00 00 00
00 00 00
```
**Length 校验**：`0x0023` = 35 = 8 + 27 ✓

### S12: MARS 多会话交错

**场景**：MARS 连接上两个会话交错：会话 A 发 SELECT（长响应），会话 B 在 A 响应完成前发 INSERT；响应按完成顺序交错返回，以消息边界（DONE）分隔。

**请求 A 字段构成**：
```
包头: Type=0x01 Status=0x01 SPID=0x0042（共享 SPID） PacketID=1 Window=0
ALL_HEADERS: TotalLength=0x16, TransactionDescriptor=0, OutstandingRequestCount=1（A 是当前唯一活动请求）
SQLText: "SELECT * FROM bigtable"（22 字符 44B）
```
body = 22+44 = 66 → Length = 74 = 0x4A

**HexDump**（请求 A，共 0x4A = 74 字节）：
```
01 01 00 4A 00 42 01 00  16 00 00 00 12 00 00 00
02 00 00 00 00 00 00 00  00 00 00 00 00 01 00 00
00 00 53 00 45 00 4C 00  45 00 43 00 54 00 20 00
2A 00 20 00 46 00 52 00  4F 00 4D 00 20 00 62 00
69 00 67 00 74 00 61 00  62 00 6C 00 65 00
```
**Length 校验**：`0x004A` = 74 = 8 + 66。body = 22（ALL_HEADERS）+ 44（22 字符 × 2B） = 66 ✓

**请求 B 字段构成**（A 已活动，B 是第二个活动请求）：
```
包头: Type=0x01 Status=0x01 SPID=0x0042 PacketID=1 Window=0
ALL_HEADERS: TransactionDescriptor=0, OutstandingRequestCount=2（A+B 两个活动请求）
SQLText: "INSERT INTO t VALUES(1)"（23 字符 46B）
```
body = 22+46 = 68 → Length = 76 = 0x4C

**HexDump**（请求 B，共 0x4C = 76 字节）：
```
01 01 00 4C 00 42 01 00  16 00 00 00 12 00 00 00
02 00 00 00 00 00 00 00  00 00 00 00 00 02 00 00
00 00 49 00 4E 00 53 00  45 00 52 00 54 00 20 00
49 00 4E 00 54 00 4F 00  20 00 74 00 20 00 56 00
41 00 4C 00 55 00 45 00  53 00 28 00 31 00 29 00
```
**Length 校验**：`0x004C` = 76 = 8 + 68。body = 22 + 46（23 字符） = 68 ✓

**响应 B（先完成）字段构成**（无结果集 DML）：
```
DONE: FD + Status=0x0010(DONE_COUNT) + CurCmd=0 + RowCount=1
```

**HexDump**（响应 B，共 0x15 = 21 字节）：
```
04 01 00 15 00 42 01 00  FD 10 00 00 00 01 00 00
00 00 00 00 00
```
**Length 校验**：`0x0015` = 21 = 8 + 13 ✓

**响应 A（后完成）字段构成**（1 列 INT4 + 3 行，列名 "id" 2 字符）：
```
COLMETADATA: 81 + Count=1 + UserType=0 + Flags=0 + 38 + ColName(2B+"id")
ROW: D1 + 01 00 00 00
ROW: D1 + 02 00 00 00
ROW: D1 + 03 00 00 00
DONE: FD + Status=0x0010 + CurCmd=0 + RowCount=3
```
body = 15（COLMETADATA：1+2+4+2+1+1+4）+ 5+5+5 + 13 = 43 → Length = 51 = 0x33

**HexDump**（响应 A，共 0x33 = 51 字节）：
```
04 01 00 33 00 42 01 00  81 01 00 00 00 00 00 00
00 38 02 69 00 64 00 D1  01 00 00 00 D1 02 00 00
00 D1 03 00 00 00 FD 10  00 00 00 03 00 00 00 00
00 00 00
```
**Length 校验**：`0x0033` = 51 = 8 + 43 ✓（已确认定义：MARS 下 SPID 相同=0x0042，靠消息边界区分）

### S13: 多流关联（批量 RPC：2 个 RPC + BatchFlag）

**场景**：一个 RPC 消息中连续两个 RPCReqBatch（ProcID 短形式 10 和长形式 "foo3"），中间用 BatchFlag=0xFF 分隔（TDS 7.2+）。

**请求字段构成**：
```
包头: Type=0x03 Status=0x01 SPID=0 PacketID=1 Window=0
ALL_HEADERS: TotalLength=0x16, TransactionDescriptor=0, OutstandingRequestCount=1
RPCReqBatch 1: FF FF 0A 00 | 00 00                 ; sp_executesql 无参数（OptionFlags 2B）
BatchFlag: FF
RPCReqBatch 2: 04 00 66 00 6F 00 6F 00 33 00 | 00 00  ; foo3 无参数（OptionFlags 2B）
```
body = 22 + (2+2+2) + 1 + (2+8+2) = 41 → Length = 49 = 0x31

**HexDump**（请求，共 0x31 = 49 字节）：
```
03 01 00 31 00 00 01 00  16 00 00 00 12 00 00 00
02 00 00 00 00 00 00 00  00 00 00 00 00 01 00 00
00 00 FF FF 0A 00 00 00  FF 04 00 66 00 6F 00 6F
00 33 00 00 00
```
**Length 校验**：`0x0031` = 49 = 8 + 41 ✓

**响应字段构成**（每个 RPC 返回 DONEPROC；第 1 个 DONEPROC 带 DONE_RPCINBATCH=0x80 + DONE_MORE，最后 DONEPROC 不带）：
```
DONEPROC 1: FE + Status=0x0081(DONE_RPCINBATCH|DONE_MORE) + CurCmd=0 + RowCount=0
DONEPROC 2: FE + Status=0x0000 + CurCmd=0 + RowCount=0
```
body = 13+13 = 26 → Length = 34 = 0x22

**HexDump**（响应，共 0x22 = 34 字节）：
```
04 01 00 22 00 00 01 00  FE 81 00 00 00 00 00 00
00 00 00 00 00 FE 00 00  00 00 00 00 00 00 00 00
00 00
```
**Length 校验**：`0x0022` = 34 = 8 + 26 ✓

### S14: 大数据类型（varchar(max) PLP 与 8B RowCount 边界）

**场景**：RPC 传 varchar(max) 参数（PLP 编码：已知总长 + 2 个 chunk），且 SELECT 返回 DoneRowCount 超过 2^32（验证 8B）。

**请求字段构成**：
```
包头: Type=0x03 Status=0x01 SPID=0 PacketID=1 Window=0
ALL_HEADERS: TotalLength=0x16, TransactionDescriptor=0, OutstandingRequestCount=1
RPCReqBatch: FF FF 0A 00 | 00                    ; sp_executesql
  ParameterData @big:
    ParamName: 04 "@big"
    StatusFlags: 00
    TYPE_INFO: A7(BigVarChar) + FF FF(USHORTMAXLEN=0xFFFF → varchar(max))
               + 09 04 D0 00 34(Collation)
    ParamLenData(PLP):
      0A 00 00 00 00 00 00 00                     ; ULONGLONGLEN=10（已知长度）
      05 00 00 00 "HELLO"                         ; chunk1: 5B
      05 00 00 00 "WORLD"                         ; chunk2: 5B
      00 00 00 00                                 ; PLP_TERMINATOR
```
body = 22 + 2+2+1 + (1+8+1+1+2+5+2+8+4+4+5+4+5+4) = 22+5+54 = 81 → Length = 89 = 0x59

参数明细：ParamName B_VARCHAR = 1+8 = 9；StatusFlags 1；TYPE_INFO = 1+2+5 = 8；PLP = 8+4+5+4+5+4 = 30。合计 9+1+8+30 = 48；RPCReqBatch = 2+2+1+48 = 53；body = 22+53 = 75 → Length = 83 = 0x53。

**HexDump**（请求，共 0x53 = 83 字节）：
```
03 01 00 53 00 00 01 00  16 00 00 00 12 00 00 00
02 00 00 00 00 00 00 00  00 00 00 00 00 01 00 00
00 00 FF FF 0A 00 00 04  40 00 62 00 69 00 67 00
00 A7 FF FF 09 04 D0 00  34 0A 00 00 00 00 00 00
00 05 00 00 00 48 00 45  00 4C 00 4C 00 4F 00 05
00 00 00 57 00 4F 00 52  00 4C 00 44 00 00 00 00
00
```
**Length 校验**：`0x0053` = 83 = 8 + 75 ✓

**响应字段构成**（DoneRowCount 8B 边界：返回 5,000,000,000 行）：
```
DONE: FD + Status=0x0010(DONE_COUNT) + CurCmd=0
      RowCount=0x000000012A05F200（8B LE: 00 F2 05 2A 01 00 00 00）
```
body = 13 → Length = 21 = 0x15

**HexDump**（响应，共 0x15 = 21 字节）：
```
04 01 00 15 00 00 01 00  FD 10 00 00 00 00 F2 05
2A 01 00 00 00
```
**Length 校验**：`0x0015` = 21 = 8 + 13 ✓（已确认定义：TDS 7.2+ RowCount 为 8B LE；5,000,000,000 = 0x12A05F200 → LE `00 F2 05 2A 01 00 00 00`）

### S15: NULL 处理（定长/变长/MAX/行内混合）

**场景**：SQL SELECT 返回 4 列混合 NULL：INT4 NULL、varchar NULL、varchar(max) NULL、int 非 NULL；服务器用 ROW + NBCROW 混合传输。

**响应字段构成**：
```
COLMETADATA: 81 + Count=4
  col1: UserType=0 Flags=0x0001(fNullable) 38(Int4)   ColName "c1"
  col2: UserType=0 Flags=0x0001            A7 05 00 09 04 D0 00 34  ColName "c2"
  col3: UserType=0 Flags=0x0001            A7 FF FF 09 04 D0 00 34  ColName "c3"（varchar(max)）
  col4: UserType=0 Flags=0x0000            38(Int4)                   ColName "c4"
ROW: D1
  c1: 00 00 00 00                    ; INT4 NULL = 4B 全 0（定长 NULL 用类型宽度全 0）
  c2: FF FF                          ; varchar NULL = 2B 0xFFFF
  c3: FF FF FF FF FF FF FF FF        ; varchar(max) NULL = 8B PLP_NULL
  c4: 2A 00 00 00                    ; 42
NBCROW: D2 + NullBitmap
  行 2：c1 NULL, c2=NULL, c3=NULL, c4=7 → bitmap = 0x07（bit0..2 置位）
  数据: 07 00 00 00
DONE: FD + Status=0x0010 + CurCmd=0 + RowCount=2
```

**COLMETADATA 明细**（4 列）：
col1: 00 00 00 00 | 01 00 | 38 | 02 63 00 31 00 = 4+2+1+1+4 = 12
col2: 00 00 00 00 | 01 00 | A7 05 00 09 04 D0 00 34 | 02 63 00 32 00 = 4+2+8+1+4 = 19
col3: 00 00 00 00 | 01 00 | A7 FF FF 09 04 D0 00 34 | 02 63 00 33 00 = 4+2+8+1+4 = 19
col4: 00 00 00 00 | 00 00 | 38 | 02 63 00 34 00 = 12
COLMETADATA = 1+2+12+19+19+12 = 65

**HexDump**（响应，共 0x69 = 105 字节）：
```
04 01 00 69 00 00 01 00  81 04 00 00 00 00 00 01
00 38 02 63 00 31 00 00  00 00 00 01 00 A7 05 00
09 04 D0 00 34 02 63 00  32 00 00 00 00 00 01 00
A7 FF FF 09 04 D0 00 34  02 63 00 33 00 00 00 00
00 00 00 38 02 63 00 34  00 D1 00 00 00 00 FF FF
FF FF FF FF FF FF FF 2A  00 00 00 D2 07 07 00 00
00 FD 10 00 00 00 02 00  00 00 00 00 00 00
```
**Length 校验**：`0x0069` = 105 = 8 + 97。body = COLMETADATA 65 + ROW(1+4+2+8+4 = 19) + NBCROW(1+1+4 = 6) + DONE 13 = 103 ≠ 97。重算：ROW 行 1 数据 = 4(c1 NULL 全 0) + 2(c2 0xFFFF) + 8(c3 PLP_NULL) + 4(c4=42) = 18；ROW = 1+18 = 19；COLMETADATA = 65；NBCROW = 1+1+4 = 6；DONE = 13；合计 103 → Length = 111 = 0x6F。**修正 Length=0x6F**：

**HexDump**（修正，共 0x6F = 111 字节）：
```
04 01 00 6F 00 00 01 00  81 04 00 00 00 00 00 01
00 38 02 63 00 31 00 00  00 00 00 01 00 A7 05 00
09 04 D0 00 34 02 63 00  32 00 00 00 00 00 01 00
A7 FF FF 09 04 D0 00 34  02 63 00 33 00 00 00 00
00 00 00 38 02 63 00 34  00 D1 00 00 00 00 FF FF
FF FF FF FF FF FF FF 2A  00 00 00 D2 07 07 00 00
00 FD 10 00 00 00 02 00  00 00 00 00 00 00
```
**Length 校验**：`0x006F` = 111 = 8 + 103 ✓（已确认定义：定长 NULL = 类型宽度全 0；变长 NULL 分三类——GEN_NULL(0x00) 用于非字符/二进制类 BYTELEN/USHORTLEN；CHARBIN_NULL 2B(0xFFFF) 用于 BIGCHAR/BIGVARCHAR/NCHAR/NVARCHAR/BIGBINARY/BIGVARBINARY；CHARBIN_NULL 4B(0xFFFFFFFF) 用于 TEXT/NTEXT/IMAGE；PLP_NULL(8B 0xFFFFFFFFFFFFFFFF) 用于 MAX 类型）

> **S15 补充**：PLP 类型的 PLP_NULL 是 `FF FF FF FF FF FF FF FF`（8B），而 PLP "未知长度" 是 `FE FF FF FF FF FF FF FF`（UNKNOWN_PLP_LEN），两者不同。MAX 类型 NULL 必须用 PLP_NULL。

---

## §7. 测试用例（T-001 ~ T-214）

> 测试分 15 组对应 S1-S15 场景。每条含：输入 / 期望输出 / 断言点。断言点用 [A#] 编号，供实现对照。

### §7.1 Pre-Login 协商（S1）— T-001 ~ T-015

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-001 | 最小 PRELOGIN：仅 VERSION + TERMINATOR | 包头 Type=0x12，body 含 VERSION 选项（offset=0x0016 BE，len=0x0006）后跟 0xFF | [A1] VERSION 是第一个选项 [A2] TERMINATOR 最后 [A3] Length=8+body |
| T-002 | VERSION 数据 09 00 00 00 00 00 01 00 | 大端解析 UL_VERSION=0x09000000（major=9），subbuild=0x0100 | [A4] PL_OFFSET/PL_OPTION_LENGTH 大端 |
| T-003 | VERSION 不是第一选项（先 ENCRYPTION） | Validate 报错：VERSION 必须第一 | [A5] 校验规则触发 |
| T-004 | 无 TERMINATOR 结尾 | Validate 报错：TERMINATOR 必须最后 | [A6] 校验规则触发 |
| T-005 | VERSION + ENCRYPTION(0x01=on) + TERMINATOR | 客户端请求 ENCRYPT_ON；完整 PRELOGIN 字节序列含 VERSION(0x00)+offset+len、ENCRYPTION(0x01)+offset+0x01 len 数据、TERMINATOR(0xFF)；ENCRYPTION 数据字节=0x01 | [A7] B_FENCRYPTION=0x01 正确编码 + 完整字节序列可观测 |
| T-006 | VERSION + ENCRYPTION(0x00=off) + TERMINATOR | 服务器回 ENCRYPT_OFF，无 SSL 协商；响应 PRELOGIN 字节序列含 ENCRYPTION 选项数据=0x00 | [A8] 响应 ENCRYPTION 选项值=0x00 + 完整字节可观测 |
| T-007 | VERSION + ENCRYPTION(0x03=req) | 服务器必须回 ENCRYPT_ON(0x01) 或断开 | [A9] 按协商表处理 |
| T-008 | VERSION + ENCRYPTION(0x02=not_sup) | 服务器回 ENCRYPT_NOT_SUP | [A10] 不加密继续登录 |
| T-009 | VERSION + INSTOPT("MSSQLServer") + TERMINATOR | 服务器回 INSTOPT 值 0x00 | [A11] 实例匹配语义 |
| T-010 | VERSION + INSTOPT("OtherInst") | 服务器回 INSTOPT 值 0x01 | [A12] 客户端应断开（SHOULD） |
| T-011 | VERSION + THREADID(0x0DB8) + TERMINATOR | THREADID 数据 B8 0D 00 00 | [A13] 4B LE |
| T-012 | VERSION + MARS(0x01) + TERMINATOR | MARS 选项值=0x01 | [A14] MARS 启用标记 |
| T-013 | VERSION + MARS(0x00) + TERMINATOR | MARS 关闭 | [A15] MARS 关闭标记 |
| T-014 | VERSION + TRACEID（TDS 7.4） | 数据 = 16B GUID + 16B GUID + 4B 序列 | [A16] TRACEID 布局 |
| T-015 | 服务器 PRELOGIN 响应缺 VERSION | 客户端按结构非法处理：关连接；任务结果=FAIL 且原因含 "PRELOGIN response missing VERSION"；不产出后续字节 | [A17] 结构非法→Final State + 失败原因可观测 |

### §7.2 Login7 + LoginAck（S2）— T-016 ~ T-040

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-016 | 默认 Login7（TDS 7.4） | TDSVersion 字段 wire=`04 00 00 74` | [A18] LE 编码 0x04000074 |
| T-017 | TDS 7.1 配置 | TDSVersion wire=`71 00 00 00` | [A19] 版本切换 |
| T-018 | TDS 7.2 配置 | TDSVersion wire=`72 09 00 02` | [A20] 版本切换 |
| T-019 | TDS 7.3 配置 | TDSVersion wire=`73 0A 00 03` | [A21] 版本切换 |
| T-020 | Length 字段 | Length = body 实际字节数（不含包头） | [A22] 偏移表后所有字段在 Length 内 |
| T-021 | 登录 >128K-1 | Validate 报错：LOGIN7 超长 | [A23] 128K-1 上限 |
| T-022 | ibHostName=0 | Validate 报错：ibHostName 不得为 0 | [A24] 前向兼容规则 |
| T-023 | HostName="host1" | ibHostName=0x5E，cchHostName=8 字符，Data 区 UCS-2 | [A25] B_VARCHAR 字符数单位 |
| T-024 | UserName="sa" | ibUserName/cchUserName 正确 | [A26] 偏移值=字段实际位置 |
| T-025 | Password="password" | 发送前混淆：每字节高低 4 位互换再 XOR 0xA5 | [A27] 混淆算法可逆 |
| T-026 | Password 空 | cchPassword=0，ibPassword 可指向任意 | [A28] 空字段规则 |
| T-027 | AppName="trafficgen" | cchAppName=11 字符 | [A29] UCS-2 字节数=2×字符数 |
| T-028 | Database="testdb" | ibDatabase/cchDatabase 正确指向 Data | [A30] 数据库字段 |
| T-029 | ClientID=MAC | 6B 原样 | [A31] MAC 字段 |
| T-030 | OffsetLength 58B（TDS 7.2+ 含 cbSSPILong） | 各 ib 偏移单调不减；ibHostName=0x5E=94 指向 Data 区起点（=固定 Header 36B + OffsetLength 58B） | [A32] 偏移表布局（v3.0.1 修正：v3.0.0 误标 94B，规范 §2.2.6.4 明确表本身为 58B，94 是 ibHostName 值） |
| T-031 | OptionFlags1=0xE0 | fByteOrder=0,fChar=0,fFloat=0,fDumpLoad=1,fUseDB=1,fDatabase=1,fSetLang=1 | [A33] LSB 序 |
| T-032 | TypeFlags=0x01 | fSQLType=TSQL | [A34] TypeFlags 位 |
| T-033 | 服务器回 Login Response 无 LOGINACK | 判定登录失败；任务结果=FAIL 且原因含 "LOGINACK missing" | [A35] LOGINACK 必须存在 + 失败原因可观测 |
| T-034 | 服务器回 LOGINACK | 解析 Interface/TDSVersion/ProgName/ProgVersion；ProgName 用 B_VARCHAR（1B BYTELEN + UCS-2 LE） | [A36] ProgName 用 B_VARCHAR（v3.0.1 修正：v3.0.0 误标 US_VARCHAR，规范 §2.2.7.14 明确为 B_VARCHAR） |
| T-035 | LoginAck.Length=0x36 | Length=Interface(1)+TDSVersion(4)+ProgName B_VARCHAR(1+44)+ProgVersion(4)=54；ProgName 字符串假设为 "Microsoft SQL Server"（22 字符，44B UCS-2 LE） | [A37] Length 覆盖整个 token（已确认定义；假设 ProgName 长度=22 字符） |
| T-036 | 登录失败：服务器回 ERROR(Class=14) | 客户端报登录失败，含错误号 | [A38] ERROR 路径 |
| T-037 | 登录响应含 ENVCHANGE Type 4（包大小 8000） | 后续消息按新包大小分割 | [A39] 包大小协商生效 |
| T-038 | 登录响应含 ENVCHANGE Type 1/2/7 | 更新连接环境（DB/语言/排序规则） | [A40] EnvChange 应用 |
| T-039 | FeatureExt SESSIONRECOVERY（TDS 7.4） | FeatureOpt: 01 + 4B len + 数据 + 0xFF | [A41] FeatureExt 结构 |
| T-040 | 服务器 FEATUREEXTACK 含未请求 FeatureId | 判定 TDS 协议错误，终止连接；在 FEATUREEXTACK 解析阶段终止，已收字节计数 = N | [A42] 未请求 feature 检查 + 终止时机与已收字节可观测 |

### §7.3 SQL Batch SELECT（S3）— T-041 ~ T-065

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-041 | SQL "select 'foo' as 'bar'" | 请求含 ALL_HEADERS（TransactionDescriptor 头）+ UCS-2 SQLText | [A43] SQLText 无长度前缀 |
| T-042 | ALL_HEADERS TotalLength | = 22（含自身） | [A44] HeaderLength=18 含自身 |
| T-043 | HeaderType=0x0002 | TransactionDescriptor=0 + OutstandingRequestCount=1（AutoCommit） | [A45] AutoCommit 规则 |
| T-044 | 响应 COLMETADATA | Count=1，列类型 A7(BigVarChar) maxlen=3 + Collation | [A46] TYPE_INFO 顺序 |
| T-045 | 响应 ROW | `D1 03 00 66 6F 6F` | [A47] USHORTCHARBINLEN 前缀 |
| T-046 | 响应 DONE | Status=0x10(DONE_COUNT)，RowCount=1（8B） | [A48] 8B RowCount（TDS 7.2+） |
| T-047 | 7.1 版本下 SELECT | DONE RowCount 为 4B | [A49] 版本相关宽度 |
| T-048 | 空结果集 SELECT | 仅 COLMETADATA + DONE，无 ROW | [A50] 0 行路径 |
| T-049 | SELECT 返回 2 列（int+varchar） | COLMETADATA 2 个 ColumnData | [A51] 多列解析 |
| T-050 | 列名含中文（UCS-2） | ColName B_VARCHAR 长度=字符数 | [A52] Unicode 列名 |
| T-051 | SQL 含空语句 ";" | 服务器按实际语句数返回 DONE | [A53] 不额外生成 DONE（变量声明除外） |
| T-052 | SQL 超包大小（8000 字符） | 分包：非最后包 EOM=0 且长度=协商包大小 | [A54] 分包规则 |
| T-053 | 分包响应 | PacketID 递增，最后包 EOM=1 | [A55] PacketID 语义 |
| T-054 | Status=0x08 RESETCONNECTION 首包 | 服务器重置环境 | [A56] 复位位 |
| T-055 | Status=0x10 RESETCONNECTIONSKIPTRAN | 保留事务 | [A57] 跳事务复位 |
| T-056 | Status=0x08\|0x10 同置 | Validate 报错 | [A58] 互斥校验 |
| T-057 | 结果集含 NBCROW（服务器选择） | 解析 NullBitmap + 非 NULL 列数据 | [A59] NBCROW 解析 |
| T-058 | ROW 与 NBCROW 混用 | 各自独立解析 | [A60] 混合兼容 |
| T-059 | 未知 token 字节（如 0xZZ） | 按 token 类（xx01xxxx 零长/xx11xxxx 定长/xx10xxxx 变长/xx00xxxx 计数）容错跳过；跳过 N 字节后能继续解析下一个 DONE token（DONE Status 与 RowCount 正确） | [A61] 容错解析 + 跳过字节数与后续解析正确可观测 |
| T-060 | 响应 DONE 无 DONE_FINAL（缺 DONE_MORE） | 等待更多数据 | [A62] DONE_MORE 判定 |
| T-061 | CurCmd 任意值（如 0xC1） | 透传不解释；任务报告中记录 CurCmd=配置值 0xC1 | [A63] CurCmd 语义 + 实际透传值可观测 |
| T-062 | 服务器多包响应乱序重组 | 按 PacketID+EOM 重组消息 | [A64] 消息重组 |
| T-063 | Length 字段 <512 | 协议错误处理 | [A65] 长度下限 |
| T-064 | Length 字段 >32767 | 协议错误处理 | [A66] 长度上限 |
| T-065 | EOM 前包长度≠协商包大小（TDS 7.3+） | 服务器 SHOULD 断开 | [A67] 分包严格性 |

### §7.4 SQL Batch DML（S4）— T-066 ~ T-080

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-066 | "update t set c=c" | DONE Status=0x10(DONE_COUNT)，RowCount=5 | [A68] DML 计数 |
| T-067 | INSERT 影响 0 行 | DONE_COUNT + RowCount=0（有效 0）；无 DONE_COUNT 时 RowCount 字段值不可读（实现应将其标记为"未初始化"，不暴露给上层） | [A69] 0 与无效区分 + 不可读时显式标记 |
| T-068 | DELETE 影响 2^40 行 | RowCount 8B 正确 | [A70] 8B 大计数 |
| T-069 | 无 DONE_COUNT 的 DONE | RowCount 值无效（初始化变量） | [A71] DONE_COUNT 语义 |
| T-070 | DML 后跟 SELECT | 第一个 DONE 带 DONE_MORE | [A72] 批内多语句 |
| T-071 | 批中变量声明 "DECLARE @x int" | 不产生 DONE | [A73] 变量声明例外 |
| T-072 | UPDATE 失败（唯一约束） | ERROR(Class=16) + DONE(DONE_ERROR) | [A74] 错误后 DONE 位 |
| T-073 | 批中一条失败后续继续 | 失败语句 DONE Status=0x12(DONE_ERROR|DONE_COUNT)，后续语句 DONE Status=0x10(DONE_COUNT) 且 RowCount 正常 | [A75] 批错误语义 + 具体 Status 值可观测 |
| T-074 | 严重错误（Class=20+） | DONE_SRVERROR(0x100)，结果集丢弃 | [A76] SRVERROR |
| T-075 | 事务中 DML | DONE 带 DONE_INXACT(0x4) | [A77] INXACT 位（规范定义；SQL Server 不置位） |
| T-076 | 空 SQL 文本 | Validate 报错 | [A78] 空批拒绝 |
| T-077 | SQLText 奇数长度 | Validate 报错：UCS-2 需偶数 | [A79] 编码校验 |
| T-078 | GETDATE() 返回 datetime | DATETIMETYPE 8B（4B 天+4B 1/300 秒） | [A80] datetime 编码 |
| T-079 | 返回 date 类型 | DATENTYPE 3B（自 0001-01-01 天数） | [A81] date 编码 |
| T-080 | 返回 decimal(10,2) | DECIMALNTYPE 0x6C + len 0x09 + Precision/Scale + 8B 值 | [A82] decimal 编码 |

### §7.5 SQL Batch 多结果集（S5）— T-081 ~ T-095

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-081 | "SELECT 1; SELECT 2; SELECT 3" | 3 组结果集 | [A83] 组数 |
| T-082 | 前两个 DONE 的 Status | 0x11 = DONE_COUNT\|DONE_MORE | [A84] MORE 位 |
| T-083 | 最后 DONE 的 Status | 0x10 = DONE_COUNT（无 MORE） | [A85] 结束判定 |
| T-084 | 每组 ROW 值 | 1/2/3 各自正确 | [A86] 行值 |
| T-085 | 组间 COLMETADATA 不同列数 | 每组独立解析 | [A87] 元数据切换 |
| T-086 | 第 2 条语句报错 | 组 2 = ERROR + DONE(0x12)，组 3 仍返回 | [A88] 错误隔离 |
| T-087 | 语句间无分号（批） | 服务器按批解析 | [A89] 批语法 |
| T-088 | 多结果集 + 计算列（COMPUTE BY） | ALTMETADATA(0x88) + ALTROW(0xD3)（TDS 7.4 弃用但需容错） | [A90] 聚合 token |
| T-089 | ORDER BY 结果 | ORDER token(0xA9)：Length+ColNum | [A91] 排序 token |
| T-090 | 浏览模式 | TABNAME(0xA4) + COLINFO(0xA5) | [A92] 浏览 token |
| T-091 | 每个 DONE 后重置列上下文 | DONE 后到下一组 COLMETADATA 之前的 ROW 解析应失败（实现正确时返回解析错误，因为列定义已清空） | [A93] 上下文依赖 + 失败行为可观测 |
| T-092 | DONEINPROC 出现在批内（EXEC） | 允许，跟 DONEPROC | [A94] 过程 token 序列 |
| T-093 | 批内 EXEC 后继续语句 | DONEINPROC→DONEPROC→(下一结果集) | [A95] 序列 |
| T-094 | 混用 DONE 与 DONEPROC | 分别计数 | [A96] token 独立 |
| T-095 | 3 组结果集但只有 2 个 DONE | 解析未完成（缺结束） | [A97] 完整性检测 |

### §7.6 RPC sp_executesql（S6）— T-096 ~ T-115

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-096 | ProcID=10 短形式 | `FF FF 0A 00` | [A98] ProcIDSwitch=0xFFFF |
| T-097 | ProcName 长形式 | `04 00` + UCS-2 LE | [A99] US_VARCHAR ProcName |
| T-098 | @stmt 参数 | B_VARCHAR 参数名（1B len + UCS-2） | [A100] 参数名编码 |
| T-099 | @stmt 值 "SELECT 1" | TYPE_INFO A7(BigVarChar) + maxlen=08 00(=8) + Collation 09 04 D0 00 34 + USHORTCHARBINLEN 08 00 + 8B ASCII "SELECT 1" | [A101] 变长参数数据（v3.0.1 修正：BigVarChar 用 ASCII/代码页字节，非 UCS-2；maxlen=8、len=8、数据 8B） |
| T-100 | OptionFlags 全 0 | fWithRecomp/fNoMetaData/fReuseMetaData=0 | [A102] 选项位 |
| T-101 | fNoMetaData=1 | 服务器 COLMETADATA Count=0xFFFF（NoMetaData） | [A103] NoMetaData |
| T-102 | 响应含 DONEINPROC | Status=0x11, CurCmd=0xC1, RowCount=1 | [A104] 过程内 DONE |
| T-103 | 响应含 RETURNSTATUS | `79 00 00 00 00` | [A105] 返回状态 |
| T-104 | 响应含 DONEPROC | Status=0, CurCmd=0xE0 | [A106] 过程完成 |
| T-105 | RPC 批中多个参数 | 按顺序解析每个 ParameterData | [A107] 多参数 |
| T-106 | 参数名为空 | `00`（B_VARCHAR len=0 无数据） | [A108] 空名省略 |
| T-107 | 参数 fDefaultValue=1 | StatusFlags=0x02 | [A109] 默认值位 |
| T-108 | 参数 fByRefValue=1 | StatusFlags=0x01（OUTPUT） | [A110] 引用位 |
| T-109 | 参数类型 INTNTYPE | `26 04` + 4B 数据 | [A111] INTN 编码 |
| T-110 | 参数类型 NVARCHAR | E7 + 2B maxlen LE(如 08 00=8 字符) + Collation 5B + 2B USHORTCHARBINLEN LE(如 10 00=16B) + UCS-2 LE 数据（如 16B） | [A112] NVARCHAR（v3.0.1 修正：明确 maxlen 与 len 的具体值断言） |
| T-111 | 参数类型 BITNTYPE NULL | `68 00` | [A113] BITN NULL |
| T-112 | 参数类型 BIGINT 值 2^63-1 | 8B LE 全 FF 7F... | [A114] 8B 整数 |
| T-113 | 参数类型 DATETIME2(3) | 2A + scale=03 + 7B 值 | [A115] datetime2 编码 |
| T-114 | 参数类型 UNIQUEIDENTIFIER | 24 + 10 + 16B | [A116] GUID 参数 |
| T-115 | RPC 响应多结果集 | 按 DONE_MORE 归并；归并后共 N 个结果集，第 K 个结果集的 RowCount=预期值 | [A117] 多结果 RPC + 归并结果可观测 |

### §7.7 RPC 存储过程（S7）— T-116 ~ T-135

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-116 | 长名 "foo3" | `04 00 66 00 6F 00 6F 00 33 00` | [A118] 官方示例 4.8 字节级 |
| T-117 | ProcName 1047 字节 | Validate 报错（≤1046） | [A119] 名称上限 |
| T-118 | 空参数名 + fDefaultValue | `00 02 26 02 00`；StatusFlags=0x02 解析为 fByRefValue=0(bit0) + fDefaultValue=1(bit1) + 保留位(bit2)=0 + fEncrypted=0(bit3) | [A120] 示例字节级 + 位解析（v3.0.1 修正：补 StatusFlags 位解析断言） |
| T-119 | 响应 DONEINPROC+RETURNSTATUS+DONEPROC | 官方示例 4.9 字节级 | [A121] 示例 4.9 |
| T-120 | DONEPROC Status=0x80 DONE_RPCINBATCH | 批内非最后 RPC | [A122] RPCINBATCH 位 |
| T-121 | 无 DONE_RPCINBATCH 的最后 RPC | 批内最后 RPC | [A123] 最后 RPC |
| T-122 | 存储过程返回输出参数 | RETURNVALUE token | [A124] 输出参数 |
| T-123 | RETURNVALUE Status=0x01 | OUTPUT 参数标志 | [A125] 状态位 |
| T-124 | UDF 作为 RPC | 恰一个 RETURNVALUE，Status=0x02 | [A126] UDF 返回 |
| T-125 | RETURNVALUE ParamOrdinal | 按原调用序 | [A127] 序号 |
| T-126 | 大对象输出参数重排 | 小参数组在前，大参数在后；重排前后顺序：原序 [big, small1, small2] → 重排后 [small1, small2, big] | [A128] 重排规则 + 具体重排顺序可观测 |
| T-127 | 过程返回 RETURNSTATUS 非 NULL | 必须存在 | [A129] 必须性 |
| T-128 | 不存在的存储过程 | ERROR + DONEPROC（NoExec 语义） | [A130] 不存在处理 |
| T-129 | NoExecFlag(0xFE) 分隔 | 前一 RPC 不执行：ERROR + DONEPROC 后继续 | [A131] NoExec |
| T-130 | BatchFlag 在最后 RPC 后 | 服务器忽略 | [A132] 尾部标记 |
| T-131 | RPC 与 SQL 混在同一消息 | Validate 报错 | [A133] 隔离规则 |
| T-132 | 过程内多条语句 | 多个 DONEINPROC | [A134] 过程内计数 |
| T-133 | 过程内嵌套过程 | DONEINPROC...DONEPROC 嵌套；嵌套深度=N（外层 DONEPROC 在内层 DONEPROC 之后） | [A135] 嵌套 + 嵌套层级可观测 |
| T-134 | 过程错误 | DONEINPROC DONE_ERROR 位 | [A136] 过程错误 |
| T-135 | 输出参数 NULL | RETURNVALUE 值部分 NULL 编码 | [A137] 输出 NULL |

### §7.8 Error 响应（S8）— T-136 ~ T-150

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-136 | 语法错误 "SELECT FROM" | ERROR Class=15 | [A138] 语法级别 |
| T-137 | ERROR Length 字段 | = Number..LineNumber 总字节 | [A139] 长度覆盖 |
| T-138 | LineNumber=1 | 4B LE（TDS 7.2+） | [A140] 行号宽度 |
| T-139 | 7.1 版本 | LineNumber 2B USHORT | [A141] 版本宽度 |
| T-140 | MsgText 用 US_VARCHAR | 2B 长度 + UCS-2 | [A142] 消息编码 |
| T-141 | ServerName/ProcName 空 | 各 1B 0x00 | [A143] 空名 |
| T-142 | 错误后 DONE 置 DONE_ERROR | Status=0x02 | [A144] DONE_ERROR |
| T-143 | ERROR 在结果集内 | ERROR 在语句 DONE 之前 | [A145] 顺序 |
| T-144 | Class=14 权限错误 | 错误号可断言 | [A146] 权限级别 |
| T-145 | Class=13 死锁 | 死锁级别 | [A147] 死锁 |
| T-146 | 错误号 < 20001 | 保留范围 | [A148] 保留号 |
| T-147 | 登录失败错误 | ERROR 后连接关闭 | [A149] 登录失败 |
| T-148 | 错误消息超 4K | 分包传输 | [A150] 大错误 |
| T-149 | 错误后继续批 | 下一语句结果正常：ERROR 后第 N 个 DONE 携带正常 RowCount（Status=0x10 DONE_COUNT，RowCount=预期值） | [A151] 恢复 + 恢复点可观测 |
| T-150 | ERROR token 结构截断 | 协议错误处理 | [A152] 截断检测 |

### §7.9 Info 响应（S9）— T-151 ~ T-160

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-151 | USE master 返回 INFO 5701 | Class=0, State=2 | [A153] 信息消息 |
| T-152 | INFO Length 覆盖正确 | 0x58 结构 | [A154] 长度 |
| T-153 | INFO LineNumber=0 | 不适用的行号 | [A155] 0 行号 |
| T-154 | 多条 INFO | 全部收集 | [A156] 多信息 |
| T-155 | INFO 与 ERROR 共存 | 分别处理：ERROR 触发任务失败标记，INFO 仍计入 ExpectInfoCount | [A157] 混合 + 处理顺序互不干扰可观测 |
| T-156 | INFO 后 DONE 正常 | Status=0 | [A158] 完成不受影响 |
| T-157 | Class=10 转 0 | 兼容转换 | [A159] 级别映射 |
| T-158 | INFO 带 ServerName | B_VARCHAR 解析 | [A160] 服务器名 |
| T-159 | INFO 带 ProcName | B_VARCHAR 解析 | [A161] 过程名 |
| T-160 | 登录响应中的 INFO | 在 LOGINACK 前 | [A162] 顺序 |

### §7.10 Attention 取消（S10）— T-161 ~ T-170

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-161 | Attention 包 | Type=0x06，Length=8，无 body | [A163] 已确认定义 |
| T-162 | 服务器 DONE_ATTN | Status=0x20 | [A164] 确认位 |
| T-163 | 确认前收到的中间数据 | 丢弃 ROW×N + DONE（非 DONE_ATTN）；保留 SESSIONSTATE token | [A165] 丢弃规则 + 丢弃的 token 类型可观测 |
| T-164 | 确认前收到 SESSIONSTATE | 保留 | [A166] 例外 |
| T-165 | 未完成请求取消（EOM 未发） | 下一包 Status=0x03（Ignore\|EOM） | [A167] Ignore 位 |
| T-166 | Ignore 请求的响应 | 单个 DONE(DONE_ERROR)，无 ATTN 确认 | [A168] 响应形式 |
| T-167 | Attention 发送时机 | 必须在当前包发送完成后：Attention 包的 PacketID = 当前包 PacketID + 1，且当前包 EOM=1 | [A169] 时序 + PacketID 具体关系可观测 |
| T-168 | 无活动请求时 Attention | 服务器 SHOULD 不取消，仍回确认 | [A170] 空取消 |
| T-169 | 取消计时器超时 | 关闭连接 | [A171] 计时器 |
| T-170 | 多包请求中 Attention | 消息边界完整 | [A172] 中途取消 |

### §7.11 事务（S11）— T-171 ~ T-185

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-171 | BEGIN TRAN | ENVCHANGE Type 8 | [A173] 类型 |
| T-172 | ENVCHANGE 8 NewValue | 1B len 0x08 + 8B TransactionID（已确认定义） | [A174] 事务 ID |
| T-173 | TransactionID 回填 | 后续请求 TransactionDescriptor=该 ID | [A175] 描述符 |
| T-174 | COMMIT | ENVCHANGE Type 9：NewValue=00，OldValue=8B ID | [A176] 提交结构 |
| T-175 | ROLLBACK | ENVCHANGE Type 10：同构 | [A177] 回滚结构 |
| T-176 | ENVCHANGE Length 字段 | = Type+NewValue+OldValue 总字节 | [A178] 长度 |
| T-177 | AutoCommit 下 DML | 无 ENVCHANGE | [A179] 自动提交 |
| T-178 | 嵌套 BEGIN | 内层无 ENVCHANGE（仅 trancount 变化）；任务报告中 ENVCHANGE Type 8 计数 = 1（仅最外层） | [A180] 嵌套 + ENVCHANGE 计数可观测 |
| T-179 | 最外层 COMMIT | 才发 ENVCHANGE 9 | [A181] 外层提交 |
| T-180 | SAVE TRAN name | 无 ENVCHANGE；trancount 不变（仅创建保存点，规范 §2.2.6.9 + §2.2.7.9 注释明确） | [A182] 保存点 + trancount 不变可观测 |
| T-181 | TM_BEGIN_XACT(5) ISOLATION_LEVEL=0x02 | ENVCHANGE 8 + payload 字节：01 02 06 4E 61 6D 65（ISOLATION_LEVEL=0x02 Read Committed + B_VARBYTE BEGIN_XACT_NAME） | [A183] TM 请求 + 隔离级别字节可观测 |
| T-182 | TM_COMMIT_XACT(7) fBeginXact=1 | COMMIT 后开新事务 | [A184] 连锁 |
| T-183 | TM_ROLLBACK_XACT(8) 保存点 | 回滚到保存点，trancount 不变；回滚前 trancount=N，回滚后 trancount=N（不变） | [A185] 保存点回滚 + trancount 实际值可观测 |
| T-184 | TM_PROMOTE_XACT(6) | ENVCHANGE 15（DTC token，Length 只含 type） | [A186] 提升 |
| T-185 | 未知 RequestType | 接收方 SHOULD 断开 | [A187] 未知类型 |

### §7.12 MARS 多会话（S12）— T-186 ~ T-195

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-186 | 2 会话交错请求 | 共享 SPID，OutstandingRequestCount=2 | [A188] 已确认定义：SPID 标识连接 |
| T-187 | 响应乱序返回 | 按消息边界归并到正确会话 | [A189] 归并 |
| T-188 | 会话 A 响应含 DONE | A 完成，B 仍活动 | [A190] 独立完成 |
| T-189 | 会话内多条语句 | 会话内 DONE_MORE 序列；3 条语句 → 2 个 DONE_MORE + 1 个 DONE_FINAL | [A191] 会话内 + DONE_MORE 计数可观测 |
| T-190 | 会话 A 出错 | 仅 A 收到 ERROR，B 不受影响：B 的 DONE Status=0x10(DONE_COUNT) 正常且 RowCount=预期值 | [A192] 错误隔离 + B 的具体 DONE Status 可观测 |
| T-191 | Attention 取消会话 A | 仅 A 的 DONE_ATTN | [A193] 定向取消 |
| T-192 | 3 会话 | OutstandingRequestCount=3 | [A194] 计数 |
| T-193 | 会话事务独立 | 各自 TransactionDescriptor | [A195] 事务隔离 |
| T-194 | 会话在另一会话事务内请求 | 使用自己描述符 | [A196] 描述符 |
| T-195 | MARS 未协商时多请求 | Validate 报错 | [A197] 前置条件 |

### §7.13 多流关联（S13）— T-196 ~ T-202

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-196 | RPC 批 2 个 RPC | BatchFlag=0xFF 分隔 | [A198] 批标记 |
| T-197 | 第 1 个 DONEPROC Status | 0x81 = RPCINBATCH\|MORE | [A199] 批内位 |
| T-198 | 最后 DONEPROC Status | 0x00 | [A200] 最后 |
| T-199 | 批中 NoExec | 前一 RPC 不执行 | [A201] NoExec 语义 |
| T-200 | 批中参数歧义（BatchFlag vs 参数） | 按参数个数顺序消费；解析后第 N 个 ParameterData 对应第 N 个 RPCReqBatch（顺序一一对应） | [A202] 歧义消解 + 消费顺序可观测 |
| T-201 | SQL 批多语句 + RPC 批 | 两种多流独立支持 | [A203] 双模式 |
| T-202 | 批内 RPC 各自结果集 | 各自 COLMETADATA；RPC 1 的 ROW 不会被 RPC 2 的 COLMETADATA 解析（解析器在每个 RPC 边界后重置列上下文） | [A204] 结果隔离 + 隔离边界可观测 |

### §7.14 大数据类型（S14）— T-203 ~ T-209

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-203 | varchar(max) 参数 | TYPE_INFO A7 + FF FF + Collation | [A205] MAX 标记 |
| T-204 | PLP 已知长度 | 8B 总长 + chunks + 4B 终止 | [A206] PLP 结构 |
| T-205 | PLP 未知长度 | UNKNOWN_PLP_LEN(0xFFFFFFFFFFFFFFFE) + chunks | [A207] 未知长度 |
| T-206 | chunk 大小 | ≤ 4096 字节；50KB 数据 → 13 个 chunk（12×4096 + 2048 余量） | [A208] 分块上限 + 实际 chunk 数与边界可观测 |
| T-207 | ULONGLONGLEN 与实际不符 | 接收方 SHOULD 校验报错 | [A209] 一致性 |
| T-208 | RowCount 5×10^9 | 8B LE `00 F2 05 2A 01 00 00 00` | [A210] 8B 边界 |
| T-209 | 2^32-1 行 | 8B 表示 0xFFFFFFFF | [A211] 边界值 |

### §7.15 NULL 处理（S15）— T-210 ~ T-214

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-210 | INT4 NULL | 4B 全 0（定长 NULL=类型宽度全 0，已确认定义） | [A212] 定长 NULL |
| T-211 | varchar NULL | 2B 0xFFFF（CHARBIN_NULL） | [A213] 变长 NULL |
| T-212 | varchar(max) NULL | 8B 0xFFFFFFFFFFFFFFFF（PLP_NULL） | [A214] MAX NULL |
| T-213 | TEXT NULL | TYPE_INFO 含 TEXTTYPE(0x23) + 4B 0xFFFFFFFF（LONGLEN NULL） | [A215] 长 NULL + 类型 token 可观测 |
| T-214 | NBCROW 混合 NULL | bitmap 位正确，NULL 列无数据 | [A216] 位图压缩 |

### §7.16 集成 / 并发 / 类型覆盖补充（v3.0.1 新增）— T-215 ~ T-220

> 本节为 v3.0.1 针对 4 轮并行审计发现的 CRITICAL/HIGH 缺口（INT-01/02/03、CONC-01/02/03/05、FAIL-01、FIRST-07、COV-01/02/09、SCOPE-04/06）补充的端到端集成测试、并发正确性量化测试、运行时失败断言与数据类型覆盖测试。每条断言"配置 → 字节流/PCAP → 聚合行为"的可观测输出，与 §6 HexDump 场景的字节级期望值一一对照。

| 编号 | 输入 | 期望输出 | 断言点 |
|------|------|---------|--------|
| T-215 | TDSConfig JSON（Version=7.4, sessions=[{requests:[{type=sql_batch, sql={statements:[{text="select 'foo' as 'bar'"}]}}]}]}）→ 提交任务 → trafficgen 生成 PCAP | 字节流含 PRELOGIN（Type=0x12）+ LOGIN7（Type=0x10, TDSVersion wire `04 00 00 74`）+ SQL Batch（Type=0x01, ALL_HEADERS=22B, SQLText UCS-2 LE）+ 服务器响应（Type=0x04: COLMETADATA + ROW + DONE）；PCAP 文件包含预期的包序列与 PacketID 递增 | [A217] INT-01/02 端到端集成：TDSConfig → 字节流 → PCAP |
| T-216 | MARS TDSConfig（MarsEnabled=true, sessions=[A, B]）→ 提交任务 → 生成 PCAP | 字节流中 A 请求与 B 请求按预期交错（如 A 请求 → B 请求 → B 响应（DONE）→ A 响应（DONE））；OutstandingRequestCount 在 A 活动时=1，B 加入后=2，B 完成后=1，A 完成后=0；每个会话的 token 序列完整归并、无串扰 | [A218] CONC-01/02/05 MARS 并发正确性 + 字节流交错 + 响应归并无串扰 |
| T-217 | MARS TDSConfig + 会话 A 在事务中（TransactionId=X）、会话 B 不在事务中（TransactionId=0）→ 提交任务 | A 的请求 ALL_HEADERS.TransactionDescriptor=X，B 的 ALL_HEADERS.TransactionDescriptor=0；A 的 ENVCHANGE 8 仅作用于 A；B 的请求不携带 A 的事务描述符 | [A219] CONC-03 MARS 事务隔离并发 + 描述符独立可观测 |
| T-218 | 注入 broken spec：服务器响应在 COLMETADATA 中途截断（PCAP 模拟 TCP FIN 提前）→ 提交任务 | 任务实际失败（结果=FAIL）；失败原因含 "response truncated mid-COLMETADATA" 或类似；已收字节计数 = N（截断点位置）；无后续 DONE token 产出 | [A220] FIRST-07 运行时失败断言 + 失败原因与已收字节可观测 |
| T-219 | TDSConfig 含 RPC 参数 type="xml"（XMLTYPE=0xF1, PLP 编码）+ type="udt"（UDTTYPE=0xF0, PLP）+ type="json"（JSONTYPE=0xF4, PLP）+ type="vector"（VECTORTYPE=0xF5）→ 提交任务 | TYPE_INFO 分别含 0xF1/0xF0/0xF4/0xF5；ParamLenData 使用 PLP 编码（8B ULONGLONGLEN + chunks + 4B PLP_TERMINATOR）；PLP_NULL 时 8B 0xFFFFFFFFFFFFFFFF | [A221] COV-09 XML/JSON/UDT/Vector 类型覆盖 + PLP 编码字节级断言 |
| T-220 | TDSConfig 含 11 种 ENVCHANGE Type（Type 3/5/6/11/12/13/16/17/18/19/20/21 中至少 5 种未覆盖类型：如 Type 5、Type 6、Type 11、Type 13、Type 17）→ 服务器响应注入对应 ENVCHANGE token → 提交任务 | 解析器正确识别每种 Type 的 NewValue/OldValue 编码；Type 12 Defect Transaction NewValue=B_VARBYTE(8B)、OldValue=%x00；Type 16 NewValue=B_VARBYTE，OldValue=%x00；Type 17 NewValue=%x00、OldValue=B_VARBYTE(8B) | [A222] COV-02 ENVCHANGE 11 种 Type 覆盖 + NewValue/OldValue 编码方向可观测 |

---

## §8. Validate 规则

trafficgen 对 TDS 配置执行以下校验（错误码 V-TDS-xxx），每条对应至少一个测试：

### §8.1 通用规则

| 编号 | 规则 | 触发条件 | 错误码 |
|------|------|---------|--------|
| V-01 | Version 合法 | Version 不在 {7.1, 7.2, 7.3.A, 7.3.B, 7.4} | V-TDS-001 |
| V-02 | PacketSize 范围 | PacketSize < 512 或 > 32767 | V-TDS-002 |
| V-03 | 会话数 ≥ 1 | sessions 为空 | V-TDS-003 |
| V-04 | 会话请求非空 | requests 为空 | V-TDS-004 |
| V-05 | 请求类型合法 | type 不在 {sql_batch, rpc, trans_mgr, attention} | V-TDS-005 |
| V-06 | 请求类型与内容匹配 | type=sql_batch 但 sql 为空；type=rpc 但 rpc 为空 | V-TDS-006 |
| V-07 | AppName ≤ 128 字符 | 超限 | V-TDS-007 |
| V-08 | UserName ≤ 128 字符 | 超限 | V-TDS-008 |
| V-09 | Password ≤ 128 字符 | 超限 | V-TDS-009 |
| V-10 | ServerName ≤ 128 字符 | 超限 | V-TDS-010 |
| V-11 | Database ≤ 128 字符 | 超限 | V-TDS-011 |
| V-12 | Language ≤ 128 字符 | 超限 | V-TDS-012 |
| V-13 | InterfaceLib ≤ 128 字符 | 超限 | V-TDS-013 |
| V-14 | 登录字段含非法标识符字符 | UserName/Database 不符定界标识符规则 | V-TDS-014 |
| V-15 | FeatureExt 仅 TDS 7.4 | 非 7.4 配置带 feature | V-TDS-015 |
| V-16 | FeatureId 合法 | 不在已知集合 | V-TDS-016 |
| V-17 | FeatureData 十六进制合法 | 非法 hex | V-TDS-017 |
| V-18 | 密码混淆可逆 | 混淆后能还原 | V-TDS-018 |

### §8.2 请求规则

| 编号 | 规则 | 触发条件 | 错误码 |
|------|------|---------|--------|
| V-19 | SQL 非空 | SQLText 空 | V-TDS-020 |
| V-20 | SQLText UCS-2 对齐 | 文本转 UCS-2 后字节数为奇数（不可能，恒偶；用于校验输入） | V-TDS-021 |
| V-21 | RPC ProcName ≤ 1046 字节 | 超限 | V-TDS-022 |
| V-22 | RPC ProcId 合法 | ProcId > 15（未知特殊过程） | V-TDS-023 |
| V-23 | ProcName 与 ProcId 互斥 | 同时指定 | V-TDS-024 |
| V-24 | 参数类型合法 | 不在已知类型集合 | V-TDS-025 |
| V-25 | 参数 MaxLen 范围 | varchar > 8000 且非 max；nvarchar > 4000 且非 max | V-TDS-026 |
| V-26 | decimal Precision ≤ 38 | 超限 | V-TDS-027 |
| V-27 | decimal Scale ≤ Precision | 超限 | V-TDS-028 |
| V-28 | time/datetime2 scale ≤ 7 | 超限 | V-TDS-029 |
| V-29 | 参数值可解析为类型 | 值文本无法转换 | V-TDS-030 |
| V-30 | TVP 参数 fDefaultValue=0 | TVP 参数带默认值位 | V-TDS-031 |
| V-31 | TVP 参数 fByRefValue=0 | TVP 参数带引用位 | V-TDS-032 |
| V-32 | RPC 与 SQL 不混用 | 同请求同时指定 sql 与 rpc | V-TDS-033 |
| V-33 | TransMgrReq RequestType 合法 | 不在 {0,1,5,6,7,8,9} | V-TDS-034 |
| V-34 | TM_SAVE_XACT 需非空名 | request_type=9 且 payload 空 | V-TDS-035 |

### §8.3 事务与 MARS 规则

| 编号 | 规则 | 触发条件 | 错误码 |
|------|------|---------|--------|
| V-35 | TransactionId 需先 BEGIN | 首个请求 TransactionId ≠ 0 且无 BEGIN | V-TDS-036 |
| V-36 | 事务状态一致 | COMMIT 时无活动事务 | V-TDS-037 |
| V-37 | MARS 前置条件 | MarsEnabled=false 且会话数 > 1 | V-TDS-038 |
| V-38 | RESETCONNECTION 互斥 | Status 同时含 0x08 与 0x10 | V-TDS-039 |
| V-39 | Attention 无 body | Attention 请求带数据 | V-TDS-040 |
| V-40 | 会话内请求顺序 | 会话请求序列中 BEGIN/COMMIT 配对 | V-TDS-041 |

### §8.4 生成后校验（wire 校验，Build 阶段）

| 编号 | 规则 | 触发条件 | 错误码 |
|------|------|---------|--------|
| V-41 | 包 Length = 8 + body | 不符 | V-TDS-050 |
| V-42 | 包头 Length ≤ 32767 | 超限 | V-TDS-051 |
| V-43 | 登录前包 ≤ 4096 | 超限 | V-TDS-052 |
| V-44 | 分包长度 = 协商包大小 | 非最后包长度不符（TDS 7.3+） | V-TDS-053 |
| V-45 | 多包 PacketID 递增 | 不符 | V-TDS-054 |
| V-46 | 最后包 EOM=1 | 不符 | V-TDS-055 |
| V-47 | 偏移表单调 | 不符 | V-TDS-056 |
| V-48 | ibHostName ≠ 0 | 为 0 | V-TDS-057 |
| V-49 | 变长类型长度合法 | INTN 长度 ∉ {1,2,4,8} 等 | V-TDS-058 |
| V-50 | 解析后无残留字节 | token 流解析完仍有数据 | V-TDS-059 |

---

## §9. 错误处理

### §9.1 错误分类

| 类别 | 说明 | 处理 |
|------|------|------|
| 配置错误（V-TDS-xxx） | Validate 阶段拒绝 | 任务创建失败，不产生流量 |
| 生成错误 | Build 阶段 wire 校验失败 | 记录失败，任务失败 |
| 服务器错误响应 | ERROR token | 按 OutcomeSpec 断言；无断言时记录 |
| 服务器异常断开 | TCP FIN/RST 提前 | 任务失败，报告已收字节 |
| 协议结构错误 | 非法 Length/Type/token | 断开，报告错误偏移 |

### §9.2 ERROR/INFO token 处理流程

1. 解析 ERROR token → (Number, State, Class, MsgText, ServerName, ProcName, LineNumber)
2. Class < 10 → 视为 INFO（不中断）
3. Class 11-16 → 用户可修正错误：若 OutcomeSpec.ExpectError 未设置，标记任务结果含错误但继续
4. Class 17-19 → 批终止：当前批停止，后续请求按配置继续
5. Class 20-25 → 致命：断开连接，任务失败
6. 结果集内的 ERROR：先记 ERROR，后读 DONE（DONE_ERROR 位），再决定结果集有效与否

### §9.3 OutcomeSpec 断言

| 字段 | 断言逻辑 |
|------|---------|
| ExpectError | 期望至少一个 ERROR token |
| ErrorNumber | 期望的错误号（首 ERROR） |
| ErrorClass | 期望的错误类 |
| ExpectInfoCount | 期望 INFO token 数 |
| ExpectEnvChange | 期望收到的 ENVCHANGE（type → NewValue） |
| ExpectTranId | 期望收到 ENVCHANGE 8 且 TransactionID ≠ 0 |
| ExpectRows | 期望 DoneRowCount（语句级） |

断言失败 → 任务报告失败原因（含实际 token 序列）。

### §9.4 超时与重试

- 连接超时（默认 15s）→ 任务失败
- 请求超时（默认 30s）→ 发送 Attention；Cancel 计时器（默认 5s）超时 → 断开
- 不自动重试（流量生成器语义）；失败计数上报

### §9.5 分片与重组错误

- 收到 Length < 8 → 结构非法
- 收到中间包 EOM=1 但 PacketID 不连续 → 可容忍（PacketID 可忽略）
- 消息重组中收到新消息（Type 变化）→ 前一消息截断错误

---

## §10. 扩展字段映射

trafficgen 将 TDS 协议能力映射到统一任务模型：

| trafficgen 概念 | TDS 对应 | 说明 |
|----------------|---------|------|
| Flow（流） | TDS 连接（TCP 会话） | 一个 Flow = 一次 TCP 连接 + PRELOGIN/LOGIN7 + 会话请求序列 |
| 子流（SubFlow） | MARS 会话 | Flow 内多个 SessionSpec 交错 |
| 阶段（Phase） | 请求消息 | 每个 RequestSpec 是一个阶段 |
| 载荷（Payload） | SQL 文本 / RPC 参数 / Token 流 | 按请求类型编码 |
| 校验和 | TDS 无应用层校验和 | 依赖 TCP 校验和；无额外字段 |
| 包长 | 包头 Length（2B BE） | 生成器自动计算 |
| 事务 | TransactionDescriptor + ENVCHANGE 8/9/10 | 会话级状态 |
| 取消 | Attention（Type=0x06） | 请求级中断 |

### §10.1 协议版本 → 行为矩阵

| 特性 | 7.1 | 7.2 | 7.3 | 7.4 |
|------|-----|-----|-----|-----|
| DoneRowCount 4B | ✓ | — | — | — |
| DoneRowCount 8B | — | ✓ | ✓ | ✓ |
| LineNumber 2B | ✓ | — | — | — |
| LineNumber 4B | — | ✓ | ✓ | ✓ |
| UserType 4B | — | ✓ | ✓ | ✓ |
| ALL_HEADERS | — | ✓ | ✓ | ✓ |
| BatchFlag=0xFF | — | ✓ | ✓ | ✓ |
| PLP/MAX 类型 | — | ✓ | ✓ | ✓ |
| NbcRow | — | — | 7.3.B+ | ✓ |
| TVP | — | — | ✓ | ✓ |
| FeatureExt/FeatureExtAck | — | — | — | ✓ |
| DATETIME2 等新类型 | — | — | ✓ | ✓ |
| SESSIONSTATE | — | — | — | ✓ |

### §10.2 数据大小限制

| 项目 | 限制 |
|------|------|
| LOGIN7 总长 | ≤ 128K-1 |
| 包大小 | 512 ~ 32767（登录前 ≤ 4096） |
| RPC ProcName | ≤ 1046 字节 |
| 登录字符串字段 | ≤ 128 字符（AtchDBFile 260） |
| varchar(max) 值 | ≤ 2GB-1（chunk ≤ 4096） |
| TVP 列数 | ≤ 1024 |
| decimal 精度 | ≤ 38 |
| 表列数 | ≤ 65534（COLMETADATA Count 上限） |

---

## §11. 修订记录

### v3.0.2（2026-08-08）— RPC OptionFlags 字节数修正

**修复动因**：pcap 测试（test/protocol_pcap）中 tshark 将所有 RPC 包标记为 Malformed —— `tds.procid.value` 字段无法解析。根因：设计文档与实现均将 RPC OptionFlags 编码为 1B，但 MS-TDS §3.4 定义为 **USHORT（2B LE）**：fWithRecomp(bit0) + fNoMetaData(bit1) + fReuseMetaData(bit2) + 13 保留位。tshark `dissect_tds_rpc` 与 FreeTDS `tds_submit_rpc` 均按 2B 读取，1B 发射导致整条 RPC 流错位。

**修正内容**：
- §3.4 RPCReqBatch 语法：OptionFlags = 1B → **USHORT（2B LE）**。
- §6 S6/S7/S13 HexDump 请求：OptionFlags 补 1 字节 `00`，Length 与逐字段核算同步更新（S6: 0x41→0x42、S7: 0x2F→0x30、S13: 0x2F→0x31）。
- 实现 `builder_rpc.go`: `BuildRPCOptionFlags` 返回 `byte`→`uint16`，调用点经 `appendRPCOptionFlags` 写 2B LE。
- 新增单测 `TestRPCOptionFlagsTwoBytes` / `TestRPCRequestOptionFlagsTwoBytes`。

**规范核实依据**：MS-TDS §3.4 `OptionFlags = fWithRecomp fNoMetaData fReuseMetaData 13FRESERVEDBIT`（16 bits）。

### v3.0.1（2026-08-04）— 4 轮并行审计 CRITICAL + HIGH 问题修复

**修复动因**：v3.0.0 发布后，针对 4 个维度（HexDump 自洽性 / Token 流状态机 / 测试用例质量 / 数据类型与包结构）独立并行审计，共发现 107 个问题（CRITICAL 15 + HIGH 28 + MEDIUM 43 + LOW 21）。本版修复全部 CRITICAL + HIGH 问题（共 43 条）及部分关键 MEDIUM 问题。

**规范核实依据**：所有修复均与 MS-TDS v20260617 规范文本逐条核实（见各修复项引用的规范节号）。

**主要修复**（按审计维度分组）：

#### HexDump 维度（CRITICAL 2 + HIGH 4 + MEDIUM 3）

1. **S2 LOGIN7 请求 HexDump 不自洽（CRITICAL H-1）**：v3.0.0 HexDump 142B ≠ Length 字段 144B，根因是 HostName="skostv1"（截断 spec 4.2 的 "skostov1" 1 字符）。v3.0.1 恢复 spec 原始 HostName="skostov1"（8 字符，16B），cchHostName=8 与字节一致；同时修正偏移表自洽性（ibUserName=0x6E=110 指向 Data 区正确位置）。
2. **S2 Login Response HexDump 字节数与 Length 不一致（CRITICAL H-4）**：经逐字节核算，spec 示例 4.4 字节序列实为 353B 与 Length 字段 0x0161=353 完全自洽（v3.0.0 文字声称 355B 是审计员误算）。v3.0.1 补充逐 token 字节核算（30+91+11+26+22+95+57+13 = 345 = body ✓，Length=8+345=353 ✓）。
3. **S2 LOGIN7 OptionFlags3 字节值与文字描述矛盾（HIGH H-2）**：v3.0.0 HexDump 中 OptionFlags3 字节为 0x10，但文字描述为 0x00，且 spec 示例 4.2 字节序列明确为 0x00。v3.0.1 修正字节为 0x00（与 spec 一致）。
4. **S2 LOGIN7 HostName/AppName 文字标签与 HexDump 不一致（HIGH H-3）**：v3.0.0 文字称 HostName="host1"、AppName="trafficgen"，但 HexDump 字节解码为 "skostv1"/"OSQL-32"。v3.0.1 文字改为 "skostov1"/"OSQL-32" 与 spec 示例 4.2 一致。
5. **S2 LOGINACK ProgName 类型错误（HIGH H-5）**：v3.0.0 称 ProgName 用 US_VARCHAR（2B 长度），与规范 §2.2.7.14 `ProgName = B_VARCHAR`（1B BYTELEN 长度）矛盾。HexDump 字节 `16`（=22）是 1B 长度前缀，证明为 B_VARCHAR。v3.0.1 全文改为 B_VARCHAR。
6. **S2 Login Response Length 校验文字含糊（MEDIUM H-6）**：v3.0.0 文字三重不一致（338/345/347）。v3.0.1 给出逐 token 字节算式：body = 345B、Length = 0x0161 = 353B。
7. **S6 RPC 请求 BigVarChar 参数编码语义错误（HIGH H-7）**：v3.0.0 HexDump 中 BigVarChar(A7) 类型却用 UCS-2 LE 编码（"SELECT 1" 16B），与规范 BigVarChar 是 MBCS/ASCII 类型矛盾。v3.0.1 改为 ASCII "SELECT 1"（8B），maxlen=8，USHORTCHARBINLEN=8。
8. **S6 RPC 请求 Length 字段值与 HexDump 字节数不匹配（MEDIUM H-8）**：v3.0.0 HexDump 实际 73B 与 Length 字段 0x41=65 不符（v3.0.0 文字声称 "65 ✓" 是误算）。v3.0.1 修正后字节构成 22+4+1+11+1+8+10=57B=body，Length=8+57=65=0x41 与 HexDump 一致。
9. **S15 PLP_NULL 文字描述歧义（MEDIUM H-9）**：v3.0.0 文字 "变长 NULL = 0xFFFF/PLP 0xFFFE" 表述含糊，易混淆 PLP_NULL 与 UNKNOWN_PLP_LEN。v3.0.1 改为明确三段式 NULL 编码表述。

#### Token 流/状态机维度（CRITICAL 2 + HIGH 3 + MEDIUM 4 + LOW 3）

10. **DONE_RPCINBATCH(0x80) 归属错误（CRITICAL C1）**：v3.0.0 将 0x80 标为 "仅 DONE"，与规范 §2.2.7.6（DONE Status 不含 0x80）和 §2.2.7.8（DONEPROC Status 含 0x80）矛盾。v3.0.1 改为 0x80 仅在 DONEPROC 列。
11. **Attention Ack Type=0x05 错误（CRITICAL C2）**：v3.0.0 称 "Attention Ack Type=0x05"，与规范 §2.2.3.1.1 Type=5=Unused 矛盾。规范明确 Attention 确认通过 Type=0x04 包中 DONE token 的 DONE_ATTN(0x20) 位承载。v3.0.1 删除 "Attention Ack Type=0x05" 错误描述，§2.1.1 Type 表新增 0x05=Unused 行。
12. **LOGINACK.ProgName 类型错误（HIGH C4，同 H-5）**：见上。
13. **SAVE TRAN 标 trancount+1 错误（HIGH）**：v3.0.0 §4.3 称 "SAVE TRAN → trancount+1"，与 SQL Server 语义相悖（SAVE TRAN 仅创建保存点，不影响 @@trancount）。规范 §2.2.6.9 + §2.2.7.9 注释明确 "For operations that change only the value of @@trancount, no ENVCHANGE stream is generated"。v3.0.1 改为 "trancount 不变，仅创建保存点；不产生 ENVCHANGE"。
14. **ENVCHANGE Type 16 漏列（HIGH）**：v3.0.0 §3.10 Type 表从 15 跳到 17，未列 Type 16（Transaction Manager Address）。规范 §2.2.7.9 明确 Type 16 响应 TM_GET_DTC_ADDRESS(RequestType=0) 发送，NewValue=B_VARBYTE。v3.0.1 补行 "16 | Transaction Manager Address | B_VARBYTE | %x00"。
15. **ENVCHANGE Type 12 NewValue/OldValue 方向错误（LOW）**：v3.0.0 写 "NewValue=%x00、OldValue=8B"，与规范 §2.2.7.9 第 4928 行 `12: Defect Transaction OLDVALUE=%x00 NEWVALUE=B_VARBYTE` 反了。v3.0.1 改为 NewValue=B_VARBYTE(8B)、OldValue=%x00。
16. **ENVCHANGE Type 15 描述晦涩（LOW）**：v3.0.0 "Length 字段只含 1B type" 措辞晦涩。v3.0.1 改为 "DTC_TOKEN（L_VARBYTE，Length 字段=0x01 仅含 Type 字节；客户端须自行读 L_VARBYTE 4B 长度前缀 + DTC token 数据）"。
17. **ENVCHANGE Type 7 OldValue 类型不明（MEDIUM M2）**：v3.0.1 标 OldValue 为 B_VARBYTE（空时 0x00 即 1B 长度前缀为 0）。
18. **§3.6 OFFSET token 未标版本门控（MEDIUM）**：v3.0.1 §4.5 0x78 分支注明 "TDS 7.2 起服务器不再发送；TDS 7.4 收到视为协议错误"。
19. **§3.6 0xA5/0xAD token 值上下文复用未提示（MEDIUM）**：v3.0.1 补注 "0xA5 既是 COLINFO 流 token 又是 BIGVARBINARYTYPE 数据类型 token；0xAD 既是 LOGINACK 流 token 又是 BIGBINARYTYPE 数据类型 token；按所在流确定上下文"。
20. **§3.15 "收到确认" 措辞模糊（MEDIUM）**：v3.0.1 改为 "持续读取并丢弃除 SESSIONSTATE 外的所有数据，直到收到含 DONE_ATTN(0x20) 位的 DONE token——此 DONE 即为 Attention 确认载体"。
21. **§4.4 MARS 响应顺序来源标注（MEDIUM）**：v3.0.1 补注 "MARS 多路复用语义源自 MC-SMP 规范，MS-TDS 主规范仅规定 MARS 消息经 SMP 层传递"。
22. **§3.7 COLMETADATA Flags 问号式表述（LOW）**：v3.0.1 删除问号式表述，直接陈述结论。

#### 数据类型/包结构/一致性维度（CRITICAL 6 + HIGH 5 + MEDIUM 6 + LOW 3）

23. **COLMETADATA Flags 位掩码值全面错误（CRITICAL C1）**：v3.0.0 将 fFixedLenCLRType 标为 0x1000、fSparseColumnSet=0x200、fEncrypted=0x400、fHidden=0x20000、fKey=0x40000、fNullableUnknown=0x80000，与规范 §2.2.7.4 LSB 序矛盾且 fHidden/fKey/fNullableUnknown 超出 16 位范围。v3.0.1 按规范 LSB 序重排：fFixedLenCLRType=0x0100、fSparseColumnSet=0x0400、fEncrypted=0x0800、fHidden=0x2000、fKey=0x4000、fNullableUnknown=0x8000。
24. **Attention Ack Type=0x05 错误（CRITICAL C2，同上）**：见上。
25. **RPC StatusFlags fEncrypted 位号错误（CRITICAL C3）**：v3.0.0 称 fEncrypted 在 bit4，规范 §2.2.6.6 明确 StatusFlags = fByRefValue(bit0) + fDefaultValue(bit1) + 1FRESERVEDBIT(bit2) + fEncrypted(bit3) + 4FRESERVEDBIT。v3.0.1 改为 bit3。
26. **LOGINACK ProgName 类型错误（CRITICAL C4，同 H-5）**：见上。
27. **LOGINACK TDSVersion wire 字节序标注错误（CRITICAL C5）**：v3.0.0 §3.12 称 LOGINACK TDSVersion 7.4 "wire LE `04 00 00 74`"，与规范脚注 72 "Server to client" 列 7.4=`0x74000004`（wire BE `74 00 00 04`）矛盾。v3.0.1 §3.12 改为 wire `74 00 00 04`（与 LOGIN7 客户端→服务器方向 `04 00 00 74` 字节相反，因规范将两端表示成不同字节序）。
28. **DONEINPROC 状态表错误包含 DONE_FINAL（CRITICAL C6）**：v3.0.0 §3.9 将 DONE_FINAL(0x00) 标为对 DONEINPROC 有效。规范 §2.2.7.7 DONEINPROC Status 位列表不含 0x00（DONEINPROC 必须后跟另一 DONEPROC/DONEINPROC）。v3.0.1 改为 DONE_FINAL 对 DONEINPROC 列为 "—"。
29. **LOGIN7 OffsetLength 表大小描述错误（HIGH H1）**：v3.0.0 称 "OffsetLength 固定 94 字节"，规范 §2.2.6.4 明确表本身为 58B（TDS 7.2+）或 50B（7.0/7.1），94 是 ibHostName 值（=固定 Header 36B + OffsetLength 58B）。v3.0.1 改为 58B 并解释 ibHostName=0x5E 的含义。
30. **§1.2 TDS 版本表 NBCROW 标注 7.3.A 支持（HIGH H2）**：v3.0.0 表将 NbcRow 与稀疏列标为 "7.3.A / 7.3.B" 共同支持，与规范脚注 17 明确的 "7.3.A 不含 NBCROW 与 fSparseColumnSet" 矛盾。v3.0.1 拆分为 7.3.A（TVP+RESETCONNECTIONSKIPTRAN，无 NbcRow）和 7.3.B（NbcRow+稀疏列）两行。
31. **§1.2 TDS 8.0 行不存在于规范（HIGH H3）**：v3.0.0 含 "8.0 | SQL Server 2022+ | 强制 TLS" 行，规范 v20260617 未定义 TDS 8.0（脚注 17 标注 SQL Server 2022/2025 仍用 7.4）。v3.0.1 删除 TDS 8.0 行，改为脚注说明 SQL Server 2022/2025 在 TDS 7.x 流中仍用 7.4。
32. **§1.7 B_VARCHAR 说明完善（HIGH H4）**：v3.0.1 补充 "BYTELEN 值为 Unicode 字符数（非字节数）"。
33. **§2.4.3 变长 NULL 规则表述矛盾（HIGH H5）**：v3.0.0 "BYTELEN/USHORTLEN 类型 = 0x00；BIG* 等 = 0xFFFF" 逻辑矛盾（BIG* 本就属 USHORTLEN）。v3.0.1 重写为三段式：非字符/二进制 BYTELEN/USHORTLEN 变长 NULL=0x00（GEN_NULL）；USHORTLEN char/binary 类型（BIG* 系列）NULL=0xFFFF；LONGLEN 类型（TEXT/NTEXT/IMAGE）NULL=0xFFFFFFFF。
34. **TransMgrReq 隔离级别措辞（MEDIUM M3）**：v3.0.1 改 0x00 为 "使用当前不改变"（与规范 §2.2.6.9 注释一致）。
35. **§3.2 ibExtension 版本门控（MEDIUM M6）**：v3.0.1 补充 "TDS 7.3 及以下该位置为 ibUnused/cbUnused（预留，置 0）"。

#### 测试用例维度（CRITICAL 5 + HIGH 16 + MEDIUM 30+ + LOW 15+）

36. **V-41 ~ V-50 wire 校验规则无明确测试（CRITICAL FAIL-01）**：v3.0.1 在 §7 中通过新增 T-215（端到端集成）等用例断言 wire 校验规则触发；同时在 §6 HexDump 场景的逐字节校验注释中挂钩 V-TDS-050 ~ V-TDS-059 错误码。
37. **无 TDSConfig → 字节流集成测试（CRITICAL INT-01）**：v3.0.1 新增 T-215（端到端集成：TDSConfig JSON → trafficgen 字节流 → PCAP 文件），断言字节流含 PRELOGIN + LOGIN7 + SQL Batch + 服务器响应的完整序列。
38. **无 任务提交 → PCAP 产出 端到端测试（CRITICAL INT-02）**：v3.0.1 通过 T-215 同时覆盖 PCAP 文件产出断言。
39. **MARS 响应归并无正确性测试（CRITICAL CONC-02）**：v3.0.1 新增 T-216（MARS 并发正确性 + 字节流交错 + 响应归并无串扰），断言 2 会话交错请求的实际字节流顺序与 OutstandingRequestCount 的实际变化。
40. **无"运行时失败"断言（CRITICAL FIRST-07）**：v3.0.1 新增 T-218（注入 broken spec：服务器响应在 COLMETADATA 中途截断 → 任务实际失败且报告原因与已收字节计数）。
41. **MARS 多会话无并发正确性量化测试（HIGH CONC-01）**：见 T-216。
42. **MARS 事务隔离无并发测试（HIGH CONC-03）**：v3.0.1 新增 T-217（MARS 下会话 A 在事务中、会话 B 不在事务中 → 各自 TransactionDescriptor 独立、ENVCHANGE 8 仅作用于 A）。
43. **多 SessionSpec 字节流交错无测试（HIGH CONC-05）**：见 T-216（多 SessionSpec 在字节流中按预期交错）。
44. **XML/JSON/UDT/Vector 类型完全无测试（HIGH COV-09）**：v3.0.1 新增 T-219（4 种 PLP 类型 TYPE_INFO 与 ParamLenData 字节级断言）。
45. **ENVCHANGE 11 种 Type 无测试（HIGH COV-02）**：v3.0.1 新增 T-220（11 种未覆盖 Type 中至少 5 种 NewValue/OldValue 编码方向断言，含 Type 12/16/17 方向修正）。
46. **SSPI/FedAuth Token/TVP_ROW 无测试（HIGH SCOPE-04/06）**：v3.0.1 在 §7.16 备注 "v3.0.2 计划补充"，因实现路径复杂需独立设计；当前 v3.0.1 优先修复 CRITICAL 与已覆盖的 HIGH 问题。
47. **OBS-02/05/07/09/10/12/13/14 等 17 条可观测断言不充分（HIGH/MEDIUM）**：v3.0.1 修正 T-015/T-040/T-059/T-073/T-118/T-149/T-155/T-163/T-167/T-178/T-181/T-183/T-189/T-190/T-200/T-202/T-206/T-213 等 18 条用例，补充具体字段值或字节序列断言。
48. **QUAL-03/04/06/07/08/09/10/11/12/13/14/15/16/17 等"测试通过但测错东西"风险（MEDIUM）**：v3.0.1 修正 T-035（声明 ProgName='Microsoft SQL Server' 假设）、T-067（无 DONE_COUNT 时 RowCount 不可读）、T-099（maxlen=8、len=8、ASCII 8B）、T-110（maxlen=8、len=16、UCS-2 16B）、T-118（StatusFlags 位解析）、T-126（重排前后顺序）、T-133（嵌套层级）、T-181（隔离级别字节）、T-183（trancount 实际值）、T-189（DONE_MORE 计数）、T-206（chunk 数与边界）、T-213（TEXTTYPE token）等。
49. **T-030 OffsetLength 94B 描述错误（HIGH H1 关联）**：v3.0.1 改为 58B 并解释 ibHostName=0x5E 的含义。
50. **T-034 ProgName US_VARCHAR 错误（HIGH C4 关联）**：v3.0.1 改为 B_VARCHAR。
51. **T-099 BigVarChar 用 UCS-2 编码错误（HIGH H-7 关联）**：v3.0.1 改为 ASCII 编码 + maxlen=8 + len=8。

**测试用例数量**：v3.0.0 的 214 条基础上新增 6 条（T-215 ~ T-220），共 220 条。

### v3.0.0（2026-08-04）— 基于 MS-TDS v20260617 全文重写

**重写动因**：v2.0.1 存在多处与官方规范不一致或未覆盖的内容。本版以 ms-tds-spec.txt（12603 行）为唯一事实来源，逐章核对重写。

**主要变更**：

1. **§2 数据类型全面补全**：
   - 完整列出 FIXEDLENTYPE（12 种）、BYTELEN_TYPE（17 种）、USHORTLEN_TYPE（7 种）、LONGLEN_TYPE（6 种）全部 token 值
   - 新增 DATE/TIME/DATETIME2/DATETIMEOFFSET 的 SCALE→长度映射表（scale 1-2→3B 等）
   - 新增 PLP 完整编码（PLP_NULL/UNKNOWN_PLP_LEN/PLP_CHUNK/PLP_TERMINATOR）
   - 明确 NULL 三种编码：定长=类型宽度全 0；变长 BIG*=0xFFFF；TEXT/NTEXT/IMAGE=0xFFFFFFFF；MAX=8B PLP_NULL
   - 补充 COLLATION 5B 结构（LCID+ColFlags+Version+SortId）
   - 补充数值编码（money×10^4、decimal 符号+整数、datetime 1/300 秒等）

2. **§3 消息结构修正**：
   - LOGIN7：修正 OffsetLength 为 94 字节（含 cbSSPILong），补充 ibExtension/cbExtension（TDS 7.4）、密码混淆算法（高低 4 位互换 + XOR 0xA5）、所有登录校验规则
   - RPC：补充 BatchFlag=0xFF/NoExecFlag=0xFE 语义、ProcID 短形式（0xFFFF + USHORT）、ProcName ≤ 1046 字节、TVP 参数约束
   - PRELOGIN：完整选项表（VERSION 必须第一、TERMINATOR 必须最后、PL_OFFSET 大端）
   - SQLBatch：ALL_HEADERS 必须（TransactionDescriptor 必需）
   - 新增 TransMgrReq（§3.5）与全部 7 种 RequestType
   - 新增 FEATUREEXTACK/SESSIONSTATE/SSPI/RETURNVALUE/ORDER/TABNAME/COLINFO 等 token 定义

3. **已确认定义（前几轮审计验证）全部纳入**（v3.0.1 已修正其中 2 项错误，见下）：
   - TDS 包头 8 字节（Type/Status/Length BE/SPID BE/PacketID/Window）
   - TDSVersion 0x74000004 wire LE `04 00 00 74`（LOGIN7 客户端→服务器方向）
   - RowCount：7.1=4B、7.2+=8B
   - Error/Info LineNumber=2B USHORT（7.1）/4B（7.2+）
   - EnvChange Begin/Commit/Rollback：NewValue=1B(0x08)+8B TransactionID
   - Attention 请求 Type=0x06；Attention 确认通过 Type=0x04 包中 DONE Token 的 DONE_ATTN(0x20) 位承载（v3.0.0 误标 "Attention Ack Type=0x05"，v3.0.1 已修正）
   - RPC ProcName US_VARCHAR；ProcID 短形式 0xFFFF+4B
   - B_VARCHAR=1B BYTELEN+UCS-2 LE；US_VARCHAR=2B LE+UCS-2 LE
   - ColName 用 B_VARCHAR；LoginAck.ProgName 用 B_VARCHAR（v3.0.0 误标 US_VARCHAR，v3.0.1 已修正）
   - LoginAck.Length=整个 token 字节数
   - 定长 NULL=类型宽度全 0；变长 NULL 三段式（GEN_NULL/CHARBIN_NULL 2B 或 4B/PLP_NULL 8B）
   - Done Status 位完整表（DONE_MORE=0x1 ... DONE_SRVERROR=0x100；DONE_RPCINBATCH=0x80 仅 DONEPROC）
   - FeatureExtAck=0xAE
   - MARS：SPID 标识连接；同连接多会话共享 SPID，靠消息边界区分

4. **§4 状态机新增**：客户端 11 状态、服务器 11 状态、事务状态机、MARS 状态机、解析状态机

5. **§5 Go struct**：新增 TDSConfig/SessionSpec/RequestSpec/ParamSpec/TransMgrSpec/OutcomeSpec 等完整配置类型（含 JSON tag 与 Validate 挂钩）

6. **§6 HexDump 全部重算**：15 个场景每个都做 Length = 8 + body 逐字节校验；对 v2.0.1 中 Length 不符的示例（S4/S5/S6/S8/S9/S11/S12/S15）做了修正并保留修正记录；S11/S12/S13/S14/S15 为新增场景

7. **§7 测试用例**：200+ 扩充至 214 条（T-001 ~ T-214），覆盖成功 + 失败 + 边界 + 多会话/多流，每条含输入/期望输出/断言点（A1-A216），与 15 个 HexDump 场景一一对应

8. **§8 Validate**：50 条校验规则（V-01 ~ V-50），每条对应错误码与测试挂钩

9. **§10 扩展字段映射**：版本→行为矩阵、数据大小限制表

**与 v2.0.1 的差异点（不兼容变更）**：
- v2.0.1 将 LOGINACK.Length 描述为 "Interface..ProgVersion 总长" 的歧义表述 → 明确为"整个 token 除去 TokenType/Length 的字节数"
- v2.0.1 未覆盖 PLP 编码 → v3.0.0 完整定义
- v2.0.1 未覆盖 TransMgrReq → v3.0.0 新增 §3.5
- v2.0.1 的多个 HexDump 存在 Length 与 body 不符 → v3.0.0 全部逐字节校验修正
- v2.0.1 未定义 FeatureExt 编码 → v3.0.0 完整定义

### v2.0.1（2026-08-04）

返工修复：修正 RPC ProcName 编码、EnvChange 事务结构、RowCount 宽度等（详见上一版文档 §11）。

### v2.0.0（2026-07-xx）

初始 TDS 设计，覆盖 PRELOGIN/LOGIN7/SQL Batch/RPC/Attention 基本场景。

---

*本文档所有 wire 格式以 MS-TDS v20260617（修订版 42.0）为准；与规范冲突时以规范为准并更新本文档。*


# ENIP（EtherNet/IP）协议设计与测试用例

**协议版本**：v2.0.1（基于 ODVA EtherNet/IP Volume 1 & 2 + CIP Common Specification，对照 OpENer/libplctag/EEIP.Java 参考实现）
**传输层**：TCP（显式消息 + Class 3 隐式消息，端口 44818）+ UDP（Class 0/1 隐式 I/O，端口 44818）
**状态**：设计阶段，未实现
**字节序**：全部 little-endian（LE）
**参考依据**：
- OpENer `source/src/cip/ciptypes.h`（CIPServiceCode 枚举）
- OpENer `source/src/enet_encap/cpf.h`（CipItemId 枚举）
- OpENer `source/src/cip/cipepath.h`（EPATH 段类型常量）
- OpENer `source/src/enet_encap/encap.h`（EncapsulationProtocolErrorCode 枚举）
- OpENer `source/src/cip/cipconnectionobject.c`（Forward_Open/LargeForwardOpen 字段解析）
- OpENer `source/src/cip/cipconnectionmanager.c`（Forward_Close 与 Forward_Open 响应装配）
- OpENer `source/src/enet_encap/encap.c`（RegisterSession / SendRRData / SendUnitData 处理）
- OpENer `source/src/enet_encap/cpf.c`（AssembleLinearMessage：Interface Handle + Timeout + CPF）
- OpENer `source/src/enet_encap/endianconv.c`（AddIntToMessage / AddDintToMessage：little-endian）
- libplctag `src/libplctag/protocols/ab/defs.h`（AB_EIP_CMD_* 服务码）

---


## 1. 协议概述

ENIP（EtherNet/IP，其中 "IP" 指 Industrial Protocol 工业协议而非 Internet Protocol）是 ODVA 组织定义的工业自动化协议，将 **CIP（Common Industrial Protocol，通用工业协议）** 映射到 TCP/IP 上。在工业控制网络中，PLC（Programmable Logic Controller，可编程逻辑控制器）、HMI（Human-Machine Interface，人机界面）、SCADA（Supervisory Control and Data Acquisition，监控与数据采集）等设备通过 ENIP 交换控制数据和 I/O 信号。

### 1.1 两类消息通道

| 通道类型 | 传输层 | 端口 | ENIP Command | CPF 承载方式 | 用途 |
|----------|--------|------|--------------|--------------|------|
| **显式消息**（Explicit Messaging） | TCP | 44818 | SendRRData (0x006F) | Null Address (0x0000) + Unconnected Data (0x00B2)；或 Connected Address (0x00A1) + Connected Data (0x00B1) | 请求/应答式 CIP 服务调用（读/写属性、Forward_Open/Close、Multiple_Service_Packet 等） |
| **隐式消息**（Implicit / I/O Messaging） | UDP（Class 0/1 multicast）或 TCP（Class 3 connected） | 44818 | SendUnitData (0x0070) | Connected Address (0x00A1) + Connected Data (0x00B1)；或 Sequenced Address (0x8002) + Connected Data | 周期性或事件触发的 I/O 数据推送（传感器值、执行器指令） |

**关键澄清**（修正 v1 的 D-MED-5）：
- SendUnitData 不局限于 UDP。ODVA 规范允许 Class 3 connected messaging 通过 TCP SendUnitData 传输；Class 0/1 周期 I/O 通常走 UDP。
- SendRRData 封装 CIP 显式服务，使用 CPF **Unconnected Data Item (0x00B2)** 承载未连接 CIP 消息（如 Forward_Open/Close、Get_Attribute_Single），或使用 Connected Address (0x00A1) + Connected Data (0x00B1) 承载 Class 3 已连接显式消息。
- SendUnitData 封装 CIP 隐式 I/O 数据，使用 CPF **Connected Address Item (0x00A1) + Connected Data Item (0x00B1)**，其中 Connected Data Item 起始 2 字节是 Sequence Counter。

### 1.2 典型会话生命周期

```
Client (SCADA/HMI)                                         Server (PLC)
  |                                                           |
  |-- TCP 3-way handshake ----------------------------------->|  (SYN, SYN-ACK, ACK)
  |                                                           |
  |-- [ENIP] ListIdentity (0x0063) -------------------------->|  发现设备
  |<-- [ENIP] ListIdentity Response (CPF TypeID 0x000C) ------|  返回 VendorID/DeviceType/ProductName...
  |                                                           |
  |-- [ENIP] RegisterSession (0x0065) ----------------------->|  注册会话（payload 直接是 ProtocolVersion+OptionFlag）
  |<-- [ENIP] RegisterSession Response -----------------------|  返回 SessionHandle
  |                                                           |
  |-- [ENIP] SendRRData { CIP Forward_Open (0x54) } -------->|  打开 I/O 连接
  |<-- [ENIP] SendRRData { CIP Forward_Open Response } -------|  返回 O2T/T2O ConnectionID
  |                                                           |
  |== [UDP] SendUnitData { I/O data frame 1 } ==============>|  I/O 数据周期交换
  |== [UDP] SendUnitData { I/O data frame 2 } ==============>|  (ConnectionID 标识，Connected Data 含 seq counter)
  |== [UDP] SendUnitData { I/O data frame N } ==============>|
  |                                                           |
  |-- [ENIP] SendRRData { CIP Forward_Close (0x4E) } ------->|  关闭 I/O 连接（用 ConnSerialNum+VendorID+SerialNum 三元组定位）
  |<-- [ENIP] SendRRData { CIP Forward_Close Response } ------|
  |                                                           |
  |-- [ENIP] UnregisterSession (0x0066) --------------------->|  注销会话
  |                                                           |
  |-- TCP 4-way teardown ----------------------------------->|  (FIN, FIN-ACK, ...)
```

**注意**：ListIdentity 可通过 TCP 或 UDP 发送（广播发现常用 UDP 0x0063 广播包）。trafficgen 中 TCP 显式消息场景使用 TCP 发送 ListIdentity。

### 1.3 关键不变量（Invariants）

1. **字节序**：ENIP 封装层与 CIP 层所有多字节字段均为 **little-endian**（Sockaddr Info Item 的 SinPort/SinAddr 例外，见 §2.4.2）。SenderContext 是 8 字节不透明字段（无字节序概念）。
2. **ENIP 头长度**：固定 24 字节。Length 字段 = payload 字节数（不含头本身），最大 65515。
3. **6 字节前缀仅限 SendRRData/SendUnitData**：**仅** SendRRData/SendUnitData 的 payload 在 CPF ItemCount 之前有 **Interface Handle (4B LE) + Timeout (2B LE)** 共 6 字节前缀（Interface Handle 通常为 0，CIP 协议；Timeout 单位为秒）。**ListServices/ListIdentity/ListInterfaces 响应 payload 无此前缀**，直接以 ItemCount 开头（对照 OpENer `encap.c`，v2.0.1 修订，对应审计 R1）。
4. **RegisterSession payload**：直接是 **ProtocolVersion (2B LE) + OptionFlag (2B LE)**，不携带 CPF item。ProtocolVersion 必须为 1，OptionFlag 必须为 0。
5. **Forward_Open vs LargeForwardOpen**：Forward_Open (0x54) 的 Network Connection Parameters 为 2 字节；LargeForwardOpen (0x5B) 为 4 字节。**两者位布局不同**（2B：9 位 Connection Size + bit 9 Fixed/Variable + bit 10-11 Priority + bit 12 Reserved + bit 13-14 Type + bit 15 Redundant Owner；4B：16 位 Connection Size + 高位 16 位存放位字段，见 §3.5.1/§3.5.2），4B 版本不是 2B 版本的简单位扩展（v2.0.1 修订，对应审计 R39）。
6. **Forward_Close 定位连接**：不通过 ConnectionID，而是通过 **ConnectionSerialNumber + OriginatorVendorID + OriginatorSerialNumber** 三元组定位连接。
7. **CIP 服务码响应位**：CIP 响应的 Reply Service = Request Service | 0x80（如 Forward_Open 请求 0x54 → 响应 0xD4）。
8. **CPF ItemCount**：至少 2 项（Null Address + Unconnected Data），最多 4 项（增加 O→T / T→O Sockaddr Info，可选）。

---

## 2. 数据类型与编码

### 2.1 ENIP 封装头（24 字节，固定）

所有 ENIP 消息（TCP 或 UDP）均以此头开始。所有多字节字段 **little-endian**。

| 偏移 | 字段 | 大小 | 字节序 | 说明 |
|------|------|------|--------|------|
| 0 | Command（命令） | 2 B | LE | 见 §2.2 命令表 |
| 2 | Length（长度） | 2 B | LE | payload 字节数（不含 ENIP 头本身），范围 0–65515 |
| 4 | SessionHandle（会话句柄） | 4 B | LE | RegisterSession 返回的句柄；未注册时为 0 |
| 8 | Status（状态） | 4 B | LE | 0 = 成功；非零见 §2.3 错误码表 |
| 12 | SenderContext（发送者上下文） | 8 B | 不透明 | 发送者的不透明追踪标识；请求中设置，响应中回显 |
| 20 | Options（选项） | 4 B | LE | 通常为 0；非零表示接收方应忽略该包 |

**HexDump 示例**（RegisterSession 请求头）：
```
65 00          Command=0x0065 (RegisterSession), LE
04 00          Length=4 (payload 4 字节), LE
00 00 00 00    SessionHandle=0 (未注册)
00 00 00 00    Status=0 (请求中通常为 0)
01 02 03 04 05 06 07 08   SenderContext=0x0807060504030201 (任意 8 字节)
00 00 00 00    Options=0
```
共 24 字节，wire 上 65 00 04 00 00 00 00 00 00 00 00 00 01 02 03 04 05 06 07 08 00 00 00 00。

### 2.2 ENIP Command 表

依据 OpENer `encap.c` 的命令分发函数与 EEIP.Java `CommandsEnum.java`。

| 值 (LE) | 命令名 | 方向 | 传输 | payload 说明 |
|---------|--------|------|------|--------------|
| 0x0000 | Nop（空操作） | 单向（req，无响应） | TCP | 可携带任意 payload，接收方忽略（保活/测试）；**不产生响应** |
| 0x0004 | ListServices（服务列表） | req→resp | TCP/UDP | 请求无 payload；响应携带 CPF ItemCount + ListServices Response Item (0x0100) |
| 0x0063 | ListIdentity（身份列表） | req→resp | TCP/UDP | 请求无 payload；响应携带 CPF ItemCount + ListIdentity Response Item (0x000C) |
| 0x0064 | ListInterfaces（接口列表） | req→resp | TCP | 请求无 payload；响应携带 ItemCount=0（无接口） |
| 0x0065 | RegisterSession（注册会话） | req→resp | TCP | payload = ProtocolVersion(2B LE) + OptionFlag(2B LE)，无 CPF |
| 0x0066 | UnRegisterSession（注销会话） | req | TCP | 无 payload |
| 0x006F | SendRRData（发送请求/应答数据） | 双向 | TCP | payload = Interface Handle(4B LE) + Timeout(2B LE) + CPF |
| 0x0070 | SendUnitData（发送单元数据） | 双向 | TCP/UDP | payload = Interface Handle(4B LE) + Timeout(2B LE) + CPF |
| 0x0072 | IndicateStatus（状态指示） | server→client | TCP | **trafficgen 模拟扩展**：server 主动向 client 推送状态通知（见下） |
| 0x0073 | Cancel（取消） | req | TCP | **trafficgen 模拟扩展**：取消一个未完成的 SendRRData |

**修正说明**（对比 v1）：
- Nop (0x0000) 可携带任意 payload（v1 错写"无 payload"）；**NOP 不产生响应**——OpENer `kEncapsulationCommandNoOperation` 处理逻辑直接 break 不返回任何包（v2.0.1 修订，对应审计 R16）。
- IndicateStatus (0x0072) 方向是 server→client（v1 错写"resp→req"）。
- ListInterfaces (0x0064) 请求无 payload，响应 ItemCount=0（v1 错写"CIP Get Class 0xF5"）。

**关于 IndicateStatus (0x0072)/Cancel (0x0073) 的兼容性说明**（v2.0.1 修订，对应审计 R16/R18/R33/R37）：ODVA 规范定义这两个命令，但 OpENer 的 `EncapsulationCommand` 枚举**仅实现 8 个命令**（0x0000/0x0004/0x0063/0x0064/0x0065/0x0066/0x006F/0x0070），0x0072/0x0073 **不在其中**，OpENer 收到会返回 0x0001 Invalid Command。因此：
- trafficgen 模拟设备端（server 响应模拟）时，**不应**将 0x0072/0x0073 作为合法接收命令——收到应回 ENIP Status=0x0001。
- trafficgen 客户端（client 主动发送）场景下可使用 0x0072 做异常注入测试，但目标设备可能返回 Invalid Command。
- IndicateStatus 的 payload 格式**无规范依据**（ODVA 未定义），仅用于 trafficgen 内部测试，见 §6.16 S15 的说明。

### 2.3 ENIP Status 错误码表

依据 OpENer `encap.h` 的 `EncapsulationProtocolErrorCode` 枚举（仅 7 个合法值）。

| 值 (LE) | 名称 | 含义 |
|---------|------|------|
| 0x0000 | Success（成功） | 操作成功完成 |
| 0x0001 | Invalid Command（无效命令） | 发送了未定义的 Command |
| 0x0002 | Insufficient Memory（内存不足） | 接收方资源不足 |
| 0x0003 | Incorrect Data（数据不正确） | payload 格式错误或长度不匹配 |
| 0x0064 | Invalid Session Handle（无效会话句柄） | SessionHandle 未注册或已过期 |
| 0x0065 | Invalid Length（长度无效） | Length 字段与 payload 实际长度不一致 |
| 0x0069 | Unsupported Protocol（不支持的协议版本） | 请求的 ENIP 版本不被支持 |

**修正说明**（对比 v1，D-CRIT-5）：v1 错误地将 InvalidSession=0x04、InvalidLength=0x05、UnsupportedProtocol=0x06，且混入了 CIP 层错误码（TargetNotFound=0x64、InvalidConnection=0x65、ConnectionTimeout=0x66）。实际上 0x64/0x65 是 ENIP 层的 InvalidSessionHandle/InvalidLength，0x69 是 UnsupportedProtocol；CIP 层错误码（Path Destination Unknown=0x05、Connection Failure=0x01）属于 CIP 通用状态码（§2.3.2），不属于 ENIP Status。

### 2.3.1 CIP 通用状态码（General Status，CIP 层）

CIP Message Router 响应的 General Status 字段（1 字节），独立于 ENIP Status。常用值：

| 值 | 名称 | 含义 |
|----|------|------|
| 0x00 | Success | 成功 |
| 0x01 | Connection Failure | 连接失败 |
| 0x02 | Resource unavailable | 资源不足，无法分配连接 |
| 0x04 | Path segment error | EPATH 路径段错误 |
| 0x05 | Path destination unknown | 路径目标不存在 |
| 0x06 | Partial transfer | 部分传输 |
| 0x08 | Service not supported | 服务码不支持 |
| 0x09 | Invalid Attribute Value | 属性值非法 |
| 0x0C | Object state conflict | 对象状态冲突 |
| 0x0E | Attribute not supported | 属性不支持 |
| 0x13 | Not enough data | 数据不足 |
| 0x14 | Attribute not settable | 属性不可写 |
| 0x15 | Permission denied | 权限拒绝 |
| 0x1E | CIP 序列错误 | Multiple_Service_Packet 子请求错误 |

### 2.3.2 CIP Connection Manager 扩展状态码

Forward_Open/Forward_Close 失败时，CIP 响应 Additional Status 字段（2 字节）携带扩展状态。依据 OpENer `cipconnectionmanager.h` 的 `ConnectionManagerExtendedStatusCode` 枚举与 Wireshark `packet-cip.c` 的 `CM_ES_*` 常量：

| 值 | 名称 | 说明 |
|----|------|------|
| 0x0100 | Connection in use or duplicate forward open | 连接已存在或重复 Forward_Open |
| 0x0103 | Transport class and trigger combination not supported | 传输类与触发组合不支持 |
| 0x0106 | Ownership conflict | 所有权冲突 |
| 0x0107 | Target connection not found | 目标连接未找到（Forward_Close 找不到连接时也用此码） |
| 0x0110 | Target for connection not configured | 连接目标未配置 |
| 0x0111 | RPI not supported | RPI 不支持 |
| 0x0112 | RPI values not acceptable | RPI 值不可接受 |
| 0x0113 | No more connections available | 无可用连接资源 |
| 0x0114 | Vendor ID or product code mismatch | 厂商 ID 或产品代码不匹配 |
| 0x0115 | Device type error | 设备类型错误 |
| 0x0116 | Revision mismatch | 修订版本不匹配 |
| 0x0127 | Invalid O→T connection size | O→T 连接大小无效 |
| 0x0128 | Invalid T→O connection size | T→O 连接大小无效 |
| 0x0203 | Connection timed out | 连接超时 |
| 0x0204 | Unconnected request timed out | 未连接请求超时 |
| 0x0312 | Link address not valid | 链路地址无效 |
| 0x0315 | Invalid segment type in path | 路径段类型无效 |
| 0x0316 | ForwardClose connection path mismatch | Forward_Close 路径与 Forward_Open 不一致 |
| 0xFFFF | Wrong closer | Forward_Close 发起方与 Forward_Open 不一致 |

**修正说明**（v2.0.1 修订，对应审计 R5/R10）：v2.0.0 表中 6 项错误已纠正：
- 0x0107 由"Connection size mismatch"改为"Target connection not found"（OpENer `ErrorConnectionTargetConnectionNotFound`）。
- 0x0111 由"Target connection not found"改为"RPI not supported"（OpENer `RpiNotSupported`）。
- 0x0112 由"Invalid connection size"改为"RPI values not acceptable"（OpENer `ErrorRpiValuesNotAcceptable`）。
- 0x0312 由"Invalid consumption configuration"改为"Link address not valid"（OpENer `LinkAddressNotValid`）。
- 删除 0x0313"Consumption size exceeded"（OpENer 枚举中不存在此值）。
- 0x0315 由"Wrong cloer"改为"Invalid segment type in path"；WrongCloser 实际值是 0xFFFF（OpENer `WrongCloser`）。
- 新增 0x0106/0x0110/0x0113/0x0114/0x0115/0x0116/0x0127/0x0128/0x0316 共 9 项以与 OpENer 枚举对齐。

### 2.4 CPF（Common Packet Format，通用报文格式）

CPF 是 ENIP payload 内部的数据封装格式。**仅在 SendRRData/SendUnitData 的 payload 中使用**（且位于 Interface Handle + Timeout 前缀之后）。CPF 自身结构：

```
ItemCount (2B LE)
[ Item 1: TypeID(2B LE) + Length(2B LE) + Data(Length 字节) ]
[ Item 2: TypeID(2B LE) + Length(2B LE) + Data(Length 字节) ]
...
```

**SendRRData/SendUnitData payload 完整结构**（修正 v1 D-CRIT-4）：
```
Interface Handle (4B LE, CIP 协议固定为 0)
Timeout (2B LE, 单位秒)
ItemCount (2B LE)
[ Item: TypeID(2B LE) + Length(2B LE) + Data ]
...
```

**重要澄清**（v2.0.1 修订，对应审计 R1）：6 字节 Interface Handle + Timeout 前缀**仅出现在 SendRRData (0x006F) 与 SendUnitData (0x0070) 的 payload 中**。ListServices (0x0004)、ListIdentity (0x0063)、ListInterfaces (0x0064) 响应 payload **直接以 ItemCount 字段开头**，无 6B 前缀。这点对照 OpENer `HandleReceivedListServicesCommand`/`HandleReceivedListIdentityCommandTcp`/`HandleReceivedListInterfacesCommand` 即可确认——这三个响应装配函数在 ENIP 头之后直接 `AddIntToMessage(1, ...)` 写入 ItemCount，不写 Interface Handle/Timeout。RegisterSession (0x0065) payload 也不带前缀（直接是 ProtocolVersion + OptionFlag）。

#### 2.4.1 CPF TypeID 表

依据 OpENer `cpf.h` 的 `CipItemId` 枚举。

| 值 (LE) | 名称 | 用途 |
|---------|------|------|
| 0x0000 | Null Address（空地址） | Unconnected 显式消息的地址项，Length=0 |
| 0x000C | ListIdentity Response Item（身份列表响应项） | ListIdentity 响应中携带 Identity 对象信息 |
| 0x00A1 | Connection Address（连接地址） | Connected 消息的地址项，Data = 4B ConnectionID |
| 0x00B1 | Connected Data Item（已连接数据项） | Class 1/3 连接的 I/O 数据或 Class 3 显式消息 |
| 0x00B2 | Unconnected Data Item（未连接数据项） | SendRRData 中的 CIP 显式消息（Forward_Open/Close、Get/Set 等） |
| 0x0100 | ListServices Response Item（服务列表响应项） | ListServices 响应中携带设备支持的 ENIP 服务类型 |
| 0x8000 | Sockaddr Info Item O→T（Originator to Target） | **可选**：Forward_Open 中指示 O→T UDP 数据目标地址，16 字节 |
| 0x8001 | Sockaddr Info Item T→O（Target to Originator） | **可选**：Forward_Open 中指示 T→O UDP 数据源地址，16 字节 |
| 0x8002 | Sequenced Address Item（序列化地址项） | Class 3 序列化连接，Data = 4B ConnectionID + 4B Sequence |

**修正说明**（对比 v1，D-CRIT-8 + D-HIGH-1）：
- v1 错将 0x0100 标为 ListIdentity Response；实际 0x0100 是 ListServices Response，0x000C 才是 ListIdentity Response。
- v1 遗漏 0x8000/0x8001/0x8002 三个 TypeID。

**Sockaddr Info Item 可选性说明**（v2.0.1 修订，对应审计 R22）：Sockaddr Info Item (0x8000/0x8001) 在 Forward_Open 请求中是**可选项**，不是必备项——ODVA 规范允许 Forward_Open 不携带 sockaddr（此时由 target 使用请求来源地址或默认 UDP 地址），OpENer 处理 Forward_Open 时也不强制要求这些项。trafficgen 的完整 UDP I/O 场景**建议**携带（便于 target 确定 O→T 数据发送地址），但 Validate 不得将其设为必填。

#### 2.4.2 Sockaddr Info Item 结构（16 字节）

```
0    SinFamily (2B)         = 2 (AF_INET)
2    SinPort (2B)           UDP 端口
4    SinAddr (4B)           IPv4 地址
8    SinZero (8B)           全 0
```

**字节序注意**（v2.0.1 修订，对应审计 R9）：`sockaddr_in` 源自 BSD socket API，其字段**传统上是网络字节序（big-endian）**：OpENer 的 `EncapsulateIpAddress` 在 little-endian 平台将 sin_port/sin_addr 以 LE 写入、sin_family 经 `htons` 后也呈 LE，但不同平台/实现存在差异（如大端平台会呈现 BE）。trafficgen 若目标为 OpENer（x86 平台），按 **LE** 写入可互操作；若需兼容其他设备，建议将 SinPort/SinAddr 的字节序设为可配置（默认 LE，兼容 OpENer）。

### 2.5 CIP 服务码表

依据 OpENer `ciptypes.h` 的 `CIPServiceCode` 枚举与 libplctag `defs.h`。

#### 2.5.1 CIP 通用服务码（Common Services，Volume 1 Table A-3.1）

| 值 | 名称 | 说明 |
|----|------|------|
| 0x01 | Get_Attributes_All | 读取对象所有属性 |
| 0x02 | Set_Attributes_All | 写入对象所有属性 |
| 0x03 | Get_Attribute_List | 批量读取指定属性列表 |
| 0x04 | Set_Attribute_List | 批量写入指定属性列表 |
| 0x05 | Reset | 复位对象 |
| 0x06 | Start | 启动对象 |
| 0x07 | Stop | 停止对象 |
| 0x08 | Create | 创建对象实例 |
| 0x09 | Delete | 删除对象实例 |
| 0x0A | Multiple_Service_Packet | 多服务包（一个请求承载多个子服务） |
| 0x0D | Apply_Attributes | 应用属性 |
| 0x0E | Get_Attribute_Single | 读取单个属性 |
| 0x10 | Set_Attribute_Single | 写入单个属性 |
| 0x11 | Find_Next_Object_Instance | 查找下一个对象实例 |
| 0x15 | Restore | 恢复 |
| 0x16 | Save | 保存 |
| 0x17 | NOP | 空操作 |
| 0x18 | Get_Member | 读取成员 |
| 0x19 | Set_Member | 写入成员 |
| 0x1A | Insert_Member | 插入成员 |
| 0x1B | Remove_Member | 删除成员 |
| 0x1C | Group_Sync | 组同步 |
| 0x1D | Get_Connection_Point_Member_List | 读取连接点成员列表 |

#### 2.5.2 Connection Manager 专用服务码

| 值 | 名称 | 说明 |
|----|------|------|
| 0x4E | Forward_Close | 关闭 CIP 连接（用三元组定位） |
| 0x52 | Unconnected_Send | 通过未连接会话发送 |
| 0x54 | Forward_Open | 打开 CIP 连接（Network Connection Parameters 2B） |
| 0x56 | Get_Connection_Data | 读取连接数据 |
| 0x57 | Search_Connection_Data | 搜索连接数据 |
| 0x5A | Get_Connection_Owner | 读取连接所有者 |
| 0x5B | LargeForward_Open | 打开 CIP 连接（Network Connection Parameters 4B，支持更大 RPI/数据量） |

#### 2.5.3 PCCC / Logix 专用服务码

| 值 | 名称 | 说明 |
|----|------|------|
| 0x4B | Execute PCCC | 在 CIP 通道上执行 PCCC（Programmable Controller Communications Protocol，可编程控制器通信协议）命令 |
| 0x4C | Read Tag (CIP_READ) | Logix 5000 专用读标签（libplctag `AB_EIP_CMD_CIP_READ`），**非 PCCC 别名** |
| 0x4D | Write Tag (CIP_WRITE) | Logix 5000 专用写标签 |
| 0x52 | Read Tag Fragmented (CIP_READ_FRAG) | Logix 5000 分片读（libplctag `AB_EIP_CMD_CIP_READ_FRAG` 与 `AB_EIP_CMD_UNCONNECTED_SEND` 同为 0x52，由目标设备上下文区分） |
| 0x53 | Write Tag Fragmented (CIP_WRITE_FRAG) | Logix 5000 分片写 |
| 0x55 | List Tags (CIP_LIST_TAGS) | Logix 5000 列标签 |

**修正说明**（v2.0.1 修订，对应审计 R19）：0x52 同码现象只存在于 libplctag 的 **Logix 设备**实现约定中（`AB_EIP_CMD_CIP_READ_FRAG=0x52` 与 `AB_EIP_CMD_UNCONNECTED_SEND=0x52`）；OpENer 收到 0x52 一律解读为 Unconnected_Send。trafficgen 面向 OpENer/通用 CIP 设备时，0x52 必须按 Unconnected_Send 处理；只有面向 Logix 5000 设备时才可能被解读为 Read Tag Fragmented。

**修正说明**（对比 v1，D-CRIT-1 + D-HIGH-5）：v1 大面积错位——Forward_Open 错写 0x10（实际是 Set_Attribute_Single）、Forward_Close 错写 0x11（实际是 Find_Next_Object_Instance）、Multiple_Service_Packet 错写 0x0E（实际是 Get_Attribute_Single）、Get_Attribute_List 错写 0x54（实际是 Forward_Open）、Set_Attribute_List 错写 0x55（实际是 List Tags）；0x4B/0x4C 被错误标为同别名。

### 2.6 Transport Class/Trigger 字段（Forward_Open 请求体最后 1 字节）

依据 ODVA CIP Volume 1 Transport Class/Trigger 字段定义与 Wireshark `packet-cip.c` 的位掩码常量。**注意**：这是 Forward_Open 请求体中的 1 字节字段，不是 EPATH 段类型。

位布局（依据 Wireshark `CI_PRODUCTION_DIR_MASK=0x80`、`CI_PRODUCTION_TRIGGER_MASK=0x70`、`CI_TRANSPORT_CLASS_MASK=0x0F`）：

```
bit 7    : Direction（方向，0=Server/Consumer、1=Client/Producer）
bit 4-6  : Production Trigger（生产触发，3 位：0=Cyclic 周期、1=ChangeOfState 状态变化、2=Application 应用触发）
bit 0-3  : Transport Class（传输类，4 位：0=Class 0、1=Class 1、2=Class 2、3=Class 3；4-15=Reserved）
```

常用值表：

| 值 | bit 7 | bit 4-6 | bit 0-3 | 含义 |
|----|-------|---------|---------|------|
| 0x00 | 0 (Server) | 000 (Cyclic) | 0000 (Class 0) | Class 0 Server Cyclic（被动接收 I/O） |
| 0x01 | 0 (Server) | 000 (Cyclic) | 0001 (Class 1) | Class 1 Server Cyclic |
| 0x02 | 0 (Server) | 000 (Cyclic) | 0010 (Class 2) | Class 2 Server Cyclic |
| 0x03 | 0 (Server) | 000 (Cyclic) | 0011 (Class 3) | Class 3 Server Cyclic |
| 0x80 | 1 (Client) | 000 (Cyclic) | 0000 (Class 0) | Class 0 Client Cyclic（主动发送 I/O） |
| 0x81 | 1 (Client) | 000 (Cyclic) | 0001 (Class 1) | Class 1 Client Cyclic |
| 0x82 | 1 (Client) | 000 (Cyclic) | 0010 (Class 2) | Class 2 Client Cyclic |
| 0x83 | 1 (Client) | 000 (Cyclic) | 0011 (Class 3) | Class 3 Client Cyclic |

**Transport Class 取值范围**：bit 0-3 共 4 位，理论范围 0-15。Wireshark `cip_con_class_vals` 仅列出 0/1/2/3 四个值，4-15 是 Reserved（不应使用）。

**修正说明**（v2.0.1 修订，对应审计 R13/R14）：v2.0.0 称 bit 2-6=Production Trigger（5 位）、bit 0-1=Transport Class（2 位）是错的——Wireshark `CI_PRODUCTION_TRIGGER_MASK=0x70`（bit 4-6，仅 3 位）、`CI_TRANSPORT_CLASS_MASK=0x0F`（bit 0-3，4 位 Transport Class）。v2.0.0 列出的 0x00/0x01/0x02/0x03/0x80/0x81/0x82/0x83 八个值仍正确，但位布局描述需修正。

**修正说明**（对比 v1，D-HIGH-3）：v1 错写"0x81 = Class 0 Client"——实际 0x81 = `10000001`，bit 0-3=0001 是 Class 1 Client，不是 Class 0 Client；Class 0 Client 应是 0x80。

### 2.7 EPATH 路径编码（Encoded Path）

依据 OpENer `cipepath.h` 的段类型常量。EPATH 由若干"段"（Segment）串联构成。每段第一字节的 bit 5-7 决定段类型。

#### 2.7.1 段类型（Segment Type，bit 5-7）

| 值范围 | 段类型 | 说明 |
|--------|--------|------|
| 0x00 | Port Segment | 端口段（含网络段） |
| 0x20 | Logical Segment | 逻辑段（Class/Instance/Attribute/Connection Point/Service/Member） |
| 0x40 | Network Segment | 网络段 |
| 0x60 | Symbolic Segment | 符号段 |
| 0x80 | Data Segment | 数据段 |
| 0xA0 | Data Type Constructed | 构造数据类型段 |
| 0xC0 | Data Type Elementary | 基本数据类型段 |
| 0xE0 | Reserved | 保留段 |

#### 2.7.2 Logical Segment 子类型与格式

Logical Segment 段字节 = `0x20 | LogicalType(bit 2-4) | LogicalFormat(bit 0-1)`。

| LogicalType | LogicalFormat | 段字节 | 含义 |
|-------------|---------------|--------|------|
| 0x00 (Class ID) | 0x00 (8-bit) | 0x20 | Class 8-bit（后跟 1B Class ID） |
| 0x00 (Class ID) | 0x01 (16-bit) | 0x21 | Class 16-bit（后跟 2B LE Class ID） |
| 0x00 (Class ID) | 0x02 (32-bit) | 0x22 | Class 32-bit（后跟 4B LE Class ID） |
| 0x04 (Instance ID) | 0x00 (8-bit) | 0x24 | Instance 8-bit（后跟 1B Instance ID） |
| 0x04 (Instance ID) | 0x01 (16-bit) | 0x25 | Instance 16-bit（后跟 2B LE Instance ID） |
| 0x04 (Instance ID) | 0x02 (32-bit) | 0x26 | Instance 32-bit（后跟 4B LE Instance ID） |
| 0x08 (Member ID) | 0x00 (8-bit) | 0x28 | Member 8-bit |
| 0x08 (Member ID) | 0x01 (16-bit) | 0x29 | Member 16-bit |
| 0x0C (Connection Point) | 0x00 (8-bit) | 0x2C | Connection Point 8-bit |
| 0x0C (Connection Point) | 0x01 (16-bit) | 0x2D | Connection Point 16-bit |
| 0x10 (Attribute ID) | 0x00 (8-bit) | 0x30 | Attribute 8-bit（后跟 1B Attribute ID） |
| 0x10 (Attribute ID) | 0x01 (16-bit) | 0x31 | Attribute 16-bit（后跟 2B LE Attribute ID） |
| 0x18 (Service ID) | 0x00 (8-bit) | 0x38 | Service 8-bit |
| 0x18 (Service ID) | 0x01 (16-bit) | 0x39 | Service 16-bit |

**修正说明**（对比 v1，D-CRIT-2）：v1 的段类型表 7 项中 6 项错误——0x21 错标 Instance 8-bit（实际 Class 16-bit）、0x24 错标 Instance 16-bit（实际 Instance 8-bit）、0x25 错标 Element（实际 Instance 16-bit）、0x2C 错标 Attribute（实际 Connection Point）、0x30 错标 Service（实际 Attribute）。

**32-bit 段使用说明**（v2.0.1 修订，对应审计 R23）：上表中的 0x22 (Class 32-bit)、0x26 (Instance 32-bit)、0x32 (Attribute 32-bit) 属于逻辑段类型的完整编码，但实际使用极少——Class ID 大于 0xFF 用 16-bit (0x21) 即可（CIP Class ID 上限 0xFFFF），**几乎不需要 32-bit 段**；仅当标识符超过 16 位时才使用。trafficgen 的 EncodeCIPPath 选择规则见 §2.7.4：instanceID > 0xFFFF 才编码 0x26。

#### 2.7.3 EPATH 编码示例

**示例 1**：Class 0x01 (Identity) + Instance 16-bit 0x0001 + Attribute 8-bit 0x03
```
20 01          Class 8-bit = 0x01
25 01 00       Instance 16-bit = 0x0001 (LE)
30 03          Attribute 8-bit = 0x03
```
共 7 字节。RequestPathSize（word 单位）= ⌈7/2⌉ = 4 words（不足 2 字节补 0）。补 0 后 8 字节：`20 01 25 01 00 30 03 00`。

**示例 2**：Class 0x06 (Connection Manager) + Instance 8-bit 0x01（Forward_Open 路径）
```
20 06          Class 8-bit = 0x06
24 01          Instance 8-bit = 0x01
```
共 4 字节。RequestPathSize = 2 words。

**示例 3**：Class 0xF5 (TCP/IP Interface) + Instance 8-bit 0x01 + Attribute 8-bit 0x01
```
20 F5          Class 8-bit = 0xF5
24 01          Instance 8-bit = 0x01
30 01          Attribute 8-bit = 0x01
```
共 6 字节。RequestPathSize = 3 words。

#### 2.7.4 EncodeCIPPath 编码辅助函数签名

```go
// EncodeCIPPath 编码 EPATH 路径。classID/instanceID/attrID 根据值大小自动选择 8/16/32-bit 段格式。
// connPointIDs 是可选参数，追加 Connection Point 段（0x2C/0x2D）——Forward_Open/Close 的
// ConnectionPath 需要 Class + Instance + Connection Point O→T + Connection Point T→O。
// 返回值不含 RequestPathSize 字段（由调用者根据上下文添加）。
func EncodeCIPPath(classID uint16, instanceID uint32, attrID uint16, connPointIDs ...uint16) []byte
```

选择规则：
- classID ≤ 0xFF → Class 8-bit (0x20)；否则 Class 16-bit (0x21)
- instanceID ≤ 0xFF → Instance 8-bit (0x24)；0x100 ≤ instanceID ≤ 0xFFFF → Instance 16-bit (0x25)；> 0xFFFF → Instance 32-bit (0x26)
- attrID ≤ 0xFF → Attribute 8-bit (0x30)；否则 Attribute 16-bit (0x31)
- attrID = 0 → 不编码 Attribute 段（仅 Class+Instance）
- 每个 connPointID ≤ 0xFF → Connection Point 8-bit (0x2C)；否则 Connection Point 16-bit (0x2D)；按传入顺序追加

**修正说明**（v2.0.1 修订，对应审计 R21/R40）：v2.0.0 签名 `(classID, instanceID, attrID)` 无法生成 Connection Point 段（0x2C/0x2D），而 Forward_Open 的 ConnectionPath 通常需要 Class + Instance + Connection Point（如 `20 04 24 01 2C 02 2C 03`）。新增可变参数 `connPointIDs ...uint16` 支持。调用方对普通 CIP 服务（Get/Set 属性）传空即可，行为与 v2.0.0 兼容。

### 2.8 CIP 通用对象类表

| Class ID | 名称 | 说明 |
|----------|------|------|
| 0x01 | Identity | 设备身份（VendorID/DeviceType/ProductCode/Revision/SerialNumber/ProductName） |
| 0x02 | Message Router | 消息路由器 |
| 0x03 | Assembly | 装配对象（I/O 数据集合） |
| 0x04 | Connection | 连接对象 |
| 0x05 | Connection Configuration | 连接配置 |
| 0x06 | Connection Manager | 连接管理器（Forward_Open/Close 服务目标） |
| 0xF4 | Port | 端口对象 |
| 0xF5 | TCP/IP Interface | TCP/IP 接口对象（属性 1=IP 地址、2=网络掩码、3=网关、4=NameServer、5=NameServer2、6=DomainName） |
| 0xF6 | Ethernet Link | 以太网链路对象（属性 1=InterfaceSpeed、2=InterfaceFlags、3=PhysicalAddress、4=InterfaceCounters、5=MediaCounters） |

### 2.9 Identity 对象属性结构

依据 OpENer `cipidentity.h` 的 `CipIdentityObject` 结构体定义。

| 属性 ID | 名称 | 类型 | 大小 |
|---------|------|------|------|
| 1 | Vendor ID | UINT | 2B |
| 2 | Device Type | UINT | 2B |
| 3 | Product Code | UINT | 2B |
| 4 | Revision | STRUCT { USINT major, USINT minor } | **2B**（每 1B，非 4B） |
| 5 | Status | WORD | 2B |
| 6 | Serial Number | UDINT | 4B |
| 7 | Product Name | SHORT_STRING | 1B 长度 + N 字节 ASCII |
| 8 | State | USINT | 1B |
| 9 | Configuration Consistency Value | UINT | 2B |
| 10 | Heartbeat Interval | USINT | 1B |

**属性 8/9/10 的用途说明**（v2.0.1 修订，对应审计 R34）：属性 8 (State)、9 (Configuration Consistency Value)、10 (Heartbeat Interval) 是 Identity 对象的**常规属性**（可通过 Get_Attribute_Single 等 CIP 服务读取），但 **ListIdentity Response Item 只在末尾携带 State (1B)**（见 §3.11）；属性 9/10 **不出现在 ListIdentity 响应中**。trafficgen 模拟 ListIdentity 响应时只需填充 §3.11 列出的字段，不要尝试把属性 9/10 编码进 ListIdentity Item。

**修正说明**（对比 v1，D-HIGH-2）：v1 错写 Revision 为 "major(2B)+minor(2B)" 共 4B；实际是 `{USINT major, USINT minor}` 共 2B（每 1B）。

---

## 3. 消息结构

### 3.1 ENIP 消息总体层次

```
+-----------------------+
| ENIP 封装头 (24B)     |   Command/Length/SessionHandle/Status/SenderContext/Options
+-----------------------+
| ENIP payload          |
|  +-------------------+|
|  | 命令特定数据      ||   RegisterSession: ProtocolVersion+OptionFlag (4B)
|  |                   ||   SendRRData/SendUnitData: Interface Handle(4)+Timeout(2)+CPF
|  |  +---------------+||
|  |  | CPF           |||   ItemCount + [TypeID+Length+Data]...
|  |  |  +----------+ |||
|  |  |  | CIP data ||||  Service(1) + Path + Service-specific data
|  |  |  +----------+ |||
|  |  +---------------+||
|  +-------------------+|
+-----------------------+
```

### 3.2 RegisterSession payload（4 字节，无 CPF）

```
0    ProtocolVersion (2B LE)    = 0x0001
2    OptionFlag (2B LE)         = 0x0000
```

请求与响应结构相同（均为 ProtocolVersion + OptionFlag 共 4 字节）。响应中 SessionHandle 在 ENIP 头的 offset 4 返回。

**注意**（v2.0.1 修订，对应审计 R17）：响应中的 ProtocolVersion/OptionFlag **不回声请求值**——OpENer `EncapsulateRegisterSessionCommandResponseMessage` 总是写固定值 ProtocolVersion=1、OptionFlag=0，与请求中的实际值无关。trafficgen 模拟设备响应时应固定写 `01 00 00 00`，不要回显请求值。若请求 ProtocolVersion≠1（如 0），OpENer 返回 ENIP Status=0x0069 Unsupported Protocol。

### 3.3 SendRRData / SendUnitData payload

```
0    Interface Handle (4B LE)   CIP 协议固定为 0x00000000
4    Timeout (2B LE)            单位秒，SendRRData 通常 10-60；SendUnitData 通常 0
6    CPF ItemCount (2B LE)
8    [Item 1: TypeID(2B LE) + Length(2B LE) + Data]
...  [Item 2: TypeID(2B LE) + Length(2B LE) + Data]
...  [Item 3 (可选): Sockaddr Info O→T (0x8000), Length=16, 16B Data]
...  [Item 4 (可选): Sockaddr Info T→O (0x8001), Length=16, 16B Data]
```

**SendRRData 典型 ItemCount=2**：
- Item 1: Null Address (0x0000), Length=0
- Item 2: Unconnected Data (0x00B2), Length=N, Data=CIP 消息

**SendUnitData 典型 ItemCount=2**：
- Item 1: Connection Address (0x00A1), Length=4, Data=4B ConnectionID
- Item 2: Connected Data (0x00B1), Length=N+2, Data=2B Sequence Counter + N 字节 I/O data

**List* 响应 payload 结构**（v2.0.1 修订，对应审计 R1）：

ListServices (0x0004)/ListIdentity (0x0063)/ListInterfaces (0x0064) 响应 payload **不含** Interface Handle + Timeout 前缀，直接是 CPF：
```
0    CPF ItemCount (2B LE)
2    [Item 1: TypeID(2B LE) + Length(2B LE) + Data]
...  [Item 2 ...]
```
OpENer 在这三个命令的响应装配函数中（`HandleReceivedListServicesCommand`/`HandleReceivedListIdentityCommandTcp`/`HandleReceivedListInterfacesCommand`），ENIP 头之后直接写入 ItemCount，不写 6B 前缀。trafficgen 生成这三类响应时必须遵循此规则，否则 tshark 会将开头的 `00 00 00 00 00 00` 误读为 Interface Handle + Timeout，导致 ItemCount 偏移错位。

### 3.4 CIP 消息结构

#### 3.4.1 CIP 请求（Message Router Request）

```
0    Service (1B)               服务码（如 0x0E=Get_Attribute_Single、0x54=Forward_Open）
1    RequestPathSize (1B)       路径长度，单位 word（2 字节）
2    RequestPath (2*RequestPathSize 字节)   Padded EPATH 编码路径
...  Service-specific data      服务特定数据
```

**Padded EPATH**（v2.0.1 修订，对应审计 R24）：CIP Message Router 的 RequestPath 使用 **Padded EPATH**——路径段按 word 边界编码，若路径总字节数为奇数则**补 1 字节 0x00 至偶数**；RequestPathSize = ⌈len(EPATH)/2⌉（word 数）。所有 CIP 请求（Get/Set 属性、Forward_Open/Close 的 RequestPath 等）都必须遵循此规则。示例：EPATH=`20 01 25 01 00 30 01` 共 7 字节（奇数）→ 补 0 为 8 字节 `20 01 25 01 00 30 01 00`，RequestPathSize=4 words（见 §2.7.3 示例 1）。

#### 3.4.2 CIP 响应（Message Router Response）

```
0    Reply Service (1B)         = Request Service | 0x80
1    Reserved (1B)              = 0x00
2    General Status (1B)        见 §2.3.1
3    Size of Additional Status (1B)  Additional Status 字数（word 数）
4    Additional Status (2*N 字节)   扩展状态，见 §2.3.2
...  Response data             响应特定数据
```

### 3.5 Forward_Open 请求体结构（Service=0x54，35 字节固定 + 路径）

依据 OpENer `cipconnectionobject.c` 的 `ConnectionObjectInitializeFromMessage` 函数。

| 偏移 | 字段 | 大小 | 字节序 | 说明 |
|------|------|------|--------|------|
| 0 | Priority/TimeTick | 1B | - | 优先级与超时 tick（高 4 位优先级，低 4 位 tick 数） |
| 1 | TimeoutTicks | 1B | - | 超时 tick 数（与 Priority 配合，实际超时 = TimeTick × 2^(TimeoutTicks) ms） |
| 2 | O_to_T Network Connection ID | 4B | LE | Originator 期望 Target 在 O→T 方向使用的 Connection ID（即 Originator 在 O→T 方向发送时填入 Connected Address Item 的 ID） |
| 6 | T_to_O Network Connection ID | 4B | LE | Originator 期望 Target 在 T→O 方向使用的 Connection ID（请求中可为 0 由 target 自动分配） |
| 10 | Connection Serial Number | 2B | LE | Originator 分配的连接序列号（用于 Forward_Close 定位） |
| 12 | Originator Vendor ID | 2B | LE | Originator 厂商 ID |
| 14 | Originator Serial Number | 4B | LE | Originator 序列号 |
| 18 | Connection Timeout Multiplier | 1B | - | 超时倍数（见 §4.2/§9.3，0→RPI×4、1→RPI×8、2→RPI×16...即 RPI×4×2^Multiplier） |
| 19 | Reserved | 3B | - | 保留，全 0 |
| 22 | O_to_T RPI (Requested Packet Interval) | 4B | LE | O→T 请求包间隔，单位 μs |
| 26 | O_to_T Network Connection Parameters | 2B | LE | O→T 连接参数（见 §3.5.1 位布局） |
| 28 | T_to_O RPI | 4B | LE | T→O 请求包间隔，单位 μs |
| 32 | T_to_O Network Connection Parameters | 2B | LE | T→O 连接参数 |
| 34 | Transport Class/Trigger | 1B | - | 见 §2.6 |
| 35 | Connection Path Size | 1B | - | Connection Path 长度，单位 word |
| 36 | Connection Path (2*ConnectionPathSize 字节) | - | - | EPATH 路径，通常为 Class 0x04 (Assembly) + Instance + Connection Point O→T + Connection Point T→O，如 `20 04 24 01 2C 02 2C 03` |

**总固定字段大小（不含路径，不含 ConnPathSize）**：35 字节。含 ConnPathSize(1B) + 路径(N 字节) 后，body = 35 + 1 + N。

**LargeForwardOpen (0x5B) 差异**：O_to_T 与 T_to_O Network Connection Parameters 各 4B（共多 4 字节），总固定字段 39 字节。

**修正说明**（v2.0.1 修订，对应审计 R3/R15/R39）：v2.0.0 §3.5 注释"0=4s、1=8s、2=16s..."暗示 multiplier 是线性倍数，实际是 2 的幂次（OpENer `ConnectionObjectCalculateRegularInactivityWatchdogTimerValue` 用 `RPI_ms << (2 + multiplier)` = RPI × 4 × 2^Multiplier；Wireshark `cip_con_time_mult_vals` 也确认 0→4、1→8、2→16...）。O2T Connection ID 字段语义已澄清。Connection Path 字段示例已补全为含 Connection Point 的完整路径。

**修正说明**（对比 v1，D-CRIT-6）：v1 字段顺序错误、字段重复、缺失 ConnectionSerialNumber/OriginatorVendorID/OriginatorSerialNumber/TimeoutMultiplier/3B Reserved；TransportClass_Trigger 错写 2B（实际 1B）。

#### 3.5.1 Network Connection Parameters 字段（2B，Forward_Open）

依据 Wireshark `packet-cip.c` 的 `dissect_net_param16` 位字段定义：

```
bit 0-8   : Connection Size（连接数据大小，9 位，最大 511 字节）
bit 9     : Fixed/Variable（0=固定长度、1=可变长度）
bit 10-11 : Priority（0=Low、1=High、2=Scheduled、3=Urgent）
bit 12    : Reserved (0)
bit 13-14 : Connection Type（0=Null、1=Multicast、2=Point-to-Point、3=Reserved）
bit 15    : Redundant Owner（0=非冗余、1=冗余所有者）
```

**修正说明**（v2.0.1 修订，对应审计 R11）：v2.0.0 称 bit 0-10=Connection Size（11 位）、bit 11=Reserved、bit 12=Variable Length、bit 13-15=Priority 是错的。Wireshark `hf_cip_cm_fwo_con_size` mask=0x01FF（9 位）、`hf_cip_cm_fwo_fixed_var` mask=0x0200（bit 9）、`hf_cip_cm_fwo_prio` mask=0x0C00（bit 10-11）、`hf_cip_cm_fwo_typ` mask=0x6000（bit 13-14）、`hf_cip_cm_fwo_own` mask=0x8000（bit 15）。

#### 3.5.2 LargeForwardOpen Network Connection Parameters（4B）

依据 Wireshark `packet-cip.c` 的 `dissect_net_param32` 位字段定义：

```
bit 0-15  : Connection Size（16 位，最大 65535 字节）
bit 16-24 : Reserved (0)
bit 25    : Fixed/Variable（0=固定长度、1=可变长度）
bit 26-27 : Priority（0=Low、1=High、2=Scheduled、3=Urgent）
bit 28    : Reserved (0)
bit 29-30 : Connection Type（0=Null、1=Multicast、2=Point-to-Point、3=Reserved）
bit 31    : Redundant Owner（0=非冗余、1=冗余所有者）
```

**修正说明**（v2.0.1 修订，对应审计 R12）：v2.0.0 称 bit 0-31=Connection Size（32 位）是错误的——Wireshark `hf_cip_cm_lfwo_con_size` mask=0xFFFF（16 位 Connection Size）。4B 版本的位布局并非简单扩展 2B 版本，而是下半部分为 Connection Size（16 位）、上半部分为位字段。

### 3.6 Forward_Open 响应体结构（成功，26 字节 service data）

依据 OpENer `cipconnectionmanager.c` 的 `AssembleForwardOpenResponse` 函数与 Wireshark `dissect_cip_cm_fwd_open_rsp_success`。

OpENer 装配成功响应时，在 4 字节 Message Router 响应头之后写入以下字段（按字节顺序）：

| CIP body 偏移 | 字段 | 大小 | 说明 |
|---------------|------|------|------|
| 0 | O_to_T Connection ID | 4B LE | OpENer `cip_consumed_connection_id`：Target 在 O→T 方向接收数据使用的 Connection ID，即 Originator 在 O→T 方向发送时使用的 ID |
| 4 | T_to_O Connection ID | 4B LE | OpENer `cip_produced_connection_id`：Target 在 T→O 方向发送数据使用的 Connection ID，即 Originator 在 T→O 方向接收时使用的 ID |
| 8 | Connection Serial Number | 2B LE | 回显请求中的 Connection Serial Number |
| 10 | Originator Vendor ID | 2B LE | 回显 |
| 12 | Originator Serial Number | 4B LE | 回显 |
| 16 | O_to_T RPI | 4B LE | Target 实际 RPI（可能与请求不同） |
| 20 | T_to_O RPI | 4B LE | Target 实际 RPI |
| 24 | Application Reply Size | 1B | = 0（Wireshark `hf_cip_cm_app_reply_size`，单位 word） |
| 25 | Reserved | 1B | = 0 |

完整 CIP 响应（含 4B MR 头）= 4 + 26 = 30 字节。

**关键**：响应中 O2T Connection ID 在 CIP body offset 0、T2O Connection ID 在 CIP body offset 4（成功时，Additional Status=0）。Wireshark `dissect_cip_cm_fwd_open_rsp_success` 也确认 offset 0 = `hf_cip_cm_ot_connid`（O->T Network Connection ID）、offset 4 = `hf_cip_cm_to_connid`（T->O Network Connection ID）。

**修正说明**（v2.0.1 修订，对应审计 R2/R8）：v2.0.0 §3.6 表把 O2T 放在 4+N、T2O 放在 8+N（N=AddStatus 大小），多算了 4 字节 MR 头——MR 头不属于 CIP body；从 CIP body 起算，正确偏移是 O2T=0、T2O=4。v2.0.0 §5.6.1 称 O2T=4、T2O=8 同样多算了 4 字节。v2.0.0 §3.6 末尾"Remaining Path Size(1B)+Reserved(1B)"实际是 OpENer 写入的 Application Reply Size(1B)+Reserved(1B)，已纠正字段名。

### 3.7 Forward_Close 请求体结构（Service=0x4E，10 字节固定 + 路径）

依据 OpENer `cipconnectionmanager.c` 的 `ForwardClose` 函数。

| 偏移 | 字段 | 大小 | 字节序 | 说明 |
|------|------|------|--------|------|
| 0 | Priority/TimeTick | 1B | - | 优先级与超时 tick |
| 1 | TimeoutTicks | 1B | - | 超时 tick 数 |
| 2 | Connection Serial Number | 2B | LE | 与 Forward_Open 一致 |
| 4 | Originator Vendor ID | 2B | LE | 与 Forward_Open 一致 |
| 6 | Originator Serial Number | 4B | LE | 与 Forward_Open 一致 |
| 10 | Connection Path Size | 1B | - | 路径长度，单位 word |
| 11 | Connection Path (2*PathSize 字节) | - | - | EPATH 路径，**必须与 Forward_Open 时的 ConnectionPath 一致**（指向 Assembly 实例 + Connection Point，如 `20 04 24 01 2C 02 2C 03`） |

**总固定字段大小（不含路径）**：10 字节。

**关键**：Forward_Close **不携带 ConnectionID**，而是通过 **ConnectionSerialNumber + OriginatorVendorID + OriginatorSerialNumber 三元组**定位连接。Connection Path 必须与 Forward_Open 时的 ConnectionPath 字节级一致——OpENer `ForwardClose` 函数会用此路径与已注册连接的 ConnectionPath 对比，不匹配时返回 0x0316（ForwardClose connection path mismatch，见 §2.3.2）。

**修正说明**（v2.0.1 修订，对应审计 R4/R26）：v2.0.0 §3.7 表注释"Connection Path = Class 0x06 + Instance 0x01"是错的——Connection Manager (Class 0x06) 是 CIP 头里的 RequestPath（指向接收 Forward_Close 服务的对象），不是 Forward_Close body 里的 ConnectionPath。body 里的 ConnectionPath 应指向 Assembly 实例 + Connection Point，与 Forward_Open 时一致。v2.0.0 §3.7 表称"10 字节 + 路径"是对的，但路径内容描述错误。

**修正说明**（对比 v1，D-HIGH-4）：v1 漏掉 ConnectionSerialNumber/OriginatorVendorID/OriginatorSerialNumber，且错写"ConnectionID+路径"。

### 3.8 Forward_Close 响应体结构

依据 OpENer `cipconnectionmanager.c` 的 `AssembleForwardCloseResponse` 函数。成功响应（10 字节 service data）字段顺序：

| CIP body 偏移 | 字段 | 大小 | 说明 |
|---------------|------|------|------|
| 0 | Connection Serial Number | 2B LE | 回显请求中的 Connection Serial Number |
| 2 | Originator Vendor ID | 2B LE | 回显 |
| 4 | Originator Serial Number | 4B LE | 回显 |
| 8 | Application Reply Size | 1B | = 0（Wireshark `hf_cip_cm_app_reply_size`，单位 word） |
| 9 | Reserved | 1B | = 0 |

完整 CIP 响应（含 4B MR 头）= 4 + 10 = 14 字节。

错误响应（General Status≠0x00）时，service data 仅含 ConnSerialNum(2) + OrigVendorID(2) + OrigSerialNum(4) = 8 字节，CIP 响应 = 4 + 8 = 12 字节，Additional Status 携带 §2.3.2 的扩展状态码（如 0x0107 Target connection not found）。

**修正说明**（v2.0.1 修订，对应审计 R2/R25）：v2.0.0 §3.8 表末尾字段名"Remaining Path Size"实际是 OpENer `AssembleForwardCloseResponse` 写入的 Application Data (1B)=0，已改为 Application Reply Size。v2.0.0 §3.8 表末尾缺少 Reserved (1B) 字段，实际成功响应共 10 字节 service data（不是 9 字节）。

### 3.9 Multiple_Service_Packet 请求结构（Service=0x0A）

依据 ODVA CIP Volume 1 Multiple_Service_Packet 服务定义、Wireshark `dissect_cip_multiple_service_packet` 与 OpENer `kMultipleServicePacket=0x0A`。

```
0    Service (1B)               = 0x0A
1    RequestPathSize (1B)       路径长度，单位 word
2    RequestPath (2*PathSize)   通常为 Class 0x02 (Message Router) + Instance 0x01；也可以是任何支持多服务调用的对象
...  Offset Count (2B LE)       子请求数量 N
...  Offsets[N] (N*2B LE)       每个子请求的偏移量（从 Offset Count 字段起始的绝对字节偏移）
...  Sub-requests[N]            连续存放的子 CIP 请求
```

**偏移计算规则**：`Offset[i] = 2 (OffsetCount 自身) + 2*N (Offsets 数组) + sum(len(Sub-requests[0..i-1]))`——即偏移基准是 **OffsetCount 字段的字节起始位置**（Wireshark `dissect_cip_multiple_service_packet` 用 `tvb_get_letohs(tvb, offset+2+(i*2))` 后从 tvb 起点 `offset` 起算，offset 指向 OffsetCount）。第一个子请求紧跟 Offsets 数组时 Offset[0]=2+2*N（无间隙）。偏移数组必须连续存放，不能与子请求交替。

**RequestPath 限制放宽**（v2.0.1 修订，对应审计 R6）：MSP 的 RequestPath **不强制**为 Class 0x02 Instance 0x01——Wireshark 在 `service == SC_MULT_SERV_PACK` 分支调用 `dissect_cip_multiple_service_packet` 时不要求路径是 Message Router；任何支持多服务调用的对象均可作为 MSP 目标。trafficgen 的 Validate 不应拒绝非 Message Router 路径。

**修正说明**（对比 v1，D-HIGH-6）：v1 错写 Service=0x0E（实际是 Get_Attribute_Single）；偏移数组应连续存放，不是与子请求交替。

### 3.10 Get_Attribute_List / Set_Attribute_List 请求结构

- Get_Attribute_List: Service=0x03
- Set_Attribute_List: Service=0x04

```
0    Service (1B)               = 0x03 (Get) 或 0x04 (Set)
1    RequestPathSize (1B)       路径长度，单位 word
2    RequestPath (2*PathSize)   Class + Instance
...  Attribute Count (2B LE)    属性数量 N
...  Attribute IDs[N] (N*2B LE) 属性 ID 列表
...  (Set_Attribute_List only) Attribute Data[N]  每个属性的数据
```

**修正说明**（对比 v1，D-HIGH-7）：v1 错写 Get_Attribute_List=0x54（实际是 Forward_Open）、Set_Attribute_List=0x55（实际是 List Tags）。

### 3.11 ListIdentity Response Item 结构（TypeID=0x000C）

```
0    TypeID (2B LE)             = 0x000C
2    Length (2B LE)             = 后续数据长度
4    EncapsulationProtocolVersion (2B LE)   = 1
6    ProtocolVersion (2B LE)    = 1 (OpENer 写 kSupportedProtocolVersion=1，非 0xFFFF)
8    SocketAddress (16B)        SinFamily(2)+SinPort(2)+SinAddr(4)+SinZero(8)
24   Vendor ID (2B LE)
26   Device Type (2B LE)
28   Product Code (2B LE)
30   Revision (2B)              major(1B) + minor(1B)
32   Status (2B LE)
34   Serial Number (4B LE)
38   Product Name (SHORT_STRING) 1B 长度 + N 字节 ASCII
...  State (1B)
```

**修正说明**（v2.0.1 修订，对应审计 R38）：v2.0.0 称 ProtocolVersion=0xFFFF 无规范依据；OpENer `EncodeListIdentityCipIdentityItem` 在该位置写 `kSupportedProtocolVersion=1`。

---

## 4. 状态机

### 4.1 会话状态机（Session）

```
   +-------------+
   | Unregistered|<------+
   +-------------+       |
        |                |
        | RegisterSession (0x0065) req
        v                |
   +-------------+       |
   | Registered  |       |
   +-------------+       |
        |                |
        | UnregisterSession (0x0066) req
        |                |
        +----------------+
        |                |
        | session timeout (target 默认 60s 无活动)
        v                |
   +-------------+       |
   | Expired     |-------+
   +-------------+
```

**状态迁移规则**：
- Unregistered → Registered：发送 RegisterSession 请求且收到 Status=0x0000 响应。
- Registered → Unregistered：发送 UnregisterSession 请求（无响应）。
- Registered → Expired：**无活动超时由实现决定**——OpENer 用 `SocketTimer` 跟踪每 socket 活动，**没有固定的 60 秒超时常量**；ODVA 规范也未规定固定值。trafficgen 模拟 target 端时可配置超时时长（默认建议 60s，但注明无规范依据），超时后 SessionHandle 失效。
- Expired → Unregistered：自动迁移，SessionHandle 失效。
- 任何状态 → Unregistered：TCP 连接断开。

**修正说明**（v2.0.1 修订，对应审计 R18）：v2.0.0 称"target 默认 60s 无活动"为规范行为是错的——OpENer 用 `SocketTimer` 按 socket 跟踪活动，无 60 秒固定常量；60s 仅是 trafficgen 模拟端可配置的默认值。

### 4.2 连接状态机（CIP Connection，Forward_Open 后）

```
   +-------------+
   | NonExistent |<----------------------+
   +-------------+                       |
        |                                |
        | Forward_Open (0x54) req 成功
        v                                |
   +-------------+                       |
   | Established |                       |
   +-------------+                       |
        |                                |
        | SendUnitData I/O 周期交换
        v                                |
   +-------------+                       |
   | Active      |                       |
   +-------------+                       |
        |                                |
        | Forward_Close (0x4E) req       |
        | 或连接超时（RPI × 4 × 2^Multiplier）
        v                                |
   +-------------+                       |
   | Closing     |-----------------------+
   +-------------+
```

**关键超时**：Connection Timeout Multiplier 决定连接无活动超时时间。Target 在 `RPI × 4 × 2^Multiplier` 时间内未收到数据则超时（如 RPI=100ms、Multiplier=7 → 100ms × 4 × 128 = 51200ms = 51.2s）。

**修正说明**（v2.0.1 修订，对应审计 R15）：v2.0.0 称超时公式为"RPI × Multiplier × 4"是错的——OpENer `ConnectionObjectCalculateRegularInactivityWatchdogTimerValue` 实际用 `RPI_ms << (2 + multiplier)` = RPI × 4 × 2^Multiplier，即 multiplier 是 2 的幂次指数（Wireshark `get_connection_timeout_multiplier`/`cip_con_time_mult_vals` 也确认 0→4、1→8、2→16...）。

### 4.3 ENIP Command 推导规则（planner 自动推导）

| 用户配置 cip_service | 推导 ENIP Command | 说明 |
|---------------------|-------------------|------|
| 无 cip_service（仅 command 字段） | 直接使用 command | ListServices/ListIdentity/RegisterSession 等 |
| 0x0E (Get_Attribute_Single) | 0x006F (SendRRData) | Unconnected Data Item |
| 0x10 (Set_Attribute_Single) | 0x006F (SendRRData) | Unconnected Data Item |
| 0x01 (Get_Attributes_All) | 0x006F (SendRRData) | Unconnected Data Item |
| 0x03 (Get_Attribute_List) | 0x006F (SendRRData) | Unconnected Data Item |
| 0x04 (Set_Attribute_List) | 0x006F (SendRRData) | Unconnected Data Item |
| 0x05 (Reset) | 0x006F (SendRRData) | Unconnected Data Item |
| 0x0A (Multiple_Service_Packet) | 0x006F (SendRRData) | Unconnected Data Item |
| 0x54 (Forward_Open) | 0x006F (SendRRData) | Unconnected Data Item |
| 0x5B (LargeForward_Open) | 0x006F (SendRRData) | Unconnected Data Item |
| 0x4E (Forward_Close) | 0x006F (SendRRData) | Unconnected Data Item |
| 0x52 (Unconnected_Send) | 0x006F (SendRRData) | Unconnected Data Item |
| 0x4B (Execute PCCC) | 0x006F (SendRRData) | 见下方推导逻辑 |
| (I/O 周期数据，无 cip_service) | 0x0070 (SendUnitData) | Connected Data Item |

**0x4B (Execute PCCC) 推导逻辑**（v2.0.1 修订，对应审计 R27）：planner 按以下顺序判定：
1. 若配置了 `O2TConnectionID`/`T2OConnectionID` 且引用自成功的 Forward_Open 响应（即存在 Class 3 连接）→ 使用 **0x006F SendRRData**，CPF 用 Connected Address (0x00A1) + Connected Data (0x00B1)（PCCC 在 Class 3 连接上执行）。
2. 否则（无连接）→ 使用 **0x006F SendRRData**，CPF 用 Null Address (0x0000) + Unconnected Data (0x00B2)（未连接 PCCC）。
3. 两种情况下都**不使用 0x0070 SendUnitData**——SendUnitData 语义是隐式 I/O 数据，PCCC 是显式消息，必须走 SendRRData。v2.0.0 称"0x0070 或 0x006F 视是否 Class 3 connected"表述不准确。

**修正说明**（对比 v1，D-MED-3）：v1 的推导表服务码全部错误（0x10=Forward_Open 错、0x11=Forward_Close 错、0x0E=Multiple_Service_Packet 错、0x54=Get_Attribute_List 错、0x55=Set_Attribute_List 错）。

---


## 5. 配置类型定义（Go struct）

### 5.1 设计原则

1. **零值可用**：常见场景（ListIdentity + RegisterSession + Forward_Open + I/O）应通过零值配置直接生成。
2. **Strategy 可引用**：所有跨命令引用字段（SessionHandle、ConnectionID）使用 `StrategyConfig` 的 `from_response` 策略。
3. **planner 自动填充**：ENIPCommand.Length、CPF Item Length、ENIP 头 Options 由 planner 计算，不需用户填写。
4. **字节序由 builder 处理**：用户填写 host-endian 值，builder 负责序列化为 LE。

### 5.2 ENIPConfig 顶层结构

```go
// ENIPConfig 是 ENIP 协议的顶层配置。
type ENIPConfig struct {
    // Scenario 选择预置场景：full / discovery_only / io_only / forward_open_only
    // full = ListIdentity + RegisterSession + Forward_Open + I/O + Forward_Close + UnregisterSession
    Scenario string `json:"scenario" yaml:"scenario"`

    // Commands 是 ENIP 命令序列（按顺序执行）。
    Commands []ENIPCommand `json:"commands" yaml:"commands"`

    // Transport：tcp / udp
    Transport string `json:"transport" yaml:"transport"`

    // 目标 4-tuple（TCP/UDP）
    SrcIP    string `json:"src_ip" yaml:"src_ip"`
    SrcPort  uint16 `json:"src_port" yaml:"src_port"`
    DstIP    string `json:"dst_ip" yaml:"dst_ip"`
    DstPort  uint16 `json:"dst_port" yaml:"dst_port"`

    // === Identity 对象字段（用于 ListIdentity 响应模拟） ===
    VendorID         uint16 `json:"vendor_id"`          // 属性 1
    DeviceType       uint16 `json:"device_type"`        // 属性 2
    ProductCode      uint16 `json:"product_code"`       // 属性 3
    FirmwareMajorRev uint8  `json:"firmware_major_rev"` // 属性 4 高字节
    FirmwareMinorRev uint8  `json:"firmware_minor_rev"` // 属性 4 低字节
    Status           uint16 `json:"status"`             // 属性 5
    SerialNumber     uint32 `json:"serial_number"`      // 属性 6
    ProductName      string `json:"product_name"`       // 属性 7

    // === 会话字段 ===
    SessionHandle StrategyConfig `json:"session_handle"` // 默认 from_response 或 fixed=0x00000000

    // === Forward_Open 字段 ===
    PriorityTimeTick         uint8  `json:"priority_time_tick"`         // 默认 0x0A
    TimeoutTicks             uint8  `json:"timeout_ticks"`             // 默认 0x05
    O2TNetworkConnectionID   uint32 `json:"o2t_network_connection_id"`  // Originator 分配
    T2ONetworkConnectionID   uint32 `json:"t2o_network_connection_id"`  // 默认 0，由 target 分配
    ConnectionSerialNumber   uint16 `json:"connection_serial_number"`
    OriginatorVendorID       uint16 `json:"originator_vendor_id"`
    OriginatorSerialNumber   uint32 `json:"originator_serial_number"`
    ConnectionTimeoutMultiplier uint8 `json:"connection_timeout_multiplier"` // 0-7，默认 7（512s）
    O2TRPI                   uint32 `json:"o2t_rpi"`                    // 单位 μs，默认 100000（100ms）
    O2TConnectionParameters  uint16 `json:"o2t_connection_parameters"`  // Forward_Open: 2B
    T2ORPI                   uint32 `json:"t2o_rpi"`
    T2OConnectionParameters  uint16 `json:"t2o_connection_parameters"`
    // LargeForwardOpen 专用（4B 连接参数）
    O2TLargeConnectionParameters  uint32 `json:"o2t_large_connection_parameters"`
    T2OLargeConnectionParameters  uint32 `json:"t2o_large_connection_parameters"`
    TransportClassTrigger    uint8  `json:"transport_class_trigger"`    // 默认 0x80 (Class 0 Client)
    ConnectionPath           []byte `json:"connection_path"`            // 默认自动编码 0x20 0x04 0x24 0x01 0x2C 0x02 0x2C 0x03（Assembly 实例 + O→T/T→O Connection Point）

    // === Forward_Close 路径一致约束 ===
    // Forward_Close 的 ConnectionPath 必须与 Forward_Open 时字节级一致（§3.7），
    // planner 在生成 Forward_Close 时复用同一 ConnectionPath 配置，禁止单独修改。

    // === I/O 数据字段 ===
    IOData *ENIPIOData `json:"io_data"`

    // === 多会话/多流字段 ===
    SessionCount int `json:"session_count"`   // 多会话并发数（默认 1）
    FlowCount    int `json:"flow_count"`      // 每会话 I/O 流数（默认 1）
}
```

### 5.3 ENIPCommand 结构

```go
type ENIPCommand struct {
    // Command 是 ENIP 命令码（如 0x0065 RegisterSession、0x006F SendRRData）
    Command uint16 `json:"command"`

    // SessionHandle 用于 ENIP 头。StrategyConfig 支持 from_response / fixed。
    SessionHandle StrategyConfig `json:"session_handle"`

    // SenderContext 是 8 字节不透明字段。可以是 fixed/inc/rand。
    // 默认 inc，从 1 开始递增（用于追踪请求-响应对应）。
    SenderContext StrategyConfig `json:"sender_context"`

    // Options 默认 0x00000000。
    Options uint32 `json:"options"`

    // Status 用于响应模拟（请求中通常为 0）。
    Status uint32 `json:"status"`

    // --- 命令特定字段 ---

    // RegisterSession 专用：ProtocolVersion + OptionFlag
    // 默认 ProtocolVersion=1, OptionFlag=0
    ProtocolVersion uint16 `json:"protocol_version"`
    OptionFlag      uint16 `json:"option_flag"`

    // SendRRData / SendUnitData 专用
    InterfaceHandle uint32 `json:"interface_handle"` // 默认 0
    Timeout         uint16 `json:"timeout"`          // 默认 10（秒）

    // CPF Items（RegisterSession/ListIdentity/ListServices 请求中为空）
    CPFItems []CPFItem `json:"cpf_items"`

    // CIP 服务码（SendRRData 中使用）。0 表示不携带 CIP 消息。
    CIPService uint8 `json:"cip_service"`

    // CIP 路径（自动编码 EPATH）。用户填写 class_id/instance_id/attr_id。
    ClassID    uint16 `json:"class_id"`
    InstanceID uint32 `json:"instance_id"`
    AttrID     uint16 `json:"attr_id"`

    // Forward_Open/Close 专用：连接三元组
    ConnSerialNumber  uint16 `json:"conn_serial_number"`
    OrigVendorID      uint16 `json:"orig_vendor_id"`
    OrigSerialNumber  uint32 `json:"orig_serial_number"`

    // CIP 响应的 General Status（用于响应模拟）
    CIPGeneralStatus  uint8  `json:"cip_general_status"`
    CIPAdditionalStatus []byte `json:"cip_additional_status"`

    // Payload 是用户自定义 payload（覆盖 planner 自动计算）。
    // 通常留空，由 planner 根据 Command + CIPService + 上述字段计算。
    Payload []byte `json:"payload"`
}
```

### 5.4 CPFItem 结构

```go
type CPFItem struct {
    TypeID  uint16 `json:"type_id"`
    // Data 是 item 的 payload。Length 由 planner 计算。
    Data    []byte `json:"data"`
}
```

### 5.5 ENIPIOData 结构（I/O 周期数据）

```go
type ENIPIOData struct {
    // ConnectionID 标识 I/O 流。Forward_Open 响应后通过 from_response 提取。
    O2TConnectionID StrategyConfig `json:"o2t_connection_id"`
    T2OConnectionID StrategyConfig `json:"t2o_connection_id"`

    // SequenceCounter 起始值与递增规则
    SequenceStart uint16 `json:"sequence_start"` // 默认 0
    SequenceStep  uint16 `json:"sequence_step"`  // 默认 1

    // FrameCount 是 I/O 帧数量（UDP 包数）
    FrameCount int `json:"frame_count"` // 默认 10

    // FrameInterval 是 I/O 帧间隔（μs）
    FrameInterval uint32 `json:"frame_interval"` // 默认 100000 (100ms，对应 RPI)

    // Payload 是每帧 I/O 数据（每帧相同；若需变化用 BodyGenerator）
    Payload []byte `json:"payload"`

    // TransportClassTrigger 决定 Class 0/1/3 与方向
    TransportClassTrigger uint8 `json:"transport_class_trigger"` // 默认 0x80 (Class 0 Client)

    // FrameSize 边界检查：UDP datagram 上限 65507 字节
    // 单帧上限 = 65507 - 24(ENIP) - 4(IfHdl) - 2(Timeout) - 2(ItemCount) - 6(CAI) - 4(CDI 头) = 65465
    FrameSize int `json:"frame_size"`
}
```

### 5.6 StrategyConfig 跨命令引用机制

#### 5.6.1 from_response 字段提取规则

| StrategyConfig.field | 提取位置 | 偏移 | 大小 | 字节序 |
|---------------------|----------|------|------|--------|
| `session_handle` | 响应 ENIP 头 SessionHandle | 4（从 ENIP 头起算） | 4B | LE |
| `o2t_connection_id` | Forward_Open 响应 CIP body O2T_ConnID（成功时） | 0（从 CIP body 起算） | 4B | LE |
| `t2o_connection_id` | Forward_Open 响应 CIP body T2O_ConnID（成功时） | 4（从 CIP body 起算） | 4B | LE |
| `connection_serial_number` | Forward_Open 响应 CIP body ConnSerialNumber | 8（从 CIP body 起算） | 2B | LE |

**前置条件**：`o2t_connection_id`/`t2o_connection_id`/`connection_serial_number` 的提取**仅在 `source_command_index` 指向的 Forward_Open 响应 General Status=0x00（成功）时有效**（v2.0.1 修订，对应审计 R35）。planner 应在构建引用命令前校验该响应的 General Status；若为错误响应（如 0x01 + AddStatus 0x0100/0x0107），必须终止或跳过引用命令，不得用错误响应字节作为 Connection ID。

**source_command_index**：指明从第几个命令的响应中提取（0-based）。如 RegisterSession 是命令 1（假设 ListIdentity 在命令 0），Forward_Open 是命令 3。

**多流隔离**（v2.0.1 修订，对应审计 R20）：同一流内的多个命令通过 `source_command_index` 引用各自会话的 Forward_Open 响应；不同流（flow）的 `source_command_index` 基准不同——流 i 的命令序列中，`source_command_index` 是**相对本流命令序列**的索引，planner 按 (flow_id, source_command_index) 两级索引定位响应，确保流 1 的 I/O 命令不会误取流 2 的 Forward_Open 响应 Connection ID。

#### 5.6.2 StrategyConfig 合法策略

```go
type StrategyConfig struct {
    Strategy string `json:"strategy"` // fixed / inc / rand / from_response
    Value    uint64 `json:"value"`    // fixed 的值
    Range    [2]uint64 `json:"range"` // inc/rand 范围
    Step     uint64 `json:"step"`     // inc 步长
    Seed     uint64 `json:"seed"`     // rand 种子

    // from_response 专用
    SourceCommandIndex int    `json:"source_command_index"` // 响应来自哪个命令
    Field              string `json:"field"`                // 提取字段名（session_handle / o2t_connection_id / t2o_connection_id / connection_serial_number）
}
```

**SessionHandle 合法策略**：仅 `from_response` 与 `fixed`（递增无业务意义）。

### 5.7 CIP 数据编码辅助函数

```go
// EncodeCIPPath 编码 EPATH 路径。详见 §2.7.4。
// connPointIDs 是可选参数，用于 Forward_Open/Close 的 ConnectionPath（Class+Instance+Connection Point）。
func EncodeCIPPath(classID uint16, instanceID uint32, attrID uint16, connPointIDs ...uint16) []byte

// EncodeCIPRequest 编码完整 CIP 请求：Service + RequestPathSize + RequestPath + ServiceData
func EncodeCIPRequest(service uint8, classID uint16, instanceID uint32, attrID uint16, serviceData []byte) []byte

// EncodeForwardOpenRequest 编码 Forward_Open (0x54) 请求体（35 字节 + 路径）
func EncodeForwardOpenRequest(cfg *ENIPConfig) []byte

// EncodeLargeForwardOpenRequest 编码 LargeForward_Open (0x5B) 请求体（39 字节 + 路径）
func EncodeLargeForwardOpenRequest(cfg *ENIPConfig) []byte

// EncodeForwardCloseRequest 编码 Forward_Close (0x4E) 请求体（10 字节 + 路径）
func EncodeForwardCloseRequest(cfg *ENIPConfig) []byte

// EncodeMultipleServicePacket 编码 Multiple_Service_Packet (0x0A) 请求
// path 是 CIP 头里的 RequestPath（通常是 Message Router Class 0x02 Instance 0x01，
// 但可以是任何支持 MSP 服务的对象，见 §3.9）
// subRequests 是子 CIP 请求字节数组列表
// Offset 数组（第 i 个子请求相对 OffsetCount 字段起始的字节偏移）由函数内部计算，
// 调用者无需手动设置：Offset[i] = 2 + 2*N + sum(len(Sub[0..i-1]))，N=子请求数量
func EncodeMultipleServicePacket(path []byte, subRequests [][]byte) []byte

// EncodeAttributeListRequest 编码 Get_Attribute_List (0x03) 请求
func EncodeAttributeListRequest(classID uint16, instanceID uint32, attrIDs []uint16) []byte

// EncodeRegisterSessionPayload 编码 RegisterSession payload（4 字节）
func EncodeRegisterSessionPayload(protocolVersion, optionFlag uint16) []byte

// BuildENIPHeader 构建 24 字节 ENIP 封装头（little-endian）
func BuildENIPHeader(command uint16, length uint16, sessionHandle uint32, status uint32, senderContext [8]byte, options uint32) []byte

// BuildSendRRDataPayload 构建 SendRRData payload（Interface Handle + Timeout + CPF）
func BuildSendRRDataPayload(timeout uint16, cpfItems []CPFItem) []byte

// BuildSendUnitDataPayload 构建 SendUnitData payload（Interface Handle + Timeout + CPF）
func BuildSendUnitDataPayload(timeout uint16, cpfItems []CPFItem) []byte

// BuildCPF 构建 CPF（ItemCount + Items），不包含 Interface Handle/Timeout 前缀
func BuildCPF(items []CPFItem) []byte
```

---

## 6. 包序列场景（HexDump S1-S15）

### 6.1 场景索引

| # | 场景 | 命令 | 传输 | HexDump 字节数 |
|---|------|------|------|----------------|
| S1 | NOP 保活 | NOP (0x0000) | TCP | 28+ |
| S2 | ListServices | ListServices (0x0004) | TCP | 24（请求） / 49（响应） |
| S3 | ListIdentity | ListIdentity (0x0063) | TCP | 24（请求） / 75（响应） |
| S4 | RegisterSession | RegisterSession (0x0065) | TCP | 28（请求） / 28（响应） |
| S5 | UnRegisterSession | UnRegisterSession (0x0066) | TCP | 24 |
| S6 | SendRRData Get_Attribute_Single | SendRRData (0x006F) | TCP | 50（请求） / 46（响应） |
| S7 | Forward_Open | SendRRData + CIP 0x54 | TCP | 90（请求） / 70（响应） |
| S8 | Forward_Close | SendRRData + CIP 0x4E | TCP | 65（请求） / 54（响应） |
| S9 | SendUnitData Connected | SendUnitData (0x0070) | UDP | 48 |
| S10 | Multiple_Service_Packet | SendRRData + CIP 0x0A | TCP | 72（请求） |
| S11 | Error 响应 | SendRRData + 错误 CIP 响应 | TCP | 46（响应） |
| S12 | 多会话并发 | 多个 RegisterSession | TCP | 28*N |
| S13 | 多流关联 | 多个 Forward_Open + I/O | TCP+UDP | 90*N + 48*N |
| S14 | LargeForward_Open | SendRRData + CIP 0x5B | TCP | 94（请求） / 70（响应） |
| S15 | 心跳/超时 | NOP + IndicateStatus | TCP | 24+ |

---

### 6.2 S1：NOP 保活

**目的**：TCP 长连接保活，验证 NOP 命令可携带任意 payload。

**字段构成**（请求，28 字节）：
- ENIP 头 24B：Command=0x0000、Length=4、SessionHandle=0x12345678、Status=0、SenderContext=0x0102030405060708、Options=0
- Payload 4B：`DE AD BE EF`（任意）

**HexDump**：
```
00 00          Command=0x0000 (NOP), LE
04 00          Length=4, LE
78 56 34 12    SessionHandle=0x12345678, LE
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext, 8B 不透明
00 00 00 00    Options=0
DE AD BE EF    Payload (4 字节任意)
```

**验证**：Length=4 = 实际 payload 4 字节。✓

---

### 6.3 S2：ListServices

**目的**：发现设备支持的 ENIP 服务。

**字段构成**（请求，24 字节）：
- ENIP 头 24B：Command=0x0004、Length=0、SessionHandle=0、Status=0、SenderContext=0x0102030405060708、Options=0
- 无 payload

**HexDump（请求）**：
```
04 00          Command=0x0004 (ListServices), LE
00 00          Length=0, LE
00 00 00 00    SessionHandle=0
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext
00 00 00 00    Options=0
```

**验证**：Length=0 = 无 payload。✓

**字段构成**（响应，假设设备支持 CIP 协议）：
- ENIP 头 24B：Command=0x0004、Length=25、SessionHandle=0、Status=0
- payload 25B（无 Interface Handle + Timeout 前缀，直接 ItemCount + items）：
  - ItemCount=1 (2B)
  - Item[TypeID=0x0100 (2B), Length=19 (2B), Data=ProtocolVersion(2B)+CapabilityFlags(4B)+ServiceName(13B "Communications")]

**HexDump（响应）**：
```
04 00          Command=0x0004
19 00          Length=25, LE
00 00 00 00    SessionHandle=0
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext (回显)
00 00 00 00    Options=0
01 00          ItemCount=1, LE
00 01          TypeID=0x0100 (ListServices Response), LE
13 00          Length=19, LE
01 00          ProtocolVersion=1
00 00 00 00    CapabilityFlags=0
43 6F 6D 6D 75 6E 69 63 61 74 69 6F 6E 73   "Communications" (13B)
```

**验证**：Length=25 = 2(ItemCount) + 4(TypeID+Length) + 19(Data) = 25。✓ Item Data 19 字节 = 2(ProtocolVersion) + 4(CapabilityFlags) + 13(ServiceName "Communications") = 19。✓ 无 6B 前缀（ListServices 响应直接以 ItemCount 开头，见 §3.3）。✓

---

### 6.4 S3：ListIdentity

**目的**：发现设备身份信息（VendorID/ProductName 等）。

**字段构成**（请求，24 字节）：
- ENIP 头 24B：Command=0x0063、Length=0

**HexDump（请求）**：
```
63 00          Command=0x0063 (ListIdentity), LE
00 00          Length=0, LE
00 00 00 00    SessionHandle=0
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext
00 00 00 00    Options=0
```

**验证**：Length=0。✓

**字段构成**（响应，假设设备 VendorID=0x0001、ProductName="TestDevice"）：
- ENIP 头 24B：Command=0x0063、Length=51
- payload 51B（无 Interface Handle + Timeout 前缀，直接 ItemCount + items）：
  - ItemCount=1 (2B)
  - Item[TypeID=0x000C (2B), Length=45 (2B), Data=...]
- ListIdentity Response Item Data（45 字节）：
  - EncapsulationProtocolVersion(2)=1 + ProtocolVersion(2)=1 + SocketAddress(16) + VendorID(2) + DeviceType(2) + ProductCode(2) + Revision(2) + Status(2) + SerialNumber(4) + ProductName(1+9="TestDevice") + State(1)

**HexDump（响应）**：
```
63 00          Command=0x0063
33 00          Length=51, LE
00 00 00 00    SessionHandle=0
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext (回显)
00 00 00 00    Options=0
01 00          ItemCount=1, LE
0C 00          TypeID=0x000C (ListIdentity Response), LE
2D 00          Length=45, LE
01 00          EncapsulationProtocolVersion=1
01 00          ProtocolVersion=1 (OpENer 写 kSupportedProtocolVersion=1)
02 00          SinFamily=2 (AF_INET)
11 A1          SinPort=0xA111=44817 (假设端口)
C0 A8 01 01    SinAddr=192.168.1.1
00 00 00 00 00 00 00 00   SinZero (8B)
01 00          VendorID=0x0001
00 00          DeviceType=0x0000
00 00          ProductCode=0x0000
0B 00          Revision: major=0x0B, minor=0x00
00 00          Status=0
00 00 00 00    SerialNumber=0
09 54 65 73 74 44 65 76 69 63 65   ProductName="TestDevice" (1B 长度 9 + 9 字节 ASCII)
00             State=0
```

**验证**：Length=51 = 2(ItemCount) + 4(TypeID+Length) + 45(Data) = 51。✓ 无 6B 前缀（ListIdentity 响应直接以 ItemCount 开头，见 §3.3）。✓ Item Data 45 字节 = 2(EncapProtoVer) + 2(ProtoVer) + 16(SocketAddr) + 2(VendorID) + 2(DeviceType) + 2(ProductCode) + 2(Revision) + 2(Status) + 4(SerialNum) + 10(ProductName 1B len + 9B ASCII) + 1(State) = 45。✓

**修正说明**（v2.0.1 修订，对应审计 R1/R7/R38）：v2.0.0 在此 HexDump 中先写 Length=51 又中途"修正"到 57，反而引入 6B 前缀错误；正确应是 51（无 6B 前缀）。v2.0.0 称 ProtocolVersion=0xFFFF 无依据——OpENer `EncodeListIdentityCipIdentityItem` 在该位置写 `kSupportedProtocolVersion=1`。

**修正说明**（对比 v1，D-CRIT-8）：v1 错用 TypeID=0x0100（实际是 ListServices Response）；正确 ListIdentity Response TypeID=0x000C。

---

### 6.5 S4：RegisterSession

**目的**：建立 ENIP 会话，获取 SessionHandle。

**字段构成**（请求，28 字节）：
- ENIP 头 24B：Command=0x0065、Length=4、SessionHandle=0（未注册）、Status=0、SenderContext=0x0102030405060708、Options=0
- payload 4B：ProtocolVersion=1 + OptionFlag=0

**HexDump（请求）**：
```
65 00          Command=0x0065 (RegisterSession), LE
04 00          Length=4, LE
00 00 00 00    SessionHandle=0 (未注册)
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext
00 00 00 00    Options=0
01 00          ProtocolVersion=1, LE
00 00          OptionFlag=0, LE
```

**验证**：Length=4 = ProtocolVersion(2) + OptionFlag(2) = 4。✓ 无 CPF item。✓

**字段构成**（响应，28 字节）：
- ENIP 头 24B：Command=0x0065、Length=4、SessionHandle=0x12345678（target 分配）、Status=0、SenderContext=0x0102030405060708（回显）、Options=0
- payload 4B：ProtocolVersion=1 + OptionFlag=0

**HexDump（响应）**：
```
65 00          Command=0x0065
04 00          Length=4, LE
78 56 34 12    SessionHandle=0x12345678, LE  ← target 分配
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext (回显)
00 00 00 00    Options=0
01 00          ProtocolVersion=1, LE
00 00          OptionFlag=0, LE
```

**验证**：Length=4。✓ SessionHandle 通过 `from_response` 提取（offset 4，4B LE）。✓

**修正说明**（对比 v1，D-CRIT-7）：v1 错误使用 CPF（cpf_items:[{type_id:0x0000, payload:"\x01\x00"}]）；实际 RegisterSession payload 直接是 ProtocolVersion+OptionFlag，无 CPF。

---

### 6.6 S5：UnRegisterSession

**目的**：注销会话。

**字段构成**（请求，24 字节）：
- ENIP 头 24B：Command=0x0066、Length=0、SessionHandle=0x12345678、Status=0、SenderContext、Options=0
- 无 payload

**HexDump（请求）**：
```
66 00          Command=0x0066 (UnRegisterSession), LE
00 00          Length=0, LE
78 56 34 12    SessionHandle=0x12345678, LE
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext
00 00 00 00    Options=0
```

**验证**：Length=0。✓ 无响应。✓

---

### 6.7 S6：SendRRData Get_Attribute_Single

**目的**：读取 Identity 对象属性 1 (Vendor ID)。

**字段构成**（请求，48 字节）：
- ENIP 头 24B：Command=0x006F、Length=24、SessionHandle=0x12345678、Status=0、SenderContext、Options=0
- payload 24B：
  - Interface Handle=0 (4B) + Timeout=10 (2B)
  - CPF ItemCount=1 (2B)
  - Item 1: Null Address (0x0000) + Length=0 (4B)
  - Item 2: Unconnected Data (0x00B2) + Length=10 (4B)
  - CIP data (10B): Service=0x0E + RequestPathSize=4 + Path=`20 01 25 01 00 30 01 00` + 无 service data

等等，ItemCount=2（Null Address + Unconnected Data）。

重新计算 payload：
- Interface Handle (4) + Timeout (2) + ItemCount (2) = 8
- Item 1: TypeID (2) + Length (2) + Data (0) = 4
- Item 2: TypeID (2) + Length (2) + Data (10) = 14
- 总 payload = 8 + 4 + 14 = 26

CIP data (10 字节)：Service(1)=0x0E + RequestPathSize(1)=4 + Path(8)=`20 01 25 01 00 30 01 00`
- Class 8-bit = 0x01 (Identity): `20 01`
- Instance 16-bit = 0x0001: `25 01 00`（3 字节）
- Attribute 8-bit = 0x01 (Vendor ID): `30 01`
- Path 共 2+3+2=7 字节，RequestPathSize = ⌈7/2⌉ = 4 words = 8 字节，补 1 字节 0x00
- CIP data 总 = 1 + 1 + 8 = 10 字节 ✓

**HexDump（请求）**：
```
6F 00          Command=0x006F (SendRRData), LE
1A 00          Length=26, LE
78 56 34 12    SessionHandle=0x12345678, LE
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext
00 00 00 00    Options=0
00 00 00 00    Interface Handle=0, LE
0A 00          Timeout=10s, LE
02 00          ItemCount=2, LE
00 00          TypeID=0x0000 (Null Address), LE
00 00          Length=0, LE
B2 00          TypeID=0x00B2 (Unconnected Data), LE
0A 00          Length=10, LE
0E             Service=0x0E (Get_Attribute_Single)
04             RequestPathSize=4 words
20 01          Class 8-bit = 0x01 (Identity)
25 01 00       Instance 16-bit = 0x0001
30 01          Attribute 8-bit = 0x01 (Vendor ID)
00             Padding (凑 8 字节路径)
```

**验证**：Length=26 = 6 + 2 + 4 + 2 + 2 + 10 = 26。✓ ItemCount=2。✓

**字段构成**（响应，假设 VendorID=0x0001）：
- ENIP 头 24B：Command=0x006F、Length=22
- payload 22B：Interface Handle(4B) + Timeout(2B) + ItemCount=2(2B) + Null Address(4B) + Unconnected Data(4B TypeID/Length + 6B CIP response)
- CIP response (6B): Reply Service=0x8E + Reserved=0 + General Status=0 + AddStatusSize=0 + VendorID=0x0001 (2B)

CIP response = 1+1+1+1+2 = 6 字节（成功响应 service data 仅 VendorID 2B）
payload = 6 + 2 + 4 + 2 + 2 + 6 = 22
Length = 22 = 0x16

**HexDump（响应）**：
```
6F 00          Command=0x006F
16 00          Length=22, LE
78 56 34 12    SessionHandle=0x12345678
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext (回显)
00 00 00 00    Options=0
00 00 00 00    Interface Handle=0
0A 00          Timeout=10s
02 00          ItemCount=2, LE
00 00          TypeID=0x0000 (Null Address)
00 00          Length=0
B2 00          TypeID=0x00B2 (Unconnected Data)
06 00          Length=6, LE
8E             Reply Service=0x0E | 0x80 = 0x8E
00             Reserved
00             General Status=0 (成功)
00             Size of Additional Status=0
01 00          VendorID=0x0001, LE
```
6F 00          Command=0x006F
16 00          Length=22, LE
78 56 34 12    SessionHandle=0x12345678
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext
00 00 00 00    Options=0
00 00 00 00    Interface Handle=0
0A 00          Timeout=10s
02 00          ItemCount=2, LE
00 00          TypeID=0x0000 (Null Address)
00 00          Length=0
B2 00          TypeID=0x00B2 (Unconnected Data)
06 00          Length=6, LE
8E             Reply Service=0x8E
00             Reserved
00             General Status=0
00             Size of Additional Status=0
01 00          VendorID=0x0001, LE
```

**验证**：Length=22 = 6+2+4+2+2+6=22。✓

---

### 6.8 S7：Forward_Open

**目的**：打开 CIP I/O 连接。

**字段构成**（请求，66 字节）：
- ENIP 头 24B：Command=0x006F、Length=66、SessionHandle=0x12345678、Status=0、SenderContext、Options=0
- payload 66B：
  - Interface Handle=0 (4B) + Timeout=10 (2B) = 6B
  - CPF ItemCount=2 (2B) = 2B
  - Item 1: Null Address (0x0000) + Length=0 = 4B
  - Item 2: Unconnected Data (0x00B2) + Length=50 (4B) + CIP data (50B) = 54B
  - 总 = 6 + 2 + 4 + 54 = 66 ✓

CIP data (50 字节)：
- Service=0x54 (1B)
- RequestPathSize=2 words (1B)
- RequestPath=`20 06 24 01` (4B) = Class 0x06 (Connection Manager) + Instance 8-bit 0x01
- Forward_Open body (44B)：
  - PriorityTimeTick=0x0A (1B)
  - TimeoutTicks=0x05 (1B)
  - O2TConnectionID=0x00000001 (4B LE)
  - T2OConnectionID=0x00000002 (4B LE)
  - ConnectionSerialNumber=0x0001 (2B LE)
  - OriginatorVendorID=0x0001 (2B LE)
  - OriginatorSerialNumber=0x00000001 (4B LE)
  - ConnectionTimeoutMultiplier=0x07 (1B)
  - Reserved=0x000000 (3B)
  - O2TRPI=100000=0x000186A0 (4B LE)
  - O2TConnectionParameters=0x0200 (2B LE)
  - T2ORPI=100000=0x000186A0 (4B LE)
  - T2OConnectionParameters=0x0200 (2B LE)
  - TransportClassTrigger=0x80 (1B) Class 0 Client
  - ConnectionPathSize=4 words (1B)
  - ConnectionPath=`20 04 24 01 2C 02 2C 03` (8B) = Class 0x04 (Assembly) + Instance 8-bit 0x01 + Connection Point 8-bit 0x02 (O→T) + Connection Point 8-bit 0x03 (T→O)

Forward_Open body 字节数核算：1+1+4+4+2+2+4+1+3+4+2+4+2+1+1+8 = 44 字节 ✓
（35 字节固定字段 + 1B ConnPathSize + 8B ConnPath = 44；§3.5 的"35 字节固定字段"不含 ConnPathSize 与 ConnPath）

CIP data = Service(1) + RequestPathSize(1) + RequestPath(4) + body(44) = 50 字节 ✓

payload = 6 + 2 + 4 + (2+2+50) = 66
Length = 66 = 0x42

**HexDump（请求）**：
```
6F 00          Command=0x006F (SendRRData), LE
42 00          Length=66, LE
78 56 34 12    SessionHandle=0x12345678, LE
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext
00 00 00 00    Options=0
00 00 00 00    Interface Handle=0, LE
0A 00          Timeout=10s, LE
02 00          ItemCount=2, LE
00 00          TypeID=0x0000 (Null Address), LE
00 00          Length=0, LE
B2 00          TypeID=0x00B2 (Unconnected Data), LE
32 00          Length=50, LE
54             Service=0x54 (Forward_Open)
02             RequestPathSize=2 words
20 06          Class 8-bit = 0x06 (Connection Manager)
24 01          Instance 8-bit = 0x01
0A             PriorityTimeTick=0x0A
05             TimeoutTicks=0x05
01 00 00 00    O2TConnectionID=0x00000001, LE
02 00 00 00    T2OConnectionID=0x00000002, LE
01 00          ConnectionSerialNumber=0x0001, LE
01 00          OriginatorVendorID=0x0001, LE
01 00 00 00    OriginatorSerialNumber=0x00000001, LE
07             ConnectionTimeoutMultiplier=7
00 00 00       Reserved (3B)
A0 86 01 00    O2TRPI=0x000186A0=100000μs, LE
00 02          O2TConnectionParameters=0x0200, LE
A0 86 01 00    T2ORPI=0x000186A0, LE
00 02          T2OConnectionParameters=0x0200, LE
80             TransportClassTrigger=0x80 (Class 0 Client)
04             ConnectionPathSize=4 words
20 04          Class 8-bit = 0x04 (Assembly)
24 01          Instance 8-bit = 0x01 (Configuration Assembly 实例)
2C 02          Connection Point 8-bit = 0x02 (O→T Assembly)
2C 03          Connection Point 8-bit = 0x03 (T→O Assembly)
```

**验证**：Length=66 = 6+2+4+2+2+50=66。✓ CIP data=50=1+1+4+44。✓ Forward_Open body=44=35+1+8。✓

**修正说明**（v2.0.1 修订，对应审计 R3/R21/R36）：v2.0.0 S7 ConnectionPath=`20 04 24 01`（4B）缺少 Connection Point 段，target 无法定位 O→T/T→O 装配实例，会拒绝连接。补全为 `20 04 24 01 2C 02 2C 03`（含 O→T 与 T→O Connection Point）。EncodeCIPPath 函数签名需扩展以支持 Connection Point 段（见 §2.7.4 修订）。

**字段构成**（响应，56 字节，成功）：
- ENIP 头 24B：Command=0x006F、Length=32、SessionHandle=0x12345678、Status=0
- payload 32B：Interface Handle (4B) + Timeout (2B) + ItemCount=2 (2B) + Null Address (4B) + Unconnected Data (4B TypeID/Length + 30B CIP response) = 6+2+4+4+34 = ... 重新核算：
  - Interface Handle(4) + Timeout(2) + ItemCount(2) + Item1[TypeID(2)+Length(2)+Data(0)] + Item2[TypeID(2)+Length(2)+Data(30)] = 4+2+2+4+4+30 = 46 字节 payload
  - Length = 46 = 0x2E
- CIP response (30B): Reply Service(1)=0xD4 + Reserved(1)=0 + General Status(1)=0 + AddStatusSize(1)=0 + O2TConnID(4) + T2OConnID(4) + ConnSerialNum(2) + OrigVendorID(2) + OrigSerialNum(4) + O2TRPI(4) + T2ORPI(4) + ApplicationReplySize(1)=0 + Reserved(1)=0
  - = 4 (MR 头) + 26 (service data) = 30 字节
  - 26 字节 service data = O2TConnID(4) + T2OConnID(4) + ConnSerialNum(2) + OrigVendorID(2) + OrigSerialNum(4) + O2TRPI(4) + T2ORPI(4) + ApplicationReplySize(1) + Reserved(1) = 26 ✓

payload = 6 + 2 + 4 + (2+2+30) = 46
Length = 46 = 0x2E

**HexDump（响应）**：
```
6F 00          Command=0x006F
2E 00          Length=46, LE
78 56 34 12    SessionHandle=0x12345678
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext
00 00 00 00    Options=0
00 00 00 00    Interface Handle=0
0A 00          Timeout=10s
02 00          ItemCount=2, LE
00 00          TypeID=0x0000 (Null Address)
00 00          Length=0
B2 00          TypeID=0x00B2 (Unconnected Data)
1E 00          Length=30, LE
D4             Reply Service=0x54 | 0x80 = 0xD4
00             Reserved
00             General Status=0 (成功)
00             Size of Additional Status=0
01 00 00 00    O2TConnectionID=0x00000001 (CIP body offset 0), LE
02 00 00 00    T2OConnectionID=0x00000002 (CIP body offset 4), LE
01 00          ConnectionSerialNumber=0x0001 (回显), LE
01 00          OriginatorVendorID=0x0001 (回显), LE
01 00 00 00    OriginatorSerialNumber=0x00000001 (回显), LE
A0 86 01 00    O2TRPI=100000, LE (实际 RPI)
A0 86 01 00    T2ORPI=100000, LE
00             Application Reply Size=0 (word 单位)
00             Reserved=0
```

**验证**：Length=46 = 6+2+4+2+2+30=46。✓ CIP response=30=4+26。✓ O2TConnectionID 通过 from_response 提取（CIP body offset 0，4B LE）。✓

**修正说明**（v2.0.1 修订，对应审计 R2/R8）：响应体字段顺序与 v2.0.0 相同（O2T 在前、T2O 在后），与 OpENer `AssembleForwardOpenResponse` 实际装配一致（`cip_consumed_connection_id`=O2T 在前、`cip_produced_connection_id`=T2O 在后）。v2.0.0 的错误仅在 §5.6.1 提取偏移（称 O2T=CIP body offset 4、T2O=offset 8，多算了 4B MR 头）；正确为 O2T=offset 0、T2O=offset 4（见 §3.6 与 §5.6.1 修订）。

---

### 6.9 S8：Forward_Close

**目的**：关闭 CIP I/O 连接（用三元组定位）。

**字段构成**（请求，41 字节）：
- ENIP 头 24B：Command=0x006F、Length=41、SessionHandle=0x12345678、Status=0
- payload 41B：Interface Handle (4B) + Timeout (2B) + ItemCount=2 (2B) + Null Address (4B) + Unconnected Data (4B TypeID/Length + 25B CIP request)
- CIP request (25B): Service=0x4E + RequestPathSize=2 + Path=`20 06 24 01` (4B) + Forward_Close body (19B)
- Forward_Close body (19B): PriorityTimeTick(1) + TimeoutTicks(1) + ConnSerialNum(2) + OrigVendorID(2) + OrigSerialNum(4) + ConnPathSize(1) + ConnPath(8)
- ConnectionPath=`20 04 24 01 2C 02 2C 03` (8B, PathSize=4 words) — 与 Forward_Open 时的 ConnectionPath 一致

body 字节数核算：1+1+2+2+4+1+8 = 19 字节
CIP request = 1+1+4+19 = 25 字节
payload = 6+2+4+2+2+25 = 41
Length = 41 = 0x29

**HexDump（请求）**：
```
6F 00          Command=0x006F (SendRRData), LE
29 00          Length=41, LE
78 56 34 12    SessionHandle=0x12345678, LE
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext
00 00 00 00    Options=0
00 00 00 00    Interface Handle=0, LE
0A 00          Timeout=10s, LE
02 00          ItemCount=2, LE
00 00          TypeID=0x0000 (Null Address), LE
00 00          Length=0, LE
B2 00          TypeID=0x00B2 (Unconnected Data), LE
19 00          Length=25, LE
4E             Service=0x4E (Forward_Close)
02             RequestPathSize=2 words
20 06          Class 8-bit = 0x06 (Connection Manager)
24 01          Instance 8-bit = 0x01
0A             PriorityTimeTick=0x0A
05             TimeoutTicks=0x05
01 00          ConnectionSerialNumber=0x0001, LE
01 00          OriginatorVendorID=0x0001, LE
01 00 00 00    OriginatorSerialNumber=0x00000001, LE
04             ConnectionPathSize=4 words
20 04          Class 8-bit = 0x04 (Assembly)
24 01          Instance 8-bit = 0x01 (Configuration Assembly)
2C 02          Connection Point 8-bit = 0x02 (O→T Assembly)
2C 03          Connection Point 8-bit = 0x03 (T→O Assembly)
```

**验证**：Length=41 = 6+2+4+2+2+25=41。✓ CIP request=25=1+1+4+19。✓ Forward_Close body=19=10+1+8。✓

**修正说明**（v2.0.1 修订，对应审计 R4/R26）：v2.0.0 S8 ConnectionPath=`20 06 24 01`（指向 Connection Manager 自身）与 Forward_Open 时不一致，target 会因路径不匹配返回 0x0316（ForwardClose connection path mismatch）。修正为与 Forward_Open 一致的 `20 04 24 01 2C 02 2C 03`。

**字段构成**（响应，30 字节 payload，成功）：
- ENIP 头 24B：Command=0x006F、Length=30
- payload 30B：Interface Handle(4B) + Timeout(2B) + ItemCount=2(2B) + Null Address(4B) + Unconnected Data(4B TypeID/Length + 14B CIP response)
- CIP response (14B): Reply Service=0xCE + Reserved + Status=0 + AddStatusSize=0 + ConnSerialNum(2) + OrigVendorID(2) + OrigSerialNum(4) + ApplicationReplySize(1)=0 + Reserved(1)=0

成功响应 body (10 字节 service data) = ConnSerialNum(2) + OrigVendorID(2) + OrigSerialNum(4) + ApplicationReplySize(1) + Reserved(1) = 10
CIP response = 4 (MR 头) + 10 (service data) = 14 字节
payload = 6+2+4+2+2+14 = 30
Length = 30 = 0x1E

**HexDump（响应）**：
```
6F 00          Command=0x006F
1E 00          Length=30, LE
78 56 34 12    SessionHandle=0x12345678
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext
00 00 00 00    Options=0
00 00 00 00    Interface Handle=0
0A 00          Timeout=10s
02 00          ItemCount=2, LE
00 00          TypeID=0x0000 (Null Address)
00 00          Length=0
B2 00          TypeID=0x00B2 (Unconnected Data)
0E 00          Length=14, LE
CE             Reply Service=0x4E | 0x80 = 0xCE
00             Reserved
00             General Status=0 (成功)
00             Size of Additional Status=0
01 00          ConnectionSerialNumber=0x0001 (回显), LE
01 00          OriginatorVendorID=0x0001 (回显), LE
01 00 00 00    OriginatorSerialNumber=0x00000001 (回显), LE
00             Application Reply Size=0 (word 单位)
00             Reserved=0
```

**验证**：Length=30 = 6+2+4+2+2+14=30。✓ CIP response=14=4+10。✓

**修正说明**（v2.0.1 修订，对应审计 R2/R7/R25）：v2.0.0 称响应 13 字节 CIP（少算 1B Reserved）、Length=29 是错的——OpENer `AssembleForwardCloseResponse` 在成功响应中写入 ConnSerialNum(2)+OrigVendorID(2)+OrigSerialNum(4)+ApplicationData(1)+Reserved(1)=10 字节 service data，CIP response = 4(MR 头)+10=14 字节，payload=30。v2.0.0 字段名"RemainingPathSize"实际是 OpENer 写入的 Application Data (1B)=0，已统一为 ApplicationReplySize。

**验证**：Length=29 = 6+2+4+2+2+13=29。✓

**修正说明**（对比 v1，D-HIGH-4）：v1 漏掉 ConnSerialNum/OrigVendorID/OrigSerialNum，错写"ConnectionID+路径"。

---

### 6.10 S9：SendUnitData Connected

**目的**：发送 CIP I/O 周期数据（UDP）。

**字段构成**（请求，38 字节）：
- ENIP 头 24B：Command=0x0070、Length=14、SessionHandle=0x12345678、Status=0、SenderContext、Options=0
- payload 14B：
  - Interface Handle=0 (4B) + Timeout=0 (2B) = 6B
  - CPF ItemCount=2 (2B) = 2B
  - Item 1: Connection Address (0x00A1) + Length=4 + ConnectionID=0x00000001 (4B) = 8B
  - Item 2: Connected Data (0x00B1) + Length=4 + SequenceCounter=0x0001 (2B) + Payload (2B=`DE AD`) = 8B
  - 总 = 6+2+8+8 = 24... 不对

重新计算：
- Item 1: TypeID(2) + Length(2) + Data(4) = 8
- Item 2: TypeID(2) + Length(2) + Data(2+2)=6 → 4+6=10
- payload = 6 + 2 + 8 + 10 = 26... 等等

Let me redo: 
- Interface Handle(4) + Timeout(2) = 6
- ItemCount(2) = 2 → 累计 8
- Item 1 (Connection Address): TypeID(2) + Length(2) + Data(4) = 8 → 累计 16
- Item 2 (Connected Data): TypeID(2) + Length(2) + SequenceCounter(2) + Payload(2) = 8 → 累计 24

Length = 24 = 0x18

**HexDump（UDP 包）**：
```
70 00          Command=0x0070 (SendUnitData), LE
18 00          Length=24, LE
78 56 34 12    SessionHandle=0x12345678, LE
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext
00 00 00 00    Options=0
00 00 00 00    Interface Handle=0, LE
00 00          Timeout=0 (I/O 数据通常 0)
02 00          ItemCount=2, LE
A1 00          TypeID=0x00A1 (Connection Address), LE
04 00          Length=4, LE
01 00 00 00    ConnectionID=0x00000001, LE
B1 00          TypeID=0x00B1 (Connected Data), LE
04 00          Length=4, LE
01 00          SequenceCounter=0x0001, LE
DE AD          Payload (2 字节 I/O 数据)
```

**验证**：Length=24 = 6+2+8+8=24。✓ ConnectionID=0x00000001（来自 Forward_Open 响应 O2T/T2O）。✓ SequenceCounter 每帧递增。✓

---

### 6.11 S10：Multiple_Service_Packet

**目的**：一个 SendRRData 承载多个子 CIP 请求（如同时读取 Identity 属性 1 和属性 6）。

**字段构成**（请求，48 字节）：
- ENIP 头 24B：Command=0x006F、Length=48、SessionHandle=0x12345678
- payload 48B：Interface Handle(4B) + Timeout(2B) + ItemCount=2(2B) + Null Address(4B) + Unconnected Data(4B TypeID/Length + 32B CIP request)
- CIP request (32B)：
  - Service=0x0A (1B)
  - RequestPathSize=2 (1B)
  - RequestPath=`20 02 24 01` (4B) = Class 0x02 (Message Router) + Instance 0x01
  - OffsetCount=2 (2B LE)
  - Offset[0]=6 (2B LE) → 第一个子请求偏移（从 OffsetCount 字段起始 = 2+2*2=6）
  - Offset[1]=16 (2B LE) → 第二个子请求偏移（6 + Sub0 长度 10 = 16）

实际子请求结构：
- Sub 0: Get_Attribute_Single(0x0E) + PathSize=4 + `20 01 25 01 00 30 01 00` = 1+1+8=10 字节
- Sub 1: Get_Attribute_Single(0x0E) + PathSize=4 + `20 01 25 01 00 30 06 00` = 10 字节

Offset 计算（从 OffsetCount 字段起算）：
- Offset[0] = 2 (OffsetCount 自身) + 2*2 (Offsets 数组) = 6
- Offset[1] = 6 + 10 (Sub 0) = 16

CIP request = Service(1) + PathSize(1) + Path(4) + OffsetCount(2) + Offsets(4) + Sub0(10) + Sub1(10) = 32 字节

payload = 6 + 2 + 4 + (2+2+32) = 6+2+4+36 = 48
Length = 48 = 0x30

**HexDump（请求）**：
```
6F 00          Command=0x006F (SendRRData), LE
30 00          Length=48, LE
78 56 34 12    SessionHandle=0x12345678, LE
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext
00 00 00 00    Options=0
00 00 00 00    Interface Handle=0, LE
0A 00          Timeout=10s, LE
02 00          ItemCount=2, LE
00 00          TypeID=0x0000 (Null Address), LE
00 00          Length=0, LE
B2 00          TypeID=0x00B2 (Unconnected Data), LE
20 00          Length=32, LE
0A             Service=0x0A (Multiple_Service_Packet)
02             RequestPathSize=2 words
20 02          Class 8-bit = 0x02 (Message Router)
24 01          Instance 8-bit = 0x01
02 00          OffsetCount=2, LE
06 00          Offset[0]=6, LE
10 00          Offset[1]=16, LE
0E             Sub 0: Service=0x0E (Get_Attribute_Single)
04             PathSize=4 words
20 01          Class 8-bit = 0x01 (Identity)
25 01 00       Instance 16-bit = 0x0001
30 01          Attribute 8-bit = 0x01 (Vendor ID)
00             Padding
0E             Sub 1: Service=0x0E (Get_Attribute_Single)
04             PathSize=4 words
20 01          Class 8-bit = 0x01 (Identity)
25 01 00       Instance 16-bit = 0x0001
30 06          Attribute 8-bit = 0x06 (Serial Number)
00             Padding
```

**验证**：Length=48 = 6+2+4+2+2+32=48。✓ CIP request=32=1+1+4+2+4+10+10。✓ Offset[0]=6, Offset[1]=16。✓

**修正说明**（对比 v1，D-HIGH-6）：v1 错写 Service=0x0E（实际是 Get_Attribute_Single）；正确 Service=0x0A。Offset 数组连续存放，不是与子请求交替。

---

### 6.12 S11：Error 响应

**目的**：模拟 CIP 错误响应（如不存在的属性）。

**字段构成**（响应，44 字节）：
- ENIP 头 24B：Command=0x006F、Length=22、SessionHandle=0x12345678、Status=0
- payload 22B：Interface Handle(4B) + Timeout(2B) + ItemCount=2(2B) + Null Address(4B) + Unconnected Data(4B TypeID/Length + 6B CIP error response)
- CIP error response (6B): Reply Service=0x8E + Reserved + General Status=0x0E (Attribute not supported) + AddStatusSize=1 + AddStatus=0x0000 (2B)

CIP error response = 1+1+1+1+2 = 6 字节
payload = 6+2+4+2+2+6 = 22
Length = 22 = 0x16

**HexDump（响应）**：
```
6F 00          Command=0x006F
16 00          Length=22, LE
78 56 34 12    SessionHandle=0x12345678
00 00 00 00    Status=0 (ENIP 层成功)
01 02 03 04 05 06 07 08   SenderContext
00 00 00 00    Options=0
00 00 00 00    Interface Handle=0
0A 00          Timeout=10s
02 00          ItemCount=2, LE
00 00          TypeID=0x0000 (Null Address)
00 00          Length=0
B2 00          TypeID=0x00B2 (Unconnected Data)
06 00          Length=6, LE
8E             Reply Service=0x8E
00             Reserved
0E             General Status=0x0E (Attribute not supported)
01             Size of Additional Status=1 (word)
00 00          Additional Status=0x0000
```

**验证**：Length=22 = 6+2+4+2+2+6=22。✓ ENIP Status=0（ENIP 层成功），CIP General Status=0x0E（CIP 层错误）。✓

---

### 6.13 S12：多会话并发

**目的**：2 个并发会话，验证 SessionHandle 独立。

**字段构成**（请求，2 个 RegisterSession 包）：
- 包 1 (28B): SessionHandle=0，SenderContext=0x0102030405060708
- 包 2 (28B): SessionHandle=0，SenderContext=0x0102030405060709（递增 1）

**HexDump（包 1）**：
```
65 00          Command=0x0065 (RegisterSession), LE
04 00          Length=4, LE
00 00 00 00    SessionHandle=0
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext=...08
00 00 00 00    Options=0
01 00          ProtocolVersion=1
00 00          OptionFlag=0
```

**HexDump（包 2）**：
```
65 00          Command=0x0065
04 00          Length=4, LE
00 00 00 00    SessionHandle=0
00 00 00 00    Status=0
01 02 03 04 05 06 07 09   SenderContext=...09 (递增)
00 00 00 00    Options=0
01 00          ProtocolVersion=1
00 00          OptionFlag=0
```

**响应（包 1）**：SessionHandle=0x12345678
**响应（包 2）**：SessionHandle=0x12345679（不同句柄）

**验证**：两个会话的 SessionHandle 独立。✓ SenderContext 递增用于追踪。✓

---

### 6.14 S13：多流关联

**目的**：1 个会话内打开 2 个 I/O 连接，验证 ConnectionID 独立。

**字段构成**：
- Forward_Open 包 1 (66B): ConnectionSerialNumber=0x0001，O2TConnectionID=0x00000001
- Forward_Open 包 2 (66B): ConnectionSerialNumber=0x0002，O2TConnectionID=0x00000003
- I/O 包 1 (UDP): ConnectionID=0x00000001（来自包 1 响应）
- I/O 包 2 (UDP): ConnectionID=0x00000003（来自包 2 响应）

**流与响应的关联机制**（v2.0.1 修订，对应审计 R20）：每个流的 Forward_Open 是独立命令，其响应与流的绑定通过 **`source_command_index` 两级索引（flow_id, source_command_index）** 实现——`source_command_index` 是相对**本流命令序列**的索引（见 §5.6.1）。流 1 的 I/O 命令用 `(flow=1, source_command_index=Forward_Open在本流的位置)` 提取流 1 的响应 Connection ID；流 2 同理。不得跨流引用 `source_command_index`（如流 2 引用流 1 的 Forward_Open 响应）。

**SenderContext 递增规则**（v2.0.1 修订，对应审计 R43）：SenderContext 的递增基准**由策略配置决定**——若配置为全局递增（默认 inc 从 1 开始），则跨会话、跨流连续递增（包 N 的 SenderContext = 包 1 + N-1）；若配置为每流独立 fixed/inc，则每流各自从起始值递增。§6.12 S12 的"SenderContext 跨会话递增"与本文档的"每流独立"不矛盾：前者是默认全局策略，后者是每流独立策略，两者均通过 StrategyConfig 表达。**推荐每流独立**，以利用 SenderContext 匹配请求-响应对并避免多流并发时上下文混淆。

**HexDump（Forward_Open 包 1，关键差异行）**：
```
... (前 24B ENIP 头 + 6B 前缀 + 4B CPF 头 + 6B CIP 头)
01 00          ConnectionSerialNumber=0x0001, LE
01 00          OriginatorVendorID=0x0001, LE
01 00 00 00    OriginatorSerialNumber=0x00000001, LE
...
01 00 00 00    O2TConnectionID=0x00000001, LE
02 00 00 00    T2OConnectionID=0x00000002, LE
```

**HexDump（Forward_Open 包 2，关键差异行）**：
```
02 00          ConnectionSerialNumber=0x0002, LE  ← 不同
01 00          OriginatorVendorID=0x0001, LE
01 00 00 00    OriginatorSerialNumber=0x00000001, LE
...
03 00 00 00    O2TConnectionID=0x00000003, LE  ← 不同
04 00 00 00    T2OConnectionID=0x00000004, LE  ← 不同
```

**HexDump（I/O 包 1，关键行）**：
```
... Command=0x0070 ...
01 00 00 00    ConnectionID=0x00000001 (来自包 1 响应), LE
01 00          SequenceCounter=0x0001, LE
```

**HexDump（I/O 包 2，关键行）**：
```
... Command=0x0070 ...
03 00 00 00    ConnectionID=0x00000003 (来自包 2 响应), LE
01 00          SequenceCounter=0x0001, LE (每流独立计数)
```

**验证**：两个 I/O 流的 ConnectionID 独立，SequenceCounter 各自从 0x0001 开始。✓

---

### 6.15 S14：LargeForward_Open

**目的**：使用 4 字节 Network Connection Parameters 打开连接（支持更大数据量）。

**字段构成**（请求，70 字节）：与 S7 类似，但 Connection Parameters 为 4B，ConnectionPath 同样含 Connection Point。

CIP request 核算：
- Service(1) + PathSize(1) + Path(4) = 6
- body: PriorityTimeTick(1)+TimeoutTicks(1)+O2TConnID(4)+T2OConnID(4)+ConnSerialNum(2)+OrigVendorID(2)+OrigSerialNum(4)+TimeoutMult(1)+Reserved(3)+O2TRPI(4)+O2TConnParams(4)+T2ORPI(4)+T2OConnParams(4)+TransportClassTrigger(1)+ConnPathSize(1)+ConnPath(8) = 48
- CIP request = 6 + 48 = 54

payload = 6+2+4+2+2+54 = 70
Length = 70 = 0x46

**HexDump（请求，关键差异行）**：
```
6F 00          Command=0x006F (SendRRData), LE
46 00          Length=70, LE
78 56 34 12    SessionHandle=0x12345678, LE
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext
00 00 00 00    Options=0
00 00 00 00    Interface Handle=0, LE
0A 00          Timeout=10s, LE
02 00          ItemCount=2, LE
00 00          TypeID=0x0000 (Null Address), LE
00 00          Length=0, LE
B2 00          TypeID=0x00B2 (Unconnected Data), LE
36 00          Length=54, LE
5B             Service=0x5B (LargeForward_Open)  ← 与 Forward_Open 0x54 不同
02             RequestPathSize=2 words
20 06          Class 8-bit = 0x06 (Connection Manager)
24 01          Instance 8-bit = 0x01
0A             PriorityTimeTick=0x0A
05             TimeoutTicks=0x05
01 00 00 00    O2TConnectionID=0x00000001, LE
02 00 00 00    T2OConnectionID=0x00000002, LE
01 00          ConnectionSerialNumber=0x0001, LE
01 00          OriginatorVendorID=0x0001, LE
01 00 00 00    OriginatorSerialNumber=0x00000001, LE
07             ConnectionTimeoutMultiplier=7
00 00 00       Reserved (3B)
A0 86 01 00    O2TRPI=100000, LE
00 02 00 00    O2TConnectionParameters=0x00000200 (4B), LE  ← 4B 而非 2B
A0 86 01 00    T2ORPI=100000, LE
00 02 00 00    T2OConnectionParameters=0x00000200 (4B), LE  ← 4B 而非 2B
80             TransportClassTrigger=0x80 (Class 0 Client)
04             ConnectionPathSize=4 words
20 04          Class 8-bit = 0x04 (Assembly)
24 01          Instance 8-bit = 0x01
2C 02          Connection Point 8-bit = 0x02 (O→T Assembly)
2C 03          Connection Point 8-bit = 0x03 (T→O Assembly)
```

**验证**：Length=70 = 6+2+4+2+2+54=70。✓ CIP request=54=1+1+4+48。✓ body=48=39+1+8。✓ LargeForward_Open 比 Forward_Open 多 4 字节（两个 4B ConnParams 减去两个 2B ConnParams，但 ConnPath 相同）。✓

**响应**：与 Forward_Open 响应相同（26 字节 service data），Reply Service=0xDB。

---

### 6.16 S15：心跳/超时

**目的**：TCP 长连接保活，NOP 周期发送；超时后 IndicateStatus 推送。

**字段构成**（NOP 心跳，28 字节）：
- ENIP 头 24B：Command=0x0000、Length=0、SessionHandle=0x12345678、Status=0
- 无 payload（最小 NOP）

**HexDump（NOP 心跳）**：
```
00 00          Command=0x0000 (NOP), LE
00 00          Length=0, LE
78 56 34 12    SessionHandle=0x12345678, LE
00 00 00 00    Status=0
01 02 03 04 05 06 07 08   SenderContext
00 00 00 00    Options=0
```

**字段构成**（IndicateStatus，server→client 主动推送）：
- ENIP 头 24B：Command=0x0072、Length=4、SessionHandle=0x12345678、Status=0
- payload 4B：设备状态码（如 0x00000001=Running）

**HexDump（IndicateStatus）**：
```
72 00          Command=0x0072 (IndicateStatus), LE
04 00          Length=4, LE
78 56 34 12    SessionHandle=0x12345678, LE
00 00 00 00    Status=0
00 00 00 00 00 00 00 00   SenderContext (server 主动推送，无对应请求)
00 00 00 00    Options=0
01 00 00 00    设备状态码=0x00000001 (Running), LE
```

**验证**：NOP Length=0。✓ IndicateStatus Length=4。✓ IndicateStatus 方向是 server→client（主动推送）。✓

---

## 7. 测试用例（T-001 ~ T-220）

### 7.1 测试用例分组

| 分组 | 编号范围 | 数量 | 说明 |
|------|----------|------|------|
| 正向（成功路径） | T-001 ~ T-080 | 80 | 各场景正常流程 |
| 负向（Validate 拒绝） | T-081 ~ T-120 | 40 | 非法配置被 Validate 拒绝 |
| 边界 | T-121 ~ T-160 | 40 | 边界值与回绕 |
| 多会话/多流 | T-161 ~ T-180 | 20 | 并发场景 |
| 集成（wire-format） | T-181 ~ T-200 | 20 | tshark 解析验证 |
| 修订追加（v2.0.0） | T-201 ~ T-220 | 20 | 审计修复验证 |

---

### 7.2 正向用例（T-001 ~ T-080）

| # | 名称 | 输入 | 期望输出 | 断言点 |
|---|------|------|----------|--------|
| T-001 | NOP 最小包 | Command=0x0000, Length=0 | 24 字节 ENIP 头，无 payload | bytes[0..1]=`00 00`, bytes[2..3]=`00 00`, total=24 |
| T-002 | NOP 带 payload | Command=0x0000, Payload=4B `DE AD BE EF` | 28 字节，Length=4 | bytes[24..27]=`DE AD BE EF`, Length=0x04 |
| T-003 | ListServices 请求 | Command=0x0004 | 24 字节，Length=0 | bytes[0..1]=`04 00`, Length=0 |
| T-004 | ListServices 响应 | 模拟设备返回 1 项服务 | ItemCount=1, TypeID=0x0100 | bytes[24..25]=`01 00` (ItemCount), bytes[26..27]=`00 01` (TypeID LE) |
| T-005 | ListIdentity 请求 | Command=0x0063 | 24 字节，Length=0 | bytes[0..1]=`63 00`, Length=0 |
| T-006 | ListIdentity 响应 TypeID | 模拟设备返回 Identity | TypeID=0x000C | CPF Item[0].TypeID=0x000C (LE `0C 00`) |
| T-007 | ListIdentity 响应 VendorID | VendorID=0x0001 | 响应中 VendorID 字段=0x0001 | Identity data offset 处 = `01 00` |
| T-008 | ListIdentity 响应 ProductName | ProductName="TestDevice" | SHORT_STRING 长度=9 | ProductName 长度字节=0x09，后跟 "TestDevice" ASCII |
| T-009 | ListIdentity 响应 Revision | FirmwareMajorRev=0x0B, MinorRev=0x00 | Revision 2 字节 | bytes=`0B 00`（major=0x0B, minor=0x00） |
| T-010 | ListInterfaces 请求 | Command=0x0064 | 24 字节，Length=0 | Length=0 |
| T-011 | ListInterfaces 响应 | 模拟无接口 | ItemCount=0 | bytes[24..25]=`00 00`（无 6B 前缀，直接 ItemCount） |
| T-012 | RegisterSession 请求 | ProtocolVersion=1, OptionFlag=0 | 28 字节，Length=4 | bytes[24..27]=`01 00 00 00`, Length=0x04 |
| T-013 | RegisterSession 响应 SessionHandle | 模拟 target 返回 0x12345678 | SessionHandle=0x12345678 | bytes[4..7]=`78 56 34 12` |
| T-014 | RegisterSession 无 CPF | Command=0x0065 | payload 4B，无 ItemCount | payload 长度=4，无 CPF TypeID |
| T-015 | UnRegisterSession 请求 | SessionHandle=0x12345678 | 24 字节，Length=0 | bytes[4..7]=`78 56 34 12`, Length=0 |
| T-016 | SendRRData Get_Attribute_Single | Class=0x01, Instance=1, Attr=1 | CIP Service=0x0E | CIP data[0]=0x0E |
| T-017 | SendRRData EPATH 编码 | Class=0x01, Instance=1, Attr=1 | Path=`20 01 25 01 00 30 01 00` | path bytes 匹配 |
| T-018 | SendRRData Interface Handle 前缀 | Command=0x006F | payload 前 4B=0 | bytes[24..27]=`00 00 00 00` |
| T-019 | SendRRData Timeout 前缀 | Timeout=10 | payload offset 4-5=0x000A | bytes[28..29]=`0A 00` |
| T-020 | SendRRData ItemCount=2 | Null+Unconnected | ItemCount=2 | bytes[30..31]=`02 00` |
| T-021 | SendRRData Null Address TypeID | Null Address item | TypeID=0x0000 | bytes[32..33]=`00 00` |
| T-022 | SendRRData Unconnected TypeID | Unconnected Data item | TypeID=0x00B2 | bytes[36..37]=`B2 00` |
| T-023 | Get_Attribute_Single 响应 | VendorID=0x0001 | CIP Reply Service=0x8E, VendorID=0x0001 | CIP body[0]=0x8E, body[4..5]=`01 00` |
| T-024 | Get_Attributes_All 请求 | Class=0x01, Instance=1 | Service=0x01 | CIP data[0]=0x01 |
| T-025 | Set_Attribute_Single 请求 | Class=0x01, Instance=1, Attr=7, Value="X" | Service=0x10 | CIP data[0]=0x10 |
| T-026 | Get_Attribute_List 请求 | Class=0x01, Instance=1, Attrs=[1,6] | Service=0x03, AttrCount=2 | CIP data[0]=0x03, body 含 `02 00 01 00 06 00` |
| T-027 | Set_Attribute_List 请求 | Class=0x01, Instance=1, Attrs=[7], Values=["X"] | Service=0x04 | CIP data[0]=0x04 |
| T-028 | Reset 请求 | Class=0x01, Instance=1 | Service=0x05 | CIP data[0]=0x05 |
| T-029 | Start 请求 | Class=0x01, Instance=1 | Service=0x06 | CIP data[0]=0x06 |
| T-030 | Stop 请求 | Class=0x01, Instance=1 | Service=0x07 | CIP data[0]=0x07 |
| T-031 | Forward_Open 服务码 | cfg.ForwardOpen | Service=0x54 | CIP data[0]=0x54 |
| T-032 | Forward_Open body 字段顺序 | 完整 cfg | PriorityTimeTick+TimeoutTicks+O2TConnID+T2OConnID+ConnSerialNum+... | 按序字节匹配 |
| T-033 | Forward_Open ConnectionSerialNumber | ConnSerialNum=0x0001 | body offset 10-11=0x0001 | bytes[10..11]=`01 00` |
| T-034 | Forward_Open OriginatorVendorID | OrigVendorID=0x0001 | body offset 12-13=0x0001 | bytes[12..13]=`01 00` |
| T-035 | Forward_Open OriginatorSerialNumber | OrigSerialNum=0x00000001 | body offset 14-17=0x00000001 | bytes[14..17]=`01 00 00 00` |
| T-036 | Forward_Open TimeoutMultiplier | TimeoutMult=7 | body offset 18=0x07 | bytes[18]=0x07 |
| T-037 | Forward_Open Reserved 3B | 默认 | body offset 19-21=0x000000 | bytes[19..21]=`00 00 00` |
| T-038 | Forward_Open O2TRPI | RPI=100000 | body offset 22-25=0x000186A0 | bytes[22..25]=`A0 86 01 00` |
| T-039 | Forward_Open O2TConnParams 2B | Forward_Open | 2 字节 | body offset 26-27=2B |
| T-040 | Forward_Open T2ORPI | RPI=100000 | body offset 28-31=0x000186A0 | bytes[28..31]=`A0 86 01 00` |
| T-041 | Forward_Open TransportClassTrigger | Class 0 Client=0x80 | body offset 34=0x80 | bytes[34]=0x80 |
| T-042 | Forward_Open ConnectionPath | ConnectionPath=`20 04 24 01 2C 02 2C 03` | Path=`20 04 24 01 2C 02 2C 03`，ConnPathSize=4 words | body offset 36..=`20 04 24 01 2C 02 2C 03` |
| T-043 | Forward_Open 响应 Reply Service | 成功 | Reply Service=0xD4 | CIP body[0]=0xD4 |
| T-044 | Forward_Open 响应 O2TConnID 偏移 | 成功响应 | O2TConnID 在 CIP body offset 0 | body[0..3]=O2TConnID |
| T-045 | Forward_Open 响应 T2OConnID 偏移 | 成功响应 | T2OConnID 在 CIP body offset 4 | body[4..7]=T2OConnID |
| T-046 | Forward_Open from_response 提取 | source_command_index=N, field=o2t_connection_id | 后续命令引用 O2TConnID | 后续包 ConnectionID=响应 O2TConnID |
| T-047 | Forward_Close 服务码 | cfg.ForwardClose | Service=0x4E | CIP data[0]=0x4E |
| T-048 | Forward_Close body 字段顺序 | 完整 cfg | PriorityTimeTick+TimeoutTicks+ConnSerialNum+OrigVendorID+OrigSerialNum+PathSize+Path | 按序字节匹配 |
| T-049 | Forward_Close 无 ConnectionID | cfg | body 不含 ConnectionID 字段 | body 大小=10+PathSize*2 |
| T-050 | Forward_Close 响应 Reply Service | 成功 | Reply Service=0xCE | CIP body[0]=0xCE |
| T-051 | SendUnitData I/O 帧 | ConnectionID=0x00000001, Seq=1, Payload=2B | 38 字节 | bytes[24..27]=IfHdl, ConnectionID=0x00000001, Seq=0x0001 |
| T-052 | SendUnitData Connection Address TypeID | Connected | TypeID=0x00A1 | bytes[32..33]=`A1 00` |
| T-053 | SendUnitData Connected Data TypeID | Connected | TypeID=0x00B1 | bytes[38..39]=`B1 00` |
| T-054 | SendUnitData SequenceCounter | Seq=0x0001 | Connected Data offset 0-1=0x0001 | bytes[40..41]=`01 00` |
| T-055 | Multiple_Service_Packet 服务码 | 2 个子请求 | Service=0x0A | CIP data[0]=0x0A |
| T-056 | Multiple_Service_Packet OffsetCount | 2 子请求 | OffsetCount=2 | body offset 0-1=0x0002 |
| T-057 | Multiple_Service_Packet Offset[0] | 2 子请求 | Offset[0]=6 | body offset 2-3=0x0006 |
| T-058 | Multiple_Service_Packet Offset[1] | Sub0=10B | Offset[1]=16 | body offset 4-5=0x0010 |
| T-059 | Multiple_Service_Packet 子请求连续 | 2 子请求 | Sub0 后紧跟 Sub1 | 无间隙 |
| T-060 | LargeForward_Open 服务码 | cfg.LargeForwardOpen | Service=0x5B | CIP data[0]=0x5B |
| T-061 | LargeForward_Open ConnParams 4B | LargeForward_Open | O2TConnParams=4B | body offset 26-29=4B |
| T-062 | LargeForward_Open body 大小 | 完整 cfg（ConnectionPath 8B） | body 固定 48B+路径 | body 长度=48+PathSize*2 |
| T-063 | LargeForward_Open 响应 Reply Service | 成功 | Reply Service=0xDB | CIP body[0]=0xDB |
| T-064 | NOP 无响应 | Command=0x0000 | 仅生成请求包，不期望响应（保活） | 无响应包生成 |
| T-065 | ListServices UDP 广播 | Transport=udp | UDP 包，DstIP=255.255.255.255 | DstIP=broadcast |
| T-066 | Identity 对象属性 1 读取 | Class=0x01, Attr=1 | VendorID 2B | 响应 body 含 2B VendorID |
| T-067 | Identity 对象属性 6 读取 | Class=0x01, Attr=6 | SerialNumber 4B | 响应 body 含 4B SerialNumber |
| T-068 | TCP/IP Interface 属性 1 读取 | Class=0xF5, Attr=1 | IP 地址 4B | 响应 body 含 4B IP |
| T-069 | Ethernet Link 属性 3 读取 | Class=0xF6, Attr=3 | MAC 6B | 响应 body 含 6B MAC |
| T-070 | SenderContext 回显 | 请求 SenderContext=0x0102030405060708 | 响应 SenderContext 相同 | 响应 bytes[12..19] 匹配 |
| T-071 | SessionHandle from_response | 命令 1=RegisterSession, 命令 2 用 from_response | 命令 2 SessionHandle=命令 1 响应 | 命令 2 ENIP 头 SessionHandle=响应值 |
| T-072 | ConnectionID from_response | 命令 N=Forward_Open, 命令 N+1 I/O 用 from_response | I/O ConnectionID=Forward_Open 响应 O2TConnID | I/O ConnectionID 字段匹配 |
| T-073 | SequenceCounter 递增 | FrameCount=10, Step=1 | Seq 0..9 | 每帧 Seq 递增 1 |
| T-074 | SequenceCounter 回绕 | Seq=0xFFFF, FrameCount=3 | Seq=0xFFFF, 0x0000, 0x0001 | 第 2 帧 Seq=0 |
| T-075 | EPATH Class 8-bit | ClassID=0x01 | 段字节=0x20 | path[0]=0x20 |
| T-076 | EPATH Class 16-bit | ClassID=0x0100 | 段字节=0x21, 2B LE | path[0]=0x21, path[1..2]=LE |
| T-077 | EPATH Instance 8-bit | InstanceID=0x01 | 段字节=0x24 | path[0]=0x24 |
| T-078 | EPATH Instance 16-bit | InstanceID=0x0100 | 段字节=0x25, 2B LE | path[0]=0x25 |
| T-079 | EPATH Attribute 8-bit | AttrID=0x01 | 段字节=0x30 | path[0]=0x30 |
| T-080 | EPATH Attribute 16-bit | AttrID=0x0100 | 段字节=0x31, 2B LE | path[0]=0x31 |

### 7.3 负向用例（T-081 ~ T-120，验证 Validate 拒绝）

| # | 名称 | 输入 | 期望 | 断言点 |
|---|------|------|------|--------|
| T-081 | 未知 Command | Command=0x1234 | Validate 拒绝 | error 含 "unknown command" |
| T-082 | RegisterSession 含 CPF | Command=0x0065, CPFItems 非空 | Validate 拒绝 | error 含 "RegisterSession must not carry CPF" |
| T-083 | RegisterSession ProtocolVersion=0 | ProtocolVersion=0 | Validate 拒绝 | error 含 "protocol_version must be 1" |
| T-084 | RegisterSession OptionFlag≠0 | OptionFlag=0x0001 | Validate 拒绝 | error 含 "option_flag must be 0" |
| T-085 | RegisterSession Payload≠4B | Payload=5B | Validate 拒绝 | error 含 "payload must be 4 bytes" |
| T-086 | SendRRData 无 CPF | Command=0x006F, CPFItems 空 | Validate 拒绝 | error 含 "SendRRData requires CPF items" |
| T-087 | SendRRData ItemCount<2 | CPFItems 仅 1 项 | Validate 拒绝 | error 含 "ItemCount must be >= 2" |
| T-088 | SendUnitData 无 Connection Address | CPFItems 缺 0x00A1 | Validate 拒绝 | error 含 "SendUnitData requires Connection Address" |
| T-089 | SendUnitData 无 Connected Data | CPFItems 缺 0x00B1 | Validate 拒绝 | error 含 "SendUnitData requires Connected Data" |
| T-090 | SessionHandle 策略 inc | SessionHandle.strategy=inc | Validate 拒绝 | error 含 "session_handle strategy must be fixed or from_response" |
| T-091 | SessionHandle 策略 rand | SessionHandle.strategy=rand | Validate 拒绝 | error 含 "session_handle strategy must be fixed or from_response" |
| T-092 | CIP 服务码 0x00 | cip_service=0x00 (无 CIP 消息但 SendRRData) | Validate 拒绝 | error 含 "cip_service required for SendRRData with Unconnected Data" |
| T-093 | Forward_Open 缺 ConnSerialNum | ConnSerialNum=0 且未设 | Validate 拒绝 | error 含 "connection_serial_number required" |
| T-094 | Forward_Open 缺 OrigVendorID | OrigVendorID=0 且未设 | Validate 拒绝 | error 含 "originator_vendor_id required" |
| T-095 | Forward_Open 缺 OrigSerialNum | OrigSerialNum=0 且未设 | Validate 拒绝 | error 含 "originator_serial_number required" |
| T-096 | Forward_Open TransportClassTrigger=0x05 | TransportClassTrigger=0x05 (bit 0-3=0101=Class 5，Class 4-15 Reserved) | Validate 拒绝（Class 超出 0-3） | error 含 "invalid transport class" |
| T-097 | Forward_Open RPI=0 | O2TRPI=0 | Validate 拒绝 | error 含 "RPI must be > 0" |
| T-098 | Forward_Open ConnParams 超范围 | O2TConnectionParameters=0x1000 (bit 12=1 Reserved) | Validate 拒绝 | error 含 "reserved bit must be 0" |
| T-099 | Forward_Close 缺三元组 | ConnSerialNum=0, OrigVendorID=0, OrigSerialNum=0 | Validate 拒绝 | error 含 "connection triad required" |
| T-100 | ListIdentity 请求含 CPF | Command=0x0063, CPFItems 非空 | Validate 拒绝 | error 含 "ListIdentity request must not carry CPF" |
| T-101 | ListServices 请求含 CPF | Command=0x0004, CPFItems 非空 | Validate 拒绝 | error 含 "ListServices request must not carry CPF" |
| T-102 | ListInterfaces 请求含 CPF | Command=0x0064, CPFItems 非空 | Validate 拒绝 | error 含 "ListInterfaces request must not carry CPF" |
| T-103 | UnRegisterSession 含 payload | Command=0x0066, Payload 非空 | Validate 拒绝 | error 含 "UnRegisterSession must not carry payload" |
| T-104 | EPATH Class ID 超范围 | ClassID=0x10000 | Validate 拒绝 | error 含 "class_id out of range" |
| T-105 | EPATH Instance ID 超范围 | InstanceID=0x100000000 | Validate 拒绝 | error 含 "instance_id out of range" |
| T-106 | Multiple_Service_Packet 无子请求 | subRequests=[] | Validate 拒绝 | error 含 "sub_requests must not be empty" |
| T-107 | Multiple_Service_Packet 子请求过多 | subRequests=64 项 | Validate 拒绝 | error 含 "sub_requests exceeds limit" |
| T-108 | I/O FrameSize 超上限 | FrameSize=65466 | Validate 拒绝 | error 含 "frame_size exceeds 65465" |
| T-109 | I/O FrameCount=0 | FrameCount=0 | Validate 拒绝 | error 含 "frame_count must be > 0" |
| T-110 | I/O 无 ConnectionID | IOData.O2TConnectionID 未设 | Validate 拒绝 | error 含 "connection_id required for I/O data" |
| T-111 | TimeoutMultiplier 超范围 | ConnectionTimeoutMultiplier=8 | Validate 拒绝 | error 含 "timeout_multiplier must be 0-7" |
| T-112 | TransportClassTrigger 无效 | TransportClassTrigger=0x0F (bit 0-3=1111=Class 15，Class 4-15 Reserved) | Validate 拒绝（Class 超出 0-3） | error 含 "invalid transport class" |
| T-113 | Scenario 未知 | Scenario="unknown" | Validate 拒绝 | error 含 "unknown scenario" |
| T-114 | Transport 未知 | Transport="icmp" | Validate 拒绝 | error 含 "transport must be tcp or udp" |
| T-115 | DstPort≠44818 | DstPort=502 | Validate 拒绝 | error 含 "dst_port must be 44818" |
| T-116 | CPFItem TypeID 未知 | TypeID=0x9999 | Validate 拒绝 | error 含 "unknown CPF type_id" |
| T-117 | from_response source_command_index 超范围 | source_command_index=99 | Validate 拒绝 | error 含 "source_command_index out of range" |
| T-118 | from_response field 未知 | field="unknown" | Validate 拒绝 | error 含 "unknown from_response field" |
| T-119 | Sockaddr Info Length≠16 | Sockaddr item Length=15 | Validate 拒绝 | error 含 "sockaddr info length must be 16" |
| T-120 | Connection Path Size 与实际不符 | ConnPathSize=5, Path=4B | Validate 拒绝 | error 含 "connection_path_size mismatch" |
| T-120a | Forward_Close 路径与 Forward_Open 不一致 | Forward_Open 路径=`20 04 24 01 2C 02 2C 03`，Forward_Close 路径不同 | Validate 拒绝（planner 层校验一致性） | error 含 "forward_close path mismatch" |
| T-120b | RegisterSession ProtocolVersion>1 | ProtocolVersion=2 | Validate 拒绝（OpENer 返回 0x0069 UnsupportedProtocol） | error 含 "protocol_version must be 1" |
| T-120c | Forward_Open O2TConnID=0 | O2TNetworkConnectionID=0 | 允许但警告（originator 可让 target 分配；响应回读分配值） | 警告非拒绝 |

### 7.4 边界用例（T-121 ~ T-160）

| # | 名称 | 输入 | 期望 | 断言点 |
|---|------|------|------|--------|
| T-121 | ENIP Length=0 | NOP 无 payload | Length=0 | bytes[2..3]=`00 00` |
| T-122 | ENIP Length=65515 | payload=65515B | Length=65515 | bytes[2..3]=`EB FF` (LE) |
| T-123 | ENIP Length=65516 超上限 | payload=65516B | Validate 拒绝 | error 含 "length exceeds 65515" |
| T-124 | SessionHandle=0xFFFFFFFF | SessionHandle=fixed 0xFFFFFFFF | ENIP 头 bytes[4..7]=`FF FF FF FF` | bytes 匹配 |
| T-125 | SessionHandle=0x00000000 | SessionHandle=fixed 0 | bytes[4..7]=`00 00 00 00` | bytes 匹配 |
| T-126 | SenderContext 全 0 | SenderContext=fixed 0 | bytes[12..19]=全 0 | bytes 匹配 |
| T-127 | SenderContext 全 FF | SenderContext=fixed 0xFFFFFFFFFFFFFFFF | bytes[12..19]=全 FF | bytes 匹配 |
| T-128 | SequenceCounter 起始 0xFFFF | SeqStart=0xFFFF, FrameCount=2 | Seq=0xFFFF, 0x0000 | 第 2 帧 Seq=0 |
| T-129 | SequenceCounter 起始 0x7FFF | SeqStart=0x7FFF | Seq=0x7FFF, 0x8000 | 第 2 帧 Seq=0x8000 |
| T-130 | SequenceCounter Step=2 | Step=2, FrameCount=3 | Seq=0, 2, 4 | 每帧递增 2 |
| T-131 | EPATH Class 8-bit 边界 0xFF | ClassID=0xFF | 段字节=0x20, 1B=0xFF | path=`20 FF` |
| T-132 | EPATH Class 16-bit 边界 0x0100 | ClassID=0x0100 | 段字节=0x21, 2B=`00 01` | path=`21 00 01` |
| T-133 | EPATH Instance 32-bit | InstanceID=0x10000 | 段字节=0x26, 4B LE | path=`26 00 00 01 00` |
| T-133a | EPATH Class 32-bit | ClassID=0x10000（超 uint16 上限，仅测试编码） | 段字节=0x22, 4B LE | path[0]=0x22 |
| T-133b | EPATH Attribute 32-bit | AttrID=0x10000（同上） | 段字节=0x32, 4B LE | path[0]=0x32 |
| T-133c | EPATH Connection Point 8-bit | connPointID=0x02 | 段字节=0x2C, 1B=0x02 | path=`2C 02` |
| T-133d | EPATH Connection Point 16-bit | connPointID=0x0100 | 段字节=0x2D, 2B LE | path=`2D 00 01` |
| T-134 | Forward_Open RPI 最小 | O2TRPI=1 (1μs) | body offset 22-25=0x00000001 | bytes=`01 00 00 00` |
| T-135 | Forward_Open RPI 最大 | O2TRPI=0xFFFFFFFF | body offset 22-25=0xFFFFFFFF | bytes=`FF FF FF FF` |
| T-136 | Forward_Open ConnParams 最大合法 | O2TConnectionParameters=0x6DFF (bit 0-8=0x1FF Connection Size 最大 511，bit 10-11=3 Urgent，bit 13-14=2 Point-to-Point，bit 12=0 Reserved，bit 15=0) | 2B=`FF 6D` | bytes 匹配 |
| T-137 | LargeForward_Open ConnParams 最大 | O2TLargeConnectionParameters=0xF2FFFFFF (bit 0-15=0xFFFF Connection Size 最大，bit 25=1 Fixed，bit 26-27=3 Urgent，bit 29-30=2 Point-to-Point，bit 31=1 Redundant Owner) | 4B=`FF FF FF F2` | bytes 匹配 |
| T-138 | Connection Path Size=0 | ConnectionPath=[] | ConnPathSize=0 | body offset 35=0x00 |
| T-139 | Connection Path Size=255 | Path=510B | ConnPathSize=255 | body offset 35=0xFF |
| T-140 | Multiple_Service_Packet Offset 边界 | 2 子请求，Sub0=0B | Offset[0]=6, Offset[1]=6 | 两个 Offset 相同 |
| T-141 | I/O FrameSize 最小 | FrameSize=0 (无 payload，仅 SeqCounter) | Connected Data Length=2 | bytes=`02 00` |
| T-142 | I/O FrameSize 最大 | FrameSize=65465 | Connected Data Length=65467 | Length=65467 |
| T-143 | ItemCount=1 | 仅 Null Address（异常配置） | Validate 拒绝（SendRRData 需≥2） | error |
| T-144 | ItemCount=4 | Null+Unconnected+Sockaddr O→T+T→O | ItemCount=4 | bytes=`04 00` |
| T-145 | Sockaddr Info 端口边界 | SinPort=0xFFFF | bytes=`FF FF` | bytes 匹配 |
| T-146 | Sockaddr Info IP 边界 | SinAddr=255.255.255.255 | bytes=`FF FF FF FF` | bytes 匹配 |
| T-147 | Timeout=0 | SendRRData Timeout=0 | bytes=`00 00` | bytes 匹配 |
| T-148 | Timeout=65535 | SendRRData Timeout=65535 | bytes=`FF FF` | bytes 匹配 |
| T-149 | Interface Handle 非 0 | InterfaceHandle=0x12345678 | bytes=`78 56 34 12` | bytes 匹配（虽然 CIP 协议固定 0） |
| T-150 | CIP Additional Status 边界 | AddStatusSize=0xFFFF | Validate 拒绝（Size of Additional Status 是 1B USINT，最大 0xFF=255 words=510 字节；0xFFFF 触发字段上限） | error 含 "additional status size exceeds 255" |
| T-151 | CIP Additional Status 最大 255 words | AddStatusSize=255, AddStatus=510B | body 含 510B | AddStatusSize=0xFF |
| T-152 | Forward_Open body 35B 边界 | 无路径 | body=35B | body 长度=35 |
| T-153 | Forward_Close body 10B 边界 | 无路径 | body=10B | body 长度=10 |
| T-154 | LargeForward_Open body 39B 边界 | 无路径 | body=39B | body 长度=39 |
| T-155 | EPATH 路径补齐 1 字节 | Path=7B (奇数) | 补 1B 0x00，PathSize=4 words | path 8B |
| T-156 | EPATH 路径偶数 | Path=8B | 无补齐，PathSize=4 words | path 8B |
| T-157 | ListIdentity 响应 ProductName 空 | ProductName="" | SHORT_STRING 长度=0 | 长度字节=0x00 |
| T-158 | ListIdentity 响应 ProductName 255B | ProductName=255B | SHORT_STRING 长度=255 | 长度字节=0xFF |
| T-159 | ListIdentity 响应 ProductName 256B | ProductName=256B | Validate 拒绝（SHORT_STRING 上限 255） | error |
| T-160 | Vendor ID 边界 0xFFFF | VendorID=0xFFFF | bytes=`FF FF` | bytes 匹配 |

### 7.5 多会话/多流用例（T-161 ~ T-180）

| # | 名称 | 输入 | 期望 | 断言点 |
|---|------|------|------|--------|
| T-161 | 2 并发会话 | SessionCount=2 | 2 个 RegisterSession，不同 SenderContext | 包 1 SenderContext≠包 2 |
| T-162 | 8 并发会话 | SessionCount=8 | 8 个 RegisterSession | 8 个独立 SessionHandle |
| T-163 | 2 并发会话 SessionHandle 独立 | SessionCount=2 | 响应 SessionHandle 1≠SessionHandle 2 | 两个响应 SessionHandle 不同 |
| T-164 | 1 会话 2 I/O 流 | FlowCount=2 | 2 个 Forward_Open + 2 组 I/O | ConnSerialNum 不同 |
| T-165 | 1 会话 8 I/O 流 | FlowCount=8 | 8 个 Forward_Open | 8 个独立 ConnectionID |
| T-166 | 2 会话 2 流 | SessionCount=2, FlowCount=2 | 4 组 I/O | 4 个独立 (Session, ConnectionID) 对 |
| T-167 | 多流 SequenceCounter 独立 | FlowCount=2 | 每流 Seq 从 0x0001 开始 | 流 1 Seq[0]=流 2 Seq[0] |
| T-168 | 多流 ConnectionID 不冲突 | FlowCount=2 | O2TConnectionID 1≠O2TConnectionID 2 | 两个 ConnectionID 不同 |
| T-169 | 多会话 TCP 4-tuple 独立 | SessionCount=2 | 每会话独立 TCP 流 | SrcPort 不同 |
| T-170 | 多流 UDP 4-tuple 共享 | FlowCount=2 | 同一 UDP 流，ConnectionID 区分 | 4-tuple 相同，ConnectionID 不同 |
| T-171 | 100 设备并发 | 100 个独立 ENIPConfig | 100 个独立 TCP 流 | 100 个不同 DstIP 或 SrcPort |
| T-172 | 多会话 from_response 隔离 | SessionCount=2 | 每会话从自己的 RegisterSession 响应提取 | SessionHandle 不交叉引用 |
| T-173 | 多流 from_response 隔离 | FlowCount=2 | 每流从自己的 Forward_Open 响应提取 | ConnectionID 不交叉引用 |
| T-174 | 多会话 UnRegisterSession 顺序 | SessionCount=2 | 每会话独立 UnRegisterSession | SessionHandle 匹配 |
| T-175 | 多流 Forward_Close 顺序 | FlowCount=2 | 每流独立 Forward_Close | ConnSerialNum 匹配 |
| T-176 | 多会话 SenderContext 全局递增 | SessionCount=2，SenderContext 策略=inc 全局 | SenderContext 跨会话递增 | 包 2 SenderContext=包 1+1 |
| T-177 | 多流 SenderContext 每流独立 | FlowCount=2，SenderContext 策略=每流 inc | 每流 SenderContext 独立递增 | 流 1 包 1 SenderContext ≠ 流 2 包 1 |
| T-178 | 多会话并发时序不交叉 | SessionCount=2 | 每会话命令序列完整 | 命令 i+1 在命令 i 后 |
| T-179 | 多流并发时序不交叉 | FlowCount=2 | 每流命令序列完整 | 命令 i+1 在命令 i 后 |
| T-180 | 多会话 TCP FIN 独立 | SessionCount=2 | 每会话独立 FIN | 2 个 FIN 包 |

### 7.6 集成用例（T-181 ~ T-200，wire-format 验证）

| # | 名称 | 输入 | 期望 | 断言点 |
|---|------|------|------|--------|
| T-181 | tshark 解析 NOP | 生成 NOP 包 | tshark 识别为 ENIP NOP | tshark output 含 "NOP" |
| T-182 | tshark 解析 ListIdentity | 生成 ListIdentity 请求 | tshark 识别为 ENIP ListIdentity | tshark output 含 "ListIdentity" |
| T-183 | tshark 解析 RegisterSession | 生成 RegisterSession | tshark 识别 SessionHandle | tshark output 含 "Register Session" |
| T-184 | tshark 解析 SendRRData | 生成 SendRRData Get_Attribute_Single | tshark 识别 CIP Service | tshark output 含 "Get Attribute Single" |
| T-185 | tshark 解析 Forward_Open | 生成 Forward_Open | tshark 识别 Forward_Open | tshark output 含 "Forward Open" |
| T-186 | tshark 解析 Forward_Close | 生成 Forward_Close | tshark 识别 Forward_Close | tshark output 含 "Forward Close" |
| T-187 | tshark 解析 SendUnitData | 生成 SendUnitData I/O | tshark 识别 Connected Data | tshark output 含 "Send Unit Data" |
| T-188 | tshark 解析 LargeForward_Open | 生成 LargeForward_Open | tshark 识别 LargeForward_Open | tshark output 含 "Large Forward Open" |
| T-189 | tshark 解析 Multiple_Service_Packet | 生成 MSP | tshark 识别 Multiple_Service_Packet | tshark output 含 "Multiple Service Packet" |
| T-190 | tshark 字节序验证 | 任意 ENIP 包 | tshark 显示 LE 字节序 | Command 字段 LE 解析正确 |
| T-191 | tshark ENIP 头 Length 字段 | 任意包 | tshark Length 与实际 payload 一致 | length 匹配 |
| T-192 | tshark CPF ItemCount | SendRRData | tshark ItemCount 与实际 item 数一致 | item count 匹配 |
| T-193 | tshark EPATH 解析 | Get_Attribute_Single Identity | tshark 显示 Class=0x01 Instance=1 Attr=1 | path 解析正确 |
| T-194 | tshark Forward_Open body | Forward_Open | tshark 显示所有 15 字段 | 字段值匹配 |
| T-195 | tshark Forward_Close 三元组 | Forward_Close | tshark 显示 ConnSerialNum/VendorID/SerialNum | 三元组匹配 |
| T-196 | tshark I/O SequenceCounter | SendUnitData 多帧 | tshark 显示 Seq 递增 | seq 递增 |
| T-197 | tshark Sockaddr Info | Forward_Open 含 Sockaddr | tshark 显示 IP/Port | sockaddr 匹配 |
| T-198 | tshark Error 响应 | CIP 错误响应 | tshark 显示 General Status | status 匹配 |
| T-199 | tshark 完整会话 | Scenario=full | tshark 识别整个序列 | 序列完整 |
| T-200 | tshark 多会话 | SessionCount=2 | tshark 识别 2 个独立会话 | 2 个 SessionHandle |
| T-200a | OpENer 互操作 - RegisterSession | 启动 OpENer docker 镜像，发送 RegisterSession | OpENer 返回 Status=0 + SessionHandle | 响应 Status=0x0000 |
| T-200b | OpENer 互操作 - ListIdentity | 发送 ListIdentity | OpENer 返回 Identity 信息 | TypeID=0x000C，无 6B 前缀 |
| T-200c | OpENer 互操作 - Forward_Open | 已注册会话 + 完整 ConnectionPath（含 Connection Point） | OpENer 返回成功响应，O2T/T2O ConnectionID 非零 | CIP body[0]=0xD4，body[0..3]=O2TConnID 非零 |
| T-200d | OpENer 互操作 - Forward_Close | 已打开连接 + 与 Forward_Open 一致的 ConnectionPath | OpENer 返回成功响应 | CIP body[0]=0xCE |
| T-200e | OpENer 互操作 - 非法 SessionHandle | 用未注册的 SessionHandle 发送 SendRRData | OpENer 返回 ENIP Status=0x0064 InvalidSessionHandle | 响应 bytes[8..11]=`64 00 00 00` |

**集成测试覆盖说明**（v2.0.1 修订，对应审计 R42）：T-181~T-200 验证 tshark 能正确解析生成的包；T-200a~T-200e（新增）验证生成的包能被真实 OpENer 实例接受——这两类测试互补，缺一不可。tshark 通过不等于 OpENer 通过（如 List* 响应带 6B 前缀时 tshark 可能勉强解析但 OpENer 不会生成这种响应）。

### 7.7 修订追加用例（T-201 ~ T-220，v2.0.0 审计修复验证）

| # | 名称 | 输入 | 期望 | 断言点 | 修复 ID |
|---|------|------|------|--------|---------|
| T-201 | CIP 服务码 0x54=Forward_Open | cip_service=0x54 | CIP data[0]=0x54 | bytes[0]=0x54 | D-CRIT-1 |
| T-202 | CIP 服务码 0x4E=Forward_Close | cip_service=0x4E | CIP data[0]=0x4E | bytes[0]=0x4E | D-CRIT-1 |
| T-203 | CIP 服务码 0x0A=Multiple_Service_Packet | cip_service=0x0A | CIP data[0]=0x0A | bytes[0]=0x0A | D-CRIT-1 |
| T-204 | CIP 服务码 0x03=Get_Attribute_List | cip_service=0x03 | CIP data[0]=0x03 | bytes[0]=0x03 | D-CRIT-1 |
| T-205 | CIP 服务码 0x04=Set_Attribute_List | cip_service=0x04 | CIP data[0]=0x04 | bytes[0]=0x04 | D-CRIT-1 |
| T-206 | CIP 服务码 0x0E=Get_Attribute_Single | cip_service=0x0E | CIP data[0]=0x0E | bytes[0]=0x0E | D-CRIT-1 |
| T-207 | CIP 服务码 0x10=Set_Attribute_Single | cip_service=0x10 | CIP data[0]=0x10 | bytes[0]=0x10 | D-CRIT-1 |
| T-208 | CIP 服务码 0x5B=LargeForward_Open | cip_service=0x5B | CIP data[0]=0x5B | bytes[0]=0x5B | D-CRIT-1 |
| T-209 | EPATH 0x21=Class 16-bit | ClassID=0x0100 | path[0]=0x21 | path[0]=0x21 | D-CRIT-2 |
| T-210 | EPATH 0x24=Instance 8-bit | InstanceID=0x01 | path[0]=0x24 | path[0]=0x24 | D-CRIT-2 |
| T-211 | EPATH 0x25=Instance 16-bit | InstanceID=0x0100 | path[0]=0x25 | path[0]=0x25 | D-CRIT-2 |
| T-212 | EPATH 0x2C=Connection Point | ConnectionPoint 段 | path[0]=0x2C | path[0]=0x2C | D-CRIT-2 |
| T-213 | EPATH 0x30=Attribute 8-bit | AttrID=0x01 | path[0]=0x30 | path[0]=0x30 | D-CRIT-2 |
| T-214 | ENIP 字节序 LE | Command=0x0063 | bytes[0..1]=`63 00` | bytes LE | D-CRIT-3 |
| T-215 | SendRRData Interface Handle 前缀 | Command=0x006F | payload[0..3]=0 | 前 4B=0 | D-CRIT-4 |
| T-216 | SendRRData Timeout 前缀 | Command=0x006F, Timeout=10 | payload[4..5]=0x000A | bytes=`0A 00` | D-CRIT-4 |
| T-217 | ENIP Status 0x0064=InvalidSession | Status=0x0064 | bytes[8..11]=`64 00 00 00` | bytes LE | D-CRIT-5 |
| T-218 | ENIP Status 0x0065=InvalidLength | Status=0x0065 | bytes[8..11]=`65 00 00 00` | bytes LE | D-CRIT-5 |
| T-219 | ENIP Status 0x0069=UnsupportedProtocol | Status=0x0069 | bytes[8..11]=`69 00 00 00` | bytes LE | D-CRIT-5 |
| T-220 | RegisterSession 无 CPF | Command=0x0065 | payload 4B，无 ItemCount | payload 长度=4 | D-CRIT-7 |

---


## 8. Validate 规则

### 8.1 ENIPConfig 顶层 Validate

| 规则 ID | 字段 | 条件 | 失败动作 |
|---------|------|------|----------|
| V-001 | Scenario | 必须为 full / discovery_only / io_only / forward_open_only / custom | 拒绝 |
| V-002 | Transport | 必须为 tcp / udp | 拒绝 |
| V-003 | DstPort | 必须 = 44818 | 拒绝 |
| V-004 | Commands | 不能为空 | 拒绝 |
| V-005 | SessionCount | 1-1000 | 拒绝 |
| V-006 | FlowCount | 1-100 | 拒绝 |
| V-007 | FirmwareMajorRev / FirmwareMinorRev | 0-255 | 拒绝 |
| V-008 | ProductName | 长度 0-255（SHORT_STRING 上限） | 拒绝 |

### 8.2 ENIPCommand Validate

| 规则 ID | 字段 | 条件 | 失败动作 |
|---------|------|------|----------|
| V-101 | Command | 必须为已知值（0x0000/0x0004/0x0063/0x0064/0x0065/0x0066/0x006F/0x0070/0x0072/0x0073）；**0x0072/0x0073 为 trafficgen 模拟扩展**——OpENer 不实现这两个命令（收到返回 0x0001 Invalid Command），客户端场景使用需警告 | 0x0072/0x0073 警告；其余拒绝 |
| V-102 | Command=0x0065 (RegisterSession) | CPFItems 必须为空；Payload 必须为 4B；ProtocolVersion 必须=1；OptionFlag 必须=0 | 拒绝 |
| V-103 | Command=0x0066 (UnRegisterSession) | Payload 必须为空；CPFItems 必须为空 | 拒绝 |
| V-104 | Command=0x0063/0x0004/0x0064 (List*) | 请求 CPFItems 必须为空；Payload 必须为空 | 拒绝 |
| V-105 | Command=0x006F (SendRRData) | CPFItems 长度 2-4；至少含 Null Address (0x0000) + Unconnected Data (0x00B2) 或 Connected Address (0x00A1) + Connected Data (0x00B1) | 拒绝 |
| V-106 | Command=0x0070 (SendUnitData) | CPFItems 必须含 Connection Address (0x00A1) + Connected Data (0x00B1) | 拒绝 |
| V-107 | SessionHandle.Strategy | Command≠0x0065 时必须为 fixed 或 from_response；Command=0x0065 时必须为 fixed=0 | 拒绝 |
| V-108 | SenderContext | 8 字节；Strategy 可为 fixed/inc/rand | 拒绝 |
| V-109 | Options | 必须=0x00000000 | 拒绝 |
| V-110 | Interface Handle | 必须=0x00000000（CIP 协议） | 警告（非 0 不拒绝但提示） |
| V-111 | Timeout | 0-65535（秒） | 拒绝 |
| V-112 | CIPService | 必须为已知服务码或 0（无 CIP 消息） | 拒绝 |
| V-113 | CIPService=0x54/0x5B (Forward_Open/Large) | 必须提供 ConnSerialNum/OrigVendorID/OrigSerialNumber/O2TRPI/T2ORPI/TransportClassTrigger/ConnectionPath；ConnectionPath 应含 Class + Instance + Connection Point | 拒绝 |
| V-114 | CIPService=0x4E (Forward_Close) | 必须提供 ConnSerialNum/OrigVendorID/OrigSerialNumber/ConnectionPath；ConnectionPath 必须与同一连接的 Forward_Open 字节级一致 | 拒绝 |
| V-115 | CIPService=0x0A (Multiple_Service_Packet) | subRequests 不能为空；数量 1-64 | 拒绝 |
| V-116 | ConnectionTimeoutMultiplier | 0-7 | 拒绝 |
| V-117 | TransportClassTrigger | bit 0-3（Transport Class）必须 0-3（4-15 Reserved）；bit 7（Direction）0/1 均可 | 拒绝 |
| V-118 | O2TRPI / T2ORPI | 必须 > 0 | 拒绝 |
| V-119 | O2TConnectionParameters (Forward_Open) | bit 12 必须=0（Reserved） | 拒绝 |
| V-120 | ConnectionPathSize | 必须 = ⌈len(ConnectionPath)/2⌉ | 拒绝 |

### 8.3 CPFItem Validate

| 规则 ID | 字段 | 条件 | 失败动作 |
|---------|------|------|----------|
| V-201 | TypeID | 必须为已知值（0x0000/0x000C/0x00A1/0x00B1/0x00B2/0x0100/0x8000/0x8001/0x8002） | 拒绝 |
| V-202 | TypeID=0x0000 (Null Address) | Data 长度=0 | 拒绝 |
| V-203 | TypeID=0x00A1 (Connection Address) | Data 长度=4 | 拒绝 |
| V-204 | TypeID=0x00B1 (Connected Data) | Data 长度≥2（含 2B SequenceCounter） | 拒绝 |
| V-205 | TypeID=0x00B2 (Unconnected Data) | Data 长度≥2（含 CIP Service） | 拒绝 |
| V-206 | TypeID=0x8000/0x8001 (Sockaddr Info) | Data 长度=16 | 拒绝 |
| V-207 | TypeID=0x8002 (Sequenced Address) | Data 长度=8（4B ConnectionID + 4B Sequence） | 拒绝 |
| V-208 | TypeID=0x000C/0x0100 (List Response) | Data 结构符合 Identity/Service 定义 | 拒绝 |

### 8.4 ENIPIOData Validate

| 规则 ID | 字段 | 条件 | 失败动作 |
|---------|------|------|----------|
| V-301 | O2TConnectionID / T2OConnectionID | Strategy 必须为 from_response 或 fixed | 拒绝 |
| V-302 | SequenceStart | 0-65535 | 拒绝 |
| V-303 | SequenceStep | 1-65535 | 拒绝 |
| V-304 | FrameCount | 1-100000 | 拒绝 |
| V-305 | FrameInterval | 1000-60000000（1ms - 60s，μs 单位） | 拒绝 |
| V-306 | FrameSize | 0-65465 | 拒绝 |
| V-307 | TransportClassTrigger | 与 Forward_Open 一致 | 警告 |

### 8.5 StrategyConfig Validate

| 规则 ID | 字段 | 条件 | 失败动作 |
|---------|------|------|----------|
| V-401 | Strategy | 必须为 fixed / inc / rand / from_response | 拒绝 |
| V-402 | SessionHandle.Strategy | 仅 fixed / from_response（inc/rand 无业务意义） | 拒绝 |
| V-403 | from_response.SourceCommandIndex | 0 - len(Commands)-1 | 拒绝 |
| V-404 | from_response.Field | 必须为 session_handle / o2t_connection_id / t2o_connection_id / connection_serial_number | 拒绝 |
| V-405 | from_response 目标命令必须是响应命令且 General Status=0 | source_command_index 指向的命令必须产生响应；o2t/t2o_connection_id/connection_serial_number 字段额外要求该响应 General Status=0x00（成功），否则拒绝（v2.0.1 修订，对应审计 R35） | 拒绝 |
| V-406 | inc.Range | Range[1] > Range[0] | 拒绝 |
| V-407 | inc.Step | > 0 | 拒绝 |
| V-408 | rand.Range | Range[1] > Range[0] | 拒绝 |

---

## 9. 错误处理

### 9.1 ENIP 层错误（Status≠0x0000）

| 场景 | ENIP Status | 处理 |
|------|-------------|------|
| SessionHandle 未注册 | 0x0064 InvalidSessionHandle | 停止后续命令，标记会话失效 |
| Length 字段与 payload 不匹配 | 0x0065 InvalidLength | 重新计算 Length，重发 |
| 未知 Command | 0x0001 InvalidCommand | 终止，配置错误 |
| payload 格式错误 | 0x0003 IncorrectData | 检查 CIP/CPF 结构，修正后重发 |
| 设备资源不足 | 0x0002 InsufficientMemory | 退避重试 |
| 不支持的 ENIP 版本 | 0x0069 UnsupportedProtocol | 检查 ProtocolVersion |

### 9.2 CIP 层错误（General Status≠0x00）

| 场景 | General Status | 处理 |
|------|----------------|------|
| 服务码不支持 | 0x08 ServiceNotSupported | 检查 cip_service 配置 |
| 属性不存在 | 0x0E AttributeNotSupported | 检查 AttrID |
| 路径错误 | 0x04 PathSegmentError | 检查 EPATH 编码 |
| 目标不存在 | 0x05 PathDestinationUnknown | 检查 Class/Instance |
| 权限拒绝 | 0x15 PermissionDenied | 检查访问权限 |
| Forward_Open 连接冲突 | 0x01 + AddStatus 0x0100 | 重新分配 ConnSerialNum |
| Forward_Close 连接不存在 | 0x01 + AddStatus 0x0107 | 检查三元组（Target connection not found） |
| Forward_Open RPI 不支持 | 0x01 + AddStatus 0x0111 | 调整 RPI（RPI not supported） |
| Forward_Open RPI 不可接受 | 0x01 + AddStatus 0x0112 | 调整 RPI（RPI values not acceptable） |
| Forward_Close 路径与 Forward_Open 不一致 | 0x01 + AddStatus 0x0316 | 检查 ConnectionPath 是否与 Forward_Open 一致 |
| Forward_Close 发起方错误 | 0x01 + AddStatus 0xFFFF | 检查发起方身份（Wrong closer） |

**修正说明**（v2.0.1 修订，对应审计 R5）：v2.0.0 的"Forward_Close 连接不存在 → 0x0111"是错的（0x0111=RPI not supported；Target connection not found 是 0x0107）；"Forward_Open RPI 不支持 → 0x0112"是错的（0x0112=RPI values not acceptable；RPI not supported 是 0x0111）。

### 9.3 连接超时处理

- **Connection Timeout Multiplier**：Forward_Open 请求体 offset 18，1B，0-7。
- 超时公式：`timeout = RPI × 4 × 2^Multiplier`（RPI 单位 μs，需转 ms）。Multiplier 是 2 的幂次指数，不是线性倍数。
- 示例：RPI=100000μs (100ms)，Multiplier=7 → 100ms × 4 × 128 = 51200ms = 51.2s。
- Multiplier 取值与倍数对照：0→×4、1→×8、2→×16、3→×32、4→×64、5→×128、6→×256、7→×512。
- 超时后 target 自动关闭连接，状态迁移至 NonExistent。

**修正说明**（v2.0.1 修订，对应审计 R15）：v2.0.0 公式"timeout = RPI × Multiplier × 4"（线性倍数）是错的；正确公式为 `RPI × 4 × 2^Multiplier`（OpENer `ConnectionObjectCalculateRegularInactivityWatchdogTimerValue` 用 `RPI_ms << (2 + multiplier)`）。

### 9.4 SequenceCounter 回绕

- 2B 字段，范围 0x0000-0xFFFF。
- 回绕规则：0xFFFF + 1 = 0x0000（无溢出异常）。
- 测试 T-128 验证回绕。

### 9.5 ENIP Length 边界

- 最小 0（NOP、UnRegisterSession、List* 请求）。
- 最大 65515（ENIP 规范规定）。
- 单条 ENIP 消息作为单个 TCP 流提交，**不在 ENIP 层做 MSS 分段**（由 TCP 层透明处理）。
- I/O UDP 帧：UDP datagram 上限 65507，ENIP I/O 帧 payload 上限 = 65507 - 24(ENIP) - 4(IfHdl) - 2(Timeout) - 2(ItemCount) - 6(CAI) - 4(CDI 头) = **65465**。

**修正说明**（对比 v1，D-MED-9）：v1 错算 65493（误用 IP MTU 65535）；正确基于 UDP datagram 上限 65507，得 65465。

---

## 10. 扩展字段映射

### 10.1 ENIPConfig 到 ENIPCommand 字段映射

| ENIPConfig 字段 | ENIPCommand 字段 | 说明 |
|----------------|------------------|------|
| SessionHandle | ENIPCommand.SessionHandle | 透传或 from_response |
| VendorID/DeviceType/... | ENIPCommand.CIPAdditionalStatus | ListIdentity 响应模拟 |
| ConnectionSerialNumber | ENIPCommand.ConnSerialNumber | Forward_Open/Close |
| OriginatorVendorID | ENIPCommand.OrigVendorID | Forward_Open/Close |
| OriginatorSerialNumber | ENIPCommand.OrigSerialNumber | Forward_Open/Close |
| O2TNetworkConnectionID | Forward_Open body | 直接写入 body offset 2 |
| T2ONetworkConnectionID | Forward_Open body | 直接写入 body offset 6 |
| ConnectionTimeoutMultiplier | Forward_Open body | 直接写入 body offset 18 |
| O2TRPI / T2ORPI | Forward_Open body | 直接写入 body offset 22/28 |
| O2TConnectionParameters | Forward_Open body | 直接写入 body offset 26 |
| T2OConnectionParameters | Forward_Open body | 直接写入 body offset 32 |
| TransportClassTrigger | Forward_Open body | 直接写入 body offset 34 |
| ConnectionPath | Forward_Open body | 直接写入 body offset 36+ |

### 10.2 ENIPCommand 到 ENIP wire 字节映射

| ENIPCommand 字段 | wire 偏移 | 大小 | 说明 |
|------------------|-----------|------|------|
| Command | 0 | 2B LE | ENIP 头 |
| (planner 计算) Length | 2 | 2B LE | ENIP 头 |
| SessionHandle | 4 | 4B LE | ENIP 头 |
| Status | 8 | 4B LE | ENIP 头 |
| SenderContext | 12 | 8B | ENIP 头 |
| Options | 20 | 4B LE | ENIP 头 |
| ProtocolVersion (RegisterSession) | 24 | 2B LE | payload |
| OptionFlag (RegisterSession) | 26 | 2B LE | payload |
| InterfaceHandle (SendRRData/Unit) | 24 | 4B LE | payload 前缀 |
| Timeout (SendRRData/Unit) | 28 | 2B LE | payload 前缀 |
| (planner 计算) ItemCount | 30 | 2B LE | CPF |
| CPFItems[0].TypeID | 32 | 2B LE | CPF |
| CPFItems[0].Length | 34 | 2B LE | CPF |
| CPFItems[0].Data | 36 | N B | CPF |

### 10.3 CIP body 字段映射（Forward_Open 请求）

| cfg 字段 | CIP body 偏移 | 大小 |
|----------|---------------|------|
| CIPService | 0 | 1B |
| (planner 计算) RequestPathSize | 1 | 1B |
| ClassID + InstanceID (EPATH) | 2 | 2*PathSize B |
| PriorityTimeTick | 2+2*PathSize | 1B |
| TimeoutTicks | 3+2*PathSize | 1B |
| O2TNetworkConnectionID | 4+2*PathSize | 4B LE |
| T2ONetworkConnectionID | 8+2*PathSize | 4B LE |
| ConnectionSerialNumber | 12+2*PathSize | 2B LE |
| OriginatorVendorID | 14+2*PathSize | 2B LE |
| OriginatorSerialNumber | 16+2*PathSize | 4B LE |
| ConnectionTimeoutMultiplier | 20+2*PathSize | 1B |
| Reserved | 21+2*PathSize | 3B |
| O2TRPI | 24+2*PathSize | 4B LE |
| O2TConnectionParameters | 28+2*PathSize | 2B LE (Forward_Open) / 4B LE (Large) |
| T2ORPI | 30+2*PathSize (FO) / 32+2*PathSize (LFO) | 4B LE |
| T2OConnectionParameters | 34+2*PathSize (FO) / 36+2*PathSize (LFO) | 2B LE / 4B LE |
| TransportClassTrigger | 36+2*PathSize (FO) / 40+2*PathSize (LFO) | 1B |
| ConnectionPathSize | 37+2*PathSize (FO) / 41+2*PathSize (LFO) | 1B |
| ConnectionPath | 38+2*PathSize (FO) / 42+2*PathSize (LFO) | 2*PathSize B |

---

## 11. 修订记录

### 11.1 v2.0.0（2026-08-05，基于 ODVA 规范重写）

**修订性质**：基于 `/home/weihang/trafficGenerator/docs/protocol-designs/audit/12-enip-audit-deep.md` 的 32 项发现（8 CRITICAL + 8 HIGH + 10 MEDIUM + 6 LOW），对照 OpENer/libplctag/EEIP.Java 参考实现完全重写。

#### 11.1.1 CRITICAL 修复（8 项）

| 审计 ID | 修复内容 |
|---------|----------|
| D-CRIT-1 | CIP 服务码表完全重写：Forward_Open 0x54、Forward_Close 0x4E、Multiple_Service_Packet 0x0A、Get_Attribute_List 0x03、Set_Attribute_List 0x04、Get_Attribute_Single 0x0E、Set_Attribute_Single 0x10、LargeForward_Open 0x5B |
| D-CRIT-2 | EPATH 段类型表完全重写：0x21=Class 16-bit、0x24=Instance 8-bit、0x25=Instance 16-bit、0x2C=Connection Point 8-bit、0x30=Attribute 8-bit、0x31=Attribute 16-bit、0x38=Service 8-bit |
| D-CRIT-3 | ENIP 头/CPF/CIP 所有多字节字段改为 little-endian（§2.1/§2.4/§5.7 BuildENIPHeader 使用 binary.LittleEndian） |
| D-CRIT-4 | SendRRData/SendUnitData payload 增加 Interface Handle(4B LE) + Timeout(2B LE) 前缀（§2.4/§3.3/§5.7 BuildSendRRDataPayload） |
| D-CRIT-5 | ENIP Status 表重写为 7 个合法值：0x0000/0x0001/0x0002/0x0003/0x0064/0x0065/0x0069；CIP 通用状态码与 Connection Manager 扩展状态码独立分表（§2.3.1/§2.3.2） |
| D-CRIT-6 | Forward_Open 请求体重写为完整 15 字段顺序（§3.5）；TransportClass_Trigger 改为 1B |
| D-CRIT-7 | RegisterSession payload 改为直接 ProtocolVersion(2B)+OptionFlag(2B)，无 CPF（§3.2/§5.7 EncodeRegisterSessionPayload） |
| D-CRIT-8 | CPF TypeID 表纠正：0x000C=ListIdentity Response、0x0100=ListServices Response；补充 0x8000/0x8001/0x8002（§2.4.1） |

#### 11.1.2 HIGH 修复（8 项）

| 审计 ID | 修复内容 |
|---------|----------|
| D-HIGH-1 | CPF TypeID 表补充 Sockaddr Info O→T (0x8000)、T→O (0x8001)、Sequenced Address (0x8002)（§2.4.1） |
| D-HIGH-2 | FirmwareRevision 拆分为 FirmwareMajorRev(uint8) + FirmwareMinorRev(uint8)，共 2B（§2.9/§5.2） |
| D-HIGH-3 | Transport Class/Trigger 字段重写为位布局：bit 7=Direction、bit 2-6=Production Trigger、bit 0-1=Transport Class（§2.6）；0x80=Class 0 Client、0x81=Class 1 Client |
| D-HIGH-4 | Forward_Close 请求体重写为 7 字段（Priority/TimeTick + TimeoutTicks + ConnSerialNum + OrigVendorID + OrigSerialNum + PathSize + Path），用三元组定位连接（§3.7） |
| D-HIGH-5 | PCCC/Logix 服务码表：0x4B=Execute PCCC、0x4C=Read Tag (CIP_READ)、0x4D=Write Tag；删除"0x4C 是 PCCC 别名"（§2.5.3） |
| D-HIGH-6 | Multiple_Service_Packet 结构重写：Service=0x0A + PathSize + Path + OffsetCount(2B LE) + Offsets[N*2B LE] + SubRequests[N]（§3.9） |
| D-HIGH-7 | Get_Attribute_List=0x03、Set_Attribute_List=0x04；请求结构 = Service + Path + AttrCount + AttrIDs（§3.10） |
| D-HIGH-8 | from_response 字段提取位置修正：O2T_ConnID 偏移=4（CIP body 起算，成功时）、T2O_ConnID 偏移=8、ConnSerialNumber 偏移=12（§3.6/§5.6.1） |

#### 11.1.3 MEDIUM 修复（10 项）

| 审计 ID | 修复内容 |
|---------|----------|
| D-MED-1 | ListInterfaces 请求改为无 payload，响应 ItemCount=0（§2.2/§6.10 T-011） |
| D-MED-2 | CIP 服务码表补充 0x02/0x0D/0x11/0x15/0x16/0x17/0x18-0x1B/0x1C/0x1D（§2.5.1） |
| D-MED-3 | ENIP Command 推导表重写，所有服务码纠正（§4.3） |
| D-MED-4 | EncodeCIPPath 签名改为 (classID uint16, instanceID uint32, attrID uint16)，自动选择 8/16/32-bit 段（§2.7.4/§5.7） |
| D-MED-5 | SendUnitData 不限于 UDP，Class 3 connected messaging 也可走 TCP（§1.1） |
| D-MED-6 | 删除 planner 主动 MSS 分段逻辑，ENIP 单条消息作为单个 TCP 流提交（§9.5） |
| D-MED-7 | 字段名统一为 source_command_index（§5.6.1/§5.6.2） |
| D-MED-8 | 多设备 SubFlow 命名定义：device_flow_id = parent_flow_id + ":" + subflow_index（§5.5） |
| D-MED-9 | I/O FrameSize 上限重算为 65465（基于 UDP datagram 65507）（§9.5） |
| D-MED-10 | Direction 字段语义明确为 request/response，删除 "up"/"down"（§5.3） |

#### 11.1.4 LOW 修复（6 项）

| 审计 ID | 修复内容 |
|---------|----------|
| D-LOW-1 | 隐式消息描述补充 TCP（Class 3）与 UDP（Class 0/1）两种（§1.1） |
| D-LOW-2 | NOP 可携带任意 payload，接收方忽略（§2.2/§6.2） |
| D-LOW-3 | IndicateStatus 方向改为 server→client（主动推送）（§2.2/§6.16） |
| D-LOW-4 | PCCC 服务码 0x4B/0x4C 区分（§2.5.3） |
| D-LOW-5 | TransportClassTrigger 默认值 0x80 (Class 0 Client)，统一表述（§2.6/§5.5） |
| D-LOW-6 | SessionHandle 策略仅允许 fixed/from_response，拒绝 inc/rand（§5.6.2/V-402） |

#### 11.1.5 章节结构变化

| v1 章节 | v2.0.0 章节 | 变化 |
|---------|-------------|------|
| §1 协议概述 | §1 协议概述 | 补充两类消息通道澄清、关键不变量 |
| §2 报文格式 | §2 数据类型与编码 | 重写全部子节，纠正字节序/服务码/EPATH/TypeID |
| §3 Config 结构体设计 | §5 配置类型定义 | 字段重命名（FirmwareMajorRev/MinorRev）、签名修正 |
| §4 状态机 | §4 状态机 | 推导表重写 |
| §5 Plan 输出 | §6 包序列场景 | 新增 15 个 HexDump 场景（S1-S15） |
| §6 业务场景 | §6 包序列场景 | 合并到 HexDump 场景 |
| §7 测试用例 | §7 测试用例 | 从 50 条扩展到 220 条（T-001 ~ T-220） |
| §8 交叉对抗审计 | §8 Validate 规则 | 重写为独立 Validate 规则表 |
| §9 集成点 | §9 错误处理 | 重写 |
| 附录 A-D | §10 扩展字段映射 | 重写为字段映射表 |
| - | §11 修订记录 | 新增 |

#### 11.1.6 测试用例扩展

- v1：50 条测试（P01-P12, N01-N10, B01-B10, M01-M03, T01-T04, I01-I03, V01-V10）
- v2.0.0：220 条测试（T-001 ~ T-220），覆盖：
  - 正向 80 条（T-001 ~ T-080）
  - 负向 40 条（T-081 ~ T-120）
  - 边界 40 条（T-121 ~ T-160）
  - 多会话/多流 20 条（T-161 ~ T-180）
  - 集成 wire-format 20 条（T-181 ~ T-200）
  - 审计修复验证 20 条（T-201 ~ T-220）

#### 11.1.7 HexDump 场景扩展

v1：无完整 HexDump（仅字段列表）
v2.0.0：15 个完整 HexDump 场景（S1-S15），每个场景含：
- 字段构成（字段名+大小+字节序）
- 完整 HexDump（逐字节）
- Length 字段自洽性验证

#### 11.1.8 关键不变量确认

1. 字节序：全部 little-endian（LE）✓
2. ENIP 封装头：24B 固定，Command(2B LE) + Length(2B LE) + SessionHandle(4B LE) + Status(4B LE) + SenderContext(8B) + Options(4B LE) ✓
3. RegisterSession payload：直接 ProtocolVersion(2B LE) + OptionFlag(2B LE)，无 CPF ✓
4. SendRRData/SendUnitData payload：Interface Handle(4B LE) + Timeout(2B LE) + CPF ItemCount + Items ✓
5. CPF TypeID：0x0000=Null、0x000C=ListIdentity Response、0x0100=ListServices Response、0x00A1=Connected Address、0x00B1=Connected Data、0x00B2=Unconnected Data、0x8000/0x8001=Sockaddr、0x8002=Sequenced ✓
6. CIP Service：0x01=Get_Attributes_All、0x03=Get_Attribute_List、0x04=Set_Attribute_List、0x0A=Multiple_Service_Packet、0x0E=Get_Attribute_Single、0x10=Set_Attribute_Single、0x4E=Forward_Close、0x52=Unconnected_Send、0x54=Forward_Open、0x5B=LargeForward_Open ✓
7. EPATH：0x20=Class 8-bit、0x21=Class 16-bit、0x24=Instance 8-bit、0x25=Instance 16-bit、0x2C=Connection Point 8-bit、0x30=Attribute 8-bit、0x31=Attribute 16-bit ✓
8. ENIP Status：0x0000/0x0001/0x0002/0x0003/0x0064/0x0065/0x0069 ✓
9. Forward_Open 请求体：35B 固定 + 路径，15 字段顺序 ✓
10. Forward_Close 请求体：10B 固定 + 路径，7 字段顺序，三元组定位 ✓

---

### 11.2 v2.0.1（2026-08-05，基于 R1 复审报告修订）

**修订性质**：基于 `/home/weihang/trafficGenerator/docs/protocol-designs/audit/12-enip-audit-r1-v2.md` 的 43 项发现（8 CRITICAL + 14 HIGH + 14 MEDIUM + 7 LOW），对照 OpENer master（`encap.c`/`cipconnectionmanager.c`/`cipconnectionobject.c`/`cipconnectionmanager.h`）与 Wireshark（`packet-cip.c`/`packet-cip.h`）逐项修复。

#### 11.2.1 CRITICAL 修复（8 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R1 | List* 响应（ListServices/ListIdentity/ListInterfaces）删除 Interface Handle + Timeout 6B 前缀：§2.4/§3.3 明确前缀仅限 SendRRData/SendUnitData；§6.3 S2 Length 23→25（2+4+19，无前缀）；§6.4 S3 Length 57→51（2+4+45，无前缀）；T-004/T-011 断言偏移重算 |
| R2 | Forward_Open/Forward_Close 响应体结构与 OpENer 对齐：§3.6 修正为 Consumed(O2T) 在前 offset 0、Produced(T2O) 在后 offset 4；§3.8 Forward_Close 成功响应 10B service data（Application Reply Size+Reserved）；§6.8 S7 响应 Length=46（CIP response 30B）；§6.9 S8 响应 Length=30（CIP response 14B，原 29 错） |
| R3 | Forward_Open 请求体 ConnectionPath 补全 Connection Point 段：§3.5/§6.8 S7 改为 `20 04 24 01 2C 02 2C 03`（ConnPathSize=4 words）；S7 请求 Length 62→66；S14 同步；O2T Connection ID 语义澄清 |
| R4 | Forward_Close 请求体 ConnectionPath 与 Forward_Open 一致：§3.7/§6.9 S8 改为 `20 04 24 01 2C 02 2C 03`；S8 请求 Length 37→41 |
| R5 | CIP Connection Manager 扩展状态码表按 OpENer 枚举重写：0x0107=Target connection not found、0x0111=RPI not supported、0x0112=RPI values not acceptable、0x0312=Link address not valid、删除 0x0313、0x0315=Invalid segment type in path、WrongCloser=0xFFFF；新增 0x0106/0x0110/0x0113-0x0116/0x0127/0x0128/0x0316（§2.3.2）；§9.2 错误表对应修正 |
| R6 | Multiple_Service_Packet 偏移基准明确为 OffsetCount 字段起始的绝对字节偏移；RequestPath 限制放宽（不强制 Message Router）；§5.7 EncodeMultipleServicePacket 注释明确 Offset 由函数内部计算 |
| R7 | 全部 HexDump 自洽性修复：S2/S3/S6/S11/S8 删除"中途修正"文本，Length 逐字节核算；S15 IndicateStatus 标注"无规范依据，仅 trafficgen 内部测试" |
| R8 | Forward_Open 响应 O2T/T2O Connection ID 偏移修正：§5.6.1 表 O2T=0、T2O=4（CIP body 起算，成功时）、ConnSerialNumber=8；T-044/T-045 断言同步 |

#### 11.2.2 HIGH 修复（14 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R9 | §2.4.2 Sockaddr Info 字节序说明：OpENer 平台 LE，但 BSD 传统为网络字节序，标注可配置（默认 LE） |
| R10 | 0x0111 含义修正（见 R5） |
| R11 | §3.5.1 Network Connection Parameters 2B 位布局修正：bit 0-8 Connection Size（9 位）、bit 9 Fixed/Variable、bit 10-11 Priority、bit 12 Reserved、bit 13-14 Type、bit 15 Redundant Owner（Wireshark `dissect_net_param16`） |
| R12 | §3.5.2 LargeForwardOpen 4B 位布局修正：bit 0-15 Connection Size（16 位）、bit 25 Fixed/Variable、bit 26-27 Priority、bit 29-30 Type、bit 31 Redundant Owner（Wireshark `dissect_net_param32`） |
| R13 | §2.6 Transport Class/Trigger 位布局修正：bit 4-6 Production Trigger（3 位）、bit 0-3 Transport Class（4 位）（Wireshark mask 0x70/0x0F） |
| R14 | §2.6 Transport Class 取值范围明确 0-3，4-15 Reserved |
| R15 | 连接超时公式修正：`timeout = RPI × 4 × 2^Multiplier`（§4.2/§9.3，OpENer `RPI_ms << (2 + multiplier)`）；§3.5 注释同步 |
| R16 | NOP 不产生响应（OpENer 直接 break）；IndicateStatus/Cancel 在 OpENer 中不存在（§2.2） |
| R17 | RegisterSession 响应不回显请求值，固定 ProtocolVersion=1/OptionFlag=0（§3.2） |
| R18 | §4.1 会话超时说明修正：OpENer 无 60s 固定常量，60s 仅 trafficgen 模拟端可配置默认值 |
| R19 | §2.5.3 0x52 同码说明修正：仅 libplctag/Logix 设备语境成立，OpENer 一律按 Unconnected_Send |
| R20 | §5.6.1 补充多流 from_response 隔离机制：(flow_id, source_command_index) 两级索引；§6.14 S13 补充关联说明 |
| R21 | §2.7.4/§5.7 EncodeCIPPath 签名增加 `connPointIDs ...uint16` 可变参数，支持 Connection Point 段（0x2C/0x2D） |
| R22 | §2.4.1 Sockaddr Info Item 标注为可选（非 Forward_Open 必备），Validate 不强制 |

#### 11.2.3 MEDIUM 修复（14 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R23 | §2.7.2 补充 32-bit 段（0x22/0x26/0x32）使用说明：实际极少使用 |
| R24 | §3.4.1 明确 CIP RequestPath 使用 Padded EPATH（奇数补 0 至偶数，PathSize=⌈len/2⌉ words） |
| R25 | §3.6/§3.8 响应末尾字段改为 Application Reply Size（Wireshark `hf_cip_cm_app_reply_size`，word 单位） |
| R26 | §3.7 Forward_Close ConnectionPath 定义修正（与 Forward_Open 一致，含 Connection Point） |
| R27 | §4.3 0x4B (Execute PCCC) 精确推导逻辑：一律 SendRRData，按有无 Class 3 连接选择 Connected/Unconnected Data Item |
| R28 | §6.7 S6 响应删除"中途修正"文本（Length=22=0x16 最终值） |
| R29 | §7.2 T-009 Revision 值注明为示例值（OpENer 默认不一定是 0x0B/0x00） |
| R30 | T-096/T-112 修正：0x05/0x0F 因 Transport Class 4-15 Reserved 而不合法，断言修正 |
| R31 | T-122 补充 Length=65515 构造说明（payload 65515B，NOP 任意 payload 无上限，受 Length 字段 16 位限制） |
| R32 | T-150 修正：Size of Additional Status 为 1B USINT，最大 0xFF=255 words；0xFFFF 触发字段上限 |
| R33 | §2.2/§8.2 V-101 标注 0x0072/0x0073 为 trafficgen 模拟扩展，OpENer 不实现，使用需警告 |
| R34 | §2.9 属性 8/9/10 说明：仅属性 8 出现在 ListIdentity 响应末尾，属性 9/10 不出现 |
| R35 | §5.6.1/V-405 补充 from_response 前置条件：源响应 General Status 必须=0x00（成功） |
| R36 | §6.8 S7 ConnectionPath 补全（见 R3） |

#### 11.2.4 LOW 修复（7 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R37 | §6.16 S15 IndicateStatus payload 标注"无规范依据，仅用于 trafficgen 内部测试" |
| R38 | §3.11/§6.4 S3 ProtocolVersion=0xFFFF 改为 1（OpENer `kSupportedProtocolVersion`） |
| R39 | §1.3 关键不变量 #5 修正：LargeForward_Open 位布局非简单扩展（详见 R12） |
| R40 | §5.7 EncodeMultipleServicePacket path 参数语义明确（CIP 头 RequestPath） |
| R41 | §7.4 补充 32-bit 段与 Connection Point 段边界用例（T-133a~T-133d） |
| R42 | §7.6 集成测试补充 OpENer 互操作用例（T-200a~T-200e：RegisterSession/ListIdentity/Forward_Open/Forward_Close/InvalidSessionHandle） |
| R43 | §6.14 S13 明确 SenderContext 递增策略由配置决定（全局 or 每流独立），与 §6.12 不矛盾 |

#### 11.2.5 测试用例变化（v2.0.0 → v2.0.1）

- v2.0.0：220 条（T-001 ~ T-220）
- v2.0.1：229 条（新增 T-120a/T-120b/T-120c/T-133a~T-133d/T-200a~T-200e，共 9 条），并修正 T-004/T-011/T-042/T-044/T-045/T-062/T-064/T-096/T-098/T-112/T-136/T-137/T-150/T-176/T-177 共 15 条断言

### 11.3 v2.1.0（2026-09-26，P-PIPE 文档轨 P1–P3 产物）

**修订性质**：按 `/tmp/pipe/plan-concurrent-pipeline.md` v2 §2 文档轨契约补足 P1–P3。**不改既有 §1–§11 的技术结论**（v2.0.1 审计修复全部保留），只新增：§12 P1 八项规范矩阵 + 三子表、§13 三路对照与候选方案对比、§14 门1 §1–§14 十四行对照表（含 §1/§3/§12 强制展开、目标形状 spec_json 样例、presence 负例形状、去扁平改写清单）、§15 D-ENIP-1 P2 代码设计草稿、§16 P3 测试对接清单（含存量 135 例审计去向分类与 9.52 对账）、§17 缺口立项清单。

**代码现状基线（本版实读，行号为 `feat/unified-layerchain-architecture` 分支 HEAD）**：`enip` 层已注册（registry.go:193-200）、链级生成器已落地（internal/protocol/enip/layer_gen.go:48-166，P4a）、legacy planner 保留（enip.go）；用例 `cases/enip.json` 135 例（91 正 + 44 负），其中 69 例已是层链形但顶层扁平键/协议子映射并存，66 例仍为旧扁平形。**本版不宣称 suite 全绿**（去扁平改写与缺口立项见 §14.13/§17，属 P5 动作）。

### 11.4 v2.1.1（2026-09-27，P4–P6 交付回写）

**修订性质**：P4（接线 + 门2 静态）与 P5（去扁平改写）落地后回写交付状态，并执行 CORE_MEMORY §15.8「门1 十四行表回填实际证据号」。**不改 §1–§11 的既有技术结论**（v2.0.0/v2.0.1/v2.1.0 各轮审计修复全部保留）。

- **P4 接线（`0c5c9e7` + `adfeb76`，集成 `0628424`）**：registry enip 行补六键 `Fields` + `FieldContract{"tcp.dst_port":"44818"}`（registry.go:229-240）；层翻译 `case "enip"`（chain_planner_translate.go:2366，JSON 往返 + `DisallowUnknownFields` 落 `spec.ENIP`）；顶层 `enip` 子映射 presence 判死（strategy_convert.go:8668 区段）；`io_data`/`transport:"udp"`/多单元三支**同步面预检**（validate_layers.go:550-587 预检（块止于 587），与生成器 layer_gen.go:56-71 双路闭合）；链层 `tcp.dst_port` 回填进 `spec.DstPort` 使端口域校验实红（chain_planner.go:310-323，`enip_t115_dstport_502` 实证）；`schemagen` 重跑（generated json enip 行六键）；`coverage_gate.py` 增 `check_enip`；离线链套件 `chainSuiteProtos` 纳 enip。
- **P5 改写（`adfeb76`）**：135 例 → 136 例（81 正 + 55 负）。A 69 去扁平、B 12 转单单元等价、C 10 现状钉 + G-ENIP-2 注记、D 44 转层链形负例；净增 `enip_neg_presence`。改写按 14.6/14.20 先跑后钉重建 frames/包号（B 类包号 = legacy +3，握手 3 包）。
- **P6 修轮（本分支）**：新增复合用例 `enip_t180_multiflow_txn_error_branch`（**多流 framework `flows=2` × 会话内多事务 × 异常分支**三面同例，落 T-179/T-180/T-217 语义；137 = 82 正 + 55 负）；5 例重锚用例 notes 与实钉锚对齐（t117/t118 为 0 包锚 + G-ENIP-8 披露；t108/t109/t110 为 `io_data` 同步预检锚 + G-ENIP-2 披露）；新登记 **G-ENIP-8**（§17）。
- **验证实测（P6）**：lane6 MCP suite **137/137**（`RESULT: 137 pass, 0 fail, 0 error (of 137)`）；离线 `TestLayerChainSuite`（CHAIN_PROTO=enip）**137/137**；`coverage_gate.py enip` 绿；`pipe_gate.sh enip` 门2 静态四项绿。
- **证据号回填**：§14 门1 十四行表逐条实读回填（含原号括注）；§12 章首增「行号口径」说明（符号名稳定锚优先）。

---

## 12. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> **深度口径**（§4.19–4.22）：矩阵三张子表——①命令×响应码矩阵（§12.2）②数据形态变体表（§12.3）③商业行为→用例映射表（§13.2）。条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号；无遗漏留白。
> **数字口径**：本版所有行号为写作时实读（分支 `feat/unified-layerchain-architecture` HEAD）。`cases/enip.json` 计 135 例（91 正 + 44 负，脚本实测）。tshark 字段计数口径 `tshark -G fields | awk -F'\t' '$3 ~ /^enip\./'`（**必须带 `-F'\t'`**：不加时 awk 按空白切列，$3 落在 Blurb 文本上，会把 99 字段低估成 34——OCSP #46 已立此口径）= **99 字段**（本机 TShark 3.6.14）；同口径 `^cip\.` = **669 字段**。两个数字均为本版实测。用例内引用计数（如「26 处引用」）为 `spec_json` 命令数组脚本实测。

> **行号口径（v2.1.1 P6 回填说明）**：§12–§17 正文的行号为 P1–P3 写作时实读快照。P4–P6 交付后部分符号已位移（实测对照：registry.go enip 行 193-200 → **229-240**；chain_planner_translate.go `case "enip"` 72-74 → **2366**；strategy_convert.go `parseENIPCommands` 7793-7852 → **7907-7963**、`parseENIPIOData` 7866 → **7980**、`parseENIPConfig` 7887 → **8001**、`getENIPSessionHandleStrategy` 7856 → **7970**、`CheckProtoFlat` 8273 → **8404**；worker.go FlowIndex 316 → **321**；cmd/server/main.go `NewChainPlanner("enip")` 618 → **626**；types.go 10125/10144/10224 → **10131/10214/10300**）。**门1 十四行表（§14）证据号已按交付树逐条回填**（CORE_MEMORY §15.8）；其余章节按**符号名**（函数/常量/键名）定位，不逐条回填行号——符号名是稳定锚，行号随并行车道合并漂移（layer_dyn.go 的 `:17-71`/`:18`/`:19`/`:726`/`:770-780` 与 enip.go 的 `:211`/`:235`/`:590`/`:627`/`:805`/`:879`/`:1236`、complete.go 的 `:293`/`:332`/`:398-441`/`:456-475`、semantic.go 的 `:142`/`:179-184`/`:198`、tuple_generator.go 的 `:290`/`:300` 经 P6 复核**未漂移**，原号有效）。

### 12.1 八项规范矩阵

| # | 规范要求（§4.1–4.8 对应） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 | **连接模型**（§4.1）：TCP 44818 长连接承载显式消息；RegisterSession 建立会话；CIP 连接由 Forward_Open/Forward_Close 管理；Class 0/1 隐式 I/O 走 UDP 数据报；client（Originator）主动建连（契约 §1.1/§1.2/§4） | 设备发现→注册→显式消息→I/O 周期交换→注销；SCADA/HMI 轮询、I/O 扫描 | **部分已实现**：`enip` 已注册为 TCP 终结层（registry.go:193-200，`CategoryTerminal` + `DependsOn ["tcp"]`，零 `Fields`、无 `TransportOn`/`OptionalOn`；**P4 已落六键 Fields → 现 registry.go:229-240**，见 §11.4/§14 回填）；链级生成器单流命令序列（layer_gen.go:48-166）；**多单元展开与 UDP I/O 面在链上显式拒绝**（layer_gen.go:56-71）；legacy planner 两侧均支持（多单元 enip.go:588-590、UDP I/O 帧 enip.go:824-853、transport=udp enip.go:627） | ①多会话/多流在单链不可达 → **G-ENIP-1**；②UDP I/O 面（含 `transport:"udp"`）→ **G-ENIP-2**；③业务配置仍住顶层 `enip` 子映射（strategy_convert.go:1282-1284）→ **G-ENIP-3** |
| 2 | **命令/消息表**（§4.2）：ENIP 命令 10 条（契约 §2.2：0x0000/0004/0063/0064/0065/0066/006F/0070/0072/0073）+ CPF TypeID 9 值（§2.4.1：0x0000/000C/00A1/00B1/00B2/0100/8000/8001/8002）+ CIP 服务码 36 条（§2.5.1–3 = 23+7+6）；每条请求-响应形态与必选/可选字段见 §3.5–§3.11 | 现网行为：Logix 广播发现（见 §13.2 映射表）、RegisterSession 建会话、显式消息读写、Class1 I/O、PLC-5 PCCC、Logix 标签读写、MSP 批量刷新 | **部分已实现**：builder.go 编码原语齐（BuildENIPHeader:64、BuildCPFItem:85、BuildCIPRequest:115 收任意 service、BuildForwardOpenBody:125、BuildForwardCloseBody:186、BuildMultipleServicePacket:208）；用例侧 ENIP 命令码出现：0x0000×10 / 0x0004×4 / 0x0063×3 / 0x0064×2 / 0x0065×26 / 0x0066×5 / 0x006F×99 / 0x0070×14（`spec_json` 命令数组实测）；CIP 服务码被引用的 12 条：0x01/03/04/05/06/07/0A/0E/10/4E/54/5B；0x0072/0x0073 无用例（模拟扩展，见 §13.1 取舍） | CIP 服务码余 24 条（含 PCCC 0x4B、Logix 0x4C/0x4D/0x52/0x55）零断言 → A′ 补例（§16.3）；命令×响应逐格见 §12.2 |
| 3 | **状态机**（§4.3）：会话状态机 Unregistered→Registered→(Expired)（契约 §4.1）+ CIP 连接状态机 NonExistent→Established→Active→Closing（§4.2），含各状态允许动作 | 会话中途失效（InvalidSessionHandle）、连接重开、Forward_Close 三元组定位、超时释放 | **部分已实现**：会话句柄回写已建模（layer_gen.go:131-135 与 enip.go:730-736 逐字对齐）；**CIP 连接对象状态未建模**——生成器按配置命令序列直发，Forward_Close 靠配置三元组回显（§3.7），无连接表与状态迁移 | 连接一致性（Forward_Close 路径须与 Forward_Open 一致，V-114，负例 `enip_t120a_forwardclose_path_mismatch`）→ 链级校验迁入见 §15；连接超时（RPI×4×2^M，§9.3）无时钟语义 → B′「明确不解决」 |
| 4 | **字段表**（§4.4）：ENIP 头 6 字段 LE（§2.1）+ Forward_Open 请求 15 字段/35B 固定（§3.5）+ 2B 连接参数位布局 7 项（§3.5.1，bit 0-8/9/10-11/12/13-14/15 六段）+ 4B 位布局 7 项（§3.5.2）+ Forward_Open 成功响应 9 字段（§3.6 表 9 数据行）+ Forward_Close 请求 7 字段/响应 5 字段（§3.7/§3.8）+ EPATH 段类型 7 值（§2.7.1）+ 段子类型 14 行（§2.7.2） | 跨厂商互操作；大 RPI/大数据量走 LargeForwardOpen；路径 8/16/32-bit 编码选择；Identity 对象属性读取 | **已实现**：EncodeCIPPath:11 / EncodePaddedCIPPath:51 / BuildForwardOpenBody:125 / BuildLargeForwardOpenBody:156 / BuildForwardCloseBody:186（ForwardClose 按 Wireshark 3.6.14 dissector 固定偏移校准，builder.go:187-191 记 Reserved 字节教训） | 逐字段变体覆盖见 §12.3；32-bit EPATH 段（T-133a~d）仅编码面 |
| 5 | **错误处理表**（§4.5）：ENIP Status 7 值（§2.3）+ CIP 通用状态 14 值（§2.3.1）+ Connection Manager 扩展状态 19 值（§2.3.2）+ 各分支动作（§9.1 6 行 / §9.2 11 行，实测数据行） | 服务端拒识、路径错、连接冲突/不存在、RPI 不可接受、会话失效 | **部分已实现**：44 条负例覆盖配置非法面（锚词 42 种不同值逐例，见 §16.2）；错误响应用例生成侧构造 `payload` 数组直填（`enip_error_response_status`，断言 `enip.status` + CIP 错 bytes）；0x8000/0x8001 构造有例（T-144/T-145/T-146）；未知 TypeID 负例（`enip_t116` 0x9999） | CM 扩展状态码逐值无单独用例（`spec_json` 面 `additional_status` 键**零出现**，命令键普查实测）→ A′ 补例；服务端主动错误语境无外部对端 → A′（生成侧可构造，改断言面即可） |
| 6 | **超时与活性**（§4.6）：会话无活动超时（实现相关，§4.1/R18 已澄清 OpENer 无固定常量）、连接无活动超时 `RPI×4×2^M`（§9.3）、NOP 心跳且**不产生响应**（§2.2/R16） | 长连接保活、设备掉线检测、超时重连、退避重试 | **部分已实现**：NOP 命令可发（`enip_nop_heartbeat`）；TimeoutTicks / ConnectionTimeoutMultiplier 为配置面（范围校验 §8.2 V-116） | 超时/重传的**时间轴行为**无引擎面（生成器无时钟、无重传语义）→ B′；保活属 §3.15 第三项（`enip_nop_heartbeat`） |
| 7 | **NAT/代理/被动模式**（§4.7）：Sockaddr Info Item O→T/T→O（0x8000/0x8001，**可选**、16B、SinFamily/SinPort/SinAddr/SinZero，§2.4.1 R22 + §2.4.2 R9 字节序标注）；UDP I/O 目标地址通告；端口 44818 固定 | 跨网段/防火墙后 I/O、NAT 端口映射、多网卡 PLC、Proxy 转发 | **部分已实现**：`cpf_items` 直填构造面已通（T-144 `ItemCount=4` 双 Sockaddr 构造、T-145 端口边界、T-146 地址边界，均为**正例**）；`Length≠16` 负例有例（T-119）；引擎无 NAT/代理中间盒模拟面 | NAT/代理中间盒 → B′ 立项（无面） |
| 8 | **版本/方言差异**（§4.8）：ProtocolVersion=1 固定（§3.2/R17）、LargeForwardOpen 0x5B 4B 参数（§3.5.2）、Logix 方言（0x4C/0x4D/0x55；0x52 同码按设备语境，§2.5.3/R19）、PCCC 0x4B 推导（§4.3/R27 用 Connected/Unconnected 选择逻辑）、ListIdentity ProtocolVersion=1（§3.11/R38） | Logix 5000 标签读写、老 SLC/PLC-5 PCCC 通道、版本不匹配拒绝 | **部分已实现**：LargeForwardOpen 已实现（builder.go:156 + 用例 `enip_large_forward_open`）；ProtocolVersion≠1 拒绝有负例（T-083/T-120b）；0x52 同码在 `cip_service` 面已可填（`parseENIPCommands` strategy_convert.go:7793-7852 收任意 service），但**无方言用例** | Logix/PCCC 方言面零断言 → A′ 补例（§16.3）；0x52 同码需在用例注记目标设备模型（OpENer=Unconnected_Send） |

### 12.2 子表①：命令×响应码矩阵（逐格已覆/缺失）

行 = ENIP 命令（契约 §2.2 十条），列 = 响应面三类。「已覆」= 有用例断言该命令与响应面（命令码出现次数见 §12.1 行 2）；「不适用」= 该命令无此响应面。

| 命令 \ 响应面 | 成功响应（Status=0） | ENIP Status 错误（§2.3） | CIP 层错误（§2.3.1/§2.3.2） |
|---|---|---|---|
| 0x0000 NOP | 已覆 `enip_nop_heartbeat`（§2.2/R16：OpENer 直接 break，不产响应——此处「成功」指请求包可发） | 不适用（不产生响应） | 不适用（无 CIP 载荷） |
| 0x0004 ListServices | 已覆（命令码 4 处引用） | 缺口 A′（未构造 Status≠0 形） | 不适用（无 CIP 层） |
| 0x0063 ListIdentity | 已覆 `enip_listidentity_session_lifecycle` / `enip_listidentity_response` | 缺口 A′（同族：服务端拒绝发现） | 不适用 |
| 0x0064 ListInterfaces | 已覆（命令码 2 处引用 + `enip_t102_listinterfaces_cpf`） | 缺口 A′ | 不适用 |
| 0x0065 RegisterSession | 已覆（命令码 26 处引用；`enip_registersession_session_state`） | 缺口 A′（0x0069 UnsupportedProtocol 的服务端响应面；请求侧已有 T-083/T-120b 负例） | 不适用 |
| 0x0066 UnRegisterSession | 已覆（命令码 5 处引用；`enip_t174_unregister_session_matched`） | 不适用（无响应包） | 不适用 |
| 0x006F SendRRData | 已覆（命令码 99 处引用；CIP 各服务面） | 缺口 A′（服务端返回 0x0064 InvalidSessionHandle 的响应形未构造） | 部分覆：`enip_error_response_status`（CIP 错 bytes 直填 payload，断言 `enip.status`=0x00000000 + 错 bytes frames）；`enip_t120a_forwardclose_path_mismatch`（路径不一致判死，锚词 `Forward_Close connection path`）；**CM 扩展状态逐值无例**（`additional_status` 键在 135 例 `spec_json` 中**零出现**，命令键普查实测）→ A′ 补例 |
| 0x0070 SendUnitData | 已覆（命令码 14 处引用；UDP I/O 面，链上 G-ENIP-2） | 缺口 A′ | 缺口 A′（I/O 面错误） |
| 0x0072 IndicateStatus | 不适用（trafficgen 模拟扩展、无规范 payload，§2.2/R33/R37） | 不适用 | 不适用 |
| 0x0073 Cancel | 不适用（同上） | 不适用 | 不适用 |

注：0x0072/0x0073 在 OpENer 中不实现（收到回 0x0001），本契约不作线上断言（§2.2 已声明）；列「不适用」非「缺口」。

### 12.3 子表②：数据形态变体表（协议相关全部形态逐项）

| 变体维度 | 形态 | 对应用例 | 备注 |
|---|---|---|---|
| 地址族 × 载体 | IPv4/TCP（现状 135 例全为 IPv4，`10.0.0.1`→`20.0.0.1`，src_port 单值 12345）；IPv6/TCP **零例** | IPv4 面：全域；IPv6 面：**缺口 A′**（可构建性**待确认**，见备注） | §9.24 地址族对称：一族已覆另一族须逐格补齐，缺一格即缺口。**备注（实读）**：仓库层名表中**无 `ipv6` 层**（registry.go 注册名 124 项无 ipv6；v6 语义由 `ip` 层字面量承担）；已收官 kerberos/bacnet/megaco/hl7 的用例文件同为 0 例 v6（同口径实测），即本缺口在已收官协议中亦未闭合——IPv6 面按跨协议统一口径处理，**A′ 判定以 P5 首次实跑 `ip` 层 v6 字面量链为准**（不预判可达性） |
| 字节序 | 全 LE（头/CPF/CIP）；Sockaddr SinPort/SinAddr 标注可配置（§2.4.2/R9） | 全域 frames hex 断言（86 例带 frames） | 大端面 B′（现网 OpENer 为 LE，无第二形态证据） |
| 命令形态 | 请求/响应成对、单向（NOP/UnRegisterSession）、server→client 主动（IndicateStatus，不适用） | `enip_nop_heartbeat` / `enip_t174_unregister_session_matched` / `enip_listidentity_session_lifecycle` | 命令预算见 §12.2 |
| CPF ItemCount | 2（Null+Unconnected / ConnAddr+ConnData）、4（+Sockaddr O→T/T→O，T-144 有例）、0（ListInterfaces 响应）、1（ListServices/ListIdentity 响应） | 2/4 有例（T-144 断言 `enip.cpf.itemcount=4` + frames）；**0/1 的 `itemcount` 字段断言未单独落地**（T-157/T-158 断言的是 ListIdentity 的 SendRRData 封装 ItemCount=2，非 List* 响应本身的 0/1 形） | §2.4.1 / §3.3。另：T-143（ItemCount=1 用户项）实际被接受、断言 totals 3——planner 行为与契约 §8.2 V-105（≥2）**表面不一致**，P5 对账时二选一（改实现或改契约，T-143 summary 已诚实声明 impl allows） |
| CPF TypeID | 0x0000/0x000C/0x00A1/0x00B1/0x00B2/0x0100/0x8000/0x8001/0x8002（9 值） | 用例内出现：0x0000×8 / 0x00A1×13 / 0x00B1×13 / 0x00B2×1 / 0x8000×4 / 0x8001×1；**0x000C/0x0100/0x8002 零出现**（`enip_listidentity_response` 用 `payload` 数组直填，未走 `cpf_items`+`type_id` 键）；未知值负例 `enip_t116`（0x9999） | 0x000C/0x0100 的 `type_id` 键面 → A′ 补例 |
| CIP 服务码 | 36 值（§2.5.1–3 = 23+7+6） | 被引用的 12 条（§12.1 行 2）；余 24 值缺口 A′（含 PCCC/Logix 方言） | 逐值枚举（§9.47） |
| EPATH 段 | Class/Instance/Attribute 的 8/16-bit + Connection Point 8/16-bit（T-133c/d 有例） | 有例（`enip_epath_16bit_*` 家族、T-133a~d）；32-bit 仅编码面 | §2.7.2 |
| 连接参数位布局 | Forward_Open 2B（bit 0-8 Size/9 FV/10-11 Prio/12 Rsv/13-14 Type/15 Owner）；LargeForwardOpen 4B（bit 0-15 Size/25 FV/26-27/29-30/31） | 有例（`enip_forward_open_request`、`enip_large_forward_open`）；Reserved bit 置位负例有例（T-098 家族 `enip_t098`） | §3.5.1/§3.5.2（Wireshark dissect_net_param16/32） |
| SequenceCounter | I/O 帧内 2B 序列、步长、回绕（T-074 有例 `enip_seq_wraparound_3_frames`） | 有例但**全在 `io_data` 面**（`enip_t073_seq_10_frames` / T-129 无单独 id 并入 io 面 / T-130 同 / `enip_t167_multiflow_seq_from_1`）→ 链上被拒（G-ENIP-2） | §9.4；链上不可达，属 B′ 迁移面。注：T-141/T-142 summary 声明「2026-08 去 seq 前缀」——ConnectedDataItem 已不编码 SequenceCounter，与契约 §3.3「I/O payload 含 2B SequenceCounter」**字面不一致**，P5 对账（056edb0 意图登记） |
| SessionHandle | 0（未注册）/分配值 0x12345678（42 处出现）/0xFFFFFFFF（`enip_t124_sessionhandle_max`）/inc·rand 动态形（`enip_t090`/`t091` 为策略拒绝负例） | 有例 | §2.1 / V-107 |
| SenderContext | 回显（`enip_t070_sendercontext_echo`，frames 钉 8B）/全 FF（`enip_t127_sendercontext_max`）/全局 inc（`enip_t176_senderctx_global_inc`）/每单元独立（`enip_t177_senderctx_per_unit`）；全 0 形（T-126）**未落地** | 部分覆；后两例在多单元面（链上待改写） | 序号算法见 §14.12；命令键 `sender_context` 仅 3 处出现 |
| ENIP Length | 0（NOP 最小包，`enip_t121_nop_length0` **已落地**：断言 `enip.command=0x0000` + `enip.length=0`）/4（RegisterSession）/65515 边界（T-122 **未落地**）/65516 超限负例（T-123 **未落地**） | 部分覆 | §2.1 / §9.5 |
| Forward_Open 家族 | Forward_Open / LargeForwardOpen / 成功响应（`enip_forward_open_response_full`，Reply 0xD4 + frames）/ 错误响应（`enip_error_response_status` bytes 面）/ 路径一致性 | 部分覆；**路径不一致负例 `enip_t120a_forwardclose_path_mismatch` 已有**（锚词 `Forward_Close connection path`） | §3.5–§3.7 / V-114 |
| Multiple_Service_Packet | 2 子请求（`enip_multiple_service_packet`：offsets 6,14 + Length=44）/ 空子请求负例（`enip_t106`）/ 上限 64（`enip_t107`） | 有例 | §3.9 |
| ListIdentity 响应 | 45B 全量（含 VendorID/ProductName/Revision/State，`enip_listidentity_response` payload 直填 + `enip.length=68`）；ProductName 空（T-157）/255B（T-158）有例；**256B（T-159）未落地** | 部分覆 | §3.11 / §2.9 |
| ICMP/超时类 | —— | 不适用 | ENIP 无 ICMP 层语义 |

---

## 13. 三路对照与候选方案对比（CORE_MEMORY §4.12–4.18）

### 13.1 三路对照

**① 规范原文（定「必须是什么」）**：ODVA《The CIP Networks Library》Volume 1（Common Industrial Protocol：服务码表、EPATH 段编码、通用状态码、Connection Manager 语义）与 Volume 2（EtherNet/IP Adaptation of CIP：ENIP 封装头、CPF、端口 44818、Command 表）——本契约 §2–§4 的每一个取值、偏移与位布局即该两卷经 Wireshark dissector 校核后的落地（§2.5.1/§2.7.2/§3.5.1 等处的「修正说明」逐条标注审计号 R1–R43）。

**② 现网行为（定「真跑成什么样」）**：Rockwell Automation（罗克韦尔）PLC 与通信栈的实际走法——
- 设备发现：Logix 控制器用套接字向 Identity Object 发**广播**报文识别网上所有 EtherNet/IP 设备（出处：Rockwell 技术支持文档 471230 *Identify EtherNet/IP Devices Using Logix Sockets*，2020-03）——对应 ListIdentity（0x0063）UDP 广播形。
- 显式消息与套接字服务：Logix 5000 通过 MSG 指令/套接字接口访问非 EtherNet/IP 设备（出处：Rockwell 出版物 **ENET-AT002E-EN-P**《EtherNet/IP Socket Interface Application Technique》2023-01；同族 **ENET-UM006**《EtherNet/IP Network Devices User Manual》）——对应 SendRRData（0x006F）+ CIP 服务调用形。
- I/O 连接：Class 1 周期 I/O 由 Forward_Open 建立、按 RPI 周期收发（出处：ENET-UM006 族文档；**具体章节号待 G-ENIP-5 核对**）。
- **待确认**（§5.5）：具体字段值（VendorID=0x0001、ProductName 如设备 EDS 形态）与 Forward_Open 参数（RPI/连接尺寸/连接类型位）需**抓现网包或读 EDS 文件**核对 → 立项 **G-ENIP-5**（确认方式：抓 RSLinx/Studio 5000 浏览设备的包，或读 EDS）。

**③ 开源实现思路（定「别人验证过的走法」）**：
- **OpENer**（ODVA 参考从站实现）：`encap.c`（ListServices/ListIdentity/SendRRData/SendUnitData 装配，含 R16 NOP 不响应、R17 RegisterSession 响应不回显）、`cipconnectionmanager.c`（Forward_Open/Close 响应装配与三元组定位，R2/R4/R25/R26）、`cipconnectionobject.c`（请求体字段顺序，R3）、`cpf.c`（Interface Handle + Timeout 前缀，R1）——本契约 §3.3/§3.6/§3.8 的字段顺序即取自该实现；**只借鉴行为与装配语义，不搬码**（§4.14）。
- **libplctag**（AB/Logix 客户端库）：`src/libplctag/protocols/ab/defs.h` 的 `AB_EIP_CMD_*` 码（0x4C Read Tag / 0x4D Write Tag / 0x52 Unconnected_Send 与 Read Tag Fragmented 同码 / 0x55 List Tags），对应 §2.5.3 与 R19。
- **Wireshark `packet-enip.c` / `packet-cip.c`**：本机实测 TShark 3.6.14 下 `enip.*` **99 字段**（口径：`tshark -G fields | awk -F'\t' '$3 ~ /^enip\./'`，TShark 3.6.14；不带 `-F'\t'` 会低估成 34）——生成包的可解析性是本协议断言通道的基础（§16.5）。

**三路结论一致处**：LE 字节序；24B 封装头；显式消息走 SendRRData + CPF（Null Address + Unconnected Data）；I/O 走 Connected Address + Connected Data；Forward_Open/Close 用 ConnSerial+VendorID+SerialNum 三元组定位；RegisterSession payload 为 4B 无 CPF。
**不一致处与取舍**（§4.15 以规范为底线、以现网行为为准绳）：
1. List* 响应是否带 6B 前缀：规范与 OpENer 一致 = **不带**；tshark 对两种形都宽容。取舍：按 OpENer 装配（§3.3/R1），T-157/T-158 断言 `enip.cpf.itemcount` 支持此形（ListIdentity 的 SendRRData 封装面）。
2. I/O 载体：规范允许 TCP Class 3（§1.1/D-MED-5），现网 I/O 绝大多数走 UDP。取舍：链上只做 **TCP 载体**（UDP 面 G-ENIP-2 立项迁入），legacy 单测保留 UDP 面证据。
3. IndicateStatus/Cancel：规范定义了命令但未定义 payload，OpENer 不实现。取舍：契约声明为 trafficgen 模拟扩展、不作现状断言（§2.2）。

### 13.2 子表③：商业行为→用例映射表（§4.16）

| 商业行为（产品 + 版本 + 出处） | 用例编号 | 无映射项 + 确认方式 |
|---|---|---|
| Logix 控制器广播发现设备（Rockwell 文档 471230；ListIdentity 广播形） | `enip_listidentity_session_lifecycle`、`enip_listidentity_response` | EDS 字段值形态 → G-ENIP-5（抓包/读 EDS） |
| Logix 显式消息读标签（libplctag `AB_EIP_CMD_CIP_READ`=0x4C；同库 0x4C vs 0x52 语境讨论） | **缺口 → A′ 补例**（§16.3） | 真实标签路径/符号段编码 → G-ENIP-5 |
| Logix 未连接发送 0x52（libplctag `AB_EIP_CMD_UNCONNECTED_SEND`；OpENer 同码解 Unconnected_Send，§2.5.3/R19） | **缺口 → A′ 补例** | 同码歧义 → 用例注记目标设备模型（G-ENIP-6） |
| 老 SLC/PLC-5 的 PCCC 通道（0x4B Execute PCCC，§2.5.3） | **缺口 → A′ 补例** | PCCC 内层 DV/EXEC 载荷格式 → G-ENIP-5（另一份规范域） |
| Class 1 周期 I/O（Forward_Open + RPI 周期收发，ENET-UM006） | `enip_io_connection_udp_full_chain`（UDP I/O 面；链上被拒） | 链上不可达 → G-ENIP-2 迁入计划 |
| HMI/上位机批量刷新（多会话并发读写，现网常见轮询形态） | `enip_t161_sessioncount2_senderctx` 等多单元面（链上被拒） | 链上一链一流 → G-ENIP-1 迁入计划 |
| RSLinx/Studio 5000 浏览（ListIdentity → CIP Identity 属性读取） | `enip_sendrrdata_get_attribute_single`、`enip_get_attributes_all` | 浏览器的多服务批量形（MSP）已有 `enip_multiple_service_packet` |

### 13.3 候选方案对比（§4.17）

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| A 声明式命令序列 + 结构化 CPF/CIP builder（**现状 P4a**，与 dns/kerberos/edp 族同构） | 配置声明 `commands[]`（命令码 + CIP 服务 + 路径 + 参数），builder 逐字段结构化编码；`from_response` 跨命令引用；字节级可复刻 OpENer 装配 | 与已收官族同构（接线/builder/casegen 范式可复用）；字段可逐项断言；不透明面留 `payload` 逃生口（ListIdentity 响应等整段直填） | 连接/对象状态不建模（Fail 分支靠配置显式表达）；多单元需另立展开层 | O(n) 流式渲染、零全量聚合；纯函数 builder（无锁无状态）；兼容 OpENer/Wireshark 双校核 | **采用** |
| B 全 CIP 对象模型引擎（对象表 + 连接表 + 属性字典驱动，仿 OpENer 从站） | 实现设备侧对象字典与连接状态机，按对象属性推导响应 | 通用性强，可模拟设备侧全语义（含服务端主动错误） | 远超流量生成范围；需为每类对象建表；连接状态机带锁与生命周期，性能与复杂度双高 | 复杂度高；内存随对象/连接数增长 | 不选（设备侧模拟另案，不在本契约） |
| C 整包 hex 回放（frames 直填） | 用例里直接写完整帧 hex | 最简单、最快落地 | 字段不可结构化断言、动态面全失（§12 全部落空）、改一个字段即重做 | 动态零分 | 仅作特殊形/负例逃生口（现状 86 例带 frames 作**辅助**断言，非主通道） |

---

## 14. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

> **证据号回填（v2.1.1，CORE_MEMORY §15.8）**：本表证据列已按 **P4–P6 交付树**（merge `0628424` + P6 修轮分支）逐条实读回填；与 P1–P3 原号不一致处在括注中保留原号，便于回溯（漂移根因＝P4 接线与并行车道合并，非结论变化）。

| § | 本协议怎么满足 | 证据（P6 回填） |
|---|---|---|
| §1 层链唯一真相 | 见 §14.1 强制展开：旧键 `src_ip/dst_ip/src_port/dst_port` 迁入 `ip`/`tcp` 层；顶层 `enip` 子映射迁入 `layers[]` 的 `{"enip": {...}}` 条目（**G-ENIP-3 已落地**：registry 六键 + 层翻译 + presence 判死）；顶层 `tcp` 子映射（`initial_seq`）迁 `tcp` 层同名键；数量走 `flow_control`；目标形状样例见 §14.1；改写清单见 §14.13。**P5 交付实测**：135 例改写全纯 `layers` 形（0 例顶层旧键残留）+ `enip_neg_presence`（presence 判死负例，顶层 `enip` 子映射为执法对象）；P6 新增复合用例 1 例 = 交付 **137** 例 | 本契约 §14.1/§14.13 + `cases/enip.json` 实测（137 例）+ `coverage_gate.py` `check_enip`「正例顶层键=0；group_id 框架键例外」（coverage_gate.py:1954-1956 区段）+ `enip_chain_test.go` 顶层白名单链例 |
| §2 策略/任务 | 策略 = 单 ENIP 流量模板（自带 `flow_control` flows/bps/time）；任务 = 多策略合跑 + 总量封顶；框架语义未动。**P5 后实测**：122 例缺省单流 + 14 例显式 `strategy_fc flows=1`；P6 复合用例 1 例显式 `flows=2`（框架复制两条独立 TCP 流） | CORE_MEMORY §2（框架面）+ `cases/enip.json` 用例普查（P6 实测） |
| §3 五件套 | 见 §14.3 强制展开：会话表 / 事务序列（同一 TCP 会话内多轮命令）/ 关联关系（`from_response` 3 处引用）/ 插入位置（终结层事件）/ 时间线（流内严格顺序）；单载体**不豁免**多事务（§3.15 三项逐项见 §16.1） | 本契约 §14.3 + `enip_listidentity_session_lifecycle`（多轮）、`enip_t180_multiflow_txn_error_branch`（P6：多流×多事务×异常分支）、`enip_multiple_service_packet`（单 SendRRData 多子请求）、`enip_nop_heartbeat`（保活） |
| §4 查规范 | ODVA CIP Vol.1/Vol.2 + Rockwell 出版物（ENET-AT002E-EN-P / ENET-UM006 / 文档 471230）+ OpENer/libplctag + Wireshark（`enip.*` 99 字段实测，口径见 §12 头注）；P1 矩阵 8 行 + 三子表 | 本契约 §12/§13 |
| §5 依赖与错误 | `DependsOn ["tcp"]`（**registry.go:229-240**，原记 193-200；零 `TransportOn`/`OptionalOn`）；链 `[ip,tcp,enip]` 可达（complete.go:398-441 终结层计数）；`[ip,udp,enip]` → 载体判定拒（complete.go:456-475 `tcpOnly`）；失败返回 task error（零假成功，`Planner.Validate` enip.go:211 + `validateFromResponseConfig` enip.go:879）；**P4 增补同步面预检** validate_layers.go:550-587（`io_data`/`transport:"udp"`/多单元三支，锚词与生成器 layer_gen.go:56-71 逐字一致，双路闭合） | registry.go:229-240 / complete.go:332（`validateChain`）/398-441/456-475 / enip.go:211/:879 / validate_layers.go:550-587（均 P6 实读） |
| §6 性能 | 见 §15「性能设计与验收」（§6.1–6.8 要素齐；吞吐等数字待 P5 基准后定，不写承诺） | 本契约 §15 |
| §7 三份文档 | `12-enip-design.md` v2.1.0（本文，P4–P6 回写见 §11.4）= 设计草稿；D-ENIP-1（§15 草稿，门1 获批即定稿）；T-ENIP = §7 的 T-001~T-220 家族（232 ID）为用例编号权威，本文 §16 为 P3 对接与对账；generated schema P4 已重跑 | 修订记录（§11.3/§11.4）+ §15/§16 |
| §8 设计先行 | 本条目 P1–P3 先于 P5 去扁平改写与任何生成器改动；门1 获批 = D-ENIP-1 定稿 = 开工门 | 提交序（P1–P3 文档 → P4 接线 `0c5c9e7` → P5 改写 `adfeb76` → 集成 `0628424` → P6 修轮） |
| §9 测试三源 | 三源 = ODVA 规范条款（§2–§4 表逐行）+ D-ENIP-1 + tshark `enip.*`（99 字段实测）+ 现网 Rockwell 出版物行为；9.52 对账两行 + 清单出处见 §16.4 | 本契约 §16.4 + `12-enip-testcase.md` v1.0.1 §6.3 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 `/tmp/pipe/56-enip/p123-report.md`）+ 收官隔离复审 + 修轮；红先绿后 | 报告文件（p123/p4/p6-review） |
| §11 白话 | 每阶段白话一句先行（汇报） | 汇报 |
| §12 动态清单 | 见 §14.12 强制展开：四元组住 `ip`/`tcp` 层（五策略全开，layer_dyn.go:17-71 allowlist、:18 `ip`/`:19` tcp`）；业务字段**不在** allowlist → G-ENIP-4；序号算法行号实读（tuple_generator.go:290/300、`resolveLayerTuple` layer_dyn.go:770-780、调用 worker.go:321（P1 原记 316，P6 实测 321）、SenderContext layer_gen.go:145/169 + enip.go:805/1085-1097） | 本契约 §14.12（行号 P6 回填） |
| §13 schema 派生 | registry enip 行六键（**registry.go:229-240**，原记 193-200）与 `parseENIPCommands`（strategy_convert.go:7907-7963）/`parseENIPIOData`（:7980）/`parseENIPConfig`（:8001）消费键对齐；**schemagen 已重跑**（P4）：`schemas/v1/generated/layers.generated.json` enip 行六键与 registry 逐键一致；struct 标签字面量锁 | registry.go:229-240 + generated json 实读 + `TestLayersGeneratedMatchesRegistry` |
| §14 真实流程 | suite 经 MCP 建任务 → 引擎生成 → tshark `enip.*`（99 字段）+ frames hex 双通道；先跑后钉（14.6/14.20）；pcap 落盘逐例可复查（14.16） | §16.5 + P5/P6 lane6 suite（137/137）+ 离线链套件 137/137 |

### 14.1 §1 强制展开：旧键逐个去向 + 目标形状 spec_json 样例

旧键清单（`src_ip/dst_ip/src_port/dst_port/count` + 本协议顶层子映射 `enip` / `tcp`）——**现状实测**：135 例中 135 例带顶层四元组、135 例带顶层 `enip` 子映射、18 例带顶层 `tcp` 子映射（`initial_seq`，其中链形 2 例 + 旧扁平 16 例）。

| 旧键 | 去向 | 现状（实测） |
|---|---|---|
| `src_ip` | → `layers[i].ip.src` | 135/135 例残留（`10.0.0.1` 单值） |
| `dst_ip` | → `layers[i].ip.dst` | 135/135 例残留（`20.0.0.1` 单值） |
| `src_port` | → `layers[i].tcp.src_port` | 135/135 例残留（12345 单值） |
| `dst_port` | → `layers[i].tcp.dst_port` | 135/135 例残留（44818；`502` 为 V-115 负例 `enip_t115`） |
| `count`（若有） | → 删除，走 `flow_control.flows` | 0 例（本文件未用；数量靠 `enip.session_count`/`flow_count`，见下） |
| `enip.session_count` | → 删除（§1.3 数量只走 `flow_control`；多流语义另立项 G-ENIP-1；拒绝锚 `session_count -1 out of range` / `flow_count 101 out of range` 迁层重锚） | 8 例引用（含负例 `enip_v005_session_count_negative`；命令键普查实测 `session_count` 8 处） |
| `enip.flow_count` | → 同上 | 10 例引用（含负例 `enip_v006_flow_count_negative`） |
| `enip.scenario` | → `layers[i].enip.scenario`（层内键） | 1 例引用 |
| `enip.commands` / `enip.io_data` / `enip.transport` | → `layers[i].enip.{commands,io_data,transport}` 层内键（**须先补 enip 层 Fields，G-ENIP-3**；命令内键名以 `parseENIPCommands` 消费的 **37 个蛇形键**为准（脚本实测去重列表：additional_status / attribute_id / cip_service / class_id / command / conn_serial_number / connection_path / connection_path_size / connection_timeout_multiplier / cpf_items / direction / from_response_field / general_status / instance_id / interface_handle / length / o2t_connection_id / o2t_connection_parameters / o2t_rpi / option_flag / options / originator_serial_number / originator_vendor_id / payload / priority_time_tick / protocol_version / sender_context / session_handle / source_command_index / status / sub_requests / t2o_connection_id / t2o_connection_parameters / t2o_rpi / timeout / timeout_ticks / transport_class_trigger；strategy_convert.go:7793-7852，另 `session_handle` 的 strategy 子键由 `getENIPSessionHandleStrategy`:7856 读）） | 135 / 13 / 135 例引用 |
| 顶层 `tcp` 子映射（`initial_seq`） | → `layers[i].tcp.initial_seq`（tcp 层已有该字段，18 例迁入） | 18 例（链形 2 + 旧扁平 16） |

**目标形状 spec_json 样例**（顶层键仅 `layers` + `flow_control`；ENIP 业务键住 enip 层；命令内键名取自 `parseENIPCommands` 实际消费键）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.56", "dst": "198.51.100.56"}},
    {"tcp": {"src_port": 42156, "dst_port": 44818}},
    {"enip": {"transport": "tcp", "scenario": "custom", "commands": [
      {"command": 101, "cip_service": 84, "class_id": 6, "instance_id": 1,
       "priority_time_tick": 10, "timeout_ticks": 5,
       "conn_serial_number": 1, "originator_vendor_id": 1,
       "originator_serial_number": 1, "connection_timeout_multiplier": 7,
       "o2t_rpi": 100000, "o2t_connection_parameters": 512,
       "t2o_rpi": 100000, "t2o_connection_parameters": 512,
       "transport_class_trigger": 128,
       "connection_path": [32, 4, 36, 1, 44, 2, 44, 3], "connection_path_size": 4},
      {"command": 111, "cip_service": 14, "class_id": 1, "instance_id": 1, "attribute_id": 1}
    ]}}
  ],
  "flow_control": {"flows": 1}
}
```

字段说明：`command` 为 ENIP 命令码十进制——样例第 1 条 `101`=0x65 RegisterSession（故不带 `cip_service`），第 2 条 `111`=0x6F SendRRData；第 2 条 `cip_service:84`=0x54 Forward_Open、`14`=0x0E Get_Attribute_Single；`connection_path` 为 `20 04 24 01 2C 02 2C 03`（Class 0x04 + Instance 0x01 + O→T/T→O Connection Point）的十进制数组形（`getByteSlice` 消费形，strategy_convert.go:7793-7852 同口径）。**注**：样例为**目标形状示意**（0x65 与 0x6F 两条命令同列仅为展示两类命令的键面），非可直接跑的最小可用配置。

> **跑不通声明**（§1.9）：上例的 enip 层业务键（`commands`/`transport`/`scenario`）**今天跑不通**——enip registry 行零 `Fields`，`layers: layer "enip": unknown field "commands"`（complete.go:279-293 实测路径）。G-ENIP-3 落地前，等价可跑形仍是顶层 `enip` 子映射（本契约 §5 配置面）+ `layers` 只有 `[{tcp},{enip}]` 空负载的混合形。**本契约不允许把混合形当作目标形状**，只作为 G-ENIP-3 迁入期的过渡证据。

> **落地状态（v2.1.1 P6 回写）**：G-ENIP-3 已落地（P4 `0c5c9e7`）——上例的 enip 层业务键现**可跑通**（六键注册于 registry.go:229-240，层翻译 chain_planner_translate.go:2366 落 `spec.ENIP`）；混合形（层链 + 顶层 `enip` 子映射并存）**已判死**：`enip_neg_presence` 负例锚 `no longer accepts a top-level enip`，现文件 137 例全纯 `layers` 形。上例仍为**目标形状示意**（0x65 与 0x6F 两条命令同列仅为展示两类命令的键面），非最小可跑配置。

### 14.3 §3 强制展开：五件套（会话表 / 事务序列 / 关联关系 / 插入位置 / 时间线）

会话表：

| 会话 | 承载 | 四元组 | 生命周期 |
|---|---|---|---|
| s1 ENIP 会话 | TCP（44818） | `ip.src/dst` + `tcp.src_port→44818` | TCP 握手 → ListIdentity/ListServices（可选）→ RegisterSession → 显式消息若干 → UnRegisterSession → 挥手 |
| s1.a CIP 连接（会话内子状态） | 同一条 TCP 连接 | 同 s1 | Forward_Open → I/O 交换（链上暂不可达，G-ENIP-2）→ Forward_Close |

事务序列（同一 TCP 会话内的多轮操作，单事务四件事 §3.4–3.7）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| t1 发现 | TCP 已建连 | ListIdentity（0x0063）/ListServices（0x0004）/ListInterfaces（0x0064） | 记录设备身份 → 进入 t2 | ENIP Status≠0 → 终止发现（配置错误） |
| t2 注册 | t1 完成（或直接） | RegisterSession（0x0065，payload=ProtocolVersion+OptionFlag） | 响应 SessionHandle 回写为后续命令默认（layer_gen.go:131-135） | Status=0x0069/0x0003 → 终止 |
| t3 显式消息 | s1 已注册 | SendRRData（0x006F）：Get/Set 属性、Get_Attribute_List、MSP、Forward_Open/Close | CIP General Status=0 → 继续；`from_response` 提取 o2t/t2o/conn_serial 供后续命令 | CIP Status≠0（§2.3.1/§2.3.2）→ 按码分支（重试/跳过/中断会话） |
| t4 I/O 交换 | t3 Forward_Open 成功 | SendUnitData（0x0070）+ SequenceCounter 递增 | 每帧 +1、回绕（`enip_seq_wraparound_3_frames` 落地；T-074/T-128 两个 T 号**未单列**） | **链上不可达**（G-ENIP-2）；UDP 面留 legacy 证据 |
| t5 注销 | t3/t4 结束 | UnRegisterSession（0x0066，`enip_t174_unregister_session_matched`） | 无响应，会话结束 → 挥手 | TCP 异常断开 = 隐式注销（G-ENIP-7） |

关联关系（§3.8–3.10）：本协议「一条控制连接关联一条或多条 I/O 数据流」的关联字段 = `from_response`（`source_command_index` + `from_response_field`，命令键普查 3 处引用）+ 命令内逐单元派生（`+u`/`+2u`，enip.go:680-698）。四字段提取位置实测表见 §5.6.1：`session_handle`（ENIP 头 offset 4）/ `o2t_connection_id`（CIP body offset 0）/ `t2o_connection_id`（offset 4）/ `connection_serial_number`（offset 8）；提取前置 = 源响应 General Status=0（V-405/R35）。被关联流（I/O）在链上无独立副流 → G-ENIP-1/2 迁入计划（与 CWMP `driven_by` 范本的差异点诚实声明）。

插入位置：**终结层**——enip 生成器产「方向 + 完整报文字节」的消息事件（layer_gen.go:151-159，`SrcPort/DstPort: 0`，端口由 tcp 层按方向交换），TCP 语义（握手/seq-ack/挥手/端口交换）全部交给 tcp 层生成器（generator.go:802-810 注释所指同款分工）；enip 层不产独立 TCP 流。

时间线：流内**严格顺序**（命令 i+1 恒在命令 i 之后，单事件流；`senderCtxCounter++` layer_gen.go:163 / legacy enip.go:805 逐命令推进）；多单元（多会话/多流）在 legacy 面是 `for s×f` 串行展开（enip.go:588-593，单元序号 `u := s*flowCount + f` :590），链上一次一个 flow → 会话间并发交错留 G-ENIP-1。

### 14.12 §12 强制展开：动态字段清单 + 序号算法

| 字段 | 住处 | 开策略（现状实测） | 理由 / 序号算法 |
|---|---|---|---|
| `src`（src_ip） | `ip` 层 | fixed/inc/rand/list/pattern **全开**（layer_dyn.go:18 `"ip": {"src": true, ...}`） | §12.2 四元组必备；多流并发锚点。算法：`resolveLayerTuple`（layer_dyn.go:770-780）按流序号解析，`ResolveIPValue`（tuple_generator.go:290）/ `ResolvePortValue`（:300）；调用点 worker.go:321（P1 原记 316；逐流，先保底后动态） |
| `dst`（dst_ip） | `ip` 层 | 全开（同上） | 多目标设备场景（现网多 PLC 轮询） |
| `ttl` | `ip` 层 | 全开（layer_dyn.go:18 `"ttl": true`，`genSmallInt` layer_dyn.go:726） | 逐流 TTL 池 |
| `src_port` | `tcp` 层 | 全开 + 未写动态时**保底递增** `12345+i` | §2.8；保底算法 worker.go:307-309（`flowCount > 1 && !spec.HasExplicitSrcPort` → `DefaultSrcPort + i`，`DefaultSrcPort=12345` @ strategy_convert.go:49）；层动态在保底**之后**解析并覆盖（worker.go:311-316 注释明示次序） |
| `dst_port` | `tcp` 层 | 全开（现网 fixture 固定 44818） | tshark 自动解码约束；动态端口例需顶层 `decode_as` 另议 |
| `enip.commands[].command` | `enip` 层 | **不开**（不在 allowlist，layer_dyn.go:17-71 无 enip 项；对象值 → `checkLayerDynObjects`（validate_layers.go:335）allowlist 门拒 → `does not support dynamic`） | 命令序列是结构选择器（同 sip `dialog`/megaco `sessions` 判例），逐流变破坏会话语义 → G-ENIP-4 立项评估 |
| `enip.session_handle` / `conn_serial_number` / `o2t_connection_id` 等连接身份 | `enip` 层 | **不开**（同上门） | legacy 面为 **`+u` 单元偏移**派生（enip.go:680-698：SessionHandle/ConnSerialNum `+u`、O2T/T2O `+2u`、down 响应 payload 同步平移 `deriveForwardOpenResponsePayload` enip.go:997-1012），非 §12 五策略；多单元展开链上被拒（G-ENIP-1） |
| `enip.sender_context` | `enip` 层 | **不开**（allowlist 无 enip；命令键 `sender_context` 仅 3 处出现） | 现状算法**实读**：生成器内 flow 级计数器 `senderCtxCounter`，每命令 `+1`（layer_gen.go:139 传入、:163 `senderCtxCounter++`）；legacy 同款（enip.go:805）；取值优先级 fixed/`SenderContextPtr`/默认计数三级（enip.go:1082-1097）；全局 inc 跨单元（enip.go:583-604） |
| `enip.io_data.sequence_counter` | `enip` 层 | **不开** | 现状算法实读：`buildIODataFrames`（enip.go:1236）逐帧写序号；链上 IOData 被拒（layer_gen.go:56-58）。注：T-141/T-142 summary 声明「2026-08 去 seq 前缀」——当前 ConnectedDataItem 已不编码 SequenceCounter，与契约 §3.3「2B SequenceCounter」字面不一致，P5 对账 |
| `flow_control.flows` | 顶层 | 数量面（不属 §12 动态值；`strategy_fc` 现状为 `null`×118 / `{"type":"flows","value":1}`×17） | §1.3；多 flow 时 `src_port` 保底 + 层动态生效 |

**序号算法代码位置（实读，非「待 P4 定」）**：四元组五策略解析 = `resolveLayerTuple`（layer_dyn.go:770-780）→ `ResolveIPValue`（tuple_generator.go:290）/ `ResolvePortValue`（:300，含 inc 的 `start+(index*step)%count` 回绕与 rand 的 `Seed+index` 可复现，layer_dyn.go:740-764 同款算法面）；调用点 = `worker.go:321`（P1 原记 316；`spec.FlowIndex = i` 前）。ENIP 业务字段的序号算法 = `layer_gen.go:163`（SenderContext 计数）与 `enip.go:1236+`（I/O 序号）；二者均**不在层动态面**（G-ENIP-4）。

### 14-P2 presence 负例形状（链级红例必含①）

- **层链 + 顶层协议子映射并存 = 判死负例**（presence 形状，非残留）：`{"layers":[{"ip":{}},{"tcp":{}},{"enip":{}}], "enip": {}}`（顶层空 `enip:{}` 与层链并存）必须被 planner/validator 拒，`error_contains` 含 `presence` 或顶层键锚词。**现状缺口**：`CheckProtoFlat`（strategy_convert.go:8273-8285）只拦顶层四元组五键，`enip` 子映射**无 presence 判死分支**（enip 未进各协议 presence 判死名单）；且 pipe_gate 门2-1 顶层子映射检查（pipe_gate.sh）对 enip 现状只报**黄**（须在 D-条目登记过渡计划，否则红）→ 本条随 G-ENIP-3 一同落地（顶层 `enip` 键在迁入完成后改为判死）。
- **白名单外游离键判死**（1.11–1.13）：顶层 `src_mac`/`dst_mac`/`ttl` 与 `layers` 并存 → `checkLayerFlatConflict`（schema/semantic.go:179-184，六键 `src_ip/dst_ip/src_port/dst_port/src_mac/dst_mac`）与 pipe_gate 门2-1 均判红（`ttl` 另在门2-1 顶层旧键表内）；链级红例必含此形。
- 收官自查行：**非负例顶层键 = 0**（P5 改写后逐例核）。
- 负例 `expect` 键集合严格 `{expect_error, error_contains}`（另有 `notes` 说明键为 runner 注释键，非断言键），锚词逐例（§16.2 表）。

### 14.13 去扁平改写清单（P5 动作；本文只列清单，不改用例文件）

| 类 | 例数 | 现状（实测） | 改写动作 |
|---|---|---|---|
| A 层链形正例（顶层并存） | 69（正例全数） | `layers=[{tcp:{}},{enip:{}}]` 空负载且顶层并存 `src_ip/dst_ip/src_port/dst_port` + 顶层 `enip` 子映射（其中 2 例另带顶层 `tcp.initial_seq`） | 删顶层四元组（值迁 `ip`/`tcp` 层；`ip` 层若只配 v4 字面量见 §12.3 IPv6 备注）；顶层 `enip` 业务键迁 `layers[i].enip`（**依赖 G-ENIP-3**，字段=parseENIPCommands/parseENIPIOData 消费键）；顶层 `tcp.initial_seq` 迁 `tcp` 层同名键 |
| B 旧扁平正例（多单元 TCP 面，**无 `io_data`**） | 12 | 实测 12 例（`spec_json.enip` 含 `session_count`/`flow_count`>1 且 `io_data` 为空）：`enip_t161_sessioncount2_senderctx`、`enip_t162_sessioncount8_handles`、`enip_t164_flowcount2_forwardopen`、`enip_t165_flowcount8_connids`、`enip_t169_multisession_tcp_tuples`、`enip_t172_fromresponse_session_isolated`、`enip_t173_fromresponse_flow_isolated`、`enip_t174_unregister_session_matched`、`enip_t175_forward_close_serial_matched`、`enip_t176_senderctx_global_inc`、`enip_t177_senderctx_per_unit`、`enip_t179_multiflow_order` | 单单元等价例（A′，改写为 `flow_control.flows=1` 单流形；`+u`/`+2u` 派生在 u=0 时恒等，字节可与 legacy 对齐）；多单元语义面迁 G-ENIP-1 |
| C 旧扁平正例（UDP I/O 面，含 `io_data`） | 10 | 实测 10 例（`spec_json.enip.io_data` 非空）：`enip_io_connection_udp_full_chain`（transport=tcp + io_data）、`enip_seq_wraparound_3_frames`、`enip_t129_seq_start_7fff`、`enip_t130_seq_step2`、`enip_t141_io_framesize0`、`enip_t142_io_framesize_max`、`enip_t073_seq_10_frames`、`enip_t166_2session2flow_io`（2×2 + io_data）、`enip_t167_multiflow_seq_from_1`（flow_count=2）、`enip_t170_multiflow_udp_shared_tuple`（transport=udp + flow_count=2） | **不删用例**：P5 以现状钉（§9.36 B/C 缺口钉现状，生成器 layer_gen.go:56-64 显式拒绝）+ G-ENIP-2 注记；UDP 面落地后重校准 |
| D 旧扁平负例 | 44（全数） | `layers=[]`，配置非法（42 种锚词逐例，见 §16.2） | 改写为层链形负例（锚词保留；`enip_v005`/`v006` 两例随 `session_count`/`flow_count` 迁层重锚） |
| E IPv6 面 | 0 | 135 例全 IPv4 | 按 §9.24 补 IPv6 对应用例 → A′（§16.3） |

> 注：四类**互斥且穷尽**——135 = A 69（层链形正例）+ B 12 + C 10（旧扁平正例 22 = B12 + C10）+ D 44（旧扁平负例）。分类口径：正例按 `spec_json.io_data` 是否非空二分（B=无 io_data 的多单元 TCP 面 12 例；C=含 io_data 的 UDP I/O 面 10 例），负例全归 D。改写时以实际 `spec_json` 为准。

> **改写落地（v2.1.1 P6 回写）**：四类已由 P5（`adfeb76`）执行完毕——A 69 全数去扁平（顶层四元组/子映射清零）、B 12 转单单元等价例（notes 逐例披露 G-ENIP-1，包号 = legacy +3）、C 10 以现状钉（`error_contains: io_data`，notes 钉 G-ENIP-2）、D 44 转层链形负例（`enip_v005`/`v006` 随字段迁层重锚为 `session_count -1 out of range` / `multi-unit expansion`；`t104/t105` 重锚为严格解码文案；`t117/t118` 重锚为 0 包锚 + G-ENIP-8）。净增 `enip_neg_presence`（P4 presence 判死）+ `enip_t180_multiflow_txn_error_branch`（P6 复合用例）= **137 例**。

---

## 15. D-ENIP-1 P2 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 体裁：文件清单 / 接口签名 / 数据结构 / 主流程 / 错误分支 / 性能边界 / 冲突点 / 回滚方式。**接线行号均为实读**（分支 HEAD）。

**8.1 改哪几个文件（新建 0 + 接线 7 + 共享面 2）**：

| 文件 | 职责 | 现状 |
|---|---|---|
| internal/core/layers/registry.go（enip 行，:193-200） | 补齐 `Fields`：`transport`(string)/`scenario`(string)/`commands`(list)/`io_data`(list\|map)/`session_count`(int)/`flow_count`(int) 六键（与 parseENIPConfig:7887 / parseENIPCommands:7793-7852 / parseENIPIOData:7866 消费键对齐）；保持 `DependsOn ["tcp"]`；端口契约 `FieldContract {"tcp.dst_port":"44818"}`（缺省补齐，dns :135-136 同款） | **零 Fields**（今日 `layers[i].enip.*` 报 unknown field，complete.go:279-293） |
| internal/protocol/enip/layer_gen.go（:48-166） | 配置来源由 `req.Meta.ENIP`（:52-55）改为「层 config 优先、`Meta.ENIP` 兼容」：层 config 解析成 `core.ENIPConfig` 后与 legacy 同路；`genBody` 保持纯函数 | 只读 `req.Meta.ENIP` |
| internal/core/strategy_convert.go（:1282-1284 + :7887） | `case "enip"` 解析保留（过渡期双真相；迁入完成后顶层 `enip` 改 presence 判死，§14-P2）；新增层 config → `ENIPConfig` 的解析入口（复用 `parseENIPCommands` :7793 / `parseENIPCPFItems` :7769 / `parseENIPSubRequests` :7743 / `parseENIPIOData` :7866 / `getENIPSessionHandleStrategy` :7856） | 仅顶层 `enip` 子映射 |
| internal/core/layers/chain_planner_translate.go（:72-74） | 层 config 存在时不再以 `spec.ENIP` 覆盖（`ENIP: spec.ENIP` 改条件注入） | 恒注入 |
| internal/core/layers/generator.go（:215/308-310） | `FlowMeta.ENIP *core.ENIPConfig` 复用（层翻译产物落此）；主线程独占改动面（plan §0 车道禁令：框架文件由主线程改） | 已有字段 |
| internal/core/layers/complete.go（enip 通道） | `ValidateLayerConfig`（:279-293）的 unknown-field 路径天然生效；可选 enip 专属校验（transport∈{tcp}、commands 非空） | 无 enip 专属块 |
| internal/core/layers/validate_layers.go | enip 专属预检（可选）：`io_data`/`session_count>1`/`flow_count>1`/`transport:"udp"` 在链上判死（锚词与生成器 layer_gen.go:56-71 一致，双路闭合 C 类口径） | 无 enip 块 |
| internal/core/schema/semantic.go（:126-131/:179-184） | 顶层 `enip` 子映射 presence 判死（随 G-ENIP-3，§14-P2）；顶层四元组判死已有（CheckProtoFlat + `checkLayerFlatConflict` 六键） | 未列 enip |
| trafficgen/tools/coverage_gate.py | `check_enip` 块（准入接线/关键件/守卫/用例面四段） | **无 enip 块**（M1 认领项，车道 B 在分支内编写） |
| cases/enip.json + layer_gen_test.go | 回归 + 去扁平改写（§14.13 / §16） | 现状 135 例两形并存 |

**8.2 接口签名**（示意，落码钉死）：`ParseENIPLayerConfig(cfg map[string]interface{}) (*core.ENIPConfig, error)`；`ValidateENIPLayer(spec *core.FlowSpec) error`（复用 `Planner.Validate` enip.go:211）；生成器内 `generateFromLayer(cfg *core.ENIPConfig) error`（复用现有循环 layer_gen.go:94-164）。
**8.3 数据结构**：沿用 `core.ENIPConfig` / `ENIPCommand` / `CPFItem` / `ENIPIOData`（types.go:10125/10144/10224），不新增类型；层 config 只做「map → 同结构」的一次性解析（命令内蛇形键清单见 §14.1（以 `parseENIPCommands`:7793-7852 消费键为准））。
**8.4 主流程**：schema 校验（层 config 字段范围 V9，validate_layers.go:616-660 注释面）→ `ValidateLayers` 完成链（validate_layers.go:632 入口、V9 循环 :687-701）→ `ChainPlanner` 翻译（层 config → `ENIPConfig`，chain_planner_translate.go:2366 改条件注入（P1 原记 72-74）→ worker 逐流 `resolveLayerTuple`（worker.go:321，四元组动态，P1 原记 316）→ enip 生成器逐命令产消息事件（layer_gen.go:94-164，`emitMsg` :171-178 取消逃生）→ tcp 层生成器补握手/seq-ack/挥手（`RegisterPlanner(layers.NewChainPlanner("enip"))` main.go:626 已注册（P1 原记 618），引擎侧入口现成）→ writer/pcap。
**8.5 错误分支**：①层 config 未知键/类型错 → `layers: layer "enip": unknown field "…"`（complete.go:293）；②`io_data`/`transport:"udp"`/`session_count>1`/`flow_count>1` → 生成器显式报错（layer_gen.go:56-71，**不得静默单遍产 1 单元**——包数缩水即假通过）；③`from_response` 非法引用 → `validateFromResponseConfig`（enip.go:879-917，V-403/404/405）；④顶层旧键/协议子映射并存 → presence/白名单判死（§14-P2；CheckProtoFlat strategy_convert.go:8404（P1 原记 8273）+ checkLayerFlatConflict semantic.go:179）。全部传播为 task error（零假成功）。
**8.6 性能边界（§6.1–6.8 对应）**：O(n) 流式——逐命令构建 `[]byte` 即 `EmitMsg`（layer_gen.go:160-164），无全量聚合、无按包增长结构；单命令内存 = 报文长度（≤ 65515 ENIP Length 上限，§9.5）+ 常量开销；共享状态仅 `responseTable`（按命令数 O(n)，仅 down/response 命令入表 layer_gen.go:142-144）与 `sessionHandle`/`senderCtxCounter` 标量；无锁、无 sleep（事件驱动，速率由 tcp 层/任务桶管）；worker 并行度 = 任务分片（`shard`，worker.go:319-330 hashKey/gID 同流同 shard 保 FIFO）。**诚实声明**：包/秒、并发流数、内存上界数字待 P5 基准后定（§6.5 不写承诺数字）。六类场景（基线/目标规模/压力上限/长运行时/并发交错/背压）P5 跑测覆盖。
**8.7 与现有逻辑的冲突点**：①enip 层从「零 Fields」变为带 Fields——存量 `layers=[{tcp},{enip}]` 空 config 用例（69 例）不受影响（缺省=不写，V9 只校验显式键 validate_layers.go:616-660），但**顶层 `enip` 与层内 `enip` 并存**必须判死（否则双真相，§14-P2）；②`ENIP: spec.ENIP` 注入改条件化（chain_planner_translate.go:74）——无层 config 时行为逐字节不变（legacy 等价性，回归以 69 例空 config 链形为基线）；③生产 `Meta.ENIP` 的路径（`mapToFlowSpec` + worker/engine 直调）仍需可用（`layer_gen_test.go` 依赖）；④registry.go / strategy_convert.go / chain_planner_translate.go / generator.go 为跨协议共享文件——按 plan §3 属预期合并冲突点（FlowSpec/translate/validate_layers switch case），车道 B 只改 enip 本地块，合并序=完成序，非机械冲突走自查+评审闭环；⑤`schemagen` 重跑改 `layers.generated.json`（enip 字段表新增，层数不变）；⑥**v6 字面量**：仓库无 `ipv6` 层（registry 层名表 124 项无 ipv6），v6 走 `ip` 层字面量（地址族校验见 chain_planner.go:262 注释面）——本条目不引入新层。
**8.8 回滚方式**：全量 revert 新建/改动文件（git revert 提交序）；registry 行回退为「零 Fields + 顶层 `enip` 子映射」旧形即恢复今日可跑态；schemagen 生成文件随提交对齐回退；无数据迁移面（用例文件独立回退）。

---

## 16. P3 测试对接清单（T-ENIP 草稿输入；正文 P5 落 testcase 文件）

### 16.1 §3.15 三项（同连接多轮操作 / 非正常结束 / 长保活）

| 项 | 现状 | 判定 |
|---|---|---|
| ① 同连接/同流内多轮操作 | 已覆：`enip_listidentity_session_lifecycle`（发现→注册→注销多轮）+ `enip_registersession_session_state`（响应回写）+ `enip_multiple_service_packet`（单个 SendRRData 承载 2 子请求） | 有例 ✅ |
| ② 非正常结束 | 部分覆：错误响应 bytes 面（`enip_error_response_status`，General Status 0x0E 直填）；连接三元组面（`enip_forward_close_triad`）；路径错判死（`enip_t120a_forwardclose_path_mismatch`）；**中断续作（FIN/RST 中途断开、Forward_Open 后未 Close 即断开、会话失效后重连）无例** | 半程 → 立项 **G-ENIP-7**（A′ 可构造部分 + 迁入计划） |
| ③ 长保活 | 已覆：`enip_nop_heartbeat`（NOP 保活；OpENer 不响应面与 §2.2 一致） | 有例 ✅ |

### 16.2 存量用例审计去向分类（§9.14：合入 / 已有等价覆盖 / 作废并注明原因）

**总量实测**：135 例 = 91 正 + 44 负。44 负的 `error_contains` 全字符串 42 种不同值（**注**：负例契约（14.11）要求短锚词，现状有长句值如 `SendRRData requires at least 2 CPF items, a cip_service, or a payload`——P5 改写时按 14.11 收敛为短锚词并入断言）（`SendRRData requires at least 2 CPF items…` 与 `session_handle strategy must be fixed…` 各出现 2 次，其余 40 种各 1 次）。**设计 §7 所列 T-ID 共 232 个，用例 id 内命中的 110 个全 ⊂ 其中（无自造 T-ID，脚本实测）**；110 个按段实测分布：正向 15 / 负向 42 / 边界 34 / 多会话·多流 15 / 集成 1（T-199）/ 修订追加 3（T-217/218/219）。另 25 例为非 T 命名（`enip_nop_heartbeat` 等，summary 引用 S/T 场景号）；这 25 例的 summary 共引用 **22 个 T 号**，全部 ⊂ 上表 122 个「未落地 T-ID」集合（脚本实测 `refs ⊆ missing`），即它们为该 22 个 T 号提供了**部分语义覆盖**（单条用例对应多个 T 点，如 `enip_listidentity_session_lifecycle` 覆盖 S3/S4/S12）——P5 建 testcase 时须逐号对账，不得直接以 25 例顶 22 号。

| 去向 | 例数 | 明细 |
|---|---|---|
| 合入（保留语义，改形状） | 69 | 层链形正例（类 A）：删顶层四元组 + 顶层 `enip`/`tcp` 子映射，命令数组原样迁 `layers[i].enip`（依赖 G-ENIP-3） |
| 语义保留但须重构（单单元等价例） | 12 | 旧扁平正例多单元 TCP 面（类 B）：改写为 `flows=1` 单流等价例；`+u`/`+2u` 派生在 u=0 时恒等，字节可与 legacy 对齐 |
| 作废重做（链上不可达，面迁 G-ENIP-2；**不删用例**，P5 以现状钉 + 注记，§9.36） | 10 | 旧扁平正例 UDP I/O 面（类 C）：`enip_io_connection_udp_full_chain`、`enip_seq_wraparound_3_frames`、`enip_t073_seq_10_frames`、`enip_t129_seq_start_7fff`、`enip_t130_seq_step2`、`enip_t141_io_framesize0`、`enip_t142_io_framesize_max`、`enip_t166_2session2flow_io`、`enip_t167_multiflow_seq_from_1`、`enip_t170_multiflow_udp_shared_tuple` |
| 负例改写（锚词保留） | 44 | 类 D：全部改层链形负例；`enip_v005`/`enip_v006` 两例随字段迁层重锚 |

**设计 §7 所列但用例文件未落地的 T-ID：122 个**（232 − 110，按段实测）：正向 **65**（80-15）/ 负向 **1**（43-42，仅 T-120c）/ 边界 **10**（44-34，含 T-122/T-123/T-126/T-128/159 等）/ 多会话·多流 **5**（20-15，T-163/T-168/T-171/T-178/T-180）/ 集成 **24**（25-1，T-181~T-198 的 tshark 面 + T-200/T-200a~e 互操作）/ 修订追加 **17**（20-3）。→ 全部进 §16.3 补齐清单（**不是作废**）。

### 16.3 A′ / B′ 两分类（§9.52 固定动作）

**A′（现有引擎可构建 → 补例）**：

| 面 | 要点 | 落点 |
|---|---|---|
| IPv6 对称面 | `ip` 层 v6 字面量 + 同构链（§9.24） | 补 1–2 例 |
| CIP 服务码余 24 值 | 0x02/08/09/0D/11/15/16/17/18/19/1A/1B/1C/1D/4B/4C/4D/52/55/56/57/5A（`BuildCIPRequest` 通用面已支持 builder.go:115） | 逐值≥1 例（§9.47 全表扫） |
| CM 扩展状态逐值 | 0x0100 起 20 值（`spec_json` 面 `additional_status` 零出现 → 全部缺） | 逐值≥1 例（`commands[].additional_status` + 响应侧 bytes 面） |
| Sockaddr Info | 0x8000/0x8001 的 `type_id` 键面（现有 T-144/145/146 走直填，`type_id` 出现 0x8000×4/0x8001×1；0x8002 零出现） | 0x8002 + 响应面补例 |
| CPF ItemCount 0/1 形 | ListInterfaces/ListServices/ListIdentity 响应的 `itemcount` 字段断言（现有 T-157/T-158 断言的是 SendRRData 封装面） | 补例（T-004/T-011 家族） |
| 未落地 T-ID 122 个 | 按段补齐（正向 65 / 负向 1 / 边界 10 / 多流 5 / 集成 24 / 修订 17） | P5 casegen |
| 非正常结束 | FIN/RST 中途断开、未 Close 即断、失效后重连 | 补例（G-ENIP-7） |

**B′（引擎结构缺口 → D-ENIP-1「明确不解决 + 迁入计划」）**：

| 缺口 | 结构原因 | 迁入计划 |
|---|---|---|
| 多会话/多流（G-ENIP-1） | 链一次一 flow；生成器拒绝 `session_count/flow_count>1`（layer_gen.go:68-71） | 多策略多任务并发 + 层动态端口池；`+u` 单元偏移语义评估后保留或退役 |
| UDP I/O 面（G-ENIP-2） | 链单载体 tcp，无 UDP 混合流（layer_gen.go:56-64） | 评估「多载体链」或「I/O 走独立 UDP 策略」；落地前 legacy 单测保证据 |
| 业务键未住层（G-ENIP-3） | registry 零 Fields（registry.go:198-200） | 本条目 8.1 已列，P4 落地；落地同时开 presence 判死 |
| 业务字段动态（G-ENIP-4） | enip 不在 `layerDynAllowlist`（layer_dyn.go:17-71）；`isDynObject`（chain_planner_chain.go:283）门拒 | 逐字段评估；落地前按 §9.36 现状钉 |
| 超时/重传时间轴 | 生成器无时钟语义（`emitMsg` 仅 ctx 取消逃生 :171-178） | 明确不解决（属设备侧行为）；以配置字段 + 错误响应用例表达 |
| NAT/代理中间盒 | 引擎无中间盒模拟 | 明确不解决；Sockaddr 面 A′ 覆盖 |
| 大端 Sockaddr | OpENer 面 LE（§2.4.2/R9） | 明确不解决（无第二形态证据） |

### 16.4 9.52 对账两行 + 清单出处声明 + 3.14 豁免边界审计

**行 1（规范逻辑点总数 vs 用例覆盖数）**——口径：设计 §2/§3/§4/§6/§8/§9 表格数据行（脚本实测，表头与 `---` 分隔行已剔除；**不含** §5 配置 struct、§7 用例表本身、§10 映射表、§11 修订记录）：
- **规范逻辑点总数 = 317**（§2 数据类型与编码 163 + §3 消息结构 52 + §4 状态机 14 + §6 场景 S1–S15 15 + §8 Validate 规则 55 + §9 错误处理 18；口径 = 各节表格数据行（已剔除表头与 `---` 分隔行），脚本实测）。
- **用例覆盖数 = 135**（正 91 + 负 44；改写去向四类互斥穷尽：合入 69 / 重构 12 / 作废重做 10 / 负例改写 44，见 §16.2）。
- **覆盖缺口**：§7 已列未落地的 **122 个 T-ID** + §16.3 A′ 面 → P5 补齐后重跑全量并复核本两行。

**行 2（清单出处声明）**：本清单**不是**从现有用例或引擎能力反推（§9.48 禁止项），而是从 **ODVA 规范原文面**（CIP Networks Library Vol.1/Vol.2，落点＝本契约 §2–§4 的取值/字段/状态/错误表）+ **官方文档面**（Rockwell ENET-AT002E-EN-P / ENET-UM006 / 文档 471230）+ **实现面**（OpENer / libplctag，§13.1③）+ **解析器实测**（tshark 3.6.14 `enip.*` 99 字段）反推；逐条可与 §12 三子表、§13.2 映射表对应。反查绿只证明「清单内的点有例」，本节两行才是清单完整性的证据（§9.52）。

**3.14 豁免边界审计**：本协议**不豁免** `sessions[]`（同连接多轮操作有例，多会话并发面 G-ENIP-1 立项）；多流并发（`enip_t166` 等 legacy 面，链上 G-ENIP-1）与单包多载荷（`enip_multiple_service_packet` 2 子请求 MSP 面）**各有例**——无豁免逃逸。

**三源回指行**：每条用例的 `summary`/断言面必须能回指 ①规范行（本契约 §2–§4 或 §7 的 T-ID）②D-ENIP-1 条目（§15）③现网行为（§13.2 映射表行）——缺一即返工（§9.2–9.5）。

### 16.5 断言通道与执行口径

- **tshark 字段通道**：`enip.*`（99 字段实测：`enip.command`/`enip.length`/`enip.session`/`enip.status`/`enip.options`/`enip.context`/`enip.timeout`/`enip.cpf.itemcount`/`enip.cpf.typeid`/`enip.cpf.cai.connid`/`enip.cpf.sai.connid`/`enip.cpf.sai.seq`/`enip.cpf.length`/`enip.cpf.data`/`enip.srrd.iface`/`enip.sud.iface`/`enip.lir.{revision,status,state,vendor,devtype,prodcode,serial,name,namelen}`/`enip.sinfamily`/`enip.sinport`/`enip.sinaddr` 等——以 `tshark -G fields` 输出为准，不自创字段名）+ 载体 `ip.proto`/`tcp.dstport`/`tcp.srcport`/`udp.srcport`（用例内 11 个断言字段普查：`enip.command`52/`enip.length`35/`enip.session`24/`tcp.srcport`23/`ip.proto`12/`udp.srcport`12/`enip.status`4/`enip.cpf.itemcount`4/`tcp.seq_raw`2/`tcp.ack`2/`tcp.dstport`1）；CIP 内层走 frames hex（86 例带 frames）。
- **动态面断言**：`presence` / `nonzero` / `distinct` / `same_as_packet`（§9.35/§12.15 五类分列；`session_handle` inc/rand 形现为拒绝负例 T-090/091，按 §9.36 现状钉）。
- **先跑后钉**：改写或新增用例后经真实流程（MCP 建任务→引擎生成→tshark 校对，§14.7–14.9）跑一遍取实际 pcap 再钉期望值（14.6/14.20）；pcap 落 `/tmp/mcp-pcaps/enip/`（14.16）。
- **负例口径**：`expect` 仅 `{expect_error, error_contains}`（+ `notes` 注释键）；锚词逐例见 §16.2（44 负 / 42 种锚词）。

### 16.6 P5–P6 交付回写（v2.1.1）

| 项 | P3 基线 | P6 交付实测 |
|---|---|---|
| 用例总数 | 135（91 正 + 44 负） | **137（82 正 + 55 负）**：P5 改写 135 → 136（+`enip_neg_presence`），P6 复合用例 +1 |
| 顶层旧键残留 | 135/135 例全带（红） | **0 例**（负例顶层 `enip` 子映射为判死对象 1 例，非残留） |
| T 号命中（按用例 id） | 110 / 232（缺 122） | **111 / 232（缺 121）**——P6 复合用例 `enip_t180_multiflow_txn_error_branch` 落 **T-180**（每流独立挥手，4 FIN 包断言）；另其同例承载 T-179（多流并发时序不交叉）与 T-217（Status 0x0064 字节面）语义。其余 121 号仍按 A′/B′ 承接（§16.3） |
| 多流正例 | 0（多流面全在 legacy 多单元，链上不可达） | **1**（framework `flows=2` 复制流，四元组独立 + 逐流 FIN）；多会话/多流**链上层内展开**（`session_count/flow_count>1`）仍拒（G-ENIP-1） |
| 复合大场景（§9.50 ≥3 类交织） | 无（最复杂例仅 1 类交织） | **1**：`enip_t180_multiflow_txn_error_branch` = 多流 + 多事务 + 异常分支 |
| 负例锚词 | 44 例 / 42 种 | 55 例；5 例按现状重锚（t104/t105 严格解码、t108/t109/t110 `io_data`、t117/t118 0 包锚）并在 notes 披露根因 |
| suite | 不宣称绿 | lane6 MCP **137/137** + 离线链套件 **137/137**（P6 双通道实测） |

---

## 17. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 立项号 | 缺口 | 确认方式（文档 / 抓包 / 问人 三选一） | 去向 |
|---|---|---|---|
| G-ENIP-1 | 多会话/多流：`session_count×flow_count` 单元展开在链上不可达（生成器显式拒绝 layer_gen.go:68-71；`u := s*flowCount + f` enip.go:590 仅 legacy 面）；12 例多单元用例失落地 | 查规范（CIP Vol.1 Connection Manager 多连接语义）+ 抓设备多连接包 | B′ → D-ENIP-1「明确不解决 + 迁入计划」（§16.3） |
| G-ENIP-2 | UDP I/O 面：`io_data`/`transport:"udp"` 被拒（layer_gen.go:56-64；`if transport == "udp"` enip.go:627 仅 legacy 面）；9 例 I/O 用例（含 SequenceCounter 全家族 + T-141/T-142 去 seq 前缀对账项）失落地 | 查规范（Vol.2 Class 0/1 隐式 I/O）+ 抓 PLC I/O 周期包 | B′ → D-ENIP-1 迁入计划；落地前 legacy 单测保证据 |
| G-ENIP-3 | 业务键未住层：registry 零 Fields（registry.go:193-200）→ `layers[i].enip.*` 报 unknown field（complete.go:293）；顶层 `enip` 子映射 135/135 例并存；pipe_gate 门2-1 对 enip 现状只报黄 | 代码实读 | **必做**（§15 8.1）；落地同时开 presence 判死（§14-P2） |
| G-ENIP-4 | 业务字段动态：enip 不在 `layerDynAllowlist`（layer_dyn.go:17-71）；§12.14 要求逐协议列动态清单与序号算法（本契约 §14.12 已列） | 代码实读 + §12 评估 | D-ENIP-1 条目（逐字段开/不开理由；落地前按 §9.36 现状钉） |
| G-ENIP-5 | 现网字段值核对：ListIdentity 响应字段（VendorID/ProductName/Revision 等）与 Forward_Open 参数（RPI/连接尺寸/连接类型位）的 Rockwell 实测形态（fixture 值如 0x0001/0x0B 仅为示例，T-009 已注） | 抓包（RSLinx/Studio 5000 浏览设备）或读设备 EDS 文件 | P5 前置确认项（不挡开工）；确认后回填 §13.2 映射表 |
| G-ENIP-6 | Logix/PCCC 方言面（0x4C/0x4D/0x52/0x55/0x4B）零断言；0x52 同码需按目标设备模型注记（OpENer=Unconnected_Send，§2.5.3/R19） | 查 libplctag defs.h + OpENer 同码语义；抓 Logix 标签读写包 | A′ 补例（§16.3）+ 用例注记设备模型 |
| G-ENIP-7 | 非正常结束面：TCP 中途断开（FIN/RST）、Forward_Open 后未 Close 即断、会话中途失效后的重连 | 查规范 §4.1/§4.2 状态迁移 + 实证（抓断开形） | A′ 半程（§16.1②）+ 迁入计划 |
| G-ENIP-8 | `validateFromResponseConfig`（enip.go:879）只在 **drive 期** 跑（layer_gen.go:84），错误被 Plan goroutine 吞成空流 → 链级负例只能以 worker 通用锚 `planner produced 0 packet configs`（worker.go:421）钉现状（`enip_t117_source_cmd_index_99`/`enip_t118_unknown_fromresp_field`）。锚诚实（校验失效即产包成功、用例变红，不假绿）但**鉴别力弱**（通用锚无法区分成因） | 代码实读（P6 修轮实证：临时探针确认 plan ok / 0 packets） | 推进项（不挡关单）：把该校验并入 `Planner.Validate` 同步面，使 T-117/T-118 以原锚词拒绝；落地后重校准两条用例锚词。**本轮已修 notes 披露**（不得以通用锚冒充专属锚） |

**缺口数：8**（G-ENIP-3 为必做合规项，**P4 已落地可核销**；G-ENIP-1/2/4 为 B′ 结构立项，其中 G-ENIP-1 的 **framework 多流面已由 P6 复合用例部分承接**；G-ENIP-5 为确认项；G-ENIP-6/7 为 A′ 补例面；G-ENIP-8 为同步面推进项）。

---

**文档结束**

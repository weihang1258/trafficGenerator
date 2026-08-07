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

---

**文档结束**

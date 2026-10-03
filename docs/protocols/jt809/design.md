# Part B: JT809

> **文档状态（2026-10-01）**：本文件 §§2B–16 保留为规范/目标设计基线，并与当前实现分层对照；其中旧的 32B、无起止符、无 CRC 描述仅作历史候选，不是当前生成器线形。当前可执行契约以 `trafficgen/test/protocol_pcap/cases/jt809.json` 与 `docs/protocols/jt809/testcase.md` 为准：15 例（11 正、4 负，其中 T-15 为 presence 判死负例），正例均为 `[ip,jt809]` as-built 层形；当前线形为 `5B` 起始、`5D` 结束、CRC16、2011/2013 为 22B 头、2019 为 30B 头。以下文档只报告静态机读核对，不声称 suite、pcap 或 NIC 已运行。
>
> 三源权威链：JT/T 809-2019（字段/枚举/链路语义）→本设计（候选与目标矩阵）→`trafficgen/internal/protocol/jt809/{types.go,builder.go,layer_gen.go,parser.go}`（as-built）→ cases JSON（可执行断言）。冲突时实现与 cases 现状必须单列缺口，不得把历史设计当作证据。

## 2B. 协议概述

JT809（JT/T 809-2019，道路运输车辆卫星定位系统平台数据交换，platform data exchange / 平台数据交换）定义下级平台（lower platform / 下级平台）与上级平台（upper platform / 上级平台）之间的数据交换协议。区别于 JT808（终端↔平台），JT809 是平台↔平台。

JT809 使用两条独立 TCP 连接：
- 主链路（main link / 主链路）：下级平台 → 上级平台，端口 8812。下级平台作为 TCP 客户端发起连接，承载业务数据上报。
- 从链路（slave link / 从链路）：上级平台 → 下级平台，端口可由实现约定（典型 8813）。上级平台作为 TCP 客户端发起连接，承载管理/控制消息。

两条链路独立维护 MsgSN 计数器。主链路消息以 MsgId 0x1xxx 标识，从链路以 0x9xxx 标识。

JT809 报文无起始/结束符，定界依赖 4 字节 MsgLength 前缀。无转义。无显式校验字段（依赖 TCP 校验和与上层业务逻辑）。

## 3B. 报文格式

### 3B.1 消息头字段表（32 字节固定）

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 4 | MsgLength | uint32 BE，整条报文长度（含本字段、消息头、消息体；不含加密填充） |
| 4 | 4 | MsgSN | uint32 BE，0-4294967295 回绕 |
| 8 | 2 | MsgId | uint16 BE，例 0x1001=主链路登录请求 |
| 10 | 1 | VehicleColor | 车辆颜色（同 JT808 LicenseColor；0=未上车牌） |
| 11 | 21 | VehiclePlate | 车牌号，GBK，左空格填充至 21 字节 |

> VehicleColor + VehiclePlate 是消息头的固定部分（不归消息体），所有 MsgId 共享。对于非车辆相关消息（如 0x1001 登录），VehicleColor=0、VehiclePlate=空格填充 21 字节。
>
> VehicleColor 取值表（JT/T 809-2019 §4.2 与 JT/T 415-2006《道路运输车辆卫星定位系统 车载终端》表 A.1 一致；该取值表源自 JT/T 415-2006，并非 JT/T 808-2019 附录 A——JT/T 808-2019 附录 A 定义的是 AlarmFlag/StatusFlag 报警标志位与状态标志位，与车辆颜色无关）：
>
> | 值 | 含义 | 值 | 含义 |
> |----|------|----|------|
> | 0 | 未上车牌/其他 | 5 | 黄色 |
> | 1 | 蓝色 | 6 | 黑色 |
> | 2 | 黄色（农用） | 7 | 白色 |
> | 3 | 绿色 | 8 | 渐变绿 |
> | 4 | 红色 | 9 | 黄绿双拼色 |
>
> 车辆相关 MsgId（VehicleColor/VehiclePlate 携带有效值，必须填实际车辆信息）：0x1200/0x1300/0x1400/0x1500/0x1600（下级平台→上级平台方向）以及 0x9100/0x9600（从链路双向）共 7 个容器/单发消息。非车辆 MsgId（VehicleColor=0、VehiclePlate=21 字节空格填充）：0x1001/0x1002/0x1003（主链路登录/登出/保活）以及 0x9001/0x9002/0x9003（从链路登录/登出/保活）共 6 个。

### 3B.2 主链路 / 从链路区分

| 链路 | MsgId 高字节 | 方向 | 典型 MsgId |
|------|--------------|------|------------|
| 主链路 | 0x10-0x7F | 下级→上级 | 0x1001 登录请求、0x1003 注销、0x1200 车辆动态、0x1300 平台交互、0x1400 报警、0x1500 静态信息、0x1600 控制应答 |
| 从链路 | 0x80-0xFF | 上级→下级 | 0x9001 连接请求、0x9100 平台管理、0x9600 车辆控制 |

主链路与从链路是两条独立 TCP 4-tuple，但同属一个"下级平台↔上级平台"业务会话。Planner 通过 GroupID 关联两者，保证同一对平台的两条 TCP 流由同一 PacketWorker 处理（顺序：先主链路登录，后从链路连接）。

### 3B.3 加密标识

MsgId bit 位不携带加密标识。加密由消息体内的 `EncryptFlag + EncryptKey` 字段携带（M1/IA1/IC1 算法）。本实现不真做加密，仅置位 EncryptFlag 与占位 EncryptKey。

## 4B. 关键消息体格式

### 4B.1 0x1001 主链路登录请求（main link login request / 主链路登录请求）

| 字段 | 长度 | 类型 | 说明 |
|------|------|------|------|
| UserName | 5 | byte[5] ASCII | 下级平台用户名（**不足 5 字符时右补 0x00 至 5 字节**；默认值 = GNSSCenterId 转为 9 位零填充数字字符串后取末 5 位，如 GNSSCenterId=291 → "000000291" → 末 5 位 "00291"） |
| Password | 10 | byte[10] ASCII | 下级平台密码（不足 10 字符时右补 0x00 至 10 字节） |
| GNSSCenterId | 4 | uint32 BE | 下级平台唯一编号（9 位数字的整型表示） |
| VersionFlag | 1 | uint8 | 协议版本（0=2011，1=2013，2=2019） |
| EncryptFlag | 1 | uint8 | 加密标识（0=不加密，1=加密） |
| EncryptKey | 4 | uint32 BE | 加密密钥（占位） |

> 0x1001 仅在主链路上发送，**不含 LinkFlag 字段**：链路由 Procedure.Link 字段（"main"/"slave"）与消息发送在哪条 TCP 连接决定，不由消息体字段决定。JT/T 809-2019 §4.2.1.1 明确 0x1001 消息体仅上述 6 个字段共 25 字节。0x1001 的消息头中 VehicleColor=0、VehiclePlate=空格填充。UserName 5 字节固定，Password 10 字节固定。

### 4B.2 0x1002 主链路登录应答（main link login response / 主链路登录应答）

| 字段 | 长度 | 说明 |
|------|------|------|
| Result | 1 | 0=成功，1=失败，2=密码错误，3=账号不存在，4=已登录（按 JT/T 809-2019，仅 0-4 五值；99 在标准附录存在时用于"其他"扩展，本设计 Validate 拒绝 Result ∉ {0,1,2,3,4}，若启用"99=其他"扩展须显式配置） |
| GNSSCenterId | 4 | uint32 BE |

> 0x1002 **仅用于应答 0x1001**（主链路登录请求），不用于应答 0x1200/0x1400 等业务消息。JT809 **没有**类似 JT808 0x8001 的"通用应答"消息——每个 0x1200 SubMsgId 子业务有自己的应答模式（部分子业务无应答，部分有专门的应答子消息如 0x1300 SubMsgId=0x03）。上级平台对 0x1200/0x1400 等的应答按 JT/T 809-2019 应为对应子业务应答或不应答，而非 0x1002。消息体 5 字节，**无 ResponseSN 字段**（应答绑定通过消息头的 GNSSCenterId + MsgSN 完成）。

### 4B.3 0x1003 主链路注销请求（main link logout / 主链路注销）

消息体空。下级平台主动断开。

### 4B.4 0x1007 主链路断开通知（main link disconnect notice / 主链路断开通知）

| 字段 | 长度 | 说明 |
|------|------|------|
| ReasonCode | 1 | 0=正常，1=紧急，2=故障（按 JT/T 809-2019 仅 0-2 三值；Validate 拒绝 ReasonCode ∉ {0,1,2}，删除"99=其他"以避免臆造值） |
| GNSSCenterId | 4 | uint32 BE |

### 4B.5 0x1200 主链路车辆动态信息（vehicle dynamic / 车辆动态）

容器消息，承载子类型（sub type / 子类型）0x1201-0x120A。子类型由消息体首字节的 SubMsgId 标识。

| 字段 | 长度 | 说明 |
|------|------|------|
| SubMsgId | 1 | 0x01=车辆注册 0x1201，0x02=实时定位 0x1202，0x03=定位补报 0x1203，0x04=报警附件 0x1204，0x05=车辆定向 0x1205，0x06=区域车辆 0x1206，0x07=路径记录上报 0x1207，0x08=报警 0x1208，0x09=事件上报 0x1209，0x0A=车辆注销 0x120A |
| SubLength | 2 | uint16 BE，子消息体长度（不含 SubMsgId + SubLength 自身） |
| SubBody | variable | 子消息体 |

子类型 0x1201 车辆注册 SubBody（JT809 自有布局，**不复用 JT808 0x0100**——车牌/车牌颜色已在 0x1200 消息头 VehicleColor/VehiclePlate 中出现，不重复）：

| 字段 | 长度 | 说明 |
|------|------|------|
| TerminalPhone | 6 | BCD（同 JT808 Phone） |
| ManufacturerId | 5 | byte[5] ASCII |
| TerminalModel | 20 | byte[20]，左对齐右补空格 |
| TerminalId | 7 | byte[7] |

子类型 0x1202 实时定位 SubBody：等同 JT808 0x0200 消息体（AlarmFlag 4 + StatusFlag 4 + Lat 4 + Lon 4 + Alt 2 + Speed 2 + Direction 2 + Time 6 + ExtraItems variable）。

子类型 0x1203 定位补报 SubBody：首字段 TimeRange(12 BCD)，后接 N 条 0x0200 消息体。

子类型 0x1204 报警附件 SubBody（JT/T 809-2019 §5.4.2）：

| 字段 | 长度 | 说明 |
|------|------|------|
| AlarmFlag | 4 | uint32 BE |
| AlarmTime | 6 | BCD YYMMDDhhmmss |
| AlarmInfo | variable | 报警详情 |
| FileType | 1 | 0=无，1=图片，2=音频，3=视频 |
| FileSize | 4 | uint32 BE，附件字节数；FileType=0 时填 0 |
| FileUrl | variable | 附件 URL（GBK，编码后最大 256 字节） |

子类型 0x1205 车辆定向 SubBody：

| 字段 | 长度 | 说明 |
|------|------|------|
| TerminalPhone | 6 | BCD |
| Direction | 2 | uint16 BE |

子类型 0x1206 区域车辆 SubBody：

| 字段 | 长度 | 说明 |
|------|------|------|
| TerminalPhone | 6 | BCD |
| AreaType | 1 | 0=圆形，1=矩形，2=多边形 |
| AreaData | variable | 区域定义（按 AreaType 不同布局） |

子类型 0x1207 路径记录上报 SubBody：

| 字段 | 长度 | 说明 |
|------|------|------|
| TerminalPhone | 6 | BCD |
| PathCount | 2 | uint16 BE，路径点数 |
| PathPoints | variable | N 条位置点（每条同 0x0200 简化体） |

子类型 0x1208 报警 SubBody：

| 字段 | 长度 | 说明 |
|------|------|------|
| AlarmFlag | 4 | uint32 BE（同 JT808） |
| PulseSpeed | 2 | uint16 BE，脉冲速度（0.1 km/h，扩展表 3 字段） |
| ... | variable | 同 0x0200 + 附加报警信息字段 |

子类型 0x1209 事件上报 SubBody：

| 字段 | 长度 | 说明 |
|------|------|------|
| TerminalPhone | 6 | BCD |
| EventId | 2 | uint16 BE，事件 ID |
| EventTime | 6 | BCD YYMMDDhhmmss |

子类型 0x120A 车辆注销 SubBody：

| 字段 | 长度 | 说明 |
|------|------|------|
| TerminalPhone | 6 | BCD |

### 4B.6 0x1300 平台交互（platform interaction / 平台交互）

| 字段 | 长度 | 说明 |
|------|------|------|
| SubMsgId | 1 | 0x01=查询车辆 0x1301，0x02=查询区域车辆 0x1302，0x03=应答 0x1303，0x04=查询指定车牌车辆 0x1304，0x05=查询车主手机号 0x1305 |
| SubLength | 2 | uint16 BE |
| SubBody | variable | 子消息体 |

SubMsgId=0x01 (0x1301 查询车辆) SubBody：

| 字段 | 长度 | 说明 |
|------|------|------|
| VehicleColor | 1 | 车辆颜色 |
| VehiclePlate | 21 | GBK 车牌 |
| QueryTime | 6 | BCD 查询时间 |

SubMsgId=0x03 (0x1303 应答) SubBody：

| 字段 | 长度 | 说明 |
|------|------|------|
| ResponseSN | 4 | uint32 BE，所应答的报文 MsgSN |
| Result | 1 | 0=成功，1=失败 |

### 4B.7 0x1400 报警信息（alarm with attachment / 报警附件）

| 字段 | 长度 | 说明 |
|------|------|------|
| AlarmFlag | 4 | uint32 BE |
| AlarmTime | 6 | BCD YYMMDDhhmmss |
| AlarmInfo | variable | 报警详情 |
| FileType | 1 | 0=无附件，1=图片，2=音频，3=视频 |
| FileUrl | variable | 附件 URL（GBK，**GBK 编码后最大 256 字节**；FileType=0 时为空） |

### 4B.8 0x9001 从链路连接请求（slave link connect request / 从链路连接请求）

| 字段 | 长度 | 说明 |
|------|------|------|
| UserName | 5 | byte[5] ASCII |
| Password | 10 | byte[10] ASCII |
| GNSSCenterId | 4 | uint32 BE |
| VersionFlag | 1 | 同 0x1001 |
| EncryptFlag | 1 | 同 0x1001 |
| EncryptKey | 4 | uint32 BE |

> 0x9001 仅在从链路上发送，**不含 LinkFlag 字段**：从链路特性由 TCP 连接方向决定，不需要在消息体中重复标识。结构对称于 0x1001（仅 MsgId 不同）。

### 4B.9 0x9002 从链路连接应答

| 字段 | 长度 | 说明 |
|------|------|------|
| Result | 1 | 同 0x1002 |
| GNSSCenterId | 4 | uint32 BE |

### 4B.10 0x9100 从链路平台管理（slave platform management / 从链路平台管理）

| 字段 | 长度 | 说明 |
|------|------|------|
| SubMsgId | 1 | 0x01=查询主链路状态 0x9101，0x02=主链路断开通知 0x9102，0x03=链路连接情况 0x9103，0x04=休眠状态通知 0x9104，0x05=轮询计划发送 0x9105 |
| SubLength | 2 | uint16 BE |
| SubBody | variable | 子消息体 |

SubMsgId=0x01 (0x9101 查询主链路状态) SubBody：

| 字段 | 长度 | 说明 |
|------|------|------|
| GNSSCenterId | 4 | uint32 BE，所查询的下级平台编号 |

SubMsgId=0x02 (0x9102 主链路断开通知) SubBody：

| 字段 | 长度 | 说明 |
|------|------|------|
| GNSSCenterId | 4 | uint32 BE |
| ReasonCode | 1 | 0=正常，1=紧急，2=故障 |

### 4B.11 0x9600 从链路车辆控制（slave vehicle control / 从链路车辆控制）

| 字段 | 长度 | 说明 |
|------|------|------|
| SubMsgId | 1 | 0x01=车辆控制 0x9601，0x02=下发报警 0x9602，0x03=下发定位条件 0x9603 |
| SubLength | 2 | uint16 BE |
| SubBody | variable | 子消息体 |

SubMsgId=0x01 (0x9601 车辆控制) SubBody：

| 字段 | 长度 | 说明 |
|------|------|------|
| VehicleColor | 1 | uint8 |
| VehiclePlate | 21 | GBK |
| ControlType | 1 | 0=锁车，1=解锁，2=断油路，3=恢复油路，4=点火，5=熄火 |
| ControlParam | variable | 控制参数（按 ControlType 不同布局） |

SubMsgId=0x02 (0x9602 下发报警) SubBody：

| 字段 | 长度 | 说明 |
|------|------|------|
| VehicleColor | 1 | uint8 |
| VehiclePlate | 21 | GBK |
| AlarmType | 1 | 0=解除报警，1=下发报警 |
| AlarmContent | variable | GBK 报警内容 |

### 4B.12 0x1500 车辆静态信息（vehicle static info / 车辆静态信息）

| 字段 | 长度 | 说明 |
|------|------|------|
| SubMsgId | 1 | 0x01=车辆静态信息 0x1501，0x02=查询车辆静态信息 0x1502 |
| SubLength | 2 | uint16 BE |
| SubBody | variable | 车辆静态信息 |

SubMsgId=0x01 (0x1501 车辆静态信息) SubBody：

| 字段 | 长度 | 说明 |
|------|------|------|
| VehicleColor | 1 | uint8 |
| VehiclePlate | 21 | GBK |
| VIN | 17 | ASCII 车架号 |
| VehicleBrand | variable | GBK 品牌 |
| VehicleModel | variable | GBK 型号 |
| ProductionDate | 6 | BCD YYMMDDhhmmss |
| OwnerName | variable | GBK 车主姓名 |

### 4B.13 0x1600 车辆控制应答（vehicle control response / 车辆控制应答）

| 字段 | 长度 | 说明 |
|------|------|------|
| SubMsgId | 1 | 0x01=控制应答 0x1601，0x02=报警下发应答 0x1602 |
| SubLength | 2 | uint16 BE |
| SubBody | variable | 控制结果 |

SubMsgId=0x01 (0x1601 控制应答) SubBody：

| 字段 | 长度 | 说明 |
|------|------|------|
| VehicleColor | 1 | uint8 |
| VehiclePlate | 21 | GBK |
| ControlType | 1 | 同 0x9601 的 ControlType |
| Result | 1 | 0=成功，1=失败，2=消息有误，3=不支持 |

## 5B. Config 结构体设计

### 5B.1 Validate 规则表

| 字段 | 合法范围 | 拒绝条件 |
|------|----------|----------|
| GNSSCenterId | uint32 (0-999999999) | >999999999 |
| UserName | 0-5 ASCII 字符（不足 5 时右补 0x00） | >5 字符 |
| Password | 0-10 ASCII 字符（不足 10 时右补 0x00） | >10 字符 |
| VersionFlag | 0,1,2 | >=3 |
| EncryptFlag | 0,1 | >=2 |
| LoginResult | 0,1,2,3,4（按 JT/T 809-2019） | >=5（若启用"99=其他"需显式配置） |
| DisconnectReason | 0,1,2 | >=3 |
| FileUrl | GBK 编码后 ≤ 256 字节 | 编码后 >256 字节 |
| VehiclePlate | GBK 编码后 ≤ 21 字节 | 编码后 >21 字节 |
| InitialSN | uint32 (0-0xFFFFFFFF) | （无限制） |

> **多下级平台唯一性**：当 strategies 列表中有多个 JT809Config 时，Validate 强制所有 GNSSCenterId 互异——若存在重复，GroupID=hash(GNSSCenterId) 会将两条不同 TCP 流路由到同一 PacketWorker，导致 MsgSN 计数器共享与消息串扰。UniquePlatformGNSSCenterIds 字段级别检查。

```go
// JT809Config configures a JT/T 809-2019 platform-to-platform exchange.
type JT809Config struct {
    // GNSSCenterId (下级平台编号) 9-digit integer, packed into uint32.
    // Required. Range 0..999999999.
    GNSSCenterId uint32 `json:"gnss_center_id"`

    // UserName (用户名) 5 ASCII chars, default = last 5 digits of
    // GNSSCenterId zero-padded. Concretely: GNSSCenterId (uint32) is
    // formatted as a 9-digit zero-padded decimal string, then the last
    // 5 digits are taken. E.g., GNSSCenterId=291 → "000000291" →
    // "00291". When the user-supplied string is shorter than 5 chars,
    // it is right-padded with 0x00 to 5 bytes.
    UserName string `json:"user_name,omitempty"`

    // Password (密码) 10 ASCII chars, default "0000000000".
    Password string `json:"password,omitempty"`

    // VersionFlag (协议版本) 0=2011, 1=2013, 2=2019 (default).
    VersionFlag uint8 `json:"version_flag,omitempty"`

    // EncryptFlag (加密标识) 0=plain (default), 1=encrypted.
    // When 1, EncryptKey is emitted as a placeholder uint32; no real
    // encryption is applied (design §11B.2).
    EncryptFlag uint8 `json:"encrypt_flag,omitempty"`

    // EncryptKey (加密密钥) placeholder, default 0x00000000.
    EncryptKey uint32 `json:"encrypt_key,omitempty"`

    // LoginResult (登录应答结果) for 0x1002/0x9002. 0=success (default).
    LoginResult uint8 `json:"login_result,omitempty"`

    // VehicleColor (车辆颜色) for vehicle-related messages. 0 when
    // the message is not vehicle-specific (e.g. 0x1001).
    VehicleColor uint8 `json:"vehicle_color,omitempty"`

    // VehiclePlate (车牌号) GBK, only when VehicleColor != 0.
    VehiclePlate string `json:"vehicle_plate,omitempty"`

    // InitialSN (起始流水号) for the per-link MsgSN counter. Each
    // link (main + slave) maintains an independent counter.
    InitialSN uint32 `json:"initial_sn,omitempty"`

    // Procedures (业务流程) ordered list of JT809 messages.
    Procedures []JT809Procedure `json:"procedures"`

    // SlaveLinkEnabled (从链路启用) when true, the planner emits a
    // second TCP flow (upper→lower) carrying 0x9xxx messages. Default
    // false (main link only).
    SlaveLinkEnabled bool `json:"slave_link_enabled,omitempty"`
}

type JT809Procedure struct {
    // Type selects the message template. One of:
    // "main_login", "main_login_response", "main_logout",
    // "main_disconnect_notice", "vehicle_register", "realtime_location",
    // "history_location", "alarm", "alarm_with_attachment",
    // "platform_interaction", "vehicle_static", "control_response",
    // "slave_connect", "slave_connect_response", "slave_management",
    // "slave_vehicle_control".
    Type string `json:"type"`

    // Link (链路) "main" (default) | "slave". Selects which TCP flow
    // carries this message. The planner auto-routes 0x9xxx to slave,
    // 0x1xxx to main; this field is an override for edge cases.
    Link string `json:"link,omitempty"`

    // SubMsgId (子消息ID) for 0x1200/0x1300 container messages.
    // 0x01..0x0A.
    SubMsgId uint8 `json:"sub_msg_id,omitempty"`

    // SubBody (子消息体) raw bytes for container messages.
    SubBody []byte `json:"sub_body,omitempty"`

    // LocationData (位置数据) for "realtime_location" / "history_location".
    // Reuses JT808Location since the location body layout is identical.
    LocationData *JT808Location `json:"location_data,omitempty"`

    // HistoryCount (历史条数) for "history_location", default 1.
    HistoryCount int `json:"history_count,omitempty"`

    // AlarmFlag (报警标志) for "alarm".
    AlarmFlag uint32 `json:"alarm_flag,omitempty"`

    // PulseSpeed (脉冲速度) for "alarm" 0x1208 SubBody. uint16 BE,
    // 0.1 km/h. Required for 0x1208 报警子业务 by JT/T 809-2019
    // §4.2.2.8 (扩展表 3 字段)。0 = no pulse speed data.
    PulseSpeed uint16 `json:"pulse_speed,omitempty"`

    // AlarmTime (报警时间) "YYMMDDhhmmss".
    AlarmTime string `json:"alarm_time,omitempty"`

    // FileType (附件类型) for "alarm_with_attachment". 0/1/2/3.
    FileType uint8 `json:"file_type,omitempty"`

    // FileUrl (附件URL) GBK string, **max 256 bytes after GBK encoding**
    // (Validate first GBKEncode(FileUrl) then check len <= 256).
    FileUrl string `json:"file_url,omitempty"`

    // LoginResult (登录结果) per-procedure override for
    // "main_login_response" / "slave_connect_response".
    // **Per-procedure value takes precedence over the top-level
    // JT809Config.LoginResult**; top-level is the default when the
    // per-procedure pointer is nil. When the planner generates 0x1002
    // /0x9002 responses, it uses the LoginResult from the
    // corresponding 0x1001/0x9001 procedure (per-procedure), falling
    // back to top-level if nil.
    LoginResult *uint8 `json:"login_result,omitempty"`

    // DisconnectReason (断开原因) for "main_disconnect_notice".
    DisconnectReason uint8 `json:"disconnect_reason,omitempty"`

    // VehicleColor / VehiclePlate per-procedure override (for messages
    // that switch vehicle mid-session).
    VehicleColor *uint8 `json:"vehicle_color,omitempty"`
    VehiclePlate string `json:"vehicle_plate,omitempty"`
}
```

## 6B. 状态机

下级平台侧状态机：

```
       [init]
         |
         |  TCP connect to upper:8812 (main link)
         v
    [main_connected]
         |
         |  send 0x1001 main login
         v
  [main_login_await] --0x1002 result=0--> [main_logged_in]
         |                                     |
         |  0x1002 result!=0                   |  optional: slave link
         v                                     v
    [terminated]                         [main_logged_in]
                                              |
                                              |  if SlaveLinkEnabled:
                                              |  accept upper→lower TCP (slave link)
                                              v
                                       [slave_connected]
                                              |
                                              |  send 0x9001 slave connect
                                              v
                                       [slave_logged_in]
                                              |
                                              |  send 0x1200/0x1300/0x1400... (main)
                                              |  send 0x9100/0x9600... (slave)
                                              v
                                       [exchanging]
                                              |
                                              |  send 0x1003 logout OR 0x1007 disconnect
                                              v
                                       [terminated]
                                              |
                                              |  TCP 4-way teardown (both links)
                                              v
                                         [closed]
```

上级平台侧（响应方）状态机对称：接收 0x1001 → 回 0x1002（仅应答登录）；接收 0x1200 → 回 0x1300 SubMsgId=0x03 子业务应答或不应答（**不**用 0x1002 应答业务消息）。

### 6B.1 主链路状态转移表

| 当前状态 | 触发事件 | 输出消息 | 下一状态 |
|----------|----------|----------|----------|
| init | task 启动 | TCP SYN (main link) | main_connected |
| main_connected | 进入登录前置 | 0x1001 main_login | main_login_await |
| main_login_await | 收到 0x1002 result=0 | - | main_logged_in |
| main_login_await | 收到 0x1002 result!=0 | TCP FIN | terminated |
| main_logged_in | 准备上报车辆 | 0x1200 (SubMsgId=0x01) | vehicle_register_await |
| vehicle_register_await | 收到 0x1300 SubMsgId=0x03 (应答) | - | main_logged_in |
| vehicle_register_await | 30s 超时无应答 | - | main_logged_in（JT809 部分子业务无应答，planner 直接进入下一状态） |
| main_logged_in | 准备上报定位 | 0x1200 (SubMsgId=0x02) | location_await |
| location_await | 收到 0x1300 SubMsgId=0x03 | - | main_logged_in |
| location_await | 30s 超时无应答 | - | main_logged_in |
| main_logged_in | 准备上报报警 | 0x1400 | alarm_await |
| alarm_await | 收到 0x1300 SubMsgId=0x03 | - | main_logged_in |
| alarm_await | 30s 超时无应答 | - | main_logged_in |
| main_logged_in | 主动注销 | 0x1003 logout | terminated |
| main_logged_in | 故障断开 | 0x1007 disconnect_notice | terminated |
| terminated | TCP teardown (main + slave) | FIN/ACK | closed |

### 6B.2 从链路状态转移表

| 当前状态 | 触发事件 | 输出消息 | 下一状态 |
|----------|----------|----------|----------|
| init | SlaveLinkEnabled=true 且主链路已登录 | TCP SYN (slave link, upper→lower) | slave_connected |
| slave_connected | 进入从链路登录 | 0x9001 slave_connect | slave_login_await |
| slave_login_await | 收到 0x9002 result=0 | - | slave_logged_in |
| slave_login_await | 收到 0x9002 result!=0 | TCP FIN (slave) | slave_terminated |
| slave_logged_in | 平台管理触发 | 0x9100 (SubMsgId) | slave_exchanging |
| slave_logged_in | 车辆控制触发 | 0x9600 (SubMsgId) | slave_exchanging |
| slave_exchanging | 主链路注销 | TCP FIN (slave) | slave_terminated |

### 6B.3 状态变量

每个下级平台会话维护以下状态变量：

- `mainMsgSN uint32`：主链路消息流水号，初值=InitialSN，**首条消息使用 SN=InitialSN，发送后递增**（即第二条 SN=InitialSN+1），回绕 0xFFFFFFFF→0。
- `slaveMsgSN uint32`：从链路消息流水号，**完全独立于主链路计数器**，初值=InitialSN，**首条消息 SN=InitialSN**；主链路 0x1001 用完 SN=0、SN=1 后，从链路 0x9001 仍可从 SN=0 重新开始（两者互不影响）。
- `platformMainMsgSN uint32`：平台侧主链路消息流水号，**per-Platform 独立**——每个下级平台会话（含对端上级平台模拟）拥有自己的 platformMainMsgSN 计数器，与对端平台的 platformMainMsgSN 互不干扰；初值=0（默认 PlatformInitialSN=0），**首条应答 SN=0**，发送后递增，回绕 0xFFFFFFFF→0。
- `platformSlaveMsgSN uint32`：平台侧从链路消息流水号，**per-Platform 独立**，完全独立于 platformMainMsgSN；初值=0（默认 PlatformInitialSN=0），**首条应答 SN=0**，发送后递增。
- `gnssCenterId uint32`：下级平台编号。
- `mainFlowID string`："jt809-main-{GNSSCenterId}-{InitialSN}"（在 Config 阶段就确定，避免 src_port 晚分配导致 flowID 不稳定）。
- `slaveFlowID string`："jt809-slave-{GNSSCenterId}-{InitialSN}"（同上；从链路 InitialSN 与主链路独立，但通常同值）。
- `groupID string`：hash(GNSSCenterId)，保证主从链路同 PacketWorker。
- `mainTcpSeq uint32` / `mainTcpAck uint32`：主链路 TCP 序列号。
- `slaveTcpSeq uint32` / `slaveTcpAck uint32`：从链路 TCP 序列号。
- `lastMainSentSN uint32` / `lastSlaveSentSN uint32`：用于绑定 0x1300 SubMsgId=0x03 应答的 ResponseSN（注意：0x1002 **不**绑定 ResponseSN，0x1002 仅应答 0x1001）。
- `lastMainReceivedSN uint32` / `lastSlaveReceivedSN uint32`：上级平台侧状态。

### 6B.4 上级平台侧状态机

上级平台侧（响应方）状态机对称：

| 当前状态 | 触发事件 | 输出消息 | 下一状态 |
|----------|----------|----------|----------|
| init | TCP SYN 到达 (main link) | SYN-ACK | main_connected |
| main_connected | 收到 0x1001 | 0x1002 main_login_resp | main_logged_in |
| main_logged_in | 收到 0x1200 | 0x1300 SubMsgId=0x03 子业务应答（或不应答） | main_logged_in |
| main_logged_in | 收到 0x1400 | 0x1300 SubMsgId=0x03 子业务应答（或不应答） | main_logged_in |
| main_logged_in | 收到 0x1003 | TCP FIN | terminated |
| main_logged_in | 收到 0x1007 | TCP FIN | terminated |
| main_logged_in | 上级主动发起从链路 | TCP SYN (slave link) | slave_initiated |
| slave_initiated | 收到 0x9001 | 0x9002 slave_connect_resp | slave_logged_in |

## 7B. 业务场景与数据场景

### 7B.1 主链路登录 0x1001 → 0x1002

下级平台 TCP 连接到上级 8812，发送 0x1001，上级回 0x1002。

数据场景：
- (a) 成功：Result=0，GNSSCenterId 一致。
- (b) 密码错误：Result=2。
- (c) 账号不存在：Result=3。
- (d) 已登录：Result=4（对抗，重连场景）。
- (e) 其他：Result=99。

### 7B.2 主链路注销 0x1003

下级平台发送 0x1003（消息体空），随后 TCP 四次挥手。

数据场景：
- (a) 标准注销。
- (b) 注销前有未应答的 0x1200（对抗，planner 仍按 Procedures 顺序，0x1003 在最后）。

### 7B.3 主链路断开通知 0x1007

下级平台发送 0x1007（含 ReasonCode），通知上级即将断开，随后 TCP teardown。

数据场景：
- (a) ReasonCode=0（正常）。
- (b) ReasonCode=2（故障）。
- (c) ReasonCode=1（紧急断开，验证紧急场景编码与字段正确）。
- (d) ReasonCode=99（其他，对抗，Validate 拒绝——按 §4B.4 仅 0-2 合法）。

### 7B.4 车辆注册 0x1201（SubMsgId=0x01 of 0x1200）

下级平台通过 0x1200 容器上报车辆注册信息。

数据场景：
- (a) 标准注册：TerminalPhone="13800138000"，ManufacturerId/Model/Id 填充。
- (b) TerminalPhone 12 位全 0（边界）。

### 7B.5 实时定位 0x1202（SubMsgId=0x02）

下级平台上报车辆实时位置，SubBody 等同 JT808 0x0200 消息体。

数据场景：
- (a) 标准位置：北京，速度 60 km/h。
- (b) 边界：lat=0/lon=0。
- (c) 多条上报：5 条 0x1202，MsgSN 递增。

### 7B.6 定位补报 0x1203（SubMsgId=0x03）

下级平台批量上报历史位置。SubBody 首字段 TimeRange(12 BCD)，后接 N 条 0x0200 消息体。

数据场景：
- (a) TimeRange="240803000000"-"240803120000"，3 条位置。
- (b) N=0（边界，仅 TimeRange，对抗，planner 应允许）。

### 7B.7 报警上报 0x1208（SubMsgId=0x08）

下级平台上报车辆报警。

数据场景：
- (a) AlarmFlag=0x00000001（紧急报警），AlarmTime="240803120000"。
- (b) AlarmFlag=0x00000002（超速报警）。

### 7B.8 报警附件地址 0x1400 with FileUrl

下级平台上报报警，附带图片/音频/视频附件 URL。

数据场景：
- (a) FileType=1（图片），FileUrl="http://example.com/alarm/001.jpg"。
- (b) FileType=0（无附件），FileUrl=""。
- (c) FileUrl 超长（GBK 编码后 256 字节边界；UTF-8 输入 128 个汉字 = 256 GBK 字节，验证 Validate 接受）。
- (d) FileUrl 含中文字符（GBK 编码），如"报警图片001.jpg"（"报警图片"4 汉字 = 8 GBK 字节 + 12 ASCII = 20 字节）。
- (e) FileUrl GBK 编码后超 256 字节（对抗，Validate 拒绝；UTF-8 输入 129 个汉字 = 258 GBK 字节）。

### 7B.9 从链路连接 0x9001

上级平台反向连接下级平台（从链路），发送 0x9001。

数据场景：
- (a) SlaveLinkEnabled=true，主链路登录成功后发起从链路 TCP。
- (b) 从链路 LoginResult=0。
- (c) 从链路 LoginResult=2（密码错误，对抗，主链路仍保持）。

### 7B.10 多下级平台并发

M 个下级平台 = M 条主链路 TCP 4-tuple（src_port 各异，dst_port=8812），可选 M 条从链路 TCP。每个平台独立 GNSSCenterId、独立 MsgSN。

数据场景：
- (a) M=3 平台，每个独立完成 main_login → vehicle_register × 2 → logout。
- (b) M=2 平台 + SlaveLinkEnabled，验证主从链路 GroupID 关联正确（同平台的 2 条 TCP 路由到同一 PacketWorker）。
- (c) M=20 平台高并发（性能场景）。

### 7B.11 边界

- (a) GNSSCenterId=0（边界，允许但实际非法）。
- (b) GNSSCenterId=999999999（最大 9 位）。
- (c) 经纬度 0/最大（同 JT808）。
- (d) VehiclePlate 空（消息头 21 字节空格填充）。
- (e) FileUrl 256 字节超长。
- (f) UserName 不足 5 字符（Validate 拒绝）。
- (g) Password 超过 10 字符（Validate 拒绝）。
- (h) VersionFlag=3（对抗，Validate 拒绝）。

### 7B.12 加密占位

EncryptFlag=1，EncryptKey=0xDEADBEEF，验证消息体字段存在且 MsgBody 不变（仅置位）。

数据场景：
- (a) 0x1001 with EncryptFlag=1, EncryptKey=0xDEADBEEF。
- (b) 0x1002 response also carries EncryptFlag=1。

### 7B.13 报文示例（hex dump）

主链路登录请求 0x1001（hex，不含 TCP/IP 头）：

```
                            ; --- 消息头 (32 字节) ---
00 00 00 39                 ; MsgLength=57 (32 + 25 = 57，32 字节消息头 + 25 字节消息体；0x1001 消息体含 UserName 5 + Password 10 + GNSSCenterId 4 + VersionFlag 1 + EncryptFlag 1 + EncryptKey 4)
00 00 00 00                 ; MsgSN=0 (首条=InitialSN，默认 InitialSN=0)
10 01                       ; MsgId=0x1001 (主链路登录请求)
00                          ; VehicleColor=0 (非车辆消息)
20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20  ; VehiclePlate=21 字节空格
                            ; --- 消息体 (25 字节，不含 LinkFlag) ---
54 45 53 54 00              ; UserName="TEST\0" (5 ASCII, 不足 5 字符右补 0x00)
30 30 30 30 30 30 30 30 30 30  ; Password="0000000000" (10 ASCII)
00 00 01 23                 ; GNSSCenterId=291 (下级平台编号)
02                          ; VersionFlag=2 (2019)
01                          ; EncryptFlag=1 (加密占位)
de ad be ef                 ; EncryptKey=0xDEADBEEF
```

> 注：JT809 无起始/结束符，无转义，无校验字节。MsgLength=57 是整条报文长度（32 字节消息头 + 25 字节消息体）。

主链路登录应答 0x1002（成功）：

```
00 00 00 25                 ; MsgLength=37 (32 + 1 + 4 = 37，32 字节消息头含 MsgLength/MsgSN/MsgId/VehicleColor/VehiclePlate，消息体仅 Result+GNSSCenterId 共 5 字节)
00 00 00 00                 ; MsgSN=0 (上级平台侧，首条应答，初值=0)
10 02                       ; MsgId=0x1002
00                          ; VehicleColor=0
20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20  ; VehiclePlate=21 空格
                            ; --- 消息体 (5 字节) ---
00                          ; Result=0 (成功)
00 00 01 23                 ; GNSSCenterId=291
```

车辆注册 0x1200（SubMsgId=0x01，子消息体=终端注册信息）：

```
00 00 00 49                 ; MsgLength=73 (32 + 1 + 2 + 38 = 73)
00 00 00 01                 ; MsgSN=1 (第二条消息，首条 0x1001 用 SN=0 后递增)
12 00                       ; MsgId=0x1200
01                          ; VehicleColor=1 (蓝牌)
be a9 41 31 32 33 34 35 20 20 20 20 20 20 20 20 20 20 20 20 20  ; VehiclePlate="京A12345" + 13 空格 = 21 字节
                            ; --- 消息体 ---
01                          ; SubMsgId=0x01 (车辆注册 0x1201)
00 26                       ; SubLength=38 (子消息体 38 字节)
                            ; --- 子消息体 (0x1201 自有布局，38 字节) ---
01 38 00 13 80 00           ; TerminalPhone BCD "013800138000" (6 字节)
54 45 53 54 00              ; ManufacturerId="TEST\0" (5 ASCII)
54 47 2d 44 45 4d 4f 20 20 20 20 20 20 20 20 20 20 20 20 20  ; TerminalModel="TG-DEMO" 左对齐右补空格至 20 字节
30 30 30 30 30 30 31        ; TerminalId="0000001" (7 ASCII)
```

> 注：0x1201 SubBody 是 JT809 **自有字段布局**（TerminalPhone 6 + ManufacturerId 5 + TerminalModel 20 + TerminalId 7 = 38 字节，**不复用 JT808 0x0100** 的 ProvinceId/CityId/LicenseColor/LicensePlate 字段——这些字段已在 0x1200 消息头的 VehicleColor/VehiclePlate 中出现，不重复）。SubLength=38 是 SubBody 字节数（不含 SubMsgId + SubLength 自身 3 字节）。MsgLength=73 = 32(头) + 1(SubMsgId) + 2(SubLength) + 38(SubBody)。

实时定位 0x1202（SubMsgId=0x02，子消息体=JT808 0x0200 消息体）：

```
00 00 00 3f                 ; MsgLength=63 (32 + 1 + 2 + 28 = 63，0x1202 SubBody=28 字节=AlarmFlag 4+StatusFlag 4+Lat 4+Lon 4+Alt 2+Speed 2+Dir 2+Time 6)
00 00 00 02                 ; MsgSN=2 (第三条消息)
12 00                       ; MsgId=0x1200
01                          ; VehicleColor=1
be a9 41 31 32 33 34 35 ... (21)  ; VehiclePlate
                            ; --- 消息体 ---
02                          ; SubMsgId=0x02 (实时定位 0x1202)
00 1c                       ; SubLength=28 (= 4(AlarmFlag)+4(StatusFlag)+4(Latitude)+4(Longitude)+2(Altitude)+2(Speed)+2(Direction)+6(Time)，不含 SubMsgId/SubLength 自身 3 字节)
                            ; --- 子消息体 (= JT808 0x0200 body) ---
00 00 00 01                 ; AlarmFlag
00 00 00 01                 ; StatusFlag
02 63 b5 60                 ; Latitude=39900000 (39.9 度, 北京实际纬度，与 §7A.14 JT808 0x0200 一致)
06 e6 0c 80                 ; Longitude
00 32                       ; Altitude
02 58                       ; Speed
00 b4                       ; Direction
24 08 03 12 00 00           ; Time BCD
```

> 关键：JT809 0x1202 的子消息体与 JT808 0x0200 的消息体布局完全一致，可直接复用 `jtcommon` 的位置消息体编码函数。但消息头格式不同（JT809 32 字节头 vs JT808 12 字节头），不能整体复用。

从链路连接请求 0x9001：

```
00 00 00 39                 ; MsgLength=57 (32 + 25 = 57，与 0x1001 消息体布局相同)
00 00 00 00                 ; MsgSN=0 (从链路独立计数，首条=InitialSN)
90 01                       ; MsgId=0x9001
00                          ; VehicleColor=0
20 20 ... (21)              ; VehiclePlate=21 空格
                            ; --- 消息体 (25 字节，不含 LinkFlag) ---
54 45 53 54 00              ; UserName
30 30 30 30 30 30 30 30 30 30  ; Password
00 00 01 23                 ; GNSSCenterId
02                          ; VersionFlag=2
01                          ; EncryptFlag=1
de ad be ef                 ; EncryptKey
```

## 8B. 测试用例清单

| # | 用例名 | 类型 | 验证点 |
|---|--------|------|--------|
| B-01 | main_login_success | happy path | 0x1001 字段顺序、固定字段长度；0x1002 Result=0 |
| B-02 | main_login_password_error | negative | Result=2 |
| B-03 | main_login_account_not_found | negative | Result=3 |
| B-04 | main_login_already_logged | negative | Result=4 |
| B-05 | main_login_other | boundary | Result=99 → Validate 拒绝（仅 0-4 合法）；Result=5 → Validate 拒绝（同上边界外值） |
| B-06 | main_logout | happy path | 0x1003 消息体空，TCP FIN 跟随 |
| B-07 | main_disconnect_notice_normal | happy path | 0x1007 ReasonCode=0 |
| B-08 | main_disconnect_notice_fault | boundary | ReasonCode=2 |
| B-09 | vehicle_register | happy path | 0x1200 SubMsgId=0x01，SubLength 正确 |
| B-10 | vehicle_register_zero_phone | boundary | TerminalPhone=12 位 0 |
| B-11 | realtime_location | happy path | 0x1200 SubMsgId=0x02，SubBody=JT808 0x0200 |
| B-12 | realtime_location_zero_latlon | boundary | lat=0, lon=0 |
| B-13 | realtime_location_multi | integration | 5 条 0x1202，MsgSN 递增 |
| B-14 | history_location | happy path | 0x1203 TimeRange + 3 条 0x0200 body |
| B-15 | history_location_zero_count | boundary | N=0，仅 TimeRange |
| B-16 | alarm_emergency | happy path | 0x1208 AlarmFlag=0x01 |
| B-17 | alarm_overspeed | happy path | AlarmFlag=0x02 |
| B-18 | alarm_with_attachment_image | happy path | 0x1400 FileType=1, FileUrl 非空 |
| B-19 | alarm_with_attachment_none | boundary | FileType=0, FileUrl="" |
| B-20 | alarm_with_attachment_long_url | boundary | FileUrl=256 字节 |
| B-21 | alarm_with_attachment_chinese_url | boundary | FileUrl GBK 中文 |
| B-22 | slave_connect_success | integration | SlaveLinkEnabled=true，0x9001 Result=0 |
| B-23 | slave_connect_password_error | integration | 0x9002 Result=2，主链路保持 |
| B-24 | slave_link_groupid_routing | integration | 同平台主从 2 条 TCP 路由到同一 PacketWorker |
| B-24b | slave_link_independent_msgsn | wire-format | SlaveLinkEnabled=true，断言主链路 0x1001 MsgSN 与从链路 0x9001 MsgSN 完全独立计数（各从 InitialSN 开始独立递增，回绕也互不影响） |
| B-25 | multi_platforms_independent | integration | 3 平台 4-tuple 独立，MsgSN 互不干扰 |
| B-26 | multi_platforms_with_slave | integration | 2 平台 + 从链路，4 条 TCP 不串扰 |
| B-27 | msgsn_wraparound_32bit | boundary | InitialSN=0xFFFFFFFE，4 条消息 SN=...FE/FF/0/1 |
| B-28 | gnss_center_id_zero | boundary | GNSSCenterId=0 允许 |
| B-29 | gnss_center_id_max | boundary | GNSSCenterId=999999999 |
| B-30 | vehicle_plate_padding | wire-format | 空车牌 → 21 字节空格填充 |
| B-31 | encrypt_flag_placeholder | wire-format | EncryptFlag=1, EncryptKey=0xDEADBEEF, body 不变 |
| B-32 | validate_short_username | validation | UserName 不足 5 字符 → 右补 0x00 后通过；超过 5 字符 → 拒绝 |
| B-33 | validate_bad_password | validation | Password >10 字符 → 拒绝 |
| B-34 | validate_bad_version | validation | VersionFlag=3 → 拒绝 |
| B-35 | msglength_correct | wire-format | 0x1001 MsgLength=57；0x1002 MsgLength=37；0x1200(SubMsgId=0x01) MsgLength=73；0x1202 MsgLength=63；0x9001 MsgLength=57。每条报文 MsgLength = 32(头) + body length（精确数值断言） |
| B-36 | no_escape_in_jt809 | wire-format | 消息体含 0x7e 不转义（区别 JT808） |
| B-37 | main_then_slave_order | integration | 主链路登录应答后才能发起从链路 TCP |
| B-38 | full_lifecycle_e2e | integration | login→vehicle_register→location×3→alarm→logout 全流程 |
| B-39 | submsg_0x1204_alarm_attachment | wire-format | 0x1200 SubMsgId=0x04 报警附件 SubBody：AlarmFlag(4B)+AlarmTime(6B BCD)+AlarmInfo(变长)+FileType(1B)+FileSize(4B uint32 BE)+FileURL(变长 GBK，编码后 ≤256B)。SubBody 不含 VehicleColor/VehiclePlate（这些已在 0x1200 外层消息头中出现，不重复） |
| B-40 | submsg_0x1205_vehicle_direction | wire-format | 0x1200 SubMsgId=0x05 车辆定向 SubBody：TerminalPhone(6B BCD)+Direction(2B uint16 BE) |
| B-41 | submsg_0x1206_area_vehicle | wire-format | 0x1200 SubMsgId=0x06 区域车辆 SubBody：TerminalPhone(6B BCD)+AreaType(1B)+AreaData(变长) |
| B-42 | submsg_0x1207_path_record | wire-format | 0x1200 SubMsgId=0x07 路径记录 SubBody：TerminalPhone(6B BCD)+PathCount(2B)+PathPoints(变长，每条同 0x0200 简化体) |
| B-43 | submsg_0x1209_event_report | wire-format | 0x1200 SubMsgId=0x09 事件上报 SubBody：TerminalPhone(6B BCD)+EventId(2B uint16 BE)+EventTime(6B BCD) |
| B-44 | submsg_0x120A_vehicle_logout | wire-format | 0x1200 SubMsgId=0x0A 车辆注销 SubBody：TerminalPhone(6B BCD) |
| B-45 | container_0x1300_downlink | wire-format | 0x1300 主链路下行容器：SubMsgId/SubLength/SubBody 三字段顺序、SubLength = len(SubBody) |
| B-46 | container_0x1500_updown | wire-format | 0x1500 主链路上下行双向容器：SubMsgId/SubLength/SubBody |
| B-47 | container_0x1600_downlink | wire-format | 0x1600 从链路下行容器：SubMsgId/SubLength/SubBody，从链路 4-tuple 验证 |
| B-48 | container_0x9100_updown | wire-format | 0x9100 从链路平台管理容器：SubMsgId/SubLength/SubBody 三字段顺序、SubLength = len(SubBody)，含 VehicleColor/VehiclePlate/AlarmTime/AlarmType/... |
| B-49 | container_0x9600_updown | wire-format | 0x9600 从链路车辆动态监管容器：SubMsgId/SubLength/SubBody 三字段顺序、SubLength = len(SubBody)，含 VehicleColor/VehiclePlate/VehicleNo/Status/Time |
| B-50 | main_disconnect_notice_urgent | wire-format | 0x1007 ReasonCode=1（紧急），合法原因代码 → Validate 通过 |
| B-51 | submsg_0x1204_alarm_attachment_with_filesize | wire-format | 0x1200 SubMsgId=0x04 SubBody 字段顺序：AlarmFlag(4B)+AlarmTime(6B BCD)+AlarmInfo(变长)+FileType(1B)+FileSize(4B uint32 BE)+FileURL(变长)；FileType=1（图片）时 FileSize=实际字节数；FileType=0 时 FileSize=0 |
| B-52 | vehicle_color_list_all_values | wire-format | VehicleColor 全 10 个取值（0=未上车牌、1=蓝、2=黄农、3=绿、4=红、5=黄、6=黑、7=白、8=渐变绿、9=黄绿双拼）逐值构造 0x1200 报文；非车辆 MsgId（0x1001/0x1002/0x1003/0x9001/0x9002/0x9003）VehicleColor=0、VehiclePlate=21 字节空格 |
| B-53 | realtime_location_latitude_sync_with_jt808 | wire-format | 0x1202 SubBody Latitude=0x0263b560（39.9° 北京实际纬度，与 §7A.14 JT808 0x0200 一致）；Longitude=0x06e60c80；断言与 JT808 0x0200 消息体字段布局完全一致（28 字节） |
| B-54 | flowid_stable_main_slave_independent | integration | 主链路 flowID="jt809-main-{GNSSCenterId}-{InitialSN}"、从链路 flowID="jt809-slave-{GNSSCenterId}-{InitialSN}"；Config 阶段确定，src_port 晚分配不影响；主从 InitialSN 独立递增 |
| B-55 | sublength_calc_formula_0x1202 | wire-format | 0x1202 SubLength=28 = 4(AlarmFlag)+4(StatusFlag)+4(Latitude)+4(Longitude)+2(Altitude)+2(Speed)+2(Direction)+6(Time)；断言 SubLength 不含 SubMsgId(1B)+SubLength(2B) 自身 |
| B-56 | vehicle_plate_pad_right_space_not_zero | wire-format | JT809 VehiclePlate GBK 编码后左对齐空格（0x20）填充至 21 字节，非 0x00；断言填充字节 = 0x20（与 JT808 TerminalModel 一致，与 PadRightGBK 行为明确区分） |

JT809 用例数：57 条（≥20 要求满足）。

---


---

# Part D（通用附录，原样复制）

# Part D: 通用

## 9. 交叉对抗审计检查清单

实现完成后，按本清单逐项做 spec-vs-implementation 审计（参考 CLAUDE.md 测试策略第 8 条）：

### 9.1 字段覆盖审计

- [ ] JT808 0x0100 所有字段（ProvinceId/CityId/ManufacturerId 5/TerminalModel 20/TerminalId 7/LicenseColor/LicensePlate）是否各有至少 1 个测试断言非零值？
- [ ] JT808 0x0200 所有字段（AlarmFlag/StatusFlag/Latitude/Longitude/Altitude/Speed/Direction/Time）是否各有至少 1 个测试断言非零值？
- [ ] JT808 0x0107 所有字段（DeviceType/ManufacturerId/TerminalModel/TerminalId/IccId/Imei/SoftwareVersion/GnssModule/CommModule）是否各有至少 1 个测试？
- [ ] JT809 0x1001 所有字段（UserName 5/Password 10/GNSSCenterId/VersionFlag/EncryptFlag/EncryptKey）是否各有至少 1 个测试？
- [ ] JT809 0x1200 SubMsgId 0x01-0x0A 是否每个子类型至少 1 个测试？
- [ ] JTT905 0x1001 所有字段（DriverId 20/DriverName 16/LicensePlate 21/LicenseColor/OnTime/VehicleModel 16/LoadCapacity）是否各有至少 1 个测试？
- [ ] JTT905 0x1002 所有字段（DriverId/DriverName/LicensePlate/LicenseColor/OffTime/Mileage/Income/PassengerCount）是否各有至少 1 个测试？

### 9.2 错误路径审计

- [ ] JT808 注册 4 种 Result（0-4）是否各有至少 1 个测试？
- [ ] JT808 通用应答 4 种 Result（0/1/2/3）是否各有至少 1 个测试？
- [ ] JT809 登录 5 种 Result（0/1/2/3/4）是否各有至少 1 个测试？
- [ ] JTT905 ISU 通用应答 4 种 Result（0/1/2/3）是否各有至少 1 个测试？
- [ ] JTT905 中心通用应答 4 种 Result（0/1/2/3）是否各有至少 1 个测试？
- [ ] Validate 是否对每个非法字段（Phone/Version/LicenseColor/LicensePlate 不匹配/UserName/Password/DriverId/...）都有拒绝测试？

### 9.3 代码路径审计

- [ ] JT808 分包路径（bit14=1）是否有测试？ PackageNum/PackageTotal 字段是否被读取？
- [ ] JT808 EncryptFlag=1 路径是否有测试？ bit15 是否被置位？
- [ ] JT808 Version 三个值（2011/2013/2019）是否各有 bit10-12 编码测试？
- [ ] JT809 SlaveLinkEnabled=true 路径是否有测试？ 从链路 TCP 是否被发起？
- [ ] JT809 0x1200 容器消息路径（SubMsgId + SubLength + SubBody）是否有测试？
- [ ] JTT905 Procedures 空路径（planner 自动生成）是否有测试？
- [ ] JTT905 Procedures 非空路径（用户自定义）是否有测试？

### 9.4 集成审计

- [ ] JT808 全流程 e2e（register→auth→location×3→query→cancel）是否有 1 个测试？
- [ ] JT809 全流程 e2e（login→vehicle_register→location×3→alarm→logout）是否有 1 个测试？
- [ ] JTT905 全流程 e2e（check-in→heartbeat×3→check-out）是否有 1 个测试？
- [ ] 多终端/多平台并发场景是否至少 1 个测试？
- [ ] 主从链路 GroupID 路由（同平台 2 条 TCP 同 PacketWorker）是否有 1 个测试？

### 9.5 可观察性审计

- [ ] 测试是否断言 MsgSN 实际值（而非仅"递增"）？
- [ ] 测试是否断言校验码实际字节值？
- [ ] 测试是否断言转义后字节流（hex 比较）？
- [ ] 测试是否断言 MsgBodyProps 位编码（而非仅"已设置"）？
- [ ] 测试是否断言 MsgLength 实际数值（JT809）？

### 9.6 转义/校验对抗审计

- [ ] JT808/JTT905 消息体含 0x7e 转义测试？
- [ ] JT808/JTT905 消息体含 0x7d 转义测试？
- [ ] JT808/JTT905 校验字节恰好等于 0x7e/0x7d 的对抗测试？
- [ ] JT808/JTT905 校验范围测试（验证包含消息体及分包 SN，不含起始符/结束符/校验字节本身）？
- [ ] JT809 不转义的对抗测试（消息体含 0x7e 仍原样发出）？

### 9.7 并发正确性审计

- [ ] 多终端/多平台测试是否断言每个 flow 的 MsgSN 独立（而非共享全局计数器）？
- [ ] 多终端/多平台测试是否断言每个 flow 的 Phone/GNSSCenterId 各异？
- [ ] 多终端/多平台测试是否在 -race 下运行？
- [ ] JT809 主从链路是否断言两条 TCP 的 MsgSN 独立？

### 9.8 时序与速率审计

- [ ] JTT905 心跳间隔测试是否断言实际包间隔（而非仅"按顺序发出"）？
- [ ] JT809 主从链路登录顺序测试是否断言主链路 0x1002 在从链路 0x9001 之前？
- [ ] JT808 多次位置上报测试是否断言 MsgSN 单调递增（含回绕）？
- [ ] 多终端并发测试是否断言各 flow 间没有时序耦合（一条 flow 的延迟不影响另一条）？

### 9.9 字节级对抗审计

- [ ] JT808 完整报文 hex 比对测试是否至少 1 条（从 MsgId 到结束符 0x7e 的全字节断言）？
- [ ] JT809 完整报文 hex 比对测试是否至少 1 条（从 MsgLength 到末字节）？
- [ ] JTT905 完整报文 hex 比对测试是否至少 1 条？
- [ ] BCD 编码边界测试：Phone 全 0、全 9、含前导 0。
- [ ] GBK 编码边界测试：纯 ASCII（每字节 < 0x80）、纯中文（每字符 2 字节）、混合。
- [ ] 大端序断言：所有 uint16/uint32 字段是否断言大端字节序（而非平台序）？

## 10. 集成点

### 10.1 types.go 注册

在 `internal/core/types.go` 的 `FlowSpec` 结构体追加：

```go
JT808  *JT808Config  `json:"jt808,omitempty"`
JT809  *JT809Config  `json:"jt809,omitempty"`
JTT905 *JTT905Config `json:"jtt905,omitempty"`
```

位置：紧跟现有 `Socks *SocksConfig` 等字段之后，按字母序插入。

**互斥规则（mutual exclusion / 协议字段互斥）**：三个 JT 子协议字段
`JT808` / `JT809` / `JTT905` 在同一 `FlowSpec` 中**至多一个非 nil**。
验证逻辑（在 `Validate()` 中实现）：

```go
func (fs *FlowSpec) Validate() error {
    n := 0
    if fs.JT808  != nil { n++ }
    if fs.JT809  != nil { n++ }
    if fs.JTT905 != nil { n++ }
    if n > 1 {
        return fmt.Errorf("FlowSpec.jt*: at most one of JT808/JT809/JTT905 may be set (got %d)", n)
    }
    return nil
}
```

应用范围：策略解析（`strategy_convert.go`）、手动构造的 FlowSpec、API 提交路径，全部走该 Validate。拒绝原因写入 `ValidationErrors`，任务以 `ValidationError` 终止，不进入 planner。

### 10.2 strategy_convert.go 映射

在 `internal/core/strategy_convert.go` 的 strategy→FlowSpec 映射中添加：

- strategy.Protocol = "jt808" → FlowSpec.JT808 = parseJT808Config(strategy.Config)
- strategy.Protocol = "jt809" → FlowSpec.JT809 = parseJT809Config(strategy.Config)
- strategy.Protocol = "jtt905" → FlowSpec.JTT905 = parseJTT905Config(strategy.Config)

每个 parse 函数将 `map[string]interface{}` 解析为对应 Config 结构体，并执行 Validate（错误加入 `ValidationErrors`）。

### 10.3 默认端口

在 `mapToFlowSpec`（或等价的策略→4-tuple 转换函数）中：

- protocol="jt808" 且 DstPort=0 → DstPort=7611
- protocol="jt809" 且 DstPort=0 → DstPort=8812
- protocol="jtt905" 且 DstPort=0 → DstPort=10700

### 10.4 PacketWorker 路由

- JT808 单 flow：FlowID = "jt808-{Phone}-{InitialSN}"，GroupID = hash(Phone) 保证同终端消息有序。
- JT809 主从双 flow：主链路 FlowID = "jt809-main-{GNSSCenterId}-{InitialSN}"，从链路 FlowID = "jt809-slave-{GNSSCenterId}-{InitialSN}"，GroupID = hash(GNSSCenterId) 保证同平台两条 TCP 同 PacketWorker。
- JTT905 单 flow：FlowID = "jtt905-{Phone}-{InitialSN}"，GroupID = hash(Phone)。

### 10.5 TCP 握手/挥手

三个协议都基于 TCP，复用 `internal/protocol/tcp` 或 `internal/protocol/rtsp` 中已有的握手/挥手逻辑：

- SYN/SYN-ACK/ACK 三次握手，MSS/WinScale/SACK 选项
- PSH-ACK 承载应用层消息，按 MSS 分段
- FIN/FIN-ACK/ACK 四次挥手

每个 Planner 在 emit 应用消息前先 emit 握手，最后 emit 挥手，参考 `rtsp.go` 的 emit/emitData 闭包模式。

### 10.6 测试基础设施

- 单元测试：每个协议包内 `*_test.go`，构造 FlowSpec，调用 Planner.Plan，断言 PacketConfig.Payload 字节。
- 集成测试：构造完整业务流程 FlowSpec，驱动到 PacketConfig channel，按 flow 聚合，断言跨消息时序。
- tshark 验证（参考 RTSP/SOCKS5/RADIUS 惯例）：将生成的 pcap 用 tshark 解码，验证字段解码正确。
- -race：所有测试 `go test -race` 运行。

### 10.7 测试辅助函数约定

每个协议包的测试应提供以下辅助函数（参考 socks5/socks5_test.go 模式）：

```go
// mustPlan 调用 Plan 并收集所有 PacketConfig 到切片，失败时 t.Fatal。
func mustPlan(t *testing.T, spec core.FlowSpec) []core.PacketConfig

// extractPayloadBytes 从 PacketConfig 列表中提取所有 L4 payload（应用层字节）。
func extractPayloadBytes(packets []core.PacketConfig) [][]byte

// hexEqual 比较 []byte 与 hex 字符串（无空格）。
func hexEqual(b []byte, hex string) bool

// mustReadFile 读取测试 pcap 文件，失败时 t.Fatal。
func mustReadFile(t *testing.T, path string) []byte

// assertPhoneBCD 断言 6 字节 BCD 与 12 位数字字符串一致。
func assertPhoneBCD(t *testing.T, b []byte, phone string)

// assertXORChecksum 断言给定字节序列的 XOR 校验等于预期值。
func assertXORChecksum(t *testing.T, buf []byte, expected byte)

// assertMsgSN 断言消息头中 MsgSN 字段等于 expected（大端）。
func assertMsgSN(t *testing.T, msg []byte, expected uint16)

// flowByPhone 从多 flow 的 packets 中按 Phone 提取单 flow 的所有包。
func flowByPhone(packets []core.PacketConfig, phone string) []core.PacketConfig
```

### 10.8 tshark 解码约定

三个协议的 tshark 解码验证（参考 RADIUS/LDAP/VNC 已有惯例）：

| 协议 | tshark 显示过滤器 | 关键字段断言 |
|------|-------------------|--------------|
| JT808 | `jt808` | `jt808.msg_id`, `jt808.phone`, `jt808.msg_sn`, `jt808.body_length` |
| JT809 | `jt809` | `jt809.msg_id`, `jt809.gnss_center_id`, `jt809.msg_sn`, `jt809.vehicle_plate` |
| JTT905 | `jtt905`（若 tshark 未内置，用 `data` + 自定义断言） | 手动断言 MsgId/Phone/MsgSN |

注意：tshark 可能不内置 JTT905 解码器（与 JT808 格式相似但 MsgId 空间不同）。JTT905 测试可降级为：用 `tcp.payload` 提取应用层字节，手动断言字段偏移与值。

## 11. 三个协议的代码复用方案

### 11.1 共享工具包 `internal/protocol/jtcommon/`

```go
// Package jtcommon provides shared helpers for the JT/T 808, JT/T 809,
// and JT/T 905 vehicle-networking protocols.
package jtcommon

// Escape applies JT808/JTT905 escape rules to a raw payload:
//   0x7e -> 0x7d 0x02
//   0x7d -> 0x7d 0x01
// Used after checksum computation, before wrapping with 0x7e delimiters.
func Escape(raw []byte) []byte

// Unescape reverses Escape.
func Unescape(escaped []byte) ([]byte, error)

// XORChecksum computes the XOR of all bytes from start to end (exclusive
// of the checksum byte itself). Used by JT808 and JTT905.
func XORChecksum(buf []byte) byte

// XORChecksumGBK is a named wrapper around XORChecksum for payload bytes
// already encoded as GBK (e.g. GBK LicensePlate, DriverName, FileUrl).
// It makes the GBK-byte checksum scope explicit so callers cannot
// accidentally pass UTF-8 strings to a byte-level XOR. The function is
// defined here (not inlined) so jtcommon tests can assert it equals
// XORChecksum on identical input bytes (D-02 covers this equivalence).
//
// Definition:
//   func XORChecksumGBK(payload []byte) byte {
//       return XORChecksum(payload)
//   }
func XORChecksumGBK(payload []byte) byte {
    return XORChecksum(payload)
}

// BCDEncode encodes a 12-digit string into 6-byte BCD. Returns an error
// if the input is not 12 digits.
func BCDEncode(s string) ([]byte, error)

// BCDDecode decodes 6-byte BCD into a 12-digit string.
func BCDDecode(b []byte) string

// EncodeMsgBodyProps packs the JT808/JTT905 message body properties:
//   bits 0-9:   body length (0-1023)
//   bits 10-12: version flag (0=2011, 1=2013, 2=2019)
//   bit 13:     reserved (0)
//   bit 14:     package flag (0/1)
//   bit 15:     encrypt flag (0/1)
func EncodeMsgBodyProps(bodyLen int, version string, pkgFlag, encFlag uint8) (uint16, error)

// DecodeMsgBodyProps unpacks the properties into the same components.
func DecodeMsgBodyProps(props uint16) (bodyLen int, version string, pkgFlag, encFlag uint8)

// ParseVersionFlag converts "2011"/"2013"/"2019" to 0/1/2.
func ParseVersionFlag(v string) (uint8, error)

// FormatVersionFlag converts 0/1/2 to "2011"/"2013"/"2019".
func FormatVersionFlag(v uint8) string

// GBKEncode encodes a UTF-8 string to GBK bytes (for license plates,
// driver names, text-down content). Uses golang.org/x/text/encoding/simplifiedchinese.
func GBKEncode(s string) ([]byte, error)

// GBKDecode decodes GBK bytes back to UTF-8.
func GBKDecode(b []byte) (string, error)

// PadRight pads s with spaces to width bytes. Used for JT809's 21-byte
// VehiclePlate and JTT905's 16-byte DriverName/VehicleModel fields.
func PadRight(s string, width int) []byte

// PadRightSpace pads s with 0x20 (ASCII space) to width bytes. Used for
// JT808's 20-byte TerminalModel and any ASCII field requiring right-padded
// space fill (not 0x00).
func PadRightSpace(s string, width int) []byte

// PadRightGBK encodes s as GBK and right-pads the encoded bytes with 0x00
// until totalBytes. It returns an error if the encoded value exceeds the width.
//
// IMPORTANT: JT809 VehiclePlate and JTT905 DriverName/VehicleModel/LicensePlate
// fields require left-aligned space fill (0x20) per JT/T 809-2019 §5.2 and
// JT/T 905-2014 §4.2, NOT 0x00 padding. For those fields, use the separate
// "PadRightSpace (GBK-encoded bytes)" path documented in §11.2 — calling
// PadRightGBK on them will produce wrong bytes (0x00 fills where 0x20 is
// required), and the receiving platform will reject the frame as
// "invalid plate / driver name". This function is appropriate only for
// byte fields that genuinely want zero-padding (e.g. fixed-length numeric
// fields that allow zero as a legitimate "absent" value).
func PadRightGBK(s string, totalBytes int) ([]byte, error) {
    encoded, err := GBKEncode(s)
    if err != nil {
        return nil, err
    }
    if len(encoded) > totalBytes {
        return nil, fmt.Errorf("GBK-encoded string length %d exceeds %d", len(encoded), totalBytes)
    }
    out := make([]byte, totalBytes)
    copy(out, encoded)
    return out, nil
}

// ParseTimeBCD parses a 6-byte BCD "YYMMDDhhmmss" into time.Time.
func ParseTimeBCD(b []byte) (time.Time, error)

// EncodeTimeBCD encodes a "YYMMDDhhmmss" string into 6-byte BCD.
func EncodeTimeBCD(s string) ([]byte, error)
```

### 11.2 复用映射

| 工具 | JT808 | JT809 | JTT905 |
|------|-------|-------|--------|
| Escape / Unescape | 用 | 不用 | 用 |
| XORChecksum | 用 | 不用 | 用 |
| BCDEncode / BCDDecode | 用（Phone, Time） | 用（VehiclePlate 不是 BCD，但 Time 是） | 用（Phone, OnTime, OffTime） |
| EncodeMsgBodyProps | 用 | 不用（消息头格式不同） | 用 |
| ParseVersionFlag / FormatVersionFlag | 用 | 用（VersionFlag 0/1/2 而非字符串，需包装） | 用 |
| GBKEncode / GBKDecode | 用（LicensePlate, Text） | 用（VehiclePlate, FileUrl） | 用（DriverName, LicensePlate） |
| PadRight / PadRightGBK / PadRightSpace | PadRightSpace（TerminalModel 右补空格至 20 字节，非 0x00）；LicensePlate 无固定长度前缀不用 | PadRightSpace（VehiclePlate GBK 编码后左对齐空格填充至 21 字节，0x20 填充）；UserName/Password 不足时右补 0x00 | PadRightSpace（DriverName/VehicleModel/LicensePlate GBK 编码后左对齐空格填充，0x20） |
| ParseTimeBCD / EncodeTimeBCD | 用（0x0200 Time） | 用（0x1208 AlarmTime, 0x1400 AlarmTime） | 用（OnTime, OffTime） |

### 11.3 包内不复制的约束

为避免 "fragmented-TCP test always established the flow with a non-fragmented handshake first" 这类反模式（CLAUDE.md 测试策略 §2），三个协议包必须：

- 不在自己的包内复制 jtcommon 的工具函数（强制 import jtcommon，避免实现漂移）。
- jtcommon 的每个工具函数有独立的单元测试（在 jtcommon 包内），三个协议包的测试只断言"调用了 jtcommon 后得到预期字节"，不重新测试转义/校验/BCD 本身。
- 三个协议包共享的 TCP 握手/挥手 emit 逻辑，参考 rtsp.go 的模式，但**不**抽到 jtcommon（避免引入 jtcommon→core 的循环依赖；每个协议包各自 emit，代码相似但独立）。

### 11.4 测试共享

jtcommon 提供测试辅助：

```go
// MustParseHex parses a hex string (no spaces) into []byte, panicking
// on error. For test-only use.
func MustParseHex(s string) []byte

// HexEqual compares a []byte to a hex string.
func HexEqual(b []byte, hex string) bool

// MustBCD encodes a 12-digit string to BCD, panicking on error. Test-only.
func MustBCD(s string) []byte
```

三个协议包的测试都通过 jtcommon.MustParseHex / HexEqual 做字节断言，统一断言风格。

### 11.5 共用测试用例（D 类）

D 类共用测试用例覆盖 jtcommon 自身：

| # | 用例名 | 验证点 |
|---|--------|--------|
| D-01 | escape_roundtrip | Escape 然后 Unescape 还原原字节；覆盖含 0x7e/0x7d/普通字节的混合 |
| D-02 | xor_checksum_known_vector | 已知向量：MsgId=0x0100 + MsgBodyProps=0x0000 + Phone=0x000000000001 + MsgSN=0x0001 → 校验字节=已知值；XORChecksumGBK 对已编码 GBK 字节结果一致 |
| D-03 | bcd_encode_decode_roundtrip | 12 位数字 ↔ 6 字节 BCD 双向 |
| D-04 | msg_body_props_all_versions | EncodeMsgBodyProps 对 2011/2013/2019 + 加密/分包 + 长度 1023 的位编码 |
| D-05 | gbk_chinese_roundtrip | "京A12345" ↔ GBK 字节双向 |
| D-06 | pad_right_gbk_exact | PadRightGBK 等宽时不补 0x00 |
| D-07 | pad_right_gbk_short | PadRightGBK 短字符串按 GBK 字节补 0x00 至指定宽度 |
| D-08 | time_bcd_roundtrip | "240803120000" ↔ 6 字节 BCD 双向 |
| D-09 | time_bcd_invalid | 非法时间字符串 → EncodeTimeBCD 报错 |
| D-10 | unescape_invalid_sequence | 0x7d 后跟非 0x01/0x02 → Unescape 报错 |
| D-11 | gbk_pure_ascii | GBKEncode("ABC123") → 全 < 0x80 字节；GBKDecode 还原 |
| D-12 | gbk_pure_chinese | GBKEncode("张三") → 双字节 0xD5 0xC5 0xC8 0xCB 形式；GBKDecode 还原 |
| D-13 | bcd_all_zeros | BCDEncode("000000000000") → 6 字节全 0x00；BCDDecode 还原 "000000000000" |
| D-14 | bcd_all_nines | BCDEncode("999999999999") → 6 字节全 0x99；BCDDecode 还原 "999999999999" |
| D-15 | bcd_leading_zero | BCDEncode("013000000001") → 0x01 0x30 0x00 0x00 0x00 0x01；前导零保留 |

D 类共用测试用例：15 条。

## 12. 用例数总计

| 协议 | 用例数 |
|------|--------|
| JT808（A 类） | 65 |
| JT809（B 类） | 57 |
| JTT905（C 类） | 37 |
| 共用（D 类） | 15 |
| 跨协议（X 类） | 3 |
| **总计** | **177** |

要求 ≥60，实际 177，余量充足。

## 13. 实现优先级建议

1. **jtcommon 先行**：先实现并测试 jtcommon（D 类用例），三个协议包依赖它。
2. **JT808 优先**：JT808 是 JT809 0x1202/0x1203 SubBody 的基础（位置上报消息体直接复用 JT808 0x0200 布局），必须先完成。
3. **JTT905 次之**：JTT905 报文格式与 JT808 几乎一致，复用 jtcommon 后实现成本低。
4. **JT809 最后**：JT809 双链路 + 容器消息最复杂，依赖 jtcommon 与 JT808 的位置消息体定义。

## 14. 已知限制与不实现项

- **JT808 真加密**：不实现 M1/IA1/IC1 等加密算法，仅置位 EncryptFlag + 占位 EncryptKey。
- **JT809 真加密**：同上。
- **JT808 文件下发（0x8105）**：不实现，涉及分包传输复杂状态机。
- **JT808 部分报警/状态位详细解码**：AlarmFlag/StatusFlag 按整体 uint32 处理，不逐 bit 解码。
- **JT809 报警附件传输（0x1401-0x1403）**：不实现，仅 0x1400 携带 URL。
- **JTT905 计价器联动**：不实现，仅 Mileage/Income/PassengerCount 字段。
- **JTT905 紧急报警语音对讲**：不实现。
- **大规模并发（>1000 终端）**：性能场景仅在 e2e 标记，不在单测覆盖。

## 15. 参考规范

- JT/T 808-2019 道路运输车辆卫星定位系统终端通讯协议
- JT/T 809-2019 道路运输车辆卫星定位系统平台数据交换
- JT/T 905-2014 出租车车载信息服务终端通讯协议
- GB/T 2260 中华人民共和国行政区划代码（省域/市域 ID）
- JT/T 808-2019 附录 A 报警标志位定义
- JT/T 808-2019 附录 B 状态标志位定义
- JT/T 808-2019 附录 C 附加项 TLV 定义
- GBK 编码：GB 2312 / GBK 国家标准

## 16. 修订记录

| 日期 | 修订 | 备注 |
|------|------|------|
| 2026-08-03 | 初版 | 合并 JT808 + JT809 + JTT905 设计与测试用例，总计 155 条用例 |
| 2026-08-03 | v1.1 | 对抗审计 61 问题修复（详见下表） |

## 17. 层链迁移契约（D1-D8，2026-09-30）

本节覆盖当前实现与 `cases/jt809.json` 的可执行形状；旧合集的 32 字节无校验信封仅保留为历史参考，不是当前线契约。

| ID | 结论 | 证据与处理 |
|---|---|---|
| D1 | 地址只住 `layers[].ip`，端口只住 `layers[].tcp`，数量只住用例驱动器或 `flow_control` | 15 例机读审计；11 个正例无顶层地址/端口/count，T-15 的顶层 `jt809` 仅为 presence 判死输入 | 
| D2 | JT809 是 TCP 终结层，当前标准链为 `[ip,tcp,jt809]`；协议配置住同名层 | 15 例正例 `spec_json.layers` 均为 `[ip,jt809]` 的历史 as-built 形，迁移缺口登记 G-JT809-LC-1，禁止伪称已完成 |
| D3 | TCP 载体决定端口与方向，JT809 层不声明扁平端口 | 当前 JSON 地址已在 ip 层；端口由实现默认 8812/8813 |
| D4 | `procedures` 是 JT809 业务编排，留在 `layers[].jt809`；多链路由 `slave_link_enabled` 显式声明 | T-1/T-4/T-7/T-10 |
| D5 | 顶层 `jt809` 子映射禁止作为正例入口；presence 负例必须保留层链 + 顶层空子映射并明确判死 | 14 个正例无顶层协议键；`jt809_t15_neg_presence_top_level_jt809` 保留故意违规形状与 presence 锚词 |
| D6 | 数量/速率是用例驱动字段，不复制进协议配置；每平台独立 MsgSN | `initial_sn` 与 procedures 的线断言；当前无静态复制字段 |
| D7 | 负例保留故意违规输入并带 `expect_error`、`error_contains`；不得洗成正例 | T-11/T-12/T-13/T-15 四例 |
| D8 | 代码未支持的容器业务不伪造已覆盖，登记缺口 | G-JT809-N/G-JT809-3；本轮只改文档与 JSON 形状 |

### 17.1 层链迁移缺口

| 编号 | 内容 | 处理 |
|---|---|---|
| G-JT809-LC-1 | 当前 cases 的 JT809 作为直接终结层，缺显式 tcp 层；端口/握手由注册器补全 | 在不改代码的文档修复范围内保留 as-built，后续层链迁移需先补 registry/translate，再重钉所有 offsets |

## 18. 六项审查清单（C1-C6）

| ID | 审查结论 |
|---|---|
| C1 | JSON 可解析，15 个 ID 唯一，文档 §8B 与 JSON 顺序一致；数量为 11 正、4 负 | 机读审计：T-1…T-14 + T-15 presence 判死负例；历史 §8B 目标清单不与当前存量混算 | 
| C2 | 正例 `spec_json` 顶层仅 `layers`；无顶层 JT809/地址/端口/count；presence 负例仅按 D5 保留顶层空 `jt809` | 正例 11/11 无游离顶层键；T-15 为唯一故意例外且为严格负例 | 
| C3 | 地址在 ip 层；当前实现补默认端口，JSON 未伪造游离协议字段 | 15 例地址均在 `layers[].ip`；主链 8812、从链 8813 由实现供给 | 
| C4 | 4 个负例 `expect` 严格为 `{expect_error,error_contains}` 两键；无 `notes` 或其他附加键 | T-11/T-12/T-13 保留真实越界锚词；T-15 保留 presence 锚词 | 
| C5 | 主从双流、保活、非正常结束、转义和 presence 判死均有现状用例；车辆容器和长保活仍登记缺口 | T-4/T-5/T-6/T-7/T-8/T-9/T-15；G-JT809-N/G-JT809-1/G-JT809-3 不冒充覆盖 | 
| C6 | 本轮范围严格为 design.md、testcase.md、jt809.json；不改生成器、schema、其他文档或索引 | 文件范围与任务边界一致 |

## 19. 当前 as-built 闭环（2026-10-01）

### 19.1 三源比较与规范矩阵

| 面 | JT/T 809-2019 / 设计目标 | 当前实现 | 当前 cases 证据 |
|---|---|---|---|
| 载体 | 主链/从链独立 TCP；主链 8812、从链 8813 | `PlanWithConfig` 生成主链，`SlaveProcedures` 非空时生成从链；共享 GroupID | T-1…T-10、T-14；T-7/T-8 双流 |
| 信封 | 历史目标描述曾写 32B、无定界/CRC | `5B + Escape809(header+body+CRC16) + 5D`；2011/2013 22B、2019 30B | T-2、T-9、T-14 |
| 消息族 | 标准业务/链路管理面 | 当前仅编排 16 型链路管理族；容器族未编排 | T-1、T-4…T-10、T-14 |
| 配置权威 | 层链是唯一入口 | `JT809Generator.Generate` → `PlanWithConfig`；缺层明确报错 | 14 个正例仅 `spec_json.layers`；T-15 仅为 presence 判死 |
| 校验 | 字段范围与帧完整性 | `ValidateConfig` 校验 GNSS、版本、加密、密码、过程类型/链路、Result/Code；builder/parser 校验 CRC/长度 | T-11/T-12/T-13 负例；正例 frames |

候选实现比较：继续沿用旧合集 32B 无 CRC 方案会与当前 builder/parser 和已钉帧冲突；直接在 cases 中伪造 `[ip,tcp,jt809]` 会与当前注册器 as-built 形冲突；因此本轮采用最小诚实方案：保留历史目标，按当前 `5B/5D + CRC16 + 22/30B` 记录可执行契约，并登记显式 TCP 层迁移缺口 `G-JT809-LC-1`。

### 19.2 依赖、错误、重试与超时

依赖链为层翻译/校验 → `JT809Generator` → `PlanWithConfig` → builder → raw-IP Emit；任一校验或 Emit 错误都应终止任务，不能返回 completed/0 packets。当前 planner 不实现响应等待、重试、保活定时器或超时驱动；`procedures` 只是确定性顺序，`main_keepalive`/response 需显式配置。故设计中的 30s 应答超时和重试属于目标状态机，不能宣称当前支持（缺口 G-JT809-N）。

### 19.3 八要素与动态字段

| 要素 | 当前裁定 |
|---|---|
| 身份/端点 | 地址在 `layers[].ip`；端口由实现默认主链 8812、从链 8813，非 JT809 顶层 flat 键 |
| 会话 | 主链先握手和消息，再开启从链；双流共享 GroupID |
| 消息 | 16 型链路管理族；业务体按 procedure 模板生成 |
| 顺序 | `main handshake → main procedures → slave handshake/procedures → main teardown → slave teardown` |
| SN | 主/从链路及上下行各自独立；首条从 `InitialSN` 或 `PlatformInitialSN`，发送后递增并回绕 |
| 编码 | 大端整数、3B version、2019 `time_sec`；Password/DownLinkIP 定长零填充 |
| 校验/定界 | CRC16 在转义前计算；内容整体转义；5B/5D 包围 |
| 失败/边界 | planner/validator 错误传播；GNSS、VersionFlag、ErrorCode 等越界拒绝 |

动态算法固定为：复制配置并补 `UserId=GNSSCenterId`、密码、下行 IP/8813；按链路/方向选择四个 SN 计数器；`buildFrameVer` 先写占位长度、头、体，再回填整帧长度，计算 CRC16，最后转义。长度/偏移变更必须同时更新 parser、frames 断言和文档，不能只改摘要。

### 19.4 Gate-1（当前可执行形状）

| 门禁 | 判定 | 证据 |
|---|---|---|
| G1-1 JSON 形状 | 通过静态核对 | 15 个唯一 ID；顶层键 `{expect,id,proto,spec_json,summary}` |
| G1-2 层链约束 | as-built 通过，目标 TCP 层未完成 | 15 例中 14 个正例为 `[ip,jt809]`；T-15 是故意 presence 负例；`G-JT809-LC-1` |
| G1-3 正负例 | 通过静态核对 | 11 正、4 负；负例 `expect` 严格二键 |
| G1-4 断言规模 | 通过静态核对 | 正例 packet_count 分布 7×7、8×2、13×1、14×1；35 fields、59 frames |
| G1-5 执行证据 | 未执行 | 本轮未运行 suite、pcap 或 NIC，不能宣称通过 |

`docs/protocols/jt809/testcase.md` §1–§10 是本矩阵的机器契约回指；其 15 例（14 个正例/越界或业务负例 + T-15 presence 判死）是当前 baseline，不得与本设计 §8B 的历史 57 条目标清单相加或混称。

### 19.5 D1-D8/T1-T6/C1-C6 静态闭环（2026-10-01）

本轮以 `cases/jt809.json` 为唯一机器事实重数：15 例，11 正 + 4 负；14 个既有线字节契约例全部保留，新增 T-15 仅验证顶层 `jt809` presence 判死，不伪造协议线面。四个负例均为严格双键 `expect_error`/`error_contains`；T-11/T-12/T-13 使用实现 `ValidateConfig` 真实锚词，T-15 使用 `rawWrapChains` 的 `no longer accepts a top-level jt809 sub-config` 真实锚词。层链仍是 `[ip,jt809]` as-built，显式 `[ip,tcp,jt809]` 继续保留 G-JT809-LC-1；不改 offsets、生成器、schema 或索引。

## 20. 本轮静态验收结论

- D1-D8：通过静态核对；D5 的 presence 判死形已保留，正例仍无顶层协议键；D2 的显式 TCP 层迁移仍是 G-JT809-LC-1。
- T1-T6：通过静态核对；ID、数量、层形、负例双键、地址归属、业务配置归层和缺口登记均与 JSON 一致。
- C1-C6：通过静态核对；C1=15（11 正/4 负），C2 按正例零游离键且 T-15 为唯一判死例外，C4=4 个严格双键负例；C5/C6 保留缺口与三文件范围。
- 执行边界：仅运行 `json.tool`、静态 diff/脚本核对；未运行 suite、服务、MCP 或 NIC，不宣称运行证据。



| ID | 严重度 | 章节 | 修复内容 |
|----|--------|------|----------|
| C-01 | CRITICAL | §3A.4 | 校验范围 = MsgId..消息体末字节（含消息体 + 分包项 PackageNum/PackageTotal），不含起始符/结束符/校验字节本身 |
| C-02 | CRITICAL | §4A.7 | 0x8001 消息体删除 Phone(6)，固定 5 字节 = ResponseSN(2)+ResponseMsgId(2)+Result(1) |
| C-03 | CRITICAL | §7A.14 | 0x0100 hex dump BodyLength 从 28 修正为 45（45=2+2+5+20+7+1+8），MsgBodyProps=0x002d；§8A A-01/A-26/A-50 断言 BodyLength=45 |
| C-04 | CRITICAL | §3A.3 | 反转义遇非法 0x7d 后跟字节明确"整条报文丢弃并记录错误日志"；新增 A-41 unescape_invalid_sequence |
| H-01 | HIGH | §5A | JT808Config 新增 IMEI(15 ASCII) 与 SoftwareVersion(20)；JT808Procedure 新增 *IMEI/*SoftwareVersion 覆盖 |
| H-02 | HIGH | §4A.6 | 0x0107 字段表补全至 17 字段（ProvinceId/CityId/CountyId/TownId/Operator/APN/HardwareVersion/MaxSpeed）；JT808Property 同步 |
| H-03 | HIGH | §4A.7 / §7A.10 | Result 删除 99=臆造值；ACKFlag 限制 {0,1,2,3}；A-40 改为 ACKFlag=3（不支持） |
| H-04 | HIGH | §6A.1/§6A.3 | 终端侧新增 text_await/set_params_await/query_params_await/query_location_await 及超时转移；平台侧补全 set_params_await/query_params_await；新增 A-42 |
| H-05 | HIGH | §5A | JT808Location 新增 ACC/DoorStatus/OilCircuit/RunStatus *bool bit 级便捷字段（OR 合并入 StatusFlag）；新增 A-43 status_flag_bit_merge |
| H-06 | HIGH | §5A.1 | 新增 Validate 规则表集中列出所有字段合法范围；新增 A-44~A-47 LicenseColor/Direction/Latitude/Time 边界 |
| H-07 | HIGH | §4A.2 / §7A.2 / §8A | AuthCode 空时 Validate 拒绝；A-07 改为 auth_empty_code validation 拒绝路径 |
| H-08 | HIGH | §8A | A-28 拆分为 A-28a（分包结构）+ A-28b（重组字节级 hexEqual 断言） |
| M-01 | MEDIUM | §7A.14 | 行 637 与 648 注释统一为"左对齐右补空格" |
| M-02 | MEDIUM | §7A.14 | 0x0200 hex dump Latitude 从 0x025BC860(39.5°) 修正为 0x0263B560(39.9°，北京实际纬度) |
| M-03 | MEDIUM | §4A.1 / §7A.14 | 省域 ID 标准从 JT/T 4150 改为 GB/T 2260 |
| M-04 | MEDIUM | §5A | Type 枚举拆分 platform_general_response (0x8001) 与 terminal_general_response (0x0001)；新增 A-52/A-53 |
| M-05 | MEDIUM | §5A | ResponseSN=0 自动绑定改为按 MsgId 匹配（0x8100→0x0100，0x8001→最近 terminal-up），避免 most-recent-upstream 错绑 |
| M-06 | MEDIUM | §7A.11 | 多终端 src_port 自动递增策略明确（从 10000 起，参考 socks5.go） |
| M-07 | MEDIUM | §3A.2 / §7A.12 | 分包共享同一 MsgSN（JT/T 808-2019 §4.2.3），仅 PackageNum 递增；每个分包独立校验码 |
| M-08 | MEDIUM | §7A.13 | 场景 (f) 删除非标准 MsgId=0x017e，改为用 AuthCode/Phone/MsgSN/校验码构造 0x7e/0x7d 字节 |
| L-01 | LOW | §4A.1 | LicensePlate 长度公式明确"= BodyLength - 37 固定字节" |
| L-02 | LOW | §3A.1 | Phone BCD 编码明确 big-endian（'012345678901' → 0x01 0x23 ... 0x01） |
| L-03 | LOW | §7A.14 | 校验字节 XX 计算示例改为含消息体的 57 字节 XOR |
| L-04 | LOW | §4A.3 | Time 字段明确"北京时间 UTC+8" |
| L-05 | LOW | §6A.2 | flowID 改为 "jt808-{Phone}-{InitialSN}"（Phone + InitialSN 在 Config 阶段确定） |

#### Part B: JT809（17 问题）

| ID | 严重度 | 章节 | 修复内容 |
|----|--------|------|----------|
| C-01 | CRITICAL | §7B.13 | 0x1002 hex dump MsgLength 从 0x0f(15) 修正为 0x25(37)；公式 32+1+4=37 |
| C-02 | CRITICAL | §4B.5 / §7B.13 | 0x1201 SubBody 明确为 JT809 自有字段布局（不复用 JT808 0x0100）；SubLength=38、MsgLength=63(32+1+2+38) |
| C-03 | CRITICAL | §7B.13 | 0x1202 hex dump MsgLength 从 0x36(54) 修正为 0x35(53) |
| C-04 | CRITICAL | §4B.2 / §6B.1 / §6B.3 | 0x1002 仅应答 0x1001，不应答 0x1200/0x1400；状态机改用 0x1300 SubMsgId=0x03 应答业务；删除 lastMainSentSN 绑 0x1002 声明 |
| H-01 | HIGH | §4B.1 / §4B.8 | 删除 LinkFlag 字段（JT/T 809-2019 不存在）；链路由 Procedure.Link 字段决定 |
| H-02 | HIGH | §4B.5 / §8B | 0x1200 SubMsgId 0x01-0x0A 字段表全部补全（含 0x1204 报警附件/0x1205 车辆定向/0x1206 区域车辆/0x1207 路径记录/0x1209 事件上报/0x120A 车辆注销）；新增 B-39~B-44 测试 |
| H-03 | HIGH | §8B | 新增 B-45~B-49 覆盖 0x1300/0x1500/0x1600/0x9100/0x9600 五个容器消息 |
| H-04 | HIGH | §4B.7 / §5B | FileUrl 明确"GBK 编码后最大 256 字节"；Validate 先 GBKEncode 再检查；B-20 测试 UTF-8 输入 128 汉字=256 GBK 字节 |
| H-05 | HIGH | §4B.1 / §4B.8 | LinkFlag=2 语义已随 H-01 删除 LinkFlag 字段而消除 |
| H-06 | HIGH | §5B.1 / §7B.10 | Validate 强制多平台 GNSSCenterId 互异；UniquePlatformGNSSCenterIds 检查；B-25/B-26 断言 GNSSCenterId 各异 |
| M-01 | MEDIUM | §4B.1 / §7B.13 | UserName 不足 5 字符右补 0x00 明确；hex dump UserName="TEST\0" 一致 |
| M-02 | MEDIUM | §6B.3 | 首条消息 SN=InitialSN（发送后递增）；0x1001/0x9001 hex dump MsgSN=0（InitialSN=0） |
| M-03 | MEDIUM | §4B.4 / §7B.3 / §8B | ReasonCode 删除 99=其他；§7B.3 新增 (c) ReasonCode=1（紧急）；新增 B-50 测试 |
| M-04 | MEDIUM | §4B.10 / §4B.11 | 0x9100 SubMsgId 补全 0x01-0x05；0x9600 补全 0x01-0x03；SubBody 字段表已补 |
| M-05 | MEDIUM | §5B | per-procedure LoginResult 优先于全局 LoginResult；planner 生成 0x1002 应答用对应 procedure 的 LoginResult |

#### Part C: JTT905（13 问题）

| ID | 严重度 | 章节 | 修复内容 |
|----|--------|------|----------|
| C-05 | CRITICAL | §7C.8 | 0x1001 hex dump MsgBodyProps 从 0x0040 修正为 0x0852（BodyLength=82, Version=2019） |
| C-06 | CRITICAL | §7C.8 | 0x1002 hex dump MsgBodyProps 从 0x0040 修正为 0x084a（BodyLength=74, Version=2019） |
| C-07 | CRITICAL | §4C.4 / §7C.8 | 0x8001 字段表删除 Phone(6)，消息体固定 5 字节；与 JT/T 905-2014 §8.2 一致 |
| H-07 | HIGH | §7C.8 | 0x1002 OffTime BCD 从 7 字节混合编码修正为 6 字节纯 BCD `24 08 03 16 00 00` |
| H-08 | HIGH | §1 / §4C.2 | 对比表修正：JTT905 车牌仅在 0x1001/0x1002 消息体，消息头不含车牌 |
| H-09 | HIGH | §5C | Procedures 空自动生成逻辑完整声明：check-in(SN=InitialSN) → heartbeat×N(SN+1..SN+N) → check-out(SN+N+1)；每条上行消息后跟 0x8001 应答；HeartbeatCount=0 跳过心跳；HeartbeatInterval=0 时 PacketConfig.TimeOffset=0 |
| H-10 | HIGH | §6C.1 | 心跳失败路径 Result=0/1/2/3/99 各值 ISU 行为明确（继续/重发/停止） |
| M-06 | MEDIUM | §4C.4 / §4C.5 | 0x8001 与 0x0001 结构对称（都 5 字节无 Phone） |
| M-07 | MEDIUM | §6C.2 / §7C.8 | 统一首条 SN=InitialSN；0x1001 hex MsgSN=0；C-29 期望与 hex 一致 |
| M-08 | MEDIUM | §5C.1 | startTime = OnTime，endTime = OffTime（扩展表 4 字段别名映射） |
| M-09 | MEDIUM | §5C.1 | 新增 Validate 规则表（Phone/DriverId/DriverName/OnTime/OffTime/HeartbeatCount/LoadCapacity 全部明确） |
| L-03 | LOW | §5C | DriverName 空时默认 16 字节空格填充，Validate 不拒绝 |
| L-04 | LOW | §5C | Phone 无默认值，必须用户配置；hex dump 示例用 013800138000 |
| L-05 | LOW | §6C.2 | platformMsgSN 初值=0（默认 PlatformInitialSN=0），首条应答 SN=0 |

#### Part D: 共用（6 问题）

| ID | 严重度 | 章节 | 修复内容 |
|----|--------|------|----------|
| H-11 | HIGH | §10.1 / §8D | FlowSpec 互斥规则：JT808/JT809/JTT905 至多一个非 nil；新增 X-01 multi_protocol_mutex_rejected（§8D 跨协议用例 X-01~X-03） |
| H-12 | HIGH | §11.1 | XORChecksum 注释明确调用者必须传入 MsgId 到消息体末字节范围；新增 XORChecksumJT808Header 包装函数；D-02 增加负面用例 |
| M-10 | MEDIUM | §11.1 | PadRight 签名保持 string 输入但注释明确"先 GBKEncode 再 PadRight"；新增 PadRightGBK(s, width) ([]byte, error) |
| M-11 | MEDIUM | §11.5 | 新增 D-11/D-12 gbk_pure_ascii/gbk_pure_chinese；D-13/D-14/D-15 bcd_all_zeros/bcd_all_nines/bcd_leading_zero |

### 16.2 修订记录 v1.1.1（2026-08-03 重审返工）

| ID | 修复位置 | 修复内容 |
|----|----------|----------|
| N-01 | §5B.1、§8B B-32 | UserName 短于 5 字符按正文规则右补 0x00 后通过；仅超长拒绝。 |
| N-02 | §8B B-50 | 紧急断开消息统一为 0x1007，ReasonCode=1 合法并通过 Validate。 |
| N-03 | §8B B-39~B-49 | 按 §4B 字段表统一字段、长度、方向及容器说明。 |
| N-04 | §7C.8、§6C.2 | 平台首条应答 MsgSN 统一为 0。 |
| N-05 | §12 | 用例统计统一为 JT808 53、JT809 50、JTT905 32、D 15、X 3，总计 153；同步修正余量说明。 |
| N-06 | §9.2 | 各协议通用应答 Result 统一按规范的 0-3 枚举，删除 99 要求。 |
| N-07 | §9.6 | 校验范围改为包含消息体及分包 SN，不含起始符、结束符及校验字节。 |
| D M-10 | §11.1、§11.2 | 新增 `PadRightGBK(s string, totalBytes int) ([]byte, error)`，GBK 编码后按字节以 0x00 填充。 |
| D H-12 | §11.1 | 新增 `XORChecksumGBK(payload []byte) byte` 包装函数，明确对 GBK 编码字节执行 XOR。 |

### 16.3 修订记录 v1.1.2（2026-08-03 第二轮复审返工，19 问题修复）

| ID | 严重度 | 修复位置（行号） | 修复内容 |
|----|--------|------------------|----------|
| C-1 | CRITICAL | §12 用例统计（约 L2526-L2533）/ §16.1 N-05（约 L2663） | §12 表格 JT808 用例数从 40 修正为 59；§16.1 N-05 "55" 修正为 "53"（与正文 A 类用例 53 一致，本轮另增 6 条边界用例至 59） |
| C-2 | CRITICAL | §8A A-17 后（约 L819-L825） | A-17 原仅覆盖 13/17 字段，新增 A-17b~A-17g 边界测试：CountyId=0 / TownId=0 / Operator=3 / APN 超长 / HardwareVersion 空 / MaxSpeed=65535 |
| C-3 | CRITICAL | §1 对比表（约 L27）/ §3B.1（约 L884）/ §7B.13 hex 注释（约 L1516-L1571） | "22 字节固定" 修正为 "32 字节"（4+4+2+1+21=32）；同步修正 §7B.13 所有 MsgLength 计算公式与 hex dump 注释（0x1001/0x1002/0x1200/0x1202/0x9001） |
| C-4 | CRITICAL | §7B.13 0x1002 hex 注释（约 L1523） | "4+4+2+1+21+1+4=37" 公式修正为 "32+1+4=37"（与 §3B.1 一致），实际数值 37 不变 |
| C-5 | CRITICAL | §7A.13(g)（约 L728） | "BodyLength=0x017d 不可能"（10 位最大 0x3FF）修正为 "构造 MsgBodyProps 低字节=0x7d 合法场景（BodyLength=0x7d=125 字节）" |
| H-1 | HIGH | §6B.3（约 L1393）/ §8B B-24b（约 L1640） | 主从链路 MsgSN 独立性测试缺失：§6B.3 slaveMsgSN 描述明确"完全独立"；新增 B-24b slave_link_independent_msgsn |
| H-2 | HIGH | §6C.2（约 L1941） | platformMsgSN 明确为 per-ISU 独立（每个 ISU 会话独立计数器），不与同进程其他 ISU 会话共享 |
| H-3 | HIGH | §9.1（约 L2175） | 删除过时 LinkFlag 引用，改为 VehicleColor(1)/VehiclePlate(21) |
| H-4 | HIGH | §11.1（约 L2426）/ §11.2（约 L2467） | 复用表新增 PadRightSpace 行（JT808 TerminalModel 右补空格至 20 字节） |
| H-5 | HIGH | §8B B-40~B-43（约 L1662-L1665） | 0x1205/0x1206/0x1207/0x1209 子类型验证点描述已补全（字段顺序与长度断言） |
| H-6 | HIGH | §3A.2（约 L82）/ §5C Version 注释（约 L1742） | 明确 JTT905 Version 字段语义："2019" 是协议兼容版本，不是发布年份（JT/T 905-2014 兼容 bit10-12=010） |
| M-1 | MEDIUM | §4A.6 字段表（约 L226-L229）/ §5A JT808Property（约 L476-L479） | 字段名 ProvinceID/CityID/CountyID/TownID 统一为 ProvinceId/CityId/CountyId/TownId（去掉大写 ID），JSON tag 不变（province_id/city_id/county_id/town_id） |
| M-2 | MEDIUM | §5A JT808Extra（约 L466-L475） | 明确编码：Type(1) + Length(1) + Value，新增 Length 字段说明（planner 自动计算），Value 注释为原始字节 |
| M-3 | MEDIUM | §8A A-40（约 L849） | "Result=3" 改为 "Validate 通过 ACKFlag=3（合法枚举）；ACKFlag=99 → Validate 拒绝" |
| M-4 | MEDIUM | §8B B-05（约 L1620） | "Result=99" 改为 "Result=99 → Validate 拒绝（仅 0-4 合法）；Result=5 → Validate 拒绝（边界外值）" |
| M-5 | MEDIUM | §11.1 XORChecksumGBK（约 L2387-L2396） | 补充 XORChecksumGBK 函数定义与等价性测试说明（D-02 覆盖与 XORChecksum 等价性） |
| L-1 | LOW | §7A.3(a)（约 L618） | 示例 Time "240803120000" 加注："示例沿用 2024 年日期；实现可使用任何合法 YYMMDDhhmmss 北京时间" |
| L-2 | LOW | §16.1 Part B/C/D 表（约 L2606-L2648） | 编号风格统一：Part B/C/D 的 C-1/H-1/M-1/L-1 等改为零填充 C-01/H-01/M-01/L-01（与 Part A 一致） |
| L-3 | LOW | §4A.6（约 L223）/ §5A JT808Property.IccId（约 L478） | IccId/ICCID 拼写统一：Go 字段 IccId，JSON tag icc_id，注释明确"勿用 ICCID 或 IccID 变体" |

本轮返工新增测试用例：A-17b/A-17c/A-17d/A-17e/A-17f/A-17g（JT808，6 条）、B-24b（JT809，1 条）。§12 总计从 153 修正为 160（JT808 53→59、JT809 50→51）。

### 16.4 修订记录 v1.1.3（2026-08-03 第三轮复审返工，20 问题修复）

来源：`audit/02-jt808-audit.md` 三轮审计 7 问题（1C/1H/3M/2L）+ `audit/03-04-jt809-jtt905-audit.md` 三轮审计 13 问题（3C/2H/5M/3L），合计 20 问题（4C/3H/8M/5L）。

| 编号 | 级别 | 位置 | 修复内容 |
|------|------|------|----------|
| J-3.01 | CRITICAL | §11.1 PadRightGBK 函数注释 / §11.2 PadRight 映射表 | JT809 VehiclePlate 与 JTT905 DriverName/VehicleModel/LicensePlate 必须 0x20 空格填充（PadRightSpace），非 0x00（PadRightGBK）；§11.1 函数前新增警示注释，§11.2 映射表三协议列明确区分适用字段 |
| J-3.02 | CRITICAL | §8B B-39~B-44 | 0x1200 SubMsgId 0x04-0x0A 测试用例描述修正：删除 SubBody 中错误的 VehicleColor(1B)+VehiclePlate(21B) 前缀；B-39 同步补 FileSize(4B) 字段 |
| J-3.03 | CRITICAL | §7C.8 0x8001 hex dump | MsgBodyProps 从 0x0005 修正为 0x0805（Version=2019），与同会话 0x1001/0x1002 Version=2019 一致 |
| J-3.04 | CRITICAL | §7A.13(g) | "BodyLength=0x017d 不可能" 修正为单一明确描述：构造 MsgBodyProps=0x007d（BodyLength=125, Version=2011），验证低字节 0x7d 转义 |
| J-3.05 | HIGH | §7B.13 0x1202 hex dump | Latitude 从 0x025bc860 修正为 0x0263b560（39.9° 北京实际纬度），与 §7A.14 JT808 0x0200 一致 |
| J-3.06 | HIGH | §5C Procedures 自动生成逻辑 | 平台侧 0x8001 MsgSN 来源从 InitialSN 修正为 PlatformInitialSN（per-ISU 独立计数器，初值=0）；明确 platformMsgSN 与 ISU 侧 InitialSN 完全独立 |
| J-3.07 | MEDIUM | §6B.3 mainFlowID/slaveFlowID / §6C.2 flowID / §10.4 路由 | flowID 模板从 {SrcPort} 修正为 {InitialSN}（Config 阶段确定）；JT809 主从链路、JTT905 单 flow、§10.4 路由表三处同步 |
| J-3.08 | MEDIUM | §7C.8 0x0002 心跳 hex dump | MsgBodyProps 从 0x0000 修正为 0x0800（Version=2019, BodyLength=0），与同会话 0x1001/0x1002 Version=2019 一致 |
| J-3.09 | MEDIUM | §11.5 D-06 表 | 删除表内多余注释行（破坏 markdown 表格结构） |
| J-3.10 | MEDIUM | §4B.5 0x1204 字段表 / §8B B-39 | 0x1204 报警附件 SubBody 字段表补 FileSize(4B uint32 BE)；FileType=0 时 FileSize=0；B-39 同步补 FileSize |
| J-3.11 | MEDIUM | §3B.1 VehicleColor 注释 | 新增 VehicleColor 取值表（10 个取值）；明确车辆相关 MsgId 与非车辆 MsgId 分类 |
| J-3.12 | MEDIUM | §6A.2 状态变量 | JT808 状态变量新增 platformMsgSN uint16 字段：per-Terminal 独立、初值=PlatformInitialSN=0、首条应答 SN=0、不与终端侧 msgSN 共用计数器；与 §6C.2 JTT905 platformMsgSN 定义对齐 |
| J-3.13 | LOW | §16.3 C-2 | CountyID/TownID 统一为 CountyId/TownId（去大写 ID，与 §4A.6 字段名一致） |
| J-3.14 | LOW | §16.1 H-02 | ProvinceID/CityID/CountyID/TownID 统一为 ProvinceId/CityId/CountyId/TownId（去大写 ID） |
| J-3.15 | LOW | §7B.13 0x1200 hex dump SubLength 注释 | SubLength=28 补计算公式注释：= 4+4+4+4+2+2+2+6，明确不含 SubMsgId/SubLength 自身 3 字节 |
| J-3.16 | LOW | §7A.14 0x8100 hex dump MsgSN 注释 | MsgSN=2 注释补充来源说明：来自 platformMsgSN 计数器（per-Terminal 独立、初值=PlatformInitialSN、首条应答 SN=PlatformInitialSN、不与终端侧 msgSN 共用） |
| J-3.17 | MEDIUM | §6B.3/§6C.2/§10.4 flowID（与 J-3.07 合并） | flowID 模板 {SrcPort}→{InitialSN} 同步（详见 J-3.07） |
| J-3.18 | HIGH | §11.1 PadRightGBK（与 J-3.01 合并） | PadRightGBK 警示注释与 §11.2 映射表同步（详见 J-3.01） |
| J-3.19 | LOW | §7A.14 0x8100 MsgSN 注释（与 J-3.16 合并） | platformMsgSN 来源说明（详见 J-3.16） |
| J-3.20 | LOW | §7B.13 0x1200 SubLength 注释（与 J-3.15 合并） | SubLength 计算公式（详见 J-3.15） |

本轮返工新增测试用例：A-54/A-55/A-56/A-57/A-58/A-59（JT808，6 条）、B-51/B-52/B-53/B-54/B-55/B-56（JT809，6 条）、C-33/C-34/C-35/C-36/C-37（JTT905，5 条）。§12 总计从 160 修正为 177（JT808 59→65、JT809 51→57、JTT905 32→37）。

### 16.5 修订记录 v1.1.4（2026-08-03 第四轮复审返工，7 问题修复）

来源：第四轮审计 7 问题（3 CRITICAL / 2 HIGH / 2 MEDIUM），编号 J-4.01 ~ J-4.07。

| 编号 | 级别 | 位置 | 修复内容 |
|------|------|------|----------|
| J-4.01 | CRITICAL | §7B.13 0x1200 hex dump（SubMsgId=0x01） | MsgLength 字节从 `00 00 00 3f`(63) 修正为 `00 00 00 49`(73)；注释 MsgLength=63 修正为 MsgLength=73；公式 32+1+2+38=73 自洽 |
| J-4.02 | CRITICAL | §7B.13 0x1202 hex dump | MsgLength 字节从 `00 00 00 35`(53) 修正为 `00 00 00 3f`(63)；注释 MsgLength=53 修正为 MsgLength=63；公式 32+1+2+28=63 自洽 |
| J-4.03 | CRITICAL | §8B B-35 测试用例断言 | `0x1200(SubMsgId=0x01) MsgLength=63；0x1202 MsgLength=53` 修正为 `0x1200(SubMsgId=0x01) MsgLength=73；0x1202 MsgLength=63`，与 J-4.01/J-4.02 修正后的 HexDump 一致 |
| J-4.04 | HIGH | §7C.8 0x8001 hex dump | MsgSN 修正为 0x0002（平台第 3 条应答）；校验码修正为 0x24（XOR 17 字节） |
| J-4.05 | HIGH | §7A.14 0x8100 平台注册应答 hex dump | MsgSN 从 0x0002 修正为 0x0000（按 §6A.2 平台首次应答流水号从 PlatformInitialSN=0 开始；本 0x8100 是平台对终端 0x0100 的首条应答，MsgSN 应为 0）；校验码 XX 修正为 0x1d（XOR 全部 31 字节：0x81^0x00^0x00^0x13^0x01^0x23^0x45^0x67^0x89^0x01^0x00^0x00^0x00^0x01^0x00^0x41^0x42^0x43^0x44^0x45^0x46^0x31^0x32^0x33^0x34^0x35^0x36^0x37^0x38^0x39^0x30 = 0x1d） |
| J-4.06 | MEDIUM | §7C.8 0x0002 心跳 hex dump 校验码注释 | 注释参与异或字节列表补齐 0x08（MsgBodyProps 高字节，Version=2019 bits10-12=010），原列表缺 0x08 导致 XOR 结果算成 0xa9（含 0x08 后实际为 0xa1）；校验字节 XX 修正为 0xa1，注释列出全部 12 参与字节 |
| J-4.07 | MEDIUM | §3B.1 VehicleColor 取值表注释 | 注释"与 JT/T 808-2019 附录 A 一致"修正为"与 JT/T 415-2006《道路运输车辆卫星定位系统 车载终端》表 A.1 一致；该取值表源自 JT/T 415-2006，并非 JT/T 808-2019 附录 A——JT/T 808-2019 附录 A 定义的是 AlarmFlag/StatusFlag 报警标志位与状态标志位，与车辆颜色无关" |

本轮返工无新增测试用例（全部为已有 HexDump/注释/测试断言的数值修正）。

### 16.6 修订记录 v1.1.4-patch（2026-08-04 第五轮复审返工，6 问题修复）

来源：第五轮审计 6 问题（1 HIGH / 3 MEDIUM / 2 LOW），编号 H-R5-01 ~ L-R5-06。

| 编号 | 级别 | 位置 | 修复内容 |
|------|------|------|----------|
| H-R5-01 | HIGH | §8B B-35 | 测试断言 `0x1200(SubMsgId=0x01) MsgLength=73；0x1202 MsgLength=63` 逐字节核算 HexDump 自洽性确认；MsgLength 计算公式 32+1+2+38=73 与 32+1+2+28=63 与 hex dump 一致 |
| M-R5-02 | MEDIUM | §6B.3 状态变量 | 新增 `platformMainMsgSN uint32` 与 `platformSlaveMsgSN uint32` 字段，明确初值=PlatformInitialSN（默认 0），与 JT808/JTT905 的 PlatformInitialSN 术语统一 |
| M-R5-03 | MEDIUM | §8B B-56 | 测试描述补充"断言填充字节 = 0x20（与 PadRightGBK 0x00 填充明确区分）"精确描述，与 §11.2 映射表一致 |
| M-R5-04 | MEDIUM | §16.5 J-4.04 | 修订记录表格 J-4.04 行长描述简化为"MsgSN 修正为 0x0002（平台第 3 条应答）；校验码修正为 0x24（XOR 17 字节）"，避免 markdown 表格渲染异常 |
| L-R5-05 | LOW | §16.4 | 修订记录表编号格式统一为 J-3.xx 格式（与 §16.5 J-4.xx 格式保持一致），删除"02-C-3.01 / 03-04-C-3.01"等多前缀混合格式 |
| L-R5-06 | LOW | §8C C-38 | 新增测试用例 C-38 "procedures_non_empty_custom"：Procedures 非空路径（用户自定义流程）planner 严格按用户指定顺序生成，不触发自动补全；验证 MsgSN 与 PlatformInitialSN 独立递增 |

本轮返工新增测试用例：C-38（JTT905，1 条）。§12 总计从 177 修正为 178（JT808 65、JT809 57、JTT905 38、D 15、X 3）。



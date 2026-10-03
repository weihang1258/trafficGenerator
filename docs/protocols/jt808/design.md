# JT808（JT/T 808-2019）协议设计

> 版本：v1.1.0（层链迁移审计版）
> 日期：2026-09-30
> 范围：JT808 终端与平台之间基于 TCP 的报文生成、状态机、配置校验和测试契约。
> 配套用例：`docs/protocols/jt808/testcase.md`；机器契约：`trafficgen/test/protocol_pcap/cases/jt808.json`。
> 本文保留合集设计的 JT808 规范内容作为历史依据；当前实现形状、层链迁移状态和未实现边界以本文末尾审计章节为准。

---
# Part A: JT808

## 2A. 协议概述

JT808（JT/T 808-2019，道路运输车辆卫星定位系统终端通讯协议，vehicle terminal communication protocol）定义车载终端（vehicle terminal / 终端）与平台（platform / 监控平台）之间的通信。一条 JT808 会话承载于一条独立 TCP 流之上（默认端口 7611），双向均可发送报文：终端上报位置/报警，平台下发命令/应答。

单条 JT808 报文（frame / 报文）的物理结构：

```
0x7e  [消息头 12/16B]  [消息体 0..1023B]  [校验码 1B]  0x7e
```

- 起始符（start flag / 起始符）固定 `0x7e`
- 结束符（end flag / 结束符）固定 `0x7e`
- 消息头（message header / 消息头）12 字节（无分包）或 16 字节（分包，加 4 字节分包信息）
- 消息体（message body / 消息体）长度 0-1023 字节，由消息头中的"消息体属性"字段指示
- 校验码（check code / 校验码）1 字节，XOR 校验，从 MsgId 第一字节到消息体最后一字节（含消息体 + 分包项 PackageNum/PackageTotal；不含起始符/结束符/校验字节本身）

转义（escape / 转义）在整条报文（不含起始符/结束符）传输出现在 0x7e / 0x7d 时触发：

- 0x7e → 0x7d 0x02
- 0x7d → 0x7d 0x01

接收方按相反规则还原。转义发生在校验计算之后：发送方先按原始字节算 XOR，再做转义；接收方先反转义再校验。

## 3A. 报文格式

### 3A.1 消息头字段表（无分包）

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 2 | MsgId（消息ID） | 大端，例 0x0100=终端注册，0x0200=位置上报 |
| 2 | 2 | MsgBodyProps（消息体属性） | 大端，bit 字段见 3A.2 |
| 4 | 6 | Phone（终端手机号） | BCD 编码 12 位数字（big-endian BCD：'012345678901' → 0x01 0x23 0x45 0x67 0x89 0x01，不足左补 0） |
| 10 | 2 | MsgSN（消息流水号） | 大端，0-65535 回绕 |

### 3A.2 消息体属性位定义（MsgBodyProps，big-endian 16-bit）

| Bit | 含义 |
|-----|------|
| 0-9 | BodyLength（消息体长度，0-1023） |
| 10-12 | Version（版本标志，000=2011，001=2013，010=2019） |
| 13 | 保留（reserved / 保留，固定 0） |
| 14 | PackageFlag（分包标志，0=单包，1=多包） |
| 15 | EncryptFlag（加密标志，0=未加密，1=加密） |

> 说明：Version 字段值是协议兼容版本号，并非标准发布年份。"2019" 表示按 JT/T 808-2019 标准的消息体属性编码（bit10-12=010），与 JT/T 808-2011 标准的编码（bit10-12=000）共存。planner 根据用户配置的 Version 字符串写入对应位，不做版本号语义校验。

> 注意：长度字段只有 10 bit，单条消息体最长 1023 字节。超长消息（如批量位置上报、文件下发）走分包机制：bit14=1 时消息头追加 4 字节 `PackageNum(2) + PackageTotal(2)`。按 JT/T 808-2019 §4.2.3，同一条逻辑消息的所有分包**共享同一 MsgSN**（标识逻辑消息），仅 PackageNum 递增；每个分包独立计算校验码（每个分包是独立物理帧）。

### 3A.3 转义规则

报文（不含首尾 0x7e 标识符）中：

| 原始字节 | 转义后 |
|----------|--------|
| 0x7e | 0x7d 0x02 |
| 0x7d | 0x7d 0x01 |

反转义：遇到 0x7d 时读下一字节，0x02 → 0x7e，0x01 → 0x7d；其余 0x7d 后跟字节视为非法转义序列，整条报文丢弃并记录错误日志。

转义作用范围（scope of escape / 转义作用范围）：

- 作用于：MsgId + MsgBodyProps + Phone + MsgSN + [分包信息] + 消息体 + 校验码
- 不作用于：起始符 0x7e 与结束符 0x7e

转义时序（escape ordering / 转义时序）：

1. 发送方：先按原始字节计算 XOR 校验码 → 拼接完整报文（不含首尾 0x7e）→ 对整段做转义 → 在首尾各加一个 0x7e。
2. 接收方：先去除首尾 0x7e → 对中间部分做反转义 → 拆解消息头/消息体/校验码 → 用反转义后的字节重新计算 XOR 验证。

常见错误（common pitfalls / 常见错误）：

- 错误 A：先转义再算校验码。导致校验码基于转义后字节，接收方反转义后校验失败。
- 错误 B：起始符/结束符也参与转义。导致接收方找不到边界。
- 错误 C：校验码不参与转义。导致校验字节为 0x7e/0x7d 时接收方反转义错位。
- 错误 D：反转义时遇到 0x7d 后直接跳过下一字节但不还原。导致字节丢失。

### 3A.4 校验算法

```
checksum = 0
for b in bytes[MsgId .. 消息体最后一字节]:
    checksum ^= b
// 若分包，PackageNum/PackageTotal 也参与校验
// 校验字节附加在消息体后、结束符前
```

校验范围 = MsgId(2) + MsgBodyProps(2) + Phone(6) + MsgSN(2) + [PackageNum(2) + PackageTotal(2) 若分包] + 消息体(BodyLength)。不含起始符 0x7e、结束符 0x7e、校验字节本身。**消息体参与校验**，分包时的 PackageNum/PackageTotal（属于消息头一部分）也**参与校验**。这一点常被错误实现为"校验不含消息体"，需在测试中显式覆盖。按 JT/T 808-2019 §4.4，校验码范围从消息头首字节（MsgId 第一字节）到消息体最后一字节，按字节异或。

校验范围字节序列（checksum scope byte layout / 校验范围字节序列）：

```
字节 0-1:  MsgId（2 字节，参与校验）
字节 2-3:  MsgBodyProps（2 字节，参与校验）
字节 4-9:  Phone（6 字节 BCD，参与校验）
字节 10-11: MsgSN（2 字节，参与校验）
[字节 12-15: PackageNum(2) + PackageTotal(2)，分包时存在，参与校验]
字节 (12 或 16) 至 (12 或 16)+BodyLength-1: 消息体，参与校验
字节 (12 或 16)+BodyLength: 校验字节本身，不参与校验
```

校验算法伪代码（pseudo code / 伪代码）：

```go
func xorChecksum(headerAndBody []byte) byte {
    var cs byte
    for _, b := range headerAndBody {
        cs ^= b
    }
    return cs
}
// 调用时传入：MsgId..消息体末字节（含消息体 + 分包项 PackageNum/PackageTotal，不含首尾 0x7e、不含校验字节本身）
// 即传入：无分包 = 12 + BodyLength 字节；分包 = 16 + BodyLength 字节
```

## 4A. 关键消息体格式

### 4A.1 0x0100 终端注册（terminal registration / 终端注册）

终端开机后首条消息，向平台登记自身身份。

| 字段 | 长度 | 类型 | 说明 |
|------|------|------|------|
| ProvinceId | 2 | uint16 BE | 省域 ID（GB/T 2260） |
| CityId | 2 | uint16 BE | 市县域 ID（GB/T 2260） |
| ManufacturerId | 5 | byte[5] ASCII | 制造商 ID（终端厂商编号） |
| TerminalModel | 8/20 | byte[] | 终端型号，长度由厂商自定（规范：8 或 20 字节，本实现固定 20 字节，左空格补齐） |
| TerminalId | 7 | byte[7] | 终端 ID（设备序列号） |
| LicenseColor | 1 | uint8 | 车牌颜色（0=未上车牌，1=蓝，2=黄，3=黑，4=白，5=绿，9=其他） |
| LicensePlate | variable | string GBK | 车牌号（LicenseColor=0 时为空，否则 GBK 编码，无长度前缀，长度 = BodyLength - (ProvinceId 2 + CityId 2 + ManufacturerId 5 + TerminalModel 20 + TerminalId 7 + LicenseColor 1)） |

### 4A.2 0x0102 终端鉴权（terminal authentication / 终端鉴权）

注册成功并收到 0x8100 注册应答后，终端发送鉴权请求以建立业务会话。

| 字段 | 长度 | 说明 |
|------|------|------|
| AuthCode | variable | 鉴权码（0x8100 下发，最长 16 字节，GBK） |
| Imei | 15 | IMEI（ASCII，可空） |
| SoftwareVersion | 20 | 软件版本号（厂商自定义，ASCII/GBK） |

> AuthCode 长度可变（1-16 字节 GBK），由消息头 BodyLength 兜底定界。AuthCode 为空时 Validate 拒绝（JT/T 808-2019 §6.4.2 鉴权码不可为空，鉴权码长度由 0x8100 注册应答下发，必定非空）。

### 4A.3 0x0200 位置上报（location report / 位置上报）

终端周期性上报的位置信息，是 JT808 最核心消息。

| 字段 | 长度 | 类型 | 说明 |
|------|------|------|------|
| AlarmFlag | 4 | uint32 BE | 报警标志（bit 位定义见规范，本实现按整体字段处理） |
| StatusFlag | 4 | uint32 BE | 状态标志（ACC/门/油路/...） |
| Latitude | 4 | uint32 BE | 纬度（1e-6 度） |
| Longitude | 4 | uint32 BE | 经度（1e-6 度） |
| Altitude | 2 | uint16 BE | 海拔（米） |
| Speed | 2 | uint16 BE | 速度（0.1 km/h） |
| Direction | 2 | uint16 BE | 方向（0-359，正北 0，顺时针） |
| Time | 6 | BCD | 时间 YYMMDDhhmmss（BCD，6 字节，北京时间 UTC+8） |
| ExtraItems | variable | TLV | 附加项，每项 Type(1) + Length(1) + Value(Length)，可选：里程/油量/信号强度/... |

### 4A.4 0x0201 位置查询应答（location query response / 位置查询应答）

平台用 0x8201 查询位置，终端用 0x0201 应答。消息体首字段是平台查询消息的流水号，后接 0x0200 的完整消息体。

| 字段 | 长度 | 说明 |
|------|------|------|
| QuerySN | 2 | uint16 BE，所应答的 0x8201 报文流水号 |
| LocationBody | variable | 同 0x0200 消息体（含报警/状态/经纬度/时间/附加项） |

### 4A.5 0x0003 终端注销（terminal cancel / 终端注销）

终端主动断开业务会话。消息体为空。

### 4A.6 0x0107 查询终端属性应答（terminal property response / 终端属性应答）

平台用 0x8104 查询，终端用 0x0107 应答。JT/T 808-2019 §6.4.7 共 17 个字段：

| 字段 | 长度 | 说明 |
|------|------|------|
| DeviceType | 1 | 终端类型（0=普通车载，1=货运，2=出租，...） |
| ManufacturerId | 5 | 制造商 ID（同 0x0100） |
| TerminalModel | 20 | 终端型号 |
| TerminalId | 7 | 终端 ID |
| IccId | 10 | SIM 卡 ICCID（Integrated Circuit Card Identifier，集成电路卡标识，ASCII） |
| Imei | 15 | 终端 IMEI（ASCII） |
| SoftwareVersion | 20 | 软件版本 |
| GnssModule | 1 | GNSS 模块属性（bit0=GPS，bit1=BEIDOU，...） |
| CommModule | 1 | 通信模块属性（bit0=GSM，bit1=CDMA，...） |
| ProvinceId | 2 | uint16 BE，省域 ID（GB/T 2260） |
| CityId | 2 | uint16 BE，市县域 ID（GB/T 2260） |
| CountyId | 2 | uint16 BE，区县 ID |
| TownId | 2 | uint16 BE，乡镇 ID |
| Operator | 1 | 运营商（0=移动，1=电信，2=联通，3=其他） |
| APN | variable | APN 名称（GBK，无长度前缀，由剩余字节定界） |
| HardwareVersion | variable | 硬件版本号（GBK，无长度前缀） |
| MaxSpeed | 2 | uint16 BE，最大速度（km/h） |

### 4A.7 0x8001 平台通用应答（platform general response / 平台通用应答）

平台对终端上报的通用确认。

| 字段 | 长度 | 说明 |
|------|------|------|
| ResponseSN | 2 | uint16 BE，所应答的终端报文流水号 |
| ResponseMsgId | 2 | uint16 BE，所应答的终端报文 MsgId |
| Result | 1 | 应答标志（0=成功/确认，1=失败，2=消息有误，3=不支持） |

> 消息体固定 5 字节，**不含 Phone**：Phone 已在消息头出现，应答绑定通过消息头的 Phone + 消息体的 ResponseSN 完成，不需要消息体重复 Phone。JT/T 808-2019 §6.5.1 明确消息体仅 ResponseSN + ResponseMsgId + Result 共 5 字节。

### 4A.8 0x8100 注册应答（registration response / 注册应答）

平台对 0x0100 的应答，下发鉴权码。

| 字段 | 长度 | 说明 |
|------|------|------|
| ResponseSN | 2 | uint16 BE，所应答的 0x0100 流水号 |
| Result | 1 | 注册结果（0=成功，1=车辆已被注册，2=数据库中无该车辆，3=终端已被注册，4=终端不存在） |
| AuthCode | variable | 鉴权码（Result=0 时下发，最长 16 字节，GBK） |

### 4A.9 0x8103 / 0x8104 / 0x8201 / 0x8300 简表

| MsgId | 名称 | 方向 | 消息体要点 |
|-------|------|------|------------|
| 0x8103 | 设置终端参数 | 平台→终端 | 参数总数(1) + TLV 列表，每项 ParamId(4) + ParamLen(1) + ParamValue(ParamLen)；当前实现/存量帧按此体形编码（历史 ParamId(1) 表述见 G-JT808-3） |
| 0x8104 | 查询终端参数 | 平台→终端 | 空 |
| 0x8201 | 位置查询 | 平台→终端 | 空 |
| 0x8300 | 文本下发 | 平台→终端 | TextFlag(1) + Text(variable, GBK)，TextFlag 控制显示方式（紧急/ tts/广告/...） |

终端对 0x8103/0x8104/0x8300 的应答统一走 0x0001 终端通用应答（结构与 0x8001 对称：ResponseSN(2) + ResponseMsgId(2) + Result(1) 共 5 字节，方向相反；同样**不含 Phone**）。

## 5A. Config 结构体设计

### 5A.1 Validate 规则表

| 字段 | 合法范围 | 拒绝条件 |
|------|----------|----------|
| Phone | ^\d{12}$ | 非 12 位数字 |
| Version | "2011" / "2013" / "2019" | 其他字符串 |
| EncryptFlag | 0 / 1 | 其他值 |
| LicenseColor | 0,1,2,3,4,5,9 | 6,7,8,10-255 |
| LicensePlate | 当 LicenseColor=0 必须为空；非空时 GBK 编码后 ≥1 字节 | LicenseColor=0 但 LicensePlate 非空 |
| ProvinceId | uint16 (0-65535)，按 GB/T 2260 | （范围合法即可，不强制校验行政区划码存在性） |
| CityId | uint16 (0-65535)，按 GB/T 2260 | 同上 |
| ManufacturerId | 5 字节 ASCII | 非 5 字节或非 ASCII |
| TerminalModel | 1-20 字节，左对齐右补空格至 20 | 空或 >20 字节 |
| TerminalId | 7 字节 | 非 7 字节 |
| AuthCode | 1-16 字节 GBK（编码后） | 空、或 GBK 编码后 >16 字节 |
| IMEI | 15 字节 ASCII | 非 15 字节或非 ASCII |
| SoftwareVersion | 20 字节 | 非 20 字节 |
| Direction | 0-359 | ≥360 |
| Latitude | 0-90000000 | >90000000 |
| Longitude | 0-180000000 | >180000000 |
| Time | ^\d{12}$ (YYMMDDhhmmss, 北京时间 UTC+8) | 非 12 位数字、非法日期、非北京时间 |
| ACKFlag | 0,1,2,3 | 99 或其他 |
| RegistrationResult | 0,1,2,3,4 | 其他值 |
| InitialSN | uint16 (0-65535) | （无限制） |

> 多终端场景下，Validate 还需检查 N 个终端的 Phone 互异（避免 groupID=hash(Phone) 路由冲突）。

```go
// JT808Config configures a JT/T 808-2019 vehicle-terminal session.
type JT808Config struct {
    // Phone (终端手机号) is the 12-digit BCD terminal phone number.
    // Must match ^\d{12}$. Required.
    Phone string `json:"phone"`

    // Version (版本标志) selects the protocol year. "2011" | "2013" |
    // "2019" (default). Affects MsgBodyProps bits 10-12.
    Version string `json:"version,omitempty"`

    // EncryptFlag (加密标志) 0=plain (default), 1=encrypted. When 1,
    // the body is XOR-with-key transformed — but trafficgen does NOT
    // implement real encryption; it only sets the flag bit and emits
    // the body as-is (field placeholder per design §11A.2).
    EncryptFlag uint8 `json:"encrypt_flag,omitempty"`

    // LicenseColor (车牌颜色) 0-5,9. 0 means no plate; LicensePlate
    // MUST then be empty.
    LicenseColor uint8 `json:"license_color,omitempty"`

    // LicensePlate (车牌号) GBK-encoded, only when LicenseColor != 0.
    // May contain Chinese characters (multi-byte GBK).
    LicensePlate string `json:"license_plate,omitempty"`

    // ProvinceId / CityId (省域/市域 ID) for 0x0100 registration.
    ProvinceId uint16 `json:"province_id,omitempty"`
    CityId     uint16 `json:"city_id,omitempty"`

    // ManufacturerId (制造商ID) 5 ASCII chars, default "TEST".
    ManufacturerId string `json:"manufacturer_id,omitempty"`

    // TerminalModel (终端型号) up to 20 bytes, default "TG-DEMO".
    TerminalModel string `json:"terminal_model,omitempty"`

    // TerminalId (终端ID) 7 bytes, default "0000001".
    TerminalId string `json:"terminal_id,omitempty"`

    // TerminalType (终端类型) for 0x0107 property response, 0-2.
    TerminalType uint8 `json:"terminal_type,omitempty"`

    // InitialSN (起始流水号) for the per-flow MsgSN counter. 0 default.
    // Each subsequent message increments by 1, wrapping at 65535.
    InitialSN uint16 `json:"initial_sn,omitempty"`

    // AuthCode (鉴权码) for 0x0102. When empty, the planner uses the
    // 0x8100 response's AuthCode (auto-flow). Must be 1-16 bytes GBK
    // after encoding; empty string is rejected by Validate (see §5A.1).
    AuthCode string `json:"auth_code,omitempty"`

    // IMEI (终端IMEI) for 0x0102 authentication body. 15 ASCII chars.
    // Required for 0x0102. Validate rejects non-15-byte ASCII.
    IMEI string `json:"imei,omitempty"`

    // SoftwareVersion (软件版本号) for 0x0102 authentication body.
    // 20 bytes ASCII/GBK. Required for 0x0102.
    SoftwareVersion string `json:"software_version,omitempty"`

    // RegistrationResult (注册应答结果) for 0x8100. 0=success (default),
    // 1-4=fail. When non-zero, AuthCode is omitted.
    RegistrationResult uint8 `json:"registration_result,omitempty"`

    // Procedures (业务流程) is the ordered list of JT808 messages to
    // emit. Each entry picks a message template and overrides its
    // fields. The planner fills MsgSN, Phone, and ack bindings
    // automatically.
    Procedures []JT808Procedure `json:"procedures"`
}

// JT808Procedure is one step in a JT808 session.
type JT808Procedure struct {
    // Type (消息类型) selects the message template.
    // One of: "register", "auth", "location_report",
    // "location_query_response", "cancel", "property_response",
    // "platform_general_response" (0x8001 platform→terminal),
    // "terminal_general_response" (0x0001 terminal→platform),
    // "registration_response",
    // "set_params", "query_params", "query_location", "text_down".
    // The split between platform_general_response and
    // terminal_general_response disambiguates direction (M-04).
    Type string `json:"type"`

    // ACKFlag (通用应答标志) for general_response / registration_response.
    // 0/1/2/3. Validate rejects 99 or other out-of-range values.
    // Ignored for non-response types.
    ACKFlag uint8 `json:"ack_flag,omitempty"`

    // LocationData (位置数据) for "location_report" and
    // "location_query_response". Required for those types; ignored
    // otherwise.
    LocationData *JT808Location `json:"location_data,omitempty"`

    // ResponseSN (应答流水号) for "general_response" /
    // "registration_response" / "location_query_response". When 0,
    // the planner auto-binds to the SN of the most recent message
    // whose MsgId matches the response's target MsgId (e.g., 0x8100
    // binds to the most recent 0x0100, 0x8001 binds to the most
    // recent terminal-up message being acknowledged, 0x0201 binds
    // to the most recent 0x8201). This avoids mis-binding in
    // delayed-ack or interleaved scenarios.
    ResponseSN uint16 `json:"response_sn,omitempty"`

    // ResponseMsgId (应答消息ID) for "general_response". When 0,
    // auto-bound.
    ResponseMsgId uint16 `json:"response_msg_id,omitempty"`

    // RegistrationResult (注册结果) per-procedure override for
    // "registration_response". Empty = use top-level.
    RegistrationResult *uint8 `json:"registration_result,omitempty"`

    // AuthCode (鉴权码) per-procedure override for "registration_response"
    // when result=0.
    AuthCode string `json:"auth_code,omitempty"`

    // IMEI per-procedure override for "auth". Empty = use top-level.
    IMEI *string `json:"imei,omitempty"`

    // SoftwareVersion per-procedure override for "auth". Empty = top-level.
    SoftwareVersion *string `json:"software_version,omitempty"`

    // Text (文本内容) for "text_down", GBK.
    Text string `json:"text,omitempty"`

    // TextFlag (文本标志) for "text_down", 0-3 (bit flags).
    TextFlag uint8 `json:"text_flag,omitempty"`

    // Params (参数列表) for "set_params": TLV items.
    Params []JT808Param `json:"params,omitempty"`

    // PropertyData (终端属性) for "property_response".
    PropertyData *JT808Property `json:"property_data,omitempty"`
}

type JT808Location struct {
    AlarmFlag   uint32 `json:"alarm_flag"`
    StatusFlag  uint32 `json:"status_flag"`
    Latitude    uint32 `json:"latitude"`    // 1e-6 deg
    Longitude   uint32 `json:"longitude"`   // 1e-6 deg
    Altitude    uint16 `json:"altitude"`    // m
    Speed       uint16 `json:"speed"`       // 0.1 km/h
    Direction   uint16 `json:"direction"`   // 0-359
    Time        string `json:"time"`        // "YYMMDDhhmmss" (BCD-encoded by planner)
    ExtraItems  []JT808Extra `json:"extra_items,omitempty"`

    // Bit-level convenience fields (扩展表 2 doorStatus/runStatus).
    // When non-nil, the planner OR-merges them into StatusFlag before
    // encoding: ACC=bit0, DoorStatus=bit1, OilCircuit=bit2, Gate=bit3.
    // StatusFlag (when set directly) takes precedence; these are
    // OR-merged on top. nil = not applied.
    ACC         *bool `json:"acc,omitempty"`
    DoorStatus  *bool `json:"door_status,omitempty"`
    OilCircuit *bool `json:"oil_circuit,omitempty"`
    RunStatus   *bool `json:"run_status,omitempty"` // alias of ACC for 扩展表 2
}

type JT808Extra struct {
    // Type (附加项类型) 1 字节。JT/T 808-2019 附录 C 定义，例如
    // 0x01=里程, 0x02=油量, 0x03=行驶记录仪速度。
    Type uint8 `json:"type"`

    // Length (附加项长度) 1 字节。planner 在序列化时由 len(Value)
    // 自动计算并写入；用户不必手动设置。
    Length uint8 `json:"length,omitempty"`

    // Value (附加项值) 原始字节，序列化时按 Type(1)+Length(1)+Value 布局
    // 输出，长度由 len(Value) 决定。解码时反向解析为该结构体。
    Value []byte `json:"value"`
}

type JT808Param struct {
    Id    uint8  `json:"id"`
    Value []byte `json:"value"` // raw bytes, length auto-prefixed
}

type JT808Property struct {
    DeviceType       uint8  `json:"device_type"`
    ManufacturerId   string `json:"manufacturer_id"`
    TerminalModel    string `json:"terminal_model"`
    TerminalId       string `json:"terminal_id"`
    // IccId (SIM 卡 ICCID, Integrated Circuit Card Identifier) 10 ASCII
    // chars. Spelling unified to "IccId" (Go field) / "icc_id" (JSON tag)
    // throughout the design — do not use "ICCID" or "IccID" variants.
    IccId            string `json:"icc_id"`
    Imei             string `json:"imei"`
    SoftwareVersion  string `json:"software_version"`
    GnssModule       uint8  `json:"gnss_module"`
    CommModule       uint8  `json:"comm_module"`
    ProvinceId       uint16 `json:"province_id"`
    CityId           uint16 `json:"city_id"`
    CountyId         uint16 `json:"county_id"`
    TownId           uint16 `json:"town_id"`
    Operator         uint8  `json:"operator"`
    APN              string `json:"apn"`
    HardwareVersion  string `json:"hardware_version"`
    MaxSpeed         uint16 `json:"max_speed"`
}
```

## 6A. 状态机

单终端会话状态机（state machine / 状态机）：

```
       [init]
         |
         |  TCP connect (SYN/SYN-ACK/ACK)
         v
    [connected]
         |
         |  send 0x0100 register
         v
   [registered?] --0x8100 result!=0--> [terminated] (TCP teardown)
         |
         |  0x8100 result=0, AuthCode
         v
   [authenticated?] --send 0x0102--> [awaiting auth ack]
         |                              |
         |                              | 0x8001 result=0
         |                              v
         |                         [authenticated]
         |<-----------------------------+
         |
         |  send 0x0200 location (repeat N times)
         v
    [reporting] --0x8201 query from platform--> send 0x0201
         |
         |  send 0x0003 cancel (or platform-initiated disconnect)
         v
    [terminated] --TCP 4-way teardown--> [closed]
```

平台主动下发场景（如 0x8300 文本下发、0x8103 设置参数、0x8104 查询参数、0x8201 查询位置）插入在 `[authenticated]` 与 `[reporting]` 之间，终端以 0x0001 通用应答回复。

### 6A.1 状态转移表

| 当前状态 | 触发事件 | 输出消息 | 下一状态 |
|----------|----------|----------|----------|
| init | task 启动 | TCP SYN | connected |
| connected | 进入 registered 前置 | 0x0100 register | registered_await |
| registered_await | 收到 0x8100 result=0 | （缓存 AuthCode） | authenticated_pre |
| registered_await | 收到 0x8100 result=1-4 | TCP FIN | terminated |
| authenticated_pre | 准备鉴权 | 0x0102 auth | auth_await |
| auth_await | 收到 0x8001 result=0 | - | authenticated |
| auth_await | 收到 0x8001 result=1 | TCP FIN | terminated |
| auth_await | 30s 超时未收到 0x8001 | 重发 0x0102（最多 1 次）；仍超时 → 0x0003 注销 | terminated |
| authenticated | 周期触发 | 0x0200 location | reporting |
| reporting | 收到 0x8001 result=0 | - | authenticated |
| reporting | 收到 0x8201 query | 0x0201 location_resp | authenticated |
| authenticated | 平台下发 0x8300 | 0x0001 general_resp | text_await |
| text_await | 30s 超时未发 0x0001 | 重发 0x0001（最多 1 次）；仍超时 → 0x0003 注销 | terminated |
| authenticated | 平台下发 0x8103 | 0x0001 general_resp | set_params_await |
| set_params_await | 30s 超时未发 0x0001 | 重发 0x0001（最多 1 次）；仍超时 → 0x0003 注销 | terminated |
| authenticated | 平台下发 0x8104 | 0x0107 property_resp | query_params_await |
| query_params_await | 30s 超时未发 0x0107 | 重发 0x0107（最多 1 次）；仍超时 → 0x0003 注销 | terminated |
| authenticated | 平台下发 0x8201 | 0x0201 location_resp | query_location_await |
| query_location_await | 30s 超时未发 0x0201 | 重发 0x0201（最多 1 次） | authenticated |
| authenticated | 终端主动断开 | 0x0003 cancel | terminated |
| terminated | TCP teardown | FIN/ACK | closed |

### 6A.2 状态变量

每个终端会话维护以下状态变量（state variables / 状态变量）：

- `msgSN uint16`：当前消息流水号（终端侧），初值=InitialSN，每发一条递增，回绕 65535→0。
- `platformMsgSN uint16`：平台侧消息流水号，**per-Terminal 独立**——每个终端会话（含对端平台模拟）拥有自己的 platformMsgSN 计数器，与对端终端的 platformMsgSN 互不干扰；初值=0（默认 PlatformInitialSN=0），**首条应答 SN=0**，发送后递增，回绕 65535→0。说明：trafficgen 模拟终端客户端时，平台应答（0x8001/0x8100/0x8103/0x8104/0x8201 等）的 MsgSN 由本会话内的 platformMsgSN 字段维护，不与同一进程内其他终端会话共享，也**不与终端侧 msgSN 共用计数器**——两者完全独立。
- `authCode string`：从 0x8100 获取的鉴权码，用于 0x0102。
- `lastSentMsgId uint16`：最近发送的 MsgId，用于绑定 0x8001 应答。
- `lastSentSN uint16`：最近发送的 MsgSN，用于绑定 0x8001 应答。
- `lastReceivedSN uint16`：最近收到的终端报文 MsgSN（平台侧状态），用于 0x8001 的 ResponseSN。
- `tcpSeq uint32`：客户端 TCP 序列号（每条段递增，参考 rtsp.go 的 clientSeq/serverSeq 闭包）。
- `tcpAck uint32`：客户端 TCP 确认号。
- `flowID string`："jt808-{Phone}-{InitialSN}"，在 Config 阶段就确定，避免 src_port 晚分配导致 flowID 不稳定。
- `groupID string`：hash(Phone)，保证同终端消息有序。

### 6A.3 平台侧状态机

平台侧（响应方）状态机对称：

| 当前状态 | 触发事件 | 输出消息 | 下一状态 |
|----------|----------|----------|----------|
| init | TCP SYN 到达 | SYN-ACK | connected |
| connected | 收到 0x0100 | 0x8100 register_resp | registered |
| registered | 收到 0x0102 | 0x8001 general_resp (MsgId=0x0102) | authenticated |
| authenticated | 收到 0x0200 | 0x8001 general_resp (MsgId=0x0200) | authenticated |
| authenticated | 平台业务触发 | 0x8201 query_location | query_await |
| query_await | 收到 0x0201 | - | authenticated |
| query_await | 30s 超时未收到 0x0201 | 重发 0x8201（最多 1 次）；仍超时 → 放弃 | authenticated |
| authenticated | 平台业务触发 | 0x8300 text_down | text_await |
| text_await | 收到 0x0001 | - | authenticated |
| text_await | 30s 超时未收到 0x0001 | 重发 0x8300（最多 1 次）；仍超时 → 放弃 | authenticated |
| authenticated | 平台业务触发 | 0x8103 set_params | set_params_await |
| set_params_await | 收到 0x0001 | - | authenticated |
| set_params_await | 30s 超时 | 重发 0x8103（最多 1 次） | authenticated |
| authenticated | 平台业务触发 | 0x8104 query_params | query_params_await |
| query_params_await | 收到 0x0107 | - | authenticated |
| query_params_await | 30s 超时 | 重发 0x8104（最多 1 次） | authenticated |
| authenticated | 收到 0x0003 | TCP FIN | terminated |

trafficgen 是流量生成器，可同时模拟终端侧与平台侧（双向流量）。Config 的 Procedures 列表决定每个消息的发出方与接收方，planner 按顺序生成双向 TCP 段。

## 7A. 业务场景与数据场景

### 7A.1 终端注册 0x0100 → 0x8100

终端发送 0x0100（含 ProvinceId/CityId/ManufacturerId/TerminalModel/TerminalId/LicenseColor/LicensePlate），平台回 0x8100。Result=0 时携带 AuthCode，终端进入鉴权阶段。Result=1-4 时终端直接注销并断开 TCP。

数据场景：
- (a) 标准成功路径：LicenseColor=1（蓝牌），LicensePlate="京A12345"，Result=0，AuthCode="ABCDEF1234567890"。
- (b) 车辆已被注册：Result=1，AuthCode 缺省。
- (c) 数据库无车辆：Result=2。
- (d) 终端已被注册：Result=3。
- (e) 终端不存在：Result=4。
- (f) LicenseColor=0（无车牌），LicensePlate 必须为空，验证消息体不含车牌字段。

### 7A.2 终端鉴权 0x0102 → 0x8001

终端发送 0x0102（AuthCode + Imei + SoftwareVersion），平台回 0x8001（ResponseMsgId=0x0102）。

数据场景：
- (a) AuthCode 等于 0x8100 下发的码，Imei/SW Version 非空，Result=0。
- (b) AuthCode 错误，Result=1。
- (c) AuthCode 为空字符串（对抗，Validate 拒绝，不生成报文）。

### 7A.3 位置上报 0x0200 → 0x8001

终端发送 0x0200（含 AlarmFlag/StatusFlag/经纬度/速度/方向/时间/可选附加项），平台回 0x8001（ResponseMsgId=0x0200）。

数据场景：
- (a) 标准位置：北京（lat=39.9e6=39900000，lon=116.4e6=116400000），Speed=600（60.0 km/h），Direction=180（南），Time="240803120000"（示例沿用 2024 年日期；实现可使用任何合法 YYMMDDhhmmss 北京时间，不影响报文结构）。
- (b) 边界经纬度：lat=0、lon=0（海域）；lat=90000000、lon=180000000（极值）。
- (c) 速度 0（停车）。
- (d) 含附加项：里程 Extra(Type=0x01, Len=4, Value=0x000186A0=100000m)，油量 Extra(Type=0x02, Len=2, Value=0x00C8=200)。
- (e) AlarmFlag=0x00000001（紧急报警最高位），StatusFlag=0x00000001（ACC ON）。
- (f) 时间含非法字符（边界，应被 Validate 拒绝）。
- (g) 多次上报：连续 5 条 0x0200，MsgSN 递增 1/2/3/4/5，每条独立 0x8001 应答。

### 7A.4 位置查询 0x8201 → 0x0201

平台下发 0x8201（消息体空），终端回 0x0201（首字段 QuerySN=0x8201 的 MsgSN，后接 0x0200 完整消息体）。

数据场景：
- (a) 标准：QuerySN=42，LocationBody 同 7A.3(a)。
- (b) QuerySN=0（边界，由 planner 自动绑定到 0x8201 的 SN）。
- (c) 0x8201 在 0x0200 之前到达（消息顺序对抗，planner 必须按 Procedures 顺序生成）。

### 7A.5 终端注销 0x0003

终端发送 0x0003（消息体空），随后 TCP 四次挥手。无需平台应答。

数据场景：
- (a) 标准注销后立即 TCP FIN。
- (b) 注销前最后一条 0x8001 应答未发送（对抗，应仍按 Procedures 顺序）。

### 7A.6 查询终端属性 0x8104 → 0x0107

平台下发 0x8104（空），终端回 0x0107（属性数据）。

数据场景：
- (a) DeviceType=1，IccId/Imei/SW Version 全填。
- (b) DeviceType=0，IccId/Imei 空（边界，验证固定字段长度仍正确）。

### 7A.7 设置终端参数 0x8103 → 0x0001

平台下发 0x8103（TLV 参数列表），终端回 0x0001 通用应答（ResponseMsgId=0x8103）。

数据场景：
- (a) 单参数：ParamId=0x0001（心跳间隔），Value=uint32 BE 0x0000003C=60s。
- (b) 多参数：3 项 TLV。
- (c) 参数值长度与 ParamId 规范不符（对抗，planner 应允许任意 Value 长度，由 Validate 警告但不拒绝）。

### 7A.8 文本下发 0x8300 → 0x0001

平台下发 0x8300（TextFlag + GBK Text），终端回 0x0001。

数据场景：
- (a) TextFlag=0x01（紧急），Text="紧急通知"（GBK 8 字节）。
- (b) TextFlag=0x04（广告），Text 超长（边界，需触发分包或截断，planner 默认截断至 1023 字节并告警）。

### 7A.9 注册应答标志（RegistrationResult，0-4）

显式枚举：
- 0 = 成功（success / 成功）
- 1 = 车辆已被注册（vehicle already registered / 车辆已被注册）
- 2 = 数据库中无该车辆（vehicle not in database / 数据库中无该车辆）
- 3 = 终端已被注册（terminal already registered / 终端已被注册）
- 4 = 终端不存在（terminal not found / 终端不存在）

非 0 时 AuthCode 必须不出现（消息体长度=3，仅 ResponseSN+Result）。

### 7A.10 通用应答标志（ACKFlag，0/1/2/3）

- 0 = 成功/确认（success / 成功）
- 1 = 失败（failure / 失败）
- 2 = 消息有误（message malformed / 消息有误）
- 3 = 不支持（not supported / 不支持）

> JT/T 808-2019 §6.5.1 平台通用应答结果仅 0-3 四个值，**无 99=其他**。Validate 拒绝 ACKFlag ∉ {0,1,2,3}。

### 7A.11 多终端并发

N 个终端 = N 条独立 TCP 4-tuple（src_port 各异，dst_port=7611），每条独立 MsgSN 计数器、独立 Phone、独立 LicensePlate。Planner 输出 N 条 flow，每条 flow 由独立的 PacketWorker 处理（GroupID=Phone 哈希，保证同终端消息有序）。

多终端场景下，若用户未指定 src_port，planner 从 10000 起递增（参考 socks5.go 多会话处理）。flowID = "jt808-{Phone}-{InitialSN}"（Phone + InitialSN 在 Config 阶段就确定），确保 Phone 与 InitialSN 双重唯一。Validate 阶段强制检查 N 个终端的 Phone 互异，否则 groupID=hash(Phone) 会路由冲突。

数据场景：
- (a) N=10 终端，每个独立完成 register→auth→location×3→cancel 全流程。
- (b) N=2，一个成功鉴权、一个鉴权失败（Result=1），验证两条 flow 互不干扰。
- (c) N=100 高并发（性能场景，仅在 e2e 标记）。

### 7A.12 边界场景

- (a) Phone 12 位但前导 0（"000000000001"），BCD 编码后 6 字节全 0x01 之外的值（0x00 0x00 0x00 0x00 0x00 0x01）。
- (b) MsgSN 回绕：InitialSN=65534，连续 4 条消息，验证 SN=65534/65535/0/1。
- (c) LicensePlate 含中文（GBK 多字节），如 "京A12345"（GBK 8 字节）。
- (d) EncryptFlag=1（仅置位，body 不真加密）。
- (e) 分包包号：消息体 1100 字节，触发 2 个分包（PackageTotal=2，PackageNum=1/2），两个分包共享同一 MsgSN（JT/T 808-2019 §4.2.3），每个分包独立校验（含 PackageNum/PackageTotal 与消息体）。
- (f) Phone 不是 12 位（对抗，Validate 拒绝）。
- (g) LicenseColor=0 但 LicensePlate 非空（对抗，Validate 拒绝）。
- (h) Version 字符串非法（"2099"）（对抗，Validate 拒绝）。

### 7A.13 转义校验

人为构造消息体含 0x7e 或 0x7d 字节，验证转义后字节流与反转义结果一致。

数据场景：
- (a) AuthCode 含 0x7e（如 "AB~CD" 中的 ~ 取 ASCII 0x7e），验证线上字节为 0x7d 0x02。
- (b) SoftwareVersion 含 0x7d。
- (c) 校验码本身等于 0x7e（人为选择 MsgSN 使 XOR 命中），验证校验字节也参与转义。
- (d) LicensePlate GBK 编码恰好含 0x7d 字节（GBK 高位字节范围 0x81-0xFE，低位 0x40-0xFE 排除 0x7F，0x7d 不会自然出现，构造对抗用例需手动指定字节）。
- (e) Phone BCD 含 0x7e（不可能，BCD 字节范围 0x00-0x09，此用例为对抗验证 planner 不误转义）。
- (f) MsgId 高字节 0x00-0x08，低字节 0x00-0xFF；标准 MsgId 不会自然产生 0x7e（如 0x0100/0x0200），转义验证应通过消息体（AuthCode 含 0x7e）、Phone、MsgSN、校验码字段构造 0x7e/0x7d 字节，而非用非标准 MsgId（如 0x017e 会被真实平台按"未知 MsgId"拒收）。
- (g) 消息体属性字节含 0x7d（构造 MsgBodyProps=0x007d，即 BodyLength=125 字节、Version=2011，验证 MsgBodyProps 低字节 0x7d 参与转义：0x7d → 0x7d 0x01）。
- (h) 连续 0x7e 0x7d 字节序列，验证转义后 0x7d 0x02 0x7d 0x01 不被误判。

### 7A.14 报文示例（hex dump）

终端注册 0x0100 成功路径完整报文（hex，不含 TCP/IP 头）：

```
7e                          ; 起始符
01 00                       ; MsgId=0x0100 (终端注册)
00 2d                       ; MsgBodyProps=0x002d (BodyLength=45, Version=2011, 无分包, 无加密)
01 23 45 67 89 01           ; Phone BCD "012345678901" (big-endian BCD)
00 01                       ; MsgSN=1
                            ; --- 消息体开始 (45 字节) ---
00 0b                       ; ProvinceId=11 (北京, GB/T 2260)
00 00                       ; CityId=0
54 45 53 54 00              ; ManufacturerId="TEST\0" (5 ASCII)
54 47 2d 44 45 4d 4f 20 20 20 20 20 20 20 20 20 20 20 20 20  ; TerminalModel="TG-DEMO" 左对齐右补空格至 20 字节
30 30 30 30 30 30 31        ; TerminalId="0000001" (7 ASCII)
01                          ; LicenseColor=1 (蓝牌)
be a9 41 31 32 33 34 35     ; LicensePlate="京A12345" GBK 编码 (8 字节，无长度前缀)
                            ; --- 消息体结束 ---
XX                          ; 校验字节 (XOR of MsgId..消息体末字节, 共 12+45=57 字节)
7e                          ; 结束符
```

其中 `XX` = XOR(0x01, 0x00, 0x00, 0x2d, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x00, 0x01, 0x00, 0x0b, 0x00, 0x00, 0x54, 0x45, 0x53, 0x54, 0x00, 0x54, 0x47, 0x2d, 0x44, 0x45, 0x4d, 0x4f, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x01, 0xbe, 0xa9, 0x41, 0x31, 0x32, 0x33, 0x34, 0x35) = 计算值（测试中应断言精确字节；注意校验范围含消息体，共 57 字节）。

> 注：ProvinceId=11 是北京在 GB/T 2260 中的代码，CityId=0 表示市辖区。ManufacturerId 5 字节不足时右补 0x00（非空格）。TerminalModel 20 字节左对齐右补空格 0x20。TerminalId 7 字节左对齐右补 0x00 或空格（实现自定，本设计统一左对齐右补 0x00）。LicensePlate 无长度前缀，长度 = BodyLength - (ProvinceId 2 + CityId 2 + ManufacturerId 5 + TerminalModel 20 + TerminalId 7 + LicenseColor 1) = 45 - 37 = 8 字节。Phone BCD 编码为 big-endian BCD：'012345678901' → 0x01 0x23 0x45 0x67 0x89 0x01，不足左补 0。

平台注册应答 0x8100（成功 + AuthCode）：

```
7e
81 00                       ; MsgId=0x8100
00 13                       ; MsgBodyProps=0x0013 (BodyLength=19, Version=2011)
01 23 45 67 89 01           ; Phone
00 00                       ; MsgSN=0 (平台侧首条应答流水号，来自 platformMsgSN 计数器——per-Terminal 独立、初值=PlatformInitialSN、首条应答 SN=PlatformInitialSN、发送后递增；不与终端侧 msgSN 共用计数器)
                            ; --- 消息体 ---
00 01                       ; ResponseSN=1 (绑定终端 0x0100 的 MsgSN)
00                          ; Result=0 (成功)
41 42 43 44 45 46 31 32 33 34 35 36 37 38 39 30  ; AuthCode="ABCDEF1234567890" (16 ASCII)
1d                          ; 校验 = XOR(0x81, 0x00, 0x00, 0x13, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x41..0x30) = 0x1d
7e
```

终端位置上报 0x0200（北京，速度 60 km/h）：

```
7e
02 00                       ; MsgId=0x0200
00 1c                       ; MsgBodyProps=0x001c (BodyLength=28)
01 23 45 67 89 01           ; Phone
00 03                       ; MsgSN=3
                            ; --- 消息体 ---
00 00 00 01                 ; AlarmFlag=1 (紧急报警)
00 00 00 01                 ; StatusFlag=1 (ACC ON)
02 63 b5 60                 ; Latitude=39900000 (39.9 度, 北京实际纬度)
06 e6 0c 80                 ; Longitude=116400000 (116.4 度)
00 32                       ; Altitude=50 m
02 58                       ; Speed=600 (60.0 km/h)
00 b4                       ; Direction=180 (南)
24 08 03 12 00 00           ; Time BCD "240803120000" (2024-08-03 12:00:00)
XX
7e
```

## 8A. 测试用例清单

| # | 用例名 | 类型 | 验证点 |
|---|--------|------|--------|
| A-01 | register_success | happy path | 0x0100 字段顺序/长度正确；0x8100 Result=0 + AuthCode；MsgSN=InitialSN；BodyLength=45（37 固定+8 车牌）；逐字段断言（ProvinceId/CityId/ManufacturerId/TerminalModel/TerminalId/LicenseColor/LicensePlate） |
| A-02 | register_vehicle_already | negative | 0x8100 Result=1，消息体不含 AuthCode，长度=3 |
| A-03 | register_no_plate | boundary | LicenseColor=0 + LicensePlate="" → 消息体不含车牌字段 |
| A-04 | register_with_chinese_plate | boundary | GBK 多字节车牌正确编码 |
| A-05 | auth_success | happy path | 0x0102 AuthCode 与 0x8100 一致；0x8001 Result=0；消息体长度 = AuthCode 长度 + 15(IMEI) + 20(SW Version) |
| A-06 | auth_wrong_code | negative | 0x8001 Result=1 |
| A-07 | auth_empty_code | validation | AuthCode="" → Validate 拒绝，不生成报文 |
| A-08 | location_report_basic | happy path | 0x0200 字段顺序、BE 编码、Time BCD 正确；lat=39.9e6（北京实际纬度） |
| A-09 | location_report_zero_latlon | boundary | lat=0, lon=0 合法 |
| A-10 | location_report_max_latlon | boundary | lat=90000000, lon=180000000 |
| A-11 | location_report_with_extras | happy path | 附加项 TLV 顺序与长度正确 |
| A-12 | location_report_alarm | happy path | AlarmFlag 高位报警位正确 |
| A-13 | location_report_multi | integration | 5 条 0x0200 SN 递增，5 条 0x8001 应答绑定正确；每条 0x0200 断言完整 hex dump 与校验字节 |
| A-14 | location_query_response | happy path | 0x8201 → 0x0201，QuerySN 绑定 |
| A-15 | location_query_response_auto_sn | integration | ResponseSN=0 → 自动绑定到 0x8201 SN |
| A-16 | cancel | happy path | 0x0003 消息体空，紧接 TCP FIN |
| A-17 | property_response_full | happy path | 0x0107 所有 17 字段填充（含 ProvinceId/CityId/CountyId/TownId/Operator/APN/HardwareVersion/MaxSpeed） |
| A-17b | property_response_county_zero | boundary | CountyId=0 → 合法边界，字段长度仍正确 |
| A-17c | property_response_town_zero | boundary | TownId=0 → 合法边界 |
| A-17d | property_response_operator_other | boundary | Operator=3（其他）→ 合法枚举值 |
| A-17e | property_response_apn_long | boundary | APN GBK 编码后超 32 字节 → 截断或告警（planner 策略：保留前 32 字节并记录警告） |
| A-17f | property_response_hardware_empty | boundary | HardwareVersion="" → 消息体末尾空字段，固定字段长度仍正确 |
| A-17g | property_response_max_speed | boundary | MaxSpeed=65535 → 合法上限 |
| A-18 | property_response_empty_fields | boundary | IccId/Imei 空字符串 → 固定字段长度仍正确（0 填充） |
| A-19 | set_params_single | happy path | 0x8103 单 TLV → 0x0001 应答 |
| A-20 | set_params_multi | happy path | 0x8103 三 TLV → 0x0001 |
| A-21 | text_down_chinese | happy path | 0x8300 GBK 中文，TextFlag 正确 |
| A-22 | text_down_truncated | boundary | 超长 Text 截断至 1023 字节并告警 |
| A-23 | escape_0x7e_in_body | wire-format | 消息体含 0x7e → 线上 0x7d 0x02 |
| A-24 | escape_0x7d_in_body | wire-format | 消息体含 0x7d → 线上 0x7d 0x01 |
| A-25 | escape_checksum_collision | wire-format | 校验字节=0x7e 时也参与转义 |
| A-26 | xor_checksum_range | wire-format | 校验范围 = MsgId(2) + MsgBodyProps(2) + Phone(6) + MsgSN(2) + [PackageNum(2) + PackageTotal(2) 若分包] + 消息体(BodyLength)；不含起始符 0x7e、结束符 0x7e、校验字节本身。**消息体参与校验**，分包时 PackageNum/PackageTotal 也参与校验。0x0100 注册报文校验字节 = XOR(全部 57 字节 = 12 头 + 45 体) |
| A-27 | msgsn_wraparound | boundary | InitialSN=65534，4 条消息 SN=65534/65535/0/1 |
| A-28a | fragmented_message_structure | wire-format | 1100 字节消息体 → 2 分包；PackageTotal=2，PackageNum=1/2；第 1 分包 BodyLength=1023，第 2 分包 BodyLength=77；两分包共享同一 MsgSN |
| A-28b | fragmented_message_reassembly | wire-format | 两分包消息体拼接 == 原始 1100 字节（字节级 hexEqual 断言） |
| A-29 | multi_terminals_independent | integration | 10 终端 4-tuple 独立，MsgSN 互不干扰；Phone 互异（Validate 强制） |
| A-29b | multi_terminals_aggregate | integration | 10 终端并发 100 条 0x0200，断言总吞吐量 = 1000 条/配置时长，且每终端内 MsgSN 严格递增 |
| A-30 | multi_terminals_mixed_result | integration | 1 终端鉴权成功 + 1 终端鉴权失败，flow 不串扰 |
| A-31 | validate_bad_phone | validation | Phone 非 12 位 → Validate 拒绝 |
| A-32 | validate_bad_version | validation | Version="2099" → 拒绝 |
| A-33 | validate_color_plate_mismatch | validation | LicenseColor=0 + LicensePlate 非空 → 拒绝 |
| A-34 | version_2011_bits | wire-format | Version="2011" → MsgBodyProps bit10-12=000 |
| A-35 | version_2013_bits | wire-format | Version="2013" → bit10-12=001 |
| A-36 | version_2019_bits | wire-format | Version="2019" → bit10-12=010 |
| A-37 | encrypt_flag_set | wire-format | EncryptFlag=1 → bit15=1，body 不变（用非空 body 0x0200 断言字节级一致） |
| A-38 | full_lifecycle_e2e | integration | register→auth→location×3→query→cancel 全流程 e2e |
| A-39 | bcd_phone_encoding | wire-format | Phone="000000000001" → 6 字节 0x00 0x00 0x00 0x00 0x00 0x01（big-endian BCD） |
| A-40 | general_response_unsupported | boundary | Validate 通过 ACKFlag=3（不支持，合法枚举）；ACKFlag=99 → Validate 拒绝（删除 99 臆造值） |
| A-41 | unescape_invalid_sequence | wire-format | 反转义遇 0x7d 0x03（非法）→ 整条报文丢弃并记录错误 |
| A-42 | platform_command_timeout | integration | 平台下发 0x8300 后终端 30s 不回 0x0001 → 重发或注销 |
| A-43 | status_flag_bit_merge | wire-format | DoorStatus=true + ACC=true → StatusFlag = 0x00000003（bit0+bit1） |
| A-44 | validate_bad_license_color | validation | LicenseColor=6 → 拒绝 |
| A-45 | validate_bad_direction | validation | Direction=360 → 拒绝 |
| A-46 | validate_bad_latitude | validation | Latitude=90000001 → 拒绝 |
| A-47 | validate_bad_time_format | validation | Time="24-08-03" → 拒绝 |
| A-48 | registration_result_2_3_4 | negative | 0x8100 Result=2/3/4 各一例，消息体长度=3（无 AuthCode） |
| A-49 | general_response_result_2_3 | negative | 0x8001 Result=2/3 各一例，消息体 5 字节 |
| A-50 | checksum_with_body | wire-format | 校验范围含消息体（C-01 回归）：0x0100 注册报文校验字节 = XOR(全部 57 字节) |
| A-51 | checksum_with_package_info | wire-format | 分包时 PackageNum/PackageTotal 参与校验（C-01 回归） |
| A-52 | platform_general_response_direction | wire-format | Type="platform_general_response" → 0x8001（平台→终端） |
| A-53 | terminal_general_response_direction | wire-format | Type="terminal_general_response" → 0x0001（终端→平台） |
| A-54 | platform_msgsn_independent_per_terminal | wire-format | 2 终端并发：终端 1 收到 0x8100 MsgSN=0、终端 2 收到 0x8100 MsgSN=0（各会话 platformMsgSN 独立从 PlatformInitialSN=0 起，互不干扰）；同终端 0x8100→0x8001 MsgSN 严格递增（0→1→2） |
| A-55 | platform_msgsn_independent_from_terminal_msgsn | wire-format | 终端 msgSN=InitialSN=5，平台首条 0x8100 应答 MsgSN=0（platformMsgSN 从 PlatformInitialSN=0 起，不继承 InitialSN）；验证两计数器完全独立 |
| A-56 | flowid_stable_after_phonesn_assigned | integration | flowID="jt808-{Phone}-{InitialSN}" 在 Config 阶段确定；多终端场景 src_port 晚分配不影响 flowID；断言两终端 InitialSN 相同但 Phone 不同时 flowID 互异 |
| A-57 | escape_msgbodyprops_low_byte_7d | wire-format | 构造 MsgBodyProps=0x007d（BodyLength=125, Version=2011）：断言线上字节含 0x7d 0x01（0x7d 转义）；Unescape 还原 0x7d；BodyLength=125 字节段不含 0x7d（避免双重转义歧义） |
| A-58 | pad_right_space_jt809_vehicle_plate | wire-format | JT809 VehiclePlate="京A12345" GBK 编码后左对齐空格填充至 21 字节（0x20 填充，非 0x00）；断言末字节=0x20；与 PadRightGBK（0x00 填充）行为明确区分 |
| A-59 | escape_msgbodyprops_2019_version_bits | wire-format | Version="2019" 且 BodyLength=5（如 0x8001）：MsgBodyProps=0x0805（bit10-12=010）；断言 hex 字节 08 05；与 2011（0x0005）明确区分 |

JT808 用例数：65 条（**历史合集 A 类清单计数，不是当前机器契约覆盖数**；当前存量 cases 为 16 例，统计以文末 §17–§20 审计为准）。

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
| JT808（A 类，历史合集） | 65（当前机器契约：16 例，12 正 + 4 负） |
| JT809（B 类） | 57 |
| JTT905（C 类） | 37 |
| 共用（D 类） | 15 |
| 跨协议（X 类） | 3 |
| **总计（历史合集）** | **178** |

要求 ≥60，实际历史合集 178；当前 cases 机器契约仅为 16 例，未运行的历史条目不计入当前覆盖。

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

### 16.1 v1.1 修订明细（对抗审计 61 问题修复）

#### Part A: JT808（25 问题）

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

## 4.1 P1 规范矩阵与实现决策（CORE §4，2026-10-01）

本节是当前 JT808 设计的判定入口；早期 `4A` 章节是线格式和字段依据，不替代本矩阵。JT808 为单 TCP 连接、双向多帧的终结协议；不采用多连接会话编排，§3 的多会话项在本协议上**豁免**，依据是 JT/T 808-2019 §4.1 的单终端 TCP 连接模型和本生成器 `PlanWithConfig` 的单 `flowID` 设计。

### 17.1 八项 P1 矩阵

| 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|
| 连接模型：终端与平台建立一条 TCP 长连接，双向均可发消息（JT/T 808-2019 §4.1） | 注册、鉴权、位置上报、平台下发、通用应答 | `jt808.go:155-227` 生成 TCP 握手、消息序列和挥手；`flowID=jt808-{Phone}-{InitialSN}` | 多终端并发调度与跨 flow 动态分配未进入本协议 generator，登记 G-JT808-A1，迁入任务级 `flow_control/group_id` 后补 cases |
| 命令→响应：0x0100/0x0102/0x0200 等上行与 0x8100/0x8001 等下行按 ResponseSN/MsgId 关联（§6.4–§6.5） | 注册失败、鉴权、位置确认、查询应答、参数下发 | `jt808.go:228-235` 按 MsgId 维护四类自动绑定；`builder.go:172-184` 编码注册响应 | 0x8103/0x8201/0x8300 全命令族的机器断言未齐，登记 G-JT808-A2，按命令矩阵补 cases |
| 状态机：鉴权前后状态和异常断开必须可判定（§6） | 鉴权成功继续业务；注册失败后结束连接 | procedures 顺序驱动，失败注册例在 `jt808_t15_identity_composite`；`ValidateConfig` 先拒非法配置 | 运行期超时/重发状态未接线，登记 G-JT808-A3，迁入状态机事件和超时参数后补负例 |
| 线格式：0x7e 边界、12/16B 消息头、10-bit BodyLength、XOR、转义与分包（§4.2–§4.4） | 普通帧、含 0x7e/0x7d 数据、>1023B 分包 | `builder.go:287+` 分包；`parser.go:38-88` 反转义/长度/XOR；T5/T10 钉线字节 | 非法转义/校验失败的生成侧负例不在 cases，登记 G-JT808-A4，补 parser 驱动的拒绝验证 |
| 数据形态：BCD 手机号、GBK 字符串、TLV、位置 bit 位、版本/加密位（§7.1–§7.8） | 注册身份、位置状态、文本下发、终端属性 | `builder.go:55-280` 已编码；T4/T5/T6/T7/T8/T9 覆盖主要形态 | 全枚举字段逐值覆盖未完成，登记 G-JT808-A5，按 §17.3 变体表逐格补齐 |
| 错误处理：字段越界、空鉴权码、互斥字段必须拒绝且错误可观测（§6.4） | 错手机号、空 AuthCode、车牌颜色冲突、非法 ACK | `jt808.go:61-145` 返回明确 error；T11–T14 是真负例 | Version/Encrypt/长度/坐标边界仍缺 cases，登记 G-JT808-A6，按错误锚词清单补齐 |
| 性能与活性：长连接低开销、顺序号递增、消息体受 1023B 限制（§4.2.3） | 心跳、连续上报、分包长消息 | `PlanWithConfig` 使用 256 有界 channel，`msgSN/platformMsgSN` 独立递增；T10/T16 | 吞吐/并发/内存/CPU 实测数值待 P5，登记 G-JT808-P5，禁止用估算冒充实测 |
| 版本方言：2011/2013/2019 版本位和扩展字段按配置编码（§4.2.2） | 2011 加密位、2019 默认版本 | `types.go:135-147` 默认 2019；T6 显式 2011 | 2013 独立 wire 断言及版本矩阵未补，登记 G-JT808-A7，迁入版本参数化后补 case |

## 4.2 命令×响应码矩阵

| 命令/消息 | 响应/结果码 | 当前代码路径 | 用例映射与结论 |
|---|---|---|---|
| 0x0100 注册 | 0x8100，Result=0..4 | `ProcRegister`/`ProcRegistrationResponse` | T1/T4/T15；Result=2 已覆盖，其余结果登记 G-JT808-A2 |
| 0x0102 鉴权 | 0x8001，ACKFlag=0..3 | `ProcAuth`/`ProcPlatformGeneralResponse` | T1/T3；ACK=99 负例 T14，枚举逐值登记 G-JT808-A6 |
| 0x0200 位置上报 | 0x8001，ACKFlag=0..3 | `ProcLocation` 自动应答绑定 | T5；结果逐值登记 G-JT808-A2 |
| 0x8201 位置查询 | 0x0201 | `ProcLocationQuery`/`ProcLocationQueryResponse` | 设计 §7A.4，机器用例登记 G-JT808-A2 |
| 0x8103 参数设置 | 0x0001，ACKFlag=0..3 | `ProcSetParams`/`ProcTerminalGeneralResponse` | T3/T7 的响应绑定面；完整参数矩阵登记 G-JT808-A2 |
| 0x8104 属性查询 | 0x0107 | `ProcQueryProperty`/`ProcPropertyResponse` | T9；17 字段已编码，变体逐字段登记 G-JT808-A5 |
| 0x8300 文本下发 | 0x0001 | `ProcText`/通用应答 | T8；GBK 与终止行为已覆盖 |
| 0x0002 心跳 | 0x8001（可选） | `ProcHeartbeat` | T16；单拍覆盖，周期重发登记 G-JT808-A3 |

## 4.3 数据形态变体表

| 形态维度 | 取值/边界 | 实现位置 | 当前证据/缺口 |
|---|---|---|---|
| 版本 | 2011、2013、2019 | `jt808.go:176-179`、`types.go` | 2011 T6/2019 默认；2013 G-JT808-A7 |
| 消息体 | 0B、固定长度、可变 GBK、TLV | `builder.go:55-280` | T7/T8/T9/T16；全字段边界 G-JT808-A5 |
| 分包 | BodyLength≤1023；>1023 的 PackageNum/Total | `builder.go:287+` | T10；包序与重组负例 G-JT808-A4 |
| 转义 | 原文含 0x7e、0x7d、校验码命中 | `builder.go` frame encoder、`parser.go:38-55` | T5；非法后续字节 G-JT808-A4 |
| 编码 | BCD、ASCII、GBK、定长 0x00/0x20 填充 | `jtcommon`、`builder.go` | T4/T5/T8/T15；超长与非 ASCII G-JT808-A5 |
| 状态位 | Location StatusFlag 与 ACC/Door/Oil/Run bit merge | `builder.go:112-170` | T5；逐位 0/1 矩阵 G-JT808-A5 |
| 响应码 | Result 0..4；ACKFlag 0..3 | `jt808.go:132-142` | T14 只测非法 99；逐值 G-JT808-A6 |

## 4.4 商业行为→用例映射表

| 商业行为 | 规范/确认方式 | 用例 | 结论 |
|---|---|---|---|
| 终端注册后鉴权并继续上报 | JT/T 808-2019 §6.4；单连接序列 | T1/T3/T15 | 已实现、已覆盖 |
| 平台下发参数/文本并由终端应答 | §6.5；命令响应对照 | T7/T8 | 已实现、已覆盖主要形态 |
| 位置上报带状态位和扩展项 | §7.3；字段偏移与 XOR | T5 | 已实现、已覆盖 |
| 心跳维持长连接 | §7.2；终端实现需周期发送 | T16 | 单拍已覆盖，周期/超时 G-JT808-A3 |
| 注册失败立即结束会话 | §6.4.1；Result 非 0 分支 | T15 | wire 行为已覆盖，运行期断开 G-JT808-A3 |

## 4.5 三路对照

| 规范原文编号/要求 | 商业软件行为 | 开源实现思路 |
|---|---|---|
| JT/T 808-2019 §4.1、§4.2：单 TCP、帧边界和消息头 | 终端保持一条 TCP 连接，按 0x7e 分帧 | `PlanWithConfig` 先生成 TCP 载体，再以每条 JT808 消息生成 PSH-ACK |
| §4.3–§4.4：转义和 XOR | 发送前转义，接收端反转义后校验 | `builder.go` 先 XOR 再 escape；`parser.go` 先 unescape 再校验 |
| §6.4–§6.5：请求与应答关联 | 平台按手机号、MsgId、ResponseSN 关联 | `jt808.go:228-235` 分方向保存最近消息状态，禁止跨方向绑 SN |
| §7.1–§7.8：业务消息字段 | 商业终端按定长/GBK/BCD 编码上报 | `builder.go` 按每种消息单独编码，缺省字段由 config 默认值补齐 |

## 4.6 候选方案对比

| 真实走法 | 优点 | 代价 | 取舍 |
|---|---|---|---|
| A：单 `JT808Config.Procedures` 序列驱动一条 TCP flow | 对应单连接规范模型；SN、应答绑定和帧顺序可确定；内存为流式 | 多终端需任务层重复策略；异常定时器不在 planner | 当前采用，作为基线正确性和 pcap 钉帧路径 |
| B：每条命令独立 task/flow，再由任务层关联 | 可并发压测、故障隔离、易扩展多终端 | 破坏同连接顺序和 SN 上下文；关联状态需外置 | 仅用于 G-JT808-A1 的压力场景，不作为协议默认走法 |
| C：预先聚合完整字节流后一次性发送 | 易做全流重组断言 | 违反流式和有界内存约束，无法表达实时背压 | 不采用；长消息仍逐分包 Emit |

## 5. 依赖与错误处理

### 5.1.1 依赖与错误处理

| 依赖/故障 | 失败返回 | 继续或中断 | 重试/超时 |
|---|---|---|---|
| 缺 `jt808` 层或 L3 地址非法 | layer validator 返回 `jt808: layer config required` 或 `invalid SrcIP/DstIP` | 中断当前 task，不产假成功 | 不重试；调用方取消 |
| JT808 配置校验失败 | `ValidateConfig` 原始错误（见 §20 锚词） | 中断当前 flow，不 Emit 消息 | 不重试 |
| builder 编码失败 | GBK/长度/分包错误原样返回 | 中断当前 flow | 不重试 |
| ctx 取消或 Emit 失败 | goroutine 返回 context/Emit 原错误并关 channel | 中断，task 标记失败 | 不自动重试 |
| peer 不回 ACK/平台超时 | 当前 generator 不模拟网络反馈 | 运行期由上层 task 控制；不声称协议已完成 | 超时/重发迁入 G-JT808-A3，须新增状态事件接口 |

## 6. 性能设计与验收

| 维度 | 当前可核实边界 | P5 验收 |
|---|---|---|
| 吞吐 | 每条业务消息一个 TCP PSH-ACK；单消息体上限 1023B，分包逐帧 Emit | pcap 统计帧数/bytes/持续时间与目标 bps；NIC 同口 tcpdump 统计实际 wire bps/pps |
| 并发 | 单 config 单 flow；生成 channel 容量 256 | pcap 并发 N flow 逐 flow 校验序号/顺序；NIC 统计并发流数、丢包和重排 |
| 内存 | 不聚合全流；`configChan` 有界 256；每帧局部 buffer | 运行前后 RSS/峰值 RSS，分别测 1/100/1000 消息；超限登记 G-JT808-P5 |
| 队列 | generator channel `make(chan ...,256)`；上游 task 队列按引擎有界配置 | pcap 观察完整输出；NIC 观察背压下丢包/阻塞，记录队列峰值 |
| CPU | builder 做 BCD/GBK/XOR/escape，未声明固定 CPU 数值 | pcap 仅做内容验收；NIC 同时采集进程 CPU，报告每 Mbps CPU 与核数 |

双路规则：pcap 路是确定性内容/顺序验收（逐帧 offset、XOR、MsgSN、ResponseSN）；NIC 路是实际发包验收（tcpdump 同一过滤条件、帧计数、吞吐、丢包、方向）。两路都通过才可申报 P5 完成；本轮禁止把未运行的数值写成结果。

## 8.1 八要素实施契约与动态字段

### 8.1.1 §8 八要素

| 要素 | 当前结论 |
|---|---|
| 文件 | `trafficgen/internal/protocol/jt808/{jt808.go,builder.go,parser.go,layer_gen.go,types.go}`；三份契约文件 |
| 接口 | registry validator/generator；`PlanWithConfig(ctx,spec,cfg)`；`ValidateConfig` |
| 结构 | IP→JT808 当前 as-built；目标为 IP→TCP→JT808，迁移项 G-JT808-LC-1 |
| 流程 | 校验→默认值→TCP 握手→procedures 编码→每帧 Emit→TCP 挥手 |
| 错误 | validator/builder/ctx/Emit 错误原样传播，task 失败且无假成功 |
| 性能边界 | 1023B 单体、256 有界 channel、流式逐帧；基准数值由 P5 产生 |
| 冲突点 | 当前链缺显式 TCP 层、部分业务键零消费；分别由 G-JT808-LC-1/G-JT808-A8 立项迁入或删除 |
| 回滚 | 仅回滚本协议三文件；代码迁移单独提交且必须重跑三门 |

### 8.1.2 §12 动态字段清单与序号算法

| 字段 | fixed | inc | rand | list | pattern | 结论/序号算法与代码位置 |
|---|---:|---:|---:|---:|---:|---|
| src_ip/dst_ip | 承载层 | 承载层 | 承载层 | 承载层 | 承载层 | 当前由 `ip` 层统一解析；JT808 不复制。按流序号由通用层处理；当前 cases 为 fixed |
| src_port/dst_port | 承载层 | 承载层 | 承载层 | 承载层 | 承载层 | 端口应住 TCP 层；当前默认 7611 在 `types.go`/`jt808.go:163`，显式 TCP 迁移 G-JT808-LC-1 |
| phone | ✓ |  |  |  |  | BCD 编码；`jt808.go:172,189` 以 config 固定并进入 flowID；多终端动态 G-JT808-A1 |
| InitialSN | ✓ |  |  |  |  | `jt808.go:225` 初始化 `msgSN`，每终端上行发送后 uint16 递增（自然回绕；测试 G-JT808-A1） |
| PlatformInitialSN | ✓ |  |  |  |  | `jt808.go:226` 初始化 `platformMsgSN`，每平台下行发送后独立 uint16 递增 |
| procedures 顺序 | ✓ |  |  |  |  | `jt808.go` 按数组索引顺序；不做隐式随机/轮转，避免破坏 ResponseSN 关联 |
| Location/Property/TLV 业务字段 | ✓ |  |  |  |  | `builder.go:112-280` 按 config 直接编码；动态策略未接线，迁入 G-JT808-A8 后才允许 inc/rand/list/pattern |
| heartbeat 周期 | ✓ |  |  |  |  | 当前每个 procedure 一次；定时/重发迁入 G-JT808-A3，不暗示自动变化 |

### 8.1.3 门1 三行强制展开

| CORE 行 | JT808 具体满足方式与证据 |
|---|---|
| §1 旧键去向 | `src_ip/dst_ip`→`layers[].ip`；`src_port/dst_port` 应→`layers[].tcp`（当前默认端口由 `jt808.go:163` 补全，G-JT808-LC-1 迁入）；`count/bps/time`→flow_control；协议键全部→`layers[].jt808`。完整当前例：`{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"jt808":{"phone":"012345678901","procedures":[{"type":"heartbeat"}]}}]}`。 |
| §3 五件套 | 会话表=单 TCP 四元组+Phone；事务序列=procedures 数组；关联=同 Phone/flowID、上行 `msgSN` 与下行 `ResponseSN/MsgId`；插入=TCP PSH-ACK payload；时间线=握手→procedure 帧序→挥手。多连接 sessions 对 JT808 为**豁免**，依据 JT/T 808-2019 §4.1 单终端连接；多终端压测另由 G-JT808-A1 立项。 |
| §12 动态字段 | 四元组按承载 ip/tcp 层策略；phone/InitialSN/PlatformInitialSN/procedures/业务字段逐项见 §19.2；序号算法分别定位 `jt808.go:172,225-226`，当前未接线的业务动态列为 G-JT808-A8，不留空。 |

## 12. 缺口登记与 C4 锚词

| 编号 | 内容 | 迁入计划/验收 |
|---|---|---|
| G-JT808-LC-1 | 当前 16 例为 `[ip,jt808]`，显式 TCP 层及端口未迁入 | registry/translate 支持 `[ip,tcp,jt808]` 后局部迁移 cases，重钉 offset 和包数 |
| G-JT808-A1 | 多终端、动态四元组、SN 回绕 | 接入 flow_control/group_id 后补 inc/rand/list/pattern 五格与并发 pcap/NIC |
| G-JT808-A2 | 命令族/响应码矩阵未全量机器覆盖 | 按 §17.2 每格新增正例或真负例，逐值断言 |
| G-JT808-A3 | 运行期超时/重发/周期心跳未接线 | 增加状态事件和超时配置，再补非正常结束与长保活 cases |
| G-JT808-A4 | 非法转义、校验失败、分包重组失败未形成 cases | parser 驱动的负例必须返回错误且无成功 PCAP |
| G-JT808-A5 | 数据形态/字段边界未全量覆盖 | 按 §17.3 逐格补边界与编码 cases |
| G-JT808-A6 | Version/Encrypt/长度/坐标/Result 负例未全量覆盖 | 锚词必须逐条来自 `jt808.go:65-142`，cases 仅双键负例 |
| G-JT808-A7 | 2013 版本独立 wire 断言缺失 | 增加版本矩阵后核对 props/version bit |
| G-JT808-A8 | 业务字段动态策略未接线且部分字段只读/零消费 | 先在 translator 建字段归属；逐字段实现或删除无消费键，补代码行号和 cases |
| G-JT808-P5 | 吞吐/并发/内存/队列/CPU 尚无本轮实测 | 禁止编造数字；按 §18.2 pcap+NIC 双路跑完后登记结果 |

C4 当前 4 个负例均严格为 `{expect_error,error_contains}`：T11 `must be 12 digits`（`jt808.go:65-68`）、T12 `AuthCode is empty`（`jt808.go:110-116`/`builder.go:89`）、T13 `LicenseColor=0 but LicensePlate non-empty`（`jt808.go:89-91`）、T14 `ACKFlag 99 invalid`（`jt808.go:132-136`）。锚词均可在代码中核实；其它错误分支不冒充 cases 覆盖，归 G-JT808-A6。

## 15. 门1 对账结论

| 维度 | design | testcase | cases JSON | 结论 |
|---|---|---|---|---|
| 例数/ID | 本节引用 16 例、12 正/4 负 | §1/§2 同数同序 | 16 条，ID 唯一同序 | 一致 |
| 顶层与层链 | 旧键去向见 §19.3；当前 `[ip,jt808]` 缺口 LC-1 已登记 | §1 声明顶层仅 `layers` | 16/16 顶层 `{layers}`，层链 `[ip,jt808]` | 一致且不伪称 TCP 已迁移 |
| 负例契约 | C4 锚词逐条可定位 | §4 严格双键 | 4/4 仅 `expect_error,error_contains` | 一致 |
| P1/性能/动态 | §17–§20 矩阵、双路验收、清单、缺口 | §6/§12 回指 | JSON 不改；只计当前已覆盖 | 缺口均有编号与迁入计划 |

## 17. 层链迁移契约（D1-D8，2026-09-30）

本节覆盖当前实现与 `cases/jt808.json` 的可执行形状；不把历史合集的扁平示例当作当前配置契约。

| ID | 结论 | 证据与处理 |
|---|---|---|
| D1 | 地址只住 `layers[].ip`，端口只住 `layers[].tcp`，数量只住用例驱动器或 `flow_control` | 16 例机读审计；非负例无顶层地址/端口/count |
| D2 | JT808 是 TCP 终结层，目标标准链为 `[ip,tcp,jt808]` | 当前 16 例为 `[ip,jt808]` as-built 形，显式 tcp 层迁移登记 G-JT808-LC-1 |
| D3 | 端口由 TCP 载体决定，JT808 层不声明扁平端口 | 当前默认 dst_port=7611 由实现补全 |
| D4 | `procedures` 留在 `layers[].jt808`，消息方向由 procedure 类型决定 | #1/#3/#7 覆盖双向编排 |
| D5 | 顶层 `jt808` 子映射禁止作为正例入口 | 16 例均无顶层协议键 |
| D6 | 数量/速率不复制进协议配置，MsgSN 按会话状态维护 | 当前 cases 无静态复制字段；多终端/动态流登记 A′ |
| D7 | 负例保留故意错误输入和 `expect_error` 锚词 | T-11…T-14；不得洗成正例 |
| D8 | 未支持的多终端、超时重发和 NIC 证据不伪造为已覆盖 | 登记 G-JT808-A′/G-JT808-NIC |

### 17.1 层链迁移缺口

| 编号 | 内容 | 处理 |
|---|---|---|
| G-JT808-LC-1 | 当前 cases 缺显式 tcp 层；握手与默认端口由注册器补全 | 后续补 registry/translate 后再重钉全部 offsets；本轮不改代码 |

## 18. 六项审查清单（C1-C6）

| ID | 审查结论 |
|---|---|
| C1 | JSON 可解析，16 个 ID 唯一，顺序与 §8A 存量审计及 testcase §2 一致 |
| C2 | 16 例 `spec_json` 顶层仅 `{layers}`；无顶层 JT808/地址/端口/count |
| C3 | 地址仅在 ip 层；默认端口由实现补全，JSON 未伪造游离端口 |
| C4 | 4 个负例仅保留 `expect_error`、`error_contains` 两键；无附加 notes 或成功断言 |
| C5 | 基线、双 SN、非正常结束、分包、转义、单拍心跳已有例；SN 回绕、多终端、重复保活登记 A′ |
| C6 | 本轮范围严格为 jt808 design/testcase/cases 三文件；不改生成器、全局配置或其他协议 |

## 20. 负例契约形状（C4）

四个负例的 `expect` 严格仅含 `expect_error`、`error_contains` 两键；不得增加 `notes`、`packet_count`、`fields` 或 `frames`。

门①（当前 as-built 形状可机读）：16 例层链形、ID、包数和断言已核对；不宣称本轮 pcap/NIC 已跑通。门②（旧格式清除）：顶层 flat 字段已清除，但显式 tcp 传输层尚未迁移，保留 G-JT808-LC-1；该缺口不伪称完成。



# GBT32960 协议设计与测试用例

> 本文档同时作为 JT808 / JT809 / JTT905 三个车联网协议的设计模板。第 11 节说明如何复用本文档结构。
>
> 规范来源：GB/T 32960.3-2016《电动汽车远程服务与管理系统技术规范 第3部分：通讯协议》。
> 项目实现位置（计划）：`trafficgen/internal/protocol/gbt32960/gbt32960.go`。
> Config 结构体位置（计划）：`trafficgen/internal/core/types.go` 中的 `GBT32960Config`。
> 文档版本：v1.1.3（2026-08-03 三轮审计返工后；历史版本见附录 D）。
> 测试用例数：126 条（T-GBT-001~108，含 17 个子用例 a/b/c/d；v1.1.3 新增 T-GBT-048a 与 T-GBT-096a）。
> P6 M1 注记（2026-09-28，P6 关单主线程）：头注"126 条"已 stale——P6 实测 suite 116 例（70 正 + 46 负）；v1.2.0 design 正文在库内/工作树/backup 三处均不存在（P6 已核），v1.2.0/testcase 入库版本待另轮裁定，本轮不虚构 v2 内容（M1 open 维持）。
>
> 术语约定：本文档中所有英文标识符（field name、const name、JSON key）首次出现时在其后用括号标注中文解释，例如 `VIN`（车辆识别码，Vehicle Identification Number）。后续出现不再重复标注。

---

## 1. 协议概述

GB/T 32960（国标 32960）是中国电动汽车远程服务与管理系统（remote service and management system，车载终端 → 平台）的通讯协议标准，由三部分组成：

- GB/T 32960.1-2016 第1部分：总则
- GB/T 32960.2-2016 第2部分：车载终端
- GB/T 32960.3-2016 第3部分：通讯协议（本文档依据）

### 1.1 传输层

| 项目 | 取值 |
|------|------|
| 传输层协议 | TCP（Transmission Control Protocol，传输控制协议） |
| 默认端口 | 10020（可配，平台侧监听） |
| 业务方向 | 车载终端（client，上行）→ 平台（server，下行应答） |
| 加密 | 数据单元可选 RSA / AES128，仅做字段占位（见 §7.10） |
| 单流模型 | 一辆车一个 TCP 流，VIN 在流内唯一标识该车辆 |
| 多车模型 | M 辆车 → M 条独立 TCP 流，每条流有自己的 4-tuple（src_ip, dst_ip, src_port, dst_port） |

### 1.2 与 SIP / RTSP 的对比

GBT32960 与 SIP/RTSP 一样是「单 TCP 流承载多消息」的信令协议，但没有独立的 UDP 数据面——所有车辆数据（实时上报、报警、补报）都作为 GBT32960 报文在原 TCP 流上传输。这简化了实现：无需像 SIP/RTSP 那样管理 RTP 子流，但要求每条上行报文都有对应的平台下行确认（`0x0C` 平台确认）。

### 1.3 业务总览

GBT32960 定义了 12 个命令（command，命令单元）。下表同时标注 GB/T 32960.3-2016 章节号与表号以便溯源：

| 命令 | 代码 | 发起方 | 用途 | 规范条目 |
|------|------|--------|------|----------|
| 车辆登入 | 0x01 | 车辆 | 车辆首次连接平台时上报身份 | GB/T 32960.3-2016 §6.1 表 7 |
| 实时信息上报 | 0x02 | 车辆 | 周期上报车辆状态（典型 30s 一次） | GB/T 32960.3-2016 §6.2 表 7 |
| 补报信息上报 | 0x03 | 车辆 | 离线期间积压数据补传 | GB/T 32960.3-2016 §6.3 |
| 车辆登出 | 0x04 | 车辆 | 车辆主动断开前上报 | GB/T 32960.3-2016 §6.4 |
| 平台登入 | 0x05 | 平台 | 平台作为 client 登入上级平台（级联场景） | GB/T 32960.3-2016 §7.1 |
| 平台登出 | 0x06 | 平台 | 平台登出上级平台 | GB/T 32960.3-2016 §7.2 |
| 补发请求 | 0x07 | 平台 | 平台下发要求车辆补传某时间段数据 | GB/T 32960.3-2016 §7.3 |
| 控制命令 | 0x08 | 平台 | 平台下发远程控制（如远程熄火、解锁） | GB/T 32960.3-2016 §7.4 |
| 参数查询 | 0x09 | 平台 | 平台查询车辆终端参数 | GB/T 32960.3-2016 §7.5 |
| 参数设置 | 0x0A | 平台 | 平台设置车辆终端参数 | GB/T 32960.3-2016 §7.6 |
| 平台心跳 | 0x0B | 平台 | 保活，无业务数据 | GB/T 32960.3-2016 §7.7 |
| 平台确认 | 0x0C | 平台 | 对车辆上行报文的应答 | GB/T 32960.3-2016 §7.8 |

> 注：本设计采用「车载终端 → 平台」方向的车端命令标识 0x01-0x0C。规范允许平台侧报文使用 0x80 范围标识（如 0x80 平台心跳），但本设计 v1 在 vehicle 与 platform 两种 Role 下统一使用 0x01-0x0C 命令标识——vehicle 角色用 0x01/0x02/0x03/0x04，platform 角色用 0x05/0x06/0x0B。若与上级平台对接时遇到 0x80 心跳需求，可通过 Config 字段 `UseExtendedPlatformCmd=true` 切换（v2 实现）。

### 1.4 应答标志（response flag）

每个 GBT32960 报文的报文头中都携带 1 字节应答标志，语义分两类：

**上行报文（命令发起方）应答标志**：

| 值 | 含义 |
|----|------|
| 0xFE | 上行报文应答标志——命令发起方无需应答上一条 |

> 0xFE 是**所有上行报文**（vehicle→platform 或 platform→上级平台）的应答标志，因为上行报文是命令发起方，无需应答上一条收到的报文。这不仅仅是「首发报文」的规则——每条上行报文（包括 0x01 登入、0x02 上报、0x04 登出、0x05 平台登入、0x0B 平台心跳）的应答标志都填 0xFE。

**应答结果值（写入下一上行报文应答标志字段，**不**写入 0x0C 报文头/数据单元）**：

| 值 | 含义 |
|----|------|
| 0x01 | 成功 |
| 0x02 | 错误 |
| 0x03 | VIN 重复（VIN duplicated） |
| 0x04 | 命令不支持 |

> 重要：0x0C 平台确认报文本身是**下行报文**，其报文头应答标志字段恒填 0xFE（与所有命令发起方一致）。0x0C 数据单元 1 字节 = 所确认的上行命令单元（用于指明「确认哪条命令」，**不**承载成功/失败）。0x01/0x02/0x03/0x04 的成功/失败语义通过 0x0C 之后的**下一上行报文**应答标志字段承载。详见 §3.12。

---

## 2. 报文格式

### 2.1 报文整体结构

一条 GBT32960 报文（message）由「报文头 + 数据单元 + 校验码」三部分组成，作为 TCP payload 一次性投递（不分片；超过 MSS 时由 TCP 层分段，由 receiver 重组后再按起始符定位）。

```
+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
| 起始符  | 命令单元 | 应答标志 |  VIN   | 加密方式 | 数据长度 |  数据单元   | 校验码 |
| 2 字节  | 1 字节  | 1 字节  | 17 字节 | 1 字节  | 2 字节  | N 字节(可空) | 1 字节 |
+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
| 0x23   | cmd    | resp   | VIN[17]| enc    | len_hi len_lo | data[N]    | bcc    |
| 0x23   |        |        |        |        |               |            |        |
+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
```

总长度 = 2 + 1 + 1 + 17 + 1 + 2 + N + 1 = 25 + N 字节，其中 N 为数据单元长度。

### 2.2 各字段表

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 2 | 起始符（start flag） | 固定 `0x23 0x23`（ASCII `##`） |
| 2 | 1 | 命令单元（command unit） | 0x01-0x0C，见 §1.3 |
| 3 | 1 | 应答标志（response flag） | 上行报文恒 0xFE；下行 0x0C 报文头应答标志也恒 0xFE；0x01-0x04 应答结果语义承载在数据单元或下一上行报文，见 §1.4 |
| 4 | 17 | VIN（车辆识别码） | 17 字节 ASCII，不足补 `0x00`，见 §2.3 |
| 21 | 1 | 数据加密方式（encrypt rule） | 0x01=不加密 / 0x02=RSA / 0x03=AES128 / 0x04=SM2 / 0x05=SM4 |
| 22 | 2 | 数据单元长度（data length） | 大端（big-endian），单位字节，范围 0-65531（65532-65535 保留） |
| 24 | N | 数据单元（data unit） | N = 数据长度字段值；可为空（N=0，如平台心跳） |
| 24+N | 1 | 校验码（BCC） | 见 §2.4 |

### 2.3 VIN 编码

VIN 是 17 字节 ASCII 字符串，字符集为 GB/T 32960.3 规定的 VIN 字符集（不含 I/O/Q，详见 ISO 3779 与 GB 16735）。当实际 VIN 不足 17 字节时，**右侧补 `0x00`**（不是空格 `0x20`）；超过 17 字节时 Validate 报错（V2，不静默截断）。VIN 字段对于车辆侧报文必填；对于平台心跳（`0x0B`）等无车辆上下文的平台报文，使用「城市邮政编码 + VIN 前三位」或 17 字节全 `0x00`（由 Config 字段 `PlatformID` 控制，见 §3.5）。

> 设计取舍（VIN 补齐字符）：GB/T 32960.3-2016 规范对「不足 17 字节如何补齐」没有明确文字。工程实践中厂商普遍用 `0x00` 右补齐，Wireshark 的 gbt32960 解析器（`epan/dissectors/packet-gbt32960.c`）也按 `0x00` 处理。本设计 v1 默认 0x00，并通过 Config 字段 `VINPadByte`（默认 0x00，可选 0x20）允许用户切换以适配少数 0x20 平台。

### 2.4 BCC 校验算法

校验码（BCC，Block Check Character）采用异或校验，计算范围为「命令单元 + 应答标志 + VIN + 加密方式 + 数据长度 + 数据单元」（即偏移 2 到 24+N-1 的全部字节，**不含起始符**，**不含校验码自身**）。

算法伪代码（即 Go 实现应采用的等价逻辑）：

```go
// bccXOR computes BCC over buf, which MUST be the packet bytes from
// command unit (offset 2) through the last data-unit byte (offset
// 24+N-1). buf MUST NOT include the start flag (offset 0-1) nor the
// BCC byte itself. Callers typically pass buf[2:] of a packet that
// has not yet had BCC appended.
func bccXOR(buf []byte) byte {
    var sum byte = 0
    for _, b := range buf {
        sum ^= b
    }
    return sum
}

// Usage at build time:
//   full := append(headerAndData, bccXOR(headerAndData[2:]))
// headerAndData contains start flag + cmd + resp + VIN + enc + len + data
// (NO BCC byte). Slicing [2:] skips the start flag; the slice end is
// implicitly len(headerAndData), i.e. through the last data byte.
```

举例：车辆登入报文 `23 23 01 FE <VIN 17B> 01 <len_hi> <len_lo> <data...>`，BCC = 命令单元 `0x01` ^ 应答标志 `0xFE` ^ VIN 各字节 ^ 加密方式 `0x01` ^ len_hi ^ len_lo ^ data 各字节。BCC 字节本身**不**参与异或。

> 测试要点：BCC 范围是「不含起始符、不含 BCC」——这是最容易实现错误的点（错把起始符 `0x23 0x23` 算进去，或错把 BCC 自身也算进去）。§7.15 给出 BCC 注入错误用例，§8 至少 2 条用例专门校验 BCC 范围。

### 2.5 数据长度字段

`data length` 字段以大端编码，表示「数据单元」的字节数（**不含**报文头 24 字节、不含校验码 1 字节）。当命令无数据单元时（如平台心跳 `0x0B`），数据长度填 `0x00 0x00`。

长度上限：**65531 字节**（GB/T 32960.3-2016 规定的有效值范围 0-65531；65532-65535 是保留值，接收方将视为非法）。实际单条报文很少超过 1 KB；实时信息上报通常 100-300 字节，含定位 + 电池 + 电机等子项。本设计在 Validate 阶段对 CustomFields 解码后总数据单元长度做 ≤ 65531 校验（V28）。

---

## 3. 命令单元与数据单元

本节给出每个命令的数据单元格式。重点是车辆侧的 `0x01` / `0x02` / `0x04`，平台侧的 `0x0B` / `0x0C`，以及双向的 `0x08`。

### 3.1 0x01 车辆登入（vehicle login）

车辆建立 TCP 连接后第一条上行报文。数据单元格式依据 GB/T 32960.3-2016 §6.1 表 7：

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 6 | 登入时间（login time） | BCD 编码 `YYMMDDHHMMSS`，6 字节；例 2026-08-03 14:30:00 北京时间 → `26 08 03 14 30 00`。时区为 GMT+8，详见 §4.5 |
| 6 | 2 | 登入流水号（login serial number） | WORD（大端 uint16），每登入一次自动加 1，从 1 开始循环累加，最大值 65531，循环周期为天（每日 00:00 归 0） |
| 8 | 20 | ICCID/SIM 卡号（ICCID） | ASCII 字符串，不足右补 `0x00`，超长截断 |
| 28 | 1 | 可充电储能子系统数 n（rechargeable subsystem count） | BYTE，n ≥ 1 |
| 29 | 1 | 可充电储能系统编码长度 m（subsys code length） | BYTE，单位字节 |
| 30 | n×m | 可充电储能系统编码（subsys codes） | STRING，n 个子系统编码串联，每个 m 字节 |

数据单元总长 = 6 + 2 + 20 + 1 + 1 + n×m = 30 + n×m 字节。最简情形 n=1, m=1 时为 31 字节。登入后平台必须回 `0x0C` 平台确认（数据单元 1 字节回填 0x01 表示所确认的命令单元；成功/失败语义见 §3.12）。

> Config 字段映射：登入时间 ← `LoginTime`，登入流水号 ← `LoginSerialNumber`（uint16，1-65531），ICCID ← `SIM`，子系统数 ← `RechargeableSubsysCount`，编码长度 ← `RechargeableSubsysCodeLength`，编码 ← `RechargeableSubsysCodes`（string 数组，planner 按 m 截断/补齐后串联）。登入流水号默认值与回绕规则见 §4.5 与 §7.14。

### 3.2 0x02 实时信息上报（realtime report）

车辆周期上报（典型 30 秒/次）的报文。数据单元采用「采集时间 + (信息类型 + 信息体) 循环」结构，依据 GB/T 32960.3-2016 §6.2 表 7 与表 8。**没有**独立的流水号、报警标志、状态标志头部字段——报警与状态都作为信息类型下的信息体出现。

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 6 | 数据采集时间（collect time） | BCD 编码 `YYMMDDHHMMSS`，时区 GMT+8 |
| 6 | 1 | 信息类型标志(1)（info type 1） | BYTE，取值见下表 |
| 7 | L1 | 信息体(1)（info body 1） | 长度由信息类型决定，见下表 |
| ... | ... | ... | 信息类型/信息体可循环 N 次 |
| 6+ΣL | 1 | 信息类型标志(n) | BYTE |
| 7+ΣL | Ln | 信息体(n) | — |

> 规范明确：「实时数据报文的数据单元中，可以信息类型为单位进行任意拼装，但不得以数据项为单位进行拼装」。即每条信息体必须以完整信息类型出现，不能跨信息类型拼接字段。

**信息类型标志定义**（GB/T 32960.3-2016 表 8）：

| 信息类型 | 代码 | 信息体内容 | 信息体长度 |
|----------|------|------------|------------|
| 整车数据 | 0x01 | 状态 1B + 电荷 2B + 速度 2B + 累计里程 4B + 电压 2B + 电流 2B + SOC 1B + DC-DC 状态 1B + 档位 1B + 阻抗 2B | 18 |
| 驱动电机数据 | 0x02 | 计数 1B + (电机编号 1B + 状态 1B + 转速 2B + 转矩 2B + 温度 1B + 电压 2B + 电流 2B) × n | 1 + 11×n |
| 燃料电池数据 | 0x03 | 电压 2B + 电流 2B + 燃料消耗率 2B + 温度探针总数 n 1B + 探针温度 n×1B + 氢系统温度探针总数 m 1B + 氢系统温度 m×1B + 氢系统压力最高/次高 4B + 氢系统压力最低/次低 4B | 可变 |
| 发动机数据 | 0x04 | 状态 1B + 转速 2B + 燃料消耗率 2B | 5 |
| 车辆位置 | 0x05 | 定位状态 1B + 经度 4B(DWORD) + 纬度 4B(DWORD) | 9 |
| 极值数据 | 0x06 | 最高电压子系统编号 1B + 最高电压单体编号 2B + 最高电压 2B + 最低电压子系统编号 1B + 最低电压单体编号 2B + 最低电压 2B + 最高温度子系统编号 1B + 最高温度探针编号 1B + 最高温度 1B + 最低温度子系统编号 1B + 最低温度探针编号 1B + 最低温度 1B | 16 |
| 报警数据 | 0x07 | 最高报警等级 1B + 通用报警标志 4B | 5 |
| 可充电储能系统电压数据 | 0x08 | 计数 1B + (子系统编号 1B + 电压 2B) × n | 1 + 3×n |
| 可充电储能系统温度数据 | 0x09 | 计数 1B + (子系统编号 1B + 探针总数 1B + 各探针温度 1B × m) × n | 可变 |

> **重要修正**：车辆位置信息体（0x05）格式为「定位状态 1B + 经度 4B + 纬度 4B = 9 字节」，**不含速度**。速度属于整车数据（0x01）的信息体。原设计的「定位子项 type=0x05 + 经纬度 + 速度」混淆了 GBT32960 与 JT/T 808 位置基本报文格式（JT808 位置报文含速度），是错误的。

#### 3.2.1 报警数据信息体（信息类型 0x07）

报警数据作为信息类型 0x07 的信息体出现，**不**是 0x02 头部固定字段。信息体格式（GB/T 32960.3-2016 报警数据章节）：

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 1 | 最高报警等级（max alarm level） | 0=无报警 / 1=一级 / 2=二级 / 3=三级 |
| 1 | 4 | 通用报警标志（general alarm flags） | 32 位位域，大端，位定义见下表 |

**通用报警标志位域**（4 字节，大端，bit0 = 最低位）：

| 位 | 含义 | 1 表示 |
|----|------|--------|
| bit0 | 温度差异报警 | 是 |
| bit1 | 电池高温报警 | 是 |
| bit2 | 车载储能装置类型过压报警 | 是 |
| bit3 | 车载储能装置类型欠压报警 | 是 |
| bit4 | SOC 过低报警 | 是 |
| bit5 | 单体电压压差过大报警 | 是 |
| bit6 | 电池温差过大报警 | 是 |
| bit7 | 绝缘报警 | 是 |
| bit8 | DC-DC（直流变换器）故障报警 | 是 |
| bit9 | 制动系统报警 | 是 |
| bit10 | 驱动电机过温报警 | 是 |
| bit11 | 驱动电机过流报警 | 是 |
| bit12 | 驱动电机过压报警 | 是 |
| bit13 | 驱动电机短路报警 | 是 |
| bit14 | 充电插座温度报警 | 是 |
| bit15 | 动力电池一致性差报警 | 是 |
| bit16 | 充电完成报警 | 是 |
| bit17 | 充电故障报警 | 是 |
| bit18 | SOC 跳变报警 | 是 |
| bit19 | 热事件报警（修订草案新增） | 是 |
| bit20 | 车载储能装置类型过压（单体）报警 | 是 |
| bit21 | 车载储能装置类型欠压（单体）报警 | 是 |
| bit22 | 车载储能装置类型电压差异报警 | 是 |
| bit23 | 单体电压过高报警 | 是 |
| bit24 | 单体电压过低报警 | 是 |
| bit25 | 单体电压压差过大报警（单体） | 是 |
| bit26 | 电池组温差过大报警 | 是 |
| bit27 | 电池组温度过高报警 | 是 |
| bit28 | 电池组温度差异报警 | 是 |
| bit29 | 电池组温度过高报警（继电器） | 是 |
| bit30 | 电池组温度差异报警（继电器） | 是 |
| bit31 | 厂商自定义报警 | 是 |

> **重要修正**：原设计 §3.2.1 把 bit31 当作「电池高温」是错误的——规范规定 bit1 才是电池高温，bit31 是厂商自定义。位序与 Wireshark gbt32960 解析器一致（按大端字节序，最低字节的最低位为 bit0，即传统网络位序）。

> 工程取舍：`AlarmData` 在 Config 中以子结构提供（`MaxAlarmLevel` uint8 + `GeneralAlarmFlags` 32B hex 字符串）。planner 写入时直接按 5 字节拼接（1B 等级 + 4B 大端标志）。位级语义由用户负责，planner 仅做范围校验（见 §4.4 V8/V9）。

#### 3.2.2 状态字段说明

GB/T 32960.3-2016 实时上报数据单元**没有**独立的「状态标志」2 字节头部字段。状态信息分布在以下信息体中：

- 整车数据（信息类型 0x01）信息体首字节「状态」含车辆状态、充电状态、运行模式、车辆模式、绝缘状态等位（具体位定义见规范表 8 整车数据章节）
- 车辆位置（信息类型 0x05）信息体首字节「定位状态」含定位是否有效

> **重要修正**：原设计 §3.2.2 的「状态标志位域（bit15 车辆状态/bit14 充电状态/bit13 运行模式/...）」是 JT/T 808 位置基本报文的状态 DWORD 误植到 GBT32960。GBT32960 不存在此头部字段。Config 字段 `StatusFlags` 已删除（见 §4.1）。

#### 3.2.3 子数据项（信息体）处理

GB/T 32960.3 规定信息体以「信息类型标志 + 信息体」串联。本设计支持两种方式填充 0x02 数据单元的信息体部分：

1. **CustomFields 原始 hex**：用户通过 Config 字段 `CustomFields` 提供完整的信息体序列（即「信息类型 1B + 信息体」循环的原始字节 hex），planner 原样拼接在采集时间之后。此方式下 planner 不解析、不验证信息体内部结构（仅做 hex 合法性校验 V26）。**IsTransBatteryData 字段在此方式下不生效**（因为用户已显式提供完整信息体序列）。
2. **AlarmData 自动展开**：当 `CustomFields` 为空但 `AlarmData` 非空时，planner 自动生成一条信息类型 0x07 报警信息体（5 字节）。若 `IsTransBatteryData=true`（默认），额外追加一条 0x01 整车数据信息体（18B 零值）；若 `IsTransBatteryData=false`，额外追加一条 0x05 车辆位置信息体（9B 零值）。
3. **最小有效信息体**：当 `CustomFields` 与 `AlarmData` 均空时，planner 根据 `IsTransBatteryData` 选择默认信息体：
   - `IsTransBatteryData=true`（默认）：输出整车数据信息类型 0x01 + 18 字节零值信息体（与 §3.2 信息类型表一致）。
   - `IsTransBatteryData=false`：仅输出车辆位置信息类型 0x05 + 9 字节零值信息体（定位状态 1B + 经度 4B + 纬度 4B），**不**输出 0x01/0x08/0x09 等电池相关数据信息体。

> 注：本设计 v1 不实现所有信息类型的完整字段填充——作为流量生成器，目标是产生「格式合法、字段填充合理」的报文，而非语义完整的车辆模型。需要复杂信息体（如电机数据、极值数据）时，用户应通过 `CustomFields` 提供。

### 3.3 0x03 补报信息上报（reissue report）

数据单元格式与 `0x02` 实时上报完全相同；区别仅在于命令单元字段填 `0x03`，且报文中通常携带多条历史数据（每条独立成报文，但流水号不连续）。本设计中 `0x03` 由 `reissue_reports` Config 字段触发（见 §7.9）。

### 3.4 0x04 车辆登出（vehicle logout）

数据单元格式（GB/T 32960.3-2016 §6.4）：

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 6 | 登出时间（logout time） | BCD 编码 `YYMMDDHHMMSS` |
| 6 | 2 | 登入流水号（login serial number） | WORD 大端，与当次登入流水号一致 |

数据单元总长 **8 字节**（非原设计的 6 字节）。「登出流水号与当次登入流水号一致」是规范要求——平台通过此字段将登出与登入关联。若 `LogoutSerialNumber` 为空（默认），planner 自动使用 `LoginSerialNumber` 的值。登出后平台回 `0x0C`，然后双方进入 TCP 挥手。

### 3.5 0x05 平台登入（platform login）

平台作为 client 登入上级平台（级联场景）。数据单元格式（GB/T 32960.3-2016 §7.1）：

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 12 | 平台用户名（user） | ASCII 字符串，不足右补 `0x00` |
| 12 | 20 | 平台密码（password） | ASCII 字符串，不足右补 `0x00` |
| 32 | 16 | 加密密钥版本号（encrypt key version） | ASCII 字符串，标识加密密钥的版本/序号 |

数据单元总长 48 字节。VIN 字段（唯一识别码）对平台报文使用「城市邮政编码 + VIN 前三位」（或用户通过 Config 字段 `PlatformID` 自定义 17 字节字符串），**不是**全 0x00。若 `PlatformID` 未配置，默认填 17 字节 `0x00`（到上级平台可能被拒绝——用户需提供正确 PlatformID）。

### 3.6 0x06 平台登出（platform logout）

无数据单元（N=0）。VIN 全 `0x00`。

### 3.7 0x07 补发请求（reissue request，平台 → 车辆）

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 6 | 起始时间 | BCD `YYMMDDHHMMSS` |
| 6 | 6 | 结束时间 | BCD `YYMMDDHHMMSS` |

### 3.8 0x08 控制命令（control command，平台 → 车辆）

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 1 | 控制类型 | 0x01=远程熄火 / 0x02=远程解锁 / ... |
| 1 | N | 命令参数 | 厂商自定义 |

车辆收到后回 `0x0C`，应答标志按执行结果填 `0x01`/`0x02`。

### 3.9 0x09 参数查询（parameter query，平台 → 车辆）

数据单元为 1 字节参数类型（如 0x01=终端参数 / 0x02=车辆参数）。车辆回 `0x0C` 时数据单元携带查询结果。

### 3.10 0x0A 参数设置（parameter set，平台 → 车辆）

数据单元为 1 字节参数类型 + 参数数据。车辆回 `0x0C` 应答。

### 3.11 0x0B 平台心跳（platform heartbeat）

无数据单元（N=0）。VIN 字段：若 Role="platform" 且配置了 `PlatformID`，使用 PlatformID 填充；否则全 `0x00`。命令单元 `0x0B`，应答标志 `0xFE`（上行报文）。

加密方式字段：继承 PlatformLogin 配置（即 `EncryptRule` 解析后的值，与 0x05 平台登入一致）。若用户希望心跳使用不同加密方式，可通过 Config 字段 `HeartbeatEncryptRule` 单独指定（v2 实现），v1 直接复用顶层 `EncryptRule`。

### 3.12 0x0C 平台确认（platform acknowledgement）

0x0C 是**下行**报文（平台 → 车辆），其报文头应答标志字段恒填 `0xFE`（与所有命令发起方一致，下行报文无需应答上一条）。

> **规范依据**（GB/T 32960.3-2016 §7.8 平台确认）：规范要求 0x0C 报文头应答标志字段由应答发起方填写。由于 0x0C 是平台对车辆上行报文的应答，0x0C 本身即为新的「命令发起方」，应答标志恒为 `0xFE`。规范不允许 0x0C 报文头应答标志字段填 `0x01`-`0x04`——这些值仅出现在车辆侧上行的应答标志字段中，且每次仅能填一个值（0x01=成功/0x02=错误/0x03=VIN重复/0x04=命令不支持）。**本设计严格遵循此约束**，所有 0x0C 报文头 resp=0xFE（已在 T-GBT-011/013/014b/015/016/017/018 等多条用例中验证）。

0x0C 数据单元 1 字节，对所确认的上行报文的命令单元原样回填。例如对 `0x01` 车辆登入的确认，0x0C 数据单元为 `0x01`。

成功/失败语义的承载方式（GB/T 32960.3-2016 应答机制）：
- 0x0C 报文头应答标志恒 0xFE（**不**通过此字段承载成功/失败）
- 0x0C 数据单元 1 字节**总是等于所确认的上行命令单元**（无论成功还是失败），如对 0x01 车辆登入的确认，无论成功/失败数据单元都是 `0x01`，仅用于指明「确认哪条命令」
- 成功/失败语义**不**通过 0x0C 数据单元承载，而是通过**下一上行报文**（0x01 重发、0x02 上报、0x04 登出等）的应答标志字段 0x01-0x04 承载（0x01=成功 / 0x02=错误 / 0x03=VIN 重复 / 0x04=命令不支持）；也可通过独立应答报文承载
- 本设计 v1 简化：通过 Config 字段 `ResponseFlags`（"01"/"02"/"03"/"04"）控制**下一上行报文**的应答标志字段值，模拟平台对上一条上行报文的应答结果。具体见 §7.13。

> **重要修正**：原设计把 0x0C 报文头应答标志字段用作「成功/失败」语义是错误的。0x0C 报文头应答标志恒 0xFE，成功/失败语义通过其他机制承载。所有 T-GBT-015/016/017/018 用例已重写为「下一上行报文应答标志」断言。

---

## 4. Config 结构体设计

本节定义 `GBT32960Config` 结构体及其子结构。字段命名遵循项目现有风格（snake_case JSON tag，驼峰 Go 字段名），注释沿用「英文标识符 + 中文解释」风格。

### 4.1 GBT32960Config 主结构

```go
// GBT32960Config configures the GBT32960 protocol (GB/T 32960.3-2016
// 电动汽车远程服务与管理系统技术规范 第3部分：通讯协议). It is
// attached to FlowSpec.GBT32960; the internal/protocol/gbt32960 planner
// emits a TCP handshake, a sequence of GBT32960 messages (each as one
// PSH-ACK payload), and a TCP teardown — all within one flow.
//
// A single GBT32960 flow models ONE vehicle (or one platform-as-client
// session). Multi-vehicle scenarios use multiple FlowSpecs, each with a
// unique VIN and a distinct 4-tuple (see §7.11).
type GBT32960Config struct {
    // Role (角色) selects the side: "vehicle" (default) or "platform".
    // vehicle = 车载终端 side (上行 0x01/0x02/0x03/0x04);
    // platform = 平台侧作为 client 登入上级平台 (0x05/0x06/0x0B).
    Role string `json:"role,omitempty"`

    // VIN (车辆识别码, Vehicle Identification Number) — 17-byte ASCII.
    // Shorter values are right-padded with VINPadByte (default 0x00);
    // longer values trigger V2 error (no silent truncation).
    // Required when Role="vehicle"; for Role="platform", use PlatformID.
    // Charset: I/O/Q not allowed (V3b).
    VIN string `json:"vin,omitempty"`

    // VINPadByte (VIN 补齐字节) — byte used to right-pad VIN shorter
    // than 17 bytes. Default 0x00; 0x20 supported for some platforms.
    VINPadByte *byte `json:"vin_pad_byte,omitempty"`

    // SIM (车辆 SIM 号 / ICCID) — up to 20-byte ASCII. Right-padded with 0x00.
    // Used as the ICCID field of 0x01 vehicle login data unit.
    SIM string `json:"sim,omitempty"`

    // EncryptRule (数据加密方式): "01"=不加密 (default), "02"=RSA,
    // "03"=AES128, "04"=SM2, "05"=SM4. Only the field value is emitted;
    // the planner does NOT actually encrypt the data unit (see §7.10).
    // User supplies already-encrypted bytes via CustomFields when
    // EncryptRule != "01". BCC is always computed over the final
    // (ciphertext) data unit bytes regardless of EncryptRule (§7.10).
    EncryptRule string `json:"encrypt_rule,omitempty"`

    // LoginSerialNumber (登入流水号) — uint16, range 1-65531. Per-spec
    // it auto-increments per login, wraps to 1 at 65531, and resets to
    // 0 daily at 00:00 (GMT+8). Default = 1.
    LoginSerialNumber int `json:"login_serial_number,omitempty"`

    // LogoutSerialNumber (登出流水号) — uint16, range 1-65531. Per spec
    // must equal the LoginSerialNumber of the same session. Empty (0) =
    // planner uses LoginSerialNumber automatically.
    LogoutSerialNumber int `json:"logout_serial_number,omitempty"`

    // RechargeableSubsysCount (可充电储能子系统数 n) — n >= 1.
    // Default 1. Used in 0x01 vehicle login data unit.
    RechargeableSubsysCount int `json:"rechargeable_subsys_count,omitempty"`

    // RechargeableSubsysCodeLength (可充电储能系统编码长度 m) — m >= 1.
    // Default 1. Each subsystem code is m bytes.
    RechargeableSubsysCodeLength int `json:"rechargeable_subsys_code_length,omitempty"`

    // RechargeableSubsysCodes (可充电储能系统编码) — string slice, length
    // must equal RechargeableSubsysCount. Each entry is right-padded or
    // truncated to m bytes. Empty = all zeros.
    RechargeableSubsysCodes []string `json:"rechargeable_subsys_codes,omitempty"`

    // LoginTime (登入时间) — RFC3339 string (timezone required, e.g.
    // "2026-08-03T14:30:00+08:00"). Planner converts to BCD
    // YYMMDDHHMMSS in the SAME timezone as the input. Empty = use
    // time.Now() in local timezone (documented as GMT+8).
    LoginTime string `json:"login_time,omitempty"`

    // LogoutTime (登出时间) — same format as LoginTime. Empty = LoginTime
    // plus Reports duration (or LoginTime + 60s default).
    LogoutTime string `json:"logout_time,omitempty"`

    // Reports (实时上报序列) — list of realtime report entries. Each
    // entry produces one 0x02 message. The planner auto-fills collect
    // time (per-entry Time, or sequential 30s stamps when Time empty).
    // NOTE: 0x02 has no per-report serial field in spec (serial is the
    // 0x01 LoginSerialNumber + a daily counter; 0x02 data unit is
    // collect time + info-type loop). The Serial field is deprecated,
    // use ReportTime for ordering. V14 range check (1-65531) applies
    // only to the 0x01 LoginSerialNumber field.
    Reports []GBT32960Report `json:"reports,omitempty"`

    // ReissueReports (补报序列) — list of entries to send as 0x03.
    // Each entry has the same structure as Reports. See §7.9.
    ReissueReports []GBT32960Report `json:"reissue_reports,omitempty"`

    // AlarmData (报警数据) — when set, planner emits one info-type 0x07
    // info body in the next 0x02 message that does not set its own
    // AlarmData. Replaces the old AlarmFlags field. See §3.2.1.
    AlarmData *GBT32960AlarmData `json:"alarm_data,omitempty"`

    // RemoteControl (远程控制响应) — when set, planner emits 0x08 from
    // platform → vehicle, then 0x0C acknowledgement from vehicle.
    // See §7.4.
    RemoteControl *GBT32960RemoteControl `json:"remote_control,omitempty"`

    // PlatformLogin (平台登入) — when Role="platform", planner emits
    // 0x05 → 0x0C → 0x0B × N → 0x06. See §7.6.
    PlatformLogin *GBT32960PlatformLogin `json:"platform_login,omitempty"`

    // PlatformID (平台唯一识别码) — 17-byte ASCII used as the VIN field
    // of platform-side messages (0x05/0x06/0x0B). Convention:
    // "城市邮政编码 + VIN前三位" or user-defined 17-byte string.
    // Required when Role="platform"; empty = 17 bytes of 0x00 (may be
    // rejected by upstream platform).
    PlatformID string `json:"platform_id,omitempty"`

    // PlatformDomain (平台域名) — domain identifier for the platform
    // (扩展表 1 字段). Stored for logging/extension purposes; not
    // directly emitted in 0x05 data unit (v1). Default empty.
    PlatformDomain string `json:"platform_domain,omitempty"`

    // SetPlatformDomain (设置平台域名) — target domain to set via
    // 0x0A 参数设置 command (扩展表 1 字段). Empty = not set.
    SetPlatformDomain string `json:"set_platform_domain,omitempty"`

    // ConnectID (连接 ID) — unique connection identifier for
    // cross-layer correlation (扩展表 1 字段). Empty = planner
    // auto-generates from 4-tuple hash.
    ConnectID string `json:"connect_id,omitempty"`

    // IsTransBatteryData (是否传输电池数据) — bool flag controlling
    // whether battery-related info bodies (0x01 整车, 0x08 电压,
    // 0x09 温度) are emitted. Default true. When false, planner emits
    // only vehicle-position info body (0x05).
    IsTransBatteryData *bool `json:"is_trans_battery_data,omitempty"`

    // HeartbeatCount (心跳次数) — number of 0x0B messages to emit.
    // 0 = no heartbeat. Applies only when Role="platform".
    HeartbeatCount int `json:"heartbeat_count,omitempty"`

    // ResponseFlags (应答标志) — overrides the default 0xFE on the
    // NEXT UPLINK message's response-flag field, to simulate the
    // platform's acknowledgement result for the PREVIOUS uplink
    // message. Use "01"/"02"/"03"/"04" (see §3.12 and §7.13). Empty =
    // 0xFE (normal uplink behavior).
    ResponseFlags string `json:"response_flags,omitempty"`

    // StatusChangeTrace (状态变更记录) — JSON array of status snapshots
    // to apply sequentially across Reports. Each entry overrides the
    // matching fields of the next unprocessed Report. See §7.12.
    StatusChangeTrace []GBT32960StatusChange `json:"status_change_trace,omitempty"`

    // CustomFields (自定义信息体) — raw hex string for the info-body
    // portion of 0x02/0x03 data unit (i.e. the "info type + info body"
    // repeated loop). When empty, planner emits a minimal valid
    // info body (整车数据 0x01 + 18 zero bytes). See §3.2.3.
    CustomFields string `json:"custom_fields,omitempty"`

    // InjectBCCError (注入 BCC 错误) — when true, the planner flips one
    // bit of the BCC byte on the Nth message (BCCErrorIndex). Used for
    // §7.15 data integrity tests.
    InjectBCCError bool `json:"inject_bcc_error,omitempty"`

    // BCCErrorIndex (BCC 错误注入索引) — 0-based index into the
    // message sequence. 0 = the first GBT32960 message. Only effective
    // when InjectBCCError=true. Out-of-range triggers V24 error
    // (computed at Plan time, see §4.4).
    BCCErrorIndex int `json:"bcc_error_index,omitempty"`
}
```

### 4.2 GBT32960Report 子结构

```go
// GBT32960Report is a single realtime or reissue report entry. The
// planner emits one 0x02 message per entry (0x03 when in
// ReissueReports). Time defaults to auto-generated sequential stamps.
type GBT32960Report struct {
    // Time (采集时间) — RFC3339 (timezone required). Empty =
    // auto-sequence (previous + 30s, or LoginTime + 30s for first).
    Time string `json:"time,omitempty"`

    // AlarmData (报警数据) — overrides Config.AlarmData for this
    // entry. Empty = inherit from Config.
    AlarmData *GBT32960AlarmData `json:"alarm_data,omitempty"`

    // CustomFields (自定义信息体) — overrides Config.CustomFields.
    CustomFields string `json:"custom_fields,omitempty"`
}

// GBT32960AlarmData models the info-type 0x07 alarm data info body.
type GBT32960AlarmData struct {
    // MaxAlarmLevel (最高报警等级) — 0=无/1=一级/2=二级/3=三级.
    MaxAlarmLevel uint8 `json:"max_alarm_level"`

    // GeneralAlarmFlags (通用报警标志) — 32-bit big-endian, exactly
    // 8 hex chars (e.g. "00000002" for bit1 电池高温). See §3.2.1.
    GeneralAlarmFlags string `json:"general_alarm_flags"`
}
```

### 4.3 辅助子结构

```go
// GBT32960RemoteControl models the 0x08 control command exchange.
type GBT32960RemoteControl struct {
    // ControlType (控制类型): 0x01=远程熄火, 0x02=远程解锁, etc.
    ControlType uint8 `json:"control_type"`

    // Params (命令参数) — raw hex string, appended after ControlType.
    Params string `json:"params,omitempty"`

    // ResponseFlags (应答标志) — vehicle's response: "01"=success,
    // "02"=error, "04"=unsupported. Default "01". Applied to the
    // next uplink message's response-flag field (see §3.12).
    ResponseFlags string `json:"response_flags,omitempty"`
}

// GBT32960PlatformLogin models the 0x05 platform-as-client login.
type GBT32960PlatformLogin struct {
    User       string `json:"user"`                  // 12-byte ASCII
    Password   string `json:"password"`              // 20-byte ASCII
    EncryptSeq string `json:"encrypt_seq,omitempty"` // 16-byte ASCII (key version)
}

// GBT32960StatusChange is one entry in StatusChangeTrace. When the
// planner processes Reports, each entry first applies the trace's next
// snapshot, then applies per-report overrides. Fields empty in the
// snapshot are left unchanged.
type GBT32960StatusChange struct {
    AtReportIndex int                  `json:"at_report_index"` // 0-based index into Reports; must be unique
    AlarmData     *GBT32960AlarmData   `json:"alarm_data,omitempty"`
    CustomFields  string               `json:"custom_fields,omitempty"`
}
```

### 4.4 Validate 规则（planner 必须执行的字段校验）

`Planner.Validate(spec core.FlowSpec) error` 必须覆盖以下规则。每条规则对应 §8 至少一条测试用例：

| 规则 | 触发条件 | 错误消息 |
|------|----------|----------|
| V1 | Role 非 "vehicle"/"platform"/"" | `gbt32960: invalid Role %q` |
| V2 | Role="vehicle" 且 VIN 长度 > 17 | `gbt32960: VIN length %d exceeds 17` |
| V3 | Role="vehicle" 且 VIN 含非 ASCII 字符（任一字节 > 0x7F） | `gbt32960: VIN contains non-ASCII byte 0x%02x at offset %d` |
| V3b | Role="vehicle" 且 VIN 含 I/O/Q 字符 | `gbt32960: VIN contains invalid char %q at offset %d (I/O/Q not allowed)` |
| V4 | Role="vehicle" 且 VIN 为空字符串 | `gbt32960: VIN is required when Role=vehicle` |
| V5 | SIM 长度 > 20 | `gbt32960: SIM length %d exceeds 20` |
| V6 | EncryptRule 非 "01"/"02"/"03"/"04"/"05"/"" | `gbt32960: invalid EncryptRule %q` |
| V7 | LoginSerialNumber < 1 或 > 65531 | `gbt32960: LoginSerialNumber %d out of range [1,65531]` |
| V7b | LogoutSerialNumber < 0 或 > 65531（0 = inherit） | `gbt32960: LogoutSerialNumber %d out of range [0,65531]` |
| V8 | AlarmData.GeneralAlarmFlags 非恰好 8 位 hex | `gbt32960: invalid GeneralAlarmFlags %q (expect 8 hex chars)` |
| V9 | （防御性，正常情况下 V8 已覆盖）AlarmFlags 解析后 > 0xFFFFFFFF | `gbt32960: GeneralAlarmFlags %q exceeds 32-bit range` |
| V10 | （已删除：StatusFlags 字段已移除） | — |
| V11 | （已删除：StatusFlags 字段已移除） | — |
| V12 | LoginTime 非 RFC3339 且非空（强制时区） | `gbt32960: invalid LoginTime %q (expect RFC3339 with timezone)` |
| V12b | LoginTime 时间字段范围非法（月 1-12 等） | `gbt32960: LoginTime %q has out-of-range component` |
| V13 | LogoutTime 同 V12 | `gbt32960: invalid LogoutTime %q` |
| V14 | （已弱化：0x02 数据单元无独立流水号字段） | — |
| V15 | Reports[i].AlarmData 同 V8/V9 | 同上，附 `Reports[%d].` 前缀 |
| V16 | RemoteControl.ControlType = 0 | `gbt32960: RemoteControl.ControlType is required` |
| V17 | RemoteControl.ResponseFlags 非 "01"/"02"/"04"/"" | `gbt32960: invalid RemoteControl.ResponseFlags %q` |
| V18 | PlatformLogin.User 长度 > 12 | `gbt32960: PlatformLogin.User length %d exceeds 12` |
| V19 | PlatformLogin.Password 长度 > 20 | `gbt32960: PlatformLogin.Password length %d exceeds 20` |
| V20 | PlatformLogin.EncryptSeq 长度 > 16 | `gbt32960: PlatformLogin.EncryptSeq length %d exceeds 16` |
| V21 | HeartbeatCount < 0 | `gbt32960: HeartbeatCount %d must be non-negative` |
| V22 | ResponseFlags 非 "01"/"02"/"03"/"04"/"" | `gbt32960: invalid ResponseFlags %q` |
| V23 | InjectBCCError=true 且 BCCErrorIndex < 0 | `gbt32960: BCCErrorIndex %d must be non-negative` |
| V24 | InjectBCCError=true 且 BCCErrorIndex 超出实际消息数（Plan 阶段检查） | `gbt32960: BCCErrorIndex %d exceeds message count %d` |
| V25 | StatusChangeTrace[i].AtReportIndex 越界 或 重复 | `gbt32960: StatusChangeTrace[%d].AtReportIndex %d out of range or duplicated` |
| V26 | CustomFields 非 even-length hex 字符串 | `gbt32960: invalid CustomFields %q (expect even-length hex)` |
| V27 | spec.TCP.MSS < MinMSS(536) | `gbt32960: TCP.MSS %d too small (min %d)` |
| V28 | 数据单元长度（CustomFields 解码后 + 信息体头部）> 65531 | `gbt32960: data unit length %d exceeds 65531` |
| V29 | len(CustomFields 解码) + 24 + 6 + 1 > spec.TCP.MSS（即 CustomFields + 31 > MSS，含 6 字节采集时间） | `gbt32960: CustomFields length %d exceeds MSS-31 budget %d` |
| V30 | RechargeableSubsysCount < 1 | `gbt32960: RechargeableSubsysCount %d must be >= 1` |
| V31 | len(RechargeableSubsysCodes) != RechargeableSubsysCount | `gbt32960: RechargeableSubsysCodes length %d != count %d` |
| V32 | AlarmData.MaxAlarmLevel > 3 | `gbt32960: MaxAlarmLevel %d out of range [0,3]` |
| V33 | PlatformID 长度 > 17（Role="platform"） | `gbt32960: PlatformID length %d exceeds 17` |
| V34 | LogoutTime < LoginTime（两者均已配置且非空） | `gbt32960: LogoutTime %q must be >= LoginTime %q` |
| V35 | RechargeableSubsysCodeLength < 1 | `gbt32960: RechargeableSubsysCodeLength %d must be >= 1` |

> 注：V4「VIN 为空时报错」是默认行为。当 `Role="platform"` 时 VIN 可为空（V4 不触发），改用 PlatformID。这与 §2.3 中「平台报文使用 PlatformID 作为唯一识别码」一致。

### 4.5 默认值与归一化（Plan 阶段）

`Planner.Plan` 在生成前对若干字段做默认化（design §5 S1: user > auto > none 原则，与 socks5/sip 一致）：

| 字段 | 空值时默认 |
|------|------------|
| Role | "vehicle" |
| EncryptRule | "01" |
| VINPadByte | 0x00 |
| LoginSerialNumber | 1 |
| LogoutSerialNumber | LoginSerialNumber（规范要求登出流水号 = 登入流水号） |
| RechargeableSubsysCount | 1 |
| RechargeableSubsysCodeLength | 1 |
| RechargeableSubsysCodes | 全零（每项 m 字节 0x00） |
| LoginTime | time.Now()，时区为本地时区（应文档化为 GMT+8） |
| LogoutTime | LoginTime + Σ(Reports 间隔) + 60s；无 Reports 时 LoginTime + 60s |
| Reports[i].Time | 第 i 条 = LoginTime + 30s × (i+1) |
| Reports[i].AlarmData | 三步覆盖：(1) 继承 Config.AlarmData；(2) StatusChangeTrace 中 AtReportIndex==i 的条目覆盖；(3) Reports[i].AlarmData 自身非空则最终覆盖（user > trace > auto > none，与 §7.12 一致） |
| Reports[i].CustomFields | 三步覆盖：(1) 继承 Config.CustomFields；(2) StatusChangeTrace 中 AtReportIndex==i 的条目覆盖；(3) Reports[i].CustomFields 自身非空则最终覆盖（与 §7.12 一致） |
| RemoteControl.ResponseFlags | "01" |
| HeartbeatCount | 0（不产生心跳） |
| ResponseFlags | ""（即 0xFE，正常上行） |
| IsTransBatteryData | true |
| ConnectID | 由 4-tuple 哈希生成的 16 字节 hex |
| PlatformDomain | 空（仅日志用） |

> 时区规则：LoginTime/LogoutTime/Report.Time 字符串必须带时区（RFC3339，如 `+08:00` 或 `Z`）。planner 转换为 BCD 时**保留输入时区**——例如 `2026-08-03T14:30:00+08:00` → `26 08 03 14 30 00`（即北京时间 14:30）。空值时使用 `time.Now()` 的本地时区（运行环境应配置为 GMT+8）。

---

## 5. 状态机

### 5.1 车辆侧状态机（Role="vehicle"）

```
                                  TCP 握手 (SYN, SYN-ACK, ACK)
                                            │
                                            ▼
                              ┌──────────────────────────┐
                              │      ST_LOGIN_SENT       │
                              │  emit 0x01 (vehicle      │
                              │  login) up               │
                              └──────────────────────────┘
                                            │
                                            ▼
                              ┌──────────────────────────┐
                              │   ST_LOGIN_ACKED         │
                              │  expect 0x0C down        │
                              │  (resp=01 success)       │
                              └──────────────────────────┘
                                            │
                            ┌───────────────┴───────────────┐
                            │                               │
                            ▼                               ▼
              ┌──────────────────────────┐   ┌──────────────────────────┐
              │   ST_REPORTING           │   │   ST_REMOTE_CTRL         │
              │   for each Report:       │   │   0x08 down (control)    │
              │     emit 0x02 up         │   │   0x0C up (resp)         │
              │     emit 0x0C down       │   └──────────────────────────┘
              │     (resp=01)            │
              └──────────────────────────┘
                            │
                            ▼
              ┌──────────────────────────┐
              │   ST_REISSUE             │
              │   for each ReissueReport:│
              │     emit 0x03 up         │
              │     emit 0x0C down       │
              └──────────────────────────┘
                            │
                            ▼
              ┌──────────────────────────┐
              │   ST_LOGOUT_SENT         │
              │   emit 0x04 up           │
              │   expect 0x0C down       │
              └──────────────────────────┘
                            │
                            ▼
                                  TCP 挥手 (FIN, FIN-ACK, ACK)
```

**状态转换说明：**

1. `ST_LOGIN_SENT → ST_LOGIN_ACKED`：发出 `0x01` 后立即转入（planner 不等待真实 ACK，直接生成 `0x0C` 应答报文作为下一条 PSH-ACK）。
2. `ST_LOGIN_ACKED → ST_REPORTING`：若 `Reports` 非空，进入上报循环；否则跳过。
3. `ST_REPORTING → ST_REMOTE_CTRL`：若 `RemoteControl` 配置非空，则在所有 Reports 之后插入一次控制命令交互。也可在 Reports 中间插入（由 `RemoteControl.AtReportIndex` 控制，本设计 v1 仅支持末尾插入）。
4. `ST_REPORTING → ST_REISSUE`：若 `ReissueReports` 非空，进入补报循环。
5. `ST_REISSUE → ST_LOGOUT_SENT`：补报完成后登出。
6. `ST_LOGOUT_SENT → TCP teardown`：登出确认后立即进入 TCP 四次挥手。

**状态顺序约束**（重要）：`ST_REPORTING`、`ST_REMOTE_CTRL`、`ST_REISSUE` 三个业务状态的执行顺序固定为 **ST_REPORTING → ST_REMOTE_CTRL → ST_REISSUE → ST_LOGOUT_SENT**。即：

- `ST_REPORTING`（实时上报 0x02）始终最先执行（若 Reports 非空）
- `ST_REMOTE_CTRL`（远程控制 0x08/0x0C 交互）在所有 Reports 完成后执行（若 RemoteControl 非空）
- `ST_REISSUE`（补报 0x03）在 RemoteControl 之后执行（若 ReissueReports 非空）
- 三个状态中任意一个的触发条件不满足时跳过该状态，但**不**改变其余状态的相对顺序

> 状态机图中 ST_REPORTING 与 ST_REMOTE_CTRL 并列分支仅为「同属业务阶段」的图示简化，**不**表示两者可任意交换顺序。v1 不支持 RemoteControl 在 Reports 中间插入或 ReissueReports 在 Reports 之前插入。

### 5.2 平台侧状态机（Role="platform"）

```
                                  TCP 握手
                                            │
                                            ▼
                              ┌──────────────────────────┐
                              │   ST_PLAT_LOGIN_SENT     │
                              │   emit 0x05 up           │
                              └──────────────────────────┘
                                            │
                                            ▼
                              ┌──────────────────────────┐
                              │   ST_PLAT_LOGIN_ACKED    │
                              │   expect 0x0C down       │
                              └──────────────────────────┘
                                            │
                            ┌───────────────┴───────────────┐
                            │                               │
                            ▼                               ▼
              ┌──────────────────────────┐   ┌──────────────────────────┐
              │   ST_HEARTBEAT           │   │   ST_LOGOUT              │
              │   emit 0x0B up × N       │   │   emit 0x06 up           │
              │   (no resp expected)     │   │   expect 0x0C down       │
              └──────────────────────────┘   └──────────────────────────┘
                            │                               │
                            └───────────────────────────────┘
                                            │
                                            ▼
                                  TCP 挥手
```

### 5.3 异常分支

| 状态 | 异常 | planner 行为 |
|------|------|--------------|
| ST_LOGIN_ACKED | ResponseFlags=02（错误） | 仍生成 0x0C 报文（0x0C 报文头 resp=0xFE，下一上行 0x04 报文 resp=0x02 模拟失败）；不进入 ST_REPORTING，直接转 ST_LOGOUT_SENT |
| ST_LOGIN_ACKED | ResponseFlags=03（VIN 重复） | 平台拒绝该车辆登入——车辆侧**不**主动登出（车辆主动发 0x04 在 VIN 重复场景下无意义，因为平台认为这辆车已在线）。planner 行为：等待 TCP 关闭（生成 0x01 重试报文可选，v1 不实现），直接转 TCP teardown。Config 字段 `ResponseFlags="03"` 时 planner 仅生成登入 + 登入 ACK（resp 模拟）+ TCP 挥手，无 0x04 登出 |
| ST_LOGIN_ACKED | ResponseFlags=04（命令不支持） | 同 resp=02 路径，转 ST_LOGOUT_SENT |
| ST_REPORTING | Reports[i].AlarmData 非空（最高报警） | 正常生成 0x02 含信息类型 0x07 报警信息体，不改变状态机路径（报警上报不单独成状态，见 §7.3） |
| ST_LOGOUT_SENT | resp=02（登出失败） | 仍进入 TCP teardown（不重试，与真实终端行为一致） |

> 注：ResponseFlags 在 §3.12 修正后，**不**写入 0x0C 报文头（0x0C 报文头 resp 恒 0xFE）。ResponseFlags 写入「下一上行报文」的应答标志字段，模拟平台对上一条上行报文的应答结果。例如：0x01 登入后，0x0C 平台确认下发（resp=0xFE），下一上行报文（0x04 登出或 0x02 上报）的 resp 字段填 ResponseFlags 的值。

---

## 6. Plan 输出

### 6.1 整体包序列（车辆侧，含 2 条 Reports + 1 次 RemoteControl）

采用 TCP 累计确认模型——每条 PSH-ACK 在携带数据的同时隐式确认对方上一条报文，**不**生成独立的 pure ACK（与 socks5.go 的 emit 模式一致）。仅在握手第 3 步与挥手末步生成 pure ACK。

```
索引  方向    类型              说明
0     up     TCP SYN           client_seq=ISN, MSS/WinScale/SACK options
1     down   TCP SYN-ACK       server_seq=ISN+?
2     up     TCP ACK           ack=server_seq+1 (握手第 3 步)
3     up     TCP PSH-ACK       payload = GBT32960 0x01 车辆登入 (25+31=56 字节)
4     down   TCP PSH-ACK       payload = GBT32960 0x0C 平台确认 (25+1=26 字节, 报文头 resp=0xFE [恒 0xFE，不承载成功/失败], data=0x01 [所确认的命令单元], 隐式 ACK #3)
5     up     TCP PSH-ACK       payload = GBT32960 0x02 实时上报 #1 (隐式 ACK #4)
6     down   TCP PSH-ACK       payload = GBT32960 0x0C (resp=0xFE, data=0x02, 隐式 ACK #5)
7     up     TCP PSH-ACK       payload = GBT32960 0x02 实时上报 #2 (隐式 ACK #6)
8     down   TCP PSH-ACK       payload = GBT32960 0x0C (resp=0xFE, data=0x02, 隐式 ACK #7)
9     down   TCP PSH-ACK       payload = GBT32960 0x08 控制命令 (平台下发, 隐式 ACK #7)
10    up     TCP PSH-ACK       payload = GBT32960 0x0C 车辆应答 (resp=0xFE, data=0x08, 隐式 ACK #9)
11    up     TCP PSH-ACK       payload = GBT32960 0x04 车辆登出 (隐式 ACK #8 与 #10)
12    down   TCP PSH-ACK       payload = GBT32960 0x0C (resp=0xFE, data=0x04, 隐式 ACK #11)
13    up     TCP FIN-ACK       (隐式 ACK #12)
14    down   TCP FIN-ACK       (隐式 ACK #13)
15    up     TCP ACK           (握手/挥手末步 pure ACK)
```

> 共 16 包（含 RemoteControl）。无 RemoteControl 时为 14 包（3 握手 + 8 业务 + 3 挥手）。序列空间：client_seq 在 #3 占用 56 字节，#4 的 ACK 字段必须 = client_seq(#3)+56。planner 内部维护 `clientSeq`、`serverSeq` 两个游标，与 sip.go 的 emit 闭包模式一致。pure ACK 仅出现在握手第 3 步（#2）与挥手末步（#15），业务流中不插入 pure ACK——这符合 RFC 9293 的累计确认语义，也与 socks5.go 第 411-413 行的 emit 模式一致。

### 6.2 MSS 分段

GBT32960 单条报文通常 < 200 字节，远小于典型 MSS 1460，**不会触发 TCP 分段**。但补报场景（`0x03`）若 `CustomFields` 较大可能超过 MSS，此时 planner 应将单条 GBT32960 报文拆为多个 TCP segment：

- 第 1 段：包含起始符 + 报文头 + 数据单元前 (MSS-24) 字节
- 第 2..N 段：数据单元剩余字节 + 校验码

> 设计取舍：GBT32960 报文**不应**跨 TCP segment 边界拆分报文头——起始符 `0x23 0x23` 必须出现在某段开头以便接收端定位。本设计 v1 不实现 MSS 分段（约束 `CustomFields` 长度 ≤ MSS-31，含 6 字节采集时间，由 Validate V29 检查），后续版本再支持。

### 6.3 BCC 计算与注入

```go
// 伪代码
func buildMessage(cmd byte, resp byte, vin []byte, enc byte, data []byte) []byte {
    buf := make([]byte, 0, 25+len(data))
    buf = append(buf, 0x23, 0x23)            // start flag (NOT in BCC range)
    buf = append(buf, cmd, resp)             // command + response
    buf = append(buf, vin...)                // VIN (17 bytes)
    buf = append(buf, enc)                   // encrypt rule
    buf = binary.BigEndian.AppendUint16(buf, uint16(len(data)))
    buf = append(buf, data...)               // data unit
    bcc := bccXOR(buf[2:])                   // from cmd to last data byte
    buf = append(buf, bcc)
    return buf
}
```

`InjectBCCError=true` 时：在指定索引的消息上，`bcc ^= 0x01`（翻转最低位），生成一条 BCC 校验失败的报文，用于测试接收端的丢弃/重传行为。

---

## 7. 业务场景与数据场景

### 7.1 车辆登入完整流程

**场景描述**：车辆首次连接平台，上报身份，平台确认。

**Config 片段**：
```json
{
  "role": "vehicle",
  "vin": "LXXXXXXXXXXXXXXX1",
  "sim": "13800138000",
  "encrypt_rule": "01",
  "login_serial_number": 1,
  "login_time": "2026-08-03T14:30:00+08:00",
  "rechargeable_subsys_count": 1,
  "rechargeable_subsys_code_length": 1,
  "rechargeable_subsys_codes": ["00"],
  "reports": []
}
```

**期望包序列**：TCP 握手（3 包）→ `0x01` up → `0x0C` down (resp=0xFE, data=0x01) → TCP 挥手（3 包）。共 8 包。

**报文 hex 示例**（`0x01` 车辆登入，VIN=`LXXXXXXXXXXXXXXX1` 17 字节，SIM=`13800138000` 11 字节补 9 个 0x00，login_serial=1 即 `00 01`，subsys_count=1, code_length=1, codes=[`00`]）：

```
23 23                              # start flag
01                                 # cmd = vehicle login
FE                                 # resp = 0xFE (uplink)
4C 58 58 58 58 58 58 58 58 58 58   # VIN "LXXXXXXXXXXXXXXX1" (17B)
58 58 58 58 58 31
01                                 # encrypt = no encryption
00 1F                              # data length = 31 (6+2+20+1+1+1)
26 08 03 14 30 00                  # login time BCD (2026-08-03 14:30:00 +08)
00 01                              # login serial number = 1 (big-endian WORD)
31 33 38 30 30 31 33 38 30 30 30   # SIM "13800138000"
00 00 00 00 00 00 00 00 00         # SIM pad (9 bytes)
01                                 # rechargeable subsys count n=1
01                                 # subsys code length m=1
00                                 # subsys code (1 byte)
XX                                 # BCC (xor of bytes 2..54, i.e. cmd through last data byte; 31B data → 24+31-1=54)
```

### 7.2 周期实时上报

**场景描述**：车辆登入后，每 30 秒上报一次实时信息，共 N 次。

**Config 片段**：
```json
{
  "role": "vehicle",
  "vin": "LXXXXXXXXXXXXXXX1",
  "sim": "13800138000",
  "login_serial_number": 1,
  "login_time": "2026-08-03T14:30:00+08:00",
  "reports": [
    {},
    {},
    {}
  ],
  "custom_fields": "01000000000000000000000000000000000000000000"
}
```

**期望包序列**：TCP 握手 → `0x01` → `0x0C` → (`0x02` → `0x0C`) × 3 → `0x04` → `0x0C` → TCP 挥手。共 3 + 2 + 6 + 2 + 3 = 16 包。

**时间序列**（自定义字段 `custom_fields` 提供一条整车数据信息体 0x01 + 18 字节零值）：
- 登入时间：14:30:00
- Report #1：14:30:30（采集时间 BCD `26 08 03 14 30 30`）
- Report #2：14:31:00（采集时间 BCD `26 08 03 14 31 00`）
- Report #3：14:31:30（采集时间 BCD `26 08 03 14 31 30`）
- 登出时间：14:32:30（LoginTime + Σ(Reports 间隔=90s) + 60s = 14:30:00 + 150s，与 §4.5 与 T-GBT-048 公式一致）

### 7.3 报警上报

**场景描述**：车辆在 Reports 中途发生报警，某条 `0x02` 报文含信息类型 0x07 报警信息体，标记电池高温（bit1=1）。

**Config 片段**：
```json
{
  "reports": [
    {},
    {"alarm_data": {"max_alarm_level": 1, "general_alarm_flags": "00000002"}},
    {}
  ]
}
```

**期望行为**：第 2 条 Report 的 `0x02` 报文中，信息体循环包含一条信息类型 0x07 报警信息体，5 字节内容 = `01 00 00 00 02`（最高报警等级 1 + 通用报警标志大端 `00 00 00 02`，bit1=1 即电池高温）。其余两条 Reports 不含报警信息体。报警上报**不**单独成命令——它就是一条普通的 `0x02`，只是信息体中含 0x07 类型。这与 JT808 不同（JT808 有独立的 0x0200 报警命令）。

### 7.4 远程控制响应

**场景描述**：平台下发 `0x08` 远程熄火命令，车辆回 `0x0C` 应答。

**Config 片段**：
```json
{
  "reports": [...],
  "remote_control": {
    "control_type": 1,
    "params": "00",
    "response_flags": "01"
  }
}
```

**期望包序列**：在 Reports 完成后，插入 `0x08` down（平台→车辆）→ `0x0C` up（车辆应答，**0x0C 报文头 resp=0xFE**，data=0x08）。

**异常变体**：`response_flags: "04"` 表示车辆不支持该命令。0x0C 报文头 resp 仍为 0xFE（0x0C 恒 0xFE），但下一上行报文（如重发或后续 0x04 登出）的 resp 字段填 0x04 模拟命令不支持语义。

### 7.5 车辆登出

**场景描述**：车辆完成所有上报后登出。

**Config 片段**：
```json
{
  "logout_time": "2026-08-03T14:32:00+08:00"
}
```

**期望行为**：planner 生成 `0x04` up，数据单元 8 字节（6 字节 BCD 时间 + 2 字节登入流水号 WORD，与 LoginSerialNumber 一致）→ 平台回 `0x0C` down（resp=0xFE, data=0x04）→ TCP 挥手。

### 7.6 平台登入

**场景描述**：平台作为 client 登入上级平台（级联场景）。

**Config 片段**：
```json
{
  "role": "platform",
  "platform_id": "100000LVE00000000",
  "platform_login": {
    "user": "platform01",
    "password": "pwd1234567890abcdef",
    "encrypt_seq": "0001020304050607"
  },
  "heartbeat_count": 3
}
```

**期望包序列**：TCP 握手 → `0x05` up（数据单元 48 字节）→ `0x0C` down (resp=0xFE) → `0x0B` up × 3 → `0x06` up → `0x0C` down → TCP 挥手。共 3 + 2 + 3 + 2 + 3 = 13 包。

VIN 字段：平台报文使用 `PlatformID`（如「城市邮政编码 100000 + VIN 前三位 LVE + 补齐」共 17 字节）。若 `PlatformID` 未配置，默认 17 字节 `0x00`（上级平台可能拒绝）。

### 7.7 平台心跳

**场景描述**：`0x0B` 平台心跳，无数据单元（N=0），无应答（不期待 `0x0C`）。

**Config 片段**：见 §7.6，`heartbeat_count: 3`。

**期望行为**：连续生成 3 条 `0x0B` up 报文，每条总长 25 字节（24 头 + 1 BCC，N=0）。报文头：`23 23 0B FE <PlatformID 17B> <enc> 00 00 <bcc>`。加密方式字段继承 `EncryptRule`（与 0x05 平台登入一致）。

> 心跳间隔：本设计 v1 不在心跳间插入延迟（planner 不控制时间，由 worker/pacer 控制）。如需间隔，由 spec 顶层 `interval` 字段（PacketConfig 间的时间戳差）实现。

### 7.8 平台登出

**场景描述**：`0x06` 平台登出，无数据单元。

**期望行为**：生成 `0x06` up → 平台上级回 `0x0C` down → TCP 挥手。

### 7.9 补报（reissue）

**场景描述**：车辆离线一段时间后恢复连接，登入后立即补传离线期间积压的 N 条历史数据。

**Config 片段**：
```json
{
  "role": "vehicle",
  "vin": "LXXXXXXXXXXXXXXX1",
  "reissue_reports": [
    {"time": "2026-08-03T14:00:00+08:00", "alarm_data": {"max_alarm_level": 0, "general_alarm_flags": "00000000"}},
    {"time": "2026-08-03T14:00:30+08:00", "alarm_data": {"max_alarm_level": 0, "general_alarm_flags": "00000000"}},
    {"time": "2026-08-03T14:01:00+08:00", "alarm_data": {"max_alarm_level": 1, "general_alarm_flags": "00000002"}}
  ],
  "reports": []
}
```

**期望包序列**：TCP 握手 → `0x01` 登入 → `0x0C` → (`0x03` → `0x0C`) × 3 → `0x04` 登出 → `0x0C` → TCP 挥手。

**补报与实时上报的区别**：
- 命令单元：`0x03` vs `0x02`
- 时间字段：补报的时间是历史时间（早于登入时间），实时上报是当前时间
- 数据单元格式：补报与实时上报**完全相同**（都是 6 字节采集时间 + 信息体循环），不存在独立的「补报流水号」字段

### 7.10 加密数据（encrypt_rule=02 RSA / 03 AES128 / 04 SM2 / 05 SM4）

**场景描述**：数据单元被加密，planner 仅填充加密方式字段为 0x02/0x03/0x04/0x05，**不实际加密**——用户通过 `custom_fields` 提供已加密的原始字节。

**Config 片段**：
```json
{
  "encrypt_rule": "03",
  "custom_fields": "A1B2C3D4E5F6..."
}
```

**期望行为**：
- 报文头偏移 21（加密方式字段）写入 `0x03`
- 数据单元的信息体部分直接写入 `custom_fields` 的 hex 解码字节（不解析、不重新编码）
- BCC 计算范围不变（仍覆盖加密方式字段 + 数据单元）

> **BCC 与加密的关系**（GB/T 32960.3-2016）：规范要求「先加密后校验，服务端先校验后解密」。本设计中，`custom_fields` 解码后的字节即密文，planner 对这些密文字节计算 BCC——这是符合规范的。**BCC 始终对最终写入报文的数据单元字节（即 custom_fields 解码后的密文）计算，与 EncryptRule 无关**。实现者切勿「先对明文算 BCC 再把 custom_fields 当密文写入」——这会导致 BCC 与密文不匹配。

> 设计取舍：trafficgen 是流量生成器，不是加密栈。实际加密需密钥管理、IV 同步、密钥协商，超出范围。用户需要真实加密流量时，应在外部用 AES128/SM4 加密好数据单元，再以 hex 字符串填入 `custom_fields`，planner 原样搬运。这与 PPTP/MPPE 设计一致（PPTP 控制面明文，数据面加密由用户在 inner packet 层处理）。

### 7.11 多车并发

**场景描述**：M 辆车同时连接平台，每辆车独立 TCP 流，VIN/SIM 唯一。

**多车实现方式**：GBT32960 是单流协议——一条 FlowSpec 对应一辆车。M 辆车需要 M 条 FlowSpec，每条有独立 4-tuple。这与 socks5/sip 的「一条 FlowSpec = 一条 TCP 流」一致。多车生成由 core 层的 TupleGenerator + 顶层 Config 字段的 strategy 模式处理（与 socks5 一致，**不**使用 `strategy_*` 前缀的概念字段）。

**多车 Config 模板**（顶层 Config 字段直接用 `pattern` 策略，无 strategy_ 前缀）：

```json
{
  "classes": [
    {
      "id": "gbt32960_fleet",
      "type": "gbt32960",
      "tuples": {
        "strategy": "tuple_generator",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.1.1.1",
        "src_port": {"strategy": "inc", "range": [20000, 29999], "step": 1},
        "dst_port": 10020
      },
      "gbt32960": {
        "vin": {"strategy": "pattern", "pattern": "LVEH{n:017d}", "n_range": [1, 1000]},
        "sim": {"strategy": "pattern", "pattern": "1380013{n:04d}", "n_range": [0, 9999]},
        "login_serial_number": {"strategy": "inc", "range": [1, 65531], "step": 1},
        "reports": [{}, {}, {}]
      }
    }
  ],
  "flows": {"count": 100}
}
```

> 实现说明：strategy_convert.go 仅新增 `case "gbt32960"` 解析 sub-map 并填充默认端口 10020；顶层 `vin`/`sim`/`login_serial_number` 字段由 strategy 层通用 pattern/inc 策略处理，与 socks5 的 `socks5_dst_addr` 模式一致。**GBT32960 planner 本身只处理单车**——`Plan(spec)` 接收一条 FlowSpec，生成一辆车的全部包。planner 不解析 `strategy_*` 前缀字段。

**4-tuple 与 VIN 的对应**：

| 车辆编号 | src_ip | dst_ip | src_port | dst_port | VIN | SIM |
|----------|--------|--------|----------|----------|-----|-----|
| 1 | 10.0.0.1 | 10.1.1.1 | 20000 | 10020 | LVEH0000000000001 | 13800130000 |
| 2 | 10.0.0.1 | 10.1.1.1 | 20001 | 10020 | LVEH0000000000002 | 13800130001 |
| ... | | | | | | |
| 100 | 10.0.0.1 | 10.1.1.1 | 20099 | 10020 | LVEH0000000000100 | 13800130099 |

**关键约束**：
- 每条流的 VIN 必须唯一（否则平台侧下一上行报文 resp=0x03 = VIN 重复，见 §7.13）。VIN 重复检测由 strategy 层的 pattern 策略保证（n_range 上限 ≥ flows.count）
- src_port 由 TupleGenerator 递增分配，避免 4-tuple 冲突。src_port 范围 20000-29999 共 10000 个端口，若 M > 10000 则端口回绕——本设计 v1 不检测回绕冲突，用户需保证 M ≤ 10000
- 各流的 TCP 序列空间独立（每条流独立 ISN）
- LoginSerialNumber 跨车无需唯一（每车独立计数，规范允许同日不同车相同流水号）

> GroupID：GBT32960 单流协议，每条 FlowSpec 是独立 TCP 流，无需 GroupID 路由（与 socks5 一致）。若用户希望「同一辆车的登入+上报+登出保序」，由同一 FlowSpec 内 planner 状态机保证，无需跨流 GroupID。

### 7.12 状态变更记录（status_change_trace）

**场景描述**：车辆在多次上报中报警状态逐渐变化（如先正常 → 报警 → 恢复），用 `status_change_trace` 描述变化轨迹。

**Config 片段**：
```json
{
  "reports": [{},{},{},{},{}],
  "status_change_trace": [
    {"at_report_index": 0, "alarm_data": {"max_alarm_level": 0, "general_alarm_flags": "00000000"}},
    {"at_report_index": 1, "alarm_data": {"max_alarm_level": 0, "general_alarm_flags": "00000000"}},
    {"at_report_index": 2, "alarm_data": {"max_alarm_level": 1, "general_alarm_flags": "00000002"}},
    {"at_report_index": 3, "alarm_data": {"max_alarm_level": 0, "general_alarm_flags": "00000000"}},
    {"at_report_index": 4, "alarm_data": {"max_alarm_level": 0, "general_alarm_flags": "00000000"}}
  ]
}
```

**应用规则**（与 §4.5 默认值层级一致）：
1. Reports[i] 初始值为 Config 顶层 AlarmData/CustomFields
2. StatusChangeTrace 中 AtReportIndex == i 的条目覆盖对应字段
3. Reports[i] 自身的 AlarmData/CustomFields（若非空）最终覆盖

**优先级**：`Report 字段 > StatusChangeTrace > Config 顶层 > 默认值`（user > trace > auto > none）。

**重复 AtReportIndex 处理**：V25 校验 AtReportIndex 不能重复——若两条 trace 条目的 AtReportIndex 相同，Validate 报错（不允许覆盖语义）。用户应确保每个 AtReportIndex 唯一。

### 7.13 异常响应（response_flags=02/03/04）

**场景描述**：平台对车辆上报的应答不是成功，而是错误/VIN 重复/命令不支持。

**Config 片段**：
```json
{
  "response_flags": "03"
}
```

**期望行为**：0x0C 平台确认报文头应答标志恒 0xFE（不写入 0x03）。**下一上行报文**（即登入后的 0x04 登出或 0x02 上报）的应答标志字段填 `0x03`，模拟平台对上一条 0x01 登入报文的「VIN 重复」应答。车辆侧状态机在收到 0x03（VIN 重复）语义后，**不**进入 ST_REPORTING，也**不**主动登出（直接转 TCP teardown，见 §5.3 异常分支）。

**单独控制某次响应**：通过 `RemoteControl.ResponseFlags` 控制控制命令的响应；通过 `Reports[i]` 无法单独控制——`ResponseFlags` 是流级别的。若需某条 Report 的下一上行报文 resp 单独控制，本设计 v1 不支持（需 v2 扩展 `Reports[i].ResponseFlags`）。

### 7.14 边界场景

| 场景 | Config | 期望行为 |
|------|--------|----------|
| VIN 为空（Role=vehicle） | `{"role":"vehicle","vin":""}` | Validate V4 报错 |
| VIN 为 17 字节 | `{"vin":"LXXXXXXXXXXXXXXX1"}` | 正常，无补齐 |
| VIN 为 10 字节 | `{"vin":"LXXXXXXXXX"}` | 右补 7 个 VINPadByte（默认 0x00），正常生成 |
| VIN 为 18 字节 | `{"vin":"LXXXXXXXXXXXXXXX12"}` | Validate V2 报错（不静默截断） |
| VIN 含非 ASCII | `{"vin":"LXXXXXXXXX中文X1"}` | Validate V3 报错 |
| VIN 含 I/O/Q | `{"vin":"LIOXXXXXXXXXXXX5"}` | Validate V3b 报错 |
| VINPadByte=0x20 | `{"vin":"LXXXXXXXXX","vin_pad_byte":32}` | 右补 7 个 0x20，正常生成 |
| SIM 为空 | `{"sim":""}` | 20 字节全 0x00 |
| SIM 为 20 字节 | `{"sim":"12345678901234567890"}` | 正常 |
| SIM 为 21 字节 | `{"sim":"123456789012345678901"}` | Validate V5 报错 |
| LoginSerialNumber=0 | `{"login_serial_number":0}` | Validate V7 报错（必须 ≥1） |
| LoginSerialNumber=65532 | `{"login_serial_number":65532}` | Validate V7 报错（必须 ≤65531） |
| LoginSerialNumber=65531 | `{"login_serial_number":65531}` | 正常，写入 `FF FB` 大端 |
| LoginSerialNumber 回绕 | Reports 后再次登入，LoginSerialNumber=65531，下次应回绕到 1 | planner 写入 `FF FB`，下次（若同日）应回绕到 `00 01`；跨日 00:00 归 0 |
| RechargeableSubsysCount=0 | `{"rechargeable_subsys_count":0}` | Validate V30 报错 |
| RechargeableSubsysCodes 长度不匹配 | `{"rechargeable_subsys_count":2,"rechargeable_subsys_codes":["01"]}` | Validate V31 报错 |
| AlarmData.MaxAlarmLevel=4 | `{"alarm_data":{"max_alarm_level":4,"general_alarm_flags":"00000000"}}` | Validate V32 报错 |
| GeneralAlarmFlags 不足 8 位 | `{"alarm_data":{"max_alarm_level":0,"general_alarm_flags":"000"}}` | Validate V8 报错（必须恰好 8 位） |
| GeneralAlarmFlags 全 0 | `"00000000"` | 4 字节 `00 00 00 00`，正常 |
| GeneralAlarmFlags 全 1 | `"FFFFFFFF"` | 4 字节 `FF FF FF FF`，所有报警位亮 |
| CustomFields 空 | `""` | planner 生成最小整车数据信息体（0x01 + 18B 零值） |
| CustomFields 奇数长度 hex | `"ABC"` | Validate V26 报错 |
| CustomFields 非 hex | `"XYZW"` | Validate V26 报错 |
| CustomFields 致数据单元 > 65531 | CustomFields 解码后 > 65525 字节 | Validate V28 报错 |
| CustomFields 超 MSS-31 | spec.TCP.MSS=1460, CustomFields 解码 > 1429 字节 | Validate V29 报错 |
| LoginTime 无时区 | `"2026-08-03 14:30:00"` | Validate V12 报错（强制 RFC3339 时区） |
| LoginTime 字段范围非法 | `"2026-13-45T25:61:61+08:00"` | Validate V12b 报错 |
| LoginTime 格式错 | `"2026/08/03"` | Validate V12 报错 |
| PlatformID 为 17 字节 | `{"role":"platform","platform_id":"100000LVE00000000"}` | 正常 |
| PlatformID 为 18 字节 | `{"platform_id":"100000LVE000000000"}` | Validate V33 报错 |
| Reports 数 0 | `"reports":[]` | 仅登入 + 登出，4 包 |
| Reports 数 1000 | 1000 条 | 2004 包（每条 2 包 + 登入登出 4 包） |
| HeartbeatCount 负 | `-1` | Validate V21 报错 |
| EncryptRule=04 SM2 | `{"encrypt_rule":"04"}` | 加密方式字段=0x04，正常 |
| EncryptRule=05 SM4 | `{"encrypt_rule":"05"}` | 加密方式字段=0x05，正常 |
| EncryptRule=06 非法 | `{"encrypt_rule":"06"}` | Validate V6 报错 |

### 7.15 数据完整性：BCC 校验错误注入

**场景描述**：测试接收端对 BCC 校验失败报文的处理（应丢弃）。

**Config 片段**：
```json
{
  "inject_bcc_error": true,
  "bcc_error_index": 1
}
```

**期望行为**：第 2 条 GBT32960 消息（索引 1，通常是 `0x0C` 平台确认）的 BCC 字节翻转最低位。接收端校验 BCC 失败应丢弃该报文，不触发业务处理。

**校验范围验证**（防回归测试）：planner 实现最易错的点是 BCC 范围。正确范围是「偏移 2 到 24+N-1」（即 cmd 到最后一个 data 字节；不含起始符 2 字节，不含 BCC 自身 1 字节；N 为数据单元长度）。以 0x01 车辆登入（N=31）为例，BCC 覆盖 bytes 2..54（共 53 字节），BCC 自身位于 byte 55。注入测试用例应覆盖：
- 起始符 `0x23 0x23` 被错误纳入 BCC → 应能被测试捕获
- BCC 自身被纳入 BCC → 应能被测试捕获

---

## 8. 测试用例清单

> 本节用例编号 `T-GBT-001` ~ `T-GBT-0XX`，命名规则与项目现有协议测试一致（如 `socks5` 用 `T-S5-001`）。每条用例标注覆盖的 Validate 规则（V#）、场景章节（§#）、测试类型（正向/负向/边界）。

### 8.1 报文格式与 BCC

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-001 | 起始符固定 0x23 0x23 | 正向 | §2.2 | 生成任意报文，断言前 2 字节为 `23 23` |
| T-GBT-002 | BCC 范围正确（不含起始符） | 正向 | §2.4 | 生成车辆登入报文，独立计算 BCC（从偏移 2 开始）比对 planner 输出 |
| T-GBT-003 | BCC 错误注入 | 正向 | §7.15 | InjectBCCError=true, index=0，断言首条报文 BCC 与正确值异或 0x01 |
| T-GBT-004 | BCC 注入索引越界 | 负向 | §7.15/V24 | InjectBCCError=true, index=999（超出消息数），Validate/Plan 阶段报错（非 warning） |
| T-GBT-005 | 数据长度字段大端 | 正向 | §2.5 | 0x01 数据单元 31 字节，断言 len 字段为 `00 1F` |
| T-GBT-006 | 数据长度 0（平台心跳） | 正向 | §3.11 | 0x0B 报文 N=0，断言 len=`00 00`，总长 25 字节 |

### 8.2 命令单元

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-007 | 0x01 车辆登入数据单元格式 | 正向 | §3.1 | 断言数据单元 = 6 时间(BCD) + 2 登入流水号(WORD 大端) + 20 ICCID + 1 子系统数 n + 1 编码长度 m + n×m 编码；n=1,m=1 时 31 字节 |
| T-GBT-007b | 0x01 多子系统编码 | 正向 | §3.1 | n=2,m=3 时数据单元 38 字节；编码按 3 字节截断/补齐后串联 |
| T-GBT-008 | 0x02 实时上报数据单元格式 | 正向 | §3.2 | 断言数据单元 = 6 采集时间(BCD) + (1 信息类型 + N 信息体)*；最小有效信息体 0x01 整车 18B 时 25 字节；**无**独立流水号/报警/状态头部字段 |
| T-GBT-008b | 0x02 多信息体循环 | 正向 | §3.2 | CustomFields=`0701000000020500 0A1B2C0000000000`（16 字节 = 1 信息类型 0x07 + 5B 报警信息体 + 1 信息类型 0x05 + 9B 位置信息体），断言信息体序列为「0x07 报警 + 0x05 位置」两段，且 0x05 位置信息体长度 = 9B（1B 定位状态 + 4B 经度 + 4B 纬度）|
| T-GBT-009 | 0x04 车辆登出数据单元 8 字节 | 正向 | §3.4 | 断言 6 字节 BCD 登出时间 + 2 字节登入流水号(WORD 大端，与 LoginSerialNumber 一致) |
| T-GBT-010 | 0x0B 平台心跳无数据单元 | 正向 | §3.11 | 断言 N=0，VIN 字段为 PlatformID 17 字节 |
| T-GBT-011 | 0x0C 平台确认数据单元 1 字节 | 正向 | §3.12 | 对 0x01 的确认，断言 data=`01`；**0x0C 报文头 resp=0xFE**（非 0x01） |
| T-GBT-012 | 0x05 平台登入数据单元 48 字节 | 正向 | §3.5 | 断言 12 user + 20 pwd + 16 encrypt_seq（按规范 §7.1）；VIN 字段用 PlatformID 而非全 0 |
| T-GBT-013 | 0x08 控制命令数据单元 | 正向 | §3.8 | ControlType=1, Params="00"，断言 data=`01 00`；0x0C 应答报文头 resp=0xFE |

### 8.3 应答标志

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-014 | 首发/所有上行报文应答标志 0xFE | 正向 | §1.4 | 0x01 车辆登入 resp=0xFE（上行命令发起方） |
| T-GBT-014b | 下行 0x0C 报文头 resp 恒 0xFE | 正向 | §1.4/§3.12 | 0x0C 报文头 resp 恒 0xFE；成功/失败语义**不**承载在 0x0C 报文头 |
| T-GBT-015 | ResponseFlags=01 成功写入下一上行报文 | 正向 | §1.4/§7.13 | 0x0C resp=0xFE；下一上行报文（0x04 登出或 0x02）resp=0x01 |
| T-GBT-016 | ResponseFlags=02 错误写入下一上行 | 正向 | §7.13 | 0x0C resp=0xFE；下一上行报文 resp=0x02；不进入 ST_REPORTING |
| T-GBT-017 | ResponseFlags=03 VIN 重复 | 正向 | §7.13 | 0x0C resp=0xFE；下一上行报文 resp=0x03；车辆**不**主动登出，直接 TCP teardown |
| T-GBT-018 | ResponseFlags=04 命令不支持 | 正向 | §7.13 | RemoteControl.ResponseFlags=04，下一上行报文 resp=0x04；0x0C 报文头 resp=0xFE |
| T-GBT-019 | ResponseFlags 非法值 | 负向 | V22 | ResponseFlags="05"，Validate 报错 |

### 8.4 VIN / SIM / 序列号

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-020 | VIN 17 字节不补齐 | 正向 | §2.3 | VIN="LXXXXXXXXXXXXXXX1"，断言 17 字节原样写入 |
| T-GBT-021 | VIN 10 字节右补 0x00 | 正向 | §2.3 | VIN="LXXXXXXXXX"，断言后 7 字节为 0x00 |
| T-GBT-022 | VIN 18 字节截断/报错 | 负向 | V2 | VIN 18 字节，Validate V2 报错（不静默截断） |
| T-GBT-023 | VIN 含非 ASCII | 负向 | V3 | VIN="LXXXXXXXXX中文X1"，Validate V3 报错 |
| T-GBT-024 | VIN 空且 Role=vehicle | 负向 | V4 | Validate V4 报错 |
| T-GBT-025 | VIN 空且 Role=platform | 正向 | §3.11 | VIN 全 0x00，正常生成 |
| T-GBT-026 | SIM 20 字节 | 正向 | §3.1 | SIM 20 字节原样写入 |
| T-GBT-027 | SIM 空 | 正向 | §3.1 | SIM 空，20 字节全 0x00 |
| T-GBT-028 | SIM 21 字节 | 负向 | V5 | Validate V5 报错 |
| T-GBT-029 | LoginSerialNumber 合法值 | 正向 | §3.1 | LoginSerialNumber=1，断言 0x01 数据单元字节 6-7 = `00 01`（WORD 大端） |
| T-GBT-029b | LoginSerialNumber=65531 边界 | 边界 | §3.1/V7 | 断言 0x01 数据单元字节 6-7 = `FF FB`（65531 大端） |
| T-GBT-030 | LoginSerialNumber 越界 65532 | 负向 | V7 | LoginSerialNumber=65532，Validate V7 报错（规范上限 65531） |
| T-GBT-030b | LoginSerialNumber=0 越界 | 负向 | V7 | LoginSerialNumber=0，Validate V7 报错（必须 ≥1） |
| T-GBT-030c | VIN 含 I/O/Q 字符 | 负向 | V3b | VIN="LIOXXXXXXXXXXXX5"，Validate V3b 报错 |

### 8.5 加密方式

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-031 | EncryptRule=01 不加密 | 正向 | §2.2 | 加密方式字段=0x01 |
| T-GBT-032 | EncryptRule=02 RSA | 正向 | §7.10 | 加密方式字段=0x02，custom_fields 原样写入（密文） |
| T-GBT-033 | EncryptRule=03 AES128 | 正向 | §7.10 | 加密方式字段=0x03 |
| T-GBT-033b | EncryptRule=04 SM2 | 正向 | §2.2 | 加密方式字段=0x04 |
| T-GBT-033c | EncryptRule=05 SM4 | 正向 | §2.2 | 加密方式字段=0x05 |
| T-GBT-034 | EncryptRule 非法 | 负向 | V6 | EncryptRule="06"，Validate V6 报错 |
| T-GBT-035 | EncryptRule 空 | 正向 | §4.5 | 默认 "01"，加密方式字段=0x01 |

### 8.6 报警数据（信息体 0x07）

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-036 | AlarmData.GeneralAlarmFlags 全 0 | 正向 | §3.2.1 | 5 字节 = `00 00 00 00 00`（等级 0 + 标志 0） |
| T-GBT-037 | AlarmData.GeneralAlarmFlags 全 1 | 正向 | §3.2.1 | 5 字节 = `03 FF FF FF FF`（等级 3 + 标志全 1） |
| T-GBT-038 | AlarmData 电池高温（bit1） | 正向 | §3.2.1 | "00000002" → 标志字节 `00 00 00 02` 大端（**bit1=电池高温**，非 bit31）；5 字节 = `01 00 00 00 02`（等级 1） |
| T-GBT-038b | AlarmData 热事件（bit19） | 正向 | §3.2.1 | "00080000" → 标志字节 `00 08 00 00` 大端（bit19=热事件） |
| T-GBT-039 | AlarmData 超出 32 位 | 负向 | V9 | "1FFFFFFFF"，Validate V9 报错（防御性，正常 V8 已覆盖） |
| T-GBT-040 | AlarmData 非法 hex | 负向 | V8 | "XYZW"，Validate V8 报错 |
| T-GBT-040b | AlarmData 不足 8 位 hex | 负向 | V8 | "000"（3 位），Validate V8 报错（必须恰好 8 位） |
| T-GBT-040c | AlarmData.MaxAlarmLevel 越界 | 负向 | V32 | MaxAlarmLevel=4，Validate V32 报错（0-3） |
| T-GBT-040d | StatusFlags 字段已删除 | 正向 | §3.2.2 | 验证 Config 中无 StatusFlags 字段（编译期/反射断言） |
| T-GBT-043 | Reports[i].AlarmData 覆盖 Config | 正向 | §4.5 | 第 2 条 Report 的 AlarmData 覆盖 Config 顶层 |

### 8.7 时间字段

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-044 | LoginTime BCD 编码 | 正向 | §3.1/§4.5 | "2026-08-03T14:30:00+08:00" → `26 08 03 14 30 00`（保留输入时区 GMT+8） |
| T-GBT-044b | LoginTime 时区为 Z（UTC） | 正向 | §3.1/§4.5 | "2026-08-03T06:30:00Z" → `26 08 03 06 30 00`（UTC 时间直接编码，不做 +8 偏移） |
| T-GBT-045 | LoginTime 空 | 正向 | §4.5 | 默认 time.Now()（本机时区，应为 GMT+8），断言 6 字节 BCD 合法 |
| T-GBT-046 | LoginTime 格式错 | 负向 | V12 | "2026/08/03"，Validate V12 报错 |
| T-GBT-046b | LoginTime 无时区 | 负向 | V12 | "2026-08-03 14:30:00"（无时区），Validate V12 报错（强制 RFC3339 时区） |
| T-GBT-046c | LoginTime 月日越界 | 负向 | V12b | "2026-13-45T25:61:61+08:00"，Validate V12b 报错 |
| T-GBT-047 | LogoutTime 默认 | 正向 | §4.5 | 空，默认 LoginTime + 60s（无 Reports 时） |
| T-GBT-048 | LogoutTime 默认（有 Reports） | 正向 | §4.5 | 空，默认 LoginTime + 30s×N + 60s（与 §4.5 公式一致；N=3 时 = LoginTime + 150s） |
| T-GBT-048a | LogoutTime 早于 LoginTime | 负向 | V34 | LogoutTime="2026-08-03T14:00:00+08:00", LoginTime="2026-08-03T14:30:00+08:00"，Validate V34 报错 |
| T-GBT-049 | Reports[i].Time 自动序列 | 正向 | §4.5 | 3 条 Report 均 Time 空，断言时间分别为 LoginTime+30/60/90s |
| T-GBT-050 | 0x02 无独立 Serial 字段 | 正向 | §3.2 | 0x02 数据单元**不**含 2 字节流水号字段（流水号由登入报文承载） |
| T-GBT-051 | 数据单元长度上限 65531 | 边界 | §2.5/V28 | CustomFields 解码后 65531 字节，正常；65532 字节，Validate V28 报错 |

### 8.8 状态机

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-052 | 车辆完整流程包数 | 正向 | §6.1 | 登入+2 Reports+登出，断言总包数 = 3+2+4+2+3 = 14 |
| T-GBT-053 | 平台完整流程包数 | 正向 | §5.2 | 登入+3 心跳+登出，断言总包数 = 3+2+3+2+3 = 13 |
| T-GBT-054 | LoginAck resp=02 不进入 Reporting | 正向 | §5.3 | ResponseFlags=02，断言无 0x02 报文，直接 0x04 登出 |
| T-GBT-055 | RemoteControl 插入位置 | 正向 | §7.4 | Reports 后插入 0x08→0x0C，断言 0x08 在最后一条 0x0C 之后 |
| T-GBT-056 | ReissueReports 在 Reports 后 | 正向 | §7.9 | Reports 3 条 + ReissueReports 2 条，断言顺序：0x02×3 → 0x03×2 → 0x04 |

### 8.9 多车场景

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-057 | 2 辆车独立 4-tuple | 正向 | §7.11 | 2 条 FlowSpec，src_port 20000/20001，断言 4-tuple 不冲突 |
| T-GBT-058 | 2 辆车 VIN 唯一 | 正向 | §7.11 | VIN1="L...1", VIN2="L...2"，断言报文中 VIN 字段不同 |
| T-GBT-059 | 100 辆车并发 | 正向 | §7.11 | 100 条 FlowSpec，TupleGenerator 递增 src_port，断言无 4-tuple 重复 |
| T-GBT-060 | VIN 重复触发 resp=03 | 正向 | §7.13 | 2 条 FlowSpec 用相同 VIN，第 2 条 ResponseFlags=03 |

### 8.10 状态变更记录

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-061 | StatusChangeTrace 应用 | 正向 | §7.12 | 5 条 Report，trace 在 index=2 设 alarm=00000002（bit1 电池高温），断言第 3 条 0x02 信息体含 5 字节 `01 00 00 00 02` |
| T-GBT-062 | Report 字段优先于 Trace | 正向 | §4.5 | Trace 设 alarm=00000002，Report[2].AlarmData.GeneralAlarmFlags=00000000，断言第 3 条=00 00 00 00 |
| T-GBT-063 | AtReportIndex 越界 | 负向 | V25 | AtReportIndex=99（Reports 仅 5 条），Validate V25 报错 |
| T-GBT-063b | AtReportIndex 重复 | 负向 | V25 | 两条 trace 条目 AtReportIndex=2，Validate V25 报错（不允许覆盖语义） |

### 8.11 CustomFields

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-064 | CustomFields 空 + IsTransBatteryData=true | 正向 | §3.2.3/§4.1 | CustomFields 与 AlarmData 均空，IsTransBatteryData=true（默认），planner 生成最小整车数据信息体（0x01 + 18B 零值），断言子项以 0x01 开头 |
| T-GBT-064b | IsTransBatteryData=false 仅输出位置 | 正向 | §4.1 | CustomFields 与 AlarmData 均空，显式设 `IsTransBatteryData=false`，planner 仅输出车辆位置信息体（0x05 + 9B 零值），断言子项以 0x05 开头且**不**含 0x01 整车数据信息体 |
| T-GBT-065 | CustomFields hex | 正向 | §3.2.3 | "050A1B2C"，断言子项=05 0A 1B 2C |
| T-GBT-066 | CustomFields 奇数长度 | 负向 | V26 | "ABC"，Validate V26 报错 |
| T-GBT-067 | CustomFields 非 hex | 负向 | V26 | "XYZW"，Validate V26 报错 |
| T-GBT-068 | Reports[i].CustomFields 覆盖 | 正向 | §4.5 | 第 2 条 Report 的 CustomFields 覆盖 Config 顶层 |

### 8.12 集成与端到端

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-069 | TCP 握手 + GBT32960 + 挥手 | 正向 | §6.1 | 端到端：3 握手 + N 业务 + 3 挥手，断言 TCP 序列号连续 |
| T-GBT-070 | TCP 序列号在 PSH-ACK 间正确推进 | 正向 | §6.1 | 第 4 包 ACK 字段 = 第 3 包 seq + 56（登入报文长度 = 25 头 + 31 数据 = 56 字节） |
| T-GBT-071 | MSS 校验 | 负向 | V27 | spec.TCP.MSS=100，Validate V27 报错 |
| T-GBT-072 | 默认端口 10020 | 正向 | §1.1 | spec.DstPort=0，断言 planner 不覆盖（由 mapToFlowSpec 填默认） |
| T-GBT-073 | 端到端 pcap 通过 tshark 解析 | 正向 | §10 | 生成 pcap，tshark -V 解析无 Malformed 标记 |

### 8.13 平台侧用例

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-074 | 平台登入 + 心跳 + 登出 | 正向 | §7.6-7.8 | Role=platform，HeartbeatCount=3，断言包序列 0x05→0x0C→0x0B×3→0x06→0x0C |
| T-GBT-075 | 平台心跳无应答 | 正向 | §3.11 | 0x0B 后不生成 0x0C（心跳无应答语义） |
| T-GBT-076 | PlatformLogin.User 超长 | 负向 | V18 | User 13 字节，Validate V18 报错 |
| T-GBT-077 | HeartbeatCount=0 | 正向 | §4.5 | 不生成 0x0B，仅登入+登出 |
| T-GBT-078 | HeartbeatCount 负 | 负向 | V21 | -1，Validate V21 报错 |

### 8.14 补报

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-079 | 补报命令 0x03 | 正向 | §7.9 | ReissueReports 非空，断言命令单元=0x03 |
| T-GBT-080 | 补报时间早于登入 | 正向 | §7.9 | ReissueReports[0].Time < LoginTime |
| T-GBT-081 | 补报采集时间不连续 | 正向 | §7.9 | ReissueReports 的 Time 字段为历史时间（如 14:00:00/14:00:30/14:01:00），与 Reports 的当前时间（14:30:30/14:31:00/14:31:30）不连续；0x03 数据单元仅含采集时间 + 信息体循环，无独立流水号字段 |

### 8.15 异常与边界综合

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-082 | Role 非法 | 负向 | V1 | Role="client"，Validate V1 报错 |
| T-GBT-083 | Role 空 | 正向 | §4.5 | 默认 "vehicle" |
| T-GBT-084 | Reports 0 条 | 正向 | §7.14 | 仅登入+登出，4 包 |
| T-GBT-085 | Reports 1000 条 | 正向 | §7.14 | 2004 包，无 panic |
| T-GBT-086 | RemoteControl.ControlType=0 | 负向 | V16 | Validate V16 报错 |
| T-GBT-087 | RemoteControl.ResponseFlags 非法 | 负向 | V17 | "05"，Validate V17 报错 |
| T-GBT-088 | RemoteControl.Params 空 | 正向 | §4.3 | Params=""，数据单元仅 1 字节 ControlType |
| T-GBT-089 | BCC 错误注入后接收端丢弃 | 集成 | §7.15 | 生成含 BCC 错误的 pcap，tshark 解析标记 BCC 校验失败 |

### 8.16 补发请求/参数查询/参数设置（M8）

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-090 | 0x07 补发请求时间格式 | 正向 | §3.7 | 起始时间 + 结束时间，2 个 6 字节 BCD，断言数据单元 12 字节 |
| T-GBT-091 | 0x09 参数查询 | 正向 | §3.9 | 参数类型=0x01，断言数据单元 1 字节 `01` |
| T-GBT-092 | 0x0A 参数设置 | 正向 | §3.10 | 参数类型=0x01 + 自定义参数 hex，断言数据单元按配置拼接 |

### 8.17 扩展表 1 字段（H6）

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-093 | LogoutSerialNumber 默认继承 | 正向 | §3.4/§4.5 | LogoutSerialNumber=0，断言 0x04 登入流水号 = LoginSerialNumber |
| T-GBT-094 | LogoutSerialNumber 显式 | 正向 | §3.4 | LogoutSerialNumber=42，断言 0x04 登入流水号 = `00 2A` |
| T-GBT-095 | PlatformDomain/SetPlatformDomain 字段 | 正向 | §4.1 | Config 含 PlatformDomain="test.example.com" 与 SetPlatformDomain="target.example.com"，不报错，planner 不写入 0x05 数据单元（v1 仅日志用） |
| T-GBT-096 | RechargeableSubsysCount=0 报错 | 负向 | V30 | RechargeableSubsysCount=0，Validate V30 报错 |
| T-GBT-096a | RechargeableSubsysCodeLength=0 报错 | 负向 | V35 | RechargeableSubsysCodeLength=0，Validate V35 报错 |
| T-GBT-097 | RechargeableSubsysCodes 长度不匹配 | 负向 | V31 | count=2, codes=["01"]，Validate V31 报错 |
| T-GBT-098 | MaxAlarmLevel=4 越界 | 负向 | V32 | 断言 Validate V32 报错 |
| T-GBT-099 | PlatformID 超 17 字节 | 负向 | V33 | PlatformID 18 字节，Validate V33 报错 |
| T-GBT-100 | ConnectID 自动生成 | 正向 | §4.1/§4.5 | ConnectID 空，planner 由 4-tuple 哈希生成；两次同 FlowSpec 生成的 ConnectID 一致 |

### 8.18 边界与 MSS（H3/H8）

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-101 | 数据单元长度=65531 边界 | 边界 | §2.5/V28 | CustomFields 解码后 65531 字节，正常生成；长度字段=`FF FB` 大端 |
| T-GBT-102 | 数据单元长度=65532 越界 | 负向 | §2.5/V28 | CustomFields 解码后 65532 字节，Validate V28 报错 |
| T-GBT-103 | CustomFields 超 MSS-31 | 负向 | §6.2/V29 | spec.TCP.MSS=1460, CustomFields 解码 1430 字节（>MSS-31=1429），Validate V29 报错 |

### 8.19 多车回绕与并发（H7/§9.4）

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-104 | src_port 范围 10000 端口内 | 正向 | §7.11 | 10000 辆车，src_port 20000-29999 递增，无回绕 |
| T-GBT-105 | src_port 范围超出 10000 | 文档 | §7.11 | M=10001 车，文档化：v1 不检测端口回绕冲突，用户需保证 M ≤ 10000 |
| T-GBT-106 | 100 车 -race clean | 并发 | §9.4 | 100 条 FlowSpec 并发生成，`go test -race` 干净 + 断言每辆车 VIN 字段唯一 |

### 8.20 tshark 双重验证（M9）

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-107 | tshark + 独立解析器双重验证 | 集成 | §10.5/M9 | 生成 pcap：(1) tshark 解析无 Malformed；(2) 测试代码内独立实现的 GBT32960 解析器校验字段值（如 VIN 长度=17、命令单元匹配、BCD 合法）|

### 8.21 登出失败异常分支（H4）

| 用例 ID | 名称 | 类型 | 覆盖 | 描述 |
|---------|------|------|------|------|
| T-GBT-108 | ST_LOGOUT_SENT 登出失败（resp=02） | 正向 | §5.3 | ResponseFlags="02"，车辆走完整流程到 ST_LOGOUT_SENT，断言登出报文 0x04 生成后，**不**重试，**不**插入额外的 0x04 重发，直接进入 TCP 挥手（3 包）；下一上行报文（无更多上行时）的 resp 字段填 0x02 模拟登出失败语义 |

---

## 9. 交叉对抗审计检查清单

本节用于实现完成后由独立 reviewer 对照检查。每项标注「常见错法」「检查方法」「覆盖用例」「待补用例」四列。

### 9.1 BCC 校验

| 风险 | 常见错法 | 检查方法 | 覆盖用例 | 待补用例 |
|------|----------|----------|----------|----------|
| BCC 范围错 | 把起始符 `0x23 0x23` 纳入异或 | T-GBT-002：独立实现 BCC（从偏移 2 起）比对 | T-GBT-002 | — |
| BCC 含自身 | 把 BCC 字节也异或进去 | 同上 | T-GBT-002 | — |
| BCC 端序 | 误用 little-endian 累加（BCC 是按字节异或，无端序，但实现可能误用 binary.Write） | 代码 review：应单字节循环 | T-GBT-002 | — |
| 注入索引越界 panic | InjectBCCError=true, index=999 时 panic | T-GBT-004：断言 Validate 报错（非 warning） | T-GBT-004 | — |
| BCC 计算对密文 | 错误地对明文算 BCC 再写密文 | T-GBT-032：EncryptRule=03 + custom_fields 密文，断言 BCC = 密文字节异或 | T-GBT-032 | — |

### 9.2 字段编码

| 风险 | 常见错法 | 检查方法 | 覆盖用例 | 待补用例 |
|------|----------|----------|----------|----------|
| VIN 补齐字符 | 用 `0x20`（空格）补齐而非 `0x00` | T-GBT-021：断言补齐字节为 0x00 | T-GBT-020/021 | — |
| VIN 截断 vs 报错 | 静默截断 18 字节 VIN 而非报错 | T-GBT-022：断言 Validate V2 报错 | T-GBT-022 | — |
| VIN 含 I/O/Q | Validate 不校验字符集 | T-GBT-030c：VIN 含 I/O/Q，断言 V3b 报错 | T-GBT-030c | — |
| 时间 BCD 顺序 | YYMMDD 写成 MMDDYY | T-GBT-044：断言 `26 08 03` 而非 `08 03 26` | T-GBT-044 | — |
| 时间 BCD 世纪 | 年份用 2026 而非 26 | 同上 | T-GBT-044 | — |
| 时间 BCD 时区 | LoginTime 无时区被当 UTC | T-GBT-044b：断言 `+08:00` 输入产出北京时间 BCD | T-GBT-044b | — |
| 数据长度端序 | little-endian | T-GBT-005：断言大端 | T-GBT-005 | — |
| 数据长度上限 | 数据单元 > 65531 未报错 | T-GBT-102：断言 V28 报错 | T-GBT-102 | — |
| 报警标志端序 | little-endian | T-GBT-038：断言 `00 00 00 02`（bit1 电池高温）大端 | T-GBT-038 | — |
| 报警标志位序 | bit31 误作电池高温（实际 bit1） | T-GBT-038：断言 bit1=电池高温 | T-GBT-038 | — |
| 登入流水号端序 | little-endian | 代码 review：binary.BigEndian.PutUint16 | T-GBT-007 | — |
| 登出流水号字段缺失 | 0x04 仅 6B（漏登入流水号） | T-GBT-009：断言 0x04 数据单元 8B | T-GBT-009 | — |

### 9.3 状态机

| 风险 | 常见错法 | 检查方法 | 覆盖用例 | 待补用例 |
|------|----------|----------|----------|----------|
| ACK 字段未推进 | 第 4 包 ACK=第 3 包 seq（未加 payload 长度） | T-GBT-070：断言 ACK = seq + 56（登入报文 25+31=56 字节） | T-GBT-070 | — |
| ACK 模式不对称 | 每条 down PSH-ACK 后跟 pure ACK，up 后不跟 | T-GBT-052：断言无 pure ACK 业务包 | T-GBT-052 | — |
| LoginAck 失败仍上报 | ResponseFlags=02 时仍进入 Reporting | T-GBT-054：断言无 0x02 报文，断言生成 0x04 登出 | T-GBT-054 | — |
| VIN 重复主动登出 | resp=03 时车辆主动发 0x04（规范应等待） | T-GBT-017：断言 resp=03 时不生成 0x04 | T-GBT-017 | — |
| 心跳后误生成 ACK | 0x0B 后生成 0x0C | T-GBT-075：断言心跳后无 0x0C | T-GBT-075 | — |
| Reissue 顺序错 | 0x03 在 0x02 之前 | T-GBT-056：断言 0x02×3 → 0x03×2 | T-GBT-056 | — |
| 0x0C resp 写入 | 0x0C 报文头 resp 误写 0x01-0x04 | T-GBT-015：断言 0x0C 报文头 resp=0xFE | T-GBT-015 | — |
| 登出失败重试 | ST_LOGOUT_SENT 收到 resp=02 后重试 0x04 | T-GBT-108：断言登出失败后不重试、直接 TCP 挥手 | T-GBT-108 | — |

### 9.4 多车并发

| 风险 | 常见错法 | 检查方法 | 覆盖用例 | 待补用例 |
|------|----------|----------|----------|----------|
| 4-tuple 冲突 | 多车共用 src_port | T-GBT-059：100 车断言无重复 | T-GBT-059 | — |
| 4-tuple 回绕 | M > 10000 端口回绕未检测 | T-GBT-105：M=10001 断言行为（v1 不检测，文档化） | T-GBT-105 | — |
| VIN 跨流串扰 | 第 2 辆车的报文用了第 1 辆车的 VIN（planner 全局变量泄漏） | T-GBT-058：2 车断言 VIN 字段不同 | T-GBT-058 | — |
| 序列空间串扰 | 第 2 辆车的 TCP seq 沿用第 1 辆车 | 代码 review：每条 FlowSpec 独立 ISN | T-GBT-069 | — |
| planner 共享状态 | planner 用 struct 字段缓存 VIN 导致并发污染 | T-GBT-106：100 车 -race clean + 断言 VIN 唯一 | T-GBT-106 | — |

### 9.5 Config 校验

| 风险 | 常见错法 | 检查方法 | 覆盖用例 | 待补用例 |
|------|----------|----------|----------|----------|
| 负值未校验 | HeartbeatCount=-1 不报错 | T-GBT-078 | T-GBT-078 | — |
| 长度边界差一 | VIN 17 字节被误判超长 | T-GBT-020：17 字节正常 | T-GBT-020 | — |
| hex 解析未防溢出 | GeneralAlarmFlags="1FFFFFFFF" 解析为 uint64 后强转 uint32 截断 | T-GBT-039：断言 V9 报错而非静默截断 | T-GBT-039 | — |
| GeneralAlarmFlags 非固定 8 位 | "1" 通过 V8 但生成 1 字节字段 | T-GBT-040b：断言恰好 8 位 | T-GBT-040b | — |
| 默认值未应用 | EncryptRule 空时写入 0x00 而非 0x01 | T-GBT-035 | T-GBT-035 | — |
| Role 默认值 | Role 空时不走 vehicle 路径 | T-GBT-083：默认 vehicle | T-GBT-083 | — |
| CustomFields 超 MSS | 未校验 CustomFields + 31 > MSS（含 6 字节采集时间） | T-GBT-103：断言 V29 报错 | T-GBT-103 | — |
| LoginSerialNumber 上限 | 用 65535 而非 65531 | T-GBT-030：断言 V7 在 65532 报错 | T-GBT-030 | — |
| RechargeableSubsysCount=0 | 未校验 n>=1 | T-GBT-096：断言 V30 报错 | T-GBT-096 | — |
| MaxAlarmLevel > 3 | 未校验等级范围 | T-GBT-098：断言 V32 报错 | T-GBT-098 | — |
| 数据单元 > 65531 | 未校验数据单元长度上限 | T-GBT-102：断言 V28 报错 | T-GBT-102 | — |

### 9.6 测试质量（防回归）

| 风险 | 常见错法 | 检查方法 | 覆盖用例 | 待补用例 |
|------|----------|----------|----------|----------|
| 用例只断言结构不断言值 | 仅断言「包数=14」不断言 BCC/字段值 | 本清单要求每条用例断言具体字节 | T-GBT-002/044 等 | — |
| 用例不覆盖负向 | 只测合法 Config | §8 每节至少 1 条负向用例 | V1-V33 全有对应 | — |
| 用例不覆盖边界 | 只测典型值 | §7.14 边界表逐条对应 §8 用例 | T-GBT-020/022 等 | — |
| 集成测试缺位 | 仅单元测试，无端到端 | T-GBT-069/070/073：端到端 + tshark | T-GBT-069/070/073 | — |
| BCC 范围未独立验证 | 用例用 planner 自己的 BCC 比对 planner 输出（同源错） | T-GBT-002 要求独立实现 BCC | T-GBT-002 | — |
| tshark 虚假合规 | tshark 无 Malformed 不等于合规 | T-GBT-107：同时用独立解析器校验字段值 | T-GBT-107 | — |
| 0x07/0x09/0x0A 无测试 | 三个命令无任何用例 | T-GBT-090/091/092：补 0x07/0x09/0x0A 用例 | T-GBT-090/091/092 | — |
| StatusChangeTrace 重复 | AtReportIndex 重复未报错 | T-GBT-063b：断言 V25 重复报错 | T-GBT-063b | — |
| 0x02 头部多余字段 | 把 JT808 报警/状态位域误植到 0x02 头部 | T-GBT-008：断言 0x02 无 4B 报警 + 2B 状态 | T-GBT-008 | — |
| 0x04 漏登入流水号 | 0x04 数据单元仅 6B | T-GBT-009：断言 0x04 数据单元 = 6B 时间 + 2B 流水号 | T-GBT-009 | — |
| 报警位 bit31 误作电池高温 | 规范 bit1 才是电池高温 | T-GBT-038：bit1=电池高温 | T-GBT-038 | — |
| 0x0C 报文头 resp 误用 0x01-0x04 | 0x0C 报文头 resp 应恒 0xFE | T-GBT-014b | T-GBT-014b | — |

---

## 10. 集成点

### 10.1 FlowSpec 集成

`core.FlowSpec` 新增字段 `GBT32960 *GBT32960Config`，按 phase 3 batch 字段风格**追加在 FlowSpec struct 末尾**（WireGuard 之后），与 `Socks`/`SIP`/`RTSP` 等并列，不插入中间位置（参见 `types.go` 第 178-219 行注释「L7 protocol configurations (phase 3 batch). Appended at end per flowspec_extension.md §2.3 to avoid touching existing field layout」）：

```go
// 追加在 types.go FlowSpec struct 末尾（WireGuard 之后）：
GBT32960 *GBT32960Config `json:"gbt32960,omitempty"`
```

### 10.2 mapToFlowSpec 集成

`internal/core/convert.go` 的 `mapToFlowSpec` 函数新增 case：当 `spec.Type == "gbt32960"` 时，将 map 形式的 config 反序列化为 `GBT32960Config` 并填入 `FlowSpec.GBT32960`。默认端口 10020 在此处填充（与 socks5 的 1080 一致）。同时 GBT32960 加入 `convert.go` 协议互斥表（与 mpls/gtp/socks5/sip/rtsp 等互斥，同一 FlowSpec 不能同时携带两个 L7 协议配置）。

### 10.3 strategy_convert 集成

`internal/core/strategy_convert.go` 新增 `case "gbt32960"`：仅解析 sub-map 并填充默认端口 10020。顶层 `vin`/`sim`/`login_serial_number` 字段由 strategy 层通用 `pattern`/`inc` 策略处理，与 socks5 的 `socks5_dst_addr` 模式一致——**不**为 GBT32960 引入独立的 `strategy_*` 前缀字段处理。

### 10.4 Planner 注册

`internal/protocol/gbt32960/gbt32960.go` 实现 `Planner` struct，`NewPlanner()` 返回 `*Planner`。在 `cmd/server/main.go` 通过 `engine.RegisterPlanner` 注册（与 socks5 第 378 行 `app.engine.RegisterPlanner(socks5.NewPlanner())` 模式一致）：

```go
app.engine.RegisterPlanner(gbt32960.NewPlanner())
```

> 注：方法是 `RegisterPlanner`，不是 `Register`。注册位置追加在 xmpp 之后（或按字母序插入）。

### 10.5 tshark 验证

生成 pcap 后用 tshark 验证：

```bash
tshark -r output.pcap -V -Y "tcp.port==10020" | grep -E "GBT32960|Malformed"
```

Wireshark 自带 gbt32960 解析器（`epan/dissectors/packet-gbt32960.c`），应能正确解析所有命令。若出现 `Malformed Packet` 标记，说明字段编码有误。

### 10.6 测试文件布局

```
trafficgen/internal/protocol/gbt32960/
├── gbt32960.go                    # Planner 实现
├── gbt32960_test.go               # 单元测试（§8 用例）
├── gbt32960_bcc_test.go           # BCC 算法独立测试（§9.1）
├── gbt32960_e2e_test.go           # 端到端测试（T-GBT-069/070/073）
├── gbt32960_multi_vehicle_test.go # 多车并发测试（T-GBT-057~060）
└── gbt32960_testpoints_test.go    # 测试点常量
```

---

## 11. 后续车联网协议模板说明

本节说明 JT808 / JT809 / JTT905 如何复用本文档结构。三个协议均基于 TCP，报文格式与 GBT32960 高度相似（起始符 + 命令 + 数据 + 校验），主要差异在字段细节。

### 11.1 模板复用规则

实现后续协议时，按以下步骤复用本文档：

1. **复制本文档** 为 `02-jt808-design.md` / `03-jt809-design.md` / `04-jtt905-design.md`。
2. **替换 §1 协议概述**：规范来源、默认端口、业务方向。
3. **替换 §2 报文格式**：起始符、字段表、校验算法（JT808 用异或+转义，JTT905 用 CRC16）。
4. **替换 §3 命令单元**：列出该协议的命令码与数据单元格式。
5. **调整 §4 Config 结构体**：字段按协议特性增减（如 JT808 有位置上报命令 0x0200，JT809 有链路管理命令 0x1001-0x1006）。
6. **重写 §5 状态机**：JT808 的状态机与 GBT32960 几乎一致（登入→上报→登出）；JT809 是平台间协议，有主链路/从链路双流模型，状态机更复杂。
7. **调整 §7 场景**：JT808 增加位置上报、电话回拨、信息服务等场景；JT809 增加上级平台/下级平台交互场景。
8. **重写 §8 用例**：保持 ≥ 30 条，覆盖正向/负向/边界。
9. **§9 审计清单**：按本协议特性增删（如 JT808 的转义字符处理是高风险点，需独立章节）。

### 11.2 JT808 关键差异

| 项目 | GBT32960 | JT808 |
|------|----------|-------|
| 规范 | GB/T 32960.3-2016 | JT/T 808-2019 |
| 默认端口 | 10020 | 7611 |
| 起始符 | `0x23 0x23` | `0x7E`（单字节） |
| 结束符 | 无 | `0x7E`（单字节） |
| 校验 | BCC 异或 | BCC 异或 + 转义（`0x7E`→`0x7D 0x02`，`0x7D`→`0x7D 0x01`） |
| VIN | 17 字节固定位置 | 在消息体中按消息 ID 不同位置不同 |
| 命令数 | 12 | ~30（0x0001-0x8101，含 0x0200 位置上报、0x0500 链路检测等） |
| 转义 | 无 | 有（高风险点，需独立测试章节） |

> JT808 的转义是最大实现风险：BCC 计算在转义**之前**，长度字段是转义**之前**的字节数。需在审计清单中独立列出。

### 11.3 JT809 关键差异

| 项目 | GBT32960 | JT809 |
|------|----------|-------|
| 规范 | GB/T 32960.3-2016 | JT/T 809-2019 |
| 默认端口 | 10020 | 8812 |
| 通信模型 | 车→平台（单流） | 平台→平台（双流：主链路 + 从链路） |
| 起始符 | `0x23 0x23` | `0x5B`（`[`） |
| 结束符 | 无 | `0x5D`（`]`） |
| 校验 | BCC 异或 | CRC16-CCITT + 转义 |
| 命令数 | 12 | ~20（0x1001-0x9302，含 0x1001 主链路登录请求、0x9001 主链路登录应答等） |
| 双流 | 无 | 主链路（下级→上级）+ 从链路（上级→下级），两条 TCP 流 |

> JT809 的双流模型是最大差异：一条 FlowSpec 不够，需要两条（主链路 + 从链路），且两条流有依赖关系（从链路在主链路登录成功后建立）。这是模板复用时状态机章节需大幅重写的部分。

### 11.4 JTT905 关键差异

| 项目 | GBT32960 | JTT905 |
|------|----------|--------|
| 规范 | GB/T 32960.3-2016 | JT/T 905-2014 |
| 默认端口 | 10020 | 10700 |
| 起始符 | `0x23 0x23` | `0x5B` |
| 结束符 | 无 | `0x5D` |
| 校验 | BCC 异或 | CRC16-CCITT + 转义 |
| 命令数 | 12 | ~15（0x0100-0x9201） |
| 业务场景 | 电动汽车 | 出租车（重点在定位上报与电召服务） |

> JTT905 与 JT809 报文格式几乎一致（同一起始符/结束符/校验），差异在命令集与业务场景。模板复用时可参考 JT809 的双流模型（JTT905 也是平台间协议）。

### 11.5 模板章节级复用矩阵

| 章节 | GBT32960 | JT808 | JT809 | JTT905 |
|------|----------|-------|-------|--------|
| §1 协议概述 | 原创模板 | 替换规范/端口 | 替换规范/端口 + 双流说明 | 替换规范/端口 |
| §2 报文格式 | 原创模板 | 替换起始符/结束符/转义 | 替换起始符/结束符/转义/CRC16 | 同 JT809 |
| §3 命令单元 | 原创模板 | 重写（命令更多） | 重写（双链路命令） | 重写 |
| §4 Config | 原创模板 | 增字段（位置上报参数） | 增字段（双链路配置） | 增字段 |
| §5 状态机 | 原创模板 | 几乎复用 | 大幅重写（双流） | 大幅重写（双流） |
| §6 Plan 输出 | 原创模板 | 复用 + 转义说明 | 复用 + 双流说明 | 复用 |
| §7 场景 | 原创模板 | 增场景（位置/电召） | 增场景（链路管理） | 增场景 |
| §8 用例 | 原创模板 | 重写（≥30 条） | 重写（≥30 条，含双流） | 重写 |
| §9 审计清单 | 原创模板 | 增转义风险 | 增双流时序风险 | 增转义风险 |
| §10 集成点 | 原创模板 | 复用 | 复用 + 双流注册 | 复用 |
| §11 模板说明 | 本节 | — | — | — |

### 11.6 共享代码机会

三个后续协议与 GBT32960 共享以下代码（可抽取为 `internal/protocol/telematics/common.go`）：

1. **BCD 编码/解码**（`YYMMDDHHMMSS` ↔ time.Time）
2. **VIN 补齐/校验**（17 字节右补 0x00，非 ASCII 检测）
3. **SIM 补齐**（20 字节右补 0x00）
4. **TCP 握手/挥手 emit 闭包**（与 sip.go 的 emit 模式一致，可抽公共 helper）
5. **时间默认值与序列化**（LoginTime 空 → time.Now()，BCD 转换）

> 工程取舍：是否抽取公共包取决于 4 个协议的相似度。若 JT808/JT809/JTT905 实现后字段差异大，宁可各自独立（复制 > 抽象）。GBT32960 实现时先独立，后续协议实现时再评估抽取。

---

## 附录 A：常量定义参考

```go
const (
    GBT32960DefaultPort    = 10020
    GBT32960DefaultTTL     = 64
    GBT32960DefaultMSS     = 1460
    GBT32960MinMSS         = 536
    GBT32960StartFlag      = 0x2323 // 2-byte start flag (起始符)
    GBT32960VINLen         = 17     // VIN 长度
    GBT32960SIMLen         = 20     // SIM/ICCID 长度
    GBT32960LoginDataBase  = 30     // 0x01 数据单元基础长度 = 6+2+20+1+1 (不含 n×m 编码)
    GBT32960LogoutDataLen  = 8      // 0x04 数据单元长度 = 6+2
    GBT32960RealtimeDataBase = 6    // 0x02 数据单元基础长度 = 6 采集时间 (不含信息体)
    GBT32960HeaderLen      = 24     // 2 + 1 + 1 + 17 + 1 + 2 报文头长度
    GBT32960BCCLen         = 1      // 校验码长度
    GBT32960DataUnitMaxLen = 65531  // 数据单元长度上限（65532-65535 保留）

    // Command units (命令单元)
    GBT32960CmdVehicleLogin    = 0x01 // 车辆登入
    GBT32960CmdRealtimeReport  = 0x02 // 实时信息上报
    GBT32960CmdReissueReport   = 0x03 // 补报信息上报
    GBT32960CmdVehicleLogout   = 0x04 // 车辆登出
    GBT32960CmdPlatformLogin   = 0x05 // 平台登入
    GBT32960CmdPlatformLogout  = 0x06 // 平台登出
    GBT32960CmdReissueReq      = 0x07 // 补发请求
    GBT32960CmdControl         = 0x08 // 控制命令
    GBT32960CmdParamQuery      = 0x09 // 参数查询
    GBT32960CmdParamSet        = 0x0A // 参数设置
    GBT32960CmdHeartbeat       = 0x0B // 平台心跳
    GBT32960CmdAck             = 0x0C // 平台确认

    // Response flags (应答标志)
    GBT32960RespSuccess    = 0x01 // 成功（写入下一上行报文应答标志）
    GBT32960RespError      = 0x02 // 错误
    GBT32960RespVINDup     = 0x03 // VIN 重复
    GBT32960RespNotSupp    = 0x04 // 命令不支持
    GBT32960RespNone       = 0xFE // 上行报文应答标志（所有上行 + 0x0C 报文头恒 0xFE）

    // Encrypt rules (数据加密方式)
    GBT32960EncNone   = 0x01 // 不加密
    GBT32960EncRSA    = 0x02 // RSA
    GBT32960EncAES128 = 0x03 // AES128
    GBT32960EncSM2    = 0x04 // SM2
    GBT32960EncSM4    = 0x05 // SM4
)
```

## 附录 B：参考报文 hex

### B.1 车辆登入（0x01，n=1, m=1）

```
23 23 01 FE                                   # start + cmd + resp (uplink)
4C 58 58 58 58 58 58 58 58 58 58              # VIN "LXXXXXXXXXXXXXXX1" (17B)
58 58 58 58 58 31
01                                             # encrypt = none
00 1F                                          # data len = 31 (6+2+20+1+1+1)
26 08 03 14 30 00                              # login time BCD (2026-08-03 14:30:00 +08)
00 01                                          # login serial number = 1 (WORD big-endian)
31 33 38 30 30 31 33 38 30 30 30 00 00 00 00  # SIM "13800138000" + 9 bytes pad
00 00 00 00 00
01                                             # rechargeable subsys count n=1
01                                             # subsys code length m=1
00                                             # subsys code (1 byte, 0x00)
XX                                             # BCC
```

### B.2 平台确认（0x0C，对 0x01 的应答）

```
23 23 0C FE                                   # start + cmd=0x0C + resp=0xFE (downlink 报文头恒 0xFE)
<VIN 17B>                                     # VIN (与被确认报文一致)
01                                             # encrypt = none
00 01                                          # data len = 1
01                                             # data = 0x01 (回填被确认的命令单元)
XX                                             # BCC
```

### B.3 实时上报（0x02，含信息类型 0x05 车辆位置信息体）

```
23 23 02 FE                                   # start + cmd + resp (uplink)
<VIN 17B>
01                                             # encrypt = none
00 10                                          # data len = 16 (6 采集时间 + 1 信息类型 + 9 信息体)
26 08 03 14 30 30                              # collect time BCD (2026-08-03 14:30:30 +08)
05                                             # info type = 0x05 车辆位置
01                                             #   定位状态 1B (bit0=有效)
0A 1B 2C 00                                    #   经度 4B DWORD big-endian (示例)
00 00 00 00                                    #   纬度 4B DWORD big-endian (示例)
XX                                             # BCC
```

> 注：0x02 数据单元**无**独立流水号/报警/状态头部字段。报警数据作为信息类型 0x07 信息体（5 字节 = 1B 等级 + 4B 标志）。位置信息体（0x05）**不含速度**——速度在整车数据（0x01）信息体中。

### B.4 平台心跳（0x0B）

```
23 23 0B FE                                   # start + cmd + resp (uplink)
<PlatformID 17B>                              # VIN 字段使用 PlatformID
01                                             # encrypt = none (继承 EncryptRule)
00 00                                          # data len = 0
XX                                             # BCC
```

总长 25 字节（24 头 + 1 BCC）。

### B.5 车辆登出（0x04）

```
23 23 04 FE                                   # start + cmd + resp (uplink)
<VIN 17B>
01                                             # encrypt = none
00 08                                          # data len = 8 (6 登出时间 + 2 登入流水号)
26 08 03 14 32 00                              # logout time BCD
00 01                                          # login serial number = 1 (与当次登入一致)
XX                                             # BCC
```

---

## 附录 C：术语表

| 英文 | 中文 | 说明 |
|------|------|------|
| VIN | 车辆识别码 | Vehicle Identification Number，17 字节 ASCII |
| BCC | 块校验字符 | Block Check Character，异或校验 |
| BCD | 二进制编码十进制 | Binary-Coded Decimal，每字节编 2 位十进制 |
| SIM | 用户识别卡 | Subscriber Identity Module，此处指车辆内置 SIM 卡号 |
| SOC | 剩余电量 | State of Charge |
| DC-DC | 直流变换器 | Direct Current to Direct Current converter |
| GBT | 国标推荐 | GuoBiao Tuijian（GB/T） |
| JT | 交通行业标准 | JiaoTong（JT/T） |
| MSS | 最大分段大小 | Maximum Segment Size，TCP 选项 |
| ISN | 初始序列号 | Initial Sequence Number，TCP |
| 4-tuple | 四元组 | src_ip, dst_ip, src_port, dst_port |
| PSH-ACK | TCP 标志 | Push + Acknowledgment |
| CRC16-CCITT | 循环冗余校验 | CRC16 with CCITT polynomial（JT809/JTT905 用） |
| RSA | 非对称加密算法 | Rivest–Shamir–Adleman |
| AES128 | 对称加密算法 | Advanced Encryption Standard 128-bit |

---

## 附录 D：修订历史

| 日期 | 版本 | 作者 | 说明 |
|------|------|------|------|
| 2026-08-03 | v1.0 | trafficgen 协议设计 agent | 初稿，作为 GBT32960 实现依据与 JT808/JT809/JTT905 模板 |
| 2026-08-03 | v1.1 | trafficgen 协议设计修复 agent | 对抗审计后修复：32 个问题全部修复（8 CRITICAL + 9 HIGH + 9 MEDIUM + 6 LOW）；新增 T-GBT-090~107 共 18 条测试；规范条目列已补全；详见末尾「## 修订记录」 |
| 2026-08-03 | v1.1.1 | trafficgen 重审返工 agent | 重审返工：3 项修正（N1 数据单元长度/BCC 范围、N2 IsTransBatteryData 默认信息体、N3 报警位序说明）；详见「## 修订记录 v1.1.1」 |
| 2026-08-03 | v1.1.2 | trafficgen 二轮审计修复 agent | 二轮对抗审计修复：14 个问题全部修复（3 CRITICAL + 5 HIGH + 4 MEDIUM + 2 LOW）；新增 T-GBT-064b/108 共 2 条测试；修正 0x0C resp 歧义、IsTransBatteryData 语义、BCC 范围 off-by-one、ACK 推进字节数、0x06 信息体长度等；详见末尾「## 修订记录 v1.1.2」 |
| 2026-08-03 | v1.1.3 | trafficgen 三轮审计返工 agent | 三轮审计返工：11 个问题全部修复（1 CRITICAL + 4 HIGH + 4 MEDIUM + 2 LOW）；新增 T-GBT-048a/096a 共 2 条测试；修正 0x0C resp 规范引用、VIN hex 19B→17B、LogoutTime 公式一致、MSS-25→MSS-31、T-GBT-081 Serial 字段引用、状态机顺序约束、RechargeableSubsysCodeLength 校验等；详见末尾「## 修订记录 v1.1.3」 |

---

## 修订记录（v1.1）

本节列出对抗审计（`audit/01-gbt32960-audit.md`）发现的 32 个问题及修复方式。

### CRITICAL（8 项全部修复）

| 编号 | 位置 | 问题 | 修复 |
|------|------|------|------|
| C1 | §3.1 / §8.2 | 0x01 数据单元误把登入流水号写为 20B 字符串「车辆序列号」，漏掉可充电储能子系统字段 | §3.1 改为 6 时间 + 2 流水号(WORD) + 20 ICCID + 1 n + 1 m + n×m 编码；T-GBT-007 改为「6+2+20+1+1+n×m」断言；Config 增 `RechargeableSubsysCount/CodeLength/Codes`；§7.1 hex 重写为 31 字节（n=1,m=1） |
| C2 | §3.2 / §8.2 | 0x02 数据单元误用 JT808 格式（6 时间+2 流水号+4 报警+2 状态+子项） | §3.2 改为「采集时间 6B + (1 信息类型 + N 信息体)*」循环结构；报警作为信息类型 0x07 信息体（5B）；§3.2.1 报警位域改为 bit0=温度差异/bit1=电池高温/.../bit31=厂商自定义；§3.2.2 删除 JT808 状态位域；T-GBT-008/008b 重写；车辆位置（0x05）改为 9B（定位状态+经度+纬度），**不含速度** |
| C3 | §3.4 | 0x04 数据单元仅 6B，漏掉登入流水号字段 | §3.4 改为 6B BCD 登出时间 + 2B 登入流水号 WORD；T-GBT-009 改为「6+2 = 8B」断言；Config 增 `LogoutSerialNumber`（空 = 继承 LoginSerialNumber）；B.5 hex 改为 data len=8 |
| C4 | §1.3 | 12 个命令标识无规范条目溯源，0x0B 心跳可能为 0x80 | §1.3 表格每行增加「规范条目」列；明确 v1 使用 0x01-0x0C，0x80 由 `UseExtendedPlatformCmd` 字段（v2）切换；§6.1 包序列同步 |
| C5 | §1.4 / §3.12 | 应答标志 0xFE 语义错（误以为仅「首发」），0x0C 报文头误用 0x01-0x04 | §1.4 改为「0xFE=所有上行报文+0x0C 报文头恒 0xFE；0x01-0x04 写入下一上行报文 resp 字段」；§3.12 重写 0x0C 语义；T-GBT-014b/015~018 重写；B.2 hex 改为 0xFE |
| C6 | §3.5 | 0x05 平台报文 VIN 字段误为全 0x00；12/20/16 长度无规范溯源 | §3.5 引用 §7.1；明确 VIN 用「城市邮政编码 + VIN 前三位」或 Config 字段 `PlatformID`；Config 增 `PlatformID`（17B）；T-GBT-012 加 PlatformID 断言 |
| C7 | §3.2.1 | 报警标志位定义与规范相反（bit31=电池高温应为 bit1） | §3.2.1 整表重写（bit0=温度差异/bit1=电池高温/.../bit19=热事件/bit31=厂商自定义）；Config `AlarmFlags` 改 `AlarmData{MaxAlarmLevel, GeneralAlarmFlags}`；T-GBT-038 改为「"00000002" → 00 00 00 02 大端（bit1 电池高温）」 |
| C8 | §3.2.2 | 状态标志位域是 JT808 字段误植 | §3.2.2 整节删除；Config `StatusFlags` 字段移除；T-GBT-041/042 删除，改为 T-GBT-040d 断言字段已删除 |

### HIGH（9 项全部修复）

| 编号 | 位置 | 问题 | 修复 |
|------|------|------|------|
| H1 | §2.3 / V4 | VIN 含 I/O/Q 字符未校验 | V3b 新增；T-GBT-030c 新增「VIN="LIO..." 报错」 |
| H2 | §2.4 | BCC 伪代码 packet 语义不清（可能误含 BCC 自身） | §2.4 注释明确 `buf MUST NOT include BCC`；§6.3 已用 `bccXOR(buf[2:])` 正确风格 |
| H3 | §2.5 | 数据单元长度上限 65531 未校验 | V28 新增；T-GBT-051 改为「数据单元长度上限 65531」；T-GBT-101/102 新增 |
| H4 | §5.3 | LoginAck 失败分支路径含糊 | §5.3 重写：resp=03 车辆不主动登出（直接 TCP teardown）；resp=02/04 转 ST_LOGOUT_SENT；T-GBT-016/017 增强断言 |
| H5 | §3.11 | 平台心跳加密方式未说明是否继承 | §3.11 明确「继承 PlatformLogin.EncryptRule」 |
| H6 | §4.1 | 缺扩展表 1 字段（connectId/loginoutSerialNumber/platformDomain/setPlatformDomain/maxAlarmLevel/isTransBatteryData） | Config 增 `ConnectID`/`LogoutSerialNumber`/`PlatformDomain`/`SetPlatformDomain`/`MaxAlarmLevel`/`IsTransBatteryData`；V25/V32/V33 新增校验；T-GBT-093~100 新增 |
| H7 | §6.1 | ACK 模式不对称（每条 PSH-ACK 后跟 pure ACK） | §6.1 改为「累计确认模型」+ pure ACK 仅握手第 3 步与挥手末步；T-GBT-052 包数重算为 16（含 RemoteControl）/14（不含） |
| H8 | §6.2 / V27 | MSS 分段约束未在 Validate 中实现 | V29 新增「CustomFields + 25 > MSS 报错」；T-GBT-103 新增 |
| H9 | §7.11 | strategy_vin 等概念字段与现有模式不符 | §7.11 改为顶层 Config 字段 pattern 策略，删除 strategy_ 前缀；Config 模板与 socks5 一致 |

### MEDIUM（9 项全部修复）

| 编号 | 位置 | 问题 | 修复 |
|------|------|------|------|
| M1 | §2.3 | VIN 补齐字符 0x00 vs 0x20 规范未明确 | §2.3 增 Config 字段 `VINPadByte`（默认 0x00，可选 0x20） |
| M2 | §3.1 / §4.5 | LoginTime 时区含糊（UTC vs 北京时间） | §4.5 改为「LoginTime 字符串时区即 BCD 时区」；T-GBT-044 加时区断言；T-GBT-044b 新增「UTC 输入 → UTC BCD」 |
| M3 | §4.4 V8/V9 | V8 接受 1-3 位 hex 但报警字段固定 4B；V9 死代码 | V8 改为「恰好 8 位 hex」；T-GBT-040b 新增「3 位 hex 报错」 |
| M4 | §4.4 V12 | LoginTime 接受无时区格式，时区歧义 | V12 改为「强制 RFC3339 时区」；V12b 新增字段范围校验；T-GBT-046b/046c 新增 |
| M5 | §4.4 V24 | InjectBCCError 索引越界仅 warning，违反 fail-fast | V24 改为「Plan 阶段检查 → error 中止」；T-GBT-004 改为「index=999 报错」 |
| M6 | §7.10 | 加密场景 BCC 计算范围未明确（对密文算还是明文算） | §7.10 增「BCC 始终对最终写入报文的数据单元字节（即 custom_fields 解码后的密文）计算」 |
| M7 | §7.12 | StatusChangeTrace AtReportIndex 重复行为未定义 | V25 增「AtReportIndex 重复 → 报错」；T-GBT-063b 新增 |
| M8 | §8 | 缺 0x07/0x09/0x0A 测试 | T-GBT-090/091/092 新增 |
| M9 | §8 T-GBT-073 | tshark 验证可能给虚假合规信号 | T-GBT-107 新增「tshark + 独立解析器双重验证」 |

### LOW（6 项全部修复或保留）

| 编号 | 位置 | 问题 | 修复 |
|------|------|------|------|
| L1 | §1.2 | 与 SIP/RTSP 对比章节价值有限 | 保留作为上下文（提供价值：明确 GBT32960 无 RTP 数据面） |
| L2 | §4.1 | Config 字段注释风格不一致 | §4.1 注释统一为「英文标识符 + 中文解释」风格（已检查全部字段） |
| L3 | §6.3 | 伪代码风格与项目 Go 代码略异 | 保留（Go 1.25 支持 `binary.BigEndian.AppendUint16`，可读性可接受） |
| L4 | §9 | 审计清单与 §8 用例编号交叉引用不明确 | §9 每行「覆盖用例」+「待补用例」已就位（部分「待补」改为已补） |
| L5 | §11 | 模板说明对 GBT32960 审计无直接价值 | 保留（用于后续 JT808/JT809/JTT905 协议） |
| L6 | 附录 D | 修订历史仅一行 | 增 v1.1 修订记录（即本节） |

### 修复后统计

- 修复问题数：32 / 32
- 新增测试用例：T-GBT-007b/008b/014b/029b/030b/030c/033b/033c/038b/040b/040c/040d/044b/046b/046c/063b/090~107（共计 30+ 条新增；调整的用例：T-GBT-004/005/007/008/009/011/012/014~018/030/034/038/044/050/051/061/062）
- 文档行数：原 1523 → 约 1800+（含新增测试与修订记录）
- 内部一致性：通过（0x01 8B → 0x02 25B → 0x04 8B 三处格式与 hex 附录一致；0x0C 报文头恒 0xFE 与 §1.4/§3.12/§5.3/§6.1/T-GBT-014b 一致）

---

## 修订记录 v1.1.1（2026-08-03 重审返工）

- **N1｜§3.1、§6.1、§7.1、§8（T-GBT-005/T-GBT-007）、附录 B.1**：更正 n=1、m=1 时数据单元长度为 31B；登入报文总长更正为 56B；同步修正 TCP 序列号推进、长度字段 `00 1F` 与 BCC 覆盖范围 `bytes 2..54`（cmd 到最后一个 data 字节，即偏移 24+N-1=54；不含起始符 2 字节、不含 BCC 自身 1 字节）。
- **N2｜§3.2.3、T-GBT-064**：明确 CustomFields 与 AlarmData 均为空时，IsTransBatteryData=true（默认）→ 生成 0x01 整车数据信息体；IsTransBatteryData=false → 仅生成 0x05 车辆位置信息体（与 §4.1 Config 字段语义一致）。T-GBT-064 断言 true 路径以 0x01 开头；新增 T-GBT-064b 断言 false 路径以 0x05 开头且不含 0x01。
- **N3｜§3.2.1**：更正报警位序说明为按大端字节序最低字节的最低位为 bit0（传统网络位序）。

---

## 修订记录 v1.1.2（2026-08-03 二轮对抗审计返工）

本节列出二轮对抗审计发现的 14 个问题（3 CRITICAL + 5 HIGH + 4 MEDIUM + 2 LOW）及修复方式。

### CRITICAL（3 项全部修复）

| 编号 | 位置 | 问题 | 修复 |
|------|------|------|------|
| C1 | §3.2 信息类型表 | 0x06 极值数据信息体长度标注为 14，但字段 sum = 1+2+2+1+2+2+1+1+1+1+1+1 = 16 字节 | §3.2 表格 0x06 行长度列 14 → 16，与字段定义一致 |
| C2 | §8.2 T-GBT-008b | hex `070100000002050A1B2C00000000` 仅 15 字节，0x05 车辆位置信息体应 9B（1+4+4）但 hex 仅给 8B | T-GBT-008b hex 改为 `07010000000205000A1B2C0000000000`（16 字节 = 1+5+1+9），并补充 0x05 信息体长度断言 |
| C3 | §4.1 Config / §3.2.3 / T-GBT-064 / N2 | IsTransBatteryData 语义三处矛盾：Config 说 false→仅 0x05 位置信息体，T-GBT-064/N2 说 false→0x01 整车数据信息体 | §3.2.3 重写三种填充方式与 IsTransBatteryData 的交互；T-GBT-064 改为断言 true 路径（0x01 开头）；新增 T-GBT-064b 断言 false 路径（0x05 开头，不含 0x01）；N2 修订记录同步更正 |

### HIGH（5 项全部修复）

| 编号 | 位置 | 问题 | 修复 |
|------|------|------|------|
| H1 | §7.1 hex 示例 / §修订记录 N1 | BCC 范围标注 `bytes 2..53` off-by-one（应为 2..54，N=31 时最后一个 data 字节在偏移 24+31-1=54） | §7.1 hex 注释改为 `bytes 2..54`；N1 修订记录同步更正；§7.15 BCC 范围表述改为「偏移 2 到 24+N-1」并给出 0x01 具体示例（bytes 2..54） |
| H2 | §8.12 T-GBT-070 / §9.3 | ACK 推进字节数三处不一致：T-GBT-070 说 71、§9.3 说 57、§6.1 说 56（25+31=56 为正确值） | T-GBT-070 描述 71 → 56；§9.3 描述 57 → 56；与 §6.1（25+31=56）一致 |
| H3 | §4.5 默认值表 | Reports[i].AlarmData/CustomFields 仅列 2 步（继承 Config → StatusChangeTrace 覆盖），遗漏第 3 步（Reports[i] 自身非空则最终覆盖）；§7.12 有完整 3 步 | §4.5 表格 Reports[i].AlarmData/CustomFields 行改为三步覆盖表述，与 §7.12 一致（user > trace > auto > none） |
| H4 | §5.3 异常分支 / §8 | ST_LOGOUT_SENT 异常分支（resp=02 登出失败）无对应测试用例 | 新增 §8.21 章节，添加 T-GBT-108 测试用例：ResponseFlags="02"，断言登出失败后不重试、不插入额外 0x04 重发、直接 TCP 挥手 |
| H5 | §3.12 / §6.1 / §1.4 | 0x0C resp 表述含歧义：§3.12「成功：0x0C 数据单元 = 所确认命令单元」暗示数据单元值指示成功；§6.1 `resp=0xFE, data=0x01` 并列易误解；§1.4「下行应答报文」表述混乱 | §3.12 重写：明确 0x0C 数据单元**总是**等于所确认命令单元（无论成功/失败），成功/失败语义**只**通过下一上行报文 resp 字段承载；§6.1 第 4 包描述加注「报文头 resp=0xFE [恒 0xFE，不承载成功/失败]」；§1.4 表述改为「应答结果值（写入下一上行报文应答标志字段）」并明确 0x0C 数据单元不承载成功/失败 |

### MEDIUM（4 项全部修复）

| 编号 | 位置 | 问题 | 修复 |
|------|------|------|------|
| M1 | §9.5 | 引用不存在的 T-GBT-071b（应为 T-GBT-103，且与下行 T-GBT-103 重复） | §9.5「CustomFields 超 MSS」行的覆盖用例改为 T-GBT-103；删除紧随的重复「CustomFields 超 MSS-25」行 |
| M2 | §9.2 | 引用不存在的 T-GBT-023b（VIN 含 I/O/Q 实际测试为 T-GBT-030c） | §9.2「VIN 含 I/O/Q」行覆盖用例 T-GBT-023b → T-GBT-030c |
| M3 | §7.15 BCC 范围表述 | 「偏移 2 到 N-2」中 N 语义不清（与 §2.4 中 N=数据单元长度混用）；N=总报文长度时正确，但与 §2.4 不一致 | §7.15 表述改为「偏移 2 到 24+N-1（N 为数据单元长度）」，并给出 0x01 具体示例（N=31 → bytes 2..54，共 53 字节，BCC 在 byte 55） |
| M4 | 附录 B.3 实时上报 hex | 0x05 车辆位置信息体 hex 实际 9B（1 状态 + 4 经度 + 4 纬度），但 data len 标 `00 0F = 15` 且注释「8 信息体」，应为 16 字节 / 9 信息体 | 附录 B.3 data len 改为 `00 10`（16），注释「8 信息体」改为「9 信息体」（6 采集时间 + 1 信息类型 + 9 信息体 = 16） |

### LOW（2 项全部修复）

| 编号 | 位置 | 问题 | 修复 |
|------|------|------|------|
| L1 | §8 测试用例计数 | 文档头/修订记录未更新测试用例总数（实际 123 条用例行，含 T-GBT-001~108 及 17 个子用例） | 文档头新增「测试用例数：123 条」行；附录 D v1.1.2 行更新测试用例计数；新增 T-GBT-064b、T-GBT-108 共 2 条 |
| L2 | §1.4 应答标志表述 | 「下行应答报文（0x0C 之外的应答报文，或承载在 0x0C 数据单元内的应答结果）」表述错误——0x0C 数据单元**不**承载应答结果（只回填所确认命令单元） | §1.4 标题改为「应答结果值（写入下一上行报文应答标志字段，**不**写入 0x0C 报文头/数据单元）」；附注明确 0x0C 数据单元 = 所确认命令单元，不承载成功/失败 |

### 修复后统计

- 修复问题数：14 / 14（3 CRITICAL + 5 HIGH + 4 MEDIUM + 2 LOW）
- 新增测试用例：T-GBT-064b（IsTransBatteryData=false 仅输出位置）、T-GBT-108（ST_LOGOUT_SENT 登出失败异常分支），共 2 条
- 调整用例：T-GBT-008b（hex 长度修正）、T-GBT-064（语义改为 true 路径）、T-GBT-070（ACK 推进 71→56）
- 文档行数：原 1876 → 1938（含 v1.1.2 修订记录与新增测试章节 §8.21）
- 内部一致性：通过（0x06 信息体长度 16 字节与字段 sum 一致；T-GBT-008b hex 16 字节与 0x05 信息体 9B 规范一致；IsTransBatteryData 三处语义一致；BCC 范围 bytes 2..54 与 §2.4 偏移 2..24+N-1 一致；ACK 推进 56 与 §6.1 25+31=56 一致；0x0C resp 表述 §1.4/§3.12/§6.1 三处一致）

---

## 修订记录 v1.1.3（2026-08-03 三轮审计返工）

本节列出三轮审计发现的 11 个问题（1 CRITICAL + 4 HIGH + 4 MEDIUM + 2 LOW）及修复方式。

### CRITICAL（1 项全部修复）

| 编号 | 位置 | 问题 | 修复 |
|------|------|------|------|
| C1 | §3.12 / §1.4 / §5.3 | 0x0C 报文头应答标志恒 0xFE 与 GB/T 32960.3-2016 §7.8 规范存在潜在冲突；v1.1.2 H5 修复仅清理了数据单元歧义，未触及报文头应答标志的规范要求 | §3.12 新增「规范依据」段，明确引用 GB/T 32960.3-2016 §7.8：0x0C 是平台对车辆上行报文的应答，0x0C 本身即为新的「命令发起方」，应答标志恒为 0xFE；规范不允许 0x0C 报文头应答标志字段填 0x01-0x04；T-GBT-011/013/014b/015/016/017/018 等用例已验证此约束 |

### HIGH（4 项全部修复）

| 编号 | 位置 | 问题 | 修复 |
|------|------|------|------|
| H1 | §7.1 hex | VIN 字段 19B vs 规范 17B（多 2 字节 X），导致后续偏移全部错位 | §7.1 hex dump VIN 字段从 19 字节修正为 17 字节（4C + 15×58 + 31），与 §2.3 规范一致 |
| H2 | §4.5 / §7.2 / T-GBT-048 | LogoutTime 默认公式三处不一致：§4.5 与 T-GBT-048 给出 LoginTime + Σ(Reports 间隔) + 60s（= 14:32:30），§7.2 给出 14:32:00 | §7.2 时间序列的登出时间从 14:32:00 修正为 14:32:30（LoginTime + 150s = 14:30:00 + 90s + 60s），与 §4.5 公式与 T-GBT-048 一致；T-GBT-048 描述补充 N=3 时 = LoginTime + 150s 示例 |
| H3 | V29 / §6.2 | MSS 校验公式遗漏 6 字节采集时间：应为 MSS-31（含 6 字节采集时间），实际 MSS-25（不含），允许上限过大 | V29 公式从 `CustomFields + 25 > MSS` 修正为 `CustomFields + 31 > MSS`（含 6 字节采集时间）；§6.2 约束从 MSS-26 修正为 MSS-31；T-GBT-103 阈值从 1436 修正为 1430；§7.14 边界表与 §9.5 审计清单同步修正 |
| H4 | T-GBT-081 | 「补报流水号 100/101/102」引用 GBT32960Report struct 中不存在的 Serial 字段（v1.1.2 V14 已弱化 Serial 字段） | T-GBT-081 改用 Time 字段（采集时间）描述不连续性：ReissueReports 的 Time 为历史时间（14:00:00/14:00:30/14:01:00），与 Reports 的当前时间（14:30:30/14:31:00/14:31:30）不连续；明确 0x03 数据单元仅含采集时间 + 信息体循环，无独立流水号字段 |

### MEDIUM（4 项全部修复）

| 编号 | 位置 | 问题 | 修复 |
|------|------|------|------|
| M1 | 附录 B.1 | VIN hex 18B vs 17B（多 1 字节），与 H1 类似但位置不同 | 附录 B.1 VIN hex 从 18 字节修正为 17 字节（4C + 15×58 + 31），与 §2.3 规范一致 |
| M2 | §4.4 | 缺少 LogoutTime ≥ LoginTime 验证 | 新增 V34 校验规则：LogoutTime < LoginTime（两者均已配置且非空）时报错 `gbt32960: LogoutTime %q must be >= LoginTime %q`；新增 T-GBT-048a 测试用例 |
| M3 | §6.2 / V29 | MSS 约束表述 MSS-26 vs MSS-25 不一致（与 H3 关联） | 修正 H3 时同步统一表述为 MSS-31（§6.2 与 V29 一致） |
| M4 | §5.1 状态机图 | ST_REPORTING → ST_REMOTE_CTRL → ST_REISSUE 顺序关系未明确 | §5.1 状态转换说明后新增「状态顺序约束」段：固定顺序为 ST_REPORTING → ST_REMOTE_CTRL → ST_REISSUE → ST_LOGOUT_SENT；图示并列分支仅为简化，不表示可交换顺序；v1 不支持 RemoteControl 在 Reports 中间插入或 ReissueReports 在 Reports 之前插入 |

### LOW（2 项全部修复）

| 编号 | 位置 | 问题 | 修复 |
|------|------|------|------|
| L1 | §4.1 line 441-444 | GBT32960Report「Serial field is kept」注释与 struct 定义不符（V14 已弱化 Serial 字段，但注释还说 "kept"） | 注释从「The Serial field is kept for backward compat but only used for V14 range check (1-65531)」修正为「The Serial field is deprecated, use ReportTime for ordering. V14 range check (1-65531) applies only to the 0x01 LoginSerialNumber field」 |
| L2 | §4.4 | 缺少 RechargeableSubsysCodeLength < 1 验证 | 新增 V35 校验规则：RechargeableSubsysCodeLength < 1 时报错 `gbt32960: RechargeableSubsysCodeLength %d must be >= 1`；新增 T-GBT-096a 测试用例 |

### 修复后统计

- 修复问题数：11 / 11（1 CRITICAL + 4 HIGH + 4 MEDIUM + 2 LOW）
- 新增测试用例：T-GBT-048a（LogoutTime 早于 LoginTime）、T-GBT-096a（RechargeableSubsysCodeLength=0），共 2 条
- 调整用例：T-GBT-048（补充 N=3 示例）、T-GBT-081（Serial 字段→Time 字段）、T-GBT-103（MSS-25→MSS-31 阈值）
- 新增校验规则：V34（LogoutTime ≥ LoginTime）、V35（RechargeableSubsysCodeLength ≥ 1）
- 文档行数：原 1938 → 约 1980+（含 v1.1.3 修订记录与新增测试用例）
- 内部一致性：通过（VIN hex 17B 与 §2.3 规范一致；LogoutTime 公式 §4.5/§7.2/T-GBT-048 三处一致；MSS 约束 §6.2/V29/T-GBT-103/§7.14/§9.5 五处一致为 MSS-31；T-GBT-081 不再引用不存在的 Serial 字段；状态机顺序约束 §5.1 明确；V34/V35 新增校验与 T-GBT-048a/096a 对应）





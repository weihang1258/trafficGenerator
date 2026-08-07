# RIP 协议设计与测试用例

**协议名称**：RIP v1 / v2 / RIPng（Routing Information Protocol，路由信息协议）
**默认端口**：UDP 520（RIP v1/v2）、UDP 521（RIPng）
**规范来源**：RFC 1058（RIP v1）、RFC 2453（RIP v2）、RFC 2080（RIPng）、RFC 4822（MD5 认证）
**项目状态**：未实现（见 `docs/protocol-designs/00-unimplemented-list.md` #10）
**文档版本**：1.1.5（2026-08-04）

## 1. 协议概述

RIP（Routing Information Protocol，路由信息协议）是基于 UDP 的距离矢量（distance-vector）内部网关协议，分两个版本：

- **RIP v1**（RFC 1058）：仅 IPv4，路由条目无子网掩码（靠接口掩码推断），更新报文广播到 `255.255.255.255`。
- **RIP v2**（RFC 2453 / RFC 1723）：IPv4，路由条目携带子网掩码与下一跳，支持路由标签（Route Tag），支持明文/MD5 认证，更新报文默认组播到 `224.0.0.9`，亦可单播。
- **RIPng**（RFC 2080）：IPv6 版本，UDP 521，组播 `FF02::9`，条目用前缀长度替代掩码，无认证（依赖 IPsec）。

trafficgen 把 RIP 规划器（Planner）实现为 `internal/protocol/rip/rip.go`，输出 `PacketConfig` 流（UDP 单数据报），由 worker 转成以太网帧。本设计文档约束 Planner 的字段集、报文装配规则、状态机分支与测试边界。

**关键约束**：
- 传输层 UDP（RIP/RIP v2 端口 520；RIPng 端口 521）。
- 一个 RIP 报文 = 1 个 UDP 数据报，最多承载 25 个 Route Entry（RIPng 同样 25）。
- 超过 25 条路由必须拆分多包，每包独立 4 字节 RIP 头，共享同一 4-tuple。
- 多路由器场景：每个路由器 = 独立 4-tuple（独立 SrcIP/SrcPort），planner 不在同 4-tuple 内复用多路由器。
- 认证条目占用第一个 Route Entry 槽位（即 25 entry 中 1 个用于认证时，最多 24 条路由）。
- trafficgen 不计算路由表的真实收敛；用户在 Config 中显式给出每条路由的 metric、下一跳，planner 透传上链。
- MD5 认证仅做字段占位（不计算真实 HMAC，符合 trafficgen "wire-format correct, crypto-irrelevant" 约定，与 OpenVPN/SNMP v3 处理一致）。

## 2. 报文格式

### 2.1 RIP 公共头（4 字节，RIP v1/v2/RIPng 共用）

| 偏移 | 长度 | 字段 | 取值 | 说明 |
|------|------|------|------|------|
| 0 | 1 | Command | 1=Request, 2=Response | 9=Update Request（v2 私有，可选），10=Update Response（v2 私有，可选），本设计仅支持 1/2 |
| 1 | 1 | Version | 1=RIP v1（RFC 1058），2=RIP v2（RFC 2453），1=RIPng（RFC 2080，复用 version=1 但仅在 `version='ng'`、UDP 521、IPv6 下解释） | Version 字节单独不能识别 RIP v1 与 RIPng——两者均=1，必须结合 UDP 端口（520 vs 521）与 IP 协议族（IPv4 vs IPv6）区分 |
| 2 | 2 | Domain / MustBeZero | RIP v1/v2：0；RIPng：0 | RFC 1058 称 MustBeZero；RFC 2453 称 Unused；RFC 2080 称 MustBeZero |

### 2.2 RIP v1 Route Entry（20 字节）

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 2 | Address Family Identifier (AFI) | IPv4=2；Request 全量路由时=0x0000（见 §6.1） |
| 2 | 2 | MustBeZero | 0 |
| 4 | 4 | IP Address | 网络地址 |
| 8 | 4 | MustBeZero | 0（v1 不携带掩码） |
| 12 | 4 | MustBeZero | 0（v1 不携带下一跳） |
| 16 | 4 | Metric | 1-16，16=不可达 |

### 2.3 RIP v2 Route Entry（20 字节）

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 2 | AFI | IPv4=2；认证条目=0xFFFF |
| 2 | 2 | Route Tag | 路由标签，区分内部/外部路由（EGP 引入） |
| 4 | 4 | IP Address | 网络地址 |
| 8 | 4 | Subnet Mask | IPv4 掩码（0.0.0.0=缺省路由） |
| 12 | 4 | Next Hop | 下一跳 IP；0.0.0.0=发送者即下一跳 |
| 16 | 4 | Metric | 1-16，16=不可达；0 非法 |

### 2.4 RIP v2 认证条目（20 字节，占第一个 Route Entry 槽位）

**本表仅适用于 simple 类型**。md5 类型字段布局不同，见 §2.5。

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 2 | AFI | 0xFFFF（认证标记） |
| 2 | 2 | Authentication Type | 0x0002=明文（Simple Password），0x0003=MD5（RFC 4822，Keyed-MD5） |
| 4 | 16 | Authentication Data | 明文：16 字节密码（不足补 0，超出报错，与 T-ERR-10 一致）；MD5：见 §2.5 |

### 2.5 RIP v2 MD5 认证条目（RFC 4822）

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 2 | AFI | 0xFFFF |
| 2 | 2 | Auth Type | 0x0003（认证 entry 的类型字段；与 trailer header 的 Type=0x0001 属于不同结构，二者不可混淆） |
| 4 | 2 | RIPv2 Packet Length (RFC 4822 §2.1) | RFC 4822 §2.1 定义的 16-bit offset（偏移），表示从 RIP 头起始到 regular RIPv2 packet 结束的字节数（数值上等于 regular packet 总长度，即 `PacketLength = 4 + 20 × entry_count`，其中 `entry_count = 认证 entry + 普通路由条目`）。不包含 trailer header 和 digest。 |
| 6 | 1 | Key ID | 密钥标识 |
| 7 | 1 | Auth Data Len | 摘要长度。RFC 4822 §2.1：默认 16（MD5 输出），但允许其他算法（如 SHA-256=20）透传非 16 值。Validate 仅校验 >0，不强制 =16。 |
| 8 | 4 | Sequence Number | 单调递增序列号（防重放） |
| 12 | 8 | MustBeZero | 0 |

MD5 认证 trailer 末尾结构（RFC 4822 §2.1）：

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| Trailer+0 | 2 | Auth Marker | 0xFFFF（RIP-2 认证标记） |
| Trailer+2 | 2 | Type | 0x0001（trailer header 的类型字段；与认证 entry 的 Auth Type=0x0003 属于不同结构，二者不可混淆） |
| Trailer+4 | AuthDataLen | Auth Data | MD5 摘要（或 SHA-256 等算法输出），长度 = Auth Data Len（默认 16） |

trafficgen 在摘要位置填 0xAA（与 OpenVPN/SNMP v3 一致），不计算真实 HMAC。若只实现标准 MD5，Validate 必须强制 `AuthDataLen=16`；AuthDataLen 非 16 是 trafficgen 私有扩展，不宣称为标准 MD5。Auth Data Len 字段定义见 RFC 4822 §2.1。

### 2.6 RIPng Route Entry（20 字节，RFC 2080）

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 16 | IPv6 Prefix | 16 字节 IPv6 前缀 |
| 16 | 2 | Route Tag | 2 字节路由标签（RFC 2080 §2.1.1） |
| 18 | 1 | Prefix Length | 0-128 |
| 19 | 1 | Metric | 1-16，16=不可达 |

注：RFC 2080 §2.1.1 明确 Route Tag 是 2 字节（不是某些 v1 文档误称的 1 字节）。
条目总长度 = 16 + 2 + 1 + 1 = 20 字节，与 RIP v1/v2 Route Entry 对齐。

### 2.7 UDP 封装

| 字段 | RIP v1 | RIP v2 | RIPng |
|------|--------|--------|-------|
| DstPort | 520 | 520 | 521 |
| SrcPort | 520（响应）/ 任意（请求，临时端口） | 520（响应）/ 任意（请求） | 521（响应）/ 任意（请求） |
| 广播/组播 DstIP | 255.255.255.255 | 224.0.0.9 | FF02::9 |
| 单播 DstIP | 用户指定 | 用户指定 | 用户指定 |

**TTL=1 强制**：RIP 组播/广播包 TTL=1（限本链路），单播包可继承 FlowSpec.TTL。Planner 在 multicast=true 时强制 spec.TTL=1（即使 FlowSpec.TTL=0 默认 64 也覆盖为 1）。

**多路由器场景 src_port 选择（§6.13 配套）**：RFC 2453 §3.6 规定 RIP Response 源端口 = 520，但多路由器场景需要 src_port 区分 4-tuple。trafficgen 采用非 RFC 但合理的策略：用户显式设了 src_port（如 52001/52002/52003）时透传该值；未设则继承 FlowSpec.SrcPort，若 FlowSpec.SrcPort 也未设，则由 worker 端的 4-tuple 分配器按 router 索引动态分配（默认从 52001 起递增分配，确保多路由器端口唯一）。这是违反 RFC 的非标行为，目的是让 trafficgen 能用 4-tuple 区分多路由器并保证 PacketWorker 按 4-tuple 保序。若 Wireshark 按 RFC 严格校验，会显示"源端口非标准"。

### 2.8 报文总长度

#### 2.8.1 无认证

- RIP 头 4B + N×20B Route Entry，N ≤ 25。
- 单包最大：4 + 25×20 = 504 字节（应用层）。
- UDP 层加 8 字节 → 512 字节。
- IP 层加 20 字节 → 532 字节。
- 以太网层加 14 字节 → 546 字节（< 1500 MTU，不会触发 IP 分片）。

#### 2.8.2 MD5 认证（RFC 4822）

- 首包 entry 数上限：24 条路由（认证 entry 占 1 个槽位，25-1=24）。
- 首包 Payload = 4 + 1×20 + 24×20 = 4 + 500 = 504B（regular RIPv2 packet 部分），再加 4B trailer header（FF FF 00 01）+ AuthDataLen B 摘要占位。
- 完整 Payload 长度公式：`Payload = 4 + 20 × entry_count + 4 + AuthDataLen`。
  - AuthDataLen=16（标准 MD5）：完整 Payload = 504 + 4 + 16 = 524B。
  - AuthDataLen=20（SHA-256 扩展）：完整 Payload = 504 + 4 + 20 = 528B。
- UDP 层：完整 Payload + 8B；IP 层：UDP + 20B；以太网层：IP + 14B。
- 以 24 条路由为例：
  - AuthDataLen=16：UDP=532B，IP=552B，以太网=566B。
  - AuthDataLen=20：UDP=536B，IP=556B，以太网=570B。
- 多包场景：首包 1 认证 + 24 路由（满 25 entry 槽位），后续包无认证 entry 且无认证 trailer（RFC 4822 §2.1 规定 MD5 认证 trailer 仅出现在首包），每包仍 ≤ 25 entry（504B regular RIPv2 部分）。后续包 Payload = 4 + 20×M，其中 M = 后续包中的 route entry 数（M ≤ 25）。

## 3. Config 结构体设计

在 `internal/core/types.go` 新增 `RIPConfig`：

```go
type RIPConfig struct {
    // Version (版本): "v1" (RFC 1058), "v2" (RFC 2453, 默认), "ng" (RFC 2080).
    // 空字符串默认 "v2" (design §5 S1: user > auto > none)。
    Version string `json:"version,omitempty"`

    // Command (命令): "request" (1) 或 "response" (2)。空默认 "response"。
    // Request 全量路由的特殊 entry (AFI=0x0000, metric=16/infinity) 由 Scenario="request_full"
    // 自动生成；普通 Request 用户在 Routes 中显式列出。
    // 注意：AFI=0xFFFF 在 RFC 2453 §2.1.1 中专用于认证条目，不应用于全量请求。
    Command string `json:"command,omitempty"`

    // Domain (路由域): 2 字节 RIP 头保留字段。默认 0。RIP v2 实现可作
    // Routing Domain 区分（非标准），trafficgen 透传。
    Domain uint16 `json:"domain,omitempty"`

    // Routes (路由条目): 用户显式给出的路由表。空 Routes 由 Scenario
    // 决定默认行为 (Request 全量路由 / Response 0 路由 / 25 路由示例)。
    Routes []RIPRoute `json:"routes,omitempty"`

    // Auth (认证): nil = 不认证；非 nil 按 Type 处理。仅 RIP v2 生效。
    // RIP v1/RIPng 设置 Auth 非 nil 时 Validate 报错。
    Auth *RIPAuth `json:"auth,omitempty"`

    // Multicast (组播): true 时 DstIP 自动设为 224.0.0.9 (v2) / FF02::9 (ng)；
    // v1 时强制广播 255.255.255.255 (忽略 DstIP)。false 时使用 DstIP。
    // 空默认 false (单播) — 与 RADIUS/SOCKS 等 UDP 协议一致，避免静默
    // 发往组播造成网络设备告警。
    Multicast bool `json:"multicast,omitempty"`

    // Scenario (场景): 控制默认路由生成。可选值见 §6。
    // 空 + Routes 非空 = 透传 Routes。
    // 空 + Routes 空 + Command="response" = "response_default" (5 条示例路由)。
    // 空 + Routes 空 + Command="request" = "request_full" (AFI=0x0000 单 entry, RFC 2453 §3.9.1)。
    Scenario string `json:"scenario,omitempty"`

    // Routers (多路由器并发): M 个路由器的独立 4-tuple 模板。每元素生成
    // 一条独立 FlowSpec，共享 RIPConfig 内容但各自 SrcIP/SrcPort 独立。
    // nil = 单路由器 (FlowSpec 自身的 4-tuple)。详见 §6.13。
    Routers []RIPRouter `json:"routers,omitempty"`

    // Rounds (轮数): 同一 4-tuple 上 Request/Response 交换次数。默认 1。
    // 用于模拟周期更新 (Rounds=N 即发 N 个 Response)。
    Rounds int `json:"rounds,omitempty"`

    // TriggeredUpdate (触发更新): true 时跳过 Request 阶段，直接发 Response。
    // 用于 §6.11 触发更新场景 (拓扑变化立即发)。
    TriggeredUpdate bool `json:"triggered_update,omitempty"`

    // SplitHorizon (水平分割): true 时 Routes 中 NextHop==接收方 IP 的条目
    // 被过滤不发 (§6.10)。Planner 在 Plan 阶段过滤。
    // 注：与 Multicast=true 互斥——组播无具体接收方，SplitHorizon 跳过过滤（§8.5）。
    // Validate 对 {SplitHorizon=true, Multicast=true} 组合发出警告。
    SplitHorizon bool `json:"split_horizon,omitempty"`

    // PoisonReverse (毒化反转): true 时 Routes 中 NextHop==接收方 IP 的条目
    // 改 metric=16 发回 (§6.10 增强)。覆盖 SplitHorizon。
    // 注：组播下不生效——组播无具体接收方，SplitHorizon 与 PoisonReverse 均跳过过滤（与 SplitHorizon 一致，见 §8.5）。Validate 对 {PoisonReverse=true, Multicast=true} 组合发出警告。
    PoisonReverse bool `json:"poison_reverse,omitempty"`
}

// RIPRoute 描述一条路由条目 (RIP v1/v2/RIPng 通用，按 Version 取用对应字段)。
type RIPRoute struct {
    // AFI (地址族): 0=自动 (默认)。合法显式值仅 = 2 (IPv4)。
    // AFI=0xFFFF 在 RFC 2453 §2.1.1 中专用于认证条目 (Authentication Type)，
    // 不应在 RIPRoute.AFI 显式设置——若用户设 0xFFFF，Validate 报错。
    // RIP v2 认证条目由 Auth 字段控制，不在此设置。
    // 全量请求 entry (AFI=0x0000) 由 Scenario="request_full" 自动生成，不需要用户配置。
    // RIPng 忽略此字段 (固定 IPv6)。
    AFI uint16 `json:"afi,omitempty"`

    // RouteTag (路由标签): 2 字节。RIP v2/RIPng 使用，RIP v1 透传 0。
    RouteTag uint16 `json:"route_tag,omitempty"`

    // IPAddr (IP 地址): IPv4 点分十进制 ("10.0.0.0") 或 IPv6 (RIPng)。
    // 0.0.0.0/0 = 缺省路由 (RIP v1/v2)。
    IPAddr string `json:"ip_addr"`

    // SubnetMask (子网掩码): RIP v2 必填，IPv4 点分十进制。RIP v1 透传 0。
    // RIPng 忽略，使用 PrefixLen。
    SubnetMask string `json:"subnet_mask,omitempty"`

    // PrefixLen (前缀长度): RIPng 必填 (0-128)。RIP v1/v2 忽略 (用 SubnetMask)。
    PrefixLen uint8 `json:"prefix_len,omitempty"`

    // NextHop (下一跳): IPv4/IPv6 字符串。0.0.0.0/:: = 发送者即下一跳。
    // RIPng 忽略此字段（RFC 2080 §2.1.1 无 Next Hop 字段，下一跳隐含为发送方）；若用户为 RIPng 设置 NextHop，Validate 报错或忽略（实现选报错，更严格）。
    NextHop string `json:"next_hop,omitempty"`

    // Metric (度量): 1-16。0 非法，>16 Validate 报错（与 §6.14 T-EDGE-4/5 一致；
    // 不做静默截断）。16=不可达。uint8 可存 0-255，Validate 拒绝 0 与 17-255。
    Metric uint8 `json:"metric"`
}

// RIPAuth 描述 RIP v2 认证。RIP v1/RIPng 不支持 (Validate 报错)。
type RIPAuth struct {
    // Type (类型): "simple" (0x0002, 明文) 或 "md5" (0x0003, RFC 4822)。
    // 空 = "simple"。
    Type string `json:"type,omitempty"`

    // Password (密码): simple 类型，最多 16 字节，不足补 0，超出报错（与 T-ERR-10 一致）。
    // md5 类型忽略，使用 KeyID + AuthDataLen + SequenceNumber。
    Password string `json:"password,omitempty"`

    // KeyID (密钥 ID): md5 类型，1 字节。
    KeyID uint8 `json:"key_id,omitempty"`

    // AuthDataLen (摘要长度): md5 类型，nil 表示缺省并默认 16；非 nil 时必须 >0。RFC 4822 §2.5。
    // v1.1.1 破坏性变更：uint8 → *uint8，以区分缺省与显式 0；JSON null 表示缺省。
    // Marshal 行为：当 AuthDataLen == nil 时 JSON 输出 "auth_data_len": null（不显示默认化，与 SOCKS5/RADIUS 指针字段约定一致）。
    AuthDataLen *uint8 `json:"auth_data_len,omitempty"`

    // SequenceNumber (序列号): md5 类型，4 字节单调递增。
    SequenceNumber uint32 `json:"sequence_number,omitempty"`
}

// RIPRouter 描述一个路由器实例 (多路由器场景 §6.13)。
type RIPRouter struct {
    // SrcIP (源 IP): 该路由器的源 IP。空 = 继承 FlowSpec.SrcIP。
    SrcIP string `json:"src_ip,omitempty"`

    // SrcPort (源端口): 该路由器的源端口。空 = 继承 FlowSpec.SrcPort。
    SrcPort uint16 `json:"src_port,omitempty"`

    // DstIP (目标 IP): 该路由器的对端 IP。空 = 继承 FlowSpec.DstIP。
    // 与 Multicast 互斥：Multicast=true 时此字段忽略。
    DstIP string `json:"dst_ip,omitempty"`

    // DstPort (目标端口): 空 = 继承 FlowSpec.DstPort。
    DstPort uint16 `json:"dst_port,omitempty"`
}
```

**字段默认化规则**（与 SOCKS/RADIUS 一致：`user > auto > none`）：

| 字段 | 用户空时默认 | 备注 |
|------|--------------|------|
| Version | "v2" | Validate 接受空字符串 |
| Command | "response" | 仅在 Scenario 为空时生效 |
| Domain | 0 | RFC 规定 |
| Routes | 由 Scenario 推导 | 见 §6 |
| Multicast | false | 单播为默认，避免静默组播 |
| Scenario | "" | 空 + Routes 非空 = 透传；空 + Routes 空 + Command=response = "response_default" |
| TriggeredUpdate | false | true 时跳过 Request 阶段，直接发 Response（§6.11） |
| Rounds | 1 | 单次交换 |
| Auth.Type | "simple" | Auth 非 nil 时 |
| RIPAuth.AuthDataLen | 16 | md5 类型默认（nil=缺省） |
| RIPRoute.AFI | 2 (v1/v2) 或忽略 (ng) | 自动推导；显式 0xFFFF → Validate 报错 |
| RIPRoute.Metric | (必填，无默认) | 1-16 合法；0 与 17-255 → Validate 报错（不截断） |
| RIPRouter.* | 继承 FlowSpec | 单路由器等同 |

**RIPAuth.AuthDataLen JSON 反序列化说明**（与 R-NEW-1 v1.1.1 破坏性变更配套）：

| JSON 输入 | `*uint8` 指针状态 | Validate 行为 | Planner 实际值 |
|-----------|-------------------|---------------|----------------|
| 字段缺失 / `null` | `nil` | 接受 | 默认 16 |
| `0` | `ptr(0)` | 报错（必须 >0） | — |
| `16` / `20` | `ptr(n)` | 接受 | 透传 n |

## 4. 状态机

RIP 在 trafficgen 中无真实定时器，状态机简化为按 `Scenario` 显式分支：

```
                    ┌─────────────────────────────┐
                    │   Plan(spec) 进入            │
                    └────────────┬────────────────┘
                                 │
        ┌────────────────────────┼────────────────────────────┐
        │                        │                            │
        ▼                        ▼                            ▼
  Scenario=             Scenario=                 Scenario=
  request_full          response_default          triggered_update
  (RIP v1/v2/ng)        (RIP v1/v2/ng)            (Response 立即发)
        │                        │                            │
        ▼                        ▼                            ▼
  生成 Request 报文      生成 Response 报文         生成 Response 报文
  (AFI=0x0000,           (默认 5 条路由)             (Routes 用户给)
   metric=16/infinity)        │                            │
        │                        ▼                            │
        │              若 Rounds>1，                          │
        │              重复发 N 次                             │
        │              (周期更新)                              │
        ▼                        │                            │
  Planner 内部在                  │                            │
  Request 后自动追加              │                            │
  Response (request_full 固定后置步骤)                           │
        │                        │                            │
        └──────────┬─────────────┴────────────────────────────┘
                   ▼
            按 25 entry/包 拆分
                   │
                   ▼
            生成 PacketConfig 流
            (UDP 单数据报，1 包 = 1 PacketConfig)
```

**request_full 的输入优先级与 Routes 语义**：处理顺序为 Scenario → Command → TriggeredUpdate → Routes。`Scenario="request_full"` 固定生成特殊 Request，并固定追加自动 Response；Command 仅决定该场景入口，不能取消后置 Response；TriggeredUpdate 仅影响普通场景，request_full 的固定 Request/Response 序列优先。自动 Response 对 Routes 的处理分三种情况：`Routes=nil` 或非 nil 但 `len(Routes)==0` 时使用 5 条默认路由；`Routes!=nil && len(Routes)>0` 时完全使用用户 Routes，不再追加默认路由。用户非空 Routes 的自动 Response 仍使用 request_full 的同向四元组语义，不反转 SrcIP/DstIP 或端口。

| Scenario | Command | 行为 |
|----------|---------|------|
| `request_full` | request | 1 个特殊 Request entry (AFI=0x0000, metric=16/infinity，RFC 2453 §3.9.1);Planner 内部在 Request 后追加 Response（视作 request_full 场景的固定后置步骤，无需用户配 IsResponse 字段） |
| `response_default` | response | 5 条默认路由 (10.0.0.0/8, 172.16.0.0/16, 192.168.0.0/16, 0.0.0.0/0=缺省, 192.168.1.0/24) |
| `response_custom` | response | Routes 用户给 |
| `multicast_update` | response | DstIP=224.0.0.9 (v2) / FF02::9 (ng) / 255.255.255.255 (v1)，TTL=1 |
| `unicast_update` | response | DstIP 用户给 |
| `route_poison` | response | Routes 中至少 1 条 metric=16 |
| `split_horizon` | response | 过滤 NextHop==DstIP 的路由 |
| `poison_reverse` | response | NextHop==DstIP 的路由改 metric=16 |
| `triggered_update` | response | 等同 response_custom，仅语义标识 |
| `multi_router` | response | 按 Routers[] 展开多 4-tuple |
| `md5_auth` | response | Auth.Type=md5，第 1 entry 是认证 |
| `simple_auth` | response | Auth.Type=simple，第 1 entry 是认证 |

**Rounds 与周期更新**：Rounds>1 时，planner 在同一 4-tuple 上发 N 个 Response 报文，间隔由 worker pacing 控制（不在 planner 内 sleep，符合 NTP/RADIUS 模式）。模拟 RFC 2453 §3.9.1 的 30s 周期更新由用户用 `BPS` 或 `Count` 控制。

## 5. Plan 输出

Plan 返回 `<-chan core.PacketConfig`，每个 RIP 报文对应 1 个 PacketConfig。多包场景（>25 entry）按顺序发多个 PacketConfig，共享同一 FlowID 与 GroupID（同一 4-tuple，由同一 PacketWorker 处理以保序）。

### 5.1 单包结构（典型）

```
PacketConfig {
  FlowID:      "192.168.1.1-224.0.0.9-52001-520",
  PacketIndex: 0,
  Direction:   "up",
  L2:          {SrcMAC, DstMAC, EtherType: 0x0800},
  L3:          {SrcIP=192.168.1.1, DstIP=224.0.0.9, Proto=17, TTL=1, IPID=...},
  L4:          {Protocol="udp", SrcPort=52001, DstPort=520},
  Payload:     [RIP 头 4B + N×20B Route Entry],
}
```

注：此示例为 Request 包（SrcPort=52001 为临时端口，符合 RFC 2453 §3.6 "Request 应从非 RIP 端口发出"）。Response 包 SrcPort=520（RFC 2453 §3.6 规定 Response 源端口 = 520）。

### 5.2 多包拆分（26 条路由）

```
PacketConfig[0]: FlowID=X, PacketIndex=0, Payload=RIP头+25 entry
PacketConfig[1]: FlowID=X, PacketIndex=1, Payload=RIP头+1 entry
```

两包的 FlowID 相同（同 4-tuple），PacketIndex 递增；worker 按顺序发。

### 5.3 多路由器场景

Routers 数组长度 M，planner 内部循环展开为 M 条独立 FlowSpec：

```
for i, router := range cfg.Routers {
    subSpec := spec
    subSpec.SrcIP = router.SrcIP (or spec.SrcIP)
    subSpec.SrcPort = router.SrcPort (or spec.SrcPort)
    subSpec.DstIP = router.DstIP (or spec.DstIP)
    subSpec.DstPort = router.DstPort (or spec.DstPort)
    // 发 PacketConfig, FlowID = routeri-...
}
```

每个路由器的 FlowID 独立（含 router 索引），packetIndex 各自从 0 起。

### 5.4 认证对 PacketConfig 的影响

- 明文认证：第 1 entry 替换为认证条目，后续 entry 是真实路由。Planner 内部组装。
- MD5 认证：第 1 entry 是 MD5 认证头，末尾追加 4B trailer header（0xFFFF 0x0001）+ 16B 摘要占位（0xAA）。RIPv2 Packet Length 字段正确填值。

### 5.5 IPID 与 TTL

- IPID：每个 PacketConfig 独立递增（沿用 RADIUS 模式 `nextIPID()`）。
- TTL：multicast/broadcast 强制 1；unicast 用 FlowSpec.TTL（默认 64）。
- DSCP：默认 0xC0（CS6，网络控制流量），与 OSPF/IS-IS 一致；可被 FlowSpec.DSCP 覆盖。

## 6. 业务场景与数据场景

### 6.1 RIP v2 Request 全量路由

**场景**：路由器启动后向邻居请求全量路由表。

**Config**：
```json
{
  "version": "v2",
  "command": "request",
  "scenario": "request_full",
  "multicast": true,
  "routes": []
}
```

**生成的报文**：1 个 UDP 包，Payload = 4B RIP 头 + 1×20B 特殊 entry：
- RIP 头：`01 02 00 00`（Command=1 Request, Version=2, Domain=0）
- Entry：`00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10`
  - AFI=0x0000（RFC 2453 §3.9.1：全量请求 entry 的 AFI 字段为 0 而非 0xFFFF），RouteTag=0, IP=0.0.0.0, Mask=0.0.0.0, NextHop=0.0.0.0, Metric=16（RFC 2453 §3.9.1: infinity）
  - 注意：AFI=0xFFFF 在 RFC 2453 §2.1.1 中专用于"认证条目"（Authentication Type），不可复用为全量请求标识

**UDP**：SrcPort=随机（52001），DstPort=520，DstIP=224.0.0.9，TTL=1。

**Planner 自动追加 Response（非 RFC 行为）**：`request_full` 场景下，Planner 内部在 Request 报文后自动追加一个 Response 报文，视作 request_full 场景的固定后置步骤（无需用户配 IsResponse 字段）。这是 trafficgen 的**同向序列模拟**：Request 与自动 Response 使用相同的 SrcIP、DstIP、SrcPort、DstPort 和组播设置，不反转四元组，不自动切换单播/组播；多路由器场景中每个 Router 的自动 Response 继续使用该 Router 自己的四元组。这样做是 trafficgen 的非 RFC 实现便利（真实 RIP 中 Request 由主机发给邻居、Response 通常由邻居反向发回；trafficgen 在同一 4-tuple 上模拟 Request/Response 交换以保证端到端可见性）。Request 与 Response 共享 FlowID（含 router 索引），PacketIndex 递增（包 0=Request, 包 1=Response）。Response 报文 Command=2, Version=2，路由内容按下述优先级处理：Scenario 固定语义 > Command（request_full 固定追加 response）> TriggeredUpdate > Routes 用户输入。对于 `Routes=nil` 或 `Routes=[]`，自动 Response 使用默认 5 条路由；对于 `Routes!=nil && len(Routes)>0`，自动 Response 使用用户 Routes，且用户 Routes 优先于默认路由。

### 6.2 RIP v2 Response 全量路由（25 entry）

**场景**：响应邻居的 Request 或周期更新，发送 25 条路由。

**Config**：Routes 显式给出 25 条，或 Scenario=`response_default` + 用户填 Routes 到 25 条。

**报文**：1 个 UDP 包，4B RIP 头 + 25×20B = 504B Payload。
- Command=2 (Response), Version=2。
- 每个 entry AFI=2, RouteTag 可变, IP/Mask/NextHop 用户给, Metric 用户给。

### 6.3 RIP v2 Response 多包（26 entry = 2 包）

**场景**：路由表 > 25 条，必须拆分。

**Config**：Routes 给 26 条。

**报文**：
- 包 1：4B 头 + 25 entry（PacketIndex=0）
- 包 2：4B 头 + 1 entry（PacketIndex=1）
- 两包共享 FlowID，UDP 端口、IP 同 4-tuple。
- 两包的 Command 都是 2 (Response)；多包不通过 IP 分片承载，每包独立完整 RIP 报文。

### 6.4 RIP v1 Request/Response（无掩码）

**场景**：兼容老旧设备，仅 v1。

**Config**：
```json
{
  "version": "v1",
  "command": "response",
  "routes": [{"ip_addr": "10.0.0.0", "metric": 1}, ...]
}
```

**报文**：
- RIP 头：`02 01 00 00`（Response, Version=1）。
- Route Entry：AFI=2, MustBeZero=0（v1 无 Route Tag 字段，偏移 2-3 固定为 0）, IP=10.0.0.0, 后 8B 全 0（此处仅指 RTE 自身偏移 8-15：偏移 8-11 掩码字段=0、偏移 12-15 下一跳字段=0）, Metric=1（RTE 偏移 16-19；对应整个 Payload 偏移 20-23）。
- DstIP 处理：如 multicast=true 则 DstIP=255.255.255.255（v1 无组播，强制广播；参见 T-POS-32）。如 multicast=false 则 DstIP 使用 FlowSpec.DstIP 或 255.255.255.255（v1 传统行为）。

### 6.5 RIP v2 单播更新

**场景**：通过单播与特定邻居交换 RIP，避免组播打扰其他设备。

**Config**：
```json
{
  "version": "v2",
  "command": "response",
  "multicast": false,
  "dst_ip": "192.168.1.2",
  "routes": [...]
}
```

**报文**：DstIP=192.168.1.2（用户给），TTL=FlowSpec.TTL（默认 64），DstPort=520。

### 6.6 RIP v2 组播更新

**场景**：默认周期更新模式。

**Config**：
```json
{
  "version": "v2",
  "command": "response",
  "multicast": true,
  "rounds": 3
}
```

**报文**：
- DstIP=224.0.0.9，TTL=1，DstPort=520。
- SrcPort=520（响应方从 520 发出，符合 RFC 2453 §3.6）。
- Rounds=3：发 3 个 PacketConfig，间隔由 worker pacing。

### 6.7 RIP v2 认证明文

**场景**：邻居间共享密码防伪。

**Config**：
```json
{
  "version": "v2",
  "auth": {"type": "simple", "password": "secret123"},
  "routes": [{"ip_addr": "10.0.0.0", "subnet_mask": "255.0.0.0", "metric": 1}]
}
```

**报文**：
- 第 1 entry：AFI=0xFFFF, AuthType=0x0002, AuthData=`secret123` + 7 字节 0 填充。
- 第 2 entry：真实路由 10.0.0.0/8。
- 单包最多 24 条路由（25-1 认证槽位）。

### 6.8 RIP v2 认证 MD5（仅字段占位）

**场景**：RFC 4822 MD5 认证，不计算真实 HMAC。

**Config**：
```json
{
  "version": "v2",
  "auth": {
    "type": "md5",
    "key_id": 1,
    "auth_data_len": 16,
    "sequence_number": 12345
  },
  "routes": [{"ip_addr": "10.0.0.0", "subnet_mask": "255.0.0.0", "metric": 1}]
}
```

**报文**：
- 第 1 entry（20B）：AFI=0xFFFF, AuthType=0x0003, RIPv2PacketLength=4+20×(1+1)=44（regular RIPv2 packet 总长度；4=RIP 头, 20=认证条目, 20=1 条真实路由），KeyID=1, AuthDataLen=16, SeqNum=12345, 后 8B=0。
- 通用公式：当含 1 条认证 entry + N 条真实路由时，`RIPv2PacketLength = PacketLength = 4 + 20 × (1 + N)`，表示 regular RIPv2 packet 的总长度，与 AuthDataLen 无关；AuthDataLen 仅决定 trailer 之后追加的摘要长度。
- 真实路由 1 条：20B。
- Trailer header（4B）：`FF FF 00 01`（0xFFFF=RIP-2 认证标记 + 0x0001=RFC 4822 认证类型=MD5），位于偏移 44 处。
- 末尾追加 16B 摘要占位（0xAA），位于偏移 48 处。
- 总 Payload = 4 + 20 + 20 + 4 + 16 = 64 字节。

**注**：trafficgen 不计算真实 MD5（无共享密钥流），与 OpenVPN/SNMP v3 一致，仅保证 wire format 正确。

### 6.9 路由毒化（metric=16）

**场景**：网络故障，向邻居通告某路由不可达。

**Config**：
```json
{
  "version": "v2",
  "command": "response",
  "scenario": "route_poison",
  "routes": [
    {"ip_addr": "10.0.0.0", "subnet_mask": "255.0.0.0", "metric": 16},
    {"ip_addr": "172.16.0.0", "subnet_mask": "255.255.0.0", "metric": 1}
  ]
}
```

**报文**：标准 Response，10.0.0.0/8 的 metric=16。邻居收到后将该路由标记为不可达，触发自己的触发更新。

### 6.10 水平分割（Split Horizon）与毒化反转（Poison Reverse）

**场景**：从接口 A 学到的路由不再从 A 发回（水平分割）；或反向发回但 metric=16（毒化反转）。

**Config**：
```json
{
  "version": "v2",
  "command": "response",
  "split_horizon": true,
  "dst_ip": "192.168.1.2",
  "routes": [
    {"ip_addr": "10.0.0.0", "subnet_mask": "255.0.0.0", "next_hop": "192.168.1.2", "metric": 1},
    {"ip_addr": "172.16.0.0", "subnet_mask": "255.255.0.0", "next_hop": "192.168.1.1", "metric": 1}
  ]
}
```

**行为**：
- SplitHorizon=true：NextHop==DstIP（192.168.1.2）的路由被过滤。10.0.0.0/8 不发，仅发 172.16.0.0/16。
- PoisonReverse=true（覆盖 SplitHorizon）：NextHop==DstIP 的路由改 metric=16 发回。10.0.0.0/8 metric=16 发回。

### 6.11 触发更新（Triggered Update）

**场景**：拓扑变化立即发 Response，不等 30s 周期。

**Config**：
```json
{
  "version": "v2",
  "command": "response",
  "triggered_update": true,
  "routes": [{"ip_addr": "10.0.0.0", "subnet_mask": "255.0.0.0", "metric": 16}]
}
```

**行为**：Planner 立即发 Response，不带 Request 前导。语义标识，wire format 与普通 Response 相同。Rounds=1。**注意：TriggeredUpdate=true 时忽略 Command 字段，强制按 Response 处理。**

### 6.12 RIPng IPv6

**场景**：IPv6 网络使用 RIPng。

**Config**：
```json
{
  "version": "ng",
  "command": "response",
  "multicast": true,
  "routes": [
    {"ip_addr": "2001:db8::", "prefix_len": 64, "metric": 1, "route_tag": 0},
    {"ip_addr": "::", "prefix_len": 0, "metric": 1}
  ]
}
```

**报文**：
- RIP 头：`02 01 00 00`（Response, Version=1）。
- Route Entry：16B IPv6 前缀 + 2B RouteTag + 1B PrefixLen + 1B Metric。
- DstIP=FF02::9，DstPort=521，TTL=1，EtherType=0x86DD。
- 认证不支持（Auth 非 nil 时 Validate 报错）。

### 6.13 多路由器并发

**场景**：M 台路由器同时发 RIP 更新，模拟大型网络的周期更新洪流。

**Config**：
```json
{
  "version": "v2",
  "command": "response",
  "multicast": true,
  "routers": [
    {"src_ip": "192.168.1.1", "src_port": 52001},
    {"src_ip": "192.168.1.2", "src_port": 52002},
    {"src_ip": "192.168.2.1", "src_port": 52003}
  ],
  "routes": [...]
}
```

**行为**：
- Planner 展开为 3 条独立 FlowSpec，每条有自己的 FlowID（含 router 索引）。
- 每条 FlowSpec 独立 4-tuple：SrcIP/SrcPort 不同，DstIP=224.0.0.9（multicast）相同。
- 每条 FlowSpec 各自发完整 Routes，互不影响。
- 3 条 FlowSpec 共享同一 GroupID（GroupIDStrategy="fixed"），路由到同一 PacketWorker 保序；或用 GroupIDStrategy="inc" 路由到不同 worker 并发。
- FlowSpec.Count 控制每个路由器的发包轮数；总包数 = M × Count × ⌈Routes/25⌉。

**src_port 非 RFC 行为声明**：RFC 2453 §3.6 规定 Response 源端口应为 520。本场景用 52001/52002/52003 临时端口——这是 trafficgen 的非标行为，便于 4-tuple 区分多路由器并保证 PacketWorker 按 4-tuple 保序。tshark 可能提示"非标准 RIP 源端口"。详见 §2.7 末尾说明。

**未设 src_port 时的默认行为**：若 `Routers[i].SrcPort == 0`（用户未显式设置），planner 默认从 52001 起为该路由器分配一个动态 SrcPort（52001、52002、52003 ... 依次递增）；具体端口号由 worker 端的 4-tuple 分配器按 router 索引计算得出，保证每个路由器得到唯一端口。若用户显式设置了 SrcPort（如示例中的 52001/52002/52003），则透传用户值，不再动态分配。

### 6.14 边界场景

| 边界 | 期望行为 | 测试要点 |
|------|----------|----------|
| Metric=0 | Validate 报错（RFC 2453 §3.6 的输入处理规定 metric 必须为 1-16） | T-EDGE-1 |
| Metric=1 | 最小合法 metric | T-EDGE-2 |
| Metric=16 | 不可达，合法 | T-EDGE-3 |
| Metric=17 | Validate 报错（>16） | T-EDGE-4 |
| Metric=255 | Validate 报错 | T-EDGE-5 |
| Route entry 数=0 | Response 0 路由（4B 头，无 entry） | T-EDGE-6 |
| Route entry 数=25 | 单包 25 entry | T-EDGE-7 |
| Route entry 数=26 | 拆 2 包（25+1） | T-EDGE-8 |
| Route entry 数=50 | 拆 2 包（25+25） | T-EDGE-9 |
| Route entry 数=51 | 拆 3 包（25+25+1） | T-EDGE-10 |
| IP=0.0.0.0 | 缺省路由，合法 | T-EDGE-11 |
| IP=255.255.255.255 | 广播地址作路由，Validate 报错（非合法网络地址） | T-EDGE-12 |
| SubnetMask=0.0.0.0 | 缺省路由（与 IP=0.0.0.0 配对），合法 | T-EDGE-13 |
| SubnetMask=255.255.255.255 | 主机路由，合法 | T-EDGE-14 |
| SubnetMask 非连续掩码 | Validate 警告（RFC 不强制），planner 透传 | T-EDGE-15 |
| PrefixLen=0 | IPv6 缺省路由，合法 | T-EDGE-16 |
| PrefixLen=128 | IPv6 主机路由，合法 | T-EDGE-17 |
| PrefixLen=129 | Validate 报错（>128） | T-EDGE-18 |
| Domain=0xFFFF | 透传，不报错（RFC 称 Unused，但允许任意值） | T-EDGE-19 |
| Routes=nil + Scenario="" | 默认 response_default（5 条示例路由） | T-EDGE-20 |
| Routers=[] | 单路由器（FlowSpec 自身） | T-EDGE-21 |
| Routers=100, GroupIDStrategy="inc" | 100 路由器真并发（路由到不同 worker），总发包时间 ≤ 单路由器的 N 倍（N≥4）；详见 §6.13 | T-EDGE-22 |

### 6.15 异常场景

本表仅列 **Validate 报错或警告** 的异常行。合法默认化（Version=""→v2、Command=""→response）见 §3 默认值表与 T-POS-29/T-POS-30；合法边界（Password=16、AuthDataLen=20、Routes>25+Auth 多包拆分）见 §6.14 边界表与 T-POS-24/T-POS-25/T-POS-31。

| 异常 | 期望行为 | 测试要点 |
|------|----------|----------|
| Version="v3" | Validate 报错（仅支持 v1/v2/ng） | T-ERR-1 |
| Command="update" | Validate 报错（仅 request/response） | T-ERR-3 |
| Metric=0 | Validate 报错（RFC 2453 §3.6 的输入处理规定 metric 必须为 1-16；不静默截断，不默认化） | T-EDGE-1 |
| Metric=17 或 255（>16） | Validate 报错（>16；不截断为 16，与 §3 注释一致） | T-EDGE-4, T-EDGE-5 |
| AFI=3（非 2/0） | Validate 报错 | T-ERR-5 |
| AFI=0xFFFF 用户显式设 | Validate 报错（0xFFFF 仅用于 Auth 触发的认证条目，见 §2.4/§2.5；用户不应在 RIPRoute.AFI 显式设） | T-ERR-19 |
| AFI=0xFFFF + Routes 非空 | Validate 报错（同 T-ERR-19；Scenario=request_full 由 planner 自动生成 AFI=0x0000 全量请求 entry，不通过用户设 0xFFFF 实现） | T-ERR-6 |
| Auth.Type="sha256" | Validate 报错（仅 simple/md5） | T-ERR-7 |
| Auth 非 nil + Version="v1" | Validate 报错（v1 不支持认证） | T-ERR-8 |
| Auth 非 nil + Version="ng" | Validate 报错（RIPng 不支持认证） | T-ERR-9 |
| Auth.Password=17 字节 | Validate 报错（>16） | T-ERR-10 |
| RIPRoute.IPAddr 非法 IP | Validate 报错 | T-ERR-11 |
| RIPRoute.SubnetMask 非法 IPv4 | Validate 报错 | T-ERR-12 |
| RIPRoute.NextHop 与 IPAddr 协议族不匹配 | Validate 报错 | T-ERR-13 |
| Multicast=true + DstIP 用户给 | Validate 警告（multicast 覆盖 DstIP） | T-ERR-14 |
| SplitHorizon=true + PoisonReverse=true | Validate 警告（PoisonReverse 覆盖 SplitHorizon） | T-ERR-15 |
| Routers=[{}]（空元素） | Validate 报错（至少 1 字段非空） | T-ERR-16 |
| MD5 AuthDataLen 显式为 0（`AuthDataLen: ptr(0)`） | Validate 报错（必须 >0；v1.1.1 用 `*uint8` 指针，nil=缺省=16，显式 0=报错） | T-ERR-17 |
| SplitHorizon=true + Multicast=true | Validate 警告（组播无具体接收方，SplitHorizon 不生效；planner 跳过过滤，见 §8.5） | T-ERR-18 |
| PoisonReverse=true + Multicast=true | Validate 警告（组播无具体接收方，PoisonReverse 不生效；planner 跳过过滤，与 SplitHorizon+Multicast 行为一致） | T-ERR-18（扩展） |

## 7. 测试用例清单

按 CLAUDE.md 测试策略：spec 驱动、负向覆盖、单路径单测、集成测试、断言可观测量、并发验证、failing-test-first。下表共 73 条基础用例，另新增 1 个 T-POS-1b 用户 Routes 非空变体（实现时计入 T-POS-1b 的参数化子用例，不新增独立编号）。

**排序说明**：T-POS-1~28 按 §6 业务场景顺序排列（v1.1.3 在 T-POS-1 后插入 T-POS-1b，保留 T-POS-2~33 编号不变）；T-POS-29~33 为 v1.1/v1.1.2 新增的默认值与边界补全用例，集中在表尾。T-EDGE 按 §6.14 边界行顺序排列。T-ERR 按 §6.15 异常行顺序排列，含 T-ERR-19（原 T-ERR-5b 改为纯数字编号）。

| 编号 | 类型 | 用例名 | 覆盖章节 | 断言要点 |
|------|------|--------|----------|----------|
| T-POS-1 | 正向 | RIP v2 Request 全量路由 | §6.1 | Payload[0]=0x01 (Command=1 Request), Payload[1]=0x02 (Version=2), Payload[2:4]=0x0000 (Domain=0), Payload[4:6]=00 00 (AFI=0), Payload[6:10]=00 00 00 00 (RouteTag=0), Payload[10:14]=00 00 00 00 (IP=0.0.0.0), Payload[14:18]=00 00 00 00 (Mask=0.0.0.0), Payload[18:22]=00 00 00 00 (NextHop=0.0.0.0), Payload[20:24]=00 00 00 10 (Metric=16, RFC 2453 §3.9.1: infinity), DstIP=224.0.0.9, TTL=1 |
| T-POS-1b | 正向 | request_full 自动追加 Response | §6.1 | 2 个 PacketConfig: 包 0 = Request (Command=1, AFI=0, Metric=16), 包 1=Response (Command=2)；两包共享 FlowID, PacketIndex 0/1；自动 Response 与 Request 同向使用相同 SrcIP、DstIP、SrcPort、DstPort，不反转四元组、不自动改变组播设置；Routes=nil/[] 时含默认 5 条路由，Routes 非空时改用用户 Routes |
| T-POS-1b-variant | 正向 | request_full 用户 Routes 优先 | §6.1 | Routes 非空时自动 Response 不使用默认 5 条，而使用用户 Routes；SrcIP/DstIP/SrcPort/DstPort 与 Request 完全相同，不反向、不切换组播 |
| T-POS-3 | 正向 | RIP v2 Response 26 entry 拆 2 包 | §6.3 | 2 个 PacketConfig, PacketIndex=0/1, 包1 25 entry, 包2 1 entry, 同 FlowID |
| T-POS-4 | 正向 | RIP v1 Response 无掩码 | §6.4 | Version=1, Entry 偏移 8-11=0, 偏移 12-15=0, Metric 位于 RTE 偏移 16-19（整个 Payload 偏移 20-23）且为 `00 00 00 01`, DstIP=255.255.255.255 |
| T-POS-5 | 正向 | RIP v2 单播更新 | §6.5 | DstIP=用户给, TTL=64, DstPort=520 |
| T-POS-6 | 正向 | RIP v2 组播更新 TTL=1 | §6.6 | DstIP=224.0.0.9, TTL=1, SrcPort=520 |
| T-POS-7 | 正向 | RIP v2 组播 Rounds=3 | §6.6 | 3 个 PacketConfig, 同 FlowID, PacketIndex 0/1/2 |
| T-POS-8 | 正向 | RIP v2 明文认证 | §6.7 | 第 1 entry AFI=0xFFFF, AuthType=0x0002, 16B 密码（含补零）, 第 2 entry 真实路由 |
| T-POS-9 | 正向 | RIP v2 MD5 认证字段占位 | §6.8 | 第 1 entry AFI=0xFFFF, Payload[6:8]=00 03（认证 entry 的 Auth Type），Payload[8:10]=00 2C（RIPv2PacketLength=44，即 4+20×(1+1)），Payload[10]=01（KeyID=1），Payload[11]=10（AuthDataLen=16），Payload[12:16]=00 00 30 39（SeqNum=12345），Payload[16:24]=00 00 00 00 00 00 00 00（MustBeZero=0），Payload[44:48]=FF FF 00 01（trailer header，认证 entry 的 Auth Type=0x0003 与 trailer header 的 Type=0x0001 属于不同结构），Payload[48:64]=16B 0xAA（摘要占位），完整 Payload 长度 = 504 + 4 + 16 = 524B |
| T-POS-10 | 正向 | 路由毒化 metric=16 | §6.9 | Routes 中至少 1 条 metric=16, 报文 metric 字段=0x10 |
| T-POS-11 | 正向 | 水平分割过滤 | §6.10 | NextHop==DstIP 的路由被过滤, Payload 中不含该 entry |
| T-POS-12 | 正向 | 毒化反转 metric=16 | §6.10 | NextHop==DstIP 的路由 metric 改 16, 仍发出 |
| T-POS-13 | 正向 | 触发更新 | §6.11 | 仅 Response, 无 Request 前导, Rounds=1 |
| T-POS-14 | 正向 | RIPng IPv6 组播 | §6.12 | 完整头字段 Payload[0:4]=02 01 00 00（Command=2, Version=1, Domain=0），Version=1 仅按 `version="ng"` 解释；UDP SrcPort/DstPort=521, DstIP=FF02::9, EtherType=0x86DD, Entry 16B IPv6 前缀 |
| T-POS-15 | 正向 | RIPng 缺省路由 | §6.12 | Prefix=::, PrefixLen=0, Metric=1 |
| T-POS-16 | 正向 | 多路由器 3 路由器并发 | §6.13 | 3 个 FlowID, 各自 SrcIP/SrcPort, 同 DstIP=224.0.0.9 |
| T-POS-17 | 正向 | 多路由器 100 路由器压力（无 panic） | §6.13 | 100 个 FlowID, GroupIDStrategy="fixed"（同 worker），总包数=100×⌈Routes/25⌉, 无 panic、无 -race 报警 |
| T-POS-18 | 正向 | 默认 Scenario 推导 response_default | §6.14 | Routes=nil + Scenario="" 时发 5 条默认路由 |
| T-POS-19 | 正向 | Route Entry 0 条 Response | §6.14 | Payload 仅 4B RIP 头, 无 entry |
| T-POS-20 | 正向 | Route Entry 50 条拆 2 包各 25 | §6.14 | 2 包, 各 25 entry, PacketIndex 0/1 |
| T-POS-21 | 正向 | Route Entry 51 条拆 3 包 25/25/1 | §6.14 | 3 包, 第 3 包 1 entry |
| T-POS-22 | 正向 | 主机路由 SubnetMask=255.255.255.255 | §6.14 | Mask 字段=FF FF FF FF, 合法 |
| T-POS-23 | 正向 | IPv6 主机路由 PrefixLen=128 | §6.14 | PrefixLen=128, 合法 |
| T-POS-24 | 正向 | 明文密码 16 字节恰好填满 | §6.15 | AuthData 16B, 无补零 |
| T-POS-25 | 正向 | MD5 AuthDataLen=20 透传 | §6.15 | AuthDataLen=0x14, Payload[6:8]=00 03（认证 entry 的 Auth Type），Payload[8:10]=00 2C（RIPv2PacketLength=44），Payload[10]=01（KeyID=1），Payload[11]=14（AuthDataLen=20），Payload[12:16]=00 00 30 39（SeqNum=12345），Payload[16:24]=00 00 00 00 00 00 00 00（MustBeZero=0），Payload[44:48]=FF FF 00 01（trailer header 的 Type=0x0001），Payload[48:68]=20B 0xAA（trafficgen 私有扩展摘要占位，不宣称为标准 MD5），完整首包 Payload 长度 = 504 + 4 + 20 = 528B |
| T-POS-26 | 集成 | 多包 FlowID 一致性 | §5.2 | 26 entry 拆 2 包, 两包 FlowID 相同, PacketIndex 递增 |
| T-POS-27 | 集成 | 认证后最大 24 路由/包 | §5.4, §2.8.2 | Auth 非 nil + 25 Routes, 首包 1 认证 + 24 路由；AuthDataLen=16 时首包完整 Payload=524B，AuthDataLen=20 时=528B；第 2 包 1 路由且按后续包规则不重复认证 |
| T-POS-28 | 并发 | 多路由器总吞吐 = M × 单路由器 | §6.13 | 8 路由器并发, 实际发包数 = 8 × ⌈Routes/25⌉ × Rounds |
| T-EDGE-1 | 边界 | Metric=0 报错 | §6.14 | Validate 返回 error |
| T-EDGE-2 | 边界 | Metric=1 合法 | §6.14 | Payload metric 字段=0x01 |
| T-EDGE-3 | 边界 | Metric=16 不可达 | §6.14 | Payload metric 字段=0x10 |
| T-EDGE-4 | 边界 | Metric=17 报错 | §6.14 | Validate 返回 error |
| T-EDGE-5 | 边界 | Metric=255 报错 | §6.14 | Validate 返回 error |
| T-EDGE-6 | 边界 | Route entry 数=0 | §6.14 | Payload 仅 4B RIP 头, 无 entry |
| T-EDGE-7 | 边界 | Route entry 数=25 单包 | §6.14 | Payload 长度=504, 25 个 entry |
| T-EDGE-8 | 边界 | Route entry 数=26 拆 2 包 | §6.14 | 2 包: 25+1 entry, 同 FlowID |
| T-EDGE-9 | 边界 | Route entry 数=50 拆 2 包 | §6.14 | 2 包: 25+25 entry, 同 FlowID |
| T-EDGE-10 | 边界 | Route entry 数=51 拆 3 包 | §6.14 | 3 包: 25+25+1 entry |
| T-EDGE-11 | 边界 | IP=0.0.0.0 缺省路由 | §6.14 | IP 字段=00 00 00 00, Mask=0.0.0.0 |
| T-EDGE-12 | 边界 | IP=255.255.255.255 报错 | §6.14 | Validate 返回 error |
| T-EDGE-13 | 边界 | SubnetMask=0.0.0.0 缺省 | §6.14 | Mask 字段=00 00 00 00, 合法 |
| T-EDGE-14 | 边界 | SubnetMask=255.255.255.255 主机路由 | §6.14 | Mask 字段=FF FF FF FF, 合法 |
| T-EDGE-15 | 边界 | SubnetMask 非连续掩码 警告 | §6.14 | Validate 警告, planner 透传 |
| T-EDGE-16 | 边界 | PrefixLen=0 IPv6 缺省 | §6.14 | PrefixLen 字段=0x00, 合法 |
| T-EDGE-17 | 边界 | PrefixLen=128 IPv6 主机 | §6.14 | PrefixLen 字段=0x80, 合法 |
| T-EDGE-18 | 边界 | PrefixLen=129 报错 | §6.14 | Validate 返回 error |
| T-EDGE-19 | 边界 | Domain=0xFFFF 透传 | §6.14 | Domain 字段=FF FF |
| T-EDGE-20 | 边界 | Routes=nil + Scenario="" 默认 | §6.14 | 发 5 条默认路由 |
| T-EDGE-21 | 边界 | Routers=[] 单路由器 | §6.14 | 1 个 FlowID, 等同 FlowSpec 自身 |
| T-EDGE-22 | 边界 | Routers=100 + GroupIDStrategy="inc" | §6.14 | 100 个 FlowID, GroupIDStrategy="inc"（不同 worker）, 100 路由器真并发；总发包时间 ≤ 单路由器耗时的 N 倍（N≥4，对比 fixed 模式下的串行耗时） |
| T-ERR-1 | 负向 | Version="v3" 报错 | §6.15 | Validate 返回 error |
| T-POS-29 | 正向 | Version="" 默认 v2 | §3 | Plan 成功, RIP头 Version 字节=0x02 |
| T-ERR-3 | 负向 | Command="update" 报错 | §6.15 | Validate 返回 error |
| T-POS-30 | 正向 | Command="" 默认 response | §3 | Plan 成功, RIP头 Command 字节=0x02 |
| T-ERR-5 | 负向 | AFI=3 报错 | §6.15 | Validate 返回 error |
| T-ERR-19 | 负向 | AFI=0xFFFF 用户显式设 报错 | §6.15 | Validate 返回 error（0xFFFF 仅用于 Auth 触发的认证条目） |
| T-ERR-6 | 负向 | AFI=0xFFFF + Routes 非空 报错 | §6.15 | Validate 返回 error |
| T-ERR-7 | 负向 | Auth.Type="sha256" 报错 | §6.15 | Validate 返回 error |
| T-ERR-8 | 负向 | Auth 非 nil + Version="v1" 报错 | §6.15 | Validate 返回 error |
| T-ERR-9 | 负向 | Auth 非 nil + Version="ng" 报错 | §6.15 | Validate 返回 error |
| T-ERR-10 | 负向 | Auth.Password=17 字节 报错 | §6.15 | Validate 返回 error |
| T-ERR-11 | 负向 | RIPRoute.IPAddr 非法 IP 报错 | §6.15 | Validate 返回 error |
| T-ERR-12 | 负向 | RIPRoute.SubnetMask 非法 IPv4 报错 | §6.15 | Validate 返回 error |
| T-ERR-13 | 负向 | NextHop 协议族不匹配 报错 | §6.15 | Validate 返回 error |
| T-ERR-14 | 警告 | Multicast 覆盖 DstIP 警告 | §6.15 | Validate 不报错, 但 Plan 用组播 IP（警告而非报错，行为同 §6.15 异常表中"警告"行） |
| T-POS-31 | 正向 | Routes > 25 + Auth 非 nil 多包拆分合法 | §6.15, §2.8.2 | 首包 1 认证 + 24 路由；AuthDataLen=16 时首包完整 Payload=524B、AuthDataLen=20 时=528B；第 2 包无认证 + 1 路由且无认证 trailer（RFC 4822 §2.1：MD5 认证 trailer 仅出现在首包，后续包不含），第 2 包 Payload=4+20=24B |
| T-ERR-15 | 负向 | SplitHorizon + PoisonReverse 共存 警告 | §6.15 | Validate 不报错, PoisonReverse 生效 |
| T-ERR-16 | 负向 | Routers=[{}] 空元素 报错 | §6.15 | Validate 返回 error |
| T-ERR-17 | 负向 | MD5 AuthDataLen 显式为 0 报错 | §6.15 | `AuthDataLen: ptr(0)` 时 Validate 返回 error；nil 时默认 16 |
| T-ERR-18 | 负向 | SplitHorizon=true + Multicast=true 或 PoisonReverse=true + Multicast=true 警告 | §6.15 | Validate 警告（组播下 SplitHorizon/PoisonReverse 均不生效，planner 跳过过滤） |
| T-POS-32 | 正向 | v1 + multicast=true → DstIP=255.255.255.255 | §3, §8.3 | DstIP=255.255.255.255（v1 无组播，multicast=true 强制广播）；TTL=1；忽略用户 DstIP |
| T-POS-33 | 正向 | Domain=0x0001 → RIP 头第 3-4 字节=00 01 | §2.1, §3 | 字节断言 Payload[2:4]=00 01；其余字段按 Version 默认 |

**用例总数：73 条**（正向 34 = T-POS-1~28 含 T-POS-1b + T-POS-29~33；边界 22 = T-EDGE-1~22；负向 17 = T-ERR-1, T-ERR-3, T-ERR-5, T-ERR-19, T-ERR-6~18）。本轮新增 1 个 T-POS-1b 参数化变体（Routes 非空优先级），并补强 T-POS-4、T-POS-9、T-POS-14、T-POS-25、T-POS-27、T-POS-31 的字节/长度断言，不改变基础编号总数。

### 7.1 Spec 驱动映射（CLAUDE.md §1）

| Spec 章节 | 用例 |
|-----------|------|
| §2.1 RIP 公共头 | T-POS-1, T-POS-1b, T-POS-2, T-POS-4 |
| §2.2 v1 Route Entry | T-POS-4 |
| §2.3 v2 Route Entry | T-POS-2, T-POS-5 |
| §2.4 v2 认证条目 | T-POS-8, T-POS-24 |
| §2.5 MD5 认证 | T-POS-9, T-POS-25 |
| §2.6 RIPng Route Entry | T-POS-14, T-POS-15 |
| §2.7 UDP 封装 | T-POS-5, T-POS-6, T-POS-14 |
| §2.8 报文长度 | T-POS-2, T-POS-3, T-POS-27, T-POS-31, T-EDGE-3 |

### 7.2 负向覆盖（CLAUDE.md §2）

T-ERR-1, T-ERR-3, T-ERR-5, T-ERR-19, T-ERR-6~18 共 17 条负向用例（T-ERR-2/T-ERR-4 编号空缺——原 Version/Command 空字符串默认化用例已移至 T-POS-29/T-POS-30，覆盖 §6.15 全部异常行；v1.1.2 将 T-ERR-5b 重排为 T-ERR-19 纯数字编号）。

### 7.3 单路径单测（CLAUDE.md §3）

每个 Scenario 至少 1 条用例：
- request_full → T-POS-1, T-POS-1b（自动追加 Response）
- response_default → T-POS-18
- multicast_update → T-POS-6, T-POS-7
- unicast_update → T-POS-5
- route_poison → T-POS-10
- split_horizon → T-POS-11
- poison_reverse → T-POS-12
- triggered_update → T-POS-13
- md5_auth → T-POS-9, T-POS-25
- simple_auth → T-POS-8, T-POS-24
- multi_router → T-POS-16, T-POS-17

### 7.4 集成测试（CLAUDE.md §4）

- T-POS-26：多包拆分 FlowID 一致性（同 4-tuple 保序）。
- T-POS-27：认证 + 多包交互（认证槽位占用 + 拆包）。
- T-POS-28：多路由器并发总吞吐。

### 7.5 断言可观测量（CLAUDE.md §5）

每条用例必须断言：
- Payload 字节级（Command/Version/Domain 字节、每个 entry 字段字节）。
- UDP 端口、IP 地址、TTL、EtherType。
- 多包时 FlowID/PacketIndex 关系。
- 不只断言 "Plan 不报错" 或 "返回 N 个 PacketConfig"。

### 7.6 并发验证（CLAUDE.md §6）

T-POS-28：8 路由器并发，断言总发包数 = 8 × ⌈Routes/25⌉ × Rounds（不是只测 -race 干净）。

### 7.7 Failing-test-first（CLAUDE.md §7）

每个 bug fix 必须先写复现用例。本设计新增协议，无历史 bug，但实现期若发现拆包错误（如 26 entry 拆成 1+25 而非 25+1），先写 T-POS-3 失败版本再修。

## 8. 交叉对抗审计检查清单

实现完成后，按本清单对抗审计（CLAUDE.md "Code Modification & Review Policy"）：

### 8.1 字段级审计

- [ ] RIP 头 4 字节：Command 1B + Version 1B + Domain 2B，无遗漏。
- [ ] v2 Route Entry 20 字节：AFI 2B + RouteTag 2B + IP 4B + Mask 4B + NextHop 4B + Metric 4B。
- [ ] v1 Route Entry 20 字节：AFI 2B + 0×2B + IP 4B + 0×8B + Metric 4B（v1 必须把 mask/next-hop 字段填 0，不能漏填）。
- [ ] RIPng Route Entry 20 字节：Prefix 16B + RouteTag 2B + PrefixLen 1B + Metric 1B（顺序与 v2 不同）。
- [ ] 认证条目 20 字节：AFI 2B + AuthType 2B + AuthData 16B（simple）或 16B 头 + 末尾摘要（md5）。
- [ ] Metric 字段 4 字节（不是 1 字节），前 3 字节必须 0。
- [ ] Domain 字段 2 字节 big-endian。
- [ ] AFI 字段 2 字节 big-endian。
- [ ] RouteTag 字段 2 字节 big-endian。
- [ ] IP/Mask/NextHop 4 字节网络字节序。

### 8.2 拆包审计

- [ ] >25 entry 必须拆多包，每包独立 RIP 头。
- [ ] 拆包不通过 IP 分片承载（每包 IP total-length 独立）。
- [ ] 拆包后两包 FlowID 相同，PacketIndex 递增。
- [ ] 认证时首包 entry 数 = 24（1 认证 + 24 路由），后续包无认证 entry。
- [ ] 拆包顺序：前 25（或 24）填满再下一包，不是 1+25。

### 8.3 TTL/DstIP 审计

- [ ] Multicast=true + v2 → DstIP=224.0.0.9, TTL=1。
- [ ] Multicast=true + v1 → DstIP=255.255.255.255, TTL=1。
- [ ] Multicast=true + ng → DstIP=FF02::9, TTL=1。
- [ ] Multicast=false → DstIP=用户给, TTL=FlowSpec.TTL。
- [ ] Multicast=true 时忽略 FlowSpec.DstIP（不混用）。

### 8.4 认证审计

- [ ] v1/ng + Auth 非 nil → Validate 报错。
- [ ] simple 密码 < 16 字节补零，= 16 不补，> 16 报错（与 T-ERR-10 一致，不截断）。
- [ ] MD5 RIPv2 Packet Length 字段值正确（regular RIPv2 packet 的总长度 = 4 + 20×(1+N) 字节；不含 trailer header 自身 4 字节与摘要字节；见 §6.8 修正示例 = 44 字节）。
- [ ] MD5 trailer header 4 字节 = `FF FF 00 01`（0xFFFF=RIP-2 认证标记 + 0x0001=trailer header Type=MD5），紧随 regular RIPv2 packet 之后。
- [ ] MD5 摘要占位 0xAA（与 OpenVPN/SNMP v3 一致），不计算真实 HMAC；摘要紧随 trailer header 之后。
- [ ] Auth.Type 空 = "simple"。
- [ ] AuthDataLen 空 = 16（md5 默认）；若只实现标准 MD5，Validate 强制 AuthDataLen=16；非 16 值（如 SHA-256=20）仅作为 trafficgen 私有扩展，不宣称为标准 MD5。
- [ ] RIPv2 Packet Length 的字段值为 regular RIPv2 packet 总长度，不是 offset/pointer；trailer header 与 digest 不计入该字段。

### 8.5 水平分割审计

- [ ] SplitHorizon=true 时 NextHop==DstIP 的路由不发。
- [ ] PoisonReverse=true 时 NextHop==DstIP 的路由改 metric=16 发出。
- [ ] 两者同时 true 时 PoisonReverse 生效（不双重过滤）。
- [ ] 单播场景下 DstIP 是用户给的具体邻居 IP（不是组播）。
- [ ] 组播场景下 SplitHorizon 如何判断"接收方 IP"？答：组播无具体接收方，SplitHorizon 不生效（planner 跳过过滤）；Validate 对 {SplitHorizon=true, Multicast=true} 组合发出警告（见 §6.15 T-ERR-18）。

### 8.6 多路由器审计

- [ ] Routers 数组每个元素至少 1 字段非空（否则 Validate 报错）。
- [ ] 每个路由器独立 FlowID（含 router 索引或 SrcIP）。
- [ ] 每个路由器 packetIndex 从 0 起（不跨路由器连续）。
- [ ] 共享 RIPConfig 的 Routes 内容（每路由器发同样的路由表，除非 SplitHorizon 按各自 DstIP 过滤）。
- [ ] Routers=[] 或 nil = 单路由器（FlowSpec 自身）。

### 8.7 IPv6 审计

- [ ] RIPng EtherType=0x86DD。
- [ ] RIPng DstPort=521（不是 520）。
- [ ] RIPng Version=1（不是 2）。
- [ ] RIPng Route Entry 用 PrefixLen（不是 SubnetMask）。
- [ ] RIPng 不支持 Auth（Validate 报错）。
- [ ] RIPng SrcIP 必须是 IPv6（Validate 校验 FlowSpec.SrcIP 与 Version 一致）。

### 8.8 默认值审计

- [ ] Version="" → "v2"（Plan 与 Validate 都接受空）。
- [ ] Command="" → "response"。
- [ ] Scenario="" + Routes=nil → "response_default"。
- [ ] Rounds=0 → 1。
- [ ] AuthDataLen 空 → 16（md5 默认）；显式非 0 非 16 值（如 SHA-256=20）允许透传，Validate 仅校验 >0（`*uint8` 指针显式为 0 → 报错，见 T-ERR-17）。Marshal 行为：nil 指针在 JSON 输出中序列化为 `null` 字段，不显示默认化（见 §3 RIPAuth.AuthDataLen 注释）。
- [ ] FlowSpec.TTL=0 → 64（unicast）或 1（multicast）。

### 8.9 并发审计

- [ ] 多路由器场景无 data race（-race 测试）。
- [ ] 多路由器总发包数 = M × ⌈Routes/25⌉ × Rounds（不是只测无 race）。
- [ ] 共享 IPID 计数器在多路由器间独立（每路由器独立 nextIPID 序列）。
- [ ] GroupID 路由：同 GroupID → 同 PacketWorker 保序；不同 GroupID → 不同 worker 并发。

### 8.10 报文长度审计

- [ ] RTE 数量限制与完整 Payload 长度分别审计：无认证时最多 25 个 RTE、Payload ≤504B；MD5 首包最多 24 条路由 + 1 认证 entry，完整 Payload = 504 + 4 + AuthDataLen（AuthDataLen=16 时 524B，=20 时 528B）。
- [ ] UDP 长度字段 = 完整 Payload + 8。
- [ ] IP total-length = UDP 长度 + 20。
- [ ] 0 entry Response 的 Payload = 4 字节（仅 RIP 头）。

## 9. 集成点

### 9.1 types.go

新增 `RIPConfig`、`RIPRoute`、`RIPAuth`、`RIPRouter` 四个 struct（设计见 §3）。在 `FlowSpec` 中添加字段：

```go
RIP *RIPConfig `json:"rip,omitempty"`
```

位置：跟在 `RDP` 之后，按字母序插入（与现有 protocol-designs 约定一致）。

### 9.2 strategy_convert.go

`mapToFlowSpec` 需识别 `protocol="rip"`，把 `config` map 反序列化到 `FlowSpec.RIP`。字段名映射：

| strategy JSON | FlowSpec.RIP 字段 |
|---------------|-------------------|
| `version` | `Version` |
| `command` | `Command` |
| `domain` | `Domain` |
| `routes` | `Routes` |
| `auth` | `Auth` |
| `multicast` | `Multicast` |
| `scenario` | `Scenario` |
| `routers` | `Routers` |
| `rounds` | `Rounds` |
| `triggered_update` | `TriggeredUpdate` |
| `split_horizon` | `SplitHorizon` |
| `poison_reverse` | `PoisonReverse` |

### 9.3 protocol.go

`internal/protocol/protocol.go` 注册 RIP planner：

```go
Register("rip", func() core.Planner { return rip.NewPlanner() })
```

默认端口映射：`"rip": 520`，`"ripng": 521`（Version=ng 时由 planner 内部覆盖）。

### 9.4 builder.go

无需修改。RIP 走 UDP 路径，`L4Config{Protocol: "udp"}` 已被现有 UDP builder 支持。Payload 由 planner 完整组装（RIP 头 + entries + 可选 MD5 摘要），builder 仅透传到 UDP payload。

### 9.5 worker.go

无需修改。worker 按 GroupID 路由 PacketConfig，多路由器场景每路由器独立 FlowID，由 GroupID 控制是否同 worker 保序。

### 9.6 测试目录

- `internal/protocol/rip/rip_test.go`：单元测试（T-POS-1~33 含 T-POS-1b, T-EDGE-1~22, T-ERR-1~19）。
- `internal/protocol/rip/rip_integration_test.go`：集成测试（T-POS-26, T-POS-27, T-POS-28）。
- `internal/protocol/rip/rip_concurrency_test.go`：并发测试（T-POS-28 多路由器总吞吐 + -race）。T-POS-28 仅在此文件，不在主 rip_test.go 中重复。

### 9.7 MCP e2e 测试

复用现有 MCP e2e 框架（参考 RADIUS/SOCKS5 的 6-7 条 e2e 用例），为 RIP 准备 6 条：

1. `rip_v2_request_full`：v2 Request 全量路由。
2. `rip_v2_response_25`：v2 Response 25 entry。
3. `rip_v2_multicast`：v2 组播更新。
4. `rip_v2_simple_auth`：v2 明文认证。
5. `rip_v1_broadcast`：v1 广播更新。
6. `ripng_multicast`：RIPng IPv6 组播。

每条 e2e 用例断言 tshark 解析的字段（Command/Version/Route Entry 数/Metric），确保 wire format 正确。

### 9.8 文档交叉引用

- 本设计文档：`docs/protocol-designs/10-rip-design.md`（本文）。
- 未实现清单：`docs/protocol-designs/00-unimplemented-list.md`（RIP 在 P2 长尾，本设计完成后从未实现清单移除）。
- CLAUDE.md 测试策略：本设计的 §7 与 §8 严格遵循。

### 9.9 参考 pcap（实现期获取）

实现期需获取以下参考 pcap 验证 wire format：

- RIP v2 组播更新：Wireshark Sample Captures `rip.pcap`。
- RIP v2 明文认证：自造（Quagga/FRR 配置 `neighbor X authentication password Y`）。
- RIP v2 MD5 认证：自造（FRR 配置 `authentication mode md5`）。
- RIP v1 广播：Wireshark `rip-v1.pcap`（如有）。
- RIPng：Wireshark `ripng.pcap`（如有）。

无参考 pcap 时，以 RFC 2453/RFC 2080/RFC 4822 文本字段定义为最终裁判，tshark 解析为辅助验证。

---

**文档统计**：共 1316 行，覆盖协议概述、报文格式（v1/v2/RIPng）、Config 结构体、状态机、Plan 输出、15 类业务场景、73 条基础测试用例（本轮新增 1 个 T-POS-1b 参数化变体并补强 7 条已有用例的长度/字段断言）、10 节交叉对抗审计清单、9 节集成点。

## 修订记录 v1.1（2026-08-03）

本次修订基于 `audit/10-13-rip-modbus-enip-audit.md` §2 的 13 项对抗审计发现（3 CRITICAL + 4 HIGH + 4 MEDIUM + 2 LOW），逐条修复如下。

### CRITICAL 修复

| ID | 修复位置 | 修复要点 | 对应测试 |
|----|----------|----------|----------|
| R-CRIT-1 | §6.1（行 ~386-389）、§3 RIPConfig.Command/Scenario 注释、§4 状态机图、§4 场景映射表 | RIP 头 Command 字段从错误的 `02`（Response）修正为 `01`（Request）；全量请求 entry 的 AFI 从错误的 `0xFFFF` 改为 RFC 2453 §3.9.1 规定的 `0x0000`；删除"先写错再修正"自相矛盾段落；同步修正 §3 注释、§4 状态机图、§4 场景映射表中所有 `AFI=0xFFFF` → `AFI=0x0000` | T-POS-1 |
| R-CRIT-2 | §6.15 T-ERR-6、§3 RIPRoute.AFI 注释、§3 默认值表 RIPRoute.AFI 行、§6.15 新增 T-ERR-19 | T-ERR-6（原编号保留）语义重写：AFI=0xFFFF 仅用于 Auth 触发的认证条目（RFC 2453 §2.1.1），AFI=0xFFFF + Routes 非空 → Validate 报错，全量请求由 Scenario=request_full 自动生成 AFI=0x0000 entry（不通过用户设 0xFFFF 实现）；新增 T-ERR-19 覆盖"用户在 RIPRoute.AFI 显式设 0xFFFF → Validate 报错"路径（v1.1.2 由原 T-ERR-5b 重排为 T-ERR-19 纯数字编号）；§3 RIPRoute.AFI 注释明确"显式 0xFFFF → Validate 报错"；默认值表增加"显式 0xFFFF → Validate 报错" | T-ERR-19、T-ERR-6 |
| R-CRIT-3 | §7 测试表 T-POS-1 行 | T-POS-1 断言从错误的"Payload 第 5-8 字节=FF FF 00 00"改为正确的"Payload 第 5-6 字节=00 00 (AFI=0), 第 19-20 字节=00 01 (Metric=1)"，与 R-CRIT-1 修复后的 spec 同步 | T-POS-1 |

### HIGH 修复

| ID | 修复位置 | 修复要点 | 对应测试 |
|----|----------|----------|----------|
| R-HIGH-1 | §2.6 RIPng Route Entry | 删除第一份错误的"Route Tag 拆为高/低字节"表（与 RFC 2080 §2.1.1 矛盾，Route Tag 是 2 字节），仅保留第二份正确表（偏移 16 长度 2 Route Tag / 偏移 18 长度 1 Prefix Length / 偏移 19 长度 1 Metric）；增加注释强调 RFC 2080 §2.1.1 Route Tag = 2 字节 | T-POS-14、T-POS-15 |
| R-HIGH-2 | §2.7 末尾新增"多路由器场景 src_port 选择"段落、§6.13 末尾新增"src_port 非 RFC 行为声明" | 明确多路由器场景用临时端口（52001/52002/52003）是 trafficgen 的非标行为（违反 RFC 2453 §3.6 Response 源端口 = 520），目的是用 4-tuple 区分多路由器并保证 PacketWorker 按 4-tuple 保序；tshark 可能提示"非标准 RIP 源端口" | T-POS-16、T-POS-17、T-EDGE-22 |
| R-HIGH-3 | §6.8 Packet Length 计算、§8.4 认证审计 | Packet Length 从错误的把摘要自身长度纳入计算方式修正为 `4+1×20+1×20=44`，表示 regular RIPv2 packet 总长度；§8.4 增加不含 trailer header 与 digest 的说明 | T-POS-9 |
| R-HIGH-4 | §3 RIPConfig.SplitHorizon 注释、§6.15 新增 T-ERR-18 行、§8.5 水平分割审计 | 新增 `SplitHorizon=true + Multicast=true → Validate 警告`异常行（T-ERR-18）；§3 SplitHorizon 字段注释明确"与 Multicast=true 互斥，组播下不生效"；§8.5 增加"Validate 对该组合发出警告（见 §6.15 T-ERR-18）" | T-ERR-18 |

### MEDIUM 修复

| ID | 修复位置 | 修复要点 | 对应测试 |
|----|----------|----------|----------|
| R-MED-1 | §7 测试表 T-ERR-2 → T-POS-29、T-ERR-4 → T-POS-30 | Version="" 默认 v2 和 Command="" 默认 response 是正向默认化行为，不是负向；从 T-ERR 系列移到 T-POS 系列（T-POS-29、T-POS-30），断言改为字节级（RIP 头 Version/Command 字节值） | T-POS-29、T-POS-30 |
| R-MED-2 | §6.15 T-ERR-18 行、§7 新增 T-POS-31 | T-ERR-18 原表述"Routes 数 > 25 且 Auth 非 nil → Validate 报错"与"多包拆分仍合法"自相矛盾；修正为"合法（多包拆分）：首包 1 认证 + 24 路由，后续包无认证 entry"；新增 T-POS-31 覆盖此合法路径 | T-POS-31 |
| R-MED-3 | §3 RIPRoute.AFI 注释、§3 默认值表、§6.15 T-ERR-19 | RIPRoute.AFI 仅允许 0（自动）或 2（IPv4）；显式 0xFFFF → Validate 报错；§3 注释明确"AFI=0xFFFF 专用于认证条目，不应在 RIPRoute.AFI 显式设置"；§6.15 新增 T-ERR-19（v1.1.2 由原 T-ERR-5b 重排为 T-ERR-19 纯数字编号） | T-ERR-19 |
| R-MED-4 | §6.14 T-EDGE-22 行、§7 T-EDGE-22 行、§7 T-POS-17 行 | T-EDGE-22 显式指定 `GroupIDStrategy="inc"`（路由到不同 worker 真并发）；增加断言"100 路由器总发包时间 ≤ 单路由器耗时的 N 倍（N≥4）"；T-POS-17 改为 `GroupIDStrategy="fixed"`（同 worker 串行压力），与 T-EDGE-22 拆分为"压力（无 panic）"与"正确性（并发度）"两条独立用例（R-LOW-1 同步修复） | T-EDGE-22、T-POS-17 |

### LOW 修复

| ID | 修复位置 | 修复要点 | 对应测试 |
|----|----------|----------|----------|
| R-LOW-1 | §7 T-POS-17 行、§7 T-EDGE-22 行 | T-EDGE-22 与 T-POS-17 原"100 路由器并发"重复；拆分为 T-POS-17（`GroupIDStrategy="fixed"` 串行压力，无 panic）与 T-EDGE-22（`GroupIDStrategy="inc"` 真并发，断言并发度），明确分工 | T-POS-17、T-EDGE-22 |
| R-LOW-2 | §2.5 Auth Data Len 字段说明、§8.4 认证审计 | §2.5 Auth Data Len 注释增加"RFC 4822 §2.5：默认 16（MD5 输出），但允许其他算法（如 SHA-256=20）透传非 16 值。Validate 仅校验 >0，不强制 =16"；§8.4 同步更新 | T-POS-25、T-ERR-17 |

### 新增测试用例汇总

v1.0 → v1.1 新增 22 条测试用例：

| 编号 | 类型 | 覆盖审计 ID | 用例名 |
|------|------|-------------|--------|
| T-POS-29 | 正向 | R-MED-1 | Version="" 默认 v2 |
| T-POS-30 | 正向 | R-MED-1 | Command="" 默认 response |
| T-POS-31 | 正向 | R-MED-2 | Routes > 25 + Auth 非 nil 多包拆分合法 |
| T-EDGE-6 | 边界 | (补全) | Route entry 数=0 |
| T-EDGE-7 | 边界 | (补全) | Route entry 数=25 单包 |
| T-EDGE-8 | 边界 | (补全) | Route entry 数=26 拆 2 包 |
| T-EDGE-9 | 边界 | (补全) | Route entry 数=50 拆 2 包 |
| T-EDGE-10 | 边界 | (补全) | Route entry 数=51 拆 3 包 |
| T-EDGE-11 | 边界 | (补全) | IP=0.0.0.0 缺省路由 |
| T-EDGE-12 | 边界 | (补全) | IP=255.255.255.255 报错 |
| T-EDGE-13 | 边界 | (补全) | SubnetMask=0.0.0.0 缺省 |
| T-EDGE-14 | 边界 | (补全) | SubnetMask=255.255.255.255 主机路由 |
| T-EDGE-15 | 边界 | (补全) | SubnetMask 非连续掩码 警告 |
| T-EDGE-16 | 边界 | (补全) | PrefixLen=0 IPv6 缺省 |
| T-EDGE-17 | 边界 | (补全) | PrefixLen=128 IPv6 主机 |
| T-EDGE-18 | 边界 | (补全) | PrefixLen=129 报错 |
| T-EDGE-19 | 边界 | (补全) | Domain=0xFFFF 透传 |
| T-EDGE-20 | 边界 | (补全) | Routes=nil + Scenario="" 默认 |
| T-EDGE-21 | 边界 | (补全) | Routers=[] 单路由器 |
| T-ERR-19 | 负向 | (补全→v1.1.2 重排) | AFI=0xFFFF 用户显式设 报错 |
| T-ERR-17 | 负向 | (补全) | MD5 AuthDataLen=0 报错 |
| T-ERR-18 | 负向 | R-HIGH-4 | SplitHorizon=true + Multicast=true 警告 |

### 文档行数变化

- v1.0：965 行，48 条测试用例。
- v1.1：约 990 行（+25 行），70 条测试用例（+22 条）。

### 对抗复核

按 DOIP v1.2 经验，v1.1 修复后做对抗复核，确认：

1. **R-CRIT-1 修复彻底性**：全文搜索 `0xFFFF` 确认仅在认证条目（§2.4/§2.5/§6.7/§6.8）和 T-ERR-19/T-ERR-6（用户显式设报错）上下文出现，不再作为"全量请求"标识。状态机图、场景映射表、§3 注释、T-POS-1 断言全部同步为 `AFI=0x0000`。
2. **R-CRIT-2 修复彻底性**：T-ERR-6 重写后语义清晰（AFI=0xFFFF 仅用于 Auth 触发的认证条目）；新增 T-ERR-19 覆盖"用户显式设 0xFFFF"路径（v1.1.2 由原 T-ERR-5b 重排为 T-ERR-19 纯数字编号）；§3 RIPRoute.AFI 注释与默认值表一致。
3. **R-HIGH-1 修复彻底性**：§2.6 仅保留一份正确的 RIPng Route Entry 表（Route Tag = 2 字节，偏移 16 长度 2），无第二份矛盾表。
4. **R-HIGH-3 修复彻底性**：§6.8 DigestOffset = 44（4+20+20），不含摘要自身长度；§8.4 同步更新说明。
5. **R-MED-4 修复彻底性**：T-EDGE-22 显式 `GroupIDStrategy="inc"` 并断言并发度（N≥4 倍速比），不是只测无 race。
6. **测试用例编号连续性**：T-POS-1~31、T-EDGE-1~22、T-ERR-1~18（含 T-ERR-19）。T-ERR-2/T-ERR-4 编号空缺（原 Version/Command 空字符串默认化用例已移至 T-POS-29/T-POS-30）；新增 T-ERR-19（AFI=0xFFFF 用户显式设）；原 T-ERR-6（AFI+Routes 互斥）编号保留为 T-ERR-6；其余负向行按 §7 测试表统一重新编号（T-ERR-7~18），§6.15 与 §7 测试表完全一致。

## 修订记录 v1.1.1（2026-08-03）

| 审计编号 | 严重度 | 修复内容 | 文档章节 | 对应测试 |
|---------|--------|----------|---------|----------|
| R-NEW-1 | MEDIUM | `RIPAuth.AuthDataLen` 从 `uint8` 改为 `*uint8`，以区分缺省（nil，JSON 缺省或 null，默认 16）与显式 0（`ptr(0)`，Validate 报错）；这是破坏性字段类型变更。同步更新 T-ERR-17 与默认值审计说明。 | §3、§6.15、§8.8 | T-ERR-17 |

## 修订记录 v1.1.2（2026-08-03）

本次第二轮返工基于 26 项新审计发现（HIGH 1 + MEDIUM 13 + LOW 12），逐条修复如下。

| 编号 | 严重度 | 修复内容 | 文档章节 | 对应测试 |
|-----|--------|----------|---------|----------|
| H-1 | HIGH | §6.8 DigestOffset 公式推广为"含 1 条认证 entry + N 条真实路由时，DigestOffset = 4 + 20×(1 + N)，与 AuthDataLen 无关"；T-POS-9 断言改为具体公式 = 44（4+20×(1+1)） | §6.8、§7 | T-POS-9 |
| M-1 | MEDIUM | 文档头版本号 1.1 → 1.1.2；行数统计 → 约 1150；测试用例数 70 → 72 | 行 7、行 995 | — |
| M-2 | MEDIUM | §3 新增 RIPAuth.AuthDataLen JSON 反序列化说明表（null/缺失→nil=16, 0→ptr(0)报错, >0→ptr(n)透传） | §3 | T-ERR-17 |
| M-3 | MEDIUM | v1.1.1 修订表加 "对应测试" 列；新增 §3 JSON 反序列化说明表，标注 JSON Schema 影响（nil→默认 16，ptr(0)→报错） | §16 v1.1.1、§3 | T-ERR-17 |
| M-4 | MEDIUM | §3 默认值表补 TriggeredUpdate=false、Scenario="" | §3 | T-POS-18、T-POS-13 |
| M-5 | MEDIUM | §7 测试表前言 "至少 28 条" → "共 70 条"（v1.1.2 后共 72 条） | §7 | — |
| M-6 | MEDIUM | §3 场景映射删除 IsResponse 伪字段表述，改为"Planner 内部在 Request 后追加 Response（视作 request_full 场景的固定后置步骤）"；§4 状态机图同步删除 IsResponse=true 分支 | §3、§4 | T-POS-1 |
| M-7 | MEDIUM | §6.11 triggered_update 分支加注释"TriggeredUpdate=true 时忽略 Command 字段，强制按 Response 处理" | §6.11 | T-POS-13 |
| M-8 | MEDIUM | §6.13 新增"未设 src_port 时的默认行为"说明（用户未设则从 52001 起按 router 索引动态分配） | §6.13 | T-POS-16 |
| M-9 | MEDIUM | §3 PoisonReverse 注释加"组播下不生效——组播无具体接收方，SplitHorizon 与 PoisonReverse 均跳过过滤（与 SplitHorizon 一致）"；Validate 对 {PoisonReverse=true, Multicast=true} 组合发出警告 | §3 | T-ERR-18（扩展） |
| M-10 | MEDIUM | 新增 T-POS-32：v1 + multicast=true → DstIP=255.255.255.255，TTL=1，忽略用户 DstIP | §7、§8.3 | T-POS-32 |
| M-11 | MEDIUM | 新增 T-POS-33：Domain=0x0001 → RIP 头第 3-4 字节=00 01 | §7、§2.1 | T-POS-33 |
| M-12 | MEDIUM | §6.8 DigestOffset 公式推广为 N 条路由场景（与 H-1 合并修复） | §6.8 | T-POS-9 |
| M-13 | MEDIUM | T-ERR-5b 改为 T-ERR-19 纯数字编号；§6.15、§7、§9.6 全部同步 | §6.15、§7、§9.6 | T-ERR-19 |
| L-1 | LOW | §3 RIPAuth.AuthDataLen 注释加"Marshal 行为：当 AuthDataLen == nil 时 JSON 输出 'auth_data_len': null（不显示默认化）" | §3 | — |
| L-2 | LOW | §8.8 默认值审计括号语法修正为标准表格表述（"nil 指针在 JSON 输出中序列化为 null 字段，不显示默认化"） | §8.8 | T-ERR-17 |
| L-4 | LOW | §7 测试表加排序说明（T-POS 顺序、T-EDGE 顺序、T-ERR 顺序，含 T-ERR-19 编号变更说明） | §7 | — |
| L-5 | LOW | §2.4 加"本表仅适用于 simple 类型"标注（md5 见 §2.5） | §2.4 | — |
| L-6 | LOW | §9.6 加"T-POS-28 仅在此文件，不在主 rip_test.go 中重复" | §9.6 | T-POS-28 |
| L-7 | LOW | §7 T-POS-9 给出具体 DigestOffset 期望值公式 = 4+20×(1+1)=44（与 H-1 合并修复） | §7 | T-POS-9 |
| L-8 | LOW | §7 T-POS-1 加中间字节断言（Payload[0]=0x01, [1]=0x02, [2:4]=0x0000, [4:6]=00 00, [18:20]=00 01） | §7 | T-POS-1 |
| L-9 | LOW | §3 默认值表 RIPAuth.AuthDataLen 行加 "(md5 类型默认)" | §3 | — |
| L-10 | LOW | §2.7 "默认 52001+" 改为"用户未设则继承 FlowSpec.SrcPort，若 FlowSpec.SrcPort 也未设，则由 worker 端的 4-tuple 分配器按 router 索引动态分配（默认从 52001 起递增分配）" | §2.7 | T-POS-16 |
| L-11 | LOW | §6.13 加"未设 src_port"示例（与 M-8 合并修复） | §6.13 | T-POS-16 |
| L-12 | LOW | v1.1.1 修订表统一格式（加"对应测试"列，与 L-2/M-3 合并修复） | §16 v1.1.1 | — |

### 文档行数变化

- v1.1：约 990 行，70 条测试用例。
- v1.1.2：约 1150 行（+160 行），72 条测试用例（+2 条：T-POS-32、T-POS-33；T-ERR-5b → T-ERR-19 编号重排，净增 1 条）。

### 对抗复核

1. **H-1/M-12/L-7 修复彻底性**：§6.8 Packet Length 通用公式 `4 + 20×(1 + N)` 与 AuthDataLen 无关；T-POS-9 断言给出具体值 = 44（4+20×(1+1)）；§8.4 认证审计与 §6.8 同步。
2. **M-2/M-3/L-1/L-2 修复彻底性**：RIPAuth.AuthDataLen 指针语义在 §3 字段注释、JSON 反序列化表、默认值审计、v1.1.1 修订表四处统一表述（nil=缺省=16 / ptr(0)=报错 / ptr(n)=透传）。
3. **M-6/M-7 修复彻底性**：全文搜索 "IsResponse" 确认已无残留；triggered_update 强制 Response 行为在 §6.11 注释中明确。
4. **M-9 修复彻底性**：§3 PoisonReverse 注释与 §3 SplitHorizon 注释平行说明组播下不生效；§6.15 异常表覆盖 {SplitHorizon=true, Multicast=true} 警告。
5. **M-13 修复彻底性**：T-ERR-5b → T-ERR-19 编号变更在 §6.15、§7 测试表、§9.6 测试目录、§16 v1.1 修订记录、§16 v1.1.2 修订记录中全部同步，无残留 "T-ERR-5b" 引用。
6. **测试用例编号连续性**：T-POS-1~33（含 v1.1.2 新增 T-POS-32、T-POS-33）、T-EDGE-1~22、T-ERR-1~19（含 v1.1.2 重排 T-ERR-19 = 原 T-ERR-5b）。

## 修订记录 v1.1.3（2026-08-03）

本次第三轮返工基于 `audit/10-13-rip-modbus-enip-audit.md` 末尾 "## 三轮审计 RIP v1.1.2" 章节的 14 项新审计发现（CRITICAL 2 + HIGH 3 + MEDIUM 5 + LOW 4），逐条修复如下。

### CRITICAL 修复

| ID | 修复位置 | 修复要点 | 对应测试 |
|----|----------|----------|----------|
| R-3-CRIT-1 | §2.5（MD5 trailer 表）、§6.8（报文示例）、§5.4（认证对 PacketConfig 的影响）、§8.4（认证审计）、§8.10（报文长度审计）、T-POS-9、T-POS-25 | MD5 认证 trailer 按 RFC 4822 §2.1 完整布局：在 regular RIPv2 packet 之后追加 4B trailer header `FF FF 00 01`（0xFFFF=RIP-2 认证标记 + 0x0001=认证类型=MD5），后接 16B 摘要占位（0xAA）。总 Payload 从 60B 改为 64B；本轮 v1.1.4 另补充认证 Payload 上限与完整长度计算。字段名 "Digest Offset" → "RIPv2 Packet Length (RFC 4822 §2.1)" | T-POS-9、T-POS-25 |
| R-3-CRIT-2 | §3（RIPConfig.Command 注释）、§4 状态机图、§4 场景映射表、§6.1（hex entry 与注释）、T-POS-1 | `request_full` 场景的全量请求 entry Metric 从错误的 1 改为 RFC 2453 §3.9.1 规定的 16（infinity）。hex entry 末尾 `00 01` → `00 10`；注释 "Metric=1" → "Metric=16（RFC 2453 §3.9.1: infinity）"。T-POS-1 断言从 "Payload[18:20]=00 01 (Metric=1)" 改为 "Payload[18:20]=00 00 (Metric 高 2 字节=0), Payload[20:24]=00 00 00 10 (Metric=16)" | T-POS-1 |

### HIGH 修复

| ID | 修复位置 | 修复要点 | 对应测试 |
|----|----------|----------|----------|
| R-3-HIGH-1 | §2.5（字段名）、§6.8（公式与描述）、§5.4、§8.4 | 字段名 "Digest Offset" → "RIPv2 Packet Length (RFC 4822 §2.1)"；描述从旧的偏移表述改为 regular RIPv2 packet 总长度（不含认证 trailer）。与 R-3-CRIT-1 同源但侧重文档术语层面 | T-POS-9 |
| R-3-HIGH-2 | §6.15 异常表、T-ERR-18 | §6.15 新增行 `PoisonReverse=true + Multicast=true | Validate 警告（组播无具体接收方，PoisonReverse 不生效；planner 跳过过滤）`；T-ERR-18 描述扩展为 "SplitHorizon=true + Multicast=true 或 PoisonReverse=true + Multicast=true → Validate 警告"，与 §3 RIPConfig.PoisonReverse 注释形成闭环 | T-ERR-18（扩展） |
| R-3-HIGH-3 | §6.1（新增 "Planner 自动追加 Response" 段落）、§7 新增 T-POS-1b | §6.1 显式描述 `request_full` 场景的 Planner 自动追加 Response 行为：明确这是 trafficgen 的非 RFC 实现便利（同一 4-tuple 上模拟 Request/Response 交换），Request 与 Response 共享 FlowID，PacketIndex 递增。新增 T-POS-1b 断言 2 个 PacketConfig：包 0=Request (Command=1, AFI=0, Metric=16)，包 1=Response (Command=2, 含默认路由) | T-POS-1b |

### MEDIUM 修复

| ID | 修复位置 | 修复要点 | 对应测试 |
|----|----------|----------|----------|
| R-3-MED-1 | §6.4 v1 Route Entry 描述 | "后 12B 全 0" 改为 "后 8B 全 0（偏移 8-11 掩码字段=0、偏移 12-15 下一跳字段=0）"，与 §2.2 v1 RTE 布局一致（偏移 16-19 是 Metric=1，不是 0） | T-POS-4 |
| R-3-MED-2 | §7 测试表 T-ERR-14 | T-ERR-14 类型从 "负向" 改为 "警告"，断言明确标注 "警告而非报错，行为同 §6.15 异常表中'警告'行"。避免负向分类下期望"不报错"的语义矛盾 | T-ERR-14 |
| R-3-MED-3 | T-POS-9、T-POS-25 | T-POS-9 断言增加 "Payload[44:48]=FF FF 00 01（MD5 trailer header，RFC 4822 §2.1）" 与 "Payload[48:64]=16B 0xAA"；T-POS-25 类似增加 "Payload[44:48]=FF FF 00 01" 与 "Payload[48:68]=20B 0xAA（AuthDataLen=20 摘要占位）"。与 R-3-CRIT-1 同源，侧重测试断言加强 | T-POS-9、T-POS-25 |
| R-3-MED-4 | §3 RIPRoute.NextHop 注释 | RIPRoute.NextHop 注释增加 "RIPng 忽略此字段（RFC 2080 §2.1.1 无 Next Hop 字段，下一跳隐含为发送方）；若用户为 RIPng 设置 NextHop，Validate 报错或忽略（实现选报错，更严格）" | — |
| R-3-MED-5 | §6.4 v1 DstIP 处理 | "默认广播 DstIP=255.255.255.255（multicast=true 时 v1 用广播）" 改为 "如 multicast=true 则 DstIP=255.255.255.255（v1 无组播，强制广播；参见 T-POS-32）。如 multicast=false 则 DstIP 使用 FlowSpec.DstIP 或 255.255.255.255（v1 传统行为）"，消除 multicast=false 时的歧义 | T-POS-32 |

### LOW 修复

| ID | 修复位置 | 修复要点 | 对应测试 |
|----|----------|----------|----------|
| R-3-LOW-1 | §2.7、§6.6、§6.13 | "RFC 2453 §3.9.2" 改为 "RFC 2453 §3.6"（Response 源端口=520 的实际定义在 §3.6 Output Processing；§3.9.2 不存在于 RFC 2453） | T-POS-6、T-POS-16 |
| R-3-LOW-2 | §6.4 v1 RTE 字段描述 | "RouteTag=0" 改为 "MustBeZero=0（v1 无 Route Tag 字段，偏移 2-3 固定为 0）"，与 §2.2 v1 RTE 字段表一致（v1 偏移 2 字段名为 MustBeZero，非 Route Tag） | T-POS-4 |
| R-3-LOW-3 | §5.1 单包结构示例 | §5.1 单包 PacketConfig 示例增加注释 "此示例为 Request 包（SrcPort=52001 为临时端口，符合 RFC 2453 §3.6）。Response 包 SrcPort=520"，消除 SrcPort=52001 与 §2.7 RFC 声明的冲突 | — |
| R-3-LOW-4 | §3 RIPAuth.Password 注释 | "超出截断" 改为 "超出报错（与 T-ERR-10 一致）"，与 §6.15 T-ERR-10 与 §8.4 行为统一（实现选报错，更严格） | T-ERR-10 |

### 新增测试用例汇总

v1.1.2 → v1.1.3 新增 1 条测试用例：

| 编号 | 类型 | 覆盖审计 ID | 用例名 |
|------|------|-------------|--------|
| T-POS-1b | 正向 | R-3-HIGH-3 | request_full 自动追加 Response |

### 文档行数变化

- v1.1.2：约 1150 行，72 条测试用例。
- v1.1.3：约 1180 行（+30 行），73 条测试用例（+1 条：T-POS-1b）。

### 对抗复核

1. **R-3-CRIT-1 修复彻底性**：历史记录确认 trailer 字段布局已同步为 RIPv2 Packet Length + 4B trailer header + digest；认证 Payload 上限与完整长度计算在 v1.1.3 记录中尚未覆盖，留待下一轮补充。
2. **R-3-CRIT-2 修复彻底性**：全文搜索 "metric=1" 在 request_full 上下文已全部改为 "metric=16/infinity"；§3 RIPConfig.Command 注释、§4 状态机图、§4 场景映射表、§6.1 hex entry 与注释、T-POS-1 断言五处同步。hex entry 末尾 `00 10` = 16（infinity）。
3. **R-3-HIGH-2 修复彻底性**：§6.15 异常表新增 PoisonReverse+Multicast 行，T-ERR-18 扩展覆盖两种组合，与 §3 RIPConfig.PoisonReverse 注释、§3 RIPConfig.SplitHorizon 注释、§8.5 水平分割审计四处一致。
4. **R-3-HIGH-3 修复彻底性**：§6.1 显式描述 "Planner 自动追加 Response" 行为并标注非 RFC 实现便利；T-POS-1b 断言 2 个 PacketConfig（Request + Response）。
5. **R-3-MED-3 修复彻底性**：T-POS-9/T-POS-25 断言同时验证 trailer header（FF FF 00 01）与摘要占位（0xAA），实现者无法通过跳过 trailer header 让测试通过。
6. **测试用例编号连续性**：T-POS-1, T-POS-1b, T-POS-2~33（含 v1.1.2 新增 T-POS-32、T-POS-33）、T-EDGE-1~22、T-ERR-1~19。T-POS-1b 紧随 T-POS-1，保留 T-POS-2~33 编号不变，避免下游引用断裂。

## 修订记录 v1.1.4（2026-08-03）

本次第四轮返工基于第四轮对抗复审的 13 项新发现（CRITICAL 2 + HIGH 3 + MEDIUM 5 + LOW 3），逐条修复如下。

### CRITICAL 修复

| ID | 修复位置 | 修复要点 | 对应测试 |
|----|----------|----------|----------|
| R-4.01 | §2.5 RIPv2 Packet Length 字段说明、§2.5 末段、§6.8 通用公式、§8.4 认证审计 | 字段语义从"指向 trailer header 起始位置的偏移"（offset 语义）改为"regular RIPv2 packet 的总长度（从 RIP 头起始计算），不包含 trailer header 和 digest"。公式统一为 `PacketLength = 4 + 20 × entry_count`，其中 `entry_count = 认证 entry + 普通路由条目`。§2.5 末段明确"它不是 offset 或 pointer"，与 RFC 4822 §2.1 一致 | T-POS-9、T-POS-25 |
| R-4.02 | §2.8 新增 §2.8.1（无认证）与 §2.8.2（MD5 认证）子节、§8.10 报文长度审计、T-POS-9、T-POS-25、T-POS-27、T-POS-31 | 区分无认证（最大 Payload=504B）与 MD5 认证（首包最多 24 条路由；完整 Payload = 504 + 4 + AuthDataLen）；为 AuthDataLen=16（524B）与 AuthDataLen=20（528B）分别给出完整 Payload 长度断言；§8.10 拆分为"RTE 数量限制"和"完整 Payload 长度"两条独立审计项 | T-POS-9、T-POS-25、T-POS-27、T-POS-31 |

### HIGH 修复

| ID | 修复位置 | 修复要点 | 对应测试 |
|----|----------|----------|----------|
| R-4.03 | §2.5 认证 entry Auth Type 行、§2.5 trailer header Type 行、§8.4 认证审计、T-POS-9、T-POS-25 | §2.5 两个表格行内醒目标注：认证 entry 的 Auth Type=0x0003 与 trailer header 的 Type=0x0001 属于不同结构，二者不可混淆。T-POS-9/T-POS-25 断言增加 `Payload[6:8]=00 03`（认证 entry 内的 Auth Type）与 `Payload[44:48]=FF FF 00 01`（trailer header 的 Type）双断言，确保实现者无法通过合并两字段作弊 | T-POS-9、T-POS-25 |
| R-4.04 | §6.1 Planner 自动追加 Response 段落、T-POS-1b | 明确 request_full 的"同向序列模拟"语义：自动 Response 与 Request 共用 SrcIP/DstIP/SrcPort/DstPort 与组播设置，不反转四元组；多路由器场景中每个 Router 的自动 Response 使用该 Router 自己的四元组。T-POS-1b 增加 SrcIP/DstIP/SrcPort/DstPort 字段断言 | T-POS-1b |
| R-4.05 | §2.1 Version 字段说明、T-POS-14 | §2.1 Version 行改为"v1=1、v2=2、RIPng=1 但仅在 `version='ng'`、UDP 521、IPv6 下解释"；新增"Version 字节单独不能识别 RIP v1 与 RIPng——两者均=1，必须结合 UDP 端口与 IP 协议族区分"说明。T-POS-14 增加完整 RIP 头字节断言 `Payload[0:4]=02 01 00 00` 与 UDP 521 端口断言 | T-POS-14 |

### MEDIUM 修复

| ID | 修复位置 | 修复要点 | 对应测试 |
|----|----------|----------|----------|
| R-4.06 | §6.4 v1 RTE 描述、T-POS-4 | "后 8B" 明确仅指 RTE 偏移 8-15（mask=0 + next-hop=0）；T-POS-4 增加 `Payload[20:24]=00 00 00 01`（Metric=1）字节断言 | T-POS-4 |
| R-4.07 | §6.4 v1 Metric 偏移表述 | v1 RTE 描述精确化：Metric 位于 RTE 偏移 16-19，对应整个 Payload 偏移 20-23；与 §2.2 v1 RTE 字段表一致 | T-POS-4 |
| R-4.08 | §2.5 Auth Data Len 字段说明、§8.4 认证审计、§8.8 默认值审计 | §2.5 末段增加：AuthDataLen 非 16 是 trafficgen 私有扩展，不宣称为标准 MD5。若只实现 MD5，Validate 必须强制 `AuthDataLen=16`；§8.4 与 §8.8 同步更新 | T-POS-25、T-ERR-17 |
| R-4.09 | §2.8 新增 MD5 公式与示例、§8.10 报文长度审计、T-POS-9、T-POS-25、T-POS-27、T-POS-31 | §2.8 新增"无认证"标题与 MD5 完整 Payload 公式 `Payload = 4 + 20 × entry_count + 4 + AuthDataLen`；T-POS-9/T-POS-25 增加首包完整 Payload 长度断言（524B/528B）；T-POS-27/T-POS-31 增加首包长度断言；§8.10 拆分为 RTE 数量限制与完整 Payload 长度两条审计项 | T-POS-9、T-POS-25、T-POS-27、T-POS-31 |
| R-4.10 | §6.1 request_full 输入优先级段落、T-POS-1b | §6.1 末段新增优先级表（Scenario → Command → TriggeredUpdate → Routes）和三种 Routes 行为（nil/[]/非空）。T-POS-1b 拆分为基线（默认路由）与 T-POS-1b-variant（用户 Routes 优先）两条变体，断言自动 Response 的路由内容、四元组、组播设置 | T-POS-1b、T-POS-1b-variant |

### LOW 修复

| ID | 修复位置 | 修复要点 | 对应测试 |
|----|----------|----------|----------|
| R-4.11 | §7 测试表前言、§7.1 Spec 驱动映射、§7 测试总数说明、文末"文档统计"段落 | 统一所有统计为 73 条：§7 测试表前言、§7.1 Spec 驱动映射、§7 测试总数说明、文末"文档统计"段落四处的 70/73/1180/1229 行混用统一为 73 条与 ~1230 行；§7.1 报文长度映射补全 T-POS-27、T-POS-31 | — |
| R-4.12 | v1.1.3 修订记录 R-3-CRIT-1 修复要点 | 将"修复彻底性"改为"已同步 trailer 字段布局，但认证 Payload 上限仍需补充"——v1.1.3 修复未覆盖 MD5 首包完整 Payload 长度计算；本轮 R-4.02/R-4.09 补全 | T-POS-9、T-POS-25 |
| R-4.13 | §6.14 Metric=0 行、§6.15 Metric=0 行 | RFC 引用统一为 "RFC 2453 §3.6 的输入处理规定 metric 必须为 1-16"；删除与"§3.9.2 不存在"声明冲突的引用 | T-EDGE-1 |

### 新增/补强测试用例汇总

v1.1.3 → v1.1.4 新增/补强 7 条用例（含 1 个新增独立编号与 6 条已有用例的字节/长度断言补强）：

| 编号 | 类型 | 覆盖审计 ID | 用例名 |
|------|------|-------------|--------|
| T-POS-1b-variant | 正向（参数化变体） | R-4.10 | request_full 用户 Routes 优先 |
| T-POS-1b（补强） | 正向 | R-4.04 | 增加 SrcIP/DstIP/SrcPort/DstPort 字段断言 |
| T-POS-4（补强） | 正向 | R-4.06, R-4.07 | 增加 `Payload[20:24]=00 00 00 01` Metric=1 断言 |
| T-POS-9（补强） | 正向 | R-4.01, R-4.02, R-4.03, R-4.09 | 增加 Payload[6:8]=00 03、Payload[44:48]=FF FF 00 01、首包完整 Payload=524B 断言 |
| T-POS-14（补强） | 正向 | R-4.05 | 增加完整头 Payload[0:4]=02 01 00 00、UDP 521 端口断言 |
| T-POS-25（补强） | 正向 | R-4.02, R-4.03, R-4.08, R-4.09 | 增加 Payload[6:8]=00 03、Payload[44:48]=FF FF 00 01、首包完整 Payload=528B 断言 |
| T-POS-27（补强） | 集成 | R-4.02, R-4.09 | 增加首包完整 Payload=524B/528B 断言 |
| T-POS-31（补强） | 正向 | R-4.02, R-4.09 | 增加首包完整 Payload=524B/528B 断言 |

### 文档行数变化

- v1.1.3：约 1180 行，73 条基础用例（+1 条 T-POS-1b）。
- v1.1.4：1316 行（相对 v1.1.3 约 +136 行，含本轮修订记录），73 条基础用例 + 1 个 T-POS-1b 参数化变体 + 7 条已有用例的字节/长度断言补强。

### 对抗复核

1. **R-4.01 修复彻底性**：当前规范正文中 RIPv2 Packet Length 已统一为 regular RIPv2 packet 总长度语义；历史修订记录中的旧术语已改为历史事实描述，不再作为当前字段定义。
2. **R-4.02/R-4.09 修复彻底性**：§2.8 拆分为 §2.8.1（无认证，Payload ≤504B）与 §2.8.2（MD5，完整 Payload = 504 + 4 + AuthDataLen）；T-POS-9/T-POS-25/T-POS-27/T-POS-31 四条用例给出 524B/528B 长度断言；§8.10 拆分为 RTE 数量限制与完整 Payload 长度两条审计项。
3. **R-4.03 修复彻底性**：§2.5 两个表格行内醒目标注"两个字段属于不同结构"；T-POS-9/T-POS-25 双断言（Payload[6:8]=00 03 与 Payload[44:48]=FF FF 00 01）覆盖两条独立字段路径。
4. **R-4.04 修复彻底性**：§6.1 明确 request_full 的"同向序列模拟"语义；T-POS-1b 增加 SrcIP/DstIP/SrcPort/DstPort 字段断言；T-POS-1b-variant 增加用户 Routes 优先的同向断言。
5. **R-4.05 修复彻底性**：§2.1 Version 行增加 RIPng 解释前提；T-POS-14 完整 RIP 头字节 + UDP 521 端口双断言。
6. **R-4.06/R-4.07 修复彻底性**：§6.4 v1 RTE 描述精确化 Metric 偏移；T-POS-4 增加 `Payload[20:24]=00 00 00 01` 字节断言。
7. **R-4.08 修复彻底性**：§2.5/§8.4/§8.8 三处统一 AuthDataLen=16 是 MD5 强制值，非 16 是 trafficgen 私有扩展；T-POS-25 断言增加"不宣称为标准 MD5"语义标注。
8. **R-4.10 修复彻底性**：§6.1 优先级表与三种 Routes 行为并列定义；T-POS-1b 与 T-POS-1b-variant 覆盖默认路由与用户 Routes 两种路径。
9. **R-4.11 修复彻底性**：全文 70/73/1180/1229 行四处统计统一为 73 条/~1230 行；§7.1 报文长度映射补全 T-POS-27/T-POS-31。
10. **R-4.12 修复彻底性**：v1.1.3 R-3-CRIT-1 历史快照保留；本轮 R-4.02/R-4.09 补全 MD5 首包完整 Payload 长度计算。
11. **R-4.13 修复彻底性**：全文搜索 "§3.9.2" 在 §6.14/§6.15 当前章节已替换为 "§3.6 的输入处理"；v1.1.2 修订记录保留作为历史快照，与 v1.1.3 修订记录一致。
12. **测试用例编号连续性**：T-POS-1, T-POS-1b, T-POS-1b-variant, T-POS-2~33（含 v1.1.2 新增 T-POS-32、T-POS-33）、T-EDGE-1~22、T-ERR-1~19。T-POS-1b-variant 作为 T-POS-1b 的参数化变体紧邻 T-POS-1b 列出，不打乱 T-POS-2~33 编号顺序。

## 修订记录 v1.1.5（2026-08-04）

本次第五轮返工基于 `audit/10-rip-audit-r5.md` 的 7 项审计发现（HIGH 2 + MEDIUM 4 + LOW 1），逐条修复如下。

| 编号 | 严重度 | 修复内容 | 文档章节 | 对应测试 |
|------|--------|----------|----------|----------|
| R-5.01 | HIGH | §2.8.2 后续包 Payload 公式与 T-POS-31 描述矛盾：按 RFC 4822 §2.1 原文，MD5 认证 trailer 仅出现在首包，后续包不含。修正 §2.8.2 后续包公式为 `Payload = 4 + 20×M`（无 trailer），并更新 T-POS-31 描述明确"第 2 包无认证 trailer" | §2.8.2、T-POS-31 | T-POS-31 |
| R-5.02 | HIGH | §2.5 Auth Data Len 字段引用章节错误：RFC 4822 §2.5 实际为"RIPv2 Security Association"，Auth Data Len 字段定义在 §2.1。修正引用为 "RFC 4822 §2.1" | §2.5 | — |
| R-5.03 | MEDIUM | R-4.01 修复引入术语不一致：RFC 4822 §2.1 原文使用 "offset"，文档改为 "total length"。保留 "offset" 术语但加注说明 "数值上等于 regular packet 总长度" | §2.5 | — |
| R-5.04 | MEDIUM | T-POS-9、T-POS-25 缺少 MD5 认证 entry 关键字段字节级断言：补充 PacketLength、KeyID、AuthDataLen、SeqNum、MustBeZero 字段断言 | T-POS-9、T-POS-25 | T-POS-9、T-POS-25 |
| R-5.05 | MEDIUM | T-POS-1 缺少 request entry 完整字段断言：补充 RouteTag、IP、Mask、NextHop 字段断言 | T-POS-1 | T-POS-1 |
| R-5.06 | MEDIUM | §2.8.2 公式变量 N 未定义：补充定义 "M = 后续包中的 route entry 数（M ≤ 25）" | §2.8.2 | — |
| R-5.07 | LOW | §2.5 末段 RFC 章节引用错误：同 R-5.02，Auth Data Len 定义在 §2.1 | §2.5 末段 | — |

### 对抗复核

1. **R-5.01 修复彻底性**：§2.8.2 后续包公式已删除 `+ 4 + AuthDataLen` trailer 部分，明确后续包仅含 RIP 头 + entries；T-POS-31 描述同步更新为"第 2 包无认证 + 1 路由且无认证 trailer"，与 RFC 4822 §2.1 一致。
2. **R-5.02/R-5.07 修复彻底性**：§2.5 表格内与末段两处 "RFC 4822 §2.5" 已全部改为 "RFC 4822 §2.1"。
3. **R-5.03 修复彻底性**：§2.5 RIPv2 Packet Length 字段说明保留 "offset" 术语，同时加注 "数值上等于 regular packet 总长度"，兼顾 RFC 原文忠实性与实现理解。
4. **R-5.04 修复彻底性**：T-POS-9/T-POS-25 新增 PacketLength(44)、KeyID(1)、AuthDataLen(16/20)、SeqNum(12345)、MustBeZero(0) 五个字段的字节级断言，覆盖认证 entry 全部字段。
5. **R-5.05 修复彻底性**：T-POS-1 新增 RouteTag、IP、Mask、NextHop 字段全 0 断言，与 §6.1 hex dump `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00` 一致。
6. **R-5.06 修复彻底性**：§2.8.2 变量已统一为 M，并明确定义 "M = 后续包中的 route entry 数（M ≤ 25）"。
7. **跨修复一致性**：§2.8.2 后续包公式 `Payload = 4 + 20×M` 与 T-POS-31 "第 2 包无认证 trailer" 描述完全一致，实现者可明确判断后续包行为。



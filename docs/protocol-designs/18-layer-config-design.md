# 方案 C：分层配置架构设计

> 版本：v1.3.0（P1 review 修订版）
> 设计日期：2026-08-11
> 修订日期：2026-08-11（v1.3.0，参见修订记录）
> 范围：把当前"扁平协议字典 + 顶层平铺字段"的配置架构，重写为"层链（layers，层列表）+ schema（说明书）"的分层配置架构
> 实现位置：`trafficgen/internal/core/`（schema 定义、层注册表、校验）、`trafficgen/internal/core/strategy_convert.go`（配置解析重写）、各 `internal/protocol/<proto>/`（层生成器适配）
> 配套决策：本文档是设计稿，实现细节（层注册表全量字段、迁移计划、测试计划）在评审后补充

---

## 目录

1. [背景与问题](#1-背景与问题)
2. [目标与非目标](#2-目标与非目标)
3. [核心概念](#3-核心概念)
4. [层注册表（schema 集合）](#4-层注册表schema-集合)
5. [层类型](#5-层类型)
6. [配置格式](#6-配置格式)
7. [自动补全算法](#7-自动补全算法)
8. [配置优先级](#8-配置优先级)
9. [递归生成](#9-递归生成)
10. [校验规则](#10-校验规则)
11. [迁移与存量](#11-迁移与存量)
12. [示例](#12-示例)
13. [测试计划](#13-测试计划)
14. [实施计划](#14-实施计划)

---

## 1. 背景与问题

### 1.1 现状：扁平协议字典 + 顶层平铺字段

当前配置架构（`strategy_convert.go`）是**扁平字典**：

- `mapToFlowSpec` 用 `defaultString/getUint16` 等手写 getter 解析顶层字段（`src_ip`、`dst_port`、`ttl`、`vlan_id`……）
- 各协议用 `case` 分派解析协议子块（`case "tcp"`、`case "http"`、`case "dns"`……共 68 个 case）
- TCP/HTTP 子配置在 universal 段被所有协议通用读取（`cfg["tcp"]`、`cfg["http"]`）

**问题**：

1. **没有分层思想**：IP/TCP/应用层的字段全部平铺在顶层，配置长什么样完全靠记忆，没有结构约束
2. **没有组合能力**：GRE 内层复用顶层 `src_port/dst_port`（`gre/planner.go:186-291`），无法为"GRE 里的 HTTP"独立配置内层 IP/端口
3. **协议与传输绑定**：每个协议固定走 TCP 或 UDP，无法自由拼接"UDP 上的 HTTP""TLS 里的 SMTP"等组合
4. **没有自动补全**：字段缺省靠手写 getter 的默认值容错，没有"空配置自动生成整条协议栈"的能力
5. **扩展成本高**：新增一个可组合协议要同时改解析、生成、校验，无法复用已有层

### 1.2 设计目标

把配置改造成**层链 + schema** 架构，核心能力是**自由拼装**：

- 任意层任意组合：GRE 里可以放 HTTP、DNS、FTP；TLS 里可以放 HTTP、SMTP
- 空配置自动补全依赖链：写 `{"http":{}}` 就自动生成 `[ip → tcp → http]`
- 每层有 schema（说明书）：字段 + 默认值 + 依赖声明，缺省自动用默认值
- 手动配置值 > schema 默认值（用户写什么用什么）

### 1.3 约定（通俗表达）

本文档使用以下约定：

- **层**（layer）：协议栈中的一级，如 ip、tcp、http
- **层链**（layer chain）：一条有序的层列表，从外到内，如 `[ip, tcp, http]`
- **schema（说明书）**：每层声明的字段 + 默认值 + 依赖，系统据它补全和生成
- **硬依赖**（depends_on）：这层下面缺什么就自动补什么（默认启用）
- **可选底座**（optional_on）：这层可以垫在什么上面，但系统永不自动补，只有用户亲手写才生效

---

## 2. 目标与非目标

### 2.1 目标

| # | 目标 | 说明 |
|---|------|------|
| G1 | 分层配置（方案 C） | 配置按层组织，不再有独立顶层字段；`src_ip`、`dst_port` 等必须写进层里 |
| G2 | 层链 | 用户配置 = 一条有序层列表，从外到内 |
| G3 | 自由拼装 | 任意层任意组合，层与层之间通过 schema 声明依赖，互不硬编码 |
| G4 | 手动/自动双写法 | 手动 = 写全每层；自动 = 只写核心层，系统查 schema 补齐依赖链 |
| G5 | 每层有 schema | 字段 + 类型 + 默认值 + 依赖 + 约束，集中注册在层注册表 |
| G6 | 优先级明确 | 手动配置值 > schema 默认值，同层内生效 |
| G7 | 递归生成 | 从最内层往外生成字节，每层 = 本层头 + 内层字节 |

### 2.2 非目标

| # | 非目标 | 说明 |
|---|--------|------|
| N1 | 不实现协议本身 | 只改配置架构，不新增协议；已有 66 个注册 planner 的逻辑保留，改为按层适配 |
| N2 | 不迁移存量策略 | 存量策略（数据库已存的）直接删除，不迁移、不兼容解析（Q2 已定） |
| N3 | 不做配置兼容层 | 旧写法（顶层平铺 + 子块）不支持解析，所有测试用例用新层链写法重写（Q1 已定） |
| N4 | 不做 UI 层改动 | 本文档只涉及配置格式与生成架构，API 层（REST/MCP）的配置透传不变 |

---

## 3. 核心概念

### 3.1 层链（layers）

用户配置 = **一条有序的层列表**，从外（二层）到内（应用层）：

```json
{
  "layers": [
    { "ip": { "src": "10.0.0.1", "dst": "20.0.0.1" } },
    { "tcp": { "mss": 1460 } },
    { "http": { "method": "GET" } }
  ]
}
```

- 层链的**顺序**表达嵌套关系：`[ip, tcp, http]` = HTTP 包在 TCP 里，TCP 包在 IP 里
- 层链的**首层**是最外层（对端先看到），**末层**是最内层（应用层）
- 层链生成字节时**从最内层往外**递归：http 生成字节 → tcp 加头 → ip 加头

### 3.2 层（layer）

每层是 `{ "层名": { 字段配置 } }` 结构，层名即层类型（`ip`、`tcp`、`http`……）。

### 3.3 schema（说明书）

每层有一张 schema，声明该层：

- **字段**：类型 + 默认值 + 范围
- **硬依赖**（depends_on）：这层下面缺什么就自动补什么（默认启用）
- **可选底座**（optional_on）：这层可以垫在什么上面，但系统永不自动补（默认不启用）
- **内层要求**（inner_required）：隧道层专用，内层必须从什么层开始
- **角色**：终结层 / 隧道层 / 传输层 / 二层层

### 3.4 手动 / 自动双写法

| 写法 | 用户写什么 | 系统做什么 |
|------|-----------|-----------|
| 手动 | 写全每层 | 直接用，字段缺省用 schema 默认值 |
| 自动 | 只写核心层（如 `{"http":{}}`） | 查 schema 补齐依赖链（http→tcp→ip），全默认 |

### 3.5 优先级

**手动配置值 > schema 默认值**。同层内生效，不跨层覆盖。

### 3.6 一个包只有一个终结层

层链的**末层必须是终结层**（应用层，如 http），隧道层（tls、gre）和传输层（tcp、udp）都不能当末层。这是校验规则之一。

---

## 4. 层注册表（schema 集合）

### 4.1 设计

**每协议一张 schema，全部收在层注册表（layer registry，所有说明书的总目录）**。没有"组合说明书"——http、http+tls、gre+http 等组合用层链表达，复用靠依赖声明指向同一张 schema。

注册表是一个 `map[string]LayerSchema`，key 是层名，value 是 schema：

```go
// internal/core/layers/registry.go
type Registry struct {
    schemas map[string]LayerSchema  // key: 层名（"ip"、"tcp"、"http"……）
}

type LayerSchema struct {
    Name           string             // 层名
    Category       LayerCategory      // 角色：终结/隧道/传输/二层
    DependsOn      []string           // 硬依赖：缺了自动补（默认启用）
    OptionalOn     []string           // 可选底座：默认不启用，写了才生效
    InnerRequired  []string           // 隧道层专用：内层起点，缺了自动补
    Fields         map[string]FieldSchema  // 字段：类型+默认值+范围
    Constraints    []Constraint       // 校验规则（字段范围、层间约束）
}
```

### 4.2 schema 模板

每张 schema 长这样（以 http 为例）：

| 项 | 值 |
|----|----|
| name | `http` |
| category | 终结层 |
| depends_on | `[tcp]` |
| optional_on | `[tls]` |
| inner_required | （无） |
| fields | `method=GET`、`uri=/`、`version=1.1`、`headers={}`、`body=""` |
| constraints | 终结层全链只能一个 |

### 4.3 四张示例 schema

```yaml
http:                    # 终结层
  category: 终结层
  depends_on: [tcp]      # 硬依赖，自动补
  optional_on: [tls]     # 可选底座，默认不用 → {"http":{}} 生成的是 http 不是 https
  fields:
    method: GET
    uri: /
    version: "1.1"
    headers: {}
    body: ""

tls:                     # 隧道层
  category: 隧道层
  depends_on: [tcp]      # 自动补 tcp
  inner_required: []     # 内层可以是任意终结层（http/smtp/...），不用补
  fields:
    version: tls1.3
    sni: ""
    alpn: []
    role: client

gre:                     # 隧道层
  category: 隧道层
  depends_on: [ip]       # 外层 ip 自动补
  inner_required: [ip]   # 内层必须从 ip 开始，缺了自动补内层 ip
  fields:
    key: 0
    checksum: false
    sequence: false

tcp:                     # 传输层
  category: 传输层
  depends_on: [ip]
  fields:
    src_port: 0          # 0 = 由协议默认（http 用 80、tls 用 443）
    dst_port: 0
    mss: 1460
    window_size: 65535
    handshake: true
```

### 4.4 层注册表内容（完整）

以下为全部协议层的 schema 汇总（字段默认值与现有实现对齐，完整字段表见实现计划）：

| 层名 | 角色 | depends_on | optional_on | inner_required | 默认端口 |
|------|------|-----------|-------------|----------------|---------|
| ip | 二层层 | — | — | — | — |
| eth | 二层层 | — | — | — | — |
| vlan | 二层层 | — | eth（默认不启用） | — | — |
| tcp | 传输层 | ip | — | — | 0（由上层决定） |
| udp | 传输层 | ip | — | — | 0（由上层决定） |
| http | 终结层 | tcp | tls（默认不启用） | — | 80 |
| dns | 终结层 | udp（默认；可选 tcp） | tls（默认不启用） | — | 53 |
| ftp | 终结层 | tcp | tls（默认不启用） | — | 21 |
| smtp | 终结层 | tcp | tls（默认不启用） | — | 25 |
| tls | 隧道层 | tcp | — | —（内层任意终结层） | 443 |
| gre | 隧道层 | ip | — | ip | — |
| mpls | 二层层 | — | — | — | — |
| pppoe | 二层层 | — | — | — | — |
| … | … | … | … | … | … |

**注**：vlan 的 `optional_on: [eth]` 表示"vlan 垫在 eth 上"（默认不启用，用户写 vlan 时自动补 eth）；dns 的 `depends_on` 默认为 udp，用户可显式写 tcp 层覆盖（`{"dns":{}, "tcp":{}}` → `[ip → tcp → dns]`，**已实现**：schema 的 `TransportOn` 字段声明可用传输层，补全时用户显式写的可用传输层替代默认传输层，校验同样遵循）。**`https` 组合层已撤销**（见 §4.6），本表不含 https。

### 4.5 TLS 接线现状（重要约束）

**当前代码只有 tls 独立 planner 读 `spec.TLS`**（`tls/planner.go:166-169`，全库唯一），且只在一个协议（case "tls"）里被设置。**smtp/ftp/imap/pop3/mysql/postgresql/redis/grpc 等协议的 `optional_on: [tls]` 是本文档的设计目标，不是现状**：

| 协议 | 当前状态 |
|------|---------|
| tls | 独立 planner，读 `spec.TLS`，实现 TLS 1.2/1.3 握手 + 随机 ApplicationData |
| smtp/ftp/imap/pop3/mysql/postgresql/redis/grpc | **零 TLS 接线**：planner 里没有读 `spec.TLS`，没有 STARTTLS/隐式 TLS 逻辑 |
| syslog | 注释声称"engine layer handles TLS handshake"（`syslog/planner.go:426`），但 `need_tls` 从未被赋值，实际发 TCP 明文 |
| rdp | 占位 TLS ClientHello（`rdp/planner.go:559`），非真实 TLS 协商 |
| xmpp | STARTTLS 仅 XML 协商（未加密） |
| openvpn | 合成握手（`openvpn` 头注释"Encryption is NOT implemented"） |

**实现依赖**：要让 `optional_on: [tls]` 真正可用，需为这些协议补 TLS 内层委托（隧道层 tls 包它们的内层字节），这是实现计划 P2 的独立工作项，**不是本设计文档自动解决的**。本文档只定义架构与配置格式，TLS 接线能力是 P2 阶段的明确交付物之一。

### 4.6 撤销 https 组合层（review 发现的设计矛盾）

**初稿曾设计 `https` 组合层**（`http + tls`，用户写 `{"https":{}}` 一个层生成 `[ip → tcp → tls → http]`），review 发现三个矛盾，**已撤销**：

1. **与"每协议一张 schema"冲突**：https 不是独立协议，是组合层，违反"层注册表每层=一个协议"的架构一致性
2. **与"自由拼装"冲突**：https 是 http+tls 的硬编码组合，用户想拼 `http+gre+tls` 时无法表达，组合层反而限制了拼装自由
3. **与"手动 > 默认"冲突**：`{"https":{}}` 无法表达"只要 tls1.2"（tls 字段被 https 层吞掉）

**正确写法**（两种等价）：

```json
{ "layers": [ { "tls": {} }, { "http": {} } ] }        // 显式 tls 层（推荐）
{ "layers": [ { "tcp": {} }, { "tls": {} }, { "http": {} } ] }  // 全显式
```

不提供 https 快捷层，保持"层=协议"一一对应。

---

## 5. 层类型

### 5.1 四种角色

| 角色 | 含义（通俗） | 层举例 | 层链规则 |
|------|-------------|--------|---------|
| 终结层（terminal） | 最里面那层，应用层 | http、dns、ftp、smtp | 一个包只能有一个；层链末层必须是终结层 |
| 隧道层（tunnel） | 必须包别人 | tls、gre | 不能当末层；内层起点由 inner_required 声明 |
| 传输层（transport） | 只能垫底不能结尾 | tcp、udp | 不能当末层；一个包只能有一个传输层 |
| 二层层（L2） | 物理帧头 | eth、vlan、mpls | 自动补全的终点 |

### 5.2 层链合法性规则

1. **终结层唯一**：全链只能有一个终结层（http 或 dns 或 ftp……）
2. **传输层唯一**：全链只能有一个传输层（tcp 或 udp），且不能是末层
3. **隧道层不能是末层**：tls、gre 必须包内层
4. **二层层在最外**：eth、vlan、mpls 只能出现在链的最外层（或外层隧道之外）
5. **顺序必须符合依赖**：层链中每层的 depends_on 必须在它**更外层方向**出现（外层包内层，与 §7.5 不变量 1、§12 示例一致）

### 5.3 同层多实例

**同层协议可多次出现（双层 vlan、双层 ip），顺序即身份**：第一个是外层，最后一个是最内层，每层参数独立。校验规则允许 vlan、ip 重复，但终结层只能一个。

---

## 6. 配置格式

### 6.1 完整配置（方案 C 层链）

```json
{
  "protocol": "gre",
  "config": {
    "layers": [
      { "ip": { "src": "10.0.0.1", "dst": "20.0.0.1" } },
      { "gre": { "key": 100 } },
      { "ip": { "src": "192.168.1.1", "dst": "192.168.1.2" } },
      { "tcp": { "src_port": 12345, "dst_port": 80 } },
      { "http": { "method": "GET", "uri": "/" } }
    ]
  }
}
```

### 6.2 protocol 字段（保留但可省）

- 写 `"protocol": "gre"` → 声明**最外层协议**，用于选 planner + 顶层校验
- 不写 → 由层链**最外层**推断
- 写但不匹配层链最外层 → 校验报错（R3）

### 6.3 层链中的字段命名

层内字段沿用现有配置字段名（`src_ip`、`dst_port`、`ttl`、`mss`、`window_size`……），但**按层归位**：`src_ip` 在 `ip` 层内、`src_port` 在 `tcp`/`udp` 层内、`method` 在 `http` 层内。

**tcp 层的端口默认 0** = "由上层协议决定"（http 用 80、tls 用 443、dns 用 53）；上层终结层的 schema 声明默认端口，生成时填入。

### 6.4 显式 0 ≠ 缺失

用户写 `"dst_port": 0` 是**显式要求 0**（可能故意发非法包）；字段**没写**才走默认值。解析时区分"字段存在但值为 0"和"字段缺失"。

---

## 7. 自动补全算法

### 7.1 规则

**自动补全只补"硬依赖"（depends_on），永远不补"可选底座"（optional_on）**。tls、vlan 等可选层只能由用户亲手写出来。

### 7.2 算法（通俗版）

把用户写的链从外往里读：

1. 每层查自己的 schema；
2. 检查它下面缺不缺硬依赖 → 缺就插入；
3. 一直补到二层（eth）为止；
4. 隧道层检查内层起点是否满足 inner_required → 不满足就补；
5. 补完统一校验（终结层唯一、传输层不在末层、顺序合法）。

### 7.3 伪代码（v1.2.0 修正：依赖方向按 §12 示例定稿）

**补全分两趟：第一趟补"缺的硬依赖"，第二趟补"缺的内层起点"**。硬依赖按"该层更外层方向"定位插入点。

**方向约定（关键）**：层链首层=最外层，末层=最内层；`depends_on`（如 http→[tcp]、tcp→[ip]）**必须在依赖层更外层方向出现**，即"外层包内层"——http 需要 tcp 包它，所以 tcp 在 http 外面，补全示例见 §12.1 `[ip → tcp → http]`。

```
func CompleteChain(chain []Layer, reg Registry) ([]Layer, error):
    # 第一趟：硬依赖（depends_on），迭代直到稳定（新插入层自己的依赖也要补）
    changed := true
    while changed:
        changed := false
        for i := 0; i < len(chain); i++:
            schema := reg[chain[i].Name]
            for _, dep := range schema.DependsOn:
                if outerHas(chain, i, dep):    # 该层更外层（索引 < i）已有 dep
                    continue
                insert dep 于 chain 位置 i（该层外侧）   # depends_on 顺序 = 从外到内
                changed := true
                i++                            # 跳过刚插入的层

    # 第二趟：内层起点（inner_required），隧道层专用
    for i := 0; i < len(chain); i++:
        schema := reg[chain[i].Name]
        if schema.InnerRequired 非空:
            # 内层直接邻居必须满足起点要求
            if i+1 >= len(chain) or chain[i+1].Name not in schema.InnerRequired:
                insert schema.InnerRequired[0] 紧贴 chain[i] 内侧（位置 i+1）

    validate(chain)                              # 校验：终结层唯一、传输层不在末层、顺序合法
    return chain

# outerHas 检查 chain 中索引 < i 的层里是否存在 name（只查"更外层方向"）
func outerHas(chain, i, name) bool:
    for k := 0; k < i; k++:
        if chain[k].Name == name: return true
    return false
```

**关键区别**：`outerHas` 只查"该层更外层方向"是否已有依赖，**不查内层**——这样双层 ip 场景中，gre 的内层 ip 不会让外层 ip 被跳过（gre 依赖的外层 ip 在 gre 更外层补，内层 ip 由 `inner_required` 在 gre 更内层补，两层 ip 各司其职）。

### 7.4 补全结果验证（关键场景推演）

```
gre+http：
  用户写 [gre, tcp, http]
  ↓ 第一趟：gre 缺外层 ip（更外层无 ip）→ 插在 gre 外侧 → [ip, gre, tcp, http]
  ↓         tcp 更外层有 ip → 不补；http 更外层有 tcp → 不补
  ↓         （迭代结束）
  ↓ 第二趟：gre 的 inner_required=[ip]，内层直接邻居是 tcp ≠ ip → 补内层 ip
  ↓         → [ip, gre, ip, tcp, http]
  最终 [ip → gre → ip → tcp → http]   ← 外层 ip 在 gre 外，内层 ip 在 gre 内
```

**http+tls 手写：**

```
用户写 [http, tls]
  ↓ 第一趟：http 下方无 tcp → 插在 http 内侧 → [http, tcp, tls]
  ↓         tcp 下方无 ip → 插在 tcp 内侧 → [http, tcp, ip, tls]
  ↓         tls 下方无 tcp → 插在 tls 内侧 → [http, tcp, ip, tcp, tls]  ← 问题：tcp 重复
```

**这个推演暴露了 §7.3 伪代码的缺陷**：当 tls 写在 http 内侧（更内层）时，http 补的 tcp 和 tls 补的 tcp 会重复。**正确行为**：tls 的 depends_on=[tcp] 应该复用 http 补的 tcp，不重复插入。修正 `belowHas` 的语义——**tcp 只补一次**（传输层唯一，见 §5.2 规则 2）。

**修正后的完整补全结果：**

```
http+tls 手写：
  用户写 [http, tls]   ← 注意：这是错误写法（http 在外包 tls，§12.2 ⚠️）
  ↓ 第一趟：http 缺 tcp → 插在 http 外侧 → [tcp, http, tls]
  ↓         tcp 缺 ip → 插在 tcp 外侧 → [ip, tcp, http, tls]
  ↓         tls 更外层有 tcp → 不补（传输层唯一，复用 http 补的 tcp）
  ↓ 第二趟：tls 无 inner_required → 不补
  ↓ 校验：末层 tls 是隧道层不能当末层 → 报错 ✓（用户须按 §12.2 写 [tls, http]）
```

**正确写法 [tls, http]：**

```
用户写 [tls, http]
  ↓ 第一趟：tls 缺 tcp → 插在 tls 外侧 → [tcp, tls, http]
  ↓         tcp 缺 ip → 插在 tcp 外侧 → [ip, tcp, tls, http]
  ↓         http 更外层有 tcp → 不补
  ↓ 校验：末层 http 是终结层 → 通过
  最终 [ip → tcp → tls → http]   ← tls 手写，系统不自动补 tls（§7.1）
```

**结论**（v1.2.0 修正）：§7.3 伪代码按 §12 示例的方向约定（depends_on 在外层）重写，**第一趟迭代直到稳定**（新插入层自己的依赖也补），实现与文档一致。

（gre+http 的两层 ip 各司其职：外层 = 隧道端点，内层 = 真实主机。**系统补出来的层和用户手写的层用同一张 ip schema**，默认值相同；用户想改哪层就亲手写哪层，写了哪层只改哪层。）

### 7.5 自动补全的结果

补全后的层链**和用户手写全的层链完全等价**，生成逻辑不区分"用户写的"和"系统补的"。

**补全正确性的判定标准（等价性不变量）**：无论用户怎么补、补全实现怎么写，结果链必须满足：

1. 每层的全部 `depends_on` 都在该层更外层方向出现
2. 隧道层的直接内层邻居 ∈ `inner_required`（或内层由用户显式给出）
3. 传输层全链唯一（tcp/udp 不重复）
4. 终结层全链唯一
5. 末层是终结层、传输层/隧道层不在末层
6. 二层层（eth/vlan/mpls）只能出现在链最外的开头连续段（双层 vlan 时 vlan 均在链首，且按链序从外到内）

**实现建议**：补全算法以这 6 条不变量为验收条件，任何实现（迭代插入、递归、图遍历）只要最终满足不变量即正确。§7.3 的伪代码是参考实现，**不是唯一实现**。

---

## 8. 配置优先级

### 8.1 规则

**手动显式配置值 > schema 默认值**。层级越靠内层的手动配置，只影响那一层，不覆盖外层。

### 8.2 举例

```json
{
  "layers": [
    { "ip": { "src": "10.0.0.1" } },            // 手动：src 用 10.0.0.1；dst 没写 → schema 默认 20.0.0.1
    { "tcp": { "mss": 1460 } },                 // 手动：mss 用 1460；窗口没写 → 65535
    { "http": {} }                              // 空 → method=GET、uri=/、version=1.1 全默认
  ]
}
```

### 8.3 边界

- **同层内生效**：该层字段 vs 该层默认值
- **不跨层覆盖**：内层 http 的 GET 不会影响外层 ip 的 src
- **层链是"每层独立取值"**：层与层之间只传递字节，不传递配置值
- **显式 0 ≠ 缺失**（§6.4）：用户写 `"dst_port": 0` 用 0，没写才用默认

---

## 9. 递归生成

### 9.1 生成模型

层链生成字节时**从最内层往外**递归：

```
生成(层链[i]) = 本层头(生成(层链[i+1]))     # 每层 = 本层头 + 内层字节
```

- 最内层（终结层）先生成自己的应用载荷
- 每往上一层，加本层头部（tcp 加 TCP 头、ip 加 IP 头……）
- 最外层（二层层）生成物理帧

### 9.2 内层委托复用（统一"包内层"动作）

**tls 包 http、gre 包 http 走同一套机制**：隧道层（tls/gre）生成时把"内层字节生成"委托给内层协议，复用同一张 http schema，**不重写 http 逻辑**。

```go
// 隧道层生成器的统一接口
type LayerGenerator interface {
    Plan(ctx, layer, innerBytes []byte) ([]PacketConfig, error)
}
```

隧道层只做两件事：
1. 调用内层生成器拿内层字节（`inner := innerLayer.Plan(ctx, ...)`）
2. 包自己的头，输出整段字节

### 9.3 生成与解析的对偶

层链即"生成顺序"的镜像：生成从内到外，解析（tshark/接收方）从外到内。**层链的写法就是解析顺序**，方便测试对照。

### 9.4 隧道层特殊处理（gre 现状对齐）

gre 的 inner_required=[ip] 自动补内层 ip 后，内层 IP/TCP 字段（src/dst、端口）**独立于外层**：
- 外层 ip 的 src/dst = 隧道端点（对端可见）
- 内层 ip 的 src/dst = 真实主机（隧道内）
- 内层 tcp 的端口独立配置（不再复用顶层端口）

---

## 10. 校验规则

### 10.1 两层校验时机

| 时机 | 校验什么 | 何时执行 |
|------|---------|---------|
| **创建时**（策略创建） | 静态合法性：层类型合法、顺序合法、终结层唯一、传输层不在末层、字段范围（mss≥536 等） | 创建策略时，提前报错 |
| **运行时**（生成时） | 依赖上下文才知道的默认值补全（如端口按协议默认） | 生成流量时 |

### 10.2 创建时校验清单

| # | 规则 | 报错示例 |
|---|------|---------|
| V1 | 层名必须在层注册表中 | `unknown layer "foo"` |
| V2 | 终结层唯一 | `terminal layer "http" duplicated` |
| V3 | 传输层唯一 | `transport layer duplicated` |
| V4 | 末层必须是终结层 | `layer chain must end with a terminal layer, got "tcp"` |
| V5 | 传输层不能是末层 | 与 V4 合并为同一条消息（见下） |
| V6 | 隧道层不能是末层 | 与 V4 合并为同一条消息（见下） |
| V7 | 二层层只能出现在最外 | `layer "vlan" cannot be inside a tunnel` |
| V8 | 依赖顺序合法 | `layer "http" depends on "tcp" which is not below it` |
| V9 | 字段范围 | `tcp.mss 500 invalid: too small (min 536)` |
| V10 | protocol 与层链最外层一致 | `protocol "gre" does not match outermost layer "ip"` |

> **消息口径（实现定稿）**：V4/V5/V6 在 `validateChain` 中合并为一条
> `layer chain must end with a terminal layer, got "<层名>" (<类别>)`，类别标注
> transport / tunnel / l2 / network 区分违规类型。单层链豁免例外（§14.1）：
> `[tcp]`、`[http]` 等单层非隧道链中传输层/协议层可当末层（legacy 每协议风格，
> 与 ChainPlanner 合成链同口径）；隧道层单层（`[tls]`、`[gre]`）不豁免。

### 10.3 运行时校验清单

| # | 规则 | 说明 |
|---|------|------|
| R1 | 默认端口补全 | 终结层 schema 声明的默认端口（http 80、tls 443）填入下层 tcp |
| R2 | 字段默认值补全 | 未写的字段按 schema 默认值填 |
| R3 | 依赖链补全 | 硬依赖缺失时自动插入（§7） |

---

## 11. 迁移与存量

### 11.1 旧用例重写（Q1 已定）

**测试用例用新层链写法重写**。当前 `test/protocol_pcap/cases/` 下有 16 个 JSON 文件，共 **2057 个用例**（按 `proto` 统计：a2a 185、dnp3 70、doip 115、enip 135、gbt32960 105、mcp 79、modbus 213、mqtt 168、nfs 201、rip 71、smb 280、srv6 68、tcp 10、tds 131、tftp 226，另有 probe_smb 1 个诊断用例）。全部改为层链写法。

用例现状主要用顶层平铺写法（`src_ip` 1730 次、`dst_port` 995 次、`tcp` 子块 247 次、`http` 子块 7 次、`vlan_id` 2 次），重写时遵循 CLAUDE.md §Testing Policy：从 spec 推导、覆盖失败路径、断言可观察输出，不机械翻译。

### 11.2 存量策略直接删除（Q2 已定）

**存量策略（数据库已存的）不迁移、不兼容解析，直接删除**。新架构上线后，用户用新写法创建新策略。

### 11.3 上线步骤

1. 新架构实现完成（层注册表、补全、生成）
2. 测试用例重写 + 全部通过
3. 存量策略清理脚本（删除数据库中的旧策略）
4. 发布

---

## 12. 示例

### 12.1 http（最简，自动补全）

```json
{
  "layers": [
    { "http": {} }
  ]
}
```

系统自动补全为 `[ip → tcp → http]`，全默认：http method=GET、tcp 端口 80、ip 10.0.0.1→20.0.0.1。

### 12.2 http+tls（https，tls 手写）

```json
{
  "layers": [
    { "tls": {} },
    { "http": { "method": "POST", "uri": "/api" } }
  ]
}
```

**tls 手写**（optional_on 默认不启用，系统永不自动补），**层序：tls 在外、http 在内**（首层=最外层），补全后 `[ip → tcp → tls → http]`，tls 默认 tls1.3。

> ⚠️ **顺序易错点**：`[http, tls]`（http 在外）是错误写法——它表示 http 包 tls，校验会报错（末层 tls 是隧道层不能当末层）。正确写法是 tls 在外、http 在内。

### 12.3 gre+http（隧道，自动补双层 ip）

```json
{
  "layers": [
    { "gre": { "key": 100 } },
    { "http": {} }
  ]
}
```

自动补外层 ip + 内层 ip → `[ip → gre → ip → tcp → http]`（gre 硬依赖外层 ip、内层起点要求 ip，tcp 是 http 的硬依赖）。最简写法只需 `{"gre":{}}` + `{"http":{}}`，tcp 不用写。

### 12.4 双层 vlan（QinQ）

```json
{
  "layers": [
    { "vlan": { "id": 100 } },
    { "vlan": { "id": 200 } },
    { "ip": {} },
    { "http": {} }
  ]
}
```

两个 vlan 层按顺序：第一个是外层（0x88a8），第二个是内层（0x8100）。**顺序即身份**。注意 vlan 的 `optional_on: [eth]` 是默认不启用——用户写 vlan 时自动补 eth，不会把 vlan 当作可选项跳过。

### 12.5 手动写全 ip 层

```json
{
  "layers": [
    { "ip": { "src": "10.0.0.1", "dst": "20.0.0.1" } },
    { "tcp": {} },
    { "http": {} }
  ]
}
```

tcp/http 用默认，ip 层手动指定。

---

## 13. 测试计划

### 13.1 测试策略（遵循 CLAUDE.md §Testing Policy 8 条规则）

**测试必须从 spec 推导，覆盖失败路径，断言可观察输出**。以下每项测试都对应本文档的一个明确条款（§号）。

### 13.2 单元测试（internal/core/layers/）

| # | 测试 | 对应条款 |
|---|------|---------|
| T1 | 层注册表：所有 schema 注册完整，字段默认值正确 | §4.4 |
| T2 | 层链补全：http 空配置 → [ip, tcp, http] | §7.3 |
| T3 | 层链补全：gre 空配置 → [ip, gre, ip, tcp, http]（双层 ip） | §7.4 |
| T4 | 层链补全：tls 手写 → [ip, tcp, tls, http]，tls 不自动补 | §7.1 |
| T5 | 可选底座默认不启用：`{"http":{}}` 生成 http 非 https | §7.1 |
| T6 | 手动配置值 > schema 默认值（同层） | §8.1 |
| T7 | 显式 0 ≠ 缺失（`dst_port:0` 用 0，没写用默认） | §6.4 |
| T8 | 同层多实例：双层 vlan 顺序即身份（外层 0x88a8 内层 0x8100） | §5.3 |
| T9 | 校验 V1-V10 逐条：非法层名、终结层重复、传输层当末层、隧道层当末层、字段范围…… | §10.2 |
| T10 | 校验：protocol 与层链最外层一致 | §10.2 V10 |

### 13.3 集成测试（API → 引擎 → 输出）

| # | 测试 | 对应条款 |
|---|------|---------|
| T11 | 层链配置走完整链路：创建策略 → 生成流量 → pcap 输出，字节正确 | §9 |
| T12 | 隧道层内层委托：gre+http 生成，内层 http 字节正确 | §9.2 |
| T13 | 隧道层内层委托：tls+http 生成，内层 http 字节正确 | §9.2 |
| T14 | 创建时校验错误传播：非法层链 → 策略创建失败（不是生成时才报） | §10.1 |
| T15 | 旧用例重写后全部通过（2057 个用例，见 §11.1） | §11.1 |

### 13.4 负向测试

| # | 测试 | 对应条款 |
|---|------|---------|
| T16 | 空 layers → 报错 | §6.1 |
| T17 | 层名不在注册表 → 报错 | §10.2 V1 |
| T18 | 终结层重复（两个 http）→ 报错 | §10.2 V2 |
| T19 | 传输层当末层（[ip, tcp]）→ 报错 | §10.2 V5 |
| T20 | 隧道层当末层（[ip, tcp, tls]）→ 报错 | §10.2 V6 |
| T21 | 字段超范围（mss 500）→ 报错 | §10.2 V9 |
| T22 | protocol 与层链最外层不一致 → 报错 | §10.2 V10 |

### 13.5 性能测试

| # | 测试 | 对应条款 |
|---|------|---------|
| T23 | 层链生成性能：与扁平配置同量级（不因分层显著变慢） | §9 |

> **注意**：T3 引用的 §7.4 已改为"补全结果验证"；T4 的"tls 不自动补"断言可选底座逻辑（§7.1）；T5 与 §4.6 撤销 https 组合层一致（`{"http":{}}` 不生成 https）。

---

## 14. 实施计划

### 14.1 阶段划分

| 阶段 | 内容 | 交付物 |
|------|------|--------|
| P1 | 层注册表 + schema 定义 + 层链补全算法 | `internal/core/layers/`（新包），单测 T1-T10 |
| P2 | 层生成器适配：现有 66 个协议按层归位（ip/tcp/udp/http/dns/ftp/smtp 等公共层先做，长尾协议后做） | 各 `internal/protocol/<proto>/` 增加层生成器，集成测试 T11-T13 |
| P3 | 校验（创建时）+ protocol 字段推断 | `internal/core/validate.go` 重写，单测 T9-T10、T16-T22 |
| P4 | 旧用例重写（2057 个） | 全部用例新层链写法，T15 |
| P5 | 存量策略清理脚本 + 发布 | 数据库清理脚本 |

### 14.2 依赖与风险

| 风险 | 缓解 |
|------|------|
| 66 个注册 planner 全部适配工作量大（`cmd/server/main.go:354-420` 注册 66 个，含公共层与长尾协议） | 分层抽象后，公共层（ip/tcp/udp/eth）只做一次；长尾协议先保持独立 planner，仅适配接口 |
| 旧用例重写量大（2057 个） | 与 P2 并行推进；用例重写遵循"从 spec 推导"原则，不机械翻译 |
| 性能退化 | 层链生成在核心路径，P1 阶段就做性能测试（T23） |
| TLS 接线现状未实现 | 见 §4.5：当前仅 tls 独立 planner 读 `spec.TLS`，smtp/ftp/imap/pop3/mysql/postgresql/redis/grpc 的 `optional_on: [tls]` 是设计目标，不是现状；实现时需为这些协议补 TLS 内层委托 |

---

## 修订记录

| 版本 | 日期 | 内容 |
|------|------|------|
| v1.0.0 | 2026-08-11 | 初稿：基于需求确认清单 R1-R24 + E1-E5 整理 |
| v1.1.0 | 2026-08-11 | review 修订：修正用例数 2046→2057（§11.1）、协议数 50→66（§2.2/§14.1/§14.2）、新增 §4.5 TLS 接线现状约束、撤销 https 组合层（§4.6）、修正 §12.2 层序错误（http 在外 → tls 在外）、补全算法伪代码重写（§7.3）+ 推演验证（§7.4）+ 等价性不变量（§7.5） |
| v1.2.0 | 2026-08-11 | P1 实现修订：§7.3 伪代码依赖方向定稿（depends_on 在外层，外层包内层）——与 §12 全部示例一致（v1.1.0 的"下方/内层方向"与示例矛盾）；第一趟改为迭代直到稳定；§7.4 推演重写（gre 补内层 ip 是第二趟 inner_required 的结果）；§7.5 不变量 #1/#6 修正方向表述 |
| v1.3.0 | 2026-08-11 | P1 review 修订：实现"传输层替代"（§4.4 注记落地）——schema 新增 `TransportOn` 字段（可用传输层，第一个=默认）；补全第一趟与校验 V8 遵循替代（用户显式写可用传输层时不再补默认，如 `{"dns":{}, "tcp":{}}` → `[ip → tcp → dns]`）；修复注册表 TransportOn 顺序与 DependsOn[0] 不一致导致的替代失效 |
| v1.4.0 | 2026-08-15 | P2-P6 实现修订：§10.2 新增层链路径（`layers` 键 + `ValidateLayers`）；§11.2 决策落地——存量策略不迁移、不兼容解析、直接删除；P5 清理工具 `cmd/legacyclean`（分类：层链/遗留/畸形/replay，dry-run 默认 + backup 先行 + 单事务删除，实测 2023 遗留 + 1264 层链）；P6 MCP 同步——`manageStrategiesInput.Config` 教学层链格式、新增 `flowb_query_layers` 注册表查询工具（33 层字段/默认值/依赖 + 隧道内层嵌套）；协议推断语义定稿：**最外层**非骨架层（跳 ip/eth/vlan/mpls/pppoe/tcp/udp），隧道链推断隧道名（`[ip,gre,ip,tcp,http]` → `gre`），显式 protocol 必须与推断一致否则 V10 拒绝 |

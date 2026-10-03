# #109 radius（RADIUS · 远程认证拨号用户服务，UDP 1812/1813）设计契约

> 版本：v1.0.0（批次二 as-built 文档轨，#109 radius 续号）
> 日期：2026-09-29
> 车道：文档轨（`pipe/radius-doc`，基 `300dfc4`）
> 前置权威：`docs/CODE_DESIGN.md` **D-RADIUS-1**（P2 定稿 / P4 落码 `1501264` / P5 全绿 / P6 已验收）、`docs/TEST_CASES.md` **T-RADIUS-1…25**（P5 全绿）
> 存量用例：`trafficgen/test/protocol_pcap/cases/radius.json`（**25 例 = 14 正 + 11 负**，ID/顺序/包数/断言逐条机读实测，见 §9/§12.1）
> 规范基线：① **RFC 2865**（RADIUS 认证：§3 报文格式 / §4.1 Request Authenticator / §5 属性 TLV / §5.26 Vendor-Specific）；② **RFC 2866**（RADIUS 计费：§3 报文 + 1813 端口 + Accounting Request/Response Authenticator / §5.1 Acct-Status-Type=40 / §5.5 Acct-Session-Id=44）；③ **RFC 5997**（Status-Server=12 探询，§2/§3/§4.1）；④ **RFC 5176**（CoA/Disconnect 码族 40–45 + 3799 端口，§2.3）；⑤ **RFC 3579**（Message-Authenticator=80，§3.2/§3.3）；⑥ 本机 tshark 3.6.14 `radius.*` 字段表与 **25 例实测 pcap**；⑦ 本仓库落码（`internal/protocol/radius/` 三文件 **1358 行** + 接线，§11）；⑧ 旧基线 `docs/CODE_DESIGN.md` D-RADIUS-1 条目（内部契约，非外部规范）。
> 白话一句：**网络接入设备的"门禁对讲"——设备（NAS）冲服务器喊一句"这人能进吗"（Access-Request，带用户名等一串小标签），服务器回"能进"（Access-Accept）或"不能"（Access-Reject）；计费另开一条线（Accounting-Request/Response）。一句话一问一答，没有握手也没有告别，跑在 UDP 上，所以丢了就重喊。**

## 0. 本版定位与旧基线关系（门1 必答：基线继承关系）

本 #109 是 `D-RADIUS-1` 既有实现的 **as-built 契约文档**，不是新设计。文档阶段定位（需求文档 §3）：交付物是 design + testcase + cases JSON 三件套；本版把**已落码的实现与已全绿的 25 例**如实写成契约，不引入任何未实现能力，不声称任何未跑过的结论。

| # | 事项 | HEAD 实测（2026-09-29） | 本版处置 |
|---|---|---|---|
| 1 | 旧基线文档 | `docs/CODE_DESIGN.md:2809` D-RADIUS-1 条目（含门 1 对照表、决策对比、8 要素、验收）；`docs/TEST_CASES.md:3592` T-RADIUS-1…25 清单（含 P5 校准 4 处、C 类注记、枚举覆盖） | **承其事实**（层形/端口住处/13 锚词/随机性口径/校准 4 处逐条对齐）；本版是同一协议的**独立成文契约**，不与旧条目互为摘要 |
| 2 | 层注册 | `layers/registry.go:1870` 已注册 `radius`（`CategoryTerminal`，`DependsOn ["ip"]`，**Fields 9 键**） | as-built 定稿（§11.1） |
| 3 | 生成器落码 | `internal/protocol/radius/{radius.go 477, layer_gen.go 76, radius_test.go 805}` 共 **1358 行**；`radius.go` 为 legacy 字节事实（D-RADIUS-1「零改动」声明成立） | as-built 定稿（§11） |
| 4 | 接线 | `main.go:135` 空导入 + `:593` `NewChainPlanner("radius")`；`chain_planner_translate.go:1726` 层内 translate；`strategy_convert.go:8975` presence 判死；`chain_planner.go:766/:996/:1074` 端口三处；`chain_planner_util.go:54` isRawIPChain；`layer_dyn.go:70/:266/:868` 动态三处 | 全通（§11.1 表） |
| 5 | 存量用例 | **25 例**，`spec_json` 顶层 `{layers}` ×24 + `{layers,radius}` ×1（唯一残留 = 负例 `radius_flat_presence`，**判死执法对象非残留**）；层形 **`[ip,radius]` ×25 全部**；`strategy_fc` ×2 | §12.1 机读展开 |
| 6 | 结果产物 | `trafficgen/docs/protocol-pcap-test/radius.md`（**tracked**）写 "Cases: 25 — pass 25, fail 0, error 0"，末次提交 `dbe0765`（**2026-09-19 23:42**）——**晚于**判死提交 `0417be5`（2026-09-13 00:25），`git merge-base --is-ancestor` 实测成立 → **不构成过期产物**（与 opcua G-OPCUA-10 的情形相反） | 不登记过期缺口；本车道另在**隔离目录**复跑（§6/§9 实测行） |
| 7 | 文档编号沿革 | 本协议此前**无** `docs/protocol-designs/NN-radius-*.md`（`ls` 实测零命中；`INDEX.md` 零命中）——旧基线只在 `CODE_DESIGN.md`/`TEST_CASES.md` 两处 | 本 #109 为**首份独立设计+用例文档**，非续号重做；无「旧稿校正表」可列（对照表见上 6 行） |

**依赖链判定纪律**：以上 7 行均为可判题（代码行 / cases JSON / git 三级对照），直接判定，不问偏好。

**radius 特殊性（须写清，不得含糊）**：
1. **TLV 属性协议**——20B 固定头 + 属性 TLV 序列，逐字段偏移与总长度公式见 §3.1/§3.2；
2. **Authenticator 是本协议核心安全面**——请求侧随机/可钉值、响应侧恒随机，且**引擎不计算 RFC 的 MD5 合成**（§3.4 + G-RADIUS-1）；
3. **Code 值域与各 Code 允许的属性集**见 §3.3/§3.5，非法组合逐条列于 §7；
4. **raw 自驱五件套**——radius 与 ldap 对称（`[ip,radius]` 无传输层，终层生成器自产完整 UDP 包，`GenEvents()=nil` + force-up 防双换，§11.4）；
5. **UDP 无状态**——无握手/无挥手/无连接边界，`sessions[]` 豁免（§12.3），多轮由 `rounds` 承载。

## 1. 范围、profile 与实现状态边界

本版定义 **RADIUS 报文（RFC 2865 §3 / RFC 2866 §3 定义的 20B 头 + 属性 TLV）承载于 UDP** 的流量生成：认证请求/响应、计费请求/响应、状态探询对、以及拒绝/质询两类显式响应。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `radius_udp_auth_v1`（主） | UDP，fixture 1812 | Code 1/3/11/12 请求 + 显式或 auto 响应，Rounds 轮交换 | 真实服务器鉴权判定（用户是否存在、密码是否正确） |
| `radius_udp_acct_v1` | UDP，fixture 1813（code=4 缺省分流） | Code 4 → auto 5 | 计费会话生命周期语义（Acct-Status-Type 只作为字节承载） |
| `radius_ipv6_v1` | 同上，仅外层 IPv6 | 同上（族对称，`Validate` 无族强制） | 从 IPv4 fixture 推导 IPv6 地址 |
| `radius_multiflow_v1` | 同上，`flow_control{flows:N}` + 层内端口动态对象 | 逐流四元组（§12.12） | 逐流业务字段（7 键全关） |

显式边界（"不实现、不声称、不许静默转换"）：① **不计算任何 RFC 定义的 Authenticator 合成**——请求 Authenticator 是随机 16B 或用户给定 hex，响应 Authenticator 恒随机 16B（§3.4，G-RADIUS-1）；② 不支持 **RFC 5176 CoA/Disconnect 码族**（40–45）与 3799 端口（G-RADIUS-2）；③ **Message-Authenticator(80) 只作 opaque 字节承载**，不算不校验 HMAC-MD5，EAP-Message 配对语义未实现（G-RADIUS-3）；④ 不实现 **UDP 重传/超时计时**（RFC 2865 §2.4），多轮用 `identifier+round` 递增替代（G-RADIUS-5）；⑤ VSA 内层**只写单个 vendor type/length/value 三元组**，不支持 RFC 2865 §5.26 允许多个子属性（G-RADIUS-12）；⑥ 不执法 RFC 2865 §3 的报文 Length 上界 4096，只守 65535（G-RADIUS-6）；⑦ 不实现 1645/1646 传统端口（RFC 2865 §3 / RFC 2866 §3 注记的历史端口）；⑧ **不声称**属性语义具备真实服务器可执行性——生成器按配置把属性编码成字节，不校验 Type 与 Code 的业务合法性（§3.5）。

**实现状态（2026-09-29 实测）**：`radius` 层已注册（`registry.go:1870`，9 键）；legacy planner + 链路径生成器已落码；`allowedProtocols["radius"]=true`（`protocols.go:52`）；层内 translate 已接线（`chain_planner_translate.go:1726`）；缺省目的端口 1812/1813（`chain_planner.go:1074`）；25 用例已落 `cases/radius.json` 且**今日隔离目录复跑 25/25 全绿**（§6 实测行）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`udp.srcport/dstport`、`ipv6.dst`、`radius.code/id/length/req/rsp/reqframe/authenticator/avp.type/avp.length`）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。本版 25 例的落盘路径实测为 pcap 一路；NIC 一路由框架能力承接（§6.3 如实标注）。

## 2. 协议栈、端口和固定偏移

推荐层链为 **`[ip, radius]`**（引擎自动补 `ip`；本协议存量 25/25 即此形，无 `tcp`/`udp` 中间层——radius 是 **raw 自驱终层**，生成器自产 Eth+IPv4/IPv6+UDP+RADIUS 整包）。

端口：RADIUS 认证 **UDP 1812**、计费 **UDP 1813**（RFC 2865 §3 / RFC 2866 §3）。缺省规则（`chain_planner.go:1074-1081`）：层内 `dst_port` 缺席时按 `code==4 ? 1813 : 1812` 补齐；层内 `src_port` 缺席时链路径**保持 0**（worker 按 `12345+i` 保底，`chain_planner.go:996` 零保持名单）。用例一律显式写 `12345/1812`（T-20 例外，用于钉缺省路径）。

固定偏移：无 VLAN/IP options 时，**每帧 RADIUS 报文起点为 IPv4 offset 42**（14 Eth + 20 IP + 8 UDP）、**IPv6 offset 62**（14 + 40 + 8）。报文内字段偏移按 §3.1 头布局递推；**变长属性之后的偏移不稳**（§3.2 注）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**本协议存量 24/25 已是此形，无需迁移**）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"radius": {"src_port": 12345, "dst_port": 1812, "code": 1}}
  ]
}
```

多流样例（数量只走 `strategy_fc`/`flow_control`；四元组必须写动态对象，否则触发静态复制拒，CORE_MEMORY 9.39）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"radius": {
      "code": 1,
      "src_port": {"strategy": "inc", "range": [12001, 12002], "step": 1, "group_id": "radius-src"},
      "dst_port": {"strategy": "inc", "range": [1812, 1813], "step": 1, "group_id": "radius-dst"}
    }}
  ],
  "strategy_fc": {"type": "flows", "value": 2}
}
```

## 3. 线格式编码（RFC 2865 §3/§5 + RFC 2866 §3；逐字段按代码钉）

### 3.1 报文头（固定 20 字节）

| 偏移 | 字段 | 类型/尺寸 | 端序 | 取值与来源 |
|---|---|---|---|---|
| 0 | Code | 1B | — | 请求 `{1,3,4,11,12}` / 响应 `{2,3,5,11,13}`（§3.3） |
| 1 | Identifier | 1B | — | `byte(cfg.Identifier + round)`，round 从 0 起（`radius.go:307`） |
| 2 | Length | **UInt16** | **大端** | 报文总长（含 20B 头 + 全部属性） |
| 4 | Authenticator | 16B | — | 请求：用户 hex 或随机；响应：**恒随机**（§3.4） |
| 20 | Attributes | 变长 | — | 属性 TLV 序列，按配置顺序（§3.2） |

**总长度公式**：`Length = 20 + Σ attrLen_i`，其中普通属性 `attrLen = 2 + valueBytes`，VSA 属性 `attrLen = 8 + valueBytes`（含内层 2 字节头）。代码一次算定（`buildRadiusMessage`，`radius.go:379-399`）：先算 body 全长，再回填 `Length`。

**tshark 实证（今日隔离目录复跑，`/tmp/radius-probe/`）**：空属性 → `radius.length=20`（T-1 帧 2）；User-Name `"user"`(4B) → **26**（T-1 帧 1）；253B 值 → **255**（T-23）；VSA vendor 9 `"vs"`(2B) → 外层 `avp.length=10`（T-15 帧 1）；计费两属性（6+6）→ **32**（T-4 帧 1）。

### 3.2 属性 TLV（RFC 2865 §5）

**普通属性**：`Type(1B) + Length(1B) + Value(变长)`，`Length = 2 + valueBytes`。
**值长上界**：`valueBytes ≤ 253`（`MaxAttrValue = 253`，`radius.go:36`）——因 Length 只有 1 字节（2+253=255 恰满）。

**Vendor-Specific（Type 26，`VendorID > 0` 时自动外层包装，`radius.go:432-445`）**：

| 层 | 字段 | 尺寸 | 值 |
|---|---|---|---|
| 外层 | Type | 1B | 恒 **26** |
| 外层 | Length | 1B | `8 + valueBytes` |
| 外层 | Vendor-Id | 4B **大端** | 配置的 `vendor_id` |
| 内层 | Vendor-Type | 1B | = 配置的 `type`（**复用用户写的 type，非独立字段**） |
| 内层 | Vendor-Length | 1B | `2 + valueBytes` |
| 内层 | Value | 变长 | 同 format 编码 |

**VSA 值长上界**：`valueBytes ≤ 247`（`MaxVSAValue = 247`，`radius.go:37`）——因外层 Length 只有 1 字节（8+247=255 恰满）。
**诚实边界**：内层**只写一个** vendor type/length/value 三元组；RFC 2865 §5.26 允许「Multiple subattributes MAY be encoded」（MAY，非 MUST），本实现不支持多个（G-RADIUS-12）。

**format 四态编码表（`encodeRadiusAttribute`，`radius.go:404-454`）**：

| format | 编码规则 | valueBytes | tshark 实证（隔离复跑） |
|---|---|---|---|
| `""` / `"string"` | 原始 UTF-8 字节 | `len(value)` | T-1 type 1 `"user"` → `avp.length=6` |
| `"ipv4"` | `net.ParseIP().To4()` 4 字节**大端** | 恒 4 | T-4 type 4 `10.0.0.1` → `avp.length=6` |
| `"uint32"` | 十进制解析后 4 字节**大端** | 恒 4 | T-15 type 5 `42` → `avp.length=6` |
| `"hex"` | hex 解码后的字节 | `len(hex)/2` | T-15 type 6 `"aabb"` → `avp.length=4` |

> **端序纪律**：`Length`、`Vendor-Id`、`ipv4`、`uint32` **全部大端**（RFC 2865 §5 网络字节序）；本协议**无小端字段**，与 Gnutella 类混写协议不同。
> **变长字段之后偏移不稳**：同一包内多属性时，tshark 把 `radius.avp.type`/`radius.avp.length` 按**逗号拼接**输出（T-15 实测 `"1,8,5,6,26"` / `"6,6,6,4,10"`，P5 校准①）。

### 3.3 Code 值域与 auto 响应（RFC 2865 §3 / RFC 2866 §3 / RFC 5997 §1）

| Code | 名称 | 可作请求（`requestCodes`） | 可作响应（`responseCodes`） | auto 映射（`autoResponse`） | 用例 |
|---:|---|---|---|---|---|
| 1 | Access-Request | ✓ | — | **→ 2** Access-Accept | T-1/T-8/T-12/T-15/T-18/T-19/T-20/T-21/T-23/T-24 |
| 2 | Access-Accept | —（`Validate` 拒） | ✓ | — | T-1（auto 产物）/T-15 |
| 3 | Access-Reject | ✓（legacy 合同） | ✓ | **无**（必须显式） | T-7（请求码 3）/T-8（响应码 3） |
| 4 | Accounting-Request | ✓ | — | **→ 5** Accounting-Response | T-4 |
| 5 | Accounting-Response | —（`Validate` 拒） | ✓ | — | T-4（auto 产物） |
| 11 | Access-Challenge | ✓ | ✓ | **无**（必须显式） | T-5 |
| 12 | Status-Server | ✓ | — | **→ 13** Status-Client | T-6 |
| 13 | Status-Client | —（`Validate` 拒） | ✓ | — | T-6（auto 产物） |
| 40–45 | Disconnect-* / CoA-*（RFC 5176 §2.3） | ✗ | ✗ | 无 | T-25（43 负例执法格） |

**值域实现**：`requestCodes` 白名单 `{1,3,4,11,12}`（`radius.go:43-49`）、`responseCodes` 白名单 `{2,3,5,11,13}`（`:52-58`）、`autoResponse` 表 `{1→2, 4→5, 12→13}`（`:61-65`）。`code==0` 缺省落 `1`（`:113-115`）。
**RFC 事实与实现的差异（如实登记）**：RFC 2865 §3 把 Code 12/13 标为 experimental，RFC 5997 §1 把 12 收编为 Status-Server；RFC 5997 §2/§4.1 规定服务器对 Status-Server 应回 **Access-Accept(2) 或 Accounting-Response(5)**，**而本引擎 auto 映射回 13（Status-Client）**——属本引擎自定合同（T-6 按实现钉），非 RFC 行为（G-RADIUS-13）。
**RFC 未定义的"请求/响应可作位"**：RFC 2865 §3 只说"invalid Code 静默丢弃"，未给出请求/响应分列白名单——本引擎的白名单是**自定执法口径**（T-9/T-10/T-11/T-25 四例执法格）。

### 3.4 Authenticator（RFC 2865 §4.1 / §3、RFC 2866 §3；本协议核心安全面）

**取值规则（确定性）**：

| 侧 | 条件 | 值 | 代码 |
|---|---|---|---|
| 请求 | `authenticator` 配置为 16B hex | 该 hex 的解码字节 | `radius.go:267-277` + `:309-311` |
| 请求 | `authenticator` 缺席 | **每轮新随机 16B**（`crypto/rand`；失败回退 `0xA5+i` 固定图案） | `:311` + `:459-468` |
| 响应 | **恒** | **每响应新随机 16B**（即使请求侧固定） | `:343` |

**RFC 要求 vs 本实现（缺口 G-RADIUS-1，明确不解决）**：

| RFC 条款 | 规范要求 | 本实现 |
|---|---|---|
| RFC 2865 §4.1 | Access-Request 的 Request Authenticator = 16 字节随机数，且**每个新 Identifier 必须换值** | 每轮新随机 ✓（轮间天然不同）；fixed hex 时逐轮同值（用户显式选择） |
| RFC 2865 §3 | ResponseAuth = `MD5(Code+ID+Length+RequestAuth+Attributes+Secret)` | **不计算**，恒随机 |
| RFC 2866 §3 | Accounting-Request 的 Request Authenticator = `MD5(Code+ID+Length+16×00+Attributes+Secret)` | **不计算**，随机 |
| RFC 2866 §3 | Accounting-Response 的 Response Authenticator = MD5(…RequestAuth…+Secret) | **不计算**，随机 |

**成因**：MD5 合成需要**客户端与服务器共享密钥**（`Secret`），生成器不建模共享密钥。**本版不声称**产出流可通过真实服务器的 Authenticator 校验。**可钉值面**：只有"请求侧 fixed hex"一格（T-12 断言 `radius.authenticator = 000102…0e0f` 精确值）；其余一律 `nonzero`（T-1 两包 nonzero、T-12 响应 nonzero）。

### 3.5 缺省属性集（`defaultRequestAttrs`，`radius.go:69-79`）

`attributes` 缺席时按 Code 派生：

| 请求 Code | 缺省属性集 | 依据 |
|---|---|---|
| 4（Accounting-Request） | `[{Type:40, format:uint32, value:"1"}, {Type:44, value:"session-0001"}]` | RFC 2866 §5.1 Acct-Status-Type=40（1=Start）/ §5.5 Acct-Session-Id=44 |
| 其他（1/3/11/12） | `[{Type:1, value:"user"}]` | RFC 2865 §5.1 User-Name=1（参考 pcap `portion_Radius.pcap` 形） |

**诚实登记（G-RADIUS-4）**：Code 3/11/12 复用同一 User-Name 缺省集，**没有按 Code 分列各自语义属性**；RFC 5997 §3 对 Status-Server 未强制属性，故 T-6 的 User-Name 承载不违规范，但属"最小填充"而非"语义正确"。**响应侧属性缺省为空**（`response_attributes` 缺席 → `Length=20`，T-1/T-4/T-6 等实测），与 RFC 2865 §5 各 Code 的"允许属性集"无关联执法。

**属性 Type 与 Code 的业务合法性不做校验**（`Validate` 只查 format/长度，不查 `Type` 与 `Code` 的匹配）——T-15/T-24 可把任意 Type 放进任意 Code，这是**生成器合同**（不做服务器语义），如实声明。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明 Code/轮数/属性模板，引擎按固定剧本产出事件序列（每轮：请求 up → 响应 down），UDP 无连接、无握手挥手、无自动应答（响应由配置显式声明或按 auto 表派生一次）。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 802.1X/PPPoE 接入认证 | Access-Request(User-Name/NAS-IP) → Access-Accept | T-1（基线）、T-20（缺省端口）、T-23（大属性） |
| ② 认证被拒 | Access-Request → Access-Reject | T-8（响应码 3）、T-7（请求码 3 枚举） |
| ③ CHAP/EAP 质询 | Access-Request → Access-Challenge（显式） | T-5 |
| ④ 计费开始/停止 | Accounting-Request(Status-Type=1) → Accounting-Response，1813 | T-4 |
| ⑤ 服务器存活探询 | Status-Server → Status-Client（本引擎 auto 合同） | T-6 |
| ⑥ 现网 NAS 组合属性 | Service-Type/NAS-IP/Calling-Station/Message-Authenticator 四属性同包 | T-24 |
| ⑦ 多轮重传/重复尝试 | 同四元组 Rounds 轮，Identifier 逐轮递增 | T-18（rounds=3） |
| ⑧ 厂商私有属性 | VSA(26) 外层 + vendor_id + 内层三元组 | T-15 |
| ⑨ IPv6 产线 | 同上，仅外层 IPv6 | T-19 |
| ⑩ 多设备并发（逐流四元组） | `flows=N` + 层内端口动态对象 | T-21 |

**五层覆盖逐层结论**：
- **功能层**——8 个 Code 的请求/响应正例（T-1/T-4/T-5/T-6/T-7/T-8 + auto 产物）＋ 11 条负例覆盖配置错/长度错/值域错/载体错四类（§7）。
- **性能层**——最小报文（20B，T-1 帧 2）、最大合法属性（253B→255，T-23）、多轮展开（rounds=3 → 6 包，T-18）、多流并发（2 流 → 4 包，T-21）、长度上界守卫（`MaxMessageLen=65535`，不可达，G-RADIUS-6）。
- **数据场景层**——format 四态全覆盖（T-15）、VSA 承载（T-15/T-24）、值长边界 253 过/254 拒（T-23/T-16）、VSA 边界 247/248（T-15/T-22）、Identifier 递增与 uint8 回绕（T-18 + 代码 `:307`）、Authenticator 可钉值与随机（T-12）。
- **地址与流层**——IPv4（T-1 等 24 例）/ IPv6（T-19）逐格对照；单流基线（T-1）；**多流**由策略级 `strategy_fc` 承载（T-21）；**流关联（控制流派生数据流）显式不适用**——RADIUS 无派生连接概念。
- **业务层**——十场景全部有落点；**多会话显式不适用**（UDP 无连接，§12.3 豁免）；**多事务** = 同四元组 Rounds 轮（T-18）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① 真实 Authenticator 合成（未实现，G-RADIUS-1）；② CoA/Disconnect 码族（未实现，G-RADIUS-2）；③ Message-Authenticator HMAC 计算（未实现，G-RADIUS-3）；④ UDP 重传/超时计时（未实现，G-RADIUS-5）；⑤ 多子属性 VSA（未实现，G-RADIUS-12）；⑥ 报文 Length 4096 上界（未执法，G-RADIUS-6）；⑦ 传统端口 1645/1646（未实现）；⑧ 被动模式/NAT 穿越（无此概念，§10.1 第 7 项）。

## 5. 消息/事务模型与状态机

**事务定义**：一次请求 + 一次响应（同一 4 元组，Identifier 复刻）。**多事务** = 一个 flow 内 Rounds 轮按序执行（T-18：3 轮 = 6 包，Identifier 5/6/7）。

radius 层**无自有状态机**：UDP 无连接、无握手/挥手/保活/重连，`Validate` 与 `Plan` 都是"按配置把参数翻译成包"的纯函数驱动；唯一"状态"是 round 计数器。

| 阶段 | 产出帧 | 用例 |
|---|---|---|
| 请求 | 1 帧 up（`src_port→dst_port`，`SrcMAC→DstMAC`） | 全正例 |
| 响应 | 1 帧 down（**端口/地址/MAC 全交换**，`radius.go:347-368`） | 全正例 |
| 重复 | 每轮重复上述两帧，Identifier 递增 | T-18 |

**事件序（`Plan`，`radius.go:306-370`）**：`for round in 0..Rounds-1`：`id = byte(Identifier + round)` → `reqAuth`（fixed 或新随机）→ 请求包（`Direction="up"`，`PacketIndex=2r`）→ 响应包（`Direction="down"`，`PacketIndex=2r+1`，`respCode` + 新随机 auth + `ResponseAttributes`）。

**自动派生规则（逐个列出，不依赖隐含知识）**：
1. `code` 缺省 → `1`（Access-Request，`:113`/`:254`）；
2. `rounds` 缺省 → `1`（`:249-252`）；
3. `response_code` 缺省 → `autoResponse[code]`；无 auto 映射（3/11）时 `Validate` 直接拒（`:127-128`）；
4. `dst_port` 缺省 → `code==4 ? 1813 : 1812`（链路径 translate 自补，`chain_planner_translate.go:1786-1792`；legacy `:243-248` 同款）；
5. `src_port` 缺省 → 链路径保持 **0**（worker 按 `12345+i` 保底）；
6. `attributes` 缺省 → §3.5 表；
7. 响应 Authenticator 恒新随机（`:343`）——**不是**请求 auth 的函数；
8. 每包新 `ip.id`（`randomIPID`，`:294-299`），不断言（随机面）。

**raw 自驱五件套（与 ldap 对称）**：`[ip,radius]` 无传输层 → `isRawIPChain` 命中（`chain_planner_util.go:54`）→ 终层生成器 `Generate` 逐包 relay legacy `Plan` 的输出，并**强制 `Direction="up"`**（`layer_gen.go:51`）——因为 legacy 已自行交换响应帧的地址/端口/MAC，raw-IP 驱动若再换向会**双换错**（前七协议同款防双换）。`GenEvents()` 返回 `nil`（`:26`，非 nil 会被路由到事件路径）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流包数 = `2 × rounds`（无握手挥手）；单条属性值上界 253B（普通）/247B（VSA）；报文总长上界 `MaxMessageLen = 65535`（`radius.go:389-391`，实际不可达，G-RADIUS-6）；Rounds 上界由 `uint8` 回绕决定（Identifier 逐轮 +1，>256 轮回绕，`radius.go:307`）。吞吐数字待框架基准，**本版不写承诺**（§6.5）。
- **依据（数据流与资源）**：`Plan` 用 `chan PacketConfig`（缓冲 256，`radius.go:281`）**流式产出**，逐包 emit，**不聚合**；每流内存 = 单包 payload（≤ 65535B）+ 属性切片；`ctx.Done()` 在每个 emit 点检查（`:286/:319/:338/:347/:366`），取消即返回；无跨流共享状态；**无锁**（全局部变量 + channel）；限速由框架 `SharedTokenBucket` 承担（本层不重复定义）。
- **验收两路（§6.3 强制）**：**pcap 路** = 套件经 MCP 真实流程产出 pcap + tshark 逐字段校对（**本车道今日已跑，25/25 全绿**，见下行实测行）；**NIC 路** = `enp135s0f0np0` 经 tcpdump 捕获（`nic_capture` 用例级开关），共用同一断言集——**本车道今日未跑 NIC 路**，如实标注（G-RADIUS-14）。
- **今日实测行（本车道，2026-09-29）**：`PCAP_ROOT=/tmp/radius-probe MCP_API_KEY=dev-mcp-key CASE_PROTO=radius go test ./test/protocol_pcap/ -run TestProtocolPcapDrive` → `RESULT: 25 pass, 0 fail, 0 error (of 25)`；**14 个正例（`packet_count` 全覆盖）的实测帧数与 JSON 逐例一致**（2/2/2/2/2/2/2/2/6/2/2/4/2/2）；9 个 task-time 负例落 `.neg.pcap` 且 **0 帧**；2 个 create-time 负例（`radius_flat_presence`/`radius_flat_static_port`）**不产文件**（§7 负例分层）。
- **六类场景落点（§6.6）**：基线（T-1，2 包）/ 目标规模（T-18 rounds=3 → 6 包）/ 压力上限（T-23 253B 属性 + T-15 五属性同包）/ 长时间运行（Rounds 多轮展开承载语义）/ 并发交错（T-21 两流并发，`distinct_values` 聚合断言）/ 背压（`packet_count` 精确计数守卫帧数漂移 + `MaxMessageLen` 守卫）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

**负例分层（as-built 实测，重要）**：本协议 11 个负例分两类执行期——

| 层 | 拒绝时机 | 落盘 | 例数 | 例 |
|---|---|---|---|---|
| **create-time** | 建策略即 400（框架门） | **不产 pcap 文件** | 2 | `radius_flat_presence`、`radius_flat_static_port` |
| **task-time** | 建策略通过、启动任务时 planner 拒 | 产 `<id>.neg.pcap`，**0 帧**（24B 仅文件头） | 9 | 其余 9 例 |

**逐条锚词表（代码逐字，`radius.go` 实测行号）**：

| # | 负例 ID | 故障输入 | 代码锚词 | 代码行 | 时机 |
|---:|---|---|---|---|---|
| N-1 | `radius_neg_no_auto` | `code:3` 无 `response_code` | `radius: code %d has no default response code; set response_code explicitly` | `:128` | task-time |
| N-2 | `radius_neg_reqcode` | `code:42` | `radius: invalid request code %d (allowed: 1, 3, 4, 11, 12)` | `:117` | task-time |
| N-3 | `radius_neg_rspcode` | `response_code:9` | `radius: invalid response code %d (allowed: 2, 3, 5, 11, 13)` | `:125` | task-time |
| N-4 | `radius_neg_auth_hex` | `authenticator:"zz"` | `radius: invalid authenticator hex: %v` | `:135` | task-time |
| N-5 | `radius_neg_auth_len` | 15B hex | `radius: authenticator must be 16 bytes, got %d` | `:138` | task-time |
| N-6 | `radius_neg_attr_len` | string 254B | `radius %s[%d]: value length %d exceeds the %d-byte field limit (type %d)`（`%d`=253） | `:171` | task-time |
| N-7 | `radius_neg_vsa_len` | VSA value 248B | 同上（`%d`=247） | `:171` | task-time |
| N-8 | `radius_neg_format` | `format:"dword"` | `radius %s[%d]: unknown format %q (allowed: string, ipv4, uint32, hex)` | `:189` | task-time |
| N-9 | `radius_neg_coa` | `code:43`（RFC 5176 CoA-Request） | `radius: invalid request code %d (allowed: 1, 3, 4, 11, 12)` | `:117` | task-time |
| N-10 | `radius_flat_presence` | `{layers:[ip,radius{}], radius:{}}` 并存 | `protocol radius no longer accepts a top-level radius sub-config (move it into the radius layer of an [ip,radius] layers chain)` | `strategy_convert.go:8977` | **create-time** |
| N-11 | `radius_flat_static_port` | `[ip{},radius{src_port,dst_port}]` + `flows=2` | `layers pin a static four-tuple but flows > 1: …` | `schema/semantic.go:285` | **create-time** |

**负例原子性**：每例单一故障注入。**N-6/N-7 同锚词面**（同一 `:171` 分支的 253/247 两个上界，两例分锚词后缀区分）；**N-2/N-9 同锚词面**（同一 `:117` 分支，假码 42 与现网真码 43 各一例）。
**负例纯净性**：11 例 `expect` 均无 `packet_count`/`fields`/`frames`，且严格为 `{expect_error, error_contains}` 两键（G-RADIUS-9 已于 2026-09-30 关闭）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：
- `Validate`：`invalid source IP: %s`（`:98`）、`invalid destination IP: %s`（`:103`）、`radius config is required`（`:107`，**链路径不可达**——translate 恒填非 nil）、`format=ipv4 value %q is not an IPv4 address`（`:178`）、`format=uint32 value %q is not a uint32`（`:182`）、`format=hex value %q is not valid hex`（`:186`）；
- builder（`Validate` 之后不可达）：`radius message length %d exceeds 65535`（`:390`）、`radius: unknown attribute format %q`（`:429`）、`radius: VSA value length %d exceeds the %d-byte field limit`（`:434`）、`radius: value length %d exceeds the %d-byte field limit`（`:448`）；
- 生成器：`radius generator: invalid request`（`layer_gen.go:34`）。

**不得误报的合法协议事件**：多属性同包（T-15/T-24）；Rounds 多轮（T-18）；`code:3`/`code:11` 作**请求码**（legacy 合同，T-7/T-5）；VSA 空值（`vendor_id` 有、value 空 → 内层 len 2，合法）；IPv6（T-19）；多流（T-21）。

## 8. 边界

- **报文长度**：最小 **20**（无属性，T-1 帧 2）；单属性最大 **255**（253 值 + 2 头，T-23）；VSA 外层最大 **255**（247 值 + 8）；多属性可叠加至 `MaxMessageLen` 65535（今日无例 → A′ 立项）。RFC 2865 §3 的 **4096 上界未执法**（G-RADIUS-6）。
- **属性数量**：无显式上限（`attributes` 为列表，逐条编码）；T-15 用 5 条、T-24 用 4 条。
- **Identifier**：`byte(cfg.Identifier + round)`；**uint8 回绕**（rounds>256 时回到起点，`radius.go:307`）——今日用例避开（T-18 rounds=3），A′ 候选。
- **Rounds**：`rounds` 为 `uint16`（registry `{Type:"uint16", Max:65535}`），`Plan` 循环 `rounds` 次；0 或缺席 → 1。
- **端口**：显式 `12345/1812`（23 例）；缺省 `dst=1812`（T-20，`code!=4`）；`code=4` 缺省 `dst=1813`（T-4）；动态逐流（T-21）；**`src_port` 缺省链路径为 0**（worker `12345+i` 保底，T-20 未断言 srcport，G-RADIUS-8）。
- **地址族**：v4（24 例）/ v6（T-19）逐格；**异族混写**由 `validateSpecBase` 拒（`chain_planner.go:886`，锚词 `must be same IP version`），今日无例 → A′ 立项。
- **format**：只接受 `""`/`string`/`ipv4`/`uint32`/`hex` 五态（空串与 `string` 等价）；其余即拒（N-8）。
- **属性语义**：Type 与 Code 的匹配不做校验（§3.5）；VSA 内层单子属性（G-RADIUS-12）。
- **不可回绕/超量分配**：报文长度一次算定（`buildRadiusMessage` 先算 body 再回填 Length），无逐段追加导致的长度漂移。

## 9. 原子 ID 与完成定义（25 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count（今日实测） |
|---:|---|---|---|---:|
| 1 | `radius_smoke_01` | 正 | §3.1/§3.5：空业务面 1 轮基线（code1→2 auto、id 0、length 26/20） | 2 |
| 2 | `radius_flat_presence` | 负 | §7 N-10：顶层 `radius` presence 判死 | —（**不产文件**） |
| 3 | `radius_flat_static_port` | 负 | §7 N-11：静态四元组 + flows=2 拒 | —（**不产文件**） |
| 4 | `radius_acct_1813` | 正 | §3.3/§2：Accounting-Request→1813，auto 5 | 2 |
| 5 | `radius_challenge` | 正 | §3.3：code 11 显式响应 11（无 auto） | 2 |
| 6 | `radius_status` | 正 | §3.3：code 12 → auto 13 | 2 |
| 7 | `radius_code3` | 正 | §3.3：请求码 3 枚举格 + 显式响应 3 | 2 |
| 8 | `radius_reject` | 正 | §3.3：code 1 + 显式响应 3（失败分支） | 2 |
| 9 | `radius_neg_no_auto` | 负 | §7 N-1：无默认响应码 | —（0 帧） |
| 10 | `radius_neg_reqcode` | 负 | §7 N-2：请求码非法 42 | —（0 帧） |
| 11 | `radius_neg_rspcode` | 负 | §7 N-3：响应码非法 9 | —（0 帧） |
| 12 | `radius_auth_fixed` | 正 | §3.4：fixed authenticator 钉值 | 2 |
| 13 | `radius_neg_auth_hex` | 负 | §7 N-4：authenticator 非法 hex | —（0 帧） |
| 14 | `radius_neg_auth_len` | 负 | §7 N-5：authenticator 长度门 | —（0 帧） |
| 15 | `radius_attr_formats` | 正 | §3.2：format 四态 + VSA 枚举格 | 2 |
| 16 | `radius_neg_attr_len` | 负 | §7 N-6：253 门超长 | —（0 帧） |
| 17 | `radius_neg_format` | 负 | §7 N-8：format 非法 | —（0 帧） |
| 18 | `radius_rounds` | 正 | §5：rounds=3 + identifier=5 → 6 包 | 6 |
| 19 | `radius_v6` | 正 | §2：IPv6 链同构 | 2 |
| 20 | `radius_default_port` | 正 | §2：端口缺省 → 1812 | 2 |
| 21 | `radius_port_dyn` | 正 | §12.12：端口动态 + flows=2 | 4 |
| 22 | `radius_neg_vsa_len` | 负 | §7 N-7：VSA 247 门 | —（0 帧） |
| 23 | `radius_attr_boundary` | 正 | §8：253 边界等值（avp.length=255） | 2 |
| 24 | `radius_nas_combo` | 正 | §4 场景⑥：现网 NAS 四属性组合 | 2 |
| 25 | `radius_neg_coa` | 负 | §7 N-9：CoA-Request(43) 白名单外 | —（0 帧） |

**包数公式**：单流 = `2 × rounds`（每轮请求 + 响应，**无握手/无挥手**）。校验：rounds 缺省 1 → **2 包 ×12 例**（另 T-21 为 2 流 × 1 轮 × 2 = **4 包**）；T-18 rounds=3 → **6 包** ✓。合计 12×2 + 4 + 6 = **34 帧**。**14 个正例（`packet_count` 全覆盖）逐例与今日实测 pcap 一致**（§6 实测行）。

**枚举取值覆盖（CORE_MEMORY 9.20）**：请求码 `{1(T-1),3(T-7/N-1),4(T-4),11(T-5),12(T-6)}` **5/5**；响应码 `{2(T-1 auto),3(T-7/T-8),5(T-4),11(T-5),13(T-6)}` **5/5**；format `{string,ipv4,uint32,hex}` **4/4**（T-15）+ VSA；地址族 `{v4,v6}` **2/2**（T-19）；端口 `{显式,缺省,动态}` **3/3**（T-1/T-20/T-21）；`rounds{1,3}` 2 档。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | UDP 无连接；客户端（NAS）主动向服务器 1812/1813 发；RFC 2865 §2 定义"NAS→Server"单向请求模型 | ①–⑩ | `DependsOn ["ip"]` 单值（`registry.go:1870`）；raw 自驱终层自产 UDP 包 | 无 |
| 2 | 命令/消息表 | 8 个已分配 Code（RFC 2865 §3）+ 6 个 RFC 5176 码 | ①–⑦ | `requestCodes`/`responseCodes`/`autoResponse` 三表（`radius.go:43-65`） | RFC 5176 码族未支持（G-RADIUS-2） |
| 3 | 状态机 | 无连接状态机；一问一答 | ①–⑩ | 无状态；唯一计数器 = round（`:307`） | 无 |
| 4 | 字段表 | 20B 头（Code/ID/Length/Auth）+ TLV 属性（RFC 2865 §3/§5） | 数据场景层 | §3.1/§3.2 逐字段；`buildRadiusMessage`/`encodeRadiusAttribute` | 无 |
| 5 | 错误处理 | Code 非法静默丢弃（§3）；属性 Length 非法 → Reject/丢弃（§5） | 负例 N-1…N-11 | `Validate` 13 锚词 + 2 框架门（§7） | A′ 11 例未入例分支（§13；§7 末列 6 条锚词面） |
| 6 | 超时与活性 | RFC 2865 §2.4 重传/超时（NAS 重发计时）；RFC 5997 Status-Server 存活探询 | ⑤⑦ | **重传未实现**（G-RADIUS-5）；Status-Server 探询对已落码（T-6） | G-RADIUS-5 |
| 7 | NAT/代理/被动 | RADIUS 有 Proxy 概念（RFC 2865 §2.1，同一报文转发）；无被动模式 | — | 无 proxy 语义、无被动模式 | **显式不适用**（生成器不模拟转发链） |
| 8 | 版本/方言 | RFC 2865/2866 主族 + RFC 5176 扩展 + 传统端口 1645/1646 | ⑨ | 端口只 1812/1813；v6 已覆（T-19） | 1645/1646 未实现（§1 边界⑦）；CoA 见 G-RADIUS-2 |

### 10.2 子表①：Code × 可作位矩阵（逐格已覆/立项/不适用）

| Code | T1 作请求 | T2 作响应 | T3 auto 映射 | 用例 |
|---:|---|---|---|---|
| 1 Access-Request | 已覆 | 不适用（`Validate` 拒） | 已覆（→2） | T-1 |
| 2 Access-Accept | 不适用（拒） | 已覆 | 不适用 | T-1/T-15 |
| 3 Access-Reject | 已覆 | 已覆 | 不适用（无 auto，须显式） | T-7/T-8 |
| 4 Accounting-Request | 已覆 | 不适用（拒） | 已覆（→5） | T-4 |
| 5 Accounting-Response | 不适用（拒） | 已覆 | 不适用 | T-4 |
| 11 Access-Challenge | 已覆 | 已覆 | 不适用（无 auto，须显式） | T-5 |
| 12 Status-Server | 已覆 | 不适用（拒） | 已覆（→13，**引擎自定**） | T-6 |
| 13 Status-Client | 不适用（拒） | 已覆 | 不适用 | T-6 |
| 40–45 RFC 5176 六码 | **A′ 立项**（G-RADIUS-2） | **A′ 立项** | **A′ 立项** | T-25（43 负例执法格） |

**逐格重数**：9 行 × 3 列 = 27 格 —— **已覆 13**（T1 列 5：1/3/4/11/12 行 + T2 列 4：2/3/5/13 行 + T3 列 4：1/4/12 行……精确逐行数见下）/ **不适用 11**（"`Validate` 拒" 5 格 + "无 auto" 6 格）/ **A′ 立项 3**（40–45 行三格）。13 + 11 + 3 = 27 ✓ 零空格。**逐行重数**：行 1 = 2 覆 + 1 不适用；行 2 = 1 覆 + 2 不适用；行 3 = 2 覆 + 1 不适用；行 4 = 2 覆 + 1 不适用；行 5 = 1 覆 + 2 不适用；行 11 = 2 覆 + 1 不适用；行 12 = 2 覆 + 1 不适用；行 13 = 1 覆 + 2 不适用；行 40–45 = 3 A′。合计 覆 13 + 不适用 11 + A′ 3 = 27 ✓。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **34 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | 空属性（Length=20） | 覆（T-1 帧 2） |
| 2 | 单属性 string | 覆（T-1 帧 1，`"user"`） |
| 3 | format=ipv4 | 覆（T-4/T-15） |
| 4 | format=uint32 | 覆（T-15） |
| 5 | format=hex | 覆（T-15/T-24） |
| 6 | format 非法（`dword`） | 覆负例（T-17） |
| 7 | format 缺席（= string） | 覆（T-1 等多例） |
| 8 | 普通属性值 253B（边界过） | 覆（T-23） |
| 9 | 普通属性值 254B（边界拒） | 覆负例（T-16） |
| 10 | 普通属性值 0B（空串） | **A′ 立项**（`encodeRadiusAttribute` 允许，今日无例） |
| 11 | VSA 值 247B（边界过） | **A′ 立项**（`Validate` 放行；T-15 只 2B） |
| 12 | VSA 值 248B（边界拒） | 覆负例（T-22） |
| 13 | VSA 空值 | **A′ 立项**（内层 len 2，合法，今日无例） |
| 14 | VSA vendor_id 缺省（=0） | 覆（普通属性路径，全例） |
| 15 | 多属性同包（5 条） | 覆（T-15） |
| 16 | 多属性同包（4 条现网组合） | 覆（T-24） |
| 17 | `identifier` 显式 5 + rounds 3 | 覆（T-18，id 5/6/7） |
| 18 | `identifier` 缺省 0 | 覆（T-1 等多例） |
| 19 | `identifier + round` uint8 回绕 | **A′ 立项**（rounds>256，今日避开） |
| 20 | `rounds` 缺省 1 | 覆（13 例 spec 省略 rounds，其中 12 例产 2 包、T-21 产 4 包） |
| 21 | `rounds=3` | 覆（T-18） |
| 22 | `rounds=0` 显式 | **A′ 立项**（代码 `:249` 兜底为 1，今日无例） |
| 23 | Authenticator fixed 16B hex | 覆（T-12） |
| 24 | Authenticator 非法 hex | 覆负例（T-13） |
| 25 | Authenticator 长度非 16 | 覆负例（T-14） |
| 26 | Authenticator 缺省随机 | 覆（12 例：14 正例中 T-12 为 fixed 钉值、T-15 未断言 authenticator，余 12 例 nonzero） |
| 27 | 响应 Authenticator 恒随机 | 覆（全正例 nonzero） |
| 28 | 端口显式 12345/1812 | 覆（23 例） |
| 29 | 端口缺省（1812/1813 分流） | 覆（T-20/T-4） |
| 30 | 端口动态 + 多流 | 覆（T-21） |
| 31 | 地址族 IPv6 | 覆（T-19） |
| 32 | 地址族异族混写 | **A′ 立项**（`chain_planner.go:886` 有分支，今日无例） |
| 33 | 响应侧属性非空 | 覆（T-15 帧 2 带 VSA） |
| 34 | 响应侧属性缺省空 | 覆（T-1/T-4/T-6 等） |

**逐格重数**：34 行 —— 覆 **28** + A′ 立项 **6**（#10 空值属性 / #11 VSA 247B 过 / #13 VSA 空值 / #19 uint8 回绕 / #22 `rounds=0` / #32 异族混写）= 34 ✓（本表按 34 行计，§5.2 对账同步用 34）。

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 802.1X/PPPoE 接入认证（RFC 2865 §2） | T-1/T-20/T-23 | 已覆 |
| 2 | 认证拒绝（RFC 2865 §3 Code 3） | T-8/T-7 | 已覆 |
| 3 | CHAP/EAP 质询（RFC 2865 §3 Code 11） | T-5 | 已覆（显式响应合同） |
| 4 | 计费 Start/Stop（RFC 2866 §5.1） | T-4 | 已覆（属性字节承载） |
| 5 | 服务器存活探询（RFC 5997） | T-6 | 已覆（**auto 13 为本引擎合同**，G-RADIUS-13） |
| 6 | 现网 NAS 属性组合（Service-Type/NAS-IP/Calling-Station/MA） | T-24 | 已覆 |
| 7 | 多轮重传/重复尝试（RFC 2865 §2.4） | T-18 | 已覆（**Identifier 递增替代重传计时**，G-RADIUS-5） |
| 8 | 厂商私有属性（RFC 2865 §5.26） | T-15 | 已覆（单子属性形） |
| 9 | IPv6 产线 | T-19 | 已覆 |
| 10 | 多设备并发 | T-21 | 已覆 |
| 11 | Authenticator 合成校验（RFC 2865 §3 / RFC 2866 §3） | — | **明确不解决**（G-RADIUS-1） |
| 12 | CoA/Disconnect 动态授权（RFC 5176） | — | **明确不解决**（G-RADIUS-2） |
| 13 | EAP + Message-Authenticator 完整性（RFC 3579） | — | **明确不解决**（G-RADIUS-3） |
| 14 | 代理/转发链（RFC 2865 §2.1） | — | **明确不解决**（§10.1 第 7 项） |
| 15 | 传统端口 1645/1646 兼容 | — | **明确不解决**（§1 边界⑦） |

10 覆 + 5 不适用 = 15。✓ 无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

**三路**：① **规范原文**（RFC 2865/2866/5997/5176/3579，定"必须是什么"——本轮已用 RFC 原文校正三处口径：Response Authenticator 的 MD5 公式、Accounting-Request 的 MD5 公式、VSA 的 `SHOULD 多子属性`，§3.2/§3.4）；② **商业化软件实际行为**（参考 pcap `portion_Radius.pcap`（认证 1812）/`start-stop.pcap`（计费 1813），出处记于 `radius.go:17-18`；**这两份 pcap 不在本仓**，本车道无法二次核验 → G-RADIUS-15 待确认）；③ **可靠开源实现思路**（FreeRADIUS 的 `rad_packet` 编解码结构、`radclient` 的请求构造——只借鉴"属性顺序即配置顺序""Length 一次算定"两条思路，未搬运代码）。

**三路一致点**：20B 头布局与大端、属性 TLV 形、`Length = 20 + Σ`。
**三路不一致点**：① 响应 Authenticator——规范要求 MD5 合成，本实现随机（G-RADIUS-1，本版按实现钉、不声称合规）；② Status-Server 响应码——RFC 5997 §2/§4.1 要求 2 或 5，本实现 auto 13（G-RADIUS-13）；③ 属性 Type 与 Code 的业务匹配——规范有允许属性集，本实现不执法（§3.5）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | **`[ip,radius]` raw 自驱终层**（本版；D-RADIUS-1 裁定 A1，stun/tftp 同组 UDP 无状态先例） | 零字节回归（legacy `radius.go` 一行不改）；UDP 无状态无需握手托管；代价 = 层内无端口位需 translate 补端口缺省 | **采用** |
| B | `[ip,udp,radius]` 事件面（udp 层管端口，radius 变 `MessageEvents`） | 端口天然住 udp 层、无需顺序修正；但需把 legacy 整包 relay 拆成事件序列（大改），且 UDP 无握手可托管——事件面无额外收益 | **否决** |
| C | 保留 legacy 扁平路径（不走层链） | 无需接线；但违反 CORE_MEMORY §1 层链唯一真相，且 25 例中 presence/static 两负例无法表达 | **否决** |

## 11. P2 D-RADIUS-1 代码设计（CORE_MEMORY §8 八要素；as-built 定稿）

> 状态说明：实现已落码（`internal/protocol/radius/` 三文件）并经 P4 `1501264` / P5 / P6 验收；本 P2 条目为**逆向定稿**（as-built），供后续改动的唯一入口。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go:8858-8915` | `RadiusConfig`（7 字段）+ `RadiusAttribute`（4 字段）+ `FlowSpec.Radius` 槽位 | —（共享文件） |
| `trafficgen/internal/core/types.go:3683-3685` | `LayerDynValues.RADIUS`（`LayerTransportDyn`，端口 2 键） | —（共享文件） |
| `trafficgen/internal/protocol/radius/radius.go` | 常量表 + 三张 Code 表 + `Validate`（13 锚词）+ `Plan`（Rounds 循环）+ `buildRadiusMessage`/`encodeRadiusAttribute` + 随机源 | **477** |
| `trafficgen/internal/protocol/radius/layer_gen.go` | 终结层生成器（`Generate` relay + force-up；`GenEvents()=nil`；`validateLayer` 委托 legacy；`init()` 注册） | **76** |
| `trafficgen/internal/protocol/radius/radius_test.go` | 40 个 `Test*`（报文面 / 属性面 / Code 面 / 状态机面 / Validate 面 / 场景面 / 边界面） | **805** |
| 接线 6 处 | registry（`registry.go:1870`，9 键）/ translate 层内分支（`chain_planner_translate.go:1726`）/ convert 子配置搬运（`strategy_convert.go:1293`）+ presence 判死（`:8975`）/ protocols 准入（`protocols.go:52`）/ 缺省端口三处（`chain_planner.go:766/:996/:1074`）+ isRawIPChain（`chain_planner_util.go:54`）/ 动态三处（`layer_dyn.go:70/:266/:868`）+ `chain_planner_chain.go:28` carry / `main.go:135/:593` | — |

### 11.2 接口签名

- `Planner.Validate(spec core.FlowSpec) error`（`radius.go:95`）：`Radius==nil` 即拒（`:107`，**与前七协议 nil 合法不同**）；请求码/响应码白名单、无 auto 拒、authenticator hex/16B、属性 format/长度（两列表逐条）。
- `Planner.Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`:235`）：缺省化（dst 1812/1813、rounds 1、code 1、reqAttrs、fixedAuth）→ goroutine 内 Rounds 循环产出 2R 个 `PacketConfig`。
- `buildRadiusMessage(code, id byte, authenticator []byte, attrs []core.RadiusAttribute) ([]byte, error)`（`:379`）。
- `encodeRadiusAttribute(attr core.RadiusAttribute) ([]byte, error)`（`:404`）。
- 生成器：`Name() "radius"`；`GenEvents()` 返回 `nil`（**必须为 nil**，非 nil 会被 `chain_planner.go` 的事件分支接管）；`Generate` 逐包 relay + 强制 `Direction="up"`（`layer_gen.go:32-57`）；`validateLayer` = legacy `Validate` 零新文案（`:68-71`）。

### 11.3 数据结构

`RadiusConfig{Code int, Identifier uint8, Authenticator string, Attributes []RadiusAttribute, ResponseCode uint8, ResponseAttributes []RadiusAttribute, Rounds int}`（`types.go:8868-8902`，JSON 键 `code/identifier/authenticator/attributes/response_code/response_attributes/rounds`）；`RadiusAttribute{Type uint8, Format string, Value string, VendorID uint32}`（`:8904-8915`，JSON 键 `type/format/value/vendor_id`）；`LayerTransportDyn{SrcPort, DstPort *StrategyConfig}`。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry 9 键 allowlist）→ translate（层内 config → `spec.Radius` + 端口双态/顺序修正）→ `ChainPlanner` → `validateSpecBase`（src 0 保持名单）→ `validateLayer`（legacy 13 锚词）→ `Plan` → `isRawIPChain` 命中 → raw-IP 驱动 → `Generator.Generate`（relay + force-up）→ builder（UDP L4 装配 + IP 校验和）→ writer（PCAP/NIC）。

**端口顺序修正（D-RADIUS-1 核心裁定，as-built 复核）**：`validateSpecBase` 先于 translate 执行，其 `chain_planner.go:1074` 的预写拿不到 `spec.Radius`（恒 nil）→ 恒落 1812；translate 在 `chain_planner_translate.go:1786-1792` 依据**层 config 是否显式含 `dst_port`** 覆盖：缺席 → `code==4?1813:1812`，显式 → 层值赢。T-4（1813）与 T-20（1812）即该修正的双向执法格。

### 11.5 错误分支

`Validate` 13 条（§7 表）+ builder 4 条（不可达）+ 生成器 1 条（`layer_gen.go:34`）全部传 task error（零假成功——9 个 task-time 负例实测 0 帧）。**create-time 2 条**（presence/static）在建策略阶段 400，**不产文件**。

### 11.6 性能边界

见 §6（流式 channel 256、逐包 emit、无聚合、无锁、per-flow 局部状态；吞吐数字待框架基准）。

### 11.7 与现有逻辑的冲突点

- `validateSpecBase` 的 **`src_port` 零保持名单**（`chain_planner.go:996`）含 `radius`——链路径 src 缺席时保持 0（worker `12345+i` 保底），与 legacy `mapToFlowSpec` 的 `12345` 缺省**不同口径**（两路各自闭合，D-RADIUS-1 已裁定保留扁平侧默认）。
- `strategy_convert.go:1298-1310` 保留扁平侧 `radius` 子映射解析 + 1812/1813 缺省（注释写"统一架构落地后移除"，D-RADIUS-1 裁定**不移除**）——扁平路径仍服务内部形状。
- `CheckProtoFlat` 的 radius 分支只拦**顶层 `radius` 子映射**（空 map 也死）；**游离顶层未知键无通用门**（如 `{layers:[…], bogus:1}` 今日不判死）→ G-RADIUS-16。
- 动态 allowlist（`layer_dyn.go:70`）radius 行**只有 2 个端口键**，业务 7 键对象即 `does not support dynamic`（`radius_layer_dyn_test.go` 锁住）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 3 文件 + 接线 6 处（registry/protocols/translate/convert/chain_planner/layer_dyn/main）；不触及其他协议。cases 回滚 = 恢复 25 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 24/25 顶层 = `{layers}`（唯一残留 = 负例 presence 判死对象）；目标形状见 §2 样例且**存量已达标** | §12.1；`cases/radius.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 radius 流量模板（Code/轮数/属性模板）；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表**豁免**（UDP 无状态，RFC 2865 §2）/ 事务序列 = Rounds×(req→rsp) / 关联 = Identifier 复刻 / 插入位置 = raw 自驱终层 / 时间线 = 轮次线性 | §12.3 + §5 |
| §4 查规范 | RFC 2865 + 2866 + 5997 + 5176 + 3579 + tshark 3.6.14 字段与 25 例实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["ip"]` 单值（`registry.go:1870`）；13 锚词 + 2 框架门；失败传 task error（9 例 0 帧实测） | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待框架基准，不写承诺；pcap/NIC 两路验收明写） | §6 |
| §7 三份文档 | `109-radius-{design,testcase}.md` v1.0.0（本版）+ D-RADIUS-1（`CODE_DESIGN.md:2809`，as-built 定稿）+ T-RADIUS-1…25（`TEST_CASES.md:3592`）+ cases JSON 25 例 | 修订记录 |
| §8 设计先行 | 旧基线 P2 定稿先于 P4 落码（`1501264`）；本版为 as-built 追认，不改语义 | 提交序 |
| §9 测试三源 | 三源 = RFC 2865/2866/5997/5176/3579（§10）+ D-RADIUS-1（§11）+ 参考 pcap 转录与 25 例实测（**已到抓包级**：本车道今日隔离复跑 25/25，14 正例帧数逐例对账）；25 ID 逐项回指；存量审计去向 testcase §8 | `109-radius-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 `/tmp/pipe/doc-lanes/radius.md`）+ 收官隔离复审；红先绿后 | 自审日志 |
| §11 白话 | 本文首节白话一句先行 | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组 + 端口开（allowlist 实测 2 键）；业务 7 键关 + 逐键理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `radius` 已在 `registry.go:1870` 注册（**不新增层**）；Fields 9 键与 `types.go` 7 业务键 + 2 端口键一一对应；**P4 若改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `radius.*` 字段 + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/radius/`（本车道复跑落 `/tmp/radius-probe/`） | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | `spec_json` 顶层键分布 | 层形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/radius.json` | 25 | **`{layers}` ×24**（唯一顶层键）+ **`{layers,radius}` ×1**（`radius_flat_presence`，判死执法对象） | **`[ip,radius]` ×25 全部** | 11 例均为 `{expect_error, error_contains}` 严格两键 |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 本协议**从未用过顶层地址**；地址住 `layers[0].ip.{src,dst}`（25/25 显式写） |
| `src_port` | **0** | 已住 `layers[1].radius.src_port`（T-20 缺省不写，走 worker 保底） |
| `dst_port` | **0** | 已住 `layers[1].radius.dst_port`（24 例显式；T-20 缺省） |
| `count` | **0** | 走 `strategy_fc`（T-3/T-21 两例 `{"type":"flows","value":2}`） |
| 顶层 `radius` 子映射 | **1**（`radius_flat_presence`） | 判死执法对象（**非残留**，记忆 `presence-negative-case-shape`）；业务键已全部住 `layers[1].radius` |
| `strategy_fc` | **2** | 结构性键（CORE_MEMORY 1.11 白名单家族），非违规 |

**结论**：**本协议非负例顶层零残留**——§1 门的动作 = ①无旧键可删；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测 24/24 非负例 `spec_json` 顶层仅 `layers`）；③A′ 新增例全部沿用纯 layers 形（§13）。

目标形状样例见 §2（顶层仅 `layers`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"radius":{}}` **今日被拒**（`CheckProtoFlat` 有 radius 分支，`strategy_convert.go:8975-8979`；空 map 也死）→ **已建例**（`radius_flat_presence`），锚词 `top-level radius sub-config`。② 白名单外游离键判死（`unknown field`）今日**无通用门** → **不建该负例**（建了会真绿 = 假通过）→ G-RADIUS-16 登记。③ 11 负例每条带锚词（已齐，§7）。④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

**会话表**：**豁免**——RADIUS 承载于 UDP，RFC 2865 §2 无连接建立/释放过程，无握手/无挥手/无保活，故无 `sessions[]` 结构。豁免理由如实写出（CORE_MEMORY 3.14），**不硬凑**。单流基线 = T-1（1 个 4 元组，1 轮）。
**事务序列**：`t1` 请求（Code/ID/Auth/Attributes，up）→ `t2` 响应（同 ID 复刻，端口/地址交换，down）；`Rounds` 轮按序重复（T-18 = 3 轮）。每事务四件事：前置（无，UDP 无状态）/ 触发（配置声明或 auto 派生）/ 成功（响应包产出，`packet_count` +2）/ 失败（配置非法 → `Validate` 拒，零包，§7）。
**关联关系**：请求-响应对关联键 = **Identifier 复刻**（RFC 2865 §3 "aids in matching requests and replies"）；**无派生流**（RADIUS 不派生数据/媒体流，无 `driven_by`）。
**插入位置**：**raw 自驱终层**（`[ip,radius]`，无中间层）——生成器自产 Eth+IP+UDP+RADIUS 整包，`isRawIPChain` 命中（`chain_planner_util.go:54`）。
**时间线**：轮次线性——第 r 轮两帧（请求 → 响应），Identifier = `base + r`；**无并发、无交错**（多流并发由策略级 `strategy_fc` 承载，T-21，`distinct_values` 聚合断言不钉包位）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组 + 端口**：`ip.src`/`ip.dst`（ip 层，allowlist `layer_dyn.go` 头部 `"ip"` 全开）、`radius.src_port`/`radius.dst_port`（`layer_dyn.go:70` **开**，5 策略全支持）。T-21 实证：`inc` 双 group_id → 2 流端口池 `12001/12002`（源）与 `1812/1813`（目的），实测 4 包内 `udp.srcport`/`udp.dstport` 各聚 4 值（响应侧端口交换，聚合含双向）。
**业务字段 7 项全关**（allowlist 无对应键，对象即 `does not support dynamic`；`radius_layer_dyn_test.go` 锁住）：`code`（协议语义选择器，逐流变即"同流多协议"）/ `response_code`（同上）/ `identifier`（轮序基址，逐流变破坏 ID 语义）/ `rounds`（结构计数，逐流变应由 `flows` 承载）/ `authenticator`（鉴权面，逐流变无意义且破坏可钉值格）/ `attributes`·`response_attributes`（AVP 静态模板，列表无动态形状）——逐流变体需求列 A′ 候选（testcase §6.2）。
**序号算法实读**：`parseLayerDyn`（`layer_dyn.go:78`）→ allowlist 判定（`:1051-1054`）→ 逐流解析 `resolveLayerTuple`（`:770`）的 **radius 块（`:867-877`）**：`ld.RADIUS.SrcPort`/`DstPort` 非 nil 时 `ResolvePortValue(strategy, i)`，非 0 才写回 `spec.SrcPort`/`spec.DstPort`（0 值 no-op 保留静态）；保底自增由 worker 承担（`12345+i`）。

## 13. P3 对接清单（T-RADIUS 草稿输入；正文落 testcase 文件）

25 ID（14 正 + 11 负）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。**A′ 候选 12 例**：`radius_neg_attr_empty`（空值属性）/ `radius_neg_vsa_boundary_ok`（247B 过）/ `radius_vsa_empty`（VSA 空值）/ `radius_neg_attr254_vsa`（VSA 254 拒，与 248 分格）/ `radius_rounds_zero`（显式 0）/ `radius_rounds_wrap`（rounds>256 回绕）/ `radius_neg_ipv4_format`（format=ipv4 非法值）/ `radius_neg_uint32_format`（format=uint32 非法值）/ `radius_neg_hex_format`（format=hex 非法值）/ `radius_neg_ip`（非法 IP，链不可达须注明）/ `radius_neg_mixed_family`（异族混写）/ `radius_neg_flat_key`（游离顶层键，**须先补通用门**，G-RADIUS-16）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-RADIUS-1 | **Authenticator 不按 RFC 计算**：响应侧恒随机（`radius.go:343`），不实现 RFC 2865 §3 的 `MD5(Code+ID+Length+RequestAuth+Attributes+Secret)`；请求侧不实现 RFC 2866 §3 的 Accounting-Request MD5 合成 | **明确不解决**（无共享密钥模型，属生成器边界）；用例断言仅 `nonzero`/fixed hex；若未来实现须新增独立例并重钉（T-12 的响应侧断言须重写） |
| G-RADIUS-2 | RFC 5176 CoA/Disconnect 码族（40–45）与 3799 端口未支持；T-25 为负例执法格 | **B′ 立项**（扩 `requestCodes`/`responseCodes`/`autoResponse` 三表 + 端口语义 + 用例）；今日不得声称支持 |
| G-RADIUS-3 | Message-Authenticator(80) 只作 opaque 字节承载（T-24），不计算不校验 HMAC-MD5（RFC 3579 §3.2）；EAP-Message 配对语义未实现 | **B′ 立项**；今日不得声称完整性保护 |
| G-RADIUS-4 | 缺省属性集只覆盖 code 1/4 两类（§3.5）；code 3/11/12 复用 User-Name 缺省；响应侧缺省空；属性 Type 与 Code 的匹配不校验 | **A′ 候选**（按 Code 分列缺省集 + 语义校验开关）；今日按 §3.5 钉 |
| G-RADIUS-5 | UDP 重传/超时计时（RFC 2865 §2.4）未模拟；多轮用 `identifier+round` 递增替代 | **C 类口径**（harness 无法表达重传计时；多轮语义由 T-18 承载） |
| G-RADIUS-6 | 报文 Length 上界 **4096**（RFC 2865 §3）未执法；引擎只守 65535（`radius.go:389`）——多属性叠加可产 >4096 报文 | **A′ 候选**（补 4096 执法门 + 边界例）或登记为生成器边界 |
| G-RADIUS-7 | `MaxMessageLen=65535` 分支不可达（UDP 载荷上限 65507 < 65535），无用例 | **C 类注记**（死分支）；A′ 可补"多属性逼近上限"例 |
| G-RADIUS-8 | `src_port` 缺省时链路径为 **0**（worker `12345+i` 保底），T-20 未断言 srcport；legacy 扁平路径默认 `12345`（两路口径不同） | **A′ 候选**（补 srcport 保底断言例）；今日如实标注口径差异 |
| G-RADIUS-9 | **已关闭（2026-09-30）**：存量 `radius_neg_vsa_len`/`radius_neg_coa` 两例曾带 `expect.notes`，与负例严格两键口径不符 | 本轮删除该两键，11/11 负例执行期 `expect` 严格为 `expect_error` + `error_contains`；14 个正例的说明性 `notes` 保留 |
| G-RADIUS-10 | **陈旧负例产物**：`/tmp/mcp-pcaps/radius/radius_flat_static_port.neg.pcap` 是 **186B/2 包**（2026-09-19 23:21），而该例今日为 **create-time 拒绝、不产文件**（本车道隔离复跑实测：`/tmp/radius-probe2/` 零文件） | **代码阶段**（重跑套件后清理/重生成该目录）；**结果文档该行的 "0" 是文档值非 pcap 实测值**，读者不得据此判断产物一致 |
| G-RADIUS-11 | **结果文档的 25/25 非本车道复跑产物**：`trafficgen/docs/protocol-pcap-test/radius.md` 末次提交 `dbe0765`（2026-09-19 23:42）**晚于**判死提交 `0417be5`（2026-09-13）→ **不构成过期产物**（与 pcep G-PCEP-11 / opcua G-OPCUA-10 情形相反）；但本车道**未改写该 tracked 产物**，其 25/25 仍是 2026-09-19 的数字 | 本车道今日在**隔离目录**复跑得 25/25（§6 实测行），两数字独立；读者须知二者非同一产物 |
| G-RADIUS-12 | VSA 内层**只写单个** vendor type/length/value 三元组；RFC 2865 §5.26 允许 MAY 多个子属性；内层 Type 复用用户 `type` 字段（非独立 vendor type 字段） | **A′ 候选**（多子属性形 + 独立内层 type 键）；今日按单子属性钉（T-15 实测外层 len 10） |
| G-RADIUS-13 | **Status-Server 的 auto 响应码与 RFC 5997 §2/§4.1 不符**：规范要求 Access-Accept(2) 或 Accounting-Response(5)，本引擎 auto 回 **13 Status-Client**（`radius.go:61-65`）；T-6 按实现钉 | **代码阶段裁定**：改 auto 表（须重钉 T-6 断言 `radius.code=13`→`2`）或保留为引擎合同并加注；今日不得声称符合 RFC 5997 |
| G-RADIUS-14 | **NIC 输出路径本车道未跑**（pcap 路今日已跑 25/25）；两路共用同一断言集（§1 输出契约）但 NIC 侧无今日证据 | **代码阶段**（`nic_capture` 开关 + `enp135s0f0np0` 复跑）；今日不得声称 NIC 路已验 |
| G-RADIUS-15 | 参考 pcap `portion_Radius.pcap`/`start-stop.pcap`（`radius.go:17-18` 记为其字节事实来源）**不在本仓**，本车道无法二次核验其内容 | **待确认**（确认方式：向 D-RADIUS-1 作者索取原始 pcap，或抓现网 RADIUS 认证/计费包对照）；确认前不据此声称现网合规 |
| G-RADIUS-16 | `CheckProtoFlat` 有 radius presence 分支，但**无游离顶层未知键通用门**（`{layers:[…], bogus:1}` 今日不判死） | **B′ 框架面**（等框架级 unknown-key 白名单，**禁加单协议黑名单分支**，kingbase 记忆裁定）；今日不建该负例（建了会真绿） |

## 15. 层链迁移设计审计（D1–D8，2026-09-30）

| ID | 结论 | 证据/缺口 |
|---|---|---|
| D1 | 已登记 | RFC 2865/2866/5997/5176/3579 → §1–§5 业务与线格式 → §10 矩阵 → §14 缺口；未把未实现能力写成已实现 |
| D2 | 已登记 | `[ip,radius]` 是唯一正例目标形；ip 地址与 radius 端口/业务字段均住层内；唯一顶层 `radius` 仅为 presence 判死负例 |
| D3 | 已登记 | `radius` 为 raw-IP 终结层，`DependsOn=["ip"]`；无 tcp/udp 中间层，UDP 头由终结生成器自产 |
| D4 | 已登记 | §3.1/§3.2 逐字段给出偏移、宽度、端序、长度公式；§3.3/§3.4 给出 Code、Identifier、Authenticator 规则 |
| D5 | 已登记 | §7 逐条错误锚词与拒绝时机；未覆盖 validator 分支列入 A′，未伪造 JSON 用例 |
| D6 | 已登记 | §6 明确流式 channel、单包上界、并发/背压与 pcap/NIC 双输出验收；吞吐数字标待确认 |
| D7 | 已登记 | §12.12 列出端口动态 2 键、序号算法及业务 7 键关闭理由；`strategy_fc` 仅为流控兄弟键 |
| D8 | 已登记 | §14 的 G-RADIUS-1…16 明确未实现边界、去向与失败用例要求；不改 Go 代码 |

## 16. 六项设计审查清单（C1–C6）

| ID | 结论 |
|---|---|
| C1 | design/testcase/cases 的 25 个 ID、顺序、包数和字段断言已对账；cases JSON 可解析 |
| C2 | 24 个非负例严格使用 `[ip,radius]`，唯一顶层 `radius` 是故意 presence 负例 |
| C3 | 20B 头、TLV/VSA、Code/响应、默认端口、IPv4/IPv6 与 raw-IP 路径均有依据；Authenticator RFC 合成与 Status-Server 差异已登记 |
| C4 | 11 个负例均有单一故障与锚词；未覆盖分支归入 A′/B′，不冒充当前覆盖 |
| C5 | 多轮、多流、边界、VSA、属性格式及响应属性均有 cases 落点；RFC 重传、真实 HMAC、CoA 等明确不适用/待实现 |
| C6 | 本次只改 design、testcase、cases 三件套；不改 Go、全局索引或其他协议；pcap/NIC 共用同一 JSON 契约，NIC 本轮未运行 |

## 17. 缺口与后续计划

本轮不新增能力。G-RADIUS-1…16 继续作为实现阶段缺口；优先补齐 A′ 的非法 format/IP、边界/回绕、异族混写与源端口保底断言，并按“失败用例先行”再改代码。B′ 的 CoA/HMAC/顶层白名单保持框架级立项。

## 18. 修订记录

- 2026-09-30：补齐 D1–D8/C1–C6 层链审计；删除两条负例 `expect.notes` 形状偏差的 cases 文本；未改 Go 代码。
- v1.0.0（2026-09-29）：批次二文档轨 as-built 首版。

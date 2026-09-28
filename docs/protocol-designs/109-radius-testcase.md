# #109 radius（RADIUS · UDP 1812/1813）测试用例契约

> 版本：v1.0.0（批次二 as-built 文档轨）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/109-radius-design.md` v1.0.0（D-RADIUS-1 as-built 定稿）
> 前置权威：`docs/TEST_CASES.md:3592` **T-RADIUS-1…25**（P5 全绿）、`docs/CODE_DESIGN.md:2809` **D-RADIUS-1**
> 机器契约：`trafficgen/test/protocol_pcap/cases/radius.json`（**25/25 ID 与本版 §2 一致、顺序一致**，机读实测）
> 白话一句：**二十五条检查：十四条看正常一问一答（认证、计费、质询、探询、多轮、厂商标签、新网段、多设备），十一条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **25 个唯一语义 ID：14 正 + 11 负**。派生规则：设计 §3 每个字段/编码条款、§5 每个事务与自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：25/25 例顶层键 = `{expect,id,proto,spec_json,summary}`（+ `strategy_fc` ×2）；`spec_json` 顶层键 = **`{layers}` ×24 + `{layers,radius}` ×1**（唯一残留 = 负例 `radius_flat_presence`，**判死执法对象非残留**）；层形 **`[ip,radius]` ×25 全部**（无 tcp/udp 中间层——raw 自驱终层）；14 正例 `expect` 键 = `{packet_count, fields, notes}`（**14/14 带 `notes`**）；11 负例 `expect` 键 = `{expect_error, error_contains}` ×9（严格两键）+ `{expect_error, error_contains, notes}` ×2（`radius_neg_vsa_len`/`radius_neg_coa`，G-RADIUS-9）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`udp.srcport`/`udp.dstport`、`ipv6.dst`、`radius.code`/`id`/`length`/`req`/`rsp`/`reqframe`/`authenticator`/`avp.type`/`avp.length`）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。**今日证据只有 pcap 一路**（§7 实测行），NIC 路未跑（G-RADIUS-14）。

**TSHARK 基线（本机 3.6.14 实测）**：有 `radius` dissector——`tshark -G decodes` 含 `udp.port 1812/1813/1645/1646/3799 radius`；`tshark -G fields` 中 `radius.*` 字段可用。本套件实际使用的断言通道：① `radius.code`（十进制串）；② `radius.id`；③ `radius.length`；④ `radius.req`/`radius.rsp`（请求/响应标记，取值 `1`）；⑤ `radius.reqframe`（**响应帧里回指请求帧号**，值随包位变化）；⑥ `radius.authenticator`（32 位小写 hex）；⑦ `radius.avp.type`/`radius.avp.length`（**同包多属性逗号拼接**）；⑧ `udp.srcport`/`udp.dstport`；⑨ `ipv6.dst`。

**rsp/reqframe 实测口径（重要，与本套件断言口径相关）**：tshark 只对**标准请求/响应对**（Access-Request↔Access-Accept、Accounting-Request↔Accounting-Response、Access-Request↔Access-Reject）打 `radius.rsp`/`radius.reqframe`；对 **11→11**、**12→13**、**3→3** 三类**非标准对不打**（实测 `radius_challenge`/`radius_status`/`radius_code3` 三例 `rsp`/`reqframe` 全空）——故这三例的方向**改用 `udp.srcport`/`udp.dstport` 交换**钉（P5 校准②，设计 §3.1）。

**断言基线**：今日 25 例共 **61 条 field 断言**（`value` 55 + `nonzero` 3 + `distinct_values` 3），零 frames 断言（本套件走 tshark 字段通道，非原始 hex）；`packet_count` **14 条 = 14/14 正例全覆盖**（机读实测，无正例缺包数断言）。

**动态字段禁止硬编码**：随机面（响应 Authenticator 恒随机、请求缺省随机、`ip.id`）一律用 `nonzero` 或不作断言（设计 §3.4）；`radius_port_dyn` 用 `distinct_values` 聚合（不钉包位，P5 校准③）。

**包数约定（实测公式，设计 §9）**：单流 = **`2 × rounds`**（每轮请求 up + 响应 down；**无握手、无挥手**——UDP 无连接）。校验：rounds 缺省 1 → **2 包 ×12 例**（另 T-21 为 2 流 × 1 轮 × 2 = **4 包**）；`radius_rounds` rounds=3 → **6 包** ✓。合计 12×2 + 4 + 6 = **34 帧**。**14/14 正例均带 `packet_count`**。负例无 `packet_count`。

**保活/重试/RST 口径**：协议层**无保活、无重试、无 FIN/RST**（UDP 无连接）；RFC 2865 §2.4 的重传计时未实现（G-RADIUS-5）；RFC 5997 的 Status-Server 存活探询以**单次一问一答**承载（T-6），不是周期心跳。**正例无任何终止类断言**（本套件零 `terminates`/`has_handshake`）。

## 2. 原子用例索引（25 ID = 14 正 + 11 负，顺序为权威）

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

**T-编号对照**：T-RADIUS-1 ≡ #1；T-2 ≡ #2；T-3 ≡ #3；T-4 ≡ #4；T-5 ≡ #5；T-6 ≡ #6；T-7 ≡ #7；T-8 ≡ #8；T-9 ≡ #9；T-10 ≡ #10；T-11 ≡ #11；T-12 ≡ #12；T-13 ≡ #13；T-14 ≡ #14；T-15 ≡ #15；T-16 ≡ #16；T-17 ≡ #17；T-18 ≡ #18；T-19 ≡ #19；T-20 ≡ #20；T-21 ≡ #21；T-22 ≡ #22；T-23 ≡ #23；T-24 ≡ #24；T-25 ≡ #25。（**JSON 顺序 ≠ T-编号顺序**：JSON 中 #4 是 T-4、#5 是 T-5、#6 是 T-6、#7 是 T-7、#8 是 T-8，而 T-9…T-17 的负例紧随其后；**序号以 cases JSON 顺序为权威**。）

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count` + `radius.code` 断言；帧位由 §1 公式与实测 pcap 双向确认。**下表的"实测"列全部来自本车道 2026-09-29 隔离目录复跑（`/tmp/radius-probe/`），非 2026-09-19 的旧产物。**

### 3.1 `radius_smoke_01`（2 包）

`layers[0].ip={10.0.0.1→20.0.0.1}`、`radius={src_port:12345, dst_port:1812}`（业务面全缺省）。

- `packet_count=2`。
- 帧 1：`udp.dstport=1812`、`radius.code=1`、`radius.id=0`、`radius.length=26`、`radius.req=1`、`radius.avp.type=1`、`radius.avp.length=6`、`radius.authenticator` **nonzero**（缺省随机）。
- 帧 2：`radius.code=2`（auto）、`radius.id=0`（**复刻**）、`radius.rsp=1`、`radius.reqframe=1`、`radius.length=20`（响应侧无属性）、`radius.authenticator` **nonzero**（恒随机）。
- **实测**：帧 1 `udp.length=34`（8+26）、`avp.type=1`/`avp.length=6`（User-Name `"user"` 4B + 2）；帧 2 `udp.length=28`（8+20），`rsp=1`/`reqframe=1`。
- **缺省证据**：业务面全空仍产 2 包 = 设计 §5 自动派生规则 1/2/3/6 的联合执法格。

### 3.2 `radius_acct_1813`（2 包）

`radius={src_port:12345, code:4, attributes:[{type:40,format:uint32,value:"1"},{type:4,format:ipv4,value:"10.0.0.1"}]}`（**`dst_port` 缺席**）。

- `packet_count=2`。
- 帧 1：`udp.dstport=**1813**`（缺省分流）、`radius.code=4`、`radius.avp.type="40,4"`。
- 帧 2：`radius.code=5`（auto）、`radius.rsp=1`、`radius.reqframe=1`。
- **实测**：帧 1 `avp.type=40,4`、`avp.length=6,6`、`radius.length=32`；帧 2 `radius.length=20`。
- **顺序修正专项证据（设计 §11.4）**：`validateSpecBase` 的 1812 预写拿不到 `spec.Radius`，靠 translate 依层键缺席覆盖为 1813——本例是 1813 侧执法格，`radius_default_port` 是 1812 侧执法格。

### 3.3 `radius_challenge`（2 包）

`radius={src_port:12345, dst_port:1812, code:11, response_code:11}`。

- `packet_count=2`。
- 帧 1：`radius.code=11`、`udp.srcport=12345`。
- 帧 2：`radius.code=11`、`udp.srcport=**1812**`、`udp.dstport=**12345**`。
- **实测**：两帧 `radius.req`/`radius.rsp` **均空**（tshark 不对 11→11 打标准对标记）→ 方向用**端口交换**钉（§1 口径）；两帧 `radius.id=0`（复刻）。
- **合同证据**：code 11 无 auto 映射（`autoResponse` 无 11），不写 `response_code` 会被 N-1 拒——本例是"显式响应合同"的执法格。

### 3.4 `radius_status`（2 包）

`radius={src_port:12345, dst_port:1812, code:12}`。

- `packet_count=2`。
- 帧 1：`radius.code=12`、`udp.srcport=12345`。
- 帧 2：`radius.code=**13**`（auto）、`udp.srcport=1812`、`udp.dstport=12345`。
- **实测**：两帧 `rsp`/`reqframe` 均空 → 端口交换钉；两帧 `radius.id=0`。
- **诚实边界（G-RADIUS-13）**：RFC 5997 §2/§4.1 规定服务器应回 **Access-Accept(2) 或 Accounting-Response(5)**；本引擎 auto 回 13（Status-Client）是**引擎自定合同**。本用例按实现钉 `code=13`，**不声称符合 RFC 5997**。

### 3.5 `radius_code3`（2 包）

`radius={src_port:12345, dst_port:1812, code:3, response_code:3}`。

- `packet_count=2`；帧 1 `radius.code=3`、帧 2 `radius.code=3`。
- **实测**：两帧 `rsp`/`reqframe` 均空（非标准对）→ 端口交换钉（本例未写端口断言，仅 code 双断言）。
- **合同证据**：`requestCodes{1,3,4,11,12}` 含 3（legacy 合同，RFC 里 3 是响应码）——本例是"请求码 3 枚举格"。

### 3.6 `radius_reject`（2 包）

`radius={src_port:12345, dst_port:1812, code:1, response_code:3}`。

- `packet_count=2`；帧 1 `radius.code=1`、帧 2 `radius.code=3`、帧 2 `radius.rsp=1`。
- **实测**：帧 2 `rsp=1`（**Access-Request↔Access-Reject 是标准对，tshark 打标**）。
- **失败分支证据（CORE_MEMORY 3.7/9.9）**：显式 `response_code:3` **覆盖** auto 的 2——鉴权失败分支。

### 3.7 `radius_auth_fixed`（2 包）

`radius={src_port:12345, dst_port:1812, code:1, authenticator:"000102030405060708090a0b0c0d0e0f"}`。

- `packet_count=2`。
- 帧 1：`radius.authenticator=**000102030405060708090a0b0c0d0e0f**`（**唯一可钉值格**）。
- 帧 2：`radius.authenticator` **nonzero**（**恒随机，即使请求侧固定**，设计 §3.4）。
- **实测**：帧 2 实测 `64e6e27a1c98ca6fa5e997a641b489d1`（每次跑不同，故只能 nonzero）。

### 3.8 `radius_attr_formats`（2 包）

`radius={src_port:12345, dst_port:1812, code:1, attributes:[5 条：type1 string/type8 ipv4/type5 uint32/type6 hex/type26 VSA vendor_id 9], response_code:2, response_attributes:[{type:26, vendor_id:9, value:"ok"}]}`。

- `packet_count=2`。
- 帧 1：`radius.avp.type="1,8,5,6,26"`、`radius.avp.length="6,6,6,4,10"`。
- 帧 2：`radius.avp.type="26"`。
- **实测**：帧 1 `radius.length=52`、`avp.length=6,6,6,4,10`；帧 2 `radius.length=30`、`avp.length=10`。
- **枚举证据**：format 四态 4/4（`string`→len6、`ipv4`→len6、`uint32`→len6、`hex "aabb"`→len4）；VSA 外层 type 26 / 外层 len 10（= 8 + 内层 2）；**`response_attributes` 非空格**（CORE_MEMORY 9.22 双列表各 ≥1 格）。
- **逗号拼接口径**：同包多属性 tshark 逗号拼接（P5 校准①），断言按序全列。

### 3.9 `radius_rounds`（6 包）

`radius={src_port:12345, dst_port:1812, code:1, identifier:5, rounds:3}`。

- `packet_count=6`。
- `radius.id` 逐帧 = **5, 5, 6, 6, 7, 7**（每轮 req+resp 同 id 复刻）。
- **实测**：`radius.reqframe` 帧 2/4/6 = **1/3/5**（响应回指对应请求帧号）。
- **合同证据**：`byte(identifier + round)`（设计 §3.1）；同四元组多轮 = 同流多事务（设计 §5）。

### 3.10 `radius_v6`（2 包）

`layers[0].ip={fd00::1→fd00::2}`、`radius={src_port:12345, dst_port:1812, code:1}`。

- `packet_count=2`；帧 1 `ipv6.dst=fd00::2`、`radius.code=1`；帧 2 `radius.code=2`。
- **实测**：报文起点从 IPv4 offset 42 移至 **IPv6 offset 62**（14+40+8），**报文字节不变**（`radius.length` 26/20 同 T-1）。
- **族对称证据**：`Validate` 无族强制（设计 §1 profile 表）。

### 3.11 `radius_default_port`（2 包）

`radius={code:1}`（**`src_port`/`dst_port` 全缺**）。

- `packet_count=2`；帧 1 `udp.dstport=**1812**`、`radius.code=1`；帧 2 `radius.code=2`。
- **实测**：帧 1 `udp.srcport=**12345**`（**worker 保底**——层键缺席时 spec.SrcPort 为 0，worker 注入 `12345+i`）；本例**不写 srcport 断言**（G-RADIUS-8：链路径缺省语义与 legacy 的 12345 不同口径，断言口径待 A′ 明确）。
- **缺省分流证据**：`code!=4` → 1812（对照 T-4 的 1813）。

### 3.12 `radius_port_dyn`（4 包）

`radius={code:1, src_port:{strategy:inc, range:[12001,12002], step:1, group_id:"radius-src"}, dst_port:{strategy:inc, range:[1812,1813], step:1, group_id:"radius-dst"}}` + `strategy_fc={type:flows, value:2}`。

- `packet_count=4`（2 流 × 1 轮 × 2）。
- `udp.srcport` **distinct_values = ["12001","12002","1812","1813"]**、`udp.dstport` 同集、`radius.code` distinct_values = ["1","2"]。
- **实测**：4 帧端口组合为 `(12002→1813)`、`(12001→1812)`、`(1812→12001)`、`(1813→12002)`——**响应帧端口交换**导致 src/dst 双向各聚 4 值（CORE_MEMORY 14.13 客户端/服务端口双向混入，P5 校准③）。
- **不钉包位证据**：多流调度非确定交织（`group_id` 固定保证同 worker FIFO），故用 `distinct_values` 聚合而非包位断言。

### 3.13 `radius_attr_boundary`（2 包）

`radius={src_port:12345, dst_port:1812, code:1, attributes:[{type:1, value:<253 字节 x>}]}`。

- `packet_count=2`；帧 1 `radius.avp.type=1`、`radius.avp.length=**255**`；帧 2 `radius.code=2`。
- **实测**：帧 1 `radius.length=275`（20 + 255）、`udp.length=283`。
- **边界证据（CORE_MEMORY 9.46）**：253+2 = 255 恰满 1 字节 Length；254 由 T-16 拒——**边界相邻值对偶**。

### 3.14 `radius_nas_combo`（2 包）

`radius={src_port:12345, dst_port:1812, code:1, attributes:[{type:6,format:uint32,value:"2"},{type:4,format:ipv4,value:"10.0.0.1"},{type:31,value:"00-11-22-33-44-55"},{type:80,format:hex,value:"000102…0f"}]}`。

- `packet_count=2`；帧 1 `radius.avp.type="6,4,31,80"`、`radius.avp.length="6,6,19,18"`；帧 2 `radius.code=2`。
- **实测**：帧 1 `radius.length=69`（20 + 6+6+19+18）、`udp.length=77`。
- **现网组合证据（CORE_MEMORY 9.10）**：Service-Type(6)/NAS-IP(4)/Calling-Station-Id(31)/Message-Authenticator(80) 四属性同包承载；**MA 只作 opaque 字节**（`hex` 16B → len 18），**不计算不校验 HMAC-MD5**（G-RADIUS-3，设计 §1 边界③）。

**正例总则**：多属性同包、多轮展开、显式响应覆盖 auto、VSA 承载、IPv6 载体、缺省端口、逐流端口均为正例形态；只有配置错/长度错/值域错/载体错进入负例。

## 4. 负例契约

负例必须在建策略或启动任务阶段失败并传播为 task error，不得产生成功 PCAP 或"任务报成功 0 包"的假成功。**本协议负例分两层执行期（今日实测，设计 §7）**：

| 层 | 拒绝时机 | 落盘 | 例数 | ID |
|---|---|---|---|---|
| **create-time** | 建策略即 400（框架门） | **不产 pcap 文件** | 2 | `radius_flat_presence`、`radius_flat_static_port` |
| **task-time** | 建策略通过、启动任务时 planner 拒 | `<id>.neg.pcap`，**0 帧**（24B 仅文件头） | 9 | 其余 9 例 |

**逐条锚词表（代码逐字，`radius.go` 实测行号；与设计 §7 同序）**：

| ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（逐字） | 代码行 | 时机 |
|---|---|---|---|---|---|
| `radius_neg_no_auto` | `code:3` 无 `response_code` | `has no default response code` | `radius: code %d has no default response code; set response_code explicitly` | `radius.go:128` | task-time |
| `radius_neg_reqcode` | `code:42` | `invalid request code` | `radius: invalid request code %d (allowed: 1, 3, 4, 11, 12)` | `:117` | task-time |
| `radius_neg_rspcode` | `code:1, response_code:9` | `invalid response code` | `radius: invalid response code %d (allowed: 2, 3, 5, 11, 13)` | `:125` | task-time |
| `radius_neg_auth_hex` | `authenticator:"zz"` | `invalid authenticator hex` | `radius: invalid authenticator hex: %v` | `:135` | task-time |
| `radius_neg_auth_len` | 15B hex | `must be 16 bytes, got 15` | `radius: authenticator must be 16 bytes, got %d` | `:138` | task-time |
| `radius_neg_attr_len` | string 254B | `exceeds the 253-byte field limit` | `radius %s[%d]: value length %d exceeds the %d-byte field limit (type %d)` | `:171` | task-time |
| `radius_neg_format` | `format:"dword"` | `unknown format` | `radius %s[%d]: unknown format %q (allowed: string, ipv4, uint32, hex)` | `:189` | task-time |
| `radius_neg_vsa_len` | VSA value 248B | `exceeds the 247-byte field limit` | 同 `:171`（`%d`=247） | `:171` | task-time |
| `radius_neg_coa` | `code:43`（RFC 5176 CoA-Request） | `invalid request code` | `radius: invalid request code %d (allowed: 1, 3, 4, 11, 12)` | `:117` | task-time |
| `radius_flat_presence` | `{layers:[ip,radius{}], radius:{}}` 并存 | `top-level radius sub-config` | `protocol radius no longer accepts a top-level radius sub-config (move it into the radius layer of an [ip,radius] layers chain)` | `strategy_convert.go:8977` | **create-time** |
| `radius_flat_static_port` | `[ip{},radius{src_port,dst_port}]` + `strategy_fc{flows:2}` | `static four-tuple` | `layers pin a static four-tuple but flows > 1: …` | `schema/semantic.go:285` | **create-time** |

**锚词口径**：`error_contains` 是**子串**判定；11/11 均命中代码文案（前 9 例带 `radius: ` 前缀或 `radius %s[%d]: ` 前缀，后 2 例为框架文案）。

**负例原子性**：每例单一故障注入；单次执行不得混注。**同锚词面两组**：`radius_neg_attr_len`/`radius_neg_vsa_len`（同一 `:171` 分支的 253/247 两个上界）；`radius_neg_reqcode`/`radius_neg_coa`（同一 `:117` 分支，假码 42 与现网真码 43 各一例——后者更贴近现网，RFC 5176 §2.3）。

**负例纯净性**：11 例 `expect` 均**无** `packet_count`/`fields`/`frames`；**其中 2 例另带 `notes`**（`radius_neg_vsa_len`/`radius_neg_coa`），与严格两键口径不符（G-RADIUS-9，代码阶段收窄）。

**陈旧产物提醒（G-RADIUS-10）**：`/tmp/mcp-pcaps/radius/radius_flat_static_port.neg.pcap` 是 **186B/2 包**（2026-09-19 23:21 产物），而该例今日为 create-time 拒绝、**不产文件**（本车道隔离复跑实测 `/tmp/radius-probe2/` 零文件）。结果文档该行写的 "0" 是**文档值非 pcap 实测值**——读者不得据此判断产物一致。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：`invalid source IP: %s`（`:98`）、`invalid destination IP: %s`（`:103`）、`radius config is required`（`:107`，**链路径不可达**）、`format=ipv4 value %q is not an IPv4 address`（`:178`）、`format=uint32 value %q is not a uint32`（`:182`）、`format=hex value %q is not valid hex`（`:186`）；builder 四条（`:390/:429/:434/:448`，`Validate` 后不可达）；`radius generator: invalid request`（`layer_gen.go:34`）。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 2865 + RFC 2866 + RFC 5997 + RFC 5176 + RFC 3579（设计 §10）+ D-RADIUS-1（设计 §11）+ 参考 pcap 转录（`portion_Radius.pcap`/`start-stop.pcap`，`radius.go:17-18`）与 **25 例实测 pcap**（本车道 2026-09-29 复跑 `/tmp/radius-probe/`；历史落盘 `/tmp/mcp-pcaps/radius/`）→ 25 ID（本契约 §2）。

**25 ID 逐项回指（CORE_MEMORY 9.5）**：#1←设计 §3.1/§3.5；#2←§7 N-10；#3←§7 N-11；#4←§3.3/§2；#5←§3.3；#6←§3.3；#7←§3.3；#8←§3.3；#9←§7 N-1；#10←§7 N-2；#11←§7 N-3；#12←§3.4；#13←§7 N-4；#14←§7 N-5；#15←§3.2；#16←§7 N-6；#17←§7 N-8；#18←§5；#19←§2；#20←§2；#21←§12.12；#22←§7 N-7；#23←§8；#24←§4 场景⑥；#25←§7 N-9。

**第三源缺口（G-RADIUS-15）**：参考 pcap 两份**不在本仓**，本车道无法二次核验其字节内容；确认方式 = 索取原始 pcap 或抓现网 RADIUS 认证/计费包对照。确认前**不据此声称现网合规**。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 2865/2866/5997/5176/3579 公开语义 + D-RADIUS-1 设计条目 + 仓库落码反推 + 25 例 pcap 实测**，**非纯规范反推**（参考 pcap 未二次核验 → G-RADIUS-15；RFC 2865 §5.31 等条款未逐条核对）。
- **对账两行**：**要求逻辑点总数 = 84**（八项 8 行 + 矩阵 27 格 + 变体 34 行 + 商业映射 15 行）；**用例覆盖数 = 55**（八项已覆 4 + 子表① 已覆 13 + 子表② 已覆 28 + 子表③ 已覆 10）；**不适用 = 17**（八项 1 + 子表① 11 + 子表③ 5）；**开放立项 = 12**（八项 3 + 子表① A′ 3 + 子表② A′ 6）。55 + 17 + 12 = 84 ✓
  **粒度声明**：行/格粒度每点 1 计；G-RADIUS-1…G-RADIUS-16 不折进 84。**反查全绿 ≠ 覆盖全**（CORE_MEMORY 9.52 原文）。逐表重数见设计 §10.1（八项 8 = 覆 4 + 立项 3 + 不适用 1）/§10.2（27 格 = 覆 13 + 不适用 11 + A′ 3）/§10.3（34 行 = 覆 28 + A′ 6）/§10.4（15 行 = 覆 10 + 不适用 5）。**84 之外另按枚举面单独对账（不折进 84）**：线上 Code 逐值 **8/8**（25 例 pcap 全扫实测 `{1×14, 2×13, 3×3, 4×1, 5×1, 11×2, 12×1, 13×1}`；40–45 六码未覆 → G-RADIUS-2）；format 四态 **4/4**（#15）；端口三档 **3/3**（#1/#20/#4）；地址族 **2/2**（#1 等 / #19）；§3.15 三项 = 已覆 2 + 显式不适用 1。
- **门3 抽查候选**：最复杂用例 = **#24 `radius_nas_combo`**（四属性同包：Service-Type/NAS-IP/Calling-Station-Id/Message-Authenticator，长度 6/6/19/18 逐序断言，报文 69B）；交织维度 = 属性数(4)×format(3 种：uint32/ipv4/string+hex)×承载位（请求侧）×(现网组合语义)。**建议门3 抽 #24 + #21**（`radius_port_dyn` 补多流+动态面）+ **#18**（`radius_rounds` 补多事务面）。

### 5.3 存量审计入口

存量 25 例**全部为本次契约覆盖对象**（`cases/radius.json` 即本版 §2 的机器形态，25/25 ID 与顺序一致）；逐条去向见 §8.3。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | UDP 无连接，多轮 = 同 4 元组 `Rounds` 轮（Identifier 递增） | **已覆** #18（rounds=3 → 6 包，id 5/6/7） |
| ② | 非正常结束 | **显式不适用**——UDP 无连接，无 FIN/RST/挥手概念；"异常"在协议层只有"配置被拒"（§4 负例） | **不适用 + 理由**（UDP 无状态）；RFC 2865 §2.4 重传计时未实现（G-RADIUS-5） |
| ③ | 长保活 | 协议层**无保活心跳**；RFC 5997 Status-Server 探询以**单次一问一答**承载（#6） | **已覆** #6（单次探询对）；**周期心跳不适用**（规范未定义周期性） |

**无空项**：① 有已覆例；② 显式不适用 + 理由；③ 有已覆例（单次探询）+ 周期心跳不适用。

### 6.2 A′/B′ 两分类表

**A′（代码阶段接线/补例）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 拒绝分支面 | `format=ipv4/uint32/hex` 非法值三例、非法 IP 两例（链不可达须注明）、游离顶层键（**须先补通用门**） | 设计 §13；G-RADIUS-16 |
| 长度边界面 | 空值属性、VSA 247B 过 / VSA 空值 / VSA 254 拒、报文 4096 上界 | G-RADIUS-6/G-RADIUS-12 |
| 轮次面 | `rounds:0` 显式、`rounds>256` uint8 回绕 | 设计 §8 |
| 端口面 | `src_port` 缺省保底 12345 的断言 | G-RADIUS-8 |
| 地址族面 | 异族混写拒绝（`must be same IP version`） | 设计 §8 |
| 缺省集面 | 按 Code 分列缺省属性集（code 3/11/12） | G-RADIUS-4 |
| 多子属性 VSA 面 | RFC 2865 §5.26 的多 sub-attribute 形 | G-RADIUS-12 |

**B′（框架面/独立条目）**：RFC 5176 CoA/Disconnect 码族 + 3799 端口（G-RADIUS-2，另立条目）/ Message-Authenticator HMAC-MD5 计算与 EAP 配对（G-RADIUS-3，另立条目）/ 游离顶层键通用门（G-RADIUS-16，等框架级 unknown-key 白名单，**禁加单协议黑名单分支**）/ `CheckProtoFlat` 之外的顶层白名单执法（CORE_MEMORY 1.13）。进设计 §14。

### 6.3 3.14 豁免边界审计

**无长连接载体（UDP 无状态）→ `sessions[]` 豁免成立**（RFC 2865 §2 无连接建立/释放；设计 §12.3 写出豁免理由）。**但豁免 `sessions[]` 不等于豁免多流覆盖（CORE_MEMORY 3.14）**：多流并发由策略级 `strategy_fc {"flows": N}` 承载，**已有用例** = #21 `radius_port_dyn`（2 流并发 + 逐流端口池 + `distinct_values` 聚合）。**单包多载荷**：本协议**一包一报文**（RFC 2865 §3 一个 UDP 数据报恰好一个 RADIUS 报文），**不适用**（如实声明，非缺口）。

## 7. 实现后执行建议

1. **本协议无 §1 迁移步骤**（非负例顶层零残留，设计 §12.1）；代码阶段顺序：①补 A′ 拒绝分支例（§6.2）；②补长度边界与轮次回绕例；③修 G-RADIUS-13（Status-Server auto 码，须重钉 #6 断言）与 G-RADIUS-9（删 2 负例 `notes`）；④重跑全量。
2. **实测顺序（本车道已走）**：先 #1（基线 length 26/20 + id 复刻），再 #4（1813 分流 + auto 5），再 #15（format 四态 + 逗号拼接），再 #18（多轮 id 5/6/7），再 #19（IPv6 offset 62），最后 #21（多流端口聚合）。
3. **今日实测行（本车道，2026-09-29）**：`PCAP_ROOT=/tmp/radius-probe MCP_API_KEY=dev-mcp-key CASE_PROTO=radius go test ./test/protocol_pcap/ -run TestProtocolPcapDrive -count=1` → `RESULT: 25 pass, 0 fail, 0 error (of 25)`；**14 个正例（`packet_count` 全覆盖）逐例与 pcap 帧数一致**（2/2/2/2/2/2/2/2/6/2/2/4/2/2）；8 个 task-time 负例 `.neg.pcap` **0 帧**；2 个 create-time 负例**不产文件**（隔离目录实测）。**落盘路径 = 隔离目录**（`/tmp/radius-probe/`、`/tmp/radius-probe2/`），`trafficgen/docs/protocol-pcap-test/` 下**零改动**。
4. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=radius` 全量不是增量）；门2④ 反查绿后进 P6。**本车道不跑门 2 脚本、不碰 `tools/**`**。

## 8. 存量审计（25 例逐条去向）

### 8.1 存量实测面（2026-09-29 机读）

`cases/radius.json` **25 例**：14 正例**全部带 `packet_count`**（2/2/2/2/2/2/2/2/6/2/2/4/2/2），**14/14 与今日实测 pcap 帧数逐例一致**；11 负例中 9 例 task-time（`.neg.pcap` 0 帧）、2 例 create-time（不产文件）；`spec_json` 顶层键仅 `{layers}` ×24 + `{layers,radius}` ×1；层形 `[ip,radius]` ×25；61 条 field 断言（value 55/nonzero 3/distinct_values 3）；`strategy_fc` ×2。

**机读复核行（脚本生成，不手算）**：
- 例数 = 25；正 = 14；负 = 11；`packet_count` 出现次数 = **14**（= 正例数，**零正例缺包数断言**）；
- 顶层键并集 = `{layers, radius}`；非负例顶层键计数 = **0**（`radius_flat_presence` 为负例）；
- `expect` 键并集 = `{fields, notes, packet_count, error_contains, expect_error}`；负例键分布 = 严格两键 ×9 + 含 `notes` ×2；
- field 断言总数 = **61**；`nonzero` ×3（均在 `radius_smoke_01` ×2 / `radius_auth_fixed` ×1 的 `radius.authenticator`）；`distinct_values` ×3（均在 `radius_port_dyn`）；
- `strategy_fc` 例 = `radius_flat_static_port`、`radius_port_dyn`（各 `{type:flows, value:2}`）。

### 8.2 现状矛盾点（诚实登记）

1. **`packet_count` 覆盖 14/14 正例**（机读实测，**无缺项**）；`expect` 键形状统一为 `{packet_count, fields, notes}`（14/14 正例）。**唯二形状偏差**是 2 个负例带 `notes`（见下条）。
2. **2 个负例带 `notes` 键**（`radius_neg_vsa_len`/`radius_neg_coa`），与严格两键口径不符 → G-RADIUS-9，代码阶段收窄。
3. **16/25 例带 `expect.notes` 文案**（14/14 正 + 2/11 负）：正例 `notes` 为说明性文案（不影响断言执行），负例 `notes` 见上条。
4. **陈旧负例产物**：`/tmp/mcp-pcaps/radius/radius_flat_static_port.neg.pcap`（186B/2 包，2026-09-19）与今日 create-time 语义不符（今日不产文件）→ G-RADIUS-10。
5. **结果文档 25/25 非本车道复跑产物**：`trafficgen/docs/protocol-pcap-test/radius.md` 末次提交 `dbe0765`（2026-09-19 23:42）**晚于**判死提交 `0417be5`（2026-09-13）→ **不构成过期产物**（与 pcep G-PCEP-11 / opcua G-OPCUA-10 相反）；但该数字仍是 2026-09-19 的，与本车道今日隔离复跑的两个数字**相互独立** → G-RADIUS-11。
6. **Authenticator 不含 RFC 合成**（G-RADIUS-1）：响应恒随机、请求缺省随机——断言只能 `nonzero`（1 格 fixed hex 例外）。
7. **Status-Server auto 码与 RFC 5997 不符**（G-RADIUS-13）：实现回 13，规范要求 2 或 5——#6 按实现钉，不声称合规。
8. **缺省属性集不按 Code 分列**（G-RADIUS-4）：code 3/11/12 复用 User-Name。
9. **报文 4096 上界未执法**（G-RADIUS-6）。
10. **VSA 单子属性**（G-RADIUS-12）：RFC 2865 §5.26 允许多个（MAY）。
11. **UDP 重传/超时未实现**（G-RADIUS-5）。
12. **NIC 输出路径本车道未跑**（G-RADIUS-14）；参考 pcap 不在本仓（G-RADIUS-15）。
13. **未覆盖项**：format 三态非法值、VSA 边界过侧与空值、rounds 0/回绕、srcport 缺省保底、异族混写、非法 IP 两分支、游离顶层键——**今日零用例**（A′ 补，§6.2）。

### 8.3 逐条去向表（25 行）

| 存量 id | T-编号 | 去向 | 改写动作（代码阶段） |
|---|---|---|---|
| `radius_smoke_01` | T1 | **保留** | 已合规（纯 layers）；可补 `srcport` 保底断言（G-RADIUS-8） |
| `radius_flat_presence` | T2 | **保留** | 判死负例（**非残留**，presence 形状执法对象）；create-time 语义已在 summary 说明 |
| `radius_flat_static_port` | T3 | **保留** | create-time 语义正确；**旧 `.neg.pcap` 产物须清理**（G-RADIUS-10） |
| `radius_acct_1813` | T4 | **保留** | 顺序修正执法格；可补 `avp.length="6,6"` 断言 |
| `radius_challenge` | T5 | **保留** | 端口交换钉方向（tshark 不打 11→11 标记） |
| `radius_status` | T6 | **改写** | G-RADIUS-13 裁定后重钉 `radius.code`（13→2 若改 auto 表） |
| `radius_code3` | T7 | **保留** | 可补 `packet_count`（当前缺）与端口交换断言 |
| `radius_reject` | T8 | **保留** | 标准对，`rsp=1` 已断言 |
| `radius_neg_no_auto` | T9 | **保留** | 锚词 `has no default response code` |
| `radius_neg_reqcode` | T10 | **保留** | 假码 42；与 T-25 真码 43 分格 |
| `radius_neg_rspcode` | T11 | **保留** | 锚词 `invalid response code` |
| `radius_auth_fixed` | T12 | **保留** | 唯一可钉值格；可补 `packet_count`（当前缺） |
| `radius_neg_auth_hex` | T13 | **保留** | 锚词 `invalid authenticator hex` |
| `radius_neg_auth_len` | T14 | **保留** | 锚词 `must be 16 bytes, got 15` |
| `radius_attr_formats` | T15 | **保留** | format 四态 + VSA；响应侧非空格 |
| `radius_neg_attr_len` | T16 | **保留** | 253 门（与 T-22 的 247 门分锚） |
| `radius_neg_format` | T17 | **保留** | 锚词 `unknown format` |
| `radius_rounds` | T18 | **保留** | 多事务执法格（id 5/6/7） |
| `radius_v6` | T19 | **保留** | 族对称格；可补 `ipv6.src` 断言 |
| `radius_default_port` | T20 | **保留** | 1812 缺省执法格；srcport 口径见 G-RADIUS-8 |
| `radius_port_dyn` | T21 | **保留** | 动态整格（端口 2 键 × inc）；`distinct_values` 双向聚合 |
| `radius_neg_vsa_len` | T22 | **改写** | **删 `notes` 键**（G-RADIUS-9） |
| `radius_attr_boundary` | T23 | **保留** | 253 边界过侧（avp.length=255） |
| `radius_nas_combo` | T24 | **保留** | 现网组合格；MA 只作字节承载（G-RADIUS-3） |
| `radius_neg_coa` | T25 | **改写** | **删 `notes` 键**（G-RADIUS-9）；CoA 支持另立条目（G-RADIUS-2） |

无"作废不注原因"：**0 作废**，25 例全部保留（23）或改写（2）。**本协议非负例顶层零残留**（24/24 非负例 `spec_json` 顶层仅 `layers`）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

`coverage_gate.py` **已有** `check_radius`（`:3627` 与 `:5948` 两处同名定义，后者覆盖前者；`COVERAGE_CHECKS["radius"]` 实测指向 `:10278` 的注册行）。**本车道不改该文件**，建议主线程合入后登记下列**增量**断言（每条均可从本契约与 cases JSON 直接机读，不需新造事实）：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['radius']) == 25` 且 ID 集合与顺序 = 本契约 §2 二十五项 | 本契约 §2 |
| 2 | 24/24 非负例 `spec_json` 顶层键 == `{layers}`（**零游离键**）；唯一含 `radius` 顶层键者为负例 | 本契约 §1；设计 §12.1 |
| 3 | 14 个正例 `packet_count` == `2 × rounds`（rounds 由 spec 推出，缺省 1） | 设计 §9 公式 |
| 4 | 11 负例 `expect` 键 ⊆ `{expect_error, error_contains}`（**今日 2 例含 `notes` → 红项如实标红**） | 本契约 §4；G-RADIUS-9 |
| 5 | 负例 `error_contains` ⊆ 代码锚词集 `{"top-level radius sub-config", "static four-tuple", "has no default response code", "invalid request code", "invalid response code", "invalid authenticator hex", "must be 16 bytes", "exceeds the 253-byte", "exceeds the 247-byte", "unknown format"}` | 设计 §7 |
| 6 | 层形 25/25 == `[ip,radius]`（无 tcp/udp 中间层） | 设计 §2 |
| 7 | `strategy_fc` 例 == 2（`radius_flat_static_port`/`radius_port_dyn`，各 `{type:flows,value:2}`） | 本契约 §1 |
| 8 | 动态 allowlist 收 `radius` 2 键（`src_port`/`dst_port`）且业务 7 键全关 | 设计 §12.12；`layer_dyn.go:70` |
| 9 | `registry` radius 行 Fields == 9 键（7 业务 + 2 端口） | 设计 §11.1；`registry.go:1870` |
| 10 | **create-time 2 例不得要求 `.neg.pcap` 存在**（今日 create-time 不产文件；旧 186B 产物是陈旧物） | 本契约 §4；G-RADIUS-10 |
| 11 | **反查不得把 `docs/protocol-pcap-test/radius.md` 的 25/25 当作"今日已复跑"证据**——该产物末次提交 `dbe0765`（2026-09-19 23:42）晚于判死提交 `0417be5`（2026-09-13）故**非过期产物**，但仍是旧数字；本车道今日复跑数字在 `/tmp/radius-probe/`（隔离目录） | 设计 §0 第 6 行；G-RADIUS-11 |

**另注意**：`coverage_gate.py` 现有 `check_radius` 的场景面清单是 **21 例**口径（T-RADIUS-1…21），而实际 cases 为 **25 例**——该清单是 P5 早期版本（T-22…25 补充批未登记）。本建议断言行 #1 以 **25 例全量**为准；**该差异属既有实现事实，本车道不改 `tools/**`**，如实登记为建议。

## 10. 修订记录

- v1.0.0（2026-09-29）：批次二文档轨 as-built 首版。**本协议此前无 `docs/protocol-designs/NN-radius-*.md`**，本 #109 为首份独立用例文档。内容：§1 形状基线机读（25 例 / 顶层键分布 / 层形 / 61 field 断言 / 14 正例 `packet_count` 全覆盖 / `2×rounds` 公式 / tshark `rsp`/`reqframe` 口径）；§2 25 ID 索引 + T-编号对照（含 JSON 顺序 ≠ T 编号顺序的声明）；§3 十四正例逐项断言契约（**全部实测值取自本车道 2026-09-29 隔离复跑**）；§4 负例契约（**双层执行期**：create-time 2 例不产文件 / task-time 9 例 0 帧 + 11 条锚词逐字 + 陈旧产物提醒）；§5 三源回指 + 对账两行（84 = 覆 55 + 不适用 17 + 立项 12，枚举面另按 Code 8/8、format 4/4、端口 3/3、地址族 2/2 单列）+ 门3 抽查候选（#24/#21/#18）；§6 P3 固定动作（§3.15 三项 = 已覆/显式不适用+理由/已覆；A′/B′ 两分类；3.14 豁免审计）；§7 执行建议 + 今日实测行；§8 存量审计（25 例逐条去向：**0 作废，23 保留 + 2 改写**）；§9 覆盖反查门建议 11 行（含**既有 `check_radius` 是 21 例口径而 cases 为 25 例**的事实登记）。**未动 JSON/代码/tools**。自审 3 轮，末轮干净（见 `/tmp/pipe/doc-lanes/radius.md`）。

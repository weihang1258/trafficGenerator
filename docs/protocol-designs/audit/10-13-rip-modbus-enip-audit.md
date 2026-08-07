# RIP / MODBUS / ENIP 设计文档对抗审计报告

**审计对象**：
- RIP 设计文档（`docs/protocol-designs/10-rip-design.md`，965 行，48 用例）
- MODBUS 设计文档（`docs/protocol-designs/13-modbus-design.md`，1188 行，50 用例）
- ENIP 设计文档（`docs/protocol-designs/12-enip-design.md`，1078 行，40 用例）

**审计依据**：
- RFC 2453 (RIP v2)、RFC 1058 (RIP v1)、RFC 2080 (RIPng)、RFC 4822 (RIP MD5)
- Modbus.org MB-ASYM-TCP（MODBUS TCP）
- ODVA EtherNet/IP Volume 1+2
- CLAUDE.md 测试策略 8 条规则
- `internal/protocol/socks5/socks5.go`（Planner 模式参考）

**审计人**：独立审计 agent（非设计者）
**审计日期**：2026-08-03

---

## 1. 审计概览

本次审计对三个 L7 协议设计文档做对抗式审查，按 CRITICAL / HIGH / MEDIUM / LOW 四级定级。CLAUDE.md "Code Modification & Review Policy" 与 "Testing Policy" 8 条规则是定级依据：

- **CRITICAL**：会导致 wire format 错误、Wireshark 解析失败、spec 直接被违反；或测试策略规则被整体违背（如 §3 单路径覆盖完全缺失、§5 断言不观测）。
- **HIGH**：会导致部分场景失败、字段语义错误、状态机分支不可达；或测试覆盖在关键路径上空缺。
- **MEDIUM**：默认值/边界处理不一致、文档自相矛盾、字段命名歧义、测试用例与 spec 章节脱节。
- **LOW**：可读性、命名、注释、冗余字段、次要场景未覆盖。

| 协议 | CRITICAL | HIGH | MEDIUM | LOW | 总计 |
|------|----------|------|--------|-----|------|
| RIP | 3 | 4 | 4 | 2 | 13 |
| MODBUS | 3 | 3 | 3 | 1 | 10 |
| ENIP | 3 | 4 | 4 | 2 | 13 |
| **合计** | **9** | **11** | **11** | **5** | **36** |

合计 36 个问题，远超要求的 18 个下限。下文分协议详述。

---

## 2. RIP 审计

### 2.1 CRITICAL/HIGH/MEDIUM/LOW 问题

#### R-CRIT-1：§6.1 报文示例 RIP 头 Command 字段写错，且修正后仍自相矛盾

**位置**：§6.1，第 387-388 行。

**问题**：原文写道：

> RIP 头：`02 02 00 00`（Command=2 Request, Version=2, Domain=0）
> 注：Request 全量路由的 Command 仍是 1（Request），上面 `02` 应为 `01`。修正：RIP 头 = `01 02 00 00`。

文档自身先写错（`02` 表示 Response 而非 Request），再用注释修正，但修正只在文字层面——同一处示例 entry `FF FF 00 00 ... 00 01` 紧随其后，读者无法判断到底应以哪份字节为准。RFC 2453 §3.9.1 明确：Request 全量路由时 Command=1（Request），且 AFI=0、metric=1，而非 AFI=0xFFFF。设计文档用 AFI=0xFFFF 表示"全量请求"，这与 RFC 不一致——RFC 2453 §3.9.1 规定全量请求是 AFI=0（不是 0xFFFF），metric=1，IP/Mask/NextHop 全 0。AFI=0xFFFF 是认证条目标识，不是全量请求标识。这是 wire-level 错误，会被 Wireshark 误判为认证条目。

**修复建议**：
- 删除自相矛盾的"先写错再修正"段落，直接写正确字节 `01 02 00 00`。
- 全量请求 entry 改为 AFI=0x0000、metric=1（而非 0xFFFF），与 RFC 2453 §3.9.1 一致。
- 若设计者刻意使用 AFI=0xFFFF 表示"全量请求"非标变体，需在 §2.2/§6.1 显式标注"非 RFC 行为"，并提供 pcap 参考。

#### R-CRIT-2：§6.1 字段说明中"AFI=0xFFFF" 与 §6.15 "AFI=0xFFFF + Routes 非空 互斥"冲突

**位置**：§6.1 第 388 行 vs §6.15 T-ERR-6 第 655 行。

**问题**：§6.1 称全量请求 entry 是 `AFI=0xFFFF, metric=1`，而 §6.15 T-ERR-6 称"AFI=0xFFFF + Routes 非空 → Validate 报错（全量请求 entry 与路由互斥）"。这里把 AFI=0xFFFF 当成了"全量请求"标识。但 RFC 2453 §3.9.1 的全量请求 entry 是 AFI=0（IPv4 family 但请求全部路由），不是 0xFFFF。AFI=0xFFFF 在 RFC 2453 §2.1.1 中专用于"认证条目"（Authentication Type），不可复用为全量请求标识。设计者把两个完全不同的语义混到了同一 AFI 值，导致：
- Validate 无法区分"全量请求 entry"与"认证条目"。
- §6.15 T-ERR-6 的"互斥"规则会误拒合法的"认证 + 单 entry 全量请求"。

**修复建议**：
- 全量请求 entry 改用 AFI=0x0000（RFC 标准行为）。
- §6.15 T-ERR-6 重写：AFI=0xFFFF 仅用于 Auth 字段触发的认证条目，不允许用户在 RIPRoute.AFI 显式设 0xFFFF。

#### R-CRIT-3：测试用例 T-POS-1 的断言"Payload 第 5-8 字节=FF FF 00 00"基于错误的 spec

**位置**：§7 测试用例表 T-POS-1（第 677 行）。

**问题**：T-POS-1 断言"Payload 第 5-8 字节=FF FF 00 00"。这正是 R-CRIT-1/R-CRIT-2 的错误 spec 在测试层的体现。按 RFC 2453 §3.9.1，全量请求 entry 应为 `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01`（AFI=0、metric=1）。如果按此修复，T-POS-1 必须同步更新；否则测试会通过但 wire format 仍错。这是 CLAUDE.md 测试策略 §1（spec 驱动）的典型违规——测试用例基于错误的 spec 派生，会"绿"但实际错误。

**修复建议**：T-POS-1 断言改为"Payload 第 5-6 字节=00 00（AFI=0），第 19-20 字节=00 01（metric=1）"。

#### R-HIGH-1：RIPng Route Entry 布局自相矛盾（§2.6 内部两份表）

**位置**：§2.6，第 78-94 行。

**问题**：第一份表（第 78-84 行）写：

| 偏移 16 | 长度 1 | Route Tag | 高字节 |
| 偏移 17 | 长度 1 | Prefix Length |
| 偏移 18 | 长度 1 | Metric |
| 偏移 19 | 长度 1 | (保留) |

按此布局 Route Tag 只占 1 字节（偏移 16），保留字节在偏移 19。但 RFC 2080 §2.1.1 明确 Route Tag 是 2 字节。第二份表（第 88-93 行）修正为"偏移 16 长度 2 Route Tag / 偏移 18 长度 1 Prefix Length / 偏移 19 长度 1 Metric"，与 RFC 2080 一致。但第一份错误的表仍在文档中，读者会以第一份为准。这是文档自相矛盾的典型，属于 CLAUDE.md 测试策略 §8（adversarial review of test quality）要求发现的级别。

**修复建议**：删除第一份错误表，仅保留第二份。或标注"第一份已废弃"。

#### R-HIGH-2：§6.6 称"SrcPort=520（响应方从 520 发出）"，但 §6.1 称"SrcPort=随机（52001）"

**位置**：§2.7 第 100 行、§6.1 第 391 行、§6.6 第 466 行。

**问题**：
- §2.7 称 RIP v2 SrcPort=520（响应）/ 任意（请求，临时端口）。
- §6.1 Request 全量路由场景称"SrcPort=随机（52001）"，与 §2.7 一致（请求用临时端口）。
- §6.6 Response 组播更新场景称"SrcPort=520（响应方从 520 发出，符合 RFC 2453 §3.9.2）"。

但 RFC 2453 §3.9.2 实际规定：RIP 响应（Response）的源端口必须是 520，请求（Request）的源端口可以是 520 或临时端口。设计文档对 Request 的描述与 RFC 一致，但对"多路由器场景"（§6.13）中每路由器用 `src_port: 52001/52002/52003` 作为唯一性标识——这些都是 Response 场景（command=response），按 RFC 应该用 520，但设计文档让它们用 52001/52002/52003。这违反 RFC 2453 §3.9.2。设计者需明确：多路由器场景是 Response 但用临时端口（非标），还是 Response 必须用 520（那多路由器无法用 src_port 区分，需用 src_ip）。

**修复建议**：
- 在 §6.13 明确：多路由器场景的 src_port 用临时端口（违反 RFC 但便于 trafficgen 区分 4-tuple），或用 src_ip 区分而 src_port 全用 520。
- 在 §2.7 增加"多路由器场景的 src_port 选择"说明。

#### R-HIGH-3：MD5 DigestOffset 计算示例（§6.8）可能错误

**位置**：§6.8 第 506 行。

**问题**：示例称"DigestOffset=4+1×20+1×20+16=60"。这里 4 是 RIP 头，第一个 20 是 MD5 认证条目本身，第二个 20 是 1 条真实路由，最后的 16 是 MD5 摘要长度。但 RFC 4822 §2.5 定义 Digest Offset 是"从报文起始到 MD5 摘要起始位置的字节偏移"。计算应为：4（RIP 头）+ 20（MD5 认证条目）+ 20（1 条路由）= 44，而非 60。把 16 也加进去等于把摘要自身长度算进了 offset，这指向了摘要末尾而非起始。这是 wire-level 错误，会被 Wireshark 标记为"Digest Offset incorrect"。

**修复建议**：DigestOffset=4+20+20=44（指向末尾摘要起始位置），不含摘要自身长度。修复 §6.8 示例与 §2.5 描述。

#### R-HIGH-4：§8.5 自承认"组播场景下 SplitHorizon 如何判断接收方 IP？答：组播无具体接收方，SplitHorizon 不生效（planner 跳过过滤）"，但 §3 Config 字段 SplitHorizon 与 Multicast 无互斥校验

**位置**：§3 RIPConfig 字段、§6.10、§8.5。

**问题**：§8.5 自承认组播下 SplitHorizon 不生效，但 §3 的 RIPConfig 没有声明 `SplitHorizon + Multicast=true` 的互斥校验，§6.15 异常表也无此行。用户配置 `{split_horizon: true, multicast: true}` 时，planner 静默跳过过滤，用户预期过滤生效但实际未生效——这是 silent-failure bug，属于 CLAUDE.md 测试策略 §2（cover failure paths）要覆盖的"broken mid-operation state"。

**修复建议**：在 §6.15 增加 `SplitHorizon=true + Multicast=true → Validate 警告`或 `→ Validate 报错`，并在 §3 字段注释显式声明互斥。

#### R-MED-1：§3 默认值规则表与 §6.15 T-ERR-2 冲突

**位置**：§3 第 240-254 行默认值表 vs §6.15 T-ERR-2。

**问题**：§3 默认值表称"Version 空字符串默认 v2"，§6.15 T-ERR-2 也称"Version='' 默认 v2"，但 T-ERR-2 编号在"负向用例"分类下（T-ERR-* 是负向）。空值默认化是正向行为，不是负向。该用例分类错误，会让实现者误以为"Version='' 应被拒绝"。

**修复建议**：把 T-ERR-2 移到 T-POS 系列，或重命名为 T-DEF-2（default）。

#### R-MED-2：§6.15 T-ERR-18 称"Routes 数 > 25 且 Auth 非 nil → Validate 报错"，但 §6.3/§5.2 称多包拆分合法

**位置**：§6.15 T-ERR-18 vs §6.3/§5.2。

**问题**：T-ERR-18 称"Routes 数 > 25 且 Auth 非 nil → Validate 报错（认证后最大 24 条/包，多包拆分仍合法，但首包 24）"。括号里的"多包拆分仍合法"与"Validate 报错"自相矛盾。若 26 条路由 + Auth，按 §5.4 拆为"首包 1 认证 + 24 路由，第 2 包 1 路由"，是合法的。但 T-ERR-18 表述为"报错"，会让实现者拒收合法配置。

**修复建议**：T-ERR-18 改为"Routes 数 > 25 且 Auth 非 nil → 合法（多包拆分），首包 entry 数 = 24，后续包无认证 entry"。或删除该行。

#### R-MED-3：§3 RIPRoute.AFI 字段允许用户设 0xFFFF，但语义不清

**位置**：§3 RIPRoute.AFI 第 178-180 行。

**问题**：注释称"0xFFFF 仅用于 Request 全量路由的特殊 entry，用户一般不显式设"。但根据 R-CRIT-2，AFI=0xFFFF 是认证条目标识，不是全量请求。这里再次混淆了 AFI 的语义。同时 §6.15 T-ERR-5 称"AFI=3（非 2/0xFFFF）→ Validate 报错"，意味着 AFI 只能是 2 或 0xFFFF——但 0xFFFF 由 Auth 字段控制，用户在 RIPRoute.AFI 显式设 0xFFFF 应被拒绝。

**修复建议**：RIPRoute.AFI 仅允许 0（自动）或 2（IPv4）；显式 0xFFFF → Validate 报错。

#### R-MED-4：§6.14 T-EDGE-22 称"Routers=100 → 100 路由器并发"，但 §6.13 GroupID 策略未明示

**位置**：§6.13 第 616 行、§6.14 T-EDGE-22。

**问题**：§6.13 称"3 条 FlowSpec 共享同一 GroupID（GroupIDStrategy=fixed），路由到同一 PacketWorker 保序；或用 GroupIDStrategy=inc 路由到不同 worker 并发"。但 §6.14 T-EDGE-22 称"100 路由器并发压力"未指明用哪种 GroupID 策略。若用 fixed（同 worker），100 路由器串行发包，"并发"不成立；若用 inc（不同 worker），100 路由器真并发。测试预期"无 panic"未断言实际并发度，属于 CLAUDE.md 测试策略 §6（concurrency tests must verify correctness）违规——只测无 race，不测并发度。

**修复建议**：T-EDGE-22 显式指定 GroupIDStrategy=inc，并增加断言"100 路由器总发包时间 ≤ 单路由器的 N 倍（N≥4）"。

#### R-LOW-1：§6.14 T-EDGE-22 与 §7 T-POS-17 重复

**位置**：§6.14 T-EDGE-22、§7 T-POS-17。

**问题**：两者都是"100 路由器并发"，断言要点几乎一致（无 panic、总包数）。冗余。

**修复建议**：合并为一条，或拆分为"压力（无 panic）"与"正确性（总包数）"两条独立用例。

#### R-LOW-2：§2.5 称 "Auth Data Len 通常 16"，但 §6.15 T-ERR-13 称"AuthDataLen=20 透传"

**位置**：§2.5 第 70 行、§6.15 T-ERR-13。

**问题**：§2.5 称 Auth Data Len 通常 16（RFC 4822 §2.5），但 T-ERR-13 称"AuthDataLen=20 透传（不强制 16，RFC 4822 §2.5 允许 Key ID 指定算法）"。RFC 4822 §2.5 实际规定 Auth Data Len 字段是"摘要字节数"，对 MD5 是 16，对其他算法（如 SHA-256）可以是其他值。设计文档允许 20 透传是合理的，但应在 §2.5 显式声明"非 MD5 算法可透传非 16 值"，否则实现者会以 §2.5 为准拒绝 20。

**修复建议**：§2.5 注释增加"AuthDataLen 默认 16（MD5），其他算法（如 SHA-256=20）允许透传"。

### 2.2 字段覆盖率（扩展表 21 字段）

按审计要求对照扩展表 21 字段（addrfamid/authtype/cmd/ipaddr/metric/nexthop/routag/submask/ver 等），RIP 设计文档覆盖情况：

| 扩展表字段 | RIPConfig 对应字段 | 覆盖 | 备注 |
|-----------|---------------------|------|------|
| addrfamid (AFI) | RIPRoute.AFI | 是 | 但语义混乱，见 R-CRIT-2、R-MED-3 |
| authtype | RIPAuth.Type | 是 | simple/md5 |
| cmd | RIPConfig.Command | 是 | request/response |
| ipaddr | RIPRoute.IPAddr | 是 | IPv4/IPv6 |
| metric | RIPRoute.Metric | 是 | 1-16 |
| nexthop | RIPRoute.NextHop | 是 | IPv4/IPv6 |
| routag | RIPRoute.RouteTag | 是 | 2 字节 |
| submask | RIPRoute.SubnetMask | 是 | v2 only |
| ver | RIPConfig.Version | 是 | v1/v2/ng |
| domain | RIPConfig.Domain | 是 | 2 字节 |
| prefixlen | RIPRoute.PrefixLen | 是 | RIPng only |
| keyid | RIPAuth.KeyID | 是 | md5 |
| authdata_len | RIPAuth.AuthDataLen | 是 | md5 |
| seqnum | RIPAuth.SequenceNumber | 是 | md5 |
| password | RIPAuth.Password | 是 | simple |
| scenario | RIPConfig.Scenario | 是 | 控制默认路由 |
| multicast | RIPConfig.Multicast | 是 | true/false |
| rounds | RIPConfig.Rounds | 是 | 周期更新 |
| routers | RIPConfig.Routers | 是 | 多路由器 |
| triggered_update | RIPConfig.TriggeredUpdate | 是 | 触发更新 |
| split_horizon / poison_reverse | RIPConfig.SplitHorizon / PoisonReverse | 是 | 但组播下不生效，见 R-HIGH-4 |

扩展表 21 字段全部覆盖。但 AFI 语义、SplitHorizon 互斥校验缺失（R-CRIT-2、R-HIGH-4）影响字段正确性。

### 2.3 测试用例质量

**总评**：48 条用例（正向 28 + 边界 9 + 负向 15，去重后 48）。覆盖广度合格，但深度有以下缺陷：

1. **CLAUDE.md §1（spec 驱动）违规**：T-POS-1 基于错误的 spec（AFI=0xFFFF 全量请求），见 R-CRIT-3。
2. **CLAUDE.md §2（负向覆盖）基本合格**：15 条负向覆盖 §6.15 大部分异常行，但缺少 `SplitHorizon + Multicast` 互斥、`AFI=0xFFFF 用户显式设` 等。
3. **CLAUDE.md §3（单路径单测）合格**：每个 Scenario 至少 1 条用例。
4. **CLAUDE.md §4（集成测试）合格**：T-POS-26/27/28 覆盖多包/认证/多路由器集成。
5. **CLAUDE.md §5（断言可观测量）基本合格**：每条用例断言字节级 payload，但 T-EDGE-22/T-POS-17 只断言"无 panic"，未断言并发度（R-MED-4）。
6. **CLAUDE.md §6（并发验证）部分违规**：T-POS-28 断言总发包数 = M × ⌈Routes/25⌉ × Rounds，但未断言实际并发度（如总时间）。
7. **CLAUDE.md §7（failing-test-first）合规**：§7.7 明确"实现期若发现拆包错误，先写 T-POS-3 失败版本再修"。
8. **CLAUDE.md §8（adversarial review of test quality）合规度低**：本文档审计即是对设计文档的对抗审查，但设计者自身未在 §8 清单中标记任何已知问题。

**测试质量评分**：7/10。

---

## 3. MODBUS 审计

### 3.1 CRITICAL/HIGH/MEDIUM/LOW 问题

#### M-CRIT-1：附录 A.1 Length 字段计算错误（"00 07"被指错误，"修正"后仍是 23=0x17，但注释混乱）

**位置**：附录 A.1，第 1119-1133 行。

**问题**：原文写道：

```
00 07  -- Length = 7 (Unit ID + FC + byte count + 10 registers = 1+1+1+20)

注：Length = 7 不对，正确是 1+1+1+20 = 23 = 0x17。修正：
00 00
00 00
00 17  -- Length = 23
```

设计者先写错（7），再用"注：Length = 7 不对"修正为 23。这种"先写错再修正"的写法在文档中存在（RIP §6.1 也有类似问题）。读者极易混淆哪份字节是正确的。此外，"Length = 7 (Unit ID + FC + byte count + 10 registers = 1+1+1+20)" 这条注释本身就是 1+1+1+20=23 的算式，却得出 7 的结论——算式与结论矛盾。这是 CLAUDE.md 测试策略 §5（assert observable outcomes）的典型违规——示例本身不一致，实现者会以哪份为准无法确定。

**修复建议**：删除"先写错再修正"段落，直接写正确字节序列 `00 00 00 00 00 17 01 03 14 ...`。

#### M-CRIT-2：§2.3.1 称"读线圈响应 byte count = ⌈Quantity/8⌉"，但 §6.1.2 示例"quantity=10 → byte count=2" 与之矛盾，且 §7 T02 断言未明确位数

**位置**：§2.3.1 第 88 行、§6.1.2 第 591 行、§7 T02。

**问题**：
- §2.3.1 称 byte count = ⌈Quantity/8⌉。
- §6.1.2 quantity=10 → byte count=2。⌈10/8⌉=2，正确。
- 但 §6.1.2 称"位打包 LSB 优先，bit0 = starting_address+0 的线圈"，第二字节高位补 0。这意味着 10 位数据占 2 字节，但只有 bit0-9 有效，bit10-15 补 0。
- §7 T02 断言"响应 byte count=2"，但未断言"位数据 = 03 00"（即 bit0-7=0x03, bit8-9=0x01）。T02 仅断言 byte count，未断言位数据本身——这是 CLAUDE.md 测试策略 §5（assert observable outcomes, not just structure）违规：byte count 是结构，位数据才是可观测量。

**修复建议**：T02 增加"位数据第 1 字节 = 0x03，第 2 字节 = 0x01"断言（按 §6.1.2 示例）。或显式说明 T02 仅验证 byte count，位数据由 T03 验证。

#### M-CRIT-3：§7 T05 响应 PDU `03 02 12 34`，但 §7 T01 响应 PDU `01 01 01 00`——T01 的 byte count 后跟 1 字节数据，但 quantity=1 应只占 1 位（bit0），高 7 位补 0，即 0x00 或 0x01

**位置**：§7 T01、T05。

**问题**：
- T01（FC=0x01 读单线圈，quantity=1）：响应 PDU `01 01 01 00`。byte count=1，位数据=0x00。但 quantity=1 意味着只有 bit0 有效，bit0=0 表示线圈 OFF。若用户期望 ON，应返回 0x01。设计文档未在 T01 声明"线圈值"，直接用 0x00——这是合理的（默认 OFF），但未显式说明。
- T05（FC=0x03 读单寄存器，quantity=1）：响应 PDU `03 02 12 34`。byte count=2，寄存器值=0x1234。这是 1 个 16 位寄存器，合理。
- 但 T01 与 T05 都未在 Config 中声明"响应值"——T05 的 0x1234 从哪来？设计文档 §3.2 ModbusTransaction.ResponseValues 字段称"non-nil 时覆盖 auto-derived"，但 T05 未声明 ResponseValues，按 §3.4 默认值规则，"读寄存器响应 auto-derived = zeros of correct length"。0x1234 不是 zeros，与默认规则矛盾。

**修复建议**：T05 显式声明 `ResponseValues=[0x12, 0x34]`，或修改默认规则为"读寄存器响应默认 = 0x0000（zeros）"，T05 改为 `03 02 00 00`。

#### M-HIGH-1：§3.2 ModbusTransaction.Direction 字段语义不清

**位置**：§3.2 第 443-447 行。

**问题**：Direction 字段注释称"informational only — the planner always emits request up then response down"。但 §3.4 默认值规则表称"Direction = up（请求）/ down（响应），由 planner 强制"。两者矛盾：前者说"informational only"，后者说"planner 强制"。若 Direction 是 informational，用户设 `direction: "down"` 不应影响 planner 行为；但若 planner 强制按 Direction 决定方向，用户设错会导致请求被当成响应。这是字段语义不清，会导致实现者对 Direction 处理不一致。

**修复建议**：删除 Direction 字段（planner 始终按 request→response 顺序），或显式声明"Direction 字段已废弃，保留仅为向后兼容"。

#### M-HIGH-2：§6.5.3 称"WriteValue=0x1234 → Validate 拒绝"，但 §6.10.3 称"Quantity=0 + ExceptionCode=0x03 → 响应 83 03"——两者对"非法值"处理不一致

**位置**：§6.5.3、§6.10.3、§3.2 ExceptionCode 字段。

**问题**：
- §6.5.3：用户设 `WriteValue=0x1234`（FC=0x05 写单线圈，非法值）→ Validate 拒绝。设计选择"Validate 拒绝，仅 ResponseValues 可注入任意字节"。
- §6.10.3：用户设 `Quantity=0 + ExceptionCode=0x03` → 响应 `83 03`。即"非法 quantity"通过 ExceptionCode 触发异常响应，不通过 Validate 拒绝。

这两种"非法值"处理策略不一致：
- WriteValue 非法 → Validate 拒绝（不能生成异常响应）。
- Quantity 非法 → Validate 拒绝（必须用 ExceptionCode）。
- 但 §6.5.3 又说"用户设 ExceptionCode=0x03 可触发异常响应"——那么 WriteValue=0x1234 + ExceptionCode=0x03 是否合法？设计未明示。

§3.2 ExceptionCode 字段注释称"non-zero 时 planner emits exception response instead of normal response"，意味着任何 FC + ExceptionCode 都可触发异常响应，包括 FC=0x05 + WriteValue=0x1234 + ExceptionCode=0x03。但 §6.5.3 又说"Validate 拒绝 0x1234"，那么 0x1234 + ExceptionCode=0x03 是否被拒？设计未明示。

**修复建议**：统一规则：Validate 拒绝"语义非法值"（如 WriteValue=0x1234），但允许"通过 ExceptionCode 触发异常响应"的路径独立工作。即：
- WriteValue=0x1234 + ExceptionCode=0 → Validate 拒绝。
- WriteValue=0x1234 + ExceptionCode=0x03 → 合法（请求 PDU 仍含 0x1234，响应是异常）。
- Quantity=0 + ExceptionCode=0 → Validate 拒绝。
- Quantity=0 + ExceptionCode=0x03 → 合法。

#### M-HIGH-3：§3.2 称"Transaction ID 自增：第 N 个事务 = N-1（0 起步，回绕到 0）"，但 §6.11.3 称"65536 事务：Transaction ID 从 0 自增到 65535 后回绕到 0"

**位置**：§3.2 第 467 行、§6.11.3、§6.13.8。

**问题**：
- §3.2 默认值规则：第 N 个事务 = N-1。即第 1 个事务 TID=0，第 2 个 TID=1，... 第 65536 个 TID=65535。
- §6.13.8：65536 事务时第 65536 个事务 TID=0。这意味着第 65536 个事务 = (65536-1) mod 65536 = 65535，但 §6.13.8 说 TID=0。
- §6.11.3：65537 事务时第 65537 个 TID=1。即第 65537 个 = (65537-1) mod 65536 = 0，但 §6.11.3 说 TID=1。

§3.2 与 §6.13.8/§6.11.3 矛盾。若按 §3.2 (N-1) mod 65536，则：
- 第 65536 个 TID = 65535。
- 第 65537 个 TID = 0。
- 第 65538 个 TID = 1。

若按 §6.13.8/§6.11.3：
- 第 65536 个 TID = 0。
- 第 65537 个 TID = 1。

两者差 1。这是 off-by-one 错误，会导致 Transaction ID 关联请求/响应时错位，Wireshark 会将"事务 65536 的请求"与"事务 65535 的响应"误关联。

**修复建议**：统一为 (N-1) mod 65536，即第 65536 个 TID=65535，第 65537 个 TID=0。修正 §6.13.8/§6.11.3。

#### M-MED-1：§7 T31 称"65537 事务：第 65536 个 TID=0, 第 65537 个 TID=1"，与 M-HIGH-3 同源

**位置**：§7 T31。

**问题**：T31 基于 §6.13.8 的错误 spec，断言"第 65536 个 TID=0"。若按 M-HIGH-3 修复，T31 应改为"第 65536 个 TID=65535，第 65537 个 TID=0"。这是 spec 错误向测试层的传播。

**修复建议**：T31 同步修复。

#### M-MED-2：§3.2 SubFunction 字段同时用于 FC=0x08 和 FC=0x2B，但默认值不同

**位置**：§3.2 SubFunction 第 423-426 行。

**问题**：SubFunction 注释称"FC 0x08 (diagnostics) sub-function 0x0000-0x0018, and FC 0x2B MEI Type (0x0D/0x0E)。Empty defaults to 0x0000 (Return Query Data for FC 0x08)"。但 FC=0x2B 的 MEI Type 默认值未声明。若用户设 FC=0x2B 但 SubFunction=0，planner 应默认 MEI Type=0x0D（Read Device Identification）还是报错？设计未明示。

**修复建议**：明确 FC=0x2B 时 SubFunction 必须 ≥ 0x0D，否则 Validate 报错。

#### M-MED-3：§6.7.2 位打包示例 `0F 0000 000A 02 03 01` 含义不清

**位置**：§6.7.2 第 660 行。

**问题**：示例称"byte count=2, value=0x0103"，注释"bit0-7 = 0x03（前 8 位），bit8-9 = 0x01（后 2 位，高位补 0）"。但 `03 01` 是按"低字节先、高字节后"的位打包，即第一字节 0x03 = bit0-7，第二字节 0x01 = bit8-15（其中 bit8-9=01，bit10-15=0）。这是 LSB-first 的正确解释。但 §2.3.1 第 89 行称"位打包，LSB 优先，最后字节高位补 0"——LSB 优先指"位"优先级，不是"字节"优先级。设计文档未显式说明"字节序 = little-endian（低字节先）"，会让实现者误以为 big-endian（高字节先，即 `01 03`）。

**修复建议**：§2.3.1 显式声明"位数据字节序 = little-endian（低地址字节先），字节内位序 = LSB-first"。

#### M-LOW-1：§7 T17 称"多会话 2 master"，但 T33 也称"多 master 8x5"

**位置**：§7 T17、T33。

**问题**：T17 是 2 master，T33 是 8 master × 5 事务。两者覆盖度重叠，T17 是 T33 的子集。冗余。

**修复建议**：T17 改为"多 master 2x1（最小并发）"，T33 保持"多 master 8x5（压力）"，明确分工。

### 3.2 字段覆盖率（扩展表 25 字段）

按审计要求对照扩展表 25 字段（protoid/len/func/excp/transid/unitid/regcount/vendor/product/firmwarev/softwarev 等），MODBUS 设计文档覆盖情况：

| 扩展表字段 | ModbusConfig 对应字段 | 覆盖 | 备注 |
|-----------|------------------------|------|------|
| protoid (Protocol ID) | （固定 0x0000） | 是 | §2.1 注释 |
| len (Length) | （ planner 自动计算） | 是 | §2.1 |
| func (Function Code) | ModbusTransaction.FunctionCode | 是 | 0x01-0x2B |
| excp (Exception Code) | ModbusTransaction.ExceptionCode | 是 | 0x01-0x0B |
| transid (Transaction ID) | （planner 自动分配） | 是 | §3.4 默认值 |
| unitid (Unit ID) | ModbusConfig.UnitID | 是 | 0-247 |
| regcount (Quantity) | ModbusTransaction.Quantity | 是 | 1-2000 |
| vendor | （不支持） | 否 | MODBUS 无 vendor 字段 |
| product | （不支持） | 否 | MODBUS 无 product 字段 |
| firmwarev | （不支持） | 否 | MODBUS 无 firmware 字段 |
| softwarev | （不支持） | 否 | MODBUS 无 software 字段 |
| starting_address | ModbusTransaction.StartingAddress | 是 | 0x0000-0xFFFF |
| write_value | ModbusTransaction.WriteValue | 是 | FC=0x05/0x06 |
| values | ModbusTransaction.Values | 是 | FC=0x0F/0x10 |
| mask_and / mask_or | ModbusTransaction.MaskAND/MaskOR | 是 | FC=0x16 |
| read_address / write_address | ModbusTransaction.ReadAddress/WriteAddress | 是 | FC=0x17 |
| read_quantity / write_quantity | ModbusTransaction.ReadQuantity/WriteQuantity | 是 | FC=0x17 |
| sub_function | ModbusTransaction.SubFunction | 是 | FC=0x08/0x2B |
| response_values | ModbusTransaction.ResponseValues | 是 | 响应覆盖 |
| suppress_broadcast | ModbusConfig.SuppressBroadcast | 是 | Unit ID=0 |
| direction | ModbusTransaction.Direction | 是 | 但语义不清，见 M-HIGH-1 |

**注**：vendor/product/firmwarev/softwarev 4 个字段在 MODBUS 协议本身不存在（这些是 ENIP 的字段），扩展表 25 字段中有 4 个不适用于 MODBUS。设计文档应显式声明"MODBUS 不支持这 4 个字段"。当前文档未声明。

扩展表 25 字段中 21 个适用字段全部覆盖。但 Direction 字段语义不清（M-HIGH-1）、Transaction ID 自增规则矛盾（M-HIGH-3）影响字段正确性。

### 3.3 测试用例质量

**总评**：50 条用例（正向 17 + 异常 8 + 边界 10 + 负向 8 + 集成 4 + wire 3）。覆盖广度合格，但深度有以下缺陷：

1. **CLAUDE.md §1（spec 驱动）违规**：T05 默认响应值 0x1234 与默认值规则矛盾（M-CRIT-3）。
2. **CLAUDE.md §2（负向覆盖）合格**：8 条负向覆盖 §6.14 异常场景。
3. **CLAUDE.md §3（单路径单测）部分违规**：FC=0x07/0x08/0x11/0x14/0x15/0x16/0x18/0x2B 共 8 个 FC 无单测（仅在 §2 描述，未在 §7 出现）。
4. **CLAUDE.md §4（集成测试）合格**：T44-T47 覆盖 e2e。
5. **CLAUDE.md §5（断言可观测量）部分违规**：T02 仅断言 byte count，未断言位数据（M-CRIT-2）。
6. **CLAUDE.md §6（并发验证）缺失**：T33 断言"8 条流互不干扰"，但未断言"8 条流总发包时间 ≤ 单流的 N 倍"。
7. **CLAUDE.md §7（failing-test-first）未明示**：§7 无 failing-test-first 段落。
8. **CLAUDE.md §8（adversarial review of test quality）合规度中**：§8.5 列出测试质量清单，但未对每个用例做对抗审查。

**测试质量评分**：6/10。

---

## 4. ENIP 审计

### 4.1 CRITICAL/HIGH/MEDIUM/LOW 问题

#### E-CRIT-1：§3.3 ENIPCommand.SessionHandle 字段类型为 `*StrategyConfig`，但 §3.6 FlowSpec 挂载点未声明 StrategyConfig 类型

**位置**：§3.3 第 285 行、§3.6 第 392 行。

**问题**：ENIPCommand.SessionHandle 字段类型是 `*StrategyConfig`，SenderContext 也是 `*StrategyConfig`。但 §3.6 FlowSpec 挂载点仅声明 `ENIP *ENIPConfig`，未引入 StrategyConfig 类型。设计文档假定读者已知 StrategyConfig（从其他协议继承），但 ENIP 是首个使用 `*StrategyConfig` 引用响应值的协议——`{"strategy":"from_response","field":"session_handle","source_command_index":5}`。这种"跨命令引用响应值"机制是新引入的，但设计文档未在 §3 中定义该机制的语义、生命周期、错误处理（如引用未执行的命令）。这是 spec 级缺失，会导致实现者自行解释机制，行为不一致。

**修复建议**：新增 §3.7 "StrategyConfig 跨命令引用"小节，定义：
- `from_response` 策略：从指定命令的响应 payload 中提取字段。
- `source_command_index`：命令在 Commands[] 中的索引。
- `field`：要提取的字段（session_handle / connection_id / ...）。
- 错误处理：引用未执行的命令 → Validate 报错；响应字段缺失 → Plan 报错。

#### E-CRIT-2：§3.5 ENIPIOData.Direction 默认 "up"，但 §5.2 UDP SubFlow 只显示 "up" 方向帧

**位置**：§3.5 第 374-376 行、§5.2 第 493-500 行。

**问题**：ENIPIOData.Direction 默认 "up"（producer→consumer）。但 §5.2 的 UDP SubFlow 示例只显示 "up" 方向帧（producer 发送给 consumer）。然而真实 ENIP I/O 是双向的：Class 1 Connection 中，O→T（originator→target）和 T→O（target→originator）是两条独立的 UDP 流，各自有自己的 ConnectionID。设计文档的 ENIPIOData 只配置单方向，无法表达双向 I/O。这是 spec 级缺失——多设备场景（§6.16）中"设备 1 的 I/O → 设备 2 的 I/O"假设是单向，但真实工业网络是双向。

**修复建议**：ENIPIOData 增加 `ReverseDirection *ENIPIOData` 字段，或拆分为 `O2T_IOData` 和 `T2O_IOData` 两个字段，分别配置两个方向的 I/O 流。

#### E-CRIT-3：§3.3 ENIPCommand.CIPData 是 string 类型，但 §6.13 Multiple_Service_Packet 称"cip_data=<编码后的多服务请求>"

**位置**：§3.3 第 324 行、§6.13 第 699 行。

**问题**：CIPData 字段是 `string`，注释称"hex or raw string"。但 §6.13 Multiple_Service_Packet 的 `cip_data` 是"编码后的多服务请求"——这是结构化数据（OffsetCount + [Offset + ServiceRequest]），不是简单的 hex 字符串。用户需要手动编码二进制为 hex 字符串传入，但设计文档未提供编码辅助函数或示例。同样，§6.14 Get_Attribute_List 的 `cip_data` 是 `"\x03\x00\x04\x00\x05\x00"`（属性 3, 4, 5），但用户如何知道"AttributeCount(2) + [AttributeID(2)]"的格式？设计文档假定用户熟悉 CIP 二进制编码，但未提供编码辅助。这是 spec 级缺失，会导致用户配置错误。

**修复建议**：
- 增加 §3.7 "CIP 数据编码辅助"小节，提供 `EncodeCIPPath(class, instance, attr)` 等辅助函数。
- 或将 CIPData 改为结构化字段（如 `CIPAttributes []uint16`），由 planner 自动编码。

#### E-HIGH-1：§3.2 ENIPConfig.Path 是 hex string（如 "2001042401"），但 §3.3 ENIPCommand.Path 也是 hex string，两者关系未明示

**位置**：§3.2 第 256-258 行、§3.3 第 327-329 行。

**问题**：
- ENIPConfig.Path：会话级默认 CIP 路径。
- ENIPCommand.Path：单命令级 CIP 路径，"overrides session-level Path"。

但两者都是 hex string，编码格式未定义。"2001042401" 是 5 字节 = 10 hex 字符，注释称"Class 0x04, Instance 0x01"。但 CIP 路径编码规则（如 0x20 = class segment, 0x04 = class ID, 0x24 = instance segment, 0x01 = instance ID）未在设计文档中解释。用户不熟悉 CIP 路径编码会写错。此外，ENIPCommand.Path "overrides" 会话级 Path，但 Forward_Open 必须用会话级 Path（连接路径），Get/Set 用命令级 Path（对象路径）——两者语义不同，不应简单 override。

**修复建议**：
- 新增 §2.7 "CIP 路径编码"小节，解释 0x20/0x24/0x30 segment 类型。
- 区分会话级 ConnectionPath 与命令级 ObjectPath，分别用不同字段。

#### E-HIGH-2：§3.5 ENIPIOData.TransportType 默认 0x01（Class 0），但 §2.6 称 0x01/0x02 是 "Class 0 / Class 1 (Server Transport)"

**位置**：§3.5 第 383-385 行、§2.6 第 145-149 行。

**问题**：
- §2.6：Transport_Type 0x01/0x02 = Class 0/Class 1 (Server Transport)；0x82/0x83 = Class 0/Class 1 (Client Transport)；0x03 = Class 3。
- §3.5：TransportType 默认 0x01，注释"0x01 = Class 0, 0x03 = Class 3"。

但 §2.6 的 0x01 是 "Class 0/Class 1 (Server Transport)"，不是单纯的 "Class 0"。0x01 vs 0x02 区分 Class 0 vs Class 1，0x01 vs 0x81 区分 Server vs Client transport（bit 7）。§3.5 注释过于简化，丢失了 bit 7（方向）与 bit 0-1（Class 0/1）的位字段语义。用户设 TransportType=0x01 表示"Server Class 0"，但若用户期望"Client Class 0"应设 0x81——设计文档未说明。

**修复建议**：§3.5 TransportType 注释改为"0x01=Class 0 Server, 0x02=Class 1 Server, 0x81=Class 0 Client, 0x82=Class 1 Client, 0x03=Class 3"，与 §2.6 一致。

#### E-HIGH-3：§5.2 称 UDP SubFlow 使用 `<parent_flow_id>:io` 命名，但 §6.16 多设备场景未说明 SubFlow 命名

**位置**：§5.2 第 502 行、§6.16 第 744 行。

**问题**：§5.2 称 UDP SubFlow FlowID = `<parent_flow_id>:io`。但 §6.16 多设备场景有 N 个设备，每个设备有自己的 TCP FlowSpec，每个 TCP FlowSpec 又有自己的 UDP SubFlow。命名应为 `<parent_flow_id>:io`，但 parent_flow_id 在多设备下是 `device_0`/`device_1`/...，所以 SubFlow 是 `device_0:io`/`device_1:io`。设计文档未显式说明多设备下 SubFlow 命名规则，会让实现者自行解释。

**修复建议**：§6.16 显式说明"多设备下 SubFlow FlowID = `<device_flow_id>:io`，如 `device_0:io`"。

#### E-HIGH-4：§4.1 状态机图中 "OPENED" 状态下 "I/O 数据包（TCP/UDP）" 不改变状态，但 §4.2 状态迁移规则表无"OPENED → OPENED (I/O)" 行

**位置**：§4.1 第 427-428 行、§4.2 第 449-461 行。

**问题**：§4.1 状态机图称"OPENED 状态下 I/O 数据包不改变状态"。但 §4.2 状态迁移规则表只有"OPENED | Forward_Close 完成 | CLOSED_CIP"行，没有"OPENED | I/O 数据包 | OPENED"行。这是状态机图与迁移规则表不一致，属于 spec 内部矛盾。

**修复建议**：§4.2 增加"OPENED | I/O 数据包（TCP/UDP） | OPENED | 不改变状态"行。

#### E-MED-1：§3.2 ENIPConfig.ConnectionTimeout 默认 10s，但 §6.9 Forward_Open 称"Timeout=0"是边界场景

**位置**：§3.2 第 226-228 行、§6.9 第 641 行。

**问题**：§3.2 ConnectionTimeout 默认 10s（0 时默认 10s）。但 §6.9 边界场景称"RPI=0（零间隔），Timeout=0"——这里 Timeout=0 是边界值，与 §3.2 的"0 时默认 10s"矛盾。若 0 默认 10s，则 Timeout=0 永远不会发生（被默认化）。若 0 是合法边界值（零超时），则 §3.2 默认规则错误。

**修复建议**：明确 ConnectionTimeout=0 的语义：
- 选项 A：0 = 默认 10s（§3.2 当前规则），删除 §6.9 的 "Timeout=0" 边界。
- 选项 B：0 = 零超时（合法边界），§3.2 默认改为"0 = 零超时，非零 = 显式超时"。

#### E-MED-2：§3.3 ENIPCommand.Command 默认 0 时"auto-derived from CIP service context if CIPService is set"，但 auto-derivation 规则未定义

**位置**：§3.3 第 278-280 行。

**问题**：Command=0 时若 CIPService 非 0，Command 自动推导。但推导规则未定义。例如：
- CIPService=0x10 (Forward_Open) → Command=0x006F (SendRRData)？
- CIPService=0x01 (Get_Attributes_All) → Command=0x006F (SendRRData)？
- CIPService=0x0E (Multiple_Service_Packet) → Command=0x006F？

设计文档未说明哪些 CIPService 推导出哪些 Command。若所有 CIPService 都推导为 SendRRData，那么 SendUnitData (0x0070) 如何触发？只能通过 IOData 触发？这限制了显式 SendUnitData 的使用。

**修复建议**：§3.3 增加 auto-derivation 规则表：
- CIPService 0x01-0x09, 0x0E, 0x10, 0x11, 0x54, 0x55 → Command=0x006F (SendRRData)。
- 显式 SendUnitData (0x0070) 必须用户设 Command=0x0070，不通过 CIPService 推导。

#### E-MED-3：§3.4 CPFItem 同时有 Data 和 Payload 字段，但关系不清

**位置**：§3.4 第 336-346 行。

**问题**：CPFItem 有两个 payload 字段：
- Data：hex-encoded or raw payload bytes。
- Payload：raw string payload (alternative to hex Data)。

注释称"Payload = alternative to hex Data"，但两者同时存在时哪个优先？Data 是 hex string，Payload 是 raw string——编码方式不同。用户设 `Data="1234"`（hex，2 字节）vs `Payload="1234"`（raw，4 字节 '1','2','3','4'）——结果不同。设计未说明优先级、互斥校验。

**修复建议**：
- 删除 Payload 字段（保留 Data 既能 hex 也能 raw，通过前缀如 `0x` 区分）。
- 或显式声明"Data 与 Payload 互斥，同时非空 → Validate 报错"。

#### E-MED-4：§6.17 B10 称"FrameSize=65535 → 超大 I/O 帧，UDP 层 IP 分片"，但 UDP payload 65535 + ENIP 头 24 + CPF 包络 6 = 65565 字节，超过 IP 最大长度 65535

**位置**：§6.17 B10 第 759 行。

**问题**：FrameSize=65535 意味着 I/O data payload 65535 字节。ENIP 头 24 + CPF ItemCount 2 + Connected Address Item 6 + Connected Data Item 头 4 + payload 65535 = 65571 字节。UDP 头 8 + 65571 = 65579 字节。IP 头 20 + 65579 = 65599 字节，超过 IP 最大总长 65535。这是物理不可能的边界值。设计文档称"UDP 层 IP 分片"——但 IP 分片也不能超过 65535 总长。该边界值非法，应被 Validate 拒绝。

**修复建议**：§6.17 B10 改为"FrameSize 上限 = 65535 - 24 - 6 - 4 - 8 = 65493 字节"，超过 → Validate 报错。

#### E-LOW-1：§7.1 V10 称"DeviceType=65535 → 无报错（允许）；或报 warning"

**位置**：§7.1 V10 第 800 行。

**问题**：V10 测试预期"无报错（允许）；或报 warning"——这种"或"表述让实现者无法判断应否报错。测试用例必须有明确预期。

**修复建议**：V10 改为"DeviceType=65535 → 无报错（允许任意 uint16 值）"。

#### E-LOW-2：§6.4 称"重复 RegisterSession 导致旧会话被覆盖"，但 §4 状态机未体现该行为

**位置**：§6.4 第 575 行、§4 状态机。

**问题**：§6.4 异常说"重复 RegisterSession 导致旧会话被覆盖"，但 §4 状态机只有"DISCOVERED → RegisterSession → REGISTERED"，没有"REGISTERED → RegisterSession → REGISTERED (新 SessionHandle)"迁移。状态机缺失该异常路径。

**修复建议**：§4.2 增加"REGISTERED | RegisterSession（重复）| REGISTERED | 旧 SessionHandle 失效，分配新 SessionHandle"行。

### 4.2 字段覆盖率（扩展表 24 字段）

按审计要求对照扩展表 24 字段（enipcmd/enipl/enips/enipsta/enipcon/enipip/enipport/enipvendor/eniptype/enipname/enipsn/enipfver 等），ENIP 设计文档覆盖情况：

| 扩展表字段 | ENIPConfig 对应字段 | 覆盖 | 备注 |
|-----------|------------------------|------|------|
| enipcmd (Command) | ENIPCommand.Command | 是 | §2.2 命令表 |
| enipl (Length) | （planner 自动计算） | 是 | §2.1 |
| enips (SessionHandle) | ENIPCommand.SessionHandle | 是 | *StrategyConfig |
| enipsta (Status) | ENIPCommand.Status | 是 | §2.3 错误码 |
| enipcon (SenderContext) | ENIPCommand.SenderContext | 是 | *StrategyConfig |
| enipip (Options) | ENIPCommand.Options | 是 | 通常 0 |
| enipport | （FlowSpec.DstPort） | 是 | 默认 44818 |
| enipvendor (VendorID) | ENIPConfig.VendorID | 是 | §3.2 |
| eniptype (DeviceType) | ENIPConfig.DeviceType | 是 | §3.2 |
| enipname (ProductName) | ENIPConfig.ProductName | 是 | §3.2 |
| enipsn (SerialNumber) | ENIPConfig.SerialNumber | 是 | §3.2 |
| enipfver (FirmwareRevision) | ENIPConfig.FirmwareRevision | 是 | §3.2 |
| product_code | ENIPConfig.ProductCode | 是 | §3.2 |
| scenario | ENIPConfig.Scenario | 是 | full/explicit_only/io_only/discovery |
| commands | ENIPConfig.Commands | 是 | §3.3 |
| cpf_items | ENIPCommand.CPFItems | 是 | §3.4 |
| cip_service | ENIPCommand.CIPService | 是 | §2.5 |
| cip_class_id | ENIPCommand.CIPClassID | 是 | §3.3 |
| cip_instance_id | ENIPCommand.CIPInstanceID | 是 | §3.3 |
| cip_attribute_id | ENIPCommand.CIPAttributeID | 是 | §3.3 |
| cip_data | ENIPCommand.CIPData | 是 | 但编码辅助缺失，见 E-CRIT-3 |
| io_data | ENIPConfig.IOData | 是 | §3.5 |
| connection_timeout | ENIPConfig.ConnectionTimeout | 是 | 默认 10s |
| o2t_rpi / t2o_rpi | ENIPConfig.O2T_RPI / T2O_RPI | 是 | 默认 10000μs |
| o2t_size / t2o_size | ENIPConfig.O2T_Size / T2O_Size | 是 | |
| connection_id | ENIPConfig.ConnectionID | 是 | |
| sequence_number | ENIPConfig.SequenceNumber | 是 | |
| path | ENIPConfig.Path | 是 | 但编码未解释，见 E-HIGH-1 |
| devices | ENIPConfig.Devices | 是 | 多设备 |
| transport_type | ENIPIOData.TransportType | 是 | 但语义简化，见 E-HIGH-2 |

扩展表 24 字段全部覆盖。但 SessionHandle 跨命令引用机制缺失（E-CRIT-1）、CIPData 编码辅助缺失（E-CRIT-3）、TransportType 语义简化（E-HIGH-2）影响字段正确性。

### 4.3 测试用例质量

**总评**：40 条用例（Validate 10 + Plan 正向 12 + 边界 8 + 多设备 3 + TCP/ENIP 序列 4 + 集成 3）。覆盖广度合格，但深度有以下缺陷：

1. **CLAUDE.md §1（spec 驱动）部分违规**：§8.1 字段覆盖率表自承认多个字段"待补充"（SerialNumber, FirmwareRevision, ConnectionTimeout, O2T_Size, T2O_Size, Status, Options, Direction, Interval, ENIPIOData.Direction）。这些字段在 §7 测试用例中无对应测试。
2. **CLAUDE.md §2（负向覆盖）合格**：V01-V10 覆盖 Validate 异常；E1-E10 覆盖 §6.18 异常场景。
3. **CLAUDE.md §3（单路径单测）部分违规**：§8.2 ENIP Command 覆盖率表自承认 Nop/ListServices/ListInterfaces/IndicateStatus/Cancel 5 个命令无测试。§8.3 CIP Service 覆盖率表自承认 Start/Stop/Create/Delete/PCCC Execute 5 个服务无测试。
4. **CLAUDE.md §4（集成测试）合格**：I01-I03 覆盖 e2e。
5. **CLAUDE.md §5（断言可观测量）部分违规**：T03 称"响应 payload 含 ProductName 字节"——但未断言具体字节值，仅断言"含"。T04 称"SessionHandle != 0"——未断言具体值。
6. **CLAUDE.md §6（并发验证）缺失**：M01/M03 多设备测试未断言"多设备总发包时间 ≤ 单设备的 N 倍"。
7. **CLAUDE.md §7（failing-test-first）未明示**：§7 无 failing-test-first 段落。
8. **CLAUDE.md §8（adversarial review of test quality）合规度中**：§8 字段覆盖率表自承认多个"待补充"，是诚实的对抗审查，但未给出补充计划。

**测试质量评分**：6/10。

---

## 5. 总体评分（三个协议分别评分）

### 5.1 RIP 设计文档

| 维度 | 评分 | 说明 |
|------|------|------|
| RFC 一致性 | 5/10 | AFI=0xFFFF 全量请求错误（R-CRIT-1/2），SrcPort 多路由器场景与 RFC 矛盾（R-HIGH-2），MD5 DigestOffset 计算错误（R-HIGH-3） |
| 字段覆盖率 | 9/10 | 扩展表 21 字段全覆盖 |
| 状态机 | 7/10 | 简化合理，但 SplitHorizon+Multicast 互斥缺失（R-HIGH-4） |
| 测试用例 | 7/10 | 48 条覆盖广度合格，但 T-POS-1 基于 spec 错误（R-CRIT-3），并发度未断言（R-MED-4） |
| 文档自洽性 | 5/10 | §6.1 自相矛盾（R-CRIT-1），RIPng 布局两份表（R-HIGH-1），T-ERR-18 矛盾（R-MED-2） |
| **总分** | **6.6/10** | 可用但需修复 3 个 CRITICAL 后才能进入实现 |

### 5.2 MODBUS 设计文档

| 维度 | 评分 | 说明 |
|------|------|------|
| 规范一致性 | 7/10 | MBAP/PDU 格式正确，但附录 A.1 Length 自相矛盾（M-CRIT-1），Transaction ID 自增 off-by-one（M-HIGH-3） |
| 字段覆盖率 | 8/10 | 扩展表 25 字段中 21 个适用字段全覆盖，但 vendor/product 等 4 个不适用字段未声明 |
| 状态机 | 8/10 | TCP 握手/事务/挥手清晰，但 Direction 字段语义不清（M-HIGH-1） |
| 测试用例 | 6/10 | 50 条覆盖广度合格，但 T05 默认响应值矛盾（M-CRIT-3），T02 位数据未断言（M-CRIT-2），8 个 FC 无单测 |
| 文档自洽性 | 6/10 | 附录 A.1 自相矛盾（M-CRIT-1），WriteValue/Quantity 非法处理不一致（M-HIGH-2） |
| **总分** | **7.0/10** | 可用但需修复 3 个 CRITICAL 后才能进入实现 |

### 5.3 ENIP 设计文档

| 维度 | 评分 | 说明 |
|------|------|------|
| 规范一致性 | 6/10 | ENIP 头/CPF/CIP 服务码覆盖广，但 TransportType 语义简化（E-HIGH-2），B10 物理不可能（E-MED-4） |
| 字段覆盖率 | 8/10 | 扩展表 24 字段全覆盖，但 §8.1 自承认多个"待补充" |
| 状态机 | 6/10 | OPENED 状态 I/O 迁移缺失（E-HIGH-4），重复 RegisterSession 路径缺失（E-LOW-2） |
| 测试用例 | 6/10 | 40 条覆盖广度合格，但 §8.2/§8.3 自承认 5 个 ENIP 命令 + 5 个 CIP 服务无测试，T03/T04 断言不充分 |
| 文档自洽性 | 5/10 | StrategyConfig 跨命令引用机制未定义（E-CRIT-1），CIPData 编码辅助缺失（E-CRIT-3），ConnectionTimeout=0 矛盾（E-MED-1） |
| **总分** | **6.2/10** | 可用但需修复 3 个 CRITICAL 后才能进入实现 |

### 5.4 三协议综合排名

1. **MODBUS 7.0/10**（最高，问题最少，主要是文档自洽性）
2. **RIP 6.6/10**（中等，3 个 CRITICAL 都是 RFC 一致性问题）
3. **ENIP 6.2/10**（最低，3 个 CRITICAL 都是 spec 级缺失，需补定义）

### 5.5 修复优先级建议

**P0（进入实现前必须修复）**：
- R-CRIT-1/R-CRIT-2/R-CRIT-3：RIP AFI=0xFFFF 全量请求错误，spec 与测试同步修复。
- M-CRIT-1：MODBUS 附录 A.1 Length 自相矛盾，删除"先写错再修正"。
- M-CRIT-3：MODBUS T05 默认响应值与默认规则矛盾，显式声明 ResponseValues。
- E-CRIT-1：ENIP StrategyConfig 跨命令引用机制定义。
- E-CRIT-2：ENIP 双向 I/O 支持（O2T + T2O）。
- E-CRIT-3：ENIP CIP 数据编码辅助。

**P1（实现期修复）**：
- R-HIGH-1/R-HIGH-2/R-HIGH-3/R-HIGH-4
- M-HIGH-1/M-HIGH-2/M-HIGH-3
- E-HIGH-1/E-HIGH-2/E-HIGH-3/E-HIGH-4

**P2（实现后优化）**：
- 所有 MEDIUM/LOW 问题。

### 5.6 审计结论

三份设计文档整体质量中等偏上（平均 6.6/10），覆盖广度合格但深度有缺陷。主要问题集中在：

1. **spec 内部自相矛盾**（RIP §6.1、MODBUS 附录 A.1、ENIP §4 状态机）——CLAUDE.md 测试策略 §1（spec 驱动）的典型违规，会导致测试基于错误 spec 派生。
2. **RFC 一致性错误**（RIP AFI=0xFFFF、MODBUS Transaction ID off-by-one、ENIP TransportType 语义）——wire-level 错误，会被 Wireshark 标记。
3. **新机制未定义**（ENIP StrategyConfig 跨命令引用、CIP 编码辅助）——实现者自行解释，行为不一致。
4. **测试用例断言不充分**（MODBUS T02 位数据、ENIP T03/T04 字节值）——CLAUDE.md 测试策略 §5 违规，测试通过但实际错误。

建议设计者在进入实现前修复所有 P0 问题，实现期修复 P1 问题。本审计报告作为实现期对抗审查的基线，实现完成后应再做一轮代码级审计。

---

**审计统计**：

| 协议 | CRITICAL | HIGH | MEDIUM | LOW | 总计 | 评分 |
|------|----------|------|--------|-----|------|------|
| RIP | 3 | 4 | 4 | 2 | 13 | 6.6/10 |
| MODBUS | 3 | 3 | 3 | 1 | 10 | 7.0/10 |
| ENIP | 3 | 4 | 4 | 2 | 13 | 6.2/10 |
| **合计** | **9** | **11** | **11** | **5** | **36** | **6.6/10** |

报告行数：约 600 行（含表格）。

---

## 三轮审计 RIP v1.1.2（2026-08-03）

**审计对象**：`docs/protocol-designs/10-rip-design.md` v1.1.2（1151 行，72 条测试用例）
**审计依据**：RFC 2453 (RIP v2) §3.6/§3.9.1/§4/§5；RFC 4822 (RIP-2 MD5 Authentication) §2.1/§2.5；RFC 1058 §3.1/§3.6；CLAUDE.md Testing Policy 8 条规则
**审计方法**：独立对抗式审计，默认"有 bug"。逐字段与 RFC 对比，重点核查 v1.1.2 修复的 26 个问题是否真正修复，以及修复过程是否引入新问题。按 6 维度对抗：RFC 一致性 / 字段命名与语义 / 状态机 / 多路由 / 测试质量 / 常见陷阱。
**审计范围**：仅审计 RIP 部分（§1-§9 + 修订记录），不修改 MODBUS/ENIP 部分。

### 审计概览

| 级别 | 数量 | 说明 |
|------|------|------|
| CRITICAL | 2 | wire-format 直接违反 RFC，会导致 Wireshark 解析失败或语义错误 |
| HIGH | 3 | 规范字段命名错误 / 测试断言不充分 / 组播毒化反转警告缺失 |
| MEDIUM | 5 | 文档自相矛盾 / 测试用例分类错误 / 行为分支未覆盖 |
| LOW | 4 | 章节引用错误 / 字段语义含糊 / 术语不一致 |
| **合计** | **14** | 较 v1.1.2 的 26 问题大幅减少，但仍有 2 个 CRITICAL 必须修复后才能进入实现 |

---

### CRITICAL 级别

#### R-3-CRIT-1：MD5 认证报文缺少 RFC 4822 §2.1 规定的 4 字节 trailer header

**位置**：§2.5（第 76-82 行）、§6.8（第 529-533 行）、T-POS-9（第 716 行）、T-POS-25（第 732 行）、§8.4（第 874-876 行）、§8.10（第 925 行）。

**问题**：RFC 4822 §2.1 明确定义 MD5 认证 trailer 包含两层结构——先 4 字节 header `0xFFFF 0x0001`，后接 AuthData（摘要）。设计文档在 §2.5 中将此字段命名为 "Digest Offset"，并描述为"后续 RIP 报文中 MD5 摘要相对报文起始的 16-bit 偏移"。§6.8 示例写道："末尾追加 16B 摘要占位（0xAA）"，"总 Payload = 4 + 20 + 20 + 16 = 60 字节"。完全缺失 `0xFFFF 0x0001` 这 4 字节 trailer header。

wire-format 影响：
- 文档设计：在偏移 44 处直接放置 16B 摘要（0xAA 占位），总 payload 60B
- RFC 4822 要求：在偏移 44 处放置 4B header（`FF FF 00 01`），偏移 48 处放置 16B 摘要，总 payload 64B

任何 RFC 4822 合规的解析器（包括 Wireshark、Quagga/FRR 的 MD5 认证模块）会在偏移 44 处查找 trailer header，发现是 `0xAA 0xAA 0xAA 0xAA`（非 `0xFFFF 0x0001`），会判定 trailer 格式错误并丢弃该报文。

更深层问题——字段命名与语义混淆：
- 设计文档称此字段为 "Digest Offset"，值 = 44，描述为"指向末尾摘要起始位置"
- RFC 4822 实际字段名为 "RIPv2 Packet Length"（unsigned 16-bit offset from start of RIPv2 header to **end of regular RIPv2 packet**, **not including authentication trailer**）
- 设计文档计算的值 44 = `4 + 20×(1+1)`，恰好等于 "RIPv2 Packet Length"（regular RIP 数据包末尾），而非 "Digest Offset"（摘要起始位置 = 44+4=48）

即：值的数值正确（RIPv2 Packet Length），但名称/描述错误（写成 Digest Offset 并指向摘要），并且 wire format 跳过了 trailer header。

测试断言 T-POS-9 "末尾 16B=0xAA" 会通过错误实现——如果实现把 16B 0xAA 直接放在偏移 44 处（跳过 trailer header），断言仍然成立。这违背 CLAUDE.md 测试策略 §5（assert observable outcomes, not just structure）——测试应同时断言偏移 40-43 处的 4 字节 trailer header `FF FF 00 01`。

**依据**：
- RFC 4822 §2.1：trailer 包含 `0xFFFF | 0x0001` 4 字节 header + AuthData
- RFC 4822 §2.5："RIPv2 Packet Length... not including the authentication trailer"

**修复建议**：
1. §2.5 字段名 "Digest Offset" → "RIPv2 Packet Length (RFC 4822 §2.1)"；描述改为 "RIP 报文中 regular RIPv2 packet 末尾相对报文起始的偏移（不含认证 trailer）"
2. §6.8 在 1 条真实路由（20B）之后追加 4B trailer header（`FF FF 00 01`）+ 16B 摘要占位（0xAA），总 Payload = 4 + 20 + 20 + 4 + 16 = **64 字节**
3. T-POS-9 断言增加："Payload[44:48] = FF FF 00 01（trailer header）"，"Payload[48:64] = 16B 0xAA（摘要占位）"
4. §8.4 同步修订："MD5 trailer = 4B header (0xFFFF 0x0001) + AuthData 字节，不计入 25 entry 限制"
5. §8.10 修订："认证 MD5 末尾 4B trailer header + AuthData 字节不计入 25 entry 限制"

#### R-3-CRIT-2：`request_full` 场景的全量请求 entry Metric 值错误（应为 16 不是 1）

**位置**：§3（第 128 行）、§4 状态机图（第 298 行）、§4 场景映射表（第 321 行）、§6.1（第 410-411 行）、T-POS-1（第 708 行）。

**问题**：RFC 2453 §3.9.1 明确规定全量路由表请求的 entry 格式：
> "If there is exactly one entry in the request, and it has an address family identifier of zero and a metric of infinity (i.e., 16), then this is a request to send the entire routing table."

设计文档在多处使用 metric=1 而非 metric=16（infinity）：
- §3 第 128 行："Request 全量路由的特殊 entry (AFI=0x0000, metric=1)"
- §4 状态机图第 298 行：`(AFI=0x0000, metric=1)`
- §4 场景映射表第 321 行：`1 个特殊 Request entry (AFI=0x0000, metric=1)`
- §6.1 第 410 行：hex entry 最后 2 字节 `00 01`（metric=1）
- §6.1 第 411 行：注释明确写 "Metric=1"
- T-POS-1 第 708 行：`Payload[18:20]=00 01 (Metric=1)`

wire-format 影响：metric=1 ≠ metric=16（infinity）。按 RFC 2453 §3.9.1 的语义，如果 entry 的 metric 不是 16，则该 entry 不会被识别为"全量路由表请求"，而会被处理为"对特定目的地址 0.0.0.0 的单个路由查询"。接收方只会返回到 0.0.0.0 的单条路由，而非整个路由表。

这是 v1.1.0 审计（R-CRIT-1）修复 AFI=0xFFFF→0x0000 之后残留的姊妹 bug——AFI 修对了，但 metric 仍然是错误值（应该是 16 不是 1）。两轮审计（v1.1.1/v1.1.2）均未发现此问题。

**依据**：RFC 2453 §3.9.1 "metric of infinity (i.e., 16)"。

**修复建议**：
1. §3 第 128 行：`metric=1` → `metric=16（infinity）`
2. §4 状态机图第 298 行：`metric=1` → `metric=16`
3. §4 场景映射表第 321 行：`metric=1` → `metric=16`
4. §6.1 第 410 行：hex entry `... 00 01` → `... 00 10`
5. §6.1 第 411 行：`Metric=1` → `Metric=16（RFC 2453 §3.9.1: infinity）`
6. T-POS-1 第 708 行：`Payload[18:20]=00 01 (Metric=1)` → `Payload[20:24]=00 00 00 10 (Metric=16)`；同时 Payload[20:22] = 00 00（高 2 字节，因 Metric 是 4 字节字段）

### HIGH 级别

#### R-3-HIGH-1：§2.5 字段命名 "Digest Offset" 与 RFC 4822 §2.1 不一致

**位置**：§2.5（第 76 行）、§6.8（第 529 行）。

**问题**：RFC 4822 §2.1 将此字段命名为 "RIPv2 Packet Length"，定义为 "An unsigned 16-bit offset from the start of the RIPv2 header to the end of the regular RIPv2 packet (not including the authentication trailer)"。设计文档将其命名为 "Digest Offset" 并描述为 "后续 RIP 报文中 MD5 摘要相对报文起始的 16-bit 偏移"。

虽然文档的公式 `DigestOffset = 4 + 20×(1 + N)` 算出的值数值上等于 RIPv2 Packet Length（regular packet 末尾偏移），但描述中的"MD5 摘要起始位置"是错误的（因为 trailer header 4B 在摘要之前，摘要实际从偏移 48 开始，不是 44）。如果实现者按字面理解 "Digest Offset" 名称将摘要放在偏移 44，会违反 RFC 4822。

此条与 R-3-CRIT-1 同源，但侧重于字段命名/语义描述错误的文档层面。R-3-CRIT-1 侧重 wire format（trailer header 缺失），R-3-HIGH-1 侧重术语和描述。

**依据**：RFC 4822 §2.1 字段名 "RIPv2 Packet Length"；§2.5 定义。

**修复建议**：§2.5 第 76 行 `Digest Offset` → `RIPv2 Packet Length (RFC 4822)`；描述改为 "RIP 报文中 regular packet 末尾相对报文起始的 16-bit 偏移（不含认证 trailer）"。§6.8 同步：`DigestOffset` → `RIPv2 Packet Length`。

#### R-3-HIGH-2：`split_horizon`/`poison_reverse` 同时为 true 且组播场景的毒化反转警告在 §6.15 异常表中缺失

**位置**：§3 第 178 行、§6.15（第 695 行仅 SplitHorizon+PoisonReverse、697 行 SplitHorizon+Multicast）。

**问题**：§3 RIPConfig.PoisonReverse 注释明确写道："Validate 对 {PoisonReverse=true, Multicast=true} 组合发出警告"。M-9 修复（v1.1.2）扩展 T-ERR-18 涵盖此场景。但 §6.15 异常表中：
- 第 695 行 T-ERR-15：SplitHorizon=true + PoisonReverse=true → Validate 警告 ✓
- 第 697 行 T-ERR-18：SplitHorizon=true + Multicast=true → Validate 警告 ✓
- **缺失**：PoisonReverse=true + Multicast=true → Validate 警告（仅在 §3 注释中提及）

§6.15 异常表应当有显式行覆盖此组合，与 §3 注释形成闭环。同时 T-ERR-18 断言要点仅写 "SplitHorizon=true + Multicast=true"，未提及 PoisonReverse 路径——如果实现者只对 SplitHorizon+Multicast 触发警告而忽略 PoisonReverse+Multicast，测试仍可能通过。

**依据**：CLAUDE.md 测试策略 §8（adversarial review of test quality），§3 与 §6.15 表的内部一致性。

**修复建议**：§6.15 增加行 `PoisonReverse=true + Multicast=true | Validate 警告（组播无具体接收方，PoisonReverse 不生效；planner 跳过过滤）| T-ERR-18（扩展）`。T-ERR-18 描述改为 "SplitHorizon=true + Multicast=true 或 PoisonReverse=true + Multicast=true → Validate 警告（组播无具体接收方，两者均跳过过滤）"。

#### R-3-HIGH-3：`request_full` 场景的 "Planner 内部在 Request 后自动追加 Response" 行为在 §6.1 未描述，且无测试覆盖

**位置**：§4 状态机图（第 304-306 行）、§4 场景映射表（第 321 行）、§6.1（第 393-414 行）、§3（第 128 行）。

**问题**：§4 状态机图和场景映射表都声称 `request_full` 场景的 Planner 内部行为是："Planner 内部在 Request 后自动追加 Response（视作 request_full 场景的固定后置步骤，无需用户配 IsResponse 字段）"。

但 §6.1（`request_full` 场景的具体描述，393-414 行）仅描述了 Request 报文（1 个 UDP 包，Payload = 4B RIP 头 + 1×20B 特殊 entry），完全未提及自动追加的 Response 报文。

T-POS-1（覆盖 §6.1）也只断言 Request 报文（Payload[0]=0x01, [1]=0x02, [4:6]=00 00, [18:20]=00 01, DstIP=224.0.0.9, TTL=1），未断言 Response 报文。

RFC 2453 中 Request 报文是发给邻居的，Response 由邻居返回；同一路由器不会在同一个 UDP 数据报中既发 Request 又发 Response 到同一目的地址。trafficgen 的 "自动追加 Response" 是非 RFC 的实现便利（在同一 4-tuple 上模拟 Request/Response 交换），但应在 §6.1 显式描述并由测试覆盖。如果实现者未实现自动追加行为（仅发 Request），T-POS-1 仍能通过，导致 wire-level 行为与文档不符。

**依据**：CLAUDE.md 测试策略 §3（单路径单测，每条路径单独验证）；§4 文档自洽性。

**修复建议**：
1. §6.1 增加一段 "Planner 自动追加 Response" 描述：明确这是 trafficgen 的非 RFC 行为（同一 4-tuple 上模拟 Request/Response 交换），Response 报文与 Request 共享 FlowID，PacketIndex 递增。
2. 新增 T-POS-N（如 T-POS-1b）：断言 `request_full` 场景产生 2 个 PacketConfig：包 0 是 Request（Command=1, AFI=0, Metric=16），包 1 是 Response（Command=2，含默认路由或用户 Routes）。

### MEDIUM 级别

#### R-3-MED-1：§6.4 v1 Route Entry "后 12B 全 0" 与 "Metric=1" 自相矛盾

**位置**：§6.4（第 453 行）。

**问题**：§6.4 写道："Route Entry：AFI=2, RouteTag=0, IP=10.0.0.0, 后 12B 全 0（无掩码、无下一跳）, Metric=1"。

按 §2.2 v1 Route Entry 布局：
- 偏移 0-1: AFI (2B)
- 偏移 2-3: MustBeZero (2B)
- 偏移 4-7: IP (4B)
- 偏移 8-11: MustBeZero (4B，v1 无 SubnetMask)
- 偏移 12-15: MustBeZero (4B，v1 无 Next Hop)
- 偏移 16-19: Metric (4B)

"后 12B 全 0" 含糊——如果指偏移 8-19（4+4+4=12B），其中偏移 16-19 是 Metric=1，不是 0，自相矛盾。如果指偏移 8-15（4+4=8B），描述错误（应是 "后 8B 全 0"）。

§8.1 字段级审计表使用正确的 "0×8B" 描述（偏移 8-15）。§6.4 与 §8.1 不一致。

**依据**：RFC 1058 §3.1（v1 RTE 布局）；CLAUDE.md 文档自洽性。

**修复建议**：§6.4 第 453 行 "后 12B 全 0" → "后 8B 全 0（偏移 8-11 掩码字段=0、偏移 12-15 下一跳字段=0）"。

#### R-3-MED-2：T-ERR-14 归类为 "负向" 但期望行为是 "Validate 不报错"

**位置**：§7（第 772 行）。

**问题**：T-ERR-14 断言 "Validate 不报错，但 Plan 用组播 IP"。CLAUDE.md 测试策略 §2 要求负向测试覆盖错误路径——负向测试的期望行为应是"Validate 报错"。T-ERR-14 的期望行为是 "不报错，只警告"，与 "负向用例" 分类矛盾，应归入 T-WARN-* 或归入 §6.15 但标注 "警告而非报错"。

**依据**：CLAUDE.md 测试策略 §2（cover failure paths, not just happy path）；测试用例分类一致性。

**修复建议**：T-ERR-14 重命名为 T-WARN-1 或在断言中明确标注 "警告（不报错）"。或者在 §6.15 异常表中区分 "报错" 和 "警告" 两列。

#### R-3-MED-3：T-POS-9 / T-POS-25 测试断言不验证 RFC 4822 trailer header

**位置**：T-POS-9（第 716 行）、T-POS-25（第 732 行）。

**问题**：T-POS-9 断言 "末尾 16B=0xAA"。如 R-3-CRIT-1 所述，MD5 认证 trailer 必须包含 4B header（`0xFFFF 0x0001`）+ AuthData。如果实现把 16B 0xAA 直接放在偏移 44（跳过 trailer header），T-POS-9 断言仍通过。T-POS-25 断言 "AuthDataLen=0x14, 末尾 20B 占位" 同样缺少 trailer header 验证。

测试用例应同时断言：Payload[44:48] = `FF FF 00 01`（trailer header），Payload[48:64] = 16B `0xAA`（摘要占位）。

**依据**：CLAUDE.md 测试策略 §5（assert observable outcomes, not just structure）。

**修复建议**：T-POS-9 断言增加 "Payload[44:48] = FF FF 00 01（MD5 trailer header，RFC 4822 §2.1）"，"Payload[48:64] = 16B 0xAA"。T-POS-25 类似："Payload[44:48] = FF FF 00 01"，"Payload[48:68] = 20B 0xAA（AuthDataLen=20 摘要占位）"。

#### R-3-MED-4：RIPng 路由条目忽略 RIPRoute.NextHop / RIPRoute.SubnetMask / RIPRoute.RouteTag 的行为未明确文档化

**位置**：§3 RIPRoute 字段注释（第 189-211 行）、§6.12（第 594-615 行）。

**问题**：§3 RIPRoute.AFI 注释称 "RIPng 忽略此字段 (固定 IPv6)"，RIPng 用 PrefixLen 而非 SubnetMask。但 RIPRoute.NextHop（"下一跳：IPv4/IPv6 字符串"）和 RIPRoute.RouteTag 的注释未说明 RIPng 下的行为：
- RIPRoute.RouteTag 注释称 "RIP v2/RIPng 使用，RIP v1 透传 0"——RIPng 下 RouteTag 有效
- RIPRoute.NextHop 注释对 RIPng 只字未提
- RIPRoute.SubnetMask 注释称 "RIPng 忽略，使用 PrefixLen"——OK

RFC 2080 §2.1.1 RIPng RTE 布局是 IPv6 Prefix(16B) + Route Tag(2B) + PrefixLen(1B) + Metric(1B) = 20B，没有 Next Hop 字段（下一跳隐含为发送方）。如果用户为 RIPng 设置 NextHop，设计文档未说明是忽略还是 Validate 报错。

**依据**：RFC 2080 §2.1.1（RIPng RTE 布局，无 Next Hop）；CLAUDE.md 文档完整性。

**修复建议**：§3 RIPRoute.NextHop 注释增加 "RIPng 忽略此字段（RFC 2080 §2.1.1 无 Next Hop 字段）；如设置则 Validate 报错或忽略"。

#### R-3-MED-5：§6.4 v1 默认广播行为与 §3 Multicast=false 语义含糊

**位置**：§6.4（第 454 行）、§3 第 145-148 行。

**问题**：§6.4 写道 "默认广播 DstIP=255.255.255.255（multicast=true 时 v1 用广播）"，但配置示例中 multicast 未设置（默认 false）。按 §3 第 146 行 Multicast=false → "使用 DstIP"（单播）；按 §6.4 文字暗示 v1 默认广播。这两处描述在 multicast=false 时存在歧义：v1 是默认广播还是单播？

T-POS-32（v1.1.2 新增）已明确 v1+multicast=true → 广播，但 §6.4 文字描述含糊。

**依据**：CLAUDE.md 文档自洽性。

**修复建议**：§6.4 第 454 行 "默认广播 DstIP=255.255.255.255" → "如 multicast=true 则 DstIP=255.255.255.255（v1 无组播，强制广播；参见 T-POS-32）。如 multicast=false 则 DstIP 使用 FlowSpec.DstIP 或 255.255.255.255（v1 传统行为）"。

### LOW 级别

#### R-3-LOW-1：§2.7 / §6.6 / §6.13 引用 "RFC 2453 §3.9.2" 但 RIP Response 源端口定义在 §3.6

**位置**：§2.7（第 107 行）、§6.6（第 489 行）、§6.13（第 643 行）。

**问题**：设计文档多处引用 "RFC 2453 §3.9.2" 作为 "Response 源端口 = 520" 的依据。但 RFC 2453 中：
- §3.6 "Input Processing" 写道 "Unsolicited routing update messages have both the source and destination port equal to the RIP port"
- §3.9.1 "Request" 写道 "the Request should be sent directly to that router from a UDP port other than the RIP port"

§3.9.2 实际是关于 "Responding to Request" 的，但内容是 "The Response must be sent to the address and port from which the Request came"——这支持 Response 源端口 = 520，但严格来说 §3.6 是主要依据。

实际上 §3.9.2 不在 RFC 2453 中——RFC 2453 §3.9 标题是 "Hosts"，§3.9.1 是 "Host Considerations"，§3.9.2 不存在。源端口定义在 §3.6 "Output Processing"。

**依据**：RFC 2453 §3.6（Output Processing：源/目的端口定义）；章节引用准确性。

**修复建议**：§2.7 / §6.6 / §6.13 的 "RFC 2453 §3.9.2" → "RFC 2453 §3.6"。

#### R-3-LOW-2：§6.4 v1 RTE "RouteTag=0" 表述与 §2.2 字段表不一致

**位置**：§6.4（第 453 行）、§2.2（第 42-48 行）。

**问题**：§6.4 描述 v1 Route Entry 字段时说 "RouteTag=0"，但 §2.2 v1 RTE 字段表中偏移 2 字段名为 "MustBeZero"，非 "Route Tag"。v1 没有 Route Tag 概念（那是 v2 扩展）。

这只是术语不一致，wire format 不受影响（两个字段在偏移 2 都必须是 0），但会让读者误以为 v1 有 Route Tag 字段。

**依据**：RFC 1058 §3.1（v1 RTE 无 Route Tag）；§2.2/§6.4 内部一致性。

**修复建议**：§6.4 第 453 行 "RouteTag=0" → "MustBeZero=0（v1 无 Route Tag 字段，偏移 2-3 固定为 0）"。

#### R-3-LOW-3：§5.1 单包 PacketConfig 示例 SrcPort=52001 与多路由器声明冲突

**位置**：§5.1（第 344 行）、§2.7（第 107 行）。

**问题**：§5.1 给出典型单包 PacketConfig 结构示例，其中 SrcPort=52001。但 §2.7 明确声明 Response SrcPort=520（RFC 2453 §3.6），52001 是 "多路由器场景的非 RFC 端口分配"。§5.1 单包示例使用 52001 会让读者误解为单路由器 Response 也用 52001。

实际语义可能是：§5.1 示例是 Request 包（Request 可用非 520 端口），但 FlowID 排序方式 "192.168.1.1-224.0.0.9-52001-520" 不明确哪个是 SrcPort 哪个是 DstPort。如果 SrcPort=52001 是 Request，§5.1 未说明此为 Request；如果是 Response，则违反 §2.7 的 RFC 声明。

**依据**：§2.7 vs §5.1 内部一致性。

**修复建议**：§5.1 第 344-350 行增加注释 "此示例为 Request 包（SrcPort=52001 为临时端口）。Response 包 SrcPort=520"。

#### R-3-LOW-4：§3 `RIPAuth.Password` "超出截断" 与 §6.15 T-ERR-10 "报错" 不一致

**位置**：§3（第 220 行）、§6.15（第 690 行）、§8.4（第 873 行）。

**问题**：§3 RIPAuth.Password 注释写道 "simple 类型，最多 16 字节，不足补 0，超出截断"。§6.15 T-ERR-10 "Auth.Password=17 字节 | Validate 报错（>16）"。§8.4 第 873 行 "simple 密码 < 16 字节补零，= 16 不补，> 16 截断或报错（实现选报错，更严格）"。

三处表述：§3 说截断，§6.15 说报错，§8.4 说 "实现选报错"。虽然最终行为是报错，但 §3 注释未同步更新为 "超出报错"，与 §6.15/§8.4 不一致。

**依据**：文档内部一致性。

**修复建议**：§3 第 220 行 "超出截断" → "超出报错（与 T-ERR-10 一致）"。

---

### 修复优先级建议

**P0（进入实现前必须修复）**：
- R-3-CRIT-1（MD5 trailer header 缺失，wire format 错误）
- R-3-CRIT-2（request_full metric=1 应为 16，违反 RFC 2453 §3.9.1）

**P1（实现期修复）**：
- R-3-HIGH-1 / R-3-HIGH-2 / R-3-HIGH-3
- R-3-MED-3（测试断言加强）

**P2（实现后优化）**：
- 所有 MEDIUM（除 M-3）和 LOW 问题

---

### 审计结论

**不可进入实现阶段**——R-3-CRIT-1（MD5 trailer header 缺失）和 R-3-CRIT-2（request_full metric 错误）均为 RFC wire-format 直接违反，会导致 Wireshark/Quagga/FRR 等合规解析器拒收报文或误解析。

修复完 2 个 CRITICAL 后，剩余 HIGH/MEDIUM/LOW 问题不阻碍进入实现阶段（可在实现期或实现后修复），但建议至少修复 R-3-HIGH-1（字段命名）、R-3-HIGH-2（毒化反转警告缺失）、R-3-HIGH-3（auto-Response 行为未测试）后再进入实现，因为这些会在实现期造成理解歧义或测试遗漏。

**v1.1.2 vs v1.1.1 vs v1.0 审计对比**：
- v1.1.0 → v1.1：修复 3 CRITICAL + 4 HIGH + 4 MEDIUM + 2 LOW = 13 问题
- v1.1.0 审计（R-CRIT-1）将 AFI 从 0xFFFF 修正为 0x0000，但遗留 metric=1 错误——v1.1/v1.1.1/v1.1.2 均未发现 R-3-CRIT-2
- v1.1.0 → v1.1.1：1 问题（破坏性变更 `*uint8`）
- v1.1.1 → v1.1.2：26 问题（HIGH 1 + MEDIUM 13 + LOW 12）
- **v1.1.2 → v1.1.2 三轮审计（本轮）**：14 问题（CRITICAL 2 + HIGH 3 + MEDIUM 5 + LOW 4）

本轮发现 2 个 v1.0 → v1.1.2 三轮修复中均被遗漏的 wire-format CRITICAL，说明 "测试通过" 不等于 "wire format 正确"——R-3-CRIT-2 属于 CLAUDE.md 测试策略 §1 典型违规（测试基于错误 spec 派生但通过），R-3-CRIT-1 属于 §5 违规（测试断言不充分，未验证 trailer header）。

# SRv6 设计文档深度对抗审计报告（R2）

**审计对象**：`/home/weihang/trafficGenerator/docs/protocol-designs/15-srv6-design.md`（912 行，v1.1，声称 107 条用例）

**审计日期**：2026-08-04
**审计人**：独立协议审计员（非设计者）
**审计依据**：
1. **RFC 8754**（Segment Routing over IPv6 / SRH，Segment Routing Header 段路由头部）
2. **RFC 8200**（IPv6，Internet Protocol, Version 6 Specification，IPv6 协议规范）§4.4 Routing Header
3. **RFC 8986**（SRv6 Network Programming，SRv6 网络编程）
4. **CLAUDE.md** 测试策略 8 条强制规则（§1 spec 驱动 / §2 失败路径 / §3 一测一路径 / §4 集成测试 / §5 可观察值 / §6 并发正确性 / §7 失败优先 / §8 测试质量审计）
5. `trafficgen/internal/core/types.go` L2Config / L3Config / IPv6Option 现状
6. `trafficgen/internal/core/builder.go` `writeL3v6` / `serializeIPv6HopByHop` 现状

**审计方法**：逐节对照 RFC 8754 / RFC 8200 原文，对每一处字节级期望值逐字节验算；对每条 RFC 引用逐字核对原文；对每个字段默认值规则检查歧义；对 §7 107 条用例逐条核查覆盖性与可观察断言；对 §9 集成点对照现有 builder.go `writeL3v6` 已有实现。默认"有 bug"，除非证据确凿。

---

## 1. 审计概览

### 1.1 严重度分布

| 严重度 | 数量 | 说明 |
|--------|------|------|
| CRITICAL | 7 | 协议根本性错误：Segment List 顺序颠倒 / DstIP 关系错误 / TLV 类型错误 / HMAC Flag 虚构 / Reduced SRH 语义错误 / End* 行为地址更新公式错误 / 不存在字段 |
| HIGH | 6 | Hdr Ext Len 与 RFC 8754 公式不一致 / 测试用例与 RFC 矛盾 / B7 字节布局错误 / HopByHop 共存 NextHeader 链顺序违反 RFC 8200 / 字段边界错误 |
| MEDIUM | 5 | 测试覆盖缺口 / 默认值歧义 / Hdr Ext Len 上限计算错 / LastEntry 默认值与源节点语义冲突 / 单测断言弱 |
| LOW | 3 | 文档表述不清 / 错误信息措辞 / 命名歧义 |
| **合计** | **21** | — |

### 1.2 总体结论

**本设计文档不可直接进入实现阶段**。

v1.1 修订（2026-08-03）针对 v1.0 审计的 14 个问题做了修复，但 v1.1 仍存在 **7 个 CRITICAL 协议根本性错误**，其中 5 个是 v1.0 审计未发现的**新问题**（v1.0 审计只看了"用例虚胖"和"内部矛盾"，没有逐字核对 RFC 8754 原文）：

1. **Segment List 顺序完全颠倒**（C-SRV6-R2-1）：文档 §2.2 反复声明"List[0] = 第一个要处理的 segment"，但 RFC 8754 §2.3 原文明确"Segment List[0] contains the **last** segment of the SR Policy"——List[0] 是最后一段，不是第一段。整个设计的语义模型与 RFC 相反。
2. **IPv6 DstIP 与 Segment List[0] 关系错误**（C-SRV6-R2-2）：文档说"DstIP = SegmentList[0]"，但 RFC 8754 §4.1 原文"DA is set with the value of the **first** segment"——而第一段在 Segment List 的最高索引 `List[n-1]`，不是 `List[0]`。
3. **SRH TLV PadN 类型错误**（C-SRV6-R2-3）：文档 §2.4 写"PadN（Type=1）"，但 RFC 8754 §2.1.1.2 明确 SRH PadN Type=4（Hop-by-Hop 的 PadN 才是 Type=1）。
4. **SRH HMAC Flag 虚构**（C-SRV6-R2-4）：文档 §2.2 写"Flags bit 0 = HMAC"，但 RFC 8754 §2.1 明确 SRH Flags 全部 8 位都是 Unused（MUST be 0），HMAC 由 TLV（Type=5）携带，**不是 Flag 位**。
5. **HMAC-Sig TLV（Type=6）虚构**（C-SRV6-R2-5）：文档 §2.4 写"HMAC 签名 TLV（Type=6）"，但 RFC 8754 §8.2 IANA 注册表 Type=6 是 **Reserved**，不存在 HMAC-Sig TLV。
6. **Reduced SRH 语义错误**（C-SRV6-R2-6）：文档 §6.7 说"省略 SegmentList[0] 字节 / Hdr Ext Len 减 2"，但 RFC 8754 §4.1.1 原文说 reduced SRH 省略的是**第一段**（即 List[n-1]，因为第一段已在 DA 中），Last Entry = n-2。文档语义与 RFC 相反（因 C-SRV6-R2-1 顺序颠倒导致连带错误）。
7. **§2.3 End* 行为地址更新公式错误**（C-SRV6-R2-7）：文档 §2.3 End 行写"DstIP = SegmentList[LastEntry-SegmentsLeft+1]"，但 RFC 8754 §4.3.1 S15-S16 原文是"Decrement SL by 1; Copy Segment List[SL] to DA"——即 `DA = SegmentList[SL_new]`（SL 减 1 后的新值），不是 `List[LastEntry-SL+1]`。这两个公式在反序存储下并不等价（除非 LastEntry 恒等于 n-1，但 reduced SRH 下 LastEntry=n-2）。

此外另有 6 个 HIGH / 5 个 MEDIUM / 3 个 LOW，共 21 个问题。其中 v1.1 自称"已修复 v1.0 全部 14 个问题"的说法**不成立**——L-SRV6-3（环境变量跳过）等确实修复，但 H-SRV6-1（SegmentList 顺序）的"修复"反而引入了更严重的 RFC 错误（v1.0 写"反序"虽表述混乱但方向正确，v1.1 改为"正序"后整个语义模型就错了）。

---

## 2. CRITICAL 问题（7 项，必须返工）

### C-SRV6-R2-1：Segment List 顺序与 RFC 8754 完全相反

**位置**：§2.2 表格 Segment List 行（第 41 行）、§3.1 SegmentList 字段注释（第 110-114 行）、§6.1 断言（第 311 行）、§6.2 断言（第 337 行）、§8.1 检查清单（第 734 行）

**描述**：文档多处声明 Segment List 按处理顺序"正序"存储，即 `List[0]` = 第一个处理的 segment。例如：
- §2.2 第 41 行：`"按处理顺序正序存储：List[0] = 第一个要处理的 segment；List[LastEntry] = 最后一段"`
- §3.1 第 110-114 行：`"Entry 0 is the first segment processed (also written to IPv6 DstIP by the source node); the last entry is the final destination"`
- §6.1 第 311 行：`"IPv6 DstIP = fc00:2::2 = SegmentList[0]"`
- §6.2 第 337 行：`"SegmentList 在 SRH 中的字节顺序：fc00:s1::1 fc00:s2::1 fc00:b::1（按配置顺序，RFC 8754 §2.3）"`
- §8.1 第 734 行：`"SegmentList[0] 同时出现在 IPv6 DstIP"`

**依据**：RFC 8754 §2.3 原文：
> "the first element of the Segment List (Segment List[0]) contains the **last segment** of the SR Policy"
> "the second element contains the penultimate segment of the SR Policy, and so on"

RFC 8754 §2.3 示例：SR Policy `<S1, S2, S3>`（S1 先处理，S3 最后处理），Segment List 编码为 `Segment List[0]=S3, Segment List[1]=S2, Segment List[2]=S1`。即 **List 按处理顺序反序存储**，List[0] 是最后一段（最终目的），List[n-1] 是第一段（第一个要处理的）。

**影响**：
- 整个设计的语义模型与 RFC 相反。若实现者照此实现，生成的 SRH 帧 tshark 会按 RFC 反序解析，配置顺序与实际处理顺序完全颠倒。
- 所有断言"DstIP = SegmentList[0]"全部错误（应为 DstIP = SegmentList[n-1]）。
- §6.2 示例 SegmentList `[s1, s2, b]` 实际 RFC 编码应为 `[b, s2, s1]`（List[0]=b 最后一段，List[2]=s1 第一段）。
- §6.3 "End 节点处理后 DstIP = SegmentList[1]" 也错（按 RFC，SL=1 时 DstIP = SegmentList[SL=1] = S2，但配置中 S2 是第二段——这里恰好对，但只是巧合，因为 §6.3 用的 List 顺序本身也错了）。

**修复建议**：
1. §2.2 Segment List 行改为："**按处理顺序反序存储**（RFC 8754 §2.3）：List[0] = 最后一段（最终目的），List[n-1] = 第一段（第一个要处理的 segment，同时写入 IPv6 DstIP）"。
2. §3.1 SegmentList 字段注释改为："Entry 0 is the **last** segment (final destination); the last entry (index n-1) is the **first** segment to process (also written to IPv6 DstIP by the source node)."
3. §6.1 / §6.2 / §6.3 / §8.1 所有"DstIP = SegmentList[0]"改为"DstIP = SegmentList[n-1]"。
4. §6.2 示例 SegmentList 顺序改为 `[fc00:b::1, fc00:s2::1, fc00:s1::1]`（List[0]=b 最后一段，List[2]=s1 第一段=DstIP）。

---

### C-SRV6-R2-2：IPv6 DstIP 与 Segment List 关系错误

**位置**：§2.2 表格 DstIP 行（第 26 行）、§3.1 DstIPv6 字段注释（第 105-108 行）、§3.3 S3（第 217 行）、§6.1 断言（第 311 行）

**描述**：文档多处声明源节点发送时 IPv6 DstIP = SegmentList[0]。例如：
- §2.1 第 26 行：`"Destination Address | segment_list[0] 或 dst_ipv6 | 关键：源节点发送时 DstIP = Segment List[0]（即第一个要处理的 segment），而非最终目的"`
- §3.1 第 105-108 行：`"DstIPv6 is the outer IPv6 destination as written by the source node. Empty = SegmentList[0]. Per RFC 8754 §2.3 the source node writes SegmentList[0] here (the first segment to process)."`
- §3.3 S3 第 217 行：`"DstIPv6 空 → SegmentList[0]"`
- §6.1 第 311 行：`"IPv6 DstIP = fc00:2::2 = SegmentList[0]"`

**依据**：RFC 8754 §4.1（Source Node）原文：
> "The DA of the packet is set with the value of the **first segment**."

而第一段在 Segment List 中的位置是 `List[n-1]`（因 List 反序存储，见 C-SRV6-R2-1）。所以 `DstIP = SegmentList[n-1]`，**不是** `SegmentList[0]`。

例：SR Policy `<S1, S2, S3>`，List 编码 `[S3, S2, S1]`（List[0]=S3, List[1]=S2, List[2]=S1）。源节点 DstIP = S1（第一段）= `List[2]` = `List[n-1]`。

文档说 `DstIP = List[0]`，等价于 `DstIP = S3`（最后一段），与 RFC 完全相反。

**影响**：
- 与 C-SRV6-R2-1 连带，整个地址解析链错误。
- 若照此实现，tshark 解析显示 DstIP 是最终目的而不是第一跳，与 RFC 8754 §4.1 矛盾，Wireshark 可能标"malformed SRH"或目的不可达。

**修复建议**：
1. §2.1 DstIP 行改为："Destination Address | segment_list[n-1] 或 dst_ipv6 | 源节点发送时 DstIP = Segment List[n-1]（即第一个要处理的 segment，因 List 反序存储在最高索引）"。
2. §3.1 DstIPv6 注释改为："Empty = SegmentList[n-1] (the first segment to process, stored at the highest index because the list is in reverse order per RFC 8754 §2.3)."
3. §3.3 S3 改为："DstIPv6 空 → SegmentList[n-1]"。
4. §6.1 / §6.2 断言改为"DstIP = SegmentList[n-1]"。

---

### C-SRV6-R2-3：SRH PadN TLV 类型错误（应是 4，非 1）

**位置**：§2.4 TLV 格式表（第 78 行）、§2.4 PadN 说明（第 83 行）、§3.1 SRv6TLV Type 注释（第 190 行）、§6.14 E6/E7（第 545-546 行）、§7.2 V-N-11/V-N-12（第 594-595 行）、§8.1 检查清单（第 738 行）

**描述**：文档 §2.4 表格写"PadN（Type=1）"，§2.4 第 83 行写"PadN（Type=1）：N≥2 字节填充"，§3.1 SRv6TLV 注释写"0=Pad1, 1=PadN, 5=HMAC, 6=HMAC-Sig"，§8.1 检查清单写"PadN（Type=1）Type+Len+N-2 字节 0"。

**依据**：RFC 8754 §2.1.1.2 + §8.2 IANA 注册表：

| Type | 描述 |
|------|------|
| 0 | Pad1 |
| 1-3 | Reserved |
| 4 | **PadN** |
| 5 | HMAC |
| 6 | Reserved |
| 124-126 | Experimentation and Test |
| 127 | Reserved |
| 252-254 | Experimentation and Test |
| 255 | Reserved |

RFC 8754 §2.1.1.2 原文：
> "Type: 4"

注：RFC 8200 §4.2 的 Hop-by-Hop PadN 确实是 Type=1，但 RFC 8754 的 SRH 有独立的 TLV 注册表，PadN 是 Type=4。现有 `builder.go` 行 585 用 `0x01` 作为 PadN 是 Hop-by-Hop 路径（`serializeIPv6HopByHop`），SRH 必须用 `0x04`，两者不能混用。

文档 §2.4 把 SRH PadN 写成 Type=1，是把 Hop-by-Hop 的 PadN 类型错误移植到 SRH。

**影响**：
- 若实现者照此实现，SRH 帧中 PadN 字节 = 0x01，tshark 按 RFC 8754 解析会标"unknown TLV type 1 (Reserved)"，而非 PadN。
- 8 字节对齐填充变成"未知 TLV"，可能导致 tshark 解析中断或报 malformed。
- §6.14 E7 用户显式配 tlv type=1 报错"padN must not be set manually"，但用户配 type=4 反而不报错——逻辑完全颠倒（type=4 才是真 PadN，type=1 是 Reserved 不应让用户随便填）。

**修复建议**：
1. §2.4 表格 Type 列改为："0=Pad1，4=PadN，5=HMAC"。
2. §2.4 第 83 行改为："PadN（Type=4）：N≥2 字节填充，Length = N-2，Value 全 0。"
3. §3.1 SRv6TLV 注释改为："0=Pad1, 4=PadN, 5=HMAC"。
4. §6.14 E6 改为"tlv type=0 报错 pad1 must not be set manually"，E7 改为"tlv type=4 报错 padN must not be set manually"。
5. §7.2 V-N-11 改为"tlv type=0"，V-N-12 改为"tlv type=4"。
6. §8.1 检查清单改为"PadN（Type=4）Type+Len+N-2 字节 0"。

---

### C-SRV6-R2-4：SRH HMAC Flag 虚构（Flags 全部 Unused）

**位置**：§2.2 表格 Flags 行（第 39 行）、§3.1 Flags 字段注释（第 139-141 行）、§3.3 S8（第 222 行）、§6.11 配置（第 474 行）、§6.11 断言（第 482 行）、§6.13 B11/B12（第 524-525 行）、§7.1 V-P-07（第 570 行）、§7.2 V-N-09（第 592 行）、§8.1 检查清单（第 736 行）

**描述**：文档多处声明 SRH Flags bit 0 = HMAC。例如：
- §2.2 第 39 行：`"Flags | 0x00 | RFC 8754 §2.1 仅定义 Bit 0 = HMAC（其余必须 0）"`
- §3.1 第 139-141 行：`"Flags is the 8-bit SRH Flags field. RFC 8754 §2.1 defines only bit 0 (HMAC). Other bits must be 0. 0x00 / 0x01."`
- §6.11 第 474 行配置 `"flags": 1`，第 482 行断言"Flags bit 0 = 1（HMAC）"
- §6.13 B11"Flags bit 0 = 1（HMAC） → 通过"，B12"Flags bit 1 = 1（保留） → 报错"
- §7.1 V-P-07"HMAC TLV + Flags.HMAC=1 → Validate 返回 nil"
- §7.2 V-N-09"flags bit 1=1（保留位） → 'reserved flag bit must be 0'"
- §8.1 第 736 行"Flags 仅 bit 0 定义（HMAC），其余必须 0"

**依据**：RFC 8754 §2.1 原文：

> "Flags: 8 bits of flags."
> "U: Unused and for future use. MUST be 0 on transmission and ignored on receipt."

RFC 8754 §2.1 的 Flags 字段图示全部 8 位都标注为 "U"（Unused），**没有任何定义位**。HMAC 机制由独立的 HMAC TLV（Type=5）携带，HMAC TLV 内部有一个 D 位（1 bit，表示 reduced SRH 的 DA verification disabled），但这是 HMAC TLV 的 D 位，不是 SRH Flags 的位。

文档把"HMAC"虚构为 Flags bit 0，与 RFC 8754 矛盾。可能是误把 HMAC TLV 的存在性当作 Flags 位，或混淆了其他协议的 flag 设计。

**影响**：
- §6.11 配置 `flags: 1` 实际违反 RFC 8754（必须为 0），若照此实现 tshark 会标"Flags: 0x01 (Unused bits set)"。
- §7.2 V-N-09"flags bit 1=1 报错"逻辑反了——bit 0=1 也应报错（所有位都 unused），但文档允许 bit 0=1。
- §7.1 V-P-07"HMAC TLV + Flags.HMAC=1 → 通过"语义错误，应改为"HMAC TLV + Flags=0 → 通过"。

**修复建议**：
1. §2.2 Flags 行改为："Flags | 0x00 | RFC 8754 §2.1 全部 8 位 Unused，MUST be 0；HMAC 由 TLV（Type=5）携带，不由 Flags 表示"。
2. §3.1 Flags 注释改为："Flags is the 8-bit SRH Flags field. RFC 8754 §2.1 defines ALL 8 bits as Unused (MUST be 0 on transmission). HMAC is carried by the HMAC TLV (Type=5), not by a flag bit. Validate rejects any non-zero Flags value."
3. §3.3 S8 改为"Flags 空 → 0x00；非 0 → Validate 报错 'flags must be 0 (RFC 8754 §2.1)'"
4. §6.11 配置删除 `"flags": 1`，断言改为"Flags = 0x00"。
5. §6.13 B11 改为"Flags=0x01 → Validate 报错"，B12 删除（bit 1 不需要单独测，整体非 0 即报错）。
6. §7.1 V-P-07 改为"HMAC TLV + Flags=0 → Validate 返回 nil"。
7. §7.2 V-N-09 改为"flags=0x01 → 'flags must be 0 (RFC 8754 §2.1)'"。
8. §8.1 改为"Flags 全 8 位 Unused（MUST be 0）"。

---

### C-SRV6-R2-5：HMAC-Sig TLV（Type=6）虚构

**位置**：§2.4 TLV 格式表（第 78 行）、§2.4 HMAC 签名说明（第 85 行）、§3.1 SRv6TLV 注释（第 190 行）

**描述**：文档 §2.4 表格写"HMAC 签名 TLV（Type=6）"，§2.4 第 85 行写"HMAC 签名 TLV（Type=6）：32 字节 HMAC-SHA-256 截断；v1 留空或全 0"，§3.1 SRv6TLV 注释写"6=HMAC-Sig"。

**依据**：RFC 8754 §8.2 IANA 注册表：

| Type | 描述 |
|------|------|
| 0 | Pad1 |
| 1-3 | Reserved |
| 4 | PadN |
| 5 | HMAC |
| 6 | **Reserved** |

RFC 8754 §2.1.1.2 注："Values 1, 2, 3, and 6 were defined in draft versions" — 即 Type=6 在 draft 阶段曾有定义，但 RFC 最终发布时已 Reserved。RFC 8754 只定义 3 个 TLV：Pad1 / PadN / HMAC，**不存在 HMAC-Sig TLV**。

文档虚构了一个不存在的 TLV 类型，可能是误抄了 draft-ietf-6man-segment-routing-header-xx 早期版本。

**影响**：
- 若实现者照此实现 type=6 的 TLV，tshark 按 RFC 8754 解析会标"Reserved TLV type 6"。
- 用户配 tlv type=6 时 Validate 行为未定义（文档未列入 V-N 负向，也未列入 V-P 正向）。

**修复建议**：
1. §2.4 表格删除"HMAC 签名 TLV（Type=6）"行。
2. §2.4 第 85 行删除"HMAC 签名 TLV"整段说明。
3. §3.1 SRv6TLV 注释改为"0=Pad1, 4=PadN, 5=HMAC"。
4. 新增 §7.2 V-N 用例：tlv type=6 → 报错"reserved TLV type 6 must not be set"（与 type=2/3 同处理）。

---

### C-SRV6-R2-6：Reduced SRH 语义错误（省略的是第一段，非 List[0]）

**位置**：§6.7（第 411-419 行）、§7.1 V-P-15（第 578 行）、§7.10 T-SRV6-NEW-17（第 722 行）

**描述**：文档 §6.7 写"外层 SRH 的 Segment List 可省略（依赖 DstIP 携带当前 segment）"，断言"Reduced 模式仅在外层 SRH 中省略 SegmentList[0] 的字节（RFC 8754 §6.1），Hdr Ext Len 相应减少 2（16 字节 / 8）"。§7.10 T-SRV6-NEW-17 断言"外层 SRH 省略 SegmentList[0]（字节 48+ 仅 1 段 16 字节）；Hdr Ext Len = (8+16-8)/8 = 2；DstIP = SegmentList[0]（与省略段一致）"。

**依据**：RFC 8754 §4.1.1（Reduced SRH）原文：
> "A reduced SRH does not contain the **first segment** of the related SR Policy (the first segment is the one already in the DA of the IPv6 header)"
> "the Last Entry field is set to n-2, where n is the number of elements in the SR Policy"

即 reduced SRH 省略的是**第一段**（first segment to process），而第一段在 Segment List 中位于最高索引 `List[n-1]`（因 List 反序存储，见 C-SRV6-R2-1）。所以 reduced SRH 省略的是 `List[n-1]`，**不是 `List[0]`**。

文档说"省略 SegmentList[0]"，因 C-SRV6-R2-1 顺序颠倒，恰好省略了错误的段——文档省略的是最后一段（List[0]），而 RFC 要求省略第一段（List[n-1]）。

另外 RFC 8754 §4.1.1 说 reduced SRH 的 Last Entry = n-2（不是 n-1），Segments Left 仍 = n-1（§4.1 通用规则）。文档 §6.7 / §7.10 T-SRV6-NEW-17 完全没提 Last Entry = n-2 这条 RFC 强制规则。

还有：RFC 8754 §4.1.1 没有任何"End.B6.Encaps.Red"的提法——End.B6.Encaps.Red 是 RFC 8986 定义的 SID 行为，与 reduced SRH 是两个概念。文档 §6.7 把"End.B6.Encaps.Red"等同于"reduced SRH"是概念混淆。reduced SRH 是 SRH 编码格式（任何 SID 都可用 reduced SRH），End.B6.Encaps.Red 是 SID 行为（封装时使用 reduced SRH）。两者关系：End.B6.Encaps.Red 在外层封装时**可以**使用 reduced SRH，但 reduced SRH 不是 End.B6.Encaps.Red 专属。

**影响**：
- 若照此实现 reduced SRH，省略错误的段（最后一段而非第一段），生成的帧语义错误，tshark 按 RFC 8754 §4.1.1 解析会标"reduced SRH missing first segment"。
- Last Entry 字段值错误（应为 n-2，文档未提及）。
- Hdr Ext Len 计算错误（§7.10 T-SRV6-NEW-17 算 (8+16-8)/8=2，但 reduced SRH 2 段 n=2 时 Last Entry=n-2=0，省略 List[n-1]=List[1] 后只剩 List[0]，Hdr Ext Len = (8+16-8)/8 = 2，恰好算对——但这是因为 §7.10 用 2 段举例且省略了 List[0] 凑巧对上，逻辑仍是错的）。

**修复建议**：
1. §6.7 改为："Reduced SRH（RFC 8754 §4.1.1）省略 SegmentList[n-1]（第一段，已在 DstIP 中），Last Entry = n-2，Segments Left 仍 = n-1。例：SR Policy `<S1, S2>`（n=2），List 编码 [S2]（仅 1 项，省略 S1），Last Entry = 0，Segments Left = 1，DstIP = S1。"
2. §7.10 T-SRV6-NEW-17 改为："seg_type=end.b6.encaps.red + 2 段 SR Policy <S1, S2> → 外层 SRH reduced 编码：SegmentList = [S2]（仅 1 项，S1 省略），Last Entry = 0，Segments Left = 1，DstIP = S1，Hdr Ext Len = (8+16-8)/8 = 2。"
3. §7.1 V-P-15 补充"reduced SRH 模式下 Last Entry = n-2"断言。
4. §6.7 末尾补充说明："End.B6.Encaps.Red（RFC 8986）是在 End.B6.Encaps 封装时使用 reduced SRH 的 SID 行为，与 reduced SRH 编码格式是两个概念。"

---

### C-SRV6-R2-7：§2.3 End* 行为地址更新公式与 RFC 8754 不一致

**位置**：§2.3 End 行为表（第 52 行）、§4 状态机（第 240 行）、§6.3 断言（第 360 行）

**描述**：文档 §2.3 End 行写"SegmentsLeft--，DstIP = SegmentList[LastEntry-SegmentsLeft+1]"，§4 状态机写"SL--, DstIP=S[SL]"，§6.3 断言"IPv6 DstIP = fc00:s2::1（SegmentList[1]，End 处理后下一跳）"。

**依据**：RFC 8754 §4.3.1.1（SRH Processing）伪代码 S15-S16：
> S15: "Decrement Segments Left by 1."
> S16: "Copy Segment List[Segments Left] from the SRH to the destination address of the IPv6 header."

即：先 SL 减 1（S15），再用减 1 后的新 SL 值索引 `SegmentList[SL_new]` 复制到 DA（S16）。公式是 `DA = SegmentList[SL_new]`，其中 `SL_new = SL_old - 1`。

文档公式 `DstIP = SegmentList[LastEntry - SegmentsLeft + 1]` 在 RFC 反序存储下：
- 设 n=3，LastEntry=2（n-1），SL_old=2，SL_new=1。
- RFC 公式：`DA = SegmentList[1]`（SL_new=1）。
- 文档公式：`DA = SegmentList[2 - 2 + 1] = SegmentList[1]`（SL_old=2，未减 1）。

两者在非 reduced SRH 下恰好相等（因 LastEntry = n-1，公式可化简为 `List[LastEntry - SL_old + 1] = List[n-1 - SL_old + 1] = List[n - SL_old] = List[SL_new]` 因为 SL_new = SL_old - 1，n - SL_old = n - SL_new - 1，与 SL_new 不等... 实际化简：在反序存储下 List[i] = 第 (n-i) 个处理的段；RFC SL_new 索引的是第 (n - SL_new) = (n - SL_old + 1) 个段；文档 LastEntry - SL_old + 1 = n-1 - SL_old + 1 = n - SL_old，索引 List[n - SL_old] = 第 (n - (n - SL_old)) = SL_old 个段，按反序即倒数第 SL_old 个 = 第 (n - SL_old + 1) 个段——恰好相等）。

所以文档公式在非 reduced SRH 下**等价于** RFC 公式。但在 reduced SRH 下 LastEntry = n-2 ≠ n-1，文档公式失效（会索引错误段）。

更根本的问题：文档公式用 LastEntry 表达，但 RFC 公式只用 SL，不涉及 LastEntry。文档引入 LastEntry 是多余且易错的——reduced SRH 下 LastEntry 改变但 RFC 行为不变。

另外文档 §4 状态机写"S[SL]"含义不清（是 SL 减 1 前还是后？），与 §2.3 公式不一致。

**影响**：
- 非 reduced SRH 下碰巧等价，但 reduced SRH 下会算错地址。
- 文档两个公式（§2.3 用 LastEntry，§4 用 SL）表述不一致，实现者可能照任一实现，reduced SRH 下行为不同。

**修复建议**：
1. §2.3 End 行改为："SegmentsLeft--，DstIP = SegmentList[SegmentsLeft]（SL 减 1 后的新值索引 List，RFC 8754 §4.3.1 S15-S16）"。
2. §4 状态机改为"SL := SL - 1; DstIP := SegmentList[SL]（RFC 8754 §4.3.1 S15-S16）"。
3. §6.3 断言保留"DstIP = SegmentList[1]"但补充注释"（SL=2 减 1 后 SL_new=1，索引 List[1]）"。
4. 删除所有用 LastEntry 表达的地址更新公式，统一用 SL。

---

## 3. HIGH 问题（6 项）

### H-SRV6-R2-1：Hdr Ext Len 公式与 RFC 8754 §2.1 表述不一致

**位置**：§2.2 Hdr Ext Len 行（第 35 行）、§2.2 Hdr Ext Len 计算说明（第 44 行）、§6.13 B6/B7（第 519-520 行）

**描述**：文档 §2.2 写"Hdr Ext Len = (总长-8)/8"，§2.2 计算说明写"总长 = 8 + 16N + T，向上对齐到 8 字节倍数（Pad TLV 填充），Hdr Ext Len = (总长 - 8) / 8"。

**依据**：RFC 8754 §2.1 原文：
> "TLVs are present when the Hdr Ext Len is greater than (Last Entry+1)*2."
> "max_last_entry = ( Hdr Ext Len / 2 ) - 1"

即 RFC 8754 的标准关系式是 `Hdr Ext Len = (Last Entry + 1) * 2`（无 TLV 时），等价于 `Hdr Ext Len = 2N`（N = 段数 = Last Entry + 1），即 `Hdr Ext Len = (总长 - 8) / 8`（因总长 = 8 + 16N，(8+16N-8)/8 = 2N）。文档公式 `(总长-8)/8` 数值上正确。

但文档 §2.2 的"总长 = 8 + 16N + T，向上对齐到 8 字节倍数"表述有歧义：TLV 长度 T 不是任意值，必须满足 `(16N + T) % 8 == 0`（即 T 必须使总长对齐到 8 字节），PadN TLV 用于补齐。文档写"向上对齐到 8 字节倍数（Pad TLV 填充）"暗示 T 是任意值再补齐，但 RFC 8754 §2.1.1 PadN 是 TLV 的一种，T 已包含 PadN 字节，不应再"向上对齐"。

更严重的是 §6.13 B7 写"127 段 + 大 TLV → (8+16*127+T-8)/8 ≤ 254（N=127 无 TLV 时 = 254）"。这里"T"未定义上限，若 T 很大（如 200 字节），(8+2032+200-8)/8 = 2232/8 = 279 > 255 溢出，但 B7 说"≤ 254"暗示不会溢出——实际 127 段加任何 TLV 都可能溢出 Hdr Ext Len 8-bit 上限。B7 的"≤ 254"是错误断言（无 TLV 时 = 254，加 TLV 必然 > 254 溢出）。

**影响**：
- §6.13 B7"127 段 + 大 TLV 通过"是错误的——127 段 + 任何 TLV 都会 Hdr Ext Len 溢出。
- §7.6 T-SRV6-BND-07"127 段 → Hdr Ext Len = 254 ≤ 255"通过，但若加 TLV 就溢出，B7 未覆盖此场景。
- 实现者可能允许 127 段 + TLV 的配置通过 Validate，导致 builder 生成 Hdr Ext Len 溢出的非法帧。

**修复建议**：
1. §2.2 计算说明改为："Hdr Ext Len = (8 + 16N + T - 8) / 8 = 2N + T/8，其中 T 是所有 TLV（含 PadN）总字节数，T 必须使 (16N + T) 是 8 的倍数。"
2. §6.13 B7 改为"127 段 + 任意 TLV → Validate 报错 'hdr_ext_len overflow (max 255)'（127 段 Hdr Ext Len=254，加任何 TLV 都溢出）"。
3. 新增 §6.13 边界用例"126 段 + 16 字节 TLV → Hdr Ext Len = 2*126 + 2 = 254，通过"。

---

### H-SRV6-R2-2：§7.3 T-SRV6-P-09 Direction="down" 断言与 §3.1 Direction 默认值矛盾

**位置**：§3.1 Direction 字段（第 184-185 行）、§7.3 T-SRV6-P-09（第 617 行）、§7.5 T-SRV6-MF-04（第 652 行）

**描述**：§3.1 第 184-185 行 Direction 注释写"Direction is the flow direction: 'up' (default) or 'down' (swaps MACs, IPs, ports)"。§7.3 T-SRV6-P-09 断言"Direction='down' → MAC/IP/Port 全部 swap"。§7.5 T-SRV6-MF-04 断言"Count=10，Direction='down' → 每流 MAC/IP/Port swap"。

**问题**：Direction="down" 在 SRv6 下的 swap 语义未定义清楚——Swap 时 IPv6 SrcIP 和 DstIP 都交换吗？那 SegmentList 是否也整体反转？RFC 8754 没定义"反向流"概念，SRv6 的反向流语义由 trafficgen 自己决定。

更严重的是：若 Direction="down" 只 swap SrcIP/DstIP 不动 SegmentList，则反向流的 DstIP ≠ SegmentList[n-1]（违反 RFC 8754 §4.1 源节点规则）。若 Direction="down" 同时反转 SegmentList，则反向流的 List[0]/List[n-1] 互换，但文档没说这一点。

**依据**：RFC 8754 §4.1 源节点规则要求 DstIP = SegmentList[n-1]（第一段）。Direction="down" 若只 swap SrcIP/DstIP，反向流 DstIP = 原 SrcIP（不是任何 segment），违反 RFC 8754。

**影响**：
- 实现者不知道 Direction="down" 时 SegmentList 该如何处理。
- §7.3 T-SRV6-P-09 / §7.5 T-SRV6-MF-04 断言"swap"未定义 swap 范围，测试无法写。

**修复建议**：
1. §3.1 Direction 注释补充："SRv6 反向流语义：Direction='down' 时 SrcIP↔DstIP 交换，SegmentList 整体反转（原 List[n-1] 变 List[0]），SegmentsLeft 重置为 n-1，使反向流仍满足 RFC 8754 §4.1 源节点规则（DstIP = 新 List[n-1]）。"
2. §7.3 T-SRV6-P-09 断言补充："SegmentList 反转；DstIP = 反转后 List[n-1] = 原 List[0] = 原最终目的"。
3. §7.5 T-SRV6-MF-04 同步补充。

---

### H-SRV6-R2-3：§7.4 T-SRV6-BYT-01 单 segment 字节布局偏移错误

**位置**：§7.4 T-SRV6-BYT-01（第 629 行）

**描述**：§7.4 T-SRV6-BYT-01 断言"字节 0-39 IPv6 头 NH=43；40-63 SRH（24 字节）；64+ payload"。

**问题**：单 segment SRH = 8（固定头）+ 16×1（1 段）= 24 字节。字节偏移 40-63 是 24 字节，数学正确。但文档没考虑同时配置 HopByHop 的情况——§7.1 V-P-14 / §7.3 T-SRV6-P-12 / §8.2 检查清单都说"HopByHop 与 SRH 共存"是合法配置，此时字节 40 之后是 HopByHop 头（变长），SRH 在 HopByHop 之后，偏移不再是 40。

T-SRV6-BYT-01 假设"无 HopByHop"，但用例描述没说"无 HopByHop"，实现者可能误以为该断言对任意配置都成立。

**依据**：RFC 8200 §4.3 Hop-by-Hop 在 IPv6 固定头之后（NH=0），SRH 在 HopByHop 之后（HopByHop NH=43）。链式：IPv6(40B) → HopByHop(变长) → SRH → 内层。

**影响**：测试用例描述不严谨，实现者可能在 HopByHop 共存场景误用 BYT-01 的偏移。

**修复建议**：
1. §7.4 T-SRV6-BYT-01 描述补充"（无 HopByHop 配置）"。
2. 新增 §7.4 T-SRV6-BYT-16："IPv6 + HopByHop + SRH 字节布局 → 字节 0-39 IPv6 NH=0；40+ HopByHop（变长，含 PadN 对齐 8 字节）；HopByHop 之后 SRH（NH=43 指向 SRH）；SRH 之后 payload"。

---

### H-SRV6-R2-4：§2.1 IPv6 头 Next Header 字段 Traffic Class 偏移错误

**位置**：§2.1 IPv6 固定头部表（第 20 行）

**描述**：§2.1 表第 20 行写"Offset=0, 长度=8 bit, 字段=Traffic Class"。但 IPv6 头前 4 bit 是 Version（第 19 行 Offset=0, 4 bit），Traffic Class 是接下来的 8 bit（实际偏移 4 bit，即字节 0 的高 4 bit 后）。

文档表格 Offset 用"0"既表示 Version 又表示 Traffic Class，但 Version 占 4 bit，Traffic Class 应从 bit 4 开始。RFC 8200 §3 图示：

```
|Version| Traffic Class |     Flow Label     |
|  4b   |     8b        |       20b          |
```

字节 0 = Version(4) + Traffic Class 高 4 bit；字节 1 = Traffic Class 低 4 bit + Flow Label 高 4 bit。

文档表 Offset=0 给 Version（4 bit），Offset=0 给 Traffic Class（8 bit）——两个 Offset 都是 0，但实际 Traffic Class 跨字节 0-1。

**依据**：RFC 8200 §3。

**影响**：实现者可能误以为 Traffic Class 在字节 0 整 8 bit（实际跨字节 0-1）。现有 `builder.go` 行 990-991 `tc := (config.L3.DSCP << 2) | (config.L3.ECN & 0x03); dst[0] = (6 << 4) | (tc >> 4); dst[1] = (tc << 4) | 0` 编码正确，但设计文档表格误导。

**修复建议**：
1. §2.1 表 Traffic Class 行 Offset 改为"0.4"（bit 偏移）或"0-1"（字节范围），说明"跨字节 0 高 4 bit + 字节 1 低 4 bit"。
2. 同理 Flow Label Offset 改为"1.4"或"1-3"。

---

### H-SRV6-R2-5：§3.1 SegmentList 上限 127 但 SegmentsLeft 注释说"0..126 in practice"

**位置**：§3.1 SegmentList 字段（第 113-116 行）、§3.1 SegmentsLeft 字段（第 118-131 行）、§3.1 LastEntry 字段（第 134-137 行）

**描述**：§3.1 SegmentList 注释"1..127 entries"，SegmentsLeft 注释"0..126 in practice (SegmentList max 127 entries → source-node SegmentsLeft max 126)"，LastEntry 注释"0..126 (SegmentList max 127 entries → LastEntry max 126)"。

**问题**：LastEntry = len(SegmentList) - 1 = 126（当 N=127）。但 SegmentsLeft 在源节点 = n - 1 = 126（当 N=127），两者都是 126——这点文档对。

但 reduced SRH 下 LastEntry = n - 2 = 125（当 N=127），文档 §3.1 LastEntry 注释"0..126"未涵盖 reduced SRH 场景。更严重的是 §6.13 B2"SegmentsLeft=126 满值，segment_list 长度 127 → 通过"，但 reduced SRH 下 N=127 时 SL 仍 = 126（RFC §4.1 通用规则），LastEntry = 125，文档 B2 未提 reduced 模式。

**依据**：RFC 8754 §4.1.1 reduced SRH Last Entry = n-2。

**影响**：reduced SRH 大段数场景的 LastEntry 边界未覆盖。

**修复建议**：
1. §3.1 LastEntry 注释补充"0..126 (non-reduced) / 0..125 (reduced SRH, Last Entry = n-2 per RFC 8754 §4.1.1)"。
2. §6.13 新增 B22"reduced SRH 127 段 → LastEntry=125, SL=126, Validate 通过"。

---

### H-SRV6-R2-6：§7.4 T-SRV6-BYT-15 Pad1 单字节填充场景与 RFC 8754 PadN 强制规则矛盾

**位置**：§7.4 T-SRV6-BYT-15（第 643 行）、§2.4 Pad1 说明（第 82 行）

**描述**：§7.4 T-SRV6-BYT-15 断言"Pad1 单字节填充：当 TLV 需 1 字节对齐时，出现 0x00 单字节"。§2.4 第 82 行"Pad1（Type=0）：单字节填充，无 Length/Value"。

**依据**：RFC 8754 §2.1.1.1 原文：
> "A single Pad1 TLV MUST be used when a single byte of padding is required."

RFC 8754 §2.1.1.2 原文：
> "The PadN TLV MUST be used when more than one byte of padding is required."

即：1 字节填充必须用 Pad1（Type=0），≥2 字节填充必须用 PadN（Type=4）。文档 §2.4 / §7.4 BYT-15 表述与 RFC 一致。

但 §6.14 E6"tlv type=0 报错'pad1 must not be set manually (builder auto-inserts)'"——这是说**用户**不能手动设 type=0，但 builder 自动插入 Pad1 是允许的。这与 RFC 8754 §2.1.1.1 一致（Pad1 由实现自动插入）。

但问题在 §7.4 BYT-15 的触发条件：SRH 总长 = 8（固定头）+ 16N（段）+ T（TLV），需对齐到 8 字节。需 1 字节填充的场景：16N + T mod 8 == 7。但 16N mod 8 == 0（16 是 8 的倍数），所以填充需求由 T mod 8 决定。若 T = 7（如 HMAC TLV 部分），需 1 字节 Pad1。

但 HMAC TLV（Type=5）的 Length 是 4 字节 HMAC Key ID + 变长 HMAC（8 的倍数，最多 32）= 12/16/20/24/28/32/36 字节，T = 2（Type+Len）+ 上述 = 14/18/.../38 字节。T mod 8 = 6/2/.../6。需 2 字节填充时用 PadN（Type=4），需 1 字节填充时用 Pad1（Type=0）。

但 RFC 8754 §2.1.2 HMAC TLV 有"8n alignment"要求（HMAC TLV 必须对齐到 8 字节边界）。这意味着 HMAC TLV 之前若有未对齐字节，需先 PadN 再 HMAC。Pad1 仅在 HMAC 之后凑 1 字节时使用。

§7.4 BYT-15 没说 Pad1 触发场景，实现者可能误以为任意 1 字节填充都用 Pad1，但实际 HMAC TLV 8n 对齐要求可能改变填充策略。

**影响**：测试用例描述不严谨，HMAC TLV 8n 对齐规则未在文档任何地方提及。

**修复建议**：
1. §2.4 HMAC TLV 说明补充"RFC 8754 §2.1.2 HMAC TLV 要求 8n 对齐（alignment = 8n），即 HMAC TLV 起始偏移必须是 8 的倍数"。
2. §7.4 BYT-15 描述补充"触发场景：HMAC TLV 之后总长 mod 8 == 7（需 1 字节填充）"。
3. 新增 §7.4 BYT-16"HMAC TLV 8n 对齐：HMAC TLV 起始偏移是 8 的倍数（PadN 填充 HMAC 之前的未对齐字节）"。

---

## 4. MEDIUM 问题（5 项）

### M-SRV6-R2-1：§7 测试用例未覆盖 RFC 8754 §2.3 反序存储的核心断言

**位置**：§7 全部用例

**描述**：§7 共 107 条用例，没有一条断言"SegmentList 按反序存储"这一 RFC 8754 §2.3 核心规则。所有 BYT-* 用例只断言"字节 48+ 按配置顺序 16 字节一段"（§7.4 BYT-08），但"配置顺序"在文档语义下是正序（C-SRV6-R2-1 错误），RFC 要求反序。

**依据**：RFC 8754 §2.3 + CLAUDE.md §1（spec 驱动：每个 RFC 字段至少一个测试）。

**影响**：实现者可能照文档正序实现，tshark 解析报错，但测试全绿（因测试也按正序断言）——典型的"测试测错了对象"反模式（CLAUDE.md §8）。

**修复建议**：
1. 新增 §7.4 BYT-17："3 段 SR Policy <S1, S2, S3> → SRH Segment List 字节顺序 = S3 S2 S1（反序，RFC 8754 §2.3）；DstIP = S1 = SegmentList[n-1] = SegmentList[2]"。
2. §7.4 BYT-08 改为"字节 48+ 按反序存储（List[0]=最后一段在字节 48-63，List[n-1]=第一段在字节 48+16(n-1)）"。

---

### M-SRV6-R2-2：§3.1 SegmentsLeftSet bool 字段方案不如 *uint8 指针

**位置**：§3.1 SegmentsLeft 字段（第 118-132 行）、§3.3 S4（第 218 行）

**描述**：v1.1 引入 `SegmentsLeftSet bool` 区分"未设置"与"显式 0"。这种 bool 伴随字段方案在 Go 里可行但不优雅——用户配 JSON 时必须同时设 `segments_left: 0` 和 `segments_left_set: true` 两个字段，易漏。

**依据**：Go 惯用 `*uint8` 指针（nil = 未设置，非 nil = 显式值含 0）。现有 trafficgen 代码中 `L2Config.Pad *bool`（types.go 行 1122）就是这种模式。

**影响**：用户接口冗余，易因漏设 `segments_left_set` 导致默认值覆盖显式 0。

**修复建议**：把 `SegmentsLeft uint8` + `SegmentsLeftSet bool` 改为 `SegmentsLeft *uint8`（nil = 默认 len-1，非 nil = 显式值含 0）。同步 §3.3 S4、§7.10 NEW-05/06/13。

---

### M-SRV6-R2-3：§3.1 LastEntry 默认值规则未覆盖 reduced SRH

**位置**：§3.1 LastEntry 字段（第 134-137 行）、§3.3 S5（第 219 行）

**描述**：§3.1 LastEntry 注释"Source node sets it to len(SegmentList)-1"，§3.3 S5"LastEntry 空 → len(SegmentList)-1"。

**依据**：RFC 8754 §4.1.1 reduced SRH 下 Last Entry = n-2，不是 n-1。文档默认值规则未区分 reduced / non-reduced。

**影响**：reduced SRH 场景下 LastEntry 默认值错误（应为 n-2，文档默认 n-1）。

**修复建议**：§3.3 S5 补充"non-reduced SRH: len-1; reduced SRH (seg_type=end.b6.encaps.red): len-2 (RFC 8754 §4.1.1)"。

---

### M-SRV6-R2-4：§7.2 V-N-13 / V-N-15 / V-N-20 InnerPayload 边界断言弱

**位置**：§7.2 V-N-13 / V-N-15 / V-N-20（第 596/598/603 行）

**描述**：V-N-15"seg_type=end.b6 inner_payload < 40 字节 → 报错"，V-N-20"seg_type=end.dx6 inner_payload < 40 字节 → 报错"。但 40 字节是 IPv6 头最小长度，断言合理。问题在 V-N-13"payload_protocol=none + inner_payload 非空 → 报错"——这条断言过严，RFC 8754 没规定 NoNextHeader 时不能有 payload（实际上 NoNextHeader=59 表示"无后续头"，但 payload 字节仍可存在于 IPv6 Payload Length 字段覆盖范围内）。

**依据**：RFC 8200 §4.7 "No Next Header"："If, as a result of processing a header, the destination header is encountered and the Next Header field value is 59, the packet is discarded."——即 NoNextHeader 时**packet 应被丢弃**，但不是"payload 必须为空"。文档 V-N-13 把"应被丢弃"误读为"必须为空"。

**影响**：实现者可能在 Validate 阶段拒绝合法的 NoNextHeader + payload 配置。

**修复建议**：
1. §7.2 V-N-13 改为"payload_protocol='none' + inner_payload 非空 → Validate 警告 'payload_protocol=none with non-empty inner_payload: packet will be discarded per RFC 8200 §4.7'（不报错，v1 宽松）"。
2. §6.14 E15 同步改为"警告，不报错"。

---

### M-SRV6-R2-5：§8.6 测试质量审计清单未覆盖 RFC 8754 §4.3.1 SRH 处理伪代码

**位置**：§8.6（第 781-790 行）

**描述**：§8.6 列出 8 条测试质量审计项，但未包含"SRH 处理伪代码 S01-S26 每步是否有对应测试"。RFC 8754 §4.3.1 定义了 SRH 处理伪代码 26 步（S01-S26），包括 S01 (SL=0 时若 DA!=local 则 forward)、S05 (if NH==58 drop)、S09 (max_last_entry 检查)、S11 (if SL==0 → continue)、S12 (if local address match → S15)、S15 (SL--)、S16 (DA=List[SL])、S17 (decrement Hop Limit)、S25 (forward) 等。

trafficgen 不实现节点处理逻辑（只生成报文），但 §2.3 End* 行为表声称"模拟节点处理后的报文形态"——即生成 End 节点处理后的帧。这需要按 S15-S16 公式更新 DA 和 SL。§8.6 没要求测试这些公式。

**依据**：CLAUDE.md §1 spec 驱动 + RFC 8754 §4.3.1。

**影响**：§6.3 End 节点视角用例的 DA 更新公式可能错误（C-SRV6-R2-7）而测试不覆盖。

**修复建议**：§8.6 新增第 9 条："RFC 8754 §4.3.1 SRH 处理伪代码 S15-S16 (DA 更新) 在 End 节点视角用例中是否有断言？验证：§6.3 End 节点 DstIP = SegmentList[SL_new]，SL_new = SL_old - 1"。

---

## 5. LOW 问题（3 项）

### L-SRV6-R2-1：§2.2 表格 Tag 字段说明"0x0000..0xFFFF"冗余

**位置**：§2.2 Tag 行（第 40 行）

**描述**：§2.2 Tag 行写"0x0000..0xFFFF"——16-bit 字段的值域显然是 0x0000..0xFFFF，无需说明。

**修复建议**：删除"0x0000..0xFFFF"，改为"任意 16-bit 值；0 = 无标签"。

---

### L-SRV6-R2-2：§6.13 B2 "SegmentsLeft=126 满值"措辞误导

**位置**：§6.13 B2（第 515 行）

**描述**：§6.13 B2 写"SegmentsLeft=126 满值"——但 SegmentsLeft 是 uint8，理论值域 0..255，"满值"应是 255。文档把 126 称"满值"是因为 SegmentList 上限 127 → SL 上限 126，但措辞容易误解为"uint8 满值"。

**修复建议**：B2 改为"SegmentsLeft=126（SegmentList 127 段时源节点最大值，受 Hdr Ext Len 8-bit 限制）"。

---

### L-SRV6-R2-3：§7.10 T-SRV6-NEW-14 seg_type="end.t" 断言弱

**位置**：§7.10 T-SRV6-NEW-14（第 719 行）

**描述**：§7.10 T-SRV6-NEW-14 断言"seg_type='end.t'（未支持行为）→ Validate 通过（v1 仅做格式生成，不做语义校验）"。但 §2.3 表把 End.T 列为"v1 实现重点支持 9 个"之一——即 End.T 是**已支持**行为，不是"未支持"。NEW-14 把 End.T 标"未支持"与 §2.3 矛盾。

**修复建议**：§7.10 NEW-14 改为"seg_type='end.un'（v1 未支持的 20 个行为之一）→ Validate 通过（仅做 seg_type 字符串合法性检查，不做 End* 语义校验）"。

---

## 6. 字段覆盖率与测试用例质量

### 6.1 SRH 8 字段覆盖率

| # | 字段名 | RFC 8754 章节 | 设计文档章节 | Config 字段 | 测试用例 | 覆盖状态 |
|---|--------|--------------|------------|-------------|---------|---------|
| 1 | Next Header | §2 | §2.2 | SRHConfig.NextHeader | P-10/P-11/P-12/BYT-01 | ✓ |
| 2 | Hdr Ext Len | §2 | §2.2 | builder 计算 | P-01/P-02/BYT-02/BND-07 | ✓（但公式表述 H-SRV6-R2-1） |
| 3 | Routing Type | §2 | §2.2 | SRHConfig.RoutingType | BYT-03/V-N-19 | ✓ |
| 4 | Segments Left | §2 | §2.2 | SRv6Config.SegmentsLeft | P-02/P-03/P-15/B-04 | ✓ |
| 5 | Last Entry | §2 | §2.2 | SRv6Config.LastEntry | P-02/P-03/B-02 | ✓（但 reduced SRH 未覆盖 H-SRV6-R2-5） |
| 6 | Flags | §2.1 | §2.2 | SRv6Config.Flags | V-P-08/V-N-09/B-06 | ✗ HMAC Flag 虚构（C-SRV6-R2-4） |
| 7 | Tag | §2.1 | §2.2 | SRv6Config.Tag | V-P-08/P-07/B-07 | ✓ |
| 8 | Segment List | §2.3 | §2.2 | SRv6Config.SegmentList | P-01..P-09/B-08 | ✗ 顺序与 RFC 相反（C-SRV6-R2-1） |

**8 字段中 6 字段覆盖，2 字段（Flags / Segment List）有 RFC 事实错误**。

### 6.2 107 条用例的 CLAUDE.md 8 条规则核查

| 规则 | 覆盖状态 |
|------|----------|
| §1 spec 驱动 | ✗ Segment List 反序存储零断言（M-SRV6-R2-1）；RFC 8754 §4.3.1 伪代码 S15-S16 零断言（M-SRV6-R2-5）；HMAC TLV 8n 对齐零断言（H-SRV6-R2-6） |
| §2 失败路径 | ✓ V-N 20 条覆盖负路径 |
| §3 一测一路径 | ✗ V-N-19 测 builder 层 RoutingType，但 planner Validate 不检查 RoutingType（v1.0 已指出，v1.1 未修） |
| §4 集成测试 | ✓ E2E 8 条 |
| §5 可观察值 | ✗ §6.1 DstIP=SegmentList[0] 字节断言错误（C-SRV6-R2-2）；§6.7 reduced SRH 字节布局错误（C-SRV6-R2-6） |
| §6 并发正确性 | ✓ MF-05 GroupID 单 worker 顺序；AUD-04 速率断言 |
| §7 失败优先 | ✓ AUD-05 失败测试先例 |
| §8 测试质量审计 | ✓ AUD-01..08 8 条元测试；但未覆盖 RFC 8754 §4.3.1 伪代码（M-SRV6-R2-5） |

### 6.3 v1.1 修复情况核查

v1.1 自称修复 v1.0 全部 14 个问题，核查如下：

| v1.0 审计 ID | v1.1 修复状态 | 说明 |
|--------------|--------------|------|
| C-SRV6-1（用例虚胖） | ✓ 已修 | §7.7 EXC 删除，§7.6 BND-01..06 删除，总数 106→90 |
| C-SRV6-2（Hdr Ext Len 自报错误） | ✓ 已修 | §6.1 直接写正确值 2 |
| H-SRV6-1（SegmentList[0] 语义矛盾） | ✗ **修复反而引入更严重错误** | v1.0 写"反序"虽表述混乱但方向正确（List[0]=最后一段），v1.1 改为"正序"（List[0]=第一段）后整个语义模型与 RFC 相反（C-SRV6-R2-1） |
| H-SRV6-2（Hdr Ext Len 单位表述不清） | ✓ 已修 | §2.2 补充"不含前 8 字节"说明 |
| H-SRV6-3（MPLS 互斥理由错误） | ✓ 已修 | §9.2 改为"v1 不实现字节布局" |
| H-SRV6-4（GRE 互斥理由矛盾） | ✓ 已修 | §9.2 改为"v1 不实现字节布局" |
| M-SRV6-1（seg_type 数字不一致） | ✓ 已修 | §2.3 改为"29 个 End* 行为"，新增 NEW-01/02/14/17 |
| M-SRV6-2（Frames 负数未测） | ✓ 已修 | §3.1 补充注释，新增 NEW-09 |
| M-SRV6-3（InnerSrcPort 默认值未测） | ✓ 已修 | §3.1 补充注释，新增 NEW-03/04 |
| M-SRV6-4（SegmentsLeft 0 歧义） | ✓ 已修 | §3.1 新增 SegmentsLeftSet bool，新增 NEW-05/06/13 |
| M-SRV6-5（B7 Hdr Ext Len 溢出错误） | ✓ 已修 | §6.13 B2 改为 127 段，B4 改为 128 段报错 |
| L-SRV6-1（B 与 BND 编号冲突） | ✓ 已修 | §7.4 重命名为 BYT |
| L-SRV6-2（B5 报错信息不准确） | ✓ 已修 | §6.13 B5 改为"too large for 8-bit hdr_ext_len" |
| L-SRV6-3（E2E-07 硬编码网卡） | ✓ 已修 | §7.8 改为环境变量，新增 NEW-15 |

**14 个 v1.0 问题中 13 个已修复，1 个（H-SRV6-1）修复反向引入更严重错误**。

但 v1.1 暴露了 **21 个新问题**（7 CRITICAL + 6 HIGH + 5 MEDIUM + 3 LOW），其中 7 个 CRITICAL 是 v1.0 审计完全未发现的 RFC 事实错误——v1.0 审计只看了"用例虚胖"和"内部矛盾"，没有逐字核对 RFC 8754 原文。这是 v1.0 审计的方法学缺陷。

---

## 7. 最终结论

### 7.1 严重度汇总

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 7 | C-SRV6-R2-1..7 |
| HIGH | 6 | H-SRV6-R2-1..6 |
| MEDIUM | 5 | M-SRV6-R2-1..5 |
| LOW | 3 | L-SRV6-R2-1..3 |
| **合计** | **21** | — |

### 7.2 必须返工的问题

**本设计文档不可直接进入实现阶段**。

必须先返工的问题编号（按优先级）：

**CRITICAL（必须修复，否则实现必然错误）**：
1. C-SRV6-R2-1（Segment List 顺序与 RFC 相反）
2. C-SRV6-R2-2（DstIP 与 SegmentList 关系错误）
3. C-SRV6-R2-3（PadN TLV Type 应为 4 非 1）
4. C-SRV6-R2-4（HMAC Flag 虚构，Flags 全 Unused）
5. C-SRV6-R2-5（HMAC-Sig TLV Type=6 不存在）
6. C-SRV6-R2-6（Reduced SRH 语义错误）
7. C-SRV6-R2-7（End* 地址更新公式与 RFC 不一致）

**HIGH（建议修复，否则测试与实现有歧义）**：
8. H-SRV6-R2-1（Hdr Ext Len 公式与 B7 矛盾）
9. H-SRV6-R2-2（Direction="down" SRv6 swap 语义未定义）
10. H-SRV6-R2-3（BYT-01 字节偏移未排除 HopByHop 共存）
11. H-SRV6-R2-4（IPv6 头 Traffic Class 偏移错误）
12. H-SRV6-R2-5（LastEntry reduced SRH 边界未覆盖）
13. H-SRV6-R2-6（HMAC TLV 8n 对齐规则未提及）

**MEDIUM / LOW** 可在实现阶段同步修复。

### 7.3 根因分析

本设计文档的根本问题是 **没有逐字核对 RFC 8754 原文**。设计者可能参考了 secondary sources（博客、其他实现、draft 版本），导致：
1. Segment List 顺序：误用 MPLS 标签栈"正序"心智模型（MPLS 是后入先出，SRH 是前向反序存储）。
2. HMAC Flag：可能误把 HMAC TLV 的存在性当作 Flag 位，或混淆了其他协议。
3. PadN Type=1：误把 Hop-by-Hop（RFC 8200）的 PadN Type 移植到 SRH（RFC 8754 的 PadN Type=4）。
4. HMAC-Sig TLV Type=6：可能误抄 draft-ietf-6man-segment-routing-header 早期版本（draft 中 Type=6 曾有定义，RFC 最终发布时 Reserved）。
5. Reduced SRH：因 Segment List 顺序错误连带 reduced SRH 语义错误（省略错误的段）。
6. End* 地址公式：用 LastEntry 表达而非 SL，reduced SRH 下失效。

v1.0 审计的方法学缺陷是 **只看了内部一致性（用例虚胖、表述矛盾），没有逐字核对 RFC 原文**。本次 R2 审计通过 WebFetch 逐字核对 RFC 8754 / RFC 8200 原文，发现了 v1.0 审计漏掉的 7 个 CRITICAL。

### 7.4 修复优先级建议

修复顺序（依赖关系）：
1. **先修 C-SRV6-R2-1**（Segment List 顺序）：这是根本性错误，其他 5 个 CRITICAL（C-SRV6-R2-2/6/7、H-SRV6-R2-1 部分、M-SRV6-R2-1）都依赖此修复。
2. **再修 C-SRV6-R2-2**（DstIP 关系）：依赖 C-SRV6-R2-1。
3. **再修 C-SRV6-R2-6**（Reduced SRH）：依赖 C-SRV6-R2-1/2。
4. **再修 C-SRV6-R2-7**（End* 公式）：依赖 C-SRV6-R2-1。
5. **并行修 C-SRV6-R2-3/4/5**（TLV 类型 + Flags）：独立问题，不依赖顺序。
6. **最后修 HIGH/MEDIUM/LOW**。

修复后建议重跑 R3 审计，重点核查：
- Segment List 反序存储的字节断言
- DstIP = SegmentList[n-1] 的字节断言
- PadN Type=4 的字节断言
- Flags=0 的强制断言
- Reduced SRH 省略 List[n-1] 的字节断言
- HMAC TLV 8n 对齐的字节断言

---

**审计完成时间**：2026-08-04
**审计员**：独立协议审计员（R2 深度对抗审计）
**审计依据**：RFC 8754 / RFC 8200 / RFC 8986 原文（WebFetch 逐字核对）+ CLAUDE.md 测试策略 8 条
**问题总数**：21（CRITICAL 7 + HIGH 6 + MEDIUM 5 + LOW 3）
**最终结论**：**不可直接进入实现阶段**，必须先返工 7 个 CRITICAL + 6 个 HIGH 共 13 个问题。

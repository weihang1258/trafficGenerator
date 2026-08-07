# SRv6 设计文档复审审计报告（R3 / v2.0.0）

**审计对象**：`/home/weihang/trafficGenerator/docs/protocol-designs/15-srv6-design.md`（1543 行，v2.0.0，声称 130 条用例 + 15 个 HexDump 场景）
**审计日期**：2026-08-05
**审计人**：独立协议审计员（复审，默认"有 bug"）
**审计依据**：
1. **RFC 8754**（SRH）— 已 WebFetch 逐字核对：§2 SRH 结构 / §2.1 Flags 与 TLV / §2.1.1 Pad1/PadN / §2.1.2 HMAC TLV（Length 定义、8n 对齐、D bit）/ §2.3 Segment List 反序 / §4.1 源节点（n 的定义）/ §4.1.1 Reduced SRH / §4.3.1 S15-S16 / §8.2 IANA 注册表
2. **RFC 8200**（IPv6）— §3 固定头 / §4.2 TLV（Hop-by-Hop PadN=1）/ §4.4 Routing Header（Hdr Ext Len）/ Next Header 值表
3. **RFC 8986**（SRv6 Network Programming）— End.DX6（内层 IPv6 必须 Upper-Layer header type=41）/ End.DX4（=4）/ End.B6.Encaps（RFC 2473 规则）
4. **CLAUDE.md** 测试策略 8 条
5. 前次审计报告 `audit/15-srv6-audit-deep.md`（21 问题）及 `audit/11-15-dnp3-srv6-audit.md`
6. `trafficgen/internal/core/builder.go` 现有 HopByHop 实现（Pad1=0x00/PadN=0x01，RFC 8200 §4.2，正确）

---

## 1. 审计概览

### 1.1 严重度分布

| 严重度 | 数量 | 说明 |
|--------|------|------|
| CRITICAL | 2 | RFC 8754 事实错误：HMAC TLV Length 语义错误（38≠36）；End.DX6/End.DX4 封装 Next Header=59 违反 RFC 8986（应为 41/4），S6/S10 HexDump 按错误值构造 |
| HIGH | 8 | HexDump 自洽性批量错误（S2/S12/S13/S4 四帧 Payload Length 溢出）；reduced SRH 在 Reduced 标志自动置位与 LastEntry 显式覆盖间的自相矛盾；Pad1 禁止用户设置但配置语法无法表达；S15 Frame 2/5 描述与 S15-S16 公式矛盾；§3.2.1 公式行 2N+T/8-1 歧义（与 2N+T/8 矛盾）；N 上限推导含 128 段无法编码的歧义行；EXC-01"显式 HdrExtLen"与 SRHConfig 无 HdrExtLen 字段矛盾；Direction="down" 反转 SegmentList 设计缺陷（S15-S16 在中转视角失效） |
| MEDIUM | 7 | IPv6 校验和未提；UDP/TCP 校验和"IPv6 伪头"未排除 SRH 是否参与校验和的争议；VR-15/VR-22 与 RFC 8986 §4.1.1"仅 decaps 处理"矛盾；PayloadProtocol=icmpv6 无构建细节；FlowID 含"协议号"但 SRH 不是 L4；srv6_segment_count=len(SRHConfig.SegmentList) 在 reduced SRH 下把"wire 段数"与"SR Policy 段数"混用；报告字段 total_segments 对 reduced 流统计口径错误；S4/S14 的 UDP 数据报长度为 0 无说明 |
| LOW | 4 | S1 草稿式"Wait, 重算"文字残留（§6.1 596-616 行）；SRHConfig.SegmentList 用 []string 且类型注释与 SRv6TLV 定义顺序不一致；"文档总行数：见文件末尾"占位符；§10.2 report 断言挂到 AUD-02 而 AUD-02 实际断言的是任务状态与 pcap 内容 |
| **合计** | **21** | — |

### 1.2 总体结论

**本设计文档不可直接进入实现阶段。**

v2.0.0 对 v1.1 的 7 个 CRITICAL 协议根本性错误（反序存储、DstIP、PadN Type、Flags、HMAC-Sig、Reduced SRH、S15-S16 公式）的修复**方向正确、表述与 RFC 8754 原文一致**——重点核查项 1/2/3/4/5/7/8（反序、DstIP、PadN=4、Flags、Type=6 Reserved、Hdr Ext Len、HMAC 8n 对齐）全部确认无误。但本次复审发现 **2 个新的 CRITICAL**（HMAC TLV Length=38 与 RFC 8754 明文 Length=36 矛盾；End.DX6/End.DX4 外层 Next Header=59 违反 RFC 8986），以及 **8 个 HIGH**（含 4 帧 HexDump 的 IPv6 Payload Length 自相矛盾——这是上一轮审计漏掉的字节级硬伤，且§6.1 用"Wait"草稿式修正过的 HexDump 恰好在 S2/S12/S13 又复制了同一错误）。

---

## 2. CRITICAL 问题（2 项，必须返工）

### C-SRV6-R3-1：HMAC TLV 结构自相矛盾——"D+RES+KeyID+HMAC"与"38 字节、Length=36"两者不可同时成立

**位置**：§2.4.4 表（164-167 行）、§5.1 SRv6TLV 注释（"HMAC（8n alignment，see §2.4.4）"）、§6.4 S4 字段构成（742 行）与 HexDump（756 行）、§6.14 S14 字段构成（1116 行）与 HexDump（1130 行）、§7.6 BND-09（1315 行）

**描述**：同一文档内部出现三套互相冲突的 HMAC TLV 字节数：

1. **§2.4.4 表（161-166 行）**：`Length = 后续字段总字节数（D+RES+KeyID+HMAC = 4+4+HMAC_len）`。RFC 8754 §2.1.2 的 Length 定义是"the length of the variable-length data in bytes"，即 **Type/Length 之后的所有字节**——按此定义 D+RES(2) + KeyID(4) + HMAC(32) = **38**，Length 字段应写 38（0x26）。文档表此处"4+4+HMAC_len"又是错的（4+4+32=40≠38，且把 2 字节 D+RES 算成 4）。
2. **§6.4 S4（742 行）**："HMAC TLV：Type=5 + Length=36 + D(1bit)+RES(15bit)=0x0000 + KeyID=0x00000001 + HMAC(32B 0) = **2+36 = 38 字节**"。Length=36、TLV 总长 38。
3. **§6.4 S4 HexDump（756 行）**：offset 64-103 共 40 字节 = Type(1)+Length(1)+D+RES(2)+KeyID(4)+HMAC(32)。按 3 套数字逐字节核算：**总长 40 ≠ 38**；Length 字段 `0x24`=36，但 Type/Length 之后实际字节数是 **38**（2+4+32），36 ≠ 38。

再叠加 §7.6 BND-09："Single segment + 1 TLV（**HMAC 36 字节 + PadN 2 字节**）Hdr Ext Len = (8+16+38+2-8)/8 = 56/8 = 7"——这里把"HMAC TLV 36 字节"与"38+2"混写，且按 BND-09 分子 38 推回 HMAC TLV 是 38 字节（2+36），与 S4 的 38 一致、但与 HexDump 的 40 字节不一致。

**依据**：RFC 8754 §2.1.2 原文（WebFetch 逐字核对）：
> "Length: The length of the variable-length data in bytes."
> "HMAC: Keyed HMAC, in multiples of 8 octets, at most 32 octets."

HMAC TLV 完整布局 = Type(1) + Length(1) + D|RESERVED(2) + HMAC Key ID(4) + HMAC(32) = **40 字节**；Length 字段 = 2+4+32 = **38 (0x26)**；HMAC 最小 8 字节（"multiples of 8 octets, at most 32 octets"）→ 最短 HMAC TLV = 2+2+4+8 = 16 字节。

**影响**：
- S4/S14 HexDump 中 HMAC TLV 区标"05 24"（Type=5, Length=36=0x24）。0x24=36 与 RFC 要求的 38 不符。若实现照 Length=36 编码，Wireshark/tshark 会按 36 字节读 Value，把 HMAC 的最后 2 字节（offset 102-103）错划入后续 PadN，导致 TLV 解析错位、SRH 总长与 Hdr Ext Len 对不上，报 malformed。
- 若实现照 HexDump 的 40 字节总长实现而 Length 写 36，则自相矛盾（RFC 校验 Length 语义即失败）。
- 8 字节对齐计算（S4/S14 的 62→64）在 38 字节模型下成立，在 40 字节模型下是 8+16+40=64 直接对齐、**无需 PadN**——HexDump 末尾的 PadN `04 00`（offset 104-105）在正确模型下根本不该出现。整段 S4/S14 的"需 PadN 补 2 字节"逻辑基于错误的 38 字节模型。
- §2.4.4 表"4+4+HMAC_len"同时自洽性失败（4+4+32=40，但 D+RES 实际 2 字节）。

**修复建议**：
1. §2.4.4 表改为：`Length = 2（D+RES）+ 4（Key ID）+ HMAC_len；HMAC_len ∈ {8,16,24,32}`，并注明 HMAC 必须为 8 的倍数（RFC 8754 §2.1.2 "multiples of 8 octets"——文档"8/16/24/32"未列 8 的最小值下限之外，还应明确 HMAC 长度由用户 Value 长度决定，不与"截断"混为一谈）。
2. §6.4 S4 重算：TLV 总长 = 2+2+4+32 = **40 字节**；SRH 总长 = 8+16+40 = **64**（已 8n 对齐，无 PadN）；Hdr Ext Len = 64/8-1 = **7**（保留原值，但删除 PadN 字节）；HexDump 末尾 `04 00` 删除；Payload Length 同步修正（见 H-SRV6-R3-1）。
3. §6.14 S14 同步重算（同样 40 字节 TLV，无 PadN；HexDump 末尾 `04 00` 删除）。
4. §7.6 BND-09 改为"HMAC TLV 40 字节 → Hdr Ext Len = (8+16+40-8)/8 = 7"。
5. 补一条字节级用例：HMAC TLV Length 字节 = 0x26（=38），TSRV6-BYT 新增"HMAC Length 字段 = 38（D+RES+KeyID+HMAC）"。

---

### C-SRV6-R3-2：End.DX6 / End.DX4 外层 SRH Next Header = 59（NoNextHeader）违反 RFC 8986——解封装类行为的 InnerPayload 必须用 41/4 标识

**位置**：§6.6 S6 配置（830 行 `payload_protocol: "none"`）与字段构成（843 行"外层 NextHeader = 59（NoNextHeader，InnerPayload 是裸 IPv6 包）"）、§7.3 T-SRV6-P-04（1253 行"SRH NextHeader=59"）、§6.6 HexDump offset 40 = `3b`（851 行）、§6.10 S10 同款（962 行、980 行）

**描述**：End.DX6（解封装到 IPv6）的外层 SRH 携带内层完整 IPv6 包时，文档规定外层 Next Header = 59（NoNextHeader），理由是"InnerPayload 是裸 IPv6 包"。End.B6.Encaps（S10）同样规定外层 SRH Next Header = 59。End.DX4（T-SRV6-NEW-01，1359 行）则正确写了 Next Header = 4（IPv4）。

**依据**：RFC 8986（WebFetch 逐字核对）：
- End.DX6（RFC 8986 §4.4）：`"If (Upper-Layer header type == 41(IPv6))"` 才执行解封装——**内层 IPv6 由外层 Next Header 值 41 标识**（IANA "Assigned Internet Protocol Numbers" 注册表：41 = IPv6 encapsulation）。
- End.DX4（RFC 8986 §4.5）：`"If (Upper-Layer header type == 4(IPv4))"`——值 4 = IPv4。
- 若 Next Header 不是 41/4，RFC 8986 明文要求转入 §4.1.1（普通 End 处理），**不执行解封装**——即 Next Header=59 的包永远到不了 DX6 的解封装动作，配置语义直接失效。

RFC 8200 §4.7：Next Header=59 表示"nothing following"，接收端丢弃；文档 §8.1 VR-22 自己也承认"packet will be discarded per RFC 8200 §4.7"。因此"外层 SRH NextHeader=59 + 裸 IPv6 InnerPayload"在两条 RFC 下都是自相矛盾：59 意味着无后续内容，而 41 才是封装 IPv6。

**影响**：
- S6/S10 的 HexDump 按 `3b`（59）构造，tshark 会把 InnerPayload 判为 No Next Header 之后的残余字节，DX6 语义不成立；实现者照抄后生成的帧在真实 SRv6 网络中无法触发解封装。
- 与文档自己的 NEW-01（End.DX4 → NextHeader=4）形成双重标准：IPv4 内层用 4，IPv6 内层却用 59。
- §9.4 互斥表把 End.DX6 的 InnerPayload 标为"裸 IPv6 包"（843 行），与 SRH.NextHeader=41 的语义矛盾。

**修复建议**：
1. §6.6 S6 配置改 `payload_protocol` 为支持 `"ipv6"`（外层 SRH Next Header = 41），或在内层为 IPv6 包时默认 Next Header=41；HexDump offset 40 改为 `29`（41）。
2. §6.10 S10（End.B6.Encaps）同步：外层 SRH Next Header = 41（RFC 8986 End.B6.Encaps 依 RFC 2473 封 IPv6 包）。
3. §7.3 T-SRV6-P-04 断言改为"SRH NextHeader=41"。
4. §7.2 新增负向用例：seg_type=end.dx6 且 payload_protocol="none"（NextHeader=59）→ Validate 报错或警告"end.dx6 requires Next Header 41 (IPv6 encapsulation)"。
5. PayloadProtocol 枚举补充 "ipv6"（值 41），并与 none 区分；§5.1 字段注释同步。

---

## 3. HIGH 问题（8 项）

### H-SRV6-R3-1：S2 / S12 / S13 / S4 四帧 HexDump 的 IPv6 Payload Length 与 SRH+内层长度矛盾（字节级硬伤）

**位置**：§6.2 S2（647 行 HexDump，Payload Length=`00 44`）、§6.12 S12（1032 行，同 `00 44`）、§6.13 S13（1074 行，`07 f8`）、§6.4 S4（752 行，`00 38`）；§6.1 S1（609 行，`00 28`，已自修正确）

**描述**：按文档自身定义"IPv6 Payload Length = SRH 长度 + 内层 L4 头 + payload"（§7.4 BYT-12），逐帧核算：

| 场景 | Payload Length 字段 | SRH | 内层 L4 | 隐含 payload | 判定 |
|------|---------------------|-----|---------|--------------|------|
| S2（TCP） | 0x0044=68 | 56 | TCP 20 | **68-56-20 = -8** | ✗ 溢出 |
| S12（TCP） | 0x0044=68 | 56 | TCP 20 | **-8** | ✗ 溢出 |
| S13（127 段） | 0x07F8=2040 | 2040 | UDP 8 | **-8** | ✗ 溢出 |
| S4（HMAC TLV） | 0x0038=56 | 64 | UDP 8 | **-16** | ✗ 溢出 |
| S1（单段 UDP） | 0x0028=40 | 24 | UDP 8 | +8 | ✓（S1 无 payload 声明，但 8 字节残留可容忍） |
| S7（End 视角） | 0x0040=64 | 56 | UDP 8 | 0 | ✓ |
| S15（5 段） | 0x0060=96 | 88 | UDP 8 | 0 | ✓ |

S2 的 TCP 头 20 字节 + SRH 56 字节已经 76 > 68；S13 的 SRH 2040 + UDP 8 已经 2048 > 2040。S4 的 `00 38`=56 < 64+8=72（即使按文档自己的 64 字节 SRH 模型也溢出；若按 RFC 正确的 40 字节 HMAC TLV 模型 SRH 仍为 64，同样溢出）。**任何真实 builder 生成的帧都不可能满足这些 HexDump**——payload 为负意味着字段值必然比实际小 8/16 字节，或 SRH 长度与字段构成部分不一致。

**根因**：§6.1 在草稿 HexDump 里发现 Hdr Ext Len 写错后"Wait, 重算"修正（596-616 行），但把错误复制进 S2/S12 时把 Payload Length 也一并照抄（S2 与 S1 的 `00 44` 系从 `00 28` 按"TCP 头 20 字节"推算错位）；S13/S4 是新增场景时未重算。

**依据**：RFC 8200 §3 Payload Length = "Length of the IPv6 payload... in octets"（含扩展头）。文档 §7.4 BYT-12 自己断言"= SRH 长度 + 内层 L4 + payload 长度"。

**影响**：
- 测试按 HexDump 字节断言（§7.4 BYT-*、AUD-03 序列化后字节比对）会得到与 RFC 不符的"期望值"；而 tshark 按 Payload Length 截包，E2E 用例的包会被截断、校验和计算范围错误。
- 实现者按文档实现 Payload Length 必然与测试期望冲突，或被迫"将错就错"生成溢出帧——两种路径都产生 malformed 包。

**修复建议**：逐帧重算 Payload Length：
- S2/S12：`56 + 20 + payload`（文档未定义 payload 长度，需补一个明确的 payload 值，如 8 → `00 54`；或把 HexDump 改为不含 payload 的 TCP 空负载 → `00 4C`=76）。
- S13：`2040 + 8 + payload` → ≥ `08 00`（2048），或声明 payload 为 0 → `08 00`。
- S4：64+8=72 → `00 48`；S14 同理（若 HMAC TLV 修正为 40 字节后 SRH 64，Payload Length=72）。
- 补一条 BYT 用例：每个 HexDump 场景断言 Payload Length == SRH 长度 + L4 + payload。

---

### H-SRV6-R3-2：Reduced 标志自动置位与 LastEntry 显式覆盖的矛盾——S3 场景的 LastEntry 值与配置规则冲突

**位置**：§6.3 S3 配置（675-681 行）、§5.3 S5（523 行）、§3.2 SRH 格式表 LastEntry 行（205 行）、§5.1 SRv6Config.Reduced 注释（418-422 行）

**描述**：§5.3 S5 定义"LastEntryPtr=nil → reduced SRH (Reduced=true): len(SegmentList)-2"。S3 场景配置了 `reduced: true` 但**没有显式 LastEntry**——按规则 LastEntry 应为 2-2=0，字段构成也写"LastEntry = n-2 = 0"，字节 44 = `00`。这条链本身自洽。

但文档没有定义 **Reduced 标志自动置位** 的规则：当用户配 `last_entry_ptr` 显式为 n-2 或 `seg_type=end.b6.encaps.red` 时，Reduced 是否自动为 true？§6.3 场景标题是"Reduced SRH"，`seg_type` 是 `end.b6.encaps.red`——此时若用户只配 seg_type 不配 reduced，LastEntry 默认值规则（S5）走 non-reduced 分支（len-1），而 seg_type 语义暗示 reduced——两条默认规则对同一字段给出不同结果，文档未定义优先级。

**影响**：
- 实现者选择任意一条规则都能通过文档的 S3 测试（S3 两个标志同时显式设置），但用户"只配 seg_type=end.b6.encaps.red"的配置会得到 LastEntry=n-1 的错误帧（reduced SRH 应 n-2）。
- §7.2 V-P-15（seg_type=end.b6.encaps.red + Reduced=true + 2 段）也是双标志同时设置，掩盖了该缺口。

**修复建议**：在 §5.3 增加明确规则："Reduced 默认值 = (SegType == "end.b6.encaps.red")；用户显式配 reduced 时以用户值为准"；补用例：seg_type=end.b6.encaps.red + reduced 未设置 → LastEntry=n-2。

---

### H-SRV6-R3-3：Pad1（Type=0）禁止用户设置但 SRv6TLV 配置语法无法表达"builder 自动插入"的输入——BYT-15 不可实现

**位置**：§5.1 SRv6TLV（483-492 行）、§7.2 V-N-11（1232 行）、§7.4 BYT-15（1286 行）、§2.4.2（138-144 行）

**描述**：§7.4 BYT-15 断言"Pad1（Type=0）单字节填充：当 TLV 需 1 字节对齐时，出现 0x00 单字节"。但 §5.1 SRv6TLV 是 `{Type uint8, Value []byte}`——用户 TLV 列表里**没有任何字段能触发 builder 插入 Pad1**，且 §7.2 V-N-11 明确禁止用户写 type=0。§2.4.2 说"Pad1 MUST be used when a single byte of padding is required"，但 §3.2.1 的填充模型只提到"由 PadN TLV 补齐"（221 行），Builder 对齐逻辑的规范里完全没提 Pad1 何时插入（只有 BYT-15 一条断言"当 TLV 需 1 字节对齐时出现 0x00"）。

**依据**：RFC 8754 §2.1.1.1："A single Pad1 TLV MUST be used when a single byte of padding is required" / "Must NOT be used if more than one consecutive byte is needed"。HMAC TLV 8n 对齐（§2.4.4）保证 HMAC 起始对齐，但 HMAC 之后的尾部填充若 SRH 总长 mod 8 == 7（如 HMAC TLV 后剩 1 字节），必须用 Pad1 而非 PadN。文档对"builder 尾部填充用 Pad1 还是 PadN"没有任何规则。

**影响**：实现者按文档只有 PadN 填充模型实现，遇到 mod 8 == 7 场景（HMAC=40 字节时 SRH 总长 = 8+16+40 = 64 已对齐，但 2 段 + HMAC 40 字节 = 8+32+40=80 已对齐；3 段 + HMAC 40 = 8+48+40=96 对齐；HMAC=8 字节时 1 段 = 8+16+2+2+4+8=40 已对齐——尾部 1 字节填充实际出现在 HMAC 8 字节+1 段+自定义 TLV 等组合）会产出 PadN 填 1 字节（PadN Length=0 是允许的？RFC 8754 §2.1.1.2 Length 范围 0..5，PadN 单字节合法但违反 MUST-use-Pad1），tshark 不报错但 RFC 合规性失败。

**修复建议**：
1. §3.2.1 填充模型补充："尾部填充 1 字节用 Pad1（Type=0），≥2 字节用 PadN（Type=4）（RFC 8754 §2.1.1.1/.2）"。
2. 补用例：构造 SRH 总长 mod 8 == 7 的配置（如 2 段 + HMAC(8 字节) → 8+32+16=56？56 mod 8=0；1 段 + HMAC 8 字节 = 8+16+16=40 mod 8=0；实际上 1 段 + 自定义 TLV 1 字节 + …；或 HMAC 24 字节 1 段 = 8+16+2+2+4+24=56 mod 8=0；HMAC 16 字节 1 段 = 48 mod 8=0。1 段 + HMAC 32 = 64。需要 TLV 组合使 16N+T mod 8 == 7——如 1 段 + 实验 TLV Value=5 字节：8+16+2+5=31 mod 8=7，尾部 Pad1 1 字节 → 32），断言出现单字节 0x00 且无 Length。

---

### H-SRV6-R3-4：S15 Frame 2 / Frame 5 描述与 S15-S16 公式及 S7 模型矛盾

**位置**：§6.15（1178-1189 行）

**描述**：S15 说"Frame 2（S1 处理后）：仅 offset 24-39（DstIP）变为 fc00:s2::1，offset 43（SL）变为 03；其余不变"。但按 RFC 8754 §4.3.1 S15-S16 与文档自己的 §4.2 公式：S1 节点处理后 SL=3，**DstIP = SegmentList[SL_new=3]**——即第 4 个处理段 S4，不是 S2！S15 的 Frame 2 写"S1 处理后 DstIP=S2"用的是 v1.1 已废弃的"LastEntry-SL+1"错误公式的残留（=List[4-3+1]=List[2]=S3？不，按反序 List=[B,S4,S3,S2,S1]，List[2]=S3，Frame 2 写 S2=List[3]，对 SL=3 应 List[3]=S2——等等，重新算：SL_new=3 → DA=List[3]=S2。所以 Frame 2 的 DstIP=S2 恰好与"DA=List[SL_new=3]"一致！）。

再核对 Frame 2：SL_new = 4-1 = 3，DA = List[3] = S2（wire List=[B,S4,S3,S2,S1]，List[3]=S2）✓——Frame 2 正确。Frame 3：SL=2，DA=List[2]=S3 ✓。Frame 4：SL=1，DA=List[1]=S4 ✓。Frame 5：SL=0，DA=List[0]=B ✓。**S15 的五帧 DstIP 全部正确**。

真正的问题在 Frame 2 的文字："仅 offset 24-39（DstIP）变为 fc00:s2::1，offset 43（SL）变为 03；**其余不变**"——"其余不变"与 §6.7 S7 的模型矛盾：S7（3 段 SL=2→1）要求用户显式设 `dst_ipv6`（885-886 行），S15 的 Frame 2 却无此要求。更关键的是 S15 场景声明"1 条 FlowSpec + Frames=5 + 视角递增"时（1147 行），§5.1 Frames 字段注释只定义"Hop Limit 递减 / 内层 IPID 递增"（470-471 行），**没有"视角递增（SL 递减、DstIP 更新）"的定义**——Frames=5 的五帧内容是否按 S15 变化、由哪个配置驱动，文档未定义。

**依据**：§5.1 Frames 注释（"each gets a distinct Hop Limit / inner IP ID when applicable"）与 S15 的"视角递增"需求冲突。

**影响**：实现者按 §5.1 Frames 语义实现（仅 Hop Limit/IPID 变化），S15 的"5 帧 SL 递减"无法实现；按 S15 实现则 Frames 语义与 §5.1 冲突。E2E-10（tshark 捕获 5 包 SL 递减）无法用现有配置表达。

**修复建议**：S15 明确"视角递增"的配置驱动方式（如新增 frames_view 枚举，或声明 5 条 FlowSpec 是唯一实现路径），并把 Frame 2/5 的"其余不变"改为逐字段列明（SL、DstIP、Hop Limit）。

---

### H-SRV6-R3-5：§3.2.1 Hdr Ext Len 公式行 `2N + T/8 - 1` 与上/下行公式矛盾

**位置**：§3.2.1（219-220 行）

**描述**：文档先给出正确推导 `Hdr Ext Len = (8 + 16N + T)/8 - 1 = 2N + T/8`，下一行却写 `= 2N + T/8 - 1`。二者差 1。VR-18（1404 行）"non-reduced SRH: Hdr Ext Len = 2N + T/8 - 1"、VR-19（1405 行）"reduced: 2(N-1) + T/8 - 1"同样带了多余的 -1。BND-02（1308 行）"126 段 + 16 字节 TLV → Hdr Ext Len = 2×126 + 16/8 = 252+2 = 254"用的是 2N+T/8（正确式），与 VR-18 自相矛盾。

**验证**：取 §3.2.1 表第二行（N=2, T=0，SRH 总长 40）：正确式 2×2+0=4 ✓（表内"验证 (4+1)×8=40 ✓"），带 -1 的式子得 3 ✗。即**文档自己的计算示例证明 `-1` 是错的**。

**依据**：RFC 8200 §4.4：Hdr Ext Len = 8 字节单位数减去前 8 字节 → HEL = 总长/8 - 1，而 T 已含在总长内，公式为 2N + T/8（T 是 8 的倍数时）。文档 219 行的最终算式 `2N + T/8 - 1` 是把"总长/8 - 1"里的 -1 错误二次展开。

**影响**：VR-18/19 若照字面实现，合法配置（如 126 段 + 8 字节 TLV，HEL=253 正确式）会被误判为 252 或 254，边界判定错一；实现者按示例表实现则正确——两条路径不一致，测试会漂移。

**修复建议**：§3.2.1 与 VR-18/19 统一为 `Hdr Ext Len = 2N + T/8`（reduced: `2(N-1) + T/8`），删除 -1；BND-02 保留。

---

### H-SRV6-R3-6：EXC-01 "builder 收到显式 HdrExtLen" 与 SRHConfig 无 HdrExtLen 字段矛盾

**位置**：§5.2 SRHConfig（504-514 行，无 HdrExtLen 字段）、§7.7 EXC-01（1323 行）、§7.10 NEW-16（1374 行）、§9.2（1452 行）

**描述**：§9.2 / EXC-01 / NEW-16 规定 builder 报错 "hdr_ext_len mismatch"（"如显式 HdrExtLen=6 但实际只有 1 段"），但 §5.2 SRHConfig 结构体只有 NextHeader/RoutingType/SegmentsLeft/LastEntry/Flags/Tag/SegmentList/TLV/Reduced，**没有 HdrExtLen 字段**——builder 无从"收到显式 HdrExtLen"。这是 §9.2 与 §5.2 的字段表级矛盾。若 HdrExtLen 由 builder 自算，则"mismatch"检查没有输入可比较，该错误路径不存在，EXC-01/NEW-16 是不可实现的测试。

**依据**：§5.2 注释"builder 侧 SRHConfig…由 planner 在 Plan 时填入"，§9.2 却说 builder 校验"显式 HdrExtLen"。

**影响**：实现者写测试 NEW-16 时发现无处挂钩——要么给 SRHConfig 加 HdrExtLen 字段（违背"builder 自算"的 §3.2.1），要么删掉该错误路径。

**修复建议**：二选一：① SRHConfig 增加 `HdrExtLen uint8`（planner 计算填入，builder 复核），EXC-01 成立；② 删除 EXC-01/NEW-16 与 §9.2 该行，改为 builder 自算断言（内部不变式检查）。推荐①，与 §7.4 BYT 字节断言对齐。

---

### H-SRV6-R3-7：Direction="down" 反转 SegmentList 使 End 中转视角（SegmentsLeft 显式）下的 DstIP 更新公式失效

**位置**：§5.4（530-541 行）、§8.3 DD-01..06（1430-1437 行）、§7.3 P-09（1258 行）

**描述**：§5.4 定义 Direction="down" 时"SegmentList 整体反转、SegmentsLeft 重置为 n-1、DstIP = 反转后 List[n-1] = 原 List[0] = 原最终目的"。这在**源节点视角**下自洽（反转后新 List[n-1] 是新第一段=原最终目的，RFC 8754 §4.1 成立）。但若用户同时配 SegmentsLeftPtr（End 中转视角，§4.4 表格第 2-4 行），反转后"SegmentsLeft 重置为 n-1"会覆盖用户显式中转值，且 **DstIP 更新公式（S15-S16）要求 DstIP = List[SL_new]，反转后的 List 与用户显式 dst_ipv6 的对应关系未定义**——用户按正向路径配的"中间节点 S2 后 DstIP=S3"，反转流里没有任何规则告诉实现者该变成什么。

**依据**：RFC 8754 无"反向流"概念（前次审计 H-SRV6-R2-2 已指出语义需自行定义）；§5.4 只覆盖源节点视角。

**影响**：Direction="down" + 中转视角（End 行为模拟）的组合配置无定义，P-09/MF-04 用例只测源节点视角（SegmentsLeft 默认），掩盖缺口；实现者遇到组合配置时行为未定。

**修复建议**：§5.4 增加限制："Direction='down' 仅支持源节点视角（SegmentsLeftPtr 必须为 nil，否则 Validate 报错 'direction=down requires source-node view (segments_left not set)'）"，或完整定义反转下 End 视角的 DstIP 映射。补负向用例。

---

### H-SRV6-R3-8：§6.6 S6 HexDump 内层包 Payload Length=0x10 与"内层 UDP+payload 48+ 字节"冲突

**位置**：§6.6 S6 HexDump（853-855 行）、字段构成（844 行）

**描述**：S6 内层 IPv6 头 offset 64 起，`60 00 00 00 00 10 11 40`——内层 Payload Length = 0x0010 = 16 字节。但字段构成说"内层 = IPv6 头 40B + UDP 头 8B + payload，48+ 字节"，且外层 Payload Length（`00 38`=56）= 外层 SRH 24 + 内层 32 → 内层总长 32 字节 = 40 头 + 8 UDP + payload → **payload = -16，溢出**（与 H-SRV6-R3-1 同根因）。内层 Payload Length 0x10=16 与内层 UDP(8)+payload 合计 16 也不自洽（payload=8，内层 Payload Length 应为 8+8=16？若 UDP 头 8 + payload 8 = 16 ✓ 内层 40+16=56 字节，外层 Payload Length 应为 24+56=80，而非 56）。S6 整帧三处长度全部对不上。

**依据**：RFC 8200 §3 Payload Length 定义。

**影响**：实现者按 S6 HexDump 字节做 BYT 断言（内层 UDP 头位置、校验和范围）全部错位；tshark 按外层 Payload Length 截包，内层被截断。

**修复建议**：重算 S6：外层 Payload Length = 24 + 内层总长；内层 Payload Length = 8（UDP）+ payload；补齐明确的内层 UDP 头与 payload 字节。

---

## 4. MEDIUM 问题（7 项）

### M-SRV6-R3-1：IPv6 头校验和（IPv6 无校验和）未在文档说明，SRH 字段变更不影响任何校验和

**位置**：§3.1 IPv6 固定头（无校验和说明）、§7.4 BYT-13/14（仅 UDP/TCP 校验和）

**描述**：RFC 8200 §3 明确 IPv6 固定头无校验和（"no checksum field"），SRH 是扩展头也不参与任何校验和计算。文档 BYT-13/14 只测 UDP/TCP 校验和（含 IPv6 伪头），未声明"IPv6+SRH 无校验和、SRH 修改不改写任何校验和"这一实现约束。实现者若在 SRH 路径误加/误跳校验和逻辑会引入回归（builder 现有 IPv6 路径可能按 HopByHop 逻辑处理）。

**影响**：低风险但属 spec 驱动缺口（CLAUDE.md §1：RFC 8200 §3 每字段应有用例）。

**修复建议**：§3.1 补一句"IPv6 固定头无校验和（RFC 8200 §3），SRH 不参与任何校验和；BYT 补一条'SRH 存在时 IPv6 头无校验和字段'断言"。

### M-SRV6-R3-2：UDP/TCP 校验和伪头"Next Header"取值的歧义——SRH 参与与否未定义

**位置**：§7.4 BYT-13/14（1284-1285 行）

**描述**：RFC 8200 §8.1 IPv6 伪头含"Upper-Layer Packet Length"与"Next Header"——后者是**内层协议号**（6/17），不是外层 IPv6 头的 Next Header（43）。BYT-13 写"计算 IPv6 伪头（SrcIP+DstIP+Length+NextHeader）"未指明 NextHeader 用内层协议号（17）而非 43。而"Upper-Layer Packet Length"对带 SRH 的包：RFC 8200 伪头长度 = TCP/UDP 头+数据长度（不含 SRH）；但 SRH 处理中 UDP 校验和覆盖范围含伪头，若实现者把 SRH 长度计入"Upper-Layer Packet Length"则校验和错误，tshark 报 bad checksum。

**依据**：RFC 8200 §8.1。

**影响**：E2E-02/E2E-01（tshark 断言 TCP/UDP 校验和正确）在实现者选错伪头参数时失败但测试无法区分是哪个参数错了。

**修复建议**：BYT-13/14 明确："伪头 Next Header = 内层协议号（17/6），Upper-Layer Packet Length = 内层 L4+payload 长度（不含 SRH）；SRH 不参与 UDP/TCP 校验和输入（除伪头 SrcIP/DstIP）"。

### M-SRV6-R3-3：VR-15 与 VR-22 用 RFC 8200 §4.7 "discard" 论证 End.DX6/End.B6 的 InnerPayload 合法性，与 RFC 8986 解封装语义冲突

**位置**：§8.1 VR-15（1401 行）、VR-22（1408 行）、§7.2 V-N-21（1242 行）

**描述**：VR-22 说"payload_protocol=none + inner_payload 非空 → 警告（不报错），'packet will be discarded per RFC 8200 §4.7'"——但 seg_type=end.dx6 的 InnerPayload 场景（V-N-20/P-04/S6）正是"none + 非空 payload"，文档一边允许（解封装语义依赖它），一边警告"将被丢弃"，自相矛盾。RFC 8986 的解封装前提是 Next Header=41/4（见 C-SRV6-R3-2），修复后 VR-22 的"none + 非空"应改为报错或仅对非解封装 seg_type 生效。

**依据**：RFC 8986 §4.4/§4.5 + RFC 8200 §4.7。

**影响**：实现者无法确定"none+非空 payload"是合法（DX6）还是非法（丢弃）；Validate 规则含糊导致 E2E 测试不确定性。

**修复建议**：VR-22 改为"payload_protocol='none' 且 seg_type ∉ 解封装类 且 inner_payload 非空 → 报错；解封装类（end.dx6/dx4/b6/b6.encaps/b6.encaps.red）要求 payload_protocol 隐含为 ipv6/ipv4（Next Header 41/4）"。

### M-SRV6-R3-4：PayloadProtocol="icmpv6" 无内层 ICMPv6 头构建细节

**位置**：§7.1 V-P-13（1213 行）、§7.3 P-11（1260 行）

**描述**：P-11 断言"SRH NextHeader=58；ICMPv6 头在 Payload"，但文档无任何 ICMPv6 头字段定义（type/code/checksum/echo data），也无校验和规则（ICMPv6 校验和必须包含 IPv6 伪头，RFC 4443）。builder 现有 ICMPv6 实现路径是否存在未说明。

**影响**：实现者需要自行发明 ICMPv6 头构造，P-11 断言不足（仅 NextHeader=58），字节正确性无 spec 依据。

**修复建议**：补充 ICMPv6 头字段表（echo request: type=128, code=0, checksum 含伪头）或声明 v1 仅生成固定 ICMPv6 Echo 头并给出字节模板。

### M-SRV6-R3-5：FlowID 定义含"协议号"——SRH 不是 L4 协议，多流区分度表述含糊

**位置**：§6.12（1025 行"FlowID=hash(SrcIP,DstIP,1024,80,6)"）

**描述**：§6.12 说"每流独立 IPv6 5-tuple（源 IPv6、目的 IPv6、源端口、目的端口、协议号）"，FlowID 用 hash(SrcIP,DstIP,src_port,dst_port,6)——协议号固定 6（TCP），而 SRH 本身不是 L4。SRv6 流的"5-tuple"实际是 IPv6 地址对 + 内层 L4 端口对 + 内层协议号。文档对同一概念两处表述（§1.3 "5-tuple"、§6.12 hash）未统一，且 SRH 路径上"协议号"是否指内层协议未定义。

**影响**：多流识别（MF-03 断言"5-tuple 全唯一"）在实现时可能把外层协议号（43）算进 hash 导致所有流 hash 相同。

**修复建议**：统一表述："SRv6 流标识 = 外层 IPv6 对 + 内层 L4 端口对 + 内层协议号（6/17/58）"；MF-03 断言明确 hash 输入字段。

### M-SRV6-R3-6：§10.2 report 字段 total_segments 对 reduced 流的口径错误

**位置**：§10.1 srv6_segment_count（1484 行）、§10.2 total_segments（1505 行）

**描述**：srv6_segment_count = len(SRHConfig.SegmentList)（wire 反序后的段数）。reduced SRH 的 wire 段数 = n-1，但 SR Policy 段数 = n。total_segments = sum(srv6_segment_count) 会把 reduced 流少计 1 段；avg/max_segments_left 用 wire 口径时与 SR Policy 口径混用。report 语义未定义"段数"是 SR Policy 口径还是 wire 口径。

**影响**：report 聚合结果与用户配置（segment_list 长度）不一致，误导统计。

**修复建议**：元数据增加 srv6_policy_segments = len(用户 SegmentList)（或注明 srv6_segment_count 在 reduced 下为 n-1），total_segments 用 policy 口径；补用例断言 reduced 流的 total_segments = n。

### M-SRV6-R3-7：S4/S14 的 UDP 数据报长度为 0 未说明（合法但需声明）

**位置**：§6.4 S4（752 行 `00 38` 修复后为 72）、§6.14 S14（1126 行）

**描述**：S4/S14 字段构成未声明 UDP payload 长度；修复 Payload Length 后（H-SRV6-R3-1）UDP 头 8 字节 + payload 0 的 8 字节数据报合法但文档未写明；S6/S10 内层 UDP 同样。文档对"payload 缺省长度"无全局规则（S1 隐含 8 字节、S7 隐含 0）。

**影响**：实现者给 UDP payload 默认值不统一（0 vs 8），HexDump 无法作为字节基准。

**修复建议**：§6 开头补"默认 payload 长度"声明（如 0 字节），每场景显式标注。

---

## 5. LOW 问题（4 项）

### L-SRV6-R3-1：§6.1 草稿式"Wait, 重算"文字残留

**位置**：§6.1（594-616 行）

**描述**：正文中出现"Wait, Hdr Ext Len = 2，不是 0。重算 offset 41："以及两份 HexDump（一份错误草稿 + 一份修正），是设计者推演过程未清理。正式设计文档不应含"wait"式草稿，且错误草稿（`11 00 00 00 04 00 00 00`）若被实现者误读会传播错误。此外 §6.1 的"修正 HexDump"把 S1 的 SRH 段从"单段"正确改为 24 字节，但同文件 S2 却用错了 Payload Length（H-SRV6-R3-1）——说明该处草稿修正未覆盖其他场景。

**修复建议**：删除草稿与"Wait"段落，只保留修正后 HexDump；全文档统一 HexDump 风格。

### L-SRV6-R3-2：SRHConfig.SegmentList 类型 []string 与 builder 层效率、SRv6TLV 定义位置不统一

**位置**：§5.2（511 行）、§5.1（481-493 行）

**描述**：builder 层 SegmentList 用 []string（每次序列化需 net.ParseIP），与 §5.2 注释"builder 收到已反序列表"的职责不符（builder 应拿到 []net.IP 或 [][]byte 避免重复解析）；且 SRv6TLV 定义在 §5.1（用户层）被 §5.2（builder 层）复用，未注明同一类型跨层复用的序列化职责。

**影响**：实现细节含糊，性能与分层不明确。

**修复建议**：builder 层 SegmentList 改 [][]byte 或 []net.IP，注明由 planner 完成 ParseIP 一次。

### L-SRV6-R3-3：元数据/报告"文档总行数：见文件末尾"占位符

**位置**：§结尾（1541 行）

**描述**："文档总行数：见文件末尾"是未填写的占位符，且设计文档无需记录行数。

**修复建议**：删除该行或填写实际行数。

### L-SRV6-R3-4：§10.2 实现要点 4 的测试覆盖挂错用例

**位置**：§10.2（1521 行）

**描述**："测试覆盖：T-SRV6-AUD-02（report 字段聚合）验证上述字段在 default spec 下全部正确输出"——AUD-02 实际是"API → engine → builder → writer 全链路，任务状态 completed，pcap 文件含 SRH 帧"（1345 行），没有 report 字段聚合断言。引用错位。

**修复建议**：改为引用新用例"report 聚合字段断言"或补充 AUD-11。

---

## 6. 重点核查项逐项结论（任务要求对照表）

| # | 核查项 | 结论 |
|---|--------|------|
| 1 | Segment List 反序存储（List[0]=最后一段） | ✓ 正确。§2.2/§3.2/BYT-08 与 RFC 8754 §2.3 一致 |
| 2 | DstIP = SegmentList[n-1] | ✓ 正确。§2.3/§3.1/BYT-17 与 RFC 8754 §4.1 一致 |
| 3 | SRH PadN Type=4 | ✓ 正确。§2.4.1/§2.4.3/§6.5 与 RFC 8754 §2.1.1.2 + §8.2 一致；§1.2 区分 HopByHop PadN=1 正确 |
| 4 | Flags 全 8 位 Unused（HMAC 是 TLV） | ✓ 正确。§2.4.1/§3.2/V-N-09 与 RFC 8754 §2.1 一致 |
| 5 | HMAC-Sig Type=6 不存在 | ✓ 正确。§2.4.1/§5.1/V-N-15 与 RFC 8754 §8.2 一致 |
| 6 | Reduced SRH 省略 List[n-1]，LastEntry=n-2 | ✓ 正确。§3.3/S3/S14 与 RFC 8754 §4.1.1 一致 |
| 7 | End* 地址更新 SL-- 后 DA=SegmentList[SL_new] | ✓ 正确。§4.2/§6.7/BYT-20 与 RFC 8754 §4.3.1 S15-S16 一致 |
| 8 | Hdr Ext Len = (总长/8)-1 | ✓ 主公式正确，但 §3.2.1 中间行 `2N+T/8-1` 与 VR-18/19 差一错误（H-SRV6-R3-5） |
| 9 | 所有 HexDump 自洽性 | ✗ **S2/S12/S13/S4/S6 五帧不满足自洽**（Payload Length 溢出，H-SRV6-R3-1/8；HMAC TLV 40 vs 38 vs 36 三套数字，C-SRV6-R3-1）；S1/S3/S7/S15 自洽 ✓ |
| 10 | 测试用例符合 CLAUDE.md §Testing Policy | ✗ 部分符合。V-N 23 条负路径、BYT 字节断言、AUD 元测试结构良好；但 EXC-01/NEW-16 测不存在路径（H-SRV6-R3-6）、BYT-15 不可实现（H-SRV6-R3-3）、PayloadProtocol/FlowID/report 口径含糊（M-4/5/6）、§10.2 挂错用例（L-4） |

---

## 7. 与上一轮审计（deep 21 问题）的对照

| 上轮 CRITICAL | v2.0.0 修复状态 | 本次复核 |
|---------------|------------------|----------|
| C-R2-1 反序存储 | ✓ 已修（§2.2 全面反序化） | 确认正确 |
| C-R2-2 DstIP=List[n-1] | ✓ 已修（§2.3/§3.1） | 确认正确 |
| C-R2-3 PadN Type=4 | ✓ 已修（§2.4.1/§6.5） | 确认正确 |
| C-R2-4 Flags 全 Unused | ✓ 已修（§3.2/V-N-09） | 确认正确 |
| C-R2-5 HMAC-Sig 不存在 | ✓ 已修（§2.4.1/V-N-15） | 确认正确 |
| C-R2-6 Reduced SRH 语义 | ✓ 已修（§3.3/S3） | 确认正确 |
| C-R2-7 S15-S16 公式 | ✓ 已修（§4.2/BYT-20） | 确认正确 |
| H-R2-1 Hdr Ext Len 公式 | △ 部分修复（公式主线正确，但 -1 残留，H-R3-5） | 需再修 |
| H-R2-2 Direction="down" | △ 已定义源节点视角（§5.4），中转视角缺口（H-R3-7） | 需再修 |
| H-R2-3 BYT-01 HopByHop 共存 | ✓ 已修（BYT-19 补充） | 确认 |
| H-R2-4 Traffic Class 偏移 | ✓ 已修（§3.1 跨字节说明） | 确认 |
| H-R2-5 LastEntry reduced 边界 | ✓ 已修（§5.1 注释 + V-P-16/BND-04） | 确认 |
| H-R2-6 HMAC 8n 对齐 | ✓ 已修（§2.4.4/BYT-16） | 确认（但 HMAC TLV 字节数错误，C-R3-1） |

上轮 21 个问题中 18 个确认修复；HMAC TLV 8n 对齐修复了"对齐规则"却漏了"TLV 自身字节数"，衍生出新的 CRITICAL C-SRV6-R3-1。本次新增问题集中在 **HexDump 字节级自洽性**（上轮只验算了 Hdr Ext Len 单字段，未交叉验证 IPv6 Payload Length 与 HMAC TLV 全字节数）与 **RFC 8986 解封装语义**（上轮把 End.DX6 作为纯格式生成，未核对 Next Header=41 的 RFC 8986 明文要求）。

---

## 8. 最终结论

**本设计文档不可直接进入实现阶段。**

| 严重度 | 数量 |
|--------|------|
| CRITICAL | 2（C-SRV6-R3-1 HMAC TLV 长度三套数字自相矛盾 / C-SRV6-R3-2 End.DX6·End.B6.Encaps Next Header=59 违反 RFC 8986） |
| HIGH | 8（H-SRV6-R3-1..8） |
| MEDIUM | 7（M-SRV6-R3-1..7） |
| LOW | 4（L-SRV6-R3-1..4） |
| **合计** | **21** |

**必须先修复**：
1. C-SRV6-R3-1：HMAC TLV 统一为 Type(1)+Length(1)+D+RES(2)+KeyID(4)+HMAC(32) = 40 字节、Length=38；同步 S4/S14 HexDump（删 PadN）、BND-09。
2. C-SRV6-R3-2：End.DX6/End.DX4/End.B6.Encaps 外层 Next Header = 41（内层 IPv6）/ 4（内层 IPv4），PayloadProtocol 增加 "ipv6"；S6/S10 HexDump 改字节。
3. H-SRV6-R3-1/8：S2/S12/S13/S4/S6 五帧 Payload Length 逐帧重算并补"Payload Length == SRH+L4+payload"字节用例。
4. H-SRV6-R3-5：删去 Hdr Ext Len 公式与 VR-18/19 的多余 -1。
5. 其余 HIGH/MEDIUM/LOW 建议在实现前同步修订。

修复后建议重跑 R4，重点核查：HMAC TLV 全字节数与 Length 字段、End.DX6/Encaps 的 Next Header 41、五帧 Payload Length、Frames 视角递增语义、Direction=down 中转视角限制。

---

**审计完成时间**：2026-08-05
**审计员**：独立协议审计员（R3 复审）
**审计依据**：RFC 8754 / RFC 8200 / RFC 8986 原文（WebFetch 逐字核对）+ CLAUDE.md 测试策略 8 条 + 前两轮审计报告 + builder.go 现有 HopByHop 实现
**问题总数**：21（CRITICAL 2 + HIGH 8 + MEDIUM 7 + LOW 4）
**最终结论**：**不可直接进入实现阶段**，必须先返工 2 个 CRITICAL + 5 个 HIGH（H-R3-1/5/6/7/8）共 7 个问题。

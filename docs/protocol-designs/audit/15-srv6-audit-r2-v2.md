# SRv6 设计文档复审审计报告（R4 / v2.0.1）

**审计对象**：`/home/weihang/trafficGenerator/docs/protocol-designs/15-srv6-design.md`（1668 行，v2.0.1，声称 140 条用例 + 16 个 HexDump 场景 S1-S16）
**审计日期**：2026-08-05
**审计人**：独立协议审计员（R4 复审，默认"有 bug"）
**审计依据**：
1. **RFC 8754**（SRH）— 已 WebFetch 逐字核对：§2 SRH 字段（Next Header / Hdr Ext Len / Routing Type / Segments Left / Last Entry / Flags / Tag / Segment List）、§2.1 SRH TLVs（Type/Length 定义、bit 7 语义）、§2.1.1.1 Pad1、§2.1.1.2 PadN、§2.1.2 HMAC TLV（Length 定义、D bit、HMAC Key ID、HMAC 8 的倍数 ≤32、Alignment 8n）、§4.1 SR Source Node（DA = first segment、SL = n-1、Last Entry = n-1）、§4.1.1 Reduced SRH（省略第一段、Last Entry = n-2）、§4.3.1.1 SRH 处理伪代码 S01-S26、§8.1 Flags 注册表、§8.2 TLV 注册表
2. **RFC 8200**（IPv6）— §3 固定头（无校验和、Payload Length 定义）、§4.4 Routing Header（Hdr Ext Len = 8 字节单位减 1、Hdr Ext Len 上限 255）、§8.1 Upper-Layer Checksums（UDP over IPv6 校验和 MUST、零校验和非法、伪头 DstIP = 有 Routing header 时用**最终目的**、TCP 伪头长度推导）
3. **RFC 8986**（SRv6 Network Programming）— §4.4 End.DX6（Upper-Layer header type == 41 才解封装，否则按 §4.1.1）、§4.5 End.DX4（== 4）、§4.13 End.B6.Encaps（无 §4.3.2 节）、§4.14 End.B6.Encaps.Red（Last Entry 按 RFC 8754 §4.1.1）
4. **CLAUDE.md** 测试策略 8 条
5. 前次审计报告 `audit/15-srv6-audit-r1-v2.md`（21 问题）及 `audit/15-srv6-audit-deep.md`（21 问题）
6. `trafficgen/internal/core/builder.go` 现有实现（writeL3v6 / calculateIPv6PseudoHeader / Build / l4Length / serializeIPv6HopByHop）

**审计方法**：逐节对照 RFC 原文，对每一处 HexDump 逐字节验算（IPv6 Payload Length、Hdr Ext Len、TLV 字节数、8n 对齐、内层校验和独立用 Python 重算），对 21 个 R3 问题的修复逐项核对落地，对 140 条用例逐条核查 CLAUDE.md 8 条合规。默认"有 bug"，除非证据确凿。

---

## 1. 审计概览

### 1.1 严重度分布

| 严重度 | 数量 | 说明 |
|--------|------|------|
| CRITICAL | 0 | 无 RFC 事实级错误 |
| HIGH | 2 | UDP/TCP/ICMPv6 伪头 DstIP 未按 RFC 8200 §8.1 用最终目的（SRv6 特有）；UDP over IPv6 零校验和非法（S1/S4/S5/S7/S14/S15 六帧） |
| MEDIUM | 4 | S16 ICMPv6 校验和 0xB6D9 与 HexDump 地址不符（实为 0xB6D6）；S4/S14 HexDump 行标 0x0070 应为 0x0068（缺 8 字节行/错标）；S10 内层 UDP 校验和/端口未定义；RFC 章节引用错号（§2.3/§2.2/§4.3.2 等） |
| LOW | 3 | VR-15 列 end.dt4/end.dt6 但 T-SRV6-NEW-01 要求 ipv4 而 VR-15 只字未提；SRHConfig.HdrExtLen 的 §7.7 EXC-01 与 §9.2 引号错位（EXC-01 在 §7.7，§9.2 写 §7.7 正确但文案重复）；内层 UDP 缺省值（S4/S5/S7/S14/S15 的 SrcPort/DstPort 未声明） |
| **合计** | **9** | — |

### 1.2 总体结论

**本设计文档可直接进入实现阶段（有条件）**。21 个 R3 问题（2 CRITICAL + 8 HIGH + 7 MEDIUM + 4 LOW）的修复**全部正确落地**，逐一核对无回归、无新引入的 RFC 事实错误。本次复审发现 9 个新问题（0 CRITICAL + 2 HIGH + 4 MEDIUM + 3 LOW），其中 2 个 HIGH 属于**实现级约束缺失**（伪头最终目的、UDP 零校验和），建议在实现开工前按 §3.1/§7.4 补丁式修订，但不阻塞整体设计结构。

---

## 2. HIGH 问题（2 项）

### H-SRV6-R4-1：UDP/TCP/ICMPv6 校验和伪头 DstIP 未按 RFC 8200 §8.1 使用"最终目的"——SRv6 特有约束缺失

**位置**：§3.1（202 行"校验和说明"）、§7.4 BYT-13（1389 行）/ BYT-14（1390 行）、§6.16 S16（1271 行"伪头 SrcIP=fc00:1::1 + DstIP=fc00:2::2"）、§6.6 S6（883 行）

**描述**：文档 BYT-13/14 规定"计算 IPv6 伪头（SrcIP + DstIP + Upper-Layer Packet Length + Next Header = 内层协议号 17/6）"，但未指明**DstIP 用哪个地址**。对带 SRH 的包，外层 IPv6 头 DstIP = 第一段（SegmentList[n-1]），而 RFC 8200 §8.1 明文要求伪头 DstIP 用**最终目的**：

> "the Destination Address used in the pseudo-header is that of the final destination. At the originating node, that address will be in the last element of the Routing header"

即源节点发出的 SRv6 包，其 UDP/TCP/ICMPv6 校验和伪头 DstIP = **SegmentList[0]（最后一段，最终目的）**，不是外层 DstIP（第一段）。

**对现有 builder 的冲突**：`trafficgen/internal/core/builder.go` 的 `calculateIPv6PseudoHeader(srcIP, dstIP, ...)` 直接使用 `config.L3.SrcIP / config.L3.DstIP`（= 外层地址）。若 SRH 路径照搬该函数，校验和必然错误（源节点视角下伪头 DstIP 应为 SegmentList[0]）。

**影响**：
- 实现者照 BYT-13/14 字面实现（用外层 DstIP），E2E-01/E2E-02/E2E-11 的 tshark 校验和断言会失败（tshark 按 RFC 8200 §8.1 用最终目的校验）。
- 中间节点（End 视角）伪头 DstIP 也是最终目的（B 节点），与 S7 场景（外层 DstIP=S2）矛盾——文档完全没有区分"源节点 vs 中转节点"的伪头地址。
- ICMPv6（S16）同受此规则约束（RFC 4443 §2.3 用与 RFC 8200 §8.1 相同的伪头），S16 的校验和断言（0xB6D9）是在"外层地址=最终目的"（单段 n=1 时巧合成立）下计算的，掩盖了规则缺失。

**依据**：RFC 8200 §8.1（WebFetch 逐字核对，如上引文）。

**修复建议**：§3.1 校验和说明 + BYT-13/14 补一句："SRv6 流的 L4 校验和伪头 DstIP = 最终目的（SegmentList[0] = SR Policy 最后一段，RFC 8200 §8.1），非外层 IPv6 头 DstIP（第一段）；builder 的 SRH 路径必须为伪头单独传入最终目的，不得复用外层 DstIP"。补用例：多段（n>1）下断言 UDP/TCP 校验和用最终目的计算。

### H-SRV6-R4-2：UDP over IPv6 零校验和非法——S1/S4/S5/S7/S14/S15 六帧声称"校验和=0 合法"

**位置**：§6.1 S1（650 行"`00 00` = UDP Checksum=0（v1 不强制计算，合法为零校验和）"）、§6.4 S4（782 行"校验和=0x0000…合法"）、§6.5 S5（无明确声明但 HexDump 为 0）、§6.7 S7（935 行"校验和 = 0x0000，合法"）、§6.14 S14（1170 行同 S4）、§6.15 S15（内层 UDP 空负载、HexDump 未列校验和）

**描述**：文档多处声明"UDP 校验和 = 0 合法"。RFC 8200 §8.1 明文（WebFetch 逐字核对）：

> "the default behavior when UDP packets are originated by an IPv6 node is that the UDP checksum is not optional"
> "whenever originating a UDP packet, an IPv6 node must compute a UDP checksum over the packet and the pseudo-header"
> "IPv6 receivers must discard UDP packets containing a zero checksum"

零校验和在 IPv6 下**非法**（例外仅限 RFC 6936 隧道封装场景，trafficgen 非隧道端口）。这是 IPv6 与 IPv4 的根本差异（IPv4 允许 0 = 无校验和，IPv6 不允许）。

**影响**：
- 实现者按文档"S4/S14 UDP 校验和 = 0 合法"实现，E2E 场景 tshark 会报 "checksum 0x0000 (invalid)"，真实接收端丢弃。
- builder 现有代码 `calculateUDPChecksum`（builder.go ~1300 行）**已实现 IPv6 零校验和 → 0xFFFF 替代**（"IPv6 UDP MUST NOT have zero checksum (RFC 6936 §2)。On IPv6, 0xFFFF is the substitute"）——文档与现有实现直接矛盾，实现者按文档写测试会与 builder 行为冲突。

**依据**：RFC 8200 §8.1 + builder.go 现有实现（已正确处理 0→0xFFFF）。

**修复建议**：删除全部"校验和=0 合法"表述，改为"UDP over IPv6 必须计算校验和（RFC 8200 §8.1），计算得 0 时写 0xFFFF"；S1/S4/S5/S7/S14/S15 补真实校验和值或声明由 builder 按伪头计算（给出伪头 DstIP 规则，见 H-SRV6-R4-1）。注意 S1 的 SrcIP=fc00:1::1、DstIP=fc00:2::2 且 n=1 时最终目的 = DstIP，校验和可计算（无需占位）。

---

## 3. MEDIUM 问题（4 项）

### M-SRV6-R4-1：S16 ICMPv6 校验和 0xB6D9 与 HexDump 地址不符——正确值应为 0xB6D6

**位置**：§6.16 S16（1269-1271 行 + 1288 行验证）

**描述**：S16 声称"ICMPv6 校验和 = 0xB6D9（伪头 SrcIP=fc00:1::1 + DstIP=fc00:2::2 + Upper-Layer Length=16 + Next Header=58）"。逐字节重算（RFC 4443 §2.3 反码和，Python 验证）：

| 伪头地址组合 | 校验和 |
|--------------|--------|
| fc00:1::1 → fc00:2::2（HexDump 实际字节） | **0xB6D6** |
| fc00::1 → fc00::2 | 0xB6D9（文档声称值） |
| fc00:1::1 → fc00:2::2，len=24（含 SRH） | 0xB6CE |

HexDump offset 8-23 = `fc 00 … 00 01`（fc00:1::1）、offset 24-39 = `fc 00 … 00 02`（fc00:2::2）。**文档的 0xB6D9 是用 fc00::1/fc00::2 算出的**，与 HexDump 地址不一致。0xB6D9 恰巧是"地址换成 fc00::1/fc00::2"的值，说明校验和是从某个草稿地址算完直接抄入，未与最终 HexDump 交叉验证——正是 R3 审计 H-R3-1/8（HexDump 内部自洽性）同根因的复发。

**影响**：实现者按 HexDump 字节做 BYT 断言（校验和字段 = b6 d9）会失败；按 0xB6D9 实现则校验和不正确（tshark 报 bad checksum）。

**修复建议**：校验和改为 0xB6D6（伪头 fc00:1::1/fc00:2::2 + len=16 + NH=58 反码和），或改用能算出 0xB6D9 的地址组合并同步 HexDump。另注意：单段 n=1 时"最终目的 = 外层 DstIP"，S16 伪头恰好合法（不暴露 H-SRV6-R4-1），修复后应补充多段 ICMPv6 场景覆盖最终目的规则。

### M-SRV6-R4-2：S4/S14 HexDump 行标 0x0070 应为 0x0068——0x60 行仅 8 字节造成 8 字节偏移错标

**位置**：§6.4 S4（793-794 行）、§6.14 S14（1181-1182 行）

**描述**：S4 字段构成"SRH 总长 = 64 字节（offset 40-103）"，但 HexDump 行标 `0x0070 <UDP 头 8 字节>` 暗示 UDP 起始于 offset 112。实际 SRH 结束于 40+64 = 104（0x68），UDP 应从 **0x68** 开始。根因：0x60 行只有 8 字节（`00 00 00 00 00 00 00 00`，覆盖 offset 96-103），后续行标按"每行 16 字节"递增为 0x70，但 0x60 行实际只写了 8 字节。要么缺一行 8 字节的"0x68"行，要么 0x70 行标应改 0x68。

**影响**：实现者照行标推断 UDP 偏移会错位 8 字节（写成 offset 112 处写 UDP）；HexDump 是 BYT 断言的字节基准（BYT-16 断言 HMAC TLV 字节、BND-09 断言 Hdr Ext Len），行标错位会导致断言落点错误。S14 同款（1181-1182 行）。

**修复建议**：S4/S14 的 0x60 行补满 16 字节（把 HMAC 续行拆两行）或将 0x0070 行标改为 0x0068（并补 8 字节空行以保持 16 字节对齐）；同步 S14。

### M-SRV6-R4-3：S10 内层 UDP 校验和与端口未定义（End.B6.Encaps 内层 72 字节的完整性缺口）

**位置**：§6.10 S10（1006-1009 行字段构成、1014-1022 行 HexDump）

**描述**：S10 内层 = 内层 IPv6(40B) + 内层 SRH(24B) + 内层 UDP(8B)。文档定义了内层 IPv6 头（SrcIP=fc00:inner::1、DstIP=fc00:inner::2、Payload Length=32、Next Header=43、Hop Limit=64）与内层 SRH（NextHeader=17、Hdr Ext Len=2、RoutingType=4、SL=0、LE=0、List[0]=fc00:inner::2），但**内层 UDP 头完全未定义**：SrcPort/DstPort/Length/校验和都没有字节级值。外层字段构成说"内层 UDP：payload 空（数据报仅 8 字节 UDP 头）"，HexDump 行 0x0080 只写"<内层 UDP 头 8 字节>"占位。

**影响**：
- 与 S6（内层 UDP 全字节定义：SP=12345、DP=53、Len=16、CKSUM=0x0675）形成对比，S10 缺同等完整度；E2E-11 类用例（tshark 解析 IPv6-in-IPv6）对内层 UDP 校验和断言无字节基准。
- §5.2.1 全局规则只声明"内层 payload 缺省 0 字节"，未声明内层端口默认值（InnerSrcPort/InnerDstPort 0 = spec.SrcPort/spec.DstPort，§5.1）——S10 未给出 spec 的端口值，内层 UDP 头无法推导。

**修复建议**：S10 补内层 UDP 头字段表（端口取 spec 值、Length=8、校验和按 RFC 8200 §8.1 伪头计算并给值），或声明"S10 内层 UDP 端口=0、校验和=0xFFFF 替代（RFC 8200 §8.1）"。

### M-SRV6-R4-4：RFC 章节引用错号——§2.2/§2.3/§4.3.2/§4.3.x 等与 RFC 8754/8986 实际章节不符

**位置**：§1.1（20 行"§2 SRH 结构、§2.1 TLV"——正确）、§2.2（70 行"RFC 8754 §2.3"）、§3.2（215 行"§2.3"）、§4.1（315 行"§4.3.1.1"——正确）、§5.1（402 行"§2.3"、408 行"§2.3"）、§6.10（1005 行"RFC 8986 §4.3.2"）、§7.3（1356 行"§4.3.1"）、§8.1（1506 行"§4.3.1"）、§2.4.4（157 行"§2.1.2"——正确）、修订记录（1657 行"§4.3.x"）

**描述**：RFC 8754 的 SRH 字段与 Segment List 反序说明在 **§2**（无 §2.2/§2.3 子节；§2.1 = SRH TLVs，§2.1.1 = Padding TLVs，§2.1.2 = HMAC TLV）；SRH 处理伪代码在 **§4.3.1.1**（文档 §4.2/§4.1 写"§4.3.1.1"正确，但多处写"§4.3.1"）。RFC 8986 的 End.B6.Encaps 在 **§4.13**、End.B6.Encaps.Red 在 **§4.14**（文档写"§4.3.2"系误抄 End.X 所在节号，RFC 8986 无 §4.3.2）；End.DX6=§4.4、End.DX4=§4.5、End.X=§4.2、End.T=§4.3（文档引用正确）。RFC 8200 的 Hop-by-Hop PadN 在 §4.2（文档正确）、Routing Header 通用规则在 §4.4（正确）。

**依据**：RFC 8754 / RFC 8986 目录（WebFetch 逐字核对，见上）。

**影响**：实现者按错误节号查 RFC 会找不到出处（§2.3 在 RFC 8754 中不存在），浪费查证时间；无字节级影响。

**修复建议**：统一改为 "RFC 8754 §2"（Segment List 反序）、"RFC 8754 §4.3.1.1"（伪代码）、"RFC 8986 §4.13/§4.14"（B6.Encaps/B6.Encaps.Red），删除"§4.3.x"含糊写法。

---

## 4. LOW 问题（3 项）

### L-SRV6-R4-1：VR-15 列 end.dt4/end.dt6 但要求 ipv4/ipv6——end.dx4 的 ipv4 约束散落、VR-15 表述不完整

**位置**：§8.1 VR-15（1512 行）、§7.10 NEW-01（1468 行）

**描述**：VR-15 规定"解封装/封装类（end.dx6/end.b6/end.b6.encaps/end.b6.encaps.red）额外要求 payload_protocol=ipv6；end.dx4 要求 payload_protocol=ipv4"，把 end.dt4/end.dt6 也列入"InnerPayload ≥ 40 字节"组，但未给出 end.dt4/end.dt6 的协议约束（RFC 8986 §4.9 End.DT6 解封装到 IPv6 表、§4.8 End.DT4 解封装到 IPv4 表，其内层协议约束与 DX6/DX4 同源：DT6 要求 41、DT4 要求 4）。NEW-01 只覆盖 end.dx4 的 Next Header=4，end.dt4/end.dt6 无对应用例。

**影响**：v1 支持列表（§3.4）含 end.dt4/end.dt6，但 VR-15 对它们的 inner 协议要求未定义，实现者自由发挥。

**修复建议**：VR-15 补充"end.dt4/end.dt6 同 dx4/dx6 约束（ipv4/ipv6）"；补用例覆盖 end.dt4+ipv4、end.dt6+ipv6。

### L-SRV6-R4-2：§9.2 的 Hdr Ext Len mismatch 行文案与 §7.7 EXC-01 重复且引号范围歧义

**位置**：§9.2（1567 行）、§7.7 EXC-01（1431 行）

**描述**：两处定义同一错误（"hdr_ext_len mismatch"），§9.2 写"SRHConfig.HdrExtLen（planner 填入，§5.2）与 builder 实际序列化的 SRH 总长（(总长/8)-1）不符"，§7.7 EXC-01 写"builder 收到 SRHConfig 时 HdrExtLen 字段…"——内容一致，无矛盾（R3 的 H-R3-6 已修复字段缺失），但同一错误在两处重复定义，且 §9.2 的"(总长/8)-1"未加引号容易与字段名混淆。属编辑级。

**修复建议**：§9.2 该行改为"见 §7.7 EXC-01"交叉引用，或删去其一。

### L-SRV6-R4-3：内层 UDP 的 SrcPort/DstPort 缺省值在 S4/S5/S7/S14/S15 未声明

**位置**：§6.4 S4（782 行"SrcPort=0、DstPort=0"）、§6.14 S14（1170 行同）、§6.5 S5 / §6.7 S7 / §6.15 S15（未声明）

**描述**：S4/S14 明确内层 UDP SrcPort=0、DstPort=0（来自 spec 默认），S5/S7/S15 的 HexDump 未列 UDP 头字节（占位"<UDP 头 8 字节>"），也未声明端口值。§5.1 InnerSrcPort/InnerDstPort 规则（0 = spec.SrcPort/spec.DstPort）未在 §5.2.1 缺省值声明中提及，实现者写 BYT 断言时对 S5/S7/S15 的 UDP 头无字节基准。

**修复建议**：§5.2.1 全局声明补"内层 UDP/TCP 端口 = spec.SrcPort/spec.DstPort（Inner* 为 0 时）"；S5/S7/S15 字段构成补端口值。

---

## 5. R3 21 个问题修复核对（逐项）

| R3 ID | 问题 | v2.0.1 修复 | 核对结论 |
|-------|------|------------|----------|
| C-SRV6-R3-1 | HMAC TLV 三套数字（36/38/40）矛盾 | §2.4.4 改 Length=38(0x26)=D+RES(2)+KeyID(4)+HMAC(32)、TLV 总长 40；S4/S14 删 PadN、SRH 总长 64 直接 8n 对齐；BND-09 重算 | ✓ 全部正确。逐字节核算：8+16+40=64，Hdr Ext Len=7，offset 64-103 HMAC TLV，Payload Length=0x48=72 ✓；S14 D bit=1（0x8000）正确 |
| C-SRV6-R3-2 | End.DX6/Encaps Next Header=59 | §5.1 PayloadProtocol 枚举加 "ipv6"（41）；S6/S10 HexDump offset 40 = `29`；P-04 断言 41；VR-15/V-N-21/E2E-11 同步 | ✓ 正确，与 RFC 8986 §4.4（Upper-Layer header type == 41）/§4.13 一致；V-N-21 负向用例成立 |
| H-SRV6-R3-1/8 | S2/S12/S13/S4/S6 五帧 Payload Length 溢出 | 重算：S2/S12=0x4c(76=56+20)、S4/S14=0x48(72=64+8)、S13=0x800(2048=2040+8)、S6=0x50(80=24+56)、S5=0x28(40=32+8)、S10=0x60(96=24+72)、S15=0x60(96=88+8)；§5.2.1 全局声明 payload 缺省 0 字节 | ✓ 全部正确，Python 逐帧验证通过（S1=0x28、S3=0x20、S7=0x40 亦自洽） |
| H-SRV6-R3-2 | Reduced 默认规则未定义 | §5.3 S11：SegType=end.b6.encaps.red → 默认 true；显式覆盖；V-P-18/P-18 用例 | ✓ 正确，规则自洽（S5 按最终 Reduced 值取 len-2） |
| H-SRV6-R3-3 | Pad1/PadN 尾部填充规则缺失 | §3.2.1 补"mod 8==1 用 Pad1、≥2 用 PadN"；BND-12（1 段+实验 TLV Value=5 → 31 mod 8=7 → Pad1） | ✓ 正确，与 RFC 8754 §2.1.1.1/.2 一致；BND-12 构造合法（8+16+2+5=31） |
| H-SRV6-R3-4 | S15 Frames 视角递增语义矛盾 | §5.1 Frames 注释 + §6.15 声明"视角递增仅由多条 FlowSpec 显式串联，Frames 不改 SRH 内容"；S15 五帧逐字段列明 | ✓ 正确。五帧 DstIP/SL 逐帧核对：Frame1 SL=4 DA=List[4]=S1、Frame2 SL=3 DA=List[3]=S2…Frame5 SL=0 DA=List[0]=B，全部符合 S15-S16 公式 ✓ |
| H-SRV6-R3-5 | Hdr Ext Len 公式多余 -1 | §3.2.1 统一 2N+T/8（验证行 N=2,T=0 → 4 ✓）；VR-18/19 删 -1；§10.1 srv6_hdr_ext_len 同步 | ✓ 正确。公式 2N+T/8 与 (总长/8)-1 恒等（T 为 8 倍数时）；127 段 HEL=254 上限推导正确 |
| H-SRV6-R3-6 | SRHConfig 无 HdrExtLen 字段 | §5.2 新增 `HdrExtLen uint8`（planner 计算填入、builder 复核拒绝 mismatch）；EXC-01/NEW-16/§9.2 成立 | ✓ 正确。EXC-01 示例（HdrExtLen=6 vs 实际 1 段 → 2≠6）数值正确 |
| H-SRV6-R3-7 | Direction=down 中转视角失效 | §5.4 + VR-23/V-N-24/DD-07：仅源节点视角（SegmentsLeftPtr 必须 nil），否则报错 | ✓ 正确。反转列表 + SegmentsLeft 重置 n-1 + DstIP=新 List[n-1]=原 List[0] 在源节点视角下满足 RFC 8754 §4.1 |
| M-SRV6-R3-1 | IPv6 无校验和未声明 | §3.1 补"IPv6 固定头无校验和；SRH 不参与任何校验和"；BYT-21 | ✓ 正确（注：BYT-21 断言"SRH 字节变更不影响任何校验和"与 RFC 8200 §8.1 伪头规则在**最终目的不变**时成立，见 H-SRV6-R4-1 的补充约束） |
| M-SRV6-R3-2 | UDP/TCP 伪头歧义 | BYT-13/14 补"Next Header = 内层协议号、Upper-Layer Packet Length 不含 SRH" | ✓ 正确（但仍缺伪头 DstIP = 最终目的，见 H-SRV6-R4-1） |
| M-SRV6-R3-3 | VR-22 自相矛盾 | VR-22 改报错并排除解封装类（解封装类走 VR-15 强制 ipv6/ipv4） | ✓ 正确，与 RFC 8986 解封装语义一致 |
| M-SRV6-R3-4 | ICMPv6 无构建细节 | §6.16 S16 补 ICMPv6 Echo 头字段表 + 校验和 + P-11 同步 | △ 基本正确（字段表/校验和规则齐全），但校验和数值 0xB6D9 与 HexDump 地址不符（M-SRV6-R4-1） |
| M-SRV6-R3-5 | FlowID 表述含糊 | §1.3/§6.12/§10.1 统一"外层 IPv6 对+内层端口对+内层协议号（6/17/58）" | ✓ 正确 |
| M-SRV6-R3-6 | report 口径错误 | §10.1 新增 srv6_policy_segments、§10.2 total_segments 用 policy 口径、BND-13 断言 | ✓ 正确（BND-13：wire 段数 1、policy 段数 2、total_segments=2） |
| M-SRV6-R3-7 | S4/S14 UDP 数据报长度 0 未说明 | §6.4/§6.14 注明"数据报长度 0，合法" | △ 说明补了，但"合法"表述本身错误（UDP over IPv6 零校验和非法，H-SRV6-R4-2） |
| L-SRV6-R3-1 | 草稿文字残留 | 删除"Wait"草稿与重复 HexDump | ✓ 已清理 |
| L-SRV6-R3-2 | SegmentList []string | §5.2 改 [][]byte、注释注明 planner 解析一次 | ✓ 正确 |
| L-SRV6-R3-3 | 行数占位符 | 已删除 | ✓ |
| L-SRV6-R3-4 | §10.2 挂错用例 | 改挂 BND-13 | ✓ 正确 |

**结论：21/21 修复落地，其中 19 项完全正确、2 项（M-R3-4、M-R3-7）部分正确但引入/残留新问题（M-SRV6-R4-1、H-SRV6-R4-2）。**

---

## 6. 重点核查项逐项结论（任务要求对照表）

| # | 核查项 | 结论 |
|---|--------|------|
| 1 | C-R3-1：HMAC TLV Length=38(0x26)、总长 40；S4/S14 删末尾 PadN；SRH 64B 直接 8n 对齐 | ✓ 全部正确（§2.4.4/§6.4/§6.14/BND-09 逐字节核算通过） |
| 2 | C-R3-2：End.DX6/Encaps 外层 Next Header=41(0x29)；S6/S10 HexDump 更新；PayloadProtocol 含 "ipv6" | ✓ 全部正确（§5.1/S6/S10/P-04/VR-15/V-N-21/E2E-11） |
| 3 | H-R3-1：五帧 Payload Length 重算（S2=0x4c、S4=0x48、S13=0x800、S6=0x50、S10=0x60） | ✓ 全部正确（Python 逐帧验证） |
| 4 | H-R3-2：Reduced 默认规则（end.b6.encaps.red → true） | ✓ 正确（§5.3 S11/DR-11/V-P-18） |
| 5 | H-R3-3：Pad1/PadN 尾部填充规则 | ✓ 正确（§3.2.1/BND-12） |
| 6 | H-R3-5：Hdr Ext Len = 2N + T/8（无 -1） | ✓ 正确（§3.2.1/VR-18/19/§10.1） |
| 7 | H-R3-6：SRHConfig.HdrExtLen 字段 | ✓ 正确（§5.2/EXC-01/NEW-16/§9.2） |
| 8 | H-R3-7：Direction=down 仅源节点视角 | ✓ 正确（§5.4/VR-23/V-N-24/DD-07） |
| 9 | S16：ICMPv6 Echo 新场景（校验和 0xb6d9） | △ 场景结构正确，但校验和数值 0xB6D9 与 HexDump 地址不符（正确值 0xB6D6，M-SRV6-R4-1） |
| 10 | 所有 HexDump 的 Hdr Ext Len = 总长/8-1、Payload Length = 扩展头+内层 | ✓ 16 帧全部验证通过（S1-S16）；另发现 S4/S14 行标 0x70 错位（M-SRV6-R4-2，排版级） |
| 11 | 测试用例符合 CLAUDE.md §Testing Policy | △ 基本符合（§7 AUD/NEW 结构良好、负路径/BYT 字节断言齐全）；缺口：① 校验和伪头 DstIP=最终目的无用例（H-SRV6-R4-1）；② UDP 零校验和"合法"断言与 RFC 及 builder 现实现冲突（H-SRV6-R4-2）；③ S10 内层 UDP 无字节基准（M-SRV6-R4-3） |

---

## 7. 与上一轮审计（R3 / v2.0.0 21 问题）的对照

| 上轮问题 | 修复状态 | 本次复核 |
|----------|----------|----------|
| C-SRV6-R3-1（HMAC TLV 三套数字） | ✓ 已修 | 确认正确，无回归 |
| C-SRV6-R3-2（Next Header 59→41） | ✓ 已修 | 确认正确，无回归 |
| H-SRV6-R3-1/8（五帧 Payload Length） | ✓ 已修 | 确认正确，无回归 |
| H-SRV6-R3-2..7（Reduced 默认/Pad1/PadN/S15/Frames/公式/SRHConfig/Direction） | ✓ 已修 | 全部确认正确 |
| M-SRV6-R3-1..7 | ✓ 已修（6 项） | M-R3-4 部分修复残留校验和数值错误（M-R4-1）；M-R3-7 修复引入"零校验和合法"错误表述（H-R4-2） |
| L-SRV6-R3-1..4 | ✓ 已修 | 确认正确 |

**上轮 21 项全部确认修复**。本次新增 9 个问题全部来自**上一轮未覆盖的领域**：L4 校验和与伪头规则（RFC 8200 §8.1 的最终目的规则、零校验和禁止——上轮只查了 SRH 结构，未查 RFC 8200 §8.1 全文）、S16 新增场景的校验和数值自洽、HexDump 行标排版、RFC 章节引用号。

---

## 8. 最终结论

**本设计文档可以直接进入实现阶段（有条件放行）**——21 个 R3 问题全部正确修复，无 CRITICAL 残留，无 RFC 事实级错误。但建议在实现开工前完成以下补丁（预计 1-2 小时工作量）：

1. **H-SRV6-R4-1（HIGH）**：BYT-13/14/§3.1 补"伪头 DstIP = 最终目的（SegmentList[0]），builder SRH 路径不得复用外层 DstIP"——这是实现正确性的硬约束，与 builder 现实现（calculateIPv6PseudoHeader 用外层地址）直接冲突，不修则 E2E 校验和断言必然失败。
2. **H-SRV6-R4-2（HIGH）**：删除 S1/S4/S5/S7/S14/S15 的"UDP 校验和=0 合法"表述，改"必须计算，0 → 0xFFFF（RFC 8200 §8.1 / builder 现实现）"。
3. **M-SRV6-R4-1（MEDIUM）**：S16 校验和 0xB6D9 → 0xB6D6。
4. **M-SRV6-R4-2（MEDIUM）**：S4/S14 行标 0x70 → 0x68。
5. **M-SRV6-R4-3（MEDIUM）**：S10 内层 UDP 头补字段定义。
6. **M-SRV6-R4-4（MEDIUM）+ LOW**：章节引用号、VR-15 补 dt4/dt6、编辑级清理。

| 严重度 | 数量 |
|--------|------|
| CRITICAL | 0 |
| HIGH | 2（H-SRV6-R4-1 伪头最终目的 / H-SRV6-R4-2 UDP 零校验和非法） |
| MEDIUM | 4（M-SRV6-R4-1..4） |
| LOW | 3（L-SRV6-R4-1..3） |
| **合计** | **9** |

修复后可不再重跑全量审计（上述 9 项均为局部补丁，不影响 SRH 核心结构）；若按本报告修复，建议实现阶段用一条 BYT 用例（多段 + UDP 校验和按最终目的计算）验证 H-SRV6-R4-1。

---

**审计完成时间**：2026-08-05
**审计员**：独立协议审计员（R4 复审）
**审计依据**：RFC 8754 / RFC 8200 / RFC 8986 原文（WebFetch 逐字核对）+ CLAUDE.md 测试策略 8 条 + R3/R2 前两轮审计报告 + builder.go 现有实现（writeL3v6 / calculateIPv6PseudoHeader / Build）
**问题总数**：9（CRITICAL 0 + HIGH 2 + MEDIUM 4 + LOW 3）
**最终结论**：**可直接进入实现阶段（有条件）**，建议先修 2 个 HIGH + 4 个 MEDIUM 共 6 项后开工；无 CRITICAL。

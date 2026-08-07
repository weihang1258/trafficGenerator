# ENIP 设计文档复审报告（r1-v2）

**审计目标**：`/home/weihang/trafficGenerator/docs/protocol-designs/12-enip-design.md`（v2.0.0，2509 行）
**审计性质**：复审（对照 ODVA EtherNet/IP + OpENer/Wireshark 源码），独立审计员
**审计日期**：2026-08-05
**审计方法**：逐节对照 OpENer `master` 源码（`encap.c`、`cipconnectionmanager.c`、`cipconnectionmanager.h`、`cpf.c`）+ Wireshark `packet-cip.h`，逐 HexDump 核算自洽性
**审计约束**：未修改设计文档；未执行 go build/go test

---

## 0. 审计依据（地面真值）

以下 4 个来源已通过 WebFetch 逐行核实：

1. **OpENer `source/src/enet_encap/encap.c`**（`master`）
   - `HandleReceivedListServicesCommand`：响应直接写 ItemCount，无 6B 前缀
   - `EncapsulateListIdentityResponseMessage`：响应直接写 ItemCount，无 6B 前缀 → **确认 R1**
   - `EncodeListIdentityCipIdentityItem`：ProtocolVersion 写 `kSupportedProtocolVersion=1`，Item 字段顺序 = ItemID+Length+ProtoVersion+SocketAddress(6+8)+VendorID+...

2. **OpENer `source/src/cip/cipconnectionmanager.c`**（`master`）
   - `AssembleForwardOpenResponse`：成功响应字段顺序 = Consumed(O→T) 4B + Produced(T→O) 4B + ConnSerialNum 2B + OrigVendorID 2B + OrigSerialNum 4B + O→T Actual Rate 4B + T→O Actual Rate 4B + RemainingPathSize 1B + Reserved 1B → **确认设计文档 §3.6/S7 HexDump 字段顺序正确，§5.6.1 偏移表错误**

3. **OpENer `source/src/cip/cipconnectionmanager.h`**（`master`）
   - `ConnectionManagerExtendedStatusCode` 枚举完整列表（55 个值）→ **确认设计文档 §2.3.2 表 10 项中 7 项名称/取值错误**

4. **Wireshark `epan/dissectors/packet-cip.h`**（`master`）
   - `CI_TRANSPORT_CLASS_MASK=0x0F`（4 位）、`CI_PRODUCTION_TRIGGER_MASK=0x70`（3 位）、`CI_PRODUCTION_DIR_MASK=0x80`（1 位）→ **确认设计文档 §2.6 位布局错误**

---

## 1. 总体结论

v2.0.0 对 v1 进行了实质性改进（CIP 服务码表、EPATH 段类型、字节序等已纠正），但仍存在 **17 项遗留与新引入问题**（3 CRITICAL / 5 HIGH / 5 MEDIUM / 4 LOW）。

**结论：本文档不可直接进入实现阶段。** 3 项 CRITICAL 问题直接导致生成的网络包字节布局错误，OpENer/Wireshark 将无法正确解析。修复 CRITICAL + HIGH 后，可逐步进入实现阶段。

---

## 2. 严重问题汇总

| 编号 | 严重度 | 节号 | 摘要 |
|------|--------|------|------|
| C1 | CRITICAL | §2.4、§3.3、§6.3 S2、§6.4 S3 | **ListServices/ListIdentity/ListInterfaces 响应错误包含 6B 前缀**：OpENer `encap.c` 确认 List* 响应 payload 直接以 ItemCount 开始，无 Interface Handle(4B)+Timeout(2B) 前缀；只有 SendRRData/SendUnitData 才有该前缀。S2/S3 HexDump 的 Length 核算基于错误假设 |
| C2 | CRITICAL | §2.3.2、§9.2 | **CIP CM 扩展状态码表 7 项错误**：0x0107 是 TargetConnectionNotFound 非"Connection size mismatch"；0x0111 是 RpiNotSupported 非"Target connection not found"；0x0112 是 RpiValuesNotAcceptable 非"Invalid connection size"；0x0312 是 LinkAddressNotValid 非"Invalid consumption"；0x0313 不存在；0x0315 是 InvalidSegmentTypeInPath 非"Wrong cloer"；WrongCloser 实际是 0xFFFF |
| C3 | CRITICAL | §2.6 | **Transport Class/Trigger 位布局错误**：Wireshark `packet-cip.h` 确认 Transport Class 是 bit 0-3（4 位，mask 0x0F），非 bit 0-1（2 位）；Production Trigger 是 bit 4-6（3 位，mask 0x70），非 bit 2-6（5 位）。常用值表（0x80=Class 0 Client 等）本身正确，但位布局描述错误会导致自定义值位计算失误 |
| H1 | HIGH | §5.6.1、§3.6 | **from_response O2T/T2O/ConnSerialNumber 偏移错误**：OpENer `AssembleForwardOpenResponse` 确认 O→T ConnID 在 CIP body offset 0（非设计文档的 4）、T→O ConnID 在 offset 4（非 8）、ConnSerialNum 在 offset 8（非 12）。S7 HexDump 本身正确，但 §5.6.1 偏移表与 §3.6 表不一致 |
| H2 | HIGH | §3.11、S3 HexDump | **ListIdentity Response 字段结构错误**：OpENer `EncodeListIdentityCipIdentityItem` 写 ProtocolVersion=0x0001（非 0xFFFF）；无单独的"EncapsulationProtocolVersion"字段，共 1 个 ProtocolVersion 字段而非 2 个；SocketAddress 为 port(2)+addr(4)+zero(10) 共 16 字节（含 sin_family），设计文档 16 字节含义需重新核算 |
| H3 | HIGH | §3.5.1 | **Forward_Open Network Connection Parameters (2B) 位布局与 Wireshark 不一致**：设计文档 bit 0-10=Connection Size；但 Wireshark 实际 mask 预期为 9 位连接尺寸。Priority/Variable Length 等字段的位偏移可能与规范不符 |
| H4 | HIGH | §5.2、§6.8 S7、§6.9 S8 | **ConnectionPath 与 RequestPath 混淆**：Forward_Open body 内 ConnectionPath 应指向 Assembly 实例（Class 0x04）+ Connection Point，非 Connection Manager（Class 0x06）。§5.2 ConnectionPath 注释写"0x20 0x06 0x24 0x01"（错）；S8 Forward_Close ConnectionPath 同样错误（用 Class 0x06 而非 Assembly） |
| H5 | HIGH | §2.6、§4.3、§8.2 V-117 | **Transport Class 取值范围扩展**：Transport Class 是 4 位（0-15 合法），非 2 位（0-3）。bit 3 含义需查阅 ODVA 规范。V-117 校验规则"bit 0-1 必须 0-3"过于严格 |
| M1 | MEDIUM | §3.5 | "总固定字段大小 = 35 字节"表述歧义：35 是否含 ConnPathSize(1B)？按表偏移算，TransportClassTrigger 在 offset 34，ConnPathSize 在 offset 35——若 35 不含 ConnPathSize 则正确，但注释不明确 |
| M2 | MEDIUM | §3.4.2、§3.6、§3.8 | Additional Status Size 单位在 §3.6/§3.8 表中未标"word"，与 §3.4.2 不一致（§3.4.2 明确"word 数"） |
| M3 | MEDIUM | §2.5.2、§2.5.3、§4.3 | 0x52 服务码在 Unconnected_Send 与 Read Tag Fragmented 之间跨上下文的消歧逻辑未说明 |
| M4 | MEDIUM | §3.5.2 | LargeForwardOpen 4B Connection Parameters 位布局：bit 0-31 填满但 bit 13-22 另有语义，自相矛盾 |
| M5 | MEDIUM | §9.2 | 错误处理表引用的 CIP CM 扩展状态码与 §2.3.2 联动，C2 修复后需同步更新 |
| L1 | LOW | §3.11、§2.7.2 | §2.7.2 公式 `0x20 | LogicalType(bit 2-4) | LogicalFormat(bit 0-1)` 与表中已移位值易误读（详见分析） |
| L2 | LOW | §7.2 T-042 | T-042 断言 Forward_Open ConnectionPath 含 Class 0x06——混淆 RequestPath 与 ConnectionPath |
| L3 | LOW | §7.3 T-096/T-112 | 测试输入列包含长串解释文字，非明确输入值，违反 CLAUDE.md §Testing Policy |
| L4 | LOW | §7.7 T-201~T-220 | 修订追加测试 20 条覆盖 32 项修复（多修复无对应测试）；缺少 Transport Class 4 位/Production Trigger 3 位位级测试 |

---

## 3. 详细问题分析

### C1：ListServices/ListIdentity/ListInterfaces 响应错误包含 6B 前缀（CRITICAL）

**位置**：§2.4（行 184-201）、§3.3（行 460-470）、§6.3 S2（行 1061-1079）、§6.4 S3（行 1109-1145）

**描述**：设计文档在 §3.3 规定 SendRRData/SendUnitData payload 结构为 `Interface Handle(4B) + Timeout(2B) + CPF`，但在 §6.3 S2 ListServices 响应和 §6.4 S3 ListIdentity 响应中也写入了这 6 字节前缀：

S2 响应 HexDump（行 1069-1076）：
```
00 00 00 00    Interface Handle=0 (注意：ListServices 响应也带 6B 前缀)
00 00          Timeout=0
01 00          ItemCount=1, LE
```

**地面真值**：OpENer `encap.c` `HandleReceivedListServicesCommand` 和 `EncapsulateListIdentityResponseMessage` 确认，List* 响应 payload 第一个字段**直接是 ItemCount**，无 Interface Handle + Timeout 前缀。只有 SendRRData/SendUnitData 才有这 6 字节。

OpENer 相关代码：
```c
// ListServices
GenerateEncapsulationHeader(receive_data, kListServicesCommandSpecificDataLength, 0, ...);
AddIntToMessage(1, outgoing_message);  // Item count -- 第一个字段
// ListIdentity
EncapsulateListIdentityResponseMessage(...)
  AddIntToMessage(1, outgoing_message); /* Item count: one item */ -- 第一个字段
```

**影响**：
- S2 响应 Length 核算错误：设计文档算的 23 基于 6+2+4+11 假设；正确是 2+4+all_items_length
- S3 响应 Length 核算错误：设计文档中途"修正"从 51 到 57 基于错误假设；正确应是 2+4+45=51（删除 6B 前缀后回到原始值）
- tshark 非 SendRRData/SendUnitData 的响应包解析时会把开头的 `00 00 00 00 00 00` 当作第一个 CPF Item 的 TypeID+Length（0x0000, 0x0000 = Null Address, Length=0），导致误读
- T-004/T-006/T-011 等测试用例的 bytes 偏移断言全部需要重算

**修复建议**：
1. §2.4/§3.3 区分："SendRRData/SendUnitData payload = InterfaceHandle(4)+Timeout(2)+CPF" vs "ListServices/ListIdentity/ListInterfaces 响应 payload = ItemCount+Items（无 6B 前缀）"
2. S2/S3 HexDump 删除 6B 前缀行，重新核算 Length
3. 所有 List* 相关测试用例 bytes 偏移断言重算

---

### C2：CIP CM 扩展状态码表 7 项错误（CRITICAL）

**位置**：§2.3.2（行 167-181）、§9.2（行 2300-2311）

**描述**：设计文档 §2.3.2 列出 10 个 Connection Manager 扩展状态码，对照 OpENer `cipconnectionmanager.h` `ConnectionManagerExtendedStatusCode` 枚举（55 个条目）：

| 设计文档值 | 设计文档名称 | OpENer 实际名称 | 更正 |
|-----------|-------------|----------------|------|
| 0x0100 | Connection in use or duplicate forward open | ErrorConnectionInUseOrDuplicateForwardOpen | ✓ |
| 0x0103 | Transport class not supported | ErrorTransportClassAndTriggerCombinationNotSupported | ✓名称略异 |
| 0x0107 | Connection size mismatch | **ErrorConnectionTargetConnectionNotFound** | 目标连接未找到，非"尺寸不匹配" |
| 0x0111 | Target connection not found | **RpiNotSupported** | RPI 不支持，非"目标连接未找到" |
| 0x0112 | Invalid connection size | **ErrorRpiValuesNotAcceptable** | RPI 值不可接受，非"无效连接尺寸" |
| 0x0203 | Connection timed out | ConnectionTimedOut | ✓ |
| 0x0204 | Unconnected request timed out | UnconnectedRequestTimedOut | ✓ |
| 0x0312 | Invalid consumption configuration | **LinkAddressNotValid** | 链路地址无效，非"无效消费配置" |
| 0x0313 | Consumption size exceeded | **不存在于 OpENer 枚举** | 删除此行 |
| 0x0315 | Wrong cloer | **ErrorInvalidSegmentTypeInPath** | 路径段类型无效，非"Wrong cloer" |
| — | — | 0xFFFF WrongCloser | 补充此行 |

此外，OpENer 枚举中还有 `0x0106 OwnershipConflict`、`0x0110 TargetNotConfigured`、`0x0116 RevisionMismatch`、`0x0127 InvalidOToTConnectionSize`、`0x0128 InvalidTToOConnectionSize` 等高频使用值，设计文档均遗漏。

**依据**：OpENer `source/src/cip/cipconnectionmanager.h` `ConnectionManagerExtendedStatusCode` 枚举（WebFetch 核实）。

**修复建议**：
1. §2.3.2 扩展状态码表按 OpENer 枚举重写，至少覆盖 20+ 常用值
2. §9.2 错误处理表同步修正：Forward_Close 连接不存在 → 0x01 + AddStatus 0x0107（非 0x0111）；Forward_Open RPI 不支持 → 0x01 + AddStatus 0x0111（非 0x0112）

---

### C3：Transport Class/Trigger 位布局错误（CRITICAL）

**位置**：§2.6（行 288-312）

**描述**：设计文档 §2.6 位布局：
```
bit 7    : Direction
bit 2-6  : Production Trigger（5 位）
bit 0-1  : Transport Class（2 位）
```

**地面真值**：Wireshark `epan/dissectors/packet-cip.h`：
```c
#define CI_TRANSPORT_CLASS_MASK     0x0F   // bit 0-3, 4 位
#define CI_PRODUCTION_TRIGGER_MASK  0x70   // bit 4-6, 3 位
#define CI_PRODUCTION_DIR_MASK      0x80   // bit 7, 1 位
```

正确位布局：
```
bit 7    : Direction（0=Server/1=Client）
bit 4-6  : Production Trigger（3 位；0=Cyclic、1=COS、2=Application）
bit 0-3  : Transport Class（4 位；0=Class 0、1=Class 1、2=Class 2、3=Class 3、4-15=Reserved）
```

**影响**：
- 常用值表（0x80=Class 0 Client、0x81=Class 1 Client 等）本身**正确**（bit 0-1 范围内恰巧对），但 Transport Class 实际有 4 位，Class 4-15 的取值文档未覆盖
- 位布局图错误会导致自定义 TransportClassTrigger 值时位计算失误
- §8.2 V-117 校验规则"bit 0-1 必须 0-3"过于严格，应为"bit 0-3 必须 0-3（bit 3 须为 0）"
- 常用值表应标注 bit 3 = 0（保留）

**修复建议**：
1. §2.6 位布局图改为 bit 0-3=Transport Class、bit 4-6=Production Trigger、bit 7=Direction
2. 常用值表补充注释"Class 4-15 reserved"
3. §8.2 V-117 改为"bit 0-3 有效值 0-3（bit 3 须 0）"

---

### H1：from_response O2T/T2O/ConnSerialNumber 偏移错误（HIGH）

**位置**：§5.6.1（行 920-927）、§3.6（行 550-573）

**描述**：设计文档 §5.6.1 表：

| StrategyConfig.field | 提取位置 | 偏移（CIP body 起算） |
|---------------------|----------|----------------------|
| o2t_connection_id | Forward_Open 响应 CIP body O2T_ConnID | **4** |
| t2o_connection_id | Forward_Open 响应 CIP body T2O_ConnID | **8** |
| connection_serial_number | Forward_Open 响应 CIP body ConnSerialNumber | **12** |

**地面真值**：OpENer `AssembleForwardOpenResponse` 确认成功响应字段顺序（CIP body 起始 = MR 头之后）：
- offset 0: O→T (Consumed) Connection ID (4B)
- offset 4: T→O (Produced) Connection ID (4B)
- offset 8: Connection Serial Number (2B)
- offset 10: Originator Vendor ID (2B)
- offset 12: Originator Serial Number (4B)

正确偏移应为：
- o2t_connection_id: offset **0**（CIP body 起算）
- t2o_connection_id: offset **4**（CIP body 起算）
- connection_serial_number: offset **8**（CIP body 起算）

**矛盾点**：
- §3.6 表写 "O2T 偏移 = 4 + N, T2O 偏移 = 8 + N"——这里"4+N"若理解为"从整个 CIP 响应起算，4 字节 MR 头 + 0 字节 AddStatus = 偏移 4"，则**O2T 在 CIP 响应偏移 4 = CIP body 偏移 0，T2O 在偏移 8 = CIP body 偏移 4**——§3.6 的"4+N"实际上是正确的（N=0 时 O2T 在响应偏移 4=CIP body 偏移 0）。
- 但 §5.6.1 明确说"**从 CIP body 起算**"且写 O2T=4、T2O=8——这是**错的**（多加了一个 4 字节 MR 头）。
- S7 HexDump 实际写的字节顺序又是**正确**的（O2T 紧跟 MR 头）。

**结论**：§5.6.1 偏移表数值错误（多加 4 字节），§3.6 表正确，S7 HexDump 正确。设计文档内部 §5.6.1 与 §3.6/S7 自相矛盾。

**影响**：
- 若实现者按 §5.6.1 实现 from_response 提取 O2TConnectionID，会多偏 4 字节读到 T2OConnectionID（值错误）
- T-044/T-045 测试断言 "body[4..7]=O2TConnID" 是 §5.6.1 的表驱动结果——实际 wire 上 O2T 在 body[0..3]

**修复建议**：
1. §5.6.1 表修正为 O2T offset=0、T2O offset=4、ConnSerialNum offset=8（均从 CIP body 起算）
2. T-044 断言改为 body[0..3]、T-045 改为 body[4..7]

---

### H2：ListIdentity Response 字段结构错误（HIGH）

**位置**：§3.11（行 641-657）

**描述**：设计文档 §3.11 ListIdentity Response Item 结构：
```
4    EncapsulationProtocolVersion (2B LE)   = 1
6    ProtocolVersion (2B LE)    = 0xFFFF
8    SocketAddress (16B)        SinFamily(2)+SinPort(2)+SinAddr(4)+SinZero(8)
```

**地面真值**：OpENer `EncodeListIdentityCipIdentityItem` 实际结构：
```
offset 0: Item TypeCode (2B) = 0x000C
offset 2: Item Length (2B)
offset 4: Protocol Version (2B) = kSupportedProtocolVersion = 1
offset 6: Socket Address = port(2) + address(4) (通过 EncapsulateIpAddress)
offset 12: sin_zero (8B)
offset 20: VendorID (2B)
...依此类推
```

**差异**：
1. ProtocolVersion = **0x0001**，非 0xFFFF。ODVA 规范明确"Protocol Version shall be 1"
2. 只有**1 个** ProtocolVersion 字段（2B），非设计文档写的"EncapsulationProtocolVersion(2) + ProtocolVersion(2)"=4B
3. SocketAddress 实际是 sin_family(2)+sin_port(2)+sin_addr(4)+sin_zero(8)=16B，设计文档同样 16B 但 offset 因缺少"EncapsulationProtocolVersion"字段而偏移 2 字节

**影响**：
- ListIdentity 响应 Item 的总长度差 2 字节（少算 1 个 ProtocolVersion 字段）
- ProtocolVersion=0xFFFF 不符合 ODVA 规范
- S3 HexDump 的 Item Data 核算和 Length 核算整体偏移 2 字节

**修复建议**：
1. §3.11 删除"EncapsulationProtocolVersion"字段行，ProtocolVersion 改为 0x0001
2. 重新核算 SocketAddress 起始偏移（应为 Item 内 offset 4，非 offset 8）
3. 更新 Item Data 总长度核算
4. S3 HexDump 重新对齐

---

### H3：Forward_Open 2B Connection Parameters 位布局可疑（HIGH）

**位置**：§3.5.1（行 531-537）

**描述**：设计文档 §3.5.1：
```
bit 0-10   : Connection Size（11 位）
bit 11     : Reserved (0)
bit 12     : Variable Length
bit 13-15  : Priority
```

Wireshark `packet-cip.c` 字段声明提示了不同布局：`hf_cip_cm_fwo_con_size`、`hf_cip_cm_fwo_fixed_var`、`hf_cip_cm_fwo_prio`、`hf_cip_cm_fwo_typ`、`hf_cip_cm_fwo_own`——存在 5 个字段而设计文档只有 4 个，且 `hf_cip_cm_fwo_typ`（Connection Type）、`hf_cip_cm_fwo_own`（Redundant Owner）未出现在设计文档的位布局中。

ODVA CIP 规范的实际布局通常为：
- bit 0-8: Connection Size（9 位）
- bit 9: Fixed/Variable
- bit 10-11: Priority
- bit 12: Reserved
- bit 13-14: Connection Type（0=Null, 1=Multicast, 2=Point-to-Point, 3=Reserved）
- bit 15: Redundant Owner

设计文档缺 Connection Type 和 Redundant Owner 两位段。虽然常用值（如 0x0200=9 位 Connection Size=0x0200）可能碰巧对，但位布局表本身不完整。

**影响**：构建器按错误位布局组装 Connection Parameters 字段时，bit 13-14（Connection Type）会被误解为 bit 13-15（Priority 的一部分），导致目标设备拒绝连接。

**修复建议**：查阅 ODVA CIP Volume 1 Connection Manager Object 规范，重写 §3.5.1 和 §3.5.2 两个位布局表。

---

### H4：ConnectionPath 与 RequestPath 混淆（HIGH）

**位置**：§5.2 行 807、§3.5 表行 36、§3.7 表行 11、S7/S8 HexDump

**描述**：Forward_Open 请求有**两个**不同路径：
1. **RequestPath**（CIP 头内）：指向 Connection Manager (Class 0x06 + Instance 0x01)——表示"请求目标是 Connection Manager 对象"
2. **ConnectionPath**（Forward_Open body 尾部）：指向 Assembly 实例 + Connection Point——表示"要打开到哪个 Assembly 的连接"

§5.2 ConnectionPath 字段注释："默认自动编码 0x20 0x06 0x24 0x01 + Assembly 实例"——0x06 是 Connection Manager，但 ConnectionPath 应指向 Assembly (Class 0x04)。

S7 HexDump RequestPath=`20 06 24 01`（正确），ConnectionPath=`20 04 24 01`（正确）——HexDump 本身正确，但 §5.2 注释和 T-042 测试用例混写了两个路径。

S8 Forward_Close ConnectionPath 是 `20 06 24 01`——但 Forward_Close 的 ConnectionPath 应与 Forward_Open 的 ConnectionPath **一致**（Assembly 实例 + Connection Point），而非 Connection Manager。Forward_Close 的 RequestPath 才是指向 Connection Manager (Class 0x06 + Instance 0x01)。

**影响**：
- T-042 断言 "body offset 36..=`20 06 24 01`" 是错的（那是 RequestPath，不是 ConnectionPath）
- S8 ConnectionPath 用 Class 0x06 会被 OpENer 返回 0x0316（ConnectionPathMismatch）

**修复建议**：
1. §5.2 ConnectionPath 注释改为 "默认自动编码 0x20 0x04 0x24 0x01 + Connection Point"
2. §3.7 表 clarify RequestPath vs ConnectionPath：Forward_Close 有 RequestPath（CIP 头，Class 0x06）+ ConnectionPath（body 尾部，与 Forward_Open 一致）
3. S8 Forward_Close 区分 RequestPath（`20 06 24 01`）和 ConnectionPath（`20 04 24 01 + Connection Point`）
4. T-042 拆为 T-042a（RequestPath 断言）和 T-042b（ConnectionPath 断言）

---

### H5：Transport Class 4 位扩展的影响（HIGH）

**位置**：§2.6（行 296）、§8.2 V-117（行 2242）

**描述**：Transport Class 实际是 bit 0-3（4 位），非 bit 0-1（2 位）。Class 取值 0-3 合法，4-15 reserved（但规范允许扩展）。

§8.2 V-117：`bit 0-1 必须 0-3`——应改为 `bit 0-3：低 2 位须为 0-3；bit 2-3 须均为 0（reserved）`，或简化为 `(value & 0x0F) <= 3`。

**影响**：Validate 规则过于宽松（bit 2-3 未校验为 0），可能导致非法 Class 值通过验证。

---

### M1："35 字节固定字段"表述歧义（MEDIUM）

**位置**：§3.5 行 524

**描述**：TransportClassTrigger 在 offset 34，ConnPathSize 在 offset 35。35 若不含 ConnPathSize 则正确（从 0 到 34 共 35 字节），但注释未明确是"含/不含 ConnPathSize"。

**修复建议**：明确 "总固定字段 = 36 字节（含 ConnPathSize），35 字节（不含 ConnPathSize）。以下 35 字节指不含 ConnPathSize。"

---

### M2：AddStatus Size 单位歧义（MEDIUM）

**位置**：§3.4.2 行 496、§3.6 行 558、§3.8 行 603

**描述**：§3.4.2 明确 Size of Additional Status 单位是"word 数"。但 §3.6 表"Size of Additional Status, 0=成功；错误时通常 1 或 2"未标单位；§3.8 表同样。读者可能误解为 byte。

**修复建议**：§3.6/§3.8 表统一写 "1 或 2 word"。

---

### M3：0x52 双义消歧（MEDIUM）

**位置**：§2.5.2 行 269、§2.5.3 行 277

**描述**：0x52 在两个表中出现，注释"由路径上下文区分"。但 §4.3 推导表未体现路径区分逻辑，默认推导为 SendRRData Unconnected。实现时若用户配 class_id=0x73（Logix Tag），如何处理？

**修复建议**：§4.3 补充说明"0x52 在 trafficgen 中默认按 Unconnected_Send 处理；若需 Logix Read Tag Fragmented，需设置 class_id 偏移判定"。

---

### M4：LargeForwardOpen 4B Params 位布局自矛盾（MEDIUM）

**位置**：§3.5.2 行 541-546

**描述**：bit 0-31 占满，同时 bit 13-22 另有定义。应分字段或标明确切优先级。

**修复建议**：查阅 ODVA 规范重写。

---

### M5：错误处理表引错误状态码（MEDIUM）

**位置**：§9.2 行 2308-2310

**描述**：§9.2 行 2308 "Forward_Close 连接不存在 → AddStatus 0x0111"——C2 修复后应为 0x0107。行 2310 "Forward_Open RPI 不支持 → AddStatus 0x0112"——C2 修复后应为 0x0111。

**修复建议**：随 C2 同步修正。

---

### L1：EPATH 段字节公式易误读（LOW）

**位置**：§2.7.2 行 333

**描述**：公式 "0x20 | LogicalType(bit 2-4) | LogicalFormat(bit 0-1)" 中 LogicalType 表首列是已移位值（0x00/0x04/0x08...），非原始值（0/1/2/3/4/5）。建议改为 "0x20 | (LogicalType << 2) | LogicalFormat"。

---

### L2：T-042 测试混淆（LOW）

**位置**：§7.2 T-042 行 1998

**描述**：T-042 "Forward_Open ConnectionPath，Path=`20 06 24 01`" 断言 body offset 36=此值——但这是 RequestPath，不是 ConnectionPath。参见 H4。

---

### L3：T-096/T-112 输入描述含解释文字（LOW）

**位置**：§7.3 行 2057、行 2073

**描述**：T-096 输入列写 "TransportClassTrigger=0x05 (无效 bit 0-1=01 但... 实际 0x05 合法。改用 0x10 (bit 0-1=00... 超范围)"——800+ 字符的解释嵌在输入列。测试输入应仅含具体值。违反 CLAUDE.md 测试"输入明确"原则。

---

### L4：修订追加测试覆盖不完整（LOW）

**位置**：§7.7 T-201~T-220

**描述**：20 条测试覆盖 32 项修订——多项修订（D-HIGH-2 FirmwareRevision 拆分、D-HIGH-3 TransportClassTrigger 位布局、D-MED-5 SendUnitData TCP、D-MED-6 删除 MSS 分段）无对应测试。缺少 C3（Transport Class 4 位）和 H1（from_response 偏移）的测试。

---

## 4. 已确认正确的修复

以下 v1 审计发现的修复在 v2.0.0 中已正确实施，本复审确认无误：

| v1 发现 | v2.0.0 修复 | 复审确认 |
|---------|-------------|----------|
| D-CRIT-1 CIP 服务码表 | §2.5 重写全部服务码 | ✓ OpENer 核实 |
| D-CRIT-2 EPATH 段类型表 | §2.7.2 重写全部段字节值 | ✓ 公式表述可改进但值正确 |
| D-CRIT-3 字节序 | 全文 LE | ✓ |
| D-CRIT-4 Interface Handle 前缀 | §2.4/§3.3 增加 | ✓（但 List* 响应误加，见 C1） |
| D-CRIT-5 ENIP Status 表 | §2.3 重写为 7 个合法值 | ✓ |
| D-CRIT-6 Forward_Open 字段顺序 | §3.5 重写为 15 字段顺序 | ✓ OpENer 核实 |
| D-CRIT-7 RegisterSession 无 CPF | §3.2 改为 4B payload | ✓ |
| D-CRIT-8 CPF TypeID 表 | §2.4.1 全部纠正 | ✓ |
| D-HIGH-1 Sockaddr TypeID 补充 | §2.4.1 增加 0x8000/0x8001/0x8002 | ✓ |
| D-HIGH-2 FirmwareRevision 拆分 | §2.9 major(1B)+minor(1B) | ✓ |
| D-HIGH-4 Forward_Close 请求体 | §3.7 三元组定位 | ✓（但 ConnectionPath 见 H4） |
| D-HIGH-6 MSP 结构 | §3.9 重写 | ✓ |
| D-HIGH-7 Get/Set_Attribute_List | §3.10 0x03/0x04 | ✓ |
| Forward_Open 响应字段顺序 | §3.6/S7 HexDump O→T 在前 | ✓ OpENer 核实（§5.6.1 表格偏移除外，见 H1） |
| S7/S8/S10/S14 请求 HexDump | 大量 HexDump 正确 | ✓ 逐字节核算 |

---

## 5. 最终结论

### 5.1 问题统计

| 严重度 | 数量 |
|--------|------|
| CRITICAL | 3 (C1, C2, C3) |
| HIGH | 5 (H1, H2, H3, H4, H5) |
| MEDIUM | 5 (M1, M2, M3, M4, M5) |
| LOW | 4 (L1, L2, L3, L4) |
| **总计** | **17** |

### 5.2 结论

**本文档不可直接进入实现阶段。**

v2.0.0 相比 v1 在 CIP 服务码、EPATH 段类型、ENIP 字节序等关键安全漏洞上已修正，但 3 项 CRITICAL 残存问题会直接导致生成的网络包字节布局错误：

1. **C1**（List* 响应含 6B 前缀）——S2/S3/S11 的 HexDump Length 全部错误，tshark 解析失败
2. **C2**（CM 扩展状态码表）——错误响应解析、log 输出、Validate 校验全部基于错误状态码
3. **C3**（Transport Class/Trigger 位布局）——自定义 TransportClassTrigger 值时位计算错误

5 项 HIGH 问题进一步影响 from_response 机制、ListIdentity 响应结构、ConnectionPath 语义、位字段精确布局。

### 5.3 修复优先级

1. **P0（阻塞）**：C1 + C2 + C3 + H1 + H2 + H4
2. **P1（关键）**：H3 + H5 + M1 + M2
3. **P2（改善）**：M3 + M4 + M5
4. **P3（优化）**：L1 + L2 + L3 + L4

建议修复 P0+P1 后进行 r2 复审，然后可进入实现阶段。

---

**审计报告结束**

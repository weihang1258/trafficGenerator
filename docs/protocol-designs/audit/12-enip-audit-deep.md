# ENIP 设计文档深度对抗式审计报告

**审计目标**：`/home/weihang/trafficGenerator/docs/protocol-designs/12-enip-design.md`
**审计性质**：独立审计（非设计者），对照 ODVA EtherNet/IP Volume 1 & 2 与 CIP Common Specification
**审计日期**：2026-08-04
**审计方法**：逐节比对设计文档与 ODVA 参考实现（OpENer / libplctag / cpppo / EEIP.Java），默认"有 bug"假设

## 0. 审计依据来源

本审计以 ODVA 参考实现为权威依据，引用下列开源代码作为规范地面真值（ground truth）：

1. **OpENer**（EIPStackGroup/OpENer）：Rockwell Automation 出品的官方参考实现，定义了 CIP 服务码枚举 `CIPServiceCode`（`source/src/cip/ciptypes.h`）、CPF TypeID 枚举 `CipItemId`（`source/src/enet_encap/cpf.h`）、ENIP Status 枚举（`source/src/enet_encap/encap.h`）、EPATH 段类型常量（`source/src/cip/cipepath.h`）。
2. **libplctag**（libplctag/libplctag）：工业级 AB PLC 通信库，`defs.h` 给出 Forward_Open=0x54、Forward_Close=0x4E、CIP_READ=0x4C、CIP_WRITE=0x4D 等服务码。
3. **EEIP.Java**（rossmann-engineering/EEIP.Java）：明确列出 "Table 2-3.2 Encapsulation Commands" 与 "Table A-3.1 Volume 1 Chapter A-3" 的 CIP 通用服务码枚举。
4. **cpppo**（pjkundert/cpppo）：在 `parser.py` 注释中明确段类型 "0x30 == Attribute ID, 8-bit"、"0x38 == 8-Bit Service ID Segment"。

---

## 1. 严重问题汇总

| 编号 | 严重度 | 节号 | 摘要 |
|------|--------|------|------|
| D-CRIT-1 | CRITICAL | §2.5, §3.3.1, §6.9, §6.10, §6.13, §6.14 | **CIP 服务码表大面积错误**：Forward_Open/Forward_Close/Multiple_Service_Packet/Get/Set/Get_Attribute_List/Set_Attribute_List 全部用错值 |
| D-CRIT-2 | CRITICAL | §2.7, §3.8.1 | **EPATH 段类型表 7 项中 6 项错误**：0x21/0x24/0x25/0x26/0x2C/0x30 的语义全部错位，导致 `EncodeCIPPath` 输出非法路径 |
| D-CRIT-3 | CRITICAL | 附录 C, 附录 D | **整个 ENIP 头/CPF 编码使用大端序**（`binary.BigEndian.PutUint16/32`），但 ODVA 规范强制 little-endian |
| D-CRIT-4 | CRITICAL | §2.4 | **SendRRData/SendUnitData payload 缺少 Interface Handle(4B)+Timeout(2B) 前缀**，CPF ItemCount 不是 payload 第一个字段 |
| D-CRIT-5 | CRITICAL | §2.3 | **ENIP Status 错误码表 6 个值中 5 个错误**：InvalidSession=0x04/InvalidLength=0x05/UnsupportedProtocol=0x06 应为 0x64/0x65/0x69；TargetNotFound/InvalidConnection/ConnectionTimeout 不属于 ENIP Status 层 |
| D-CRIT-6 | CRITICAL | §6.9 | **Forward_Open 请求体字段顺序与字段重复**：实际顺序为 SecSN(2)+OVendor(2)+OSerial(4)+TimeoutMult(1)+3B保留+O2T_RPI(4)+O2T_ConnParams(2)+T2O_RPI(4)+T2O_ConnParams(2)+TransportClassTrigger(1)；设计文档列出的字段重复且缺少 ConnectionSerialNumber/OriginatorVendorID/OriginatorSerialNumber/TimeoutMultiplier/Reserved |
| D-CRIT-7 | CRITICAL | §2.4, §6.4 | **RegisterSession payload 不使用 CPF**：规范规定 RegisterSession 的 payload 直接是 ProtocolVersion(2)+OptionFlag(2)，不携带任何 CPF item；设计文档 §6.4 写 `cpf_items:[{type_id:0x0000, payload:"\x01\x00"}]` 是错的 |
| D-CRIT-8 | CRITICAL | §2.4 | **CPF TypeID 0x0100 错标为 ListIdentity Response**：0x0100 实际是 ListServices Response；ListIdentity Response 的 TypeID 是 0x000C |
| D-HIGH-1 | HIGH | §2.4 | **遗漏 3 个 CPF TypeID**：未列出 Sockaddr Info O→T (0x8000)、T→O (0x8001)、Sequenced Address (0x8002)；这些是 Forward_Open 必备项 |
| D-HIGH-2 | HIGH | §3.2 FirmwareRevision | **FirmwareRevision 类型/大小错误**：Identity 对象属性 4 Revision 是 `{USINT major, USINT minor}` 共 2 字节；设计文档注释"major(2B)+minor(2B)"且类型 `uint16`，共 2 字节凑巧对，但语义错（应是 2×USINT 而非 1×UINT16） |
| D-HIGH-3 | HIGH | §2.6 | **TransportType 位字段描述错误**：实际位布局是 bit 0-1 = Logical Format（0=8bit/1=16bit/2=32bit），bit 2-4 = Logical Type，bit 5-7 = Segment Type；设计文档把 "bit 7 = 方向、bit 0-1 = Class" 与 TransportClass_Trigger 字段（Forward_Open 中的 1 字节）混淆。TransportClass_Trigger 的 bit 7 是方向（0=Server/1=Client），bit 0-1 是 Class（0/1/3），但 §2.6 把它当作独立枚举值列表，与 EPATH 段类型概念混淆 |
| D-HIGH-4 | HIGH | §6.10 Forward_Close | **Forward_Close 请求体字段错误**：实际是 Priority/TimeTick(1)+TimeoutTicks(1)+ConnectionSerialNumber(2)+OriginatorVendorID(2)+OriginatorSerialNumber(4)+ConnectionPathSize(1)+ConnectionPath；设计文档漏掉 ConnectionSerialNumber/OriginatorVendorID/OriginatorSerialNumber，且 §6.10 的 "ConnectionID+路径" 是错的 |
| D-HIGH-5 | HIGH | §3.3.1 | **CIPService=0x4B/0x4C "PCCC Execute" 服务码描述混乱**：0x4B 是 Execute PCCC（在 CIP 通道上执行 PCCC，Class 3 connected 服务），0x4C 在 libplctag 中是 CIP_READ（Logix 5000 专用 Read Tag），不是"PCCC Execute 别名" |
| D-HIGH-6 | HIGH | §6.13 Multiple_Service_Packet 结构 | **Multiple_Service_Packet 请求结构错误**：实际是 Service(0x0A)+PathSize+Path+OffsetCount(2)+Offsets[]+子请求；设计文档 §6.13 描述 "Service(0x0E)+PathSize+Path+OffsetCount(2)+[Offset(2)+ServiceRequest...]"——Service 码错（0x0E 是 Get_Attribute_Single），且偏移数组与子请求的排布描述含糊 |
| D-HIGH-7 | HIGH | §6.14 Get/Set_Attribute_List | **服务码与 CIP 请求结构双双错误**：Get_Attribute_List 实际是 0x03（不是 0x54），Set_Attribute_List 是 0x04（不是 0x55）；CIP 请求是 Service+Path(Class+Instance)+AttributeCount(2)+[AttrID(2)]...；设计文档同时用错服务码和编码辅助 |
| D-HIGH-8 | HIGH | §3.7.1 from_response 字段表 | **`connection_id` 字段提取位置错误**：Forward_Open 响应中 O2T_NetworkConnID 不是 "offset 4"；Forward_Open 响应体结构是 Service(1)+Reserved(1)+Status(1)+4B 保留 + ... 实际 O2T_ConnID 偏移需对照规范；§3.7.1 给出的 "offset 4" 是 ENIP 头 SessionHandle 偏移，混淆了 ENIP 头与 CIP body |
| D-MED-1 | MEDIUM | §6.3 ListInterfaces | **ListInterfaces payload 描述错误**：实际 ListInterfaces 请求无 payload（响应携带 ItemCount=0 表示无接口）；设计文档 §6.3 写 "CPF Unconnected Data Item + CIP Get (Class 0xF5...)" 是把 ListInterfaces 与 Get_Attribute_Single 混为一谈 |
| D-MED-2 | MEDIUM | §2.5 | **CIP 服务表缺失关键服务**：缺少 0x02 Set_Attributes_All、0x0D Apply_Attributes、0x11 Find_Next_Object_Instance、0x14 Error_Response、0x15 Restore、0x16 Save、0x17 NOP、0x18-0x1B Member 系列、0x1C GroupSync；且把 0x54 列为 Get_Attribute_List 占用了 Forward_Open 的位置 |
| D-MED-3 | MEDIUM | §3.3.1 自动推导规则 | **自动推导表与 §6.4 矛盾**：表中说 CIPService=0x10 Forward_Open → SendRRData，但 0x10 实际是 Set_Attribute_Single；这意味着所有自动推导测试用例（P07/P10-P12）的输入假设全部错误 |
| D-MED-4 | MEDIUM | §3.8.1 EncodeCIPPath 签名 | **`EncodeCIPPath(classID uint8, instanceID uint16, attrID uint8)` 签名错误**：classID 实际可以是 uint16（Class 0xF5/0xF6 等都需要 16-bit 段），attrID 也常用 uint16；签名应允许 16-bit，且返回值需根据值大小选择 8-bit/16-bit 段格式 |
| D-MED-5 | MEDIUM | §3.3.2 SendRRData/SendUnitData 混淆防范 | **混淆"通道"与"传输层"**：§1.1 表说 SendUnitData 用 UDP，但 ODVA 规范规定 SendUnitData 也可在 TCP 上传输（Class 3 connected messaging via TCP）；设计文档把它强制绑定 UDP 是错的 |
| D-MED-6 | MEDIUM | §5.3 MSS 分段 | **MSS 分段规则违反 ENIP 规范**：ENIP 规范规定单条 ENIP 消息的 Length 字段最大 65515，且单条 ENIP 消息应作为单个 TCP 流提交，**不应在 ENIP 层做 MSS 分段**；MSS 分段由 TCP 层透明处理。设计文档 §5.3 让 planner 主动切分 CIP 数据为多个 PSH-ACK 段，会导致 ENIP 头部重复出现，接收方解析出错 |
| D-MED-7 | MEDIUM | §6.4 字段引用 | **`command_index:5` 示例与 Commands[] 索引规则不符**：§6.4 描述 "config 中的 SessionHandle 可以是策略引用（如 {strategy:from_response, command_index:5}）"，但 §3.7.1 的字段名是 `source_command_index` 而非 `command_index`，且无 `field` 字段，前后不一致 |
| D-MED-8 | MEDIUM | §6.16 多设备 SubFlow 命名 | **`<device_flow_id>:io` 命名约定缺少来源说明**：设计文档未说明 `<device_flow_id>` 是什么——是 SubFlow 的 FlowID？父 FlowID？多设备场景下每个设备主 FlowID 如何生成？该字段在 §6.16 突然出现但无前置定义 |
| D-MED-9 | MEDIUM | §6.17 B10 FrameSize 上限计算 | **65493 计算包含 8B UDP 头 + 20B IP 头，但 ENIP 帧已不在 IP/UDP 层以下**：FrameSize 是 I/O 数据 payload 大小，ENIP 头+CPF+payload 总和受 UDP datagram 65507 字节限制；正确上限应为 65507 - 24 - 2 - 6 - 4 = 65471，而非 65493（误用 IP MTU 65535 而非 UDP datagram 上限） |
| D-MED-10 | MEDIUM | §3.3 ENIPCommand.Direction | **Direction 字段语义不明**："up"/"down" 与 ENIP 规范无关；ENIP 是请求-响应协议，方向由 Command 语义决定（如 SendRRData 请求 vs 响应）；把 Direction 作为 config 字段会让用户能任意伪造"server→client"方向的请求包，违反协议 |
| D-LOW-1 | LOW | §1.1 表格 | **"隐式消息（Implicit / I/O Messaging）UDP 44818"描述不完整**：ODVA 规范允许 I/O 通过 TCP（Class 3 connected）或 UDP（Class 0/1 multicast）传输；强制绑定 UDP 不准确 |
| D-LOW-2 | LOW | §2.2 命令表 | **Nop(0x0000) 描述"无 payload"且"双向"**：ODVA 规范规定 NOP 仅 TCP，且可携带任意 payload（接收方忽略）；设计文档说"无 payload"是错的 |
| D-LOW-3 | LOW | §2.2 命令表 | **IndicateStatus(0x0072) 方向标 "resp→req"**：实际是 server 主动向 client 推送状态，方向应是 "server→client" 而非 "resp→req" |
| D-LOW-4 | LOW | §2.5 PCCC 服务码 | **0x4B/0x4C 同时列为 PCCC Execute**：libplctag 中 0x4B=Execute PCCC、0x4C=CIP_READ（Read Tag，Logix 专用），不是同一服务的别名 |
| D-LOW-5 | LOW | §3.5 ENIPIOData.TransportType 默认值 | **"0=默认 0x01 Class 0 Server"** 与 §6.11 "transport_type: 1" 重复声明，但 §6.12 又说 "transport_type: 0 不是合法值（会被默认化为 0x01）"，前后表述不一致 |
| D-LOW-6 | LOW | §7.1 V08 | **V08 测试名 "SessionHandle 策略类型错误"** 与 §3.7.1 描述的 `from_response`/`fixed`/`inc` 三种合法策略不符——`inc` 是否真的合法？SessionHandle 递增无业务意义，应只允许 `from_response`/`fixed` |

---

## 2. 详细问题分析

### D-CRIT-1：CIP 服务码表大面积错误（CRITICAL）

**位置**：§2.5（行 127-145）、§3.3.1（行 411-426）、§6.9（行 887-907）、§6.10（行 911-921）、§6.13（行 959-977）、§6.14（行 980-991）

**描述**：设计文档 §2.5 的 CIP 服务码表存在系统性的服务码错位。以下是逐项对照（依据 OpENer `ciptypes.h` 的 `CIPServiceCode` 枚举与 libplctag `defs.h`）：

| 服务名 | 设计文档值 | ODVA 规范值 | 依据 |
|--------|-----------|-------------|------|
| Get_Attributes_All | 0x01 | 0x01 | ✓ 正确 |
| Get (读取单个属性) | 0x03 | **0x0E** (Get_Attribute_Single) | OpENer `kGetAttributeSingle = 0x0E` |
| Set (写入单个属性) | 0x04 | **0x10** (Set_Attribute_Single) | OpENer `kSetAttributeSingle = 0x10` |
| Reset | 0x05 | 0x05 | ✓ |
| Start | 0x06 | 0x06 | ✓ |
| Stop | 0x07 | 0x07 | ✓ |
| Create | 0x08 | 0x08 | ✓ |
| Delete | 0x09 | 0x09 | ✓ |
| Multiple_Service_Packet | **0x0E** | **0x0A** | OpENer `kMultipleServicePacket = 0x0A` |
| Forward_Open | **0x10** | **0x54** | OpENer `kForwardOpen = 0x54`；libplctag `AB_EIP_CMD_FORWARD_OPEN = 0x54` |
| Forward_Close | **0x11** | **0x4E** | OpENer `kForwardClose = 0x4E`；libplctag `AB_EIP_CMD_FORWARD_CLOSE = 0x4E` |
| Get_Attribute_List | **0x54** | **0x03** | OpENer `kGetAttributeList = 0x03` |
| Set_Attribute_List | **0x55** | **0x04** | OpENer `kSetAttributeList = 0x04` |
| LargeForwardOpen | **未列出** | **0x5B** | OpENer `kLargeForwardOpen = 0x5B`；libplctag `AB_EIP_CMD_FORWARD_OPEN_EX = 0x5B` |

**根本原因**：设计者将"Get/Set"（俗称）对应到了 0x03/0x04，但 0x03 实际是 Get_Attribute_List（批量）、0x04 是 Set_Attribute_List（批量）；真正的单属性读写是 0x0E/0x10。Forward_Open 0x54 被误标为 Get_Attribute_List，Forward_Close 0x4E 被误标为 Set_Attribute_List，0x10（Set_Attribute_Single）被误标为 Forward_Open，0x11（Find_Next_Object_Instance）被误标为 Forward_Close。

**影响**：
- §3.3.1 自动推导表把 `cip_service:0x10` 推导为 "Forward_Open"，但实际 0x10 是 Set_Attribute_Single；用户写 `cip_service:0x10` 期望打开连接，生成的却是单属性写请求。
- §6.9 "Forward_Open (0x10)" 与 §6.10 "Forward_Close (0x11)" 全章节基于错误服务码，所有 Forward_Open/Close 相关测试（P07）都会生成错误包。
- §6.13 Multiple_Service_Packet 用 0x0E 作为服务码，实际 0x0E 是 Get_Attribute_Single；生成的"多服务包"会被对端解析为单属性读请求。
- §6.14 Get_Attribute_List 用 0x54、Set_Attribute_List 用 0x55，但 0x54 是 Forward_Open、0x55 在 libplctag 中是 List Tags（Logix 专用）；批量属性读写完全无法工作。
- §3.8.1 `EncodeAttributeListRequest` 的调用约定基于错误服务码，编码辅助函数无法生成合规包。
- 附录 B 默认命令序列 `{Command: 0x006F, CIPService: 0x10, ...}` 注释为 "SendRRData Forward_Open"，但 CIPService=0x10 实际是 Set_Attribute_Single。

**依据**：ODVA CIP Common Specification Volume 1, Table A-3.1；OpENer `source/src/cip/ciptypes.h` 的 `CIPServiceCode` 枚举；libplctag `src/libplctag/protocols/ab/defs.h`；EEIP.Java `CIPCommonServicesEnum.java`。

**修复建议**：
1. 重写 §2.5 CIP 服务码表，按 ODVA 规范逐项纠正：
   - 0x01 Get_Attributes_All
   - 0x02 Set_Attributes_All
   - 0x03 Get_Attribute_List
   - 0x04 Set_Attribute_List
   - 0x05 Reset
   - 0x06 Start / 0x07 Stop / 0x08 Create / 0x09 Delete
   - 0x0A Multiple_Service_Packet
   - 0x0D Apply_Attributes
   - 0x0E Get_Attribute_Single
   - 0x10 Set_Attribute_Single
   - 0x11 Find_Next_Object_Instance
   - 0x54 Forward_Open
   - 0x5B LargeForwardOpen
   - 0x4E Forward_Close
   - 0x52 Unconnected_Send
   - 0x4B Execute PCCC
2. 同步更新 §3.3.1 自动推导表、§6.9-6.14、§3.8.1 编码辅助函数签名、附录 B 默认序列。
3. §6.13 Multiple_Service_Packet 改用 0x0A。
4. §6.14 Get/Set_Attribute_List 改用 0x03/0x04。

---

### D-CRIT-2：EPATH 段类型表 7 项中 6 项错误（CRITICAL）

**位置**：§2.7（行 168-192）、§3.8.1（行 600-619）

**描述**：§2.7 的 EPATH 段类型表对照 OpENer `cipepath.h` 的常量定义完全错位。EPATH 段字节布局为 `Segment Type (bit 5-7) | Logical Type (bit 2-4) | Logical Format (bit 0-1)`，其中 Logical Segment = 0x20。

| 段字节 | 设计文档命名 | ODVA 规范命名 | 计算公式 |
|--------|-------------|---------------|----------|
| 0x20 | Class Segment 8-bit | Class Segment 8-bit ✓ | `0x20 \| 0x00 \| 0x00` |
| 0x21 | Instance Segment 8-bit | **Class Segment 16-bit** | `0x20 \| 0x00 \| 0x01` |
| 0x24 | Instance Segment 16-bit | **Instance Segment 8-bit** | `0x20 \| 0x04 \| 0x00` |
| 0x25 | Element Segment | **Instance Segment 16-bit** | `0x20 \| 0x04 \| 0x01` |
| 0x26 | Element Segment 16-bit | **Instance Segment 32-bit** | `0x20 \| 0x04 \| 0x02` |
| 0x2C | Attribute Segment 8-bit | **Connection Point 8-bit** | `0x20 \| 0x0C \| 0x00` |
| 0x30 | Service Segment 8-bit | **Attribute Segment 8-bit** | `0x20 \| 0x10 \| 0x00` |
| 0x38 | （未列出） | Service Segment 8-bit | `0x20 \| 0x18 \| 0x00` |
| 0x28 | （未列出） | Member Segment 8-bit | `0x20 \| 0x08 \| 0x00` |

**依据**：OpENer `source/src/cip/cipepath.h`：
```c
#define SEGMENT_TYPE_LOGICAL_SEGMENT 0x20
#define LOGICAL_SEGMENT_TYPE_CLASS_ID     0x00  // 0x20|0x00|fmt
#define LOGICAL_SEGMENT_TYPE_INSTANCE_ID  0x04  // 0x20|0x04|fmt
#define LOGICAL_SEGMENT_TYPE_MEMBER_ID    0x08  // 0x20|0x08|fmt
#define LOGICAL_SEGMENT_TYPE_CONNECTION_POINT 0x0C  // 0x20|0x0C|fmt
#define LOGICAL_SEGMENT_TYPE_ATTRIBUTE_ID 0x10  // 0x20|0x10|fmt
#define LOGICAL_SEGMENT_TYPE_SERVICE_ID   0x18  // 0x20|0x18|fmt
#define LOGICAL_SEGMENT_FORMAT_EIGHT_BIT      0x00
#define LOGICAL_SEGMENT_FORMAT_SIXTEEN_BIT    0x01
#define LOGICAL_SEGMENT_FORMAT_THIRTY_TWO_BIT 0x02
```
cpppo `parser.py` 注释明确："0x30 == Attribute ID, 8-bit"、"0x31 == Attribute ID, 16-bit"、"0x38 == 8-Bit Service ID Segment"。

**影响**：
- §2.7 示例 "20 01 24 01 00 2C 03"（声称 = Class 0x01 + Instance 16-bit 0x0001 + Attribute 3）实际解析为：Class 0x01 + Instance 8-bit 0x01（多余 0x00）+ Connection Point 0x03。完全无法定位到目标属性。
- §3.8.1 `EncodeCIPPath(0x04, 0x0001, 3)` 返回 `[0x20, 0x04, 0x24, 0x01, 0x00, 0x2C, 0x03]`（N06 测试断言此值），但 0x24 是 Instance 8-bit，传 0x0001 会被截断或解析为 Instance=1 + 多余 0x00 字节；0x2C 是 Connection Point 不是 Attribute。
- 设计文档 §2.7 还说 "RequestPathSize = ⌈5/2⌉ = 3 words" 用 `20 04 24 01 00`（5 字节）举例，但这 5 字节实际是 Class 0x04 + Instance 8-bit 0x01 + 多余 0x00，不是 Class 0x04 + Instance 16-bit 0x0001。
- 所有依赖 EncodeCIPPath 的测试（N06/N07/P11/P12）和 Forward_Open 的 ConnectionPath 都会生成非法路径。

**修复建议**：
1. 重写 §2.7 段类型表，按 ODVA EPATH 规范纠正：
   - 0x20 = Class 8-bit / 0x21 = Class 16-bit / 0x22 = Class 32-bit
   - 0x24 = Instance 8-bit / 0x25 = Instance 16-bit / 0x26 = Instance 32-bit
   - 0x28 = Member 8-bit / 0x29 = Member 16-bit
   - 0x2C = Connection Point 8-bit / 0x2D = Connection Point 16-bit
   - 0x30 = Attribute 8-bit / 0x31 = Attribute 16-bit
   - 0x38 = Service 8-bit
2. 修改 `EncodeCIPPath` 签名为 `EncodeCIPPath(classID uint16, instanceID uint32, attrID uint16) []byte`，根据值大小自动选择 8-bit/16-bit/32-bit 段格式。
3. §2.7 示例改为 `20 01 25 01 00 30 03`（Class 0x01 + Instance 16-bit 0x0001 + Attribute 0x03，共 7 字节，RequestPathSize=4 words）。
4. N06 测试断言改为 `[0x20, 0x01, 0x25, 0x01, 0x00, 0x30, 0x03]`（如果 EncodeCIPPath 选择 Instance 16-bit）或 `[0x20, 0x04, 0x24, 0x01, 0x30, 0x03]`（如果 Instance 用 8-bit 因为 0x01 在 8-bit 范围内）。

---

### D-CRIT-3：ENIP 头/CPF 编码使用大端序，规范强制 little-endian（CRITICAL）

**位置**：附录 C（行 1340-1351）、附录 D（行 1355-1373）、§9.5（行 1306-1310）

**描述**：附录 C 的 `buildENIPHeader` 使用 `binary.BigEndian.PutUint16/32` 编码 ENIP 头的所有字段（Command/Length/SessionHandle/Status/SenderContext/Options）。附录 D 的 `buildCPFEnvelope` 同样使用 `binary.BigEndian.PutUint16` 编码 ItemCount 和 TypeID/Length。

但 ODVA EtherNet/IP 规范 Volume 2 明确规定 **ENIP 封装层所有多字节字段使用 little-endian 字节序**。

**依据**：
- OpENer `endianconv.c` 的 `AddIntToMessage` / `AddDintToMessage` 函数将低字节先写入（little-endian）：
  ```c
  outgoing_message->current_message_position[0] = (unsigned char) data;
  outgoing_message->current_message_position[1] = (unsigned char) (data >> 8);
  ```
- OpENer `GenerateEncapsulationHeader` 使用 `AddIntToMessage`/`AddDintToMessage` 写入所有 ENIP 头字段。
- EEIP.Java `CommonPacketFormat.toBytes()` 明确按 little-endian 写入（`returnValue[0] = (byte)ItemCount; returnValue[1] = (byte)(ItemCount >> 8);`）。
- §9.5 还写 "uint16/uint32 大端序编码（ENIP 头）"——这是直接违反规范的注释。

**影响**：
- 所有 ENIP 包的 Command、Length、SessionHandle 字段都会以大端序出现在线缆上，任何合规的 ENIP 接收方（包括 Wireshark ENIP 解析器、OpENer、libplctag）都无法解析。
- 集成测试 I01（"产出的 PCAP 能被 Wireshark tshark ENIP 解析器正确识别"）必然失败。
- 这是一个会导致整个协议实现无法工作的根本性错误。

**修复建议**：
1. 附录 C `buildENIPHeader` 全部改为 `binary.LittleEndian.PutUint16/32`。
2. 附录 D `buildCPFEnvelope` 同样改为 `binary.LittleEndian`。
3. §9.5 依赖说明改为 "encoding/binary：uint16/uint32 **little-endian** 编码（ENIP 头、CPF、CIP 多字节字段）"。
4. SenderContext 是 8 字节不透明字段（无字节序概念），但 Options 是 uint32 LE。
5. 在所有 HexDump 示例中验证字节序：例如 ListIdentity (0x0063) 在线缆上应是 `63 00` 而非 `00 63`。

---

### D-CRIT-4：SendRRData/SendUnitData payload 缺少 Interface Handle + Timeout 前缀（CRITICAL）

**位置**：§2.4（行 105-115）、§5.1（行 733-753）、§5.4 emit 伪代码、附录 D

**描述**：§2.4 描述 CPF 格式为 `ItemCount(2) + [TypeID(2)+Length(2)+Data]...`，并说 "ENIP payload（SendRRData / SendUnitData 的 data 部分）使用 CPF 封装"。但实际 ODVA 规范规定 SendRRData 和 SendUnitData 的 payload 在 ItemCount 之前还有 **Interface Handle (4B LE) + Timeout (2B LE)** 共 6 字节前缀。

**依据**：OpENer `cpf.c` `AssembleLinearMessage`：
```c
if(message_router_response) {
    /* add Interface Handle and Timeout = 0 -> only for SendRRData and SendUnitData necessary */
    AddDintToMessage(0, outgoing_message);  // Interface Handle (4B LE, 通常 0)
    AddIntToMessage(0, outgoing_message);   // Timeout (2B LE)
}
EncodeItemCount(common_packet_format_data_item, outgoing_message);
```

即 SendRRData/SendUnitData payload 实际结构为：
```
Interface Handle (4B LE, 通常 0)  ← 设计文档遗漏
Timeout (2B LE)                   ← 设计文档遗漏
ItemCount (2B LE)
[TypeID(2B LE) + Length(2B LE) + Data]...
```

**影响**：
- 所有 SendRRData 包（Forward_Open/Close、Get/Set、Get_Attributes_All 等）的 payload 都会少 6 字节前缀，接收方解析 ItemCount 时会读取到 Interface Handle 的低 2 字节，导致 ItemCount 错误。
- 所有 SendUnitData 包（I/O 数据帧）同样受影响。
- §5.1 包序列表、§5.4 emit 伪代码、§6.11 UDP 帧结构描述、附录 D `buildCPFEnvelope` 都基于错误结构。
- §6.17 B10 FrameSize 上限计算也错误（计算中包含 "2 ItemCount" 但漏了 "6 接口句柄+超时"）。

**修复建议**：
1. §2.4 CPF 章节明确区分："SendRRData/SendUnitData payload = Interface Handle(4B LE) + Timeout(2B LE) + CPF（ItemCount+Items）"。CPF 本身只是 ItemCount+Items，不含前缀。
2. 附录 D `buildCPFEnvelope` 增加 SendRRData/SendUnitData 专用包装函数 `buildSendRRDataPayload(cpfItems, timeout)`，先写 4B Interface Handle + 2B Timeout，再写 CPF。
3. §6.11 UDP 帧结构改为 "ENIP头(24) + Interface Handle(4) + Timeout(2) + CPF ItemCount(2) + [Connected Address Item (Type 0x00A1)] + [Connected Data Item (Type 0x00B1, seq#, data)]"。
4. §6.17 B10 FrameSize 上限重新计算：65507 (UDP datagram max) - 24 (ENIP) - 4 (IfHdl) - 2 (Timeout) - 2 (ItemCount) - 6 (CAI) - 4 (CDI 头) = 65465。

---

### D-CRIT-5：ENIP Status 错误码表 6 个值中 5 个错误（CRITICAL）

**位置**：§2.3（行 92-104）、§6.5（行 847）、§6.9（行 908）、§6.10（行 920）、§6.18 E1（行 1044）

**描述**：§2.3 列出的 ENIP Status 错误码大量错误，混淆了 ENIP 封装层状态码与 CIP 通用状态码、CIP 连接管理器扩展状态码。

| 设计文档值 | 设计文档命名 | ODVA 规范值 | 规范命名 | 依据 |
|-----------|-------------|-------------|----------|------|
| 0x00000000 | Success | 0x0000 | Success | ✓ |
| 0x00000001 | InvalidCommand | 0x0001 | Invalid Command | ✓ |
| 0x00000002 | InsufficientMemory | 0x0002 | Insufficient Memory | ✓ |
| 0x00000003 | IncorrectData | 0x0003 | Incorrect Data | ✓ |
| 0x00000004 | InvalidSession | **0x0064** | Invalid Session Handle | OpENer `kEncapsulationProtocolInvalidSessionHandle = 0x0064` |
| 0x00000005 | InvalidLength | **0x0065** | Invalid Length | OpENer `kEncapsulationProtocolInvalidLength = 0x0065` |
| 0x00000006 | UnsupportedProtocol | **0x0069** | Unsupported Encapsulation Protocol | OpENer `kEncapsulationProtocolUnsupportedProtocol = 0x0069` |
| 0x00000064 | TargetNotFound | （非 ENIP Status） | （这是 CIP Path Destination Unknown 通用状态 0x05，不是 ENIP 层） | OpENer `kCipErrorPathDestinationUnknown = 0x05` |
| 0x00000065 | InvalidConnection | （非 ENIP Status） | （CIP Connection Failure 0x01 或 Connection Manager 扩展状态） | OpENer `kCipErrorConnectionFailure = 0x01` |
| 0x00000066 | ConnectionTimeout | （非 ENIP Status） | （CIP Connection Manager 扩展状态 0x0203） | OpENer `kConnectionManagerExtendedStatusCodeConnectionTimedOut = 0x0203` |

**依据**：
- OpENer `encap.h` 的 `EncapsulationProtocolErrorCode` 枚举只有 7 个值：0x0000/0x0001/0x0002/0x0003/0x0064/0x0065/0x0069。
- EEIP.Java `StatusEnum.java` 同样定义 7 个值，与 OpENer 一致。
- CIP 通用错误码（`ciperror.h`）与 ENIP Status 是不同层。

**影响**：
- §6.5 "对已注销的 SessionHandle 发送 UnregisterSession → 响应 InvalidSession(0x04)" 错误，应是 0x64。
- §6.9 "不存在的目标路径 → Status=TargetNotFound(0x64)" 错误，0x64 是 InvalidSession；TargetNotFound 是 CIP 层 Path Destination Unknown (0x05)，不在 ENIP Status。
- §6.10 "不存在的 ConnectionID → Status=InvalidConnection(0x65)" 错误，0x65 是 InvalidLength；InvalidConnection 是 CIP Connection Manager 扩展状态。
- §6.18 E1 描述 "InvalidSession (Status=4)" 错误。
- §6.17 B4 "Status=最大值 0xFFFFFFFF" 作为"异常状态"测试，但 ENIP Status 合法值上限是 0x0069，0xFFFFFFFF 会被接收方视为未知错误码。

**修复建议**：
1. 重写 §2.3 ENIP Status 表，仅保留 7 个合法值：0x0000/0x0001/0x0002/0x0003/0x0064/0x0065/0x0069。
2. 将 TargetNotFound/InvalidConnection/ConnectionTimeout 移到独立的"CIP 通用状态码"与"CIP Connection Manager 扩展状态码"表，并标注正确的层归属。
3. §6.5/6.9/6.10/6.18 中的 Status 引用全部更新。
4. §6.17 B4 的 "Status=0xFFFFFFFF" 改为 "Status=0x0069"（UnsupportedProtocol）或保留 0xFFFFFFFF 但标注为"非规范值，用于测试接收方容错"。

---

### D-CRIT-6：Forward_Open 请求体字段顺序与字段重复（CRITICAL）

**位置**：§6.9（行 887-898）

**描述**：§6.9 的 Forward_Open 请求结构描述存在字段重复、字段缺失和顺序错误。

设计文档列出的字段（按出现顺序）：
1. Priority/TimeTick(1) + TimeoutTicks(1)
2. O2T_NetworkConnID(4) + T2O_NetworkConnID(4)
3. TransportClass_Trigger(2)  ← 错误：应是 1 字节
4. ConnectionPathSize(1) + ConnectionPath(variable)
5. O2T_RPI(4) + O2T_NetworkConnParams(2)
6. T2O_RPI(4) + T2O_NetworkConnParams(2)
7. TransportType_Trigger(1)
8. ConnectionPath(variable)

实际 ODVA 规范 Forward_Open 请求体（依据 OpENer `cipconnectionobject.c` `ConnectionObjectInitializeFromMessage`）：
1. Priority/TimeTick(1) + TimeoutTicks(1)
2. O_to_T Network Connection ID(4 LE)
3. T_to_O Network Connection ID(4 LE)
4. Connection Serial Number(2 LE)
5. Originator Vendor ID(2 LE)
6. Originator Serial Number(4 LE)
7. Connection Timeout Multiplier(1)
8. Reserved(3)  ← 3 字节保留
9. O_to_T RPI(4 LE)
10. O_to_T Network Connection Parameters(2 LE)
11. T_to_O RPI(4 LE)
12. T_to_O Network Connection Parameters(2 LE)
13. Transport Class/Trigger(1)  ← 1 字节，不是 2 字节
14. Connection Path Size(1)  ← 单位 word
15. Connection Path(variable)

设计文档的问题：
- 字段 4 (ConnectionPathSize) 出现两次（一次在第 4 位、一次在第 8 位），且字段 4 之后又出现"ConnectionPath(variable)"两次。
- 完全缺失 Connection Serial Number / Originator Vendor ID / Originator Serial Number / Connection Timeout Multiplier / 3 字节 Reserved。
- TransportClass_Trigger 应是 1 字节，文档写 2 字节。
- 字段顺序错误：RPI/ConnParams 应在 TransportClass_Trigger 之前，ConnectionPath 在最后。

**依据**：OpENer `source/src/cip/cipconnectionobject.c` 行 120-186：
```c
void ConnectionObjectInitializeFromMessage(...) {
  CipByte priority_timetick = GetByteFromMessage(message);     // 1B
  CipUsint timeout_ticks = GetUsintFromMessage(message);       // 1B
  ConnectionObjectSetCipConsumedConnectionID(... GetUdintFromMessage(message));  // O_to_T 4B
  ConnectionObjectSetCipProducedConnectionID(... GetUdintFromMessage(message));  // T_to_O 4B
  ConnectionObjectSetConnectionSerialNumber(... GetUintFromMessage(message));    // 2B
  ConnectionObjectSetOriginatorVendorId(... GetUintFromMessage(message));        // 2B
  ConnectionObjectSetOriginatorSerialNumber(... GetUdintFromMessage(message));   // 4B
  ConnectionObjectSetConnectionTimeoutMultiplier(... GetUsintFromMessage(message));  // 1B
  (*message) += 3; /* 3 bytes reserved */
  ConnectionObjectSetOToTRequestedPacketInterval(... GetUdintFromMessage(message));  // 4B
  ConnectionObjectSetOToTNetworkConnectionParameters(... GetWordFromMessage(message));  // 2B
  ConnectionObjectSetTToORequestedPacketInterval(... GetUdintFromMessage(message));  // 4B
  ConnectionObjectSetTToONetworkConnectionParameters(... GetWordFromMessage(message));  // 2B
  connection_object->transport_class_trigger = GetByteFromMessage(message);  // 1B
}
```

**影响**：
- Forward_Open 请求生成的字节流完全错误，任何 CIP Connection Manager 都会拒绝。
- §6.9 "关键字段：ConnectionID 用于后续 I/O 数据帧的标识" 描述错位——Forward_Open 请求中的 O2T_NetworkConnID 是 originator 分配给 target 用的，响应中才返回 target 分配给 originator 用的 ConnectionID。
- §3.7.1 `from_response` 的 `connection_id` 字段提取位置（"响应 CIP Forward_Open body 中的 O2T_NetworkConnID，offset 4"）也基于错误的 body 结构。

**修复建议**：
1. 重写 §6.9 Forward_Open 请求结构为完整的 15 字段顺序，按 ODVA 规范。
2. 区分 Forward_Open (0x54, Network Connection Parameters 2B) 与 LargeForwardOpen (0x5B, Network Connection Parameters 4B)。
3. 更新 §3.2 ConnectionTimeout 字段说明：实际是 "Connection Timeout Multiplier"（1 字节），与 Priority/TimeTick + TimeoutTicks 配合计算超时；不是单独的 uint32 秒数。重新定义 `ConnectionTimeout` config 字段语义。
4. 更新 §3.7.1 `from_response` 字段表：Forward_Open 响应中 O2T_ConnID 偏移需重新计算（响应体：Service(1)+Reserved(1)+Status(1)+ConnectionSerialNumber(2)+OriginatorVendorID(2)+OriginatorSerialNumber(4)+O2T_ConnID(4)+T2O_ConnID(4)+...，O2T_ConnID 偏移 = 1+1+1+2+2+4 = 11 字节，不是 4）。

---

### D-CRIT-7：RegisterSession payload 不使用 CPF（CRITICAL）

**位置**：§6.4（行 830-839）、附录 B（行 1328-1336）

**描述**：§6.4 描述 RegisterSession 配置为 `commands[{command:0x0065, cpf_items:[{type_id:0x0000, payload:"\x01\x00"}]}]`，并说 "Payload：CPF Null Address Item（Type 0x0000, Length=4） + ProtocolVersion(2) + OptionsFlags(2)"。

但 ODVA 规范规定 **RegisterSession 的 payload 直接是 ProtocolVersion(2B LE) + OptionFlag(2B LE)**，共 4 字节，不携带任何 CPF item（无 ItemCount、无 TypeID、无 Length）。

**依据**：OpENer `encap.c` `HandleReceivedRegisterSessionCommand`：
```c
EipUint16 protocol_version = GetUintFromMessage(...);  // 直接读 2B
EipUint16 option_flag = GetUintFromMessage(...);       // 直接读 2B
```
没有任何 CPF ItemCount 解析。响应也直接回 ProtocolVersion(2)+OptionFlag(2)。

**影响**：
- 用户按 §6.4 配置生成的 RegisterSession 请求会多出 6 字节 CPF 头（ItemCount + TypeID + Length），实际 ProtocolVersion 会被解析为 ItemCount=1，OptionFlag 被解析为 TypeID，后续字节错位。
- 附录 B 默认命令序列 `{Command: 0x0065, CPFItems: []CPFItem{{TypeID: 0x0000}}}` 同样错误。
- §3.3 `ENIPCommand.CPFItems` 字段在 RegisterSession 场景下不应被使用，但文档未声明此约束。

**修复建议**：
1. §6.4 改为 `commands[{command:0x0065, cip_data:"\x01\x00\x00\x00"}]`（ProtocolVersion=1, OptionFlag=0）。
2. 增加 Validate 规则：Command=0x0065 时 `CPFItems` 必须为空，`CIPData` 必须为 4 字节。
3. 附录 B 默认序列改为 `{Command: 0x0065, CIPData: "\x01\x00\x00\x00"}`。
4. §3.3 `ENIPCommand` 增加注释："RegisterSession (0x0065) 不使用 CPF，payload 直接是 ProtocolVersion+OptionFlag"。

---

### D-CRIT-8：CPF TypeID 0x0100 错标为 ListIdentity Response（CRITICAL）

**位置**：§2.4（行 119-125）、§6.2（行 815）

**描述**：§2.4 CPF TypeID 表列出 `0x0100 = ListIdentity Response Item`。但实际 0x0100 是 **ListServices Response Item**；ListIdentity Response 的 TypeID 是 **0x000C**。

**依据**：OpENer `cpf.h`：
```c
typedef enum {
  kCipItemIdNullAddress = 0x0000,
  kCipItemIdListIdentityResponse = 0x000C,        // ← ListIdentity Response
  kCipItemIdConnectionAddress = 0x00A1,
  kCipItemIdConnectedDataItem = 0x00B1,
  kCipItemIdUnconnectedDataItem = 0x00B2,
  kCipItemIdListServiceResponse = 0x0100,         // ← ListServices Response
  kCipItemIdSocketAddressInfoOriginatorToTarget = 0x8000,
  kCipItemIdSocketAddressInfoTargetToOriginator = 0x8001,
  kCipItemIdSequencedAddressItem = 0x8002
} CipItemId;
```
EEIP.Java `CipIdentityItem.java` 注释："Code indicating item type of CIP Identity (0x0C)"。

**影响**：
- §6.2 "Config (TCP)：`commands[{command:0x0063, cpf_items:[{type_id:0x0100}]}]`" 会生成 ListServices 响应格式的包，而非 ListIdentity 请求。Wireshark 会显示为 "Malformed packet"。
- ListIdentity 请求本身不需要携带 CPF item（payload 为空），响应才携带 0x000C item；设计文档把请求和响应的 TypeID 混淆。

**修复建议**：
1. §2.4 表格纠正：`0x000C = ListIdentity Response Item`、`0x0100 = ListServices Response Item`。
2. §6.2 Config (TCP) 改为 `commands[{command:0x0063}]`（请求无 payload）。
3. 增加 ListIdentity 响应的 TypeID=0x000C 说明。

---

### D-HIGH-1：遗漏 3 个 CPF TypeID（HIGH）

**位置**：§2.4（行 119-125）

**描述**：§2.4 未列出 Sockaddr Info Item O→T (0x8000)、T→O (0x8001)、Sequenced Address Item (0x8002)。

**依据**：OpENer `cpf.h`（见 D-CRIT-8 引用）。

**影响**：
- Forward_Open 请求通常需要携带 Sockaddr Info Items（O→T 和 T→O 各一个，各 16 字节）以指示 UDP I/O 数据的目标地址；遗漏会导致 Forward_Open 后无法建立 UDP I/O 流。
- Class 1 Connection 的双向 I/O 需要 Sockaddr Info。
- Sequenced Address Item (0x8002) 用于 Class 3 连接的序列化寻址。

**修复建议**：
1. §2.4 表格补充 3 项：0x8000、0x8001、0x8002。
2. §6.9 Forward_Open 请求结构补充 Sockaddr Info Items 字段说明。
3. §3.5 ENIPIOData 增加 SockaddrInfo 配置字段（可选）。

---

### D-HIGH-2：FirmwareRevision 类型/语义错误（HIGH）

**位置**：§3.2（行 264）

**描述**：§3.2 `FirmwareRevision uint16` 注释为 "major(2B) + minor(2B)"。但实际 Identity 对象属性 4 Revision 是 `{USINT major, USINT minor}` 共 **2 字节**（每个 1 字节），不是 4 字节。

**依据**：OpENer `cipidentity.h`：
```c
typedef struct {
  CipUint vendor_id;       // Attr 1
  CipUint device_type;     // Attr 2
  CipUint product_code;    // Attr 3
  CipRevision revision;    // Attr 4: {CipUsint major, CipUsint minor}
  CipWord status;          // Attr 5
  CipUdint serial_number;  // Attr 6
  CipShortString product_name;  // Attr 7
  CipUsint state;          // Attr 8
} CipIdentityObject;
```
`CipRevision` 是 `{EipUint8 major_revision, EipUint8 minor_revision}`（每个 1 字节）。

设计文档类型 `uint16` 凑巧是 2 字节大小，但注释 "major(2B)+minor(2B)" 暗示 4 字节，与实际 2 字节不符。

**影响**：
- ListIdentity 响应中 Revision 字段会被错误编码为 4 字节，导致后续 SerialNumber/ProductName 偏移错位。
- RegisterSession 响应中也涉及 Revision 字段（如果设备返回 Identity 信息）。

**修复建议**：
1. §3.2 `FirmwareRevision` 改为 `FirmwareMajorRevision uint8` + `FirmwareMinorRevision uint8` 两个字段，或改为 `FirmwareRevision [2]byte` / `FirmwareRevision uint16` 但注释明确 "low byte = major, high byte = minor"。
2. 注释改为 "major(1B USINT) + minor(1B USINT)"。

---

### D-HIGH-3：TransportType 位字段描述错误（HIGH）

**位置**：§2.6（行 147-166）、§3.5（行 511-521）

**描述**：§2.6 把 "Transport_Type" 当作独立枚举值列表，并说 "bit 7 = 方向，bit 0-1 = Class"。但实际：
1. Forward_Open 请求中的 `Transport Class/Trigger` 字段是 1 字节，位布局为 `bit 7 = 方向（0=Server/1=Client）、bit 0-1 = Transport Class（0/1/2/3）`，bit 2-6 是 Production Trigger（Cyclic/Change-of-State/Application）。
2. §2.6 还说 "原 v1.0 文档将 Client Transport 列为 0x82/0x83 是错误的...正确配对应为 0x81/0x82（Class 0/1 Client）"——但 0x81 = `10000001`，bit 7=1 (Client), bit 0-1=01 (Class 1)，所以 0x81 实际是 **Class 1 Client**，不是 Class 0 Client；0x82 = `10000010`，bit 0-1=10 (Class 2)，是 Class 2 Client。设计文档的"Class 0 Client = 0x81"是错的。

**依据**：ODVA CIP Volume 1 Transport Class/Trigger 字段定义：
- bit 7: Direction (0=Server, 1=Client)
- bit 2-6: Production Trigger (0=Cyclic, 1=ChangeOfState, 2=Application, ...)
- bit 0-1: Transport Class (0=Class 0, 1=Class 1, 2=Class 2, 3=Class 3)

所以：
- 0x01 = Class 0 Server (Cyclic)
- 0x02 = Class 1 Server (Cyclic)
- 0x03 = Class 3 Server (Cyclic, 事件)
- 0x81 = Class 1 Client (Cyclic)  ← bit 0-1=01 是 Class 1，不是 Class 0
- 0x82 = Class 2 Client (Cyclic)
- 0x83 = Class 3 Client (Cyclic)

**影响**：
- §3.5 `TransportType` 默认值 0x01 = "Class 0 Server" 的描述需核实——0x01 实际是 Class 0 Server (bit 0-1=01 是 Class 1，但 Class 0 在某些实现中用 0x00)。
- §6.11/6.12 的 TransportType 值列表全部需要重新核对。
- N10 测试 "TransportType=0x82 (Class 1 Client)" 的描述错误，0x82 实际是 Class 2 Client。

**修复建议**：
1. §2.6 重写为 Transport Class/Trigger 字段的完整位布局：bit 7 方向、bit 2-6 Production Trigger、bit 0-1 Transport Class。
2. 给出正确的 6 个常用值：0x01 (Class 1 Server Cyclic)、0x02 (Class 2 Server Cyclic)、0x03 (Class 3 Server Cyclic)、0x81 (Class 1 Client Cyclic)、0x82 (Class 2 Client Cyclic)、0x83 (Class 3 Client Cyclic)。
3. §3.5 默认值与注释更新。
4. N10 测试描述改为 "TransportType=0x81 (Class 1 Client)" 或 "TransportType=0x83 (Class 3 Client)"。

---

### D-HIGH-4：Forward_Close 请求体字段错误（HIGH）

**位置**：§6.10（行 911-921）

**描述**：§6.10 的 Forward_Close 请求结构列出 "Priority/TimeTick(1) + TimeoutTicks(1) + ConnectionSerialNumber(2) + OVendorID(2) + OSerialNumber(4) + ConnectionPathSize(1) + ConnectionPath(variable)"。但 §6.10 的 Config 示例却是 `commands[{cip_service:0x11, connection_id:<值>, path:"2001042401"}]`——这里 `connection_id` 字段不属于 Forward_Close 请求体（Forward_Close 不携带 ConnectionID，而是用 ConnectionSerialNumber+OriginatorVendorID+OriginatorSerialNumber 三元组定位连接）。

实际 Forward_Close 请求体（依据 OpENer `cipconnectionmanager.c` `ForwardClose` 函数）：
1. Priority/TimeTick(1) + TimeoutTicks(1)
2. ConnectionSerialNumber(2 LE)
3. OriginatorVendorID(2 LE)
4. OriginatorSerialNumber(4 LE)
5. ConnectionPathSize(1, word 单位)
6. ConnectionPath(variable)

设计文档 Config 示例的 `connection_id` 字段无法对应到请求体的任何字段。

**依据**：OpENer `ForwardClose` 函数（行 670-680）：
```c
message_router_request->data += 2; /* ignore Priority/Time_tick and Time-out_ticks */
EipUint16 connection_serial_number = GetUintFromMessage(...);
EipUint16 originator_vendor_id = GetUintFromMessage(...);
EipUint32 originator_serial_number = GetUdintFromMessage(...);
```

**影响**：
- Forward_Close 请求无法正确生成，因为 Config 缺少 ConnectionSerialNumber/OriginatorVendorID/OriginatorSerialNumber 三个字段。
- §6.10 异常 "不存在的 ConnectionID → Status=InvalidConnection(0x65)" 描述错位——Forward_Close 不通过 ConnectionID 定位，而是通过三元组；异常码也应是 CIP Connection Manager 扩展状态。

**修复建议**：
1. §6.10 Config 改为 `commands[{cip_service:0x4E, cip_data:<编码后的 Forward_Close body>, path:"2001042401"}]`，cip_data 包含 Priority/TimeoutTicks/ConnSerialNum/OVendorID/OSerialNum。
2. §3.2 增加 `ConnectionSerialNumber uint16`、`OriginatorVendorID uint16`、`OriginatorSerialNumber uint32` 三个 config 字段。
3. §3.7.1 `from_response` 增加 `connection_serial_number` 字段提取（从 Forward_Open 响应中提取）。

---

### D-HIGH-5：CIPService=0x4B/0x4C PCCC 服务码描述混乱（HIGH）

**位置**：§2.5（行 142-143）、§3.3.1（行 424）

**描述**：§2.5 同时列出 "0x4B Execute PCCC" 和 "0x4C PCCC Execute" 并说"同上（别名）"。但实际：
- 0x4B 是 Execute PCCC（CIP 通道上执行 PCCC，Class 3 connected 服务）
- 0x4C 在 libplctag 中是 `AB_EIP_CMD_CIP_READ`（Read Tag，Logix 5000 专用），不是 PCCC 别名

**依据**：libplctag `defs.h`：
```c
#define AB_EIP_CMD_PCCC_EXECUTE ((uint8_t)0x4B)
#define AB_EIP_CMD_CIP_READ     ((uint8_t)0x4C)  // 不是 PCCC 别名
```

**影响**：用户配置 `cip_service:0x4C` 期望执行 PCCC，实际生成的是 Logix Read Tag 请求。

**修复建议**：
1. §2.5 删除 "0x4C PCCC Execute" 行，仅保留 "0x4B Execute PCCC"。
2. 增加 "0x4C Read Tag (Logix 5000 specific)" 行。
3. §3.3.1 自动推导表对应修正。

---

### D-HIGH-6：Multiple_Service_Packet 结构描述错误（HIGH）

**位置**：§6.13（行 959-977）

**描述**：§6.13 描述 Multiple_Service_Packet 结构为 "Service(0x0E) + PathSize + Path + OffsetCount(2) + [Offset(2) + ServiceRequest...]"。问题：
1. 服务码应是 0x0A（不是 0x0E，0x0E 是 Get_Attribute_Single）。
2. 偏移数组和子请求的排布描述含糊。实际结构是：Service(0x0A) + PathSize(1) + Path + OffsetCount(2 LE) + Offsets[N × 2 LE] + SubRequests[N]。

**依据**：ODVA CIP Volume 1 Multiple_Service_Packet 服务定义；OpENer `kMultipleServicePacket = 0x0A`。

**影响**：
- §3.8.1 `EncodeMultipleServicePacket(subRequests [][]byte) []byte` 的返回值 "OffsetCount(2) + [Offset(2) + ServiceRequest...]" 漏了 Path 部分，且 Offset 数组应单独连续存放，不是与子请求交替。
- P10 测试基于错误结构。

**修复建议**：
1. §6.13 服务码改为 0x0A。
2. 结构改为 "Service(0x0A) + RequestPathSize(1) + RequestPath + OffsetCount(2 LE) + Offsets[N × 2 LE] + SubRequests[N]"。
3. §3.8.1 `EncodeMultipleServicePacket` 签名增加 path 参数：`EncodeMultipleServicePacket(path []byte, subRequests [][]byte) []byte`，返回值包含完整 CIP data（Service+PathSize+Path+OffsetCount+Offsets+SubRequests）。
4. Offset 计算规则：第 i 个 Offset = 2 + pathSize + 2 + 2*N + sum(len(subRequests[0..i-1]))，单位字节。

---

### D-HIGH-7：Get/Set_Attribute_List 服务码与请求结构双双错误（HIGH）

**位置**：§6.14（行 980-991）、§3.8.1（行 607-610）、§3.3（行 389-397）

**描述**：§6.14 描述 Get_Attribute_List 用 0x54、Set_Attribute_List 用 0x55。实际：
- Get_Attribute_List = 0x03（不是 0x54）
- Set_Attribute_List = 0x04（不是 0x55）

且 §3.8.1 `EncodeAttributeListRequest(classID, instanceID, attrIDs)` 的返回值 "\x03\x00\x04\x00\x05\x00"（AttributeCount=3 + AttrID 3,4,5）漏了 classID/instanceID 的 EPATH 路径部分。实际 Get_Attribute_List 请求的 CIP data = Service(0x03) + PathSize + Path(Class+Instance) + AttributeCount(2) + AttrIDs[]。

**依据**：OpENer `kGetAttributeList = 0x03`、`kSetAttributeList = 0x04`（见 D-CRIT-1 引用）。

**影响**：
- P11/P12 测试基于错误服务码。
- N07 测试 "CIPAttributes:[3,4,5] → CIPData = \x03\x00\x04\x00\x05\x00" 漏了 Path 部分，生成的 CIP 请求无法被 Message Router 路由。

**修复建议**：
1. §6.14 Get_Attribute_List 服务码改为 0x03，Set_Attribute_List 改为 0x04。
2. §3.8.1 `EncodeAttributeListRequest` 签名增加 path 参数或返回完整 CIP data（Service+Path+AttrCount+AttrIDs），不只是 AttrCount+AttrIDs。
3. §3.3 `CIPAttributes` 字段注释中的服务码改为 0x03/0x04。
4. N07 测试断言更新。

---

### D-HIGH-8：from_response 字段提取位置错误（HIGH）

**位置**：§3.7.1（行 559-567）

**描述**：§3.7.1 表给出 `session_handle` 提取位置为 "响应 ENIP 头 SessionHandle（offset 4，uint32）"——这是正确的（ENIP 头 offset 4）。但 `connection_id` 提取位置 "响应 CIP Forward_Open body 中的 O2T_NetworkConnID（offset 4，uint32）" 是错的：Forward_Open 响应 body 的 O2T_ConnID 偏移不是 4。

实际 Forward_Open 响应体结构（依据 OpENer `AssembleForwardOpenResponse`）：
1. Reply Service(1) = 0x54|0x80 = 0xD4
2. Reserved(1) = 0x00
3. General Status(1)
4. Size of Additional Status(1)
5. Additional Status(variable, 通常 0 或 2 字节)
6. Connection Serial Number(2 LE)
7. Originator Vendor ID(2 LE)
8. Originator Serial Number(4 LE)
9. O_to_T Connection ID(4 LE)  ← O2T_ConnID
10. T_to_O Connection ID(4 LE)  ← T2O_ConnID
11. Connection Timeout Multiplier(1)
12. Reserved(3)
13. O_to_T RPI(4 LE)
14. T_to_O RPI(4 LE)
15. ...

如果 Additional Status 为 0 字节，O2T_ConnID 偏移 = 1+1+1+1+2+2+4 = 12 字节。如果 Additional Status 为 2 字节（典型错误响应），偏移 = 14。

设计文档说 "offset 4" 是错的——这混淆了 ENIP 头 SessionHandle 偏移（4）与 CIP body O2T_ConnID 偏移（12+）。

**影响**：
- §3.7.2 示例时序 "命令 1：SendRRData {SessionHandle: from_response(...)}" 正确。
- 但 `connection_id` / `o2t_conn_id` / `t2o_conn_id` 提取位置错误，I/O SubFlow 的 ConnectionID 会取错值。

**修复建议**：
1. §3.7.1 表更新 `connection_id` / `o2t_conn_id` 提取位置为 "Forward_Open 响应 CIP body 中 O2T_ConnID，偏移 = 12 + AdditionalStatusSize（典型 12 字节）"。
2. `t2o_conn_id` 偏移 = 12 + AdditionalStatusSize + 4。
3. 增加 `connection_serial_number` 字段提取（偏移 4+AdditionalStatusSize）。

---

### D-MED-1 至 D-MED-10：中等问题（汇总）

- **D-MED-1**：§6.3 ListInterfaces payload 描述错误。实际 ListInterfaces 请求无 payload，响应携带 ItemCount=0。改为 `commands[{command:0x0064}]`，删除 "CIP Get (Class 0xF5...)" 描述。
- **D-MED-2**：§2.5 CIP 服务表缺失 0x02/0x0D/0x11/0x14/0x15/0x16/0x17/0x18-0x1B/0x1C 等关键服务。补充完整 CIP 通用服务码表。
- **D-MED-3**：§3.3.1 自动推导表与 §6.4 矛盾，且服务码全部错误（见 D-CRIT-1）。重写整张表。
- **D-MED-4**：`EncodeCIPPath(classID uint8, instanceID uint16, attrID uint8)` 签名错误。classID 实际可以是 uint16（如 0xF5/0xF6），attrID 也常用 uint16。改为 `EncodeCIPPath(classID uint16, instanceID uint32, attrID uint16)`。
- **D-MED-5**：§3.3.2 SendUnitData 不限于 UDP，Class 3 connected messaging 也走 TCP SendUnitData。删除 "SendUnitData = UDP 隐式消息" 的强制绑定。
- **D-MED-6**：§5.3 MSS 分段规则违反 ENIP 规范。ENIP 单条消息应作为单个 TCP 流提交，MSS 分段由 TCP 层透明处理，不应在 ENIP 层主动切分。删除 §5.3 的 planner 主动分段逻辑。
- **D-MED-7**：§6.4 字段引用 `command_index:5` 与 §3.7.1 的 `source_command_index` 不一致。统一字段名。
- **D-MED-8**：§6.16 `<device_flow_id>:io` 命名约定缺少 `<device_flow_id>` 的定义。补充说明。
- **D-MED-9**：§6.17 B10 FrameSize 上限 65493 计算错误。应基于 UDP datagram 上限 65507 而非 IP MTU 65535。正确上限 = 65507 - 24 - 4 - 2 - 2 - 6 - 4 = 65465（包含 Interface Handle 4B + Timeout 2B 前缀，见 D-CRIT-4）。
- **D-MED-10**：§3.3 `Direction` 字段语义不明，"up"/"down" 与 ENIP 规范无关。删除该字段或重新定义为 "request"/"response"。

---

### D-LOW-1 至 D-LOW-6：低优先问题（汇总）

- **D-LOW-1**：§1.1 隐式消息可走 TCP（Class 3）也可走 UDP（Class 0/1），描述不完整。
- **D-LOW-2**：§2.2 NOP(0x0000) 可携带任意 payload，文档说"无 payload"错误。
- **D-LOW-3**：§2.2 IndicateStatus(0x0072) 方向应为 "server→client"（主动推送）。
- **D-LOW-4**：§2.5 PCCC 服务码 0x4B/0x4C 不是别名（见 D-HIGH-5）。
- **D-LOW-5**：§3.5 TransportType 默认值表述前后不一致。
- **D-LOW-6**：§7.1 V08 SessionHandle 策略 `inc` 是否合法存疑，SessionHandle 递增无业务意义。

---

## 3. HexDump 自洽性检查

设计文档中无完整 HexDump 示例（仅给出字段列表和 EPATH 字节序列），无法进行 Length 字段自洽性验证。但 §2.7 的 EPATH 示例字节序列基于错误的段类型表（D-CRIT-2），所有 EPATH 字节序列示例都需要重写。

**示例错误**：§2.7 "20 01 24 01 00 2C 03" 声称是 "Class 0x01 + Instance 16-bit 0x0001 + Attribute 3"，实际解析为 "Class 0x01 + Instance 8-bit 0x01 + 多余 0x00 + Connection Point 0x03"。

---

## 4. 测试用例质量审计（对照 CLAUDE.md §Testing Policy 8 条规则）

### §1 Spec 驱动测试推导——**不达标**

设计文档 §7 测试用例清单声称"按照 CLAUDE.md §Testing Policy 推导"，但实际上：
- P07 测试 "Forward_Open + Forward_Close" 基于 **错误的服务码 0x10/0x11**（应为 0x54/0x4E），不是从 spec 推导。
- P10 Multiple_Service_Packet 基于 **错误服务码 0x0E**（应为 0x0A）。
- P11/P12 Get/Set_Attribute_List 基于 **错误服务码 0x54/0x55**（应为 0x03/0x04）。
- N06 测试 `EncodeCIPPath(0x04, 0x0001, 3) → [0x20, 0x04, 0x24, 0x01, 0x00, 0x2C, 0x03]` 基于 **错误的段类型表**（0x24 是 Instance 8-bit 不是 16-bit，0x2C 是 Connection Point 不是 Attribute）。
- T04 测试 "RegisterSession 响应含非零 SessionHandle" 但 RegisterSession 响应结构错误（D-CRIT-7），测试无法验证正确字段。

### §2 覆盖失败路径——**部分达标**

正向路径较多，负向路径有 V01-V10 + N01/N02/N05/N09。但缺少：
- Forward_Open 失败路径（如 ConnectionSerialNumber 冲突、Resource Unavailable）。
- CIP 服务不支持路径（kCipErrorServiceNotSupported = 0x08）。
- ENIP Length 不匹配路径（设计文档 E2 说 "plan 层面不做校验"，但应至少有测试验证 planner 以实际 payload 计算 Length）。

### §3 每个路径对应单独测试——**不达标**

- §2.5 列出 16 个 CIP 服务，但 §8.3 显示 Start/Stop/Create/Delete/PCCC Execute 等多个服务"待补充"。
- §2.2 列出 10 个 ENIP Command，但 §8.2 显示 Nop/ListServices/ListInterfaces/IndicateStatus/Cancel "待补充"。
- Forward_Open/LargeForwardOpen 区分无测试。

### §4 集成测试——**部分达标**

I01/I02/I03 集成测试存在，但 I01 "Wireshark tshark ENIP 解析器正确识别" 在当前设计（大端序 + 错误服务码 + 错误 EPATH）下必然失败，测试本身正确但实现无法通过。

### §5 断言可观测输出——**部分达标**

多数测试断言了输出字段值（如 SessionHandle=0x12345678），但：
- P01 "Scenario=full" 的断言是 "TCP 握手 + ListIdentity + ..." 流程描述，未断言具体字节值。
- T03 "响应 payload 含 ProductName 字节" 未断言 ProductName 在 ListIdentity Response 中的具体偏移和长度。

### §6 并发正确性——**部分达标**

I03 测试 "多 worker 时序不交叉" 检查 GroupID 路由，但未测量实际吞吐率或顺序保证。CLAUDE.md §6 要求 "测量聚合可观测行为"，建议增加 100 设备并发下的实际包顺序断言。

### §7 失败测试先行——**无法评估**

设计文档未记录 bug 修复过程，无法判断是否遵循"先写失败测试再修复"。

### §8 测试质量对抗审查——**不达标**

§8.1 字段覆盖率表声称所有字段都有测试编号，但：
- `ENIPCommand.Options` 标注 "P01 (default 0)"——P01 是流程测试，未断言 Options 字段值。
- `ENIPConfig.O2T_RPI / T2O_RPI` 标注 "P01 (default)"——P01 未断言 RPI 值。
- `ENIPConfig.O2T_Size / T2O_Size` 标注 "P01 (在 Forward_Open request 中验证)"——但 Forward_Open 请求结构本身错误（D-CRIT-6），无法验证。

---

## 5. 业务场景覆盖检查

| 场景 | 设计文档覆盖 | 问题 |
|------|-------------|------|
| 会话注册 (RegisterSession) | §6.4 | D-CRIT-7：payload 结构错误 |
| 服务列表 (ListServices) | §6.1 | D-LOW-2：payload 描述不完整 |
| 身份发现 (ListIdentity) | §6.2 | D-CRIT-8：TypeID 0x0100 错标 |
| 接口列表 (ListInterfaces) | §6.3 | D-MED-1：payload 描述错误 |
| 读属性 (Get/Get_Attribute_Single) | §6.7 | D-CRIT-1：服务码 0x03 错（应 0x0E） |
| 写属性 (Set/Set_Attribute_Single) | §6.7 | D-CRIT-1：服务码 0x04 错（应 0x10） |
| 读全部属性 (Get_Attributes_All) | §6.6 | 服务码 0x01 正确 |
| 批量读属性 (Get_Attribute_List) | §6.14 | D-CRIT-1：服务码 0x54 错（应 0x03） |
| 批量写属性 (Set_Attribute_List) | §6.14 | D-CRIT-1：服务码 0x55 错（应 0x04） |
| 多服务包 (Multiple_Service_Packet) | §6.13 | D-CRIT-1/D-HIGH-6：服务码与结构错误 |
| 复位 (Reset) | §6.8 | 服务码 0x05 正确 |
| 启动/停止 (Start/Stop) | §6.8 | 服务码 0x06/0x07 正确 |
| Forward_Open | §6.9 | D-CRIT-1/D-CRIT-6：服务码与请求体错误 |
| Forward_Close | §6.10 | D-CRIT-1/D-HIGH-4：服务码与请求体错误 |
| LargeForwardOpen | **未覆盖** | 完全缺失（应支持 0x5B） |
| CIP I/O 周期数据 | §6.11 | 部分正确（SequenceNumber 回绕覆盖） |
| CIP I/O 事件数据 | §6.12 | D-HIGH-3：TransportType 值错误 |
| NOP 保活 | §6.15 | D-LOW-2：payload 描述错误 |
| 多设备并发 | §6.16 | D-MED-8：SubFlow 命名定义缺失 |
| IndicateStatus | **未覆盖业务场景** | 仅在命令表列出 |
| Cancel | **未覆盖业务场景** | 仅在命令表列出 |
| Unconnected_Send (0x52) | **未覆盖** | 完全缺失 |

---

## 6. 文档自洽性问题

1. **§3.2 ConnectionTimeout 与 §6.9 矛盾**：§3.2 说 "0=默认 10 秒"，但 Forward_Open 请求体中没有独立的 4 字节 ConnectionTimeout 字段（实际是 1 字节 TimeoutMultiplier，见 D-CRIT-6）。config 字段 `ConnectionTimeout uint32` 无法直接映射到请求体。
2. **§3.3.1 自动推导表与 §6.4 矛盾**：§6.4 示例 `command_index:5` 与 §3.7.1 的 `source_command_index` 字段名不一致（D-MED-7）。
3. **§6.11 与 §6.12 TransportType 值列表不一致**：§6.11 用 `transport_type: 1`，§6.12 用 `transport_type: 0x01`，虽值相同但表述风格不一。
4. **附录 B 默认序列与 §6.4 矛盾**：附录 B `{Command: 0x0065, CPFItems: []CPFItem{{TypeID: 0x0000}}}` 与 §6.4 的 `cpf_items:[{type_id:0x0000, payload:"\x01\x00"}]` 不一致（前者无 payload，后者有 payload）。
5. **§7 测试总数 50 条**：但 §8.2/8.3 大量"待补充"，实际可执行测试数远低于 50。

---

## 7. 最终结论

### 问题统计

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 8 | D-CRIT-1 ~ D-CRIT-8 |
| HIGH | 8 | D-HIGH-1 ~ D-HIGH-8 |
| MEDIUM | 10 | D-MED-1 ~ D-MED-10 |
| LOW | 6 | D-LOW-1 ~ D-LOW-6 |
| **总计** | **32** | |

### 必须先返工的问题（CRITICAL + 关键 HIGH）

下列问题必须在进入实现阶段前返工：

- **D-CRIT-1**：CIP 服务码表完全重写（影响 Forward_Open/Close、Get/Set、Multiple_Service_Packet、Get/Set_Attribute_List 共 6 个服务）
- **D-CRIT-2**：EPATH 段类型表完全重写（影响所有 CIP 路径编码）
- **D-CRIT-3**：ENIP 头/CPF 编码字节序改为 little-endian（影响所有 ENIP 包）
- **D-CRIT-4**：SendRRData/SendUnitData payload 增加 Interface Handle + Timeout 前缀（影响所有显式消息和 I/O 帧）
- **D-CRIT-5**：ENIP Status 错误码表重写（影响错误处理逻辑）
- **D-CRIT-6**：Forward_Open 请求体重写（影响 Forward_Open 功能）
- **D-CRIT-7**：RegisterSession payload 改为直接 ProtocolVersion+OptionFlag（影响会话注册）
- **D-CRIT-8**：CPF TypeID 0x0100 改为 ListServices Response，0x000C 改为 ListIdentity Response（影响 ListIdentity/ListServices）
- **D-HIGH-1**：补充 Sockaddr Info Item / Sequenced Address Item（影响 Forward_Open 完整性）
- **D-HIGH-4**：Forward_Close 请求体重写（影响 Forward_Close 功能）
- **D-HIGH-6**：Multiple_Service_Packet 结构重写（影响多服务包）
- **D-HIGH-7**：Get/Set_Attribute_List 服务码与结构重写（影响批量属性读写）
- **D-HIGH-8**：from_response 字段提取位置修正（影响跨命令引用）

### 最终结论

**本文档不可以直接进入实现阶段**。

理由：
1. **8 个 CRITICAL 问题**中有 6 个（D-CRIT-1/2/3/4/6/7）会导致生成的 ENIP/CIP 包从字节层面就无法被任何合规接收方解析——大端序 + 错误服务码 + 错误 EPATH + 缺失前缀 + 错误请求体字段，意味着实现完成后所有集成测试（I01）必然失败，Wireshark 会显示所有包为 "Malformed packet"。
2. **测试用例与 spec 不一致**：§7 的 50 条测试基于错误的服务码和 EPATH 表，即使全部通过也无法证明实现正确——违反 CLAUDE.md §Testing Policy §1（spec 驱动）和 §8（测试质量审查）。
3. **业务场景覆盖不完整**：LargeForwardOpen、Unconnected_Send、IndicateStatus、Cancel 等关键场景完全缺失。
4. **文档自洽性不足**：§3.2 与 §6.9、§3.3.1 与 §6.4、附录 B 与 §6.4 多处矛盾。

**返工建议**：
1. 由独立审计员重新审校 ODVA EtherNet/IP Volume 1 & 2 规范，逐节核对 CIP 服务码、EPATH 段类型、ENIP Status、CPF TypeID、Forward_Open/Close 请求体字段顺序。
2. 重写 §2.1-2.7 全部协议格式章节，以 OpENer/libplctag 源码为权威依据。
3. 重写 §6.4/6.9/6.10/6.13/6.14 业务场景，使用正确的服务码和请求体结构。
4. 重写附录 C/D 伪代码，改为 little-endian 并补全 Interface Handle + Timeout 前缀。
5. 重写 §7 测试用例，基于修正后的 spec 重新推导，确保每个测试断言的字节值与 ODVA 规范一致。
6. 增加 LargeForwardOpen (0x5B)、Unconnected_Send (0x52) 业务场景与测试。
7. 返工完成后，由独立审计员重新执行深度对抗式审计，确认 0 个 CRITICAL 问题方可进入实现阶段。

---

## 附录：审计依据源码引用

- **OpENer CIPServiceCode 枚举**：`source/src/cip/ciptypes.h`（`kGetAttributeAll=0x01`、`kMultipleServicePacket=0x0A`、`kGetAttributeSingle=0x0E`、`kSetAttributeSingle=0x10`、`kForwardOpen=0x54`、`kLargeForwardOpen=0x5B`、`kForwardClose=0x4E`）
- **OpENer CipItemId 枚举**：`source/src/enet_encap/cpf.h`（`kCipItemIdListIdentityResponse=0x000C`、`kCipItemIdListServiceResponse=0x0100`、`kCipItemIdSocketAddressInfoOriginatorToTarget=0x8000`、`kCipItemIdSequencedAddressItem=0x8002`）
- **OpENer EPATH 段类型常量**：`source/src/cip/cipepath.h`（`SEGMENT_TYPE_LOGICAL_SEGMENT=0x20`、`LOGICAL_SEGMENT_TYPE_CLASS_ID=0x00`、`LOGICAL_SEGMENT_TYPE_INSTANCE_ID=0x04`、`LOGICAL_SEGMENT_TYPE_ATTRIBUTE_ID=0x10`、`LOGICAL_SEGMENT_TYPE_SERVICE_ID=0x18`）
- **OpENer EncapsulationProtocolErrorCode 枚举**：`source/src/enet_encap/encap.h`（`kEncapsulationProtocolInvalidSessionHandle=0x0064`、`kEncapsulationProtocolInvalidLength=0x0065`、`kEncapsulationProtocolUnsupportedProtocol=0x0069`）
- **OpENer Forward_Open 字段解析**：`source/src/cip/cipconnectionobject.c` `ConnectionObjectInitializeFromMessage`（行 120-186）
- **OpENer Forward_Close 字段解析**：`source/src/cip/cipconnectionmanager.c` `ForwardClose`（行 670-680）
- **OpENer RegisterSession payload 解析**：`source/src/enet_encap/encap.c` `HandleReceivedRegisterSessionCommand`（直接读 ProtocolVersion+OptionFlag，无 CPF）
- **OpENer SendRRData/SendUnitData payload 前缀**：`source/src/enet_encap/cpf.c` `AssembleLinearMessage`（Interface Handle 4B + Timeout 2B 在 ItemCount 之前）
- **OpENer 字节序**：`source/src/enet_encap/endianconv.c` `AddIntToMessage`/`AddDintToMessage`（little-endian）
- **OpENer Identity 对象 Revision**：`source/src/cip/cipidentity.h`（`CipRevision = {CipUsint major, CipUsint minor}`，2 字节）
- **libplctag 服务码**：`src/libplctag/protocols/ab/defs.h`（`AB_EIP_CMD_FORWARD_OPEN=0x54`、`AB_EIP_CMD_FORWARD_CLOSE=0x4E`、`AB_EIP_CMD_FORWARD_OPEN_EX=0x5B`、`AB_EIP_CMD_CIP_READ=0x4C`、`AB_EIP_CMD_CIP_WRITE=0x4D`、`AB_EIP_CMD_CIP_MULTI=0x0A`）
- **EEIP.Java CommandsEnum**：`de/re/eeip/encapsulation/datatypes/CommandsEnum.java`（确认 0x0072 IndicateStatus、0x0073 Cancel 有效）
- **EEIP.Java StatusEnum**：`de/re/eeip/encapsulation/datatypes/StatusEnum.java`（确认 ENIP Status 仅 7 个合法值）
- **EEIP.Java CIPCommonServicesEnum**：`de/re/eeip/cip/datatypes/CIPCommonServicesEnum.java`（确认 Get_Attribute_List=0x03、Set_Attribute_List=0x04、Multiple_Service_Packet=0x0A、Get_Attribute_Single=0x0E、Set_Attribute_Single=0x10）
- **cpppo EPATH 段类型注释**：`server/enip/parser.py`（`0x30 == Attribute ID, 8-bit`、`0x38 == 8-Bit Service ID Segment`）

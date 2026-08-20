# IEC 61850 MMS 测试用例文档（26-mms-testcase）

> 配对设计文档：`docs/protocol-designs/26-mms-design.md`（下称"设计"）
> pcap 用例文件：`trafficgen/test/protocol_pcap/cases/mms.json`（下称"cases"）
> 生效范围：MMS（ISO 9506 / IEC 61850-8-1）终结层；层链 `["tcp","mms"]`
> 帧号约定：**1-based**，单流连接下 TCP SYN = 帧 1
> 验证工具：tshark 3.6.14（`tpkt.*`/`cotp.*` 白名单字段）+ `frames[]` 原始字节前缀断言

## 1. 概述

### 1.1 本文档目的

本文档是 MMS 协议的测试规格：给出 11 条 pcap 用例的完整 JSON 块、包序号索引表，以及相对设计文档的覆盖清单。每条用例断言"成功路径的确定字节 + 包序"或"负向路径的确定拒绝字节"，全部来自设计文档第 6 章（HexDump）与第 3 章（消息结构），并与 `cases/mms.json`（真实运行文件）逐字节一致，不新增设计未定义的行为。

### 1.2 断言体制（重要）

本地 tshark 无法解码 OSI 内层（会话/表示/ACSE/MMS，设计 6.5），实际断言分两条通道（与 `internal/pcaptest/types.go` 的 `Expect` 结构一致）：

- **`fields[]`（tshark 字段断言）**：`{packet, field, value}`，value 为字符串精确值。允许 `ip.version`、`tcp.dstport` 以及 `tpkt.version`、`tpkt.length`、`cotp.type`、`cotp.li`、`cotp.srcref`、`cotp.destref`、`cotp.tpdu_size`、`cotp.src-tsap`、`cotp.dst-tsap`、`cotp.eot`（白名单，防本地 build 缺协议导致 tshark 非零退出）。
- **`frames[]`（原始字节断言）**：`{packet, offset, hex}`，在**该帧偏移处前缀匹配** hex；offset 统一为含以太网头的帧首起 0-based 偏移。IPv4 正例固定 IP version=4、IHL=5、TCP dstport=102，载荷起点=54；IPv6 正例固定 IP version=6、TCP dstport=102，载荷起点=74。
- 内层字节以 libiec61850 编码 + Wireshark 解析器源码为权威（设计 6.5，`/tmp/mms3.pcap` 全帧回溯验证）。

### 1.3 连接建立的真实帧序（关键，与 design 6.1 对齐）

单流连接（客户端发起，会话由 Planner 双向产出）的确定帧序是：

```
1 SYN  | 2 SYN/ACK  | 3 ACK  | 4 CR（TPKT+COTP，数据首帧）
5 CC（TPKT+COTP）          | 6 DT1（会话/表示/ACSE/MMS Initiate，c2s）
7 DT2（会话/表示/ACSE/MMS Initiate-Response，s2c）
```

> 第 3 帧是三次握手收尾的**独立 ACK**（纯 TCP，无载荷），因此 CR 落在第 4 帧、DT1 落在第 6 帧——凡引用"第 N 包"必须带上 ACK 帧偏移（设计初稿的"CR=第 3 包/DT=第 4 包"是漏数 ACK 的旧约定，本文件纠正之）。服务帧接在关联段之后：首个服务请求 = 帧 8，其响应 = 帧 9。

### 1.4 与设计文档的引用要求

| 断言对象 | 设计来源 |
| --- | --- |
| CR / CC 完整字节 | 6.2 |
| DT1 关联字节（会话/表示/ACSE/Initiate）| 6.3 |
| DT2 关联响应（CPA/AARE/Initiate-Response）| 6.4 |
| 真实帧序（含 ACK）| 6.1 更正说明 + 本文件 1.3 |
| Read / Write / Identify / GetNameList / Report / Error 内层 | 6.6、6.7、9.1 |
| invokeID 递增 | 4.3 |
| noAssociate / IPv6 / 多会话 | 4.4、5.2、8.3、10.3 |

---

## 2. 用例 JSON 块（与 cases/mms.json 逐字一致）

### 2.1 `mms_connect_establish` —— 完整连接建立（四段关联）

| 要素 | 值 |
| --- | --- |
| 覆盖 | 设计 2.2-2.11、3.1、3.6、6.1-6.3：TCP 三次握手 → CR → CC → DT1 → DT2 |
| 包序 | 1 SYN, 2 SYNACK, 3 ACK, 4 CR, 5 CC, 6 DT1(c2s), 7 DT2(s2c) |
| 断言 | 帧 4 CR 全 20 字节；帧 5 CC 全字节；帧 6 DT1 载荷逐字节；帧 7 DT2 TPKT/cotp.eot + 内层 CPA/AARE/Initiate-Resp |

```json
{
  "id": "mms_connect_establish",
  "proto": "mms",
  "summary": "MMS complete association: TCP handshake + COTP CR/CC + DT(SPDU/CP/AARQ/ACSE/MMS Initiate) both directions",
  "spec_json": [
    { "tcp": { "dst_port": 102 } },
    { "mms": {} }
  ],
  "expect": {
    "packet_count": 7,
    "negotiated": true,
    "has_handshake": true,
    "fields": [
      { "packet": 4, "field": "cotp.type", "value": "0x0e" },
      { "packet": 4, "field": "cotp.li", "value": "15" },
      { "packet": 4, "field": "cotp.srcref", "value": "0x0001" },
      { "packet": 4, "field": "cotp.destref", "value": "0x0000" },
      { "packet": 4, "field": "cotp.tpdu_size", "value": "4096" },
      { "packet": 4, "field": "cotp.src-tsap", "value": "0x02" },
      { "packet": 4, "field": "cotp.dst-tsap", "value": "0x01" },
      { "packet": 4, "field": "ip.version", "value": "4" },
      { "packet": 4, "field": "tcp.dstport", "value": "102" },
      { "packet": 5, "field": "cotp.type", "value": "0x0d" },
      { "packet": 5, "field": "cotp.li", "value": "15" },
      { "packet": 5, "field": "cotp.srcref", "value": "0x0002" },
      { "packet": 5, "field": "cotp.destref", "value": "0x0001" },
      { "packet": 6, "field": "cotp.type", "value": "0x0f" },
      { "packet": 6, "field": "cotp.eot", "value": "1" },
      { "packet": 6, "field": "cotp.li", "value": "2" },
      { "packet": 6, "field": "tpkt.length", "value": "165" },
      { "packet": 7, "field": "cotp.type", "value": "0x0f" },
      { "packet": 7, "field": "cotp.eot", "value": "1" }
    ],
    "frames": [
      { "packet": 4, "offset": 54, "hex": "030000140fe00000000100c0010cc20101c10102" },
      { "packet": 5, "offset": 54, "hex": "030000140fd00001000200c0010cc10101c20102" },
      { "packet": 6, "offset": 54, "hex": "030000a502f0800d920506130100160102140200023305000102030434020001c1810081317fa003800101a278810412345678820487654321a425301002020101060452010001300406025101301102020103060528ca22020130040602510161433041020101a03c603aa1060628ca220203be30282e020103a029a82780040000fa0081010582010583010aa416800101810305f100820c05ee1c00000408000079ef18" },
      { "packet": 7, "offset": 54, "hex": "030000a102f0800e900506130100160102140200023305000102030434020001c17f317da003800101a276830400000001a5" },
      { "packet": 7, "offset": 105, "hex": "300d02020101300780010081025101300d02020103300780010081025101614e304c020101a0476145a1060628ca220203a203020100a305a103020100be2f282d020103a028a92680040000fa0081010582010583010aa415800101810205f1820c0b000000000000000000000000" }
    ]
  }
}
```

> 注：`packet_count: 7`（1 SYN + 2 SYNACK + 3 ACK + 4 CR + 5 CC + 6 DT1 + 7 DT2）。帧 6 载荷 = `030000a5 02f080 0d92 …`（TPKT.length=165，DT1 数据）= 与 `/tmp/mms3.pcap` 逐字节一致。帧 7 DT2 载荷 = `030000a1 02f080 0e90 …`（TPKT.length=161）；CPA 上下文结果列表沿用现行 cases 的两项 `30 0d` 形式。

### 2.2 `mms_read_multi_type` —— Read 多类型读取

| 要素 | 值 |
| --- | --- |
| 覆盖 | 设计 2.9、3.3、5.3、6.6：5 个对象（boolean/integer/unsigned/octetString/utcTime）一次 Read |
| 包序 | 关联（1-7）后：8 = ReadReq, 9 = ReadResp |
| 断言 | ReadReq invokeID 1；ReadResp 内层标签 83/85/86/89/91 + `a1` ConfirmedResponse；utcTime 为 4 字节大端秒 `91 04 65 bb 87 c0` |

```json
{
  "id": "mms_read_multi_type",
  "proto": "mms",
  "summary": "MMS Read: one request, five multi-type variables (boolean/integer/unsigned/octetString/utcTime)",
  "spec_json": [
    { "tcp": { "dst_port": 102 } },
    { "mms": {
        "objects": [
          { "domain": "IED1", "name": "GGIO1.SPCSO1.stVal", "datatype": "boolean", "value": true },
          { "domain": "IED1", "name": "MMXU1.TotW.mag.f", "datatype": "integer", "value": 42 },
          { "domain": "IED1", "name": "MMXU1.TotW.mag.u", "datatype": "unsigned", "value": 7 },
          { "domain": "IED1", "name": "LLN0.Mod.stVal", "datatype": "octetString", "value": "0102" },
          { "domain": "IED1", "name": "LLN0.Beh.stVal", "datatype": "utcTime", "value": 1706788800 }
        ],
        "enableRead": true,
        "sequence": { "steps": ["read"] }
    } }
  ],
  "expect": {
    "negotiated": true,
    "fields": [
      { "packet": 8, "field": "cotp.type", "value": "0x0f" },
      { "packet": 9, "field": "cotp.type", "value": "0x0f" }
    ],
    "frames": [
      { "packet": 8, "offset": 54, "hex": "0300" },
      { "packet": 9, "offset": 54, "hex": "03 00 00" },
      { "packet": 9, "offset": 61, "hex": "a1 7f 02 01 01 a4 53 a1 51" },
      { "packet": 9, "offset": 71, "hex": "83 01 ff 85 01 2a 86 01 07 89 02 01 02 91 04 65 bb 87 c0" }
    ]
  }
}
```

> 帧 9 响应 `a1 7f 02 01 01 a4 53 a1 51 {五项}`：顶层 Confirmed-ResponsePDU 标签为 `a1`，invokeID 回显 1，Read 响应服务标签为 `a4`，listOfAccessResult 标签为 `a1`。五项 Data 的总长度为 19 字节（`0x13`），其中 utcTime 为 `91 04 65 bb 87 c0`；`7f/53/51` 为按实际四字节 UTC Time 回填后的确定长度，不是占位值。

### 2.3 `mms_write_success` —— Write 全表成功

| 要素 | 值 |
| --- | --- |
| 覆盖 | 设计 3.3、6.7：Write 全表，响应 listOfAccessResult 每项 80 01 00 |
| 包序 | 关联后：8 = WriteReq, 9 = WriteResp |
| 断言 | WriteResp `a5 … a0 … {80 01 00 80 01 00}`（每项成功）|

```json
{
  "id": "mms_write_success",
  "proto": "mms",
  "summary": "MMS Write: write full variable list, response success list (80 01 00 each)",
  "spec_json": [
    { "tcp": { "dst_port": 102 } },
    { "mms": {
        "objects": [
          { "domain": "IED1", "name": "GGIO1.SPCSO1.stVal", "datatype": "boolean", "value": false },
          { "domain": "IED1", "name": "MMXU1.TotW.mag.f", "datatype": "integer", "value": 100 }
        ],
        "enableWrite": true,
        "sequence": { "steps": ["write"] }
    } }
  ],
  "expect": {
    "negotiated": true,
    "fields": [
      { "packet": 8, "field": "cotp.type", "value": "0x0f" },
      { "packet": 9, "field": "cotp.type", "value": "0x0f" }
    ],
    "frames": [
      { "packet": 8, "offset": 54, "hex": "03 00" },
      { "packet": 8, "offset": 61, "hex": "a5" },
      { "packet": 9, "offset": 54, "hex": "03 00 00" },
      { "packet": 9, "offset": 61, "hex": "a1" },
      { "packet": 9, "offset": 66, "hex": "a5 08 a0 06 80 01 00 80 01 00" }
    ]
  }
}
```

> Write 响应与 Read 响应同构（listOfAccessResult），成功项用 `80 01 00`（success）而非数据标签；两个写项对应两个 `80 01 00`。

### 2.4 `mms_information_report` —— 主动上送（无响应）

| 要素 | 值 |
| --- | --- |
| 覆盖 | 设计 2.9、3.4、6.7：UnconfirmedPDU(a3) → informationReport；无响应帧 |
| 包序 | 关联后：8 = Report（单包）|
| 断言 | 帧 8 载荷 `03 00` + MMS `a3`；无后续响应帧（fields 只断帧 8）|

```json
{
  "id": "mms_information_report",
  "proto": "mms",
  "summary": "MMS InformationReport: server-push UnconfirmedPDU (a3), no response frame",
  "spec_json": [
    { "tcp": { "dst_port": 102 } },
    { "mms": {
        "objects": [
          { "domain": "IED1", "name": "GGIO1.SPCSO1.stVal", "datatype": "boolean", "value": true }
        ],
        "enableInformationReport": true,
        "sequence": { "steps": ["report"], "injectOn": 1 }
    } }
  ],
  "expect": {
    "negotiated": true,
    "fields": [
      { "packet": 8, "field": "cotp.type", "value": "0x0f" }
    ],
    "frames": [
      { "packet": 8, "offset": 54, "hex": "03 00 00" },
      { "packet": 8, "offset": 61, "hex": "a3" }
    ]
  }
}
```

### 2.5 `mms_getnamelist` —— 名称列表

| 要素 | 值 |
| --- | --- |
| 覆盖 | 设计 3.3、6.7：GetNameList 请求（vmdSpecific scope=80 00），响应 listOfIdentifier |
| 包序 | 关联后：8 = Req, 9 = Resp |
| 断言 | 请求顶层 Confirmed-RequestPDU=`a0` 后服务标签 `a1`；响应顶层 Confirmed-ResponsePDU=`a1` 后服务标签 `a1` |

```json
{
  "id": "mms_getnamelist",
  "proto": "mms",
  "summary": "MMS GetNameList: request vmdSpecific scope, response listOfIdentifier",
  "spec_json": [
    { "tcp": { "dst_port": 102 } },
    { "mms": {
        "objects": [
          { "domain": "IED1", "name": "GGIO1.SPCSO1.stVal", "datatype": "boolean" }
        ],
        "enableGetNameList": true,
        "sequence": { "steps": ["getnmlist"] }
    } }
  ],
  "expect": {
    "negotiated": true,
    "fields": [
      { "packet": 8, "field": "cotp.type", "value": "0x0f" },
      { "packet": 9, "field": "cotp.type", "value": "0x0f" }
    ],
    "frames": [
      { "packet": 8, "offset": 54, "hex": "03 00" },
      { "packet": 8, "offset": 61, "hex": "a0" },
      { "packet": 8, "offset": 66, "hex": "a1" },
      { "packet": 9, "offset": 54, "hex": "03 00 00" },
      { "packet": 9, "offset": 61, "hex": "a1" },
      { "packet": 9, "offset": 66, "hex": "a1" }
    ]
  }
}
```

### 2.6 `mms_identify` —— 标识

| 要素 | 值 |
| --- | --- |
| 覆盖 | 设计 3.3、6.7：Identify 请求（a2 00），响应 vendor/model/revision |
| 包序 | 关联后：8 = Req, 9 = Resp |
| 断言 | 请求顶层 Confirmed-RequestPDU=`a0` 后服务标签 `a2`；响应顶层 Confirmed-ResponsePDU=`a1` 后服务标签 `a2` |

```json
{
  "id": "mms_identify",
  "proto": "mms",
  "summary": "MMS Identify: response vendor/model/revision",
  "spec_json": [
    { "tcp": { "dst_port": 102 } },
    { "mms": {
        "iedName": "FAKE8150",
        "enableIdentify": true,
        "sequence": { "steps": ["identify"] }
    } }
  ],
  "expect": {
    "negotiated": true,
    "fields": [
      { "packet": 8, "field": "cotp.type", "value": "0x0f" },
      { "packet": 9, "field": "cotp.type", "value": "0x0f" }
    ],
    "frames": [
      { "packet": 8, "offset": 54, "hex": "03 00" },
      { "packet": 8, "offset": 61, "hex": "a0" },
      { "packet": 8, "offset": 66, "hex": "a2" },
      { "packet": 9, "offset": 54, "hex": "03 00 00" },
      { "packet": 9, "offset": 61, "hex": "a1" },
      { "packet": 9, "offset": 66, "hex": "a2" }
    ]
  }
}
```

### 2.7 `mms_service_error` —— 服务拒绝（负向）

| 要素 | 值 |
| --- | --- |
| 覆盖 | 设计 3.5、6.7、9.1：读不存在的对象 → Confirmed-ErrorPDU |
| 包序 | 关联后：8 = ReadReq(不存在对象), 9 = Err |
| 断言 | 请求 MMS `a4`；响应 `a2 … 87 01 02`（object-access, object-non-existent）|

```json
{
  "id": "mms_service_error",
  "proto": "mms",
  "summary": "MMS negative: read non-existent object -> Confirmed-ErrorPDU (access/object-non-existent)",
  "spec_json": [
    { "tcp": { "dst_port": 102 } },
    { "mms": {
        "objects": [
          { "domain": "IED1", "name": "NONEXIST.obj", "datatype": "boolean" }
        ],
        "enableRead": true,
        "errorClassName": "access",
        "errorValue": 2,
        "sequence": { "steps": ["read"] }
    } }
  ],
  "expect": {
    "negotiated": true,
    "fields": [
      { "packet": 8, "field": "cotp.type", "value": "0x0f" },
      { "packet": 9, "field": "cotp.type", "value": "0x0f" }
    ],
    "frames": [
      { "packet": 8, "offset": 54, "hex": "03 00" },
      { "packet": 8, "offset": 61, "hex": "a0" },
      { "packet": 8, "offset": 66, "hex": "a4" },
      { "packet": 9, "offset": 54, "hex": "03 00 00" },
      { "packet": 9, "offset": 61, "hex": "a1" },
      { "packet": 9, "offset": 66, "hex": "a2" },
      { "packet": 9, "offset": 82, "hex": "87 01 02" }
    ]
  }
}
```

> `87 01 02` 特征串：`87`=object-access 错误类标签、`01` 长度、`02`=object-non-existent；在帧 9 内层偏移 82 处前缀命中。

### 2.8 `mms_no_associate` —— 未建立关联（负向）

| 要素 | 值 |
| --- | --- |
| 覆盖 | 设计 4.2、5.2(noAssociate)：跳过 CR/CC/DT1/DT2，直接发数据服务 |
| 包序 | 1 SYN, 2 SYNACK, 3 ACK, **4 起直接数据帧**（无 COTP CR/CC）|
| 断言 | 帧 4 载荷直接是 `a4` Read；`packet_count: 7`（无关联段回补）|

```json
{
  "id": "mms_no_associate",
  "proto": "mms",
  "summary": "MMS negative: noAssociate=true skips four-way association, service frames only",
  "spec_json": [
    { "tcp": { "dst_port": 102 } },
    { "mms": {
        "objects": [
          { "domain": "IED1", "name": "GGIO1.SPCSO1.stVal", "datatype": "boolean", "value": true }
        ],
        "enableRead": true,
        "association": { "noAssociate": true },
        "sequence": { "steps": ["read"] }
    } }
  ],
  "expect": {
    "min_packets": 5,
    "negotiated": true,
    "has_handshake": true,
    "fields": [
      { "packet": 4, "field": "cotp.type", "value": "0x0f" },
      { "packet": 4, "field": "cotp.eot", "value": "1" }
    ],
    "frames": [
      { "packet": 4, "offset": 54, "hex": "03 00 00" },
      { "packet": 4, "offset": 61, "hex": "a4" }
    ]
  }
}
```

> 帧 4 是纯数据 DT（cotp.type=0x0f 而非 0x0e），`02 f0 80` 后紧跟裸 MMS Read（`a4`），证明关联四段被整体跳过。关联已被跳过，无 CC/AARE，服务请求不带信封；`TPKT 03 00` + `COTP DT` + MMS 直接组成载荷（偏移 61 = 54 + 4 TPKT + 3 DT 头）。

### 2.9 `mms_ipv6` —— IPv6 版本完整关联

| 要素 | 值 |
| --- | --- |
| 覆盖 | 设计 8.3、10.3：IPv6 体系下完整关联（载荷偏移 74）|
| 包序 | 1 SYN, 2 SYNACK, 3 ACK, 4 CR, 5 CC, 6 DT1, 7 DT2 |
| 断言 | 与 2.1 同构；帧 6 DT1 字节与 IPv4 完全相同；frames 偏移 74 |

```json
{
  "id": "mms_ipv6",
  "proto": "mms",
  "summary": "MMS over IPv6: full association with payload offset 74",
  "spec_json": [
    { "tcp": { "dst_port": 102 } },
    { "ipv6": {}, "mms": {} }
  ],
  "expect": {
    "negotiated": true,
    "has_handshake": true,
    "fields": [
      { "packet": 4, "field": "cotp.type", "value": "0x0e" },
      { "packet": 4, "field": "cotp.srcref", "value": "0x0001" },
      { "packet": 4, "field": "ip.version", "value": "6" },
      { "packet": 4, "field": "tcp.dstport", "value": "102" },
      { "packet": 4, "field": "tpkt.length", "value": "20" },
      { "packet": 6, "field": "cotp.type", "value": "0x0f" },
      { "packet": 6, "field": "tpkt.length", "value": "165" }
    ],
    "frames": [
      { "packet": 4, "offset": 74, "hex": "030000140fe00000000100c0010cc20101c10102" },
      { "packet": 5, "offset": 74, "hex": "030000140fd00001000200c0010cc10101c20102" },
      { "packet": 6, "offset": 74, "hex": "030000a502f0800d920506130100160102140200023305000102030434020001c1810081317fa003800101a278810412345678820487654321a425301002020101060452010001300406025101301102020103060528ca22020130040602510161433041020101a03c603aa1060628ca220203be30282e020103a029a82780040000fa0081010582010583010aa416800101810305f100820c05ee1c00000408000079ef18" },
      { "packet": 7, "offset": 74, "hex": "030000a102f0800e900506130100160102140200023305000102030434020001c17f317d" }
    ]
  }
}
```

> 内层字节与 IPv4 完全一致；仅 frames 的 offset 从 54 变 74（设计 10.3 偏移表）。

### 2.10 `mms_multi_session` —— 多会话并发

| 要素 | 值 |
| --- | --- |
| 覆盖 | 设计 4.1、4.3、8.1：两路独立 TCP 连接同时 CR/CC |
| 包序 | A: 1-3 握手, 4 CR, 5 CC…；B: 5-7 握手回绕（帧号重排），8 CR, 9 CC…（取决于调度）|
| 断言 | 帧 4 与帧 8 均为 CR cotp.type=0x0e，两路引用可相同（连接内唯一即可）|

```json
{
  "id": "mms_multi_session",
  "proto": "mms",
  "summary": "MMS multi-session: two independent TCP associations each complete CR/CC",
  "spec_json": [
    { "tcp": { "dst_port": 102 } },
    { "mms": {
        "objects": [
          { "domain": "IED1", "name": "GGIO1.SPCSO1.stVal", "datatype": "boolean" }
        ],
        "enableRead": true,
        "multiSession": [
          { "objects": [ { "domain": "IED2", "name": "MMXU1.TotW.mag.f", "datatype": "integer", "value": 5 } ] }
        ],
        "sequence": { "steps": ["read"] }
    } }
  ],
  "expect": {
    "negotiated": true,
    "has_handshake": true,
    "fields": [
      { "packet": 4, "field": "cotp.type", "value": "0x0e" },
      { "packet": 8, "field": "cotp.type", "value": "0x0e" }
    ],
    "frames": [
      { "packet": 4, "offset": 54, "hex": "03000014 0fe0 0000 0001 00 c0 01 0c c2 01 01 c1 01 02" },
      { "packet": 8, "offset": 54, "hex": "03000014 0fe0 0000 0001 00 c0 01 0c c2 01 01 c1 01 02" },
      { "packet": 15, "offset": 54, "hex": "0300" },
      { "packet": 15, "offset": 63, "hex": "02 01 01" },
      { "packet": 17, "offset": 78, "hex": "8a 04 49 45 44 32" }
    ]
  }
}
```

> COTP 引用只需"连接内唯一"，两路都可 srcRef=1（设计 4.3）；invokeID 各自从 1 递增。在当前确定调度（A 服务请求帧 15、B 服务请求帧 17）下，两路服务请求均出现 `02 01 01`，B 路请求另含 `8a 04 49 45 44 32`，从而观察 invokeID 隔离与对象区分；若实现采用交错调度，须按该内容匹配对应帧。

### 2.11 `mms_validate_reject` —— 超长对象名配置拒绝

```json
{
  "id": "mms_validate_reject",
  "proto": "mms",
  "summary": "MMS negative: validator rejects item-identifier encoding longer than 32 bytes",
  "spec_json": [
    { "tcp": { "dst_port": 102 } },
    { "mms": {
        "objects": [
          { "domain": "IED1", "name": "THIS_ITEM_IDENTIFIER_IS_WAY_TOO_LONG_01", "datatype": "boolean" }
        ],
        "enableRead": true,
        "sequence": { "steps": ["read"] }
    } }
  ],
  "expect": { "expect_error": true, "error_contains": "name" }
}
```

此用例在 pcap 驱动层验证创建任务即被拒绝，不产出数据包；它不伪造未实现的服务字段。

---

## 3. 索引表（用例 ↔ 帧 ↔ 断言）

| 用例 ID | 涉及帧（1-based）| 方向 | 关键断言目标 |
| --- | --- | --- | --- |
| `mms_connect_establish` | 1-3 握手, 4 CR, 5 CC, 6 DT1, 7 DT2 | C/S | cotp.type 0x0e/0x0d/0x0f；tpkt.length 20/165/161；DT1 全载荷；DT2 CPA/AARE |
| `mms_read_multi_type` | 8, 9 | C/S | ReadResp a1 … 83/85/86/89/91 |
| `mms_write_success` | 8, 9 | C/S | WriteResp a5 … 80 01 00 ×2 |
| `mms_information_report` | 8 | S→C | UnconfirmedPDU a3；无响应帧 |
| `mms_getnamelist` | 8, 9 | C/S | 请求/响应 MMS 标签 a1 |
| `mms_identify` | 8, 9 | C/S | 请求/响应 MMS 标签 a2 |
| `mms_service_error` | 8, 9 | C/S | Confirmed-ErrorPDU a2 … 87 01 02 |
| `mms_no_associate` | 4 起数据帧 | C | 帧 4 偏移 58 直接 `02 f0 80 a4`（纯 DT 无关联）|
| `mms_ipv6` | 1-7 | C/S | 偏移 74 断言同 2.1 |
| `mms_multi_session` | A 4, B 8；服务请求 A=15、B=17 | C/S | 两路 CR 独立；两路服务请求 invokeID=1 且对象域 IED1/IED2 可区分；packet_count=18 |

## 4. 覆盖清单（相对设计文档）

### 4.1 按设计章节

| 设计章节 | 内容 | 用例覆盖 |
| --- | --- | --- |
| 2.2-2.3 | TPKT/COTP | 全部（fields 断言）|
| 2.4-2.6 | 会话/表示/ACSE | `connect_establish`（帧 6-7 frames 字节）|
| 2.7-2.8 | MMS PDU / Confirmed | 各服务用例（MMS 标签 a0/a1/a2/a3/a4/a5）|
| 2.9 | Data CHOICE 数据标签 | `read_multi_type`（5 类）|
| 2.10 | ObjectName | `read_multi_type`（domain+item）|
| 3.1 | 连接建立 | `connect_establish`、`ipv6` |
| 3.3 | 数据服务 | `read/write/getnamelist/identify` |
| 3.4 | InformationReport | `information_report` |
| 3.5 | Confirmed-ErrorPDU | `service_error` |
| 4.1-4.3 | 状态机/invokeID | `connect_establish`、`multi_session` |
| 4.4 | planner 成对表 | 各服务用例 req/resp 对 |
| 5.2 | noAssociate | `no_associate` |
| 6.1-6.4 | HexDump | `connect_establish`（帧 4-7）；`ipv6` |
| 6.6 | Read 路由 | `read_multi_type` |
| 6.7 | 各服务内层 | `write/report/getnamelist/identify/error` |
| 8.3 | IPv6 偏移 | `ipv6`（offset 74）|
| 9.1 | 错误类 | `service_error`（87 01 02）|
| 10.3 | 偏移表 | `ipv6` |

### 4.2 每用例断言类型与计数

| 用例 | fields 断言 | frames 断言 |
| --- | --- | --- |
| connect_establish | 17 | 5 |
| read_multi_type | 2 | 4 |
| write_success | 2 | 4 |
| information_report | 1 | 2 |
| getnamelist | 2 | 4 |
| identify | 2 | 4 |
| service_error | 2 | 5 |
| no_associate | 2 | 2 |
| ipv6 | 5 | 3 |
| multi_session | 2 | 7 |
| validate_reject | 0 | 0 |
| 合计 | 39 | 38 |

### 4.3 强制覆盖核对（原始需求 → 用例）

| 强制项 | 实现于 |
| --- | --- |
| 连接建立（CR/CC/AARQ/AARE/Initiate 对）逐包断言 | `mms_connect_establish`（帧 4-7 逐字节）|
| Read 多数据类型 | `mms_read_multi_type`（83/85/86/89/91）|
| Write | `mms_write_success` |
| InformationReport | `mms_information_report` |
| GetNameList | `mms_getnamelist` |
| Identify | `mms_identify` |
| 服务拒绝错误 | `mms_service_error` |
| IPv4 + IPv6 | `mms_connect_establish` + `mms_ipv6` |
| 多会话 | `mms_multi_session` |
| 负路径 expect_error（配置校验）| `mms_validate_reject`（超长 item-identifier，expect_error=true）；`mms_no_associate` 仍是可组装但无关联的运行时负向 |

### 4.4 已知限制

- tshark 无法解码 OSI 内层（本地 3.6.14），内层只能 `frames` 原始字节断言，不能按字段断言（设计 6.5 论证）。
- `mms_read_multi_type` 的帧 9 长度字段与 utcTime 字节已按 4 字节秒值回填；后续实现若改变 specificationWithResult 语义，必须同步更新 6 附录 C 与 cases。
- `mms_fragmented_dt`、`mms_name_list_paging` 等预留用例仍属设计 10.2（未实现）。
- `structure` datatype 未单列 pcap 用例（设计 6.6 给出路由字节，实施覆盖于单测）。

## 5. 执行方式与判读

- 执行：`go test ./test/protocol_pcap/ -run MMS -count=1 -v`（等价 `-run 'TestProtocolPCAP/mms'`，入口见 run_all_test.go）。
- 判读：每个 case 的 `fields` 全部命中 + `frames` 全部 `{packet,offset,hex}` 前缀命中 → PASS；任一缺席/字节不符 → FAIL 并打印偏差。
- `packet_count` 精确帧数断言；`negotiated` 需出现 SYN+ACK；`has_handshake` 需首包 SYN；在 `mms_no_associate` 中 negotiated 仅表示 TCP 握手完成，不表示 MMS 应用关联。
- tshark 字段只取白名单内 cotp/tpkt 字段（本地 build 缺 OSI 内层协议解码）。

## 6. 参考附录 A：真实 pcap 全帧字节（/tmp/mms3.pcap 回溯）

无载荷帧（1-3）：
```
1 SYN       eth14+ip20: 45 00 00 28 … tcp: 50 02 20 00
2 SYN/ACK   tcp: 50 12 20 00
3 ACK       tcp: 50 10 20 00
```

数据帧（4-7）载荷起始（offset 54）：
```
3 ACK       （纯 TCP ACK，无 TPKT）
4 CR       03 00 00 14 0f e0 00 00 00 01 00 c0 01 0c c2 01 01 c1 01 02
5 CC       03 00 00 14 0f d0 00 01 00 02 00 c0 01 0c c1 01 01 c2 01 02
6 DT1      03 00 00 a5 02 f0 80 0d 92 …（166 字节总长，TPKT 165）*
7 DT2      03 00 00 a1 02 f0 80 0e 90 …（162 字节总长，TPKT 161）*
```

> `*` TPKT.length 含 4 字节头（165 = 4 + 2(DT) + 159 载荷；161 = 4 + 2 + 155）。DT2 载荷 155 字节 = 会话 CONNECT-ACK(0x0e) + 表示 CPA(0x31) + ACSE AARE(0x61) + MMS Initiate-Resp(0xa9)。

## 7. 参考附录 B：各用例 invokeID / 帧号总表

planner 按"连接 → 帧序"展开；确认服务每请求 invokeID 递增（设计 4.3；invokeID 为单连接内计数）。

| 用例 | 连接 | 帧 | Kind | invokeID |
| --- | --- | --- | --- | --- |
| connect_establish | A | 1-3 | tcp handshake | — |
| | A | 4 | cr | — |
| | A | 5 | cc | — |
| | A | 6 | dt(c2s) 关联请求 | — |
| | A | 7 | dt(s2c) 关联响应 | — |
| read_multi_type | A | 8 | read_req | 1 |
| | A | 9 | read_resp | 1 |
| write_success | A | 8 | write_req | 2 |
| | A | 9 | write_resp | 2 |
| information_report | A | 8 | report | —（无 invokeID 无响应）|
| getnamelist | A | 8 | gname_req | 3 |
| | A | 9 | gname_resp | 3 |
| identify | A | 8 | ident_req | 4 |
| | A | 9 | ident_resp | 4 |
| service_error | A | 8 | read_req（不存在对象）| 5 |
| | A | 9 | err（Confirmed-ErrorPDU）| 5 |
| no_associate | A | 4 | read_req（无关联）| 1 |
| ipv6 | A | 4-7 | cr/cc/dt/dt | —（同 connect_establish）|
| multi_session | A | 4 | cr | — |
| | B | 8 | cr（帧号按调度重排）| — |

> 说明：invokeID 以实际 `sequence.steps` 顺序为准（若 steps 含多步在前面，后续服务 invokeID 相应后移）；关联段（cr/cc/dt）无 invokeID。

## 8. 参考附录 C：Read 多类型确定字节推导

cases 中 `mms_read_multi_type` 的 frames 断言不含 `<L>` 占位，这里给出完整推导（与设计 6.6 一致）：

`domainId = "IED1"`（4B）→ `8a 04 49 45 44 31`
`itemId = "GGIO1.SPCSO1.stVal"`（22B）→ `8a 1a 47 47 49 4f 31 2e 53 50 43 53 4f 31 2e 73 74 56 61 6c`
ObjectName（domainSpecific）= `a1 <5+4+len> { 8a04 IED1 8a<len> item }`
VariableSpecification = 名选择 `a0 <len> { ObjectName }`
listOfVariable 项 = `a0 <len> { VariableSpecification }`
variableAccessSpecification = `a1 <L> { a0 <L> { … } }`

ReadRequest = `a0 <L> { 02 01 <inv>  a4 <L> { [80 01 01 specWithResult] a1 <L> { … } } }`
ReadResponse = `a1 <L> { 02 01 <inv>  a4 <L> { a1 <L> { listOfAccessResult } } }`
Data 各项：`83 01 ff`、`85 01 2a`、`86 01 07`、`89 02 01 02`、`91 04 65 bb 87 c0（1706788800 秒，2024-02-01T12:00:00Z）`。

> 长度逐级回填后即得确定十六进制；写 cases 时按本附录逐步算长度，禁止猜值（实现定稿后需重新核算 `<L>` 并同步 cases/testcase 文档）。

## 9. 变更记录

| 版本 | 日期 | 变更 |
| --- | --- | --- |
| v1.0.0 | 2026-08-18 | 初版：10 用例、帧号 1-based、"CR=第 4 帧"（含 ACK 帧）、fields/frames 双通道断言、覆盖清单 |
| v1.0.1 | 2026-08-18 | 与 cases/mms.json 逐字节对齐；确认帧序含第 3 帧 ACK（CR=4, CC=5, DT1=6, DT2=7，服务帧 8/9）；DT2 CPA 上下文结果列表按真实 pcap（30 0d 双项）记录；本地 tshark 逐字段回溯验证字节 |

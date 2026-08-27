# NMEA 0183（海用电子设备串行接口标准，National Marine Electronics Association 0183）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与 PCAP（抓包文件）/NIC（网卡）用例契约；`nmea` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/69-nmea-testcase.md`、`trafficgen/test/protocol_pcap/cases/nmea.json`  
> 规范基线：NMEA 0183（常用句子格式）、NMEA 0183 4.x 语义；TCP/UDP 载体按 RFC 9293/RFC 768。

## 1. 范围、证据等级和未注册边界

本契约定义 NMEA 0183 sentence（句子）在 TCP/UDP 上的生成与观察边界，覆盖 `$` 起始、talker ID（设备说话者标识）/sentence type（句子类型）、逗号字段、可选 `*` 后两位十六进制 XOR checksum（异或校验和）和 `\r\n` 行结束。重点覆盖 GGA、RMC、GSA、GSV、VTG、GLL、ZDA 与 `$P` proprietary sentence（专有句子），以及 IPv4/IPv6、多会话、TCP 分段/粘连、UDP 数据报和 PCAP/NIC 一致性。

NMEA 0183 原生常见于串行链路；本项目契约明确将同一 sentence wire format（线格式）承载在 TCP/UDP，不凭空添加 record length（记录长度）或二进制帧头。TCP segment（分段）不是句子边界，接收方必须按 `\r\n` 重组；一个 UDP datagram（数据报）可含一个或多个完整句子。

当前仓库没有注册 `nmea` layer、planner（规划器）、validator（校验器）或生成器。`cases/nmea.json` 只保留一个 `nmea_neg_unregistered` 注册前置占位，必须 `expect_error=true` 且 `error_contains="unknown layer"`；该占位不计入下文 20 个语义 ID。注册前拒绝、0 包、空 PCAP 或只有 TCP/UDP 外壳均不是 NMEA 行为通过。

动态经纬度、UTC 时间、状态、fix quality（定位质量）、卫星数、随机会话字段和校验和不得硬编码具体运行值；使用 `presence`、`nonzero`、`same_as_packet`、`distinct` 或“按句内字节复算 XOR”的关系断言。合法句子的规范格式与故意注入的非法负载必须在文档中明确区分。

## 2. 推荐配置、层链和载体 profile（档案）

推荐 TCP 链为 `[ip, tcp, nmea]` 或 `[ipv6, tcp, nmea]`，推荐 UDP 链为 `[ip, udp, nmea]` 或 `[ipv6, udp, nmea]`。层链是未来实现接入契约，不表示当前注册。

```json
{
  "protocol": "nmea",
  "config": {
    "layers": [
      {"ip": {"src": "192.0.2.69", "dst": "198.51.100.69"}},
      {"tcp": {"src_port": 40069, "dst_port": 10110}},
      {"nmea": {
        "talker_id": "GP", "sentence_types": ["GGA", "RMC"],
        "checksum": true, "framing": "crlf", "sentences": 4
      }}
    ]
  }
}
```

| 配置键 | 约束 |
|---|---|
| `transport` | `tcp` 或 `udp`；默认 TCP。TCP 默认端口 10110（NMEA 常见），UDP 端口可显式指定；显式 `0` 与缺失不同。 |
| `talker_id` | 两个 ASCII 字母，如 `GP`、`GN`、`II`；`P` 专有句子使用 `$P` 后接厂商 ID，不能把普通 talker 三字母误作厂商句子。 |
| `sentence_types`/`sentences` | 类型列表和句子数量；保留用户顺序，不能静默去重或重排。每个句子必须独立以 `\r\n` 结束。 |
| `fields` | 按句子类型提供字段；GGA/RMC 等字段顺序由规范决定，缺失字段不能移位填充。 |
| `checksum` | 合法句子必须为 true；校验和为 `$` 后至 `*` 前全部 ASCII 字节的 8 位 XOR，以两位大写或小写十六进制编码。 |
| `framing` | 仅 `crlf`；禁止用 `\n`、自定义长度或 NUL 替代结尾。 |
| `tcp.mss` | TCP 分段参数；可把一个句子拆跨多个 segment，但不能改变应用字节。 |
| `wire_fault` | 只允许测试注入：`missing_dollar`、`missing_crlf`、`truncated`、`checksum_missing`、`checksum_bad`、`field_invalid`、`carrier`、`boundary`。 |

层 schema（说明书）建议：`nmea` 为终结层，`DependsOn=[tcp]`、`TransportOn=[tcp,udp]`，允许显式 UDP 替代默认 TCP；字段约束负责 sentence type、talker、字段数量、CRLF 和 XOR。此处只定义未来注册契约，不向未注册 registry（注册表）写代码。

## 3. 句子线格式与校验和

规范句子抽象为：

```text
sentence = "$" + address + "," + data_fields + "*" + hex8(xor(address + "," + data_fields)) + "\r\n"
address  = talker_id(2) + sentence_type(3)
```

`$` 不参加 XOR；`*` 也不参加 XOR；XOR 输入是从 `$` 后第一个字节开始到 `*` 前最后一个字节的全部原始 ASCII bytes。`*` 后必须正好两个十六进制字符，再接 `\r\n`。空字段可以是规范定义的占位，但不能删掉逗号造成后续字段左移。校验和具体值随动态字段变化，测试应重新计算并比较句内两位 hex，不枚举固定值。

标准示例（仅作为格式说明，未来 fixture（固定样本）可使用动态字段；示例值不应成为运行期硬编码断言）：

```text
$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47\r\n
```

`4807.038` 是 48°07.038′ 的度分格式（不是十进制度）；纬度方向只能 `N/S`，经度方向只能 `E/W`。解析器必须区分数值字段、方向字段和空保留字段，并对度分范围做校验。

## 4. 常见句子类型与字段契约

### 4.1 GGA

GGA（GPS 定位数据）字段顺序为 UTC time、latitude、N/S、longitude、E/W、fix quality、satellite count、HDOP、altitude、altitude unit、geoid separation、geoid unit、age of differential、station ID。要求覆盖完整字段、合法度分、方向、数值边界和动态时间；不把卫星数或 fix quality 当字符串常量断言。

### 4.2 RMC

RMC（推荐最小 GNSS 数据）至少覆盖 UTC time、status `A/V`、纬度/方向、经度/方向、speed over ground、course over ground、date、磁偏角/方向。`A/V` 是动态数据字段；句子存在不等于定位有效，测试需分别观察 status。

### 4.3 GSA/GSV、VTG/GLL/ZDA

GSA（卫星工作状态与 DOP）覆盖模式、fix dimension、卫星 ID 列表和 PDOP/HDOP/VDOP；GSV（可见卫星）覆盖总消息数、消息序号、总卫星数以及每颗卫星的 ID/elevation/azimuth/SNR。GSV 多句序列必须保留消息序号与会话内关联。

VTG（航向/地速）覆盖 course、speed 与单位；GLL（地理位置）覆盖纬度/经度、时间和 status；ZDA（时间日期）覆盖 UTC、日/月/年与本地时区。每类字段顺序和空字段位置均由句型定义，不能用通用 CSV 解析后重排。

### 4.4 专有句子

专有句子以 `$P` 开头，后接厂商标识和厂商字段。实现应保留未知厂商字段的原始字节与逗号边界；不能把 `$P...` 当作普通两字母 talker ID。除 `$P`、校验和和 CRLF 外，厂商 payload（载荷）按 opaque（不透明）字段观察，不臆造语义。

## 5. TCP/UDP framing、IPv4/IPv6 和会话

TCP 是字节流：握手后 payload 可以在 `$`、字段中间、`*` 或 `\r\n` 中间切段，也可以在一个 segment 中粘连多条句子；接收端只能按完整 CRLF 重组。一个 TCP session（会话）中多句保持顺序；不同 session 的句子、动态字段和重组缓存必须隔离。MSS 变化不能改变句子字节或校验和。

UDP 每个 datagram 保留自己的边界；单句 datagram 必须以 CRLF 结尾，多句 datagram 只能由多个完整句子连续组成。截断句子、跨 datagram 拼接或把 datagram 边界当成 CRLF 均进入负例。

IPv4 与 IPv6 使用独立 fixture，分别断言 EtherType、地址族、TCP/UDP next-header（下一头部）、端口、方向和校验和。IPv6 不是把 IPv4 地址字符串替换后仍沿用 IPv4 header；IPv4/IPv6 混用层链、错误 transport 或错误端口属于 carrier 负例。

## 6. 正例、故障注入、PCAP/NIC 证据

正例断言可观察字节和解析关系：`$`/address/逗号位置、CRLF、句型顺序、动态字段存在、TCP 重组、UDP datagram 边界、IPv4/IPv6、方向、端口和 XOR 一致性。不能因无法运行 NMEA 专用 dissector（解析器）而自创 tshark 字段；可退回 `tcp`/`udp`、raw payload（原始载荷）和稳定 hex offsets。

ID `nmea_invalid_checksum` 是**观测正例**：它专门验证 carrier 透明转发一个故意构造的非法句子（校验和与句内 XOR 不一致），因此 expect 不报 planner 错误；该句子不是合法 NMEA 格式，不能污染本节合法句子定义。真正的配置/语义拒绝由 15–20 负例覆盖。

负例必须在 planner/validator 失败并传播为 task error，不能产出成功 PCAP、`completed/0 packet` 或仅有 TCP/UDP 外壳。负例执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`，不添加 notes、packet_count 或其他断言键。

PCAP/NIC 正例应重复检查：方向、IPv4/IPv6、TCP/UDP、端口、TCP payload 重组后的 CRLF、UDP 单/多句边界，以及每句 XOR 关系。NIC 测试需记录 checksum offload（校验和卸载）可能导致的链路抓包差异；不能把网卡抓包中的未填充校验和误判成 NMEA payload 校验和错误。

## 7. 错误处理和实现完成定义

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `nmea_neg_framing` | 缺 `$`、缺 CRLF、TCP 截断或非法粘连边界 | `framing`、`sentence` 或 `crlf` |
| `nmea_neg_checksum` | 缺 `*xx` 或 XOR 与句内字节不一致 | `checksum` |
| `nmea_neg_type_fields` | 未知 talker/type、GGA/RMC 字段缺失或多余 | `talker`、`sentence` 或 `field` |
| `nmea_neg_position` | 度分数值越界、方向不是 N/S/E/W | `latitude`、`longitude` 或 `direction` |
| `nmea_neg_carrier` | 非 TCP/UDP、错误端口、IPv4/IPv6 层链混用 | `carrier`、`transport` 或 `port` |
| `nmea_neg_boundary_json` | 坏 JSON、非法多句边界、跨 UDP datagram 拼接 | `json`、`boundary` 或 `datagram` |

实现完成定义：注册 `nmea` layer；实现 TCP/UDP、IPv4/IPv6、GGA/RMC/GSA/GSV/VTG/GLL/ZDA/`$P` 句子、动态字段策略、CRLF 重组、XOR、字段校验和故障传播；planner→worker→PCAP/NIC 输出链完整；集成测试覆盖多 session、MSS 分段、粘连、多句 UDP、正负路径；`-race`（竞态检测）通过；不将非法校验和观测正例声称为合法句子。

## 8. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例和 6 个负例；顺序必须与 `69-nmea-testcase.md` §2 及未来注册后的 `nmea.json` 完全一致。当前 JSON 只有不计数的注册前置占位。

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `nmea_tcp_ipv4_sentence_stream` | 正 | IPv4/TCP、多条句子、`$..*xx\r\n` | 8 |
| 2 | `nmea_tcp_ipv6_sentence_stream` | 正 | IPv6/TCP 独立地址族与句子流 | 8 |
| 3 | `nmea_gga_full_fields` | 正 | GGA 完整字段、度分格式、方向与海拔 | 6 |
| 4 | `nmea_rmc_sentence` | 正 | RMC status、经纬度、SOG/COG、日期 | 6 |
| 5 | `nmea_checksum_xor` | 正 | `$` 排除、`*` 前 XOR、两位 hex 可复算 | 6 |
| 6 | `nmea_gsa_gsv_multi_type` | 正 | GSA/GSV 混合、多消息序号与卫星字段 | 10 |
| 7 | `nmea_vtg_gll_zda` | 正 | VTG/GLL/ZDA 类型与字段边界 | 10 |
| 8 | `nmea_proprietary_sentence` | 正 | `$P` 专有句子与 opaque 厂商字段 | 6 |
| 9 | `nmea_line_framing_reassembly` | 正 | CRLF 边界、TCP 分段/合并、多句粘连 | 10 |
| 10 | `nmea_invalid_checksum` | 正 | 故意非法 checksum 的透明观测（非规范合法格式） | 6 |
| 11 | `nmea_multi_session_stream` | 正 | 多 TCP session、状态/重组缓存隔离 | 12 |
| 12 | `nmea_udp_datagram` | 正 | UDP 单句/多句 datagram 边界 | 6 |
| 13 | `nmea_mixed_transport_fixture` | 正 | TCP 与 UDP 多流、方向和端口独立 | 12 |
| 14 | `nmea_pcap_nic_consistency` | 正 | PCAP/NIC 方向、载体、句边界和 XOR 一致 | 12 |
| 15 | `nmea_neg_framing` | 负 | 缺 `$`、缺 CRLF、截断或非法粘连 | — |
| 16 | `nmea_neg_checksum` | 负 | checksum 缺失或 XOR 不一致 | — |
| 17 | `nmea_neg_type_fields` | 负 | 未知 talker/type、字段缺失或多余 | — |
| 18 | `nmea_neg_position` | 负 | 度分越界、非法方向字符 | — |
| 19 | `nmea_neg_carrier` | 负 | 非 TCP/UDP、错误端口或地址族混用 | — |
| 20 | `nmea_neg_boundary_json` | 负 | 坏 JSON、边界错误、跨 datagram 拼接 | — |

三方契约必须保持本文 §8、`69-nmea-testcase.md` §2、注册后的 `nmea.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `nmea_neg_unregistered`，且唯一预期为 `unknown layer`。

## 9. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 NMEA 0183 TCP/UDP 正例和 6 个严格负例，覆盖句子线格式、GGA/RMC/GSA/GSV/VTG/GLL/ZDA、专有句子、XOR、CRLF 重组、IPv4/IPv6、多会话、多句 UDP、PCAP/NIC 与错误传播；明确非法 checksum 透明观测正例不属于合法规范；不修改 Go 实现。

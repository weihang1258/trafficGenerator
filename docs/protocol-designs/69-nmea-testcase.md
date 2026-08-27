# NMEA 0183（海用电子设备串行接口标准，National Marine Electronics Association 0183）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/69-nmea-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/nmea.json`  
> 状态：`nmea` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `nmea_neg_unregistered`，其 `expect` 必须 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

NMEA sentence（句子）必须是 `$` + 地址字段 + 逗号字段 + `*` 后两位十六进制 XOR checksum（异或校验和）+ `\r\n`。`$` 和 `*` 不参加 XOR；校验输入为 `$` 后至 `*` 前全部原始 ASCII bytes。动态经纬度、UTC、状态、卫星数、会话 ID 和 checksum 具体值不硬编码，使用 presence（存在）、nonzero（非零）、same_as_packet（与指定包相同）、distinct（不同）或句内 XOR 复算关系。

TCP 是字节流，segment（分段）边界不能当 sentence 边界；UDP datagram（数据报）边界必须保留，datagram 可含一条或多条完整句子。ID `nmea_invalid_checksum` 是**正例中的透明观测**：它发送故意不符合 XOR 的非法输入以验证载体不篡改，不代表合法 NMEA，不能污染规范合法格式。真正应被拒绝的坏输入列在 15–20。

## 2. 原子用例索引

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

## 3. 正例逐项断言契约

1. **`nmea_tcp_ipv4_sentence_stream`**：IPv4/TCP 默认端口 10110，完成握手后发送至少多条完整句子；断言 `$`、五字符 address、逗号字段、`*` 两位 hex、CRLF、方向和 payload，`packet_count=8`。
2. **`nmea_tcp_ipv6_sentence_stream`**：独立 IPv6 fixture，断言 EtherType `0x86DD`、IPv6 next-header=TCP、端口和句子格式；不得从 IPv4 fixture 继承地址族，`packet_count=8`。
3. **`nmea_gga_full_fields`**：断言 GGA 字段顺序完整、纬度/经度为度分格式、方向分别属于 N/S 与 E/W、fix quality/卫星数/HDOP/海拔字段存在；动态数值只 presence/nonzero，`packet_count=6`。
4. **`nmea_rmc_sentence`**：断言 RMC 时间、status（只能 A/V）、纬度经度方向、SOG/COG 和日期位置；A/V 不硬编码为固定运行值，`packet_count=6`。
5. **`nmea_checksum_xor`**：对每句从 `$` 后至 `*` 前逐字节 XOR，并与句内两位十六进制文本比较；断言 `$`/`*` 排除、两位长度和 CRLF，禁止枚举某个 checksum，`packet_count=6`。
6. **`nmea_gsa_gsv_multi_type`**：同一流混合 GSA/GSV；断言 GSA 模式/DOP/卫星 ID 列表、GSV 总消息数/序号/总卫星数和卫星字段，保留消息序列，`packet_count=10`。
7. **`nmea_vtg_gll_zda`**：断言 VTG 航向/速度单位、GLL 位置/时间/status、ZDA 日期/时区字段边界和各自 sentence type，`packet_count=10`。
8. **`nmea_proprietary_sentence`**：断言句子以 `$P` 开始、厂商 ID 和 opaque 字段按原始逗号边界保留、checksum/CRLF 完整；不臆断厂商 payload 语义，`packet_count=6`。
9. **`nmea_line_framing_reassembly`**：设置 TCP MSS 使 `$`、字段、`*` 或 CRLF 跨 segment，并在 segment 中粘连多句；断言按 CRLF 重组句子，不把 segment 当边界且句序不变，`packet_count=10`。
10. **`nmea_invalid_checksum`**：载体透明转发一个故意使句内 XOR 与 `*xx` 不一致的句子；断言原始非法 payload、长度、CRLF 和方向，不断言其为合法 NMEA，也不要求 planner error，`packet_count=6`。
11. **`nmea_multi_session_stream`**：至少两个不同 TCP 四元组并行，每 session 多句；断言每流独立重组、句序和动态字段关联，不能跨 session 拼接，`packet_count=12`。
12. **`nmea_udp_datagram`**：发送单句 datagram 与包含多条完整句子的 datagram；断言每个 UDP payload 的边界、句数、每句 CRLF/XOR，不跨 datagram 拼接，`packet_count=6`。
13. **`nmea_mixed_transport_fixture`**：同时观察 TCP 和 UDP 多流，断言 transport、端口、方向和每种载体的 framing 独立；TCP 可分段，UDP 保留 datagram，`packet_count=12`。
14. **`nmea_pcap_nic_consistency`**：同一 fixture 分别输出 PCAP 与 NIC，断言 IPv4/IPv6、TCP/UDP、方向、端口、重组后的句子边界和 XOR 关系一致；记录 checksum offload（校验和卸载）边界，`packet_count=12`。

没有 NMEA 专用 dissector（解析器）时，使用 `tcp`/`udp`、raw payload、稳定 hex offsets（偏移）和按 CRLF 重组后的脚本断言；不得自创 `nmea.*` 字段。不得添加“经纬度属于某真实位置”“签名/随机性合格”等不可观察断言。

## 4. 负例契约

每个负例必须在 planner/validator 失败并传播为 task error；不能产生成功 PCAP、`completed/0 packet` 或只有 TCP/UDP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `nmea_neg_framing` | 明确注入缺 `$`、缺 CRLF、TCP 截断或非法粘连边界；这些是非法输入，不是正例格式 | `framing`、`sentence` 或 `crlf` |
| `nmea_neg_checksum` | 明确注入缺 `*xx` 或 XOR 与句内字节不一致；这些是非法 checksum，不是 `nmea_checksum_xor` 的合法约束 | `checksum` |
| `nmea_neg_type_fields` | 未知 talker/type、GGA/RMC 字段缺失或多余、字段顺序错误 | `talker`、`sentence` 或 `field` |
| `nmea_neg_position` | 纬度/经度度分越界，或方向不是 N/S/E/W | `latitude`、`longitude` 或 `direction` |
| `nmea_neg_carrier` | 非 TCP/UDP、错误端口、IPv4/IPv6 混用层链 | `carrier`、`transport` 或 `port` |
| `nmea_neg_boundary_json` | 坏 JSON、跨 UDP datagram 拼接、未按 CRLF 切分的非法多句边界 | `json`、`boundary` 或 `datagram` |

负例不能用“0 包”“空 PCAP”或任务成功替代错误传播。`nmea_invalid_checksum` 的透明观测必须与 `nmea_neg_checksum` 区分：前者验证载体保留非法字节，后者验证 planner/validator 拒绝非法配置/语义。

## 5. 三方一致性和静态检查

1. 设计 §8 的 20 个 ID、本文 §2、注册后的 JSON 和审计必须保持同一组 ID、同一顺序：14 正例 + 6 负例；当前 JSON 另有一个 `nmea_neg_unregistered` 占位，不计入 20 个。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、载体、方向和可观察句子字段；6 个负例的 `expect` 只能有 `expect_error`、`error_contains`。负例描述的缺 `$`、缺 CRLF、坏 checksum、非法方向等必须明确是非法输入。
3. 每句格式断言 `$`、2+3 字符地址、逗号字段、`*` 两位 hex 与 `\r\n`；GGA/RMC/GSA/GSV/VTG/GLL/ZDA 按自身字段顺序，不使用通用字段重排。
4. 校验和按 `$` 后至 `*` 前原始字节逐字节 XOR；不得把 `$`/`*` 纳入输入，不得硬编码动态 checksum 文本；`nmea_invalid_checksum` 仅为透明非法输入观测。
5. TCP 先按字节流重组再按 CRLF 切句，允许 segment 跨边界和多句粘连；UDP 以 datagram 为边界，不跨 datagram 拼接。
6. 动态时间、经纬度、方向状态、卫星数和会话字段只用 presence/nonzero/same_as_packet/distinct；度分格式与 N/S/E/W 关系须以实际字段观察。
7. IPv4/IPv6、TCP/UDP、多 session、PCAP/NIC 断言不依赖全局交织包序；NIC 校验和卸载只影响 L3/L4 checksum，不改变 NMEA payload XOR。
8. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/nmea.json` 应成功；当前数组只能含 `nmea_neg_unregistered`，且 `proto=nmea`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `nmea` layer 后，先检查 JSON parser、ID 顺序、正负 expect 键集合、句子 offsets、CRLF 重组和 XOR 复算，再运行 1–14 的 PCAP/NIC 正例和 15–20 的错误传播。若环境没有 NMEA dissector，使用 TCP/UDP/raw payload 与脚本验证；不能将唯一 placeholder 运行结果报告为 NMEA suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 NMEA 0183 TCP/UDP 正例和 6 个严格负例，覆盖句子格式、GGA/RMC/GSA/GSV/VTG/GLL/ZDA、专有句子、XOR、CRLF 重组、IPv4/IPv6、多会话、多句 UDP、PCAP/NIC 和错误传播；明确非法 checksum 透明观测与非法输入负例的边界；不修改 Go 实现。
